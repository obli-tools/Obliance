import { db } from '../db';
import { logger } from '../utils/logger';
import { AppError } from '../middleware/errorHandler';
import type {
  AgentUpdatePolicy, UpdatePolicyKind, ResolvedUpdatePolicy, DeviceUpdatePolicies, UpdatePolicyLevelView,
} from '@obliance/shared';
import {
  UPDATE_POLICY_KINDS, UPDATE_POLICY_CONFIG_KEYS, UPDATE_POLICY_COLUMNS, asUpdatePolicy, resolveUpdatePolicy,
  unresolvedUpdatePolicy, allowsManualUpdate, describePolicySource, type UpdatePolicyGroupEntry,
} from '../utils/updatePolicy';

// ── Agent update policy cascade (platform → tenant → group chain) ───────────
//
// Model and semantics: shared/src/updatePolicy.ts (ported from Obliguard
// C17-1). This service reads the three levels into ONE in-memory context
// (app_config 2 keys + the tenants / groups that carry a value + the group
// tree), cached CONTEXT_TTL_MS per process and dropped on every write, so
// the hot paths (every agent push builds the ObliReach target, every
// ObliReach heartbeat) resolve a device's policy without a query.
//
// Only groups of the device's OWN tenant count (a group of another tenant on
// the parent chain — legacy cross-tenant nesting — is ignored), so no level
// of one tenant can change another tenant's devices.
//
// A failed read is cached FAILURE_TTL_MS and resolves every device to
// 'frozen' / source 'unresolved' (fail closed: nothing automatic, explicit
// actions answered 503).

const CONTEXT_TTL_MS = 15_000;
const FAILURE_TTL_MS = 5_000;
/** Bound of a parent-chain walk (a corrupt cycle never loops). */
const MAX_DEPTH = 64;

type Pair = Record<UpdatePolicyKind, AgentUpdatePolicy | null>;
interface GroupNode extends Pair { id: number; tenantId: number; parentId: number | null; name: string }
export interface UpdatePolicyContext {
  global: Pair;
  tenants: Map<number, Pair>;
  groups: Map<number, GroupNode>;
}

let cache: { ctx: UpdatePolicyContext | null; at: number } | null = null;
let loading: Promise<UpdatePolicyContext | null> | null = null;
let gen = 0;
let loaderOverride: (() => Promise<UpdatePolicyContext>) | null = null;

const COLS = UPDATE_POLICY_KINDS.map((k) => UPDATE_POLICY_COLUMNS[k]);

/** A row's own value of every kind (anything unknown = inherit). */
function pairOf(row: Record<string, unknown> | Map<string, string | null>, keyOf: (k: UpdatePolicyKind) => string): Pair {
  const get = (key: string) => (row instanceof Map ? row.get(key) : row[key]);
  const out = {} as Pair;
  for (const k of UPDATE_POLICY_KINDS) out[k] = asUpdatePolicy(get(keyOf(k)));
  return out;
}

/** No own value at any kind (levels views). */
export function emptyPair(): Pair {
  const out = {} as Pair;
  for (const k of UPDATE_POLICY_KINDS) out[k] = null;
  return out;
}

async function loadContext(): Promise<UpdatePolicyContext> {
  const [cfgRows, tenantRows, groupRows] = await Promise.all([
    db('app_config').whereIn('key', Object.values(UPDATE_POLICY_CONFIG_KEYS)).select('key', 'value') as Promise<Array<{ key: string; value: string | null }>>,
    db('tenants')
      .where((w) => { for (const c of COLS) w.orWhereNotNull(c); })
      .select('id', ...COLS) as Promise<Array<Record<string, unknown> & { id: number }>>,
    db('device_groups')
      .select('id', 'tenant_id', 'parent_id', 'name', ...COLS) as Promise<Array<Record<string, unknown> & {
        id: number; tenant_id: number; parent_id: number | null; name: string;
      }>>,
  ]);
  const cfg = new Map(cfgRows.map((r) => [r.key, r.value]));
  const global = pairOf(cfg, (k) => UPDATE_POLICY_CONFIG_KEYS[k]);
  const tenants = new Map<number, Pair>();
  for (const t of tenantRows) tenants.set(Number(t.id), pairOf(t, (k) => UPDATE_POLICY_COLUMNS[k]));
  const groups = new Map<number, GroupNode>();
  for (const g of groupRows) {
    groups.set(Number(g.id), {
      id: Number(g.id),
      tenantId: Number(g.tenant_id),
      parentId: g.parent_id == null ? null : Number(g.parent_id),
      name: g.name,
      ...pairOf(g, (k) => UPDATE_POLICY_COLUMNS[k]),
    });
  }
  return { global, tenants, groups };
}

/** Groups with an explicit `kind` value from `groupId` up (nearest first), own tenant only. */
export function groupChainOf(ctx: UpdatePolicyContext, kind: UpdatePolicyKind, tenantId: number, groupId: number | null): UpdatePolicyGroupEntry[] {
  const chain: UpdatePolicyGroupEntry[] = [];
  const seen = new Set<number>();
  let id = groupId;
  for (let depth = 0; id != null && depth < MAX_DEPTH && !seen.has(id); depth++) {
    seen.add(id);
    const g = ctx.groups.get(id);
    if (!g) break;
    if (g.tenantId === Number(tenantId) && g[kind]) chain.push({ groupId: g.id, groupName: g.name, policy: g[kind]! });
    id = g.parentId;
  }
  return chain;
}

/** Effective policy of a device / a group position in the tree (pure, from a context). */
export function resolveIn(ctx: UpdatePolicyContext, kind: UpdatePolicyKind, tenantId: number, groupId: number | null): ResolvedUpdatePolicy {
  return resolveUpdatePolicy(kind, {
    global: ctx.global[kind],
    tenant: ctx.tenants.get(Number(tenantId))?.[kind] ?? null,
    groupChain: groupChainOf(ctx, kind, tenantId, groupId),
  });
}

function bothIn(ctx: UpdatePolicyContext | null, tenantId: number, groupId: number | null): DeviceUpdatePolicies {
  const out = {} as DeviceUpdatePolicies;
  for (const k of UPDATE_POLICY_KINDS) out[k] = ctx ? resolveIn(ctx, k, tenantId, groupId) : unresolvedUpdatePolicy();
  return out;
}

/** The own values of a level as the editors' fields. */
function overridesOf(pair: Pair): Pick<UpdatePolicyLevelView, 'agentUpdatePolicy' | 'oblireachUpdatePolicy' | 'vmconsoleInstallPolicy'> {
  return {
    agentUpdatePolicy: pair.agent,
    oblireachUpdatePolicy: pair.oblireach,
    vmconsoleInstallPolicy: pair.vmconsole,
  };
}

export const updatePolicyService = {
  /** The cascade (cached), or null when it could not be read (fail closed). */
  async context(): Promise<UpdatePolicyContext | null> {
    if (cache) {
      const ttl = cache.ctx === null ? FAILURE_TTL_MS : CONTEXT_TTL_MS;
      if (Date.now() - cache.at < ttl) return cache.ctx;
    }
    if (loading) return loading;
    const myGen = gen;
    const p = (async () => {
      try {
        const ctx = await (loaderOverride ?? loadContext)();
        if (myGen === gen) cache = { ctx, at: Date.now() };
        return ctx;
      } catch (err) {
        logger.warn({ err }, 'update policy: cascade read failed — automatic updates held, explicit ones refused until it succeeds');
        if (myGen === gen) cache = { ctx: null, at: Date.now() };
        return null;
      }
    })();
    loading = p;
    try { return await p; } finally { if (loading === p) loading = null; }
  },

  /** The cascade, re-read once when a group asked about is not in it yet
   *  (created / imported since the last read on another process). */
  async contextFor(groupIds: Array<number | null | undefined>): Promise<UpdatePolicyContext | null> {
    const ctx = await this.context();
    if (!ctx) return null;
    if (groupIds.some((g) => g != null && !ctx.groups.has(Number(g)))) {
      this.invalidate();
      return this.context();
    }
    return ctx;
  },

  /** A level changed: the next resolution re-reads the cascade. */
  invalidate(): void {
    cache = null;
    loading = null;
    gen++;
  },

  /** Effective policy of one kind for a device (its tenant + group). */
  async resolve(kind: UpdatePolicyKind, device: { tenant_id: number; group_id: number | null }): Promise<ResolvedUpdatePolicy> {
    const ctx = await this.contextFor([device.group_id]);
    if (!ctx) return unresolvedUpdatePolicy();
    return resolveIn(ctx, kind, Number(device.tenant_id), device.group_id == null ? null : Number(device.group_id));
  },

  async resolveDevice(device: { tenant_id: number; group_id: number | null }): Promise<DeviceUpdatePolicies> {
    return bothIn(await this.contextFor([device.group_id]), Number(device.tenant_id), device.group_id == null ? null : Number(device.group_id));
  },

  /** Batch: device id → effective policy of `kind` (one cascade read). */
  async resolveMany(kind: UpdatePolicyKind, devices: Array<{ id: number; tenant_id: number; group_id: number | null }>): Promise<Map<number, ResolvedUpdatePolicy>> {
    const ctx = await this.contextFor(devices.map((d) => d.group_id));
    const out = new Map<number, ResolvedUpdatePolicy>();
    for (const d of devices) {
      out.set(Number(d.id), ctx ? resolveIn(ctx, kind, Number(d.tenant_id), d.group_id == null ? null : Number(d.group_id)) : unresolvedUpdatePolicy());
    }
    return out;
  },

  /**
   * Explicit (manual) update of `kind` on a device: refused when its policy
   * is 'frozen' (409, code update_policy_frozen) or unreadable (503).
   */
  async assertManualAllowed(kind: UpdatePolicyKind, device: { id?: number; tenant_id: number; group_id: number | null; hostname?: string | null }): Promise<ResolvedUpdatePolicy> {
    const r = await this.resolve(kind, device);
    if (allowsManualUpdate(r)) return r;
    if (r.source === 'unresolved') {
      throw new AppError(503, 'The update policy could not be read — try again in a few seconds', 'update_policy_unresolved');
    }
    const what = kind === 'agent' ? 'Agent updates are' : kind === 'oblireach' ? 'ObliReach updates are' : 'The VM console installation is';
    throw new AppError(409, `${what} ${kind === 'vmconsole' ? 'disabled' : 'frozen'} for this device (set by ${describePolicySource(r)})`, 'update_policy_frozen');
  },

  // ── Level views (editors) ────────────────────────────────────────────────

  /** Platform level: its values + the built-in defaults it overrides. */
  async globalView(): Promise<UpdatePolicyLevelView> {
    const ctx = await this.context();
    if (!ctx) throw new AppError(503, 'The update policy could not be read — try again in a few seconds', 'update_policy_unresolved');
    const none: UpdatePolicyContext = { global: emptyPair(), tenants: new Map(), groups: new Map() };
    return {
      ...overridesOf(ctx.global),
      inherited: bothIn(none, 0, null),
      effective: bothIn({ ...ctx, tenants: new Map(), groups: new Map() }, 0, null),
      canEdit: false, // set by the route
    };
  },

  /** Tenant level: its values, what it inherits (platform) and its effective value. */
  async tenantView(tenantId: number): Promise<UpdatePolicyLevelView> {
    const ctx = await this.context();
    if (!ctx) throw new AppError(503, 'The update policy could not be read — try again in a few seconds', 'update_policy_unresolved');
    const own = ctx.tenants.get(Number(tenantId)) ?? emptyPair();
    const withoutTenant: UpdatePolicyContext = { ...ctx, tenants: new Map(), groups: new Map() };
    const tenantOnly: UpdatePolicyContext = { ...ctx, groups: new Map() };
    return {
      ...overridesOf(own),
      inherited: bothIn(withoutTenant, tenantId, null),
      effective: bothIn(tenantOnly, tenantId, null),
      canEdit: false,
    };
  },

  /** Group level: its values, what it inherits (parent groups → tenant → platform), its effective value. */
  async groupView(group: { id: number; tenantId: number; parentId: number | null }): Promise<UpdatePolicyLevelView> {
    const ctx = await this.contextFor([group.id]);
    if (!ctx) throw new AppError(503, 'The update policy could not be read — try again in a few seconds', 'update_policy_unresolved');
    const node = ctx.groups.get(Number(group.id));
    return {
      ...overridesOf(node ?? emptyPair()),
      inherited: bothIn(ctx, group.tenantId, group.parentId),
      effective: bothIn(ctx, group.tenantId, group.id),
      canEdit: false,
    };
  },

  // ── Test seams (verification harness only) ──
  __setLoaderForTests(fn: (() => Promise<UpdatePolicyContext>) | null): void {
    loaderOverride = fn;
    this.invalidate();
  },
};

export { UPDATE_POLICY_KINDS };
