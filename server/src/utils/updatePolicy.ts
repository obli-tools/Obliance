// Agent update policy (ported from Obliguard C17-1) — pure helpers, no DB.
// Model and semantics: shared/src/updatePolicy.ts.
import type {
  AgentUpdatePolicy, UpdatePolicyKind, ResolvedUpdatePolicy,
} from '@obliance/shared';

export const UPDATE_POLICIES: readonly AgentUpdatePolicy[] = ['auto', 'manual', 'frozen'];
export const UPDATE_POLICY_KINDS: readonly UpdatePolicyKind[] = ['agent', 'oblireach', 'vmconsole'];

/** Nothing set anywhere: today's behaviour of each agent. */
export const DEFAULT_UPDATE_POLICY: Readonly<Record<UpdatePolicyKind, AgentUpdatePolicy>> = {
  agent: 'manual',
  oblireach: 'auto',
  // VM console helper: installed on demand (first console opening / button).
  vmconsole: 'manual',
};

/** app_config keys of the platform level. */
export const UPDATE_POLICY_CONFIG_KEYS: Readonly<Record<UpdatePolicyKind, string>> = {
  agent: 'agent_update_policy',
  oblireach: 'oblireach_update_policy',
  vmconsole: 'vmconsole_install_policy',
};

/** Column of the tenant / group level. */
export type UpdatePolicyColumn = 'agent_update_policy' | 'oblireach_update_policy' | 'vmconsole_install_policy';
export const UPDATE_POLICY_COLUMNS: Readonly<Record<UpdatePolicyKind, UpdatePolicyColumn>> = {
  agent: 'agent_update_policy',
  oblireach: 'oblireach_update_policy',
  vmconsole: 'vmconsole_install_policy',
};

/** Request-body field of the tenant / group editors. */
export type UpdatePolicyField = 'agentUpdatePolicy' | 'oblireachUpdatePolicy' | 'vmconsoleInstallPolicy';
export const UPDATE_POLICY_FIELDS: Readonly<Record<UpdatePolicyKind, UpdatePolicyField>> = {
  agent: 'agentUpdatePolicy',
  oblireach: 'oblireachUpdatePolicy',
  vmconsole: 'vmconsoleInstallPolicy',
};

export function isUpdatePolicy(v: unknown): v is AgentUpdatePolicy {
  return typeof v === 'string' && (UPDATE_POLICIES as readonly string[]).includes(v);
}

/** A stored value read as a policy (anything else = inherit). */
export function asUpdatePolicy(v: unknown): AgentUpdatePolicy | null {
  return isUpdatePolicy(v) ? v : null;
}

export interface UpdatePolicyGroupEntry {
  groupId: number;
  groupName?: string | null;
  policy: AgentUpdatePolicy;
}

/**
 * Cascade resolution. `groupChain` = the groups WITH an explicit value on the
 * ancestor chain, nearest first (own group first), restricted to the
 * device's tenant.
 *   1. platform 'frozen' (kill-switch);
 *   2. tenant 'frozen';
 *   3. a 'frozen' group on the chain (the highest one is reported);
 *   4. nearest explicit value: group chain, tenant, platform;
 *   5. built-in default.
 */
export function resolveUpdatePolicy(
  kind: UpdatePolicyKind,
  levels: {
    global: AgentUpdatePolicy | null | undefined;
    tenant: AgentUpdatePolicy | null | undefined;
    groupChain: UpdatePolicyGroupEntry[];
  },
): ResolvedUpdatePolicy {
  const g = asUpdatePolicy(levels.global);
  const t = asUpdatePolicy(levels.tenant);
  const chain = levels.groupChain.filter((e) => isUpdatePolicy(e.policy));
  if (g === 'frozen') return { policy: 'frozen', source: 'global', sourceGroupId: null };
  if (t === 'frozen') return { policy: 'frozen', source: 'tenant', sourceGroupId: null };
  for (let i = chain.length - 1; i >= 0; i--) {
    if (chain[i].policy === 'frozen') {
      return { policy: 'frozen', source: 'group', sourceGroupId: chain[i].groupId, sourceGroupName: chain[i].groupName ?? null };
    }
  }
  if (chain.length > 0) {
    return { policy: chain[0].policy, source: 'group', sourceGroupId: chain[0].groupId, sourceGroupName: chain[0].groupName ?? null };
  }
  if (t) return { policy: t, source: 'tenant', sourceGroupId: null };
  if (g) return { policy: g, source: 'global', sourceGroupId: null };
  return { policy: DEFAULT_UPDATE_POLICY[kind], source: 'default', sourceGroupId: null };
}

/** Fail-closed value when the cascade cannot be read: nothing automatic, explicit actions refused (503). */
export function unresolvedUpdatePolicy(): ResolvedUpdatePolicy {
  return { policy: 'frozen', source: 'unresolved', sourceGroupId: null };
}

/** May an update of this kind be started automatically? */
export function allowsAutomaticUpdate(r: ResolvedUpdatePolicy): boolean {
  return r.source !== 'unresolved' && r.policy === 'auto';
}

/** May an explicit (manual) update be started? */
export function allowsManualUpdate(r: ResolvedUpdatePolicy): boolean {
  return r.source !== 'unresolved' && r.policy !== 'frozen';
}

/** Short human description of where a frozen policy comes from (logs, 409 messages). */
export function describePolicySource(r: ResolvedUpdatePolicy): string {
  switch (r.source) {
    case 'global': return 'the platform setting';
    case 'tenant': return 'the tenant setting';
    case 'group': return r.sourceGroupName ? `the group "${r.sourceGroupName}"` : `group #${r.sourceGroupId}`;
    case 'default': return 'the built-in default';
    default: return 'an unreadable policy';
  }
}
