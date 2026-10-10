import { db } from '../db';
import { MASTER_TENANT_ID, isMasterTenant } from '@obliance/shared';
import { permissionService } from './permission.service';
import { logger } from '../utils/logger';
// Static (like process.service / vmConsole.service): getIO is only called at
// emit time, so the socket.ts ↔ services import cycle is harmless.
import { getIO } from '../socket';

/**
 * Who may receive a live Socket.io event carrying the data of ONE device —
 * the SAME rules as the REST routes that serve that data
 * (deviceScope.service resolveRequestDevice [+ capability]):
 *
 *   - platform admin: the device's tenant, or — when the rule says so
 *     (`masterGodView`) — the master tenant (god view);
 *   - other users: socket tenant = the device's tenant, member of it, the
 *     device visible to their teams and, when the rule names one, the
 *     capability granted on it.
 *
 * Until 2026-10 these events (Hyper-V VM lists / console frames, Veeam job
 * lists, command results, service lists, compliance results…) went to the
 * whole `tenant:<id>` room: every member of the tenant got them, device
 * visible or not, capability or not.
 *
 * The socket identity (user, tenant) is frozen at handshake (socket.ts puts
 * it on socket.data); the role, is_active, membership and grants are re-read
 * at each emit — or, for the high-frequency events (`cacheMs`), at most every
 * `cacheMs` (a revocation then takes effect within that delay).
 */
export interface DeviceAudienceRule {
  /** Capability a non-admin must hold on the device (none: visibility only). */
  capability?: string;
  /** Also the admins of the master tenant (god view), as the matching list route does. */
  masterGodView?: boolean;
  /** Verdict cache (ms) for high-frequency events; 0/absent = re-read every time. */
  cacheMs?: number;
}

/**
 * The readers of a device (no capability: its tenant's admins, members who
 * see it — the device REST routes' rule), for the high-frequency per-device
 * events (command updates / results, service lists, compliance results):
 * verdicts cached 5 s (a revocation takes effect within 5 s), the device's
 * tenant room only (as before: no god-view widening).
 */
export const DEVICE_READERS: Readonly<DeviceAudienceRule> = Object.freeze({ cacheMs: 5_000 });

export interface SocketIdent { userId: number; tenantId: number | null }

const verdictCache = new Map<string, { v: boolean; exp: number }>();
const CACHE_MAX = 20_000;

/** Test seam (never set in production): the verification harnesses run the
 *  server on a fake socket layer with no sockets to filter; they record the
 *  per-device emissions here, as if sent to the device's tenant room. */
export const deviceEventsTestSink: { record: null | ((deviceId: number, deviceTenantId: number, events: Array<[string, unknown]>) => void) } = { record: null };

/** Test hook / tenant-wide permission change: forget every cached verdict. */
export function resetDeviceAudienceCache(): void { verdictCache.clear(); }

/** A NON-admin whose session is on `tenantId`: may see this device (+ capability)? */
async function nonAdminMay(userId: number, tenantId: number, deviceId: number, deviceTenantId: number, capability?: string): Promise<boolean> {
  if (tenantId !== deviceTenantId) return false; // no god view for non-admins
  const member = await db('user_tenants').where({ user_id: userId, tenant_id: deviceTenantId }).first('user_id');
  if (!member) return false;
  if (!(await permissionService.canReadDevice(userId, deviceId, false))) return false;
  if (!capability) return true;
  return permissionService.canUseCapability(userId, deviceId, false, capability);
}

/** May a socket (identity frozen at handshake, role re-read live) receive this device's data? */
export async function socketMayReceiveDevice(
  ident: SocketIdent,
  deviceId: number,
  deviceTenantId: number,
  rule: DeviceAudienceRule = {},
): Promise<boolean> {
  if (!ident.tenantId) return false;
  const user = await db('users').where({ id: ident.userId, is_active: true }).first('role') as { role: string } | undefined;
  if (!user) return false;
  if (user.role === 'admin') {
    return ident.tenantId === deviceTenantId || (!!rule.masterGodView && isMasterTenant(ident.tenantId));
  }
  return nonAdminMay(ident.userId, ident.tenantId, deviceId, deviceTenantId, rule.capability);
}

async function cachedVerdict(ident: SocketIdent, deviceId: number, deviceTenantId: number, rule: DeviceAudienceRule): Promise<boolean> {
  const ttl = rule.cacheMs ?? 0;
  if (ttl <= 0) return socketMayReceiveDevice(ident, deviceId, deviceTenantId, rule);
  const key = `${ident.userId}:${ident.tenantId}:${deviceId}:${deviceTenantId}:${rule.capability ?? ''}:${rule.masterGodView ? 1 : 0}`;
  const now = Date.now();
  const hit = verdictCache.get(key);
  if (hit && hit.exp > now) return hit.v;
  const v = await socketMayReceiveDevice(ident, deviceId, deviceTenantId, rule);
  if (verdictCache.size >= CACHE_MAX) {
    for (const [k, e] of verdictCache) if (e.exp <= now) verdictCache.delete(k);
    if (verdictCache.size >= CACHE_MAX) verdictCache.clear();
  }
  verdictCache.set(key, { v, exp: now + ttl });
  return v;
}

/**
 * Emit one or more events about `deviceId` to the authorised sockets only:
 * the sockets of the device's tenant room (+ the master tenant room when the
 * rule has `masterGodView`), each one checked (one check per user and tenant
 * per call, shared by every event of the call). Never throws (socket not
 * ready, DB hiccup: nothing sent; the views poll / reload anyway). Returns the
 * number of sockets reached.
 */
export async function emitToDeviceAudience(
  deviceId: number,
  deviceTenantId: number,
  events: Array<[event: string, payload: unknown]>,
  rule: DeviceAudienceRule = {},
): Promise<number> {
  try {
    const did = Number(deviceId);
    const tid = Number(deviceTenantId);
    if (!Number.isInteger(did) || did <= 0 || !Number.isInteger(tid) || tid <= 0 || events.length === 0) return 0;
    if (deviceEventsTestSink.record) { deviceEventsTestSink.record(did, tid, events); return 1; }
    const io = getIO();
    const rooms = [`tenant:${tid}`];
    if (rule.masterGodView && !isMasterTenant(tid)) rooms.push(`tenant:${MASTER_TENANT_ID}`);
    const sockets = await io.in(rooms).fetchSockets();
    if (sockets.length === 0) return 0;
    const verdicts = new Map<string, Promise<boolean>>();
    let sent = 0;
    for (const s of sockets) {
      const userId = Number(s.data?.userId);
      const tenantId = s.data?.tenantId == null ? null : Number(s.data.tenantId);
      if (!Number.isInteger(userId) || userId <= 0) continue;
      const key = `${userId}:${tenantId}`;
      if (!verdicts.has(key)) {
        verdicts.set(key, cachedVerdict({ userId, tenantId }, did, tid, rule).catch(() => false));
      }
      if (await verdicts.get(key)) {
        for (const [event, payload] of events) s.emit(event, payload);
        sent++;
      }
    }
    return sent;
  } catch (err) {
    logger.debug({ err, deviceId, events: events.map((e) => e[0]) }, 'device audience: filtered emit skipped');
    return 0;
  }
}

/**
 * Of `candidateIds` (devices of the tenant `tenantId`), those a NON-admin
 * whose session is on `tenantId` may read with `capability`: member of the
 * tenant, device visible to their teams, capability granted. A constant
 * number of queries (getVisibleDeviceIds + devicesLackingCapability: no
 * per-device check). Not a member of the tenant → none.
 */
export async function devicesWithCapability(userId: number, tenantId: number, candidateIds: number[], capability: string): Promise<number[]> {
  const ids = [...new Set(candidateIds.map(Number).filter((n) => Number.isInteger(n) && n > 0))];
  if (ids.length === 0) return [];
  const member = await db('user_tenants').where({ user_id: userId, tenant_id: tenantId }).first('user_id');
  if (!member) return [];
  const visible = await permissionService.getVisibleDeviceIds(userId, false);
  if (visible !== 'all' && visible.length === 0) return [];
  const seen = visible === 'all' ? null : new Set(visible.map(Number));
  const shown = ids.filter((id) => seen === null || seen.has(id));
  if (shown.length === 0) return [];
  const lacking = new Set(await permissionService.devicesLackingCapability(userId, shown, capability));
  return shown.filter((id) => !lacking.has(id));
}

// ── Device state events (DEVICE_UPDATED / _DELETED / _OFFLINE / _APPROVED,
//    DEVICE_METRICS_PUSHED) ────────────────────────────────────────────────
//
// Until 2026-10 these went to the whole `tenant:<id>` room, some carrying the
// full device row: every member of the tenant got every device, visible to
// their teams or not. They now reach the device's READERS only — the rule of
// the device list (GET /api/devices): the device's tenant admins, the members
// of that tenant who see the device through their teams, and (unless the
// caller says otherwise) the platform admins on the master tenant (god view).
//
// They are frequent (status flips of a whole fleet, metrics on every push
// when someone is watching), so the per-socket check must not cost queries
// per device: each USER's audience profile (active, platform role, tenants,
// visible device ids) is read once and cached 5 s, whatever the number of
// devices — a revocation takes effect within 5 s. Per emit: one room lookup
// (local adapter) and a Set lookup per socket. Events of one device keep their
// order (one promise chain per device; the chain of an idle device is freed).

interface AudienceProfile { active: boolean; admin: boolean; tenants: Set<number>; visible: Set<number> | null }
const PROFILE_TTL_MS = 5_000;
const PROFILE_MAX = 10_000;
const profiles = new Map<number, { exp: number; p: Promise<AudienceProfile> }>();

async function loadProfile(userId: number): Promise<AudienceProfile> {
  const user = await db('users').where({ id: userId, is_active: true }).first('role') as { role: string } | undefined;
  if (!user) return { active: false, admin: false, tenants: new Set(), visible: null };
  if (user.role === 'admin') return { active: true, admin: true, tenants: new Set(), visible: null };
  const memberships = await db('user_tenants').where({ user_id: userId }).pluck('tenant_id') as number[];
  const visible = await permissionService.getVisibleDeviceIds(userId, false);
  return {
    active: true, admin: false,
    tenants: new Set(memberships.map(Number)),
    visible: new Set((visible === 'all' ? [] : visible).map(Number)),
  };
}

function profileOf(userId: number): Promise<AudienceProfile> {
  const now = Date.now();
  const hit = profiles.get(userId);
  if (hit && hit.exp > now) return hit.p;
  if (profiles.size >= PROFILE_MAX) {
    for (const [k, e] of profiles) if (e.exp <= now) profiles.delete(k);
    if (profiles.size >= PROFILE_MAX) profiles.clear();
  }
  const p = loadProfile(userId).catch(() => ({ active: false, admin: false, tenants: new Set<number>(), visible: null }));
  profiles.set(userId, { exp: now + PROFILE_TTL_MS, p });
  return p;
}

/** Forget the cached audience profiles (one user, or all): sessions killed,
 *  team or tenant membership changed (tests, admin actions). */
export function forgetDeviceEventProfiles(userId?: number): void {
  if (userId === undefined) profiles.clear();
  else profiles.delete(userId);
}

export interface DeviceEventOptions {
  /** Also the platform admins on the master tenant (god view). Default true. */
  masterGodView?: boolean;
  /** Rooms whose members were authorised when they joined (the metrics watch
   *  room, deviceMetricsWatch.service.ts): reached without a re-check. */
  trustedRooms?: string[];
  /** The payload names the device only (DEVICE_DELETED {id}): a member of the
   *  device's tenant gets it even when the device already left their (re-read)
   *  visible set — the row must leave their list. */
  idOnly?: boolean;
}

function profileMay(p: AudienceProfile, sessionTenant: number | null, deviceId: number, deviceTenantId: number, opts: DeviceEventOptions): boolean {
  if (!p.active || !sessionTenant) return false;
  if (p.admin) return sessionTenant === deviceTenantId || ((opts.masterGodView ?? true) && isMasterTenant(sessionTenant));
  if (sessionTenant !== deviceTenantId || !p.tenants.has(deviceTenantId)) return false;
  return !!opts.idOnly || !!p.visible?.has(deviceId);
}

const deviceChains = new Map<number, Promise<void>>();

async function sendDeviceEvents(deviceId: number, deviceTenantId: number, events: Array<[string, unknown]>, opts: DeviceEventOptions): Promise<void> {
  const io = getIO();
  const rooms = [`tenant:${deviceTenantId}`];
  if ((opts.masterGodView ?? true) && !isMasterTenant(deviceTenantId)) rooms.push(`tenant:${MASTER_TENANT_ID}`);
  const trusted = opts.trustedRooms ?? [];
  const [checked, trustedSockets] = await Promise.all([
    io.in(rooms).fetchSockets(),
    trusted.length ? io.in(trusted).fetchSockets() : Promise.resolve([] as Awaited<ReturnType<typeof io.fetchSockets>>),
  ]);
  const done = new Set<string>();
  for (const s of trustedSockets) {
    done.add(s.id);
    for (const [event, payload] of events) s.emit(event, payload);
  }
  for (const s of checked) {
    if (done.has(s.id)) continue;
    done.add(s.id);
    const userId = Number(s.data?.userId);
    if (!Number.isInteger(userId) || userId <= 0) continue;
    const sessionTenant = s.data?.tenantId == null ? null : Number(s.data.tenantId);
    const p = await profileOf(userId);
    if (!profileMay(p, sessionTenant, deviceId, deviceTenantId, opts)) continue;
    for (const [event, payload] of events) s.emit(event, payload);
  }
}

/**
 * Emit state events of ONE device to its readers only (see above). Fire and
 * forget: never throws, never blocks the caller; nothing is sent when no
 * socket sits in the rooms concerned (checked synchronously, local adapter).
 */
export function emitDeviceEvents(
  deviceId: number,
  deviceTenantId: number,
  events: Array<[event: string, payload: unknown]>,
  opts: DeviceEventOptions = {},
): void {
  try {
    const did = Number(deviceId);
    const tid = Number(deviceTenantId);
    if (!Number.isInteger(did) || did <= 0 || !Number.isInteger(tid) || tid <= 0 || events.length === 0) return;
    if (deviceEventsTestSink.record) { deviceEventsTestSink.record(did, tid, events); return; }
    let io: ReturnType<typeof getIO>;
    try { io = getIO(); } catch { return; } // socket layer not started (tests, boot)
    const roomsMap = io.sockets?.adapter?.rooms;
    if (roomsMap) {
      const names = [`tenant:${tid}`, ...((opts.masterGodView ?? true) ? [`tenant:${MASTER_TENANT_ID}`] : []), ...(opts.trustedRooms ?? [])];
      if (names.every((r) => (roomsMap.get(r)?.size ?? 0) === 0)) return;
    }
    const prev = deviceChains.get(did) ?? Promise.resolve();
    const next: Promise<void> = prev
      .then(() => sendDeviceEvents(did, tid, events, opts))
      .catch((err) => { logger.debug({ err, deviceId: did, events: events.map((e) => e[0]) }, 'device events: filtered emit skipped'); })
      .finally(() => { if (deviceChains.get(did) === next) deviceChains.delete(did); });
    deviceChains.set(did, next);
  } catch { /* never throws */ }
}
