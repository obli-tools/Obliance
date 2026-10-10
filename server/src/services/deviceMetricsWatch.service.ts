import { db } from '../db';
import { permissionService } from './permission.service';
import { parseRequestDeviceId } from './deviceScope.service';
import { metricsWatchRoom } from '../utils/metricsRooms';

export { metricsWatchRoom, metricsRooms } from '../utils/metricsRooms';

/**
 * Live metrics of ONE device for a socket that is not in the device's tenant
 * room (DEVICE_METRICS_PUSHED goes to `tenant:<device tenant>`, and a socket
 * joins the room of its session's tenant at the handshake only): a master
 * tenant admin in god view, the Oblireach Desktop's multi-server mode (one
 * socket per server, its tenant pinned per request). The socket asks
 * DEVICE_METRICS_WATCH {deviceId, on}; once authorized it joins
 * `devicemetrics:<id>`, which the metric emitters address too (socket.io
 * sends one copy to a socket in both rooms).
 *
 * Authorization, like reading the device (and the file explorer's device
 * rule, fileExplorerGate.service.ts): an active user; admins any device;
 * others a member of the device's tenant who sees it (team scope). A watch
 * lasts METRICS_WATCH_TTL_MS: the client renews it (the Desktop every 50 s,
 * with its live-metrics request) or the socket leaves the room, so a right
 * taken away stops the stream within that time. At most METRICS_WATCH_MAX
 * devices per socket.
 */
export const METRICS_WATCH_TTL_MS = 120_000;
export const METRICS_WATCH_MAX = 16;

export type MetricsWatchFailure = 'invalid' | 'session' | 'not_found' | 'too_many';

export async function authorizeMetricsWatch(
  userId: number,
  rawDeviceId: unknown,
): Promise<{ ok: true; deviceId: number; tenantId: number } | { ok: false; code: MetricsWatchFailure }> {
  const deviceId = parseRequestDeviceId(rawDeviceId);
  if (deviceId === null) return { ok: false, code: 'invalid' };
  const user = await db('users').where({ id: userId }).first('is_active', 'role') as { is_active: boolean; role: string } | undefined;
  if (!user || user.is_active === false) return { ok: false, code: 'session' };
  const device = await db('devices').where({ id: deviceId }).first('id', 'tenant_id') as { id: number; tenant_id: number } | undefined;
  if (!device) return { ok: false, code: 'not_found' };
  if (user.role !== 'admin') {
    const member = await db('user_tenants').where({ user_id: userId, tenant_id: device.tenant_id }).first('user_id');
    if (!member) return { ok: false, code: 'not_found' };
    if (!(await permissionService.canReadDevice(userId, device.id, false))) return { ok: false, code: 'not_found' };
  }
  return { ok: true, deviceId: device.id, tenantId: device.tenant_id };
}

type WatchSocket = { id: string; join(room: string): unknown; leave(room: string): unknown };

// socket id -> device id -> expiry timer
const watches = new Map<string, Map<number, ReturnType<typeof setTimeout>>>();

/**
 * 'on' requests still being checked (the checks await the DB), per socket
 * and device. An 'off' — or a newer 'on' — that arrives meanwhile takes the
 * device's ticket away, so the late 'on' never joins (an 'off' is handled at
 * once, and would otherwise run BEFORE the 'on' it follows). Entries live
 * only while a check runs; at most METRICS_WATCH_PENDING_MAX per socket.
 */
export const METRICS_WATCH_PENDING_MAX = 32;
const pending = new Map<string, Map<number, symbol>>();

/** An 'on' starts its checks: its ticket, or null when the socket has too many in flight. */
export function watchIntent(socketId: string, deviceId: number): symbol | null {
  let mine = pending.get(socketId);
  if (!mine) { mine = new Map(); pending.set(socketId, mine); }
  if (!mine.has(deviceId) && mine.size >= METRICS_WATCH_PENDING_MAX) return null;
  const ticket = Symbol('watch');
  mine.set(deviceId, ticket);
  return ticket;
}

/** True while no 'off' / newer 'on' for this device came in since the ticket was taken. */
export function watchIntentCurrent(socketId: string, deviceId: number, ticket: symbol): boolean {
  return pending.get(socketId)?.get(deviceId) === ticket;
}

/** The 'on' is finished (joined, refused or superseded): its ticket goes, if still its own. */
export function watchIntentDone(socketId: string, deviceId: number, ticket: symbol): void {
  const mine = pending.get(socketId);
  if (mine?.get(deviceId) !== ticket) return;
  mine.delete(deviceId);
  if (mine.size === 0) pending.delete(socketId);
}

function dropIntent(socketId: string, deviceId: number): void {
  const mine = pending.get(socketId);
  if (!mine) return;
  mine.delete(deviceId);
  if (mine.size === 0) pending.delete(socketId);
}

/** Joins (or renews) the watch; false when the socket already watches too many devices. */
export function watchJoin(socket: WatchSocket, deviceId: number): boolean {
  let mine = watches.get(socket.id);
  if (!mine) { mine = new Map(); watches.set(socket.id, mine); }
  const prev = mine.get(deviceId);
  if (prev) clearTimeout(prev);
  else if (mine.size >= METRICS_WATCH_MAX) return false;
  socket.join(metricsWatchRoom(deviceId));
  const timer = setTimeout(() => { watchLeave(socket, deviceId); }, METRICS_WATCH_TTL_MS);
  (timer as { unref?: () => void }).unref?.();
  mine.set(deviceId, timer);
  return true;
}

export function watchLeave(socket: WatchSocket, deviceId: number): void {
  dropIntent(socket.id, deviceId); // an 'on' still being checked must not join after this
  const mine = watches.get(socket.id);
  const t = mine?.get(deviceId);
  if (t) clearTimeout(t);
  mine?.delete(deviceId);
  if (mine && mine.size === 0) watches.delete(socket.id);
  try { socket.leave(metricsWatchRoom(deviceId)); } catch { /* socket gone */ }
}

/** The socket is gone: its timers go (socket.io drops its rooms itself). */
export function watchForget(socketId: string): void {
  pending.delete(socketId);
  const mine = watches.get(socketId);
  if (!mine) return;
  for (const t of mine.values()) clearTimeout(t);
  watches.delete(socketId);
}

/** Tests: how many devices a socket watches. */
export function watchCount(socketId: string): number {
  return watches.get(socketId)?.size ?? 0;
}
