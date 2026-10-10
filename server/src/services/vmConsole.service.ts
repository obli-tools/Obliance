// Hyper-V VM interactive console — helper bundle install lifecycle, state
// and policy (server side).
//
//  - The agent reports its helper bundle in every push (`vmConsole`,
//    agent/vmconsole_common.go VmConsoleReport) → devices.vmconsole_state.
//  - Every install is a REAL task (command_queue `install_vm_console`):
//    Pending → Sent → Running (progress: download x %, verify, extract) →
//    Success / Failure (agent error text) / Timeout — explicit, the "Install
//    now" / "Repair" button, the automatic install of the 'auto' policy and
//    the on-demand install started by a console opening alike. One task per
//    device at a time (a second click returns the running one).
//  - Policy: third kind of the update-policy cascade ('vmconsole'):
//    'auto' = pre-installed on confirmed Hyper-V hosts, 'manual' = on demand
//    (default), 'frozen' = never (explicit install refused, 409).
//  - Only on a CONFIRMED Hyper-V host (virtualization_host_type 'hyperv',
//    Windows, modern agent): never anything on another machine.
import { db } from '../db';
import { logger } from '../utils/logger';
import { SocketEvents } from '@obliance/shared';
import type { Command, VmConsoleState, VmConsoleStatus, ResolvedUpdatePolicy } from '@obliance/shared';
import { AppError } from '../middleware/errorHandler';
import { commandService } from './command.service';
import { emitToDeviceAudience, emitDeviceEvents, DEVICE_READERS } from './deviceAudience.service';
import { updatePolicyService } from './updatePolicy.service';
import { allowsAutomaticUpdate, allowsManualUpdate, describePolicySource } from '../utils/updatePolicy';
import { getDistFileInfo } from './oblireachAutoInstall.service';
import { isWindowsNt6 } from '../utils/deviceOs';
import { VM_CONSOLE_MIN_AGENT, versionAtLeast } from '../utils/vmConsoleCodes';

export const VMCONSOLE_BUNDLE = 'vmconsole.zip';
export const INSTALL_TYPE = 'install_vm_console';
/** Statuses of a task still in flight. */
const INFLIGHT = ['pending', 'sent', 'ack_running'];
/** A queued / delivered install waits this long for its agent. */
const INSTALL_EXPIRES_S = 30 * 60;
/** Running install with no progress for this long: timed out. */
const STALE_RUNNING_MS = 15 * 60_000;
/** Automatic install pass cadence, batch size, retry delay after a failure. */
const AUTO_EVERY_MS = 5 * 60_000;
const AUTO_BATCH = 5;
const AUTO_RETRY_AFTER_MS = 6 * 3600_000;

const SHA_RE = /^[0-9a-f]{64}$/;
const STATES = new Set(['not_installed', 'installing', 'installed', 'error']);

function str(v: unknown, max: number): string | null {
  if (typeof v !== 'string') return null;
  const s = v.replace(/[\u0000-\u001f\u007f]/g, ' ').trim();
  return s ? s.slice(0, max) : null;
}

/** Push-body `vmConsole` → stored state (null = not a valid report). */
export function sanitizeVmConsoleReport(raw: unknown, nowIso: string): VmConsoleState | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const r = raw as Record<string, unknown>;
  const state = typeof r.state === 'string' && STATES.has(r.state) ? r.state as VmConsoleState['state'] : null;
  if (!state) return null;
  const sha = typeof r.sha256 === 'string' && SHA_RE.test(r.sha256.toLowerCase()) ? r.sha256.toLowerCase() : null;
  const num = (v: unknown, lo: number, hi: number) => (typeof v === 'number' && Number.isFinite(v) ? Math.min(hi, Math.max(lo, Math.round(v))) : null);
  const iso = (v: unknown) => (typeof v === 'string' && !Number.isNaN(Date.parse(v)) ? new Date(v).toISOString() : null);
  return {
    state,
    sha256: sha,
    installedAt: iso(r.installedAt),
    protocol: num(r.protocol, 1, 99),
    built: str(r.built, 40),
    signed: typeof r.signed === 'boolean' ? r.signed : null,
    error: str(r.error, 500),
    phase: str(r.phase, 20),
    percent: num(r.percent, 0, 100),
    reportedAt: nowIso,
  };
}

/** Comparable form (reportedAt / progress excluded: no write per push while installing). */
function stateKey(s: VmConsoleState | null): string {
  if (!s) return 'null';
  return JSON.stringify([s.state, s.sha256, s.installedAt, s.protocol, s.built, s.signed, s.error, s.state === 'installing' ? s.phase : null]);
}

export function parseStoredVmConsoleState(v: unknown): VmConsoleState | null {
  if (!v) return null;
  try {
    const o = typeof v === 'string' ? JSON.parse(v) : v;
    return o && typeof o === 'object' && typeof (o as VmConsoleState).state === 'string' ? o as VmConsoleState : null;
  } catch { return null; }
}

/**
 * Next stored value from a push: undefined = keep (field absent: older
 * agent, or nothing to change), null = clear (the host lost its Hyper-V
 * role, or the legacy agent), else the new state (written on change only).
 */
export function nextVmConsoleState(args: {
  report: unknown; stored: unknown; hyperV: boolean | undefined; legacy: boolean; nowIso: string;
}): VmConsoleState | null | undefined {
  const stored = parseStoredVmConsoleState(args.stored);
  if (args.legacy || args.hyperV === false) return stored ? null : undefined;
  if (args.report === undefined) return undefined;
  const next = sanitizeVmConsoleReport(args.report, args.nowIso);
  if (!next) return undefined;
  return stateKey(next) === stateKey(stored) ? undefined : next;
}

/** The bundle this server ships, or null. */
export async function serverBundle(): Promise<{ sha256: string; size: number } | null> {
  try { return await getDistFileInfo(VMCONSOLE_BUNDLE); } catch { return null; }
}

export function deriveStatus(state: VmConsoleState | null, bundle: { sha256: string } | null): VmConsoleStatus['status'] {
  if (!state) return 'unknown';
  if (state.state === 'installed') {
    return bundle && state.sha256 !== bundle.sha256 ? 'outdated' : 'installed';
  }
  return state.state;
}

/** Install wanted by the 'auto' policy for this state. */
export function needsAutoInstall(state: VmConsoleState | null, bundle: { sha256: string } | null): boolean {
  if (!state || !bundle) return false;
  if (state.state === 'not_installed' || state.state === 'error') return true;
  return state.state === 'installed' && state.sha256 !== bundle.sha256;
}

interface HostRow {
  id: number; tenant_id: number; group_id: number | null; hostname?: string | null;
  virtualization_host_type: string | null; agent_flavor: string | null; os_type: string | null;
  vmconsole_state?: unknown; approval_status?: string | null;
  agent_version?: string | null; os_name?: string | null; os_version?: string | null; os_build?: string | null;
}

export function isConfirmedHyperVHost(d: Pick<HostRow, 'virtualization_host_type' | 'agent_flavor' | 'os_type'>): boolean {
  return d.virtualization_host_type === 'hyperv' && d.agent_flavor !== 'legacy' && d.os_type === 'windows';
}

const HOST_COLS = ['id', 'tenant_id', 'group_id', 'hostname', 'virtualization_host_type', 'agent_flavor', 'os_type', 'vmconsole_state', 'approval_status',
  'agent_version', 'os_name', 'os_version', 'os_build'];

/** VMCONSOLE_ALLOW_NT6=true lifts the Windows NT 6.x refusal (for a helper bundle rebuilt for Windows 8 / 2012). */
function nt6Allowed(): boolean { return String(process.env.VMCONSOLE_ALLOW_NT6 ?? '').trim().toLowerCase() === 'true'; }

export type VmConsoleHostRefusal = {
  code: 'vm_console_unsupported' | 'vm_console_agent_outdated' | 'vm_console_os_unsupported';
  message: string;
};

/**
 * Can this host run the VM console at all (beyond being a confirmed Hyper-V
 * host)? null = yes; otherwise the refusal (409) with its viewer code:
 *  - legacy agent (reduced Go 1.20 build): no console bridge at all;
 *  - agent older than VM_CONSOLE_MIN_AGENT: its bridge never reports a
 *    failure (bare relay close: the viewer reconnected in a loop);
 *  - Windows NT 6.x (7 / 8 / 8.1, Server 2008 R2 / 2012 / 2012 R2): the
 *    shipped helper (MSYS2 FreeRDP 3 -> FFmpeg avcodec -> librsvg / rav1e,
 *    Rust built for Windows 10: bcryptprimitives!ProcessPrng) cannot be
 *    loaded there (loader error before main). Unknown OS: allowed.
 */
export function vmConsoleHostRefusal(d: Pick<HostRow, 'agent_flavor' | 'agent_version' | 'os_type' | 'os_name' | 'os_version' | 'os_build'>): VmConsoleHostRefusal | null {
  if (d.agent_flavor === 'legacy') {
    return { code: 'vm_console_unsupported', message: 'The legacy agent has no VM console: migrate this host to the full agent first.' };
  }
  if (!versionAtLeast(d.agent_version, VM_CONSOLE_MIN_AGENT)) {
    return {
      code: 'vm_console_agent_outdated',
      message: `The agent of this host (${d.agent_version || 'unknown version'}) is too old for the VM console: update it to ${VM_CONSOLE_MIN_AGENT} or later.`,
    };
  }
  if (!nt6Allowed() && isWindowsNt6(d)) {
    return {
      code: 'vm_console_os_unsupported',
      message: 'The VM console needs Windows Server 2016 / Windows 10 or later on the Hyper-V host: its component cannot run on Windows Server 2008 R2 / 2012 / 2012 R2.',
    };
  }
  return null;
}

export async function inflightInstall(deviceId: number): Promise<any | null> {
  return await db('command_queue')
    .where({ device_id: deviceId, type: INSTALL_TYPE })
    .whereIn('status', INFLIGHT)
    .orderBy('created_at', 'desc')
    .first() ?? null;
}

async function lastFinishedInstall(deviceId: number): Promise<any | null> {
  return await db('command_queue')
    .where({ device_id: deviceId, type: INSTALL_TYPE })
    .whereIn('status', ['success', 'failure', 'timeout', 'cancelled'])
    .orderBy('created_at', 'desc')
    .first() ?? null;
}

async function emitCommand(row: any): Promise<void> {
  try {
    const cmd = commandService.rowToCommand(row);
    // The device's readers only (deviceAudience.service), not the whole tenant
    // room. Awaited by the callers: successive states keep their order.
    await emitToDeviceAudience(Number(row.device_id), Number(row.tenant_id), [[SocketEvents.COMMAND_UPDATED, cmd]], DEVICE_READERS);
  } catch { /* socket not ready */ }
}

/**
 * Queue (and push live when the agent is connected) an install task.
 * One per device: an install already in flight is returned (created:false).
 */
export async function requestInstall(args: {
  device: HostRow; createdBy?: number | null; force?: boolean;
  source: 'vmconsole_manual' | 'vmconsole_auto' | 'vmconsole_on_demand';
  priority?: 'low' | 'normal' | 'high';
  /** On-demand: the open_vm_console carries the task, nothing is pushed separately. */
  noPush?: boolean;
}): Promise<{ command: Command; created: boolean; delivered: boolean }> {
  const existing = await inflightInstall(args.device.id);
  if (existing) return { command: commandService.rowToCommand(existing), created: false, delivered: existing.status !== 'pending' };
  // The payload says WHICH bundle is wanted: an agent never answers
  // "already installed" for another build (otherwise "Update" on an
  // outdated helper ends in 5 ms, Success, nothing replaced). force is also
  // set when the installed build differs, for agents that ignore sha256.
  const bundle = await serverBundle();
  const installedSha = installedBundleSha(args.device.vmconsole_state);
  const outdated = !!(bundle && installedSha && installedSha !== bundle.sha256);
  const payload: Record<string, unknown> = {};
  if (args.force || outdated) payload.force = true;
  if (bundle) payload.sha256 = bundle.sha256;
  const cmd = await commandService.enqueue({
    deviceId: args.device.id,
    tenantId: Number(args.device.tenant_id),
    type: INSTALL_TYPE as any,
    payload,
    priority: args.priority ?? 'high',
    expiresInSeconds: INSTALL_EXPIRES_S,
    sourceType: args.source,
    createdBy: args.createdBy ?? undefined,
  });
  let delivered = false;
  if (args.noPush) {
    const [row] = await db('command_queue').where({ id: cmd.id, status: 'pending' })
      .update({ status: 'sent', sent_at: new Date(), updated_at: new Date() }).returning('*');
    if (row) await emitCommand(row);
    return { command: row ? commandService.rowToCommand(row) : cmd, created: true, delivered: true };
  }
  const { agentHub } = await import('./agentHub.service');
  delivered = agentHub.push(args.device.id, { type: 'command', id: cmd.id, commandType: INSTALL_TYPE, payload });
  if (delivered) {
    const [row] = await db('command_queue').where({ id: cmd.id, status: 'pending' })
      .update({ status: 'sent', sent_at: new Date(), updated_at: new Date() }).returning('*');
    if (row) {
      await emitCommand(row);
      return { command: commandService.rowToCommand(row), created: true, delivered };
    }
  }
  return { command: cmd, created: true, delivered };
}

/** The sha256 of the bundle a host reports as installed (vmconsole_state), or null. */
export function installedBundleSha(raw: unknown): string | null {
  const st = parseStoredVmConsoleState(raw);
  return st && st.state === 'installed' ? st.sha256 : null;
}

/** The explicit "Install now" / "Repair" (route): Hyper-V host + policy checks. */
export async function requestManualInstall(deviceId: number, tenantScope: { tenantId: number; isMaster: boolean }, userId: number, force: boolean) {
  const q = db('devices').where({ id: deviceId });
  if (!tenantScope.isMaster) q.where({ tenant_id: tenantScope.tenantId });
  const device = await q.first(...HOST_COLS) as HostRow | undefined;
  if (!device) throw new AppError(404, 'Device not found');
  if (!isConfirmedHyperVHost(device)) {
    throw new AppError(409, 'This device is not a confirmed Hyper-V host: the VM console is not installed on it', 'vmconsole_not_hyperv');
  }
  // An OS that cannot run the helper: never a 52 MB download for nothing.
  const osRefusal = vmConsoleHostRefusal(device);
  if (osRefusal?.code === 'vm_console_os_unsupported') throw new AppError(409, osRefusal.message, osRefusal.code);
  const pol = await updatePolicyService.resolve('vmconsole', { tenant_id: Number(device.tenant_id), group_id: device.group_id });
  if (!allowsManualUpdate(pol)) {
    if (pol.source === 'unresolved') throw new AppError(503, 'The install policy could not be read — try again in a few seconds', 'update_policy_unresolved');
    throw new AppError(409, `The VM console installation is disabled for this device (set by ${describePolicySource(pol)})`, 'update_policy_frozen');
  }
  if (!(await serverBundle())) {
    throw new AppError(409, 'This server ships no VM console bundle (vmconsole.zip missing from the release)', 'vmconsole_bundle_missing');
  }
  return requestInstall({ device, createdBy: userId, force, source: 'vmconsole_manual' });
}

/** GET console-status. */
export async function consoleStatus(deviceId: number, tenantScope: { tenantId: number; isMaster: boolean }): Promise<VmConsoleStatus> {
  const q = db('devices').where({ id: deviceId });
  if (!tenantScope.isMaster) q.where({ tenant_id: tenantScope.tenantId });
  const device = await q.first(...HOST_COLS) as HostRow | undefined;
  if (!device) throw new AppError(404, 'Device not found');
  const state = parseStoredVmConsoleState(device.vmconsole_state);
  const bundle = await serverBundle();
  const policy: ResolvedUpdatePolicy = await updatePolicyService.resolve('vmconsole', { tenant_id: Number(device.tenant_id), group_id: device.group_id });
  const inflight = await inflightInstall(deviceId);
  const last = await lastFinishedInstall(deviceId);
  const hyperVHost = isConfirmedHyperVHost(device);
  let status = deriveStatus(state, bundle);
  if (inflight) status = 'installing';
  return {
    hyperVHost,
    state,
    status,
    serverBundle: bundle,
    policy,
    installCommand: inflight ? commandService.rowToCommand(inflight) : null,
    lastInstall: last ? commandService.rowToCommand(last) : null,
    canInstall: hyperVHost && !!bundle && allowsManualUpdate(policy) && !inflight
      && vmConsoleHostRefusal(device)?.code !== 'vm_console_os_unsupported',
  };
}

/** A terminal install ack: the device's state follows at once (no wait for the next push). */
export async function onInstallAck(deviceId: number, tenantId: number, status: string, result: any): Promise<void> {
  try {
    const row = await db('devices').where({ id: deviceId }).first('vmconsole_state');
    const prev = parseStoredVmConsoleState(row?.vmconsole_state);
    const now = new Date().toISOString();
    let next: VmConsoleState;
    if (status === 'success') {
      next = {
        state: 'installed',
        sha256: typeof result?.sha256 === 'string' && SHA_RE.test(result.sha256) ? result.sha256 : prev?.sha256 ?? null,
        installedAt: typeof result?.installedAt === 'string' ? result.installedAt : prev?.installedAt ?? now,
        protocol: typeof result?.protocol === 'number' ? result.protocol : prev?.protocol ?? null,
        built: prev?.built ?? null,
        signed: typeof result?.signed === 'boolean' ? result.signed : prev?.signed ?? null,
        error: null, phase: null, percent: null, reportedAt: now,
      };
    } else {
      const err = str(result?.error, 500) ?? (status === 'timeout' ? 'Install timed out' : 'Install failed');
      next = prev?.state === 'installed'
        ? { ...prev, error: err, phase: null, percent: null, reportedAt: now }
        : { state: 'error', sha256: null, installedAt: null, protocol: null, built: null, signed: null, error: err, phase: null, percent: null, reportedAt: now };
    }
    await db('devices').where({ id: deviceId }).update({ vmconsole_state: JSON.stringify(next) });
    emitDeviceEvents(deviceId, tenantId, [[SocketEvents.DEVICE_UPDATED, { deviceId, vmConsoleState: next }]]);
  } catch (err) {
    logger.warn({ err, deviceId }, 'vm console: install ack state update failed');
  }
}

/**
 * Sweep pass (command.service sweepExpired, every minute):
 *  - a RUNNING install with no progress for 15 min is timed out (agent
 *    restarted / offline mid-download: the task never stays "Running");
 *  - every 5 min, the 'auto' policy queues installs on confirmed Hyper-V
 *    hosts whose helper is missing or differs from the shipped bundle.
 */
let lastAuto = 0;
export async function vmConsoleTick(now = Date.now()): Promise<{ timedOut: number; queued: number }> {
  let timedOut = 0;
  let queued = 0;
  try {
    const stale = await db('command_queue')
      .where({ type: INSTALL_TYPE, status: 'ack_running' })
      .where('updated_at', '<', new Date(now - STALE_RUNNING_MS))
      .update({
        status: 'timeout', finished_at: new Date(now), updated_at: new Date(now),
        result: JSON.stringify({ error: 'No progress from the agent for 15 minutes: install abandoned (agent restarted or offline). Retry with "Install now".' }),
      })
      .returning('*');
    for (const row of stale) {
      timedOut++;
      await emitCommand(row);
      await onInstallAck(Number(row.device_id), Number(row.tenant_id), 'timeout', typeof row.result === 'string' ? JSON.parse(row.result) : row.result);
    }
  } catch (err) {
    logger.error({ err }, 'vm console: stale install sweep failed');
  }
  if (now - lastAuto < AUTO_EVERY_MS) return { timedOut, queued };
  lastAuto = now;
  try {
    const bundle = await serverBundle();
    if (!bundle) return { timedOut, queued };
    const rows = await db('devices')
      .where({ virtualization_host_type: 'hyperv', os_type: 'windows', approval_status: 'approved' })
      .where((w) => w.whereNull('agent_flavor').orWhereNot('agent_flavor', 'legacy'))
      .whereNotNull('vmconsole_state')
      .select(...HOST_COLS) as HostRow[];
    const wanted = rows.filter((r) => isConfirmedHyperVHost(r) && needsAutoInstall(parseStoredVmConsoleState(r.vmconsole_state), bundle)
      && vmConsoleHostRefusal(r)?.code !== 'vm_console_os_unsupported');
    if (!wanted.length) return { timedOut, queued };
    const pol = await updatePolicyService.resolveMany('vmconsole', wanted.map((r) => ({ id: r.id, tenant_id: Number(r.tenant_id), group_id: r.group_id })));
    const { agentHub } = await import('./agentHub.service');
    for (const r of wanted) {
      if (queued >= AUTO_BATCH) break;
      const p = pol.get(Number(r.id));
      if (!p || !allowsAutomaticUpdate(p)) continue;
      if (!agentHub.isConnected(Number(r.id))) continue;
      if (await inflightInstall(Number(r.id))) continue;
      const lastFail = await db('command_queue')
        .where({ device_id: r.id, type: INSTALL_TYPE })
        .whereIn('status', ['failure', 'timeout'])
        .where('created_at', '>', new Date(now - AUTO_RETRY_AFTER_MS))
        .first('id');
      if (lastFail) continue;
      const out = await requestInstall({ device: r, source: 'vmconsole_auto', priority: 'low' });
      if (out.created) {
        queued++;
        logger.info({ deviceId: r.id, commandId: out.command.id }, 'vm console: automatic install queued (policy auto)');
      }
    }
  } catch (err) {
    logger.error({ err }, 'vm console: automatic install pass failed');
  }
  return { timedOut, queued };
}

/** Tests: run the automatic pass at the next tick. */
export function __resetVmConsoleTickForTests(): void { lastAuto = 0; }

export { vmConsoleErrorCode } from '../utils/vmConsoleCodes';

// ── Console session preparation (POST /api/remote/sessions, protocol vmconsole) ──

const GUID_RE = /^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$/;

export interface VmConsolePrepared {
  vmId: string;
  vmName: string;
  /** Effective install policy sent to the agent ('frozen' = do not install). */
  installPolicy: 'auto' | 'manual' | 'frozen';
  /** On-demand install task created for this opening (helper missing). */
  installCommandId: string | null;
  /** Sessions of the SAME user on this VM, to end before the new one. */
  replaceSessionIds: string[];
}

/**
 * Checks of a console opening, beyond the remote-session ones (capability
 * 'remote', restriction, legacy agent) done by the route:
 *  - a bare GUID, a VM of THIS host (tenant-scoped), not off / saved;
 *  - a confirmed Hyper-V host;
 *  - privacy mode → 423 unless the user holds the 'remote' unlock;
 *  - one console per VM: another user's open console → 409
 *    vm_console_busy (an administrator may take it over); the caller's own
 *    previous one is replaced;
 *  - helper missing + policy 'frozen' → 409 vmconsole_disabled; helper
 *    missing otherwise → an on-demand install TASK (visible in Tasks).
 */
export async function prepareConsoleSession(args: {
  deviceId: number; tenantId: number; userId: number; isAdmin: boolean; vmId: unknown; takeover?: boolean;
}): Promise<VmConsolePrepared> {
  const vmId = typeof args.vmId === 'string' ? args.vmId.trim() : '';
  if (!GUID_RE.test(vmId)) throw new AppError(400, 'vmId must be the VM GUID', 'vm_id_invalid');
  const device = await db('devices').where({ id: args.deviceId })
    .first(...HOST_COLS, 'privacy_mode_enabled') as (HostRow & { privacy_mode_enabled?: boolean }) | undefined;
  if (!device) throw new AppError(404, 'Device not found');
  // Agent / OS able to run the console, BEFORE anything is created (no
  // session, no install task): a clear 409 instead of a session the host
  // closes at once (the viewer used to reconnect to it in a loop).
  const refusal = vmConsoleHostRefusal(device);
  if (refusal) throw new AppError(409, refusal.message, refusal.code);
  if (!isConfirmedHyperVHost(device)) {
    throw new AppError(409, 'This device is not a confirmed Hyper-V host', 'vm_not_hyperv');
  }
  const { privacyGateService } = await import('./privacyGate.service');
  if (device.privacy_mode_enabled && !privacyGateService.get(args.userId, args.deviceId, 'remote')) {
    throw new AppError(423, "Privacy mode is active on this device — unlock required for feature 'remote'", 'privacy_mode');
  }
  const vm = await db('device_virtual_machines')
    .where({ host_device_id: args.deviceId, tenant_id: device.tenant_id })
    .whereRaw('lower(vm_id) = ?', [vmId.toLowerCase()])
    .first('vm_id', 'name', 'state') as { vm_id: string; name: string; state: string } | undefined;
  if (!vm) throw new AppError(404, 'This virtual machine is not known on this host (refresh the VM list)', 'vm_not_found');
  if (vm.state === 'off' || vm.state === 'saved') {
    throw new AppError(409, `The virtual machine "${vm.name}" is ${vm.state === 'off' ? 'turned off' : 'in saved state'}: start it first`, 'vm_off');
  }

  // One interactive console per VM.
  const open = await db('remote_sessions as rs')
    .leftJoin('users as u', 'u.id', 'rs.started_by')
    .where({ 'rs.device_id': args.deviceId, 'rs.protocol': 'vmconsole' })
    .whereRaw('lower(rs.vm_id) = ?', [vm.vm_id.toLowerCase()])
    .whereIn('rs.status', ['waiting', 'connecting', 'active'])
    .select('rs.id', 'rs.started_by', 'rs.started_at', 'u.display_name', 'u.username') as Array<{
      id: string; started_by: number; started_at: Date | string; display_name: string | null; username: string | null;
    }>;
  const replaceSessionIds: string[] = [];
  for (const s of open) {
    if (Number(s.started_by) === Number(args.userId)) { replaceSessionIds.push(String(s.id)); continue; }
    if (args.isAdmin && args.takeover) { replaceSessionIds.push(String(s.id)); continue; }
    const who = s.display_name || s.username || `#${s.started_by}`;
    throw new AppError(409, `The console of "${vm.name}" is already open by ${who}. Only one interactive console per VM: ask them to close it${args.isAdmin ? ', or take it over' : ''}.`, 'vm_console_busy');
  }

  const pol = await updatePolicyService.resolve('vmconsole', { tenant_id: Number(device.tenant_id), group_id: device.group_id });
  const installPolicy: VmConsolePrepared['installPolicy'] = pol.source === 'unresolved' ? 'frozen' : pol.policy;
  const state = parseStoredVmConsoleState(device.vmconsole_state);
  let installCommandId: string | null = null;
  // Only an agent that reports its helper state knows the install task id.
  if (state && state.state !== 'installed') {
    if (installPolicy === 'frozen') {
      throw new AppError(409, 'The VM console component is not installed on this host and its installation is disabled by policy.', 'vmconsole_disabled');
    }
    const inflight = await inflightInstall(args.deviceId);
    if (inflight) {
      installCommandId = null; // the running task finishes by itself; the agent joins its download
    } else if (await serverBundle()) {
      const out = await requestInstall({ device, createdBy: args.userId, source: 'vmconsole_on_demand', noPush: true });
      installCommandId = out.command.id;
    }
  }
  return { vmId: vm.vm_id, vmName: vm.name, installPolicy, installCommandId, replaceSessionIds };
}

/** The on-demand install task of an opening that could not be delivered. */
export async function failOnDemandInstall(commandId: string | null, reason: string): Promise<void> {
  if (!commandId) return;
  try {
    const rows = await db('command_queue').where({ id: commandId }).whereIn('status', INFLIGHT)
      .update({ status: 'failure', finished_at: new Date(), updated_at: new Date(), result: JSON.stringify({ error: reason }) })
      .returning('*');
    for (const r of rows) await emitCommand(r);
  } catch (err) {
    logger.warn({ err, commandId }, 'vm console: failing the on-demand install task failed');
  }
}
