// VM console (Hyper-V) error codes carried by agent error texts — pure, no
// imports (remote.service.ts reads them when it fails a session from an ack).
// Producer: agent/vmconsole_common.go (vmCodedError: "code: message").

/** Viewer error code carried by an agent error text "code: message". */
const VM_CODE_LIST = [
  'vm_off', 'vm_not_found', 'vm_not_hyperv', 'vmconsole_disabled', 'vmconsole_install_failed',
  'vm_console_start_failed', 'vm_console_connect_failed', 'vm_console_taken', 'vm_console_auth',
  'vm_console_closed', 'vm_console_lost', 'vm_console_encoder', 'vm_console_ended', 'relay_refused',
  // Server-side refusals / outcomes (also stored as "code: message" in end_reason).
  'vm_console_agent_outdated', 'vm_console_unsupported', 'vm_console_os_unsupported', 'vm_console_agent_timeout',
] as const;
export type VmConsoleErrorCode = typeof VM_CODE_LIST[number];
const VM_CODES: ReadonlySet<string> = new Set(VM_CODE_LIST);
export function vmConsoleErrorCode(text: string | null | undefined): { code: VmConsoleErrorCode | 'privacy_mode'; message: string } | null {
  if (!text) return null;
  const m = /^([a-z_]{3,40}): ([\s\S]*)$/.exec(text.trim());
  if (m && VM_CODES.has(m[1])) return { code: m[1] as VmConsoleErrorCode, message: m[2].trim() };
  if (/privacy mode/i.test(text)) return { code: 'privacy_mode', message: text };
  return null;
}

/**
 * First agent version whose VM console bridge reports its failures (coded
 * relay `error` + coded ack, protocol-2 helper, install task). Older agents
 * (4.5.65 – 4.5.86) spawn the helper AFTER pairing and, when it dies, only
 * close the relay: the viewer saw a bare close (1005) and reconnected in a
 * loop. They are refused up front (409 vm_console_agent_outdated).
 */
export const VM_CONSOLE_MIN_AGENT = '4.5.87';

/** "4.5.87" >= "4.5.79" (numeric parts; anything unreadable = not at least). */
export function versionAtLeast(v: string | null | undefined, min: string): boolean {
  if (!v) return false;
  const a = String(v).trim().replace(/^v/i, '').split(/[.\-+ ]/).slice(0, 3).map((x) => Number.parseInt(x, 10));
  const b = min.split('.').map((x) => Number.parseInt(x, 10));
  if (a.length < 3 || a.some((n) => !Number.isFinite(n))) return false;
  for (let i = 0; i < 3; i++) {
    if (a[i] > b[i]) return true;
    if (a[i] < b[i]) return false;
  }
  return true;
}

/** Relay notice the viewer gets (same shape as remote.service RelayErrorNotice). */
export interface VmConsoleNotice { type: 'error'; code: string; message: string; retry: false; agentCode?: string }

/**
 * The notice for a VM console session that is ALREADY OVER when its viewer
 * (re)connects (a fast failure on the host ends it before the browser
 * upgrade arrives): built from the stored end_reason, so the viewer shows
 * the real cause instead of a bare refused upgrade (1006) and stops.
 */
export function vmConsoleEndNotice(endReason: string | null | undefined, status: string | null | undefined): VmConsoleNotice {
  const coded = vmConsoleErrorCode(endReason ?? '');
  if (coded) return { type: 'error', code: coded.code, agentCode: coded.code, message: coded.message, retry: false };
  const r = String(endReason ?? '');
  if (r === 'timeout') return { type: 'error', code: 'vm_console_agent_timeout', message: 'The host agent did not open the VM console in time.', retry: false };
  if (r.startsWith('command_failure')) {
    return { type: 'error', code: 'agent_error', message: r.replace(/^command_failure:?\s*/, '') || 'The host agent could not open the VM console.', retry: false };
  }
  if (r === 'replaced' || r === 'taken_over' || r === 'user_disconnect') {
    return { type: 'error', code: 'session_closed', message: `VM console session closed (${r}).`, retry: false };
  }
  return { type: 'error', code: 'vm_console_ended', message: `The VM console session already ended on the host (${r || status || 'closed'}).`, retry: false };
}

/** A VM console agent end must attach this soon after the open command. */
export const VM_CONSOLE_AGENT_ATTACH_MS = 60_000;

/**
 * The host agent closed a VM console relay: what the viewer is told and the
 * end reason stored. `agentError`: the {"type":"error"} the agent itself sent
 * (agents >= 4.5.87, already relayed to an attached viewer: no second
 * notice); `pictures`: the agent sent at least one frame.
 *  - agent error  -> end reason "code: message" (a late viewer gets it);
 *  - no error, no picture -> vm_console_ended, retry:false (an old agent, or
 *    a helper that died before its first frame: reconnecting cannot help);
 *  - no error after pictures -> vm_console_ended too (the stream stopped
 *    without a reason; the viewer offers Retry, it never loops by itself).
 */
export function vmConsoleAgentCloseOutcome(
  agentError: { code: string; message: string } | undefined,
  pictures: boolean,
): { endReason: string; notice: VmConsoleNotice | null } {
  if (agentError && agentError.code) {
    return { endReason: `${agentError.code}: ${agentError.message}`.slice(0, 100), notice: null };
  }
  const message = pictures
    ? 'The host agent closed the VM console without a reason (agent restarted, or the console helper stopped).'
    : 'The host closed the VM console before its first picture (the console helper did not start on the host: see the agent log).';
  return { endReason: `vm_console_ended: ${message}`.slice(0, 100), notice: { type: 'error', code: 'vm_console_ended', agentCode: 'vm_console_ended', message, retry: false } };
}
