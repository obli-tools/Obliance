import type { TFunction } from 'i18next';
import type { RemoteProtocol, RemoteSession } from '@obliance/shared';
import { apiErrorMessage } from '@/api/sshBastion.api';

/**
 * Client-side rules matching the server's remote-tunnel security:
 *   - the relay token (`sessionToken`) is only sent to the user who started
 *     the session (GET /remote/sessions and socket events strip it for
 *     everyone else), and the tunnel refuses any other user anyway;
 *   - so the UI only offers "View" / "Open" on sessions the current user
 *     started, and never opens a tunnel or adds a shell tab without a token.
 */

/** True when `userId` started this session and the client holds its relay token. */
export function canAttachRemoteSession(
  session: Pick<RemoteSession, 'startedBy'> & { sessionToken?: string | null } | null | undefined,
  userId: number | null | undefined,
): boolean {
  if (!session || userId == null || session.startedBy == null) return false;
  return !!session.sessionToken && Number(session.startedBy) === Number(userId);
}

/** Thrown when a freshly started session comes back without its relay token. */
export class MissingSessionTokenError extends Error {
  constructor() {
    super('Remote session has no relay token');
    this.name = 'MissingSessionTokenError';
  }
}

/**
 * Return the session's relay token, or throw MissingSessionTokenError.
 * Use it right after `remoteApi.startSession` (and in viewer `onReconnect`
 * callbacks: a throw there stops the viewer's auto-reconnect loop).
 */
export function requireSessionToken(session: { sessionToken?: string | null } | null | undefined): string {
  const token = session?.sessionToken;
  if (!token) throw new MissingSessionTokenError();
  return token;
}

/**
 * Message to toast for a failed `remoteApi.startSession`, or null when the
 * api client interceptor already showed one (401/403/423 with a server
 * message). A 409 on the VM console means the host agent is not connected.
 */
export function remoteStartErrorMessage(
  err: unknown,
  t: TFunction,
  fallback: string,
  protocol?: RemoteProtocol,
): string | null {
  if (err instanceof MissingSessionTokenError) {
    return t('remoteSessions.noToken', 'The server did not return a connection token for this session.');
  }
  const response = (err as { response?: { status?: number; data?: { error?: unknown; code?: unknown } } } | null)?.response;
  const serverMsg = typeof response?.data?.error === 'string' ? response.data.error : '';
  // The ObliReach agent's live channel uses another API key than the device (never relaxed).
  if (response?.status === 409 && response.data?.code === 'oblireach_key_mismatch') {
    return t('remoteSessions.reachKeyMismatch', 'The ObliReach agent is registered with another API key. Reinstall ObliReach from Obliance.');
  }
  // Windows older than build 17763: no pseudo console (ConPTY) for CMD / PowerShell.
  if (response?.status === 409 && response.data?.code === 'conpty_unsupported') {
    return t('remoteShell.conpty') || 'Remote console available from Windows 10 1809 / Windows Server 2019';
  }
  // VM console refusals with a machine code (server: vmConsole.service).
  const code = typeof response?.data?.code === 'string' ? response.data.code : '';
  if (protocol === 'vmconsole' && code) {
    switch (code) {
      case 'vm_off': return t('hyperv.console.err.vmOff', 'The virtual machine is turned off or saved: start it, then open the console.');
      case 'vm_not_found': return t('hyperv.console.err.vmNotFound', 'This virtual machine is not known on this host: refresh the VM list.');
      case 'vm_not_hyperv': return t('hyperv.console.err.notHyperV', 'This device is not a confirmed Hyper-V host.');
      case 'vmconsole_disabled': return t('hyperv.console.err.disabled', 'The VM console component is not installed on this host and its installation is disabled by policy.');
      case 'vm_console_busy': return serverMsg || t('hyperv.console.err.busy', 'The console of this VM is already open by another user.');
      // The server message carries the host's agent version and the minimum required.
      case 'vm_console_agent_outdated': return t('hyperv.console.err.agentOutdated', { defaultValue: 'The agent of this Hyper-V host is too old for the VM console: update the agent first. ({{detail}})', detail: serverMsg });
      case 'vm_console_unsupported': return t('hyperv.console.err.unsupported', 'The agent of this host (legacy agent) has no VM console: migrate it to the full agent.');
      case 'vm_console_os_unsupported': return t('hyperv.console.err.osUnsupported', 'The VM console needs Windows Server 2016 / Windows 10 or later on the Hyper-V host (not available on Windows Server 2012 / 2012 R2).');
      default: break;
    }
  }
  // The other 409 of POST /remote/sessions (legacy agent) keeps its own message.
  if (response?.status === 409 && protocol === 'vmconsole' && !/legacy/i.test(serverMsg) && !code) {
    return t('hyperv.consoleHostUnreachable', 'The host agent is not connected — the VM console needs a live agent connection.');
  }
  return apiErrorMessage(err, fallback);
}
