import type { Device, CommandType } from '@obliance/shared';
import { agentSupportsCommand, SERVICE_START_TYPE_MIN_AGENT } from '@obliance/shared';

/** Whether a device's agent build can run a given command type. Legacy
 *  (Go 1.20) agents only support the LEGACY_AGENT_COMMANDS subset; modern
 *  / unknown agents support everything. */
export function isCommandSupported(device: Pick<Device, 'agentFlavor'>, command: CommandType): boolean {
  return agentSupportsCommand(device.agentFlavor, command);
}

/** Tooltip shown on a control disabled because the device's agent build
 *  can't run the underlying command. */
export function unsupportedTooltip(t: (k: string) => string): string {
  return t('commands.unsupportedOnAgent') || 'Not supported by this agent build';
}

/** Why the start type of a service cannot be changed on this device (null =
 *  it can): legacy agent, agent older than SERVICE_START_TYPE_MIN_AGENT
 *  (unknown version = refused, the server refuses it too), or an OS other than
 *  Windows / Linux (systemd). */
export function serviceStartTypeBlockReason(
  device: Pick<Device, 'agentFlavor' | 'agentVersion' | 'osType'>,
  t: (k: string, o?: Record<string, unknown>) => string,
): string | null {
  if (!isCommandSupported(device, 'set_service_start_type')) return unsupportedTooltip(t);
  if (device.osType !== 'windows' && device.osType !== 'linux') {
    return t('deviceDetail.services.startType.unsupportedOs') || 'Changing the start type is only available on Windows and Linux (systemd)';
  }
  if (!agentVersionAtLeast(device.agentVersion, SERVICE_START_TYPE_MIN_AGENT)) {
    return t('deviceDetail.services.startType.agentTooOld', { version: SERVICE_START_TYPE_MIN_AGENT })
      || 'Requires agent ' + SERVICE_START_TYPE_MIN_AGENT + ' or later';
  }
  return null;
}

/** v >= min for dotted agent versions ('4.5.103'); unknown / unparsable = false. */
export function agentVersionAtLeast(v: string | null | undefined, min: string): boolean {
  const a = String(v ?? '').trim().replace(/^v/i, '').split(/[.+ -]/).slice(0, 3).map((x) => Number.parseInt(x, 10));
  const b = min.split('.').map((x) => Number.parseInt(x, 10));
  if (a.length < 3 || a.some((n) => !Number.isFinite(n))) return false;
  for (let i = 0; i < 3; i++) {
    if (a[i] !== b[i]) return a[i] > b[i];
  }
  return true;
}
