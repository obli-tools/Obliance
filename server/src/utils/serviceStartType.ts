import type { ServiceStartType } from '@obliance/shared';

// Mirror of SERVICE_START_TYPES (@obliance/shared), kept local so this file has
// no runtime import (node --test resolves @obliance/shared to its last build).
const SERVICE_START_TYPES: readonly ServiceStartType[] = ['auto', 'auto_delayed', 'manual', 'disabled'];

/**
 * Payload check of set_service_start_type (POST /api/commands). The agent
 * (service_start_type.go) re-validates everything and refuses its own
 * services; this keeps junk out of the queue / approvals and gives a clear
 * error before anything is sent.
 */

/** Same bound as the agent (Windows and systemd: 256 characters). */
export const SERVICE_NAME_MAX = 256;

export type ServiceStartTypeCheck =
  | { payload: { name: string; startType: ServiceStartType } }
  | { status: number; error: string };

export function checkServiceStartTypePayload(payload: unknown, osType: string | null | undefined): ServiceStartTypeCheck {
  const p = (payload && typeof payload === 'object' ? payload : {}) as Record<string, unknown>;
  const name = p.name;
  if (typeof name !== 'string' || name.length === 0 || name.length > SERVICE_NAME_MAX
    || name.trim() !== name || /[\u0000-\u001f\u007f-\u009f]/.test(name)) {
    return { status: 400, error: `payload.name must be a service name (1-${SERVICE_NAME_MAX} characters, no control characters)` };
  }
  const startType = p.startType;
  if (typeof startType !== 'string' || !(SERVICE_START_TYPES as readonly string[]).includes(startType)) {
    return { status: 400, error: `payload.startType must be one of ${SERVICE_START_TYPES.join(', ')}` };
  }
  const os = String(osType ?? '').toLowerCase();
  if (os === 'windows') {
    if (/[\/]/.test(name)) return { status: 400, error: 'payload.name is not a valid Windows service name' };
  } else if (os === 'linux') {
    if (startType === 'auto_delayed') {
      return { status: 400, error: 'Automatic (delayed start) is only available on Windows' };
    }
    if (name.startsWith('-') || !/^[A-Za-z0-9:_.\@-]+$/.test(name)) {
      return { status: 400, error: 'payload.name is not a valid systemd unit name' };
    }
  } else {
    return { status: 409, error: `Changing a service start type is not supported on ${os === 'macos' ? 'macOS' : 'this operating system'} (Windows and Linux systemd only)` };
  }
  return { payload: { name, startType: startType as ServiceStartType } };
}

/** v >= min, dotted numbers ('4.5.103'); unknown / unparsable = false. */
export function agentVersionAtLeast(v: string | null | undefined, min: string): boolean {
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
