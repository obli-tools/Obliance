/**
 * A device's OS as the agents report it (devices.os_type / os_name /
 * os_version / os_build), read the same way by every route that decides what
 * a device can do: its family, and on Windows its build number.
 *
 *   - modern agent (gopsutil): os_type 'windows', os_name "Microsoft Windows
 *     Server 2012 R2 Standard", os_version "6.3.9600.20563 Build 9600.20563";
 *   - legacy agent (Go 1.20): os_type 'windows', os_name "windows",
 *     os_version "Windows Server 2008 R2 Standard (Build 7601)";
 *   - os_build: only written by POST /api/agent/register (rarely set).
 *
 * The remote consoles on Windows (CMD, PowerShell) need the pseudo console
 * (ConPTY): Windows 10 1809 / Windows Server 2019, build 17763, or later.
 */
export const CONPTY_MIN_WINDOWS_BUILD = 17763;

/** The remote shell protocols (the agent's PTY / ConPTY tunnel). */
export const SHELL_PROTOCOLS: ReadonlySet<string> = new Set(['ssh', 'cmd', 'powershell']);

export type DeviceOsRow = {
  os_type?: string | null;
  os_name?: string | null;
  os_version?: string | null;
  os_build?: string | null;
};

const str = (v: unknown): string => (typeof v === 'string' ? v : '');

/** A Windows build number in a plausible range, else null. */
function build(n: number): number | null {
  return Number.isInteger(n) && n >= 1000 && n <= 999999 ? n : null;
}

/** True when the device runs Windows, from its type or (type unknown) its name / version. */
export function isWindowsOs(dev: DeviceOsRow | null | undefined): boolean {
  if (!dev) return false;
  const type = str(dev.os_type).toLowerCase();
  if (type === 'windows') return true;
  if (type && type !== 'other' && type !== 'unknown') return false; // (macos, linux, freebsd)
  return /\bwindows\b|microsoft/i.test(str(dev.os_name)) || /\bwindows\b/i.test(str(dev.os_version))
    || /^\s*(?:6|10)\.\d+\.\d{4,6}(?:\.\d+)?\s+build\s+\d/i.test(str(dev.os_version));
}

/**
 * The Windows build number of a device (9600, 14393, 17763, 26100…), null
 * when it is not Windows or the build is not reported.
 */
export function windowsBuildOf(dev: DeviceOsRow | null | undefined): number | null {
  if (!dev || !isWindowsOs(dev)) return null;
  const b = /^\s*(\d{4,6})\b/.exec(str(dev.os_build));
  if (b) { const n = build(Number(b[1])); if (n !== null) return n; }
  for (const s of [str(dev.os_version), str(dev.os_name)]) {
    const m = /\bbuild\s+(\d{4,6})\b/i.exec(s) ?? /^\s*(?:6|10)\.\d+\.(\d{4,6})\b/.exec(s);
    if (m) { const n = build(Number(m[1])); if (n !== null) return n; }
  }
  return null;
}

/**
 * True when the device is Windows with a KNOWN build older than 17763: its
 * agent cannot start CMD / PowerShell (no ConPTY). Unknown build: false (the
 * agent itself refuses with a clear message).
 */
export function conptyUnsupported(dev: DeviceOsRow | null | undefined): boolean {
  const b = windowsBuildOf(dev);
  return b !== null && b < CONPTY_MIN_WINDOWS_BUILD;
}

/** First Windows 10 / Server 2016 build (10.0.10240): below it = Windows NT 6.x. */
export const WINDOWS10_MIN_BUILD = 10240;

/**
 * True when the device runs Windows NT 6.x (Windows 7 SP1 / 8 / 8.1, Server
 * 2008 R2 / 2012 / 2012 R2): it needs the agent's "nt6" build line (Go 1.20)
 * — obliance-agent-nt6[-x86].msi, oblireach-agent-nt6.msi — since the modern
 * MSIs refuse Windows < 10. Read from the build when known (< 10240), else
 * from a "6.x" version (gopsutil "6.3.9600…") or the product name (legacy
 * agent "Windows Server 2008 R2 Standard (Build 7601)", a bare name). Unknown
 * (no build, no recognisable version / name): false — never guessed.
 */
export function isWindowsNt6(dev: DeviceOsRow | null | undefined): boolean {
  if (!dev || !isWindowsOs(dev)) return false;
  const b = windowsBuildOf(dev);
  if (b !== null) return b < WINDOWS10_MIN_BUILD;
  if (/^\s*6\.\d+(?:\.|\s|$)/.test(str(dev.os_version))) return true;
  if (/^\s*10\.\d+(?:\.|\s|$)/.test(str(dev.os_version))) return false;
  const name = `${str(dev.os_name)} ${str(dev.os_version)}`;
  if (/\bwindows\s+(?:10|11)\b|\bserver\s+20(?:16|19|22|25)\b/i.test(name)) return false;
  return /\bwindows\s+(?:7|8(?:\.1)?|vista)\b|\bserver\s+20(?:08|12)\b/i.test(name);
}

/** isWindowsNt6 over a camelCase Device (API / service objects). */
export function isWindowsNt6Device(d: { osType?: string | null; osName?: string | null; osVersion?: string | null; osBuild?: string | null } | null | undefined): boolean {
  if (!d) return false;
  return isWindowsNt6({ os_type: d.osType, os_name: d.osName, os_version: d.osVersion, os_build: d.osBuild });
}
