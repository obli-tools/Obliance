import type { TFunction } from 'i18next';
import type { Device } from '@obliance/shared';
import type { ShellProtocol } from '@/store/remoteShellStore';

/**
 * Which remote consoles a device offers, and why one is greyed out — the
 * same rules as the server (utils/deviceOs.ts, POST /api/remote/sessions) and
 * the Oblireach Desktop (agent_tools.go):
 *   - the OS family is read from every report (osType, then the OS name and
 *     version: an older or odd report can leave osType at 'other'); an
 *     unknown OS gets NO console (never a guessed SSH);
 *   - CMD / PowerShell run in the Windows pseudo console (ConPTY) from
 *     Windows 10 1809 / Windows Server 2019 (build 17763) on. A build KNOWN
 *     to be older (2012 R2: 9600, 2016: 14393) no longer greys them out — the
 *     agent falls back to a degraded plain-pipe shell (no cursor addressing,
 *     no live resize, no full-screen TUI: tunnel_shell_pipe_windows.go) rather
 *     than refusing. `shellDegradedReason` surfaces that as a hint, never a
 *     block;
 *   - the legacy agent (Go 1.20) has no tunnels at all — this one still blocks.
 */
export const CONPTY_MIN_WINDOWS_BUILD = 17763;

type OsInfo = Partial<Pick<Device, 'osType' | 'osName' | 'osVersion' | 'osBuild' | 'agentFlavor'>> | null | undefined;
export type OsFamily = 'windows' | 'macos' | 'unix';

function osWord(v: unknown): OsFamily | null {
  const s = (typeof v === 'string' ? v : '').toLowerCase().trim();
  if (!s || s === 'other' || s === 'unknown') return null;
  if (/mac\s?os|darwin|os x\b|macintosh/.test(s)) return 'macos';
  if (/windows|^win(32|64|nt)?$|microsoft/.test(s)) return 'windows';
  if (/^\d+\.\d+\.\d{4,6}(\.\d+)?\s+build\s+\d/.test(s)) return 'windows'; // gopsutil: "6.3.9600.20563 Build 9600.20563"
  if (/linux|bsd|ubuntu|debian|cent\s?os|red\s?hat|rhel|fedora|suse|alpine|\barch\b|rocky|alma|amazon|gentoo|\bmint\b|raspbian|proxmox|unix/.test(s)) return 'unix';
  return null;
}

/** The device's OS family, every report crossed; null when unknown. */
export function deviceOsFamily(d: OsInfo): OsFamily | null {
  if (!d) return null;
  for (const v of [d.osType, d.osName, d.osVersion]) {
    const k = osWord(v);
    if (k) return k;
  }
  return null;
}

/** The Windows build number (9600, 14393, 17763…), null when not Windows or not reported. */
export function windowsBuild(d: OsInfo): number | null {
  if (!d || deviceOsFamily(d) !== 'windows') return null;
  const ok = (n: number) => Number.isInteger(n) && n >= 1000 && n <= 999999;
  const b = /^\s*(\d{4,6})\b/.exec(String(d.osBuild ?? ''));
  if (b && ok(Number(b[1]))) return Number(b[1]);
  for (const s of [d.osVersion, d.osName]) {
    const text = typeof s === 'string' ? s : '';
    const m = /\bbuild\s+(\d{4,6})\b/i.exec(text) ?? /^\s*(?:6|10)\.\d+\.(\d{4,6})\b/.exec(text);
    if (m && ok(Number(m[1]))) return Number(m[1]);
  }
  return null;
}

/** True when the device is Windows with a KNOWN build older than 17763. */
export function conptyMissing(d: OsInfo): boolean {
  const b = windowsBuild(d);
  return b !== null && b < CONPTY_MIN_WINDOWS_BUILD;
}

/** The consoles of the device's OS: Windows CMD + PowerShell, macOS / Linux / BSD SSH, unknown none. */
export function shellProtocolsFor(d: OsInfo): ShellProtocol[] {
  const k = deviceOsFamily(d);
  return k === 'windows' ? ['cmd', 'powershell'] : k ? ['ssh'] : [];
}

/** Why the OS offers no console (unknown), or null. */
export function shellUnknownReason(d: OsInfo, t: TFunction): string | null {
  return d && !shellProtocolsFor(d).length
    ? (t('remoteShell.osUnknown') || 'Unknown operating system: no remote console offered')
    : null;
}

/** Why this console cannot open on the device at all (legacy agent), or null. */
export function shellBlockReason(d: OsInfo, _protocol: string, t: TFunction): string | null {
  if (!d) return null;
  if (d.agentFlavor === 'legacy') {
    return t('remoteShell.legacy') || 'Legacy agent: remote sessions are not available (upgrade the agent)';
  }
  return null;
}

/**
 * Why this console will open in DEGRADED mode (no cursor addressing, no live
 * resize, no full-screen TUI) rather than not open at all — a hint only,
 * never a reason to disable the button. The tunnel's own "mode" control frame
 * (pty: "pipe") is the definitive signal once connected; this lets the UI
 * warn ahead of the click.
 */
export function shellDegradedReason(d: OsInfo, protocol: string, t: TFunction): string | null {
  if (!d || d.agentFlavor === 'legacy') return null;
  if ((protocol === 'cmd' || protocol === 'powershell') && conptyMissing(d)) {
    return t('remoteShell.conptyDegraded') || 'Older Windows: this console will open in degraded mode (no full-screen apps, no live resize)';
  }
  return null;
}
