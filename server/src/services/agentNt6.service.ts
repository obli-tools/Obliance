import { isWindowsNt6, type DeviceOsRow } from '../utils/deviceOs';

// ── Windows "nt6" build line of the Obliance agent (server side) ────────────
//
// Windows 7 SP1 / 8.1 / Server 2008 R2 / 2012 / 2012 R2 (NT 6.x) run the
// agent built with Go 1.20 ("nt6"): obliance-agent-nt6.msi /
// obliance-agent-nt6-x86.msi (agent/BUILD_NT6.txt). The MODERN MSIs refuse
// Windows < 10 (launch condition).
//
// Self-update of agents already deployed on 8.1 / 2012 / 2012 R2 (modern
// build, older version): they download `obliance-agent.msi` (or -x86) from
// /api/agent/download/ — an anonymous GET (no device header) — and msiexec it.
// The modern MSI would now refuse → update_error. The server answers them
// with the nt6 MSI of the same architecture (same UpgradeCode: an in-place
// major upgrade), with the X-Content-SHA256 of the file actually served.
//
// Identification: right before downloading, the agent calls
// POST /api/agent/notifying-update (authenticated: API key + device UUID),
// from the same process / address. That call records (client address, NT 6.x?,
// architecture) here for a few minutes; the download from that address then
// gets the nt6 MSI when every recent notification from that address for that
// architecture comes from an NT 6.x device. Mixed (an NT 6.x and a Windows 10+
// device updating at the same time behind one NAT address): the requested
// (modern) file is served — on NT 6.x its MSI then refuses cleanly (nothing is
// changed, the update is retried later), whereas an nt6 MSI on Windows 10
// would silently move that machine to the nt6 line for good.
//
// Agents built with the nt6 awareness (agent >= the nt6 release) ask for the
// nt6 file themselves (currentAgentMSIName): served as is.

export const AGENT_MSI_X64 = 'obliance-agent.msi';
export const AGENT_MSI_X86 = 'obliance-agent-x86.msi';
export const AGENT_MSI_NT6_X64 = 'obliance-agent-nt6.msi';
export const AGENT_MSI_NT6_X86 = 'obliance-agent-nt6-x86.msi';
export const OBLIREACH_MSI = 'oblireach-agent.msi';
export const OBLIREACH_MSI_NT6 = 'oblireach-agent-nt6.msi';

/** How long a notifying-update counts for the download that follows it. */
export const NT6_NOTIFY_WINDOW_MS = 5 * 60_000;
/** Bound of the in-memory table (oldest dropped first). */
const MAX_ENTRIES = 5000;

export type MsiArch = 'x64' | 'x86';

/** The agent architecture as stored (os_arch: GOARCH of the agent) → MSI flavour. */
export function msiArchOf(osArch: string | null | undefined): MsiArch {
  const a = String(osArch ?? '').trim().toLowerCase();
  return a === '386' || a === 'x86' || a === 'i386' || a === 'i686' ? 'x86' : 'x64';
}

/** The nt6 MSI of an architecture. */
export function nt6AgentMsiName(arch: MsiArch): string {
  return arch === 'x86' ? AGENT_MSI_NT6_X86 : AGENT_MSI_NT6_X64;
}

/** The modern MSI an older agent asks for, and its architecture (null: not one of them). */
export function modernAgentMsiArch(file: string): MsiArch | null {
  if (file === AGENT_MSI_X64) return 'x64';
  if (file === AGENT_MSI_X86) return 'x86';
  return null;
}

interface NotifyEntry { ip: string; deviceId: number; nt6: boolean; arch: MsiArch; at: number }

let entries: NotifyEntry[] = [];

/** Tests only. */
export function __resetNt6NotifyForTests(): void { entries = []; }

function prune(now: number): void {
  if (entries.length && now - entries[0].at >= NT6_NOTIFY_WINDOW_MS) {
    entries = entries.filter((e) => now - e.at < NT6_NOTIFY_WINDOW_MS);
  }
  if (entries.length > MAX_ENTRIES) entries = entries.slice(entries.length - MAX_ENTRIES);
}

/**
 * POST /api/agent/notifying-update: remember who is about to download its
 * update, from which address. Windows devices only (others never fetch an MSI).
 */
export function noteAgentUpdateNotify(input: {
  ip: string | null | undefined;
  deviceId: number;
  os: DeviceOsRow & { os_arch?: string | null };
}, now = Date.now()): void {
  const ip = String(input.ip ?? '').trim();
  if (!ip) return;
  const type = String(input.os.os_type ?? '').toLowerCase();
  const nt6 = isWindowsNt6(input.os);
  if (type !== 'windows' && !nt6) return;
  prune(now);
  // One entry per device: the latest notification replaces the previous one.
  entries = entries.filter((e) => e.deviceId !== input.deviceId);
  entries.push({ ip, deviceId: input.deviceId, nt6, arch: msiArchOf(input.os.os_arch), at: now });
}

export interface AgentDownloadChoice {
  /** The dist file to serve. */
  file: string;
  /** True when it replaces the requested file (nt6 MSI for an NT 6.x device). */
  substituted: boolean;
  /** Why (logs, tests). */
  reason: 'as_requested' | 'nt6_device' | 'mixed_address' | 'no_notification';
}

/**
 * The file to serve for GET /api/agent/download/<requested> from `ip`.
 * Only the two modern Windows MSIs can be substituted (by the nt6 MSI of the
 * same architecture); every other name is served as requested.
 */
export function chooseAgentDownload(requested: string, ip: string | null | undefined, now = Date.now()): AgentDownloadChoice {
  const arch = modernAgentMsiArch(requested);
  if (!arch) return { file: requested, substituted: false, reason: 'as_requested' };
  const addr = String(ip ?? '').trim();
  if (!addr) return { file: requested, substituted: false, reason: 'no_notification' };
  prune(now);
  const recent = entries.filter((e) => e.ip === addr && e.arch === arch && now - e.at < NT6_NOTIFY_WINDOW_MS);
  if (!recent.length) return { file: requested, substituted: false, reason: 'no_notification' };
  if (recent.every((e) => e.nt6)) return { file: nt6AgentMsiName(arch), substituted: true, reason: 'nt6_device' };
  if (recent.some((e) => e.nt6)) return { file: requested, substituted: false, reason: 'mixed_address' };
  return { file: requested, substituted: false, reason: 'as_requested' };
}

/**
 * ObliReach MSI for a Windows device ('' = none): x64 only; NT 6.x → the nt6
 * build ONLY (the modern one never starts there — the agent refuses it with
 * "unsupported os_too_old"). Name exactly as the Obliance agent expects
 * (agent/oblireach_manager.go obliReachWindowsArtifact).
 */
export function obliReachWindowsMsi(arch: string | null | undefined, nt6: boolean): string {
  const a = String(arch ?? '').trim().toLowerCase();
  if (a !== 'amd64' && a !== 'x86_64' && a !== 'x64') return '';
  return nt6 ? OBLIREACH_MSI_NT6 : OBLIREACH_MSI;
}
