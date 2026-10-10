// Software compliance OS conditions ("sous-système") — pure helpers, no DB.
// Model and catalogs: shared/src/softwareOsCondition.ts (the tables below are
// a copy: the server runs against shared/dist; softwareOsCondition.test.ts
// checks both copies agree).
import type { SoftwareOsCondition, SoftwareOsEdition, SoftwareOsPlatform } from '@obliance/shared';
import { isWindowsOs, windowsBuildOf, type DeviceOsRow } from './deviceOs';

export const OS_PLATFORMS: readonly SoftwareOsPlatform[] = ['all', 'windows', 'linux', 'macos', 'freebsd'];

/** key → [edition, first build]. Same order / values as shared WINDOWS_RELEASES. */
export const WINDOWS_RELEASE_BUILDS: ReadonlyArray<readonly [string, 'client' | 'server', number]> = [
  ['win7', 'client', 7600],
  ['win8', 'client', 9200],
  ['win81', 'client', 9600],
  ['win10', 'client', 10240],
  ['win11', 'client', 22000],
  ['ws2008r2', 'server', 7600],
  ['ws2012', 'server', 9200],
  ['ws2012r2', 'server', 9600],
  ['ws2016', 'server', 14393],
  ['ws2019', 'server', 17763],
  ['ws2022', 'server', 20348],
  ['ws2025', 'server', 26100],
];

export const MACOS_MAJORS: readonly string[] = ['11', '12', '13', '14', '15', '26'];

export const LINUX_FAMILY_KEYS: readonly string[] = ['family:debian', 'family:rhel', 'family:suse', 'family:arch'];

/**
 * Linux flavors: key → [family, pattern over os_name (PRETTY_NAME, or the
 * gopsutil platform id on older agents) / os_distro]. Order matters: the
 * first pattern that matches wins (specific derivatives before their base).
 */
export const LINUX_FLAVORS: ReadonlyArray<readonly [string, string, RegExp]> = [
  ['linuxmint', 'debian', /\blinux\s*mint\b|\blinuxmint\b/i],
  ['pop', 'debian', /\bpop!?[_\s-]?os\b|^pop$/i],
  ['raspbian', 'debian', /\braspbian\b|\braspberry\s*pi\s*os\b/i],
  ['ubuntu', 'debian', /\bubuntu\b/i],
  ['debian', 'debian', /\bdebian\b/i],
  ['rocky', 'rhel', /\brocky\b/i],
  ['almalinux', 'rhel', /\balma\s*linux\b|\balmalinux\b|^alma$/i],
  ['centos', 'rhel', /\bcentos\b/i],
  ['oracle', 'rhel', /\boracle\s*linux\b|^ol$|^oracle$/i],
  ['amazon', 'rhel', /\bamazon\s*linux\b|^amzn$|^amazon$/i],
  ['rhel', 'rhel', /\bred\s*hat\b|^rhel$|\brhel\b/i],
  ['fedora', 'fedora', /\bfedora\b/i],
  ['sles', 'suse', /\bsuse\s+linux\s+enterprise\b|^sles(?:_sap)?$|\bsles\b/i],
  ['opensuse', 'suse', /\bopensuse\b/i],
  ['manjaro', 'arch', /\bmanjaro\b/i],
  ['arch', 'arch', /\barch\s*linux\b|^arch$/i],
  ['alpine', 'alpine', /\balpine\b/i],
];

/** os_distro values (agent family map, or the raw os-release ID) → family. */
const DISTRO_FAMILY_ALIASES: Record<string, string> = {
  debian: 'debian', ubuntu: 'debian', linuxmint: 'debian', pop: 'debian', raspbian: 'debian', elementary: 'debian',
  rhel: 'rhel', centos: 'rhel', rocky: 'rhel', almalinux: 'rhel', alma: 'rhel', ol: 'rhel', oracle: 'rhel', amzn: 'rhel',
  fedora: 'fedora',
  suse: 'suse', opensuse: 'suse', 'opensuse-leap': 'suse', 'opensuse-tumbleweed': 'suse', sles: 'suse',
  arch: 'arch', manjaro: 'arch', endeavouros: 'arch',
  alpine: 'alpine',
};

const str = (v: unknown): string => (typeof v === 'string' ? v : '');

export type SoftwareDeviceOsRow = DeviceOsRow & { os_distro?: string | null };

/** What the matcher reads from a device. null = unknown. */
export interface DeviceOsFacts {
  platform: 'windows' | 'linux' | 'macos' | 'freebsd' | 'other';
  windowsBuild: number | null;
  windowsEdition: 'client' | 'server' | null;
  linuxFlavor: string | null;
  linuxFamily: string | null;
  /** macOS / Linux / FreeBSD version string as reported. */
  version: string | null;
}

export function deviceOsFacts(dev: SoftwareDeviceOsRow | null | undefined): DeviceOsFacts {
  const type = str(dev?.os_type).toLowerCase();
  const facts: DeviceOsFacts = {
    platform: 'other', windowsBuild: null, windowsEdition: null,
    linuxFlavor: null, linuxFamily: null, version: null,
  };
  if (!dev) return facts;
  if (isWindowsOs(dev)) {
    facts.platform = 'windows';
    facts.windowsBuild = windowsBuildOf(dev);
    const text = `${str(dev.os_name)} ${str(dev.os_version)}`;
    if (/\bserver\b/i.test(text)) facts.windowsEdition = 'server';
    else if (/\bwindows\s+(?:7|8(?:\.1)?|10|11|vista|xp)\b/i.test(text)) facts.windowsEdition = 'client';
    return facts;
  }
  const version = str(dev.os_version).trim();
  facts.version = version && version.toLowerCase() !== 'unknown' ? version : null;
  if (type === 'macos' || type === 'darwin') { facts.platform = 'macos'; return facts; }
  if (type === 'freebsd') { facts.platform = 'freebsd'; return facts; }
  if (type === 'linux') {
    facts.platform = 'linux';
    const name = str(dev.os_name).trim();
    const distro = str(dev.os_distro).trim().toLowerCase();
    for (const [key, family, re] of LINUX_FLAVORS) {
      if ((name && re.test(name)) || (distro && re.test(distro))) {
        facts.linuxFlavor = key;
        facts.linuxFamily = family;
        break;
      }
    }
    if (!facts.linuxFamily && distro) facts.linuxFamily = DISTRO_FAMILY_ALIASES[distro] ?? null;
    return facts;
  }
  return facts;
}

/** Leading integer of each dot segment ("14.0-RELEASE-p6" → [14, 0]). null = no number. */
export function versionSegments(v: string | null | undefined): number[] | null {
  const s = str(v).trim();
  if (!/^\d/.test(s)) return null;
  const out: number[] = [];
  for (const part of s.split('.')) {
    const m = /^(\d+)/.exec(part);
    if (!m) break;
    out.push(Number(m[1]));
  }
  return out.length ? out : null;
}

/** Compare by numeric segments, missing segments = 0. */
export function compareVersionSegments(a: number[], b: number[]): number {
  const n = Math.max(a.length, b.length);
  for (let i = 0; i < n; i++) {
    const x = a[i] ?? 0, y = b[i] ?? 0;
    if (x !== y) return x < y ? -1 : 1;
  }
  return 0;
}

/**
 * Inclusive range check at the precision of each bound: min "22.04" accepts
 * 22.04 and above; max "22.04" accepts 22.04.x (the device version truncated
 * to the bound's length is compared). Unparsable device version with a bound
 * set → false.
 */
export function versionInRange(version: string | null, min?: string | null, max?: string | null): boolean {
  if (!min && !max) return true;
  const v = versionSegments(version);
  if (!v) return false;
  if (min) {
    const m = versionSegments(min);
    if (!m) return false;
    if (compareVersionSegments(v, m) < 0) return false;
  }
  if (max) {
    const m = versionSegments(max);
    if (!m) return false;
    if (compareVersionSegments(v.slice(0, m.length), m) > 0) return false;
  }
  return true;
}

function windowsRelease(key: string | null | undefined) {
  if (!key) return null;
  const i = WINDOWS_RELEASE_BUILDS.findIndex((r) => r[0] === key);
  if (i < 0) return null;
  const [k, edition, build] = WINDOWS_RELEASE_BUILDS[i];
  const next = WINDOWS_RELEASE_BUILDS.slice(i + 1).find((r) => r[1] === edition);
  return { key: k, edition, build, nextBuild: next ? next[2] : null };
}

/** Windows build range [min, maxExclusive) of a condition's release keys. */
export function windowsBuildRange(min?: string | null, max?: string | null): { min: number | null; maxExclusive: number | null } {
  const lo = windowsRelease(min);
  const hi = windowsRelease(max);
  return { min: lo ? lo.build : null, maxExclusive: hi ? hi.nextBuild : null };
}

function isEmptyCondition(c: SoftwareOsCondition): boolean {
  return (!c.platform || c.platform === 'all')
    && !c.distro && !c.minVersion && !c.maxVersion && (!c.edition || c.edition === 'any');
}

/**
 * True when the device matches the condition. null / empty condition → true.
 * Unknown OS data needed by the condition → false (never guessed).
 */
export function matchOsCondition(cond: SoftwareOsCondition | null | undefined, facts: DeviceOsFacts): boolean {
  if (!cond || isEmptyCondition(cond)) return true;
  const platform = cond.platform || 'all';
  if (platform === 'all') return true; // (a sanitized 'all' condition carries nothing else)
  if (facts.platform !== platform) return false;

  if (platform === 'windows') {
    const edition = cond.edition && cond.edition !== 'any' ? cond.edition : null;
    if (edition && facts.windowsEdition !== edition) return false;
    if (cond.minVersion || cond.maxVersion) {
      const b = facts.windowsBuild;
      if (b === null) return false;
      const { min, maxExclusive } = windowsBuildRange(cond.minVersion, cond.maxVersion);
      if (cond.minVersion && min === null) return false; // unknown key: never matches
      if (min !== null && b < min) return false;
      if (maxExclusive !== null && b >= maxExclusive) return false;
    }
    return true;
  }

  if (platform === 'linux' && cond.distro) {
    if (cond.distro.startsWith('family:')) {
      if (facts.linuxFamily !== cond.distro.slice('family:'.length)) return false;
    } else if (facts.linuxFlavor !== cond.distro) {
      return false;
    }
  }
  return versionInRange(facts.version, cond.minVersion, cond.maxVersion);
}

const VERSION_RE = /^\d+(?:\.\d+){0,3}$/;

/**
 * A condition from a request body, sanitized: unknown keys dropped, bounds
 * validated per platform. `forcedPlatform` (list level) replaces the
 * platform. Returns null when nothing restricts anything.
 */
export function sanitizeOsCondition(raw: unknown, forcedPlatform?: string): SoftwareOsCondition | null {
  const r = (raw && typeof raw === 'object') ? raw as Record<string, unknown> : {};
  const platform = (forcedPlatform ?? str(r.platform)) as SoftwareOsPlatform;
  if (!OS_PLATFORMS.includes(platform) || platform === 'all') return null;
  const out: SoftwareOsCondition = { platform };
  const min = str(r.minVersion).trim();
  const max = str(r.maxVersion).trim();
  if (platform === 'windows') {
    const ed = str(r.edition) as SoftwareOsEdition;
    if (ed === 'client' || ed === 'server') out.edition = ed;
    const keys = WINDOWS_RELEASE_BUILDS.map((w) => w[0]);
    if (keys.includes(min)) out.minVersion = min;
    if (keys.includes(max)) out.maxVersion = max;
  } else if (platform === 'macos') {
    if (VERSION_RE.test(min)) out.minVersion = min;
    if (VERSION_RE.test(max)) out.maxVersion = max;
  } else {
    if (platform === 'linux') {
      const d = str(r.distro).trim();
      if (LINUX_FAMILY_KEYS.includes(d) || LINUX_FLAVORS.some((f) => f[0] === d)) out.distro = d;
    }
    if (VERSION_RE.test(min)) out.minVersion = min;
    if (VERSION_RE.test(max)) out.maxVersion = max;
  }
  return out;
}

/** Parse a stored jsonb value (object, string or null). */
export function parseStoredOsCondition(v: unknown): SoftwareOsCondition | null {
  if (v == null) return null;
  let o: unknown = v;
  if (typeof v === 'string') { try { o = JSON.parse(v); } catch { return null; } }
  if (!o || typeof o !== 'object') return null;
  return sanitizeOsCondition(o);
}
