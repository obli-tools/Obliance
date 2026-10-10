// ─── Software compliance: OS conditions ("sous-système") ────────────────────
//
// Catalogs of the OS versions a software list (or one alternative of an
// entry) can be restricted to. Used by the client selectors. The runtime
// matcher lives in server/src/utils/softwareOsCondition.ts (the server runs
// against shared/dist, rebuilt only by a release build) and carries the same
// tables — server/src/utils/softwareOsCondition.test.ts checks they agree.
//
// What the agents report (devices row):
//   Windows  os_name    "Microsoft Windows 11 Pro", "Microsoft Windows Server 2022 Standard"
//                       (legacy Go 1.20 agent: "windows")
//            os_version "10.0.22631.4317 Build 22631.4317" (legacy agent:
//                       "Windows Server 2008 R2 Standard (Build 7601)")
//            → the BUILD number decides the release (Windows 11 = build >= 22000,
//              same 10.0 version as Windows 10); "Server" in the name = server edition.
//   macOS    os_version "14.5", "26.0" (os_name = marketing name "Sonoma").
//   Linux    os_distro  family from /etc/os-release ID: debian, rhel, fedora,
//                       arch, suse, or the raw ID (almalinux, ol, amzn, alpine…)
//            os_name    PRETTY_NAME "Ubuntu 22.04.4 LTS", "Rocky Linux 9.3 (Blue Onyx)"
//            os_version gopsutil platform version "22.04", "12.5", "9.3".
//   FreeBSD  os_version "14.0-RELEASE-p6".

export type SoftwareOsPlatform = 'windows' | 'linux' | 'macos' | 'freebsd' | 'all';
export type SoftwareOsEdition = 'client' | 'server' | 'any';

/**
 * An OS condition. Bounds are INCLUSIVE:
 *   minVersion "À partir de" = this release or newer,
 *   maxVersion "Jusqu'à"     = up to and including this release (every
 *                              build / point release of it).
 * Windows bounds are release keys of WINDOWS_RELEASES ('win10', 'ws2019'…);
 * macOS bounds are major versions ('14'); Linux / FreeBSD bounds are free
 * version strings compared by numeric segments ("22.04" includes 22.04.4).
 * A device whose OS data is missing / unparsable does NOT match a condition
 * that needs it (never guessed).
 */
export interface SoftwareOsCondition {
  platform: SoftwareOsPlatform;
  /** Linux only: a flavor key of LINUX_DISTROS ('ubuntu') or a family key ('family:debian'). */
  distro?: string | null;
  minVersion?: string | null;
  maxVersion?: string | null;
  /** Windows only: client (7…11), server (2008 R2…2025) or any. */
  edition?: SoftwareOsEdition | null;
}

export interface WindowsReleaseInfo {
  key: string;
  label: string;
  edition: 'client' | 'server';
  /** First build of the release (NT 6.1.7600 = 7600, Windows 11 = 22000…). */
  build: number;
  /** NT version, for display. */
  nt: string;
}

/** Ordered by build within each edition. */
export const WINDOWS_RELEASES: readonly WindowsReleaseInfo[] = [
  { key: 'win7', label: 'Windows 7', edition: 'client', build: 7600, nt: '6.1' },
  { key: 'win8', label: 'Windows 8', edition: 'client', build: 9200, nt: '6.2' },
  { key: 'win81', label: 'Windows 8.1', edition: 'client', build: 9600, nt: '6.3' },
  { key: 'win10', label: 'Windows 10', edition: 'client', build: 10240, nt: '10.0' },
  { key: 'win11', label: 'Windows 11', edition: 'client', build: 22000, nt: '10.0' },
  { key: 'ws2008r2', label: 'Windows Server 2008 R2', edition: 'server', build: 7600, nt: '6.1' },
  { key: 'ws2012', label: 'Windows Server 2012', edition: 'server', build: 9200, nt: '6.2' },
  { key: 'ws2012r2', label: 'Windows Server 2012 R2', edition: 'server', build: 9600, nt: '6.3' },
  { key: 'ws2016', label: 'Windows Server 2016', edition: 'server', build: 14393, nt: '10.0' },
  { key: 'ws2019', label: 'Windows Server 2019', edition: 'server', build: 17763, nt: '10.0' },
  { key: 'ws2022', label: 'Windows Server 2022', edition: 'server', build: 20348, nt: '10.0' },
  { key: 'ws2025', label: 'Windows Server 2025', edition: 'server', build: 26100, nt: '10.0' },
];

export interface MacOsReleaseInfo { version: string; label: string }

/** Same names as macOsRelease() in server/src/routes/agent.routes.ts. */
export const MACOS_RELEASES: readonly MacOsReleaseInfo[] = [
  { version: '11', label: 'Big Sur' },
  { version: '12', label: 'Monterey' },
  { version: '13', label: 'Ventura' },
  { version: '14', label: 'Sonoma' },
  { version: '15', label: 'Sequoia' },
  { version: '26', label: 'Tahoe' },
];

export interface LinuxDistroInfo {
  /** Flavor key ('ubuntu') or family key ('family:debian'). */
  key: string;
  label: string;
  /** Family the flavor belongs to (debian, rhel, fedora, suse, arch, alpine). */
  family: string;
  /** Example version, for the input placeholder (flavors only). */
  example?: string;
}

export const LINUX_FAMILIES: readonly LinuxDistroInfo[] = [
  { key: 'family:debian', label: 'Debian / Ubuntu (family)', family: 'debian' },
  { key: 'family:rhel', label: 'Red Hat / RHEL (family)', family: 'rhel' },
  { key: 'family:suse', label: 'SUSE (family)', family: 'suse' },
  { key: 'family:arch', label: 'Arch (family)', family: 'arch' },
];

export const LINUX_DISTROS: readonly LinuxDistroInfo[] = [
  { key: 'ubuntu', label: 'Ubuntu', family: 'debian', example: '22.04' },
  { key: 'debian', label: 'Debian', family: 'debian', example: '12' },
  { key: 'linuxmint', label: 'Linux Mint', family: 'debian', example: '21.3' },
  { key: 'pop', label: 'Pop!_OS', family: 'debian', example: '22.04' },
  { key: 'raspbian', label: 'Raspberry Pi OS', family: 'debian', example: '12' },
  { key: 'rhel', label: 'Red Hat Enterprise Linux', family: 'rhel', example: '9.4' },
  { key: 'rocky', label: 'Rocky Linux', family: 'rhel', example: '9.4' },
  { key: 'almalinux', label: 'AlmaLinux', family: 'rhel', example: '9.4' },
  { key: 'centos', label: 'CentOS', family: 'rhel', example: '8' },
  { key: 'oracle', label: 'Oracle Linux', family: 'rhel', example: '9.4' },
  { key: 'amazon', label: 'Amazon Linux', family: 'rhel', example: '2023' },
  { key: 'fedora', label: 'Fedora', family: 'fedora', example: '40' },
  { key: 'opensuse', label: 'openSUSE', family: 'suse', example: '15.6' },
  { key: 'sles', label: 'SUSE Linux Enterprise', family: 'suse', example: '15.6' },
  { key: 'arch', label: 'Arch Linux', family: 'arch' },
  { key: 'manjaro', label: 'Manjaro', family: 'arch' },
  { key: 'alpine', label: 'Alpine Linux', family: 'alpine', example: '3.20' },
];
