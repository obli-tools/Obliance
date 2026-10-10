import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  deviceOsFacts, matchOsCondition, sanitizeOsCondition, versionInRange, windowsBuildRange,
  WINDOWS_RELEASE_BUILDS, MACOS_MAJORS, LINUX_FAMILY_KEYS, LINUX_FLAVORS,
} from './softwareOsCondition';
import {
  WINDOWS_RELEASES, MACOS_RELEASES, LINUX_FAMILIES, LINUX_DISTROS,
} from '../../../shared/src/softwareOsCondition';

// OS conditions of software compliance lists / alternatives. Run:
//   cd server
//   node --import ./src/services/deviceKey/test-resolve.mjs --disable-warning=MODULE_TYPELESS_PACKAGE_JSON \
//        --test "src/utils/softwareOsCondition.test.ts"

// Device rows as the agents report them.
const WIN11 = { os_type: 'windows', os_name: 'Microsoft Windows 11 Pro', os_version: '10.0.22631.4317 Build 22631.4317' };
// Old gopsutil: Windows 11 still named "Windows 10" — the build decides.
const WIN11_AS_10 = { os_type: 'windows', os_name: 'Microsoft Windows 10 Pro', os_version: '10.0.26100.1742 Build 26100.1742' };
const WIN10 = { os_type: 'windows', os_name: 'Microsoft Windows 10 Pro', os_version: '10.0.19045.5011 Build 19045.5011' };
const WIN81 = { os_type: 'windows', os_name: 'Microsoft Windows 8.1 Pro', os_version: '6.3.9600.20563 Build 9600.20563' };
const WIN7 = { os_type: 'windows', os_name: 'Microsoft Windows 7 Professional', os_version: '6.1.7601.24546 Build 7601.24546' };
const WS2022 = { os_type: 'windows', os_name: 'Microsoft Windows Server 2022 Standard', os_version: '10.0.20348.2700 Build 20348.2700' };
const WS2019 = { os_type: 'windows', os_name: 'Microsoft Windows Server 2019 Datacenter', os_version: '10.0.17763.6293 Build 17763.6293' };
const WS2012R2 = { os_type: 'windows', os_name: 'Microsoft Windows Server 2012 R2 Standard', os_version: '6.3.9600.20563 Build 9600.20563' };
// Legacy Go 1.20 agent.
const WS2008R2_LEGACY = { os_type: 'windows', os_name: 'windows', os_version: 'Windows Server 2008 R2 Standard (Build 7601)' };
const WIN_UNKNOWN = { os_type: 'windows', os_name: 'windows', os_version: 'unknown' };
const UBUNTU = { os_type: 'linux', os_name: 'Ubuntu 22.04.4 LTS', os_version: '22.04', os_distro: 'debian' };
const UBUNTU_OLD_AGENT = { os_type: 'linux', os_name: 'ubuntu', os_version: '20.04', os_distro: 'debian' };
const DEBIAN = { os_type: 'linux', os_name: 'Debian GNU/Linux 12 (bookworm)', os_version: '12.5', os_distro: 'debian' };
const ROCKY = { os_type: 'linux', os_name: 'Rocky Linux 9.3 (Blue Onyx)', os_version: '9.3', os_distro: 'rhel' };
const ALMA = { os_type: 'linux', os_name: 'AlmaLinux 8.10 (Cerulean Leopard)', os_version: '8.10', os_distro: 'almalinux' };
const ARCH = { os_type: 'linux', os_name: 'Arch Linux', os_version: '', os_distro: 'arch' };
const SONOMA = { os_type: 'macos', os_name: 'Sonoma', os_version: '14.5' };
const TAHOE = { os_type: 'macos', os_name: 'Tahoe', os_version: '26.0.1' };
const BSD = { os_type: 'freebsd', os_name: 'freebsd', os_version: '14.0-RELEASE-p6' };

const f = deviceOsFacts;

test('device facts: Windows build + edition', () => {
  assert.deepEqual([f(WIN11).windowsBuild, f(WIN11).windowsEdition], [22631, 'client']);
  assert.equal(f(WIN11_AS_10).windowsBuild, 26100);
  assert.deepEqual([f(WS2022).windowsBuild, f(WS2022).windowsEdition], [20348, 'server']);
  assert.deepEqual([f(WS2008R2_LEGACY).windowsBuild, f(WS2008R2_LEGACY).windowsEdition], [7601, 'server']);
  assert.deepEqual([f(WIN_UNKNOWN).windowsBuild, f(WIN_UNKNOWN).windowsEdition], [null, null]);
});

test('device facts: Linux flavor / family', () => {
  assert.deepEqual([f(UBUNTU).linuxFlavor, f(UBUNTU).linuxFamily, f(UBUNTU).version], ['ubuntu', 'debian', '22.04']);
  assert.equal(f(UBUNTU_OLD_AGENT).linuxFlavor, 'ubuntu');
  assert.deepEqual([f(DEBIAN).linuxFlavor, f(DEBIAN).linuxFamily], ['debian', 'debian']);
  assert.deepEqual([f(ROCKY).linuxFlavor, f(ROCKY).linuxFamily], ['rocky', 'rhel']);
  assert.deepEqual([f(ALMA).linuxFlavor, f(ALMA).linuxFamily], ['almalinux', 'rhel']);
  assert.deepEqual([f(ARCH).linuxFlavor, f(ARCH).version], ['arch', null]);
  // Unknown flavor, known family through os_distro
  const odd = f({ os_type: 'linux', os_name: 'elementary OS 7.1 Horus', os_version: '7.1', os_distro: 'elementary' });
  assert.deepEqual([odd.linuxFlavor, odd.linuxFamily], [null, 'debian']);
  // Raw os-release ID as os_distro (agent family map has no entry): Oracle "ol"
  const ol = f({ os_type: 'linux', os_name: 'Oracle Linux Server 9.4', os_version: '9.4', os_distro: 'ol' });
  assert.deepEqual([ol.linuxFlavor, ol.linuxFamily], ['oracle', 'rhel']);
});

test('versionInRange: inclusive at the precision of the bound', () => {
  assert.equal(versionInRange('22.04', '22.04', null), true);
  assert.equal(versionInRange('20.04', '22.04', null), false);
  assert.equal(versionInRange('22.04', null, '22.04'), true);
  assert.equal(versionInRange('22.10', null, '22.04'), false);
  assert.equal(versionInRange('14.5', null, '14'), true); // "Jusqu'à Sonoma" includes 14.x
  assert.equal(versionInRange('15.0', null, '14'), false);
  assert.equal(versionInRange('9.3', '9', '9'), true);
  assert.equal(versionInRange('14.0-RELEASE-p6', '13.2', null), true);
  assert.equal(versionInRange(null, '1', null), false); // unknown version + bound
  assert.equal(versionInRange(null, null, null), true);
});

test('windowsBuildRange: "Jusqu\'à" includes the whole release', () => {
  assert.deepEqual(windowsBuildRange('win10', 'win10'), { min: 10240, maxExclusive: 22000 });
  assert.deepEqual(windowsBuildRange(null, 'win81'), { min: null, maxExclusive: 10240 });
  assert.deepEqual(windowsBuildRange('win11', 'win11'), { min: 22000, maxExclusive: null });
  assert.deepEqual(windowsBuildRange('ws2016', 'ws2019'), { min: 14393, maxExclusive: 20348 });
  assert.deepEqual(windowsBuildRange(null, 'ws2025'), { min: null, maxExclusive: null });
});

test('matchOsCondition: Windows (Passly example)', () => {
  const modern = { platform: 'windows' as const, minVersion: 'win10' };
  const old = { platform: 'windows' as const, maxVersion: 'win81' };
  assert.equal(matchOsCondition(modern, f(WIN10)), true);
  assert.equal(matchOsCondition(modern, f(WIN11)), true);
  assert.equal(matchOsCondition(modern, f(WIN81)), false);
  assert.equal(matchOsCondition(old, f(WIN81)), true);
  assert.equal(matchOsCondition(old, f(WIN7)), true);
  assert.equal(matchOsCondition(old, f(WIN10)), false);
  // Windows 11 vs 10 by build
  assert.equal(matchOsCondition({ platform: 'windows', minVersion: 'win11' }, f(WIN11_AS_10)), true);
  assert.equal(matchOsCondition({ platform: 'windows', maxVersion: 'win10' }, f(WIN11)), false);
  // Unknown build → no match when a bound is set; matches with no bound
  assert.equal(matchOsCondition(modern, f(WIN_UNKNOWN)), false);
  assert.equal(matchOsCondition({ platform: 'windows' }, f(WIN_UNKNOWN)), true);
  // Other platform
  assert.equal(matchOsCondition(modern, f(UBUNTU)), false);
});

test('matchOsCondition: Windows edition', () => {
  const servers = { platform: 'windows' as const, edition: 'server' as const, minVersion: 'ws2016' };
  assert.equal(matchOsCondition(servers, f(WS2022)), true);
  assert.equal(matchOsCondition(servers, f(WS2012R2)), false);
  assert.equal(matchOsCondition(servers, f(WIN11)), false);
  assert.equal(matchOsCondition({ platform: 'windows', edition: 'client' }, f(WIN10)), true);
  assert.equal(matchOsCondition({ platform: 'windows', edition: 'client' }, f(WS2019)), false);
  assert.equal(matchOsCondition({ platform: 'windows', edition: 'client' }, f(WIN_UNKNOWN)), false);
  assert.equal(matchOsCondition({ platform: 'windows', edition: 'server', maxVersion: 'ws2008r2' }, f(WS2008R2_LEGACY)), true);
});

test('matchOsCondition: macOS, Linux, FreeBSD', () => {
  assert.equal(matchOsCondition({ platform: 'macos', minVersion: '14' }, f(SONOMA)), true);
  assert.equal(matchOsCondition({ platform: 'macos', minVersion: '15' }, f(SONOMA)), false);
  assert.equal(matchOsCondition({ platform: 'macos', maxVersion: '15' }, f(TAHOE)), false);
  assert.equal(matchOsCondition({ platform: 'linux', distro: 'ubuntu', minVersion: '22.04' }, f(UBUNTU)), true);
  assert.equal(matchOsCondition({ platform: 'linux', distro: 'ubuntu' }, f(DEBIAN)), false);
  assert.equal(matchOsCondition({ platform: 'linux', distro: 'family:debian' }, f(DEBIAN)), true);
  assert.equal(matchOsCondition({ platform: 'linux', distro: 'family:rhel' }, f(ALMA)), true);
  assert.equal(matchOsCondition({ platform: 'linux', distro: 'rocky', maxVersion: '8' }, f(ROCKY)), false);
  assert.equal(matchOsCondition({ platform: 'linux', distro: 'arch', minVersion: '1' }, f(ARCH)), false);
  assert.equal(matchOsCondition({ platform: 'freebsd', minVersion: '14' }, f(BSD)), true);
  assert.equal(matchOsCondition(null, f(BSD)), true);
  assert.equal(matchOsCondition({ platform: 'all' }, f(BSD)), true);
});

test('sanitizeOsCondition: validates per platform', () => {
  assert.equal(sanitizeOsCondition(null), null);
  assert.equal(sanitizeOsCondition({ platform: 'all', minVersion: 'win10' }), null);
  assert.deepEqual(sanitizeOsCondition({ platform: 'windows', minVersion: 'win10', maxVersion: 'bogus', edition: 'x', extra: 1 }),
    { platform: 'windows', minVersion: 'win10' });
  assert.deepEqual(sanitizeOsCondition({ platform: 'linux', distro: 'ubuntu', minVersion: '22.04', maxVersion: '$(rm)' }),
    { platform: 'linux', distro: 'ubuntu', minVersion: '22.04' });
  assert.deepEqual(sanitizeOsCondition({ platform: 'linux', distro: 'nope' }), { platform: 'linux' });
  // List level: platform forced to the target platform; foreign bounds dropped.
  assert.deepEqual(sanitizeOsCondition({ platform: 'linux', minVersion: 'win10', edition: 'server' }, 'windows'),
    { platform: 'windows', minVersion: 'win10', edition: 'server' });
  assert.deepEqual(sanitizeOsCondition({ minVersion: 'win10' }, 'macos'), { platform: 'macos' });
});

test('catalogs: server tables match shared/src/softwareOsCondition.ts', () => {
  assert.deepEqual(
    WINDOWS_RELEASE_BUILDS.map(([k, e, b]) => [k, e, b]),
    WINDOWS_RELEASES.map((w) => [w.key, w.edition, w.build]),
  );
  assert.deepEqual([...MACOS_MAJORS], MACOS_RELEASES.map((m) => m.version));
  assert.deepEqual([...LINUX_FAMILY_KEYS], LINUX_FAMILIES.map((l) => l.key));
  assert.deepEqual(
    LINUX_FLAVORS.map(([k, fam]) => [k, fam]).sort(),
    LINUX_DISTROS.map((d) => [d.key, d.family]).sort(),
  );
});
