import type { ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { clsx } from 'clsx';
import { AlertTriangle } from 'lucide-react';
import {
  WINDOWS_RELEASES, MACOS_RELEASES, LINUX_FAMILIES, LINUX_DISTROS,
  type SoftwareOsCondition, type SoftwareOsEdition, type SoftwareOsPlatform,
} from '@obliance/shared';

// OS condition ("sous-système") editors of the software compliance page:
// the list-level "Versions" row and the per-alternative "OS condition" row.
// Bounds are inclusive: "From" = this release or newer, "Up to" = this
// release included (every build / point release of it).

export type ConcretePlatform = Exclude<SoftwareOsPlatform, 'all'>;

export interface OsConditionForm {
  platform: ConcretePlatform;
  distro: string;
  minVersion: string;
  maxVersion: string;
  edition: SoftwareOsEdition;
}

export const CONCRETE_PLATFORMS: ConcretePlatform[] = ['windows', 'linux', 'macos', 'freebsd'];

export function platformLabel(p: string): string {
  return p === 'macos' ? 'macOS' : p === 'freebsd' ? 'FreeBSD' : p === 'linux' ? 'Linux' : p === 'windows' ? 'Windows' : p;
}

export function emptyOsCondition(platform: ConcretePlatform): OsConditionForm {
  return { platform, distro: '', minVersion: '', maxVersion: '', edition: 'any' };
}

export function osConditionFromApi(c: SoftwareOsCondition | null | undefined): OsConditionForm | null {
  if (!c || !c.platform || c.platform === 'all') return null;
  return {
    platform: c.platform,
    distro: c.distro ?? '',
    minVersion: c.minVersion ?? '',
    maxVersion: c.maxVersion ?? '',
    edition: c.edition ?? 'any',
  };
}

export function osConditionToApi(f: OsConditionForm | null | undefined): SoftwareOsCondition | null {
  if (!f) return null;
  const out: SoftwareOsCondition = { platform: f.platform };
  if (f.platform === 'linux' && f.distro) out.distro = f.distro;
  if (f.platform === 'windows' && f.edition !== 'any') out.edition = f.edition;
  if (f.minVersion.trim()) out.minVersion = f.minVersion.trim();
  if (f.maxVersion.trim()) out.maxVersion = f.maxVersion.trim();
  return out;
}

/** True when the condition restricts more than the platform. */
export function osConditionHasBounds(f: OsConditionForm | null | undefined): boolean {
  return !!f && (!!f.distro || !!f.minVersion.trim() || !!f.maxVersion.trim() || (f.platform === 'windows' && f.edition !== 'any'));
}

const segs = (v: string) => v.split('.').map((x) => parseInt(x, 10) || 0);
function cmpVersions(a: string, b: string): number {
  const x = segs(a), y = segs(b);
  for (let i = 0; i < Math.max(x.length, y.length); i++) {
    if ((x[i] ?? 0) !== (y[i] ?? 0)) return (x[i] ?? 0) < (y[i] ?? 0) ? -1 : 1;
  }
  return 0;
}

/** "From" after "Up to": nothing can match. */
function rangeInverted(f: OsConditionForm): boolean {
  if (!f.minVersion || !f.maxVersion) return false;
  if (f.platform === 'windows') {
    const lo = WINDOWS_RELEASES.find((w) => w.key === f.minVersion);
    const hi = WINDOWS_RELEASES.find((w) => w.key === f.maxVersion);
    return !!lo && !!hi && lo.build > hi.build;
  }
  // "Up to" is inclusive at its precision: compare on its length.
  const max = segs(f.maxVersion);
  const min = segs(f.minVersion).slice(0, max.length).join('.');
  return cmpVersions(min, f.maxVersion) > 0;
}

function windowsLabel(key: string): string {
  return WINDOWS_RELEASES.find((w) => w.key === key)?.label ?? key;
}
function macLabel(v: string): string {
  const r = MACOS_RELEASES.find((m) => m.version === v);
  return r ? `macOS ${r.version} ${r.label}` : `macOS ${v}`;
}
function distroLabel(key: string): string {
  return [...LINUX_FAMILIES, ...LINUX_DISTROS].find((d) => d.key === key)?.label ?? key;
}

/** One-line summary ("Windows 10 → Windows 11 · Servers"). Empty string when unrestricted. */
export function describeOsCondition(
  c: SoftwareOsCondition | null | undefined,
  t: (k: string, o?: Record<string, unknown>) => string,
  withPlatform = false,
): string {
  if (!c || !c.platform || c.platform === 'all') return '';
  const label = (v: string) => c.platform === 'windows' ? windowsLabel(v) : c.platform === 'macos' ? macLabel(v) : v;
  const parts: string[] = [];
  if (withPlatform && !(c.platform === 'linux' && c.distro)) parts.push(platformLabel(c.platform));
  if (c.platform === 'linux' && c.distro) parts.push(distroLabel(c.distro));
  if (c.minVersion && c.maxVersion) parts.push(c.minVersion === c.maxVersion ? label(c.minVersion) : `${label(c.minVersion)} → ${label(c.maxVersion)}`);
  else if (c.minVersion) parts.push(`≥ ${label(c.minVersion)}`);
  else if (c.maxVersion) parts.push(`≤ ${label(c.maxVersion)}`);
  if (c.platform === 'windows' && c.edition && c.edition !== 'any') {
    parts.push(c.edition === 'server'
      ? (t('softwareCompliance.osCond.editionServer') || 'Servers')
      : (t('softwareCompliance.osCond.editionClient') || 'Workstations'));
  }
  return parts.join(' · ');
}

/**
 * The platform-specific selectors of a condition (the platform itself is
 * chosen elsewhere): Windows edition + From / Up to named releases, macOS
 * From / Up to releases, Linux distribution + From / Up to versions,
 * FreeBSD From / Up to versions.
 */
export function OsVersionFields({
  value, onChange, variant = 'entry',
}: {
  value: OsConditionForm;
  onChange: (v: OsConditionForm) => void;
  /** 'list' = list form inputs (larger), 'entry' = inside an entry card. */
  variant?: 'list' | 'entry';
}) {
  const { t } = useTranslation();
  const set = (patch: Partial<OsConditionForm>) => onChange({ ...value, ...patch });
  const field = variant === 'list'
    ? 'w-full px-3 py-2 text-sm bg-bg-tertiary rounded-lg text-text-primary focus:outline-none focus:ring-1 focus:ring-accent'
    : 'w-full px-2 py-1.5 text-sm bg-bg-secondary rounded text-text-primary focus:outline-none focus:ring-1 focus:ring-accent';
  const lbl = 'text-[10px] font-semibold text-text-muted uppercase tracking-wider';
  const anyLabel = t('softwareCompliance.osCond.anyVersion') || 'Any';
  const fromLabel = t('softwareCompliance.osCond.from') || 'From';
  const toLabel = t('softwareCompliance.osCond.to') || 'Up to';

  let selectors: ReactNode;
  if (value.platform === 'windows') {
    const groups = (['client', 'server'] as const).filter((g) => value.edition === 'any' || value.edition === g);
    const options = (
      <>
        <option value="">{anyLabel}</option>
        {groups.map((g) => (
          <optgroup key={g} label={g === 'client' ? (t('softwareCompliance.osCond.editionClient') || 'Workstations') : (t('softwareCompliance.osCond.editionServer') || 'Servers')}>
            {WINDOWS_RELEASES.filter((w) => w.edition === g).map((w) => (
              <option key={w.key} value={w.key}>{w.label}</option>
            ))}
          </optgroup>
        ))}
      </>
    );
    selectors = (
      <>
        <div className="space-y-0.5 min-w-0">
          <span className={lbl}>{t('softwareCompliance.osCond.edition') || 'Edition'}</span>
          <div className="flex gap-1" role="group">
            {(['any', 'client', 'server'] as const).map((ed) => (
              <button
                key={ed}
                type="button"
                aria-pressed={value.edition === ed}
                onClick={() => {
                  // Bounds of the other edition no longer apply.
                  const keep = (k: string) => !k || ed === 'any' || WINDOWS_RELEASES.find((w) => w.key === k)?.edition === ed;
                  set({ edition: ed, minVersion: keep(value.minVersion) ? value.minVersion : '', maxVersion: keep(value.maxVersion) ? value.maxVersion : '' });
                }}
                className={clsx(
                  'flex-1 px-2 text-xs rounded-lg border transition-colors whitespace-nowrap coarse:min-h-10',
                  variant === 'list' ? 'py-2' : 'py-1.5',
                  value.edition === ed ? 'bg-accent/10 border-accent text-accent' : 'border-transparent text-text-muted hover:border-accent/50',
                )}
              >
                {ed === 'any' ? (t('softwareCompliance.osCond.editionAny') || 'All')
                  : ed === 'client' ? (t('softwareCompliance.osCond.editionClient') || 'Workstations')
                    : (t('softwareCompliance.osCond.editionServer') || 'Servers')}
              </button>
            ))}
          </div>
        </div>
        <label className="space-y-0.5 min-w-0">
          <span className={lbl}>{fromLabel}</span>
          <select value={value.minVersion} onChange={(e) => set({ minVersion: e.target.value })} className={field}>{options}</select>
        </label>
        <label className="space-y-0.5 min-w-0">
          <span className={lbl}>{toLabel}</span>
          <select value={value.maxVersion} onChange={(e) => set({ maxVersion: e.target.value })} className={field}>{options}</select>
        </label>
      </>
    );
  } else if (value.platform === 'macos') {
    const options = (
      <>
        <option value="">{anyLabel}</option>
        {MACOS_RELEASES.map((m) => <option key={m.version} value={m.version}>{`${m.version} — ${m.label}`}</option>)}
      </>
    );
    selectors = (
      <>
        <label className="space-y-0.5 min-w-0">
          <span className={lbl}>{fromLabel}</span>
          <select value={value.minVersion} onChange={(e) => set({ minVersion: e.target.value })} className={field}>{options}</select>
        </label>
        <label className="space-y-0.5 min-w-0">
          <span className={lbl}>{toLabel}</span>
          <select value={value.maxVersion} onChange={(e) => set({ maxVersion: e.target.value })} className={field}>{options}</select>
        </label>
      </>
    );
  } else {
    const flavor = LINUX_DISTROS.find((d) => d.key === value.distro);
    const example = value.platform === 'freebsd' ? '14.1' : (flavor?.example ?? '22.04');
    const placeholder = t('softwareCompliance.osCond.versionPlaceholder', { example }) || `e.g. ${example}`;
    const versionInput = (key: 'minVersion' | 'maxVersion', label: string) => (
      <label className="space-y-0.5 min-w-0">
        <span className={lbl}>{label}</span>
        <input
          value={value[key]}
          onChange={(e) => set({ [key]: e.target.value.replace(/[^0-9.]/g, '').slice(0, 20) } as Partial<OsConditionForm>)}
          placeholder={placeholder}
          inputMode="decimal"
          autoCapitalize="off" autoCorrect="off" spellCheck={false}
          className={clsx(field, 'font-mono')}
        />
      </label>
    );
    selectors = (
      <>
        {value.platform === 'linux' && (
          <label className="space-y-0.5 min-w-0">
            <span className={lbl}>{t('softwareCompliance.osCond.distro') || 'Distribution'}</span>
            <select value={value.distro} onChange={(e) => set({ distro: e.target.value })} className={field}>
              <option value="">{t('softwareCompliance.osCond.distroAny') || 'All distributions'}</option>
              <optgroup label={t('softwareCompliance.osCond.families') || 'Families'}>
                {LINUX_FAMILIES.map((d) => <option key={d.key} value={d.key}>{d.label}</option>)}
              </optgroup>
              <optgroup label={t('softwareCompliance.osCond.distros') || 'Distributions'}>
                {LINUX_DISTROS.map((d) => <option key={d.key} value={d.key}>{d.label}</option>)}
              </optgroup>
            </select>
          </label>
        )}
        {versionInput('minVersion', fromLabel)}
        {versionInput('maxVersion', toLabel)}
      </>
    );
  }

  return (
    <div className="space-y-1">
      <div className={clsx('grid grid-cols-1 gap-2', value.platform === 'windows' || value.platform === 'linux' ? 'sm:grid-cols-3' : 'sm:grid-cols-2')}>
        {selectors}
      </div>
      {rangeInverted(value) ? (
        <p className="flex items-center gap-1 text-[11px] text-amber-400">
          <AlertTriangle className="w-3 h-3 shrink-0" />
          {t('softwareCompliance.osCond.rangeInverted') || '"From" is after "Up to": no device will match.'}
        </p>
      ) : value.platform === 'linux' && !LINUX_DISTROS.some((d) => d.key === value.distro) && (value.minVersion || value.maxVersion) ? (
        <p className="flex items-center gap-1 text-[11px] text-amber-400">
          <AlertTriangle className="w-3 h-3 shrink-0" />
          {t('softwareCompliance.osCond.linuxVersionNeedsDistro') || 'Versions differ between distributions: pick a distribution for a version range.'}
        </p>
      ) : null}
    </div>
  );
}
