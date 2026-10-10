import { useCallback, useEffect, useState, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { Bug, ShieldCheck, Package, ChevronRight, ChevronDown, Loader2, History } from 'lucide-react';
import { clsx } from 'clsx';
import { cveApi } from '@/api/cve.api';
import { complianceApi } from '@/api/compliance.api';
import { softwareComplianceApi } from '@/api/softwareCompliance.api';
import type { DeviceCve, ComplianceResult, SoftwareComplianceResult } from '@obliance/shared';

// Compliance section of a device: the data of the three sub-tabs (CVEs,
// compliance checks, software compliance), summarized for the Overview
// sub-tab and the sub-tab badges. Each detail sub-tab still loads its own
// data (actions, expand state…); this is only the summary.

export type DeviceComplianceSubTab = 'overview' | 'cves' | 'checks' | 'software';

export interface DeviceComplianceSummary {
  loading: boolean;
  /** null: no access (cve:read) or not loaded. */
  cves: DeviceCve[] | null;
  checks: ComplianceResult[] | null;
  software: SoftwareComplianceResult[] | null;
  /** Rules ignored on this device, by policy id. */
  ignored: Record<number, string[]>;
  reload: () => void;
}

export function useDeviceComplianceSummary(deviceId: number, canSeeCves: boolean): DeviceComplianceSummary {
  const [state, setState] = useState<Omit<DeviceComplianceSummary, 'reload'>>({ loading: true, cves: null, checks: null, software: null, ignored: {} });

  const reload = useCallback(() => {
    let alive = true;
    setState((s) => ({ ...s, loading: true }));
    Promise.all([
      canSeeCves ? cveApi.listForDevice(deviceId).catch(() => null) : Promise.resolve(null),
      complianceApi.listResults({ deviceId }).then((r) => r.items).catch(() => null),
      softwareComplianceApi.getDeviceResults(deviceId).catch(() => null),
      complianceApi.getIgnoredRules(deviceId).catch(() => ({} as Record<number, string[]>)),
    ]).then(([cves, checks, software, ignored]) => {
      if (alive) setState({ loading: false, cves, checks, software, ignored: ignored ?? {} });
    });
    return () => { alive = false; };
  }, [deviceId, canSeeCves]);

  useEffect(() => reload(), [reload]);
  return { ...state, reload };
}

const SEVERITIES = ['critical', 'high', 'medium', 'low'] as const;
const SEVERITY_CLR: Record<string, string> = {
  critical: 'text-red-400 bg-red-400/10 border-red-400/30',
  high: 'text-orange-400 bg-orange-400/10 border-orange-400/30',
  medium: 'text-yellow-400 bg-yellow-400/10 border-yellow-400/30',
  low: 'text-blue-400 bg-blue-400/10 border-blue-400/30',
};

/**
 * Results of a device are stored per check run: the CURRENT state is the
 * latest result of each policy / list; the older ones are history only.
 */
export function splitLatest<T extends { checkedAt: string }>(rows: T[] | null, key: (r: T) => number): { current: T[]; history: T[] } {
  const sorted = [...(rows ?? [])].sort((a, b) => new Date(b.checkedAt).getTime() - new Date(a.checkedAt).getTime());
  const seen = new Set<number>();
  const current: T[] = [];
  const history: T[] = [];
  for (const r of sorted) {
    const k = key(r);
    if (seen.has(k)) history.push(r);
    else { seen.add(k); current.push(r); }
  }
  return { current, history };
}

/** Older results by local day, newest first. */
function groupByDay<T extends { checkedAt: string }>(rows: T[]): Array<{ day: string; items: T[] }> {
  const out: Array<{ day: string; items: T[] }> = [];
  for (const r of rows) {
    const day = new Date(r.checkedAt).toLocaleDateString(undefined, { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' });
    const last = out[out.length - 1];
    if (last && last.day === day) last.items.push(r);
    else out.push({ day, items: [r] });
  }
  return out;
}

/** Collapsible history of the older results, grouped by day (read-only rows). */
export function ResultHistory<T extends { checkedAt: string }>({ rows, render }: { rows: T[]; render: (r: T) => ReactNode }) {
  const { t } = useTranslation();
  const [open, setOpen] = useState(false);
  if (rows.length === 0) return null;
  return (
    <div className="pt-2">
      <button
        onClick={() => setOpen((v) => !v)}
        className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-text-muted hover:text-text-primary coarse:min-h-10"
        aria-expanded={open}
      >
        {open ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronRight className="w-3.5 h-3.5" />}
        <History className="w-3.5 h-3.5" />
        {t('deviceDetail.complianceTabs.history', { count: rows.length }) || `History (${rows.length})`}
      </button>
      {open && (
        <div className="mt-2 space-y-3 opacity-80">
          {groupByDay(rows).map((g) => (
            <div key={g.day}>
              <p className="text-xs text-text-muted mb-1.5 first-letter:uppercase">{g.day}</p>
              {g.items.map((r) => render(r))}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export function scoreColor(score: number): string {
  return score >= 80 ? 'text-green-400' : score >= 50 ? 'text-yellow-400' : 'text-red-400';
}

export function averageScore(rows: Array<{ complianceScore: number }> | null): number | null {
  if (!rows || rows.length === 0) return null;
  return rows.reduce((a, r) => a + (Number(r.complianceScore) || 0), 0) / rows.length;
}

export function failedChecks(r: ComplianceResult, ignored: Record<number, string[]> = {}): number {
  const ign = ignored[r.policyId] ?? [];
  return r.results.filter((x) => x.status === 'fail' && !x.ignored && !ign.includes(x.ruleId)).length;
}

export function softwareIssues(r: SoftwareComplianceResult): number {
  return r.results.filter((x) => x.status === 'non_compliant' || x.status === 'remediation_failed' || x.status === 'error').length;
}

/** Badge of a sub-tab: the CVE count / the average score. */
export function subTabBadge(kind: 'cves' | 'checks' | 'software', s: DeviceComplianceSummary): ReactNode {
  if (s.loading) return null;
  if (kind === 'cves') {
    if (!s.cves) return null;
    const crit = s.cves.some((c) => c.cve.kevFlag || c.cve.severity === 'critical');
    return (
      <span className={clsx('px-1.5 rounded-full text-[10px] font-semibold tabular-nums',
        s.cves.length === 0 ? 'bg-green-400/10 text-green-400' : crit ? 'bg-red-400/15 text-red-400' : 'bg-orange-400/15 text-orange-400')}>
        {s.cves.length}
      </span>
    );
  }
  const avg = kind === 'checks'
    ? averageScore(s.checks && splitLatest(s.checks, (r) => r.policyId).current)
    : averageScore(s.software && splitLatest(s.software, (r) => r.listId).current);
  if (avg == null) return null;
  return <span className={clsx('text-[10px] font-semibold tabular-nums', scoreColor(avg))}>{avg.toFixed(0)}%</span>;
}

function Card({ icon, title, onOpen, children }: { icon: ReactNode; title: string; onOpen: () => void; children: ReactNode }) {
  const { t } = useTranslation();
  return (
    <div className="rounded-xl bg-bg-secondary p-4 flex flex-col gap-3 min-w-0">
      <div className="flex items-center gap-2">
        {icon}
        <h3 className="text-sm font-semibold text-text-primary flex-1 min-w-0 truncate">{title}</h3>
        <button
          onClick={onOpen}
          className="flex items-center gap-0.5 text-xs text-accent hover:underline shrink-0 coarse:min-h-10"
        >
          {t('deviceDetail.complianceTabs.details') || 'Details'}
          <ChevronRight className="w-3.5 h-3.5" />
        </button>
      </div>
      {children}
    </div>
  );
}

function Big({ value, className, sub }: { value: ReactNode; className?: string; sub: ReactNode }) {
  return (
    <div className="flex items-baseline gap-2 min-w-0">
      <span className={clsx('text-3xl font-bold tabular-nums', className)}>{value}</span>
      <span className="text-xs text-text-muted min-w-0">{sub}</span>
    </div>
  );
}

function Empty({ children }: { children: ReactNode }) {
  return <p className="text-sm text-text-muted">{children}</p>;
}

/** The worst rows (lowest score first) with their score. */
function WorstList({ rows }: { rows: Array<{ key: number; name: string; score: number; issues: number; issuesLabel: string }> }) {
  if (rows.length === 0) return null;
  return (
    <ul className="space-y-1.5">
      {rows.map((r) => (
        <li key={r.key} className="flex items-center gap-2 text-xs min-w-0">
          <span className={clsx('w-10 text-right font-semibold tabular-nums shrink-0', scoreColor(r.score))}>{r.score.toFixed(0)}%</span>
          <span className="flex-1 min-w-0 truncate text-text-primary">{r.name}</span>
          {r.issues > 0 && <span className="text-red-400 shrink-0">{r.issuesLabel}</span>}
        </li>
      ))}
    </ul>
  );
}

export function DeviceComplianceOverview({ summary, canSeeCves, onOpen }: {
  summary: DeviceComplianceSummary;
  canSeeCves: boolean;
  onOpen: (tab: Exclude<DeviceComplianceSubTab, 'overview'>) => void;
}) {
  const { t } = useTranslation();

  if (summary.loading) {
    return (
      <div className="flex items-center justify-center h-48">
        <Loader2 className="w-5 h-5 animate-spin text-text-muted" />
      </div>
    );
  }

  const cves = summary.cves ?? [];
  const kev = cves.filter((c) => c.cve.kevFlag).length;
  const bySev = Object.fromEntries(SEVERITIES.map((s) => [s, cves.filter((c) => c.cve.severity === s).length])) as Record<string, number>;

  const checks = splitLatest(summary.checks, (r) => r.policyId).current;
  const checksAvg = averageScore(checks);
  const checksFailed = checks.reduce((a, r) => a + failedChecks(r, summary.ignored), 0);

  const software = splitLatest(summary.software, (r) => r.listId).current;
  const swAvg = averageScore(software);
  const swIssues = software.reduce((a, r) => a + softwareIssues(r), 0);

  const worst = <T,>(rows: T[], score: (r: T) => number, n = 4) => [...rows].sort((a, b) => score(a) - score(b)).slice(0, n);

  return (
    <div className={clsx('grid grid-cols-1 gap-4', canSeeCves ? 'lg:grid-cols-3' : 'lg:grid-cols-2')}>
      {canSeeCves && (
        <Card icon={<Bug className="w-5 h-5 text-red-400 shrink-0" />} title={t('deviceDetail.complianceTabs.cves') || 'CVEs'} onOpen={() => onOpen('cves')}>
          {summary.cves == null ? (
            <Empty>{t('deviceDetail.complianceTabs.unavailable') || 'Unavailable'}</Empty>
          ) : cves.length === 0 ? (
            <Big value="0" className="text-green-400" sub={t('deviceDetail.complianceTabs.noCve') || 'No known vulnerability matched on this device'} />
          ) : (
            <>
              <Big
                value={cves.length}
                className={bySev.critical > 0 || kev > 0 ? 'text-red-400' : 'text-orange-400'}
                sub={t('deviceDetail.complianceTabs.cveMatches', { count: cves.length }) || 'CVE matches'}
              />
              <div className="flex flex-wrap gap-1.5">
                {SEVERITIES.filter((s) => bySev[s] > 0).map((s) => (
                  <span key={s} className={clsx('px-2 py-0.5 rounded border text-xs font-medium tabular-nums', SEVERITY_CLR[s])}>
                    {bySev[s]} {t(`deviceDetail.complianceTabs.sev.${s}`) || s}
                  </span>
                ))}
              </div>
              {kev > 0 && (
                <p className="text-xs text-red-400">
                  {t('cves.deviceSectionKev', { count: kev }) || `${kev} actively exploited (CISA KEV)`}
                </p>
              )}
            </>
          )}
        </Card>
      )}

      <Card icon={<ShieldCheck className="w-5 h-5 text-accent shrink-0" />} title={t('deviceDetail.complianceTabs.checks') || 'Compliance checks'} onOpen={() => onOpen('checks')}>
        {summary.checks == null ? (
          <Empty>{t('deviceDetail.complianceTabs.unavailable') || 'Unavailable'}</Empty>
        ) : checksAvg == null ? (
          <Empty>{t('deviceDetail.complianceTabs.noChecks') || 'No compliance check run yet'}</Empty>
        ) : (
          <>
            <Big
              value={`${checksAvg.toFixed(0)}%`}
              className={scoreColor(checksAvg)}
              sub={t('deviceDetail.complianceTabs.checksSub', { count: checks.length, failed: checksFailed }) || `${checks.length} policies · ${checksFailed} failed rules`}
            />
            <WorstList rows={worst(checks, (r) => r.complianceScore).map((r) => ({
              key: r.id,
              name: r.policy?.name ?? `#${r.policyId}`,
              score: r.complianceScore,
              issues: failedChecks(r, summary.ignored),
              issuesLabel: t('deviceDetail.complianceTabs.failedCount', { count: failedChecks(r, summary.ignored) }) || `${failedChecks(r, summary.ignored)} failed`,
            }))} />
          </>
        )}
      </Card>

      <Card icon={<Package className="w-5 h-5 text-accent shrink-0" />} title={t('deviceDetail.complianceTabs.software') || 'Software'} onOpen={() => onOpen('software')}>
        {summary.software == null ? (
          <Empty>{t('deviceDetail.complianceTabs.unavailable') || 'Unavailable'}</Empty>
        ) : swAvg == null ? (
          <Empty>{t('deviceDetail.complianceTabs.noSoftware') || 'No software compliance check run yet'}</Empty>
        ) : (
          <>
            <Big
              value={`${swAvg.toFixed(0)}%`}
              className={scoreColor(swAvg)}
              sub={t('deviceDetail.complianceTabs.softwareSub', { count: software.length, issues: swIssues }) || `${software.length} lists · ${swIssues} non-compliant entries`}
            />
            <WorstList rows={worst(software, (r) => r.complianceScore).map((r) => ({
              key: r.id,
              name: r.list?.name ?? `#${r.listId}`,
              score: r.complianceScore,
              issues: softwareIssues(r),
              issuesLabel: t('deviceDetail.complianceTabs.issuesCount', { count: softwareIssues(r) }) || `${softwareIssues(r)} non-compliant`,
            }))} />
          </>
        )}
      </Card>
    </div>
  );
}
