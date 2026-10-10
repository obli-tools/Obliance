import { Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import type { TFunction } from 'i18next';
import { AlertTriangle, CheckCircle2, HelpCircle, ShieldAlert, ShieldCheck, XCircle } from 'lucide-react';
import type { Device, WindowsPrereqCheck } from '@obliance/shared';
import { obliReachUpdateReasonText } from '@/components/devices/ObliReachAutoStatus';
import { cn } from '@/utils/cn';

// Windows NT 6.x (7 SP1 / 8.1 / Server 2008 R2 – 2012 R2) devices: the
// prerequisites the Obliance agent reports (push body `prereqs`, evaluated by
// the server: device.windowsPrereqChecks), the build line of the Obliance and
// ObliReach agents ("nt6") and the exact Windows version. Hidden on
// Windows 10+ / other OSes.

/** What the device page knows about its ObliReach agent (useObliReachAgentInfo). */
export interface WindowsPrereqsReachInfo {
  installed: boolean | null;
  flavor: 'modern' | 'nt6' | null;
  osBuild: string | null;
  updateReason: string | null;
}

function checkLabel(c: WindowsPrereqCheck, t: TFunction): string {
  switch (c.id) {
    case 'sp1': return t('winPrereqs.item.sp1', 'Service Pack 1');
    case 'sha2Signing': return t('winPrereqs.item.sha2Signing', 'SHA-2 code signing support');
    case 'kb2533623': return t('winPrereqs.item.kb2533623', 'Secure DLL loading (KB2533623)');
    case 'tls12Schannel': return t('winPrereqs.item.tls12Schannel', 'TLS 1.2 (Schannel)');
    case 'wmf51': return t('winPrereqs.item.wmf51', 'Windows PowerShell 5.1 (WMF 5.1)');
    case 'dotnet48': return t('winPrereqs.item.dotnet48', '.NET Framework 4.8');
    default: return String(c.id);
  }
}

/** Recommended action of a missing prerequisite. */
function checkAction(c: WindowsPrereqCheck, t: TFunction): string {
  switch (c.id) {
    case 'sp1': return t('winPrereqs.action.sp1', 'Install Service Pack 1 (KB976932) — required by every later update');
    case 'sha2Signing': return t('winPrereqs.action.sha2Signing', 'Install KB4474419 (SHA-2 signing) and KB3033929 — required for ObliReach updates');
    case 'kb2533623': return t('winPrereqs.action.kb2533623', 'Install KB2533623 (or its successor KB3063858) — required by recent installers and runtimes');
    case 'tls12Schannel': return t('winPrereqs.action.tls12Schannel', 'Enable TLS 1.2 (Schannel) for clients (KB3140245 + registry key SCHANNEL\\Protocols\\TLS 1.2\\Client) — needed by PowerShell, BITS and .NET downloads');
    case 'wmf51': return t('winPrereqs.action.wmf51', 'Install WMF 5.1 (needs .NET Framework 4.5.2 or later) — recommended for scripts');
    case 'dotnet48': return t('winPrereqs.action.dotnet48', 'Install .NET Framework 4.8 — recommended');
    default: return '';
  }
}

/** Reported value shown next to the label (versions, SHA-2 KBs). */
function checkValue(c: WindowsPrereqCheck, t: TFunction): string | null {
  if (c.id === 'dotnet48' && c.value === '') return t('winPrereqs.value.none', 'none');
  if (c.id === 'wmf51' && c.value) return `PowerShell ${c.value}`;
  return c.value ? String(c.value) : null;
}

function CheckIcon({ c }: { c: WindowsPrereqCheck }) {
  const cls = 'w-4 h-4 shrink-0 mt-0.5';
  if (c.status === 'ok') return <CheckCircle2 className={cn(cls, 'text-green-400')} />;
  if (c.status === 'unknown') return <HelpCircle className={cn(cls, 'text-text-muted')} />;
  if (c.severity === 'required') return <XCircle className={cn(cls, 'text-red-400')} />;
  return <AlertTriangle className={cn(cls, 'text-amber-400')} />;
}

/** "Agent for Windows 7 / 8.1 / 2008 R2 – 2012 R2" chip, or the other build lines. */
export function Nt6BuildChip({ build, className }: { build: 'modern' | 'nt6' | 'legacy' | null; className?: string }) {
  const { t } = useTranslation();
  if (build === 'nt6') {
    return (
      <span
        className={cn('inline-flex items-center px-2 py-0.5 text-xs font-semibold rounded-full bg-sky-400/10 text-sky-400 border border-sky-400/30', className)}
        title={t('winPrereqs.build.nt6Hint', 'Full build compiled for Windows 7 SP1 / 8.1 / Server 2008 R2 – 2012 R2: every feature')}
      >
        {t('winPrereqs.build.nt6', 'Agent for Windows 7 / 8.1 / 2008 R2 – 2012 R2')}
      </span>
    );
  }
  if (build === 'legacy') {
    return <span className={cn('text-xs text-amber-400', className)}>{t('winPrereqs.build.legacy', 'reduced legacy agent')}</span>;
  }
  if (build === 'modern') {
    return (
      <span className={cn('text-xs text-amber-400', className)} title={t('winPrereqs.build.modernOnNt6Hint', 'The Windows 10+ build: it moves to the Windows 7 / 8.1 / 2008 R2 – 2012 R2 build at its next update')}>
        {t('winPrereqs.build.modernOnNt6', 'Windows 10+ build (moves to the nt6 build at its next update)')}
      </span>
    );
  }
  return <span className={cn('text-xs text-text-muted', className)}>{t('winPrereqs.build.unknown', 'not reported')}</span>;
}

/** Windows build number from what the agents report ("6.3.9600.20563 Build 9600.20563" → "6.3.9600"). */
function windowsVersionOf(device: Device, reachOsBuild: string | null): string | null {
  if (reachOsBuild) return reachOsBuild;
  const m = /^\s*(\d{1,2}\.\d{1,2}\.\d{3,6})/.exec(device.osVersion ?? '') ?? /\(Build\s+(\d{4,6})\)/i.exec(device.osVersion ?? '');
  return m ? m[1] : (device.osVersion ?? null);
}

/** Windows family of an NT 6.x build (7600/7601 → 7 / 2008 R2…), null otherwise. */
function nt6FamilyOf(version: string | null, t: TFunction): string | null {
  const b = /(?:^|\.)(\d{4,6})(?:\.|$)/.exec(version ?? '')?.[1] ?? /^(\d{4,6})$/.exec(version ?? '')?.[1];
  switch (Number(b)) {
    case 7600: return t('winPrereqs.family.7rtm', 'Windows 7 / Server 2008 R2 (no Service Pack)');
    case 7601: return t('winPrereqs.family.7sp1', 'Windows 7 SP1 / Server 2008 R2 SP1');
    case 9200: return t('winPrereqs.family.8', 'Windows 8 / Server 2012');
    case 9600: return t('winPrereqs.family.81', 'Windows 8.1 / Server 2012 R2');
    default: return null;
  }
}

export function WindowsPrereqsCard({ device, reach }: { device: Device; reach?: WindowsPrereqsReachInfo }) {
  const { t } = useTranslation();
  const checks = device.windowsPrereqChecks ?? null;
  if (!device.windowsNt6 && !checks) return null;

  const missing = device.windowsPrereqsMissing ?? 0;
  const version = windowsVersionOf(device, reach?.osBuild ?? null);
  const family = nt6FamilyOf(version, t);
  const agentBuild: 'modern' | 'nt6' | 'legacy' | null = device.agentFlavor === 'legacy' ? 'legacy' : (device.agentBuild ?? null);
  const reachReason = reach?.updateReason ? (obliReachUpdateReasonText(reach.updateReason, t) ?? reach.updateReason) : null;

  return (
    <div className="p-4 bg-bg-secondary rounded-xl space-y-3" data-testid="windows-prereqs">
      <div className="flex items-center justify-between gap-2 flex-wrap">
        <h3 className="text-sm font-semibold text-text-muted uppercase tracking-wide flex items-center gap-2">
          {checks && missing > 0
            ? <ShieldAlert className="w-4 h-4 text-red-400" />
            : <ShieldCheck className="w-4 h-4 text-green-400" />}
          {t('winPrereqs.title', 'Windows prerequisites')}
        </h3>
        {checks && (missing > 0 ? (
          <Link
            to="/devices?prereqsMissing=1"
            className="text-xs font-medium px-2 py-0.5 rounded-full bg-red-500/10 text-red-400 border border-red-400/30 hover:bg-red-500/20"
            title={t('winPrereqs.listLink', 'Show every device with missing prerequisites')}
          >
            {t('winPrereqs.missingCount', { count: missing, defaultValue: '{{count}} required prerequisite(s) missing' })}
          </Link>
        ) : (
          <span className="text-xs font-medium px-2 py-0.5 rounded-full bg-green-500/10 text-green-400 border border-green-400/30">
            {t('winPrereqs.allOk', 'Required prerequisites present')}
          </span>
        ))}
      </div>

      <dl className="space-y-2 text-sm">
        <div className="flex justify-between gap-2">
          <dt className="text-text-muted shrink-0">{t('winPrereqs.windowsVersion', 'Windows version')}</dt>
          <dd className="text-text-primary font-medium text-right min-w-0">
            <span className="break-words">{device.osName ?? 'Windows'}</span>
            {version && <span className="ml-1 font-mono text-xs text-text-muted">{version}</span>}
            {family && <div className="text-xs text-text-muted">{family}</div>}
          </dd>
        </div>
        <div className="flex justify-between gap-2 items-center">
          <dt className="text-text-muted shrink-0">{t('winPrereqs.oblianceAgent', 'Obliance agent')}</dt>
          <dd className="min-w-0 text-right"><Nt6BuildChip build={agentBuild} /></dd>
        </div>
        {reach?.installed === true && (
          <div className="flex justify-between gap-2 items-center">
            <dt className="text-text-muted shrink-0">ObliReach</dt>
            <dd className="min-w-0 text-right"><Nt6BuildChip build={reach.flavor} /></dd>
          </div>
        )}
      </dl>

      {checks ? (
        <ul className="space-y-2">
          {checks.map((c) => {
            const value = checkValue(c, t);
            return (
              <li key={c.id} className="flex items-start gap-2 text-sm">
                <CheckIcon c={c} />
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-text-primary font-medium">{checkLabel(c, t)}</span>
                    {value && <span className="font-mono text-xs text-text-muted">{value}</span>}
                    <span className="text-[10px] uppercase tracking-wide text-text-muted">
                      {c.severity === 'required'
                        ? t('winPrereqs.severity.required', 'required')
                        : t('winPrereqs.severity.recommended', 'recommended')}
                    </span>
                  </div>
                  {c.status === 'missing' && (
                    <p className={cn('text-xs mt-0.5', c.severity === 'required' ? 'text-red-400' : 'text-amber-400')}>
                      {checkAction(c, t)}
                    </p>
                  )}
                  {c.status === 'unknown' && (
                    <p className="text-xs mt-0.5 text-text-muted">{t('winPrereqs.unknown', 'not reported yet')}</p>
                  )}
                </div>
              </li>
            );
          })}
        </ul>
      ) : (
        <p className="text-xs text-text-muted">
          {device.agentFlavor === 'legacy'
            ? t('winPrereqs.notReportedLegacy', 'The reduced legacy agent does not report the prerequisites: migrate it to the full agent.')
            : t('winPrereqs.notReported', 'Prerequisites not reported yet: they appear once the agent runs a version that reports them.')}
        </p>
      )}

      {reachReason && (
        <p className="text-xs text-red-400 flex items-start gap-1.5">
          <AlertTriangle className="w-3.5 h-3.5 shrink-0 mt-0.5" />
          <span>{t('winPrereqs.reachUpdateFailed', { reason: reachReason, defaultValue: 'Last ObliReach update failure: {{reason}}' })}</span>
        </p>
      )}
    </div>
  );
}
