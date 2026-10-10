import { PieChart } from 'lucide-react';
import { clsx } from 'clsx';
import { useTranslation } from 'react-i18next';
import type { Device } from '@obliance/shared';
import { isCommandSupported } from '@/utils/capabilities';

/**
 * Shared pieces of the disk usage analyzer (UsageAnalyzer.tsx): the agent
 * version gate, number formatting, and the space of each drive (Windows) /
 * file system (Unix) on the explorer's roots listing.
 *
 * Port of the Oblireach Desktop analyzer (client-app/usage_viewer.go). The
 * agent's data is untrusted text: rendered as React text only, never markup.
 */

/** First Obliance agent with the analyzer (agent/usage_scan.go). */
export const USAGE_MIN_AGENT = '4.5.93';

/** 40 px tap targets on touch screens (same as ExplorerPane). */
export const TB = 'coarse:min-h-10 coarse:min-w-10 coarse:inline-flex coarse:items-center coarse:justify-center';

/** a vs b, dotted numbers ('4.5.93'): -1, 0, 1. */
export function usageVerCmp(a: string, b: string): number {
  const x = String(a || '').split(/[.\-+ ]/);
  const y = String(b || '').split(/[.\-+ ]/);
  for (let i = 0; i < 3; i++) {
    const p = parseInt(x[i], 10) || 0;
    const q = parseInt(y[i], 10) || 0;
    if (p !== q) return p < q ? -1 : 1;
  }
  return 0;
}

/** The analyzer on this device: never the legacy agent; recent enough when its version is known. */
export function usageAvailability(device: Pick<Device, 'agentFlavor' | 'agentVersion'>): { offered: boolean; ok: boolean } {
  const offered = isCommandSupported(device, 'start_usage_scan');
  const v = typeof device.agentVersion === 'string' ? device.agentVersion : '';
  return { offered, ok: offered && (!v || usageVerCmp(v, USAGE_MIN_AGENT) >= 0) };
}

export function usageNum(v: unknown): number {
  const n = Number(v);
  return Number.isFinite(n) && n > 0 ? n : 0;
}

export function usageStr(v: unknown, max = 4096): string {
  return typeof v === 'string' ? v.slice(0, max) : '';
}

/** Bytes for humans (0 B, 1.2 KB, ...). */
export function fmtBytes(bytes: number, lang?: string): string {
  const n = usageNum(bytes);
  const units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
  let v = n;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  const digits = i === 0 ? 0 : v < 10 ? 2 : v < 100 ? 1 : 0;
  let text: string;
  try { text = v.toLocaleString(lang, { maximumFractionDigits: digits, minimumFractionDigits: digits }); } catch { text = v.toFixed(digits); }
  return `${text} ${units[i]}`;
}

export function fmtInt(n: number, lang?: string): string {
  try { return Math.round(usageNum(n)).toLocaleString(lang); } catch { return String(Math.round(usageNum(n))); }
}

/** A share (0..1) as a percentage (one decimal below 10 %). */
export function fmtPct(f: number, lang?: string): string {
  const v = Math.max(0, Math.min(1, Number(f) || 0));
  try {
    return v.toLocaleString(lang, { style: 'percent', maximumFractionDigits: v >= 0.1 || v === 0 ? 0 : 1 });
  } catch {
    return `${Math.round(v * 1000) / 10} %`;
  }
}

/** 83000 ms -> '1:23', 3723000 -> '1:02:03'. */
export function fmtElapsed(ms: number): string {
  const s = Math.floor(usageNum(ms) / 1000);
  const h = Math.floor(s / 3600);
  const m = Math.floor(s / 60) % 60;
  const r = s % 60;
  const two = (v: number) => (v < 10 ? '0' : '') + v;
  return h ? `${h}:${two(m)}:${two(r)}` : `${m}:${two(r)}`;
}

/** The used share of a drive, its level ('' , 'warn' from 85 %, 'danger' from 95 %). */
function fillLevel(f: number): '' | 'warn' | 'danger' {
  return f >= 0.95 ? 'danger' : f >= 0.85 ? 'warn' : '';
}

/** A horizontal bar (0..1). */
export function UsageBar({ value, className, fillClassName }: { value: number; className?: string; fillClassName?: string }) {
  const w = (Math.max(0, Math.min(1, Number(value) || 0)) * 100).toFixed(1);
  return (
    <span className={clsx('block h-1.5 rounded-full overflow-hidden bg-text-muted/15', className)} aria-hidden="true">
      <span className={clsx('block h-full rounded-full', fillClassName ?? 'bg-accent/70')} style={{ width: `${w}%` }} />
    </span>
  );
}

/** The space of one drive / file system: fill bar, label, file system, "x free of y". */
export function DriveSpace({ totalBytes, freeBytes, label, fsType, className }: {
  totalBytes?: unknown; freeBytes?: unknown; label?: unknown; fsType?: unknown; className?: string;
}) {
  const { t, i18n } = useTranslation();
  const total = usageNum(totalBytes);
  const lbl = usageStr(label, 128);
  const fs = usageStr(fsType, 40);
  if (!total && !lbl && !fs) return null;
  const free = Math.min(total, usageNum(freeBytes));
  const used = total ? 1 - free / total : 0;
  const lv = fillLevel(used);
  return (
    <div className={clsx('mt-1 flex flex-col gap-1 min-w-0', className)}>
      {(lbl || fs) && (
        <div className="flex items-center gap-1.5 min-w-0 text-[11px] text-text-muted">
          {lbl && <span className="truncate">{lbl}</span>}
          {fs && <span className="shrink-0 px-1.5 rounded bg-bg-tertiary">{fs}</span>}
        </div>
      )}
      {total > 0 && (
        <div className="flex items-center gap-2 min-w-0 max-w-md">
          <UsageBar
            value={used}
            className="flex-1 min-w-[60px] h-2"
            fillClassName={lv === 'danger' ? 'bg-red-500' : lv === 'warn' ? 'bg-amber-400' : 'bg-accent/70'}
          />
          <span
            className={clsx('shrink-0 text-[11px] tabular-nums', lv === 'danger' ? 'text-red-400' : lv === 'warn' ? 'text-amber-400' : 'text-text-muted')}
            title={t('fileExplorer.usage.drive.used', '{{pct}} used', { pct: fmtPct(used, i18n.language) })}
          >
            {t('fileExplorer.usage.drive.free', '{{free}} free of {{total}}', { free: fmtBytes(free, i18n.language), total: fmtBytes(total, i18n.language) })}
          </span>
        </div>
      )}
    </div>
  );
}

/** The "Analyze" button of a drive / file system. */
export function AnalyzeButton({ path, device, onAnalyze, compact }: {
  path: string;
  device: Pick<Device, 'agentFlavor' | 'agentVersion'>;
  onAnalyze: (path: string) => void;
  compact?: boolean;
}) {
  const { t } = useTranslation();
  const { offered, ok } = usageAvailability(device);
  if (!offered) return null;
  const title = ok
    ? t('fileExplorer.usage.analyzeOn', 'Analyze the disk usage of {{path}}', { path })
    : agentTooOldText(t);
  return (
    <button
      type="button"
      onClick={(e) => { e.stopPropagation(); onAnalyze(path); }}
      onDoubleClick={(e) => e.stopPropagation()}
      disabled={!ok}
      title={title}
      aria-label={title}
      className={clsx(
        'inline-flex items-center gap-1 px-2 py-1 rounded-md text-xs font-medium text-text-muted hover:text-accent hover:bg-accent/10 disabled:opacity-30 disabled:cursor-not-allowed transition-colors',
        TB,
      )}
    >
      <PieChart className="w-3.5 h-3.5 shrink-0" />
      <span className={clsx(compact && 'max-sm:sr-only')}>{t('fileExplorer.usage.analyzeShort', 'Analyze')}</span>
    </button>
  );
}

export function agentTooOldText(t: ReturnType<typeof useTranslation>['t']): string {
  return t('fileExplorer.usage.err.agentTooOld', 'The disk usage analyzer needs agent {{version}} or later.', { version: USAGE_MIN_AGENT });
}

export interface UsageVolume {
  path: string;
  totalBytes: number;
  freeBytes: number;
  fsType: string;
}

/** A Unix device's file systems (list_directory roots answer: `volumes`). */
export function parseVolumes(res: unknown): UsageVolume[] {
  const list = res && typeof res === 'object' && !Array.isArray(res) && Array.isArray((res as any).volumes) ? (res as any).volumes : [];
  const out: UsageVolume[] = [];
  for (let i = 0; i < list.length && out.length < 64; i++) {
    const v = list[i];
    if (!v || typeof v !== 'object' || typeof v.path !== 'string' || v.path.charAt(0) !== '/') continue;
    const total = usageNum(v.totalBytes);
    if (!total) continue;
    out.push({ path: v.path.slice(0, 4096), totalBytes: total, freeBytes: Math.min(total, usageNum(v.freeBytes)), fsType: usageStr(v.fsType, 40) });
  }
  return out;
}

/** The file systems of a Unix device, above the listing of '/'. */
export function UsageVolumes({ volumes, device, onAnalyze }: {
  volumes: UsageVolume[];
  device: Pick<Device, 'agentFlavor' | 'agentVersion'>;
  onAnalyze: (path: string) => void;
}) {
  if (!volumes.length) return null;
  return (
    <div className="px-4 pb-3 grid gap-2 grid-cols-1 sm:grid-cols-2 xl:grid-cols-3 max-sm:px-3">
      {volumes.map((v) => (
        <div key={v.path} className="rounded-lg bg-bg-tertiary/50 px-3 py-2 min-w-0">
          <div className="flex items-center gap-2 min-w-0">
            <span className="text-sm text-text-primary font-medium truncate" title={v.path}>{v.path}</span>
            <span className="flex-1" />
            <AnalyzeButton path={v.path} device={device} onAnalyze={onAnalyze} compact />
          </div>
          <DriveSpace totalBytes={v.totalBytes} freeBytes={v.freeBytes} fsType={v.fsType} />
        </div>
      ))}
    </div>
  );
}
