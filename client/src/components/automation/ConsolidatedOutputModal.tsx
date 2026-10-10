import { useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Copy, Download, FileText, Layers, ListTree, Loader2, Search } from 'lucide-react';
import { clsx } from 'clsx';
import toast from 'react-hot-toast';
import { Modal } from '@/components/common/Modal';
import { copyText } from '@/utils/clipboard';
import { saveText } from '@/utils/download';

// One script run on N machines (an Automations › History batch, a schedule
// run, a scenario script node) shown as ONE consolidated output: a line per
// machine "MACHINE: output", identical outputs grouped, filter, copy and
// export. The rows come from the caller (already permission-filtered by the
// server endpoints that list them).

export interface ConsolidatedRow {
  deviceId: number;
  device: string;
  /** Execution status as stored (success, failure, timeout, pending, sent, running…). */
  status: string;
  exitCode: number | null;
  stdout: string | null;
  stderr: string | null;
}

export type ConsolidatedOutcome = 'ok' | 'failed' | 'waiting' | 'skipped';

export function outcomeOf(r: Pick<ConsolidatedRow, 'status' | 'exitCode'>): ConsolidatedOutcome {
  const s = (r.status || '').toLowerCase();
  if (['pending', 'sent', 'running', 'queued', 'waiting', 'in_progress'].includes(s)) return 'waiting';
  // Not run on this machine (scenario path that never reached the node, cancelled run).
  if (s === 'skipped' || s === 'cancelled') return 'skipped';
  if (['success', 'completed', 'succeeded', 'passed', 'ok'].includes(s)) return r.exitCode != null && r.exitCode !== 0 ? 'failed' : 'ok';
  if (s === '' && r.exitCode === 0) return 'ok';
  return 'failed';
}

/** The output of a row: stdout, else stderr (a failing script often only writes there). */
function outputOf(r: ConsolidatedRow): string {
  const out = (r.stdout ?? '').replace(/\r\n/g, '\n').trim();
  if (out) return out;
  return (r.stderr ?? '').replace(/\r\n/g, '\n').trim();
}

function firstLine(s: string): string {
  const line = s.split('\n').find((l) => l.trim() !== '');
  return (line ?? '').trim();
}

const OUTCOME_CLR: Record<ConsolidatedOutcome, string> = {
  ok: 'text-green-400 bg-green-400/10 border-green-400/30',
  failed: 'text-red-400 bg-red-400/10 border-red-400/30',
  waiting: 'text-yellow-400 bg-yellow-400/10 border-yellow-400/30',
  skipped: 'text-text-muted bg-bg-tertiary border-transparent',
};

export function ConsolidatedOutputModal({ open, onClose, title, rows, fileName, extra }: {
  open: boolean;
  onClose: () => void;
  title: string;
  /** null: loading. */
  rows: ConsolidatedRow[] | null;
  /** Export file name, without extension. */
  fileName: string;
  /** Above the summary (e.g. the script node picker of a scenario run). */
  extra?: React.ReactNode;
}) {
  const { t } = useTranslation();
  const [full, setFull] = useState(false);
  const [grouped, setGrouped] = useState(false);
  const [query, setQuery] = useState('');
  const [outcome, setOutcome] = useState<ConsolidatedOutcome | 'all'>('all');

  const outcomeLabel = (o: ConsolidatedOutcome) => o === 'ok'
    ? (t('automation.consolidated.ok') || 'OK')
    : o === 'failed'
      ? (t('automation.consolidated.failed') || 'Failed')
      : o === 'waiting'
        ? (t('automation.consolidated.waiting') || 'No answer yet')
        : (t('automation.consolidated.skipped') || 'Not run');

  const prepared = useMemo(() => (rows ?? [])
    .map((r) => {
      const all = outputOf(r);
      return { ...r, outcome: outcomeOf(r), all, line: firstLine(all) };
    })
    .sort((a, b) => a.device.localeCompare(b.device, undefined, { numeric: true, sensitivity: 'base' })), [rows]);

  const counts = useMemo(() => {
    const c = { ok: 0, failed: 0, waiting: 0, skipped: 0 };
    prepared.forEach((r) => { c[r.outcome]++; });
    return c;
  }, [prepared]);

  const text = (r: (typeof prepared)[number]) => (full ? r.all : r.line);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return prepared.filter((r) => (outcome === 'all' || r.outcome === outcome)
      && (!q || r.device.toLowerCase().includes(q) || text(r).toLowerCase().includes(q)));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [prepared, query, outcome, full]);

  const groups = useMemo(() => {
    const m = new Map<string, typeof filtered>();
    filtered.forEach((r) => {
      const k = text(r);
      const g = m.get(k);
      if (g) g.push(r); else m.set(k, [r]);
    });
    return [...m.entries()].map(([output, items]) => ({ output, items })).sort((a, b) => b.items.length - a.items.length);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [filtered, full]);

  const noOutput = t('automation.consolidated.noOutput') || '(no output)';

  // "MACHINE: output" — a multi-line output keeps its lines, indented.
  const asText = () => filtered.map((r) => {
    const out = text(r) || noOutput;
    const [head, ...rest] = out.split('\n');
    return [`${r.device}: ${head}`, ...rest.map((l) => `    ${l}`)].join('\n');
  }).join('\n');

  const asCsv = () => {
    const cell = (v: unknown) => '"' + String(v ?? '').replace(/"/g, '""') + '"';
    const head = ['Device', 'Status', 'Result', 'Exit code', 'Output'];
    const lines = [head.map(cell).join(',')];
    filtered.forEach((r) => lines.push([r.device, r.status, r.outcome, r.exitCode ?? '', text(r)].map(cell).join(',')));
    return '﻿' + lines.join('\r\n') + '\r\n';
  };

  const doCopy = async () => {
    if (await copyText(asText())) toast.success(t('automation.consolidated.copied', { count: filtered.length }) || `${filtered.length} lines copied`);
    else toast.error(t('common.error'));
  };
  const stamp = new Date().toISOString().slice(0, 16).replace(/[:T]/g, '-');
  const doTxt = () => void saveText(asText() + '\n', `${fileName}-${stamp}.txt`);
  const doCsv = () => void saveText(asCsv(), `${fileName}-${stamp}.csv`, 'text/csv;charset=utf-8');

  const chip = (o: ConsolidatedOutcome | 'all', n: number, label: string) => (
    <button
      key={o}
      onClick={() => setOutcome(outcome === o ? 'all' : o)}
      aria-pressed={outcome === o}
      className={clsx(
        'px-2.5 py-1 rounded-full border text-xs font-medium tabular-nums transition-colors coarse:min-h-9',
        o === 'all' ? 'text-text-primary bg-bg-tertiary border-transparent' : OUTCOME_CLR[o],
        outcome === o ? 'ring-1 ring-accent' : 'opacity-90 hover:opacity-100',
      )}
    >
      {n} {label}
    </button>
  );

  const toggle = (on: boolean, set: (v: boolean) => void, icon: React.ReactNode, label: string) => (
    <button
      onClick={() => set(!on)}
      aria-pressed={on}
      className={clsx(
        'flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg border text-xs transition-colors coarse:min-h-10',
        on ? 'bg-accent/10 border-accent/40 text-accent' : 'border-transparent text-text-muted hover:text-text-primary hover:bg-bg-tertiary',
      )}
    >
      {icon}{label}
    </button>
  );

  return (
    <Modal
      open={open}
      onClose={onClose}
      size="2xl"
      title={title}
      icon={<ListTree className="w-5 h-5 text-accent" />}
      bodyClassName="space-y-3"
    >
      {extra}
      {rows == null ? (
        <div className="flex items-center justify-center h-40"><Loader2 className="w-5 h-5 animate-spin text-text-muted" /></div>
      ) : rows.length === 0 ? (
        <p className="text-sm text-text-muted text-center py-10">{t('automation.consolidated.empty') || 'No machine in this run.'}</p>
      ) : (
        <>
          <div className="flex flex-wrap items-center gap-1.5">
            {chip('all', prepared.length, t('automation.consolidated.machines', { count: prepared.length }) || 'machines')}
            {counts.ok > 0 && chip('ok', counts.ok, outcomeLabel('ok'))}
            {counts.failed > 0 && chip('failed', counts.failed, outcomeLabel('failed'))}
            {counts.waiting > 0 && chip('waiting', counts.waiting, outcomeLabel('waiting'))}
            {counts.skipped > 0 && chip('skipped', counts.skipped, outcomeLabel('skipped'))}
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <div className="relative flex-1 min-w-[12rem]">
              <Search className="w-3.5 h-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-text-muted" />
              <input
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder={t('automation.consolidated.search') || 'Filter: machine or output contains…'}
                className="w-full pl-8 pr-2 py-1.5 text-sm bg-bg-secondary rounded-lg text-text-primary focus:outline-none focus:ring-1 focus:ring-accent"
              />
            </div>
            {toggle(full, setFull, <FileText className="w-3.5 h-3.5" />, t('automation.consolidated.fullOutput') || 'Full output')}
            {toggle(grouped, setGrouped, <Layers className="w-3.5 h-3.5" />, t('automation.consolidated.group') || 'Group identical')}
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <button onClick={doCopy} disabled={!filtered.length} className="flex items-center gap-1.5 px-3 py-1.5 text-xs rounded-lg bg-accent/10 border border-accent/30 text-accent hover:bg-accent/20 disabled:opacity-50 coarse:min-h-10">
              <Copy className="w-3.5 h-3.5" />{t('automation.consolidated.copy') || 'Copy "MACHINE: output"'}
            </button>
            <button onClick={doTxt} disabled={!filtered.length} className="flex items-center gap-1.5 px-3 py-1.5 text-xs rounded-lg text-text-muted hover:text-text-primary hover:bg-bg-tertiary disabled:opacity-50 coarse:min-h-10">
              <Download className="w-3.5 h-3.5" />TXT
            </button>
            <button onClick={doCsv} disabled={!filtered.length} className="flex items-center gap-1.5 px-3 py-1.5 text-xs rounded-lg text-text-muted hover:text-text-primary hover:bg-bg-tertiary disabled:opacity-50 coarse:min-h-10">
              <Download className="w-3.5 h-3.5" />CSV
            </button>
            <span className="text-xs text-text-muted ml-auto">
              {t('automation.consolidated.shown', { count: filtered.length, total: prepared.length }) || `${filtered.length} / ${prepared.length}`}
            </span>
          </div>

          {grouped ? (
            <div className="space-y-2">
              {groups.map((g, i) => (
                <div key={i} className="rounded-lg bg-bg-secondary p-3 space-y-1.5 min-w-0">
                  <div className="flex items-start gap-2 min-w-0">
                    <span className="shrink-0 px-2 py-0.5 rounded bg-bg-tertiary text-xs font-semibold tabular-nums">{g.items.length} ×</span>
                    <pre className="flex-1 min-w-0 text-xs font-mono whitespace-pre-wrap break-words text-text-primary">{g.output || noOutput}</pre>
                  </div>
                  <p className="text-xs text-text-muted break-words">
                    {g.items.map((r) => r.device).join(', ')}
                  </p>
                </div>
              ))}
            </div>
          ) : (
            <div className="rounded-lg bg-bg-secondary overflow-x-auto">
              <table className="w-full text-xs">
                <tbody className="divide-y divide-bg-tertiary">
                  {filtered.map((r) => (
                    <tr key={`${r.deviceId}-${r.device}`} className="align-top">
                      <td className="px-3 py-2 font-medium text-text-primary whitespace-nowrap">{r.device}</td>
                      <td className="px-2 py-2 whitespace-nowrap">
                        <span className={clsx('px-1.5 py-0.5 rounded border text-[10px] font-medium', OUTCOME_CLR[r.outcome])}>
                          {outcomeLabel(r.outcome)}{r.exitCode != null && r.exitCode !== 0 ? ` (${r.exitCode})` : ''}
                        </span>
                      </td>
                      <td className="px-3 py-2 w-full">
                        <pre className="font-mono whitespace-pre-wrap break-words text-text-primary">{text(r) || <span className="text-text-muted">{noOutput}</span>}</pre>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </>
      )}
    </Modal>
  );
}
