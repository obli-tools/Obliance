import { useCallback, useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { AlertCircle, CheckCircle2, ListTree, Loader2, Minus, RefreshCw } from 'lucide-react';
import { clsx } from 'clsx';
import toast from 'react-hot-toast';
import { scenarioApi, type ScenarioBatchConsolidated, type ScenarioRunBatch } from '@/api/scenario.api';
import { ConsolidatedOutputModal } from '@/components/automation/ConsolidatedOutputModal';

// Recent batches of a scenario (the runs one firing created on several
// devices: manual trigger, "Run on devices", one cron tick — older runs are
// grouped by the server) with, per batch, the consolidated output of a script
// node: one line "MACHINE: output" per device.

const slug = (s: string) => s.replace(/[^a-z0-9_-]+/gi, '-').replace(/^-+|-+$/g, '').toLowerCase() || 'scenario';

export function ScenarioBatchList({ scenarioId, scenarioName }: { scenarioId: number; scenarioName: string }) {
  const { t } = useTranslation();
  const [batches, setBatches] = useState<ScenarioRunBatch[] | null>(null);
  const [refreshing, setRefreshing] = useState(false);
  const [open, setOpen] = useState<{ batch: ScenarioRunBatch; nodeId: number | null; data: ScenarioBatchConsolidated | null } | null>(null);
  // Ignore answers of a request superseded by a newer one (node switch).
  const reqSeq = useRef(0);

  const load = useCallback(async () => {
    setRefreshing(true);
    try {
      setBatches(await scenarioApi.listBatches(scenarioId));
    } catch {
      toast.error(t('common.error'));
      setBatches((b) => b ?? []);
    } finally {
      setRefreshing(false);
    }
  }, [scenarioId, t]);

  useEffect(() => { void load(); }, [load]);

  // Live while a batch is still running.
  const anyRunning = (batches ?? []).some((b) => b.counts.running > 0);
  useEffect(() => {
    if (!anyRunning) return;
    const id = setInterval(() => { void load(); }, 5000);
    return () => clearInterval(id);
  }, [anyRunning, load]);

  const fetchConsolidated = useCallback((batch: ScenarioRunBatch, nodeId: number | null) => {
    const seq = ++reqSeq.current;
    setOpen({ batch, nodeId, data: null });
    scenarioApi.getBatchConsolidated(scenarioId, batch.key, nodeId)
      .then((data) => {
        if (seq !== reqSeq.current) return;
        setOpen((o) => o && { ...o, nodeId: data.nodeId, data });
      })
      .catch(() => {
        if (seq !== reqSeq.current) return;
        toast.error(t('common.error'));
        setOpen(null);
      });
  }, [scenarioId, t]);

  const when = (b: ScenarioRunBatch) => (b.startedAt ? new Date(b.startedAt).toLocaleString() : '');
  const nodes = open?.data?.scriptNodes ?? [];
  const nodeLabel = nodes.find((n) => n.nodeId === open?.nodeId)?.label;

  const nodePicker = open?.data && nodes.length > 1 ? (
    <label className="flex flex-wrap items-center gap-2 text-xs text-text-muted">
      <span>{t('scenarios.batches.node') || 'Script node'}</span>
      <select
        value={open.nodeId ?? ''}
        onChange={(e) => fetchConsolidated(open.batch, Number(e.target.value))}
        className="flex-1 min-w-[12rem] px-2 py-1.5 text-sm bg-bg-secondary rounded-lg text-text-primary focus:outline-none focus:ring-1 focus:ring-accent coarse:min-h-10"
      >
        {nodes.map((n) => (
          <option key={n.nodeId} value={n.nodeId}>
            {n.label}{n.runCount === 0 ? ` (${t('scenarios.batches.notReached') || 'not reached'})` : ''}
          </option>
        ))}
      </select>
    </label>
  ) : open?.data && nodes.length === 0 ? (
    <p className="text-xs text-text-muted">{t('scenarios.batches.noScriptNode') || 'This scenario has no script or command node.'}</p>
  ) : null;

  return (
    <div className="flex-1 min-h-0 overflow-y-auto overscroll-contain">
      <div className="flex items-center gap-2 px-3 py-2 border-b border-border/50">
        <p className="flex-1 min-w-0 text-[11px] text-text-muted">
          {t('scenarios.batches.hint') || 'One line per firing (manual trigger, schedule tick…) with all the machines it ran on.'}
        </p>
        <button
          onClick={() => { void load(); }}
          title={t('common.refresh') || 'Refresh'}
          aria-label={t('common.refresh') || 'Refresh'}
          className="p-1.5 rounded-lg text-text-muted hover:text-text-primary hover:bg-bg-tertiary coarse:min-h-10 coarse:min-w-10 flex items-center justify-center"
        >
          <RefreshCw className={clsx('w-3.5 h-3.5', refreshing && 'animate-spin')} />
        </button>
      </div>

      {batches == null ? (
        <div className="p-8 flex justify-center"><Loader2 className="w-5 h-5 animate-spin text-text-muted" /></div>
      ) : batches.length === 0 ? (
        <div className="p-8 text-center text-xs text-text-muted">
          {t('scenarios.batches.empty') || 'No runs yet. Trigger the scenario to create one.'}
        </div>
      ) : (
        <div className="divide-y divide-border/50">
          {batches.map((b) => (
            <div key={b.key} className="px-3 py-2 coarse:py-3 flex flex-wrap items-center gap-x-3 gap-y-2 text-xs">
              <div className="flex-1 min-w-[10rem]">
                <div className="font-medium text-text-primary">
                  {t('scenarios.batches.devices', { count: b.deviceCount }) || `${b.deviceCount} machines`}
                </div>
                <div className="text-[10px] text-text-muted mt-0.5">{b.triggerType} · {when(b)}</div>
              </div>
              <div className="flex items-center gap-1.5">
                {b.counts.success > 0 && (
                  <span title={t('scenarios.batches.success') || 'Succeeded'} className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded border text-[10px] font-medium tabular-nums text-green-400 bg-green-400/10 border-green-400/30">
                    <CheckCircle2 className="w-3 h-3" />{b.counts.success}
                  </span>
                )}
                {b.counts.failed > 0 && (
                  <span title={t('scenarios.batches.failed') || 'Failed'} className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded border text-[10px] font-medium tabular-nums text-red-400 bg-red-400/10 border-red-400/30">
                    <AlertCircle className="w-3 h-3" />{b.counts.failed}
                  </span>
                )}
                {b.counts.running > 0 && (
                  <span title={t('scenarios.batches.running') || 'Running'} className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded border text-[10px] font-medium tabular-nums text-blue-400 bg-blue-400/10 border-blue-400/30">
                    <Loader2 className="w-3 h-3 animate-spin" />{b.counts.running}
                  </span>
                )}
                {b.counts.cancelled > 0 && (
                  <span title={t('scenarios.batches.cancelled') || 'Cancelled'} className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded border text-[10px] font-medium tabular-nums text-gray-400 bg-gray-400/10 border-gray-400/30">
                    <Minus className="w-3 h-3" />{b.counts.cancelled}
                  </span>
                )}
              </div>
              <button
                onClick={() => fetchConsolidated(b, null)}
                className="flex items-center gap-1.5 px-3 py-1.5 text-xs rounded-lg bg-accent/10 border border-accent/30 text-accent hover:bg-accent/20 transition-colors coarse:min-h-10"
              >
                <ListTree className="w-3.5 h-3.5" />
                {t('automation.consolidated.open') || 'Consolidated output'}
              </button>
            </div>
          ))}
        </div>
      )}

      <ConsolidatedOutputModal
        open={!!open}
        onClose={() => { reqSeq.current++; setOpen(null); }}
        title={open ? `${scenarioName}${nodeLabel ? ` › ${nodeLabel}` : ''} — ${when(open.batch)}` : ''}
        rows={open?.data ? open.data.rows : null}
        fileName={`${slug(scenarioName)}${nodeLabel ? `-${slug(nodeLabel)}` : ''}`}
        extra={nodePicker}
      />
    </div>
  );
}
