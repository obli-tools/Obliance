import { useCallback, useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import toast from 'react-hot-toast';
import { ArrowUpCircle, CheckCircle2, Clock, XCircle } from 'lucide-react';
import type { Device, LegacyMigrationState } from '@obliance/shared';
import { deviceApi } from '@/api/device.api';
import { isStepUpHandled } from '@/api/client';
import { useAuthStore } from '@/store/authStore';
import { useConfirm } from '@/components/common/ConfirmDialog';

/** A "done" migration stays visible this long after the agent came back. */
const DONE_VISIBLE_MS = 7 * 86400_000;

/**
 * Migration of a device from the reduced legacy agent to the full agent
 * (nt6 MSI): the state chip + the admin button (device page header).
 * Server: POST /api/devices/:id/migrate-legacy-agent, GET …/legacy-migration.
 */
export function LegacyMigrationControl({ device }: { device: Device }) {
  const { t } = useTranslation();
  const confirm = useConfirm();
  const isAdmin = useAuthStore((s) => s.user?.role === 'admin');
  const [state, setState] = useState<LegacyMigrationState | null>(device.legacyMigration ?? null);
  const [busy, setBusy] = useState(false);

  const isLegacy = device.agentFlavor === 'legacy';
  const refresh = useCallback(() => {
    deviceApi.getLegacyMigration(device.id).then(setState).catch(() => { /* keep the last state */ });
  }, [device.id]);

  // The device row changed (socket / reload): re-read the folded state.
  useEffect(() => {
    if (isLegacy || device.legacyMigration) refresh();
  }, [isLegacy, device.legacyMigration?.state, device.legacyMigration?.commandId, device.agentFlavor, refresh]);

  // While it runs: poll the command outcome.
  const live = state?.state === 'pending' || state?.state === 'scheduled';
  useEffect(() => {
    if (!live) return;
    const h = setInterval(refresh, 15_000);
    return () => clearInterval(h);
  }, [live, refresh]);

  const start = async () => {
    const ok = await confirm({
      title: t('nt6.migration.confirmTitle') || 'Migrate to the full agent',
      message: t('nt6.migration.confirmMessage') || 'The reduced legacy agent will be replaced by the full agent (Windows 7 / 8.1 / Server 2008 R2 – 2012 R2 build): the device keeps its identity, its history and its API key. The service is stopped for about two minutes; if the installation fails, the legacy agent is restored automatically. Continue?',
      confirmLabel: t('nt6.migration.confirmButton') || 'Migrate',
    });
    if (!ok) return;
    setBusy(true);
    try {
      const r = await deviceApi.migrateLegacyAgent(device.id);
      setState(r.legacyMigration);
      toast.success(t('nt6.migration.queued') || 'Migration queued: it runs at the next contact of the agent.');
    } catch (err) {
      if (isStepUpHandled(err)) return;
      const msg = (err as { response?: { data?: { error?: unknown } } })?.response?.data?.error;
      toast.error(typeof msg === 'string' && msg ? msg : (t('nt6.migration.error') || 'The migration could not be started'));
    } finally {
      setBusy(false);
    }
  };

  const doneRecently = state?.state === 'done' && state.doneAt && Date.now() - new Date(state.doneAt).getTime() < DONE_VISIBLE_MS;
  if (!isLegacy && !doneRecently) return null;

  const chip = (cls: string, icon: React.ReactNode, text: string, title?: string) => (
    <span title={title} className={`inline-flex items-center gap-1 px-2 py-0.5 text-xs font-medium rounded-full border ${cls}`}>
      {icon}
      {text}
    </span>
  );

  return (
    <span className="inline-flex items-center gap-1.5 flex-wrap">
      {state?.state === 'pending' && chip('bg-blue-500/10 text-blue-400 border-blue-400/30', <Clock className="w-3 h-3" />,
        t('nt6.migration.statePending') || 'Migration queued')}
      {state?.state === 'scheduled' && chip('bg-blue-500/10 text-blue-400 border-blue-400/30', <Clock className="w-3 h-3" />,
        t('nt6.migration.stateScheduled') || 'Migration in progress — the agent is replaced within a few minutes')}
      {state?.state === 'failed' && chip('bg-red-500/10 text-red-400 border-red-400/30', <XCircle className="w-3 h-3" />,
        t('nt6.migration.stateFailed') || 'Migration failed', state.error ?? undefined)}
      {state?.state === 'done' && chip('bg-green-500/10 text-green-400 border-green-400/30', <CheckCircle2 className="w-3 h-3" />,
        t('nt6.migration.stateDone') || 'Migrated to the full agent')}
      {isAdmin && isLegacy && !live && (
        <button
          type="button"
          onClick={start}
          disabled={busy}
          className="inline-flex items-center gap-1 px-2 py-0.5 text-xs font-medium rounded-full bg-[#C83232] text-white hover:opacity-90 disabled:opacity-50 coarse:min-h-8"
          title={t('nt6.migration.buttonHint') || 'Replace the reduced legacy agent by the full agent (all features, automatic updates)'}
        >
          <ArrowUpCircle className="w-3 h-3" />
          {state?.state === 'failed'
            ? (t('nt6.migration.retry') || 'Retry the migration')
            : (t('nt6.migration.button') || 'Migrate to the full agent')}
        </button>
      )}
    </span>
  );
}

/** Agent build line + PowerShell version rows of the device Identity block. */
export function AgentBuildRows({ device }: { device: Device }) {
  const { t } = useTranslation();
  if (!device.agentBuild && !device.psVersion) return null;
  return (
    <>
      {device.agentBuild && (
        <div className="flex justify-between gap-2 text-sm">
          <dt className="text-text-muted shrink-0">{t('nt6.agentBuild.label') || 'Agent build'}</dt>
          <dd className="text-text-primary font-medium truncate">
            {device.agentBuild === 'nt6' ? (
              <span
                className="inline-flex items-center px-2 py-0.5 text-xs font-semibold rounded-full bg-sky-400/10 text-sky-400 border border-sky-400/30"
                title={t('nt6.agentBuild.nt6Hint') || 'Full agent built for Windows 7 SP1 / 8.1 / Server 2008 R2 – 2012 R2: every feature'}
              >
                {t('nt6.agentBuild.nt6Chip') || 'build nt6'}
              </span>
            ) : (t('nt6.agentBuild.modern') || 'modern')}
          </dd>
        </div>
      )}
      {device.psVersion && (
        <div className="flex justify-between gap-2 text-sm">
          <dt className="text-text-muted shrink-0">{t('nt6.psVersion.label') || 'PowerShell'}</dt>
          <dd className="text-text-primary font-medium truncate">{device.psVersion}</dd>
        </div>
      )}
    </>
  );
}
