import { useCallback, useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import toast from 'react-hot-toast';
import { clsx } from 'clsx';
import { Download, Loader2, MonitorPlay, RefreshCw, ShieldCheck, Wrench, AlertTriangle, CheckCircle2 } from 'lucide-react';
import type { Command, VmConsoleStatus } from '@obliance/shared';
import { hypervApi } from '@/api/hyperv.api';
import { getSocket } from '@/socket/socketClient';
import { UpdatePolicyBadge, sourceLabel } from '@/components/settings/UpdatePolicyControls';
import { apiErrorMessage } from '@/api/sshBastion.api';

/** Progress of a running install task ({ progress: { phase, percent } }). */
function progressOf(cmd: Command | null): { phase: string; percent: number } | null {
  const p = (cmd?.result as { progress?: { phase?: unknown; percent?: unknown } } | undefined)?.progress;
  if (!p) return null;
  return { phase: typeof p.phase === 'string' ? p.phase : '', percent: typeof p.percent === 'number' ? p.percent : 0 };
}

export function vmConsolePhaseLabel(t: ReturnType<typeof useTranslation>['t'], phase: string): string {
  switch (phase) {
    case 'download': return t('hyperv.helper.phase.download', 'Downloading');
    case 'verify': return t('hyperv.helper.phase.verify', 'Checking integrity');
    case 'extract': return t('hyperv.helper.phase.extract', 'Unpacking');
    case 'done': return t('hyperv.helper.phase.done', 'Finishing');
    default: return t('hyperv.helper.phase.start', 'Starting');
  }
}

/**
 * Hyper-V block of the device page: state of the VM console helper on this
 * host (installed / version / error, install task in flight with its
 * progress) and "Install now" / "Update" / "Repair". The install is a real
 * task, also listed in the Tasks tab.
 */
export function VmConsoleHelperCard({ deviceId }: { deviceId: number }) {
  const { t } = useTranslation();
  const [st, setSt] = useState<VmConsoleStatus | null>(null);
  const [failed, setFailed] = useState(false);
  const [busy, setBusy] = useState(false);

  const load = useCallback(() => {
    hypervApi.consoleStatus(deviceId).then((s) => { setSt(s); setFailed(false); }).catch(() => setFailed(true));
  }, [deviceId]);
  useEffect(() => { load(); }, [load]);

  useEffect(() => {
    const socket = getSocket();
    if (!socket) return;
    const onCmd = (cmd: Command) => {
      if (cmd.deviceId !== deviceId || cmd.type !== 'install_vm_console') return;
      // Progress lands in place; the end re-reads the whole status.
      setSt((prev) => (prev && (cmd.status === 'pending' || cmd.status === 'sent' || cmd.status === 'ack_running')
        ? { ...prev, status: 'installing', installCommand: cmd, canInstall: false }
        : prev));
      if (!['pending', 'sent', 'ack_running'].includes(cmd.status)) load();
    };
    const onDevice = (p: { deviceId?: number; id?: number; vmConsoleState?: unknown }) => {
      if ((p.deviceId ?? p.id) === deviceId && p.vmConsoleState !== undefined) load();
    };
    socket.on('COMMAND_UPDATED', onCmd);
    socket.on('DEVICE_UPDATED', onDevice);
    return () => { socket.off('COMMAND_UPDATED', onCmd); socket.off('DEVICE_UPDATED', onDevice); };
  }, [deviceId, load]);

  const install = async (force: boolean) => {
    setBusy(true);
    try {
      const out = await hypervApi.installConsole(deviceId, force);
      if (out.alreadyRunning) {
        toast(t('hyperv.helper.alreadyRunning', 'An installation is already in progress on this host.'));
      } else if (out.delivered) {
        toast.success(t('hyperv.helper.started', 'Installation started on the host (follow it here or in the Tasks tab).'));
      } else {
        toast.success(t('hyperv.helper.queued', 'Installation queued: it starts when the host agent connects.'));
      }
      load();
    } catch (e) {
      toast.error(apiErrorMessage(e, t('hyperv.helper.installError', 'The installation could not be started')));
    } finally {
      setBusy(false);
    }
  };

  if (failed) return null;
  if (!st) {
    return <div className="rounded-lg bg-bg-secondary p-3"><Loader2 className="w-4 h-4 animate-spin text-text-muted" /></div>;
  }
  if (!st.hyperVHost) return null;

  const prog = progressOf(st.installCommand);
  const sha = st.state?.sha256 ? st.state.sha256.slice(0, 12) : null;
  const installedAt = st.state?.installedAt ? new Date(st.state.installedAt).toLocaleString() : null;
  const lastError = st.status !== 'installing' && st.lastInstall && (st.lastInstall.status === 'failure' || st.lastInstall.status === 'timeout')
    ? ((st.lastInstall.result as { error?: string } | undefined)?.error || t('hyperv.helper.failedNoDetail', 'The last installation failed.'))
    : (st.state?.error ?? null);
  const frozen = st.policy.policy === 'frozen';

  const badge = (() => {
    switch (st.status) {
      case 'installed': return { cls: 'bg-green-500/15 text-green-400', icon: <CheckCircle2 className="w-3.5 h-3.5" />, text: t('hyperv.helper.status.installed', 'Installed') };
      case 'outdated': return { cls: 'bg-amber-500/15 text-amber-400', icon: <RefreshCw className="w-3.5 h-3.5" />, text: t('hyperv.helper.status.outdated', 'Installed — newer version available') };
      case 'installing': return { cls: 'bg-accent/15 text-accent', icon: <Loader2 className="w-3.5 h-3.5 animate-spin" />, text: t('hyperv.helper.status.installing', 'Installing') };
      case 'error': return { cls: 'bg-red-500/15 text-red-400', icon: <AlertTriangle className="w-3.5 h-3.5" />, text: t('hyperv.helper.status.error', 'Installation failed') };
      case 'not_installed': return { cls: 'bg-bg-tertiary text-text-secondary', icon: <Download className="w-3.5 h-3.5" />, text: t('hyperv.helper.status.notInstalled', 'Not installed (installed at the first console opening)') };
      default: return { cls: 'bg-bg-tertiary text-text-muted', icon: <AlertTriangle className="w-3.5 h-3.5" />, text: t('hyperv.helper.status.unknown', 'Unknown (update the agent of this host to see it)') };
    }
  })();

  const action = st.status === 'installing' ? null
    : st.status === 'installed' ? { force: true, icon: <Wrench className="w-3.5 h-3.5" />, label: t('hyperv.helper.repair', 'Repair') }
    : st.status === 'outdated' ? { force: false, icon: <RefreshCw className="w-3.5 h-3.5" />, label: t('hyperv.helper.update', 'Update') }
    : { force: false, icon: <Download className="w-3.5 h-3.5" />, label: t('hyperv.helper.installNow', 'Install now') };

  return (
    <div className="rounded-lg bg-bg-secondary p-3 space-y-2">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex flex-wrap items-center gap-2 min-w-0">
          <MonitorPlay className="w-4 h-4 text-text-muted shrink-0" />
          <span className="text-sm font-medium text-text-primary">{t('hyperv.helper.title', 'Interactive console component')}</span>
          <span className={clsx('inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs font-medium', badge.cls)}>{badge.icon}{badge.text}</span>
          <UpdatePolicyBadge resolved={st.policy} kind="vmconsole" />
        </div>
        {action && (
          <button
            onClick={() => void install(action.force)}
            disabled={busy || !st.canInstall}
            title={frozen
              ? t('hyperv.helper.frozenHint', 'Installation disabled by the VM console policy ({{source}})', { source: sourceLabel(t, st.policy) })
              : !st.serverBundle ? t('hyperv.helper.noBundle', 'This server ships no console component') : undefined}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs bg-bg-tertiary text-text-primary rounded-lg hover:bg-bg-active disabled:opacity-50 transition-colors coarse:min-h-10"
          >
            {busy ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : action.icon}
            {action.label}
          </button>
        )}
      </div>

      {st.status === 'installing' && (
        <div className="space-y-1">
          <div className="flex items-center justify-between text-xs text-text-secondary">
            <span>{prog ? vmConsolePhaseLabel(t, prog.phase) : (st.installCommand?.status === 'pending'
              ? t('hyperv.helper.waitingAgent', 'Waiting for the host agent')
              : t('hyperv.helper.phase.start', 'Starting'))}</span>
            {prog && <span>{prog.percent} %</span>}
          </div>
          <div className="h-1.5 rounded-full bg-bg-tertiary overflow-hidden">
            <div className="h-full bg-accent transition-all" style={{ width: `${prog ? Math.max(3, prog.percent) : 3}%` }} />
          </div>
        </div>
      )}

      {(st.status === 'installed' || st.status === 'outdated') && (
        <p className="text-xs text-text-muted flex flex-wrap items-center gap-x-3 gap-y-1">
          {sha && <span className="font-mono">{t('hyperv.helper.version', 'Version {{sha}}', { sha })}</span>}
          {installedAt && <span>{t('hyperv.helper.installedAt', 'Installed {{date}}', { date: installedAt })}</span>}
          {st.state?.protocol != null && st.state.protocol < 2 && (
            <span className="text-amber-400">{t('hyperv.helper.oldProtocol', 'Older component: typing text and Ctrl+Alt+Del need an update')}</span>
          )}
          {st.state?.signed === true && <span className="inline-flex items-center gap-1 text-green-400"><ShieldCheck className="w-3 h-3" />{t('hyperv.helper.signed', 'Signed')}</span>}
        </p>
      )}

      {lastError && (
        <p className="text-xs text-red-400 break-words">{t('hyperv.helper.lastError', 'Last error: {{error}}', { error: lastError })}</p>
      )}
    </div>
  );
}
