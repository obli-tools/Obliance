import { useCallback, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import toast from 'react-hot-toast';
import type { RemoteSession, VirtualMachine } from '@obliance/shared';
import { remoteApi } from '@/api/remote.api';
import { ObliReachViewer } from '@/components/ObliReachViewer';
import { useConfirm } from '@/components/common/ConfirmDialog';
import { useAuthStore } from '@/store/authStore';
import { remoteStartErrorMessage, requireSessionToken } from '@/utils/remoteSession';

/**
 * Interactive console of a Hyper-V VM (helper on the host, ObliReach viewer
 * here): one hook for every place that opens it (device Hyper-V tab, the
 * Dashboard's Hyper-V grid). Same right as a remote session (capability
 * 'remote'), one console per VM: another user's open console is refused
 * (409 vm_console_busy) — an administrator is offered to take it over.
 */
export function useVmConsole() {
  const { t } = useTranslation();
  const confirm = useConfirm();
  const isAdmin = useAuthStore((s) => s.user?.role === 'admin');
  const [live, setLive] = useState<{ hostDeviceId: number; vmId: string; vmName: string; token: string; sessionId: string } | null>(null);
  const liveRef = useRef(live);
  liveRef.current = live;

  const start = useCallback(async (hostDeviceId: number, vmId: string, takeover: boolean): Promise<RemoteSession> => {
    return remoteApi.startSession(hostDeviceId, 'vmconsole', undefined, undefined, vmId, takeover ? { takeover: true } : undefined);
  }, []);

  const busyOf = (e: unknown): string | null => {
    const r = (e as { response?: { status?: number; data?: { code?: string; error?: string } } })?.response;
    return r?.status === 409 && r.data?.code === 'vm_console_busy' ? (r.data.error || '') : null;
  };

  const open = useCallback(async (vm: Pick<VirtualMachine, 'hostDeviceId' | 'vmId' | 'name'>) => {
    let sess: RemoteSession | null = null;
    try {
      try {
        sess = await start(vm.hostDeviceId, vm.vmId, false);
      } catch (e) {
        const busy = busyOf(e);
        if (busy === null || !isAdmin) throw e;
        const ok = await confirm({
          message: `${busy}\n\n${t('hyperv.console.takeoverConfirm', 'Take over this console? The other user is disconnected.')}`,
          confirmLabel: t('hyperv.console.takeover', 'Take over'),
          danger: true,
        });
        if (!ok) return;
        sess = await start(vm.hostDeviceId, vm.vmId, true);
      }
      const token = requireSessionToken(sess);
      setLive({ hostDeviceId: vm.hostDeviceId, vmId: vm.vmId, vmName: vm.name, token, sessionId: String(sess.id) });
    } catch (e) {
      if (sess) remoteApi.endSession(String(sess.id)).catch(() => {});
      const msg = remoteStartErrorMessage(e, t, t('hyperv.consoleError', 'Could not open the interactive console'), 'vmconsole');
      if (msg) toast.error(msg);
    }
  }, [confirm, isAdmin, start, t]);

  // Auto-reconnect (mobile networks drop the socket in the background): a
  // fresh session, same VM. A throw stops the viewer's loop (said first).
  const reconnect = useCallback(async () => {
    const cur = liveRef.current;
    if (!cur) return;
    // End the previous session first (a no-op when the host already ended
    // it; the server also replaces the caller's own console of this VM):
    // a reconnection never competes with its own previous session.
    try { await remoteApi.endSession(cur.sessionId); } catch { /* already over */ }
    let sess: RemoteSession;
    try {
      sess = await start(cur.hostDeviceId, cur.vmId, false);
    } catch (e) {
      const msg = remoteStartErrorMessage(e, t, t('hyperv.consoleError', 'Could not open the interactive console'), 'vmconsole');
      if (msg) toast.error(msg);
      throw e;
    }
    try {
      requireSessionToken(sess);
    } catch (e) {
      remoteApi.endSession(String(sess.id)).catch(() => {});
      throw e;
    }
    setLive((prev) => (prev ? { ...prev, token: sess.sessionToken, sessionId: String(sess.id) } : prev));
  }, [start, t]);

  const close = useCallback(async () => {
    const cur = liveRef.current;
    setLive(null);
    if (cur) {
      try { await remoteApi.endSession(cur.sessionId); } catch { /* already over */ }
    }
  }, []);

  const viewer = live ? (
    <ObliReachViewer
      sessionToken={live.token}
      deviceName={live.vmName}
      onClose={close}
      onReconnect={reconnect}
      kind="vmconsole"
    />
  ) : null;

  return { open, viewer, active: !!live };
}
