import { useCallback, useEffect, useRef } from 'react';
import { useTranslation } from 'react-i18next';
import { fileApi } from '@/api/file.api';
import { getSocket } from '@/socket/socketClient';

/**
 * The file explorer's socket channel (FILE_EXPLORER_CMD → FILE_EXPLORER_RESULT),
 * read-only subset, for the Obli* agent logs viewer. Same server path as the
 * Explorer tab (socket.ts → fileExplorerGate.service.ts): the device's tenant,
 * the team capability 'files', the tenant restrictions (`command.<type>`, a
 * 'sensitive' action asks the usual step-up), the privacy unlock token attached
 * server-side, and the agent's own privacy-mode refusal. Nothing new on the
 * server: `download_file` stays audited (`file_explorer.download_file`).
 */

export type LogsExplorerCommand = 'list_directory' | 'download_file';

export interface ExplorerResult {
  id: string;
  status: string;
  result: any;
}

export interface ExplorerFileEntry {
  name: string;
  path: string;
  isDir: boolean;
  size: number;
  modified: string;
}

export function useExplorerChannel(deviceId: number) {
  const { t } = useTranslation();
  const pendingRef = useRef<Map<string, { resolve: (r: ExplorerResult) => void; timer: ReturnType<typeof setTimeout> }>>(new Map());
  const stepUpRef = useRef<Map<string, Promise<unknown>>>(new Map());

  useEffect(() => {
    const socket = getSocket();
    if (!socket) return;
    const pending = pendingRef.current;
    const onResult = (msg: { id: string; commandType: string; status: string; result: any }) => {
      const p = pending.get(msg.id);
      if (!p) return;
      clearTimeout(p.timer);
      pending.delete(msg.id);
      p.resolve({ id: msg.id, status: msg.status, result: msg.result });
    };
    socket.on('FILE_EXPLORER_RESULT', onResult);
    return () => {
      socket.off('FILE_EXPLORER_RESULT', onResult);
      for (const [, p] of pending) clearTimeout(p.timer);
      pending.clear();
    };
  }, []);

  const emit = useCallback((type: LogsExplorerCommand, payload: Record<string, unknown>, timeoutMs: number): Promise<ExplorerResult> => {
    const socket = getSocket();
    if (!socket) return Promise.reject(new Error(t('oblilogs.err.socket', 'Not connected to the server.')));
    const requestId = crypto.randomUUID();
    return new Promise<ExplorerResult>((resolve, reject) => {
      const timer = setTimeout(() => {
        pendingRef.current.delete(requestId);
        reject(new Error(t('oblilogs.err.timeout', 'The agent did not answer in time.')));
      }, timeoutMs);
      pendingRef.current.set(requestId, { resolve, timer });
      socket.emit('FILE_EXPLORER_CMD', { requestId, deviceId, commandType: type, payload });
    });
  }, [deviceId, t]);

  /** Sends the command; on `step_up_required` asks the step-up once (2FA prompt
   *  of the API client) and sends it again. Throws when the prompt is cancelled
   *  or refused (isStepUpHandled tells whether the user was already told). */
  const send = useCallback(async (type: LogsExplorerCommand, payload: Record<string, unknown>, timeoutMs = 30000): Promise<ExplorerResult> => {
    const needsStepUp = (r: ExplorerResult) => r?.status === 'failure' && r?.result?.code === 'step_up_required';
    const first = await emit(type, payload, timeoutMs);
    if (!needsStepUp(first)) return first;
    let pending = stepUpRef.current.get(type);
    const joined = !!pending;
    if (!pending) {
      pending = fileApi.stepUp(deviceId, type).finally(() => stepUpRef.current.delete(type));
      stepUpRef.current.set(type, pending);
    }
    await pending;
    const second = await emit(type, payload, timeoutMs);
    if (!joined || !needsStepUp(second)) return second;
    await fileApi.stepUp(deviceId, type);
    return emit(type, payload, timeoutMs);
  }, [emit, deviceId]);

  /** The reason of a failed command: the server's refusals translated, else
   *  the agent's own text, else ''. */
  const failureText = useCallback((res: ExplorerResult | undefined): string => {
    const r = res?.result;
    switch (r?.code) {
      case 'restricted': return t('fileExplorer.err.restricted', 'This file operation is restricted by your tenant (approval required): an approval cannot run it from the explorer. Ask an administrator.');
      case 'forbidden': return t('fileExplorer.err.forbidden', 'The file explorer is not permitted for your team on this device.');
      case 'not_found': return t('fileExplorer.err.notFound', 'Device not found.');
      case 'session': return t('fileExplorer.err.session', 'Your session has expired. Sign in again.');
      case 'step_up_required': return t('fileExplorer.err.stepUp', 'A two-factor confirmation is required for this file operation.');
      case 'invalid': return t('fileExplorer.err.invalid', 'Invalid file explorer request.');
    }
    if (typeof r?.error === 'string' && r.error) return r.error;
    if (typeof r === 'string' && r) return r;
    return '';
  }, [t]);

  return { send, failureText };
}

/** base64 → bytes (atob is fine up to the viewer's cap). */
export function base64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
