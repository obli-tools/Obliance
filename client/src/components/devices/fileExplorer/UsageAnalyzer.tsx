import { useCallback, useEffect, useReducer, useRef } from 'react';
import {
  ArrowLeft,
  ChevronRight,
  File,
  Files,
  FolderOpen,
  HardDrive,
  Loader2,
  PieChart,
  RefreshCw,
  Square,
  Trash2,
} from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { clsx } from 'clsx';
import toast from 'react-hot-toast';
import { isStepUpHandled } from '@/api/client';
import { getSocket } from '@/socket/socketClient';
import { useConfirm } from '@/components/common/ConfirmDialog';
import type { Device } from '@obliance/shared';
import { TB, UsageBar, agentTooOldText, fmtBytes, fmtElapsed, fmtInt, fmtPct, usageNum, usageStr } from './usageShared';

/**
 * Disk usage analyzer of the file explorer (TreeSize-like): which folders hold
 * the space of a drive, drilled down to the file, while the device's agent
 * walks it. Port of the Oblireach Desktop analyzer (client-app/usage_viewer.go).
 *
 * The Obliance agent (usage_scan.go, 4.5.93+) walks the tree in the
 * background; the commands travel like every explorer command
 * (FILE_EXPLORER_CMD: the device's tenant, capability 'files', the browsing
 * step-up — the analyzer is browsing for the restrictions —, the privacy
 * unlock attached server-side):
 *   start_usage_scan {path, restart} -> {scanId, root, reused}
 *   get_usage_children {scanId, paths[], limit[, files, filesLimit]} ->
 *     {state, progress, nodes: [{path, found, node, children[], childrenTotal,
 *     filesGroup, files?, filesTotal?}]}
 *   get_usage_top_files {scanId} -> {files[]} (the 100 largest)
 *   cancel_usage_scan {scanId}
 * While the scan runs, the folders on screen (the root and the expanded ones
 * not complete yet: a complete folder never changes) are read again about
 * every second, one command for them all, the next one only once the
 * previous answer came; nothing is read any more once the scan is over.
 * A deletion goes through delete_file (confirmation first); the agent takes
 * it out of its scans and the folders concerned are read again.
 *
 * The agent's data is untrusted text: React text only, never markup.
 */

export type UsageCommand = 'start_usage_scan' | 'get_usage_children' | 'get_usage_top_files' | 'cancel_usage_scan' | 'delete_file';

export interface UsageAnalyzerProps {
  device: Device;
  /** The folder analyzed. */
  root: string;
  /** The pane is on screen (polling slows down otherwise). */
  visible: boolean;
  /** Closed (back to the files) but kept: the scan goes on, shown again on the same folder. */
  hidden: boolean;
  /** Height cap of the list (mosaic panes), as ExplorerPane computes it. */
  listMaxHeight?: string;
  inMosaic: boolean;
  canDelete: boolean;
  send: (type: UsageCommand, payload: Record<string, any>, timeoutMs?: number) => Promise<any>;
  failureText: (res: any) => string;
  onClose: () => void;
  onAnalyze: (path: string) => void;
  onReveal: (dir: string, select?: string) => void;
  onChanged: (paths: string[]) => void;
}

const POLL_MS = 1000;        // while the scan runs
const POLL_MAX_MS = 5000;    // a slow answer: the next one later
const POLL_HIDDEN_MS = 4000; // the pane not on screen
const MAX_PATHS = 64;        // folders read in one command
const CHILD_LIMIT = 300;     // subfolders of one folder
const FILES_LIMIT = 500;     // files of one folder
const MAX_ROWS = 5000;       // rows drawn at most
const MAX_ERRORS = 5;        // reads failed in a row: the polling stops
const CMD_MS = 20000;
const DELETE_MS = 120000;
const STOP_CODES = new Set(['restricted', 'forbidden', 'not_found', 'session', 'step_up_required', 'invalid']);
const CMD_PREFIX_RE = /^(start_usage_scan|get_usage_children|get_usage_top_files|cancel_usage_scan|delete_file):\s*/i;

// ─── Data ────────────────────────────────────────────────────────────────────

interface UNode {
  name: string; path: string; size: number; allocated: number; files: number; folders: number;
  modified: string; done: boolean; denied: boolean; errors: number; truncated: boolean; childCount: number;
}
interface UFile { name: string; path: string; size: number; allocated: number; modified: string }
interface UGroup { count: number; size: number; allocated: number; modified: string }
interface UProgress { files: number; folders: number; bytes: number; allocated: number; errors: number; skipped: number; current: string; elapsedMs: number }

type ScanState = '' | 'starting' | 'running' | 'done' | 'cancelled' | 'error' | 'expired';
type SortKey = 'name' | 'size' | 'allocated' | 'files' | 'folders' | 'pct' | 'modified' | 'dir';

interface UState {
  root: string;
  scanId: string;
  state: ScanState;
  error: string;
  fail: string;
  progress: UProgress;
  sum: Map<string, { node: UNode; parent: string }>;
  nodes: Map<string, { node: UNode; kids: string[]; total: number; group: UGroup; stale: boolean }>;
  expanded: Set<string>;
  groups: Set<string>;
  files: Map<string, { list: UFile[]; total: number; err: string }>;
  top: UFile[];
  topWanted: boolean;
  view: 'tree' | 'top';
  sortKey: SortKey;
  sortDir: 1 | -1;
  sel: string;
  timer: ReturnType<typeof setTimeout> | null;
  busy: boolean;
  again: boolean;
  gen: number;
  errs: number;
  rtt: number;
  notified: string;
}

type Row =
  | { kind: 'dir'; key: string; path: string; n: UNode; depth: number; pct: number; top?: false }
  | { kind: 'group'; key: string; path: string; g: UGroup; depth: number; pct: number }
  | { kind: 'file'; key: string; path: string; f: UFile & { dir?: string }; depth: number; pct: number; top: boolean }
  | { kind: 'more'; key: string; depth: number; text?: string }
  | { kind: 'loading'; key: string; depth: number; text?: string };

function progressOf(p: any): UProgress {
  const o = p && typeof p === 'object' ? p : {};
  return {
    files: usageNum(o.files), folders: usageNum(o.folders), bytes: usageNum(o.bytes), allocated: usageNum(o.allocated),
    errors: usageNum(o.errors), skipped: usageNum(o.skipped), current: usageStr(o.current), elapsedMs: usageNum(o.elapsedMs),
  };
}

function nodeOf(o: any): UNode | null {
  if (!o || typeof o !== 'object' || typeof o.path !== 'string' || !o.path) return null;
  return {
    name: usageStr(o.name, 1024) || usageStr(o.path), path: usageStr(o.path), size: usageNum(o.size), allocated: usageNum(o.allocated),
    files: usageNum(o.files), folders: usageNum(o.folders), modified: usageStr(o.modified, 40), done: o.done === true, denied: o.denied === true,
    errors: usageNum(o.errors), truncated: o.truncated === true, childCount: usageNum(o.childCount),
  };
}

function fileOf(o: any): UFile | null {
  if (!o || typeof o !== 'object' || typeof o.path !== 'string' || !o.path) return null;
  return { name: usageStr(o.name, 1024) || usageStr(o.path), path: usageStr(o.path), size: usageNum(o.size), allocated: usageNum(o.allocated), modified: usageStr(o.modified, 40) };
}

function newState(root: string): UState {
  return {
    root, scanId: '', state: '', error: '', fail: '', progress: progressOf(null), sum: new Map(), nodes: new Map(), expanded: new Set(),
    groups: new Set(), files: new Map(), top: [], topWanted: false, view: 'tree', sortKey: 'size', sortDir: -1, sel: '', timer: null,
    busy: false, again: false, gen: 0, errs: 0, rtt: 0, notified: '',
  };
}

/** The folder of a path ('C:\a\b.txt' -> 'C:\a'; 'C:\b.txt' -> 'C:\'; '/a/b' -> '/a'; '/b' -> '/'). */
function dirOf(p: string, os: string): string {
  const sep = os === 'windows' ? '\\' : '/';
  const i = p.lastIndexOf(sep);
  if (i < 0) return '';
  const d = p.slice(0, i);
  if (os === 'windows' && /^[A-Za-z]:$/.test(d)) return d + '\\';
  return d || '/';
}

function fmtDate(iso: string): string {
  if (!iso) return '';
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? '' : d.toLocaleString();
}

/** Siblings in the order asked; ties by name. */
function sortItems<T extends { name: string; size: number; allocated: number; modified: string; files?: number; folders?: number; dir?: string }>(
  items: T[], key: SortKey, dir: 1 | -1, coll: Intl.Collator | null,
): T[] {
  const byText = (a: string, b: string) => (coll ? coll.compare(a, b) : a.toLowerCase() < b.toLowerCase() ? -1 : a.toLowerCase() > b.toLowerCase() ? 1 : 0);
  const val = (r: T): number => {
    if (key === 'modified') return Date.parse(r.modified) || 0;
    if (key === 'pct') return r.size;
    return usageNum((r as any)[key]);
  };
  return items.slice().sort((a, b) => {
    let c = key === 'name' ? byText(a.name, b.name) : key === 'dir' ? byText(a.dir ?? '', b.dir ?? '') : val(a) - val(b);
    if (!c) c = byText(a.name, b.name);
    return c * dir;
  });
}

/** An expanded folder is on screen when all its ancestors are expanded. */
function isShown(u: UState, p: string): boolean {
  if (p === u.root) return true;
  let x = u.sum.get(p);
  for (let i = 0; x && i < 512; i++) {
    if (!x.parent) return false;
    if (x.parent === u.root) return u.expanded.has(u.root);
    if (!u.expanded.has(x.parent)) return false;
    x = u.sum.get(x.parent);
  }
  return false;
}

/** The folders to read now: the root, and the expanded ones on screen not read yet or not complete yet. */
function wantedPaths(u: UState): string[] {
  const out: string[] = [];
  const want = (p: string) => {
    if (out.length >= MAX_PATHS || out.includes(p)) return;
    const rec = u.nodes.get(p);
    if (!rec || !rec.node.done || rec.stale) out.push(p);
  };
  want(u.root);
  u.expanded.forEach((p) => { if (isShown(u, p)) want(p); });
  return out;
}

function setScanState(u: UState, state: unknown, err: unknown, progress: unknown) {
  if (state === 'running' || state === 'done' || state === 'cancelled' || state === 'error') u.state = state;
  u.error = usageStr(err, 400);
  if (progress) u.progress = progressOf(progress);
}

/** One get_usage_children answer: the folders read, their subfolders. */
function applyChildren(u: UState, r: any) {
  if (!r || typeof r !== 'object') return;
  setScanState(u, r.state, r.error, r.progress);
  for (const e of Array.isArray(r.nodes) ? r.nodes : []) {
    if (!e || typeof e !== 'object') continue;
    const n = nodeOf(e.node);
    if (!n) {
      // Gone (deleted, or never a folder of this scan): out of the view.
      const p = usageStr(e.path);
      if (p && p !== u.root) { u.nodes.delete(p); u.expanded.delete(p); }
      continue;
    }
    const prev = u.sum.get(n.path);
    u.sum.set(n.path, { node: n, parent: prev ? prev.parent : '' });
    const kids: string[] = [];
    for (const c of (Array.isArray(e.children) ? e.children : []).slice(0, CHILD_LIMIT)) {
      const k = nodeOf(c);
      if (!k) continue;
      u.sum.set(k.path, { node: k, parent: n.path });
      kids.push(k.path);
    }
    const g = e.filesGroup && typeof e.filesGroup === 'object' ? e.filesGroup : {};
    u.nodes.set(n.path, {
      node: n, kids, total: Math.max(usageNum(e.childrenTotal), kids.length),
      group: { count: usageNum(g.count), size: usageNum(g.size), allocated: usageNum(g.allocated), modified: usageStr(g.modified, 40) },
      stale: false,
    });
    // Files listed while the scan goes on: read again with the folder.
    if (u.files.has(n.path) && !n.done) u.files.delete(n.path);
  }
}

class UsageError extends Error {
  code?: string;
  raw: string;
  constructor(message: string, code?: string, raw = '') {
    super(message);
    this.code = code;
    this.raw = raw;
  }
}

// ─── Component ───────────────────────────────────────────────────────────────

export default function UsageAnalyzer({
  device, root, visible, hidden, listMaxHeight, inMosaic, canDelete,
  send, failureText, onClose, onAnalyze, onReveal, onChanged,
}: UsageAnalyzerProps) {
  const { t, i18n } = useTranslation();
  const lang = i18n.language;
  const confirm = useConfirm();
  const [, bump] = useReducer((x: number) => x + 1, 0);
  const ur = useRef<UState>(newState(root));
  const aliveRef = useRef(true);
  const listRef = useRef<HTMLDivElement>(null);
  const visibleRef = useRef(visible);
  visibleRef.current = visible;
  const hiddenRef = useRef(hidden);
  hiddenRef.current = hidden;
  const os = device.osType;

  // Latest props for the timers.
  const sendRef = useRef(send);
  sendRef.current = send;
  const failureRef = useRef(failureText);
  failureRef.current = failureText;

  // ── Commands ──

  const cmd = useCallback(async (type: UsageCommand, payload: Record<string, any>, timeoutMs = CMD_MS): Promise<any> => {
    const res = await sendRef.current(type, payload, timeoutMs);
    if (res?.status === 'success') return res.result ?? {};
    const r = res?.result;
    const raw = typeof r?.error === 'string' ? r.error : typeof r === 'string' ? r : '';
    throw new UsageError(failureRef.current(res) || raw, typeof r?.code === 'string' ? r.code : undefined, raw);
  }, []);

  // An explorer error, or the analyzer's own cases, in words.
  const errText = useCallback((e: any): string => {
    if (isStepUpHandled(e)) return t('fileExplorer.err.stepUp', 'A two-factor confirmation is required for this file operation.');
    const msg = String((e instanceof UsageError ? e.raw || e.message : e?.message) || '');
    if (/unknown command type/i.test(msg)) return agentTooOldText(t);
    if (e?.code === 'invalid' && /not allowed on the file explorer channel/i.test(msg)) {
      return t('fileExplorer.usage.err.serverTooOld', 'This server does not support the disk usage analyzer yet.');
    }
    if (/usage scan not found/i.test(msg)) return t('fileExplorer.usage.err.expired', 'The scan is no longer available on the device (expired or replaced): rescan.');
    if (e?.code && e?.message) return String(e.message);
    const text = msg.replace(CMD_PREFIX_RE, '').slice(0, 400) || t('common.error', 'Error');
    return t('fileExplorer.usage.err.failed', 'Disk usage: {{error}}', { error: text });
  }, [t]);

  // ── Reading the scan ──

  const tickRef = useRef<() => void>(() => {});

  const schedule = useCallback((ms: number) => {
    const u = ur.current;
    if (!aliveRef.current || hiddenRef.current || !u.scanId) return;
    if (u.timer) { clearTimeout(u.timer); u.timer = null; }
    if (u.busy) { u.again = true; return; }
    u.timer = setTimeout(() => { u.timer = null; tickRef.current(); }, Math.max(0, ms));
  }, []);

  const nextDelay = () => {
    const u = ur.current;
    const d = Math.min(POLL_MAX_MS, Math.max(POLL_MS, u.rtt * 2));
    return visibleRef.current ? d : Math.max(d, POLL_HIDDEN_MS);
  };

  tickRef.current = async () => {
    const u = ur.current;
    if (!aliveRef.current || hiddenRef.current || !u.scanId || u.busy) return;
    const paths = wantedPaths(u);
    const top = u.view === 'top' && (u.state === 'running' || !u.topWanted);
    const groups: string[] = [];
    u.groups.forEach((p) => { if (!u.files.has(p) && u.nodes.has(p) && isShown(u, p)) groups.push(p); });
    if (!paths.length && !top && !groups.length) return;
    u.busy = true;
    const gen = u.gen;
    const t0 = Date.now();
    let failed: any = null;
    try {
      if (paths.length) {
        const r = await cmd('get_usage_children', { scanId: u.scanId, paths, limit: CHILD_LIMIT });
        if (gen !== u.gen || !aliveRef.current) return;
        applyChildren(u, r);
      }
      for (let i = 0; i < groups.length && gen === u.gen; i++) {
        const g = await cmd('get_usage_children', { scanId: u.scanId, path: groups[i], limit: 1, files: true, filesLimit: FILES_LIMIT });
        if (gen !== u.gen || !aliveRef.current) return;
        if (g && typeof g === 'object') setScanState(u, g.state, g.error, g.progress);
        const e = g && Array.isArray(g.nodes) ? g.nodes[0] : null;
        if (!e || !e.node) {
          u.files.set(groups[i], { list: [], total: 0, err: t('fileExplorer.usage.err.expired', 'The scan is no longer available on the device (expired or replaced): rescan.') });
        } else {
          const list = (Array.isArray(e.files) ? e.files : []).map(fileOf).filter(Boolean).slice(0, FILES_LIMIT) as UFile[];
          u.files.set(groups[i], { list, total: Math.max(usageNum(e.filesTotal), list.length), err: usageStr(e.filesError, 300) });
        }
      }
      if (top && gen === u.gen) {
        const tf = await cmd('get_usage_top_files', { scanId: u.scanId });
        if (gen !== u.gen || !aliveRef.current) return;
        u.top = ((tf && Array.isArray(tf.files) ? tf.files : []).map(fileOf).filter(Boolean) as UFile[]).slice(0, 100);
        u.topWanted = true;
        if (tf && typeof tf.state === 'string') setScanState(u, tf.state, tf.error, tf.progress);
      }
      u.errs = 0;
    } catch (e) {
      if (gen !== u.gen || !aliveRef.current) return;
      failed = e;
    } finally {
      if (gen === u.gen) {
        u.busy = false;
        u.rtt = Date.now() - t0;
      }
    }
    if (failed) {
      const text = errText(failed);
      const raw = String((failed instanceof UsageError ? failed.raw : failed?.message) || '');
      if (/usage scan not found/i.test(raw)) { u.state = 'expired'; u.fail = text; bump(); return; }
      u.errs++;
      if (u.notified !== text) { u.notified = text; if (!isStepUpHandled(failed)) toast.error(text); }
      if (u.errs >= MAX_ERRORS || isStepUpHandled(failed) || STOP_CODES.has(failed?.code)) { u.fail = text; bump(); return; }
      bump();
      schedule(Math.min(POLL_MAX_MS, POLL_MS * (1 + u.errs)));
      return;
    }
    u.notified = '';
    bump();
    if (u.again) { u.again = false; schedule(0); return; }
    if (u.state === 'running') schedule(nextDelay());
    else if (wantedPaths(u).length) schedule(0); // (expanded meanwhile)
  };

  // ── Starting, stopping ──

  const start = useCallback(async (path: string, restart: boolean) => {
    const prev = ur.current;
    if (prev.timer) clearTimeout(prev.timer);
    const u = newState(path);
    u.gen = prev.gen + 1;
    u.view = prev.view;
    u.state = 'starting';
    ur.current = u;
    const gen = u.gen;
    bump();
    let r: any;
    try {
      r = await cmd('start_usage_scan', { path, restart });
    } catch (e) {
      if (!aliveRef.current || gen !== ur.current.gen) return;
      u.state = 'error';
      u.fail = errText(e);
      bump();
      return;
    }
    if (!aliveRef.current || gen !== ur.current.gen) return;
    u.scanId = usageStr(r?.scanId, 64);
    if (!u.scanId) { u.state = 'error'; u.fail = t('common.error', 'Error'); bump(); return; }
    if (typeof r?.root === 'string' && r.root) u.root = usageStr(r.root);
    u.state = 'running';
    u.expanded = new Set([u.root]);
    u.sel = u.root;
    if (r?.reused === true) toast.success(t('fileExplorer.usage.joined', 'A scan of this folder was already running: joined.'));
    bump();
    schedule(0);
  }, [cmd, errText, schedule, t]);

  // Mount: start (or join) the scan. Unmount (another folder analyzed, the
  // sub-tab closed): a scan still running is stopped on the device.
  useEffect(() => {
    aliveRef.current = true;
    start(root, false);
    return () => {
      aliveRef.current = false;
      const u = ur.current;
      u.gen++;
      if (u.timer) { clearTimeout(u.timer); u.timer = null; }
      if (u.scanId && (u.state === 'running' || u.state === 'starting')) {
        // Fire and forget, straight on the socket: no 2FA prompt while closing.
        getSocket()?.emit('FILE_EXPLORER_CMD', {
          requestId: crypto.randomUUID(), deviceId: device.id, commandType: 'cancel_usage_scan', payload: { scanId: u.scanId },
        });
      }
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Back to the files: reading stops; shown again: it goes on.
  useEffect(() => {
    const u = ur.current;
    if (hidden) {
      if (u.timer) { clearTimeout(u.timer); u.timer = null; }
      return;
    }
    if (u.scanId) schedule(0);
    listRef.current?.focus({ preventScroll: true });
  }, [hidden, schedule]);

  // The pane back on screen: the next read now (it was slowed down).
  useEffect(() => {
    if (visible && ur.current.state === 'running') schedule(0);
  }, [visible, schedule]);

  const stop = async () => {
    const u = ur.current;
    if (!u.scanId || u.state !== 'running') return;
    const gen = u.gen;
    try {
      await cmd('cancel_usage_scan', { scanId: u.scanId });
    } catch (e) {
      if (aliveRef.current && !isStepUpHandled(e)) toast.error(errText(e));
      return;
    }
    if (gen !== u.gen || !aliveRef.current) return;
    u.state = 'cancelled';
    // (one last read: the sizes as they stand)
    u.nodes.forEach((rec) => { rec.stale = true; });
    bump();
    schedule(0);
  };

  const rescan = () => {
    const u = ur.current;
    if (u.root) start(u.root, true);
  };

  // ── View actions ──

  const setView = (v: 'tree' | 'top') => {
    const u = ur.current;
    if (u.view === v) return;
    u.view = v;
    u.sel = '';
    if (v === 'top') { u.sortKey = 'size'; u.sortDir = -1; }
    bump();
    if (v === 'top' && (!u.topWanted || u.state === 'running')) schedule(0);
  };

  const sortBy = (key: SortKey) => {
    const u = ur.current;
    if (u.sortKey === key) u.sortDir = u.sortDir === 1 ? -1 : 1;
    else { u.sortKey = key; u.sortDir = key === 'name' || key === 'dir' ? 1 : -1; }
    bump();
  };

  const toggle = (path: string) => {
    const u = ur.current;
    if (u.expanded.has(path)) u.expanded.delete(path);
    else {
      u.expanded.add(path);
      const rec = u.nodes.get(path);
      if (!rec || !rec.node.done) schedule(0);
    }
    bump();
  };

  const toggleGroup = (dir: string) => {
    const u = ur.current;
    if (u.groups.has(dir)) u.groups.delete(dir);
    else { u.groups.add(dir); if (!u.files.has(dir)) schedule(0); }
    bump();
  };

  const select = (key: string) => {
    ur.current.sel = key;
    bump();
  };

  const reveal = (r: Row) => {
    if (r.kind === 'dir') onReveal(r.n.path);
    else if (r.kind === 'group') onReveal(r.path);
    else if (r.kind === 'file') onReveal(dirOf(r.path, os), r.path);
  };

  // Delete: confirmation, then delete_file (a folder with its contents); the
  // folders concerned are read again (the agent took it out of its scans).
  const remove = async (r: Row) => {
    if (r.kind !== 'dir' && r.kind !== 'file') return;
    const u = ur.current;
    const it = r.kind === 'dir'
      ? { name: r.n.name, path: r.n.path, isDir: true, size: r.n.size }
      : { name: r.f.name, path: r.f.path, isDir: false, size: r.f.size };
    if (!canDelete || (it.isDir && it.path === u.root)) return;
    const ok = await confirm({
      title: t('fileExplorer.delete', 'Delete'),
      message: it.isDir
        ? t('fileExplorer.usage.deleteFolderConfirm', 'Delete the folder "{{name}}" and everything it contains ({{size}})? This cannot be undone.', { name: it.name, size: fmtBytes(it.size, lang) })
        : t('fileExplorer.deleteConfirm', 'Delete "{{name}}"?', { name: it.name }),
      danger: true,
    });
    if (!ok || !aliveRef.current) return;
    try {
      await cmd('delete_file', { path: it.path, isDir: it.isDir, recursive: it.isDir }, DELETE_MS);
    } catch (e: any) {
      if (aliveRef.current && !isStepUpHandled(e)) toast.error((e instanceof UsageError ? e.message : '') || t('fileExplorer.deleteFailed', 'Delete failed'));
      return;
    }
    if (!aliveRef.current) return;
    toast.success(t('fileExplorer.deleted', 'Deleted'));
    const cur = ur.current;
    const dir = it.isDir ? (cur.sum.get(it.path)?.parent || dirOf(it.path, os)) : dirOf(it.path, os);
    // Its folder and every folder above: read again; the item: out of the view.
    let p = dir;
    for (let i = 0; p && i < 512; i++) {
      const rec = cur.nodes.get(p);
      if (rec) rec.stale = true;
      p = cur.sum.get(p)?.parent ?? '';
    }
    const rootRec = cur.nodes.get(cur.root);
    if (rootRec) rootRec.stale = true;
    if (it.isDir) {
      cur.nodes.delete(it.path);
      cur.expanded.delete(it.path);
      cur.sum.delete(it.path);
      const rp = cur.nodes.get(dir);
      if (rp) rp.kids = rp.kids.filter((k) => k !== it.path);
    } else {
      cur.files.delete(dir);
    }
    const sep = os === 'windows' ? '\\' : '/';
    cur.top = cur.top.filter((f) => f.path !== it.path && !(it.isDir && f.path.startsWith(it.path + sep)));
    if (cur.view === 'top') cur.topWanted = false;
    if (cur.sel === it.path || cur.sel === r.key) cur.sel = '';
    onChanged([dir]);
    bump();
    schedule(0);
  };

  // ── Rows ──

  const u = ur.current;
  let coll: Intl.Collator | null = null;
  try { coll = new Intl.Collator(lang, { numeric: true, sensitivity: 'base' }); } catch { coll = null; }

  const treeRows = (): Row[] => {
    const rows: Row[] = [];
    const topSum = u.sum.get(u.root);
    if (!topSum) return rows;
    const push = (n: UNode, depth: number, parentSize: number) => {
      if (rows.length >= MAX_ROWS) return;
      rows.push({ kind: 'dir', key: n.path, path: n.path, n, depth, pct: parentSize > 0 ? n.size / parentSize : (depth ? 0 : 1) });
      if (!u.expanded.has(n.path)) return;
      const rec = u.nodes.get(n.path);
      if (!rec) { rows.push({ kind: 'loading', key: `l:${n.path}`, depth: depth + 1 }); return; }
      type Item = { kind: 'dir' | 'group'; name: string; size: number; allocated: number; files: number; folders: number; modified: string; n?: UNode };
      const items: Item[] = rec.kids
        .map((p) => u.sum.get(p)?.node)
        .filter((k): k is UNode => !!k)
        .map((k) => ({ kind: 'dir' as const, n: k, name: k.name, size: k.size, allocated: k.allocated, files: k.files, folders: k.folders, modified: k.modified }));
      if (rec.group.count > 0) {
        items.push({ kind: 'group', name: '', size: rec.group.size, allocated: rec.group.allocated, files: rec.group.count, folders: 0, modified: rec.group.modified });
      }
      for (const it of sortItems(items, u.sortKey, u.sortDir, coll)) {
        if (rows.length >= MAX_ROWS) return;
        if (it.kind === 'dir' && it.n) { push(it.n, depth + 1, n.size); continue; }
        rows.push({ kind: 'group', key: `g:${n.path}`, path: n.path, g: rec.group, depth: depth + 1, pct: n.size > 0 ? rec.group.size / n.size : 0 });
        if (!u.groups.has(n.path)) continue;
        const fl = u.files.get(n.path);
        if (!fl) { rows.push({ kind: 'loading', key: `lf:${n.path}`, depth: depth + 2 }); continue; }
        if (fl.err && !fl.list.length) {
          rows.push({ kind: 'more', key: `fe:${n.path}`, depth: depth + 2, text: t('fileExplorer.usage.err.failed', 'Disk usage: {{error}}', { error: fl.err }) });
          continue;
        }
        for (const f of sortItems(fl.list.map((x) => ({ ...x, files: 1, folders: 0 })), u.sortKey, u.sortDir, coll)) {
          if (rows.length < MAX_ROWS) rows.push({ kind: 'file', key: f.path, path: f.path, f, depth: depth + 2, pct: n.size > 0 ? f.size / n.size : 0, top: false });
        }
        if (fl.total > fl.list.length) {
          rows.push({ kind: 'more', key: `fm:${n.path}`, depth: depth + 2, text: t('fileExplorer.usage.moreFiles', '{{n}} smaller files not shown', { n: fmtInt(fl.total - fl.list.length, lang) }) });
        }
      }
      if (rec.total > rec.kids.length) {
        rows.push({ kind: 'more', key: `dm:${n.path}`, depth: depth + 1, text: t('fileExplorer.usage.moreFolders', '{{n}} smaller folders not shown', { n: fmtInt(rec.total - rec.kids.length, lang) }) });
      }
    };
    push(topSum.node, 0, 0);
    return rows;
  };

  const topRows = (): Row[] => sortItems(u.top.map((f) => ({ ...f, dir: dirOf(f.path, os) })), u.sortKey, u.sortDir, coll)
    .map((f) => ({ kind: 'file' as const, key: f.path, path: f.path, f, depth: 0, pct: 0, top: true }));

  const rows = u.view === 'top' ? topRows() : treeRows();
  const selectable = rows.filter((r) => r.kind === 'dir' || r.kind === 'group' || r.kind === 'file');
  const selRow = selectable.find((r) => r.key === u.sel) ?? null;

  // ── Keyboard: arrows move, Right / Left open and close, Enter opens,
  // Delete deletes, Escape goes back to the files. Never reaches the pane.
  const onKeyDown = (e: React.KeyboardEvent<HTMLDivElement>) => {
    e.stopPropagation();
    const el = e.target as HTMLElement;
    if (el.isContentEditable || ['INPUT', 'TEXTAREA', 'SELECT'].includes(el.tagName)) return;
    const k = e.key;
    const handled = () => e.preventDefault();
    if (k === 'Escape') { handled(); onClose(); return; }
    const i = selRow ? selectable.indexOf(selRow) : -1;
    if ((k === 'ArrowDown' || k === 'ArrowUp' || k === 'Home' || k === 'End') && selectable.length) {
      handled();
      const j = k === 'Home' ? 0 : k === 'End' ? selectable.length - 1 : k === 'ArrowDown' ? Math.min(selectable.length - 1, i + 1) : Math.max(0, i - 1);
      const key = selectable[j].key;
      select(key);
      requestAnimationFrame(() => {
        listRef.current?.querySelector<HTMLElement>(`tr[data-row="${CSS.escape(key)}"]`)?.scrollIntoView({ block: 'nearest' });
      });
      return;
    }
    if (!selRow || el.tagName === 'BUTTON') return;
    if (k === 'ArrowRight' || k === 'ArrowLeft') {
      handled();
      const open = k === 'ArrowRight';
      if (selRow.kind === 'dir' && u.view === 'tree' && u.expanded.has(selRow.path) !== open) toggle(selRow.path);
      else if (selRow.kind === 'group' && u.groups.has(selRow.path) !== open) toggleGroup(selRow.path);
      return;
    }
    if (k === 'Enter') {
      handled();
      if (selRow.kind === 'dir' && u.view === 'tree') toggle(selRow.path);
      else if (selRow.kind === 'group') toggleGroup(selRow.path);
      else reveal(selRow);
      return;
    }
    if (k === 'Delete' && (selRow.kind === 'dir' || selRow.kind === 'file')) { handled(); remove(selRow); }
  };

  // ── Render ──

  const running = u.state === 'running' || u.state === 'starting';
  const p = u.progress;
  const stateText = (() => {
    if (u.fail && u.state !== 'expired' && u.state !== 'error') return u.fail;
    switch (u.state) {
      case 'starting': return t('fileExplorer.usage.state.starting', 'Starting…');
      case 'running': return t('fileExplorer.usage.state.running', 'Scanning…');
      case 'done': return t('fileExplorer.usage.state.done', 'Scan complete');
      case 'cancelled': return t('fileExplorer.usage.state.cancelled', 'Scan stopped');
      case 'expired': return t('fileExplorer.usage.err.expired', 'The scan is no longer available on the device (expired or replaced): rescan.');
      case 'error': return t('fileExplorer.usage.state.error', 'Scan failed: {{error}}', { error: u.fail || u.error || t('common.error', 'Error') });
      default: return '';
    }
  })();
  const stateClass = u.fail && u.state !== 'expired'
    ? 'text-red-400'
    : u.state === 'running' ? 'text-accent' : u.state === 'done' ? 'text-green-400' : u.state === 'cancelled' || u.state === 'expired' ? 'text-amber-400' : 'text-text-primary';

  const note = u.state === 'starting' || (u.scanId && !rows.length && u.view === 'tree')
    ? t('fileExplorer.usage.loading', 'Loading…')
    : u.view === 'top' && !rows.length && u.scanId
      ? (u.topWanted ? t('fileExplorer.usage.noTop', 'No files found.') : t('fileExplorer.usage.loading', 'Loading…'))
      : '';

  const isRootDir = (r: Row | null) => !!r && r.kind === 'dir' && r.path === u.root;

  const sortHead = (key: SortKey, label: string, className: string, align: 'left' | 'right' = 'right') => {
    const on = u.sortKey === key;
    return (
      <th
        className={clsx('px-3 py-2 font-medium', align === 'right' ? 'text-right' : 'text-left', className)}
        aria-sort={on ? (u.sortDir === 1 ? 'ascending' : 'descending') : 'none'}
      >
        <button
          type="button"
          onClick={() => sortBy(key)}
          className={clsx('uppercase tracking-wider hover:text-text-primary transition-colors', on && 'text-text-primary')}
        >
          {label}{on ? (u.sortDir === 1 ? ' \u2191' : ' \u2193') : ''}
        </button>
      </th>
    );
  };

  const colName = t('fileExplorer.usage.col.name', 'Name');
  const colSize = t('fileExplorer.usage.col.size', 'Size');
  const colAlloc = t('fileExplorer.usage.col.allocated', 'On disk');
  const colFiles = t('fileExplorer.usage.col.files', 'Files');
  const colFolders = t('fileExplorer.usage.col.folders', 'Folders');
  const colPct = t('fileExplorer.usage.col.percent', '% of parent');
  const colMod = t('fileExplorer.usage.col.modified', 'Modified');
  const colDir = t('fileExplorer.usage.col.folder', 'Folder');
  const ncols = u.view === 'top' ? 5 : 7;

  const caret = (open: boolean, leaf: boolean, onClick: () => void) => (
    <button
      type="button"
      tabIndex={-1}
      disabled={leaf}
      onClick={(e) => { e.stopPropagation(); onClick(); }}
      onDoubleClick={(e) => e.stopPropagation()}
      aria-label={open ? t('fileExplorer.usage.collapse', 'Collapse') : t('fileExplorer.usage.expand', 'Expand')}
      aria-expanded={leaf ? undefined : open}
      className={clsx('shrink-0 w-5 h-5 rounded flex items-center justify-center text-text-muted hover:text-text-primary hover:bg-bg-tertiary disabled:opacity-0', TB)}
    >
      <ChevronRight className={clsx('w-3.5 h-3.5 transition-transform', open && 'rotate-90')} />
    </button>
  );

  const renderRow = (r: Row) => {
    const indent = { paddingLeft: `${8 + Math.min(r.depth, 24) * 14}px` };
    if (r.kind === 'more' || r.kind === 'loading') {
      return (
        <tr key={`${r.kind}:${r.key}`} className="text-text-muted italic text-xs">
          <td colSpan={ncols} className="px-3 py-1.5" style={indent}>
            {r.kind === 'loading'
              ? <span className="inline-flex items-center gap-1.5"><Loader2 className="w-3 h-3 animate-spin" />{t('fileExplorer.usage.loading', 'Loading…')}</span>
              : r.text}
          </td>
        </tr>
      );
    }
    const it = r.kind === 'dir'
      ? r.n
      : r.kind === 'group'
        ? { size: r.g.size, allocated: r.g.allocated, files: r.g.count, folders: 0, modified: r.g.modified }
        : { ...r.f, files: 0, folders: 0 };
    const selected = u.sel === r.key;
    const name = r.kind === 'dir'
      ? (r.depth === 0 ? r.n.path : r.n.name)
      : r.kind === 'group'
        ? t('fileExplorer.usage.filesGroup', 'Files in this folder ({{n}})', { n: fmtInt(r.g.count, lang) })
        : r.f.name;
    const Icon = r.kind === 'dir' ? (r.depth === 0 ? HardDrive : FolderOpen) : r.kind === 'group' ? Files : File;
    const topRow = r.kind === 'file' && r.top;
    const fileDir = r.kind === 'file' ? (r.f.dir ?? '') : '';
    return (
      <tr
        key={`${r.kind}:${r.key}`}
        data-row={r.key}
        onClick={() => select(r.key)}
        onDoubleClick={() => {
          if (r.kind === 'dir' && u.view === 'tree') toggle(r.path);
          else if (r.kind === 'group') toggleGroup(r.path);
          else reveal(r);
        }}
        onContextMenu={() => select(r.key)}
        aria-selected={selected}
        className={clsx(
          'cursor-pointer transition-colors coarse:select-none',
          selected ? 'bg-accent/10' : 'hover:bg-bg-tertiary/50',
          r.kind === 'group' && 'text-text-muted',
        )}
      >
        <td className="px-3 py-1 coarse:py-1.5 max-sm:px-1" style={indent}>
          <div className="flex items-center gap-1.5 min-w-0">
            {!topRow && (
              r.kind === 'dir'
                ? caret(u.expanded.has(r.path), r.n.childCount === 0 && r.n.files === 0 && r.n.done && !(u.nodes.get(r.path)?.group.count), () => toggle(r.path))
                : r.kind === 'group'
                  ? caret(u.groups.has(r.path), !(r.g.count > 0), () => toggleGroup(r.path))
                  : <span className="shrink-0 w-5 coarse:w-10" />
            )}
            <Icon className={clsx('w-4 h-4 shrink-0', r.kind === 'dir' ? 'text-yellow-500' : 'text-text-muted')} />
            <div className="min-w-0 flex-1">
              <div className="flex items-center gap-1.5 min-w-0">
                <span className={clsx('truncate', r.kind === 'dir' ? 'text-text-primary font-medium' : r.kind === 'file' ? 'text-text-primary' : '')} title={r.path}>
                  {name}
                </span>
                {r.kind === 'dir' && r.n.denied && (
                  <span className="shrink-0 px-1.5 rounded text-[10px] bg-red-400/10 text-red-400">{t('fileExplorer.usage.denied', 'access denied')}</span>
                )}
                {r.kind === 'dir' && r.n.truncated && (
                  <span className="shrink-0 px-1.5 rounded text-[10px] bg-bg-tertiary text-text-muted" title={t('fileExplorer.usage.truncated', 'Deeper folders are counted here without detail (too many folders).')}>+</span>
                )}
                {r.kind === 'dir' && !r.n.done && u.state === 'running' && (
                  <span title={t('fileExplorer.usage.partial', 'Still being scanned')}><Loader2 className="w-3 h-3 shrink-0 animate-spin text-text-muted" /></span>
                )}
              </div>
              {topRow && fileDir && (
                <div className="lg:hidden text-[11px] text-text-muted truncate" title={fileDir}>{fileDir}</div>
              )}
            </div>
          </div>
        </td>
        <td className="px-3 py-1 text-right text-xs tabular-nums text-text-primary whitespace-nowrap max-sm:px-1">{fmtBytes(it.size, lang)}</td>
        <td className="px-3 py-1 text-right text-xs tabular-nums text-text-muted whitespace-nowrap hidden md:table-cell">{fmtBytes(it.allocated, lang)}</td>
        {u.view === 'top' ? (
          <>
            <td className={clsx('px-3 py-1 text-xs text-text-muted whitespace-nowrap hidden', !inMosaic && 'xl:table-cell')}>{fmtDate(it.modified)}</td>
            <td className="px-3 py-1 text-xs text-text-muted hidden lg:table-cell max-w-0 w-1/3">
              <div className="truncate" title={fileDir}>{fileDir}</div>
            </td>
          </>
        ) : (
          <>
            <td className="px-3 py-1 text-right text-xs tabular-nums text-text-muted hidden lg:table-cell">{r.kind === 'file' ? '' : fmtInt(it.files, lang)}</td>
            <td className="px-3 py-1 text-right text-xs tabular-nums text-text-muted hidden lg:table-cell">{r.kind === 'dir' ? fmtInt(it.folders, lang) : ''}</td>
            <td className="px-3 py-1 max-sm:px-1">
              <div className="flex items-center justify-end gap-2">
                <UsageBar value={r.pct} className="w-16 hidden sm:block" />
                <span className="text-xs tabular-nums text-text-muted w-12 text-right">{fmtPct(r.pct, lang)}</span>
              </div>
            </td>
            <td className={clsx('px-3 py-1 text-xs text-text-muted whitespace-nowrap hidden', !inMosaic && 'xl:table-cell')}>{fmtDate(it.modified)}</td>
          </>
        )}
      </tr>
    );
  };

  const btn = 'inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-medium transition-colors disabled:opacity-30 disabled:cursor-not-allowed coarse:min-h-10';
  const tabBtn = (v: 'tree' | 'top', label: string) => (
    <button
      type="button"
      role="tab"
      aria-selected={u.view === v}
      onClick={() => setView(v)}
      className={clsx(
        'px-3 py-2 text-xs font-semibold border-b-2 transition-colors coarse:min-h-10',
        u.view === v ? 'text-accent border-accent' : 'text-text-muted border-transparent hover:text-text-primary',
      )}
    >
      {label}
    </button>
  );

  return (
    <div className={clsx('flex flex-col min-w-0 flex-1', hidden && 'hidden')} onKeyDown={onKeyDown}>
      {/* ── Bar: back, title + folder, stop / rescan ── */}
      <div className="px-4 py-3 flex items-center gap-2 flex-wrap max-sm:px-3">
        <button
          type="button"
          onClick={onClose}
          className={clsx(btn, 'text-text-muted hover:text-text-primary hover:bg-bg-tertiary')}
          title={t('fileExplorer.usage.back', 'Back to the files')}
          aria-label={t('fileExplorer.usage.back', 'Back to the files')}
        >
          <ArrowLeft className="w-4 h-4" />
          <span className="max-sm:sr-only">{t('fileExplorer.usage.backShort', 'Files')}</span>
        </button>
        <div className="flex items-center gap-2 min-w-0 flex-1 px-2.5 py-1.5 rounded-lg bg-bg-tertiary/60 text-xs max-sm:order-last max-sm:basis-full" title={u.root}>
          <PieChart className="w-3.5 h-3.5 text-accent shrink-0" />
          <span className="shrink-0 font-semibold text-text-muted">{t('fileExplorer.usage.title', 'Disk usage')}</span>
          <span className="truncate text-text-primary">{u.root}</span>
        </div>
        <div className="flex items-center gap-1 shrink-0 max-sm:ml-auto">
          {running ? (
            <button
              type="button"
              onClick={stop}
              disabled={u.state !== 'running'}
              className={clsx(btn, 'text-text-primary hover:bg-bg-tertiary')}
              title={t('fileExplorer.usage.stop', 'Stop')}
            >
              <Square className="w-3.5 h-3.5 fill-current" />
              {t('fileExplorer.usage.stop', 'Stop')}
            </button>
          ) : (
            <button
              type="button"
              onClick={rescan}
              className={clsx(btn, 'text-text-primary hover:bg-bg-tertiary')}
              title={t('fileExplorer.usage.rescan', 'Rescan')}
            >
              <RefreshCw className="w-3.5 h-3.5" />
              {t('fileExplorer.usage.rescan', 'Rescan')}
            </button>
          )}
        </div>
      </div>

      {/* ── Progress ── */}
      <div className="px-4 pb-2 flex items-center gap-3 flex-wrap min-w-0 text-xs text-text-muted max-sm:px-3" aria-live="polite">
        <span className={clsx('shrink-0 font-semibold', stateClass)}>{stateText}</span>
        {u.scanId && (
          <span className="tabular-nums">
            {t('fileExplorer.usage.progress', '{{files}} files · {{folders}} folders · {{size}} · {{time}}', {
              files: fmtInt(p.files, lang), folders: fmtInt(p.folders, lang), size: fmtBytes(p.bytes, lang), time: fmtElapsed(p.elapsedMs),
            })}
          </span>
        )}
        {p.errors > 0 && (
          <span className="shrink-0 px-1.5 rounded bg-amber-400/10 text-amber-400" title={t('fileExplorer.usage.errorsHint', 'Entries that could not be read (access denied, in use…) are not counted.')}>
            {t('fileExplorer.usage.errors', '{{n}} unreadable', { n: fmtInt(p.errors, lang) })}
          </span>
        )}
        {u.state === 'running' && p.current && (
          <span className="flex-1 min-w-0 truncate opacity-70 max-sm:basis-full" title={p.current}>{p.current}</span>
        )}
      </div>
      <div className={clsx('h-0.5 shrink-0', running ? 'bg-accent/70 animate-pulse' : 'bg-transparent')} />

      {/* ── Views + actions on the selected row ── */}
      <div className="px-2 flex items-center gap-1 flex-wrap border-b border-border/50">
        <div className="flex items-center" role="tablist">
          {tabBtn('tree', t('fileExplorer.usage.tabTree', 'Folders'))}
          {tabBtn('top', t('fileExplorer.usage.tabTop', 'Largest files'))}
        </div>
        {selRow && (
          <div className="ml-auto flex items-center gap-1 py-1 min-w-0 max-sm:basis-full max-sm:justify-end">
            <button
              type="button"
              onClick={() => reveal(selRow)}
              className={clsx(btn, 'text-text-muted hover:text-text-primary hover:bg-bg-tertiary')}
              title={t('fileExplorer.usage.openInExplorer', 'Open in the explorer')}
            >
              <FolderOpen className="w-3.5 h-3.5 text-yellow-500" />
              <span className="max-md:sr-only">{t('fileExplorer.usage.openInExplorer', 'Open in the explorer')}</span>
            </button>
            {selRow.kind === 'dir' && !isRootDir(selRow) && (
              <button
                type="button"
                onClick={() => onAnalyze(selRow.path)}
                className={clsx(btn, 'text-text-muted hover:text-text-primary hover:bg-bg-tertiary')}
                title={t('fileExplorer.usage.analyzeFolder', 'Analyze this folder')}
              >
                <PieChart className="w-3.5 h-3.5 text-accent" />
                <span className="max-md:sr-only">{t('fileExplorer.usage.analyzeFolder', 'Analyze this folder')}</span>
              </button>
            )}
            {(selRow.kind === 'file' || (selRow.kind === 'dir' && !isRootDir(selRow))) && (
              <button
                type="button"
                onClick={() => remove(selRow)}
                disabled={!canDelete}
                className={clsx(btn, 'text-red-400 hover:bg-red-400/10')}
                title={t('fileExplorer.delete', 'Delete')}
              >
                <Trash2 className="w-3.5 h-3.5" />
                <span className="max-md:sr-only">{t('fileExplorer.delete', 'Delete')}</span>
              </button>
            )}
          </div>
        )}
      </div>

      {/* ── List ── */}
      <div
        ref={listRef}
        tabIndex={0}
        role="treegrid"
        aria-label={t('fileExplorer.usage.title', 'Disk usage')}
        style={listMaxHeight ? { maxHeight: `calc(${listMaxHeight} - 70px)` } : undefined}
        className={clsx(
          'overflow-auto outline-none min-h-[240px] flex-1',
          !inMosaic && 'max-h-[calc(100dvh-400px)] supports-[not(height:100dvh)]:max-h-[calc(100vh-400px)] max-md:max-h-none coarse:[@media(max-height:600px)]:max-h-none',
        )}
      >
        {rows.length > 0 && (
          <table className="w-full text-sm table-fixed">
            <thead className="sticky top-0 z-[5]">
              <tr className="bg-bg-tertiary/80 backdrop-blur text-text-muted text-xs">
                {sortHead('name', colName, 'w-auto max-sm:px-1', 'left')}
                {sortHead('size', colSize, 'w-24 max-sm:w-20 max-sm:px-1')}
                {sortHead('allocated', colAlloc, 'w-24 hidden md:table-cell')}
                {u.view === 'top' ? (
                  <>
                    {sortHead('modified', colMod, clsx('w-44 hidden', !inMosaic && 'xl:table-cell'), 'left')}
                    {sortHead('dir', colDir, 'w-1/3 hidden lg:table-cell', 'left')}
                  </>
                ) : (
                  <>
                    {sortHead('files', colFiles, 'w-24 hidden lg:table-cell')}
                    {sortHead('folders', colFolders, 'w-24 hidden lg:table-cell')}
                    {sortHead('pct', colPct, 'w-16 sm:w-36 max-sm:px-1')}
                    {sortHead('modified', colMod, clsx('w-44 hidden', !inMosaic && 'xl:table-cell'), 'left')}
                  </>
                )}
              </tr>
            </thead>
            <tbody>{rows.map(renderRow)}</tbody>
          </table>
        )}
        {note && (
          <div className="flex items-center justify-center gap-2 py-12 text-sm text-text-muted">
            {(u.state === 'starting' || note === t('fileExplorer.usage.loading', 'Loading…')) && <Loader2 className="w-4 h-4 animate-spin" />}
            {note}
          </div>
        )}
        {!rows.length && !note && u.fail && (
          <div className="py-12 px-4 text-center text-sm text-red-400">{u.fail}</div>
        )}
      </div>

      {/* ── Status bar ── */}
      <div className="px-4 py-1.5 bg-bg-tertiary/50 flex items-center justify-between gap-3 text-xs text-text-muted">
        <span className="shrink-0">
          {u.view === 'top'
            ? t('fileExplorer.usage.topCount', '{{n}} largest files', { n: fmtInt(u.top.length, lang) })
            : (u.sum.get(u.root) ? fmtBytes(u.sum.get(u.root)!.node.size, lang) : '')}
        </span>
        <span className="opacity-60 min-w-0 truncate">{selRow && selRow.kind !== 'group' ? selRow.path : u.root}</span>
      </div>
    </div>
  );
}
