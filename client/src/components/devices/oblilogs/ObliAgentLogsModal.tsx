import { useCallback, useDeferredValue, useEffect, useLayoutEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import toast from 'react-hot-toast';
import { clsx } from 'clsx';
import {
  ScrollText, FileText, FileJson, RefreshCw, Download, Copy, Search, WrapText, ListOrdered,
  Loader2, AlertTriangle, ChevronUp, ChevronDown, ShieldCheck, FolderX,
} from 'lucide-react';
import type { Device } from '@obliance/shared';
import { Modal } from '@/components/common/Modal';
import { isStepUpHandled } from '@/api/client';
import { saveBlob } from '@/utils/download';
import { copyText } from '@/utils/clipboard';
import { useMediaQuery, MEDIA } from '@/hooks/useMediaQuery';
import { useExplorerChannel, base64ToBytes, type ExplorerFileEntry } from './useExplorerChannel';
import { formatAndMaskJson, maskSecretsInText } from './maskSecrets';
import { agentFilesFor, agentNotesFor, joinAgentPath, type ObliAgentDef, type AgentFileKind } from './agentFileCatalog';

// ─── Size policy ─────────────────────────────────────────────────────────────
// The agent's download_file returns the WHOLE file (base64, no byte range), so
// the viewer reads files up to VIEW_MAX_BYTES and shows only their last
// TAIL_BYTES; a bigger file is offered as a download only (the explorer's
// download path, agent cap 150 MB).
const TAIL_BYTES = 512 * 1024;
const VIEW_MAX_BYTES = 4 * 1024 * 1024;
const DOWNLOAD_TIMEOUT_MS = 90_000;

interface Props {
  device: Device;
  agent: ObliAgentDef;
  onClose: () => void;
}

type DirState = { status: 'loading' } | { status: 'ok'; entries: ExplorerFileEntry[] } | { status: 'missing' } | { status: 'error'; error: string };

interface ViewFile {
  key: string;              // full path
  name: string;
  path: string;
  dir: string;
  kind: AgentFileKind;
  desc: string;
  present: boolean | null;  // null = unknown (listing failed)
  size?: number;
  modified?: string;
}

type ContentState =
  | { status: 'idle' }
  | { status: 'loading' }
  | { status: 'error'; error: string }
  | { status: 'tooLarge'; size: number }
  | { status: 'binary' }
  | { status: 'ok'; text: string; truncated: boolean; totalBytes: number; pretty: boolean };

function formatSize(bytes?: number): string {
  if (bytes === undefined || bytes < 0) return '-';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1073741824) return `${(bytes / 1048576).toFixed(1)} MB`;
  return `${(bytes / 1073741824).toFixed(2)} GB`;
}

function formatDate(iso?: string): string {
  if (!iso) return '-';
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString();
}

const NOT_FOUND_RE = /cannot find|no such file|does not exist|not exist|ENOENT/i;

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

export function ObliAgentLogsModal({ device, agent, onClose }: Props) {
  const { t } = useTranslation();
  const { send, failureText } = useExplorerChannel(device.id);
  const isMd = useMediaQuery(MEDIA.md);
  const spec = useMemo(() => agentFilesFor(agent, device.osType), [agent, device.osType]);
  const notes = useMemo(() => agentNotesFor(agent, device.osType), [agent, device.osType]);
  const sep = device.osType === 'windows' ? '\\' : '/';

  const [dirs, setDirs] = useState<Record<string, DirState>>({});
  const [selectedKey, setSelectedKey] = useState<string | null>(null);
  const [content, setContent] = useState<ContentState>({ status: 'idle' });
  const [wrap, setWrap] = useState(false);
  const [lineNumbers, setLineNumbers] = useState(true);
  const [query, setQuery] = useState('');
  const deferredQuery = useDeferredValue(query.trim());
  const [matchIndex, setMatchIndex] = useState(0);
  const [downloading, setDownloading] = useState(false);
  const rawRef = useRef<{ key: string; bytes: Uint8Array } | null>(null);
  const contentRef = useRef<HTMLDivElement>(null);
  const loadSeq = useRef(0);

  // ── Directory listings ───────────────────────────────────────────────────
  const listDirs = useCallback(async () => {
    const init: Record<string, DirState> = {};
    for (const d of spec) init[d.dir] = { status: 'loading' };
    setDirs(init);
    await Promise.all(spec.map(async (d) => {
      let state: DirState;
      try {
        const res = await send('list_directory', { path: d.dir });
        if (res.status === 'success') {
          const files: ExplorerFileEntry[] = res.result?.files ?? [];
          state = { status: 'ok', entries: files.filter((f) => !f.isDir) };
        } else {
          const text = failureText(res);
          state = NOT_FOUND_RE.test(text) ? { status: 'missing' } : { status: 'error', error: text || t('oblilogs.err.list', 'Could not list the folder.') };
        }
      } catch (err: any) {
        state = isStepUpHandled(err) ? { status: 'error', error: t('oblilogs.err.cancelled', 'Confirmation cancelled.') } : { status: 'error', error: err?.message || t('oblilogs.err.list', 'Could not list the folder.') };
      }
      setDirs((prev) => ({ ...prev, [d.dir]: state }));
    }));
  }, [spec, send, failureText, t]);

  useEffect(() => { void listDirs(); }, [listDirs]);

  // ── Files shown on the left (known files + present rotated siblings) ─────
  const files = useMemo<ViewFile[]>(() => {
    const out: ViewFile[] = [];
    for (const d of spec) {
      const st = dirs[d.dir];
      const entries = st?.status === 'ok' ? st.entries : [];
      const byName = new Map(entries.map((e) => [e.name.toLowerCase(), e]));
      const known = new Set<string>();
      for (const f of d.files) {
        const e = byName.get(f.name.toLowerCase());
        known.add(f.name.toLowerCase());
        out.push({
          key: joinAgentPath(d.dir, f.name, sep), name: f.name, path: e?.path || joinAgentPath(d.dir, f.name, sep), dir: d.dir,
          kind: f.kind, desc: t(f.descKey, f.desc),
          present: st?.status === 'ok' ? !!e : st?.status === 'missing' ? false : null,
          size: e?.size, modified: e?.modified,
        });
      }
      for (const p of d.patterns ?? []) {
        const matches = entries
          .filter((e) => !known.has(e.name.toLowerCase()) && p.re.test(e.name))
          .sort((a, b) => (b.modified || '').localeCompare(a.modified || ''));
        for (const e of matches) {
          known.add(e.name.toLowerCase());
          out.push({
            key: e.path || joinAgentPath(d.dir, e.name, sep), name: e.name, path: e.path || joinAgentPath(d.dir, e.name, sep), dir: d.dir,
            kind: p.kind, desc: t(p.descKey, p.desc), present: true, size: e.size, modified: e.modified,
          });
        }
      }
    }
    return out;
  }, [spec, dirs, sep, t]);

  const selected = files.find((f) => f.key === selectedKey) ?? null;
  const listing = Object.values(dirs).some((d) => d.status === 'loading');

  // First present file selected once the listings are in.
  useEffect(() => {
    if (selectedKey || listing) return;
    const first = files.find((f) => f.present && f.kind === 'log') ?? files.find((f) => f.present);
    if (first) setSelectedKey(first.key);
  }, [files, listing, selectedKey]);

  // ── Read one file ─────────────────────────────────────────────────────────
  const loadFile = useCallback(async (f: ViewFile) => {
    const seq = ++loadSeq.current;
    rawRef.current = null;
    setMatchIndex(0);
    if (f.present === false) { setContent({ status: 'idle' }); return; }
    if (f.size !== undefined && f.size > VIEW_MAX_BYTES) { setContent({ status: 'tooLarge', size: f.size }); return; }
    setContent({ status: 'loading' });
    try {
      const res = await send('download_file', { path: f.path }, DOWNLOAD_TIMEOUT_MS);
      if (seq !== loadSeq.current) return;
      if (res.status !== 'success') {
        const text = failureText(res);
        if (/too large/i.test(text)) { setContent({ status: 'tooLarge', size: f.size ?? 0 }); return; }
        setContent({ status: 'error', error: text || t('oblilogs.err.read', 'Could not read the file.') });
        return;
      }
      const bytes = base64ToBytes(res.result?.data ?? '');
      rawRef.current = { key: f.key, bytes };
      if (bytes.length > VIEW_MAX_BYTES) { setContent({ status: 'tooLarge', size: bytes.length }); return; }
      const head = bytes.subarray(0, Math.min(bytes.length, 8192));
      if (head.includes(0)) { setContent({ status: 'binary' }); return; }
      let slice = bytes;
      let truncated = false;
      if (bytes.length > TAIL_BYTES) {
        slice = bytes.subarray(bytes.length - TAIL_BYTES);
        const nl = slice.indexOf(10);
        if (nl >= 0 && nl < slice.length - 1) slice = slice.subarray(nl + 1);
        truncated = true;
      }
      const raw = new TextDecoder('utf-8', { fatal: false }).decode(slice);
      let text: string;
      let pretty = false;
      if (f.kind === 'json' && !truncated) {
        const r = formatAndMaskJson(raw);
        text = r.text; pretty = r.pretty;
      } else {
        text = maskSecretsInText(raw.replace(/^﻿/, ''));
      }
      setContent({ status: 'ok', text: text.replace(/\r\n/g, '\n'), truncated, totalBytes: bytes.length, pretty });
    } catch (err: any) {
      if (seq !== loadSeq.current) return;
      setContent({ status: 'error', error: isStepUpHandled(err) ? t('oblilogs.err.cancelled', 'Confirmation cancelled.') : (err?.message || t('oblilogs.err.read', 'Could not read the file.')) });
    }
  }, [send, failureText, t]);

  // Read on a selection change only: a refreshed listing must not re-read
  // (each read is an audited download_file, possibly behind a step-up).
  useEffect(() => {
    if (selected) void loadFile(selected);
    else setContent({ status: 'idle' });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedKey]);

  // ── Download (raw bytes: the same file the Explorer tab gives) ────────────
  const handleDownload = async () => {
    if (!selected) return;
    setDownloading(true);
    try {
      let bytes = rawRef.current?.key === selected.key ? rawRef.current.bytes : null;
      if (!bytes) {
        const res = await send('download_file', { path: selected.path }, 180_000);
        if (res.status !== 'success') { toast.error(failureText(res) || t('fileExplorer.downloadFailed', 'Download failed')); return; }
        bytes = base64ToBytes(res.result?.data ?? '');
      }
      const ok = await saveBlob(new Blob([bytes as BlobPart]), selected.name, 'application/octet-stream');
      if (ok) toast.success(t('fileExplorer.downloadSuccess', 'File downloaded'));
      else toast.error(t('fileExplorer.downloadFailed', 'Download failed'));
    } catch (err: any) {
      if (!isStepUpHandled(err)) toast.error(err?.message || t('fileExplorer.downloadFailed', 'Download failed'));
    } finally {
      setDownloading(false);
    }
  };

  const handleCopy = () => {
    if (content.status !== 'ok') return;
    copyText(content.text).then((ok) => ok
      ? toast.success(t('oblilogs.copied', 'Copied (secrets masked)'))
      : toast.error(t('common.error', 'Error')));
  };

  const handleRefresh = () => {
    void listDirs();
    if (selected) void loadFile(selected);
  };

  // ── Search ────────────────────────────────────────────────────────────────
  const lines = useMemo(() => (content.status === 'ok' ? content.text.split('\n') : []), [content]);
  const searchRe = useMemo(() => (deferredQuery ? new RegExp(escapeRegExp(deferredQuery), 'gi') : null), [deferredQuery]);
  const matchCount = useMemo(() => {
    if (!searchRe) return 0;
    let n = 0;
    for (const l of lines) { const m = l.match(searchRe); if (m) n += m.length; }
    return n;
  }, [lines, searchRe]);

  useEffect(() => { setMatchIndex(0); }, [deferredQuery]);

  const scrollToMatch = useCallback((i: number) => {
    const el = contentRef.current?.querySelector(`[data-m="${i}"]`);
    if (el) (el as HTMLElement).scrollIntoView({ block: 'center' });
  }, []);

  useEffect(() => {
    if (matchCount > 0) scrollToMatch(Math.min(matchIndex, matchCount - 1));
  }, [matchIndex, matchCount, scrollToMatch]);

  const stepMatch = (dir: 1 | -1) => {
    if (matchCount === 0) return;
    setMatchIndex((i) => (i + dir + matchCount) % matchCount);
  };

  // Logs open at their end (the newest lines).
  useLayoutEffect(() => {
    if (content.status !== 'ok' || !contentRef.current) return;
    if (selected?.kind === 'log' && !deferredQuery) contentRef.current.scrollTop = contentRef.current.scrollHeight;
    else contentRef.current.scrollTop = 0;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [content]);

  const renderedLines = useMemo(() => {
    let counter = 0;
    return lines.map((line, idx) => {
      let body: ReactNode = line || '​';
      if (searchRe && line) {
        const parts: ReactNode[] = [];
        let last = 0;
        searchRe.lastIndex = 0;
        let m: RegExpExecArray | null;
        while ((m = searchRe.exec(line)) !== null) {
          if (m[0] === '') { searchRe.lastIndex++; continue; }
          if (m.index > last) parts.push(line.slice(last, m.index));
          const i = counter++;
          parts.push(
            <mark key={`${idx}-${i}`} data-m={i} className={clsx('rounded-sm px-0.5 text-inherit', i === matchIndex ? 'bg-amber-400/70 text-black' : 'bg-amber-400/25')}>
              {m[0]}
            </mark>,
          );
          last = m.index + m[0].length;
        }
        if (parts.length) {
          if (last < line.length) parts.push(line.slice(last));
          body = parts;
        }
      }
      return (
        <div key={idx} className="flex">
          {lineNumbers && (
            <span className="sticky left-0 shrink-0 w-12 select-none bg-bg-primary pr-3 text-right text-text-muted/60">{idx + 1}</span>
          )}
          <span className={clsx('min-w-0 flex-1', wrap ? 'whitespace-pre-wrap break-all' : 'whitespace-pre')}>{body}</span>
        </div>
      );
    });
  }, [lines, searchRe, matchIndex, lineNumbers, wrap]);

  // ── Layout ────────────────────────────────────────────────────────────────
  const fileIcon = (kind: AgentFileKind) => (kind === 'json' ? FileJson : FileText);

  const fileList = (
    <div className="flex min-h-0 flex-col overflow-y-auto overscroll-contain rounded-lg border border-border bg-bg-primary/40 max-md:max-h-[38dvh] max-md:supports-[not(height:100dvh)]:max-h-[38vh] md:w-72 md:shrink-0">
      {notes.map((n) => (
        <div key={n.key} className="border-b border-border px-3 py-2 text-[11px] text-text-muted break-words">
          {t(n.key, { defaultValue: n.text, ...(n.vars ?? {}) })}
        </div>
      ))}
      {spec.map((d) => {
        const st = dirs[d.dir];
        const dirFiles = files.filter((f) => f.dir === d.dir);
        // A folder that only holds optional files (rotated / update logs) is
        // left out when none of them is there.
        if (d.files.length === 0 && dirFiles.length === 0 && (st?.status === 'ok' || st?.status === 'missing')) return null;
        return (
          <div key={d.dir} className="border-b border-border last:border-b-0">
            <div className="flex items-center gap-1.5 px-3 py-1.5 font-mono text-[11px] text-text-muted break-all" title={d.dir}>
              {st?.status === 'loading' && <Loader2 className="h-3 w-3 shrink-0 animate-spin" />}
              {st?.status === 'missing' && <FolderX className="h-3 w-3 shrink-0" />}
              {st?.status === 'error' && <AlertTriangle className="h-3 w-3 shrink-0 text-yellow-400" />}
              <span className="min-w-0">{d.dir}</span>
            </div>
            {st?.status === 'missing' && (
              <div className="px-3 pb-1.5 text-[11px] text-text-muted/70">{t('oblilogs.dirMissing', 'Folder absent on this device')}</div>
            )}
            {st?.status === 'error' && (
              <div className="px-3 pb-1.5 text-[11px] text-yellow-400/90 break-words">{st.error}</div>
            )}
            {dirFiles.map((f) => {
              const Icon = fileIcon(f.kind);
              const active = f.key === selectedKey;
              const absent = f.present === false;
              return (
                <button
                  key={f.key}
                  type="button"
                  onClick={() => setSelectedKey(f.key)}
                  title={f.desc}
                  className={clsx(
                    'flex w-full items-start gap-2 px-3 py-1.5 text-left transition-colors coarse:min-h-10',
                    active ? 'bg-accent/15 text-text-primary' : 'hover:bg-bg-tertiary/60',
                    absent && 'opacity-45',
                  )}
                >
                  <Icon className={clsx('mt-0.5 h-3.5 w-3.5 shrink-0', active ? 'text-accent' : 'text-text-muted')} />
                  <span className="min-w-0 flex-1">
                    <span className="block truncate font-mono text-xs text-text-primary">{f.name}</span>
                    <span className="block truncate text-[11px] text-text-muted">
                      {absent
                        ? t('oblilogs.absent', 'absent')
                        : f.present === null
                          ? f.desc
                          : `${formatSize(f.size)} · ${formatDate(f.modified)}`}
                    </span>
                  </span>
                </button>
              );
            })}
          </div>
        );
      })}
    </div>
  );

  const toolbarBtn = 'inline-flex items-center gap-1.5 rounded-lg px-2 py-1 text-xs text-text-muted transition-colors hover:bg-bg-tertiary hover:text-text-primary disabled:cursor-not-allowed disabled:opacity-40 coarse:min-h-10 coarse:min-w-10 coarse:justify-center';

  const contentPane = (
    <div className="flex min-h-0 min-w-0 flex-1 flex-col overflow-hidden rounded-lg border border-border">
      {/* Toolbar */}
      <div className="flex flex-wrap items-center gap-1.5 border-b border-border px-2 py-1.5">
        <div className="min-w-0 flex-1 basis-40">
          <div className="truncate font-mono text-xs text-text-primary" title={selected?.path}>{selected?.path ?? '—'}</div>
          {selected?.desc && <div className="truncate text-[11px] text-text-muted">{selected.desc}</div>}
        </div>
        <div className="flex items-center gap-1 rounded-lg bg-bg-tertiary px-2 py-1 max-sm:w-full">
          <Search className="h-3.5 w-3.5 shrink-0 text-text-muted" />
          <input
            type="search"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={(e) => { if (e.key === 'Enter') { e.preventDefault(); stepMatch(e.shiftKey ? -1 : 1); } }}
            placeholder={t('oblilogs.search', 'Search…')}
            autoCapitalize="off" autoCorrect="off" spellCheck={false}
            className="w-36 min-w-0 bg-transparent text-xs text-text-primary placeholder:text-text-muted focus:outline-none max-sm:flex-1"
          />
          {deferredQuery && (
            <span className="shrink-0 text-[11px] tabular-nums text-text-muted">
              {matchCount > 0 ? `${Math.min(matchIndex, matchCount - 1) + 1}/${matchCount}` : '0'}
            </span>
          )}
          <button type="button" onClick={() => stepMatch(-1)} disabled={matchCount === 0} className="text-text-muted hover:text-text-primary disabled:opacity-30" aria-label={t('oblilogs.prevMatch', 'Previous match')}>
            <ChevronUp className="h-3.5 w-3.5" />
          </button>
          <button type="button" onClick={() => stepMatch(1)} disabled={matchCount === 0} className="text-text-muted hover:text-text-primary disabled:opacity-30" aria-label={t('oblilogs.nextMatch', 'Next match')}>
            <ChevronDown className="h-3.5 w-3.5" />
          </button>
        </div>
        <button type="button" onClick={() => setWrap((w) => !w)} className={clsx(toolbarBtn, wrap && 'bg-bg-tertiary text-text-primary')} title={t('oblilogs.wrap', 'Wrap lines')} aria-pressed={wrap}>
          <WrapText className="h-3.5 w-3.5" />
        </button>
        <button type="button" onClick={() => setLineNumbers((v) => !v)} className={clsx(toolbarBtn, lineNumbers && 'bg-bg-tertiary text-text-primary')} title={t('oblilogs.lineNumbers', 'Line numbers')} aria-pressed={lineNumbers}>
          <ListOrdered className="h-3.5 w-3.5" />
        </button>
        <button type="button" onClick={handleCopy} disabled={content.status !== 'ok'} className={toolbarBtn} title={t('oblilogs.copy', 'Copy to clipboard')}>
          <Copy className="h-3.5 w-3.5" />
        </button>
        <button type="button" onClick={handleRefresh} disabled={listing || content.status === 'loading'} className={toolbarBtn} title={t('oblilogs.refresh', 'Refresh')}>
          <RefreshCw className={clsx('h-3.5 w-3.5', (listing || content.status === 'loading') && 'animate-spin')} />
        </button>
        <button type="button" onClick={handleDownload} disabled={!selected || selected.present === false || downloading} className={toolbarBtn} title={t('oblilogs.download', 'Download')}>
          {downloading ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Download className="h-3.5 w-3.5" />}
        </button>
      </div>

      {/* Notices */}
      {content.status === 'ok' && content.truncated && (
        <div className="flex flex-wrap items-center gap-2 border-b border-border bg-yellow-400/10 px-3 py-1.5 text-[11px] text-yellow-300">
          <AlertTriangle className="h-3.5 w-3.5 shrink-0" />
          <span className="min-w-0 flex-1">
            {t('oblilogs.tailNotice', {
              defaultValue: 'Large file ({{size}}): only the last {{tail}} are shown.',
              size: formatSize(content.totalBytes), tail: formatSize(TAIL_BYTES),
            })}
          </span>
          <button type="button" onClick={handleDownload} disabled={downloading} className="rounded-md border border-yellow-400/40 px-2 py-0.5 hover:bg-yellow-400/20 disabled:opacity-50">
            {t('oblilogs.downloadFull', 'Download full file')}
          </button>
        </div>
      )}

      {/* Body */}
      <div ref={contentRef} className="min-h-0 flex-1 overflow-auto overscroll-contain bg-bg-primary font-mono text-xs leading-5 text-text-primary max-md:min-h-[40dvh] max-md:supports-[not(height:100dvh)]:min-h-[40vh]">
        {content.status === 'ok' && <div className="min-w-max py-2 pr-3" style={wrap ? { minWidth: 0 } : undefined}>{renderedLines}</div>}
        {content.status === 'loading' && (
          <div className="flex h-full min-h-32 items-center justify-center gap-2 font-sans text-sm text-text-muted">
            <Loader2 className="h-4 w-4 animate-spin" /> {t('oblilogs.loading', 'Reading the file on the agent…')}
          </div>
        )}
        {content.status === 'error' && (
          <div className="flex h-full min-h-32 flex-col items-center justify-center gap-2 p-6 text-center font-sans text-sm text-red-400">
            <AlertTriangle className="h-5 w-5" /> <span className="break-words">{content.error}</span>
          </div>
        )}
        {content.status === 'binary' && (
          <div className="flex h-full min-h-32 items-center justify-center p-6 text-center font-sans text-sm text-text-muted">
            {t('oblilogs.binary', 'Binary file: use Download.')}
          </div>
        )}
        {content.status === 'tooLarge' && (
          <div className="flex h-full min-h-32 flex-col items-center justify-center gap-3 p-6 text-center font-sans text-sm text-text-muted">
            <span>
              {t('oblilogs.tooLarge', {
                defaultValue: 'This file is too large to be shown here ({{size}}, viewer limit {{max}}).',
                size: formatSize(content.size), max: formatSize(VIEW_MAX_BYTES),
              })}
            </span>
            <button type="button" onClick={handleDownload} disabled={downloading} className="inline-flex items-center gap-1.5 rounded-lg bg-[#C83232] px-3 py-1.5 text-xs font-medium text-white hover:brightness-110 disabled:opacity-50">
              {downloading ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Download className="h-3.5 w-3.5" />}
              {t('oblilogs.downloadFull', 'Download full file')}
            </button>
          </div>
        )}
        {content.status === 'idle' && (
          <div className="flex h-full min-h-32 items-center justify-center p-6 text-center font-sans text-sm text-text-muted">
            {listing
              ? <span className="inline-flex items-center gap-2"><Loader2 className="h-4 w-4 animate-spin" /> {t('oblilogs.listing', 'Listing the agent folders…')}</span>
              : selected?.present === false
                ? t('oblilogs.absentFile', 'This file does not exist on this device.')
                : t('oblilogs.pick', 'Select a file.')}
          </div>
        )}
      </div>
    </div>
  );

  return (
    <Modal
      open
      onClose={onClose}
      size="full"
      icon={<ScrollText className="h-4 w-4 text-accent" />}
      title={t('oblilogs.title', { defaultValue: 'Logs and data of the {{agent}} agent', agent: agent.label })}
      bodyClassName={clsx('flex min-h-0 gap-3', isMd ? 'flex-row overflow-hidden' : 'flex-col')}
      footerClassName="justify-between"
      footer={(
        <>
          <span className="inline-flex min-w-0 items-center gap-1.5 text-[11px] text-text-muted">
            <ShieldCheck className="h-3.5 w-3.5 shrink-0 text-green-400" />
            {t('oblilogs.maskedNotice', 'Secrets (API keys, tokens, passwords) are masked in this view; Download gives the raw file.')}
          </span>
          <button type="button" onClick={onClose} className="rounded-lg bg-bg-tertiary px-3 py-1.5 text-xs text-text-primary hover:brightness-110 coarse:min-h-10">
            {t('common.close', 'Close')}
          </button>
        </>
      )}
    >
      {fileList}
      {contentPane}
    </Modal>
  );
}
