import { useState, useEffect, useCallback, useRef, type KeyboardEvent, type MouseEvent } from 'react';
import { Plus, X, Folder, FolderOpen, HardDrive, LayoutGrid, Columns2 } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { clsx } from 'clsx';
import toast from 'react-hot-toast';
import { fileApi } from '@/api/file.api';
import { isCommandSupported, unsupportedTooltip } from '@/utils/capabilities';
import { useMediaQuery, MEDIA } from '@/hooks/useMediaQuery';
import { useConfirm } from '@/components/common/ConfirmDialog';
import ExplorerPane, { folderLabel, type ExplorerRefreshSignal } from './fileExplorer/ExplorerPane';
import type { Device } from '@obliance/shared';

// ─── Files sub-tabs ──────────────────────────────────────────────────────────
//
// The Explorer tab of a device holds several Files views of the SAME machine
// (sub-tabs). Each sub-tab is an <ExplorerPane> with its own state (folder,
// listing, selection, scroll, editor); hidden sub-tabs stay mounted so
// nothing is lost when switching. Ctrl+click (⌘+click) on sub-tabs builds a
// MOSAIC (2 = two columns, 3-4 = a 2 × 2 grid) from lg up; a plain click
// goes back to a single view. The open sub-tabs (paths only) are kept in
// sessionStorage per device, so a page reload brings them back.

interface Props {
  device: Device;
}

interface SubTab {
  id: string;
  path: string;
}

const MAX_TABS = 8;
const MAX_MOSAIC = 4;

// 40 px tap targets on touch screens (desktop sizes unchanged).
const TB = 'coarse:min-h-10 coarse:min-w-10 coarse:inline-flex coarse:items-center coarse:justify-center';

let idSeq = 0;
const newTabId = () => `fx${Date.now().toString(36)}${(idSeq++).toString(36)}`;

const storageKey = (deviceId: Device['id']) => `obliance.fileExplorer.subTabs.${deviceId}`;

function loadTabs(deviceId: Device['id']): { tabs: SubTab[]; activeId: string } {
  try {
    const raw = window.sessionStorage.getItem(storageKey(deviceId));
    if (raw) {
      const saved = JSON.parse(raw) as { paths?: unknown; active?: unknown };
      const paths = Array.isArray(saved.paths)
        ? saved.paths.filter((p): p is string => typeof p === 'string').slice(0, MAX_TABS)
        : [];
      if (paths.length > 0) {
        const tabs = paths.map((path) => ({ id: newTabId(), path }));
        const idx = typeof saved.active === 'number' && saved.active >= 0 && saved.active < tabs.length ? saved.active : 0;
        return { tabs, activeId: tabs[idx].id };
      }
    }
  } catch {
    /* storage unavailable or corrupted: start fresh */
  }
  const first = { id: newTabId(), path: '' };
  return { tabs: [first], activeId: first.id };
}

function saveTabs(deviceId: Device['id'], tabs: SubTab[], activeId: string) {
  try {
    window.sessionStorage.setItem(
      storageKey(deviceId),
      JSON.stringify({ paths: tabs.map((tab) => tab.path), active: Math.max(0, tabs.findIndex((tab) => tab.id === activeId)) }),
    );
  } catch {
    /* storage unavailable (private mode, quota): the sub-tabs just are not restored */
  }
}

export default function FileExplorerTab({ device }: Props) {
  const { t } = useTranslation();

  // Audit: one "explorer opened" per visit of the tab, whatever the number of sub-tabs.
  useEffect(() => {
    fileApi.logOpen(device.id).catch(() => {});
  }, [device.id]);

  // Defensive guard: if an agent build can't browse directories at all
  // (list_directory), show an explanatory banner instead of a dead toolbar.
  // Both current flavors support browsing/create/rename/delete; only file
  // TRANSFER (upload_file/download_file) is legacy-unsupported and is greyed
  // per-action in the panes — so in practice this banner is reserved for
  // future capability-restricted builds.
  if (!isCommandSupported(device, 'list_directory')) {
    return (
      <div className="bg-bg-secondary rounded-xl p-10 text-center text-text-muted text-sm flex flex-col items-center gap-2">
        <FolderOpen className="w-8 h-8 opacity-40" />
        <p>{unsupportedTooltip(t)}</p>
      </div>
    );
  }

  // A new device = new sub-tabs (never the previous device's panes).
  return <ExplorerSubTabs key={device.id} device={device} />;
}

function ExplorerSubTabs({ device }: Props) {
  const { t } = useTranslation();
  const confirm = useConfirm();
  // The mosaic needs room: from lg up. Below, one pane + the sub-tab strip.
  const isLg = useMediaQuery(MEDIA.lg);
  const isWindows = device.osType === 'windows';

  const [initial] = useState(() => loadTabs(device.id));
  const [tabs, setTabs] = useState<SubTab[]>(initial.tabs);
  const [activeId, setActiveId] = useState(initial.activeId);
  // Sub-tabs shown side by side (in sub-tab order); fewer than 2 = single view.
  const [mosaic, setMosaic] = useState<string[]>([]);
  const [refreshSignal, setRefreshSignal] = useState<ExplorerRefreshSignal>({ seq: 0, paths: [], sourcePaneId: null });
  // 2FA confirmations in flight, shared by the panes (one prompt per action).
  const stepUpMap = useRef(new Map<string, Promise<unknown>>()).current;
  // Panes whose text editor holds unsaved changes.
  const dirtyRef = useRef(new Set<string>());
  const stripRef = useRef<HTMLDivElement>(null);

  const mosaicActive = isLg && mosaic.length >= 2;

  useEffect(() => {
    saveTabs(device.id, tabs, activeId);
  }, [device.id, tabs, activeId]);

  // Keep the active sub-tab in view when the strip scrolls (horizontal only).
  useEffect(() => {
    const strip = stripRef.current;
    if (!strip || strip.scrollWidth <= strip.clientWidth) return;
    const el = strip.querySelector<HTMLElement>(`[data-tab-id="${activeId}"]`);
    if (!el) return;
    const left = el.offsetLeft;
    const right = left + el.offsetWidth;
    if (left < strip.scrollLeft) strip.scrollTo({ left: Math.max(0, left - 8), behavior: 'smooth' });
    else if (right > strip.scrollLeft + strip.clientWidth) strip.scrollTo({ left: right - strip.clientWidth + 8, behavior: 'smooth' });
  }, [activeId, tabs.length]);

  // ── Pane callbacks (stable) ─────────────────────────────────────────────

  const handlePathChange = useCallback((paneId: string, path: string) => {
    setTabs((prev) => (prev.some((tab) => tab.id === paneId && tab.path !== path)
      ? prev.map((tab) => (tab.id === paneId ? { ...tab, path } : tab))
      : prev));
  }, []);

  const handleFocus = useCallback((paneId: string) => setActiveId(paneId), []);

  const handleChanged = useCallback((paths: string[], sourcePaneId: string | null) => {
    setRefreshSignal((s) => ({ seq: s.seq + 1, paths, sourcePaneId }));
  }, []);

  const handleDirtyChange = useCallback((paneId: string, dirty: boolean) => {
    if (dirty) dirtyRef.current.add(paneId);
    else dirtyRef.current.delete(paneId);
  }, []);

  // ── Sub-tab actions ─────────────────────────────────────────────────────

  const selectTab = (id: string) => {
    setMosaic([]);
    setActiveId(id);
  };

  // Ctrl / ⌘ + click: add the sub-tab to the mosaic, or take it out.
  const toggleMosaic = (id: string) => {
    const base = mosaicActive ? mosaic : [activeId];
    let next: string[];
    if (base.includes(id)) {
      next = base.filter((x) => x !== id);
    } else {
      if (base.length >= MAX_MOSAIC) {
        toast(t('fileExplorer.tabs.mosaicMax', 'Up to {{count}} views side by side', { count: MAX_MOSAIC }));
        return;
      }
      next = [...base, id];
    }
    // Sub-tab order, whatever the order of the clicks.
    next = tabs.map((tab) => tab.id).filter((x) => next.includes(x));
    if (next.length < 2) {
      setMosaic([]);
      if (next.length === 1) setActiveId(next[0]);
      return;
    }
    setMosaic(next);
    setActiveId(next.includes(id) ? id : (next.includes(activeId) ? activeId : next[next.length - 1]));
  };

  const handleTabClick = (e: MouseEvent, id: string) => {
    if ((e.ctrlKey || e.metaKey) && isLg) toggleMosaic(id);
    else selectTab(id);
  };

  const addTab = () => {
    if (tabs.length >= MAX_TABS) return;
    // The new view opens on the folder of the current one.
    const current = tabs.find((tab) => tab.id === activeId);
    const tab = { id: newTabId(), path: current?.path ?? '' };
    setTabs((prev) => [...prev, tab]);
    // In a mosaic with room left, the new view joins it.
    if (mosaicActive && mosaic.length < MAX_MOSAIC) setMosaic([...mosaic, tab.id]);
    else setMosaic([]);
    setActiveId(tab.id);
  };

  const closeTab = async (id: string) => {
    if (tabs.length <= 1) return; // the last view stays
    if (dirtyRef.current.has(id)) {
      const ok = await confirm({
        message: t('fileExplorer.tabs.closeUnsaved', 'This view has a file with unsaved changes. Close it anyway?'),
        confirmLabel: t('fileExplorer.discardChanges', 'Discard changes'),
        danger: true,
      });
      if (!ok) return;
    }
    dirtyRef.current.delete(id);
    const index = tabs.findIndex((tab) => tab.id === id);
    const nextTabs = tabs.filter((tab) => tab.id !== id);
    let nextMosaic = mosaic.filter((x) => x !== id);
    if (nextMosaic.length < 2) nextMosaic = [];
    let nextActive = activeId;
    if (activeId === id || !nextTabs.some((tab) => tab.id === activeId)) {
      nextActive = mosaic.includes(id) && mosaic.length === 2
        ? mosaic.find((x) => x !== id)!
        : nextMosaic.length > 0
          ? nextMosaic[nextMosaic.length - 1]
          : nextTabs[Math.min(index, nextTabs.length - 1)].id;
    }
    setTabs(nextTabs);
    setMosaic(nextMosaic);
    setActiveId(nextActive);
  };

  const handleStripKeyDown = (e: KeyboardEvent<HTMLDivElement>) => {
    const idx = tabs.findIndex((tab) => tab.id === activeId);
    let next = -1;
    if (e.key === 'ArrowRight') next = (idx + 1) % tabs.length;
    else if (e.key === 'ArrowLeft') next = (idx - 1 + tabs.length) % tabs.length;
    else if (e.key === 'Home') next = 0;
    else if (e.key === 'End') next = tabs.length - 1;
    else if (e.key === 'Delete' && tabs.length > 1) {
      e.preventDefault();
      closeTab(activeId);
      return;
    }
    if (next < 0) return;
    e.preventDefault();
    selectTab(tabs[next].id);
    requestAnimationFrame(() => {
      stripRef.current?.querySelector<HTMLElement>(`[data-tab-id="${tabs[next].id}"]`)?.focus();
    });
  };

  // ── Layout ──────────────────────────────────────────────────────────────

  const visibleIds = mosaicActive ? mosaic : [activeId];
  const mosaicRows = mosaicActive ? (visibleIds.length <= 2 ? 1 : 2) : 0;
  const rootLabel = isWindows ? t('fileExplorer.drives') : '/';
  const canAdd = tabs.length < MAX_TABS;

  return (
    <div className="space-y-2">
      {/* ── Sub-tab strip (+ new view) ─────────────────────────────────── */}
      <div className="flex items-center gap-2 min-w-0">
        <div
          ref={stripRef}
          role="tablist"
          aria-label={t('fileExplorer.tabs.label', 'Files views')}
          aria-multiselectable={mosaicActive || undefined}
          onKeyDown={handleStripKeyDown}
          className="relative flex items-center gap-1 min-w-0 rounded-lg bg-bg-secondary p-[5px] overflow-x-auto overscroll-x-contain scrollbar-none"
        >
          {tabs.map((tab) => {
            const isActive = tab.id === activeId;
            const inMosaic = mosaicActive && mosaic.includes(tab.id);
            const label = folderLabel(tab.path, device.osType) || rootLabel;
            return (
              <div
                key={tab.id}
                data-tab-id={tab.id}
                role="tab"
                aria-selected={isActive || inMosaic}
                tabIndex={isActive ? 0 : -1}
                title={tab.path || rootLabel}
                onClick={(e) => handleTabClick(e, tab.id)}
                // Middle click closes (and no autoscroll cursor).
                onMouseDown={(e) => { if (e.button === 1) e.preventDefault(); }}
                onAuxClick={(e) => {
                  if (e.button !== 1) return;
                  e.preventDefault();
                  closeTab(tab.id);
                }}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault();
                    selectTab(tab.id);
                  }
                }}
                className={clsx(
                  'group/tab flex shrink-0 items-center gap-1.5 max-w-[13rem] rounded-md py-1 text-xs font-medium cursor-pointer select-none whitespace-nowrap transition-colors coarse:min-h-10',
                  tabs.length > 1 ? 'pl-2.5 pr-1' : 'px-2.5',
                  'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-accent/60',
                  isActive
                    ? 'bg-accent text-white'
                    : inMosaic
                      ? 'bg-accent/15 text-text-primary ring-1 ring-inset ring-accent/40 hover:bg-accent/20'
                      : 'text-text-muted hover:text-text-primary hover:bg-bg-tertiary',
                )}
              >
                {tab.path
                  ? <Folder className={clsx('w-3.5 h-3.5 shrink-0', isActive ? 'text-white' : 'text-yellow-500')} />
                  : <HardDrive className="w-3.5 h-3.5 shrink-0" />}
                <span className="truncate py-0.5">{label}</span>
                {tabs.length > 1 && (
                  <button
                    type="button"
                    tabIndex={-1}
                    onClick={(e) => {
                      e.stopPropagation();
                      closeTab(tab.id);
                    }}
                    className={clsx(
                      'shrink-0 p-0.5 rounded transition-[opacity,color,background-color] coarse:p-1.5',
                      isActive
                        ? 'text-white/70 hover:text-white hover:bg-white/15'
                        : 'text-text-muted hover:text-text-primary hover:bg-bg-tertiary',
                      // Mouse: revealed on hover (always on the active view).
                      !isActive && 'can-hover:opacity-0 can-hover:group-hover/tab:opacity-100 can-hover:focus-visible:opacity-100',
                    )}
                    title={t('fileExplorer.tabs.close', 'Close view')}
                    aria-label={t('fileExplorer.tabs.closeNamed', 'Close {{name}}', { name: label })}
                  >
                    <X className="w-3 h-3" />
                  </button>
                )}
              </div>
            );
          })}
        </div>

        <button
          type="button"
          onClick={addTab}
          disabled={!canAdd}
          className={clsx('shrink-0 p-1.5 rounded-lg text-text-muted hover:text-text-primary hover:bg-bg-tertiary disabled:opacity-30 disabled:cursor-not-allowed transition-colors', TB)}
          title={canAdd
            ? t('fileExplorer.tabs.new', 'New Files view (opens on the current folder)')
            : t('fileExplorer.tabs.max', 'Up to {{count}} Files views', { count: MAX_TABS })}
          aria-label={t('fileExplorer.tabs.newShort', 'New Files view')}
        >
          <Plus className="w-4 h-4" />
        </button>

        {/* Mosaic: how to (desktop) / back to a single view. */}
        <div className="ml-auto hidden lg:flex items-center shrink-0 text-xs text-text-muted">
          {mosaicActive ? (
            <button
              type="button"
              onClick={() => selectTab(activeId)}
              className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg hover:text-text-primary hover:bg-bg-tertiary transition-colors"
              title={t('fileExplorer.tabs.singleViewHint', 'Show only the focused view (or click a tab)')}
            >
              <LayoutGrid className="w-3.5 h-3.5" />
              {t('fileExplorer.tabs.singleView', 'Single view')}
            </button>
          ) : tabs.length > 1 && (
            <span className="flex items-center gap-1.5 opacity-70">
              <Columns2 className="w-3.5 h-3.5" />
              {t('fileExplorer.tabs.mosaicHint', 'Ctrl+click tabs to show them side by side')}
            </span>
          )}
        </div>
      </div>

      {/* ── Panes: all mounted, only the shown ones displayed ─────────── */}
      <div className={clsx(mosaicActive && 'grid grid-cols-2 gap-3')}>
        {tabs.map((tab) => {
          const pos = visibleIds.indexOf(tab.id);
          const visible = pos >= 0;
          // 3 views: the third one takes the full width of the second row.
          const span = mosaicActive && visibleIds.length === 3 && pos === 2;
          return (
            <div key={tab.id} className={clsx('min-w-0', !visible && 'hidden', span && 'col-span-2')}>
              <ExplorerPane
                device={device}
                paneId={tab.id}
                initialPath={tab.path}
                visible={visible}
                focused={tab.id === activeId}
                mosaicRows={visible ? mosaicRows : 0}
                onFocus={handleFocus}
                onPathChange={handlePathChange}
                stepUpMap={stepUpMap}
                refreshSignal={refreshSignal}
                onChanged={handleChanged}
                onDirtyChange={handleDirtyChange}
              />
            </div>
          );
        })}
      </div>
    </div>
  );
}
