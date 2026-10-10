import { useEffect, useMemo, useState, type KeyboardEvent } from 'react';
import { useTranslation } from 'react-i18next';
import { ChevronRight, FolderOpen, Check, Minus, AlertTriangle } from 'lucide-react';
import { clsx } from 'clsx';
import { groupsApi } from '@/api/groups.api';
import { Button } from '@/components/common/Button';
import type { DeviceGroupTreeNode } from '@obliance/shared';
import {
 buildGroupTreeIndex,
 computeGroupCheckStates,
 excludeFromAutoGroup,
 findCoveringAncestor,
 isGroupChecked,
 normalizeGroupTarget,
 sameGroupTarget,
 toggleGroup,
 type GroupTargetValue,
 type GroupTreeIndex,
} from './groupTargetSelection';

export type { GroupTargetValue } from './groupTargetSelection';

/**
 * Loads the group tree once and indexes it (parent / children maps). Used by
 * the picker and by the list views that show "N group(s)" (normalized count).
 */
export function useGroupTreeIndex(): { tree: DeviceGroupTreeNode[]; index: GroupTreeIndex | null; loaded: boolean } {
 const [tree, setTree] = useState<DeviceGroupTreeNode[]>([]);
 const [loaded, setLoaded] = useState(false);
 useEffect(() => {
  let alive = true;
  groupsApi.tree().then((nodes) => { if (alive) { setTree(nodes); setLoaded(true); } }).catch(() => { if (alive) setLoaded(true); });
  return () => { alive = false; };
 }, []);
 const index = useMemo(() => (loaded ? buildGroupTreeIndex(tree) : null), [tree, loaded]);
 return { tree, index, loaded };
}

interface Props {
 value: GroupTargetValue;
 onChange: (value: GroupTargetValue) => void;
}

/**
 * Inline group tree multi-select shared by every "target groups" form
 * (schedules, scenarios, script run, compliance, software compliance, update
 * policies, custom sections).
 *
 * Semantics (see groupTargetSelection.ts): a ticked group includes all its
 * sub-groups, present AND future. Unticking a sub-group covered by a ticked
 * ancestor switches that ancestor to "manual" after an in-page confirmation.
 *
 * Touch: the whole row toggles the selection, rows
 * are 40 px tall on coarse pointers and the expand chevron gets a bigger hit
 * area.
 */
export function GroupTreeMultiSelect({ value, onChange }: Props) {
 const { t } = useTranslation();
 const { tree, index } = useGroupTreeIndex();
 const [expanded, setExpanded] = useState<Set<number> | null>(null);
 const [pending, setPending] = useState<{ groupId: number; anchorId: number } | null>(null);

 // Auto-expand everything on first load.
 useEffect(() => {
  if (!index || expanded) return;
  setExpanded(new Set(index.parentOf.keys()));
 }, [index, expanded]);

 const names = useMemo(() => {
  const m = new Map<number, string>();
  const walk = (list: DeviceGroupTreeNode[]) => { for (const n of list) { m.set(n.id, n.name); walk(n.children); } };
  walk(tree);
  return m;
 }, [tree]);

 // Normalize legacy rows (old frozen expansion: group + every descendant)
 // as soon as the tree is known — same display, same server semantics.
 useEffect(() => {
  if (!index) return;
  const norm = normalizeGroupTarget(value, index);
  if (!sameGroupTarget(norm, value) || norm.targetIds.length !== value.targetIds.length) onChange(norm);
  // eslint-disable-next-line react-hooks/exhaustive-deps
 }, [index, value]);

 // A pending confirmation becomes stale if the value changed underneath.
 useEffect(() => {
  if (pending && index && findCoveringAncestor(value, index, pending.groupId) !== pending.anchorId) setPending(null);
 }, [value, index, pending]);

 const states = useMemo(() => (index ? computeGroupCheckStates(value, index) : new Map()), [value, index]);

 const toggleNode = (node: DeviceGroupTreeNode) => {
  if (!index) return;
  const res = toggleGroup(value, index, node.id);
  if (res.kind === 'confirm') { setPending({ groupId: node.id, anchorId: res.anchorId }); return; }
  setPending(null);
  onChange(res.value);
 };

 const confirmPending = () => {
  if (!pending || !index) return;
  onChange(excludeFromAutoGroup(value, index, pending.groupId));
  setPending(null);
 };

 const toggleExpand = (id: number) => {
  setExpanded((prev) => {
   const next = new Set(prev ?? []);
   if (next.has(id)) next.delete(id); else next.add(id);
   return next;
  });
 };

 const onCheckboxKey = (e: KeyboardEvent<HTMLButtonElement>) => {
  // Space/Enter already click the button; stop the row from seeing it twice.
  if (e.key === ' ' || e.key === 'Enter') e.stopPropagation();
 };

 const coveringName = (id: number) => {
  if (!index) return '';
  const a = findCoveringAncestor(value, index, id);
  return a != null ? names.get(a) ?? '' : '';
 };

 const manualHint = t('groupTarget.manualHint', 'Manual selection: only the ticked sub-groups are included, new sub-groups are not added automatically.');

 const renderNode = (node: DeviceGroupTreeNode, depth: number) => {
  const hasChildren = node.children.length > 0;
  const isExpanded = expanded?.has(node.id) ?? true;
  const state = states.get(node.id) ?? 'none';
  const checked = isGroupChecked(state);
  const count = node.total ?? node.deviceCount ?? 0;
  const coveredTitle = state === 'covered'
   ? t('groupTarget.coveredHint', { name: coveringName(node.id), defaultValue: 'Included through "{{name}}"' })
   : undefined;

  return (
   <div key={node.id}>
    {/* The whole row toggles the selection (big tap target on touch);
        the chevron and the checkbox stop propagation so they act once. */}
    <div
     onClick={() => toggleNode(node)}
     title={coveredTitle}
     className={clsx(
      'flex items-center gap-1.5 py-1.5 transition-colors rounded hover:bg-bg-hover cursor-pointer coarse:min-h-10',
      (state === 'selected' || state === 'manual') && 'bg-accent/5',
      pending?.groupId === node.id && 'ring-1 ring-amber-400/60',
     )}
     style={{ paddingLeft: `${8 + depth * 20}px`, paddingRight: 8 }}
    >
     <button
      type="button"
      onClick={(e) => { e.stopPropagation(); if (hasChildren) toggleExpand(node.id); }}
      aria-label={isExpanded ? t('automations.collapse', 'Collapse') : t('automations.expand', 'Expand')}
      aria-expanded={hasChildren ? isExpanded : undefined}
      tabIndex={hasChildren ? 0 : -1}
      className={clsx(
       'shrink-0 p-0.5 coarse:p-2.5 rounded text-text-muted hover:text-text-primary transition-colors',
       !hasChildren && 'invisible',
      )}
     >
      <ChevronRight className={clsx('w-3 h-3 transition-transform', isExpanded && 'rotate-90')} />
     </button>

     <button
      type="button"
      role="checkbox"
      aria-checked={checked ? true : state === 'partial' ? 'mixed' : false}
      aria-label={node.name}
      onClick={(e) => { e.stopPropagation(); toggleNode(node); }}
      onKeyDown={onCheckboxKey}
      className={clsx(
       'w-4 h-4 coarse:w-5 coarse:h-5 rounded border flex items-center justify-center shrink-0 transition-colors',
       state === 'selected' || state === 'manual' ? 'bg-accent border-accent text-white' :
       state === 'covered' ? 'bg-accent/60 border-accent/60 text-white' :
       state === 'partial' ? 'bg-accent/30 border-accent text-white' :
       'border-transparent hover:border-accent/50',
      )}
     >
      {checked && <Check className="w-3 h-3" />}
      {state === 'partial' && <Minus className="w-3 h-3" />}
     </button>

     <FolderOpen className={clsx('w-3.5 h-3.5 shrink-0', state !== 'none' ? 'text-accent' : 'text-text-muted')} />
     <span
      className={clsx(
       'flex-1 min-w-0 text-sm truncate cursor-pointer',
       state === 'selected' || state === 'manual' ? 'text-text-primary font-medium' : 'text-text-primary',
      )}
     >
      {node.name}
     </span>
     {state === 'manual' && (
      <span
       className="shrink-0 text-[9px] uppercase tracking-wider px-1 py-px rounded border border-amber-400/40 text-amber-400"
       title={manualHint}
      >
       {t('groupTarget.manualBadge', 'manual')}
      </span>
     )}
     <span className="text-text-muted text-[10px] shrink-0">{count}</span>
    </div>
    {hasChildren && isExpanded && node.children.map((c) => renderNode(c, depth + 1))}
   </div>
  );
 };

 if (!index) return <p className="text-sm text-text-muted py-2">{t('common.loading', 'Loading...')}</p>;
 if (tree.length === 0) {
  return <p className="text-sm text-text-muted py-2">{t('automations.groupTree.empty', 'No groups available')}</p>;
 }

 return (
  <div className="space-y-1.5">
   <div className="rounded-lg bg-bg-tertiary max-h-60 coarse:max-h-80 overflow-y-auto overscroll-contain py-1">
    {tree.map((n) => renderNode(n, 0))}
   </div>
   {pending && (
    <div role="alert" className="rounded-lg border border-amber-400/40 bg-amber-400/10 p-2.5 text-xs text-text-primary space-y-2">
     <div className="flex gap-2">
      <AlertTriangle className="w-4 h-4 shrink-0 text-amber-400" />
      <p>
       {t('groupTarget.switchToManualWarning', {
        group: names.get(pending.groupId) ?? '',
        parent: names.get(pending.anchorId) ?? '',
        defaultValue: 'Unticking "{{group}}" switches "{{parent}}" to manual selection: new sub-groups of "{{parent}}" will no longer be added automatically.',
       })}
      </p>
     </div>
     <div className="flex justify-end gap-2">
      <Button type="button" size="sm" variant="secondary" onClick={() => setPending(null)}>{t('common.cancel', 'Cancel')}</Button>
      <Button type="button" size="sm" onClick={confirmPending}>{t('groupTarget.switchToManualConfirm', 'Untick and switch to manual')}</Button>
     </div>
    </div>
   )}
   <p className="text-[11px] text-text-muted">
    {t('groupTarget.legend', 'A checked group includes its future sub-groups.')}
    {' '}
    <span className="inline-flex items-center gap-1" title={manualHint}>
     <span className="text-[9px] uppercase tracking-wider px-1 rounded border border-amber-400/40 text-amber-400">{t('groupTarget.manualBadge', 'manual')}</span>
     {t('groupTarget.legendManual', '= only the ticked sub-groups.')}
    </span>
   </p>
  </div>
 );
}
