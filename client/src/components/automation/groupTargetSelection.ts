/**
 * Pure logic of the "group target" selection (no React, no I/O) — shared by
 * GroupTreeMultiSelect and the Teams permission tree. Kept dependency-free so
 * it can be unit-tested as-is (the client has no test runner yet: run the
 * scenarios at the bottom of this comment with any TS runner, e.g. tsx).
 *
 * Contract (identical on the server):
 *   value = { targetIds, targetManualGroupIds }
 *   - id in targetIds AND in targetManualGroupIds -> that group's DIRECT
 *     devices only ("manual" group);
 *   - id in targetIds, not manual -> the group and ALL its descendants,
 *     including sub-groups created later ("auto" group).
 *
 * Display: a group is checked when it is itself in targetIds, or when an
 * ancestor is an auto entry ("covered"). A group that is not checked but has
 * a selected descendant is "partial".
 *
 * Normalized form (what the pickers emit): no entry is covered by an auto
 * ancestor (redundant), manual ids ⊆ targetIds, no duplicates. Legacy rows
 * saved with the old frozen expansion (group + every descendant at click
 * time) normalize to the group alone: same display, same server semantics.
 *
 * Unticking a group X covered by an auto ancestor A (path A=p0 … pk=X):
 *   for i in 0..k-1: p_i becomes manual (p0 is already an entry; p1..p_{k-1}
 *   are added as manual entries) and every child of p_i other than p_{i+1}
 *   is added as an auto entry. Result: A's direct devices, every intermediate
 *   ancestor's direct devices and every sibling subtree stay covered; X's
 *   subtree is excluded; new sub-groups of A (or of an intermediate) are no
 *   longer added automatically — hence the confirmation shown to the user.
 *
 * Worked example (tree: 1{2{4,5},3}, value {[1],[]}):
 *   untick 4 -> needs confirm (anchor 1) -> exclude -> {[1,2,3,5],[1,2]}
 *   untick 3 -> {[1,2],[1]}       tick 4 on {[1,2,3,5],[1,2]} -> {…,4} (auto)
 *   tick 1 on {[1,2,3,5],[1,2]} -> {[1],[]} (descendants dropped, back to auto)
 *   normalize {[1,2,3,4,5],[]} -> {[1],[]} (legacy frozen expansion)
 */

export interface GroupTargetValue {
 targetIds: number[];
 targetManualGroupIds: number[];
}

export interface GroupTreeLike {
 id: number;
 children: GroupTreeLike[];
}

export interface GroupTreeIndex {
 /** parent id, null for a root. Only ids present in the tree are keys. */
 parentOf: Map<number, number | null>;
 childrenOf: Map<number, number[]>;
 roots: number[];
}

export type GroupCheckState = 'selected' | 'manual' | 'covered' | 'partial' | 'none';

export type GroupToggleResult =
 | { kind: 'change'; value: GroupTargetValue }
 /** Unticking a group covered by the auto ancestor `anchorId`: ask the user
  *  first, then apply `excludeFromAutoGroup`. */
 | { kind: 'confirm'; anchorId: number };

export const EMPTY_GROUP_TARGET: GroupTargetValue = { targetIds: [], targetManualGroupIds: [] };

export function buildGroupTreeIndex(tree: GroupTreeLike[]): GroupTreeIndex {
 const parentOf = new Map<number, number | null>();
 const childrenOf = new Map<number, number[]>();
 const walk = (nodes: GroupTreeLike[], parent: number | null) => {
  for (const n of nodes) {
   parentOf.set(n.id, parent);
   childrenOf.set(n.id, n.children.map((c) => c.id));
   walk(n.children, n.id);
  }
 };
 walk(tree, null);
 return { parentOf, childrenOf, roots: tree.map((n) => n.id) };
}

/** Ancestors of `id`, nearest first. */
export function ancestorsOf(index: GroupTreeIndex, id: number): number[] {
 const out: number[] = [];
 const seen = new Set<number>([id]);
 let p = index.parentOf.get(id) ?? null;
 while (p != null && !seen.has(p)) { out.push(p); seen.add(p); p = index.parentOf.get(p) ?? null; }
 return out;
}

export function descendantsOf(index: GroupTreeIndex, id: number): number[] {
 const out: number[] = [];
 const stack = [...(index.childrenOf.get(id) ?? [])];
 while (stack.length) {
  const c = stack.pop()!;
  out.push(c);
  stack.push(...(index.childrenOf.get(c) ?? []));
 }
 return out;
}

/** Topmost auto entry among the ancestors of `id`, or null. */
export function findCoveringAncestor(value: GroupTargetValue, index: GroupTreeIndex, id: number): number | null {
 const ids = new Set(value.targetIds);
 const manual = new Set(value.targetManualGroupIds);
 let found: number | null = null;
 for (const a of ancestorsOf(index, id)) if (ids.has(a) && !manual.has(a)) found = a;
 return found;
}

export function normalizeGroupTarget(value: GroupTargetValue, index: GroupTreeIndex): GroupTargetValue {
 const ids: number[] = [];
 const seen = new Set<number>();
 for (const id of value.targetIds) if (!seen.has(id)) { seen.add(id); ids.push(id); }
 const manual = new Set(value.targetManualGroupIds.filter((id) => seen.has(id)));
 // Ids unknown to the tree (deleted group, other tenant…) are kept untouched.
 const kept = ids.filter((id) => !ancestorsOf(index, id).some((a) => seen.has(a) && !manual.has(a)));
 const keptSet = new Set(kept);
 return { targetIds: kept, targetManualGroupIds: [...manual].filter((id) => keptSet.has(id)) };
}

export function sameGroupTarget(a: GroupTargetValue, b: GroupTargetValue): boolean {
 const eq = (x: number[], y: number[]) => {
  if (x.length !== y.length) return false;
  const s = new Set(x);
  return y.every((v) => s.has(v));
 };
 return eq(a.targetIds, b.targetIds) && eq(a.targetManualGroupIds, b.targetManualGroupIds);
}

/** Check state of every group in the tree, for one render pass. */
export function computeGroupCheckStates(value: GroupTargetValue, index: GroupTreeIndex): Map<number, GroupCheckState> {
 const ids = new Set(value.targetIds);
 const manual = new Set(value.targetManualGroupIds);
 const hasSelectedDescendant = new Set<number>();
 for (const id of ids) for (const a of ancestorsOf(index, id)) hasSelectedDescendant.add(a);
 const states = new Map<number, GroupCheckState>();
 const walk = (nodeIds: number[], coveredAbove: boolean) => {
  for (const id of nodeIds) {
   let state: GroupCheckState;
   if (ids.has(id)) state = manual.has(id) ? 'manual' : 'selected';
   else if (coveredAbove) state = 'covered';
   else state = hasSelectedDescendant.has(id) ? 'partial' : 'none';
   states.set(id, state);
   walk(index.childrenOf.get(id) ?? [], coveredAbove || state === 'selected');
  }
 };
 walk(index.roots, false);
 return states;
}

export const isGroupChecked = (s: GroupCheckState | undefined) => s === 'selected' || s === 'manual' || s === 'covered';

/** Tick `id` as an auto entry; its descendants become redundant and are dropped. */
export function tickGroup(value: GroupTargetValue, index: GroupTreeIndex, id: number): GroupTargetValue {
 const drop = new Set([id, ...descendantsOf(index, id)]);
 return normalizeGroupTarget({
  targetIds: [...value.targetIds.filter((x) => !drop.has(x)), id],
  targetManualGroupIds: value.targetManualGroupIds.filter((x) => !drop.has(x)),
 }, index);
}

/**
 * Click on a group. Checked -> untick (direct removal, or a confirmation when
 * the group is only covered by an auto ancestor); otherwise -> tick (auto).
 */
export function toggleGroup(value: GroupTargetValue, index: GroupTreeIndex, id: number): GroupToggleResult {
 const v = normalizeGroupTarget(value, index);
 if (v.targetIds.includes(id)) {
  return { kind: 'change', value: {
   targetIds: v.targetIds.filter((x) => x !== id),
   targetManualGroupIds: v.targetManualGroupIds.filter((x) => x !== id),
  } };
 }
 const anchor = findCoveringAncestor(v, index, id);
 if (anchor != null) return { kind: 'confirm', anchorId: anchor };
 return { kind: 'change', value: tickGroup(v, index, id) };
}

export interface ExclusionPlan {
 /** Groups that become manual (anchor first, then the intermediates down to X's parent). */
 manualIds: number[];
 /** Siblings along the path, added as auto entries. */
 autoIds: number[];
}

/** The conversion described in the header comment, as a plan (ids only). */
export function planExclusion(index: GroupTreeIndex, anchorId: number, excludedId: number): ExclusionPlan | null {
 const up = ancestorsOf(index, excludedId);
 const at = up.indexOf(anchorId);
 if (at < 0) return null;
 const path = [...up.slice(0, at + 1).reverse(), excludedId]; // anchor … X
 const manualIds: number[] = [];
 const autoIds: number[] = [];
 for (let i = 0; i < path.length - 1; i++) {
  manualIds.push(path[i]);
  for (const c of index.childrenOf.get(path[i]) ?? []) if (c !== path[i + 1]) autoIds.push(c);
 }
 return { manualIds, autoIds };
}

/** Apply the confirmed exclusion of `excludedId` (covered by an auto ancestor). */
export function excludeFromAutoGroup(value: GroupTargetValue, index: GroupTreeIndex, excludedId: number): GroupTargetValue {
 const v = normalizeGroupTarget(value, index);
 const anchor = findCoveringAncestor(v, index, excludedId);
 if (anchor == null) return v;
 const plan = planExclusion(index, anchor, excludedId)!;
 const ids = [...v.targetIds];
 for (const id of [...plan.manualIds, ...plan.autoIds]) if (!ids.includes(id)) ids.push(id);
 const manual = [...v.targetManualGroupIds];
 for (const id of plan.manualIds) if (!manual.includes(id)) manual.push(id);
 return normalizeGroupTarget({ targetIds: ids, targetManualGroupIds: manual }, index);
}

// ── Recursive grants (Teams permissions) ─────────────────────────────────────
//
// Same model with per-group payloads (level / capabilities): a grant with
// recursive=true covers the group and all its descendants (future ones too),
// recursive=false only the group's direct devices. Grants are NOT normalized
// (a descendant grant may carry a different level), so the exclusion has to
// neutralize EVERY recursive ancestor of X, nearest first: each region keeps
// the level of the nearest grant that used to cover it.

export interface RecursiveGrant<P> {
 recursive: boolean;
 payload: P;
}

/** Recursive grants on the ancestors of `id`, nearest first. */
export function coveringRecursiveGrants<P>(grants: Map<number, RecursiveGrant<P>>, index: GroupTreeIndex, id: number): number[] {
 return ancestorsOf(index, id).filter((a) => grants.get(a)?.recursive === true);
}

/**
 * Exclude group X (and its subtree) from the recursive grants that cover it.
 * For each covering ancestor C (nearest first) with payload P: C and every
 * intermediate down to X's parent become non-recursive (an intermediate
 * without a grant gets P), every sibling along the path gets a recursive
 * grant with P — a sibling that already has a grant keeps it, and when that
 * grant is non-recursive its children are filled the same way so nothing that
 * C used to cover is lost. Returns a new map (input untouched).
 */
export function excludeFromRecursiveGrants<P>(
 grants: Map<number, RecursiveGrant<P>>,
 index: GroupTreeIndex,
 excludedId: number,
): Map<number, RecursiveGrant<P>> {
 const next = new Map<number, RecursiveGrant<P>>();
 for (const [k, g] of grants) next.set(k, { ...g });
 const fill = (groupId: number, payload: P) => {
  for (const c of index.childrenOf.get(groupId) ?? []) {
   const g = next.get(c);
   if (!g) next.set(c, { recursive: true, payload });
   else if (!g.recursive) fill(c, payload);
  }
 };
 for (const anchor of coveringRecursiveGrants(grants, index, excludedId)) {
  const payload = grants.get(anchor)!.payload;
  const plan = planExclusion(index, anchor, excludedId);
  if (!plan) continue;
  for (const m of plan.manualIds) {
   const g = next.get(m);
   if (g) g.recursive = false;
   else next.set(m, { recursive: false, payload });
  }
  for (const a of plan.autoIds) {
   const g = next.get(a);
   if (!g) next.set(a, { recursive: true, payload });
   else if (!g.recursive) fill(a, payload);
  }
 }
 return next;
}

/** Number of top-level entries ("N group(s)"): normalized entry count. */
export function countGroupTargets(value: GroupTargetValue, index: GroupTreeIndex | null): number {
 if (!index) return new Set(value.targetIds).size;
 return normalizeGroupTarget(value, index).targetIds.length;
}

/** Build a value from an API row (missing manual list = none). */
export function groupTargetFrom(targetIds: number[] | null | undefined, manualIds: number[] | null | undefined): GroupTargetValue {
 return { targetIds: targetIds ?? [], targetManualGroupIds: manualIds ?? [] };
}
