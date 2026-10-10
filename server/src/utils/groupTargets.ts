// Group target sets — pure helpers (no database: unit-tested by
// groupTargets.test.ts).
//
// A group-targeted entity (compliance policy, software list, schedule,
// scenario, custom section, update policy) stores two lists:
//   - targetIds              the selected groups;
//   - targetManualGroupIds   the subset of targetIds that is "manual".
//
// Semantics (shared with the client):
//   - a group of targetIds that is NOT manual covers itself and ALL its
//     descendants, including the sub-groups created later (closure table);
//   - a manual group covers only the devices directly in it
//     (devices.group_id = id), never its sub-groups;
//   - the union of all of them. A manual id absent from targetIds is ignored.
//
// Manual ids can only NARROW what targetIds alone would cover: they never
// broaden a target set.

import type { Knex } from 'knex';

/**
 * SECURITY (permission.service.ts) — a team group grant reaches a group
 * through device_group_closure. A grant with team_permissions.recursive =
 * false (migration 143) covers ONLY its own group (closure depth 0: the
 * devices directly in it, and the group itself), never the descendants.
 * Every closure join that resolves a group grant MUST add this guard;
 * without it a non-recursive grant would still open the whole subtree.
 * `tp` / `dgc` = the aliases of team_permissions and device_group_closure.
 */
export function recursiveGrantGuard(tp: string, dgc: string) {
  return function (this: Knex.QueryBuilder) {
    this.where(`${tp}.recursive`, true).orWhere(`${dgc}.depth`, 0);
  };
}

export interface GroupTargetSet {
  groupIds: number[];
  manualGroupIds?: number[] | null;
}

export interface ClosureRow {
  ancestor_id: number;
  descendant_id: number;
}

/** A stored or received id list (JSON string, array, null) → positive
 *  integers, deduplicated, input order kept. Anything else is dropped. */
export function toIdList(raw: unknown): number[] {
  let v: unknown = raw;
  if (typeof v === 'string') {
    try { v = JSON.parse(v || '[]'); } catch { return []; }
  }
  if (!Array.isArray(v)) return [];
  const out: number[] = [];
  const seen = new Set<number>();
  for (const x of v) {
    const n = typeof x === 'number' ? x : (typeof x === 'string' && /^\d+$/.test(x.trim()) ? Number(x) : NaN);
    if (!Number.isSafeInteger(n) || n <= 0 || seen.has(n)) continue;
    seen.add(n);
    out.push(n);
  }
  return out;
}

/** Manual ids sanitised for storage: integers, deduplicated, and a subset
 *  of `targetIds` (already sanitised by the caller's tenant rules, so the
 *  manual ids inherit them). */
export function sanitizeManualGroupIds(targetIds: unknown, rawManual: unknown): number[] {
  const targets = new Set(toIdList(targetIds));
  return toIdList(rawManual).filter((id) => targets.has(id));
}

/**
 * Manual ids to store on a create / update of a group-targeted entity.
 *  - create: `current` omitted → always an array.
 *  - update: `current` = the stored row (or null when not found) → undefined
 *    when the payload carries none of targetIds / targetManualGroupIds /
 *    targetType (column left untouched); otherwise the stored manual ids
 *    re-sanitised against the resulting targetIds (an id removed from
 *    targetIds loses its manual flag, an older client that only sends
 *    targetIds keeps the flags of the groups still selected).
 * A target type other than 'group' stores [] (manual ids are group ids).
 */
export function manualIdsForWrite(
  data: { targetType?: unknown; targetIds?: unknown; targetManualGroupIds?: unknown },
  current?: { target_type?: unknown; target_ids?: unknown; target_manual_group_ids?: unknown } | null,
): number[] | undefined {
  const isUpdate = current !== undefined;
  const hasType = data.targetType !== undefined;
  const hasTargets = data.targetIds !== undefined;
  const hasManual = data.targetManualGroupIds !== undefined;
  if (isUpdate && !hasType && !hasTargets && !hasManual) return undefined;
  const type = hasType ? data.targetType : (isUpdate ? current?.target_type : 'group');
  if (type !== 'group') return [];
  const targets = hasTargets ? data.targetIds : (current?.target_ids ?? []);
  const manual = hasManual ? data.targetManualGroupIds : (current?.target_manual_group_ids ?? []);
  return sanitizeManualGroupIds(targets, manual);
}

/** Splits a target set into the recursive and the manual (direct-only)
 *  groups. Manual ids not in groupIds are ignored. */
export function splitGroupTargets(t: GroupTargetSet): { recursive: number[]; manual: number[] } {
  const groupIds = toIdList(t.groupIds);
  const manualSet = new Set(toIdList(t.manualGroupIds ?? []));
  const recursive: number[] = [];
  const manual: number[] = [];
  for (const id of groupIds) (manualSet.has(id) ? manual : recursive).push(id);
  return { recursive, manual };
}

/**
 * The group ids whose DIRECT devices are covered by a target set: every
 * recursive group and its descendants (from `closure`, the rows of
 * device_group_closure whose ancestor_id is a recursive group), plus every
 * manual group itself. A device is covered iff its group_id is in it.
 */
export function effectiveGroupIds(t: GroupTargetSet, closure: ClosureRow[]): number[] {
  const { recursive, manual } = splitGroupTargets(t);
  const recursiveSet = new Set(recursive);
  const out = new Set<number>([...recursive, ...manual]);
  for (const r of closure) {
    if (recursiveSet.has(Number(r.ancestor_id))) out.add(Number(r.descendant_id));
  }
  return [...out];
}

/**
 * Whether a device living directly in `groupId` is covered by a target set.
 * `ancestorIds` = the ancestors of groupId (closure rows whose descendant is
 * groupId), self included or not: groupId itself is always considered.
 */
export function groupMatchesTargets(groupId: number | null | undefined, ancestorIds: number[], t: GroupTargetSet): boolean {
  if (groupId == null) return false;
  const gid = Number(groupId);
  const { recursive, manual } = splitGroupTargets(t);
  if (manual.includes(gid)) return true;
  const recursiveSet = new Set(recursive);
  if (recursiveSet.has(gid)) return true;
  return ancestorIds.some((a) => recursiveSet.has(Number(a)));
}
