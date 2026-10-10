import type { Knex } from 'knex';
import { db } from '../db';
import {
  effectiveGroupIds, groupMatchesTargets, splitGroupTargets, toIdList,
  type GroupTargetSet, type ClosureRow,
} from '../utils/groupTargets';

// Database side of the group target sets (semantics: utils/groupTargets.ts).
// Every feature that resolves "the devices of these groups" goes through
// here, so a manual group (direct devices only) is honoured everywhere.

type Exec = Knex | Knex.Transaction;

/**
 * The group ids whose direct devices a target set covers (recursive groups
 * + all their descendants, manual groups alone). No tenant filter: the
 * caller scopes the devices query (devices.tenant_id) as it did before.
 */
export async function resolveGroupTargetGroupIds(t: GroupTargetSet, exec: Exec = db): Promise<number[]> {
  const { recursive, manual } = splitGroupTargets(t);
  if (recursive.length === 0) return manual;
  const closure = await exec('device_group_closure')
    .whereIn('ancestor_id', recursive)
    .select('ancestor_id', 'descendant_id') as ClosureRow[];
  return effectiveGroupIds(t, closure);
}

/**
 * Device ids covered by a target set. `tenantId` (number) restricts to the
 * devices of that tenant; null/undefined = no tenant filter (master god
 * view callers only). `approvedOnly` keeps approval_status='approved'.
 */
export async function resolveGroupTargetDeviceIds(
  t: GroupTargetSet,
  opts: { tenantId?: number | null; approvedOnly?: boolean; exec?: Exec } = {},
): Promise<number[]> {
  const exec = opts.exec ?? db;
  const groupIds = await resolveGroupTargetGroupIds(t, exec);
  if (groupIds.length === 0) return [];
  const q = exec('devices').whereIn('group_id', groupIds);
  if (opts.tenantId != null) q.where({ tenant_id: opts.tenantId });
  if (opts.approvedOnly) q.where({ approval_status: 'approved' });
  return (await q.pluck('id')).map(Number);
}

/** Ancestors of a group, self included (closure rows with descendant_id = groupId). */
export async function groupAncestorIds(groupId: number, exec: Exec = db): Promise<number[]> {
  return (await exec('device_group_closure').where({ descendant_id: groupId }).pluck('ancestor_id')).map(Number);
}

/** Whether a device whose group_id is `groupId` is covered by a target set
 *  (ancestor-based single-device check). */
export async function groupIdMatchesGroupTargets(groupId: number | null | undefined, t: GroupTargetSet, exec: Exec = db): Promise<boolean> {
  if (groupId == null) return false;
  const { recursive, manual } = splitGroupTargets(t);
  if (recursive.length === 0 && manual.length === 0) return false;
  const ancestors = recursive.length > 0 ? await groupAncestorIds(Number(groupId), exec) : [];
  return groupMatchesTargets(Number(groupId), ancestors, t);
}

/** Whether a device (by id, or a row carrying group_id) is covered by a target set. */
export async function deviceMatchesGroupTargets(
  device: number | { group_id: number | null },
  t: GroupTargetSet,
  exec: Exec = db,
): Promise<boolean> {
  let groupId: number | null;
  if (typeof device === 'number') {
    const row = await exec('devices').where({ id: device }).first('group_id') as { group_id: number | null } | undefined;
    if (!row) return false;
    groupId = row.group_id;
  } else {
    groupId = device.group_id;
  }
  return groupIdMatchesGroupTargets(groupId, t, exec);
}

/** Read helper: the stored manual ids of a row (target_manual_group_ids). */
export function rowManualGroupIds(row: { target_manual_group_ids?: unknown } | null | undefined): number[] {
  return toIdList(row?.target_manual_group_ids ?? []);
}
