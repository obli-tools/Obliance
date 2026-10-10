import { test } from 'node:test';
import assert from 'node:assert/strict';
import knexFactory from 'knex';
import {
  recursiveGrantGuard,
  toIdList, sanitizeManualGroupIds, splitGroupTargets, effectiveGroupIds,
  groupMatchesTargets, manualIdsForWrite, type ClosureRow,
} from './groupTargets';

// Group target sets (utils/groupTargets.ts). Run:
//   cd server
//   node --import ./src/services/deviceKey/test-resolve.mjs --disable-warning=MODULE_TYPELESS_PACKAGE_JSON \
//        --test "src/utils/groupTargets.test.ts"
//
// Tree used below:
//   1
//   ├── 2
//   │   └── 4
//   └── 3
//   5 (separate root)

const CLOSURE: ClosureRow[] = [
  [1, 1], [1, 2], [1, 3], [1, 4],
  [2, 2], [2, 4],
  [3, 3],
  [4, 4],
  [5, 5],
].map(([a, d]) => ({ ancestor_id: a, descendant_id: d }));

/** Ancestors of g (self included), from CLOSURE. */
const ancestorsOf = (g: number) => CLOSURE.filter((r) => r.descendant_id === g).map((r) => r.ancestor_id);
/** Closure rows of the given ancestors (what resolveGroupTargetGroupIds queries). */
const closureOf = (ids: number[]) => CLOSURE.filter((r) => ids.includes(r.ancestor_id));
const sorted = (a: number[]) => [...a].sort((x, y) => x - y);

test('toIdList: JSON string, arrays, junk', () => {
  assert.deepEqual(toIdList('[3,1,3]'), [3, 1]);
  assert.deepEqual(toIdList([1, '2', 0, -1, 1.5, 'x', null, 2]), [1, 2]);
  assert.deepEqual(toIdList(null), []);
  assert.deepEqual(toIdList('not json'), []);
  assert.deepEqual(toIdList({ a: 1 }), []);
});

test('sanitizeManualGroupIds: subset of targetIds, deduped, ints only', () => {
  assert.deepEqual(sanitizeManualGroupIds([1, 2, 3], [2, 2, 9, 'x', 3]), [2, 3]);
  assert.deepEqual(sanitizeManualGroupIds([], [1]), []);
  assert.deepEqual(sanitizeManualGroupIds([1], null), []);
});

test('splitGroupTargets ignores manual ids absent from groupIds', () => {
  assert.deepEqual(splitGroupTargets({ groupIds: [1, 2], manualGroupIds: [2, 5] }), { recursive: [1], manual: [2] });
});

test('effectiveGroupIds: no manual = group + all descendants (identical to before)', () => {
  const t = { groupIds: [1] };
  assert.deepEqual(sorted(effectiveGroupIds(t, closureOf([1]))), [1, 2, 3, 4]);
});

test('effectiveGroupIds: a group created later is included (closure-driven)', () => {
  const later = [...CLOSURE, { ancestor_id: 1, descendant_id: 6 }, { ancestor_id: 3, descendant_id: 6 }];
  assert.deepEqual(sorted(effectiveGroupIds({ groupIds: [1] }, later.filter((r) => r.ancestor_id === 1))), [1, 2, 3, 4, 6]);
});

test('effectiveGroupIds: manual group = itself only', () => {
  // 1 manual, child 2 selected recursively, 3 unticked
  const t = { groupIds: [1, 2], manualGroupIds: [1] };
  assert.deepEqual(sorted(effectiveGroupIds(t, closureOf([2]))), [1, 2, 4]);
  // only the manual group
  assert.deepEqual(effectiveGroupIds({ groupIds: [2], manualGroupIds: [2] }, []), [2]);
});

test('effectiveGroupIds: manual never narrows a recursive ancestor', () => {
  // 1 recursive covers 2 and 4 even if 2 is flagged manual
  const t = { groupIds: [1, 2], manualGroupIds: [2] };
  assert.deepEqual(sorted(effectiveGroupIds(t, closureOf([1]))), [1, 2, 3, 4]);
});

test('effectiveGroupIds: closure rows of unrelated / manual ancestors are ignored', () => {
  // A manual group's own closure rows must NOT pull its descendants in.
  const t = { groupIds: [2], manualGroupIds: [2] };
  assert.deepEqual(effectiveGroupIds(t, CLOSURE), [2]);
});

test('groupMatchesTargets: recursive via ancestors, manual direct only', () => {
  const recursive = { groupIds: [1] };
  assert.equal(groupMatchesTargets(4, ancestorsOf(4), recursive), true);
  assert.equal(groupMatchesTargets(5, ancestorsOf(5), recursive), false);

  const manual = { groupIds: [1], manualGroupIds: [1] };
  assert.equal(groupMatchesTargets(1, ancestorsOf(1), manual), true);
  assert.equal(groupMatchesTargets(2, ancestorsOf(2), manual), false);
  assert.equal(groupMatchesTargets(4, ancestorsOf(4), manual), false);

  assert.equal(groupMatchesTargets(null, [], recursive), false);
  assert.equal(groupMatchesTargets(4, ancestorsOf(4), { groupIds: [] }), false);
});

test('groupMatchesTargets agrees with effectiveGroupIds on every group', () => {
  const sets = [
    { groupIds: [1] },
    { groupIds: [1], manualGroupIds: [1] },
    { groupIds: [1, 2], manualGroupIds: [1] },
    { groupIds: [2, 5], manualGroupIds: [5] },
    { groupIds: [1, 2], manualGroupIds: [2, 9] },
  ];
  for (const t of sets) {
    const eff = new Set(effectiveGroupIds(t, closureOf(splitGroupTargets(t).recursive)));
    for (const g of [1, 2, 3, 4, 5]) {
      assert.equal(groupMatchesTargets(g, ancestorsOf(g), t), eff.has(g), `set ${JSON.stringify(t)} group ${g}`);
    }
  }
});

test('manualIdsForWrite: create', () => {
  assert.deepEqual(manualIdsForWrite({ targetType: 'group', targetIds: [1, 2], targetManualGroupIds: [2, 3] }), [2]);
  assert.deepEqual(manualIdsForWrite({ targetType: 'device', targetIds: [1, 2], targetManualGroupIds: [2] }), []);
  assert.deepEqual(manualIdsForWrite({ targetType: 'group', targetIds: [1] }), []);
});

test('manualIdsForWrite: update keeps / re-sanitises / leaves untouched', () => {
  const current = { target_type: 'group', target_ids: [1, 2, 3], target_manual_group_ids: '[2,3]' };
  // nothing target-related in the payload → untouched
  assert.equal(manualIdsForWrite({}, current), undefined);
  // older client sends targetIds only: flags of the groups still selected stay
  assert.deepEqual(manualIdsForWrite({ targetIds: [1, 2] }, current), [2]);
  // explicit manual list replaces
  assert.deepEqual(manualIdsForWrite({ targetManualGroupIds: [1] }, current), [1]);
  // switching away from 'group' clears
  assert.deepEqual(manualIdsForWrite({ targetType: 'all' }, current), []);
  // row not found (null) behaves like an update with nothing stored
  assert.deepEqual(manualIdsForWrite({ targetIds: [1] }, null), []);
});

// ── recursiveGrantGuard (permission.service.ts) — SQL shape only, no DB ──
// SECURITY: the guard must be ONE parenthesised OR group ANDed with the rest
// of the query, so "recursive OR depth 0" never short-circuits the user /
// team / scope filters.

const qb = knexFactory({ client: 'pg' });

test('recursiveGrantGuard: parenthesised, ANDed after the other filters', () => {
  const sql = qb('team_permissions as tp')
    .join('device_group_closure as dgc', 'dgc.ancestor_id', 'tp.scope_id')
    .where({ 'tp.scope': 'group', 'dgc.descendant_id': 7 })
    .whereIn('tp.team_id', [1, 2])
    .where(recursiveGrantGuard('tp', 'dgc'))
    .select('tp.level')
    .toSQL();
  assert.match(sql.sql, /and \("tp"\."recursive" = \? or "dgc"\."depth" = \?\)/);
  assert.ok(sql.sql.indexOf('"tp"."scope" = ?') < sql.sql.indexOf('"tp"."recursive"'));
  const b = sql.bindings as unknown[];
  assert.deepEqual(b.slice(-2), [true, 0]);
});

test('recursiveGrantGuard: full table names (getVisibleDeviceIds shape)', () => {
  const sql = qb('devices')
    .join('device_group_closure', 'device_group_closure.descendant_id', 'devices.group_id')
    .join('team_permissions', function () {
      this.on('team_permissions.scope_id', 'device_group_closure.ancestor_id')
        .andOn(qb.raw("team_permissions.scope = 'group'"));
    })
    .whereIn('team_permissions.team_id', [3])
    .where(recursiveGrantGuard('team_permissions', 'device_group_closure'))
    .select('devices.id')
    .toSQL().sql;
  assert.match(sql, /where "team_permissions"\."team_id" in \(\?\) and \("team_permissions"\."recursive" = \? or "device_group_closure"\."depth" = \?\)/);
});

/** What the guard admits, evaluated in memory over (grant, closure) pairs:
 *  a reference model of the permission semantics. */
function grantCovers(grant: { scopeId: number; recursive: boolean }, deviceGroupId: number): boolean {
  return CLOSURE.some((r) => r.ancestor_id === grant.scopeId && r.descendant_id === deviceGroupId
    && (grant.recursive || r.ancestor_id === r.descendant_id /* depth 0 */));
}

test('permission semantics: recursive=false never reaches a descendant', () => {
  const flat = { scopeId: 1, recursive: false };
  assert.equal(grantCovers(flat, 1), true);
  for (const g of [2, 3, 4]) assert.equal(grantCovers(flat, g), false, `group ${g}`);
  assert.equal(grantCovers(flat, 5), false);
  const deep = { scopeId: 1, recursive: true };
  for (const g of [1, 2, 3, 4]) assert.equal(grantCovers(deep, g), true, `group ${g}`);
  assert.equal(grantCovers(deep, 5), false);
  // a non-recursive grant on a child never widens to its parent
  assert.equal(grantCovers({ scopeId: 2, recursive: false }, 1), false);
});
