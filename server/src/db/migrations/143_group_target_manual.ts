import type { Knex } from 'knex';

// "A selected group includes its future sub-groups and devices; unticking a
// child switches that group to manual."
//
// - target_manual_group_ids (jsonb, default '[]') next to target_ids on every
//   group-targeted entity: the subset of target_ids that covers only the
//   devices DIRECTLY in the group (never its sub-groups). Empty = every
//   selected group is recursive (the behaviour so far).
// - update_policies gains target_ids (+ manual): several targets instead of
//   the single target_id (kept, = first id, for compatibility). Backfilled
//   from target_id.
// - team_permissions.recursive (default true): false = a group grant covers
//   the group's direct devices only, not its descendants.
//
// Purely additive: ADD COLUMN with a constant default is metadata-only on
// PostgreSQL 11+ (no rewrite), no index build. The backfill touches the
// update_policies rows with a target_id (a handful).

const MANUAL_TABLES = [
  'compliance_policies',
  'software_compliance_lists',
  'script_schedules',
  'scenarios',
  'custom_sections',
  'update_policies',
];

export async function up(knex: Knex): Promise<void> {
  if (await knex.schema.hasTable('update_policies')) {
    if (!(await knex.schema.hasColumn('update_policies', 'target_ids'))) {
      await knex.schema.alterTable('update_policies', (t) => {
        t.jsonb('target_ids').notNullable().defaultTo('[]');
      });
      await knex.raw(`
        UPDATE update_policies
        SET target_ids = jsonb_build_array(target_id)
        WHERE target_id IS NOT NULL AND target_type IN ('group', 'device')
      `);
    }
  }

  for (const table of MANUAL_TABLES) {
    if (!(await knex.schema.hasTable(table))) continue;
    if (await knex.schema.hasColumn(table, 'target_manual_group_ids')) continue;
    await knex.schema.alterTable(table, (t) => {
      t.jsonb('target_manual_group_ids').notNullable().defaultTo('[]');
    });
  }

  if (await knex.schema.hasTable('team_permissions')
    && !(await knex.schema.hasColumn('team_permissions', 'recursive'))) {
    await knex.schema.alterTable('team_permissions', (t) => {
      t.boolean('recursive').notNullable().defaultTo(true);
    });
  }
}

export async function down(knex: Knex): Promise<void> {
  if (await knex.schema.hasTable('team_permissions')
    && await knex.schema.hasColumn('team_permissions', 'recursive')) {
    await knex.schema.alterTable('team_permissions', (t) => { t.dropColumn('recursive'); });
  }
  for (const table of MANUAL_TABLES) {
    if (!(await knex.schema.hasTable(table))) continue;
    if (!(await knex.schema.hasColumn(table, 'target_manual_group_ids'))) continue;
    await knex.schema.alterTable(table, (t) => { t.dropColumn('target_manual_group_ids'); });
  }
  if (await knex.schema.hasTable('update_policies')
    && await knex.schema.hasColumn('update_policies', 'target_ids')) {
    await knex.schema.alterTable('update_policies', (t) => { t.dropColumn('target_ids'); });
  }
}
