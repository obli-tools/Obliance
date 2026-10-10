import type { Knex } from 'knex';

// Agent update policies (ported from Obliguard C17-1) — tenant and group
// levels of the cascade (platform level: app_config 'agent_update_policy' /
// 'oblireach_update_policy', no row written here).
//
//   tenants.agent_update_policy            'auto' | 'manual' | 'frozen' | NULL
//   tenants.oblireach_update_policy        (same)
//   device_groups.agent_update_policy      (same; inherited by sub-groups)
//   device_groups.oblireach_update_policy  (same)
//
// NULL = inherit. Nothing set anywhere = built-in default in code ('manual'
// for the agent, 'auto' for ObliReach: today's behaviour), so nothing changes
// at deploy. Nullable, no default: catalog-only changes in PostgreSQL (no
// table rewrite). Idempotent (columns and CHECK constraints guarded).
const TABLES = ['tenants', 'device_groups'] as const;
const COLUMNS = ['agent_update_policy', 'oblireach_update_policy'] as const;

export async function up(knex: Knex): Promise<void> {
  for (const table of TABLES) {
    if (!(await knex.schema.hasTable(table))) continue;
    for (const col of COLUMNS) {
      if (!(await knex.schema.hasColumn(table, col))) {
        await knex.schema.alterTable(table, (t) => { t.string(col, 8).nullable(); });
      }
      const ck = `${table}_${col}_check`;
      await knex.raw(`ALTER TABLE ?? DROP CONSTRAINT IF EXISTS ??`, [table, ck]);
      await knex.raw(
        `ALTER TABLE ?? ADD CONSTRAINT ?? CHECK (?? IS NULL OR ?? IN ('auto', 'manual', 'frozen'))`,
        [table, ck, col, col],
      );
    }
  }
}

export async function down(knex: Knex): Promise<void> {
  for (const table of TABLES) {
    if (!(await knex.schema.hasTable(table))) continue;
    for (const col of COLUMNS) {
      await knex.raw(`ALTER TABLE ?? DROP CONSTRAINT IF EXISTS ??`, [table, `${table}_${col}_check`]);
      if (await knex.schema.hasColumn(table, col)) {
        await knex.schema.alterTable(table, (t) => t.dropColumn(col));
      }
    }
  }
}
