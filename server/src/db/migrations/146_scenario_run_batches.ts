import type { Knex } from 'knex';

// Scenario run batches: every run created by ONE firing that fans out to
// several devices (manual "Trigger" / editor "Run on devices", one cron tick
// of a schedule trigger) carries the same batch_id, so the history can show
// "this firing, these N machines" and a consolidated output of a script node.
// Single-device event triggers (session_login, machine_boot, metric_*…) keep
// NULL. Rows written before this migration stay NULL as well: the API groups
// them by their trigger_source batch marker when they have one, else by
// (scenario, trigger type, minute) — see scenarioBatch.service.ts.
//
// The (scenario_id, batch_id) index is NOT built here: scenario_runs is one of
// the big tables, its indexes are built in the background after startup
// (services/backgroundIndexes.service.ts, idx_scenario_runs_batch). Adding a
// nullable column without default is a metadata-only change.
export async function up(knex: Knex): Promise<void> {
  if (!(await knex.schema.hasColumn('scenario_runs', 'batch_id'))) {
    await knex.schema.alterTable('scenario_runs', (t) => {
      t.uuid('batch_id').nullable();
    });
  }
}

export async function down(knex: Knex): Promise<void> {
  await knex.raw('DROP INDEX IF EXISTS idx_scenario_runs_batch');
  if (await knex.schema.hasColumn('scenario_runs', 'batch_id')) {
    await knex.schema.alterTable('scenario_runs', (t) => {
      t.dropColumn('batch_id');
    });
  }
}
