import type { Knex } from 'knex';

// devices (rewritten by every agent push: latest metrics) and
// oblireach_devices (every ObliReach heartbeat) are tiny tables updated all
// the time. When autovacuum fell behind (hours-long queries holding an old
// snapshot, 2026-10-06), a dev install reached 1.5 GB for ~100 devices and
// every page reading devices went to disk.
//
// Storage parameters only (metadata, instant, no rewrite):
// - fillfactor 50: half of each page left free, so an update can write the
//   new row version on the same page (HOT update) instead of a new page;
// - autovacuum on a fixed small threshold instead of 20 % of the table, and
//   without cost delay (the table is small: a pass costs nothing).
// The free space applies to pages written from now on; a table already
// bloated is compacted by backgroundIndexes.service.ts (compactHotTables).
const TABLES = ['devices', 'oblireach_devices'];
const PARAMS = `fillfactor = 50, autovacuum_vacuum_scale_factor = 0, autovacuum_vacuum_threshold = 200,
  autovacuum_analyze_scale_factor = 0.05, autovacuum_vacuum_cost_delay = 0`;

export async function up(knex: Knex): Promise<void> {
  for (const t of TABLES) {
    if (await knex.schema.hasTable(t)) await knex.raw(`ALTER TABLE ${t} SET (${PARAMS})`);
  }
}

export async function down(knex: Knex): Promise<void> {
  for (const t of TABLES) {
    if (await knex.schema.hasTable(t)) {
      await knex.raw(`ALTER TABLE ${t} RESET (fillfactor, autovacuum_vacuum_scale_factor, autovacuum_vacuum_threshold,
        autovacuum_analyze_scale_factor, autovacuum_vacuum_cost_delay)`);
    }
  }
}
