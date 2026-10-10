import type { Knex } from 'knex';

// Intentionally empty (2026-10-06). This migration used to build two indexes
// (idx_command_queue_secret_params, idx_script_exec_schedule_finished) with
// CREATE INDEX CONCURRENTLY. On a large install that kept the server from
// starting for tens of minutes (migrations run before it listens), and a
// restart in the middle left the knex migration lock set.
//
// idx_script_exec_schedule_finished is now built in the background after
// startup by services/backgroundIndexes.service.ts. The secret-parameter
// index is dropped altogether: building it opened every JSON payload of
// command_queue (hours on a large install) — the sweep is bounded by date
// instead (scriptParams.service.ts). Whatever this migration did before:
// already built (dev, by hand), marked done without building (prod), or never
// run. The file stays so installs that recorded it keep a consistent history.

export async function up(_knex: Knex): Promise<void> {
  // nothing: see services/backgroundIndexes.service.ts
}

export async function down(_knex: Knex): Promise<void> {
  // nothing
}
