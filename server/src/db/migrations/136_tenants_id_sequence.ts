import type { Knex } from 'knex';

// 001 inserts the default tenant with an explicit id (1) and nothing moved the
// tenants id sequence past it: on a new database, the first tenant created
// from the API failed on tenants_pkey (the sequence handed out 1 again) and
// only the retry got 2. Moves the sequence past the highest tenant id, and
// never backwards: on a database where it already moved on (after that first
// failure, or after tenants were deleted) it stays where it is, so the id of
// a deleted tenant is never handed out again. Idempotent.
export async function up(knex: Knex): Promise<void> {
  await knex.raw(`
    SELECT setval(
      s.seq,
      GREATEST(
        (SELECT COALESCE(MAX(id), 0) FROM tenants),
        COALESCE(pg_sequence_last_value(s.seq::regclass), 0),
        1
      ),
      true
    )
    FROM (SELECT pg_get_serial_sequence('tenants', 'id') AS seq) s
    WHERE s.seq IS NOT NULL
  `);
}

export async function down(): Promise<void> {
  // Nothing to undo: moving a sequence back could hand out an id in use.
}
