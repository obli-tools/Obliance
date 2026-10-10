import type { Knex } from 'knex';

// Software compliance: "OR" entries (alternatives) + OS conditions.
//
// - software_compliance_entries
//     parent_entry_id  null = an entry (its row is ALSO its first
//                      alternative: name / match / publisher / versions /
//                      sources stay where they always were); set = alternative
//                      2..N of that entry (same columns, own sources rows).
//                      ON DELETE CASCADE with the entry.
//     alt_order        position among the alternatives (1..N-1 for children;
//                      0 on the entry row) = remediation order.
//     os_condition     jsonb, OS condition of THIS alternative (null = any).
//     label            entry display label ("Passly"), null = first name.
//   Existing rows need no data migration: each is an entry with exactly one
//   alternative (itself), the API / agent payload of such an entry is
//   unchanged. Every listing of entries filters parent_entry_id IS NULL.
// - software_compliance_lists.os_condition  jsonb, version restriction of the
//   list's target_platform (null = every version).
// - software_compliance_remediations  server-driven remediation through the
//   alternatives, one row per (device, entry): attempts of the current cycle,
//   exhaustion time, alternative that succeeded. Deleted with the entry (a
//   list edit re-creates its entries: progress restarts).
//
// Additive only: nullable columns / constant defaults (metadata-only on
// PostgreSQL 11+), one new table.

export async function up(knex: Knex): Promise<void> {
  if (!(await knex.schema.hasColumn('software_compliance_entries', 'parent_entry_id'))) {
    await knex.schema.alterTable('software_compliance_entries', (t) => {
      t.integer('parent_entry_id').nullable()
        .references('id').inTable('software_compliance_entries').onDelete('CASCADE');
      t.integer('alt_order').notNullable().defaultTo(0);
      t.jsonb('os_condition').nullable();
      t.string('label', 300).nullable();
      t.index(['parent_entry_id'], 'idx_sw_compliance_entries_parent');
    });
  }

  if (!(await knex.schema.hasColumn('software_compliance_lists', 'os_condition'))) {
    await knex.schema.alterTable('software_compliance_lists', (t) => {
      t.jsonb('os_condition').nullable();
    });
  }

  if (!(await knex.schema.hasTable('software_compliance_remediations'))) {
    await knex.schema.createTable('software_compliance_remediations', (t) => {
      t.increments('id').primary();
      t.integer('tenant_id').notNullable().references('id').inTable('tenants').onDelete('CASCADE');
      t.integer('device_id').notNullable().references('id').inTable('devices').onDelete('CASCADE');
      t.integer('list_id').notNullable().references('id').inTable('software_compliance_lists').onDelete('CASCADE');
      t.integer('entry_id').notNullable().references('id').inTable('software_compliance_entries').onDelete('CASCADE');
      t.jsonb('attempts').notNullable().defaultTo('[]');
      t.timestamp('cycle_started_at', { useTz: true }).nullable();
      t.timestamp('exhausted_at', { useTz: true }).nullable();
      t.integer('succeeded_alternative_id').nullable();
      t.timestamp('succeeded_at', { useTz: true }).nullable();
      t.timestamp('updated_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());
      t.unique(['device_id', 'entry_id'], { indexName: 'uq_sw_compliance_remediation_device_entry' });
      t.index(['entry_id'], 'idx_sw_compliance_remediation_entry');
      t.index(['list_id'], 'idx_sw_compliance_remediation_list');
    });
  }
}

export async function down(knex: Knex): Promise<void> {
  await knex.schema.dropTableIfExists('software_compliance_remediations');
  if (await knex.schema.hasColumn('software_compliance_lists', 'os_condition')) {
    await knex.schema.alterTable('software_compliance_lists', (t) => { t.dropColumn('os_condition'); });
  }
  if (await knex.schema.hasColumn('software_compliance_entries', 'parent_entry_id')) {
    // Alternatives 2..N would become standalone entries: drop them first.
    await knex('software_compliance_entries').whereNotNull('parent_entry_id').delete();
    await knex.schema.alterTable('software_compliance_entries', (t) => {
      t.dropIndex(['parent_entry_id'], 'idx_sw_compliance_entries_parent');
      t.dropColumn('parent_entry_id');
      t.dropColumn('alt_order');
      t.dropColumn('os_condition');
      t.dropColumn('label');
    });
  }
}
