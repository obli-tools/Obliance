import type { Knex } from 'knex';

// Software compliance remediation through alternatives: the first cycle plus
// REMEDIATION_MAX_RETRIES (3) new cycles, 24 h apart; when the last one fails
// too, the install is a failure (state 'failed') until a manual "Remediate".
// failed_cycles counts the cycles of the current run that ended with every
// alternative failed (reset on success / manual cycle).
export async function up(knex: Knex): Promise<void> {
  if (!(await knex.schema.hasColumn('software_compliance_remediations', 'failed_cycles'))) {
    await knex.schema.alterTable('software_compliance_remediations', (t) => {
      t.integer('failed_cycles').notNullable().defaultTo(0);
    });
  }
}

export async function down(knex: Knex): Promise<void> {
  if (await knex.schema.hasColumn('software_compliance_remediations', 'failed_cycles')) {
    await knex.schema.alterTable('software_compliance_remediations', (t) => {
      t.dropColumn('failed_cycles');
    });
  }
}
