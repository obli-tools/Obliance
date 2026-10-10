import type { Knex } from 'knex';

// Windows "nt6" build line of the agent (Windows 7 SP1 / 8.1 / Server 2008 R2
// – 2012 R2, Go 1.20) + migration from the reduced legacy agent.
//
//   devices.agent_build       'modern' | 'nt6' (push body `agentBuild`; the
//                             nt6 agent reports agentFlavor 'modern': every
//                             feature stays on). NULL = not reported.
//   devices.ps_version        Windows PowerShell version (push body
//                             `psVersion`, "2.0", "5.1.17763.1"). NULL = unknown.
//   devices.legacy_migration  state of "migrate to the full agent" for a
//                             device running the legacy agent (shared
//                             LegacyMigrationState). NULL = never requested.
//
// Nullable, no default: catalog-only changes in PostgreSQL (no table
// rewrite). Idempotent.
export async function up(knex: Knex): Promise<void> {
  const add: Array<[string, (t: Knex.AlterTableBuilder) => void]> = [
    ['agent_build', (t) => { t.string('agent_build', 16).nullable(); }],
    ['ps_version', (t) => { t.string('ps_version', 32).nullable(); }],
    ['legacy_migration', (t) => { t.jsonb('legacy_migration').nullable(); }],
  ];
  for (const [col, fn] of add) {
    if (!(await knex.schema.hasColumn('devices', col))) {
      await knex.schema.alterTable('devices', fn);
    }
  }
}

export async function down(knex: Knex): Promise<void> {
  for (const col of ['legacy_migration', 'ps_version', 'agent_build']) {
    if (await knex.schema.hasColumn('devices', col)) {
      await knex.schema.alterTable('devices', (t) => t.dropColumn(col));
    }
  }
}
