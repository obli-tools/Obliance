import type { Knex } from 'knex';

// Windows NT 6.x prerequisites + build line of ObliReach (agent "nt6" line,
// Windows 7 SP1 / 8.1 / Server 2008 R2 – 2012 R2).
//
//   devices.windows_prereqs          push body `prereqs` of the Obliance agent
//                                    on Windows < 10 (sp1, sha2Signing, sha2Kbs,
//                                    kb2533623, tls12Schannel, wmfVersion,
//                                    dotnet4x), sanitised. NULL = not reported
//                                    (Windows 10+, other OS, older agent).
//   devices.windows_prereqs_missing  number of REQUIRED prerequisites missing
//                                    (utils/windowsPrereqs.ts), the device
//                                    list filter. NULL = not reported.
//   oblireach_devices.flavor         heartbeat `flavor`: 'modern' | 'nt6'.
//   oblireach_devices.os_build       heartbeat `osBuild` ("6.1.7601").
//   oblireach_devices.update_reason  heartbeat `selfUpdate.lastReason`
//                                    (sha2_unsupported, wrong_flavor…),
//                                    cleared by a successful update.
//
// Nullable, no default: catalog-only changes in PostgreSQL (no table
// rewrite). Idempotent.
const COLUMNS: Array<[string, string, (t: Knex.AlterTableBuilder) => void]> = [
  ['devices', 'windows_prereqs', (t) => { t.jsonb('windows_prereqs').nullable(); }],
  ['devices', 'windows_prereqs_missing', (t) => { t.smallint('windows_prereqs_missing').nullable(); }],
  ['oblireach_devices', 'flavor', (t) => { t.string('flavor', 16).nullable(); }],
  ['oblireach_devices', 'os_build', (t) => { t.string('os_build', 32).nullable(); }],
  ['oblireach_devices', 'update_reason', (t) => { t.string('update_reason', 32).nullable(); }],
];

export async function up(knex: Knex): Promise<void> {
  for (const [table, col, fn] of COLUMNS) {
    if (!(await knex.schema.hasTable(table))) continue;
    if (!(await knex.schema.hasColumn(table, col))) {
      await knex.schema.alterTable(table, fn);
    }
  }
}

export async function down(knex: Knex): Promise<void> {
  for (const [table, col] of [...COLUMNS].reverse()) {
    if (!(await knex.schema.hasTable(table))) continue;
    if (await knex.schema.hasColumn(table, col)) {
      await knex.schema.alterTable(table, (t) => t.dropColumn(col));
    }
  }
}
