import type { Knex } from 'knex';

// Hyper-V VM interactive console — helper bundle install policy, install
// state and console sessions.
//
//   tenants.vmconsole_install_policy        'auto' | 'manual' | 'frozen' | NULL
//   device_groups.vmconsole_install_policy  (same; inherited by sub-groups)
//       Third kind of the update-policy cascade (platform level: app_config
//       'vmconsole_install_policy'). 'auto' = pre-installed on confirmed
//       Hyper-V hosts, 'manual' = on demand (first console opening or the
//       "Install now" button: today's behaviour, the built-in default),
//       'frozen' = never installed. NULL = inherit.
//   devices.vmconsole_state                 push body `vmConsole` of the agent
//       (state, sha256, protocol, error, progress), sanitised. NULL = not
//       reported (not a Hyper-V host, or an agent older than the feature).
//   remote_sessions.vm_id                   VM GUID of a 'vmconsole' session
//       (one interactive console per VM: busy check, audit).
//   remote_protocol enum                    'vmconsole' — NEVER added before:
//       every POST /api/remote/sessions {protocol:'vmconsole'} failed on the
//       INSERT (500, SQLSTATE 22P02), so the interactive console could never
//       open and only the read-only preview (thumbnails) ever worked.
//   command_type enum                       install / open / close_vm_console
//       re-ensured (117 added them; harmless when present).
//
// Nullable, no default: catalog-only changes (no table rewrite). Idempotent
// (columns, CHECK constraints and enum values guarded).
export const config = { transaction: false };

const POLICY_TABLES = ['tenants', 'device_groups'] as const;
const POLICY_COL = 'vmconsole_install_policy';

async function ensureEnumValue(knex: Knex, typeName: string, value: string): Promise<void> {
  const r = await knex.raw(
    `SELECT 1 FROM pg_enum e JOIN pg_type t ON t.oid = e.enumtypid WHERE t.typname = ? AND e.enumlabel = ?`,
    [typeName, value],
  );
  const rows = (Array.isArray(r) ? r : r?.rows ?? []) as unknown[];
  if (rows.length > 0) return;
  const t = await knex.raw(`SELECT 1 FROM pg_type WHERE typname = ?`, [typeName]);
  if (((Array.isArray(t) ? t : t?.rows ?? []) as unknown[]).length === 0) return;
  await knex.raw(`ALTER TYPE ${typeName} ADD VALUE '${value}'`);
}

export async function up(knex: Knex): Promise<void> {
  for (const table of POLICY_TABLES) {
    if (!(await knex.schema.hasTable(table))) continue;
    if (!(await knex.schema.hasColumn(table, POLICY_COL))) {
      await knex.schema.alterTable(table, (t) => { t.string(POLICY_COL, 8).nullable(); });
    }
    const ck = `${table}_${POLICY_COL}_check`;
    await knex.raw(`ALTER TABLE ?? DROP CONSTRAINT IF EXISTS ??`, [table, ck]);
    await knex.raw(
      `ALTER TABLE ?? ADD CONSTRAINT ?? CHECK (?? IS NULL OR ?? IN ('auto', 'manual', 'frozen'))`,
      [table, ck, POLICY_COL, POLICY_COL],
    );
  }
  if (await knex.schema.hasTable('devices') && !(await knex.schema.hasColumn('devices', 'vmconsole_state'))) {
    await knex.schema.alterTable('devices', (t) => { t.jsonb('vmconsole_state').nullable(); });
  }
  if (await knex.schema.hasTable('remote_sessions') && !(await knex.schema.hasColumn('remote_sessions', 'vm_id'))) {
    await knex.schema.alterTable('remote_sessions', (t) => { t.string('vm_id', 36).nullable(); });
  }
  await ensureEnumValue(knex, 'remote_protocol', 'vmconsole');
  for (const v of ['install_vm_console', 'open_vm_console', 'close_vm_console']) {
    await ensureEnumValue(knex, 'command_type', v);
  }
}

export async function down(knex: Knex): Promise<void> {
  if (await knex.schema.hasTable('remote_sessions') && await knex.schema.hasColumn('remote_sessions', 'vm_id')) {
    await knex.schema.alterTable('remote_sessions', (t) => t.dropColumn('vm_id'));
  }
  if (await knex.schema.hasTable('devices') && await knex.schema.hasColumn('devices', 'vmconsole_state')) {
    await knex.schema.alterTable('devices', (t) => t.dropColumn('vmconsole_state'));
  }
  for (const table of POLICY_TABLES) {
    if (!(await knex.schema.hasTable(table))) continue;
    await knex.raw(`ALTER TABLE ?? DROP CONSTRAINT IF EXISTS ??`, [table, `${table}_${POLICY_COL}_check`]);
    if (await knex.schema.hasColumn(table, POLICY_COL)) {
      await knex.schema.alterTable(table, (t) => t.dropColumn(POLICY_COL));
    }
  }
  // Enum values stay (dropping one needs a type rebuild; extra values are inert).
}
