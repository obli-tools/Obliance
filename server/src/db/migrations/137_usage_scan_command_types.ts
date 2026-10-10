import { Knex } from 'knex';

// Disk usage analyzer of the file explorer (agent usage_scan.go): enum values.
//
//   command_type  'start_usage_scan'    — start (or join) a background scan of a folder
//                 'get_usage_children'  — read the live tree of a scan
//                 'get_usage_top_files' — the largest files of a scan
//                 'cancel_usage_scan'   — stop a scan
//
// The four commands are live FILE_EXPLORER_CMD commands (agentHub.push, no
// command_queue row) and POST /api/commands refuses them, but a missing enum
// value is a 500 the day one does reach the queue (see
// 117_sync_command_type_enum) — so they are registered anyway.
// Idempotent (pg_enum check), no transaction (ALTER TYPE ... ADD VALUE).

export const config = { transaction: false };

const VALUES = ['start_usage_scan', 'get_usage_children', 'get_usage_top_files', 'cancel_usage_scan'] as const;

async function ensureEnumValue(knex: Knex, typeName: string, value: string): Promise<void> {
  const exists = await knex.raw(
    `SELECT 1 FROM pg_enum e JOIN pg_type t ON e.enumtypid = t.oid WHERE t.typname = ? AND e.enumlabel = ? LIMIT 1`,
    [typeName, value],
  );
  if (!exists.rows || exists.rows.length === 0) {
    // Frozen constants above, never user input.
    await knex.raw(`ALTER TYPE ${typeName} ADD VALUE '${value}'`);
  }
}

export async function up(knex: Knex): Promise<void> {
  for (const v of VALUES) await ensureEnumValue(knex, 'command_type', v);
}

export async function down(_knex: Knex): Promise<void> {
  // Enum values cannot be dropped without rebuilding the type; extra values are inert.
}
