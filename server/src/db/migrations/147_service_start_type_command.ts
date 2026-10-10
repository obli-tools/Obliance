import { Knex } from 'knex';

// Services tab: change a service's start type (agent service_start_type.go,
// 4.5.103+).
//
//   command_type  'set_service_start_type'  — payload {name, startType:
//                 'auto' | 'auto_delayed' | 'manual' | 'disabled'}
//
// A missing enum value is a 500 (SQLSTATE 22P02) on the INSERT into
// command_queue — see 117_sync_command_type_enum.
// Idempotent (pg_enum check), no transaction (ALTER TYPE ... ADD VALUE).

export const config = { transaction: false };

const VALUES = ['set_service_start_type'] as const;

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
