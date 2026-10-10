import type { Knex } from 'knex';

// Device identity v2: agents move from a
// hardware-derived UUID to a shared random Obli* device ID. When a device row
// is re-keyed, its previous UUID is kept here so in-flight requests, ObliReach
// routing and cross-app (Obligate) links keep resolving it.
//
// `uuid` is NOT unique: a junk SMBIOS UUID shared by several machines can end
// up as an alias of each of them over time.
export async function up(knex: Knex): Promise<void> {
  await knex.schema.createTable('device_uuid_aliases', (t) => {
    t.increments('id').primary();
    t.integer('device_id').notNullable().references('id').inTable('devices').onDelete('CASCADE');
    t.integer('tenant_id').notNullable().references('id').inTable('tenants').onDelete('CASCADE');
    t.string('uuid', 64).notNullable();
    t.string('reason', 32).notNullable().defaultTo('migrated');
    t.timestamp('created_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());
    t.index(['uuid']);
    t.index(['device_id']);
  });

  // ObliReach agent: previous device_uuid after its own v2 switch, so the
  // device can be reached whichever agent (Obliance / ObliReach) moved first.
  await knex.schema.alterTable('oblireach_devices', (t) => {
    t.string('legacy_uuid', 64).nullable();
    t.index(['legacy_uuid']);
  });
}

export async function down(knex: Knex): Promise<void> {
  await knex.schema.alterTable('oblireach_devices', (t) => {
    t.dropIndex(['legacy_uuid']);
    t.dropColumn('legacy_uuid');
  });
  await knex.schema.dropTableIfExists('device_uuid_aliases');
}
