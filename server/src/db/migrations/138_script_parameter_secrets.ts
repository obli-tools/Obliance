import type { Knex } from 'knex';
import { sealJson } from '../../utils/secretBox';

// Script parameters, secret values (scriptParams.service.ts):
//
//  - script_schedules.secret_parameter_values (jsonb, NULL = none):
//    { names: string[], box: "v1.<iv>.<tag>.<ct>" } — the values of the
//    schedule's 'secret' parameters, AES-256-GCM sealed (utils/secretBox.ts,
//    key derived from SCRIPT_PARAMS_SECRET / SESSION_SECRET, never in the
//    database). parameter_values keeps the non-secret ones only.
//
// Clean-up of what was stored in clear before (values of parameters declared
// 'secret'):
//  - a schedule's secret values move from parameter_values to the sealed
//    column (dropped if they cannot be sealed: re-entered in the schedule);
//  - history (script_executions.parameter_values) and the finished commands
//    linked to it (command_queue.payload.parameters): value → '••••'.
// Idempotent. down() drops the column (sealed values lost, by design).

const MASK = '••••';

function obj(v: unknown): Record<string, unknown> {
  if (typeof v === 'string') { try { v = JSON.parse(v); } catch { return {}; } }
  return v && typeof v === 'object' && !Array.isArray(v) ? { ...(v as Record<string, unknown>) } : {};
}

const has = (o: Record<string, unknown>, k: string) => Object.prototype.hasOwnProperty.call(o, k)
  && o[k] !== null && o[k] !== undefined && o[k] !== '' && o[k] !== MASK;

export async function up(knex: Knex): Promise<void> {
  if (!(await knex.schema.hasColumn('script_schedules', 'secret_parameter_values'))) {
    await knex.schema.alterTable('script_schedules', (t) => { t.jsonb('secret_parameter_values').nullable(); });
  }
  if (!(await knex.schema.hasTable('script_parameters'))) return;

  const secretRows = await knex('script_parameters').where({ type: 'secret' }).select('script_id', 'name') as Array<{ script_id: number; name: string }>;
  const secretsByScript = new Map<number, string[]>();
  for (const r of secretRows) secretsByScript.set(r.script_id, [...(secretsByScript.get(r.script_id) ?? []), r.name]);
  if (!secretsByScript.size) return;
  const scriptIds = [...secretsByScript.keys()];

  // Schedules: clear values → sealed column.
  const schedules = await knex('script_schedules').whereIn('script_id', scriptIds)
    .select('id', 'script_id', 'parameter_values', 'secret_parameter_values');
  for (const s of schedules) {
    const plain = obj(s.parameter_values);
    const names = secretsByScript.get(s.script_id) ?? [];
    const moved: Record<string, unknown> = {};
    for (const n of names) {
      if (has(plain, n)) moved[n] = plain[n];
      delete plain[n];
    }
    if (!Object.keys(moved).length && Object.keys(plain).length === Object.keys(obj(s.parameter_values)).length) continue;
    let sealed: string | null = null;
    if (Object.keys(moved).length && !s.secret_parameter_values) {
      try {
        sealed = JSON.stringify({ names: Object.keys(moved), box: sealJson(moved, 'script_schedules.secret_parameter_values') });
      } catch { sealed = null; /* no key: the values are dropped, re-entered in the schedule */ }
    }
    await knex('script_schedules').where({ id: s.id }).update({
      parameter_values: JSON.stringify(plain),
      ...(sealed ? { secret_parameter_values: sealed } : {}),
    });
  }

  // History + the finished commands it links to.
  const execs = await knex('script_executions').whereIn('script_id', scriptIds)
    .select('id', 'script_id', 'parameter_values', 'command_queue_id');
  for (const e of execs) {
    const names = secretsByScript.get(e.script_id) ?? [];
    const pv = obj(e.parameter_values);
    let changed = false;
    for (const n of names) if (has(pv, n)) { pv[n] = MASK; changed = true; }
    if (changed) await knex('script_executions').where({ id: e.id }).update({ parameter_values: JSON.stringify(pv) });
    if (!e.command_queue_id) continue;
    const cmd = await knex('command_queue').where({ id: e.command_queue_id })
      .whereIn('status', ['success', 'failure', 'timeout', 'cancelled']).first('id', 'payload');
    if (!cmd) continue;
    const payload = obj(cmd.payload);
    const params = obj(payload.parameters);
    let cChanged = false;
    for (const n of names) if (has(params, n)) { params[n] = MASK; cChanged = true; }
    if (cChanged) await knex('command_queue').where({ id: cmd.id }).update({ payload: JSON.stringify({ ...payload, parameters: params }) });
  }
}

export async function down(knex: Knex): Promise<void> {
  if (await knex.schema.hasColumn('script_schedules', 'secret_parameter_values')) {
    await knex.schema.alterTable('script_schedules', (t) => { t.dropColumn('secret_parameter_values'); });
  }
}
