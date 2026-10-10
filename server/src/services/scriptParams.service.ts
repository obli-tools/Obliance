import { db } from '../db';
import { AppError } from '../middleware/errorHandler';
import {
  isSecretParameter,
  maskScriptParameterValues,
  normalizeScriptParameterDefinitions,
  resolveScriptParameterValues,
  SCRIPT_SECRET_MASK,
} from '@obliance/shared';
import type {
  ResolveOptions,
  ScriptParameterDef,
  ScriptParameterDefinitionInput,
  ScriptParameterValueError,
  ScriptParameterValues,
} from '@obliance/shared';
import { openJson, sealJson } from '../utils/secretBox';
import { scriptParameterDefinitionsSchema } from '../validators/scriptParameters.schema';

// ── Script parameters: server side ─────────────────────────────────────────
//
// Definitions live in script_parameters (ordered by sort_order). Every path
// that runs a script (manual run, schedules, scenario run_script nodes) goes
// through resolveOrThrow + runScriptParamPayload:
//
//  - values are validated / coerced against the definitions, defaults applied
//    (shared/src/scriptParameters.ts);
//  - the queued run_script payload carries the NON-secret values in clear
//    (`parameters`), the secret ones sealed (`secretParameters`, AES-GCM,
//    utils/secretBox.ts), plus `secretParameterNames` and `parameterOrder`
//    for the agent. The sealed values are opened only when the command is
//    handed to the agent (payloadForAgent, agentUpdateRollout
//    .claimPendingCommands — the one claim path of the HTTP push, the WS
//    heartbeat / drain and the HTTP poll) and purged from the row once the
//    command is finished (ack, expiry, cancel; hourly sweep as a backstop);
//  - history (script_executions.parameter_values) and audit get the masked
//    copy: a secret is SCRIPT_SECRET_MASK there.
//
// Raw run_script commands (POST /api/commands) carry whatever the caller
// sent: no definitions, nothing treated as secret (unchanged behaviour).

export const QUEUE_SECRET_PURPOSE = 'command_queue.run_script.secretParameters';
export const SCHEDULE_SECRET_PURPOSE = 'script_schedules.secret_parameter_values';

export type ParamDef = ScriptParameterDef & { id?: number; label?: string; description?: string | null; sortOrder?: number };

function parseOptions(v: unknown): string[] {
  if (Array.isArray(v)) return v.map(String);
  if (typeof v === 'string') { try { const p = JSON.parse(v); return Array.isArray(p) ? p.map(String) : []; } catch { return []; } }
  return [];
}

export function rowToParamDef(p: any): ParamDef {
  return {
    id: p.id,
    name: p.name,
    label: p.label,
    description: p.description ?? null,
    type: p.type,
    options: parseOptions(p.options),
    defaultValue: p.default_value ?? null,
    required: !!p.required,
    sortOrder: p.sort_order,
  };
}

/** Definitions of a script, in their order. UNSAFE without tenant scope:
 *  callers resolve the script within the caller's tenant first. */
export async function loadParameterDefs(scriptId: number): Promise<ParamDef[]> {
  const rows = await db('script_parameters').where({ script_id: scriptId }).orderBy('sort_order').orderBy('id');
  return rows.map(rowToParamDef);
}

export function parameterValuesError(errors: ScriptParameterValueError[]): AppError {
  const list = errors.map((e) => `${e.name || '(parameterValues)'}: ${e.code}`).join(', ');
  return new AppError(400, `Invalid parameter values — ${list}`, 'invalid_parameter_values', errors);
}

/** Validated, typed values (defaults applied) or a 400 AppError. */
export function resolveOrThrow(defs: readonly ParamDef[], values: unknown, opts?: ResolveOptions): ScriptParameterValues {
  const r = resolveScriptParameterValues(defs, values, opts);
  if (r.errors.length) throw parameterValuesError(r.errors);
  return r.values;
}

/** Normalized definitions for create / update, or a 400 AppError. */
export function normalizeDefinitionsOrThrow(input: unknown): ScriptParameterDefinitionInput[] {
  const shape = scriptParameterDefinitionsSchema.safeParse(input ?? []);
  if (!shape.success) {
    const details = shape.error.issues.map((i) => {
      const index = typeof i.path[0] === 'number' ? i.path[0] : -1;
      const raw = Array.isArray(input) && index >= 0 ? (input[index] as any) : null;
      return { index, name: typeof raw?.name === 'string' ? raw.name : '', code: (i.code === 'too_big' && i.path.length === 0 ? 'too_many' : 'invalid_type') as string };
    });
    throw new AppError(400, `Invalid script parameters — ${details.map((d) => `#${d.index}: ${d.code}`).join(', ')}`, 'invalid_parameters', details);
  }
  const r = normalizeScriptParameterDefinitions(input);
  if (r.errors.length) {
    const list = r.errors.map((e) => `#${e.index}${e.name ? ` ${e.name}` : ''}: ${e.code}`).join(', ');
    throw new AppError(400, `Invalid script parameters — ${list}`, 'invalid_parameters', r.errors);
  }
  return r.definitions;
}

/** Replace a script's definitions (array order = sort_order). */
export async function replaceParameterDefs(trx: any, scriptId: number, defs: ScriptParameterDefinitionInput[]): Promise<any[]> {
  await trx('script_parameters').where({ script_id: scriptId }).delete();
  if (!defs.length) return [];
  return trx('script_parameters').insert(defs.map((p, i) => ({
    script_id: scriptId,
    name: p.name,
    label: p.label,
    description: p.description,
    type: p.type,
    options: JSON.stringify(p.options ?? []),
    default_value: p.defaultValue,
    required: p.required,
    sort_order: i,
  }))).returning('*');
}

export interface RunScriptParamPayload {
  parameters: Record<string, unknown>;
  secretParameters?: string;
  secretParameterNames: string[];
  parameterOrder: string[];
}

/** The run_script payload fields + the masked copy for history / audit. */
export function runScriptParamPayload(defs: readonly ParamDef[], values: ScriptParameterValues): { payload: RunScriptParamPayload; masked: Record<string, unknown> } {
  const secretNames = new Set(defs.filter(isSecretParameter).map((d) => d.name));
  const plain: Record<string, unknown> = {};
  const secrets: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(values)) (secretNames.has(k) ? secrets : plain)[k] = v;
  const payload: RunScriptParamPayload = {
    parameters: plain,
    secretParameterNames: Object.keys(secrets),
    parameterOrder: defs.map((d) => d.name),
  };
  if (Object.keys(secrets).length) payload.secretParameters = sealJson(secrets, QUEUE_SECRET_PURPOSE);
  return { payload, masked: maskScriptParameterValues(defs, values) };
}

/**
 * The payload as handed to the agent: sealed secret values opened and merged
 * into `parameters`. `error` when they cannot be opened (server secret
 * rotated): the caller fails the command instead of running it without them.
 */
export function payloadForAgent(type: string, payload: unknown): { payload: any; error?: string } {
  if (type !== 'run_script') return { payload };
  let p: any = payload;
  if (typeof p === 'string') { try { p = JSON.parse(p); } catch { return { payload } } }
  if (!p || typeof p !== 'object' || typeof p.secretParameters !== 'string') return { payload: p };
  const { secretParameters, ...rest } = p;
  try {
    const secrets = openJson<Record<string, unknown>>(secretParameters, QUEUE_SECRET_PURPOSE);
    return { payload: { ...rest, parameters: { ...(rest.parameters ?? {}), ...secrets } } };
  } catch {
    return {
      payload: rest,
      error: 'The secret parameter values of this run could not be decrypted on the server (SCRIPT_PARAMS_SECRET / SESSION_SECRET changed?): the script was not run.',
    };
  }
}

/** Drop the sealed secret values of finished commands. */
export async function purgeQueuedSecrets(ids: readonly string[]): Promise<number> {
  const list = ids.filter(Boolean);
  if (!list.length) return 0;
  return db('command_queue')
    .whereIn('id', list as string[])
    .whereRaw(`jsonb_exists(payload, 'secretParameters')`)
    .update({ payload: db.raw(`payload - 'secretParameters'`) });
}

/** Backstop: every finished run_script still holding sealed values.
 *  Recent commands only: sealed values are cleared at ACK and only exist on
 *  commands created since the feature (migration 138); a command stays
 *  pending at most until its expiry. Without the date bound this opened the
 *  JSON payload of every row of command_queue (millions of rows on a large
 *  install: hours of disk reads); with it the (status, created_at) index
 *  serves the scan. */
const SECRET_SWEEP_WINDOW_DAYS = 30;
export async function purgeFinishedQueuedSecrets(): Promise<number> {
  return db('command_queue')
    .where({ type: 'run_script' })
    .where('created_at', '>', new Date(Date.now() - SECRET_SWEEP_WINDOW_DAYS * 86400_000))
    .whereIn('status', ['success', 'failure', 'timeout', 'cancelled'])
    .whereRaw(`jsonb_exists(payload, 'secretParameters')`)
    .update({ payload: db.raw(`payload - 'secretParameters'`) });
}

// ── Schedules: stored values ────────────────────────────────────────────────

export interface StoredScheduleSecrets { names: string[]; box: string }

export function parseStoredSecrets(col: unknown): StoredScheduleSecrets | null {
  let v: any = col;
  if (typeof v === 'string') { try { v = JSON.parse(v); } catch { return null; } }
  if (!v || typeof v !== 'object' || typeof v.box !== 'string' || !Array.isArray(v.names)) return null;
  return { names: v.names.map(String), box: v.box };
}

export function sealScheduleSecrets(secrets: Record<string, unknown>): StoredScheduleSecrets | null {
  const names = Object.keys(secrets);
  if (!names.length) return null;
  return { names, box: sealJson(secrets, SCHEDULE_SECRET_PURPOSE) };
}

/** Throws when the stored values cannot be opened. */
export function openScheduleSecrets(col: unknown): Record<string, unknown> {
  const s = parseStoredSecrets(col);
  if (!s) return {};
  return openJson<Record<string, unknown>>(s.box, SCHEDULE_SECRET_PURPOSE);
}

function parseJsonObject(v: unknown): Record<string, unknown> {
  if (typeof v === 'string') { try { v = JSON.parse(v); } catch { return {}; } }
  return v && typeof v === 'object' && !Array.isArray(v) ? v as Record<string, unknown> : {};
}

/**
 * What a schedule stores for `incoming` parameter values (create / PATCH).
 *  - non-secret values: replaced by the incoming ones (coerced; only the
 *    values actually given are stored — defaults apply at each run);
 *  - secret values: a new value replaces the stored one, omitted / '' /
 *    SCRIPT_SECRET_MASK keeps it, null clears it; sealed at rest.
 * `incoming` undefined = keep everything (re-checked against `defs`, e.g.
 * after a script change: values of parameters the script no longer has are
 * dropped). Throws a 400 AppError on invalid values.
 */
export function prepareScheduleValues(
  defs: readonly ParamDef[],
  incoming: unknown,
  existing: { parameterValues: unknown; secretCol: unknown } | null,
): { parameterValues: Record<string, unknown>; secretCol: StoredScheduleSecrets | null } {
  const secretDefs = new Set(defs.filter(isSecretParameter).map((d) => d.name));
  const known = new Set(defs.map((d) => d.name));
  const oldPlain = parseJsonObject(existing?.parameterValues);
  let oldSecrets: Record<string, unknown> = {};
  if (existing?.secretCol) {
    try { oldSecrets = openScheduleSecrets(existing.secretCol); } catch { oldSecrets = {}; }
  }
  const keepAll = incoming === undefined;
  if (!keepAll && (incoming === null || typeof incoming !== 'object' || Array.isArray(incoming))) {
    throw parameterValuesError([{ name: '', code: 'invalid_type' }]);
  }
  const src = keepAll ? { ...oldPlain } : { ...(incoming as Record<string, unknown>) };
  const kept: Record<string, unknown> = {};
  const input: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(src)) {
    if (keepAll && !known.has(k)) continue;
    if (secretDefs.has(k)) {
      if (v === null) continue; // cleared
      if (v === undefined || v === '' || v === SCRIPT_SECRET_MASK) {
        if (oldSecrets[k] !== undefined) kept[k] = oldSecrets[k];
        continue;
      }
    }
    input[k] = v;
  }
  // Secrets not mentioned at all are kept.
  for (const name of secretDefs) {
    if (!Object.prototype.hasOwnProperty.call(src, name) && oldSecrets[name] !== undefined) kept[name] = oldSecrets[name];
  }
  const r = resolveScriptParameterValues(defs, input, { provided: Object.keys(kept) });
  if (r.errors.length) throw parameterValuesError(r.errors);
  const parameterValues: Record<string, unknown> = {};
  const secrets: Record<string, unknown> = { ...kept };
  for (const k of Object.keys(input)) {
    if (r.values[k] === undefined) continue;
    if (secretDefs.has(k)) secrets[k] = r.values[k];
    else parameterValues[k] = r.values[k];
  }
  return { parameterValues, secretCol: sealScheduleSecrets(secrets) };
}

/** A schedule's values for one run: stored values + opened secrets,
 *  validated against the script's CURRENT definitions (unknown names dropped,
 *  defaults applied). `error` = do not run (message for the execution row). */
export function scheduleRunValues(
  defs: readonly ParamDef[],
  parameterValues: unknown,
  secretCol: unknown,
): { values: ScriptParameterValues; error?: string } {
  let secrets: Record<string, unknown> = {};
  try { secrets = openScheduleSecrets(secretCol); } catch {
    return { values: {}, error: 'The stored secret parameter values of this schedule could not be decrypted (SCRIPT_PARAMS_SECRET / SESSION_SECRET changed?): re-enter them in the schedule.' };
  }
  const r = resolveScriptParameterValues(defs, { ...parseJsonObject(parameterValues), ...secrets }, { dropUnknown: true });
  if (r.errors.length) {
    return { values: r.values, error: `Invalid parameter values for this schedule — ${r.errors.map((e) => `${e.name}: ${e.code}`).join(', ')}` };
  }
  return { values: r.values };
}

/** Parameter values safe for logs / audit: every value of every key replaced. */
export function redactAllValues(v: unknown): unknown {
  if (!v || typeof v !== 'object' || Array.isArray(v)) return v === undefined ? undefined : '[redacted]';
  return Object.fromEntries(Object.keys(v as Record<string, unknown>).map((k) => [k, '[redacted]']));
}
