// ─── Script parameters: definitions, run-time values, secrets ────────────────
//
// Pure helpers shared by the server (validation of POST /api/scripts and
// /api/scripts/:id/execute, schedules, scenario run_script nodes) and the web
// client (parameter editor, run forms, "Detect from script"). No dependency.
//
// Contract (also implemented by Oblireach Desktop):
//  - A script declares ordered parameters (Script.parameters, sortOrder).
//    Names match SCRIPT_PARAM_NAME_RE and are unique per script, compared
//    case-insensitively (they become environment variables
//    OBLI_PARAM_<UPPERCASE NAME> on the device).
//  - A run sends `parameterValues: Record<name, string|number|boolean|string[]>`.
//    The server coerces each value to its declared type, applies the default of
//    a missing optional value, refuses unknown names / missing required values /
//    values outside the options:
//      400 { error, details: [{ name, code }] }   (codes: ScriptParameterValueErrorCode)
//  - 'secret' values are never stored nor shown in clear: SCRIPT_SECRET_MASK
//    stands for them in every API response, history and audit row.

import type { ScriptParameter, ScriptParameterType } from './types';

export const SCRIPT_PARAMETER_TYPES: readonly ScriptParameterType[] = Object.freeze(
  ['string', 'number', 'boolean', 'secret', 'select', 'multiselect'] as ScriptParameterType[],
);

/** Parameter name: a PowerShell / shell / environment-friendly identifier. */
export const SCRIPT_PARAM_NAME_RE = /^[A-Za-z_][A-Za-z0-9_]{0,63}$/;

/** Shown (and stored in history / audit) in place of a secret value. */
export const SCRIPT_SECRET_MASK = '••••';

export const SCRIPT_PARAM_LIMITS = Object.freeze({
  maxParameters: 50,
  maxLabel: 200,
  maxDescription: 2000,
  maxOptions: 200,
  maxOption: 200,
  /** Longest value (characters) of a string / secret parameter. */
  maxValue: 32768,
});

export type ScriptParameterValue = string | number | boolean | string[];
export type ScriptParameterValues = Record<string, ScriptParameterValue>;

export type ScriptParameterValueErrorCode =
  | 'unknown'         // no parameter of that name on the script
  | 'required'        // required, no value and no default
  | 'invalid_type'    // wrong JSON type (object, array for a scalar...) / not a boolean
  | 'invalid_number'  // not a finite number
  | 'invalid_option'  // select / multiselect value outside the options
  | 'too_long';       // string / secret longer than SCRIPT_PARAM_LIMITS.maxValue

export interface ScriptParameterValueError {
  name: string;
  code: ScriptParameterValueErrorCode;
}

export type ScriptParameterDefinitionErrorCode =
  | 'invalid_name'
  | 'duplicate_name'
  | 'invalid_type'
  | 'options_required'
  | 'invalid_options'
  | 'invalid_default'
  | 'secret_default'
  | 'too_long'
  | 'too_many';

export interface ScriptParameterDefinitionError {
  index: number;
  name: string;
  code: ScriptParameterDefinitionErrorCode;
}

/** What a script editor sends for one parameter (order = array order). */
export interface ScriptParameterDefinitionInput {
  name: string;
  label: string;
  description: string | null;
  type: ScriptParameterType;
  options: string[];
  defaultValue: string | null;
  required: boolean;
}

/** The part of a definition the value helpers need. */
export type ScriptParameterDef = Pick<ScriptParameter, 'name' | 'type' | 'options' | 'defaultValue' | 'required'>;

export function isSecretParameter(def: { type: string }): boolean {
  return def.type === 'secret';
}

/** Environment variable that carries a parameter on the device. */
export function scriptParameterEnvName(name: string): string {
  return 'OBLI_PARAM_' + name.toUpperCase();
}

// ── Values ───────────────────────────────────────────────────────────────────

const NUMBER_RE = /^[+-]?(\d+\.?\d*|\.\d+)([eE][+-]?\d+)?$/;
const TRUE_WORDS = new Set(['true', '1', 'yes', 'on', 'y']);
const FALSE_WORDS = new Set(['false', '0', 'no', 'off', 'n']);

function isMissing(v: unknown): boolean {
  return v === undefined || v === null || v === '' || (Array.isArray(v) && v.length === 0);
}

type Coerced = { ok: true; value: ScriptParameterValue } | { ok: false; code: ScriptParameterValueErrorCode };

/** Coerce one present (non-missing) raw value to the declared type. */
export function coerceScriptParameterValue(def: Pick<ScriptParameterDef, 'type' | 'options'>, raw: unknown): Coerced {
  const options = Array.isArray(def.options) ? def.options : [];
  switch (def.type) {
    case 'number': {
      if (typeof raw === 'number') return Number.isFinite(raw) ? { ok: true, value: raw } : { ok: false, code: 'invalid_number' };
      if (typeof raw === 'string' && NUMBER_RE.test(raw.trim())) {
        const n = Number(raw.trim());
        return Number.isFinite(n) ? { ok: true, value: n } : { ok: false, code: 'invalid_number' };
      }
      return { ok: false, code: typeof raw === 'string' ? 'invalid_number' : 'invalid_type' };
    }
    case 'boolean': {
      if (typeof raw === 'boolean') return { ok: true, value: raw };
      if (raw === 1 || raw === 0) return { ok: true, value: raw === 1 };
      if (typeof raw === 'string') {
        const w = raw.trim().toLowerCase();
        if (TRUE_WORDS.has(w)) return { ok: true, value: true };
        if (FALSE_WORDS.has(w)) return { ok: true, value: false };
      }
      return { ok: false, code: 'invalid_type' };
    }
    case 'select': {
      const s = typeof raw === 'string' ? raw : typeof raw === 'number' ? String(raw) : null;
      if (s === null) return { ok: false, code: 'invalid_type' };
      return options.includes(s) ? { ok: true, value: s } : { ok: false, code: 'invalid_option' };
    }
    case 'multiselect': {
      const arr = Array.isArray(raw) ? raw : (typeof raw === 'string' ? [raw] : null);
      if (!arr) return { ok: false, code: 'invalid_type' };
      const out: string[] = [];
      for (const x of arr) {
        if (typeof x !== 'string') return { ok: false, code: 'invalid_type' };
        if (!options.includes(x)) return { ok: false, code: 'invalid_option' };
        if (!out.includes(x)) out.push(x);
      }
      return { ok: true, value: out };
    }
    case 'secret':
    case 'string':
    default: {
      let s: string;
      if (typeof raw === 'string') s = raw;
      else if ((typeof raw === 'number' && Number.isFinite(raw)) || (typeof raw === 'boolean' && def.type !== 'secret')) s = String(raw);
      else return { ok: false, code: 'invalid_type' };
      if (s.length > SCRIPT_PARAM_LIMITS.maxValue) return { ok: false, code: 'too_long' };
      return { ok: true, value: s };
    }
  }
}

/** The typed default of a definition (undefined: none / not usable). Secrets never have one. */
export function parseScriptParameterDefault(def: ScriptParameterDef): ScriptParameterValue | undefined {
  if (isSecretParameter(def)) return undefined;
  const d = def.defaultValue;
  if (d === null || d === undefined || d === '') return undefined;
  let raw: unknown = d;
  if (def.type === 'multiselect') {
    const t = String(d).trim();
    if (t.startsWith('[')) {
      try { raw = JSON.parse(t); } catch { return undefined; }
    } else {
      raw = t.split(',').map((x) => x.trim()).filter(Boolean);
    }
  }
  const c = coerceScriptParameterValue(def, raw);
  return c.ok && !isMissing(c.value) ? c.value : undefined;
}

export interface ResolveOptions {
  /** Apply the default of a missing optional value (default true). */
  applyDefaults?: boolean;
  /** Ignore values of unknown names instead of refusing them (stored values
   *  whose script changed since: schedules). Default false. */
  dropUnknown?: boolean;
  /** Names to consider provided although absent from `values` (a schedule's
   *  stored secret kept as is). */
  provided?: readonly string[];
  /** Do not report missing required values (saving a draft). Default false. */
  skipRequired?: boolean;
}

/**
 * Validate and coerce run-time values against the definitions (order of the
 * definitions). Returns the typed values (defaults applied) and the errors;
 * the run must be refused when `errors` is not empty.
 */
export function resolveScriptParameterValues(
  defs: readonly ScriptParameterDef[],
  values: unknown,
  opts: ResolveOptions = {},
): { values: ScriptParameterValues; errors: ScriptParameterValueError[] } {
  const out: ScriptParameterValues = {};
  const errors: ScriptParameterValueError[] = [];
  if (values !== undefined && values !== null && (typeof values !== 'object' || Array.isArray(values))) {
    return { values: out, errors: [{ name: '', code: 'invalid_type' }] };
  }
  const src = (values ?? {}) as Record<string, unknown>;
  const byName = new Map<string, ScriptParameterDef>();
  for (const d of defs) byName.set(d.name, d);
  if (!opts.dropUnknown) {
    for (const k of Object.keys(src)) if (!byName.has(k)) errors.push({ name: k, code: 'unknown' });
  }
  const provided = new Set(opts.provided ?? []);
  for (const d of defs) {
    const raw = Object.prototype.hasOwnProperty.call(src, d.name) ? src[d.name] : undefined;
    if (!isMissing(raw)) {
      const c = coerceScriptParameterValue(d, raw);
      if (!c.ok) { errors.push({ name: d.name, code: c.code }); continue; }
      if (!isMissing(c.value)) { out[d.name] = c.value; continue; }
    }
    if (provided.has(d.name)) continue;
    if (opts.applyDefaults !== false) {
      const def = parseScriptParameterDefault(d);
      if (def !== undefined) { out[d.name] = def; continue; }
    }
    if (d.required && !opts.skipRequired) errors.push({ name: d.name, code: 'required' });
  }
  return { values: out, errors };
}

/** Copy of the values with every secret replaced by SCRIPT_SECRET_MASK
 *  (history, audit, API responses). Unknown names are kept as given. */
export function maskScriptParameterValues(
  defs: readonly Pick<ScriptParameterDef, 'name' | 'type'>[],
  values: Record<string, unknown> | null | undefined,
): Record<string, unknown> {
  const secret = new Set(defs.filter(isSecretParameter).map((d) => d.name));
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(values ?? {})) out[k] = secret.has(k) && !isMissing(v) ? SCRIPT_SECRET_MASK : v;
  return out;
}

/** One value as text (history, summaries). */
export function formatScriptParameterValue(v: unknown): string {
  if (Array.isArray(v)) return v.map((x) => String(x)).join(', ');
  if (v === null || v === undefined) return '';
  return String(v);
}

// ── Definitions ─────────────────────────────────────────────────────────────

/**
 * Normalize + validate the definitions a script editor sends (create /
 * update). Labels default to the name, options are trimmed and de-duplicated
 * (kept only for select / multiselect), '' defaults become null, a
 * multiselect default is stored as a JSON array.
 */
export function normalizeScriptParameterDefinitions(input: unknown): {
  definitions: ScriptParameterDefinitionInput[];
  errors: ScriptParameterDefinitionError[];
} {
  const definitions: ScriptParameterDefinitionInput[] = [];
  const errors: ScriptParameterDefinitionError[] = [];
  if (input === undefined || input === null) return { definitions, errors };
  if (!Array.isArray(input)) return { definitions, errors: [{ index: -1, name: '', code: 'invalid_type' }] };
  if (input.length > SCRIPT_PARAM_LIMITS.maxParameters) errors.push({ index: -1, name: '', code: 'too_many' });
  const seen = new Set<string>();
  input.forEach((raw, index) => {
    const p = (raw && typeof raw === 'object' ? raw : {}) as Record<string, unknown>;
    const name = typeof p.name === 'string' ? p.name.trim() : '';
    const err = (code: ScriptParameterDefinitionErrorCode) => errors.push({ index, name, code });
    if (!SCRIPT_PARAM_NAME_RE.test(name)) err('invalid_name');
    else if (seen.has(name.toLowerCase())) err('duplicate_name');
    seen.add(name.toLowerCase());
    const type = SCRIPT_PARAMETER_TYPES.includes(p.type as ScriptParameterType) ? p.type as ScriptParameterType : null;
    if (!type) { err('invalid_type'); return; }
    const label = (typeof p.label === 'string' && p.label.trim()) ? p.label.trim() : name;
    const description = typeof p.description === 'string' && p.description.trim() ? p.description.trim() : null;
    if (label.length > SCRIPT_PARAM_LIMITS.maxLabel || (description && description.length > SCRIPT_PARAM_LIMITS.maxDescription)) err('too_long');
    let options: string[] = [];
    if (type === 'select' || type === 'multiselect') {
      if (p.options !== undefined && p.options !== null && !Array.isArray(p.options)) err('invalid_options');
      const list = Array.isArray(p.options) ? p.options : [];
      for (const o of list) {
        if (typeof o !== 'string' && typeof o !== 'number') { err('invalid_options'); continue; }
        const s = String(o).trim();
        if (!s) continue;
        if (s.length > SCRIPT_PARAM_LIMITS.maxOption) { err('too_long'); continue; }
        if (!options.includes(s)) options.push(s);
      }
      if (options.length > SCRIPT_PARAM_LIMITS.maxOptions) err('invalid_options');
      if (options.length === 0) err('options_required');
    }
    const required = p.required === true;
    let defaultValue: string | null = null;
    const rawDefault = p.defaultValue;
    const hasDefault = !isMissing(rawDefault);
    if (hasDefault && type === 'secret') err('secret_default');
    else if (hasDefault) {
      const asRaw = type === 'multiselect' && typeof rawDefault === 'string'
        ? (rawDefault.trim().startsWith('[') ? safeJson(rawDefault) : rawDefault.split(',').map((x) => x.trim()).filter(Boolean))
        : rawDefault;
      const c = coerceScriptParameterValue({ type, options }, asRaw);
      if (!c.ok) err('invalid_default');
      else defaultValue = Array.isArray(c.value) ? JSON.stringify(c.value) : String(c.value);
    }
    definitions.push({ name, label, description, type, options, defaultValue, required });
  });
  return { definitions, errors };
}

function safeJson(s: string): unknown {
  try { return JSON.parse(s); } catch { return null; }
}

// ── "Detect from script" ─────────────────────────────────────────────────────

/**
 * Pre-fill definitions from a script: the PowerShell `param(...)` block
 * (SecureString → secret, switch / bool → boolean, int / double… → number,
 * ValidateSet → select (multiselect for an array type), Mandatory → required,
 * literal defaults, HelpMessage → description) then every `{{PARAM_name}}`
 * placeholder not declared there (string). Best effort, never throws.
 */
export function detectScriptParameters(content: string, runtime?: string): ScriptParameterDefinitionInput[] {
  const out: ScriptParameterDefinitionInput[] = [];
  const has = (n: string) => out.some((p) => p.name.toLowerCase() === n.toLowerCase());
  try {
    if (!runtime || runtime === 'powershell' || runtime === 'pwsh') {
      for (const p of detectPowerShellParamBlock(content)) if (!has(p.name)) out.push(p);
    }
  } catch { /* best effort */ }
  const re = /\{\{PARAM_([A-Za-z_][A-Za-z0-9_]{0,63})\}\}/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(content)) !== null) {
    if (!has(m[1])) out.push({ name: m[1], label: m[1], description: null, type: 'string', options: [], defaultValue: null, required: false });
  }
  return out;
}

/** Skip whitespace and comments from `i`; returns the next significant index. */
function psSkip(s: string, i: number): number {
  for (;;) {
    while (i < s.length && /\s/.test(s[i])) i++;
    if (s.startsWith('<#', i)) { const e = s.indexOf('#>', i + 2); if (e < 0) return s.length; i = e + 2; continue; }
    if (s[i] === '#') { const e = s.indexOf('\n', i); if (e < 0) return s.length; i = e + 1; continue; }
    return i;
  }
}

/** Index just after the bracket that closes the one at `open` (quotes and comments aware). */
function psMatch(s: string, open: number): number {
  const pairs: Record<string, string> = { '(': ')', '[': ']', '{': '}' };
  const stack: string[] = [];
  let i = open;
  while (i < s.length) {
    const c = s[i];
    if (c === "'") { i++; while (i < s.length) { if (s[i] === "'") { if (s[i + 1] === "'") { i += 2; continue; } break; } i++; } i++; continue; }
    if (c === '"') { i++; while (i < s.length && s[i] !== '"') { if (s[i] === '`') i++; i++; } i++; continue; }
    if (s.startsWith('<#', i)) { const e = s.indexOf('#>', i + 2); i = e < 0 ? s.length : e + 2; continue; }
    if (c === '#') { const e = s.indexOf('\n', i); i = e < 0 ? s.length : e + 1; continue; }
    if (pairs[c]) stack.push(pairs[c]);
    else if (c === ')' || c === ']' || c === '}') {
      if (stack.pop() !== c) return -1;
      if (stack.length === 0) return i + 1;
    }
    i++;
  }
  return -1;
}

/** Split `s` on top-level commas. */
function psSplitTop(s: string): string[] {
  const parts: string[] = [];
  let start = 0;
  let i = 0;
  while (i < s.length) {
    const c = s[i];
    if (c === '(' || c === '[' || c === '{' || c === "'" || c === '"' || c === '#' || s.startsWith('<#', i)) {
      if (c === "'" || c === '"' || c === '#' || s.startsWith('<#', i)) {
        // reuse psMatch semantics by wrapping: skip a quoted string / comment
        if (c === "'") { i++; while (i < s.length) { if (s[i] === "'") { if (s[i + 1] === "'") { i += 2; continue; } break; } i++; } i++; continue; }
        if (c === '"') { i++; while (i < s.length && s[i] !== '"') { if (s[i] === '`') i++; i++; } i++; continue; }
        if (s.startsWith('<#', i)) { const e = s.indexOf('#>', i + 2); i = e < 0 ? s.length : e + 2; continue; }
        const e = s.indexOf('\n', i); i = e < 0 ? s.length : e + 1; continue;
      }
      const e = psMatch(s, i);
      i = e < 0 ? s.length : e;
      continue;
    }
    if (c === ',') { parts.push(s.slice(start, i)); start = i + 1; }
    i++;
  }
  parts.push(s.slice(start));
  return parts.map((p) => p.trim()).filter(Boolean);
}

function psLiteral(expr: string): string | null {
  const t = expr.trim();
  if (/^'(?:[^']|'')*'$/.test(t)) return t.slice(1, -1).replace(/''/g, "'");
  if (/^"[^"`$]*"$/.test(t)) return t.slice(1, -1);
  if (/^\$true$/i.test(t)) return 'true';
  if (/^\$false$/i.test(t)) return 'false';
  if (NUMBER_RE.test(t)) return t;
  return null;
}

function psStringList(args: string): string[] {
  return psSplitTop(args).map(psLiteral).filter((x): x is string => x !== null && x !== '');
}

const PS_NUMBER_TYPES = new Set(['int', 'int16', 'int32', 'int64', 'long', 'short', 'byte', 'sbyte', 'uint16', 'uint32', 'uint64',
  'double', 'float', 'single', 'decimal', 'system.int32', 'system.int64', 'system.double', 'system.decimal']);

function detectPowerShellParamBlock(content: string): ScriptParameterDefinitionInput[] {
  const s = content.replace(/^﻿/, '');
  let i = psSkip(s, 0);
  // Leading attributes ([CmdletBinding()], [OutputType(...)]) before param(
  while (s[i] === '[') {
    const e = psMatch(s, i);
    if (e < 0) return [];
    i = psSkip(s, e);
  }
  if (!/^param\s*\(/i.test(s.slice(i, i + 64))) return [];
  const open = s.indexOf('(', i);
  const close = psMatch(s, open);
  if (close < 0) return [];
  const body = s.slice(open + 1, close - 1);
  const out: ScriptParameterDefinitionInput[] = [];
  for (const decl of psSplitTop(body)) {
    let j = psSkip(decl, 0);
    let type = '';
    let required = false;
    let validateSet: string[] | null = null;
    let help: string | null = null;
    while (decl[j] === '[') {
      const e = psMatch(decl, j);
      if (e < 0) break;
      const inner = decl.slice(j + 1, e - 1).trim();
      const am = /^([A-Za-z_][\w.]*)\s*\(([\s\S]*)\)$/.exec(inner);
      if (am) {
        const attr = am[1].toLowerCase();
        if (attr === 'parameter' || attr === 'system.management.automation.parameter') {
          for (const arg of psSplitTop(am[2])) {
            const kv = /^(\w+)\s*(?:=\s*([\s\S]+))?$/.exec(arg);
            if (!kv) continue;
            const k = kv[1].toLowerCase();
            if (k === 'mandatory') required = kv[2] === undefined || /^\$true$/i.test(kv[2].trim());
            if (k === 'helpmessage' && kv[2]) help = psLiteral(kv[2]);
          }
        } else if (attr === 'validateset') {
          validateSet = psStringList(am[2]);
        }
      } else if (!/\(/.test(inner)) {
        type = inner.toLowerCase(); // a type constraint such as [SecureString] or [string[]]
      }
      j = psSkip(decl, e);
    }
    const vm = /^\$([A-Za-z_][A-Za-z0-9_]*)\s*(?:=\s*([\s\S]+))?$/.exec(decl.slice(j).trim());
    if (!vm) continue;
    const name = vm[1];
    if (!SCRIPT_PARAM_NAME_RE.test(name)) continue;
    const isArray = type.endsWith('[]');
    const base = type.replace(/\[\]$/, '').replace(/^system\.management\.automation\./, '').replace(/^system\.security\./, '');
    let ptype: ScriptParameterType = 'string';
    let options: string[] = [];
    if (base === 'securestring') ptype = 'secret';
    else if (base === 'switch' || base === 'switchparameter' || base === 'bool' || base === 'boolean' || base === 'system.boolean') ptype = 'boolean';
    else if (PS_NUMBER_TYPES.has(base)) ptype = 'number';
    if (validateSet && validateSet.length && ptype !== 'secret' && ptype !== 'boolean') {
      ptype = isArray ? 'multiselect' : 'select';
      options = validateSet;
    }
    let defaultValue: string | null = null;
    if (vm[2] !== undefined && ptype !== 'secret') {
      const lit = psLiteral(vm[2]);
      if (lit !== null) {
        const n = normalizeScriptParameterDefinitions([{ name, type: ptype, options, defaultValue: lit }]);
        if (!n.errors.length) defaultValue = n.definitions[0].defaultValue;
      }
    }
    // A switch is never "required" in practice (absent = $false).
    if (base === 'switch' || base === 'switchparameter') required = false;
    out.push({ name, label: name, description: help, type: ptype, options, defaultValue, required });
  }
  return out;
}
