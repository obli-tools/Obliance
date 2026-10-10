import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import type { TFunction } from 'i18next';
import { Eye, EyeOff, X } from 'lucide-react';
import { clsx } from 'clsx';
import {
  isSecretParameter,
  parseScriptParameterDefault,
  resolveScriptParameterValues,
  SCRIPT_SECRET_MASK,
  formatScriptParameterValue,
} from '@obliance/shared';
import type {
  ScriptParameter,
  ScriptParameterValueErrorCode,
  ScriptParameterValues,
} from '@obliance/shared';
import { ToggleSwitch } from '@/components/common/ToggleSwitch';

/** What the run / schedule forms need of a definition. */
export type ScriptParameterFormDef = Pick<ScriptParameter, 'name' | 'label' | 'description' | 'type' | 'options' | 'defaultValue' | 'required'>;

/** Raw form state: strings for text / number / secret / select, boolean, string[]. */
export type ScriptParameterFormValue = string | boolean | string[];
export type ScriptParameterFormValues = Record<string, ScriptParameterFormValue>;
export type ScriptParameterFieldErrors = Record<string, ScriptParameterValueErrorCode | string>;

/** Initial form values: `existing` (a schedule's stored values) else the defaults. */
export function initialScriptParameterFormValues(
  defs: readonly ScriptParameterFormDef[],
  existing?: Record<string, unknown> | null,
): ScriptParameterFormValues {
  const out: ScriptParameterFormValues = {};
  for (const d of defs) {
    const has = existing && Object.prototype.hasOwnProperty.call(existing, d.name) && existing[d.name] !== null && existing[d.name] !== undefined;
    const v: unknown = has ? existing![d.name] : (existing ? undefined : parseScriptParameterDefault(d));
    if (d.type === 'boolean') {
      const def = parseScriptParameterDefault(d);
      out[d.name] = has ? (v === true || v === 'true' || v === 1 || v === '1') : def === true;
    } else if (d.type === 'multiselect') {
      out[d.name] = Array.isArray(v) ? v.map(String) : (typeof v === 'string' && v ? [v] : []);
    } else if (isSecretParameter(d)) {
      out[d.name] = '';
    } else {
      out[d.name] = v === undefined || v === null ? '' : String(v);
    }
  }
  return out;
}

/** Form values → the request's raw parameterValues ('' / [] left out). */
export function scriptParameterFormToRaw(
  defs: readonly ScriptParameterFormDef[],
  values: ScriptParameterFormValues,
): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const d of defs) {
    const v = values[d.name];
    if (v === undefined) continue;
    if (typeof v === 'boolean') { out[d.name] = v; continue; }
    if (Array.isArray(v)) { if (v.length) out[d.name] = v; continue; }
    if (v === '') continue;
    out[d.name] = v;
  }
  return out;
}

/**
 * Validate the form for a RUN: typed values with defaults applied, or the
 * per-field errors (same rules as the server).
 */
export function validateScriptParameterForm(
  defs: readonly ScriptParameterFormDef[],
  values: ScriptParameterFormValues,
  opts: { provided?: string[]; applyDefaults?: boolean } = {},
): { values: ScriptParameterValues; errors: ScriptParameterFieldErrors } {
  const r = resolveScriptParameterValues(defs, scriptParameterFormToRaw(defs, values), {
    provided: opts.provided,
    applyDefaults: opts.applyDefaults,
  });
  const errors: ScriptParameterFieldErrors = {};
  for (const e of r.errors) errors[e.name] = e.code;
  return { values: r.values, errors };
}

/** Server 400 `{ code: 'invalid_parameter_values', details: [{ name, code }] }` → field errors, or null. */
export function scriptParameterErrorsFromApi(err: unknown): ScriptParameterFieldErrors | null {
  const data = (err as { response?: { status?: number; data?: { code?: string; details?: unknown } } })?.response;
  if (data?.status !== 400 || !Array.isArray(data.data?.details)) return null;
  const out: ScriptParameterFieldErrors = {};
  for (const d of data.data!.details as Array<{ name?: unknown; code?: unknown }>) {
    if (d && typeof d.code === 'string') out[typeof d.name === 'string' ? d.name : ''] = d.code;
  }
  return Object.keys(out).length ? out : null;
}

/** User-facing message of a value error code. */
export function scriptParameterValueErrorText(t: TFunction, code: string, name?: string): string {
  switch (code) {
    case 'required': return t('scriptParams.valueError.required', 'A value is required');
    case 'invalid_number': return t('scriptParams.valueError.invalid_number', 'Enter a valid number');
    case 'invalid_option': return t('scriptParams.valueError.invalid_option', 'This value is not one of the allowed options');
    case 'invalid_type': return t('scriptParams.valueError.invalid_type', 'Invalid value');
    case 'too_long': return t('scriptParams.valueError.too_long', 'Value too long');
    case 'unknown': return t('scriptParams.valueError.unknown', { name: name ?? '', defaultValue: 'Unknown parameter "{{name}}"' });
    default: return t('scriptParams.valueError.invalid_type', 'Invalid value');
  }
}

function defaultHint(d: ScriptParameterFormDef): string | undefined {
  const v = parseScriptParameterDefault(d);
  return v === undefined ? undefined : String(v);
}

const inputCls = 'w-full px-3 py-2 text-sm bg-bg-tertiary rounded-lg text-text-primary focus:outline-none focus:ring-1 focus:ring-accent';

function SecretInput({ id, value, onChange, placeholder, invalid }: {
  id: string; value: string; onChange: (v: string) => void; placeholder?: string; invalid?: boolean;
}) {
  const { t } = useTranslation();
  const [reveal, setReveal] = useState(false);
  return (
    <div className="relative">
      <input
        id={id}
        type={reveal ? 'text' : 'password'}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        autoComplete="new-password"
        autoCapitalize="off"
        autoCorrect="off"
        spellCheck={false}
        placeholder={placeholder}
        aria-invalid={invalid || undefined}
        className={clsx(inputCls, 'pr-10', invalid && 'ring-1 ring-red-500')}
      />
      <button
        type="button"
        onClick={() => setReveal((r) => !r)}
        className="absolute inset-y-0 right-0 flex items-center justify-center w-10 text-text-muted hover:text-text-primary"
        aria-label={reveal ? t('scriptParams.hideValue', 'Hide value') : t('scriptParams.showValue', 'Show value')}
        title={reveal ? t('scriptParams.hideValue', 'Hide value') : t('scriptParams.showValue', 'Show value')}
      >
        {reveal ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
      </button>
    </div>
  );
}

interface FormProps {
  definitions: readonly ScriptParameterFormDef[];
  values: ScriptParameterFormValues;
  onChange: (next: ScriptParameterFormValues) => void;
  errors?: ScriptParameterFieldErrors;
  /** Secrets with a stored value (schedule edit): blank = keep it. */
  storedSecretNames?: string[];
  /** Stored secrets the user asked to clear (sent as null). */
  clearedSecrets?: string[];
  onClearedSecretsChange?: (next: string[]) => void;
  idPrefix?: string;
}

/** Form generated from a script's parameter definitions. */
export function ScriptParameterForm({
  definitions, values, onChange, errors = {}, storedSecretNames = [], clearedSecrets = [], onClearedSecretsChange, idPrefix = 'sp',
}: FormProps) {
  const { t } = useTranslation();
  const set = (name: string, v: ScriptParameterFormValue) => onChange({ ...values, [name]: v });
  const general = errors[''];
  return (
    <div className="space-y-3">
      {definitions.map((d) => {
        const id = `${idPrefix}-${d.name}`;
        const err = errors[d.name];
        const v = values[d.name];
        const stored = isSecretParameter(d) && storedSecretNames.includes(d.name);
        const cleared = clearedSecrets.includes(d.name);
        const label = (
          <label htmlFor={id} className="text-xs font-medium text-text-muted">
            {d.label || d.name}
            {d.required && <span className="text-red-400 ml-0.5" aria-hidden>*</span>}
            {d.label && d.label !== d.name && <span className="ml-1.5 font-mono text-[10px] text-text-muted/70">{d.name}</span>}
          </label>
        );
        let control: React.ReactNode;
        switch (d.type) {
          case 'boolean':
            control = (
              <ToggleSwitch
                checked={v === true}
                onChange={(next) => set(d.name, next)}
                label={<span className="text-sm text-text-primary">{d.label || d.name}{d.required && <span className="text-red-400 ml-0.5" aria-hidden>*</span>}</span>}
              />
            );
            break;
          case 'number':
            control = (
              <input id={id} type="number" inputMode="decimal" step="any" value={typeof v === 'string' ? v : ''}
                onChange={(e) => set(d.name, e.target.value)} aria-invalid={!!err || undefined}
                placeholder={defaultHint(d)} className={clsx(inputCls, err && 'ring-1 ring-red-500')} />
            );
            break;
          case 'select':
            control = (
              <select id={id} value={typeof v === 'string' ? v : ''} onChange={(e) => set(d.name, e.target.value)}
                aria-invalid={!!err || undefined} className={clsx(inputCls, err && 'ring-1 ring-red-500')}>
                <option value="">{t('scriptParams.selectPlaceholder', '— Select —')}</option>
                {d.options.map((o) => <option key={o} value={o}>{o}</option>)}
              </select>
            );
            break;
          case 'multiselect': {
            const arr = Array.isArray(v) ? v : [];
            control = (
              <div id={id} role="group" className={clsx('flex flex-wrap gap-1.5', err && 'ring-1 ring-red-500 rounded-lg p-1')}>
                {d.options.map((o) => {
                  const on = arr.includes(o);
                  return (
                    <button key={o} type="button" aria-pressed={on}
                      onClick={() => set(d.name, on ? arr.filter((x) => x !== o) : [...arr, o])}
                      className={clsx('px-2.5 py-1 coarse:min-h-10 text-xs rounded-full border transition-colors',
                        on ? 'bg-accent/15 border-accent text-accent' : 'border-border text-text-muted hover:text-text-primary')}>
                      {o}
                    </button>
                  );
                })}
              </div>
            );
            break;
          }
          case 'secret':
            control = (
              <div className="flex items-center gap-2">
                <div className="flex-1 min-w-0">
                  <SecretInput id={id} value={typeof v === 'string' ? v : ''} invalid={!!err}
                    onChange={(nv) => {
                      set(d.name, nv);
                      if (nv && cleared && onClearedSecretsChange) onClearedSecretsChange(clearedSecrets.filter((x) => x !== d.name));
                    }}
                    placeholder={stored && !cleared ? t('scriptParams.secretUnchanged', { mask: SCRIPT_SECRET_MASK, defaultValue: '{{mask}} (unchanged)' }) : undefined} />
                </div>
                {stored && !cleared && !d.required && onClearedSecretsChange && (
                  <button type="button" onClick={() => { onClearedSecretsChange([...clearedSecrets, d.name]); set(d.name, ''); }}
                    className="shrink-0 flex items-center gap-1 px-2 py-1.5 coarse:min-h-10 text-xs text-text-muted hover:text-red-400 rounded-lg hover:bg-red-500/10"
                    title={t('scriptParams.clearSecret', 'Clear the stored value')}>
                    <X className="w-3.5 h-3.5" /> {t('scriptParams.clear', 'Clear')}
                  </button>
                )}
              </div>
            );
            break;
          default:
            control = (
              <input id={id} type="text" value={typeof v === 'string' ? v : ''} onChange={(e) => set(d.name, e.target.value)}
                autoCapitalize="off" autoCorrect="off" spellCheck={false} aria-invalid={!!err || undefined}
                placeholder={defaultHint(d)} className={clsx(inputCls, err && 'ring-1 ring-red-500')} />
            );
        }
        return (
          <div key={d.name} className="space-y-1">
            {d.type !== 'boolean' && label}
            {control}
            {cleared && <p className="text-[11px] text-amber-400">{t('scriptParams.secretWillBeCleared', 'The stored value will be removed on save.')}</p>}
            {d.description && <p className="text-[11px] text-text-muted">{d.description}</p>}
            {err && <p className="text-[11px] text-red-400">{scriptParameterValueErrorText(t, err, d.name)}</p>}
          </div>
        );
      })}
      {general && <p className="text-[11px] text-red-400">{scriptParameterValueErrorText(t, general)}</p>}
      {Object.entries(errors).filter(([n, c]) => n && c === 'unknown' && !definitions.some((d) => d.name === n)).map(([n]) => (
        <p key={n} className="text-[11px] text-red-400">{scriptParameterValueErrorText(t, 'unknown', n)}</p>
      ))}
    </div>
  );
}

/** Compact "Parameters: a=1, b=••••" line of an execution (values already masked by the server). */
export function ScriptParameterValuesLine({ values, className }: { values?: Record<string, unknown> | null; className?: string }) {
  const { t } = useTranslation();
  const entries = Object.entries(values ?? {}).filter(([, v]) => v !== undefined && v !== null && v !== '');
  if (!entries.length) return null;
  return (
    <p className={clsx('text-[11px] text-text-muted break-words', className)}>
      <span className="font-medium">{t('scriptParams.valuesLabel', 'Parameters')}:</span>{' '}
      {entries.map(([k, v], i) => (
        <span key={k}>
          {i > 0 && ', '}
          <span className="font-mono">{k}</span>=<span className="font-mono text-text-primary">{formatScriptParameterValue(v)}</span>
        </span>
      ))}
    </p>
  );
}

/**
 * Values to STORE on a schedule: coerced, without defaults (the script's
 * current default applies at each run), a secret left blank is omitted (the
 * stored one is kept), a cleared secret is sent as null. `errors` holds the
 * per-field problems (required counted with the stored secrets and defaults).
 */
export function scheduleParameterPayload(
  defs: readonly ScriptParameterFormDef[],
  values: ScriptParameterFormValues,
  opts: { storedSecretNames?: string[]; clearedSecrets?: string[] } = {},
): { payload: Record<string, ScriptParameterValues[string] | null>; errors: ScriptParameterFieldErrors } {
  const cleared = opts.clearedSecrets ?? [];
  const provided = (opts.storedSecretNames ?? []).filter((n) => !cleared.includes(n));
  const check = validateScriptParameterForm(defs, values, { provided });
  const r = resolveScriptParameterValues(defs, scriptParameterFormToRaw(defs, values), { provided, applyDefaults: false, skipRequired: true });
  const payload: Record<string, ScriptParameterValues[string] | null> = { ...r.values };
  for (const n of cleared) if (!(n in payload)) payload[n] = null;
  return { payload, errors: check.errors };
}
