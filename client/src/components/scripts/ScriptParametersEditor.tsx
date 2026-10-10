import { useTranslation } from 'react-i18next';
import type { TFunction } from 'i18next';
import { ArrowDown, ArrowUp, Plus, Trash2, Wand2, SlidersHorizontal } from 'lucide-react';
import toast from 'react-hot-toast';
import { clsx } from 'clsx';
import {
  detectScriptParameters,
  normalizeScriptParameterDefinitions,
  SCRIPT_PARAMETER_TYPES,
} from '@obliance/shared';
import type {
  ScriptParameter,
  ScriptParameterDefinitionError,
  ScriptParameterDefinitionInput,
  ScriptParameterType,
} from '@obliance/shared';
import { IconButton } from '@/components/common/IconButton';

/** One definition being edited (options kept as raw text, one per line). */
export interface EditorParameter extends ScriptParameterDefinitionInput {
  _key: string;
  _optionsText: string;
}

let keySeq = 0;
const newKey = () => `p${Date.now().toString(36)}${(keySeq++).toString(36)}`;

export function toEditorParameters(params: readonly (ScriptParameter | ScriptParameterDefinitionInput)[] | undefined | null): EditorParameter[] {
  return (params ?? []).map((p) => ({
    name: p.name,
    label: p.label ?? p.name,
    description: p.description ?? null,
    type: p.type,
    options: [...(p.options ?? [])],
    defaultValue: p.defaultValue ?? null,
    required: !!p.required,
    _key: newKey(),
    _optionsText: (p.options ?? []).join('\n'),
  }));
}

/** Editor rows → the `parameters` body of POST / PATCH /api/scripts. */
export function fromEditorParameters(rows: readonly EditorParameter[]): ScriptParameterDefinitionInput[] {
  return rows.map((r) => {
    const options = r.type === 'select' || r.type === 'multiselect'
      ? r._optionsText.split(/\r?\n/).map((x) => x.trim()).filter(Boolean)
      : [];
    return {
      name: r.name.trim(),
      label: r.label.trim() || r.name.trim(),
      description: r.description?.trim() ? r.description.trim() : null,
      type: r.type,
      options,
      defaultValue: r.type === 'secret' || r.defaultValue === '' ? null : r.defaultValue,
      required: r.required,
    };
  });
}

/** Client-side check (same rules as the server). */
export function validateEditorParameters(rows: readonly EditorParameter[]): ScriptParameterDefinitionError[] {
  return normalizeScriptParameterDefinitions(fromEditorParameters(rows)).errors;
}

/** Server 400 `{ code: 'invalid_parameters', details: [{ index, name, code }] }` → errors, or null. */
export function definitionErrorsFromApi(err: unknown): ScriptParameterDefinitionError[] | null {
  const r = (err as { response?: { status?: number; data?: { code?: string; details?: unknown } } })?.response;
  if (r?.status !== 400 || r.data?.code !== 'invalid_parameters' || !Array.isArray(r.data.details)) return null;
  return r.data.details as ScriptParameterDefinitionError[];
}

export function definitionErrorText(t: TFunction, code: string): string {
  switch (code) {
    case 'invalid_name': return t('scriptParams.defError.invalid_name', 'Name: letters, digits and _ only, not starting with a digit (64 max)');
    case 'duplicate_name': return t('scriptParams.defError.duplicate_name', 'Another parameter has the same name (case-insensitive)');
    case 'invalid_type': return t('scriptParams.defError.invalid_type', 'Invalid type');
    case 'options_required': return t('scriptParams.defError.options_required', 'At least one option is required');
    case 'invalid_options': return t('scriptParams.defError.invalid_options', 'Invalid options');
    case 'invalid_default': return t('scriptParams.defError.invalid_default', 'The default value does not match the type or the options');
    case 'secret_default': return t('scriptParams.defError.secret_default', 'A secret parameter cannot have a default value');
    case 'too_long': return t('scriptParams.defError.too_long', 'Text too long');
    case 'too_many': return t('scriptParams.defError.too_many', 'Too many parameters (50 max)');
    default: return t('scriptParams.defError.invalid_type', 'Invalid type');
  }
}

export function typeLabel(t: TFunction, type: ScriptParameterType): string {
  switch (type) {
    case 'string': return t('scriptParams.type.string', 'Text');
    case 'number': return t('scriptParams.type.number', 'Number');
    case 'boolean': return t('scriptParams.type.boolean', 'Yes / No');
    case 'secret': return t('scriptParams.type.secret', 'Secret');
    case 'select': return t('scriptParams.type.select', 'Choice');
    case 'multiselect': return t('scriptParams.type.multiselect', 'Multiple choice');
    default: return type;
  }
}

const inputCls = 'w-full px-2.5 py-1.5 text-sm bg-bg-tertiary rounded-lg text-text-primary focus:outline-none focus:ring-1 focus:ring-accent';
const labelCls = 'text-[11px] font-medium text-text-muted uppercase';

interface Props {
  value: EditorParameter[];
  onChange: (next: EditorParameter[]) => void;
  /** Script content + runtime, for "Detect from script". */
  content: string;
  runtime: string;
  /** Errors returned by the server on save (index-based). */
  serverErrors?: ScriptParameterDefinitionError[] | null;
}

export function ScriptParametersEditor({ value, onChange, content, runtime, serverErrors }: Props) {
  const { t } = useTranslation();
  const localErrors = validateEditorParameters(value);
  const errors = [...localErrors, ...(serverErrors ?? []).filter((se) => !localErrors.some((le) => le.index === se.index && le.code === se.code))];
  const errorsOf = (i: number) => errors.filter((e) => e.index === i);
  const globalErrors = errors.filter((e) => e.index < 0);

  const update = (i: number, patch: Partial<EditorParameter>) => {
    const next = value.slice();
    next[i] = { ...next[i], ...patch };
    onChange(next);
  };
  const move = (i: number, dir: -1 | 1) => {
    const j = i + dir;
    if (j < 0 || j >= value.length) return;
    const next = value.slice();
    [next[i], next[j]] = [next[j], next[i]];
    onChange(next);
  };
  const add = () => onChange([...value, {
    name: '', label: '', description: null, type: 'string', options: [], defaultValue: null, required: false, _key: newKey(), _optionsText: '',
  }]);
  const detect = () => {
    const found = detectScriptParameters(content, runtime);
    const existing = new Set(value.map((p) => p.name.trim().toLowerCase()));
    const fresh = found.filter((p) => !existing.has(p.name.toLowerCase()));
    if (fresh.length === 0) {
      toast(found.length
        ? t('scriptParams.detectNothingNew', 'All detected parameters are already defined')
        : t('scriptParams.detectNone', { placeholder: '{{PARAM_name}}', defaultValue: 'No parameter found in the script (PowerShell param() block or {{placeholder}} placeholders)' }));
      return;
    }
    onChange([...value, ...toEditorParameters(fresh)]);
    toast.success(t('scriptParams.detectAdded', { count: fresh.length, defaultValue: '{{count}} parameter(s) added' }));
  };

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <SlidersHorizontal className="w-4 h-4 text-text-muted" />
        <span className="text-xs font-medium text-text-muted uppercase">{t('scriptParams.sectionTitle', 'Parameters')}</span>
        <span className="text-xs text-text-muted">({value.length})</span>
        <div className="ml-auto flex flex-wrap gap-2">
          <button type="button" onClick={detect}
            className="flex items-center gap-1.5 px-2.5 py-1.5 coarse:min-h-10 text-xs bg-bg-secondary rounded-lg text-text-muted hover:text-text-primary transition-colors"
            title={t('scriptParams.detectHint', { placeholder: '{{PARAM_name}}', defaultValue: 'Read the PowerShell param() block and {{placeholder}} placeholders of the content' })}>
            <Wand2 className="w-3.5 h-3.5" /> {t('scriptParams.detect', 'Detect from script')}
          </button>
          <button type="button" onClick={add}
            className="flex items-center gap-1.5 px-2.5 py-1.5 coarse:min-h-10 text-xs bg-accent text-white rounded-lg hover:bg-accent/80 transition-colors">
            <Plus className="w-3.5 h-3.5" /> {t('scriptParams.add', 'Add parameter')}
          </button>
        </div>
      </div>
      <p className="text-[11px] text-text-muted">
        {t('scriptParams.editorHint', 'Values are asked at each run. On the device every value is an environment variable OBLI_PARAM_<NAME>; PowerShell scripts also receive them as their own param() parameters (SecureString for secrets). Secrets are never written into the script.')}
      </p>
      {globalErrors.map((e, k) => <p key={k} className="text-[11px] text-red-400">{definitionErrorText(t, e.code)}</p>)}
      {value.length === 0 && (
        <p className="text-xs text-text-muted italic">{t('scriptParams.none', 'No parameter.')}</p>
      )}
      {value.map((p, i) => {
        const errs = errorsOf(i);
        const hasOptions = p.type === 'select' || p.type === 'multiselect';
        const options = p._optionsText.split(/\r?\n/).map((x) => x.trim()).filter(Boolean);
        let defaultControl: React.ReactNode;
        if (p.type === 'secret') {
          defaultControl = <input disabled value="" placeholder={t('scriptParams.noSecretDefault', 'No default for a secret')} className={clsx(inputCls, 'opacity-50')} />;
        } else if (p.type === 'boolean') {
          defaultControl = (
            <select value={p.defaultValue ?? ''} onChange={(e) => update(i, { defaultValue: e.target.value || null })} className={inputCls}>
              <option value="">{t('scriptParams.noDefault', '— None —')}</option>
              <option value="true">{t('common.yes', 'Yes')}</option>
              <option value="false">{t('common.no', 'No')}</option>
            </select>
          );
        } else if (p.type === 'select') {
          defaultControl = (
            <select value={p.defaultValue ?? ''} onChange={(e) => update(i, { defaultValue: e.target.value || null })} className={inputCls}>
              <option value="">{t('scriptParams.noDefault', '— None —')}</option>
              {options.map((o) => <option key={o} value={o}>{o}</option>)}
            </select>
          );
        } else if (p.type === 'multiselect') {
          let current: string[] = [];
          try { const j = p.defaultValue ? JSON.parse(p.defaultValue) : []; if (Array.isArray(j)) current = j.map(String); } catch { current = (p.defaultValue ?? '').split(',').map((x) => x.trim()).filter(Boolean); }
          defaultControl = (
            <div className="flex flex-wrap gap-1.5 min-h-[2rem] items-center">
              {options.length === 0 && <span className="text-[11px] text-text-muted">{t('scriptParams.addOptionsFirst', 'Add options first')}</span>}
              {options.map((o) => {
                const on = current.includes(o);
                return (
                  <button key={o} type="button" aria-pressed={on}
                    onClick={() => {
                      const next = on ? current.filter((x) => x !== o) : [...current, o];
                      update(i, { defaultValue: next.length ? JSON.stringify(next) : null });
                    }}
                    className={clsx('px-2 py-0.5 coarse:min-h-9 text-xs rounded-full border', on ? 'bg-accent/15 border-accent text-accent' : 'border-border text-text-muted')}>
                    {o}
                  </button>
                );
              })}
            </div>
          );
        } else {
          defaultControl = (
            <input type={p.type === 'number' ? 'number' : 'text'} step="any" value={p.defaultValue ?? ''}
              onChange={(e) => update(i, { defaultValue: e.target.value === '' ? null : e.target.value })}
              autoCapitalize="off" autoCorrect="off" spellCheck={false} className={inputCls} />
          );
        }
        return (
          <div key={p._key} className={clsx('rounded-xl bg-bg-secondary p-3 space-y-2', errs.length && 'ring-1 ring-red-500/60')}>
            <div className="flex items-center gap-1">
              <span className="text-xs font-mono text-text-muted">#{i + 1}</span>
              <span className="text-sm font-medium text-text-primary truncate ml-1">{p.name || t('scriptParams.unnamed', '(unnamed)')}</span>
              <div className="ml-auto flex items-center gap-0.5">
                <IconButton label={t('scriptParams.moveUp', 'Move up')} onClick={() => move(i, -1)} disabled={i === 0} variant="plain" icon={<ArrowUp className="w-3.5 h-3.5" />} />
                <IconButton label={t('scriptParams.moveDown', 'Move down')} onClick={() => move(i, 1)} disabled={i === value.length - 1} variant="plain" icon={<ArrowDown className="w-3.5 h-3.5" />} />
                <IconButton label={t('scriptParams.remove', 'Remove parameter')} onClick={() => onChange(value.filter((_, k) => k !== i))} variant="plain" icon={<Trash2 className="w-3.5 h-3.5 text-red-400" />} />
              </div>
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
              <div className="space-y-0.5">
                <label className={labelCls}>{t('scriptParams.name', 'Name')} *</label>
                <input value={p.name} onChange={(e) => update(i, { name: e.target.value })}
                  autoCapitalize="off" autoCorrect="off" spellCheck={false} placeholder="AdminPassword"
                  className={clsx(inputCls, 'font-mono')} />
              </div>
              <div className="space-y-0.5">
                <label className={labelCls}>{t('scriptParams.label', 'Label')}</label>
                <input value={p.label} onChange={(e) => update(i, { label: e.target.value })} placeholder={p.name} className={inputCls} />
              </div>
              <div className="space-y-0.5">
                <label className={labelCls}>{t('scriptParams.typeLabel', 'Type')}</label>
                <select value={p.type}
                  onChange={(e) => {
                    const type = e.target.value as ScriptParameterType;
                    update(i, { type, defaultValue: type === p.type ? p.defaultValue : null });
                  }}
                  className={inputCls}>
                  {SCRIPT_PARAMETER_TYPES.map((ty) => <option key={ty} value={ty}>{typeLabel(t, ty)}</option>)}
                </select>
              </div>
              <div className="space-y-0.5">
                <label className={labelCls}>{t('scriptParams.default', 'Default value')}</label>
                {defaultControl}
              </div>
              {hasOptions && (
                <div className="space-y-0.5 sm:col-span-2">
                  <label className={labelCls}>{t('scriptParams.options', 'Options (one per line)')} *</label>
                  <textarea value={p._optionsText} rows={3} onChange={(e) => update(i, { _optionsText: e.target.value })}
                    autoCapitalize="off" autoCorrect="off" spellCheck={false} className={clsx(inputCls, 'resize-y font-mono')} />
                </div>
              )}
              <div className="space-y-0.5 sm:col-span-2">
                <label className={labelCls}>{t('scriptParams.description', 'Description')}</label>
                <input value={p.description ?? ''} onChange={(e) => update(i, { description: e.target.value })} className={inputCls} />
              </div>
            </div>
            <label className="flex items-center gap-2 text-sm text-text-primary cursor-pointer select-none">
              <input type="checkbox" checked={p.required} onChange={(e) => update(i, { required: e.target.checked })} className="w-4 h-4 accent-accent" />
              {t('scriptParams.required', 'Required')}
            </label>
            {errs.map((e, k) => <p key={k} className="text-[11px] text-red-400">{definitionErrorText(t, e.code)}</p>)}
          </div>
        );
      })}
    </div>
  );
}
