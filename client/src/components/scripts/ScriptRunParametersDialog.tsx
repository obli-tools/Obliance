import { useCallback, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Loader2, Play, SlidersHorizontal } from 'lucide-react';
import toast from 'react-hot-toast';
import type { Script, ScriptParameterValues } from '@obliance/shared';
import { Modal } from '@/components/common/Modal';
import { scriptApi } from '@/api/script.api';
import {
  ScriptParameterForm,
  initialScriptParameterFormValues,
  scriptParameterErrorsFromApi,
  validateScriptParameterForm,
  type ScriptParameterFieldErrors,
  type ScriptParameterFormValues,
} from './ScriptParameterForm';

type Submit = (parameterValues: ScriptParameterValues) => Promise<void>;

interface DialogState {
  script: Script;
  submit: Submit;
}

/** Message of an API error (server `error`), else the generic one. */
function apiErrorText(err: unknown, fallback: string): string {
  const msg = (err as { response?: { data?: { error?: unknown } } })?.response?.data?.error;
  return typeof msg === 'string' && msg ? msg : fallback;
}

/**
 * Ask a script's parameter values before running it.
 *
 *   const prompt = useScriptParameterPrompt();
 *   await prompt.run(scriptOrId, async (parameterValues) => { await scriptApi.executeNow(id, { ..., parameterValues }); });
 *   ...
 *   {prompt.dialog}
 *
 * No parameter → `submit({})` right away (as before). Otherwise a dialog with
 * the generated form; a 400 `invalid_parameter_values` from `submit` keeps it
 * open with the field errors. Any other error is toasted (submit should just
 * throw).
 */
export function useScriptParameterPrompt() {
  const { t } = useTranslation();
  const [state, setState] = useState<DialogState | null>(null);
  const [values, setValues] = useState<ScriptParameterFormValues>({});
  const [errors, setErrors] = useState<ScriptParameterFieldErrors>({});
  const [busy, setBusy] = useState(false);
  const loadingRef = useRef(false);

  const run = useCallback(async (scriptOrId: Script | number, submit: Submit) => {
    let script: Script | null = typeof scriptOrId === 'number' ? null : scriptOrId;
    if (!script || !Array.isArray(script.parameters)) {
      if (loadingRef.current) return;
      loadingRef.current = true;
      try {
        script = await scriptApi.getById(typeof scriptOrId === 'number' ? scriptOrId : scriptOrId.id);
      } catch (err) {
        toast.error(apiErrorText(err, t('common.error', 'An error occurred')));
        return;
      } finally {
        loadingRef.current = false;
      }
    }
    const defs = script.parameters ?? [];
    if (defs.length === 0) {
      try {
        await submit({});
      } catch (err) {
        toast.error(apiErrorText(err, t('scriptParams.runFailed', 'Failed to execute script')));
      }
      return;
    }
    setValues(initialScriptParameterFormValues(defs));
    setErrors({});
    setState({ script, submit });
  }, [t]);

  const close = () => { if (!busy) { setState(null); setValues({}); setErrors({}); } };

  const confirm = async () => {
    if (!state) return;
    const defs = state.script.parameters ?? [];
    const v = validateScriptParameterForm(defs, values);
    setErrors(v.errors);
    if (Object.keys(v.errors).length) return;
    setBusy(true);
    try {
      await state.submit(v.values);
      setState(null);
      setValues({});
    } catch (err) {
      const fieldErrors = scriptParameterErrorsFromApi(err);
      if (fieldErrors) setErrors(fieldErrors);
      else toast.error(apiErrorText(err, t('scriptParams.runFailed', 'Failed to execute script')));
    } finally {
      setBusy(false);
    }
  };

  const dialog = (
    <Modal
      open={!!state}
      onClose={close}
      dismissible={!busy}
      size="md"
      icon={<SlidersHorizontal className="w-4 h-4 text-accent" />}
      title={t('scriptParams.runDialogTitle', { name: state?.script.name ?? '', defaultValue: 'Run "{{name}}"' })}
      footer={(
        <>
          <button type="button" onClick={close} disabled={busy}
            className="px-4 py-2 coarse:min-h-10 text-sm text-text-muted hover:text-text-primary bg-bg-secondary rounded-lg transition-colors disabled:opacity-50">
            {t('common.cancel', 'Cancel')}
          </button>
          <button type="button" onClick={confirm} disabled={busy}
            className="flex items-center gap-2 px-4 py-2 coarse:min-h-10 text-sm bg-accent text-white rounded-lg hover:bg-accent/80 disabled:opacity-50 transition-colors">
            {busy ? <Loader2 className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
            {t('scriptParams.runNow', 'Run')}
          </button>
        </>
      )}
    >
      {state && (
        <form onSubmit={(e) => { e.preventDefault(); void confirm(); }} className="space-y-3" autoComplete="off">
          <p className="text-xs text-text-muted">{t('scriptParams.runDialogHint', 'This script takes parameters. Secret values are never stored in clear nor shown in the history.')}</p>
          <ScriptParameterForm definitions={state.script.parameters ?? []} values={values} onChange={setValues} errors={errors} idPrefix="run-param" />
          <button type="submit" className="hidden" aria-hidden tabIndex={-1} />
        </form>
      )}
    </Modal>
  );

  return { run, dialog, isOpen: !!state };
}
