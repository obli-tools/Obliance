import { useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { ClipboardType, Loader2, X } from 'lucide-react';
import { VM_KEYBOARD_LAYOUTS, VM_TYPE_TEXT_MAX, loadVmLayout, saveVmLayout } from './vmKeyboardLayouts';

/**
 * "Type text" of a Hyper-V VM console (vmconnect's "Type clipboard text"):
 * a basic VM console has no shared clipboard, so the text is TYPED into the
 * guest, key by key, with the guest's keyboard layout. Pre-filled with the
 * local clipboard when the browser lets the page read it.
 */
export function VmTypeTextPanel({
  open, onClose, onSend, onCancel, typing,
}: {
  open: boolean;
  onClose: () => void;
  onSend: (text: string, layout: string) => void;
  onCancel: () => void;
  /** Typing in progress (helper status), null when idle. */
  typing: { done: number; total: number } | null;
}) {
  const { t } = useTranslation();
  const [text, setText] = useState('');
  const [layout, setLayout] = useState(loadVmLayout);
  const areaRef = useRef<HTMLTextAreaElement>(null);

  useEffect(() => {
    if (!open) return;
    setTimeout(() => areaRef.current?.focus(), 0);
    // Best effort: the async Clipboard API needs a secure context and the
    // user's permission; otherwise the operator pastes into the box.
    const clip = typeof navigator !== 'undefined' ? navigator.clipboard : undefined;
    if (window.isSecureContext && clip?.readText) {
      clip.readText().then((v) => { if (v) setText((cur) => cur || v); }).catch(() => { /* refused: paste by hand */ });
    }
  }, [open]);

  if (!open) return null;
  const tooLong = text.length > VM_TYPE_TEXT_MAX;
  const send = () => {
    if (!text || tooLong) return;
    saveVmLayout(layout);
    onSend(text, layout);
  };
  return (
    <>
      <div className="fixed inset-0 z-40" onClick={onClose} />
      <div
        role="dialog"
        aria-label={t('reach.vmConsole.typeTitle', 'Type text into the VM')}
        className="absolute right-0 top-full mt-1 z-50 w-96 max-w-[calc(100vw-1rem)] bg-bg-secondary rounded-lg shadow-2xl p-3 space-y-2"
        // Keys typed here are for the box, never for the VM.
        onKeyDown={(e) => { e.stopPropagation(); if (e.key === 'Escape') onClose(); }}
        onKeyUp={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between">
          <span className="text-sm font-medium text-text-primary flex items-center gap-1.5">
            <ClipboardType className="w-4 h-4" />
            {t('reach.vmConsole.typeTitle', 'Type text into the VM')}
          </span>
          <button onClick={onClose} aria-label={t('common.close', 'Close')} className="p-1 text-text-muted hover:text-text-primary rounded coarse:min-h-10 coarse:min-w-10">
            <X className="w-4 h-4" />
          </button>
        </div>
        <p className="text-[11px] leading-snug text-text-muted">
          {t('reach.vmConsole.typeHint', 'A VM console has no shared clipboard: the text is typed on the VM\'s keyboard, character by character. Choose the keyboard layout configured in the VM.')}
        </p>
        <textarea
          ref={areaRef}
          value={text}
          onChange={(e) => setText(e.target.value)}
          rows={5}
          placeholder={t('reach.vmConsole.typePlaceholder', 'Paste or type the text to send…')}
          className="w-full rounded-md border border-border bg-bg-tertiary px-2 py-1.5 text-sm text-text-primary font-mono resize-y"
        />
        <div className="flex items-center gap-2">
          <label htmlFor="vm-type-layout" className="text-xs text-text-muted shrink-0">{t('reach.vmConsole.layout', 'VM keyboard')}</label>
          <select
            id="vm-type-layout"
            value={layout}
            onChange={(e) => setLayout(e.target.value)}
            className="min-w-0 flex-1 rounded-md border border-border bg-bg-tertiary px-2 py-1 text-xs text-text-primary coarse:min-h-10"
          >
            {VM_KEYBOARD_LAYOUTS.map((l) => <option key={l.klid} value={l.klid}>{l.label}</option>)}
          </select>
        </div>
        {tooLong && (
          <p className="text-xs text-red-400">{t('reach.vmConsole.typeTooLong', 'Too long: {{max}} characters at most.', { max: VM_TYPE_TEXT_MAX })}</p>
        )}
        {typing ? (
          <div className="flex items-center gap-2">
            <Loader2 className="w-4 h-4 animate-spin text-accent" />
            <span className="text-xs text-text-secondary flex-1">
              {t('reach.vmConsole.typing', 'Typing… {{done}} / {{total}}', { done: typing.done, total: typing.total })}
            </span>
            <button onClick={onCancel} className="px-3 py-1 text-xs bg-bg-tertiary text-text-primary rounded hover:bg-bg-active coarse:min-h-10">
              {t('common.cancel', 'Cancel')}
            </button>
          </div>
        ) : (
          <div className="flex justify-end">
            <button
              onClick={send}
              disabled={!text || tooLong}
              className="px-3 py-1.5 text-xs bg-[#C83232] text-white rounded hover:bg-[#C83232]/90 disabled:opacity-50 coarse:min-h-10"
            >
              {t('reach.vmConsole.typeSend', 'Type into the VM')}
            </button>
          </div>
        )}
      </div>
    </>
  );
}
