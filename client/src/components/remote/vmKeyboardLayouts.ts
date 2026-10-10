// Keyboard layouts of a Hyper-V VM console's "Type text" (vmconnect's
// "Clipboard > Type clipboard text"): the helper turns each character into
// the key presses of the GUEST's layout (Windows KLID), so the text arrives
// as typed on that keyboard. Physical keys typed in the viewer need no
// layout (scancodes: the guest applies its own).

export interface VmKeyboardLayout {
  /** Windows keyboard layout id (KLID, 8 hex digits). */
  klid: string;
  /** Label (layout names are not translated: they are what Windows shows). */
  label: string;
  /** BCP-47 prefixes this layout is the usual one for (default guess). */
  langs: string[];
}

export const VM_KEYBOARD_LAYOUTS: VmKeyboardLayout[] = [
  { klid: '0000040C', label: 'Français (France) — AZERTY', langs: ['fr-fr', 'fr'] },
  { klid: '0000080C', label: 'Français (Belgique)', langs: ['fr-be', 'nl-be'] },
  { klid: '0000100C', label: 'Français (Suisse)', langs: ['fr-ch'] },
  { klid: '00001009', label: 'Français (Canada)', langs: ['fr-ca'] },
  { klid: '00000409', label: 'English (US) — QWERTY', langs: ['en-us', 'en'] },
  { klid: '00000809', label: 'English (UK)', langs: ['en-gb', 'en-ie'] },
  { klid: '00020409', label: 'English (US International)', langs: [] },
  { klid: '00000407', label: 'Deutsch (Deutschland) — QWERTZ', langs: ['de-de', 'de', 'de-at'] },
  { klid: '00000807', label: 'Deutsch (Schweiz)', langs: ['de-ch'] },
  { klid: '0000040A', label: 'Español (España)', langs: ['es-es', 'es'] },
  { klid: '0000080A', label: 'Español (Latinoamérica)', langs: ['es-mx', 'es-419', 'es-ar', 'es-co'] },
  { klid: '00000410', label: 'Italiano', langs: ['it'] },
  { klid: '00000816', label: 'Português (Portugal)', langs: ['pt-pt'] },
  { klid: '00000416', label: 'Português (Brasil ABNT)', langs: ['pt-br', 'pt'] },
  { klid: '00000413', label: 'Nederlands', langs: ['nl-nl', 'nl'] },
  { klid: '00000406', label: 'Dansk', langs: ['da'] },
  { klid: '0000041D', label: 'Svenska', langs: ['sv'] },
  { klid: '00000414', label: 'Norsk', langs: ['nb', 'no', 'nn'] },
  { klid: '0000040B', label: 'Suomi', langs: ['fi'] },
  { klid: '00000415', label: 'Polski (programisty)', langs: ['pl'] },
  { klid: '00000405', label: 'Čeština', langs: ['cs'] },
  { klid: '0000041F', label: 'Türkçe (Q)', langs: ['tr'] },
  { klid: '00000419', label: 'Русский', langs: ['ru'] },
  { klid: '00000422', label: 'Українська', langs: ['uk'] },
  { klid: '00000411', label: '日本語', langs: ['ja'] },
  { klid: '00000412', label: '한국어', langs: ['ko'] },
  { klid: '00000804', label: '中文 (简体) — US', langs: ['zh', 'zh-cn'] },
  { klid: '00000401', label: 'العربية (101)', langs: ['ar'] },
];

const STORAGE_KEY = 'obliance.vmconsole.layout';

/** Layout matching the browser language (the operator's guests usually share it). */
export function guessVmLayout(languages: readonly string[] = typeof navigator !== 'undefined' ? navigator.languages ?? [navigator.language] : []): string {
  for (const raw of languages) {
    const lang = String(raw || '').toLowerCase();
    if (!lang) continue;
    const exact = VM_KEYBOARD_LAYOUTS.find((l) => l.langs.includes(lang));
    if (exact) return exact.klid;
    const base = lang.split('-')[0];
    const loose = VM_KEYBOARD_LAYOUTS.find((l) => l.langs.includes(base));
    if (loose) return loose.klid;
  }
  return '00000409';
}

export function loadVmLayout(): string {
  try {
    const v = localStorage.getItem(STORAGE_KEY);
    if (v && VM_KEYBOARD_LAYOUTS.some((l) => l.klid === v)) return v;
  } catch { /* private mode */ }
  return guessVmLayout();
}

export function saveVmLayout(klid: string): void {
  try { localStorage.setItem(STORAGE_KEY, klid); } catch { /* private mode */ }
}

/** The helper types at most this many characters per request (agent cap). */
export const VM_TYPE_TEXT_MAX = 20000;
