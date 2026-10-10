/**
 * ObliReach — Mac keyboard mapping, viewer side (agents that list
 * 'key_map_mac' in init.features: macOS agents only; same protocol and
 * setting as the Oblireach Desktop viewer, agent keymap_mac.go).
 *
 * Driving a Mac from a Windows / Linux computer: the Windows key acts as Cmd,
 * Alt as Option, the characters typed are this keyboard's (whatever the Mac's
 * layout), AltGr types its character, and with "Ctrl → Cmd" the Windows
 * shortcuts (Ctrl+C / V / X / A / Z / Y / S / F / T / W / N / Q / R / P,
 * Ctrl+arrows, Home / End) do the same on the Mac. The agent does the
 * mapping; every key message carries `macMap`:
 *   absent — no mapping (older viewers: the agent's behaviour before);
 *   1      — mapping;
 *   2      — mapping + Ctrl → Cmd.
 * A per-user setting (this browser, localStorage):
 *   'auto' — (default) on for an agent that lists the feature, unless this
 *            computer is a Mac itself (its own Cmd / layout already match);
 *   'off'  — never.
 * Windows / Linux agents never list the feature: nothing changes for them.
 */

export const MAC_KEYS_FEATURE = 'key_map_mac';

export type MacKeysMode = 'auto' | 'off';
export const MAC_KEYS_DEFAULT_MODE: MacKeysMode = 'auto';
/** localStorage keys (shared by every viewer of this browser). */
export const MAC_KEYS_STORAGE_KEY = 'obliance.reach.macKeys';
export const MAC_KEYS_CTRL_STORAGE_KEY = 'obliance.reach.macKeysCtrlCmd';

/** A stored value → a mode (anything unknown: the default). */
export function parseMacKeysMode(v: unknown): MacKeysMode {
  return v === 'off' ? 'off' : MAC_KEYS_DEFAULT_MODE;
}

/** A stored value → "Ctrl → Cmd" (on unless turned off). */
export function parseMacKeysCtrlCmd(v: unknown): boolean {
  return v !== 'off';
}

export function loadMacKeysMode(): MacKeysMode {
  try { return parseMacKeysMode(localStorage.getItem(MAC_KEYS_STORAGE_KEY)); } catch { return MAC_KEYS_DEFAULT_MODE; }
}

export function saveMacKeysMode(mode: MacKeysMode): void {
  try { localStorage.setItem(MAC_KEYS_STORAGE_KEY, mode); } catch { /* private mode, storage blocked */ }
}

export function loadMacKeysCtrlCmd(): boolean {
  try { return parseMacKeysCtrlCmd(localStorage.getItem(MAC_KEYS_CTRL_STORAGE_KEY)); } catch { return true; }
}

export function saveMacKeysCtrlCmd(on: boolean): void {
  try { localStorage.setItem(MAC_KEYS_CTRL_STORAGE_KEY, on ? 'on' : 'off'); } catch { /* private mode, storage blocked */ }
}

export interface MacKeysState {
  mode: MacKeysMode;
  ctrlCmd: boolean;
  /** The agent listed 'key_map_mac' in THIS connection's init. */
  agentMaps: boolean;
  /** This computer is a Mac. */
  operatorIsMac: boolean;
}

/** The macMap a key message carries (0: none, the field is left out). */
export function macMapValue(s: MacKeysState): 0 | 1 | 2 {
  if (s.mode === 'off' || !s.agentMaps || s.operatorIsMac) return 0;
  return s.ctrlCmd ? 2 : 1;
}

/** Stamps a key message (any other message, or macMap 0: unchanged). */
export function withMacMap<T extends { type?: string }>(msg: T, macMap: 0 | 1 | 2): T | (T & { macMap: 1 | 2 }) {
  if (msg.type !== 'key' || macMap === 0) return msg;
  return { ...msg, macMap };
}
