/**
 * ObliReach "lock the session when the connection ends" — viewer side
 * (agents that list 'lock_on_end' in init.features; same protocol as the
 * Oblireach Desktop viewer and the Oblireach agent):
 *
 *   agent → viewer  {"type":"session_lock_state","lockedAtConnect":bool,"lockOnEnd":bool}
 *                   after the session is ready and after each change. It is
 *                   the source of truth of the padlock button.
 *   viewer → agent  {"type":"set_lock_on_end","enabled":bool}
 *
 * The agent turns lockOnEnd on by itself when the Windows session was locked
 * when the operator connected (we unlocked it), and locks the session at the
 * end of the connection. The viewer only toggles.
 *
 * A per-user setting can turn the whole thing off: no button, and every
 * lockOnEnd:true the agent reports is answered set_lock_on_end false at once.
 * It is an account preference (preferences.reachLockOnEnd, Profile page),
 * mirrored into localStorage at sign-in (store/authStore) where the viewers
 * read it; an account that never set it keeps this browser's value (on by
 * default).
 */

export const LOCK_ON_END_FEATURE = 'lock_on_end';

/** localStorage key (shared by every viewer of this browser): 'off' disables, anything else = on (default). */
export const LOCK_ON_END_STORAGE_KEY = 'obliance.reach.lockOnEnd';

export interface ReachSessionLockState {
  lockedAtConnect: boolean;
  lockOnEnd: boolean;
}

/** A session_lock_state frame → its state, or null when malformed. */
export function parseSessionLockState(v: unknown): ReachSessionLockState | null {
  if (!v || typeof v !== 'object') return null;
  const o = v as Record<string, unknown>;
  if (o.type !== 'session_lock_state' || typeof o.lockOnEnd !== 'boolean') return null;
  return { lockedAtConnect: o.lockedAtConnect === true, lockOnEnd: o.lockOnEnd };
}

/** Viewer → agent message. */
export function setLockOnEndMessage(enabled: boolean): { type: 'set_lock_on_end'; enabled: boolean } {
  return { type: 'set_lock_on_end', enabled };
}

/** A stored value → the setting (anything but 'off': on). */
export function parseLockOnEndSetting(v: unknown): boolean {
  return v !== 'off';
}

export function loadLockOnEndSetting(): boolean {
  try { return parseLockOnEndSetting(localStorage.getItem(LOCK_ON_END_STORAGE_KEY)); } catch { return true; }
}

export function saveLockOnEndSetting(on: boolean): void {
  try { localStorage.setItem(LOCK_ON_END_STORAGE_KEY, on ? 'on' : 'off'); } catch { /* private mode, storage blocked */ }
}
