// Device display name ("alias") rules — shared by the single rename (pencil
// on the device page → PATCH /api/devices/:id { displayName }) and the bulk
// rename (services/bulkRename.service.ts), so both accept exactly the same
// names.
//
// Renaming only ever touches `devices.display_name` (the Obliance-side
// alias). The real machine name reported by the agent (`devices.hostname`)
// is never modified, and nothing is sent to the agent.
//
// Rules:
//  - trimmed; an empty result is "no name" (the caller decides what that
//    means: the PATCH keeps its historical behaviour, the bulk rename skips
//    the row);
//  - at most 500 characters (the column is varchar(500): a longer value used
//    to fail as a 500 Internal Server Error);
//  - no control characters (C0/C1, DEL, line/paragraph separators) and no
//    bidirectional overrides/isolates (U+202A–U+202E, U+2066–U+2069): a name
//    is rendered in lists, notifications, mails and CSV exports, where those
//    characters break lines or visually reorder the text (spoofing).

export const DEVICE_DISPLAY_NAME_MAX = 500;

export type DeviceNameError = 'not_string' | 'empty' | 'too_long' | 'forbidden_chars';

const FORBIDDEN_RANGES: Array<[number, number]> = [
  [0x00, 0x1f], [0x7f, 0x9f],   // C0 / DEL / C1 control characters
  [0x2028, 0x2029],             // line / paragraph separators
  [0x202a, 0x202e],             // bidi embeddings / overrides
  [0x2066, 0x2069],             // bidi isolates
];
function hasForbiddenChar(s: string): boolean {
  for (const ch of s) {
    const c = ch.codePointAt(0)!;
    if (FORBIDDEN_RANGES.some(([a, b]) => c >= a && c <= b)) return true;
  }
  return false;
}

export function validateDeviceDisplayName(raw: unknown):
  { ok: true; value: string } | { ok: false; reason: DeviceNameError } {
  if (typeof raw !== 'string') return { ok: false, reason: 'not_string' };
  const value = raw.trim();
  if (value === '') return { ok: false, reason: 'empty' };
  if ([...value].length > DEVICE_DISPLAY_NAME_MAX) return { ok: false, reason: 'too_long' };
  if (hasForbiddenChar(value)) return { ok: false, reason: 'forbidden_chars' };
  return { ok: true, value };
}

/** The name the UI shows for a device: its alias, else its hostname. */
export function effectiveDeviceName(row: { display_name?: string | null; hostname?: string | null }): string {
  const d = (row.display_name ?? '').trim();
  return d !== '' ? d : (row.hostname ?? '');
}
