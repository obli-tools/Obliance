import crypto from 'crypto';
import { config } from '../config';

// ── At-rest encryption of small secrets (AES-256-GCM) ──────────────────────
//
// Used for the values of 'secret' script parameters: the queued run_script
// payload (command_queue.payload.secretParameters, decrypted only when the
// command is handed to the agent, purged once it is finished) and the values
// a schedule stores (script_schedules.secret_parameter_values).
//
// Key: HKDF-SHA256 of SCRIPT_PARAMS_SECRET, else SESSION_SECRET — a secret
// that never reaches the database, so a dump of the database alone does not
// reveal the values. Rotating that secret makes the stored schedule secrets
// unreadable: the schedule's run then fails with a clear message ("re-enter
// the secret parameters") instead of running without them.
//
// Format: "v1.<iv>.<tag>.<ciphertext>" (base64url), the purpose string bound
// as additional authenticated data (a box sealed for one use cannot be
// replayed into another).

const VERSION = 'v1';
let memo: { src: string; key: Buffer } | null = null;

function key(): Buffer {
  const src = process.env.SCRIPT_PARAMS_SECRET || config.sessionSecret;
  if (!src) throw new Error('secretBox: no SCRIPT_PARAMS_SECRET / SESSION_SECRET to derive the key from');
  if (!memo || memo.src !== src) {
    memo = { src, key: Buffer.from(crypto.hkdfSync('sha256', Buffer.from(src, 'utf8'), Buffer.from('obliance'), Buffer.from('script-parameters/v1'), 32)) };
  }
  return memo.key;
}

export function sealSecret(plain: string, purpose: string): string {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', key(), iv);
  c.setAAD(Buffer.from(purpose, 'utf8'));
  const ct = Buffer.concat([c.update(plain, 'utf8'), c.final()]);
  const tag = c.getAuthTag();
  return [VERSION, iv.toString('base64url'), tag.toString('base64url'), ct.toString('base64url')].join('.');
}

/** Throws when the box is malformed, sealed for another purpose or with another key. */
export function openSecret(box: string, purpose: string): string {
  const parts = typeof box === 'string' ? box.split('.') : [];
  if (parts.length !== 4 || parts[0] !== VERSION) throw new Error('secretBox: unsupported format');
  const [, iv, tag, ct] = parts;
  const d = crypto.createDecipheriv('aes-256-gcm', key(), Buffer.from(iv, 'base64url'));
  d.setAAD(Buffer.from(purpose, 'utf8'));
  d.setAuthTag(Buffer.from(tag, 'base64url'));
  return Buffer.concat([d.update(Buffer.from(ct, 'base64url')), d.final()]).toString('utf8');
}

export function sealJson(value: unknown, purpose: string): string {
  return sealSecret(JSON.stringify(value), purpose);
}

export function openJson<T = unknown>(box: string, purpose: string): T {
  return JSON.parse(openSecret(box, purpose)) as T;
}
