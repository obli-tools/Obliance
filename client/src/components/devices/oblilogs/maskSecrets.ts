/**
 * Display-only masking of secrets in the Obli* agent files viewer.
 * The value of any key matching SECRET_KEY_RE becomes MASK (fixed width: the
 * real length is not revealed). The raw text never leaves this module except
 * through an explicit "Download" (the same bytes the Explorer tab gives), and
 * it is never logged.
 */

export const MASK = '••••••';

/** Keys whose values are secrets (apiKey, api_key, token, probeToken, secret,
 *  password, passphrase, privateKey…). */
export const SECRET_KEY_RE = /apiKey|api_key|token|secret|password|passphrase|probeToken|privateKey/i;

function maskValue(v: unknown): unknown {
  if (v === null || v === undefined || v === '') return v;
  return MASK;
}

function walk(node: unknown): unknown {
  if (Array.isArray(node)) return node.map(walk);
  if (node && typeof node === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(node as Record<string, unknown>)) {
      out[k] = SECRET_KEY_RE.test(k) ? maskValue(v) : walk(v);
    }
    return out;
  }
  return node;
}

/**
 * Text masking for content that is not valid JSON (log lines, a truncated
 * JSON tail, key=value files): `"key": "value"`, `"key": 123`, `key=value`,
 * `key: value`. The key may carry a prefix/suffix (`obliviewApiKey`,
 * `X-Api-Key`, `tokenHash`): the whole word is matched.
 */
const TEXT_RE = new RegExp(
  // 1: the key (optionally quoted) + separator   2: the value
  String.raw`((?:"|')?[\w.-]*(?:apiKey|api_key|api-key|token|secret|password|passphrase|probeToken|privateKey)[\w.-]*(?:"|')?\s*[:=]\s*)` +
  String.raw`("(?:[^"\\]|\\.)*"|'[^']*'|[^\s,;}\]&]+)`,
  'gi',
);

export function maskSecretsInText(text: string): string {
  return text.replace(TEXT_RE, (_m, key: string, value: string) => {
    if (value === 'null' || value === '""' || value === "''" || value === 'true' || value === 'false') return key + value;
    const q = value.startsWith('"') ? '"' : value.startsWith("'") ? "'" : '';
    return `${key}${q}${MASK}${q}`;
  });
}

/**
 * JSON files: parsed, secrets masked, pretty-printed (2 spaces). Not parseable
 * (partial tail, JSON lines…) → text masking of the raw content.
 */
export function formatAndMaskJson(text: string): { text: string; pretty: boolean } {
  const trimmed = text.replace(/^﻿/, '');
  try {
    const parsed = JSON.parse(trimmed);
    return { text: JSON.stringify(walk(parsed), null, 2), pretty: true };
  } catch {
    return { text: maskSecretsInText(trimmed), pretty: false };
  }
}
