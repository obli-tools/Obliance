import type { WindowsPrereqsReport, WindowsPrereqCheck } from '@obliance/shared';

// ── Windows NT 6.x prerequisites (push body `prereqs`) ──────────────────────
//
// The Obliance agent on Windows 7 / 8.1 / Server 2008 R2 – 2012 R2 reports
// (agent/prereqs.go, omitted on Windows 10+ and other OSes):
//   { sp1?, sha2Signing, sha2Kbs?, kb2533623, tls12Schannel, wmfVersion?, dotnet4x }
// Agent input: everything is re-validated here before it is stored / shown.
//
// Evaluation (device page, device list filter):
//   required     sp1 (7 / 2008 R2 only), sha2Signing (ObliReach updates are
//                SHA-256 signed), kb2533623 (modern installers / runtimes),
//                tls12Schannel (PowerShell / BITS / .NET downloads)
//   recommended  WMF 5.1, .NET Framework 4.8

const KB_RE = /^KB\d{6,8}$/;
const VERSION_RE = /^\d{1,2}(\.\d{1,6}){1,3}$/;
const DOTNET_RE = /^4(\.\d{1,2}){1,2}$/;

/**
 * Push body `prereqs` → sanitised report.
 *   undefined → absent or unusable (the caller decides: keep / clear)
 */
export function sanitizeWindowsPrereqs(raw: unknown): WindowsPrereqsReport | undefined {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return undefined;
  const r = raw as Record<string, unknown>;
  if (typeof r.sha2Signing !== 'boolean' || typeof r.kb2533623 !== 'boolean' || typeof r.tls12Schannel !== 'boolean') {
    return undefined;
  }
  const kbs = Array.isArray(r.sha2Kbs)
    ? [...new Set(r.sha2Kbs.filter((k): k is string => typeof k === 'string').map((k) => k.trim().toUpperCase()).filter((k) => KB_RE.test(k)))].slice(0, 4)
    : [];
  const wmf = typeof r.wmfVersion === 'string' && VERSION_RE.test(r.wmfVersion.trim()) ? r.wmfVersion.trim() : null;
  let dotnet: string | null = null;
  if (typeof r.dotnet4x === 'string') {
    const s = r.dotnet4x.trim();
    if (s === '') dotnet = '';
    else if (s === '4.0' || DOTNET_RE.test(s)) dotnet = s;
  }
  // Fixed key order: the canonical form compared with the stored one.
  return {
    sp1: typeof r.sp1 === 'boolean' ? r.sp1 : null,
    sha2Signing: r.sha2Signing,
    sha2Kbs: kbs,
    kb2533623: r.kb2533623,
    tls12Schannel: r.tls12Schannel,
    wmfVersion: wmf,
    dotnet4x: dotnet,
  };
}

/** Stored JSONB (object or string) → report, null when absent / corrupt. */
export function parseStoredWindowsPrereqs(raw: unknown): WindowsPrereqsReport | null {
  if (raw == null) return null;
  let v: unknown = raw;
  if (typeof raw === 'string') {
    try { v = JSON.parse(raw); } catch { return null; }
  }
  return sanitizeWindowsPrereqs(v) ?? null;
}

/** Canonical string of a report (fixed key order) — equality between pushes. */
export function windowsPrereqsKey(p: WindowsPrereqsReport | null): string {
  return p ? JSON.stringify(sanitizeWindowsPrereqs(p) ?? null) : '';
}

/** "5.1.14409.1005" ≥ "5.1"? (numeric, component by component) */
function versionAtLeast(v: string, min: string): boolean {
  const a = v.split('.').map(Number);
  const b = min.split('.').map(Number);
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    const x = a[i] ?? 0;
    const y = b[i] ?? 0;
    if (x !== y) return x > y;
  }
  return true;
}

/** Each prerequisite: ok / missing / unknown, required or recommended. */
export function evaluateWindowsPrereqs(p: WindowsPrereqsReport | null): WindowsPrereqCheck[] | null {
  if (!p) return null;
  const out: WindowsPrereqCheck[] = [];
  const st = (b: boolean): 'ok' | 'missing' => (b ? 'ok' : 'missing');
  if (p.sp1 !== null) out.push({ id: 'sp1', status: st(p.sp1), severity: 'required' });
  out.push({ id: 'sha2Signing', status: st(p.sha2Signing), severity: 'required', value: p.sha2Kbs.length ? p.sha2Kbs.join(', ') : null });
  out.push({ id: 'kb2533623', status: st(p.kb2533623), severity: 'required' });
  out.push({ id: 'tls12Schannel', status: st(p.tls12Schannel), severity: 'required' });
  out.push({
    id: 'wmf51',
    status: p.wmfVersion === null ? 'unknown' : st(versionAtLeast(p.wmfVersion, '5.1')),
    severity: 'recommended',
    value: p.wmfVersion,
  });
  out.push({
    id: 'dotnet48',
    status: p.dotnet4x === null ? 'unknown' : st(p.dotnet4x !== '' && versionAtLeast(p.dotnet4x, '4.8')),
    severity: 'recommended',
    value: p.dotnet4x,
  });
  return out;
}

/** Number of REQUIRED prerequisites missing (null: not reported). */
export function windowsPrereqsMissingCount(p: WindowsPrereqsReport | null): number | null {
  const checks = evaluateWindowsPrereqs(p);
  if (!checks) return null;
  return checks.filter((c) => c.severity === 'required' && c.status === 'missing').length;
}

/**
 * What the push route stores for this push.
 *   undefined → keep (field absent from an agent that does not report it, or unusable)
 *   null      → clear (legacy agent; a current agent no longer reports it: Windows 10+)
 *   report    → store
 * `reportsBuild`: the push carries a usable `agentBuild` (an agent recent
 * enough to report `prereqs` whenever it applies).
 */
export function nextWindowsPrereqs(raw: unknown, opts: { legacy: boolean; reportsBuild: boolean }): WindowsPrereqsReport | null | undefined {
  if (opts.legacy) return null;
  if (raw === undefined || raw === null) return opts.reportsBuild ? null : undefined;
  return sanitizeWindowsPrereqs(raw);
}
