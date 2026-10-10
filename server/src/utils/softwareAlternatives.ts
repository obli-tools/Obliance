// Software compliance "OR" entries (alternatives) — pure helpers, no DB.
//
// An entry holds 1..N alternatives (shared SoftwareEntryAlternative). The
// AGENT only knows flat entries (agent/software_compliance.go): the server
// sends every alternative as its own flat entry, keyed by the alternative's
// row id, and folds the agent's per-alternative results back into one result
// per entry:
//   whitelist: satisfied when ANY alternative is detected;
//   blacklist: violated when ANY alternative is detected.
//
// Remediation:
//   - plain entry (one alternative, no OS condition): unchanged — the agent
//     installs / removes it itself during the check (list autoRemediate);
//   - whitelist entry with alternatives / OS conditions: driven by the SERVER
//     (decideRemediation): the agent gets no install info for them; the
//     eligible alternatives (OS condition matches the device, an install
//     method is set) are installed ONE AT A TIME, in order. Failed install
//     (non-zero exit / agent error / command expired) or still not detected at
//     the post-install check → next alternative. Detected → recorded as the
//     alternative that succeeded, stop. All tried → "exhausted": nothing more
//     until retryAfterMs (24 h) has passed (one pass per cycle, no loop).
//     REMEDIATION_MAX_RETRIES new cycles at most; when the last one fails too
//     → "failed": the install is a failure, nothing more until a manual
//     "Remediate" (which starts over with a fresh retry budget);
//   - blacklist entry with alternatives: the agent removes every detected
//     alternative whose OS condition matches the device (install info is only
//     sent for those).
import type {
  SoftwareComplianceEntry, SoftwareEntryAlternative, SoftwareComplianceEntryResult,
  SoftwareListType, SoftwareRemediationAttemptOutcome, SoftwareRemediationInfo,
  SoftwareRemediationState, SoftwareEntrySourceConfig,
} from '@obliance/shared';
import { matchOsCondition, type DeviceOsFacts } from './softwareOsCondition';

/** Max alternatives per entry (UI + API). */
export const MAX_ALTERNATIVES = 10;

/** After every alternative failed: next cycle not before this delay. */
export const REMEDIATION_RETRY_MS = 24 * 60 * 60 * 1000;

/** New cycles after the first failed one; then the remediation gives up. */
export const REMEDIATION_MAX_RETRIES = 3;

/** An install command still not acked after this long is considered lost. */
export const REMEDIATION_COMMAND_STALE_MS = 2 * 60 * 60 * 1000;

/** The alternatives of an entry, always at least one (built from the top-level fields). */
export function entryAlternatives(entry: SoftwareComplianceEntry): SoftwareEntryAlternative[] {
  if (entry.alternatives && entry.alternatives.length > 0) return entry.alternatives;
  return [{
    id: entry.id, name: entry.name, matchType: entry.matchType, publisher: entry.publisher,
    minVersion: entry.minVersion, maxVersion: entry.maxVersion, sources: entry.sources ?? [],
    osCondition: entry.osCondition ?? null,
  }];
}

/** Plain entry: handled exactly as before alternatives existed. */
export function isPlainEntry(entry: SoftwareComplianceEntry): boolean {
  const alts = entryAlternatives(entry);
  return alts.length === 1 && !alts[0].osCondition;
}

export function entryDisplayName(entry: SoftwareComplianceEntry): string {
  const label = (entry.label ?? '').trim();
  return label || entryAlternatives(entry)[0].name;
}

/** An install / uninstall method is configured (the agent picks the source for its platform). */
export function alternativeInstallable(alt: Pick<SoftwareEntryAlternative, 'sources'>): boolean {
  return (alt.sources ?? []).some((s) => !!(s.packageId || s.installScript || s.msiUrl || s.repoPackageId || s.repoPackageUuid));
}

export function alternativeEligible(alt: Pick<SoftwareEntryAlternative, 'osCondition'>, facts: DeviceOsFacts): boolean {
  return matchOsCondition(alt.osCondition, facts);
}

/** The flat entry shape agent/software_compliance.go reads. */
export interface AgentFlatEntry {
  id: number;
  name: string;
  matchType: string;
  publisher: string | null;
  minVersion: string | null;
  maxVersion: string | null;
  installSource: string | null;
  installId: string | null;
  installScript: string | null;
  msiUrl: string | null;
  msiParams: string | null;
  sources: SoftwareEntrySourceConfig[];
}

function flat(id: number, alt: SoftwareEntryAlternative, withInstall: boolean): AgentFlatEntry {
  const s0 = withInstall ? alt.sources?.[0] : undefined;
  return {
    id, name: alt.name, matchType: alt.matchType, publisher: alt.publisher,
    minVersion: alt.minVersion, maxVersion: alt.maxVersion,
    installSource: s0?.packageManager ?? null, installId: s0?.packageId ?? null,
    installScript: s0?.installScript ?? null, msiUrl: s0?.msiUrl ?? null, msiParams: s0?.msiParams ?? null,
    sources: withInstall ? (alt.sources ?? []) : [],
  };
}

/**
 * The `entries` of a check_software_compliance payload for ONE device.
 * Plain entries keep their full shape (legacy fields included); entries with
 * alternatives become one flat entry per alternative (id = alternative id).
 */
export function buildAgentEntries(
  entries: SoftwareComplianceEntry[], listType: SoftwareListType, facts: DeviceOsFacts,
  /** Manual remediation run: only these entries keep their install info. */
  onlyEntryIds?: ReadonlySet<number>,
): Array<SoftwareComplianceEntry | AgentFlatEntry> {
  const out: Array<SoftwareComplianceEntry | AgentFlatEntry> = [];
  for (const e of entries) {
    const selected = !onlyEntryIds || onlyEntryIds.has(e.id);
    if (isPlainEntry(e)) {
      // Unchanged payload (alternatives stripped: the agent does not read them).
      const { alternatives: _a, ...rest } = e;
      out.push(selected ? rest as SoftwareComplianceEntry : {
        ...rest, installSource: null, installId: null, installScript: null, msiUrl: null, msiParams: null, sources: [],
      } as SoftwareComplianceEntry);
      continue;
    }
    for (const alt of entryAlternatives(e)) {
      const id = alt.id ?? e.id;
      // Whitelist: the server installs (decideRemediation). Blacklist: the
      // agent removes what it finds, only with alternatives eligible here.
      const withInstall = selected && listType === 'blacklist' && alternativeEligible(alt, facts);
      out.push(flat(id, alt, withInstall));
    }
  }
  return out;
}

/** One result object as posted by the agent. */
export interface AgentEntryResult {
  entryId: number;
  entryName?: string;
  status: SoftwareComplianceEntryResult['status'];
  matchedSoftware?: string | null;
  matchedVersion?: string | null;
  remediationTriggered?: boolean;
  detail?: string | null;
  checkedAt?: string;
}

/**
 * Fold the agent's results back to one result per entry. Returns null for an
 * entry none of whose ids is in the results (payload built before an edit).
 */
export function aggregateEntryResult(
  entry: SoftwareComplianceEntry, listType: SoftwareListType, byId: Map<number, AgentEntryResult>,
): SoftwareComplianceEntryResult | null {
  const alts = entryAlternatives(entry);
  const pairs = alts.map((a, i) => ({ alt: a, index: i + 1, r: byId.get(a.id ?? entry.id) }))
    .filter((p): p is { alt: SoftwareEntryAlternative; index: number; r: AgentEntryResult } => !!p.r);
  if (pairs.length === 0) return null;
  const checkedAt = pairs[0].r.checkedAt ?? new Date().toISOString();
  const base = {
    entryId: entry.id, entryName: entryDisplayName(entry), checkedAt,
    alternativeCount: alts.length,
  };
  const altFields = (p: { alt: SoftwareEntryAlternative; index: number } | undefined) => p
    ? { alternativeId: p.alt.id ?? entry.id, alternativeName: p.alt.name, alternativeIndex: p.index }
    : { alternativeId: null, alternativeName: null, alternativeIndex: null };

  if (isPlainEntry(entry)) {
    // The agent's own result, unchanged (it also remediated it itself).
    const r = pairs[0].r;
    return {
      ...base, status: r.status,
      matchedSoftware: r.matchedSoftware ?? null, matchedVersion: r.matchedVersion ?? null,
      remediationTriggered: !!r.remediationTriggered, detail: r.detail ?? null,
      ...altFields(undefined),
    };
  }

  if (listType === 'whitelist') {
    const hit = pairs.find((p) => p.r.status === 'compliant' || p.r.status === 'remediated');
    if (hit) {
      return {
        ...base, status: 'compliant',
        matchedSoftware: hit.r.matchedSoftware ?? null, matchedVersion: hit.r.matchedVersion ?? null,
        remediationTriggered: false, detail: null, ...altFields(hit),
      };
    }
    const err = pairs.find((p) => p.r.status === 'error');
    return {
      ...base, status: err && pairs.every((p) => p.r.status === 'error') ? 'error' : 'non_compliant',
      matchedSoftware: null, matchedVersion: null, remediationTriggered: false,
      detail: err?.r.detail ?? 'required software not found', ...altFields(undefined),
    };
  }

  // Blacklist: any detected alternative is a violation.
  const found = pairs.filter((p) => p.r.status !== 'compliant' && p.r.status !== 'error');
  if (found.length === 0) {
    const allErr = pairs.every((p) => p.r.status === 'error');
    return {
      ...base, status: allErr ? 'error' : 'compliant', matchedSoftware: null, matchedVersion: null,
      remediationTriggered: false, detail: allErr ? (pairs[0].r.detail ?? null) : null, ...altFields(undefined),
    };
  }
  const status: SoftwareComplianceEntryResult['status'] =
    found.some((p) => p.r.status === 'remediation_failed') ? 'remediation_failed'
      : found.some((p) => p.r.status === 'non_compliant') ? 'non_compliant'
        : 'remediated';
  const first = found.find((p) => p.r.status === status) ?? found[0];
  return {
    ...base, status,
    matchedSoftware: first.r.matchedSoftware ?? null, matchedVersion: first.r.matchedVersion ?? null,
    remediationTriggered: found.some((p) => !!p.r.remediationTriggered),
    detail: first.r.detail ?? null, ...altFields(first),
  };
}

/** Score as the agent computes it: compliant + remediated over all results. */
export function complianceScore(results: Array<Pick<SoftwareComplianceEntryResult, 'status'>>): number {
  if (results.length === 0) return 0;
  const ok = results.filter((r) => r.status === 'compliant' || r.status === 'remediated').length;
  return (ok / results.length) * 100;
}

// ─── Server-driven remediation (whitelist entries with alternatives) ───────

export interface RemediationAttempt {
  alternativeId: number;
  commandId: string | null;
  outcome: SoftwareRemediationAttemptOutcome;
  at: string;
  finishedAt?: string | null;
  detail?: string | null;
}

export interface RemediationStateData {
  attempts: RemediationAttempt[];
  cycleStartedAt: string | null;
  exhaustedAt: string | null;
  succeededAlternativeId: number | null;
  succeededAt: string | null;
  /** Cycles of this run that ended with every alternative failed. */
  failedCycles: number;
}

export function emptyRemediationState(): RemediationStateData {
  return { attempts: [], cycleStartedAt: null, exhaustedAt: null, succeededAlternativeId: null, succeededAt: null, failedCycles: 0 };
}

/** The outcome of an install command, from its command_queue row. */
export type CommandOutcome = 'pending' | 'success' | 'failure';

export function commandOutcome(
  row: { status?: string | null; expires_at?: string | Date | null; created_at?: string | Date | null } | null | undefined,
  now: Date,
): CommandOutcome {
  if (!row) return 'failure'; // purged / never created
  const st = String(row.status ?? '');
  if (st === 'success') return 'success';
  if (st === 'failure' || st === 'timeout' || st === 'cancelled') return 'failure';
  // pending: expired before the agent fetched it
  if (st === 'pending' && row.expires_at && new Date(row.expires_at).getTime() <= now.getTime()) return 'failure';
  // sent / running for far longer than any install can take
  if (row.created_at && now.getTime() - new Date(row.created_at).getTime() > REMEDIATION_COMMAND_STALE_MS) return 'failure';
  return 'pending';
}

export interface RemediationAlternative { id: number; eligible: boolean; installable: boolean }

export interface RemediationDecision {
  state: RemediationStateData;
  /** Alternative to install now (its attempt is the last one, outcome 'pending', commandId null). */
  install: number | null;
  status: SoftwareComplianceEntryResult['status'];
  remediationState: SoftwareRemediationState | null;
  retryAfter: string | null;
}

/**
 * One step of the remediation state machine, run each time a check result
 * of the entry arrives.
 *   detected        the entry is satisfied (any alternative) in this result;
 *   checkedAt       when the agent scanned (a scan older than the end of the
 *                   last install proves nothing);
 *   commands        outcome of the attempts' install commands, by id;
 *   autoRemediate   the list may START a cycle (a manual cycle continues anyway).
 */
export function decideRemediation(input: {
  state: RemediationStateData | null;
  detected: boolean;
  checkedAt: Date;
  now: Date;
  autoRemediate: boolean;
  alternatives: RemediationAlternative[];
  commands: Record<string, CommandOutcome>;
  retryAfterMs?: number;
}): RemediationDecision {
  const retryMs = input.retryAfterMs ?? REMEDIATION_RETRY_MS;
  const now = input.now;
  const nowIso = now.toISOString();
  const s: RemediationStateData = input.state
    ? { ...input.state, attempts: input.state.attempts.map((a) => ({ ...a })) }
    : emptyRemediationState();
  const last = s.attempts.length ? s.attempts[s.attempts.length - 1] : null;
  const done = (status: RemediationDecision['status'], remediationState: SoftwareRemediationState | null, install: number | null = null, retryAfter: string | null = null): RemediationDecision =>
    ({ state: s, install, status, remediationState, retryAfter });

  // Resolve the running attempt from its command.
  if (last && last.outcome === 'pending') {
    const o = last.commandId ? (input.commands[last.commandId] ?? 'pending') : 'failure';
    if (o === 'success') { last.outcome = 'installed'; last.finishedAt = last.finishedAt ?? nowIso; }
    else if (o === 'failure') { last.outcome = 'install_failed'; last.finishedAt = nowIso; last.detail = last.detail ?? 'install command failed or expired'; }
  }

  if (input.detected) {
    if (last && (last.outcome === 'installed' || last.outcome === 'pending')) {
      last.outcome = 'succeeded';
      last.finishedAt = last.finishedAt ?? nowIso;
      s.succeededAlternativeId = last.alternativeId;
      s.succeededAt = nowIso;
      s.cycleStartedAt = null;
      s.exhaustedAt = null;
      s.failedCycles = 0;
      return done('remediated', 'succeeded');
    }
    // Satisfied without a fresh install: any cycle in progress is over.
    if (s.cycleStartedAt || s.exhaustedAt || s.failedCycles) {
      s.cycleStartedAt = null;
      s.exhaustedAt = null;
      s.failedCycles = 0;
    }
    return done('compliant', s.succeededAlternativeId != null ? 'succeeded' : null);
  }

  // ── Not detected ──
  if (last && last.outcome === 'pending') return done('non_compliant', 'installing');
  if (last && last.outcome === 'installed') {
    const finished = last.finishedAt ? new Date(last.finishedAt).getTime() : 0;
    if (input.checkedAt.getTime() < finished) return done('non_compliant', 'installing');
    last.outcome = 'not_detected';
    last.detail = last.detail ?? 'installed but not detected afterwards';
  }

  if (s.exhaustedAt) {
    if (s.failedCycles > REMEDIATION_MAX_RETRIES) return done('remediation_failed', 'failed');
    const until = new Date(s.exhaustedAt).getTime() + retryMs;
    if (now.getTime() < until) return done('remediation_failed', 'exhausted', null, new Date(until).toISOString());
    if (!input.autoRemediate) return done('non_compliant', 'exhausted');
    s.attempts = [];
    s.exhaustedAt = null;
    s.cycleStartedAt = nowIso;
  } else if (!s.cycleStartedAt) {
    if (!input.autoRemediate) return done('non_compliant', null);
    s.attempts = [];
    s.cycleStartedAt = nowIso;
  }

  return pickNext(s, input.alternatives, now, retryMs, done);
}

function pickNext(
  s: RemediationStateData, alternatives: RemediationAlternative[], now: Date, retryMs: number,
  done: (status: RemediationDecision['status'], st: SoftwareRemediationState | null, install?: number | null, retryAfter?: string | null) => RemediationDecision,
): RemediationDecision {
  const candidates = alternatives.filter((a) => a.eligible && a.installable);
  if (candidates.length === 0) {
    s.cycleStartedAt = null;
    return done('non_compliant', 'no_eligible');
  }
  const tried = new Set(s.attempts.map((a) => a.alternativeId));
  const next = candidates.find((a) => !tried.has(a.id));
  if (!next) {
    s.exhaustedAt = now.toISOString();
    s.failedCycles = (s.failedCycles ?? 0) + 1;
    if (s.failedCycles > REMEDIATION_MAX_RETRIES) return done('remediation_failed', 'failed');
    return done('remediation_failed', 'exhausted', null, new Date(now.getTime() + retryMs).toISOString());
  }
  s.attempts.push({ alternativeId: next.id, commandId: null, outcome: 'pending', at: now.toISOString() });
  return done('non_compliant', 'installing', next.id);
}

/**
 * A manual "Remediate" click: a fresh cycle from the first eligible
 * alternative (even when the list does not auto-remediate). Refused (null
 * decision) while an install is still running.
 */
export function startManualCycle(input: {
  state: RemediationStateData | null;
  now: Date;
  alternatives: RemediationAlternative[];
  commands: Record<string, CommandOutcome>;
}): RemediationDecision | null {
  const s: RemediationStateData = input.state
    ? { ...input.state, attempts: input.state.attempts.map((a) => ({ ...a })) }
    : emptyRemediationState();
  const last = s.attempts.length ? s.attempts[s.attempts.length - 1] : null;
  if (last && last.outcome === 'pending' && last.commandId && (input.commands[last.commandId] ?? 'pending') === 'pending') return null;
  s.attempts = [];
  s.exhaustedAt = null;
  s.failedCycles = 0;
  s.cycleStartedAt = input.now.toISOString();
  const done = (status: RemediationDecision['status'], remediationState: SoftwareRemediationState | null, install: number | null = null, retryAfter: string | null = null): RemediationDecision =>
    ({ state: s, install, status, remediationState, retryAfter });
  return pickNext(s, input.alternatives, input.now, REMEDIATION_RETRY_MS, done);
}

/** Attempt outcome after the install command's ack. */
export function applyInstallAck(state: RemediationStateData, commandId: string, success: boolean, detail: string | null, now: Date): RemediationStateData | null {
  const s: RemediationStateData = { ...state, attempts: state.attempts.map((a) => ({ ...a })) };
  const a = s.attempts.find((x) => x.commandId === commandId);
  if (!a || a.outcome !== 'pending') return null;
  a.outcome = success ? 'installed' : 'install_failed';
  a.finishedAt = now.toISOString();
  if (!success) a.detail = (detail ?? 'install failed').slice(0, 500);
  return s;
}

/** The remediation block of an entry result. */
export function remediationInfo(
  decision: Pick<RemediationDecision, 'state' | 'remediationState' | 'retryAfter'>,
  alternatives: Array<Pick<SoftwareEntryAlternative, 'id' | 'name'>>,
): SoftwareRemediationInfo | null {
  if (!decision.remediationState) return null;
  const named = (id: number | null) => {
    if (id == null) return { alternativeId: null, alternativeName: null, alternativeIndex: null };
    const i = alternatives.findIndex((a) => a.id === id);
    return { alternativeId: id, alternativeName: i >= 0 ? alternatives[i].name : null, alternativeIndex: i >= 0 ? i + 1 : null };
  };
  const s = decision.state;
  const focus = decision.remediationState === 'succeeded'
    ? s.succeededAlternativeId
    : (s.attempts.length ? s.attempts[s.attempts.length - 1].alternativeId : null);
  return {
    state: decision.remediationState,
    ...named(focus),
    attempts: s.attempts.map((a) => {
      const n = named(a.alternativeId);
      return {
        alternativeId: a.alternativeId, alternativeName: n.alternativeName, alternativeIndex: n.alternativeIndex,
        outcome: a.outcome, at: a.finishedAt ?? a.at, detail: a.detail ?? null,
      };
    }),
    retryAfter: decision.retryAfter,
    // Number of the next retry while waiting for it (1..max).
    retryNumber: decision.remediationState === 'exhausted' && s.failedCycles > 0 ? s.failedCycles : null,
    maxRetries: REMEDIATION_MAX_RETRIES,
  };
}
