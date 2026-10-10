import { test } from 'node:test';
import assert from 'node:assert/strict';
import type { SoftwareComplianceEntry, SoftwareEntryAlternative } from '@obliance/shared';
import {
  aggregateEntryResult, buildAgentEntries, commandOutcome, complianceScore, decideRemediation,
  applyInstallAck, startManualCycle, isPlainEntry, remediationInfo, alternativeEligible, alternativeInstallable,
  REMEDIATION_RETRY_MS, REMEDIATION_MAX_RETRIES, type AgentEntryResult, type RemediationAlternative, type RemediationStateData,
} from './softwareAlternatives';
import { deviceOsFacts } from './softwareOsCondition';

// "OR" entries (alternatives) of software compliance lists. Run:
//   cd server
//   node --import ./src/services/deviceKey/test-resolve.mjs --disable-warning=MODULE_TYPELESS_PACKAGE_JSON \
//        --test "src/utils/softwareAlternatives.test.ts"

const custom = (script: string) => [{
  packageManager: 'custom' as const, packageId: null, msiUrl: null, repoPackageId: null,
  installScript: script, msiParams: null, platformScope: 'windows' as const, sortOrder: 0,
}];

function alt(id: number, name: string, extra: Partial<SoftwareEntryAlternative> = {}): SoftwareEntryAlternative {
  return { id, name, matchType: 'contains', publisher: null, minVersion: null, maxVersion: null, sources: [], osCondition: null, ...extra };
}

function entry(id: number, alternatives: SoftwareEntryAlternative[], label: string | null = null): SoftwareComplianceEntry {
  const a = alternatives[0];
  return {
    id, listId: 1, name: a.name, matchType: a.matchType, publisher: a.publisher,
    minVersion: a.minVersion, maxVersion: a.maxVersion,
    installSource: a.sources[0]?.packageManager ?? null, installId: null,
    installScript: a.sources[0]?.installScript ?? null, msiUrl: null, msiParams: null,
    sortOrder: 0, sources: a.sources, label, osCondition: a.osCondition, alternatives,
  };
}

// The Passly example: Win10+ install, Win7 / 8.1 install with TLS 1.2.
const PASSLY = entry(10, [
  alt(10, 'Passly Agent', { sources: custom('install-modern.ps1'), osCondition: { platform: 'windows', minVersion: 'win10' } }),
  alt(11, 'Passly Agent (Windows 7 / 8.1)', { sources: custom('[Net.ServicePointManager]::SecurityProtocol = "Tls12"; install-legacy.ps1'), osCondition: { platform: 'windows', maxVersion: 'win81' } }),
], 'Passly');
const CHROME = entry(20, [alt(20, 'Google Chrome', { sources: custom('choco install chrome') })]);

const WIN10 = deviceOsFacts({ os_type: 'windows', os_name: 'Microsoft Windows 10 Pro', os_version: '10.0.19045.5011 Build 19045.5011' });
const WIN81 = deviceOsFacts({ os_type: 'windows', os_name: 'Microsoft Windows 8.1 Pro', os_version: '6.3.9600.20563 Build 9600.20563' });

const T0 = new Date('2026-10-08T10:00:00Z');
const at = (min: number) => new Date(T0.getTime() + min * 60_000);

test('plain entry detection', () => {
  assert.equal(isPlainEntry(CHROME), true);
  assert.equal(isPlainEntry(PASSLY), false);
  // One alternative with an OS condition is not plain (server-driven).
  assert.equal(isPlainEntry(entry(30, [alt(30, 'X', { osCondition: { platform: 'windows' } })])), false);
  // Old payload shape (no alternatives array) = plain.
  const { alternatives: _x, ...legacy } = CHROME;
  assert.equal(isPlainEntry(legacy as SoftwareComplianceEntry), true);
});

test('eligibility / installability', () => {
  assert.equal(alternativeEligible(PASSLY.alternatives![0], WIN10), true);
  assert.equal(alternativeEligible(PASSLY.alternatives![1], WIN10), false);
  assert.equal(alternativeEligible(PASSLY.alternatives![1], WIN81), true);
  assert.equal(alternativeInstallable(PASSLY.alternatives![0]), true);
  assert.equal(alternativeInstallable(alt(1, 'none')), false);
});

test('agent payload: plain entries unchanged, alternatives flattened', () => {
  const wl = buildAgentEntries([CHROME, PASSLY], 'whitelist', WIN10) as any[];
  assert.equal(wl.length, 3);
  assert.equal(wl[0].id, 20);
  assert.equal(wl[0].installScript, 'choco install chrome');
  assert.equal(wl[0].alternatives, undefined);
  // Whitelist alternatives: detection only (the server installs).
  assert.deepEqual(wl.slice(1).map((e) => [e.id, e.name, e.sources.length, e.installScript]),
    [[10, 'Passly Agent', 0, null], [11, 'Passly Agent (Windows 7 / 8.1)', 0, null]]);
  // Blacklist: only the alternatives eligible on the device keep their method.
  const bl = buildAgentEntries([PASSLY], 'blacklist', WIN81) as any[];
  assert.deepEqual(bl.map((e) => e.sources.length), [0, 1]);
  // Manual run limited to some entries: the others lose their method.
  const only = buildAgentEntries([CHROME, PASSLY], 'blacklist', WIN10, new Set([10])) as any[];
  assert.equal(only[0].sources.length, 0);
  assert.equal(only[0].installScript, null);
  assert.equal(only[1].sources.length, 1);
});

const r = (entryId: number, status: AgentEntryResult['status'], extra: Partial<AgentEntryResult> = {}): AgentEntryResult =>
  ({ entryId, status, checkedAt: T0.toISOString(), ...extra });

test('aggregate: whitelist satisfied by ANY alternative', () => {
  const res = aggregateEntryResult(PASSLY, 'whitelist', new Map([
    [10, r(10, 'non_compliant')],
    [11, r(11, 'compliant', { matchedSoftware: 'Passly Agent 3.2', matchedVersion: '3.2' })],
  ]))!;
  assert.equal(res.entryId, 10);
  assert.equal(res.entryName, 'Passly');
  assert.equal(res.status, 'compliant');
  assert.deepEqual([res.alternativeId, res.alternativeIndex, res.alternativeName, res.alternativeCount],
    [11, 2, 'Passly Agent (Windows 7 / 8.1)', 2]);
  const none = aggregateEntryResult(PASSLY, 'whitelist', new Map([[10, r(10, 'non_compliant')], [11, r(11, 'non_compliant')]]))!;
  assert.equal(none.status, 'non_compliant');
  assert.equal(none.alternativeId, null);
  // No result for the entry at all
  assert.equal(aggregateEntryResult(PASSLY, 'whitelist', new Map()), null);
});

test('aggregate: blacklist violated by ANY alternative', () => {
  const ok = aggregateEntryResult(PASSLY, 'blacklist', new Map([[10, r(10, 'compliant')], [11, r(11, 'compliant')]]))!;
  assert.equal(ok.status, 'compliant');
  const bad = aggregateEntryResult(PASSLY, 'blacklist', new Map([
    [10, r(10, 'compliant')], [11, r(11, 'non_compliant', { matchedSoftware: 'Passly Agent' })],
  ]))!;
  assert.deepEqual([bad.status, bad.alternativeIndex, bad.matchedSoftware], ['non_compliant', 2, 'Passly Agent']);
  const removed = aggregateEntryResult(PASSLY, 'blacklist', new Map([
    [10, r(10, 'remediated', { remediationTriggered: true })], [11, r(11, 'compliant')],
  ]))!;
  assert.deepEqual([removed.status, removed.remediationTriggered], ['remediated', true]);
  const failed = aggregateEntryResult(PASSLY, 'blacklist', new Map([
    [10, r(10, 'remediated')], [11, r(11, 'remediation_failed')],
  ]))!;
  assert.equal(failed.status, 'remediation_failed');
});

test('aggregate: plain entry passes the agent result through', () => {
  const res = aggregateEntryResult(CHROME, 'whitelist', new Map([[20, r(20, 'remediated', { remediationTriggered: true, detail: 'software installed successfully' })]]))!;
  assert.deepEqual([res.status, res.remediationTriggered, res.detail, res.alternativeId], ['remediated', true, 'software installed successfully', null]);
  assert.equal(complianceScore([res, { status: 'non_compliant' }]), 50);
});

// ── Remediation state machine ────────────────────────────────────────────────

const ALTS_WIN81: RemediationAlternative[] = [
  { id: 10, eligible: false, installable: true },
  { id: 11, eligible: true, installable: true },
];
const ALTS_BOTH: RemediationAlternative[] = [
  { id: 1, eligible: true, installable: true },
  { id: 2, eligible: false, installable: true }, // other OS
  { id: 3, eligible: true, installable: false }, // no install method
  { id: 4, eligible: true, installable: true },
];

function step(state: RemediationStateData | null, opts: {
  detected?: boolean; now: Date; checkedAt?: Date; auto?: boolean;
  alternatives?: RemediationAlternative[]; commands?: Record<string, 'pending' | 'success' | 'failure'>;
}) {
  return decideRemediation({
    state, detected: !!opts.detected, now: opts.now, checkedAt: opts.checkedAt ?? opts.now,
    autoRemediate: opts.auto ?? true, alternatives: opts.alternatives ?? ALTS_BOTH, commands: opts.commands ?? {},
  });
}
/** The caller's enqueue: gives the pending attempt its command id. */
function queued(d: ReturnType<typeof step>, cmd: string): RemediationStateData {
  d.state.attempts[d.state.attempts.length - 1].commandId = cmd;
  return d.state;
}

test('remediation: eligible alternatives only, in order (Passly on 8.1)', () => {
  const d = step(null, { now: at(0), alternatives: ALTS_WIN81 });
  assert.deepEqual([d.install, d.status, d.remediationState], [11, 'non_compliant', 'installing']);
});

test('remediation: install failure → next alternative → success', () => {
  let d = step(null, { now: at(0) });
  assert.equal(d.install, 1);
  let st = queued(d, 'c1');
  // Still running: wait, nothing new.
  d = step(st, { now: at(1), commands: { c1: 'pending' } });
  assert.deepEqual([d.install, d.remediationState], [null, 'installing']);
  // Ack: failed (non-zero exit / agent error).
  st = applyInstallAck(st, 'c1', false, 'exit status 1603', at(2))!;
  assert.equal(st.attempts[0].outcome, 'install_failed');
  // Post-install check: not detected → alternative 4 (2: other OS, 3: no method).
  d = step(st, { now: at(3) });
  assert.deepEqual([d.install, d.status], [4, 'non_compliant']);
  st = queued(d, 'c4');
  st = applyInstallAck(st, 'c4', true, null, at(5))!;
  d = step(st, { now: at(6), checkedAt: at(6), detected: true });
  assert.deepEqual([d.status, d.remediationState, d.state.succeededAlternativeId, d.install], ['remediated', 'succeeded', 4, null]);
  // Afterwards: compliant, the alternative that worked is remembered.
  const later = step(d.state, { now: at(400), detected: true });
  assert.deepEqual([later.status, later.remediationState, later.state.succeededAlternativeId], ['compliant', 'succeeded', 4]);
  const info = remediationInfo(d, [{ id: 1, name: 'A' }, { id: 2, name: 'B' }, { id: 3, name: 'C' }, { id: 4, name: 'D' }])!;
  assert.deepEqual([info.state, info.alternativeName, info.alternativeIndex], ['succeeded', 'D', 4]);
  assert.deepEqual(info.attempts.map((a) => [a.alternativeIndex, a.outcome]), [[1, 'install_failed'], [4, 'succeeded']]);
});

test('remediation: installed but not detected → next; all tried → exhausted, no loop', () => {
  let d = step(null, { now: at(0) });
  let st = queued(d, 'c1');
  st = applyInstallAck(st, 'c1', true, null, at(2))!;
  // A scan that started before the install ended proves nothing.
  d = step(st, { now: at(3), checkedAt: at(1) });
  assert.deepEqual([d.install, d.remediationState], [null, 'installing']);
  // A later scan: still absent → next alternative.
  d = step(st, { now: at(4), checkedAt: at(4) });
  assert.equal(d.state.attempts[0].outcome, 'not_detected');
  assert.equal(d.install, 4);
  st = queued(d, 'c4');
  // Expired / lost command (found failed from command_queue).
  d = step(st, { now: at(20), commands: { c4: 'failure' } });
  assert.deepEqual([d.install, d.status, d.remediationState], [null, 'remediation_failed', 'exhausted']);
  assert.ok(d.retryAfter);
  // Next checks within the retry delay: nothing queued.
  const again = step(d.state, { now: at(6 * 60) });
  assert.deepEqual([again.install, again.status], [null, 'remediation_failed']);
  // After the delay: a new cycle from the first alternative.
  const retry = step(d.state, { now: new Date(at(20).getTime() + REMEDIATION_RETRY_MS + 1) });
  assert.equal(retry.install, 1);
  assert.equal(retry.state.attempts.length, 1);
});

test('remediation: 3 retries 24 h apart, then failed until a manual cycle', () => {
  const ONE = [{ id: 1, eligible: true, installable: true }];
  // Cycle n (0 = first): the only alternative fails at once.
  const failCycle = (st: any, t: Date) => {
    const d = step(st, { now: t, alternatives: ONE });
    assert.equal(d.install, 1);
    const q = applyInstallAck(queued(d, 'c' + t.getTime()), 'c' + t.getTime(), false, 'exit 1', t)!;
    return step(q, { now: t, alternatives: ONE });
  };
  let t = at(0);
  let d = failCycle(null, t);
  for (let n = 1; n <= REMEDIATION_MAX_RETRIES; n++) {
    assert.deepEqual([d.status, d.remediationState, d.state.failedCycles], ['remediation_failed', 'exhausted', n]);
    assert.equal(remediationInfo(d, [{ id: 1, name: 'Passly' }])!.retryNumber, n);
    // Within the 24 h: nothing.
    assert.equal(step(d.state, { now: new Date(t.getTime() + REMEDIATION_RETRY_MS - 1), alternatives: ONE }).install, null);
    t = new Date(t.getTime() + REMEDIATION_RETRY_MS + 1);
    d = failCycle(d.state, t);
  }
  assert.deepEqual([d.status, d.remediationState, d.retryAfter], ['remediation_failed', 'failed', null]);
  // Days later: still failed, nothing queued.
  const later = step(d.state, { now: new Date(t.getTime() + 10 * REMEDIATION_RETRY_MS), alternatives: ONE });
  assert.deepEqual([later.install, later.remediationState], [null, 'failed']);
  // A manual "Remediate": a fresh run.
  const m = startManualCycle({ state: later.state, now: new Date(t.getTime() + 11 * REMEDIATION_RETRY_MS), alternatives: ONE, commands: {} })!;
  assert.deepEqual([m.install, m.state.failedCycles], [1, 0]);
  // Installed by hand meanwhile: the counter resets.
  const ok = step(later.state, { now: new Date(t.getTime() + 12 * REMEDIATION_RETRY_MS), alternatives: ONE, detected: true });
  assert.deepEqual([ok.status, ok.state.failedCycles], ['compliant', 0]);
});

test('remediation: no auto-remediate → nothing started; a manual cycle continues', () => {
  const d = step(null, { now: at(0), auto: false });
  assert.deepEqual([d.install, d.status, d.remediationState], [null, 'non_compliant', null]);
  const m = startManualCycle({ state: null, now: at(0), alternatives: ALTS_BOTH, commands: {} })!;
  assert.equal(m.install, 1);
  let st = queued(m, 'c1');
  // Running: a second click is refused.
  assert.equal(startManualCycle({ state: st, now: at(1), alternatives: ALTS_BOTH, commands: { c1: 'pending' } }), null);
  st = applyInstallAck(st, 'c1', false, 'boom', at(2))!;
  const next = step(st, { now: at(3), auto: false });
  assert.equal(next.install, 4);
});

test('remediation: no eligible alternative', () => {
  const d = step(null, { now: at(0), alternatives: [{ id: 1, eligible: false, installable: true }, { id: 2, eligible: true, installable: false }] });
  assert.deepEqual([d.install, d.status, d.remediationState, d.state.cycleStartedAt], [null, 'non_compliant', 'no_eligible', null]);
});

test('remediation: detected while the install command is not acked yet', () => {
  const d = step(null, { now: at(0) });
  const st = queued(d, 'c1');
  const ok = step(st, { now: at(1), detected: true, commands: { c1: 'pending' } });
  assert.deepEqual([ok.status, ok.state.succeededAlternativeId], ['remediated', 1]);
});

test('applyInstallAck: unknown command / already resolved → no change', () => {
  const d = step(null, { now: at(0) });
  const st = queued(d, 'c1');
  assert.equal(applyInstallAck(st, 'other', true, null, at(1)), null);
  const once = applyInstallAck(st, 'c1', true, null, at(1))!;
  assert.equal(applyInstallAck(once, 'c1', false, 'late', at(2)), null);
});

test('commandOutcome from command_queue rows', () => {
  const now = at(60);
  assert.equal(commandOutcome({ status: 'success' }, now), 'success');
  assert.equal(commandOutcome({ status: 'failure' }, now), 'failure');
  assert.equal(commandOutcome({ status: 'timeout' }, now), 'failure');
  assert.equal(commandOutcome(null, now), 'failure');
  assert.equal(commandOutcome({ status: 'pending', expires_at: at(10), created_at: at(0) }, now), 'failure');
  assert.equal(commandOutcome({ status: 'pending', expires_at: at(70), created_at: at(55) }, now), 'pending');
  assert.equal(commandOutcome({ status: 'sent', created_at: at(-200) }, now), 'failure');
  assert.equal(commandOutcome({ status: 'ack_running', created_at: at(30) }, now), 'pending');
});
