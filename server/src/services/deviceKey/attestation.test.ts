import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {
  verifyAttestation, keyDescriptionOf, parseRootOfTrust, parseAttestationApplicationId, KM_TAG, PROVISIONING_INFO_OID,
  type AttestationPolicy, type AttestationOutcome, type AttestationFailureReason,
} from './attestation';
import { certificateExtensions, asOctetString, asInt } from './der';
import { GOOGLE_ATTESTATION_ROOTS, PINNED_ROOT_SPKI_SHA256 } from './attestationRoots';
import {
  makeChain, makeCert, makeRoot, ecKey, keyDescription, goodHardwareList, goodSoftwareList, withTag,
  rootOfTrust, applicationId, der, TAG, TEST_PACKAGE, TEST_SIGNER, OID_KEY_DESCRIPTION,
  type FakeChainSpec, type AuthItem,
} from './testdata/certFactory';
import * as G from './testdata/googleChains';

// Attestation verification, steps
// 1..11 and the key parameters the app must use.
//
// Two families of chains:
//  - REAL chains from Google's android/keyattestation testdata (genuine
//    KeyMint output, rooted in the production Google roots): they prove the
//    pins, the chain walk, the parser and the revocation step on real data,
//    then must be refused by the key policy (they are test keys without
//    user authentication and with a test package);
//  - SYNTHETIC chains rooted in a fake root generated here (certFactory.ts)
//    and injected as the only pin: every rule of steps 5..11 is bent one at a
//    time. Chains of real phones (debug build) are still to be captured as
//    fixtures.

const NOW = Date.UTC(2026, 8, 26, 12, 0, 0);
const SIGNER_HEX = TEST_SIGNER.toString('hex');

function spkiOf(certB64: string): Buffer {
  return new crypto.X509Certificate(Buffer.from(certB64, 'base64')).publicKey.export({ type: 'spki', format: 'der' }) as Buffer;
}

function fail(o: AttestationOutcome, reason: AttestationFailureReason, msg?: string): void {
  assert.equal(o.ok, false, msg ?? `expected ${reason}`);
  if (!o.ok) assert.equal(o.reason, reason, `${msg ?? ''} detail=${o.detail ?? ''}`);
}

// ── Pins ────────────────────────────────────────────────────────────────────

test('pins: sha256(SPKI) recomputed from the stored public keys; RSA + ECDSA roots', () => {
  assert.equal(GOOGLE_ATTESTATION_ROOTS.length, 2);
  for (const r of GOOGLE_ATTESTATION_ROOTS) {
    const spki = Buffer.from(r.spkiB64, 'base64');
    assert.equal(crypto.createHash('sha256').update(spki).digest('hex'), r.spkiSha256, r.name);
    const k = crypto.createPublicKey({ key: spki, format: 'der', type: 'spki' });
    assert.ok(k.asymmetricKeyType === 'rsa' || k.asymmetricKeyType === 'ec');
  }
  assert.deepEqual([...PINNED_ROOT_SPKI_SHA256], GOOGLE_ATTESTATION_ROOTS.map((r) => r.spkiSha256));
  const types = GOOGLE_ATTESTATION_ROOTS.map((r) => crypto.createPublicKey({ key: Buffer.from(r.spkiB64, 'base64'), format: 'der', type: 'spki' }).asymmetricKeyType).sort();
  assert.deepEqual(types, ['ec', 'rsa']);
});

// ── Real Google chains ─────────────────────────────────────────────────────

function realPolicy(rc: G.RealChain, over: Partial<AttestationPolicy> = {}): AttestationPolicy {
  return {
    pinnedRootSpkiSha256: PINNED_ROOT_SPKI_SHA256,
    appPackages: [TEST_PACKAGE],
    appSigners: [SIGNER_HEX],
    revocation: { entries: new Map(), fetchedAt: rc.validAt },
    now: rc.validAt,
    ...over,
  };
}

function realNonce(rc: G.RealChain): Buffer {
  const kd = keyDescriptionOf(Buffer.from(rc.chain[0], 'base64'));
  assert.ok(kd, `${rc.source}: KeyDescription present`);
  if (rc.expected) assert.equal(kd.attestationChallenge.toString('base64'), rc.expected.challengeB64);
  return kd.attestationChallenge;
}

/** The policy step a real (test-key) chain must stop at: everything before
 *  it (shape, chain, root, revocation, key, extension, levels, challenge)
 *  passed. */
const POLICY_REASONS: ReadonlySet<AttestationFailureReason> = new Set([
  'purpose', 'algorithm', 'origin', 'no_auth_required', 'all_applications', 'user_auth', 'auth_timeout',
  'root_of_trust', 'bootloader_unlocked', 'boot_state', 'app_id', 'app_signer',
]);

describe('real chains (android/keyattestation testdata)', () => {
  const genuine: Array<[string, G.RealChain, { rkp: boolean; level: 'tee' | 'strongbox' }]> = [
    ['caiman SB RKP (RSA root)', G.CAIMAN_SDK36_SB_EC_RKP, { rkp: true, level: 'strongbox' }],
    ['tegu TEE (2026 ECDSA root)', G.TEGU_SDK36_TEE_EC_2026_ROOT, { rkp: true, level: 'tee' }],
    ['sony xperia 10 III (factory keybox, CA:FALSE intermediate)', G.SONY_XPERIA10III_SDK33_TEE_EC, { rkp: false, level: 'tee' }],
    ['blueline (factory keybox)', G.BLUELINE_SDK28_TEE_EC_NONE, { rkp: false, level: 'tee' }],
  ];
  for (const [name, rc, exp] of genuine) {
    test(`${name}: chains to a pinned Google root, then refused by the key policy`, () => {
      const out = verifyAttestation(rc.chain, spkiOf(rc.chain[0]), realNonce(rc), realPolicy(rc));
      assert.equal(out.ok, false);
      if (out.ok) return;
      assert.ok(POLICY_REASONS.has(out.reason), `${name}: stopped at ${out.reason} (${out.detail ?? ''})`);
      assert.equal(out.summary.securityLevel, exp.level);
      if (rc.expected) {
        assert.equal(out.summary.attestationVersion, rc.expected.attestationVersion);
        assert.equal(out.summary.securityLevel, rc.expected.securityLevel);
      }
      assert.equal(out.summary.serials?.length, rc.chain.length);
      assert.ok(out.summary.revocationCheckedAt);
    });

    test(`${name}: the steps before the policy each refuse on their own`, () => {
      const spki = spkiOf(rc.chain[0]);
      const nonce = realNonce(rc);
      fail(verifyAttestation(rc.chain, spki, nonce, realPolicy(rc, { pinnedRootSpkiSha256: [] })), 'root_unknown');
      fail(verifyAttestation(rc.chain, spki, nonce, realPolicy(rc, { revocation: null })), 'status_unavailable');
      const tbsSerials = (verifyAttestation(rc.chain, spki, nonce, realPolicy(rc)) as { summary: { serials?: string[] } }).summary.serials!;
      fail(verifyAttestation(rc.chain, spki, nonce, realPolicy(rc, {
        revocation: { entries: new Map([[tbsSerials[1], 'REVOKED']]), fetchedAt: rc.validAt },
      })), 'revoked');
      fail(verifyAttestation(rc.chain, spki, nonce, realPolicy(rc, {
        revocation: { entries: new Map([[tbsSerials[tbsSerials.length - 1], 'SUSPENDED']]), fetchedAt: rc.validAt },
      })), 'revoked');
      fail(verifyAttestation(rc.chain, ecKey().spki, nonce, realPolicy(rc)), 'key_mismatch');
      fail(verifyAttestation(rc.chain, spki, Buffer.alloc(nonce.length, 7), realPolicy(rc)), 'challenge');
      fail(verifyAttestation(rc.chain.slice(1), spkiOf(rc.chain[1]), nonce, realPolicy(rc)), 'extension_missing');
      fail(verifyAttestation([rc.chain[0], ...rc.chain.slice(2)], spki, nonce, realPolicy(rc)), 'chain_signature');
    });
  }

  test('RKP signal: Google\'s RKP chains carry the provisioning-info extension the verifier looks for', () => {
    // The key policy stops these test keys before step 11, so the extension
    // is checked on the chain itself; the synthetic tests below cover the
    // verifier's own step 11.
    for (const [name, rc, exp] of genuine) {
      const hasProv = rc.chain.slice(1, -1).some((c) =>
        certificateExtensions(Buffer.from(c, 'base64')).some((e) => e.oid === PROVISIONING_INFO_OID));
      assert.equal(hasProv, exp.rkp, name);
    }
  });

  test('steps 9 and 10 parsers on genuine KeyMint output: root of trust, application id, OS version', () => {
    let checked = 0;
    for (const [name, rc] of genuine) {
      if (!rc.expected) continue;
      const kd = keyDescriptionOf(Buffer.from(rc.chain[0], 'base64'));
      assert.ok(kd, name);
      const rot = parseRootOfTrust(kd.hardwareEnforced.tags.get(KM_TAG.ROOT_OF_TRUST)!);
      assert.equal(rot.deviceLocked, rc.expected.deviceLocked, name);
      assert.equal(rot.deviceLockedDer, true, `${name}: canonical BOOLEAN`);
      const appTlv = kd.softwareEnforced.tags.get(KM_TAG.ATTESTATION_APPLICATION_ID);
      assert.ok(appTlv, `${name}: [709] in softwareEnforced`);
      const app = parseAttestationApplicationId(asOctetString(appTlv));
      assert.equal(app.packages[0].name, rc.expected.packageName, name);
      assert.equal(app.signatureDigests[0].toString('base64'), rc.expected.signatureB64, name);
      assert.equal(asInt(kd.hardwareEnforced.tags.get(KM_TAG.OS_VERSION)!), rc.expected.osVersion, name);
      checked++;
    }
    assert.equal(checked, 4);
  });

  test('sony: its factory chain expired on 2026-05-24 → refused today (chain_validity, see attestation.ts)', () => {
    const rc = G.SONY_XPERIA10III_SDK33_TEE_EC;
    fail(verifyAttestation(rc.chain, spkiOf(rc.chain[0]), realNonce(rc), realPolicy(rc, { now: NOW })), 'chain_validity');
  });

  test('marlin: software attestation root → root_unknown', () => {
    const rc = G.MARLIN_SDK29_TEE_EC_NONE;
    fail(verifyAttestation(rc.chain, spkiOf(rc.chain[0]), realNonce(rc), realPolicy(rc)), 'root_unknown');
  });

  test('tags not in ascending order: parsed (tolerance); that chain carries a broken leaf signature', () => {
    const rc = G.INVALID_TAGS_NOT_IN_ASCENDING_ORDER;
    const kd = keyDescriptionOf(Buffer.from(rc.chain[0], 'base64'));
    assert.ok(kd);
    const order = [...kd.hardwareEnforced.tags.keys(), ...kd.softwareEnforced.tags.keys()];
    const lists = [[...kd.hardwareEnforced.tags.keys()], [...kd.softwareEnforced.tags.keys()]];
    assert.ok(lists.some((l) => l.some((t, i) => i > 0 && t < l[i - 1])), `out of order somewhere: ${order.join(',')}`);
    fail(verifyAttestation(rc.chain, spkiOf(rc.chain[0]), kd.attestationChallenge, realPolicy(rc)), 'chain_signature');
  });

  test('deviceLocked written as a BER boolean (0x01): read as true, like Google\'s verifier', () => {
    const rc = G.INVALID_MALFORMED_ROT_DEVICE_LOCKED;
    const kd = keyDescriptionOf(Buffer.from(rc.chain[0], 'base64'));
    assert.ok(kd);
    const rot = parseRootOfTrust(kd.hardwareEnforced.tags.get(KM_TAG.ROOT_OF_TRUST)!);
    assert.equal(rot.deviceLocked, true);
    assert.equal(rot.deviceLockedDer, false);
    const out = verifyAttestation(rc.chain, spkiOf(rc.chain[0]), kd.attestationChallenge, realPolicy(rc));
    assert.equal(out.ok, false);
    if (!out.ok) assert.ok(POLICY_REASONS.has(out.reason) && out.reason !== 'root_of_trust', out.reason);
  });
});

// ── Synthetic chains ───────────────────────────────────────────────────────

const ROOT = makeRoot();
const ROOT_PIN = crypto.createHash('sha256').update(ROOT.spki).digest('hex');
const NONCE = crypto.randomBytes(32);

function policy(over: Partial<AttestationPolicy> = {}): AttestationPolicy {
  return {
    pinnedRootSpkiSha256: [ROOT_PIN],
    appPackages: [TEST_PACKAGE],
    appSigners: [SIGNER_HEX],
    releaseSigners: [SIGNER_HEX],
    revocation: { entries: new Map(), fetchedAt: NOW - 60_000 },
    now: NOW,
    ...over,
  };
}

function run(spec: Partial<FakeChainSpec> = {}, over: Partial<AttestationPolicy> = {}): AttestationOutcome {
  const c = makeChain({ nonce: NONCE, root: ROOT, ...spec });
  return verifyAttestation(c.chainB64, c.leaf.spki, NONCE, policy(over));
}

const hw = goodHardwareList;
const sw = goodSoftwareList;

describe('synthetic chains: a key made as the app makes it is accepted', () => {
  test('TEE key: ok, level tee, summary', () => {
    const c = makeChain({ nonce: NONCE, root: ROOT });
    const out = verifyAttestation(c.chainB64, c.leaf.spki, NONCE, policy());
    assert.equal(out.ok, true, out.ok ? '' : `${out.reason} ${out.detail ?? ''}`);
    if (!out.ok) return;
    assert.equal(out.level, 'tee');
    const s = out.summary;
    assert.equal(s.securityLevel, 'tee');
    assert.equal(s.attestationVersion, 200);
    assert.equal(s.keyMintVersion, 200);
    assert.equal(s.osVersion, 150000);
    assert.equal(s.osPatchLevel, 202609);
    assert.equal(s.vendorPatchLevel, 20260905);
    assert.equal(s.bootState, 'verified');
    assert.equal(s.deviceLocked, true);
    assert.equal(s.deviceLockedNonDer, undefined);
    assert.equal(s.appPackage, TEST_PACKAGE);
    assert.equal(s.appVersion, '7');
    assert.deepEqual(s.appSigners, [SIGNER_HEX]);
    assert.equal(s.debugSigner, false);
    assert.equal(s.rkp, false);
    assert.equal(s.unlockedDeviceRequired, true);
    assert.equal(s.rollbackResistance, false);
    assert.deepEqual(s.serials, c.serials);
    assert.equal(s.revocationCheckedAt, new Date(NOW - 60_000).toISOString());
  });

  test('StrongBox key (levels 2 / 2): level strongbox', () => {
    const out = run({ kd: { attestationSecurityLevel: 2, keyMintSecurityLevel: 2 } });
    assert.ok(out.ok && out.level === 'strongbox');
  });

  test('API 26-29 style (per-operation fingerprint) and rollback resistance', () => {
    const out = run({ kd: { hw: withTag(hw(), TAG.ROLLBACK_RESISTANCE, der.nul()), attestationVersion: 3, keyMintVersion: 4 } });
    assert.ok(out.ok);
    assert.equal(out.ok && out.summary.rollbackResistance, true);
  });

  test('tags out of order and ENUMERATED-typed integers are tolerated', () => {
    const reversed = [...hw()].reverse();
    assert.ok(run({ kd: { hw: reversed, sw: [...sw()].reverse() } }).ok);
    const asEnum: AuthItem[] = withTag(withTag(hw(), TAG.ALGORITHM, der.enumerated(3)), TAG.ORIGIN, der.enumerated(0));
    assert.ok(run({ kd: { hw: asEnum } }).ok);
  });

  test('factory keybox style: intermediate certified CA:FALSE / digitalSignature (deliberate deviation, documented)', () => {
    const c = makeChain({ nonce: NONCE, root: ROOT, intermediateNotCa: true });
    const leaf = new crypto.X509Certificate(c.der[0]);
    const inter = new crypto.X509Certificate(c.der[1]);
    assert.equal(leaf.checkIssued(inter), false, 'OpenSSL checkIssued refuses this link');
    assert.ok(verifyAttestation(c.chainB64, c.leaf.spki, NONCE, policy()).ok);
  });

  test('attestationApplicationId in the hardware list only is accepted', () => {
    const app = der.octet(applicationId());
    const out = run({ kd: { hw: withTag(hw(), TAG.ATTESTATION_APPLICATION_ID, app), sw: withTag(sw(), TAG.ATTESTATION_APPLICATION_ID, null) } });
    assert.ok(out.ok);
  });

  test('deviceLocked as BER 0x01 is read as locked and recorded', () => {
    const out = run({ kd: { hw: withTag(hw(), TAG.ROOT_OF_TRUST, rootOfTrust({ lockedOctet: 0x01 })) } });
    assert.ok(out.ok);
    assert.equal(out.ok && out.summary.deviceLockedNonDer, true);
  });

  test('non-leaf validity: ±5 min tolerance', () => {
    const justStarted: [Date, Date] = [new Date(NOW + 4 * 60_000), new Date(NOW + 86_400_000)];
    assert.ok(run({ intermediateValidity: justStarted }).ok);
    const justEnded: [Date, Date] = [new Date(NOW - 86_400_000), new Date(NOW - 4 * 60_000)];
    assert.ok(run({ intermediateValidity: justEnded }).ok);
  });

  test('a debug signer passes only when configured, and is flagged', () => {
    const debug = crypto.randomBytes(32);
    const app = der.octet(applicationId([[TEST_PACKAGE, 7]], [debug]));
    const spec = { kd: { sw: withTag(sw(), TAG.ATTESTATION_APPLICATION_ID, app) } };
    fail(run(spec), 'app_signer');
    const out = run(spec, { appSigners: [SIGNER_HEX, debug.toString('hex')] });
    assert.ok(out.ok);
    assert.equal(out.ok && out.summary.debugSigner, true);
    // Colons / upper case in the configured digest are normalised.
    const colon = debug.toString('hex').toUpperCase().match(/../g)!.join(':');
    assert.ok(run(spec, { appSigners: [colon] }).ok);
  });

  test('RKP: logged by default, enforced only when required (Android 13+)', () => {
    const noRkp = run();
    assert.ok(noRkp.ok && noRkp.summary.rkp === false);
    const withRkp = run({ rkp: true });
    assert.ok(withRkp.ok && withRkp.summary.rkp === true);
    fail(run({}, { requireRkp: true }), 'rkp_required');
    assert.ok(run({ rkp: true }, { requireRkp: true }).ok);
    // Below Android 13 the option does not apply.
    assert.ok(run({ kd: { hw: withTag(hw(), TAG.OS_VERSION, der.int(120000)) } }, { requireRkp: true }).ok);
  });
});

describe('synthetic chains: every rule refuses', () => {
  test('1. shape: 1 or 11 certificates, bad base64, not a certificate', () => {
    const c = makeChain({ nonce: NONCE, root: ROOT });
    fail(verifyAttestation([c.chainB64[0]], c.leaf.spki, NONCE, policy()), 'chain_shape');
    fail(verifyAttestation(Array(11).fill(c.chainB64[0]), c.leaf.spki, NONCE, policy()), 'chain_shape');
    fail(verifyAttestation('x', c.leaf.spki, NONCE, policy()), 'chain_shape');
    fail(verifyAttestation([c.chainB64[0] + '!', ...c.chainB64.slice(1)], c.leaf.spki, NONCE, policy()), 'chain_shape');
    fail(verifyAttestation([Buffer.from('not a cert').toString('base64'), ...c.chainB64.slice(1)], c.leaf.spki, NONCE, policy()), 'chain_shape');
    const trailing = Buffer.concat([c.der[0], Buffer.from([0])]).toString('base64');
    fail(verifyAttestation([trailing, ...c.chainB64.slice(1)], c.leaf.spki, NONCE, policy()), 'chain_shape');
  });

  test('2. chain: broken signature, wrong issuer name, expired / not-yet-valid intermediate or root', () => {
    fail(run({ breakLeafSignature: true }), 'chain_signature');
    fail(run({ wrongLeafIssuer: true }), 'chain_signature');
    fail(run({ intermediateValidity: [new Date(NOW - 2 * 86_400_000), new Date(NOW - 10 * 60_000)] }), 'chain_validity');
    fail(run({ intermediateValidity: [new Date(NOW + 10 * 60_000), new Date(NOW + 86_400_000)] }), 'chain_validity');
    const oldRoot = makeRoot('Old Root');
    const c = makeChain({ nonce: NONCE, root: oldRoot, rootValidity: [new Date('2016-01-01Z'), new Date('2026-05-24Z')] });
    const pin = crypto.createHash('sha256').update(oldRoot.spki).digest('hex');
    fail(verifyAttestation(c.chainB64, c.leaf.spki, NONCE, policy({ pinnedRootSpkiSha256: [pin] })), 'chain_validity');
  });

  test('3. root: unknown key, or a pinned key whose certificate is not self-signed', () => {
    fail(run({}, { pinnedRootSpkiSha256: [crypto.randomBytes(32).toString('hex')] }), 'root_unknown');
    // Chain ends at the intermediate (pinned) — not self-signed.
    const c = makeChain({ nonce: NONCE, root: ROOT });
    const interPin = crypto.createHash('sha256').update(c.intermediate.spki).digest('hex');
    fail(verifyAttestation(c.chainB64.slice(0, 2), c.leaf.spki, NONCE, policy({ pinnedRootSpkiSha256: [interPin] })), 'root_unknown');
  });

  test('4. revocation: revoked / suspended serial, no list younger than 7 days', () => {
    const c = makeChain({ nonce: NONCE, root: ROOT });
    const at = NOW - 3_600_000;
    for (const i of [0, 1, 2]) {
      const out = verifyAttestation(c.chainB64, c.leaf.spki, NONCE, policy({ revocation: { entries: new Map([[c.serials[i], i === 1 ? 'SUSPENDED' : 'REVOKED']]), fetchedAt: at } }));
      fail(out, 'revoked', `serial ${i}`);
    }
    fail(verifyAttestation(c.chainB64, c.leaf.spki, NONCE, policy({ revocation: null })), 'status_unavailable');
  });

  test('5. key: the leaf certifies another key', () => {
    const c = makeChain({ nonce: NONCE, root: ROOT });
    fail(verifyAttestation(c.chainB64, ecKey().spki, NONCE, policy()), 'key_mismatch');
    const other = ecKey();
    const c2 = makeChain({ nonce: NONCE, root: ROOT, leafSpki: other.spki });
    fail(verifyAttestation(c2.chainB64, c2.leaf.spki, NONCE, policy()), 'key_mismatch');
  });

  test('6. extension: missing in the leaf, present in an intermediate, attested key used as a CA', () => {
    fail(run({ noKd: true }), 'extension_missing');
    fail(run({ kdInIntermediate: true }), 'extension_misplaced');
    const base = makeChain({ nonce: NONCE, root: ROOT });
    const forged = ecKey();
    const forgedCert = makeCert({
      subject: 'Android Keystore Key', issuer: 'Android Keystore Key', serial: 99, spki: forged.spki,
      signer: base.leaf.privateKey,
      extensions: [{ oid: OID_KEY_DESCRIPTION, value: keyDescription({ challenge: NONCE }) }],
    });
    const chain = [forgedCert.toString('base64'), ...base.chainB64];
    fail(verifyAttestation(chain, forged.spki, NONCE, policy()), 'extension_misplaced');
  });

  test('7. KeyDescription: software level, different levels, wrong challenge, unreadable', () => {
    fail(run({ kd: { attestationSecurityLevel: 0, keyMintSecurityLevel: 0 } }), 'security_level');
    fail(run({ kd: { attestationSecurityLevel: 1, keyMintSecurityLevel: 2 } }), 'security_level');
    fail(run({ kd: { attestationSecurityLevel: 2, keyMintSecurityLevel: 1 } }), 'security_level');
    fail(run({ kd: { attestationSecurityLevel: 3, keyMintSecurityLevel: 3 } }), 'security_level');
    const c = makeChain({ nonce: NONCE, root: ROOT });
    fail(verifyAttestation(c.chainB64, c.leaf.spki, crypto.randomBytes(32), policy()), 'challenge');
    fail(verifyAttestation(c.chainB64, c.leaf.spki, NONCE.subarray(0, 16), policy()), 'challenge');
    fail(run({ kdValue: der.seq(der.int(1)) }), 'malformed');
    fail(run({ kdValue: Buffer.from([0x30, 0x80]) }), 'malformed');
    const dup: AuthItem[] = [...hw(), [TAG.PURPOSE, der.set(der.int(2))]];
    fail(run({ kd: { hw: dup } }), 'malformed');
  });

  test('8. authorisation list (hardware list only)', () => {
    // Tags present only in softwareEnforced do not count.
    const rot: AuthItem[] = [[TAG.ROOT_OF_TRUST, rootOfTrust()]];
    fail(run({ kd: { hw: rot, sw: [...sw(), ...hw().filter(([t]) => t !== TAG.ROOT_OF_TRUST)] } }), 'purpose');
    fail(run({ kd: { hw: withTag(hw(), TAG.PURPOSE, null) } }), 'purpose');
    fail(run({ kd: { hw: withTag(hw(), TAG.PURPOSE, der.set(der.int(3))) } }), 'purpose');
    fail(run({ kd: { hw: withTag(hw(), TAG.PURPOSE, der.set(der.int(2), der.int(7))) } }), 'purpose');
    fail(run({ kd: { hw: withTag(hw(), TAG.ALGORITHM, der.int(1)) } }), 'algorithm');
    fail(run({ kd: { hw: withTag(hw(), TAG.EC_CURVE, der.int(2)) } }), 'algorithm');
    fail(run({ kd: { hw: withTag(hw(), TAG.KEY_SIZE, der.int(384)) } }), 'algorithm');
    fail(run({ kd: { hw: withTag(hw(), TAG.ALGORITHM, null) } }), 'algorithm');
    fail(run({ kd: { hw: withTag(hw(), TAG.ORIGIN, der.int(2)) } }), 'origin');
    fail(run({ kd: { hw: withTag(hw(), TAG.ORIGIN, null) } }), 'origin');
    fail(run({ kd: { hw: withTag(hw(), TAG.NO_AUTH_REQUIRED, der.nul()) } }), 'no_auth_required');
    fail(run({ kd: { sw: withTag(sw(), TAG.NO_AUTH_REQUIRED, der.nul()) } }), 'no_auth_required');
    fail(run({ kd: { hw: withTag(hw(), TAG.ALL_APPLICATIONS, der.nul()) } }), 'all_applications');
    fail(run({ kd: { sw: withTag(sw(), TAG.ALL_APPLICATIONS, der.nul()) } }), 'all_applications');
    fail(run({ kd: { hw: withTag(hw(), TAG.USER_AUTH_TYPE, der.int(3)) } }), 'user_auth');   // biometric + password
    fail(run({ kd: { hw: withTag(hw(), TAG.USER_AUTH_TYPE, der.int(1)) } }), 'user_auth');   // password only
    fail(run({ kd: { hw: withTag(hw(), TAG.USER_AUTH_TYPE, null) } }), 'user_auth');
    fail(run({ kd: { hw: withTag(hw(), TAG.USER_AUTH_TYPE, null), sw: withTag(sw(), TAG.USER_AUTH_TYPE, der.int(2)) } }), 'user_auth');
    fail(run({ kd: { hw: withTag(hw(), TAG.AUTH_TIMEOUT, der.int(30)) } }), 'auth_timeout');
    fail(run({ kd: { sw: withTag(sw(), TAG.AUTH_TIMEOUT, der.int(30)) } }), 'auth_timeout');
  });

  test('9. root of trust: unlocked bootloader, SelfSigned / Unverified / Failed boot, absent', () => {
    fail(run({ kd: { hw: withTag(hw(), TAG.ROOT_OF_TRUST, rootOfTrust({ locked: false })) } }), 'bootloader_unlocked');
    fail(run({ kd: { hw: withTag(hw(), TAG.ROOT_OF_TRUST, rootOfTrust({ state: 1 })) } }), 'boot_state');
    fail(run({ kd: { hw: withTag(hw(), TAG.ROOT_OF_TRUST, rootOfTrust({ state: 2 })) } }), 'boot_state');
    fail(run({ kd: { hw: withTag(hw(), TAG.ROOT_OF_TRUST, rootOfTrust({ state: 3 })) } }), 'boot_state');
    fail(run({ kd: { hw: withTag(hw(), TAG.ROOT_OF_TRUST, null) } }), 'root_of_trust');
    // In softwareEnforced only: not read.
    fail(run({ kd: { hw: withTag(hw(), TAG.ROOT_OF_TRUST, null), sw: withTag(sw(), TAG.ROOT_OF_TRUST, rootOfTrust()) } }), 'root_of_trust');
    fail(run({ kd: { hw: withTag(hw(), TAG.ROOT_OF_TRUST, der.seq(der.octet(Buffer.alloc(32)))) } }), 'root_of_trust');
  });

  test('10. application: wrong / extra / missing package, wrong signer, conflicting lists', () => {
    const appSw = (packages: Array<[string, number]>, signers: Buffer[] = [TEST_SIGNER]) =>
      ({ kd: { sw: withTag(sw(), TAG.ATTESTATION_APPLICATION_ID, der.octet(applicationId(packages, signers))) } });
    fail(run(appSw([['tools.obli.obliance', 7]])), 'app_id');
    fail(run(appSw([[TEST_PACKAGE, 7], ['com.evil.app', 1]])), 'app_id');
    fail(run(appSw([])), 'app_id');
    fail(run({ kd: { sw: withTag(sw(), TAG.ATTESTATION_APPLICATION_ID, null) } }), 'app_id');
    fail(run({ kd: { sw: withTag(sw(), TAG.ATTESTATION_APPLICATION_ID, der.octet(Buffer.from([0x30, 0x00]))) } }), 'app_id');
    fail(run(appSw([[TEST_PACKAGE, 7]], [crypto.randomBytes(32)])), 'app_signer');
    fail(run(appSw([[TEST_PACKAGE, 7]], [TEST_SIGNER, crypto.randomBytes(32)])), 'app_signer');
    fail(run(appSw([[TEST_PACKAGE, 7]], [])), 'app_signer');
    const other = der.octet(applicationId([['com.evil.app', 1]]));
    fail(run({ kd: { hw: withTag(hw(), TAG.ATTESTATION_APPLICATION_ID, other) } }), 'app_id');
    // Package allowed by configuration only.
    assert.ok(run(appSw([['tools.obli.obliance.qual', 3]]), { appPackages: [TEST_PACKAGE, 'tools.obli.obliance.qual'] }).ok);
  });

  test('never throws on hostile input', () => {
    const c = makeChain({ nonce: NONCE, root: ROOT });
    for (const input of [null, undefined, 42, {}, [null, null], [1, 2], ['', ''], [c.chainB64[0], 5]]) {
      const out = verifyAttestation(input, c.leaf.spki, NONCE, policy());
      assert.equal(out.ok, false);
    }
    assert.equal(verifyAttestation(c.chainB64, null as unknown as Buffer, NONCE, policy()).ok, false);
    assert.equal(verifyAttestation(c.chainB64, c.leaf.spki, null as unknown as Buffer, policy()).ok, false);
  });
});
