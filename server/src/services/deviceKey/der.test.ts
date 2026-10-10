import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {
  DerError, readTlv, parseDer, children, asInt, asBigInt, asEnumerated, asBoolean, asBooleanBer, asNull,
  asOctetString, asOid, explicitInner, parseCertificateTbs, certificateExtensions, serialHex, derTimeMs,
  parseEcdsaSignature, encodeEcdsaSignature, ecdsaDerToRaw, ecdsaRawToDer, isLowS, malleate, P256_N,
} from './der';
import { der, tlv, makeCert, ecKey, basicConstraintsExt, OID_KEY_DESCRIPTION } from './testdata/certFactory';

// The hand-written DER
// reader and the ECDSA signature rules.

const hex = (s: string) => Buffer.from(s.replace(/\s+/g, ''), 'hex');

test('TLV: short / long lengths, high-tag-number form ([709] as KeyMint writes it)', () => {
  const t = parseDer(hex('04 03 61 62 63'));
  assert.equal(t.tag, 4);
  assert.equal(asOctetString(t).toString(), 'abc');
  const long = Buffer.concat([hex('04 81 80'), Buffer.alloc(128, 1)]);
  assert.equal(asOctetString(parseDer(long)).length, 128);
  // [709] EXPLICIT { OCTET STRING "x" } → bf 85 45 03 04 01 78
  const t709 = parseDer(hex('bf 85 45 03 04 01 78'));
  assert.equal(t709.cls, 2);
  assert.equal(t709.tag, 709);
  assert.equal(asOctetString(explicitInner(t709)).toString(), 'x');
  assert.deepEqual(der.explicit(709, der.octet('x')), hex('bf 85 45 03 04 01 78'));
});

test('TLV: indefinite, non-minimal, truncated, trailing and oversized inputs are refused', () => {
  const bad: Array<[string, RegExp]> = [
    ['30 80 00 00', /indefinite/],
    ['04 81 05 01 02 03 04 05', /non-minimal length/],
    ['04 82 00 05 01 02 03 04 05', /non-minimal length/],
    ['04 05 01 02', /truncated/],
    ['04', /truncated/],
    ['04 01 00 00', /trailing/],
    ['bf 80 05 00', /non-minimal tag/],
    ['bf 1e 00', /non-minimal tag/],
    ['04 85 01 00 00 00 00', /length too large/],
    ['bf ff ff ff ff 01 00', /tag too large/],
  ];
  for (const [h, re] of bad) assert.throws(() => parseDer(hex(h)), (e: unknown) => e instanceof DerError && re.test(e.message), h);
});

test('INTEGER / ENUMERATED / BOOLEAN / NULL / OID', () => {
  assert.equal(asInt(parseDer(hex('02 01 00'))), 0);
  assert.equal(asInt(parseDer(hex('02 02 00 80'))), 128);
  assert.equal(asInt(parseDer(hex('02 01 ff'))), -1);
  assert.equal(asBigInt(parseDer(der.int(2n ** 80n))), 2n ** 80n);
  assert.throws(() => asInt(parseDer(der.int(2n ** 60n))), /too large/);
  assert.throws(() => asInt(parseDer(hex('02 02 00 01'))), /non-minimal/);
  assert.throws(() => asInt(parseDer(hex('02 02 ff 80'))), /non-minimal/);
  assert.throws(() => asInt(parseDer(hex('02 00'))), /empty/);
  assert.equal(asEnumerated(parseDer(hex('0a 01 02'))), 2);
  assert.throws(() => asEnumerated(parseDer(hex('0a 01 ff'))), /range/);
  assert.throws(() => asEnumerated(parseDer(hex('02 01 02'))), /ENUMERATED/);
  assert.equal(asBoolean(parseDer(hex('01 01 ff'))), true);
  assert.equal(asBoolean(parseDer(hex('01 01 00'))), false);
  assert.throws(() => asBoolean(parseDer(hex('01 01 01'))), /non-DER BOOLEAN/);
  assert.throws(() => asBoolean(parseDer(hex('01 02 00 00'))), /length/);
  // BER boolean (RootOfTrust.deviceLocked only).
  assert.deepEqual(asBooleanBer(parseDer(hex('01 01 01'))), { value: true, der: false });
  assert.deepEqual(asBooleanBer(parseDer(hex('01 01 ff'))), { value: true, der: true });
  assert.deepEqual(asBooleanBer(parseDer(hex('01 01 00'))), { value: false, der: true });
  assert.throws(() => asBooleanBer(parseDer(hex('01 00'))), /length/);
  assert.equal(asNull(parseDer(hex('05 00'))), null);
  assert.throws(() => asNull(parseDer(hex('05 01 00'))), /NULL/);
  assert.equal(asOid(parseDer(der.oid('1.3.6.1.4.1.11129.2.1.17'))), '1.3.6.1.4.1.11129.2.1.17');
  assert.equal(asOid(parseDer(hex('06 08 2a 86 48 ce 3d 04 03 02'))), '1.2.840.10045.4.3.2');
  assert.equal(asOid(parseDer(der.oid('2.999.3'))), '2.999.3');
  assert.throws(() => asOid(parseDer(hex('06 02 80 01'))), /non-minimal/);
  assert.throws(() => asOid(parseDer(hex('06 01 86'))), /truncated/);
});

test('children / explicit tags: out-of-order context tags are read (tolerance)', () => {
  const seq = der.seq(der.explicit(706, der.int(202609)), der.explicit(1, der.set(der.int(2))), der.explicit(704, der.seq()));
  const kids = children(parseDer(seq));
  assert.deepEqual(kids.map((k) => k.tag), [706, 1, 704]);
  assert.equal(asInt(explicitInner(kids[0])), 202609);
  // An explicit tag must wrap exactly one element.
  assert.throws(() => explicitInner(parseDer(tlv(2, true, 5, Buffer.concat([der.int(1), der.int(2)])))), /one element/);
  assert.throws(() => explicitInner(parseDer(tlv(2, false, 5, Buffer.from([1])))), /explicit/);
  assert.throws(() => children(parseDer(der.int(1))), /not constructed/);
  // A truncated child inside a well-formed parent.
  assert.throws(() => children(parseDer(hex('30 03 04 05 01'))), /truncated/);
});

test('certificate TBS walk: serial, validity, extensions (duplicates refused)', () => {
  const root = ecKey();
  const leaf = ecKey();
  const cert = makeCert({
    subject: 'Leaf', issuer: 'Root', serial: 0x00ff01n, spki: leaf.spki, signer: root.privateKey,
    notBefore: new Date('1970-01-01T00:00:00Z'), notAfter: new Date('2106-02-07T06:28:15Z'),
    extensions: [basicConstraintsExt(false), { oid: OID_KEY_DESCRIPTION, value: der.seq(der.int(3)) }],
  });
  const x = new crypto.X509Certificate(cert); // Node/OpenSSL agree on the structure
  assert.ok(x.verify(root.publicKey));
  const tbs = parseCertificateTbs(cert);
  assert.equal(serialHex(tbs.serial, tbs.serialBytes), 'ff01');
  assert.equal(derTimeMs(tbs.notBefore), 0);
  assert.equal(derTimeMs(tbs.notAfter), Date.UTC(2106, 1, 7, 6, 28, 15));
  const exts = certificateExtensions(cert);
  assert.deepEqual(exts.map((e) => e.oid), ['2.5.29.19', OID_KEY_DESCRIPTION]);
  assert.equal(exts[0].critical, true);
  assert.equal(asInt(children(parseDer(exts[1].value))[0]), 3);

  const dup = makeCert({
    subject: 'Leaf', issuer: 'Root', serial: 7, spki: leaf.spki, signer: root.privateKey,
    extensions: [{ oid: OID_KEY_DESCRIPTION, value: der.seq() }, { oid: OID_KEY_DESCRIPTION, value: der.seq() }],
  });
  assert.throws(() => certificateExtensions(dup), /duplicate extension/);
  assert.throws(() => parseCertificateTbs(Buffer.concat([cert, Buffer.from([0])])), /trailing/);
});

test('serialHex: lowercase, no leading zeros (status list form)', () => {
  assert.equal(serialHex(0x0abcn, hex('0a bc')), 'abc');
  assert.equal(serialHex(0n, hex('00')), '0');
  assert.equal(serialHex(-1n, hex('ff')), 'ff');
});

test('ECDSA: strict DER parse, DER <-> raw, and malleability (s -> n - s still verifies)', () => {
  const k = ecKey();
  const msg = Buffer.from('obli-devkey-v1\npurpose:stepup');
  // Collect signatures until we have one with a high S (≈ half of them).
  let high: Buffer | null = null;
  let low: Buffer | null = null;
  for (let i = 0; i < 64 && (!high || !low); i++) {
    const sig = crypto.sign('sha256', msg, { key: k.privateKey, dsaEncoding: 'der' });
    const { s } = parseEcdsaSignature(sig);
    if (isLowS(s)) low = sig; else high = sig;
  }
  assert.ok(high && low, 'both S halves seen');
  for (const sig of [high!, low!]) {
    const other = malleate(sig);
    assert.ok(!other.equals(sig));
    // The P-256 order is right: the malleated signature verifies too, so a
    // signature can NEVER serve as a replay key.
    assert.ok(crypto.verify('sha256', msg, { key: k.publicKey, dsaEncoding: 'der' }, sig));
    assert.ok(crypto.verify('sha256', msg, { key: k.publicKey, dsaEncoding: 'der' }, other));
    // High-S is accepted by the parser (Android Keystore does not normalise).
    assert.doesNotThrow(() => parseEcdsaSignature(other));
    const raw = ecdsaDerToRaw(sig);
    assert.equal(raw.length, 64);
    assert.deepEqual(ecdsaRawToDer(raw), sig);
    assert.ok(crypto.verify('sha256', msg, { key: k.publicKey, dsaEncoding: 'ieee-p1363' }, raw));
  }
  assert.equal(P256_N.toString(16).length, 64);
});

test('ECDSA: malformed signatures are refused before crypto.verify', () => {
  const r = 5n;
  const s = 7n;
  const good = encodeEcdsaSignature({ r, s });
  assert.deepEqual(parseEcdsaSignature(good), { r, s });
  const bad: Buffer[] = [
    encodeEcdsaSignature({ r: 0n, s }),
    encodeEcdsaSignature({ r, s: P256_N }),
    encodeEcdsaSignature({ r: P256_N + 1n, s }),
    Buffer.concat([good, Buffer.from([0])]),                       // trailing byte
    hex('30 07 02 01 05 02 01 07'),                                 // declared length beyond the data
    hex('30 07 02 02 00 05 02 01 07'),                              // non-minimal INTEGER
    hex('30 06 02 01 fb 02 01 07'),                                 // negative r
    hex('30 09 02 01 05 02 01 07 02 01 01'),                        // 3 integers
    Buffer.alloc(80, 0x30),                                         // too long
    Buffer.alloc(4),                                                // too short
  ];
  for (const b of bad) assert.throws(() => parseEcdsaSignature(b), DerError, b.toString('hex'));
  assert.throws(() => ecdsaRawToDer(Buffer.alloc(63)), /raw signature length/);
});
