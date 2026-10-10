import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {
  buildPayload, normaliseOrigin, tryNormaliseOrigin, sha256hex, spkiFingerprint, enrolKeyRef,
  fromB64url, fromB64, b64url, isUuid, type PayloadInput,
} from './payload';

// Signed payload — test vectors V1 / V2.
// The ECDSA signatures of the vectors are
// VERIFIED (never compared as bytes: ECDSA is randomised).

const KEY_ID = '6f1c2d4e-8a8b-4c1e-9d2f-0a1b2c3d4e5f';

const V1: PayloadInput = {
  purpose: 'stepup',
  origin: 'https://obliance.example.com',
  userId: 42,
  keyRef: KEY_ID,
  challenges: [{
    challengeId: '1b4e28ba-2fa1-41d2-883f-0016d3cca427',
    nonce: Uint8Array.from({ length: 32 }, (_, i) => i),
    action: 'command.reboot',
    binding: sha256hex('example'),
    exp: 1790000120,
  }],
};
const V1_TEXT = [
  'obli-devkey-v1',
  'purpose:stepup',
  'origin:https://obliance.example.com',
  'user:42',
  'key:6f1c2d4e-8a8b-4c1e-9d2f-0a1b2c3d4e5f',
  'count:1',
  'challenge:1b4e28ba-2fa1-41d2-883f-0016d3cca427',
  'nonce:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8',
  'action:command.reboot',
  'binding:50d858e0985ecc7f60418aaf0cc5ab587f42c2570a884095a9e8ccacd0f6545c',
  'exp:1790000120',
].join('\n');
const V1_SHA = '5d75a9e6d6cb5dfcc0d2d9ef7fc7348a5c59fa428ece8b07f11d769fe7695fc2';
const V1_SPKI = 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEO6H1i3djvlx3Y3QnxD9qrYXeL/aREhQFgpFHkpHxU8Mmx2pp9AyQNrB//ENPMpE+Ve5VvKU0+5kXma3m+toVxg==';
const V1_FP = '6145231539132278683d273815557b66512d14d4fb6b093867122cc38b2b5770';
const V1_SIG = 'MEYCIQC/VWdsOwkNPoBmjkWg/yJWksa7HvMYqrJbp19TJefv4gIhALhNJMRDnHhOwotAVnDT6eLY+aR/Siq6JMZ1VCBD56OJ';

const V2: PayloadInput = {
  purpose: 'stepup',
  origin: 'https://obliance.example.com:8443',
  userId: 42,
  keyRef: KEY_ID,
  challenges: [
    {
      challengeId: '0f8fad5b-d9cb-469f-a165-70867728950e',
      nonce: Buffer.alloc(32, 0xab),
      action: 'command.reboot',
      binding: '42e94dc1a0b1fca10ff77a22a2c4ec22ae1fb558ffcd31f9971da0c3b8c6b5f4',
      exp: 1790000200,
    },
    {
      challengeId: '7c9e6679-7425-40de-944b-e07fc1f90ae7',
      nonce: 'zc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc0', // string form accepted
      action: 'command.reboot',
      binding: 'd1cfff2ae8c88d7fadb9f02e95153f8c71d8d29d9cf4b86ec41247da70908405',
      exp: 1790000201,
    },
  ],
};
const V2_TEXT = [
  'obli-devkey-v1',
  'purpose:stepup',
  'origin:https://obliance.example.com:8443',
  'user:42',
  'key:6f1c2d4e-8a8b-4c1e-9d2f-0a1b2c3d4e5f',
  'count:2',
  'challenge:0f8fad5b-d9cb-469f-a165-70867728950e',
  'nonce:q6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6s',
  'action:command.reboot',
  'binding:42e94dc1a0b1fca10ff77a22a2c4ec22ae1fb558ffcd31f9971da0c3b8c6b5f4',
  'exp:1790000200',
  'challenge:7c9e6679-7425-40de-944b-e07fc1f90ae7',
  'nonce:zc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc0',
  'action:command.reboot',
  'binding:d1cfff2ae8c88d7fadb9f02e95153f8c71d8d29d9cf4b86ec41247da70908405',
  'exp:1790000201',
].join('\n');
const V2_SHA = 'eeb4ef7a7d8eb846fbb7aa67afe62d280c71810f5cfd54106395f16f878b7cfb';
const V2_SPKI = 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEC8l1DDFcl+02mbjMgVVJGGAfDvqE7NZdjWWbj0n1v9A29R/hz0CAPWnt9UNheUOo+m3Cm62qxTOPALLXVW0npg==';
const V2_SIG = 'MEUCIBUBAT1EvUVDSgblSbU7jfUCDVzhzoxgvJ+CRpp+l4rRAiEAlgDjiTKua6d6K55etd0ygmMnyC8jP4xwLZQgklo2vPU=';

function verifies(payload: string, spkiB64: string, sigB64: string): boolean {
  const key = crypto.createPublicKey({ key: Buffer.from(spkiB64, 'base64'), format: 'der', type: 'spki' });
  return crypto.verify('sha256', Buffer.from(payload, 'utf8'), { key, dsaEncoding: 'der' }, Buffer.from(sigB64, 'base64'));
}

test('V1: canonical text, sha256 and the reference signature', () => {
  const p = buildPayload(V1);
  assert.equal(p, V1_TEXT);
  assert.equal(sha256hex(p), V1_SHA);
  assert.ok(!p.endsWith('\n'), 'no trailing newline');
  assert.ok(verifies(p, V1_SPKI, V1_SIG));
  assert.equal(spkiFingerprint(Buffer.from(V1_SPKI, 'base64')), V1_FP);
  assert.equal(enrolKeyRef(Buffer.from(V1_SPKI, 'base64')), 'spki-sha256:' + V1_FP);
  // One changed byte breaks it.
  assert.ok(!verifies(p.replace('exp:1790000120', 'exp:1790000121'), V1_SPKI, V1_SIG));
});

test('V2: bulk payload (count 2, non-default port), sha256 and signature', () => {
  const p = buildPayload(V2);
  assert.equal(p, V2_TEXT);
  assert.equal(sha256hex(p), V2_SHA);
  assert.ok(verifies(p, V2_SPKI, V2_SIG));
  assert.ok(!verifies(p, V1_SPKI, V2_SIG), 'another key does not verify');
});

test('payload: purposes login and enrol, "-" for absent action / binding', () => {
  const login = buildPayload({ ...V1, purpose: 'login', challenges: [{ ...V1.challenges[0], action: null, binding: null }] });
  assert.match(login, /\npurpose:login\n/);
  assert.match(login, /\naction:-\nbinding:-\nexp:1790000120$/);
  const dash = buildPayload({ ...V1, purpose: 'login', challenges: [{ ...V1.challenges[0], action: '-', binding: '-' }] });
  assert.equal(dash, login);
  const enrol = buildPayload({
    ...V1, purpose: 'enrol', keyRef: 'spki-sha256:' + V1_FP,
    challenges: [{ ...V1.challenges[0], action: 'device_key.enrol', binding: null }],
  });
  assert.match(enrol, /\nkey:spki-sha256:6145231539132278683d273815557b66512d14d4fb6b093867122cc38b2b5770\n/);
  assert.match(enrol, /\naction:device_key\.enrol\nbinding:-\n/);
});

test('payload refuses \\r and \\n in every field', () => {
  const c = V1.challenges[0];
  const bad: PayloadInput[] = [
    { ...V1, origin: 'https://obliance.example.com\n' },
    { ...V1, origin: 'https://obliance.example.com\r' },
    { ...V1, keyRef: KEY_ID + '\n' },
    { ...V1, challenges: [{ ...c, challengeId: c.challengeId + '\r' }] },
    { ...V1, challenges: [{ ...c, action: 'command.reboot\nexp:1' }] },
    { ...V1, challenges: [{ ...c, action: 'command.reboot\r' }] },
    { ...V1, challenges: [{ ...c, binding: '50d858e0985ecc7f60418aaf0cc5ab587f42c2570a884095a9e8ccacd0f6545c\n' }] },
    { ...V1, challenges: [{ ...c, nonce: 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8\n' }] },
  ];
  for (const b of bad) assert.throws(() => buildPayload(b), /device-key payload/);
});

test('payload refuses count 0 and 51 (accepts 1 and 50)', () => {
  const c = V1.challenges[0];
  const many = (n: number) => Array.from({ length: n }, (_, i) => ({
    ...c, challengeId: `00000000-0000-4000-8000-${String(i).padStart(12, '0')}`,
  }));
  assert.throws(() => buildPayload({ ...V1, challenges: [] }), /count/);
  assert.throws(() => buildPayload({ ...V1, challenges: many(51) }), /count/);
  assert.match(buildPayload({ ...V1, challenges: many(50) }), /\ncount:50\n/);
});

test('payload refuses a non-ASCII (IDN) origin, a non-normalised origin and malformed fields', () => {
  assert.throws(() => buildPayload({ ...V1, origin: 'https://obliänce.example.com' }), /origin/);
  assert.throws(() => buildPayload({ ...V1, origin: 'https://xn--oblince-cxa.example.com/' }), /origin/);
  assert.throws(() => buildPayload({ ...V1, origin: 'https://Obliance.example.com' }), /origin/);
  assert.throws(() => buildPayload({ ...V1, origin: 'https://obliance.example.com:443' }), /origin/);
  assert.throws(() => buildPayload({ ...V1, userId: 0 }), /user/);
  assert.throws(() => buildPayload({ ...V1, userId: 4.2 }), /user/);
  assert.throws(() => buildPayload({ ...V1, keyRef: 'not-a-uuid' }), /key/);
  assert.throws(() => buildPayload({ ...V1, keyRef: KEY_ID.toUpperCase() }), /key/);
  const c = V1.challenges[0];
  assert.throws(() => buildPayload({ ...V1, challenges: [{ ...c, binding: 'ABC' }] }), /binding/);
  assert.throws(() => buildPayload({ ...V1, challenges: [{ ...c, action: 'has space' }] }), /action/);
  assert.throws(() => buildPayload({ ...V1, challenges: [{ ...c, exp: 0 }] }), /exp/);
  assert.throws(() => buildPayload({ ...V1, challenges: [{ ...c, nonce: 'AAEC==' }] }), /nonce/);
  assert.throws(() => buildPayload({ ...V1, purpose: 'other' as never }), /purpose/);
  // xn-- (punycode, ASCII) is accepted as such: the app refuses IDN before.
  assert.doesNotThrow(() => buildPayload({ ...V1, origin: 'https://xn--oblince-cxa.example.com' }));
});

test('normaliseOrigin', () => {
  assert.equal(normaliseOrigin('https://Obliance.Example.com:443/x'), 'https://obliance.example.com');
  assert.equal(normaliseOrigin('HTTPS://OBLIANCE.EXAMPLE.COM'), 'https://obliance.example.com');
  assert.equal(normaliseOrigin('https://obliance.example.com:8443/'), 'https://obliance.example.com:8443');
  assert.equal(normaliseOrigin('http://10.0.0.5:80/api?x=1'), 'http://10.0.0.5');
  assert.equal(normaliseOrigin('http://10.0.0.5:3000'), 'http://10.0.0.5:3000');
  assert.equal(normaliseOrigin('https://[::1]:8443'), 'https://[::1]:8443');
  for (const bad of ['', 'obliance.example.com', 'ftp://x.example', 'https://user:pw@x.example', 'https://obliänce.example.com', 'https:// x', 'https://x.example\n']) {
    assert.throws(() => normaliseOrigin(bad), /origin/, bad);
    assert.equal(tryNormaliseOrigin(bad), null);
  }
});

test('base64 helpers are strict', () => {
  const b = crypto.randomBytes(32);
  assert.deepEqual(fromB64url(b64url(b)), b);
  assert.equal(fromB64url(b64url(b) + '='), null, 'padding refused');
  assert.equal(fromB64url('a+b/'), null, 'standard alphabet refused');
  assert.deepEqual(fromB64url('AA'), Buffer.from([0]));
  assert.equal(fromB64url('AF'), null, 'non-canonical trailing bits refused');
  assert.deepEqual(fromB64(b.toString('base64')), b);
  assert.equal(fromB64('AAE'), null, 'missing padding refused');
  assert.equal(fromB64('AA-_'), null, 'url alphabet refused');
  assert.equal(fromB64('A'.repeat(204), 200), null, 'length cap');
  assert.ok(isUuid(KEY_ID));
  assert.ok(!isUuid(KEY_ID.toUpperCase()));
});
