import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {
  computeBinding, bindingPreimage, canonicalJson, sortedUniqueDeviceIds, sha256hex, deriveBindingKey,
  BINDING_VERSION, type BindingInput,
} from './payload';
import { captureStepUpProof } from '../../middleware/captureStepUpProof';

// Request binding — test vectors B1..B6
// (the server computes, the app copies).
// obli-binding-v2: the body digest is HMAC-SHA256 under a server secret
// (never stored in the database), not a plain sha256 — the body of some bound
// requests carries a password. Vectors with the fixed test key below; they
// were cross-checked with an independent implementation (Python hmac/hashlib).

/** Fixed TEST body key: bytes 0x00..0x1f. */
const KEY = Uint8Array.from({ length: 32 }, (_, i) => i);

const B1: BindingInput = {
  method: 'POST', originalUrl: '/api/commands', tenantId: 3, actionKey: 'command.reboot',
  deviceIds: [17], body: { type: 'reboot', deviceId: 17, payload: {} },
};
const B3: BindingInput = {
  method: 'PUT', originalUrl: '/api/restrictions', tenantId: 5, actionKey: 'tenant.manage_restrictions',
  deviceIds: [], body: { restrictions: { 'command.reboot': 'sensitive' } },
};
const B5: BindingInput = {
  method: 'POST', originalUrl: '/api/profile/ssh-keys', tenantId: null, actionKey: 'profile.ssh_key_add',
  deviceIds: [], body: { name: 'laptop', publicKey: 'ssh-ed25519 AAAA' },
};
const B6: BindingInput = {
  method: 'POST', originalUrl: '/api/scripts/5/execute?dryRun=0', tenantId: 3, actionKey: 'script.execute_manual',
  deviceIds: [18, 17, 18], body: { deviceIds: [18, 17, 18], scriptId: 5, params: { b: 2, a: 1 } },
};
const cb = (b: BindingInput) => computeBinding(b, KEY);

test('B1..B6 (obli-binding-v2, test key 00..1f)', () => {
  assert.equal(BINDING_VERSION, 'obli-binding-v2');
  assert.equal(canonicalJson(B1.body), '{"deviceId":17,"payload":{},"type":"reboot"}');
  assert.equal(
    crypto.createHmac('sha256', KEY).update(canonicalJson(B1.body)).digest('hex'),
    '959045184ddd703187f481f2b4f9b09950bc791388a2ce1b59d6e289c8caec81',
  );
  assert.equal(cb(B1), '4fb7e7a5a5d46cc7439230a4f0987bdf2a9a900d8846d6feedd7961541594604');
  assert.equal(cb({ ...B1, tenantId: 1 }), 'd7ca5f97e4550d5d28f0d002483be7c1d8267607994d6f11f2e107a69e9f573b');
  assert.equal(canonicalJson(B3.body), '{"restrictions":{"command.reboot":"sensitive"}}');
  assert.equal(cb(B3), '1f5f52c76bce4a0f2465b91a2d3f015963d7eda2767afe1a64098cf164ac0eb9');
  assert.equal(cb({ ...B3, tenantId: 6 }), '3004c1b763f85612b55e5e69b72b88411facdd737eba3da3aa4efa8c2bceeb42');
  assert.equal(canonicalJson(B5.body), '{"name":"laptop","publicKey":"ssh-ed25519 AAAA"}');
  assert.equal(cb(B5), 'cc97c2cc35d5605432b730fdf22d8ccedcbe41598cc0868635ff7f0c94933902');
  assert.equal(canonicalJson(B6.body), '{"deviceIds":[18,17,18],"params":{"a":1,"b":2},"scriptId":5}');
  assert.equal(cb(B6), '1e5d0853d55a64255786afb6b2d5f2affff94ebbaffbf770a09e33ff6a61fddf');
  assert.equal(
    bindingPreimage(B6, KEY),
    'obli-binding-v2\nPOST\n/api/scripts/5/execute?dryRun=0\n3\nscript.execute_manual\n17,18\n14868e2d6f4e7e71a52595a71dc604c51a76b4d6b371a36f92b176876afc65a5',
  );
});

test('deriveBindingKey: HKDF-SHA256 (empty salt, info "obli-binding-v2"), 32 bytes', () => {
  assert.equal(deriveBindingKey('obli-binding-test-secret').toString('hex'), '66be094bc4f35d828b3fa600a4a3b3fee41028ce0e958d36d710443d8692c692');
  assert.equal(deriveBindingKey('obli-binding-test-secret').length, 32);
  assert.notEqual(deriveBindingKey('another-secret').toString('hex'), deriveBindingKey('obli-binding-test-secret').toString('hex'));
  assert.throws(() => deriveBindingKey(''), /empty/);
});

test('the body digest is keyed: no plain sha256 of the body, another key → another binding, no key → refused', () => {
  const pre = bindingPreimage(B1, KEY);
  assert.ok(!pre.endsWith(sha256hex(canonicalJson(B1.body))), 'v1 plain sha256 of the body is gone');
  assert.notEqual(computeBinding(B1, deriveBindingKey('secret-A')), computeBinding(B1, deriveBindingKey('secret-B')));
  assert.throws(() => computeBinding(B1, new Uint8Array(8)), /body key/);
  assert.throws(() => computeBinding(B1, undefined as unknown as Uint8Array), /body key/);
});

test('a password in the bound body is not recoverable from the binding without the server key', () => {
  // PUT /api/users/42/password {password} (the attack scenario): an
  // attacker holding only the database row (binding_hash) and every other
  // field of the preimage cannot test guesses without the key.
  const body = { password: 'Acme-Winter2026!' };
  const req: BindingInput = { method: 'PUT', originalUrl: '/api/users/42/password', tenantId: 3, actionKey: 'tenant.manage_users', deviceIds: [], body };
  const stored = computeBinding(req, deriveBindingKey('the-real-server-secret-0123456789'));
  const unkeyedGuess = sha256hex(['obli-binding-v2', 'PUT', '/api/users/42/password', '3', 'tenant.manage_users', '', sha256hex(canonicalJson(body))].join('\n'));
  assert.notEqual(stored, unkeyedGuess, 'the right guess, hashed without the key, does not match');
  const wrongKeyGuess = computeBinding(req, deriveBindingKey('change-this-secret'));
  assert.notEqual(stored, wrongKeyGuess);
});

test('tenant: null / undefined → "-", and a tenant switch changes the binding', () => {
  assert.match(bindingPreimage(B5, KEY), /^obli-binding-v2\nPOST\n\/api\/profile\/ssh-keys\n-\n/);
  assert.equal(cb({ ...B5, tenantId: undefined }), cb(B5));
  assert.notEqual(cb({ ...B5, tenantId: 1 }), cb(B5));
});

test('deviceIds: numeric sort, duplicates removed, non-integers dropped', () => {
  assert.deepEqual(sortedUniqueDeviceIds([18, 17, 18, 2, 100]), [2, 17, 18, 100]);
  assert.deepEqual(sortedUniqueDeviceIds(['18', 17, 1.5, null, 'x', NaN]), [17, 18]);
  assert.deepEqual(sortedUniqueDeviceIds(undefined), []);
  assert.equal(cb({ ...B6, deviceIds: [17, 18] }), cb(B6));
  assert.equal(cb({ ...B1, deviceIds: [17, 17] }), cb(B1));
  assert.notEqual(cb({ ...B1, deviceIds: [17, 18] }), cb(B1));
  assert.notEqual(cb({ ...B1, deviceIds: [] }), cb(B1));
});

test('body: key order indifferent (recursive), array order significant', () => {
  const reordered = { payload: {}, deviceId: 17, type: 'reboot' };
  assert.equal(cb({ ...B1, body: reordered }), cb(B1));
  assert.equal(
    cb({ ...B6, body: { scriptId: 5, params: { a: 1, b: 2 }, deviceIds: [18, 17, 18] } }),
    cb(B6),
  );
  assert.notEqual(cb({ ...B6, body: { ...(B6.body as object), deviceIds: [17, 18, 18] } }), cb(B6));
  assert.notEqual(cb({ ...B1, body: { ...(B1.body as object), deviceId: 18 } }), cb(B1));
});

test('canonicalJson: undefined ignored, toJSON honoured, scalars via JSON.stringify', () => {
  assert.equal(canonicalJson({ b: undefined, a: 1 }), '{"a":1}');
  assert.equal(canonicalJson([1, undefined, 'x']), '[1,null,"x"]');
  assert.equal(canonicalJson(undefined), 'null');
  assert.equal(canonicalJson(null), 'null');
  assert.equal(canonicalJson({ d: new Date('2026-09-26T00:00:00Z') }), '{"d":"2026-09-26T00:00:00.000Z"}');
  assert.equal(canonicalJson({ s: 'é"\n', n: 1.5, t: true }), '{"n":1.5,"s":"é\\"\\n","t":true}');
  assert.throws(() => canonicalJson({ big: 1n }), /bigint/);
});

test('method case, URL with query, line breaks refused', () => {
  assert.equal(cb({ ...B1, method: 'post' }), cb(B1));
  assert.notEqual(cb({ ...B1, originalUrl: '/api/commands?x=1' }), cb(B1));
  assert.throws(() => cb({ ...B1, originalUrl: '/api/commands\nPOST' }), /line break/);
  assert.throws(() => cb({ ...B1, actionKey: 'command.reboot\r' }), /line break/);
});

test('proofs never enter the binding (captureStepUpProof strips them first)', () => {
  const withProofs = {
    type: 'reboot', deviceId: 17, payload: {},
    twoFactorCode: '123456', trustIp: true, stepUpPassword: 'secret',
    deviceAssertion: { v: 1, keyId: 'x', challengeIds: ['y'], signature: 'z' },
    deviceBulkId: '0f8fad5b-d9cb-469f-a165-70867728950e',
  };
  const req = { body: withProofs } as unknown as Parameters<typeof captureStepUpProof>[0];
  let nextCalled = false;
  captureStepUpProof(req, {} as never, () => { nextCalled = true; });
  assert.ok(nextCalled);
  assert.equal(cb({ ...B1, body: req.body }), cb(B1));
  assert.equal(req.stepUpProof?.twoFactorCode, '123456');
  assert.equal(req.stepUpProof?.deviceBulkId, '0f8fad5b-d9cb-469f-a165-70867728950e');
  // First send (no proof) and second send (proofs) bind identically.
  const first = { body: { type: 'reboot', deviceId: 17, payload: {} } } as unknown as Parameters<typeof captureStepUpProof>[0];
  captureStepUpProof(first, {} as never, () => undefined);
  assert.equal(cb({ ...B1, body: first.body }), cb({ ...B1, body: req.body }));
});
