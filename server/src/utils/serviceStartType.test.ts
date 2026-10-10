import { test } from 'node:test';
import assert from 'node:assert/strict';
import { checkServiceStartTypePayload, agentVersionAtLeast } from './serviceStartType';

// set_service_start_type payload check (utils/serviceStartType.ts). Run:
//   cd server
//   node --import ./src/services/deviceKey/test-resolve.mjs --disable-warning=MODULE_TYPELESS_PACKAGE_JSON \
//        --test "src/utils/serviceStartType.test.ts"

test('accepts the four start types on Windows and keeps only name + startType', () => {
  for (const st of ['auto', 'auto_delayed', 'manual', 'disabled']) {
    const r = checkServiceStartTypePayload({ name: 'Spooler', startType: st, extra: 'x' }, 'windows');
    assert.deepEqual(r, { payload: { name: 'Spooler', startType: st } });
  }
  assert.ok('payload' in checkServiceStartTypePayload({ name: 'MSSQL$SQLEXPRESS', startType: 'manual' }, 'windows'));
});

test('refuses bad names and start types', () => {
  const bad: Array<[unknown, string]> = [
    [{ startType: 'auto' }, 'windows'],
    [{ name: '', startType: 'auto' }, 'windows'],
    [{ name: 'a'.repeat(257), startType: 'auto' }, 'windows'],
    [{ name: 'a\nb', startType: 'auto' }, 'windows'],
    [{ name: ' Spooler', startType: 'auto' }, 'windows'],
    [{ name: 'a/b', startType: 'auto' }, 'windows'],
    [{ name: 'Spooler', startType: 'boot' }, 'windows'],
    [{ name: 'Spooler', startType: 42 }, 'windows'],
    [{ name: 'ssh.service', startType: 'auto_delayed' }, 'linux'],
    [{ name: '--now', startType: 'auto' }, 'linux'],
    [{ name: 'ssh;reboot', startType: 'auto' }, 'linux'],
    [null, 'linux'],
  ];
  for (const [p, os] of bad) {
    const r = checkServiceStartTypePayload(p, os);
    assert.ok('error' in r && r.status === 400, JSON.stringify(p));
  }
});

test('Linux systemd units pass; macOS / other are refused with 409', () => {
  assert.ok('payload' in checkServiceStartTypePayload({ name: 'getty@tty1.service', startType: 'disabled' }, 'linux'));
  for (const os of ['macos', 'other', null]) {
    const r = checkServiceStartTypePayload({ name: 'x', startType: 'manual' }, os);
    assert.ok('error' in r && r.status === 409);
  }
});

test('agent version gate', () => {
  assert.equal(agentVersionAtLeast('4.5.103', '4.5.103'), true);
  assert.equal(agentVersionAtLeast('4.5.110', '4.5.103'), true);
  assert.equal(agentVersionAtLeast('4.6.0', '4.5.103'), true);
  assert.equal(agentVersionAtLeast('4.5.102', '4.5.103'), false);
  assert.equal(agentVersionAtLeast(null, '4.5.103'), false);
  assert.equal(agentVersionAtLeast('garbage', '4.5.103'), false);
});
