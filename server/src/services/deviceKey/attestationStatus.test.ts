import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  createStatusListStore, parseStatusList, normaliseSerial, STATUS_FRESH_MS, STATUS_MAX_AGE_MS,
  type StatusStoreOptions,
} from './attestationStatus';

// Attestation step 4: Google status list,
// 24 h in memory and in a file, a copy up to 7 days old when Google is
// unreachable, nothing beyond (fail closed).

const LIST = {
  entries: {
    '2c8cdddfd5e03bfc': { status: 'REVOKED', reason: 'KEY_COMPROMISE' },
    '0C8CDDDFD5E03BFD': { status: 'SUSPENDED' },
    '6681152659205225093': { status: 'REVOKED', reason: 'KEY_COMPROMISE' },
    'zz-not-hex': { status: 'REVOKED' },
    'abc': { status: 'SOMETHING_ELSE' },
  },
};

type FetchImpl = NonNullable<StatusStoreOptions['fetchImpl']>;

function fakeFetch(behaviour: { ok?: boolean; body?: unknown; throws?: boolean; status?: number }, calls: { n: number }): FetchImpl {
  return async () => {
    calls.n++;
    if (behaviour.throws) throw new Error('ECONNREFUSED');
    return {
      ok: behaviour.ok ?? true,
      status: behaviour.status ?? 200,
      text: async () => (typeof behaviour.body === 'string' ? behaviour.body : JSON.stringify(behaviour.body ?? LIST)),
      headers: { get: () => null },
    };
  };
}

function tmpFile(): string {
  return path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'obli-status-')), 'device-keys', 'attestation-status.json');
}

test('parseStatusList keeps REVOKED / SUSPENDED hex serials, normalised', () => {
  const m = parseStatusList(LIST);
  assert.ok(m);
  assert.deepEqual([...m.entries()].sort(), [
    ['2c8cdddfd5e03bfc', 'REVOKED'],
    ['6681152659205225093', 'REVOKED'],
    ['c8cdddfd5e03bfd', 'SUSPENDED'],
  ]);
  assert.equal(parseStatusList(null), null);
  assert.equal(parseStatusList({ entries: [] }), null);
  assert.equal(parseStatusList({}), null);
  assert.equal(normaliseSerial('000A'), 'a');
  assert.equal(normaliseSerial('0'), '0');
});

test('fresh download, then served from memory for 24 h, then re-downloaded', async () => {
  let now = 1_800_000_000_000;
  const calls = { n: 0 };
  const store = createStatusListStore({ filePath: null, now: () => now, fetchImpl: fakeFetch({}, calls) });
  const a = await store.get();
  assert.ok(a);
  assert.equal(a.fetchedAt, now);
  assert.equal(a.entries.get('2c8cdddfd5e03bfc'), 'REVOKED');
  assert.equal(calls.n, 1);
  now += STATUS_FRESH_MS - 1000;
  await store.get();
  assert.equal(calls.n, 1, 'cached');
  now += 2000;
  const b = await store.get();
  assert.equal(calls.n, 2, 're-downloaded after 24 h');
  assert.equal(b?.fetchedAt, now);
});

test('Google unreachable: a copy up to 7 days old is served, older → null (fail closed)', async () => {
  let now = 1_800_000_000_000;
  const calls = { n: 0 };
  const behaviour: { throws?: boolean } = {};
  const store = createStatusListStore({ filePath: null, now: () => now, fetchImpl: fakeFetch(behaviour, calls), retryAfterFailureMs: 0 });
  assert.ok(await store.get());
  behaviour.throws = true;
  now += 3 * 86_400_000;
  const stale = await store.get();
  assert.ok(stale, '3-day-old copy still served');
  assert.equal(stale.fetchedAt, 1_800_000_000_000);
  now = 1_800_000_000_000 + STATUS_MAX_AGE_MS + 1000;
  assert.equal(await store.get(), null, 'older than 7 days → null');
  assert.equal(await store.refresh(), false);
});

test('no copy at all and Google unreachable → null', async () => {
  const calls = { n: 0 };
  const store = createStatusListStore({ filePath: null, fetchImpl: fakeFetch({ throws: true }, calls) });
  assert.equal(await store.get(), null);
  const bad = createStatusListStore({ filePath: null, fetchImpl: fakeFetch({ body: '{"not":"a list"}' }, { n: 0 }) });
  assert.equal(await bad.get(), null, 'a document that is not a status list is refused');
  const http = createStatusListStore({ filePath: null, fetchImpl: fakeFetch({ ok: false, status: 503 }, { n: 0 }) });
  assert.equal(await http.get(), null);
  const huge = createStatusListStore({ filePath: null, fetchImpl: fakeFetch({ body: 'x'.repeat(9 * 1024 * 1024) }, { n: 0 }) });
  assert.equal(await huge.get(), null, 'oversized body refused');
});

test('after a failure, no retry storm (retry-after-failure delay)', async () => {
  let now = 1_800_000_000_000;
  const calls = { n: 0 };
  const store = createStatusListStore({ filePath: null, now: () => now, fetchImpl: fakeFetch({ throws: true }, calls), retryAfterFailureMs: 60_000 });
  await store.get();
  await store.get();
  assert.equal(calls.n, 1);
  now += 61_000;
  await store.get();
  assert.equal(calls.n, 2);
});

test('file cache: written on download, read after a restart, ignored when dated in the future or unreadable', async () => {
  const file = tmpFile();
  let now = 1_800_000_000_000;
  const store = createStatusListStore({ filePath: file, now: () => now, fetchImpl: fakeFetch({}, { n: 0 }) });
  assert.ok(await store.get());
  assert.ok(fs.existsSync(file));
  const onDisk = JSON.parse(fs.readFileSync(file, 'utf8')) as { fetchedAt: string; list: unknown };
  assert.equal(Date.parse(onDisk.fetchedAt), now);

  // "Restart" 2 days later, Google down: the file copy is served.
  now += 2 * 86_400_000;
  const restarted = createStatusListStore({ filePath: file, now: () => now, fetchImpl: fakeFetch({ throws: true }, { n: 0 }) });
  const v = await restarted.get();
  assert.ok(v);
  assert.equal(v.fetchedAt, 1_800_000_000_000);
  assert.equal(v.entries.get('c8cdddfd5e03bfd'), 'SUSPENDED');

  // Dated in the future (edited file / clock change): not trusted.
  fs.writeFileSync(file, JSON.stringify({ fetchedAt: new Date(now + 86_400_000).toISOString(), list: LIST }));
  const future = createStatusListStore({ filePath: file, now: () => now, fetchImpl: fakeFetch({ throws: true }, { n: 0 }) });
  assert.equal(await future.get(), null);

  fs.writeFileSync(file, '{broken');
  const broken = createStatusListStore({ filePath: file, now: () => now, fetchImpl: fakeFetch({ throws: true }, { n: 0 }) });
  assert.equal(await broken.get(), null);
});

test('concurrent get() share one download', async () => {
  const calls = { n: 0 };
  const store = createStatusListStore({ filePath: null, fetchImpl: fakeFetch({}, calls) });
  const [a, b, c] = await Promise.all([store.get(), store.get(), store.get()]);
  assert.ok(a && b && c);
  assert.equal(calls.n, 1);
});
