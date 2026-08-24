import { test } from 'node:test';
import assert from 'node:assert';
import { mkdtempSync, rmSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { createNonceStore } from '../src/nonce-store.js';

// /tmp is read-only on some dev boxes — use a project-local scratch dir.
const scratch = mkdtempSync(join(import.meta.dirname, '.tmp-test-'));
test.after(() => rmSync(scratch, { recursive: true, force: true }));
const tmpPath = (name) => join(scratch, name);

test('issue returns random nonces, consume works exactly once', async () => {
  const store = await createNonceStore(tmpPath('nonces.json'));
  const a = await store.issue();
  const b = await store.issue();
  assert.ok(a !== b, 'nonces must be unique');
  assert.equal(await store.consume(a), true, 'first use wins');
  assert.equal(await store.consume(a), false, 'replay rejected');
  assert.equal(await store.consume('missing'), false);
});

test('persists across restart', async () => {
  const path = tmpPath('nonces.json');
  let store = await createNonceStore(path);
  const n = await store.issue();
  store = await createNonceStore(path); // simulate restart
  assert.equal(await store.consume(n), true);
});

test('expired nonces are rejected', async () => {
  const store = await createNonceStore(tmpPath('n.json'), { ttlMs: 10 });
  const n = await store.issue();
  await new Promise((r) => setTimeout(r, 30));
  assert.equal(await store.consume(n), false);
});

test('file stores hashes, never raw nonces', async () => {
  const path = tmpPath('n.json');
  const store = await createNonceStore(path);
  const n = await store.issue();
  assert.ok(!readFileSync(path, 'utf8').includes(n));
});

test('consume is idempotent under concurrent double-call', async () => {
  const store = await createNonceStore(tmpPath('n.json'));
  const n = await store.issue();
  const [r1, r2] = await Promise.all([store.consume(n), store.consume(n)]);
  assert.deepEqual([r1, r2].filter(Boolean).length, 1, 'exactly one consumer wins');
});

test('claim: client-supplied ids are first-claim-wins', async () => {
  const store = await createNonceStore(tmpPath('claim.json'));
  assert.equal(await store.claim('event-id-1'), true);
  assert.equal(await store.claim('event-id-1'), false, 'second claim of same id rejected');
  assert.equal(await store.claim('event-id-2'), true);
});
