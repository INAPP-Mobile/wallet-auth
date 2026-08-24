import { test } from 'node:test';
import assert from 'node:assert';
import { generateSecretKey, getPublicKey, finalizeEvent } from 'nostr-tools/pure';
import { nip98 } from 'nostr-tools';
import { buildNostrRouter } from '../src/routes/auth-nostr.js';
import { createNonceStore } from '../src/nonce-store.js';
import { mkdtempSync } from 'node:fs';
import { join } from 'node:path';

const scratch = mkdtempSync(join(import.meta.dirname, '.tmp-test-'));
const SECRET = 'test-secret-at-least-32-chars-long!!!!';
const URL_BASE = 'http://localhost/auth/nostr';

async function makeRouter(publicUrl) {
  const store = await createNonceStore(join(scratch, `nostr-${Math.random()}.json`));
  return buildNostrRouter({ nonceStore: store, secret: SECRET, publicUrl });
}

async function makeToken(sk) {
  return nip98.getToken(URL_BASE, 'post', (e) => finalizeEvent(e, sk), true);
}

test('valid NIP-98 event verifies once; replay fails', async () => {
  const router = await makeRouter();
  const sk = generateSecretKey();
  const token = await makeToken(sk);

  const ok = await router._test.verify({ token, url: URL_BASE });
  assert.equal(ok.status, 200);
  assert.equal(ok.body.valid, true);
  assert.equal(ok.body.pubkey, getPublicKey(sk));
  assert.ok(ok.body.token.length > 20);

  const replay = await router._test.verify({ token, url: URL_BASE });
  assert.equal(replay.status, 409);
});

test('each key verifies against its own pubkey', async () => {
  const router = await makeRouter();
  const sk2 = generateSecretKey();
  const ok = await router._test.verify({ token: await makeToken(sk2), url: URL_BASE });
  assert.equal(ok.body.valid, true);
  assert.equal(ok.body.pubkey, getPublicKey(sk2));
});

test('tampered token rejected', async () => {
  const router = await makeRouter();
  const sk = generateSecretKey();
  const raw = await makeToken(sk);
  const b64 = raw.replace(/^Nostr\s+/i, '');
  const mutated = 'Nostr ' + b64.slice(0, -4) + 'AAAA';
  const r = await router._test.verify({ token: mutated, url: URL_BASE });
  assert.ok(r.status >= 400);
  assert.equal(r.body.valid, false);
});

test('garbage token rejected as malformed', async () => {
  const router = await makeRouter();
  const r = await router._test.verify({ token: 'not-a-token', url: URL_BASE });
  assert.ok(r.status >= 400);
});
