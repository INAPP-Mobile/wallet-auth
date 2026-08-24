import { test } from 'node:test';
import assert from 'node:assert';
import nacl from 'tweetnacl';
import bs58 from 'bs58';
import { buildSolanaRouter } from '../src/routes/auth-solana.js';
import { createNonceStore } from '../src/nonce-store.js';
import { mkdtempSync } from 'node:fs';
import { join } from 'node:path';

const scratch = mkdtempSync(join(import.meta.dirname, '.tmp-test-'));
const SECRET = 'test-secret-at-least-32-chars-long!!!!';

async function makeRouter() {
  const store = await createNonceStore(join(scratch, `sol-${Math.random()}.json`));
  return buildSolanaRouter({ nonceStore: store, secret: SECRET });
}

function signMessage(keypair, nonce) {
  const message = `Sign in to wallet-auth\nNonce: ${nonce}`;
  const sig = nacl.sign.detached(new TextEncoder().encode(message), keypair.secretKey);
  return { pubkey: bs58.encode(keypair.publicKey), message, signature: bs58.encode(sig) };
}

test('valid ed25519 signature verifies once; replay fails', async () => {
  const router = await makeRouter();
  const kp = nacl.sign.keyPair();

  const nb = (await router._test.nonce()).body;
  const payload = signMessage(kp, nb.nonce);

  const ok = await router._test.verify(payload);
  assert.equal(ok.status, 200);
  assert.equal(ok.body.valid, true);
  assert.equal(ok.body.pubkey, payload.pubkey);

  const replay = await router._test.verify(payload);
  assert.equal(replay.status, 401); // nonce consumed
});

test('bad signature does not burn the nonce', async () => {
  const router = await makeRouter();
  const kp = nacl.sign.keyPair();
  const other = nacl.sign.keyPair();

  const nb = (await router._test.nonce()).body;
  const payload = signMessage(kp, nb.nonce);
  const forged = { ...payload, signature: bs58.encode(nacl.sign.detached(new TextEncoder().encode(payload.message), other.secretKey)) };

  const bad = await router._test.verify(forged);
  assert.equal(bad.status, 401);
  assert.match(bad.body.error, /Signature invalid/);

  // Rightful signer can still use the same challenge.
  const ok = await router._test.verify(payload);
  assert.equal(ok.body.valid, true);
});

test('message without issued nonce rejected', async () => {
  const router = await makeRouter();
  const kp = nacl.sign.keyPair();
  const payload = signMessage(kp, 'noSuchNonce000');
  const r = await router._test.verify(payload);
  assert.equal(r.status, 401);
});

test('invalid base58 pubkey rejected as malformed', async () => {
  const router = await makeRouter();
  const r = await router._test.verify({ pubkey: '!!!not-base58!!!', message: 'x Nonce: y', signature: 'aa' });
  assert.equal(r.status, 400);
});
