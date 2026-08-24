import { test } from 'node:test';
import assert from 'node:assert';
import { Wallet } from 'ethers';
import { SiweMessage } from 'siwe';
import { buildSiweRouter } from '../src/routes/auth-siwe.js';
import { createNonceStore } from '../src/nonce-store.js';
import { mkdtempSync } from 'node:fs';
import { join } from 'node:path';

const scratch = mkdtempSync(join(import.meta.dirname, '.tmp-test-'));

const SECRET = 'test-secret-at-least-32-chars-long!!!!';

async function makeRouter() {
  const store = await createNonceStore(join(scratch, `siwe-${Math.random()}.json`));
  return buildSiweRouter({ nonceStore: store, secret: SECRET });
}

async function signedMessage(wallet, nonce) {
  const msg = new SiweMessage({
    domain: 'localhost',
    address: wallet.address,
    statement: 'Sign in to wallet-auth',
    uri: 'http://localhost',
    version: '1',
    chainId: 1,
    nonce,
  });
  const message = msg.prepareMessage();
  return { message, signature: await wallet.signMessage(message) };
}

test('valid SIWE message verifies once; replay fails', async () => {
  const router = await makeRouter();
  const wallet = Wallet.createRandom();

  const { body: nb } = await router._test.nonce();
  const { message, signature } = await signedMessage(wallet, nb.nonce);

  const ok = await router._test.verify({ message, signature });
  assert.equal(ok.status, 200);
  assert.equal(ok.body.valid, true);
  assert.ok(ok.body.token.length > 20);
  assert.equal(ok.body.address.toLowerCase(), wallet.address.toLowerCase());
  assert.equal(ok.body.chainId, 1);

  const replay = await router._test.verify({ message, signature });
  assert.equal(replay.status, 409);
  assert.equal(replay.body.valid, false);
});

test('bad signature does not burn the nonce (retry allowed)', async () => {
  const router = await makeRouter();
  const wallet = Wallet.createRandom();
  const other = Wallet.createRandom();

  const { body: nb } = await router._test.nonce();
  const { message } = await signedMessage(wallet, nb.nonce);
  const wrongSig = await other.signMessage(message); // valid sig, wrong signer

  const bad = await router._test.verify({ message, signature: wrongSig });
  assert.equal(bad.status, 401);

  // Same nonce still usable by the rightful signer.
  const good = await signedMessage(wallet, nb.nonce);
  const ok = await router._test.verify(good);
  assert.equal(ok.body.valid, true);
});

test('unknown/expired nonce rejected', async () => {
  const router = await makeRouter();
  const wallet = Wallet.createRandom();
  const { message, signature } = await signedMessage(wallet, 'neverIssuedNonce12345678'); // alphanumeric per EIP-4361 ABNF
  const r = await router._test.verify({ message, signature });
  assert.equal(r.status, 409);
  assert.equal(r.body.valid, false);
});
