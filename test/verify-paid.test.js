import { test } from 'node:test';
import assert from 'node:assert';
import { Router } from 'express';
import { Wallet } from 'ethers';
import { SiweMessage } from 'siwe';
import nacl from 'tweetnacl';
import bs58 from 'bs58';
import { generateSecretKey, getPublicKey, finalizeEvent } from 'nostr-tools/pure';
import { nip98 } from 'nostr-tools';
import { buildVerifyRouter } from '../src/routes/verify-paid.js';

function mount() {
  const router = buildVerifyRouter();
  const root = Router();
  root.use('/v1/verify', router);
  return router;
}

test('siwe scheme verifies and returns identity', async () => {
  const router = mount();
  const wallet = Wallet.createRandom();
  const msg = new SiweMessage({
    domain: 'localhost',
    address: wallet.address,
    uri: 'http://localhost',
    version: '1',
    chainId: 8453,
    nonce: 'OracleNonce12345678',
  });
  const message = msg.prepareMessage();
  const r = await router._test.dispatch({ scheme: 'siwe', message, signature: await wallet.signMessage(message) });
  assert.equal(r.status, 200);
  assert.equal(r.body.valid, true);
  assert.equal(r.body.identity.address.toLowerCase(), wallet.address.toLowerCase());
  assert.equal(r.body.identity.chainId, 8453);
});

test('nip98 scheme verifies and returns pubkey', async () => {
  const router = mount();
  const sk = generateSecretKey();
  const token = await nip98.getToken(
    'http://localhost/v1/verify',
    'post',
    (e) => finalizeEvent(e, sk),
    true,
  );
  const r = await router._test.dispatch({ scheme: 'nip98', token });
  // no url binding passed -> kind/time/sig only
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.equal(r.body.valid, true);
  assert.equal(r.body.identity.pubkey, getPublicKey(sk));
});

test('solana scheme verifies and returns pubkey', async () => {
  const router = mount();
  const kp = nacl.sign.keyPair();
  const message = 'oracle test message';
  const signature = bs58.encode(
    nacl.sign.detached(new TextEncoder().encode(message), kp.secretKey),
  );
  const r = await router._test.dispatch({ scheme: 'solana', pubkey: bs58.encode(kp.publicKey), message, signature });
  assert.equal(r.status, 200);
  assert.equal(r.body.valid, true);
  assert.equal(r.body.identity.pubkey, bs58.encode(kp.publicKey));
});

test('unknown scheme -> 400 with supported list', async () => {
  const router = mount();
  const r = await router._test.dispatch({ scheme: 'bitcoin' });
  assert.equal(r.status, 400);
  assert.match(r.body.error, /Supported/);
});

test('invalid signature -> valid:false, non-200', async () => {
  const router = mount();
  const kp = nacl.sign.keyPair();
  const other = nacl.sign.keyPair();
  const message = 'm';
  const badSig = bs58.encode(nacl.sign.detached(new TextEncoder().encode(message), other.secretKey));
  const r = await router._test.dispatch({ scheme: 'solana', pubkey: bs58.encode(kp.publicKey), message, signature: badSig });
  assert.ok(r.status >= 400);
  assert.equal(r.body.valid, false);
});
