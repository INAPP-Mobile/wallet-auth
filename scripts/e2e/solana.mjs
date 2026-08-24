#!/usr/bin/env node
// E2E: Solana ed25519 sign-in roundtrip against a deployed wallet-auth instance.
// Usage: node scripts/e2e/solana.mjs <base-url>
import nacl from 'tweetnacl';
import bs58 from 'bs58';

const base = process.argv[2]?.replace(/\/$/, '');
if (!base) {
  console.error('usage: node scripts/e2e/solana.mjs <base-url>');
  process.exit(2);
}

const kp = nacl.sign.keyPair();
const nres = await fetch(`${base}/auth/solana/nonce`, { method: 'POST' });
const { nonce } = await nres.json();

const message = `Sign in to wallet-auth\nNonce: ${nonce}`;
const signature = nacl.sign.detached(new TextEncoder().encode(message), kp.secretKey);

const res = await fetch(`${base}/auth/solana/verify`, {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify({
    pubkey: bs58.encode(kp.publicKey),
    message,
    signature: bs58.encode(signature),
  }),
});
const body = await res.json();
assert(body.valid === true, `expected valid:true got ${JSON.stringify(body)}`);
assert(body.pubkey === bs58.encode(kp.publicKey), 'pubkey mismatch');
console.log('✓ Solana verify valid — pubkey:', `${body.pubkey.slice(0, 16)}…`);

// Replay must fail
const replay = await fetch(`${base}/auth/solana/verify`, {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify({
    pubkey: bs58.encode(kp.publicKey),
    message,
    signature: bs58.encode(signature),
  }),
});
assert(replay.status === 401, `replay should be 401, got ${replay.status}`);
console.log('✓ Solana replay rejected (401)');

function assert(cond, msg) {
  if (!cond) {
    console.error('FAIL:', msg);
    process.exit(1);
  }
}
