#!/usr/bin/env node
// E2E: SIWE sign-in roundtrip against a deployed wallet-auth instance.
// Usage: node scripts/e2e/siwe.mjs <base-url>
import { Wallet } from 'ethers';
import { SiweMessage } from 'siwe';

const base = process.argv[2]?.replace(/\/$/, '');
if (!base) {
  console.error('usage: node scripts/e2e/siwe.mjs <base-url>');
  process.exit(2);
}

function assert(cond, msg) {
  if (!cond) {
    console.error('FAIL:', msg);
    process.exit(1);
  }
}

const wallet = Wallet.createRandom();
const nres = await fetch(`${base}/auth/siwe/nonce`, { method: 'POST' });
const { nonce } = await nres.json();

const msg = new SiweMessage({
  domain: new URL(base).hostname,
  address: wallet.address,
  statement: 'wallet-auth E2E',
  uri: base,
  version: '1',
  chainId: 8453,
  nonce,
});
const message = msg.prepareMessage();
const signature = await wallet.signMessage(message);

const res = await fetch(`${base}/auth/siwe/verify`, {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ message, signature }),
});
const body = await res.json();
assert(body.valid === true, `expected valid:true got ${JSON.stringify(body)}`);
assert(body.address.toLowerCase() === wallet.address.toLowerCase(), 'address mismatch');
assert(body.chainId === 8453, `chainId mismatch: ${body.chainId}`);
console.log('✓ SIWE verify valid — address:', `${body.address.slice(0, 10)}…`);

// Replay must fail
const replay = await fetch(`${base}/auth/siwe/verify`, {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ message, signature }),
});
assert(replay.status === 409, `replay should be 409, got ${replay.status}`);
console.log('✓ SIWE replay rejected (409)');
