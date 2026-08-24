#!/usr/bin/env node
// E2E: NIP-98 sign-in roundtrip against a deployed wallet-auth instance.
// Usage: node scripts/e2e/nip98.mjs <base-url>
import { generateSecretKey, getPublicKey, finalizeEvent } from 'nostr-tools/pure';

const base = process.argv[2]?.replace(/\/$/, '');
if (!base) {
  console.error('usage: node scripts/e2e/nip98.mjs <base-url>');
  process.exit(2);
}

function assert(cond, msg) {
  if (!cond) {
    console.error('FAIL:', msg);
    process.exit(1);
  }
}

const sk = generateSecretKey();
const authUrl = `${base}/auth/nostr`;

const event = finalizeEvent({
  kind: 27235,
  created_at: Math.floor(Date.now() / 1000),
  tags: [['u', authUrl], ['method', 'POST']],
  content: '',
}, sk);

const token = `Nostr ${Buffer.from(JSON.stringify(event)).toString('base64')}`;

const res = await fetch(`${base}/auth/nostr/verify`, {
  method: 'POST',
  headers: { authorization: token },
});
const body = await res.json();
assert(body.valid === true, `expected valid:true got ${JSON.stringify(body)}`);
assert(body.pubkey === getPublicKey(sk), 'pubkey mismatch');
assert(typeof body.token === 'string' && body.token.length > 20, 'missing session token');
console.log('✓ NIP-98 verify valid — pubkey:', `${body.pubkey.slice(0, 16)}…`);

// Replay must fail
const replay = await fetch(`${base}/auth/nostr/verify`, {
  method: 'POST',
  headers: { authorization: token },
});
assert(replay.status === 409, `replay should be 409, got ${replay.status}`);
console.log('✓ NIP-98 replay rejected (409)');

// Wrong URL binding must fail
const badEvent = finalizeEvent({
  kind: 27235,
  created_at: Math.floor(Date.now() / 1000),
  tags: [['u', 'https://evil.example/auth/nostr'], ['method', 'POST']],
  content: '',
}, generateSecretKey());
const badRes = await fetch(`${base}/auth/nostr/verify`, {
  method: 'POST',
  headers: { authorization: `Nostr ${Buffer.from(JSON.stringify(badEvent)).toString('base64')}` },
});
assert(badRes.status >= 400, `wrong u-tag should fail, got ${badRes.status}`);
console.log('✓ NIP-98 wrong url binding rejected');
