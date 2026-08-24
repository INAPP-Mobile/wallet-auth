import { test } from 'node:test';
import assert from 'node:assert';
import { mintToken, verifyToken } from '../src/token.js';

const secret = 'test-secret-at-least-32-chars-long!!!!';

test('roundtrip preserves claims', async () => {
  const t = await mintToken({ sub: '0xabc', scheme: 'siwe' }, secret, '1h');
  const claims = await verifyToken(t, secret);
  assert.equal(claims.sub, '0xabc');
  assert.equal(claims.scheme, 'siwe');
});

test('tampered token is rejected', async () => {
  const t = await mintToken({ sub: '0xabc', scheme: 'siwe' }, secret, '1h');
  assert.equal(await verifyToken(t + 'x', secret).catch(() => null), null);
});

test('wrong secret is rejected', async () => {
  const t = await mintToken({ sub: '0xabc' }, secret, '1h');
  assert.equal(await verifyToken(t, 'another-secret-that-is-32-chars!!!').catch(() => null), null);
});

test('expired token is rejected', async () => {
  const t = await mintToken({ sub: '0xabc' }, secret, '-1s');
  await new Promise((r) => setTimeout(r, 20));
  assert.equal(await verifyToken(t, secret).catch(() => null), null);
});
