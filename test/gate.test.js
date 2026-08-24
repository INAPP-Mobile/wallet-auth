import { test } from 'node:test';
import assert from 'node:assert';
import express from 'express';
import { mintToken } from '../src/token.js';
import { buildGate } from '../src/gate.js';

const SECRET = 'test-secret-at-least-32-chars-long!!!!';
const COOKIE = 'wa_session';

async function startApp() {
  const app = express();
  app.use(buildGate({ secret: SECRET, cookieName: COOKIE }));
  const server = app.listen(0);
  await new Promise((r) => server.on('listening', r));
  return { server, url: `http://127.0.0.1:${server.address().port}` };
}

test('no credentials -> 401 with login redirect', async () => {
  const { server, url } = await startApp();
  try {
    const res = await fetch(`${url}/gate`, { headers: { 'x-forwarded-uri': '/private' } });
    assert.equal(res.status, 401);
    assert.match(res.headers.get('location'), /\/login\?next=/);
    assert.equal((await res.json()).allowed, false);
  } finally {
    server.close();
  }
});

test('valid bearer token -> 200', async () => {
  const { server, url } = await startApp();
  try {
    const t = await mintToken({ sub: '0xabc', scheme: 'siwe' }, SECRET, '1h');
    const res = await fetch(`${url}/gate`, { headers: { authorization: `Bearer ${t}` } });
    assert.equal(res.status, 200);
  } finally {
    server.close();
  }
});

test('valid session cookie -> 200', async () => {
  const { server, url } = await startApp();
  try {
    const t = await mintToken({ sub: 'npub123', scheme: 'nostr' }, SECRET, '1h');
    const res = await fetch(`${url}/gate`, { headers: { cookie: `${COOKIE}=${t}` } });
    assert.equal(res.status, 200);
  } finally {
    server.close();
  }
});

test('garbage token -> 401', async () => {
  const { server, url } = await startApp();
  try {
    const res = await fetch(`${url}/gate`, { headers: { authorization: 'Bearer garbage.token.here' } });
    assert.equal(res.status, 401);
  } finally {
    server.close();
  }
});

test('token signed with wrong secret -> 401', async () => {
  const { server, url } = await startApp();
  try {
    const t = await mintToken({ sub: 'x', scheme: 'solana' }, 'a-different-secret-32-chars-long!!!!!!', '1h');
    const res = await fetch(`${url}/gate`, { headers: { authorization: `Bearer ${t}` } });
    assert.equal(res.status, 401);
  } finally {
    server.close();
  }
});
