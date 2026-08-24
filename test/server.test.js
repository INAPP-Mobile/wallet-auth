import { test } from 'node:test';
import assert from 'node:assert';
import { Wallet } from 'ethers';
import { SiweMessage } from 'siwe';
import { createApp } from '../src/server.js';
import { mkdtempSync } from 'node:fs';
import { join } from 'node:path';

const scratch = mkdtempSync(join(import.meta.dirname, '.tmp-test-'));

async function start(env = {}) {
  const { app, config, nonceStore } = await createApp({
    dataDir: join(scratch, `srv-${Math.random()}`),
    secret: 'test-secret-at-least-32-chars-long!!!!',
    ...env,
  });
  const server = app.listen(0);
  await new Promise((r) => server.on('listening', r));
  return { server, url: `http://127.0.0.1:${server.address().port}`, config, nonceStore };
}

test('health returns ok before any middleware', async () => {
  const s = await start({ paidVerify: false });
  try {
    const res = await fetch(`${s.url}/health`);
    assert.equal(res.status, 200);
    assert.equal((await res.json()).ok, true);
  } finally {
    s.server.close();
  }
});

test('unknown route -> express 404 html-free json', async () => {
  const s = await start({ paidVerify: false });
  try {
    const res = await fetch(`${s.url}/nope`);
    assert.equal(res.status, 404);
  } finally {
    s.server.close();
  }
});

test('/auth/siwe/checksum EIP-55-encodes lowercase wallet accounts (OKX case)', async () => {
  const s = await start({ paidVerify: false });
  try {
    const r = await (await fetch(`${s.url}/auth/siwe/checksum?address=0x917736ab1982df917d90d5abe325b9340959ca2d`)).json();
    assert.equal(r.address, '0x917736aB1982df917d90d5Abe325B9340959ca2D');
    const bad = await fetch(`${s.url}/auth/siwe/checksum?address=not-an-address`);
    assert.equal(bad.status, 400);
  } finally {
    s.server.close();
  }
});

test('PAID_VERIFY=off -> /v1/verify reachable without payment', async () => {
  const s = await start({ paidVerify: false });
  try {
    const res = await fetch(`${s.url}/v1/verify`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ scheme: 'bitcoin' }),
    });
    assert.equal(res.status, 400); // reached handler (scheme error), NOT 402
  } finally {
    s.server.close();
  }
});

test('PAID_VERIFY=on with missing wallet/CDP vars -> soft-fail to gate-only, app boots', async () => {
  // server.js reads CDP creds from process.env — clear them for determinism.
  const saved = [process.env.X402_CDP_KEY_ID, process.env.X402_CDP_KEY_SECRET];
  delete process.env.X402_CDP_KEY_ID;
  delete process.env.X402_CDP_KEY_SECRET;
  const s = await start({ paidVerify: true, payTo: '' });
  try {
    // App is up and the oracle serves free (no paywall armed -> no 402).
    const res = await fetch(`${s.url}/v1/verify`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ scheme: 'bitcoin' }),
    });
    assert.equal(res.status, 400); // reached handler, NOT 402, NOT crash
    const cfg = await (await fetch(`${s.url}/config`)).json();
    assert.equal(cfg.paidVerify, true); // requested on...
    assert.equal(s.config.paidVerifyActive, false); // ...but paywall not armed
  } finally {
    s.server.close();
    if (saved[0] !== undefined) process.env.X402_CDP_KEY_ID = saved[0];
    if (saved[1] !== undefined) process.env.X402_CDP_KEY_SECRET = saved[1];
  }
});

test('full SIWE roundtrip through mounted app mints working session for gate', async () => {
  const s = await start({ paidVerify: false });
  try {
    const wallet = Wallet.createRandom();
    const nres = await fetch(`${s.url}/auth/siwe/nonce`, { method: 'POST' });
    const { nonce } = await nres.json();

    const msg = new SiweMessage({
      domain: '127.0.0.1',
      address: wallet.address,
      uri: `${s.url}`,
      version: '1',
      chainId: 1,
      nonce,
    });
    const message = msg.prepareMessage();
    const signature = await wallet.signMessage(message);

    const vres = await fetch(`${s.url}/auth/siwe/verify`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ message, signature }),
    });
    const body = await vres.json();
    assert.equal(body.valid, true);

    const gres = await fetch(`${s.url}/gate`, {
      headers: { authorization: `Bearer ${body.token}` },
    });
    assert.equal(gres.status, 200);
  } finally {
    s.server.close();
  }
});

test('login page and dashboard are served', async () => {
  const s = await start({ paidVerify: false });
  try {
    for (const p of ['/login.html', '/index.html']) {
      const res = await fetch(`${s.url}${p}`);
      assert.equal(res.status, 200);
      assert.match(res.headers.get('content-type'), /html/);
    }
  } finally {
    s.server.close();
  }
});
