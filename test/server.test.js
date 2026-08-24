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
