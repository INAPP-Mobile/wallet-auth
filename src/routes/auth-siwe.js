import { Router, json } from 'express';
import { SiweMessage } from 'siwe';
import { mintToken } from '../token.js';

/**
 * SIWE (EIP-4361) auth routes.
 * POST /nonce  -> { nonce }
 * POST /verify { message, signature } -> { valid, token?, address?, chainId? }
 *
 * Nonce lifecycle: must exist in the store BEFORE verification runs
 * (fast-fail on stale/forged nonces) but is consumed only AFTER a
 * successful signature check, so bad signatures don't burn nonces.
 */
export function buildSiweRouter({ nonceStore, secret, ttl = process.env.SESSION_TTL_HOURS || '24h' }) {
  const router = Router();
  router.use(json());

  async function nonce() {
    return { body: { nonce: await nonceStore.issue() } };
  }

  async function verify({ message, signature }) {
    let msg;
    try {
      msg = new SiweMessage(String(message));
    } catch {
      return { status: 400, body: { valid: false, error: 'Malformed EIP-4361 message' } };
    }
    try {
      const res = await msg.verify({ signature });
      if (!res.success) throw new Error(res.error?.type || 'verification failed');
    } catch (err) {
      return { status: 401, body: { valid: false, error: `Signature invalid: ${err.message}` } };
    }
    // Signature valid — now atomically consume the nonce (replay guard).
    if (!(await nonceStore.consume(msg.nonce))) {
      return { status: 409, body: { valid: false, error: 'Nonce unknown, used, or expired' } };
    }
    const token = await mintToken(
      { sub: msg.address, scheme: 'siwe', chainId: msg.chainId ?? null },
      secret,
      String(ttl).match(/^\d+$/) ? `${ttl}h` : ttl,
    );
    return { status: 200, body: { valid: true, token, address: msg.address, chainId: msg.chainId ?? null } };
  }

  router.post('/nonce', async (_req, res) => {
    const r = await nonce();
    res.json(r.body);
  });

  router.post('/verify', async (req, res) => {
    const { message, signature } = req.body ?? {};
    if (!message || !signature) {
      return res.status(400).json({ valid: false, error: 'message and signature are required' });
    }
    const r = await verify({ message, signature });
    res.status(r.status).json(r.body);
  });

  router._test = { nonce, verify };
  return router;
}
