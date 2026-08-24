import { Router, json } from 'express';
import { mintToken } from '../token.js';
import { verifySolana } from '../verify/solana.js';

/**
 * Solana (ed25519) auth routes.
 * POST /nonce  -> { nonce }                       (server-issued)
 * POST /verify { pubkey, message, signature }     (pubkey+signature base58)
 * -> { valid, token?, pubkey? }
 *
 * Message MUST embed "Nonce: <value>" from /nonce. Signature is verified
 * before the challenge is consumed, so bad signatures never burn nonces.
 */
export function buildSolanaRouter({ nonceStore, secret, ttl = process.env.SESSION_TTL_HOURS || '24h' }) {
  const router = Router();
  router.use(json());

  const ttlArg = String(ttl).match(/^\d+$/) ? `${ttl}h` : ttl;

  async function nonce() {
    return { body: { nonce: await nonceStore.issue() } };
  }

  async function verify({ pubkey, message, signature }) {
    let result;
    try {
      result = verifySolana({ pubkey, message, signature });
    } catch (err) {
      return { status: err.status || 401, body: { valid: false, error: err.message } };
    }

    const m = /Nonce:\s*([A-Za-z0-9]+)/.exec(String(message));
    if (!m || !(await nonceStore.consume(m[1]))) {
      return { status: 401, body: { valid: false, error: 'Nonce unknown, used, or expired' } };
    }

    const jwt = await mintToken({ sub: result.pubkey, scheme: 'solana' }, secret, ttlArg);
    return { status: 200, body: { valid: true, token: jwt, pubkey: result.pubkey } };
  }

  router.post('/nonce', async (_req, res) => res.json((await nonce()).body));
  router.post('/verify', async (req, res) => {
    const r = await verify(req.body ?? {});
    res.status(r.status).json(r.body);
  });

  router._test = { nonce, verify };
  return router;
}
