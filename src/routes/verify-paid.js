import { Router, json } from 'express';
import { verifySiwe } from '../verify/siwe.js';
import { verifyNip98 } from '../verify/nostr.js';
import { verifySolana } from '../verify/solana.js';

/**
 * POST /v1/verify — pure signature-verification oracle (the paid endpoint).
 *
 * Body: { scheme, ...payload }
 *   scheme "siwe":    { message, signature }
 *   scheme "nip98":   { token, url? }
 *   scheme "solana":  { pubkey, message, signature }
 *
 * Returns { valid, scheme, identity } on success, { valid:false, error } otherwise.
 * This endpoint NEVER mints session tokens and never consumes nonces — it is a
 * stateless oracle. Replay protection is enforced by the free /auth/* flows.
 */
const SCHEMES = new Set(['siwe', 'nip98', 'nostr', 'solana', 'ed25519']);

async function dispatch(body) {
  const { scheme } = body ?? {};
  if (!SCHEMES.has(String(scheme))) {
    return {
      status: 400,
      body: { valid: false, error: `Unknown scheme "${scheme}". Supported: siwe, nip98, solana` },
    };
  }
  try {
    let identity;
    switch (scheme) {
      case 'siwe': {
        const r = await verifySiwe(body);
        identity = { address: r.address, chainId: r.chainId };
        break;
      }
      case 'nip98':
      case 'nostr': {
        const r = await verifyNip98(body);
        identity = { pubkey: r.pubkey };
        break;
      }
      case 'solana':
      case 'ed25519': {
        const r = verifySolana(body);
        identity = { pubkey: r.pubkey };
        break;
      }
    }
    return { status: 200, body: { valid: true, scheme, identity } };
  } catch (err) {
    return { status: err.status || 400, body: { valid: false, scheme, error: err.message } };
  }
}

export function buildVerifyRouter() {
  const router = Router();
  router.use(json({ limit: '64kb' }));

  router.post('/', async (req, res) => {
    const result = await dispatch(req.body);
    res.status(result.status).json(result.body);
  });

  router._test = { dispatch };
  return router;
}
