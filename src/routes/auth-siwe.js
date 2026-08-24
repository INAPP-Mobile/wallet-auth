import { Router, json } from 'express';
import { getAddress } from 'ethers';
import { mintToken } from '../token.js';
import { verifySiwe } from '../verify/siwe.js';

/**
 * SIWE (EIP-4361) auth routes.
 * POST /nonce  -> { nonce }
 * POST /verify { message, signature } -> { valid, token?, address?, chainId? }
 *
 * Nonce lifecycle: signature is verified FIRST; the message nonce is
 * consumed only after a successful check, so bad signatures never
 * burn challenges.
 */
export function buildSiweRouter({ nonceStore, secret, ttl = process.env.SESSION_TTL_HOURS || '24h' }) {
  const router = Router();
  router.use(json());

  const ttlArg = String(ttl).match(/^\d+$/) ? `${ttl}h` : ttl;

  async function nonce() {
    return { body: { nonce: await nonceStore.issue() } };
  }

  async function verify({ message, signature }) {
    let result;
    try {
      result = await verifySiwe({ message, signature });
    } catch (err) {
      const status = err.status || (String(err.message).includes('Malformed') ? 400 : 401);
      return { status, body: { valid: false, error: `Signature invalid: ${err.message}` } };
    }
    if (!result.nonce || !(await nonceStore.consume(result.nonce))) {
      return { status: 409, body: { valid: false, error: 'Nonce unknown, used, or expired' } };
    }
    const token = await mintToken(
      { sub: result.address, scheme: 'siwe', chainId: result.chainId },
      secret,
      ttlArg,
    );
    return {
      status: 200,
      body: { valid: true, token, address: result.address, chainId: result.chainId },
    };
  }

  router.post('/nonce', async (_req, res) => res.json((await nonce()).body));

  // EIP-55 checksum helper for the login UI. Some wallets (e.g. OKX) return
  // all-lowercase accounts; SIWE line 2 must be checksummed or parsing fails.
  // The signature covers exact message bytes, so this must happen pre-sign.
  router.get('/checksum', (req, res) => {
    try {
      res.json({ address: getAddress(String(req.query.address || '')) });
    } catch {
      res.status(400).json({ valid: false, error: 'invalid Ethereum address' });
    }
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
