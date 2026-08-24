import { Router, json } from 'express';
import nacl from 'tweetnacl';
import bs58 from 'bs58';
import { mintToken } from '../token.js';

/**
 * Solana (ed25519) auth routes.
 * POST /nonce  -> { nonce }                       (server-issued)
 * POST /verify { pubkey, message, signature }     (pubkey+signature base58)
 * -> { valid, token?, pubkey? }
 *
 * The message MUST embed a previously-issued nonce — this binds the
 * signature to a fresh server challenge and gives replay protection.
 */
export function buildSolanaRouter({ nonceStore, secret, ttl = process.env.SESSION_TTL_HOURS || '24h' }) {
  const router = Router();
  router.use(json());

  const ttlArg = String(ttl).match(/^\d+$/) ? `${ttl}h` : ttl;

  async function nonce() {
    return { body: { nonce: await nonceStore.issue() } };
  }

  async function verify({ pubkey, message, signature }) {
    let pubkeyBytes;
    try {
      pubkeyBytes = bs58.decode(String(pubkey));
    } catch {
      return { status: 400, body: { valid: false, error: 'pubkey is not valid base58' } };
    }
    if (pubkeyBytes.length !== 32) {
      return { status: 400, body: { valid: false, error: 'pubkey must decode to 32 bytes' } };
    }

    let sigBytes;
    try {
      sigBytes = bs58.decode(String(signature));
    } catch {
      return { status: 400, body: { valid: false, error: 'signature is not valid base58' } };
    }

    if (!String(message).match(/\S/)) {
      return { status: 400, body: { valid: false, error: 'message required' } };
    }

    // Verify pure crypto FIRST so a bad signature never burns the challenge.
    const ok = nacl.sign.detached.verify(
      new TextEncoder().encode(String(message)),
      sigBytes,
      pubkeyBytes,
    );
    if (!ok) {
      return { status: 401, body: { valid: false, error: 'Signature invalid' } };
    }

    // Message is now authenticated — the embedded nonce can be trusted and consumed.
    const m = /Nonce:\s*([A-Za-z0-9]+)/.exec(String(message));
    if (!m || !(await nonceStore.consume(m[1]))) {
      return { status: 401, body: { valid: false, error: 'Nonce unknown, used, or expired' } };
    }

    const jwt = await mintToken({ sub: String(pubkey), scheme: 'solana' }, secret, ttlArg);
    return { status: 200, body: { valid: true, token: jwt, pubkey: String(pubkey) } };
  }

  router.post('/nonce', async (_req, res) => res.json((await nonce()).body));
  router.post('/verify', async (req, res) => {
    const r = await verify(req.body ?? {});
    res.status(r.status).json(r.body);
  });

  router._test = { nonce, verify };
  return router;
}
