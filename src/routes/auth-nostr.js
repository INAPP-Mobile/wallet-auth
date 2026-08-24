import { Router, json } from 'express';
import { mintToken } from '../token.js';
import { verifyNip98 } from '../verify/nostr.js';

/**
 * NIP-98 (Nostr HTTP Auth) auth route.
 * POST /verify  { token }  or  Authorization: Nostr <base64>
 * -> { valid, token?, pubkey? }
 *
 * The `u` tag must match EXACTLY ONE expected URL:
 *   ${PUBLIC_URL}/auth/nostr if PUBLIC_URL is set, else request-derived origin.
 * No loose fallback — a signed event naming any other URL must not authenticate.
 * Replay guard: the event id is claimed once via the shared nonce store.
 */
export function buildNostrRouter({ nonceStore, secret, publicUrl, ttl = process.env.SESSION_TTL_HOURS || '24h' }) {
  const router = Router();
  router.use(json());

  const ttlArg = String(ttl).match(/^\d+$/) ? `${ttl}h` : ttl;

  function expectedUrl(req) {
    if (publicUrl) return `${String(publicUrl).replace(/\/$/, '')}/auth/nostr`;
    const host = req.headers['x-forwarded-host'] || req.headers.host;
    const proto = req.headers['x-forwarded-proto'] || 'http';
    return `${proto}://${host}/auth/nostr`;
  }

  async function verify({ token, url }) {
    let result;
    try {
      result = await verifyNip98({ token, url });
    } catch (err) {
      return { status: err.status || 401, body: { valid: false, error: err.message } };
    }
    if (!(await nonceStore.claim(result.eventId))) {
      return { status: 409, body: { valid: false, error: 'Event already used or expired' } };
    }
    const jwt = await mintToken({ sub: result.pubkey, scheme: 'nostr' }, secret, ttlArg);
    return { status: 200, body: { valid: true, token: jwt, pubkey: result.pubkey } };
  }

  async function handler(req, res) {
    let token = req.body?.token;
    const authz = req.headers.authorization;
    if (!token && authz && /^Nostr\s+/i.test(authz)) token = authz;
    if (!token) return res.status(401).json({ valid: false, error: 'Nostr token required' });

    const result = await verify({ token, url: expectedUrl(req) });
    res.status(result.status).json(result.body);
  }

  router.post('/verify', handler);
  router._test = { verify, expectedUrl };
  return router;
}
