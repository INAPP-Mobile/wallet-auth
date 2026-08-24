import { Router, json } from 'express';
import { nip98, verifyEvent } from 'nostr-tools';
import { mintToken } from '../token.js';

/**
 * NIP-98 (Nostr HTTP Auth) verification route.
 * POST /verify  { token }  or  Authorization: Nostr <base64>
 * -> { valid, token?, pubkey? }
 *
 * Validation chain: base64 unpack -> event id hash + schnorr sig
 * (verifyEvent) -> kind/timestamp/url/method (nip98.validateEvent)
 * -> event.id consumed as replay nonce.
 *
 * The `u` tag must match EXACTLY ONE expected URL:
 *   ${PUBLIC_URL}/auth/nostr if PUBLIC_URL is set, else request-derived origin.
 * There is intentionally no loose fallback — a signed event naming any other
 * URL must not authenticate here.
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
    let event;
    try {
      event = await nip98.unpackEventFromToken(token);
    } catch {
      return { status: 400, body: { valid: false, error: 'Malformed Nostr auth token' } };
    }

    if (!verifyEvent(event)) {
      return { status: 401, body: { valid: false, error: 'Event id/signature invalid' } };
    }

    try {
      if (!(await nip98.validateEvent(event, url, 'post'))) {
        return { status: 401, body: { valid: false, error: 'NIP-98 validation failed (url/method/time)' } };
      }
    } catch (err) {
      return { status: 401, body: { valid: false, error: `NIP-98 validation failed: ${err.message}` } };
    }

    // Replay guard: the event id is claimed once, forever.
    if (!(await nonceStore.claim(event.id))) {
      return { status: 409, body: { valid: false, error: 'Event already used or expired' } };
    }

    const jwt = await mintToken({ sub: event.pubkey, scheme: 'nostr' }, secret, ttlArg);
    return { status: 200, body: { valid: true, token: jwt, pubkey: event.pubkey } };
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

  router._test = {
    verify,
    expectedUrl,
  };
  return router;
}
