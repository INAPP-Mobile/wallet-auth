import { Router, json } from 'express';
import { verifyToken } from './token.js';

/**
 * Forward-auth gate for Caddy `forward_auth` and nginx `auth_request`.
 * GET /gate
 *   - valid `Authorization: Bearer <jwt>` or session cookie -> 200
 *   - otherwise 401 with Location: <login>?next=<original URL>
 *
 * Caddy:
 *   forward_auth wallet-auth:8080 { uri /gate }
 * nginx:
 *   auth_request /_wagate; location = /_wagate { proxy_pass http://wallet-auth/gate; }
 */
export function buildGate({ secret, cookieName = process.env.GATE_COOKIE_NAME || 'wa_session', loginPath = '/login' }) {
  const router = Router();

  function extractToken(req) {
    const authz = req.headers.authorization;
    if (authz && /^Bearer\s+/i.test(authz)) return authz.replace(/^Bearer\s+/i, '').trim();
    const cookies = req.headers.cookie;
    if (cookies) {
      for (const pair of cookies.split(';')) {
        const [k, ...v] = pair.trim().split('=');
        if (k === cookieName) return decodeURIComponent(v.join('='));
      }
    }
    return null;
  }

  async function check(req) {
    const token = extractToken(req);
    if (!token) return false;
    try {
      const claims = await verifyToken(token, secret);
      return Boolean(claims && claims.sub && claims.scheme);
    } catch {
      return false;
    }
  }

  router.get('/gate', async (req, res) => {
    if (await check(req)) return res.status(200).json({ allowed: true });
    // Derive the originally-requested URL from proxy headers.
    const host = req.headers['x-forwarded-host'] || req.headers.host || '';
    const proto = req.headers['x-forwarded-proto'] || 'http';
    const orig = req.headers['x-forwarded-uri'] || req.originalUrl || '/';
    res
      .status(401)
      .set('Location', `${loginPath}?next=${encodeURIComponent(`${proto}://${host}${orig}`)}`)
      .json({ allowed: false });
  });

  router._test = { check: (req) => check(req), extractToken };
  return router;
}
