import express from 'express';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { createNonceStore } from './nonce-store.js';
import { buildSiweRouter } from './routes/auth-siwe.js';
import { buildNostrRouter } from './routes/auth-nostr.js';
import { buildSolanaRouter } from './routes/auth-solana.js';
import { buildVerifyRouter } from './routes/verify-paid.js';
import { buildGate } from './gate.js';
import { applyPaywall } from './paywall.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

const env = {
  port: Number(process.env.PORT || 8080),
  dataDir: process.env.DATA_DIR || join(process.cwd(), 'data'),
  secret: process.env.SESSION_SECRET,
  sessionTtlHours: process.env.SESSION_TTL_HOURS || '24h',
  nonceTtlMinutes: Number(process.env.NONCE_TTL_MINUTES || 10),
  publicUrl: process.env.PUBLIC_URL || '',
  paidVerify: String(process.env.PAID_VERIFY ?? 'on').toLowerCase() === 'on',
  payTo: process.env.X402_PAY_TO || '',
  priceUsd: process.env.X402_PRICE_USD || '$0.001',
  network: process.env.X402_NETWORK || 'base',
  facilitatorUrl: process.env.X402_FACILITATOR_URL || undefined,
  cookieName: process.env.GATE_COOKIE_NAME || 'wa_session',
};

export async function createApp(overrides = {}) {
  const cfg = { ...env, ...overrides };
  if (!cfg.secret) {
    cfg.secret = 'insecure-dev-secret-change-me-0123456789abcdef';
    if (process.env.NODE_ENV === 'production') {
      console.warn('[wallet-auth] SESSION_SECRET not set — using INSECURE default. Set it!');
    }
  }

  const app = express();
  app.disable('x-powered-by');
  app.use(express.json({ limit: '64kb' }));

  // RAILWAY_PUBLIC_DOMAIN is a bare hostname — normalize to a full origin
  // so NIP-98 u-tag binding and the UI sign against identical URLs.
  if (cfg.publicUrl && !/^https?:\/\//i.test(cfg.publicUrl)) {
    cfg.publicUrl = `https://${cfg.publicUrl}`;
  }

  // Health first — must never be behind the paywall.
  app.get('/health', (_req, res) => res.json({ ok: true }));

  // Minimal runtime config for the bundled UI.
  app.get('/config', (_req, res) =>
    res.json({
      publicUrl: cfg.publicUrl || null,
      paidVerify: cfg.paidVerify,
      priceUsd: cfg.priceUsd,
      network: cfg.network,
    }),
  );

  const nonceStore = await createNonceStore(join(cfg.dataDir, 'nonces.json'), {
    ttlMs: cfg.nonceTtlMinutes * 60 * 1000,
  });

  // Static dashboard/login UI.
  app.use(express.static(join(__dirname, 'public')));

  // Free authenticated sign-in flows (nonce protected, mint session tokens).
  app.use('/auth/siwe', buildSiweRouter({ nonceStore, secret: cfg.secret, ttl: cfg.sessionTtlHours }));
  app.use('/auth/nostr', buildNostrRouter({ nonceStore, secret: cfg.secret, publicUrl: cfg.publicUrl, ttl: cfg.sessionTtlHours }));
  app.use('/auth/solana', buildSolanaRouter({ nonceStore, secret: cfg.secret, ttl: cfg.sessionTtlHours }));

  // Paid verification oracle (x402 v2 via Coinbase CDP facilitator).
  const paid = applyPaywall(app, {
    enabled: cfg.paidVerify,
    payTo: cfg.payTo,
    price: cfg.priceUsd,
    publicUrl: cfg.publicUrl,
    cdpKeyId: process.env.X402_CDP_KEY_ID,
    cdpKeySecret: process.env.X402_CDP_KEY_SECRET,
  });
  app.use('/v1/verify', buildVerifyRouter());

  // Forward-auth gate for Caddy/nginx.
  app.use(buildGate({ secret: cfg.secret, cookieName: cfg.cookieName }));

  return { app, config: { ...cfg, paidVerifyActive: paid }, nonceStore };
}

/* istanbul ignore next */
if (process.argv[1] && import.meta.url.endsWith(process.argv[1].split('/').pop())) {
  const { app, config } = await createApp();
  app.listen(config.port, () => {
    console.log(`[wallet-auth] listening on :${config.port}`);
    console.log(`[wallet-auth] paid verify: ${config.paidVerifyActive ? `ON (${config.priceUsd} -> ${config.payTo})` : 'off'}`);
    console.log(`[wallet-auth] data dir: ${config.dataDir}`);
  });
}
