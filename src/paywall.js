import { paymentMiddleware } from 'x402-express';

/**
 * x402 pay-per-request middleware, isolated so upstream API churn in
 * x402-express touches exactly one file.
 *
 * cfg = {
 *   enabled:        boolean            (PAID_VERIFY)
 *   payTo:          '0x...' | solana addr (X402_PAY_TO)
 *   price:          '$0.001'           (X402_PRICE_USD)
 *   network:        'base'             (X402_NETWORK)
 *   facilitatorUrl: string|undefined   (X402_FACILITATOR_URL; default x402.org)
 * }
 */
export function applyPaywall(app, cfg) {
  if (!cfg.enabled) return false;
  if (!cfg.payTo) throw new Error('X402_PAY_TO is required when PAID_VERIFY=on');
  const routes = {
    'POST /v1/verify': {
      price: cfg.price || '$0.001',
      network: cfg.network || 'base',
      config: { description: 'Wallet signature verification (SIWE / Nostr / Solana)' },
    },
  };
  const facilitator = cfg.facilitatorUrl ? { url: cfg.facilitatorUrl } : undefined;
  app.use(paymentMiddleware(cfg.payTo, routes, facilitator));
  return true;
}
