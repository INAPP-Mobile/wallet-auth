# Wallet Auth API

[![Deploy to Railway](https://railway.app/button.svg)](https://railway.com/deploy/TEMPLATE_CODE)

Wallet signature verification API for the agent economy. Verify **SIWE** (Ethereum/EIP-4361), **NIP-98** (Nostr HTTP auth), and **Solana ed25519** signatures over one HTTP interface — with x402 micropayments ($0.001 per oracle call) and a free forward-auth gate mode that protects any service behind Caddy or nginx.

## Features

- **Three chains, one endpoint** — verify Ethereum (SIWE/EIP-4361), Nostr (NIP-98 kind-27235), and Solana (ed25519) signatures
- **x402 pay-per-verify oracle** — `POST /v1/verify` charges $0.001 USDC via the x402 protocol; returns `{valid, identity}` or `402 Payment Required`
- **Replay protection built in** — single-use server challenges stored on a persistent volume; bad signatures never burn nonces
- **Free sign-in flows** — `/auth/siwe`, `/auth/nostr`, `/auth/solana` issue stateless HS256 session tokens without payment
- **Gate mode** — drop-in `forward_auth` for Caddy and `auth_request` for nginx; any service becomes wallet-gated in three lines of config
- **Bundled login UI** — working MetaMask / Alby-nos2x / Phantom sign-in pages out of the box

## Quick Start

1. Click **Deploy to Railway**.
2. Set required variables when prompted (see below).
3. After deploy, set `PUBLIC_URL=${{RAILWAY_PUBLIC_DOMAIN}}` and redeploy once (domain variables resolve on the second deploy).
4. Visit your domain and click **Sign in** to try each wallet flow.

Verify a signature through the paid oracle:

```bash
curl -X POST https://your-app.up.railway.app/v1/verify \
  -H "Content-Type: application/json" \
  -d '{"scheme":"solana","pubkey":"<base58>","message":"hello","signature":"<base58>"}'
```

## Prerequisites

No external databases or companion services required — just Railway:

- One persistent **volume** mounted at `/data` (created automatically by this template)
- A wallet address to receive x402 payments (EVM or Solana, depending on `X402_NETWORK`)
- Optional: browser extensions (MetaMask, Alby/nos2x, Phantom) to use the login UI

Set `PAID_VERIFY=off` to run pure gate-mode with no wallet configured.

## Environment Variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `SESSION_SECRET` | yes | — | HS256 signing secret (`openssl rand -hex 32`) |
| `X402_PAY_TO` | if paid | — | Wallet address receiving x402 payments |
| `PAID_VERIFY` | no | `on` | Set `off` to disable the paywall (gate-only mode) |
| `PUBLIC_URL` | recommended | — | Canonical origin, e.g. `${{RAILWAY_PUBLIC_DOMAIN}}`; binds NIP-98 URL tags |
| `X402_PRICE_USD` | no | `$0.001` | Price per oracle verification |
| `X402_NETWORK` | no | `base` | x402 network |
| `X402_FACILITATOR_URL` | no | x402.org | Custom facilitator endpoint |
| `SESSION_TTL_HOURS` | no | `24` | Session token lifetime |
| `NONCE_TTL_MINUTES` | no | `10` | Challenge lifetime |
| `GATE_COOKIE_NAME` | no | `wa_session` | Session cookie checked by `/gate` |
| `PORT` | auto | `8080` | Set by Railway |

## Architecture

```
                 ┌────────────────────────────┐
   Caddy/nginx ──► GET /gate ───────────────►│ 401 → Location /login
   forward_auth │                            │ 200 if session valid
                 │                            │
   browsers ────►│ /login · /  (static UI)    │
                 │ /auth/siwe/*    ── nonce ─►│──┐
                 │ /auth/nostr/*   ── claim ─►│  ├─► volume /data/nonces.json
                 │ /auth/solana/*  ── nonce ─►│  │   (single-use, TTL'd)
   x402 clients ►│ POST /v1/verify ─ $0.001 ─►│──┘
                 └────────────────────────────┘
```

Single Node.js service, pure-JS dependency stack. Sessions are stateless JWTs; only nonce hashes touch disk. The paid oracle is stateless by design — it never mints tokens, so replayed proofs confer nothing.

### Protect any service (Caddy)

```caddy
example.com {
    forward_auth wallet-auth:8080 {
        uri /gate
    }
    reverse_proxy your-app:3000
}
```

### nginx equivalent

```nginx
location = /_wagate { proxy_pass http://wallet-auth/gate; }
location / {
    auth_request /_wagate;
    proxy_pass http://your-app;
}
```

## Post-Deploy

1. Set `SESSION_SECRET` (random 32-byte hex) before exposing publicly.
2. Set `PUBLIC_URL=${{RAILWAY_PUBLIC_DOMAIN}}` and redeploy once.
3. Confirm `GET /health` returns `{"ok":true}`.
4. Test each flow from the bundled `/login.html`.
5. For production-grade x402 settlement on Base mainnet, point `X402_FACILITATOR_URL` at your facilitator of choice.
