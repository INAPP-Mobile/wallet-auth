# Deploy and Host

[![Deploy on Railway](https://railway.app/button.svg)](https://railway.com/deploy/wallet-auth)

![Wallet Auth API](https://raw.githubusercontent.com/INAPP-Mobile/wallet-auth/main/template-icon.svg)

Wallet Auth API is a self-hosted signature verification service for the agent economy. Verify **SIWE** (Ethereum/EIP-4361), **NIP-98** (Nostr HTTP auth), and **Solana ed25519** signatures over one HTTP interface — with an x402 micropayment oracle ($0.001 per verify) and a free forward-auth gate mode that protects any service behind Caddy or nginx.

## About Hosting

The template deploys a single Node.js container built from its own Dockerfile, with a persistent volume mounted at `/data` that stores single-use sign-in challenges (nonce store) so replay protection survives restarts and deploys.

- One service, one public domain, no companion databases required
- Sessions are stateless HS256 tokens; the only persistent state is the nonce store on the volume
- Set `PUBLIC_URL=${{RAILWAY_PUBLIC_DOMAIN}}` after first deploy and redeploy once so domain variables resolve

Railway provides compute, TLS at the edge, the public URL, and the volume.

## Why Deploy

- **Three chains, one endpoint** — Ethereum (SIWE/EIP-4361), Nostr (NIP-98 kind-27235), and Solana (ed25519) verification without wiring three SDKs
- **x402 pay-per-verify oracle** — `POST /v1/verify` charges $0.001 USDC via the x402 protocol and returns `{valid, identity}` or `402 Payment Required`
- **Replay protection built in** — single-use server challenges persisted on a volume; bad signatures never burn nonces
- **Free sign-in flows** — `/auth/siwe`, `/auth/nostr`, `/auth/solana` issue HS256 session tokens with no payment required
- **Gate mode** — drop-in `forward_auth` for Caddy and `auth_request` for nginx; any upstream becomes wallet-gated with three lines of config
- **Bundled login UI** — working MetaMask, Alby/nos2x, and Phantom sign-in pages out of the box

## Common Use Cases

- **Wallet-gated dashboards** — put a login wall in front of any homelab or internal service via Caddy/nginx forward auth
- **x402 tool sellers** — meter access to your own APIs behind proven identity checks and sell verifications at $0.001/call
- **Agent-to-agent authentication** — AI agents prove which wallet they control before calling your endpoints
- **Sign-in with Ethereum / Nostr / Solana** — issue session tokens for SPAs without running a full identity provider

## Dependencies for wallet-auth

### Deployment Dependencies

None beyond Railway itself — no companion services, no external databases. The template creates its own persistent volume at `/data`. Optional variables enable paid mode:

- `X402_PAY_TO` — your wallet address receiving x402 payments (needed only when `PAID_VERIFY=on`)
- `X402_CDP_KEY_ID` / `X402_CDP_KEY_SECRET` — Coinbase CDP API keys used by the x402 facilitator in paid mode

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

Gate mode is the default — no wallet needed. To sell verifications at $0.001 per call, set `PAID_VERIFY=on` and fill in your payment wallet and CDP keys below.

## Environment Variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `SESSION_SECRET` | yes | — | HS256 signing secret (`openssl rand -hex 32`) |
| `X402_PAY_TO` | if paid | — | Wallet address receiving x402 payments |
| `PAID_VERIFY` | no | `off` | Set `on` (+ wallet & CDP keys) to enable the paid x402 oracle |
| `PUBLIC_URL` | recommended | — | Canonical origin, e.g. `${{RAILWAY_PUBLIC_DOMAIN}}`; binds NIP-98 URL tags |
| `X402_PRICE_USD` | no | `$0.001` | Price per oracle verification |
| `X402_CDP_KEY_ID` | if paid | — | Coinbase CDP API key ID (x402 facilitator auth) |
| `X402_CDP_KEY_SECRET` | if paid | — | Coinbase CDP API key secret |
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
```

## Gate Mode Examples

### Protect any service (Caddy)

```caddy
example.yourdomain.com {
    forward_auth https://wallet-auth.up.railway.app {
        uri /gate?url={scheme}://{host}{uri}
    }
    reverse_proxy 127.0.0.1:3000
}
```

### nginx equivalent

```nginx
location / {
    auth_request /_wallet_auth;
    error_page 401 = @wallet_login;
    proxy_pass http://127.0.0.1:3000;
}
location = /_wallet_auth {
    internal;
    proxy_pass https://wallet-auth.up.railway.app/gate?url=$scheme://$host$request_uri;
}
location @wallet_login {
    return 302 https://wallet-auth.up.railway.app/login?next=$scheme://$host$request_uri;
}
```

## Post-Deploy

- Health check: `GET /health` returns `{"ok":true}`
- Dashboard: visit your domain root for the sign-in page and live verifier
- Paid path test: send an unpaid `POST /v1/verify` and you will receive a `402` with an x402 `PAYMENT-REQUIRED` header — pay it with any x402 client to complete the roundtrip
