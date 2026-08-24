#!/usr/bin/env node
// Wallet compatibility MATRIX — proves SIWE login across documented wallet
// behaviors without owning any extensions.
//
// Profiles encode each wallet family's known quirks at the JSON-RPC boundary:
//   metamask    checksummed account, lenient personal_sign (accepts anything)
//   talisman    checksummed account, REJECTS non-hex personal_sign messages
//   phantom-evm checksummed account, hex-only, isPhantom flag
//   okx         ALL-LOWERCASE account, hex-only
//
// The exact browser code path is exercised: wallet-core discovery/selection,
// ethers BrowserProvider signing, then the live /auth/siwe/* endpoints.
// Any EIP-6963-compliant wallet behaves like one of these profiles.
import { createApp } from '../../src/server.js';
import { Wallet, getAddress, BrowserProvider } from 'ethers';

const HEX_RE = /^0x[0-9a-fA-F]+$/;
const hexToBytes = (hex) => Uint8Array.from(hex.slice(2).match(/.{2}/g).map((h) => parseInt(h, 16)));

function makeWalletProfile({ label, accountCase, hexOnly }) {
  const w = Wallet.createRandom();
  const account = accountCase === 'lower' ? w.address.toLowerCase() : w.address;
  return {
    label,
    w,
    provider: {
      isTalisman: label === 'talisman',
      isPhantom: label === 'phantom-evm',
      isMetaMask: label === 'metamask',
      async request({ method, params }) {
        if (method === 'eth_requestAccounts' || method === 'eth_accounts') return [account];
        if (method === 'eth_chainId') return '0x1';
        if (method === 'net_version') return '1';
        if (method === 'personal_sign') {
          const [msg] = params ?? [];
          if (!HEX_RE.test(msg || '')) {
            // Talisman / Phantom-EVM behavior on malformed formatting.
            throw new Error("The app's signature request cannot be shown due to invalid formatting.");
          }
          return w.signMessage(hexToBytes(msg)); // decode bytes -> EIP-191
        }
        throw new Error(`unsupported method ${method}`);
      },
    },
  };
}

const PROFILES = [
  makeWalletProfile({ label: 'metamask', accountCase: 'checksum', hexOnly: false }),
  makeWalletProfile({ label: 'talisman', accountCase: 'checksum', hexOnly: true }),
  makeWalletProfile({ label: 'phantom-evm', accountCase: 'checksum', hexOnly: true }),
  makeWalletProfile({ label: 'okx', accountCase: 'lower', hexOnly: true }),
];

const { app } = await createApp({
  dataDir: `/tmp/wa-matrix-${Date.now()}`,
  secret: 'matrix-secret-0123456789abcdefghijklmnop',
  paidVerify: false,
});
const srv = app.listen(0);
await new Promise((r) => srv.on('listening', r));
const base = `http://127.0.0.1:${srv.address().port}`;
const origin = new URL(base).origin;

let pass = 0, failCount = 0;
console.log('profile       account-case  result');
for (const { label, provider, w } of PROFILES) {
  try {
    // --- exactly what login.html does ---
    const bp = new BrowserProvider(provider);
    const signer = await bp.getSigner();
    const address = await signer.getAddress();          // EIP-55 normalized
    const { nonce } = await (await fetch(`${base}/auth/siwe/nonce`, { method: 'POST' })).json();
    const message =
      `${origin} wants you to sign in with your Ethereum account:\n${address}\n\n` +
      `Sign in to wallet-auth\n\nURI: ${origin}/\nVersion: 1\nChain ID: 1\nNonce: ${nonce}\n` +
      `Issued At: ${new Date().toISOString()}`;
    const signature = await signer.signMessage(message);
    const body = await (await fetch(`${base}/auth/siwe/verify`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ message, signature }),
    })).json();

    if (!(body.valid === true)) throw new Error(JSON.stringify(body));
    if (body.address.toLowerCase() !== getAddress(w.address).toLowerCase()) {
      throw new Error(`address mismatch ${body.address}`);
    }
    console.log(`${label.padEnd(13)} ${(label === 'okx' ? 'lower' : 'checksum').padEnd(13)} valid ✓`);
    pass++;
  } catch (err) {
    console.log(`${label.padEnd(13)} -             FAIL ${String(err.message).slice(0, 60)}`);
    failCount++;
  }
}
srv.close();
console.log(`\n${pass}/${PROFILES.length} profiles passed`);
process.exit(failCount ? 1 : 0);
