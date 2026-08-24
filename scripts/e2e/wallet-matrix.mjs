#!/usr/bin/env node
// Wallet compatibility MATRIX — proves SIWE login across documented wallet
// behaviors without owning any extensions.
//
// Profiles encode each wallet family's known quirks at the JSON-RPC boundary:
//   metamask     checksummed account, lenient personal_sign (accepts anything)
//   talisman     returns LOWERCASE account; REJECTS personal_sign whose
//                message is not hex OR whose `from` is not EIP-55 checksummed
//   phantom-evm  hex-only personal_sign, strict from-checksum
//   okx          ALL-LOWERCASE account, hex-only
//
// The exact browser code path from login.html is exercised: EIP-6963-style
// discovery -> connectFirstWallet -> ethers.getAddress checksum ->
// buildSiweMessage -> personal_sign [hex, checksummed-from] -> live endpoints.
import { createApp } from '../../src/server.js';
import { Wallet, getAddress, toUtf8Bytes, hexlify } from 'ethers';
import {
  evmCandidates, legacyProviders, connectFirstWallet, buildSiweMessage,
} from '../../src/public/wallet-core.js';

const HEX_RE = /^0x[0-9a-fA-F]+$/;
const hexToBytes = (hex) => Uint8Array.from(hex.slice(2).match(/.{2}/g).map((h) => parseInt(h, 16)));
const BAD_FORMAT = "The app's signature request cannot be shown due to invalid formatting.";

function makeWalletProfile({ label, accountCase }) {
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
          const [msg, from] = params ?? [];
          // Strict wallets reject BOTH non-hex messages and non-EIP-55 from.
          if (!HEX_RE.test(msg || '')) throw new Error(BAD_FORMAT);
          try {
            if (getAddress(from) !== from) throw new Error('not checksummed');
          } catch {
            throw new Error(BAD_FORMAT);
          }
          return w.signMessage(hexToBytes(msg));
        }
        throw new Error(`unsupported method ${method}`);
      },
    },
  };
}

const PROFILES = [
  makeWalletProfile({ label: 'metamask', accountCase: 'checksum' }),
  makeWalletProfile({ label: 'talisman', accountCase: 'lower' }),   // real-world Talisman
  makeWalletProfile({ label: 'phantom-evm', accountCase: 'checksum' }),
  makeWalletProfile({ label: 'okx', accountCase: 'lower' }),
];

const { app } = await createApp({
  dataDir: `/tmp/wa-matrix-${Date.now()}`,
  secret: 'matrix-secret-0123456789abcdefghijklmnop',
  paidVerify: false,
});
const srv = app.listen(0);
await new Promise((r) => srv.on('listening', r));
const origin = `http://127.0.0.1:${srv.address().port}`;

let pass = 0;
console.log('profile       result');
for (const profile of PROFILES) {
  const { label, w } = profile;
  try {
    // --- exactly what login.html does ---
    const cands = evmCandidates([], legacyProviders({ ethereum: [profile.provider] }));
    const picked = await connectFirstWallet(cands);
    const address = getAddress(picked.address);
    const { nonce } = await (await fetch(`${origin}/auth/siwe/nonce`, { method: 'POST' })).json();
    const message = buildSiweMessage({ origin, address, nonce });
    const msgHex = hexlify(toUtf8Bytes(message));
    const signature = await picked.provider.request({
      method: 'personal_sign',
      params: [msgHex, address],
    });
    const body = await (await fetch(`${origin}/auth/siwe/verify`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ message, signature }),
    })).json();

    if (!(body.valid === true)) throw new Error(JSON.stringify(body));
    if (body.address.toLowerCase() !== getAddress(w.address).toLowerCase()) {
      throw new Error(`address mismatch ${body.address}`);
    }
    console.log(`${label.padEnd(13)} valid ✓`);
    pass++;
  } catch (err) {
    console.log(`${label.padEnd(13)} FAIL ${String(err.message).slice(0, 70)}`);
  }
}
srv.close();
console.log(`\n${pass}/${PROFILES.length} profiles passed`);
process.exit(pass === PROFILES.length ? 0 : 1);
