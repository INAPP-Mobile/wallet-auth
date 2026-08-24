// Shared login-page wallet logic. Plain ESM, no framework — served statically.
// Pure functions take their inputs explicitly so node tests can drive them
// without a DOM (see test/wallet-core.test.js).

/** EIP-55 checksum via ethers UMD global (loaded before this module in pages). */
export function toChecksumAddress(address) {
  return globalThis.ethers.getAddress(String(address));
}

/** EIP-191 personal_sign body as hex bytes — the spec form every wallet accepts. */
export function utf8ToHex(str) {
  return '0x' + [...new TextEncoder().encode(String(str))]
    .map((b) => b.toString(16).padStart(2, '0')).join('');
}

export function isRejected(e) {
  return e?.code === 4001 || /reject/i.test(e?.message || '');
}

export function walletName(p) {
  return p?.isPhantom ? 'Phantom'
    : p?.isTalisman ? 'Talisman'
    : p?.isMetaMask ? 'MetaMask'
    : p?.isCoinbaseWallet ? 'Coinbase Wallet'
    : p?.isTrust ? 'Trust' : 'wallet';
}

/**
 * Collect providers announced via EIP-6963 (the multi-wallet discovery
 * standard implemented by MetaMask, OKX, Rabby, Coinbase, Trust, Brave,
 * Phantom-EVM, Talisman, ...). Falls back to legacy injection points so
 * non-compliant extensions still work.
 */
export function collectAnnouncedProviders(win, timeoutMs = 300) {
  return new Promise((resolve) => {
    const found = [];
    const onAnnounce = (e) => {
      const d = e.detail;
      if (d?.info?.name && d?.provider) found.push(d);
    };
    try {
      win.addEventListener('eip6963:announceProvider', onAnnounce);
      win.dispatchEvent(new win.Event('eip6963:requestProvider'));
    } catch {
      /* non-DOM environment */
      resolve(found);
      return;
    }
    setTimeout(() => {
      win.removeEventListener('eip6963:announceProvider', onAnnounce);
      resolve(found);
    }, timeoutMs);
  });
}

/** Legacy injection-point scan (window.ethereum variants + talismanEth). */
export function legacyProviders(win) {
  const list = [];
  const eth = win.ethereum;
  if (Array.isArray(eth)) list.push(...eth);
  else if (eth?.providers?.length) list.push(...eth.providers);
  else if (eth) list.push(eth);
  if (win.talismanEth) list.push(win.talismanEth);
  return list;
}

/** Deduped, named EVM candidate list: announced wallets first, then legacy. */
export function evmCandidates(announced, legacy) {
  const seen = new Set();
  const out = [];
  for (const a of announced) {
    if (!a.provider || seen.has(a.provider)) continue;
    seen.add(a.provider);
    out.push({ provider: a.provider, name: a.info.name });
  }
  for (const p of legacy) {
    if (!p || seen.has(p)) continue;
    seen.add(p);
    out.push({ provider: p, name: walletName(p) });
  }
  return out;
}

/**
 * Phantom's EVM provider answers EIP-6963 discovery and often wins the
 * candidate order, but its personal_sign rejects many valid message shapes
 * with a bare "Unexpected error" — which then looks like our app failing.
 * Real EVM-first wallets go first; Phantom-EVM only gets the last shot
 * (it still works when it is the only wallet installed).
 */
export function demotePhantomEvm(candidates) {
  const rest = candidates.filter((c) => !/phantom/i.test(c.name));
  const phantom = candidates.filter((c) => /phantom/i.test(c.name));
  return [...rest, ...phantom];
}

/**
 * Try eth_requestAccounts across candidates. Returns
 * { provider, name, address } or throws aggregated errors.
 * A user rejection (4001) aborts immediately — do not punish a deliberate
 * "no" by popping the next wallet.
 */
export async function connectFirstWallet(candidates) {
  const errors = [];
  for (const c of candidates) {
    try {
      const accounts = await c.provider.request({ method: 'eth_requestAccounts' });
      if (accounts?.[0]) return { provider: c.provider, name: c.name, address: accounts[0] };
      errors.push(`${c.name}: returned no account`);
    } catch (err) {
      if (isRejected(err)) throw new Error('connection rejected in wallet');
      errors.push(`${c.name}: ${err.message || String(err)}`);
    }
  }
  throw new Error(errors.join(' | ') || 'no wallet approved the connection');
}

/** EIP-4361 message. `address` MUST already be EIP-55 checksummed. */
export function buildSiweMessage({ origin, address, nonce, statement = 'Sign in to wallet-auth', chainId = 1 }) {
  const issuedAt = new Date().toISOString();
  return (
    `${origin} wants you to sign in with your Ethereum account:\n${address}\n\n` +
    `${statement}\n\nURI: ${origin}/\nVersion: 1\nChain ID: ${chainId}\nNonce: ${nonce}\n` +
    `Issued At: ${issuedAt}`
  );
}

/**
 * Deduped, connectable Solana candidate list. The real Phantom bridge is
 * preferred; window.solana may be a stub claimed by another extension.
 */
export function solanaCandidates(win) {
  const seen = new Set();
  return [win.phantom?.solana, win.solana].filter((p) => {
    if (!p || seen.has(p) || typeof p.connect !== 'function') return false;
    seen.add(p);
    return true;
  });
}
