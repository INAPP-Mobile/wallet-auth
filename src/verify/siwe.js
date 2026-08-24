import { SiweMessage } from 'siwe';

/**
 * Pure SIWE (EIP-4361) verification — no nonce store, no tokens.
 * Throws on any failure. Honors message expiration/notBefore fields.
 */
export async function verifySiwe({ message, signature }) {
  const msg = new SiweMessage(String(message));
  const res = await msg.verify({ signature });
  if (!res.success) {
    const err = new Error(res.error?.type || 'SIWE verification failed');
    err.expose = true;
    throw err;
  }
  return { address: msg.address, chainId: msg.chainId ?? null, nonce: msg.nonce ?? null };
}
