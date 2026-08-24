import nacl from 'tweetnacl';
import bs58 from 'bs58';

/**
 * Pure Solana ed25519 message verification — no nonce store, no tokens.
 * `pubkey` and `signature` are base58; `message` is UTF-8 text.
 */
export function verifySolana({ pubkey, message, signature }) {
  let pubkeyBytes;
  try {
    pubkeyBytes = bs58.decode(String(pubkey));
  } catch {
    throw badRequest('pubkey is not valid base58');
  }
  if (pubkeyBytes.length !== 32) throw badRequest('pubkey must decode to 32 bytes');

  let sigBytes;
  try {
    sigBytes = bs58.decode(String(signature));
  } catch {
    throw badRequest('signature is not valid base58');
  }

  const ok = nacl.sign.detached.verify(
    new TextEncoder().encode(String(message)),
    sigBytes,
    pubkeyBytes,
  );
  if (!ok) throw rejected('Signature invalid');
  return { pubkey: String(pubkey) };
}

function badRequest(message) {
  const e = new Error(message);
  e.status = 400;
  return e;
}
function rejected(message) {
  const e = new Error(message);
  e.status = 401;
  return e;
}
