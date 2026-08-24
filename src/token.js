import { SignJWT, jwtVerify } from 'jose';

/** Mint a stateless HS256 session token binding identity claims. */
export function mintToken(claims, secret, ttl = '24h') {
  return new SignJWT(claims)
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setExpirationTime(ttl)
    .sign(new TextEncoder().encode(secret));
}

/** Verify a token; throws on tamper/expiry/wrong-key. */
export async function verifyToken(token, secret) {
  const { payload } = await jwtVerify(token, new TextEncoder().encode(secret));
  return payload;
}
