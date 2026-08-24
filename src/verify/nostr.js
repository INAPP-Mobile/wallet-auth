import { nip98, verifyEvent } from 'nostr-tools';

/**
 * Pure NIP-98 (Nostr HTTP Auth) event verification — no store, no tokens.
 * Always validates: base64 token format, event id hash, schnorr signature,
 * kind 27235, ±60s timestamp. When `url` is provided the u/method tags are
 * validated against it too.
 */
export async function verifyNip98({ token, url }) {
  let event;
  try {
    event = await nip98.unpackEventFromToken(token);
  } catch {
    throw malformed('Malformed Nostr auth token');
  }
  if (!verifyEvent(event)) throw rejected('Event id/signature invalid');
  if (!nip98.validateEventKind(event)) throw rejected('Not a NIP-98 auth event (kind 27235)');
  if (!nip98.validateEventTimestamp(event)) throw rejected('Event timestamp outside ±60s window');

  if (url !== undefined && url !== null) {
    try {
      await nip98.validateEvent(event, String(url), 'post');
    } catch (err) {
      throw rejected(`URL/method binding failed: ${err.message}`);
    }
  }
  return { pubkey: event.pubkey, eventId: event.id };
}

function malformed(message) {
  const e = new Error(message);
  e.status = 400;
  return e;
}
function rejected(message) {
  const e = new Error(message);
  e.status = 401;
  return e;
}
