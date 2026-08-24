// Shared client helpers for the wallet-auth UI.

export function b64urlDecodeJson(jwt) {
  try {
    const payload = jwt.split('.')[1];
    return JSON.parse(atob(payload.replace(/-/g, '+').replace(/_/g, '/')));
  } catch {
    return null;
  }
}

export function getToken() {
  const m = document.cookie.match(/(?:^|;\s*)wa_session=([^;]+)/);
  if (m) return decodeURIComponent(m[1]);
  return null;
}

export function setTokenCookie(token) {
  document.cookie = `wa_session=${encodeURIComponent(token)}; path=/; max-age=86400; samesite=lax`;
}

const SCHEME_LABEL = { siwe: 'Ethereum (SIWE)', nostr: 'Nostr', solana: 'Solana' };

export function showSession(el) {
  const t = getToken();
  if (!t) {
    el.innerHTML = '<span class="pill">not signed in</span>';
    return;
  }
  const claims = b64urlDecodeJson(t);
  el.innerHTML = claims
    ? `<span class="pill">${SCHEME_LABEL[claims.scheme] || claims.scheme}</span>
       <span class="pill" style="font-family:monospace">${claims.sub.slice(0, 20)}…</span>
       <a href="#" onclick="document.cookie='wa_session=; path=/; max-age=0';location.reload();">sign out</a>`
    : '<span class="pill">invalid session</span>';
}

export async function loadConfig(el) {
  try {
    const c = await (await fetch('/config')).json();
    el.innerHTML = `<hr><small>paid verify: ${c.paidVerify ? `${c.priceUsd} on ${c.network}` : 'off'}
      · public url: ${c.publicUrl || window.location.origin}</small>`;
  } catch {
    /* ignore */
  }
}
