// netlify/edge-functions/auth.ts
// Edge gate for private routes. Verifies HMAC-signed cookie "mh_token".
// Needs env: MH_SESSION_SECRET. Your invite function must set the cookie.

const COOKIE_NAME = "mh_token";

// --- Private routes you want to protect ---
const PRIVATE_PATTERNS: RegExp[] = [
  /^\/preview(\/|$)/i,
  /^\/app(\/|$)/i,
  /^\/assets\/private(\/|$)/i,
];

// --- Public routes/endpoints that must be allowed ---
const ALLOW_PATTERNS: RegExp[] = [
  /^\/invite(\/|$)/i,
  /^\/api\/invite(\/|$)/i,
  /^\/\.netlify\/functions\/invite(\/|$)/i,
  /^\/robots\.txt$/i,
  /^\/favicon\.ico$/i,
  // assets used by the invite page (adjust to your project)
  /^\/assets\/invite(\/|$)/i,
  /^\/css(\/|$)/i,
  /^\/js(\/|$)/i,
  // allow any non-private assets (keeps /assets/private blocked)
  /^\/assets(\/(?!private\/).*)?$/i,
];

function isPrivatePath(path: string): boolean {
  return PRIVATE_PATTERNS.some(rx => rx.test(path));
}
function isAllowedPath(path: string): boolean {
  return ALLOW_PATTERNS.some(rx => rx.test(path));
}
function parseCookies(header: string | null): Record<string, string> {
  const out: Record<string, string> = {};
  if (!header) return out;
  header.split(";").forEach(kv => {
    const [k, ...v] = kv.trim().split("=");
    if (k) out[k] = decodeURIComponent(v.join("=") || "");
  });
  return out;
}
function b64urlEncode(bytes: ArrayBuffer): string {
  const bin = String.fromCharCode(...new Uint8Array(bytes));
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
function b64urlDecodeToBytes(b64url: string): Uint8Array {
  const b64 = b64url.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((b64url.length + 3) % 4);
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
async function verifyToken(token: string, secret: string): Promise<boolean> {
  try {
    const [payloadB64, sigB64] = token.split(".");
    if (!payloadB64 || !sigB64) return false;

    const key = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(secret),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign", "verify"]
    );
    const expected = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(payloadB64));
    const expectedB64 = b64urlEncode(expected);

    // constant-time-ish compare
    if (expectedB64.length !== sigB64.length) return false;
    let diff = 0;
    for (let i = 0; i < expectedB64.length; i++) diff |= expectedB64.charCodeAt(i) ^ sigB64.charCodeAt(i);
    if (diff !== 0) return false;

    const payload = JSON.parse(new TextDecoder().decode(b64urlDecodeToBytes(payloadB64)));
    if (typeof payload.exp === "number" && Date.now() > payload.exp) return false;

    return true;
  } catch {
    return false;
  }
}

export default async (req: Request) => {
  const url = new URL(req.url);
  const path = url.pathname;

  // allow preflights and heads
  if (req.method === "OPTIONS" || req.method === "HEAD") return;

  // allow explicitly allowed paths
  if (isAllowedPath(path)) return;

  // only guard private paths
  if (!isPrivatePath(path)) return;

  const secret = Deno.env.get("MH_SESSION_SECRET") || "";
  if (!secret) {
    return Response.redirect(new URL("/invite", url), 302);
  }

  const cookies = parseCookies(req.headers.get("cookie"));
  const token = cookies[COOKIE_NAME];

  if (!token) {
    const next = encodeURIComponent(url.pathname + (url.search || ""));
    return Response.redirect(new URL(`/invite?next=${next}`, url), 302);
  }

  const ok = await verifyToken(token, secret);
  if (!ok) {
    const res = Response.redirect(new URL("/invite", url), 302);
    (res.headers as Headers).append(
      "Set-Cookie",
      `${COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`
    );
    return res;
  }

  // token valid → allow
  return;
};

// If you prefer file-local config:
// export const config = { path: "/*" };
