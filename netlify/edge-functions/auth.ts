// netlify/edge-functions/auth.ts
// Server-enforced gate for private routes.
// Expects a cookie "mh_token" signed with HMAC-SHA256 using env MH_SESSION_SECRET.
// Token format: base64url(JSON payload) + "." + base64url(signature)
// Payload must include an "exp" (ms since epoch).

const COOKIE_NAME = "mh_token";

// Routes that must be protected (edit to match your site)
const PRIVATE_PATTERNS: RegExp[] = [
  /^\/preview(\/|$)/i,
  /^\/app(\/|$)/i,
  /^\/assets\/private(\/|$)/i,
];

// Public routes/endpoints that must NEVER be blocked
const ALLOW_PATTERNS: RegExp[] = [
  /^\/invite(\/|$)/i,
  /^\/api\/validate(\/|$)/i,
  /^\/\.netlify\/functions\/validate(\/|$)/i,
  /^\/\.netlify\/functions\/invite(\/|$)/i,
  /^\/robots\.txt$/i,
  /^\/favicon\.ico$/i,
  // Assets used by the invite page (adjust as needed)
  /^\/assets\/invite(\/|$)/i,
  /^\/css(\/|$)/i,
  /^\/js(\/|$)/i,
  // Allow any non-private assets (keeps /assets/private blocked)
  /^\/assets(\/(?!private\/).*)?$/i,
];

const ALLOW_PATTERNS = [
  /^\/invite(\/|$)/i,
  /^\/api\/invite(\/|$)/i,
  /^\/\.netlify\/functions\/invite(\/|$)/i,
  // … plus robots.txt, favicon, and assets the invite page uses
];


function isPrivatePath(pathname: string): boolean {
  return PRIVATE_PATTERNS.some((rx) => rx.test(pathname));
}

function isAllowedPath(pathname: string): boolean {
  return ALLOW_PATTERNS.some((rx) => rx.test(pathname));
}

function parseCookies(header: string | null): Record<string, string> {
  const out: Record<string, string> = {};
  if (!header) return out;
  header.split(";").forEach((pair) => {
    const [k, ...v] = pair.trim().split("=");
    if (!k) return;
    out[k] = decodeURIComponent(v.join("=") || "");
  });
  return out;
}

// base64url helpers
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

async function verifyHmacToken(token: string, secret: string): Promise<{ ok: boolean; payload?: any }> {
  try {
    const [payloadB64, sigB64] = token.split(".");
    if (!payloadB64 || !sigB64) return { ok: false };

    const key = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(secret),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign", "verify"]
    );

    const data = new TextEncoder().encode(payloadB64);
    const expectedSig = await crypto.subtle.sign("HMAC", key, data);
    const expectedB64 = b64urlEncode(expectedSig);

    // Constant-time-ish compare
    if (expectedB64.length !== sigB64.length) return { ok: false };
    let diff = 0;
    for (let i = 0; i < expectedB64.length; i++) diff |= expectedB64.charCodeAt(i) ^ sigB64.charCodeAt(i);
    if (diff !== 0) return { ok: false };

    const jsonBytes = b64urlDecodeToBytes(payloadB64);
    const payload = JSON.parse(new TextDecoder().decode(jsonBytes));

    if (typeof payload.exp === "number" && Date.now() > payload.exp) return { ok: false };

    return { ok: true, payload };
  } catch {
    return { ok: false };
  }
}

export default async (req: Request) => {
  const url = new URL(req.url);
  const path = url.pathname;

  // Allow preflights and safe methods
  if (req.method === "OPTIONS" || req.method === "HEAD") return;

  // Public paths are allowed
  if (isAllowedPath(path)) return;

  // Only guard private paths
  if (!isPrivatePath(path)) return;

  const secret = Deno.env.get("MH_SESSION_SECRET") || "";
  if (!secret) {
    // If not configured, fail safe: send to /invite
    return Response.redirect(new URL("/invite", url), 302);
  }

  const cookies = parseCookies(req.headers.get("cookie"));
  const token = cookies[COOKIE_NAME];

  if (!token) {
    // No session → go to invite with return param
    const next = encodeURIComponent(url.pathname + (url.search || ""));
    return Response.redirect(new URL(`/invite?next=${next}`, url), 302);
  }

  const { ok } = await verifyHmacToken(token, secret);
  if (!ok) {
    // Invalid / expired token → clear cookie and redirect
    const res = Response.redirect(new URL("/invite", url), 302);
    (res.headers as Headers).append(
      "Set-Cookie",
      `${COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`
    );
    return res;
  }

  // Auth OK → allow request to continue
  return;
};

// Optional: if you prefer file-local config instead of netlify.toml
// export const config = { path: "/*" };
