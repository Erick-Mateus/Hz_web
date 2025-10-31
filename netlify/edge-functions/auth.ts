// Runs at the edge on every request
const PRIVATE_PREFIXES = [
  /^\/preview(\/|$)/i,
  /^\/app(\/|$)/i,
  /^\/assets\/private(\/|$)/i,
];

function isPrivate(pathname: string) {
  return PRIVATE_PREFIXES.some(rx => rx.test(pathname));
}

function getCookieMap(h: string | null) {
  const out: Record<string,string> = {};
  if (!h) return out;
  h.split(";").forEach(p => {
    const [k, ...v] = p.trim().split("=");
    if (k) out[k] = decodeURIComponent(v.join("=") || "");
  });
  return out;
}

async function verifyToken(token: string, secret: string) {
  try {
    const [b64, sig] = token.split(".");
    if (!b64 || !sig) return false;
    const data = new TextEncoder().encode(b64);
    const key = await crypto.subtle.importKey(
      "raw", new TextEncoder().encode(secret),
      { name: "HMAC", hash: "SHA-256" }, false, ["sign","verify"]
    );
    const expected = await crypto.subtle.sign("HMAC", key, data);
    const expectedB64 = btoa(String.fromCharCode(...new Uint8Array(expected)));
    if (expectedB64 !== sig) return false;

    const payload = JSON.parse(atob(b64));
    if (payload.exp && Date.now() > payload.exp) return false;
    return true;
  } catch {
    return false;
  }
}

export default async (req: Request) => {
  const url = new URL(req.url);
  if (!isPrivate(url.pathname)) return; // allow public paths

  const cookie = getCookieMap(req.headers.get("cookie"));
  const token = cookie["mh_token"];
  const secret = Deno.env.get("MH_SESSION_SECRET") || "";
  if (!token || !secret) {
    return Response.redirect(new URL("/invite", url), 302);
  }
  const ok = await verifyToken(token, secret);
  if (!ok) {
    return Response.redirect(new URL("/invite", url), 302);
  }
  return; // allow
};

export const config = { path: "/*" };
