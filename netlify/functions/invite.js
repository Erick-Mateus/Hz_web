// netlify/functions/invite.ts
// Netlify Functions (Deno runtime). Validates invite code server-side,
// then sets a signed session cookie "mh_token" (HMAC-SHA256).
// Requires env vars: MH_SESSION_SECRET and MH_INVITE_CODE_HASHES (SHA-256 hashes).

type Body = { code?: string };

function b64url(bytes: ArrayBuffer | Uint8Array | string): string {
  let u8: Uint8Array;
  if (typeof bytes === "string") u8 = new TextEncoder().encode(bytes);
  else if (bytes instanceof Uint8Array) u8 = bytes;
  else u8 = new Uint8Array(bytes);
  const bin = String.fromCharCode(...u8);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

async function sha256Hex(s: string) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, "0")).join("");
}

function timingSafeEq(a: string, b: string) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

export default async (req: Request) => {
  if (req.method === "OPTIONS") {
    return new Response(null, { status: 204 }); // allow preflight if any
  }
  if (req.method !== "POST") {
    return new Response("Method Not Allowed", { status: 405 });
  }

  const secret = Deno.env.get("MH_SESSION_SECRET") || "";
  const hashesCsv = Deno.env.get("MH_INVITE_CODE_HASHES") || "";
  const inviteHashes = hashesCsv.split(",").map(s => s.trim()).filter(Boolean);

  if (!secret || inviteHashes.length === 0) {
    // Fail safe if not configured
    return new Response("Server not configured", { status: 500 });
  }

  let code = "";
  try {
    const body = (await req.json()) as Body;
    code = (body.code || "").trim();
  } catch {
    return new Response("Bad Request", { status: 400 });
  }

  if (!code) {
    // uniform response for missing/invalid
    await new Promise(r => setTimeout(r, 150)); // jitter for timing uniformity
    return new Response(JSON.stringify({ ok: false }), {
      status: 401,
      headers: { "Content-Type": "application/json" },
    });
  }

  // Compare hash of provided code against allowed list
  const hash = await sha256Hex(code);
  const match = inviteHashes.some(h => timingSafeEq(h, hash));

  // constant-ish timing
  await new Promise(r => setTimeout(r, 120 + Math.random() * 80));

  if (!match) {
    return new Response(JSON.stringify({ ok: false }), {
      status: 401,
      headers: { "Content-Type": "application/json" },
    });
  }

  // Create signed session token (14 days)
  const payload = { iat: Date.now(), exp: Date.now() + 14 * 24 * 60 * 60 * 1000 };
  const payloadB64 = b64url(JSON.stringify(payload));

  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sigBuf = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(payloadB64));
  const token = `${payloadB64}.${b64url(sigBuf)}`;

  const headers = new Headers({
    "Content-Type": "application/json",
  });

  // HttpOnly session cookie seen by Edge Function
  headers.append(
    "Set-Cookie",
    `mh_token=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${14 * 24 * 60 * 60}`
  );

  return new Response(JSON.stringify({ ok: true }), { status: 200, headers });
};
