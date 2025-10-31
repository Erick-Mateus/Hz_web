// Deno runtime (default on Netlify Functions)

type Body = { code?: string };

function b64(input: string | Uint8Array) {
  if (typeof input === "string") input = new TextEncoder().encode(input);
  return btoa(String.fromCharCode(...new Uint8Array(input)));
}

async function sha256Hex(s: string) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2,"0")).join("");
}

function timingSafeEq(a: string, b: string) {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

export default async (req: Request) => {
  if (req.method !== "POST") {
    return new Response("Method Not Allowed", { status: 405 });
  }

  const secret = Deno.env.get("MH_SESSION_SECRET") || "";
  const codeHashes = (Deno.env.get("MH_INVITE_CODE_HASHES") || "")
    .split(",").map(s => s.trim()).filter(Boolean);

  if (!secret || codeHashes.length === 0) {
    return new Response("Server not configured", { status: 500 });
  }

  let body: Body = {};
  try { body = await req.json(); } catch { /* ignore */ }
  const code = (body.code || "").trim();
  if (!code) {
    await new Promise(r => setTimeout(r, 160)); // uniform timing
    return new Response(JSON.stringify({ ok:false }), {
      status: 401, headers: { "Content-Type": "application/json" }
    });
  }

  const hash = await sha256Hex(code);
  const match = codeHashes.some(h => timingSafeEq(h, hash));
  await new Promise(r => setTimeout(r, 160 + Math.random()*80)); // constant-ish timing

  if (!match) {
    return new Response(JSON.stringify({ ok:false }), {
      status: 401, headers: { "Content-Type": "application/json" }
    });
  }

  // issue signed session cookie (14 days)
  const payload = { iat: Date.now(), exp: Date.now() + 1000*60*60*24*14 };
  const b64payload = b64(JSON.stringify(payload));
  const key = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(b64payload));
  const token = `${b64payload}.${b64(sig)}`;

  const headers = new Headers({
    "Content-Type": "application/json",
    "Set-Cookie": `mh_token=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${60*60*24*14}`
  });
  return new Response(JSON.stringify({ ok:true }), { status: 200, headers });
};
