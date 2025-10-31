// netlify/functions/invite.js
// Node.js Netlify Function (CommonJS).
// Validates invite code server-side and sets a signed cookie "mh_token".

const crypto = require("crypto");

// Helper: constant-time compare
function timingSafeEqHex(a, b) {
  if (a.length !== b.length) return false;
  // compare as buffers to avoid early-exit timing leaks
  const ba = Buffer.from(a, "hex");
  const bb = Buffer.from(b, "hex");
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}

exports.handler = async (event, context) => {
  // Allow preflight
  if (event.httpMethod === "OPTIONS") {
    return { statusCode: 204, headers: {} };
  }

  if (event.httpMethod !== "POST") {
    return { statusCode: 405, body: "Method Not Allowed" };
  }

  const secret = process.env.MH_SESSION_SECRET || "";
  const hashesCsv = process.env.MH_INVITE_CODE_HASHES || "";
  const inviteHashes = hashesCsv.split(",").map(s => s.trim()).filter(Boolean);

  if (!secret || inviteHashes.length === 0) {
    return { statusCode: 500, body: "Server not configured" };
  }

  let code = "";
  try {
    const body = JSON.parse(event.body || "{}");
    code = (body.code || "").trim();
  } catch {
    return { statusCode: 400, body: "Bad Request" };
  }

  if (!code) {
    // uniform-ish timing
    await new Promise(r => setTimeout(r, 150));
    return {
      statusCode: 401,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ok: false })
    };
  }

  // Hash the provided code and compare against allowed list
  const hash = crypto.createHash("sha256").update(code, "utf8").digest("hex");
  const match = inviteHashes.some(h => timingSafeEqHex(h, hash));

  // Add small jitter to reduce timing hints
  await new Promise(r => setTimeout(r, 100 + Math.random() * 80));

  if (!match) {
    return {
      statusCode: 401,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ok: false })
    };
  }

  // Build HMAC-signed session token (14 days)
  const payload = { iat: Date.now(), exp: Date.now() + 14 * 24 * 60 * 60 * 1000 };
  const payloadStr = JSON.stringify(payload);
  const payloadB64 = Buffer.from(payloadStr, "utf8").toString("base64url");
  const sig = crypto.createHmac("sha256", secret).update(payloadB64, "utf8").digest("base64url");
  const token = `${payloadB64}.${sig}`;

  const headers = {
    "Content-Type": "application/json",
    // HttpOnly cookie for the Edge gate to read
    "Set-Cookie": `mh_token=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${14 * 24 * 60 * 60}`
  };

  return {
    statusCode: 200,
    headers,
    body: JSON.stringify({ ok: true })
  };
};
