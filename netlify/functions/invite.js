// netlify/functions/invite.js
exports.handler = async (event) => {
  console.log('Invite function hit', { method: event.httpMethod, body: event.body });

  if (event.httpMethod !== "POST") {
    return { statusCode: 405, body: "Method Not Allowed" };
  }

  let code = '';
  try {
    const body = JSON.parse(event.body || "{}");
    code = (body.code || "").trim();
  } catch (e) {
    console.error('JSON parse error:', e);
    return { statusCode: 400, body: "Bad Request" };
  }

  const single = (process.env.INVITE_CODE || "").trim();
  const list = (process.env.INVITE_CODES || "").split(",").map(s => s.trim()).filter(Boolean);
  const valid = (single && code === single) || (list.length > 0 && list.includes(code));

  console.log('Validation', { code, single, list, valid });

  if (!valid) {
    return {
      statusCode: 401,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ok: false, message: "Invalid invitation code." })
    };
  }

  return {
    statusCode: 200,
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ ok: true, redirect: "/preview/" })
  };
};

