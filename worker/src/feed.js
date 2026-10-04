/* GET https://feed.ranwhat.com/v1/catalogue: the capability catalogue, for
 * `ranwhat update` (ranwhat/feed.py), to anyone holding a live token.
 *
 * The document is worker/feed/catalogue.json, made by scripts/feed.py from
 * ranwhat/catalog.py and checked there by the client's own validator, so
 * this file only decides who gets it. The client sends the token and
 * nothing else, and nothing here records anything about the request.
 *
 * Tokens are kept as a SHA-256 in D1 (the tokens table), never as
 * themselves: a copy of the database hands out no feed. They are made by
 * scripts/feed_token.py now, and by the Stripe webhook once checkout exists.
 * One that is revoked, or past its expires_at, is refused.
 */
import FEED from "../feed/catalogue.json" with { type: "json" };

const BODY = JSON.stringify(FEED);
const TOKEN = /^Bearer (rw_[A-Za-z0-9_-]{20,200})$/;

const SCHEMA = `CREATE TABLE IF NOT EXISTS tokens (
  hash TEXT PRIMARY KEY,
  note TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER,
  revoked_at INTEGER)`;

const made = new WeakSet();
async function schema(db) {
  if (made.has(db)) return;
  await db.prepare(SCHEMA).run();
  made.add(db);
}

const refuse = (status, error) => new Response(JSON.stringify({ error }), {
  status,
  headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" },
});

async function sha256(text) {
  const bytes = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text)));
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export async function catalogue(request, env) {
  const m = (request.headers.get("authorization") || "").match(TOKEN);
  if (!m) return refuse(401, "A feed token is needed: https://ranwhat.com/pricing");
  if (!env.LIST) return refuse(503, "The feed is not available just now.");
  await schema(env.LIST);
  const row = await env.LIST.prepare("SELECT expires_at, revoked_at FROM tokens WHERE hash = ?")
    .bind(await sha256(m[1])).first();
  const now = Math.floor(Date.now() / 1000);
  if (!row || row.revoked_at || (row.expires_at && row.expires_at <= now)) {
    return refuse(403, "That token was not accepted.");
  }
  return new Response(BODY, {
    status: 200,
    headers: {
      "content-type": "application/json; charset=utf-8",
      /* One subscriber's answer is never another's: nothing may cache it. */
      "cache-control": "private, no-store",
      "x-content-type-options": "nosniff",
    },
  });
}
