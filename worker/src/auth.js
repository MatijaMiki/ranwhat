/* Who may have what Plus sells: entitled() reads the feed token a request
 * carries and says whether it is live, and which account it belongs to.
 *
 * Kept apart from feed.js so that the next paid route asks the same
 * question the same way, rather than growing its own copy of the check.
 *
 * Tokens are kept as a SHA-256 in D1 (the tokens table), never as
 * themselves: a copy of the database hands out no feed. A paid one is made
 * by stripe.js and tied to its Stripe subscription (token_subscriptions),
 * and works while that subscription does. One made by hand with
 * scripts/feed_token.py has no subscription and works until it is revoked.
 * Either is refused once revoked, or past its expires_at.
 */
const TOKEN = /^Bearer (rw_[A-Za-z0-9_-]{20,200})$/;

const SCHEMA = [
  `CREATE TABLE IF NOT EXISTS tokens (
     hash TEXT PRIMARY KEY,
     note TEXT NOT NULL,
     created_at INTEGER NOT NULL,
     expires_at INTEGER,
     revoked_at INTEGER)`,
  /* One row per Stripe subscription, with its status as Stripe last gave it.
     gen: which token stripe.js derives for it (0 until one is replaced).
     mailed_at: the token email went out. */
  `CREATE TABLE IF NOT EXISTS subscriptions (
     id TEXT PRIMARY KEY,
     customer TEXT NOT NULL,
     status TEXT NOT NULL,
     gen INTEGER NOT NULL DEFAULT 0,
     mailed_at INTEGER,
     updated_at INTEGER NOT NULL)`,
  /* Which subscription a paid token belongs to. Every token ever issued for
     one stays tied to it, so none outlives the subscription. */
  `CREATE TABLE IF NOT EXISTS token_subscriptions (
     hash TEXT PRIMARY KEY,
     subscription TEXT NOT NULL)`,
];

/* Stripe's statuses that keep the feed on. past_due: a renewal failed and
   Stripe is still retrying the card, which is not the moment to cut anyone
   off. unpaid, canceled, incomplete, incomplete_expired and paused do not. */
export const LIVE = new Set(["active", "trialing", "past_due"]);

/* Made on first use, like the list's tables, so a deploy needs nothing run
   by hand. */
const made = new WeakSet();
export async function schema(db) {
  if (made.has(db)) return;
  await db.batch(SCHEMA.map((sql) => db.prepare(sql)));
  made.add(db);
}

export async function sha256(text) {
  const bytes = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text)));
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/* { ok: true, account } for a live token, else { ok: false, status, error }
   for the caller to send back as it sends its other errors.

   account: the Stripe subscription id for a paid token, so every token a
   subscription has been issued counts as one customer; "tok:" and the
   token's hash for one made by hand, which has no subscription to name. It
   is never the token, so it can be stored without becoming one. */
export async function entitled(request, env) {
  const m = (request.headers.get("authorization") || "").match(TOKEN);
  if (!m) return { ok: false, status: 401, error: "A feed token is needed: https://ranwhat.com/pricing" };
  if (!env.LIST) return { ok: false, status: 503, error: "The feed is not available just now." };
  await schema(env.LIST);
  const hash = await sha256(m[1]);
  const row = await env.LIST.prepare(
    `SELECT t.expires_at, t.revoked_at, l.subscription, s.status FROM tokens t
       LEFT JOIN token_subscriptions l ON l.hash = t.hash
       LEFT JOIN subscriptions s ON s.id = l.subscription
     WHERE t.hash = ?`).bind(hash).first();
  const now = Math.floor(Date.now() / 1000);
  if (!row || row.revoked_at || (row.expires_at && row.expires_at <= now) ||
      (row.subscription && !LIVE.has(row.status))) {
    return { ok: false, status: 403, error: "That token was not accepted." };
  }
  return { ok: true, account: row.subscription || `tok:${hash}` };
}
