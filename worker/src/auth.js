/* Who may have what Plus sells: identify() reads the feed token a request
 * carries and says whose it is and on which plan; entitled() adds whether
 * that plan has the feature asked for, from features.js's one map.
 *
 * Kept apart from feed.js so that the next paid route asks the same
 * question the same way, rather than growing its own copy of the check.
 *
 * Tokens are kept as a SHA-256 in D1 (the tokens table), never as
 * themselves: a copy of the database hands out no feed. A token is one of
 * three kinds, tried in this order:
 *
 *   device, ci    A machine linked to an organisation (accounts.js's
 *                 machines), on that organisation's plan. Read whenever
 *                 the machines table exists, ACCOUNTS_ON or not, so that
 *                 switching accounts off never puts a Free organisation's
 *                 machines on Plus.
 *   subscription  Made by stripe.js and tied to its Stripe subscription
 *                 (token_subscriptions); works while that subscription does.
 *   hand          Made with scripts/feed_token.py, with no subscription;
 *                 works until it is revoked.
 *
 * Any of them is refused once revoked, or past its expires_at. The last two
 * answer exactly as they did before organisations existed.
 */
import { accountsOn, schema as accountsSchema } from "./accounts.js";
import { allows } from "./features.js";

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

/* The token's row, with whatever it is tied to. LEGACY is the query from
   before accounts, for a database that has never had their tables, where
   no machine can have been linked. Once it has them, LINKED is the query,
   whether accounts are switched on or not: a machine's token is a plain
   tokens row with no subscription, so under LEGACY it would pass for one
   made by hand, on Plus. */
const LEGACY = `SELECT t.expires_at, t.revoked_at, l.subscription, s.status FROM tokens t
       LEFT JOIN token_subscriptions l ON l.hash = t.hash
       LEFT JOIN subscriptions s ON s.id = l.subscription
     WHERE t.hash = ?`;
const LINKED = `SELECT t.expires_at, t.revoked_at, l.subscription, s.status,
       m.id AS machine, m.kind, m.org_id AS machine_org, m.user_id, m.label, m.created_at AS linked_at,
       m.last_used_day,
       o.org_id AS claimed_by
     FROM tokens t
       LEFT JOIN token_subscriptions l ON l.hash = t.hash
       LEFT JOIN subscriptions s ON s.id = l.subscription
       LEFT JOIN machines m ON m.hash = t.hash AND m.kind IN ('device', 'ci')
       LEFT JOIN org_subscriptions o ON o.subscription = l.subscription
     WHERE t.hash = ?`;

const unix = () => Math.floor(Date.now() / 1000);

/* The start (00:00 UTC) of the day a time falls in: when a machine was
   last used, to the day and no finer. */
const DAY = 24 * 3600;
const dayOf = (t) => Math.floor(t / DAY) * DAY;

/* Whether a database has the accounts tables (machines among them). Asked
   of sqlite_master, which is the schema, not one of their tables, so a
   database that has never had them is not read any further. Remembered
   once true: tables are never dropped. */
const linkedDbs = new WeakSet();
async function hasMachines(db) {
  if (linkedDbs.has(db)) return true;
  const row = await db.prepare("SELECT 1 AS yes FROM sqlite_master WHERE type = 'table' AND name = 'machines'")
    .first();
  if (row) linkedDbs.add(db);
  return Boolean(row);
}

/* An organisation's plan, worked out now and never stored:
     'team'  while a team grant is in force;
     'plus'  while a plus grant (a comp) is, or any subscription linked to
             it in org_subscriptions is LIVE;
     'free'  otherwise.
   A grant is in force from starts_at until `until`, or for good when that
   is NULL; scripts/org_admin.py writes both, and revokes by setting until. */
export async function plan(env, orgId) {
  if (!orgId || !env.LIST) return "free";
  const db = env.LIST;
  await schema(db);
  await accountsSchema(db);
  const t = unix();
  const live = [...LIVE];
  const inForce = "org_id = ? AND starts_at <= ? AND (until IS NULL OR until > ?)";
  const row = await db.prepare(
    `SELECT EXISTS (SELECT 1 FROM grants WHERE ${inForce} AND plan = 'team') AS team,
            EXISTS (SELECT 1 FROM grants WHERE ${inForce} AND plan = 'plus') AS comp,
            EXISTS (SELECT 1 FROM org_subscriptions o JOIN subscriptions s ON s.id = o.subscription
                    WHERE o.org_id = ? AND s.status IN (${live.map(() => "?").join(", ")})) AS paid`)
    .bind(orgId, t, t, orgId, t, t, orgId, ...live).first();
  if (row && row.team) return "team";
  if (row && (row.comp || row.paid)) return "plus";
  return "free";
}

/* Whose the token a request carries is, and on which plan:
     { ok: true, kind, account, plan, org, machine? }
   or { ok: false, status, error } for the caller to send back as it sends
   its other errors.

   account: who is counted as the customer, and never the token, so it can
   be stored without becoming one. The organisation ("org:" and its id) for
   a machine; the Stripe subscription id for a paid token, so every token a
   subscription has been issued counts as one customer; "tok:" and the
   token's hash for one made by hand, which has no subscription to name.

   org: the organisation a machine belongs to, or that a subscription has
   been linked to; null for a token made by hand. A subscription's or a
   hand-made token's plan is Plus, or the linked organisation's if that is
   more. */
export async function identify(request, env) {
  const m = (request.headers.get("authorization") || "").match(TOKEN);
  if (!m) return { ok: false, status: 401, error: "A feed token is needed: https://ranwhat.com/pricing" };
  if (!env.LIST) return { ok: false, status: 503, error: "The feed is not available just now." };
  const db = env.LIST;
  await schema(db);
  if (accountsOn(env)) await accountsSchema(db);
  const linked = await hasMachines(db);
  const hash = await sha256(m[1]);
  const row = await db.prepare(linked ? LINKED : LEGACY).bind(hash).first();
  const t = unix();
  const refused = { ok: false, status: 403, error: "That token was not accepted." };
  if (!row || row.revoked_at || (row.expires_at && row.expires_at <= t)) return refused;
  if (row.machine) {
    /* The day it was last used, written at most once a day, and only for
       a machine (device or ci): never for a shared or hand-made token. */
    const day = dayOf(t);
    if (row.last_used_day === null || row.last_used_day < day) {
      await db.prepare("UPDATE machines SET last_used_day = ? WHERE id = ? AND (last_used_day IS NULL OR last_used_day < ?)")
        .bind(day, row.machine, day).run();
    }
    return {
      ok: true, kind: row.kind, account: `org:${row.machine_org}`, org: row.machine_org,
      plan: await plan(env, row.machine_org),
      /* label: null until it is named on the web; a terminal's machines
         row keeps '' until then (device.js). */
      machine: { id: row.machine, user: row.user_id, label: row.label || null, linked_at: row.linked_at },
    };
  }
  if (row.subscription) {
    if (!LIVE.has(row.status)) return refused;
    const org = row.claimed_by || null;
    return { ok: true, kind: "subscription", account: row.subscription, org,
             plan: org ? await plan(env, org) : "plus" };
  }
  return { ok: true, kind: "hand", account: `tok:${hash}`, org: null, plan: "plus" };
}

export const UPGRADE = "https://account.ranwhat.com/";

/* identify(), and whether the token's plan has `feature` (features.js).
   { ok: true, account } when it does; a token whose organisation's plan
   has not got it is refused with 403 'plus_required' (or 'team_required')
   and where to upgrade. Subscription and hand-made tokens are on Plus at
   least, so for the feed they answer as they always have. */
export async function entitled(request, env, feature = "feed") {
  const who = await identify(request, env);
  if (!who.ok) return who;
  if (!allows(who.plan, feature)) {
    return { ok: false, status: 403, error: allows("plus", feature) ? "plus_required" : "team_required",
             upgrade: UPGRADE };
  }
  return { ok: true, account: who.account };
}
