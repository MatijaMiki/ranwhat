/* Accounts on account.ranwhat.com: the tables, the people and
 * organisations in them, the audit log, and the daily budget for the email
 * that signs people in.
 *
 * Dark until ACCOUNTS_ON is set: until then index.js answers 404 to
 * everything on the account host, before any of this runs, and the cron
 * leaves these tables alone.
 *
 * Every table the accounts design needs is made here, in one go, including
 * the ones later work fills (passwords, passkeys, Google and GitHub
 * identities, machines, subscriptions linked to an organisation, grants,
 * invites, device codes). Later changes then add routes, not ALTERs.
 *
 * Sign-in methods meet in one place, userForVerifiedEmail(). The emailed
 * code is the first; a password, Google, GitHub and passkeys come through
 * the same door. Two methods land on the same account only through an
 * address the method itself verified, never through one someone typed.
 *
 * The tables live in the feed's D1 database (LIST) rather than a new one,
 * because machines join the feed's tokens and org_subscriptions joins its
 * subscriptions.
 */

export const ACCOUNT_HOST = "account.ranwhat.com";
export const ACCOUNT_ORIGIN = `https://${ACCOUNT_HOST}`;

export const HOUR = 3600;
export const DAY = 24 * HOUR;
export const SESSION_IDLE = 14 * DAY;   // a session nobody used for this long is over
export const SESSION_MAX = 30 * DAY;    // and none lasts longer than this after sign-in
const KEEP_EVENTS = 396 * DAY;          // the audit log: 13 months
const KEEP_COUNTS = 7 * DAY;            // the daily email counts

/* Sign-in codes, fresh-code checks, address checks and password resets
   share Resend's free plan, 100 emails a day, with the paid token emails
   and the release list's confirmations. This keeps the account mail to
   about 60, so a burst of sign-ups can never hold back someone's token. */
export const AUTH_MAIL_PER_DAY = 60;

export const now = () => Math.floor(Date.now() / 1000);

/* "1" or "true" switch accounts on; unset, empty or anything else keeps
   them dark. */
export const accountsOn = (env) => ["1", "true"].includes(String(env.ACCOUNTS_ON ?? "").trim().toLowerCase());

/* Switched on and able to work: the database, a way to send the code, and
   a secret of its own to keep codes and form tokens under. Never
   LIST_SECRET, which every feed token is derived from. */
export const ready = (env) => Boolean(env.LIST && env.RESEND_API_KEY &&
  typeof env.ACCOUNT_SECRET === "string" && env.ACCOUNT_SECRET.length >= 32);

const SCHEMA = [
  /* The same table list.js makes; accounts_schema says which version of
     the tables below a database has, for the first ALTER when it comes. */
  `CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)`,

  /* A person. email is lower-cased and written only once a method has
     verified it, so a typed address never becomes an account by itself. */
  `CREATE TABLE IF NOT EXISTS users (
     id TEXT PRIMARY KEY,
     email TEXT NOT NULL UNIQUE COLLATE NOCASE,
     created_at INTEGER NOT NULL,
     signed_in_at INTEGER)`,

  /* Each way into an account. provider: 'email' (the emailed code, whose
     subject is the address), 'google' or 'github' (whose subject is the
     provider's own stable id, never the email, which can change hands).
     verified_email: the address the provider vouched for, the only thing
     accounts are joined on. Left without a CHECK so that SSO for Team adds
     rows, not a rebuilt table. */
  `CREATE TABLE IF NOT EXISTS identities (
     provider TEXT NOT NULL,
     provider_subject TEXT NOT NULL,
     user_id TEXT NOT NULL,
     verified_email TEXT COLLATE NOCASE,
     created_at INTEGER NOT NULL,
     used_at INTEGER,
     PRIMARY KEY (provider, provider_subject))`,
  `CREATE INDEX IF NOT EXISTS identities_user ON identities (user_id)`,

  /* A password, as its PBKDF2 hash with the salt and iteration count in
     the same string, never the password. One per person. */
  `CREATE TABLE IF NOT EXISTS credentials (
     user_id TEXT NOT NULL,
     kind TEXT NOT NULL CHECK (kind IN ('password')),
     hash TEXT NOT NULL,
     created_at INTEGER NOT NULL,
     updated_at INTEGER NOT NULL,
     PRIMARY KEY (user_id, kind))`,

  /* Passkeys: a WebAuthn credential's id and public key, never anything
     that could sign in by itself. */
  `CREATE TABLE IF NOT EXISTS passkeys (
     id TEXT PRIMARY KEY,
     user_id TEXT NOT NULL,
     public_key TEXT NOT NULL,
     sign_count INTEGER NOT NULL DEFAULT 0,
     transports TEXT,
     backed_up INTEGER NOT NULL DEFAULT 0,
     label TEXT,
     created_at INTEGER NOT NULL,
     used_at INTEGER)`,
  `CREATE INDEX IF NOT EXISTS passkeys_user ON passkeys (user_id)`,

  /* What a plan belongs to. customer: the Stripe cus_ id, once a checkout
     made from the account has one. */
  `CREATE TABLE IF NOT EXISTS orgs (
     id TEXT PRIMARY KEY,
     name TEXT NOT NULL,
     personal INTEGER NOT NULL DEFAULT 1,
     customer TEXT,
     created_at INTEGER NOT NULL)`,

  /* Exactly one owner per organisation, held by the database itself. */
  `CREATE TABLE IF NOT EXISTS memberships (
     org_id TEXT NOT NULL,
     user_id TEXT NOT NULL,
     role TEXT NOT NULL CHECK (role IN ('owner', 'admin', 'member')),
     created_at INTEGER NOT NULL,
     PRIMARY KEY (org_id, user_id))`,
  `CREATE INDEX IF NOT EXISTS memberships_user ON memberships (user_id)`,
  `CREATE UNIQUE INDEX IF NOT EXISTS one_owner ON memberships (org_id) WHERE role = 'owner'`,

  /* token_hash: the SHA-256 of 256 random bits; the invite link carries
     the bits. The sweep clears email once an invite is used, revoked or
     out of date. */
  `CREATE TABLE IF NOT EXISTS invites (
     id TEXT PRIMARY KEY,
     org_id TEXT NOT NULL,
     email TEXT COLLATE NOCASE,
     role TEXT NOT NULL CHECK (role IN ('admin', 'member')),
     token_hash TEXT NOT NULL UNIQUE,
     invited_by TEXT,
     created_at INTEGER NOT NULL,
     expires_at INTEGER NOT NULL,
     accepted_at INTEGER,
     revoked_at INTEGER)`,
  `CREATE UNIQUE INDEX IF NOT EXISTS open_invite ON invites (org_id, email)
     WHERE accepted_at IS NULL AND revoked_at IS NULL`,

  /* Which organisation a Stripe subscription (auth.js's subscriptions)
     pays for. One organisation can hold several; a subscription is linked
     once and never moved. */
  `CREATE TABLE IF NOT EXISTS org_subscriptions (
     subscription TEXT PRIMARY KEY,
     org_id TEXT NOT NULL,
     how TEXT NOT NULL CHECK (how IN ('checkout', 'session', 'email', 'script')),
     linked_by TEXT,
     linked_at INTEGER NOT NULL)`,
  `CREATE INDEX IF NOT EXISTS org_subscriptions_org ON org_subscriptions (org_id)`,

  /* Plus or Team given by hand (a contract, a comp), written only by an
     operator script. until NULL: no end date. */
  `CREATE TABLE IF NOT EXISTS grants (
     id INTEGER PRIMARY KEY,
     org_id TEXT NOT NULL,
     plan TEXT NOT NULL CHECK (plan IN ('plus', 'team')),
     starts_at INTEGER NOT NULL,
     until INTEGER,
     note TEXT,
     created_at INTEGER NOT NULL)`,
  `CREATE INDEX IF NOT EXISTS grants_org ON grants (org_id)`,

  /* A feed token that belongs to an organisation. hash: tokens.hash, where
     revocation stays. id: what forms name it by, never the hash. */
  `CREATE TABLE IF NOT EXISTS machines (
     id TEXT PRIMARY KEY,
     hash TEXT NOT NULL UNIQUE,
     org_id TEXT NOT NULL,
     user_id TEXT,
     kind TEXT NOT NULL CHECK (kind IN ('device', 'ci', 'legacy')),
     label TEXT NOT NULL,
     created_at INTEGER NOT NULL,
     last_used_day INTEGER)`,
  `CREATE INDEX IF NOT EXISTS machines_org ON machines (org_id)`,

  /* Signed in. id: the SHA-256 of the cookie's value, which is kept
     nowhere. org_id: the organisation being looked at, checked against
     memberships on every request. authed_at: when a code was last typed,
     for the actions that need a fresh one. No IP address, no user agent. */
  `CREATE TABLE IF NOT EXISTS sessions (
     id TEXT PRIMARY KEY,
     user_id TEXT NOT NULL,
     org_id TEXT,
     created_at INTEGER NOT NULL,
     seen_at INTEGER NOT NULL,
     authed_at INTEGER NOT NULL,
     expires_at INTEGER NOT NULL)`,
  `CREATE INDEX IF NOT EXISTS sessions_user ON sessions (user_id)`,

  /* An emailed code waiting to be typed. id: the SHA-256 of the browser's
     __Host-rw_signin cookie. code_mac: an HMAC of the code under
     ACCOUNT_SECRET. email_mac: the same for the address, to find every
     open attempt for one address without searching by the address. purpose:
     signing in, a fresh code before something sensitive, or (with
     passwords) proving an address and resetting a password. The sweep
     deletes a row once its code is out of date. */
  `CREATE TABLE IF NOT EXISTS signins (
     id TEXT PRIMARY KEY,
     email TEXT NOT NULL,
     email_mac TEXT NOT NULL,
     purpose TEXT NOT NULL CHECK (purpose IN ('signin', 'stepup', 'verify', 'reset')),
     user_id TEXT,
     code_mac TEXT NOT NULL,
     next TEXT NOT NULL DEFAULT '/',
     created_at INTEGER NOT NULL,
     expires_at INTEGER NOT NULL,
     tries INTEGER NOT NULL DEFAULT 0,
     used_at INTEGER)`,
  `CREATE INDEX IF NOT EXISTS signins_email ON signins (email_mac, created_at)`,

  /* Linking a terminal (RFC 8628). country, from Cloudflare, is the only
     thing kept about where the request came from, and goes with the row. */
  `CREATE TABLE IF NOT EXISTS device_codes (
     device_hash TEXT PRIMARY KEY,
     user_code_mac TEXT NOT NULL UNIQUE,
     country TEXT,
     created_at INTEGER NOT NULL,
     expires_at INTEGER NOT NULL,
     polled_at INTEGER,
     interval INTEGER NOT NULL DEFAULT 5,
     state TEXT NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'approved', 'denied', 'issued')),
     user_id TEXT,
     org_id TEXT,
     label TEXT,
     decided_at INTEGER)`,

  /* What happened to an account and when, shown on the dashboard. Never a
     code, a token, an address, an IP address or a user agent. */
  `CREATE TABLE IF NOT EXISTS auth_events (
     id INTEGER PRIMARY KEY AUTOINCREMENT,
     org_id TEXT,
     user_id TEXT,
     event TEXT NOT NULL,
     subject TEXT,
     at INTEGER NOT NULL)`,
  `CREATE INDEX IF NOT EXISTS auth_events_org ON auth_events (org_id, at)`,
  `CREATE INDEX IF NOT EXISTS auth_events_user ON auth_events (user_id, at)`,

  /* Rate limits. key: what is counted and an HMAC of whom (an address or a
     network), never the address or the IP address itself. */
  `CREATE TABLE IF NOT EXISTS throttle (
     key TEXT PRIMARY KEY,
     window_start INTEGER NOT NULL,
     count INTEGER NOT NULL)`,

  /* Emails sent per UTC day, by kind ('auth': every code). */
  `CREATE TABLE IF NOT EXISTS mail_counts (
     day TEXT NOT NULL,
     kind TEXT NOT NULL,
     sent INTEGER NOT NULL,
     PRIMARY KEY (day, kind))`,

  `INSERT OR IGNORE INTO settings (key, value) VALUES ('accounts_schema', '1')`,
];

/* Made on first use, like the list's and the feed's tables, so a deploy
   needs nothing run by hand. */
const made = new WeakSet();
export async function schema(db) {
  if (made.has(db)) return;
  await db.batch(SCHEMA.map((sql) => db.prepare(sql)));
  made.add(db);
}

/* ---------- people and organisations ---------- */

/* The account an address belongs to, made on first use: a user, their
   personal organisation with them as its owner, and the identity they came
   in with, all in one batch. Every sign-in method calls this, and only once
   it has verified the address itself: the emailed code by its being typed,
   Google and GitHub by their verified flag. That is what lets a code, a
   password and a Google sign-in for one address be one account, and
   nothing else may join two.

   A way in that is already known keeps the account it opened, whatever
   address the provider reports now: a Google or GitHub id stays with its
   person, while an address can be given up and handed to someone else.

   Two first sign-ins for one address can race: the unique address lets
   one user in, and the organisation and membership are only written for
   the user that won. */
export async function userForVerifiedEmail(env, { email, provider = "email", subject = email }) {
  const db = env.LIST;
  const t = now();
  const address = String(email).toLowerCase();
  const sub = provider === "email" ? address : String(subject);
  const touch = (user) => [
    db.prepare("UPDATE users SET signed_in_at = ? WHERE id = ?").bind(t, user),
    db.prepare("UPDATE identities SET used_at = ? WHERE provider = ? AND provider_subject = ?")
      .bind(t, provider, sub),
  ];
  const known = await db.prepare(
    "SELECT i.user_id FROM identities i JOIN users u ON u.id = i.user_id WHERE i.provider = ? AND i.provider_subject = ?")
    .bind(provider, sub).first();
  if (known) {
    await db.batch(touch(known.user_id));
    return { id: known.user_id, created: false };
  }

  const id = crypto.randomUUID();
  const org = crypto.randomUUID();
  const ours = "EXISTS (SELECT 1 FROM users WHERE id = ?)";
  await db.batch([
    db.prepare("INSERT INTO users (id, email, created_at) VALUES (?, ?, ?) ON CONFLICT(email) DO NOTHING")
      .bind(id, address, t),
    db.prepare(`INSERT INTO orgs (id, name, personal, created_at) SELECT ?, 'Personal', 1, ? WHERE ${ours}`)
      .bind(org, t, id),
    db.prepare(`INSERT INTO memberships (org_id, user_id, role, created_at) SELECT ?, ?, 'owner', ? WHERE ${ours}`)
      .bind(org, id, t, id),
    db.prepare(`INSERT OR IGNORE INTO identities (provider, provider_subject, user_id, verified_email, created_at)
                SELECT ?, ?, id, ?, ? FROM users WHERE email = ?`)
      .bind(provider, sub, address, t, address),
  ]);
  /* The identity says whose it is, so a race over the same way in ends on
     one account too. */
  const user = await db.prepare(
    "SELECT user_id FROM identities WHERE provider = ? AND provider_subject = ?").bind(provider, sub).first();
  await db.batch(touch(user.user_id));
  return { id: user.user_id, created: user.user_id === id };
}

/* The organisation a signed-in person is looking at, with their role in
   it: the one asked for if they are still a member, otherwise the one they
   own, otherwise any they belong to. null when they belong to none. */
export async function orgFor(env, userId, wanted) {
  const db = env.LIST;
  if (wanted) {
    const row = await db.prepare(
      `SELECT o.id, o.name, o.personal, m.role FROM memberships m JOIN orgs o ON o.id = m.org_id
       WHERE m.org_id = ? AND m.user_id = ?`).bind(wanted, userId).first();
    if (row) return row;
  }
  return db.prepare(
    `SELECT o.id, o.name, o.personal, m.role FROM memberships m JOIN orgs o ON o.id = m.org_id
     WHERE m.user_id = ? ORDER BY m.role = 'owner' DESC, m.created_at, o.id LIMIT 1`).bind(userId).first();
}

/* 1 to 80 characters, none of them a control or formatting character (a
   right-to-left override would make a name read as something else), with
   runs of whitespace made one space. null when the name cannot be used. */
export function orgName(input) {
  const name = String(input ?? "").replace(/\s+/g, " ").trim();
  if (!name || name.length > 80 || /\p{C}/u.test(name)) return null;
  return name;
}

export const canManage = (org) => Boolean(org) && (org.role === "owner" || org.role === "admin");

/* ---------- the audit log ---------- */

/* A statement, so that an event is written in the same batch as what it
   records. */
export const event = (db, { org = null, user = null, what, subject = null }) =>
  db.prepare("INSERT INTO auth_events (org_id, user_id, event, subject, at) VALUES (?, ?, ?, ?, ?)")
    .bind(org, user, what, subject, now());

/* One person's own history, newest first. Other members' sign-ins are
   theirs, so an organisation's shared events wait until it has members. */
export async function history(env, userId, limit = 10) {
  const { results } = await env.LIST.prepare(
    "SELECT event, at FROM auth_events WHERE user_id = ? ORDER BY at DESC, id DESC LIMIT ?")
    .bind(userId, limit).all();
  return results;
}

/* ---------- the daily email budget ---------- */

const today = (t = now()) => new Date(t * 1000).toISOString().slice(0, 10);

/* Whether another account email may go out today. Read before the
   per-address limits, so a day that is used up answers the same for every
   address. */
export async function authMailLeft(env) {
  const row = await env.LIST.prepare("SELECT sent FROM mail_counts WHERE day = ? AND kind = 'auth'")
    .bind(today()).first();
  return Math.max(0, AUTH_MAIL_PER_DAY - (row ? row.sent : 0));
}

/* Takes one email from today's budget, or returns false when none is
   left. One statement, so two requests at once cannot both take the last. */
export async function spendAuthMail(env) {
  const taken = await env.LIST.prepare(
    `INSERT INTO mail_counts (day, kind, sent) VALUES (?, 'auth', 1)
     ON CONFLICT(day, kind) DO UPDATE SET sent = sent + 1 WHERE sent < ?`)
    .bind(today(), AUTH_MAIL_PER_DAY).run();
  return taken.meta.changes === 1;
}

/* ---------- the cron ---------- */

/* Runs on the cron trigger, every quarter hour, once accounts are on.
   What a used or out-of-date code, session, limit or count needed is
   deleted, so an address someone typed and never verified is gone within
   the code's ten minutes and the next run. */
export async function sweep(env) {
  const db = env.LIST;
  await schema(db);
  const t = now();
  await db.batch([
    db.prepare("DELETE FROM signins WHERE expires_at <= ? OR used_at IS NOT NULL").bind(t),
    db.prepare("DELETE FROM sessions WHERE expires_at <= ? OR seen_at <= ?").bind(t, t - SESSION_IDLE),
    db.prepare("DELETE FROM throttle WHERE window_start <= ?").bind(t - DAY),
    db.prepare("DELETE FROM mail_counts WHERE day < ?").bind(today(t - KEEP_COUNTS)),
    db.prepare("DELETE FROM auth_events WHERE at <= ?").bind(t - KEEP_EVENTS),
    db.prepare("DELETE FROM device_codes WHERE expires_at <= ?").bind(t - HOUR),
    db.prepare(`UPDATE invites SET email = NULL WHERE email IS NOT NULL
                AND (accepted_at IS NOT NULL OR revoked_at IS NOT NULL OR expires_at <= ?)`).bind(t),
  ]);
}
