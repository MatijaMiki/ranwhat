/* Accounts on account.ranwhat.com: the tables, the people and
 * organisations in them, the audit log, and the daily budget for the email
 * that signs people in.
 *
 * Served while ACCOUNTS_ON is set, as wrangler.toml sets it. Unset, index.js
 * answers 404 to everything on the account host, before any of this runs,
 * and the cron makes none of these tables in a database that never had
 * them. Once they exist, its sweep keeps deleting what is out of date with
 * accounts on or off: switching them off stops serving them, not deleting
 * what this file promises to delete.
 *
 * Every table the accounts design needs is made here, including the ones
 * later work fills (passwords, passkeys, Google and GitHub identities,
 * machines, subscriptions linked to an organisation, grants, invites,
 * device codes). Later changes add routes and new tables, and never
 * change the columns of a table an earlier deploy may have made:
 * CREATE TABLE IF NOT EXISTS does nothing to a table that is there, and
 * the first deploy's tables are in every D1 where ACCOUNTS_ON was ever
 * set. A change to one would need an ALTER, run on purpose.
 *
 * Sign-in methods meet in one place, userForVerifiedEmail(). The emailed
 * code is the first; a password, and Google where it is the authority for
 * the address (oauth.js), come through the same door. Two methods land on
 * the same account only through an address the method itself proved is
 * held now, never through one someone typed. GitHub, and Google for an
 * address it does not give out, only open an account that linked them
 * from its own page. A passkey never makes or joins an account either: it
 * is added to the one its owner is signed in to (passkeys.js), and opens
 * only that one.
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

/* What one account may do in a day that adds a row to the audit log and
   needs no fresh code: renames (of an organisation and of its machines,
   together) and switches between its organisations. Past them it is
   refused with nothing written, and a rename or switch that changes
   nothing writes nothing either. So one account adds at most 90 such rows
   a day to what the cron keeps for 13 months (about 36,000), and a
   refused request costs the database a read, never a write. */
export const RENAMES_PER_DAY = 30;
export const SWITCHES_PER_DAY = 60;

/* Sign-in codes, fresh-code checks, address checks, password resets and
   the notices that a way in was added share Resend's free plan, 100
   emails a day, with invites (INVITE_MAIL_PER_DAY, below), the email that
   says Plus is on and the release list's confirmations (list.js sends at
   most LIST_MAIL_PER_DAY, 10, of those a day while accounts are on). This
   keeps the account's own mail to 60, so that with the 25 invites and the
   10 confirmations a burst of sign-ups can never hold back someone's
   token. */
export const AUTH_MAIL_PER_DAY = 60;

/* Fifteen of those are kept for accounts already signed in: a step-up's
   code (purpose 'stepup') and the notice that a way in was added. Codes
   asked for from the sign-in, sign-up and reset forms, by anyone, stop
   short of them, so strangers who use up the day's sign-in mail cannot
   stop a signed-in person from approving a terminal or opening billing.
   Only an account made at least a day ago draws on the reserve, and at
   most RESERVE_PER_USER_DAY a day for one account and
   RESERVE_PER_NETWORK_DAY for one network (an IPv4 /24, an IPv6 /48), so
   neither accounts made today, nor a handful of older ones, nor many from
   one network can empty it: emptying it takes eight accounts a day old or
   more, on five networks. What an account causes past its share comes out
   of the public forms' mail instead, under that mail's own limits, as a
   code asked for there would (session.js's signedInMail()). */
export const STEPUP_RESERVE = 15;
export const RESERVE_PER_USER_DAY = 2;
export const RESERVE_PER_NETWORK_DAY = 3;

/* And the step-up codes one account may ask for in a day, from the
   reserve and the public mail together, from as many networks as it
   likes. */
export const STEPUPS_PER_USER_DAY = 5;

/* The email that tells an account a way in was added to it (a Google or
   GitHub account linked, a passkey added: session.js's holdNotice() and
   tellWayIn()) is taken from the day's mail, as a step-up's code is,
   before the way in is added, and without it the way in is not added.
   So nothing another account does can silence it: other accounts can at
   most use up the day's mail, which stops the adding with it. Each
   account's first NOTICES_PER_USER_DAY a day are mailed; a way in added
   past them that day is not, as its address has had that many already
   that day, and the account's activity lists every one. */
export const NOTICES_PER_USER_DAY = 3;

/* Invites to an organisation (members.js) have a day of their own, apart
   from AUTH_MAIL_PER_DAY: however many organisations invite, nobody's
   sign-in code or step-up waits on it, and a burst of sign-ins never stops
   an invite. With the account mail that keeps Resend's 100 a day at 85,
   leaving 15: the list's 10 confirmations and the emails that say Plus is
   on. Each organisation also has its own share (INVITES_PER_ORG_DAY),
   smaller than this, so one organisation's busy day leaves room for
   another's. */
export const INVITE_MAIL_PER_DAY = 25;

export const now = () => Math.floor(Date.now() / 1000);

/* "1" or "true" switch accounts on; unset, empty or anything else keeps
   them off. */
export const accountsOn = (env) => ["1", "true"].includes(String(env.ACCOUNTS_ON ?? "").trim().toLowerCase());

/* Switched on and able to work: the database, a way to send the code, a
   secret of its own to keep codes and form tokens under (never LIST_SECRET,
   which every feed token is derived from), and Turnstile's secret, which
   every form that mails a code is checked with (challenge.js). */
export const ready = (env) => Boolean(env.LIST && env.RESEND_API_KEY &&
  typeof env.ACCOUNT_SECRET === "string" && env.ACCOUNT_SECRET.length >= 32 &&
  typeof env.TURNSTILE_SECRET === "string" && env.TURNSTILE_SECRET.length > 0);

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

  /* A Google or GitHub account (provider and provider_subject as in
     identities) that was unlinked from user_id's account. It never links
     itself to that account again through the account's address
     (oauth.js); only linking it from the account page, with a fresh code,
     takes this row away. Kept while the account is: it holds the
     provider's id and no address. */
  `CREATE TABLE IF NOT EXISTS unlinked_identities (
     provider TEXT NOT NULL,
     provider_subject TEXT NOT NULL,
     user_id TEXT NOT NULL,
     unlinked_at INTEGER NOT NULL,
     PRIMARY KEY (provider, provider_subject, user_id))`,

  /* A password, as its PBKDF2 hash with the salt and iteration count in
     the same string, never the password. One per person. */
  `CREATE TABLE IF NOT EXISTS credentials (
     user_id TEXT NOT NULL,
     kind TEXT NOT NULL CHECK (kind IN ('password')),
     hash TEXT NOT NULL,
     created_at INTEGER NOT NULL,
     updated_at INTEGER NOT NULL,
     PRIMARY KEY (user_id, kind))`,

  /* Passkeys (passkeys.js): a WebAuthn credential's id and public key,
     never anything that could sign in by itself. id and public_key are
     base64url, the key as the COSE bytes the authenticator sent, which
     say their own algorithm. transports: left NULL, as nothing here needs
     it. label: what its owner called it on the web, never empty
     (passkeyLabel()). used_at: the start (00:00 UTC) of the day it last
     signed in, and no finer. The first deploy made this table with these
     columns, so they stay as they are (see the top of this file). */
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

  /* The WebAuthn user handle of an account that has added a passkey: 32
     random bytes, base64url, made the first time and never changed, so
     every passkey of the account carries the same one. Not the user's id
     or address: an authenticator keeps nothing that names the account
     anywhere else. */
  `CREATE TABLE IF NOT EXISTS passkey_users (
     user_id TEXT PRIMARY KEY,
     handle TEXT NOT NULL UNIQUE,
     created_at INTEGER NOT NULL)`,

  /* A challenge waiting for a passkey's answer. id: the SHA-256 of the
     challenge, which is kept nowhere. purpose 'register': binding is the
     session (sessions.id) of user_id, adding a passkey. 'signin': binding
     is the SHA-256 of the browser's __Host-rw_signin cookie. Used once,
     within five minutes; the sweep deletes it once it is used or out of
     date. */
  `CREATE TABLE IF NOT EXISTS passkey_challenges (
     id TEXT PRIMARY KEY,
     purpose TEXT NOT NULL CHECK (purpose IN ('register', 'signin')),
     binding TEXT NOT NULL,
     user_id TEXT,
     created_at INTEGER NOT NULL,
     expires_at INTEGER NOT NULL,
     used_at INTEGER)`,

  /* What a plan belongs to. customer: the organisation's own Stripe cus_
     id, made with its owner's address before its first checkout from the
     account (billing.js); never a buyer's, whatever they paid. */
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
     once and never moved. how is 'checkout' for one bought from the
     account (stripe.js's webhook) or 'script' for one linked by
     scripts/org_admin.py. 'session' and 'email' were the removed
     self-service claim's, and linked_by held who claimed: nothing writes
     those values, or anything but NULL to that column, and they stay only
     because the table is as deployed. */
  `CREATE TABLE IF NOT EXISTS org_subscriptions (
     subscription TEXT PRIMARY KEY,
     org_id TEXT NOT NULL,
     how TEXT NOT NULL CHECK (how IN ('checkout', 'session', 'email', 'script')),
     linked_by TEXT,
     linked_at INTEGER NOT NULL)`,
  `CREATE INDEX IF NOT EXISTS org_subscriptions_org ON org_subscriptions (org_id)`,

  /* What the billing panel shows of a Stripe subscription, as stripe.js's
     keep() last fetched it (every webhook event about it, and the billing
     panel's one read of a subscription linked by scripts/org_admin.py):
     monthly or yearly, and when it renews or ends. Drawing the account
     page reads this and asks Stripe nothing. */
  `CREATE TABLE IF NOT EXISTS subscription_terms (
     subscription TEXT PRIMARY KEY,
     interval TEXT,
     renews_at INTEGER,
     ends_at INTEGER,
     fetched_at INTEGER NOT NULL)`,

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
     revocation stays. id: what forms name it by, never the hash. user_id:
     who approved a terminal (kind 'device', device.js) or made a CI token
     (kind 'ci', machines.js); NULL for a subscription's emailed token
     ('legacy'). label: what it is called on the web, never by the machine
     itself: a terminal's is typed on the page that approves it (device.js,
     kept in device_codes.label until the token is minted), a CI token's
     when it is made; '' is read by auth.js as no label. last_used_day: the
     start of the UTC day a device or ci
     token was last used (auth.js). */
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
     passwords) proving an address and resetting a password.
     password_hash: with 'verify', the PBKDF2 hash of the password the
     browser holding this attempt chose (password.js). This row is the only
     place it is kept until that browser types the code; then it moves to
     credentials, and it is cleared as soon as the attempt is used or
     cancelled. mailed: 1 once its code is on its way. An attempt made while
     the address was over its limits keeps 0: its code was never sent, and
     no code typed into it is ever right (session.js). The sweep deletes a
     row once its code is out of date. */
  `CREATE TABLE IF NOT EXISTS signins (
     id TEXT PRIMARY KEY,
     email TEXT NOT NULL,
     email_mac TEXT NOT NULL,
     purpose TEXT NOT NULL CHECK (purpose IN ('signin', 'stepup', 'verify', 'reset')),
     user_id TEXT,
     code_mac TEXT NOT NULL,
     password_hash TEXT,
     next TEXT NOT NULL DEFAULT '/',
     created_at INTEGER NOT NULL,
     expires_at INTEGER NOT NULL,
     tries INTEGER NOT NULL DEFAULT 0,
     mailed INTEGER NOT NULL DEFAULT 0,
     used_at INTEGER)`,
  `CREATE INDEX IF NOT EXISTS signins_email ON signins (email_mac, created_at)`,

  /* Linking a terminal (RFC 8628). country, from Cloudflare, is the only
     thing kept about where the request came from, and goes with the row.
     label: the name typed with the approval, on the web, copied onto the
     machine when its token is minted. */
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

  /* Emails sent per UTC day, by kind ('auth': codes from the public forms,
     and what an account signed in causes past its share of the reserve;
     'auth-stepup': the signed-in reserve, for the step-ups and notices of
     accounts a day old or more; 'invite': invites to an organisation). */
  `CREATE TABLE IF NOT EXISTS mail_counts (
     day TEXT NOT NULL,
     kind TEXT NOT NULL,
     sent INTEGER NOT NULL,
     PRIMARY KEY (day, kind))`,

  /* Signing in with Google or GitHub, between leaving for the provider and
     coming back (oauth.js). id: the SHA-256 of the browser's
     __Host-rw_oauth cookie. state_hash, nonce_hash, verifier_hash: the
     SHA-256 of the random state, of the random nonce (Google) and of the
     PKCE verifier, which is an HMAC of the cookie and kept nowhere.
     purpose 'link': the session (sessions.id) of user_id, adding the
     provider to their account. Used once, within ten minutes; the sweep
     deletes it once it is used or out of date. */
  `CREATE TABLE IF NOT EXISTS oauth_flows (
     id TEXT PRIMARY KEY,
     provider TEXT NOT NULL,
     purpose TEXT NOT NULL CHECK (purpose IN ('signin', 'link')),
     state_hash TEXT NOT NULL,
     nonce_hash TEXT,
     verifier_hash TEXT NOT NULL,
     user_id TEXT,
     session_id TEXT,
     next TEXT NOT NULL DEFAULT '/',
     created_at INTEGER NOT NULL,
     expires_at INTEGER NOT NULL,
     used_at INTEGER)`,

  /* An organisation whose Stripe customer email (billing.js) is still to
     be checked after someone stopped being an owner or an admin of it:
     written in the batch that changes their role, deleted once Stripe has
     the right address, and tried again by the cron while Stripe fails.
     lost_user: who stopped (or handed on ownership), as their id, never an
     address. ticket: random, so that a check only deletes the row it
     read, never one a later change wrote. */
  `CREATE TABLE IF NOT EXISTS billing_email_due (
     org_id TEXT PRIMARY KEY,
     lost_user TEXT,
     ticket TEXT NOT NULL,
     since INTEGER NOT NULL)`,

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

/* Whether this database has the tables above, made in one batch the
   first time accounts were on, without making them. */
async function tablesMade(db) {
  if (made.has(db)) return true;
  return Boolean(await db.prepare("SELECT 1 AS yes FROM sqlite_master WHERE type = 'table' AND name = 'signins'").first());
}

/* ---------- people and organisations ---------- */

/* The account an address belongs to, made on first use: a user, their
   personal organisation with them as its owner, and the identity they came
   in with, all in one batch. Every sign-in method calls this, and only once
   it has shown the address is held now: the emailed code by its being
   typed, Google only where it is the authority for the address (a Gmail
   address, or one on the Google Workspace domain the token names), never
   GitHub (oauth.js says why). That is what lets a code, a password and a
   Google sign-in for one address be one account, and nothing else may
   join two.

   A way in that is already known keeps the account it opened, whatever
   address the provider reports now: a Google or GitHub id stays with its
   person, while an address can be given up and handed to someone else.

   A provider's account that was unlinked from the account with this
   address (unlinked_identities) is not linked again here: { refused:
   "unlinked" }. oauth.js checks that first; this holds it inside the
   batch, against an unlink that lands in between.

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
                SELECT ?, ?, id, ?, ? FROM users WHERE email = ? AND NOT EXISTS (
                  SELECT 1 FROM unlinked_identities x
                  WHERE x.provider = ? AND x.provider_subject = ? AND x.user_id = users.id)`)
      .bind(provider, sub, address, t, address, provider, sub),
  ]);
  /* The identity says whose it is, so a race over the same way in ends on
     one account too. */
  const user = await db.prepare(
    "SELECT user_id FROM identities WHERE provider = ? AND provider_subject = ?").bind(provider, sub).first();
  if (!user) return { refused: "unlinked" };
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

/* The address of the organisation's owner, or null. Names are not unique
   (every personal organisation is "Personal"), so a page that asks for a
   decision about one names its owner too. */
export async function ownerOf(env, orgId) {
  const row = await env.LIST.prepare(
    `SELECT u.email FROM memberships m JOIN users u ON u.id = m.user_id WHERE m.org_id = ? AND m.role = 'owner'`)
    .bind(orgId).first();
  return row ? row.email : null;
}

/* When `userId` joined the organisation, or 0 when they are not in it. */
export async function joinedAt(env, orgId, userId) {
  const row = await env.LIST.prepare("SELECT created_at FROM memberships WHERE org_id = ? AND user_id = ?")
    .bind(orgId, userId).first();
  return row ? row.created_at : 0;
}

/* SQL for the address `email` of the user whose id is `id` (both SQL
   expressions), as someone who joined the organisation at a given time
   may see it: while that user is in the organisation, or when they left
   it after the viewer joined, so that the two shared it; otherwise NULL,
   which the pages show as a former member. Someone who joins later never
   learns the address of someone who had already gone. Three values to
   bind where it stands: the organisation, the organisation again, and
   the time the viewer joined (joinedAt()). */
export const seenAddress = (id, email) => `CASE
  WHEN EXISTS (SELECT 1 FROM memberships sx WHERE sx.org_id = ? AND sx.user_id = ${id}) THEN ${email}
  WHEN (SELECT max(sg.at) FROM auth_events sg WHERE sg.org_id = ? AND sg.user_id = ${id}
        AND sg.event IN ('org_left', 'removed_from_org')) >= ? THEN ${email}
  END`;

/* ---------- ways in ---------- */

/* The statements that take away every Google and GitHub account linked to
   `user`'s account and every passkey of it, with the event, for the
   caller's batch: for someone who signs out everywhere, or resets their
   password, because one of them may be in someone else's hands. Each
   provider's account is kept in unlinked_identities, so that none links
   itself back. The emailed code stays, and the password is the caller's
   to keep or replace. */
export function forgetWaysIn(env, { user, org = null }) {
  const db = env.LIST;
  return [
    db.prepare(`INSERT INTO unlinked_identities (provider, provider_subject, user_id, unlinked_at)
                SELECT provider, provider_subject, user_id, ? FROM identities WHERE user_id = ? AND provider != 'email'
                ON CONFLICT (provider, provider_subject, user_id) DO UPDATE SET unlinked_at = excluded.unlinked_at`)
      .bind(now(), user),
    db.prepare("DELETE FROM identities WHERE user_id = ? AND provider != 'email'").bind(user),
    db.prepare("DELETE FROM passkeys WHERE user_id = ?").bind(user),
    event(db, { org, user, what: "ways_removed" }),
  ];
}

/* ---------- the audit log ---------- */

/* A statement, so that an event is written in the same batch as what it
   records. */
export const event = (db, { org = null, user = null, what, subject = null }) =>
  db.prepare("INSERT INTO auth_events (org_id, user_id, event, subject, at) VALUES (?, ?, ?, ?, ?)")
    .bind(org, user, what, subject, now());

/* One person's own history, newest first. Other members' sign-ins are
   theirs: what an organisation shares is who came, went and changed role,
   which members.js lists for its owner and admins. */
export async function history(env, userId, limit = 10) {
  const { results } = await env.LIST.prepare(
    "SELECT event, at FROM auth_events WHERE user_id = ? ORDER BY at DESC, id DESC LIMIT ?")
    .bind(userId, limit).all();
  return results;
}

/* ---------- the daily email budget ---------- */

const today = (t = now()) => new Date(t * 1000).toISOString().slice(0, 10);

/* The day's account mail is three counters. The signed-in reserve
   ('auth-stepup', STEPUP_RESERVE), which session.js draws on for an
   older account's step-ups and notices within their shares; invites
   ('invite', INVITE_MAIL_PER_DAY); and the rest of AUTH_MAIL_PER_DAY
   ('auth'), for the public sign-in, sign-up and reset forms and for what
   an account signed in causes past its share of the reserve. None can
   spend another's, so a stranger draining the forms cannot stop an older
   account's step-up or an invite, and a session spraying invites cannot
   stop anyone signing in. */
const mailKind = (purpose) => (purpose === "invite" ? "invite" : purpose === "stepup" ? "auth-stepup" : "auth");
const mailCap = (purpose) => (purpose === "invite" ? INVITE_MAIL_PER_DAY
  : purpose === "stepup" ? STEPUP_RESERVE : AUTH_MAIL_PER_DAY - STEPUP_RESERVE);

/* How many more account emails for `purpose` may go out today. Read before
   the per-address limits, so a day that is used up answers the same for
   every address. */
export async function authMailLeft(env, purpose = "signin") {
  const row = await env.LIST.prepare("SELECT sent FROM mail_counts WHERE day = ? AND kind = ?")
    .bind(today(), mailKind(purpose)).first();
  return Math.max(0, mailCap(purpose) - (row ? row.sent : 0));
}

/* Takes one email for `purpose` from today's budget: the day it was taken
   from, for giveBackAuthMail(), or false when none is left for it. One
   statement, so two requests at once cannot both take the last. */
export async function spendAuthMail(env, purpose = "signin") {
  const day = today();
  const taken = await env.LIST.prepare(
    `INSERT INTO mail_counts (day, kind, sent) VALUES (?, ?, 1)
     ON CONFLICT(day, kind) DO UPDATE SET sent = sent + 1 WHERE sent < ?`)
    .bind(day, mailKind(purpose), mailCap(purpose)).run();
  return taken.meta.changes === 1 ? day : false;
}

/* One email for `purpose` back to the day it was taken from, for one
   taken for something that then did not happen. Never below nothing. */
export async function giveBackAuthMail(env, purpose, day) {
  await env.LIST.prepare("UPDATE mail_counts SET sent = sent - 1 WHERE day = ? AND kind = ? AND sent > 0")
    .bind(day, mailKind(purpose)).run();
}

/* ---------- the cron ---------- */

/* Runs on the cron trigger, every quarter hour. What a used or
   out-of-date code, session, limit or count needed is deleted, so an
   address someone typed and never verified is gone within the code's ten
   minutes and the next run, and so is the password hash held with it.
   That holds while accounts are switched off again after being on, too:
   off stops serving, not deleting. A database accounts were never on in
   gets no tables from it. */
export async function sweep(env) {
  const db = env.LIST;
  /* A database whose tables an earlier deploy made gets the ones added
     since, so that every statement below has its table. */
  if (accountsOn(env) || await tablesMade(db)) await schema(db);
  else return;
  const t = now();
  await db.batch([
    db.prepare("DELETE FROM signins WHERE expires_at <= ? OR used_at IS NOT NULL").bind(t),
    db.prepare("DELETE FROM oauth_flows WHERE expires_at <= ? OR used_at IS NOT NULL").bind(t),
    db.prepare("DELETE FROM passkey_challenges WHERE expires_at <= ? OR used_at IS NOT NULL").bind(t),
    db.prepare("DELETE FROM sessions WHERE expires_at <= ? OR seen_at <= ?").bind(t, t - SESSION_IDLE),
    db.prepare("DELETE FROM throttle WHERE window_start <= ?").bind(t - DAY),
    db.prepare("DELETE FROM mail_counts WHERE day < ?").bind(today(t - KEEP_COUNTS)),
    db.prepare("DELETE FROM auth_events WHERE at <= ?").bind(t - KEEP_EVENTS),
    db.prepare("DELETE FROM device_codes WHERE expires_at <= ?").bind(t - HOUR),
    db.prepare(`UPDATE invites SET email = NULL WHERE email IS NOT NULL
                AND (accepted_at IS NOT NULL OR revoked_at IS NOT NULL OR expires_at <= ?)`).bind(t),
  ]);
}
