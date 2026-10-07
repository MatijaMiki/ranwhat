/* An organisation's machines: every feed token it holds, as the account
 * page lists them (dashboard.js draws the list and routes its forms here).
 *
 * A machine is a machines row (accounts.js) beside its tokens row
 * (auth.js), of one of three kinds:
 *
 *   device  A terminal linked with ranwhat login (device.js). user_id: who
 *           approved it.
 *   ci      A CI token, made on the account page by an owner or an admin of
 *           a Plus or Team organisation, with an emailed code typed in the
 *           last 15 minutes. user_id: who made it. rw_c_ and 32 random
 *           bytes, shown once, on the page that answers the form that made
 *           it, and kept as its SHA-256 only, like every feed token.
 *   legacy  A subscription's emailed token, once the subscription is
 *           attached to the organisation. user_id NULL.
 *
 * Each is named on the web and never by itself (1 to 60 printable
 * characters: a terminal's on the page that approves it, device.js, a CI
 * token's when it is made), and can be renamed and revoked here, by an
 * owner or an admin, or by whoever linked or made it. Revoking needs a
 * fresh code, as making a CI token does, and sets tokens.revoked_at, the
 * one switch every feed token has: from the next request on, the feed
 * refuses it. The machines row stays, so the organisation's history
 * keeps naming it.
 *
 * Last use. auth.js's identify() writes the start of the UTC day a
 * terminal or CI token was last accepted, at most once a day, in one
 * UPDATE that is not even sent once the day is written. A subscription's
 * shared token and one made by hand are never noted.
 *
 * Idle terminals. The cron revokes a terminal's token once it has gone 90
 * whole days unused (or, never used, 90 days after it was linked):
 * revokeIdle(). A laptop that has left keeps no way into the feed, and
 * ranwhat login gets a new token in a minute. CI tokens are never revoked
 * for being idle, since a job may run once a quarter; they stop at the
 * expiry chosen when they were made, if one was. Shared subscription
 * tokens are the subscription's to end.
 */
import { schema as feedSchema, sha256 } from "./auth.js";
import { DAY, accountsOn, canManage, now, schema as accountsSchema } from "./accounts.js";
import { randomToken } from "./session.js";

export const CI_PREFIX = "rw_c_";
export const MAX_LABEL = 60;
export const IDLE_DAYS = 90;
export const MAX_CI = 50;           // CI tokens an organisation holds at once, neither revoked nor expired
export const MAX_LISTED = 200;      // machines the account page lists

/* What a CI token's expiry may be: the select's values, as days. */
export const EXPIRIES = Object.freeze({ never: null, 30: 30, 90: 90, 365: 365 });

const MACHINE_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/* The start (00:00 UTC) of the day a time falls in. */
export const dayOf = (t) => Math.floor(t / DAY) * DAY;

/* 1 to MAX_LABEL characters, none of them a control or formatting
   character (a right-to-left override would make a name read as something
   else), with runs of whitespace made one space. null when it cannot be
   used: a name is chosen on purpose, so a bad one is refused, not
   repaired. */
export function machineLabel(input) {
  const label = String(input ?? "").slice(0, 1000).replace(/\s+/g, " ").trim();
  if (!label || [...label].length > MAX_LABEL || /\p{C}/u.test(label)) return null;
  return label;
}

/* Whether `who` (session.js's current()) may rename or revoke `machine`:
   an owner or an admin of its organisation, or whoever linked or made it. */
export const mayChange = (who, machine) =>
  canManage(who.org) || (machine.user_id !== null && machine.user_id === who.user);

const COLUMNS = `m.id, m.kind, m.label, m.user_id, m.created_at, m.last_used_day, k.expires_at, u.email`;
const FROM = `machines m JOIN tokens k ON k.hash = m.hash LEFT JOIN users u ON u.id = m.user_id`;

async function tables(db) {
  await feedSchema(db);
  await accountsSchema(db);
}

/* The organisation's machines whose tokens are not revoked, newest first.
   An expired CI token stays listed, saying so, until it is revoked. */
export async function machinesOf(env, orgId) {
  const db = env.LIST;
  await tables(db);
  const { results } = await db.prepare(
    `SELECT ${COLUMNS} FROM ${FROM} WHERE m.org_id = ? AND k.revoked_at IS NULL
     ORDER BY m.created_at DESC, m.id LIMIT ?`).bind(orgId, MAX_LISTED).all();
  return results;
}

/* The machine a form names, only if it is this organisation's and not
   revoked: null otherwise, the same for an id from another organisation
   as for one that never was. */
export async function machineIn(env, orgId, id) {
  if (typeof id !== "string" || !MACHINE_ID.test(id)) return null;
  const db = env.LIST;
  await tables(db);
  return db.prepare(
    `SELECT ${COLUMNS} FROM ${FROM} WHERE m.id = ? AND m.org_id = ? AND k.revoked_at IS NULL`)
    .bind(id, orgId).first();
}

/* Renames it, with the event, in one batch. */
export async function renameMachine(env, who, machine, label) {
  const db = env.LIST;
  await db.batch([
    db.prepare("UPDATE machines SET label = ? WHERE id = ? AND org_id = ?").bind(label, machine.id, who.org.id),
    db.prepare("INSERT INTO auth_events (org_id, user_id, event, subject, at) VALUES (?, ?, 'machine_renamed', ?, ?)")
      .bind(who.org.id, who.user, machine.id, now()),
  ]);
}

/* Revokes its token. The event is written only by the request that
   revoked it. true when this request did. */
export async function revokeMachine(env, who, machine) {
  const db = env.LIST;
  const t = now();
  const live = `SELECT k.hash FROM machines m JOIN tokens k ON k.hash = m.hash
                WHERE m.id = ? AND m.org_id = ? AND k.revoked_at IS NULL`;
  const done = await db.batch([
    db.prepare(`INSERT INTO auth_events (org_id, user_id, event, subject, at)
                SELECT ?, ?, 'machine_revoked', ?, ? WHERE EXISTS (${live})`)
      .bind(who.org.id, who.user, machine.id, t, machine.id, who.org.id),
    db.prepare(`UPDATE tokens SET revoked_at = ? WHERE revoked_at IS NULL AND hash IN (${live})`)
      .bind(t, machine.id, who.org.id),
  ]);
  return done[1].meta.changes === 1;
}

/* The CI tokens an organisation holds now, neither revoked nor expired. */
const LIVE_CI = `SELECT count(*) AS n FROM machines c JOIN tokens ck ON ck.hash = c.hash
  WHERE c.org_id = ? AND c.kind = 'ci' AND ck.revoked_at IS NULL AND (ck.expires_at IS NULL OR ck.expires_at > ?)`;

export async function liveCi(env, orgId) {
  const db = env.LIST;
  await tables(db);
  return (await db.prepare(LIVE_CI).bind(orgId, now()).first()).n;
}

/* A new CI token for `who`'s organisation: { token, id, expires_at }, or
   { refused: "full" } when it already holds MAX_CI. The caller has checked
   the role, the plan and the fresh code. The machines row is written only
   while there is room, and the token and the event only with it, in one
   batch, so two forms sent at once cannot pass the cap together. The
   token itself is returned once and kept nowhere. */
export async function mintCi(env, who, { label, days = null }) {
  const db = env.LIST;
  await tables(db);
  const t = now();
  const token = CI_PREFIX + randomToken();
  const hash = await sha256(token);
  const id = crypto.randomUUID();
  const expires = days ? t + days * DAY : null;
  const made = "EXISTS (SELECT 1 FROM machines WHERE id = ?)";
  const done = await db.batch([
    db.prepare(`INSERT INTO machines (id, hash, org_id, user_id, kind, label, created_at)
                SELECT ?, ?, ?, ?, 'ci', ?, ? WHERE (${LIVE_CI}) < ?`)
      .bind(id, hash, who.org.id, who.user, label, t, who.org.id, t, MAX_CI),
    db.prepare(`INSERT INTO tokens (hash, note, created_at, expires_at) SELECT ?, ?, ?, ? WHERE ${made}`)
      .bind(hash, `ci ${id}`, t, expires, id),
    db.prepare(`INSERT INTO auth_events (org_id, user_id, event, subject, at)
                SELECT ?, ?, 'ci_token_created', ?, ? WHERE ${made}`)
      .bind(who.org.id, who.user, id, t, id),
  ]);
  if (done[0].meta.changes !== 1) return { refused: "full" };
  return { token, id, expires_at: expires };
}

/* ---------- the cron ---------- */

/* Revokes every terminal's token unused for IDLE_DAYS whole days, with an
   event for whoever linked it, and returns how many. Only where the
   accounts tables are: a database accounts were never on in gets nothing
   made or read beyond sqlite_master. */
export async function revokeIdle(env) {
  const db = env.LIST;
  if (!db) return 0;
  if (!accountsOn(env)) {
    const there = await db.prepare("SELECT 1 AS yes FROM sqlite_master WHERE type = 'table' AND name = 'machines'").first();
    if (!there) return 0;
  }
  await tables(db);
  const t = now();
  /* Last used (or linked) before this, it has gone IDLE_DAYS whole days
     unused: last_used_day is a day's start, so compare days with days. */
  const before = dayOf(t) - IDLE_DAYS * DAY;
  const idle = `SELECT m.hash FROM machines m JOIN tokens k ON k.hash = m.hash
                WHERE m.kind = 'device' AND k.revoked_at IS NULL AND COALESCE(m.last_used_day, m.created_at) < ?`;
  const done = await db.batch([
    db.prepare(`INSERT INTO auth_events (org_id, user_id, event, subject, at)
                SELECT m.org_id, m.user_id, 'machine_idle_revoked', m.id, ? FROM machines m
                WHERE m.hash IN (${idle})`).bind(t, before),
    db.prepare(`UPDATE tokens SET revoked_at = ? WHERE revoked_at IS NULL AND hash IN (${idle})`).bind(t, before),
  ]);
  return done[1].meta.changes;
}
