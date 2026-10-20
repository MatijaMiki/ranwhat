/* POST https://feed.ranwhat.com/v1/push: a machine sends its findings to
 * its organisation's account, as derived metadata only, for `ranwhat
 * push`. The page that shows them is account.ranwhat.com/findings
 * (dashboard.js); this file is the way in, and the reads that page makes.
 *
 * Who. A device or CI token (a terminal linked with ranwhat login, or a
 * CI token), of an organisation on Plus or Team (features.js's "push").
 * The machine is the token's, and the body has no machine, organisation,
 * host or user field, so a body cannot say it is another machine's. A
 * subscription's or a hand-made token is 403 machine_required, and an
 * organisation on Free 403 plus_required with where to upgrade, as the
 * feed answers it. Nothing found here is ever sent back out over the
 * feed host: the findings are read on the account host, by members.
 *
 * What. push_schema.js is the whole of it: an allow-list that refuses any
 * key it does not list, with rule and agent ids enumerated, so no command,
 * path, evidence, session id, secret, hostname or user name can be stored
 * even if a client sends one. A refusal never repeats a value from the
 * request, and nothing from the body, the token, the organisation or the
 * machine is ever logged.
 *
 * Kept (RETENTION). Each machine's latest push in full, and a summary of
 * the counts of each earlier push for 30 days, 30 pushes at most; the cron
 * (accounts.js's sweep) deletes anything pushed more than HARD_DAYS ago,
 * the latest included. This is not a long-term record: the 13-month
 * history is a separate, unbuilt feature. Revoking a machine hides what it
 * sent at once (every read joins its live token) and deletes it in the
 * same batch (machines.js, device.js), or at the next sweep.
 *
 * Cost. D1's free plan allows 100,000 rows written a day to the whole
 * account, which sign-in and billing share. A push whose findings changed
 * writes about 8 rows (the insert and its two index entries, one update,
 * one delete and its index entries), a repeated one 1. The caps below are
 * counted after the token is known and before the body is read, so a
 * malformed body costs quota like a good one; the account-wide cap of
 * 5000 bounds push at about 40,000 rows written a day, under half the
 * free plan's, and no organisation can have more than a fifth of that.
 * Revisit the numbers if D1 moves to a paid plan.
 */
import { identify, UPGRADE } from "./auth.js";
import { ready, now, DAY, HOUR } from "./accounts.js";
import { allows } from "./features.js";
import { FEED_HOST, fromBrowser } from "./device.js";
import { countWithin, mac, network, unbump } from "./session.js";
import { LIMITS, digestOf, validate } from "./push_schema.js";

export const PUSH_PATH = "/v1/push";

/* What is kept, by plan: the latest push in full, and `snapshots` pushes
   in all (the latest among them) for `days` days. One place to change it. */
export const RETENTION = Object.freeze({
  plus: Object.freeze({ days: 30, snapshots: 30 }),
  team: Object.freeze({ days: 30, snapshots: 30 }),
});
export const HARD_DAYS = 90;

export const PUSH_LIMITS = Object.freeze({
  PER_MACHINE_HOUR: 20,
  PER_MACHINE_DAY: 120,
  PER_ORG_DAY: 1000,
  ALL_DAY: 5000,
  MACHINES_PER_ORG: 200,
  BURST_PER_NETWORK: 30,      // a minute, PUSH_RL in wrangler.toml
});

const reply = (status, body, headers = {}) => new Response(JSON.stringify(body), {
  status,
  headers: {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
    pragma: "no-cache",
    "x-content-type-options": "nosniff",
    ...headers,
  },
});

const fail = (status, error, message, extra = {}, headers = {}) => reply(status, { error, message, ...extra }, headers);

const limited = (retry) => fail(429, "rate_limited", "Too many pushes lately. Try again later.", {},
  { "retry-after": String(retry) });

/* PUSH_RL (wrangler.toml), Workers' rate limiting binding: a burst from
   one network is turned away before the database is touched. Keyed by an
   HMAC of the network. Where the binding is missing (a preview, the tests)
   or fails, the counts in D1 still hold. */
async function burstOk(env, net) {
  const limiter = env.PUSH_RL;
  if (!limiter || typeof limiter.limit !== "function") return true;
  try {
    const { success } = await limiter.limit({ key: await mac(env, `push-rl:${net}`) });
    return success !== false;
  } catch {
    return true;
  }
}

/* The caps, counted in one statement each; one that fails gives back the
   ones counted before it. A Response when over a cap, else null. */
async function countPush(env, who) {
  const counts = [
    ["push-m-hour", who.machine.id, HOUR, PUSH_LIMITS.PER_MACHINE_HOUR],
    ["push-m-day", who.machine.id, DAY, PUSH_LIMITS.PER_MACHINE_DAY],
    ["push-org-day", who.org, DAY, PUSH_LIMITS.PER_ORG_DAY],
    ["push-all-day", "all", DAY, PUSH_LIMITS.ALL_DAY],
  ];
  const done = [];
  for (const [kind, key, window, limit] of counts) {
    if (!await countWithin(env, kind, key, window, limit)) {
      for (const [k, w, win] of done) await unbump(env, k, w, win);
      return limited(window);
    }
    done.push([kind, key, window]);
  }
  return null;
}

/* The body, at most MAX_BODY bytes, read through a counter rather than
   trusting a length. null when it is over. */
async function readBody(request) {
  if (!request.body) return new Uint8Array(0);
  const reader = request.body.getReader();
  const chunks = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > LIMITS.MAX_BODY) {
      try { await reader.cancel(); } catch { /* the stream is being dropped either way */ }
      return null;
    }
    chunks.push(value);
  }
  const out = new Uint8Array(size);
  let at = 0;
  for (const c of chunks) { out.set(c, at); at += c.byteLength; }
  return out;
}

const JSON_TYPE = /^application\/json\s*(;.*)?$/i;

export async function push(request, env) {
  if (!ready(env)) return fail(503, "unavailable", "Pushing is not available just now.");
  if (fromBrowser(request)) {
    return fail(403, "not_for_browsers", "This address takes pushes from ranwhat in a terminal, not from a web page.");
  }
  if (!await burstOk(env, network(request, { v6: 48 }))) return limited(60);

  let who;
  try {
    who = await identify(request, env);
  } catch {
    console.log("push: error");
    return fail(503, "unavailable", "Pushing is not available just now.");
  }
  if (!who.ok) {
    if (who.status === 401) return fail(401, "token_required", "A ranwhat token is needed: run ranwhat login.");
    if (who.status === 503) return fail(503, "unavailable", "Pushing is not available just now.");
    return fail(403, "token_refused", "That token was not accepted. Run ranwhat login again.");
  }
  if (who.kind !== "device" && who.kind !== "ci") {
    return fail(403, "machine_required", "Push needs a token from ranwhat login or a CI token, not a subscription's.");
  }
  if (!allows(who.plan, "push")) {
    return fail(403, "plus_required", "Push is on Plus. Your organisation is on Free.", { upgrade: UPGRADE });
  }

  const db = env.LIST;
  try {
    const over = await countPush(env, who);
    if (over) return over;

    if (request.headers.get("content-encoding") !== null) {
      return fail(415, "unsupported_media_type", "Send the body as plain application/json.");
    }
    if (!JSON_TYPE.test(request.headers.get("content-type") || "")) {
      return fail(415, "unsupported_media_type", "Send the body as application/json.");
    }
    const length = Number(request.headers.get("content-length"));
    if (Number.isFinite(length) && length > LIMITS.MAX_BODY) {
      return fail(413, "too_large", "That push is larger than the most a push can be.");
    }
    const bytes = await readBody(request);
    if (bytes === null) return fail(413, "too_large", "That push is larger than the most a push can be.");
    if (bytes.byteLength === 0) return fail(400, "bad_request", "The body is empty.");
    let doc;
    try {
      doc = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
    } catch {
      return fail(400, "bad_request", "The body is not JSON.");
    }
    if (doc === null || typeof doc !== "object" || Array.isArray(doc)) {
      return fail(400, "bad_request", "The body is not a JSON object.");
    }

    const t = now();
    const checked = validate(doc, t);
    if (!checked.ok) {
      const extra = { field: checked.field, reason: checked.reason };
      if (checked.supported) extra.supported = checked.supported;
      return fail(422, checked.error, checked.error === "unsupported_version"
        ? "That push is in a version this server does not take."
        : "That push does not match what a push may hold.", extra);
    }
    return await store(env, db, who, checked.value, t);
  } catch (err) {
    console.log("push: error");
    return fail(503, "unavailable", "Pushing is not available just now.");
  }
}

const unix = (iso) => Math.floor(Date.parse(iso) / 1000);

/* Writes a checked push for the machine whose token it came with. */
async function store(env, db, who, value, t) {
  const machine = who.machine.id;
  const keeps = RETENTION[who.plan] || RETENTION.plus;
  const digest = await digestOf(value);
  const generated = unix(value.generated_at);
  const latest = await db.prepare(
    "SELECT seq, digest, generated_at FROM pushes WHERE machine_id = ? AND org_id = ? ORDER BY seq DESC LIMIT 1")
    .bind(machine, who.org).first();

  const done = async (status) => {
    const row = await db.prepare("SELECT name FROM orgs WHERE id = ?").bind(who.org).first();
    return reply(200, {
      ok: true, v: 1, status, received_at: new Date(t * 1000).toISOString().slice(0, 19) + "Z",
      org: row ? row.name : null, machine: who.machine.label || null, actions: value.counts.flagged,
      keeps: { latest: 1, snapshots: keeps.snapshots, days: keeps.days },
    });
  };

  if (latest && latest.digest === digest) {
    await db.prepare("UPDATE pushes SET received_at = ? WHERE machine_id = ? AND seq = ? AND received_at < ?")
      .bind(t, machine, latest.seq, t).run();
    return done("unchanged");
  }
  if (latest && generated < latest.generated_at) {
    return fail(409, "stale", "A newer push from this machine is already here.");
  }
  if (!latest) {
    const n = await db.prepare(
      "SELECT count(*) AS n FROM (SELECT DISTINCT machine_id FROM pushes WHERE org_id = ?)").bind(who.org).first();
    if (n && n.n >= PUSH_LIMITS.MACHINES_PER_ORG) {
      return fail(429, "org_full", "This organisation already has as many machines pushing as it can.");
    }
  }

  const seq = latest ? latest.seq + 1 : 1;
  const c = value.counts;
  try {
    await db.batch([
      db.prepare(`INSERT INTO pushes (id, machine_id, org_id, seq, first_at, received_at, generated_at, digest,
                    version, window_days, flagged, ignored, omitted, unread, critical, high, medium,
                    rules, agents, scanned, actions)
                  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
        .bind(crypto.randomUUID(), machine, who.org, seq, t, t, generated, digest,
              value.ranwhat, value.window_days, c.flagged, c.ignored, c.omitted, c.unread,
              c.severity.critical, c.severity.high, c.severity.medium,
              JSON.stringify(c.rules), JSON.stringify(c.agents), JSON.stringify(c.scanned),
              JSON.stringify(value.actions)),
      db.prepare("UPDATE pushes SET actions = NULL WHERE machine_id = ? AND seq < ? AND actions IS NOT NULL")
        .bind(machine, seq),
      db.prepare("DELETE FROM pushes WHERE machine_id = ? AND seq < ? AND (seq <= ? OR received_at <= ?)")
        .bind(machine, seq, seq - keeps.snapshots, t - keeps.days * DAY),
    ]);
  } catch (err) {
    /* The unique (machine_id, seq) index refused it: a push from the same
       machine won the race, and the batch was rolled back whole. */
    if (/unique|constraint/i.test(String(err && err.message))) {
      return fail(409, "busy", "Another push from this machine was being stored. Try again.", {},
        { "retry-after": "1" });
    }
    throw err;
  }
  return done("stored");
}

/* The route, by host and path together; index.js asks while accounts are
   on. [handler, methods]. */
const ROUTES = { [PUSH_PATH]: [push, ["POST"]] };
export function pushRoute(url) {
  return url.hostname === FEED_HOST && Object.hasOwn(ROUTES, url.pathname) ? ROUTES[url.pathname] : null;
}

/* ---------- reads, for the page ---------- */

const JOINED = `FROM pushes p
  JOIN machines m ON m.id = p.machine_id AND m.org_id = p.org_id
  JOIN tokens k ON k.hash = m.hash`;

/* Each live machine's latest push of an organisation, summary columns
   only (never the actions). Revoked machines' are not read, and so are
   hidden the moment the token is revoked. */
export async function latestPushes(env, orgId) {
  const { results } = await env.LIST.prepare(
    `SELECT p.id, p.machine_id, p.seq, p.received_at, p.first_at, p.generated_at, p.version, p.window_days,
            p.flagged, p.ignored, p.omitted, p.unread, p.critical, p.high, p.medium, p.rules, p.agents, p.scanned
     ${JOINED}
     WHERE p.org_id = ? AND k.revoked_at IS NULL
       AND p.seq = (SELECT max(q.seq) FROM pushes q WHERE q.machine_id = p.machine_id)
     LIMIT 200`).bind(orgId).all();
  return results;
}

/* The actions of those machines' latest pushes: [{ machine_id, actions }],
   as stored text, for the page to parse and not trust. */
export async function actionsOf(env, orgId, machineIds) {
  const ids = machineIds.slice(0, 10);
  if (!ids.length) return [];
  const { results } = await env.LIST.prepare(
    `SELECT p.machine_id, p.actions ${JOINED}
     WHERE p.org_id = ? AND k.revoked_at IS NULL AND p.actions IS NOT NULL
       AND p.machine_id IN (${ids.map(() => "?").join(", ")})`).bind(orgId, ...ids).all();
  return results;
}

/* One machine's pushes, newest first, as counts: the latest and the
   summaries of the earlier ones still kept. */
export async function recentPushes(env, orgId, machineId) {
  const { results } = await env.LIST.prepare(
    `SELECT p.seq, p.received_at, p.generated_at, p.flagged, p.ignored, p.critical, p.high, p.medium
     ${JOINED}
     WHERE p.org_id = ? AND p.machine_id = ? AND k.revoked_at IS NULL
     ORDER BY p.seq DESC LIMIT 30`).bind(orgId, machineId).all();
  return results;
}
