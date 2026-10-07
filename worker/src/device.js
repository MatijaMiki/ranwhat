/* Linking a terminal to an account: RFC 8628's device authorization
 * grant, the way `gh auth login` does it, for `ranwhat login`.
 *
 * On feed.ranwhat.com, which takes a Bearer token and nothing else, and
 * never reads a cookie (index.js answers these paths there and only there):
 *
 *   POST /v1/device/code   client_id=ranwhat-cli. A device code for the
 *                          terminal to poll with, and a user code for its
 *                          person to type, eight letters shown XXXX-XXXX.
 *                          There is no verification_uri_complete: the code
 *                          is typed at ranwhat.com/device, never carried in
 *                          a link, so a link someone sends cannot approve a
 *                          terminal in one click (RFC 8628 section 5.4).
 *   POST /v1/device/token  The device code, polled for: authorization_pending,
 *                          slow_down, access_denied, expired_token, or, the
 *                          first time after approval and only then, the
 *                          terminal's own token.
 *   GET  /v1/whoami        Bearer: the token's account, organisation, plan
 *                          and machine label. Never anything secret.
 *   POST /v1/logout        Bearer: revokes this terminal's token. Shared
 *                          and CI tokens are left alone.
 *
 * GET ranwhat.com/device sends the browser to account.ranwhat.com/device,
 * where someone signed in, with an emailed code typed in the last 15
 * minutes, types the user code, sees the organisation the terminal will
 * belong to, its owner and their own role in it (and that it is not their
 * own, when it is not), and the warning to approve only a terminal they
 * started themselves, names the terminal, and approves or denies
 * (dashboard.js routes them here).
 *
 * At rest. The device code is 32 random bytes, kept as its SHA-256. The
 * user code is kept as two HMACs under ACCOUNT_SECRET, of its first four
 * letters and of all eight, so that a wrong try that names a waiting
 * code's first half counts against that code. Both live ten minutes and
 * are used once; the cron deletes them an hour after they expire. The
 * only thing kept about the terminal is the country Cloudflare saw the
 * request come from, shown on the approval page: the terminal sends no
 * hostname, operating system or machine identifier, and anything else it
 * sends is ignored.
 *
 * The token. rw_m_ and 32 random bytes, made at the first poll after
 * approval, once: the tokens row, the machines row and the code's move
 * to 'issued' are one batch that only a code still approved can pass, so
 * two polls at once get one token between them. It is kept as its
 * SHA-256 only, like every feed token (auth.js), with a machines row of
 * kind 'device' that says which organisation it belongs to and who
 * approved it; auth.js's identify() reads it as that organisation's, on
 * its plan. Its label is the name typed on the approval page, beside the
 * Approve button, and never anything the terminal sent. It
 * gives nothing on account.ranwhat.com, which never takes a Bearer token.
 *
 * Limits. Device codes per network an hour and per ten minutes, an IPv6
 * network being its /48 for these, behind a burst limit (DEVICE_RL); a
 * soft cap on the codes waiting at once, past which only a network with
 * none waiting gets one, and a ceiling past which nobody does; neither
 * device path answers a browser, so no web page can spend its visitors'
 * networks on them; slow_down for a code polled sooner than its
 * interval, which then grows by five seconds, and for a code nobody holds
 * one read and no write, with no count a network shares, so that nobody
 * else's polls can hold a waiting terminal back; wrong user codes per
 * session (five in ten minutes lock the form), per account (ten in an
 * hour) and per network (thirty in an hour), each counted before the code
 * is looked up, so that guesses sent at once are held to the limits too;
 * and five wrong tries at one waiting code lock that code, so that
 * guessing at any one terminal stops there. The network's count holds
 * back only an account that has typed WRONG_BEFORE_NETWORK wrong codes
 * itself that hour: nobody behind a shared address (an office, a campus,
 * a VPN) is locked out for codes someone else there typed, while every
 * guesser is held to a few an hour once the network is over its count,
 * and each needs a fresh emailed code for every session.
 */
import { identify, plan, schema as feedSchema, sha256 } from "./auth.js";
import { ACCOUNT_ORIGIN, HOUR, event, now, ownerOf, ready, schema as accountsSchema } from "./accounts.js";
import { PLAN_NAMES } from "./features.js";
import { escape, same } from "./list.js";
import { MAX_LABEL, machineLabel } from "./machines.js";
import {
  FRESH_FOR, SESSION_COOKIE, bump, clearCookie, current, formOk, formToken, fresh, mac, network, peek, randomToken,
  readCookie, unbump,
} from "./session.js";
import { fields, form, page, redirect, refused } from "./ui.js";
import { switcher } from "./members.js";

export const FEED_HOST = "feed.ranwhat.com";
export const SITE_HOST = "ranwhat.com";
export const CLIENT_ID = "ranwhat-cli";
export const GRANT_TYPE = "urn:ietf:params:oauth:grant-type:device_code";
export const VERIFICATION_URI = `https://${SITE_HOST}/device`;
export const DEVICE_PAGE = `${ACCOUNT_ORIGIN}/device`;

export const DEVICE_FOR = 10 * 60;        // a device code and its user code work this long
export const INTERVAL = 5;                // seconds between polls, to begin with
const SLOWER = 5;                         // added to the interval by each slow_down (RFC 8628 3.5)
const MAX_INTERVAL = 60;
export const CODES_PER_NETWORK = 20;      // device codes one network may ask for an hour
export const WAITING_PER_NETWORK = 5;     // and in DEVICE_FOR, so about as many waiting at once
export const CODE_NET_V6 = 48;            // for these two, an IPv6 network is its /48, not its /64
export const MAX_PENDING = 1000;          // codes waiting at once past which only networks with none waiting get one
export const PENDING_CEILING = 10 * MAX_PENDING; // and past which nobody does
export const WRONG_PER_SESSION = 5;       // wrong user codes one session may type in WRONG_WINDOW
export const WRONG_WINDOW = 10 * 60;
export const WRONG_PER_USER = 10;         // and one account in an hour, over all its sessions
export const WRONG_PER_NETWORK = 30;      // and one network in an hour,
export const WRONG_BEFORE_NETWORK = 3;    // for an account that has typed this many itself that hour
export const WRONG_PER_CODE = 5;          // wrong tries at one waiting code before it is locked
export const MACHINE_PREFIX = "rw_m_";

/* Twenty consonants: no vowel, so no code spells a word, and no digit, so
   nothing reads as something else (0 and O, 1 and I). 20^8 codes. */
export const USER_CODE_ALPHABET = "BCDFGHJKLMNPQRSTVWXZ";
const USER_CODE = /^[BCDFGHJKLMNPQRSTVWXZ]{8}$/;
const DEVICE_CODE = /^[A-Za-z0-9_-]{43}$/;   // 32 random bytes, base64url
const MAX_BODY = 4096;

/* ---------- codes ---------- */

/* Eight letters, each equally likely: a byte is used only below 240, the
   largest multiple of 20 a byte holds. */
export function newUserCode() {
  const out = [];
  while (out.length < 8) {
    for (const b of crypto.getRandomValues(new Uint8Array(16))) {
      if (b < 240 && out.length < 8) out.push(USER_CODE_ALPHABET[b % 20]);
    }
  }
  return out.join("");
}

export const shownCode = (code) => `${code.slice(0, 4)}-${code.slice(4)}`;

/* What was typed, as the code it means: case, spaces and the dash do not
   matter. null when it cannot be a code at all. */
export function typedUserCode(input) {
  const s = String(input ?? "").slice(0, 64).toUpperCase().replace(/[\s-]+/g, "");
  return USER_CODE.test(s) ? s : null;
}

/* user_code_mac: the HMAC of the first half, a dot, and the HMAC of the
   whole. The first part finds the code's row, and a wrong try that names
   it counts against it; the whole has to match for the row to be the one
   typed. No two codes in the table share a first half (open() makes sure),
   so a wrong try counts against one code at most. */
const halfMac = async (env, code) => `${await mac(env, `device-half:${code.slice(0, 4)}`)}.`;
const codeMac = async (env, code) => `${await halfMac(env, code)}${await mac(env, `device-code:${code}`)}`;

/* The row for a typed code, and any other rows sharing its first half. */
async function find(env, code) {
  const half = await halfMac(env, code);
  const whole = await codeMac(env, code);
  const { results } = await env.LIST.prepare(
    "SELECT * FROM device_codes WHERE substr(user_code_mac, 1, ?) = ?").bind(half.length, half).all();
  const row = results.find((r) => same(r.user_code_mac, whole)) || null;
  return { row, others: results.filter((r) => r !== row) };
}

/* ---------- answers on the feed host ---------- */

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

/* An RFC 6749 error, with a sentence the terminal may print. */
const oauthError = (status, error, description, extra = {}, headers = {}) =>
  reply(status, { error, error_description: description, ...extra }, headers);

const unavailable = () => oauthError(503, "temporarily_unavailable", "Linking a terminal is not available just now.");

/* A form body (application/x-www-form-urlencoded), or nothing: anything
   larger than a form of these few fields is not read. */
async function body(request) {
  if (Number(request.headers.get("content-length") || 0) > MAX_BODY) return new FormData();
  return fields(request);
}

/* The country Cloudflare saw, its two letters, and nothing else. */
function countryOf(request) {
  const c = request.cf && request.cf.country;
  return typeof c === "string" && /^[A-Z][A-Z0-9]$/.test(c) && c !== "XX" ? c : null;
}

async function tables(db) {
  await feedSchema(db);
  await accountsSchema(db);
}

/* A request a browser made. The terminal sends neither Origin nor
   Sec-Fetch-Site, and every browser sends one or the other with a POST,
   including the form-encoded, no-cors POST that any page on any site can
   make without a preflight: without this, a page could spend its
   visitors' networks on device codes. Sec-Fetch-Site: none is a browser's
   own navigation, typed or bookmarked, which no page can cause. */
function fromBrowser(request) {
  const site = request.headers.get("sec-fetch-site");
  return request.headers.get("origin") !== null || (site !== null && site !== "none");
}

const notForBrowsers = () => oauthError(403, "invalid_request",
  "This address takes requests from ranwhat in a terminal, not from a web page.");

/* DEVICE_RL (wrangler.toml), Workers' rate limiting binding: a burst from
   one network is turned away before the database is touched. Keyed by an
   HMAC of the network, as the throttle rows are. Where the binding is
   missing (a preview, the tests) or fails, the counts in D1 still hold. */
async function burstOk(env, net) {
  const limiter = env.DEVICE_RL;
  if (!limiter || typeof limiter.limit !== "function") return true;
  try {
    const { success } = await limiter.limit({ key: await mac(env, `device-rl:${net}`) });
    return success !== false;
  } catch {
    return true;
  }
}

const tooManyCodes = (retry) => oauthError(429, "rate_limited",
  "More terminals were linked from your network lately than we take. Try again later.",
  {}, { "retry-after": String(retry) });

/* POST /v1/device/code. Only client_id is read; a label, a hostname or
   anything else sent with it is dropped.

   Limits, so that no one source can keep everyone else from linking a
   terminal. An IPv6 network counts here by its /48 (CODE_NET_V6), so that
   the 65,536 /64s one holder is given are still one network: twenty codes
   an hour for it, and five in ten minutes, which is about as many as
   it can have waiting at once. MAX_PENDING waiting from everywhere is a
   soft cap: past it, a network that already asked for a code in the last
   ten minutes is refused, and one that did not still gets one, so filling
   the table locks out only those who filled it. PENDING_CEILING, ten times
   that, bounds the table for everyone. */
export async function deviceCode(request, env) {
  if (!ready(env)) return unavailable();
  if (fromBrowser(request)) return notForBrowsers();
  const net = network(request, { v6: CODE_NET_V6 });
  if (!await burstOk(env, net)) return tooManyCodes(60);
  const f = await body(request);
  if (f.get("client_id") !== CLIENT_ID) return oauthError(401, "invalid_client", "Unknown client. Update ranwhat and try again.");
  const db = env.LIST;
  await tables(db);
  if (await bump(env, "device-code-net", net, HOUR) > CODES_PER_NETWORK) return tooManyCodes(HOUR);
  const recent = await bump(env, "device-code-wait", net, DEVICE_FOR);
  if (recent > WAITING_PER_NETWORK) return tooManyCodes(DEVICE_FOR);
  const t = now();
  const waiting = await db.prepare("SELECT count(*) AS n FROM device_codes WHERE state = 'pending' AND expires_at > ?")
    .bind(t).first();
  if (waiting.n >= PENDING_CEILING) return unavailable();
  if (waiting.n >= MAX_PENDING && recent > 1) {
    return oauthError(503, "temporarily_unavailable",
      "Many terminals are waiting to be linked just now, and one from your network already is. " +
      "Type its code, or try again in ten minutes.", {}, { "retry-after": String(DEVICE_FOR) });
  }

  const deviceCode = randomToken();
  const hash = await sha256(deviceCode);
  const country = countryOf(request);
  /* A first half no row has, chosen inside the INSERT, so two requests at
     once cannot both take it. */
  for (let i = 0; i < 8; i++) {
    const code = newUserCode();
    const half = await halfMac(env, code);
    const made = await db.prepare(
      `INSERT INTO device_codes (device_hash, user_code_mac, country, created_at, expires_at, interval, state)
       SELECT ?, ?, ?, ?, ?, ?, 'pending'
       WHERE NOT EXISTS (SELECT 1 FROM device_codes WHERE substr(user_code_mac, 1, ?) = ?)`)
      .bind(hash, await codeMac(env, code), country, t, t + DEVICE_FOR, INTERVAL, half.length, half).run();
    if (made.meta.changes === 1) {
      return reply(200, {
        device_code: deviceCode,
        user_code: shownCode(code),
        verification_uri: VERIFICATION_URI,
        expires_in: DEVICE_FOR,
        interval: INTERVAL,
      });
    }
  }
  return unavailable();
}

/* The condition under which an approved code becomes a token: approved,
   in date, and its approver still a member of the organisation. The same
   text in every statement of mint()'s batch, so they all pass or none. */
const MINTABLE = `device_hash = ? AND state = 'approved' AND expires_at > ?
  AND EXISTS (SELECT 1 FROM memberships m WHERE m.org_id = device_codes.org_id AND m.user_id = device_codes.user_id)`;

/* The terminal's token, made once for the approved code whose hash is
   `hash`: { token, machine, org, user }, or null when the code is not (or
   no longer) approved, which includes when another poll has just taken
   it. */
export async function mint(env, hash) {
  const db = env.LIST;
  const t = now();
  const token = MACHINE_PREFIX + randomToken();
  const tokenHash = await sha256(token);
  const machine = crypto.randomUUID();
  const done = await db.batch([
    db.prepare(`INSERT INTO tokens (hash, note, created_at) SELECT ?, ?, ? FROM device_codes WHERE ${MINTABLE}`)
      .bind(tokenHash, `device ${machine}`, t, hash, t),
    db.prepare(`INSERT INTO machines (id, hash, org_id, user_id, kind, label, created_at)
                SELECT ?, ?, org_id, user_id, 'device', COALESCE(label, ''), ? FROM device_codes WHERE ${MINTABLE}`)
      .bind(machine, tokenHash, t, hash, t),
    db.prepare(`INSERT INTO auth_events (org_id, user_id, event, subject, at)
                SELECT org_id, user_id, 'machine_linked', ?, ? FROM device_codes WHERE ${MINTABLE}`)
      .bind(machine, t, hash, t),
    db.prepare(`UPDATE device_codes SET state = 'issued' WHERE ${MINTABLE}`).bind(hash, t),
  ]);
  if (done[3].meta.changes !== 1) return null;
  const row = await db.prepare("SELECT org_id, user_id FROM machines WHERE id = ?").bind(machine).first();
  return { token, machine, org: row.org_id, user: row.user_id };
}

/* POST /v1/device/token. */
export async function deviceToken(request, env) {
  if (!ready(env)) return unavailable();
  if (fromBrowser(request)) return notForBrowsers();
  const f = await body(request);
  if (f.get("client_id") !== CLIENT_ID) return oauthError(401, "invalid_client", "Unknown client. Update ranwhat and try again.");
  if (f.get("grant_type") !== GRANT_TYPE) {
    return oauthError(400, "unsupported_grant_type", "Only the device code grant is taken here.");
  }
  const unknown = () => oauthError(400, "invalid_grant",
    "That device code is not known, or was already used. Run ranwhat login again.");
  const sent = f.get("device_code");
  if (typeof sent !== "string" || !DEVICE_CODE.test(sent)) return unknown();
  const db = env.LIST;
  await tables(db);
  /* The code is looked up before anything is counted. A code nobody holds
     costs one read by the table's key, and no write, and is answered
     invalid_grant however many come; one that is waiting is held back by
     its own polled_at and interval below. No count is shared by a network,
     so polls with made-up codes from the same address, however many,
     never slow a waiting terminal there. */
  const hash = await sha256(sent);
  const t = now();
  const row = await db.prepare("SELECT state, expires_at FROM device_codes WHERE device_hash = ?").bind(hash).first();
  if (!row || row.state === "issued") return unknown();
  const expired = () => oauthError(400, "expired_token", "The code expired before it was approved. Run ranwhat login again.");
  if (row.expires_at <= t) return expired();

  /* On time when the last poll was at least the interval ago; otherwise
     slow_down, and the interval grows for this poll and every later one. */
  const onTime = await db.prepare(
    "UPDATE device_codes SET polled_at = ? WHERE device_hash = ? AND (polled_at IS NULL OR polled_at <= ? - interval)")
    .bind(t, hash, t).run();
  if (onTime.meta.changes !== 1) {
    const slower = await db.prepare(
      "UPDATE device_codes SET polled_at = ?, interval = MIN(interval + ?, ?) WHERE device_hash = ? RETURNING interval")
      .bind(t, SLOWER, MAX_INTERVAL, hash).first();
    return oauthError(400, "slow_down", "Polled too soon. Wait longer between polls.",
      { interval: slower ? slower.interval : MAX_INTERVAL });
  }
  const denied = () => oauthError(400, "access_denied", "It was not approved, so nothing was linked.");
  if (row.state === "pending") {
    return oauthError(400, "authorization_pending", `Waiting for the code to be typed at ${VERIFICATION_URI}.`);
  }
  if (row.state === "denied") return denied();

  const minted = await mint(env, hash);
  if (!minted) {
    const after = await db.prepare("SELECT state, expires_at FROM device_codes WHERE device_hash = ?").bind(hash).first();
    if (!after || after.state === "issued") return unknown();
    if (after.expires_at <= t) return expired();
    /* Approved by someone who is no longer a member of that organisation. */
    await db.prepare("UPDATE device_codes SET state = 'denied' WHERE device_hash = ? AND state = 'approved'").bind(hash).run();
    return denied();
  }
  const who = await db.prepare(
    "SELECT u.email, o.name FROM users u, orgs o WHERE u.id = ? AND o.id = ?").bind(minted.user, minted.org).first();
  return reply(200, {
    access_token: minted.token,
    token_type: "Bearer",
    email: who ? who.email : null,
    org: who ? who.name : null,
    plan: await plan(env, minted.org),
  });
}

/* What /v1/whoami says of a token identify() accepted. Never the token,
   its hash, an id or anything that could stand in for one. A CI token
   names its organisation and never the person who made it (machines.js
   keeps who did, for the account page): it sits in a pipeline's secrets,
   where others may read it. */
async function describe(env, who) {
  const db = env.LIST;
  const out = { kind: who.kind, email: null, org: null, role: null, plan: who.plan, machine: null };
  if (who.machine) {
    const row = await db.prepare(
      `SELECT o.name, u.email, m.role FROM orgs o
         LEFT JOIN users u ON u.id = ?
         LEFT JOIN memberships m ON m.org_id = o.id AND m.user_id = u.id
       WHERE o.id = ?`).bind(who.kind === "device" ? who.machine.user : null, who.org).first();
    return { ...out, email: row ? row.email : null, org: row ? row.name : null, role: row ? row.role : null,
             machine: { label: who.machine.label, created_at: who.machine.linked_at } };
  }
  if (who.org) {
    const row = await db.prepare("SELECT name FROM orgs WHERE id = ?").bind(who.org).first();
    return { ...out, org: row ? row.name : null };
  }
  return out;
}

/* GET /v1/whoami. */
export async function whoami(request, env) {
  const who = await identify(request, env);
  if (!who.ok) return reply(who.status, { error: who.error });
  return reply(200, await describe(env, who));
}

/* POST /v1/logout. Revokes the token presented when it is a terminal's;
   a shared subscription token, a hand-made one or a CI token stays as it
   is, since other machines may use it: { revoked: false, shared: true }. */
export async function logout(request, env) {
  const who = await identify(request, env);
  if (!who.ok) return reply(who.status, { error: who.error });
  if (who.kind !== "device") return reply(200, { revoked: false, shared: true });
  const db = env.LIST;
  await db.batch([
    db.prepare(`UPDATE tokens SET revoked_at = ? WHERE revoked_at IS NULL
                AND hash = (SELECT hash FROM machines WHERE id = ? AND kind = 'device')`).bind(now(), who.machine.id),
    event(db, { org: who.org, user: who.machine.user, what: "machine_logout", subject: who.machine.id }),
  ]);
  return reply(200, { revoked: true });
}

/* GET ranwhat.com/device: on to the page where the code is typed, without
   whatever query came with it. */
export const toDevicePage = () => new Response(null, {
  status: 302,
  headers: { location: DEVICE_PAGE, "cache-control": "no-store", "referrer-policy": "no-referrer" },
});

/* The paths index.js answers for these, by host: [handler, methods]. */
const FEED_ROUTES = {
  "/v1/device/code": [deviceCode, ["POST"]],
  "/v1/device/token": [deviceToken, ["POST"]],
  "/v1/whoami": [whoami, ["GET"]],
  "/v1/logout": [logout, ["POST"]],
};
const SITE_ROUTES = {
  "/device": [toDevicePage, ["GET", "HEAD"]],
  "/device/": [toDevicePage, ["GET", "HEAD"]],
};

export function deviceRoute(url) {
  const table = url.hostname === FEED_HOST ? FEED_ROUTES : url.hostname === SITE_HOST ? SITE_ROUTES : null;
  return table && Object.hasOwn(table, url.pathname) ? table[url.pathname] : null;
}

/* ---------- approving, on account.ranwhat.com ---------- */

/* No session: sign in first, and come back here. */
const toSignin = (request) =>
  redirect("/signin?next=/device", readCookie(request, SESSION_COOKIE) ? [clearCookie(SESSION_COOKIE)] : []);

const problem = (text) => (text ? `<p class="bad">${escape(text)}</p>` : "");

const WARNING = `<p class="bad"><strong>Approve only a terminal you started yourself.</strong> Type a code
       here only if you ran <strong>ranwhat login</strong> on your own machine in the last few
       minutes and it printed that code. If someone sent you a code, or asked you to type one
       here, stop: approving it gives whoever started it a token for your organisation.</p>`;

/* The countries Cloudflare names by code, in words where the runtime
   knows them. */
function countryName(code) {
  if (!code) return null;
  if (code === "T1") return "the Tor network";
  try {
    return new Intl.DisplayNames(["en"], { type: "region" }).of(code) || code;
  } catch {
    return code;
  }
}

function ago(seconds) {
  if (seconds < 60) return "less than a minute ago";
  const m = Math.floor(seconds / 60);
  return `${m} minute${m === 1 ? "" : "s"} ago`;
}

/* The three counts of wrong codes: this session's, this account's and
   this network's, each with its window and its limit. */
const WRONG_COUNTS = (request, who) => [
  ["device-wrong", who.id, WRONG_WINDOW, WRONG_PER_SESSION],
  ["device-wrong-user", who.user, HOUR, WRONG_PER_USER],
  ["device-wrong-net", network(request), HOUR, WRONG_PER_NETWORK],
];

/* Which count stops this session typing another code: "session",
   "account" or "network", or null when none does. The network's holds
   back only an account that has typed WRONG_BEFORE_NETWORK wrong codes
   itself this hour. Read only: for drawing the form. A typed code is
   counted with countTry() before it is looked up. */
async function overLimit(request, env, who) {
  const [session, account, net] = await Promise.all(WRONG_COUNTS(request, who)
    .map(([kind, key, window]) => peek(env, kind, key, window)));
  if (session >= WRONG_PER_SESSION) return "session";
  if (account >= WRONG_PER_USER) return "account";
  if (net >= WRONG_PER_NETWORK && account >= WRONG_BEFORE_NETWORK) return "network";
  return null;
}

/* Counts a typed code as a wrong try before it is looked up, and says
   whether it may be: { ok, left, over }. Counting first, in the one
   statement bump() is, is what holds the limits against a burst of
   guesses sent at once: each gets its own count, and those past the limit
   are turned away unlooked. A count past its limit stops the counting
   there, so a locked session does not spend its account's or its
   network's tries. left: the wrong codes this session may still type
   should this one be wrong, and over: the count that stops it once none
   are left. A code that turns out right gives its try back (refund()). */
async function countTry(request, env, who) {
  const s = await bump(env, "device-wrong", who.id, WRONG_WINDOW);
  if (s > WRONG_PER_SESSION) return { ok: false, left: 0, over: "session" };
  const a = await bump(env, "device-wrong-user", who.user, HOUR);
  if (a > WRONG_PER_USER) return { ok: false, left: 0, over: "account" };
  const n = await bump(env, "device-wrong-net", network(request), HOUR);
  if (n > WRONG_PER_NETWORK && a > WRONG_BEFORE_NETWORK) return { ok: false, left: 0, over: "network" };
  const lefts = [[WRONG_PER_SESSION - s, "session"], [WRONG_PER_USER - a, "account"],
    [n >= WRONG_PER_NETWORK ? Math.max(0, WRONG_BEFORE_NETWORK - a) : Infinity, "network"]];
  const [left, over] = lefts.reduce((low, next) => (next[0] < low[0] ? next : low));
  return { ok: true, left, over };
}

async function refund(request, env, who) {
  for (const [kind, key, window] of WRONG_COUNTS(request, who)) await unbump(env, kind, key, window);
}

/* The page for a session that may type no more codes for now, saying
   which count stopped it and for how long at most: the session's runs
   ten minutes, the account's and the network's an hour. */
function tooMany(over) {
  const why = {
    session: `Too many codes typed in this browser lately were not right,
       so this form is locked here for up to ${WRONG_WINDOW / 60} minutes.`,
    account: `Too many codes typed for this account in the last hour were not right,
       so this form is locked for it for up to an hour.`,
    network: `Too many codes typed from your network in the last hour were not right, some of them
       for this account, so this form is locked for it for up to an hour.`,
  }[over];
  return page("Too many wrong codes", `<h1>Too many wrong codes.</h1>
  <p class="bad">${why} Try again then, or run <strong>ranwhat login</strong> again in your terminal for a
     new code once you can.</p>
  <p><a href="/">Your account</a></p>`, { status: 429 });
}

/* The step-up, for a session whose last emailed code is older than
   FRESH_FOR: a new code mailed to the account, back here once typed. */
async function needsCode(env, who, { status = 200, error = "" } = {}) {
  return page("Link a terminal", `<h1>Link a terminal</h1>
    <p>Approving a terminal needs an emailed code typed in the last ${FRESH_FOR / 60} minutes. We
       send one to <strong>${escape(who.email)}</strong>; once you type it you come back here.</p>
    ${problem(error)}
    ${form("/stepup", await formToken(env, who.id, "stepup"), `
      <input type="hidden" name="next" value="/device">
      <button type="submit">Email me a code</button>`)}
    <p><a href="/">Your account</a></p>`, { status });
}

const ROLES = Object.freeze({ owner: "Owner", admin: "Admin", member: "Member" });

/* Whose organisation the terminal would join: names are not unique (every
   personal organisation is "Personal"), so its owner is named too, unless
   that is the person approving. */
const owned = async (env, who) => (who.org.role === "owner" ? null : await ownerOf(env, who.org.id) || "nobody");

/* The box the code is typed in, saying which organisation the terminal
   will be linked to, and whose, and, for someone in more than one, the
   switcher that picks another (members.js) and comes back here. */
async function codeBox(request, env, who, { error = "", status = 200 } = {}) {
  if (!fresh(who)) return needsCode(env, who, { status: status === 200 ? 200 : 403, error });
  const over = await overLimit(request, env, who);
  if (over) return tooMany(over);
  const owner = await owned(env, who);
  return page("Link a terminal", `<h1>Link a terminal</h1>
    <p>Type the code your terminal printed after <strong>ranwhat login</strong>. The terminal is
       linked to <strong>${escape(who.org.name)}</strong>${owner
         ? `, owned by <strong>${escape(owner)}</strong>, not an organisation of your own` : ""}.</p>
    ${await switcher(env, who, "/device")}
    ${WARNING}
    ${form("/device", await formToken(env, who.id, "device"), `
      <label for="user_code">Code from your terminal</label>
      <input id="user_code" name="user_code" type="text" autocomplete="off" autocapitalize="characters"
             spellcheck="false" maxlength="12" required autofocus>
      ${problem(error)}
      <button type="submit">Continue</button>`)}
    <p><a href="/">Your account</a></p>`, { status });
}

/* GET /device. */
export async function devicePage(request, env) {
  const who = await current(request, env);
  if (!who) return toSignin(request);
  return codeBox(request, env, who);
}

/* Why a typed code that is not waiting cannot be approved. */
function notWaiting(row) {
  const t = now();
  const [title, text] = row.expires_at <= t
    ? ["Code expired", "That code has expired. Run ranwhat login again in your terminal for a new one."]
    : row.state === "denied" && !row.user_id
      ? ["Code locked", "That code was locked after too many wrong tries at it, so it no longer works. Run ranwhat login again in your terminal for a new one."]
      : row.state === "denied"
        ? ["Code denied", "That code was denied, so it no longer works. Run ranwhat login again in your terminal for a new one."]
        : ["Code already used", "That code was already approved, so it cannot be used again. Run ranwhat login again in your terminal for a new one."];
  return page(title, `<h1>${title}.</h1>
    <p class="bad">${text}</p>
    <p><a href="/device">Type another code</a></p>`, { status: 400 });
}

/* A wrong code, already counted for this session, this account and this
   network by countTry(), counted against any waiting code whose first
   half it named: the fifth such try locks that code. */
async function wrongTry(env, others) {
  const t = now();
  for (const r of others) {
    if (r.state !== "pending" || r.expires_at <= t) continue;
    if (await bump(env, "device-code-wrong", r.device_hash, DEVICE_FOR) >= WRONG_PER_CODE) {
      await env.LIST.prepare(
        "UPDATE device_codes SET state = 'denied', decided_at = ? WHERE device_hash = ? AND state = 'pending'")
        .bind(t, r.device_hash).run();
    }
  }
}

/* POST /device: the typed code. When it is waiting, the page that says
   what approving would do, with Approve and Deny. */
export async function deviceLookup(request, env) {
  const who = await current(request, env);
  if (!who) return toSignin(request);
  const f = await fields(request);
  if (!await formOk(env, f, who.id, "device")) return refused();
  if (!fresh(who)) return needsCode(env, who, { status: 403 });
  const over = await overLimit(request, env, who);
  if (over) return tooMany(over);
  const code = typedUserCode(f.get("user_code"));
  if (!code) {
    return codeBox(request, env, who, { status: 400,
      error: "A code is eight letters, in two groups of four, as your terminal printed it." });
  }
  const tried = await countTry(request, env, who);
  if (!tried.ok) return tooMany(tried.over);
  const { row, others } = await find(env, code);
  if (!row) {
    await wrongTry(env, others);
    if (tried.left <= 0) return tooMany(tried.over);
    return codeBox(request, env, who, { status: 400,
      error: `That code is not right. ${tried.left} ${tried.left === 1 ? "try" : "tries"} left.` });
  }
  await refund(request, env, who);
  if (row.state !== "pending" || row.expires_at <= now()) return notWaiting(row);
  return confirmPage(env, who, code, row);
}

const approveAction = (code, org) => `device-approve:${code}:${org}`;
const denyAction = (code) => `device-deny:${code}`;

/* Only what the server knows: the organisation, whose it is and the
   approver's role in it, its plan, and when and from which country the
   code was asked for. Nothing the terminal wrote. An organisation that is
   not the approver's own is said to be so, with its owner, as its name
   alone may be the same as theirs. The name the terminal goes by on the
   account page is typed here, with the approval: a terminal sends none. */
async function confirmPage(env, who, code, row, { error = "", status = 200 } = {}) {
  const org = who.org;
  const onPlan = await plan(env, org.id);
  const where = countryName(row.country);
  const owner = await owned(env, who);
  const notOwn = owner ? `<p class="bad"><strong>${escape(org.name)}</strong> is not an organisation of your own: it is
       owned by <strong>${escape(owner)}</strong>. Everyone in it sees this terminal, who linked it and the day it
       was last used, and its owner and admins can revoke it.</p>` : "";
  const free = onPlan === "free"
    ? `<p>${escape(org.name)} is on Free: the terminal is linked, and what needs the server
       (ranwhat update's feed) asks for Plus.</p>` : "";
  return page("Approve this terminal?", `<h1>Approve this terminal?</h1>
    ${WARNING}
    <dl>
      <dt>Code</dt><dd>${escape(shownCode(code))}</dd>
      <dt>Asked for</dt><dd>${escape(ago(now() - row.created_at))}${where ? `, from ${escape(where)}` : ""}</dd>
      <dt>Organisation</dt><dd>${escape(org.name)}</dd>
      <dt>Owner</dt><dd>${owner ? escape(owner) : "You"}</dd>
      <dt>Your role</dt><dd>${ROLES[org.role] || "Member"}</dd>
      <dt>Plan</dt><dd>${PLAN_NAMES[onPlan]}</dd>
    </dl>
    ${notOwn}
    <p>The terminal gets a token of its own for <strong>${escape(org.name)}</strong>, listed
       under Machines on your account page by the name you give it here. Running
       <strong>ranwhat logout</strong> there revokes it, as Revoke on your account page does.</p>
    ${free}
    ${form("/device/approve", await formToken(env, who.id, approveAction(code, org.id)), `
      <input type="hidden" name="user_code" value="${escape(code)}">
      <input type="hidden" name="org" value="${escape(org.id)}">
      <label for="label">Name this terminal, to tell it apart later</label>
      <input id="label" name="label" type="text" maxlength="${MAX_LABEL}" required autocomplete="off"
             placeholder="Work laptop">
      ${problem(error)}
      <button type="submit">Approve</button>`)}
    ${form("/device/deny", await formToken(env, who.id, denyAction(code)), `
      <input type="hidden" name="user_code" value="${escape(code)}">
      <button type="submit">Deny</button>`, "row")}
    <p><a href="/device">Type another code</a></p>`, { status });
}

/* POST /device/approve: with a fresh code, for the organisation the page
   showed, which must still be the one this session is looking at, and
   with a name for the terminal (machines.js machineLabel()). The form
   token is bound to the code and that organisation, so neither can be
   swapped in the form. The name is written with the approval, in the one
   UPDATE that moves the code from pending, and mint() copies it onto the
   machine. */
export async function approve(request, env) {
  const who = await current(request, env);
  if (!who) return toSignin(request);
  const f = await fields(request);
  const code = typedUserCode(f.get("user_code"));
  const orgId = String(f.get("org") ?? "");
  if (!code || !await formOk(env, f, who.id, approveAction(code, orgId))) return refused();
  if (orgId !== who.org.id) {
    return page("Not approved", `<h1>Not approved.</h1>
      <p class="bad">That page offered to link the terminal to an organisation this account is not
         looking at now, so nothing was approved. Type the code again to see where it would go.</p>
      <p><a href="/device">Type the code again</a></p>`, { status: 403 });
  }
  if (!fresh(who)) return needsCode(env, who, { status: 403,
    error: "Your last emailed code is too old, so nothing was approved. Confirm with a new one, then type the code again." });
  const { row } = await find(env, code);
  if (!row) return notWaiting({ expires_at: 0 });
  if (row.state !== "pending" || row.expires_at <= now()) return notWaiting(row);
  const label = machineLabel(f.get("label"));
  if (!label) {
    return confirmPage(env, who, code, row, { status: 400,
      error: `Give the terminal a name of 1 to ${MAX_LABEL} printable characters, to tell it apart on your account page. Nothing was approved.` });
  }
  const t = now();
  const db = env.LIST;
  const done = await db.prepare(
    `UPDATE device_codes SET state = 'approved', user_id = ?, org_id = ?, label = ?, decided_at = ?
     WHERE device_hash = ? AND state = 'pending' AND expires_at > ?`)
    .bind(who.user, who.org.id, label, t, row.device_hash, t).run();
  if (done.meta.changes !== 1) {
    return notWaiting(await db.prepare("SELECT * FROM device_codes WHERE device_hash = ?").bind(row.device_hash).first()
      || { expires_at: 0 });
  }
  await event(db, { org: who.org.id, user: who.user, what: "device_approved" }).run();
  const owner = await owned(env, who);
  return page("Approved", `<h1>Approved.</h1>
    <p>Go back to your terminal. Within a few seconds it says it is linked to
       <strong>${escape(who.org.name)}</strong> as <strong>${escape(who.email)}</strong>. If it names
       anything else, run <strong>ranwhat logout</strong> there.</p>
    ${owner ? `<p><strong>${escape(who.org.name)}</strong> is owned by <strong>${escape(owner)}</strong>, not you.</p>` : ""}
    <p>It is listed under Machines on your account page as <strong>${escape(label)}</strong>.</p>
    <p><a href="/">Your account</a></p>`);
}

/* POST /device/deny: the terminal is told access_denied, and gets nothing. */
export async function deny(request, env) {
  const who = await current(request, env);
  if (!who) return toSignin(request);
  const f = await fields(request);
  const code = typedUserCode(f.get("user_code"));
  if (!code || !await formOk(env, f, who.id, denyAction(code))) return refused();
  const { row } = await find(env, code);
  if (!row) return notWaiting({ expires_at: 0 });
  const t = now();
  const db = env.LIST;
  const done = await db.prepare(
    `UPDATE device_codes SET state = 'denied', user_id = ?, org_id = ?, decided_at = ?
     WHERE device_hash = ? AND state = 'pending' AND expires_at > ?`)
    .bind(who.user, who.org.id, t, row.device_hash, t).run();
  if (done.meta.changes !== 1) {
    return notWaiting(await db.prepare("SELECT * FROM device_codes WHERE device_hash = ?").bind(row.device_hash).first()
      || { expires_at: 0 });
  }
  await event(db, { org: who.org.id, user: who.user, what: "device_denied" }).run();
  return page("Denied", `<h1>Denied.</h1>
    <p>The terminal that asked is told no, and gets nothing.</p>
    <p><a href="/">Your account</a></p>`);
}
