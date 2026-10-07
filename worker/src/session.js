/* Who is signed in on account.ranwhat.com, and how they got there: the
 * emailed code, the session it opens, the limits on both, and the check
 * every form passes.
 *
 * The code. Eight characters from a 32-letter alphabet (40 bits), mailed
 * with no link: nothing in the email signs anyone in, it has to be typed
 * into the browser that asked for it. That browser holds the attempt in
 * the __Host-rw_signin cookie, and the code is good there only, once, for
 * ten minutes and five tries. A new request from the same browser cancels
 * its last attempt. The database keeps an HMAC of the code under
 * ACCOUNT_SECRET, and the SHA-256 of the cookie, never either one.
 *
 * Asking for a code gives the same answer for every address, known or
 * not, limited or not: the code is mailed after the reply has gone, no
 * account is looked up until a code is typed, and an address over its
 * limit gets an attempt whose code was never sent, and which no code
 * completes.
 *
 * The limits. What one person does must not use up what another needs, so
 * a stranger can neither lock someone out of their account nor shut
 * sign-in for everyone. Each is counted for a network (network() below:
 * an IPv6 /64 counts as one, as an IPv4 address does) or for an address
 * as asked for from one network, and the only limit on codes for an
 * address alone is the mail it can be sent in an hour. Wrong codes count
 * against the network that typed them, never against another browser's
 * attempt. The day's account mail (accounts.js) keeps a reserve for
 * signed-in step-ups, and each network (for this, an IPv4 /24) gets a
 * share of the rest. The forms that mail a code also pass Turnstile first
 * (dashboard.js, challenge.js).
 *
 * The session. __Host-rw_session holds 32 random bytes; D1 keeps their
 * SHA-256 as the session's id. Every sign-in opens a new one and ends the
 * one the browser had. A session ends after 14 days unused and 30 days
 * after sign-in at most, and on sign out, or sign out everywhere.
 *
 * Forms. Every POST must come from a page on this host: Sec-Fetch-Site
 * same-origin where the browser sends it, the exact Origin where it sends
 * that, at least one of the two, and a form token, an HMAC of what the
 * form does and the session (or sign-in attempt) it was shown to. The
 * cookies' SameSite=Lax is a second layer, not the check.
 */
import { sha256 } from "./auth.js";
import { REPLY_TO, mail, resend, same } from "./list.js";
import {
  ACCOUNT_HOST, ACCOUNT_ORIGIN, DAY, HOUR, SESSION_IDLE, SESSION_MAX, STEPUPS_PER_USER_DAY,
  authMailLeft, now, orgFor, spendAuthMail,
} from "./accounts.js";

export const SESSION_COOKIE = "__Host-rw_session";
export const SIGNIN_COOKIE = "__Host-rw_signin";

export const CODE_FOR = 10 * 60;      // a code works this long
export const CODE_TRIES = 5;          // and is burned by this many wrong tries
const CODE_EVERY = 60;                // one code a minute for an address, from one network
const CODES_PER_HOUR = 5;             // and five an hour
const CODES_PER_ADDRESS = 20;         // and twenty an hour for an address from every network together
const ASKS_PER_NETWORK = 20;          // code requests from one network an hour
export const NETWORK_MAIL_PER_DAY = 10; // codes mailed a day for one network: an IPv6 /64, or here an IPv4 /24
const GUESSES_PER_HOUR = 10;          // wrong codes for one address from one network an hour
const GUESSES_PER_NETWORK = 30;       // wrong codes from one network an hour, whatever the address
export const SIGNIN_FOR = HOUR;       // the sign-in cookie: long enough to leave the form open a while
export const FRESH_FOR = 15 * 60;     // a code typed this recently counts as fresh
const SEEN_EVERY = 5 * 60;            // seen_at is written at most this often

/* Crockford's base 32: no I, L, O or U, so nothing reads as something else,
   and 256 is a multiple of 32, so every letter is equally likely. */
const ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const TOKEN = /^[A-Za-z0-9_-]{43}$/;   // 32 random bytes, base64url

/* Stricter than RFC 5322 on purpose, as the contact form is: the address
   goes into an email's To. */
const EMAIL = /^[^@\s<>()[\]\\,;:"]+@[^@\s<>()[\]\\,;:".]+(\.[^@\s<>()[\]\\,;:".]+)+$/;

/* Where a sign-in may send the browser on to. M3 adds /device. */
const NEXT = new Set(["/"]);
export const nextPath = (value) => (NEXT.has(value) ? value : "/");

/* ---------- secrets ---------- */

const enc = new TextEncoder();

export function b64url(bytes) {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export const randomToken = () => b64url(crypto.getRandomValues(new Uint8Array(32)));

let keyed = { secret: null, key: null };

/* HMAC-SHA256 under ACCOUNT_SECRET, base64url. index.js only lets a
   request this far when the secret is set and long enough. */
export async function mac(env, text) {
  if (keyed.secret !== env.ACCOUNT_SECRET) {
    keyed = {
      secret: env.ACCOUNT_SECRET,
      key: await crypto.subtle.importKey("raw", enc.encode(env.ACCOUNT_SECRET),
        { name: "HMAC", hash: "SHA-256" }, false, ["sign"]),
    };
  }
  return b64url(new Uint8Array(await crypto.subtle.sign("HMAC", keyed.key, enc.encode(text))));
}

export function newCode() {
  return [...crypto.getRandomValues(new Uint8Array(8))].map((b) => ALPHABET[b & 31]).join("");
}

/* What was typed, as the code it means: case, spaces and the dash in the
   middle do not matter, and O, I and L are read as 0, 1 and 1. null when
   it cannot be a code at all. */
export function typedCode(input) {
  const s = String(input ?? "").toUpperCase().replace(/[\s-]+/g, "")
    .replace(/O/g, "0").replace(/[IL]/g, "1");
  return /^[0-9A-HJKMNP-TV-Z]{8}$/.test(s) ? s : null;
}

const codeMac = (env, attempt, code) => mac(env, `code:${attempt}:${code}`);

export function address(input) {
  const s = String(input ?? "").trim().toLowerCase();
  return s.length <= 200 && EMAIL.test(s) ? s : null;
}

/* ---------- cookies ---------- */

export function readCookie(request, name) {
  for (const part of (request.headers.get("cookie") || "").split(";")) {
    const at = part.indexOf("=");
    if (at > 0 && part.slice(0, at).trim() === name) {
      const value = part.slice(at + 1).trim();
      return TOKEN.test(value) ? value : null;
    }
  }
  return null;
}

/* __Host-: the browser refuses it unless it is Secure, has Path=/ and no
   Domain, so it is never sent to any other ranwhat.com host. */
export const setCookie = (name, value, maxAge) =>
  `${name}=${value}; Max-Age=${maxAge}; Path=/; Secure; HttpOnly; SameSite=Lax`;
export const clearCookie = (name) => setCookie(name, "", 0);

/* ---------- forms ---------- */

/* Sec-Fetch-Site must say same-origin and Origin must be this host, where
   the browser sends them; same-site (another ranwhat.com host) is not
   enough, and a request with neither is refused. The pages' Referrer-Policy
   is same-origin rather than no-referrer for this: under no-referrer a
   browser sends Origin: null on its own form posts. */
export function sameOrigin(request) {
  const site = request.headers.get("sec-fetch-site");
  const origin = request.headers.get("origin");
  if (site === null && origin === null) return false;
  if (site !== null && site !== "same-origin") return false;
  if (origin !== null && origin !== ACCOUNT_ORIGIN) return false;
  return new URL(request.url).hostname === ACCOUNT_HOST;
}

/* The token a form carries: what it does, bound to the session or the
   sign-in attempt it was shown to. */
export const formToken = (env, binding, action) => mac(env, `form:${action}:${binding}`);

export async function formOk(env, form, binding, action) {
  const sent = form.get("form");
  if (!binding || typeof sent !== "string") return false;
  return same(sent, await formToken(env, binding, action));
}

/* ---------- limits ---------- */

/* The network a request comes from, as the limits count it: an IPv4
   address by itself (with `v4: 24`, its /24), and an IPv6 address by its
   /64, which is what one home, phone or server is given, so that walking
   through the addresses of one /64 is still one network. An address that
   cannot be read is counted as itself. */
export function network(request, { v4 = 32 } = {}) {
  const ip = (request.headers.get("cf-connecting-ip") || "unknown").trim().toLowerCase();
  const four = /^(?:::ffff:)?(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip);
  if (four) return v4 === 24 ? `${four[1]}.${four[2]}.${four[3]}.0/24` : four.slice(1).join(".");
  const halves = ip.split("::");
  if (!ip.includes(":") || halves.length > 2) return ip;
  const head = halves[0] ? halves[0].split(":") : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  const gap = 8 - head.length - tail.length;
  if (halves.length === 1 ? gap !== 0 : gap < 1) return ip;
  const groups = [...head, ...Array(halves.length === 2 ? gap : 0).fill("0"), ...tail];
  if (!groups.every((g) => /^[0-9a-f]{1,4}$/.test(g))) return ip;
  return `${groups.slice(0, 4).map((g) => parseInt(g, 16).toString(16)).join(":")}::/64`;
}

/* One key for two things counted together, such as an address as asked
   for from one network. */
const both = (a, b) => JSON.stringify([a, b]);

const throttleKey = async (env, kind, who) => `${kind}:${await mac(env, `throttle:${kind}:${who}`)}`;

/* Counts one more in a fixed window, and returns the count. One statement,
   so concurrent requests cannot both read the old count. */
export async function bump(env, kind, who, window) {
  const t = now();
  const key = await throttleKey(env, kind, who);
  const row = await env.LIST.prepare(
    `INSERT INTO throttle (key, window_start, count) VALUES (?, ?, 1)
     ON CONFLICT(key) DO UPDATE SET
       count = CASE WHEN window_start <= ? THEN 1 ELSE count + 1 END,
       window_start = CASE WHEN window_start <= ? THEN excluded.window_start ELSE window_start END
     RETURNING count`).bind(key, t, t - window, t - window).first();
  return row.count;
}

/* The count so far in the window, without adding to it. */
export async function peek(env, kind, who, window) {
  const key = await throttleKey(env, kind, who);
  const row = await env.LIST.prepare("SELECT count FROM throttle WHERE key = ? AND window_start > ?")
    .bind(key, now() - window).first();
  return row ? row.count : 0;
}

/* The statement that starts a count again from nothing, for the caller's
   batch. */
export async function forget(env, kind, who) {
  return env.LIST.prepare("DELETE FROM throttle WHERE key = ?").bind(await throttleKey(env, kind, who));
}

/* ---------- asking for a code ---------- */

/* Starts an attempt and mails its code, after the reply, through
   ctx.waitUntil. Returns { token } for the __Host-rw_signin cookie, or
   { refused: "network" | "network-day" | "budget" } when nothing can be
   sent right now: none depends on the address, so none says anything
   about it.

   The order matters. The network's requests this hour are counted first,
   then the day's mail for this purpose and the network's share of it are
   read, before anything about the address; mail is taken from both only
   when a code is mailed, so they say no more about an address than the
   day's budget always has. Then the address, as asked for from this
   network (a minute, an hour) and from everywhere (an hour). A stranger's
   requests for someone's address therefore use up the stranger's own
   limits, not theirs, until there are enough of them to reach the
   address's hourly cap on mail.

   previous: the browser's last attempt, cancelled by this one. When the
   address is over its limits, the browser keeps a live attempt it already
   has for that address, or gets one whose code was never sent (mailed 0)
   and which checkCode() never accepts: either way the reply is the same
   as for any other address.

   passwordHash: with purpose 'verify', the hash of the password this
   browser chose (password.js). It is kept in this attempt's row and
   nowhere else, so only this browser, typing this code, can attach it to
   an account. A browser that keeps its live attempt keeps it with the
   password it typed last. */
export async function requestCode(request, env, ctx, {
  email, purpose, userId = null, next = "/", previous = null, passwordHash = null,
}) {
  const db = env.LIST;
  const t = now();
  const net = network(request);
  const wide = network(request, { v4: 24 });
  if (await bump(env, "ask-ip", net, HOUR) > ASKS_PER_NETWORK) return { refused: "network" };
  // A step-up is keyed on the account, which no change of network escapes.
  if (purpose === "stepup" && userId &&
      await bump(env, "stepup-user", userId, DAY) > STEPUPS_PER_USER_DAY) return { refused: "budget" };
  if (await authMailLeft(env, purpose) <= 0) return { refused: "budget" };
  if (await peek(env, "mail-net", wide, DAY) >= NETWORK_MAIL_PER_DAY) return { refused: "network-day" };

  const emailMac = await mac(env, `email:${email}`);
  const here = both(email, net);
  const limited = await bump(env, "code-minute", here, CODE_EVERY) > 1 ||
    await bump(env, "code-hour", here, HOUR) > CODES_PER_HOUR ||
    await bump(env, "code-address", email, HOUR) > CODES_PER_ADDRESS;
  const before = previous ? await db.prepare(
    "SELECT email_mac, purpose, expires_at, tries, used_at FROM signins WHERE id = ?")
    .bind(await sha256(previous)).first() : null;
  if (limited && before && before.email_mac === emailMac && before.purpose === purpose &&
      !before.used_at && before.tries < CODE_TRIES && before.expires_at > t) {
    if (passwordHash) {
      await db.prepare("UPDATE signins SET password_hash = ? WHERE id = ? AND used_at IS NULL")
        .bind(passwordHash, await sha256(previous)).run();
    }
    return { token: previous };
  }
  if (!limited) {
    if (!await spendAuthMail(env, purpose)) return { refused: "budget" };
    await bump(env, "mail-net", wide, DAY);
  }

  const token = randomToken();
  const id = await sha256(token);
  const code = newCode();
  const statements = [
    db.prepare(`INSERT INTO signins (id, email, email_mac, purpose, user_id, code_mac, password_hash, next,
                                     created_at, expires_at, mailed)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
      .bind(id, email, emailMac, purpose, userId, await codeMac(env, id, code), passwordHash, nextPath(next),
        t, t + CODE_FOR, limited ? 0 : 1),
  ];
  if (previous) {
    statements.push(db.prepare("UPDATE signins SET used_at = ?, password_hash = NULL WHERE id = ? AND used_at IS NULL")
      .bind(t, await sha256(previous)));
  }
  await db.batch(statements);
  if (!limited) {
    ctx.waitUntil(mailCode(env, email, code, purpose).catch((err) => {
      console.log(`account code mail: ${err.code || "error"}`);
    }));
  }
  return { token };
}

const FROM = "ranwhat <account@ranwhat.com>";

/* No link: the code is typed, never clicked. The text names the one place
   it goes, because a code someone reads out to a caller signs the caller
   in. A code that sets a password says so, so that someone who never chose
   one knows what ignoring it prevents. */
async function mailCode(env, email, code, purpose) {
  const shown = `${code.slice(0, 4)}-${code.slice(4)}`;
  const what = { signin: "sign-in code", reset: "password reset code" }[purpose] || "confirmation code";
  const sets = {
    verify: "Typing it confirms this address and sets the password chosen on that page, replacing any password the account had and signing it out everywhere else.",
    reset: "Typing it, with a new password, on that page replaces this account's password and signs it out everywhere else.",
  }[purpose] || "";
  await resend(env, "POST", "/emails", {
    from: FROM,
    to: [email],
    reply_to: REPLY_TO,
    subject: `Your ranwhat ${what}`,
    text: [
      `Your ranwhat ${what}:`,
      "",
      `    ${shown}`,
      "",
      `Type it on the page at ${ACCOUNT_HOST} that asked for it. It works`,
      "once, for 10 minutes, in that browser only.",
      "",
      ...(sets ? [sets, ""] : []),
      `Never type it anywhere else. Nobody from ranwhat will ever ask you`,
      "for it, by email, chat or phone.",
      "",
      "If you did not ask for a code, ignore this email: nothing happens",
      "without it.",
      "",
      "ranwhat.com",
    ].join("\n"),
    html: mail(`
      <p>Your ranwhat ${what}:</p>
      <p style="margin:22px 0;font-family:Menlo,Consolas,monospace;font-size:26px;letter-spacing:3px">${shown}</p>
      <p>Type it on the page at ${ACCOUNT_HOST} that asked for it. It works once, for 10 minutes,
         in that browser only.</p>${sets ? `\n      <p>${sets}</p>` : ""}
      <p>Never type it anywhere else. Nobody from ranwhat will ever ask you for it, by email,
         chat or phone.</p>
      <p style="color:#5a6672">If you did not ask for a code, ignore this email: nothing happens
         without it.</p>`),
  });
}

/* ---------- typing it ---------- */

export async function attempt(env, token) {
  if (!token) return null;
  return env.LIST.prepare("SELECT * FROM signins WHERE id = ?").bind(await sha256(token)).first();
}

/* Checks a typed code against the browser's attempt. Every try is counted
   before the code is compared, and the fifth wrong one burns the attempt.
   Wrong codes are also counted for the network that typed them: ten for
   one address, or thirty for any, in an hour, and that network's attempts
   are burned as it tries them. Nothing typed anywhere else touches this
   attempt, so a stranger's guesses can never spend the tries of the
   person whose address it is. An attempt whose code was never mailed
   answers as any attempt does, and is never right.

   The attempt is then used in one UPDATE that has to change exactly one
   row, so two requests with the right code at once open one session, not
   two. The same UPDATE clears a password hash the attempt held: the row
   that comes back still carries it, for the caller to attach.

   { ok: true, row } or { ok: false, why: "expired" | "burned" | "wrong", left } */
export async function checkCode(request, env, token, typed) {
  const db = env.LIST;
  const t = now();
  const row = await attempt(env, token);
  if (!row || row.used_at || row.expires_at <= t) return { ok: false, why: "expired" };
  if (row.tries >= CODE_TRIES) return { ok: false, why: "burned" };
  const net = network(request);
  const here = both(row.email_mac, net);
  const burned = async () => {
    await db.prepare("UPDATE signins SET tries = ? WHERE id = ? AND used_at IS NULL").bind(CODE_TRIES, row.id).run();
    return { ok: false, why: "burned" };
  };
  if (await peek(env, "guess", here, HOUR) >= GUESSES_PER_HOUR ||
      await peek(env, "guess-net", net, HOUR) >= GUESSES_PER_NETWORK) {
    return burned();
  }
  const counted = await db.prepare(
    "UPDATE signins SET tries = tries + 1 WHERE id = ? AND used_at IS NULL AND tries < ? AND expires_at > ?")
    .bind(row.id, CODE_TRIES, t).run();
  if (counted.meta.changes !== 1) return { ok: false, why: "burned" };

  const code = typedCode(typed);
  const matches = code !== null && same(await codeMac(env, row.id, code), row.code_mac);
  if (!matches || row.mailed !== 1) {
    /* This network's tenth wrong code for the address, or thirtieth in
       all, burns this attempt now, so the answer says so at once. */
    const forAddress = await bump(env, "guess", here, HOUR);
    const fromNetwork = await bump(env, "guess-net", net, HOUR);
    if (forAddress >= GUESSES_PER_HOUR || fromNetwork >= GUESSES_PER_NETWORK) return burned();
    const left = CODE_TRIES - row.tries - 1;
    return left > 0 ? { ok: false, why: "wrong", left } : { ok: false, why: "burned" };
  }
  const used = await db.prepare("UPDATE signins SET used_at = ?, password_hash = NULL WHERE id = ? AND used_at IS NULL")
    .bind(t, row.id).run();
  if (used.meta.changes !== 1) return { ok: false, why: "expired" };
  return { ok: true, row };
}

/* ---------- sessions ---------- */

/* A new session for someone who has just signed in, ending the one the
   browser had. Returns the cookie's value, which is kept nowhere. The
   statements come back unrun so the caller writes its event in the same
   batch.

   coded: whether a code was typed to open it, which makes it fresh. A
   password alone is not a fresh code (authed_at 0): what needs one still
   needs one, so a password that leaked opens the account but cannot
   approve a terminal, mint a token or do anything else fresh() guards. */
export async function openSession(env, { user, org, previous = null, coded = true }) {
  const db = env.LIST;
  const t = now();
  const value = randomToken();
  const statements = [
    db.prepare(`INSERT INTO sessions (id, user_id, org_id, created_at, seen_at, authed_at, expires_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)`)
      .bind(await sha256(value), user, org, t, t, coded ? t : 0, t + SESSION_MAX),
  ];
  if (previous) statements.push(db.prepare("DELETE FROM sessions WHERE id = ?").bind(await sha256(previous)));
  return { value, statements };
}

/* The signed-in person behind a request, or null: { id, user, email,
   authed_at, org: { id, name, personal, role } }. Membership is read again
   every time, so a removed member is out on their next request. */
export async function current(request, env) {
  const value = readCookie(request, SESSION_COOKIE);
  if (!value) return null;
  const db = env.LIST;
  const t = now();
  const id = await sha256(value);
  const row = await db.prepare(
    `SELECT s.user_id, s.org_id, s.seen_at, s.authed_at, s.expires_at, u.email
     FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.id = ?`).bind(id).first();
  if (!row) return null;
  if (row.expires_at <= t || row.seen_at <= t - SESSION_IDLE) {
    await db.prepare("DELETE FROM sessions WHERE id = ?").bind(id).run();
    return null;
  }
  const org = await orgFor(env, row.user_id, row.org_id);
  if (!org) return null;
  if (org.id !== row.org_id || row.seen_at <= t - SEEN_EVERY) {
    await db.prepare("UPDATE sessions SET seen_at = ?, org_id = ? WHERE id = ?").bind(t, org.id, id).run();
  }
  return { id, user: row.user_id, email: row.email, authed_at: row.authed_at, org };
}

/* For what needs a code typed in the last 15 minutes: approving a
   terminal, a CI token, billing, claiming, members, deleting. */
export const fresh = (who) => Boolean(who) && who.authed_at > now() - FRESH_FOR;
