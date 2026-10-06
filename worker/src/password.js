/* Passwords on account.ranwhat.com: how one is kept, checked and judged,
 * and how a new one reaches an account.
 *
 * Kept. PBKDF2-HMAC-SHA256 through WebCrypto, with a 16-byte random salt,
 * stored as "pbkdf2-sha256$<iterations>$<salt>$<hash>", salt and hash in
 * base64url. Each hash carries its own count, so the count can be raised
 * later: older hashes still verify, and needsRehash() says which to hash
 * again when their owner next signs in with the password. The password is
 * NFKC-normalised first (NIST SP 800-63B), so the same characters typed on
 * another keyboard or system are the same password.
 *
 * Judged. 12 to 128 characters, counted as code points, and nothing asked
 * of its make-up: no "a digit and a symbol", which make passwords harder
 * to remember and no harder to guess. A password that has appeared in a
 * breach is refused, checked with Have I Been Pwned's range API: only the
 * first five hex digits of its SHA-1 leave the Worker, with Add-Padding so
 * that not even the size of the answer depends on them. When that service
 * is slow or down the check is skipped, with a warning in the log, so that
 * signing up never depends on it.
 *
 * Reaching an account. The password typed at sign-up is hashed and held
 * only in the signins row of the browser that asked (session.js), next to
 * the code mailed to the address, and written to credentials only when
 * that browser types that code (dashboard.js). Someone who signs up with
 * another person's address and a password of their own therefore gains
 * nothing: the code goes to the address, and without it no password is
 * attached. The address's owner signs in, or chooses a password, in their
 * own browser, whose attempt never holds anyone else's hash.
 *
 * Signing in with one. checkPassword() gives one answer for a wrong
 * password, an address with no password and an address with no account,
 * after the same work: an address without a hash is checked against a
 * decoy, one PBKDF2 run at the current count, as a real one would be. An
 * address gets five tries in fifteen minutes, counted before the hash so
 * that tries at once cannot slip past, and started again by a right
 * password or a typed code. Ten wrong passwords from one network (an IPv6
 * /64, an IPv4 address) in those fifteen minutes pause password sign-in
 * for that network, whatever the addresses: that caps spraying one
 * password across many accounts without letting anyone pause it for
 * everyone else. Either way the emailed code still works, and is then the
 * way in. Both counts are kept whether or not an account exists, so
 * neither says anything about one.
 */
import { HOUR, event, now } from "./accounts.js";
import { b64url, bump, forget, network, peek } from "./session.js";

/* OWASP's 2023 count for PBKDF2-HMAC-SHA256. PBKDF2_ITERATIONS sets
   another, for two limits on Workers:
   - Workers' WebCrypto refuses PBKDF2 above 100,000 iterations
     (NotSupportedError, "iteration counts above 100000 are not
     supported"), on the Free and the Paid plan alike, and only in
     production: Node, wrangler dev and Miniflare all run 600,000. Until
     Cloudflare lifts it, production needs PBKDF2_ITERATIONS = "100000",
     or no password can be set (the sign-up page then says passwords are
     not available, and the emailed code still works).
   - CPU: 100,000 iterations take about 10 ms, 600,000 about 50 ms. Workers
     Free allows 10 ms of CPU a request, so even the lower count may not
     fit, and the owner may need Workers Paid for passwords at all.
   A value that is not a whole number from 1,000 to 10,000,000 is ignored. */
export const ITERATIONS = 600000;
const MIN_ITERATIONS = 1000;
const MAX_ITERATIONS = 10000000;

export const MIN_LENGTH = 12;
export const MAX_LENGTH = 128;

const PWNED = "https://api.pwnedpasswords.com/range/";
const PWNED_WAIT = 2000;              // ms; after this the check is skipped

/* Hashing costs real CPU, so one network may ask for a password to be
   hashed this many times an hour, as it may ask for this many codes. */
const HASHES_PER_NETWORK = 20;

const enc = new TextEncoder();

export function iterations(env) {
  const n = Number(String(env.PBKDF2_ITERATIONS ?? "").trim());
  return Number.isInteger(n) && n >= MIN_ITERATIONS && n <= MAX_ITERATIONS ? n : ITERATIONS;
}

/* What is hashed and judged: the password as NFKC code points. */
const normal = (password) => String(password).normalize("NFKC");

function unb64url(text) {
  const s = atob(text.replace(/-/g, "+").replace(/_/g, "/"));
  return Uint8Array.from(s, (c) => c.charCodeAt(0));
}

async function derive(password, salt, count) {
  const key = await crypto.subtle.importKey("raw", enc.encode(normal(password)), "PBKDF2", false, ["deriveBits"]);
  return new Uint8Array(await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations: count }, key, 256));
}

/* 16 bytes of salt are 22 base64url characters, 32 of hash 43. */
const STORED = /^pbkdf2-sha256\$([1-9][0-9]{0,7})\$([A-Za-z0-9_-]{22})\$([A-Za-z0-9_-]{43})$/;

function parse(stored) {
  const m = typeof stored === "string" ? STORED.exec(stored) : null;
  if (!m || Number(m[1]) > MAX_ITERATIONS) return null;
  return { count: Number(m[1]), salt: unb64url(m[2]), hash: unb64url(m[3]) };
}

export const isPasswordHash = (stored) => parse(stored) !== null;

export async function hashPassword(env, password) {
  const count = iterations(env);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const hash = await derive(password, salt, count);
  return `pbkdf2-sha256$${count}$${b64url(salt)}$${b64url(hash)}`;
}

/* Whether a password is the one a stored hash was made from. The two
   hashes are compared in full, whatever byte differs first. false for
   anything that is not a hash this file made. */
export async function verifyPassword(stored, password) {
  const kept = parse(stored);
  if (!kept || typeof password !== "string" || password.length > 4096) return false;
  const got = await derive(password, kept.salt, kept.count);
  let diff = got.length ^ kept.hash.length;
  for (let i = 0; i < kept.hash.length; i++) diff |= got[i] ^ kept.hash[i];
  return diff === 0;
}

/* True when a hash was made with fewer iterations than are set now (or is
   not one this file can read): hash the password again, once it has just
   been verified. */
export function needsRehash(env, stored) {
  const kept = parse(stored);
  return !kept || kept.count < iterations(env);
}

/* ---------- judging a new password ---------- */

/* What is wrong with a password someone wants to set, in a sentence for the
   form, or null when nothing is. fetch is the one the check against Have I
   Been Pwned uses; tests pass their own. */
export async function passwordProblem(env, password, { fetch: get = globalThis.fetch, wait = PWNED_WAIT } = {}) {
  const p = typeof password === "string" ? normal(password) : "";
  const length = [...p].length;
  if (length < MIN_LENGTH) return `A password needs at least ${MIN_LENGTH} characters.`;
  if (length > MAX_LENGTH) return `A password can have at most ${MAX_LENGTH} characters.`;
  if (await pwned(p, get, wait)) {
    return "That password is in a known data breach, so it is among the first that attackers try. Choose another.";
  }
  return null;
}

class Late extends Error {
  name = "TimeoutError";
}

/* Whether Have I Been Pwned has seen this password. Only the first five hex
   digits of its SHA-1 are sent; the rest is looked for in the answer. With
   padding, the answer also lists made-up suffixes with a count of 0, which
   are not breaches. Any failure, or no answer within `wait` ms, is a
   warning and a pass. The warning names what failed, never the password
   or any part of its hash. */
async function pwned(password, get, wait) {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-1", enc.encode(password)));
  const hex = [...digest].map((b) => b.toString(16).padStart(2, "0")).join("").toUpperCase();
  const rest = hex.slice(5);
  const stop = new AbortController();
  let timer;
  const late = new Promise((_, reject) => {
    timer = setTimeout(() => {
      stop.abort();
      reject(new Late());
    }, wait);
  });
  let text;
  try {
    const res = await Promise.race([get(PWNED + hex.slice(0, 5), {
      headers: { "add-padding": "true", "user-agent": "ranwhat-account" },
      signal: stop.signal,
    }), late]);
    if (!res.ok) {
      console.warn(`account pwned check: skipped, status ${res.status}`);
      return false;
    }
    text = await Promise.race([res.text(), late]);
  } catch (err) {
    const why = err instanceof Late || (err && err.name === "AbortError") ? "timeout" : (err && err.name) || "error";
    console.warn(`account pwned check: skipped, ${why}`);
    return false;
  } finally {
    clearTimeout(timer);
  }
  for (const line of String(text).split("\n")) {
    const [suffix, count] = line.trim().split(":");
    if (suffix === rest && Number(count) > 0) return true;
  }
  return false;
}

/* Counts one more hash for the request's network, and says whether it may
   go ahead. Asked before the breach check and the hash, which are what the
   limit protects. */
export async function hashAllowed(request, env) {
  return await bump(env, "hash-ip", network(request), HOUR) <= HASHES_PER_NETWORK;
}

/* ---------- signing in with one ---------- */

export const LOCKOUT = 15 * 60;          // the window both counts below are kept over
export const TRIES_PER_ADDRESS = 5;      // password tries for one address in it
export const WRONG_PER_NETWORK = 10;     // wrong passwords from one network, for any addresses, in it

/* What a password is checked against when the address has none: the
   current count, and a salt and hash of zero bytes. Never accepted, even
   in the impossible case that a password derives to it. */
const decoy = (env) => `pbkdf2-sha256$${iterations(env)}$${"A".repeat(22)}$${"A".repeat(43)}`;

/* The account an address belongs to, with its password hash if it has a
   usable one. */
async function holder(env, email) {
  return env.LIST.prepare(
    `SELECT u.id, c.hash FROM users u
     LEFT JOIN credentials c ON c.user_id = u.id AND c.kind = 'password'
     WHERE u.email = ?`).bind(email).first();
}

export async function passwordOf(env, user) {
  const row = await env.LIST.prepare("SELECT hash FROM credentials WHERE user_id = ? AND kind = 'password'")
    .bind(user).first();
  return row && isPasswordHash(row.hash) ? row.hash : null;
}

/* Whether `typed` is the password of the account at `email`, under the
   limits. { ok: true, user, stored } or { ok: false, why }:
     "locked"       this address's tries, or this network's wrong
                    passwords, are used up for now: an emailed code is the
                    way in;
     "network"      the request's network has asked for its hashes;
     "unavailable"  the runtime refused to hash (PBKDF2_ITERATIONS);
     "wrong"        anything else, the same whatever the reason.
   A right one starts the address's tries again; a wrong one counts
   towards the network's. */
export async function checkPassword(request, env, email, typed) {
  const net = network(request);
  if (await peek(env, "pw-wrong", net, LOCKOUT) >= WRONG_PER_NETWORK) return { ok: false, why: "locked" };
  const tries = await bump(env, "pw-tries", email, LOCKOUT);
  if (tries > TRIES_PER_ADDRESS) return { ok: false, why: "locked" };
  if (!await hashAllowed(request, env)) return { ok: false, why: "network" };
  const row = await holder(env, email);
  const real = Boolean(row) && isPasswordHash(row.hash);
  let right;
  try {
    right = await verifyPassword(real ? row.hash : decoy(env), typeof typed === "string" ? typed : "");
  } catch (err) {
    console.log(`account password check: ${err.name || "error"}`);
    return { ok: false, why: "unavailable" };
  }
  if (real && right) {
    await (await unlock(env, email)).run();
    return { ok: true, user: row.id, stored: row.hash };
  }
  await bump(env, "pw-wrong", net, LOCKOUT);
  return { ok: false, why: tries >= TRIES_PER_ADDRESS ? "locked" : "wrong" };
}

/* The statement that gives an address its password tries back: after a
   right password, and after a typed code, which is how a locked address
   gets in. */
export const unlock = (env, email) => forget(env, "pw-tries", email);

/* The statement that keeps a just-verified password hashed again at the
   current count, when its hash was made with fewer (needsRehash). The new
   hash is written only if the stored one is still the one verified. */
export async function rehashed(env, { user, stored, typed }) {
  if (!needsRehash(env, stored)) return [];
  let hash;
  try {
    hash = await hashPassword(env, typed);
  } catch (err) {
    console.log(`account password rehash: ${err.name || "error"}`);
    return [];
  }
  return [env.LIST.prepare(
    "UPDATE credentials SET hash = ?, updated_at = ? WHERE user_id = ? AND kind = 'password' AND hash = ?")
    .bind(hash, now(), user, stored)];
}

/* ---------- attaching one ---------- */

/* The statements that make `hash` the account's password, with the event
   that records it, for the caller's batch. Called only once the person
   has shown the address is theirs (a code typed in the browser that chose
   the password) or that the account is (a fresh code or the current
   password). A password the account already had is replaced: with
   `reset`, the event says it was reset by code. */
export async function attachPassword(env, { user, org = null, hash, reset = false }) {
  const db = env.LIST;
  const t = now();
  const had = await db.prepare("SELECT 1 AS yes FROM credentials WHERE user_id = ? AND kind = 'password'")
    .bind(user).first();
  return [
    db.prepare(`INSERT INTO credentials (user_id, kind, hash, created_at, updated_at) VALUES (?, 'password', ?, ?, ?)
                ON CONFLICT(user_id, kind) DO UPDATE SET hash = excluded.hash, updated_at = excluded.updated_at`)
      .bind(user, hash, t, t),
    event(db, { org, user, what: !had ? "password_added" : reset ? "password_reset" : "password_changed" }),
  ];
}

/* The statements that take an account's password away, with the event. */
export function detachPassword(env, { user, org = null }) {
  const db = env.LIST;
  return [
    db.prepare("DELETE FROM credentials WHERE user_id = ? AND kind = 'password'").bind(user),
    event(db, { org, user, what: "password_removed" }),
  ];
}

/* How many ways into an account there are besides its password. The
   emailed code is always one, so today a password can always go; Google,
   GitHub and passkeys add to it as they arrive. */
export async function otherWaysIn(env, user) {
  const row = await env.LIST.prepare(
    `SELECT (SELECT count(*) FROM identities WHERE user_id = ? AND provider != 'email')
          + (SELECT count(*) FROM passkeys WHERE user_id = ?) AS n`).bind(user, user).first();
  return 1 + row.n;
}
