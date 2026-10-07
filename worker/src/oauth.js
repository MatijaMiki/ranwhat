/* Signing in with Google or GitHub on account.ranwhat.com: OAuth 2.0's
 * authorization code flow with PKCE, written here on WebCrypto alone, and
 * the rule for which account a provider's answer opens. The pages and
 * routes are dashboard.js's; this file is the protocol.
 *
 * Leaving. GET /auth/<provider> (or, to link a provider to the account
 * someone is signed in to, a POST from the account page) starts a flow:
 * the browser gets __Host-rw_oauth, 32 random bytes, and D1 keeps the
 * SHA-256 of that cookie as the flow's id with the SHA-256 of a random
 * state, of a random nonce (Google), and of the PKCE verifier. The verifier
 * itself is an HMAC of the cookie under ACCOUNT_SECRET, so it is kept
 * nowhere: only the browser that holds the cookie can have it sent. The
 * provider gets the state, the nonce and the verifier's S256 challenge.
 *
 * Coming back. /auth/<provider>/callback reads the flow by the cookie and
 * uses it in one UPDATE that has to change exactly one row, whatever comes
 * after: a flow works once, for ten minutes, in the browser that started
 * it. Then the state must match, the code is exchanged with the verifier,
 * and the provider's answer is checked:
 *   Google  the id_token is verified here: RS256 under a key from Google's
 *           JWKS (kept in memory for its max-age), the issuer, the audience
 *           (our client id), its times within a minute's skew, and the
 *           nonce. sub is the subject; email and email_verified come from
 *           the token.
 *   GitHub  the numeric user id is the subject, and the only address taken
 *           is the one GitHub marks primary and verified. The access token
 *           is used for those two calls and kept nowhere.
 *
 * Which account. A provider's own id, once linked, signs in its account
 * whatever address the provider reports now. Otherwise the provider must
 * say the address is verified, and then the address is the account
 * (userForVerifiedEmail() in accounts.js): an account with it gets this
 * way in linked to it, and an address without one gets an account, as the
 * emailed code would make. An address the provider does not vouch for
 * never makes or joins an account: the emailed code is the way in then.
 * A signed-in person can also link a provider from the account page, with
 * a fresh code, under the same rule.
 *
 * A provider without its client id and secret in the environment is not
 * offered and its routes answer 404.
 */
import { sha256 } from "./auth.js";
import { same } from "./list.js";
import { ACCOUNT_ORIGIN, DAY, HOUR, event, now, userForVerifiedEmail } from "./accounts.js";
import { address, b64url, bump, mac, network, randomToken, readCookie, setCookie } from "./session.js";

export const OAUTH_COOKIE = "__Host-rw_oauth";
export const FLOW_FOR = 10 * 60;        // a flow works this long
export const STARTS_PER_NETWORK = 30;   // flows one network may start an hour
export const SKEW = 60;                 // seconds our clock and Google's may differ by
const WAIT = 10000;                     // milliseconds for each call to a provider
const AGENT = "ranwhat-account";        // GitHub's API refuses a request without one

export const GOOGLE_TOKEN = "https://oauth2.googleapis.com/token";
export const GOOGLE_KEYS = "https://www.googleapis.com/oauth2/v3/certs";
export const GOOGLE_ISSUERS = new Set(["accounts.google.com", "https://accounts.google.com"]);
export const GITHUB_TOKEN = "https://github.com/login/oauth/access_token";
export const GITHUB_USER = "https://api.github.com/user";
export const GITHUB_EMAILS = "https://api.github.com/user/emails";

/* origin: where the browser is sent, which the account page's
   form-action has to allow for its link forms (ui.js). */
export const PROVIDERS = {
  google: {
    name: "Google",
    id: "GOOGLE_CLIENT_ID",
    secret: "GOOGLE_CLIENT_SECRET",
    authorize: "https://accounts.google.com/o/oauth2/v2/auth",
    origin: "https://accounts.google.com",
    scope: "openid email",
    extra: { prompt: "select_account" },
  },
  github: {
    name: "GitHub",
    id: "GITHUB_CLIENT_ID",
    secret: "GITHUB_CLIENT_SECRET",
    authorize: "https://github.com/login/oauth/authorize",
    origin: "https://github.com",
    scope: "read:user user:email",
    extra: {},
  },
};

const set = (value) => typeof value === "string" && value.trim().length > 0;

/* Whether `provider` is one we know and its client id and secret are set. */
export const configured = (env, provider) =>
  Object.hasOwn(PROVIDERS, provider) && set(env[PROVIDERS[provider].id]) && set(env[PROVIDERS[provider].secret]);

/* The providers offered, in the order they are shown. */
export const offered = (env) => Object.keys(PROVIDERS).filter((p) => configured(env, p));

/* Exactly what is registered with each provider. */
export const redirectUri = (provider) => `${ACCOUNT_ORIGIN}/auth/${provider}/callback`;

const enc = new TextEncoder();

/* The PKCE verifier for a flow: 43 base64url characters, from the cookie
   and ACCOUNT_SECRET, so that nothing stored can give it. */
const verifierFor = (env, cookie) => mac(env, `pkce:${cookie}`);

async function s256(text) {
  return b64url(new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(text))));
}

/* A refusal the provider's answer earned, as opposed to a provider that
   could not be reached. */
class Refused extends Error {
  constructor(why) {
    super(why);
    this.why = why;
  }
}

/* ---------- leaving for the provider ---------- */

/* Starts a flow. Returns { to, cookie }: the provider's authorization URL
   and the __Host-rw_oauth cookie, or { refused: "network" } when this
   network has started too many this hour. A flow the browser had is
   cancelled.

   purpose 'link': `user`, signed in with the session whose id is
   `session`, is adding this provider; the callback checks it is still
   that session. */
export async function begin(request, env, { provider, purpose = "signin", user = null, session = null, next = "/" }) {
  if (await bump(env, "oauth-start", network(request), HOUR) > STARTS_PER_NETWORK) return { refused: "network" };
  const p = PROVIDERS[provider];
  const db = env.LIST;
  const t = now();
  const cookie = randomToken();
  const state = randomToken();
  const nonce = provider === "google" ? randomToken() : null;
  const verifier = await verifierFor(env, cookie);
  const statements = [
    db.prepare(`INSERT INTO oauth_flows (id, provider, purpose, state_hash, nonce_hash, verifier_hash, user_id,
                                         session_id, next, created_at, expires_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
      .bind(await sha256(cookie), provider, purpose, await sha256(state), nonce ? await sha256(nonce) : null,
        await sha256(verifier), user, session, next, t, t + FLOW_FOR),
  ];
  const previous = readCookie(request, OAUTH_COOKIE);
  if (previous) {
    statements.push(db.prepare("UPDATE oauth_flows SET used_at = ? WHERE id = ? AND used_at IS NULL")
      .bind(t, await sha256(previous)));
  }
  await db.batch(statements);
  const to = new URL(p.authorize);
  const query = {
    client_id: env[p.id].trim(),
    redirect_uri: redirectUri(provider),
    response_type: "code",
    scope: p.scope,
    state,
    code_challenge: await s256(verifier),
    code_challenge_method: "S256",
    ...(nonce ? { nonce } : {}),
    ...p.extra,
  };
  for (const [k, v] of Object.entries(query)) to.searchParams.set(k, v);
  return { to: to.href, cookie: setCookie(OAUTH_COOKIE, cookie, FLOW_FOR) };
}

/* ---------- coming back ---------- */

/* The provider's answer, checked. { ok: true, flow, profile: { subject,
   email, verified } } or { ok: false, why, flow }:
     "expired"      no flow for this browser, or one already used or out
                    of date (flow is then null);
     "cancelled"    the provider says the person said no;
     "mismatch"     the state, the code or the verifier is not this flow's;
     "invalid"      the provider refused the code, or its answer did not
                    pass the checks above;
     "unavailable"  the provider could not be asked. */
export async function finish(request, env, provider, url) {
  const cookie = readCookie(request, OAUTH_COOKIE);
  if (!cookie) return { ok: false, why: "expired", flow: null };
  const db = env.LIST;
  const t = now();
  const id = await sha256(cookie);
  const flow = await db.prepare("SELECT * FROM oauth_flows WHERE id = ?").bind(id).first();
  if (!flow || flow.provider !== provider) return { ok: false, why: "expired", flow: null };
  const used = await db.prepare(
    "UPDATE oauth_flows SET used_at = ? WHERE id = ? AND used_at IS NULL AND expires_at > ?").bind(t, id, t).run();
  if (used.meta.changes !== 1) return { ok: false, why: "expired", flow: null };

  const q = url.searchParams;
  if (q.has("error")) return { ok: false, why: "cancelled", flow };
  const state = q.get("state");
  const code = q.get("code");
  if (!state || state.length > 512 || !same(await sha256(state), flow.state_hash)) {
    return { ok: false, why: "mismatch", flow };
  }
  if (!code || code.length > 2048) return { ok: false, why: "mismatch", flow };
  const verifier = await verifierFor(env, cookie);
  if (!same(await sha256(verifier), flow.verifier_hash)) return { ok: false, why: "mismatch", flow };
  try {
    const profile = provider === "google"
      ? await google(env, { code, verifier, nonceHash: flow.nonce_hash })
      : await github(env, { code, verifier });
    return { ok: true, flow, profile };
  } catch (err) {
    if (err instanceof Refused) return { ok: false, why: err.why, flow };
    console.log(`account ${provider} sign-in: ${err.name || "error"}`);
    return { ok: false, why: "unavailable", flow };
  }
}

const call = (url, init = {}) => fetch(url, { ...init, signal: AbortSignal.timeout(WAIT) });

/* A provider's 5xx is its outage, not a verdict on the code. */
function judged(res) {
  if (res.status >= 500) throw new Error(`provider ${res.status}`);
  return res.ok;
}

async function body(res) {
  try {
    return await res.json();
  } catch {
    return null;
  }
}

async function google(env, { code, verifier, nonceHash }) {
  const res = await call(GOOGLE_TOKEN, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      client_id: env.GOOGLE_CLIENT_ID.trim(),
      client_secret: env.GOOGLE_CLIENT_SECRET.trim(),
      redirect_uri: redirectUri("google"),
      code_verifier: verifier,
    }).toString(),
  });
  const ok = judged(res);
  const answer = await body(res);
  if (!ok || !answer) throw new Refused("invalid");
  const claims = await verifyIdToken(env, answer.id_token, { nonceHash });
  return {
    subject: claims.sub,
    email: typeof claims.email === "string" ? claims.email : null,
    verified: claims.email_verified === true || claims.email_verified === "true",
  };
}

async function github(env, { code, verifier }) {
  const res = await call(GITHUB_TOKEN, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json", "user-agent": AGENT },
    body: new URLSearchParams({
      client_id: env.GITHUB_CLIENT_ID.trim(),
      client_secret: env.GITHUB_CLIENT_SECRET.trim(),
      code,
      redirect_uri: redirectUri("github"),
      code_verifier: verifier,
    }).toString(),
  });
  const ok = judged(res);
  const answer = await body(res);
  /* GitHub answers a bad code with 200 and an error field. */
  if (!ok || !answer || typeof answer.access_token !== "string" || !answer.access_token) throw new Refused("invalid");
  const headers = {
    accept: "application/vnd.github+json",
    authorization: `Bearer ${answer.access_token}`,
    "user-agent": AGENT,
    "x-github-api-version": "2022-11-28",
  };
  const [who, addresses] = await Promise.all([call(GITHUB_USER, { headers }), call(GITHUB_EMAILS, { headers })]);
  if (!judged(who)) throw new Refused("invalid");
  const me = await body(who);
  if (!me || !Number.isSafeInteger(me.id) || me.id <= 0) throw new Refused("invalid");
  /* Without user:email granted the list is refused: then there is no
     verified address, which is an answer, not an outage. */
  const list = judged(addresses) ? await body(addresses) : [];
  const primary = Array.isArray(list)
    ? list.find((e) => e && e.primary === true && e.verified === true && typeof e.email === "string")
    : null;
  return { subject: String(me.id), email: primary ? primary.email : null, verified: Boolean(primary) };
}

/* ---------- Google's id_token ---------- */

function bytesOf(text) {
  const raw = atob(text.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((text.length + 3) % 4));
  return Uint8Array.from(raw, (c) => c.charCodeAt(0));
}

function objectOf(segment) {
  try {
    const value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytesOf(segment)));
    return value && typeof value === "object" && !Array.isArray(value) ? value : null;
  } catch {
    return null;
  }
}

/* Google's signing keys by kid, until the time their max-age gives. */
let keys = { byKid: new Map(), until: 0, fetched: 0 };

/* For tests: start from no keys. */
export function forgetKeys() {
  keys = { byKid: new Map(), until: 0, fetched: 0 };
}

async function loadKeys() {
  const res = await call(GOOGLE_KEYS, { headers: { accept: "application/json" } });
  if (!res.ok) throw new Error(`keys ${res.status}`);
  const answer = await res.json();
  const byKid = new Map();
  for (const k of Array.isArray(answer && answer.keys) ? answer.keys : []) {
    if (!k || k.kty !== "RSA" || typeof k.kid !== "string" || typeof k.n !== "string" || typeof k.e !== "string" ||
        (k.use !== undefined && k.use !== "sig") || (k.alg !== undefined && k.alg !== "RS256")) continue;
    try {
      byKid.set(k.kid, await crypto.subtle.importKey("jwk", { kty: "RSA", n: k.n, e: k.e, alg: "RS256", ext: true },
        { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]));
    } catch {
      /* A key that will not import verifies nothing. */
    }
  }
  const control = res.headers.get("cache-control") || "";
  const maxAge = /(?:^|[,\s])max-age=(\d+)/i.exec(control);
  const age = Number(res.headers.get("age")) || 0;
  const t = now();
  const fresh = /no-store|no-cache/i.test(control) || !maxAge ? 0 : Math.max(0, Number(maxAge[1]) - age);
  keys = { byKid, until: t + Math.min(fresh, DAY), fetched: t };
}

/* The key for `kid`: from memory while its max-age lasts, and fetched
   again when it has run out, or when Google has rotated to a key we do not
   have yet (at most once a minute). */
async function keyFor(kid) {
  const t = now();
  if (t >= keys.until || (!keys.byKid.has(kid) && t - keys.fetched >= 60)) await loadKeys();
  return keys.byKid.get(kid) || null;
}

/* The claims of a Google id_token that passes every check, or a
   Refused("invalid"). Checked even though it came straight from Google's
   token endpoint over TLS: this is the check that the answer is for this
   client, this flow, and now. */
export async function verifyIdToken(env, token, { nonceHash, clientId = (env.GOOGLE_CLIENT_ID || "").trim() } = {}) {
  const invalid = new Refused("invalid");
  if (typeof token !== "string" || token.length > 8192) throw invalid;
  const parts = token.split(".");
  if (parts.length !== 3 || !parts.every((p) => /^[A-Za-z0-9_-]+$/.test(p))) throw invalid;
  const header = objectOf(parts[0]);
  const claims = objectOf(parts[1]);
  if (!header || !claims || header.alg !== "RS256" || typeof header.kid !== "string" || "crit" in header) throw invalid;
  const key = await keyFor(header.kid);
  if (!key) throw invalid;
  let signature;
  try {
    signature = bytesOf(parts[2]);
  } catch {
    throw invalid;
  }
  if (!await crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, signature, enc.encode(`${parts[0]}.${parts[1]}`))) {
    throw invalid;
  }
  const t = now();
  const audience = claims.aud === clientId ||
    (Array.isArray(claims.aud) && claims.aud.includes(clientId) && claims.azp === clientId);
  if (!clientId || !audience || (claims.azp !== undefined && claims.azp !== clientId)) throw invalid;
  if (!GOOGLE_ISSUERS.has(claims.iss)) throw invalid;
  if (!Number.isFinite(claims.exp) || !Number.isFinite(claims.iat)) throw invalid;
  if (claims.exp <= t - SKEW || claims.iat > t + SKEW || claims.iat < t - FLOW_FOR - SKEW) throw invalid;
  if (typeof nonceHash !== "string" || typeof claims.nonce !== "string" ||
      !same(await sha256(claims.nonce), nonceHash)) throw invalid;
  if (typeof claims.sub !== "string" || !claims.sub || claims.sub.length > 255) throw invalid;
  return claims;
}

/* ---------- which account ---------- */

async function owner(env, provider, subject) {
  const row = await env.LIST.prepare(
    `SELECT i.user_id FROM identities i JOIN users u ON u.id = i.user_id
     WHERE i.provider = ? AND i.provider_subject = ?`).bind(provider, subject).first();
  return row ? row.user_id : null;
}

/* The address a provider vouched for, as an account may hold it, or null. */
const vouched = (profile) => (profile.verified ? address(profile.email) : null);

/* Signing in with a provider. { user, what } where what is 'signin' (this
   way in was already linked), 'linked' (the provider's verified address
   is an account's, which this way in now opens too) or 'signup' (a new
   account, its organisation and this way in), or { refused: "unverified" }
   when the provider vouched for no address we can use. */
export async function arrive(env, provider, profile) {
  const db = env.LIST;
  const known = await owner(env, provider, profile.subject);
  if (known) {
    const t = now();
    await db.batch([
      db.prepare("UPDATE users SET signed_in_at = ? WHERE id = ?").bind(t, known),
      db.prepare("UPDATE identities SET used_at = ? WHERE provider = ? AND provider_subject = ?")
        .bind(t, provider, profile.subject),
    ]);
    return { user: known, what: "signin" };
  }
  const email = vouched(profile);
  if (!email) return { refused: "unverified" };
  const found = await userForVerifiedEmail(env, { email, provider, subject: profile.subject });
  return { user: found.id, what: found.created ? "signup" : "linked" };
}

/* A signed-in person linking a provider to their account. { what:
   'linked' | 'already' } or { refused }:
     "unverified"  the provider vouched for no address;
     "taken"       this way in already opens another account, and stays
                   with it;
     "address"     the address it vouched for is another account's, which
                   this way in would join on its own: it is that account's
                   to link. */
export async function attach(env, { user, org, provider, profile }) {
  const db = env.LIST;
  const known = await owner(env, provider, profile.subject);
  if (known) return known === user ? { what: "already" } : { refused: "taken" };
  const email = vouched(profile);
  if (!email) return { refused: "unverified" };
  const holder = await db.prepare("SELECT id FROM users WHERE email = ?").bind(email).first();
  if (holder && holder.id !== user) return { refused: "address" };
  const t = now();
  const added = await db.prepare(
    `INSERT INTO identities (provider, provider_subject, user_id, verified_email, created_at, used_at)
     VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(provider, provider_subject) DO NOTHING`)
    .bind(provider, profile.subject, user, email, t, t).run();
  if (added.meta.changes !== 1) {
    return await owner(env, provider, profile.subject) === user ? { what: "already" } : { refused: "taken" };
  }
  await event(db, { org, user, what: `linked_${provider}` }).run();
  return { what: "linked" };
}

/* The Google and GitHub ways into an account, oldest first. */
export async function linked(env, user) {
  const { results } = await env.LIST.prepare(
    `SELECT provider, provider_subject, verified_email, created_at FROM identities
     WHERE user_id = ? AND provider IN ('google', 'github') ORDER BY created_at, provider_subject`).bind(user).all();
  return results;
}

/* The statements that take one away, with the event, for the caller's
   batch; nothing when it is not this account's. */
export async function detach(env, { user, org, provider, subject }) {
  const db = env.LIST;
  const mine = await db.prepare(
    "SELECT 1 AS yes FROM identities WHERE provider = ? AND provider_subject = ? AND user_id = ?")
    .bind(provider, subject, user).first();
  if (!mine) return [];
  return [
    db.prepare("DELETE FROM identities WHERE provider = ? AND provider_subject = ? AND user_id = ?")
      .bind(provider, subject, user),
    event(db, { org, user, what: `unlinked_${provider}` }),
  ];
}
