/* Signing in with Google and GitHub (oauth.js), end to end through the
 * Worker over a real SQLite database. Google's token endpoint and JWKS,
 * GitHub's token endpoint and API, Resend and Turnstile are stand-ins; the
 * id_tokens are signed with an RSA key made here and served as Google's
 * JWKS.
 *
 * The cases this file is for: a callback that is not the one this browser
 * started (state, PKCE, nonce, replay, age), an id_token that is not
 * Google's or not for us, a provider's address that is not verified, or
 * that it verified once but is not the authority for (GitHub's always),
 * which must never make or join an account, and an unlinked provider
 * account, which must never link itself back.
 *
 *     node --test --test-timeout=60000 worker/test/oauth.test.mjs
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { d1 } from "./stand-ins.mjs";

const worker = (await import("../src/index.js")).default;
const { FRESH_FOR, formToken } = await import("../src/session.js");
const { FLOW_FOR, SKEW, STARTS_PER_NETWORK, forgetKeys, googleGivesOut } = await import("../src/oauth.js");
const { NOTICES_PER_USER_DAY, userForVerifiedEmail } = await import("../src/accounts.js");

const ORIGIN = "https://account.ranwhat.com";
const SECRET = "an-account-test-secret-" + "that-is-long-enough-0123456789";
const SESSION = "__Host-rw_session";
const OAUTH = "__Host-rw_oauth";
const FROM_PAGE = { "sec-fetch-site": "same-origin", origin: ORIGIN };
const MINUTE = 60;
const GOOGLE_ID = "1234567890-test" + ".apps.googleusercontent.com";
const GOOGLE_SECRET = "GOCSPX-" + "test-secret";
const GITHUB_ID = "Ov23" + "litestclient";
const GITHUB_SECRET = "github-" + "test-secret-0123";

/* The clock, which a test moves forward when it needs time to pass. */
const realNow = Date.now;
let skew = 0;
Date.now = () => realNow() + skew * 1000;
const later = (seconds) => { skew += seconds; };
const nowS = () => Math.floor(Date.now() / 1000);

const sha256 = (text) => createHash("sha256").update(text).digest("hex");
const s256 = (text) => createHash("sha256").update(text).digest("base64url");

/* ---------- Google's keys ---------- */

const { privateKey: KEY, publicKey: PUBLIC } = generateKeyPairSync("rsa", { modulusLength: 2048 });
const { privateKey: FORGER } = generateKeyPairSync("rsa", { modulusLength: 2048 });
const KID = "test-key-1";
const JWK = { ...PUBLIC.export({ format: "jwk" }), kid: KID, alg: "RS256", use: "sig" };

const part = (value) => Buffer.from(typeof value === "string" ? value : JSON.stringify(value)).toString("base64url");
function idToken(claims, { key = KEY, header = { alg: "RS256", kid: KID, typ: "JWT" } } = {}) {
  const input = `${part(header)}.${part(claims)}`;
  return `${input}.${sign("sha256", Buffer.from(input), key).toString("base64url")}`;
}

/* ---------- stand-ins ---------- */

/* Every service the Worker calls. A code is good once, and only with the
   verifier whose challenge it was given for, as the providers hold it.
   s.codes maps a code to what the provider says about the person. */
function services() {
  const s = { emails: [], calls: [], codes: new Map(), bodies: [], tokens: new Map(), keyFetches: 0,
              google: "up", github: "up", n: 0 };
  globalThis.fetch = async (url, init = {}) => {
    const u = new URL(String(url));
    const method = init.method || "GET";
    const headers = new Headers(init.headers);
    s.calls.push(`${method} ${u.hostname}${u.pathname}`);
    const json = (value, status = 200, extra = {}) =>
      new Response(JSON.stringify(value), { status, headers: { "content-type": "application/json", ...extra } });
    if (u.hostname === "challenges.cloudflare.com") {
      const m = /^solved:([a-z]+)$/.exec(JSON.parse(init.body).response);
      return json(m ? { success: true, hostname: "account.ranwhat.com", action: m[1] } : { success: false });
    }
    if (u.hostname === "api.resend.com") {
      s.emails.push(JSON.parse(init.body));
      return json({ id: `e${s.emails.length}` });
    }
    if (u.hostname === "api.pwnedpasswords.com") return new Response("", { status: 200 });
    if (`${u.hostname}${u.pathname}` === "www.googleapis.com/oauth2/v3/certs") {
      s.keyFetches += 1;
      return json({ keys: [JWK] }, 200, { "cache-control": "public, max-age=3600, must-revalidate" });
    }
    if (`${method} ${u.hostname}${u.pathname}` === "POST oauth2.googleapis.com/token") {
      if (s.google === "down") return json({ error: "internal" }, 503);
      const body = new URLSearchParams(init.body);
      s.bodies.push(body);
      assert.equal(headers.get("content-type"), "application/x-www-form-urlencoded");
      assert.equal(body.get("grant_type"), "authorization_code");
      assert.equal(body.get("client_id"), GOOGLE_ID);
      assert.equal(body.get("client_secret"), GOOGLE_SECRET);
      assert.equal(body.get("redirect_uri"), "https://account.ranwhat.com/auth/google/callback");
      const grant = s.codes.get(body.get("code"));
      if (!grant || grant.provider !== "google" || grant.used || s256(body.get("code_verifier")) !== grant.challenge) {
        return json({ error: "invalid_grant" }, 400);
      }
      grant.used = true;
      const t = nowS();
      /* A Google Workspace account on example.com unless a test says
         otherwise: Google is the authority for its address. */
      const claims = { iss: "https://accounts.google.com", azp: GOOGLE_ID, aud: GOOGLE_ID, sub: "1001",
                       email: "ana@example.com", email_verified: true, hd: "example.com", iat: t, exp: t + 3600,
                       nonce: grant.nonce, ...grant.claims };
      for (const k of Object.keys(claims)) if (claims[k] === undefined) delete claims[k];
      return json({ access_token: "ya29." + "test-access", expires_in: 3599, token_type: "Bearer",
                    scope: "openid https://www.googleapis.com/auth/userinfo.email",
                    id_token: grant.token || idToken(claims, grant) });
    }
    if (`${method} ${u.hostname}${u.pathname}` === "POST github.com/login/oauth/access_token") {
      if (s.github === "down") return json({ message: "unavailable" }, 502);
      const body = new URLSearchParams(init.body);
      s.bodies.push(body);
      assert.equal(headers.get("accept"), "application/json");
      assert.equal(body.get("client_id"), GITHUB_ID);
      assert.equal(body.get("client_secret"), GITHUB_SECRET);
      assert.equal(body.get("redirect_uri"), "https://account.ranwhat.com/auth/github/callback");
      const grant = s.codes.get(body.get("code"));
      if (!grant || grant.provider !== "github" || grant.used || s256(body.get("code_verifier")) !== grant.challenge) {
        return json({ error: "bad_verification_code", error_description: "The code passed is incorrect or expired." });
      }
      grant.used = true;
      const token = "gho_" + `TestAccessToken${++s.n}`;
      s.tokens.set(token, grant);
      return json({ access_token: token, token_type: "bearer", scope: "read:user,user:email" });
    }
    if (u.hostname === "api.github.com") {
      assert.equal(method, "GET");
      assert.ok(headers.get("user-agent"), "GitHub refuses a request without a User-Agent");
      const grant = s.tokens.get((headers.get("authorization") || "").replace(/^Bearer /, ""));
      if (!grant) return json({ message: "Bad credentials" }, 401);
      if (u.pathname === "/user") return json(grant.user || { id: 4242, login: "ana-codes" });
      if (u.pathname === "/user/emails") {
        if (grant.emailsStatus) return json({ message: "Not Found" }, grant.emailsStatus);
        return json(grant.emails || [{ email: "ana@example.com", primary: true, verified: true, visibility: "private" }]);
      }
    }
    throw new Error(`unexpected fetch ${method} ${url}`);
  };
  return s;
}

const env = (extra = {}) => ({
  LIST: d1(), RESEND_API_KEY: "re_" + "test_key", ACCOUNT_SECRET: SECRET, TURNSTILE_SECRET: "turnstile-" + "test",
  ACCOUNTS_ON: "1", PBKDF2_ITERATIONS: "1000",
  GOOGLE_CLIENT_ID: GOOGLE_ID, GOOGLE_CLIENT_SECRET: GOOGLE_SECRET,
  GITHUB_CLIENT_ID: GITHUB_ID, GITHUB_CLIENT_SECRET: GITHUB_SECRET,
  ...extra,
});

class Browser {
  constructor(e, { ip = "198.51.100.7" } = {}) {
    this.e = e;
    this.ip = ip;
    this.jar = new Map();
  }

  async send(path, { method = "GET", body, headers = {} } = {}) {
    const h = new Headers({ "cf-connecting-ip": this.ip, ...headers });
    if (this.jar.size) h.set("cookie", [...this.jar].map(([k, v]) => `${k}=${v}`).join("; "));
    const waits = [];
    const res = await worker.fetch(new Request(`${ORIGIN}${path}`, {
      method, headers: h, body: body === undefined ? undefined : new URLSearchParams(body).toString(),
    }), this.e, { waitUntil: (p) => waits.push(p) });
    await Promise.all(waits);
    for (const line of res.headers.getSetCookie()) {
      const [pair, ...attributes] = line.split("; ");
      const at = pair.indexOf("=");
      if (attributes.includes("Max-Age=0")) this.jar.delete(pair.slice(0, at));
      else this.jar.set(pair.slice(0, at), pair.slice(at + 1));
    }
    return { status: res.status, location: res.headers.get("location"), headers: res.headers, text: await res.text() };
  }

  get(path, headers = {}) {
    return this.send(path, { headers });
  }

  post(path, body, headers = FROM_PAGE) {
    return this.send(path, { method: "POST", body,
      headers: { "content-type": "application/x-www-form-urlencoded", ...headers } });
  }
}

function tokenFor(html, action, nth = 0) {
  const re = new RegExp(`<form method="post" action="${action}"[^>]*><input type="hidden" name="form" value="([^"]+)">`, "g");
  const all = [...html.matchAll(re)];
  assert.ok(all[nth], `no form for ${action}`);
  return all[nth][1];
}

const codeIn = (mail) => mail.text.match(/^ {4}([0-9A-Z]{4}-[0-9A-Z]{4})$/m)[1];

async function signInByCode(b, s, email) {
  const form = await b.get("/signin");
  await b.post("/signin", { form: tokenFor(form.text, "/signin"), email, next: "/",
                            "cf-turnstile-response": "solved:signin" });
  const page = await b.get("/signin/code");
  const done = await b.post("/signin/code", { form: tokenFor(page.text, "/signin/code"), code: codeIn(s.emails.at(-1)) });
  assert.equal(done.status, 303, done.text);
}

/* Leaves for the provider, from the sign-in page's link or (link) the
   account page's form, and reads what the browser was sent with. */
async function leave(b, provider, { link = false } = {}) {
  let res;
  if (link) {
    const home = await b.get("/");
    res = await b.post(`/auth/${provider}`, { form: tokenFor(home.text, `/auth/${provider}`) });
  } else {
    res = await b.get(`/auth/${provider}`);
  }
  assert.equal(res.status, 303, res.text);
  const to = new URL(res.location);
  const q = to.searchParams;
  return { res, to, state: q.get("state"), nonce: q.get("nonce"), challenge: q.get("code_challenge"), cookie: b.jar.get(OAUTH) };
}

/* The provider's side: the person said yes, and it sends the browser back
   with a code bound to the challenge (and nonce) it was given. */
function consent(s, provider, flow, what = {}) {
  const code = `code-${provider}-${++s.n}`;
  s.codes.set(code, { provider, challenge: flow.challenge, nonce: flow.nonce, ...what });
  return `/auth/${provider}/callback?${new URLSearchParams({ code, state: what.state ?? flow.state })}`;
}

async function viaProvider(b, s, provider, what = {}, options = {}) {
  const flow = await leave(b, provider, options);
  return { flow, res: await b.get(consent(s, provider, flow, what)) };
}

const rows = (e, sql, ...p) => e.LIST.sql.prepare(sql).all(...p).map((r) => ({ ...r }));
const count = (e, table) => e.LIST.sql.prepare(`SELECT count(*) AS n FROM ${table}`).get().n;
const tables = (e) => rows(e, "SELECT name FROM sqlite_master WHERE type = 'table'").map((r) => r.name);
const everything = (e) => JSON.stringify(tables(e).map((t) => rows(e, `SELECT * FROM ${t}`)));
const userOf = (e, email) => rows(e, "SELECT id FROM users WHERE email = ?", email)[0]?.id ?? null;
const identities = (e) => rows(e, "SELECT provider, provider_subject, user_id, verified_email FROM identities ORDER BY provider, provider_subject");
const eventsOf = (e, user) => rows(e, "SELECT event FROM auth_events WHERE user_id = ? ORDER BY id", user).map((r) => r.event);
const tokenCalls = (s) => s.calls.filter((c) => c.endsWith("/token") || c.endsWith("/access_token")).length;

/* Signed out: no session cookie, and the account page sends to /signin. */
async function signedOut(b) {
  assert.equal(b.jar.has(SESSION), false, "no session cookie");
  assert.equal((await b.get("/")).location, "/signin");
}

/* ---------- offered only when set up ---------- */

test("a provider without its client id and secret is not offered, and every /auth/ path of it answers 404", async () => {
  services();
  const none = env({ GOOGLE_CLIENT_ID: undefined, GITHUB_CLIENT_SECRET: "" });
  const b = new Browser(none);
  const page = await b.get("/signin");
  assert.equal(page.status, 200);
  assert.doesNotMatch(page.text, /Continue with/);
  for (const path of ["/auth/google", "/auth/google/callback?code=x&state=y", "/auth/github", "/auth/github/callback",
                      "/auth/nobody", "/auth/github/unlink"]) {
    assert.equal((await b.get(path)).status, 404, path);
    assert.equal((await b.post(path, {})).status, 404, `POST ${path}`);
  }
  assert.equal(count(none, "oauth_flows"), 0);

  const github = env({ GOOGLE_CLIENT_SECRET: undefined });
  const shown = await new Browser(github).get("/signin");
  assert.match(shown.text, /<a class="button" href="\/auth\/github">Continue with GitHub<\/a>/);
  assert.doesNotMatch(shown.text, /Continue with Google/);
  assert.equal((await new Browser(github).get("/auth/google")).status, 404);
  assert.equal((await new Browser(github).get("/auth/github")).status, 303);
});

test("the sign-in page offers both as plain links, with no script of ours and no change to its policy", async () => {
  services();
  const b = new Browser(env());
  const page = await b.get("/signin");
  assert.match(page.text, /<a class="button" href="\/auth\/google">Continue with Google<\/a>/);
  assert.match(page.text, /<a class="button" href="\/auth\/github">Continue with GitHub<\/a>/);
  assert.match(page.text, /keeps only that account's id and the address it has verified/);
  const scripts = page.text.match(/<script[^>]*>/g);
  assert.deepEqual(scripts, ['<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer>']);
  assert.match(page.headers.get("content-security-policy"), /form-action 'self'; /);
  const style = page.text.match(/<style>([\s\S]*?)<\/style>/)[1];
  assert.ok(page.headers.get("content-security-policy").includes(`'sha256-${createHash("sha256").update(style).digest("base64")}'`));
});

/* ---------- Google ---------- */

test("Google: PKCE, state and nonce leave with the browser, only their hashes stay, and a verified address makes the account", async () => {
  const s = services();
  const e = env();
  const b = new Browser(e);
  const flow = await leave(b, "google");
  assert.equal(`${flow.to.origin}${flow.to.pathname}`, "https://accounts.google.com/o/oauth2/v2/auth");
  const q = flow.to.searchParams;
  assert.equal(q.get("client_id"), GOOGLE_ID);
  assert.equal(q.get("redirect_uri"), "https://account.ranwhat.com/auth/google/callback");
  assert.equal(q.get("response_type"), "code");
  assert.equal(q.get("scope"), "openid email");
  assert.equal(q.get("code_challenge_method"), "S256");
  assert.match(flow.challenge, /^[A-Za-z0-9_-]{43}$/);
  assert.match(flow.state, /^[A-Za-z0-9_-]{43}$/);
  assert.match(flow.nonce, /^[A-Za-z0-9_-]{43}$/);
  assert.notEqual(flow.state, flow.nonce);
  const set = flow.res.headers.getSetCookie();
  assert.equal(set.length, 1);
  assert.match(set[0], /^__Host-rw_oauth=[A-Za-z0-9_-]{43}; Max-Age=600; Path=\/; Secure; HttpOnly; SameSite=Lax$/);
  assert.equal(flow.res.headers.get("cache-control"), "no-store");

  const [row] = rows(e, "SELECT * FROM oauth_flows");
  assert.equal(row.id, sha256(flow.cookie));
  assert.equal(row.state_hash, sha256(flow.state));
  assert.equal(row.nonce_hash, sha256(flow.nonce));
  assert.deepEqual([row.provider, row.purpose, row.user_id, row.session_id, row.next, row.used_at],
                   ["google", "signin", null, null, "/", null]);
  assert.equal(row.expires_at - row.created_at, FLOW_FOR);
  for (const secret of [flow.cookie, flow.state, flow.nonce]) assert.ok(!everything(e).includes(secret));

  const back = await b.get(consent(s, "google", flow));
  assert.equal(back.status, 303, back.text);
  assert.equal(back.location, "/");
  const verifier = s.bodies.at(-1).get("code_verifier");
  assert.match(verifier, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(s256(verifier), flow.challenge, "the verifier sent is the one challenged");
  assert.equal(row.verifier_hash, sha256(verifier));
  assert.ok(!everything(e).includes(verifier), "the verifier is kept nowhere");
  const cookies = back.headers.getSetCookie();
  assert.match(cookies[0], /^__Host-rw_session=[A-Za-z0-9_-]{43}; Max-Age=2592000;/);
  assert.ok(cookies.includes("__Host-rw_oauth=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Lax"));
  assert.equal(b.jar.has(OAUTH), false);

  const user = userOf(e, "ana@example.com");
  assert.ok(user);
  assert.deepEqual(identities(e), [{ provider: "google", provider_subject: "1001", user_id: user, verified_email: "ana@example.com" }]);
  assert.equal(rows(e, "SELECT role FROM memberships WHERE user_id = ?", user)[0].role, "owner");
  assert.deepEqual(eventsOf(e, user), ["signup_google"]);
  const [session] = rows(e, "SELECT authed_at FROM sessions");
  assert.equal(session.authed_at, 0, "Google is not a code typed just now: the session is not fresh");
  const home = await b.get("/");
  assert.match(home.text, /Account made, with Google/);
  assert.match(home.text, /data-method="google"><strong>Google<\/strong> <span class="tag">linked/);
  assert.match(home.text, /Linking or unlinking Google needs an emailed code/);
  assert.equal(rows(e, "SELECT used_at FROM oauth_flows")[0].used_at > 0, true);
});

test("Google: a callback works once; a replay, a late one, and one in another browser sign nobody in", async () => {
  const s = services();
  const e = env();
  const b = new Browser(e);
  const flow = await leave(b, "google");
  const back = consent(s, "google", flow);
  const cookie = b.jar.get(OAUTH);
  assert.equal((await b.get(back)).status, 303);
  assert.equal(tokenCalls(s), 1);

  /* The same callback again, with the flow's cookie put back. */
  const again = new Browser(e);
  again.jar.set(OAUTH, cookie);
  const replay = await again.get(back);
  assert.equal(replay.status, 400);
  assert.match(replay.text, /expired or was already used/);
  assert.equal(tokenCalls(s), 1, "a used flow never reaches Google");
  await signedOut(again);

  /* Ten minutes and a second later. */
  const slow = new Browser(e);
  const old = await leave(slow, "google");
  later(FLOW_FOR + 1);
  const late = await slow.get(consent(s, "google", old));
  assert.equal(late.status, 400);
  assert.equal(tokenCalls(s), 1);
  await signedOut(slow);

  /* Login CSRF: someone else's good callback, opened in a browser that
     started nothing. */
  const attacker = new Browser(e, { ip: "203.0.113.66" });
  const theirs = consent(s, "google", await leave(attacker, "google"), { claims: { sub: "666", email: "mallory@example.com" } });
  const victim = new Browser(e, { ip: "198.51.100.50" });
  assert.equal((await victim.get(theirs)).status, 400);
  await signedOut(victim);
  /* Nor in a browser that started a flow of its own. */
  await leave(victim, "google");
  assert.equal((await victim.get(theirs)).status, 400);
  await signedOut(victim);
  assert.equal(userOf(e, "mallory@example.com"), null);
  assert.equal(tokenCalls(s), 1);
});

test("Google: a wrong state, a code for another flow's PKCE challenge, or a verifier that no longer derives sign nobody in", async () => {
  const s = services();
  const e = env();

  const b = new Browser(e);
  const flow = await leave(b, "google");
  const wrongState = await b.get(consent(s, "google", flow, { state: "A".repeat(43) }));
  assert.equal(wrongState.status, 400);
  assert.match(wrongState.text, /did not check out/);
  assert.equal(tokenCalls(s), 0, "a wrong state never reaches Google");
  /* and the flow is spent: the right state afterwards is too late. */
  assert.equal((await b.get(consent(s, "google", flow))).status, 400);
  await signedOut(b);

  /* A code Google gave for another browser's challenge, brought back with
     this browser's state: Google refuses this browser's verifier for it. */
  const victim = new Browser(e);
  const mine = await leave(victim, "google");
  const other = await leave(new Browser(e, { ip: "203.0.113.9" }), "google");
  const swapped = await victim.get(consent(s, "google", { ...mine, challenge: other.challenge }));
  assert.equal(swapped.status, 400);
  assert.equal(tokenCalls(s), 1);
  await signedOut(victim);

  /* The verifier is derived from the cookie under ACCOUNT_SECRET; one that
     no longer matches what the flow recorded is never sent. */
  const c = new Browser(e);
  const rotated = await leave(c, "google");
  e.ACCOUNT_SECRET = SECRET.replace("test", "TEST");
  assert.equal((await c.get(consent(s, "google", rotated))).status, 400);
  assert.equal(tokenCalls(s), 1);
  assert.equal(count(e, "users"), 0);
});

test("Google: the person saying no at Google signs nobody in, and says so", async () => {
  services();
  const e = env();
  const b = new Browser(e);
  const flow = await leave(b, "google");
  const res = await b.get(`/auth/google/callback?${new URLSearchParams({ error: "access_denied", state: flow.state })}`);
  assert.equal(res.status, 200);
  assert.match(res.text, /cancelled/);
  await signedOut(b);
});

test("Google: an id_token that is forged, not for us, not Google's, out of date or for another nonce is refused", async () => {
  const s = services();
  const e = env();
  const t = () => nowS();
  const cases = {
    "forged signature": { key: FORGER },
    "unknown key": { header: { alg: "RS256", kid: "not-a-google-key" } },
    "alg none": { token: `${part({ alg: "none", kid: KID })}.${part({ sub: "1001" })}.` },
    "alg HS256": { header: { alg: "HS256", kid: KID } },
    "wrong aud": { claims: { aud: "someone-else.apps.googleusercontent.com", azp: "someone-else.apps.googleusercontent.com" } },
    "wrong azp": { claims: { azp: "someone-else.apps.googleusercontent.com" } },
    "aud list without azp": { claims: { aud: [GOOGLE_ID, "other"], azp: undefined } },
    "wrong iss": { claims: { iss: "https://accounts.example.com" } },
    "expired": { claims: { iat: t() - 5 * MINUTE, exp: t() - SKEW - 1 } },
    "issued in the future": { claims: { iat: t() + SKEW + 30, exp: t() + 7200 } },
    "issued long ago": { claims: { iat: t() - 3 * 3600, exp: t() + 3600 } },
    "another nonce": { claims: { nonce: "n".repeat(43) } },
    "no nonce": { claims: { nonce: undefined } },
    "no sub": { claims: { sub: undefined } },
    "tampered claims": { tamper: true },
  };
  for (const [name, what] of Object.entries(cases)) {
    const b = new Browser(e);
    const flow = await leave(b, "google");
    if (what.tamper) {
      const good = idToken({ iss: "https://accounts.google.com", aud: GOOGLE_ID, azp: GOOGLE_ID, sub: "1001",
                             email: "ana@example.com", email_verified: true, iat: t(), exp: t() + 3600, nonce: flow.nonce });
      const [h, , sig] = good.split(".");
      what.token = `${h}.${part({ iss: "https://accounts.google.com", aud: GOOGLE_ID, azp: GOOGLE_ID, sub: "1",
                                   email: "boss@example.com", email_verified: true, iat: t(), exp: t() + 3600,
                                   nonce: flow.nonce })}.${sig}`;
    }
    const res = await b.get(consent(s, "google", flow, what));
    assert.equal(res.status, 400, name);
    assert.match(res.text, /did not check out/, name);
    await signedOut(b);
  }
  assert.equal(count(e, "users"), 0);
  assert.equal(count(e, "identities"), 0);

  /* Both issuer spellings Google uses pass, with a minute's skew either way. */
  const b = new Browser(e);
  assert.equal((await viaProvider(b, s, "google", { claims: { iss: "accounts.google.com", iat: t() + SKEW - 5 } })).res.status, 303);
});

test("Google's keys are fetched once and kept for their max-age, then fetched again", async () => {
  const s = services();
  const e = env();
  forgetKeys();
  await viaProvider(new Browser(e), s, "google");
  await viaProvider(new Browser(e), s, "google");
  assert.equal(s.keyFetches, 1);
  later(3601);
  await viaProvider(new Browser(e), s, "google");
  assert.equal(s.keyFetches, 2);
  /* A key Google has not published makes one fetch more, not one per token. */
  const unknown = { header: { alg: "RS256", kid: "rotated-in" } };
  later(61);
  assert.equal((await viaProvider(new Browser(e), s, "google", unknown)).res.status, 400);
  assert.equal((await viaProvider(new Browser(e), s, "google", unknown)).res.status, 400);
  assert.equal(s.keyFetches, 3);
});

test("Google: an address Google does not call verified never makes an account, nor joins one", async () => {
  const s = services();
  const e = env();
  const res = (await viaProvider(new Browser(e), s, "google", { claims: { email_verified: false } })).res;
  assert.equal(res.status, 403);
  assert.match(res.text, /did not vouch for an email address/);
  assert.match(res.text, /<a href="\/signin">Sign in with an emailed code<\/a>/);
  assert.equal(count(e, "users"), 0);

  const ana = new Browser(e);
  await signInByCode(ana, s, "ana@example.com");
  const before = identities(e);
  for (const claims of [{ email_verified: false }, { email_verified: undefined }, { email: undefined },
                        { email: "not an address", email_verified: true }]) {
    const b = new Browser(e, { ip: "203.0.113.20" });
    assert.equal((await viaProvider(b, s, "google", { claims: { ...claims, sub: "7777" } })).res.status, 403);
    await signedOut(b);
  }
  assert.deepEqual(identities(e), before, "nothing was linked to ana's account");
  assert.equal(count(e, "users"), 1);
});

test("Google: a verified address that has an account links to it and signs in; then the Google id alone does", async () => {
  const s = services();
  const e = env();
  const ana = new Browser(e);
  await signInByCode(ana, s, "ana@example.com");
  const user = userOf(e, "ana@example.com");

  const b = new Browser(e, { ip: "203.0.113.5" });
  const res = (await viaProvider(b, s, "google", { claims: { email: "Ana@Example.com" } })).res;
  assert.equal(res.status, 303);
  assert.equal(count(e, "users"), 1);
  assert.deepEqual(identities(e).filter((i) => i.provider === "google"),
                   [{ provider: "google", provider_subject: "1001", user_id: user, verified_email: "ana@example.com" }]);
  assert.deepEqual(eventsOf(e, user), ["signup", "linked_google", "signin_google"]);
  assert.match((await b.get("/")).text, /Signed in as<\/dt><dd>ana@example\.com/);

  /* Later the Google account's address is someone else's, verified: the id
     still opens the account it was linked to, not theirs. */
  const bo = new Browser(e, { ip: "203.0.113.6" });
  await signInByCode(bo, s, "bo@example.com");
  const c = new Browser(e, { ip: "203.0.113.7" });
  assert.equal((await viaProvider(c, s, "google", { claims: { email: "bo@example.com" } })).res.status, 303);
  assert.match((await c.get("/")).text, /Signed in as<\/dt><dd>ana@example\.com/);
  /* and even when Google no longer calls an address verified. */
  const d = new Browser(e, { ip: "203.0.113.8" });
  assert.equal((await viaProvider(d, s, "google", { claims: { email_verified: false } })).res.status, 303);
  assert.deepEqual(eventsOf(e, user), ["signup", "linked_google", "signin_google", "signin_google", "signin_google"]);
  assert.equal(identities(e).filter((i) => i.user_id === userOf(e, "bo@example.com") && i.provider !== "email").length, 0);
});

test("Google could not be reached: nobody is signed in, and the page says to try again", async () => {
  const s = services();
  const e = env();
  s.google = "down";
  const b = new Browser(e);
  const { res } = await viaProvider(b, s, "google");
  assert.equal(res.status, 502);
  assert.match(res.text, /could not be reached/);
  await signedOut(b);
});

/* ---------- GitHub ---------- */

test("GitHub: PKCE and state, the numeric id as the subject, the primary verified address, and no access token kept", async () => {
  const s = services();
  const e = env();
  const b = new Browser(e);
  await signInByCode(b, s, "ana@example.com");
  const user = userOf(e, "ana@example.com");
  const flow = await leave(b, "github", { link: true });
  assert.equal(`${flow.to.origin}${flow.to.pathname}`, "https://github.com/login/oauth/authorize");
  const q = flow.to.searchParams;
  assert.equal(q.get("client_id"), GITHUB_ID);
  assert.equal(q.get("redirect_uri"), "https://account.ranwhat.com/auth/github/callback");
  assert.equal(q.get("scope"), "read:user user:email");
  assert.equal(q.get("code_challenge_method"), "S256");
  assert.equal(q.get("nonce"), null);
  assert.equal(rows(e, "SELECT nonce_hash FROM oauth_flows")[0].nonce_hash, null);

  const res = await b.get(consent(s, "github", flow, {
    user: { id: 583231, login: "ana-codes" },
    emails: [{ email: "ana@users.noreply.github.com", primary: false, verified: true },
             { email: "Ana@Example.com", primary: true, verified: true }],
  }));
  assert.equal(res.status, 303, res.text);
  assert.equal(s256(s.bodies.at(-1).get("code_verifier")), flow.challenge);
  assert.deepEqual(identities(e).filter((i) => i.provider === "github"),
                   [{ provider: "github", provider_subject: "583231", user_id: user, verified_email: "ana@example.com" }]);
  assert.deepEqual(eventsOf(e, user), ["signup", "linked_github"]);
  assert.ok(s.calls.includes("GET api.github.com/user") && s.calls.includes("GET api.github.com/user/emails"));

  /* From then on the numeric id signs in to ana's account, whatever
     address GitHub has for it now, verified or not. */
  const elsewhere = new Browser(e, { ip: "203.0.113.25" });
  const back = await viaProvider(elsewhere, s, "github", { user: { id: 583231, login: "ana-codes" }, emails: [] });
  assert.equal(back.res.status, 303, back.res.text);
  assert.match((await elsewhere.get("/")).text, /Signed in as<\/dt><dd>ana@example\.com/);
  assert.deepEqual(eventsOf(e, user), ["signup", "linked_github", "signin_github"]);
  for (const token of s.tokens.keys()) assert.ok(!everything(e).includes(token), "the access token is kept nowhere");
  assert.ok(!everything(e).includes("ana-codes"), "nor the login");
});

test("GitHub: only a primary and verified address counts for a link, and none makes an account", async () => {
  const s = services();
  const e = env();
  const ana = new Browser(e);
  await signInByCode(ana, s, "ana@example.com");

  /* Linked from ana's own page: a primary that is not verified, a
     verified address that is not the primary, or none at all (user:email
     not granted) are all refused, and ana's account gains nothing. */
  for (const what of [
    { user: { id: 777 }, emails: [{ email: "ana@example.com", primary: true, verified: false }] },
    { user: { id: 777 }, emails: [{ email: "someone@example.org", primary: true, verified: false },
                                  { email: "ana@example.com", primary: false, verified: true }] },
    { user: { id: 779 }, emailsStatus: 404 },
  ]) {
    const { res } = await viaProvider(ana, s, "github", what, { link: true });
    assert.equal(res.status, 403, res.text);
    assert.match(res.text, /did not vouch for an email address on that account, so it cannot be linked/);
  }
  assert.equal(identities(e).filter((i) => i.provider === "github").length, 0);

  /* Signing in with it says which address counts. */
  const unverified = await viaProvider(new Browser(e, { ip: "203.0.113.30" }), s, "github", {
    user: { id: 777 }, emails: [{ email: "ana@example.com", primary: true, verified: false }] });
  assert.equal(unverified.res.status, 403);
  assert.match(unverified.res.text, /only its primary address, and only once GitHub has verified it/);
  /* A verified primary of the GitHub user's own, with ana's address
     verified beside it: no account for either. */
  const mallory = new Browser(e, { ip: "203.0.113.32" });
  const own = await viaProvider(mallory, s, "github", {
    user: { id: 778 }, emails: [{ email: "mallory@example.com", primary: true, verified: true },
                                { email: "ana@example.com", primary: false, verified: true }] });
  assert.equal(own.res.status, 403);
  await signedOut(mallory);
  assert.equal(count(e, "users"), 1);
  assert.equal(identities(e).filter((i) => i.provider === "github").length, 0);
});

test("GitHub: a refused code, a bad answer or GitHub down sign nobody in", async () => {
  const s = services();
  const e = env();
  const b = new Browser(e);
  const flow = await leave(b, "github");
  const refused = await b.get(consent(s, "github", { ...flow, challenge: "x".repeat(43) }));
  assert.equal(refused.status, 400);
  await signedOut(b);
  const odd = await viaProvider(new Browser(e), s, "github", { user: { id: "4242" } });
  assert.equal(odd.res.status, 400, "an id that is not a number");
  s.github = "down";
  const down = await viaProvider(new Browser(e), s, "github");
  assert.equal(down.res.status, 502);
  assert.equal(count(e, "users"), 0);
});

/* ---------- linking from the account page ---------- */

test("signed in with a fresh code, a person links GitHub with another verified address; without one, nothing", async () => {
  const s = services();
  const e = env();
  const ana = new Browser(e);
  await signInByCode(ana, s, "ana@example.com");
  const user = userOf(e, "ana@example.com");
  let home = await ana.get("/");
  assert.match(home.text, /data-method="github"><strong>GitHub<\/strong> <span class="tag">not linked/);
  assert.match(home.text, /<form method="post" action="\/auth\/github">/);
  assert.match(home.headers.get("content-security-policy"),
               /form-action 'self' https:\/\/accounts\.google\.com https:\/\/github\.com; /);
  assert.doesNotMatch(home.text, /<script/);

  const { flow, res } = await viaProvider(ana, s, "github", {
    user: { id: 9001 }, emails: [{ email: "ana@work.example", primary: true, verified: true }] }, { link: true });
  assert.equal(res.status, 303, res.text);
  assert.equal(res.location, "/");
  const [row] = rows(e, "SELECT purpose, user_id, session_id FROM oauth_flows");
  assert.deepEqual(row, { purpose: "link", user_id: user, session_id: sha256(ana.jar.get(SESSION)) });
  assert.ok(flow.cookie);
  assert.deepEqual(identities(e).filter((i) => i.provider === "github"),
                   [{ provider: "github", provider_subject: "9001", user_id: user, verified_email: "ana@work.example" }]);
  assert.equal(eventsOf(e, user).at(-1), "linked_github");
  home = await ana.get("/");
  assert.match(home.text, /data-method="github"><strong>GitHub<\/strong> <span class="tag">linked/);
  assert.match(home.text, /ana@work\.example, linked/);
  assert.match(home.text, /GitHub account linked/);

  /* GitHub then signs in to ana's account on its own. */
  const elsewhere = new Browser(e, { ip: "203.0.113.40" });
  assert.equal((await viaProvider(elsewhere, s, "github", {
    user: { id: 9001 }, emails: [{ email: "ana@work.example", primary: true, verified: true }] })).res.status, 303);
  assert.match((await elsewhere.get("/")).text, /Signed in as<\/dt><dd>ana@example\.com/);

  /* Fifteen minutes on, the code is no longer fresh: no link form, and
     a form kept from before is refused before anything leaves. */
  const token = tokenFor(home.text, "/auth/google");
  later(FRESH_FOR + 1);
  home = await ana.get("/");
  assert.doesNotMatch(home.text, /action="\/auth\/google"/);
  assert.match(home.text, /Linking or unlinking Google needs an emailed code typed in the last 15 minutes/);
  assert.match(home.headers.get("content-security-policy"), /form-action 'self'; /);
  const flows = count(e, "oauth_flows");
  const stale = await ana.post("/auth/google", { form: token });
  assert.equal(stale.status, 403);
  assert.equal(count(e, "oauth_flows"), flows);
  /* Nor from another site, or without the form's token. */
  later(-(FRESH_FOR + 1));
  assert.equal((await ana.post("/auth/google", { form: token }, { "sec-fetch-site": "cross-site", origin: "https://evil.example" })).status, 403);
  assert.equal((await ana.post("/auth/google", {})).status, 403);
  assert.equal(count(e, "oauth_flows"), flows);
});

test("linking refuses another account's way in, another account's address, an unverified one, and a changed session", async () => {
  const s = services();
  const e = env();
  const bo = new Browser(e, { ip: "203.0.113.50" });
  await signInByCode(bo, s, "bo@example.com");
  assert.equal((await viaProvider(bo, s, "github", {
    user: { id: 31337 }, emails: [{ email: "bo@example.com", primary: true, verified: true }] }, { link: true })).res.status, 303);
  const boId = userOf(e, "bo@example.com");

  const ana = new Browser(e);
  await signInByCode(ana, s, "ana@example.com");
  const anaId = userOf(e, "ana@example.com");
  const before = identities(e);

  const taken = await viaProvider(ana, s, "github", {
    user: { id: 31337 }, emails: [{ email: "ana@example.com", primary: true, verified: true }] }, { link: true });
  assert.equal(taken.res.status, 409);
  assert.match(taken.res.text, /already signs in to another ranwhat account/);

  const theirs = await viaProvider(ana, s, "google", { claims: { sub: "5005", email: "bo@example.com" } }, { link: true });
  assert.equal(theirs.res.status, 409);
  assert.match(theirs.res.text, /has its own ranwhat account/);

  const unverified = await viaProvider(ana, s, "google", { claims: { sub: "5006", email_verified: false } }, { link: true });
  assert.equal(unverified.res.status, 403);
  assert.deepEqual(identities(e), before);

  /* Signed out between leaving and coming back, or signed in again with
     a new session: the flow belongs to the session that started it. */
  const flow = await leave(ana, "google", { link: true });
  let home = await ana.get("/");
  await ana.post("/signout", { form: tokenFor(home.text, "/signout") });
  const gone = await ana.get(consent(s, "google", flow, { claims: { sub: "5007" } }));
  assert.equal(gone.status, 403);
  assert.match(gone.text, /nothing was linked/);
  const kept = ana.jar.get(OAUTH);
  assert.equal(kept, undefined, "the flow's cookie is cleared");
  later(MINUTE);
  await signInByCode(ana, s, "ana@example.com");
  const second = await leave(ana, "google", { link: true });
  home = await ana.get("/");
  await ana.post("/signout", { form: tokenFor(home.text, "/signout") });
  later(MINUTE);
  await signInByCode(ana, s, "ana@example.com");
  const renewed = await ana.get(consent(s, "google", second, { claims: { sub: "5008" } }));
  assert.equal(renewed.status, 403);
  assert.deepEqual(identities(e), before);
  assert.equal(identities(e).filter((i) => i.user_id === anaId && i.provider !== "email").length, 0);
  assert.equal(identities(e).filter((i) => i.user_id === boId && i.provider === "github").length, 1);
});

test("unlinking needs a fresh code, takes only this account's own, and leaves the emailed code", async () => {
  const s = services();
  const e = env();
  const ana = new Browser(e);
  await signInByCode(ana, s, "ana@example.com");
  const user = userOf(e, "ana@example.com");
  await viaProvider(ana, s, "github", { user: { id: 9001 } }, { link: true });
  await viaProvider(ana, s, "google", { claims: { sub: "2002" } }, { link: true });
  const bo = new Browser(e, { ip: "203.0.113.60" });
  await signInByCode(bo, s, "bo@example.com");
  await viaProvider(bo, s, "github", { user: { id: 9002 }, emails: [{ email: "bo@example.com", primary: true, verified: true }] },
                    { link: true });
  assert.equal(count(e, "identities"), 5);

  let home = await ana.get("/");
  const unlink = tokenFor(home.text, "/auth/github/unlink");
  assert.match(home.text, /name="subject" value="9001"/);
  /* bo's GitHub, named in ana's form: nothing happens, and nothing is recorded. */
  assert.equal((await ana.post("/auth/github/unlink", { form: unlink, subject: "9002" })).status, 303);
  assert.equal(count(e, "identities"), 5);
  assert.equal(count(e, "unlinked_identities"), 0);
  assert.ok(!eventsOf(e, user).includes("unlinked_github"));
  /* Not fresh: refused. */
  later(FRESH_FOR + 1);
  const stale = await ana.post("/auth/github/unlink", { form: unlink, subject: "9001" });
  assert.equal(stale.status, 403);
  assert.equal(count(e, "identities"), 5);
  /* Fresh again with a step-up code. */
  home = await ana.get("/");
  assert.doesNotMatch(home.text, /action="\/auth\/github\/unlink"/);
  await ana.post("/stepup", { form: tokenFor(home.text, "/stepup"), next: "/" });
  const page = await ana.get("/signin/code");
  await ana.post("/signin/code", { form: tokenFor(page.text, "/signin/code"), code: codeIn(s.emails.at(-1)) });
  const done = await ana.post("/auth/github/unlink", { form: tokenFor((await ana.get("/")).text, "/auth/github/unlink"), subject: "9001" });
  assert.equal(done.status, 303);
  assert.deepEqual(identities(e).filter((i) => i.user_id === user).map((i) => i.provider), ["email", "google"]);
  assert.equal(eventsOf(e, user).at(-1), "unlinked_github");
  assert.match((await ana.get("/")).text, /GitHub account unlinked/);
  /* That GitHub account no longer opens ana's account, even with ana's
     address as its verified primary. */
  const b = new Browser(e, { ip: "203.0.113.61" });
  const back = await viaProvider(b, s, "github", { user: { id: 9001 } });
  assert.equal(back.res.status, 403);
  await signedOut(b);
  assert.deepEqual(identities(e).filter((i) => i.user_id === user).map((i) => i.provider), ["email", "google"]);
});

/* ---------- verified once is not held now ---------- */

test("Google is the authority only for Gmail and for its Workspace domain", () => {
  for (const [email, hd] of [["a@gmail.com"], ["A@GMail.com"], ["a@googlemail.com"], ["a@corp.example", "corp.example"],
                             ["a@CORP.example", "Corp.Example"]]) {
    assert.equal(googleGivesOut(email, hd), true, `${email} ${hd}`);
  }
  for (const [email, hd] of [["a@corp.example"], ["a@corp.example", ""], ["a@corp.example", "other.example"],
                             ["a@mail.corp.example", "corp.example"], ["a@gmail.com.evil.example"], ["a@corp.example", 1],
                             [null, "corp.example"], ["corp.example", "corp.example"]]) {
    assert.equal(googleGivesOut(email, hd), false, `${email} ${hd}`);
  }
});

test("Google: an address it verified but does not give out neither makes an account nor joins one, and says the same either way", async () => {
  const s = services();
  const e = env();
  const corp = { sub: "666", email: "alice@corp.example", email_verified: true, hd: undefined };
  const first = (await viaProvider(new Browser(e, { ip: "203.0.113.66" }), s, "google", { claims: corp })).res;
  assert.equal(first.status, 403);
  assert.match(first.text, /Use an emailed code first/);
  assert.match(first.text, /<a href="\/signin">Sign in with an emailed code<\/a>, which makes the account if there is none yet/);
  assert.equal(count(e, "users"), 0, "no account made ahead of the address's owner");

  const alice = new Browser(e);
  await signInByCode(alice, s, "alice@corp.example");
  const victim = userOf(e, "alice@corp.example");
  const mails = s.emails.length;
  for (const claims of [corp, { ...corp, hd: "other.example" }, { ...corp, hd: "" }, { ...corp, email_verified: "true" }]) {
    const b = new Browser(e, { ip: "203.0.113.67" });
    const res = (await viaProvider(b, s, "google", { claims })).res;
    assert.equal(res.status, 403, JSON.stringify(claims));
    assert.equal(res.text, first.text, "the same page whether or not an account has the address");
    await signedOut(b);
  }
  assert.deepEqual(identities(e), [{ provider: "email", provider_subject: "alice@corp.example", user_id: victim,
                                     verified_email: "alice@corp.example" }]);
  assert.equal(rows(e, "SELECT count(*) AS n FROM sessions WHERE user_id = ?", victim)[0].n, 1);
  assert.deepEqual(eventsOf(e, victim), ["signup"]);
  assert.equal(s.emails.length, mails, "and nobody is mailed");

  /* Google gives out Gmail addresses itself: those make an account. */
  const carla = new Browser(e, { ip: "203.0.113.68" });
  const made = (await viaProvider(carla, s, "google", { claims: { sub: "1234", email: "Carla@Gmail.com", hd: undefined } })).res;
  assert.equal(made.status, 303, made.text);
  assert.match((await carla.get("/")).text, /Signed in as<\/dt><dd>carla@gmail\.com/);
});

test("GitHub never makes an account or joins one by its address, verified or not, and says the same either way", async () => {
  const s = services();
  const e = env();
  const gh = { user: { id: 777, login: "mallory" }, emails: [{ email: "alice@corp.example", primary: true, verified: true }] };
  const first = (await viaProvider(new Browser(e, { ip: "203.0.113.77" }), s, "github", gh)).res;
  assert.equal(first.status, 403);
  assert.match(first.text, /GitHub says the address on that account was verified once, which does not show it\s+is still yours/);
  assert.match(first.text, /Then link GitHub from your account page/);
  assert.equal(count(e, "users"), 0);

  const alice = new Browser(e);
  await signInByCode(alice, s, "alice@corp.example");
  const victim = userOf(e, "alice@corp.example");
  const h = new Browser(e, { ip: "203.0.113.78" });
  const again = (await viaProvider(h, s, "github", gh)).res;
  assert.equal(again.status, 403);
  assert.equal(again.text, first.text);
  await signedOut(h);
  assert.deepEqual(identities(e).map((i) => i.provider), ["email"]);
  assert.deepEqual(eventsOf(e, victim), ["signup"]);
  assert.equal(rows(e, "SELECT count(*) AS n FROM sessions WHERE user_id = ?", victim)[0].n, 1);
});

test("nobody can make an account ahead of an address's owner, who then has only the ways in they chose", async () => {
  const s = services();
  const e = env();
  const google = { claims: { sub: "666", email: "bob@corp.example", hd: undefined } };
  const github = { user: { id: 777 }, emails: [{ email: "bob@corp.example", primary: true, verified: true }] };
  assert.equal((await viaProvider(new Browser(e, { ip: "203.0.113.66" }), s, "google", google)).res.status, 403);
  assert.equal((await viaProvider(new Browser(e, { ip: "203.0.113.66" }), s, "github", github)).res.status, 403);
  assert.equal(count(e, "users"), 0);

  const bob = new Browser(e);
  await signInByCode(bob, s, "bob@corp.example");
  const user = userOf(e, "bob@corp.example");
  assert.deepEqual(eventsOf(e, user), ["signup"]);
  assert.deepEqual(identities(e).map((i) => i.provider), ["email"]);

  for (const [provider, what] of [["google", google], ["github", github]]) {
    const back = new Browser(e, { ip: "203.0.113.67" });
    assert.equal((await viaProvider(back, s, provider, what)).res.status, 403, provider);
    await signedOut(back);
  }
  assert.equal(rows(e, "SELECT count(*) AS n FROM sessions WHERE user_id = ?", user)[0].n, 1);
  assert.equal(count(e, "users"), 1);
});

/* ---------- unlinking is for good ---------- */

test("an unlinked Google or GitHub account never links itself back, and only a link from the account page undoes it", async () => {
  const s = services();
  const e = env();
  const ana = new Browser(e);
  await signInByCode(ana, s, "ana@example.com");
  const user = userOf(e, "ana@example.com");
  /* Google, the authority for ana's Workspace address, links itself on
     sign-in; GitHub is linked from the account page. */
  assert.equal((await viaProvider(new Browser(e, { ip: "203.0.113.90" }), s, "google", { claims: { sub: "2002" } })).res.status, 303);
  assert.equal((await viaProvider(ana, s, "github", { user: { id: 777 } }, { link: true })).res.status, 303);
  assert.equal(identities(e).filter((i) => i.user_id === user).length, 3);

  for (const [provider, subject] of [["google", "2002"], ["github", "777"]]) {
    const home = await ana.get("/");
    assert.match(home.text, /Unlinking one keeps its id here, so that it does not link itself back/);
    const done = await ana.post(`/auth/${provider}/unlink`, { form: tokenFor(home.text, `/auth/${provider}/unlink`), subject });
    assert.equal(done.status, 303);
  }
  assert.deepEqual(rows(e, "SELECT provider, provider_subject, user_id FROM unlinked_identities ORDER BY provider"),
                   [{ provider: "github", provider_subject: "777", user_id: user },
                    { provider: "google", provider_subject: "2002", user_id: user }]);

  /* Each signs in again with ana's address, verified, Google as its
     authority: neither is let in, and neither is linked. */
  const events = eventsOf(e, user).length;
  const google = (await viaProvider(new Browser(e, { ip: "203.0.113.91" }), s, "google", { claims: { sub: "2002" } })).res;
  assert.equal(google.status, 403);
  assert.match(google.text, /That Google account was unlinked from the ranwhat account for its address/);
  const github = (await viaProvider(new Browser(e, { ip: "203.0.113.92" }), s, "github", { user: { id: 777 } })).res;
  assert.equal(github.status, 403);
  assert.deepEqual(identities(e).filter((i) => i.user_id === user).map((i) => i.provider), ["email"]);
  assert.equal(eventsOf(e, user).length, events, "nothing linked, nobody signed in");

  /* Inside the batch too: an unlink that lands after the check holds. */
  assert.deepEqual(await userForVerifiedEmail(e, { email: "ana@example.com", provider: "google", subject: "2002" }),
                   { refused: "unlinked" });
  assert.equal(identities(e).filter((i) => i.provider === "google").length, 0);
  /* Another Google account with ana's address is not held back. */
  assert.equal((await viaProvider(new Browser(e, { ip: "203.0.113.93" }), s, "google", { claims: { sub: "3003" } })).res.status, 303);

  /* Linking it again from the account page, with a fresh code, takes the
     note away, and it signs in by itself again. */
  assert.equal((await viaProvider(ana, s, "google", { claims: { sub: "2002" } }, { link: true })).res.status, 303);
  assert.deepEqual(rows(e, "SELECT provider FROM unlinked_identities"), [{ provider: "github" }]);
  const g = new Browser(e, { ip: "203.0.113.94" });
  assert.equal((await viaProvider(g, s, "google", { claims: { sub: "2002" } })).res.status, 303);
  assert.match((await g.get("/")).text, /Signed in as<\/dt><dd>ana@example\.com/);
});

test("signing out everywhere can take every Google, GitHub and passkey way in with it, with a fresh code, for good", async () => {
  const s = services();
  const e = env();
  const ana = new Browser(e);
  await signInByCode(ana, s, "ana@example.com");
  const user = userOf(e, "ana@example.com");
  let home = await ana.get("/");
  assert.doesNotMatch(home.text, /remove every other way in/, "not offered with nothing to remove");
  await viaProvider(ana, s, "github", { user: { id: 777 } }, { link: true });
  await viaProvider(ana, s, "google", { claims: { sub: "2002" } }, { link: true });
  e.LIST.sql.prepare(`INSERT INTO passkeys (id, user_id, public_key, sign_count, backed_up, label, created_at)
                      VALUES ('pk1', ?, 'AQ', 0, 0, 'Phone', ?)`).run(user, nowS());
  const elsewhere = new Browser(e, { ip: "203.0.113.95" });
  assert.equal((await viaProvider(elsewhere, s, "github", { user: { id: 777 } })).res.status, 303);

  home = await ana.get("/");
  assert.match(home.text, /<button type="submit">Sign out everywhere and remove every other way in<\/button>/);
  assert.match(home.text, /leaving the emailed code\./);
  const token = tokenFor(home.text, "/signout-all");
  /* Not fresh: refused, and nothing changes, not even the sessions. */
  later(FRESH_FOR + 1);
  home = await ana.get("/");
  assert.doesNotMatch(home.text, /<button type="submit">Sign out everywhere and remove/);
  assert.match(home.text, /confirm with an\s+emailed code first/);
  const stale = await ana.post("/signout-all", { form: token, ways: "remove" });
  assert.equal(stale.status, 403);
  assert.match(stale.text, /so nothing was done/);
  assert.equal(identities(e).filter((i) => i.provider !== "email").length, 2);
  assert.equal(count(e, "passkeys"), 1);
  assert.equal(count(e, "sessions"), 2);
  later(-(FRESH_FOR + 1));

  const done = await ana.post("/signout-all", { form: token, ways: "remove" });
  assert.equal(done.status, 303);
  assert.equal(done.location, "/signin");
  assert.deepEqual(identities(e).map((i) => i.provider), ["email"]);
  assert.equal(count(e, "passkeys"), 0);
  assert.equal(count(e, "sessions"), 0);
  assert.equal(count(e, "unlinked_identities"), 2);
  assert.deepEqual(eventsOf(e, user).slice(-2), ["ways_removed", "signout_all"]);
  assert.equal((await elsewhere.get("/")).location, "/signin", "the session GitHub opened is over");
  assert.equal((await viaProvider(new Browser(e, { ip: "203.0.113.96" }), s, "github", { user: { id: 777 } })).res.status, 403);
  assert.equal((await viaProvider(new Browser(e, { ip: "203.0.113.96" }), s, "google", { claims: { sub: "2002" } })).res.status, 403);
  assert.equal(count(e, "sessions"), 0);
});

test("a password reset can take every Google, GitHub and passkey way in with it", async () => {
  const s = services();
  const e = env();
  const ana = new Browser(e);
  await signInByCode(ana, s, "ana@example.com");
  const user = userOf(e, "ana@example.com");
  await viaProvider(ana, s, "github", { user: { id: 777 } }, { link: true });
  e.LIST.sql.prepare(`INSERT INTO passkeys (id, user_id, public_key, sign_count, backed_up, label, created_at)
                      VALUES ('pk1', ?, 'AQ', 0, 0, 'Phone', ?)`).run(user, nowS());

  const b = new Browser(e, { ip: "203.0.113.97" });
  const form = await b.get("/reset");
  await b.post("/reset", { form: tokenFor(form.text, "/reset"), email: "ana@example.com", "cf-turnstile-response": "solved:reset" });
  const page = await b.get("/signin/code");
  assert.match(page.text, /<label><input type="checkbox" name="ways" value="remove"> Also unlink every Google and GitHub account/);
  const done = await b.post("/signin/code", { form: tokenFor(page.text, "/signin/code"), code: codeIn(s.emails.at(-1)),
                                              password: "a long and unbreached passphrase", ways: "remove" });
  assert.equal(done.status, 303, done.text);
  assert.deepEqual(identities(e).map((i) => i.provider), ["email"]);
  assert.equal(count(e, "passkeys"), 0);
  assert.deepEqual(rows(e, "SELECT provider, provider_subject FROM unlinked_identities"), [{ provider: "github", provider_subject: "777" }]);
  assert.deepEqual(eventsOf(e, user).slice(-2), ["password_added", "ways_removed"]);
  assert.equal((await ana.get("/")).location, "/signin", "every other session ended");
});

/* ---------- telling the account ---------- */

test("the account's address is told when a Google or GitHub account is linked to it, within a daily share", async () => {
  const s = services();
  const e = env();
  const ana = new Browser(e);
  await signInByCode(ana, s, "ana@example.com");
  const user = userOf(e, "ana@example.com");
  const mails = s.emails.length;
  /* Google links itself, Google being the authority for the address;
     GitHub is linked from the account page. */
  assert.equal((await viaProvider(new Browser(e, { ip: "203.0.113.98" }), s, "google", { claims: { sub: "2002" } })).res.status, 303);
  assert.equal((await viaProvider(ana, s, "github", { user: { id: 777 } }, { link: true })).res.status, 303);
  const notices = s.emails.slice(mails);
  assert.deepEqual(notices.map((m) => m.text.split("\n")[0]), [
    "A Google account was linked to your ranwhat account (ana@example.com), and can now sign in to it.",
    "A GitHub account was linked to your ranwhat account (ana@example.com), and can now sign in to it.",
  ]);
  for (const m of notices) {
    assert.deepEqual(m.to, ["ana@example.com"]);
    assert.equal(m.subject, "A new way into your ranwhat account");
    assert.match(m.text, /Sign out everywhere and remove every other way in/);
    assert.ok(!JSON.stringify(m).includes("2002") && !JSON.stringify(m).includes("777"), "no provider id");
  }
  /* Signing in with one already linked, or making an account with
     Google, tells nobody: nothing was added to an account. */
  assert.equal((await viaProvider(new Browser(e, { ip: "203.0.113.98" }), s, "google", { claims: { sub: "2002" } })).res.status, 303);
  assert.equal((await viaProvider(new Browser(e, { ip: "203.0.113.98" }), s, "google",
    { claims: { sub: "4004", email: "dee@gmail.com", hd: undefined } })).res.status, 303);
  assert.equal(s.emails.length, mails + 2);
  /* At most NOTICES_PER_USER_DAY a day for one account, from the
     signed-in reserve; the activity lists every link all the same. */
  for (let id = 800; id < 800 + NOTICES_PER_USER_DAY; id++) {
    assert.equal((await viaProvider(ana, s, "github", { user: { id } }, { link: true })).res.status, 303);
  }
  assert.equal(s.emails.length, mails + NOTICES_PER_USER_DAY);
  assert.deepEqual(rows(e, "SELECT sent FROM mail_counts WHERE kind = 'auth-stepup'"), [{ sent: NOTICES_PER_USER_DAY }]);
  assert.equal(eventsOf(e, user).filter((x) => x === "linked_github").length, 1 + NOTICES_PER_USER_DAY);
});

/* ---------- limits, the session, and the sweep ---------- */

test("one network starts at most thirty flows an hour; another network is not held back", async () => {
  services();
  const e = env();
  const b = new Browser(e);
  for (let i = 0; i < STARTS_PER_NETWORK; i++) assert.equal((await b.get("/auth/github")).status, 303);
  const over = await b.get("/auth/google");
  assert.equal(over.status, 429);
  assert.equal(count(e, "oauth_flows"), STARTS_PER_NETWORK);
  assert.equal(rows(e, "SELECT count(*) AS n FROM oauth_flows WHERE used_at IS NULL")[0].n, 1,
               "each new flow cancels the browser's last");
  assert.equal((await new Browser(e, { ip: "203.0.113.70" }).get("/auth/google")).status, 303);
  later(3601);
  assert.equal((await b.get("/auth/google")).status, 303);
});

test("signed in already, the sign-in link goes home; a Google session is not fresh for what needs a code", async () => {
  const s = services();
  const e = env();
  const b = new Browser(e);
  await viaProvider(b, s, "google");
  const again = await b.get("/auth/google");
  assert.equal(again.status, 303);
  assert.equal(again.location, "/");
  const home = await b.get("/");
  assert.doesNotMatch(home.text, /action="\/auth\/github"/);
  const late = await b.post("/password", { form: await formToken(e, sha256(b.jar.get(SESSION)), "password"),
                                          password: "slipped in without a code" });
  assert.equal(late.status, 403);
  assert.equal(count(e, "credentials"), 0);
});

test("the cron deletes flows once used or out of date, and nothing logged carries a code, state or token", async () => {
  const s = services();
  const e = env();
  const lines = [];
  const real = console.log;
  console.log = (...a) => lines.push(a.join(" "));
  try {
    await viaProvider(new Browser(e), s, "google");
    s.github = "down";
    await viaProvider(new Browser(e), s, "github");
    await leave(new Browser(e, { ip: "203.0.113.80" }), "google");
  } finally {
    console.log = real;
  }
  assert.equal(count(e, "oauth_flows"), 3);
  const waits = [];
  await worker.scheduled({}, e, { waitUntil: (p) => waits.push(p) });
  await Promise.all(waits);
  assert.equal(count(e, "oauth_flows"), 1, "the flow still waiting stays");
  later(FLOW_FOR + 1);
  await worker.scheduled({}, e, { waitUntil: (p) => waits.push(p) });
  await Promise.all(waits);
  assert.equal(count(e, "oauth_flows"), 0);
  const logged = lines.join("\n");
  assert.match(logged, /account github sign-in: Error/);
  for (const secret of ["code-", "gho_", GOOGLE_SECRET, GITHUB_SECRET, "ana@example.com"]) {
    assert.ok(!logged.includes(secret), secret);
  }
});
