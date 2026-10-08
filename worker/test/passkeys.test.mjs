/* Passkeys on account.ranwhat.com (passkeys.js), end to end through the
 * Worker over a real SQLite database: adding one with a fresh code,
 * signing in with it, the counter, removing it, and /passkeys.js itself,
 * run against a stand-in page. The authenticators are authenticators.mjs's,
 * with keys made by node:crypto; Resend and Turnstile are stand-ins.
 *
 * The cases this file is for: a challenge that is out of date, used, or
 * someone else's; a form from another site; a counter that does not go
 * up; that every way a passkey can fail to sign in looks the same; and a
 * database whose passkeys table the first deploy made.
 *
 *     node --test --test-timeout=60000 worker/test/passkeys.test.mjs
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import { d1 } from "./stand-ins.mjs";
import { onNoPage } from "./account-pages.mjs";
import {
  AT, ORIGIN, UP, UV, authData, b64, bytes, cbor, clientData, concat, ed25519, es256, rs256, sha256, unb64,
} from "./authenticators.mjs";

const worker = (await import("../src/index.js")).default;
const { FRESH_FOR, formToken } = await import("../src/session.js");
const {
  CHALLENGE_FOR, CHALLENGES_PER_NETWORK, MAX_LABEL, OPTIONS_PER_USER, PAGE_SCRIPT, passkeyLabel,
} = await import("../src/passkeys.js");
const { coseKey } = await import("../src/webauthn.js");
const { AUTH_MAIL_PER_DAY, STEPUP_RESERVE, schema, sweep } = await import("../src/accounts.js");

const SECRET = "an-account-test-secret-" + "that-is-long-enough-0123456789";
const SESSION = "__Host-rw_session";
const SIGNIN = "__Host-rw_signin";
const FROM_PAGE = { "sec-fetch-site": "same-origin", origin: ORIGIN };
const FETCHED = { "sec-fetch-site": "same-origin" };       // a same-origin GET carries no Origin
const MINUTE = 60, DAY = 86400;

/* The clock, which a test moves forward when it needs time to pass. */
const realNow = Date.now;
let skew = 0;
Date.now = () => realNow() + skew * 1000;
const later = (seconds) => { skew += seconds; };
const nowS = () => Math.floor(Date.now() / 1000);
const today = () => Math.floor(nowS() / DAY);

const hex = (text) => createHash("sha256").update(text).digest("hex");

/* ---------- stand-ins ---------- */

function services() {
  const s = { emails: [] };
  globalThis.fetch = async (url, init = {}) => {
    const u = new URL(String(url));
    const json = (value) => new Response(JSON.stringify(value), { status: 200 });
    if (u.hostname === "challenges.cloudflare.com") {
      const m = /^solved:([a-z]+)$/.exec(JSON.parse(init.body).response);
      return json(m ? { success: true, hostname: "account.ranwhat.com", action: m[1] } : { success: false });
    }
    if (u.hostname === "api.resend.com") {
      s.emails.push(JSON.parse(init.body));
      return json({ id: `e${s.emails.length}` });
    }
    throw new Error(`unexpected fetch ${url}`);
  };
  return s;
}

const env = (extra = {}) => ({
  LIST: d1(), RESEND_API_KEY: "re_" + "test_key", ACCOUNT_SECRET: SECRET, TURNSTILE_SECRET: "turnstile-" + "test",
  ACCOUNTS_ON: "1", PBKDF2_ITERATIONS: "1000", ...extra,
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

  /* What /passkeys.js fetches: { status, body } with the JSON read. */
  async json(path, headers = FETCHED) {
    const r = await this.get(path, headers);
    assert.match(r.headers.get("content-type"), /^application\/json/);
    return { ...r, body: JSON.parse(r.text) };
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

/* A way to sign in, as its card on the Security page names it:
   [its name, its state]. */
function method(html, key) {
  const m = html.match(new RegExp(`data-method="${key}">\\s*<header class="card-head"><h3>(?:<svg[\\s\\S]*?</svg>)?` +
    `([^<]*)</h3><span class="pill[^"]*">([^<]*)</span>`));
  assert.ok(m, `no card for ${key}`);
  return [m[1], m[2]];
}

const codeIn = (mail) => mail.text.match(/^ {4}([0-9A-Z]{4}-[0-9A-Z]{4})$/m)[1];

async function signInByCode(b, s, email) {
  const form = await b.get("/signin");
  await b.post("/signin", { form: tokenFor(form.text, "/signin"), email, next: "/", "cf-turnstile-response": "solved:signin" });
  const page = await b.get("/signin/code");
  const done = await b.post("/signin/code", { form: tokenFor(page.text, "/signin/code"), code: codeIn(s.emails.at(-1)) });
  assert.equal(done.status, 303, done.text);
}

/* A fresh code for someone signed in, from the account page. */
async function confirm(b, s) {
  const home = await b.get("/security");
  assert.equal((await b.post("/stepup", { form: tokenFor(home.text, "/stepup"), next: "/" })).status, 303);
  const page = await b.get("/signin/code");
  const done = await b.post("/signin/code", { form: tokenFor(page.text, "/signin/code"), code: codeIn(s.emails.at(-1)) });
  assert.equal(done.status, 303, done.text);
}

const rows = (e, sql, ...p) => e.LIST.sql.prepare(sql).all(...p).map((r) => ({ ...r }));
const count = (e, table) => e.LIST.sql.prepare(`SELECT count(*) AS n FROM ${table}`).get().n;
const userOf = (e, email) => rows(e, "SELECT id FROM users WHERE email = ?", email)[0]?.id ?? null;
const eventsOf = (e, email) =>
  rows(e, "SELECT event FROM auth_events WHERE user_id = ? ORDER BY id", userOf(e, email)).map((r) => r.event);
const passkeysOf = (e, email) => rows(e, "SELECT * FROM passkeys WHERE user_id = ? ORDER BY created_at, id", userOf(e, email));
const sessionOf = (e, b) => rows(e, "SELECT * FROM sessions WHERE id = ?", hex(b.jar.get(SESSION)))[0] ?? null;

/* ---------- a device that holds passkeys ---------- */

/* What navigator.credentials.create() and .get() hand back, base64url, as
   the page posts it. Each passkey has its own key; `counts` false makes a
   device whose counter always says 0, as synced passkeys do. */
class Device {
  constructor({ make = es256, counts = true } = {}) {
    this.make = make;
    this.counts = counts;
    this.keys = [];
  }

  create(options, { origin, flags = UP | UV | AT } = {}) {
    const pair = this.make();
    const id = bytes(randomBytes(16));
    const key = { id: b64(id), pair, handle: options.user.id, rp: options.rp.id, count: this.counts ? 1 : 0 };
    this.keys.push(key);
    const data = authData({ flags, signCount: key.count, credential: { id, cose: pair.cose } });
    return {
      clientDataJSON: b64(clientData({ type: "webauthn.create", challenge: options.challenge, origin })),
      attestationObject: b64(cbor(new Map([["fmt", "none"], ["attStmt", new Map()], ["authData", data]]))),
    };
  }

  get(options, { key = this.keys.at(-1), signCount, origin, flags = UP | UV, handle, signer } = {}) {
    if (this.counts && signCount === undefined) key.count += 1;
    const client = clientData({ type: "webauthn.get", challenge: options.challenge, origin });
    const data = authData({ flags, signCount: signCount ?? key.count });
    return {
      id: key.id, clientDataJSON: b64(client), authenticatorData: b64(data),
      signature: b64((signer || key.pair).sign(concat([data, sha256(client)]))),
      userHandle: handle ?? key.handle,
    };
  }
}

/* Adds a passkey from the account page, as /passkeys.js would. */
async function addPasskey(b, device, { label = "Work laptop", made } = {}) {
  const page = await b.get("/passkeys/add");
  assert.equal(page.status, 200, page.text);
  const options = await b.json("/passkeys/new");
  assert.equal(options.status, 200, options.text);
  const res = await b.post("/passkeys", { form: tokenFor(page.text, "/passkeys"), label, ...(made || device.create(options.body)) });
  return { res, options: options.body };
}

/* Signs in on the passkey page, as /passkeys.js would. */
async function passkeySignIn(b, device, answer = {}) {
  const page = await b.get("/signin/passkey");
  assert.equal(page.status, 200, page.text);
  const options = await b.json("/passkeys/challenge");
  assert.equal(options.status, 200, options.text);
  const fields = typeof answer === "function" ? answer(options.body) : device.get(options.body, answer);
  return b.post("/signin/passkey", { form: tokenFor(page.text, "/signin/passkey"), next: "/", ...fields });
}

/* Someone with an account and a passkey, still in the browser that added it. */
async function withPasskey(e, s, email = "ana@example.com", device = new Device()) {
  const b = new Browser(e);
  await signInByCode(b, s, email);
  const { res } = await addPasskey(b, device);
  assert.equal(res.status, 303, res.text);
  return { b, device };
}

/* ---------- adding one ---------- */

test("adding a passkey: the options, the challenge kept hashed, the row, and the account page", async () => {
  const s = services();
  const e = env();
  const b = new Browser(e);
  await signInByCode(b, s, "ana@example.com");
  const device = new Device();

  let home = await b.get("/security");
  assert.deepEqual(method(home.text, "passkeys"), ["Passkeys", "None added"]);
  assert.match(home.text, /<a class="btn" href="\/passkeys\/add"><svg class="i"[^>]*>[^]*?<\/svg>Add a passkey<\/a>/);

  const page = await b.get("/passkeys/add");
  assert.equal(page.status, 200);
  assert.match(page.text, /<form method="post" action="\/passkeys" data-passkey="\/passkeys\/new" data-ceremony="create">/);
  assert.match(page.headers.get("content-security-policy"),
    /; script-src https:\/\/account\.ranwhat\.com\/passkeys\.js; connect-src https:\/\/account\.ranwhat\.com\/passkeys\/new https:\/\/account\.ranwhat\.com\/passkeys\/challenge$/);
  assert.deepEqual(page.text.match(/<script[^>]*>/g), ['<script src="/passkeys.js" defer>']);
  assert.doesNotMatch(page.text, /<script[^>]*>[^<]/, "no inline script");
  assert.doesNotMatch(page.text, /\son[a-z]+=/i);

  const { body: options, headers } = await b.json("/passkeys/new");
  assert.equal(headers.get("cache-control"), "no-store");
  assert.deepEqual(options.rp, { id: "account.ranwhat.com", name: "ranwhat" });
  assert.deepEqual(options.user, { id: options.user.id, name: "ana@example.com", displayName: "ana@example.com" });
  assert.match(options.user.id, /^[A-Za-z0-9_-]{43}$/);
  assert.match(options.challenge, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(unb64(options.challenge).length, 32);
  assert.deepEqual(options.pubKeyCredParams, [
    { type: "public-key", alg: -7 }, { type: "public-key", alg: -8 }, { type: "public-key", alg: -257 }]);
  assert.deepEqual(options.authenticatorSelection, { residentKey: "required", requireResidentKey: true, userVerification: "required" });
  assert.equal(options.attestation, "none");
  assert.deepEqual(options.excludeCredentials, []);
  assert.equal(options.timeout, CHALLENGE_FOR * 1000);

  /* The challenge is kept as its hash only, bound to this session, for
     five minutes; the handle is not the user's id or address. */
  const [challenge] = rows(e, "SELECT * FROM passkey_challenges");
  assert.equal(challenge.id, hex(options.challenge));
  assert.equal(challenge.purpose, "register");
  assert.equal(challenge.binding, hex(b.jar.get(SESSION)));
  assert.equal(challenge.user_id, userOf(e, "ana@example.com"));
  assert.equal(challenge.expires_at - challenge.created_at, CHALLENGE_FOR);
  assert.equal(JSON.stringify(rows(e, "SELECT * FROM passkey_challenges")).includes(options.challenge), false);
  assert.deepEqual(rows(e, "SELECT user_id, handle FROM passkey_users"),
    [{ user_id: userOf(e, "ana@example.com"), handle: options.user.id }]);

  const made = device.create(options);
  const added = await b.post("/passkeys", { form: tokenFor(page.text, "/passkeys"), label: "  Work\u202e laptop\n ", ...made });
  assert.equal(added.status, 303, added.text);
  assert.equal(added.location, "/security");
  const [row] = passkeysOf(e, "ana@example.com");
  assert.deepEqual({ ...row, created_at: 0 }, {
    id: device.keys[0].id, user_id: userOf(e, "ana@example.com"), public_key: b64(cbor(device.keys[0].pair.cose)),
    sign_count: 1, transports: null, backed_up: 0, label: "Work laptop", created_at: 0, used_at: null,
  });
  assert.equal(coseKey(unb64(row.public_key)).alg, -7, "the stored key says its own algorithm");
  assert.ok(Math.abs(row.created_at - nowS()) < 5);
  assert.equal(eventsOf(e, "ana@example.com").at(-1), "passkey_added");
  /* The account's address is told, and told nothing about the passkey
     but that there is one. */
  const notice = s.emails.at(-1);
  assert.deepEqual(notice.to, ["ana@example.com"]);
  assert.equal(notice.subject, "A new way into your ranwhat account");
  assert.match(notice.text, /^A passkey was added to your ranwhat account \(ana@example\.com\)/);
  assert.ok(!JSON.stringify(notice).includes(device.keys[0].id) && !JSON.stringify(notice).includes("Work laptop"));
  assert.deepEqual(rows(e, "SELECT kind, sent FROM mail_counts ORDER BY kind"),
                   [{ kind: "auth", sent: 2 }], "an account made today: out of the public mail, with its sign-in code");
  assert.equal(rows(e, "SELECT used_at FROM passkey_challenges")[0].used_at > 0, true);

  /* The handle is made once; the passkey just added is left out next time. */
  const again = (await b.json("/passkeys/new")).body;
  assert.equal(again.user.id, options.user.id);
  assert.notEqual(again.challenge, options.challenge);
  assert.deepEqual(again.excludeCredentials, [{ type: "public-key", id: device.keys[0].id }]);

  home = await b.get("/security");
  assert.doesNotMatch(home.text, /<script/);
  assert.deepEqual(method(home.text, "passkeys"), ["Passkeys", "1 added"]);
  const date = new Date(nowS() * 1000).toISOString().slice(0, 10);
  assert.match(home.text, new RegExp(`<li><span>Work laptop, added ${date},\\s+never used</span><form method="post" action="/passkeys/remove"`));
  assert.match((await b.get("/")).text, /Passkey added, confirmed with an emailed code/);
});

test("adding a passkey takes RS256 and Ed25519 keys too, and labels are cleaned, never refused", async () => {
  const s = services();
  const e = env();
  const b = new Browser(e);
  await signInByCode(b, s, "ana@example.com");
  for (const make of [rs256, ed25519]) {
    const { res } = await addPasskey(b, new Device({ make }), { label: "" });
    assert.equal(res.status, 303, res.text);
  }
  assert.deepEqual(passkeysOf(e, "ana@example.com").map((p) => [coseKey(unb64(p.public_key)).alg, p.label]).sort(),
                   [[-257, "Passkey"], [-8, "Passkey"]]);
  assert.equal(passkeyLabel("x".repeat(500)), "x".repeat(MAX_LABEL));
  assert.equal(passkeyLabel("\u0000\u200b"), "Passkey");
  assert.equal(passkeyLabel(" Phone  \t one "), "Phone one");
  assert.equal(passkeyLabel("Work\nlaptop"), "Work laptop");
  assert.equal(passkeyLabel("a\u200b b"), "a b");
});

test("adding a passkey needs a session and a code typed in the last 15 minutes", async () => {
  const s = services();
  const e = env();
  const stranger = new Browser(e);
  const signedOutOptions = await stranger.json("/passkeys/new");
  assert.equal(signedOutOptions.status, 401);
  assert.equal((await stranger.get("/passkeys/add")).location, "/signin");

  const b = new Browser(e);
  await signInByCode(b, s, "ana@example.com");
  const device = new Device();
  const page = await b.get("/passkeys/add");
  later(FRESH_FOR - 2 * MINUTE);
  const options = (await b.json("/passkeys/new")).body;
  later(3 * MINUTE);
  /* The challenge is still in date; the code is not. */
  const late = await b.post("/passkeys", { form: tokenFor(page.text, "/passkeys"), label: "x", ...device.create(options) });
  assert.equal(late.status, 403);
  assert.match(late.text, /Adding or removing a passkey needs an emailed code typed in the last 15 minutes/);
  assert.equal(count(e, "passkeys"), 0);
  const stale = await b.json("/passkeys/new");
  assert.equal(stale.status, 403);
  assert.match(stale.body.error, /emailed code typed in the last 15 minutes/);
  const addPage = await b.get("/passkeys/add");
  assert.equal(addPage.status, 403);
  assert.doesNotMatch(addPage.text, /<script/);

  const home = await b.get("/security");
  assert.doesNotMatch(home.text, /href="\/passkeys\/add"/);
  assert.match(home.text, /<div class="callout warn" id="confirm">[^]*?[Aa]dding or removing a passkey[^.]* needs? an emailed code typed in the last 15 minutes/);
  assert.match(home.text, /data-method="passkeys">\s*<header class="card-head"><h3>[^]*?<\/h3><span class="pill">None added<\/span><span class="pill warn">Needs a code<\/span>/);
  await confirm(b, s);
  const { res } = await addPasskey(b, device);
  assert.equal(res.status, 303);
  assert.equal(count(e, "passkeys"), 1);
});

test("other accounts' mail never silences the email that tells of a passkey: without one, none is added", async () => {
  const s = services();
  const e = env();
  const b = new Browser(e);
  await signInByCode(b, s, "ana@example.com");
  later(DAY + MINUTE);            // an account older than a day
  await confirm(b, s);
  const day = new Date(Date.now()).toISOString().slice(0, 10);
  const used = (kind, sent) => e.LIST.sql.prepare(
    "INSERT OR REPLACE INTO mail_counts (day, kind, sent) VALUES (?, ?, ?)").run(day, kind, sent);

  /* Other accounts have used up the day's signed-in reserve: the email
     goes all the same, from the public mail. */
  used("auth-stepup", STEPUP_RESERVE);
  const device = new Device();
  const before = s.emails.length;
  const { res } = await addPasskey(b, device);
  assert.equal(res.status, 303, res.text);
  assert.equal(s.emails.length, before + 1);
  assert.equal(s.emails.at(-1).subject, "A new way into your ranwhat account");
  assert.deepEqual(s.emails.at(-1).to, ["ana@example.com"]);

  /* With the public mail used up as well, no passkey is added without its
     email, and nothing is spent. */
  used("auth", AUTH_MAIL_PER_DAY - STEPUP_RESERVE);
  const again = await addPasskey(b, device, { label: "Phone" });
  assert.equal(again.res.status, 503);
  assert.match(again.res.text, /No passkey was added/);
  assert.equal(passkeysOf(e, "ana@example.com").length, 1);
  assert.equal(s.emails.length, before + 1);
  assert.deepEqual(rows(e, "SELECT kind, sent FROM mail_counts WHERE day = ? ORDER BY kind", day),
                   [{ kind: "auth", sent: AUTH_MAIL_PER_DAY - STEPUP_RESERVE }, { kind: "auth-stepup", sent: STEPUP_RESERVE }]);
  assert.equal(eventsOf(e, "ana@example.com").filter((x) => x === "passkey_added").length, 1);
});

/* ---------- challenges ---------- */

test("a challenge expires after five minutes and works once, whether or not what came with it checked out", async () => {
  const s = services();
  const e = env();
  const b = new Browser(e);
  await signInByCode(b, s, "ana@example.com");
  const device = new Device();

  /* Registering. */
  let page = await b.get("/passkeys/add");
  let options = (await b.json("/passkeys/new")).body;
  later(CHALLENGE_FOR + 1);
  const expired = await b.post("/passkeys", { form: tokenFor(page.text, "/passkeys"), label: "x", ...device.create(options) });
  assert.equal(expired.status, 400);
  assert.match(expired.text, /That passkey request has expired or was already used/);
  assert.equal(count(e, "passkeys"), 0);

  page = await b.get("/passkeys/add");
  options = (await b.json("/passkeys/new")).body;
  const made = device.create(options);
  const broken = { ...made, clientDataJSON: b64(clientData({ type: "webauthn.create", challenge: options.challenge,
                                                                origin: "https://evil.example" })) };
  const bad = await b.post("/passkeys", { form: tokenFor(page.text, "/passkeys"), label: "x", ...broken });
  assert.equal(bad.status, 400);
  assert.match(bad.text, /did not check out/);
  const afterBad = await b.post("/passkeys", { form: tokenFor(page.text, "/passkeys"), label: "x", ...made });
  assert.equal(afterBad.status, 400, "the failed try used the challenge");
  assert.match(afterBad.text, /expired or was already used/);

  options = (await b.json("/passkeys/new")).body;
  const good = device.create(options);
  assert.equal((await b.post("/passkeys", { form: tokenFor(page.text, "/passkeys"), label: "x", ...good })).status, 303);
  const replay = await b.post("/passkeys", { form: tokenFor(page.text, "/passkeys"), label: "x", ...good });
  assert.equal(replay.status, 400);
  assert.equal(count(e, "passkeys"), 1);

  /* Signing in. */
  const other = new Browser(e, { ip: "203.0.113.5" });
  const signinPage = await other.get("/signin/passkey");
  const token = tokenFor(signinPage.text, "/signin/passkey");
  let challenge = (await other.json("/passkeys/challenge")).body;
  assert.deepEqual(Object.keys(challenge).sort(), ["allowCredentials", "challenge", "rpId", "timeout", "userVerification"]);
  assert.deepEqual(challenge.allowCredentials, []);
  assert.equal(challenge.rpId, "account.ranwhat.com");
  assert.equal(challenge.userVerification, "required");
  const [row] = rows(e, "SELECT * FROM passkey_challenges WHERE purpose = 'signin'");
  assert.equal(row.binding, hex(other.jar.get(SIGNIN)));
  assert.equal(row.user_id, null);
  later(CHALLENGE_FOR + 1);
  const late = await other.post("/signin/passkey", { form: token, next: "/", ...device.get(challenge) });
  assert.equal(late.status, 400);
  assert.equal(other.jar.has(SESSION), false);

  challenge = (await other.json("/passkeys/challenge")).body;
  const answer = device.get(challenge);
  const cookie = other.jar.get(SIGNIN);
  const first = await other.post("/signin/passkey", { form: token, next: "/", ...answer });
  assert.equal(first.status, 303, first.text);
  /* The same answer again, from the same browser as it was before it
     signed in: the challenge is spent. */
  const before = new Browser(e, { ip: "203.0.113.5" });
  before.jar.set(SIGNIN, cookie);
  const again = await before.post("/signin/passkey", { form: token, next: "/", ...answer });
  assert.equal(again.status, 400, "an answer works once");
  assert.equal(before.jar.has(SESSION), false);
});

test("a challenge works only for the session, or the browser, it was given to", async () => {
  const s = services();
  const e = env();
  const a = new Browser(e);
  await signInByCode(a, s, "ana@example.com");
  const b = new Browser(e, { ip: "203.0.113.7" });
  await signInByCode(b, s, "ana@example.com");
  const bo = new Browser(e, { ip: "203.0.113.8" });
  await signInByCode(bo, s, "bo@example.com");
  const device = new Device();

  /* A's options, posted by B (the same account, another session) and by
     Bo (another account): neither can use them, and A still can. */
  await a.get("/passkeys/add");
  const options = (await a.json("/passkeys/new")).body;
  const made = device.create(options);
  for (const thief of [b, bo]) {
    const page = await thief.get("/passkeys/add");
    const res = await thief.post("/passkeys", { form: tokenFor(page.text, "/passkeys"), label: "x", ...made });
    assert.equal(res.status, 400);
    assert.match(res.text, /expired or was already used/);
  }
  assert.equal(count(e, "passkeys"), 0);
  const page = await a.get("/passkeys/add");
  assert.equal((await a.post("/passkeys", { form: tokenFor(page.text, "/passkeys"), label: "x", ...made })).status, 303);

  /* A sign-in challenge fetched by one browser, answered from another. */
  const one = new Browser(e, { ip: "192.0.2.10" });
  const two = new Browser(e, { ip: "192.0.2.11" });
  await one.get("/signin/passkey");
  const challenge = (await one.json("/passkeys/challenge")).body;
  const answer = device.get(challenge);
  const twoPage = await two.get("/signin/passkey");
  const stolen = await two.post("/signin/passkey", { form: tokenFor(twoPage.text, "/signin/passkey"), next: "/", ...answer });
  assert.equal(stolen.status, 400);
  assert.equal(two.jar.has(SESSION), false);
  const onePage = await one.get("/signin/passkey");
  const mine = await one.post("/signin/passkey", { form: tokenFor(onePage.text, "/signin/passkey"), next: "/", ...answer });
  assert.equal(mine.status, 303, mine.text);

  /* Without the sign-in cookie there is no challenge to be had. */
  const bare = new Browser(e, { ip: "192.0.2.12" });
  assert.equal((await bare.json("/passkeys/challenge")).status, 403);
  assert.equal(count(e, "passkey_challenges"), 2);
});

test("sign-in challenges are limited per network, registration options per account", async () => {
  const s = services();
  const e = env();
  const b = new Browser(e, { ip: "2001:db8:1:2::1" });
  await b.get("/signin/passkey");
  for (let i = 0; i < CHALLENGES_PER_NETWORK; i++) assert.equal((await b.json("/passkeys/challenge")).status, 200);
  const over = await b.json("/passkeys/challenge");
  assert.equal(over.status, 429);
  assert.match(over.body.error, /from your network in the last hour/);
  /* Another address in the same /64 is the same network; another is not. */
  const twin = new Browser(e, { ip: "2001:db8:1:2::99" });
  await twin.get("/signin/passkey");
  assert.equal((await twin.json("/passkeys/challenge")).status, 429);
  const elsewhere = new Browser(e, { ip: "2001:db8:1:3::1" });
  await elsewhere.get("/signin/passkey");
  assert.equal((await elsewhere.json("/passkeys/challenge")).status, 200);

  const ana = new Browser(e);
  await signInByCode(ana, s, "ana@example.com");
  for (let i = 0; i < OPTIONS_PER_USER; i++) assert.equal((await ana.json("/passkeys/new")).status, 200);
  assert.equal((await ana.json("/passkeys/new")).status, 429);
});

/* ---------- forms from elsewhere ---------- */

test("the passkey forms need this host's origin and their own token; the JSON is not for other sites", async () => {
  const s = services();
  const e = env();
  const { b, device } = await withPasskey(e, s);
  const page = await b.get("/passkeys/add");
  const token = tokenFor(page.text, "/passkeys");
  const options = (await b.json("/passkeys/new")).body;
  const made = device.create(options);
  const challenges = count(e, "passkey_challenges");

  const elsewhere = [
    {},
    { origin: "https://evil.example" },
    { "sec-fetch-site": "same-site", origin: "https://ranwhat.com" },
    { "sec-fetch-site": "cross-site" },
  ];
  for (const headers of elsewhere) {
    assert.equal((await b.post("/passkeys", { form: token, label: "x", ...made }, headers)).status, 403);
  }
  const wrongToken = await formToken(e, hex(b.jar.get(SESSION)), "passkey-remove");
  assert.equal((await b.post("/passkeys", { form: wrongToken, label: "x", ...made })).status, 403);
  assert.equal((await b.post("/passkeys", { label: "x", ...made })).status, 403);
  assert.equal(count(e, "passkeys"), 1);

  for (const headers of [{ "sec-fetch-site": "cross-site" }, { "sec-fetch-site": "same-site" }, { origin: "https://evil.example" }]) {
    assert.equal((await b.json("/passkeys/new", headers)).status, 403);
    assert.equal((await b.json("/passkeys/challenge", headers)).status, 403);
  }
  assert.equal(count(e, "passkey_challenges"), challenges, "nothing was made for another site");
  /* A browser that sends neither header still gets its options. */
  assert.equal((await b.json("/passkeys/new", {})).status, 200);

  const remove = await formToken(e, hex(b.jar.get(SESSION)), "passkey-remove");
  for (const headers of elsewhere) {
    assert.equal((await b.post("/passkeys/remove", { form: remove, id: device.keys[0].id }, headers)).status, 403);
  }
  assert.equal((await b.post("/passkeys/remove", { form: token, id: device.keys[0].id })).status, 403);
  assert.equal(count(e, "passkeys"), 1);

  const fresh = new Browser(e, { ip: "203.0.113.20" });
  const signinPage = await fresh.get("/signin/passkey");
  const signinToken = tokenFor(signinPage.text, "/signin/passkey");
  const challenge = (await fresh.json("/passkeys/challenge")).body;
  const answer = device.get(challenge, { key: device.keys[0] });
  for (const headers of elsewhere) {
    assert.equal((await fresh.post("/signin/passkey", { form: signinToken, next: "/", ...answer }, headers)).status, 403);
  }
  const otherToken = await formToken(e, fresh.jar.get(SIGNIN), "signin");
  assert.equal((await fresh.post("/signin/passkey", { form: otherToken, next: "/", ...answer })).status, 403);
  assert.equal(fresh.jar.has(SESSION), false);
  /* None of those spent the challenge. */
  assert.equal((await fresh.post("/signin/passkey", { form: signinToken, next: "/", ...answer })).status, 303);
});

/* ---------- signing in ---------- */

test("someone whose only way in besides the code is a passkey signs in with it", async () => {
  const s = services();
  const e = env();
  const { device } = await withPasskey(e, s);
  assert.equal(count(e, "credentials"), 0, "no password");
  assert.deepEqual(rows(e, "SELECT provider FROM identities"), [{ provider: "email" }]);
  const mails = s.emails.length;

  const b = new Browser(e, { ip: "203.0.113.30" });
  const home = await b.get("/");
  assert.equal(home.location, "/signin");
  const page = await b.get("/signin/passkey");
  assert.match(page.text, /<form method="post" action="\/signin\/passkey" data-passkey="\/passkeys\/challenge" data-ceremony="get">/);
  assert.match(page.headers.get("content-security-policy"),
    /; script-src https:\/\/account\.ranwhat\.com\/passkeys\.js; connect-src https:\/\/account\.ranwhat\.com\/passkeys\/new https:\/\/account\.ranwhat\.com\/passkeys\/challenge$/);
  assert.deepEqual(page.text.match(/<script[^>]*>/g), ['<script src="/passkeys.js" defer>']);
  const res = await passkeySignIn(b, device);
  assert.equal(res.status, 303, res.text);
  assert.equal(res.location, "/");
  assert.equal(b.jar.has(SIGNIN), false);
  assert.equal(s.emails.length, mails, "no email");

  const signedIn = await b.get("/");
  assert.equal(signedIn.status, 200);
  assert.match(signedIn.text, /ana@example\.com/);
  assert.match(signedIn.text, /Signed in with a passkey/);
  assert.equal(eventsOf(e, "ana@example.com").at(-1), "signin_passkey");
  /* Not fresh: what needs a code still needs one. */
  assert.equal(sessionOf(e, b).authed_at, 0);
  const security = await b.get("/security");
  assert.match(security.text, /<div class="callout warn" id="confirm">[^]*?[Aa]dding or removing a passkey[^.]* needs? an emailed code/);
  const [row] = passkeysOf(e, "ana@example.com");
  assert.equal(row.sign_count, 2);
  assert.equal(row.used_at, today() * DAY, "the day, and no finer");
  const date = new Date(today() * DAY * 1000).toISOString().slice(0, 10);
  assert.match(security.text, new RegExp(`last used ${date}`));

  /* Signed in already: the page sends you on. */
  assert.equal((await b.get("/signin/passkey")).location, "/");
  /* The sign-in page offers it. */
  const signin = await new Browser(e, { ip: "203.0.113.31" }).get("/signin");
  assert.match(signin.text, /<a href="\/signin\/passkey">Sign in with it<\/a>/);
});

test("the counter is written on every sign-in, and one that does not go up is refused", async () => {
  const s = services();
  const e = env();
  const { device } = await withPasskey(e, s);
  const counted = (n) => assert.equal(passkeysOf(e, "ana@example.com")[0].sign_count, n);
  counted(1);
  const b = new Browser(e, { ip: "203.0.113.40" });
  assert.equal((await passkeySignIn(b, device, { signCount: 5 })).status, 303);
  counted(5);
  for (const n of [5, 4, 0]) {
    const res = await passkeySignIn(new Browser(e, { ip: "203.0.113.41" }), device, { signCount: n });
    assert.equal(res.status, 400, `count ${n}`);
  }
  counted(5);
  assert.equal((await passkeySignIn(new Browser(e, { ip: "203.0.113.42" }), device, { signCount: 6 })).status, 303);
  counted(6);

  /* A passkey whose counter always says 0, as synced ones do. */
  const synced = new Device({ counts: false });
  const bo = new Browser(e, { ip: "203.0.113.43" });
  await signInByCode(bo, s, "bo@example.com");
  assert.equal((await addPasskey(bo, synced)).res.status, 303);
  for (let i = 0; i < 3; i++) {
    assert.equal((await passkeySignIn(new Browser(e, { ip: "203.0.113.44" }), synced)).status, 303);
  }
  assert.equal(passkeysOf(e, "bo@example.com")[0].sign_count, 0);
  assert.equal(passkeysOf(e, "bo@example.com")[0].used_at, today() * DAY);
});

test("every way a passkey can fail to sign in gets the same answer", async () => {
  const s = services();
  const e = env();
  const { device } = await withPasskey(e, s);
  const bo = await withPasskey(e, s, "bo@example.com", new Device());
  const forger = es256();
  const b = new Browser(e, { ip: "203.0.113.50" });
  const answers = {
    "an unknown passkey": (o) => ({ ...device.get(o), id: b64(randomBytes(16)) }),
    "another account's handle": (o) => device.get(o, { handle: bo.device.keys[0].handle }),
    "no handle": (o) => device.get(o, { handle: "" }),
    "a signature by another key": (o) => device.get(o, { signer: forger }),
    "another passkey's id": (o) => ({ ...device.get(o), id: bo.device.keys[0].id }),
    "another site": (o) => device.get(o, { origin: "https://evil.example" }),
    "no user verification": (o) => device.get(o, { flags: UP }),
    "a challenge we never gave": () => device.get({ challenge: b64(randomBytes(32)) }),
    "a counter that went back": (o) => device.get(o, { signCount: 1 }),
    "nothing at all (no script)": () => ({}),
  };
  const texts = new Set();
  for (const [name, answer] of Object.entries(answers)) {
    const res = await passkeySignIn(b, device, answer);
    assert.equal(res.status, 400, name);
    assert.equal(b.jar.has(SESSION), false, name);
    texts.add(res.text);
  }
  assert.equal(texts.size, 1);
  assert.match([...texts][0], /That passkey did not sign you in\. Try again, or sign in another way\./);
  assert.equal((await passkeySignIn(b, device)).status, 303, "and the passkey still works");
});

/* ---------- taking one away ---------- */

test("removing a passkey: a fresh code, only your own, and it no longer signs in", async () => {
  const s = services();
  const e = env();
  const { b, device } = await withPasskey(e, s);
  const bo = await withPasskey(e, s, "bo@example.com", new Device());
  const second = new Device();
  assert.equal((await addPasskey(b, second, { label: "Phone" })).res.status, 303);
  assert.equal(passkeysOf(e, "ana@example.com").length, 2);

  let home = await b.get("/security");
  assert.deepEqual(method(home.text, "passkeys"), ["Passkeys", "2 added"]);
  const remove = tokenFor(home.text, "/passkeys/remove");

  /* Someone else's passkey: nothing happens. */
  assert.equal((await b.post("/passkeys/remove", { form: remove, id: bo.device.keys[0].id })).status, 303);
  assert.equal(passkeysOf(e, "bo@example.com").length, 1);
  assert.equal((await b.post("/passkeys/remove", { form: remove, id: "" })).status, 303);

  /* Without a fresh code: refused, and no form to do it with. */
  later(FRESH_FOR + 1);
  home = await b.get("/security");
  assert.doesNotMatch(home.text, /action="\/passkeys\/remove"/);
  await onNoPage(b, /action="\/passkeys\/remove"|href="\/passkeys\/add"/, { why: "removing or adding a passkey without a fresh code" });
  const late = await b.post("/passkeys/remove", { form: remove, id: device.keys[0].id });
  assert.equal(late.status, 403);
  assert.match(late.text, /Adding or removing a passkey needs an emailed code typed in the last 15 minutes/);
  assert.equal(passkeysOf(e, "ana@example.com").length, 2);

  /* A step-up opens a new session, so the page's forms are new too. */
  await confirm(b, s);
  assert.equal((await b.post("/passkeys/remove", { form: remove, id: device.keys[0].id })).status, 403);
  home = await b.get("/security");
  const removeNow = tokenFor(home.text, "/passkeys/remove");
  assert.equal((await b.post("/passkeys/remove", { form: removeNow, id: device.keys[0].id })).status, 303);
  assert.deepEqual(passkeysOf(e, "ana@example.com").map((p) => p.label), ["Phone"]);
  assert.equal(eventsOf(e, "ana@example.com").at(-1), "passkey_removed");
  const gone = await passkeySignIn(new Browser(e, { ip: "203.0.113.60" }), device);
  assert.equal(gone.status, 400);
  assert.equal((await passkeySignIn(new Browser(e, { ip: "203.0.113.61" }), second)).status, 303);

  /* The last one can go too: the emailed code is always a way in. */
  assert.equal((await b.post("/passkeys/remove", { form: removeNow, id: second.keys[0].id })).status, 303);
  assert.equal(passkeysOf(e, "ana@example.com").length, 0);
  home = await b.get("/security");
  assert.deepEqual(method(home.text, "passkeys"), ["Passkeys", "None added"]);
  assert.match((await b.get("/")).text, /Passkey removed/);
  const back = new Browser(e, { ip: "203.0.113.62" });
  await signInByCode(back, s, "ana@example.com");
  assert.equal((await back.get("/")).status, 200);
});

test("removing a passkey ends every other session of the account, the one it opened among them, and the page says so", async () => {
  const s = services();
  const e = env();
  const { b, device } = await withPasskey(e, s);
  const thief = new Browser(e, { ip: "203.0.113.63" });
  assert.equal((await passkeySignIn(thief, device)).status, 303);
  assert.equal((await thief.get("/")).status, 200);

  const home = await b.get("/security");
  const r = await b.post("/passkeys/remove", { form: tokenFor(home.text, "/passkeys/remove"), id: device.keys[0].id });
  assert.equal(r.status, 303, r.text);
  assert.equal(passkeysOf(e, "ana@example.com").length, 0);
  assert.equal((await thief.get("/")).location, "/signin", "the passkey's session is over");
  assert.equal((await b.get("/")).status, 200, "this one goes on");
  assert.equal(count(e, "sessions"), 1);
  assert.match((await b.get("/")).text, /Passkey removed, and every other session signed out/);
  assert.match(home.text, /Removing one signs this account out everywhere else\./);
});

/* ---------- the script ---------- */

/* Runs /passkeys.js against a stand-in of the page `html`: its form, its
   fields, fetch() to the Worker from browser `b`, and the device as
   navigator.credentials, with ArrayBuffers where a browser has them.
   Returns what the form would send, or the problem the page shows. */
async function runScript(b, html, device, { supported = true, answer = {} } = {}) {
  const m = html.match(/<form method="post" action="([^"]+)" data-passkey="([^"]+)" data-ceremony="([^"]+)">([\s\S]*?)<\/form>/);
  assert.ok(m, "a passkey form");
  const [, action, path, ceremony, inner] = m;
  const fields = new Map();
  for (const [, attributes] of inner.matchAll(/<input([^>]*)>/g)) {
    const name = /name="([^"]*)"/.exec(attributes)[1];
    const value = /value="([^"]*)"/.exec(attributes);
    fields.set(name, { value: value ? value[1] : "" });
  }
  let handler = null;
  let sent = null;
  const problem = { hidden: true, textContent: "" };
  const button = { disabled: false };
  const form = {
    getAttribute: (name) => ({ "data-passkey": path, "data-ceremony": ceremony })[name] ?? null,
    querySelector: (selector) => ({ button, ".passkey-problem": problem })[selector] ?? null,
    elements: { namedItem: (name) => fields.get(name) },
    addEventListener: (type, fn) => { assert.equal(type, "submit"); handler = fn; },
    submit: () => { sent = Object.fromEntries([...fields].map(([k, v]) => [k, v.value])); },
  };
  const buffer = (text) => unb64(text).buffer;
  const credentials = {
    async create({ publicKey }) {
      assert.ok(publicKey.challenge instanceof Uint8Array && publicKey.user.id instanceof Uint8Array);
      for (const c of publicKey.excludeCredentials) assert.ok(c.id instanceof Uint8Array);
      const made = device.create({ ...publicKey, challenge: b64(publicKey.challenge), user: { ...publicKey.user, id: b64(publicKey.user.id) } });
      return { rawId: buffer(device.keys.at(-1).id),
               response: { clientDataJSON: buffer(made.clientDataJSON), attestationObject: buffer(made.attestationObject) } };
    },
    async get({ publicKey }) {
      assert.ok(publicKey.challenge instanceof Uint8Array);
      const got = device.get({ ...publicKey, challenge: b64(publicKey.challenge) }, answer);
      return { rawId: buffer(got.id), response: {
        clientDataJSON: buffer(got.clientDataJSON), authenticatorData: buffer(got.authenticatorData),
        signature: buffer(got.signature), userHandle: got.userHandle ? buffer(got.userHandle) : null } };
    },
  };
  const fetchHere = async (url, init) => {
    assert.equal(init.credentials, "same-origin");
    const r = await b.get(url, FETCHED);
    return { ok: r.status >= 200 && r.status < 300, json: async () => JSON.parse(r.text) };
  };
  const window = supported ? { PublicKeyCredential: function PublicKeyCredential() {} } : {};
  const document = { querySelector: (selector) => (selector === "form[data-passkey]" ? form : null) };
  new Function("window", "document", "navigator", "fetch", PAGE_SCRIPT)(window, document, { credentials }, fetchHere);
  if (!supported) return { problem, button };
  assert.ok(handler, "the script listens for the form");
  let prevented = false;
  handler({ preventDefault: () => { prevented = true; } });
  assert.ok(prevented);
  for (let i = 0; i < 200 && !sent && problem.hidden; i++) await new Promise((r) => setTimeout(r, 5));
  return { action, sent, problem, button };
}

test("/passkeys.js adds a passkey and signs in with it, posting the page's own form", async () => {
  const s = services();
  const e = env();
  const b = new Browser(e);
  await signInByCode(b, s, "ana@example.com");
  const device = new Device();

  const served = await b.get("/passkeys.js");
  assert.equal(served.status, 200);
  assert.equal(served.headers.get("content-type"), "text/javascript; charset=utf-8");
  assert.equal(served.headers.get("x-content-type-options"), "nosniff");
  assert.equal(served.text, PAGE_SCRIPT);
  assert.equal((await b.post("/passkeys.js", {})).status, 405);

  const page = await b.get("/passkeys/add");
  const made = await runScript(b, page.text, device);
  assert.equal(made.problem.hidden, true, made.problem.textContent);
  assert.equal(made.action, "/passkeys");
  assert.deepEqual(Object.keys(made.sent).sort(), ["attestationObject", "clientDataJSON", "form", "label"]);
  made.sent.label = "Laptop";
  assert.equal((await b.post(made.action, made.sent)).status, 303);
  assert.deepEqual(passkeysOf(e, "ana@example.com").map((p) => p.id), [device.keys[0].id]);

  const other = new Browser(e, { ip: "203.0.113.70" });
  const signin = await other.get("/signin/passkey");
  const got = await runScript(other, signin.text, device);
  assert.equal(got.problem.hidden, true, got.problem.textContent);
  assert.deepEqual(Object.keys(got.sent).sort(),
    ["authenticatorData", "clientDataJSON", "form", "id", "next", "signature", "userHandle"]);
  assert.equal(got.sent.id, device.keys[0].id);
  const res = await other.post(got.action, got.sent);
  assert.equal(res.status, 303, res.text);
  assert.equal((await other.get("/")).status, 200);

  /* What the server refuses, the page says; a browser without passkeys is
     told so and its button is off. */
  later(FRESH_FOR + 1);
  const stale = await runScript(b, page.text, device);
  assert.equal(stale.sent, null);
  assert.match(stale.problem.textContent, /emailed code typed in the last 15 minutes/);
  assert.equal(stale.button.disabled, false);
  const old = await runScript(b, page.text, device, { supported: false });
  assert.match(old.problem.textContent, /This browser cannot use passkeys/);
  assert.equal(old.button.disabled, true);
});

test("the account page and every other page stay script-free; passkeys are dark with the rest", async () => {
  const s = services();
  const e = env();
  const { b } = await withPasskey(e, s);
  for (const path of ["/", "/signin/password"]) {
    const r = await b.get(path);
    assert.doesNotMatch(r.text, /<script/, path);
    assert.doesNotMatch(r.headers.get("content-security-policy"), /script-src|connect-src/, path);
  }
  const dark = env({ ACCOUNTS_ON: "" });
  for (const path of ["/passkeys.js", "/signin/passkey", "/passkeys/challenge"]) {
    assert.equal((await new Browser(dark).get(path)).status, 404, path);
  }
});

test("the sweep deletes challenges once used or out of date", async () => {
  const s = services();
  const e = env();
  const { b, device } = await withPasskey(e, s);
  await b.json("/passkeys/new");
  const other = new Browser(e, { ip: "203.0.113.80" });
  assert.equal((await passkeySignIn(other, device)).status, 303);
  assert.equal(count(e, "passkey_challenges"), 3);
  const waits = [];
  await worker.scheduled({}, e, { waitUntil: (p) => waits.push(p) });
  await Promise.all(waits.map((p) => p.catch(() => {})));
  assert.equal(count(e, "passkey_challenges"), 1, "the one in date and unused stays");
  later(CHALLENGE_FOR + 1);
  waits.length = 0;
  await worker.scheduled({}, e, { waitUntil: (p) => waits.push(p) });
  await Promise.all(waits.map((p) => p.catch(() => {})));
  assert.equal(count(e, "passkey_challenges"), 0);
  assert.equal(count(e, "passkeys"), 1);
});

/* ---------- a database the first deploy made ---------- */

/* The tables the first accounts deploy made (wave 1, merged before passkeys
   were written), as it made them: they are in every D1 where ACCOUNTS_ON
   was ever set, and CREATE TABLE IF NOT EXISTS leaves each as it is. */
const WAVE_1 = [
  `CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE COLLATE NOCASE, created_at
   INTEGER NOT NULL, signed_in_at INTEGER)`,
  `CREATE TABLE IF NOT EXISTS identities (provider TEXT NOT NULL, provider_subject TEXT NOT NULL, user_id TEXT
   NOT NULL, verified_email TEXT COLLATE NOCASE, created_at INTEGER NOT NULL, used_at INTEGER, PRIMARY KEY
   (provider, provider_subject))`,
  `CREATE INDEX IF NOT EXISTS identities_user ON identities (user_id)`,
  `CREATE TABLE IF NOT EXISTS credentials (user_id TEXT NOT NULL, kind TEXT NOT NULL CHECK (kind IN
   ('password')), hash TEXT NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, PRIMARY KEY
   (user_id, kind))`,
  `CREATE TABLE IF NOT EXISTS passkeys (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, public_key TEXT NOT NULL,
   sign_count INTEGER NOT NULL DEFAULT 0, transports TEXT, backed_up INTEGER NOT NULL DEFAULT 0, label TEXT,
   created_at INTEGER NOT NULL, used_at INTEGER)`,
  `CREATE INDEX IF NOT EXISTS passkeys_user ON passkeys (user_id)`,
  `CREATE TABLE IF NOT EXISTS orgs (id TEXT PRIMARY KEY, name TEXT NOT NULL, personal INTEGER NOT NULL DEFAULT
   1, customer TEXT, created_at INTEGER NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS memberships (org_id TEXT NOT NULL, user_id TEXT NOT NULL, role TEXT NOT NULL
   CHECK (role IN ('owner', 'admin', 'member')), created_at INTEGER NOT NULL, PRIMARY KEY (org_id, user_id))`,
  `CREATE INDEX IF NOT EXISTS memberships_user ON memberships (user_id)`,
  `CREATE UNIQUE INDEX IF NOT EXISTS one_owner ON memberships (org_id) WHERE role = 'owner'`,
  `CREATE TABLE IF NOT EXISTS invites (id TEXT PRIMARY KEY, org_id TEXT NOT NULL, email TEXT COLLATE NOCASE,
   role TEXT NOT NULL CHECK (role IN ('admin', 'member')), token_hash TEXT NOT NULL UNIQUE, invited_by TEXT,
   created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, accepted_at INTEGER, revoked_at INTEGER)`,
  `CREATE UNIQUE INDEX IF NOT EXISTS open_invite ON invites (org_id, email) WHERE accepted_at IS NULL AND
   revoked_at IS NULL`,
  `CREATE TABLE IF NOT EXISTS org_subscriptions (subscription TEXT PRIMARY KEY, org_id TEXT NOT NULL, how TEXT
   NOT NULL CHECK (how IN ('checkout', 'session', 'email', 'script')), linked_by TEXT, linked_at INTEGER NOT
   NULL)`,
  `CREATE INDEX IF NOT EXISTS org_subscriptions_org ON org_subscriptions (org_id)`,
  `CREATE TABLE IF NOT EXISTS grants (id INTEGER PRIMARY KEY, org_id TEXT NOT NULL, plan TEXT NOT NULL CHECK
   (plan IN ('plus', 'team')), starts_at INTEGER NOT NULL, until INTEGER, note TEXT, created_at INTEGER NOT
   NULL)`,
  `CREATE INDEX IF NOT EXISTS grants_org ON grants (org_id)`,
  `CREATE TABLE IF NOT EXISTS machines (id TEXT PRIMARY KEY, hash TEXT NOT NULL UNIQUE, org_id TEXT NOT NULL,
   user_id TEXT, kind TEXT NOT NULL CHECK (kind IN ('device', 'ci', 'legacy')), label TEXT NOT NULL, created_at
   INTEGER NOT NULL, last_used_day INTEGER)`,
  `CREATE INDEX IF NOT EXISTS machines_org ON machines (org_id)`,
  `CREATE TABLE IF NOT EXISTS sessions (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, org_id TEXT, created_at
   INTEGER NOT NULL, seen_at INTEGER NOT NULL, authed_at INTEGER NOT NULL, expires_at INTEGER NOT NULL)`,
  `CREATE INDEX IF NOT EXISTS sessions_user ON sessions (user_id)`,
  `CREATE TABLE IF NOT EXISTS signins (id TEXT PRIMARY KEY, email TEXT NOT NULL, email_mac TEXT NOT NULL,
   purpose TEXT NOT NULL CHECK (purpose IN ('signin', 'stepup', 'verify', 'reset')), user_id TEXT, code_mac
   TEXT NOT NULL, password_hash TEXT, next TEXT NOT NULL DEFAULT '/', created_at INTEGER NOT NULL, expires_at
   INTEGER NOT NULL, tries INTEGER NOT NULL DEFAULT 0, mailed INTEGER NOT NULL DEFAULT 0, used_at INTEGER)`,
  `CREATE INDEX IF NOT EXISTS signins_email ON signins (email_mac, created_at)`,
  `CREATE TABLE IF NOT EXISTS device_codes (device_hash TEXT PRIMARY KEY, user_code_mac TEXT NOT NULL UNIQUE,
   country TEXT, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, polled_at INTEGER, interval INTEGER
   NOT NULL DEFAULT 5, state TEXT NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'approved', 'denied',
   'issued')), user_id TEXT, org_id TEXT, label TEXT, decided_at INTEGER)`,
  `CREATE TABLE IF NOT EXISTS auth_events (id INTEGER PRIMARY KEY AUTOINCREMENT, org_id TEXT, user_id TEXT,
   event TEXT NOT NULL, subject TEXT, at INTEGER NOT NULL)`,
  `CREATE INDEX IF NOT EXISTS auth_events_org ON auth_events (org_id, at)`,
  `CREATE INDEX IF NOT EXISTS auth_events_user ON auth_events (user_id, at)`,
  `CREATE TABLE IF NOT EXISTS throttle (key TEXT PRIMARY KEY, window_start INTEGER NOT NULL, count INTEGER NOT
   NULL)`,
  `CREATE TABLE IF NOT EXISTS mail_counts (day TEXT NOT NULL, kind TEXT NOT NULL, sent INTEGER NOT NULL,
   PRIMARY KEY (day, kind))`,
  `INSERT OR IGNORE INTO settings (key, value) VALUES ('accounts_schema', '1')`,
];

const columns = (e, table) => rows(e, `SELECT name, type, "notnull", dflt_value, pk FROM pragma_table_info('${table}')`);

test("a database the first deploy made: every table it has keeps the columns today's code uses", async () => {
  const old = env();
  for (const sql of WAVE_1) old.LIST.sql.exec(sql);
  await schema(old.LIST);
  const made = env();
  await schema(made.LIST);
  const tables = (e) => rows(e, "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name").map((r) => r.name);
  assert.deepEqual(tables(old), tables(made), "the tables made since are added");
  for (const table of tables(made)) assert.deepEqual(columns(old, table), columns(made, table), table);
  assert.deepEqual(columns(old, "passkeys").map((c) => c.name),
                   ["id", "user_id", "public_key", "sign_count", "transports", "backed_up", "label", "created_at", "used_at"]);
});

test("a database the first deploy made: the account page, adding a passkey, signing in with it, removing it and the sweep work", async () => {
  const s = services();
  const e = env();
  for (const sql of WAVE_1) e.LIST.sql.exec(sql);
  const b = new Browser(e);
  await signInByCode(b, s, "ana@example.com");
  for (const path of ["/", "/machines", "/members", "/billing", "/activity"]) {
    const shown = await b.get(path);
    assert.equal(shown.status, 200, `${path}: ${shown.text}`);
  }
  let home = await b.get("/security");
  assert.equal(home.status, 200, home.text);
  assert.deepEqual(method(home.text, "passkeys"), ["Passkeys", "None added"]);
  const device = new Device();
  const { res } = await addPasskey(b, device);
  assert.equal(res.status, 303, res.text);
  const signedIn = await passkeySignIn(new Browser(e, { ip: "203.0.113.90" }), device);
  assert.equal(signedIn.status, 303, signedIn.text);
  assert.equal(passkeysOf(e, "ana@example.com")[0].used_at, today() * DAY);
  home = await b.get("/security");
  assert.match(home.text, new RegExp(`Work laptop, added [0-9-]+,\\s+last used ${new Date(today() * DAY * 1000).toISOString().slice(0, 10)}`));

  for (const on of ["1", ""]) {
    const waits = [];
    await worker.scheduled({}, { ...e, ACCOUNTS_ON: on }, { waitUntil: (p) => waits.push(p) });
    await Promise.all(waits);
  }
  await sweep(e);
  assert.equal(count(e, "passkey_challenges"), 0, "used challenges are swept");

  const removed = await b.post("/passkeys/remove", { form: tokenFor(home.text, "/passkeys/remove"), id: device.keys[0].id });
  assert.equal(removed.status, 303, removed.text);
  assert.equal(count(e, "passkeys"), 0);
  assert.equal(rows(e, "SELECT value FROM settings WHERE key = 'accounts_schema'")[0].value, "1");
});
