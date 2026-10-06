/* Accounts on account.ranwhat.com: the Worker's own fetch and scheduled
 * handlers over a real SQLite database (node:sqlite, which is what D1
 * runs), with Resend answered by a stand-in that keeps every email, and a
 * browser stand-in that keeps cookies as a browser does and sends the
 * headers a browser sends with a form from the page it is on.
 *
 *     node --test worker/test/accounts.test.mjs
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { d1 } from "./stand-ins.mjs";

const worker = (await import("../src/index.js")).default;
const { formToken } = await import("../src/session.js");
const { AUTH_MAIL_PER_DAY } = await import("../src/accounts.js");

const ORIGIN = "https://account.ranwhat.com";
const SECRET = "an-account-test-secret-that-is-long-enough-0123456789";
const SESSION = "__Host-rw_session";
const SIGNIN = "__Host-rw_signin";
const FROM_PAGE = { "sec-fetch-site": "same-origin", origin: ORIGIN };
const MINUTE = 60, HOUR = 3600, DAY = 24 * HOUR;

/* The clock, which a test moves forward when it needs time to pass. */
const realNow = Date.now;
let skew = 0;
Date.now = () => realNow() + skew * 1000;
const later = (seconds) => { skew += seconds; };
const today = () => new Date(Date.now()).toISOString().slice(0, 10);

const sha = (text) => createHash("sha256").update(text).digest("hex");

/* ---------- stand-ins ---------- */

/* Resend's /emails, the only call accounts make to anyone. */
function services() {
  const s = { emails: [], fail: 0 };
  globalThis.fetch = async (url, init = {}) => {
    const u = new URL(String(url));
    assert.equal(`${init.method} ${u.hostname}${u.pathname}`, "POST api.resend.com/emails");
    assert.match(init.headers.authorization, /^Bearer re_test/);
    if (s.fail) {
      return new Response(JSON.stringify({ statusCode: s.fail, name: "application_error" }), { status: s.fail });
    }
    s.emails.push(JSON.parse(init.body));
    return new Response(JSON.stringify({ id: `e${s.emails.length}` }), { status: 200 });
  };
  return s;
}

const env = (extra = {}) => ({
  LIST: d1(), RESEND_API_KEY: "re_test_key", ACCOUNT_SECRET: SECRET, ACCOUNTS_ON: "1", ...extra,
});

class Browser {
  constructor(e, { ip = "198.51.100.7" } = {}) {
    this.e = e;
    this.ip = ip;
    this.jar = new Map();
  }

  clone() {
    const twin = new Browser(this.e, { ip: this.ip });
    twin.jar = new Map(this.jar);
    return twin;
  }

  /* { status, location, headers, text }, after anything the Worker left
     running in waitUntil (the email) has finished. */
  async send(path, { method = "GET", body, headers = {}, origin = ORIGIN } = {}) {
    const h = new Headers({ "cf-connecting-ip": this.ip, ...headers });
    if (this.jar.size) h.set("cookie", [...this.jar].map(([k, v]) => `${k}=${v}`).join("; "));
    const waits = [];
    const res = await worker.fetch(new Request(`${origin}${path}`, {
      method, headers: h, body: body === undefined ? undefined : new URLSearchParams(body).toString(),
    }), this.e, { waitUntil: (p) => waits.push(p) });
    await Promise.all(waits);
    for (const line of res.headers.getSetCookie()) {
      const [pair, ...attributes] = line.split("; ");
      const at = pair.indexOf("=");
      if (attributes.includes("Max-Age=0")) this.jar.delete(pair.slice(0, at));
      else this.jar.set(pair.slice(0, at), pair.slice(at + 1));
    }
    return { status: res.status, location: res.headers.get("location"), headers: res.headers,
             text: await res.text(), waits: waits.length };
  }

  get(path) {
    return this.send(path);
  }

  /* A form posted from a page on this host, unless the test says otherwise. */
  post(path, body, headers = FROM_PAGE) {
    return this.send(path, { method: "POST", body,
      headers: { "content-type": "application/x-www-form-urlencoded", ...headers } });
  }
}

/* The token in the page's form for that action. */
function tokenFor(html, action) {
  const m = html.match(new RegExp(`<form method="post" action="${action}"[^>]*>` +
    `<input type="hidden" name="form" value="([^"]+)">`));
  assert.ok(m, `no form for ${action}`);
  return m[1];
}

const codeIn = (mail) => mail.text.match(/^ {4}([0-9A-Z]{4}-[0-9A-Z]{4})$/m)[1];

/* A code of the right shape that is not this one. */
const ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
function wrongFor(code) {
  const c = code.replace("-", "");
  return ALPHABET[(ALPHABET.indexOf(c[0]) + 1) % 32] + c.slice(1);
}

async function askCode(b, email, next) {
  const form = await b.get(next === undefined ? "/signin" : `/signin?next=${encodeURIComponent(next)}`);
  assert.equal(form.status, 200);
  return b.post("/signin", { form: tokenFor(form.text, "/signin"), email,
                             next: form.text.match(/name="next" value="([^"]*)"/)[1] });
}

async function typeCode(b, code) {
  const page = await b.get("/signin/code");
  assert.equal(page.status, 200, page.text);
  return b.post("/signin/code", { form: tokenFor(page.text, "/signin/code"), code });
}

async function signIn(b, s, email = "ana@example.com") {
  const asked = await askCode(b, email);
  assert.equal(asked.status, 303);
  const done = await typeCode(b, codeIn(s.emails.at(-1)));
  assert.equal(done.status, 303, done.text);
  assert.ok(b.jar.has(SESSION));
  return done;
}

const rows = (e, sql, ...p) => e.LIST.sql.prepare(sql).all(...p).map((r) => ({ ...r }));
const count = (e, table) => e.LIST.sql.prepare(`SELECT count(*) AS n FROM ${table}`).get().n;
const tables = (e) => rows(e, "SELECT name FROM sqlite_master WHERE type = 'table'").map((r) => r.name);

/* ---------- the switch and the host ---------- */

test("with ACCOUNTS_ON unset, the account host answers 404 to everything, as an unknown path does", async () => {
  for (const extra of [{ ACCOUNTS_ON: undefined }, { ACCOUNTS_ON: "" }, { ACCOUNTS_ON: "0" }, { ACCOUNTS_ON: "false" }]) {
    const s = services();
    const e = env(extra);
    const b = new Browser(e);
    const elsewhere = await b.send("/no-such-page", { origin: "https://ranwhat.com" });
    assert.equal(elsewhere.status, 404);
    for (const path of ["/", "/signin", "/signin/code", "/signout", "/org", "/stepup", "/api/contact", "/v1/catalogue"]) {
      for (const r of [await b.get(path), await b.post(path, { email: "ana@example.com" })]) {
        assert.equal(r.status, 404, path);
        assert.equal(r.text, elsewhere.text);
        assert.deepEqual([...r.headers], [...elsewhere.headers]);
      }
    }
    assert.equal(s.emails.length, 0);
    assert.deepEqual(tables(e), [], "nothing is made in the database while it is off");
  }
});

test("switched on without its secret, its database or its mail key, it signs nobody in", async () => {
  for (const extra of [{ ACCOUNT_SECRET: undefined }, { ACCOUNT_SECRET: "too-short" },
                       { RESEND_API_KEY: undefined }, { LIST: undefined }]) {
    const s = services();
    const b = new Browser(env(extra));
    assert.equal((await b.get("/")).status, 503);
    assert.equal((await b.get("/signin")).status, 503);
    assert.equal((await b.post("/signin", { email: "ana@example.com" })).status, 503);
    assert.equal(b.jar.size, 0);
    assert.equal(s.emails.length, 0);
  }
});

test("account pages answer only on the account host, and the site's routes never answer there", async () => {
  services();
  const e = env();
  const b = new Browser(e);
  for (const origin of ["https://ranwhat.com", "https://feed.ranwhat.com"]) {
    for (const path of ["/", "/signin", "/signin/code", "/signin/again", "/signout", "/signout-all", "/org", "/stepup"]) {
      for (const method of ["GET", "POST"]) {
        const r = await b.send(path, { method, origin, headers: FROM_PAGE, body: method === "POST" ? {} : undefined });
        assert.equal(r.status, 404, `${method} ${origin}${path}`);
        assert.deepEqual(JSON.parse(r.text), { error: "Not found." });
      }
    }
  }
  for (const path of ["/api/contact", "/api/subscribe", "/api/checkout", "/api/welcome", "/api/billing",
                      "/api/stripe", "/v1/catalogue"]) {
    const r = await b.get(path);
    assert.equal(r.status, 404, path);
    assert.match(r.headers.get("content-type"), /^text\/html/);
  }
  assert.equal((await b.get("/signout")).status, 405);
  assert.equal((await b.get("/signout")).headers.get("allow"), "POST");
});

/* ---------- signing up and in ---------- */

test("an emailed code, typed, makes the account, a personal organisation it owns, and a session", async () => {
  const s = services();
  const e = env();
  const b = new Browser(e);
  const asked = await askCode(b, "  Ana@Example.com ");
  assert.equal(asked.status, 303);
  assert.equal(asked.location, "/signin/code");
  assert.equal(asked.waits, 1, "the email goes out after the reply, through waitUntil");

  assert.equal(s.emails.length, 1);
  const mail = s.emails[0];
  assert.deepEqual(mail.to, ["ana@example.com"]);
  assert.match(mail.from, /<account@ranwhat\.com>$/);
  const code = codeIn(mail);
  assert.match(code, /^[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}$/);
  assert.doesNotMatch(mail.text + mail.html, /https?:\/\/|<a\b/i, "nothing in the email to click");
  assert.match(mail.text, /account\.ranwhat\.com/);
  assert.match(mail.text, /Never type it anywhere else/);
  assert.ok(!mail.subject.includes(code) && !mail.subject.includes(code.replace("-", "")));
  assert.equal(count(e, "users"), 0, "no account until the code is typed");

  const page = await b.get("/signin/code");
  assert.equal(page.status, 200);
  assert.match(page.text, /ana@example\.com/);
  assert.ok(!page.text.includes(code) && !page.text.includes(code.replace("-", "")), "the box is never filled in");
  assert.doesNotMatch(page.text, /name="code"[^>]*value=/);

  // Typed in lower case and without the dash, as people do.
  const done = await b.post("/signin/code", { form: tokenFor(page.text, "/signin/code"),
                                              code: ` ${code.replace("-", "").toLowerCase()} ` });
  assert.equal(done.status, 303);
  assert.equal(done.location, "/");
  const set = done.headers.getSetCookie();
  assert.equal(set.length, 2);
  assert.match(set[0], /^__Host-rw_session=[A-Za-z0-9_-]{43}; Max-Age=2592000; Path=\/; Secure; HttpOnly; SameSite=Lax$/);
  assert.equal(set[1], "__Host-rw_signin=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Lax");

  const [user] = rows(e, "SELECT * FROM users");
  assert.equal(user.email, "ana@example.com");
  const [org] = rows(e, "SELECT * FROM orgs");
  assert.deepEqual([org.name, org.personal, org.customer], ["Personal", 1, null]);
  assert.deepEqual(rows(e, "SELECT org_id, user_id, role FROM memberships"),
                   [{ org_id: org.id, user_id: user.id, role: "owner" }]);
  assert.deepEqual(rows(e, "SELECT provider, provider_subject, user_id, verified_email FROM identities"),
                   [{ provider: "email", provider_subject: "ana@example.com", user_id: user.id,
                      verified_email: "ana@example.com" }]);
  assert.deepEqual(rows(e, "SELECT org_id, user_id, event, subject FROM auth_events"),
                   [{ org_id: org.id, user_id: user.id, event: "signup", subject: null }]);

  const home = await b.get("/");
  assert.equal(home.status, 200);
  for (const shown of ["ana@example.com", "Personal", "Owner", "Free", "Account made"]) {
    assert.ok(home.text.includes(shown), shown);
  }
  assert.equal((await b.get("/signin")).location, "/", "signed in, the sign-in page sends you home");
});

test("signing in again finds the same account, and its new session replaces the browser's old one", async () => {
  const s = services();
  const e = env();
  const b = new Browser(e);
  await signIn(b, s, "ana@example.com");
  const first = b.jar.get(SESSION);
  later(MINUTE + 1);
  // Signed in, /signin sends the browser home; a tab opened before that
  // still has the form, and posts it with the session cookie it now has.
  assert.equal((await b.get("/signin")).location, "/");
  b.jar.delete(SESSION);
  await askCode(b, "ANA@example.com");
  b.jar.set(SESSION, first);
  assert.equal((await typeCode(b, codeIn(s.emails.at(-1)))).status, 303);
  assert.notEqual(b.jar.get(SESSION), first);
  for (const table of ["users", "orgs", "memberships", "identities", "sessions"]) assert.equal(count(e, table), 1, table);
  assert.deepEqual(rows(e, "SELECT event FROM auth_events ORDER BY id").map((r) => r.event), ["signup", "signin"]);

  const stale = new Browser(e);
  stale.jar.set(SESSION, first);
  const r = await stale.get("/");
  assert.equal(r.status, 303);
  assert.equal(r.location, "/signin");
  assert.ok(!stale.jar.has(SESSION), "a cookie that opens nothing is dropped");
});

test("no code, session or attempt is kept as itself, and limits never key on an address or IP", async () => {
  const s = services();
  const e = env();
  const ana = new Browser(e);
  await askCode(ana, "ana@example.com");
  const used = codeIn(s.emails.at(-1));
  const attemptCookie = ana.jar.get(SIGNIN);
  await typeCode(ana, used);
  const bo = new Browser(e, { ip: "203.0.113.50" });
  await askCode(bo, "bo@example.com");
  const pending = codeIn(s.emails.at(-1));
  const everything = JSON.stringify(tables(e).map((t) => rows(e, `SELECT * FROM ${t}`)));
  for (const secret of [used, used.replace("-", ""), pending, pending.replace("-", ""),
                        ana.jar.get(SESSION), attemptCookie, bo.jar.get(SIGNIN)]) {
    assert.ok(!everything.includes(secret), "kept in plain text");
  }
  const limits = JSON.stringify(rows(e, "SELECT * FROM throttle"));
  for (const raw of ["example.com", "198.51.100.7", "203.0.113.50"]) assert.ok(!limits.includes(raw), raw);
  assert.ok(!JSON.stringify(rows(e, "SELECT * FROM auth_events")).includes("@"));
});

test("every address gets the same answer: known, new, or over its limit", async () => {
  const s = services();
  const e = env();
  await signIn(new Browser(e), s, "known@example.com");
  later(HOUR + 1);
  const shape = (r) => ({
    status: r.status,
    location: r.location,
    text: r.text,
    headers: [...r.headers].filter(([k]) => k !== "set-cookie"),
    cookies: r.headers.getSetCookie().map((c) => c.replace(/^([^=]+)=[^;]*/, "$1=")),
  });
  const known = shape(await askCode(new Browser(e, { ip: "203.0.113.1" }), "known@example.com"));
  const fresh = shape(await askCode(new Browser(e, { ip: "203.0.113.2" }), "new@example.com"));
  const limited = shape(await askCode(new Browser(e, { ip: "203.0.113.3" }), "known@example.com"));
  assert.deepEqual(fresh, known);
  assert.deepEqual(limited, known);
  assert.equal(known.status, 303);
  assert.equal(s.emails.length, 3, "the one over its limit was not mailed");
  assert.equal(count(e, "users"), 1, "asking makes no account");
});

/* ---------- the code ---------- */

test("a code works for ten minutes and no longer", async () => {
  const s = services();
  const e = env();
  const late = new Browser(e);
  await askCode(late, "ana@example.com");
  const page = await late.get("/signin/code");
  later(10 * MINUTE + 1);
  const r = await late.post("/signin/code", { form: tokenFor(page.text, "/signin/code"), code: codeIn(s.emails.at(-1)) });
  assert.equal(r.status, 400);
  assert.match(r.text, /expired/);
  assert.ok(!late.jar.has(SESSION));
  const back = await late.get("/signin/code");
  assert.equal(back.status, 200);
  assert.match(back.text, /expired or was already used/);
  assert.doesNotMatch(back.text, /name="code"/, "no box for a code that cannot work");

  const inTime = new Browser(e);
  await askCode(inTime, "bo@example.com");
  later(10 * MINUTE - 5);
  assert.equal((await typeCode(inTime, codeIn(s.emails.at(-1)))).status, 303);
  assert.equal(count(e, "users"), 1);
});

test("a code works once, and two tabs typing it at once open one session", async () => {
  const s = services();
  const e = env();
  const b = new Browser(e);
  await askCode(b, "ana@example.com");
  const code = codeIn(s.emails.at(-1));
  const page = await b.get("/signin/code");
  const body = { form: tokenFor(page.text, "/signin/code"), code };
  const tabs = [b.clone(), b.clone()];
  const answers = await Promise.all(tabs.map((tab) => tab.post("/signin/code", body)));
  assert.deepEqual(answers.map((r) => r.status).sort(), [303, 400]);
  assert.equal(count(e, "sessions"), 1);
  assert.equal(count(e, "users"), 1);
  assert.equal(count(e, "orgs"), 1);

  const replay = b.clone();
  const r = await replay.post("/signin/code", body);
  assert.equal(r.status, 400);
  assert.match(r.text, /expired or was already used/);
  assert.equal(count(e, "sessions"), 1);
});

test("five wrong tries burn a code, and ten wrong for an address burn all of its codes for an hour", async () => {
  const s = services();
  const e = env();
  const b = new Browser(e);
  await askCode(b, "ana@example.com");
  let code = codeIn(s.emails.at(-1));
  const first = tokenFor((await b.get("/signin/code")).text, "/signin/code");
  for (let left = 4; left >= 1; left--) {
    const r = await typeCode(b, wrongFor(code));
    assert.equal(r.status, 400);
    assert.match(r.text, new RegExp(`not right\\. ${left} tr(y|ies) left`));
  }
  let r = await typeCode(b, wrongFor(code));
  assert.equal(r.status, 400);
  assert.match(r.text, /Too many wrong tries/);
  r = await b.post("/signin/code", { form: first, code });
  assert.equal(r.status, 400, "the right code after the fifth wrong one");
  assert.match(r.text, /Too many wrong tries/);
  assert.match((await b.get("/signin/code")).text, /Too many wrong tries/, "and the page no longer offers the box");
  assert.ok(!b.jar.has(SESSION));

  // Four more wrong on a second code (nine for the address), then one on a third.
  later(MINUTE + 1);
  await askCode(b, "ana@example.com");
  code = codeIn(s.emails.at(-1));
  for (let i = 0; i < 4; i++) await typeCode(b, wrongFor(code));
  later(MINUTE + 1);
  await askCode(b, "ana@example.com");
  code = codeIn(s.emails.at(-1));
  const third = tokenFor((await b.get("/signin/code")).text, "/signin/code");
  assert.match((await typeCode(b, wrongFor(code))).text, /Too many wrong tries/, "the tenth");
  assert.match((await b.post("/signin/code", { form: third, code })).text, /Too many wrong tries/,
               "this code had one wrong try, but the address had ten");

  // A code asked for from another browser in the same hour is mailed, and refused.
  later(MINUTE + 1);
  const other = new Browser(e, { ip: "203.0.113.9" });
  await askCode(other, "ana@example.com");
  assert.match((await typeCode(other, codeIn(s.emails.at(-1)))).text, /Too many wrong tries/);
  assert.equal(count(e, "sessions"), 0);

  later(HOUR + 1);
  await signIn(b, s, "ana@example.com");
});

test("a new request cancels the browser's last code, and a code works only in the browser that asked", async () => {
  const s = services();
  const e = env();
  const b = new Browser(e);
  await askCode(b, "ana@example.com");
  const first = codeIn(s.emails.at(-1));
  const before = b.clone();
  later(MINUTE + 1);
  const page = await b.get("/signin/code");
  assert.equal((await b.post("/signin/again", { form: tokenFor(page.text, "/signin/again") })).status, 303);
  assert.equal(s.emails.length, 2);
  const second = codeIn(s.emails.at(-1));
  assert.notEqual(second, first);
  // The first code, typed into a tab still open on the first attempt.
  const old = await before.post("/signin/code", { form: tokenFor(page.text, "/signin/code"), code: first });
  assert.equal(old.status, 400);
  assert.match(old.text, /expired or was already used/, "the first attempt is cancelled");

  // Someone with the code but not the browser: their own attempt, or none.
  const mallory = new Browser(e, { ip: "192.0.2.66" });
  await askCode(mallory, "mallory@example.com");
  assert.match((await typeCode(mallory, second)).text, /not right/);
  const nobody = new Browser(e, { ip: "192.0.2.67" });
  const r = await nobody.post("/signin/code", { form: tokenFor(page.text, "/signin/code"), code: second });
  assert.equal(r.status, 403);
  assert.equal(count(e, "sessions"), 0);

  assert.equal((await typeCode(b, second)).status, 303);
});

/* ---------- forms ---------- */

test("a form is refused from another host, without its origin, or without its token", async () => {
  const s = services();
  const e = env();
  const b = new Browser(e);
  await signIn(b, s, "ana@example.com");
  const home = await b.get("/");
  const token = tokenFor(home.text, "/signout");
  for (const headers of [
    { "sec-fetch-site": "same-site", origin: "https://ranwhat.com" },
    { "sec-fetch-site": "same-site" },
    { "sec-fetch-site": "cross-site", origin: "https://evil.example" },
    { origin: "https://evil.example" },
    { origin: "null" },
    { origin: "http://account.ranwhat.com" },
    { "sec-fetch-site": "same-origin", origin: "https://ranwhat.com" },
    {},
  ]) {
    const r = await b.post("/signout", { form: token }, headers);
    assert.equal(r.status, 403, JSON.stringify(headers));
  }
  assert.equal((await b.post("/signout", {})).status, 403, "no token");
  assert.equal((await b.post("/signout", { form: tokenFor(home.text, "/signout-all") })).status, 403, "another form's token");
  const bo = new Browser(e, { ip: "203.0.113.20" });
  await signIn(bo, s, "bo@example.com");
  const theirs = tokenFor((await bo.get("/")).text, "/signout");
  assert.equal((await b.post("/signout", { form: theirs })).status, 403, "another session's token");
  assert.equal((await b.get("/")).status, 200, "still signed in after all of that");

  const fresh = new Browser(e, { ip: "203.0.113.21" });
  const form = await fresh.get("/signin");
  assert.equal((await fresh.post("/signin", { email: "x@example.com" })).status, 403);
  assert.equal((await fresh.post("/signin", { form: tokenFor(form.text, "/signin"), email: "x@example.com" },
    { "sec-fetch-site": "same-site", origin: "https://ranwhat.com" })).status, 403);
  assert.equal(s.emails.length, 2, "no code for a refused form");

  // A browser that sends Origin and no Sec-Fetch-Site is still let through.
  const r = await b.post("/signout", { form: token }, { origin: ORIGIN });
  assert.equal(r.status, 303);
  assert.ok(!b.jar.has(SESSION));
});

test("sign-in sends you on only to a page on the list", async () => {
  const s = services();
  const e = env();
  for (const asked of ["/", "//evil.example/", "https://evil.example/", "/\\evil.example", "/signout"]) {
    const b = new Browser(e, { ip: `198.51.100.${s.emails.length + 20}` });
    const form = await b.get(`/signin?next=${encodeURIComponent(asked)}`);
    assert.match(form.text, /name="next" value="\/"/);
    await b.post("/signin", { form: tokenFor(form.text, "/signin"), email: `n${s.emails.length}@example.com`, next: asked });
    assert.equal((await typeCode(b, codeIn(s.emails.at(-1)))).location, "/", asked);
  }
});

/* ---------- sessions ---------- */

test("a session ends after 14 days unused, and 30 days after sign-in however much it is used", async () => {
  const s = services();
  const e = env();
  const idle = new Browser(e);
  await signIn(idle, s, "ana@example.com");
  later(13 * DAY);
  assert.equal((await idle.get("/")).status, 200);
  later(14 * DAY + 1);
  const r = await idle.get("/");
  assert.equal(r.location, "/signin");
  assert.ok(!idle.jar.has(SESSION));
  assert.equal(count(e, "sessions"), 0);

  const busy = new Browser(e);
  await signIn(busy, s, "bo@example.com");
  for (let i = 0; i < 2; i++) {
    later(10 * DAY);
    assert.equal((await busy.get("/")).status, 200);
  }
  later(10 * DAY - MINUTE);
  assert.equal((await busy.get("/")).status, 200);
  later(2 * MINUTE);
  assert.equal((await busy.get("/")).location, "/signin");
});

test("sign out ends this session; sign out everywhere ends every one of the account's", async () => {
  const s = services();
  const e = env();
  const laptop = new Browser(e), phone = new Browser(e, { ip: "203.0.113.30" }), bo = new Browser(e, { ip: "203.0.113.31" });
  await signIn(laptop, s, "ana@example.com");
  later(MINUTE + 1);
  await signIn(phone, s, "ana@example.com");
  await signIn(bo, s, "bo@example.com");
  const old = laptop.jar.get(SESSION);

  let page = await laptop.get("/");
  let r = await laptop.post("/signout", { form: tokenFor(page.text, "/signout") });
  assert.equal(r.status, 303);
  assert.equal(r.location, "/signin");
  assert.deepEqual(r.headers.getSetCookie(), ["__Host-rw_session=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Lax"]);
  assert.equal((await phone.get("/")).status, 200);
  const replay = new Browser(e);
  replay.jar.set(SESSION, old);
  assert.equal((await replay.get("/")).location, "/signin", "a signed-out cookie opens nothing");

  page = await phone.get("/");
  r = await phone.post("/signout-all", { form: tokenFor(page.text, "/signout-all") });
  assert.equal(r.status, 303);
  assert.equal((await phone.get("/")).location, "/signin");
  const [ana] = rows(e, "SELECT id FROM users WHERE email = 'ana@example.com'");
  assert.equal(rows(e, "SELECT * FROM sessions WHERE user_id = ?", ana.id).length, 0);
  assert.equal((await bo.get("/")).status, 200, "someone else's session is theirs");
  assert.deepEqual(rows(e, "SELECT event FROM auth_events WHERE user_id = ? ORDER BY id", ana.id).map((x) => x.event),
                   ["signup", "signin", "signout", "signout_all"]);
});

test("a fresh code opens a new session, confirmed now, in place of the old one", async () => {
  const s = services();
  const e = env();
  const b = new Browser(e);
  await signIn(b, s, "ana@example.com");
  const before = b.jar.get(SESSION);
  later(20 * MINUTE);
  const [{ authed_at: then }] = rows(e, "SELECT authed_at FROM sessions");

  assert.equal((await b.post("/stepup", { form: "forged" })).status, 403);
  const r = await b.post("/stepup", { form: await formToken(e, sha(before), "stepup") });
  assert.equal(r.location, "/signin/code");
  assert.equal(s.emails.at(-1).subject, "Your ranwhat confirmation code");
  assert.deepEqual(s.emails.at(-1).to, ["ana@example.com"]);
  const done = await typeCode(b, codeIn(s.emails.at(-1)));
  assert.equal(done.location, "/");
  assert.notEqual(b.jar.get(SESSION), before);
  const [session] = rows(e, "SELECT * FROM sessions");
  assert.equal(session.id, sha(b.jar.get(SESSION)));
  assert.ok(session.authed_at > then);
  assert.equal(count(e, "users"), 1);
  assert.equal(rows(e, "SELECT event FROM auth_events ORDER BY id").at(-1).event, "stepup");

  const nobody = new Browser(e);
  assert.equal((await nobody.post("/stepup", { form: "x" })).location, "/signin");
});

/* ---------- limits ---------- */

test("an address gets a code a minute and five an hour, and the browser that asked keeps its code", async () => {
  const s = services();
  const e = env();
  const b = new Browser(e);
  await askCode(b, "ana@example.com");
  const first = codeIn(s.emails.at(-1));
  const again = await askCode(b, "ana@example.com");
  assert.equal(again.status, 303);
  assert.equal(s.emails.length, 1, "a second request inside the minute sends nothing");
  assert.equal((await typeCode(b, first)).status, 303, "and the first code still works in that browser");

  for (let i = 2; i <= 5; i++) {
    later(MINUTE + 1);
    await askCode(new Browser(e, { ip: `203.0.113.${i}` }), "ana@example.com");
  }
  assert.equal(s.emails.length, 5);
  later(MINUTE + 1);
  assert.equal((await askCode(new Browser(e, { ip: "203.0.113.6" }), "ana@example.com")).status, 303);
  assert.equal(s.emails.length, 5, "the sixth in the hour sends nothing");
  later(HOUR);
  await askCode(new Browser(e, { ip: "203.0.113.7" }), "ana@example.com");
  assert.equal(s.emails.length, 6);
});

test("one network asks for at most twenty codes an hour", async () => {
  const s = services();
  const e = env();
  for (let i = 0; i < 20; i++) {
    assert.equal((await askCode(new Browser(e, { ip: "192.0.2.1" }), `p${i}@example.com`)).status, 303);
  }
  const r = await askCode(new Browser(e, { ip: "192.0.2.1" }), "p20@example.com");
  assert.equal(r.status, 429);
  assert.equal(s.emails.length, 20);
  assert.equal((await askCode(new Browser(e, { ip: "192.0.2.2" }), "p20@example.com")).status, 303);
});

test("account email stops at the day's cap, for every address alike, and starts again the next day", async () => {
  const s = services();
  const e = env();
  await signIn(new Browser(e, { ip: "203.0.113.40" }), s, "known@example.com");
  e.LIST.sql.prepare("UPDATE mail_counts SET sent = ? WHERE day = ? AND kind = 'auth'").run(AUTH_MAIL_PER_DAY - 1, today());
  const last = await askCode(new Browser(e, { ip: "203.0.113.41" }), "a@example.com");
  assert.equal(last.status, 303);
  assert.equal(s.emails.length, 2);
  for (const [email, ip] of [["b@example.com", "203.0.113.42"], ["known@example.com", "203.0.113.43"]]) {
    const b = new Browser(e, { ip });
    const r = await askCode(b, email);
    assert.equal(r.status, 503);
    assert.match(r.text, /No more codes today/);
    assert.equal(r.headers.getSetCookie().length, 0);
  }
  assert.equal(s.emails.length, 2);
  assert.deepEqual(rows(e, "SELECT sent FROM mail_counts WHERE kind = 'auth'"), [{ sent: AUTH_MAIL_PER_DAY }]);
  later(DAY);
  assert.equal((await askCode(new Browser(e, { ip: "203.0.113.44" }), "b@example.com")).status, 303);
  assert.equal(s.emails.length, 3);
});

/* ---------- pages ---------- */

test("every page from the account host runs no script and carries its own strict headers", async () => {
  const s = services();
  const e = env();
  const b = new Browser(e);
  const pages = [await b.get("/signin"), await b.get("/no-such-page"), await b.get("/")];
  await signIn(b, s);
  pages.push(await b.get("/"));
  for (const r of pages) {
    const csp = r.headers.get("content-security-policy");
    assert.match(csp, /^default-src 'none'; style-src 'sha256-[A-Za-z0-9+/]+=*'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'$/);
    if (r.text) {
      const style = r.text.match(/<style>([\s\S]*?)<\/style>/)[1];
      assert.ok(csp.includes(`'sha256-${createHash("sha256").update(style).digest("base64")}'`), "the hash is the page's own style");
      assert.doesNotMatch(r.text, /<script|\son[a-z]+=/i);
    }
    assert.equal(r.headers.get("cache-control"), "no-store");
    assert.equal(r.headers.get("x-frame-options"), "DENY");
    assert.equal(r.headers.get("x-content-type-options"), "nosniff");
    assert.equal(r.headers.get("referrer-policy"), "same-origin");
    assert.equal(r.headers.get("strict-transport-security"), "max-age=31536000");
  }
  for (const origin of ["https://ranwhat.com", "https://feed.ranwhat.com"]) {
    for (const path of ["/api/billing", "/v1/catalogue", "/signin"]) {
      assert.equal((await b.send(path, { origin })).headers.get("strict-transport-security"), null, origin + path);
    }
  }
});

test("an owner renames the organisation; a name is escaped, and a member cannot", async () => {
  const s = services();
  const e = env();
  const ana = new Browser(e);
  await signIn(ana, s, "ana@example.com");
  let home = await ana.get("/");
  let r = await ana.post("/org", { form: tokenFor(home.text, "/org"), name: "  Acme <b>&\n Co  " });
  assert.equal(r.location, "/");
  home = await ana.get("/");
  assert.ok(home.text.includes("Acme &lt;b&gt;&amp; Co"));
  assert.ok(!home.text.includes("<b>&"));
  assert.equal(rows(e, "SELECT name FROM orgs")[0].name, "Acme <b>& Co");
  for (const bad of ["", "   ", "x".repeat(81), "evil‮gnp.exe", "bell\u0007"]) {
    r = await ana.post("/org", { form: tokenFor(home.text, "/org"), name: bad });
    assert.equal(r.status, 400, JSON.stringify(bad));
  }
  assert.equal(rows(e, "SELECT name FROM orgs")[0].name, "Acme <b>& Co");

  // Bo, a member of Ana's organisation and looking at it, gets no form and is refused one.
  const bo = new Browser(e, { ip: "203.0.113.60" });
  await signIn(bo, s, "bo@example.com");
  const [{ org_id: acme }] = rows(e, "SELECT m.org_id FROM memberships m JOIN users u ON u.id = m.user_id WHERE u.email = 'ana@example.com'");
  const [{ id: boId }] = rows(e, "SELECT id FROM users WHERE email = 'bo@example.com'");
  e.LIST.sql.prepare("INSERT INTO memberships (org_id, user_id, role, created_at) VALUES (?, ?, 'member', 0)").run(acme, boId);
  e.LIST.sql.prepare("UPDATE sessions SET org_id = ? WHERE user_id = ?").run(acme, boId);
  const theirs = await bo.get("/");
  assert.ok(theirs.text.includes("Acme &lt;b&gt;&amp; Co") && theirs.text.includes("Member"));
  assert.doesNotMatch(theirs.text, /action="\/org"/);
  r = await bo.post("/org", { form: await formToken(e, sha(bo.jar.get(SESSION)), "org"), name: "Taken" });
  assert.equal(r.status, 403);
  assert.equal(rows(e, "SELECT name FROM orgs WHERE id = ?", acme)[0].name, "Acme <b>& Co");

  // Removed from it, Bo is back in his own on the next request.
  e.LIST.sql.prepare("DELETE FROM memberships WHERE org_id = ? AND user_id = ?").run(acme, boId);
  assert.ok((await bo.get("/")).text.includes("Personal"));
  assert.equal(rows(e, "SELECT event FROM auth_events WHERE event = 'org_renamed'").length, 1);
});

/* ---------- logs and the cron ---------- */

test("nothing logged carries an address or a code", async () => {
  const lines = [];
  const real = console.log;
  console.log = (...a) => lines.push(a.join(" "));
  try {
    const s = services();
    const e = env();
    s.fail = 500;
    const r = await askCode(new Browser(e), "secret.person@example.com");
    assert.equal(r.status, 303, "a failed send answers like any other");
    s.fail = 0;
    later(MINUTE + 1);
    const b = new Browser(e, { ip: "203.0.113.70" });
    await askCode(b, "secret.person@example.com");
    await typeCode(b, wrongFor(codeIn(s.emails.at(-1))));
  } finally {
    console.log = real;
  }
  assert.ok(lines.length >= 1);
  for (const line of lines) assert.doesNotMatch(line, /@|secret\.person|example\.com|[0-9A-Z]{4}-[0-9A-Z]{4}/);
});

test("the cron deletes what is out of date once accounts are on, and touches nothing while they are off", async () => {
  const s = services();
  const off = env({ ACCOUNTS_ON: undefined });
  const waits = [];
  await worker.scheduled({}, off, { waitUntil: (p) => waits.push(p) });
  await Promise.all(waits);
  assert.deepEqual(tables(off), []);

  const e = env();
  await signIn(new Browser(e), s, "ana@example.com");
  await askCode(new Browser(e, { ip: "203.0.113.80" }), "bo@example.com");
  await worker.scheduled({}, e, { waitUntil: (p) => waits.push(p) });
  await Promise.all(waits);
  assert.equal(count(e, "signins"), 1, "a code still waiting to be typed stays");
  assert.equal(count(e, "sessions"), 1);

  later(31 * DAY);
  await worker.scheduled({}, e, { waitUntil: (p) => waits.push(p) });
  await Promise.all(waits);
  for (const table of ["signins", "sessions", "throttle"]) assert.equal(count(e, table), 0, table);
  assert.equal(count(e, "users"), 1);
  assert.equal(count(e, "auth_events"), 1, "the history is kept 13 months");
});
