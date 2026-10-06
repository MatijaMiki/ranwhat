/* Passwords: how one is hashed, verified and judged (password.js), and
 * making an account with one, signing in with it, resetting, changing and
 * removing it on account.ranwhat.com, end to end through the Worker over a
 * real SQLite database. PBKDF2 runs at 1,000 iterations here, and Have I
 * Been Pwned and Resend are stand-ins.
 *
 * The cases this file is for: someone signs up with another person's
 * address and a password of their own, and must gain nothing, now or after
 * the address's owner turns up; and someone guessing passwords, who must
 * learn nothing about which addresses have accounts and get few guesses.
 *
 *     node --test --test-timeout=20000 worker/test/password.test.mjs
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash, pbkdf2Sync } from "node:crypto";
import { d1 } from "./stand-ins.mjs";

const worker = (await import("../src/index.js")).default;
const { AUTH_MAIL_PER_DAY, sweep } = await import("../src/accounts.js");
const { CODE_FOR, FRESH_FOR, formToken } = await import("../src/session.js");
const {
  ITERATIONS, LOCKOUT, MAX_LENGTH, MIN_LENGTH, TRIES_PER_ADDRESS, WRONG_PER_NETWORK, hashPassword, isPasswordHash,
  iterations, needsRehash, passwordProblem, verifyPassword,
} = await import("../src/password.js");

const ORIGIN = "https://account.ranwhat.com";
const SECRET = "an-account-test-secret-" + "that-is-long-enough-0123456789";
const RESEND_KEY = "re_" + "test_key";
const SESSION = "__Host-rw_session";
const SIGNIN = "__Host-rw_signin";
const FROM_PAGE = { "sec-fetch-site": "same-origin", origin: ORIGIN };
const MINUTE = 60;
const LOW = { PBKDF2_ITERATIONS: "1000" };
const PREFIX = "pbkdf2-" + "sha256$";

const ANA_PASSWORD = "plum kettle orbit canvas";
const MALLORY_PASSWORD = "mallory was here first";

/* The clock, which a test moves forward when it needs time to pass. */
const realNow = Date.now;
let skew = 0;
Date.now = () => realNow() + skew * 1000;
const later = (seconds) => { skew += seconds; };

const sha1 = (text) => createHash("sha1").update(text).digest("hex").toUpperCase();
const sha256 = (text) => createHash("sha256").update(text).digest("hex");

/* ---------- stand-ins ---------- */

/* Have I Been Pwned's range API, Resend's /emails and Turnstile's
   siteverify. `breached` holds the passwords the range API knows; every
   answer is padded with made-up suffixes at a count of 0, and `padded` adds
   a real one at 0. A Turnstile token from solved(action) passes for that
   form on the account host. */
const solved = (action) => `solved:${action}`;
function services({ breached = [], padded = [] } = {}) {
  const s = { emails: [], ranges: [], hibp: "up" };
  const known = breached.map(sha1);
  const zero = padded.map(sha1);
  globalThis.fetch = async (url, init = {}) => {
    const u = new URL(String(url));
    if (u.hostname === "challenges.cloudflare.com") {
      const m = /^solved:([a-z]+)$/.exec(JSON.parse(init.body).response);
      return new Response(JSON.stringify(m ? { success: true, hostname: "account.ranwhat.com", action: m[1] }
        : { success: false }), { status: 200 });
    }
    if (u.hostname === "api.pwnedpasswords.com") {
      s.ranges.push({ url: String(url), method: init.method || "GET", headers: new Headers(init.headers) });
      if (s.hibp === "down") throw new TypeError("fetch failed");
      if (s.hibp === "error") return new Response("", { status: 503 });
      const prefix = u.pathname.replace("/range/", "");
      const lines = [
        ...known.filter((h) => h.startsWith(prefix)).map((h) => `${h.slice(5)}:3861493`),
        ...zero.filter((h) => h.startsWith(prefix)).map((h) => `${h.slice(5)}:0`),
        "0018A45C4D1DEF81644B54AB7F969B88D65:0",
        "00D4F6E8FA6EECAD2A3AA415EEC418D38EC:2",
      ];
      return new Response(lines.join("\r\n"), { status: 200 });
    }
    assert.equal(`${init.method} ${u.hostname}${u.pathname}`, "POST api.resend.com/emails");
    s.emails.push(JSON.parse(init.body));
    return new Response(JSON.stringify({ id: `e${s.emails.length}` }), { status: 200 });
  };
  return s;
}

const env = (extra = {}) => ({
  LIST: d1(), RESEND_API_KEY: RESEND_KEY, ACCOUNT_SECRET: SECRET, TURNSTILE_SECRET: "turnstile-" + "test",
  ACCOUNTS_ON: "1", ...LOW, ...extra,
});

/* A browser: keeps cookies as one does, and sends the headers it sends
   with a form from the page it is on. */
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

  get(path) {
    return this.send(path);
  }

  post(path, body, headers = FROM_PAGE) {
    return this.send(path, { method: "POST", body,
      headers: { "content-type": "application/x-www-form-urlencoded", ...headers } });
  }
}

function tokenFor(html, action) {
  const m = html.match(new RegExp(`<form method="post" action="${action}"[^>]*>` +
    `<input type="hidden" name="form" value="([^"]+)">`));
  assert.ok(m, `no form for ${action}`);
  return m[1];
}

const codeIn = (mail) => mail.text.match(/^ {4}([0-9A-Z]{4}-[0-9A-Z]{4})$/m)[1];

const ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const wrongFor = (code) => {
  const c = code.replace("-", "");
  return ALPHABET[(ALPHABET.indexOf(c[0]) + 1) % 32] + c.slice(1);
};

async function signUp(b, email, password) {
  const form = await b.get("/signup");
  assert.equal(form.status, 200, form.text);
  return b.post("/signup", { form: tokenFor(form.text, "/signup"), email, password, next: "/",
                             "cf-turnstile-response": solved("signup") });
}

async function askCode(b, email) {
  const form = await b.get("/signin");
  return b.post("/signin", { form: tokenFor(form.text, "/signin"), email, next: "/",
                             "cf-turnstile-response": solved("signin") });
}

async function typeCode(b, code) {
  const page = await b.get("/signin/code");
  assert.equal(page.status, 200, page.text);
  return b.post("/signin/code", { form: tokenFor(page.text, "/signin/code"), code });
}

async function again(b) {
  const page = await b.get("/signin/again");
  return b.post("/signin/again", { form: tokenFor(page.text, "/signin/again"), "cf-turnstile-response": solved("again") });
}

const rows = (e, sql, ...p) => e.LIST.sql.prepare(sql).all(...p).map((r) => ({ ...r }));
const count = (e, table) => e.LIST.sql.prepare(`SELECT count(*) AS n FROM ${table}`).get().n;
const tables = (e) => rows(e, "SELECT name FROM sqlite_master WHERE type = 'table'").map((r) => r.name);
const everything = (e) => JSON.stringify(tables(e).map((t) => rows(e, `SELECT * FROM ${t}`)));

const passwordOf = (e, email) => {
  const r = rows(e, `SELECT c.hash FROM credentials c JOIN users u ON u.id = c.user_id
                     WHERE u.email = ? AND c.kind = 'password'`, email);
  return r.length ? r[0].hash : null;
};
const eventsOf = (e, email) => rows(e, `SELECT a.event FROM auth_events a JOIN users u ON u.id = a.user_id
                                        WHERE u.email = ? ORDER BY a.id`, email).map((r) => r.event);

/* Console output while fn runs. */
async function logged(fn) {
  const lines = [];
  const real = { log: console.log, warn: console.warn };
  console.log = console.warn = (...a) => lines.push(a.join(" "));
  try {
    return { result: await fn(), lines };
  } finally {
    Object.assign(console, real);
  }
}

/* ---------- the hash ---------- */

test("a password is kept as standard PBKDF2-SHA256 with its own salt and count, and only it verifies", async () => {
  const stored = await hashPassword(LOW, ANA_PASSWORD);
  const m = stored.match(/^pbkdf2-sha256\$1000\$([A-Za-z0-9_-]{22})\$([A-Za-z0-9_-]{43})$/);
  assert.ok(m, stored);
  const salt = Buffer.from(m[1], "base64url");
  assert.equal(salt.length, 16);
  assert.equal(Buffer.from(m[2], "base64url").toString("hex"),
    pbkdf2Sync(ANA_PASSWORD, salt, 1000, 32, "sha256").toString("hex"), "any PBKDF2 can check it");

  const twice = await hashPassword(LOW, ANA_PASSWORD);
  assert.notEqual(twice, stored, "a new salt every time");
  assert.equal(await verifyPassword(stored, ANA_PASSWORD), true);
  assert.equal(await verifyPassword(twice, ANA_PASSWORD), true);
  for (const wrong of ["", "plum kettle orbit canva", "Plum kettle orbit canvas", `${ANA_PASSWORD} `]) {
    assert.equal(await verifyPassword(stored, wrong), false, JSON.stringify(wrong));
  }
  assert.ok(!stored.includes(ANA_PASSWORD));
});

test("the same characters typed another way are the same password", async () => {
  const composed = "Ångström-fjord-1234";
  const decomposed = composed.normalize("NFD");
  assert.notEqual(composed, decomposed);
  assert.equal(await verifyPassword(await hashPassword(LOW, composed), decomposed), true);
  assert.equal(await verifyPassword(await hashPassword(LOW, "ｐａｓｓｐｈｒａｓｅ　ｗｉｄｅ"), "passphrase wide"), true);
});

test("the count comes from PBKDF2_ITERATIONS, 600,000 by default, and a lower one asks for a hash again", async () => {
  assert.equal(ITERATIONS, 600000);
  assert.equal(iterations({}), 600000);
  assert.equal(iterations({ PBKDF2_ITERATIONS: "100000" }), 100000);
  assert.equal(iterations({ PBKDF2_ITERATIONS: " 1000 " }), 1000);
  for (const bad of ["", "abc", "999", "2.5", "1e9", "-5", "600k"]) {
    assert.equal(iterations({ PBKDF2_ITERATIONS: bad }), 600000, bad);
  }
  assert.match(await hashPassword({}, ANA_PASSWORD), /^pbkdf2-sha256\$600000\$/);

  const old = await hashPassword(LOW, ANA_PASSWORD);
  assert.equal(needsRehash(LOW, old), false);
  assert.equal(needsRehash({ PBKDF2_ITERATIONS: "2000" }, old), true);
  assert.equal(needsRehash({}, old), true);
  assert.equal(await verifyPassword(old, ANA_PASSWORD), true, "an older count still verifies");
  assert.equal(needsRehash(LOW, "not a hash"), true);
});

test("a stored value that is not a hash made here verifies nothing", async () => {
  const good = await hashPassword(LOW, ANA_PASSWORD);
  const [, , salt, hash] = good.split("$");
  const bad = [
    null, undefined, "", ANA_PASSWORD,
    `${PREFIX}1000$${salt}`,
    `${PREFIX}1000$${salt}$${hash}$`,
    `${PREFIX}1000$${salt}$${hash.slice(1)}`,
    `${PREFIX}0$${salt}$${hash}`,
    `${PREFIX}01000$${salt}$${hash}`,
    `${PREFIX}99999999$${salt}$${hash}`,
    `pbkdf2-` + `sha1$1000$${salt}$${hash}`,
    `${PREFIX}1000$${salt}$${hash}`.replace("$", " $"),
  ];
  for (const stored of bad) {
    assert.equal(isPasswordHash(stored), false, String(stored));
    assert.equal(await verifyPassword(stored, ANA_PASSWORD), false, String(stored));
  }
  assert.equal(await verifyPassword(`${PREFIX}1001$${salt}$${hash}`, ANA_PASSWORD), false, "the count is part of it");
  assert.equal(await verifyPassword(good, null), false);
  assert.equal(isPasswordHash(good), true);
});

/* ---------- judging a new one ---------- */

test("a password is 12 to 128 characters, counted as code points, with nothing asked of its make-up", async () => {
  const s = services();
  const judge = (p) => passwordProblem(LOW, p, { fetch: globalThis.fetch });
  assert.equal(MIN_LENGTH, 12);
  assert.equal(MAX_LENGTH, 128);
  assert.match(await judge("a".repeat(11)), /at least 12/);
  assert.equal(await judge("abcdefghijkl"), null, "lower-case letters only are fine");
  assert.equal(await judge("x".repeat(128)), null);
  assert.match(await judge("x".repeat(129)), /at most 128/);
  assert.match(await judge("🔑".repeat(6)), /at least 12/, "twelve UTF-16 units, six characters");
  assert.equal(await judge("🔑".repeat(12)), null);
  assert.equal(await judge("🔑".repeat(128)), null, "256 UTF-16 units, 128 characters");
  assert.match(await judge(null), /at least 12/);
  assert.match(await judge(undefined), /at least 12/);
  assert.equal(s.ranges.length, 4, "the breach check runs only for a password of the right length");
});

test("the breach check sends five hex digits of the SHA-1, padded, and refuses a breached password", async () => {
  const breached = "password1234";
  const s = services({ breached: [breached], padded: [ANA_PASSWORD] });
  const problem = await passwordProblem(LOW, breached, { fetch: globalThis.fetch });
  assert.match(problem, /known data breach/);
  const [asked] = s.ranges;
  assert.equal(asked.url, `https://api.pwnedpasswords.com/range/${sha1(breached).slice(0, 5)}`);
  assert.equal(asked.method, "GET");
  assert.equal(asked.headers.get("add-padding"), "true");
  const sent = JSON.stringify([asked.url, [...asked.headers]]);
  assert.ok(!sent.includes(breached) && !sent.includes(sha1(breached).slice(5)), "nothing more than the prefix");

  assert.equal(await passwordProblem(LOW, ANA_PASSWORD, { fetch: globalThis.fetch }), null,
    "a padding line at a count of 0 is not a breach");
  assert.equal(await passwordProblem(LOW, "a password nobody has used", { fetch: globalThis.fetch }), null);
});

test("a breached password that NFKC changes is refused as it was breached, though it would sign in as either", async () => {
  const typed = "\uFB01refly-dragon-2009";     // an "fi" ligature, as some keyboards and pastes give it
  const plainForm = typed.normalize("NFKC");
  assert.equal(plainForm, "firefly-dragon-2009");
  const s = services({ breached: [typed] });
  assert.match(await passwordProblem(LOW, typed, { fetch: globalThis.fetch }), /known data breach/);
  assert.deepEqual(s.ranges.map((r) => r.url.slice(-5)), [sha1(plainForm).slice(0, 5), sha1(typed).slice(0, 5)],
    "each form sends only its own five hex digits");
  assert.equal(await verifyPassword(await hashPassword(LOW, plainForm), typed), true, "why it matters");

  /* A password NFKC leaves alone is looked up once. */
  s.ranges.length = 0;
  assert.equal(await passwordProblem(LOW, "a password nobody has used", { fetch: globalThis.fetch }), null);
  assert.equal(s.ranges.length, 1);
});

test("when the breach check fails or is slow, it is skipped with a warning that names no part of the password", async () => {
  const pw = "correct horse battery staple";
  const prefix = sha1(pw).slice(0, 5);
  const fails = [
    async () => { throw new TypeError("fetch failed"); },
    async () => new Response("", { status: 503 }),
    () => { throw new Error("sync"); },
    () => new Promise(() => {}),                                   // never answers, ignores the signal
    (url, init) => new Promise((_, reject) => init.signal.addEventListener("abort", () => reject(init.signal.reason))),
    async () => ({ ok: true, text: () => new Promise(() => {}) }), // headers, then a body that never comes
  ];
  for (const fetch of fails) {
    const started = Date.now();
    const { result, lines } = await logged(() => passwordProblem(LOW, pw, { fetch, wait: 50 }));
    assert.equal(result, null, "fails open");
    assert.ok(Date.now() - started < 2000, "within the wait");
    assert.equal(lines.length, 1);
    assert.match(lines[0], /^account pwned check: skipped, /);
    assert.ok(!lines[0].includes(pw) && !lines[0].includes(prefix), lines[0]);
  }
});

/* ---------- making an account with one ---------- */

test("sign-up holds the hash only in the asking browser's attempt, and sets it once that browser types the code", async () => {
  const s = services();
  const e = env();
  const b = new Browser(e);
  const form = await b.get("/signup");
  assert.equal(form.status, 200);
  assert.match(form.text, /type="password" autocomplete="new-password"/);
  assert.deepEqual(form.text.match(/<script[^>]*>/g),
                   ['<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer>'],
                   "Turnstile's script alone");
  assert.doesNotMatch(form.text, /\son[a-z]+=/i);
  assert.match(form.headers.get("content-security-policy"), /^default-src 'none'; /);

  const asked = await b.post("/signup", { form: tokenFor(form.text, "/signup"), "cf-turnstile-response": solved("signup"),
    email: "Ana@Example.com",
                                          password: ANA_PASSWORD, next: "/" });
  assert.equal(asked.status, 303);
  assert.equal(asked.location, "/signin/code");
  assert.equal(s.emails.length, 1);
  assert.deepEqual(s.emails[0].to, ["ana@example.com"]);
  assert.match(s.emails[0].subject, /confirmation code/);
  assert.match(s.emails[0].text, /sets the password chosen on that page/);

  assert.equal(count(e, "users"), 0, "no account before the code");
  assert.equal(count(e, "credentials"), 0, "no password before the code");
  const [held] = rows(e, "SELECT purpose, password_hash FROM signins");
  assert.equal(held.purpose, "verify");
  assert.equal(await verifyPassword(held.password_hash, ANA_PASSWORD), true);
  assert.ok(!everything(e).includes(ANA_PASSWORD), "never kept as itself");

  const page = await b.get("/signin/code");
  assert.match(page.text, /Your password is set when the code is typed/);
  assert.match(page.text, /href="\/signup">Use a different email/);
  const done = await typeCode(b, codeIn(s.emails[0]));
  assert.equal(done.status, 303, done.text);
  assert.equal(done.location, "/");
  assert.ok(b.jar.has(SESSION));
  assert.ok(!b.jar.has(SIGNIN));

  assert.equal(await verifyPassword(passwordOf(e, "ana@example.com"), ANA_PASSWORD), true);
  assert.deepEqual(eventsOf(e, "ana@example.com"), ["signup", "password_added"]);
  assert.equal(rows(e, "SELECT count(*) AS n FROM signins WHERE password_hash IS NOT NULL")[0].n, 0,
    "the attempt lets go of the hash once used");
  assert.match((await b.get("/")).text, /Password added, confirmed with an emailed code/);
  assert.ok(!everything(e).includes(ANA_PASSWORD));
});

test("pre-registration: another person's address with your own password gets you nothing, before or after they come", async () => {
  const s = services();
  const e = env();
  const mallory = new Browser(e, { ip: "203.0.113.66" });
  const ana = new Browser(e, { ip: "198.51.100.7" });

  /* Mallory signs up with Ana's address. The code goes to Ana. */
  assert.equal((await signUp(mallory, "ana@example.com", MALLORY_PASSWORD)).status, 303);
  const mallorysCode = codeIn(s.emails.at(-1));
  assert.deepEqual(s.emails.at(-1).to, ["ana@example.com"]);

  /* Without it, guessing gets her nowhere, and nothing is attached. */
  for (let i = 0; i < 2; i++) assert.equal((await typeCode(mallory, wrongFor(mallorysCode))).status, 400);
  assert.equal(count(e, "users"), 0);
  assert.equal(count(e, "credentials"), 0);
  assert.ok(!mallory.jar.has(SESSION));

  /* Ana asks for a sign-in code in her own browser. The code Mallory's
     attempt mailed her does not work there: it belongs to Mallory's
     attempt. Nor does Ana's work in Mallory's browser. */
  later(MINUTE + 1);
  assert.equal((await askCode(ana, "ana@example.com")).status, 303);
  const anasCode = codeIn(s.emails.at(-1));
  assert.equal((await typeCode(ana, mallorysCode)).status, 400);
  assert.ok(!ana.jar.has(SESSION));
  assert.equal((await typeCode(mallory, anasCode)).status, 400);
  assert.ok(!mallory.jar.has(SESSION));
  assert.equal(count(e, "users"), 0);

  /* Ana signs in. Her account has no password: Mallory's was never attached. */
  assert.equal((await typeCode(ana, anasCode)).status, 303);
  assert.ok(ana.jar.has(SESSION));
  assert.equal(count(e, "users"), 1);
  assert.equal(passwordOf(e, "ana@example.com"), null);
  assert.equal(count(e, "credentials"), 0);
  assert.deepEqual(eventsOf(e, "ana@example.com"), ["signup"]);

  /* Mallory's attempt, still open, still attaches nothing: she burns it. */
  for (let i = 0; i < 2; i++) await typeCode(mallory, wrongFor(mallorysCode));
  assert.equal(count(e, "credentials"), 0);
  assert.ok(!mallory.jar.has(SESSION));

  /* Ana later chooses a password of her own: hers is set, never Mallory's. */
  later(MINUTE + 1);
  const anaAgain = new Browser(e, { ip: "198.51.100.8" });
  assert.equal((await signUp(anaAgain, "ana@example.com", ANA_PASSWORD)).status, 303);
  assert.equal((await typeCode(anaAgain, codeIn(s.emails.at(-1)))).status, 303);
  const kept = passwordOf(e, "ana@example.com");
  assert.equal(await verifyPassword(kept, ANA_PASSWORD), true);
  assert.equal(await verifyPassword(kept, MALLORY_PASSWORD), false);

  /* Mallory's hash lives only in her own attempt, and the sweep takes it
     once its code is out of date. */
  later(CODE_FOR + 1);
  await sweep(e);
  assert.equal(rows(e, "SELECT count(*) AS n FROM signins WHERE password_hash IS NOT NULL")[0].n, 0);
  assert.equal(await verifyPassword(passwordOf(e, "ana@example.com"), MALLORY_PASSWORD), false);
});

test("pre-registration: Mallory asks first, then Ana signs up herself, and only Ana's password is set", async () => {
  const s = services();
  const e = env();
  const mallory = new Browser(e, { ip: "203.0.113.66" });
  const ana = new Browser(e, { ip: "198.51.100.7" });
  await signUp(mallory, "ana@example.com", MALLORY_PASSWORD);
  const mallorysCode = codeIn(s.emails.at(-1));
  later(MINUTE + 1);
  await signUp(ana, "ana@example.com", ANA_PASSWORD);
  const anasCode = codeIn(s.emails.at(-1));
  assert.notEqual(anasCode, mallorysCode);

  assert.equal((await typeCode(ana, anasCode)).status, 303);
  const kept = passwordOf(e, "ana@example.com");
  assert.equal(await verifyPassword(kept, ANA_PASSWORD), true);
  assert.equal(await verifyPassword(kept, MALLORY_PASSWORD), false);
  assert.equal(rows(e, "SELECT count(*) AS n FROM credentials")[0].n, 1);

  /* Mallory's attempt is still hers, still unverified, and still useless
     without the code that went to Ana. */
  const guess = await typeCode(mallory, wrongFor(mallorysCode));
  assert.equal(guess.status, 400);
  assert.equal(await verifyPassword(passwordOf(e, "ana@example.com"), MALLORY_PASSWORD), false);
});

test("a new code keeps the attempt's password, and a password typed again replaces it", async () => {
  const s = services();
  const e = env();
  const b = new Browser(e);
  await signUp(b, "ana@example.com", "first choice of password");
  later(MINUTE + 1);
  assert.equal((await again(b)).status, 303);
  assert.equal(s.emails.length, 2);
  assert.match(s.emails[1].text, /sets the password/);
  assert.equal((await typeCode(b, codeIn(s.emails[1]))).status, 303);
  assert.equal(await verifyPassword(passwordOf(e, "ana@example.com"), "first choice of password"), true);

  /* Within the minute the address gets no new code: the browser keeps its
     attempt, now with the password it typed last. */
  const c = new Browser(e, { ip: "203.0.113.9" });
  later(MINUTE + 1);
  await signUp(c, "bo@example.com", "the one I mistyped");
  const sent = s.emails.length;
  assert.equal((await signUp(c, "bo@example.com", "the one I meant all along")).status, 303);
  assert.equal(s.emails.length, sent, "no second code within the minute");
  assert.equal((await typeCode(c, codeIn(s.emails.at(-1)))).status, 303);
  const kept = passwordOf(e, "bo@example.com");
  assert.equal(await verifyPassword(kept, "the one I meant all along"), true);
  assert.equal(await verifyPassword(kept, "the one I mistyped"), false);
});

test("an account that has a password gets a new one only through its code, which signs it out everywhere else, as logged", async () => {
  const s = services();
  const e = env();
  const first = new Browser(e);
  await signUp(first, "ana@example.com", ANA_PASSWORD);
  await typeCode(first, codeIn(s.emails.at(-1)));
  /* Someone else has the password, and a session of their own with it. */
  const thief = new Browser(e, { ip: "192.0.2.66" });
  assert.equal((await withPassword(thief, "ana@example.com", ANA_PASSWORD)).status, 303);
  assert.equal((await thief.get("/")).status, 200);
  later(MINUTE + 1);
  const second = new Browser(e, { ip: "203.0.113.20" });
  await signUp(second, "ana@example.com", "a brand new passphrase");
  assert.match(s.emails.at(-1).text, /replacing any password the account had and signing it out everywhere else/);
  assert.equal(await verifyPassword(passwordOf(e, "ana@example.com"), ANA_PASSWORD), true, "unchanged until the code");
  assert.equal((await thief.get("/")).status, 200, "and so is every session");
  await typeCode(second, codeIn(s.emails.at(-1)));
  const kept = passwordOf(e, "ana@example.com");
  assert.equal(await verifyPassword(kept, "a brand new passphrase"), true);
  assert.equal(await verifyPassword(kept, ANA_PASSWORD), false);
  assert.deepEqual(eventsOf(e, "ana@example.com"),
                   ["signup", "password_added", "signin_password", "signin", "password_reset"]);
  assert.equal(count(e, "users"), 1);

  /* Every other session ended, as the log says: the thief's and the first browser's. */
  assert.equal((await thief.get("/")).location, "/signin");
  assert.equal((await first.get("/")).location, "/signin");
  assert.deepEqual(sessionsOf(e, "ana@example.com").map((r) => r.id), [sha256(second.jar.get(SESSION))]);
  const home = await second.get("/");
  assert.match(home.text, /Password reset with an emailed code, and every other session signed out/);
  assert.doesNotMatch(home.text, /Password changed/);

  /* An account with no password that gets one this way is signed out elsewhere too. */
  const coded = new Browser(e, { ip: "203.0.113.30" });
  await askCode(coded, "bo@example.com");
  await typeCode(coded, codeIn(s.emails.at(-1)));
  later(MINUTE + 1);
  const added = new Browser(e, { ip: "203.0.113.31" });
  await signUp(added, "bo@example.com", "bo picks a passphrase now");
  await typeCode(added, codeIn(s.emails.at(-1)));
  assert.equal((await coded.get("/")).location, "/signin");
  assert.equal((await added.get("/")).status, 200);
  assert.deepEqual(eventsOf(e, "bo@example.com"), ["signup", "signin", "password_added"]);
});

test("a short or breached password is refused before any code is sent, and the form never shows it back", async () => {
  const s = services({ breached: ["password123456"] });
  const e = env();
  const b = new Browser(e);
  for (const [password, says] of [["too short", /at least 12/], ["password123456", /known data breach/]]) {
    const r = await signUp(b, "ana@example.com", password);
    assert.equal(r.status, 400);
    assert.match(r.text, says);
    assert.ok(!r.text.includes(password), "not echoed");
    assert.match(r.text, /value="ana@example.com"/, "the address is kept in the form");
  }
  const bad = await signUp(b, "not an address", ANA_PASSWORD);
  assert.equal(bad.status, 400);
  assert.match(bad.text, /does not look right/);
  assert.equal(s.emails.length, 0);
  assert.equal(count(e, "signins"), 0);

  s.hibp = "down";
  const { result, lines } = await logged(() => signUp(b, "ana@example.com", ANA_PASSWORD));
  assert.equal(result.status, 303, "Have I Been Pwned down does not stop a sign-up");
  assert.equal(s.emails.length, 1);
  for (const line of lines) assert.doesNotMatch(line, /@|example\.com|plum|kettle/);
});

test("the sign-up form is refused from another site or without its token, and one network hashes twenty an hour", async () => {
  const s = services();
  const e = env();
  const b = new Browser(e);
  const form = await b.get("/signup");
  const token = tokenFor(form.text, "/signup");
  const body = { form: token, email: "ana@example.com", password: ANA_PASSWORD };
  assert.equal((await b.post("/signup", body, { "sec-fetch-site": "same-site", origin: "https://ranwhat.com" })).status, 403);
  assert.equal((await b.post("/signup", body, {})).status, 403);
  assert.equal((await b.post("/signup", { ...body, form: "x" })).status, 403);
  const signinToken = tokenFor((await b.get("/signin")).text, "/signin");
  assert.equal((await b.post("/signup", { ...body, form: signinToken })).status, 403, "another form's token");
  assert.equal(s.ranges.length, 0);
  assert.equal(count(e, "signins"), 0);

  for (let i = 0; i < 20; i++) {
    assert.equal((await signUp(b, "person@example.com", ANA_PASSWORD)).status, 303, `sign-up ${i}`);
  }
  const over = await signUp(new Browser(e, { ip: b.ip }), "one-more@example.com", ANA_PASSWORD);
  assert.equal(over.status, 429);
  assert.equal(s.ranges.length, 20, "refused before the breach check");
  assert.equal(s.emails.length, 1, "the same address inside the minute: one code");
});

test("when the runtime refuses the iteration count, sign-up says passwords are not available and sends nothing", async () => {
  const s = services();
  const e = env({ PBKDF2_ITERATIONS: undefined });
  const b = new Browser(e);
  crypto.subtle.deriveBits = async () => {
    throw new DOMException("Pbkdf2 failed: iteration counts above 100000 are not supported", "NotSupportedError");
  };
  try {
    const { result, lines } = await logged(() => signUp(b, "ana@example.com", ANA_PASSWORD));
    assert.equal(result.status, 503);
    assert.match(result.text, /Passwords are not available just now/);
    assert.match(result.text, /href="\/signin"/);
    assert.deepEqual(lines, ["account password hash: NotSupportedError"]);
  } finally {
    delete crypto.subtle.deriveBits;
  }
  assert.equal(s.emails.length, 0);
  assert.equal(count(e, "signins"), 0);
  assert.equal(count(e, "credentials"), 0);
});

test("a 'verify' attempt that holds no usable hash attaches nothing", async () => {
  const s = services();
  const e = env();
  const b = new Browser(e);
  await signUp(b, "ana@example.com", ANA_PASSWORD);
  e.LIST.sql.prepare("UPDATE signins SET password_hash = ?").run(`${PREFIX}1000$short$short`);
  const r = await typeCode(b, codeIn(s.emails.at(-1)));
  assert.equal(r.status, 303);
  assert.equal(r.location, "/signup");
  assert.equal(count(e, "credentials"), 0);
  assert.equal(count(e, "users"), 0);
  assert.ok(!b.jar.has(SESSION));
});

/* ---------- signing in with one ---------- */

async function withPassword(b, email, password) {
  const form = await b.get("/signin/password");
  assert.equal(form.status, 200, form.text);
  return b.post("/signin/password", { form: tokenFor(form.text, "/signin/password"), email, password, next: "/" });
}

/* An account with a password, made by signing up, its browser signed in. */
async function account(e, s, email, password, ip = "198.51.100.7") {
  const b = new Browser(e, { ip });
  assert.equal((await signUp(b, email, password)).status, 303);
  assert.equal((await typeCode(b, codeIn(s.emails.at(-1)))).status, 303);
  return b;
}

/* The iteration count of every PBKDF2 run while fn runs. */
async function derived(fn) {
  const counts = [];
  const real = crypto.subtle.deriveBits;
  crypto.subtle.deriveBits = (algorithm, ...rest) => {
    counts.push(algorithm.iterations);
    return real.call(crypto.subtle, algorithm, ...rest);
  };
  try {
    return { result: await fn(), counts };
  } finally {
    delete crypto.subtle.deriveBits;
  }
}

/* A page with its address and its form tokens taken out, to compare two. */
const plain = (text, email) => text.replaceAll(email, "ADDRESS").replace(/name="form" value="[^"]+"/g, "");

const sessionsOf = (e, email) => rows(e, `SELECT s.* FROM sessions s JOIN users u ON u.id = s.user_id
                                          WHERE u.email = ?`, email);

test("a password signs in as a code does, in place of the browser's old session, but not as a fresh code", async () => {
  const s = services();
  const e = env();
  await account(e, s, "ana@example.com", ANA_PASSWORD);
  later(MINUTE + 1);
  const bo = await account(e, s, "bo@example.com", "bo has a passphrase too", "203.0.113.5");
  const [{ signed_in_at: before }] = rows(e, "SELECT signed_in_at FROM users WHERE email = 'ana@example.com'");
  later(MINUTE);

  const b = new Browser(e, { ip: "192.0.2.10" });
  const form = await b.get("/signin/password");
  assert.match(form.text, /autocomplete="username"/);
  assert.match(form.text, /type="password" autocomplete="current-password"/);
  assert.match(form.text, /href="\/reset"/);
  assert.doesNotMatch(form.text, /<script|\son[a-z]+=/i);
  assert.match((await b.get("/signin")).text, /href="\/signin\/password"/);
  b.jar.set(SESSION, bo.jar.get(SESSION));                      // the browser had another session
  const r = await b.post("/signin/password", { form: tokenFor(form.text, "/signin/password"),
                                               email: "Ana@Example.com", password: ANA_PASSWORD, next: "/" });
  assert.equal(r.status, 303, r.text);
  assert.equal(r.location, "/");
  assert.notEqual(b.jar.get(SESSION), bo.jar.get(SESSION));
  assert.ok(!b.jar.has(SIGNIN));
  assert.equal(sessionsOf(e, "bo@example.com").length, 0, "the session the browser had is over");
  const [session] = rows(e, "SELECT * FROM sessions WHERE id = ?", sha256(b.jar.get(SESSION)));
  assert.equal(session.user_id, rows(e, "SELECT id FROM users WHERE email = 'ana@example.com'")[0].id);
  assert.equal(session.authed_at, 0, "a password is not a fresh code");
  assert.ok(rows(e, "SELECT signed_in_at FROM users WHERE email = 'ana@example.com'")[0].signed_in_at > before);
  assert.equal(eventsOf(e, "ana@example.com").at(-1), "signin_password");

  const home = await b.get("/");
  assert.equal(home.status, 200);
  assert.match(home.text, /Signed in with your password/);
  assert.match(home.text, /id="current-password"/, "changing it asks for the current one");
  assert.equal((await b.get("/signin/password")).location, "/", "signed in already");
  assert.ok(!everything(e).includes(ANA_PASSWORD));
});

test("a wrong password, an address with no password and one with no account get one answer, after the same PBKDF2 work", async () => {
  const s = services();
  const e = env();
  await account(e, s, "ana@example.com", ANA_PASSWORD);
  const bo = new Browser(e, { ip: "203.0.113.5" });
  await askCode(bo, "bo@example.com");
  await typeCode(bo, codeIn(s.emails.at(-1)));

  const b = new Browser(e, { ip: "192.0.2.10" });
  const answers = [];
  for (const [email, password] of [["ana@example.com", "not ana's password at all"],
                                   ["bo@example.com", ANA_PASSWORD],
                                   ["cy@example.com", ANA_PASSWORD]]) {
    const { result, counts } = await derived(() => withPassword(b, email, password));
    assert.deepEqual(counts, [1000], `${email}: one run at the current count`);
    assert.equal(result.status, 400, email);
    assert.match(result.text, /That email and password do not match/);
    assert.ok(!result.text.includes(password), "never shown back");
    assert.deepEqual(result.headers.getSetCookie(), []);
    answers.push(plain(result.text, email));
  }
  assert.equal(answers[1], answers[0]);
  assert.equal(answers[2], answers[0]);
  assert.ok(!b.jar.has(SESSION));
  assert.equal(count(e, "users"), 2, "no account is made");
  assert.equal(rows(e, "SELECT count(*) AS n FROM auth_events WHERE event = 'signin_password'")[0].n, 0);

  /* The decoy runs at whatever count is set now, as a real hash would. */
  e.PBKDF2_ITERATIONS = "3000";
  const { counts } = await derived(() => withPassword(b, "dee@example.com", ANA_PASSWORD));
  assert.deepEqual(counts, [3000]);

  /* Ana's hash is still at 1,000, as she has not signed in since the count
     was raised: it is topped up to 3,000, so her address costs what one
     with no account does and gets the same answer. */
  const older = await derived(() => withPassword(new Browser(e, { ip: "192.0.2.11" }), "ana@example.com", "still not ana's password"));
  assert.deepEqual(older.counts, [1000, 2000]);
  assert.equal(older.result.status, 400);
  assert.equal(plain(older.result.text, "ana@example.com"), answers[0]);
  assert.match(passwordOf(e, "ana@example.com"), /^pbkdf2-sha256\$1000\$/, "a wrong password rehashes nothing");

  /* A runtime that refuses the count refuses the decoy and the top-up
     alike, though it would run Ana's own 1,000. */
  const runtime = crypto.subtle.deriveBits;
  const ran = [];
  crypto.subtle.deriveBits = (algorithm, ...rest) => {
    ran.push(algorithm.iterations);
    if (algorithm.iterations > 1500) {
      return Promise.reject(new DOMException("iteration counts above 1500 are not supported", "NotSupportedError"));
    }
    return runtime.call(crypto.subtle, algorithm, ...rest);
  };
  try {
    const refusedFor = [];
    for (const [email, ip] of [["ana@example.com", "192.0.2.12"], ["eve@example.com", "192.0.2.13"]]) {
      const { result, lines } = await logged(() => withPassword(new Browser(e, { ip }), email, "not the password at all"));
      assert.deepEqual(lines, ["account password check: NotSupportedError"], email);
      refusedFor.push([result.status, plain(result.text, email)]);
    }
    assert.deepEqual(ran, [1000, 2000, 3000]);
    assert.equal(refusedFor[0][0], 503);
    assert.deepEqual(refusedFor[1], refusedFor[0]);
  } finally {
    delete crypto.subtle.deriveBits;
  }

  /* The form is refused from another site or without its token, before any hashing. */
  const form = await b.get("/signin/password");
  const body = { form: tokenFor(form.text, "/signin/password"), email: "ana@example.com", password: ANA_PASSWORD };
  const refused = await derived(async () => [
    (await b.post("/signin/password", body, { "sec-fetch-site": "same-site", origin: "https://ranwhat.com" })).status,
    (await b.post("/signin/password", { ...body, form: "forged" })).status,
    (await b.post("/signin/password", { ...body, form: tokenFor((await b.get("/signin")).text, "/signin") })).status,
  ]);
  assert.deepEqual(refused.result, [403, 403, 403]);
  assert.deepEqual(refused.counts, []);
  assert.ok(!b.jar.has(SESSION));
});

test("an address gets five password tries in fifteen minutes, then only a code signs it in, and the code gives them back", async () => {
  const s = services();
  const e = env();
  await account(e, s, "ana@example.com", ANA_PASSWORD);
  assert.equal(TRIES_PER_ADDRESS, 5);
  assert.equal(LOCKOUT, 15 * MINUTE);
  const m = new Browser(e, { ip: "203.0.113.66" });
  for (let i = 1; i < TRIES_PER_ADDRESS; i++) {
    assert.equal((await withPassword(m, "ana@example.com", `wrong guess number ${i}`)).status, 400);
  }
  const fifth = await withPassword(m, "ana@example.com", "the fifth wrong guess");
  assert.equal(fifth.status, 429);
  assert.match(fifth.text, /password sign-in\s+is paused/);

  /* Now even the right password, from another network, does not sign in,
     and is not hashed. */
  const ana = new Browser(e, { ip: "198.51.100.9" });
  const { result: held, counts } = await derived(() => withPassword(ana, "ana@example.com", ANA_PASSWORD));
  assert.equal(held.status, 429);
  assert.deepEqual(counts, []);
  assert.ok(!ana.jar.has(SESSION));

  /* An address with no account locks the same way, with the same page. */
  for (let i = 0; i < TRIES_PER_ADDRESS; i++) await withPassword(m, "nobody@example.com", `guess ${i} for nobody`);
  const nobody = await withPassword(m, "nobody@example.com", "one guess more");
  assert.equal(nobody.status, 429);
  assert.equal(plain(nobody.text, "nobody@example.com"), plain(held.text, "ana@example.com"));

  /* The page offers the code for that address, and typing it gives the
     address its tries back. */
  assert.match(held.text, /name="email" value="ana@example.com"/);
  later(MINUTE + 1);
  assert.match(held.text, /<div class="cf-turnstile"[^>]* data-action="signin">/);
  const sent = await ana.post("/signin", { form: tokenFor(held.text, "/signin"), email: "ana@example.com", next: "/",
                                           "cf-turnstile-response": solved("signin") });
  assert.equal(sent.location, "/signin/code");
  assert.equal((await typeCode(ana, codeIn(s.emails.at(-1)))).status, 303);
  assert.equal((await withPassword(new Browser(e, { ip: "198.51.100.10" }), "ana@example.com", ANA_PASSWORD)).status, 303);

  /* The other address's tries come back when the window ends. */
  assert.equal((await withPassword(m, "nobody@example.com", "still guessing")).status, 429);
  later(LOCKOUT + 1);
  assert.equal((await withPassword(m, "nobody@example.com", "still guessing")).status, 400);
  assert.ok(!everything(e).includes("nobody@example.com"), "kept only as an HMAC");
});

test("a right password gives the address its tries back", async () => {
  const s = services();
  const e = env();
  await account(e, s, "ana@example.com", ANA_PASSWORD);
  const b = new Browser(e, { ip: "203.0.113.70" });
  for (let i = 1; i < TRIES_PER_ADDRESS; i++) await withPassword(b, "ana@example.com", `a typo number ${i}`);
  assert.equal((await withPassword(b, "ana@example.com", ANA_PASSWORD)).status, 303);
  const c = new Browser(e, { ip: "203.0.113.71" });
  for (let i = 1; i < TRIES_PER_ADDRESS; i++) {
    assert.equal((await withPassword(c, "ana@example.com", `a typo number ${i}`)).status, 400);
  }
  assert.equal((await withPassword(c, "ana@example.com", ANA_PASSWORD)).status, 303);
});

test("wrong passwords pause password sign-in for the network they come from, never for everyone", async () => {
  const s = services();
  const e = env();
  await account(e, s, "ana@example.com", ANA_PASSWORD);
  assert.equal(WRONG_PER_NETWORK, 10);

  /* A hundred wrong passwords, ten from each of ten networks, many addresses. */
  for (let n = 1; n <= 10; n++) {
    for (let i = 0; i < WRONG_PER_NETWORK; i++) {
      const r = await withPassword(new Browser(e, { ip: `192.0.2.${n}` }), `person${n}-${i}@example.com`,
                                   `stuffed password ${i}`);
      assert.equal(r.status, 400, `network ${n}, try ${i}`);
    }
  }
  const ana = new Browser(e, { ip: "198.51.100.9" });
  assert.equal((await withPassword(ana, "ana@example.com", ANA_PASSWORD)).status, 303, "nothing paused for Ana");

  /* Each of those networks is paused, unhashed, even for the right password. */
  const { result, counts } = await derived(() => withPassword(new Browser(e, { ip: "192.0.2.3" }), "ana@example.com",
                                                              ANA_PASSWORD));
  assert.equal(result.status, 429);
  assert.match(result.text, /from your network/);
  assert.deepEqual(counts, []);

  /* Every address in an IPv6 /64 is one network. */
  const statuses = [];
  for (let i = 0; i < 12; i++) {
    statuses.push((await withPassword(new Browser(e, { ip: `2001:db8:1:2::${(i % 5) + 1}` }), `spray${i}@example.org`,
                                      `wrong password ${i}`)).status);
  }
  assert.deepEqual(statuses, [...Array(10).fill(400), 429, 429]);

  /* There, the code still signs in; and the pause ends with the window. */
  const there = new Browser(e, { ip: "2001:db8:1:2::77" });
  later(MINUTE + 1);
  await askCode(there, "ana@example.com");
  assert.equal((await typeCode(there, codeIn(s.emails.at(-1)))).status, 303, "the code still signs in");
  assert.equal((await withPassword(new Browser(e, { ip: "2001:db8:1:2::78" }), "ana@example.com", ANA_PASSWORD)).status,
               429);
  later(LOCKOUT);
  assert.equal((await withPassword(new Browser(e, { ip: "2001:db8:1:2::79" }), "ana@example.com", ANA_PASSWORD)).status,
               303);
});

test("one network has twenty password hashes an hour, sign-ins among them", async () => {
  services();
  const e = env();
  const b = new Browser(e, { ip: "203.0.113.80" });
  for (let i = 0; i < 20; i++) {
    if (i === WRONG_PER_NETWORK) later(LOCKOUT + 1);
    assert.equal((await withPassword(b, `someone${i}@example.com`, ANA_PASSWORD)).status, 400, `try ${i}`);
  }
  later(LOCKOUT + 1);
  const { result, counts } = await derived(() => withPassword(b, "one-more@example.com", ANA_PASSWORD));
  assert.equal(result.status, 429);
  assert.match(result.text, /from your network/);
  assert.deepEqual(counts, []);
});

test("signing in hashes the password again when the count has been raised, and only then", async () => {
  const s = services();
  const e = env();
  await account(e, s, "ana@example.com", ANA_PASSWORD);
  const first = passwordOf(e, "ana@example.com");
  assert.match(first, /^pbkdf2-sha256\$1000\$/);

  const same = await derived(() => withPassword(new Browser(e, { ip: "203.0.113.30" }), "ana@example.com", ANA_PASSWORD));
  assert.equal(same.result.status, 303);
  assert.deepEqual(same.counts, [1000]);
  assert.equal(passwordOf(e, "ana@example.com"), first, "kept as it was");

  e.PBKDF2_ITERATIONS = "2000";
  const raised = await derived(() => withPassword(new Browser(e, { ip: "203.0.113.31" }), "ana@example.com", ANA_PASSWORD));
  assert.equal(raised.result.status, 303);
  assert.deepEqual(raised.counts, [1000, 1000, 2000],
                   "verified at its own count and topped up to the new one, then hashed again at it");
  const second = passwordOf(e, "ana@example.com");
  assert.match(second, /^pbkdf2-sha256\$2000\$/);
  assert.equal(await verifyPassword(second, ANA_PASSWORD), true);

  e.PBKDF2_ITERATIONS = "3000";
  const wrong = await withPassword(new Browser(e, { ip: "203.0.113.32" }), "ana@example.com", "not the password at all");
  assert.equal(wrong.status, 400);
  assert.equal(passwordOf(e, "ana@example.com"), second, "a wrong password changes nothing");
  assert.deepEqual(eventsOf(e, "ana@example.com"), ["signup", "password_added", "signin_password", "signin_password"]);
});

/* ---------- a forgotten one ---------- */

async function askReset(b, email) {
  const form = await b.get("/reset");
  assert.equal(form.status, 200, form.text);
  return b.post("/reset", { form: tokenFor(form.text, "/reset"), email, "cf-turnstile-response": solved("reset") });
}

test("asking for a reset answers the same for every address, and takes from the day's mail", async () => {
  const s = services();
  const e = env();
  await account(e, s, "ana@example.com", ANA_PASSWORD);
  const shape = async (email, ip) => {
    const b = new Browser(e, { ip });
    const r = await askReset(b, email);
    return { status: r.status, location: r.location, text: r.text, cookies: [...b.jar.keys()].sort() };
  };
  later(MINUTE + 1);
  const known = await shape("ana@example.com", "203.0.113.1");
  const unknown = await shape("nobody@example.com", "203.0.113.2");
  assert.equal(known.status, 303);
  assert.equal(known.location, "/signin/code");
  assert.deepEqual(unknown, known);
  assert.equal(s.emails.length, 3, "a code goes to both, after the reply");
  assert.deepEqual(s.emails[1].to, ["ana@example.com"]);
  assert.equal(s.emails[1].subject, "Your ranwhat password reset code");
  assert.match(s.emails[1].text, /replaces this account's password and signs it out everywhere else/);
  assert.deepEqual(rows(e, "SELECT sent FROM mail_counts WHERE kind = 'auth'"), [{ sent: 3 }]);

  e.LIST.sql.prepare("UPDATE mail_counts SET sent = ? WHERE kind = 'auth'").run(AUTH_MAIL_PER_DAY);
  later(MINUTE + 1);
  const spentKnown = await shape("ana@example.com", "203.0.113.3");
  const spentUnknown = await shape("nobody@example.com", "203.0.113.4");
  assert.equal(spentKnown.status, 503);
  assert.match(spentKnown.text, /No more codes today/);
  assert.deepEqual(spentUnknown, spentKnown);
  assert.equal(s.emails.length, 3);

  const bad = await askReset(new Browser(e, { ip: "203.0.113.5" }), "not an address");
  assert.equal(bad.status, 400);
  assert.match(bad.text, /does not look right/);
});

test("a reset code sets the new password, ends every session of the account but this one, and is logged", async () => {
  const s = services({ breached: ["password123456"] });
  const e = env();
  const laptop = await account(e, s, "ana@example.com", ANA_PASSWORD);
  const phone = new Browser(e, { ip: "198.51.100.20" });
  assert.equal((await withPassword(phone, "ana@example.com", ANA_PASSWORD)).status, 303);
  assert.equal(sessionsOf(e, "ana@example.com").length, 2);

  later(MINUTE + 1);
  const b = new Browser(e, { ip: "203.0.113.40" });
  await askReset(b, "ana@example.com");
  const code = codeIn(s.emails.at(-1));
  const page = await b.get("/signin/code");
  assert.match(page.text, /type="password" autocomplete="new-password"/);
  assert.match(page.text, /Set password and sign in/);
  assert.match(page.text, /href="\/reset">Use a different email/);
  const token = tokenFor(page.text, "/signin/code");

  /* A refused password costs the attempt no try, and changes nothing. */
  for (const [password, says] of [["too short", /at least 12/], ["password123456", /known data breach/]]) {
    const r = await b.post("/signin/code", { form: token, code, password });
    assert.equal(r.status, 400);
    assert.match(r.text, says);
    assert.ok(!r.text.includes(password) && !r.text.includes(code), "neither is shown back");
  }
  assert.equal(rows(e, "SELECT tries FROM signins WHERE purpose = 'reset'")[0].tries, 0);

  /* A wrong code changes nothing either. */
  const wrong = await b.post("/signin/code", { form: token, code: wrongFor(code), password: "a fresh new passphrase" });
  assert.equal(wrong.status, 400);
  assert.match(wrong.text, /That code is not right. 4 tries left/);
  assert.equal(await verifyPassword(passwordOf(e, "ana@example.com"), ANA_PASSWORD), true);
  assert.equal(sessionsOf(e, "ana@example.com").length, 2);

  const held = b.jar.get(SIGNIN);
  const done = await b.post("/signin/code", { form: token, code, password: "a fresh new passphrase" });
  assert.equal(done.status, 303, done.text);
  assert.equal(done.location, "/");
  assert.ok(b.jar.has(SESSION));
  assert.ok(!b.jar.has(SIGNIN));
  assert.deepEqual(sessionsOf(e, "ana@example.com").map((x) => x.id), [sha256(b.jar.get(SESSION))]);
  assert.equal((await laptop.get("/")).location, "/signin");
  assert.equal((await phone.get("/")).location, "/signin");
  const kept = passwordOf(e, "ana@example.com");
  assert.equal(await verifyPassword(kept, "a fresh new passphrase"), true);
  assert.equal(await verifyPassword(kept, ANA_PASSWORD), false);
  assert.equal(eventsOf(e, "ana@example.com").at(-1), "password_reset");
  assert.match((await b.get("/")).text, /Password reset with an emailed code, and every other session signed out/);
  assert.equal(rows(e, "SELECT count(*) AS n FROM signins WHERE used_at IS NULL")[0].n, 0, "the code is used");
  assert.ok(!everything(e).includes("a fresh new passphrase"));

  assert.equal((await withPassword(new Browser(e, { ip: "203.0.113.41" }), "ana@example.com", ANA_PASSWORD)).status, 400);
  assert.equal((await withPassword(new Browser(e, { ip: "203.0.113.42" }), "ana@example.com", "a fresh new passphrase")).status, 303);

  /* A used reset code does nothing more, and is not hashed for, even in a
     browser that kept its cookie. */
  assert.equal((await b.post("/signin/code", { form: token, code, password: "and yet another one" })).status, 403);
  b.jar.set(SIGNIN, held);
  const again = await derived(() => b.post("/signin/code", { form: token, code, password: "and yet another one" }));
  assert.equal(again.result.status, 400);
  assert.match(again.result.text, /expired or was already used/);
  assert.deepEqual(again.counts, []);
  assert.equal(await verifyPassword(passwordOf(e, "ana@example.com"), "a fresh new passphrase"), true);
});

test("a reset for an address with no account makes one with that password, as sign-up would", async () => {
  const s = services();
  const e = env();
  const b = new Browser(e);
  await askReset(b, "new@example.com");
  assert.equal(count(e, "users"), 0);
  const page = await b.get("/signin/code");
  const r = await b.post("/signin/code", { form: tokenFor(page.text, "/signin/code"), code: codeIn(s.emails.at(-1)),
                                           password: ANA_PASSWORD });
  assert.equal(r.status, 303);
  assert.equal(await verifyPassword(passwordOf(e, "new@example.com"), ANA_PASSWORD), true);
  assert.deepEqual(eventsOf(e, "new@example.com"), ["signup", "password_added"]);
});

/* ---------- changing and removing one, signed in ---------- */

test("changing the password needs the current one, and ends every other session", async () => {
  const s = services();
  const e = env();
  const first = await account(e, s, "ana@example.com", ANA_PASSWORD);
  const b = new Browser(e, { ip: "198.51.100.30" });
  await withPassword(b, "ana@example.com", ANA_PASSWORD);
  const other = new Browser(e, { ip: "198.51.100.31" });
  await withPassword(other, "ana@example.com", ANA_PASSWORD);
  const home = await b.get("/");
  assert.match(home.text, /<h2>Sign-in methods<\/h2>/);
  assert.match(home.text, /Password<\/strong> <span class="tag">set/);
  const token = tokenFor(home.text, "/password");
  const NEW = "a brand new passphrase";

  assert.equal((await b.post("/password", { form: "forged", current: ANA_PASSWORD, password: NEW })).status, 403);
  assert.equal((await b.post("/password", { form: await formToken(e, sha256(b.jar.get(SESSION)), "org"),
                                            current: ANA_PASSWORD, password: NEW })).status, 403, "another form's token");
  assert.equal((await b.post("/password", { form: token, current: ANA_PASSWORD, password: NEW },
    { "sec-fetch-site": "same-site", origin: "https://ranwhat.com" })).status, 403);
  for (const current of [undefined, "not my password at all"]) {
    const r = await b.post("/password", { form: token, password: NEW, ...(current ? { current } : {}) });
    assert.equal(r.status, 400);
    assert.match(r.text, /Your current password is not right/);
  }
  const short = await b.post("/password", { form: token, current: ANA_PASSWORD, password: "too short" });
  assert.equal(short.status, 400);
  assert.match(short.text, /at least 12/);
  assert.equal(await verifyPassword(passwordOf(e, "ana@example.com"), ANA_PASSWORD), true);
  assert.equal(sessionsOf(e, "ana@example.com").length, 3);

  const r = await b.post("/password", { form: token, current: ANA_PASSWORD, password: NEW });
  assert.equal(r.status, 303, r.text);
  assert.equal(r.location, "/");
  const kept = passwordOf(e, "ana@example.com");
  assert.equal(await verifyPassword(kept, NEW), true);
  assert.equal(await verifyPassword(kept, ANA_PASSWORD), false);
  assert.equal((await b.get("/")).status, 200, "this session stays");
  assert.equal((await first.get("/")).location, "/signin");
  assert.equal((await other.get("/")).location, "/signin");
  assert.deepEqual(sessionsOf(e, "ana@example.com").map((x) => x.id), [sha256(b.jar.get(SESSION))]);
  assert.equal(eventsOf(e, "ana@example.com").at(-1), "password_changed");
  assert.match((await b.get("/")).text, /Password changed, and every other session signed out/);
  assert.ok(!everything(e).includes(NEW));
});

test("with a code typed in the last 15 minutes the current password is not asked for, and wrong ones lock as sign-in does", async () => {
  const s = services();
  const e = env();
  const b = await account(e, s, "ana@example.com", ANA_PASSWORD);
  let home = await b.get("/");
  assert.doesNotMatch(home.text, /id="current-password"/);
  assert.match(home.text, /You typed an emailed code in the last 15 minutes/);
  assert.equal((await b.post("/password", { form: tokenFor(home.text, "/password"), password: "changed with a code" })).status,
    303);
  assert.equal(await verifyPassword(passwordOf(e, "ana@example.com"), "changed with a code"), true);

  later(FRESH_FOR + 1);
  home = await b.get("/");
  assert.match(home.text, /id="current-password"/);
  const token = tokenFor(home.text, "/password");
  for (let i = 1; i < TRIES_PER_ADDRESS; i++) {
    assert.equal((await b.post("/password", { form: token, current: `guess ${i}`, password: "a stolen session's pick" })).status, 400);
  }
  const fifth = await b.post("/password", { form: token, current: "guess 5", password: "a stolen session's pick" });
  assert.equal(fifth.status, 429);
  assert.match(fifth.text, /Too many tries with a password/);
  const right = await b.post("/password", { form: token, current: "changed with a code", password: "a stolen session's pick" });
  assert.equal(right.status, 429, "locked for the right one too");
  assert.equal(await verifyPassword(passwordOf(e, "ana@example.com"), "changed with a code"), true);

  /* A fresh code is the way through, and gives the address its tries back. */
  const asked = await b.post("/stepup", { form: tokenFor(home.text, "/stepup"), next: "/" });
  assert.equal(asked.location, "/signin/code");
  assert.equal((await typeCode(b, codeIn(s.emails.at(-1)))).status, 303);
  home = await b.get("/");
  assert.doesNotMatch(home.text, /id="current-password"/);
  assert.equal((await b.post("/password", { form: tokenFor(home.text, "/password"), password: "changed with a code again" })).status,
    303);
  assert.equal(await verifyPassword(passwordOf(e, "ana@example.com"), "changed with a code again"), true);
  assert.equal((await withPassword(new Browser(e, { ip: "203.0.113.90" }), "ana@example.com", "changed with a code again")).status,
    303);
});

test("the sign-in methods: the code always, a password added with a fresh code and removed, the rest coming", async () => {
  const s = services();
  const e = env();
  const b = new Browser(e);
  await askCode(b, "ana@example.com");
  await typeCode(b, codeIn(s.emails.at(-1)));
  let home = await b.get("/");
  assert.doesNotMatch(home.text, /<script|\son[a-z]+=/i);
  assert.match(home.text, /data-method="code"><strong>Emailed code<\/strong> <span class="tag">always on/);
  assert.match(home.text, /data-method="password"><strong>Password<\/strong> <span class="tag">not set/);
  for (const [key, name] of [["google", "Google"], ["github", "GitHub"], ["passkeys", "Passkeys"]]) {
    assert.match(home.text, new RegExp(`data-method="${key}"><strong>${name}</strong> <span class="tag">coming`));
  }
  assert.doesNotMatch(home.text, /action="\/password\/remove"/);

  const added = await b.post("/password", { form: tokenFor(home.text, "/password"), password: ANA_PASSWORD });
  assert.equal(added.status, 303);
  assert.equal(await verifyPassword(passwordOf(e, "ana@example.com"), ANA_PASSWORD), true);
  assert.equal(eventsOf(e, "ana@example.com").at(-1), "password_added");
  home = await b.get("/");
  assert.match(home.text, /data-method="password"><strong>Password<\/strong> <span class="tag">set/);
  assert.match(home.text, /action="\/password\/remove"/);

  later(FRESH_FOR + 1);
  home = await b.get("/");
  const remove = tokenFor(home.text, "/password/remove");
  assert.match(home.text, /id="current-password-remove"/);
  const refused = await b.post("/password/remove", { form: remove, current: "not the password" });
  assert.equal(refused.status, 400);
  assert.ok(passwordOf(e, "ana@example.com"));
  const removed = await b.post("/password/remove", { form: remove, current: ANA_PASSWORD });
  assert.equal(removed.status, 303);
  assert.equal(passwordOf(e, "ana@example.com"), null);
  assert.equal(eventsOf(e, "ana@example.com").at(-1), "password_removed");
  assert.equal((await withPassword(new Browser(e, { ip: "203.0.113.91" }), "ana@example.com", ANA_PASSWORD)).status, 400);

  /* Without a password and without a fresh code, adding one needs the code. */
  home = await b.get("/");
  assert.match(home.text, /tag">not set/);
  assert.match(home.text, /Adding one needs an emailed code typed in the last 15 minutes/);
  assert.doesNotMatch(home.text, /action="\/password"/);
  assert.match(home.text, /action="\/stepup"/);
  const late = await b.post("/password", { form: await formToken(e, sha256(b.jar.get(SESSION)), "password"),
                                          password: "slipped in without a code" });
  assert.equal(late.status, 403);
  assert.equal(passwordOf(e, "ana@example.com"), null);
  assert.equal((await b.post("/password/remove", { form: remove })).status, 303, "nothing to remove");
});
