/* Passwords: how one is hashed, verified and judged (password.js), and
 * making an account with one on account.ranwhat.com, end to end through
 * the Worker over a real SQLite database. PBKDF2 runs at 1,000 iterations
 * here, and Have I Been Pwned and Resend are stand-ins.
 *
 * The case this file is for: someone signs up with another person's
 * address and a password of their own. They must gain nothing, now or
 * after the address's owner turns up.
 *
 *     node --test --test-timeout=20000 worker/test/password.test.mjs
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash, pbkdf2Sync } from "node:crypto";
import { d1 } from "./stand-ins.mjs";

const worker = (await import("../src/index.js")).default;
const { sweep } = await import("../src/accounts.js");
const { CODE_FOR } = await import("../src/session.js");
const {
  ITERATIONS, MAX_LENGTH, MIN_LENGTH, hashPassword, isPasswordHash, iterations, needsRehash, passwordProblem,
  verifyPassword,
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

/* ---------- stand-ins ---------- */

/* Have I Been Pwned's range API and Resend's /emails. `breached` holds the
   passwords the range API knows; every answer is padded with made-up
   suffixes at a count of 0, and `padded` adds a real one at 0. */
function services({ breached = [], padded = [] } = {}) {
  const s = { emails: [], ranges: [], hibp: "up" };
  const known = breached.map(sha1);
  const zero = padded.map(sha1);
  globalThis.fetch = async (url, init = {}) => {
    const u = new URL(String(url));
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
  LIST: d1(), RESEND_API_KEY: RESEND_KEY, ACCOUNT_SECRET: SECRET, ACCOUNTS_ON: "1", ...LOW, ...extra,
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
  return b.post("/signup", { form: tokenFor(form.text, "/signup"), email, password, next: "/" });
}

async function askCode(b, email) {
  const form = await b.get("/signin");
  return b.post("/signin", { form: tokenFor(form.text, "/signin"), email, next: "/" });
}

async function typeCode(b, code) {
  const page = await b.get("/signin/code");
  assert.equal(page.status, 200, page.text);
  return b.post("/signin/code", { form: tokenFor(page.text, "/signin/code"), code });
}

async function again(b) {
  const page = await b.get("/signin/code");
  return b.post("/signin/again", { form: tokenFor(page.text, "/signin/again") });
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
  assert.doesNotMatch(form.text, /<script|\son[a-z]+=/i);
  assert.match(form.headers.get("content-security-policy"), /^default-src 'none'; /);

  const asked = await b.post("/signup", { form: tokenFor(form.text, "/signup"), email: "Ana@Example.com",
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

test("an account that has a password gets a new one only through its code, and the change is logged", async () => {
  const s = services();
  const e = env();
  const first = new Browser(e);
  await signUp(first, "ana@example.com", ANA_PASSWORD);
  await typeCode(first, codeIn(s.emails.at(-1)));
  later(MINUTE + 1);
  const second = new Browser(e, { ip: "203.0.113.20" });
  await signUp(second, "ana@example.com", "a brand new passphrase");
  assert.equal(await verifyPassword(passwordOf(e, "ana@example.com"), ANA_PASSWORD), true, "unchanged until the code");
  await typeCode(second, codeIn(s.emails.at(-1)));
  const kept = passwordOf(e, "ana@example.com");
  assert.equal(await verifyPassword(kept, "a brand new passphrase"), true);
  assert.equal(await verifyPassword(kept, ANA_PASSWORD), false);
  assert.deepEqual(eventsOf(e, "ana@example.com"), ["signup", "password_added", "signin", "password_changed"]);
  assert.equal(count(e, "users"), 1);
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
    assert.equal((await signUp(b, `person${i}@example.com`, ANA_PASSWORD)).status, 303, `sign-up ${i}`);
  }
  const over = await signUp(b, "one-more@example.com", ANA_PASSWORD);
  assert.equal(over.status, 429);
  assert.equal(s.ranges.length, 20, "refused before the breach check");
  assert.equal(s.emails.length, 20);
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
