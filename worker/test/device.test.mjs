/* Linking a terminal (device.js): RFC 8628's device grant on
 * feed.ranwhat.com, asked for and polled as `ranwhat login` will, and its
 * approval on account.ranwhat.com by a browser stand-in that keeps
 * cookies as a browser does. The Worker's own fetch and scheduled
 * handlers run over a real SQLite database (node:sqlite, which is what D1
 * runs), with Resend and Turnstile answered by stand-ins, as in
 * accounts.test.mjs. And end to end: the real `ranwhat login`, `whoami`,
 * `logout` and `update` (ranwhat/account.py) against the Worker over
 * node:http, as feed.test.mjs runs `update`.
 *
 *     node --test --test-timeout=60000 worker/test/device.test.mjs
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { createServer } from "node:http";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { d1 } from "./stand-ins.mjs";

const worker = (await import("../src/index.js")).default;
const device = await import("../src/device.js");
const { formToken } = await import("../src/session.js");

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const BODY = JSON.stringify(JSON.parse(readFileSync(join(ROOT, "worker", "feed", "catalogue.json"), "utf8")));
const ORIGIN = "https://account.ranwhat.com";
const FEED = "https://feed.ranwhat.com";
const SECRET = "an-account-test-secret-that-is-long-enough-0123456789";
const SESSION = "__Host-rw_session";
const FROM_PAGE = { "sec-fetch-site": "same-origin", origin: ORIGIN };
const GRANT = "urn:ietf:params:oauth:grant-type:device_code";
const UPGRADE = { error: "plus_required", upgrade: "https://account.ranwhat.com/" };
const MINUTE = 60, HOUR = 3600, DAY = 24 * HOUR;
const ctx = { waitUntil() {} };

/* auth.js's TOKEN: a terminal's token must still be a feed token. */
const FEED_TOKEN = /^Bearer (rw_[A-Za-z0-9_-]{20,200})$/;
const ALPHABET = "BCDFGHJKLMNPQRSTVWXZ";
const USER_CODE = /^[BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4}$/;

/* The clock, which a test moves forward when it needs time to pass. */
const realNow = Date.now;
let skew = 0;
Date.now = () => realNow() + skew * 1000;
const later = (seconds) => { skew += seconds; };
const unix = () => Math.floor(Date.now() / 1000);

const sha = (text) => createHash("sha256").update(text).digest("hex");
/* Made here rather than written out: nothing token-shaped sits in the source. */
const madeToken = (prefix = "rw_") => prefix + randomBytes(32).toString("base64url");

/* ---------- stand-ins ---------- */

/* Resend's /emails and Turnstile's siteverify, as accounts.test.mjs has
   them: a token from solved(action) passes for that form. */
const solved = (action) => `solved:${action}`;
function services() {
  const s = { emails: [] };
  globalThis.fetch = async (url, init = {}) => {
    const u = new URL(String(url));
    if (u.hostname === "challenges.cloudflare.com") {
      const m = /^solved:([a-z]+)$/.exec(JSON.parse(init.body).response);
      return new Response(JSON.stringify(m ? { success: true, hostname: "account.ranwhat.com", action: m[1] }
        : { success: false }), { status: 200 });
    }
    assert.equal(`${init.method} ${u.hostname}${u.pathname}`, "POST api.resend.com/emails");
    s.emails.push(JSON.parse(init.body));
    return new Response(JSON.stringify({ id: `e${s.emails.length}` }), { status: 200 });
  };
  return s;
}

const env = (extra = {}) => ({
  LIST: d1(), RESEND_API_KEY: "re_test_key", ACCOUNT_SECRET: SECRET, TURNSTILE_SECRET: "turnstile-" + "test",
  ACCOUNTS_ON: "1", ...extra,
});

class Browser {
  constructor(e, { ip = "198.51.100.7" } = {}) {
    this.e = e;
    this.ip = ip;
    this.jar = new Map();
  }

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
    return { status: res.status, location: res.headers.get("location"), headers: res.headers, text: await res.text() };
  }

  get(path) {
    return this.send(path);
  }

  post(path, body, headers = FROM_PAGE) {
    return this.send(path, { method: "POST", body,
      headers: { "content-type": "application/x-www-form-urlencoded", ...headers } });
  }

  get session() {
    return sha(this.jar.get(SESSION));
  }
}

function tokenFor(html, action) {
  const m = html.match(new RegExp(`<form method="post" action="${action}"[^>]*>` +
    `<input type="hidden" name="form" value="([^"]+)">`));
  assert.ok(m, `no form for ${action}`);
  return m[1];
}

const codeIn = (mail) => mail.text.match(/^ {4}([0-9A-Z]{4}-[0-9A-Z]{4})$/m)[1];

async function typeCode(b, code) {
  const page = await b.get("/signin/code");
  assert.equal(page.status, 200, page.text);
  return b.post("/signin/code", { form: tokenFor(page.text, "/signin/code"), code });
}

/* Signs in with an emailed code, which makes the session fresh. */
async function signIn(b, s, email = "ana@example.com", next = "/") {
  const form = await b.get(`/signin?next=${encodeURIComponent(next)}`);
  const asked = await b.post("/signin", { form: tokenFor(form.text, "/signin"), email,
    next: form.text.match(/name="next" value="([^"]*)"/)[1], "cf-turnstile-response": solved("signin") });
  assert.equal(asked.status, 303, asked.text);
  const done = await typeCode(b, codeIn(s.emails.at(-1)));
  assert.equal(done.status, 303, done.text);
  assert.ok(b.jar.has(SESSION));
  return done;
}

const rows = (e, sql, ...p) => e.LIST.sql.prepare(sql).all(...p).map((r) => ({ ...r }));
const one = (e, sql, ...p) => rows(e, sql, ...p)[0];
const count = (e, table) => e.LIST.sql.prepare(`SELECT count(*) AS n FROM ${table}`).get().n;
const tables = (e) => rows(e, "SELECT name FROM sqlite_master WHERE type = 'table'").map((r) => r.name);
const dump = (e) => JSON.stringify(tables(e).map((t) => rows(e, `SELECT * FROM ${t}`)));
const orgOf = (e, email) => one(e,
  "SELECT m.org_id AS id FROM memberships m JOIN users u ON u.id = m.user_id WHERE u.email = ?", email).id;

/* ---------- the terminal's side ---------- */

async function call(e, path, { method = "POST", form, token, headers = {}, ip = "203.0.113.5", country, host = FEED } = {}) {
  const h = new Headers({ "cf-connecting-ip": ip, ...headers });
  if (token) h.set("authorization", `Bearer ${token}`);
  let body;
  if (form) {
    h.set("content-type", "application/x-www-form-urlencoded");
    body = new URLSearchParams(form).toString();
  }
  const request = new Request(`${host}${path}`, { method, headers: h, body });
  if (country) Object.defineProperty(request, "cf", { value: { country } });
  const res = await worker.fetch(request, e, ctx);
  const text = await res.text();
  let json = null;
  try { json = JSON.parse(text); } catch { /* not JSON */ }
  return { status: res.status, headers: res.headers, text, json };
}

const askDevice = (e, extra = {}, opts = {}) =>
  call(e, "/v1/device/code", { form: { client_id: "ranwhat-cli", ...extra }, ...opts });
const poll = (e, deviceCode, opts = {}) =>
  call(e, "/v1/device/token", { form: { client_id: "ranwhat-cli", grant_type: GRANT, device_code: deviceCode }, ...opts });
const whoami = (e, token, opts = {}) => call(e, "/v1/whoami", { method: "GET", token, ...opts });
const logout = (e, token, opts = {}) => call(e, "/v1/logout", { token, ...opts });
const feed = (e, token) => call(e, "/v1/catalogue", { method: "GET", token });

async function newCode(e, opts) {
  const r = await askDevice(e, {}, opts);
  assert.equal(r.status, 200, r.text);
  return r.json;
}

/* ---------- the person's side ---------- */

async function typeDevice(b, userCode) {
  const page = await b.get("/device");
  assert.equal(page.status, 200, page.text);
  return b.post("/device", { form: tokenFor(page.text, "/device"), user_code: userCode });
}

/* Types the code, names the terminal and approves it from the page that
   shows. */
async function approve(b, userCode, label = "Work laptop") {
  const shown = await typeDevice(b, userCode);
  assert.equal(shown.status, 200, shown.text);
  const org = shown.text.match(/name="org" value="([^"]+)"/)[1];
  const code = shown.text.match(/name="user_code" value="([^"]+)"/)[1];
  const done = await b.post("/device/approve", { form: tokenFor(shown.text, "/device/approve"), user_code: code, org, label });
  return { shown, done };
}

async function deny(b, userCode) {
  const shown = await typeDevice(b, userCode);
  assert.equal(shown.status, 200, shown.text);
  const code = shown.text.match(/name="user_code" value="([^"]+)"/)[1];
  return b.post("/device/deny", { form: tokenFor(shown.text, "/device/deny"), user_code: code });
}

const stateOf = (e, deviceCode) => one(e, "SELECT * FROM device_codes WHERE device_hash = ?", sha(deviceCode));

/* A code sharing the first half of `userCode`, with its last letter moved
   on by k. */
function sibling(userCode, k) {
  const plain = userCode.replace("-", "");
  return plain.slice(0, 7) + ALPHABET[(ALPHABET.indexOf(plain[7]) + k) % 20];
}

/* One that does not share it. */
function stranger(userCode, k = 1) {
  const plain = userCode.replace("-", "");
  return ALPHABET[(ALPHABET.indexOf(plain[0]) + 1) % 20] + plain.slice(1, 7) + ALPHABET[(ALPHABET.indexOf(plain[7]) + k) % 20];
}

/* A signed-in person, and a terminal whose code they approved and that
   has its token. */
async function linked(e, s, { email = "ana@example.com", ip = "198.51.100.7" } = {}) {
  const b = new Browser(e, { ip });
  await signIn(b, s, email);
  const cli = await newCode(e);
  const { done } = await approve(b, cli.user_code);
  assert.equal(done.status, 200, done.text);
  later(device.INTERVAL);
  const got = await poll(e, cli.device_code);
  assert.equal(got.status, 200, got.text);
  return { b, cli, token: got.json.access_token, got };
}

function grant(e, orgId, which = "plus") {
  e.LIST.sql.prepare("INSERT INTO grants (org_id, plan, starts_at, until, note, created_at) VALUES (?, ?, ?, NULL, 'test', ?)")
    .run(orgId, which, unix() - 60, unix());
}

/* ---------- the switch and the hosts ---------- */

test("with ACCOUNTS_ON unset, every device path answers 404 as an unknown path does, and nothing is made", async () => {
  for (const extra of [{ ACCOUNTS_ON: undefined }, { ACCOUNTS_ON: "" }, { ACCOUNTS_ON: "0" }]) {
    const e = env(extra);
    const unknown = await worker.fetch(new Request(`${FEED}/v1/no-such-path`), e, ctx);
    const expected = [unknown.status, await unknown.text(), [...unknown.headers]];
    assert.equal(expected[0], 404);
    const tok = madeToken("rw_m_");
    for (const [url, method] of [[`${FEED}/v1/device/code`, "POST"], [`${FEED}/v1/device/token`, "POST"],
                                 [`${FEED}/v1/whoami`, "GET"], [`${FEED}/v1/logout`, "POST"],
                                 ["https://ranwhat.com/device", "GET"], ["https://ranwhat.com/device/", "GET"],
                                 [`${ORIGIN}/device`, "GET"], [`${ORIGIN}/device`, "POST"], [`${ORIGIN}/device/approve`, "POST"]]) {
      const r = await worker.fetch(new Request(url, { method, headers: { authorization: `Bearer ${tok}` },
        body: method === "POST" ? "client_id=ranwhat-cli" : undefined }), e, ctx);
      assert.deepEqual([r.status, await r.text(), [...r.headers]], expected, `${method} ${url}`);
    }
    assert.deepEqual(tables(e), [], "nothing is made in the database while it is off");
  }
});

test("each path answers on its own host only, and ranwhat.com/device sends the browser on to the account host", async () => {
  services();
  const e = env();
  for (const host of ["https://ranwhat.com", ORIGIN]) {
    for (const [path, method] of [["/v1/device/code", "POST"], ["/v1/device/token", "POST"], ["/v1/whoami", "GET"],
                                  ["/v1/logout", "POST"]]) {
      const r = await call(e, path, { method, host, form: method === "POST" ? { client_id: "ranwhat-cli" } : undefined });
      assert.equal(r.status, 404, `${host}${path}`);
    }
  }
  for (const path of ["/device", "/device/"]) {
    const r = await call(e, `${path}?user_code=BCDFGHJK&next=https://evil.example/`, { method: "GET", host: "https://ranwhat.com" });
    assert.equal(r.status, 302);
    assert.equal(r.headers.get("location"), "https://account.ranwhat.com/device", "the query is dropped");
    assert.equal(r.headers.get("set-cookie"), null);
  }
  assert.equal((await call(e, "/device", { method: "HEAD", host: "https://ranwhat.com" })).status, 302);
  const post = await call(e, "/device", { host: "https://ranwhat.com", form: { user_code: "BCDFGHJK" } });
  assert.equal(post.status, 405);
  assert.equal(post.headers.get("allow"), "GET, HEAD");
  for (const path of ["/devices", "/device/approve"]) {
    assert.equal((await call(e, path, { method: "GET", host: "https://ranwhat.com" })).status, 404, path);
  }
  assert.equal((await call(e, "/device", { method: "GET" })).status, 404, "not on the feed host");
  const wrong = [await call(e, "/v1/device/code", { method: "GET" }), await call(e, "/v1/device/token", { method: "GET" }),
                 await call(e, "/v1/whoami", { form: {} }), await call(e, "/v1/logout", { method: "GET" })];
  assert.deepEqual(wrong.map((r) => r.status), [405, 405, 405, 405]);

  /* The account page, signed out, signs in first and comes back. */
  const b = new Browser(e);
  const page = await b.get("/device");
  assert.equal(page.status, 303);
  assert.equal(page.location, "/signin?next=/device");
  assert.match((await b.get("/signin?next=/device")).text, /name="next" value="\/device"/);

  /* Switched on without the account secret: nothing is handed out. */
  for (const extra of [{ ACCOUNT_SECRET: undefined }, { ACCOUNT_SECRET: "too-short" }]) {
    const off = env(extra);
    const r = await askDevice(off);
    assert.equal(r.status, 503);
    assert.equal(r.json.error, "temporarily_unavailable");
    assert.equal((await poll(off, madeToken("").slice(0, 43))).status, 503);
  }
});

/* ---------- the device code ---------- */

test("a device code: RFC 8628's answer, a code to type and no link, and nothing kept as itself", async () => {
  const e = env();
  const r = await askDevice(e, { label: "my-laptop", hostname: "secret-host.local", os: "Darwin" },
    { country: "HR" });
  assert.equal(r.status, 200, r.text);
  assert.deepEqual(Object.keys(r.json).sort(), ["device_code", "expires_in", "interval", "user_code", "verification_uri"]);
  assert.equal(r.json.verification_uri_complete, undefined, "no link with the code in it");
  assert.equal(r.json.verification_uri, "https://ranwhat.com/device");
  assert.equal(r.json.expires_in, 600);
  assert.equal(r.json.interval, 5);
  assert.match(r.json.user_code, USER_CODE);
  assert.match(r.json.device_code, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(r.headers.get("cache-control"), "no-store");
  assert.match(r.headers.get("content-type"), /^application\/json/);
  assert.equal(r.headers.get("set-cookie"), null);

  const row = stateOf(e, r.json.device_code);
  assert.ok(row, "kept as the SHA-256 of the device code");
  assert.deepEqual([row.state, row.country, row.expires_at - row.created_at, row.interval, row.user_id, row.org_id, row.label],
                   ["pending", "HR", 600, 5, null, null, null]);
  const all = dump(e);
  for (const secret of [r.json.device_code, r.json.user_code, r.json.user_code.replace("-", ""), "my-laptop",
                        "secret-host", "Darwin"]) {
    assert.ok(!all.includes(secret), `${secret} is not in the database`);
  }

  for (const form of [{}, { client_id: "someone-else" }, { client_id: "" }]) {
    const bad = await call(e, "/v1/device/code", { form });
    assert.equal(bad.status, 401);
    assert.equal(bad.json.error, "invalid_client");
  }
  const json = await call(e, "/v1/device/code", { headers: { "content-type": "application/json" } });
  assert.equal(json.status, 401);
  assert.equal(count(e, "device_codes"), 1);

  /* Every letter of the alphabet turns up, and nothing else. */
  const seen = new Set();
  for (let i = 0; i < 400; i++) for (const c of device.newUserCode()) seen.add(c);
  assert.equal([...seen].sort().join(""), ALPHABET);
  /* No two codes share a first half. */
  for (let i = 0; i < 15; i++) await newCode(e, { ip: `203.0.113.${100 + i}` });
  const halves = rows(e, "SELECT substr(user_code_mac, 1, 44) AS h FROM device_codes").map((x) => x.h);
  assert.equal(new Set(halves).size, halves.length);
  assert.equal(device.typedUserCode(" bcdf ghjk "), "BCDFGHJK");
  for (const typed of ["BCDF-GHJ", "BCDF-GHJKL", "ABCD-EFGH", "BCDF-GHJ1", "", null]) {
    assert.equal(device.typedUserCode(typed), null, String(typed));
  }
});

test("device codes: five in ten minutes and twenty an hour for a network, an IPv6 /48 being one", async () => {
  const e = env();
  const ask = (ip) => askDevice(e, {}, { ip });
  for (let i = 0; i < device.WAITING_PER_NETWORK; i++) assert.equal((await ask("203.0.113.9")).status, 200);
  const waiting = await ask("203.0.113.9");
  assert.equal(waiting.status, 429);
  assert.equal(waiting.json.error, "rate_limited");
  assert.equal(waiting.headers.get("retry-after"), String(device.DEVICE_FOR));
  assert.equal((await ask("203.0.113.10")).status, 200, "another network still gets one");

  /* Five every ten minutes, up to twenty in the hour. */
  for (let round = 0; round < device.CODES_PER_NETWORK / device.WAITING_PER_NETWORK; round++) {
    for (let i = 0; i < device.WAITING_PER_NETWORK; i++) assert.equal((await ask("203.0.113.20")).status, 200);
    later(device.DEVICE_FOR);
  }
  const hourly = await ask("203.0.113.20");
  assert.equal(hourly.status, 429);
  assert.equal(hourly.headers.get("retry-after"), String(HOUR));
  later(HOUR);
  assert.equal((await ask("203.0.113.20")).status, 200);

  /* IPv6: every /64 of one /48 is the same network here. */
  for (let i = 0; i < device.WAITING_PER_NETWORK; i++) {
    assert.equal((await ask(`2001:db8:1:${(i * 4099).toString(16)}::${i + 1}`)).status, 200);
  }
  assert.equal((await ask("2001:db8:1:ffff::9")).status, 429, "another /64 of the same /48");
  assert.equal((await ask("2001:db8:2::1")).status, 200, "another /48 is another network");
});

test("50 /64s of one /48 cannot fill the cap on waiting codes, and past the cap only networks already waiting are refused", async () => {
  const e = env();
  /* The review's attack: every /64 of 2001:db8:abcd::/48 asks for all the
     codes it is allowed. */
  const statuses = {};
  for (let n = 0; n < device.MAX_PENDING / device.CODES_PER_NETWORK; n++) {
    for (let i = 0; i < device.CODES_PER_NETWORK; i++) {
      const r = await askDevice(e, {}, { ip: `2001:db8:abcd:${n.toString(16)}::1` });
      statuses[r.status] = (statuses[r.status] || 0) + 1;
    }
  }
  assert.deepEqual(statuses, { 200: device.WAITING_PER_NETWORK, 429: device.MAX_PENDING - device.WAITING_PER_NETWORK });
  assert.equal(count(e, "device_codes"), device.WAITING_PER_NETWORK);
  assert.equal((await askDevice(e, {}, { ip: "198.51.100.200" })).status, 200, "ranwhat login elsewhere still works");

  /* Filled anyway, from a thousand networks: a network with nothing
     waiting still gets a code; one that asked in the last ten minutes,
     and so filled it, does not. */
  const insert = e.LIST.sql.prepare(`INSERT INTO device_codes (device_hash, user_code_mac, created_at, expires_at)
                                     VALUES (?, ?, ?, ?)`);
  const fill = (to, tag) => {
    const t = unix();
    const n = e.LIST.sql.prepare("SELECT count(*) AS n FROM device_codes WHERE expires_at > ?").get(t).n;
    for (let i = n; i < to; i++) insert.run(`${tag}${i}`, `${tag}${i}`, t, t + 600);
  };
  fill(device.MAX_PENDING, "a");
  const fresh = await askDevice(e, {}, { ip: "198.51.100.201" });
  assert.equal(fresh.status, 200, fresh.text);
  for (const ip of ["198.51.100.201", "198.51.100.200"]) {
    const r = await askDevice(e, {}, { ip });
    assert.equal(r.status, 503, ip);
    assert.equal(r.json.error, "temporarily_unavailable");
    assert.match(r.json.error_description, /one from your network already is/);
  }
  assert.equal((await askDevice(e, {}, { ip: "2001:db8:abcd:77::1" })).status, 429, "and the /48 is still over its own");
  later(device.DEVICE_FOR + 1);
  assert.equal((await askDevice(e, {}, { ip: "198.51.100.201" })).status, 200, "ten minutes on, its codes have expired");

  /* The ceiling: past it, nobody gets one. */
  fill(device.PENDING_CEILING, "b");
  const full = await askDevice(e, {}, { ip: "198.51.100.202" });
  assert.equal(full.status, 503);
  assert.equal(full.json.error, "temporarily_unavailable");
  assert.doesNotMatch(full.json.error_description, /your network/);
  e.LIST.sql.prepare("UPDATE device_codes SET expires_at = ? WHERE device_hash = 'b9999'").run(unix() - 1);
  assert.equal((await askDevice(e, {}, { ip: "198.51.100.203" })).status, 200, "an expired code no longer counts");
});

test("no web page can ask for or poll a device code: a request with Origin, or from a browser's fetch, is refused", async () => {
  const e = env();
  const cli = await newCode(e);
  const before = dump(e);
  const fromPages = [
    { origin: "https://evil.example", "sec-fetch-site": "cross-site", "sec-fetch-mode": "no-cors" },
    { origin: "https://evil.example" },
    { origin: "null" },
    { origin: "https://ranwhat.com" },
    { origin: ORIGIN, "sec-fetch-site": "same-site" },
    { "sec-fetch-site": "cross-site" },
    { "sec-fetch-site": "same-origin" },
  ];
  for (const headers of fromPages) {
    for (let n = 0; n < 3; n++) {
      const code = await askDevice(e, {}, { headers, ip: `2001:db8:abcd:${n}::1` });
      assert.deepEqual([code.status, code.json.error], [403, "invalid_request"], JSON.stringify(headers));
      const polled = await poll(e, cli.device_code, { headers });
      assert.deepEqual([polled.status, polled.json.error], [403, "invalid_request"], JSON.stringify(headers));
    }
  }
  assert.equal(dump(e), before, "nothing was counted, made or polled");
  /* A browser's own navigation, typed in its address bar, is no page's doing. */
  assert.equal((await askDevice(e, {}, { headers: { "sec-fetch-site": "none" } })).status, 200);
});

test("DEVICE_RL turns a burst from one network away before the database is touched", async () => {
  const keys = [];
  let allowed = 2;
  const e = env({ DEVICE_RL: { async limit({ key }) { keys.push(key); return { success: allowed-- > 0 }; } } });
  assert.equal((await askDevice(e, {}, { ip: "2001:db8:abcd:1::1" })).status, 200);
  assert.equal((await askDevice(e, {}, { ip: "2001:db8:abcd:2::1" })).status, 200);
  const before = dump(e);
  const burst = await askDevice(e, {}, { ip: "2001:db8:abcd:3::1" });
  assert.deepEqual([burst.status, burst.json.error, burst.headers.get("retry-after")], [429, "rate_limited", "60"]);
  assert.equal(dump(e), before, "nothing was written");
  assert.equal(new Set(keys).size, 1, "one /48, one key");
  assert.ok(!keys[0].includes("2001") && !keys[0].includes("db8"), "keyed by an HMAC, not by the address");
  /* A binding that fails lets the request through to the counts in D1. */
  const broken = env({ DEVICE_RL: { async limit() { throw new Error("down"); } } });
  assert.equal((await askDevice(broken)).status, 200);
});

/* ---------- the whole way through ---------- */

test("typed at ranwhat.com/device, approved with a fresh code, minted once, and the feed answers by plan", async () => {
  const s = services();
  const e = env();
  const cli = await newCode(e, { country: "HR" });

  let r = await poll(e, cli.device_code);
  assert.deepEqual([r.status, r.json.error], [400, "authorization_pending"]);
  assert.match(r.json.error_description, /ranwhat\.com\/device/);
  r = await poll(e, cli.device_code);
  assert.deepEqual([r.status, r.json.error, r.json.interval], [400, "slow_down", 10], "polled sooner than the interval");
  later(5);
  assert.equal((await poll(e, cli.device_code)).json.error, "slow_down", "the interval grew to ten seconds");
  later(15);
  assert.equal((await poll(e, cli.device_code)).json.error, "authorization_pending");

  /* The person follows the address the terminal printed. */
  const there = await call(e, "/device", { method: "GET", host: "https://ranwhat.com" });
  assert.equal(there.headers.get("location"), `${ORIGIN}/device`);
  const b = new Browser(e);
  assert.equal((await b.get("/device")).location, "/signin?next=/device");
  const done = await signIn(b, s, "ana@example.com", "/device");
  assert.equal(done.location, "/device", "signing in comes back to the page");

  const box = await b.get("/device");
  assert.equal(box.status, 200);
  for (const shown of ["Link a terminal", "Personal", "Approve only a terminal you started yourself", "ranwhat login"]) {
    assert.ok(box.text.includes(shown), shown);
  }
  assert.match(box.text, /name="user_code"/);
  assert.doesNotMatch(box.text, /name="user_code"[^>]*value=/, "the box is never filled in");
  assert.doesNotMatch(box.text, /<script/i);

  /* Typed in lower case, with a space for the dash, as people do. */
  const shown = await typeDevice(b, cli.user_code.toLowerCase().replace("-", " "));
  assert.equal(shown.status, 200, shown.text);
  for (const text of ["Approve this terminal?", "Approve only a terminal you started yourself", cli.user_code,
                      "Personal", "Croatia", "less than a minute ago", ">Free<", "asks for Plus"]) {
    assert.ok(shown.text.includes(text), text);
  }
  assert.doesNotMatch(shown.text, /<script/i);
  assert.match(shown.text, /<input id="label" name="label" type="text" maxlength="60" required/, "a name is typed here");
  assert.equal(stateOf(e, cli.device_code).state, "pending", "looking a code up approves nothing");

  const org = orgOf(e, "ana@example.com");
  const user = one(e, "SELECT id FROM users").id;
  const ok = await b.post("/device/approve", { form: tokenFor(shown.text, "/device/approve"),
    user_code: cli.user_code.replace("-", ""), org, label: "  Ana's <laptop>  " });
  assert.equal(ok.status, 200, ok.text);
  assert.match(ok.text, /Approved/);
  assert.match(ok.text, /ana@example\.com/);
  assert.ok(ok.text.includes("Ana's &lt;laptop&gt;") && !ok.text.includes("<laptop>"), "the name, escaped");
  const approved = stateOf(e, cli.device_code);
  assert.deepEqual([approved.state, approved.user_id, approved.org_id, approved.label],
                   ["approved", user, org, "Ana's <laptop>"]);
  assert.equal(count(e, "machines"), 0, "nothing is made until the terminal asks");

  later(15);
  const got = await poll(e, cli.device_code);
  assert.equal(got.status, 200, got.text);
  assert.deepEqual(Object.keys(got.json).sort(), ["access_token", "email", "org", "plan", "token_type"]);
  const token = got.json.access_token;
  assert.ok(token.startsWith("rw_m_"));
  assert.match(`Bearer ${token}`, FEED_TOKEN);
  assert.equal(token.length, "rw_m_".length + 43);
  assert.deepEqual([got.json.token_type, got.json.email, got.json.org, got.json.plan], ["Bearer", "ana@example.com", "Personal", "free"]);
  assert.equal(got.headers.get("cache-control"), "no-store");

  later(10);
  const again = await poll(e, cli.device_code);
  assert.deepEqual([again.status, again.json.error], [400, "invalid_grant"], "the token is handed out once");
  assert.ok(!again.text.includes(token));

  /* Kept as hashes only, a machine of the organisation, named as it was
     on the web. */
  const machine = one(e, "SELECT * FROM machines");
  assert.deepEqual([machine.hash, machine.org_id, machine.user_id, machine.kind, machine.label, machine.last_used_day],
                   [sha(token), org, user, "device", "Ana's <laptop>", null]);
  const tokenRow = one(e, "SELECT * FROM tokens WHERE hash = ?", sha(token));
  assert.deepEqual([tokenRow.note, tokenRow.revoked_at, tokenRow.expires_at], [`device ${machine.id}`, null, null]);
  assert.equal(stateOf(e, cli.device_code).state, "issued");
  assert.ok(!dump(e).includes(token) && !dump(e).includes(token.slice(5)), "no token in the database");

  /* whoami: who, where, on what, and nothing secret. */
  const me = await whoami(e, token);
  assert.equal(me.status, 200);
  assert.deepEqual(me.json, { kind: "device", email: "ana@example.com", org: "Personal", role: "owner", plan: "free",
                              machine: { label: "Ana's <laptop>", created_at: machine.created_at } });
  for (const secret of [token, sha(token), machine.id, org, user]) assert.ok(!me.text.includes(secret));

  /* Free: linked, and the feed says where Plus is. */
  const refused = await feed(e, token);
  assert.equal(refused.status, 403);
  assert.deepEqual(refused.json, UPGRADE);
  grant(e, org, "plus");
  const served = await feed(e, token);
  assert.equal(served.status, 200);
  assert.equal(served.text, BODY);
  assert.equal((await whoami(e, token)).json.plan, "plus");

  /* logout revokes this terminal's token, and only it. */
  const out = await logout(e, token);
  assert.deepEqual([out.status, out.json], [200, { revoked: true }]);
  assert.ok(one(e, "SELECT revoked_at FROM tokens WHERE hash = ?", sha(token)).revoked_at);
  assert.deepEqual((await feed(e, token)).json, { error: "That token was not accepted." });
  assert.equal((await whoami(e, token)).status, 403);
  assert.equal((await logout(e, token)).status, 403);

  const events = rows(e, "SELECT org_id, user_id, event FROM auth_events WHERE event NOT IN ('signup', 'signin')");
  assert.deepEqual(events.map((x) => x.event), ["device_approved", "machine_linked", "machine_logout"]);
  for (const x of events) assert.deepEqual([x.org_id, x.user_id], [org, user]);
  const home = await b.get("/");
  for (const text of ["Terminal approved", "Terminal linked", "Terminal unlinked"]) assert.ok(home.text.includes(text), text);
});

test("every answer a terminal can get: invalid_client, unsupported_grant_type, invalid_grant, expired_token, access_denied", async () => {
  const s = services();
  const e = env();
  const b = new Browser(e);
  await signIn(b, s);

  const cli = await newCode(e);
  const ask = (form) => call(e, "/v1/device/token", { form });
  assert.deepEqual([(await ask({ grant_type: GRANT, device_code: cli.device_code })).status,
                    (await ask({ client_id: "other", grant_type: GRANT, device_code: cli.device_code })).json.error],
                   [401, "invalid_client"]);
  for (const grantType of ["authorization_code", "", "device_code"]) {
    const r = await ask({ client_id: "ranwhat-cli", grant_type: grantType, device_code: cli.device_code });
    assert.deepEqual([r.status, r.json.error], [400, "unsupported_grant_type"]);
  }
  for (const code of [madeToken("").slice(0, 43), "short", "", cli.device_code + "x", cli.user_code]) {
    const r = await poll(e, code);
    assert.deepEqual([r.status, r.json.error], [400, "invalid_grant"], code);
  }
  assert.equal(stateOf(e, cli.device_code).polled_at, null, "none of those polled the real code");

  /* Denied: the terminal is told so, and the code is done. */
  const denied = await deny(b, cli.user_code);
  assert.equal(denied.status, 200, denied.text);
  assert.match(denied.text, /Denied/);
  assert.equal(stateOf(e, cli.device_code).state, "denied");
  for (let i = 0; i < 2; i++) {
    const r = await poll(e, cli.device_code);
    assert.deepEqual([r.status, r.json.error], [400, "access_denied"]);
    later(10);
  }
  const typedAgain = await typeDevice(b, cli.user_code);
  assert.equal(typedAgain.status, 400);
  assert.match(typedAgain.text, /was denied/);
  assert.equal(rows(e, "SELECT event FROM auth_events").at(-1).event, "device_denied");

  /* Expired: ten minutes and no more, for the terminal and the page. */
  const late = await newCode(e);
  const shown = await typeDevice(b, late.user_code);
  assert.equal(shown.status, 200);
  later(9 * MINUTE + 50);
  assert.equal((await poll(e, late.device_code)).json.error, "authorization_pending");
  later(11);
  const expired = await poll(e, late.device_code);
  assert.deepEqual([expired.status, expired.json.error], [400, "expired_token"]);
  const org = orgOf(e, "ana@example.com");
  const tooLate = await b.post("/device/approve", { form: tokenFor(shown.text, "/device/approve"),
    user_code: late.user_code, org });
  assert.equal(tooLate.status, 400);
  assert.match(tooLate.text, /expired/);
  assert.equal(stateOf(e, late.device_code).state, "pending");
  assert.match((await typeDevice(b, late.user_code)).text, /has expired/);
  assert.equal((await poll(e, late.device_code)).json.error, "expired_token");
  assert.equal(count(e, "machines"), 0);
  assert.equal(count(e, "tokens"), 0);
});

test("two polls at once, or any number, mint exactly one token", async () => {
  const s = services();
  const e = env();
  const b = new Browser(e);
  await signIn(b, s);
  const cli = await newCode(e);
  assert.equal((await approve(b, cli.user_code)).done.status, 200);
  later(device.INTERVAL);
  const answers = await Promise.all(Array.from({ length: 6 }, () => poll(e, cli.device_code)));
  const tokens = answers.filter((r) => r.status === 200).map((r) => r.json.access_token);
  assert.equal(tokens.length, 1, answers.map((r) => r.text).join("\n"));
  for (const r of answers.filter((x) => x.status !== 200)) assert.ok(["slow_down", "invalid_grant"].includes(r.json.error));
  assert.deepEqual([count(e, "tokens"), count(e, "machines")], [1, 1]);

  /* And mint() itself, called at once for one approved code. */
  const second = await newCode(e);
  assert.equal((await approve(b, second.user_code)).done.status, 200);
  const minted = (await Promise.all(Array.from({ length: 5 }, () => device.mint(e, sha(second.device_code)))))
    .filter(Boolean);
  assert.equal(minted.length, 1);
  assert.deepEqual([count(e, "tokens"), count(e, "machines")], [2, 2]);
  later(device.INTERVAL);
  assert.equal((await poll(e, second.device_code)).json.error, "invalid_grant", "the terminal is not handed another");
});

/* ---------- approving: what a phished code meets ---------- */

test("approving needs a session, a fresh code, this page's form, and the organisation it showed", async () => {
  const s = services();
  const e = env();
  const b = new Browser(e);
  await signIn(b, s);
  const org = orgOf(e, "ana@example.com");
  later(16 * MINUTE);   // the code typed to sign in is no longer fresh
  const cli = await newCode(e);
  const code = cli.user_code.replace("-", "");

  /* Signed out: sign in first; nothing is approved. */
  const nobody = new Browser(e);
  const out = await nobody.post("/device/approve", { form: "x", user_code: code, org });
  assert.deepEqual([out.status, out.location], [303, "/signin?next=/device"]);

  /* Signed in, but not lately: the step-up comes first, with no code box. */
  const stale = await b.get("/device");
  assert.equal(stale.status, 200);
  assert.match(stale.text, /needs an emailed code typed in the last 15 minutes/);
  assert.doesNotMatch(stale.text, /name="user_code"/);
  tokenFor(stale.text, "/stepup");
  const lookup = await b.post("/device", { form: await formToken(e, b.session, "device"), user_code: code });
  assert.equal(lookup.status, 403);
  assert.doesNotMatch(lookup.text, /Approve this terminal/);
  const forced = await b.post("/device/approve", {
    form: await formToken(e, b.session, `device-approve:${code}:${org}`), user_code: code, org });
  assert.equal(forced.status, 403);
  assert.match(forced.text, /nothing was approved/);
  assert.equal(stateOf(e, cli.device_code).state, "pending");

  /* The step-up mails a code and comes back here. */
  const asked = await b.post("/stepup", { form: tokenFor(stale.text, "/stepup"), next: "/device" });
  assert.equal(asked.location, "/signin/code");
  const back = await typeCode(b, codeIn(s.emails.at(-1)));
  assert.equal(back.location, "/device");
  const shown = await typeDevice(b, cli.user_code);
  assert.equal(shown.status, 200);
  const approveForm = tokenFor(shown.text, "/device/approve");

  /* The form must be this page's, sent from this page. */
  for (const [form, headers] of [["forged", FROM_PAGE], [approveForm, {}], [approveForm, { "sec-fetch-site": "same-site" }],
                                 [approveForm, { origin: "https://ranwhat.com" }]]) {
    const r = await b.post("/device/approve", { form, user_code: code, org }, headers);
    assert.equal(r.status, 403);
  }
  /* Neither the code nor the organisation can be swapped in it. */
  const other = await newCode(e);
  const swapped = [
    await b.post("/device/approve", { form: approveForm, user_code: other.user_code, org }),
    await b.post("/device/approve", { form: approveForm, user_code: code, org: randomUUID() }),
  ];
  assert.deepEqual(swapped.map((r) => r.status), [403, 403]);
  /* A deny form's token approves nothing. */
  const denyForm = tokenFor(shown.text, "/device/deny");
  assert.equal((await b.post("/device/approve", { form: denyForm, user_code: code, org })).status, 403);
  for (const c of [cli, other]) assert.equal(stateOf(e, c.device_code).state, "pending");

  /* The organisation the page showed is no longer the one this account is
     looking at (its membership there ended): nothing is approved. */
  const user = one(e, "SELECT id FROM users").id;
  const elsewhere = randomUUID();
  e.LIST.sql.prepare("INSERT INTO orgs (id, name, personal, created_at) VALUES (?, 'Elsewhere', 0, ?)").run(elsewhere, unix());
  e.LIST.sql.prepare("INSERT INTO memberships (org_id, user_id, role, created_at) VALUES (?, ?, 'member', ?)")
    .run(elsewhere, user, unix());
  e.LIST.sql.prepare("DELETE FROM memberships WHERE org_id = ? AND user_id = ?").run(org, user);
  const moved = await b.post("/device/approve", { form: approveForm, user_code: code, org });
  assert.equal(moved.status, 403);
  assert.match(moved.text, /nothing was approved/);
  assert.equal(stateOf(e, cli.device_code).state, "pending");

  /* Typed again, it would go to the organisation shown now. */
  const now = await typeDevice(b, cli.user_code);
  assert.match(now.text, /Elsewhere/);
  assert.equal((await approve(b, cli.user_code)).done.status, 200);
  assert.equal(stateOf(e, cli.device_code).org_id, elsewhere);

  /* A code approved once is used: nobody else can approve it again. */
  const mallory = new Browser(e, { ip: "203.0.113.66" });
  await signIn(mallory, s, "mallory@example.com");
  const taken = await typeDevice(mallory, cli.user_code);
  assert.equal(taken.status, 400);
  assert.match(taken.text, /already approved/);
  assert.equal(stateOf(e, cli.device_code).user_id, user);
});

test("a terminal is named on the page that approves it: without a good name nothing is approved, and the machine carries it", async () => {
  const s = services();
  const e = env();
  const b = new Browser(e);
  await signIn(b, s);
  const asked = await askDevice(e, { label: "named-by-the-terminal", hostname: "box.local" });
  assert.equal(asked.status, 200, asked.text);
  const cli = asked.json;
  const shown = await typeDevice(b, cli.user_code);
  assert.equal(shown.status, 200, shown.text);
  assert.ok(!shown.text.includes("named-by-the-terminal"), "nothing the terminal sent is shown");
  const org = shown.text.match(/name="org" value="([^"]+)"/)[1];
  const code = shown.text.match(/name="user_code" value="([^"]+)"/)[1];
  const form = tokenFor(shown.text, "/device/approve");

  for (const bad of [undefined, "", "   ", "x".repeat(61), "evil\u202egnp.exe", "bell\u0007", "zero\u200bwidth"]) {
    const sent = { form, user_code: code, org };
    if (bad !== undefined) sent.label = bad;
    const r = await b.post("/device/approve", sent);
    assert.equal(r.status, 400, JSON.stringify(bad));
    assert.match(r.text, /Give the terminal a name of 1 to 60 printable characters/);
    assert.match(r.text, /Nothing was approved/);
    assert.equal(tokenFor(r.text, "/device/approve"), form, "the same page again, to name it and approve");
    const row = stateOf(e, cli.device_code);
    assert.deepEqual([row.state, row.label, row.user_id], ["pending", null, null]);
  }
  later(device.INTERVAL);
  assert.equal((await poll(e, cli.device_code)).json.error, "authorization_pending");

  const ok = await b.post("/device/approve", { form, user_code: code, org, label: " Build\tbox " });
  assert.equal(ok.status, 200, ok.text);
  assert.equal(stateOf(e, cli.device_code).label, "Build box");
  later(device.INTERVAL);
  const got = await poll(e, cli.device_code);
  assert.equal(got.status, 200, got.text);
  const machine = one(e, "SELECT * FROM machines WHERE hash = ?", sha(got.json.access_token));
  assert.equal(machine.label, "Build box");
  assert.equal((await whoami(e, got.json.access_token)).json.machine.label, "Build box");
  const home = await b.get("/");
  assert.ok(home.text.includes("<strong>Build box</strong>"), "listed by that name");
  assert.ok(!home.text.includes("Unnamed terminal"));
  const all = dump(e);
  assert.ok(!all.includes("named-by-the-terminal") && !all.includes("box.local"), "what the terminal sent is kept nowhere");
});

test("a token is minted only while its approver is still a member of the organisation", async () => {
  const s = services();
  const e = env();
  const b = new Browser(e);
  await signIn(b, s);
  const cli = await newCode(e);
  assert.equal((await approve(b, cli.user_code)).done.status, 200);
  e.LIST.sql.prepare("DELETE FROM memberships").run();
  later(device.INTERVAL);
  const r = await poll(e, cli.device_code);
  assert.deepEqual([r.status, r.json.error], [400, "access_denied"]);
  assert.deepEqual([count(e, "tokens"), count(e, "machines")], [0, 0]);
});

test("wrong codes: five in ten minutes lock a session's form, and five at one waiting code lock that code", async () => {
  const s = services();
  const e = env();
  const b = new Browser(e, { ip: "198.51.100.20" });
  await signIn(b, s);
  const cli = await newCode(e);

  /* Not the shape of a code: said so, and not counted. */
  for (const typed of ["ABCD", "BCDF-GHJK-L", "1234-5678"]) {
    const r = await typeDevice(b, typed);
    assert.equal(r.status, 400);
    assert.match(r.text, /eight letters/);
  }
  /* Wrong codes that share nothing with the waiting one. */
  for (let k = 1; k <= 4; k++) {
    const r = await typeDevice(b, stranger(cli.user_code, k));
    assert.equal(r.status, 400);
    assert.match(r.text, new RegExp(`That code is not right\\. ${5 - k} tr(y|ies) left\\.`));
  }
  const fifth = await typeDevice(b, stranger(cli.user_code, 5));
  assert.equal(fifth.status, 429);
  assert.match(fifth.text, /Too many wrong codes/);
  assert.equal(stateOf(e, cli.device_code).state, "pending", "codes it never named are untouched");
  /* Locked: even the right code waits, and the box is not shown. */
  assert.equal((await b.get("/device")).status, 429);
  const right = await b.post("/device", { form: await formToken(e, b.session, "device"), user_code: cli.user_code });
  assert.equal(right.status, 429);
  assert.doesNotMatch(right.text, /Approve this terminal/);

  /* Ten minutes on, the form is back. */
  later(10 * MINUTE + 1);
  const fresh = await newCode(e);
  assert.equal((await typeDevice(b, fresh.user_code)).status, 200);

  /* Five wrong tries naming a waiting code's first half lock that code,
     wherever they come from; the terminal is told no. */
  const target = await newCode(e);
  const guesser = new Browser(e, { ip: "203.0.113.77" });
  await signIn(guesser, s, "guesser@example.com");
  for (let k = 1; k <= 4; k++) {
    const r = await typeDevice(guesser, sibling(target.user_code, k));
    assert.equal(r.status, 400, "the same answer as any wrong code");
    assert.match(r.text, /That code is not right/);
    assert.equal(stateOf(e, target.device_code).state, "pending");
  }
  assert.equal((await typeDevice(guesser, sibling(target.user_code, 5))).status, 429);
  const locked = stateOf(e, target.device_code);
  assert.deepEqual([locked.state, locked.user_id], ["denied", null]);
  later(device.INTERVAL);
  assert.equal((await poll(e, target.device_code)).json.error, "access_denied");
  const owner = await typeDevice(b, target.user_code);
  assert.equal(owner.status, 400);
  assert.match(owner.text, /locked after too many wrong tries/);
  assert.equal(stateOf(e, fresh.device_code).state, "pending", "other codes are untouched");

  /* The counts are keyed on an HMAC, never a session, account or address. */
  const keys = rows(e, "SELECT key FROM throttle").map((x) => x.key).join(" ");
  for (const raw of [b.session, guesser.session, one(e, "SELECT id FROM users").id, "198.51.100.20", "203.0.113.77",
                     sha(target.device_code)]) {
    assert.ok(!keys.includes(raw));
  }
});

test("guesses sent at once are held to the limits: each is counted before it is looked up", async () => {
  const s = services();
  const e = env();
  const victim = await newCode(e, { ip: "203.0.113.77" });
  const b = new Browser(e, { ip: "198.51.100.40" });
  await signIn(b, s, "mallory@example.com");
  const form = tokenFor((await b.get("/device")).text, "/device");
  /* Fifty wrong guesses that share nothing with the waiting code, and the
     waiting code itself among them, past the first few. */
  const guesses = Array.from({ length: 50 }, (_, k) => stranger(victim.user_code, (k % 19) + 1));
  guesses[30] = victim.user_code;
  const replies = await Promise.all(guesses.map((user_code) => b.post("/device", { form, user_code })));
  const looked = replies.filter((r) => r.status !== 429);
  assert.ok(looked.length <= device.WRONG_PER_SESSION, `${looked.length} guesses were looked up`);
  assert.ok(replies.filter((r) => r.status === 429).length >= 50 - device.WRONG_PER_SESSION);
  assert.ok(!replies.some((r) => /Approve this terminal/.test(r.text)), "the waiting code was never shown");
  assert.equal(stateOf(e, victim.device_code).state, "pending");
  /* Locked afterwards, the right code included. */
  assert.equal((await b.get("/device")).status, 429);
  assert.equal((await b.post("/device", { form, user_code: victim.user_code })).status, 429);

  /* A right code gives its try back: a person who types their own code
     between wrong ones is not locked out sooner for it. */
  const ana = new Browser(e, { ip: "198.51.100.41" });
  await signIn(ana, s);
  const mine = await newCode(e, { ip: "198.51.100.41" });
  for (let k = 1; k <= 3; k++) assert.equal((await typeDevice(ana, stranger(mine.user_code, k))).status, 400);
  assert.equal((await typeDevice(ana, mine.user_code)).status, 200);
  const fourth = await typeDevice(ana, stranger(mine.user_code, 4));
  assert.equal(fourth.status, 400);
  assert.match(fourth.text, /That code is not right\. 1 try left\./);
  assert.equal((await typeDevice(ana, stranger(mine.user_code, 5))).status, 429);
});

test("an account gets ten wrong codes an hour over all its sessions", async () => {
  const s = services();
  const e = env();
  const first = new Browser(e, { ip: "198.51.100.30" });
  await signIn(first, s);
  const cli = await newCode(e);
  for (let k = 1; k <= 5; k++) await typeDevice(first, stranger(cli.user_code, k));
  later(MINUTE + 1);
  const second = new Browser(e, { ip: "198.51.100.31" });
  await signIn(second, s);
  for (let k = 1; k <= 4; k++) assert.equal((await typeDevice(second, stranger(cli.user_code, k + 5))).status, 400);
  assert.equal((await typeDevice(second, stranger(cli.user_code, 10))).status, 429);
  later(10 * MINUTE);
  assert.equal((await second.get("/device")).status, 429, "the account's hour is not over");
  later(HOUR);
  assert.equal((await second.get("/device")).status, 200);
});

/* ---------- tokens of every kind ---------- */

test("whoami and logout take a Bearer token, never a cookie, and leave shared and CI tokens alone", async () => {
  const s = services();
  const e = env();
  const { b, token } = await linked(e, s);
  const org = orgOf(e, "ana@example.com");
  grant(e, org, "plus");

  /* A cookie is no token here. */
  const cookie = `${SESSION}=${b.jar.get(SESSION)}`;
  for (const r of [await call(e, "/v1/whoami", { method: "GET", headers: { cookie } }),
                   await call(e, "/v1/logout", { headers: { cookie } })]) {
    assert.equal(r.status, 401);
    assert.equal(r.headers.get("set-cookie"), null);
  }
  assert.equal((await whoami(e, madeToken("rw_m_"))).status, 403);

  /* A subscription's token, as stripe.js issues one, and one made by hand. */
  const t = unix();
  const run = (sql, ...p) => e.LIST.sql.prepare(sql).run(...p);
  const paid = madeToken();
  run("INSERT INTO subscriptions (id, customer, status, updated_at) VALUES ('sub_test1', 'cus_test1', 'active', ?)", t);
  run("INSERT INTO tokens (hash, note, created_at) VALUES (?, 'stripe sub_test1', ?)", sha(paid), t);
  run("INSERT INTO token_subscriptions (hash, subscription) VALUES (?, 'sub_test1')", sha(paid));
  const hand = madeToken();
  run("INSERT INTO tokens (hash, note, created_at) VALUES (?, 'by hand', ?)", sha(hand), t);
  /* A CI token of the same organisation. */
  const ci = madeToken("rw_c_");
  run("INSERT INTO tokens (hash, note, created_at) VALUES (?, 'ci', ?)", sha(ci), t);
  run("INSERT INTO machines (id, hash, org_id, user_id, kind, label, created_at) VALUES (?, ?, ?, NULL, 'ci', 'build', ?)",
      randomUUID(), sha(ci), org, t);

  assert.deepEqual((await whoami(e, paid)).json,
                   { kind: "subscription", email: null, org: null, role: null, plan: "plus", machine: null });
  assert.deepEqual((await whoami(e, hand)).json,
                   { kind: "hand", email: null, org: null, role: null, plan: "plus", machine: null });
  const ciWho = (await whoami(e, ci)).json;
  assert.deepEqual([ciWho.kind, ciWho.email, ciWho.org, ciWho.plan, ciWho.machine.label], ["ci", null, "Personal", "plus", "build"]);
  /* Once linked to an organisation (scripts/org_admin.py), a subscription's token names it. */
  run("INSERT INTO org_subscriptions (subscription, org_id, how, linked_at) VALUES ('sub_test1', ?, 'script', ?)", org, t);
  assert.equal((await whoami(e, paid)).json.org, "Personal");

  for (const shared of [paid, hand, ci]) {
    assert.deepEqual((await logout(e, shared)).json, { revoked: false, shared: true });
    assert.equal((await feed(e, shared)).status, 200, "still works");
  }
  assert.equal(count(e, "tokens") - rows(e, "SELECT 1 FROM tokens WHERE revoked_at IS NULL").length, 0);
  assert.deepEqual((await logout(e, token)).json, { revoked: true });
  assert.equal(rows(e, "SELECT hash FROM tokens WHERE revoked_at IS NOT NULL")[0].hash, sha(token));
});

test("last use is noted to the day, at most once a day, and never for a shared token", async () => {
  const s = services();
  const e = env();
  const { token } = await linked(e, s);
  const org = orgOf(e, "ana@example.com");
  grant(e, org, "plus");
  const writes = [];
  const prepare = e.LIST.prepare;
  e.LIST.prepare = (sql) => {
    if (/UPDATE machines SET last_used_day/.test(sql)) writes.push(sql);
    return prepare(sql);
  };
  for (let i = 0; i < 3; i++) assert.equal((await feed(e, token)).status, 200);
  await whoami(e, token);
  assert.equal(writes.length, 1);
  const day = Math.floor(unix() / DAY) * DAY;
  assert.equal(one(e, "SELECT last_used_day FROM machines").last_used_day, day);
  later(DAY);
  await feed(e, token);
  await feed(e, token);
  assert.equal(writes.length, 2);
  assert.equal(one(e, "SELECT last_used_day FROM machines").last_used_day, day + DAY);

  /* A subscription's token with a legacy machine row: used, never noted. */
  const t = unix();
  const run = (sql, ...p) => e.LIST.sql.prepare(sql).run(...p);
  const paid = madeToken();
  run("INSERT INTO subscriptions (id, customer, status, updated_at) VALUES ('sub_test2', 'cus_test2', 'active', ?)", t);
  run("INSERT INTO tokens (hash, note, created_at) VALUES (?, 'stripe sub_test2', ?)", sha(paid), t);
  run("INSERT INTO token_subscriptions (hash, subscription) VALUES (?, 'sub_test2')", sha(paid));
  run("INSERT INTO machines (id, hash, org_id, kind, label, created_at) VALUES (?, ?, ?, 'legacy', 'emailed', ?)",
      randomUUID(), sha(paid), org, t);
  assert.equal((await feed(e, paid)).status, 200);
  assert.equal(writes.length, 2);
  assert.equal(one(e, "SELECT last_used_day FROM machines WHERE kind = 'legacy'").last_used_day, null);
});

/* ---------- housekeeping ---------- */

test("slow_down adds five seconds each time, up to a minute, and polls with made-up codes never hold a terminal back", async () => {
  const e = env();
  const cli = await newCode(e);
  await poll(e, cli.device_code);
  const intervals = [];
  for (let i = 0; i < 13; i++) intervals.push((await poll(e, cli.device_code)).json.interval);
  assert.deepEqual(intervals, [10, 15, 20, 25, 30, 35, 40, 45, 50, 55, 60, 60, 60]);
  later(59);
  assert.equal((await poll(e, cli.device_code)).json.error, "slow_down");
  later(60);
  assert.equal((await poll(e, cli.device_code)).json.error, "authorization_pending");

  /* Someone on the same network polls with codes nobody holds, as many
     times as an hour's budget once was: each is told invalid_grant, no
     count is written for them, and the terminal waiting there is answered
     on time, then given its token once approved. */
  const s = services();
  const many = env();
  const code = await newCode(many, { ip: "203.0.113.50" });
  const throttles = count(many, "throttle");
  for (let i = 0; i < 1250; i++) {
    const r = await poll(many, madeToken("").slice(0, 43), { ip: "203.0.113.50" });
    assert.equal(r.json.error, "invalid_grant");
  }
  assert.equal(count(many, "throttle"), throttles, "a made-up code writes nothing");
  assert.equal((await poll(many, code.device_code, { ip: "203.0.113.50" })).json.error, "authorization_pending");
  const b = new Browser(many);
  await signIn(b, s);
  assert.equal((await approve(b, code.user_code)).done.status, 200);
  later(device.INTERVAL);
  const got = await poll(many, code.device_code, { ip: "203.0.113.50" });
  assert.equal(got.status, 200, got.text);
  assert.match(got.json.access_token, /^rw_m_/);
});

test("the cron deletes device codes an hour after they expire; the terminal's token stays", async () => {
  const s = services();
  const e = env();
  const { token } = await linked(e, s);
  await newCode(e);
  const sweep = async () => {
    const waits = [];
    await worker.scheduled({}, e, { waitUntil: (p) => waits.push(p) });
    await Promise.all(waits);
  };
  await sweep();
  assert.equal(count(e, "device_codes"), 2);
  later(device.DEVICE_FOR + HOUR + 1);
  await sweep();
  assert.equal(count(e, "device_codes"), 0);
  assert.deepEqual([count(e, "tokens"), count(e, "machines")], [1, 1]);
  assert.equal((await whoami(e, token)).status, 200);
});

test("nothing logged carries a code or a token", async () => {
  const lines = [];
  const real = console.log;
  console.log = (...a) => lines.push(a.join(" "));
  let secrets = [];
  try {
    const s = services();
    const e = env();
    const { cli, token } = await linked(e, s);
    secrets = [token, cli.device_code, cli.user_code, cli.user_code.replace("-", "")];
    await poll(e, cli.device_code);
    await whoami(e, token);
    await logout(e, token);
  } finally {
    console.log = real;
  }
  for (const line of lines) {
    for (const secret of secrets) assert.ok(!line.includes(secret));
    assert.doesNotMatch(line, /rw_|@/);
  }
});

/* ---------- end to end, with the real CLI ---------- */

/* The Worker on a port of this machine, answering as feed.ranwhat.com,
   and `python3 -m ranwhat` run against it with a home of its own. */
async function overHttp(e) {
  const server = createServer(async (req, res) => {
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    const headers = new Headers({ "cf-connecting-ip": "203.0.113.9" });
    for (const [k, v] of Object.entries(req.headers)) {
      if (!["host", "connection", "content-length", "transfer-encoding"].includes(k)) headers.set(k, v);
    }
    const reply = await worker.fetch(new Request(`${FEED}${req.url}`, {
      method: req.method, headers, body: chunks.length ? Buffer.concat(chunks) : undefined,
    }), e, ctx);
    res.writeHead(reply.status, Object.fromEntries(reply.headers));
    res.end(Buffer.from(await reply.arrayBuffer()));
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const home = mkdtempSync(join(tmpdir(), "ranwhat-login-"));
  const base = `http://127.0.0.1:${server.address().port}/v1`;
  const childEnv = { ...process.env, RANWHAT_HOME: home, HOME: home, USERPROFILE: home,
    RANWHAT_ACCOUNT_URL: base, RANWHAT_FEED_URL: `${base}/catalogue`, RANWHAT_NO_HINTS: "1",
    NO_COLOR: "1", NO_PROXY: "127.0.0.1,localhost", no_proxy: "127.0.0.1,localhost" };
  for (const k of ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "RANWHAT_TOKEN",
                   "SSH_CONNECTION", "SSH_CLIENT", "SSH_TTY"]) delete childEnv[k];
  /* { done, until(re) }: done resolves to { stdout, stderr, status }, and
     until(re) to re's match in stdout once it is printed. */
  const start = (...args) => {
    const out = { stdout: "", stderr: "" };
    const waiting = [];
    const p = spawn("python3", ["-m", "ranwhat", ...args], { cwd: ROOT, env: childEnv });
    p.stdout.on("data", (d) => {
      out.stdout += d;
      for (const w of waiting.splice(0)) {
        const m = out.stdout.match(w.re);
        if (m) w.resolve(m); else waiting.push(w);
      }
    });
    p.stderr.on("data", (d) => (out.stderr += d));
    const done = new Promise((resolve) => p.on("close", (status) => resolve({ ...out, status })));
    const until = (re) => new Promise((resolve, reject) => {
      const m = out.stdout.match(re);
      if (m) return resolve(m);
      waiting.push({ re, resolve });
      done.then((r) => reject(new Error(`exited ${r.status} first: ${r.stdout} ${r.stderr}`)));
    });
    return { done, until };
  };
  const run = (...args) => start(...args).done;
  const close = () => {
    server.close();
    rmSync(home, { recursive: true, force: true });
  };
  return { home, start, run, close };
}

test("the real ranwhat login, whoami, update and logout, against the Worker over HTTP", async () => {
  const s = services();
  const e = env();
  const cli = await overHttp(e);
  try {
    const none = await cli.run("whoami");
    assert.equal(none.status, 1);
    assert.match(none.stderr, /Not logged in/);

    const b = new Browser(e);
    await signIn(b, s);
    const login = cli.start("login", "--no-browser");
    const [, userCode] = await login.until(/^ {4}([BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4})$/m);
    const { done } = await approve(b, userCode, "Ana's laptop");
    assert.equal(done.status, 200, done.text);
    const linkedRun = await login.done;
    assert.equal(linkedRun.status, 0, linkedRun.stderr);
    assert.match(linkedRun.stdout, /^ {4}https:\/\/ranwhat\.com\/device$/m, "the page, as the Worker names it");
    assert.ok(!linkedRun.stdout.split("\n").some((l) => l.includes("http") && l.includes(userCode)),
      "the code is never in a link");
    assert.match(linkedRun.stdout, /Linked to Personal as ana@example\.com \(Free\)\./);
    assert.match(linkedRun.stdout, /need Plus:\s+https:\/\/account\.ranwhat\.com\//);

    let token = readFileSync(join(cli.home, "token"), "utf8").trim();
    assert.match(token, /^rw_m_[A-Za-z0-9_-]{43}$/);
    assert.ok(!dump(e).includes(token), "D1 holds the token's hash, never the token");
    assert.equal(one(e, "SELECT kind FROM machines WHERE hash = ?", sha(token)).kind, "device");
    const cache = readFileSync(join(cli.home, "account.json"), "utf8");
    assert.ok(!cache.includes(token));
    assert.equal(JSON.parse(cache).tokens[0].plan, "free");

    const again = await cli.run("login");
    assert.equal(again.status, 1);
    assert.match(again.stderr, /already has a saved token \(ana@example\.com, Personal, Free\)/);

    /* --force links it again, and revokes the token it replaces: no copy
       of the old one is left working, nor listed on the account page. */
    const forced = cli.start("login", "--no-browser", "--force");
    const [, forcedCode] = await forced.until(/^ {4}([BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4})$/m);
    assert.equal((await approve(b, forcedCode, "Ana's laptop")).done.status, 200);
    const relinked = await forced.done;
    assert.equal(relinked.status, 0, relinked.stderr);
    assert.match(relinked.stdout, /The token this machine had before is revoked\./);
    const replaced = token;
    token = readFileSync(join(cli.home, "token"), "utf8").trim();
    assert.notEqual(token, replaced);
    assert.equal((await whoami(e, replaced)).status, 403, "the replaced token no longer works");
    assert.equal((await whoami(e, token)).status, 200);
    assert.equal(rows(e, `SELECT m.id FROM machines m JOIN tokens t ON t.hash = m.hash
                          WHERE m.kind = 'device' AND t.revoked_at IS NULL`).length, 1);

    const who = await cli.run("whoami");
    assert.equal(who.status, 0, who.stderr);
    for (const line of [/Account\s+ana@example\.com/, /Organisation\s+Personal/, /Role\s+owner/, /Plan\s+Free/,
                        /Machine\s+Ana's laptop/]) {
      assert.match(who.stdout, line);
    }

    const free = await cli.run("update");
    assert.equal(free.status, 1);
    assert.match(free.stderr, /linked to Personal, which is on Free/);
    assert.match(free.stderr, /part of Plus: https:\/\/account\.ranwhat\.com\//);

    grant(e, orgOf(e, "ana@example.com"));
    const plus = await cli.run("update");
    assert.equal(plus.status, 0, plus.stderr);
    assert.match(plus.stdout, /Updated to feed/);
    assert.equal(JSON.parse(readFileSync(join(cli.home, "account.json"), "utf8")).tokens[0].plan, "plus");

    const out = await cli.run("logout");
    assert.equal(out.status, 0, out.stderr);
    assert.match(out.stdout, /revoked and deleted/);
    assert.ok(!existsSync(join(cli.home, "token")));
    assert.ok(one(e, "SELECT revoked_at FROM tokens WHERE hash = ?", sha(token)).revoked_at);
    assert.equal((await feed(e, token)).status, 403);

    for (const r of [linkedRun, again, relinked, who, free, plus, out]) {
      for (const t of [token, replaced]) {
        assert.ok(!r.stdout.includes(t) && !r.stderr.includes(t), "no command prints a token");
      }
    }
  } finally {
    cli.close();
  }
});
