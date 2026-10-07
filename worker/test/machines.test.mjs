/* An organisation's machines on account.ranwhat.com (machines.js, drawn
 * and routed by dashboard.js): the list, renaming and revoking, CI tokens,
 * the day each was last used, and the cron that revokes idle terminals.
 * The Worker's own fetch and scheduled handlers run over a real SQLite
 * database (node:sqlite, which is what D1 runs), with Resend and Turnstile
 * answered by stand-ins and terminals linked through the real device
 * grant, as in device.test.mjs.
 *
 *     node --test --test-timeout=60000 worker/test/machines.test.mjs
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { d1 } from "./stand-ins.mjs";

const worker = (await import("../src/index.js")).default;
const device = await import("../src/device.js");
const machines = await import("../src/machines.js");
const { FEATURES, allows } = await import("../src/features.js");
const { formToken } = await import("../src/session.js");

const ORIGIN = "https://account.ranwhat.com";
const FEED = "https://feed.ranwhat.com";
const SECRET = "an-account-test-secret-that-is-long-enough-0123456789";
const SESSION = "__Host-rw_session";
const FROM_PAGE = { "sec-fetch-site": "same-origin", origin: ORIGIN };
const GRANT = "urn:ietf:params:oauth:grant-type:device_code";
const MINUTE = 60, HOUR = 3600, DAY = 24 * HOUR;
const ctx = { waitUntil() {} };

/* auth.js's TOKEN: a CI token must still be a feed token. */
const FEED_TOKEN = /^Bearer (rw_[A-Za-z0-9_-]{20,200})$/;
const CI_TOKEN = /<code class="secret">(rw_c_[A-Za-z0-9_-]{43})<\/code>/;

/* The clock, which a test moves forward when it needs time to pass. */
const realNow = Date.now;
let skew = 0;
Date.now = () => realNow() + skew * 1000;
const later = (seconds) => { skew += seconds; };
const unix = () => Math.floor(Date.now() / 1000);
const dayOf = (t) => Math.floor(t / DAY) * DAY;
const isoDay = (t) => new Date(t * 1000).toISOString().slice(0, 10);

const sha = (text) => createHash("sha256").update(text).digest("hex");
/* Made here rather than written out: nothing token-shaped sits in the source. */
const madeToken = (prefix = "rw_") => prefix + randomBytes(32).toString("base64url");
const nonce = () => randomBytes(32).toString("base64url");

/* ---------- stand-ins ---------- */

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
  LIST: d1(), RESEND_API_KEY: "re_" + "test_key", ACCOUNT_SECRET: SECRET, TURNSTILE_SECRET: "turnstile-" + "test",
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
async function signIn(b, s, email = "ana@example.com") {
  const form = await b.get("/signin");
  const asked = await b.post("/signin", { form: tokenFor(form.text, "/signin"), email, next: "/",
    "cf-turnstile-response": solved("signin") });
  assert.equal(asked.status, 303, asked.text);
  const done = await typeCode(b, codeIn(s.emails.at(-1)));
  assert.equal(done.status, 303, done.text);
  assert.ok(b.jar.has(SESSION));
}

/* A fresh code for a session that is no longer fresh: asked for from the
   account page, typed, and back there. */
async function confirm(b, s) {
  const home = await b.get("/");
  const asked = await b.post("/stepup", { form: tokenFor(home.text, "/stepup"), next: "/" });
  assert.equal(asked.location, "/signin/code");
  const back = await typeCode(b, codeIn(s.emails.at(-1)));
  assert.equal(back.location, "/");
}

const rows = (e, sql, ...p) => e.LIST.sql.prepare(sql).all(...p).map((r) => ({ ...r }));
const one = (e, sql, ...p) => rows(e, sql, ...p)[0];
const run = (e, sql, ...p) => e.LIST.sql.prepare(sql).run(...p);
const count = (e, table) => e.LIST.sql.prepare(`SELECT count(*) AS n FROM ${table}`).get().n;
const tables = (e) => rows(e, "SELECT name FROM sqlite_master WHERE type = 'table'").map((r) => r.name);
const dump = (e) => JSON.stringify(tables(e).map((t) => rows(e, `SELECT * FROM ${t}`)));
const userId = (e, email) => one(e, "SELECT id FROM users WHERE email = ?", email).id;
const orgOf = (e, email) => one(e,
  "SELECT m.org_id AS id FROM memberships m JOIN users u ON u.id = m.user_id WHERE u.email = ? AND m.role = 'owner'", email).id;

function grant(e, orgId, which = "plus") {
  run(e, "INSERT INTO grants (org_id, plan, starts_at, until, note, created_at) VALUES (?, ?, ?, NULL, 'test', ?)",
    orgId, which, unix() - 60, unix());
}

/* `email` joins `orgId` as `role`, and their session looks at it. */
function join(e, email, orgId, role = "member") {
  const user = userId(e, email);
  run(e, "INSERT INTO memberships (org_id, user_id, role, created_at) VALUES (?, ?, ?, ?)", orgId, user, role, unix());
  run(e, "UPDATE sessions SET org_id = ? WHERE user_id = ?", orgId, user);
}

/* A subscription's emailed token, claimed by `orgId`: a legacy machine. */
function legacy(e, orgId) {
  const t = unix();
  const token = madeToken();
  const sub = `sub_${randomUUID().slice(0, 8)}`;
  const id = randomUUID();
  run(e, "INSERT INTO subscriptions (id, customer, status, updated_at) VALUES (?, 'cus_legacy', 'active', ?)", sub, t);
  run(e, "INSERT INTO tokens (hash, note, created_at) VALUES (?, ?, ?)", sha(token), `stripe ${sub}`, t);
  run(e, "INSERT INTO token_subscriptions (hash, subscription) VALUES (?, ?)", sha(token), sub);
  run(e, "INSERT INTO org_subscriptions (subscription, org_id, how, linked_at) VALUES (?, ?, 'script', ?)", sub, orgId, t);
  run(e, "INSERT INTO machines (id, hash, org_id, kind, label, created_at) VALUES (?, ?, ?, 'legacy', '', ?)",
    id, sha(token), orgId, t);
  return { token, id };
}

/* ---------- the feed host ---------- */

async function call(e, path, { method = "POST", form, token, ip = "203.0.113.5" } = {}) {
  const h = new Headers({ "cf-connecting-ip": ip });
  if (token) h.set("authorization", `Bearer ${token}`);
  let body;
  if (form) {
    h.set("content-type", "application/x-www-form-urlencoded");
    body = new URLSearchParams(form).toString();
  }
  const res = await worker.fetch(new Request(`${FEED}${path}`, { method, headers: h, body }), e, ctx);
  const text = await res.text();
  let json = null;
  try { json = JSON.parse(text); } catch { /* not JSON */ }
  return { status: res.status, text, json };
}

const feed = (e, token) => call(e, "/v1/catalogue", { method: "GET", token });
const whoami = (e, token) => call(e, "/v1/whoami", { method: "GET", token });

/* A terminal linked to the organisation `b`'s session is looking at,
   approved by `b` (whose session must be fresh) under the name `label`:
   its token and machine. */
async function linkTerminal(e, b, label = "Work laptop") {
  const cli = (await call(e, "/v1/device/code", { form: { client_id: "ranwhat-cli" } })).json;
  const box = await b.get("/device");
  const shown = await b.post("/device", { form: tokenFor(box.text, "/device"), user_code: cli.user_code });
  assert.equal(shown.status, 200, shown.text);
  const done = await b.post("/device/approve", { form: tokenFor(shown.text, "/device/approve"),
    user_code: shown.text.match(/name="user_code" value="([^"]+)"/)[1],
    org: shown.text.match(/name="org" value="([^"]+)"/)[1], label });
  assert.equal(done.status, 200, done.text);
  later(device.INTERVAL);
  const got = await call(e, "/v1/device/token", { form: { client_id: "ranwhat-cli", grant_type: GRANT,
    device_code: cli.device_code } });
  assert.equal(got.status, 200, got.text);
  const token = got.json.access_token;
  return { token, id: one(e, "SELECT id FROM machines WHERE hash = ?", sha(token)).id };
}

/* ---------- the account page ---------- */

const section = (html) => {
  const m = html.match(/<section class="panel" id="machines">([\s\S]*?)<\/section>/);
  assert.ok(m, "no machines section");
  return m[1];
};

const listed = (html) => Object.fromEntries([...section(html).matchAll(/<li data-machine="([^"]+)">([\s\S]*?)<\/li>/g)]
  .map((m) => [m[1], m[2]]));

/* Makes a CI token with the form on the account page. */
async function makeCi(b, { label = "deploy", expires = "never" } = {}) {
  const home = await b.get("/");
  const form = tokenFor(home.text, "/tokens/ci");
  const sent = { form, nonce: home.text.match(/name="nonce" value="([^"]+)"/)[1], label, expires };
  const r = await b.post("/tokens/ci", sent);
  const m = r.text.match(CI_TOKEN);
  return { r, sent, token: m ? m[1] : null };
}

/* A CI form this session could have been shown, with a nonce of its own. */
async function forgedCi(e, b, fields = {}) {
  const n = nonce();
  return b.post("/tokens/ci", { form: await formToken(e, b.session, `ci-token:${n}`), nonce: n,
    label: "forged", expires: "never", ...fields });
}

const cron = async (e) => {
  const waits = [];
  await worker.scheduled({}, e, { waitUntil: (p) => waits.push(p) });
  await Promise.all(waits);
};

const revoked = (e, token) => one(e, "SELECT revoked_at FROM tokens WHERE hash = ?", sha(token)).revoked_at;

/* ---------- the switch ---------- */

test("dark: with ACCOUNTS_ON unset the new forms answer 404 as an unknown path does, and the cron makes nothing", async () => {
  for (const extra of [{ ACCOUNTS_ON: undefined }, { ACCOUNTS_ON: "" }, { ACCOUNTS_ON: "0" }]) {
    const e = env(extra);
    const unknown = await worker.fetch(new Request(`${ORIGIN}/no-such-path`), e, ctx);
    const expected = [unknown.status, await unknown.text(), [...unknown.headers]];
    assert.equal(expected[0], 404);
    for (const path of ["/machines/rename", "/machines/revoke", "/tokens/ci"]) {
      const r = await worker.fetch(new Request(`${ORIGIN}${path}`, { method: "POST", headers: FROM_PAGE,
        body: "label=x" }), e, ctx);
      assert.deepEqual([r.status, await r.text(), [...r.headers]], expected, path);
    }
    await cron(e);
    assert.deepEqual(tables(e), [], "nothing is made in the database while it is off");
    assert.equal(await machines.revokeIdle(e), 0);
    assert.deepEqual(tables(e), []);
  }
});

test("the feature map: CI tokens are live and need Plus", () => {
  assert.equal(FEATURES.ci_tokens.plan, "plus");
  assert.equal(FEATURES.ci_tokens.status, "live");
  assert.deepEqual(["free", "plus", "team"].map((p) => allows(p, "ci_tokens")), [false, true, true]);
});

/* ---------- the list ---------- */

test("the Machines section lists each machine of the organisation: name, kind, who linked it and when, last use", async () => {
  const s = services();
  const e = env();
  const ana = new Browser(e);
  await signIn(ana, s);
  const org = orgOf(e, "ana@example.com");
  let html = (await ana.get("/")).text;
  assert.match(section(html), /None yet\. Run <strong>ranwhat login<\/strong>/);

  const terminal = await linkTerminal(e, ana, "Ana's <laptop>");
  grant(e, org, "plus");
  const ci = await makeCi(ana, { label: "GitHub Actions", expires: "90" });
  assert.equal(ci.r.status, 200, ci.r.text);
  const ciId = one(e, "SELECT id FROM machines WHERE kind = 'ci'").id;
  const old = legacy(e, org);

  /* Someone else's terminal, in their own organisation. */
  const mallory = new Browser(e, { ip: "203.0.113.66" });
  await signIn(mallory, s, "mallory@example.com");
  const theirs = await linkTerminal(e, mallory);

  assert.equal((await feed(e, terminal.token)).status, 200);
  html = (await ana.get("/")).text;
  const items = listed(html);
  assert.deepEqual(Object.keys(items).sort(), [terminal.id, ciId, old.id].sort());
  assert.ok(!html.includes(theirs.id), "another organisation's machine is not listed");
  const today = isoDay(unix());

  assert.match(items[terminal.id], /^<strong>Ana's &lt;laptop&gt;<\/strong> <span class="tag">terminal<\/span>/,
               "named as it was on the page that approved it, escaped");
  assert.ok(items[terminal.id].includes(`Linked by ana@example.com on ${today}.`));
  assert.ok(items[terminal.id].includes(`Last used ${today}.`));
  assert.match(items[ciId], /^<strong>GitHub Actions<\/strong> <span class="tag">CI<\/span>/);
  assert.ok(items[ciId].includes(`Made by ana@example.com on ${today}.`));
  assert.ok(items[ciId].includes("Not used yet."));
  assert.ok(items[ciId].includes(`Expires ${isoDay(unix() + 90 * DAY)}.`));
  assert.match(items[old.id], /^<strong>Subscription token<\/strong> <span class="tag">old subscription token<\/span>/);
  assert.ok(items[old.id].includes("Its use is not recorded."));

  /* The page names machines by id, never by token or hash. */
  for (const secret of [terminal.token, ci.token, old.token]) {
    assert.ok(!html.includes(secret) && !html.includes(sha(secret)));
  }
  assert.doesNotMatch(html, /<script|\son[a-z]+=/i);

  /* A CI token in use shows its day; a revoked one leaves the list. */
  assert.equal((await feed(e, ci.token)).status, 200);
  assert.ok(listed((await ana.get("/")).text)[ciId].includes(`Last used ${today}.`));
  run(e, "UPDATE tokens SET revoked_at = ? WHERE hash = ?", unix(), sha(ci.token));
  assert.equal(listed((await ana.get("/")).text)[ciId], undefined);
});

/* ---------- renaming ---------- */

test("renaming: an owner or admin, or whoever linked it; a name is escaped and printable, 60 characters at most", async () => {
  const s = services();
  const e = env();
  const ana = new Browser(e);
  await signIn(ana, s);
  const acme = orgOf(e, "ana@example.com");
  const anas = await linkTerminal(e, ana);
  const bo = new Browser(e, { ip: "203.0.113.60" });
  await signIn(bo, s, "bo@example.com");
  join(e, "bo@example.com", acme, "member");
  const bos = await linkTerminal(e, bo);
  assert.equal(one(e, "SELECT org_id FROM machines WHERE id = ?", bos.id).org_id, acme, "Bo linked it to Acme");
  const mallory = new Browser(e, { ip: "203.0.113.66" });
  await signIn(mallory, s, "mallory@example.com");
  const theirs = await linkTerminal(e, mallory, "Mallory's");

  const rename = async (b, id, label, form) => b.post("/machines/rename",
    { form: form || tokenFor((await b.get("/")).text, "/machines/rename"), id, label });
  const labelOf = (id) => one(e, "SELECT label FROM machines WHERE id = ?", id).label;

  /* The owner names Bo's terminal; the name is kept as typed, shown escaped. */
  let r = await rename(ana, bos.id, "  Bo's <b>laptop</b> &\n co  ");
  assert.equal(r.location, "/", r.text);
  assert.equal(labelOf(bos.id), "Bo's <b>laptop</b> & co");
  const page = (await ana.get("/")).text;
  assert.ok(listed(page)[bos.id].startsWith("<strong>Bo's &lt;b&gt;laptop&lt;/b&gt; &amp; co</strong>"));
  assert.ok(page.includes('value="Bo\'s &lt;b&gt;laptop&lt;/b&gt; &amp; co"'));
  assert.ok(!page.includes("<b>laptop"));

  /* 60 characters, counted as characters, and nothing unprintable. */
  r = await rename(ana, anas.id, "é".repeat(60));
  assert.equal(r.status, 303);
  assert.equal(labelOf(anas.id), "é".repeat(60));
  for (const bad of ["", "   ", "x".repeat(61), "evil\u202egnp.exe", "bell\u0007", "zero\u200bwidth", ""]) {
    r = await rename(ana, anas.id, bad);
    assert.equal(r.status, 400, JSON.stringify(bad));
    assert.match(r.text, /A name is 1 to 60 characters/);
  }
  assert.equal(labelOf(anas.id), "é".repeat(60));

  /* Bo, a member, names his own terminal and gets no form for Ana's. */
  r = await rename(bo, bos.id, "Bo's");
  assert.equal(r.status, 303);
  assert.equal(labelOf(bos.id), "Bo's");
  const boPage = listed((await bo.get("/")).text);
  assert.match(boPage[bos.id], /action="\/machines\/rename"/);
  assert.doesNotMatch(boPage[anas.id], /<form/);
  const boForm = await formToken(e, bo.session, "machine-rename");
  r = await rename(bo, anas.id, "Taken", boForm);
  assert.equal(r.status, 403);
  assert.match(r.text, /Only an owner or an admin, or whoever linked it/);
  assert.equal(labelOf(anas.id), "é".repeat(60));

  /* Made an admin, he may. */
  run(e, "UPDATE memberships SET role = 'admin' WHERE org_id = ? AND user_id = ?", acme, userId(e, "bo@example.com"));
  assert.equal((await rename(bo, anas.id, "Ana's", boForm)).status, 303);
  assert.equal(labelOf(anas.id), "Ana's");

  /* An id from another organisation, or no id at all, is not found here. */
  for (const id of [theirs.id, randomUUID(), "not-an-id", ""]) {
    r = await rename(ana, id, "Mine now");
    assert.equal(r.status, 404, id);
    assert.match(r.text, /not one of this organisation's/);
  }
  assert.equal(labelOf(theirs.id), "Mallory's");

  /* Another form's token, another session's, or another site's post renames nothing. */
  const anaRevoke = tokenFor((await ana.get("/")).text, "/machines/revoke");
  for (const [form, headers] of [[anaRevoke, FROM_PAGE], [boForm, FROM_PAGE],
                                 [await formToken(e, ana.session, "machine-rename"), { "sec-fetch-site": "same-site" }],
                                 [await formToken(e, ana.session, "machine-rename"), {}]]) {
    r = await ana.post("/machines/rename", { form, id: bos.id, label: "Hijacked" }, headers);
    assert.equal(r.status, 403);
  }
  assert.equal(labelOf(bos.id), "Bo's");
  assert.equal(rows(e, "SELECT 1 FROM auth_events WHERE event = 'machine_renamed'").length, 4);
});

/* ---------- revoking ---------- */

test("revoking needs a fresh code and the right to it, is checked against the organisation, and the feed refuses the token at once", async () => {
  const s = services();
  const e = env();
  const ana = new Browser(e);
  await signIn(ana, s);
  const acme = orgOf(e, "ana@example.com");
  grant(e, acme, "plus");
  const anas = await linkTerminal(e, ana);
  const ci = await makeCi(ana, { label: "build" });
  const ciId = one(e, "SELECT id FROM machines WHERE kind = 'ci'").id;
  const old = legacy(e, acme);
  const bo = new Browser(e, { ip: "203.0.113.60" });
  await signIn(bo, s, "bo@example.com");
  join(e, "bo@example.com", acme, "member");
  const bos = await linkTerminal(e, bo);
  for (const t of [anas.token, ci.token, old.token, bos.token]) assert.equal((await feed(e, t)).status, 200);

  /* Not lately confirmed: no revoke button, the way to a code instead, and a forged form is refused. */
  later(16 * MINUTE);
  const stale = await ana.get("/");
  assert.doesNotMatch(section(stale.text), /action="\/machines\/revoke"/);
  assert.match(section(stale.text), /Revoking a machine needs an emailed code typed in the last 15 minutes/);
  assert.match(section(stale.text), /action="\/stepup"/);
  const revokeForm = await formToken(e, ana.session, "machine-revoke");
  let r = await ana.post("/machines/revoke", { form: revokeForm, id: anas.id });
  assert.equal(r.status, 403);
  assert.match(r.text, /nothing was revoked/);
  assert.equal(revoked(e, anas.token), null);
  assert.equal((await feed(e, anas.token)).status, 200);

  /* Someone else's organisation cannot name Acme's machines, fresh or not. */
  const mallory = new Browser(e, { ip: "203.0.113.66" });
  await signIn(mallory, s, "mallory@example.com");
  for (const id of [anas.id, ciId, old.id]) {
    r = await mallory.post("/machines/revoke", { form: await formToken(e, mallory.session, "machine-revoke"), id });
    assert.equal(r.status, 404);
  }

  /* Bo, a member, revokes his own terminal, not Ana's. */
  await confirm(bo, s);
  const boRevoke = tokenFor((await bo.get("/")).text, "/machines/revoke");
  r = await bo.post("/machines/revoke", { form: boRevoke, id: anas.id });
  assert.equal(r.status, 403);
  r = await bo.post("/machines/revoke", { form: boRevoke, id: bos.id });
  assert.equal(r.location, "/");
  assert.ok(revoked(e, bos.token));
  assert.deepEqual((await feed(e, bos.token)).json, { error: "That token was not accepted." });

  /* Confirmed, Ana revokes her terminal, the CI token and the old subscription token. */
  for (const t of [anas.token, ci.token, old.token]) assert.equal(revoked(e, t), null, "none revoked by the others' tries");
  await confirm(ana, s);
  const home = await ana.get("/");
  const form = tokenFor(home.text, "/machines/revoke");
  for (const [id, token] of [[anas.id, anas.token], [ciId, ci.token], [old.id, old.token]]) {
    r = await ana.post("/machines/revoke", { form, id });
    assert.equal(r.location, "/", r.text);
    assert.ok(revoked(e, token));
    const refused = await feed(e, token);
    assert.deepEqual([refused.status, refused.json], [403, { error: "That token was not accepted." }]);
    assert.equal((await whoami(e, token)).status, 403);
    r = await ana.post("/machines/revoke", { form, id });
    assert.equal(r.status, 404, "already revoked");
  }
  assert.deepEqual(listed((await ana.get("/")).text), {});
  assert.equal(count(e, "machines"), 4, "the rows stay; the tokens are what is revoked");
  const events = rows(e, "SELECT user_id, subject FROM auth_events WHERE event = 'machine_revoked' ORDER BY id");
  assert.deepEqual(events.map((x) => x.subject), [bos.id, anas.id, ciId, old.id]);
  assert.match((await ana.get("/")).text, /Machine revoked, with a fresh code/);
});

/* ---------- CI tokens ---------- */

test("CI tokens: Plus or Team only, an owner or admin, with a fresh code; locked on Free", async () => {
  const s = services();
  const e = env();
  const ana = new Browser(e);
  await signIn(ana, s);
  const acme = orgOf(e, "ana@example.com");

  /* Free: the panel is locked, from the map, with the way up, and the form is refused. */
  let html = (await ana.get("/")).text;
  const locked = section(html).match(/<div class="panel locked" id="ci-tokens" data-feature="ci_tokens">([\s\S]*?)<\/div>/);
  assert.ok(locked, "a locked CI tokens panel");
  assert.match(locked[1], /CI tokens <span class="tag">locked, needs Plus<\/span>/);
  assert.match(locked[1], /<a href="\/upgrade">Upgrade to Plus<\/a>/);
  assert.doesNotMatch(html, /action="\/tokens\/ci"/);
  let r = await forgedCi(e, ana);
  assert.equal(r.status, 403);
  assert.match(r.text, /CI tokens come with Plus, so none was made/);
  assert.equal(count(e, "machines"), 0);

  /* Plus opens it, for the owner. */
  grant(e, acme, "plus");
  html = (await ana.get("/")).text;
  assert.doesNotMatch(section(html), /class="panel locked"|Upgrade to Plus/);
  assert.match(section(html), /<select id="ci-expires" name="expires"><option value="never">Never<\/option>/);

  /* A member sees no form and is refused one. */
  const bo = new Browser(e, { ip: "203.0.113.60" });
  await signIn(bo, s, "bo@example.com");
  join(e, "bo@example.com", acme, "member");
  html = (await bo.get("/")).text;
  assert.doesNotMatch(html, /action="\/tokens\/ci"/);
  assert.match(section(html), /An owner or an admin of Personal can make a CI token here/);
  r = await forgedCi(e, bo);
  assert.equal(r.status, 403);
  assert.match(r.text, /Only an owner or an admin can make a CI token/);

  /* An admin may. */
  run(e, "UPDATE memberships SET role = 'admin' WHERE user_id = ?", userId(e, "bo@example.com"));
  const byAdmin = await makeCi(bo, { label: "bo's pipeline" });
  assert.equal(byAdmin.r.status, 200, byAdmin.r.text);

  /* Not lately confirmed: the way to a code, no form, and a forged one makes nothing. */
  later(16 * MINUTE);
  html = (await ana.get("/")).text;
  assert.doesNotMatch(html, /action="\/tokens\/ci"/);
  assert.match(section(html), /Making one needs an emailed code typed in the last 15 minutes/);
  r = await forgedCi(e, ana);
  assert.equal(r.status, 403);
  assert.match(r.text, /none was made/);
  assert.equal(count(e, "machines"), 1);

  /* Team has it too; and when the plan ends, the form is refused again. */
  await confirm(ana, s);
  run(e, "DELETE FROM grants");
  grant(e, acme, "team");
  assert.equal((await makeCi(ana, { label: "on team" })).r.status, 200);
  run(e, "DELETE FROM grants");
  html = (await ana.get("/")).text;
  assert.match(section(html), /class="panel locked" id="ci-tokens"/);
  r = await forgedCi(e, ana);
  assert.equal(r.status, 403);
  assert.equal(count(e, "machines"), 2);

  /* Another site's post, or one without Origin or Sec-Fetch-Site, is refused before anything. */
  grant(e, acme, "plus");
  for (const headers of [{ "sec-fetch-site": "same-site" }, { origin: "https://ranwhat.com" }, {}]) {
    const n = nonce();
    r = await ana.post("/tokens/ci", { form: await formToken(e, ana.session, `ci-token:${n}`), nonce: n,
      label: "x", expires: "never" }, headers);
    assert.equal(r.status, 403);
  }
  /* The form's token is bound to its nonce. */
  const n = nonce();
  r = await ana.post("/tokens/ci", { form: await formToken(e, ana.session, `ci-token:${n}`), nonce: nonce(),
    label: "x", expires: "never" });
  assert.equal(r.status, 403);
  assert.equal(count(e, "machines"), 2);
});

test("a CI token is shown once, right after it is made, and kept only as a hash; its expiry holds", async () => {
  const s = services();
  const e = env();
  const ana = new Browser(e);
  await signIn(ana, s);
  const acme = orgOf(e, "ana@example.com");
  grant(e, acme, "plus");

  /* A name and an expiry from the list, or nothing is made. */
  for (const [fields, why] of [[{ label: "" }, /A name is 1 to 60 characters/], [{ label: "x".repeat(61) }, /A name/],
                               [{ label: "ok", expires: "7" }, /Choose when the token expires/],
                               [{ label: "ok", expires: "constructor" }, /Choose when/]]) {
    const { r } = await makeCi(ana, fields);
    assert.equal(r.status, 400, JSON.stringify(fields));
    assert.match(r.text, why);
  }
  assert.equal(count(e, "machines"), 0);

  const made = await makeCi(ana, { label: "deploy <prod>", expires: "30" });
  assert.equal(made.r.status, 200, made.r.text);
  const token = made.token;
  assert.ok(token, "the token is on the page");
  assert.match(`Bearer ${token}`, FEED_TOKEN);
  assert.equal(token.length, "rw_c_".length + 43);
  assert.equal(made.r.headers.get("cache-control"), "no-store");
  assert.doesNotMatch(made.r.text, /<script|\son[a-z]+=/i);
  assert.match(made.r.text, /only time it is shown/);
  assert.ok(made.r.text.includes("deploy &lt;prod&gt;"));
  assert.match(made.r.text, /RANWHAT_TOKEN/);
  assert.equal(made.r.text.split(token).length, 2, "once on the page");

  /* Kept as its hash, a CI machine of the organisation, made by Ana. */
  const machine = one(e, "SELECT * FROM machines");
  assert.deepEqual([machine.hash, machine.org_id, machine.user_id, machine.kind, machine.label, machine.last_used_day],
                   [sha(token), acme, userId(e, "ana@example.com"), "ci", "deploy <prod>", null]);
  const row = one(e, "SELECT * FROM tokens WHERE hash = ?", sha(token));
  assert.deepEqual([row.note, row.revoked_at, row.expires_at], [`ci ${machine.id}`, null, row.created_at + 30 * DAY]);
  assert.ok(!dump(e).includes(token) && !dump(e).includes(token.slice(5)), "no token in the database");
  assert.equal(rows(e, "SELECT subject FROM auth_events WHERE event = 'ci_token_created'")[0].subject, machine.id);

  /* Sent again (a reload of that page), the same form makes nothing more and shows nothing. */
  const again = await ana.post("/tokens/ci", made.sent);
  assert.deepEqual([again.status, again.location], [303, "/"]);
  assert.equal(count(e, "machines"), 1);
  const home = await ana.get("/");
  assert.ok(!home.text.includes(token) && !home.text.includes(sha(token)), "never shown again");
  assert.match(home.text, /CI token made, with a fresh code/);

  /* The feed takes it, on the organisation's plan; whoami names the organisation, never who made it. */
  assert.equal((await feed(e, token)).status, 200);
  const me = await whoami(e, token);
  assert.deepEqual(me.json, { kind: "ci", email: null, org: "Personal", role: null, plan: "plus",
                              machine: { label: "deploy <prod>", created_at: machine.created_at } });
  assert.ok(!me.text.includes("ana@example.com"));
  /* logout leaves it alone: a pipeline's token is not a terminal's. */
  assert.deepEqual((await call(e, "/v1/logout", { token })).json, { revoked: false, shared: true });

  /* A Free organisation's CI token is told where Plus is. */
  run(e, "DELETE FROM grants");
  assert.deepEqual((await feed(e, token)).json, { error: "plus_required", upgrade: "https://account.ranwhat.com/" });
  grant(e, acme, "plus");

  /* Past its expiry the feed refuses it; the cron does not revoke it, and the list says it expired. */
  later(30 * DAY + 1);
  assert.deepEqual((await feed(e, token)).json, { error: "That token was not accepted." });
  await cron(e);
  assert.equal(revoked(e, token), null);
  const b = new Browser(e, { ip: "198.51.100.8" });
  await signIn(b, s);
  const item = listed((await b.get("/")).text)[machine.id];
  assert.match(item, /<span class="tag">CI, expired<\/span>/);
  assert.ok(item.includes(`Expired ${isoDay(row.created_at + 30 * DAY)}.`));
  assert.match(item, /<button type="submit">Remove<\/button>/);
});

test("an organisation holds at most fifty CI tokens at once; revoked and expired ones make room", async () => {
  const s = services();
  const e = env();
  const ana = new Browser(e);
  await signIn(ana, s);
  const acme = orgOf(e, "ana@example.com");
  grant(e, acme, "plus");
  assert.equal((await ana.get("/")).status, 200);   // the feed's tables, made as the page reads the plan
  const t = unix();
  for (let i = 0; i < machines.MAX_CI - 1; i++) {
    const hash = sha(madeToken("rw_c_"));
    run(e, "INSERT INTO tokens (hash, note, created_at) VALUES (?, 'ci', ?)", hash, t);
    run(e, "INSERT INTO machines (id, hash, org_id, user_id, kind, label, created_at) VALUES (?, ?, ?, NULL, 'ci', ?, ?)",
      randomUUID(), hash, acme, `ci ${i}`, t);
  }
  assert.equal((await makeCi(ana, { label: "the fiftieth" })).r.status, 200);
  let html = (await ana.get("/")).text;
  assert.doesNotMatch(html, /action="\/tokens\/ci"/);
  assert.match(section(html), /Personal holds 50 CI tokens, the most it can/);
  const r = await forgedCi(e, ana);
  assert.equal(r.status, 400);
  assert.match(r.text, /the most it can/);
  assert.equal(rows(e, "SELECT 1 FROM machines WHERE kind = 'ci'").length, 50);

  run(e, "UPDATE tokens SET revoked_at = ? WHERE hash = (SELECT hash FROM machines WHERE label = 'ci 0')", t);
  run(e, "UPDATE tokens SET expires_at = ? WHERE hash = (SELECT hash FROM machines WHERE label = 'ci 1')", t);
  html = (await ana.get("/")).text;
  assert.match(html, /action="\/tokens\/ci"/);
  assert.equal((await makeCi(ana, { label: "room again" })).r.status, 200);
  assert.equal((await makeCi(ana, { label: "and again" })).r.status, 200);
  assert.equal((await forgedCi(e, ana)).status, 400);
  assert.equal(await machines.liveCi(e, acme), 50);
});

/* ---------- last use and the cron ---------- */

test("last use is written at most once a day for terminals and CI tokens, never for a refused token", async () => {
  const s = services();
  const e = env();
  const ana = new Browser(e);
  await signIn(ana, s);
  const acme = orgOf(e, "ana@example.com");
  grant(e, acme, "plus");
  const { token } = await makeCi(ana);
  const terminal = await linkTerminal(e, ana);
  const writes = [];
  const prepare = e.LIST.prepare;
  e.LIST.prepare = (sql) => {
    if (/UPDATE machines SET last_used_day/.test(sql)) writes.push(sql);
    return prepare(sql);
  };
  for (let i = 0; i < 3; i++) {
    assert.equal((await feed(e, token)).status, 200);
    assert.equal((await feed(e, terminal.token)).status, 200);
  }
  assert.equal(writes.length, 2, "one each");
  const day = dayOf(unix());
  assert.deepEqual(rows(e, "SELECT last_used_day FROM machines ORDER BY kind").map((x) => x.last_used_day), [day, day]);
  later(DAY);
  await feed(e, token);
  await feed(e, token);
  assert.equal(writes.length, 3);
  assert.equal(one(e, "SELECT last_used_day FROM machines WHERE kind = 'ci'").last_used_day, day + DAY);

  /* Revoked, it is refused and not noted. */
  run(e, "UPDATE tokens SET revoked_at = ? WHERE hash = ?", unix(), sha(terminal.token));
  later(DAY);
  assert.equal((await feed(e, terminal.token)).status, 403);
  assert.equal(writes.length, 3);
  assert.equal(one(e, "SELECT last_used_day FROM machines WHERE kind = 'device'").last_used_day, day);
});

test("the cron revokes a terminal's token after 90 days unused; CI and subscription tokens stay", async () => {
  const s = services();
  const e = env();
  const ana = new Browser(e);
  await signIn(ana, s);
  const acme = orgOf(e, "ana@example.com");
  grant(e, acme, "plus");
  const busy = await linkTerminal(e, ana);
  const idle = await linkTerminal(e, ana);
  const { token: ci } = await makeCi(ana, { label: "quarterly" });
  const old = legacy(e, acme);
  assert.equal((await feed(e, busy.token)).status, 200);

  const sweepTo = async (days) => {
    later(days * DAY);
    await cron(e);
  };
  /* Used on day 0 and day 60; the idle one never after it was linked. */
  await sweepTo(60);
  assert.equal((await feed(e, busy.token)).status, 200);
  await sweepTo(30);   // day 90: not yet 90 whole days for either
  for (const t of [busy.token, idle.token, ci, old.token]) assert.equal(revoked(e, t), null);
  await sweepTo(1);    // day 91: the idle terminal has gone 90 whole days unused
  assert.ok(revoked(e, idle.token));
  assert.equal((await whoami(e, idle.token)).status, 403);
  for (const t of [busy.token, ci, old.token]) assert.equal(revoked(e, t), null);
  const idleEvents = rows(e, "SELECT org_id, user_id, subject FROM auth_events WHERE event = 'machine_idle_revoked'");
  assert.deepEqual(idleEvents, [{ org_id: acme, user_id: userId(e, "ana@example.com"), subject: idle.id }]);
  await cron(e);
  assert.equal(rows(e, "SELECT 1 FROM auth_events WHERE event = 'machine_idle_revoked'").length, 1, "once");

  /* Switched off again, the cron still revokes: the busy one, 90 days after day 60. */
  e.ACCOUNTS_ON = "";
  await sweepTo(60);   // day 151
  assert.ok(revoked(e, busy.token));
  for (const t of [ci, old.token]) assert.equal(revoked(e, t), null, "CI and subscription tokens are never idle-revoked");
  assert.equal((await feed(e, ci)).status, 200);
  assert.equal((await feed(e, old.token)).status, 200);

  e.ACCOUNTS_ON = "1";
  const b = new Browser(e, { ip: "198.51.100.9" });
  await signIn(b, s);
  const home = await b.get("/");
  assert.deepEqual(Object.keys(listed(home.text)).length, 2);
  assert.match(home.text, /Terminal revoked after 90 days unused/);
});

test("nothing logged carries a CI token", async () => {
  const lines = [];
  const real = console.log;
  console.log = (...a) => lines.push(a.join(" "));
  let secrets = [];
  try {
    const s = services();
    const e = env();
    const ana = new Browser(e);
    await signIn(ana, s);
    grant(e, orgOf(e, "ana@example.com"), "plus");
    const { token } = await makeCi(ana);
    secrets = [token, sha(token)];
    await feed(e, token);
    await whoami(e, token);
    await cron(e);
  } finally {
    console.log = real;
  }
  for (const line of lines) {
    for (const secret of secrets) assert.ok(!line.includes(secret));
    assert.doesNotMatch(line, /rw_|@/);
  }
});
