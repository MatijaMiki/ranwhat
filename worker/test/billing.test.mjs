/* Paying for Plus from an account (billing.js, with stripe.js's
 * orgCheckout(), portalSession() and the webhook's link to the
 * organisation): the upgrade, the webhook that links what was bought,
 * the billing panel and Manage billing, and who may do each. The Worker's
 * own fetch handler runs over a real SQLite database (node:sqlite, which
 * is what D1 runs), with Stripe, Resend and Turnstile answered by
 * stand-ins that keep what they were asked: no call leaves the machine.
 * Webhook events are signed the way Stripe signs them.
 *
 *     node --test --test-timeout=60000 worker/test/billing.test.mjs
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash, createHmac } from "node:crypto";
import { d1 } from "./stand-ins.mjs";

const worker = (await import("../src/index.js")).default;
const { formToken, FRESH_FOR } = await import("../src/session.js");
const { UPGRADES_PER_HOUR } = await import("../src/billing.js");

const ORIGIN = "https://account.ranwhat.com";
const SITE = "https://ranwhat.com";
const FEED = "https://feed.ranwhat.com";
/* Split, so that nothing shaped like a key or a token sits in the source. */
const STRIPE_KEY = "sk_" + "test_" + "billingkey";
const WHSEC = "whsec_" + "test_" + "billing_signing_secret";
const LIST_SECRET = "a-list-test-secret-that-is-long-enough-1234567890";
const ACCOUNT_SECRET = "an-account-test-secret-that-is-long-enough-0123456789";
const SESSION = "__Host-rw_session";
const FROM_PAGE = { "sec-fetch-site": "same-origin", origin: ORIGIN };
const PLUS = { product: "ranwhat-plus" };
const MINUTE = 60, HOUR = 3600, DAY = 24 * HOUR;
const ctx = { waitUntil() {} };

/* The clock, which a test moves forward when it needs time to pass. */
const realNow = Date.now;
let skew = 0;
Date.now = () => realNow() + skew * 1000;
const later = (seconds) => { skew += seconds; };
const unix = () => Math.floor(Date.now() / 1000);
const isoDay = (t) => new Date(t * 1000).toISOString().slice(0, 10);

const sha = (text) => createHash("sha256").update(text).digest("hex");

/* ---------- stand-ins ---------- */

/* Stripe as far as stripe.js uses it, Resend's /emails and Turnstile. */
function services() {
  const s = {
    prices: {
      ranwhat_plus_monthly: { id: "price_monthly1", lookup_key: "ranwhat_plus_monthly", active: true },
      ranwhat_plus_annual: { id: "price_annual1", lookup_key: "ranwhat_plus_annual", active: true },
    },
    portals: [
      { id: "bpc_other", metadata: {} },
      { id: "bpc_plus", metadata: PLUS, login_page: { enabled: true, url: "https://billing.stripe.com/p/login/plus" } },
    ],
    sessions: new Map(), subscriptions: new Map(), emails: [], calls: [],
    fail: {},               // "METHOD /path" prefix -> [status, body]
    refuseCustomer: false,  // Checkout turns down a customer, as a deleted one would be
  };
  const reply = (status, body) => new Response(JSON.stringify(body), { status });
  const missing = () => reply(404, { error: { type: "invalid_request_error", code: "resource_missing" } });
  const under = (form, prefix) => Object.fromEntries(Object.entries(form)
    .filter(([k]) => k.startsWith(`${prefix}[`) && k.indexOf("[", prefix.length + 1) === -1)
    .map(([k, v]) => [k.slice(prefix.length + 1, -1), v]));
  globalThis.fetch = async (url, init = {}) => {
    const u = new URL(String(url));
    const method = init.method || "GET";
    const key = `${method} ${u.pathname}`;
    if (u.hostname === "challenges.cloudflare.com") {
      const m = /^solved:([a-z]+)$/.exec(JSON.parse(init.body).response);
      return reply(200, m ? { success: true, hostname: "account.ranwhat.com", action: m[1] } : { success: false });
    }
    for (const [prefix, [status, body]] of Object.entries(s.fail)) {
      if (key.startsWith(prefix)) return reply(status, body);
    }
    if (u.hostname === "api.resend.com") {
      assert.equal(key, "POST /emails");
      s.emails.push(JSON.parse(init.body));
      return reply(200, { id: `e${s.emails.length}` });
    }
    assert.equal(u.hostname, "api.stripe.com");
    assert.equal(init.headers.authorization, `Bearer ${STRIPE_KEY}`);
    const form = Object.fromEntries(method === "GET" ? u.searchParams : new URLSearchParams(init.body || ""));
    s.calls.push({ key, form });

    if (key === "GET /v1/prices") {
      return reply(200, { data: Object.values(s.prices).filter((p) => p.lookup_key === form["lookup_keys[0]"] && p.active) });
    }
    if (key === "POST /v1/checkout/sessions") {
      if (s.refuseCustomer && form.customer) {
        return reply(400, { error: { type: "invalid_request_error", code: "resource_missing", param: "customer" } });
      }
      const id = `cs_test_${"b".repeat(20)}${s.sessions.size}`;
      const session = { id, object: "checkout.session", url: `https://checkout.stripe.com/c/pay/${id}`,
        mode: form.mode, status: "open", payment_status: "unpaid", created: unix(),
        metadata: under(form, "metadata"), client_reference_id: form.client_reference_id ?? null,
        customer: form.customer ?? null, subscription: null, customer_details: null,
        price: form["line_items[0][price]"], subscription_metadata: under(form, "subscription_data[metadata]") };
      s.sessions.set(id, session);
      return reply(200, session);
    }
    let m = u.pathname.match(/^\/v1\/checkout\/sessions\/([^/]+)$/);
    if (method === "GET" && m) return s.sessions.has(m[1]) ? reply(200, s.sessions.get(m[1])) : missing();
    m = u.pathname.match(/^\/v1\/subscriptions\/([^/]+)$/);
    if (method === "GET" && m) return s.subscriptions.has(m[1]) ? reply(200, s.subscriptions.get(m[1])) : missing();
    if (key === "GET /v1/billing_portal/configurations") return reply(200, { data: s.portals });
    if (key === "POST /v1/billing_portal/sessions") {
      const n = s.calls.filter((c) => c.key === key).length;
      return reply(200, { id: `bps_test${n}`, url: `https://billing.stripe.com/p/session/test_${n}`,
        customer: form.customer, return_url: form.return_url });
    }
    return missing();
  };
  return s;
}

/* What Stripe does when someone pays for a session: a subscription with
   the session's subscription metadata, on the session's customer or a new
   one, and the session complete. */
function pay(s, sessionId, { email = "payer@example.com", status = "active" } = {}) {
  const session = s.sessions.get(sessionId);
  const n = s.subscriptions.size + 1;
  const sub = {
    id: `sub_test${n}billing`, object: "subscription", customer: session.customer || `cus_test${n}billing`,
    status, metadata: { ...session.subscription_metadata }, cancel_at_period_end: false, cancel_at: null, ended_at: null,
    items: { data: [{ current_period_end: unix() + 30 * DAY,
      price: { recurring: { interval: session.price === "price_annual1" ? "year" : "month" } } }] },
  };
  s.subscriptions.set(sub.id, sub);
  Object.assign(session, { status: "complete", payment_status: "paid", subscription: sub.id,
    customer_details: { email } });
  return sub;
}

const env = (extra = {}) => ({
  LIST: d1(), RESEND_API_KEY: "re_" + "test_key", LIST_SECRET, ACCOUNT_SECRET,
  TURNSTILE_SECRET: "turnstile-" + "test", ACCOUNTS_ON: "1",
  STRIPE_SECRET_KEY: STRIPE_KEY, STRIPE_WEBHOOK_SECRET: WHSEC, ...extra,
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
  const form = await b.get(`/signin${next === "/" ? "" : `?next=${next}`}`);
  const asked = await b.post("/signin", { form: tokenFor(form.text, "/signin"), email, next,
    "cf-turnstile-response": "solved:signin" });
  assert.equal(asked.status, 303, asked.text);
  const done = await typeCode(b, codeIn(s.emails.at(-1)));
  assert.equal(done.status, 303, done.text);
  assert.ok(b.jar.has(SESSION));
  return done;
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
const links = (e) => rows(e, "SELECT subscription, org_id, how FROM org_subscriptions ORDER BY subscription");
const eventsOf = (e, org) => rows(e, "SELECT user_id, event, subject FROM auth_events WHERE org_id = ? ORDER BY id", org)
  .filter((r) => ["upgrade_started", "billing_opened", "plus_linked"].includes(r.event));
const checkouts = (s) => s.calls.filter((c) => c.key === "POST /v1/checkout/sessions");
const portals = (s) => s.calls.filter((c) => c.key === "POST /v1/billing_portal/sessions");

/* `email` joins `orgId` as `role`, and their session looks at it. */
function join(e, email, orgId, role = "member") {
  const user = userId(e, email);
  run(e, "INSERT INTO memberships (org_id, user_id, role, created_at) VALUES (?, ?, ?, ?)", orgId, user, role, unix());
  run(e, "UPDATE sessions SET org_id = ? WHERE user_id = ?", orgId, user);
}

function grant(e, orgId, which = "plus") {
  run(e, "INSERT INTO grants (org_id, plan, starts_at, until, note, created_at) VALUES (?, ?, ?, NULL, 'test', ?)",
    orgId, which, unix() - 60, unix());
}

/* ---------- the webhook ---------- */

function deliver(e, event) {
  const body = JSON.stringify(event);
  const at = unix();
  const v1 = createHmac("sha256", WHSEC).update(`${at}.${body}`).digest("hex");
  return worker.fetch(new Request(`${SITE}/api/stripe`, { method: "POST",
    headers: { "stripe-signature": `t=${at},v1=${v1}` }, body }), e, ctx);
}

const completedEvent = (s, id) => ({
  id: `evt_${id}`, type: "checkout.session.completed", data: { object: { ...s.sessions.get(id) } },
});

const subEvent = (sub, type = "customer.subscription.updated") => ({
  id: `evt_${sub.id}_${type}`, type, data: { object: { ...sub, metadata: { ...sub.metadata } } },
});

const site = (e, path, init = {}) => worker.fetch(new Request(`${SITE}${path}`, init), e, ctx);
const feed = (e, token) => worker.fetch(new Request(`${FEED}/v1/catalogue`,
  { headers: { authorization: `Bearer ${token}` } }), e, ctx).then((r) => r.status);

/* ---------- the upgrade ---------- */

/* The owner's upgrade, from the page the locked panels link to: the
   Checkout session it opened. */
async function upgrade(b, s, plan = "monthly") {
  const page = await b.get("/upgrade");
  assert.equal(page.status, 200, page.text);
  const res = await b.post("/upgrade", { form: tokenFor(page.text, "/upgrade"), plan });
  assert.equal(res.status, 303, res.text);
  assert.match(res.location, /^https:\/\/checkout\.stripe\.com\/c\/pay\/cs_test_/);
  return res.location.split("/").pop();
}

/* Upgraded and paid, with both of Stripe's events delivered. */
async function upgraded(b, s, e, plan = "yearly") {
  const id = await upgrade(b, s, plan);
  const sub = pay(s, id);
  assert.equal((await deliver(e, subEvent(sub, "customer.subscription.created"))).status, 200);
  assert.equal((await deliver(e, completedEvent(s, id))).status, 200);
  return { id, sub };
}

test("the locked panels lead to the upgrade, which signs in first and comes back", async () => {
  const s = services();
  const e = env();
  const ana = new Browser(e);
  const away = await ana.get("/upgrade");
  assert.equal(away.status, 303);
  assert.equal(away.location, "/signin?next=/upgrade");
  const done = await signIn(ana, s, "ana@example.com", "/upgrade");
  assert.equal(done.location, "/upgrade");

  const home = (await ana.get("/")).text;
  const plus = home.match(/<section class="panel locked" id="plus">([\s\S]*?)<\/section>/)[1];
  assert.match(plus, /<a href="\/upgrade">Upgrade to Plus<\/a>/);
  assert.match(home, /<div class="panel locked" id="ci-tokens"[\s\S]*?<a href="\/upgrade">Upgrade to Plus<\/a>/);
  assert.doesNotMatch(home, /ranwhat\.com\/pricing">Upgrade/);
  const billing = home.match(/<section class="panel" id="billing">([\s\S]*?)<\/section>/)[1];
  assert.match(billing, /Personal is on Free\. Plus is €12 a month or €120 a year, one price for the organisation\./);
  assert.match(billing, /<a class="button" href="\/upgrade">Upgrade to Plus<\/a>/);
  assert.doesNotMatch(billing, /action="\/billing"/);
  assert.equal(s.calls.length, 0, "drawing a Free organisation's page asks Stripe nothing");

  /* Switched off, neither route is there. */
  const off = new Browser({ ...e, ACCOUNTS_ON: "" });
  assert.equal((await off.get("/upgrade")).status, 404);
  assert.equal((await off.post("/billing", {})).status, 404);
});

test("an owner's upgrade is a Checkout bound to the organisation, at the pricing page's prices and tax", async () => {
  const s = services();
  const e = env();
  const ana = new Browser(e);
  await signIn(ana, s);
  const org = orgOf(e, "ana@example.com");

  const page = await ana.get("/upgrade");
  assert.match(page.text, /Catalogue feed and CI tokens now/);
  assert.match(page.text, /<button type="submit">Monthly, €12 a month<\/button>/);
  assert.match(page.text, /<button type="submit">Yearly, €120 a year<\/button>/);
  assert.match(page.headers.get("content-security-policy"), /form-action 'self' https:\/\/checkout\.stripe\.com; /);
  assert.doesNotMatch(page.text, /<script/);

  for (const [plan, price] of [["monthly", "price_monthly1"], ["yearly", "price_annual1"]]) {
    await upgrade(ana, s, plan);
    const { form } = checkouts(s).at(-1);
    assert.equal(form["line_items[0][price]"], price);
    assert.equal(form["line_items[0][quantity]"], "1");
    assert.equal(form.mode, "subscription");
    assert.equal(form.client_reference_id, org);
    assert.equal(form["metadata[product]"], "ranwhat-plus");
    assert.equal(form["metadata[org]"], org);
    assert.equal(form["subscription_data[metadata][product]"], "ranwhat-plus");
    assert.equal(form["subscription_data[metadata][org]"], org);
    assert.equal(form.success_url, "https://account.ranwhat.com/?upgraded=1");
    assert.equal(form.cancel_url, "https://account.ranwhat.com/upgrade");
    assert.equal(form.customer, undefined, "a first checkout has no customer to reuse");
    // The pricing page's own settings, as STRIPE_TAX says.
    assert.match(form["custom_text[submit][message]"], /14 days/);
    assert.equal(form["tax_id_collection[enabled]"], "true");
    assert.equal(form["billing_address_collection"], "required");
  }
  const lookups = s.calls.filter((c) => c.key === "GET /v1/prices").map((c) => c.form["lookup_keys[0]"]);
  assert.deepEqual(lookups, ["ranwhat_plus_monthly", "ranwhat_plus_annual"]);
  assert.deepEqual(eventsOf(e, org).map((r) => [r.event, r.subject, r.user_id]),
    [["upgrade_started", "monthly", userId(e, "ana@example.com")], ["upgrade_started", "yearly", userId(e, "ana@example.com")]]);

  /* A plan that is not one of the two opens nothing. */
  const before = s.calls.length;
  for (const plan of ["", "annual", "lifetime", "__proto__"]) {
    const r = await ana.post("/upgrade", { form: tokenFor(page.text, "/upgrade"), plan });
    assert.equal(r.status, 400, plan);
  }
  assert.equal(s.calls.length, before);

  /* Managed Payments: only what Stripe's guide shows, and the organisation. */
  const m = env({ STRIPE_TAX: "managed" });
  const bo = new Browser(m, { ip: "203.0.113.20" });
  await signIn(bo, s, "bo@example.com");
  await upgrade(bo, s, "monthly");
  assert.deepEqual(Object.keys(checkouts(s).at(-1).form).sort(), [
    "cancel_url", "client_reference_id", "line_items[0][price]", "line_items[0][quantity]", "managed_payments[enabled]",
    "metadata[org]", "metadata[product]", "mode", "subscription_data[metadata][org]",
    "subscription_data[metadata][product]", "success_url",
  ]);

  /* Stripe down: nothing charged, said so, and the page offers it again. */
  s.fail["POST /v1/checkout"] = [500, { error: { type: "api_error" } }];
  const down = await ana.post("/upgrade", { form: tokenFor(page.text, "/upgrade"), plan: "monthly" });
  assert.equal(down.status, 502);
  assert.match(down.text, /Checkout did not open\. Nothing was charged/);
  assert.match(down.text, /action="\/upgrade"/);
});

test("a member cannot upgrade or open billing; an admin can", async () => {
  const s = services();
  const e = env();
  const ana = new Browser(e);
  await signIn(ana, s);
  const org = orgOf(e, "ana@example.com");
  const bo = new Browser(e, { ip: "203.0.113.30" });
  await signIn(bo, s, "bo@example.com");
  join(e, "bo@example.com", org, "member");

  const page = await bo.get("/upgrade");
  assert.equal(page.status, 200);
  assert.match(page.text, /Only an owner or an admin of Personal can upgrade it\./);
  assert.doesNotMatch(page.text, /action="\/upgrade"/);
  assert.doesNotMatch(page.headers.get("content-security-policy"), /stripe/);
  assert.match((await bo.get("/")).text, /Personal is on Free\. An owner or an admin of it can upgrade it to Plus\./);

  /* A form made for the member's own session, as a forged one would be: refused before Stripe is asked. */
  const forged = await formToken(e, bo.session, "upgrade");
  const r = await bo.post("/upgrade", { form: forged, plan: "monthly" });
  assert.equal(r.status, 403);
  assert.match(r.text, /Only an owner or an admin/);
  assert.equal(s.calls.length, 0);
  assert.deepEqual(eventsOf(e, org), []);

  /* An admin of the same organisation can. */
  const carl = new Browser(e, { ip: "203.0.113.31" });
  await signIn(carl, s, "carl@example.com");
  join(e, "carl@example.com", org, "admin");
  const id = await upgrade(carl, s, "monthly");
  assert.equal(checkouts(s).at(-1).form["metadata[org]"], org);
  const sub = pay(s, id);
  await deliver(e, completedEvent(s, id));
  assert.deepEqual(links(e), [{ subscription: sub.id, org_id: org, how: "checkout" }]);

  /* Plus now: the member sees the plan and status, but no Manage billing, and is refused it. */
  const home = await bo.get("/");
  assert.match(home.text, /<dd id="plan">Plus<\/dd>/);
  assert.match(home.text, /An owner or an admin of Personal manages its billing\./);
  assert.doesNotMatch(home.text, /action="\/billing"/);
  assert.doesNotMatch(home.headers.get("content-security-policy"), /billing\.stripe\.com/);
  const tried = await bo.post("/billing", { form: await formToken(e, bo.session, "billing"), subscription: sub.id });
  assert.equal(tried.status, 403);
  assert.match(tried.text, /Only an owner or an admin of Personal can open its billing\./);
  assert.equal(portals(s).length, 0);
});

test("upgrading needs a fresh code, and an organisation on Plus or Team is not sold Plus again", async () => {
  const s = services();
  const e = env();
  const ana = new Browser(e);
  await signIn(ana, s);
  const org = orgOf(e, "ana@example.com");
  const kept = tokenFor((await ana.get("/upgrade")).text, "/upgrade");

  later(FRESH_FOR + 1);
  const stale = await ana.get("/upgrade");
  assert.match(stale.text, /Opening checkout needs an emailed code typed in the last 15 minutes/);
  assert.doesNotMatch(stale.text, /action="\/upgrade"/);
  assert.match(stale.text, /<input type="hidden" name="next" value="\/upgrade">/);
  assert.doesNotMatch(stale.headers.get("content-security-policy"), /stripe/);
  const r = await ana.post("/upgrade", { form: kept, plan: "monthly" });
  assert.equal(r.status, 403);
  assert.match(r.text, /so it did not open/);
  assert.equal(s.calls.length, 0);

  /* The fresh code brings the person back to the upgrade. */
  const asked = await ana.post("/stepup", { form: tokenFor(stale.text, "/stepup"), next: "/upgrade" });
  assert.equal(asked.location, "/signin/code");
  assert.equal((await typeCode(ana, codeIn(s.emails.at(-1)))).location, "/upgrade");
  /* A fresh code is a new session, so the forms are the new page's. */
  const form = tokenFor((await ana.get("/upgrade")).text, "/upgrade");
  const { sub } = await upgraded(ana, s, e);

  /* On Plus: nothing more to buy, before anything is asked of Stripe. */
  const calls = checkouts(s).length;
  const page = await ana.get("/upgrade");
  assert.match(page.text, /Personal is on Plus already, so there is nothing to buy\./);
  assert.doesNotMatch(page.text, /action="\/upgrade"/);
  const again = await ana.post("/upgrade", { form, plan: "yearly" });
  assert.equal(again.status, 409);
  assert.equal(checkouts(s).length, calls);

  /* On Team, by a grant, likewise, with the subscription gone. */
  sub.status = "canceled";
  await deliver(e, subEvent(sub, "customer.subscription.deleted"));
  grant(e, org, "team");
  assert.match((await ana.get("/upgrade")).text, /Personal is on Team already/);
  assert.equal((await ana.post("/upgrade", { form, plan: "monthly" })).status, 409);
  assert.equal(checkouts(s).length, calls);
});

test("an organisation opens only so many checkouts an hour", async () => {
  const s = services();
  const e = env();
  const ana = new Browser(e);
  await signIn(ana, s);
  for (let i = 0; i < UPGRADES_PER_HOUR; i++) await upgrade(ana, s);
  const token = tokenFor((await ana.get("/upgrade")).text, "/upgrade");
  const r = await ana.post("/upgrade", { form: token, plan: "monthly" });
  assert.equal(r.status, 429);
  assert.equal(checkouts(s).length, UPGRADES_PER_HOUR);
});

/* ---------- the webhook ---------- */

test("the webhook links the subscription once, in any order and however often Stripe sends it", async () => {
  const s = services();
  const e = env();
  const ana = new Browser(e);
  await signIn(ana, s);
  const org = orgOf(e, "ana@example.com");
  const mails = s.emails.length;
  const id = await upgrade(ana, s, "yearly");
  const sub = pay(s, id);
  assert.match((await ana.get("/?upgraded=1")).text, /<p data-upgraded>Thank you\. Stripe is confirming the payment/);

  /* subscription.created first, before the checkout's own event. */
  assert.equal((await deliver(e, subEvent(sub, "customer.subscription.created"))).status, 200);
  assert.deepEqual(links(e), [{ subscription: sub.id, org_id: org, how: "checkout" }]);
  assert.equal(one(e, "SELECT customer FROM orgs WHERE id = ?", org).customer, sub.customer);
  assert.equal(s.emails.length, mails, "the subscription's own event mails nothing");

  assert.equal((await deliver(e, completedEvent(s, id))).status, 200);
  /* Replayed, as Stripe does when it is unsure it was heard. */
  for (let i = 0; i < 2; i++) {
    assert.equal((await deliver(e, completedEvent(s, id))).status, 200);
    assert.equal((await deliver(e, subEvent(sub, "customer.subscription.created"))).status, 200);
    assert.equal((await deliver(e, subEvent(sub))).status, 200);
  }
  assert.deepEqual(links(e), [{ subscription: sub.id, org_id: org, how: "checkout" }]);
  assert.deepEqual(eventsOf(e, org).filter((r) => r.event === "plus_linked"),
    [{ user_id: null, event: "plus_linked", subject: sub.id }]);

  /* One email, saying Plus is on and to run ranwhat login: no token in it, and none made. */
  const sent = s.emails.slice(mails);
  assert.equal(sent.length, 1);
  assert.deepEqual(sent[0].to, ["payer@example.com"]);
  assert.equal(sent[0].subject, "ranwhat Plus is on for Personal");
  assert.match(sent[0].text, /^ {2}uvx ranwhat login$/m);
  assert.match(sent[0].html, /uvx ranwhat login/);
  assert.doesNotMatch(sent[0].text + sent[0].html, /rw_|RANWHAT_TOKEN/);
  assert.equal(count(e, "tokens"), 0);
  assert.equal(count(e, "token_subscriptions"), 0);

  /* The welcome page shows no token for it either. */
  const welcome = await site(e, `/api/welcome?session_id=${id}`);
  assert.equal(welcome.status, 200);
  const shown = await welcome.text();
  assert.match(shown, /no shared token to show/);
  assert.doesNotMatch(shown, /rw_/);
  assert.equal(count(e, "tokens"), 0);

  /* The address Stripe took is in no table. */
  assert.ok(!dump(e).includes("payer@example.com"));

  /* The account page: Plus, yearly, active, and the day it renews. */
  const home = await ana.get("/?upgraded=1");
  assert.match(home.text, /<dd id="plan">Plus<\/dd>/);
  const billing = home.text.match(/<section class="panel" id="billing">([\s\S]*?)<\/section>/)[1];
  assert.match(billing, new RegExp(`<div data-subscription="${sub.id}">`));
  assert.match(billing, /<dt>Plan<\/dt><dd>Plus, yearly<\/dd>/);
  assert.match(billing, /<dd data-status="active">Active<\/dd>/);
  assert.match(billing, new RegExp(`<dt>Renews</dt><dd data-renews>${isoDay(sub.items.data[0].current_period_end)}</dd>`));
  assert.match(billing, /<p data-upgraded>Plus is on for Personal\./);
  assert.doesNotMatch(home.text, /Upgrade to Plus/);
});

test("an org mismatch links nothing to the wrong organisation, mails nothing, and never moves a link", async () => {
  const s = services();
  const e = env();
  const ana = new Browser(e);
  await signIn(ana, s);
  const acme = orgOf(e, "ana@example.com");
  const bo = new Browser(e, { ip: "203.0.113.40" });
  await signIn(bo, s, "bo@example.com");
  const other = orgOf(e, "bo@example.com");
  const lines = [];
  const real = console.log;
  console.log = (...a) => lines.push(a.join(" "));
  try {
    /* The session names one organisation as its reference and another in its metadata. */
    const mails = s.emails.length;
    const id = await upgrade(ana, s);
    const sub = pay(s, id);
    s.sessions.get(id).client_reference_id = other;
    assert.equal((await deliver(e, completedEvent(s, id))).status, 200);
    assert.equal(s.emails.length, mails, "no 'Plus is on' email on a mismatch");
    assert.ok(lines.includes("stripe checkout: org mismatch"));
    assert.deepEqual(links(e).filter((l) => l.org_id === other), []);
    assert.equal(count(e, "tokens"), 0, "and no token in its place");
    /* What the subscription itself says, as Stripe holds it, is what it is linked to. */
    assert.deepEqual(links(e), [{ subscription: sub.id, org_id: acme, how: "checkout" }]);

    /* Edited in Stripe to name the other organisation: the link stays where it was. */
    sub.metadata.org = other;
    assert.equal((await deliver(e, subEvent(sub))).status, 200);
    assert.deepEqual(links(e), [{ subscription: sub.id, org_id: acme, how: "checkout" }]);
    assert.match((await bo.get("/")).text, /<dd id="plan">Free<\/dd>/);
    assert.equal(one(e, "SELECT customer FROM orgs WHERE id = ?", other).customer, null);

    /* An organisation that is not there gets nothing, and neither does anyone else. */
    const id2 = await upgrade(bo, s);
    const sub2 = pay(s, id2);
    const ghost = "00000000-0000-4000-8000-000000000000";
    sub2.metadata.org = ghost;
    Object.assign(s.sessions.get(id2), { client_reference_id: ghost, metadata: { ...PLUS, org: ghost } });
    assert.equal((await deliver(e, subEvent(sub2, "customer.subscription.created"))).status, 200);
    assert.equal((await deliver(e, completedEvent(s, id2))).status, 200);
    assert.deepEqual(links(e).map((l) => l.subscription), [sub.id]);
    assert.equal(s.emails.length, mails);
    assert.equal(count(e, "tokens"), 0);
  } finally {
    console.log = real;
  }
  for (const line of lines) assert.doesNotMatch(line, /@|rw_|sk_|cus_|sub_/);
});

/* ---------- Manage billing ---------- */

test("Manage billing opens the portal for the organisation's own customer, with a fresh code", async () => {
  const s = services();
  const e = env();
  const ana = new Browser(e);
  await signIn(ana, s);
  const org = orgOf(e, "ana@example.com");
  const { sub } = await upgraded(ana, s, e);

  const home = await ana.get("/");
  assert.match(home.headers.get("content-security-policy"), /form-action 'self' https:\/\/billing\.stripe\.com; /);
  assert.doesNotMatch(home.text, /<script/);
  const r = await ana.post("/billing", { form: tokenFor(home.text, "/billing"), subscription: sub.id });
  assert.equal(r.status, 303, r.text);
  assert.match(r.location, /^https:\/\/billing\.stripe\.com\/p\/session\/test_/);
  assert.deepEqual(portals(s).at(-1).form,
    { customer: sub.customer, return_url: "https://account.ranwhat.com/", configuration: "bpc_plus" });
  assert.deepEqual(eventsOf(e, org).at(-1), { user_id: userId(e, "ana@example.com"), event: "billing_opened", subject: sub.id });

  /* Stripe's portal down: said so, with the portal's own login as the way round. */
  s.fail["POST /v1/billing_portal/sessions"] = [403, { error: { type: "invalid_request_error" } }];
  const down = await ana.post("/billing", { form: tokenFor(home.text, "/billing"), subscription: sub.id });
  assert.equal(down.status, 502);
  assert.match(down.text, /<a href="https:\/\/ranwhat\.com\/api\/billing">/);
  delete s.fail["POST /v1/billing_portal/sessions"];

  /* Fifteen minutes on: the step-up instead of the form, and a kept form refused. */
  later(FRESH_FOR + 1);
  const stale = await ana.get("/");
  assert.doesNotMatch(stale.text, /action="\/billing"/);
  assert.match(stale.text, /Manage billing needs an emailed code typed in the last 15 minutes/);
  assert.doesNotMatch(stale.headers.get("content-security-policy"), /stripe/);
  const n = portals(s).length;
  const refused = await ana.post("/billing", { form: tokenFor(home.text, "/billing"), subscription: sub.id });
  assert.equal(refused.status, 403);
  assert.match(refused.text, /Opening billing needs an emailed code/);
  assert.match(refused.text, /action="\/stepup"/);
  assert.equal(portals(s).length, n);
});

test("a portal session is only for a subscription linked to the organisation", async () => {
  const s = services();
  const e = env();
  const ana = new Browser(e);
  await signIn(ana, s);
  const { sub } = await upgraded(ana, s, e);
  const bo = new Browser(e, { ip: "203.0.113.50" });
  await signIn(bo, s, "bo@example.com");
  const token = await formToken(e, bo.session, "billing");
  const before = s.calls.length;
  for (const named of [sub.id, "sub_test9neverlinked", "", "cus_test1billing", "../../v1/customers"]) {
    const r = await bo.post("/billing", { form: token, subscription: named });
    assert.equal(r.status, 404, named);
    assert.match(r.text, /is not linked to Personal, so billing did not open/);
  }
  assert.equal(s.calls.length, before, "nothing was asked of Stripe");
  assert.equal(portals(s).length, 0);
  /* Nor does a form token for another action, or a request from another site, open it. */
  assert.equal((await ana.post("/billing", { form: await formToken(e, ana.session, "upgrade"), subscription: sub.id })).status, 403);
  assert.equal((await ana.post("/billing", { form: await formToken(e, ana.session, "billing"), subscription: sub.id },
    { "sec-fetch-site": "same-site", origin: "https://ranwhat.com" })).status, 403);
  assert.equal(portals(s).length, 0);
});

test("the next upgrade reuses the organisation's customer, and goes on without it when Stripe turns it down", async () => {
  const s = services();
  const e = env();
  const ana = new Browser(e);
  await signIn(ana, s);
  const org = orgOf(e, "ana@example.com");
  const { sub } = await upgraded(ana, s, e, "monthly");
  sub.status = "canceled";
  sub.ended_at = unix() - 60;
  await deliver(e, subEvent(sub, "customer.subscription.deleted"));

  /* Free again: the panel shows how it ended, and the way back. */
  let home = (await ana.get("/")).text;
  assert.match(home, /<dd id="plan">Free<\/dd>/);
  assert.match(home, /<dd data-status="canceled">Cancelled<\/dd>/);
  assert.match(home, /<dt>Ended<\/dt><dd data-ends>/);
  assert.match(home, /action="\/billing"/, "invoices stay a click away");
  assert.match(home, /href="\/upgrade">Upgrade to Plus/);

  await upgrade(ana, s, "yearly");
  let { form } = checkouts(s).at(-1);
  assert.equal(form.customer, sub.customer);
  assert.equal(form["customer_update[address]"], "auto");
  assert.equal(form["customer_update[name]"], "auto");

  s.refuseCustomer = true;
  const n = checkouts(s).length;
  await upgrade(ana, s, "yearly");
  assert.equal(checkouts(s).length, n + 2);
  ({ form } = checkouts(s).at(-1));
  assert.equal(form.customer, undefined);
  assert.equal(form["customer_update[address]"], undefined);
  assert.equal(form["metadata[org]"], org);
  assert.equal(one(e, "SELECT customer FROM orgs WHERE id = ?", org).customer, sub.customer, "the first customer stays");

  /* Under Managed Payments the customer goes alone. */
  s.refuseCustomer = false;
  const m = { ...e, STRIPE_TAX: "managed" };
  const res = await worker.fetch(new Request(`${ORIGIN}/upgrade`, { method: "POST",
    headers: { ...FROM_PAGE, "content-type": "application/x-www-form-urlencoded", "cf-connecting-ip": ana.ip,
      cookie: `${SESSION}=${ana.jar.get(SESSION)}` },
    body: new URLSearchParams({ form: await formToken(e, ana.session, "upgrade"), plan: "monthly" }).toString() }), m, ctx);
  assert.equal(res.status, 303);
  ({ form } = checkouts(s).at(-1));
  assert.equal(form.customer, sub.customer);
  assert.equal(form["customer_update[address]"], undefined);
});

test("the billing panel shows the status it has when Stripe cannot be reached, and when a plan ends", async () => {
  const s = services();
  const e = env();
  const ana = new Browser(e);
  await signIn(ana, s);
  const { sub } = await upgraded(ana, s, e);

  s.fail["GET /v1/subscriptions"] = [500, { error: { type: "api_error" } }];
  let home = await ana.get("/");
  assert.equal(home.status, 200);
  assert.match(home.text, /<dd data-status="active">Active<\/dd>\s*<dt>Renews<\/dt><dd>Not known just now<\/dd>/);
  delete s.fail["GET /v1/subscriptions"];

  sub.cancel_at_period_end = true;
  home = await ana.get("/");
  assert.match(home.text, new RegExp(`<dt>Ends</dt><dd data-ends>${isoDay(sub.items.data[0].current_period_end)}</dd>`));
  assert.doesNotMatch(home.text, /data-renews/);

  sub.status = "past_due";
  await deliver(e, subEvent(sub));
  home = await ana.get("/");
  assert.match(home.text, /<dd id="plan">Plus<\/dd>/);
  assert.match(home.text, /<dd data-status="past_due">Payment overdue: Stripe is trying the card again<\/dd>/);

  /* Plus given by a grant: nothing to pay, nothing to manage. */
  const bo = new Browser(e, { ip: "203.0.113.70" });
  await signIn(bo, s, "bo@example.com");
  grant(e, orgOf(e, "bo@example.com"), "plus");
  const given = (await bo.get("/")).text.match(/<section class="panel" id="billing">([\s\S]*?)<\/section>/)[1];
  assert.match(given, /Personal has Plus from ranwhat directly, with nothing to pay here\./);
  assert.doesNotMatch(given, /action="\/billing"|Upgrade to Plus/);
});

/* ---------- the anonymous checkout ---------- */

test("with accounts on, the pricing page's anonymous checkout, welcome and billing work as before", async () => {
  const s = services();
  const e = env();
  const res = await site(e, "/api/checkout", { method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" }, body: "plan=monthly" });
  assert.equal(res.status, 303);
  const id = res.headers.get("location").split("/").pop();
  const { form } = checkouts(s).at(-1);
  assert.deepEqual(Object.keys(form).sort(), [
    "allow_promotion_codes", "billing_address_collection", "cancel_url", "custom_text[submit][message]",
    "line_items[0][price]", "line_items[0][quantity]", "metadata[product]", "mode",
    "subscription_data[metadata][product]", "success_url", "tax_id_collection[enabled]",
  ]);
  assert.equal(form.success_url, "https://ranwhat.com/api/welcome?session_id={CHECKOUT_SESSION_ID}");
  assert.equal(form.cancel_url, "https://ranwhat.com/pricing#plus");

  const sub = pay(s, id, { email: "buyer@example.com" });
  const welcome = await (await site(e, `/api/welcome?session_id=${id}`)).text();
  const token = welcome.match(/rw_[A-Za-z0-9_-]{40,}/)[0];
  assert.match(welcome, /\/api\/billing/);
  assert.equal((await deliver(e, subEvent(sub, "customer.subscription.created"))).status, 200);
  assert.equal((await deliver(e, completedEvent(s, id))).status, 200);
  assert.equal(s.emails.length, 1);
  assert.equal(s.emails[0].subject, "Your ranwhat Plus feed token");
  assert.ok(s.emails[0].text.includes(token));
  assert.equal(await feed(e, token), 200);
  assert.deepEqual(links(e), [], "an anonymous purchase is linked to no organisation");

  const billing = await site(e, "/api/billing");
  assert.equal(billing.status, 302);
  assert.equal(billing.headers.get("location"), "https://billing.stripe.com/p/login/plus");
});
