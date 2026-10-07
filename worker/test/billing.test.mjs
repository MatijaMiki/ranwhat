/* Paying for Plus from an account (billing.js, with stripe.js's
 * orgCheckout(), portalSession() and the webhook's link to the
 * organisation): the upgrade, the webhook that links what was bought,
 * the billing panel and Manage billing, and who may do each; and, with
 * accounts on, the pricing page's checkout sending everyone to the
 * upgrade while what it sold before goes on working. The Worker's
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
const { TERMS_READS_PER_HOUR, UPGRADES_PER_HOUR } = await import("../src/billing.js");
const { schema: feedSchema } = await import("../src/auth.js");

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
    sessions: new Map(), subscriptions: new Map(), customers: new Map(), emails: [], calls: [],
    fail: {},               // "METHOD /path" prefix -> [status, body]
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
      /* A customer deleted, or never made, is turned down as Stripe does. */
      if (form.customer && (!s.customers.has(form.customer) || s.customers.get(form.customer).deleted)) {
        return reply(400, { error: { type: "invalid_request_error", code: "resource_missing", param: "customer" } });
      }
      const id = `cs_test_${"b".repeat(20)}${s.sessions.size}`;
      const session = { id, object: "checkout.session", url: `https://checkout.stripe.com/c/pay/${id}`,
        mode: form.mode, status: "open", payment_status: "unpaid", created: unix(),
        expires_at: form.expires_at ? Number(form.expires_at) : unix() + DAY,
        metadata: under(form, "metadata"), client_reference_id: form.client_reference_id ?? null,
        customer: form.customer ?? null, subscription: null, customer_details: null,
        price: form["line_items[0][price]"], subscription_metadata: under(form, "subscription_data[metadata]") };
      s.sessions.set(id, session);
      return reply(200, session);
    }
    if (key === "GET /v1/checkout/sessions") {
      /* hideOpen: two Checkouts opened at once, before either could see the other. */
      if (s.hideOpen) return reply(200, { object: "list", data: [] });
      return reply(200, { object: "list", data: [...s.sessions.values()].filter((x) =>
        (!form.customer || x.customer === form.customer) && (!form.status || x.status === form.status)) });
    }
    if (key === "POST /v1/customers") {
      const id = `cus_test${s.customers.size + 1}org`;
      s.customers.set(id, { id, object: "customer", email: form.email, metadata: under(form, "metadata") });
      return reply(200, s.customers.get(id));
    }
    let m = u.pathname.match(/^\/v1\/customers\/([^/]+)$/);
    if (m) {
      const c = s.customers.get(m[1]);
      if (!c) return missing();
      if (method === "POST") c.email = form.email ?? c.email;
      return reply(200, c.deleted ? { id: c.id, object: "customer", deleted: true } : c);
    }
    m = u.pathname.match(/^\/v1\/checkout\/sessions\/([^/]+)\/expire$/);
    if (method === "POST" && m) {
      const x = s.sessions.get(m[1]);
      if (!x) return missing();
      if (x.status !== "open") return reply(400, { error: { type: "invalid_request_error", code: "checkout_session_not_open" } });
      x.status = "expired";
      return reply(200, x);
    }
    m = u.pathname.match(/^\/v1\/checkout\/sessions\/([^/]+)$/);
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
   one, and the session complete. On a customer's session Stripe takes the
   customer's email, and the payer cannot change it; otherwise `email` is
   what the payer typed. */
function pay(s, sessionId, { email = "payer@example.com", status = "active" } = {}) {
  const session = s.sessions.get(sessionId);
  assert.equal(session.status, "open", "Stripe takes payment only on an open session");
  if (session.customer) email = s.customers.get(session.customer).email;
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

/* Every form on a page that posts to `action`, as its hidden fields: the
   token, the organisation it was drawn for, and what else it carries. */
function formsOf(html, action) {
  const re = new RegExp(`<form method="post" action="${action}"[^>]*>([\\s\\S]*?)</form>`, "g");
  return [...html.matchAll(re)].map((m) => Object.fromEntries(
    [...m[1].matchAll(/<input type="hidden" name="([a-z_-]+)" value="([^"]*)">/g)].map((x) => [x[1], x[2]])));
}

/* The first of them. */
function hidden(html, action) {
  const [first] = formsOf(html, action);
  assert.ok(first, `no form for ${action}`);
  return first;
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
const customerOf = (e, org) => one(e, "SELECT customer FROM orgs WHERE id = ?", org).customer;
/* A form token for `action` drawn for `org`, as a page would make it, with the organisation it names. */
const bound = async (e, b, action, org) => ({ form: await formToken(e, b.session, `${action}:${org}`), org });

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
  const res = await b.post("/upgrade", { ...hidden(page.text, "/upgrade"), plan });
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
  /* A subscription bought without an account is moved by hand, on request: no page does it. */
  assert.match(billing, /To move a Plus subscription bought without an account to Personal, write to\s+<a href="mailto:hello@ranwhat\.com\?subject=Move%20a%20ranwhat%20Plus%20subscription">hello@ranwhat\.com<\/a>\./);
  assert.doesNotMatch(home, /\/claim/);
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
    /* The organisation's own customer, made before its first checkout with the owner's address. */
    assert.equal(form.customer, customerOf(e, org));
    assert.deepEqual(s.customers.get(form.customer),
      { id: form.customer, object: "customer", email: "ana@example.com", metadata: { product: "ranwhat-plus", org } });
    assert.equal(form["customer_update[address]"], "auto");
    const expires = Number(form.expires_at) - unix();
    assert.ok(expires >= 30 * MINUTE && expires <= 32 * MINUTE, String(expires));
    // The pricing page's own settings, as STRIPE_TAX says.
    assert.match(form["custom_text[submit][message]"], /14 days/);
    assert.equal(form["tax_id_collection[enabled]"], "true");
    assert.equal(form["billing_address_collection"], "required");
  }
  const lookups = s.calls.filter((c) => c.key === "GET /v1/prices").map((c) => c.form["lookup_keys[0]"]);
  assert.deepEqual(lookups, ["ranwhat_plus_monthly", "ranwhat_plus_annual"]);
  assert.equal(s.calls.filter((c) => c.key === "POST /v1/customers").length, 1, "one customer, reused");
  assert.deepEqual(eventsOf(e, org).map((r) => [r.event, r.subject, r.user_id]),
    [["upgrade_started", "monthly", userId(e, "ana@example.com")], ["upgrade_started", "yearly", userId(e, "ana@example.com")]]);

  /* A plan that is not one of the two opens nothing. */
  const before = s.calls.length;
  for (const plan of ["", "annual", "lifetime", "__proto__"]) {
    const r = await ana.post("/upgrade", { ...hidden(page.text, "/upgrade"), plan });
    assert.equal(r.status, 400, plan);
  }
  assert.equal(s.calls.length, before);

  /* Managed Payments: only what Stripe's guide shows, and the organisation. */
  const m = env({ STRIPE_TAX: "managed" });
  const bo = new Browser(m, { ip: "203.0.113.20" });
  await signIn(bo, s, "bo@example.com");
  await upgrade(bo, s, "monthly");
  assert.deepEqual(Object.keys(checkouts(s).at(-1).form).sort(), [
    "cancel_url", "client_reference_id", "customer", "expires_at", "line_items[0][price]", "line_items[0][quantity]",
    "managed_payments[enabled]", "metadata[org]", "metadata[product]", "mode", "subscription_data[metadata][org]",
    "subscription_data[metadata][product]", "success_url",
  ]);

  /* Stripe down: nothing charged, said so, and the page offers it again. */
  s.fail["POST /v1/checkout"] = [500, { error: { type: "api_error" } }];
  const down = await ana.post("/upgrade", { ...hidden(page.text, "/upgrade"), plan: "monthly" });
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
  const memberHome = (await bo.get("/")).text;
  assert.match(memberHome, /Personal is on Free\. An owner or an admin of it can upgrade it to Plus\./);
  assert.doesNotMatch(memberHome, /bought without an account|subject=Move/, "only owners and admins are told how to move one");

  /* A form made for the member's own session, as a forged one would be: refused before Stripe is asked. */
  const r = await bo.post("/upgrade", { ...await bound(e, bo, "upgrade", org), plan: "monthly" });
  assert.equal(r.status, 403);
  assert.match(r.text, /Only an owner or an admin/);
  assert.equal(s.calls.length, 0);
  assert.deepEqual(eventsOf(e, org), []);

  /* An admin of the same organisation can. */
  const carl = new Browser(e, { ip: "203.0.113.31" });
  await signIn(carl, s, "carl@example.com");
  join(e, "carl@example.com", org, "admin");
  assert.match((await carl.get("/")).text, /To move a Plus subscription bought without an account to Personal, write to/);
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
  const tried = await bo.post("/billing", { ...await bound(e, bo, "billing", org), subscription: sub.id });
  assert.equal(tried.status, 403);
  assert.match(tried.text, /Only an owner or an admin of Personal can open its billing\./);
  assert.equal(portals(s).length, 0);
});

test("upgrading needs a fresh code once the organisation has a Stripe customer, and an organisation on Plus or Team is not sold Plus again", async () => {
  const s = services();
  const e = env();
  const ana = new Browser(e);
  await signIn(ana, s);
  const org = orgOf(e, "ana@example.com");
  const kept = hidden((await ana.get("/upgrade")).text, "/upgrade");

  /* No Stripe customer yet, so no card saved to charge: the first checkout opens on a code over 15 minutes old. */
  later(FRESH_FOR + 1);
  const first = await ana.get("/upgrade");
  assert.doesNotMatch(first.text, /Opening checkout needs an emailed code/);
  assert.doesNotMatch(first.text, /action="\/stepup"/);
  assert.equal(customerOf(e, org), null);
  const opened = await ana.post("/upgrade", { ...hidden(first.text, "/upgrade"), plan: "monthly" });
  assert.equal(opened.status, 303, opened.text);
  assert.match(opened.location, /^https:\/\/checkout\.stripe\.com\//);
  assert.ok(customerOf(e, org), "the organisation's customer is made for its first checkout");

  /* Left unpaid, it leaves the customer: from now on, opening checkout needs a fresh code. */
  const calls = s.calls.length;
  const stale = await ana.get("/upgrade");
  assert.match(stale.text, /Opening checkout needs an emailed code typed in the last 15 minutes, as Stripe holds\s+billing details for Personal already/);
  assert.doesNotMatch(stale.text, /action="\/upgrade"/);
  assert.match(stale.text, /<input type="hidden" name="next" value="\/upgrade">/);
  assert.doesNotMatch(stale.headers.get("content-security-policy"), /stripe/);
  const r = await ana.post("/upgrade", { ...kept, plan: "monthly" });
  assert.equal(r.status, 403);
  assert.match(r.text, /so it did not open/);
  assert.equal(s.calls.length, calls);

  /* The fresh code brings the person back to the upgrade. */
  const asked = await ana.post("/stepup", { form: tokenFor(stale.text, "/stepup"), next: "/upgrade" });
  assert.equal(asked.location, "/signin/code");
  assert.equal((await typeCode(ana, codeIn(s.emails.at(-1)))).location, "/upgrade");
  /* A fresh code is a new session, so the forms are the new page's. */
  const form = hidden((await ana.get("/upgrade")).text, "/upgrade");
  const { sub } = await upgraded(ana, s, e);

  /* On Plus: nothing more to buy, before anything is asked of Stripe. */
  const bought = checkouts(s).length;
  const page = await ana.get("/upgrade");
  assert.match(page.text, /Personal is on Plus already, so there is nothing to buy\./);
  assert.doesNotMatch(page.text, /action="\/upgrade"/);
  const again = await ana.post("/upgrade", { ...form, plan: "yearly" });
  assert.equal(again.status, 409);
  assert.equal(checkouts(s).length, bought);

  /* On Team, by a grant, likewise, with the subscription gone. */
  sub.status = "canceled";
  await deliver(e, subEvent(sub, "customer.subscription.deleted"));
  grant(e, org, "team");
  assert.match((await ana.get("/upgrade")).text, /Personal is on Team already/);
  assert.equal((await ana.post("/upgrade", { ...form, plan: "monthly" })).status, 409);
  assert.equal(checkouts(s).length, bought);
});

test("an organisation opens only so many checkouts an hour", async () => {
  const s = services();
  const e = env();
  const ana = new Browser(e);
  await signIn(ana, s);
  for (let i = 0; i < UPGRADES_PER_HOUR; i++) await upgrade(ana, s);
  const r = await ana.post("/upgrade", { ...hidden((await ana.get("/upgrade")).text, "/upgrade"), plan: "monthly" });
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
  assert.deepEqual(sent[0].to, ["ana@example.com"], "the organisation's customer's address, the owner's");
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
  const r = await ana.post("/billing", hidden(home.text, "/billing"));
  assert.equal(r.status, 303, r.text);
  assert.match(r.location, /^https:\/\/billing\.stripe\.com\/p\/session\/test_/);
  assert.deepEqual(portals(s).at(-1).form,
    { customer: sub.customer, return_url: "https://account.ranwhat.com/", configuration: "bpc_plus" });
  assert.deepEqual(eventsOf(e, org).at(-1), { user_id: userId(e, "ana@example.com"), event: "billing_opened", subject: sub.id });

  /* Stripe's portal down: said so, with the portal's own login as the way round. */
  s.fail["POST /v1/billing_portal/sessions"] = [403, { error: { type: "invalid_request_error" } }];
  const down = await ana.post("/billing", hidden(home.text, "/billing"));
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
  const refused = await ana.post("/billing", hidden(home.text, "/billing"));
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
  const token = await bound(e, bo, "billing", orgOf(e, "bo@example.com"));
  const before = s.calls.length;
  for (const named of [sub.id, "sub_test9neverlinked", "", "cus_test1billing", "../../v1/customers"]) {
    const r = await bo.post("/billing", { ...token, subscription: named });
    assert.equal(r.status, 404, named);
    assert.match(r.text, /is not linked to Personal, so billing did not open/);
  }
  assert.equal(s.calls.length, before, "nothing was asked of Stripe");
  assert.equal(portals(s).length, 0);
  /* Nor does a form token for another action, or a request from another site, open it. */
  const anaOrg = orgOf(e, "ana@example.com");
  assert.equal((await ana.post("/billing", { ...await bound(e, ana, "upgrade", anaOrg), subscription: sub.id })).status, 403);
  assert.equal((await ana.post("/billing", { form: await formToken(e, ana.session, "billing"), org: anaOrg, subscription: sub.id })).status, 403);
  assert.equal((await ana.post("/billing", { ...await bound(e, ana, "billing", anaOrg), subscription: sub.id },
    { "sec-fetch-site": "same-site", origin: "https://ranwhat.com" })).status, 403);
  assert.equal(portals(s).length, 0);
});

test("the next upgrade reuses the organisation's customer, and makes it a new one when Stripe has deleted it", async () => {
  const s = services();
  const e = env();
  const ana = new Browser(e);
  await signIn(ana, s);
  const org = orgOf(e, "ana@example.com");
  const { sub } = await upgraded(ana, s, e, "monthly");
  assert.equal(sub.customer, customerOf(e, org));
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
  assert.equal(s.calls.filter((c) => c.key === "POST /v1/customers").length, 1);

  /* Deleted in Stripe since: a new customer, with the owner's address, kept, and never none. */
  s.customers.get(sub.customer).deleted = true;
  const n = checkouts(s).length;
  await upgrade(ana, s, "yearly");
  assert.equal(checkouts(s).length, n + 2);
  ({ form } = checkouts(s).at(-1));
  assert.notEqual(form.customer, sub.customer);
  assert.equal(form.customer, customerOf(e, org));
  assert.equal(s.customers.get(form.customer).email, "ana@example.com");
  assert.equal(form["metadata[org]"], org);
  assert.ok(checkouts(s).every((c) => c.form.customer), "no checkout for an organisation is made without its customer");

  /* Under Managed Payments the customer goes alone. */
  const m = { ...e, STRIPE_TAX: "managed" };
  const res = await worker.fetch(new Request(`${ORIGIN}/upgrade`, { method: "POST",
    headers: { ...FROM_PAGE, "content-type": "application/x-www-form-urlencoded", "cf-connecting-ip": ana.ip,
      cookie: `${SESSION}=${ana.jar.get(SESSION)}` },
    body: new URLSearchParams({ ...await bound(e, ana, "upgrade", org), plan: "monthly" }).toString() }), m, ctx);
  assert.equal(res.status, 303);
  ({ form } = checkouts(s).at(-1));
  assert.equal(form.customer, customerOf(e, org));
  assert.equal(form["customer_update[address]"], undefined);
});

test("the billing panel is drawn from what the webhook kept, asking Stripe nothing however often it loads", async () => {
  const s = services();
  const e = env();
  const ana = new Browser(e);
  await signIn(ana, s);
  const org = orgOf(e, "ana@example.com");
  const { sub } = await upgraded(ana, s, e);
  const bo = new Browser(e, { ip: "203.0.113.71" });
  await signIn(bo, s, "bo@example.com");
  join(e, "bo@example.com", org, "member");

  /* Loaded over and over, by the owner and by a plain member: not one call to Stripe. */
  const renews = new RegExp(`<dd data-status="active">Active</dd>\\s*<dt>Renews</dt><dd data-renews>${isoDay(sub.items.data[0].current_period_end)}</dd>`);
  const calls = s.calls.length;
  for (let i = 0; i < 25; i++) {
    assert.match((await ana.get("/")).text, renews);
    assert.match((await bo.get("/")).text, renews);
  }
  assert.equal(s.calls.length, calls);
  assert.match((await bo.get("/")).text, /<dt>Plan<\/dt><dd>Plus, yearly<\/dd>/);

  /* Cancelled at the period's end in Stripe's billing page: its event brings the day it ends. */
  sub.cancel_at_period_end = true;
  let home = await ana.get("/");
  assert.match(home.text, renews, "nothing changes here before Stripe's event");
  await deliver(e, subEvent(sub));
  home = await ana.get("/");
  assert.match(home.text, new RegExp(`<dt>Ends</dt><dd data-ends>${isoDay(sub.items.data[0].current_period_end)}</dd>`));
  assert.doesNotMatch(home.text, /data-renews/);

  sub.status = "past_due";
  await deliver(e, subEvent(sub));
  home = await ana.get("/");
  assert.match(home.text, /<dd id="plan">Plus<\/dd>/);
  assert.match(home.text, /<dd data-status="past_due">Payment overdue: Stripe is trying the card again<\/dd>/);

  /* Plus given by a grant: nothing to pay, nothing to manage. */
  const eve = new Browser(e, { ip: "203.0.113.70" });
  await signIn(eve, s, "eve@example.com");
  grant(e, orgOf(e, "eve@example.com"), "plus");
  const given = (await eve.get("/")).text.match(/<section class="panel" id="billing">([\s\S]*?)<\/section>/)[1];
  assert.match(given, /Personal has Plus from ranwhat directly, with nothing to pay here\./);
  assert.doesNotMatch(given, /action="\/billing"|Upgrade to Plus/);
});

test("a subscription linked by hand, with no terms kept yet, is read from Stripe once, for an owner, and only so often an hour", async () => {
  const s = services();
  const e = env();
  const carl = new Browser(e, { ip: "203.0.113.72" });
  await signIn(carl, s, "carl@example.com");
  const org = orgOf(e, "carl@example.com");
  const dee = new Browser(e, { ip: "203.0.113.73" });
  await signIn(dee, s, "dee@example.com");
  join(e, "dee@example.com", org, "member");
  /* As scripts/org_admin.py links one: its rows, and no event since. */
  await feedSchema(e.LIST);
  const id = "sub_test1byhand";
  const ends = unix() + 300 * DAY;
  s.subscriptions.set(id, { id, object: "subscription", customer: "cus_test1byhand", status: "active",
    metadata: { ...PLUS }, cancel_at_period_end: false, cancel_at: null, ended_at: null,
    items: { data: [{ current_period_end: ends, price: { recurring: { interval: "year" } } }] } });
  run(e, "INSERT INTO subscriptions (id, customer, status, updated_at) VALUES (?, 'cus_test1byhand', 'active', ?)", id, unix());
  run(e, "INSERT INTO org_subscriptions (subscription, org_id, how, linked_at) VALUES (?, ?, 'script', ?)", id, org, unix());
  const unknown = /<dd data-status="active">Active<\/dd>\s*<dt>Renews<\/dt><dd>Not known just now<\/dd>/;
  const known = new RegExp(`<dt>Plan</dt><dd>Plus, yearly</dd>\\s*<dt>Status</dt><dd data-status="active">Active</dd>\\s*<dt>Renews</dt><dd data-renews>${isoDay(ends)}</dd>`);

  /* A plain member's page asks Stripe nothing, and says it is not known yet. */
  const calls = s.calls.length;
  for (let i = 0; i < 5; i++) assert.match((await dee.get("/")).text, unknown);
  assert.equal(s.calls.length, calls);

  /* The owner's page asks, and with Stripe failing, only so many times an hour. */
  const lines = [];
  const real = console.log;
  console.log = (...a) => lines.push(a.join(" "));
  try {
    s.fail["GET /v1/subscriptions"] = [500, { error: { type: "api_error" } }];
    for (let i = 0; i < TERMS_READS_PER_HOUR; i++) {
      const page = await carl.get("/");
      assert.equal(page.status, 200);
      assert.match(page.text, unknown);
    }
  } finally {
    console.log = real;
  }
  assert.equal(lines.filter((l) => l.startsWith("stripe billing panel:")).length, TERMS_READS_PER_HOUR);
  delete s.fail["GET /v1/subscriptions"];
  assert.match((await carl.get("/")).text, unknown);
  assert.equal(s.calls.length, calls, "past the hour's reads, not even the owner's page asks");

  /* An hour on: once, and kept, for everyone. */
  later(HOUR + 1);
  assert.match((await carl.get("/")).text, known);
  assert.deepEqual(s.calls.slice(calls).map((c) => c.key), [`GET /v1/subscriptions/${id}`]);
  for (let i = 0; i < 5; i++) {
    assert.match((await carl.get("/")).text, known);
    assert.match((await dee.get("/")).text, known);
  }
  assert.equal(s.calls.length, calls + 1);
});

/* ---------- the pricing page's checkout, once accounts are on ---------- */

const UPGRADE_URL = "https://account.ranwhat.com/upgrade";
const tokenIn = (text) => text.match(/rw_[A-Za-z0-9_-]{40,}/)[0];

/* `e` with its database watched: every statement prepared or batched on
   it, reads included, is kept in `seen`. */
function watched(e) {
  const seen = [];
  const db = e.LIST;
  return { seen, e: { ...e, LIST: { ...db,
    prepare: (sql) => { seen.push(sql); return db.prepare(sql); },
    batch: (statements) => { seen.push("batch"); return db.batch(statements); },
  } } };
}

test("with accounts on, the pricing page's checkout goes to the upgrade, asking Stripe nothing and writing nothing, whatever it is sent", async () => {
  const s = services();
  const stub = globalThis.fetch;
  let fetched = 0;
  globalThis.fetch = (...args) => { fetched += 1; return stub(...args); };
  try {
    for (const extra of [{}, { STRIPE_SECRET_KEY: "", STRIPE_WEBHOOK_SECRET: "" }]) {
      const { seen, e } = watched(env(extra));
      const before = dump(e);
      const form = { "content-type": "application/x-www-form-urlencoded" };
      for (const [path, init] of [
        ["/api/checkout", { headers: form, body: "plan=monthly" }],
        ["/api/checkout", { headers: form, body: "plan=annual" }],
        ["/api/checkout", { headers: form, body: "plan=lifetime" }],
        ["/api/checkout", {}],
        ["/api/checkout", { headers: form,
          body: "plan=monthly&next=https://evil.example/&success_url=https://evil.example/&org=00000000-0000-4000-8000-000000000000" }],
        ["/api/checkout", { headers: { "content-type": "application/json" }, body: '{"plan":"monthly","next":"//evil.example"}' }],
        ["/api/checkout?next=https://evil.example/&redirect=//evil.example", { headers: form, body: "plan=monthly" }],
        ["/api/checkout", { headers: { ...form, origin: "https://evil.example", referer: "https://evil.example/pricing",
          "x-forwarded-host": "evil.example", host: "evil.example", cookie: `${SESSION}=x; next=/claim` },
          body: "plan=annual" }],
      ]) {
        const request = new Request(`${SITE}${path}`, { method: "POST", ...init });
        const res = await worker.fetch(request, e, ctx);
        assert.equal(res.status, 303, `${path} ${init.body}`);
        assert.equal(res.headers.get("location"), UPGRADE_URL, `${path} ${init.body}`);
        assert.equal(request.bodyUsed, false, "the form is not read");
      }
      assert.deepEqual(seen, [], "the database is not touched");
      assert.equal(dump(e), before);
    }
    assert.equal(fetched, 0, "nothing is asked of Stripe, or of anyone");
    assert.equal(s.calls.length, 0);
  } finally {
    globalThis.fetch = stub;
  }

  /* It is a POST, as it always was. */
  const e = env();
  assert.equal((await site(e, "/api/checkout")).status, 405);
  /* Dark, it opens a Checkout as it always has (stripe.test.mjs has the rest). */
  const dark = await site(env({ ACCOUNTS_ON: "" }), "/api/checkout", { method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" }, body: "plan=monthly" });
  assert.equal(dark.status, 303);
  assert.match(dark.headers.get("location"), /^https:\/\/checkout\.stripe\.com\/c\/pay\/cs_test_/);
  assert.equal(checkouts(s).length, 1);
});

/* A Checkout opened on the pricing page while accounts were dark, in the
   same database: the id Stripe sends the browser back with. */
async function openedBefore(e) {
  const res = await site({ ...e, ACCOUNTS_ON: "" }, "/api/checkout", { method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" }, body: "plan=monthly" });
  assert.equal(res.status, 303);
  return res.headers.get("location").split("/").pop();
}

test("a checkout opened before accounts were switched on and paid after still gets its token, by email and on the welcome page", async () => {
  const s = services();
  const e = env();
  const id = await openedBefore(e);
  const { form } = checkouts(s).at(-1);
  assert.equal(form.success_url, "https://ranwhat.com/api/welcome?session_id={CHECKOUT_SESSION_ID}");
  assert.equal(form["metadata[org]"], undefined);

  /* Paid once accounts are on: Stripe's events, and the browser back at the welcome page. */
  const sub = pay(s, id, { email: "buyer@example.com" });
  assert.equal((await deliver(e, subEvent(sub, "customer.subscription.created"))).status, 200);
  assert.equal((await deliver(e, completedEvent(s, id))).status, 200);
  assert.equal(s.emails.length, 1);
  const [mail] = s.emails;
  assert.deepEqual(mail.to, ["buyer@example.com"]);
  assert.equal(mail.subject, "Your ranwhat Plus feed token");
  const token = tokenIn(mail.text);
  assert.ok(mail.html.includes(token));
  assert.match(mail.text, /Change plan or card, get invoices, or cancel: https:\/\/ranwhat\.com\/api\/billing/);
  assert.doesNotMatch(mail.text + mail.html, /account\.ranwhat\.com|claim|Attach|ranwhat login/);

  const page = await site(e, `/api/welcome?session_id=${id}`);
  assert.equal(page.status, 200);
  const welcome = await page.text();
  assert.equal(tokenIn(welcome), token, "the welcome page shows the token the email brought");
  assert.match(welcome, /<a href="\/api\/billing">Manage billing<\/a>/);
  assert.doesNotMatch(welcome, /account\.ranwhat\.com|claim|Attach|ranwhat login/);
  assert.equal(await feed(e, token), 200);
  assert.deepEqual(links(e), [], "an anonymous purchase is linked to no organisation");

  /* Replayed, as Stripe does when it is unsure it was heard: no second email. */
  assert.equal((await deliver(e, completedEvent(s, id))).status, 200);
  assert.equal(s.emails.length, 1);

  /* A bank debit that clears only after the switch: mailed when it does. */
  const slow = await openedBefore(e);
  pay(s, slow, { email: "debit@example.com" });
  s.sessions.get(slow).payment_status = "unpaid";
  assert.equal((await deliver(e, completedEvent(s, slow))).status, 200);
  assert.equal(s.emails.length, 1, "nothing until the payment clears");
  s.sessions.get(slow).payment_status = "paid";
  assert.equal((await deliver(e, { id: `evt_${slow}_async`, type: "checkout.session.async_payment_succeeded",
    data: { object: { ...s.sessions.get(slow) } } })).status, 200);
  assert.equal(s.emails.length, 2);
  assert.deepEqual(s.emails[1].to, ["debit@example.com"]);
  assert.equal(await feed(e, tokenIn(s.emails[1].text)), 200);
  assert.equal(tokenIn(await (await site(e, `/api/welcome?session_id=${slow}`)).text()), tokenIn(s.emails[1].text));

  /* And the billing login still leads to Stripe's portal. */
  const billing = await site(e, "/api/billing");
  assert.equal(billing.status, 302);
  assert.equal(billing.headers.get("location"), "https://billing.stripe.com/p/login/plus");
});

test("a subscription bought before the switch and linked by hand gives its organisation Plus; its token, revoked there, stays revoked", async () => {
  const s = services();
  const e = env();
  const id = await openedBefore(e);
  const sub = pay(s, id, { email: "ana@example.com" });
  assert.equal((await deliver(e, completedEvent(s, id))).status, 200);
  const token = tokenIn(s.emails.at(-1).text);

  /* scripts/org_admin.py link, as its SQL does it: the link, and the unrevoked token as a legacy machine. */
  const ana = new Browser(e);
  await signIn(ana, s);
  const org = orgOf(e, "ana@example.com");
  run(e, "INSERT INTO org_subscriptions (subscription, org_id, how, linked_at) VALUES (?, ?, 'script', ?)", sub.id, org, unix());
  run(e, `INSERT INTO machines (id, hash, org_id, user_id, kind, label, created_at)
          VALUES ('0b6f6a52-6c1e-4f43-9d0e-5c2a7f3e9b10', ?, ?, NULL, 'legacy', '', ?)`, sha(token), org, unix());

  let home = await ana.get("/");
  assert.match(home.text, /<dd id="plan">Plus<\/dd>/);
  assert.match(home.text, new RegExp(`<div data-subscription="${sub.id}">`));
  const mid = home.text.match(/<li data-machine="([^"]+)"><strong>Subscription token<\/strong>/)[1];
  const r = await ana.post("/machines/revoke", { form: tokenFor(home.text, "/machines/revoke"), id: mid });
  assert.equal(r.status, 303, r.text);
  assert.equal(await feed(e, token), 403);

  /* The welcome page derives the same token again, and Stripe repeats its event: still revoked. */
  assert.equal(tokenIn(await (await site(e, `/api/welcome?session_id=${id}`)).text()), token);
  assert.equal((await deliver(e, completedEvent(s, id))).status, 200);
  assert.equal(await feed(e, token), 403);
  /* The organisation keeps Plus: the subscription is what pays, not the token. */
  home = await ana.get("/");
  assert.match(home.text, /<dd id="plan">Plus<\/dd>/);
  assert.deepEqual(links(e), [{ subscription: sub.id, org_id: org, how: "script" }]);
});

/* ---------- no claim ---------- */

test("/claim and /claim/find answer exactly as any unknown path on the account host does", async () => {
  const s = services();
  const e = env();
  const ana = new Browser(e);
  await signIn(ana, s);
  const stranger = new Browser(e, { ip: "203.0.113.70" });
  const same = async (b, method, path, unknown) => {
    const body = method === "POST" ? { session_id: `cs_test_${"d".repeat(20)}`, subscription: "sub_test1billing" } : undefined;
    const send = (p) => b.send(p, { method, body,
      headers: method === "POST" ? { "content-type": "application/x-www-form-urlencoded", ...FROM_PAGE } : {} });
    const [got, want] = [await send(path), await send(unknown)];
    assert.equal(got.status, 404, `${method} ${path}`);
    assert.equal(got.status, want.status, `${method} ${path}`);
    assert.equal(got.text, want.text, `${method} ${path}`);
    assert.deepEqual([...got.headers], [...want.headers], `${method} ${path}`);
  };
  for (const b of [ana, stranger]) {
    for (const method of ["GET", "POST"]) {
      await same(b, method, "/claim", "/no-such-page");
      await same(b, method, `/claim?session_id=cs_test_${"d".repeat(20)}`, "/no-such-page");
      await same(b, method, "/claim/find", "/no-such-page/find");
    }
  }
  assert.equal(s.calls.length, 0);
  assert.deepEqual(links(e), []);
});

test("a sign-in asked to go on to /claim goes to the account instead", async () => {
  const s = services();
  const e = env();
  for (const [asked, landed] of [
    ["/claim", "/"],
    ["/claim?session_id=cs_test_x", "/"],
    [`/claim?session_id=cs_test_${"d".repeat(20)}`, "/"],
    ["/claim/find", "/"],
    ["/upgrade", "/upgrade"],
  ]) {
    const b = new Browser(e, { ip: `198.51.100.${s.emails.length + 30}` });
    const done = await signIn(b, s, `n${s.emails.length}@example.com`, asked);
    assert.equal(done.location, landed, asked);
  }
});

/* ---------- bound to the organisation ---------- */

/* `b` looks at `orgId`, with the switcher on the account page. */
async function switchTo(b, orgId) {
  const home = await b.get("/");
  const r = await b.post("/org/switch", { ...hidden(home.text, "/org/switch"), org: orgId });
  assert.equal(r.status, 303, r.text);
}

test("a form drawn for one organisation does nothing once another is switched to in a second tab", async () => {
  const s = services();
  const e = env();
  const ana = new Browser(e);
  await signIn(ana, s);
  const acme = orgOf(e, "ana@example.com");
  run(e, "UPDATE orgs SET name = 'Acme' WHERE id = ?", acme);
  const bo = new Browser(e, { ip: "203.0.113.80" });
  await signIn(bo, s, "bo@example.com");
  const own = orgOf(e, "bo@example.com");
  join(e, "bo@example.com", acme, "admin");

  /* Tab 1: the upgrade and the account page, drawn for Acme. */
  const upgradePage = await bo.get("/upgrade");
  assert.match(upgradePage.text, /everyone in <strong>Acme<\/strong>/);
  const upgradeForm = hidden(upgradePage.text, "/upgrade");
  assert.equal(upgradeForm.org, acme);
  const renameForm = hidden((await bo.get("/")).text, "/org");
  assert.equal(renameForm.org, acme);

  /* Tab 2: Bo switches to his own organisation. */
  await switchTo(bo, own);
  const before = s.calls.length;
  const stale = await bo.post("/upgrade", { ...upgradeForm, plan: "yearly" });
  assert.equal(stale.status, 409);
  assert.match(stale.text, /That form was for another of your organisations/);
  assert.equal(s.calls.length, before, "nothing was asked of Stripe");
  assert.equal(checkouts(s).length, 0);
  assert.deepEqual(eventsOf(e, own), []);
  const renamed = await bo.post("/org", { ...renameForm, name: "Renamed" });
  assert.equal(renamed.status, 409);
  assert.deepEqual(rows(e, "SELECT name FROM orgs ORDER BY name").map((r) => r.name), ["Acme", "Personal"]);

  /* A form that names no organisation, or another than its token was made for, is refused outright. */
  const { org: _drop, ...bare } = upgradeForm;
  assert.equal((await bo.post("/upgrade", { ...bare, plan: "yearly" })).status, 403);
  assert.equal((await bo.post("/upgrade", { ...upgradeForm, org: own, plan: "yearly" })).status, 403);
  assert.equal(s.calls.length, before);

  /* Back on Acme, now on Plus: Manage billing and a CI token, drawn for Acme. */
  await switchTo(bo, acme);
  const { sub } = await upgraded(ana, s, e);
  const acmeHome = (await bo.get("/")).text;
  const billingForm = hidden(acmeHome, "/billing");
  assert.equal(billingForm.org, acme);
  assert.equal(billingForm.subscription, sub.id);
  const ciForm = hidden(acmeHome, "/tokens/ci");
  assert.equal(ciForm.org, acme);
  await switchTo(bo, own);
  const n = s.calls.length;
  const portal = await bo.post("/billing", billingForm);
  assert.equal(portal.status, 409);
  assert.equal(portals(s).length, 0);
  assert.equal(s.calls.length, n);
  const ci = await bo.post("/tokens/ci", { ...ciForm, label: "deploy", expires: "never" });
  assert.equal(ci.status, 409);
  assert.doesNotMatch(ci.text, /rw_c_/);
  assert.equal(count(e, "machines"), 0);

  /* Drawn again for the organisation looked at, they work. */
  await switchTo(bo, acme);
  const again = await bo.post("/billing", hidden((await bo.get("/")).text, "/billing"));
  assert.equal(again.status, 303, again.text);
  assert.equal(portals(s).length, 1);
});

/* ---------- the organisation's own customer ---------- */

test("the organisation's Stripe customer is its own, with the owner's address, and follows the owner", async () => {
  const s = services();
  const e = env();
  const ana = new Browser(e);
  await signIn(ana, s);
  const acme = orgOf(e, "ana@example.com");
  run(e, "UPDATE orgs SET name = 'Acme' WHERE id = ?", acme);
  const yan = new Browser(e, { ip: "203.0.113.90" });
  await signIn(yan, s, "yan@example.com");
  join(e, "yan@example.com", acme, "admin");
  const carl = new Browser(e, { ip: "203.0.113.91" });
  await signIn(carl, s, "carl@example.com");
  join(e, "carl@example.com", acme, "admin");
  const [yanId, carlId] = [userId(e, "yan@example.com"), userId(e, "carl@example.com")];

  /* Yan, an admin, upgrades and pays: the Checkout is on Acme's customer, made with Ana's address,
     which the payer cannot change, so the "Plus is on" email and Stripe's billing login are Ana's. */
  const mails = s.emails.length;
  const id = await upgrade(yan, s, "monthly");
  const cus = customerOf(e, acme);
  assert.equal(s.sessions.get(id).customer, cus);
  assert.equal(s.customers.get(cus).email, "ana@example.com");
  const sub = pay(s, id, { email: "yan@example.com" });
  assert.equal((await deliver(e, completedEvent(s, id))).status, 200);
  assert.equal(sub.customer, cus);
  assert.deepEqual(s.emails.slice(mails).map((m) => m.to[0]), ["ana@example.com"]);
  assert.equal(customerOf(e, acme), cus, "the webhook keeps the organisation's own customer");

  const lines = [];
  const real = console.log;
  console.log = (...a) => lines.push(a.join(" "));
  const updates = () => s.calls.filter((c) => c.key === `POST /v1/customers/${cus}`).map((c) => c.form.email);
  try {
    /* Yan, while an admin, makes the billing email his own in Stripe's billing page; made a member, it is Ana's again. */
    s.customers.get(cus).email = "yan@example.com";
    let r = await ana.post("/members/role", formsOf((await ana.get("/")).text, "/members/role").find((f) => f.user === yanId));
    assert.equal(r.status, 303, r.text);
    assert.equal(s.customers.get(cus).email, "ana@example.com");
    assert.deepEqual(updates(), ["ana@example.com"]);

    /* An admin again, the same, and removed: Ana's again. */
    r = await ana.post("/members/role", formsOf((await ana.get("/")).text, "/members/role").find((f) => f.user === yanId));
    assert.equal(r.status, 303, r.text);
    s.customers.get(cus).email = "Yan@Example.com";
    r = await ana.post("/members/remove", formsOf((await ana.get("/")).text, "/members/remove").find((f) => f.user === yanId));
    assert.equal(r.status, 303, r.text);
    assert.equal(s.customers.get(cus).email, "ana@example.com");
    assert.equal(updates().length, 2);

    /* An address an owner chose, someone else's, stays when an admin goes. */
    s.customers.get(cus).email = "billing@acme.example";
    const dee = new Browser(e, { ip: "203.0.113.92" });
    await signIn(dee, s, "dee@example.com");
    join(e, "dee@example.com", acme, "admin");
    r = await ana.post("/members/remove", formsOf((await ana.get("/")).text, "/members/remove")
      .find((f) => f.user === userId(e, "dee@example.com")));
    assert.equal(r.status, 303, r.text);
    assert.equal(s.customers.get(cus).email, "billing@acme.example");
    assert.equal(updates().length, 2);

    /* Ownership handed on: the owner's address becomes the new owner's. */
    s.customers.get(cus).email = "ana@example.com";
    const asked = await ana.post("/members/transfer",
      formsOf((await ana.get("/")).text, "/members/transfer").find((f) => f.user === carlId));
    assert.equal(asked.status, 200, asked.text);
    r = await ana.post("/members/transfer", hidden(asked.text, "/members/transfer"));
    assert.equal(r.status, 303, r.text);
    assert.equal(s.customers.get(cus).email, "carl@example.com");

    /* Stripe down: the change is made, and the failure only logged. */
    s.customers.get(cus).email = "ana@example.com";
    s.fail[`POST /v1/customers/${cus}`] = [500, { error: { type: "api_error" } }];
    r = await carl.post("/members/remove", formsOf((await carl.get("/")).text, "/members/remove")
      .find((f) => f.user === userId(e, "ana@example.com")));
    assert.equal(r.status, 303, r.text);
    assert.equal(rows(e, "SELECT 1 FROM memberships WHERE org_id = ? AND user_id = ?", acme, userId(e, "ana@example.com")).length, 0);
    assert.ok(lines.includes("stripe billing email: api_error"), lines.join("\n"));
  } finally {
    console.log = real;
  }
  for (const line of lines) assert.doesNotMatch(line, /@|cus_|sub_|sk_/);
});

/* ---------- paying twice ---------- */

test("a new checkout expires the organisation's open one, and two paid at once are flagged", async () => {
  const s = services();
  const e = env();
  const ana = new Browser(e);
  await signIn(ana, s);
  const org = orgOf(e, "ana@example.com");

  /* Monthly opened, then yearly: the monthly one is expired before the yearly one is made. */
  const first = await upgrade(ana, s, "monthly");
  const second = await upgrade(ana, s, "yearly");
  assert.equal(s.sessions.get(first).status, "expired");
  assert.equal(s.sessions.get(second).status, "open");
  const expired = s.calls.filter((c) => c.key.endsWith("/expire")).map((c) => c.key);
  assert.deepEqual(expired, [`POST /v1/checkout/sessions/${first}/expire`]);
  assert.ok(s.calls.findIndex((c) => c.key === `POST /v1/checkout/sessions/${first}/expire`) <
    s.calls.findLastIndex((c) => c.key === "POST /v1/checkout/sessions"));
  assert.throws(() => pay(s, first), /open session/, "Stripe takes no payment on it");
  /* Another site's open session on the same customer is left alone. */
  const theirs = `cs_test_${"x".repeat(20)}`;
  s.sessions.set(theirs, { id: theirs, status: "open", customer: customerOf(e, org), metadata: { product: "other" } });
  await upgrade(ana, s, "monthly");
  assert.equal(s.sessions.get(theirs).status, "open");
  assert.equal(s.sessions.get(second).status, "expired");

  /* Two opened at once, before either could see the other, and both paid. */
  s.hideOpen = true;
  const a = await upgrade(ana, s, "monthly");
  const b = await upgrade(ana, s, "yearly");
  const lines = [];
  const real = console.log;
  console.log = (...x) => lines.push(x.join(" "));
  const mails = s.emails.length;
  try {
    const subA = pay(s, a);
    assert.equal((await deliver(e, completedEvent(s, a))).status, 200);
    const subB = pay(s, b);
    assert.equal((await deliver(e, subEvent(subB, "customer.subscription.created"))).status, 200);
    assert.equal((await deliver(e, completedEvent(s, b))).status, 200);
    assert.deepEqual(links(e).map((l) => l.subscription).sort(), [subA.id, subB.id].sort());
  } finally {
    console.log = real;
  }
  assert.deepEqual(lines, ["stripe checkout: org has another live subscription"]);
  const sent = s.emails.slice(mails);
  assert.equal(sent.length, 2);
  assert.doesNotMatch(sent[0].text, /two Plus subscriptions/);
  assert.match(sent[1].text, /Personal now has two Plus subscriptions, and needs one\. Cancel the one you do not want with Manage billing/);
  assert.match(sent[1].html, /two Plus subscriptions/);

  /* The billing panel says so too, with Manage billing for each. */
  const billing = (await ana.get("/")).text.match(/<section class="panel" id="billing">([\s\S]*?)<\/section>/)[1];
  assert.match(billing, /<p class="bad" data-twice="2">Personal has 2 live Plus\s+subscriptions, and needs one\./);
  assert.equal(formsOf(billing, "/billing").length, 2);
});
