/* Attaching a Plus subscription bought without an account (claim.js, with
 * stripe.js's checkoutClaim(), subscriptionClaim() and subscriptionsFor(),
 * and the links the welcome page and the token email gain): the two
 * proofs, what each refuses, Find my subscription, the old token as a
 * machine, and the notice. The Worker's own fetch handler runs over a
 * real SQLite database (node:sqlite, which is what D1 runs), with Stripe,
 * Resend and Turnstile answered by stand-ins that keep what they were
 * asked: no call leaves the machine. Webhook events are signed the way
 * Stripe signs them.
 *
 *     node --test --test-timeout=60000 worker/test/claim.test.mjs
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash, createHmac } from "node:crypto";
import { d1 } from "./stand-ins.mjs";

const worker = (await import("../src/index.js")).default;
const { formToken, FRESH_FOR } = await import("../src/session.js");
const { CLAIM_LOOKUPS_PER_HOUR } = await import("../src/claim.js");
const { STEPUP_RESERVE } = await import("../src/accounts.js");

const ORIGIN = "https://account.ranwhat.com";
const SITE = "https://ranwhat.com";
const FEED = "https://feed.ranwhat.com";
/* Split, so that nothing shaped like a key or a token sits in the source. */
const STRIPE_KEY = "sk_" + "test_" + "claimkey";
const WHSEC = "whsec_" + "test_" + "claim_signing_secret";
const LIST_SECRET = "a-list-test-secret-that-is-long-enough-1234567890";
const ACCOUNT_SECRET = "an-account-test-secret-that-is-long-enough-0123456789";
const SESSION = "__Host-rw_session";
const FROM_PAGE = { "sec-fetch-site": "same-origin", origin: ORIGIN };
const PLUS = { product: "ranwhat-plus" };
const HOUR = 3600, DAY = 24 * HOUR;
const ctx = { waitUntil() {} };

/* The clock, which a test moves forward when it needs time to pass. */
const realNow = Date.now;
let skew = 0;
Date.now = () => realNow() + skew * 1000;
const later = (seconds) => { skew += seconds; };
const unix = () => Math.floor(Date.now() / 1000);

const sha = (text) => createHash("sha256").update(text).digest("hex");

/* ---------- stand-ins ---------- */

/* Stripe as far as stripe.js uses it (customers and the subscription list
   included), Resend's /emails and Turnstile. */
function services() {
  const s = {
    prices: {
      ranwhat_plus_monthly: { id: "price_monthly1", lookup_key: "ranwhat_plus_monthly", active: true },
      ranwhat_plus_annual: { id: "price_annual1", lookup_key: "ranwhat_plus_annual", active: true },
    },
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
      const id = `cs_test_${"c".repeat(20)}${s.sessions.size}`;
      const session = { id, object: "checkout.session", url: `https://checkout.stripe.com/c/pay/${id}`,
        mode: form.mode, status: "open", payment_status: "unpaid", created: unix(),
        metadata: under(form, "metadata"), client_reference_id: form.client_reference_id ?? null,
        customer: form.customer ?? null, subscription: null, customer_details: null,
        price: form["line_items[0][price]"], subscription_metadata: under(form, "subscription_data[metadata]") };
      s.sessions.set(id, session);
      return reply(200, session);
    }
    if (key === "POST /v1/customers") {
      const id = `cus_test${s.customers.size + 1}org`;
      s.customers.set(id, { id, object: "customer", email: form.email, metadata: under(form, "metadata") });
      return reply(200, s.customers.get(id));
    }
    if (key === "GET /v1/checkout/sessions") {
      return reply(200, { object: "list", data: [...s.sessions.values()].filter((x) =>
        (!form.customer || x.customer === form.customer) && (!form.status || x.status === form.status)) });
    }
    if (key === "GET /v1/customers") {
      /* Stripe's filter: the email exactly as the customer has it. */
      return reply(200, { object: "list", data: [...s.customers.values()]
        .filter((c) => !c.deleted && c.email === form.email).slice(0, Number(form.limit || 10)) });
    }
    if (key === "GET /v1/customers/search") {
      /* Stripe's search: email:"..." matches exactly, but for case. */
      const q = /^email:"([^"\\]+)"$/.exec(form.query || "");
      assert.ok(q, form.query);
      return reply(200, { object: "search_result", data: [...s.customers.values()]
        .filter((c) => !c.deleted && String(c.email).toLowerCase() === q[1].toLowerCase())
        .slice(0, Number(form.limit || 10)) });
    }
    if (key === "GET /v1/subscriptions") {
      /* With no status asked for, every one that is not canceled. */
      return reply(200, { object: "list", data: [...s.subscriptions.values()]
        .filter((x) => x.customer === form.customer && x.status !== "canceled").slice(0, Number(form.limit || 10)) });
    }
    let m = u.pathname.match(/^\/v1\/checkout\/sessions\/([^/]+)$/);
    if (method === "GET" && m) return s.sessions.has(m[1]) ? reply(200, s.sessions.get(m[1])) : missing();
    m = u.pathname.match(/^\/v1\/subscriptions\/([^/]+)$/);
    if (method === "GET" && m) return s.subscriptions.has(m[1]) ? reply(200, s.subscriptions.get(m[1])) : missing();
    m = u.pathname.match(/^\/v1\/customers\/([^/]+)$/);
    if (method === "GET" && m) return s.customers.has(m[1]) ? reply(200, s.customers.get(m[1])) : missing();
    if (key === "GET /v1/billing_portal/configurations") return reply(200, { data: [] });
    return missing();
  };
  return s;
}

/* A Stripe customer with this email, made once per address unless `fresh`. */
function customer(s, email, { fresh = false } = {}) {
  const known = [...s.customers.values()].find((c) => c.email === email);
  if (known && !fresh) return known.id;
  const id = `cus_test${s.customers.size + 1}claim`;
  s.customers.set(id, { id, object: "customer", email });
  return id;
}

/* What Stripe does when someone pays for a session: a subscription with
   the session's subscription metadata, on the session's customer or the
   payer's, and the session complete. */
function pay(s, sessionId, { email = "buyer@example.com", status = "active", interval = "month" } = {}) {
  const session = s.sessions.get(sessionId);
  const n = s.subscriptions.size + 1;
  const sub = {
    id: `sub_test${n}claim`, object: "subscription", customer: session.customer || customer(s, email),
    status, metadata: { ...session.subscription_metadata }, start_date: unix(), created: unix(),
    items: { data: [{ current_period_end: unix() + 30 * DAY, price: { recurring: { interval } } }] },
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

/* The first form on a page that posts to `action`, as its hidden fields:
   the token, the organisation it was drawn for, and what else it carries. */
function hidden(html, action) {
  const m = html.match(new RegExp(`<form method="post" action="${action}"[^>]*>([\\s\\S]*?)</form>`));
  assert.ok(m, `no form for ${action}`);
  return Object.fromEntries([...m[1].matchAll(/<input type="hidden" name="([a-z_-]+)" value="([^"]*)">/g)]
    .map((x) => [x[1], x[2]]));
}

/* A form token for `action` drawn for `org`, as a page would make it, with the organisation it names. */
const bound = async (e, b, action, org) => ({ form: await formToken(e, b.session, `${action}:${org}`), org });

const codeIn = (mail) => mail.text.match(/^ {4}([0-9A-Z]{4}-[0-9A-Z]{4})$/m)[1];

async function typeCode(b, code) {
  const page = await b.get("/signin/code");
  assert.equal(page.status, 200, page.text);
  return b.post("/signin/code", { form: tokenFor(page.text, "/signin/code"), code });
}

/* Signs in with an emailed code, which makes the session fresh, and comes
   back to `next`. */
async function signIn(b, s, email = "ana@example.com", next = "/") {
  const form = await b.get(`/signin?next=${encodeURIComponent(next)}`);
  const asked = await b.post("/signin", { form: tokenFor(form.text, "/signin"), email, next,
    "cf-turnstile-response": "solved:signin" });
  assert.equal(asked.status, 303, asked.text);
  const done = await typeCode(b, codeIn(s.emails.at(-1)));
  assert.equal(done.status, 303, done.text);
  assert.ok(b.jar.has(SESSION));
  return done;
}

/* A fresh code from the page `html`'s step-up form, back where it says. */
async function stepUp(b, s, html) {
  const asked = await b.post("/stepup", { form: tokenFor(html, "/stepup"),
    next: html.match(/<form method="post" action="\/stepup">[\s\S]*?name="next" value="([^"]*)"/)[1].replace(/&amp;/g, "&") });
  assert.equal(asked.status, 303, asked.text);
  return typeCode(b, codeIn(s.emails.at(-1)));
}

const rows = (e, sql, ...p) => e.LIST.sql.prepare(sql).all(...p).map((r) => ({ ...r }));
const one = (e, sql, ...p) => rows(e, sql, ...p)[0];
const run = (e, sql, ...p) => e.LIST.sql.prepare(sql).run(...p);
const tables = (e) => rows(e, "SELECT name FROM sqlite_master WHERE type = 'table'").map((r) => r.name);
const dump = (e) => JSON.stringify(tables(e).map((t) => rows(e, `SELECT * FROM ${t}`)));
const userId = (e, email) => one(e, "SELECT id FROM users WHERE email = ?", email).id;
const orgOf = (e, email) => one(e,
  "SELECT m.org_id AS id FROM memberships m JOIN users u ON u.id = m.user_id WHERE u.email = ? AND m.role = 'owner'", email).id;
const links = (e) => rows(e, "SELECT subscription, org_id, how, linked_by FROM org_subscriptions ORDER BY subscription");
const claims = (e) => rows(e, "SELECT org_id, user_id, event, subject FROM auth_events WHERE event LIKE 'plus_claimed%' ORDER BY id");
const legacyOf = (e, org) => rows(e, "SELECT hash, user_id, label FROM machines WHERE org_id = ? AND kind = 'legacy'", org);
const stripeCalls = (s) => s.calls.length;
const lookups = (s) => s.calls.filter((c) => c.key.startsWith("GET /v1/customers") || c.key === "GET /v1/subscriptions");

/* `email` joins `orgId` as `role`, and their session looks at it. */
function join(e, email, orgId, role = "member") {
  run(e, "INSERT INTO memberships (org_id, user_id, role, created_at) VALUES (?, ?, ?, ?)", orgId, userId(e, email), role, unix());
  run(e, "UPDATE sessions SET org_id = ? WHERE user_id = ?", orgId, userId(e, email));
}

/* ---------- the pricing page, the webhook and the feed ---------- */

const site = (e, path, init = {}) => worker.fetch(new Request(`${SITE}${path}`, init), e, ctx);
const feed = (e, token) => worker.fetch(new Request(`${FEED}/v1/catalogue`,
  { headers: { authorization: `Bearer ${token}` } }), e, ctx).then((r) => r.status);
const tokenIn = (text) => text.match(/rw_[A-Za-z0-9_-]{40,}/)[0];

function deliver(e, event) {
  const body = JSON.stringify(event);
  const at = unix();
  const v1 = createHmac("sha256", WHSEC).update(`${at}.${body}`).digest("hex");
  return site(e, "/api/stripe", { method: "POST", headers: { "stripe-signature": `t=${at},v1=${v1}` }, body });
}

const completedEvent = (s, id) => ({
  id: `evt_${id}`, type: "checkout.session.completed", data: { object: { ...s.sessions.get(id) } },
});

/* The pricing page's anonymous checkout, paid: the session id and the
   subscription. `mailed`: Stripe's checkout.session.completed delivered,
   so the token email has gone. */
async function bought(s, e, { email = "buyer@example.com", mailed = true, ...opts } = {}) {
  const res = await site(e, "/api/checkout", { method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" }, body: "plan=monthly" });
  assert.equal(res.status, 303);
  const id = res.headers.get("location").split("/").pop();
  const sub = pay(s, id, { email, ...opts });
  if (mailed) assert.equal((await deliver(e, completedEvent(s, id))).status, 200);
  return { id, sub };
}

/* The claim page for `id`, and its Attach button pressed. */
async function attachByCheckout(b, id) {
  const page = await b.get(`/claim?session_id=${id}`);
  assert.equal(page.status, 200, page.text);
  return b.post("/claim", { ...hidden(page.text, "/claim"), session_id: id });
}

/* ---------- the links ---------- */

test("the welcome page and the token email link to the claim, only while accounts are on", async () => {
  const s = services();
  const e = env();
  const { id } = await bought(s, e);
  const claimUrl = `${ORIGIN}/claim?session_id=${id}`;
  const [mail] = s.emails;
  assert.deepEqual(mail.to, ["buyer@example.com"]);
  assert.ok(mail.text.includes(`  ${claimUrl}\n`), mail.text);
  assert.match(mail.text, /uvx ranwhat login/);
  assert.ok(mail.html.includes(`href="${claimUrl}"`));
  assert.match(mail.html, /Attach to\s+an account<\/a>/);
  assert.match(mail.text, /^Attach to an account/m);
  assert.match(mail.html, /uvx ranwhat login/);
  // The rest of the email is as it was.
  const token = tokenIn(mail.text);
  assert.match(mail.text, /RANWHAT_TOKEN=rw_\S+ uvx ranwhat update --save-token/);
  assert.match(mail.text, /Change plan or card, get invoices, or cancel: https:\/\/ranwhat\.com\/api\/billing/);

  const welcome = await (await site(e, `/api/welcome?session_id=${id}`)).text();
  assert.equal(tokenIn(welcome), token);
  assert.ok(welcome.includes(`<a href="${claimUrl}">Attach to an account</a>`));
  assert.match(welcome, /<code>uvx ranwhat login<\/code>/);
  assert.match(welcome, /<a href="\/api\/billing">Manage billing<\/a>/);

  /* Dark: no link and no login line, and the account host answers nothing. */
  const dark = env({ ACCOUNTS_ON: "" });
  const s2 = services();
  const bought2 = await bought(s2, dark);
  assert.equal(s2.emails.length, 1);
  assert.doesNotMatch(s2.emails[0].text, /claim|account\.ranwhat\.com|ranwhat login/);
  assert.doesNotMatch(s2.emails[0].html, /claim|account\.ranwhat\.com|ranwhat login/);
  const darkWelcome = await (await site(dark, `/api/welcome?session_id=${bought2.id}`)).text();
  assert.ok(tokenIn(darkWelcome));
  assert.doesNotMatch(darkWelcome, /claim|account\.ranwhat\.com|ranwhat login/);
  const off = new Browser(dark);
  assert.equal((await off.get(`/claim?session_id=${bought2.id}`)).status, 404);
  assert.equal((await off.post("/claim", { session_id: bought2.id })).status, 404);
  assert.equal((await off.post("/claim/find", {})).status, 404);
});

test("a checkout whose payment clears near the end of its link's day is pointed to Find my subscription", async () => {
  const s = services();
  const e = env();
  /* The checkout's own link says when it stops working. */
  const { id: quick } = await bought(s, e);
  const until = new Date((s.sessions.get(quick).created + DAY) * 1000).toISOString().slice(0, 16).replace("T", " ");
  assert.ok(s.emails[0].text.includes(`works until ${until} UTC`), s.emails[0].text);
  assert.match(s.emails[0].html, new RegExp(`the link works until ${until} UTC`));

  /* Paid by a bank debit that clears 23 hours later: the email comes then, with no link that would
     stop working within the hour, and Find my subscription instead. */
  const { id } = await bought(s, e, { mailed: false });
  const session = s.sessions.get(id);
  Object.assign(session, { payment_status: "unpaid" });
  assert.equal((await deliver(e, completedEvent(s, id))).status, 200);
  assert.equal(s.emails.length, 1, "nothing is mailed before the payment clears");
  later(DAY - HOUR);
  session.payment_status = "paid";
  assert.equal((await deliver(e, { ...completedEvent(s, id), id: `evt_${id}_async`,
    type: "checkout.session.async_payment_succeeded" })).status, 200);
  const mail = s.emails.at(-1);
  assert.equal(s.emails.length, 2);
  assert.ok(tokenIn(mail.text));
  assert.doesNotMatch(mail.text + mail.html, /session_id=/);
  assert.ok(mail.text.includes(`with Find\nmy subscription, which looks it up by this address:\n\n  ${ORIGIN}/claim\n`), mail.text);
  assert.ok(mail.html.includes(`href="${ORIGIN}/claim"`));
  assert.match(mail.html, /with Find my subscription, which looks it up by this address/);
  const welcome = await (await site(e, `/api/welcome?session_id=${id}`)).text();
  assert.ok(tokenIn(welcome));
  assert.doesNotMatch(welcome, /session_id=/);
  assert.ok(welcome.includes(`<a href="${ORIGIN}/claim">account.ranwhat.com/claim</a>`), welcome);

  /* Past its day, the checkout itself proves nothing, as before. */
  later(HOUR + 1);
  const ana = new Browser(e);
  await signIn(ana, s);
  const late = await attachByCheckout(ana, id);
  assert.equal(late.status, 403, late.text);
  assert.match(late.text, /Use Find my subscription instead/);
});

/* ---------- the checkout's proof ---------- */

test("the checkout's link signs in first, comes back, and attaches with one click", async () => {
  const s = services();
  const e = env();
  const { id, sub } = await bought(s, e);
  const token = tokenIn(s.emails[0].text);
  const calls = stripeCalls(s);

  const ana = new Browser(e);
  const away = await ana.get(`/claim?session_id=${id}`);
  assert.equal(away.status, 303);
  assert.equal(away.location, `/signin?next=${encodeURIComponent(`/claim?session_id=${id}`)}`);
  const done = await signIn(ana, s, "ana@example.com", `/claim?session_id=${id}`);
  assert.equal(done.location, `/claim?session_id=${id}`);

  /* One button, and nothing asked of Stripe to draw it. */
  const page = await ana.get(done.location);
  assert.equal(page.status, 200);
  assert.match(page.text, /<button type="submit">Attach to Personal<\/button>/);
  assert.match(page.text, new RegExp(`name="session_id" value="${id}"`));
  assert.match(page.text, /action="\/claim\/find"/);
  assert.doesNotMatch(page.text, /<script/);
  assert.equal(stripeCalls(s), calls, "drawing the page asks Stripe nothing");
  const home = await ana.get("/");
  assert.match(home.text, /<dd id="plan">Free<\/dd>/);
  assert.match(home.text, /<a href="\/claim">Attach it to Personal<\/a>/);

  const org = orgOf(e, "ana@example.com");
  const res = await ana.post("/claim", { ...hidden(page.text, "/claim"), session_id: id });
  assert.equal(res.status, 200, res.text);
  assert.match(res.text, /data-claimed/);
  assert.match(res.text, /The subscription is attached to Personal, for good\./);
  assert.ok(s.calls.some((c) => c.key === `GET /v1/checkout/sessions/${id}`), "the checkout is fetched again");
  assert.deepEqual(links(e), [{ subscription: sub.id, org_id: org, how: "session", linked_by: userId(e, "ana@example.com") }]);
  assert.equal(one(e, "SELECT customer FROM orgs WHERE id = ?", org).customer, null,
    "the buyer's Stripe customer is never made the organisation's");
  assert.deepEqual(claims(e), [{ org_id: org, user_id: userId(e, "ana@example.com"), event: "plus_claimed_checkout", subject: sub.id }]);

  /* Plus now; the old token keeps working, named as the organisation's, and is listed as a machine. */
  const after = await ana.get("/");
  assert.match(after.text, /<dd id="plan">Plus<\/dd>/);
  assert.match(after.text, /Plus subscription attached from its checkout, with a fresh code/);
  assert.match(after.text, /<strong>Subscription token<\/strong> <span class="tag">old subscription token<\/span>/);
  assert.match(after.text, /The token emailed with a subscription, attached here on/);
  assert.deepEqual(legacyOf(e, org), [{ hash: sha(token), user_id: null, label: "" }]);
  assert.equal(await feed(e, token), 200);
  const who = await worker.fetch(new Request(`${FEED}/v1/whoami`, { headers: { authorization: `Bearer ${token}` } }), e, ctx);
  assert.deepEqual([(await who.json()).kind], ["subscription"]);

  /* The notice, to the buyer's address, which is kept nowhere. */
  const notice = s.emails.at(-1);
  assert.deepEqual(notice.to, ["buyer@example.com"]);
  assert.equal(notice.from, "ranwhat <account@ranwhat.com>");
  assert.match(notice.subject, /attached to an account/);
  assert.match(notice.text, /attached to the organisation "Personal" on account\.ranwhat\.com/);
  assert.match(notice.text, /reply to this email/);
  assert.doesNotMatch(notice.text + notice.html, /ana@example\.com/, "it never names who attached it");
  assert.doesNotMatch(dump(e), /buyer@example\.com/);
  assert.doesNotMatch(dump(e), new RegExp(token));

  /* Pressed again: already here, nothing new, no second notice. */
  const mails = s.emails.length;
  const again = await ana.post("/claim", { ...hidden(page.text, "/claim"), session_id: id });
  assert.equal(again.status, 200);
  assert.match(again.text, /That subscription was attached to Personal already\./);
  assert.equal(s.emails.length, mails);
  assert.equal(claims(e).length, 1);
  assert.equal(legacyOf(e, org).length, 1);
});

test("a stale session is asked for a fresh code first, and comes back to the same checkout", async () => {
  const s = services();
  const e = env();
  const { id, sub } = await bought(s, e);
  const ana = new Browser(e);
  await signIn(ana, s);
  later(FRESH_FOR + 1);
  const calls = stripeCalls(s);
  const page = await ana.get(`/claim?session_id=${id}`);
  assert.equal(page.status, 200);
  assert.match(page.text, /Attaching needs an emailed code typed in the last 15 minutes/);
  assert.doesNotMatch(page.text, /action="\/claim"/);
  assert.doesNotMatch(page.text, /action="\/claim\/find"/);

  /* A form made for the session, as a forged one would be: refused before Stripe is asked. */
  const forged = await ana.post("/claim", { ...await bound(e, ana, "claim", orgOf(e, "ana@example.com")), session_id: id });
  assert.equal(forged.status, 403);
  assert.match(forged.text, /so nothing was looked up/);
  assert.equal(stripeCalls(s), calls);
  assert.deepEqual(links(e), []);

  const back = await stepUp(ana, s, page.text);
  assert.equal(back.location, `/claim?session_id=${id}`);
  const res = await attachByCheckout(ana, id);
  assert.equal(res.status, 200, res.text);
  assert.deepEqual(links(e).map((l) => l.subscription), [sub.id]);
});

test("refused proofs: forged, a day old, unpaid, from an account, inactive, linked elsewhere, or a feed token", async () => {
  const s = services();
  const e = env();
  const ana = new Browser(e);
  const bo = new Browser(e, { ip: "203.0.113.40" });
  const { id: shared, sub } = await bought(s, e);
  const token = tokenIn(s.emails[0].text);

  /* An old checkout: bought, then a day and a minute pass before anyone signs in. */
  const { id: old } = await bought(s, e, { email: "late@example.com" });
  later(DAY + 60);
  await signIn(ana, s);
  await signIn(bo, s, "bo@example.com");
  const anaOrg = orgOf(e, "ana@example.com");
  const boOrg = orgOf(e, "bo@example.com");

  /* A feed token, or anything else that is not a checkout or a subscription id, never reaches Stripe. */
  /* The page without a checkout has no Attach button: the token is the one it would carry. */
  const page = await ana.get("/claim");
  assert.match(page.text, /action="\/claim\/find"/);
  assert.doesNotMatch(page.text, /action="\/claim"/);
  const claimToken = await bound(e, ana, "claim", anaOrg);
  const calls = stripeCalls(s);
  for (const body of [{ session_id: token }, { subscription: token }, { token }, {},
    { session_id: shared, subscription: sub.id }, { session_id: `${shared}x/../` }]) {
    const r = await ana.post("/claim", { ...claimToken, ...body });
    assert.equal(r.status, 400, JSON.stringify(Object.keys(body)));
    assert.match(r.text, /a feed token included, shows that a subscription is yours/);
  }
  assert.equal(stripeCalls(s), calls);
  const shown = await ana.get(`/claim?session_id=${encodeURIComponent(token)}`);
  assert.doesNotMatch(shown.text, /name="session_id"/);
  assert.doesNotMatch(shown.text, /rw_/);

  /* A checkout Stripe never made. */
  const forged = await attachByCheckout(ana, `cs_test_${"z".repeat(24)}`);
  assert.equal(forged.status, 404);
  assert.match(forged.text, /That subscription was not found, so nothing was attached\./);

  /* More than a day old. */
  const late = await attachByCheckout(ana, old);
  assert.equal(late.status, 403);
  assert.match(late.text, /more than a day ago/);
  assert.match(late.text, /action="\/claim\/find"/);
  assert.doesNotMatch(late.text, /name="session_id"/);

  /* Not paid yet. */
  const open = (await site(e, "/api/checkout", { method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" }, body: "plan=monthly" })).headers.get("location").split("/").pop();
  const unpaid = await attachByCheckout(ana, open);
  assert.equal(unpaid.status, 409);
  assert.match(unpaid.text, /not paid yet/);

  /* Bought from an account: it is that organisation's, linked by the webhook or not yet. */
  const upgrade = await bo.get("/upgrade");
  const went = await bo.post("/upgrade", { ...hidden(upgrade.text, "/upgrade"), plan: "monthly" });
  const fromAccount = went.location.split("/").pop();
  pay(s, fromAccount, { email: "ana@example.com" });
  const theirs = await attachByCheckout(ana, fromAccount);
  assert.equal(theirs.status, 409);
  assert.match(theirs.text, /bought from an account/);

  /* Inactive. */
  const { id: gone, sub: goneSub } = await bought(s, e, { email: "gone@example.com", mailed: false });
  goneSub.status = "canceled";
  const inactive = await attachByCheckout(ana, gone);
  assert.equal(inactive.status, 409);
  assert.match(inactive.text, /not active/);
  assert.deepEqual(links(e), []);

  /* Bo attaches the shared one first (a fresh checkout's id is a day old by now, so a new purchase). */
  const { id: fresh, sub: freshSub } = await bought(s, e, { email: "both@example.com" });
  assert.equal((await attachByCheckout(bo, fresh)).status, 200);
  const elsewhere = await attachByCheckout(ana, fresh);
  assert.equal(elsewhere.status, 409);
  assert.match(elsewhere.text, /attached to another organisation already, and an attached subscription is never moved/);
  assert.doesNotMatch(elsewhere.text, /bo@example\.com/);
  assert.deepEqual(links(e).map((l) => [l.subscription, l.org_id]), [[freshSub.id, boOrg]]);
  assert.deepEqual(legacyOf(e, anaOrg), []);
  assert.equal(claims(e).length, 1);
  assert.equal(s.emails.filter((m) => m.subject && /attached to an account/.test(m.subject)).length, 1);
});

test("only an owner or an admin attaches, and only from this host", async () => {
  const s = services();
  const e = env();
  const { id, sub } = await bought(s, e);
  const ana = new Browser(e);
  await signIn(ana, s);
  const org = orgOf(e, "ana@example.com");
  const bo = new Browser(e, { ip: "203.0.113.50" });
  await signIn(bo, s, "bo@example.com");
  join(e, "bo@example.com", org, "member");
  const calls = stripeCalls(s);

  const page = await bo.get(`/claim?session_id=${id}`);
  assert.equal(page.status, 200);
  assert.match(page.text, /Only an owner or an admin of Personal can attach a subscription to it\./);
  assert.doesNotMatch(page.text, /action="\/claim/);
  for (const [path, action, body] of [["/claim", "claim", { session_id: id }], ["/claim", "claim", { subscription: sub.id }],
    ["/claim/find", "claim-find", {}]]) {
    const r = await bo.post(path, { ...await bound(e, bo, action, org), ...body });
    assert.equal(r.status, 403, path);
    assert.match(r.text, /Only an owner or an admin/);
  }
  assert.equal(stripeCalls(s), calls);

  /* From another site, or with no origin at all: refused before anything. */
  const anaPage = await ana.get(`/claim?session_id=${id}`);
  const form = tokenFor(anaPage.text, "/claim");
  for (const headers of [{ "sec-fetch-site": "same-site", origin: "https://ranwhat.com" }, {}]) {
    const r = await ana.post("/claim", { form, session_id: id }, headers);
    assert.equal(r.status, 403);
    assert.match(r.text, /That form was not accepted/);
  }
  assert.equal(stripeCalls(s), calls);

  /* An admin can. */
  const carl = new Browser(e, { ip: "203.0.113.51" });
  await signIn(carl, s, "carl@example.com");
  join(e, "carl@example.com", org, "admin");
  assert.equal((await attachByCheckout(carl, id)).status, 200);
  assert.deepEqual(links(e).map((l) => [l.subscription, l.org_id, l.linked_by]), [[sub.id, org, userId(e, "carl@example.com")]]);
});

/* ---------- Find my subscription ---------- */

test("Find my subscription runs only on a click with a fresh code, lists the live unattached ones, and attaches the one chosen", async () => {
  const s = services();
  const e = env();
  /* Ana paid twice, once as a second Stripe customer with the same address, and once more, now cancelled. */
  const { sub: first } = await bought(s, e, { email: "ana@example.com" });
  const second = pay(s, (await site(e, "/api/checkout", { method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" }, body: "plan=annual" })).headers.get("location").split("/").pop(),
  { email: "ana@example.com", interval: "year" });
  s.subscriptions.get(second.id).customer = customer(s, "ana@example.com", { fresh: true });
  const { sub: cancelled } = await bought(s, e, { email: "ana@example.com", mailed: false });
  cancelled.status = "canceled";
  /* Someone else's, and one of Ana's attached elsewhere already. */
  const { sub: someoneElse } = await bought(s, e, { email: "zed@example.com" });
  const { id: taken, sub: takenSub } = await bought(s, e, { email: "ana@example.com" });

  const bo = new Browser(e, { ip: "203.0.113.60" });
  await signIn(bo, s, "bo@example.com");
  assert.equal((await attachByCheckout(bo, taken)).status, 200);

  const ana = new Browser(e);
  await signIn(ana, s);
  const org = orgOf(e, "ana@example.com");
  const before = lookups(s).length;

  /* Signing in and drawing the page look nothing up. */
  const page = await ana.get("/claim");
  assert.match(page.text, /Look in Stripe for live subscriptions paid with <strong>ana@example\.com<\/strong>/);
  assert.equal(lookups(s).length, before);

  /* Stale: no button, and a forged form is refused before any lookup. */
  later(FRESH_FOR + 1);
  const stale = await ana.get("/claim");
  assert.doesNotMatch(stale.text, /action="\/claim\/find"/);
  const refused = await ana.post("/claim/find", await bound(e, ana, "claim-find", org));
  assert.equal(refused.status, 403);
  const blind = await ana.post("/claim", { ...await bound(e, ana, "claim", org), subscription: first.id });
  assert.equal(blind.status, 403);
  assert.equal(lookups(s).length, before);
  assert.doesNotMatch(refused.text + blind.text, new RegExp(`${first.id}|${second.id}|monthly|yearly`));

  /* With a fresh code, the click lists Ana's two live, unattached ones. */
  await stepUp(ana, s, stale.text);
  const found = await ana.post("/claim/find", { ...hidden((await ana.get("/claim")).text, "/claim/find") });
  assert.equal(found.status, 200, found.text);
  assert.match(found.text, /data-found="2"/);
  const listed = [...found.text.matchAll(/<li data-subscription="([^"]+)">([^<]*)/g)].map((m) => [m[1], m[2].trim()]);
  assert.deepEqual(listed.map((l) => l[0]).sort(), [first.id, second.id].sort());
  assert.ok(listed.some(([sid, text]) => sid === second.id && /^Plus, yearly, since \d{4}-\d{2}-\d{2}$/.test(text)));
  for (const gone of [cancelled.id, someoneElse.id, takenSub.id]) assert.doesNotMatch(found.text, new RegExp(gone));
  assert.equal(lookups(s).filter((c) => c.key === "GET /v1/customers").at(-1).form.email, "ana@example.com");

  /* Choosing one attaches it, by the email's proof. */
  const chosen = await ana.post("/claim", { ...hidden(found.text, "/claim"), subscription: second.id });
  assert.equal(chosen.status, 200, chosen.text);
  assert.deepEqual(links(e).filter((l) => l.org_id === org).map((l) => [l.subscription, l.how]), [[second.id, "email"]]);
  assert.deepEqual(claims(e).at(-1), { org_id: org, user_id: userId(e, "ana@example.com"), event: "plus_claimed_email", subject: second.id });
  assert.deepEqual(s.emails.at(-1).to, ["ana@example.com"]);

  /* A subscription id posted by hand is checked against the address too: another's is not found, as an unknown one is not. */
  const form = hidden(found.text, "/claim");
  const another = await ana.post("/claim", { ...form, subscription: someoneElse.id });
  const unknown = await ana.post("/claim", { ...form, subscription: "sub_test999nothing" });
  assert.equal(another.status, 404);
  assert.equal(another.text, unknown.text);
  assert.ok(!links(e).some((l) => l.subscription === someoneElse.id));
  /* And one of Ana's own attached elsewhere is said to be, and stays there. */
  const moved = await ana.post("/claim", { ...form, subscription: takenSub.id });
  assert.equal(moved.status, 409);
  assert.match(moved.text, /never moved/);

  /* Looked for again, one is left. */
  const again = await ana.post("/claim/find", { ...hidden((await ana.get("/claim")).text, "/claim/find") });
  assert.match(again.text, /data-found="1"/);
  assert.match(again.text, new RegExp(`data-subscription="${first.id}"`));
});

test("Find my subscription finds a subscription whose Stripe email has capitals in it", async () => {
  const s = services();
  const e = env();
  /* Stripe keeps the address as the buyer typed it; the account's is lower-cased. */
  const { sub } = await bought(s, e, { email: "Ana@Example.COM" });
  const ana = new Browser(e);
  await signIn(ana, s, "ana@example.com");
  const found = await ana.post("/claim/find", { ...hidden((await ana.get("/claim")).text, "/claim/find") });
  assert.equal(found.status, 200, found.text);
  assert.match(found.text, /data-found="1"/);
  assert.match(found.text, new RegExp(`data-subscription="${sub.id}"`));
  assert.equal(lookups(s).filter((c) => c.key === "GET /v1/customers/search").at(-1).form.query, 'email:"ana@example.com"');

  /* And it attaches by that proof, with the notice to the address as Stripe has it. */
  const chosen = await ana.post("/claim", { ...hidden(found.text, "/claim"), subscription: sub.id });
  assert.equal(chosen.status, 200, chosen.text);
  assert.deepEqual(links(e).map((l) => [l.subscription, l.how]), [[sub.id, "email"]]);
  assert.deepEqual(s.emails.at(-1).to, ["Ana@Example.COM"]);
});

test("Find my subscription with nothing to find says to write to us", async () => {
  const s = services();
  const e = env();
  await bought(s, e, { email: "zed@example.com" });
  const ana = new Browser(e);
  await signIn(ana, s);
  const found = await ana.post("/claim/find", { ...hidden((await ana.get("/claim")).text, "/claim/find") });
  assert.equal(found.status, 200);
  assert.match(found.text, /data-found="0"/);
  assert.match(found.text, /We found no live Plus subscription paid with <strong>ana@example\.com<\/strong>/);
  assert.match(found.text, /<a href="mailto:hello@ranwhat\.com\?subject=[^"]+">write to us<\/a>/);
  assert.doesNotMatch(found.text, /action="\/claim"/);
  assert.deepEqual(links(e), []);

  /* Stripe down: said so, and nothing in the log names the address. */
  const lines = [];
  const real = console.log;
  console.log = (...a) => lines.push(a.join(" "));
  try {
    s.fail["GET /v1/customers"] = [500, { error: { type: "api_error" } }];
    const down = await ana.post("/claim/find", { ...hidden((await ana.get("/claim")).text, "/claim/find") });
    assert.equal(down.status, 502);
    assert.match(down.text, /Stripe did not answer just now/);
  } finally {
    console.log = real;
  }
  assert.ok(lines.length >= 1);
  for (const line of lines) assert.doesNotMatch(line, /@|rw_|sk_test/);

  /* Each person looks things up only so often an hour. */
  delete s.fail["GET /v1/customers"];
  const token = hidden((await ana.get("/claim")).text, "/claim/find");
  let last;
  for (let i = 0; i < CLAIM_LOOKUPS_PER_HOUR; i++) last = await ana.post("/claim/find", token);
  assert.equal(last.status, 429);
  const calls = stripeCalls(s);
  assert.equal((await ana.post("/claim/find", token)).status, 429);
  assert.equal(stripeCalls(s), calls);
});

/* ---------- the old token ---------- */

test("the old token is listed, and once revoked stays revoked when the welcome page or the webhook makes it again", async () => {
  const s = services();
  const e = env();
  /* Attached before Stripe's event came and before the welcome page was seen: the token's row is made for it. */
  const { id, sub } = await bought(s, e, { mailed: false });
  const ana = new Browser(e);
  await signIn(ana, s);
  const org = orgOf(e, "ana@example.com");
  assert.equal((await attachByCheckout(ana, id)).status, 200);
  const [machine] = legacyOf(e, org);
  assert.ok(machine);

  /* The webhook's email then brings exactly the token listed. */
  assert.equal((await deliver(e, completedEvent(s, id))).status, 200);
  const token = tokenIn(s.emails.find((m) => /feed token/.test(m.subject)).text);
  assert.equal(machine.hash, sha(token));
  assert.equal(await feed(e, token), 200);

  /* Revoked from the account page, with the fresh code still good. */
  const home = await ana.get("/");
  const mid = home.text.match(/<li data-machine="([^"]+)"><strong>Subscription token<\/strong>/)[1];
  const r = await ana.post("/machines/revoke", { form: tokenFor(home.text, "/machines/revoke"), id: mid });
  assert.equal(r.status, 303, r.text);
  assert.equal(await feed(e, token), 403);
  assert.doesNotMatch((await ana.get("/")).text, /Subscription token/);

  /* The welcome page derives the same token again, and Stripe repeats its event: still revoked. */
  const welcome = await (await site(e, `/api/welcome?session_id=${id}`)).text();
  assert.equal(tokenIn(welcome), token);
  assert.equal((await deliver(e, completedEvent(s, id))).status, 200);
  assert.equal(await feed(e, token), 403);
  assert.ok(one(e, "SELECT revoked_at FROM tokens WHERE hash = ?", sha(token)).revoked_at);
  /* The organisation keeps Plus: the subscription is what pays, not the token. */
  assert.match((await ana.get("/")).text, /<dd id="plan">Plus<\/dd>/);
  assert.deepEqual(links(e).map((l) => l.subscription), [sub.id]);
});

/* ---------- the notice ---------- */

test("no claim is made that could not send its notice", async () => {
  const s = services();
  const e = env();
  const { id } = await bought(s, e);
  const ana = new Browser(e);
  await signIn(ana, s);
  const day = new Date(unix() * 1000).toISOString().slice(0, 10);
  run(e, "INSERT INTO mail_counts (day, kind, sent) VALUES (?, 'auth-stepup', ?) ON CONFLICT(day, kind) DO UPDATE SET sent = excluded.sent",
    day, STEPUP_RESERVE);
  const mails = s.emails.length;
  const r = await attachByCheckout(ana, id);
  assert.equal(r.status, 503);
  assert.match(r.text, /today's account email is used up/);
  assert.deepEqual(links(e), []);
  assert.equal(s.emails.length, mails);

  /* Resend failing after the claim is made does not undo it, and logs no address. */
  run(e, "UPDATE mail_counts SET sent = 0 WHERE kind = 'auth-stepup'");
  s.fail["POST /emails"] = [500, { statusCode: 500, name: "application_error" }];
  const lines = [];
  const real = console.log;
  console.log = (...a) => lines.push(a.join(" "));
  let ok;
  try {
    ok = await attachByCheckout(ana, id);
  } finally {
    console.log = real;
  }
  assert.equal(ok.status, 200);
  assert.equal(links(e).length, 1);
  assert.deepEqual(lines, ["claim notice mail: application_error"]);
});

test("sign-in carries only a checkout id of Stripe's shape on to the claim", async () => {
  const s = services();
  const e = env();
  for (const [asked, landed] of [
    ["/claim", "/claim"],
    [`/claim?session_id=cs_test_${"d".repeat(20)}`, `/claim?session_id=cs_test_${"d".repeat(20)}`],
    ["/claim?session_id=" + "rw_" + "x".repeat(43), "/"],
    [`/claim?session_id=cs_test_${"d".repeat(20)}&next=//evil.example`, "/"],
    ["/claim/find", "/"],
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

test("a claim page drawn for one organisation attaches nothing once another is switched to in a second tab", async () => {
  const s = services();
  const e = env();
  const { id, sub } = await bought(s, e, { email: "ana@example.com" });
  const ana = new Browser(e);
  await signIn(ana, s);
  const own = orgOf(e, "ana@example.com");
  const bea = new Browser(e, { ip: "203.0.113.70" });
  await signIn(bea, s, "bea@example.com");
  const corp = orgOf(e, "bea@example.com");
  run(e, "UPDATE orgs SET name = 'Bea Corp' WHERE id = ?", corp);
  run(e, "INSERT INTO memberships (org_id, user_id, role, created_at) VALUES (?, ?, 'admin', ?)",
    corp, userId(e, "ana@example.com"), unix());

  /* Tab 1: the checkout's page, and Find my subscription's list, drawn for Ana's own organisation. */
  const page = await ana.get(`/claim?session_id=${id}`);
  assert.match(page.text, /<button type="submit">Attach to Personal<\/button>/);
  const attachForm = hidden(page.text, "/claim");
  assert.equal(attachForm.org, own);
  const findForm = hidden(page.text, "/claim/find");
  assert.equal(findForm.org, own);
  const found = await ana.post("/claim/find", findForm);
  assert.match(found.text, /data-found="1"/);
  const chooseForm = hidden(found.text, "/claim");
  assert.deepEqual([chooseForm.org, chooseForm.subscription], [own, sub.id]);

  /* Tab 2: Ana switches to Bea Corp, where she is an admin too. */
  await switchTo(ana, corp);
  const calls = stripeCalls(s);
  for (const [path, form] of [["/claim", attachForm], ["/claim", chooseForm], ["/claim/find", findForm]]) {
    const r = await ana.post(path, form);
    assert.equal(r.status, 409, path);
    assert.match(r.text, /That form was for another of your organisations/);
  }
  assert.equal(stripeCalls(s), calls, "nothing was asked of Stripe");
  assert.deepEqual(links(e), [], "and nothing attached, to either");
  assert.deepEqual(claims(e), []);

  /* Back on her own, the same page attaches it there. */
  await switchTo(ana, own);
  const r = await ana.post("/claim", attachForm);
  assert.equal(r.status, 200, r.text);
  assert.deepEqual(links(e).map((l) => [l.subscription, l.org_id]), [[sub.id, own]]);
});

test("an attached purchase never makes its buyer the organisation's Stripe customer", async () => {
  const s = services();
  const e = env();
  const ana = new Browser(e);
  await signIn(ana, s);
  const acme = orgOf(e, "ana@example.com");
  run(e, "UPDATE orgs SET name = 'Acme' WHERE id = ?", acme);
  /* Yan, an admin of Acme, attaches what he bought on the pricing page. */
  const { id, sub } = await bought(s, e, { email: "yan@example.com" });
  const yan = new Browser(e, { ip: "203.0.113.71" });
  await signIn(yan, s, "yan@example.com");
  join(e, "yan@example.com", acme, "admin");
  assert.equal((await attachByCheckout(yan, id)).status, 200);
  assert.equal(one(e, "SELECT customer FROM orgs WHERE id = ?", acme).customer, null);

  /* It ends; the owner's next upgrade is on a customer of Acme's own, with her address, never Yan's. */
  sub.status = "canceled";
  assert.equal((await deliver(e, { id: "evt_gone", type: "customer.subscription.deleted",
    data: { object: { ...sub } } })).status, 200);
  const up = await ana.get("/upgrade");
  const went = await ana.post("/upgrade", { ...hidden(up.text, "/upgrade"), plan: "yearly" });
  assert.equal(went.status, 303, went.text);
  const made = s.calls.filter((c) => c.key === "POST /v1/checkout/sessions").at(-1).form;
  assert.notEqual(made.customer, sub.customer);
  assert.equal(made.customer, one(e, "SELECT customer FROM orgs WHERE id = ?", acme).customer);
  assert.equal(s.customers.get(made.customer).email, "ana@example.com");
});
