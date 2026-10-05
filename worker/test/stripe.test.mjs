/* Buying Plus: the Worker's own handlers over a real SQLite database, with
 * Stripe's and Resend's APIs answered by stand-ins that keep what they were
 * asked, and webhook events signed the way Stripe signs them. What a test
 * pays for is then fetched from the feed exactly as `ranwhat update` would.
 *
 *     node --test worker/test/stripe.test.mjs
 *
 * STRIPE_CALLS=<file> writes every call made to Stripe there as JSON, for
 * checking the parameter names against Stripe's published OpenAPI spec.
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { spawnSync } from "node:child_process";
import { writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { d1 } from "./stand-ins.mjs";

const worker = (await import("../src/index.js")).default;
const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const SECRET = "a-test-secret-that-is-long-enough-1234567890";
const WHSEC = "whsec_test_signing_secret";
const ctx = { waitUntil() {} };
const now = () => Math.floor(Date.now() / 1000);
const PLUS = { product: "ranwhat-plus" };
const recorded = [];

after(() => {
  if (process.env.STRIPE_CALLS) writeFileSync(process.env.STRIPE_CALLS, JSON.stringify(recorded, null, 1));
});

/* ---------- stand-ins ---------- */

/* Stripe as far as stripe.js uses it, and Resend's /emails. */
function services() {
  const s = {
    prices: {
      ranwhat_plus_monthly: { id: "price_monthly1", lookup_key: "ranwhat_plus_monthly", active: true },
      ranwhat_plus_annual: { id: "price_annual1", lookup_key: "ranwhat_plus_annual", active: true },
    },
    sessions: new Map(), subscriptions: new Map(), portals: [], emails: [], calls: [],
    fail: {},          // "METHOD /path" prefix -> [status, body]
  };
  const reply = (status, body) => new Response(JSON.stringify(body), { status });
  globalThis.fetch = async (url, init = {}) => {
    const u = new URL(String(url));
    const method = init.method || "GET";
    const key = `${method} ${u.pathname}`;
    for (const [prefix, [status, body]] of Object.entries(s.fail)) {
      if (key.startsWith(prefix)) return reply(status, body);
    }
    if (u.hostname === "api.resend.com") {
      assert.equal(key, "POST /emails");
      s.emails.push(JSON.parse(init.body));
      return reply(200, { id: `e${s.emails.length}` });
    }
    assert.equal(u.hostname, "api.stripe.com");
    assert.equal(init.headers.authorization, "Bearer sk_test_key");
    const params = [...(method === "GET" ? u.searchParams : new URLSearchParams(init.body || ""))];
    const form = Object.fromEntries(params);
    s.calls.push({ key, form });
    recorded.push({ method, path: u.pathname, params });

    if (key === "GET /v1/prices") {
      const found = Object.values(s.prices).filter((p) => p.lookup_key === form["lookup_keys[0]"] && p.active);
      return reply(200, { object: "list", data: found });
    }
    if (key === "POST /v1/checkout/sessions") {
      const id = `cs_test_${"a".repeat(20)}${s.sessions.size}`;
      const session = { id, object: "checkout.session", url: `https://checkout.stripe.com/c/pay/${id}`,
        mode: form.mode, status: "open", payment_status: "unpaid", created: now(),
        metadata: { product: form["metadata[product]"] }, subscription: null, customer_details: null,
        price: form["line_items[0][price]"] };
      s.sessions.set(id, session);
      return reply(200, session);
    }
    let m = u.pathname.match(/^\/v1\/checkout\/sessions\/([^/]+)$/);
    if (method === "GET" && m) {
      return s.sessions.has(m[1]) ? reply(200, s.sessions.get(m[1]))
        : reply(404, { error: { type: "invalid_request_error", code: "resource_missing" } });
    }
    m = u.pathname.match(/^\/v1\/subscriptions\/([^/]+)$/);
    if (method === "GET" && m) {
      return s.subscriptions.has(m[1]) ? reply(200, s.subscriptions.get(m[1]))
        : reply(404, { error: { type: "invalid_request_error", code: "resource_missing" } });
    }
    if (key === "GET /v1/billing_portal/configurations") return reply(200, { object: "list", data: s.portals });
    return reply(404, { error: { type: "invalid_request_error", code: "resource_missing" } });
  };
  return s;
}

/* What Stripe does when someone pays for a session: a customer, an active
   subscription carrying the session's metadata, and the session complete. */
function pay(s, sessionId, { email = "buyer@example.com", status = "active", metadata = PLUS } = {}) {
  const n = s.subscriptions.size + 1;
  const sub = { id: `sub_test${n}abcdef`, object: "subscription", customer: `cus_test${n}abcdef`, status, metadata };
  s.subscriptions.set(sub.id, sub);
  Object.assign(s.sessions.get(sessionId), {
    status: "complete", payment_status: "paid", subscription: sub.id,
    customer_details: { email }, metadata,
  });
  return sub;
}

function env(extra = {}) {
  return { LIST: d1(), RESEND_API_KEY: "re_test_key", LIST_SECRET: SECRET,
           STRIPE_SECRET_KEY: "sk_test_key", STRIPE_WEBHOOK_SECRET: WHSEC, ...extra };
}

const call = (e, path, init = {}) => worker.fetch(new Request(`https://ranwhat.com${path}`, init), e, ctx);

const buy = (e, plan = "monthly") => call(e, "/api/checkout", {
  method: "POST",
  headers: { "content-type": "application/x-www-form-urlencoded" },
  body: new URLSearchParams({ plan }).toString(),
});

/* Opens checkout and pays: the session id and the subscription. */
async function bought(s, e, opts) {
  const res = await buy(e);
  assert.equal(res.status, 303);
  const id = res.headers.get("location").split("/").pop();
  return { id, sub: pay(s, id, opts) };
}

function signed(event, { secret = WHSEC, at = now() } = {}) {
  const body = JSON.stringify(event);
  const v1 = createHmac("sha256", secret).update(`${at}.${body}`).digest("hex");
  return { body, signature: `t=${at},v1=${v1}` };
}

function deliver(e, event, opts) {
  const { body, signature } = signed(event, opts);
  return call(e, "/api/stripe", { method: "POST", headers: { "stripe-signature": signature }, body });
}

const completedEvent = (s, id) => ({
  id: `evt_${id}`, type: "checkout.session.completed", data: { object: s.sessions.get(id) },
});

const subEvent = (sub, type = "customer.subscription.updated") => ({
  id: `evt_${sub.id}_${type}`, type, data: { object: { ...sub } },
});

const tokenIn = (text) => text.match(/rw_[A-Za-z0-9_-]{40,}/)[0];

const feed = (e, token) => call(e, "/v1/catalogue", { headers: { authorization: `Bearer ${token}` } })
  .then((r) => r.status);

/* ---------- checkout ---------- */

test("each plan opens Stripe Checkout for its own price, marked as Plus", async () => {
  const s = services();
  const e = env();
  for (const [plan, price] of [["monthly", "price_monthly1"], ["annual", "price_annual1"]]) {
    const res = await buy(e, plan);
    assert.equal(res.status, 303);
    assert.match(res.headers.get("location"), /^https:\/\/checkout\.stripe\.com\/c\/pay\/cs_test_/);
    const { form } = s.calls.filter((c) => c.key === "POST /v1/checkout/sessions").pop();
    assert.equal(form["line_items[0][price]"], price);
    assert.equal(form["line_items[0][quantity]"], "1");
    assert.equal(form.mode, "subscription");
    assert.equal(form["metadata[product]"], "ranwhat-plus");
    assert.equal(form["subscription_data[metadata][product]"], "ranwhat-plus");
    assert.equal(form.success_url, "https://ranwhat.com/api/welcome?session_id={CHECKOUT_SESSION_ID}");
    assert.equal(form.cancel_url, "https://ranwhat.com/pricing#plus");
    assert.match(form["custom_text[submit][message]"], /14 days/);
    assert.equal(form["automatic_tax[enabled]"], undefined, "tax stays off until STRIPE_TAX says");
    assert.equal(form["managed_payments[enabled]"], undefined);
    assert.equal(form["tax_id_collection[enabled]"], "true");
  }
  const lookups = s.calls.filter((c) => c.key === "GET /v1/prices").map((c) => c.form["lookup_keys[0]"]);
  assert.deepEqual(lookups, ["ranwhat_plus_monthly", "ranwhat_plus_annual"]);
});

test("STRIPE_TAX=automatic turns on Stripe Tax in Checkout", async () => {
  const s = services();
  await buy(env({ STRIPE_TAX: "automatic" }));
  const { form } = s.calls.pop();
  assert.equal(form["automatic_tax[enabled]"], "true");
  assert.equal(form["tax_id_collection[enabled]"], "true");
});

test("STRIPE_TAX=managed sends Managed Payments only what Stripe's guide shows", async () => {
  // Stripe's list of refused parameters is not complete (it turned down
  // custom_text, which the list does not name), so the session is pinned
  // to exactly the keys its guide uses, plus our own metadata.
  const s = services();
  const res = await buy(env({ STRIPE_TAX: "managed" }));
  assert.equal(res.status, 303);
  const { form } = s.calls.pop();
  assert.deepEqual(Object.keys(form).sort(), [
    "cancel_url", "line_items[0][price]", "line_items[0][quantity]", "managed_payments[enabled]",
    "metadata[product]", "mode", "subscription_data[metadata][product]", "success_url",
  ]);
  assert.equal(form["managed_payments[enabled]"], "true");
});

test("a plan that is not one of the two, or a missing price, opens nothing", async () => {
  const s = services();
  const e = env();
  for (const plan of ["", "lifetime", "__proto__", "toString"]) {
    assert.equal((await buy(e, plan)).status, 400, plan);
  }
  assert.equal(s.calls.length, 0);
  delete s.prices.ranwhat_plus_annual;
  const res = await buy(e, "annual");
  assert.equal(res.status, 502);
  assert.match(await res.text(), /Nothing was charged/);
});

test("until every secret is set, checkout and the webhook say so and call nobody", async () => {
  for (const extra of [{ STRIPE_SECRET_KEY: undefined }, { STRIPE_WEBHOOK_SECRET: undefined },
                       { LIST_SECRET: undefined }, { RESEND_API_KEY: undefined }]) {
    const s = services();
    const e = env(extra);
    assert.equal((await buy(e)).status, 503);
    assert.equal((await call(e, "/api/welcome?session_id=cs_test_aaaaaaaaaaaa")).status, 503);
    assert.equal((await deliver(e, { type: "checkout.session.completed", data: { object: {} } })).status, 503);
    assert.equal(s.calls.length + s.emails.length, 0);
  }
});

/* ---------- the webhook ---------- */

test("an event without Stripe's signature, with another secret's, or an old one is refused", async () => {
  const s = services();
  const e = env();
  const { id } = await bought(s, e);
  const event = completedEvent(s, id);
  const { body } = signed(event);
  for (const headers of [{}, { "stripe-signature": "t=1,v1=00" }, { "stripe-signature": "garbage" }]) {
    assert.equal((await call(e, "/api/stripe", { method: "POST", headers, body })).status, 400);
  }
  assert.equal((await deliver(e, event, { secret: "whsec_someone_else" })).status, 400);
  assert.equal((await deliver(e, event, { at: now() - 600 })).status, 400);
  // A body changed after signing.
  const good = signed(event);
  const res = await call(e, "/api/stripe", { method: "POST", headers: { "stripe-signature": good.signature },
    body: good.body.replace("buyer@example.com", "thief@example.com") });
  assert.equal(res.status, 400);
  assert.equal(s.emails.length, 0);
});

test("a validly signed event cannot send the token anywhere Stripe does not say", async () => {
  // As if the signing secret had leaked: the event is signed, but its
  // contents are the sender's. The Worker asks Stripe for the session.
  const s = services();
  const e = env();
  const { id } = await bought(s, e);
  const forged = completedEvent(s, id);
  forged.data.object = { ...forged.data.object, customer_details: { email: "thief@example.com" } };
  assert.equal((await deliver(e, forged)).status, 200);
  assert.deepEqual(s.emails.map((m) => m.to[0]), ["buyer@example.com"]);
  assert.ok(s.calls.some((c) => c.key === `GET /v1/checkout/sessions/${id}`));

  // A session Stripe never made: acknowledged, nothing issued, no retry asked for.
  const made = { ...forged.data.object, id: "cs_test_neverexisted1" };
  assert.equal((await deliver(e, { type: "checkout.session.completed", data: { object: made } })).status, 200);
  assert.equal(s.emails.length, 1);
});

test("paying emails a token once, and the feed takes it", async () => {
  const s = services();
  const e = env();
  const { id } = await bought(s, e);
  assert.equal((await deliver(e, completedEvent(s, id))).status, 200);
  assert.equal(s.emails.length, 1);
  const [mail] = s.emails;
  assert.deepEqual(mail.to, ["buyer@example.com"]);
  assert.equal(mail.from, "ranwhat <updates@ranwhat.com>");
  const token = tokenIn(mail.text);
  assert.equal(tokenIn(mail.html), token);
  assert.match(mail.text, /RANWHAT_TOKEN=rw_\S+ uvx ranwhat update --save-token/);
  assert.match(mail.text, /\$env:RANWHAT_TOKEN="rw_\S+"; uvx ranwhat update --save-token/);
  assert.equal(await feed(e, token), 200);

  // Stripe delivers the same event again: no second email.
  assert.equal((await deliver(e, completedEvent(s, id))).status, 200);
  assert.equal(s.emails.length, 1);

  // D1 has the hash, the subscription and its status; not the token or the address.
  const dump = JSON.stringify([
    e.LIST.sql.prepare("SELECT * FROM tokens").all(),
    e.LIST.sql.prepare("SELECT * FROM subscriptions").all(),
    e.LIST.sql.prepare("SELECT * FROM token_subscriptions").all(),
  ]);
  assert.ok(!dump.includes(token));
  assert.ok(!dump.includes("buyer@example.com"));
  assert.match(dump, /"status":"active"/);
});

test("the welcome page shows the token at once, and it is the one the email brings", async () => {
  const s = services();
  const e = env();
  const { id } = await bought(s, e);
  const page = await call(e, `/api/welcome?session_id=${id}`);
  assert.equal(page.status, 200);
  assert.equal(page.headers.get("cache-control"), "no-store");
  assert.equal(page.headers.get("referrer-policy"), "no-referrer");
  assert.equal(page.headers.get("x-robots-tag"), "noindex");
  const html = await page.text();
  const token = tokenIn(html);
  assert.match(html, /A copy is on its way to buyer@example\.com/);
  assert.match(html, /\/api\/billing/);
  // Before Stripe's webhook has arrived, the token already works.
  assert.equal(await feed(e, token), 200);
  // Reloading shows the same token.
  assert.equal(tokenIn(await (await call(e, `/api/welcome?session_id=${id}`)).text()), token);

  await deliver(e, completedEvent(s, id));
  assert.equal(tokenIn(s.emails[0].text), token);
  assert.equal(e.LIST.sql.prepare("SELECT count(*) AS n FROM tokens").get().n, 1);
});

test("the welcome page shows nothing for an unpaid, unknown, foreign or day-old checkout", async () => {
  const s = services();
  const e = env();
  const open = (await buy(e)).headers.get("location").split("/").pop();
  assert.match(await (await call(e, `/api/welcome?session_id=${open}`)).text(), /still going through/);

  for (const q of ["", "?session_id=nope", "?session_id=cs_test_unknownunknown"]) {
    const res = await call(e, `/api/welcome${q}`);
    assert.equal(res.status, 404, q);
  }

  const { id: other } = await bought(s, e, { metadata: { product: "cenner-something" } });
  const res = await call(e, `/api/welcome?session_id=${other}`);
  assert.equal(res.status, 404);
  assert.doesNotMatch(await res.text(), /rw_/);

  const { id: old } = await bought(s, e);
  s.sessions.get(old).created = now() - 2 * 24 * 3600;
  const late = await (await call(e, `/api/welcome?session_id=${old}`)).text();
  assert.match(late, /in your email/);
  assert.doesNotMatch(late, /rw_/);
});

test("cancelling switches the token off, and nothing switches it back on", async () => {
  const s = services();
  const e = env();
  const { id, sub } = await bought(s, e);
  await deliver(e, completedEvent(s, id));
  const token = tokenIn(s.emails[0].text);

  // A failed renewal Stripe is still retrying keeps the feed on.
  sub.status = "past_due";
  await deliver(e, subEvent(sub));
  assert.equal(await feed(e, token), 200);

  sub.status = "canceled";
  assert.equal((await deliver(e, subEvent(sub, "customer.subscription.deleted"))).status, 200);
  assert.equal(await feed(e, token), 403);

  // An old "active" event arriving late is not believed: the status is fetched.
  await deliver(e, subEvent({ ...sub, status: "active" }));
  assert.equal(await feed(e, token), 403);
  // Even a fetch that raced the cancellation cannot bring it back.
  sub.status = "active";
  await deliver(e, subEvent(sub));
  assert.equal(await feed(e, token), 403);
  // Nor can the welcome page.
  assert.doesNotMatch(await (await call(e, `/api/welcome?session_id=${id}`)).text(), /rw_/);
});

test("unpaid and paused subscriptions are off until they are paid again", async () => {
  const s = services();
  const e = env();
  const { id, sub } = await bought(s, e);
  await deliver(e, completedEvent(s, id));
  const token = tokenIn(s.emails[0].text);
  for (const [status, code] of [["unpaid", 403], ["active", 200], ["paused", 403], ["active", 200]]) {
    sub.status = status;
    await deliver(e, subEvent(sub));
    assert.equal(await feed(e, token), code, status);
  }
});

test("when the email cannot go out, Stripe is told to retry, and the retry sends it", async () => {
  const s = services();
  const e = env();
  const { id } = await bought(s, e);
  s.fail["POST /emails"] = [429, { statusCode: 429, name: "daily_quota_exceeded" }];
  assert.equal((await deliver(e, completedEvent(s, id))).status, 500);
  delete s.fail["POST /emails"];
  assert.equal((await deliver(e, completedEvent(s, id))).status, 200);
  assert.equal(s.emails.length, 1);

  // Stripe unreachable while fetching the subscription: retry, nothing half done.
  const { id: second } = await bought(s, e, { email: "second@example.com" });
  s.fail["GET /v1/subscriptions"] = [500, { error: { type: "api_error" } }];
  assert.equal((await deliver(e, completedEvent(s, second))).status, 500);
  delete s.fail["GET /v1/subscriptions"];
  assert.equal((await deliver(e, completedEvent(s, second))).status, 200);
  assert.deepEqual(s.emails.map((m) => m.to[0]), ["buyer@example.com", "second@example.com"]);
});

test("another product's sales on the same Stripe account are ignored", async () => {
  const s = services();
  const e = env();
  const { id, sub } = await bought(s, e, { metadata: { product: "cenner-something" } });
  assert.equal((await deliver(e, completedEvent(s, id))).status, 200);
  const before = s.calls.length;
  assert.equal((await deliver(e, subEvent(sub))).status, 200);
  assert.equal(s.calls.length, before, "another site's subscription costs no call to Stripe");
  // A checkout for something else entirely, with no metadata at all.
  const bare = { id: "cs_test_bbbbbbbbbbbb", mode: "payment", status: "complete", payment_status: "paid",
                 customer_details: { email: "x@example.com" } };
  assert.equal((await deliver(e, { type: "checkout.session.completed", data: { object: bare } })).status, 200);
  assert.equal(s.emails.length, 0);
  const kept = e.LIST.sql.prepare("SELECT name FROM sqlite_master WHERE name = 'subscriptions'").get();
  assert.ok(!kept || e.LIST.sql.prepare("SELECT count(*) AS n FROM subscriptions").get().n === 0);
  // An event type this does not use is acknowledged and left alone.
  assert.equal((await deliver(e, { type: "invoice.paid", data: { object: {} } })).status, 200);
});

test("a token made by hand keeps working beside the paid ones", async () => {
  const s = services();
  const e = env();
  const { id } = await bought(s, e);
  await deliver(e, completedEvent(s, id));
  const run = spawnSync("python3", [join(ROOT, "scripts", "feed_token.py"), "new", "press: Ana"], { encoding: "utf8" });
  assert.equal(run.status, 0, run.stderr);
  e.LIST.sql.exec(run.stdout.match(/--command "([^"]+)"/)[1]);
  assert.equal(await feed(e, run.stdout.match(/^\s+(rw_\S+)$/m)[1]), 200);
});

/* ---------- billing ---------- */

test("the billing link goes to the portal login the setup script made, or to contact", async () => {
  const s = services();
  const e = env();
  const res = await call(e, "/api/billing");
  assert.equal(res.headers.get("location"), "https://ranwhat.com/contact?about=plus");
  s.portals.push(
    { id: "bpc_other", metadata: {}, login_page: { enabled: true, url: "https://billing.stripe.com/p/login/other" } },
    { id: "bpc_plus", metadata: PLUS, login_page: { enabled: true, url: "https://billing.stripe.com/p/login/plus" } });
  const ok = await call(e, "/api/billing");
  assert.equal(ok.status, 302);
  assert.equal(ok.headers.get("location"), "https://billing.stripe.com/p/login/plus");
});

/* ---------- logs ---------- */

test("nothing logged carries an address or a token", async () => {
  const lines = [];
  const real = console.log;
  console.log = (...a) => lines.push(a.join(" "));
  try {
    const s = services();
    const e = env();
    const { id } = await bought(s, e, { email: "secret.person@example.com" });
    await call(e, `/api/welcome?session_id=${id}`);
    s.fail["POST /emails"] = [500, { statusCode: 500, name: "application_error" }];
    await deliver(e, completedEvent(s, id));
    s.fail["GET /v1/prices"] = [500, { error: { type: "api_error" } }];
    await buy(e);
    s.fail["GET /v1/billing_portal"] = [401, { error: { type: "invalid_request_error" } }];
    await call(e, "/api/billing");
  } finally {
    console.log = real;
  }
  assert.ok(lines.length >= 3);
  for (const line of lines) assert.doesNotMatch(line, /@|secret\.person|rw_|sk_test/);
});
