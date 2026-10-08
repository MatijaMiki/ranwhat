/* The Stripe test-mode probe (worker/scripts/stripe_probe.mjs), against a
 * stand-in for Stripe that keeps what it was asked: no call leaves the
 * machine. It refuses a live or malformed key before any call, never
 * prints the key, reports Stripe's own words and the permission a 403
 * names, cleans up after a failure, and calls the Worker's own functions,
 * which send exactly what they send in production.
 *
 *     node --test --test-timeout=60000 worker/test/stripe_probe.test.mjs
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const SCRIPT = fileURLToPath(new URL("../scripts/stripe_probe.mjs", import.meta.url));
const probeModule = await import("../scripts/stripe_probe.mjs");
const { probe, USES, keyCheck, taxSetting } = probeModule;
const stripeJs = await import("../src/stripe.js");
const billingJs = await import("../src/billing.js");

const PLUS = { product: "ranwhat-plus" };
const B62 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
/* A key body of random letters and digits, ending in four letters that
   appear nowhere else in the output. Split prefixes, so that nothing
   shaped like a key sits in the source. */
const body = () => [...randomBytes(36)].map((b) => B62[b % 62]).join("") + "WQZK";
const SECRET = "sk_" + "test_";
const RESTRICTED = "rk_" + "test_";

/* ---------- a stand-in for Stripe ---------- */

/* Stripe as far as the probe and the functions it calls use it. fail:
   "METHOD /path" prefix -> [status, error] or a function of the form
   returning one (or null to answer as usual). */
function stripeStandIn(key, { prices = true, portal = true } = {}) {
  const s = {
    prices: prices ? [
      { id: "price_monthly1", lookup_key: "ranwhat_plus_monthly", active: true },
      { id: "price_annual1", lookup_key: "ranwhat_plus_annual", active: true },
    ] : [],
    portals: [
      { id: "bpc_default", metadata: {}, active: true },
      ...(portal ? [{ id: "bpc_plus", metadata: PLUS, active: true,
        login_page: { enabled: true, url: "https://billing.stripe.com/p/login/plus" } }] : []),
    ],
    customers: new Map(), sessions: new Map(), portalSessions: [], calls: [], fail: {}, lose: {},
  };
  const reply = (status, json) => new Response(JSON.stringify(json), { status });
  const missing = () => reply(404, { error: { type: "invalid_request_error", code: "resource_missing",
    message: "No such object." } });
  const under = (form, prefix) => Object.fromEntries(Object.entries(form)
    .filter(([k]) => k.startsWith(`${prefix}[`) && k.indexOf("[", prefix.length + 1) === -1)
    .map(([k, v]) => [k.slice(prefix.length + 1, -1), v]));
  s.fetch = async (url, init = {}) => {
    const u = new URL(String(url));
    const method = init.method || "GET";
    const route = `${method} ${u.pathname}`;
    assert.equal(u.origin, "https://api.stripe.com", "the probe calls Stripe and nothing else");
    assert.equal(init.headers.authorization, `Bearer ${key}`, "the key goes in the header, as the Worker sends it");
    const form = Object.fromEntries(method === "GET" ? u.searchParams : new URLSearchParams(init.body || ""));
    s.calls.push({ route, form });
    for (const [prefix, answer] of Object.entries(s.fail)) {
      if (!route.startsWith(prefix)) continue;
      const said = typeof answer === "function" ? answer(form) : answer;
      if (said) return reply(said[0], { error: said[1] });
    }
    const out = answer(method, u, route, form);
    /* A reply lost on the way back: Stripe did it, the caller never hears. */
    for (const prefix of Object.keys(s.lose)) {
      if (route.startsWith(prefix) && s.lose[prefix]-- > 0) throw new TypeError("fetch failed");
    }
    return out;
  };
  const answer = (method, u, route, form) => {
    if (route === "GET /v1/prices") {
      return reply(200, { object: "list", data: s.prices.filter((p) => p.lookup_key === form["lookup_keys[0]"] &&
        String(p.active) === form.active) });
    }
    if (route === "POST /v1/customers") {
      const id = `cus_probe${s.customers.size + 1}x`;
      s.customers.set(id, { id, object: "customer", livemode: false, email: form.email, metadata: under(form, "metadata") });
      return reply(200, s.customers.get(id));
    }
    if (route === "GET /v1/customers") {
      return reply(200, { object: "list", data: [...s.customers.values()].filter((c) => !c.deleted &&
        c.email === form.email) });
    }
    let m = u.pathname.match(/^\/v1\/customers\/([^/]+)$/);
    if (m) {
      const c = s.customers.get(m[1]);
      if (!c || c.deleted) return missing();
      if (method === "DELETE") {
        c.deleted = true;
        return reply(200, { id: c.id, object: "customer", deleted: true });
      }
      if (method === "POST") c.email = form.email ?? c.email;
      return reply(200, c);
    }
    if (route === "POST /v1/checkout/sessions") {
      if (form.customer && (!s.customers.has(form.customer) || s.customers.get(form.customer).deleted)) {
        return reply(400, { error: { type: "invalid_request_error", code: "resource_missing", param: "customer",
          message: `No such customer: '${form.customer}'` } });
      }
      const id = `cs_test_probe${String(s.sessions.size + 1).padStart(8, "0")}`;
      const session = { id, object: "checkout.session", url: `https://checkout.stripe.com/c/pay/${id}`,
        mode: form.mode, status: "open", payment_status: "unpaid", livemode: false,
        expires_at: form.expires_at ? Number(form.expires_at) : Math.floor(Date.now() / 1000) + 24 * 3600,
        metadata: under(form, "metadata"), client_reference_id: form.client_reference_id ?? null,
        customer: form.customer ?? null, subscription: null, form };
      s.sessions.set(id, session);
      return reply(200, session);
    }
    if (route === "GET /v1/checkout/sessions") {
      return reply(200, { object: "list", data: [...s.sessions.values()].filter((x) =>
        (!form.customer || x.customer === form.customer) && (!form.status || x.status === form.status)) });
    }
    m = u.pathname.match(/^\/v1\/checkout\/sessions\/([^/]+)\/expire$/);
    if (method === "POST" && m) {
      const x = s.sessions.get(m[1]);
      if (!x) return missing();
      if (x.status !== "open") {
        return reply(400, { error: { type: "invalid_request_error",
          message: "Only Checkout Sessions with a status of open can be expired." } });
      }
      x.status = "expired";
      return reply(200, x);
    }
    m = u.pathname.match(/^\/v1\/checkout\/sessions\/([^/]+)$/);
    if (method === "GET" && m) return s.sessions.has(m[1]) ? reply(200, s.sessions.get(m[1])) : missing();
    if (route === "GET /v1/billing_portal/configurations") {
      return reply(200, { object: "list", data: s.portals.filter((c) => String(c.active) === form.active) });
    }
    if (route === "POST /v1/billing_portal/sessions") {
      if (!s.customers.has(form.customer)) return missing();
      const n = s.portalSessions.length + 1;
      const made = { id: `bps_probe${n}`, object: "billing_portal.session", customer: form.customer,
        configuration: form.configuration || "bpc_default", return_url: form.return_url ?? null,
        url: `https://billing.stripe.com/p/session/test_probe${n}` };
      s.portalSessions.push(made);
      return reply(200, made);
    }
    return missing();
  };
  return s;
}

/* The probe run against the stand-in, its output kept. */
async function run(key, stand, { environment = {} } = {}) {
  const fetch = globalThis.fetch;
  globalThis.fetch = stand.fetch;
  const out = [], err = [];
  try {
    const code = await probe({
      environment: { STRIPE_SECRET_KEY: key, ...environment },
      print: (line) => out.push(line),
      complain: (line) => err.push(line),
    });
    assert.equal(globalThis.fetch, stand.fetch, "the probe puts fetch back as it found it");
    return { code, out: out.join("\n"), err: err.join("\n"), lines: out };
  } finally {
    globalThis.fetch = fetch;
  }
}

const line = (r, letter) => r.lines.find((l) => l.startsWith(`(${letter}) `)) || "";
const summary = (r) => r.lines.at(-1);

/* Neither the key, nor its body, nor any eight characters of it, nor
   its last four after Stripe's mask, appear in the output. */
function keptSecret(text, key) {
  const k = key.slice(SECRET.length);
  assert.ok(!text.includes(key), "the key is not printed");
  for (let i = 0; i + 8 <= k.length; i += 1) assert.ok(!text.includes(k.slice(i, i + 8)), "no part of the key is printed");
  assert.ok(!text.includes(k.slice(-4)), "nor its last four characters");
}

/* Every Checkout the run opened is expired, and every customer it made is deleted. */
function allCleanedUp(stand) {
  assert.ok([...stand.sessions.values()].every((x) => x.status === "expired"),
    [...stand.sessions.values()].map((x) => `${x.id} ${x.status}`).join(", "));
  assert.ok([...stand.customers.values()].every((c) => c.deleted), "every customer made is deleted");
}

/* ---------- the key ---------- */

test("live, publishable, missing and malformed keys are refused, with no call to Stripe", async () => {
  const b = body();
  const refused = [
    [undefined, /not set/], ["", /not set/], ["   ", /not set/],
    ["sk_" + "live_" + b, /live-mode key/], ["rk_" + "live_" + b, /live-mode key/],
    ["pk_" + "test_" + b, /not a Stripe test-mode key/], ["pk_" + "live_" + b, /not a Stripe test-mode key/],
    [SECRET, /not a Stripe test-mode key/], [SECRET + "short", /not a Stripe test-mode key/],
    [SECRET + b + " " + b, /not a Stripe test-mode key/], [SECRET + b + "!", /not a Stripe test-mode key/],
    [RESTRICTED + b.slice(0, 10) + "-" + b.slice(10), /not a Stripe test-mode key/],
    ["whsec_" + b, /not a Stripe test-mode key/], [b, /not a Stripe test-mode key/],
  ];
  for (const [key, reason] of refused) {
    const stand = stripeStandIn(String(key));
    const r = await run(key, stand);
    assert.equal(r.code, 2, String(key && key.slice(0, 3)));
    assert.match(r.err, reason);
    assert.match(r.err, /nothing was sent to Stripe/);
    assert.equal(r.out, "");
    assert.deepEqual(stand.calls, [], "no call to Stripe");
    keptSecret(r.err, SECRET + b);
  }
  assert.equal(keyCheck(` ${SECRET}${b}\n`).kind, "secret", "the surrounding whitespace of a pasted key is dropped");
  assert.equal(keyCheck(RESTRICTED + b).kind, "restricted");
});

test("run as a script, it exits 2 for a live or malformed key before anything is fetched", () => {
  /* fetch is replaced before the script loads, so that any call to it
     at all is seen and stops the run. */
  const trap = "data:text/javascript," + encodeURIComponent(
    "globalThis.fetch = () => { process.stderr.write('FETCHED'); process.exit(99); };");
  const b = body();
  for (const key of ["sk_" + "live_" + b, "rk_" + "live_" + b, SECRET + "x", ""]) {
    const r = spawnSync(process.execPath, ["--import", trap, SCRIPT], {
      env: { ...process.env, STRIPE_SECRET_KEY: key, STRIPE_TAX: "" }, encoding: "utf8", timeout: 30000,
    });
    assert.equal(r.status, 2, r.stderr);
    assert.ok(!r.stderr.includes("FETCHED"), "nothing was fetched");
    assert.match(r.stderr, /stripe probe: refused, and nothing was sent to Stripe/);
    assert.equal(r.stdout, "");
    keptSecret(r.stdout + r.stderr, SECRET + b);
  }
});

/* ---------- the checks ---------- */

test("with Stripe taking everything, every check passes, and all of it is cleaned up", async () => {
  const key = SECRET + body();
  const stand = stripeStandIn(key);
  const r = await run(key, stand);
  assert.equal(r.code, 0, r.out);
  for (const letter of "abcde") assert.match(line(r, letter), new RegExp(`^\\(${letter}\\) PASS `), r.out);
  assert.match(line(r, "f"), /^\(f\) SKIPPED .*restricted key/);
  assert.match(line(r, "b"), /Stripe took expires_at \(it closes in 31 minutes\), with no retry/);
  assert.match(line(r, "c"), /expired cs_test_probe00000001, which Stripe now says is expired/);
  assert.match(line(r, "d"), /on bpc_plus, the configuration stripe_setup\.py made/);
  assert.match(line(r, "d"), /login page, where \/api\/billing sends subscribers, is on/);
  assert.match(line(r, "e"), /Stripe now has the new one/);
  assert.match(r.out, /the Worker logged: stripe billing email: moved to the owner/);
  assert.equal(r.lines.filter((l) => l.startsWith("stripe probe: PASS")).length, 1, "one summary line");
  assert.equal(summary(r), "stripe probe: PASS. (a) pass, (b) pass, (c) pass, (d) pass, (e) pass, (f) skipped; " +
    "test mode, a secret key, STRIPE_TAX=managed; cleaned up 2 Checkout sessions and 1 customer.");
  assert.equal(stand.sessions.size, 2);
  assert.equal(stand.customers.size, 1);
  allCleanedUp(stand);
  keptSecret(r.out, key);
  /* The addresses given to Stripe take no mail. */
  for (const c of stand.calls) {
    for (const [k, v] of Object.entries(c.form)) if (/email/.test(k)) assert.match(v, /@example\.com$/);
  }
});

test("it calls the Worker's own functions, which send Stripe exactly what they send in production", async () => {
  assert.equal(USES.stripe, stripeJs.stripe);
  assert.equal(USES.orgCustomer, stripeJs.orgCustomer);
  assert.equal(USES.orgCheckout, stripeJs.orgCheckout);
  assert.equal(USES.portalSession, stripeJs.portalSession);
  assert.equal(USES.customerEmail, stripeJs.customerEmail);
  assert.equal(USES.billingEmailFollows, billingJs.billingEmailFollows);
  /* No Stripe call of its own but the lookups and the cleanup. */
  const source = readFileSync(SCRIPT, "utf8");
  assert.ok(!/fetch\(\s*[`"']https:/.test(source), "every call goes through the Worker's stripe()");
  const own = [...source.matchAll(/stripe\(env,\s*"(\w+)",\s*[`"]([^`"]+)[`"]/g)].map((m) => `${m[1]} ${m[2]}`).sort();
  assert.deepEqual(own, [
    "DELETE /customers/${id}", "GET /billing_portal/configurations", "GET /checkout/sessions",
    "GET /checkout/sessions/${first.id}", "GET /checkout/sessions/${id}", "GET /customers",
    "POST /checkout/sessions/${id}/expire",
  ].sort());

  for (const tax of ["managed", "automatic", "off"]) {
    const key = SECRET + body();
    const stand = stripeStandIn(key);
    const r = await run(key, stand, { environment: tax === "managed" ? {} : { STRIPE_TAX: tax } });
    assert.equal(r.code, 0, r.out);
    assert.match(r.lines[0], new RegExp(`STRIPE_TAX=${tax},`));
    const sent = (route) => stand.calls.filter((c) => c.route === route).map((c) => c.form);
    const [customerForm] = sent("POST /v1/customers");
    const checkouts = sent("POST /v1/checkout/sessions");
    const [portalForm] = sent("POST /v1/billing_portal/sessions");
    const org = customerForm["metadata[org]"];
    const customer = checkouts[0].customer;

    /* The same calls, made straight to the Worker's functions with the
       same arguments: the same parameters, the clock's aside. */
    const direct = stripeStandIn(key);
    const fetch = globalThis.fetch;
    globalThis.fetch = direct.fetch;
    const env = { STRIPE_SECRET_KEY: key, STRIPE_TAX: tax, ACCOUNTS_ON: "1" };
    try {
      const made = await stripeJs.orgCustomer(env, { org, email: customerForm.email });
      assert.equal(made, customer);
      await stripeJs.orgCheckout(env, { org, interval: "monthly", customer });
      await stripeJs.orgCheckout(env, { org, interval: "yearly", customer });
      await stripeJs.portalSession(env, customer);
    } finally {
      globalThis.fetch = fetch;
    }
    const clockless = (form) => ({ ...form, expires_at: typeof form.expires_at });
    const directly = (route) => direct.calls.filter((c) => c.route === route).map((c) => c.form);
    assert.deepEqual(customerForm, directly("POST /v1/customers")[0]);
    assert.deepEqual(checkouts.map(clockless), directly("POST /v1/checkout/sessions").map(clockless));
    assert.deepEqual(portalForm, directly("POST /v1/billing_portal/sessions")[0]);
    assert.deepEqual(sent("GET /v1/prices"), directly("GET /v1/prices"));
    assert.deepEqual(sent("GET /v1/checkout/sessions")[0], directly("GET /v1/checkout/sessions")[0]);

    /* And they are what the account pages need of Stripe. */
    assert.equal(customerForm["metadata[product]"], "ranwhat-plus");
    assert.match(org, /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);
    for (const form of checkouts) {
      assert.equal(form.client_reference_id, org);
      assert.equal(form["metadata[org]"], org);
      assert.equal(form["subscription_data[metadata][org]"], org);
      assert.equal(form["subscription_data[metadata][product]"], "ranwhat-plus");
      assert.ok(Number(form.expires_at) > 0);
      assert.equal(form["managed_payments[enabled]"], tax === "managed" ? "true" : undefined);
      assert.equal(form["automatic_tax[enabled]"], tax === "automatic" ? "true" : undefined);
      assert.equal(form["customer_update[address]"], tax === "managed" ? undefined : "auto");
    }
    assert.deepEqual([checkouts[0]["line_items[0][price]"], checkouts[1]["line_items[0][price]"]],
      ["price_monthly1", "price_annual1"]);
    assert.equal(portalForm.configuration, "bpc_plus");
    assert.equal(portalForm.return_url, "https://account.ranwhat.com/billing");
    /* billingEmailFollows() read the customer's address and moved it to the owner's. */
    const moved = stand.calls.filter((c) => c.route === `POST /v1/customers/${customer}`).map((c) => c.form);
    assert.equal(moved.length, 1);
    assert.match(moved[0].email, /^stripe-probe-new-owner-[0-9a-f]{8}@example\.com$/);
    allCleanedUp(stand);
  }
});

test("without STRIPE_TAX, the tax setting is wrangler.toml's", () => {
  const toml = readFileSync(new URL("../wrangler.toml", import.meta.url), "utf8");
  const set = /^STRIPE_TAX\s*=\s*"([^"]*)"/m.exec(toml)[1];
  assert.equal(taxSetting({}), set);
  assert.equal(taxSetting({ STRIPE_TAX: "" }), set);
  assert.equal(taxSetting({ STRIPE_TAX: "off" }), "off");
});

test("expires_at turned down: the Worker's retry without it is reported, and the check passes", async () => {
  const key = SECRET + body();
  const stand = stripeStandIn(key);
  stand.fail["POST /v1/checkout/sessions"] = (form) => (form.expires_at ? [400, {
    type: "invalid_request_error", code: "parameter_unknown", param: "expires_at",
    message: "Received unknown parameter: expires_at" }] : null);
  const r = await run(key, stand);
  assert.equal(r.code, 0, r.out);
  assert.match(line(r, "b"), /^\(b\) PASS .*Stripe turned down expires_at \(Stripe answered 400 \(parameter_unknown, param expires_at\) to POST \/v1\/checkout\/sessions: Received unknown parameter: expires_at\), and the Worker's retry without it was taken/);
  assert.match(line(r, "c"), /again without expires_at/);
  assert.match(r.out, /the Worker logged: stripe org checkout: parameter_unknown, without expires_at/);
  allCleanedUp(stand);
});

/* ---------- failures ---------- */

test("a check that fails says so in Stripe's words, and everything is still cleaned up", async () => {
  const key = SECRET + body();
  const stand = stripeStandIn(key);
  stand.fail["POST /v1/billing_portal/sessions"] = [400, { type: "invalid_request_error",
    message: "You can't create a portal session in test mode until you save your customer portal settings." }];
  const r = await run(key, stand);
  assert.equal(r.code, 1);
  assert.match(line(r, "d"), /^\(d\) FAIL .*Stripe answered 400 \(invalid_request_error\) to POST \/v1\/billing_portal\/sessions: You can't create a portal session/);
  for (const letter of "abce") assert.match(line(r, letter), /^\(\w\) PASS /);
  assert.match(summary(r), /^stripe probe: FAIL\. .*\(d\) fail.*cleaned up 2 Checkout sessions and 1 customer\.$/);
  allCleanedUp(stand);
  keptSecret(r.out, key);
});

test("Managed Payments turned down: the Checkouts fail, and the customer is still deleted", async () => {
  const key = SECRET + body();
  const stand = stripeStandIn(key);
  stand.fail["POST /v1/checkout/sessions"] = [400, { type: "invalid_request_error", code: "parameter_unknown",
    param: "managed_payments", message: "Received unknown parameter: managed_payments" }];
  const r = await run(key, stand);
  assert.equal(r.code, 1);
  assert.match(line(r, "b"), /^\(b\) FAIL .*\(parameter_unknown, param managed_payments\).*Received unknown parameter: managed_payments/);
  assert.match(line(r, "c"), /^\(c\) NOT RUN .*needs the Checkout from \(b\)/);
  assert.match(line(r, "d"), /^\(d\) PASS /);
  assert.match(summary(r), /\(c\) not run.*cleaned up 0 Checkout sessions and 1 customer\.$/);
  allCleanedUp(stand);
});

test("no portal of ours: says which stripe_setup.py command makes it", async () => {
  const key = SECRET + body();
  const stand = stripeStandIn(key, { portal: false });
  const r = await run(key, stand);
  assert.equal(r.code, 1);
  assert.match(line(r, "d"), /^\(d\) FAIL .*No active portal configuration in test mode has metadata product=ranwhat-plus\. scripts\/stripe_setup\.py makes it: STRIPE_SECRET_KEY=<test secret key> python3 scripts\/stripe_setup\.py/);
  assert.match(line(r, "d"), /on its default configuration instead/);
  allCleanedUp(stand);

  /* And with no default either, Stripe's refusal as well. */
  const bare = stripeStandIn(key, { portal: false });
  bare.fail["POST /v1/billing_portal/sessions"] = [400, { type: "invalid_request_error",
    message: "No configuration provided and your test mode default configuration has not been created." }];
  const again = await run(key, bare);
  assert.match(line(again, "d"), /python3 scripts\/stripe_setup\.py Stripe's default configuration was tried instead, and Stripe answered 400.*default configuration has not been created/);
  allCleanedUp(bare);
});

test("no prices: says which stripe_setup.py command makes them, and cleans up", async () => {
  const key = SECRET + body();
  const stand = stripeStandIn(key, { prices: false });
  const r = await run(key, stand);
  assert.equal(r.code, 1);
  assert.match(line(r, "b"), /^\(b\) FAIL .*no active price with lookup key ranwhat_plus_monthly in test mode\. scripts\/stripe_setup\.py makes the product and both prices: STRIPE_SECRET_KEY=<test secret key> python3 scripts\/stripe_setup\.py$/);
  assert.match(line(r, "c"), /NOT RUN/);
  assert.equal(stand.sessions.size, 0);
  allCleanedUp(stand);
});

test("replies lost on the way back: what Stripe made anyway is found and cleaned up", async () => {
  const key = SECRET + body();
  const stand = stripeStandIn(key);
  /* The customer is made, but its reply never arrives. */
  stand.lose["POST /v1/customers"] = 1;
  const r = await run(key, stand);
  assert.equal(r.code, 1);
  assert.match(line(r, "a"), /^\(a\) FAIL .*Stripe could not be reached for POST \/v1\/customers/);
  for (const letter of "bcde") assert.match(line(r, letter), /NOT RUN/);
  assert.equal(stand.customers.size, 1);
  allCleanedUp(stand);
  assert.match(summary(r), /cleaned up 0 Checkout sessions and 1 customer\.$/);

  /* A Checkout made whose reply is lost: found by the customer's open ones. */
  const other = stripeStandIn(key);
  other.lose["POST /v1/checkout/sessions"] = 1;
  const again = await run(key, other);
  assert.match(line(again, "b"), /^\(b\) FAIL .*could not be reached/);
  assert.equal(other.sessions.size, 1);
  allCleanedUp(other);
});

test("what cleanup cannot do is listed, and the run fails", async () => {
  const key = SECRET + body();
  const stand = stripeStandIn(key);
  stand.fail["DELETE /v1/customers/"] = [500, { type: "api_error", message: "An unknown error occurred." }];
  const r = await run(key, stand);
  assert.equal(r.code, 1);
  for (const letter of "abcde") assert.match(line(r, letter), /PASS/);
  assert.match(r.out, /Left behind in Stripe's test mode, to delete in the dashboard: customer cus_probe1x \(Stripe answered 500 \(api_error\) to DELETE \/v1\/customers\/cus_probe1x: An unknown error occurred\.\)\./);
  assert.match(summary(r), /^stripe probe: FAIL\. .*cleanup left 1 thing behind\.$/);
});

test("a restricted key: each 403 with the permission Stripe names, and no part of the key printed", async () => {
  const key = RESTRICTED + body();
  const stand = stripeStandIn(key);
  /* As Stripe words it: the key by its prefix and last four, behind a mask. */
  const masked = RESTRICTED + "*".repeat(24) + key.slice(-4);
  const denied = (permission) => [403, { type: "invalid_request_error",
    message: `The provided key '${masked}' does not have the required permissions for this endpoint on account ` +
      `'acct_1Probe'. Having the '${permission}' permission would allow this request to continue.` }];
  stand.fail["POST /v1/billing_portal/sessions"] = denied("rak_customer_portal_write");
  /* And a message that quotes the whole key, which Stripe's do not, should one ever. */
  stand.fail["POST /v1/customers/"] = [403, { type: "invalid_request_error",
    message: `Key ${key} may not do this: 'rak_customer_write'.` }];
  const r = await run(key, stand);
  assert.equal(r.code, 1);
  assert.match(r.lines[0], /a restricted key/);
  assert.match(line(r, "d"), /^\(d\) FAIL .*Stripe answered 403 \(invalid_request_error\) to POST \/v1\/billing_portal\/sessions: The provided key '\[key\]' does not have/);
  assert.match(line(r, "e"), /^\(e\) FAIL .*Stripe answered 403 \(invalid_request_error\) to POST \/v1\/customers\/cus_probe1x: Key \[key\] may not do this/);
  const f = line(r, "f");
  assert.match(f, /^\(f\) FAIL {2}the restricted key's permissions: Stripe refused 2 calls with a 403\./);
  assert.match(f, /POST \/v1\/billing_portal\/sessions needs rak_customer_portal_write/);
  assert.match(f, /POST \/v1\/customers\/cus_probe1x needs rak_customer_write/);
  keptSecret(r.out, key);
  allCleanedUp(stand);

  /* With every permission, (f) passes. */
  const fine = stripeStandIn(key);
  const ok = await run(key, fine);
  assert.equal(ok.code, 0, ok.out);
  assert.match(line(ok, "f"), /^\(f\) PASS .*refused none of the calls, cleanup's included/);
  assert.match(summary(ok), /\(f\) pass; test mode, a restricted key,/);
});

test("a key Stripe does not know: Stripe's words, with the key Stripe quotes cut out", async () => {
  const key = RESTRICTED + body();
  const stand = stripeStandIn(key);
  stand.fail["POST /v1/"] = [401, { type: "invalid_request_error",
    message: `Invalid API Key provided: ${RESTRICTED}${"*".repeat(30)}${key.slice(-4)}` }];
  stand.fail["GET /v1/"] = stand.fail["POST /v1/"];
  const r = await run(key, stand);
  assert.equal(r.code, 1);
  assert.match(line(r, "a"), /^\(a\) FAIL .*Stripe answered 401 \(invalid_request_error\) to POST \/v1\/customers: Invalid API Key provided: \[key\]$/);
  assert.match(line(r, "f"), /^\(f\) NOT RUN .*\(b\) and \(c\) and \(d\) and \(e\) did not run/);
  assert.match(summary(r), /\(f\) not run; .*cleaned up 0 Checkout sessions and 0 customers\.$/);
  keptSecret(r.out, key);
});

test("CI runs this file", () => {
  const ci = readFileSync(new URL("../../.github/workflows/tests.yml", import.meta.url), "utf8");
  const [run] = ci.split("\n").map((l) => l.trim()).filter((l) => l.startsWith("- run: node --test worker/test/"));
  assert.ok(run && run.split(" ").includes("worker/test/stripe_probe.test.mjs"), run);
});
