/* A check, run once in Stripe's test mode before accounts go live, that
 * Stripe accepts the requests the account pages make, exactly as the
 * Worker makes them. The Worker's own tests answer for Stripe with
 * stand-ins, so they show what is asked of Stripe, not that Stripe takes
 * it; this asks Stripe itself.
 *
 *     STRIPE_SECRET_KEY=<test key> node worker/scripts/stripe_probe.mjs
 *
 * The key is a test-mode one: the secret key, or the restricted key the
 * Worker is to run with, whose permissions this then checks too. Any
 * other, a live key above all, is refused before anything is sent. The
 * key goes to api.stripe.com and nowhere else, and neither it nor any
 * part of it is printed: Stripe's own messages, which name a key by its
 * prefix and last four characters, are printed with the key cut out.
 *
 * It calls the Worker's own functions (stripe.js and billing.js) with the
 * real fetch, and with STRIPE_TAX from the environment or, without it, as
 * wrangler.toml sets it. The checks:
 *   (a) orgCustomer()          the organisation's own customer, made with
 *                              its owner's address
 *   (b) orgCheckout()          a Checkout bound to the organisation, and
 *                              whether Stripe turned down its expiry, so
 *                              that the Worker retried without one
 *   (c) orgCheckout() again    its closeOpen() lists the customer's open
 *                              Checkouts and expires the first
 *   (d) portalSession()        Manage billing's portal session, on the
 *                              portal scripts/stripe_setup.py made
 *   (e) billingEmailFollows()  the customer's email moved to a new
 *                              owner's, over worker/test's SQLite
 *                              stand-in for D1
 *   (f) with a restricted key, every call Stripe refused with a 403, and
 *       the permission Stripe names for it
 * Whatever happens, it then expires every Checkout it opened and deletes
 * the customer it made, found from Stripe's replies or, should a reply be
 * lost, by the run's own addresses. A portal session cannot be ended
 * through Stripe's API; it lapses by itself. It prints what it runs with,
 * a line for each check and, last, one summary line, and exits 0 when
 * everything passed, 1 when anything failed or was left behind, and 2 when
 * the key was refused.
 *
 * The product, its two prices (found by lookup key, as the Worker finds
 * them) and the portal are made by scripts/stripe_setup.py, run once with
 * the test secret key; this says so when they are missing. The addresses
 * it gives Stripe are on example.com, which takes no mail.
 */
import { readFileSync, realpathSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { ACCOUNT_ORIGIN, schema as accountsSchema } from "../src/accounts.js";
import { CHECKOUT_ORIGIN, PORTAL_ORIGIN, billingEmailDue, billingEmailFollows } from "../src/billing.js";
import {
  CUSTOMER, INTERVALS, ORG_CHECKOUT_FOR, PRODUCT, customerEmail, orgCheckout, orgCustomer, portalSession, stripe,
} from "../src/stripe.js";

/* What this calls, as the Worker has it. worker/test/stripe_probe.test.mjs
   checks that each is the Worker's own. */
export const USES = Object.freeze({ stripe, orgCustomer, orgCheckout, portalSession, billingEmailFollows, customerEmail });

/* Split, so that nothing shaped like a key sits in the source. */
const TEST_KEYS = Object.freeze({ secret: "sk_" + "test_", restricted: "rk_" + "test_" });
const LIVE_KEYS = Object.freeze(["sk_" + "live_", "rk_" + "live_"]);
const KEY_BODY = /^[A-Za-z0-9]{20,250}$/;

const SETUP = "STRIPE_SECRET_KEY=<test secret key> python3 scripts/stripe_setup.py";
const STRIPE_API = "https://api.stripe.com";

const now = () => Math.floor(Date.now() / 1000);
const count = (n, one, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;

/* { kind: "secret" or "restricted", key } for a test-mode key, or
   { refused: why } for anything else. Never quotes the key. */
export function keyCheck(value) {
  const key = typeof value === "string" ? value.trim() : "";
  if (!key) return { refused: "STRIPE_SECRET_KEY is not set." };
  if (LIVE_KEYS.some((prefix) => key.startsWith(prefix))) {
    return { refused: "STRIPE_SECRET_KEY is a live-mode key. This makes and deletes customers and Checkouts, " +
      "so it runs in test mode only." };
  }
  for (const [kind, prefix] of Object.entries(TEST_KEYS)) {
    if (key.startsWith(prefix) && KEY_BODY.test(key.slice(prefix.length))) return { kind, key };
  }
  return { refused: "STRIPE_SECRET_KEY is not a Stripe test-mode key: the test secret key, or a restricted " +
    "key made in test mode, as the Stripe dashboard shows it." };
}

/* STRIPE_TAX as the Worker has it: from the environment, or else as
   wrangler.toml's [vars] sets it, or else "managed". */
export function taxSetting(environment) {
  if (typeof environment.STRIPE_TAX === "string" && environment.STRIPE_TAX.trim()) return environment.STRIPE_TAX.trim();
  try {
    const toml = readFileSync(new URL("../wrangler.toml", import.meta.url), "utf8");
    const m = /^STRIPE_TAX\s*=\s*"([^"]*)"/m.exec(toml);
    if (m) return m[1];
  } catch { /* no wrangler.toml beside this script */ }
  return "managed";
}

/* Stripe's messages name a key by its prefix and last four characters,
   behind a run of asterisks: both cut out. */
export function scrub(text) {
  return String(text ?? "")
    .replace(/\b(?:sk|rk|pk)_(?:test|live)_[^\s'"]+/g, "[key]")
    .replace(/\*{4,}[A-Za-z0-9]{0,8}/g, "[key]");
}

/* The real fetch, watched: each call's method, path, the parameters sent
   and Stripe's answer, for the checks to read, since the Worker's stripe()
   keeps Stripe's error code and not its message. Nothing but
   api.stripe.com is let through. The headers, which carry the key, are
   not kept. */
function watched(fetch, calls) {
  return async (url, init = {}) => {
    const u = new URL(String(url));
    if (u.origin !== STRIPE_API) throw new Error(`the probe sends nothing to ${u.origin}`);
    const method = init.method || "GET";
    const call = {
      method, path: u.pathname, status: 0, body: null,
      sent: new URLSearchParams(method === "GET" ? u.search : String(init.body || "")),
    };
    calls.push(call);
    const res = await fetch(url, init);
    call.status = res.status;
    call.body = await res.clone().json().catch(() => null);
    return res;
  };
}

/* What Stripe said to one call, in its own words. */
function said(call) {
  const where = `${call.method} ${call.path}`;
  if (!call.status) return `Stripe could not be reached for ${where}.`;
  const e = (call.body && call.body.error) || {};
  const what = [e.code || e.type, e.param ? `param ${e.param}` : ""].filter(Boolean).join(", ");
  return `Stripe answered ${call.status}${what ? ` (${what})` : ""} to ${where}: ${scrub(e.message || "no message")}`;
}

/* Why a step failed: what Stripe said to the last of the step's calls
   that it refused or could not be reached for, or else the error's own
   code. */
function why(err, mine) {
  const refused = mine.findLast((c) => c.status === 0 || c.status >= 400);
  if (refused) return said(refused);
  return scrub((err && (err.code || err.message)) || "an error with no message");
}

/* The permissions Stripe names in a 403 for a restricted key. */
const permissions = (call) =>
  [...new Set([...scrub(call.body && call.body.error && call.body.error.message).matchAll(/'(rak_[a-z0-9_]+)'/g)]
    .map((m) => m[1]))];

/* A failure this script words itself, for check() to print as it is. */
const stop = (detail) => Object.assign(new Error(detail), { probe: detail });

const noPrice = (key) => `Stripe has no active price with lookup key ${key} in test mode. ` +
  `scripts/stripe_setup.py makes the product and both prices: ${SETUP}`;

/* Runs the checks and cleans up. Returns the exit code. */
export async function probe({
  environment = process.env,
  print = (line) => process.stdout.write(`${line}\n`),
  complain = (line) => process.stderr.write(`${line}\n`),
} = {}) {
  const k = keyCheck(environment.STRIPE_SECRET_KEY);
  if (k.refused) {
    complain(`stripe probe: refused, and nothing was sent to Stripe. ${k.refused}`);
    complain("Run it as: STRIPE_SECRET_KEY=<test key> node worker/scripts/stripe_probe.mjs");
    return 2;
  }
  /* Belt and braces: nothing printed carries the key, whatever it came in. */
  const body = k.key.slice(TEST_KEYS[k.kind].length);
  const say = (line) => print(String(line).split(k.key).join("[key]").split(body).join("[key]"));

  const tax = taxSetting(environment);
  const tag = crypto.randomUUID().slice(0, 8);
  const run = {
    org: crypto.randomUUID(),
    owner: `stripe-probe-owner-${tag}@example.com`,
    newOwner: `stripe-probe-new-owner-${tag}@example.com`,
  };
  const env = { STRIPE_SECRET_KEY: k.key, STRIPE_TAX: tax, ACCOUNTS_ON: "1" };
  const calls = [];
  const logs = [];
  const results = [];
  const fetch = globalThis.fetch;
  const log = console.log;
  say(`stripe probe: test mode, a ${k.kind} key, STRIPE_TAX=${tax}, organisation ${run.org}.`);

  /* One check: PASS or FAIL with why, and what the Worker logged during
     it, which is what it would log in production. */
  async function check(letter, what, fn, needs = null) {
    if (needs) {
      results.push({ letter, state: "not run" });
      say(`(${letter}) NOT RUN  ${what}: it needs ${needs}.`);
      return;
    }
    const from = calls.length, logged = logs.length;
    const mine = () => calls.slice(from);
    let r;
    try {
      r = await fn(mine);
    } catch (err) {
      r = { pass: false, detail: err && typeof err.probe === "string" ? err.probe : why(err, mine()) };
    }
    results.push({ letter, state: r.pass ? "pass" : "fail" });
    say(`(${letter}) ${r.pass ? "PASS" : "FAIL"}  ${what}: ${r.detail}`);
    for (const line of logs.slice(logged)) say(`      the Worker logged: ${scrub(line)}`);
  }
  const pass = (detail) => ({ pass: true, detail });
  const fail = (detail) => ({ pass: false, detail });

  let tidy = null, stopped = false;
  globalThis.fetch = watched(fetch, calls);
  console.log = (...args) => logs.push(args.join(" "));
  try {
    try {
      let customer = null, first = null;

      await check("a", "orgCustomer(), the organisation's own customer", async (mine) => {
        customer = await orgCustomer(env, { org: run.org, email: run.owner });
        const made = mine().findLast((c) => c.method === "POST" && c.path === "/v1/customers");
        const c = (made && made.body) || {};
        const wrong = [];
        if (c.email !== run.owner) wrong.push("its email is not the owner's address");
        if (!c.metadata || c.metadata.product !== PRODUCT || c.metadata.org !== run.org) {
          wrong.push("its metadata does not hold product and org");
        }
        if (c.livemode !== false) wrong.push("Stripe did not say it is a test-mode customer");
        return wrong.length ? fail(`made ${customer}, but ${wrong.join(", and ")}.`)
          : pass(`made ${customer} with the owner's address, and metadata product and org.`);
      });

      await check("b", "orgCheckout(), a Checkout bound to the organisation", async (mine) => {
        try {
          first = await orgCheckout(env, { org: run.org, interval: "monthly", customer });
        } catch (err) {
          if (String(err.code).startsWith("no active price")) throw stop(noPrice(INTERVALS.monthly));
          throw err;
        }
        const posts = mine().filter((c) => c.method === "POST" && c.path === "/v1/checkout/sessions");
        const retried = posts.length > 1;
        const price = mine().find((c) => c.method === "GET" && c.path === "/v1/prices");
        const priceId = price && price.body && price.body.data && price.body.data[0] && price.body.data[0].id;
        const wrong = [];
        if (first.customer !== customer) wrong.push("it is not on the organisation's customer");
        if (first.client_reference_id !== run.org) wrong.push("its client_reference_id is not the organisation");
        if (!first.metadata || first.metadata.product !== PRODUCT || first.metadata.org !== run.org) {
          wrong.push("its metadata does not hold product and org");
        }
        if (first.mode !== "subscription" || first.status !== "open") wrong.push("it is not an open subscription Checkout");
        if (typeof first.url !== "string" || !first.url.startsWith(`${CHECKOUT_ORIGIN}/`)) {
          wrong.push(`its address is not on ${CHECKOUT_ORIGIN}, so billing.js's upgradePost() would not send the browser to it`);
        }
        let expiry;
        if (retried) {
          expiry = `Stripe turned down expires_at (${said(posts[0])}), and the Worker's retry without it was taken, ` +
            "so this Checkout stays open for Stripe's default 24 hours.";
        } else {
          const left = Number(first.expires_at) - now();
          if (!(left > 29 * 60 && left <= ORG_CHECKOUT_FOR + 120)) {
            wrong.push(`it expires in ${Math.round(left / 60)} minutes, not ${ORG_CHECKOUT_FOR / 60}`);
          }
          expiry = `Stripe took expires_at (it closes in ${Math.round(left / 60)} minutes), with no retry.`;
        }
        return wrong.length ? fail(`opened ${first.id}, but ${wrong.join(", and ")}. ${expiry}`)
          : pass(`opened ${first.id} for the monthly price (lookup key ${INTERVALS.monthly}, ${priceId}) on ` +
            `${customer}, with client_reference_id and metadata product and org, and subscription_data metadata, ` +
            `which Stripe shows only on the subscription a payment makes. ${expiry}`);
      }, customer ? null : "the customer from (a)");

      await check("c", "orgCheckout() again, whose closeOpen() expires the first", async (mine) => {
        let second;
        try {
          second = await orgCheckout(env, { org: run.org, interval: "yearly", customer });
        } catch (err) {
          if (String(err.code).startsWith("no active price")) throw stop(noPrice(INTERVALS.yearly));
          throw err;
        }
        const listed = mine().find((c) => c.method === "GET" && c.path === "/v1/checkout/sessions");
        if (!listed) return fail("orgCheckout() did not list the customer's open Checkouts.");
        if (listed.status !== 200) return fail(`the list failed, so ${first.id} was left open. ${said(listed)}`);
        const sent = Object.fromEntries(listed.sent);
        const ids = ((listed.body && listed.body.data) || []).map((s) => s && s.id);
        if (!ids.includes(first.id)) {
          return fail(`Stripe listed ${count(ids.length, "open Checkout")} for customer=${sent.customer} and ` +
            `status=${sent.status}, without ${first.id}, so it was left open.`);
        }
        const expire = mine().find((c) => c.method === "POST" && c.path === `/v1/checkout/sessions/${first.id}/expire`);
        if (!expire) return fail(`${first.id} was listed, but its metadata as listed did not name the product and the organisation, so it was not expired.`);
        if (expire.status !== 200) return fail(`expiring ${first.id} failed. ${said(expire)}`);
        const after = await stripe(env, "GET", `/checkout/sessions/${first.id}`);
        if (after.status !== "expired") return fail(`Stripe accepted the expiry, but says ${first.id} is ${after.status}.`);
        const retried = mine().filter((c) => c.method === "POST" && c.path === "/v1/checkout/sessions").length > 1;
        return pass(`listed ${count(ids.length, "open Checkout")} on the customer (customer and status=open), ` +
          `expired ${first.id}, which Stripe now says is expired, and opened ${second.id} for the yearly price ` +
          `(lookup key ${INTERVALS.yearly})${retried ? ", again without expires_at" : ""}.`);
      }, first ? null : "the Checkout from (b)");

      await check("d", "portalSession(), Manage billing's portal", async (mine) => {
        const { data = [] } = await stripe(env, "GET", "/billing_portal/configurations", { active: true, limit: 100 });
        const ours = data.find((c) => c.metadata && c.metadata.product === PRODUCT);
        const missing = `No active portal configuration in test mode has metadata product=${PRODUCT}. ` +
          `scripts/stripe_setup.py makes it: ${SETUP}`;
        let portal;
        try {
          portal = await portalSession(env, customer);
        } catch (err) {
          if (!ours) throw stop(`${missing} Stripe's default configuration was tried instead, and ${why(err, mine())}`);
          throw err;
        }
        if (!ours) return fail(`${missing} Stripe opened ${portal.id} on its default configuration instead.`);
        const wrong = [];
        if (portal.configuration !== ours.id) wrong.push(`it is on ${portal.configuration}, not ${ours.id}`);
        if (typeof portal.url !== "string" || !portal.url.startsWith(`${PORTAL_ORIGIN}/`)) {
          wrong.push(`its address is not on ${PORTAL_ORIGIN}, so billing.js's billingPost() would not send the browser to it`);
        }
        if (portal.return_url !== `${ACCOUNT_ORIGIN}/billing`) wrong.push(`it returns to ${portal.return_url}, not ${ACCOUNT_ORIGIN}/billing`);
        const login = ours.login_page && ours.login_page.enabled
          ? "That configuration's login page, where /api/billing sends subscribers, is on."
          : `That configuration's login page is off, so /api/billing sends subscribers to the contact page: ${SETUP} switches it on.`;
        return wrong.length ? fail(`opened ${portal.id}, but ${wrong.join(", and ")}. ${login}`)
          : pass(`opened ${portal.id} on ${ours.id}, the configuration stripe_setup.py made, for the customer, ` +
            `returning to ${ACCOUNT_ORIGIN}/billing. ${login}`);
      }, customer ? null : "the customer from (a)");

      await check("e", "billingEmailFollows(), the customer's email moved to the owner's", async (mine) => {
        let d1;
        try {
          ({ d1 } = await import("../test/stand-ins.mjs"));
        } catch (err) {
          throw stop(`worker/test's SQLite stand-in did not load (node:sqlite needs Node 22.13 or later): ${scrub(err.message)}`);
        }
        /* As when the owner who made the customer hands ownership on: the
           organisation now has another owner, the old one is an admin, and
           the address Stripe has is the old owner's, which the batch that
           handed ownership on left to be checked. */
        const db = d1();
        env.LIST = db;
        await accountsSchema(db);
        const t = now(), user = crypto.randomUUID(), before = crypto.randomUUID();
        await db.batch([
          db.prepare("INSERT INTO users (id, email, created_at) VALUES (?, ?, ?)").bind(user, run.newOwner, t),
          db.prepare("INSERT INTO users (id, email, created_at) VALUES (?, ?, ?)").bind(before, run.owner, t),
          db.prepare("INSERT INTO orgs (id, name, personal, customer, created_at) VALUES (?, ?, 0, ?, ?)")
            .bind(run.org, "Stripe probe", customer, t),
          db.prepare("INSERT INTO memberships (org_id, user_id, role, created_at) VALUES (?, ?, 'owner', ?)")
            .bind(run.org, user, t),
          db.prepare("INSERT INTO memberships (org_id, user_id, role, created_at) VALUES (?, ?, 'admin', ?)")
            .bind(run.org, before, t),
          billingEmailDue(db, run.org, before),
        ]);
        await billingEmailFollows(env, run.org);
        /* billingEmailFollows() logs a failure and goes on, as it runs after
           the change it follows: Stripe's answer says what went wrong. */
        const refused = mine().findLast((c) => c.status === 0 || c.status >= 400);
        if (refused) return fail(said(refused));
        const read = mine().find((c) => c.method === "GET" && c.path === `/v1/customers/${customer}`);
        const wrote = mine().find((c) => c.method === "POST" && c.path === `/v1/customers/${customer}`);
        if (!read || !wrote) return fail("billingEmailFollows() did not read and then change the customer's email.");
        const email = await customerEmail(env, customer);
        if (email !== run.newOwner) {
          return fail(`Stripe has ${email === run.owner ? "the old owner's address" : "another address"} on the customer still.`);
        }
        return pass("read the customer's email, the old owner's, changed it to the new owner's, and Stripe now has the new one.");
      }, customer ? null : "the customer from (a)");
    } catch (err) {
      /* Something in this script itself: what ran is still cleaned up. */
      stopped = true;
      say(`The probe stopped before its checks were done: ${scrub(err && err.stack ? err.stack : err)}`);
    } finally {
      tidy = await cleanUp(env, run, calls);
    }
  } finally {
    globalThis.fetch = fetch;
    console.log = log;
  }

  const refused = calls.filter((c) => c.status === 403);
  if (k.kind === "restricted" || refused.length) {
    const unrun = results.filter((r) => r.state === "not run").map((r) => `(${r.letter})`);
    if (!refused.length && (unrun.length || stopped)) {
      results.push({ letter: "f", state: "not run" });
      say(`(f) NOT RUN  the restricted key's permissions: Stripe refused none of the calls made, but ` +
        `${unrun.length ? `${unrun.join(" and ")} did not run` : "the probe stopped early"}, so not every one was tried.`);
    } else if (!refused.length) {
      results.push({ letter: "f", state: "pass" });
      say("(f) PASS  the restricted key's permissions: Stripe refused none of the calls, cleanup's included.");
    } else {
      results.push({ letter: "f", state: "fail" });
      const each = refused.map((c) => {
        const named = permissions(c);
        return `${c.method} ${c.path} needs ${named.length ? named.join(" or ") : `what Stripe says: ${said(c)}`}`;
      });
      say(`(f) FAIL  the ${k.kind} key's permissions: Stripe refused ${count(refused.length, "call")} with a 403. ` +
        `${[...new Set(each)].join("; ")}.`);
    }
  } else {
    results.push({ letter: "f", state: "skipped" });
    say("(f) SKIPPED  a secret key has every permission. Run this again with the Worker's restricted key to check its own.");
  }

  const { sessions, deleted, left } = tidy;
  if (left.length) {
    say(`Left behind in Stripe's test mode, to delete in the dashboard: ${left.join("; ")}.`);
  }
  const ok = !stopped && !left.length && results.every((r) => r.state === "pass" || r.state === "skipped");
  const cleaned = left.length
    ? `cleanup left ${count(left.length, "thing")} behind`
    : `cleaned up ${count(sessions, "Checkout session")} and ${count(deleted, "customer")}`;
  say(`stripe probe: ${ok ? "PASS" : "FAIL"}. ${results.map((r) => `(${r.letter}) ${r.state}`).join(", ")}` +
    `${stopped ? ", and the probe stopped early" : ""}; ` +
    `test mode, a ${k.kind} key, STRIPE_TAX=${tax}; ${cleaned}.`);
  return ok ? 0 : 1;
}

/* Every Checkout the run opened expired, and every customer it made
   deleted: those in Stripe's replies, and any whose reply was lost, found
   by the run's addresses and organisation. Each step is tried whatever
   the one before did. { sessions, deleted, left }. */
async function cleanUp(env, run, calls) {
  const made = (path) => calls.filter((c) => c.method === "POST" && c.path === path && c.status === 200 &&
    c.body && typeof c.body.id === "string").map((c) => c.body.id);
  const customers = new Set(made("/v1/customers"));
  const sessions = new Set(made("/v1/checkout/sessions"));
  const left = [];
  const ours = (x) => x && x.metadata && x.metadata.org === run.org && x.metadata.product === PRODUCT;
  const attempt = async (fn) => {
    const from = calls.length;
    try {
      await fn();
      return null;
    } catch (err) {
      return why(err, calls.slice(from));
    }
  };

  for (const email of [run.owner, run.newOwner]) {
    await attempt(async () => {
      const { data = [] } = await stripe(env, "GET", "/customers", { email, limit: 10 });
      for (const c of data) if (ours(c) && CUSTOMER.test(String(c.id))) customers.add(c.id);
    });
  }
  for (const customer of customers) {
    await attempt(async () => {
      const { data = [] } = await stripe(env, "GET", "/checkout/sessions", { customer, status: "open", limit: 100 });
      for (const s of data) if (ours(s)) sessions.add(s.id);
    });
  }
  for (const id of sessions) {
    const failed = await attempt(async () => {
      const s = await stripe(env, "GET", `/checkout/sessions/${id}`);
      if (s.status === "open") await stripe(env, "POST", `/checkout/sessions/${id}/expire`);
    });
    if (failed) left.push(`Checkout ${id} (${failed})`);
  }
  let deleted = 0;
  for (const id of customers) {
    const failed = await attempt(() => stripe(env, "DELETE", `/customers/${id}`));
    if (failed) left.push(`customer ${id} (${failed})`);
    else deleted += 1;
  }
  return { sessions: sessions.size - left.filter((x) => x.startsWith("Checkout ")).length, deleted, left };
}

const invoked = (() => {
  try {
    return pathToFileURL(realpathSync(process.argv[1] || "")).href;
  } catch {
    return "";
  }
})();
if (invoked === import.meta.url) process.exitCode = await probe();
