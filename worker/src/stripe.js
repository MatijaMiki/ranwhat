/* ranwhat Plus, sold through Stripe. Paying gets a feed token, and the token
 * works for as long as the subscription does.
 *
 *   POST /api/checkout  The pricing page's form (plan=monthly or annual).
 *                       Makes a Checkout Session for the price with that
 *                       plan's lookup key and sends the browser to Stripe;
 *                       while accounts are on and ready, to the account's
 *                       upgrade instead (checkout()).
 *   GET  /api/welcome   Where Stripe sends the browser after paying. Shows
 *                       the token, the same one the email carries.
 *   POST /api/stripe    Stripe's webhook. After a checkout: the token, by
 *                       email. On any change to a subscription: its status,
 *                       which auth.js checks on every `ranwhat update`
 *                       (and, while accounts are on, its terms, which the
 *                       account page's billing panel shows: keep()).
 *   GET  /api/billing   The customer portal's login page, where a subscriber
 *                       changes plan or card, gets invoices, or cancels.
 *
 * A token is derived, not drawn: an HMAC of the subscription id under
 * LIST_SECRET. The welcome page and the webhook each make it, in either
 * order and as often as Stripe retries, and get the same one, while D1
 * still keeps only its SHA-256. Nothing else about the customer is kept
 * here: Stripe holds the email, the card and the invoices.
 *
 * Everything this sells carries metadata product=ranwhat-plus, and anything
 * without it (another site's sale on the same Stripe account) is ignored.
 *
 * Plus bought from an account (account.ranwhat.com/upgrade, billing.js) is
 * a Checkout bound to the organisation: client_reference_id and metadata
 * org on the session, and metadata org on the subscription it makes. The
 * webhook links that subscription to the organisation in org_subscriptions
 * (sync()), once and for good, and the buyer is told to run ranwhat login
 * instead of being sent a token: an organisation's machines each get
 * their own (device.js), so no shared one is made for it, here or on the
 * welcome page.
 *
 * Such a Checkout is always on the organisation's own Stripe customer,
 * made here before its first one (orgCustomer()) with the owner's address,
 * never one Stripe makes from whatever address the payer types: Stripe's
 * billing-page login (/api/billing) mails a way in to the customer's
 * address, so that address has to be one the organisation answers for,
 * and billing.js moves it to the owner's when whoever has it stops being
 * an owner or an admin.
 *
 * While accounts are on, an account's upgrade is the only way to buy Plus:
 * the pricing page's checkout makes no Checkout of its own and sends the
 * browser there (checkout()). The welcome page, the webhook and the billing
 * login go on serving what the pricing page sold before, a Checkout
 * opened just before accounts were switched on and paid just after among
 * it, exactly as they did; a subscription bought that way is attached to
 * an organisation only by hand, with scripts/org_admin.py link.
 *
 * scripts/stripe_setup.py makes the product, its two prices, the webhook
 * endpoint and the portal. Secrets: STRIPE_SECRET_KEY and
 * STRIPE_WEBHOOK_SECRET, with the list's RESEND_API_KEY and LIST_SECRET.
 */
import { LIVE, schema, sha256 } from "./auth.js";
import { CODE, REPLY_TO, SENDER, escape, mail, page, resend, same, sign, switchedOn } from "./list.js";
import { ACCOUNT_HOST, ACCOUNT_ORIGIN, accountsOn, ready, schema as accountsSchema } from "./accounts.js";

const ORIGIN = "https://ranwhat.com";
const API = "https://api.stripe.com/v1";
export const PRODUCT = "ranwhat-plus";
export const PLANS = { monthly: "ranwhat_plus_monthly", annual: "ranwhat_plus_annual" };

const TOLERANCE = 300;            // seconds a webhook signature stays good
const SHOW_FOR = 24 * 3600;       // the welcome page shows the token this long after checkout
const PAID = new Set(["paid", "no_payment_required"]);
/* A Checkout Session's id, as Stripe makes them. */
const CHECKOUT_ID = /^cs_(test|live)_[A-Za-z0-9]{10,250}$/;
export const SUBSCRIPTION = /^sub_[A-Za-z0-9]{6,250}$/;
export const CUSTOMER = /^cus_[A-Za-z0-9]{6,250}$/;
const ORG = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/* The account page's choice (billing.js) and the price's lookup key it
   buys: the pricing page's own form says annual for the second. */
export const INTERVALS = Object.freeze({ monthly: PLANS.monthly, yearly: PLANS.annual });

/* Shown under the pay button. Checkout's own terms checkbox would need the
   terms URL set in the Stripe dashboard first; this needs nothing. */
const TERMS = "Cancel any time on the billing page, and the feed keeps working to the end of " +
  "the period you paid for. Changed your mind? Write to hello@ranwhat.com within 14 days of " +
  "your first payment for a full refund. Terms: ranwhat.com/terms";

export const sellable = (env) =>
  Boolean(env.STRIPE_SECRET_KEY && env.STRIPE_WEBHOOK_SECRET && switchedOn(env));
const now = () => Math.floor(Date.now() / 1000);

const json = (status, body) => new Response(JSON.stringify(body), {
  status,
  headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" },
});

/* ---------- Stripe ---------- */

/* Stripe takes form encoding, nested keys in brackets: a[b][0]=c. */
export function encode(params, prefix = "", out = new URLSearchParams()) {
  for (const [k, v] of Object.entries(params)) {
    if (v === undefined) continue;
    const key = prefix ? `${prefix}[${k}]` : k;
    if (v !== null && typeof v === "object") encode(v, key, out);
    else out.append(key, String(v));
  }
  return out;
}

/* One API call. Throws an Error whose code is Stripe's error code or type,
   or the HTTP status, whose status is the HTTP status (0: unreachable),
   and whose param is the parameter Stripe named, if it named one. */
export async function stripe(env, method, path, params) {
  const form = params ? encode(params).toString() : "";
  let res;
  try {
    res = await fetch(`${API}${path}${method === "GET" && form ? `?${form}` : ""}`, {
      method,
      headers: {
        authorization: `Bearer ${env.STRIPE_SECRET_KEY}`,
        "content-type": "application/x-www-form-urlencoded",
      },
      body: method === "GET" ? undefined : form,
    });
  } catch {
    throw Object.assign(new Error("Stripe unreachable"), { code: "unreachable", status: 0 });
  }
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const e = data.error || {};
    throw Object.assign(new Error(`Stripe ${res.status}`),
      { code: String(e.code || e.type || res.status), status: res.status,
        param: typeof e.param === "string" ? e.param : null });
  }
  return data;
}

/* STRIPE_TAX, in wrangler.toml, says who answers for VAT, and with it how
   much of the checkout page is ours to set:
     "managed"    Stripe's Managed Payments: Stripe (as Link) is the
                  merchant of record. It runs the page, collects the tax and
                  files it, so the session carries only what Stripe's own
                  Managed Payments guide shows. Its list of parameters it
                  refuses is not complete: it turned down custom_text, which
                  the list does not name. The terms and privacy links on the
                  page come from the dashboard's Checkout settings instead.
     "automatic"  Stripe Tax calculates it and we file it, which needs the
                  account's tax registrations entered in the dashboard.
     otherwise    no tax in Checkout.
   In the last two, the page asks for the billing address and a tax ID, so a
   business gets both on its invoice, takes promotion codes, and shows the
   cancellation and refund terms under the pay button. */
function seller(env) {
  if (env.STRIPE_TAX === "managed") return { managed_payments: { enabled: true } };
  return {
    allow_promotion_codes: true,
    billing_address_collection: "required",
    tax_id_collection: { enabled: true },
    custom_text: { submit: { message: TERMS } },
    ...(env.STRIPE_TAX === "automatic" ? { automatic_tax: { enabled: true } } : {}),
  };
}

/* ---------- tokens ---------- */

/* The subscription as Stripe has it now, with its status kept for auth.js
   and returned as kept. Fetched rather than read from the event: Stripe
   does not promise to deliver events in order, and a late one must not
   bring back an old status. null when it is not something this sells.

   org: the organisation its metadata names, for one bought from an
   account, which it is linked to here (linkOrg()); null otherwise. */
async function sync(env, id) {
  if (typeof id !== "string" || !SUBSCRIPTION.test(id)) return null;
  return keep(env, await stripe(env, "GET", `/subscriptions/${id}`));
}

/* sync() for a subscription just fetched from Stripe: its status kept,
   and returned as kept, with its customer. While accounts are on, its
   terms too (termsOf()), for the billing panel to read without asking
   Stripe; dark, nothing but what was always kept. */
async function keep(env, sub) {
  if (!sub.metadata || sub.metadata.product !== PRODUCT) return null;
  const db = env.LIST;
  await schema(db);
  const customer = typeof sub.customer === "string" ? sub.customer : String(sub.customer && sub.customer.id);
  /* A canceled subscription stays canceled in Stripe, so nothing here may
     bring one back, even a fetch that raced the cancellation. */
  await db.prepare(
    `INSERT INTO subscriptions (id, customer, status, updated_at) VALUES (?, ?, ?, ?)
     ON CONFLICT(id) DO UPDATE SET updated_at = excluded.updated_at,
       status = CASE WHEN subscriptions.status IN ('canceled', 'incomplete_expired')
                     THEN subscriptions.status ELSE excluded.status END`)
    .bind(sub.id, customer, sub.status, now()).run();
  if (accountsOn(env)) {
    await accountsSchema(db);
    const terms = termsOf(sub);
    await db.prepare(
      `INSERT INTO subscription_terms (subscription, interval, renews_at, ends_at, fetched_at) VALUES (?, ?, ?, ?, ?)
       ON CONFLICT(subscription) DO UPDATE SET interval = excluded.interval, renews_at = excluded.renews_at,
         ends_at = excluded.ends_at, fetched_at = excluded.fetched_at`)
      .bind(sub.id, terms.interval, terms.renews_at, terms.ends_at, now()).run();
  }
  const org = orgIn(sub.metadata);
  if (org) await linkOrg(env, sub.id, org);
  const kept = await db.prepare("SELECT status FROM subscriptions WHERE id = ?").bind(sub.id).first();
  return { id: sub.id, status: kept.status, org, customer };
}

/* The organisation a session's or a subscription's metadata names, when
   it names one the way orgCheckout() writes it. */
const orgIn = (metadata) =>
  metadata && typeof metadata.org === "string" && ORG.test(metadata.org) ? metadata.org : null;

/* Links a subscription bought from an account to the organisation its
   own metadata names, as Stripe holds it: nobody but this Worker, with
   its key, can set that. INSERT OR IGNORE, and the subscription is the
   key, so whichever event comes first links it (subscription.created can
   arrive before checkout.session.completed), every later one and every
   retry leave it as it is, and a subscription linked once is never moved
   to another organisation. An organisation that is no longer there gets
   nothing. The link is logged once. The organisation's Stripe customer is
   never taken from a subscription: it is the one orgCustomer() made. */
async function linkOrg(env, sub, org) {
  const db = env.LIST;
  await accountsSchema(db);
  const t = now();
  const ours = "EXISTS (SELECT 1 FROM org_subscriptions WHERE subscription = ? AND org_id = ?)";
  await db.batch([
    db.prepare(`INSERT OR IGNORE INTO org_subscriptions (subscription, org_id, how, linked_by, linked_at)
                SELECT ?, id, 'checkout', NULL, ? FROM orgs WHERE id = ?`).bind(sub, t, org),
    db.prepare(`INSERT INTO auth_events (org_id, user_id, event, subject, at)
                SELECT ?, NULL, 'plus_linked', ?, ? WHERE ${ours} AND NOT EXISTS (
                  SELECT 1 FROM auth_events WHERE org_id = ? AND event = 'plus_linked' AND subject = ?)`)
      .bind(org, sub, t, sub, org, org, sub),
  ]);
}

/* The subscription's token: the same one on every call, switched on (its
   hash stored and tied to the subscription) by the first. A token revoked
   since (on the account page, once scripts/org_admin.py has linked its
   subscription to an organisation) stays revoked: both rows are INSERT OR
   IGNORE. */
async function issue(env, sub) {
  const db = env.LIST;
  const row = await db.prepare("SELECT gen FROM subscriptions WHERE id = ?").bind(sub.id).first();
  const token = "rw_" + await sign(env, `feed-token:${sub.id}:${row ? row.gen : 0}`);
  const hash = await sha256(token);
  await db.batch([
    db.prepare("INSERT OR IGNORE INTO tokens (hash, note, created_at) VALUES (?, ?, ?)")
      .bind(hash, `stripe ${sub.id}`, now()),
    db.prepare("INSERT OR IGNORE INTO token_subscriptions (hash, subscription) VALUES (?, ?)")
      .bind(hash, sub.id),
  ]);
  return token;
}

/* ---------- checkout ---------- */

/* The account's upgrade, where Plus is bought while accounts are on. */
const UPGRADE = `${ACCOUNT_ORIGIN}/upgrade`;

export async function checkout(request, env) {
  /* With accounts on, Plus belongs to an organisation and is bought from
     its account (billing.js), so this sends every browser there, before
     reading the form, asking Stripe or writing anything, and to the same
     address whatever the request says. Switched on but not ready
     (accounts.js's ready()), the account host answers every page with its
     503, so until it is, Plus is sold here as it is dark. Nobody had
     bought Plus here when that was decided; anything bought here before
     the switch, or while it was not ready, is attached to an organisation
     by hand, with scripts/org_admin.py link. The pricing page's
     form-action (site/_headers) allows the account origin, as browsers
     hold this redirect to it too. */
  if (accountsOn(env) && ready(env)) return Response.redirect(UPGRADE, 303);
  if (!sellable(env)) return closed();
  let plan = null;
  try {
    plan = (await request.formData()).get("plan");
  } catch { /* not a form */ }
  const key = Object.hasOwn(PLANS, plan) ? PLANS[plan] : null;
  if (!key) {
    return page("Pick a plan", `<h1>Pick a plan first.</h1>
      <p>Go back to <a href="/pricing#plus">pricing</a> and choose monthly or yearly.</p>`, 400);
  }
  let session;
  try {
    const { data = [] } = await stripe(env, "GET", "/prices", { lookup_keys: [key], active: true });
    if (!data[0]) throw Object.assign(new Error("no price"), { code: `no active price ${key}` });
    session = await stripe(env, "POST", "/checkout/sessions", {
      mode: "subscription",
      line_items: [{ price: data[0].id, quantity: 1 }],
      success_url: `${ORIGIN}/api/welcome?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${ORIGIN}/pricing#plus`,
      metadata: { product: PRODUCT },
      subscription_data: { metadata: { product: PRODUCT } },
      ...seller(env),
    });
  } catch (err) {
    console.log(`stripe checkout: ${err.code}`);
    return page("Try again", `<h1>Checkout did not open.</h1>
      <p>Nothing was charged. Try again in a minute, or
         <a href="/contact?about=plus">write to us</a>.</p>`, 502);
  }
  return Response.redirect(session.url, 303);
}

/* A Checkout Session bound to an organisation, for its owner or an admin
   on the account page (billing.js, which checks who asks, the plan and
   the fresh code first). The same product, prices and tax handling as the
   pricing page's, and more: the organisation, as client_reference_id and
   in the metadata of both the session and the subscription it makes; the
   organisation's own Stripe customer (orgCustomer()), always, so that the
   payer cannot make the organisation's billing theirs by typing their own
   address; and an expiry of ORG_CHECKOUT_FOR rather than Stripe's day.
   The organisation's Checkouts still open are expired first (closeOpen()),
   so that two cannot both be paid for. Stripe sends the browser back to
   the account either way. Returns the session; throws as stripe() does,
   and with param "customer" when Stripe turns the customer down (one
   deleted since), for billing.js to make the organisation a new one. */
export const ORG_CHECKOUT_FOR = 31 * 60;  // Stripe's least is 30 minutes; one more for the clocks

export async function orgCheckout(env, { org, interval, customer }) {
  if (!ORG.test(String(org)) || !Object.hasOwn(INTERVALS, interval) || !CUSTOMER.test(String(customer))) {
    throw Object.assign(new Error("bad checkout"), { code: "bad_request", status: 400 });
  }
  const key = INTERVALS[interval];
  const { data = [] } = await stripe(env, "GET", "/prices", { lookup_keys: [key], active: true });
  if (!data[0]) throw Object.assign(new Error("no price"), { code: `no active price ${key}`, status: 0 });
  await closeOpen(env, { org, customer });
  const metadata = { product: PRODUCT, org };
  const params = {
    mode: "subscription",
    line_items: [{ price: data[0].id, quantity: 1 }],
    success_url: `${ACCOUNT_ORIGIN}/?upgraded=1`,
    cancel_url: `${ACCOUNT_ORIGIN}/upgrade`,
    client_reference_id: org,
    metadata,
    subscription_data: { metadata },
    ...seller(env),
    /* With our own tax settings, Checkout asks for the address and a tax
       ID, and with a customer it may only keep them on that customer. */
    customer,
    ...(env.STRIPE_TAX === "managed" ? {} : { customer_update: { address: "auto", name: "auto" } }),
    expires_at: now() + ORG_CHECKOUT_FOR,
  };
  try {
    return await stripe(env, "POST", "/checkout/sessions", params);
  } catch (err) {
    /* Managed Payments turns down parameters its guide does not list; an
       expiry is not worth not selling for. */
    if (err.status !== 400 || err.param !== "expires_at") throw err;
    console.log(`stripe org checkout: ${err.code}, without expires_at`);
    return stripe(env, "POST", "/checkout/sessions", { ...params, expires_at: undefined });
  }
}

/* Expires the Checkouts still open on the organisation's customer that
   were made for it, so that only the newest can be paid. Best effort:
   one that cannot be listed or expired just now runs out by itself in
   ORG_CHECKOUT_FOR, and the webhook flags an organisation that pays
   twice (orgCompleted()). */
async function closeOpen(env, { org, customer }) {
  let open = [];
  try {
    ({ data: open = [] } = await stripe(env, "GET", "/checkout/sessions", { customer, status: "open", limit: 20 }));
  } catch (err) {
    console.log(`stripe org checkout list: ${err.code || "error"}`);
    return;
  }
  for (const session of open) {
    if (!session || !CHECKOUT_ID.test(String(session.id)) || !session.metadata ||
        session.metadata.product !== PRODUCT || session.metadata.org !== org) continue;
    try {
      await stripe(env, "POST", `/checkout/sessions/${session.id}/expire`);
    } catch (err) {
      console.log(`stripe org checkout expire: ${err.code || "error"}`);
    }
  }
}

/* A Stripe customer of the organisation's own, for its Checkouts and its
   billing page: `email` is its owner's address, verified here, and Stripe
   keeps it on the customer and shows it, unchangeable, at Checkout.
   Returns its id; throws as stripe() does. */
export async function orgCustomer(env, { org, email }) {
  if (!ORG.test(String(org)) || typeof email !== "string" || !email) {
    throw Object.assign(new Error("bad customer"), { code: "bad_request", status: 400 });
  }
  const made = await stripe(env, "POST", "/customers", { email, metadata: { product: PRODUCT, org } });
  if (!made || !CUSTOMER.test(String(made.id))) {
    throw Object.assign(new Error("no customer"), { code: "no_customer", status: 0 });
  }
  return made.id;
}

/* Stripe's email for the customer, changed to `email` (billing.js, when
   whoever had it is no longer an owner or an admin). Throws as stripe()
   does. */
export async function setCustomerEmail(env, customer, email) {
  if (!CUSTOMER.test(String(customer)) || typeof email !== "string" || !email) {
    throw Object.assign(new Error("bad customer"), { code: "bad_request", status: 400 });
  }
  await stripe(env, "POST", `/customers/${customer}`, { email });
}

/* ---------- after paying ---------- */

export async function welcome(request, env) {
  if (!sellable(env)) return closed();
  const id = new URL(request.url).searchParams.get("session_id") || "";
  if (!CHECKOUT_ID.test(id)) return unknown();
  let session, sub, token;
  try {
    session = await stripe(env, "GET", `/checkout/sessions/${id}`);
    if (!session.metadata || session.metadata.product !== PRODUCT || session.mode !== "subscription") {
      return unknown();
    }
    /* Bought from an account: Stripe sends the browser back there, and no
       shared token is made for an organisation. */
    if (session.metadata.org !== undefined) return forOrg();
    if (session.status !== "complete" || !PAID.has(session.payment_status)) {
      return page("Payment pending", `<h1>Your payment is still going through.</h1>
        <p>Some payment methods take a few days to clear. Your feed token comes
           by email the moment it does.</p>`);
    }
    if (now() - session.created > SHOW_FOR) {
      return page("Token emailed", `<h1>Your token is in your email.</h1>
        <p>This page shows it only on the day you subscribe. The email it came
           in has it, or <a href="/contact?about=plus">write to us</a>.</p>
        <p><a href="/api/billing">Manage billing</a></p>`);
    }
    sub = await sync(env, session.subscription);
    if (!sub) return unknown();
    if (!LIVE.has(sub.status)) {
      return page("Not active", `<h1>This subscription is not active.</h1>
        <p>It may have been cancelled. <a href="/api/billing">Manage billing</a>, or
           <a href="/pricing#plus">subscribe again</a>.</p>`);
    }
    token = await issue(env, sub);
  } catch (err) {
    if (err.status === 404) return unknown();
    console.log(`stripe welcome: ${err.code}`);
    return page("Try again", `<h1>That did not load.</h1>
      <p>Your payment is safe. Reload this page in a minute; the token also
         comes by email.</p>`, 502);
  }
  const email = session.customer_details && session.customer_details.email;
  const t = escape(token);
  return page("Welcome to Plus", `<h1>You are on Plus.</h1>
    <p>This is your feed token.${email ? ` A copy is on its way to ${escape(email)}.` : ""}</p>
    <pre>${t}</pre>
    <h2>Switch it on</h2>
    <p>Once on each machine, in a terminal. macOS and Linux:</p>
    <pre>RANWHAT_TOKEN=${t} uvx ranwhat update --save-token</pre>
    <p>Windows PowerShell:</p>
    <pre>$env:RANWHAT_TOKEN="${t}"; uvx ranwhat update --save-token</pre>
    <p>After that, <code>uvx ranwhat update</code> fetches the newest catalogue
       with no token to type.</p>
    <p>Keep the token to yourself: anyone holding it gets your feed. It stops
       working when the subscription ends.</p>
    <p><a href="/api/billing">Manage billing</a>: change plan or card, get
       invoices, or cancel.</p>`);
}

const closed = () => page("Not open yet", `<h1>Checkout is not open yet.</h1>
  <p>If you want Plus now, <a href="/contact?about=plus">write to us</a>.</p>`, 503);

const forOrg = () => page("Plus for your organisation", `<h1>Plus is for your organisation.</h1>
  <p>This checkout was made from an account, so there is no shared token to show: each
     machine links itself with <code>uvx ranwhat login</code>. Your
     <a href="${ACCOUNT_ORIGIN}/">account page</a> shows Plus once Stripe confirms the payment.</p>`);

const unknown = () => page("Not found", `<h1>That checkout was not found.</h1>
  <p>If you paid, your token comes by email. If it does not arrive,
     <a href="/contact?about=plus">write to us</a>.</p>`, 404);

/* ---------- the webhook ---------- */

const enc = new TextEncoder();

/* The event, when Stripe-Signature holds an HMAC of "t.body" under the
   endpoint's signing secret, made in the last five minutes. */
async function verified(request, env) {
  const raw = await request.text();
  let t = "";
  const v1 = [];
  for (const part of (request.headers.get("stripe-signature") || "").split(",")) {
    const at = part.indexOf("=");
    const k = part.slice(0, at).trim(), v = part.slice(at + 1).trim();
    if (k === "t") t = v;
    else if (k === "v1") v1.push(v);
  }
  if (!/^\d{1,12}$/.test(t) || Math.abs(now() - Number(t)) > TOLERANCE) return null;
  const key = await crypto.subtle.importKey("raw", enc.encode(env.STRIPE_WEBHOOK_SECRET),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const mac = [...new Uint8Array(await crypto.subtle.sign("HMAC", key, enc.encode(`${t}.${raw}`)))]
    .map((b) => b.toString(16).padStart(2, "0")).join("");
  if (!v1.some((s) => same(s, mac))) return null;
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

export async function webhook(request, env) {
  if (!sellable(env)) return json(503, { error: "Not switched on." });
  const event = await verified(request, env);
  if (!event) return json(400, { error: "Bad signature." });
  const type = String(event.type || "");
  const object = (event.data && event.data.object) || {};
  try {
    if (type === "checkout.session.completed" || type === "checkout.session.async_payment_succeeded") {
      /* The session as Stripe has it, not as the event tells it: whoever
         held a leaked signing secret could sign an event, but could not
         make Stripe send a token to an address of their own. Another
         site's sessions cost no call. */
      if (object.metadata && object.metadata.product === PRODUCT && CHECKOUT_ID.test(String(object.id))) {
        await completed(env, await stripe(env, "GET", `/checkout/sessions/${object.id}`));
      }
    } else if (type.startsWith("customer.subscription.")) {
      /* Checked on the event first, so another site's subscriptions on the
         same account cost no call to Stripe. */
      if (object.metadata && object.metadata.product === PRODUCT) await sync(env, object.id);
    }
  } catch (err) {
    /* A session or subscription Stripe does not know: nothing to retry. */
    if (err.status === 404) return json(200, { received: true });
    /* A 500 makes Stripe deliver it again, for up to three days. */
    console.log(`stripe ${type}: ${err.code || "error"}`);
    return json(500, { error: "Not handled yet." });
  }
  return json(200, { received: true });
}

/* A finished checkout: switch the token on and email it, once. */
async function completed(env, session) {
  if (!session.metadata || session.metadata.product !== PRODUCT || session.mode !== "subscription") return;
  /* Paid by something that takes days (a bank debit): the
     async_payment_succeeded event comes back here when it clears. */
  if (!PAID.has(session.payment_status)) return;
  if (session.metadata.org !== undefined) return orgCompleted(env, session);
  const sub = await sync(env, session.subscription);
  if (!sub || !LIVE.has(sub.status)) return;
  const token = await issue(env, sub);
  const to = session.customer_details && session.customer_details.email;
  if (!to) return;
  const db = env.LIST;
  /* Claimed before sending, so a second delivery of the same event does not
     send it twice; released again if the email fails, so the retry does. */
  const claimed = await db.prepare(
    "UPDATE subscriptions SET mailed_at = ? WHERE id = ? AND mailed_at IS NULL").bind(now(), sub.id).run();
  if (!claimed.meta.changes) return;
  try {
    await mailToken(env, to, token);
  } catch (err) {
    await db.prepare("UPDATE subscriptions SET mailed_at = NULL WHERE id = ?").bind(sub.id).run();
    throw err;
  }
}

/* A finished checkout made from an account. sync() links the subscription
   to the organisation its own metadata names; this then tells the buyer
   Plus is on for it, once, as completed() sends a token once. Only when
   the session and the subscription agree on the organisation, and the
   subscription is linked to it: a mismatch (metadata edited by hand in
   Stripe) is logged and mails nothing, and no token is made. An
   organisation that has another live subscription linked already (two
   Checkouts paid, or one paid besides an attached purchase) is logged,
   and the email says so and how to cancel one; the billing panel says it
   too (billing.js). */
async function orgCompleted(env, session) {
  const org = orgIn(session.metadata);
  const sub = await sync(env, session.subscription);
  if (!sub) return;
  if (!org || session.client_reference_id !== org || sub.org !== org) {
    console.log("stripe checkout: org mismatch");
    return;
  }
  if (!LIVE.has(sub.status)) return;
  const db = env.LIST;
  const linked = await db.prepare(
    `SELECT o.name FROM org_subscriptions l JOIN orgs o ON o.id = l.org_id
     WHERE l.subscription = ? AND l.org_id = ?`).bind(sub.id, org).first();
  if (!linked) {
    console.log("stripe checkout: org not linked");
    return;
  }
  const live = [...LIVE];
  const others = await db.prepare(
    `SELECT count(*) AS n FROM org_subscriptions l JOIN subscriptions s ON s.id = l.subscription
     WHERE l.org_id = ? AND l.subscription != ? AND s.status IN (${live.map(() => "?").join(", ")})`)
    .bind(org, sub.id, ...live).first();
  const twice = Boolean(others && others.n > 0);
  if (twice) console.log("stripe checkout: org has another live subscription");
  const to = session.customer_details && session.customer_details.email;
  if (!to) return;
  const claimed = await db.prepare(
    "UPDATE subscriptions SET mailed_at = ? WHERE id = ? AND mailed_at IS NULL").bind(now(), sub.id).run();
  if (!claimed.meta.changes) return;
  try {
    await mailPlusOn(env, to, linked.name, { twice });
  } catch (err) {
    await db.prepare("UPDATE subscriptions SET mailed_at = NULL WHERE id = ?").bind(sub.id).run();
    throw err;
  }
}

/* Instead of a token: Plus is on for the organisation, and how its
   machines link themselves. The address is Stripe's, used for this email
   and kept nowhere here. twice: the organisation was paying for Plus
   already, so it now pays twice until one is cancelled. */
async function mailPlusOn(env, to, orgName, { twice = false } = {}) {
  const name = String(orgName).replace(/[\r\n]+/g, " ");
  const n = escape(name);
  const two = twice ? `${name} now has two Plus subscriptions, and needs one. Cancel the one you do not ` +
    `want with Manage billing on ${ACCOUNT_HOST}, and write to us (reply to this email) for a refund of it.` : "";
  await resend(env, "POST", "/emails", {
    from: SENDER,
    to: [to],
    reply_to: REPLY_TO,
    subject: `ranwhat Plus is on for ${name}`,
    text: [
      `Thanks for subscribing. ranwhat Plus is on for ${name}.`,
      "",
      ...(two ? [two, ""] : []),
      "Link each machine once, in a terminal:",
      "",
      "  uvx ranwhat login",
      "",
      `It prints a code to type at ${ORIGIN}/device, signed in to your account.`,
      `CI tokens are made on your account page: ${ACCOUNT_ORIGIN}/`,
      "",
      `Change plan or card, get invoices, or cancel: Manage billing on ${ACCOUNT_HOST}.`,
      "Questions: reply to this email.",
      "",
      "ranwhat.com",
    ].join("\n"),
    html: mail(`
      <p>Thanks for subscribing. ranwhat Plus is on for <strong>${n}</strong>.</p>${two ? `
      <p><strong>${escape(two)}</strong></p>` : ""}
      <p>Link each machine once, in a terminal:</p>
      <p><code style="${CODE}">uvx ranwhat login</code></p>
      <p>It prints a code to type at <a href="${ORIGIN}/device" style="color:#b8482d">ranwhat.com/device</a>,
         signed in to your account. CI tokens are made on your
         <a href="${ACCOUNT_ORIGIN}/" style="color:#b8482d">account page</a>.</p>
      <p style="margin-top:22px">Change plan or card, get invoices, or cancel: Manage billing on
         ${ACCOUNT_HOST}. Questions: reply to this email.</p>`),
  });
}

async function mailToken(env, to, token) {
  const t = escape(token);
  await resend(env, "POST", "/emails", {
    from: SENDER,
    to: [to],
    reply_to: REPLY_TO,
    subject: "Your ranwhat Plus feed token",
    text: [
      "Thanks for subscribing to ranwhat Plus. This is your feed token:",
      "",
      `  ${token}`,
      "",
      "Switch it on once on each machine, in a terminal. macOS and Linux:",
      "",
      `  RANWHAT_TOKEN=${token} uvx ranwhat update --save-token`,
      "",
      "Windows PowerShell:",
      "",
      `  $env:RANWHAT_TOKEN="${token}"; uvx ranwhat update --save-token`,
      "",
      "After that, `uvx ranwhat update` fetches the newest catalogue with no",
      "token to type. Keep the token to yourself: anyone holding it gets your",
      "feed. It stops working when the subscription ends.",
      "",
      `Change plan or card, get invoices, or cancel: ${ORIGIN}/api/billing`,
      "Questions: reply to this email.",
      "",
      "ranwhat.com",
    ].join("\n"),
    html: mail(`
      <p>Thanks for subscribing to ranwhat Plus. This is your feed token:</p>
      <p style="margin:18px 0"><code style="${CODE};font-size:14px;word-break:break-all">${t}</code></p>
      <p>Switch it on once on each machine, in a terminal. macOS and Linux:</p>
      <p><code style="${CODE};word-break:break-all">RANWHAT_TOKEN=${t} uvx ranwhat update --save-token</code></p>
      <p>Windows PowerShell:</p>
      <p><code style="${CODE};word-break:break-all">$env:RANWHAT_TOKEN="${t}"; uvx ranwhat update --save-token</code></p>
      <p>After that, <code style="${CODE}">uvx ranwhat update</code> fetches the newest catalogue
         with no token to type. Keep the token to yourself: anyone holding it gets your feed.
         It stops working when the subscription ends.</p>
      <p style="margin-top:22px"><a href="${ORIGIN}/api/billing" style="color:#b8482d">Manage billing</a>:
         change plan or card, get invoices, or cancel. Questions: reply to this email.</p>`),
  });
}

/* ---------- billing ---------- */

/* Stripe's hosted login for the portal scripts/stripe_setup.py made: the
   subscriber gives their email and Stripe mails them a link in. Looked up
   rather than written into the site, so the setup script is the only place
   it comes from. */
export async function billing(request, env) {
  if (env.STRIPE_SECRET_KEY) {
    try {
      const { data = [] } = await stripe(env, "GET", "/billing_portal/configurations", { active: true, limit: 100 });
      const portal = data.find((c) => c.metadata && c.metadata.product === PRODUCT &&
        c.login_page && c.login_page.enabled && /^https:\/\/billing\.stripe\.com\//.test(c.login_page.url || ""));
      if (portal) return Response.redirect(portal.login_page.url, 302);
      console.log("stripe billing: no portal");
    } catch (err) {
      console.log(`stripe billing: ${err.code}`);
    }
  }
  return Response.redirect(`${ORIGIN}/contact?about=plus`, 302);
}

/* ---------- billing, from an account ---------- */

/* A billing-portal session for `customer`, the Stripe customer of a
   subscription linked to the organisation (billing.js checks that, the
   role and the fresh code first), on the portal scripts/stripe_setup.py
   made where it is found, and back to the account page after. Returns the
   session; throws as stripe() does. */
export async function portalSession(env, customer) {
  if (typeof customer !== "string" || !CUSTOMER.test(customer)) {
    throw Object.assign(new Error("bad customer"), { code: "bad_customer", status: 400 });
  }
  const { data = [] } = await stripe(env, "GET", "/billing_portal/configurations", { active: true, limit: 100 });
  const portal = data.find((c) => c.metadata && c.metadata.product === PRODUCT);
  return stripe(env, "POST", "/billing_portal/sessions", {
    customer,
    return_url: `${ACCOUNT_ORIGIN}/`,
    configuration: portal ? portal.id : undefined,
  });
}

const at = (v) => (Number.isInteger(v) && v > 0 ? v : null);
const itemOf = (sub) => (sub.items && Array.isArray(sub.items.data) ? sub.items.data[0] : null);

/* Monthly or yearly, from the subscription's price; null when Stripe's
   answer does not say. */
function intervalOf(sub) {
  const item = itemOf(sub);
  const recurring = (item && item.price && item.price.recurring) || sub.plan || {};
  return { month: "monthly", year: "yearly" }[recurring.interval] || null;
}

/* What the account page shows of a subscription, from the subscription
   as Stripe gave it: monthly or yearly, and when it renews or ends. keep()
   stores it in subscription_terms. The period's end is read where either
   version of Stripe's API puts it, on the subscription or on its item. */
function termsOf(sub) {
  const item = itemOf(sub);
  const periodEnd = at(sub.current_period_end) || at(item && item.current_period_end);
  const ending = Boolean(sub.cancel_at_period_end) || at(sub.cancel_at) !== null;
  return {
    interval: intervalOf(sub),
    renews_at: !ending && LIVE.has(sub.status) ? periodEnd : null,
    ends_at: at(sub.ended_at) || at(sub.cancel_at) || (sub.cancel_at_period_end ? periodEnd : null),
  };
}

/* For a subscription linked to an organisation whose terms no event has
   brought yet (one linked by scripts/org_admin.py): fetched from Stripe
   and kept, status and terms, as an event would. billing.js asks only
   for an owner or an admin, and only so often an hour. Throws as stripe()
   does. */
export const refreshTerms = (env, id) => sync(env, id);

const idOf = (v) => (typeof v === "string" ? v : v && typeof v.id === "string" ? v.id : "");

/* The email Stripe holds for a customer, or null for one deleted, without
   one, or not found (billing.js's billingEmailFollows()). Throws as
   stripe() does, but for a 404. */
export async function customerEmail(env, customer) {
  const id = idOf(customer);
  if (!CUSTOMER.test(id)) return null;
  let c;
  try {
    c = await stripe(env, "GET", `/customers/${id}`);
  } catch (err) {
    if (err.status === 404) return null;
    throw err;
  }
  return c && !c.deleted && typeof c.email === "string" && c.email ? c.email : null;
}
