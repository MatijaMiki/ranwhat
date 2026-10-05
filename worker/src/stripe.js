/* ranwhat Plus, sold through Stripe. Paying gets a feed token, and the token
 * works for as long as the subscription does.
 *
 *   POST /api/checkout  The pricing page's form (plan=monthly or annual).
 *                       Makes a Checkout Session for the price with that
 *                       plan's lookup key and sends the browser to Stripe.
 *   GET  /api/welcome   Where Stripe sends the browser after paying. Shows
 *                       the token, the same one the email carries.
 *   POST /api/stripe    Stripe's webhook. After a checkout: the token, by
 *                       email. On any change to a subscription: its status,
 *                       which feed.js checks on every `ranwhat update`.
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
 * scripts/stripe_setup.py makes the product, its two prices, the webhook
 * endpoint and the portal. Secrets: STRIPE_SECRET_KEY and
 * STRIPE_WEBHOOK_SECRET, with the list's RESEND_API_KEY and LIST_SECRET.
 */
import { LIVE, schema, sha256 } from "./feed.js";
import { CODE, REPLY_TO, SENDER, escape, mail, page, resend, same, sign, switchedOn } from "./list.js";

const ORIGIN = "https://ranwhat.com";
const API = "https://api.stripe.com/v1";
export const PRODUCT = "ranwhat-plus";
export const PLANS = { monthly: "ranwhat_plus_monthly", annual: "ranwhat_plus_annual" };

const TOLERANCE = 300;            // seconds a webhook signature stays good
const SHOW_FOR = 24 * 3600;       // the welcome page shows the token this long after checkout
const PAID = new Set(["paid", "no_payment_required"]);
const SESSION = /^cs_(test|live)_[A-Za-z0-9]{10,250}$/;
const SUBSCRIPTION = /^sub_[A-Za-z0-9]{6,250}$/;

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
   or the HTTP status, and whose status is the HTTP status (0: unreachable). */
async function stripe(env, method, path, params) {
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
      { code: String(e.code || e.type || res.status), status: res.status });
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

/* The subscription as Stripe has it now, with its status kept for feed.js
   and returned as kept. Fetched rather than read from the event: Stripe
   does not promise to deliver events in order, and a late one must not
   bring back an old status. null when it is not something this sells. */
async function sync(env, id) {
  if (typeof id !== "string" || !SUBSCRIPTION.test(id)) return null;
  const sub = await stripe(env, "GET", `/subscriptions/${id}`);
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
  const kept = await db.prepare("SELECT status FROM subscriptions WHERE id = ?").bind(sub.id).first();
  return { id: sub.id, status: kept.status };
}

/* The subscription's token: the same one on every call, switched on (its
   hash stored and tied to the subscription) by the first. */
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

export async function checkout(request, env) {
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

/* ---------- after paying ---------- */

export async function welcome(request, env) {
  if (!sellable(env)) return closed();
  const id = new URL(request.url).searchParams.get("session_id") || "";
  if (!SESSION.test(id)) return unknown();
  let session, sub, token;
  try {
    session = await stripe(env, "GET", `/checkout/sessions/${id}`);
    if (!session.metadata || session.metadata.product !== PRODUCT || session.mode !== "subscription") {
      return unknown();
    }
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
      if (object.metadata && object.metadata.product === PRODUCT && SESSION.test(String(object.id))) {
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
