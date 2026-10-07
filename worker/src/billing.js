/* Paying for Plus from account.ranwhat.com: upgrading a Free organisation
 * through a Stripe Checkout bound to it, the billing panel on the account
 * page, and Manage billing, which opens Stripe's billing portal for the
 * organisation's customer. The calls to Stripe are stripe.js's, and so is
 * the webhook that links what was bought to the organisation.
 *
 *   GET  /upgrade   Monthly or yearly, for the organisation being looked
 *                   at. Without a session: sign in first, and back here.
 *   POST /upgrade   An owner or an admin, of an organisation on neither
 *                   Plus nor Team, with an emailed code typed in the last
 *                   15 minutes: makes the Checkout (stripe.js's
 *                   orgCheckout()) and sends the browser to it.
 *   POST /billing   An owner or an admin, with a fresh code, naming a
 *                   subscription linked to this organisation: a portal
 *                   session for that subscription's customer, and off to
 *                   it.
 *
 * The pricing page's anonymous checkout (/api/checkout) and the portal
 * login behind /api/billing are stripe.js's and unchanged. A subscription
 * bought there and attached to an organisation later is billed here like
 * any other.
 *
 * Both POSTs leave this host only for an address Stripe gave back, and
 * only for checkout.stripe.com or billing.stripe.com; a page whose form
 * goes there adds that origin, and only while the form is on it, to its
 * form-action (ui.js). An organisation opens only so many Checkout and
 * portal sessions an hour, so no session can make Stripe ones without
 * end.
 */
import { LIVE, plan } from "./auth.js";
import { escape } from "./list.js";
import { PLAN_NAMES, atLeast, featuresOf } from "./features.js";
import { HOUR, canManage, event, now } from "./accounts.js";
import {
  FRESH_FOR, SESSION_COOKIE, bump, clearCookie, current, formOk, formToken, fresh, readCookie,
} from "./session.js";
import { away, fields, form, page, redirect, refused } from "./ui.js";
import { INTERVALS, SUBSCRIPTION, orgCheckout, portalSession, sellable, subscriptionNow } from "./stripe.js";

export const CHECKOUT_ORIGIN = "https://checkout.stripe.com";
export const PORTAL_ORIGIN = "https://billing.stripe.com";
const CHECKOUT_URL = /^https:\/\/checkout\.stripe\.com\//;
const PORTAL_URL = /^https:\/\/billing\.stripe\.com\//;

export const UPGRADES_PER_HOUR = 10;    // Checkout sessions one organisation opens an hour
export const PORTALS_PER_HOUR = 20;     // and portal sessions
const SHOWN = 5;                         // subscriptions the panel lists at most

/* What each choice costs, as the pricing page says it. Stripe's price,
   found by its lookup key (stripe.js's INTERVALS), is what is charged. */
const PRICES = Object.freeze({ monthly: "€12 a month", yearly: "€120 a year" });

/* Stripe's statuses, in words. */
const STATUS = Object.freeze({
  active: "Active",
  trialing: "Trial",
  past_due: "Payment overdue: Stripe is trying the card again",
  unpaid: "Unpaid",
  canceled: "Cancelled",
  incomplete: "Waiting for the first payment",
  incomplete_expired: "Checkout not finished",
  paused: "Paused",
});

const day = (t) => new Date(t * 1000).toISOString().slice(0, 10);
const problem = (text) => (text ? `<p class="bad">${escape(text)}</p>` : "");
const back = `<p><a href="/">Your account</a></p>`;

/* No session: sign in first, and come back to the upgrade. */
const toSignin = (request) =>
  redirect("/signin?next=/upgrade", readCookie(request, SESSION_COOKIE) ? [clearCookie(SESSION_COOKIE)] : []);

/* ---------- what an organisation pays for ---------- */

/* The subscriptions linked to an organisation, with their status as the
   webhook last kept it: the live ones first, then the most recently
   linked. */
export async function linkedSubscriptions(env, orgId, limit = SHOWN) {
  const live = [...LIVE];
  const { results } = await env.LIST.prepare(
    `SELECT s.id, s.customer, s.status, l.linked_at FROM org_subscriptions l JOIN subscriptions s ON s.id = l.subscription
     WHERE l.org_id = ?
     ORDER BY s.status IN (${live.map(() => "?").join(", ")}) DESC, l.linked_at DESC, s.id LIMIT ?`)
    .bind(orgId, ...live, limit).all();
  return results;
}

/* The subscription a form names, only if it is linked to this
   organisation: null otherwise, the same for one linked to another
   organisation as for one that never was. */
export async function linkedSubscription(env, orgId, id) {
  if (typeof id !== "string" || !SUBSCRIPTION.test(id)) return null;
  return env.LIST.prepare(
    `SELECT s.id, s.customer, s.status FROM org_subscriptions l JOIN subscriptions s ON s.id = l.subscription
     WHERE l.subscription = ? AND l.org_id = ?`).bind(id, orgId).first();
}

/* The grant in force that gives the organisation its plan, if one does:
   Team before Plus, then the longest. */
async function grantOf(env, orgId) {
  const t = now();
  return env.LIST.prepare(
    `SELECT plan, until FROM grants WHERE org_id = ? AND starts_at <= ? AND (until IS NULL OR until > ?)
     ORDER BY plan = 'team' DESC, until IS NULL DESC, until DESC LIMIT 1`).bind(orgId, t, t).first();
}

/* ---------- the panel on the account page ---------- */

/* The organisation's billing, for dashboard.js: each live subscription
   (or, with none, the last one) with its plan, status and the day it
   renews or ends, read from Stripe as the page is drawn; a grant's plan;
   or, on Free, the way to upgrade. Manage billing is offered to an owner
   or an admin with a fresh code, and the step-up to one without.
   { html, away }: away is the origin its form goes on to, for the page's
   form-action, and only when the form is there. */
export async function billingPanel(env, who, onPlan, { error = "", upgraded = false } = {}) {
  const org = who.org;
  const name = escape(org.name);
  const manager = canManage(org);
  const confirmed = fresh(who);
  const t = now();
  const linked = await linkedSubscriptions(env, org.id);
  const live = linked.filter((s) => LIVE.has(s.status));
  const shown = live.length ? live : linked.slice(0, 1);
  const canOpen = manager && confirmed && Boolean(env.STRIPE_SECRET_KEY);
  const billingToken = canOpen ? await formToken(env, who.id, "billing") : null;

  const items = [];
  for (const sub of shown) {
    let known = null;
    if (env.STRIPE_SECRET_KEY) {
      try {
        known = await subscriptionNow(env, sub.id);
      } catch (err) {
        console.log(`stripe billing panel: ${err.code || "error"}`);
      }
    }
    const status = known ? known.status : sub.status;
    const words = Object.hasOwn(STATUS, status) ? STATUS[status] : status;
    const when = !known ? "<dt>Renews</dt><dd>Not known just now</dd>"
      : known.renews_at ? `<dt>Renews</dt><dd data-renews>${day(known.renews_at)}</dd>`
        : known.ends_at ? `<dt>${known.ends_at > t ? "Ends" : "Ended"}</dt><dd data-ends>${day(known.ends_at)}</dd>` : "";
    const manage = canOpen ? form("/billing", billingToken, `
        <input type="hidden" name="subscription" value="${escape(sub.id)}">
        <button type="submit">Manage billing</button>`) : "";
    items.push(`<div data-subscription="${escape(sub.id)}"><dl>
        <dt>Plan</dt><dd>Plus${known && known.interval ? `, ${known.interval}` : ""}</dd>
        <dt>Status</dt><dd data-status="${escape(status)}">${escape(words)}</dd>
        ${when}
      </dl>${manage}</div>`);
  }

  let how = "";
  if (shown.length) {
    how = !manager ? `<p>An owner or an admin of ${name} manages its billing.</p>`
      : !env.STRIPE_SECRET_KEY ? "<p>Billing cannot be opened from here just now.</p>"
        : confirmed ? "<p><small>Manage billing opens Stripe's billing page, to change the plan or the card, get invoices, or cancel.</small></p>"
          : `<p>Manage billing needs an emailed code typed in the last ${FRESH_FOR / 60} minutes.</p>
      ${form("/stepup", await formToken(env, who.id, "stepup"),
        `<input type="hidden" name="next" value="/"><button type="submit">Email me a code</button>`)}`;
  }

  let standing = "";
  if (!live.length && onPlan !== "free") {
    const grant = await grantOf(env, org.id);
    if (grant) {
      standing = `<p>${name} has ${PLAN_NAMES[grant.plan]} from ranwhat directly${grant.until
        ? `, until ${day(grant.until)}` : ""}, with nothing to pay here.</p>`;
    }
  } else if (onPlan === "free") {
    standing = manager
      ? `<p>${name} is on Free. Plus is ${PRICES.monthly} or ${PRICES.yearly}, one price for the organisation.</p>
      <p><a class="button" href="/upgrade">Upgrade to Plus</a></p>
      <p><small>Bought Plus on ranwhat.com without an account? <a href="/claim">Attach it to ${name}</a>.</small></p>`
      : `<p>${name} is on Free. An owner or an admin of it can upgrade it to Plus.</p>`;
  }

  let notice = "";
  if (upgraded) {
    notice = atLeast(onPlan, "plus")
      ? `<p data-upgraded>Plus is on for ${name}. Link a machine with <strong>uvx ranwhat login</strong>.</p>`
      : `<p data-upgraded>Thank you. Stripe is confirming the payment, and Plus switches on here as soon as
       it has, usually within a minute. Reload this page to see it.</p>`;
  }

  return {
    html: `<section class="panel" id="billing">
    <h2>Billing</h2>
    ${notice}
    ${items.join("\n    ")}
    ${standing}
    ${problem(error)}
    ${how}</section>`,
    away: canOpen && shown.length ? [PORTAL_ORIGIN] : [],
  };
}

/* ---------- upgrading ---------- */

/* The upgrade page: what Plus adds and costs, and the two choices, for an
   owner or an admin with a fresh code; otherwise whichever of those it is
   not yet, or that the organisation is on Plus already. */
async function upgradeForm(env, who, { error = "", status = 200 } = {}) {
  const org = who.org;
  const name = escape(org.name);
  const onPlan = await plan(env, org.id);
  const head = "<h1>Upgrade to Plus</h1>";
  if (atLeast(onPlan, "plus")) {
    return page("Upgrade to Plus", `${head}
    <p>${name} is on ${PLAN_NAMES[onPlan]} already, so there is nothing to buy.${canManage(org)
      ? " Manage billing on your account page changes the plan or the card." : ""}</p>
    ${problem(error)}${back}`, { status });
  }
  const served = featuresOf("plus").filter((f) => f.status === "live").map((f) => escape(f.name));
  const about = `<p>Plus adds what needs a server, for everyone in <strong>${name}</strong>:
       ${served.join(" and ")} now, and the rest of the <a href="/#plus">Plus panel</a> as it comes.
       Everything ranwhat does on your machines stays free.</p>
    <p>${PRICES.monthly}, or ${PRICES.yearly} (two months free), one price for the organisation.
       Stripe takes the payment and shows the total, with any tax, before you pay. Cancel any time
       with Manage billing on your account page; Plus stays on to the end of the period paid for.</p>`;
  if (!sellable(env)) {
    return page("Upgrade to Plus", `${head}
    <p>Upgrading is not open yet. If you want Plus now,
       <a href="mailto:hello@ranwhat.com?subject=ranwhat%20Plus">write to us</a>.</p>${back}`, { status: 503 });
  }
  if (!canManage(org)) {
    return page("Upgrade to Plus", `${head}${about}
    <p>Only an owner or an admin of ${name} can upgrade it. Ask one of them.</p>
    ${problem(error)}${back}`, { status });
  }
  if (!fresh(who)) {
    return page("Upgrade to Plus", `${head}${about}
    <p>Opening checkout needs an emailed code typed in the last ${FRESH_FOR / 60} minutes. We send one to
       <strong>${escape(who.email)}</strong>; once you type it you come back here.</p>
    ${problem(error)}
    ${form("/stepup", await formToken(env, who.id, "stepup"), `
      <input type="hidden" name="next" value="/upgrade">
      <button type="submit">Email me a code</button>`)}
    ${back}`, { status });
  }
  const token = await formToken(env, who.id, "upgrade");
  const choice = (interval, label) => form("/upgrade", token, `
      <input type="hidden" name="plan" value="${interval}">
      <button type="submit">${label}, ${PRICES[interval]}</button>`, "row");
  return page("Upgrade to Plus", `${head}${about}
    ${problem(error)}
    ${choice("monthly", "Monthly")}
    ${choice("yearly", "Yearly")}
    ${back}`, { status, away: [CHECKOUT_ORIGIN] });
}

/* GET /upgrade. */
export async function upgradePage(request, env) {
  const who = await current(request, env);
  if (!who) return toSignin(request);
  return upgradeForm(env, who);
}

/* POST /upgrade: a Checkout bound to the organisation being looked at,
   never one a form names. Who may, the plan and the fresh code are each
   checked before anything is asked of Stripe. */
export async function upgradePost(request, env) {
  const who = await current(request, env);
  if (!who) return toSignin(request);
  const f = await fields(request);
  if (!await formOk(env, f, who.id, "upgrade")) return refused();
  const org = who.org;
  if (!canManage(org)) {
    return upgradeForm(env, who, { status: 403, error: "Only an owner or an admin can upgrade it, so checkout did not open." });
  }
  if (atLeast(await plan(env, org.id), "plus")) return upgradeForm(env, who, { status: 409 });
  if (!sellable(env)) return upgradeForm(env, who);
  const interval = f.get("plan");
  if (typeof interval !== "string" || !Object.hasOwn(INTERVALS, interval)) {
    return upgradeForm(env, who, { status: 400, error: "Choose monthly or yearly." });
  }
  if (!fresh(who)) {
    return upgradeForm(env, who, { status: 403,
      error: `Opening checkout needs an emailed code typed in the last ${FRESH_FOR / 60} minutes, so it did not open.` });
  }
  if (await bump(env, "upgrade-org", org.id, HOUR) > UPGRADES_PER_HOUR) {
    return upgradeForm(env, who, { status: 429,
      error: "Checkout was opened for this organisation too many times in the last hour. Try again later." });
  }
  const db = env.LIST;
  const row = await db.prepare("SELECT customer FROM orgs WHERE id = ?").bind(org.id).first();
  let session;
  try {
    session = await orgCheckout(env, { org: org.id, interval, customer: row ? row.customer : null });
  } catch (err) {
    console.log(`stripe org checkout: ${err.code || "error"}`);
    return upgradeForm(env, who, { status: 502,
      error: "Checkout did not open. Nothing was charged; try again in a minute." });
  }
  if (!session || typeof session.url !== "string" || !CHECKOUT_URL.test(session.url)) {
    console.log("stripe org checkout: no checkout url");
    return upgradeForm(env, who, { status: 502,
      error: "Checkout did not open. Nothing was charged; try again in a minute." });
  }
  await event(db, { org: org.id, user: who.user, what: "upgrade_started", subject: interval }).run();
  return away(session.url);
}

/* ---------- Manage billing ---------- */

async function billingProblem(env, who, status, text, { stepup = false, fallback = false } = {}) {
  return page("Billing", `<h1>Billing</h1>
    ${problem(text)}
    ${fallback ? `<p>Try again in a minute, or sign in to Stripe's billing page with your billing email at
       <a href="https://ranwhat.com/api/billing">ranwhat.com/api/billing</a>.</p>` : ""}
    ${stepup ? form("/stepup", await formToken(env, who.id, "stepup"), `
      <input type="hidden" name="next" value="/">
      <button type="submit">Email me a code</button>`) : ""}
    ${back}`, { status });
}

/* POST /billing: Stripe's billing portal for the customer of a
   subscription linked to this organisation, looked up here, never taken
   from the form. */
export async function billingPost(request, env) {
  const who = await current(request, env);
  if (!who) return redirect("/signin", readCookie(request, SESSION_COOKIE) ? [clearCookie(SESSION_COOKIE)] : []);
  const f = await fields(request);
  if (!await formOk(env, f, who.id, "billing")) return refused();
  const org = who.org;
  if (!canManage(org)) {
    return billingProblem(env, who, 403, `Only an owner or an admin of ${org.name} can open its billing.`);
  }
  const sub = await linkedSubscription(env, org.id, f.get("subscription"));
  if (!sub) {
    return billingProblem(env, who, 404, `That subscription is not linked to ${org.name}, so billing did not open.`);
  }
  if (!fresh(who)) {
    return billingProblem(env, who, 403,
      `Opening billing needs an emailed code typed in the last ${FRESH_FOR / 60} minutes, so it did not open.`, { stepup: true });
  }
  if (!env.STRIPE_SECRET_KEY) return billingProblem(env, who, 503, "Billing cannot be opened from here just now.", { fallback: true });
  if (await bump(env, "billing-org", org.id, HOUR) > PORTALS_PER_HOUR) {
    return billingProblem(env, who, 429, "Billing was opened for this organisation too many times in the last hour.",
      { fallback: true });
  }
  let portal;
  try {
    portal = await portalSession(env, sub.customer);
  } catch (err) {
    console.log(`stripe portal session: ${err.code || "error"}`);
    return billingProblem(env, who, 502, "Stripe's billing page did not open.", { fallback: true });
  }
  if (!portal || typeof portal.url !== "string" || !PORTAL_URL.test(portal.url)) {
    console.log("stripe portal session: no portal url");
    return billingProblem(env, who, 502, "Stripe's billing page did not open.", { fallback: true });
  }
  await event(env.LIST, { org: org.id, user: who.user, what: "billing_opened", subject: sub.id }).run();
  return away(portal.url);
}
