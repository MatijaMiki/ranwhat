/* Paying for Plus from account.ranwhat.com: upgrading a Free organisation
 * through a Stripe Checkout bound to it, the billing panel on the account
 * page, and Manage billing, which opens Stripe's billing portal for the
 * organisation's customer. The calls to Stripe are stripe.js's, and so is
 * the webhook that links what was bought to the organisation.
 *
 *   GET  /upgrade   Monthly or yearly, for the organisation being looked
 *                   at. Without a session: sign in first, and back here.
 *   POST /upgrade   An owner or an admin, of an organisation on neither
 *                   Plus nor Team: makes the Checkout (stripe.js's
 *                   orgCheckout()), on the organisation's own Stripe
 *                   customer, and sends the browser to it. Once the
 *                   organisation has that customer, which may hold a
 *                   card saved with Stripe, only with an emailed code
 *                   typed in the last 15 minutes; its first Checkout,
 *                   with nothing saved to charge, without.
 *   POST /billing   An owner or an admin, with a fresh code, naming a
 *                   subscription linked to this organisation: a portal
 *                   session for that subscription's customer, and off to
 *                   it.
 *
 * With accounts on and the account host ready, this is the one way to buy
 * Plus: the pricing page's checkout (/api/checkout, stripe.js) sends the
 * browser to /upgrade instead. A subscription bought on the pricing page before then is
 * attached to an organisation only by hand (scripts/org_admin.py link),
 * and once it is, it is billed here like any other. The portal login
 * behind /api/billing is stripe.js's and unchanged.
 *
 * Both forms are bound to the organisation they were drawn for (session.js's
 * orgFormOk()): one left open in a tab acts on nothing once the session
 * looks at another organisation, and a Checkout or a portal is never
 * opened for an organisation the page did not name.
 *
 * The organisation's Stripe customer is its own, made here before its
 * first Checkout with its owner's address (customerFor()), and every
 * Checkout is on it: never one Stripe makes from the address whoever pays
 * types, whom Stripe's billing-page login (/api/billing) would then let in
 * for good. That address is the organisation's billing email, which an
 * owner or an admin may change in Stripe's billing portal. When someone
 * stops being an owner or an admin (members.js), billingEmailFollows()
 * moves it back to the owner's address unless it belongs to someone who
 * is still an owner or an admin, and not to an owner who has just handed
 * the organisation on; the cron tries again while Stripe fails.
 *
 * Both POSTs leave this host only for an address Stripe gave back, and
 * only for checkout.stripe.com or billing.stripe.com; a page whose form
 * goes there adds that origin, and only while the form is on it, to its
 * form-action (ui.js). An organisation opens only so many Checkout and
 * portal sessions an hour, so no session can make Stripe ones without
 * end; and the billing panel is drawn from what the webhook kept, so
 * loading the account page, however often, asks Stripe nothing
 * (billingPanel() says when it does, and how rarely).
 */
import { LIVE, plan } from "./auth.js";
import { escape } from "./list.js";
import { PLAN_NAMES, atLeast, featuresOf } from "./features.js";
import { HOUR, canManage, event, now } from "./accounts.js";
import {
  FRESH_FOR, SESSION_COOKIE, bump, clearCookie, current, formToken, fresh, orgFormOk, orgInput, orgToken, readCookie,
} from "./session.js";
import { away, elsewhere, fields, form, page, redirect, refused } from "./ui.js";
import {
  CUSTOMER, INTERVALS, SUBSCRIPTION, customerEmail, orgCheckout, orgCustomer, portalSession, refreshTerms, sellable,
  setCustomerEmail,
} from "./stripe.js";

export const CHECKOUT_ORIGIN = "https://checkout.stripe.com";
export const PORTAL_ORIGIN = "https://billing.stripe.com";
const CHECKOUT_URL = /^https:\/\/checkout\.stripe\.com\//;
const PORTAL_URL = /^https:\/\/billing\.stripe\.com\//;

export const UPGRADES_PER_HOUR = 10;    // Checkout sessions one organisation opens an hour
export const PORTALS_PER_HOUR = 20;     // and portal sessions
export const TERMS_READS_PER_HOUR = 10; // and reads of terms no event has brought (billingPanel())
const SHOWN = 5;                         // subscriptions the panel lists at most

/* What each choice costs, as the pricing page says it. Stripe's price,
   found by its lookup key (stripe.js's INTERVALS), is what is charged. */
const PRICES = Object.freeze({ monthly: "€12 a month", yearly: "€120 a year" });

/* A subscription bought without an account is moved to an organisation by
   hand (scripts/org_admin.py link), on request from whoever paid. */
const MOVE = "mailto:hello@ranwhat.com?subject=Move%20a%20ranwhat%20Plus%20subscription";

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

/* The subscriptions linked to an organisation, with their status and
   terms as the webhook last kept them (fetched_at null: no terms kept
   yet): the live ones first, then the most recently linked. */
export async function linkedSubscriptions(env, orgId, limit = SHOWN) {
  const live = [...LIVE];
  const { results } = await env.LIST.prepare(
    `SELECT s.id, s.customer, s.status, l.linked_at, t.interval, t.renews_at, t.ends_at, t.fetched_at
     FROM org_subscriptions l JOIN subscriptions s ON s.id = l.subscription
     LEFT JOIN subscription_terms t ON t.subscription = s.id
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
    `SELECT s.id, s.customer, s.status, l.linked_at, t.interval, t.renews_at, t.ends_at, t.fetched_at
     FROM org_subscriptions l JOIN subscriptions s ON s.id = l.subscription
     LEFT JOIN subscription_terms t ON t.subscription = s.id
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
   renews or ends, as the webhook last kept them (stripe.js's keep()); a
   grant's plan; or, on Free, the way to upgrade. Manage billing is
   offered to an owner or an admin with a fresh code, and the step-up to
   one without.

   Drawing the page asks Stripe nothing, whoever draws it and however
   often. The one exception is a subscription whose terms no event has
   brought yet (one linked by scripts/org_admin.py): drawn for an owner or
   an admin, it is fetched from Stripe and kept, so it is asked for once,
   and an organisation asks at most TERMS_READS_PER_HOUR times an hour
   even while Stripe fails. Anyone else sees it as not known yet.

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
  const billingToken = canOpen ? await orgToken(env, who, "billing") : null;

  const items = [];
  for (let sub of shown) {
    if (sub.fetched_at == null && manager && env.STRIPE_SECRET_KEY &&
        await bump(env, "terms-org", org.id, HOUR) <= TERMS_READS_PER_HOUR) {
      try {
        await refreshTerms(env, sub.id);
        sub = await linkedSubscription(env, org.id, sub.id) || sub;
      } catch (err) {
        console.log(`stripe billing panel: ${err.code || "error"}`);
      }
    }
    const known = sub.fetched_at == null ? null : sub;
    const status = sub.status;
    const words = Object.hasOwn(STATUS, status) ? STATUS[status] : status;
    const when = !known ? "<dt>Renews</dt><dd>Not known just now</dd>"
      : known.renews_at ? `<dt>Renews</dt><dd data-renews>${day(known.renews_at)}</dd>`
        : known.ends_at ? `<dt>${known.ends_at > t ? "Ends" : "Ended"}</dt><dd data-ends>${day(known.ends_at)}</dd>` : "";
    const manage = canOpen ? form("/billing", billingToken, `${orgInput(who)}
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
        : confirmed ? `<p><small>Manage billing opens Stripe's billing page, to change the plan or the card, get invoices, or cancel.</small></p>
      <p><small>Stripe's billing page also opens, from ranwhat.com/api/billing, for whoever reads ${name}'s
         billing email, to which Stripe mails a link. That is the owner's address unless an owner or an admin
         changes it on that page, and whenever an owner or an admin leaves, is removed, is made a member or
         hands on ownership, it goes back to the owner's address, unless it is the address of someone who is
         still an owner or an admin here and did not just hand ownership on.</small></p>`
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
      <p><small>To move a Plus subscription bought without an account to ${name}, write to
         <a href="${MOVE}">hello@ranwhat.com</a>.</small></p>`
      : `<p>${name} is on Free. An owner or an admin of it can upgrade it to Plus.</p>`;
  }

  /* Two Checkouts paid, or one besides an attached purchase: the
     organisation pays twice until one is cancelled. */
  const twice = live.length > 1 ? `<p class="bad" data-twice="${live.length}">${name} has ${live.length} live Plus
       subscriptions, and needs one. ${manager ? "Cancel the one you do not want with its Manage billing, and"
        : "An owner or an admin can cancel the one it does not want with Manage billing;"} write to
       <a href="mailto:hello@ranwhat.com?subject=ranwhat%20Plus%20paid%20twice">hello@ranwhat.com</a> for a refund
       of it.</p>` : "";

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
    ${twice}
    ${items.join("\n    ")}
    ${standing}
    ${problem(error)}
    ${how}</section>`,
    away: canOpen && shown.length ? [PORTAL_ORIGIN] : [],
  };
}

/* ---------- upgrading ---------- */

/* Whether the organisation has its own Stripe customer already: one that
   may hold a card saved with Stripe, which a Checkout on it could charge,
   so opening one then needs a fresh code. */
async function hasCustomer(env, orgId) {
  const row = await env.LIST.prepare("SELECT customer FROM orgs WHERE id = ?").bind(orgId).first();
  return Boolean(row && CUSTOMER.test(String(row.customer)));
}

/* The upgrade page: what Plus adds and costs, and the two choices, for an
   owner or an admin (with a fresh code, once the organisation has a
   Stripe customer); otherwise whichever of those it is not yet, or that
   the organisation is on Plus already. */
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
  /* Members are who "everyone" is, so they get a sentence of their own. */
  const served = featuresOf("plus").filter((f) => f.status === "live" && f.key !== "members").map((f) => escape(f.name));
  const about = `<p>Plus adds what needs a server, for everyone in <strong>${name}</strong>:
       ${served.join(" and ")} now, and the rest of the <a href="/#plus">Plus panel</a> as it comes.
       Invite as many of your team as you like. Everything ranwhat does on your machines stays free.</p>
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
  if (!fresh(who) && await hasCustomer(env, org.id)) {
    return page("Upgrade to Plus", `${head}${about}
    <p>Opening checkout needs an emailed code typed in the last ${FRESH_FOR / 60} minutes, as Stripe holds
       billing details for ${name} already. We send one to
       <strong>${escape(who.email)}</strong>; once you type it you come back here.</p>
    ${problem(error)}
    ${form("/stepup", await formToken(env, who.id, "stepup"), `
      <input type="hidden" name="next" value="/upgrade">
      <button type="submit">Email me a code</button>`)}
    ${back}`, { status });
  }
  const token = await orgToken(env, who, "upgrade");
  const choice = (interval, label) => form("/upgrade", token, `${orgInput(who)}
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

/* The organisation's own Stripe customer: the one kept for it, or, for its
   first Checkout (or `replacing` the kept one, which Stripe turned down),
   a new one with its owner's address, kept unless another request kept
   one first, whose then serves. Throws as stripe() does. */
async function customerFor(env, org, { replacing = null } = {}) {
  const db = env.LIST;
  const row = await db.prepare("SELECT customer FROM orgs WHERE id = ?").bind(org.id).first();
  const kept = row && CUSTOMER.test(String(row.customer)) ? row.customer : null;
  if (kept && kept !== replacing) return kept;
  const owner = await db.prepare(
    `SELECT u.email FROM memberships m JOIN users u ON u.id = m.user_id WHERE m.org_id = ? AND m.role = 'owner'`)
    .bind(org.id).first();
  if (!owner) throw Object.assign(new Error("no owner"), { code: "no_owner", status: 0 });
  const made = await orgCustomer(env, { org: org.id, email: owner.email });
  await db.prepare("UPDATE orgs SET customer = ? WHERE id = ? AND customer IS ?").bind(made, org.id, kept).run();
  const held = await db.prepare("SELECT customer FROM orgs WHERE id = ?").bind(org.id).first();
  return held && CUSTOMER.test(String(held.customer)) ? held.customer : made;
}

/* POST /upgrade: a Checkout bound to the organisation the form was drawn
   for, which must be the one being looked at, never one a form names.
   Who may, the plan and the fresh code (where one is needed) are each
   checked before anything is asked of Stripe. */
export async function upgradePost(request, env) {
  const who = await current(request, env);
  if (!who) return toSignin(request);
  const f = await fields(request);
  const bound = await orgFormOk(env, f, who, "upgrade");
  if (bound === "refused") return refused();
  if (bound === "elsewhere") return elsewhere();
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
  if (!fresh(who) && await hasCustomer(env, org.id)) {
    return upgradeForm(env, who, { status: 403,
      error: `Opening checkout needs an emailed code typed in the last ${FRESH_FOR / 60} minutes, so it did not open.` });
  }
  if (await bump(env, "upgrade-org", org.id, HOUR) > UPGRADES_PER_HOUR) {
    return upgradeForm(env, who, { status: 429,
      error: "Checkout was opened for this organisation too many times in the last hour. Try again later." });
  }
  const db = env.LIST;
  let session;
  try {
    let customer = await customerFor(env, org);
    try {
      session = await orgCheckout(env, { org: org.id, interval, customer });
    } catch (err) {
      /* A customer deleted in Stripe since: a new one, once. */
      if (err.status !== 400 || err.param !== "customer") throw err;
      console.log(`stripe org checkout: ${err.code}, with a new customer`);
      customer = await customerFor(env, org, { replacing: customer });
      session = await orgCheckout(env, { org: org.id, interval, customer });
    }
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

/* The statement, for the batch that ends `lostUser`'s being an owner or
   an admin of the organisation (or hands its ownership on), that leaves
   its billing email to be checked: by billingEmailFollows() after the
   response, and by the cron until that has been done. Only for an
   organisation with a Stripe customer. */
export const billingEmailDue = (db, orgId, lostUser) => db.prepare(
  `INSERT INTO billing_email_due (org_id, lost_user, ticket, since) SELECT ?, ?, ?, ?
   WHERE EXISTS (SELECT 1 FROM orgs WHERE id = ? AND customer IS NOT NULL)
   ON CONFLICT (org_id) DO UPDATE SET lost_user = excluded.lost_user, ticket = excluded.ticket, since = excluded.since`)
  .bind(orgId, lostUser, crypto.randomUUID(), now(), orgId);

/* Stripe's email for the organisation's customer, which its billing-page
   login (/api/billing) mails a way in to, after someone stopped being an
   owner or an admin (billingEmailDue()). It stays only while it is the
   address of someone who is an owner or an admin of the organisation now,
   and not the address of whoever just handed ownership on (it follows the
   owner); anything else, an address an admin chose in Stripe's billing
   portal before being removed or one no member has, becomes the owner's.
   Done once Stripe has answered; while Stripe fails it stays due, logged,
   for the cron (billingEmailsDue()). */
export async function billingEmailFollows(env, orgId) {
  const db = env.LIST;
  const due = await db.prepare("SELECT lost_user, ticket FROM billing_email_due WHERE org_id = ?").bind(orgId).first();
  if (!due) return;
  const done = () => db.prepare("DELETE FROM billing_email_due WHERE org_id = ? AND ticket = ?")
    .bind(orgId, due.ticket).run();
  const row = await db.prepare(
    `SELECT o.customer, u.email AS owner FROM orgs o
     JOIN memberships m ON m.org_id = o.id AND m.role = 'owner' JOIN users u ON u.id = m.user_id
     WHERE o.id = ?`).bind(orgId).first();
  if (!row || !CUSTOMER.test(String(row.customer))) return void await done();
  if (!env.STRIPE_SECRET_KEY) return;
  const { results: managers } = await db.prepare(
    `SELECT u.email FROM memberships m JOIN users u ON u.id = m.user_id
     WHERE m.org_id = ? AND m.role IN ('owner', 'admin')`).bind(orgId).all();
  const lost = due.lost_user
    ? await db.prepare("SELECT email FROM users WHERE id = ?").bind(due.lost_user).first() : null;
  const same = (a, b) => String(a).trim().toLowerCase() === String(b).trim().toLowerCase();
  try {
    const email = await customerEmail(env, row.customer);
    const stays = Boolean(email) && managers.some((m) => same(m.email, email)) &&
      !(lost && same(lost.email, email) && !same(lost.email, row.owner));
    if (!stays) {
      await setCustomerEmail(env, row.customer, row.owner);
      console.log("stripe billing email: moved to the owner");
    }
    await done();
  } catch (err) {
    console.log(`stripe billing email: ${err.code || "error"}`);
  }
}

/* The cron, after the sweep (accounts.js), which makes the table in any
   database accounts were ever on in: billing emails still to be checked,
   the oldest few each run, so that a quarter hour's run asks Stripe at
   most ten times for them. That goes on while accounts are switched off
   again after being on; where they never were, it touches nothing. */
export async function billingEmailsDue(env) {
  const db = env.LIST;
  if (!db || !env.STRIPE_SECRET_KEY) return;
  if (!await db.prepare("SELECT 1 AS yes FROM sqlite_master WHERE type = 'table' AND name = 'billing_email_due'").first()) {
    return;
  }
  const { results } = await db.prepare("SELECT org_id FROM billing_email_due ORDER BY since LIMIT 5").all();
  for (const r of results) await billingEmailFollows(env, r.org_id);
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
   subscription linked to the organisation the form was drawn for, which
   must be the one being looked at: looked up here, never taken from the
   form. */
export async function billingPost(request, env) {
  const who = await current(request, env);
  if (!who) return redirect("/signin", readCookie(request, SESSION_COOKIE) ? [clearCookie(SESSION_COOKIE)] : []);
  const f = await fields(request);
  const bound = await orgFormOk(env, f, who, "billing");
  if (bound === "refused") return refused();
  if (bound === "elsewhere") return elsewhere();
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
