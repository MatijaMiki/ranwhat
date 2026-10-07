/* Attaching a Plus subscription bought on the pricing page, without an
 * account, to an organisation on account.ranwhat.com. The calls to Stripe
 * are stripe.js's; the welcome page and the token email link here.
 *
 *   GET  /claim         The page, for the organisation being looked at:
 *                       with ?session_id=cs_... (the welcome page's and the
 *                       email's link), one button that attaches the
 *                       subscription that checkout bought; always, Find my
 *                       subscription. Without a session: sign in first,
 *                       and back here with the checkout. Nothing is asked of
 *                       Stripe on a GET.
 *   POST /claim         Attaches one, given exactly one of two proofs, each
 *                       fetched from Stripe again (stripe.js):
 *                         session_id    the Checkout that bought it, made
 *                                       at most a day ago, complete and
 *                                       paid;
 *                         subscription  one whose Stripe customer's email
 *                                       is the address this person has
 *                                       just typed a code for (as Find my
 *                                       subscription lists them).
 *   POST /claim/find    Find my subscription: looks the live, unattached
 *                       subscriptions paid with that address up in Stripe
 *                       and lists them to choose from; none found, write to
 *                       us. Never run but on this click.
 *
 * Every one of these is for an owner or an admin, with an emailed code
 * typed in the last 15 minutes, checked in that order before anything is
 * asked of Stripe, so that nothing says whether an address has a
 * subscription until the person asking has just shown the address is
 * theirs. A feed token is never proof: it is shared with every machine it
 * is on, and says nothing about who paid. Nothing is ever attached by
 * itself, at sign-in or anywhere else.
 *
 * Attaching links the subscription to the organisation in
 * org_subscriptions, once and for good: one already linked to an
 * organisation is never moved (and one bought from an account is its
 * organisation's from the start). The organisation is then on Plus while
 * the subscription is live. The subscription's emailed token keeps
 * working, now named as the organisation's (auth.js), and is listed
 * among its machines as an old subscription token (kind 'legacy',
 * machines.js), where it can be revoked; revoked, it stays revoked, even
 * when the welcome page makes it again (stripe.js's issue()). The claim is
 * in the organisation's activity, and a notice goes to the Stripe
 * customer's email, out of the signed-in share of the day's account mail
 * (accounts.js): a claim that could not send it is not made. That address
 * is Stripe's, used for the notice and kept nowhere here.
 *
 * A subscription paid with another address, or a token made by hand, is
 * attached by an operator with scripts/org_admin.py.
 */
import { escape, mail, resend, REPLY_TO } from "./list.js";
import { ACCOUNT_HOST, HOUR, canManage, now, spendAuthMail } from "./accounts.js";
import {
  ACCOUNT_FROM, FRESH_FOR, SESSION_COOKIE, bump, clearCookie, current, formOk, formToken, fresh, readCookie,
} from "./session.js";
import { fields, form, page, redirect, refused } from "./ui.js";
import {
  CHECKOUT_ID, CUSTOMER, SUBSCRIPTION, checkoutClaim, issue, subscriptionClaim, subscriptionsFor,
} from "./stripe.js";

/* Lookups in Stripe one person makes an hour, Find my subscription and
   attaching together: each is a few calls to Stripe, and nobody needs
   many. */
export const CLAIM_LOOKUPS_PER_HOUR = 10;

const WRITE = "mailto:hello@ranwhat.com?subject=Attach%20a%20ranwhat%20Plus%20subscription";
const problem = (text) => (text ? `<p class="bad">${escape(text)}</p>` : "");
const back = `<p><a href="/">Your account</a></p>`;
const day = (t) => new Date(t * 1000).toISOString().slice(0, 10);

/* Where this page is, with the checkout it came from: also where a sign-in
   or a fresh code comes back to (session.js's nextPath() allows both). */
const here = (checkout) => (checkout ? `/claim?session_id=${checkout}` : "/claim");
const checkoutIn = (value) => (typeof value === "string" && CHECKOUT_ID.test(value) ? value : null);

const signedOut = (request, path) =>
  redirect(path, readCookie(request, SESSION_COOKIE) ? [clearCookie(SESSION_COOKIE)] : []);

/* ---------- the page ---------- */

/* The page for `who`'s organisation: who may attach, the fresh code, and
   then the two ways, the checkout's (when it came with one) and Find my
   subscription. */
async function claimForm(env, who, { checkout = null, error = "", status = 200 } = {}) {
  const org = who.org;
  const name = escape(org.name);
  const head = `<h1>Attach a subscription</h1>
    <p>A Plus subscription bought on ranwhat.com without an account can be attached to
       <strong>${name}</strong>, for good. ${name} is then on Plus while it is live, and each machine
       links itself with <strong>uvx ranwhat login</strong>. The token emailed with it keeps working,
       listed under Machines on your account page, where you can revoke it.</p>`;
  if (!env.STRIPE_SECRET_KEY) {
    return page("Attach a subscription", `${head}
    <p>Attaching cannot be done from here just now. <a href="${WRITE}">Write to us</a>, and we attach it
       for you.</p>${back}`, { status: 503 });
  }
  if (!canManage(org)) {
    return page("Attach a subscription", `${head}
    <p>Only an owner or an admin of ${name} can attach a subscription to it. Ask one of them.</p>
    ${problem(error)}${back}`, { status });
  }
  if (!fresh(who)) {
    return page("Attach a subscription", `${head}
    <p>Attaching needs an emailed code typed in the last ${FRESH_FOR / 60} minutes. We send one to
       <strong>${escape(who.email)}</strong>; once you type it you come back here.</p>
    ${problem(error)}
    ${form("/stepup", await formToken(env, who.id, "stepup"), `
      <input type="hidden" name="next" value="${escape(here(checkout))}">
      <button type="submit">Email me a code</button>`)}
    ${back}`, { status });
  }
  const fromCheckout = checkout ? `<h2>From your checkout</h2>
    <p>The checkout you came from shows which subscription is yours, for a day after paying.</p>
    ${form("/claim", await formToken(env, who.id, "claim"), `
      <input type="hidden" name="session_id" value="${escape(checkout)}">
      <button type="submit">Attach to ${name}</button>`)}` : "";
  return page("Attach a subscription", `${head}
    ${problem(error)}
    ${fromCheckout}
    <h2>Find my subscription</h2>
    <p>Look in Stripe for live subscriptions paid with <strong>${escape(who.email)}</strong>, the address
       you just confirmed with a code, and choose the one to attach.</p>
    ${form("/claim/find", await formToken(env, who.id, "claim-find"), `
      <button type="submit">Find my subscription</button>`)}
    <p><small>Paid with another address? <a href="${WRITE}">Write to us</a> from that address, and we
       attach it for you.</small></p>
    ${back}`, { status });
}

/* GET /claim. The checkout's id is kept only when it has the shape Stripe
   gives one; nothing is asked of Stripe until a button is pressed. */
export async function claimPage(request, env, ctx, url) {
  const checkout = checkoutIn(url.searchParams.get("session_id"));
  const who = await current(request, env);
  if (!who) return signedOut(request, `/signin?next=${encodeURIComponent(here(checkout))}`);
  return claimForm(env, who, { checkout });
}

/* What both POSTs check, in this order, before anything is asked of
   Stripe: the form, the role, the fresh code, what the form names
   (`named`: true, or why not, for POST /claim), and this person's
   lookups this hour, counted only for a form that gets this far. A
   Response to send back, or null to go on. */
async function gate(env, who, f, action, { checkout = null, named = true } = {}) {
  if (!await formOk(env, f, who.id, action)) return refused();
  if (!canManage(who.org)) {
    return claimForm(env, who, { checkout, status: 403,
      error: `Only an owner or an admin of ${who.org.name} can attach a subscription to it, so nothing was attached.` });
  }
  if (!fresh(who)) {
    return claimForm(env, who, { checkout, status: 403,
      error: `Attaching needs an emailed code typed in the last ${FRESH_FOR / 60} minutes, so nothing was looked up.` });
  }
  if (!env.STRIPE_SECRET_KEY) return claimForm(env, who, { checkout });
  if (named !== true) return claimForm(env, who, { checkout, status: 400, error: named });
  if (await bump(env, "claim-user", who.user, HOUR) > CLAIM_LOOKUPS_PER_HOUR) {
    return claimForm(env, who, { checkout, status: 429,
      error: "That is more lookups in Stripe than we make for one person in an hour. Try again later." });
  }
  return null;
}

/* ---------- Find my subscription ---------- */

/* POST /claim/find: the live subscriptions paid with this person's own
   address, not yet attached to any organisation, each with a button that
   attaches it here. */
export async function claimFind(request, env) {
  const who = await current(request, env);
  if (!who) return signedOut(request, "/signin?next=/claim");
  const f = await fields(request);
  const stop = await gate(env, who, f, "claim-find");
  if (stop) return stop;
  let found;
  try {
    found = await subscriptionsFor(env, who.email);
  } catch (err) {
    console.log(`stripe claim find: ${err.code || "error"}`);
    return claimForm(env, who, { status: 502, error: "Stripe did not answer just now. Try again in a minute." });
  }
  const db = env.LIST;
  const open = [];
  for (const sub of found) {
    const linked = await db.prepare("SELECT 1 AS yes FROM org_subscriptions WHERE subscription = ?").bind(sub.id).first();
    if (!linked && !open.some((s) => s.id === sub.id)) open.push(sub);
  }
  const name = escape(who.org.name);
  if (!open.length) {
    return page("Find my subscription", `<h1>Find my subscription</h1>
    <p data-found="0">We found no live Plus subscription paid with <strong>${escape(who.email)}</strong> that is
       not attached to an organisation already.</p>
    <p>If you paid with another address, or bought Plus some other way,
       <a href="${WRITE}">write to us</a> from the address you paid with, and we attach it for you.</p>
    <p><a href="/claim">Back</a></p>`);
  }
  const token = await formToken(env, who.id, "claim");
  const items = open.map((s) => `<li data-subscription="${escape(s.id)}">Plus${s.interval ? `, ${s.interval}` : ""}${
    s.since ? `, since ${day(s.since)}` : ""}
      ${form("/claim", token, `
        <input type="hidden" name="subscription" value="${escape(s.id)}">
        <button type="submit">Attach to ${name}</button>`)}</li>`).join("\n    ");
  return page("Find my subscription", `<h1>Find my subscription</h1>
    <p data-found="${open.length}">${open.length === 1 ? "This live Plus subscription was"
      : `These ${open.length} live Plus subscriptions were`} paid with <strong>${escape(who.email)}</strong>,
       and ${open.length === 1 ? "is" : "are"} not attached to an organisation yet. Choose the one to attach to
       <strong>${name}</strong>.</p>
    <ul>${items}</ul>
    <p><a href="/claim">Back</a></p>`);
}

/* ---------- attaching ---------- */

const REFUSED = {
  unknown: [404, "That subscription was not found, so nothing was attached."],
  account: [409, "That subscription was bought from an account, and is the organisation's it was bought for."],
  old: [403, "That checkout was more than a day ago, so it no longer shows the subscription is yours. Use Find my subscription instead."],
  unpaid: [409, "That checkout is not paid yet. It can be attached once the payment has gone through."],
  inactive: [409, "That subscription is not active, so there is nothing to attach."],
  elsewhere: [409, "That subscription is attached to another organisation already, and an attached subscription is never moved. If that is wrong, write to us."],
  budget: [503, "Attaching sends a notice to the subscription's billing email, and today's account email is used up. Try again after midnight UTC."],
};

/* POST /claim: exactly one proof, session_id or subscription. Anything
   else, a feed token among them, is refused before Stripe is asked. */
export async function claimPost(request, env, ctx) {
  const who = await current(request, env);
  if (!who) return signedOut(request, "/signin?next=/claim");
  const f = await fields(request);
  const sent = f.get("session_id");
  const named = f.get("subscription");
  const checkout = checkoutIn(sent);
  const bySession = typeof sent === "string" && sent !== "";
  const byEmail = typeof named === "string" && named !== "";
  const one = bySession !== byEmail && (bySession ? Boolean(checkout) : SUBSCRIPTION.test(named));
  const stop = await gate(env, who, f, "claim", { checkout, named: one ||
    "Attach from your checkout's link, or choose a subscription from Find my subscription. Nothing else, a feed token included, shows that a subscription is yours." });
  if (stop) return stop;
  let proof;
  try {
    proof = checkout ? await checkoutClaim(env, checkout) : await subscriptionClaim(env, named, who.email);
  } catch (err) {
    console.log(`stripe claim: ${err.code || "error"}`);
    return claimForm(env, who, { checkout, status: 502, error: "Stripe did not answer just now. Try again in a minute." });
  }
  const outcome = proof.refused ? proof.refused : await attach(env, ctx, who, proof, checkout ? "session" : "email");
  if (outcome === "attached" || outcome === "here") return attached(who, outcome === "here");
  const [status, text] = REFUSED[outcome];
  return claimForm(env, who, { checkout: outcome === "old" ? null : checkout, status, error: text });
}

/* Links `proof.sub` to `who`'s organisation: "attached" when this request
   did, "here" when it was already this organisation's, otherwise why not.
   The link, the old token's machine rows, the organisation's Stripe
   customer (when it has none yet) and the event are one batch, and all
   but the link are written only once the link is this request's own. */
async function attach(env, ctx, who, { sub, email }, how) {
  const db = env.LIST;
  const org = who.org;
  const linked = async () => {
    const row = await db.prepare("SELECT org_id FROM org_subscriptions WHERE subscription = ?").bind(sub.id).first();
    return row ? (row.org_id === org.id ? "here" : "elsewhere") : null;
  };
  const before = await linked();
  if (before) return before;
  /* The notice is the buyer's word that this happened, so no claim is
     made that could not send it. */
  if (email && !await spendAuthMail(env, "notice")) return "budget";

  /* The token the welcome page and the email give, made now if neither
     has yet, so that its machine row is there for whenever it is. */
  await issue(env, sub);
  const { results: hashes } = await db.prepare(
    `SELECT l.hash FROM token_subscriptions l JOIN tokens k ON k.hash = l.hash
     WHERE l.subscription = ? AND k.revoked_at IS NULL`).bind(sub.id).all();
  const t = now();
  const mine = "EXISTS (SELECT 1 FROM org_subscriptions WHERE subscription = ? AND org_id = ? AND linked_by = ? AND linked_at = ?)";
  const mineArgs = [sub.id, org.id, who.user, t];
  const done = await db.batch([
    db.prepare(`INSERT OR IGNORE INTO org_subscriptions (subscription, org_id, how, linked_by, linked_at)
                SELECT ?, id, ?, ?, ? FROM orgs WHERE id = ?`).bind(sub.id, how, who.user, t, org.id),
    ...hashes.map(({ hash }) => db.prepare(
      `INSERT OR IGNORE INTO machines (id, hash, org_id, user_id, kind, label, created_at)
       SELECT ?, ?, ?, NULL, 'legacy', '', ? WHERE ${mine}`).bind(crypto.randomUUID(), hash, org.id, t, ...mineArgs)),
    ...(CUSTOMER.test(String(sub.customer)) ? [
      db.prepare(`UPDATE orgs SET customer = ? WHERE id = ? AND customer IS NULL AND ${mine}`)
        .bind(sub.customer, org.id, ...mineArgs),
    ] : []),
    db.prepare(`INSERT INTO auth_events (org_id, user_id, event, subject, at)
                SELECT ?, ?, ?, ?, ? WHERE ${mine}`)
      .bind(org.id, who.user, how === "session" ? "plus_claimed_checkout" : "plus_claimed_email", sub.id, t, ...mineArgs),
  ]);
  if (done[0].meta.changes !== 1) return await linked() || "unknown";
  if (email) {
    ctx.waitUntil(mailClaimed(env, email, org.name).catch((err) => {
      console.log(`claim notice mail: ${err.code || err.name || "error"}`);
    }));
  }
  return "attached";
}

/* The page after attaching, or after trying again something already
   attached here. */
function attached(who, already) {
  const name = escape(who.org.name);
  return page("Subscription attached", `<h1>Plus is on for ${name}.</h1>
    <p data-claimed>${already ? `That subscription was attached to ${name} already.`
      : `The subscription is attached to ${name}, for good.`} Link each machine with
       <strong>uvx ranwhat login</strong>, or make a CI token on your account page.</p>
    <p>The token emailed with it keeps working, listed under Machines as an old subscription token, where
       you can revoke it once every machine has moved to ranwhat login.</p>
    <p>Manage billing on your account page changes the plan or the card.</p>
    ${back}`);
}

/* To the Stripe customer's email: their subscription is now an
   organisation's. It names the organisation, never who attached it or
   their address. */
async function mailClaimed(env, to, orgName) {
  const name = String(orgName).replace(/[\r\n]+/g, " ");
  const said = `Your ranwhat Plus subscription was attached to the organisation "${name}" on ${ACCOUNT_HOST}.`;
  const after = "Its machines can now link themselves with `uvx ranwhat login`. The feed token emailed " +
    "with the subscription keeps working, and is listed on that organisation's account page, where it can be revoked.";
  const ifNot = "If that was not you, reply to this email straight away.";
  await resend(env, "POST", "/emails", {
    from: ACCOUNT_FROM,
    to: [to],
    reply_to: REPLY_TO,
    subject: "Your ranwhat Plus subscription was attached to an account",
    text: [said, "", after, "", "If that was you, there is nothing to do.", "", ifNot, "", "ranwhat.com"].join("\n"),
    html: mail(`
      <p>${escape(said)}</p>
      <p>${escape(after)}</p>
      <p>If that was you, there is nothing to do.</p>
      <p>${escape(ifNot)}</p>`),
  });
}

/* For dashboard.js's event list. */
export const CLAIM_EVENTS = Object.freeze({
  plus_claimed_checkout: "Plus subscription attached from its checkout, with a fresh code",
  plus_claimed_email: "Plus subscription attached by its billing email, with a fresh code",
});
