/* account.ranwhat.com: signing in with an emailed code, and the account
 * page behind it. index.js sends every request for this host here, and
 * only once ACCOUNTS_ON is set.
 *
 *   GET  /              The account: who you are, your organisation, its
 *                       plan and what each plan has (features.js), what
 *                       happened lately, and signing out.
 *                       Without a session it sends you to /signin.
 *   GET  /signin        The email form.
 *   POST /signin        Mails a code; the same answer for every address.
 *   GET  /signin/code   The box to type the code in. Never filled in.
 *   POST /signin/code   Checks it, makes the account on first use, and
 *                       opens a new session.
 *   POST /signin/again  A new code for the same address.
 *   POST /stepup        A fresh code for someone signed in, for the actions
 *                       that need one.
 *   POST /signout       Ends this session.
 *   POST /signout-all   Ends every session of this account.
 *   POST /org           Renames the organisation (owner or admin).
 *
 * Nothing changes on a GET. Every POST passes the origin check here and its
 * form token in its handler (session.js says what both are).
 */
import { escape } from "./list.js";
import { plan } from "./auth.js";
import { PLAN_NAMES, atLeast, featuresOf } from "./features.js";
import {
  SESSION_MAX, canManage, event, history, now, orgFor, orgName, ready, schema, userForVerifiedEmail,
} from "./accounts.js";
import {
  CODE_FOR, CODE_TRIES, SESSION_COOKIE, SIGNIN_COOKIE, SIGNIN_FOR, address, attempt, checkCode, clearCookie,
  current, formOk, formToken, nextPath, openSession, randomToken, readCookie, requestCode,
  sameOrigin, setCookie,
} from "./session.js";
import { form, notFound, page, redirect, refused, wrongMethod } from "./ui.js";

const PRIVACY = "https://ranwhat.com/privacy";
const PRICING = "https://ranwhat.com/pricing";
const TALK = "mailto:hello@ranwhat.com?subject=ranwhat%20Team";

/* A form's fields, or none when the body is not a form. */
async function fields(request) {
  try {
    return await request.formData();
  } catch {
    return new FormData();
  }
}

/* No session: to the sign-in page, dropping a cookie that no longer opens one. */
const signedOut = (request) =>
  redirect("/signin", readCookie(request, SESSION_COOKIE) ? [clearCookie(SESSION_COOKIE)] : []);

const problem = (text) => (text ? `<p class="bad">${escape(text)}</p>` : "");

/* ---------- signing in ---------- */

async function signinPage(request, env, ctx, url) {
  const next = nextPath(url.searchParams.get("next"));
  if (await current(request, env)) return redirect(next);
  return signinForm(env, readCookie(request, SIGNIN_COOKIE), { next });
}

/* The form's token is bound to the browser's __Host-rw_signin cookie, made
   here when it has none yet, so even the first form has something a page
   on another site cannot know. */
async function signinForm(env, binding, { next = "/", email = "", error = "", status = 200 } = {}) {
  const cookies = [];
  if (!binding) {
    binding = randomToken();
    cookies.push(setCookie(SIGNIN_COOKIE, binding, SIGNIN_FOR));
  }
  return page("Sign in", `<h1>Sign in</h1>
    <p>Type your email, and we send you a code to type on the next page. The
       same code makes your account if you do not have one yet.</p>
    ${form("/signin", await formToken(env, binding, "signin"), `
      <input type="hidden" name="next" value="${escape(next)}">
      <label for="email">Email</label>
      <input id="email" name="email" type="email" autocomplete="email" maxlength="200" required autofocus
             value="${escape(email)}">
      ${problem(error)}
      <button type="submit">Email me a code</button>`)}
    <p><small>The address is used to send the code, and kept only once the code
       is typed, as your account. This page sets two cookies, both only to sign
       you in, and nothing on it tracks you. <a href="${PRIVACY}">Privacy</a></small></p>`,
  { status, cookies });
}

async function signinPost(request, env, ctx) {
  const f = await fields(request);
  const binding = readCookie(request, SIGNIN_COOKIE);
  if (!await formOk(env, f, binding, "signin")) return refused();
  const next = nextPath(f.get("next"));
  const email = address(f.get("email"));
  if (!email) {
    return signinForm(env, binding, { next, email: String(f.get("email") ?? "").slice(0, 200),
      error: "That email address does not look right.", status: 400 });
  }
  return sendCode(request, env, ctx, { email, purpose: "signin", next, previous: binding });
}

/* Either refusal is about the network or the day, never the address. */
async function sendCode(request, env, ctx, wanted) {
  const result = await requestCode(request, env, ctx, wanted);
  if (result.refused === "network") {
    return page("Too many codes", `<h1>Too many codes asked for.</h1>
      <p>More sign-in codes were asked for from your network in the last hour
         than we send. Try again in an hour.</p>`, { status: 429 });
  }
  if (result.refused === "budget") {
    return page("No more codes today", `<h1>No more codes today.</h1>
      <p>We send a limited number of sign-in emails each day, and today's are
         used up. Try again after midnight UTC, or write to hello@ranwhat.com.</p>`, { status: 503 });
  }
  return redirect("/signin/code", [setCookie(SIGNIN_COOKIE, result.token, SIGNIN_FOR)]);
}

async function codePage(request, env) {
  const token = readCookie(request, SIGNIN_COOKIE);
  const row = await attempt(env, token);
  if (!row) return redirect("/signin");
  if (row.used_at || row.expires_at <= now()) return spent(env, token, row, "expired", 200);
  if (row.tries >= CODE_TRIES) return spent(env, token, row, "burned", 200);
  return codeForm(env, token, row);
}

async function codeForm(env, token, row, { error = "", status = 200 } = {}) {
  const stepup = row.purpose === "stepup";
  return page(stepup ? "Confirm it is you" : "Check your email", `<h1>Check your email.</h1>
    <p>A code is on its way to <strong>${escape(row.email)}</strong>. Type it here:
       it works for ${CODE_FOR / 60} minutes, in this browser only.</p>
    ${form("/signin/code", await formToken(env, token, "code"), `
      <label for="code">Code</label>
      <input id="code" name="code" type="text" autocomplete="one-time-code" autocapitalize="characters"
             spellcheck="false" maxlength="12" required autofocus>
      ${problem(error)}
      <button type="submit">${stepup ? "Confirm" : "Sign in"}</button>`)}
    <p>Nothing after a minute? Look in spam, then ask again.</p>
    ${form("/signin/again", await formToken(env, token, "again"), `<button type="submit">Send a new code</button>`, "row")}
    <p>${stepup ? `<a href="/">Back to your account</a>` : `<a href="/signin">Use a different email</a>`}</p>`,
  { status });
}

/* A code that can no longer be used, with the way to a new one: 400 as the
   answer to a typed code, 200 as the page a browser comes back to. */
async function spent(env, token, row, why, status = 400) {
  const text = why === "burned"
    ? "Too many wrong tries, so that code no longer works. Wait a little, then ask for a new one."
    : "That code has expired or was already used. Ask for a new one.";
  return page("Ask for a new code", `<h1>Ask for a new code.</h1>
    <p class="bad">${text}</p>
    ${form("/signin/again", await formToken(env, token, "again"), `<button type="submit">Send a new code</button>`, "row")}
    <p>${row.purpose === "stepup" ? `<a href="/">Back to your account</a>` : `<a href="/signin">Use a different email</a>`}</p>`,
  { status });
}

async function codePost(request, env) {
  const f = await fields(request);
  const token = readCookie(request, SIGNIN_COOKIE);
  if (!await formOk(env, f, token, "code")) return refused();
  const result = await checkCode(env, token, f.get("code"));
  if (result.ok) return signedIn(request, env, result.row);
  const row = await attempt(env, token);
  if (!row) return redirect("/signin");
  if (result.why === "wrong") {
    return codeForm(env, token, row, { status: 400,
      error: `That code is not right. ${result.left} ${result.left === 1 ? "try" : "tries"} left.` });
  }
  return spent(env, token, row, result.why);
}

/* A code was typed: the account (made now if this is its first sign-in), a
   new session in place of whatever the browser had, and the event, in one
   batch. */
async function signedIn(request, env, row) {
  const db = env.LIST;
  let user, what;
  if (row.purpose === "signin") {
    const found = await userForVerifiedEmail(env, { email: row.email });
    user = found.id;
    what = found.created ? "signup" : "signin";
  } else if (row.purpose === "stepup") {
    const known = await db.prepare("SELECT id FROM users WHERE id = ?").bind(row.user_id).first();
    if (!known) return redirect("/signin", [clearCookie(SIGNIN_COOKIE)]);
    user = known.id;
    what = "stepup";
  } else {
    /* 'verify' and 'reset' belong to passwords, which have their own pages. */
    return redirect("/signin", [clearCookie(SIGNIN_COOKIE)]);
  }
  const was = await current(request, env);
  const org = await orgFor(env, user, was && was.user === user ? was.org.id : null);
  const { value, statements } = await openSession(env, {
    user, org: org ? org.id : null, previous: readCookie(request, SESSION_COOKIE),
  });
  await db.batch([...statements, event(db, { org: org ? org.id : null, user, what })]);
  return redirect(nextPath(row.next), [setCookie(SESSION_COOKIE, value, SESSION_MAX), clearCookie(SIGNIN_COOKIE)]);
}

async function again(request, env, ctx) {
  const f = await fields(request);
  const token = readCookie(request, SIGNIN_COOKIE);
  if (!await formOk(env, f, token, "again")) return refused();
  const row = await attempt(env, token);
  if (!row) return redirect("/signin");
  return sendCode(request, env, ctx, {
    email: row.email, purpose: row.purpose, userId: row.user_id, next: row.next, previous: token,
  });
}

async function stepup(request, env, ctx) {
  const who = await current(request, env);
  if (!who) return signedOut(request);
  const f = await fields(request);
  if (!await formOk(env, f, who.id, "stepup")) return refused();
  return sendCode(request, env, ctx, {
    email: who.email, purpose: "stepup", userId: who.user, next: nextPath(f.get("next")),
    previous: readCookie(request, SIGNIN_COOKIE),
  });
}

/* ---------- signed in ---------- */

const EVENTS = {
  signup: "Account made, with an emailed code",
  signin: "Signed in with an emailed code",
  stepup: "Confirmed with an emailed code",
  signout: "Signed out",
  signout_all: "Signed out everywhere",
  org_renamed: "Organisation renamed",
};

const ROLES = { owner: "Owner", admin: "Admin", member: "Member" };

const when = (t) => `${new Date(t * 1000).toISOString().slice(0, 16).replace("T", " ")} UTC`;

async function home(request, env) {
  const who = await current(request, env);
  if (!who) return signedOut(request);
  return dashboard(env, who);
}

/* One panel per paid plan, drawn from features.js, so what the page shows
   locked is what the server refuses. Locked while the organisation's plan
   is below it. Plus links to the pricing page; Team has no price and no
   checkout, only a way to talk to us. */
function panel(tier, onPlan) {
  const open = atLeast(onPlan, tier);
  const items = featuresOf(tier).map((f) => {
    const state = open
      ? (f.status === "live" ? "Included" : "Coming, included in your plan")
      : (f.status === "live" ? `Needs ${PLAN_NAMES[tier]}` : `Coming, included in ${PLAN_NAMES[tier]}`);
    return `<li data-feature="${escape(f.key)}"><strong>${escape(f.name)}</strong> <span class="tag">${state}</span>
      <br>${escape(f.says)}</li>`;
  }).join("");
  const after = open ? "" : tier === "plus"
    ? `<p>Everything ranwhat does on your machines stays free. Plus adds what needs a server.</p>
       <p><a href="${PRICING}">Upgrade to Plus</a></p>`
    : `<p>Team is arranged with each organisation. <a href="${TALK}">Talk to us</a></p>`;
  return `<section class="panel${open ? "" : " locked"}" id="${tier}">
    <h2>${PLAN_NAMES[tier]}${open ? "" : ` <span class="tag">locked</span>`}</h2>
    <ul>${items}</ul>${after}</section>`;
}

async function dashboard(env, who, { error = "", status = 200 } = {}) {
  const org = who.org;
  const events = await history(env, who.user);
  const onPlan = await plan(env, org.id);
  const rename = canManage(org) ? `<h2>Organisation name</h2>
    ${form("/org", await formToken(env, who.id, "org"), `
      <label for="name">Name</label>
      <input id="name" name="name" type="text" maxlength="80" required value="${escape(org.name)}">
      ${problem(error)}
      <button type="submit">Rename</button>`)}` : "";
  const activity = events.length
    ? `<ul>${events.map((e) => `<li>${escape(when(e.at))}: ${escape(EVENTS[e.event] || e.event)}</li>`).join("")}</ul>`
    : "<p>Nothing yet.</p>";
  return page("Your account", `<h1>Your account</h1>
    <dl>
      <dt>Signed in as</dt><dd>${escape(who.email)}</dd>
      <dt>Organisation</dt><dd>${escape(org.name)}</dd>
      <dt>Your role</dt><dd>${ROLES[org.role] || "Member"}</dd>
      <dt>Plan</dt><dd id="plan">${PLAN_NAMES[onPlan]}</dd>
    </dl>
    ${panel("plus", onPlan)}
    ${panel("team", onPlan)}
    ${rename}
    <h2>Recent activity</h2>
    ${activity}
    <h2>Sign out</h2>
    <p>Sign out everywhere ends this account's sessions in every browser.</p>
    ${form("/signout", await formToken(env, who.id, "signout"), `<button type="submit">Sign out</button>`, "row")}
    ${form("/signout-all", await formToken(env, who.id, "signout-all"), `<button type="submit">Sign out everywhere</button>`, "row")}
    <p><small><a href="https://ranwhat.com/">ranwhat.com</a> &middot; <a href="${PRIVACY}">Privacy</a></small></p>`,
  { status });
}

async function signout(request, env) {
  const who = await current(request, env);
  if (!who) return signedOut(request);
  if (!await formOk(env, await fields(request), who.id, "signout")) return refused();
  const db = env.LIST;
  await db.batch([
    db.prepare("DELETE FROM sessions WHERE id = ?").bind(who.id),
    event(db, { org: who.org.id, user: who.user, what: "signout" }),
  ]);
  return redirect("/signin", [clearCookie(SESSION_COOKIE)]);
}

/* Every session of this account, this one included: for a lost laptop, or
   a cookie that may have been copied. */
async function signoutAll(request, env) {
  const who = await current(request, env);
  if (!who) return signedOut(request);
  if (!await formOk(env, await fields(request), who.id, "signout-all")) return refused();
  const db = env.LIST;
  await db.batch([
    db.prepare("DELETE FROM sessions WHERE user_id = ?").bind(who.user),
    event(db, { org: who.org.id, user: who.user, what: "signout_all" }),
  ]);
  return redirect("/signin", [clearCookie(SESSION_COOKIE)]);
}

async function rename(request, env) {
  const who = await current(request, env);
  if (!who) return signedOut(request);
  const f = await fields(request);
  if (!await formOk(env, f, who.id, "org")) return refused();
  if (!canManage(who.org)) {
    return page("Not allowed", `<h1>Only an owner or an admin can rename it.</h1>
      <p><a href="/">Your account</a></p>`, { status: 403 });
  }
  const name = orgName(f.get("name"));
  if (!name) {
    return dashboard(env, who, { status: 400,
      error: "A name is 1 to 80 characters, with no control or formatting characters." });
  }
  const db = env.LIST;
  await db.batch([
    db.prepare("UPDATE orgs SET name = ? WHERE id = ?").bind(name, who.org.id),
    event(db, { org: who.org.id, user: who.user, what: "org_renamed" }),
  ]);
  return redirect("/");
}

/* ---------- the host ---------- */

/* Path: { method: handler }. */
const ROUTES = {
  "/": { GET: home },
  "/signin": { GET: signinPage, POST: signinPost },
  "/signin/code": { GET: codePage, POST: codePost },
  "/signin/again": { POST: again },
  "/stepup": { POST: stepup },
  "/signout": { POST: signout },
  "/signout-all": { POST: signoutAll },
  "/org": { POST: rename },
};

export async function account(request, env, ctx) {
  /* Switched on without its secret, its database or its mail: say so
     rather than sign anyone in with a missing key. */
  if (!ready(env)) {
    return page("Not available", `<h1>Accounts are not available just now.</h1>
      <p>Everything ranwhat does on your machine works without one.
         <a href="https://ranwhat.com/">ranwhat.com</a></p>`, { status: 503 });
  }
  const url = new URL(request.url);
  const route = Object.hasOwn(ROUTES, url.pathname) ? ROUTES[url.pathname] : null;
  if (!route) return notFound();
  const handle = Object.hasOwn(route, request.method) ? route[request.method] : null;
  if (!handle) return wrongMethod(Object.keys(route));
  if (request.method === "POST" && !sameOrigin(request)) return refused();
  await schema(env.LIST);
  return handle(request, env, ctx, url);
}
