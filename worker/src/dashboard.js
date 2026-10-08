/* account.ranwhat.com: signing in with an emailed code or a password,
 * making an account with a password, resetting one, and the account page
 * behind them. index.js sends every request for this host here, and only
 * while ACCOUNTS_ON is set (wrangler.toml sets it).
 *
 *   GET  /              The account's overview: the organisation's plan,
 *                       machines, members and your ways in at a glance,
 *                       what is left to set up, what each paid plan has
 *                       (features.js) and what happened lately.
 *   GET  /machines      Its machines and CI tokens (machines.js).
 *   GET  /members       The organisation, its members and invites
 *                       (members.js).
 *   GET  /billing       Its billing (billing.js).
 *   GET  /security      How you sign in, and signing out.
 *   GET  /activity      What happened on your account.
 *                       Each of these is ui.js's shell(), and without a
 *                       session sends you to /signin. A form on one of
 *                       them that works goes back to it; one that does
 *                       not draws it again with what went wrong.
 *   GET  /signin        The email form.
 *   POST /signin        Mails a code; the same answer for every address.
 *   GET  /signin/code   The box to type the code in (with a new password,
 *                       for a reset). Never filled in.
 *   POST /signin/code   Checks it, makes the account on first use, sets
 *                       the password a sign-up or a reset chose, and opens
 *                       a new session.
 *   GET  /signin/again  The button for a new code, on a page of its own.
 *   POST /signin/again  A new code for the same address (and password).
 *   GET  /signin/password  The email and password form.
 *   POST /signin/password  Checks them under password.js's limits; one
 *                       answer for every way they can be wrong.
 *   GET  /signup        The email and password form for a new account.
 *   POST /signup        Judges the password, then mails a code as /signin
 *                       does; the password is set only once it is typed
 *                       (password.js says why that is the whole defence).
 *   GET  /reset         The email form for a forgotten password.
 *   POST /reset         Mails a reset code, as /signin mails its code.
 *   POST /stepup        A fresh code for someone signed in, for the actions
 *                       that need one.
 *   POST /password      Adds or changes the password: the current one or a
 *                       fresh code, then every other session ends.
 *   POST /password/remove  Takes it away, on the same terms.
 *   POST /signout       Ends this session.
 *   POST /signout-all   Ends every session of this account, and with a
 *                       fresh code can take away every Google and GitHub
 *                       link and passkey with them (forgetWaysIn()).
 *   POST /org           Renames the organisation (owner or admin).
 *   GET  /auth/google   Signs in with Google, or with GitHub at
 *   GET  /auth/github   /auth/github: off to the provider (oauth.js).
 *   POST /auth/<provider>           Links it to the account signed in, with
 *                       a fresh code.
 *   GET  /auth/<provider>/callback  Back from the provider: signs in,
 *                       makes the account, or links, by oauth.js's rule.
 *   POST /auth/<provider>/unlink    Takes one away, with a fresh code, for
 *                       good: it does not link itself back.
 *                       A provider whose client id and secret are not set
 *                       is not offered, and its /auth/ paths answer 404,
 *                       but for unlink: an account linked to it before
 *                       still lists it, and can still take it away.
 *   GET  /passkeys/add  The page that adds a passkey, with a fresh code.
 *   GET  /passkeys/new  Its options for navigator.credentials.create(), as
 *                       JSON (passkeys.js).
 *   POST /passkeys      Checks and keeps the passkey the browser made.
 *   POST /passkeys/remove  Takes one away, with a fresh code.
 *   GET  /signin/passkey   The page that signs in with a passkey.
 *   GET  /passkeys/challenge  Its options for navigator.credentials.get(),
 *                       as JSON, so many an hour from one network.
 *   POST /signin/passkey   Checks the passkey's answer and signs in; one
 *                       answer for every way it can be wrong.
 *   GET  /passkeys.js   The script the two passkey pages load, the only
 *                       script of ours on this host.
 *   GET  /device        The box for the code a terminal printed after
 *                       ranwhat login, with a fresh code (device.js).
 *   POST /device        Looks the typed code up, under its limits, and
 *                       shows what approving it would do.
 *   POST /device/approve  Links the terminal to the organisation shown,
 *                       with a fresh code.
 *   POST /device/deny   Tells the terminal no.
 *   POST /machines/rename  Names one of the organisation's machines (an
 *                       owner or admin, or whoever linked it; machines.js).
 *   POST /machines/revoke  Revokes one, on the same terms, with a fresh
 *                       code.
 *   POST /tokens/ci     Makes a CI token, on Plus or Team, as an owner or
 *                       admin, with a fresh code, and shows it this once.
 *   GET  /upgrade       Plus for a Free organisation, monthly or yearly
 *                       (billing.js); the locked panels link here.
 *   POST /upgrade       Off to a Stripe Checkout bound to the organisation,
 *                       for an owner or admin, with a fresh code once the
 *                       organisation has a Stripe customer.
 *   POST /billing       Manage billing: off to Stripe's billing portal for
 *                       the customer of a subscription linked to the
 *                       organisation, for an owner or admin with a fresh
 *                       code.
 *   POST /members/invite   Invites someone by email to a Plus or Team
 *                       organisation, as an owner or admin with a fresh
 *                       code (members.js).
 *   GET  /invite/<token>   The invite from the email: what it is for, and
 *   GET  /invite        Join for whoever is signed in as the address it
 *                       was sent to. Never joins on a GET.
 *   POST /invite        Joins, as a member.
 *   POST /invites/revoke   Takes a waiting invite back (owner or admin).
 *   POST /members/role  Makes a member an admin or an admin a member (the
 *                       owner, with a fresh code).
 *   POST /members/remove   Removes someone, revoking the terminals they
 *                       linked (owner or admin, with a fresh code).
 *   POST /members/leave    Leaves the organisation (anyone but its owner).
 *   POST /members/transfer Makes an admin the owner (the owner, with a
 *                       fresh code), after a page that says what it does.
 *   POST /org/switch    Looks at another of one's organisations.
 *
 * Nothing changes on a GET but a passkey challenge, made for whoever
 * asks and good once (and, the first time an account asks to add a
 * passkey, its WebAuthn user handle), and Google and GitHub sign-in,
 * whose start (an oauth_flows row, its cookie and the count for the
 * network) and callback (which uses the flow up, and may make the
 * account, link it and sign in) are GETs because the provider sends the
 * browser back with one. An invite's link only shows the invite, and may
 * leave the cookie that brings the browser back to it after signing in:
 * joining is a POST. Every POST passes the origin check here and its
 * form token in its handler (session.js says what both are); the passkey
 * forms are posted by /passkeys.js as the page's own form, token and all. Every form
 * that mails a code (/signin, /signup, /reset, /signin/again) also passes
 * Turnstile, checked on the server for this host and that form before any
 * limit is counted (challenge.js): the day's account mail is shared, and
 * this is what makes each email cost whoever asks for it something. Those
 * pages are the only ones Turnstile's script loads on (ui.js).
 */
import { escape } from "./list.js";
import { plan } from "./auth.js";
import { FEATURES, PLAN_NAMES, allows, atLeast, featuresOf } from "./features.js";
import {
  ACCOUNT_HOST, DAY, RENAMES_PER_DAY, SESSION_MAX, STEPUPS_PER_USER_DAY, canManage, event, forgetWaysIn, history,
  joinedAt, now, orgFor, orgName, ownerOf, ready, schema, userForVerifiedEmail,
} from "./accounts.js";
import { challenge } from "./challenge.js";
import {
  CODE_FOR, CODE_TRIES, FRESH_FOR, SESSION_COOKIE, SIGNIN_COOKIE, SIGNIN_FOR, address, attempt, bump, checkCode,
  clearCookie, current, formOk, formToken, fresh, nextPath, notCrossSite, openSession, orgFormOk, orgInput, orgToken,
  countWithin, holdNotice, randomToken, readCookie, releaseNotice, requestCode, sameOrigin, setCookie, tellWayIn,
  unbump,
} from "./session.js";
import {
  LOCKOUT, MIN_LENGTH, attachPassword, checkPassword, detachPassword, hashAllowed, hashPassword, isPasswordHash,
  otherWaysIn, passwordOf, passwordProblem, rehashed, unlock,
} from "./password.js";
import {
  OAUTH_COOKIE, PROVIDERS, arrive, attach, begin, configured, detach, finish, linked, offered,
} from "./oauth.js";
import {
  MAX_LABEL, MAX_PASSKEYS, PAGE_SCRIPT, forgetPasskey, passkeyLabel, passkeysOf, register,
  registrationOptions, signIn, signinOptions,
} from "./passkeys.js";
import { approve, deny, deviceLookup, devicePage } from "./device.js";
import { PRICES, billingPanel, billingPost, upgradePage, upgradePost, upgradedNotice } from "./billing.js";
import {
  MEMBER_EVENTS, acceptPost, inviteAgain, invitePage, invitePost, leavePost, membersOf, membersPanel, removePost,
  revokeInvitePost, rolePost, switchPost, switcher, transferPost,
} from "./members.js";
import {
  EXPIRIES, IDLE_DAYS, MAX_CI, MAX_LABEL as MAX_MACHINE_LABEL, liveCi, machineIn, machineLabel, machinesOf,
  mayChange, mintCi, renameMachine, revokeMachine,
} from "./machines.js";
import {
  APP_PAGES, away, callout, card, command, data, elsewhere, empty, fields, form, icon, lockBadge, notFound, page, pill,
  redirect, refused, script, shell, stat, widget, wrongMethod,
} from "./ui.js";

const PRIVACY = "https://ranwhat.com/privacy";
const UPGRADE = "/upgrade";
const TALK = "mailto:hello@ranwhat.com?subject=ranwhat%20Team";

/* No session: to the sign-in page, dropping a cookie that no longer opens one. */
const signedOut = (request) =>
  redirect("/signin", readCookie(request, SESSION_COOKIE) ? [clearCookie(SESSION_COOKIE)] : []);

const problem = (text) => (text ? `<p class="bad">${escape(text)}</p>` : "");

/* PBKDF2_ITERATIONS above what the runtime allows (password.js). */
const unavailable = () => page("Not available", `<h1>Passwords are not available just now.</h1>
  <p>You can still <a href="/signin">sign in with an emailed code</a>, which
     makes the account too.</p>`, { status: 503 });

/* password.js's limit on hashes from one network. */
const tooManyHashes = () => page("Too many tries", `<h1>Too many tries.</h1>
  <p>More passwords were tried from your network in the last hour than we
     check. Try again in an hour, or <a href="/signin">sign in with an emailed
     code</a>.</p>`, { status: 429 });

const NEW_PASSWORD = `<p><small>At least ${MIN_LENGTH} characters, of any kind, spaces too: a few unrelated
   words work well. Passwords known from data breaches are refused.</small></p>`;

/* A Turnstile token solved anywhere but this host does not count here. */
const CHALLENGE_HOSTS = new Set([ACCOUNT_HOST]);

/* Turnstile, for a form that mails a code: null when it passed for this
   host and `action`, otherwise [status, the sentence the form shows]. It
   says nothing about the address, which is not looked at. */
async function unchallenged(request, env, f, action) {
  const outcome = await challenge(request, env, f.get("cf-turnstile-response"),
    { hostnames: CHALLENGE_HOSTS, action });
  if (outcome === "ok") return null;
  return {
    missing: [400, "Complete the check above the button, then send the form again."],
    unavailable: [502, "The check could not be verified just now. Try again in a minute."],
  }[outcome] || [403, "That check did not pass. Try it again."];
}

/* ---------- signing in ---------- */

async function signinPage(request, env, ctx, url) {
  const next = nextPath(url.searchParams.get("next"));
  if (await current(request, env)) return redirect(next);
  return signinForm(env, readCookie(request, SIGNIN_COOKIE), { next });
}

/* The form's token is bound to the browser's __Host-rw_signin cookie, made
   here when it has none yet, so even the first form has something a page
   on another site cannot know. */
function bound(binding) {
  if (binding) return { binding, cookies: [] };
  const made = randomToken();
  return { binding: made, cookies: [setCookie(SIGNIN_COOKIE, made, SIGNIN_FOR)] };
}

async function signinForm(env, browser, { next = "/", email = "", error = "", status = 200 } = {}) {
  const { binding, cookies } = bound(browser);
  return page("Sign in", `<h1>Sign in</h1>
    <p>Type your email, and we send you a code to type on the next page. The
       same code makes your account if you do not have one yet.</p>
    ${form("/signin", await formToken(env, binding, "signin"), `
      <input type="hidden" name="next" value="${escape(next)}">
      <label for="email">Email</label>
      <input id="email" name="email" type="email" autocomplete="email" maxlength="200" required autofocus
             value="${escape(email)}">
      ${widget("signin")}
      ${problem(error)}
      <button type="submit" class="primary">Email me a code</button>`)}
    ${providerButtons(env)}
    <p>Have a passkey? <a href="/signin/passkey">Sign in with it</a>.
       Have a password? <a href="/signin/password">Sign in with it</a>.
       Want one? <a href="/signup">Make an account with a password</a></p>
    <p><small>The address is used to send the code, and kept only once the code
       is typed, as your account. This page sets two cookies, both only to sign
       you in, and nothing on it tracks you. Cloudflare Turnstile checks that a
       person is asking.${offered(env).length ? ` Continuing with ${offered(env).map((p) => PROVIDERS[p].name).join(" or ")}
       keeps only that account's id and the address it has verified.` : ""}
       <a href="${PRIVACY}">Privacy</a></small></p>`,
  { status, cookies, challenge: true });
}

/* Plain links, so that no script and no form-action stands between the
   page and the provider. */
function providerButtons(env) {
  const via = offered(env);
  if (!via.length) return "";
  return `<p>${via.map((p) => `<a class="button" href="/auth/${p}">Continue with ${PROVIDERS[p].name}</a>`).join("\n       ")}</p>`;
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
  const no = await unchallenged(request, env, f, "signin");
  if (no) return signinForm(env, binding, { next, email, error: no[1], status: no[0] });
  return sendCode(request, env, ctx, { email, purpose: "signin", next, previous: binding });
}

/* Each refusal is about the network, the day or (for a step-up) the
   account asking, never the address. */
async function sendCode(request, env, ctx, wanted) {
  const result = await requestCode(request, env, ctx, wanted);
  if (result.refused === "network") {
    return page("Too many codes", `<h1>Too many codes asked for.</h1>
      <p>More sign-in codes were asked for from your network in the last hour
         than we send. Try again in an hour.</p>`, { status: 429 });
  }
  if (result.refused === "network-day") {
    return page("Too many codes", `<h1>Too many codes asked for.</h1>
      <p>More sign-in codes were sent for your network today than we send to
         one network in a day. Try again tomorrow, from another network${wanted.purpose === "stepup" ? "."
           : `, or <a href="/signin/password">with your password</a> if you have one.`}</p>`, { status: 429 });
  }
  if (result.refused === "account-day") {
    return page("No more codes for this account today", `<h1>No more codes for this account today.</h1>
      <p>This account has asked for ${STEPUPS_PER_USER_DAY} confirmation codes today, the most one account
         can in a day. To confirm now, sign out and sign in again with an emailed code, which counts as
         confirming; or try again tomorrow.</p>
      <p><a href="/">Your account</a></p>`, { status: 429 });
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

/* The page a step-up was asked for from, which offers it again: the one
   its form named (nextPath()), and for the overview, which has no step-up
   form of its own, Security. */
const askedFrom = (row) => {
  const next = nextPath(row.next);
  return next === "/" ? "/security" : next;
};

/* Where a code page sends someone for a new code: a step-up asks again
   from the account page it was asked from, so that Turnstile's script
   never loads for someone signed in. */
const anew = (row, text) => `<a href="${row.purpose === "stepup" ? askedFrom(row) : "/signin/again"}">${text}</a>`;

/* Where a code page sends someone who wants to start again. */
const startOver = (row) => ({
  stepup: `<a href="${askedFrom(row)}">Back to your account</a>`,
  verify: `<a href="/signup">Use a different email</a>`,
  reset: `<a href="/reset">Use a different email</a>`,
}[row.purpose] || `<a href="/signin">Use a different email</a>`);

/* With 'reset', the new password goes in the same form as the code, and is
   judged before the code is checked, so a refused password costs no try. */
async function codeForm(env, token, row, { error = "", status = 200 } = {}) {
  const stepup = row.purpose === "stepup";
  const verify = row.purpose === "verify";
  const reset = row.purpose === "reset";
  return page(stepup ? "Confirm it is you" : reset ? "Reset your password" : "Check your email", `<h1>Check your email.</h1>
    <p>A code is on its way to <strong>${escape(row.email)}</strong>. Type it here:
       it works for ${CODE_FOR / 60} minutes, in this browser only.</p>
    ${verify ? `<p>Your password is set when the code is typed, and not before. If this address
       already has an account, it replaces that account's password and signs it out everywhere
       else.</p>` : ""}
    ${reset ? "<p>Type it with the password you want now. Setting it signs your account out everywhere else.</p>" : ""}
    ${form("/signin/code", await formToken(env, token, "code"), `
      <label for="code">Code</label>
      <input id="code" name="code" type="text" autocomplete="one-time-code" autocapitalize="characters"
             spellcheck="false" maxlength="12" required autofocus>
      ${reset ? `<label for="password">New password</label>
      <input id="password" name="password" type="password" autocomplete="new-password" minlength="${MIN_LENGTH}" required>
      ${NEW_PASSWORD}
      <label><input type="checkbox" name="ways" value="remove"> Also unlink every Google and GitHub account
        and remove every passkey, in case one is in someone else's hands</label>` : ""}
      ${problem(error)}
      <button type="submit" class="primary">${stepup ? "Confirm" : verify ? "Confirm and sign in" : reset ? "Set password and sign in" : "Sign in"}</button>`)}
    <p>Nothing after a minute? Look in spam, then ${anew(row, "ask for a new code")}.</p>
    <p>${startOver(row)}</p>`,
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
    <p>${anew(row, "Send a new code")}</p>
    <p>${startOver(row)}</p>`,
  { status });
}

async function codePost(request, env) {
  const f = await fields(request);
  const token = readCookie(request, SIGNIN_COOKIE);
  if (!await formOk(env, f, token, "code")) return refused();
  const held = await attempt(env, token);
  if (held && held.purpose === "reset") return resetCode(request, env, token, held, f);
  const result = await checkCode(request, env, token, f.get("code"));
  if (result.ok) return signedIn(request, env, result.row);
  return notTaken(env, token, result);
}

/* The answer to a code checkCode() turned down. */
async function notTaken(env, token, result) {
  const row = await attempt(env, token);
  if (!row) return redirect("/signin");
  if (result.why === "wrong") {
    return codeForm(env, token, row, { status: 400,
      error: `That code is not right. ${result.left} ${result.left === 1 ? "try" : "tries"} left.` });
  }
  return spent(env, token, row, result.why);
}

/* Someone just signed in as `user`: a new session in place of whatever the
   browser had, written in one batch with `before` (run first) and what
   `after(org)` returns, and the browser sent on, with `cookies` set too.
   The organisation is the one the browser was looking at, if it was
   already this person's. */
async function enter(request, env, { user, next = "/", coded = true, before = [], after, cookies = [] }) {
  const was = await current(request, env);
  const org = await orgFor(env, user, was && was.user === user ? was.org.id : null);
  const orgId = org ? org.id : null;
  const { value, statements } = await openSession(env, {
    user, org: orgId, previous: readCookie(request, SESSION_COOKIE), coded,
  });
  await env.LIST.batch([...before, ...statements, ...await after(orgId)]);
  return redirect(nextPath(next),
    [setCookie(SESSION_COOKIE, value, SESSION_MAX), clearCookie(SIGNIN_COOKIE), ...cookies]);
}

/* A code was typed: the account (made now if this is its first sign-in), a
   new session in place of whatever the browser had, and the events, in one
   batch. With 'verify', the password this browser chose becomes the
   account's in the same batch: the row is the attempt this browser holds
   and has just typed the code for, so the hash is the one it sent. A code
   also gives the address back its password tries (password.js).

   'verify' for an account that was already there sets its password as a
   reset does, because that is what it is: the code proved the address, and
   whoever else was signed in, perhaps with the password being replaced, is
   signed out, every session of the account ending in the same batch. The
   event then says so (password_reset, or password_added when it had none). */
async function signedIn(request, env, row) {
  const db = env.LIST;
  let user, what;
  let password = null;
  let reset = false;
  if (row.purpose === "signin" || row.purpose === "verify") {
    if (row.purpose === "verify") {
      if (!isPasswordHash(row.password_hash)) return redirect("/signup", [clearCookie(SIGNIN_COOKIE)]);
      password = row.password_hash;
    }
    const found = await userForVerifiedEmail(env, { email: row.email });
    user = found.id;
    what = found.created ? "signup" : "signin";
    reset = password !== null && !found.created;
  } else if (row.purpose === "stepup") {
    const known = await db.prepare("SELECT id FROM users WHERE id = ?").bind(row.user_id).first();
    if (!known) return redirect("/signin", [clearCookie(SIGNIN_COOKIE)]);
    user = known.id;
    what = "stepup";
  } else {
    /* 'reset' never gets here: codePost sends it to resetCode. */
    return redirect("/signin", [clearCookie(SIGNIN_COOKIE)]);
  }
  return enter(request, env, {
    user, next: row.next,
    before: reset ? [db.prepare("DELETE FROM sessions WHERE user_id = ?").bind(user)] : [],
    after: async (org) => [
      event(db, { org, user, what }),
      ...(password ? await attachPassword(env, { user, org, hash: password, reset }) : []),
      await unlock(env, row.email),
    ],
  });
}

/* A reset code, typed with the new password. The password is judged and
   hashed first, so a refused one costs the attempt nothing; then the code
   is checked as any code is. Once it is right the address is proven, as a
   sign-in code proves it (an address with no account gets one, as /signin
   would give it), and in one batch: every session of the account ends,
   the password is replaced, every Google, GitHub and passkey way in goes
   too when the box for it was ticked, and this browser gets the one new
   session. */
async function resetCode(request, env, token, row, f) {
  if (row.used_at || row.expires_at <= now()) return spent(env, token, row, "expired");
  if (row.tries >= CODE_TRIES) return spent(env, token, row, "burned");
  if (!await hashAllowed(request, env)) return tooManyHashes();
  const password = f.get("password");
  const wrong = await passwordProblem(env, password);
  if (wrong) return codeForm(env, token, row, { error: wrong, status: 400 });
  let hash;
  try {
    hash = await hashPassword(env, password);
  } catch (err) {
    console.log(`account password hash: ${err.name || "error"}`);
    return unavailable();
  }
  const result = await checkCode(request, env, token, f.get("code"));
  if (!result.ok) return notTaken(env, token, result);
  const db = env.LIST;
  const found = await userForVerifiedEmail(env, { email: row.email });
  const user = found.id;
  return enter(request, env, {
    user, next: row.next,
    before: [db.prepare("DELETE FROM sessions WHERE user_id = ?").bind(user)],
    after: async (org) => [
      ...(found.created ? [event(db, { org, user, what: "signup" })] : []),
      ...await attachPassword(env, { user, org, hash, reset: true }),
      ...(f.get("ways") === "remove" ? forgetWaysIn(env, { user, org }) : []),
      await unlock(env, row.email),
    ],
  });
}

/* A new code for the browser's attempt, on a page of its own, so that
   Turnstile's script never runs on the page a code is typed into. A
   step-up asks again from the account page it came from instead
   (anew()). */
async function againPage(request, env) {
  const token = readCookie(request, SIGNIN_COOKIE);
  const row = await attempt(env, token);
  if (!row) return redirect("/signin");
  if (row.purpose === "stepup") return redirect(askedFrom(row));
  return againForm(env, token, row);
}

async function againForm(env, token, row, { error = "", status = 200 } = {}) {
  return page("Send a new code", `<h1>Send a new code</h1>
    <p>To <strong>${escape(row.email)}</strong>, in place of the last one, which then stops
       working.</p>
    ${form("/signin/again", await formToken(env, token, "again"), `
      ${widget("again")}
      ${problem(error)}
      <button type="submit" class="primary">Send a new code</button>`)}
    <p>${startOver(row)}</p>`,
  { status, challenge: true });
}

async function again(request, env, ctx) {
  const f = await fields(request);
  const token = readCookie(request, SIGNIN_COOKIE);
  if (!await formOk(env, f, token, "again")) return refused();
  const row = await attempt(env, token);
  if (!row) return redirect("/signin");
  const no = await unchallenged(request, env, f, "again");
  if (no) return againForm(env, token, row, { error: no[1], status: no[0] });
  return sendCode(request, env, ctx, {
    email: row.email, purpose: row.purpose, userId: row.user_id, next: row.next, previous: token,
    passwordHash: row.password_hash,
  });
}

/* ---------- making an account with a password ---------- */

async function signupPage(request, env, ctx, url) {
  const next = nextPath(url.searchParams.get("next"));
  if (await current(request, env)) return redirect(next);
  return signupForm(env, readCookie(request, SIGNIN_COOKIE), { next });
}

/* Never filled in with the password, even after a mistake. */
async function signupForm(env, browser, { next = "/", email = "", error = "", status = 200 } = {}) {
  const { binding, cookies } = bound(browser);
  return page("Make an account", `<h1>Make an account</h1>
    <p>Choose a password, and we send you a code to type on the next page. The
       password is set only once that code is typed, in this browser.</p>
    ${form("/signup", await formToken(env, binding, "signup"), `
      <input type="hidden" name="next" value="${escape(next)}">
      <label for="email">Email</label>
      <input id="email" name="email" type="email" autocomplete="email" maxlength="200" required autofocus
             value="${escape(email)}">
      <label for="password">Password</label>
      <input id="password" name="password" type="password" autocomplete="new-password" minlength="12" required>
      <p><small>At least 12 characters, of any kind, spaces too: a few unrelated words
         work well. Passwords known from data breaches are refused.</small></p>
      ${widget("signup")}
      ${problem(error)}
      <button type="submit" class="primary">Email me a code</button>`)}
    <p>Rather not have a password? <a href="/signin">Sign in with an emailed code</a>; it makes
       the account too.</p>
    <p><small>The address is used to send the code, and kept only once the code is typed, as
       your account. The password is kept only as a salted hash. To check it against known
       breaches we send Have I Been Pwned the first 5 characters of its SHA-1 hash, never the
       password. Cloudflare Turnstile checks that a person is asking.
       <a href="${PRIVACY}">Privacy</a></small></p>`,
  { status, cookies, challenge: true });
}

/* The same answer for every address, as /signin gives: what can be wrong
   here is the address's form, the password or the network, never whether
   the address has an account. The hash goes into this browser's attempt and
   nowhere else. */
async function signupPost(request, env, ctx) {
  const f = await fields(request);
  const binding = readCookie(request, SIGNIN_COOKIE);
  if (!await formOk(env, f, binding, "signup")) return refused();
  const next = nextPath(f.get("next"));
  const typed = String(f.get("email") ?? "").slice(0, 200);
  const email = address(f.get("email"));
  if (!email) {
    return signupForm(env, binding, { next, email: typed, error: "That email address does not look right.", status: 400 });
  }
  const no = await unchallenged(request, env, f, "signup");
  if (no) return signupForm(env, binding, { next, email, error: no[1], status: no[0] });
  if (!await hashAllowed(request, env)) {
    return page("Too many tries", `<h1>Too many tries.</h1>
      <p>More accounts were asked for from your network in the last hour than
         we take. Try again in an hour, or <a href="/signin">sign in with an
         emailed code</a>.</p>`, { status: 429 });
  }
  const password = f.get("password");
  const wrong = await passwordProblem(env, password);
  if (wrong) return signupForm(env, binding, { next, email, error: wrong, status: 400 });
  let hash;
  try {
    hash = await hashPassword(env, password);
  } catch (err) {
    console.log(`account password hash: ${err.name || "error"}`);
    return unavailable();
  }
  return sendCode(request, env, ctx, { email, purpose: "verify", next, previous: binding, passwordHash: hash });
}

/* ---------- signing in with a password ---------- */

async function passwordPage(request, env, ctx, url) {
  const next = nextPath(url.searchParams.get("next"));
  if (await current(request, env)) return redirect(next);
  return passwordForm(env, readCookie(request, SIGNIN_COOKIE), { next });
}

/* Never filled in with the password. */
async function passwordForm(env, browser, { next = "/", email = "", error = "", status = 200 } = {}) {
  const { binding, cookies } = bound(browser);
  return page("Sign in with a password", `<h1>Sign in</h1>
    ${form("/signin/password", await formToken(env, binding, "password"), `
      <input type="hidden" name="next" value="${escape(next)}">
      <label for="email">Email</label>
      <input id="email" name="email" type="email" autocomplete="username" maxlength="200" required${email ? "" : " autofocus"}
             value="${escape(email)}">
      <label for="password">Password</label>
      <input id="password" name="password" type="password" autocomplete="current-password" maxlength="4096"
             required${email ? " autofocus" : ""}>
      ${problem(error)}
      <button type="submit" class="primary">Sign in</button>`)}
    <p>Forgot it? <a href="/reset">Reset it with an emailed code</a></p>
    <p>No password? <a href="/signin">Sign in with an emailed code</a>; it makes the account too.</p>
    <p><small>This page sets a cookie only to sign you in, and nothing on it tracks
       you. <a href="${PRIVACY}">Privacy</a></small></p>`,
  { status, cookies });
}

/* One answer for a wrong password, an address with no password and an
   address with no account, after the same work (password.js). Signing in
   then goes exactly as a code does, except that the session is not fresh:
   a password is not a code typed just now. */
async function passwordPost(request, env) {
  const f = await fields(request);
  const binding = readCookie(request, SIGNIN_COOKIE);
  if (!await formOk(env, f, binding, "password")) return refused();
  const next = nextPath(f.get("next"));
  const email = address(f.get("email"));
  if (!email) {
    return passwordForm(env, binding, { next, email: String(f.get("email") ?? "").slice(0, 200),
      error: "That email address does not look right.", status: 400 });
  }
  const typed = f.get("password");
  const result = await checkPassword(request, env, email, typed);
  if (result.ok) {
    const db = env.LIST;
    const user = result.user;
    return enter(request, env, { user, next, coded: false, after: async (org) => [
      db.prepare("UPDATE users SET signed_in_at = ? WHERE id = ?").bind(now(), user),
      event(db, { org, user, what: "signin_password" }),
      ...await rehashed(env, { user, stored: result.stored, typed }),
    ] });
  }
  if (result.why === "locked") return locked(env, binding, email, next);
  if (result.why === "network") return tooManyHashes();
  if (result.why === "unavailable") return unavailable();
  return passwordForm(env, binding, { next, email, status: 400,
    error: "That email and password do not match. Check both, or sign in with an emailed code." });
}

/* Password sign-in is paused for this address, or for this network: the
   code still works, one press (and Turnstile) away. */
async function locked(env, binding, email, next) {
  return page("Use an emailed code", `<h1>Use an emailed code.</h1>
    <p class="bad">There have been too many tries with a password, for this address or
       from your network, so password sign-in is paused for up to ${LOCKOUT / 60} minutes.
       An emailed code still works, and typing one gives this address its tries back.</p>
    ${form("/signin", await formToken(env, binding, "signin"), `
      <input type="hidden" name="next" value="${escape(next)}">
      <input type="hidden" name="email" value="${escape(email)}">
      ${widget("signin")}
      <button type="submit" class="primary">Email a code to ${escape(email)}</button>`)}
    <p><a href="/signin">Use a different email</a></p>`,
  { status: 429, challenge: true });
}

/* ---------- a forgotten password ---------- */

async function resetPage(request, env) {
  if (await current(request, env)) return redirect("/");
  return resetForm(env, readCookie(request, SIGNIN_COOKIE));
}

async function resetForm(env, browser, { email = "", error = "", status = 200 } = {}) {
  const { binding, cookies } = bound(browser);
  return page("Reset your password", `<h1>Reset your password</h1>
    <p>Type your email, and we send you a code. You type it on the next page with
       the password you want now, which replaces the old one and signs your
       account out everywhere else.</p>
    ${form("/reset", await formToken(env, binding, "reset"), `
      <label for="email">Email</label>
      <input id="email" name="email" type="email" autocomplete="email" maxlength="200" required autofocus
             value="${escape(email)}">
      ${widget("reset")}
      ${problem(error)}
      <button type="submit" class="primary">Email me a code</button>`)}
    <p><a href="/signin/password">Back to signing in</a></p>`,
  { status, cookies, challenge: true });
}

/* The same answer for every address, with an account or a password or
   neither, as /signin gives, and from the same day's mail. */
async function resetPost(request, env, ctx) {
  const f = await fields(request);
  const binding = readCookie(request, SIGNIN_COOKIE);
  if (!await formOk(env, f, binding, "reset")) return refused();
  const email = address(f.get("email"));
  if (!email) {
    return resetForm(env, binding, { email: String(f.get("email") ?? "").slice(0, 200),
      error: "That email address does not look right.", status: 400 });
  }
  const no = await unchallenged(request, env, f, "reset");
  if (no) return resetForm(env, binding, { email, error: no[1], status: no[0] });
  return sendCode(request, env, ctx, { email, purpose: "reset", next: "/", previous: binding });
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
  signin_password: "Signed in with your password",
  stepup: "Confirmed with an emailed code",
  password_added: "Password added, confirmed with an emailed code",
  password_changed: "Password changed, and every other session signed out",
  password_reset: "Password reset with an emailed code, and every other session signed out",
  password_removed: "Password removed, and every other session signed out",
  signout: "Signed out",
  signout_all: "Signed out everywhere",
  org_renamed: "Organisation renamed",
  signup_google: "Account made, with Google",
  signin_google: "Signed in with Google",
  linked_google: "Google account linked",
  unlinked_google: "Google account unlinked, and every other session signed out",
  signup_github: "Account made, with GitHub",
  signin_github: "Signed in with GitHub",
  linked_github: "GitHub account linked",
  unlinked_github: "GitHub account unlinked, and every other session signed out",
  signin_passkey: "Signed in with a passkey",
  passkey_added: "Passkey added, confirmed with an emailed code",
  passkey_removed: "Passkey removed, and every other session signed out",
  ways_removed: "Every Google, GitHub and passkey way in removed",
  device_approved: "Terminal approved for ranwhat login, with a fresh code",
  device_denied: "Terminal denied for ranwhat login",
  machine_linked: "Terminal linked",
  machine_logout: "Terminal unlinked with ranwhat logout",
  machine_renamed: "Machine renamed",
  machine_revoked: "Machine revoked, with a fresh code",
  machine_idle_revoked: `Terminal revoked after ${IDLE_DAYS} days unused`,
  ci_token_created: "CI token made, with a fresh code",
  upgrade_started: "Checkout for Plus opened",
  billing_opened: "Billing opened, with a fresh code",
  plus_linked: "Plus subscription linked to the organisation",
  ...MEMBER_EVENTS,
};

const ROLES = { owner: "Owner", admin: "Admin", member: "Member" };

const when = (t) => `${new Date(t * 1000).toISOString().slice(0, 16).replace("T", " ")} UTC`;

/* Each signed-in page's path, by its name in ui.js's APP_PAGES. */
const PATHS = Object.freeze(Object.fromEntries(APP_PAGES.map(([key, path]) => [key, path])));

/* How long ago `t` was, for a list read at a glance; the time itself is
   in the title, and in the datetime for anything that reads it. */
function ago(t, at = now()) {
  const s = Math.max(0, at - t);
  const n = (count, unit) => `${count} ${unit}${count === 1 ? "" : "s"} ago`;
  if (s < 60) return "just now";
  if (s < 3600) return n(Math.floor(s / 60), "minute");
  if (s < DAY) return n(Math.floor(s / 3600), "hour");
  if (s < 7 * DAY) return n(Math.floor(s / DAY), "day");
  return new Date(t * 1000).toISOString().slice(0, 10);
}

const stamp = (t) =>
  `<time datetime="${new Date(t * 1000).toISOString()}" title="${escape(when(t))}">${escape(ago(t))}</time>`;

const plural = (count, one, many = `${one}s`) => `${count} ${count === 1 ? one : many}`;

/* A signed-in page, `current` among APP_PAGES: the sidebar (the
   organisation, its plan, your role in it, the switcher back to this
   page, and signing out), then the page's header and body. */
async function app(env, who, current, { title, sub = "", action = "", body, status = 200, away: to = [], onPlan }) {
  const org = who.org;
  const on = onPlan || await plan(env, org.id);
  return shell({
    current,
    side: {
      email: who.email, org: org.name, plan: PLAN_NAMES[on], planTone: on === "free" ? "" : "brand",
      role: ROLES[org.role] || "Member",
      switcher: await switcher(env, who, PATHS[current], { compact: true }),
      signout: form("/signout", await formToken(env, who.id, "signout"),
        `<button type="submit" class="compact">${icon("exit")}Sign out</button>`),
    },
    head: { title, sub, action },
    body, status, away: to,
  });
}

/* A signed-in page's GET: its page, or sign in first. */
const signedInPage = (draw) => async (request, env, ctx, url) => {
  const who = await current(request, env);
  if (!who) return signedOut(request);
  return draw(env, who, {}, url);
};

/* ---------- the overview ---------- */

/* The paid plans' cards, drawn from features.js, so what the page shows
   locked is what the server refuses. Locked while the organisation's plan
   is below the tier. Plus links to the upgrade (billing.js) for whoever
   may buy it; Team has no price and no checkout, only a way to talk to
   us. */
function featureTiles(tier, onPlan) {
  const open = atLeast(onPlan, tier);
  return featuresOf(tier).map((f) => {
    const state = f.status === "live"
      ? (open ? pill("Included", "ok") : pill(`Needs ${PLAN_NAMES[tier]}`, "brand"))
      : pill("Coming");
    const mark = !open ? icon("lock") : f.status === "live" ? icon("check") : `<span class="soon">${icon("clock")}</span>`;
    return `<li class="feat${open ? " on" : ""}" data-feature="${escape(f.key)}"><div class="feat-top">${mark}` +
      `<strong>${escape(f.name)}</strong>${state}</div><p>${escape(f.says)}</p></li>`;
  }).join("\n      ");
}

function plusCard(who, onPlan) {
  const org = who.org;
  const name = escape(org.name);
  const open = atLeast(onPlan, "plus");
  const features = featuresOf("plus");
  const live = features.filter((f) => f.status === "live").length;
  const coming = features.length - live;
  let intro;
  if (open) {
    intro = `<span class="label">In your plan</span>
      <h2>Plus</h2>
      <p class="lead">${name} has Plus${onPlan === "plus" ? "" : `, as part of ${PLAN_NAMES[onPlan]}`}: what needs a server,
         for everyone in it.</p>
      <p>${plural(live, "feature")} ${live === 1 ? "is" : "are"} live and included now, and ${coming} more
         ${coming === 1 ? "comes" : "come"} with it as ${coming === 1 ? "it is" : "they are"} ready.</p>
      ${canManage(org) ? `<div class="actions"><a class="btn" href="${PATHS.billing}">Billing</a></div>` : ""}`;
  } else {
    intro = `<span class="label">Your plan: Free</span>
      <h2>${lockBadge()}Plus</h2>
      <p class="lead">Plus adds what needs a server, for everyone in ${name}: ${plural(live, "feature")} now, and
         ${coming} more as ${coming === 1 ? "it comes" : "they come"}.</p>
      <p>Everything ranwhat does on your machines stays free.</p>
      <p class="price">${escape(PRICES.monthly)}, or ${escape(PRICES.yearly)}</p>
      <p class="hint">One price for the organisation, however many people are in it.</p>
      ${canManage(org) ? `<div class="actions"><a class="btn primary" href="${UPGRADE}">Upgrade to Plus</a></div>`
        : `<p>Only an owner or an admin of ${name} can upgrade it. Ask one of them.</p>`}`;
  }
  return `<section class="card upsell${open ? "" : " locked"}" id="plus">
    <div class="upsell-intro">
      ${intro}
    </div>
    <ul class="feats" aria-label="What Plus has">
      ${featureTiles("plus", onPlan)}
    </ul></section>`;
}

function teamCard(who, onPlan) {
  const open = atLeast(onPlan, "team");
  return `<section class="card team${open ? "" : " locked"}" id="team">
    <header class="card-head"><h2>${icon("team")}Team</h2>${open ? pill("Your plan", "brand") : pill("By arrangement")}</header>
    ${open ? `<p>${escape(who.org.name)} is on Team, with everything in Plus.</p>`
      : `<p>Team is arranged with each organisation: everything in Plus, and the features below as they come.
         <a href="${TALK}">Talk to us</a></p>`}
    <ul class="feats" aria-label="What Team has">
      ${featureTiles("team", onPlan)}
    </ul></section>`;
}

/* What is left to set up, each step done or not from what is there (a
   terminal or CI token of your own, a second way in, someone else in the
   organisation): null once every step is done. */
function setup(who, { machines, people, ways, onPlan }) {
  const org = who.org;
  const name = escape(org.name);
  const invite = allows(onPlan, "members");
  const steps = [
    {
      done: machines.some((m) => m.user_id === who.user),
      title: "Link a machine",
      text: `<p>Run this in a terminal, then approve the code it shows. The terminal is linked to ${name}, on its
         plan. <a href="${PATHS.machines}">Machines</a></p>
         ${command("uvx ranwhat login")}`,
    },
    {
      done: ways > 1,
      title: "Add a second way in",
      text: `<p>A passkey or a password, as well as the emailed code, so that your inbox is not the only way
         in. <a href="${PATHS.security}">Security</a></p>`,
    },
    {
      done: people.length > 1,
      title: "Invite your team",
      tag: invite ? "" : pill("Needs Plus", "brand"),
      text: !invite ? `<p>Plus lets ${name} invite people by email, one price however many there are.
         <a href="#plus">What Plus adds</a></p>`
        : canManage(org) ? `<p>Invite people by email; they join as members. <a href="${PATHS.members}">Members</a></p>`
          : `<p>An owner or an admin of ${name} can invite people. <a href="${PATHS.members}">Members</a></p>`,
    },
  ];
  const done = steps.filter((s) => s.done).length;
  if (done === steps.length) return null;
  const items = steps.map((s, n) => `<li class="step${s.done ? " done" : ""}">
        <span class="step-mark">${s.done ? icon("check") : n + 1}</span>
        <div><span class="step-title">${s.title}${s.done ? pill("Done", "ok") : s.tag || ""}</span>
        ${s.text}</div></li>`).join("");
  return card({
    title: "Get started", icon: "spark", cls: "c7", attributes: 'id="setup"',
    aside: pill(`${done} of ${steps.length} done`, done === steps.length ? "ok" : ""),
    body: `<ol class="steps">${items}</ol>`,
  });
}

/* The organisation's machines, the newest few, once setting up is done. */
function machinesCard(machines) {
  const today = Math.floor(now() / DAY) * DAY;
  const used = (m) => {
    if (m.kind === "legacy") return "use not recorded";
    if (m.last_used_day === null) return "not used yet";
    const days = Math.round((today - m.last_used_day) / DAY);
    return days <= 0 ? "used today" : days === 1 ? "used yesterday" : `used ${days} days ago`;
  };
  const rows = machines.slice(0, 5).map((m) => `<li><span>${m.label ? escape(m.label) : UNNAMED[m.kind]}
        ${pill(KINDS[m.kind])}</span><span class="when">${used(m)}</span></li>`).join("");
  return card({
    title: "Machines", icon: "machines", cls: "c7",
    aside: `<a href="${PATHS.machines}">All machines</a>`,
    body: `<ul class="events">${rows}</ul>`,
  });
}

/* ?upgraded=1: back from a paid Stripe Checkout (billing.js), thanked for
   until the webhook has switched Plus on. */
async function overview(env, who, opts = {}, url = null) {
  const upgraded = url ? url.searchParams.get("upgraded") === "1" : false;
  const org = who.org;
  const name = escape(org.name);
  const onPlan = await plan(env, org.id);
  const machines = await machinesOf(env, org.id, await joinedAt(env, org.id, who.user));
  const people = await membersOf(env, org.id);
  const events = await history(env, who.user, 5);
  const stored = await passwordOf(env, who.user);
  const keys = await passkeysOf(env, who.user);
  const providers = await linked(env, who.user);
  const ways = 1 + (stored ? 1 : 0) + providers.length + keys.length;

  const kinds = (kind) => machines.filter((m) => m.kind === kind).length;
  const linkedSay = [
    kinds("device") && plural(kinds("device"), "terminal"),
    kinds("ci") && plural(kinds("ci"), "CI token"),
    kinds("legacy") && plural(kinds("legacy"), "old token"),
  ].filter(Boolean).join(", ") || "None linked yet";
  const roles = (role) => people.filter((p) => p.role === role).length;
  const peopleSay = !allows(onPlan, "members") && people.length <= 1 ? "Inviting needs Plus"
    : [plural(roles("owner"), "owner"), roles("admin") && plural(roles("admin"), "admin"),
      roles("member") && plural(roles("member"), "member")].filter(Boolean).join(", ");
  const waysSay = ["Emailed code", stored && "password",
    ...Object.keys(PROVIDERS).filter((p) => providers.some((w) => w.provider === p)).map((p) => PROVIDERS[p].name),
    keys.length && plural(keys.length, "passkey")].filter(Boolean).join(", ");
  const planSay = { free: "Everything local stays free", plus: "Plus features on", team: "Plus and Team features on" }[onPlan];

  const stats = `<div class="stats">
      ${stat({ label: "Plan", value: PLAN_NAMES[onPlan], sub: planSay, href: PATHS.billing, icon: "billing", id: "plan" })}
      ${stat({ label: "Machines linked", value: String(machines.length), sub: linkedSay, href: PATHS.machines, icon: "machines" })}
      ${stat({ label: "Members", value: String(people.length), sub: peopleSay, href: PATHS.members, icon: "members" })}
      ${stat({ label: "Ways to sign in", value: String(ways), sub: waysSay, href: PATHS.security, icon: "security" })}
    </div>`;

  const recent = card({
    title: "Recent activity", icon: "activity", cls: "c5",
    aside: `<a href="${PATHS.activity}">All activity</a>`,
    body: events.length
      ? `<ol class="events">${events.map((e) => `<li><span>${escape(EVENTS[e.event] || e.event)}</span>${stamp(e.at)}</li>`).join("")}</ol>`
      : empty("<p>Nothing yet.</p>"),
  });

  const notice = upgraded ? callout({ tone: atLeast(onPlan, "plus") ? "ok" : "info", icon: atLeast(onPlan, "plus") ? "check" : "info",
    text: upgradedNotice(org, onPlan) }) : "";
  return app(env, who, "overview", {
    title: "Overview",
    sub: `Welcome, ${escape(who.email)}. Here is ${name} at a glance.`,
    action: onPlan === "free" && canManage(org) ? `<a class="btn primary" href="${UPGRADE}">Upgrade to Plus</a>` : "",
    onPlan,
    body: `<div class="grid">
    ${notice}
    ${stats}
    ${setup(who, { machines, people, ways, onPlan }) || machinesCard(machines)}
    ${recent}
    ${plusCard(who, onPlan)}
    ${teamCard(who, onPlan)}
    </div>`,
    status: opts.status || 200,
  });
}

/* ---------- security ---------- */

/* How this account can sign in, a card each. The emailed code always
   works. A password is added, changed or removed with the current
   password or a code typed in the last 15 minutes (fresh() in session.js);
   without a password, only the code will do. Google and GitHub, where
   they are set up, are linked and unlinked with such a code too, and
   passkeys added and removed. The way to that code is once, at the top of
   the page (securityView()); each card says what of it needs one.
   Changing the password, or taking any way in away, signs the account out
   everywhere else, as the page says. */
async function methods(env, who, error, providerError, passkeyError) {
  const stored = await passwordOf(env, who.user);
  const confirmed = fresh(who);
  const method = (key, name, iconName, tag, tone, body) => card({
    title: name, icon: iconName, level: 3, attributes: `id="method-${key}" data-method="${key}"`,
    aside: pill(tag, tone), body,
  });
  const toConfirm = `<a href="#confirm">Email me a code</a>`;
  const currentField = (id) => (confirmed ? "" : `
      <label for="${id}">Current password</label>
      <input id="${id}" name="current" type="password" autocomplete="current-password" maxlength="4096" required>`);
  const newField = `
      <label for="new-password">New password</label>
      <input id="new-password" name="password" type="password" autocomplete="new-password" minlength="${MIN_LENGTH}" required>
      ${NEW_PASSWORD}`;
  /* Not sent: it tells a password manager whose password this is. */
  const username = `<input type="email" autocomplete="username" value="${escape(who.email)}" hidden readonly>`;
  const recent = `<p class="hint">You typed an emailed code in the last ${FRESH_FOR / 60} minutes, so your current
       password is not asked for.</p>`;
  let password;
  if (stored) {
    const remove = await otherWaysIn(env, who.user) > 0
      ? form("/password/remove", await formToken(env, who.id, "password-remove"), `${username}${currentField("current-password-remove")}
      <button type="submit" class="danger">Remove password</button>`, "method-form split")
      : "";
    password = method("password", "Password", "password", "set", "ok", `<p>Sign in with your email and this password.</p>
      ${problem(error)}
      ${confirmed ? recent : ""}
      ${form("/password", await formToken(env, who.id, "password"), `${username}${currentField("current-password")}${newField}
      <button type="submit">Change password</button>`, "method-form")}
      <p class="hint">Changing it signs this account out everywhere else.</p>
      ${remove}${remove ? "\n      <p class=\"hint\">Removing it signs this account out everywhere else.</p>" : ""}
      ${confirmed ? "" : `<p class="hint">Forgot it? Confirm with an emailed code, and it is not asked for: ${toConfirm}.</p>`}`);
  } else {
    password = method("password", "Password", "password", "not set", "", `<p>Add one to sign in with your email and a
         password, as well as with a code.</p>
      ${problem(error)}
      ${confirmed
        ? form("/password", await formToken(env, who.id, "password"), `${username}${newField}
      <button type="submit">Add password</button>`, "method-form")
        : `<p class="hint">Adding one needs an emailed code typed in the last ${FRESH_FOR / 60} minutes: ${toConfirm}.</p>`}`);
  }
  const ways = await linked(env, who.user);
  /* A provider switched off after accounts were linked to it still lists
     them, and still unlinks them, so nothing linked is left that cannot
     be taken away; it links nothing new. */
  const provider = async (key, says) => {
    const { name } = PROVIDERS[key];
    const on = configured(env, key);
    const mine = ways.filter((w) => w.provider === key);
    if (!on && !mine.length) return method(key, name, "link", "coming", "", `<p>${says}</p>`);
    const unlinkToken = await formToken(env, who.id, `unlink-${key}`);
    const items = mine.map((w) => `<li><span>${escape(w.verified_email || "no address")}, linked
        ${escape(when(w.created_at).slice(0, 10))}</span>${confirmed ? form(`/auth/${key}/unlink`, unlinkToken, `
        <input type="hidden" name="subject" value="${escape(w.provider_subject)}">
        <button type="submit" class="compact">Unlink</button>`) : ""}</li>`).join("");
    const err = providerError && providerError.provider === key ? providerError.text : "";
    const accounts = mine.length === 1 ? "account" : "accounts";
    const tag = !on ? "not offered now" : mine.length ? "linked" : "not linked";
    const about = !on
      ? `${name} sign-in is not offered just now, so ${mine.length === 1 ? "this" : "these"} ${name} ${accounts}
        cannot sign in here until it is again.`
      : mine.length ? `Sign in with ${mine.length === 1 ? "this" : "any of these"} ${name} ${accounts}.`
        : `Link a ${name} account here to sign in with it.${key === "google"
          ? ` A Gmail or Google Workspace account that is ${escape(who.email)} itself needs no link.` : ""}`;
    const linkForm = on
      ? form(`/auth/${key}`, await formToken(env, who.id, `link-${key}`),
        `<button type="submit">Link ${mine.length ? "another" : "a"} ${name} account</button>`)
      : "";
    return method(key, name, "link", tag, !on ? "warn" : mine.length ? "ok" : "", `<p>${about}</p>
      ${mine.length ? `<ul class="method-items">${items}</ul>` : ""}
      ${mine.length && confirmed ? `<p class="hint">Unlinking one keeps its id here, so that it does not link itself back; linking it again does.
        Unlinking one also signs this account out everywhere else.</p>` : ""}
      ${problem(err)}
      ${confirmed ? linkForm
        : `<p class="hint">${on ? "Linking or unlinking" : "Unlinking"} ${name} needs an emailed code typed in the last ${FRESH_FOR / 60} minutes: ${toConfirm}.</p>`}`);
  };
  return [
    method("code", "Emailed code", "mail", "always on", "ok",
      `<p>A code mailed to ${escape(who.email)} signs you in, and confirms what needs confirming.</p>`),
    password,
    await provider("google", "Sign in with a Google account linked here."),
    await provider("github", "Sign in with a GitHub account linked here."),
    await passkeys(env, who, passkeyError, method, toConfirm),
  ];
}

/* The account's passkeys, with the day each was added and last used, and
   the way to add or remove one, which needs a fresh code. */
async function passkeys(env, who, error, method, toConfirm) {
  const confirmed = fresh(who);
  const mine = await passkeysOf(env, who.user);
  const removeToken = await formToken(env, who.id, "passkey-remove");
  const items = mine.map((k) => `<li><span>${escape(k.label)}, added ${escape(when(k.created_at).slice(0, 10))},
        ${k.used_at === null ? "never used" : `last used ${escape(when(k.used_at).slice(0, 10))}`}</span>${confirmed
          ? form("/passkeys/remove", removeToken, `
        <input type="hidden" name="id" value="${escape(k.id)}">
        <button type="submit" class="compact">Remove</button>`) : ""}</li>`).join("");
  return method("passkeys", "Passkeys", "key", mine.length ? `${mine.length} added` : "none added", mine.length ? "ok" : "",
    `<p>${mine.length ? `Sign in with ${mine.length === 1 ? "this passkey" : "any of these"} on the
        <a href="/signin/passkey">passkey sign-in page</a>.`
      : "Sign in with this device's screen lock or a security key, once you add a passkey here."}</p>
      ${mine.length ? `<ul class="method-items">${items}</ul>` : ""}
      ${mine.length && confirmed ? `<p class="hint">Removing one signs this account out everywhere else.</p>` : ""}
      ${problem(error)}
      ${confirmed
        ? (mine.length < MAX_PASSKEYS ? `<div class="actions"><a class="btn" href="/passkeys/add">Add a passkey</a></div>` : "")
        : `<p class="hint">Adding or removing a passkey needs an emailed code typed in the last ${FRESH_FOR / 60} minutes: ${toConfirm}.</p>`}`);
}

/* Signing out everywhere and taking every other way in away with it: for
   someone who thinks a linked Google or GitHub account, or a passkey, is
   in someone else's hands. Only with a fresh code, as taking any one of
   them away is, and only offered while there is one: { html } for its
   card, or nothing but what went wrong. */
async function removeAll(env, who, error) {
  if (await otherWaysIn(env, who.user) < 2) return { html: "", error: problem(error) };
  const body = !fresh(who)
    ? `<p>To take away every Google and GitHub link and every passkey as well, confirm with an
       emailed code first (<a href="#confirm">at the top of this page</a>).</p>${problem(error)}`
    : `<p>Sign out everywhere and take away every Google and GitHub account linked here and every passkey
       with it, leaving the emailed code${await passwordOf(env, who.user) ? " and your password" : ""}. None of them
       links itself back.</p>
    ${problem(error)}
    ${form("/signout-all", await formToken(env, who.id, "signout-all"), `<input type="hidden" name="ways" value="remove">
      <button type="submit" class="danger">Sign out everywhere and remove every other way in</button>`)}`;
  return {
    html: card({ title: "Remove every other way in", icon: "alert", cls: "danger-zone", attributes: 'id="remove-ways"', body }),
    error: "",
  };
}

async function securityView(env, who, {
  passwordError = "", providerError = null, passkeyError = "", signoutError = "", status = 200,
} = {}) {
  const confirmed = fresh(who);
  const top = confirmed
    ? callout({ tone: "ok", icon: "check", title: "Confirmed", attributes: 'id="confirm"',
      text: `<p>You typed an emailed code in the last ${FRESH_FOR / 60} minutes, so the changes on this page go through
         without asking for one again.</p>` })
    : callout({ tone: "warn", icon: "security", title: "Confirm it is you", attributes: 'id="confirm"',
      text: `<p>Some changes here need an emailed code typed in the last ${FRESH_FOR / 60} minutes; each card says
         which. We send it to ${escape(who.email)}, and you come back here once it is typed.</p>`,
      act: form("/stepup", await formToken(env, who.id, "stepup"),
        `<input type="hidden" name="next" value="${PATHS.security}"><button type="submit" class="primary">Email me a code</button>`) });
  const danger = await removeAll(env, who, signoutError);
  const sessions = card({
    title: "Sessions", icon: "exit", attributes: 'id="sessions"',
    body: `<p>Sign out ends this browser's session. Sign out everywhere ends this account's sessions in every
         browser.</p>
      ${danger.error}
      <div class="actions">
      ${form("/signout", await formToken(env, who.id, "signout"), `<button type="submit">Sign out</button>`)}
      ${form("/signout-all", await formToken(env, who.id, "signout-all"), `<button type="submit">Sign out everywhere</button>`)}
      </div>`,
  });
  return app(env, who, "security", {
    title: "Security",
    sub: "How you sign in to ranwhat, and the browsers signed in as you.",
    body: `<div class="grid">
    ${top}
    <div class="c8 stack">
      <h2 class="label section-label">Ways to sign in</h2>
      ${(await methods(env, who, passwordError, providerError, passkeyError)).join("\n      ")}
    </div>
    <div class="c4 stack">
      ${sessions}
      ${danger.html}
    </div>
    </div>`,
    status,
    away: confirmed ? offered(env).map((p) => PROVIDERS[p].origin) : [],
  });
}

/* ---------- the other pages ---------- */

async function machinesView(env, who, { error = "", status = 200 } = {}) {
  const onPlan = await plan(env, who.org.id);
  return app(env, who, "machines", {
    title: "Machines",
    sub: `The terminals and CI tokens linked to ${escape(who.org.name)}, each with a token of its own.`,
    onPlan, status,
    body: `<div class="grid">${await machinesPanel(env, who, onPlan, error)}</div>`,
  });
}

async function membersView(env, who, { error = "", status = 200 } = {}) {
  const org = who.org;
  const onPlan = await plan(env, org.id);
  const rename = canManage(org) ? `<div class="method-form">${form("/org", await orgToken(env, who, "org"), `${orgInput(who)}
      <label for="name">Name</label>
      <input id="name" name="name" type="text" maxlength="80" required value="${escape(org.name)}">
      ${problem(error)}
      <button type="submit">Rename</button>`)}</div>` : problem(error);
  const about = card({
    title: "Organisation", icon: "team", attributes: 'id="organisation"',
    body: `<dl>
      <dt>Organisation</dt><dd>${escape(org.name)}</dd>
      <dt>Owner</dt><dd>${org.role === "owner" ? "You" : escape(await ownerOf(env, org.id) || "nobody")}</dd>
      <dt>Your role</dt><dd>${ROLES[org.role] || "Member"}</dd>
      <dt>Plan</dt><dd>${PLAN_NAMES[onPlan]}</dd>
    </dl>
    ${rename}`,
  });
  return app(env, who, "members", {
    title: "Members",
    sub: `Who is in ${escape(org.name)}, and their roles.`,
    onPlan, status,
    body: `<div class="grid">${about}${await membersPanel(env, who, onPlan)}</div>`,
  });
}

async function billingView(env, who, { status = 200 } = {}) {
  const onPlan = await plan(env, who.org.id);
  const billing = await billingPanel(env, who, onPlan);
  return app(env, who, "billing", {
    title: "Billing",
    sub: `What ${escape(who.org.name)} is on, and how it is paid for.`,
    onPlan, status,
    body: `<div class="grid">${billing.html}</div>`,
    away: billing.away,
  });
}

/* The account's own record, newest first. */
async function activityView(env, who) {
  const events = await history(env, who.user, 100);
  const rows = events.map((e) => `<tr><td class="when">${stamp(e.at)}</td>` +
    `<td>${escape(EVENTS[e.event] || e.event)}</td></tr>`).join("\n        ");
  return app(env, who, "activity", {
    title: "Activity",
    sub: "What happened on your account, newest first.",
    body: `<div class="grid">${card({
      title: "Your account's history", icon: "activity",
      aside: events.length ? pill(plural(events.length, "event")) : "",
      body: events.length ? `<table class="table">
      <thead><tr><th scope="col">When</th><th scope="col">What</th></tr></thead>
      <tbody>
        ${rows}
      </tbody></table>` : empty("<p>Nothing yet.</p>"),
    })}</div>`,
  });
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
   a cookie that may have been copied. With ways=remove and a fresh code,
   every Google and GitHub link and every passkey go in the same batch
   (removeAll()). */
async function signoutAll(request, env) {
  const who = await current(request, env);
  if (!who) return signedOut(request);
  const f = await fields(request);
  if (!await formOk(env, f, who.id, "signout-all")) return refused();
  const ways = f.get("ways") === "remove";
  if (ways && !fresh(who)) {
    return securityView(env, who, { status: 403,
      signoutError: `Taking every other way in away needs an emailed code typed in the last ${FRESH_FOR / 60} minutes, so nothing was done.` });
  }
  const db = env.LIST;
  await db.batch([
    ...(ways ? forgetWaysIn(env, { user: who.user, org: who.org.id }) : []),
    db.prepare("DELETE FROM sessions WHERE user_id = ?").bind(who.user),
    event(db, { org: who.org.id, user: who.user, what: "signout_all" }),
  ]);
  return redirect("/signin", [clearCookie(SESSION_COOKIE)]);
}

async function rename(request, env) {
  const who = await current(request, env);
  if (!who) return signedOut(request);
  const f = await fields(request);
  /* Bound to the organisation it was drawn for, so a page left open in
     another tab renames nothing else. */
  const bound = await orgFormOk(env, f, who, "org");
  if (bound === "refused") return refused();
  if (bound === "elsewhere") return elsewhere();
  if (!canManage(who.org)) {
    return page("Not allowed", `<h1>Only an owner or an admin can rename it.</h1>
      <p><a href="/">Your account</a></p>`, { status: 403 });
  }
  const name = orgName(f.get("name"));
  if (!name) {
    return membersView(env, who, { status: 400,
      error: "A name is 1 to 80 characters, with no control or formatting characters." });
  }
  if (name === who.org.name) return redirect(PATHS.members);
  if (!await countRename(env, who)) return membersView(env, who, { status: 429, error: TOO_MANY_RENAMES });
  /* Written, with its event, only while the name is still another: of
     renames to one name sent at once, one renames, and the rest write
     nothing and give their count back. */
  const db = env.LIST;
  const done = await db.batch([
    db.prepare(`INSERT INTO auth_events (org_id, user_id, event, subject, at)
                SELECT ?, ?, 'org_renamed', NULL, ? WHERE EXISTS (SELECT 1 FROM orgs WHERE id = ? AND name IS NOT ?)`)
      .bind(who.org.id, who.user, now(), who.org.id, name),
    db.prepare("UPDATE orgs SET name = ? WHERE id = ? AND name IS NOT ?").bind(name, who.org.id, name),
  ]);
  if (done[1].meta.changes !== 1) await uncountRename(env, who);
  return redirect(PATHS.members);
}

/* Renames, of the organisation and its machines together, are counted
   per account per day (accounts.js's RENAMES_PER_DAY). Counted before one
   is made, in one statement that counts nothing past the day's number
   (session.js's countWithin()), so renames sent at once are held to it
   too and a refused one writes nothing; one that then changes nothing
   gives its count back. */
const countRename = (env, who) => countWithin(env, "rename-user", who.user, DAY, RENAMES_PER_DAY);
const uncountRename = (env, who) => unbump(env, "rename-user", who.user, DAY);
const TOO_MANY_RENAMES = `You have renamed things ${RENAMES_PER_DAY} times today, the most one account can in a
  day, so nothing was renamed. Try again tomorrow.`.replace(/\s+/g, " ");

/* ---------- the password, signed in ---------- */

/* Whether the person may add, change or remove the password now: true when
   a code was typed in the last 15 minutes or the current password is typed
   now, under the same limits as signing in with it; otherwise the page
   that says why not. Without a password, only the code will do. */
async function allowed(request, env, who, stored, typed) {
  if (fresh(who)) return true;
  if (!stored) {
    return securityView(env, who, { status: 403,
      passwordError: `Adding a password needs an emailed code typed in the last ${FRESH_FOR / 60} minutes.` });
  }
  const result = await checkPassword(request, env, who.email, typed);
  if (result.ok && result.user === who.user) return true;
  const [status, passwordError] = {
    locked: [429, "Too many tries with a password. Confirm with an emailed code instead."],
    network: [429, "More passwords were tried from your network in the last hour than we check. Confirm with an emailed code instead."],
    unavailable: [503, "Passwords are not available just now."],
  }[result.why] || [400, "Your current password is not right."];
  return securityView(env, who, { status, passwordError });
}

/* Adds or changes it, and ends every other session of the account: a
   password that has to change may have been used elsewhere already. */
async function setPassword(request, env) {
  const who = await current(request, env);
  if (!who) return signedOut(request);
  const f = await fields(request);
  if (!await formOk(env, f, who.id, "password")) return refused();
  const ok = await allowed(request, env, who, await passwordOf(env, who.user), f.get("current"));
  if (ok !== true) return ok;
  if (!await hashAllowed(request, env)) return tooManyHashes();
  const password = f.get("password");
  const wrong = await passwordProblem(env, password);
  if (wrong) return securityView(env, who, { status: 400, passwordError: wrong });
  let hash;
  try {
    hash = await hashPassword(env, password);
  } catch (err) {
    console.log(`account password hash: ${err.name || "error"}`);
    return unavailable();
  }
  const db = env.LIST;
  await db.batch([
    ...await attachPassword(env, { user: who.user, org: who.org.id, hash }),
    db.prepare("DELETE FROM sessions WHERE user_id = ? AND id != ?").bind(who.user, who.id),
  ]);
  return redirect(PATHS.security);
}

/* Only while another way in remains, which the emailed code always is.
   Every other session of the account ends with it, as when the password
   changes: one that must go may be in someone else's hands, and so may
   the sessions it opened. */
async function removePassword(request, env) {
  const who = await current(request, env);
  if (!who) return signedOut(request);
  const f = await fields(request);
  if (!await formOk(env, f, who.id, "password-remove")) return refused();
  const stored = await passwordOf(env, who.user);
  if (!stored) return redirect(PATHS.security);
  if (await otherWaysIn(env, who.user) < 1) {
    return securityView(env, who, { status: 400, passwordError: "This password is your only way in, so it stays." });
  }
  const ok = await allowed(request, env, who, stored, f.get("current"));
  if (ok !== true) return ok;
  await env.LIST.batch([...detachPassword(env, { user: who.user, org: who.org.id }), othersOut(env, who)]);
  return redirect(PATHS.security);
}

/* The statement that ends every session of this account but this one. */
function othersOut(env, who) {
  return env.LIST.prepare("DELETE FROM sessions WHERE user_id = ? AND id != ?").bind(who.user, who.id);
}

/* ---------- Google and GitHub ---------- */

/* oauth.js's limit on sign-ins started from one network. */
const tooManyStarts = () => page("Too many tries", `<h1>Too many tries.</h1>
  <p>More sign-ins were started from your network in the last hour than we
     take. Try again in an hour, or <a href="/signin">sign in with an emailed
     code</a>.</p>`, { status: 429 });

/* Off to the provider to sign in. Someone signed in already goes home. */
async function providerStart(request, env, ctx, url, provider) {
  const next = nextPath(url.searchParams.get("next"));
  if (await current(request, env)) return redirect(next);
  const started = await begin(request, env, { provider, next });
  if (started.refused) return tooManyStarts();
  return away(started.to, [started.cookie]);
}

const needsCode = (env, who, provider) => securityView(env, who, { status: 403, providerError: { provider,
  text: `Linking or unlinking ${PROVIDERS[provider].name} needs an emailed code typed in the last ${FRESH_FOR / 60} minutes.` } });

/* Off to the provider to link it to the account signed in: a form on the
   account page, with a code typed in the last 15 minutes. The flow is
   bound to this session, and only this session can finish it. */
async function linkStart(request, env, ctx, url, provider) {
  const who = await current(request, env);
  if (!who) return signedOut(request);
  const f = await fields(request);
  if (!await formOk(env, f, who.id, `link-${provider}`)) return refused();
  if (!fresh(who)) return needsCode(env, who, provider);
  const started = await begin(request, env, { provider, purpose: "link", user: who.user, session: who.id });
  if (started.refused) return tooManyStarts();
  return away(started.to, [started.cookie]);
}

/* Back from the provider. Signing in goes as a password does: a new
   session in place of the browser's, not fresh, since no code was typed.
   Linking needs the session that asked for it, still signed in. The
   flow's cookie goes either way: it worked once already. */
async function providerBack(request, env, ctx, url, provider) {
  const name = PROVIDERS[provider].name;
  const cookies = [clearCookie(OAUTH_COOKIE)];
  const done = await finish(request, env, provider, url);
  if (!done.ok) return providerProblem(name, done.why, done.flow, cookies);
  const { flow, profile } = done;
  const db = env.LIST;
  if (flow.purpose === "link") {
    const who = await current(request, env);
    if (!who || who.id !== flow.session_id || who.user !== flow.user_id) {
      return page("Sign in again", `<h1>Sign in again.</h1>
        <p class="bad">This browser is no longer signed in as it was when linking ${name} began,
           so nothing was linked.</p>
        <p><a href="/">Your account</a></p>`, { status: 403, cookies });
    }
    /* The email that tells the account's address is taken first: without
       it, nothing is linked (session.js's holdNotice()). */
    const hold = await holdNotice(request, env, who.user);
    if (hold.refused) return noNotice(name, hold.refused, true, cookies);
    const result = await attach(env, { user: who.user, org: who.org.id, provider, profile });
    if (result.what !== "linked") await releaseNotice(env, hold);
    if (result.refused) return notLinked(name, result.refused, cookies);
    if (result.what === "linked") tellWayIn(env, ctx, { user: who.user, what: provider, hold });
    return redirect(PATHS.security, cookies);
  }
  const result = await arrive(env, provider, profile, {
    hold: (user) => holdNotice(request, env, user), release: (hold) => releaseNotice(env, hold),
  });
  if (result.refused === "unproven") return unproven(name, cookies);
  if (result.refused === "unlinked") return wasUnlinked(name, cookies);
  if (result.refused === "notice") return noNotice(name, result.why, false, cookies);
  if (result.refused) return unverified(name, cookies);
  const user = result.user;
  const entered = await enter(request, env, { user, next: flow.next, coded: false, cookies, after: async (org) => [
    ...(result.what === "linked" ? [event(db, { org, user, what: `linked_${provider}` })] : []),
    event(db, { org, user, what: `${result.what === "signup" ? "signup" : "signin"}_${provider}` }),
  ] });
  if (result.what === "linked") tellWayIn(env, ctx, { user, what: provider, hold: result.hold });
  return entered;
}

/* Why the email that tells of a new way in cannot go now, and when it
   can: [the end of a sentence, a sentence]. */
const unsent = (why) => (why === "network-day"
  ? ["more account emails were sent for your network today than we send to one network in a day",
    "Try again tomorrow, or from another network."]
  : ["today's account emails are used up", "Try again after midnight UTC."]);

/* A Google or GitHub account that would have been linked, to the account
   signed in (`linking`) or to the one its address has, without the email
   that tells that account so: nothing was linked, and nobody signed in. */
function noNotice(name, why, linking, cookies) {
  const [reason, advice] = unsent(why);
  return page("Not linked", `<h1>Not linked.</h1>
  <p class="bad">Linking ${name} to a ranwhat account sends that account's address an email to say so,
     and ${reason}, so nothing was linked${linking ? "" : " and nobody was signed in"}.</p>
  <p>${advice}</p>
  <p>${linking ? `<a href="/security">Back to your account</a>` : `<a href="/signin">Back to signing in</a>`}</p>`,
  { status: why === "network-day" ? 429 : 503, cookies });
}

/* A flow that came back without an account to open (oauth.js's finish()). */
function providerProblem(name, why, flow, cookies) {
  const linking = Boolean(flow) && flow.purpose === "link";
  const none = linking ? "nothing was linked" : "nobody was signed in";
  const [status, title, text] = {
    expired: [400, "Start again", `That ${name} sign-in has expired or was already used. Start it again from this site.`],
    cancelled: [200, "Cancelled", `${name} says it was cancelled, so ${none}.`],
    unavailable: [502, "Try again", `${name} could not be reached just now, so ${none}. Try again in a minute.`],
  }[why] || [400, "Start again", `${name}'s answer did not check out, so ${none}. Start it again from this site.`];
  return page(title, `<h1>${title}.</h1>
    <p class="bad">${text}</p>
    <p>${linking ? `<a href="/security">Back to your account</a>` : `<a href="/signin">Back to signing in</a>`}</p>`,
  { status, cookies });
}

/* The provider vouched for no address: it can neither make an account nor
   join one, and the emailed code, which proves the address itself, is the
   way in. */
const unverified = (name, cookies) => page("Use an emailed code", `<h1>Use an emailed code.</h1>
  <p class="bad">${name} did not vouch for an email address on that account${name === "GitHub"
    ? " (we take only its primary address, and only once GitHub has verified it)" : ""}, so it
     cannot make or open a ranwhat account.</p>
  <p><a href="/signin">Sign in with an emailed code</a> instead: typing it proves the address.</p>`,
{ status: 403, cookies });

/* The provider vouched for an address it is not the authority for
   (oauth.js): GitHub always, Google for an address that is not Gmail or
   its Workspace domain. The same page whether or not an account has the
   address, so it says nothing about who has one. */
const unproven = (name, cookies) => page("Use an emailed code", `<h1>Use an emailed code first.</h1>
  <p class="bad">${name} says the address on that account was verified once, which does not show it
     is still yours${name === "GitHub" ? "" : " (Google vouches for that only for Gmail and Google Workspace addresses)"},
     so ${name} cannot make or open a ranwhat account by itself.</p>
  <p><a href="/signin">Sign in with an emailed code</a>, which makes the account if there is none yet.
     Then link ${name} from your account page, and it signs you in from then on.</p>`,
{ status: 403, cookies });

/* A way in the account at this address unlinked: only linking it again
   from the account page brings it back. */
const wasUnlinked = (name, cookies) => page("Use an emailed code", `<h1>Use an emailed code.</h1>
  <p class="bad">That ${name} account was unlinked from the ranwhat account for its address, so it
     does not sign in there any more.</p>
  <p><a href="/signin">Sign in with an emailed code</a>. To use ${name} again, link it from your
     account page.</p>`,
{ status: 403, cookies });

function notLinked(name, why, cookies) {
  const text = {
    unverified: `${name} did not vouch for an email address on that account, so it cannot be linked.`,
    taken: `That ${name} account already signs in to another ranwhat account, and stays with it.`,
    address: `The address that ${name} account has verified has its own ranwhat account. Sign in to that one to link it there.`,
  }[why];
  return page("Not linked", `<h1>Not linked.</h1>
    <p class="bad">${text}</p>
    <p><a href="/security">Back to your account</a></p>`, { status: why === "unverified" ? 403 : 409, cookies });
}

/* Takes a Google or GitHub account away, with a fresh code, while another
   way in remains, which the emailed code always is, and ends every other
   session of the account with it, the ones it opened among them. */
async function unlinkPost(request, env, ctx, url, provider) {
  const who = await current(request, env);
  if (!who) return signedOut(request);
  const f = await fields(request);
  if (!await formOk(env, f, who.id, `unlink-${provider}`)) return refused();
  if (!fresh(who)) return needsCode(env, who, provider);
  const statements = await detach(env, {
    user: who.user, org: who.org.id, provider, subject: String(f.get("subject") ?? ""),
  });
  if (!statements.length) return redirect(PATHS.security);
  const left = await otherWaysIn(env, who.user) - 1 + (await passwordOf(env, who.user) ? 1 : 0);
  if (left < 1) {
    return securityView(env, who, { status: 400, providerError: { provider,
      text: `This ${PROVIDERS[provider].name} account is your only way in, so it stays.` } });
  }
  await env.LIST.batch([...statements, othersOut(env, who)]);
  return redirect(PATHS.security);
}

/* ---------- passkeys ---------- */

const needsPasskeyCode = (env, who) => securityView(env, who, { status: 403,
  passkeyError: `Adding or removing a passkey needs an emailed code typed in the last ${FRESH_FOR / 60} minutes.` });

/* The page that adds one: the form /passkeys.js sends once the device has
   made the passkey. Without the script it says why nothing happens. */
async function addPasskeyPage(request, env) {
  const who = await current(request, env);
  if (!who) return signedOut(request);
  if (!fresh(who)) return needsPasskeyCode(env, who);
  return addPasskeyForm(env, who);
}

const NO_SCRIPT = `<noscript><p class="bad">Passkeys need JavaScript, which is off in this browser. Every
       other way in works without it.</p></noscript>`;

async function addPasskeyForm(env, who, { error = "", status = 200 } = {}) {
  return page("Add a passkey", `<h1>Add a passkey</h1>
    <p>Your device asks for its screen lock (a fingerprint, your face or its PIN) or for
       a security key, and makes a passkey that signs in to this account, on this site
       only.</p>
    ${form("/passkeys", await formToken(env, who.id, "passkey-add"), `
      <input type="hidden" name="clientDataJSON" value="">
      <input type="hidden" name="attestationObject" value="">
      <label for="label">Name it, to tell it apart later</label>
      <input id="label" name="label" type="text" maxlength="${MAX_LABEL}" placeholder="Work laptop" autofocus>
      <p class="bad passkey-problem" hidden></p>
      ${problem(error)}
      <button type="submit" class="primary">Add passkey</button>`, "", `data-passkey="/passkeys/new" data-ceremony="create"`)}
    ${NO_SCRIPT}
    <p><a href="/security">Back to your account</a></p>`,
  { status, passkeys: true });
}

/* JSON for the script: { error } with the status, or the options. */
const problemJson = (status, error) => data({ error }, status);

async function passkeyOptions(request, env) {
  if (!notCrossSite(request)) return problemJson(403, "That request came from another site.");
  const who = await current(request, env);
  if (!who) return problemJson(401, "You are signed out. Sign in again, then add the passkey.");
  if (!fresh(who)) {
    return problemJson(403, `Adding a passkey needs an emailed code typed in the last ${FRESH_FOR / 60} minutes. Go back to your account for one.`);
  }
  const options = await registrationOptions(env, who);
  if (options.refused === "full") return problemJson(400, `An account holds ${MAX_PASSKEYS} passkeys at most. Remove one first.`);
  if (options.refused) return problemJson(429, "More passkeys were started for this account in the last hour than we take. Try again in an hour.");
  return data(options);
}

async function addPasskey(request, env, ctx) {
  const who = await current(request, env);
  if (!who) return signedOut(request);
  const f = await fields(request);
  if (!await formOk(env, f, who.id, "passkey-add")) return refused();
  if (!fresh(who)) return needsPasskeyCode(env, who);
  /* The email that tells the account's address is taken first: without
     it, no passkey is added (session.js's holdNotice()). */
  const hold = await holdNotice(request, env, who.user);
  if (hold.refused) {
    const [reason, advice] = unsent(hold.refused);
    return addPasskeyForm(env, who, { status: hold.refused === "network-day" ? 429 : 503,
      error: `No passkey was added: each one added sends your address an email to say so, and ${reason}. ${advice}` });
  }
  const result = await register(env, who, {
    clientDataJSON: f.get("clientDataJSON"), attestationObject: f.get("attestationObject"),
    label: passkeyLabel(f.get("label")),
  });
  if (!result.refused) {
    tellWayIn(env, ctx, { user: who.user, what: "passkey", hold });
    return redirect(PATHS.security);
  }
  await releaseNotice(env, hold);
  const [status, error] = {
    expired: [400, "That passkey request has expired or was already used, so nothing was added. Try again."],
    taken: [409, "That passkey is already added."],
    full: [400, `An account holds ${MAX_PASSKEYS} passkeys at most. Remove one first.`],
  }[result.refused] || [400, "What your browser sent did not check out, so no passkey was added. Try again."];
  return addPasskeyForm(env, who, { status, error });
}

/* Only while another way in remains, which the emailed code always is,
   and every other session of the account ends with it, the ones it opened
   among them. */
async function removePasskey(request, env) {
  const who = await current(request, env);
  if (!who) return signedOut(request);
  const f = await fields(request);
  if (!await formOk(env, f, who.id, "passkey-remove")) return refused();
  if (!fresh(who)) return needsPasskeyCode(env, who);
  const statements = await forgetPasskey(env, { user: who.user, org: who.org.id, id: f.get("id") ?? "" });
  if (!statements.length) return redirect(PATHS.security);
  const left = await otherWaysIn(env, who.user) - 1 + (await passwordOf(env, who.user) ? 1 : 0);
  if (left < 1) return securityView(env, who, { status: 400, passkeyError: "This passkey is your only way in, so it stays." });
  await env.LIST.batch([...statements, othersOut(env, who)]);
  return redirect(PATHS.security);
}

/* The page that signs in with one. Its form token and its challenges are
   bound to the browser's __Host-rw_signin cookie, made here when it has
   none yet. */
async function passkeySigninPage(request, env, ctx, url) {
  const next = nextPath(url.searchParams.get("next"));
  if (await current(request, env)) return redirect(next);
  return passkeySigninForm(env, readCookie(request, SIGNIN_COOKIE), { next });
}

async function passkeySigninForm(env, browser, { next = "/", error = "", status = 200 } = {}) {
  const { binding, cookies } = bound(browser);
  return page("Sign in with a passkey", `<h1>Sign in with a passkey</h1>
    <p>Your device shows the passkeys it has for this site, and asks for its screen lock
       or your security key.</p>
    ${form("/signin/passkey", await formToken(env, binding, "passkey"), `
      <input type="hidden" name="next" value="${escape(next)}">
      <input type="hidden" name="id" value="">
      <input type="hidden" name="clientDataJSON" value="">
      <input type="hidden" name="authenticatorData" value="">
      <input type="hidden" name="signature" value="">
      <input type="hidden" name="userHandle" value="">
      <p class="bad passkey-problem" hidden></p>
      ${problem(error)}
      <button type="submit" class="primary">Sign in with a passkey</button>`, "", `data-passkey="/passkeys/challenge" data-ceremony="get"`)}
    ${NO_SCRIPT}
    <p>No passkey here? <a href="/signin">Sign in with an emailed code</a>, or
       <a href="/signin/password">with your password</a>. Passkeys are added from your
       account page.</p>
    <p><small>This page sets a cookie only to sign you in, and nothing on it tracks you.
       <a href="${PRIVACY}">Privacy</a></small></p>`,
  { status, cookies, passkeys: true });
}

async function passkeyChallenge(request, env) {
  if (!notCrossSite(request)) return problemJson(403, "That request came from another site.");
  const cookie = readCookie(request, SIGNIN_COOKIE);
  if (!cookie) return problemJson(403, "Reload the page, then try again.");
  const options = await signinOptions(request, env, cookie);
  if (options.refused) {
    return problemJson(429, "More passkey sign-ins were started from your network in the last hour than we take. Try again in an hour, or sign in with an emailed code.");
  }
  return data(options);
}

/* One answer for every way a passkey can fail to sign in (passkeys.js's
   signIn()). Signing in then goes as a password does: a new session, not
   fresh, since no code was typed. */
async function passkeySignin(request, env) {
  const f = await fields(request);
  const binding = readCookie(request, SIGNIN_COOKIE);
  if (!await formOk(env, f, binding, "passkey")) return refused();
  const next = nextPath(f.get("next"));
  const result = await signIn(env, binding, {
    id: f.get("id"), clientDataJSON: f.get("clientDataJSON"), authenticatorData: f.get("authenticatorData"),
    signature: f.get("signature"), userHandle: f.get("userHandle"),
  });
  if (result.refused) {
    return passkeySigninForm(env, binding, { next, status: 400,
      error: "That passkey did not sign you in. Try again, or sign in another way." });
  }
  const db = env.LIST;
  const user = result.user;
  return enter(request, env, { user, next, coded: false, after: async (org) => [
    db.prepare("UPDATE users SET signed_in_at = ? WHERE id = ?").bind(now(), user),
    event(db, { org, user, what: "signin_passkey" }),
  ] });
}

const pageScript = () => script(PAGE_SCRIPT);

/* ---------- machines and CI tokens ---------- */

const KINDS = { device: "terminal", ci: "CI", legacy: "old subscription token" };
const UNNAMED = { device: "Unnamed terminal", ci: "Unnamed CI token", legacy: "Subscription token" };

/* The select's choices for a CI token's expiry, in this order. */
const EXPIRY_CHOICES = [["never", "Never"], ["30", "In 30 days"], ["90", "In 90 days"], ["365", "In a year"]];

const NONCE = /^[A-Za-z0-9_-]{43}$/;
const ciAction = (nonce) => `ci-token:${nonce}`;

const day = (t) => escape(when(t).slice(0, 10));

/* Every machine of the organisation being looked at: what it is called,
   what kind it is, who linked or made it and when, and the day it was last
   used, with a form to rename it and one to revoke it for whoever may
   (machines.js's mayChange()); revoking needs a fresh code. Then CI tokens:
   locked below the plan features.js names for them, and made by an owner
   or admin with a fresh code. */
async function machinesPanel(env, who, onPlan, error) {
  const org = who.org;
  const confirmed = fresh(who);
  const t = now();
  const list = await machinesOf(env, org.id, await joinedAt(env, org.id, who.user));
  const renameToken = await formToken(env, who.id, "machine-rename");
  const revokeToken = await formToken(env, who.id, "machine-revoke");
  const items = list.map((m) => {
    const may = mayChange(who, m);
    const id = escape(m.id);
    const name = m.label ? escape(m.label) : UNNAMED[m.kind];
    const by = m.kind === "legacy"
      ? `The token emailed with a subscription, attached here on ${day(m.created_at)}.`
      : `${m.kind === "ci" ? "Made" : "Linked"} by ${m.email ? escape(m.email) : "a former member"} on ${day(m.created_at)}.`;
    const used = m.kind === "legacy" ? "Its use is not recorded."
      : m.last_used_day === null ? "Not used yet." : `Last used ${day(m.last_used_day)}.`;
    const expired = m.expires_at !== null && m.expires_at <= t;
    const expiry = m.expires_at === null ? "" : expired ? ` Expired ${day(m.expires_at)}.` : ` Expires ${day(m.expires_at)}.`;
    const forms = may ? `
        <details><summary>${m.label ? "Rename" : "Name it"}</summary>
        ${form("/machines/rename", renameToken, `
          <input type="hidden" name="id" value="${id}">
          <label for="label-${id}">Name</label>
          <input id="label-${id}" name="label" type="text" maxlength="${MAX_MACHINE_LABEL}" required value="${escape(m.label)}">
          <button type="submit">Rename</button>`)}</details>
        ${confirmed ? form("/machines/revoke", revokeToken, `
          <input type="hidden" name="id" value="${id}">
          <button type="submit">${expired ? "Remove" : "Revoke"}</button>`) : ""}` : "";
    return `<li data-machine="${id}"><strong>${name}</strong> <span class="tag">${KINDS[m.kind]}${expired ? ", expired" : ""}</span>
        <br>${by} ${used}${expiry}${forms}</li>`;
  }).join("");
  const anyMine = list.some((m) => mayChange(who, m));

  const revokeStep = anyMine && !confirmed
    ? `<p>Revoking a machine needs an emailed code typed in the last ${FRESH_FOR / 60} minutes.</p>
      ${form("/stepup", await formToken(env, who.id, "stepup"),
        `<input type="hidden" name="next" value="/machines"><button type="submit">Email me a code</button>`)}`
    : "";

  let ci;
  const feature = FEATURES.ci_tokens;
  if (!allows(onPlan, "ci_tokens")) {
    ci = `<div class="panel locked" id="ci-tokens" data-feature="ci_tokens">
      <h2>${escape(feature.name)} <span class="tag">locked, needs ${PLAN_NAMES[feature.plan]}</span></h2>
      <p>${escape(feature.says)} Each pipeline gets a token of its own, named, with an expiry if you
         like.</p>
      <p><a href="${UPGRADE}">Upgrade to ${PLAN_NAMES[feature.plan]}</a></p></div>`;
  } else if (!canManage(org)) {
    ci = `<div class="panel" id="ci-tokens" data-feature="ci_tokens"><h2>${escape(feature.name)}</h2>
      <p>An owner or an admin of ${escape(org.name)} can make a CI token here.</p></div>`;
  } else if (await liveCi(env, org.id) >= MAX_CI) {
    ci = `<div class="panel" id="ci-tokens" data-feature="ci_tokens"><h2>${escape(feature.name)}</h2>
      <p>${escape(org.name)} holds ${MAX_CI} CI tokens, the most it can. Revoke one to make another.</p></div>`;
  } else if (!confirmed) {
    ci = `<div class="panel" id="ci-tokens" data-feature="ci_tokens"><h2>${escape(feature.name)}</h2>
      <p>${escape(feature.says)} Making one needs an emailed code typed in the last ${FRESH_FOR / 60} minutes.</p>
      ${form("/stepup", await formToken(env, who.id, "stepup"),
        `<input type="hidden" name="next" value="/machines"><button type="submit">Email me a code</button>`)}</div>`;
  } else {
    const nonce = randomToken();
    const options = EXPIRY_CHOICES.map(([value, text]) => `<option value="${value}">${text}</option>`).join("");
    ci = `<div class="panel" id="ci-tokens" data-feature="ci_tokens"><h2>${escape(feature.name)}</h2>
      <p>${escape(feature.says)} The token is shown once, on the next page, and never again.</p>
      ${form("/tokens/ci", await orgToken(env, who, ciAction(nonce)), `${orgInput(who)}
        <input type="hidden" name="nonce" value="${nonce}">
        <label for="ci-label">Name</label>
        <input id="ci-label" name="label" type="text" maxlength="${MAX_MACHINE_LABEL}" required placeholder="GitHub Actions">
        <label for="ci-expires">Expires</label>
        <select id="ci-expires" name="expires">${options}</select>
        <button type="submit">Make a CI token</button>`)}</div>`;
  }
  return `<section class="panel" id="machines">
    <h2>Machines</h2>
    <p>Terminals linked with ranwhat login, CI tokens, and a subscription's emailed token once it is
       attached here, each with a token of its own. Revoking one stops it at once. A terminal unused for
       ${IDLE_DAYS} days is revoked by itself; ranwhat login links it again.</p>
    ${items ? `<ul>${items}</ul>` : "<p>None yet. Run <strong>ranwhat login</strong> in a terminal to link it.</p>"}
    ${problem(error)}
    ${revokeStep}
    ${ci}</section>`;
}

const notInOrg = (env, who) => machinesView(env, who, { status: 404,
  error: "That machine is not one of this organisation's, or it is already revoked, so nothing was changed." });

const notYours = (env, who) => machinesView(env, who, { status: 403,
  error: "Only an owner or an admin, or whoever linked it, can rename or revoke that machine." });

/* Names it. The id is looked up in the organisation this session is
   looking at, never trusted. */
async function renameMachinePost(request, env) {
  const who = await current(request, env);
  if (!who) return signedOut(request);
  const f = await fields(request);
  if (!await formOk(env, f, who.id, "machine-rename")) return refused();
  const machine = await machineIn(env, who.org.id, f.get("id"));
  if (!machine) return notInOrg(env, who);
  if (!mayChange(who, machine)) return notYours(env, who);
  const label = machineLabel(f.get("label"));
  if (!label) {
    return machinesView(env, who, { status: 400,
      error: `A name is 1 to ${MAX_MACHINE_LABEL} characters, with no control or formatting characters.` });
  }
  if (label === machine.label) return redirect(PATHS.machines);
  if (!await countRename(env, who)) return machinesView(env, who, { status: 429, error: TOO_MANY_RENAMES });
  if (!await renameMachine(env, who, machine, label)) await uncountRename(env, who);
  return redirect(PATHS.machines);
}

/* Revokes it, with a fresh code: the feed refuses its token from the next
   request on. */
async function revokeMachinePost(request, env) {
  const who = await current(request, env);
  if (!who) return signedOut(request);
  const f = await fields(request);
  if (!await formOk(env, f, who.id, "machine-revoke")) return refused();
  const machine = await machineIn(env, who.org.id, f.get("id"));
  if (!machine) return notInOrg(env, who);
  if (!mayChange(who, machine)) return notYours(env, who);
  if (!fresh(who)) {
    return machinesView(env, who, { status: 403,
      error: `Revoking a machine needs an emailed code typed in the last ${FRESH_FOR / 60} minutes, so nothing was revoked.` });
  }
  await revokeMachine(env, who, machine);
  return redirect(PATHS.machines);
}

/* Makes a CI token: an owner or admin, of an organisation whose plan has
   ci_tokens (features.js), with a fresh code. The form carries a random
   nonce its token is bound to, and each nonce makes one token: sent again
   (a reload of the page that showed it), it goes back to the account,
   where the token it made is listed, rather than make a second. The token
   is in this response and nowhere else. */
async function ciTokenPost(request, env) {
  const who = await current(request, env);
  if (!who) return signedOut(request);
  const f = await fields(request);
  const nonce = f.get("nonce");
  /* Bound to the nonce and to the organisation it was drawn for: a token
     made from a page left open in another tab would be for an
     organisation the page did not name. */
  const bound = typeof nonce === "string" && NONCE.test(nonce) ? await orgFormOk(env, f, who, ciAction(nonce)) : "refused";
  if (bound === "refused") return refused();
  if (bound === "elsewhere") return elsewhere();
  if (!canManage(who.org)) {
    return machinesView(env, who, { status: 403, error: "Only an owner or an admin can make a CI token." });
  }
  const tier = FEATURES.ci_tokens.plan;
  if (!allows(await plan(env, who.org.id), "ci_tokens")) {
    return machinesView(env, who, { status: 403,
      error: `CI tokens come with ${PLAN_NAMES[tier]}, so none was made.` });
  }
  if (!fresh(who)) {
    return machinesView(env, who, { status: 403,
      error: `Making a CI token needs an emailed code typed in the last ${FRESH_FOR / 60} minutes, so none was made.` });
  }
  const label = machineLabel(f.get("label"));
  if (!label) {
    return machinesView(env, who, { status: 400,
      error: `A name is 1 to ${MAX_MACHINE_LABEL} characters, with no control or formatting characters.` });
  }
  const expires = String(f.get("expires") ?? "never");
  if (!Object.hasOwn(EXPIRIES, expires)) {
    return machinesView(env, who, { status: 400, error: "Choose when the token expires from the list." });
  }
  if (await bump(env, "ci-form", nonce, DAY) > 1) return redirect(PATHS.machines);
  const made = await mintCi(env, who, { label, days: EXPIRIES[expires] });
  if (made.refused) {
    return machinesView(env, who, { status: 400,
      error: `${who.org.name} holds ${MAX_CI} CI tokens, the most it can. Revoke one to make another.` });
  }
  return page("Your CI token", `<h1>Your CI token</h1>
    <p class="bad"><strong>Copy it now: this is the only time it is shown.</strong> We keep only a hash
       of it, so nobody, us included, can show it again. A lost one is revoked and replaced, never
       recovered.</p>
    <code class="secret">${escape(made.token)}</code>
    <dl>
      <dt>Name</dt><dd>${escape(label)}</dd>
      <dt>Organisation</dt><dd>${escape(who.org.name)}</dd>
      <dt>Expires</dt><dd>${made.expires_at === null ? "Never; revoke it on your account page" : day(made.expires_at)}</dd>
    </dl>
    <p>Keep it in your CI's secrets as <strong>RANWHAT_TOKEN</strong>, where <strong>ranwhat update</strong>
       reads it. Never put it in a repository, a command line or a log.</p>
    <p><a href="/machines">Back to Machines</a></p>`);
}

/* ---------- the host ---------- */

/* Path: { method: handler }. */
const ROUTES = {
  "/": { GET: signedInPage(overview) },
  "/machines": { GET: signedInPage(machinesView) },
  "/members": { GET: signedInPage(membersView) },
  "/security": { GET: signedInPage(securityView) },
  "/activity": { GET: signedInPage(activityView) },
  "/signin": { GET: signinPage, POST: signinPost },
  "/signin/code": { GET: codePage, POST: codePost },
  "/signin/again": { GET: againPage, POST: again },
  "/signin/password": { GET: passwordPage, POST: passwordPost },
  "/signup": { GET: signupPage, POST: signupPost },
  "/reset": { GET: resetPage, POST: resetPost },
  "/stepup": { POST: stepup },
  "/password": { POST: setPassword },
  "/password/remove": { POST: removePassword },
  "/signout": { POST: signout },
  "/signout-all": { POST: signoutAll },
  "/org": { POST: rename },
  "/org/switch": { POST: switchPost },
  "/passkeys/add": { GET: addPasskeyPage },
  "/passkeys/new": { GET: passkeyOptions },
  "/passkeys": { POST: addPasskey },
  "/passkeys/remove": { POST: removePasskey },
  "/signin/passkey": { GET: passkeySigninPage, POST: passkeySignin },
  "/passkeys/challenge": { GET: passkeyChallenge },
  "/passkeys.js": { GET: pageScript },
  "/device": { GET: devicePage, POST: deviceLookup },
  "/device/approve": { POST: approve },
  "/device/deny": { POST: deny },
  "/machines/rename": { POST: renameMachinePost },
  "/machines/revoke": { POST: revokeMachinePost },
  "/tokens/ci": { POST: ciTokenPost },
  "/upgrade": { GET: upgradePage, POST: upgradePost },
  "/billing": { GET: signedInPage(billingView), POST: billingPost },
  "/members/invite": { POST: invitePost },
  "/invite": { GET: inviteAgain, POST: acceptPost },
  "/invites/revoke": { POST: revokeInvitePost },
  "/members/role": { POST: rolePost },
  "/members/remove": { POST: removePost },
  "/members/leave": { POST: leavePost },
  "/members/transfer": { POST: transferPost },
};
for (const provider of Object.keys(PROVIDERS)) {
  const as = (handle) => (request, env, ctx, url) => handle(request, env, ctx, url, provider);
  ROUTES[`/auth/${provider}`] = { GET: as(providerStart), POST: as(linkStart) };
  ROUTES[`/auth/${provider}/callback`] = { GET: as(providerBack) };
  ROUTES[`/auth/${provider}/unlink`] = { POST: as(unlinkPost) };
}

export async function account(request, env, ctx) {
  /* Switched on without its secret, its database or its mail: say so
     rather than sign anyone in with a missing key. */
  if (!ready(env)) {
    return page("Not available", `<h1>Accounts are not available just now.</h1>
      <p>Everything ranwhat does on your machine works without one.
         <a href="https://ranwhat.com/">ranwhat.com</a></p>`, { status: 503 });
  }
  const url = new URL(request.url);
  /* A provider without its client id and secret is not there, but for
     unlinking an account linked while it was. */
  const via = /^\/auth\/([^/]+)/.exec(url.pathname);
  if (via && !configured(env, via[1]) &&
      !(Object.hasOwn(PROVIDERS, via[1]) && url.pathname === `/auth/${via[1]}/unlink`)) return notFound();
  /* The link in an invite email carries its token in the path. */
  const link = /^\/invite\/([^/]+)$/.exec(url.pathname);
  const route = link ? { GET: (rq, e) => invitePage(rq, e, link[1]) }
    : Object.hasOwn(ROUTES, url.pathname) ? ROUTES[url.pathname] : null;
  if (!route) return notFound();
  const handle = Object.hasOwn(route, request.method) ? route[request.method] : null;
  if (!handle) return wrongMethod(Object.keys(route));
  if (request.method === "POST" && !sameOrigin(request)) return refused();
  await schema(env.LIST);
  return handle(request, env, ctx, url);
}
