/* account.ranwhat.com: signing in with an emailed code or a password,
 * making an account with a password, resetting one, and the account page
 * behind them. index.js sends every request for this host here, and only
 * once ACCOUNTS_ON is set.
 *
 *   GET  /              The account: who you are, your organisation, its
 *                       plan and what each plan has (features.js), how you
 *                       sign in, what happened lately, and signing out.
 *                       Without a session it sends you to /signin.
 *   GET  /signin        The email form.
 *   POST /signin        Mails a code; the same answer for every address.
 *   GET  /signin/code   The box to type the code in (with a new password,
 *                       for a reset). Never filled in.
 *   POST /signin/code   Checks it, makes the account on first use, sets
 *                       the password a sign-up or a reset chose, and opens
 *                       a new session.
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
  CODE_FOR, CODE_TRIES, FRESH_FOR, SESSION_COOKIE, SIGNIN_COOKIE, SIGNIN_FOR, address, attempt, checkCode,
  clearCookie, current, formOk, formToken, fresh, nextPath, openSession, randomToken, readCookie, requestCode,
  sameOrigin, setCookie,
} from "./session.js";
import {
  LOCKOUT, MIN_LENGTH, attachPassword, checkPassword, detachPassword, hashAllowed, hashPassword, isPasswordHash,
  otherWaysIn, passwordOf, passwordProblem, rehashed, unlock,
} from "./password.js";
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
      ${problem(error)}
      <button type="submit">Email me a code</button>`)}
    <p>Have a password? <a href="/signin/password">Sign in with it</a>.
       Want one? <a href="/signup">Make an account with a password</a></p>
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

/* Where a code page sends someone who wants to start again. */
const startOver = (row) => ({
  stepup: `<a href="/">Back to your account</a>`,
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
    ${verify ? "<p>Your password is set when the code is typed, and not before.</p>" : ""}
    ${reset ? "<p>Type it with the password you want now. Setting it signs your account out everywhere else.</p>" : ""}
    ${form("/signin/code", await formToken(env, token, "code"), `
      <label for="code">Code</label>
      <input id="code" name="code" type="text" autocomplete="one-time-code" autocapitalize="characters"
             spellcheck="false" maxlength="12" required autofocus>
      ${reset ? `<label for="password">New password</label>
      <input id="password" name="password" type="password" autocomplete="new-password" minlength="${MIN_LENGTH}" required>
      ${NEW_PASSWORD}` : ""}
      ${problem(error)}
      <button type="submit">${stepup ? "Confirm" : verify ? "Confirm and sign in" : reset ? "Set password and sign in" : "Sign in"}</button>`)}
    <p>Nothing after a minute? Look in spam, then ask again.</p>
    ${form("/signin/again", await formToken(env, token, "again"), `<button type="submit">Send a new code</button>`, "row")}
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
    ${form("/signin/again", await formToken(env, token, "again"), `<button type="submit">Send a new code</button>`, "row")}
    <p>${startOver(row)}</p>`,
  { status });
}

async function codePost(request, env) {
  const f = await fields(request);
  const token = readCookie(request, SIGNIN_COOKIE);
  if (!await formOk(env, f, token, "code")) return refused();
  const held = await attempt(env, token);
  if (held && held.purpose === "reset") return resetCode(request, env, token, held, f);
  const result = await checkCode(env, token, f.get("code"));
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
   `after(org)` returns, and the browser sent on. The organisation is the
   one the browser was looking at, if it was already this person's. */
async function enter(request, env, { user, next = "/", coded = true, before = [], after }) {
  const was = await current(request, env);
  const org = await orgFor(env, user, was && was.user === user ? was.org.id : null);
  const orgId = org ? org.id : null;
  const { value, statements } = await openSession(env, {
    user, org: orgId, previous: readCookie(request, SESSION_COOKIE), coded,
  });
  await env.LIST.batch([...before, ...statements, ...await after(orgId)]);
  return redirect(nextPath(next), [setCookie(SESSION_COOKIE, value, SESSION_MAX), clearCookie(SIGNIN_COOKIE)]);
}

/* A code was typed: the account (made now if this is its first sign-in), a
   new session in place of whatever the browser had, and the events, in one
   batch. With 'verify', the password this browser chose becomes the
   account's in the same batch: the row is the attempt this browser holds
   and has just typed the code for, so the hash is the one it sent. A code
   also gives the address back its password tries (password.js). */
async function signedIn(request, env, row) {
  const db = env.LIST;
  let user, what;
  let password = null;
  if (row.purpose === "signin" || row.purpose === "verify") {
    if (row.purpose === "verify") {
      if (!isPasswordHash(row.password_hash)) return redirect("/signup", [clearCookie(SIGNIN_COOKIE)]);
      password = row.password_hash;
    }
    const found = await userForVerifiedEmail(env, { email: row.email });
    user = found.id;
    what = found.created ? "signup" : "signin";
  } else if (row.purpose === "stepup") {
    const known = await db.prepare("SELECT id FROM users WHERE id = ?").bind(row.user_id).first();
    if (!known) return redirect("/signin", [clearCookie(SIGNIN_COOKIE)]);
    user = known.id;
    what = "stepup";
  } else {
    /* 'reset' never gets here: codePost sends it to resetCode. */
    return redirect("/signin", [clearCookie(SIGNIN_COOKIE)]);
  }
  return enter(request, env, { user, next: row.next, after: async (org) => [
    event(db, { org, user, what }),
    ...(password ? await attachPassword(env, { user, org, hash: password }) : []),
    await unlock(env, row.email),
  ] });
}

/* A reset code, typed with the new password. The password is judged and
   hashed first, so a refused one costs the attempt nothing; then the code
   is checked as any code is. Once it is right the address is proven, as a
   sign-in code proves it (an address with no account gets one, as /signin
   would give it), and in one batch: every session of the account ends,
   the password is replaced, and this browser gets the one new session. */
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
  const result = await checkCode(env, token, f.get("code"));
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
      await unlock(env, row.email),
    ],
  });
}

async function again(request, env, ctx) {
  const f = await fields(request);
  const token = readCookie(request, SIGNIN_COOKIE);
  if (!await formOk(env, f, token, "again")) return refused();
  const row = await attempt(env, token);
  if (!row) return redirect("/signin");
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
      ${problem(error)}
      <button type="submit">Email me a code</button>`)}
    <p>Rather not have a password? <a href="/signin">Sign in with an emailed code</a>; it makes
       the account too.</p>
    <p><small>The address is used to send the code, and kept only once the code is typed, as
       your account. The password is kept only as a salted hash. To check it against known
       breaches we send Have I Been Pwned the first 5 characters of its SHA-1 hash, never the
       password. <a href="${PRIVACY}">Privacy</a></small></p>`,
  { status, cookies });
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
      <button type="submit">Sign in</button>`)}
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

/* Password sign-in is paused for this address, or for everyone: the code
   still works, one press away. */
async function locked(env, binding, email, next) {
  return page("Use an emailed code", `<h1>Use an emailed code.</h1>
    <p class="bad">There have been too many tries with a password, so password sign-in
       is paused for up to ${LOCKOUT / 60} minutes. An emailed code still works, and
       typing one gives this address its tries back.</p>
    ${form("/signin", await formToken(env, binding, "signin"), `
      <input type="hidden" name="next" value="${escape(next)}">
      <input type="hidden" name="email" value="${escape(email)}">
      <button type="submit">Email a code to ${escape(email)}</button>`)}
    <p><a href="/signin">Use a different email</a></p>`,
  { status: 429 });
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
      ${problem(error)}
      <button type="submit">Email me a code</button>`)}
    <p><a href="/signin/password">Back to signing in</a></p>`,
  { status, cookies });
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
  password_removed: "Password removed",
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

/* How this account can sign in. The emailed code always works. A password
   is added, changed or removed with the current password or a code typed
   in the last 15 minutes (fresh() in session.js); without a password, only
   the code will do. The others are on their way. */
async function methods(env, who, error) {
  const stored = await passwordOf(env, who.user);
  const confirmed = fresh(who);
  const stepupToken = await formToken(env, who.id, "stepup");
  const code = (label) => form("/stepup", stepupToken,
    `<input type="hidden" name="next" value="/"><button type="submit">${label}</button>`, "row");
  const currentField = (id) => (confirmed ? "" : `
      <label for="${id}">Current password</label>
      <input id="${id}" name="current" type="password" autocomplete="current-password" maxlength="4096" required>`);
  const newField = `
      <label for="new-password">New password</label>
      <input id="new-password" name="password" type="password" autocomplete="new-password" minlength="${MIN_LENGTH}" required>
      ${NEW_PASSWORD}`;
  const recent = `<p>You typed an emailed code in the last ${FRESH_FOR / 60} minutes, so your current
       password is not asked for.</p>`;
  let password;
  if (stored) {
    const remove = await otherWaysIn(env, who.user) > 0
      ? form("/password/remove", await formToken(env, who.id, "password-remove"), `${currentField("current-password-remove")}
      <button type="submit">Remove password</button>`)
      : "";
    password = `<li data-method="password"><strong>Password</strong> <span class="tag">set</span>
      <br>Sign in with your email and this password.
      ${problem(error)}
      ${confirmed ? recent : ""}
      ${form("/password", await formToken(env, who.id, "password"), `${currentField("current-password")}${newField}
      <button type="submit">Change password</button>`)}
      <p>Changing it signs this account out everywhere else.</p>
      ${remove}
      ${confirmed ? "" : `<p>Forgot it? Confirm with an emailed code, and it is not asked for.</p>
      ${code("Email me a code")}`}</li>`;
  } else {
    password = `<li data-method="password"><strong>Password</strong> <span class="tag">not set</span>
      <br>Add one to sign in with your email and a password, as well as with a code.
      ${problem(error)}
      ${confirmed
        ? form("/password", await formToken(env, who.id, "password"), `${newField}
      <button type="submit">Add password</button>`)
        : `<p>Adding one needs an emailed code typed in the last ${FRESH_FOR / 60} minutes.</p>
      ${code("Email me a code")}`}</li>`;
  }
  const coming = (key, name, says) => `<li data-method="${key}"><strong>${name}</strong> <span class="tag">coming</span>
      <br>${says}</li>`;
  return `<section class="panel" id="methods">
    <h2>Sign-in methods</h2>
    <ul>
      <li data-method="code"><strong>Emailed code</strong> <span class="tag">always on</span>
      <br>A code mailed to ${escape(who.email)} signs you in, and confirms what needs confirming.</li>
      ${password}
      ${coming("google", "Google", "Sign in with a Google account that has this address.")}
      ${coming("github", "GitHub", "Sign in with a GitHub account that has this address, verified.")}
      ${coming("passkeys", "Passkeys", "Sign in with this device's screen lock or a security key.")}
    </ul></section>`;
}

async function dashboard(env, who, { error = "", passwordError = "", status = 200 } = {}) {
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
    ${await methods(env, who, passwordError)}
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

/* ---------- the password, signed in ---------- */

/* Whether the person may add, change or remove the password now: true when
   a code was typed in the last 15 minutes or the current password is typed
   now, under the same limits as signing in with it; otherwise the page
   that says why not. Without a password, only the code will do. */
async function allowed(request, env, who, stored, typed) {
  if (fresh(who)) return true;
  if (!stored) {
    return dashboard(env, who, { status: 403,
      passwordError: `Adding a password needs an emailed code typed in the last ${FRESH_FOR / 60} minutes.` });
  }
  const result = await checkPassword(request, env, who.email, typed);
  if (result.ok && result.user === who.user) return true;
  const [status, passwordError] = {
    locked: [429, "Too many tries with a password. Confirm with an emailed code instead."],
    network: [429, "More passwords were tried from your network in the last hour than we check. Confirm with an emailed code instead."],
    unavailable: [503, "Passwords are not available just now."],
  }[result.why] || [400, "Your current password is not right."];
  return dashboard(env, who, { status, passwordError });
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
  if (wrong) return dashboard(env, who, { status: 400, passwordError: wrong });
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
  return redirect("/");
}

/* Only while another way in remains, which the emailed code always is. */
async function removePassword(request, env) {
  const who = await current(request, env);
  if (!who) return signedOut(request);
  const f = await fields(request);
  if (!await formOk(env, f, who.id, "password-remove")) return refused();
  const stored = await passwordOf(env, who.user);
  if (!stored) return redirect("/");
  if (await otherWaysIn(env, who.user) < 1) {
    return dashboard(env, who, { status: 400, passwordError: "This password is your only way in, so it stays." });
  }
  const ok = await allowed(request, env, who, stored, f.get("current"));
  if (ok !== true) return ok;
  await env.LIST.batch(detachPassword(env, { user: who.user, org: who.org.id }));
  return redirect("/");
}

/* ---------- the host ---------- */

/* Path: { method: handler }. */
const ROUTES = {
  "/": { GET: home },
  "/signin": { GET: signinPage, POST: signinPost },
  "/signin/code": { GET: codePage, POST: codePost },
  "/signin/again": { POST: again },
  "/signin/password": { GET: passwordPage, POST: passwordPost },
  "/signup": { GET: signupPage, POST: signupPost },
  "/reset": { GET: resetPage, POST: resetPost },
  "/stepup": { POST: stepup },
  "/password": { POST: setPassword },
  "/password/remove": { POST: removePassword },
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
