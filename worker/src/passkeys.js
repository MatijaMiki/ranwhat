/* Passkeys, part two: the challenges, the passkeys rows and the one script
 * on account.ranwhat.com, around the verifier in webauthn.js. The pages
 * and routes are dashboard.js's; this file is what they keep and check.
 *
 * Adding one. Signed in, with an emailed code typed in the last 15
 * minutes (fresh() in session.js). GET /passkeys/new answers the options
 * for navigator.credentials.create(): our rp, the account's user handle
 * (passkey_users, made once), a new challenge, ES256, EdDSA and RS256,
 * a discoverable credential with user verification, no attestation, and
 * the account's passkeys to leave out. The browser's answer is posted to
 * /passkeys with the form's token and the label typed on the page.
 *
 * Signing in. GET /passkeys/challenge, for anyone, so many an hour from
 * one network, answers a challenge and no credential ids: the browser
 * offers whichever passkey for account.ranwhat.com its person picks, and
 * says which by its id and the user handle. The answer is posted to
 * /signin/passkey; the passkey is found by its id, its handle must be its
 * account's, its signature must verify under the stored key, and its
 * counter must have gone up when it counts at all (webauthn.js). The new
 * count is written only if nobody wrote another since it was read, so two
 * answers at once cannot both pass on one count.
 *
 * Challenges. 32 random bytes, kept as their SHA-256 for five minutes and
 * bound to what asked for them: the session adding a passkey, or the
 * __Host-rw_signin cookie of the browser signing in. The challenge comes
 * back inside clientDataJSON; its hash finds the row, which is used in
 * one UPDATE that has to change exactly one row before anything is
 * verified, so a challenge works once, for the one that asked, whether or
 * not what came with it checks out.
 *
 * Stored. passkeys holds the credential id, the COSE public key (which
 * says its own algorithm), the counter, whether it is backed up, the label
 * and when it was added, and the day (only the day) it last signed in.
 * Nothing about the device, the network or the browser.
 */
import { sha256 } from "./auth.js";
import { DAY, HOUR, event, now } from "./accounts.js";
import { bump, network, randomToken } from "./session.js";
import { ALGORITHMS, PasskeyRefused, RP_ID, verifyAssertion, verifyRegistration } from "./webauthn.js";

export const CHALLENGE_FOR = 5 * 60;      // a challenge works this long
export const CHALLENGES_PER_NETWORK = 60; // sign-in challenges one network may ask for an hour
export const OPTIONS_PER_USER = 20;       // registration options one account may ask for an hour
export const MAX_PASSKEYS = 20;           // passkeys on one account
export const MAX_LABEL = 60;
const RP_NAME = "ranwhat";

const TOKEN = /^[A-Za-z0-9_-]{43}$/;       // 32 bytes, base64url, as randomToken() makes them
const CREDENTIAL_ID = /^[A-Za-z0-9_-]{1,1364}$/;  // 1023 bytes at most, base64url

/* ---------- challenges ---------- */

/* A new challenge for `purpose`, bound to `binding`, as base64url. */
async function issue(env, { purpose, binding, user = null }) {
  const t = now();
  const challenge = randomToken();
  await env.LIST.prepare(`INSERT INTO passkey_challenges (id, purpose, binding, user_id, created_at, expires_at)
                          VALUES (?, ?, ?, ?, ?, ?)`)
    .bind(await sha256(challenge), purpose, binding, user, t, t + CHALLENGE_FOR).run();
  return challenge;
}

/* The challenge clientDataJSON says it answers, or null. Read here only to
   find its row: webauthn.js checks the whole of clientDataJSON after. */
function challengeIn(clientDataJSON) {
  if (typeof clientDataJSON !== "string" || clientDataJSON.length > 6000 || !/^[A-Za-z0-9_-]+$/.test(clientDataJSON)) {
    return null;
  }
  try {
    const raw = atob(clientDataJSON.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((clientDataJSON.length + 3) % 4));
    const data = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(Uint8Array.from(raw, (c) => c.charCodeAt(0))));
    return data && typeof data.challenge === "string" && TOKEN.test(data.challenge) ? data.challenge : null;
  } catch {
    return null;
  }
}

/* Uses the challenge clientDataJSON answers, if it is one we issued for
   this purpose and binding (and user), in date and not used yet. The
   challenge, or null. */
async function spend(env, clientDataJSON, { purpose, binding, user = null }) {
  const challenge = challengeIn(clientDataJSON);
  if (!challenge || !binding) return null;
  const t = now();
  const used = await env.LIST.prepare(
    `UPDATE passkey_challenges SET used_at = ?
     WHERE id = ? AND purpose = ? AND binding = ? AND user_id IS ? AND used_at IS NULL AND expires_at > ?`)
    .bind(t, await sha256(challenge), purpose, binding, user, t).run();
  return used.meta.changes === 1 ? challenge : null;
}

/* ---------- the account's handle and passkeys ---------- */

/* The account's WebAuthn user handle, made the first time it is asked for. */
async function handleOf(env, user) {
  const db = env.LIST;
  await db.prepare("INSERT INTO passkey_users (user_id, handle, created_at) VALUES (?, ?, ?) ON CONFLICT(user_id) DO NOTHING")
    .bind(user, randomToken(), now()).run();
  return (await db.prepare("SELECT handle FROM passkey_users WHERE user_id = ?").bind(user).first()).handle;
}

/* An account's passkeys, oldest first. */
export async function passkeysOf(env, user) {
  const { results } = await env.LIST.prepare(
    `SELECT id, label, backed_up, created_at, used_at FROM passkeys
     WHERE user_id = ? ORDER BY created_at, id`).bind(user).all();
  return results;
}

/* What a passkey is called: what was typed, without control or
   formatting characters (a right-to-left override would make it read as
   something else), runs of whitespace made one space, and cut to
   MAX_LABEL characters; "Passkey" when nothing is left. Never refused:
   by the time the label arrives the device has made the passkey. */
export function passkeyLabel(input) {
  const label = String(input ?? "").slice(0, 1000).replace(/\s+/g, " ").replace(/\p{C}/gu, "").replace(/ +/g, " ").trim();
  return [...label].slice(0, MAX_LABEL).join("").trim() || "Passkey";
}

/* The start (00:00 UTC) of the day a time falls in: when a passkey was
   last used, to the day and no finer. */
export const dayOf = (t) => Math.floor(t / DAY) * DAY;

/* ---------- adding one ---------- */

/* The options for navigator.credentials.create(), binary values as
   base64url, for `who` (current() in session.js), or { refused:
   "limit" | "full" }. */
export async function registrationOptions(env, who) {
  if (await bump(env, "passkey-options", who.user, HOUR) > OPTIONS_PER_USER) return { refused: "limit" };
  const mine = await passkeysOf(env, who.user);
  if (mine.length >= MAX_PASSKEYS) return { refused: "full" };
  return {
    rp: { id: RP_ID, name: RP_NAME },
    user: { id: await handleOf(env, who.user), name: who.email, displayName: who.email },
    challenge: await issue(env, { purpose: "register", binding: who.id, user: who.user }),
    pubKeyCredParams: ALGORITHMS.map((alg) => ({ type: "public-key", alg })),
    timeout: CHALLENGE_FOR * 1000,
    authenticatorSelection: { residentKey: "required", requireResidentKey: true, userVerification: "required" },
    attestation: "none",
    excludeCredentials: mine.map((p) => ({ type: "public-key", id: p.id })),
  };
}

/* The passkey the browser made for `who`, from the fields it posted:
   clientDataJSON and attestationObject, base64url. { id } once it is
   stored, or { refused }:
     "expired"  no challenge of this session's, in date and unused;
     "invalid"  what the browser sent did not pass webauthn.js;
     "taken"    that credential is already stored;
     "full"     the account has MAX_PASSKEYS already. */
export async function register(env, who, { clientDataJSON, attestationObject, label }) {
  const db = env.LIST;
  const challenge = await spend(env, clientDataJSON, { purpose: "register", binding: who.id, user: who.user });
  if (!challenge) return { refused: "expired" };
  let made;
  try {
    made = await verifyRegistration({ clientDataJSON, attestationObject, expectedChallenge: challenge });
  } catch (err) {
    if (!(err instanceof PasskeyRefused)) throw err;
    console.log(`passkey registration: ${err.why}`);
    return { refused: "invalid" };
  }
  const t = now();
  const added = await db.prepare(
    `INSERT INTO passkeys (id, user_id, public_key, sign_count, backed_up, label, created_at)
     SELECT ?, ?, ?, ?, ?, ?, ? WHERE (SELECT count(*) FROM passkeys WHERE user_id = ?) < ?
     ON CONFLICT(id) DO NOTHING`)
    .bind(made.credentialId, who.user, made.publicKey, made.signCount, made.backedUp ? 1 : 0, passkeyLabel(label), t,
      who.user, MAX_PASSKEYS).run();
  if (added.meta.changes !== 1) {
    const taken = await db.prepare("SELECT 1 AS yes FROM passkeys WHERE id = ?").bind(made.credentialId).first();
    return { refused: taken ? "taken" : "full" };
  }
  await event(db, { org: who.org.id, user: who.user, what: "passkey_added" }).run();
  return { id: made.credentialId };
}

/* ---------- signing in ---------- */

/* The options for navigator.credentials.get(), for the browser whose
   __Host-rw_signin cookie is `cookie`, or { refused: "network" }. */
export async function signinOptions(request, env, cookie) {
  if (await bump(env, "passkey-challenge", network(request), HOUR) > CHALLENGES_PER_NETWORK) return { refused: "network" };
  return {
    challenge: await issue(env, { purpose: "signin", binding: await sha256(cookie) }),
    rpId: RP_ID,
    timeout: CHALLENGE_FOR * 1000,
    userVerification: "required",
    allowCredentials: [],
  };
}

/* Signs in with the passkey the browser answered with, from the fields it
   posted: id, clientDataJSON, authenticatorData, signature and userHandle,
   base64url. { user } with its count and last day written, or { refused }
   with why, which the page never shows: every way this can fail gets the
   same answer. */
export async function signIn(env, cookie, { id, clientDataJSON, authenticatorData, signature, userHandle }) {
  const db = env.LIST;
  const challenge = await spend(env, clientDataJSON, { purpose: "signin", binding: cookie ? await sha256(cookie) : null });
  if (!challenge) return { refused: "expired" };
  if (typeof id !== "string" || !CREDENTIAL_ID.test(id)) return { refused: "unknown" };
  const row = await db.prepare(
    `SELECT p.id, p.user_id, p.public_key, p.sign_count, h.handle FROM passkeys p
     JOIN users u ON u.id = p.user_id JOIN passkey_users h ON h.user_id = p.user_id WHERE p.id = ?`).bind(id).first();
  if (!row) return { refused: "unknown" };
  /* A discoverable passkey always says whose it is, and it must be this
     account's. */
  if (typeof userHandle !== "string" || !TOKEN.test(userHandle) || userHandle !== row.handle) return { refused: "handle" };
  let used;
  try {
    used = await verifyAssertion({
      clientDataJSON, authenticatorData, signature, publicKey: row.public_key,
      expectedChallenge: challenge, storedSignCount: row.sign_count,
    });
  } catch (err) {
    if (!(err instanceof PasskeyRefused)) throw err;
    console.log(`passkey sign-in: ${err.why}`);
    return { refused: err.why };
  }
  const written = await db.prepare(
    "UPDATE passkeys SET sign_count = ?, backed_up = ?, used_at = ? WHERE id = ? AND sign_count = ?")
    .bind(used.signCount, used.backedUp ? 1 : 0, dayOf(now()), row.id, row.sign_count).run();
  if (written.meta.changes !== 1) return { refused: "counter" };
  return { user: row.user_id };
}

/* ---------- taking one away ---------- */

/* The statements that take one of `user`'s passkeys away, with the event,
   for the caller's batch; nothing when it is not theirs. */
export async function forgetPasskey(env, { user, org, id }) {
  const db = env.LIST;
  const mine = await db.prepare("SELECT 1 AS yes FROM passkeys WHERE id = ? AND user_id = ?").bind(String(id), user).first();
  if (!mine) return [];
  return [
    db.prepare("DELETE FROM passkeys WHERE id = ? AND user_id = ?").bind(String(id), user),
    event(db, { org, user, what: "passkey_removed" }),
  ];
}

/* ---------- the page script ---------- */

/* /passkeys.js, the one script of ours on this host, loaded only by the
   two passkey pages. It finds the page's form[data-passkey], and when the
   form is sent: fetches the options from the form's data-passkey path,
   asks the browser to make or use a passkey with them, writes what the
   browser answers into the form's hidden fields, base64url, and sends the
   form, token and all, as any form here is sent. A browser without
   passkeys is told so, and the rest of the account works without it. */
export const PAGE_SCRIPT = String.raw`"use strict";
(function () {
  var form = document.querySelector("form[data-passkey]");
  if (!form) return;
  var button = form.querySelector("button");
  var problem = form.querySelector(".passkey-problem");
  function say(text) { problem.textContent = text; problem.hidden = false; }
  function bytes(text) {
    var raw = atob(text.replace(/-/g, "+").replace(/_/g, "/"));
    var out = new Uint8Array(raw.length);
    for (var i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
    return out;
  }
  function text(buffer) {
    var b = new Uint8Array(buffer), s = "";
    for (var i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }
  function set(name, value) { form.elements.namedItem(name).value = value; }
  if (!window.PublicKeyCredential || !navigator.credentials) {
    say("This browser cannot use passkeys. Every other way in still works.");
    button.disabled = true;
    return;
  }
  form.addEventListener("submit", function (e) {
    e.preventDefault();
    button.disabled = true;
    problem.hidden = true;
    var creating = form.getAttribute("data-ceremony") === "create";
    fetch(form.getAttribute("data-passkey"), { credentials: "same-origin", headers: { accept: "application/json" } })
      .then(function (res) {
        return res.json().then(function (options) {
          if (!res.ok) throw { said: options.error || "That did not work. Reload the page and try again." };
          options.challenge = bytes(options.challenge);
          if (creating) {
            options.user.id = bytes(options.user.id);
            options.excludeCredentials = options.excludeCredentials.map(function (c) {
              return { type: c.type, id: bytes(c.id) };
            });
            return navigator.credentials.create({ publicKey: options });
          }
          return navigator.credentials.get({ publicKey: options });
        });
      })
      .then(function (credential) {
        var r = credential.response;
        set("clientDataJSON", text(r.clientDataJSON));
        if (creating) {
          set("attestationObject", text(r.attestationObject));
        } else {
          set("id", text(credential.rawId));
          set("authenticatorData", text(r.authenticatorData));
          set("signature", text(r.signature));
          set("userHandle", r.userHandle ? text(r.userHandle) : "");
        }
        form.submit();
      })
      .catch(function (err) {
        button.disabled = false;
        if (err && err.said) say(err.said);
        else if (err && err.name === "InvalidStateError") say("This device already has a passkey for this account.");
        else if (err && err.name === "NotAllowedError") say("Cancelled, or the device did not answer in time. Try again.");
        else say("This browser could not use a passkey just now. Try again.");
      });
  });
})();
`;
