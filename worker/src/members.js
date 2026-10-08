/* Organisations with more than one person in them: inviting someone by
 * email, joining from the invite, the members and their roles, changing a
 * role, removing someone, leaving, handing the organisation to a new
 * owner, and switching between the organisations one belongs to.
 * dashboard.js draws the panel on the account page and routes the forms
 * here; the tables are accounts.js's, made with the rest.
 *
 *   POST /members/invite    An owner or an admin of a Plus or Team
 *                           organisation, with a fresh code: mails one
 *                           address an invite to join as a member.
 *   GET  /invite/<token>    What the invite is for, and Join for whoever
 *   GET  /invite            is signed in as the address it was sent to
 *                           (the second reads the token from the cookie
 *                           the first left, for the way back from signing
 *                           in). Neither ever joins anyone.
 *   POST /invite            Joins, as a member, and uses the invite up.
 *   POST /invites/revoke    An owner or an admin takes a waiting invite
 *                           back.
 *   POST /members/role      The owner makes a member an admin, or an admin
 *                           a member, with a fresh code.
 *   POST /members/remove    The owner removes an admin or a member, an
 *                           admin removes a member, with a fresh code.
 *   POST /members/leave     Anyone but the owner leaves.
 *   POST /members/transfer  The owner, with a fresh code, makes one of the
 *                           organisation's admins its owner, and stays in
 *                           it as an admin. Asked twice: the first answer
 *                           is the page that says what it does.
 *   POST /org/switch        Looks at another of one's organisations.
 *
 * Who may. Inviting is Plus and Team only (FEATURES.members): a Free
 * organisation sees the panel locked, with the way to upgrade, and
 * invites from it would be a way to send anyone mail from ranwhat. Members
 * are not counted or charged for: one price however many people. Joining
 * needs the organisation to have the feature still. Removing, leaving,
 * roles and ownership work on any plan, so an organisation whose Plus
 * ended can still tidy itself up. One organisation has exactly one owner
 * (the one_owner index), who can neither leave nor be removed nor demoted:
 * ownership is handed on first, and only to an admin.
 *
 * Every form names the organisation it was drawn for, and its token is
 * bound to that organisation, so a form left open in one tab cannot act on
 * another organisation switched to in a second. Every person, invite and
 * role it names is looked up again in that organisation, the role of
 * whoever sent it read again too, and each statement that changes
 * something holds the same conditions inside its batch, so two forms sent
 * at once cannot together do what neither may alone.
 *
 * Invites. 256 random bits in the link, kept as their SHA-256, never
 * themselves; good once, for seven days, and only for someone signed in
 * as the address it was sent to: the account's own address, which a code
 * typed from that inbox, or Google as its authority, proved (accounts.js's
 * userForVerifiedEmail()). A link in someone else's hands opens nothing.
 * The address is kept while the invite waits, and cleared once it is
 * used or taken back (the cron clears an expired one's). Invite emails
 * have a day of their own ('invite', their part of RESEND_DAILY:
 * INVITE_MAIL_PER_DAY in accounts.js), apart from sign-in codes, and an
 * organisation sends at most INVITES_PER_ORG_DAY a day.
 *
 * An invite is only as good as its sender's role: it joins nobody once
 * whoever sent it is no longer an owner or an admin of the organisation
 * (acceptPost() checks it in the batch that joins), and leaving, being
 * removed and being made a member take back, in the same batch, every
 * invite the person sent that is still waiting, so that nobody can leave
 * a way back in for themselves before they go.
 *
 * Leaving and being removed revoke, in the same batch, every terminal the
 * person linked to that organisation (machines.js): a laptop that leaves
 * with them stops reading the feed. CI tokens they made are the
 * organisation's and stay, listed under Machines for an owner or an admin
 * to revoke. Someone left with no organisation at all gets a new personal
 * one in that batch, as at their first sign-in. Whoever stops being an
 * owner or an admin, by any of these or by handing on ownership, leaves
 * the organisation's billing email in Stripe to be checked in that batch
 * too (billing.js's billingEmailDue()): it goes back to the owner's
 * address unless it is the address of someone still an owner or an admin,
 * after the response and, while Stripe fails, from the cron
 * (billingEmailFollows()).
 *
 * Everything is written to the audit log in the batch that does it: for
 * whoever did it, and, when it was done to someone else, for them too.
 */
import { plan, schema as feedSchema, sha256 } from "./auth.js";
import { REPLY_TO, escape, mail, resend } from "./list.js";
import { FEATURES, PLAN_NAMES, allows } from "./features.js";
import {
  ACCOUNT_HOST, ACCOUNT_ORIGIN, DAY, HOUR, SWITCHES_PER_DAY, canManage, event, joinedAt, now, seenAddress, spendAuthMail,
} from "./accounts.js";
import {
  ACCOUNT_FROM, FRESH_FOR, SESSION_COOKIE, address, bump, clearCookie, countWithin, current, formOk, formToken, fresh,
  nextPath, orgFormOk, randomToken, readCookie, setCookie, unbump,
} from "./session.js";
import { fields, form, page, redirect, refused } from "./ui.js";
import { billingEmailDue, billingEmailFollows } from "./billing.js";

export const INVITE_COOKIE = "__Host-rw_invite";
export const INVITE_FOR = 7 * DAY;          // an invite works this long
export const INVITES_PER_ORG_DAY = 20;      // invites one organisation sends a day
const INVITE_COOKIE_FOR = HOUR;             // long enough to sign in and come back
const MAX_LISTED = 200;                     // members, and waiting invites, the panel lists
const MAX_ORGS = 50;                        // organisations the switcher lists
const SHOWN_ACTIVITY = 10;

const ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const TOKEN = /^[A-Za-z0-9_-]{43}$/;        // 32 random bytes, base64url

const ROLES = Object.freeze({ owner: "Owner", admin: "Admin", member: "Member" });
const BY_ROLE = "CASE m.role WHEN 'owner' THEN 0 WHEN 'admin' THEN 1 ELSE 2 END";

/* For dashboard.js's list of what happened, in one person's own words. */
export const MEMBER_EVENTS = Object.freeze({
  member_invited: "Invited someone to the organisation, with a fresh code",
  invite_revoked: "Took an invite back",
  invite_accepted: "Joined an organisation from an invite",
  member_made_admin: "Made a member an admin, with a fresh code",
  member_made_member: "Made an admin a member, with a fresh code",
  role_now_admin: "Made an admin of an organisation",
  role_now_member: "Made a member of an organisation, no longer an admin",
  member_removed: "Removed someone from the organisation, with a fresh code",
  removed_from_org: "Removed from an organisation",
  org_left: "Left an organisation",
  machine_left_org: "Terminal revoked, as whoever linked it left the organisation",
  invite_left_org: "Invite taken back, as whoever sent it is no longer an owner or admin of the organisation",
  ownership_transferred: "Made an admin the owner of the organisation, with a fresh code",
  ownership_received: "Made the owner of an organisation",
  org_switched: "Switched organisation",
});

/* The organisation's own record of who came, went and changed role, shown
   to its owner and admins: whoever did it first, whoever it was done to
   second, both read from users as the page is drawn, and each shown as a
   former member to a viewer who joined after they left
   (accounts.js's seenAddress()). */
const ORG_ACTIVITY = Object.freeze({
  member_invited: (a) => `${a} invited someone`,
  invite_revoked: (a) => `${a} took an invite back`,
  invite_accepted: (a) => `${a} joined`,
  member_made_admin: (a, t) => `${a} made ${t} an admin`,
  member_made_member: (a, t) => `${a} made ${t} a member`,
  member_removed: (a, t) => `${a} removed ${t}`,
  org_left: (a) => `${a} left`,
  ownership_transferred: (a, t) => `${a} made ${t} the owner`,
});

const day = (t) => new Date(t * 1000).toISOString().slice(0, 10);
const when = (t) => `${new Date(t * 1000).toISOString().slice(0, 16).replace("T", " ")} UTC`;
const problem = (text) => (text ? `<p class="bad">${escape(text)}</p>` : "");
const back = `<p><a href="/">Your account</a></p>`;
const backToMembers = `<p><a href="/members">Back to Members</a></p>`;
const codeAge = `${FRESH_FOR / 60} minutes`;

/* Whom someone in `role` may remove: the owner anyone but themselves, an
   admin the members. */
const REMOVABLE = Object.freeze({ owner: ["admin", "member"], admin: ["member"], member: [] });
export const mayRemove = (role, target) => Object.hasOwn(REMOVABLE, role) && REMOVABLE[role].includes(target);

/* ---------- reading ---------- */

/* The organisation's people, the owner first, then admins, then members. */
export async function membersOf(env, orgId) {
  const { results } = await env.LIST.prepare(
    `SELECT m.user_id, m.role, m.created_at, u.email FROM memberships m JOIN users u ON u.id = m.user_id
     WHERE m.org_id = ? ORDER BY ${BY_ROLE}, m.created_at, u.email LIMIT ?`).bind(orgId, MAX_LISTED).all();
  return results;
}

/* The person a form names, only if they are in this organisation: null
   otherwise, the same for someone in another organisation as for nobody. */
async function memberIn(env, orgId, userId) {
  if (typeof userId !== "string" || !ID.test(userId)) return null;
  return env.LIST.prepare(
    `SELECT m.user_id, m.role, u.email FROM memberships m JOIN users u ON u.id = m.user_id
     WHERE m.org_id = ? AND m.user_id = ?`).bind(orgId, userId).first();
}

const WAITING = "accepted_at IS NULL AND revoked_at IS NULL AND expires_at > ?";

async function waitingInvites(env, orgId) {
  const { results } = await env.LIST.prepare(
    `SELECT id, email, created_at, expires_at FROM invites WHERE org_id = ? AND ${WAITING}
     ORDER BY created_at DESC, id LIMIT ?`).bind(orgId, now(), MAX_LISTED).all();
  return results;
}

/* Every organisation `userId` is in, with their role in each. */
export async function orgsOf(env, userId) {
  const { results } = await env.LIST.prepare(
    `SELECT o.id, o.name, m.role FROM memberships m JOIN orgs o ON o.id = m.org_id
     WHERE m.user_id = ? ORDER BY ${BY_ROLE}, o.name, o.id LIMIT ?`).bind(userId, MAX_ORGS).all();
  return results;
}

/* Whether whoever sent the invite (the row `invites`, or as aliased) is
   an owner or an admin of its organisation still: an invite from anyone
   else joins nobody. */
const SENDER_MANAGES = (i = "invites") => `EXISTS (SELECT 1 FROM memberships s
  WHERE s.org_id = ${i}.org_id AND s.user_id = ${i}.invited_by AND s.role IN ('owner', 'admin'))`;

/* The invite a link's token is for, in whatever state, with its
   organisation's name, the address of whoever sent it and whether they
   may still invite; null for a token that is no invite's. */
async function inviteBy(env, token) {
  if (typeof token !== "string" || !TOKEN.test(token)) return null;
  return env.LIST.prepare(
    `SELECT i.id, i.org_id, i.email, i.expires_at, i.accepted_at, i.revoked_at, o.name AS org_name,
            u.email AS by_email, ${SENDER_MANAGES("i")} AS by_manager
     FROM invites i JOIN orgs o ON o.id = i.org_id LEFT JOIN users u ON u.id = i.invited_by
     WHERE i.token_hash = ?`).bind(await sha256(token)).first();
}

async function orgActivity(env, orgId, since) {
  const kinds = Object.keys(ORG_ACTIVITY);
  const { results } = await env.LIST.prepare(
    `SELECT e.event, e.at, ${seenAddress("e.user_id", "a.email")} AS actor,
            ${seenAddress("e.subject", "s.email")} AS subject FROM auth_events e
     LEFT JOIN users a ON a.id = e.user_id LEFT JOIN users s ON s.id = e.subject
     WHERE e.org_id = ? AND e.event IN (${kinds.map(() => "?").join(", ")})
     ORDER BY e.at DESC, e.id DESC LIMIT ?`)
    .bind(orgId, orgId, since, orgId, orgId, since, orgId, ...kinds, SHOWN_ACTIVITY).all();
  return results;
}

/* ---------- the panel on the account page ---------- */

/* The organisation switcher, for someone in more than one: nothing for
   anyone else. next: where to go once switched (the account page it is
   on, or the page that approves a terminal, device.js). compact: the
   sidebar's, a select and a small button on one line. */
export async function switcher(env, who, next = "/", { compact = false } = {}) {
  const orgs = await orgsOf(env, who.user);
  if (orgs.length < 2) return "";
  const options = orgs.map((o) => `<option value="${escape(o.id)}"${o.id === who.org.id ? " selected" : ""}>` +
    `${escape(o.name)} (${ROLES[o.role].toLowerCase()})</option>`).join("");
  const choose = `<select id="org-switch" name="org">${options}</select>
      <button type="submit"${compact ? ' class="compact"' : ""}>Switch</button>`;
  return form("/org/switch", await formToken(env, who.id, "org-switch"), `
      <input type="hidden" name="next" value="${escape(nextPath(next))}">
      <label for="org-switch">Your organisations</label>
      ${compact ? `<span class="switch-row">${choose}</span>` : choose}`, compact ? "switch" : "");
}

/* Members: locked, with the way up, for a Free organisation that has only
   its owner in it; otherwise everyone in it with their role and the day
   they joined, the forms whoever is looking may use, the invites waiting
   and the invite form for an owner or an admin (the step-up for one
   without a fresh code), Leave for anyone but the owner, and the
   organisation's own record for its owner and admins. */
export async function membersPanel(env, who, onPlan, error = "") {
  const org = who.org;
  const name = escape(org.name);
  const feature = FEATURES.members;
  const needs = PLAN_NAMES[feature.plan];
  const open = allows(onPlan, "members");
  const manager = canManage(org);
  const owner = org.role === "owner";
  const confirmed = fresh(who);
  const people = await membersOf(env, org.id);
  const invites = manager ? await waitingInvites(env, org.id) : [];
  const upgrade = manager ? `<p><a href="/upgrade">Upgrade to ${needs}</a></p>`
    : `<p>An owner or an admin of ${name} can upgrade it.</p>`;
  if (!open && people.length <= 1 && !invites.length) {
    return `<section class="panel locked" id="members" data-feature="members">
    <h2>${escape(feature.name)} <span class="tag">locked, needs ${needs}</span></h2>
    <p>Invite your team: in ${needs}, one price however many people.</p>
    ${upgrade}
    ${problem(error)}</section>`;
  }

  const orgField = `<input type="hidden" name="org" value="${escape(org.id)}">`;
  const roleToken = owner && confirmed ? await formToken(env, who.id, `member-role:${org.id}`) : null;
  const transferToken = owner && confirmed ? await formToken(env, who.id, `member-transfer:${org.id}`) : null;
  const removeToken = manager && confirmed ? await formToken(env, who.id, `member-remove:${org.id}`) : null;
  const items = people.map((p) => {
    const me = p.user_id === who.user;
    const uid = escape(p.user_id);
    const target = `<input type="hidden" name="user" value="${uid}">${orgField}`;
    const forms = [];
    if (!me && roleToken && p.role !== "owner") {
      const other = p.role === "admin" ? "member" : "admin";
      forms.push(form("/members/role", roleToken, `${target}
          <input type="hidden" name="role" value="${other}">
          <button type="submit">Make ${other === "admin" ? "an admin" : "a member"}</button>`, "row"));
      if (p.role === "admin") {
        forms.push(form("/members/transfer", transferToken, `${target}
          <button type="submit">Make the owner</button>`, "row"));
      }
    }
    if (!me && removeToken && mayRemove(org.role, p.role)) {
      forms.push(form("/members/remove", removeToken, `${target}
          <button type="submit">Remove</button>`, "row"));
    }
    return `<li data-member="${uid}"><strong>${escape(p.email)}</strong> <span class="tag">${ROLES[p.role]}${me ? ", you" : ""}</span>
        <br>Joined ${day(p.created_at)}.${forms.length ? `<br>${forms.join("")}` : ""}</li>`;
  }).join("");

  let pending = "";
  if (invites.length) {
    const revokeToken = await formToken(env, who.id, `invite-revoke:${org.id}`);
    pending = `<p><strong>Invites waiting</strong></p>
    <ul>${invites.map((i) => `<li data-invite="${escape(i.id)}">${escape(i.email)}, sent ${day(i.created_at)}, works until ${day(i.expires_at)}
        ${form("/invites/revoke", revokeToken, `
          <input type="hidden" name="invite" value="${escape(i.id)}">${orgField}
          <button type="submit">Take back</button>`, "row")}</li>`).join("")}</ul>`;
  }

  /* What needs a fresh code, and the way to one, for an owner or an admin
     without: on any plan, as removing and roles work on any. */
  const stepup = manager && !confirmed && (open || people.length > 1)
    ? `<p>${open ? "Inviting someone, changing a role" : "Changing a role"} or removing someone needs an emailed
       code typed in the last ${codeAge}.</p>
    ${form("/stepup", await formToken(env, who.id, "stepup"),
      `<input type="hidden" name="next" value="/members"><button type="submit">Email me a code</button>`)}`
    : "";

  let invite = "";
  if (!manager) {
    invite = `<p>An owner or an admin of ${name} can invite people.</p>`;
  } else if (!open) {
    invite = `<p>Inviting people needs ${needs}: one price however many people.</p>${upgrade}`;
  } else if (confirmed) {
    invite = form("/members/invite", await formToken(env, who.id, `member-invite:${org.id}`), `${orgField}
      <label for="invite-email">Invite someone by email</label>
      <input id="invite-email" name="email" type="email" maxlength="200" required autocomplete="off">
      <button type="submit">Send invite</button>`) +
      `<p><small>They join as a member, signed in as that address. The link works once, for
       ${INVITE_FOR / DAY} days.</small></p>`;
  }

  let leave = "";
  if (!owner) {
    leave = form("/members/leave", await formToken(env, who.id, `member-leave:${org.id}`), `${orgField}
      <button type="submit">Leave ${name}</button>`) +
      `<p><small>Leaving revokes the terminals you linked to ${name}.${org.role === "admin"
        ? ` CI tokens you made are ${name}'s, and keep working until an owner or an admin revokes them.` : ""}</small></p>`;
  } else if (people.length > 1) {
    leave = `<p><small>As its owner you cannot leave ${name}: make one of its admins the owner first.</small></p>`;
  }

  let record = "";
  if (manager) {
    const someone = "a former member";
    const done = await orgActivity(env, org.id, await joinedAt(env, org.id, who.user));
    if (done.length) {
      record = `<p><strong>Who came, went and changed role</strong></p>
    <ul>${done.map((e) => `<li>${escape(when(e.at))}: ${ORG_ACTIVITY[e.event](escape(e.actor || someone),
        escape(e.subject || someone))}</li>`).join("")}</ul>`;
    }
  }

  return `<section class="panel" id="members" data-feature="members">
    <h2>${escape(feature.name)}</h2>
    <ul>${items}</ul>
    ${manager && people.length > 1 ? `<p><small>Removing someone revokes the terminals they linked to ${name}.
       CI tokens they made stay, under Machines, until revoked there.</small></p>` : ""}
    ${problem(error)}
    ${pending}
    ${stepup}
    ${invite}
    ${leave}
    ${record}</section>`;
}

/* ---------- answering the forms ---------- */

const signedOut = (request) =>
  redirect("/signin", readCookie(request, SESSION_COOKIE) ? [clearCookie(SESSION_COOKIE)] : []);

/* Why a members form did nothing, with the way to a fresh code when that
   is what it needed. */
async function trouble(env, who, status, text, { stepup = false } = {}) {
  return page("Members", `<h1>Members</h1>
    ${problem(text)}
    ${stepup ? form("/stepup", await formToken(env, who.id, "stepup"), `
      <input type="hidden" name="next" value="/members">
      <button type="submit">Email me a code</button>`) : ""}
    ${backToMembers}`, { status });
}

const needsCode = (env, who, what) =>
  trouble(env, who, 403, `${what} needs an emailed code typed in the last ${codeAge}, so nothing was done.`,
    { stepup: true });

/* The signed-in person and the form, once its token is right for `action`
   in the organisation it names, and that is the organisation this session
   is looking at: { who, f }, or { response } to send back instead. */
async function posted(request, env, action) {
  const who = await current(request, env);
  if (!who) return { response: signedOut(request) };
  const f = await fields(request);
  const bound = await orgFormOk(env, f, who, action);
  if (bound === "refused") return { response: refused() };
  if (bound === "elsewhere") {
    return { response: trouble(env, who, 409,
      "That form was for another of your organisations than the one this page is looking at now, so nothing was done. Reload your account page and try again.") };
  }
  return { who, f };
}

/* A statement that writes an event only while `where` holds, for a batch
   whose other statements hold the same condition. */
const eventIf = (db, { org, user, what, subject = null }, where, binds) =>
  db.prepare(`INSERT INTO auth_events (org_id, user_id, event, subject, at) SELECT ?, ?, ?, ?, ? WHERE ${where}`)
    .bind(org, user, what, subject, now(), ...binds);

const IS = "EXISTS (SELECT 1 FROM memberships WHERE org_id = ? AND user_id = ? AND role = ?)";
const IS_ONE_OF = (roles) =>
  `EXISTS (SELECT 1 FROM memberships WHERE org_id = ? AND user_id = ? AND role IN (${roles.map(() => "?").join(", ")}))`;

/* A personal organisation for `user`, owned by them, made only if they are
   in none: everyone signed in is always looking at one. */
function keepAnOrg(db, user) {
  const org = crypto.randomUUID();
  const t = now();
  const none = "NOT EXISTS (SELECT 1 FROM memberships WHERE user_id = ?)";
  return [
    db.prepare(`INSERT INTO orgs (id, name, personal, created_at) SELECT ?, 'Personal', 1, ? WHERE ${none}`)
      .bind(org, t, user),
    db.prepare(`INSERT INTO memberships (org_id, user_id, role, created_at) SELECT ?, ?, 'owner', ? WHERE ${none}`)
      .bind(org, user, t, user),
  ];
}

/* The invites `user` sent to `org` that are still waiting, taken back
   (each with an event of their own) while `where` holds, for a batch that
   ends their being an owner or an admin there: two statements. */
function theirInvitesBack(db, { org, user }, where, w) {
  const t = now();
  const waiting = "org_id = ? AND invited_by = ? AND accepted_at IS NULL AND revoked_at IS NULL AND expires_at > ?";
  return [
    db.prepare(`INSERT INTO auth_events (org_id, user_id, event, subject, at)
                SELECT org_id, invited_by, 'invite_left_org', id, ? FROM invites WHERE ${waiting} AND ${where}`)
      .bind(t, org, user, t, ...w),
    db.prepare(`UPDATE invites SET revoked_at = ?, email = NULL WHERE ${waiting} AND ${where}`)
      .bind(t, org, user, t, ...w),
  ];
}

/* `user`, in `org` as `role`, leaving it or being removed: the events, the
   terminals they linked to it revoked (each with an event of its own), the
   invites they sent that are still waiting taken back, the membership
   ended and, if it was their last, a personal organisation made. guard
   and binds: what must hold of whoever is doing it. Every statement holds
   the same conditions, so either all of it happens or, when the person
   has gone or changed role meanwhile, none. { statements, deleted }:
   deleted is the DELETE's index. Never the owner. */
function departure(db, { org, user, role, events, guard = "1", binds = [] }) {
  const t = now();
  const where = `${IS} AND ${guard}`;
  const w = [org, user, role, ...binds];
  const theirs = "SELECT m.hash FROM machines m WHERE m.org_id = ? AND m.user_id = ? AND m.kind = 'device'";
  const statements = [
    ...events.map((e) => eventIf(db, e, where, w)),
    db.prepare(`INSERT INTO auth_events (org_id, user_id, event, subject, at)
                SELECT m.org_id, m.user_id, 'machine_left_org', m.id, ? FROM machines m JOIN tokens k ON k.hash = m.hash
                WHERE m.org_id = ? AND m.user_id = ? AND m.kind = 'device' AND k.revoked_at IS NULL AND ${where}`)
      .bind(t, org, user, ...w),
    db.prepare(`UPDATE tokens SET revoked_at = ? WHERE revoked_at IS NULL AND hash IN (${theirs}) AND ${where}`)
      .bind(t, org, user, ...w),
    ...theirInvitesBack(db, { org, user }, where, w),
  ];
  const deleted = statements.length;
  statements.push(
    db.prepare(`DELETE FROM memberships WHERE org_id = ? AND user_id = ? AND role = ? AND role != 'owner' AND ${guard}`)
      .bind(org, user, role, ...binds),
    ...keepAnOrg(db, user),
  );
  return { statements, deleted };
}

/* Stripe's billing email for the organisation, checked after the
   response once someone is no longer an owner or an admin of it: the
   batch that changed it left it due (billingEmailDue()), so the cron
   tries again should this fail. */
const billingFollows = (env, ctx, orgId) => {
  ctx.waitUntil(billingEmailFollows(env, orgId).catch((err) => {
    console.log(`billing email: ${err.code || err.name || "error"}`);
  }));
};

/* ---------- inviting ---------- */

/* POST /members/invite. In this order: who may, the plan, the fresh code,
   the address, that it is neither in the organisation nor waiting on an
   invite already, then the organisation's count for the day and the day's
   invite mail, so a refusal for any other reason spends neither. */
export async function invitePost(request, env, ctx) {
  const got = await posted(request, env, "member-invite");
  if (got.response) return got.response;
  const { who, f } = got;
  const org = who.org;
  if (!canManage(org)) {
    return trouble(env, who, 403, `Only an owner or an admin of ${org.name} can invite people, so nobody was invited.`);
  }
  if (!allows(await plan(env, org.id), "members")) {
    return trouble(env, who, 403,
      `Inviting people comes with ${PLAN_NAMES[FEATURES.members.plan]}, so nobody was invited.`);
  }
  if (!fresh(who)) return needsCode(env, who, "Inviting someone");
  const email = address(f.get("email"));
  if (!email) return trouble(env, who, 400, "That email address does not look right, so nobody was invited.");
  const db = env.LIST;
  const t = now();
  const there = await db.prepare(
    "SELECT 1 AS yes FROM memberships m JOIN users u ON u.id = m.user_id WHERE m.org_id = ? AND u.email = ?")
    .bind(org.id, email).first();
  if (there) return trouble(env, who, 409, `${email} is in ${org.name} already.`);
  const waiting = () => trouble(env, who, 409,
    `${email} has an invite to ${org.name} waiting already. Take it back to send a new one.`);
  if (await db.prepare(`SELECT 1 AS yes FROM invites WHERE org_id = ? AND email = ? AND ${WAITING}`)
    .bind(org.id, email, t).first()) return waiting();
  if (await bump(env, "invite-org", org.id, DAY) > INVITES_PER_ORG_DAY) {
    return trouble(env, who, 429,
      `${org.name} has sent ${INVITES_PER_ORG_DAY} invites in the last day, the most it can, so nobody was invited. Try again tomorrow.`);
  }
  if (!await spendAuthMail(env, "invite")) {
    await unbump(env, "invite-org", org.id, DAY);
    return trouble(env, who, 503,
      "We send a limited number of account emails each day, and today's are used up, so nobody was invited. Try again after midnight UTC.");
  }
  const token = randomToken();
  const id = crypto.randomUUID();
  try {
    await db.batch([
      /* An expired invite to the same address gives way, as the cron would
         have made it: its address cleared. */
      db.prepare(`UPDATE invites SET email = NULL WHERE org_id = ? AND email = ? AND accepted_at IS NULL
                  AND revoked_at IS NULL AND expires_at <= ?`).bind(org.id, email, t),
      db.prepare(`INSERT INTO invites (id, org_id, email, role, token_hash, invited_by, created_at, expires_at)
                  VALUES (?, ?, ?, 'member', ?, ?, ?, ?)`)
        .bind(id, org.id, email, await sha256(token), who.user, t, t + INVITE_FOR),
      event(db, { org: org.id, user: who.user, what: "member_invited", subject: id }),
    ]);
  } catch (err) {
    // Another request invited the same address a moment ago (open_invite).
    if (/UNIQUE/i.test(String(err && err.message))) return waiting();
    throw err;
  }
  ctx.waitUntil(mailInvite(env, { to: email, by: who.email, orgName: org.name, token }).catch((err) => {
    console.log(`invite mail: ${err.code || err.name || "error"}`);
  }));
  return redirect("/members");
}

/* The link is the only way in, so it is in the email, and nothing else
   is: the email says who sent it and where it goes, and that it does
   nothing for anyone not signed in as this address. The organisation's
   name is whatever its owner or an admin typed, so it is quoted, on a line
   of its own that says so, and the email says ranwhat sends it on the
   inviter's behalf and that the link to the account host is the only one
   that is ours: it is never read as ranwhat's own words. */
async function mailInvite(env, { to, by, orgName, token }) {
  const link = `${ACCOUNT_ORIGIN}/invite/${token}`;
  const said = `${by} invited you to join an organisation on ranwhat, as a member.`;
  const named = `Its name, as its owner or an admin typed it: "${orgName}"`;
  const behalf = `ranwhat sends this on their behalf, and wrote none of that name. The only link from us is the one below, to ${ACCOUNT_HOST}.`;
  const terms = `The link works once, for ${INVITE_FOR / DAY} days, and only signed in to ${ACCOUNT_HOST} as ${to}. If you have no account yet, a code mailed to this address makes one.`;
  const ignore = `If you do not know ${by}, ignore this email: nothing happens unless you sign in and choose Join.`;
  await resend(env, "POST", "/emails", {
    from: ACCOUNT_FROM,
    to: [to],
    reply_to: REPLY_TO,
    subject: "An invite to an organisation on ranwhat",
    text: [said, "", named, behalf, "", "See the invite, and join:", "", `    ${link}`, "", terms, "", ignore, "", "ranwhat.com"]
      .join("\n"),
    html: mail(`
      <p>${escape(said)}</p>
      <p>${escape(named)}</p>
      <p>${escape(behalf)}</p>
      <p><a href="${escape(link)}" style="color:#b8482d">See the invite, and join</a></p>
      <p>${escape(terms)}</p>
      <p style="color:#5a6672">${escape(ignore)}</p>`),
  });
}

/* ---------- joining ---------- */

/* Why an invite cannot be used, or null while it can. */
function unusable(inv, t = now()) {
  if (!inv) {
    return [404, "That invite link does not work. Check it is the whole link from the email, or ask whoever invited you for a new one."];
  }
  if (inv.accepted_at) return [410, "That invite was used already. Each invite works once."];
  if (inv.revoked_at) return [410, "That invite was taken back. Ask whoever invited you for a new one."];
  if (!inv.by_manager) {
    return [410, "That invite no longer works: whoever sent it can no longer invite people there. Ask an owner or an admin of it for a new one."];
  }
  if (inv.expires_at <= t) {
    return [410, `That invite has expired: each works for ${INVITE_FOR / DAY} days. Ask whoever invited you for a new one.`];
  }
  return null;
}

const gone = ([status, text]) => page("Invite", `<h1>This invite cannot be used.</h1>
  ${problem(text)}${back}`, { status, cookies: [clearCookie(INVITE_COOKIE)] });

const lapsed = (inv) => page("Invite", `<h1>This invite cannot be used just now.</h1>
  ${problem(`${inv.org_name} is not on ${PLAN_NAMES[FEATURES.members.plan]} at the moment, so it cannot take new members. Ask whoever invited you.`)}
  ${back}`, { status: 403 });

const forThem = (who, inv) => who.email.toLowerCase() === String(inv.email || "").toLowerCase();

const acceptAction = (inv) => `invite-accept:${inv.id}`;

/* What an invite is for, from the link's token. Nothing changes here but
   the cookie that brings the browser back after signing in, which holds
   the token and is cleared once it is used: never the database. */
async function invitation(request, env, token) {
  const inv = await inviteBy(env, token);
  const no = unusable(inv);
  if (no) return gone(no);
  if (!allows(await plan(env, inv.org_id), "members")) return lapsed(inv);
  const who = await current(request, env);
  const name = escape(inv.org_name);
  const keep = [setCookie(INVITE_COOKIE, token, INVITE_COOKIE_FOR)];
  const head = `<h1>Join ${name}</h1>
    <p>${inv.by_email ? `<strong>${escape(inv.by_email)}</strong> invited you` : "You were invited"} to join
       <strong>${name}</strong> on ranwhat, as a member.</p>`;
  if (!who) {
    return page("Join an organisation", `${head}
    <p>Sign in with the address this invite was sent to, and you come back here to join. If you have no
       account yet, signing in with a code mailed to that address makes one.</p>
    <p><a class="button" href="/signin?next=/invite">Sign in</a></p>`, { cookies: keep });
  }
  if (!forThem(who, inv)) {
    return page("Join an organisation", `${head}
    ${problem(`This invite was sent to another address than ${who.email}, the one you are signed in with, so it cannot be used here.`)}
    <p>Sign out, sign in with the address it was sent to, then open the link from the email again.</p>
    ${form("/signout", await formToken(env, who.id, "signout"), `<button type="submit">Sign out</button>`)}
    ${back}`, { status: 403, cookies: keep });
  }
  if (await memberIn(env, inv.org_id, who.user)) {
    return page("Join an organisation", `<h1>You are in ${name} already.</h1>
    <p>Switch to it on your account page.</p>${back}`, { cookies: [clearCookie(INVITE_COOKIE)] });
  }
  return page("Join an organisation", `${head}
    <p>Joining shares ${name}'s plan with you. Everyone in ${name} sees your email address and the
       terminals you link to it, with the day each was last used; its owners and admins see when you join,
       leave or change role; and anyone who joins after you leave sees you only as a former member.</p>
    ${form("/invite", await formToken(env, who.id, acceptAction(inv)), `
      <input type="hidden" name="token" value="${escape(token)}">
      <button type="submit">Join ${name}</button>`)}
    <p><a href="/">Not now</a></p>`);
}

/* GET /invite/<token>, from the email. */
export const invitePage = (request, env, token) => invitation(request, env, token);

/* GET /invite: the same page, for the token in the cookie, after signing in. */
export async function inviteAgain(request, env) {
  const token = readCookie(request, INVITE_COOKIE);
  if (!token) {
    return page("Invite", `<h1>Open the link from your invite again.</h1>
      <p>This page shows an invite only when you come to it from the link in the email.</p>${back}`, { status: 404 });
  }
  return invitation(request, env, token);
}

/* POST /invite: joins. Every check the page made is made again, and the
   invite is used, the membership made and the event written in one batch,
   each only while the invite is waiting, for this address, and from
   someone still an owner or an admin of the organisation: two Joins at
   once make one membership, and a used, expired or taken-back invite, or
   one from someone since removed or made a member, makes none. The
   session then looks at the organisation joined. */
export async function acceptPost(request, env) {
  const who = await current(request, env);
  const f = await fields(request);
  const token = f.get("token");
  if (!who) {
    return redirect("/signin?next=/invite", [
      ...(typeof token === "string" && TOKEN.test(token) ? [setCookie(INVITE_COOKIE, token, INVITE_COOKIE_FOR)] : []),
      ...(readCookie(request, SESSION_COOKIE) ? [clearCookie(SESSION_COOKIE)] : []),
    ]);
  }
  const inv = await inviteBy(env, token);
  if (!inv) return gone(unusable(null));
  if (!await formOk(env, f, who.id, acceptAction(inv))) return refused();
  const no = unusable(inv);
  if (no) return gone(no);
  if (!forThem(who, inv)) {
    return page("Join an organisation", `<h1>Not joined.</h1>
    ${problem(`This invite was sent to another address than ${who.email}, the one you are signed in with, so nobody joined.`)}
    ${back}`, { status: 403 });
  }
  if (!allows(await plan(env, inv.org_id), "members")) return lapsed(inv);
  const db = env.LIST;
  const t = now();
  const open = `id = ? AND accepted_at IS NULL AND revoked_at IS NULL AND expires_at > ? AND email = ?
                AND ${SENDER_MANAGES()}`;
  const w = [inv.id, t, who.email];
  const done = await db.batch([
    db.prepare(`INSERT INTO auth_events (org_id, user_id, event, subject, at)
                SELECT org_id, ?, 'invite_accepted', id, ? FROM invites WHERE ${open}`).bind(who.user, t, ...w),
    db.prepare(`INSERT INTO memberships (org_id, user_id, role, created_at)
                SELECT org_id, ?, 'member', ? FROM invites WHERE ${open}
                ON CONFLICT (org_id, user_id) DO NOTHING`).bind(who.user, t, ...w),
    db.prepare(`UPDATE invites SET accepted_at = ?, email = NULL WHERE ${open}`).bind(t, ...w),
  ]);
  if (done[2].meta.changes !== 1) {
    return gone(unusable(await inviteBy(env, token)) || [410, "That invite was used already. Each invite works once."]);
  }
  await db.prepare("UPDATE sessions SET org_id = ? WHERE id = ?").bind(inv.org_id, who.id).run();
  return redirect("/", [clearCookie(INVITE_COOKIE)]);
}

/* POST /invites/revoke: an owner or an admin takes back an invite of this
   organisation that is waiting. */
export async function revokeInvitePost(request, env) {
  const got = await posted(request, env, "invite-revoke");
  if (got.response) return got.response;
  const { who, f } = got;
  const org = who.org;
  if (!canManage(org)) {
    return trouble(env, who, 403, `Only an owner or an admin of ${org.name} can take an invite back, so nothing was done.`);
  }
  const id = f.get("invite");
  const notOurs = () => trouble(env, who, 404,
    `That invite is not one of ${org.name}'s waiting, so nothing was done.`);
  if (typeof id !== "string" || !ID.test(id)) return notOurs();
  const db = env.LIST;
  const t = now();
  const where = `id = ? AND org_id = ? AND accepted_at IS NULL AND revoked_at IS NULL AND ${IS_ONE_OF(["owner", "admin"])}`;
  const w = [id, org.id, org.id, who.user, "owner", "admin"];
  const done = await db.batch([
    db.prepare(`INSERT INTO auth_events (org_id, user_id, event, subject, at)
                SELECT org_id, ?, 'invite_revoked', id, ? FROM invites WHERE ${where}`).bind(who.user, t, ...w),
    db.prepare(`UPDATE invites SET revoked_at = ?, email = NULL WHERE ${where}`).bind(t, ...w),
  ]);
  if (done[1].meta.changes !== 1) return notOurs();
  return redirect("/members");
}

/* ---------- roles, removing, leaving, ownership ---------- */

const notIn = (env, who) => trouble(env, who, 404,
  `That person is not in ${who.org.name}, so nothing was done.`);

/* POST /members/role: the owner, with a fresh code, makes a member an
   admin or an admin a member. Never their own role: the owner stays the
   owner until they hand it on. An admin made a member has the invites
   they sent that are still waiting taken back in the same batch. */
export async function rolePost(request, env, ctx) {
  const got = await posted(request, env, "member-role");
  if (got.response) return got.response;
  const { who, f } = got;
  const org = who.org;
  if (org.role !== "owner") {
    return trouble(env, who, 403, `Only the owner of ${org.name} can change who is an admin, so nothing was done.`);
  }
  if (!fresh(who)) return needsCode(env, who, "Changing a role");
  const target = await memberIn(env, org.id, f.get("user"));
  if (!target) return notIn(env, who);
  if (target.user_id === who.user || target.role === "owner") {
    return trouble(env, who, 400,
      `The owner of ${org.name} stays its owner until they make one of its admins the owner, so nothing was done.`);
  }
  const role = f.get("role");
  if (role !== "admin" && role !== "member") {
    return trouble(env, who, 400, "Choose admin or member, so nothing was done.");
  }
  if (target.role === role) return redirect("/members");
  const db = env.LIST;
  const where = `${IS} AND ${IS}`;
  const w = [org.id, who.user, "owner", org.id, target.user_id, target.role];
  const statements = [
    eventIf(db, { org: org.id, user: who.user, what: `member_made_${role}`, subject: target.user_id }, where, w),
    eventIf(db, { org: org.id, user: target.user_id, what: `role_now_${role}`, subject: who.user }, where, w),
    ...(role === "member" ? theirInvitesBack(db, { org: org.id, user: target.user_id }, where, w) : []),
  ];
  const changed = statements.length;
  statements.push(db.prepare(`UPDATE memberships SET role = ? WHERE org_id = ? AND user_id = ? AND role = ? AND ${IS}`)
    .bind(role, org.id, target.user_id, target.role, org.id, who.user, "owner"));
  if (role === "member") statements.push(billingEmailDue(db, org.id, target.user_id));
  const done = await db.batch(statements);
  if (done[changed].meta.changes !== 1) {
    return trouble(env, who, 409, "Their role changed a moment ago, so nothing was done. Reload your account page.");
  }
  if (role === "member") billingFollows(env, ctx, org.id);
  return redirect("/members");
}

/* POST /members/remove: the owner removes an admin or a member, an admin
   a member, with a fresh code; never the owner, and never oneself (that
   is Leave). The terminals they linked to the organisation are revoked
   with it (departure()). */
export async function removePost(request, env, ctx) {
  const got = await posted(request, env, "member-remove");
  if (got.response) return got.response;
  const { who, f } = got;
  const org = who.org;
  if (!canManage(org)) {
    return trouble(env, who, 403, `Only an owner or an admin of ${org.name} can remove someone, so nothing was done.`);
  }
  if (!fresh(who)) return needsCode(env, who, "Removing someone");
  const target = await memberIn(env, org.id, f.get("user"));
  if (!target) return notIn(env, who);
  if (target.user_id === who.user) {
    return trouble(env, who, 400, `To leave ${org.name}, use Leave on your account page. Nothing was done.`);
  }
  if (!mayRemove(org.role, target.role)) {
    return trouble(env, who, 403, target.role === "owner"
      ? `The owner of ${org.name} cannot be removed, so nothing was done.`
      : `Only the owner of ${org.name} can remove an admin, so nothing was done.`);
  }
  const db = env.LIST;
  await feedSchema(db);
  const by = Object.keys(REMOVABLE).filter((r) => mayRemove(r, target.role));
  const { statements, deleted } = departure(db, {
    org: org.id, user: target.user_id, role: target.role,
    guard: IS_ONE_OF(by), binds: [org.id, who.user, ...by],
    events: [
      { org: org.id, user: who.user, what: "member_removed", subject: target.user_id },
      { org: org.id, user: target.user_id, what: "removed_from_org", subject: who.user },
    ],
  });
  if (target.role === "admin") statements.push(billingEmailDue(db, org.id, target.user_id));
  const done = await db.batch(statements);
  if (done[deleted].meta.changes !== 1) {
    return trouble(env, who, 409, "They left, or their role changed, a moment ago, so nothing was done. Reload your account page.");
  }
  if (target.role === "admin") billingFollows(env, ctx, org.id);
  return redirect("/members");
}

/* POST /members/leave: anyone but the owner leaves the organisation this
   session is looking at, and their terminals linked to it are revoked. No
   fresh code: leaving takes away only one's own access. */
export async function leavePost(request, env, ctx) {
  const got = await posted(request, env, "member-leave");
  if (got.response) return got.response;
  const { who } = got;
  const org = who.org;
  if (org.role === "owner") {
    return trouble(env, who, 403,
      `As the owner of ${org.name} you cannot leave it. Make one of its admins the owner first, then leave.`);
  }
  const db = env.LIST;
  await feedSchema(db);
  const { statements, deleted } = departure(db, {
    org: org.id, user: who.user, role: org.role,
    events: [{ org: org.id, user: who.user, what: "org_left" }],
  });
  if (org.role === "admin") statements.push(billingEmailDue(db, org.id, who.user));
  const done = await db.batch(statements);
  if (done[deleted].meta.changes === 1 && org.role === "admin") billingFollows(env, ctx, org.id);
  return redirect("/");
}

/* POST /members/transfer: the owner, with a fresh code, makes one of the
   organisation's admins its owner and becomes an admin. The first post
   shows what it does; confirm=yes does it. The owner is demoted before
   the admin is promoted (one_owner allows no two), each only while both
   still hold their roles, so the organisation has one owner after it
   whatever else happens at the same time. */
export async function transferPost(request, env, ctx) {
  const got = await posted(request, env, "member-transfer");
  if (got.response) return got.response;
  const { who, f } = got;
  const org = who.org;
  const name = escape(org.name);
  if (org.role !== "owner") {
    return trouble(env, who, 403, `Only the owner of ${org.name} can make someone else its owner, so nothing was done.`);
  }
  if (!fresh(who)) return needsCode(env, who, "Making someone else the owner");
  const target = await memberIn(env, org.id, f.get("user"));
  if (!target) return notIn(env, who);
  if (target.role !== "admin") {
    return trouble(env, who, 400,
      `Only an admin of ${org.name} can be made its owner. Make them an admin first; nothing was done.`);
  }
  if (f.get("confirm") !== "yes") {
    return page("Make them the owner?", `<h1>Make ${escape(target.email)} the owner of ${name}?</h1>
    <p>${escape(target.email)} becomes the owner of ${name}, and you stay in it as an admin. Only the owner
       changes roles and makes someone else the owner, so you cannot undo this yourself. Its plan and
       billing stay with ${name}.</p>
    ${form("/members/transfer", await formToken(env, who.id, `member-transfer:${org.id}`), `
      <input type="hidden" name="user" value="${escape(target.user_id)}">
      <input type="hidden" name="org" value="${escape(org.id)}">
      <input type="hidden" name="confirm" value="yes">
      <button type="submit">Make them the owner</button>`)}
    <p><a href="/members">Keep it as it is</a></p>`);
  }
  const db = env.LIST;
  const where = `${IS} AND ${IS}`;
  const w = [org.id, who.user, "owner", org.id, target.user_id, "admin"];
  const done = await db.batch([
    eventIf(db, { org: org.id, user: who.user, what: "ownership_transferred", subject: target.user_id }, where, w),
    eventIf(db, { org: org.id, user: target.user_id, what: "ownership_received", subject: who.user }, where, w),
    db.prepare(`UPDATE memberships SET role = 'admin' WHERE org_id = ? AND user_id = ? AND role = 'owner' AND ${IS}`)
      .bind(org.id, who.user, org.id, target.user_id, "admin"),
    db.prepare(`UPDATE memberships SET role = 'owner' WHERE org_id = ? AND user_id = ? AND role = 'admin'
                AND NOT EXISTS (SELECT 1 FROM memberships WHERE org_id = ? AND role = 'owner') AND ${IS}`)
      .bind(org.id, target.user_id, org.id, org.id, who.user, "admin"),
    billingEmailDue(db, org.id, who.user),
  ]);
  if (done[3].meta.changes !== 1) {
    return trouble(env, who, 409, "Their role changed a moment ago, so nothing was done. Reload your account page.");
  }
  billingFollows(env, ctx, org.id);
  return redirect("/members");
}

/* ---------- switching ---------- */

/* POST /org/switch: the session looks at another organisation its person
   is in, and goes on to `next`. Switching to the one it looks at already
   writes nothing, and an account switches SWITCHES_PER_DAY times a day at
   most (accounts.js). A switch is counted before it is made, in one
   statement that counts nothing past the day's number (session.js's
   countWithin()), so switches sent at once are held to it too and a
   refused one writes nothing. The session and the event are written only
   while the session still looks at another organisation, so of switches
   sent at once to one organisation, one is made, and the rest write
   nothing and give their count back. */
export async function switchPost(request, env) {
  const who = await current(request, env);
  if (!who) return signedOut(request);
  const f = await fields(request);
  if (!await formOk(env, f, who.id, "org-switch")) return refused();
  const wanted = f.get("org");
  const row = typeof wanted === "string" && wanted.length <= 100 ? await env.LIST.prepare(
    "SELECT org_id FROM memberships WHERE org_id = ? AND user_id = ?").bind(wanted, who.user).first() : null;
  if (!row) return trouble(env, who, 404, "You are not in that organisation, so nothing was changed.");
  if (row.org_id === who.org.id) return redirect(nextPath(f.get("next")));
  if (!await countWithin(env, "switch-user", who.user, DAY, SWITCHES_PER_DAY)) {
    return trouble(env, who, 429,
      `You have switched organisation ${SWITCHES_PER_DAY} times today, the most one account can in a day, so nothing was changed. Try again tomorrow.`);
  }
  const db = env.LIST;
  const lookingElsewhere = "EXISTS (SELECT 1 FROM sessions WHERE id = ? AND org_id IS NOT ?)";
  const done = await db.batch([
    eventIf(db, { org: row.org_id, user: who.user, what: "org_switched" }, lookingElsewhere, [who.id, row.org_id]),
    db.prepare("UPDATE sessions SET org_id = ? WHERE id = ? AND org_id IS NOT ?").bind(row.org_id, who.id, row.org_id),
  ]);
  if (done[1].meta.changes !== 1) await unbump(env, "switch-user", who.user, DAY);
  return redirect(nextPath(f.get("next")));
}
