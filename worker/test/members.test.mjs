/* Organisations with more than one person in them, on account.ranwhat.com
 * (members.js, drawn and routed by dashboard.js): inviting by email,
 * joining from the invite, roles, removing, leaving, ownership, and
 * switching organisation. The Worker's own fetch handler runs over a real
 * SQLite database (node:sqlite, which is what D1 runs), with Resend and
 * Turnstile answered by stand-ins and terminals linked through the real
 * device grant, as in machines.test.mjs.
 *
 *     node --test --test-timeout=60000 worker/test/members.test.mjs
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { d1 } from "./stand-ins.mjs";

const worker = (await import("../src/index.js")).default;
const device = await import("../src/device.js");
const members = await import("../src/members.js");
const { FEATURES, allows } = await import("../src/features.js");
const { FRESH_FOR, formToken, peek } = await import("../src/session.js");
const { AUTH_MAIL_PER_DAY, INVITE_MAIL_PER_DAY, STEPUP_RESERVE } = await import("../src/accounts.js");

const ORIGIN = "https://account.ranwhat.com";
const FEED = "https://feed.ranwhat.com";
const SECRET = "an-account-test-secret-that-is-long-enough-0123456789";
const SESSION = "__Host-rw_session";
const INVITE = "__Host-rw_invite";
const FROM_PAGE = { "sec-fetch-site": "same-origin", origin: ORIGIN };
const GRANT = "urn:ietf:params:oauth:grant-type:device_code";
const DAY = 24 * 3600;
const ctx = { waitUntil() {} };
const LINK = /https:\/\/account\.ranwhat\.com\/invite\/([A-Za-z0-9_-]{43})/;

/* The clock, which a test moves forward when it needs time to pass. */
const realNow = Date.now;
let skew = 0;
Date.now = () => realNow() + skew * 1000;
const later = (seconds) => { skew += seconds; };
const unix = () => Math.floor(Date.now() / 1000);
const isoDay = (t) => new Date(t * 1000).toISOString().slice(0, 10);

const sha = (text) => createHash("sha256").update(text).digest("hex");
/* Made here rather than written out: nothing token-shaped sits in the source. */
const madeToken = () => randomBytes(32).toString("base64url");

/* ---------- stand-ins ---------- */

const solved = (action) => `solved:${action}`;
function services() {
  const s = { emails: [] };
  globalThis.fetch = async (url, init = {}) => {
    const u = new URL(String(url));
    if (u.hostname === "challenges.cloudflare.com") {
      const m = /^solved:([a-z]+)$/.exec(JSON.parse(init.body).response);
      return new Response(JSON.stringify(m ? { success: true, hostname: "account.ranwhat.com", action: m[1] }
        : { success: false }), { status: 200 });
    }
    assert.equal(`${init.method} ${u.hostname}${u.pathname}`, "POST api.resend.com/emails");
    s.emails.push(JSON.parse(init.body));
    return new Response(JSON.stringify({ id: `e${s.emails.length}` }), { status: 200 });
  };
  return s;
}

const env = (extra = {}) => ({
  LIST: d1(), RESEND_API_KEY: "re_" + "test_key", ACCOUNT_SECRET: SECRET, TURNSTILE_SECRET: "turnstile-" + "test",
  ACCOUNTS_ON: "1", ...extra,
});

/* Each browser on a network of its own, so no test meets a network's limits. */
let networks = 0;
const network = () => `198.51.${++networks % 250}.7`;

class Browser {
  constructor(e, { ip = network() } = {}) {
    this.e = e;
    this.ip = ip;
    this.jar = new Map();
  }

  async send(path, { method = "GET", body, headers = {}, origin = ORIGIN } = {}) {
    const h = new Headers({ "cf-connecting-ip": this.ip, ...headers });
    if (this.jar.size) h.set("cookie", [...this.jar].map(([k, v]) => `${k}=${v}`).join("; "));
    const waits = [];
    const res = await worker.fetch(new Request(`${origin}${path}`, {
      method, headers: h, body: body === undefined ? undefined : new URLSearchParams(body).toString(),
    }), this.e, { waitUntil: (p) => waits.push(p) });
    await Promise.all(waits);
    for (const line of res.headers.getSetCookie()) {
      const [pair, ...attributes] = line.split("; ");
      const at = pair.indexOf("=");
      if (attributes.includes("Max-Age=0")) this.jar.delete(pair.slice(0, at));
      else this.jar.set(pair.slice(0, at), pair.slice(at + 1));
    }
    return { status: res.status, location: res.headers.get("location"), headers: res.headers, text: await res.text() };
  }

  get(path) {
    return this.send(path);
  }

  post(path, body, headers = FROM_PAGE) {
    return this.send(path, { method: "POST", body,
      headers: { "content-type": "application/x-www-form-urlencoded", ...headers } });
  }

  get session() {
    return sha(this.jar.get(SESSION));
  }
}

/* Every form on a page that posts to `action`, as its hidden fields. */
function forms(html, action) {
  const re = new RegExp(`<form method="post" action="${action}"[^>]*>([\\s\\S]*?)</form>`, "g");
  return [...html.matchAll(re)].map((m) => Object.fromEntries(
    [...m[1].matchAll(/<input type="hidden" name="([a-z_-]+)" value="([^"]*)">/g)].map((x) => [x[1], x[2]])));
}

const tokenFor = (html, action) => {
  const found = forms(html, action);
  assert.ok(found.length, `no form for ${action}`);
  return found[0].form;
};

/* Sends the account page's form for `action` that `pick` chooses, with `extra`. */
async function submit(b, action, pick = () => true, extra = {}) {
  const home = await b.get("/");
  const found = forms(home.text, action).find(pick);
  assert.ok(found, `no ${action} form`);
  return b.post(action, { ...found, ...extra });
}

const lastTo = (s, email) => s.emails.filter((m) => m.to[0] === email).at(-1);
const codeIn = (mail) => mail.text.match(/^ {4}([0-9A-Z]{4}-[0-9A-Z]{4})$/m)[1];
const inviteFor = (s, email) => {
  const mail = s.emails.filter((m) => m.to[0] === email && LINK.test(m.text)).at(-1);
  return mail ? mail.text.match(LINK)[1] : null;
};

async function typeCode(b, code) {
  const page = await b.get("/signin/code");
  assert.equal(page.status, 200, page.text);
  return b.post("/signin/code", { form: tokenFor(page.text, "/signin/code"), code });
}

/* Signs in with an emailed code, which makes the session fresh. */
async function signIn(b, s, email, next = "/") {
  const form = await b.get(next === "/" ? "/signin" : `/signin?next=${next}`);
  const asked = await b.post("/signin", { form: tokenFor(form.text, "/signin"), email, next,
    "cf-turnstile-response": solved("signin") });
  assert.equal(asked.status, 303, asked.text);
  const done = await typeCode(b, codeIn(lastTo(s, email.toLowerCase())));
  assert.equal(done.status, 303, done.text);
  assert.ok(b.jar.has(SESSION));
  return done;
}

/* A fresh code for a session that is no longer fresh. */
async function confirm(b, s) {
  const home = await b.get("/");
  const asked = await b.post("/stepup", { form: tokenFor(home.text, "/stepup"), next: "/" });
  assert.equal(asked.location, "/signin/code");
  const mail = s.emails.at(-1);
  const back = await typeCode(b, codeIn(mail));
  assert.equal(back.location, "/");
}

const rows = (e, sql, ...p) => e.LIST.sql.prepare(sql).all(...p).map((r) => ({ ...r }));
const one = (e, sql, ...p) => rows(e, sql, ...p)[0];
const run = (e, sql, ...p) => e.LIST.sql.prepare(sql).run(...p);
const tables = (e) => rows(e, "SELECT name FROM sqlite_master WHERE type = 'table'").map((r) => r.name);
const dump = (e) => JSON.stringify(tables(e).map((t) => rows(e, `SELECT * FROM ${t}`)));
const userId = (e, email) => one(e, "SELECT id FROM users WHERE email = ?", email).id;
const ownOrg = (e, email) => one(e,
  "SELECT m.org_id AS id FROM memberships m JOIN users u ON u.id = m.user_id WHERE u.email = ? AND m.role = 'owner'", email).id;
const roleIn = (e, org, email) => {
  const r = one(e, "SELECT m.role FROM memberships m JOIN users u ON u.id = m.user_id WHERE m.org_id = ? AND u.email = ?",
    org, email);
  return r ? r.role : null;
};
const eventsOf = (e, what) => rows(e, "SELECT org_id, user_id, subject FROM auth_events WHERE event = ?", what);
const invitesOf = (e, org) => rows(e, "SELECT * FROM invites WHERE org_id = ? ORDER BY created_at, id", org);

function grant(e, orgId, which = "plus") {
  run(e, "INSERT INTO grants (org_id, plan, starts_at, until, note, created_at) VALUES (?, ?, ?, NULL, 'test', ?)",
    orgId, which, unix() - 60, unix());
}

/* Ana, signed in and fresh, owner of Acme, on Plus unless told otherwise. */
async function acmeOwner(e, s, which = "plus") {
  const ana = new Browser(e);
  await signIn(ana, s, "ana@example.com");
  const acme = ownOrg(e, "ana@example.com");
  run(e, "UPDATE orgs SET name = 'Acme' WHERE id = ?", acme);
  if (which) grant(e, acme, which);
  return { ana, acme };
}

/* `email`, signed in (fresh), put straight into `orgId` as `role` and looking at it. */
async function inOrg(e, s, orgId, email, role = "member") {
  const b = new Browser(e);
  await signIn(b, s, email);
  run(e, "INSERT INTO memberships (org_id, user_id, role, created_at) VALUES (?, ?, ?, ?)",
    orgId, userId(e, email), role, unix());
  run(e, "UPDATE sessions SET org_id = ? WHERE user_id = ?", orgId, userId(e, email));
  return b;
}

const invite = (b, email) => submit(b, "/members/invite", () => true, { email });

/* A form this session could have been shown for `action` in `org`. */
const forged = async (e, b, action, org, fields = {}) =>
  b.post(action, {
    form: await formToken(e, b.session, `${{
      "/members/invite": "member-invite", "/invites/revoke": "invite-revoke", "/members/role": "member-role",
      "/members/remove": "member-remove", "/members/leave": "member-leave", "/members/transfer": "member-transfer",
    }[action]}:${org}`), org, ...fields,
  });

const panel = (html) => {
  const m = html.match(/<section class="panel( locked)?" id="members" data-feature="members">([\s\S]*?)<\/section>/);
  assert.ok(m, "no members panel");
  return { locked: Boolean(m[1]), html: m[2] };
};

/* ---------- the feed host and terminals ---------- */

async function call(e, path, { method = "POST", form, token, ip = "203.0.113.5" } = {}) {
  const h = new Headers({ "cf-connecting-ip": ip });
  if (token) h.set("authorization", `Bearer ${token}`);
  let body;
  if (form) {
    h.set("content-type", "application/x-www-form-urlencoded");
    body = new URLSearchParams(form).toString();
  }
  const res = await worker.fetch(new Request(`${FEED}${path}`, { method, headers: h, body }), e, ctx);
  const text = await res.text();
  let json = null;
  try { json = JSON.parse(text); } catch { /* not JSON */ }
  return { status: res.status, text, json };
}

const feed = (e, token) => call(e, "/v1/catalogue", { method: "GET", token });

/* A terminal linked to the organisation `b`'s (fresh) session is looking at. */
async function linkTerminal(e, b, label = "Laptop") {
  const cli = (await call(e, "/v1/device/code", { form: { client_id: "ranwhat-cli" } })).json;
  const box = await b.get("/device");
  const shown = await b.post("/device", { form: tokenFor(box.text, "/device"), user_code: cli.user_code });
  assert.equal(shown.status, 200, shown.text);
  const done = await b.post("/device/approve", { form: tokenFor(shown.text, "/device/approve"),
    user_code: shown.text.match(/name="user_code" value="([^"]+)"/)[1],
    org: shown.text.match(/name="org" value="([^"]+)"/)[1], label });
  assert.equal(done.status, 200, done.text);
  later(device.INTERVAL);
  const got = await call(e, "/v1/device/token", { form: { client_id: "ranwhat-cli", grant_type: GRANT,
    device_code: cli.device_code } });
  assert.equal(got.status, 200, got.text);
  const token = got.json.access_token;
  return { token, id: one(e, "SELECT id FROM machines WHERE hash = ?", sha(token)).id };
}

/* A CI token made with the account page's form. */
async function makeCi(b, label = "deploy") {
  const home = await b.get("/");
  const r = await b.post("/tokens/ci", { ...forms(home.text, "/tokens/ci")[0], label, expires: "never" });
  assert.equal(r.status, 200, r.text);
  return r.text.match(/<code class="secret">(rw_c_[A-Za-z0-9_-]{43})<\/code>/)[1];
}

const revoked = (e, token) => one(e, "SELECT revoked_at FROM tokens WHERE hash = ?", sha(token)).revoked_at;

/* ---------- the switch and the map ---------- */

test("dark: with ACCOUNTS_ON unset every members path answers 404 as an unknown path does", async () => {
  for (const extra of [{ ACCOUNTS_ON: undefined }, { ACCOUNTS_ON: "" }, { ACCOUNTS_ON: "0" }]) {
    const e = env(extra);
    const unknown = await worker.fetch(new Request(`${ORIGIN}/no-such-path`), e, ctx);
    const expected = [unknown.status, await unknown.text(), [...unknown.headers]];
    assert.equal(expected[0], 404);
    for (const path of ["/members/invite", "/invite", "/invites/revoke", "/members/role", "/members/remove",
                        "/members/leave", "/members/transfer", "/org/switch"]) {
      const r = await worker.fetch(new Request(`${ORIGIN}${path}`, { method: "POST", headers: FROM_PAGE,
        body: "email=x" }), e, ctx);
      assert.deepEqual([r.status, await r.text(), [...r.headers]], expected, path);
    }
    for (const path of ["/invite", `/invite/${madeToken()}`]) {
      const r = await worker.fetch(new Request(`${ORIGIN}${path}`), e, ctx);
      assert.deepEqual([r.status, await r.text(), [...r.headers]], expected, path);
    }
    assert.deepEqual(tables(e), [], "nothing is made in the database while it is off");
  }
});

test("the feature map: members are live and need Plus; Team has them too", () => {
  assert.equal(FEATURES.members.plan, "plus");
  assert.equal(FEATURES.members.status, "live");
  assert.deepEqual(["free", "plus", "team"].map((p) => allows(p, "members")), [false, true, true]);
  assert.equal(members.INVITE_FOR, 7 * DAY);
  assert.equal(members.INVITES_PER_ORG_DAY, 20);
});

/* ---------- Free ---------- */

test("Free: the members panel is locked with the way up, and an invite is refused before any mail", async () => {
  const s = services();
  const e = env();
  const { ana, acme } = await acmeOwner(e, s, null);
  const home = (await ana.get("/")).text;
  const p = panel(home);
  assert.ok(p.locked);
  assert.match(p.html, /locked, needs Plus/);
  assert.match(p.html, /Invite your team: in Plus, one price however many people\./);
  assert.match(p.html, /<a href="\/upgrade">Upgrade to Plus<\/a>/);
  assert.equal(forms(home, "/members/invite").length, 0);
  assert.match(home, /<li data-feature="members"><strong>Members<\/strong> <span class="tag">Needs Plus<\/span>/);

  const mails = s.emails.length;
  const sent = rows(e, "SELECT * FROM mail_counts");
  const r = await forged(e, ana, "/members/invite", acme, { email: "bo@example.com" });
  assert.equal(r.status, 403);
  assert.match(r.text, /Inviting people comes with Plus, so nobody was invited/);
  assert.equal(invitesOf(e, acme).length, 0);
  assert.equal(s.emails.length, mails);
  assert.deepEqual(rows(e, "SELECT * FROM mail_counts"), sent);
  assert.equal(await peek(e, "invite-org", acme, DAY), 0);

  /* A Team grant opens it as Plus does. */
  grant(e, acme, "team");
  assert.ok(!panel((await ana.get("/")).text).locked);
  assert.equal((await invite(ana, "bo@example.com")).status, 303);
  assert.ok(inviteFor(s, "bo@example.com"));
});

/* ---------- inviting and joining ---------- */

test("an invite: mailed with a 256-bit link kept only as its hash; GET shows it, only POST joins, as a member", async () => {
  const lines = [];
  const real = console.log;
  console.log = (...a) => lines.push(a.join(" "));
  try {
    const s = services();
    const e = env();
    const { ana, acme } = await acmeOwner(e, s);
    let home = (await ana.get("/")).text;
    assert.ok(!panel(home).locked);
    assert.match(panel(home).html, /<strong>ana@example\.com<\/strong> <span class="tag">Owner, you<\/span>/);

    let r = await invite(ana, "Bo@Example.com ");
    assert.equal(r.location, "/", r.text);
    const mail = lastTo(s, "bo@example.com");
    assert.equal(mail.from, "ranwhat <account@ranwhat.com>");
    assert.equal(mail.reply_to, "hello@ranwhat.com");
    assert.match(mail.text, /^ana@example\.com invited you to join an organisation on ranwhat, as a member\.\n\nIts name, as its owner or an admin typed it: "Acme"\nranwhat sends this on their behalf/);
    assert.match(mail.text, /works once, for 7 days, and only signed in to account\.ranwhat\.com as bo@example\.com/);
    assert.equal(mail.text.match(/https?:\/\//g).length, 1, "the invite link is the only link in the text");
    const token = inviteFor(s, "bo@example.com");
    assert.equal(Buffer.from(token, "base64url").length, 32, "256 random bits");
    assert.ok(mail.html.includes(`href="https://account.ranwhat.com/invite/${token}"`));

    let [row] = invitesOf(e, acme);
    assert.equal(row.email, "bo@example.com");
    assert.equal(row.role, "member");
    assert.equal(row.token_hash, sha(token));
    assert.equal(row.invited_by, userId(e, "ana@example.com"));
    assert.equal(row.expires_at - row.created_at, 7 * DAY);
    assert.ok(!dump(e).includes(token), "the link's token is nowhere in the database");
    assert.deepEqual(eventsOf(e, "member_invited"), [{ org_id: acme, user_id: userId(e, "ana@example.com"), subject: row.id }]);
    home = (await ana.get("/")).text;
    assert.match(panel(home).html, new RegExp(`<li data-invite="${row.id}">bo@example\\.com, sent ${isoDay(unix())}, works until ${isoDay(unix() + 7 * DAY)}`));

    /* Bo, signed out, opens the link: the organisation, who sent it, and the way to sign in. */
    const bo = new Browser(e);
    r = await bo.get(`/invite/${token}`);
    assert.equal(r.status, 200);
    assert.match(r.text, /<h1>Join Acme<\/h1>/);
    assert.match(r.text, /<strong>ana@example\.com<\/strong> invited you/);
    assert.match(r.text, /href="\/signin\?next=\/invite"/);
    assert.equal(forms(r.text, "/invite").length, 0, "no Join without signing in");
    assert.equal(bo.jar.get(INVITE), token);
    assert.match(r.headers.getSetCookie().join("\n"), /__Host-rw_invite=[^;]+; Max-Age=3600; Path=\/; Secure; HttpOnly; SameSite=Lax/);

    /* Signing in comes back to the invite, whose token stayed in the cookie and never reached `next`. */
    const signedIn = await signIn(bo, s, "bo@example.com", "/invite");
    assert.equal(signedIn.location, "/invite");
    assert.ok(!dump(e).includes(token));
    r = await bo.get("/invite");
    assert.equal(r.status, 200);
    const join = forms(r.text, "/invite");
    assert.equal(join.length, 1);
    assert.equal(join[0].token, token);
    assert.match(r.text, /<button type="submit">Join Acme<\/button>/);
    /* What joining shares, said as it is: every member sees every other's address and terminals. */
    assert.match(r.text, /Everyone in Acme sees your email address and the\s+terminals you link to it/);
    /* GETs, as many as you like, join nobody. */
    assert.equal((await bo.get(`/invite/${token}`)).status, 200);
    assert.equal(roleIn(e, acme, "bo@example.com"), null);
    assert.equal(invitesOf(e, acme)[0].accepted_at, null);

    r = await bo.post("/invite", join[0]);
    assert.equal(r.location, "/", r.text);
    assert.ok(!bo.jar.has(INVITE), "the cookie goes once it is used");
    assert.equal(roleIn(e, acme, "bo@example.com"), "member");
    [row] = invitesOf(e, acme);
    assert.ok(row.accepted_at);
    assert.equal(row.email, null, "the address goes once the invite is used");
    assert.deepEqual(eventsOf(e, "invite_accepted"), [{ org_id: acme, user_id: userId(e, "bo@example.com"), subject: row.id }]);
    const boHome = (await bo.get("/")).text;
    assert.match(boHome, /<dt>Organisation<\/dt><dd>Acme<\/dd>/, "the session looks at the organisation joined");
    assert.match(boHome, /<dt>Your role<\/dt><dd>Member<\/dd>/);
    assert.match(boHome, /<dt>Plan<\/dt><dd id="plan">Plus<\/dd>/);
    assert.match(boHome, /Joined an organisation from an invite/);
    /* As the Join page said: a plain member sees the others' addresses, and the terminals they link. */
    assert.match(panel(boHome).html, /<strong>ana@example\.com<\/strong> <span class="tag">Owner<\/span>/);
    await linkTerminal(e, ana, "Ana laptop");
    assert.match((await bo.get("/")).text, /Ana laptop[\s\S]*?Linked by ana@example\.com on/);

    home = (await ana.get("/")).text;
    assert.match(panel(home).html, /<strong>bo@example\.com<\/strong> <span class="tag">Member<\/span>/);
    assert.match(panel(home).html, /bo@example\.com joined/);
    assert.match(panel(home).html, /ana@example\.com invited someone/);
    assert.doesNotMatch(panel(home).html, /data-invite=/);
    assert.match(home, /Invited someone to the organisation, with a fresh code/);

    /* Used once: the same link, the same form, again, joins nothing more. */
    r = await bo.post("/invite", join[0]);
    assert.equal(r.status, 410);
    assert.match(r.text, /used already/);
    r = await bo.get(`/invite/${token}`);
    assert.equal(r.status, 410);
    const carl = new Browser(e);
    await signIn(carl, s, "carl@example.com");
    assert.equal((await carl.get(`/invite/${token}`)).status, 410);
    assert.equal(rows(e, "SELECT 1 FROM memberships WHERE org_id = ?", acme).length, 2);
    assert.equal(eventsOf(e, "invite_accepted").length, 1);

    for (const line of lines) {
      assert.doesNotMatch(line, /@|rw_/, line);
      assert.ok(!line.includes(token), line);
    }
  } finally {
    console.log = real;
  }
});

test("two Joins at once make one membership and one event", async () => {
  const s = services();
  const e = env();
  const { ana, acme } = await acmeOwner(e, s);
  await invite(ana, "bo@example.com");
  const bo = new Browser(e);
  await signIn(bo, s, "bo@example.com");
  const join = forms((await bo.get(`/invite/${inviteFor(s, "bo@example.com")}`)).text, "/invite")[0];
  const answers = await Promise.all([bo.post("/invite", join), bo.post("/invite", join), bo.post("/invite", join)]);
  assert.deepEqual(answers.map((r) => r.status).sort(), [303, 410, 410]);
  assert.equal(rows(e, "SELECT 1 FROM memberships WHERE org_id = ? AND user_id = ?", acme, userId(e, "bo@example.com")).length, 1);
  assert.equal(eventsOf(e, "invite_accepted").length, 1);
});

test("signed in as another address: the link shows it is someone else's, and a Join is refused", async () => {
  const s = services();
  const e = env();
  const { ana, acme } = await acmeOwner(e, s);
  await invite(ana, "bo@example.com");
  const token = inviteFor(s, "bo@example.com");
  const [{ id }] = invitesOf(e, acme);

  const carl = new Browser(e);
  await signIn(carl, s, "carl@example.com");
  let r = await carl.get(`/invite/${token}`);
  assert.equal(r.status, 403);
  assert.match(r.text, /sent to another address than carl@example\.com/);
  assert.ok(!r.text.includes("bo@example.com"), "the page does not say whose address it was");
  assert.equal(forms(r.text, "/invite").length, 0);
  assert.equal(forms(r.text, "/signout").length, 1);

  /* A Join form of his own, with the right token, still joins nothing. */
  r = await carl.post("/invite", { form: await formToken(e, carl.session, `invite-accept:${id}`), token });
  assert.equal(r.status, 403);
  assert.match(r.text, /so nobody joined/);
  /* Nor does one shown to someone else's session. */
  r = await carl.post("/invite", { form: await formToken(e, sha(madeToken()), `invite-accept:${id}`), token });
  assert.equal(r.status, 403);
  assert.equal(roleIn(e, acme, "carl@example.com"), null);
  assert.equal(invitesOf(e, acme)[0].accepted_at, null, "the invite still waits for Bo");

  /* Bo, signed in however he typed his address, may. */
  const bo = new Browser(e);
  await signIn(bo, s, "BO@Example.COM");
  r = await bo.get(`/invite/${token}`);
  assert.equal(r.status, 200);
  assert.equal((await bo.post("/invite", forms(r.text, "/invite")[0])).status, 303);
  assert.equal(roleIn(e, acme, "bo@example.com"), "member");
});

test("an expired invite joins nobody, and the address can be invited again", async () => {
  const s = services();
  const e = env();
  const { ana, acme } = await acmeOwner(e, s);
  await invite(ana, "bo@example.com");
  const token = inviteFor(s, "bo@example.com");
  const [{ id }] = invitesOf(e, acme);
  const bo = new Browser(e);
  await signIn(bo, s, "bo@example.com");
  const join = forms((await bo.get(`/invite/${token}`)).text, "/invite")[0];

  later(members.INVITE_FOR + 1);
  let r = await bo.get(`/invite/${token}`);
  assert.equal(r.status, 410);
  assert.match(r.text, /has expired/);
  r = await bo.post("/invite", join);
  assert.equal(r.status, 410);
  assert.equal(roleIn(e, acme, "bo@example.com"), null);
  assert.doesNotMatch(panel((await ana.get("/")).text).html, /data-invite=/, "an expired invite is not listed as waiting");

  /* A new one, with a new link; the old one stays dead and its address is cleared. */
  await confirm(ana, s);
  assert.equal((await invite(ana, "bo@example.com")).status, 303);
  const again = inviteFor(s, "bo@example.com");
  assert.notEqual(again, token);
  const [old, fresh] = invitesOf(e, acme);
  assert.equal(old.id, id);
  assert.equal(old.email, null);
  assert.equal(fresh.email, "bo@example.com");
  assert.equal((await bo.get(`/invite/${token}`)).status, 410);
  r = await bo.get(`/invite/${again}`);
  assert.equal((await bo.post("/invite", forms(r.text, "/invite")[0])).status, 303);
  assert.equal(roleIn(e, acme, "bo@example.com"), "member");
});

test("a link that is no invite's, a malformed one, or none: nothing here", async () => {
  const s = services();
  const e = env();
  const { ana } = await acmeOwner(e, s);
  for (const path of [`/invite/${madeToken()}`, "/invite/short", `/invite/${madeToken()}x`, "/invite/%3Cb%3E"]) {
    const r = await ana.get(path);
    assert.equal(r.status, 404, path);
    assert.match(r.text, /That invite link does not work/);
  }
  const r = await ana.get("/invite");
  assert.equal(r.status, 404);
  assert.match(r.text, /Open the link from your invite again/);
  assert.equal((await ana.post(`/invite/${madeToken()}`, {})).status, 405);
  assert.equal((await ana.post("/invite", { token: madeToken(), form: "x" })).status, 404);
});

test("an invite taken back stops working; only an owner or admin of that organisation can take one back", async () => {
  const s = services();
  const e = env();
  const { ana, acme } = await acmeOwner(e, s);
  await invite(ana, "bo@example.com");
  const token = inviteFor(s, "bo@example.com");
  const [{ id }] = invitesOf(e, acme);

  /* A member cannot, even with a form of his own. */
  const carl = await inOrg(e, s, acme, "carl@example.com");
  let r = await forged(e, carl, "/invites/revoke", acme, { invite: id });
  assert.equal(r.status, 403);
  assert.equal(invitesOf(e, acme)[0].revoked_at, null);

  r = await submit(ana, "/invites/revoke", (f) => f.invite === id);
  assert.equal(r.location, "/", r.text);
  const [row] = invitesOf(e, acme);
  assert.ok(row.revoked_at);
  assert.equal(row.email, null);
  assert.deepEqual(eventsOf(e, "invite_revoked"), [{ org_id: acme, user_id: userId(e, "ana@example.com"), subject: id }]);
  assert.doesNotMatch(panel((await ana.get("/")).text).html, /data-invite=/);

  const bo = new Browser(e);
  await signIn(bo, s, "bo@example.com");
  r = await bo.get(`/invite/${token}`);
  assert.equal(r.status, 410);
  assert.match(r.text, /taken back/);
  r = await bo.post("/invite", { form: await formToken(e, bo.session, `invite-accept:${id}`), token });
  assert.equal(r.status, 410);
  assert.equal(roleIn(e, acme, "bo@example.com"), null);

  /* Taken back twice, or an id that never was: nothing to take. */
  for (const invite of [id, randomUUID(), "nope"]) {
    r = await forged(e, ana, "/invites/revoke", acme, { invite });
    assert.equal(r.status, 404, invite);
  }
  assert.equal(eventsOf(e, "invite_revoked").length, 1);
});

test("one invite waiting per address, nobody already in, and an address that is one", async () => {
  const s = services();
  const e = env();
  const { ana, acme } = await acmeOwner(e, s);
  assert.equal((await invite(ana, "bo@example.com")).status, 303);
  for (const [email, status, says] of [
    ["bo@example.com", 409, /has an invite to Acme waiting already/],
    ["BO@example.com", 409, /has an invite to Acme waiting already/],
    ["ana@example.com", 409, /is in Acme already/],
    ["not an address", 400, /does not look right/],
    ["", 400, /does not look right/],
  ]) {
    const r = await invite(ana, email);
    assert.equal(r.status, status, email);
    assert.match(r.text, says);
  }
  assert.equal(invitesOf(e, acme).length, 1);
  assert.equal(s.emails.filter((m) => LINK.test(m.text)).length, 1);
  assert.equal(await peek(e, "invite-org", acme, DAY), 1, "a refused invite spends nothing of the day's");
});

/* ---------- limits ---------- */

test("an organisation sends 20 invites a day; each comes out of the day's invite mail", async () => {
  const s = services();
  const e = env();
  const { ana, acme } = await acmeOwner(e, s);
  assert.ok(members.INVITES_PER_ORG_DAY < INVITE_MAIL_PER_DAY);
  const counted = () => (one(e, "SELECT sent FROM mail_counts WHERE kind = 'invite'") || { sent: 0 }).sent;
  const before = counted();
  for (let i = 0; i < members.INVITES_PER_ORG_DAY; i++) {
    const r = await invite(ana, `person${i}@example.com`);
    assert.equal(r.status, 303, `${i}: ${r.text}`);
  }
  assert.equal(counted() - before, members.INVITES_PER_ORG_DAY);
  let r = await invite(ana, "one-more@example.com");
  assert.equal(r.status, 429);
  assert.match(r.text, /has sent 20 invites in the last day/);
  assert.equal(lastTo(s, "one-more@example.com"), undefined);
  assert.equal(invitesOf(e, acme).length, members.INVITES_PER_ORG_DAY);
  assert.equal(counted() - before, members.INVITES_PER_ORG_DAY);

  /* Another organisation's day is its own. */
  const mallory = new Browser(e);
  await signIn(mallory, s, "mallory@example.com");
  grant(e, ownOrg(e, "mallory@example.com"));
  assert.equal((await invite(mallory, "zed@example.com")).status, 303);

  /* The next day, Acme may again. */
  later(DAY + 1);
  await confirm(ana, s);
  assert.equal((await invite(ana, "one-more@example.com")).status, 303);
});

test("with the day's invite mail used up, nobody is invited and the organisation's count is given back", async () => {
  const s = services();
  const e = env();
  const { ana, acme } = await acmeOwner(e, s);
  run(e, `INSERT INTO mail_counts (day, kind, sent) VALUES (?, 'invite', ?)
          ON CONFLICT (day, kind) DO UPDATE SET sent = excluded.sent`, isoDay(unix()), INVITE_MAIL_PER_DAY);
  const r = await invite(ana, "bo@example.com");
  assert.equal(r.status, 503);
  assert.match(r.text, /today's are used up/);
  assert.equal(invitesOf(e, acme).length, 0);
  assert.equal(lastTo(s, "bo@example.com"), undefined);
  assert.equal(await peek(e, "invite-org", acme, DAY), 0);
});

test("invites and sign-in codes each have their own day: neither can use up the other's", async () => {
  const s = services();
  const e = env();
  const { ana, acme } = await acmeOwner(e, s);
  const sent = (kind) => {
    const row = e.LIST.sql.prepare("SELECT sent FROM mail_counts WHERE day = ? AND kind = ?").get(isoDay(unix()), kind);
    return row ? row.sent : 0;
  };

  /* The public forms have used up the day's sign-in mail: an invite still goes. */
  run(e, `INSERT INTO mail_counts (day, kind, sent) VALUES (?, 'auth', ?)
          ON CONFLICT (day, kind) DO UPDATE SET sent = excluded.sent`, isoDay(unix()), AUTH_MAIL_PER_DAY - STEPUP_RESERVE);
  const authBefore = sent("auth");
  assert.equal((await invite(ana, "bo@example.com")).status, 303);
  assert.ok(lastTo(s, "bo@example.com"));
  assert.equal(sent("invite"), 1);
  assert.equal(sent("auth"), authBefore);

  /* The day's invites used up: someone can still be sent a sign-in code. */
  run(e, `DELETE FROM mail_counts WHERE kind = 'auth'`);
  run(e, `UPDATE mail_counts SET sent = ? WHERE day = ? AND kind = 'invite'`, INVITE_MAIL_PER_DAY, isoDay(unix()));
  assert.equal((await invite(ana, "carl@example.com")).status, 503);
  const stranger = new Browser(e);
  await signIn(stranger, s, "dee@example.com");
  assert.ok(lastTo(s, "dee@example.com"));
  assert.equal(sent("invite"), INVITE_MAIL_PER_DAY);
  assert.equal(sent("auth-stepup"), 0);
});

test("inviting, roles, removing and ownership need a fresh code; nothing is done without one", async () => {
  const s = services();
  const e = env();
  const { ana, acme } = await acmeOwner(e, s);
  const bo = await inOrg(e, s, acme, "bo@example.com", "admin");
  const boId = userId(e, "bo@example.com");
  later(FRESH_FOR + 1);
  const home = (await ana.get("/")).text;
  const p = panel(home).html;
  assert.match(p, /Inviting someone, changing a role or removing someone needs an emailed\s+code typed in the last 15 minutes/);
  assert.equal(forms(p, "/stepup").length, 1);
  for (const action of ["/members/invite", "/members/role", "/members/remove", "/members/transfer"]) {
    assert.equal(forms(home, action).length, 0, action);
  }
  for (const [action, fields] of [["/members/invite", { email: "carl@example.com" }],
                                  ["/members/role", { user: boId, role: "member" }],
                                  ["/members/remove", { user: boId }],
                                  ["/members/transfer", { user: boId, confirm: "yes" }]]) {
    const r = await forged(e, ana, action, acme, fields);
    assert.equal(r.status, 403, action);
    assert.match(r.text, /needs an emailed code typed in the last 15 minutes, so nothing was done/);
    assert.equal(forms(r.text, "/stepup").length, 1);
  }
  assert.equal(invitesOf(e, acme).length, 0);
  assert.equal(roleIn(e, acme, "bo@example.com"), "admin");
  assert.equal(roleIn(e, acme, "ana@example.com"), "owner");

  /* Leaving takes away only one's own access, so it needs none. */
  assert.equal((await submit(bo, "/members/leave")).status, 303);
  assert.equal(roleIn(e, acme, "bo@example.com"), null);

  await confirm(ana, s);
  assert.equal((await invite(ana, "carl@example.com")).status, 303);
});

/* ---------- roles and the owner ---------- */

test("the owner is never left out: cannot leave, be removed or be demoted; ownership goes to an admin, with a fresh code", async () => {
  const s = services();
  const e = env();
  const { ana, acme } = await acmeOwner(e, s);
  const anaId = userId(e, "ana@example.com");
  const bo = await inOrg(e, s, acme, "bo@example.com");
  const boId = userId(e, "bo@example.com");

  let r = await forged(e, ana, "/members/leave", acme);
  assert.equal(r.status, 403);
  assert.match(r.text, /As the owner of Acme you cannot leave it/);
  r = await forged(e, ana, "/members/remove", acme, { user: anaId });
  assert.equal(r.status, 400);
  r = await forged(e, ana, "/members/role", acme, { user: anaId, role: "admin" });
  assert.equal(r.status, 400);
  assert.match(r.text, /stays its owner/);
  r = await forged(e, ana, "/members/role", acme, { user: boId, role: "owner" });
  assert.equal(r.status, 400, "owner is not a role a form gives");
  assert.equal(roleIn(e, acme, "ana@example.com"), "owner");
  const home = (await ana.get("/")).text;
  assert.equal(forms(home, "/members/leave").length, 0);
  assert.match(panel(home).html, /As its owner you cannot leave Acme: make one of its admins the owner first/);

  /* Ownership only to an admin. */
  r = await forged(e, ana, "/members/transfer", acme, { user: boId, confirm: "yes" });
  assert.equal(r.status, 400);
  assert.match(r.text, /Only an admin of Acme can be made its owner/);
  assert.equal(forms(home, "/members/transfer").length, 0);

  r = await submit(ana, "/members/role", (f) => f.user === boId, {});
  assert.equal(r.location, "/", r.text);
  assert.equal(roleIn(e, acme, "bo@example.com"), "admin");
  assert.deepEqual(eventsOf(e, "member_made_admin"), [{ org_id: acme, user_id: anaId, subject: boId }]);
  assert.deepEqual(eventsOf(e, "role_now_admin"), [{ org_id: acme, user_id: boId, subject: anaId }]);

  /* Bo, an admin, can neither remove nor demote the owner, nor take ownership. */
  r = await forged(e, bo, "/members/remove", acme, { user: anaId });
  assert.equal(r.status, 403);
  assert.match(r.text, /The owner of Acme cannot be removed/);
  r = await forged(e, bo, "/members/role", acme, { user: anaId, role: "member" });
  assert.equal(r.status, 403);
  r = await forged(e, bo, "/members/transfer", acme, { user: boId, confirm: "yes" });
  assert.equal(r.status, 403);
  assert.equal(roleIn(e, acme, "ana@example.com"), "owner");

  /* The first post says what it does and does nothing; the second does it. */
  r = await submit(ana, "/members/transfer", (f) => f.user === boId);
  assert.equal(r.status, 200);
  assert.match(r.text, /Make bo@example\.com the owner of Acme\?/);
  assert.equal(roleIn(e, acme, "ana@example.com"), "owner");
  const confirmForm = forms(r.text, "/members/transfer")[0];
  assert.equal(confirmForm.confirm, "yes");
  r = await ana.post("/members/transfer", confirmForm);
  assert.equal(r.location, "/", r.text);
  assert.equal(roleIn(e, acme, "bo@example.com"), "owner");
  assert.equal(roleIn(e, acme, "ana@example.com"), "admin");
  assert.equal(rows(e, "SELECT 1 FROM memberships WHERE org_id = ? AND role = 'owner'", acme).length, 1);
  assert.deepEqual(eventsOf(e, "ownership_transferred"), [{ org_id: acme, user_id: anaId, subject: boId }]);
  assert.deepEqual(eventsOf(e, "ownership_received"), [{ org_id: acme, user_id: boId, subject: anaId }]);
  assert.match((await bo.get("/")).text, /<dt>Your role<\/dt><dd>Owner<\/dd>/);
  assert.match(panel((await bo.get("/")).text).html, /ana@example\.com made bo@example\.com the owner/);

  /* Sent again, it does nothing: Ana is no longer the owner. */
  r = await ana.post("/members/transfer", confirmForm);
  assert.equal(r.status, 403);
  assert.equal(roleIn(e, acme, "bo@example.com"), "owner");

  /* The database itself holds one owner. */
  assert.throws(() => run(e, "UPDATE memberships SET role = 'owner' WHERE org_id = ? AND user_id = ?", acme, anaId),
    /UNIQUE/);

  /* Ana, an admin now, may leave. */
  assert.equal((await submit(ana, "/members/leave")).status, 303);
  assert.equal(roleIn(e, acme, "ana@example.com"), null);
});

test("a member is refused every admin action, and an admin every owner action", async () => {
  const s = services();
  const e = env();
  const { ana, acme } = await acmeOwner(e, s);
  await invite(ana, "zed@example.com");
  const [{ id: zedInvite }] = invitesOf(e, acme);
  const bo = await inOrg(e, s, acme, "bo@example.com");
  await inOrg(e, s, acme, "carl@example.com");
  const dee = await inOrg(e, s, acme, "dee@example.com", "admin");
  const [anaId, boId, carlId, deeId] = ["ana", "bo", "carl", "dee"].map((n) => userId(e, `${n}@example.com`));

  /* A member's panel: everyone, and Leave; nothing else. */
  const html = (await bo.get("/")).text;
  for (const action of ["/members/invite", "/invites/revoke", "/members/role", "/members/remove", "/members/transfer"]) {
    assert.equal(forms(html, action).length, 0, action);
  }
  assert.equal(forms(html, "/members/leave").length, 1);
  assert.match(panel(html).html, /An owner or an admin of Acme can invite people/);
  assert.ok(!html.includes("zed@example.com"), "a member does not see who is invited");
  assert.doesNotMatch(panel(html).html, /invited someone/, "nor the organisation's record");

  const tries = [
    ["/members/invite", { email: "new@example.com" }, /Only an owner or an admin of Acme can invite people/],
    ["/invites/revoke", { invite: zedInvite }, /Only an owner or an admin of Acme can take an invite back/],
    ["/members/role", { user: carlId, role: "admin" }, /Only the owner of Acme can change who is an admin/],
    ["/members/remove", { user: carlId }, /Only an owner or an admin of Acme can remove someone/],
    ["/members/transfer", { user: deeId, confirm: "yes" }, /Only the owner of Acme can make someone else its owner/],
  ];
  for (const [action, fields, says] of tries) {
    const r = await forged(e, bo, action, acme, fields);
    assert.equal(r.status, 403, action);
    assert.match(r.text, says);
  }
  const unchanged = () => {
    assert.deepEqual(rows(e, "SELECT user_id, role FROM memberships WHERE org_id = ? ORDER BY user_id", acme),
      [[anaId, "owner"], [boId, "member"], [carlId, "member"], [deeId, "admin"]]
        .sort((a, b) => (a[0] < b[0] ? -1 : 1)).map(([user_id, role]) => ({ user_id, role })));
  };
  unchanged();
  assert.equal(invitesOf(e, acme).length, 1);
  assert.equal(invitesOf(e, acme)[0].revoked_at, null);

  /* Dee, an admin: invites, and removes a member, but no owner's action, and no other admin. */
  let r = await forged(e, dee, "/members/role", acme, { user: carlId, role: "admin" });
  assert.equal(r.status, 403);
  r = await forged(e, dee, "/members/transfer", acme, { user: deeId, confirm: "yes" });
  assert.equal(r.status, 403);
  const deeHtml = (await dee.get("/")).text;
  assert.equal(forms(deeHtml, "/members/role").length, 0);
  assert.equal(forms(deeHtml, "/members/transfer").length, 0);
  assert.deepEqual(forms(deeHtml, "/members/remove").map((f) => f.user).sort(), [boId, carlId].sort(),
    "an admin is offered Remove for members only");
  unchanged();

  run(e, "UPDATE memberships SET role = 'admin' WHERE org_id = ? AND user_id = ?", acme, boId);
  r = await forged(e, dee, "/members/remove", acme, { user: boId });
  assert.equal(r.status, 403);
  assert.match(r.text, /Only the owner of Acme can remove an admin/);
  assert.equal(roleIn(e, acme, "bo@example.com"), "admin");

  r = await submit(dee, "/members/remove", (f) => f.user === carlId);
  assert.equal(r.location, "/", r.text);
  assert.equal(roleIn(e, acme, "carl@example.com"), null);
  assert.deepEqual(eventsOf(e, "member_removed"), [{ org_id: acme, user_id: deeId, subject: carlId }]);
  assert.deepEqual(eventsOf(e, "removed_from_org"), [{ org_id: acme, user_id: carlId, subject: deeId }]);
  assert.equal((await invite(dee, "erin@example.com")).status, 303);
});

test("ids and forms from another organisation are refused, and change nothing in either", async () => {
  const s = services();
  const e = env();
  const { ana, acme } = await acmeOwner(e, s);
  await inOrg(e, s, acme, "bo@example.com");
  const mallory = new Browser(e);
  await signIn(mallory, s, "mallory@example.com");
  const evil = ownOrg(e, "mallory@example.com");
  grant(e, evil);
  await inOrg(e, s, evil, "max@example.com", "admin");
  await invite(mallory, "zed@example.com");
  const maxId = userId(e, "max@example.com");
  const [{ id: zedInvite }] = invitesOf(e, evil);
  const before = dump(e);

  /* Forms for Acme naming Evil's people or invites: not found in Acme. */
  for (const [action, fields] of [["/members/remove", { user: maxId }],
                                  ["/members/role", { user: maxId, role: "member" }],
                                  ["/members/transfer", { user: maxId, confirm: "yes" }],
                                  ["/invites/revoke", { invite: zedInvite }]]) {
    const r = await forged(e, ana, action, acme, fields);
    assert.equal(r.status, 404, action);
  }
  /* A form drawn for Evil, in Ana's session: Ana is not looking at Evil. */
  for (const [action, fields] of [["/members/remove", { user: maxId }], ["/members/invite", { email: "x@example.com" }],
                                  ["/invites/revoke", { invite: zedInvite }], ["/members/leave", {}]]) {
    const r = await forged(e, ana, action, evil, fields);
    assert.equal(r.status, 409, action);
    assert.match(r.text, /another of your organisations/);
  }
  /* A token for Acme sent naming Evil: not a form this page made. */
  let r = await ana.post("/members/remove", { form: await formToken(e, ana.session, `member-remove:${acme}`),
    org: evil, user: maxId });
  assert.equal(r.status, 403);
  /* Nor can Ana look at Evil. */
  r = await ana.post("/org/switch", { form: await formToken(e, ana.session, "org-switch"), org: evil, next: "/" });
  assert.equal(r.status, 404);
  assert.match((await ana.get("/")).text, /<dt>Organisation<\/dt><dd>Acme<\/dd>/);

  assert.equal(dump(e).replace(/"seen_at":\d+/g, ""), before.replace(/"seen_at":\d+/g, ""));
  const anaHtml = (await ana.get("/")).text;
  assert.ok(!anaHtml.includes("max@example.com") && !anaHtml.includes("zed@example.com"));
  const malloryHtml = (await mallory.get("/")).text;
  assert.ok(!malloryHtml.includes("bo@example.com") && !malloryHtml.includes("ana@example.com"));
});

/* ---------- leaving and being removed ---------- */

test("removed: the member's terminals for that organisation are revoked with them; their own and CI tokens stay", async () => {
  const s = services();
  const e = env();
  const { ana, acme } = await acmeOwner(e, s);
  const bo = await inOrg(e, s, acme, "bo@example.com", "admin");
  const [anaId, boId] = [userId(e, "ana@example.com"), userId(e, "bo@example.com")];
  const bosAcme = await linkTerminal(e, bo, "Bo at Acme");
  const ci = await makeCi(bo, "Bo's pipeline");
  const anas = await linkTerminal(e, ana, "Ana's");

  /* Bo's terminal in his own organisation. */
  const personal = ownOrg(e, "bo@example.com");
  assert.equal((await submit(bo, "/org/switch", () => true, { org: personal })).location, "/");
  const bosOwn = await linkTerminal(e, bo, "Bo at home");
  assert.equal(one(e, "SELECT org_id FROM machines WHERE id = ?", bosOwn.id).org_id, personal);
  for (const token of [bosAcme.token, ci, anas.token]) assert.equal((await feed(e, token)).status, 200);

  let r = await submit(ana, "/members/remove", (f) => f.user === boId);
  assert.equal(r.location, "/", r.text);
  assert.equal(roleIn(e, acme, "bo@example.com"), null);
  assert.ok(revoked(e, bosAcme.token));
  assert.equal((await feed(e, bosAcme.token)).status, 403);
  assert.equal(revoked(e, bosOwn.token), null, "his own organisation's terminal is not Acme's to revoke");
  assert.equal(revoked(e, ci), null);
  assert.equal((await feed(e, ci)).status, 200, "a CI token is the organisation's, and stays");
  assert.equal(revoked(e, anas.token), null);
  assert.deepEqual(eventsOf(e, "member_removed"), [{ org_id: acme, user_id: anaId, subject: boId }]);
  assert.deepEqual(eventsOf(e, "removed_from_org"), [{ org_id: acme, user_id: boId, subject: anaId }]);
  assert.deepEqual(eventsOf(e, "machine_left_org"), [{ org_id: acme, user_id: boId, subject: bosAcme.id }]);
  assert.match(panel((await ana.get("/")).text).html, /ana@example\.com removed bo@example\.com/);

  /* Bo is still signed in, in his own organisation. */
  const home = await bo.get("/");
  assert.equal(home.status, 200);
  assert.match(home.text, /<dt>Organisation<\/dt><dd>Personal<\/dd>/);
  assert.match(home.text, /Removed from an organisation/);

  /* Removed twice: nobody there. */
  r = await forged(e, ana, "/members/remove", acme, { user: boId });
  assert.equal(r.status, 404);
  assert.equal(eventsOf(e, "member_removed").length, 1);
});

test("leaving: the terminals linked to it go too, and a form drawn for another organisation does nothing", async () => {
  const s = services();
  const e = env();
  const { acme } = await acmeOwner(e, s);
  const bo = await inOrg(e, s, acme, "bo@example.com");
  const boId = userId(e, "bo@example.com");
  const terminal = await linkTerminal(e, bo);
  const leave = forms((await bo.get("/")).text, "/members/leave")[0];
  assert.equal(leave.org, acme);

  /* Switched to his own organisation in another tab, the Acme form leaves nothing. */
  const personal = ownOrg(e, "bo@example.com");
  await submit(bo, "/org/switch", () => true, { org: personal });
  let r = await bo.post("/members/leave", leave);
  assert.equal(r.status, 409);
  assert.equal(roleIn(e, acme, "bo@example.com"), "member");

  await submit(bo, "/org/switch", () => true, { org: acme });
  r = await bo.post("/members/leave", leave);
  assert.equal(r.location, "/", r.text);
  assert.equal(roleIn(e, acme, "bo@example.com"), null);
  assert.ok(revoked(e, terminal.token));
  assert.deepEqual(eventsOf(e, "org_left"), [{ org_id: acme, user_id: boId, subject: null }]);
  assert.deepEqual(eventsOf(e, "machine_left_org"), [{ org_id: acme, user_id: boId, subject: terminal.id }]);
  assert.match((await bo.get("/")).text, /<dt>Organisation<\/dt><dd>Personal<\/dd>/);
});

test("someone who left is a former member to whoever joined after, on Machines and in the record; Join and Leave say what stays", async () => {
  const s = services();
  const e = env();
  const { ana, acme } = await acmeOwner(e, s);
  const bob = await inOrg(e, s, acme, "bob@example.com", "admin");
  await makeCi(bob, "bob-made-ci");
  const leaving = (await bob.get("/")).text;
  assert.equal((await submit(bob, "/members/leave")).location, "/");
  later(60);

  /* Ana was there when Bob left: she still sees his address. */
  const anas = (await ana.get("/")).text;
  assert.match(anas, /Made by bob@example\.com on/);
  assert.match(panel(anas).html, /bob@example\.com left/);

  /* Zoe joins after: she never shared Acme with Bob, and sees a former member. */
  const zoe = await inOrg(e, s, acme, "zoe@example.com", "admin");
  const zoes = (await zoe.get("/")).text;
  assert.ok(!zoes.includes("bob@example.com"), "Bob's address is nowhere on Zoe's page");
  assert.match(zoes, /Made by a former member on/);
  assert.match(panel(zoes).html, /a former member left/);
  assert.match(panel(zoes).html, /zoe@example\.com/);

  /* Leaving, an admin was told the CI tokens they made stay. */
  assert.match(leaving, /CI tokens you made are Acme's, and keep working until an owner or an admin revokes them/);

  /* Should Bob come back, he is a member again, and named. */
  run(e, "INSERT INTO memberships (org_id, user_id, role, created_at) VALUES (?, ?, 'member', ?)",
    acme, userId(e, "bob@example.com"), unix());
  assert.match((await zoe.get("/")).text, /Made by bob@example\.com on/);

  /* The Join page says what the organisation keeps of whoever joins. */
  assert.equal((await invite(ana, "carl@example.com")).location, "/");
  const carl = new Browser(e);
  await signIn(carl, s, "carl@example.com");
  const page = (await carl.get(`/invite/${inviteFor(s, "carl@example.com")}`)).text;
  assert.match(page, /its owners and admins see when you join,\s+leave or change role/);
  assert.match(page, /anyone who joins after you leave sees you only as a former member/);
});

test("approving a terminal shows whose organisation it joins and your role there, and warns when it is not your own", async () => {
  const s = services();
  const e = env();
  const mal = new Browser(e);
  await signIn(mal, s, "mal@example.com");
  const theirs = ownOrg(e, "mal@example.com");
  grant(e, theirs);
  /* Ana, invited into Mal's "Personal", is looking at it: the same name as her own. */
  const ana = await inOrg(e, s, theirs, "ana@example.com", "member");
  const mine = ownOrg(e, "ana@example.com");
  assert.equal(one(e, "SELECT name FROM orgs WHERE id = ?", mine).name, one(e, "SELECT name FROM orgs WHERE id = ?", theirs).name);
  const home = (await ana.get("/")).text;
  assert.match(home, /<dt>Owner<\/dt><dd>mal@example\.com<\/dd>/);

  const cli = (await call(e, "/v1/device/code", { form: { client_id: "ranwhat-cli" } })).json;
  const box = await ana.get("/device");
  assert.match(box.text, /linked to <strong>Personal<\/strong>, owned by <strong>mal@example\.com<\/strong>/);
  const shown = await ana.post("/device", { form: tokenFor(box.text, "/device"), user_code: cli.user_code });
  assert.equal(shown.status, 200, shown.text);
  assert.match(shown.text, /<dt>Organisation<\/dt><dd>Personal<\/dd>/);
  assert.match(shown.text, /<dt>Owner<\/dt><dd>mal@example\.com<\/dd>/);
  assert.match(shown.text, /<dt>Your role<\/dt><dd>Member<\/dd>/);
  assert.match(shown.text, /not an organisation of your own/);
  const done = await ana.post("/device/approve", { form: tokenFor(shown.text, "/device/approve"),
    user_code: shown.text.match(/name="user_code" value="([^"]+)"/)[1],
    org: shown.text.match(/name="org" value="([^"]+)"/)[1], label: "Ana work laptop" });
  assert.equal(done.status, 200, done.text);
  assert.match(done.text, /owned by <strong>mal@example\.com<\/strong>/);

  /* Her own: she is its owner, and there is nothing to warn of. */
  await submit(ana, "/org/switch", () => true, { org: mine });
  const own = await ana.post("/device", { form: tokenFor((await ana.get("/device")).text, "/device"),
    user_code: (await call(e, "/v1/device/code", { form: { client_id: "ranwhat-cli" } })).json.user_code });
  assert.equal(own.status, 200, own.text);
  assert.match(own.text, /<dt>Owner<\/dt><dd>You<\/dd>/);
  assert.doesNotMatch(own.text, /not an organisation of your own/);
});

test("an invite email quotes the organisation's name as its admins typed it, and says ranwhat sends it on their behalf", async () => {
  const s = services();
  const e = env();
  const { ana, acme } = await acmeOwner(e, s);
  const name = "ranwhat security. Your access lapses: re-verify at https://evil.example/rw";
  run(e, "UPDATE orgs SET name = ? WHERE id = ?", name, acme);
  assert.equal((await invite(ana, "stranger@victim.example")).location, "/");
  const mail = lastTo(s, "stranger@victim.example");
  const lines = mail.text.split("\n");
  assert.equal(lines[0], "ana@example.com invited you to join an organisation on ranwhat, as a member.");
  assert.ok(lines.includes(`Its name, as its owner or an admin typed it: "${name}"`), mail.text);
  assert.match(mail.text, /ranwhat sends this on their behalf, and wrote none of that name/);
  assert.equal(lines.filter((l) => l.includes(name)).length, 1, "the name appears once, quoted");
  assert.ok(mail.html.includes(`&quot;${name.replace(/&/g, "&amp;")}&quot;`) || mail.html.includes(`“${name}”`), mail.html);
  assert.equal(mail.subject, "An invite to an organisation on ranwhat");
});

test("someone left in no organisation gets a personal one, and stays signed in", async () => {
  const s = services();
  const e = env();
  const { ana, acme } = await acmeOwner(e, s);
  const bo = await inOrg(e, s, acme, "bo@example.com");
  const [anaId, boId] = [userId(e, "ana@example.com"), userId(e, "bo@example.com")];
  const home = ownOrg(e, "bo@example.com");

  /* Bo hands his personal organisation to Ana and leaves it, so Acme is all he has. */
  run(e, "INSERT INTO memberships (org_id, user_id, role, created_at) VALUES (?, ?, 'admin', ?)", home, anaId, unix());
  await submit(bo, "/org/switch", () => true, { org: home });
  let r = await submit(bo, "/members/transfer", (f) => f.user === anaId);
  r = await bo.post("/members/transfer", forms(r.text, "/members/transfer")[0]);
  assert.equal(r.location, "/", r.text);
  assert.equal((await submit(bo, "/members/leave")).location, "/");
  assert.deepEqual(rows(e, "SELECT org_id FROM memberships WHERE user_id = ?", boId), [{ org_id: acme }]);

  r = await submit(ana, "/members/remove", (f) => f.user === boId);
  assert.equal(r.location, "/", r.text);
  const left = rows(e, "SELECT m.org_id, m.role, o.name, o.personal FROM memberships m JOIN orgs o ON o.id = m.org_id WHERE m.user_id = ?", boId);
  assert.equal(left.length, 1);
  assert.ok(![acme, home].includes(left[0].org_id));
  assert.deepEqual({ ...left[0], org_id: undefined }, { org_id: undefined, role: "owner", name: "Personal", personal: 1 });
  const page = await bo.get("/");
  assert.equal(page.status, 200);
  assert.match(page.text, /<dt>Your role<\/dt><dd>Owner<\/dd>/);
});

test("an organisation whose Plus ended takes nobody new, and can still tidy up", async () => {
  const s = services();
  const e = env();
  const { ana, acme } = await acmeOwner(e, s);
  await invite(ana, "bo@example.com");
  const token = inviteFor(s, "bo@example.com");
  const [{ id }] = invitesOf(e, acme);
  await inOrg(e, s, acme, "carl@example.com");
  run(e, "UPDATE grants SET until = ? WHERE org_id = ?", unix() - 1, acme);

  const bo = new Browser(e);
  await signIn(bo, s, "bo@example.com");
  let r = await bo.get(`/invite/${token}`);
  assert.equal(r.status, 403);
  assert.match(r.text, /Acme is not on Plus at the moment/);
  r = await bo.post("/invite", { form: await formToken(e, bo.session, `invite-accept:${id}`), token });
  assert.equal(r.status, 403);
  assert.equal(roleIn(e, acme, "bo@example.com"), null);

  /* The panel still lists who is in it, with Remove; inviting is locked. */
  const html = (await ana.get("/")).text;
  const p = panel(html);
  assert.ok(!p.locked);
  assert.match(p.html, /Inviting people needs Plus/);
  assert.equal(forms(html, "/members/invite").length, 0);
  assert.equal((await forged(e, ana, "/members/invite", acme, { email: "dee@example.com" })).status, 403);
  /* Without a fresh code, the way to one is still offered, for removing and roles. */
  later(FRESH_FOR + 1);
  const stale = (await ana.get("/")).text;
  assert.match(panel(stale).html, /Changing a role or removing someone needs an emailed\s+code/);
  assert.equal(forms(panel(stale).html, "/stepup").length, 1);
  assert.equal(forms(stale, "/members/remove").length, 0);
  await confirm(ana, s);
  r = await submit(ana, "/members/remove", (f) => f.user === userId(e, "carl@example.com"));
  assert.equal(r.location, "/");
  assert.equal((await submit(ana, "/invites/revoke", (f) => f.invite === id)).location, "/");
  /* Alone again, with nothing waiting: locked. */
  assert.ok(panel((await ana.get("/")).text).locked);
});

/* ---------- switching ---------- */

test("someone in several organisations switches between them, on the account page and before approving a terminal", async () => {
  const s = services();
  const e = env();
  const { acme } = await acmeOwner(e, s);
  const bo = await inOrg(e, s, acme, "bo@example.com");
  const boId = userId(e, "bo@example.com");
  const personal = ownOrg(e, "bo@example.com");

  let html = (await bo.get("/")).text;
  const options = [...html.matchAll(/<option value="([^"]+)"( selected)?>([^<]+)<\/option>/g)].map((m) => [m[1], Boolean(m[2]), m[3]]);
  assert.deepEqual(options, [[personal, false, "Personal (owner)"], [acme, true, "Acme (member)"]]);
  let r = await submit(bo, "/org/switch", () => true, { org: personal });
  assert.equal(r.location, "/");
  assert.equal(one(e, "SELECT org_id FROM sessions WHERE id = ?", bo.session).org_id, personal);
  html = (await bo.get("/")).text;
  assert.match(html, /<dt>Organisation<\/dt><dd>Personal<\/dd>/);
  assert.match(html, /Switched organisation/);
  assert.deepEqual(eventsOf(e, "org_switched"), [{ org_id: personal, user_id: boId, subject: null }]);

  /* The terminal page says where a terminal goes, and switches back to itself. */
  const box = (await bo.get("/device")).text;
  const sw = forms(box, "/org/switch");
  assert.equal(sw.length, 1);
  assert.equal(sw[0].next, "/device");
  r = await bo.post("/org/switch", { ...sw[0], org: acme });
  assert.equal(r.location, "/device");
  assert.match((await bo.get("/device")).text, /linked to <strong>Acme<\/strong>/);

  /* Not a member, a bad token, or a stranger's next: nothing. */
  r = await bo.post("/org/switch", { ...sw[0], org: randomUUID() });
  assert.equal(r.status, 404);
  r = await bo.post("/org/switch", { form: "x", org: personal, next: "/" });
  assert.equal(r.status, 403);
  r = await bo.post("/org/switch", { ...sw[0], org: personal, next: "https://evil.example/" });
  assert.equal(r.location, "/");

  /* Someone in one organisation sees no switcher. */
  const carl = new Browser(e);
  await signIn(carl, s, "carl@example.com");
  assert.equal(forms((await carl.get("/")).text, "/org/switch").length, 0);
  assert.equal(forms((await carl.get("/device")).text, "/org/switch").length, 0);
});

test("an invite is only as good as its sender's role: removed, made a member or gone, their waiting invites go too", async () => {
  const s = services();
  const e = env();
  const { ana, acme } = await acmeOwner(e, s);
  const bob = await inOrg(e, s, acme, "bob@example.com", "admin");
  const cy = await inOrg(e, s, acme, "cy@example.com", "admin");
  const dee = await inOrg(e, s, acme, "dee@example.com", "admin");
  const [bobId, cyId, deeId] = ["bob", "cy", "dee"].map((n) => userId(e, `${n}@example.com`));
  const waiting = (email) => one(e, "SELECT * FROM invites WHERE org_id = ? AND invited_by = ? ORDER BY created_at DESC",
    acme, userId(e, email));

  /* Each admin, expecting to lose the role, first invites an address of their own. */
  for (const [b, alt] of [[bob, "bob.alt@example.net"], [cy, "cy.alt@example.net"], [dee, "dee.alt@example.net"]]) {
    assert.equal((await invite(b, alt)).location, "/");
    assert.ok(inviteFor(s, alt));
  }
  /* An invite of Ana's own, to someone else, which none of this touches. */
  assert.equal((await invite(ana, "eve@example.com")).location, "/");

  /* Removed: Bob's waiting invite is taken back in the same batch, and the link joins nobody. */
  assert.equal((await submit(ana, "/members/remove", (f) => f.user === bobId)).location, "/");
  assert.equal(roleIn(e, acme, "bob@example.com"), null);
  let row = waiting("bob@example.com");
  assert.ok(row.revoked_at, "taken back");
  assert.equal(row.email, null, "and its address cleared");
  assert.deepEqual(eventsOf(e, "invite_left_org"), [{ org_id: acme, user_id: bobId, subject: row.id }]);
  const alt = new Browser(e);
  await signIn(alt, s, "bob.alt@example.net");
  const link = inviteFor(s, "bob.alt@example.net");
  let r = await alt.get(`/invite/${link}`);
  assert.equal(r.status, 410);
  assert.match(r.text, /taken back/);
  assert.doesNotMatch(r.text, /action="\/invite"/);
  r = await alt.post("/invite", { form: await formToken(e, alt.session, `invite-accept:${row.id}`), token: link });
  assert.equal(r.status, 410);
  assert.equal(roleIn(e, acme, "bob.alt@example.net"), null);

  /* Made a member: Cy's waiting invite goes with the role. */
  assert.equal((await submit(ana, "/members/role", (f) => f.user === cyId)).location, "/");
  assert.equal(roleIn(e, acme, "cy@example.com"), "member");
  row = waiting("cy@example.com");
  assert.ok(row.revoked_at);
  assert.equal(row.email, null);
  const cyAlt = new Browser(e);
  await signIn(cyAlt, s, "cy.alt@example.net");
  assert.equal((await cyAlt.get(`/invite/${inviteFor(s, "cy.alt@example.net")}`)).status, 410);
  assert.equal(roleIn(e, acme, "cy.alt@example.net"), null);

  /* Leaving: Dee's goes too. */
  assert.equal((await submit(dee, "/members/leave")).location, "/");
  assert.ok(waiting("dee@example.com").revoked_at);
  assert.deepEqual(eventsOf(e, "invite_left_org").map((x) => x.user_id).sort(), [bobId, cyId, deeId].sort());

  /* The owner's own invite is untouched, and still joins. */
  const eveRow = waiting("ana@example.com");
  assert.equal(eveRow.revoked_at, null);
  assert.equal(eveRow.email, "eve@example.com");
  const eve = new Browser(e);
  await signIn(eve, s, "eve@example.com");
  const join = forms((await eve.get(`/invite/${inviteFor(s, "eve@example.com")}`)).text, "/invite")[0];
  assert.equal((await eve.post("/invite", join)).location, "/");
  assert.equal(roleIn(e, acme, "eve@example.com"), "member");
});

test("Join checks, in its own batch, that whoever sent the invite is still an owner or an admin", async () => {
  const s = services();
  const e = env();
  const { acme } = await acmeOwner(e, s);
  const fay = await inOrg(e, s, acme, "fay@example.com", "admin");
  assert.equal((await invite(fay, "gus@example.com")).location, "/");
  const gus = new Browser(e);
  await signIn(gus, s, "gus@example.com");
  const join = forms((await gus.get(`/invite/${inviteFor(s, "gus@example.com")}`)).text, "/invite")[0];

  /* Fay stops being an admin between the page and the click, by a way that does not take her invites back. */
  run(e, "UPDATE memberships SET role = 'member' WHERE org_id = ? AND user_id = ?", acme, userId(e, "fay@example.com"));
  let r = await gus.post("/invite", join);
  assert.equal(r.status, 410);
  assert.match(r.text, /can no longer invite people there/);
  assert.equal(roleIn(e, acme, "gus@example.com"), null);
  assert.equal(eventsOf(e, "invite_accepted").length, 0);
  assert.equal(invitesOf(e, acme)[0].accepted_at, null);

  /* An admin again, and the same invite joins. */
  run(e, "UPDATE memberships SET role = 'admin' WHERE org_id = ? AND user_id = ?", acme, userId(e, "fay@example.com"));
  r = await gus.post("/invite", join);
  assert.equal(r.location, "/", r.text);
  assert.equal(roleIn(e, acme, "gus@example.com"), "member");
});
