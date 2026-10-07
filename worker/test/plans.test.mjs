/* Plans: what an organisation is on (auth.js's plan()), whose a token is
 * (identify()), what each plan has (features.js), what the feed answers a
 * machine on each, and the dashboard's panels, over a real SQLite database
 * with rows written as stripe.js, scripts/feed_token.py and
 * scripts/org_admin.py write them.
 *
 *     node --test worker/test/plans.test.mjs
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { d1 } from "./stand-ins.mjs";

const worker = (await import("../src/index.js")).default;
const { entitled, identify, plan, schema } = await import("../src/auth.js");
const { FEATURES, PLANS, allows, atLeast, featuresOf } = await import("../src/features.js");
const accounts = await import("../src/accounts.js");
const { openSession } = await import("../src/session.js");

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const BODY = JSON.stringify(JSON.parse(readFileSync(join(ROOT, "worker", "feed", "catalogue.json"), "utf8")));
const SECRET = "an-account-test-secret-that-is-long-enough-0123456789";
const ctx = { waitUntil() {} };
const now = () => Math.floor(Date.now() / 1000);
const DAY = 24 * 3600;
const hash = (t) => createHash("sha256").update(t).digest("hex");
/* Made here rather than written out: nothing token-shaped sits in the source. */
const token = (prefix = "rw_") => prefix + randomBytes(32).toString("base64url");

const env = (extra = {}) => ({
  LIST: d1(), RESEND_API_KEY: "re_test_key", ACCOUNT_SECRET: SECRET, TURNSTILE_SECRET: "turnstile-" + "test",
  ACCOUNTS_ON: "1", ...extra,
});

async function stand(extra) {
  const e = env(extra);
  await schema(e.LIST);
  await accounts.schema(e.LIST);
  return e;
}

const run = (e, sql, ...p) => e.LIST.sql.prepare(sql).run(...p);
const tables = (e) => e.LIST.sql.prepare("SELECT name FROM sqlite_master WHERE type = 'table'").all().map((r) => r.name);

function org(e, name = "Acme") {
  const id = randomUUID();
  run(e, "INSERT INTO orgs (id, name, personal, created_at) VALUES (?, ?, 0, ?)", id, name, now());
  return id;
}

/* A subscription in the state Stripe last gave, linked to an organisation
   when one is given, and a token tied to it as stripe.js issues one. */
function subscription(e, status, orgId = null) {
  const sub = `sub_test${randomBytes(6).toString("hex")}`;
  run(e, "INSERT INTO subscriptions (id, customer, status, updated_at) VALUES (?, ?, ?, ?)",
      sub, "cus_test1abcdef", status, now());
  if (orgId) {
    run(e, "INSERT INTO org_subscriptions (subscription, org_id, how, linked_at) VALUES (?, ?, 'script', ?)",
        sub, orgId, now());
  }
  const tok = token();
  run(e, "INSERT INTO tokens (hash, note, created_at) VALUES (?, ?, ?)", hash(tok), `stripe ${sub}`, now());
  run(e, "INSERT INTO token_subscriptions (hash, subscription) VALUES (?, ?)", hash(tok), sub);
  return { sub, tok };
}

function grant(e, orgId, which, { starts = now() - 60, until = null } = {}) {
  run(e, "INSERT INTO grants (org_id, plan, starts_at, until, note, created_at) VALUES (?, ?, ?, ?, 'test', ?)",
      orgId, which, starts, until, now());
}

/* A machine linked to an organisation, its rows inserted directly, as the
   device grant will write them. */
function machine(e, orgId, kind = "device", { revoked = null } = {}) {
  const tok = token(kind === "ci" ? "rw_c_" : "rw_m_");
  run(e, "INSERT INTO tokens (hash, note, created_at, revoked_at) VALUES (?, ?, ?, ?)",
      hash(tok), `machine ${kind}`, now(), revoked);
  const id = randomUUID();
  run(e, "INSERT INTO machines (id, hash, org_id, user_id, kind, label, created_at) VALUES (?, ?, ?, NULL, ?, ?, ?)",
      id, hash(tok), orgId, kind, "laptop", now());
  return { id, tok };
}

/* A token switched on by running the SQL scripts/feed_token.py prints. */
function byHand(e) {
  const out = spawnSync("python3", [join(ROOT, "scripts", "feed_token.py"), "new", "plans test"], { encoding: "utf8" });
  assert.equal(out.status, 0, out.stderr);
  e.LIST.sql.exec(out.stdout.match(/--command "([^"]+)"/)[1]);
  return out.stdout.match(/^\s+(rw_\S+)$/m)[1];
}

/* scripts/org_admin.py, with its printed SQL run as the console would. */
function orgAdmin(e, ...args) {
  const out = spawnSync("python3", [join(ROOT, "scripts", "org_admin.py"), ...args], { encoding: "utf8" });
  assert.equal(out.status, 0, out.stderr);
  e.LIST.sql.exec(out.stdout.match(/--command "([^"]+)"/)[1]);
}

const asking = (tok) => new Request("https://feed.ranwhat.com/v1/catalogue",
  { headers: { authorization: `Bearer ${tok}` } });
const feed = (e, tok) => worker.fetch(asking(tok), e, ctx);

/* ---------- the feature map ---------- */

test("each plan has what its map says, and nothing unknown is let through", () => {
  assert.deepEqual([...PLANS], ["free", "plus", "team"]);
  for (const [key, f] of Object.entries(FEATURES)) {
    assert.ok(["plus", "team"].includes(f.plan), key);
    assert.ok(["live", "coming"].includes(f.status), key);
    assert.ok(f.name && f.says, key);
    assert.equal(allows("free", key), false, key);
    assert.equal(allows("plus", key), f.plan === "plus", key);
    assert.equal(allows("team", key), true, key);
  }
  for (const key of ["feed", "ci_tokens", "push", "alerts", "machines", "history", "drift", "digest", "signed_reports"]) {
    assert.equal(FEATURES[key].plan, "plus", key);
  }
  for (const key of ["hash_chain", "underwriter_export"]) assert.equal(FEATURES[key].plan, "team", key);
  assert.equal(FEATURES.feed.status, "live");
  for (const [p, f] of [["plus", "nonsense"], ["team", "constructor"], ["admin", "feed"], [undefined, "feed"],
                        ["constructor", "feed"], ["team", "__proto__"]]) {
    assert.equal(allows(p, f), false, `${p} ${f}`);
  }
  assert.ok(atLeast("team", "plus") && atLeast("plus", "plus") && !atLeast("free", "plus") && !atLeast("plus", "team"));
  assert.deepEqual([...featuresOf("plus"), ...featuresOf("team")].map((f) => f.key), Object.keys(FEATURES));
  assert.throws(() => { FEATURES.feed.plan = "free"; });
});

test("no command that runs on a machine is ever a feature, so none is ever locked", () => {
  const cli = readFileSync(join(ROOT, "ranwhat", "cli.py"), "utf8");
  const block = cli.match(/^COMMANDS = \(\n([\s\S]*?)^\)/m)[1];
  const commands = [...block.matchAll(/^\s+\("([a-z-]+)",/gm)].map((m) => m[1]);
  assert.ok(commands.includes("check") && commands.includes("clean"), commands.join(" "));
  // update is the one command that asks the server: it is the feed.
  const local = commands.filter((c) => c !== "update");
  for (const [key, f] of Object.entries(FEATURES)) {
    for (const c of local) {
      assert.notEqual(key, c);
      assert.doesNotMatch(`${f.name} ${f.says}`, new RegExp(`ranwhat ${c}\\b`), `${key} names ranwhat ${c}`);
    }
  }
});

/* ---------- plan() ---------- */

test("the plan matrix: subscriptions by status, grants in and out of force", async () => {
  const e = await stand();
  const cases = [];
  const add = (label, expected, setup) => cases.push({ label, expected, id: setup(org(e, label)) });
  add("nothing", "free", (o) => o);
  for (const status of ["active", "trialing", "past_due"]) add(status, "plus", (o) => (subscription(e, status, o), o));
  for (const status of ["canceled", "unpaid", "incomplete", "incomplete_expired", "paused"]) {
    add(status, "free", (o) => (subscription(e, status, o), o));
  }
  add("canceled then active again", "plus", (o) => (subscription(e, "canceled", o), subscription(e, "active", o), o));
  add("team grant", "team", (o) => (grant(e, o, "team"), o));
  add("team grant until next year", "team", (o) => (grant(e, o, "team", { until: now() + 365 * DAY }), o));
  add("expired team grant", "free", (o) => (grant(e, o, "team", { until: now() - 1 }), o));
  add("team grant from tomorrow", "free", (o) => (grant(e, o, "team", { starts: now() + DAY }), o));
  add("plus grant", "plus", (o) => (grant(e, o, "plus"), o));
  add("expired plus grant", "free", (o) => (grant(e, o, "plus", { until: now() - 1 }), o));
  add("team grant and a live subscription", "team", (o) => (grant(e, o, "team"), subscription(e, "active", o), o));
  add("expired team grant and a live subscription", "plus",
      (o) => (grant(e, o, "team", { until: now() - 1 }), subscription(e, "active", o), o));
  add("a live subscription linked elsewhere", "free", (o) => (subscription(e, "active", org(e)), o));
  add("an unlinked live subscription", "free", (o) => (subscription(e, "active"), o));
  for (const c of cases) assert.equal(await plan(e, c.id), c.expected, c.label);
  assert.equal(await plan(e, null), "free");
  assert.equal(await plan(e, randomUUID()), "free", "an organisation that does not exist");
  assert.equal(await plan({}, "x"), "free", "no database");
});

test("a status change from Stripe moves the plan on the next request; nothing is stored", async () => {
  const e = await stand();
  const o = org(e);
  const { sub } = subscription(e, "active", o);
  const before = tables(e).map((t) => e.LIST.sql.prepare(`SELECT count(*) AS n FROM ${t}`).get().n);
  assert.equal(await plan(e, o), "plus");
  assert.deepEqual(tables(e).map((t) => e.LIST.sql.prepare(`SELECT count(*) AS n FROM ${t}`).get().n), before);
  run(e, "UPDATE subscriptions SET status = 'canceled' WHERE id = ?", sub);
  assert.equal(await plan(e, o), "free");
});

test("scripts/org_admin.py's grants and revocations are what plan() reads", async () => {
  const e = await stand();
  const o = org(e);
  orgAdmin(e, "grant", "team", o, "contract: test");
  assert.equal(await plan(e, o), "team");
  orgAdmin(e, "grant", "comp", o, "press: test", "--days", "30");
  orgAdmin(e, "revoke", "team", o);
  assert.equal(await plan(e, o), "plus", "the comp is left in force");
  orgAdmin(e, "revoke", "comp", o);
  assert.equal(await plan(e, o), "free");
  assert.equal(e.LIST.sql.prepare("SELECT count(*) AS n FROM grants").get().n, 2, "revoked grants stay on record");
});

test("scripts/org_admin.py's link puts an organisation on its subscription's plan, and never moves it", async () => {
  const e = await stand();
  const o = org(e), other = org(e, "Other");
  const { sub, tok } = subscription(e, "active");
  assert.equal(await plan(e, o), "free");
  orgAdmin(e, "link", sub, o);
  assert.equal(await plan(e, o), "plus");
  assert.equal((await identify(asking(tok), e)).org, o);
  orgAdmin(e, "link", sub, other);
  assert.equal(await plan(e, other), "free", "a linked subscription is never moved");
  assert.deepEqual(e.LIST.sql.prepare("SELECT org_id, how FROM org_subscriptions").all().map((r) => ({ ...r })),
                   [{ org_id: o, how: "script" }]);
  run(e, "UPDATE subscriptions SET status = 'canceled' WHERE id = ?", sub);
  assert.equal(await plan(e, o), "free", "Plus only while the subscription is live");
});

/* ---------- identify() and the feed ---------- */

test("a machine is its organisation's, on its plan; on Free the feed says plus_required", async () => {
  const e = await stand();
  const free = org(e, "Free"), paid = org(e, "Paid"), team = org(e, "Team");
  subscription(e, "active", paid);
  grant(e, team, "team");
  const m = machine(e, free);

  const who = await identify(asking(m.tok), e);
  assert.equal(who.ok, true);
  assert.deepEqual([who.kind, who.org, who.plan, who.account, who.machine.id, who.machine.label],
                   ["device", free, "free", `org:${free}`, m.id, "laptop"]);
  assert.ok(!JSON.stringify(who).includes(m.tok), "the token is nowhere in the answer");
  assert.deepEqual(await entitled(asking(m.tok), e),
                   { ok: false, status: 403, error: "plus_required", upgrade: "https://account.ranwhat.com/" });
  const res = await feed(e, m.tok);
  assert.equal(res.status, 403);
  assert.equal(res.headers.get("cache-control"), "no-store");
  assert.deepEqual(await res.json(), { error: "plus_required", upgrade: "https://account.ranwhat.com/" });

  for (const [o, expected] of [[paid, "plus"], [team, "team"]]) {
    for (const kind of ["device", "ci"]) {
      const t = machine(e, o, kind).tok;
      const w = await identify(asking(t), e);
      assert.deepEqual([w.kind, w.plan, w.org], [kind, expected, o]);
      assert.deepEqual(await entitled(asking(t), e), { ok: true, account: `org:${o}` });
      const r = await feed(e, t);
      assert.equal(r.status, 200);
      assert.equal(await r.text(), BODY);
    }
  }
  const teamOnly = await entitled(asking(machine(e, paid).tok), e, "underwriter_export");
  assert.deepEqual([teamOnly.status, teamOnly.error], [403, "team_required"]);
  assert.equal((await entitled(asking(machine(e, team).tok), e, "underwriter_export")).ok, true);
});

test("a machine's token, revoked or out of date, is refused like any other", async () => {
  const e = await stand();
  const o = org(e);
  grant(e, o, "team");
  const revoked = machine(e, o, "device", { revoked: now() - 1 });
  const expired = machine(e, o, "ci");
  run(e, "UPDATE tokens SET expires_at = ? WHERE hash = ?", now() - 1, hash(expired.tok));
  for (const t of [revoked.tok, expired.tok, token("rw_m_")]) {
    assert.deepEqual(await identify(asking(t), e), { ok: false, status: 403, error: "That token was not accepted." });
    assert.equal((await feed(e, t)).status, 403);
  }
});

test("subscription and hand-made tokens answer as before, accounts on or off, byte for byte", async () => {
  for (const extra of [{}, { ACCOUNTS_ON: undefined }]) {
    const e = env(extra);
    await schema(e.LIST);
    const hand = byHand(e);
    const live = subscription(e, "past_due");
    const gone = subscription(e, "canceled");
    assert.deepEqual(await entitled(asking(hand), e), { ok: true, account: `tok:${hash(hand)}` });
    assert.deepEqual(await entitled(asking(live.tok), e), { ok: true, account: live.sub });
    assert.deepEqual(await entitled(asking(gone.tok), e), { ok: false, status: 403, error: "That token was not accepted." });
    for (const t of [hand, live.tok]) {
      const r = await feed(e, t);
      assert.equal(r.status, 200);
      assert.equal(await r.text(), BODY);
      assert.equal(r.headers.get("cache-control"), "private, no-store");
    }
    const r = await feed(e, gone.tok);
    assert.equal(r.status, 403);
    assert.deepEqual(await r.json(), { error: "That token was not accepted." });
    const h = await identify(asking(hand), e);
    assert.deepEqual([h.kind, h.plan, h.org], ["hand", "plus", null]);
    const s = await identify(asking(live.tok), e);
    assert.deepEqual([s.kind, s.plan, s.org], ["subscription", "plus", null]);
  }
});

test("switching accounts off never moves a machine's plan: a Free organisation's stays refused", async () => {
  const e = await stand();
  const free = org(e, "Free"), paid = org(e, "Paid");
  subscription(e, "active", paid);
  const m = machine(e, free), p = machine(e, paid, "ci");
  for (const switched of ["1", undefined, "", "0"]) {
    e.ACCOUNTS_ON = switched;
    const who = await identify(asking(m.tok), e);
    assert.deepEqual([who.kind, who.plan, who.org], ["device", "free", free], `ACCOUNTS_ON=${switched}`);
    const r = await feed(e, m.tok);
    assert.equal(r.status, 403, `ACCOUNTS_ON=${switched}`);
    assert.deepEqual(await r.json(), { error: "plus_required", upgrade: "https://account.ranwhat.com/" });
    const ok = await feed(e, p.tok);
    assert.equal(ok.status, 200);
    assert.equal(await ok.text(), BODY);
  }
});

test("while accounts are dark, the feed reads none of their tables and makes none", async () => {
  const e = env({ ACCOUNTS_ON: undefined });
  const hand = byHand(e);
  assert.equal((await feed(e, hand)).status, 200);
  assert.deepEqual(tables(e).sort(), ["subscriptions", "token_subscriptions", "tokens"]);
});

test("a subscription linked to an organisation shows it, on that organisation's plan", async () => {
  const e = await stand();
  const o = org(e);
  const { sub, tok } = subscription(e, "active", o);
  grant(e, o, "team");
  const who = await identify(asking(tok), e);
  assert.deepEqual([who.kind, who.account, who.org, who.plan], ["subscription", sub, o, "team"]);
  /* An emailed token listed as a legacy machine on linking stays on the
     subscription's path: it works while the subscription does. */
  run(e, "INSERT INTO machines (id, hash, org_id, kind, label, created_at) VALUES (?, ?, ?, 'legacy', 'emailed', ?)",
      randomUUID(), hash(tok), o, now());
  assert.equal((await identify(asking(tok), e)).kind, "subscription");
  run(e, "UPDATE subscriptions SET status = 'canceled' WHERE id = ?", sub);
  assert.equal((await feed(e, tok)).status, 403, "even with the team grant, a dead subscription's token is dead");
});

/* ---------- the dashboard ---------- */

/* Signed in as the owner of a new personal organisation, without the
   emailed code (accounts.test.mjs covers that): the account and a session,
   as dashboard.js makes them. */
async function signedIn(e) {
  const user = await accounts.userForVerifiedEmail(e, { email: "ana@example.com" });
  const o = await accounts.orgFor(e, user.id);
  const { value, statements } = await openSession(e, { user: user.id, org: o.id });
  await e.LIST.batch(statements);
  const home = async () => {
    const res = await worker.fetch(new Request("https://account.ranwhat.com/", {
      headers: { cookie: `__Host-rw_session=${value}` } }), e, ctx);
    assert.equal(res.status, 200);
    return res.text();
  };
  return { org: o.id, home };
}

const section = (html, tier) => {
  const m = html.match(new RegExp(`<section class="panel( locked)?" id="${tier}">([\\s\\S]*?)</section>`));
  assert.ok(m, `no ${tier} panel`);
  return { locked: Boolean(m[1]), html: m[2], features: [...m[2].matchAll(/data-feature="([a-z_]+)"/g)].map((x) => x[1]) };
};

test("a Free organisation's dashboard shows Plus and Team locked, from the map, with the way up", async () => {
  const e = await stand();
  const { home } = await signedIn(e);
  const html = await home();
  assert.match(html, /<dt>Plan<\/dt><dd id="plan">Free<\/dd>/);
  const plus = section(html, "plus"), team = section(html, "team");
  assert.deepEqual([plus.locked, team.locked], [true, true]);
  assert.deepEqual(plus.features, featuresOf("plus").map((f) => f.key));
  assert.deepEqual(team.features, featuresOf("team").map((f) => f.key));
  for (const f of featuresOf("plus")) {
    assert.ok(plus.html.includes(f.name), f.key);
    assert.ok(plus.html.includes(f.status === "live" ? "Needs Plus" : "Coming, included in Plus"), f.key);
  }
  assert.deepEqual(plus.features.slice(0, 2), ["feed", "ci_tokens"], "the feed and CI tokens lead the Plus panel");
  assert.match(plus.html, /<li data-feature="ci_tokens"><strong>CI tokens<\/strong> <span class="tag">Needs Plus<\/span>/);
  assert.match(plus.html, /<a href="\/upgrade">Upgrade to Plus<\/a>/);
  // Team: no price and nothing to buy, only a way to talk to us.
  assert.doesNotMatch(team.html, /<form|€|\$|£|\/\s*(month|year)|per (month|year|seat)|pricing|checkout/i);
  assert.match(team.html, /href="mailto:hello@ranwhat\.com/);
  for (const c of ["check", "watch", "clean", "scan", "live", "demo", "sources"]) {
    assert.doesNotMatch(html, new RegExp(`ranwhat ${c}\\b`), `local command ${c} on the dashboard`);
  }
  assert.doesNotMatch(html, /<script|\son[a-z]+=/i);
});

test("Plus opens the Plus panel; Team opens both; neither shows the upgrade", async () => {
  const e = await stand();
  const { org: o, home } = await signedIn(e);
  const { sub } = subscription(e, "trialing", o);
  let html = await home();
  assert.match(html, /<dd id="plan">Plus<\/dd>/);
  assert.deepEqual([section(html, "plus").locked, section(html, "team").locked], [false, true]);
  assert.ok(section(html, "plus").html.includes("Included"));
  assert.doesNotMatch(html, /Upgrade to Plus/);

  grant(e, o, "team");
  html = await home();
  assert.match(html, /<dd id="plan">Team<\/dd>/);
  assert.deepEqual([section(html, "plus").locked, section(html, "team").locked], [false, false]);
  assert.doesNotMatch(html, /Upgrade to Plus|Talk to us/);

  run(e, "DELETE FROM grants");
  run(e, "UPDATE subscriptions SET status = 'canceled' WHERE id = ?", sub);
  assert.match(await home(), /<dd id="plan">Free<\/dd>/, "derived on every request");
});

/* ---------- locks ---------- */

/* Every element the account page draws locked, with its tag, its own
   attributes and what is inside it, found by matching its tags, so a
   locked panel drawn as a section or a div, nested or not, is found. */
function lockedPanels(html) {
  const found = [];
  const open = /<(section|div)\b([^>]*\bclass="[^"]*\blocked\b[^"]*"[^>]*)>/g;
  for (let m; (m = open.exec(html));) {
    const tag = m[1];
    const tags = new RegExp(`<(/?)${tag}\\b[^>]*>`, "g");
    tags.lastIndex = open.lastIndex;
    let depth = 1, end = -1;
    for (let t; depth && (t = tags.exec(html));) {
      depth += t[1] ? -1 : 1;
      if (!depth) end = t.index;
    }
    assert.ok(end > 0, `an unclosed locked ${tag}`);
    found.push({ attrs: m[2], inner: html.slice(open.lastIndex, end) });
  }
  return found;
}

const SRC = join(ROOT, "worker", "src");
const SOURCES = ["auth.js", "feed.js", "dashboard.js", "machines.js", "members.js", "billing.js", "device.js"]
  .map((f) => readFileSync(join(SRC, f), "utf8")).join("\n");

test("locks: every locked panel names a server-side feature, and a live one is refused on the server", async () => {
  const e = await stand();
  const { org: o, home } = await signedIn(e);
  const locals = ["check", "watch", "clean", "sources", "reach", "scan", "live", "demo", "hook"];
  const check = (html) => {
    const panels = lockedPanels(html);
    for (const { attrs, inner } of panels) {
      const id = (/\bid="([^"]+)"/.exec(attrs) || [])[1];
      const keys = [...`${attrs} ${inner}`.matchAll(/data-feature="([^"]+)"/g)].map((x) => x[1]);
      assert.ok(keys.length > 0, `locked panel ${id} names no feature`);
      for (const key of keys) {
        assert.ok(Object.hasOwn(FEATURES, key), `locked panel ${id} names ${key}, which features.js does not have`);
        const f = FEATURES[key];
        assert.ok(inner.includes(f.name), `locked panel ${id} does not say ${f.name}`);
        assert.ok(["plus", "team"].includes(f.plan), key);
        if (f.status === "live") {
          /* Drawn locked because the server refuses it: a handler works the
             plan out at request time and asks the map about this feature. */
          assert.match(SOURCES, new RegExp(
            `allows\\(await plan\\([^)]*\\), "${key}"\\)|entitled\\(request, env, "${key}"\\)`),
            `${key} is drawn locked but nothing on the server refuses it`);
        }
      }
      for (const c of locals) {
        assert.doesNotMatch(inner, new RegExp(`ranwhat ${c}\\b`), `locked panel ${id} names local command ${c}`);
      }
    }
    return panels.map(({ attrs }) => (/\bid="([^"]+)"/.exec(attrs) || [])[1]);
  };

  // Free: Plus and Team, and the two Plus features with panels of their own.
  assert.deepEqual(check(await home()).sort(), ["ci-tokens", "members", "plus", "team"]);
  // Plus: only Team stays locked.
  const { sub } = subscription(e, "active", o);
  assert.deepEqual(check(await home()), ["team"]);
  // Team: nothing is locked.
  grant(e, o, "team");
  assert.deepEqual(check(await home()), []);
  run(e, "DELETE FROM grants");
  run(e, "UPDATE subscriptions SET status = 'canceled' WHERE id = ?", sub);
  assert.deepEqual(check(await home()).sort(), ["ci-tokens", "members", "plus", "team"]);
});
