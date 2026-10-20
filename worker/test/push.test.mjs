/* Pushing findings (push.js, push_schema.js) and the page that shows them
 * (dashboard.js's /findings): POST feed.ranwhat.com/v1/push from a linked
 * terminal or a CI token, strict validation against an allow-list, what is
 * stored and kept, the limits, revoking, and the cross-machine page with
 * its escaping and policy. The Worker's own fetch and scheduled handlers
 * run over a real SQLite database (node:sqlite, which is what D1 runs).
 *
 *     node --test --test-timeout=120000 worker/test/push.test.mjs
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { d1, slow } from "./stand-ins.mjs";

const worker = (await import("../src/index.js")).default;
const { entitled, entitledWho, identify, schema } = await import("../src/auth.js");
const accounts = await import("../src/accounts.js");
const machines = await import("../src/machines.js");
const { openSession } = await import("../src/session.js");
const { LIMITS, validate, digestOf, normalise } = await import("../src/push_schema.js");
const { RETENTION, PUSH_LIMITS } = await import("../src/push.js");

const HERE = dirname(fileURLToPath(import.meta.url));
const VECTORS = JSON.parse(readFileSync(join(HERE, "push-vectors.json"), "utf8"));
const SCHEMA_JSON = JSON.parse(readFileSync(join(HERE, "..", "push", "schema.json"), "utf8"));

const FEED = "https://feed.ranwhat.com";
const SECRET = "an-account-test-secret-that-is-long-enough-0123456789";
const HOUR = 3600, DAY = 24 * HOUR;
const CANARY = "SECRETCANARY-77aa";
const ctx = { waitUntil() {} };

/* The clock, which a test moves forward when it needs time to pass. */
const realNow = Date.now;
let skew = 0;
Date.now = () => realNow() + skew * 1000;
const later = (seconds) => { skew += seconds; };
const unix = () => Math.floor(Date.now() / 1000);
const iso = (t) => new Date(t * 1000).toISOString().slice(0, 19) + "Z";

const sha = (text) => createHash("sha256").update(text).digest("hex");
const madeToken = (prefix = "rw_m_") => prefix + randomBytes(32).toString("base64url");

const env = (extra = {}) => ({
  LIST: d1(), RESEND_API_KEY: "re_" + "test_key", ACCOUNT_SECRET: SECRET, TURNSTILE_SECRET: "turnstile-" + "test",
  ACCOUNTS_ON: "1", ...extra,
});

async function stand(extra) {
  const e = env(extra);
  await schema(e.LIST);
  await accounts.schema(e.LIST);
  return e;
}

const run = (e, sql, ...p) => e.LIST.sql.prepare(sql).run(...p);
const all = (e, sql, ...p) => e.LIST.sql.prepare(sql).all(...p).map((r) => ({ ...r }));
const one = (e, sql, ...p) => { const r = e.LIST.sql.prepare(sql).get(...p); return r ? { ...r } : null; };
const dump = (e) => JSON.stringify(["pushes", "throttle", "machines", "tokens"].map((t) => all(e, `SELECT * FROM ${t} ORDER BY 1, 2`)));

function org(e, name = "Acme", plan = "plus") {
  const id = randomUUID();
  run(e, "INSERT INTO orgs (id, name, personal, created_at) VALUES (?, ?, 0, ?)", id, name, unix());
  if (plan !== "free") {
    run(e, "INSERT INTO grants (org_id, plan, starts_at, until, note, created_at) VALUES (?, ?, ?, NULL, 'test', ?)",
        id, plan, unix() - 60, unix());
  }
  return id;
}

/* A machine linked to an organisation, its rows inserted as the device
   grant writes them. */
function machine(e, orgId, kind = "device", label = "laptop") {
  const tok = madeToken(kind === "ci" ? "rw_c_" : "rw_m_");
  run(e, "INSERT INTO tokens (hash, note, created_at) VALUES (?, ?, ?)", sha(tok), `machine ${kind}`, unix());
  const id = randomUUID();
  run(e, "INSERT INTO machines (id, hash, org_id, user_id, kind, label, created_at) VALUES (?, ?, ?, NULL, ?, ?, ?)",
      id, sha(tok), orgId, kind, label, unix());
  return { id, tok };
}

const hexid = (i) => (0xb0000000 + i).toString(16).padStart(16, "0");

/* A valid push of n flagged actions, the rest of it fixed. */
function snapshot({ n = 1, extra = {}, at = unix() } = {}) {
  return {
    v: 1, ranwhat: "0.8.0", generated_at: iso(at), window_days: 30,
    counts: {
      flagged: n, ignored: 2, omitted: 0, unread: 0,
      severity: { critical: 0, high: n, medium: 0 },
      rules: n ? { "cred.read": n } : {}, agents: n ? { "claude-code": n } : {}, scanned: { "claude-code": 5 },
    },
    actions: Array.from({ length: n }, (_, i) => ({
      id: hexid(i + 1), agent: "claude-code", at: iso(at - 60 * (i + 1)), hits: [{ rule: "cred.read", severity: "high" }],
    })),
    ...extra,
  };
}

function post(e, tok, body, { headers = {}, ip = "198.51.100.7", raw = false } = {}) {
  const h = new Headers({ "cf-connecting-ip": ip, ...headers });
  if (tok) h.set("authorization", `Bearer ${tok}`);
  if (!h.has("content-type")) h.set("content-type", "application/json");
  return worker.fetch(new Request(`${FEED}/v1/push`, {
    method: "POST", headers: h, body: body === undefined ? undefined : raw ? body : JSON.stringify(body),
  }), e, ctx);
}

/* The cron, with what it waits on waited for. */
async function sweep(e) {
  const waits = [];
  await worker.scheduled({}, e, { waitUntil: (p) => waits.push(p) });
  await Promise.all(waits);
}

const answer = async (res) => ({ status: res.status, headers: res.headers, body: JSON.parse(await res.text()) });
const pushed = async (e, tok, body, opts) => answer(await post(e, tok, body, opts));

/* The placeholders in the shared vectors, replaced with times near now. */
function resolved(value) {
  if (typeof value === "string" && value.startsWith("@now")) {
    const m = /^@now(?:([+-])(\d+)([hd]))?$/.exec(value);
    const offset = m[1] ? (m[1] === "+" ? 1 : -1) * Number(m[2]) * (m[3] === "h" ? HOUR : DAY) : 0;
    return iso(unix() + offset);
  }
  if (Array.isArray(value)) return value.map(resolved);
  if (value && typeof value === "object") {
    const out = {};
    for (const k of Object.keys(value)) Object.defineProperty(out, k, { value: resolved(value[k]), enumerable: true, configurable: true, writable: true });
    return out;
  }
  return value;
}

/* ---------- the allow-list, on its own ---------- */

test("the shared vectors: every valid body passes, every invalid one fails at its pointer for its reason", () => {
  const t = unix();
  for (const { name, doc } of VECTORS.valid) {
    const r = validate(resolved(doc), t);
    assert.equal(r.ok, true, `${name}: ${JSON.stringify(r)}`);
  }
  assert.ok(VECTORS.invalid.length >= 60);
  for (const { name, doc, field, reason, error = "invalid" } of VECTORS.invalid) {
    const r = validate(resolved(doc), t);
    assert.equal(r.ok, false, name);
    assert.deepEqual([r.error, r.field, r.reason], [error, field, reason], name);
    assert.doesNotMatch(JSON.stringify(r), /SECRETCANARY|__proto__|hostname|command/, `${name} echoes a value`);
  }
});

test("the schema file lists the ids and the limits the validator and the page use", () => {
  assert.equal(SCHEMA_JSON.v, 1);
  assert.deepEqual(SCHEMA_JSON.severities, ["medium", "high", "critical"]);
  assert.ok(Object.keys(SCHEMA_JSON.rules).includes("cred.read") && Object.keys(SCHEMA_JSON.agents).includes("claude-code"));
  for (const [id, title] of Object.entries({ ...SCHEMA_JSON.rules, ...SCHEMA_JSON.agents })) {
    assert.ok(typeof title === "string" && title.length > 0, id);
  }
  assert.deepEqual({ ...LIMITS }, { MAX_BODY: 32768, MAX_ACTIONS: 100, MAX_HITS: 15, MAX_RULE_KEYS: 32, MAX_AGENT_KEYS: 40, MAX_COUNT: 1000000 });
});

test("the digest ignores the time and the order, and nothing else", async () => {
  const a = snapshot({ n: 3 });
  const b = JSON.parse(JSON.stringify(a));
  b.generated_at = iso(unix() + 5);
  b.actions.reverse();
  const ra = validate(a, unix()).value, rb = validate(b, unix()).value;
  assert.equal(await digestOf(ra), await digestOf(rb));
  const c = JSON.parse(JSON.stringify(a));
  c.counts.ignored = 3;
  assert.notEqual(await digestOf(validate(c, unix()).value), await digestOf(ra));
  const d = JSON.parse(JSON.stringify(a));
  d.actions[0].hits[0].severity = "critical";
  d.counts.severity = { critical: 1, high: 2, medium: 0 };
  assert.notEqual(await digestOf(validate(d, unix()).value), await digestOf(ra));
  assert.deepEqual(Object.keys(normalise(ra)), ["v", "ranwhat", "generated_at", "window_days", "counts", "actions"]);
});

test("what validate returns is rebuilt, so nothing unchecked rides along", () => {
  const doc = snapshot({ n: 2 });
  const r = validate(doc, unix());
  assert.equal(r.ok, true);
  assert.notEqual(r.value, doc);
  assert.notEqual(r.value.actions[0], doc.actions[0]);
  assert.deepEqual(r.value, doc);
});

/* ---------- the endpoint ---------- */

test("dark: with accounts off the route, the page and the table are not there", async () => {
  const e = { LIST: d1() };
  const res = await post(e, madeToken(), snapshot());
  assert.equal(res.status, 404);
  assert.deepEqual(JSON.parse(await res.text()), { error: "Not found." });
  const page = await worker.fetch(new Request("https://account.ranwhat.com/findings"), e, ctx);
  assert.equal(page.status, 404);
  await sweep(e);
  assert.equal(all(e, "SELECT name FROM sqlite_master WHERE name = 'pushes'").length, 0);
});

test("who may push: no token, a refused one, a subscription's, a free organisation's; device and CI tokens of Plus and Team do", async () => {
  const e = await stand();
  const plus = org(e, "Plus Co", "plus"), team = org(e, "Team Co", "team"), free = org(e, "Free Co", "free");
  const dev = machine(e, plus), ci = machine(e, team, "ci"), freeDev = machine(e, free);
  const revoked = machine(e, plus);
  run(e, "UPDATE tokens SET revoked_at = ? WHERE hash = ?", unix(), sha(revoked.tok));
  const expired = machine(e, plus, "ci");
  run(e, "UPDATE tokens SET expires_at = ? WHERE hash = ?", unix() - 5, sha(expired.tok));

  let r = await pushed(e, null, snapshot());
  assert.deepEqual([r.status, r.body.error], [401, "token_required"]);
  r = await pushed(e, "not-a-token", snapshot());
  assert.deepEqual([r.status, r.body.error], [401, "token_required"]);
  const refused = [];
  for (const tok of [madeToken(), revoked.tok, expired.tok]) {
    r = await pushed(e, tok, snapshot());
    assert.deepEqual([r.status, r.body.error], [403, "token_refused"]);
    refused.push(JSON.stringify(r.body));
  }
  assert.equal(new Set(refused).size, 1, "one answer for unknown, revoked and expired");

  // A subscription's token and a hand-made one are not a machine's.
  const sub = madeToken("rw_");
  run(e, "INSERT INTO subscriptions (id, customer, status, updated_at) VALUES ('sub_x1', 'cus_x1', 'active', ?)", unix());
  run(e, "INSERT INTO tokens (hash, note, created_at) VALUES (?, 'stripe sub_x1', ?)", sha(sub), unix());
  run(e, "INSERT INTO token_subscriptions (hash, subscription) VALUES (?, 'sub_x1')", sha(sub));
  const hand = madeToken("rw_");
  run(e, "INSERT INTO tokens (hash, note, created_at) VALUES (?, 'by hand', ?)", sha(hand), unix());
  for (const tok of [sub, hand]) {
    r = await pushed(e, tok, snapshot());
    assert.deepEqual([r.status, r.body.error], [403, "machine_required"]);
  }

  const before = JSON.stringify(all(e, "SELECT * FROM throttle"));
  const pushesBefore = JSON.stringify(all(e, "SELECT * FROM pushes"));
  r = await pushed(e, freeDev.tok, snapshot());
  assert.deepEqual([r.status, r.body.error, r.body.upgrade], [403, "plus_required", "https://account.ranwhat.com/"]);
  assert.equal(JSON.stringify(all(e, "SELECT * FROM throttle")), before, "a free organisation counts nothing");
  assert.equal(JSON.stringify(all(e, "SELECT * FROM pushes")), pushesBefore);

  for (const tok of [dev.tok, ci.tok]) {
    r = await pushed(e, tok, snapshot());
    assert.deepEqual([r.status, r.body.ok, r.body.status], [200, true, "stored"]);
  }
  assert.equal(all(e, "SELECT * FROM pushes").length, 2);
});

test("the transport: methods, media type, encoding, browsers, size, emptiness", async () => {
  const e = await stand();
  const o = org(e);
  const { tok } = machine(e, o);

  const get = await worker.fetch(new Request(`${FEED}/v1/push`, { headers: { authorization: `Bearer ${tok}` } }), e, ctx);
  assert.equal(get.status, 405);
  assert.equal(get.headers.get("allow"), "POST");

  let r = await pushed(e, tok, JSON.stringify(snapshot()), { headers: { "content-type": "text/plain" }, raw: true });
  assert.deepEqual([r.status, r.body.error], [415, "unsupported_media_type"]);
  r = await pushed(e, tok, JSON.stringify(snapshot()), { headers: { "content-type": "application/json; charset=utf-8" }, raw: true });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  r = await pushed(e, tok, JSON.stringify(snapshot({ n: 2 })), { headers: { "content-encoding": "gzip" }, raw: true });
  assert.deepEqual([r.status, r.body.error], [415, "unsupported_media_type"]);
  r = await pushed(e, tok, snapshot(), { headers: { origin: "https://evil.example" } });
  assert.deepEqual([r.status, r.body.error], [403, "not_for_browsers"]);
  r = await pushed(e, tok, snapshot(), { headers: { "sec-fetch-site": "cross-site" } });
  assert.deepEqual([r.status, r.body.error], [403, "not_for_browsers"]);

  r = await pushed(e, tok, "", { raw: true });
  assert.deepEqual([r.status, r.body.error], [400, "bad_request"]);
  r = await pushed(e, tok, "{not json", { raw: true });
  assert.deepEqual([r.status, r.body.error], [400, "bad_request"]);
  for (const text of ["[]", "5", "null", '"x"']) {
    r = await pushed(e, tok, text, { raw: true });
    assert.deepEqual([r.status, r.body.error], [400, "bad_request"], text);
  }
  r = await pushed(e, tok, new Uint8Array([0x7b, 0xff, 0x7d]), { raw: true });
  assert.deepEqual([r.status, r.body.error], [400, "bad_request"], "not UTF-8");

  r = await pushed(e, tok, "{}", { raw: true, headers: { "content-length": "40000" } });
  assert.deepEqual([r.status, r.body.error], [413, "too_large"]);
  // Streamed with no length to trust.
  const stream = new ReadableStream({ start(c) { c.enqueue(new TextEncoder().encode(" ".repeat(40000))); c.close(); } });
  const big = await worker.fetch(new Request(`${FEED}/v1/push`, {
    method: "POST", duplex: "half", body: stream,
    headers: { authorization: `Bearer ${tok}`, "content-type": "application/json" },
  }), e, ctx);
  assert.equal(big.status, 413);

  // Exactly the limit, valid, is taken: pad the body with whitespace to 32768 bytes.
  const text = JSON.stringify(snapshot({ n: 3 }));
  const padded = text + " ".repeat(LIMITS.MAX_BODY - text.length);
  assert.equal(padded.length, 32768);
  r = await pushed(e, tok, padded, { raw: true });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  r = await pushed(e, tok, padded + " ", { raw: true });
  assert.equal(r.status, 413);
});

test("the response: its shape, its headers, no CORS", async () => {
  const e = await stand();
  const o = org(e, "Acme");
  const { tok } = machine(e, o, "device", "Work laptop");
  const res = await post(e, tok, snapshot({ n: 2 }));
  assert.equal(res.status, 200);
  assert.match(res.headers.get("content-type"), /^application\/json/);
  assert.equal(res.headers.get("cache-control"), "no-store");
  assert.equal(res.headers.get("x-content-type-options"), "nosniff");
  assert.equal(res.headers.get("access-control-allow-origin"), null);
  const body = JSON.parse(await res.text());
  assert.deepEqual({ ...body, received_at: "x" }, {
    ok: true, v: 1, status: "stored", received_at: "x", org: "Acme", machine: "Work laptop", actions: 2,
    keeps: { latest: 1, snapshots: 30, days: 30 },
  });
  assert.match(body.received_at, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/);
});

test("every invalid vector is a 422 with a pointer and a reason, repeats nothing, and stores nothing", async () => {
  const e = await stand();
  const o = org(e);
  const { tok } = machine(e, o);
  let sent = 0;
  for (const { name, doc, field, reason, error = "invalid" } of VECTORS.invalid) {
    if (sent++ % 15 === 14) later(HOUR + 1);   // a bad body costs quota like a good one
    const res = await post(e, tok, JSON.stringify(resolved(doc)), { raw: true });
    const text = await res.text();
    const body = JSON.parse(text);
    assert.equal(res.status, 422, `${name}: ${text}`);
    assert.deepEqual([body.error, body.field, body.reason], [error, field, reason], name);
    assert.doesNotMatch(text, /SECRETCANARY/, `${name} repeats a value`);
    if (error === "unsupported_version") assert.deepEqual(body.supported, [1]);
  }
  assert.equal(all(e, "SELECT * FROM pushes").length, 0);
});

test("an unknown key anywhere is refused, whatever it is called", async () => {
  const e = await stand();
  const o = org(e);
  const { tok } = machine(e, o);
  const names = ["hostname", "user", "cwd", "command", "path", "evidence", "session", "machine", "org", "constructor", "__proto__"];
  let n = 0;
  for (const name of names) {
    for (const where of ["root", "counts", "severity", "action", "hit"]) {
      const doc = snapshot({ n: 2 });
      const target = { root: doc, counts: doc.counts, severity: doc.counts.severity, action: doc.actions[0], hit: doc.actions[0].hits[0] }[where];
      const text = JSON.stringify(doc).replace(JSON.stringify(target), (m) => `{${JSON.stringify(name)}:${JSON.stringify(CANARY)},${m.slice(1)}`);
      if (n++ % 15 === 14) later(HOUR + 1);
      const res = await post(e, tok, text, { raw: true });
      const out = await res.text();
      assert.equal(res.status, 422, `${name} in ${where}: ${out}`);
      assert.equal(JSON.parse(out).reason, "unknown_key", `${name} in ${where}`);
      assert.doesNotMatch(out, new RegExp(`${CANARY}|${name}`), `${name} in ${where} is echoed`);
    }
  }
  assert.equal(all(e, "SELECT * FROM pushes").length, 0);
});

test("a push is stored for the token's machine and organisation, and a repeat is only noted", async () => {
  const e = await stand();
  const o = org(e), other = org(e, "Other");
  const a = machine(e, o), b = machine(e, other);
  const body = snapshot({ n: 3, at: unix() });
  let r = await pushed(e, a.tok, body);
  assert.equal(r.body.status, "stored");
  const row = one(e, "SELECT * FROM pushes");
  assert.equal(row.machine_id, a.id);
  assert.equal(row.org_id, o);
  assert.equal(row.seq, 1);
  assert.deepEqual([row.flagged, row.ignored, row.omitted, row.unread, row.critical, row.high, row.medium],
                   [3, 2, 0, 0, 0, 3, 0]);
  assert.equal(row.window_days, 30);
  assert.equal(row.version, "0.8.0");
  assert.deepEqual(JSON.parse(row.rules), { "cred.read": 3 });
  assert.deepEqual(JSON.parse(row.agents), { "claude-code": 3 });
  assert.deepEqual(JSON.parse(row.scanned), { "claude-code": 5 });
  assert.deepEqual(JSON.parse(row.actions), normalise(validate(body, unix()).value).actions);
  assert.match(row.digest, /^[0-9a-f]{64}$/);

  // The same findings a little later: unchanged, one row, only received_at moves.
  later(120);
  r = await pushed(e, a.tok, { ...body, generated_at: iso(unix()) });
  assert.deepEqual([r.status, r.body.status], [200, "unchanged"]);
  const again = all(e, "SELECT * FROM pushes");
  assert.equal(again.length, 1);
  assert.equal(again[0].first_at, row.first_at);
  assert.ok(again[0].received_at > row.received_at);
  assert.equal(again[0].actions, row.actions);

  // The other organisation's machine is not touched by it.
  assert.equal(all(e, "SELECT * FROM pushes WHERE machine_id = ?", b.id).length, 0);

  // Changed findings: a second row, and only the latest keeps its actions.
  r = await pushed(e, a.tok, snapshot({ n: 4 }));
  assert.equal(r.body.status, "stored");
  const rows = all(e, "SELECT seq, actions FROM pushes WHERE machine_id = ? ORDER BY seq", a.id);
  assert.deepEqual(rows.map((x) => [x.seq, x.actions === null]), [[1, true], [2, false]]);

  // An older snapshot than the latest is stale, and writes nothing.
  const snap = dump(e);
  r = await pushed(e, a.tok, snapshot({ n: 5, at: unix() - 3600 }));
  assert.deepEqual([r.status, r.body.error], [409, "stale"]);
  assert.equal(all(e, "SELECT * FROM pushes").length, 2);
  assert.notEqual(snap, "");
});

test("kept: the latest in full, 30 pushes at most, 30 days of summaries, and the cron ends it all by 90", async () => {
  const e = await stand();
  const o = org(e);
  const { id, tok } = machine(e, o);
  assert.deepEqual({ ...RETENTION.plus }, { days: 30, snapshots: 30 });
  for (let i = 1; i <= 35; i++) {
    if (i % 15 === 0) later(HOUR + 5);
    const r = await pushed(e, tok, snapshot({ n: i }));
    assert.equal(r.status, 200, JSON.stringify(r.body));
    assert.equal(r.body.keeps.snapshots, 30);
  }
  const rows = all(e, "SELECT seq, actions FROM pushes WHERE machine_id = ? ORDER BY seq", id);
  assert.equal(rows.length, 30);
  assert.equal(rows[0].seq, 6);
  assert.deepEqual(rows.filter((r) => r.actions !== null).map((r) => r.seq), [35]);

  // 31 days on, a new push deletes the summaries older than 30 days but keeps the latest.
  later(31 * DAY);
  const r = await pushed(e, tok, snapshot({ n: 36 }));
  assert.equal(r.status, 200);
  assert.deepEqual(all(e, "SELECT seq FROM pushes WHERE machine_id = ? ORDER BY seq", id).map((x) => x.seq), [36]);

  // Nothing is kept past 90 days, the latest included.
  later(80 * DAY);
  await sweep(e);
  assert.equal(all(e, "SELECT * FROM pushes").length, 1);
  later(11 * DAY);
  await sweep(e);
  assert.equal(all(e, "SELECT * FROM pushes").length, 0);
});

test("the cron trims what an old run of the code left: summaries past 30 days, lists on earlier pushes", async () => {
  const e = await stand();
  const o = org(e);
  const { id } = machine(e, o);
  const t = unix();
  const put = (seq, received, actions) => run(e,
    `INSERT INTO pushes (id, machine_id, org_id, seq, first_at, received_at, generated_at, digest, version, window_days,
       flagged, ignored, omitted, unread, critical, high, medium, rules, agents, scanned, actions)
     VALUES (?, ?, ?, ?, ?, ?, ?, 'd', '0.8.0', 30, 1, 0, 0, 0, 0, 1, 0, '{}', '{}', '{}', ?)`,
    randomUUID(), id, o, seq, received, received, received, actions);
  put(1, t - 40 * DAY, "[]");
  put(2, t - 10 * DAY, "[]");
  put(3, t - 40 * DAY, "[]");   // the latest, old but within 90 days: kept
  await sweep(e);
  const rows = all(e, "SELECT seq, actions FROM pushes ORDER BY seq");
  assert.deepEqual(rows.map((r) => [r.seq, r.actions]), [[2, null], [3, "[]"]]);
});

test("limits: an hour, a day, an organisation, the account, and a busy network", async () => {
  const e = await stand();
  const o = org(e);
  const a = machine(e, o), b = machine(e, o);
  for (let i = 1; i <= PUSH_LIMITS.PER_MACHINE_HOUR; i++) {
    const r = await pushed(e, a.tok, snapshot({ n: i }));
    assert.equal(r.status, 200, `${i}: ${JSON.stringify(r.body)}`);
  }
  let r = await pushed(e, a.tok, snapshot({ n: 21 }));
  assert.deepEqual([r.status, r.body.error], [429, "rate_limited"]);
  assert.ok(Number(r.headers.get("retry-after")) >= 60);
  const counted = JSON.stringify(all(e, "SELECT * FROM throttle ORDER BY key"));
  await pushed(e, a.tok, snapshot({ n: 22 }));
  assert.equal(JSON.stringify(all(e, "SELECT * FROM throttle ORDER BY key")), counted, "a refused push counts nothing more");
  // Another machine of the same organisation is not held by it.
  r = await pushed(e, b.tok, snapshot());
  assert.equal(r.status, 200);
  // A malformed body costs the same quota.
  for (let i = 0; i < PUSH_LIMITS.PER_MACHINE_HOUR; i++) await pushed(e, b.tok, "{", { raw: true });
  r = await pushed(e, b.tok, snapshot({ n: 2 }));
  assert.equal(r.status, 429);

  // The hour turns over; the day's 120 hold.
  const c = machine(e, o);
  for (let h = 0; h < 6; h++) {
    for (let i = 0; i < PUSH_LIMITS.PER_MACHINE_HOUR; i++) {
      const out = await pushed(e, c.tok, snapshot({ n: (i % 7) + 1, extra: {} }));
      assert.ok([200, 429].includes(out.status), String(out.status));
    }
    later(HOUR + 1);
  }
  r = await pushed(e, c.tok, snapshot({ n: 9 }));
  assert.deepEqual([r.status, r.body.error], [429, "rate_limited"], "the day's cap");
  later(DAY);
  r = await pushed(e, c.tok, snapshot({ n: 9 }));
  assert.equal(r.status, 200);
});

test("limits: the organisation's and the account's day give back what an earlier count took", async () => {
  const e = await stand();
  const o = org(e);
  const a = machine(e, o);
  const { mac } = await import("../src/session.js");
  const key = async (kind, who) => `${kind}:${await mac(e, `throttle:${kind}:${who}`)}`;
  const seed = async (kind, who, count) => run(e,
    "INSERT INTO throttle (key, window_start, count) VALUES (?, ?, ?)", await key(kind, who), unix(), count);
  await seed("push-org-day", o, PUSH_LIMITS.PER_ORG_DAY);
  let r = await pushed(e, a.tok, snapshot());
  assert.deepEqual([r.status, r.body.error], [429, "rate_limited"]);
  const count = async (kind, who) => (one(e, "SELECT count FROM throttle WHERE key = ?", await key(kind, who)) || { count: 0 }).count;
  assert.equal(await count("push-m-hour", a.id), 0, "the machine's hour is given back");
  assert.equal(await count("push-m-day", a.id), 0, "and its day");
  run(e, "DELETE FROM throttle");
  await seed("push-all-day", "all", PUSH_LIMITS.ALL_DAY);
  r = await pushed(e, a.tok, snapshot());
  assert.deepEqual([r.status, r.body.error], [429, "rate_limited"]);
  assert.equal(await count("push-org-day", o), 0, "the organisation's day is given back");
});

test("a burst from one network is turned away before the database is touched", async () => {
  const calls = [];
  const e = await stand({ PUSH_RL: { limit: async () => ({ success: false }) } });
  const o = org(e);
  const { tok } = machine(e, o);
  const real = e.LIST.prepare;
  e.LIST = { ...e.LIST, sql: e.LIST.sql, prepare: (sql) => { calls.push(sql); return real(sql); }, batch: e.LIST.batch };
  const r = await pushed(e, tok, snapshot());
  assert.deepEqual([r.status, r.body.error], [429, "rate_limited"]);
  assert.deepEqual(calls, []);
  // A limiter that throws lets it through: the counts in D1 still hold.
  const e2 = await stand({ PUSH_RL: { limit: async () => { throw new Error("down"); } } });
  const t2 = machine(e2, org(e2));
  assert.equal((await pushed(e2, t2.tok, snapshot())).status, 200);
});

test("an organisation holds 200 pushing machines at most; one already pushing still pushes", async () => {
  const e = await stand();
  const o = org(e);
  const first = machine(e, o);
  assert.equal((await pushed(e, first.tok, snapshot())).status, 200);
  const t = unix();
  const insert = e.LIST.sql.prepare(
    `INSERT INTO pushes (id, machine_id, org_id, seq, first_at, received_at, generated_at, digest, version, window_days,
       flagged, ignored, omitted, unread, critical, high, medium, rules, agents, scanned, actions)
     VALUES (?, ?, ?, 1, ?, ?, ?, 'd', '0.8.0', 30, 0, 0, 0, 0, 0, 0, 0, '{}', '{}', '{}', '[]')`);
  for (let i = 0; i < PUSH_LIMITS.MACHINES_PER_ORG - 1; i++) insert.run(randomUUID(), randomUUID(), o, t, t, t);
  const late = machine(e, o);
  const r = await pushed(e, late.tok, snapshot());
  assert.deepEqual([r.status, r.body.error], [429, "org_full"]);
  assert.equal((await pushed(e, first.tok, snapshot({ n: 2 }))).status, 200);
});

test("pushes sent at once leave one row, or consistent rows, and never a 500", async () => {
  const e = await stand();
  e.LIST = slow(e.LIST);
  e.LIST.sql.exec("SELECT 1");
  const o = org(e);
  const a = machine(e, o);
  const same = await Promise.all(Array.from({ length: 8 }, (_, i) => post(e, a.tok, snapshot({ n: 2 }), { ip: `198.51.100.${i + 20}` }).then(answer)));
  for (const r of same) assert.ok([200, 409].includes(r.status), JSON.stringify(r.body));
  for (const r of same.filter((x) => x.status === 200)) assert.ok(["stored", "unchanged"].includes(r.body.status));
  for (const r of same.filter((x) => x.status === 409)) assert.equal(r.body.error, "busy");
  assert.equal(all(e, "SELECT * FROM pushes WHERE machine_id = ? AND actions IS NOT NULL", a.id).length, 1);
  const rows = all(e, "SELECT seq FROM pushes WHERE machine_id = ? ORDER BY seq", a.id).map((r) => r.seq);
  assert.deepEqual(rows, rows.map((_, i) => rows[0] + i), "seq has no gaps");

  const b = machine(e, o);
  const different = await Promise.all(Array.from({ length: 8 }, (_, i) => post(e, b.tok, snapshot({ n: i + 1 }), { ip: `198.51.100.${i + 40}` }).then(answer)));
  for (const r of different) assert.ok([200, 409].includes(r.status), JSON.stringify(r.body));
  assert.equal(all(e, "SELECT * FROM pushes WHERE machine_id = ? AND actions IS NOT NULL", b.id).length, 1);
  const seqs = all(e, "SELECT seq FROM pushes WHERE machine_id = ?", b.id).map((r) => r.seq).sort((x, y) => x - y);
  assert.equal(new Set(seqs).size, seqs.length);
});

test("revoking a machine ends its pushes and takes what it sent with it", async () => {
  const e = await stand();
  const user = await accounts.userForVerifiedEmail(e, { email: "ana@example.com" });
  const o = await accounts.orgFor(e, user.id);
  run(e, "INSERT INTO grants (org_id, plan, starts_at, until, note, created_at) VALUES (?, 'plus', ?, NULL, 't', ?)", o.id, unix() - 60, unix());
  const a = machine(e, o.id), b = machine(e, o.id);
  for (const m of [a, b]) assert.equal((await pushed(e, m.tok, snapshot({ n: 2 }))).status, 200);

  const who = { org: { id: o.id }, user: user.id };
  assert.equal(await machines.revokeMachine(e, who, { id: a.id }), true);
  assert.equal(all(e, "SELECT * FROM pushes WHERE machine_id = ?", a.id).length, 0);
  assert.equal(all(e, "SELECT * FROM pushes WHERE machine_id = ?", b.id).length, 1);
  const r = await pushed(e, a.tok, snapshot());
  assert.deepEqual([r.status, r.body.error], [403, "token_refused"]);

  // ranwhat logout, over the feed host.
  const out = await worker.fetch(new Request(`${FEED}/v1/logout`, { method: "POST", headers: { authorization: `Bearer ${b.tok}` } }), e, ctx);
  assert.equal(out.status, 200);
  assert.equal(all(e, "SELECT * FROM pushes").length, 0);

  // A token ended some other way: hidden at once, deleted by the next sweep.
  const c = machine(e, o.id);
  await pushed(e, c.tok, snapshot());
  run(e, "UPDATE tokens SET revoked_at = ? WHERE hash = ?", unix(), sha(c.tok));
  assert.equal(all(e, "SELECT * FROM pushes").length, 1);
  await sweep(e);
  assert.equal(all(e, "SELECT * FROM pushes").length, 0);

  // An idle terminal revoked by the cron: its rows go in the same run.
  const d = machine(e, o.id);
  await pushed(e, d.tok, snapshot());
  run(e, "UPDATE machines SET last_used_day = ? WHERE id = ?", unix() - 100 * DAY, d.id);
  await sweep(e);
  await sweep(e);
  assert.equal(all(e, "SELECT * FROM pushes").length, 0);
});

test("entitledWho refuses as entitled does, and entitled's answer is unchanged", async () => {
  const e = await stand();
  const free = machine(e, org(e, "F", "free")), plus = machine(e, org(e, "P", "plus"));
  const req = (tok) => new Request(`${FEED}/v1/push`, { headers: { authorization: `Bearer ${tok}` } });
  const refusedFree = await entitled(req(free.tok), e, "push");
  assert.deepEqual(refusedFree, await entitledWho(req(free.tok), e, "push"));
  assert.deepEqual([refusedFree.ok, refusedFree.status, refusedFree.error], [false, 403, "plus_required"]);
  const ok = await entitled(req(plus.tok), e, "push");
  assert.deepEqual(Object.keys(ok), ["ok", "account"]);
  const who = await entitledWho(req(plus.tok), e, "push");
  assert.equal(who.ok, true);
  assert.equal(who.who.machine.id, plus.id);
  assert.deepEqual(await entitledWho(new Request(`${FEED}/x`), e, "push"), await identify(new Request(`${FEED}/x`), e));
});

test("nothing from a body, a token, an organisation or a machine is logged", async () => {
  const e = await stand();
  const o = org(e, "Logged Org");
  const { tok } = machine(e, o, "device", "Logged laptop");
  const lines = [];
  const real = console.log;
  console.log = (...args) => { lines.push(args.join(" ")); };
  try {
    await pushed(e, tok, snapshot());
    const bad = snapshot();
    bad.actions[0].id = CANARY;
    await pushed(e, tok, bad);
    await pushed(e, tok, "{" + CANARY, { raw: true });
    await pushed(e, madeToken(), snapshot());
    await pushed(e, tok, snapshot({ n: 3 }), { headers: { "content-type": "text/plain" } });
    // A database that throws.
    const broken = { ...e, LIST: { ...e.LIST, prepare: (sql) => { if (/FROM pushes/.test(sql)) throw new Error(`${CANARY} ${tok}`); return e.LIST.prepare(sql); } } };
    const r = await pushed(broken, tok, snapshot({ n: 4 }));
    assert.deepEqual([r.status, r.body.error], [503, "unavailable"]);
  } finally {
    console.log = real;
  }
  const out = lines.join("\n");
  assert.doesNotMatch(out, new RegExp(`${CANARY}|${tok}|Logged Org|Logged laptop|${SECRET}`));
});

/* ---------- the page ---------- */

const SESSION = "__Host-rw_session";

async function signedIn(e, { email = "ana@example.com", plan = "plus" } = {}) {
  const user = await accounts.userForVerifiedEmail(e, { email });
  const o = await accounts.orgFor(e, user.id);
  if (plan !== "free") {
    run(e, "INSERT INTO grants (org_id, plan, starts_at, until, note, created_at) VALUES (?, ?, ?, NULL, 't', ?)", o.id, plan, unix() - 60, unix());
  }
  const { value, statements } = await openSession(e, { user: user.id, org: o.id });
  await e.LIST.batch(statements);
  const get = async (path, cookie = value) => {
    const res = await worker.fetch(new Request(`https://account.ranwhat.com${path}`, { headers: { cookie: `${SESSION}=${cookie}` } }), e, ctx);
    return { status: res.status, text: await res.text(), headers: res.headers, location: res.headers.get("location") };
  };
  return { user, org: o.id, get, cookie: value };
}

test("the page: signed out goes to sign in, a free organisation sees a locked card and no data", async () => {
  const e = await stand();
  const out = await worker.fetch(new Request("https://account.ranwhat.com/findings"), e, ctx);
  assert.equal(out.status, 303);
  assert.match(out.headers.get("location"), /^\/signin/);

  const s = await signedIn(e, { plan: "free" });
  const m = machine(e, s.org, "device", "freelaptop-marker");
  run(e, `INSERT INTO pushes (id, machine_id, org_id, seq, first_at, received_at, generated_at, digest, version, window_days,
            flagged, ignored, omitted, unread, critical, high, medium, rules, agents, scanned, actions)
          VALUES ('x', ?, ?, 1, ?, ?, ?, 'd', '0.8.0', 30, 777, 0, 0, 0, 777, 0, 0, '{"cred.read":777}', '{}', '{}', '[]')`,
      m.id, s.org, unix(), unix(), unix());
  const page = await s.get("/findings");
  assert.equal(page.status, 200);
  assert.match(page.text, /class="card locked"[^>]*id="findings" data-feature="machines"|id="findings" data-feature="machines"/);
  assert.match(page.text, /Cross-machine view/);
  assert.match(page.text, /Push/);
  assert.match(page.text, /href="\/upgrade">Upgrade to Plus/);
  assert.doesNotMatch(page.text, /freelaptop-marker|777/);
  // A free member who is not a manager is not offered the button.
  const nav = page.text.match(/<nav class="nav"[\s\S]*?<\/nav>/)[0];
  assert.match(nav, /href="\/findings"[^>]*>[\s\S]*?Findings/);
});

test("the page, on Plus: empty, then two machines side by side, the rules, the newest, and one machine", async () => {
  const e = await stand();
  const s = await signedIn(e);
  let page = await s.get("/findings");
  assert.equal(page.status, 200);
  assert.match(page.text, /No machines linked yet/);
  assert.match(page.text, /uvx ranwhat login/);
  assert.match(page.text, /uvx ranwhat push --dry-run/);

  const dev = machine(e, s.org, "device", "Work laptop"), ci = machine(e, s.org, "ci", "Build runner"), idle = machine(e, s.org, "device", "Idle box");
  page = await s.get("/findings");
  assert.match(page.text, /No machine has pushed yet/);

  const t = unix();
  const a = snapshot({ n: 2, at: t - 600 });
  a.counts.severity = { critical: 1, high: 1, medium: 0 };
  a.actions[0].hits = [{ rule: "cred.read", severity: "critical" }, { rule: "publish", severity: "high" }];
  a.counts.rules = { "cred.read": 2, publish: 1 };
  assert.equal((await pushed(e, dev.tok, a)).status, 200);
  const b = snapshot({ n: 1, at: t - 120 });
  b.counts.rules = { "git.destructive": 1 };
  b.actions[0] = { id: "00000000000000ff", agent: "codex", at: null, hits: [{ rule: "git.destructive", severity: "medium" }] };
  b.counts.agents = { codex: 1 };
  b.counts.severity = { critical: 0, high: 0, medium: 1 };
  assert.equal((await pushed(e, ci.tok, b)).status, 200);

  page = await s.get("/findings");
  assert.equal(page.status, 200);
  const text = page.text;
  assert.match(text, /Machines pushing<\/span><span class="stat-v">2<\/span><span class="stat-s">of 3 linked/);
  assert.match(text, /Work laptop/);
  assert.match(text, /Build runner/);
  assert.match(text, /Never pushed/);
  assert.match(text, /Idle box/);
  assert.match(text, /Credential material accessed/);
  assert.match(text, /Destructive git operation/);
  assert.match(text, /Rules across machines/);
  assert.match(text, /Newest findings/);
  // Newest first, a missing time last; the ids are there to be ignored.
  const ids = [...text.matchAll(/<code>([0-9a-f]{16})<\/code>/g)].map((m) => m[1]);
  assert.deepEqual(ids, [hexid(1), hexid(2), "00000000000000ff"]);
  assert.match(text, /No time/);
  assert.match(text, /Claude Code/);
  assert.match(text, /ranwhat ignore ID/);
  assert.match(text, /30\s+days, 30 at most, and nothing older/);
  assert.doesNotMatch(text, /13 months|13-month|a year of/i);
  // Any member sees it; the page has no form but sign out and the switcher.
  assert.doesNotMatch(text, /name="label"|\/tokens\/ci/);

  // One machine.
  page = await s.get(`/findings?machine=${dev.id}`);
  assert.equal(page.status, 200);
  assert.match(page.text, /Recent pushes/);
  assert.match(page.text, /actions of older pushes are not kept/);
  assert.match(page.text, /Work laptop/);
  page = await s.get(`/findings?machine=${idle.id}`);
  assert.equal(page.status, 200);
  assert.match(page.text, /has not pushed yet/);

  // Another organisation's machine, an unknown one and a hostile one are the same 404.
  const other = org(e, "Other");
  const foreign = machine(e, other);
  const wrong = [];
  for (const id of [foreign.id, randomUUID(), "<script>alert(1)</script>"]) {
    const r = await s.get(`/findings?machine=${encodeURIComponent(id)}`);
    assert.equal(r.status, 404, id);
    assert.doesNotMatch(r.text, /<script>alert|alert\(1\)/);
    wrong.push(r.text.replace(/<time[^>]*>[^<]*<\/time>/g, ""));
  }
  assert.equal(new Set(wrong).size, 1, "one page for every machine that is not this organisation's");

  // Revoked: gone from the page at once, before anything is deleted.
  run(e, "UPDATE tokens SET revoked_at = ? WHERE hash = ?", unix(), sha(ci.tok));
  page = await s.get("/findings");
  assert.doesNotMatch(page.text, /Build runner/);
  assert.match(page.text, /of 2 linked/);
  assert.equal((await s.get(`/findings?machine=${ci.id}`)).status, 404);
});

test("the page escapes what it draws, trusts nothing stored, and carries the policy every account page has", async () => {
  const e = await stand();
  const s = await signedIn(e);
  run(e, "UPDATE orgs SET name = ? WHERE id = ?", "<img src=x onerror=alert(1)>", s.org);
  const m = machine(e, s.org, "device", "<script>alert(1)</script>");
  assert.equal((await pushed(e, m.tok, snapshot({ n: 2 }))).status, 200);
  let page = await s.get("/findings");
  assert.equal(page.status, 200);
  assert.doesNotMatch(page.text, /<script>alert|<img src=x/);
  assert.match(page.text, /&lt;script&gt;alert\(1\)&lt;\/script&gt;/);

  // Rows written straight to D1 by anything else.
  const hostile = JSON.stringify([
    { id: "<b>x</b>", agent: "claude-code", at: iso(unix()), hits: [{ rule: "cred.read", severity: "high" }] },
    { id: "0123456789abcdef", agent: "<script>", at: "<b>", hits: [{ rule: "<i>nope</i>", severity: "high" }, { rule: "cred.read", severity: "<u>" }] },
    { id: "fedcba9876543210", agent: "constructor", at: iso(unix()), hits: [{ rule: "__proto__", severity: "critical" }] },
    "text", null, 5,
  ]);
  run(e, `UPDATE pushes SET rules = ?, agents = ?, scanned = ?, actions = ?, flagged = '1e999', critical = '<b>', high = ?, medium = -4,
            ignored = 1.5, window_days = 'x', version = ? WHERE machine_id = ?`,
      '{"<script>alert(1)</script>": 4, "cred.read": "1e999", "publish": 3, "toString": 2}', '{"<b>": 1}', "not json", hostile,
      99999999999999, "<script>9.9.9</script>", m.id);
  page = await s.get("/findings");
  assert.equal(page.status, 200);
  const focus = await s.get(`/findings?machine=${m.id}`);
  assert.equal(focus.status, 200);
  for (const p of [page, focus]) {
    const hit = /<script|<img|<b>|<u>|<i>nope|1e999/.exec(p.text);
    assert.equal(hit, null, hit && p.text.slice(Math.max(0, hit.index - 80), hit.index + 80));
    const names = [...p.text.matchAll(/<[a-z][a-z0-9]*((?:\s+[a-z:-]+(?:="[^"]*")?)*)\s*\/?>/g)]
      .flatMap((m) => [...m[1].replace(/="[^"]*"/g, "").matchAll(/\s+([a-z:-]+)/g)].map((x) => x[1]));
    assert.ok(names.length > 20);
    assert.deepEqual(names.filter((n) => n.startsWith("on") || n === "style"), [], "an event handler or inline style");
    assert.match(p.text, /an unknown (rule|agent)/);
  }
  assert.match(page.text, /0123456789abcdef/);
  assert.doesNotMatch(page.text, /&lt;b&gt;x/);

  // The same headers as the page beside it.
  const machinesPage = await s.get("/machines");
  const csp = page.headers.get("content-security-policy");
  assert.equal(csp, machinesPage.headers.get("content-security-policy"));
  assert.doesNotMatch(csp, /script-src|unsafe-inline|unsafe-eval|data:/);
  assert.match(csp, /default-src 'none'/);
  assert.equal(page.headers.get("cache-control"), "no-store");
  assert.equal(page.headers.get("x-frame-options"), "DENY");
});

test("the page is the organisation's alone, for every member, and follows a switch", async () => {
  const e = await stand();
  const ana = await signedIn(e, { email: "ana@example.com" });
  const ben = await signedIn(e, { email: "ben@example.com" });
  const am = machine(e, ana.org, "device", "ana-box-marker");
  assert.equal((await pushed(e, am.tok, snapshot({ n: 2 }))).status, 200);
  assert.match((await ana.get("/findings")).text, /ana-box-marker/);
  assert.doesNotMatch((await ben.get("/findings")).text, /ana-box-marker/);
  // Ben, a plain member of Ana's organisation, reads it too, looking at it.
  run(e, "INSERT INTO memberships (org_id, user_id, role, created_at) VALUES (?, ?, 'member', ?)", ana.org, ben.user.id, unix());
  const { value, statements } = await openSession(e, { user: ben.user.id, org: ana.org });
  await e.LIST.batch(statements);
  const asMember = await ben.get("/findings", value);
  assert.equal(asMember.status, 200);
  assert.match(asMember.text, /ana-box-marker/);
  assert.match(asMember.text, /Everyone in/);
  // Back in his own organisation, nothing of hers.
  assert.doesNotMatch((await ben.get("/findings")).text, /ana-box-marker/);
});
