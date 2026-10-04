/* The release list end to end: the Worker's own fetch and scheduled handlers,
 * over a real SQLite database (node:sqlite, which is what D1 runs) and a
 * stand-in for the email binding that records what it was asked to send.
 *
 *     node --test worker/test/
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { register } from "node:module";
import { DatabaseSync } from "node:sqlite";

/* index.js imports cloudflare:email, which only exists on Workers. */
register("data:text/javascript," + encodeURIComponent(`
  export async function resolve(spec, ctx, next) {
    if (spec === "cloudflare:email") {
      return { shortCircuit: true, url: "data:text/javascript," + encodeURIComponent(
        "export class EmailMessage { constructor(f, t, r) { this.from = f; this.to = t; this.raw = r; } }") };
    }
    return next(spec, ctx);
  }`));
const worker = (await import("../src/index.js")).default;
const list = await import("../src/list.js");

/* ---------- stand-ins ---------- */

function d1() {
  const db = new DatabaseSync(":memory:");
  const statement = (sql, params = []) => ({
    bind: (...p) => statement(sql, p),
    first: async () => { const r = db.prepare(sql).get(...params); return r ? { ...r } : null; },
    all: async () => ({ results: db.prepare(sql).all(...params).map((r) => ({ ...r })) }),
    run: async () => ({ meta: { changes: Number(db.prepare(sql).run(...params).changes) } }),
    now: () => db.prepare(sql).run(...params),
  });
  return {
    sql: db,
    prepare: (sql) => statement(sql),
    batch: async (statements) => {
      db.exec("BEGIN");
      try {
        const out = statements.map((s) => ({ meta: { changes: Number(s.now().changes) } }));
        db.exec("COMMIT");
        return out;
      } catch (err) {
        db.exec("ROLLBACK");
        throw err;
      }
    },
  };
}

function mailer() {
  const m = { sent: [], failWith: null, failAfter: Infinity };
  m.send = async (message) => {
    if (m.failWith && m.sent.length >= m.failAfter) {
      throw Object.assign(new Error("refused"), { code: m.failWith });
    }
    m.sent.push(message);
    return { messageId: `m${m.sent.length}` };
  };
  return m;
}

const SECRET = "a-test-secret-that-is-long-enough-1234567890";

function env(extra = {}) {
  return { LIST: d1(), LIST_EMAIL: mailer(), CONTACT_EMAIL: mailer(),
           LIST_SECRET: SECRET, TURNSTILE_SECRET: "ts", ...extra };
}

/* siteverify, answering for whichever action the test says the token is for */
function challenge(action = "subscribe", success = true) {
  globalThis.fetch = async (url) => {
    assert.match(String(url), /challenges\.cloudflare\.com/);
    return new Response(JSON.stringify({ success, hostname: "ranwhat.com", action }));
  };
}

const ctx = { waitUntil() {} };

async function post(e, path, body, type = "application/json") {
  return worker.fetch(new Request(`https://ranwhat.com${path}`, {
    method: "POST", headers: { "content-type": type, "cf-connecting-ip": "203.0.113.9" },
    body: typeof body === "string" ? body : JSON.stringify(body),
  }), e, ctx);
}

const get = (e, url) => worker.fetch(new Request(url), e, ctx);
const linkIn = (text, path) => text.match(new RegExp(`https://ranwhat\\.com${path}\\?[^\\s"<]+`))[0];
const rows = (e) => e.LIST.sql.prepare("SELECT * FROM subscribers").all();

async function signUp(e, address = "Reader@Example.com") {
  challenge("subscribe");
  const res = await post(e, "/api/subscribe", { email: address, "cf-turnstile-response": "tok" });
  assert.equal(res.status, 200);
  assert.deepEqual(await res.json(), { ok: true });
}

async function signUpAndConfirm(e, address) {
  const before = e.LIST_EMAIL.sent.length;
  await signUp(e, address);
  const link = linkIn(e.LIST_EMAIL.sent[before].text, "/api/confirm");
  const res = await post(e, new URL(link).pathname + new URL(link).search, "", "application/x-www-form-urlencoded");
  assert.equal(res.status, 200);
}

function feed(items) {
  const body = items.map((i) => `  <item>
    <title>${i.title}</title>
    <link>https://ranwhat.com/updates#${i.id}</link>
    <guid isPermaLink="true">https://ranwhat.com/updates#${i.id}</guid>
    <pubDate>${new Date(i.at * 1000).toUTCString()}</pubDate>
    <description>&lt;ul&gt;&lt;li&gt;&lt;span class="icode"&gt;check&lt;/span&gt; got faster&lt;/li&gt;&lt;/ul&gt;</description>
  </item>`).join("\n");
  const xml = `<?xml version="1.0" encoding="UTF-8"?>\n<rss version="2.0"><channel>\n${body}\n</channel></rss>`;
  return async () => new Response(xml);
}

const now = () => Math.floor(Date.now() / 1000);

/* ---------- switched off ---------- */

test("without the secret, the signup says so and no link is ever signed", async () => {
  for (const secret of [undefined, "short"]) {
    const e = env({ LIST_SECRET: secret });
    challenge();
    const res = await post(e, "/api/subscribe", { email: "a@example.com", "cf-turnstile-response": "tok" });
    assert.equal(res.status, 503);
    assert.match((await res.json()).error, /not switched on/);
    assert.equal((await get(e, "https://ranwhat.com/api/confirm?id=x&at=1&t=y")).status, 503);
    assert.equal((await get(e, "https://ranwhat.com/api/unsubscribe?id=x&t=y")).status, 503);
    await list.announce(e, feed([{ id: "v9", title: "x", at: now() }]));
    assert.equal(e.LIST_EMAIL.sent.length, 0);
  }
});

/* ---------- on ---------- */

test("a signup is stored unconfirmed and gets one confirmation email", async () => {
  const e = env();
  await signUp(e);
  const [row] = rows(e);
  assert.equal(row.email, "reader@example.com");
  assert.equal(row.confirmed_at, null);
  const [mail] = e.LIST_EMAIL.sent;
  assert.equal(mail.to, "reader@example.com");
  assert.deepEqual(mail.from, { email: "updates@ranwhat.com", name: "ranwhat" });
  const link = linkIn(mail.text, "/api/confirm");
  assert.ok(!link.includes("example.com"), "the link carries an id, not the address");
  assert.equal(linkIn(mail.html, "/api/confirm"), link);

  // Again at once: same answer, no second email, one row.
  await signUp(e, "reader@example.com");
  assert.equal(e.LIST_EMAIL.sent.length, 1);
  assert.equal(rows(e).length, 1);
});

test("a confirmation link shows a button, and only the button confirms", async () => {
  const e = env();
  await signUp(e);
  const link = linkIn(e.LIST_EMAIL.sent[0].text, "/api/confirm");

  const page = await get(e, link);
  assert.equal(page.status, 200);
  const html = await page.text();
  assert.match(html, /<form method="post"/);
  assert.equal(rows(e)[0].confirmed_at, null, "opening the link confirms nothing");
  assert.match(page.headers.get("content-security-policy"), /default-src 'none'/);
  assert.equal(page.headers.get("referrer-policy"), "no-referrer");

  const u = new URL(link);
  const res = await post(e, u.pathname + u.search, "", "application/x-www-form-urlencoded");
  assert.equal(res.status, 200);
  assert.match(await res.text(), /on the list/);
  assert.ok(rows(e)[0].confirmed_at > 0);

  // Confirmed: signing up again sends nothing.
  await signUp(e);
  assert.equal(e.LIST_EMAIL.sent.length, 1);
});

test("a tampered, foreign or expired confirmation link confirms nobody", async () => {
  const e = env();
  await signUp(e);
  const link = new URL(linkIn(e.LIST_EMAIL.sent[0].text, "/api/confirm"));

  const tampered = new URL(link);
  tampered.searchParams.set("t", link.searchParams.get("t").replace(/^./, (c) => (c === "A" ? "B" : "A")));
  const later = new URL(link);
  later.searchParams.set("at", String(Number(link.searchParams.get("at")) + 1));
  const other = env({ LIST_SECRET: SECRET.replace("test", "else") });

  for (const [where, url] of [[e, tampered], [e, later], [other, link]]) {
    const res = await post(where, url.pathname + url.search, "", "application/x-www-form-urlencoded");
    assert.equal(res.status, 400);
  }
  assert.equal(rows(e)[0].confirmed_at, null);

  const realNow = Date.now;
  Date.now = () => realNow() + 8 * 24 * 3600 * 1000;
  try {
    assert.equal((await post(e, link.pathname + link.search, "")).status, 400);
  } finally {
    Date.now = realNow;
  }
});

test("the signup checks the challenge, for this form, before storing anything", async () => {
  const e = env();
  challenge("contact");
  let res = await post(e, "/api/subscribe", { email: "a@example.com", "cf-turnstile-response": "tok" });
  assert.equal(res.status, 403);
  challenge("subscribe", false);
  res = await post(e, "/api/subscribe", { email: "a@example.com", "cf-turnstile-response": "tok" });
  assert.equal(res.status, 403);
  res = await post(e, "/api/subscribe", { email: "a@example.com" });
  assert.equal(res.status, 400);
  res = await post(e, "/api/subscribe", { email: "not an address", "cf-turnstile-response": "tok" });
  assert.equal(res.status, 400);
  assert.equal(e.LIST_EMAIL.sent.length, 0);
  assert.equal(e.LIST.sql.prepare("SELECT name FROM sqlite_master WHERE name = 'subscribers'").all().length
    ? rows(e).length : 0, 0);
});

test("a confirmation email that fails lets the next try through at once", async () => {
  const e = env();
  e.LIST_EMAIL.failWith = "E_INTERNAL_SERVER_ERROR";
  e.LIST_EMAIL.failAfter = 0;
  challenge();
  const res = await post(e, "/api/subscribe", { email: "a@example.com", "cf-turnstile-response": "tok" });
  assert.equal(res.status, 502);
  e.LIST_EMAIL.failWith = null;
  await signUp(e, "a@example.com");
  assert.equal(e.LIST_EMAIL.sent.length, 1);
});

/* ---------- releases ---------- */

test("the first run sends nothing; a new release goes to everyone confirmed, once", async () => {
  const e = env();
  await signUpAndConfirm(e, "one@example.com");
  await signUpAndConfirm(e, "two@example.com");
  await signUp(e, "pending@example.com");
  const confirmations = e.LIST_EMAIL.sent.length;

  const old = [{ id: "v0-5-0", title: "ranwhat 0.5.0: Twelve coding agents", at: now() - 3600 }];
  await list.announce(e, feed(old));
  assert.equal(e.LIST_EMAIL.sent.length, confirmations, "what was already published is not news");

  const fresh = [{ id: "v0-6-0", title: "ranwhat 0.6.0: Cursor", at: now() }, ...old];
  await list.announce(e, feed(fresh));
  const sent = e.LIST_EMAIL.sent.slice(confirmations);
  assert.deepEqual(sent.map((m) => m.to).sort(), ["one@example.com", "two@example.com"]);
  for (const m of sent) {
    assert.equal(m.subject, "ranwhat 0.6.0: Cursor");
    assert.match(m.headers["List-Unsubscribe"], /^<https:\/\/ranwhat\.com\/api\/unsubscribe\?id=[0-9a-f-]{36}&t=[\w-]+>$/);
    assert.equal(m.headers["List-Unsubscribe-Post"], "List-Unsubscribe=One-Click");
    assert.match(m.html, /<code style="[^"]+">check<\/code>/);
    assert.match(m.text, /- check got faster/);
  }

  await list.announce(e, feed(fresh));
  assert.equal(e.LIST_EMAIL.sent.length, confirmations + 2, "nobody gets it twice");

  // Someone who confirms after the release appeared does not get it.
  await signUpAndConfirm(e, "late@example.com");
  const count = e.LIST_EMAIL.sent.length;
  await list.announce(e, feed(fresh));
  assert.equal(e.LIST_EMAIL.sent.length, count);
});

test("a long list goes out a batch per run, and a stopped run resumes", async () => {
  const e = env();
  e.LIST.sql.exec(`CREATE TABLE IF NOT EXISTS subscribers (id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE,
    created_at INTEGER NOT NULL, mailed_at INTEGER NOT NULL, confirmed_at INTEGER)`);
  const insert = e.LIST.sql.prepare("INSERT INTO subscribers VALUES (?, ?, 1, 1, 1)");
  const n = 2 * list.BATCH + 7;
  for (let i = 0; i < n; i++) insert.run(crypto.randomUUID(), `r${i}@example.com`);

  const old = [{ id: "v1", title: "old", at: now() - 60 }];
  await list.announce(e, feed(old));
  const items = [{ id: "v2", title: "new", at: now() }, ...old];

  e.LIST_EMAIL.failWith = "E_DAILY_LIMIT_EXCEEDED";
  e.LIST_EMAIL.failAfter = 50;
  await list.announce(e, feed(items));
  assert.equal(e.LIST_EMAIL.sent.length, 50, "stops at the daily limit");

  e.LIST_EMAIL.failWith = null;
  await list.announce(e, feed(items));
  assert.equal(e.LIST_EMAIL.sent.length, 50 + list.BATCH, "one batch a run");
  await list.announce(e, feed(items));
  assert.equal(e.LIST_EMAIL.sent.length, n, "the rest");
  assert.equal(new Set(e.LIST_EMAIL.sent.map((m) => m.to)).size, n, "each address once");
  await list.announce(e, feed(items));
  assert.equal(e.LIST_EMAIL.sent.length, n);
});

test("a suppressed address is skipped rather than holding up the rest", async () => {
  const e = env();
  await signUpAndConfirm(e, "a@example.com");
  await signUpAndConfirm(e, "b@example.com");
  const before = e.LIST_EMAIL.sent.length;
  await list.announce(e, feed([{ id: "v1", title: "old", at: now() - 60 }]));
  const real = e.LIST_EMAIL.send;
  e.LIST_EMAIL.send = async (m) => {
    if (m.to === "a@example.com") throw Object.assign(new Error("suppressed"), { code: "E_RECIPIENT_SUPPRESSED" });
    return real(m);
  };
  const items = [{ id: "v2", title: "new", at: now() }, { id: "v1", title: "old", at: now() - 60 }];
  await list.announce(e, feed(items));
  assert.deepEqual(e.LIST_EMAIL.sent.slice(before).map((m) => m.to), ["b@example.com"]);
  const done = e.LIST.sql.prepare("SELECT done_at FROM releases WHERE guid LIKE '%v2'").get();
  assert.ok(done.done_at > 0);
});

test("a release that first appears weeks after it was published is not sent", async () => {
  const e = env();
  await signUpAndConfirm(e, "a@example.com");
  const before = e.LIST_EMAIL.sent.length;
  await list.announce(e, feed([{ id: "v1", title: "old", at: now() - 60 }]));
  await list.announce(e, feed([{ id: "v0", title: "backfilled", at: now() - 30 * 24 * 3600 },
                               { id: "v1", title: "old", at: now() - 60 }]));
  assert.equal(e.LIST_EMAIL.sent.length, before);
});

/* ---------- off ---------- */

test("unsubscribing shows a button; the button, or a one-click POST, deletes the address", async () => {
  for (const oneClick of [false, true]) {
    const e = env();
    await signUpAndConfirm(e, "a@example.com");
    await list.announce(e, feed([{ id: "v1", title: "old", at: now() - 60 }]));
    await list.announce(e, feed([{ id: "v2", title: "new", at: now() }, { id: "v1", title: "old", at: now() - 60 }]));
    const mail = e.LIST_EMAIL.sent.at(-1);
    const link = mail.headers["List-Unsubscribe"].slice(1, -1);
    assert.equal(linkIn(mail.text, "/api/unsubscribe"), link);

    const page = await get(e, link);
    assert.equal(page.status, 200);
    assert.match(await page.text(), /<form method="post"/);
    assert.equal(rows(e).length, 1, "opening the link removes nobody");

    const u = new URL(link);
    const res = await post(e, u.pathname + u.search, oneClick ? "List-Unsubscribe=One-Click" : "",
      "application/x-www-form-urlencoded");
    assert.equal(res.status, 200);
    assert.equal(rows(e).length, 0);
    assert.equal(e.LIST.sql.prepare("SELECT * FROM deliveries").all().length, 0);

    const bad = new URL(link);
    bad.searchParams.set("id", crypto.randomUUID());
    assert.equal((await post(e, bad.pathname + bad.search, "")).status, 400);
  }
});

/* ---------- the rest of the Worker ---------- */

test("the contact form still sends, and the routes answer only their methods", async () => {
  const e = env();
  challenge(undefined);
  const res = await post(e, "/api/contact", { email: "w@example.com", message: "hello", about: "bug",
                                              "cf-turnstile-response": "tok" });
  assert.equal(res.status, 200);
  assert.equal(e.CONTACT_EMAIL.sent.length, 1);
  assert.equal((await get(e, "https://ranwhat.com/api/subscribe")).status, 405);
  assert.equal((await get(e, "https://ranwhat.com/api/contact")).status, 405);
  assert.equal((await get(e, "https://ranwhat.com/api/nothing")).status, 404);
});

test("nothing the list logs carries an address", async () => {
  const lines = [];
  const real = console.log;
  console.log = (...a) => lines.push(a.join(" "));
  try {
    const e = env();
    e.LIST_EMAIL.failWith = "E_INTERNAL_SERVER_ERROR";
    e.LIST_EMAIL.failAfter = 0;
    challenge();
    await post(e, "/api/subscribe", { email: "secret.person@example.com", "cf-turnstile-response": "tok" });
  } finally {
    console.log = real;
  }
  assert.ok(lines.length > 0);
  for (const line of lines) assert.doesNotMatch(line, /@|secret\.person/);
});
