/* The release list end to end: the Worker's own fetch and scheduled handlers,
 * over a real SQLite database (node:sqlite, which is what D1 runs), with
 * Turnstile and Resend's API answered by stand-ins that record what they
 * were asked.
 *
 *     node --test worker/test/list.test.mjs
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { d1 } from "./stand-ins.mjs";
const worker = (await import("../src/index.js")).default;
const list = await import("../src/list.js");

/* ---------- stand-ins ---------- */

/* Resend's API as far as the list uses it, plus Turnstile's siteverify. */
function services({ action = "subscribe", success = true } = {}) {
  const s = {
    emails: [], broadcasts: [], contacts: new Map(), segments: [], calls: [],
    fail: {},           // path prefix -> { status, name } to answer with instead
    turnstile: { action, success },
  };
  const reply = (status, body) => new Response(JSON.stringify(body), { status });
  globalThis.fetch = async (url, init = {}) => {
    const u = new URL(String(url));
    const method = init.method || "GET";
    const body = init.body ? JSON.parse(init.body) : undefined;
    if (u.hostname === "challenges.cloudflare.com") {
      return reply(200, { success: s.turnstile.success, hostname: "ranwhat.com", action: s.turnstile.action });
    }
    assert.equal(u.hostname, "api.resend.com");
    assert.match(init.headers.authorization, /^Bearer re_test/);
    const path = u.pathname;
    s.calls.push(`${method} ${path}`);
    for (const [prefix, err] of Object.entries(s.fail)) {
      if (`${method} ${path}`.startsWith(prefix)) return reply(err.status, { statusCode: err.status, name: err.name });
    }
    if (method === "POST" && path === "/emails") {
      s.emails.push(body);
      return reply(200, { id: `e${s.emails.length}` });
    }
    if (method === "GET" && path === "/segments") return reply(200, { object: "list", data: s.segments });
    if (method === "POST" && path === "/segments") {
      const seg = { id: crypto.randomUUID(), name: body.name };
      s.segments.push(seg);
      return reply(201, { object: "segment", ...seg });
    }
    if (method === "POST" && path === "/contacts") {
      if (s.contacts.has(body.email)) return reply(422, { statusCode: 422, name: "validation_error" });
      s.contacts.set(body.email, { unsubscribed: body.unsubscribed, segments: new Set(body.segments.map((x) => x.id)) });
      return reply(201, { object: "contact", id: crypto.randomUUID() });
    }
    let m = path.match(/^\/contacts\/([^/]+)$/);
    if (method === "PATCH" && m) {
      const c = s.contacts.get(decodeURIComponent(m[1]));
      if (!c) return reply(404, { statusCode: 404, name: "not_found" });
      c.unsubscribed = body.unsubscribed;
      return reply(200, { object: "contact", id: "c" });
    }
    m = path.match(/^\/contacts\/([^/]+)\/segments\/([^/]+)$/);
    if (method === "POST" && m) {
      s.contacts.get(decodeURIComponent(m[1])).segments.add(m[2]);
      return reply(200, { id: m[2] });
    }
    if (method === "POST" && path === "/broadcasts") {
      s.broadcasts.push(body);
      return reply(201, { object: "broadcast", id: `b${s.broadcasts.length}` });
    }
    return reply(404, { statusCode: 404, name: "not_found" });
  };
  return s;
}

function mailer() {
  const m = { sent: [] };
  m.send = async (message) => { m.sent.push(message); return {}; };
  return m;
}

const SECRET = "a-test-secret-that-is-long-enough-1234567890";

function env(extra = {}) {
  return { LIST: d1(), CONTACT_EMAIL: mailer(), RESEND_API_KEY: "re_test_key",
           LIST_SECRET: SECRET, TURNSTILE_SECRET: "ts", ...extra };
}

const ctx = { waitUntil() {} };

async function post(e, path, body, type = "application/json") {
  return worker.fetch(new Request(`https://ranwhat.com${path}`, {
    method: "POST", headers: { "content-type": type, "cf-connecting-ip": "203.0.113.9" },
    body: typeof body === "string" ? body : JSON.stringify(body),
  }), e, ctx);
}

const get = (e, url) => worker.fetch(new Request(url), e, ctx);
const linkIn = (text) => text.match(/https:\/\/ranwhat\.com\/api\/confirm\?[^\s"<]+/)[0];
const pending = (e) => e.LIST.sql.prepare("SELECT * FROM subscribers").all();
const pathOf = (link) => { const u = new URL(link); return u.pathname + u.search; };

async function signUp(e, address = "Reader@Example.com") {
  const res = await post(e, "/api/subscribe", { email: address, "cf-turnstile-response": "tok" });
  assert.equal(res.status, 200);
  return res.json();
}

async function signUpAndConfirm(e, s, address) {
  const before = s.emails.length;
  await signUp(e, address);
  const res = await post(e, pathOf(linkIn(s.emails[before].text)), "", "application/x-www-form-urlencoded");
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
const OLD = { id: "v0-5-0", title: "ranwhat 0.5.0: Twelve coding agents", at: now() - 3600 };
const NEW = { id: "v0-6-0", title: "ranwhat 0.6.0: Cursor", at: now() };

/* ---------- switched off ---------- */

test("without the API key or the secret, the signup says so and nothing is signed or sent", async () => {
  for (const extra of [{ RESEND_API_KEY: undefined }, { LIST_SECRET: undefined }, { LIST_SECRET: "short" }]) {
    const s = services();
    const e = env(extra);
    const res = await post(e, "/api/subscribe", { email: "a@example.com", "cf-turnstile-response": "tok" });
    assert.equal(res.status, 503);
    assert.match((await res.json()).error, /not switched on/);
    assert.equal((await get(e, "https://ranwhat.com/api/confirm?id=x&at=1&t=y")).status, 503);
    await list.announce(e, feed([NEW]));
    assert.deepEqual(s.calls, []);
  }
});

/* ---------- on ---------- */

test("a signup is stored unconfirmed and gets one confirmation email", async () => {
  const s = services();
  const e = env();
  assert.deepEqual(await signUp(e), { ok: true });
  const [row] = pending(e);
  assert.equal(row.email, "reader@example.com");
  const [mail] = s.emails;
  assert.deepEqual(mail.to, ["reader@example.com"]);
  assert.equal(mail.from, "ranwhat <updates@ranwhat.com>");
  const link = linkIn(mail.text);
  assert.ok(!link.includes("example.com"), "the link carries an id, not the address");
  assert.equal(linkIn(mail.html), link);
  assert.equal(s.contacts.size, 0, "nobody is on the list before confirming");

  // Again at once: same answer, no second email, one row.
  await signUp(e, "reader@example.com");
  assert.equal(s.emails.length, 1);
  assert.equal(pending(e).length, 1);
});

test("the link shows a button; only the button adds the address to the list", async () => {
  const s = services();
  const e = env();
  await signUp(e);
  const link = linkIn(s.emails[0].text);

  const page = await get(e, link);
  assert.equal(page.status, 200);
  assert.match(await page.text(), /<form method="post"/);
  assert.equal(s.contacts.size, 0, "opening the link confirms nothing");
  assert.match(page.headers.get("content-security-policy"), /default-src 'none'/);
  assert.equal(page.headers.get("referrer-policy"), "no-referrer");

  const res = await post(e, pathOf(link), "", "application/x-www-form-urlencoded");
  assert.equal(res.status, 200);
  assert.match(await res.text(), /on the list/);
  const [seg] = s.segments;
  assert.equal(seg.name, "ranwhat releases");
  assert.deepEqual([...s.contacts.get("reader@example.com").segments], [seg.id]);
  assert.equal(s.contacts.get("reader@example.com").unsubscribed, false);
  assert.equal(pending(e).length, 0, "once Resend has it, it is not kept here");

  // The button again: still fine, nothing doubled, the segment looked up once.
  assert.equal((await post(e, pathOf(link), "")).status, 200);
  assert.equal(s.contacts.size, 1);
  assert.equal(s.calls.filter((c) => c.endsWith("/segments")).length, 2);  // one GET, one POST
});

test("someone who unsubscribed and signs up again is subscribed again", async () => {
  const s = services();
  const e = env();
  await signUpAndConfirm(e, s, "back@example.com");
  s.contacts.get("back@example.com").unsubscribed = true;
  s.contacts.get("back@example.com").segments.clear();
  await signUpAndConfirm(e, s, "back@example.com");
  const c = s.contacts.get("back@example.com");
  assert.equal(c.unsubscribed, false);
  assert.equal(c.segments.size, 1);
});

test("a tampered, foreign or expired link confirms nobody", async () => {
  const s = services();
  const e = env();
  await signUp(e);
  const link = new URL(linkIn(s.emails[0].text));

  const tampered = new URL(link);
  tampered.searchParams.set("t", link.searchParams.get("t").replace(/^./, (c) => (c === "A" ? "B" : "A")));
  const later = new URL(link);
  later.searchParams.set("at", String(Number(link.searchParams.get("at")) + 1));
  const other = env({ LIST_SECRET: SECRET.replace("test", "else") });

  for (const [where, url] of [[e, tampered], [e, later], [other, link]]) {
    assert.equal((await post(where, url.pathname + url.search, "")).status, 400);
  }
  assert.equal(s.contacts.size, 0);

  const realNow = Date.now;
  Date.now = () => realNow() + 8 * 24 * 3600 * 1000;
  try {
    assert.equal((await post(e, link.pathname + link.search, "")).status, 400);
  } finally {
    Date.now = realNow;
  }
});

test("the signup checks the challenge, for this form, before storing anything", async () => {
  const s = services({ action: "contact" });
  const e = env();
  let res = await post(e, "/api/subscribe", { email: "a@example.com", "cf-turnstile-response": "tok" });
  assert.equal(res.status, 403);
  s.turnstile = { action: "subscribe", success: false };
  res = await post(e, "/api/subscribe", { email: "a@example.com", "cf-turnstile-response": "tok" });
  assert.equal(res.status, 403);
  res = await post(e, "/api/subscribe", { email: "a@example.com" });
  assert.equal(res.status, 400);
  res = await post(e, "/api/subscribe", { email: "not an address", "cf-turnstile-response": "tok" });
  assert.equal(res.status, 400);
  assert.deepEqual(s.calls, []);
});

test("past the day's sending limit a confirmation waits, and the cron sends it", async () => {
  const s = services();
  const e = env();
  s.fail["POST /emails"] = { status: 429, name: "daily_quota_exceeded" };
  assert.deepEqual(await signUp(e, "a@example.com"), { ok: true, queued: true });
  assert.deepEqual(await signUp(e, "a@example.com"), { ok: true, queued: true });
  assert.equal(s.emails.length, 0);

  await list.announce(e, feed([OLD]));          // still limited: nothing, and no error
  assert.equal(s.emails.length, 0);

  delete s.fail["POST /emails"];
  await list.announce(e, feed([OLD]));
  assert.deepEqual(s.emails.map((m) => m.to[0]), ["a@example.com"]);
  await list.announce(e, feed([OLD]));
  assert.equal(s.emails.length, 1, "sent once");
});

test("the list sends only so many confirmations a day, ten with accounts on, so account mail keeps its room; the rest wait", async () => {
  const s = services();
  const e = env({ ACCOUNTS_ON: "1" });
  const answers = [];
  for (let i = 0; i < 25; i++) answers.push(await signUp(e, `r${i}@example.com`));
  assert.equal(s.emails.length, list.LIST_MAIL_PER_DAY);
  assert.equal(list.LIST_MAIL_PER_DAY, 10);
  assert.deepEqual(answers.slice(list.LIST_MAIL_PER_DAY), Array(25 - list.LIST_MAIL_PER_DAY).fill({ ok: true, queued: true }));
  assert.equal(pending(e).filter((r) => r.mailed_at === 0).length, 25 - list.LIST_MAIL_PER_DAY);

  /* The cron sends none of them past the day's ten either. */
  await list.announce(e, feed([OLD]));
  assert.equal(s.emails.length, list.LIST_MAIL_PER_DAY);

  /* The next day's run sends ten more of those waiting, and no more. */
  const realNow = Date.now;
  Date.now = () => realNow() + 24 * 3600 * 1000;
  try {
    await list.announce(e, feed([OLD]));
    assert.equal(s.emails.length, 2 * list.LIST_MAIL_PER_DAY);
    assert.equal(new Set(s.emails.map((m) => m.to[0])).size, 2 * list.LIST_MAIL_PER_DAY, "each address mailed once");
    assert.equal(pending(e).filter((r) => r.mailed_at === 0).length, 25 - 2 * list.LIST_MAIL_PER_DAY);
    await list.announce(e, feed([OLD]));
    assert.equal(s.emails.length, 2 * list.LIST_MAIL_PER_DAY);
  } finally {
    Date.now = realNow;
  }

  /* With accounts off, there is no account mail to keep room for. */
  const alone = services();
  const off = env();
  for (let i = 0; i < 25; i++) await signUp(off, `r${i}@example.com`);
  assert.equal(alone.emails.length, 25);
  assert.ok(list.LIST_MAIL_ALONE >= 25 && list.LIST_MAIL_ALONE <= 90);
});

test("any other failed confirmation email says so, and the next try goes through at once", async () => {
  const s = services();
  const e = env();
  s.fail["POST /emails"] = { status: 500, name: "application_error" };
  const res = await post(e, "/api/subscribe", { email: "a@example.com", "cf-turnstile-response": "tok" });
  assert.equal(res.status, 502);
  delete s.fail["POST /emails"];
  assert.deepEqual(await signUp(e, "a@example.com"), { ok: true, queued: true },
    "a row left unsent is the cron's to send");
  await list.announce(e, feed([OLD]));
  assert.equal(s.emails.length, 1);
});

test("a confirmation Resend cannot take shows a retry page and keeps the signup", async () => {
  const s = services();
  const e = env();
  await signUp(e);
  s.fail["POST /contacts"] = { status: 429, name: "rate_limit_exceeded" };
  const res = await post(e, pathOf(linkIn(s.emails[0].text)), "");
  assert.equal(res.status, 502);
  assert.equal(pending(e).length, 1);
  delete s.fail["POST /contacts"];
  assert.equal((await post(e, pathOf(linkIn(s.emails[0].text)), "")).status, 200);
  assert.equal(s.contacts.size, 1);
});

/* ---------- releases ---------- */

test("the first run sends nothing; a new release goes out once, as one broadcast", async () => {
  const s = services();
  const e = env();
  await signUpAndConfirm(e, s, "one@example.com");

  await list.announce(e, feed([OLD]));
  assert.equal(s.broadcasts.length, 0, "what was already published is not news");

  await list.announce(e, feed([NEW, OLD]));
  assert.equal(s.broadcasts.length, 1);
  const [b] = s.broadcasts;
  assert.equal(b.segment_id, s.segments[0].id);
  assert.equal(b.send, true);
  assert.equal(b.subject, "ranwhat 0.6.0: Cursor");
  assert.equal(b.from, "ranwhat <updates@ranwhat.com>");
  assert.match(b.html, /\{\{\{RESEND_UNSUBSCRIBE_URL\}\}\}/);
  assert.match(b.text, /Unsubscribe: \{\{\{RESEND_UNSUBSCRIBE_URL\}\}\}/);
  assert.match(b.html, /<code style="[^"]+">check<\/code>/);
  assert.match(b.text, /- check got faster/);

  await list.announce(e, feed([NEW, OLD]));
  assert.equal(s.broadcasts.length, 1, "nobody gets it twice");
});

test("a broadcast Resend refuses is tried again next run; one that may have gone out is not", async () => {
  const s = services();
  const e = env();
  await list.announce(e, feed([OLD]));
  s.fail["POST /broadcasts"] = { status: 500, name: "application_error" };
  await list.announce(e, feed([NEW, OLD]));
  assert.equal(s.broadcasts.length, 0);
  delete s.fail["POST /broadcasts"];
  await list.announce(e, feed([NEW, OLD]));
  assert.equal(s.broadcasts.length, 1);

  // A run that died between Resend's answer and the record of it.
  const NEWER = { id: "v0-7-0", title: "ranwhat 0.7.0", at: now() };
  e.LIST.sql.prepare("INSERT INTO releases (guid, seen_at, started_at) VALUES (?, ?, ?)")
    .run("https://ranwhat.com/updates#v0-7-0", now(), now());
  await list.announce(e, feed([NEWER, NEW, OLD]));
  assert.equal(s.broadcasts.length, 1);
});

test("a release that first appears weeks after it was published is not sent", async () => {
  const s = services();
  const e = env();
  await list.announce(e, feed([OLD]));
  await list.announce(e, feed([{ id: "v0-1-0", title: "backfilled", at: now() - 30 * 24 * 3600 }, OLD]));
  assert.equal(s.broadcasts.length, 0);
});

test("an address nobody confirms is deleted after a week", async () => {
  services();
  const e = env();
  await signUp(e);
  const realNow = Date.now;
  Date.now = () => realNow() + 8 * 24 * 3600 * 1000;
  try {
    await list.announce(e, feed([OLD]));
  } finally {
    Date.now = realNow;
  }
  assert.equal(pending(e).length, 0);
});

/* ---------- the rest of the Worker ---------- */

test("the contact form still sends, and the routes answer only their methods", async () => {
  const s = services({ action: undefined });
  const e = env();
  const res = await post(e, "/api/contact", { email: "w@example.com", message: "hello", about: "bug",
                                              "cf-turnstile-response": "tok" });
  assert.equal(res.status, 200);
  assert.equal(e.CONTACT_EMAIL.sent.length, 1);
  assert.equal((await get(e, "https://ranwhat.com/api/subscribe")).status, 405);
  assert.equal((await get(e, "https://ranwhat.com/api/contact")).status, 405);
  assert.equal((await get(e, "https://ranwhat.com/api/unsubscribe")).status, 404);
  assert.deepEqual(s.calls, []);
});

test("nothing the list logs carries an address", async () => {
  const lines = [];
  const real = console.log;
  console.log = (...a) => lines.push(a.join(" "));
  try {
    const s = services();
    const e = env();
    s.fail["POST /emails"] = { status: 500, name: "application_error" };
    await post(e, "/api/subscribe", { email: "secret.person@example.com", "cf-turnstile-response": "tok" });
    s.fail["POST /emails"] = { status: 429, name: "daily_quota_exceeded" };
    await list.announce(e, feed([OLD]));
  } finally {
    console.log = real;
  }
  assert.ok(lines.length >= 2);
  for (const line of lines) assert.doesNotMatch(line, /@|secret\.person/);
});
