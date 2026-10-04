/* The release list: who asked for an email when ranwhat ships, and the
 * emails themselves, on free tiers only. Cloudflare D1 holds a signup until
 * it is confirmed; Resend holds the confirmed list, sends the mail, and runs
 * the unsubscribe link in every release email.
 *
 * On (double opt-in):
 *   POST /api/subscribe     index.js checks the challenge, then subscribe()
 *                           stores the address unconfirmed and mails it a
 *                           signed link (Resend's email API).
 *   GET  /api/confirm       A page with one button. Mail scanners open every
 *                           link in a message, and one must not confirm on
 *                           the reader's behalf, so only the button's POST
 *                           does.
 *   POST /api/confirm       Adds the address to the Resend segment the
 *                           releases go to, then deletes it here: from then
 *                           on Resend is the only place it is kept.
 * Off: the unsubscribe link Resend puts in every release email.
 *
 * Releases: a cron trigger reads /rss.xml. A release it has not seen goes
 * out as one Resend broadcast to the segment. Broadcasts are not counted
 * against the free plan's 100 emails a day; confirmation emails are, so one
 * that hits the daily limit waits here and the cron sends it once the limit
 * resets. The first run only notes what the feed already holds: old releases
 * are never sent.
 *
 * The confirmation link carries a random id, never the address, with an
 * HMAC over it, so an id alone confirms nobody.
 */

const ORIGIN = "https://ranwhat.com";
const FEED = `${ORIGIN}/rss.xml`;
const API = "https://api.resend.com";
export const FROM = "updates@ranwhat.com";
const SENDER = `ranwhat <${FROM}>`;
const REPLY_TO = "hello@ranwhat.com";
export const SEGMENT = "ranwhat releases";

const DAY = 24 * 3600;
const CONFIRM_FOR = 7 * DAY;     // a confirmation link works this long
const RESEND_AFTER = 15 * 60;    // at most one confirmation email per address per 15 minutes
const FORGET_AFTER = 7 * DAY;    // an address nobody confirmed is deleted after this
const FRESH_FOR = 14 * DAY;      // a release older than this when first seen is never sent
export const QUEUE_BATCH = 20;   // queued confirmations a run sends, inside the free plan's 50 subrequests

const SCHEMA = [
  /* Only signups waiting to be confirmed. mailed_at 0: not mailed yet. */
  `CREATE TABLE IF NOT EXISTS subscribers (
     id TEXT PRIMARY KEY,
     email TEXT NOT NULL UNIQUE,
     created_at INTEGER NOT NULL,
     mailed_at INTEGER NOT NULL)`,
  /* started_at without done_at: a broadcast call that never reported back.
     It is not retried, because it may have gone out. */
  `CREATE TABLE IF NOT EXISTS releases (
     guid TEXT PRIMARY KEY,
     seen_at INTEGER NOT NULL,
     started_at INTEGER,
     done_at INTEGER,
     broadcast TEXT)`,
  `CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)`,
];

/* The tables are made on first use rather than by a migration step, so a
   deploy from GitHub needs nothing run by hand. */
const made = new WeakSet();
async function schema(db) {
  if (made.has(db)) return;
  await db.batch(SCHEMA.map((sql) => db.prepare(sql)));
  made.add(db);
}

export const switchedOn = (env) => Boolean(env.LIST && env.RESEND_API_KEY &&
  typeof env.LIST_SECRET === "string" && env.LIST_SECRET.length >= 32);
const now = () => Math.floor(Date.now() / 1000);

const OFF = () => page("Not switched on", `<h1>Release emails are not switched on yet.</h1>
  <p>Every release is on the <a href="/updates">updates page</a> and in its
     <a href="/rss.xml">RSS feed</a>.</p>`, 503);

/* ---------- Resend ---------- */

/* One API call. Throws an Error whose code is Resend's error name
   (daily_quota_exceeded, validation_error, ...) or the HTTP status. */
async function resend(env, method, path, body) {
  let res;
  try {
    res = await fetch(`${API}${path}`, {
      method,
      headers: { authorization: `Bearer ${env.RESEND_API_KEY}`, "content-type": "application/json" },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  } catch {
    throw Object.assign(new Error("Resend unreachable"), { code: "unreachable", status: 0 });
  }
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const code = typeof data.name === "string" ? data.name : String(res.status);
    throw Object.assign(new Error(`Resend ${res.status}`), { code, status: res.status });
  }
  return data;
}

const limited = (err) => err && err.status === 429;

/* The segment releases go to, found or made by name and kept in settings. */
async function segment(env) {
  const db = env.LIST;
  const kept = await db.prepare("SELECT value FROM settings WHERE key = 'segment'").first();
  if (kept) return kept.value;
  const { data = [] } = await resend(env, "GET", "/segments");
  let id = (data.find((s) => s.name === SEGMENT) || {}).id;
  if (!id) id = (await resend(env, "POST", "/segments", { name: SEGMENT })).id;
  await db.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('segment', ?)").bind(id).run();
  return id;
}

/* ---------- signed links ---------- */

const enc = new TextEncoder();

function b64url(bytes) {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function sign(env, text) {
  /* Never sign with a missing or guessable key: every link would be forgeable. */
  if (typeof env.LIST_SECRET !== "string" || env.LIST_SECRET.length < 32) {
    throw new Error("LIST_SECRET is not set, or shorter than 32 characters");
  }
  const key = await crypto.subtle.importKey("raw", enc.encode(env.LIST_SECRET),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return b64url(new Uint8Array(await crypto.subtle.sign("HMAC", key, enc.encode(text))));
}

/* Compares in time that does not depend on where the strings differ. */
function same(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

async function confirmLink(env, id, at) {
  const t = await sign(env, `confirm:${id}:${at}`);
  return `${ORIGIN}/api/confirm?id=${id}&at=${at}&t=${t}`;
}

/* The id, when the link's signature holds and it has not expired. */
async function checked(env, url) {
  const id = url.searchParams.get("id") || "";
  const at = url.searchParams.get("at") || "";
  const t = url.searchParams.get("t") || "";
  if (!/^[0-9a-f-]{36}$/.test(id) || !/^\d{1,12}$/.test(at)) return null;
  if (now() - Number(at) > CONFIRM_FOR) return null;
  return same(t, await sign(env, `confirm:${id}:${at}`)) ? id : null;
}

/* ---------- on ---------- */

async function mailConfirmation(env, email, id) {
  const link = await confirmLink(env, id, now());
  await resend(env, "POST", "/emails", {
    from: SENDER,
    to: [email],
    reply_to: REPLY_TO,
    subject: "Confirm ranwhat release emails",
    text: [
      "Someone, hopefully you, asked ranwhat.com for an email each time a new",
      "release of ranwhat ships. To confirm, open this link and press the button:",
      "",
      link,
      "",
      "If it was not you, ignore this. Nothing more will be sent, and the",
      "address is deleted in a week.",
      "",
      "ranwhat.com",
    ].join("\n"),
    html: mail(`
      <p>Someone, hopefully you, asked ranwhat.com for an email each time a new
         release of ranwhat ships.</p>
      <p style="margin:26px 0"><a href="${link}" style="${BUTTON}">Confirm release emails</a></p>
      <p style="color:#5a6672">If it was not you, ignore this. Nothing more will be sent, and
         the address is deleted in a week.</p>`),
  });
}

/* Stores the address unconfirmed and mails it a confirmation link. An
   address mailed in the last few minutes gets nothing more, so the form
   cannot flood an inbox. Returns { queued: true } when the day's sending
   limit is used up: the cron mails it once the limit resets. Throws when
   the email could not be sent for any other reason. */
export async function subscribe(env, address) {
  const db = env.LIST;
  await schema(db);
  const email = address.toLowerCase();
  const t = now();
  let row = await db.prepare("SELECT id, mailed_at FROM subscribers WHERE email = ?").bind(email).first();
  if (row && row.mailed_at === 0) return { queued: true };
  if (row && t - row.mailed_at < RESEND_AFTER) return {};
  if (row) {
    await db.prepare("UPDATE subscribers SET mailed_at = ? WHERE id = ?").bind(t, row.id).run();
  } else {
    row = { id: crypto.randomUUID() };
    const added = await db.prepare(
      "INSERT INTO subscribers (id, email, created_at, mailed_at) VALUES (?, ?, ?, ?) ON CONFLICT(email) DO NOTHING")
      .bind(row.id, email, t, t).run();
    if (!added.meta.changes) return {};   // the same address, signed up a moment ago in another request
  }
  try {
    await mailConfirmation(env, email, row.id);
    return {};
  } catch (err) {
    /* Unsent: 0 lets a retry, or the cron when it is the daily limit, through at once. */
    await db.prepare("UPDATE subscribers SET mailed_at = 0 WHERE id = ?").bind(row.id).run();
    console.log(`list confirm mail: ${err.code}`);
    if (limited(err)) return { queued: true };
    throw err;
  }
}

export async function confirm(request, env) {
  if (!switchedOn(env)) return OFF();
  const url = new URL(request.url);
  const id = await checked(env, url);
  if (!id) {
    return page("Link expired", `<h1>This link has expired.</h1>
      <p>Confirmation links work for a week. Sign up again on the
         <a href="/updates#follow">updates page</a> and a new one is sent.</p>`, 400);
  }
  if (request.method !== "POST") {
    return page("Confirm", `<h1>One more step.</h1>
      <p>Press the button to get an email each time a new release of ranwhat ships.</p>
      <form method="post" action="${escape(url.pathname + url.search)}">
        <button type="submit">Confirm release emails</button></form>`);
  }
  await schema(env.LIST);
  const row = await env.LIST.prepare("SELECT email FROM subscribers WHERE id = ?").bind(id).first();
  if (!row) {
    /* Confirmed already (the row goes once Resend has it), or a week passed. */
    return page("Confirmed", `<h1>You are on the list.</h1>
      <p>If you confirmed earlier, there is nothing more to do. If the
         address was deleted after a week, sign up again on the
         <a href="/updates#follow">updates page</a>.</p>`);
  }
  try {
    await addContact(env, row.email);
  } catch (err) {
    console.log(`list confirm: ${err.code}`);
    return page("Try again", `<h1>That did not go through.</h1>
      <p>Nothing is wrong with your link. Press the button in the email again
         in a minute.</p>`, 502);
  }
  await env.LIST.prepare("DELETE FROM subscribers WHERE id = ?").bind(id).run();
  return page("Confirmed", `<h1>You are on the list.</h1>
    <p>The next release comes to your inbox, with what changed. Every email has
       a link to stop.</p><p><a href="/updates">Every release so far</a></p>`);
}

/* On the releases segment and subscribed, whether the address is new to
   Resend or unsubscribed earlier and has now asked again. */
async function addContact(env, email) {
  const seg = await segment(env);
  try {
    await resend(env, "POST", "/contacts", { email, unsubscribed: false, segments: [{ id: seg }] });
    return;
  } catch (err) {
    if (limited(err) || err.status === 401 || err.status === 403 || err.status === 0) throw err;
  }
  /* Most likely known to Resend already. */
  const who = encodeURIComponent(email);
  await resend(env, "PATCH", `/contacts/${who}`, { unsubscribed: false });
  await resend(env, "POST", `/contacts/${who}/segments/${seg}`);
}

/* ---------- releases ---------- */

const unxml = (s) => s.replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"')
  .replace(/&apos;|&#39;/g, "'").replace(/&amp;/g, "&");

/* The items of ranwhat's own feed, newest first. Written by scripts/rss.py,
   so its shape is known; anything not shaped like it is skipped. */
export function parseFeed(xml) {
  const items = [];
  for (const [, body] of xml.matchAll(/<item>([\s\S]*?)<\/item>/g)) {
    const get = (tag) => {
      const m = body.match(new RegExp(`<${tag}(?:\\s[^>]*)?>([\\s\\S]*?)</${tag}>`));
      return m ? unxml(m[1].trim()) : "";
    };
    const guid = get("guid"), title = get("title"), link = get("link");
    const published = Date.parse(get("pubDate")) / 1000;
    if (!guid || !title || !link.startsWith(`${ORIGIN}/`) || !Number.isFinite(published)) continue;
    items.push({ guid, title, link, published, html: get("description") });
  }
  return items;
}

/* Runs on the cron trigger. */
export async function announce(env, fetcher = fetch) {
  if (!switchedOn(env)) return;
  const db = env.LIST;
  await schema(db);
  const t = now();
  await db.prepare("DELETE FROM subscribers WHERE created_at < ?").bind(t - FORGET_AFTER).run();
  await sendQueued(env);

  let items;
  try {
    const res = await fetcher(FEED, { headers: { "cache-control": "no-cache" } });
    if (!res.ok) return void console.log(`list feed: ${res.status}`);
    items = parseFeed(await res.text());
  } catch {
    return void console.log("list feed: unreachable");
  }
  if (!items.length) return;

  const { results } = await db.prepare("SELECT guid, started_at, done_at FROM releases").all();
  const known = new Map(results.map((r) => [r.guid, r]));
  if (!known.size) {
    /* First run: what is published already was news before the list existed. */
    await db.batch(items.map((i) => db.prepare(
      "INSERT OR IGNORE INTO releases (guid, seen_at, done_at) VALUES (?, ?, ?)").bind(i.guid, t, t)));
    return;
  }

  for (const item of items.slice().reverse()) {          // oldest first
    const release = known.get(item.guid);
    if (release && (release.done_at || release.started_at)) continue;
    if (!release) {
      const stale = t - item.published > FRESH_FOR;
      await db.prepare("INSERT OR IGNORE INTO releases (guid, seen_at, done_at) VALUES (?, ?, ?)")
        .bind(item.guid, t, stale ? t : null).run();
      if (stale) continue;
    }
    /* Marked before the call: if the Worker dies after Resend has sent it but
       before this is recorded, the next run must not send it again. */
    await db.prepare("UPDATE releases SET started_at = ? WHERE guid = ?").bind(now(), item.guid).run();
    try {
      const sent = await resend(env, "POST", "/broadcasts", await broadcast(env, item));
      await db.prepare("UPDATE releases SET done_at = ?, broadcast = ? WHERE guid = ?")
        .bind(now(), String(sent.id || ""), item.guid).run();
    } catch (err) {
      /* Resend answered with an error, so nothing went out: try again next run. */
      console.log(`list release: ${err.code}`);
      await db.prepare("UPDATE releases SET started_at = NULL WHERE guid = ?").bind(item.guid).run();
      return;
    }
  }
}

/* Confirmation emails the daily limit held back. */
async function sendQueued(env) {
  const { results } = await env.LIST.prepare(
    "SELECT id, email FROM subscribers WHERE mailed_at = 0 ORDER BY created_at LIMIT ?").bind(QUEUE_BATCH).all();
  for (const row of results) {
    try {
      await mailConfirmation(env, row.email, row.id);
    } catch (err) {
      console.log(`list queued confirm: ${err.code}`);
      if (limited(err)) return;
      continue;
    }
    await env.LIST.prepare("UPDATE subscribers SET mailed_at = ? WHERE id = ?").bind(now(), row.id).run();
  }
}

export async function broadcast(env, item) {
  /* The feed's notes mark commands with a class no mail client styles. */
  const notes = item.html.replace(/<span class="icode">([\s\S]*?)<\/span>/g, `<code style="${CODE}">$1</code>`)
    .replace(/<a href="/g, '<a style="color:#b8482d" href="');
  const text = notes.replace(/<li>/g, "\n- ").replace(/<[^>]+>/g, "")
    .replace(/&nbsp;/g, " ").replace(/&rsquo;/g, "’").replace(/&amp;/g, "&").replace(/[ \t]+/g, " ").trim();
  /* Resend fills in each reader's own unsubscribe link here. */
  const OFF_LINK = "{{{RESEND_UNSUBSCRIBE_URL}}}";
  return {
    segment_id: await segment(env),
    from: SENDER,
    reply_to: REPLY_TO,
    subject: item.title,
    name: item.title,
    send: true,
    text: [
      item.title, "", text, "",
      `Read it on ranwhat.com: ${item.link}`,
      "Run the newest: uvx ranwhat@latest check",
      "", "--",
      "You get this because you asked ranwhat.com for release emails.",
      `Unsubscribe: ${OFF_LINK}`,
    ].join("\n"),
    html: mail(`
      <h1 style="font-size:21px;line-height:1.3;margin:0 0 14px">${escape(item.title)}</h1>
      <div style="font-size:15px;line-height:1.6">${notes}</div>
      <p style="margin:22px 0 0"><a href="${escape(item.link)}" style="color:#b8482d">Read it on ranwhat.com</a>
         &middot; run the newest with <code style="${CODE}">uvx ranwhat@latest check</code></p>
      <p style="margin:30px 0 0;padding-top:14px;border-top:1px solid #d5dae0;font-size:12.5px;color:#5a6672">
         You get this because you asked ranwhat.com for release emails.
         <a href="${OFF_LINK}" style="color:#5a6672">Unsubscribe</a>.</p>`),
  };
}

/* ---------- markup ---------- */

const escape = (s) => String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;")
  .replace(/>/g, "&gt;").replace(/"/g, "&quot;");

const BUTTON = "display:inline-block;background:#12171c;color:#ffffff;text-decoration:none;" +
  "font-family:Menlo,Consolas,monospace;font-size:14px;padding:12px 18px";
const CODE = "font-family:Menlo,Consolas,monospace;font-size:13px;background:#f1f3f5;padding:1px 4px";

function mail(body) {
  return `<!doctype html><html><body style="margin:0;background:#edeff1">
<div style="max-width:560px;margin:0 auto;padding:28px 24px;background:#ffffff;color:#12171c;
  font-family:-apple-system,'Segoe UI',Helvetica,Arial,sans-serif;font-size:15px;line-height:1.55">
<p style="margin:0 0 22px;font-family:Menlo,Consolas,monospace;font-weight:700;font-size:16px">ran<span style="color:#b8482d">what</span></p>
${body}
</div></body></html>`;
}

/* The page behind the confirmation link. Served by the Worker, so Pages'
   _headers do not reach it: the policy is set here, and allows no script. */
const PAGE_CSS = `
:root{--ground:#edeff1;--surface:#fff;--ink:#12171c;--muted:#5a6672;--rule:#d5dae0;--brand:#b8482d}
@media(prefers-color-scheme:dark){:root{--ground:#0E1318;--surface:#151C23;--ink:#e9edf0;--muted:#8e99a4;--rule:#242C34;--brand:#d0603f}}
@font-face{font-family:"Archivo";font-weight:400 700;src:url("/fonts/archivo-d5751e0f.woff2") format("woff2")}
*{box-sizing:border-box}
body{margin:0;background:var(--ground);color:var(--ink);font:16px/1.6 "Archivo",-apple-system,"Segoe UI",Helvetica,Arial,sans-serif}
main{max-width:520px;margin:12vh auto 0;padding:32px 28px;background:var(--surface);border:1px solid var(--rule)}
.wm{font:700 16px Menlo,Consolas,monospace;color:var(--ink);text-decoration:none}.wm i{font-style:normal;color:var(--brand)}
h1{font-size:28px;line-height:1.15;letter-spacing:-.02em;margin:26px 0 10px}
p{color:var(--muted);margin:0 0 14px}a{color:var(--ink)}
button{margin-top:10px;font:13px Menlo,Consolas,monospace;padding:11px 16px;background:transparent;color:var(--ink);border:1px solid var(--ink);cursor:pointer}
button:hover{background:var(--ink);color:var(--surface)}`;

export function page(title, body, status = 200) {
  const html = `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex"><title>${escape(title)} | ranwhat</title>
<style>${PAGE_CSS}</style></head>
<body><main><a class="wm" href="/">ran<i>what</i></a>${body}</main></body></html>`;
  return new Response(html, {
    status,
    headers: {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store",
      "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; font-src 'self'; " +
        "form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
      /* The URL carries a signed link; it goes no further than this page. */
      "referrer-policy": "no-referrer",
      "x-content-type-options": "nosniff",
      "x-robots-tag": "noindex",
    },
  });
}
