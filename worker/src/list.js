/* The release list: who asked for an email when ranwhat ships, and the
 * emails themselves. The addresses live in this account's D1 database and
 * the mail goes out through Cloudflare Email Service, so no mailing-list
 * company holds a copy.
 *
 * On (double opt-in):
 *   POST /api/subscribe     index.js checks the challenge, then subscribe()
 *                           stores the address unconfirmed and mails it a
 *                           signed link.
 *   GET  /api/confirm       A page with one button. Mail scanners open every
 *                           link in a message, and one must not confirm on
 *                           the reader's behalf, so only the button's POST
 *                           does.
 *   POST /api/confirm       Marks the address confirmed.
 * Off:
 *   GET  /api/unsubscribe   A page with one button, for the same reason.
 *   POST /api/unsubscribe   Deletes the address. Mail clients with one-click
 *                           unsubscribe (RFC 8058) POST here straight from
 *                           the List-Unsubscribe header.
 *
 * Releases: a cron trigger reads /rss.xml. A release it has not seen goes to
 * every address confirmed before it appeared, a batch per run, and each
 * delivery is recorded as it goes, so a run that stops halfway resumes
 * without sending anyone the same release twice. The first run only notes
 * what the feed already holds: old releases are never sent.
 *
 * Links carry a random id, never the address, with an HMAC over it, so an id
 * alone confirms or removes nobody.
 */

const ORIGIN = "https://ranwhat.com";
const FEED = `${ORIGIN}/rss.xml`;
export const FROM = "updates@ranwhat.com";
const SENDER = { email: FROM, name: "ranwhat" };
const REPLY_TO = "hello@ranwhat.com";
const LIST_ID = "ranwhat releases <releases.ranwhat.com>";

const DAY = 24 * 3600;
const CONFIRM_FOR = 7 * DAY;     // a confirmation link works this long
const RESEND_AFTER = 15 * 60;    // at most one confirmation email per address per 15 minutes
const FORGET_AFTER = 7 * DAY;    // an address nobody confirmed is deleted after this
const FRESH_FOR = 14 * DAY;      // a release older than this when first seen is never sent
export const BATCH = 200;        // release emails per run, well inside a run's subrequest limit

/* Sending stops for the run on these and resumes on the next; anything else
   is about one address, which is skipped so it cannot hold up the rest. */
const STOP = new Set(["E_DAILY_LIMIT_EXCEEDED", "E_RATE_LIMIT_EXCEEDED",
  "E_INTERNAL_SERVER_ERROR", "E_SENDER_NOT_VERIFIED", "E_SENDER_DOMAIN_NOT_AVAILABLE"]);

const SCHEMA = [
  `CREATE TABLE IF NOT EXISTS subscribers (
     id TEXT PRIMARY KEY,
     email TEXT NOT NULL UNIQUE,
     created_at INTEGER NOT NULL,
     mailed_at INTEGER NOT NULL,
     confirmed_at INTEGER)`,
  `CREATE TABLE IF NOT EXISTS releases (
     guid TEXT PRIMARY KEY,
     seen_at INTEGER NOT NULL,
     done_at INTEGER)`,
  `CREATE TABLE IF NOT EXISTS deliveries (
     guid TEXT NOT NULL,
     subscriber_id TEXT NOT NULL,
     sent_at INTEGER NOT NULL,
     PRIMARY KEY (guid, subscriber_id))`,
];

/* The tables are made on first use rather than by a migration step, so a
   deploy from GitHub needs nothing run by hand. */
const made = new WeakSet();
async function schema(db) {
  if (made.has(db)) return;
  await db.batch(SCHEMA.map((sql) => db.prepare(sql)));
  made.add(db);
}

export const switchedOn = (env) => Boolean(env.LIST && env.LIST_EMAIL &&
  typeof env.LIST_SECRET === "string" && env.LIST_SECRET.length >= 32);

const OFF = () => page("Not switched on", `<h1>Release emails are not switched on yet.</h1>
  <p>Every release is on the <a href="/updates">updates page</a> and in its
     <a href="/rss.xml">RSS feed</a>.</p>`, 503);
const now = () => Math.floor(Date.now() / 1000);

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

export async function unsubscribeLink(env, id) {
  const t = await sign(env, `unsubscribe:${id}`);
  return `${ORIGIN}/api/unsubscribe?id=${id}&t=${t}`;
}

/* The id, when the link's signature holds and, for a confirmation, it has
   not expired; otherwise null. */
async function checked(env, url, purpose) {
  const id = url.searchParams.get("id") || "";
  const t = url.searchParams.get("t") || "";
  if (!/^[0-9a-f-]{36}$/.test(id)) return null;
  if (purpose === "confirm") {
    const at = url.searchParams.get("at") || "";
    if (!/^\d{1,12}$/.test(at) || now() - Number(at) > CONFIRM_FOR) return null;
    return same(t, await sign(env, `confirm:${id}:${at}`)) ? id : null;
  }
  return same(t, await sign(env, `unsubscribe:${id}`)) ? id : null;
}

/* ---------- on ---------- */

/* Stores the address unconfirmed and mails it a confirmation link. An
   address already confirmed, or mailed in the last few minutes, gets
   nothing more, so the form cannot be used to flood anyone's inbox. The
   caller answers the same either way: whether an address is on the list is
   nobody else's business. Throws when the confirmation could not be sent. */
export async function subscribe(env, address) {
  const db = env.LIST;
  await schema(db);
  const email = address.toLowerCase();
  const t = now();
  let row = await db.prepare("SELECT id, mailed_at, confirmed_at FROM subscribers WHERE email = ?")
    .bind(email).first();
  if (row && (row.confirmed_at || t - row.mailed_at < RESEND_AFTER)) return;
  if (row) {
    await db.prepare("UPDATE subscribers SET mailed_at = ? WHERE id = ?").bind(t, row.id).run();
  } else {
    const id = crypto.randomUUID();
    const added = await db.prepare(
      "INSERT INTO subscribers (id, email, created_at, mailed_at) VALUES (?, ?, ?, ?) ON CONFLICT(email) DO NOTHING")
      .bind(id, email, t, t).run();
    if (!added.meta.changes) return;   // the same address, signed up a moment ago in another request
    row = { id };
  }
  try {
    const link = await confirmLink(env, row.id, t);
    await env.LIST_EMAIL.send({
      to: email,
      from: SENDER,
      replyTo: REPLY_TO,
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
  } catch (err) {
    /* Let a retry through at once rather than making them wait out the gap. */
    await db.prepare("UPDATE subscribers SET mailed_at = 0 WHERE id = ?").bind(row.id).run();
    console.log(`list confirm mail: ${err && err.code ? err.code : "failed"}`);
    throw err;
  }
}

export async function confirm(request, env) {
  if (!switchedOn(env)) return OFF();
  const url = new URL(request.url);
  const id = await checked(env, url, "confirm");
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
  const done = await env.LIST.prepare(
    "UPDATE subscribers SET confirmed_at = COALESCE(confirmed_at, ?) WHERE id = ?").bind(now(), id).run();
  if (!done.meta.changes) {
    return page("Not found", `<h1>That address is not on the list.</h1>
      <p>It may have unsubscribed since. Sign up again on the
         <a href="/updates#follow">updates page</a>.</p>`, 404);
  }
  return page("Confirmed", `<h1>You are on the list.</h1>
    <p>The next release comes to your inbox, with what changed. Every email has
       a link to stop.</p><p><a href="/updates">Every release so far</a></p>`);
}

/* ---------- off ---------- */

export async function unsubscribe(request, env) {
  if (!switchedOn(env)) return OFF();
  const url = new URL(request.url);
  const id = await checked(env, url, "unsubscribe");
  if (!id) {
    return page("Link not valid", `<h1>This link is not valid.</h1>
      <p>Use the link at the bottom of a release email, or write to
         <a href="mailto:hello@ranwhat.com">hello@ranwhat.com</a> and we will take you off.</p>`, 400);
  }
  if (request.method !== "POST") {
    return page("Unsubscribe", `<h1>Stop release emails?</h1>
      <p>Press the button and the address is deleted from the list at once.</p>
      <form method="post" action="${escape(url.pathname + url.search)}">
        <button type="submit">Unsubscribe</button></form>`);
  }
  await schema(env.LIST);
  await env.LIST.batch([
    env.LIST.prepare("DELETE FROM deliveries WHERE subscriber_id = ?").bind(id),
    env.LIST.prepare("DELETE FROM subscribers WHERE id = ?").bind(id),
  ]);
  /* A one-click POST from a mail client reads no page. */
  const oneClick = (await request.clone().text()).trim() === "List-Unsubscribe=One-Click";
  if (oneClick) return new Response("Unsubscribed.", { status: 200 });
  return page("Unsubscribed", `<h1>You are off the list.</h1>
    <p>The address is deleted. Nothing more will be sent to it.</p>`);
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
  await db.prepare("DELETE FROM subscribers WHERE confirmed_at IS NULL AND created_at < ?")
    .bind(t - FORGET_AFTER).run();

  let items;
  try {
    const res = await fetcher(FEED, { headers: { "cache-control": "no-cache" } });
    if (!res.ok) return void console.log(`list feed: ${res.status}`);
    items = parseFeed(await res.text());
  } catch {
    return void console.log("list feed: unreachable");
  }
  if (!items.length) return;

  const { results } = await db.prepare("SELECT guid, seen_at, done_at FROM releases").all();
  const known = new Map(results.map((r) => [r.guid, r]));
  if (!known.size) {
    /* First run: what is published already was news before the list existed. */
    await db.batch(items.map((i) => db.prepare(
      "INSERT OR IGNORE INTO releases (guid, seen_at, done_at) VALUES (?, ?, ?)").bind(i.guid, t, t)));
    return;
  }

  for (const item of items.slice().reverse()) {          // oldest first
    let release = known.get(item.guid);
    if (release && release.done_at) continue;
    if (!release) {
      const stale = t - item.published > FRESH_FOR;
      await db.prepare("INSERT OR IGNORE INTO releases (guid, seen_at, done_at) VALUES (?, ?, ?)")
        .bind(item.guid, t, stale ? t : null).run();
      if (stale) continue;
      release = { guid: item.guid, seen_at: t };
    }
    if (!(await sendRelease(env, item, release.seen_at))) return;   // more next run
    await db.prepare("UPDATE releases SET done_at = ? WHERE guid = ?").bind(now(), item.guid).run();
  }
}

/* One batch of one release. True when everyone due it has had it. */
async function sendRelease(env, item, since) {
  const db = env.LIST;
  const { results } = await db.prepare(
    `SELECT s.id, s.email FROM subscribers s
      WHERE s.confirmed_at IS NOT NULL AND s.confirmed_at <= ?
        AND NOT EXISTS (SELECT 1 FROM deliveries d WHERE d.guid = ? AND d.subscriber_id = s.id)
      ORDER BY s.confirmed_at LIMIT ?`).bind(since, item.guid, BATCH).all();
  for (const s of results) {
    try {
      await env.LIST_EMAIL.send(await releaseMail(env, item, s));
    } catch (err) {
      const code = err && err.code ? String(err.code) : "failed";
      console.log(`list release mail: ${code}`);
      if (STOP.has(code) || code === "failed") return false;
      /* Suppressed after a bounce or complaint, or refused: skip this one. */
    }
    await db.prepare("INSERT OR IGNORE INTO deliveries (guid, subscriber_id, sent_at) VALUES (?, ?, ?)")
      .bind(item.guid, s.id, now()).run();
  }
  return results.length < BATCH;
}

export async function releaseMail(env, item, subscriber) {
  const off = await unsubscribeLink(env, subscriber.id);
  /* The feed's notes mark commands with a class no mail client styles. */
  const notes = item.html.replace(/<span class="icode">([\s\S]*?)<\/span>/g, `<code style="${CODE}">$1</code>`)
    .replace(/<a href="/g, '<a style="color:#b8482d" href="');
  const text = notes.replace(/<li>/g, "\n- ").replace(/<[^>]+>/g, "")
    .replace(/&nbsp;/g, " ").replace(/&rsquo;/g, "’").replace(/&amp;/g, "&").replace(/[ \t]+/g, " ").trim();
  return {
    to: subscriber.email,
    from: SENDER,
    replyTo: REPLY_TO,
    subject: item.title,
    headers: {
      "List-Unsubscribe": `<${off}>`,
      "List-Unsubscribe-Post": "List-Unsubscribe=One-Click",
      "List-Id": LIST_ID,
    },
    text: [
      item.title, "", text, "",
      `Read it on ranwhat.com: ${item.link}`,
      "Run the newest: uvx ranwhat@latest check",
      "", "--",
      "You get this because you asked ranwhat.com for release emails.",
      `Unsubscribe: ${off}`,
    ].join("\n"),
    html: mail(`
      <h1 style="font-size:21px;line-height:1.3;margin:0 0 14px">${escape(item.title)}</h1>
      <div style="font-size:15px;line-height:1.6">${notes}</div>
      <p style="margin:22px 0 0"><a href="${escape(item.link)}" style="color:#b8482d">Read it on ranwhat.com</a>
         &middot; run the newest with <code style="${CODE}">uvx ranwhat@latest check</code></p>
      <p style="margin:30px 0 0;padding-top:14px;border-top:1px solid #d5dae0;font-size:12.5px;color:#5a6672">
         You get this because you asked ranwhat.com for release emails.
         <a href="${off}" style="color:#5a6672">Unsubscribe</a> and the address is deleted.</p>`),
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

/* The pages behind the links in the emails. Served by the Worker, so
   Pages' _headers do not reach them: the policy is set here, and allows no
   script at all. */
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
