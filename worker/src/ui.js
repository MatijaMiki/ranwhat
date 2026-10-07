/* The pages account.ranwhat.com serves, and the headers on every response
 * from it.
 *
 * None of our script runs on this host: the pages are plain HTML forms.
 * The one script allowed anywhere is Cloudflare Turnstile's, and only on
 * the pages whose form mails a code to someone signing in (sign in, make
 * an account, reset, a new code, and the page that offers one when
 * password sign-in is paused): never on the page a code is typed into, and
 * never on the account's own pages, a step-up's included. Every other
 * page's policy allows no script at all. The one inline style is allowed by its hash
 * rather than by 'unsafe-inline', so markup that ever slipped past
 * escape() could not style itself either. Nothing loads from ranwhat.com,
 * so GTM, the analytics and the X pixel that run there never share a page
 * with a signed-in session.
 */
import { escape } from "./list.js";
import { CHALLENGE_ORIGIN, CHALLENGE_SCRIPT, SITEKEY } from "./challenge.js";

/* The site's colours, without its font: /fonts/ is on ranwhat.com, which
   this host's policy does not reach. */
const CSS = `
:root{--ground:#edeff1;--surface:#fff;--ink:#12171c;--muted:#5a6672;--rule:#d5dae0;--brand:#b8482d;--bad:#a3261b}
@media(prefers-color-scheme:dark){:root{--ground:#0E1318;--surface:#151C23;--ink:#e9edf0;--muted:#8e99a4;--rule:#242C34;--brand:#d0603f;--bad:#f08070}}
*{box-sizing:border-box}
body{margin:0;background:var(--ground);color:var(--ink);font:16px/1.6 -apple-system,"Segoe UI",Helvetica,Arial,sans-serif}
main{max-width:560px;margin:8vh auto 40px;padding:32px 28px;background:var(--surface);border:1px solid var(--rule)}
@media(max-width:600px){main{margin:0;border:0;padding:24px 16px}}
.wm{font:700 16px Menlo,Consolas,monospace;color:var(--ink);text-decoration:none}.wm i{font-style:normal;color:var(--brand)}
h1{font-size:28px;line-height:1.15;letter-spacing:-.02em;margin:26px 0 10px}
h2{font-size:15px;margin:26px 0 8px}
p{color:var(--muted);margin:0 0 14px}a{color:var(--ink)}
.bad{color:var(--bad)}
label{display:block;font-size:14px;margin:14px 0 6px}
input[type=email],input[type=text],input[type=password]{width:100%;font:16px Menlo,Consolas,monospace;padding:10px 12px;background:var(--ground);color:var(--ink);border:1px solid var(--rule)}
button{margin-top:12px;font:13px Menlo,Consolas,monospace;padding:11px 16px;background:transparent;color:var(--ink);border:1px solid var(--ink);cursor:pointer}
button:hover{background:var(--ink);color:var(--surface)}
a.button{display:inline-block;margin:12px 8px 0 0;font:13px Menlo,Consolas,monospace;padding:11px 16px;color:var(--ink);border:1px solid var(--ink);text-decoration:none}
a.button:hover{background:var(--ink);color:var(--surface)}
form.row{display:inline-block;margin-right:8px}
dl{display:grid;grid-template-columns:max-content 1fr;gap:6px 18px;margin:0 0 8px}dt{color:var(--muted)}dd{margin:0;overflow-wrap:anywhere}
ul{padding-left:18px;color:var(--muted)}li{margin:2px 0}
small{color:var(--muted)}
.panel{border:1px solid var(--rule);padding:2px 18px 6px;margin:18px 0}.panel h2{margin-top:16px}
.locked{border-style:dashed}.locked strong{color:var(--muted)}
.tag{font:12px Menlo,Consolas,monospace;color:var(--muted)}
.cf-turnstile{min-height:65px;margin-top:14px}`;

let styleHash = null;

/* default-src 'none' covers script, images, fonts, frames and fetches;
   form-action keeps every form posting here; frame-ancestors keeps the
   page out of anyone's frame. With `challenge`, Turnstile's script and
   its frame, from challenges.cloudflare.com and nowhere else. `away`:
   origins a form here may be redirected on to, which browsers hold to
   form-action too. Only the account page's forms that link Google or
   GitHub need it (oauth.js's PROVIDERS), and only for those two. */
async function csp(challenge = false, away = []) {
  if (!styleHash) {
    const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(CSS)));
    let s = "";
    for (const b of digest) s += String.fromCharCode(b);
    styleHash = btoa(s);
  }
  const policy = `default-src 'none'; style-src 'sha256-${styleHash}'; form-action ${["'self'", ...away].join(" ")}; ` +
    "frame-ancestors 'none'; base-uri 'none'";
  return challenge ? `${policy}; script-src ${CHALLENGE_ORIGIN}; frame-src ${CHALLENGE_ORIGIN}` : policy;
}

/* On every response from this host, redirects included. HSTS is sent here
   and only here: this host has only ever been HTTPS, and leaving out
   includeSubDomains keeps the decision for ranwhat.com and its other hosts
   separate (site/_headers says why it waits there). Referrer-Policy is
   same-origin, not no-referrer: see sameOrigin() in session.js. */
async function secured(headers, { challenge = false, away = [] } = {}) {
  headers.set("cache-control", "no-store");
  headers.set("content-security-policy", await csp(challenge, away));
  headers.set("x-frame-options", "DENY");
  headers.set("x-content-type-options", "nosniff");
  headers.set("referrer-policy", "same-origin");
  headers.set("cross-origin-opener-policy", "same-origin");
  headers.set("cross-origin-resource-policy", "same-origin");
  headers.set("x-robots-tag", "noindex, nofollow");
  headers.set("strict-transport-security", "max-age=31536000");
  return headers;
}

/* An HTML page. body is markup already escaped by the caller. challenge:
   the page holds a widget() and may load Turnstile's script. away: see
   csp(). */
export async function page(title, body, { status = 200, cookies = [], challenge = false, away = [] } = {}) {
  const script = challenge ? `\n<script src="${CHALLENGE_SCRIPT}" async defer></script>` : "";
  const html = `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex"><title>${escape(title)} | ranwhat account</title>
<style>${CSS}</style>${script}</head>
<body><main><a class="wm" href="/">ran<i>what</i></a>${body}</main></body></html>`;
  const headers = new Headers({ "content-type": "text/html; charset=utf-8" });
  for (const c of cookies) headers.append("set-cookie", c);
  return new Response(html, { status, headers: await secured(headers, { challenge, away }) });
}

/* Turnstile's box, inside a form: once solved, it adds the token to the
   form as cf-turnstile-response, which the server checks for `action`
   (challenge.js). Only on a page made with { challenge: true }. */
export const widget = (action) =>
  `<div class="cf-turnstile" data-sitekey="${SITEKEY}" data-action="${escape(action)}"></div>`;

/* 303, so the browser follows a POST with a GET. Always a path on this
   host: nothing here redirects anywhere a request named. */
export async function redirect(path, cookies = []) {
  const headers = new Headers({ location: path });
  for (const c of cookies) headers.append("set-cookie", c);
  return new Response(null, { status: 303, headers: await secured(headers) });
}

/* 303 to a provider's authorization endpoint, for Google or GitHub sign-in:
   a URL oauth.js builds from its own constants, never one a request
   named. */
export async function away(url, cookies = []) {
  const headers = new Headers({ location: url });
  for (const c of cookies) headers.append("set-cookie", c);
  return new Response(null, { status: 303, headers: await secured(headers) });
}

/* A form that posts to this host, with its token first. */
export const form = (action, token, inner, cls = "") =>
  `<form method="post" action="${escape(action)}"${cls ? ` class="${cls}"` : ""}>` +
  `<input type="hidden" name="form" value="${escape(token)}">${inner}</form>`;

export const notFound = () => page("Not found", `<h1>Nothing here.</h1>
  <p><a href="/">Your account</a></p>`, { status: 404 });

export async function wrongMethod(methods) {
  const res = await page("Not allowed", "<h1>Not allowed.</h1>", { status: 405 });
  res.headers.set("allow", methods.join(", "));
  return res;
}

/* A form that failed the origin or token check. Nothing in it says which. */
export const refused = () => page("Not accepted", `<h1>That form was not accepted.</h1>
  <p>It may have been open too long, or come from another site. Go back,
     reload the page and try again.</p><p><a href="/">Your account</a></p>`, { status: 403 });
