/* The pages account.ranwhat.com serves, and the headers on every response
 * from it.
 *
 * No script runs on this host, ours or anyone's: the pages are plain HTML
 * forms, and the policy allows no script at all. The one inline style is
 * allowed by its hash rather than by 'unsafe-inline', so markup that ever
 * slipped past escape() could not style itself either. Nothing loads from
 * ranwhat.com, so GTM, the analytics and the X pixel that run there never
 * share a page with a signed-in session.
 */
import { escape } from "./list.js";

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
form.row{display:inline-block;margin-right:8px}
dl{display:grid;grid-template-columns:max-content 1fr;gap:6px 18px;margin:0 0 8px}dt{color:var(--muted)}dd{margin:0;overflow-wrap:anywhere}
ul{padding-left:18px;color:var(--muted)}li{margin:2px 0}
small{color:var(--muted)}
.panel{border:1px solid var(--rule);padding:2px 18px 6px;margin:18px 0}.panel h2{margin-top:16px}
.locked{border-style:dashed}.locked strong{color:var(--muted)}
.tag{font:12px Menlo,Consolas,monospace;color:var(--muted)}`;

let policy = null;

/* default-src 'none' covers script, images, fonts, frames and fetches;
   form-action keeps every form posting here; frame-ancestors keeps the
   page out of anyone's frame. */
async function csp() {
  if (!policy) {
    const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(CSS)));
    let s = "";
    for (const b of digest) s += String.fromCharCode(b);
    policy = `default-src 'none'; style-src 'sha256-${btoa(s)}'; form-action 'self'; ` +
      "frame-ancestors 'none'; base-uri 'none'";
  }
  return policy;
}

/* On every response from this host, redirects included. HSTS is sent here
   and only here: this host has only ever been HTTPS, and leaving out
   includeSubDomains keeps the decision for ranwhat.com and its other hosts
   separate (site/_headers says why it waits there). Referrer-Policy is
   same-origin, not no-referrer: see sameOrigin() in session.js. */
async function secured(headers) {
  headers.set("cache-control", "no-store");
  headers.set("content-security-policy", await csp());
  headers.set("x-frame-options", "DENY");
  headers.set("x-content-type-options", "nosniff");
  headers.set("referrer-policy", "same-origin");
  headers.set("cross-origin-opener-policy", "same-origin");
  headers.set("cross-origin-resource-policy", "same-origin");
  headers.set("x-robots-tag", "noindex, nofollow");
  headers.set("strict-transport-security", "max-age=31536000");
  return headers;
}

/* An HTML page. body is markup already escaped by the caller. */
export async function page(title, body, { status = 200, cookies = [] } = {}) {
  const html = `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex"><title>${escape(title)} | ranwhat account</title>
<style>${CSS}</style></head>
<body><main><a class="wm" href="/">ran<i>what</i></a>${body}</main></body></html>`;
  const headers = new Headers({ "content-type": "text/html; charset=utf-8" });
  for (const c of cookies) headers.append("set-cookie", c);
  return new Response(html, { status, headers: await secured(headers) });
}

/* 303, so the browser follows a POST with a GET. Always a path on this
   host: nothing here redirects anywhere a request named. */
export async function redirect(path, cookies = []) {
  const headers = new Headers({ location: path });
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
