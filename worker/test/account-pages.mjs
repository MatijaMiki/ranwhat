/* The signed-in pages of account.ranwhat.com, for the tests that say
 * something must be on none of them: a form a role or a stale session is
 * not offered, a token shown once, a Stripe or provider origin in a page's
 * policy. Each test file has its own Browser; any with get(path) that
 * answers { status, text, headers } will do. Imported by the tests, never
 * run as one. */
import assert from "node:assert/strict";

export const ACCOUNT_PAGES = Object.freeze(["/", "/machines", "/members", "/billing", "/security", "/activity"]);

/* Every account page as `b` sees it now, each drawn (200): { path, text, csp }. */
export async function eachPage(b) {
  const pages = [];
  for (const path of ACCOUNT_PAGES) {
    const r = await b.get(path);
    assert.equal(r.status, 200, `${path}: ${r.status}`);
    pages.push({ path, text: r.text, csp: r.headers.get("content-security-policy") });
  }
  return pages;
}

/* That no account page `b` sees has anything matching `re` in it and, with
   `csp`, that no page's policy matches that. */
export async function onNoPage(b, re, { csp = null, why = "" } = {}) {
  for (const p of await eachPage(b)) {
    assert.doesNotMatch(p.text, re, `${why || re} on ${p.path}`);
    if (csp) assert.doesNotMatch(p.csp, csp, `${why || csp} in the policy of ${p.path}`);
  }
}
