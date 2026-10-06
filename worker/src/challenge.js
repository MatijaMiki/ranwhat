/* Cloudflare Turnstile, checked on the server, for every form that sends
 * an email: the contact form and the release list on ranwhat.com
 * (index.js), and the forms on account.ranwhat.com that mail a code
 * (dashboard.js).
 *
 * A token that is never verified is decoration. This is the call that makes
 * the widget mean anything, and it checks more than that the token is good:
 * the host it was solved on, so a token from another site with the same
 * key, or from the other ranwhat host, does not count; and the form it was
 * solved for, so a token solved on one form is no pass for another.
 *
 * The widget's site key is public: it is in every page that shows one.
 * TURNSTILE_SECRET, which siteverify takes, is a Worker secret.
 */

export const SITEVERIFY = "https://challenges.cloudflare.com/turnstile/v0/siteverify";
export const CHALLENGE_ORIGIN = "https://challenges.cloudflare.com";
export const CHALLENGE_SCRIPT = `${CHALLENGE_ORIGIN}/turnstile/v0/api.js`;
export const SITEKEY = "0x4AAAAAAFBNRE3i-BOA9gTd";

/* Turnstile's tokens are at most 2048 characters. */
const LONGEST = 2048;

/* Whether a Turnstile token is good: "ok", or why not:
     "missing"      no token came with the form;
     "unavailable"  siteverify could not be asked, or did not answer JSON;
     "failed"       it answered, and not with a pass for this host and form.
   hostnames: where the widget may have been solved. action: the form it
   must have been solved for, or null for any. */
export async function challenge(request, env, token, { hostnames, action = null }) {
  if (typeof token !== "string" || !token || token.length > LONGEST) return "missing";
  let outcome;
  try {
    const verify = await fetch(SITEVERIFY, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        secret: env.TURNSTILE_SECRET,
        response: token,
        remoteip: request.headers.get("cf-connecting-ip") || undefined,
      }),
    });
    outcome = await verify.json();
  } catch {
    return "unavailable";
  }
  if (!outcome || outcome.success !== true || !hostnames.has(outcome.hostname) ||
      (action && outcome.action !== action)) {
    return "failed";
  }
  return "ok";
}
