/* POST /api/contact and POST /api/subscribe
 *
 * /api/contact:
 * Verifies the Turnstile token server-side, then emails the message to the
 * address verified in Email Routing. Cloudflare's send_email binding can only
 * deliver to addresses already verified on this account, which is exactly the
 * shape a contact form needs and means no third-party mail service, no API key
 * and nothing leaving Cloudflare.
 *
 * This is a Worker rather than a Pages Function because send_email is not
 * among the bindings Pages Functions can hold. It is routed onto
 * ranwhat.com/api/* so the browser still sees one origin and needs no CORS.
 *
 * A Turnstile token that is never verified is decoration. This is the call that
 * makes the widget mean anything.
 *
 * /api/subscribe and /api/confirm: the release list, in list.js. The signup
 * gets the same challenge check first. A signup waits in D1 until it is
 * confirmed, Resend keeps the confirmed list and sends the mail, and a cron
 * trigger sends each new release in /rss.xml as one broadcast.
 *
 * GET feed.ranwhat.com/v1/catalogue: the subscription feed `ranwhat update`
 * reads, in feed.js, to whoever auth.js says holds a live token. Routed here
 * from its own hostname.
 *
 * /api/checkout, /api/welcome, /api/stripe and /api/billing: buying Plus
 * through Stripe, in stripe.js. Paying issues the token the feed accepts;
 * paying from an account (billing.js) links Plus to the organisation
 * instead.
 *
 * account.ranwhat.com: accounts, in dashboard.js. Checked by hostname before
 * any route is looked up, so none of the routes below answers there and
 * none of its pages answers anywhere else. Until ACCOUNTS_ON is set it
 * answers 404 to everything, exactly as an unknown path does here.
 *
 * Linking a terminal (device.js): POST feed.ranwhat.com/v1/device/code and
 * /v1/device/token, GET /v1/whoami and POST /v1/logout, which answer on
 * the feed host only and take a Bearer token, never a cookie; and GET
 * ranwhat.com/device, a redirect to the page on account.ranwhat.com where
 * the code is typed. Each is looked up by host and path together, and
 * until ACCOUNTS_ON is set none of them is there: they answer 404 as an
 * unknown path does.
 */
import { EmailMessage } from "cloudflare:email";
import { announce, confirm, subscribe, switchedOn } from "./list.js";
import { catalogue } from "./feed.js";
import { billing, checkout, webhook, welcome } from "./stripe.js";
import { ACCOUNT_HOST, accountsOn, sweep } from "./accounts.js";
import { account } from "./dashboard.js";
import { deviceRoute } from "./device.js";
import { revokeIdle } from "./machines.js";
import { challenge } from "./challenge.js";

const TO = "ranwhatcom@gmail.com";
const FROM = "form@ranwhat.com";

const SUBJECTS = {
  plus: "ranwhat Plus",
  team: "ranwhat Team",
  bug: "ranwhat: something the tool got wrong",
  other: "ranwhat enquiry",
};

const LIMITS = { message: 8000, email: 200 };

/* A token solved on another site with the same key must not count here,
   nor one solved on account.ranwhat.com, whose forms check their own.
   Preview deployments are left out on purpose: the form only sends from
   the canonical host. */
const HOSTNAMES = new Set(["ranwhat.com"]);

/* Stricter than RFC 5322 on purpose. The address lands in From, Reply-To
   and Subject, so anything with header meaning (angle brackets, commas,
   quotes, semicolons, colons, backslashes) is refused rather than escaped. */
const EMAIL = /^[^@\s<>()[\]\\,;:"]+@[^@\s<>()[\]\\,;:".]+(\.[^@\s<>()[\]\\,;:".]+)+$/;

/* X's Conversions API, for the pixel on the site. The token is a Worker
   secret (X_PIXEL_TOKEN) and the lead event's ID a plain variable
   (X_EVENT_LEAD); until both are set this does nothing. */
const X_PIXEL = "rfz6t";
const X_CONVERSIONS = `https://ads-api.x.com/12/measurement/conversions/${X_PIXEL}`;

const json = (status, body) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json; charset=utf-8" },
  });

/* Header injection: a newline in a header value lets someone append headers of
   their own, e.g. a Bcc. Strip CR and LF from anything that lands in one. */
const header = (s) => String(s || "").replace(/[\r\n]+/g, " ").trim();

/* Asks Cloudflare whether a Turnstile token is good for this site, and, when
   an action is given, for this form: a token solved on the signup form is not
   a pass for the contact form, or the other way round. Returns null when it
   is, or the Response to send back when it is not. The check itself is in
   challenge.js, which the account host's forms use too. */
async function refuseChallenge(request, env, token, action) {
  const outcome = await challenge(request, env, token, { hostnames: HOSTNAMES, action });
  if (outcome === "missing") return json(400, { error: "Complete the challenge and try again." });
  /* If siteverify is down or answers with something other than JSON, say so
     in the same shape as every other error rather than throwing a bare 500. */
  if (outcome === "unavailable") {
    return json(502, { error: "The challenge could not be checked just now. Try again in a minute." });
  }
  if (outcome !== "ok") return json(403, { error: "That challenge did not verify. Reload and try again." });
  return null;
}

/* Tells X a contact message was sent, so an ad can be credited with it. Only
   when the visitor allowed ad measurement on the page, and never with the
   message or the address: the ad-click ID if there is one, plus the IP address
   and browser X accepts in its place. It runs after the reply has gone back,
   and nothing here can fail the form. */
async function reportLead(request, env, form) {
  if (form.measure !== true || !env.X_PIXEL_TOKEN || !env.X_EVENT_LEAD) return;

  const id = {
    ip_address: request.headers.get("cf-connecting-ip") || undefined,
    user_agent: header(request.headers.get("user-agent")).slice(0, 512) || undefined,
  };
  if (typeof form.twclid === "string" && /^[A-Za-z0-9_-]{8,200}$/.test(form.twclid)) {
    id.twclid = form.twclid;
  }
  const conversionId =
    typeof form.conversion_id === "string" && /^[A-Za-z0-9-]{8,64}$/.test(form.conversion_id)
      ? form.conversion_id
      : crypto.randomUUID();

  try {
    const res = await fetch(X_CONVERSIONS, {
      method: "POST",
      headers: { "content-type": "application/json", "x-pixel-token": env.X_PIXEL_TOKEN },
      body: JSON.stringify({
        conversions: [{
          conversion_time: new Date().toISOString(),
          event_id: env.X_EVENT_LEAD,
          event_source_url: "https://ranwhat.com/contact",
          conversion_id: conversionId,
          identifiers: [id],
        }],
      }),
    });
    /* Status only: `wrangler tail` shows whether X took it, never the token. */
    if (!res.ok) console.log(`x conversions: ${res.status}`);
  } catch (err) {
    console.log("x conversions: unreachable");
  }
}

async function handleContact(request, env, ctx) {
  let form;
  try {
    form = await request.json();
  } catch {
    return json(400, { error: "Expected JSON." });
  }

  const refused = await refuseChallenge(request, env, form["cf-turnstile-response"]);
  if (refused) return refused;

  const topic = SUBJECTS[form.about] ? form.about : "other";
  const message = String(form.message || "").trim();
  const replyTo = header(form.email).slice(0, LIMITS.email);

  if (!message) return json(400, { error: "The message is empty." });
  if (message.length > LIMITS.message) {
    return json(400, { error: "That message is longer than this form accepts." });
  }
  if (!replyTo || !EMAIL.test(replyTo)) {
    return json(400, { error: "That email address does not look right." });
  }

  const body = [
    message,
    "",
    "--",
    `about: ${topic}`,
    `from:  ${replyTo}`,
  ].join("\r\n");

  /* The envelope has to come from this domain for SPF and DKIM to align, so
     the writer's address goes in the display name and the subject instead.
     Otherwise every submission looks identical in a mailbox list and you have
     to open it to find out who wrote in. Both values are run through header()
     first: a newline in either would let someone append headers of their own.
     The display name is quoted because an unquoted @ is not valid in one, and
     EMAIL has already refused the quote and backslash that could break out. */
  const raw = [
    `From: "${header(replyTo)} via ranwhat.com" <${FROM}>`,
    `To: <${TO}>`,
    `Reply-To: <${replyTo}>`,
    `Subject: ${header(SUBJECTS[topic])} \u00b7 ${header(replyTo)}`,
    `Message-ID: <${crypto.randomUUID()}@ranwhat.com>`,
    `Date: ${new Date().toUTCString()}`,
    "MIME-Version: 1.0",
    'Content-Type: text/plain; charset="utf-8"',
    "Content-Transfer-Encoding: 8bit",
    "",
    body,
  ].join("\r\n");

  try {
    await env.CONTACT_EMAIL.send(new EmailMessage(FROM, TO, raw));
  } catch (err) {
    /* Say it failed rather than showing a success page over a lost message. */
    return json(502, { error: "The message could not be sent. Write to hello@ranwhat.com instead." });
  }

  ctx.waitUntil(reportLead(request, env, form));
  return json(200, { ok: true });
}

async function handleSubscribe(request, env) {
  /* Until the list's bindings and secret are in place the form says so. */
  if (!switchedOn(env)) {
    return json(503, { error: "Email updates are not switched on yet. The RSS feed at ranwhat.com/rss.xml has every release." });
  }

  let form;
  try {
    form = await request.json();
  } catch {
    return json(400, { error: "Expected JSON." });
  }

  const address = String(form.email || "").trim();
  if (!address || address.length > LIMITS.email || !EMAIL.test(address)) {
    return json(400, { error: "That email address does not look right." });
  }

  const refused = await refuseChallenge(request, env, form["cf-turnstile-response"], "subscribe");
  if (refused) return refused;

  /* The same answer whether the address is new, waiting to confirm or
     already on the list, so the form cannot tell anyone who subscribes. */
  let result;
  try {
    result = await subscribe(env, address);
  } catch {
    return json(502, { error: "The confirmation email could not be sent just now. Try again in a minute." });
  }
  /* queued: the day's sending limit is used up, and the cron sends it later. */
  return json(200, result.queued ? { ok: true, queued: true } : { ok: true });
}

/* Path: [handler, methods it answers]. The confirmation link is opened with
   GET, and the button on the page it shows POSTs. The pricing page's form
   POSTs to checkout, and Stripe sends the browser back to welcome. */
const ROUTES = {
  "/api/contact": [handleContact, ["POST"]],
  "/api/subscribe": [handleSubscribe, ["POST"]],
  "/api/confirm": [confirm, ["GET", "POST"]],
  "/v1/catalogue": [catalogue, ["GET"]],
  "/api/checkout": [checkout, ["POST"]],
  "/api/welcome": [welcome, ["GET"]],
  "/api/stripe": [webhook, ["POST"]],
  "/api/billing": [billing, ["GET"]],
};

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (url.hostname === ACCOUNT_HOST) {
      return accountsOn(env) ? account(request, env, ctx) : json(404, { error: "Not found." });
    }
    const route = (accountsOn(env) && deviceRoute(url)) || ROUTES[url.pathname];
    if (!route) return json(404, { error: "Not found." });
    const [handle, methods] = route;
    if (!methods.includes(request.method)) {
      return new Response(JSON.stringify({ error: `${methods.join(" or ")} only.` }), {
        status: 405,
        headers: { "content-type": "application/json; charset=utf-8", allow: methods.join(", ") },
      });
    }
    return handle(request, env, ctx);
  },

  /* The cron trigger in wrangler.toml: send any new release to the list,
     delete the account codes, sessions and counts that are out of date,
     and revoke terminals' tokens unused for 90 days (machines.js). That
     goes on while accounts are switched off again after being on; where
     they never were, neither makes nor touches anything. */
  async scheduled(controller, env, ctx) {
    ctx.waitUntil(announce(env));
    if (env.LIST) {
      ctx.waitUntil(sweep(env).then(() => revokeIdle(env))
        .catch((err) => console.log(`account sweep: ${err.name || "error"}`)));
    }
  },
};
