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
 * /api/subscribe: the same check, then the address goes to Buttondown, which
 * keeps the list and sends the email. Buttondown asks the address to confirm
 * before it is on the list (double opt-in), so a stranger's address typed
 * here gets one email and nothing more. Nothing is kept here.
 */
import { EmailMessage } from "cloudflare:email";

const SITEVERIFY = "https://challenges.cloudflare.com/turnstile/v0/siteverify";
const BUTTONDOWN = "https://api.buttondown.com/v1/subscribers";
const TO = "ranwhatcom@gmail.com";
const FROM = "form@ranwhat.com";

const SUBJECTS = {
  plus: "ranwhat Plus",
  team: "ranwhat Team",
  bug: "ranwhat: something the tool got wrong",
  other: "ranwhat enquiry",
};

const LIMITS = { message: 8000, email: 200 };

/* A token solved on another site with the same key must not count here.
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
   is, or the Response to send back when it is not. */
async function refuseChallenge(request, env, token, action) {
  if (!token) return json(400, { error: "Complete the challenge and try again." });

  /* If siteverify is down or answers with something other than JSON, say so
     in the same shape as every other error rather than throwing a bare 500. */
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
    return json(502, { error: "The challenge could not be checked just now. Try again in a minute." });
  }
  if (!outcome.success || !HOSTNAMES.has(outcome.hostname) ||
      (action && outcome.action !== action)) {
    return json(403, { error: "That challenge did not verify. Reload and try again." });
  }
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

/* Same answer whether the address is new or already on the list, so the form
   cannot be used to find out who subscribes. */
const SUBSCRIBED = { ok: true };
const KNOWN = new Set(["email_already_exists", "subscriber_already_exists", "subscriber_suppressed"]);
const BLOCKED = new Set(["email_blocked", "subscriber_blocked", "ip_address_spammy"]);

async function handleSubscribe(request, env) {
  /* Until the key is set the form says so, rather than failing at Buttondown. */
  if (!env.BUTTONDOWN_API_KEY) {
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

  /* The visitor's IP address goes along because Buttondown checks sign-ups
     against it. Without it every request comes from Cloudflare's addresses,
     which its firewall may read as one sender signing up many people. No
     type is given, so Buttondown's double opt-in applies. */
  let res;
  try {
    res = await fetch(BUTTONDOWN, {
      method: "POST",
      headers: {
        authorization: `Token ${env.BUTTONDOWN_API_KEY}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        email_address: address,
        ip_address: request.headers.get("cf-connecting-ip") || undefined,
      }),
    });
  } catch {
    return json(502, { error: "The list could not be reached just now. Try again in a minute." });
  }

  if (res.status === 201) return json(200, SUBSCRIBED);

  /* Status and Buttondown's error code only: `wrangler tail` shows what went
     wrong, never the address. */
  let code = "";
  try {
    code = String((await res.json()).code || "");
  } catch { /* no body worth reading */ }
  console.log(`buttondown: ${res.status} ${code.replace(/[^\w-]/g, "").slice(0, 60)}`);

  /* Already on the list, or unsubscribed earlier: the same answer as a new
     address. Someone who unsubscribed and wants back can write to us. The
     codes are Buttondown's ValidationErrorCode, from its OpenAPI schema. */
  if (KNOWN.has(code) || res.status === 409) return json(200, SUBSCRIBED);
  if (code === "email_invalid" || code === "email_empty" || res.status === 422) {
    return json(400, { error: "That email address does not look right." });
  }
  if (code === "rate_limited" || res.status === 429) {
    return json(429, { error: "Too many sign-ups at once. Try again in a few minutes." });
  }
  if (BLOCKED.has(code)) {
    return json(403, { error: "That address could not be added. If that is a mistake, write to hello@ranwhat.com." });
  }
  return json(502, { error: "Signing up failed on our side. Write to hello@ranwhat.com and we will add you." });
}

const ROUTES = {
  "/api/contact": handleContact,
  "/api/subscribe": handleSubscribe,
};

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const handle = ROUTES[url.pathname];
    if (!handle) return json(404, { error: "Not found." });
    if (request.method !== "POST") {
      return new Response(JSON.stringify({ error: "POST only." }), {
        status: 405,
        headers: { "content-type": "application/json; charset=utf-8", allow: "POST" },
      });
    }
    return handle(request, env, ctx);
  },
};
