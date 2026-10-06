/* GET https://feed.ranwhat.com/v1/catalogue: the capability catalogue, for
 * `ranwhat update` (ranwhat/feed.py), to anyone holding a live token.
 *
 * The document is worker/feed/catalogue.json, made by scripts/feed.py from
 * ranwhat/catalog.py and worker/feed/overlay.json, the scopes written since
 * the release, which is all that makes it newer than the bundled catalogue.
 * The client's own validator checks it there, so all that is left here is
 * who gets it, which auth.js decides. The client sends the token and
 * nothing else, and nothing here records anything about the request.
 */
import FEED from "../feed/catalogue.json" with { type: "json" };
import { entitled } from "./auth.js";

const BODY = JSON.stringify(FEED);

const refuse = (status, error) => new Response(JSON.stringify({ error }), {
  status,
  headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" },
});

export async function catalogue(request, env) {
  const who = await entitled(request, env);
  if (!who.ok) return refuse(who.status, who.error);
  return new Response(BODY, {
    status: 200,
    headers: {
      "content-type": "application/json; charset=utf-8",
      /* One subscriber's answer is never another's: nothing may cache it. */
      "cache-control": "private, no-store",
      "x-content-type-options": "nosniff",
    },
  });
}
