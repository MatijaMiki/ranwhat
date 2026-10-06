/* Who a feed token belongs to: entitled() over a real SQLite database, with
 * rows written as stripe.js and scripts/feed_token.py write them. Whether
 * the feed is then served is feed.test.mjs's; this is the account each
 * accepted token is counted under, and the refusals that come before it.
 *
 *     node --test worker/test/auth.test.mjs
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import { d1 } from "./stand-ins.mjs";
import { entitled, schema } from "../src/auth.js";

const now = () => Math.floor(Date.now() / 1000);
const hash = (t) => createHash("sha256").update(t).digest("hex");
/* Made here rather than written out: nothing token-shaped sits in the source. */
const token = () => "rw_" + randomBytes(32).toString("base64url");
const asking = (tok) => new Request("https://feed.ranwhat.com/v1/catalogue",
  { headers: tok ? { authorization: `Bearer ${tok}` } : {} });

async function stand() {
  const env = { LIST: d1() };
  await schema(env.LIST);
  return env;
}

/* A token switched on as scripts/feed_token.py's printed SQL does it. */
function byHand(env, tok, { expires = null, revoked = null } = {}) {
  env.LIST.sql.prepare("INSERT INTO tokens (hash, note, created_at, expires_at, revoked_at) VALUES (?, ?, ?, ?, ?)")
    .run(hash(tok), "by hand", now(), expires, revoked);
}

/* A token tied to a subscription, as stripe.js issues one. */
function paid(env, tok, sub, status = "active") {
  env.LIST.sql.prepare(`INSERT INTO subscriptions (id, customer, status, updated_at) VALUES (?, ?, ?, ?)
    ON CONFLICT(id) DO UPDATE SET status = excluded.status`).run(sub, "cus_test1abcdef", status, now());
  env.LIST.sql.prepare("INSERT INTO tokens (hash, note, created_at) VALUES (?, ?, ?)")
    .run(hash(tok), `stripe ${sub}`, now());
  env.LIST.sql.prepare("INSERT INTO token_subscriptions (hash, subscription) VALUES (?, ?)")
    .run(hash(tok), sub);
}

test("no token, or one of the wrong shape, is asked for one before anything is read", async () => {
  for (const headers of [{}, { authorization: "Bearer" }, { authorization: "Basic abc" }]) {
    const who = await entitled(new Request("https://feed.ranwhat.com/v1/catalogue", { headers }), {});
    assert.deepEqual([who.ok, who.status], [false, 401]);
    assert.match(who.error, /token/);
  }
});

test("a well-formed token with no database is told the feed is not there, not refused", async () => {
  const who = await entitled(asking(token()), {});
  assert.deepEqual([who.ok, who.status], [false, 503]);
});

test("a token made by hand is its own account, named by its hash and never by itself", async () => {
  const env = await stand();
  const tok = token();
  byHand(env, tok);
  const who = await entitled(asking(tok), env);
  assert.deepEqual(who, { ok: true, account: `tok:${hash(tok)}` });
  assert.ok(!who.account.includes(tok));
});

test("every token a subscription is issued counts as that one subscription", async () => {
  const env = await stand();
  const first = token(), second = token();
  paid(env, first, "sub_test1abcdef");
  paid(env, second, "sub_test1abcdef");
  for (const tok of [first, second]) {
    assert.deepEqual(await entitled(asking(tok), env), { ok: true, account: "sub_test1abcdef" });
  }
});

test("a subscription Stripe is still retrying keeps its account; a canceled one has none", async () => {
  const env = await stand();
  const retrying = token(), canceled = token();
  paid(env, retrying, "sub_test2abcdef", "past_due");
  paid(env, canceled, "sub_test3abcdef", "canceled");
  assert.equal((await entitled(asking(retrying), env)).account, "sub_test2abcdef");
  const who = await entitled(asking(canceled), env);
  assert.deepEqual([who.ok, who.status, who.account], [false, 403, undefined]);
});

test("an unknown, revoked or expired token is refused alike", async () => {
  const env = await stand();
  const revoked = token(), expired = token();
  byHand(env, revoked, { revoked: now() - 1 });
  byHand(env, expired, { expires: now() - 1 });
  for (const tok of [token(), revoked, expired]) {
    const who = await entitled(asking(tok), env);
    assert.deepEqual(who, { ok: false, status: 403, error: "That token was not accepted." });
  }
});
