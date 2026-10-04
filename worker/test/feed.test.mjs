/* The subscription feed: the Worker's own handler over a real SQLite
 * database, tokens made by scripts/feed_token.py exactly as its printed
 * command would make them, and, end to end, the real `ranwhat update`
 * fetching from the Worker over HTTP.
 *
 *     node --test worker/test/feed.test.mjs
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { createServer } from "node:http";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { d1 } from "./stand-ins.mjs";

const worker = (await import("../src/index.js")).default;
const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const PUBLISHED = JSON.parse(readFileSync(join(ROOT, "worker", "feed", "catalogue.json"), "utf8"));
const ctx = { waitUntil() {} };
const now = () => Math.floor(Date.now() / 1000);

/* A token, switched on by running the SQL scripts/feed_token.py prints. */
function issue(env, note = "test") {
  const run = spawnSync("python3", [join(ROOT, "scripts", "feed_token.py"), "new", note], { encoding: "utf8" });
  assert.equal(run.status, 0, run.stderr);
  const token = run.stdout.match(/^\s+(rw_\S+)$/m)[1];
  const sql = run.stdout.match(/--command "([^"]+)"/)[1];
  env.LIST.sql.exec(sql);
  return token;
}

function revoke(env, token) {
  const run = spawnSync("python3", [join(ROOT, "scripts", "feed_token.py"), "revoke", token], { encoding: "utf8" });
  assert.equal(run.status, 0, run.stderr);
  env.LIST.sql.exec(run.stdout.match(/--command "([^"]+)"/)[1]);
}

const ask = (env, headers = {}, { method = "GET", path = "/v1/catalogue" } = {}) =>
  worker.fetch(new Request(`https://feed.ranwhat.com${path}`, { method, headers }), env, ctx);

test("no token, or a malformed one, is asked for one", async () => {
  const env = { LIST: d1() };
  for (const headers of [{}, { authorization: "Bearer" }, { authorization: "Basic abc" },
                         { authorization: "Bearer not-a-ranwhat-token-at-all" }]) {
    const res = await ask(env, headers);
    assert.equal(res.status, 401);
    assert.match((await res.json()).error, /token/);
  }
});

test("a token the server never issued is refused", async () => {
  const env = { LIST: d1() };
  issue(env);
  const res = await ask(env, { authorization: "Bearer rw_" + "x".repeat(43) });
  assert.equal(res.status, 403);
});

test("a live token gets the published catalogue, and nothing may cache it", async () => {
  const env = { LIST: d1() };
  const token = issue(env, "early access: Ana");
  const res = await ask(env, { authorization: `Bearer ${token}` });
  assert.equal(res.status, 200);
  assert.deepEqual(await res.json(), PUBLISHED);
  assert.equal(res.headers.get("cache-control"), "private, no-store");
  assert.match(res.headers.get("content-type"), /^application\/json/);
  const [row] = env.LIST.sql.prepare("SELECT * FROM tokens").all();
  assert.equal(row.note, "early access: Ana");
  assert.ok(!JSON.stringify(row).includes(token), "the database keeps a hash, not the token");
});

test("a revoked or expired token is refused; one expiring later is not", async () => {
  const env = { LIST: d1() };
  const revoked = issue(env);
  revoke(env, revoked);
  assert.equal((await ask(env, { authorization: `Bearer ${revoked}` })).status, 403);

  const later = issue(env);
  const expired = issue(env);
  const hash = (t) => createHash("sha256").update(t).digest("hex");
  const expire = env.LIST.sql.prepare("UPDATE tokens SET expires_at = ? WHERE hash = ?");
  expire.run(now() - 1, hash(expired));
  expire.run(now() + 3600, hash(later));
  assert.equal((await ask(env, { authorization: `Bearer ${expired}` })).status, 403);
  assert.equal((await ask(env, { authorization: `Bearer ${later}` })).status, 200);
});

test("only GET on /v1/catalogue is answered", async () => {
  const env = { LIST: d1() };
  const token = issue(env);
  const auth = { authorization: `Bearer ${token}` };
  assert.equal((await ask(env, auth, { method: "POST" })).status, 405);
  assert.equal((await ask(env, auth, { path: "/v1/other" })).status, 404);
});

test("the real `ranwhat update` fetches it, keeps it, and refuses a bad token", async () => {
  const env = { LIST: d1() };
  const token = issue(env);
  const server = createServer(async (req, res) => {
    const reply = await worker.fetch(new Request(`http://127.0.0.1${req.url}`,
      { method: req.method, headers: req.headers }), env, ctx);
    res.writeHead(reply.status, Object.fromEntries(reply.headers));
    res.end(Buffer.from(await reply.arrayBuffer()));
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const home = mkdtempSync(join(tmpdir(), "ranwhat-feed-"));
  try {
    const run = (tok, ...args) => {
      const childEnv = { ...process.env, RANWHAT_HOME: home, RANWHAT_TOKEN: tok,
        RANWHAT_FEED_URL: `http://127.0.0.1:${server.address().port}/v1/catalogue`,
        NO_PROXY: "127.0.0.1,localhost", no_proxy: "127.0.0.1,localhost" };
      for (const k of ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"]) delete childEnv[k];
      return new Promise((resolve) => {
        const out = { stdout: "", stderr: "" };
        const p = spawn("python3", ["-m", "ranwhat", "update", ...args], { cwd: ROOT, env: childEnv });
        p.stdout.on("data", (d) => (out.stdout += d));
        p.stderr.on("data", (d) => (out.stderr += d));
        p.on("close", (status) => resolve({ ...out, status }));
      });
    };

    const bad = await run("rw_" + "y".repeat(43));
    assert.equal(bad.status, 1);
    assert.match(bad.stderr, /not accepted/);

    const good = await run(token);
    assert.equal(good.status, 0, good.stderr);
    assert.match(good.stdout, new RegExp(`Updated to feed ${PUBLISHED.version.replace("+", "\\+")}`));
    const cached = JSON.parse(readFileSync(join(home, "feed", "catalogue.json"), "utf8"));
    assert.deepEqual(cached.catalogue, PUBLISHED.catalogue);

    const status = await run("", "--status");
    assert.equal(status.status, 0);
    assert.match(status.stdout, new RegExp(`Feed ${PUBLISHED.version.replace("+", "\\+")}\\s+\\d+ providers, \\d+ scopes`));
  } finally {
    server.close();
    rmSync(home, { recursive: true, force: true });
  }
});
