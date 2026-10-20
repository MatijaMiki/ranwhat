/* ranwhat push, end to end: the real `ranwhat push` (Python) against the
 * real Worker (index.js) over HTTP, the database a node:sqlite one, as
 * feed.test.mjs does for `ranwhat update`. A fixture history holds a
 * planted secret, commands, paths and a hostile working directory; what is
 * checked is the stored rows, every table, not only what the client says.
 *
 *     node --test worker/test/push_e2e.test.mjs
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { createServer } from "node:http";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { hostname, tmpdir, userInfo } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { d1 } from "./stand-ins.mjs";

const worker = (await import("../src/index.js")).default;
const { schema } = await import("../src/auth.js");
const accounts = await import("../src/accounts.js");
const { openSession } = await import("../src/session.js");

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const ctx = { waitUntil() {} };
const unix = () => Math.floor(Date.now() / 1000);
const sha = (t) => createHash("sha256").update(t).digest("hex");
const CANARY = "ZZE2ECANARY";
const STRIPE = "sk_" + "live_" + "Fx7Qw2Er9Ty4Ui1Op6As3Df";

const run = (e, sql, ...p) => e.LIST.sql.prepare(sql).run(...p);
const all = (e, sql, ...p) => e.LIST.sql.prepare(sql).all(...p).map((r) => ({ ...r }));

async function stand() {
  const e = { LIST: d1(), RESEND_API_KEY: "re_" + "test_key", ACCOUNT_SECRET: "an-e2e-secret-that-is-long-enough-0123456789",
              TURNSTILE_SECRET: "turnstile-test", ACCOUNTS_ON: "1" };
  await schema(e.LIST);
  await accounts.schema(e.LIST);
  return e;
}

function orgWith(e, name, plan) {
  const id = randomUUID();
  run(e, "INSERT INTO orgs (id, name, personal, created_at) VALUES (?, ?, 0, ?)", id, name, unix());
  if (plan !== "free") {
    run(e, "INSERT INTO grants (org_id, plan, starts_at, until, note, created_at) VALUES (?, ?, ?, NULL, 'test', ?)",
        id, plan, unix() - 60, unix());
  }
  return id;
}

function link(e, orgId, label) {
  const tok = "rw_m_" + randomBytes(32).toString("base64url");
  run(e, "INSERT INTO tokens (hash, note, created_at) VALUES (?, 'machine device', ?)", sha(tok), unix());
  const id = randomUUID();
  run(e, "INSERT INTO machines (id, hash, org_id, user_id, kind, label, created_at) VALUES (?, ?, ?, NULL, 'device', ?, ?)",
      id, sha(tok), orgId, label, unix());
  return { id, tok };
}

/* The Worker behind a real socket, so the client speaks HTTP to it. */
async function serve(e) {
  const server = createServer(async (req, res) => {
    const chunks = [];
    for await (const c of req) chunks.push(c);
    const body = Buffer.concat(chunks);
    const reply = await worker.fetch(new Request(`https://feed.ranwhat.com${req.url}`, {
      method: req.method, headers: { ...req.headers, "cf-connecting-ip": "198.51.100.9" },
      body: req.method === "GET" || req.method === "HEAD" ? undefined : body,
    }), e, ctx);
    res.writeHead(reply.status, Object.fromEntries(reply.headers));
    res.end(Buffer.from(await reply.arrayBuffer()));
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  return server;
}

/* A Claude Code history: a credential read, a force push and a publish
   with a live-looking key in it, in a hostile working directory. */
function history(base) {
  const proj = join(base, "projects", "-tmp-proj");
  mkdirSync(proj, { recursive: true });
  const cwd = join(base, "clients", CANARY + "-acme");
  const commands = [
    `cat ~/.aws/credentials # ${CANARY}-cmd`,
    `git push --force origin main # ${CANARY}-cmd`,
    `npm publish --token ${STRIPE}`,
  ];
  const rows = commands.map((command, i) => JSON.stringify({
    timestamp: new Date(Date.now() - (60 - i) * 1000).toISOString().replace(/\.\d+Z$/, "Z"),
    cwd, sessionId: CANARY + "-session",
    message: { role: "assistant", content: [{ type: "tool_use", id: `toolu_${i}`, name: "Bash", input: { command } }] },
  }));
  writeFileSync(join(proj, CANARY + "-session.jsonl"), rows.join("\n") + "\n");
  return { root: join(base, "projects"), cwd };
}

function ranwhat(server, home, tok, args) {
  const env = { ...process.env, HOME: home, USERPROFILE: home, RANWHAT_HOME: join(home, ".ranwhat"),
                RANWHAT_TOKEN: tok, RANWHAT_ACCOUNT_URL: `http://127.0.0.1:${server.address().port}/v1`,
                NO_PROXY: "127.0.0.1,localhost", no_proxy: "127.0.0.1,localhost" };
  for (const k of ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"]) delete env[k];
  return new Promise((resolve) => {
    const out = { stdout: "", stderr: "" };
    const p = spawn("python3", ["-m", "ranwhat", ...args], { cwd: ROOT, env });
    p.stdout.on("data", (d) => (out.stdout += d));
    p.stderr.on("data", (d) => (out.stderr += d));
    p.on("close", (status) => resolve({ ...out, status }));
  });
}

const pushArgs = (root, ...more) => ["push", "--yes", "--source", "claude-code", "--root", root, ...more];

test("push, end to end: Free is refused, Plus is stored, shown, idempotent, strict, and holds nothing but metadata", async () => {
  const e = await stand();
  const server = await serve(e);
  const home = mkdtempSync(join(tmpdir(), "ranwhat-push-e2e-"));
  try {
    const { root, cwd } = history(home);
    const free = link(e, orgWith(e, "Free Co", "free"), "free-laptop");
    const user = await accounts.userForVerifiedEmail(e, { email: "ana@example.com" });
    const plusOrg = (await accounts.orgFor(e, user.id)).id;
    run(e, "UPDATE orgs SET name = 'Plus Co' WHERE id = ?", plusOrg);
    run(e, "INSERT INTO grants (org_id, plan, starts_at, until, note, created_at) VALUES (?, 'plus', ?, NULL, 'test', ?)",
        plusOrg, unix() - 60, unix());
    const dev = link(e, plusOrg, "work-laptop");

    // A Free organisation is refused, says so, and nothing is stored.
    let r = await ranwhat(server, home, free.tok, pushArgs(root));
    assert.equal(r.status, 1, r.stderr);
    assert.match(r.stderr, /Free/);
    assert.match(r.stderr, /Nothing was sent/);
    assert.equal(all(e, "SELECT * FROM pushes").length, 0);

    // The dry run prints the document and touches nothing.
    r = await ranwhat(server, home, dev.tok, ["push", "--dry-run", "--source", "claude-code", "--root", root]);
    assert.equal(r.status, 0, r.stderr);
    const dry = JSON.parse(r.stdout);
    assert.ok(dry.counts.flagged >= 2);
    assert.equal(all(e, "SELECT * FROM pushes").length, 0);

    // A Plus organisation's machine stores it.
    r = await ranwhat(server, home, dev.tok, pushArgs(root));
    assert.equal(r.status, 0, r.stderr);
    assert.match(r.stdout, /Sent to Plus Co/);
    let rows = all(e, "SELECT * FROM pushes");
    assert.equal(rows.length, 1);
    assert.equal(rows[0].machine_id, dev.id);
    assert.equal(rows[0].org_id, plusOrg);
    assert.equal(rows[0].flagged, dry.counts.flagged);
    const stored = JSON.parse(rows[0].actions);
    assert.deepEqual(stored.map((a) => a.id).sort(), dry.actions.map((a) => a.id).sort());
    const rules = new Set(stored.flatMap((a) => a.hits.map((h) => h.rule)));
    assert.ok(rules.has("cred.read") && rules.has("git.destructive"), [...rules].join());

    // Nothing planted reached any table, whichever one it would be in.
    const dumped = JSON.stringify(["pushes", "machines", "tokens", "throttle", "orgs"].map((t) => all(e, `SELECT * FROM ${t}`)));
    for (const planted of [CANARY, STRIPE, "sk_live", "aws", "credentials", "git push", "npm", "toolu_", "clients",
                           home, cwd, "projects", hostname(), userInfo().username, "session"]) {
      if (planted === "" || planted === undefined) continue;
      assert.ok(!dumped.includes(planted), `${planted} reached the database`);
    }

    // The same findings again: unchanged, one row.
    r = await ranwhat(server, home, dev.tok, pushArgs(root));
    assert.equal(r.status, 0, r.stderr);
    assert.match(r.stdout, /Nothing changed since this machine last pushed/);
    rows = all(e, "SELECT * FROM pushes");
    assert.equal(rows.length, 1);
    assert.equal(rows[0].seq, 1);

    // The cross-machine view shows it, to a member of that organisation.
    const { value, statements } = await openSession(e, { user: user.id, org: plusOrg });
    await e.LIST.batch(statements);
    const page = await worker.fetch(new Request("https://account.ranwhat.com/findings",
      { headers: { cookie: `__Host-rw_session=${value}` } }), e, ctx);
    const html = await page.text();
    assert.equal(page.status, 200);
    assert.match(html, /work-laptop/);
    assert.match(html, /cred\.read/);
    assert.ok(!html.includes(CANARY) && !html.includes(STRIPE));

    // A body with a key the allow-list does not name is refused, whoever
    // sends it, and stores nothing.
    const doc = JSON.parse(JSON.stringify(dry));
    doc.generated_at = new Date().toISOString().replace(/\.\d+Z$/, "Z");
    doc.hostname = hostname();
    const bad = await fetch(`http://127.0.0.1:${server.address().port}/v1/push`, {
      method: "POST", headers: { authorization: `Bearer ${dev.tok}`, "content-type": "application/json" }, body: JSON.stringify(doc),
    });
    assert.equal(bad.status, 422);
    const said = await bad.json();
    assert.deepEqual([said.error, said.reason, said.field], ["invalid", "unknown_key", "/"]);
    assert.ok(!JSON.stringify(said).includes("hostname"));
    doc.generated_at = new Date().toISOString().replace(/\.\d+Z$/, "Z");
    delete doc.hostname;
    doc.actions[0].cwd = cwd;
    const bad2 = await fetch(`http://127.0.0.1:${server.address().port}/v1/push`, {
      method: "POST", headers: { authorization: `Bearer ${dev.tok}`, "content-type": "application/json" }, body: JSON.stringify(doc),
    });
    assert.equal(bad2.status, 422);
    assert.equal(all(e, "SELECT * FROM pushes").length, 1);
    assert.ok(!JSON.stringify(all(e, "SELECT * FROM pushes")).includes(cwd));
  } finally {
    server.close();
    rmSync(home, { recursive: true, force: true });
  }
});
