/* Previews of account.ranwhat.com's pages, to look at them while changing
 * them: the Worker's own fetch over the tests' in-memory SQLite stand-in
 * (worker/test/stand-ins.mjs), with a few made-up accounts in it, served
 * on 127.0.0.1 with the headers the Worker sends (its CSP included, so a
 * style or script the policy would refuse is refused here too), and,
 * optionally, screenshotted with a local Chromium (Chrome, Brave, Edge or
 * Chromium) driven over the DevTools protocol.
 *
 *   node worker/scripts/account_preview.mjs serve [port]
 *       Serves every scenario until stopped: http://127.0.0.1:<port>/
 *       lists them (default port 8789).
 *   node worker/scripts/account_preview.mjs shots <dir> [--only a,b] [--browser path]
 *       Writes <dir>/<scenario>--<page>--<width>-<theme>.png for every
 *       scenario's pages, at 1440 and 390 pixels wide, light and dark,
 *       and reports anything the browser's console says (a CSP refusal,
 *       say). --only: scenarios whose names start with these.
 *   node worker/scripts/account_preview.mjs html <dir>
 *       Writes each page's HTML.
 *
 * Nothing leaves this machine: the database is in memory, no page drawn
 * here mails anyone (the Worker's own calls out are answered by a stand-in
 * that refuses), and the browser runs headless with a profile of its own
 * in a temporary directory, removed afterwards, with every https request
 * blocked, so Turnstile's script is not loaded on the pages that would.
 * The passkey pages' script is refused too, by their own CSP, since the
 * preview is not served from account.ranwhat.com. Run from the
 * repository root.
 */
import { createServer } from "node:http";
import { spawn } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { d1 } from "../test/stand-ins.mjs";

const worker = (await import("../src/index.js")).default;
const accounts = await import("../src/accounts.js");
const { schema: feedSchema } = await import("../src/auth.js");
const { openSession } = await import("../src/session.js");
const { attachPassword, hashPassword } = await import("../src/password.js");

const ORIGIN = "https://account.ranwhat.com";
const DAY = 86400;
const now = () => Math.floor(Date.now() / 1000);
const sha = (t) => createHash("sha256").update(t).digest("hex");

/* No page here should call out; anything that tries is refused. Only the
   screenshots' own calls to the local browser use the real fetch. */
const realFetch = globalThis.fetch;
globalThis.fetch = async (url) => new Response(`preview: ${url} is not reached`, { status: 503 });

const env = {
  LIST: d1(), RESEND_API_KEY: "re_preview", ACCOUNT_SECRET: "preview-secret-that-is-long-enough-0123456789",
  TURNSTILE_SECRET: "preview", ACCOUNTS_ON: "1",
  GOOGLE_CLIENT_ID: "preview.apps.googleusercontent.com", GOOGLE_CLIENT_SECRET: "preview",
  GITHUB_CLIENT_ID: "Iv1.preview", GITHUB_CLIENT_SECRET: "preview",
};
const run = (sql, ...p) => env.LIST.sql.prepare(sql).run(...p);

await feedSchema(env.LIST);
await accounts.schema(env.LIST);

async function person(email) {
  const user = (await accounts.userForVerifiedEmail(env, { email })).id;
  const org = (await accounts.orgFor(env, user)).id;
  return { user, org };
}

async function session(user, org, { fresh = false } = {}) {
  const { value, statements } = await openSession(env, { user, org });
  await env.LIST.batch(statements);
  if (!fresh) run("UPDATE sessions SET authed_at = ? WHERE id = ?", now() - 3 * 3600, sha(value));
  return value;
}

function machine(org, user, kind, label, { days = 3, used = 0 } = {}) {
  const hash = sha(randomBytes(32).toString("hex"));
  run("INSERT INTO tokens (hash, note, created_at) VALUES (?, ?, ?)", hash, `machine ${kind}`, now() - days * DAY);
  run(`INSERT INTO machines (id, hash, org_id, user_id, kind, label, created_at, last_used_day)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, randomUUID(), hash, org, user, kind, label, now() - days * DAY,
  used === null ? null : Math.floor((now() - used * DAY) / DAY) * DAY);
}

function events(org, user, list) {
  for (const [what, ago] of list) {
    run("INSERT INTO auth_events (org_id, user_id, event, subject, at) VALUES (?, ?, ?, NULL, ?)", org, user, what, now() - ago);
  }
}

/* ---------- the scenarios ---------- */

const SIGNED_IN = ["/", "/machines", "/members", "/billing", "/security", "/activity"];

/* Ana: owner of Acme Robotics on Free, one terminal, signed in with a
   code three hours ago, so not fresh. */
const ana = await person("ana@example.com");
run("UPDATE orgs SET name = 'Acme Robotics', personal = 0 WHERE id = ?", ana.org);
machine(ana.org, ana.user, "device", "Ana's MacBook", { days: 12, used: 1 });
events(ana.org, ana.user, [["signup", 20 * DAY], ["machine_linked", 12 * DAY], ["signin", 3 * DAY],
  ["signin", 3 * 3600], ["org_renamed", 3 * 3600 - 60]]);

/* Bo: just made his account; nothing linked, fresh. */
const bo = await person("bo@example.com");
events(bo.org, bo.user, [["signup", 120]]);

/* Cy: admin of Northwind on Plus (a grant), with a password, a passkey and
   Google, two terminals and a CI token, in two organisations, fresh. */
const owner = await person("dana.owner@northwind.example");
run("UPDATE orgs SET name = 'Northwind Labs', personal = 0 WHERE id = ?", owner.org);
run("INSERT INTO grants (org_id, plan, starts_at, until, note, created_at) VALUES (?, 'plus', ?, NULL, 'preview', ?)",
  owner.org, now() - 40 * DAY, now() - 40 * DAY);
const cy = await person("cy.admin@northwind.example");
run("INSERT INTO memberships (org_id, user_id, role, created_at) VALUES (?, ?, 'admin', ?)", owner.org, cy.user, now() - 30 * DAY);
for (const [email, role] of [["eve@northwind.example", "member"], ["fin@northwind.example", "member"]]) {
  const p = await person(email);
  run("INSERT INTO memberships (org_id, user_id, role, created_at) VALUES (?, ?, ?, ?)", owner.org, p.user, role, now() - 9 * DAY);
}
machine(owner.org, cy.user, "device", "cy-thinkpad", { days: 25, used: 0 });
machine(owner.org, owner.user, "device", "build-box", { days: 18, used: 2 });
machine(owner.org, cy.user, "ci", "GitHub Actions", { days: 10, used: 0 });
await env.LIST.batch(await attachPassword(env, { user: cy.user, org: owner.org, hash: await hashPassword(env, "correct horse battery staple") }));
run(`INSERT INTO passkeys (id, user_id, public_key, sign_count, backed_up, label, created_at, used_at)
     VALUES (?, ?, 'preview', 0, 1, 'Work laptop', ?, ?)`, randomBytes(16).toString("base64url"), cy.user, now() - 8 * DAY, now() - DAY);
run(`INSERT INTO identities (provider, provider_subject, user_id, verified_email, created_at)
     VALUES ('google', '1097', ?, 'cy.admin@northwind.example', ?)`, cy.user, now() - 6 * DAY);
events(owner.org, cy.user, [["signin_google", 6 * DAY], ["passkey_added", 8 * DAY], ["machine_linked", 25 * DAY],
  ["ci_token_created", 10 * DAY], ["stepup", 300], ["signin_passkey", 3600]]);

/* Eve: a member of Northwind, not fresh. */
const eve = (await env.LIST.prepare("SELECT id FROM users WHERE email = 'eve@northwind.example'").first()).id;

const SCENARIOS = {
  "free-owner": { cookie: await session(ana.user, ana.org), paths: [...SIGNED_IN, "/upgrade"] },
  "new-account": { cookie: await session(bo.user, bo.org, { fresh: true }), paths: ["/", "/security", "/machines"] },
  "plus-admin": { cookie: await session(cy.user, owner.org, { fresh: true }), paths: SIGNED_IN },
  "plus-member": { cookie: await session(eve, owner.org), paths: ["/", "/security"] },
  "signed-out": { cookie: "", paths: ["/signin", "/signup", "/signin/password", "/reset", "/signin/passkey", "/nowhere"] },
};

/* ---------- serving ---------- */

async function fetchPage(name, path) {
  const s = SCENARIOS[name];
  const headers = new Headers({ "cf-connecting-ip": "192.0.2.10" });
  if (s.cookie) headers.set("cookie", `__Host-rw_session=${s.cookie}`);
  return worker.fetch(new Request(`${ORIGIN}${path}`, { headers }), env, { waitUntil() {} });
}

/* /<scenario>/<path>: that scenario's page, its links rewritten to stay
   within the scenario. Redirects are followed within it. */
function serve(port) {
  const server = createServer(async (req, res) => {
    const url = new URL(req.url, "http://127.0.0.1");
    const [, name, ...rest] = url.pathname.split("/");
    if (!name || !Object.hasOwn(SCENARIOS, name)) {
      res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
      res.end(`<!doctype html><title>Previews</title><ul>${Object.entries(SCENARIOS).map(([n, s]) =>
        `<li>${n}: ${s.paths.map((p) => `<a href="/${n}${p}">${p}</a>`).join(" ")}</li>`).join("")}</ul>`);
      return;
    }
    let path = `/${rest.join("/")}${url.search}`;
    let r = await fetchPage(name, path);
    for (let hops = 0; r.status === 303 && hops < 3; hops++) {
      path = r.headers.get("location");
      if (!path.startsWith("/")) break;
      r = await fetchPage(name, path);
    }
    const headers = Object.fromEntries(r.headers);
    delete headers["strict-transport-security"];
    let body = await r.text();
    body = body.replace(/(href|action)="\/(?!\/)/g, `$1="/${name}/`);
    res.writeHead(r.status, headers);
    res.end(body);
  });
  return new Promise((resolve) => server.listen(port, "127.0.0.1", () => resolve(server)));
}

/* ---------- screenshots ---------- */

const BROWSERS = [
  "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
  "/Applications/Chromium.app/Contents/MacOS/Chromium",
  "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
  "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
  "/usr/bin/google-chrome", "/usr/bin/chromium", "/usr/bin/chromium-browser",
];

async function devtools(browserPath) {
  const profile = mkdtempSync(join(tmpdir(), "account-preview-"));
  const port = 9300 + Math.floor(Math.random() * 500);
  const child = spawn(browserPath, [
    "--headless=new", "--disable-gpu", "--no-first-run", "--no-default-browser-check", "--hide-scrollbars",
    `--user-data-dir=${profile}`, `--remote-debugging-port=${port}`, "about:blank",
  ], { stdio: "ignore" });
  let target;
  for (let i = 0; i < 100 && !target; i++) {
    await new Promise((r) => setTimeout(r, 100));
    try {
      const list = await (await realFetch(`http://127.0.0.1:${port}/json/list`)).json();
      target = list.find((t) => t.type === "page");
    } catch { /* not up yet */ }
  }
  if (!target) throw new Error("the browser did not start");
  const ws = new WebSocket(target.webSocketDebuggerUrl);
  await new Promise((resolve, reject) => { ws.onopen = resolve; ws.onerror = reject; });
  let id = 0;
  const waiting = new Map();
  let listeners = [];
  ws.onmessage = (m) => {
    const msg = JSON.parse(m.data);
    if (msg.id && waiting.has(msg.id)) {
      const { resolve, reject } = waiting.get(msg.id);
      waiting.delete(msg.id);
      if (msg.error) reject(new Error(msg.error.message)); else resolve(msg.result);
    } else if (msg.method) for (const l of listeners) l(msg);
  };
  const send = (method, params = {}) => new Promise((resolve, reject) => {
    waiting.set(++id, { resolve, reject });
    ws.send(JSON.stringify({ id, method, params }));
  });
  const close = () => {
    ws.close();
    child.kill();
    rmSync(profile, { recursive: true, force: true });
  };
  const once = (method) => new Promise((resolve) => {
    const l = (msg) => {
      if (msg.method !== method) return;
      listeners = listeners.filter((x) => x !== l);
      resolve(msg);
    };
    listeners.push(l);
  });
  return { send, on: (l) => listeners.push(l), once, close };
}

async function shots(dir, { only = [], browser } = {}) {
  const path = browser || BROWSERS.find((b) => existsSync(b));
  if (!path) throw new Error("no Chromium-based browser found: pass --browser <path>");
  mkdirSync(dir, { recursive: true });
  const server = await serve(0);
  const base = `http://127.0.0.1:${server.address().port}`;
  const b = await devtools(path);
  const said = [];
  b.on((msg) => {
    if (msg.method === "Log.entryAdded") said.push(msg.params.entry.text);
    if (msg.method === "Runtime.consoleAPICalled") said.push(msg.params.args.map((a) => a.value).join(" "));
  });
  await b.send("Page.enable");
  /* Only the preview itself is fetched: Turnstile's script, on the pages
     that mail a code, is refused rather than loaded from Cloudflare. */
  await b.send("Network.enable");
  await b.send("Network.setBlockedURLs", { urls: ["https://*", "wss://*"] });
  await b.send("Log.enable");
  await b.send("Runtime.enable");
  const written = [];
  try {
    for (const [name, s] of Object.entries(SCENARIOS)) {
      if (only.length && !only.some((o) => name.startsWith(o))) continue;
      for (const p of s.paths) {
        for (const [width, height, mobile] of [[1440, 900, false], [390, 844, true]]) {
          for (const theme of ["light", "dark"]) {
            await b.send("Emulation.setDeviceMetricsOverride", { width, height, deviceScaleFactor: 1, mobile });
            await b.send("Emulation.setEmulatedMedia", { features: [{ name: "prefers-color-scheme", value: theme }] });
            said.length = 0;
            const loaded = b.once("Page.loadEventFired");
            await b.send("Page.navigate", { url: `${base}/${name}${p}` });
            await Promise.race([loaded, new Promise((r) => setTimeout(r, 4000))]);
            await new Promise((r) => setTimeout(r, 150));
            const { result } = await b.send("Runtime.evaluate", {
              expression: "JSON.stringify([document.documentElement.scrollWidth, document.documentElement.scrollHeight])",
              returnByValue: true,
            });
            const [scrollW, scrollH] = JSON.parse(result.value);
            const shot = await b.send("Page.captureScreenshot", {
              format: "png", captureBeyondViewport: true,
              clip: { x: 0, y: 0, width, height: Math.min(scrollH, 6000), scale: 1 },
            });
            const file = join(dir, `${name}--${p === "/" ? "overview" : p.slice(1).replace(/\//g, "-")}--${width}-${theme}.png`);
            writeFileSync(file, Buffer.from(shot.data, "base64"));
            written.push(file);
            if (scrollW > width) console.log(`WIDE ${file}: ${scrollW}px wide at ${width}`);
            for (const text of said) console.log(`CONSOLE ${file}: ${text}`);
          }
        }
      }
    }
  } finally {
    b.close();
    server.close();
  }
  console.log(`${written.length} screenshots in ${dir}`);
}

async function html(dir) {
  mkdirSync(dir, { recursive: true });
  for (const [name, s] of Object.entries(SCENARIOS)) {
    for (const p of s.paths) {
      const r = await fetchPage(name, p);
      const file = join(dir, `${name}--${p === "/" ? "overview" : p.slice(1).replace(/\//g, "-")}.html`);
      writeFileSync(file, await r.text());
      console.log(`${r.status} ${file}`);
    }
  }
}

const [command = "serve", arg, ...more] = process.argv.slice(2);
const flag = (f) => { const i = more.indexOf(f); return i < 0 ? undefined : more[i + 1]; };
if (command === "serve") {
  const server = await serve(Number(arg) || 8789);
  console.log(`http://127.0.0.1:${server.address().port}/`);
} else if (command === "shots") {
  if (!arg) throw new Error("shots <dir>");
  await shots(arg, { only: (flag("--only") || "").split(",").filter(Boolean), browser: flag("--browser") });
  process.exit(0);
} else if (command === "html") {
  if (!arg) throw new Error("html <dir>");
  await html(arg);
} else {
  console.log("serve [port] | shots <dir> [--only a,b] [--browser path] | html <dir>");
}
