/* Everything that is not the canonical hostname is sent to it.
 *
 * Cloudflare always publishes a project at <name>.pages.dev and that cannot be
 * turned off, so without this it is a second indexable origin serving
 * identical content. www is the same problem with a longer history: every page
 * already declares <link rel="canonical"> without it, so the redirect just
 * makes the HTTP layer agree with the HTML.
 *
 * Preview deployments at <hash>.ranwhat.pages.dev are deliberately left alone,
 * since redirecting those would remove the ability to check a branch before it
 * ships.
 *
 * Then the markdown twins scripts/build_md.py writes next to each page, for AI
 * agents: /commands.md is /commands as markdown, /index.md is /. They are
 * served noindex with the HTML page as canonical, and a request for a page
 * whose Accept header ranks text/markdown above text/html gets its twin.
 * Accept: * / * or none at all always gets HTML. No user-agent checks: the same
 * request gets the same answer whoever sends it.
 */
const CANONICAL_HOST = "ranwhat.com";
const ORIGIN = "https://" + CANONICAL_HOST;
const REDIRECT_FROM = new Set(["ranwhat.pages.dev", "www.ranwhat.com"]);

const DESCRIBED_BY = [
  `<${ORIGIN}/llms.txt>; rel="describedby"; type="text/plain"`,
  `<${ORIGIN}/llms-full.txt>; rel="describedby"; type="text/plain"`,
  `<${ORIGIN}/ai.txt>; rel="describedby"; type="text/plain"`,
].join(", ");

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, HEAD, OPTIONS",
  "Access-Control-Allow-Headers": "Accept",
  "Access-Control-Expose-Headers": "X-Markdown-Tokens, Content-Location, Link",
};

/** "/commands.md" -> "https://ranwhat.com/commands", "/index.md" -> ".../" */
function canonicalFor(mdPath) {
  const page = mdPath.slice(0, -".md".length);
  return ORIGIN + (page === "/index" ? "/" : page);
}

/** True only when text/markdown is named and outranks text/html (RFC 9110 q-values). */
export function prefersMarkdown(header) {
  const ranges = (header || "").toLowerCase().split(",").map((part) => {
    const [type, ...params] = part.trim().split(";");
    const q = params.map((p) => p.trim()).find((p) => p.startsWith("q="));
    const value = q ? Number(q.slice(2)) : 1;
    return { type: type.trim(), q: Number.isFinite(value) ? value : 0 };
  });
  const md = ranges.find((r) => r.type === "text/markdown");
  if (!md || md.q <= 0) return false;
  const html = ranges.find((r) => r.type === "text/html")
    || ranges.find((r) => r.type === "text/*")
    || ranges.find((r) => r.type === "*/*");
  return md.q > (html ? html.q : 0);
}

/** The twin itself, always by GET, so a HEAD can still count its tokens. */
function twinAsset(env, url, path) {
  return env.ASSETS.fetch(new Request(new URL(path, url), { method: "GET" }));
}

async function asMarkdown(res, canonical, negotiated, head) {
  const body = await res.text();
  const headers = new Headers(res.headers);
  headers.set("Content-Type", "text/markdown; charset=utf-8");
  headers.set("X-Markdown-Tokens", String(Math.ceil(body.length / 4)));
  headers.set("X-Robots-Tag", "noindex, follow");
  headers.set("Content-Location", canonical);
  headers.set("Link", `<${canonical}>; rel="canonical", ${DESCRIBED_BY}`);
  headers.set("Cache-Control", "public, max-age=3600");
  headers.delete("Content-Length");
  for (const [k, v] of Object.entries(CORS)) headers.set(k, v);
  if (negotiated) headers.set("Vary", "Accept");
  return new Response(head ? null : body, { status: res.status, headers });
}

function markdownNotFound(path) {
  const body = `# Not found\n\n> ${ORIGIN}${path} has no markdown version.\n\n`
    + `Every page with one: ${ORIGIN}/md-catalog.json\nThe site at a glance: ${ORIGIN}/llms.txt\n`;
  return new Response(body, {
    status: 404,
    headers: { "Content-Type": "text/markdown; charset=utf-8", "X-Robots-Tag": "noindex", ...CORS },
  });
}

export const onRequest = async ({ request, next, env }) => {
  const url = new URL(request.url);
  if (REDIRECT_FROM.has(url.hostname)) {
    url.hostname = CANONICAL_HOST;
    url.protocol = "https:";
    return Response.redirect(url.toString(), 301);
  }

  const path = url.pathname;
  const head = request.method === "HEAD";
  if (path.endsWith(".md")) {
    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: CORS });
    const res = head ? await twinAsset(env, url, path) : await next();
    // A missing twin comes back as Pages' HTML 404 page; answer in markdown instead.
    if (!res.ok || (res.headers.get("Content-Type") || "").startsWith("text/html")) {
      return markdownNotFound(path);
    }
    return asMarkdown(res, canonicalFor(path), false, head);
  }

  const isPage = !/\.[a-z0-9]+$/i.test(path) && !path.startsWith("/api/") && !path.startsWith("/cdn-cgi/");
  if (isPage && (request.method === "GET" || head)
      && prefersMarkdown(request.headers.get("Accept"))) {
    const mdPath = path === "/" ? "/index.md" : path.replace(/\/+$/, "") + ".md";
    const twin = await twinAsset(env, url, mdPath);
    if (twin.ok && !(twin.headers.get("Content-Type") || "").startsWith("text/html")) {
      return asMarkdown(twin, canonicalFor(mdPath), true, head);
    }
  }

  const res = await next();
  if (isPage && (res.headers.get("Content-Type") || "").startsWith("text/html")) {
    const headers = new Headers(res.headers);
    headers.append("Link", DESCRIBED_BY);
    headers.append("Vary", "Accept");
    return new Response(res.body, { status: res.status, statusText: res.statusText, headers });
  }
  return res;
};
