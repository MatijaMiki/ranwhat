#!/usr/bin/env python3
"""A markdown twin of every page, for AI agents, built from the page itself.

The site is hand-written HTML, so each page's <main> is the source and its
markdown is derived from it at build time: /commands.md for /commands,
/index.md for /. Nothing here is committed; build.sh runs this on the throwaway
checkout CI and Cloudflare Pages build from, so the twins cannot drift from
the pages. It also writes /llms-full.txt (every twin in one file) and
/md-catalog.json (every twin's URL, title and summary).

functions/_middleware.js serves the twins with their headers and answers
Accept: text/markdown with them. tests/test_site_md.py checks that every
indexable page has one.

Run: python3 scripts/build_md.py [OUTDIR]   (default: site/, next to the pages)
"""
import html
import html.parser
import json
import pathlib
import re
import sys

SITE = pathlib.Path(__file__).resolve().parent.parent / "site"
ORIGIN = "https://ranwhat.com"

# Pages with no twin, and why. Every other page gets one.
SKIP = {
    "404.html": "the not-found page, noindex",
    "example-report.html": "a sample of the tool's own report, not prose",
}

# llms-full.txt reads in this order: the tool, then the guides, then the rest.
FIRST = ["index.html", "install.html", "commands.html", "watch.html", "clean.html",
         "scan.html", "pricing.html", "faq.html", "about.html", "guides.html"]
LAST = ["updates.html", "contact.html", "privacy.html", "terms.html"]
FULL_WARN_CHARS = 500_000

VOID = {"br", "wbr", "img", "input", "meta", "link", "hr", "source", "col", "area"}
# Never content: interface, navigation and form controls. A <form> itself stays:
# pricing's Plus card is one.
DROP_TAGS = {"script", "style", "svg", "button", "nav", "noscript", "template",
             "select", "textarea", "input", "label"}
DROP_CLASSES = {"docnav", "marginal", "eyebrow", "crumbs", "copy"}
BLOCK = {"p", "div", "section", "article", "aside", "header", "footer", "main", "ul",
         "ol", "li", "pre", "table", "h1", "h2", "h3", "h4", "h5", "h6", "blockquote",
         "figure", "dl", "dt", "dd", "details", "summary", "form", "fieldset"}


class Node:
    def __init__(self, tag, attrs=None, parent=None):
        self.tag, self.attrs, self.parent, self.children = tag, dict(attrs or {}), parent, []

    @property
    def classes(self):
        return set((self.attrs.get("class") or "").split())


class Tree(html.parser.HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.root = self.cur = Node("root")

    def handle_starttag(self, tag, attrs):
        node = Node(tag, attrs, self.cur)
        self.cur.children.append(node)
        if tag not in VOID:
            self.cur = node

    def handle_endtag(self, tag):
        node = self.cur
        while node is not self.root and node.tag != tag:
            node = node.parent
        if node is not self.root:
            self.cur = node.parent

    def handle_data(self, data):
        self.cur.children.append(data)


def parse(fragment):
    tree = Tree()
    tree.feed(fragment)
    tree.close()
    return tree.root


def dropped(node):
    return node.tag in DROP_TAGS or bool(node.classes & DROP_CLASSES)


def text_of(node):
    """Raw text, whitespace kept (for <pre>)."""
    if isinstance(node, str):
        return node
    if dropped(node):
        return ""
    return "".join(text_of(c) for c in node.children)


def iter_tags(node, tag):
    for c in node.children:
        if isinstance(c, str):
            continue
        if c.tag == tag:
            yield c
        else:
            yield from iter_tags(c, tag)


def absolute(href, page_url):
    if href.startswith("#"):
        return page_url + href
    if href.startswith("/"):
        return ORIGIN + href
    return href


class Renderer:
    def __init__(self, page_url):
        self.url = page_url

    # -- inline ------------------------------------------------------------
    def inline(self, node):
        if isinstance(node, str):
            return re.sub(r"\s+", " ", node)
        if dropped(node):
            return ""
        tag = node.tag
        if tag == "br":
            return "\n"
        if tag == "img":
            return node.attrs.get("alt") or ""
        if tag == "code" or "icode" in node.classes:
            code = " ".join(text_of(node).split())
            return "`%s`" % code if code else ""
        inner = "".join(self.inline(c) for c in node.children)
        if tag in ("strong", "b"):
            return "**%s**" % inner.strip() if inner.strip() else ""
        if tag in ("em", "i"):
            return "*%s*" % inner.strip() if inner.strip() else ""
        if tag == "a":
            href = node.attrs.get("href") or ""
            label = " ".join(inner.split())
            if not href or not label:
                return label
            label = label.replace("[", "\\[").replace("]", "\\]")
            return "[%s](%s)" % (label, absolute(href, self.url))
        return inner

    def para(self, nodes):
        joined = "".join(self.inline(n) for n in nodes)
        return "\n".join(" ".join(line.split()) for line in joined.split("\n")).strip()

    # -- blocks ------------------------------------------------------------
    def blocks(self, node):
        """A container's children as a list of markdown blocks."""
        out, run = [], []

        def flush():
            text = self.para(run)
            if text:
                out.append(text)
            run.clear()

        for child in node.children:
            if isinstance(child, str) or (child.tag not in BLOCK
                                          and not child.classes & {"term", "cmd", "rows"}):
                run.append(child)
                continue
            flush()
            out.extend(self.block(child))
        flush()
        return out

    def block(self, node):
        if dropped(node):
            return []
        tag, cls = node.tag, node.classes
        if "term" in cls:
            return [self.terminal(node)]
        if "cmd" in cls:
            parts = [text_of(c) for c in node.children
                     if not isinstance(c, str) and c.tag != "button"
                     and not {"dollar", "copy"} & c.classes]
            return ["```\n$ %s\n```" % " ".join(" ".join(parts).split())]
        if "rows" in cls:
            return [self.rows(node)]
        if tag in ("h1", "h2", "h3", "h4", "h5", "h6"):
            text = self.para(node.children)
            return ["%s %s" % ("#" * int(tag[1]), text)] if text else []
        if tag in ("p", "dt", "dd", "summary"):
            text = self.para(node.children)
            return [text] if text else []
        if tag in ("ul", "ol"):
            return [self.listing(node, 0)]
        if tag == "pre":
            return ["```\n%s\n```" % text_of(node).strip("\n")]
        if tag == "table":
            return [self.table(node)]
        if tag == "blockquote":
            inner = "\n\n".join(self.blocks(node))
            return ["\n".join("> " + line for line in inner.split("\n"))]
        return self.blocks(node)

    def terminal(self, node):
        bar, body = "", ""
        for c in node.children:
            if isinstance(c, str):
                continue
            if "term-bar" in c.classes:
                bar = " ".join(text_of(c).split())
            elif "term-body" in c.classes:
                body = text_of(c).strip("\n")
        lines = (["$ " + bar] if bar else []) + ([body] if body else [])
        return "```\n%s\n```" % "\n".join(lines)

    def rows(self, node):
        items = []
        for row in node.children:
            if isinstance(row, str) or "row" not in row.classes:
                continue
            spans = [c for c in row.children if not isinstance(c, str)]
            key = next((self.para([c]) for c in spans if "k" in c.classes), "")
            val = next((self.para([c]) for c in spans if "v" in c.classes), "")
            items.append("- **%s**: %s" % (key, val) if key else "- %s" % val)
        return "\n".join(items)

    def listing(self, node, depth):
        lines, n = [], 0
        for li in node.children:
            if isinstance(li, str) or li.tag != "li":
                continue
            n += 1
            marker = "%d." % n if node.tag == "ol" else "-"
            holder = Node("div")
            holder.children = [c for c in li.children
                               if isinstance(c, str) or c.tag not in ("ul", "ol")]
            text = " ".join(" ".join(self.blocks(holder)).split())
            lines.append("%s%s %s" % ("  " * depth, marker, text))
            for sub in li.children:
                if not isinstance(sub, str) and sub.tag in ("ul", "ol"):
                    lines.append(self.listing(sub, depth + 1))
        return "\n".join(lines)

    def table(self, node):
        rows = []
        for tr in iter_tags(node, "tr"):
            cells = [c for c in tr.children if not isinstance(c, str) and c.tag in ("th", "td")]
            rows.append([self.para(c.children).replace("|", "\\|").replace("\n", " ")
                         for c in cells])
        if not rows:
            return ""
        width = max(len(r) for r in rows)
        rows = [r + [""] * (width - len(r)) for r in rows]
        out = ["| %s |" % " | ".join(rows[0]), "| %s |" % " | ".join(["---"] * width)]
        out += ["| %s |" % " | ".join(r) for r in rows[1:]]
        return "\n".join(out)


def url_for(rel):
    """Where Pages serves a page: extensionless, / for index.html."""
    return ORIGIN + "/" if rel == "index.html" else ORIGIN + "/" + rel[:-len(".html")]


def md_url_for(rel):
    return ORIGIN + "/" + rel[:-len(".html")] + ".md"


def first(pattern, text):
    m = re.search(pattern, text, re.S)
    return html.unescape(m.group(1)).strip() if m else ""


def render(rel):
    """One page's twin, or None when it has no <main>."""
    text = (SITE / rel).read_text(encoding="utf-8")
    main = re.search(r"<main[^>]*>(.*)</main>", text, re.S)
    if not main:
        return None
    url = url_for(rel)
    tree = parse(main.group(1))
    renderer = Renderer(url)
    h1 = next(iter_tags(tree, "h1"), None)
    heading = renderer.para(h1.children) if h1 else first(r"<title>([^<]*)</title>", text)
    if h1 is not None:
        h1.tag = "template"  # in the title line, not again in the body
    summary = first(r'<meta name="description" content="([^"]*)">', text)
    updated = first(r'<time datetime="([0-9-]{10})', text)
    head = ["# " + heading, "> " + summary,
            "Canonical: " + url + ("\nLast updated: " + updated if updated else "")]
    return {"rel": rel, "url": url, "md": md_url_for(rel), "title": heading, "summary": summary,
            "markdown": "\n\n".join(head + renderer.blocks(tree)).rstrip() + "\n"}


def pages():
    """Every page with a twin, in llms-full.txt order."""
    found = sorted(p.relative_to(SITE).as_posix() for p in SITE.rglob("*.html"))
    found = [r for r in found if r not in SKIP]
    middle = [r for r in found if r not in FIRST and r not in LAST]
    return [r for r in FIRST if r in found] + middle + [r for r in LAST if r in found]


def build(out):
    out = pathlib.Path(out)
    twins = []
    for rel in pages():
        twin = render(rel)
        if twin is None:
            raise SystemExit("build_md: %s has no <main>; add it to SKIP with a reason" % rel)
        dest = out / (rel[:-len(".html")] + ".md")
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(twin["markdown"], encoding="utf-8")
        twins.append(twin)

    parts = ["# ranwhat - full content\n\n> Every page of ranwhat.com as markdown, in one file.\n\n"
             "Index: %s/llms.txt. Any single page: its URL with .md." % ORIGIN]
    parts += ["---\n<!-- source: %s -->\n%s" % (t["url"], t["markdown"]) for t in twins]
    full = "\n\n".join(parts)
    if len(full) > FULL_WARN_CHARS:
        print("build_md: warning: llms-full.txt is %d chars" % len(full), file=sys.stderr)
    (out / "llms-full.txt").write_text(full, encoding="utf-8")

    catalog = {"site": ORIGIN + "/", "count": len(twins),
               "pages": [{k: t[k] for k in ("url", "md", "title", "summary")} for t in twins]}
    (out / "md-catalog.json").write_text(json.dumps(catalog, indent=2, ensure_ascii=False) + "\n",
                                         encoding="utf-8")
    print("build_md: %d markdown twins, llms-full.txt %d chars" % (len(twins), len(full)))
    return twins


if __name__ == "__main__":
    build(sys.argv[1] if len(sys.argv) > 1 else SITE)
