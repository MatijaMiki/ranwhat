"""Directory badges: the snippets directories give for linking back to
ranwhat, kept in scripts/badges.json and written from there into the three
files that have to agree on them.

    pbpaste | python3 scripts/badges.py add "Uneed"        the snippet on stdin
    python3 scripts/badges.py add "Uneed" --file badge.html
    python3 scripts/badges.py add "Noonlaunch" --file badge.html --self-host
    python3 scripts/badges.py list                          what is listed, and what each link passes
    python3 scripts/badges.py check                         online: fetch every badge image again
    python3 scripts/badges.py remove "Uneed"
    python3 scripts/badges.py sync                          rewrite the three files from badges.json

What it writes, and nothing else:
  site/index.html    the badges between <!-- badges:start --> and <!-- badges:end -->
  site/privacy.html  the names between <!-- badges:privacy:start --> and <!-- badges:privacy:end -->
  site/_headers      img-src: every badge's image host, sorted, after 'self' data:

Each snippet goes on the page byte for byte as its directory gave it, inside
an <li> of ours and nothing else. Their checkers read the home page's HTML
for the link as written: MarketingDB's found none while a class sat before
href (3d6fd70), and Maidensail's would not confirm its own image served from
here (306c8a3). So nothing in this file edits a snippet, and the page's
styles reach a badge only through the <li> around it.

A badge goes on the page only once its image has been fetched and set no
cookie, because the privacy page says that of each one. A directory whose
image does set one can still be listed with --self-host: the image is saved
under site/badges/ and served from here, and the page swaps only that src
for the local path. The snippet in badges.json stays as given, so its sha256
still matches; the visitor's browser never asks the directory for anything.
An SVG saved here must carry no script, handler, foreignObject or external
reference, and site/_headers gives /badges/* a policy of its own besides. add fetches it and
stamps the badge "checked"; add --offline leaves it in badges.json, unstamped,
and sync refuses to write the page until check has fetched it.

Running it twice changes nothing the second time. tests/test_badges.py fails
when any of the three files drifts from badges.json. Standard library only.
"""
import argparse
import datetime
import hashlib
import html
import html.parser
import json
import pathlib
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent

INDEX_MARKS = ("<!-- badges:start -->", "<!-- badges:end -->")
PRIVACY_MARKS = ("<!-- badges:privacy:start -->", "<!-- badges:privacy:end -->")

# Shown before the "more" disclosure. Twelve fills whole rows at each width
# the grid takes (four, three or two across). New badges go first, so a
# listing sits in the open part while its directory verifies it.
VISIBLE = 12

# Cloudflare Pages ignores a _headers line longer than 2,000 characters, with
# only a warning in the build log, and the site would then ship with no CSP.
CSP_LINE_MAX = 1900

# For a transparent badge drawn for one background: `add --ground light`.
GROUNDS = ("light", "dark")

ALLOWED_TAGS = {"a", "img", "picture", "source", "span", "div", "br"}
# The allowed tags that have no end tag.
VOID_TAGS = {"img", "source", "br"}
# A referrer policy on the image that would send the visitor's full URL,
# where the privacy page says each directory is told only ranwhat.com.
LEAKY_REFERRER = {"unsafe-url", "no-referrer-when-downgrade"}


class Files:
    """The badge list and the three files written from it, under one root
    (the repository, or a copy of it in a test)."""

    def __init__(self, root=ROOT):
        root = pathlib.Path(root)
        self.data = root / "scripts" / "badges.json"
        self.index = root / "site" / "index.html"
        self.privacy = root / "site" / "privacy.html"
        self.headers = root / "site" / "_headers"
        self.site = root / "site"


# --------------------------------------------------------------------------
# One snippet
# --------------------------------------------------------------------------

class _Tags(html.parser.HTMLParser):
    """Start and end tags in order, with attributes, as the browser sees them."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.events = []

    def handle_starttag(self, tag, attrs):
        self.events.append((tag, [(k, v or "") for k, v in attrs]))

    def handle_startendtag(self, tag, attrs):
        # A browser ignores the slash in <img/> and in <a/> alike: the first
        # has no end tag anyway, and the second stays open.
        self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag):
        self.events.append(("/" + tag, []))


def _events(snippet):
    parser = _Tags()
    parser.feed(snippet)
    parser.close()
    return parser.events


def _starts(snippet):
    return [(t, attrs) for t, attrs in _events(snippet) if not t.startswith("/")]


def image_urls(snippet):
    """Every URL the browser may fetch for the badge: src and srcset."""
    urls = []
    for tag, attrs in _starts(snippet):
        if tag not in ("img", "source"):
            continue
        for name, value in attrs:
            if name == "src":
                urls.append(value.strip())
            elif name == "srcset":
                urls += [c.split()[0] for c in value.split(",") if c.strip()]
    return urls


def origin(url):
    parts = urllib.parse.urlsplit(url.strip())
    return "%s://%s" % (parts.scheme.lower(), parts.netloc.lower())


def hosts(badge):
    """The origins img-src has to allow for one badge: its image URLs, then
    any host its image redirected through when it was added. A self-hosted
    image is served from here, which 'self' already allows."""
    out = []
    local = (badge.get("self_host") or {}).get("src")
    urls = [u for u in image_urls(badge["snippet"]) if u != local]
    for o in [origin(u) for u in urls] + badge.get("extra_hosts", []):
        if o not in out:
            out.append(o)
    return out


def rel(snippet):
    """The link's rel tokens, lower-cased."""
    for tag, attrs in _starts(snippet):
        if tag == "a":
            return dict(attrs).get("rel", "").lower().replace(",", " ").split()
    return []


def followed(snippet):
    # Search engines read only nofollow, sponsored and ugc. Anything else,
    # "dofollow" included, leaves an ordinary followed link.
    return not {"nofollow", "sponsored", "ugc"} & set(rel(snippet))


def validate(snippet):
    """Why this snippet cannot go on the page as given; [] when it can."""
    if not snippet:
        return ["it is empty"]
    problems = []
    if snippet != snippet.strip():
        problems.append("it starts or ends with whitespace")
    if "\u2014" in snippet:
        problems.append("it has an em dash, and the site has none "
                        "(tests/test_site_claims.py, NoEmDashes)")
    if "<!--" in snippet or "-->" in snippet:
        problems.append("it has an HTML comment, which would confuse the page's markers")
    events = _events(snippet)
    starts = [(t, attrs) for t, attrs in events if not t.startswith("/")]
    names = [t for t, _ in starts]
    for tag in sorted(set(names) - ALLOWED_TAGS):
        problems.append("<%s>: a badge here is one link around one image; ask the "
                        "directory for its plain image badge" % tag)
    if names.count("a") != 1:
        problems.append("expected one <a>, found %d" % names.count("a"))
    if names.count("img") != 1:
        problems.append("expected one <img>, found %d" % names.count("img"))
    inside = 0
    for tag, attrs in events:
        if tag == "a":
            inside += 1
        elif tag == "/a":
            inside -= 1
        elif tag == "img" and inside < 1:
            problems.append("the image is not inside the link")
    # Every tag the snippet opens it closes, in order, and it closes nothing
    # else. A browser keeps an unclosed <a> open and wraps it around the text
    # that follows, the rest of the section and the footer included, and a
    # stray </ul> closes our list early.
    still_open = []
    for tag, _ in events:
        if not tag.startswith("/"):
            if tag not in VOID_TAGS:
                still_open.append(tag)
            continue
        name = tag[1:]
        if name in VOID_TAGS:
            continue  # </img> is ignored, and </br> is read as <br>
        if name not in still_open:
            problems.append("</%s> closes something the snippet did not open" % name)
            continue
        if still_open[-1] != name:
            problems.append("the tags do not close in order: </%s> comes before </%s>"
                            % (name, still_open[-1]))
        # Carry on as though it closed whatever was opened inside it.
        del still_open[len(still_open) - 1 - still_open[::-1].index(name):]
    for name in still_open:
        problems.append("<%s> is never closed" % name)
    for tag, attrs in starts:
        given = dict(attrs)
        for name, value in attrs:
            if re.fullmatch(r"on[a-z]+", name):
                problems.append("%s= on <%s>: an inline handler, which the CSP refuses"
                                % (name, tag))
            if re.sub(r"\s", "", value).lower().startswith("javascript:"):
                problems.append("a javascript: URL on <%s>" % tag)
        if tag == "a" and not given.get("href", "").startswith("https://"):
            problems.append("the link is not https://")
        if tag == "img" and not given.get("alt", "").strip():
            problems.append("the image has no alt text, so the link has no name "
                            "for a screen reader")
        if given.get("referrerpolicy", "").strip().lower() in LEAKY_REFERRER:
            problems.append("referrerpolicy=%s on <%s> would send the visitor's full URL"
                            % (given["referrerpolicy"], tag))
    for url in image_urls(snippet):
        if not url.startswith("https://"):
            problems.append("image %s is not https://" % url)
    return problems


def validate_name(name):
    problems = []
    if not name or name != name.strip():
        problems.append("the name is empty or starts or ends with whitespace")
    if "\u2014" in name:
        problems.append("the name has an em dash")
    if "<" in name or ">" in name:
        problems.append("the name has < or >")
    return problems


def digest(snippet):
    return hashlib.sha256(snippet.encode("utf-8")).hexdigest()


# What an SVG saved under site/badges/ may not carry. An <img> never runs an
# SVG's script, but the file is also a page on ranwhat.com that anyone can
# open, and an external reference would ask a third party for it after all.
SVG_REFUSED = [
    (re.compile(r"<\s*script", re.I), "a <script>"),
    (re.compile(r"<\s*foreignObject", re.I), "a <foreignObject>"),
    (re.compile(r"\son[a-z]+\s*=", re.I), "an inline event handler"),
    (re.compile(r"(?:xlink:)?href\s*=\s*[\"'](?!#|data:)", re.I), "an href that is not local or data:"),
    (re.compile(r"url\(\s*[\"']?(?!#|data:)", re.I), "a url() that is not local or data:"),
    (re.compile(r"@import", re.I), "an @import"),
    (re.compile(r"<!ENTITY", re.I), "an entity declaration"),
]
SELF_HOST_TYPES = {"image/svg+xml": "svg", "image/png": "png", "image/webp": "webp"}


def svg_problems(data):
    text = data.decode("utf-8", "replace")
    return ["the SVG has %s" % why for pattern, why in SVG_REFUSED if pattern.search(text)]


def served(badge):
    """The snippet as the page carries it: as given, except that a
    self-hosted badge's image src points at the copy served from here."""
    snippet, local = badge["snippet"], badge.get("self_host")
    if not local:
        return snippet
    quoted = ['src="%s"' % local["src"], "src='%s'" % local["src"]]
    for q in quoted:
        if snippet.count(q) == 1:
            return snippet.replace(q, 'src="/%s"' % local["path"].split("site/", 1)[1])
    raise SystemExit("%s: its snippet no longer holds the src it was self-hosted from"
                     % badge["name"])


# --------------------------------------------------------------------------
# What the three files say
# --------------------------------------------------------------------------

def load(files):
    with open(files.data, encoding="utf-8") as f:
        return json.load(f)["badges"]


def save(files, badges):
    text = json.dumps({"badges": badges}, ensure_ascii=False, indent=2) + "\n"
    _write(files.data, text)


def _read(path):
    # Text mode reads a Windows checkout's CRLF as LF, the same as the tests.
    with open(path, encoding="utf-8") as f:
        return f.read()


def _write(path, text):
    with open(path, "w", encoding="utf-8", newline="") as f:
        f.write(text)


def _li(badge):
    ground = badge.get("ground")
    cls = ' class="on-%s"' % ground if ground in GROUNDS else ""
    return "<li%s>%s</li>" % (cls, served(badge))


def render_index(badges, indent):
    """The home page between its markers. Past the first VISIBLE, the rest go
    behind a disclosure; they are in the HTML either way, so a checker that
    reads the page without opening anything still finds every link."""
    shown, rest = badges[:VISIBLE], badges[VISIBLE:]
    lines = ['<ul class="listed">'] + ["  " + _li(b) for b in shown] + ["</ul>"]
    if rest:
        lines += ['<details class="reveal listed-more">',
                  "  <summary>%d more %s</summary>"
                  % (len(rest), "listing" if len(rest) == 1 else "listings"),
                  '  <ul class="listed">']
        lines += ["    " + _li(b) for b in rest]
        lines += ["  </ul>", "</details>"]
    return "\n" + "".join(indent + line + "\n" for line in lines) + indent


def render_privacy(badges):
    """'The directories are Maidensail (maidensail.com) and MarketingDB
    (marketingdb.live).', alphabetical, for a reader looking for one name."""
    parts = []
    for b in sorted(badges, key=lambda b: b["name"].casefold()):
        bare = [h.split("://", 1)[1] for h in hosts(b)]
        where = ", ".join(bare) if bare else "its image served from ranwhat.com"
        parts.append("%s (%s)" % (html.escape(b["name"], quote=False), where))
    if not parts:
        return "There are none at present."
    if len(parts) == 1:
        return "The directory is %s." % parts[0]
    return "The directories are %s and %s." % (", ".join(parts[:-1]), parts[-1])


def _span(text, marks, where):
    start, end = marks
    if text.count(start) != 1 or text.count(end) != 1:
        raise SystemExit("%s: expected %s and %s once each" % (where, start, end))
    i, j = text.index(start) + len(start), text.index(end)
    if j < i:
        raise SystemExit("%s: %s comes before %s" % (where, end, start))
    return i, j


def region(text, marks, where="page"):
    i, j = _span(text, marks, where)
    return text[i:j]


def marker_indent(text, marks):
    """The whitespace before the start marker on its line, so the generated
    lines sit at the same depth as the comment that opens them."""
    i = text.index(marks[0])
    line = text[text.rfind("\n", 0, i) + 1:i]
    return line if not line.strip() else ""


def _replace(text, marks, body, where):
    i, j = _span(text, marks, where)
    return text[:i] + body + text[j:]


def csp_line(headers_text):
    """The site-wide policy: the Content-Security-Policy line in the /* block.
    Other paths may set their own (/badges/* does), which badges never use."""
    lines, block = [], None
    for l in headers_text.splitlines():
        if l and not l[0].isspace():
            block = l.strip()
        elif block == "/*" and l.lstrip().startswith("Content-Security-Policy:"):
            lines.append(l)
    if len(lines) != 1:
        raise SystemExit("expected one Content-Security-Policy line under /* in site/_headers")
    return lines[0]


def img_src(line):
    for directive in line.split(":", 1)[1].split(";"):
        words = directive.split()
        if words and words[0] == "img-src":
            return words[1:]
    raise SystemExit("the CSP in site/_headers has no img-src")


def _is_host(token):
    return token.startswith(("https://", "http://"))


def with_hosts(line, badge_hosts, dropped=()):
    """The CSP line with img-src holding its keywords ('self' data:) as they
    were, then the badge hosts, sorted, then every other host it held, in its
    old order, minus `dropped`. Sorted, so a new badge inserts one host and
    moves no other."""
    old = img_src(line)
    wanted = sorted(set(badge_hosts))
    new = ([t for t in old if not _is_host(t)] + wanted
           + [t for t in old if _is_host(t) and t not in wanted and t not in dropped])
    return re.sub(r"\bimg-src [^;]*", lambda m: "img-src " + " ".join(new), line, count=1)


def all_hosts(badges):
    out = []
    for b in badges:
        for h in hosts(b):
            if h not in out:
                out.append(h)
    return out


def problems_with(badges):
    """What is wrong with the list itself, before anything is written."""
    out = []
    seen = set()
    for b in badges:
        for p in validate(b["snippet"]) + validate_name(b["name"]):
            out.append("%s: %s" % (b["name"], p))
        if digest(b["snippet"]) != b.get("sha256"):
            out.append("%s: the snippet is not the one given (its sha256 differs); "
                       "remove it and add it again from the directory's own snippet"
                       % b["name"])
        if b.get("ground") not in (None,) + GROUNDS:
            out.append("%s: ground must be one of %s" % (b["name"], ", ".join(GROUNDS)))
        if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", str(b.get("checked", ""))):
            out.append("%s: its image was never fetched to see that it sets no cookie, "
                       "which the privacy page says of every badge; run "
                       "python3 scripts/badges.py check" % b["name"])
        key = b["name"].casefold()
        if key in seen:
            out.append("%s: listed twice" % b["name"])
        seen.add(key)
    return out


def local_problems(files, badges):
    """A self-hosted image that is missing, or no longer the file that was
    checked when it was saved."""
    out = []
    for b in badges:
        local = b.get("self_host")
        if not local:
            continue
        path = files.site.parent / local["path"]
        if not path.is_file():
            out.append("%s: %s is missing; add it again with --self-host" % (b["name"], local["path"]))
            continue
        data = path.read_bytes()
        if hashlib.sha256(data).hexdigest() != local.get("sha256"):
            out.append("%s: %s is not the file that was checked (its sha256 differs)"
                       % (b["name"], local["path"]))
        if path.suffix == ".svg":
            out += ["%s: %s" % (b["name"], p) for p in svg_problems(data)]
    return out


def _slug(name):
    return re.sub(r"[^a-z0-9]+", "-", name.casefold()).strip("-") or "badge"


def self_host(files, name, snippet):
    """Fetch the badge's one image and save it under site/badges/. Returns the
    self_host record, or exits with why it cannot be served from here."""
    urls = image_urls(snippet)
    if len(urls) != 1:
        raise SystemExit("not added: --self-host needs a snippet with exactly one image URL")
    src = urls[0]
    request = urllib.request.Request(src, headers={
        "User-Agent": "Mozilla/5.0 (ranwhat badge check)",
        "Accept": "image/svg+xml,image/png,image/webp,image/*;q=0.8"})
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            kind = (response.headers.get("Content-Type") or "").split(";")[0].strip().lower()
            data = response.read((2 << 20) + 1)
    except (urllib.error.URLError, OSError, ValueError) as e:
        raise SystemExit("not added: could not fetch %s: %s" % (src, e))
    if kind not in SELF_HOST_TYPES:
        raise SystemExit("not added: %s is %s; --self-host takes only %s"
                         % (src, kind or "untyped", ", ".join(sorted(SELF_HOST_TYPES))))
    if len(data) > (2 << 20):
        raise SystemExit("not added: %s is over 2 MB" % src)
    if kind == "image/svg+xml":
        problems = svg_problems(data)
        if problems:
            raise SystemExit("not added:\n  " + "\n  ".join(problems))
    rel = "site/badges/%s.%s" % (_slug(name), SELF_HOST_TYPES[kind])
    path = files.site.parent / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)
    return {"src": src, "path": rel, "sha256": hashlib.sha256(data).hexdigest()}


def render(files, badges, dropped=()):
    """{path: new text} for the three files, worked out in full before any is
    written, so a refusal leaves them all as they were."""
    problems = problems_with(badges) + local_problems(files, badges)
    if problems:
        raise SystemExit("not written:\n  " + "\n  ".join(problems))
    index, privacy, headers = _read(files.index), _read(files.privacy), _read(files.headers)
    old = csp_line(headers)
    new = with_hosts(old, all_hosts(badges), dropped)
    if len(new) > CSP_LINE_MAX:
        raise SystemExit(
            "the CSP line would be %d characters. Cloudflare Pages ignores a "
            "_headers line over 2,000, and the site would ship with no CSP. "
            "Give img-src a Content-Security-Policy line of its own (browsers "
            "enforce both) or set the policy from functions/_middleware.js, "
            "then raise CSP_LINE_MAX." % len(new))
    indent = marker_indent(index, INDEX_MARKS)
    return {
        files.index: _replace(index, INDEX_MARKS, render_index(badges, indent),
                              "site/index.html"),
        files.privacy: _replace(privacy, PRIVACY_MARKS, render_privacy(badges),
                                "site/privacy.html"),
        files.headers: headers.replace(old, new, 1),
    }


def sync(files, badges, dropped=()):
    """Write whichever of the three files differ from what badges.json says.
    Returns the paths it changed; none on a second run."""
    changed = []
    for path, text in render(files, badges, dropped).items():
        if _read(path) != text:
            _write(path, text)
            changed.append(path)
    return changed


def drift(files, badges):
    """The files that do not say what badges.json says."""
    return [path for path, text in render(files, badges).items() if _read(path) != text]


# --------------------------------------------------------------------------
# Online: what the privacy page and img-src rely on
# --------------------------------------------------------------------------

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def _fetch(url, max_hops=6):
    """[(url, status, headers)], one per hop. Redirects are followed by hand,
    because the CSP checks the host of every hop, as the browser meets it."""
    opener = urllib.request.build_opener(_NoRedirect)
    hops = []
    for _ in range(max_hops):
        request = urllib.request.Request(
            url, headers={"User-Agent": "Mozilla/5.0 (ranwhat badge check)",
                          "Accept": "image/avif,image/webp,image/svg+xml,image/*,*/*;q=0.8"})
        try:
            with opener.open(request, timeout=15) as response:
                response.read(1 << 20)
                hops.append((url, response.status, response.headers))
                return hops
        except urllib.error.HTTPError as e:
            hops.append((url, e.code, e.headers))
            location = e.headers.get("Location") if e.headers else None
            if e.code in (301, 302, 303, 307, 308) and location:
                url = urllib.parse.urljoin(url, location)
                continue
            return hops
    return hops


def probe(snippet):
    """Fetch each image the snippet loads. Returns (hops, extra_hosts,
    problems): every hop, the hosts redirects went through beyond the image's
    own, and what would make the privacy page or the CSP wrong."""
    all_hops, extra, problems = [], [], []
    for url in image_urls(snippet):
        try:
            hops = _fetch(url)
        except (urllib.error.URLError, OSError, ValueError) as e:
            problems.append("could not fetch %s: %s" % (url, e))
            continue
        all_hops += hops
        for hop, _, _ in hops[1:]:
            if origin(hop) != origin(url) and origin(hop) not in extra:
                extra.append(origin(hop))
        status, headers = hops[-1][1], hops[-1][2]
        if status != 200:
            problems.append("%s answered %s" % (hops[-1][0], status))
        kind = (headers.get("Content-Type") or "") if headers else ""
        if status == 200 and not kind.lower().startswith("image/"):
            problems.append("%s is %s, not an image" % (hops[-1][0], kind or "untyped"))
        if any(h and h.get("Set-Cookie") for _, _, h in hops):
            problems.append("%s sets a cookie, and the privacy page says no badge does"
                            % url)
        corp = ((headers.get("Cross-Origin-Resource-Policy") or "") if headers else "").lower()
        if corp in ("same-origin", "same-site"):
            problems.append("%s sends Cross-Origin-Resource-Policy: %s, so browsers "
                            "will not show it here" % (hops[-1][0], corp))
    return all_hops, extra, problems


def _link_status(snippet):
    for tag, attrs in _starts(snippet):
        if tag == "a":
            href = dict(attrs).get("href", "")
            try:
                return href, _fetch(href)[-1][1]
            except (urllib.error.URLError, OSError, ValueError) as e:
                return href, str(e)
    return "", None


# --------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------

def _describe(badge):
    snippet = badge["snippet"]
    where = ", ".join(h.split("://", 1)[1] for h in hosts(badge)) or "ranwhat.com (self-hosted)"
    return "image from %s, link %s" % (
        where,
        "followed" if followed(snippet) else "not followed (rel=\"%s\")" % " ".join(rel(snippet)))


def _site(netloc):
    host = netloc.split("://", 1)[-1].split("@")[-1].split(":")[0].lower()
    return host[4:] if host.startswith("www.") else host


def other_sites(badge):
    """The image hosts that are not the linked directory's own site, nor
    under it: a CDN or a badge service, which the visitor's browser asks
    instead. The privacy page names whichever host it is."""
    link = ""
    for tag, attrs in _starts(badge["snippet"]):
        if tag == "a":
            link = _site(urllib.parse.urlsplit(dict(attrs).get("href", "")).netloc)
            break
    out = []
    for h in hosts(badge):
        site = _site(h)
        if not link or not (site == link or site.endswith("." + link)
                            or link.endswith("." + site)):
            out.append(h.split("://", 1)[1])
    return out


def cmd_add(args, files):
    if args.file:
        raw = _read(args.file)
    else:
        if sys.stdin.isatty():
            print("Paste the snippet, then Ctrl-D:", file=sys.stderr)
        raw = sys.stdin.read()
    snippet, name = raw.strip(), args.name.strip()
    problems = validate(snippet) + validate_name(name)
    if problems:
        raise SystemExit("not added:\n  " + "\n  ".join(problems))
    badges = load(files)
    same = [b for b in badges if b["name"].casefold() == name.casefold()]
    if same and same[0]["snippet"] == snippet:
        changed = sync(files, badges)
        print("%s is already listed with this snippet; %s." % (
            name, "brought %d file(s) back in step" % len(changed) if changed
            else "nothing changed"))
        return
    if same:
        raise SystemExit("%s is already listed with a different snippet. To swap it: "
                         "python3 scripts/badges.py remove \"%s\", then add it again."
                         % (name, same[0]["name"]))
    twin = [b for b in badges if b["snippet"] == snippet]
    if twin:
        raise SystemExit("this snippet is already listed, as %s" % twin[0]["name"])
    today = datetime.date.today().isoformat()
    badge = {"name": name, "added": today, "snippet": snippet, "sha256": digest(snippet)}
    if args.ground:
        badge["ground"] = args.ground
    if args.self_host:
        if args.offline:
            raise SystemExit("--self-host fetches the image, so it cannot be --offline")
        badge["self_host"] = self_host(files, name, snippet)
        # Its image is served from here, so the directory's cookie never
        # reaches a visitor: the check the privacy page describes is this.
        badge["checked"] = today
    elif not args.offline:
        _, extra, problems = probe(snippet)
        if problems:
            raise SystemExit("not added:\n  " + "\n  ".join(problems))
        if extra:
            badge["extra_hosts"] = extra
        # The privacy page says each badge was checked for cookies when it
        # was added. This is that check, and only a clean one stamps it.
        badge["checked"] = today
    # Newest first, unless --end: a directory usually verifies its badge in
    # the listing's first days, so it sits in the open part of the section.
    if args.end:
        badges.append(badge)
    else:
        badges.insert(0, badge)
    if args.offline:
        # Unchecked, it would make the privacy page untrue, so it waits in
        # badges.json, and sync refuses to write the page until check runs.
        save(files, badges)
        print("saved %s to scripts/badges.json, not yet on the page: its image was "
              "not fetched (--offline). python3 scripts/badges.py check fetches it "
              "and, if it sets no cookie, writes the three files." % name)
        return
    try:
        changed = sync(files, badges)
    except SystemExit:
        local = (badge.get("self_host") or {}).get("path")
        if local and (files.site.parent / local).is_file():
            (files.site.parent / local).unlink()
        raise
    save(files, badges)
    print("added %s: %s" % (name, _describe(badge)))
    for host in other_sites(badge):
        print("  note: the image comes from %s, not the directory's own site, so that "
              "is the host the privacy page names and visitors' browsers ask" % host)
    for path in changed:
        print("  wrote %s" % _shown(path, files))
    print("then: python3 -m unittest tests.test_badges tests.test_site_claims")


def cmd_remove(args, files):
    badges = load(files)
    gone = [b for b in badges if b["name"].casefold() == args.name.strip().casefold()]
    if not gone:
        raise SystemExit("no badge named %s; python3 scripts/badges.py list" % args.name)
    keep = [b for b in badges if b not in gone]
    dropped = set(all_hosts(gone)) - set(all_hosts(keep))
    changed = sync(files, keep, dropped)
    save(files, keep)
    for b in gone:
        local = (b.get("self_host") or {}).get("path")
        if local and (files.site.parent / local).is_file():
            (files.site.parent / local).unlink()
            print("  deleted %s" % local)
    print("removed %s%s" % (gone[0]["name"], "; img-src no longer allows " +
                            ", ".join(sorted(dropped)) if dropped else ""))
    for path in changed:
        print("  wrote %s" % _shown(path, files))


def cmd_sync(args, files):
    badges = load(files)
    changed = sync(files, badges)
    print("%d badges; %s" % (len(badges), "wrote " + ", ".join(
        _shown(p, files) for p in changed) if changed else "all three files already agree"))


def cmd_list(args, files):
    badges = load(files)
    width = max([len(b["name"]) for b in badges] + [4])
    for i, b in enumerate(badges):
        print("%-*s  %s  %s%s" % (width, b["name"], b["added"], _describe(b),
                                  "" if i < VISIBLE else "  [behind 'more']"))
    print("%d badges; followed links from the home page: %d"
          % (len(badges), sum(followed(b["snippet"]) for b in badges)))


def cmd_check(args, files):
    """Online: each image again. A badge added --offline gets its "checked"
    date here once its image passes, and goes on the page. Then offline: the
    list, and the three files against it. Then what each image and each
    listing's link answered."""
    badges = load(files)
    bad = 0
    today = datetime.date.today().isoformat()
    probed, stamped = [], []
    for b in badges:
        if b.get("self_host"):
            # Served from here: what counts is the saved file, which
            # local_problems checks below with everything else.
            probed.append((b, [], [], []))
            continue
        hops, extra, problems = probe(b["snippet"])
        if "checked" not in b and not problems:
            # Its first fetch: the hosts its redirects go through are
            # recorded now, as add would have.
            if extra:
                b["extra_hosts"] = extra
            b["checked"] = today
            stamped.append(b["name"])
        probed.append((b, hops, extra, problems))
    if stamped:
        save(files, badges)
        print("checked for the first time, and set no cookie: %s" % ", ".join(stamped))
    for p in problems_with(badges):
        print("! " + p)
        bad += 1
    if not bad:
        if stamped:
            for path in sync(files, badges):
                print("  wrote %s" % _shown(path, files))
        for path in drift(files, badges):
            print("! %s differs from badges.json: python3 scripts/badges.py sync"
                  % _shown(path, files))
            bad += 1
    allowed = set(img_src(csp_line(_read(files.headers))))
    for b, hops, extra, problems in probed:
        print(b["name"])
        for hop, status, _ in hops:
            ok = origin(hop) in allowed
            print("  image %s %s%s" % (status, hop, "" if ok else "  <- not in img-src"))
            bad += not ok
        for host in extra:
            if host not in b.get("extra_hosts", []):
                print("  ! redirects through %s, which badges.json does not record" % host)
                bad += 1
        for p in problems:
            print("  ! " + p)
            bad += 1
        if b.get("self_host"):
            print("  image served from /%s" % b["self_host"]["path"].split("site/", 1)[1])
        href, status = _link_status(b["snippet"])
        # A directory behind a bot wall answers 403 to this and 200 to a
        # browser, so only a listing that is plainly gone counts.
        gone = status in (404, 410)
        print("  link  %s %s%s" % (status, href, "  <- listing gone?" if gone else ""))
        bad += gone
    print("%s" % ("all in order" if not bad else "%d problem(s)" % bad))
    sys.exit(1 if bad else 0)


def _shown(path, files):
    try:
        return str(pathlib.Path(path).relative_to(files.data.parent.parent))
    except ValueError:
        return str(path)


def main(argv=None, files=None):
    files = files or Files()
    ap = argparse.ArgumentParser(
        prog="badges.py", description=__doc__.split("\n\n", 1)[0].replace("\n", " "))
    sub = ap.add_subparsers(dest="cmd")
    sub.required = True
    a = sub.add_parser("add", help="add a directory's snippet, from stdin or --file")
    a.add_argument("name", help="the directory's name, as the privacy page should show it")
    a.add_argument("--file", help="read the snippet from this file instead of stdin")
    a.add_argument("--end", action="store_true",
                   help="put it last rather than first")
    a.add_argument("--ground", choices=GROUNDS,
                   help="for a transparent badge drawn for one background")
    a.add_argument("--self-host", action="store_true",
                   help="save the image under site/badges/ and serve it from here, "
                        "for a directory whose image sets a cookie")
    a.add_argument("--offline", action="store_true",
                   help="do not fetch the image: save it to badges.json only, "
                        "until check fetches it and puts it on the page")
    a.set_defaults(func=cmd_add)
    r = sub.add_parser("remove", help="take a directory's badge down")
    r.add_argument("name")
    r.set_defaults(func=cmd_remove)
    sub.add_parser("list", help="what is listed, and what each link passes"
                   ).set_defaults(func=cmd_list)
    sub.add_parser("check", help="online: fetch every image and link again"
                   ).set_defaults(func=cmd_check)
    sub.add_parser("sync", help="rewrite the three files from badges.json"
                   ).set_defaults(func=cmd_sync)
    args = ap.parse_args(argv)
    args.func(args, files)


if __name__ == "__main__":
    main()
