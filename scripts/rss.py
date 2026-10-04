"""Write site/rss.xml from the releases on site/updates.html.

    python3 scripts/rss.py

The page is the one place a release is written down; the feed is made from
it. tests/test_site_claims.py rebuilds the feed and fails when the published
copy differs, so a release added to the page cannot ship without reaching
the people who follow it by RSS.

Everything here is deterministic: the feed's build date is the newest
release's, not the time the script ran, so running it twice changes nothing.
"""
import datetime
import email.utils
import html
import os
import re
from xml.sax.saxutils import escape

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PAGE = os.path.join(ROOT, "site", "updates.html")
OUT = os.path.join(ROOT, "site", "rss.xml")
ORIGIN = "https://ranwhat.com"

RELEASE = re.compile(r'<article class="release" id="([^"]+)">(.*?)</article>', re.S)


def _one(pattern, text, what, rid):
    found = re.findall(pattern, text, re.S)
    if len(found) != 1:
        raise ValueError("release %s: expected one %s, found %d" % (rid, what, len(found)))
    return found[0]


def _plain(fragment):
    return " ".join(html.unescape(re.sub(r"<[^>]+>", "", fragment)).split())


def releases(page_text):
    """[(id, version, datetime, title, list html)] in page order, newest first."""
    out = []
    for rid, body in RELEASE.findall(page_text):
        version = _one(r'<span class="rel-v">([^<]+)</span>', body, "version", rid)
        stamp = _one(r'<time datetime="([^"]+)">', body, "time", rid)
        title = _one(r"<h3>(.*?)</h3>", body, "h3", rid)
        items = _one(r"<ul>(.*?)</ul>", body, "list", rid)
        when = datetime.datetime.strptime(stamp, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=datetime.timezone.utc)
        out.append((rid, version, when, _plain(title), items))
    return out


def _absolute(fragment):
    """A feed reader shows the item away from the site, where /watch means
    nothing: make every root-relative link absolute, and the markup one line
    per item."""
    fragment = re.sub(r'href="/', 'href="%s/' % ORIGIN, fragment)
    return " ".join(fragment.split()).replace("> <li>", "><li>")


def build(page_text=None):
    if page_text is None:
        with open(PAGE, encoding="utf-8") as f:
            page_text = f.read()
    rels = releases(page_text)
    if not rels:
        raise ValueError("no releases on %s" % PAGE)
    lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom">',
        "<channel>",
        "  <title>ranwhat releases</title>",
        "  <link>%s/updates</link>" % ORIGIN,
        '  <atom:link href="%s/rss.xml" rel="self" type="application/rss+xml"/>' % ORIGIN,
        "  <description>What each release of ranwhat added and fixed: the coding"
        " agents it reads, the rules it gained, and what it got wrong before."
        "</description>",
        "  <language>en</language>",
        "  <lastBuildDate>%s</lastBuildDate>" % email.utils.format_datetime(rels[0][2]),
    ]
    for rid, version, when, title, items in rels:
        link = "%s/updates#%s" % (ORIGIN, rid)
        lines += [
            "  <item>",
            "    <title>%s</title>" % escape("ranwhat %s: %s" % (version, title)),
            "    <link>%s</link>" % link,
            '    <guid isPermaLink="true">%s</guid>' % link,
            "    <pubDate>%s</pubDate>" % email.utils.format_datetime(when),
            "    <description>%s</description>" % escape("<ul>%s</ul>" % _absolute(items)),
            "  </item>",
        ]
    lines += ["</channel>", "</rss>", ""]
    return "\n".join(lines)


if __name__ == "__main__":
    with open(OUT, "w", encoding="utf-8", newline="\n") as f:
        f.write(build())
    print("wrote", os.path.relpath(OUT, ROOT))
