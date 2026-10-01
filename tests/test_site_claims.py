"""The site states numbers that come from the catalogue. Those numbers drift
the moment a provider is added, and a marketing page that undercounts its own
product is the kind of thing nobody notices for months."""
import html
import html.parser
import importlib.util
import json
import os
import pathlib
import re
import shutil
import tempfile
import unittest
from unittest import mock

import ranwhat
from ranwhat import catalog, cli, feed

SITE = pathlib.Path(__file__).resolve().parent.parent / "site"
ORIGIN = "https://ranwhat.com"


def _example_report():
    spec = importlib.util.spec_from_file_location(
        "example_report", SITE.parent / "scripts" / "example_report.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def live():
    providers = {p: s for p, s in catalog.CATALOG.items() if s}
    return len(providers), sum(len(s) for s in providers.values())


class SiteMatchesCatalogue(unittest.TestCase):
    def test_about_page_counts_are_current(self):
        n_prov, n_scopes = live()
        text = (SITE / "about.html").read_text(encoding="utf-8")
        self.assertIn("%d providers and %d permissions" % (n_prov, n_scopes), text,
                      "about.html coverage numbers are stale")

    def test_about_page_lists_every_provider(self):
        text = (SITE / "about.html").read_text(encoding="utf-8")
        display = {
            "google": "Google Workspace", "github": "GitHub", "gitlab": "GitLab",
            "microsoft": "Microsoft 365", "slack": "Slack", "discord": "Discord",
            "stripe": "Stripe", "shopify": "Shopify", "hubspot": "HubSpot",
            "atlassian": "Atlassian", "sentry": "Sentry", "aws": "AWS",
        }
        for provider, scopes in catalog.CATALOG.items():
            if not scopes:
                continue
            self.assertIn(display[provider], text,
                          "%s is catalogued but missing from the about page" % provider)
            self.assertIn(
                "<strong>%s</strong></td><td class=\"mono\">%d</td>"
                % (display[provider], len(scopes)), text,
                "%s scope count on the about page is stale" % provider)

    def test_pricing_does_not_understate_provider_count(self):
        n_prov, _ = live()
        text = (SITE / "pricing.html").read_text(encoding="utf-8")
        self.assertNotIn("all five providers", text)
        self.assertIn("twelve providers" if n_prov == 12 else str(n_prov), text)


class NoEmDashes(unittest.TestCase):
    """Removed deliberately across the site; easy to reintroduce by hand."""

    def test_no_page_contains_an_em_dash(self):
        files = (list(SITE.rglob("*.html")) + list(SITE.glob("*.txt"))
                 + list(SITE.glob("*.xml")) + [SITE / "_headers"]
                 + [p for p in SITE.glob(".well-known/*") if p.is_file()])
        for page in sorted(files):
            self.assertNotIn("\u2014", page.read_text(encoding="utf-8"),
                             "%s has an em dash" % page.relative_to(SITE))



class ExampleReportIsCurrent(unittest.TestCase):
    """The example report shows scores. A catalogue change that moves them
    would otherwise leave the site showing numbers the tool no longer
    gives, which is the kind of drift nobody notices for months."""

    def test_published_report_matches_what_the_tool_writes(self):
        self.assertEqual((SITE / "example-report.html").read_text(encoding="utf-8"),
                         _example_report().build(),
                         "site/example-report.html is stale: "
                         "run python3 scripts/example_report.py")


class ExampleReportIgnoresThisMachinesFeed(unittest.TestCase):
    """build() scores the demo profile through the catalogue, which reads
    any subscribed feed cached under RANWHAT_HOME. On a machine with one
    that rates a demo scope, the test above failed though the page was
    right, and the script would have baked that machine's ratings in."""

    def setUp(self):
        self.home = tempfile.mkdtemp(prefix="feed-home-")
        self.addCleanup(shutil.rmtree, self.home, True)
        patch = mock.patch.dict(os.environ, {"RANWHAT_HOME": self.home})
        patch.start()
        self.addCleanup(patch.stop)
        cat = {"slack": {"chat:write": {
            "label": "Pay anyone", "authority": "destructive",
            "reversible": False, "blast": "monetary", "why": "a test feed"}}}
        feed.save({"schema": feed.SCHEMA, "version": "t", "catalogue": cat,
                   "digest": feed.digest(cat)})
        catalog.reset_feed_cache()
        self.addCleanup(catalog.reset_feed_cache)

    def test_a_cached_feed_does_not_reach_the_page(self):
        self.assertEqual(catalog.lookup("slack", "chat:write")["label"],
                         "Pay anyone", "the test feed is not in use")
        catalog.reset_feed_cache()
        self.assertEqual((SITE / "example-report.html").read_text(encoding="utf-8"),
                         _example_report().build())

    def test_the_feed_is_back_afterwards(self):
        _example_report().build()
        self.assertEqual(os.environ["RANWHAT_HOME"], self.home)
        self.assertEqual(catalog.lookup("slack", "chat:write")["label"],
                         "Pay anyone")


class AdMeasurementNeedsConsent(unittest.TestCase):
    """The X pixel sets cookies and reports the visit, so it may only load
    after a yes. These pin the parts of that which a later edit could quietly
    undo: a page pasting X's base code straight in, a page missing the way to
    withdraw, or the server sending X more than the privacy page says."""

    PAGES = sorted(SITE.rglob("*.html"))
    X_HOSTS = ("ads-twitter.com", "twq(", "uwt.js", "analytics.twitter.com")

    def test_no_page_loads_x_directly(self):
        for page in self.PAGES:
            text = page.read_text(encoding="utf-8")
            for host in self.X_HOSTS:
                self.assertNotIn(host, text.replace("static.ads-twitter.com</span>", ""),
                                 "%s references %s outside consent.js" % (page.name, host))

    def test_every_page_offers_consent_and_a_way_back(self):
        # Pages with the site footer. The example report is a standalone
        # document the tool writes, and loads nothing from X at all.
        for page in self.PAGES:
            text = page.read_text(encoding="utf-8")
            if 'class="fbase"' not in text:
                continue
            self.assertIn('src="/consent.js', text, page.name)
            self.assertIn("data-consent-open", text, page.name)

    def test_pixel_loads_only_from_the_consent_path(self):
        js = (SITE / "consent.js").read_text(encoding="utf-8")
        self.assertEqual(js.count("https://static.ads-twitter.com/uwt.js"), 1)
        calls = re.findall(r"(?<![\w.])load\(\);", js)
        self.assertEqual(len(calls), 2, "load() should be reachable only from "
                         "a stored yes and the Allow button")
        self.assertIn('now === "granted") load();', js)
        self.assertIn('answer === "granted") { load();', js)
        self.assertIn("globalPrivacyControl", js)

    def test_csp_allows_the_pixel_and_nothing_broader(self):
        headers = (SITE / "_headers").read_text(encoding="utf-8")
        csp = next(l for l in headers.splitlines()
                   if "Content-Security-Policy" in l)
        self.assertIn("https://static.ads-twitter.com", csp)
        # uwt.js reports by fetch as well as by image, to both hosts.
        connect = csp.split("connect-src", 1)[1].split(";", 1)[0]
        for host in ("https://analytics.twitter.com", "https://t.co"):
            self.assertIn(host, connect)
        self.assertNotIn("*", csp.replace("/*", ""), "no wildcard hosts")

    def test_privacy_page_describes_it(self):
        text = (SITE / "privacy.html").read_text(encoding="utf-8")
        self.assertIn('id="ads"', text)
        self.assertIn("Global Privacy Control", text)
        for stale in ("GitHub Pages", "no backend", "no tracking pixels"):
            self.assertNotIn(stale, text)

    def test_browser_and_server_report_the_same_event(self):
        # X deduplicates a lead by event and conversion ID, so the pixel and
        # the Conversions API must name the same event.
        js = (SITE / "consent.js").read_text(encoding="utf-8")
        toml = (SITE.parent / "worker" / "wrangler.toml").read_text(encoding="utf-8")
        browser = re.search(r'lead: "([^"]*)"', js).group(1)
        server = re.search(r'^X_EVENT_LEAD = "([^"]*)"', toml, re.M).group(1)
        self.assertTrue(browser.startswith("tw-rfz6t-"), browser)
        self.assertEqual(browser, server)

    def test_server_never_sends_x_the_message_or_address(self):
        src = (SITE.parent / "worker" / "src" / "index.js").read_text(encoding="utf-8")
        body = src[src.index("async function reportLead"):src.index("async function handleContact")]
        self.assertIn("form.measure !== true", body)
        for field in ("form.message", "form.email", "replyTo", "hashed_email"):
            self.assertNotIn(field, body)


# ---------------------------------------------------------------------------
# What a search engine, an answer engine or a link preview reads first. Each
# of these was wrong on a live page at least once: pages with no h1, a title
# shared by the tool and the page about it, a description that said the tool
# "transmits nothing", an FAQ whose markup had drifted from its text.
# ---------------------------------------------------------------------------

def read(page):
    return page.read_text(encoding="utf-8")


def all_pages():
    return sorted(SITE.rglob("*.html"))


def indexable(page):
    return 'name="robots" content="noindex"' not in read(page)


def url_for(page):
    """Where Pages serves a file: extensionless, index.html at its folder."""
    rel = page.relative_to(SITE).as_posix()
    if rel == "index.html":
        return ORIGIN + "/"
    if rel.endswith("/index.html"):
        return ORIGIN + "/" + rel[:-len("index.html")]
    return ORIGIN + "/" + rel[:-len(".html")]


def meta(text, attr, name):
    found = re.findall(r'<meta %s="%s" content="([^"]*)">' % (attr, re.escape(name)),
                       text)
    return [html.unescape(v) for v in found]


def title(text):
    found = re.findall(r"<title>([^<]*)</title>", text)
    return [html.unescape(v) for v in found]


def plain(fragment):
    return " ".join(html.unescape(re.sub(r"<[^>]+>", "", fragment)).split())


def json_ld(text):
    return [json.loads(block) for block in re.findall(
        r'<script type="application/ld\+json">(.*?)</script>', text, re.S)]


def faq_blocks(text):
    """The visible questions and answers, as a reader sees them."""
    return [(plain(q), plain(a)) for q, a in re.findall(
        r'<div class="faq"><h3>(.*?)</h3><p>(.*?)</p></div>', text, re.S)]


def faq_jsonld():
    """The FAQPage markup faq.html should carry, from its visible text. To
    regenerate after editing an answer: python3 -c "import sys;
    sys.path.insert(0, 'tests'); import test_site_claims as t;
    print(t.faq_jsonld())" and paste the result over the old block."""
    pairs = faq_blocks(read(SITE / "faq.html"))
    ld = {"@context": "https://schema.org", "@graph": [
        {"@type": "FAQPage", "mainEntity": [
            {"@type": "Question", "name": q,
             "acceptedAnswer": {"@type": "Answer", "text": a}}
            for q, a in pairs]},
        {"@type": "BreadcrumbList", "itemListElement": [
            {"@type": "ListItem", "position": 1, "name": "ranwhat",
             "item": ORIGIN + "/"},
            {"@type": "ListItem", "position": 2, "name": "FAQ",
             "item": ORIGIN + "/faq"}]}]}
    return ('<script type="application/ld+json">%s</script>'
            % json.dumps(ld, ensure_ascii=False, separators=(",", ":")))


def sitemap_locs():
    return re.findall(r"<loc>([^<]+)</loc>", read(SITE / "sitemap.xml"))


class SiteStructure(unittest.TestCase):

    def test_every_page_has_exactly_one_h1(self):
        for page in all_pages():
            self.assertEqual(len(re.findall(r"<h1[\s>]", read(page))), 1,
                             page.relative_to(SITE))

    def test_titles_are_unique_and_fit_a_result(self):
        seen = {}
        for page in all_pages():
            found = title(read(page))
            self.assertEqual(len(found), 1, page.name)
            self.assertLess(len(found[0]), 65, page.name)
            self.assertNotIn(found[0], seen,
                             "%s and %s share a title" % (page.name, seen.get(found[0])))
            seen[found[0]] = page.name

    def test_descriptions_fit_a_result_and_agree_everywhere(self):
        for page in filter(indexable, all_pages()):
            text = read(page)
            desc = meta(text, "name", "description")
            self.assertEqual(len(desc), 1, page.name)
            self.assertTrue(110 <= len(desc[0]) <= 165,
                            "%s description is %d chars" % (page.name, len(desc[0])))
            # Search shows the meta tags; X, Slack and LinkedIn show og and
            # twitter. One page, one summary.
            self.assertEqual(meta(text, "property", "og:description"), desc, page.name)
            self.assertEqual(meta(text, "name", "twitter:description"), desc, page.name)
            self.assertEqual(meta(text, "property", "og:title"), title(text), page.name)
            self.assertEqual(meta(text, "name", "twitter:title"), title(text), page.name)
            self.assertEqual(meta(text, "name", "twitter:site"), ["@ranwhatcom"],
                             page.name)
            self.assertNotIn('name="keywords"', text, page.name)

    def test_canonical_is_the_page_itself_without_an_extension(self):
        for page in filter(indexable, all_pages()):
            text = read(page)
            found = re.findall(r'<link rel="canonical" href="([^"]+)">', text)
            self.assertEqual(found, [url_for(page)], page.name)
            self.assertEqual(meta(text, "property", "og:url"), [url_for(page)],
                             page.name)

    def test_a_page_that_is_not_indexed_has_no_canonical(self):
        for page in all_pages():
            if not indexable(page):
                self.assertNotIn('rel="canonical"', read(page), page.name)

    def test_structured_data_parses_and_claims_nothing_invented(self):
        for page in all_pages():
            text = read(page)
            for block in json_ld(text):
                self.assertEqual(block.get("@context"), "https://schema.org",
                                 page.name)
            for never in ("aggregateRating", "AggregateRating", '"review"',
                          '"Review"'):
                self.assertNotIn(never, text, page.name)

    def test_every_interior_page_carries_its_breadcrumb(self):
        for page in filter(indexable, all_pages()):
            if page.name == "index.html":
                continue
            crumbs = [b for block in json_ld(read(page))
                      for b in block.get("@graph", [block])
                      if b.get("@type") == "BreadcrumbList"]
            self.assertEqual(len(crumbs), 1, page.name)
            items = crumbs[0]["itemListElement"]
            self.assertEqual(items[0]["item"], ORIGIN + "/", page.name)
            self.assertEqual(items[-1]["item"], url_for(page), page.name)

    def test_faq_markup_matches_the_visible_answers(self):
        text = read(SITE / "faq.html")
        pairs = faq_blocks(text)
        self.assertGreaterEqual(len(pairs), 9)
        faq = [b for block in json_ld(text) for b in block.get("@graph", [block])
               if b.get("@type") == "FAQPage"]
        self.assertEqual(len(faq), 1)
        marked = [(q["name"], q["acceptedAnswer"]["text"])
                  for q in faq[0]["mainEntity"]]
        self.assertEqual(marked, pairs, "faq.html's FAQPage markup has drifted "
                         "from its text; see faq_jsonld() in this file")

    def test_faq_markup_is_only_on_the_faq_page(self):
        for page in all_pages():
            if page.name != "faq.html":
                self.assertNotIn('"FAQPage"', read(page), page.name)

    def test_home_questions_are_copied_word_for_word_from_the_faq(self):
        faq = dict(faq_blocks(read(SITE / "faq.html")))
        home = faq_blocks(read(SITE / "index.html"))
        self.assertTrue(home)
        for q, a in home:
            self.assertEqual(faq.get(q), a, q)

    def test_sitemap_lists_every_indexable_page_and_nothing_else(self):
        locs = sitemap_locs()
        self.assertEqual(len(locs), len(set(locs)), "duplicate <loc>")
        expected = {url_for(p) for p in all_pages() if indexable(p)}
        self.assertEqual(set(locs), expected)
        for loc in locs:
            self.assertNotIn(".html", loc)

    def test_robots_allows_the_sitemap_and_names_it(self):
        robots = read(SITE / "robots.txt")
        self.assertIn("Sitemap: %s/sitemap.xml" % ORIGIN, robots.splitlines())
        self.assertIn("User-agent: *", robots.splitlines())
        blocked = [l.split(":", 1)[1].strip() for l in robots.splitlines()
                   if l.lower().startswith("disallow:") and l.split(":", 1)[1].strip()]
        for loc in sitemap_locs():
            path = loc[len(ORIGIN):]
            for prefix in blocked:
                self.assertFalse(path.startswith(prefix), (loc, prefix))

    def test_header_and_footer_are_the_same_on_every_page(self):
        def part(text, tag):
            found = re.findall(r"<%s>.*?</%s>" % (tag, tag), text, re.S)
            self.assertEqual(len(found), 1, tag)
            return found[0]
        ref = read(SITE / "watch.html")
        header = part(ref, "header").replace(' aria-current="page"', "")
        footer = part(ref, "footer")
        for page in all_pages():
            # The example report is the document the CLI writes, published
            # as is (scripts/example_report.py), not a page in the site's
            # chrome. ExampleReportIsCurrent pins it instead.
            if page.name == "example-report.html":
                continue
            text = read(page)
            self.assertEqual(part(text, "header").replace(' aria-current="page"', ""),
                             header, page.name)
            self.assertEqual(part(text, "footer"), footer, page.name)

    def test_no_page_repeats_a_claim_the_tool_does_not_keep(self):
        # live, --pull-usage and update all go online; the suite outgrew 102.
        stale = ("transmits nothing", "never sends a byte", "102 tests")
        files = all_pages() + [SITE / "llms.txt", SITE.parent / "README.md"]
        for page in files:
            text = read(page).lower()
            for claim in stale:
                self.assertNotIn(claim, text, page.name)

    def test_llms_txt_names_every_command_and_what_goes_online(self):
        text = read(SITE / "llms.txt")
        self.assertTrue(text.startswith("# ranwhat\n"))
        for name, _ in cli.COMMANDS:
            self.assertRegex(text, r"`ranwhat %s[` ]" % re.escape(name), name)
        self.assertIn("ask only the provider that issued each token", text)
        self.assertIn("ask only the provider that issued each token", cli.NETWORK)

    def test_scan_page_counts_are_current(self):
        n_prov, n_scopes = live()
        words = {12: "twelve"}
        self.assertIn("%d scopes across %s providers"
                      % (n_scopes, words.get(n_prov, n_prov)),
                      read(SITE / "scan.html"))

    def test_install_page_names_the_current_version(self):
        self.assertIn("Current version %s." % ranwhat.__version__,
                      read(SITE / "install.html"))

    def test_install_page_quotes_the_cli_on_the_network(self):
        self.assertIn(" ".join(cli.NETWORK.split()),
                      plain(read(SITE / "install.html")))


def _csp():
    """The site's Content-Security-Policy as {directive: [sources]}."""
    headers = (SITE / "_headers").read_text(encoding="utf-8")
    lines = [l for l in headers.splitlines() if "Content-Security-Policy:" in l]
    assert len(lines) == 1, "one Content-Security-Policy line in _headers"
    policy = {}
    for directive in lines[0].split(":", 1)[1].split(";"):
        words = directive.split()
        if words:
            policy[words[0].lower()] = words[1:]
    return policy


class _InlineScript(html.parser.HTMLParser):
    """Collects what a script-src without 'unsafe-inline' refuses to run: a
    <script> with no src, an on*= handler, a javascript: URL. A JSON-LD
    block is data, which script-src does not govern."""

    def __init__(self):
        super().__init__()
        self.found = []

    def handle_starttag(self, tag, attrs):
        attrs = [(k, v or "") for k, v in attrs]
        if tag == "script":
            given = dict(attrs)
            if "src" not in given and \
                    given.get("type", "").strip().lower() != "application/ld+json":
                self.found.append("line %d: inline <script>" % self.getpos()[0])
        for name, value in attrs:
            if re.fullmatch(r"on[a-z]+", name):
                self.found.append("line %d: %s=" % (self.getpos()[0], name))
            if re.sub(r"\s", "", value).lower().startswith("javascript:"):
                self.found.append("line %d: %s=javascript:" % (self.getpos()[0], name))


class InlineScriptStaysBlocked(unittest.TestCase):
    """script-src without 'unsafe-inline' is what leaves an injected <script>
    or onerror= inert. main's policy had it, and a merge that brings that
    line back, or a page that pastes X's inline base code, would otherwise
    pass every other test here."""

    def test_script_src_has_no_unsafe_inline(self):
        policy = _csp()
        self.assertIn("script-src", policy, "scripts would fall back to default-src")
        for name, sources in policy.items():
            if name.startswith("script-src") or name == "default-src":
                with self.subTest(directive=name):
                    self.assertNotIn("'unsafe-inline'", sources)
                    self.assertNotIn("'unsafe-hashes'", sources)

    def test_no_page_needs_inline_script(self):
        pages = sorted(SITE.glob("*.html"))
        self.assertTrue(pages)
        for page in pages:
            with self.subTest(page=page.name):
                parser = _InlineScript()
                parser.feed(page.read_text(encoding="utf-8"))
                parser.close()
                self.assertEqual(parser.found, [])

    def test_the_parser_sees_what_it_is_looking_for(self):
        """Or the page test would pass for the wrong reason."""
        parser = _InlineScript()
        parser.feed('<script type="application/ld+json">{}</script>'
                    '<script src="/copy.js" defer></script>'
                    '<SCRIPT>alert(1)</SCRIPT>'
                    '<img src=x ONERROR="alert(1)">'
                    '<a href=" JavaScript:alert(1)">x</a>')
        parser.close()
        self.assertEqual(len(parser.found), 3, parser.found)


if __name__ == "__main__":
    unittest.main()
