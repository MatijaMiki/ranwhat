"""The site states numbers that come from the catalogue. Those numbers drift
the moment a provider is added, and a marketing page that undercounts its own
product is the kind of thing nobody notices for months."""
import html.parser
import importlib.util
import os
import pathlib
import re
import shutil
import tempfile
import unittest
from unittest import mock

from ranwhat import catalog, feed

SITE = pathlib.Path(__file__).resolve().parent.parent / "site"


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
        for page in sorted(SITE.glob("*.html")):
            self.assertNotIn("—", page.read_text(encoding="utf-8"),
                             "%s has an em dash" % page.name)



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
    """Google Analytics and the X pixel set cookies and report the visit, so
    each may only load after its own yes. These pin the parts of that which a
    later edit could quietly undo: a page pasting a vendor snippet straight
    in, one yes switching on both tools, a page missing the way to withdraw,
    or the server sending X more than the privacy page says."""

    PAGES = sorted(SITE.glob("*.html"))
    # Loading code, not names: the privacy page may say which hosts are used.
    LOADERS = ("twq(", "uwt.js", "gtag(", "gtag/js", "dataLayer")
    SCRIPT_SRC = re.compile(
        r'<script[^>]+src="https://[^"]*(ads-twitter\.com|googletagmanager\.com|google-analytics\.com)')

    def test_no_page_loads_a_vendor_directly(self):
        for page in self.PAGES:
            text = page.read_text(encoding="utf-8")
            self.assertIsNone(self.SCRIPT_SRC.search(text), page.name)
            for marker in self.LOADERS:
                self.assertNotIn(marker, text, "%s has %s outside consent.js" % (page.name, marker))

    def test_every_page_offers_consent_and_a_way_back(self):
        # Pages with the site footer. The example report is a standalone
        # document the tool writes, and loads nothing from X or Google.
        for page in self.PAGES:
            text = page.read_text(encoding="utf-8")
            if 'class="fbase"' not in text:
                continue
            self.assertIn('src="/consent.js', text, page.name)
            self.assertIn("data-consent-open", text, page.name)

    def test_each_tool_loads_only_after_its_own_yes(self):
        js = (SITE / "consent.js").read_text(encoding="utf-8")
        self.assertEqual(js.count("https://static.ads-twitter.com/uwt.js"), 1)
        self.assertEqual(js.count("https://www.googletagmanager.com/gtag/js"), 1)
        # Statistics loads from one place, gated on its own answer.
        self.assertEqual(re.findall(r"(?<![\w.])loadStats\(\);", js), ["loadStats();"])
        self.assertIn("if (c.stats) loadStats();", js)
        # Ads load from the same gate, or from an earlier yes to the pixel
        # alone, which predates the statistics question.
        self.assertEqual(len(re.findall(r"(?<![\w.])loadAds\(\);", js)), 2)
        self.assertIn("if (c.ads) loadAds();", js)
        self.assertIn("if (earlierAds()) loadAds();", js)
        # Both boxes start unticked for a new visitor, and GPC answers no.
        self.assertIn("choice() || { stats: false, ads: earlierAds() }", js)
        self.assertIn("globalPrivacyControl", js)
        # Statistics is for counting visits, not advertising.
        self.assertIn("allow_google_signals: false", js)
        self.assertIn("allow_ad_personalization_signals: false", js)

    def test_csp_allows_the_tools_and_nothing_broader(self):
        headers = (SITE / "_headers").read_text(encoding="utf-8")
        csp = next(l for l in headers.splitlines()
                   if "Content-Security-Policy" in l)
        self.assertIn("https://static.ads-twitter.com", csp)
        # uwt.js reports by fetch as well as by image, to both hosts.
        connect = csp.split("connect-src", 1)[1].split(";", 1)[0]
        for host in ("https://analytics.twitter.com", "https://t.co",
                     "https://*.google-analytics.com"):
            self.assertIn(host, connect)
        # The only wildcards are Google's documented GA4 hosts.
        allowed = {"https://*.googletagmanager.com", "https://*.google-analytics.com",
                   "https://*.analytics.google.com"}
        wild = {tok for tok in csp.replace(";", " ").split() if "*" in tok}
        self.assertEqual(wild - allowed, set(), "unexpected wildcard hosts")

    def test_privacy_page_describes_it(self):
        text = (SITE / "privacy.html").read_text(encoding="utf-8")
        for anchor in ('id="ads"', 'id="stats"'):
            self.assertIn(anchor, text)
        for fact in ("Global Privacy Control", "Google Analytics", "_ga_MTR111ZTTE"):
            self.assertIn(fact, text)
        for stale in ("GitHub Pages", "no backend", "no tracking pixels", "no analytics"):
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
