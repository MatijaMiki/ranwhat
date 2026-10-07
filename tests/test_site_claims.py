"""The site states numbers that come from the catalogue. Those numbers drift
the moment a provider is added, and a marketing page that undercounts its own
product is the kind of thing nobody notices for months."""
import contextlib
import difflib
import functools
import html
import html.parser
import importlib.util
import io
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import ranwhat
from ranwhat import catalog, cli, feed, hints

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


class UpdateSampleIsWhatUpdatePrints(unittest.TestCase):
    """commands.html shows `update --status` with no feed, as a terminal
    shows it: the line naming the bundled release, then the dim hint. The
    line carries the version, so a release that does not change the page
    fails here rather than showing last release's number."""

    class _Tty(io.StringIO):
        def isatty(self):
            return True

    def test_the_sample_matches(self):
        home = tempfile.mkdtemp(prefix="update-home-")
        self.addCleanup(shutil.rmtree, home, True)
        env = {k: v for k, v in os.environ.items()
               if k not in ("RANWHAT_TOKEN", "RANWHAT_NO_HINTS")}
        env.update(RANWHAT_HOME=home, NO_COLOR="1")
        out, err = io.StringIO(), self._Tty()
        with mock.patch.dict(os.environ, env, clear=True), \
             contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            hints.reset()
            catalog.reset_feed_cache()
            try:
                self.assertEqual(cli.main(["update", "--status"]), 0)
            finally:
                hints.reset()
                catalog.reset_feed_cache()
        sample = re.search(r'aria-label="What ranwhat update --status prints">'
                           r'.*?<pre>(.*?)</pre>', read(SITE / "commands.html"), re.S)
        shown = plain(sample.group(1)).replace("$ uvx ranwhat update --status", "", 1)
        self.assertIn("No feed cached", out.getvalue())
        self.assertTrue(err.getvalue(), "the hint is part of the sample")
        self.assertEqual(shown.strip(), " ".join((out.getvalue() + err.getvalue()).split()))


class AdMeasurementNeedsConsent(unittest.TestCase):
    """Google Analytics and the X pixel set cookies and report the visit, so
    each may only load after its own yes. These pin the parts of that which a
    later edit could quietly undo: a page pasting a vendor snippet straight
    in, one yes switching on both tools, a page missing the way to withdraw,
    or the server sending X more than the privacy page says."""

    PAGES = sorted(SITE.rglob("*.html"))
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
        # Withdrawing stops gtag at once and sweeps leftovers on later loads.
        self.assertIn('window["ga-disable-" + GA_ID] = true;', js)
        self.assertIn("if (now && !now.stats) clearCookies(/^_ga(_|$)/);", js)

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


def faq_page(pairs):
    """An FAQPage node for these visible questions and answers."""
    return {"@type": "FAQPage", "mainEntity": [
        {"@type": "Question", "name": q,
         "acceptedAnswer": {"@type": "Answer", "text": a}}
        for q, a in pairs]}


def faq_jsonld():
    """The FAQPage markup faq.html should carry, from its visible text. To
    regenerate after editing an answer: python3 -c "import sys;
    sys.path.insert(0, 'tests'); import test_site_claims as t;
    print(t.faq_jsonld())" and paste the result over the old block."""
    pairs = faq_blocks(read(SITE / "faq.html"))
    ld = {"@context": "https://schema.org", "@graph": [
        faq_page(pairs),
        {"@type": "BreadcrumbList", "itemListElement": [
            {"@type": "ListItem", "position": 1, "name": "ranwhat",
             "item": ORIGIN + "/"},
            {"@type": "ListItem", "position": 2, "name": "FAQ",
             "item": ORIGIN + "/faq"}]}]}
    return ('<script type="application/ld+json">%s</script>'
            % json.dumps(ld, ensure_ascii=False, separators=(",", ":")))


def home_faq_jsonld():
    """The FAQPage markup index.html carries for its own questions, a block
    of its own after the site's @graph. Regenerate it the same way as
    faq_jsonld(), with print(t.home_faq_jsonld())."""
    ld = {"@context": "https://schema.org"}
    ld.update(faq_page(faq_blocks(read(SITE / "index.html"))))
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

    # The pages that carry questions of their own, each with an FAQPage
    # block made from its visible text, and how many each holds at least.
    FAQ_PAGES = {"faq.html": (9, faq_jsonld), "index.html": (6, home_faq_jsonld)}

    def test_faq_markup_matches_the_visible_answers(self):
        for name, (least, generate) in self.FAQ_PAGES.items():
            text = read(SITE / name)
            pairs = faq_blocks(text)
            self.assertGreaterEqual(len(pairs), least, name)
            faq = [b for block in json_ld(text) for b in block.get("@graph", [block])
                   if b.get("@type") == "FAQPage"]
            self.assertEqual(len(faq), 1, name)
            marked = [(q["name"], q["acceptedAnswer"]["text"])
                      for q in faq[0]["mainEntity"]]
            self.assertEqual(marked, pairs, "%s's FAQPage markup has drifted "
                             "from its text; see %s() in this file"
                             % (name, generate.__name__))
            self.assertIn(generate(), text, name)

    def test_faq_markup_is_only_on_pages_with_questions_of_their_own(self):
        for page in all_pages():
            if page.relative_to(SITE).as_posix() not in self.FAQ_PAGES:
                self.assertNotIn('"FAQPage"', read(page), page.name)

    def test_no_question_is_marked_up_on_two_pages(self):
        # Google's FAQ guidance was to mark up one instance of a question
        # and answer that repeats across a site. Both pages mark theirs up,
        # so the home page asks its own questions and gives its own answers,
        # and not /faq's reworded either: the home page's reworded "Which
        # agents does it read?" and "Does it send anything anywhere?" shared
        # about half their words with /faq's, and none kept shares a quarter.
        faq = faq_blocks(read(SITE / "faq.html"))
        home = faq_blocks(read(SITE / "index.html"))
        self.assertTrue(home)
        asked = {q.lower() for q, _ in faq}
        answered = {a for _, a in faq}

        def words(answer):
            return re.findall(r"[a-z0-9.~/-]+", plain(answer).lower())
        for q, a in home:
            self.assertNotIn(q.lower(), asked, q)
            self.assertNotIn(a, answered, q)
            for fq, fa in faq:
                shared = difflib.SequenceMatcher(None, words(a), words(fa)).ratio()
                self.assertLess(shared, 0.4, "%r reads like /faq's %r" % (q, fq))

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

    def test_every_page_offers_sign_in_in_its_header_and_footer(self):
        # A plain link to the account, which lives on a host of its own
        # (worker/src/accounts.js's ACCOUNT_HOST): ranwhat.com sets no
        # cookie for it and loads nothing from it.
        host = re.search(r'^export const ACCOUNT_HOST = "([^"]+)";',
                         read(SITE.parent / "worker" / "src" / "accounts.js"), re.M).group(1)
        link = '<a href="https://%s/">Sign in</a>' % host
        for page in all_pages():
            if page.name == "example-report.html":
                continue
            text = read(page)
            header = re.findall(r"<header>.*?</header>", text, re.S)
            footer = re.findall(r"<footer>.*?</footer>", text, re.S)
            self.assertEqual((len(header), len(footer)), (1, 1), page.name)
            self.assertEqual(header[0].count(link), 1, page.name)
            self.assertEqual(footer[0].count(link), 1, page.name)
            # In the menu with the other pages, so a phone folds it in too.
            nav = re.search(r'<nav id="site-nav">(.*?)</nav>', header[0], re.S)
            self.assertIn(link, nav.group(1), page.name)

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
        for name in ("scan.html", "index.html"):
            self.assertIn("%d scopes across %s providers"
                          % (n_scopes, words.get(n_prov, n_prov)),
                          read(SITE / name), name)

    def test_home_page_counts_the_watch_rules(self):
        from ranwhat import watch
        self.assertIn("runs %s rules over it" % WORDS[len(watch.RULES)],
                      plain(read(SITE / "index.html")))

    def test_install_page_names_the_current_version(self):
        self.assertIn("Current version %s." % ranwhat.__version__,
                      read(SITE / "install.html"))

    def test_install_page_quotes_the_cli_on_the_network(self):
        self.assertIn(" ".join(cli.NETWORK.split()),
                      plain(read(SITE / "install.html")))

    def test_a_stacked_table_labels_every_value_with_its_column(self):
        # Below 620px a .stack table puts each value under its column's name,
        # which the cell carries in data-label. The first cell heads the
        # record and goes unlabelled; a missing or stale label elsewhere
        # leaves a value on a phone under no heading, or the wrong one.
        stacked = 0
        for page in all_pages():
            for table in re.findall(r'<table class="stack">(.*?)</table>',
                                    read(page), re.S):
                stacked += 1
                head, body = table.split("</thead>", 1)
                columns = [plain(th) for th in re.findall(r"<th>(.*?)</th>", head, re.S)]
                for row in re.findall(r"<tr>(.*?)</tr>", body, re.S):
                    labels = [re.search(r'data-label="([^"]*)"', attrs)
                              for attrs in re.findall(r"<td\b([^>]*)>", row)]
                    labels = [html.unescape(m.group(1)) if m else None for m in labels]
                    self.assertEqual(labels, [None] + columns[1:],
                                     "%s: %s" % (page.name, plain(row)[:60]))
        self.assertGreaterEqual(stacked, 10)


def _csp():
    """The site's Content-Security-Policy as {directive: [sources]}."""
    headers = (SITE / "_headers").read_text(encoding="utf-8")
    # The site-wide policy is the one under /*; a path may set its own
    # (/badges/* keeps self-hosted badge images inert), which no page uses.
    lines, block = [], None
    for l in headers.splitlines():
        if l and not l[0].isspace():
            block = l.strip()
        elif block == "/*" and "Content-Security-Policy:" in l:
            lines.append(l)
    assert len(lines) == 1, "one Content-Security-Policy line under /* in _headers"
    policy = {}
    for directive in lines[0].split(":", 1)[1].split(";"):
        words = directive.split()
        if words:
            policy[words[0].lower()] = words[1:]
    return policy


class CheckoutCanLeaveThePricingPage(unittest.TestCase):
    """The pricing page's Plus form posts to the Worker's /api/checkout,
    which answers 303 to Stripe Checkout or, with accounts on, to the
    account's upgrade. Browsers hold the redirect after a form to the
    page's form-action as well as the post, so an origin missing there
    leaves the button doing nothing, while every Worker test, which sees
    only the 303, still passes."""

    def test_form_action_allows_every_place_the_checkout_sends_the_browser(self):
        src = SITE.parent / "worker" / "src"
        host = re.search(r'^export const ACCOUNT_HOST = "([^"]+)";',
                         (src / "accounts.js").read_text(encoding="utf-8"), re.M).group(1)
        stripe_checkout = re.search(r'^export const CHECKOUT_ORIGIN = "([^"]+)";',
                                    (src / "billing.js").read_text(encoding="utf-8"), re.M).group(1)
        stripe = (src / "stripe.js").read_text(encoding="utf-8")
        body = stripe[stripe.index("export async function checkout("):]
        body = body[:body.index("\n}\n")]
        # The account's upgrade, and the Checkout Session's own address on
        # Stripe. A new redirect there has to be added here and to _headers.
        self.assertIn("const UPGRADE = `${ACCOUNT_ORIGIN}/upgrade`;", stripe)
        self.assertEqual(re.findall(r"Response\.redirect\(([^,]+), 303\)", body),
                         ["UPGRADE", "session.url"])
        form_action = _csp()["form-action"]
        for origin in ("https://" + host, stripe_checkout):
            with self.subTest(origin=origin):
                self.assertIn(origin, form_action)
        # The form is on the pricing page, under the site-wide policy.
        self.assertIn('action="/api/checkout"', read(SITE / "pricing.html"))


class HeaderRulesAreNotRepeated(unittest.TestCase):
    """Pages joins a header applied twice to one path with a comma. A merge
    once left /contact.js with two Cache-Control rules, a year immutable and
    an hour, which a cache may read either way."""

    def test_each_path_has_one_block(self):
        headers = (SITE / "_headers").read_text(encoding="utf-8")
        paths = [l.strip() for l in headers.splitlines()
                 if l.strip() and not l[0].isspace() and not l.startswith("#")]
        self.assertIn("/contact.js", paths)
        self.assertEqual(sorted(p for p in set(paths) if paths.count(p) > 1), [])


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
        # rglob: the guides live in site/guides/, under the same policy.
        pages = all_pages()
        self.assertTrue(any(p.parent != SITE for p in pages))
        for page in pages:
            with self.subTest(page=page.relative_to(SITE).as_posix()):
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


# ---------------------------------------------------------------------------
# Links. The guides live one directory down, in site/guides/, where a
# relative href or src that worked at the top level points somewhere else,
# and Pages serves a page only at its extensionless path. A broken internal
# link is a dead end for a reader and a crawler alike.
# ---------------------------------------------------------------------------

class _Refs(html.parser.HTMLParser):
    """Every href and src on a page, and every id it defines."""

    def __init__(self):
        super().__init__()
        self.refs, self.ids, self.forms = [], set(), []

    def handle_starttag(self, tag, attrs):
        for name, value in attrs:
            if name in ("href", "src") and value is not None:
                self.refs.append((self.getpos()[0], value))
            if name == "id" and value:
                self.ids.add(value)
        if tag == "form" and dict(attrs).get("action"):
            self.forms.append((self.getpos()[0], dict(attrs)["action"],
                               (dict(attrs).get("method") or "get").upper()))


def refs(page):
    parser = _Refs()
    parser.feed(read(page))
    parser.close()
    return parser


EXTERNAL = ("https://", "mailto:")


def resolve(path):
    """The file Pages serves for a root-relative path, or None."""
    if path == "/" or path.endswith("/"):
        target = SITE / path.lstrip("/") / "index.html"
        return target if target.is_file() else None
    target = SITE / path.lstrip("/")
    if target.is_file() and not path.endswith(".html"):
        return target
    page = SITE / (path.lstrip("/") + ".html")
    return page if page.is_file() else None


def worker_routes():
    """{path: methods} the Worker answers on ranwhat.com: /api/* is routed
    to it ahead of Pages (worker/wrangler.toml), so nothing in site/ is."""
    index = (SITE.parent / "worker" / "src" / "index.js").read_text(encoding="utf-8")
    table = index[index.index("const ROUTES = {"):]
    table = table[:table.index("};")]
    return {path: set(re.findall(r'"([A-Z]+)"', methods))
            for path, methods in re.findall(r'"(/api/[a-z]+)": \[\w+, \[([^\]]+)\]\]', table)}


def stamped_assets():
    """The assets build.sh stamps with a content hash."""
    build = (SITE.parent / "build.sh").read_text(encoding="utf-8")
    return re.search(r"^for asset in ([^;]+);", build, re.M).group(1).split()


class InternalLinksResolve(unittest.TestCase):

    def test_every_internal_link_resolves_to_a_file(self):
        for page in all_pages():
            found = refs(page)
            name = page.relative_to(SITE).as_posix()
            for line, ref in found.refs:
                with self.subTest(page=name, line=line, ref=ref):
                    if ref.startswith(EXTERNAL):
                        continue
                    if ref.startswith("#"):
                        self.assertIn(ref[1:], found.ids, "no such id on the page")
                        continue
                    # A relative path means one thing at site/ and another at
                    # site/guides/; a protocol-relative one is an external
                    # link in disguise.
                    self.assertTrue(ref.startswith("/") and not ref.startswith("//"),
                                    "not root-relative")
                    path, _, fragment = ref.partition("#")
                    path = path.split("?", 1)[0]
                    if path.startswith("/api/"):
                        self.assertIn("GET", worker_routes().get(path, ()),
                                      "the Worker does not answer GET there")
                        continue
                    self.assertFalse(path.endswith(".html"),
                                     "Pages redirects .html; link the extensionless path")
                    target = resolve(path)
                    self.assertIsNotNone(target, "nothing in site/ is served there")
                    if fragment:
                        self.assertIn(fragment, refs(target).ids,
                                      "%s has no id %r" % (path, fragment))

    def test_every_form_posts_where_the_worker_takes_it(self):
        found = [(page.name, form) for page in all_pages() for form in refs(page).forms]
        self.assertTrue(found, "the pricing page's checkout form")
        for name, (line, action, method) in found:
            with self.subTest(page=name, line=line, action=action):
                self.assertIn(method, worker_routes().get(action, ()))

    def test_the_resolver_sees_what_it_is_looking_for(self):
        """Or the test above would pass for the wrong reason."""
        routes = worker_routes()
        self.assertEqual(routes["/api/checkout"], {"POST"})
        self.assertEqual(routes["/api/billing"], {"GET"})
        self.assertEqual(routes["/api/confirm"], {"GET", "POST"})
        self.assertEqual(resolve("/"), SITE / "index.html")
        self.assertEqual(resolve("/guides"), SITE / "guides.html")
        self.assertEqual(resolve("/guides/claude-code-history"),
                         SITE / "guides" / "claude-code-history.html")
        self.assertEqual(resolve("/styles.css"), SITE / "styles.css")
        for missing in ("/nope", "/guides/nope", "/watch.html", "/guides/"):
            self.assertIsNone(resolve(missing), missing)

    def test_stamped_assets_are_referenced_from_the_root(self):
        # build.sh rewrites each reference to /<asset>" across site/,
        # subdirectories included, so a page under site/guides/ is stamped
        # only if it names the asset the same way the top-level pages do.
        assets = stamped_assets()
        self.assertIn("styles.css", assets)
        build = (SITE.parent / "build.sh").read_text(encoding="utf-8")
        self.assertIn("grep -rlF", build, "build.sh must search site/ recursively")
        for page in all_pages():
            text = read(page)
            for asset in assets:
                for value in re.findall(r'(?:href|src)="([^"]*%s[^"]*)"'
                                        % re.escape(asset), text):
                    self.assertEqual(value, "/" + asset,
                                     "%s: %s" % (page.relative_to(SITE), value))
        guide = read(SITE / "guides" / "claude-code-history.html")
        self.assertIn('href="/styles.css"', guide)
        self.assertIn('src="/consent.js"', guide)


# ---------------------------------------------------------------------------
# The guides: an index at /guides, articles under /guides/, and the
# breadcrumb trail each of them shows.
# ---------------------------------------------------------------------------

def guide_pages():
    return sorted((SITE / "guides").glob("*.html"))


def h1_text(text):
    return plain(re.search(r"<h1[^>]*>(.*?)</h1>", text, re.S).group(1))


def graph(text, kind):
    return [b for block in json_ld(text) for b in block.get("@graph", [block])
            if b.get("@type") == kind]


HUB = "/guides/ai-coding-agent-security"


class GuidesHangTogether(unittest.TestCase):

    def test_there_are_guides(self):
        self.assertGreaterEqual(len(guide_pages()), 6)
        self.assertTrue((SITE / "guides.html").is_file())
        self.assertFalse((SITE / "guides" / "index.html").exists(),
                         "guides/index.html would make Pages redirect /guides "
                         "to /guides/, away from its canonical")

    def test_the_index_lists_every_guide_and_its_markup_matches(self):
        text = read(SITE / "guides.html")
        shown = [(ORIGIN + href, plain(name)) for href, name in
                 re.findall(r'<h3><a href="(/guides/[^"]+)">(.*?)</a></h3>', text)]
        self.assertEqual(sorted(u for u, _ in shown),
                         sorted(url_for(p) for p in guide_pages()))
        self.assertEqual(shown[0][0], ORIGIN + HUB, "the checklist comes first")
        pages = graph(text, "CollectionPage")
        self.assertEqual(len(pages), 1)
        marked = [(i["url"], i["name"])
                  for i in pages[0]["mainEntity"]["itemListElement"]]
        self.assertEqual(marked, shown, "guides.html's ItemList has drifted "
                         "from the cards on the page")
        self.assertEqual([i["position"] for i in
                          pages[0]["mainEntity"]["itemListElement"]],
                         list(range(1, len(shown) + 1)))
        self.assertEqual(pages[0]["url"], url_for(SITE / "guides.html"))
        self.assertEqual([pages[0]["description"]], meta(text, "name", "description"))

    def test_each_index_card_names_its_guide_by_its_h1(self):
        text = read(SITE / "guides.html")
        for href, name in re.findall(
                r'<h3><a href="(/guides/[^"]+)">(.*?)</a></h3>', text):
            self.assertEqual(plain(name), h1_text(read(resolve(href))), href)

    def test_every_guide_is_in_the_shared_footer(self):
        footer = re.search(r"<footer>.*?</footer>", read(SITE / "watch.html"),
                           re.S).group(0)
        self.assertIn('href="/guides"', footer)
        for page in guide_pages():
            self.assertIn('href="%s"' % url_for(page)[len(ORIGIN):], footer,
                          page.name)

    def test_every_guide_links_to_the_checklist_and_the_index(self):
        for page in guide_pages():
            main = re.search(r"<main.*?</main>", read(page), re.S).group(0)
            self.assertIn('href="/guides"', main, page.name)
            if url_for(page) != ORIGIN + HUB:
                self.assertIn('href="%s"' % HUB, main, page.name)

    def test_the_checklist_links_to_every_other_guide(self):
        text = read(resolve(HUB))
        for page in guide_pages():
            path = url_for(page)[len(ORIGIN):]
            if path != HUB:
                self.assertIn('href="%s"' % path, text, page.name)

    def test_the_step_count_quoted_for_the_checklist_is_its_length(self):
        # The home page and /guides said eleven steps when the checklist
        # had fourteen.
        text = read(resolve(HUB))
        section = re.search(r'<section[^>]*id="checklist">(.*?)</section>',
                            text, re.S).group(1)
        numbers = re.findall(r'<li class="row"><span class="k">(\d+)</span>',
                             section)
        self.assertEqual([int(n) for n in numbers],
                         list(range(1, len(numbers) + 1)))
        words = {11: "eleven", 12: "twelve", 13: "thirteen", 14: "fourteen",
                 15: "fifteen", 16: "sixteen"}
        count = words[len(numbers)]
        self.assertIn("%s steps, in order" % count,
                      plain(read(SITE / "index.html")))
        self.assertIn("%s steps, in the order worth doing them"
                      % count.capitalize(), plain(read(SITE / "guides.html")))

    def test_article_markup_matches_the_page(self):
        for page in guide_pages():
            text = read(page)
            articles = graph(text, "Article")
            self.assertEqual(len(articles), 1, page.name)
            article = articles[0]
            self.assertEqual(article["headline"], h1_text(text), page.name)
            self.assertEqual([article["description"]],
                             meta(text, "name", "description"), page.name)
            self.assertEqual(article["mainEntityOfPage"], url_for(page), page.name)
            self.assertLessEqual(article["datePublished"], article["dateModified"],
                                 page.name)
            self.assertEqual(meta(text, "property", "og:type"), ["article"], page.name)

    def test_visible_breadcrumbs_match_their_markup(self):
        # Structured data may only describe what a reader can see, so every
        # page that carries a BreadcrumbList shows the same trail. Ten pages
        # once had the markup and no trail.
        trails = marked_pages = 0
        for page in all_pages():
            text = read(page)
            found = re.findall(r'<nav class="crumbs" aria-label="Breadcrumb">(.*?)</nav>',
                               text, re.S)
            name = page.relative_to(SITE).as_posix()
            if graph(text, "BreadcrumbList"):
                marked_pages += 1
                self.assertEqual(len(found), 1, "%s has a BreadcrumbList but shows "
                                 "no breadcrumb trail" % name)
            if page.parent == SITE / "guides" or page.name == "guides.html":
                self.assertEqual(len(found), 1, "%s shows no breadcrumb trail" % name)
            if not found:
                continue
            trails += 1
            self.assertEqual(len(found), 1, name)
            # The trail sits above the heading and the first section, not
            # inside one. The example report has no <section> at all.
            start = text.index('class="crumbs"')
            self.assertLess(start, re.search(r"<h1[\s>]", text).start(), name)
            if "<section" in text:
                self.assertLess(start, text.index("<section"), name)
            links = [(ORIGIN + href if href != "/" else ORIGIN + "/", plain(label))
                     for href, label in
                     re.findall(r'<a href="([^"]+)">(.*?)</a>', found[0])]
            here = re.findall(r'<span aria-current="page">(.*?)</span>', found[0])
            self.assertEqual(len(here), 1, name)
            shown = links + [(url_for(page), plain(here[0]))]
            crumbs = graph(text, "BreadcrumbList")
            self.assertEqual(len(crumbs), 1, name)
            marked = [(i["item"], i["name"]) for i in crumbs[0]["itemListElement"]]
            self.assertEqual(marked, shown, "%s: the trail and its "
                             "BreadcrumbList disagree" % name)
        self.assertEqual(trails, marked_pages)
        interior = [p for p in all_pages() if indexable(p) and p.name != "index.html"]
        self.assertGreaterEqual(trails, len(interior))

    def test_guide_dates_agree_on_the_page_in_the_markup_and_the_sitemap(self):
        # Search engines are told to expect the visible date and the
        # structured one to match; four guides once said "checked on 1
        # October" over markup and a sitemap that said 27 September.
        lastmod = dict(re.findall(r"<loc>([^<]+)</loc><lastmod>([^<]+)</lastmod>",
                                  read(SITE / "sitemap.xml")))
        for page in guide_pages():
            text = read(page)
            article = graph(text, "Article")[0]
            shown = re.findall(r'<time datetime="([^"]+)">', text)
            self.assertEqual(shown, [article["dateModified"]], page.name)
            self.assertEqual(lastmod.get(url_for(page)), article["dateModified"],
                             page.name)


# Number words, as the site writes counts ("Nine rules", "twelve providers").
WORDS = dict(enumerate(
    "zero one two three four five six seven eight nine ten eleven twelve "
    "thirteen fourteen fifteen sixteen seventeen eighteen nineteen twenty"
    .split()))


@functools.lru_cache(maxsize=1)
def sources_json():
    """What `ranwhat sources --json` says, run in a home that holds no
    agent's history: every agent ranwhat knows, in its order, with nothing
    found on this machine deciding what the site says."""
    from ranwhat import sources
    home = tempfile.mkdtemp(prefix="site-sources-")
    try:
        moved = {var for source in sources.sources() for var in source.env}
        env = {k: v for k, v in os.environ.items() if k not in moved}
        env.update(HOME=home, USERPROFILE=home,
                   RANWHAT_HOME=os.path.join(home, "state"),
                   PYTHONPATH=str(SITE.parent))
        out = subprocess.run([sys.executable, "-m", "ranwhat", "sources",
                              "--json"], cwd=str(SITE.parent), env=env,
                             capture_output=True, text=True, encoding="utf-8",
                             timeout=60)
        return json.loads(out.stdout)
    finally:
        shutil.rmtree(home, ignore_errors=True)


def site_status(entry):
    """The status the site gives an agent `ranwhat sources --json` lists."""
    if entry["status"] == "cloud only":
        return "Cloud only"
    if entry["status"] == "next":
        return "Next"
    if entry["masking"] == "read-only":
        return "Shipped, secrets read-only"
    return "Shipped"


def names(*statuses):
    """The names of the agents with these site statuses, in order."""
    return [e["name"] for e in sources_json() if site_status(e) in statuses]


def listed(items):
    """Names as a sentence lists them: "A, B and C"."""
    items = list(items)
    return items[0] if len(items) == 1 else \
        ", ".join(items[:-1]) + " and " + items[-1]


SHIPPED = ("Shipped", "Shipped, secrets read-only")


class SiteAgentsComeFromTheRegistry(unittest.TestCase):
    """Every agent the site, llms.txt and the README name, and every count
    of them, is what `ranwhat sources --json` says."""

    def test_the_registry_is_what_sources_lists(self):
        from ranwhat import sources
        self.assertEqual(names(*SHIPPED), [s.name for s in sources.sources()])
        self.assertEqual(names("Cloud only"),
                         [name for name, _ in sources.CLOUD_ONLY])
        self.assertEqual(names("Next"), [name for name, _ in sources.NEXT])

    def test_the_watch_page_lists_every_agent_with_its_status(self):
        section = read(SITE / "watch.html").split("03 / Sources", 1)[1]
        table = re.search(r'<table class="stack">(.*?)</table>', section, re.S)
        body = table.group(1).split("</thead>", 1)[1]
        rows = []
        for row in re.findall(r"<tr>(.*?)</tr>", body, re.S):
            cells = [plain(c) for c in re.findall(r"<td\b[^>]*>(.*?)</td>", row, re.S)]
            rows.append((cells[0], cells[-1]))
        self.assertEqual(rows, [(e["name"], site_status(e)) for e in sources_json()])
        paragraphs = plain(section.split("</table>", 1)[1].split("</section>", 1)[0])
        self.assertIn(listed(names("Cloud only")).replace(" Amp", " the current Amp"),
                      paragraphs)
        if names("Next"):
            self.assertIn("%s is next" % listed(names("Next")), paragraphs)
        else:
            self.assertNotIn(" is next", paragraphs)

    def test_every_count_of_agents_is_the_registrys(self):
        shipped = names(*SHIPPED)
        n = len(shipped)
        allowed = []
        for k in range(1, 4):
            lead = ", ".join(shipped[:k]) + " and " + WORDS[n - k]
            allowed += [lead + tail for tail in (" other coding agents",
                                                 " more coding agents",
                                                 " more agents")]
        counted = re.compile(r"\b(%s) (?:more|other) (?:coding )?agents\b"
                             % "|".join(WORDS.values()))
        every = re.compile(r"\b[Aa]ll (%s)\b" % "|".join(WORDS.values()))
        files = all_pages() + [SITE / "llms.txt", SITE.parent / "README.md"]
        seen = 0
        for page in files:
            text = read(page)
            for chunk in (plain(text), " ".join(text.split())):
                for m in counted.finditer(chunk):
                    seen += 1
                    self.assertTrue(any(chunk[:m.end()].endswith(a) for a in allowed),
                                    "%s: ...%s" % (page.name, chunk[max(0, m.start() - 60):m.end()]))
                for m in every.finditer(chunk):
                    if chunk[m.end():m.end() + 7] in (" by def", ", each "):
                        self.assertEqual(m.group(1), WORDS[n], page.name)
        self.assertGreaterEqual(seen, 10)

    def test_the_faq_names_every_agent(self):
        answer = dict(faq_blocks(read(SITE / "faq.html")))["Which agents does it read?"]
        self.assertTrue(answer.startswith(listed(names(*SHIPPED)) + ", from the "),
                        answer)
        self.assertIn("read all %s by default" % WORDS[len(names(*SHIPPED))], answer)
        self.assertIn(listed(names("Cloud only")).replace(" Amp", " the current Amp"),
                      answer)
        if names("Next"):
            self.assertIn("%s is next." % listed(names("Next")), answer)
        else:
            self.assertNotIn(" is next", answer)
        for name in names("Shipped, secrets read-only"):
            self.assertIn("%s keeps its history in a database" % name, answer)

    def test_the_clean_page_says_which_agents_it_masks_and_only_reads(self):
        rows = re.findall(r'<span class="k">([^<]+)</span>\s*<span class="v">(.*?)</span></div>',
                          read(SITE / "clean.html"), re.S)
        masks = plain(dict(rows)["Masks"])
        self.assertIn("That covers %s." % listed(names("Shipped")), masks)
        self.assertTrue(re.search(r"Read only: %s\b" % re.escape(
            listed(names("Shipped, secrets read-only"))), masks), masks)

    def test_the_commands_page_lists_every_source_id(self):
        """--source's ID list on /commands is the registry's, in order."""
        from ranwhat import sources
        row = re.search(r'IDs: (.*?)</td>', read(SITE / "commands.html")).group(1)
        self.assertEqual(re.findall(r'<span class="icode">([^<]+)</span>', row),
                         list(sources.ids()))

    def test_nothing_says_an_agent_is_next_when_none_is(self):
        if names("Next"):
            return
        files = all_pages() + [SITE / "llms.txt", SITE.parent / "README.md"]
        for page in files:
            if page.name in ("updates.html",):
                continue
            text = " ".join(read(page).split())
            self.assertNotRegex(text, r"\b(is|are) next\b", page.name)

    def test_llms_txt_names_every_agent(self):
        text = " ".join(read(SITE / "llms.txt").split())
        self.assertIn("Agents read: %s." % listed(names(*SHIPPED)), text)
        self.assertIn(listed(names("Cloud only")).replace(" Amp", " the current Amp"),
                      text)
        if names("Next"):
            self.assertIn("%s is next." % listed(names("Next")), text)

    def test_the_readme_table_names_every_agent(self):
        readme = read(SITE.parent / "README.md")
        table = readme.split("| Source | Location | Format |", 1)[1].split("\n\n", 1)[0]
        rows = [line.split("|")[1].strip() for line in table.strip().splitlines()[1:]]
        self.assertEqual([re.sub(r" \(.*\)$", "", r) for r in rows], names(*SHIPPED))
        text = " ".join(readme.split())
        for name in names("Cloud only") + names("Next"):
            self.assertIn(name, text)


class ThemeSwitch(unittest.TestCase):
    """Every page in the site chrome offers the light/dark switch, and loads
    theme.js in <head> without defer so a saved choice paints first."""

    def test_every_page_has_the_switch_and_loads_it_early(self):
        for page in sorted(SITE.rglob("*.html")):
            text = page.read_text(encoding="utf-8")
            if 'class="shell nav"' not in text:
                continue
            head = text.split("</head>", 1)[0]
            self.assertRegex(head, r'<script src="/theme\.js[^"]*"></script>', page.name)
            self.assertNotRegex(head, r'<script src="/theme\.js[^"]*" (defer|async)', page.name)
            self.assertIn("data-theme-toggle", text, page.name)

    def test_switch_sits_before_github(self):
        text = (SITE / "index.html").read_text(encoding="utf-8")
        self.assertLess(text.index("data-theme-toggle"), text.index('class="ghost"'))



# ---------------------------------------------------------------------------
# Updates: the release notes on /updates, the RSS feed made from them, and
# the email signup that announces them.
# ---------------------------------------------------------------------------

def _rss_script():
    spec = importlib.util.spec_from_file_location(
        "rss_script", SITE.parent / "scripts" / "rss.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ReleaseNotesAndFeed(unittest.TestCase):

    def test_the_feed_is_what_the_script_makes_from_the_page(self):
        # To refresh it after adding a release: python3 scripts/rss.py
        self.assertEqual(read(SITE / "rss.xml"), _rss_script().build())

    def test_the_feed_parses_and_each_item_lands_on_its_release(self):
        import xml.etree.ElementTree as ET
        channel = ET.fromstring(read(SITE / "rss.xml")).find("channel")
        items = channel.findall("item")
        ids = refs(SITE / "updates.html").ids
        self.assertEqual(len(items), len(_rss_script().releases(read(SITE / "updates.html"))))
        for item in items:
            link = item.find("link").text
            self.assertTrue(link.startswith(ORIGIN + "/updates#"), link)
            self.assertIn(link.split("#", 1)[1], ids)
            # A reader shows the item off the site, where /watch goes nowhere.
            self.assertNotIn('href="/', item.find("description").text)

    def test_the_newest_release_is_the_version_that_ships(self):
        # Bumping the version means saying on /updates what changed.
        rels = _rss_script().releases(read(SITE / "updates.html"))
        self.assertEqual(rels[0][1], ranwhat.__version__)
        versions = [tuple(int(n) for n in r[1].split(".")) for r in rels]
        self.assertEqual(versions, sorted(versions, reverse=True))
        self.assertEqual(len(versions), len(set(versions)))
        for rid, version, *_ in rels:
            self.assertEqual(rid, "v" + version.replace(".", "-"))

    def test_every_page_in_the_site_chrome_points_feed_readers_at_it(self):
        tag = ('<link rel="alternate" type="application/rss+xml" '
               'title="ranwhat releases" href="https://ranwhat.com/rss.xml">')
        for page in all_pages():
            text = read(page)
            if 'class="fbase"' in text:
                self.assertIn(tag, text.split("</head>", 1)[0], page.name)


class AccountClaimsMatchTheWorker(unittest.TestCase):
    """What privacy.html and terms.html say about the account, against the
    constants in worker/src that make it true: the cookies and how long
    each lasts, how long sessions and the security history are kept, and
    when an idle terminal's token is revoked."""

    def setUp(self):
        self.src = {f.name: read(f) for f in (SITE.parent / "worker" / "src").glob("*.js")}
        self.privacy = plain(read(SITE / "privacy.html"))
        self.terms = plain(read(SITE / "terms.html"))

    def constant(self, name):
        """A lifetime constant, in seconds."""
        units = {"DAY": 86400, "HOUR": 3600}
        for text in self.src.values():
            m = re.search(r"^(?:export )?const %s = (.+?);" % name, text, re.M)
            if m:
                expr = m.group(1)
                for unit, seconds in units.items():
                    expr = re.sub(r"\b%s\b" % unit, str(seconds), expr)
                self.assertRegex(expr, r"^[\d\s*]+$", name)
                value = 1
                for factor in expr.split("*"):
                    value *= int(factor)
                return value
        self.fail("no constant %s in worker/src" % name)

    def test_privacy_names_every_cookie_the_account_sets_and_no_other(self):
        set_in_code = set()
        for text in self.src.values():
            set_in_code |= set(re.findall(r'_COOKIE = "(__Host-rw_[a-z]+)"', text))
        self.assertEqual(set_in_code, {"__Host-rw_session", "__Host-rw_signin",
                                       "__Host-rw_oauth", "__Host-rw_invite"})
        named = set(re.findall(r"__Host-rw_[a-z]+", self.privacy))
        self.assertEqual(named, set_in_code)
        self.assertIn("Four, set only on account.ranwhat.com", self.privacy)

    def test_the_lifetimes_said_are_the_ones_set(self):
        said = {
            "SESSION_MAX": "kept at most 30 days",
            "SESSION_IDLE": "after 14 days unused",
            "SIGNIN_FOR": "first shown and kept an hour",
            "FLOW_FOR": "Google or GitHub, for 10 minutes",
            "INVITE_COOKIE_FOR": "invite link, for an hour",
            "CODE_FOR": "for the code\u2019s 10 minutes",
            "KEEP_EVENTS": "kept for 13 months",
        }
        seconds = {"SESSION_MAX": 30 * 86400, "SESSION_IDLE": 14 * 86400, "SIGNIN_FOR": 3600,
                   "FLOW_FOR": 600, "INVITE_COOKIE_FOR": 3600, "CODE_FOR": 600,
                   "KEEP_EVENTS": 396 * 86400}
        for name, phrase in said.items():
            with self.subTest(constant=name):
                self.assertEqual(self.constant(name), seconds[name])
                self.assertIn(phrase, self.privacy)

    def test_an_idle_terminal_is_revoked_when_both_pages_say(self):
        days = int(re.search(r"^export const IDLE_DAYS = (\d+);",
                             self.src["machines.js"], re.M).group(1))
        self.assertIn("unused for %d days is revoked" % days, self.privacy)
        self.assertIn("unused for %d days is revoked by itself" % days, self.terms)

    def test_no_provider_token_is_kept_and_none_is_said_to_be(self):
        # oauth.js stores the provider's id and the address it vouched for,
        # and never a token: the identities table has no column for one.
        schema = self.src["accounts.js"]
        identities = schema[schema.index("CREATE TABLE IF NOT EXISTS identities"):]
        identities = identities[:identities.index("`")]
        self.assertNotRegex(identities, r"token")
        self.assertIn("It stores no Google or GitHub token", self.privacy)

    def test_the_terms_change_is_dated_and_the_notice_clause_stays(self):
        self.assertIn("Last changed 7 October 2026.", self.terms)
        self.assertIn("We will email subscribers at least 30 days before a change to "
                      "these terms reaches them.", self.terms)
        self.assertIn("There is no button that deletes the account itself yet", self.privacy)


class EmailSignup(unittest.TestCase):
    """The signup feeds our own list (worker/src/list.js), which
    worker/test/list.test.mjs runs end to end. What these pin from here: the
    challenge is checked, for this form, before the address is stored; no
    log line can carry an address; and CI runs those tests."""

    def setUp(self):
        self.index = read(SITE.parent / "worker" / "src" / "index.js")
        self.list = read(SITE.parent / "worker" / "src" / "list.js")
        self.body = self.index[self.index.index("async function handleSubscribe"):
                               self.index.index("const ROUTES")]

    def test_the_challenge_is_checked_before_the_address_is_stored(self):
        check = self.body.index('refuseChallenge(request, env, form["cf-turnstile-response"], "subscribe")')
        self.assertLess(check, self.body.index("await subscribe(env, address)"))
        self.assertIn('action: "subscribe"', read(SITE / "subscribe.js"))

    def test_the_address_is_never_logged(self):
        for name, src in (("index.js", self.body), ("list.js", self.list)):
            for line in re.findall(r"console\.log\((.*)\);", src):
                with self.subTest(file=name, line=line):
                    for word in ("email", "address", "subscriber", "row", "form"):
                        self.assertNotIn(word, line)

    def test_ci_runs_the_worker_tests(self):
        ci = "".join(read(p) for p in sorted((SITE.parent / ".github" / "workflows").glob("*.yml")))
        self.assertIn("node --test worker/test/", ci)
        self.assertIn("node --check worker/src/list.js", ci)

    def test_the_forms_load_the_script_and_turnstile_waits_for_them(self):
        for name in ("index.html", "updates.html"):
            text = read(SITE / name)
            self.assertIn("data-subscribe", text, name)
            self.assertIn('src="/subscribe.js"', text, name)
            # Loaded from subscribe.js on first use, not by the page.
            self.assertNotIn("challenges.cloudflare.com/turnstile", text, name)

if __name__ == "__main__":
    unittest.main()
