"""The site states numbers that come from the catalogue. Those numbers drift
the moment a provider is added, and a marketing page that undercounts its own
product is the kind of thing nobody notices for months."""
import pathlib
import re
import unittest

from ranwhat import catalog

SITE = pathlib.Path(__file__).resolve().parent.parent / "site"


def live():
    providers = {p: s for p, s in catalog.CATALOG.items() if s}
    return len(providers), sum(len(s) for s in providers.values())


class SiteMatchesCatalogue(unittest.TestCase):
    def test_about_page_counts_are_current(self):
        n_prov, n_scopes = live()
        text = (SITE / "about.html").read_text()
        self.assertIn("%d providers and %d permissions" % (n_prov, n_scopes), text,
                      "about.html coverage numbers are stale")

    def test_about_page_lists_every_provider(self):
        text = (SITE / "about.html").read_text()
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
        text = (SITE / "pricing.html").read_text()
        self.assertNotIn("all five providers", text)
        self.assertIn("twelve providers" if n_prov == 12 else str(n_prov), text)


class NoEmDashes(unittest.TestCase):
    """Removed deliberately across the site; easy to reintroduce by hand."""

    def test_no_page_contains_an_em_dash(self):
        for page in sorted(SITE.glob("*.html")):
            self.assertNotIn("—", page.read_text(), "%s has an em dash" % page.name)



class AdMeasurementNeedsConsent(unittest.TestCase):
    """The X pixel sets cookies and reports the visit, so it may only load
    after a yes. These pin the parts of that which a later edit could quietly
    undo: a page pasting X's base code straight in, a page missing the way to
    withdraw, or the server sending X more than the privacy page says."""

    PAGES = sorted(SITE.glob("*.html"))
    X_HOSTS = ("ads-twitter.com", "twq(", "uwt.js", "analytics.twitter.com")

    def test_no_page_loads_x_directly(self):
        for page in self.PAGES:
            text = page.read_text()
            for host in self.X_HOSTS:
                self.assertNotIn(host, text.replace("static.ads-twitter.com</span>", ""),
                                 "%s references %s outside consent.js" % (page.name, host))

    def test_every_page_offers_consent_and_a_way_back(self):
        for page in self.PAGES:
            text = page.read_text()
            self.assertIn('src="/consent.js', text, page.name)
            self.assertIn("data-consent-open", text, page.name)

    def test_pixel_loads_only_from_the_consent_path(self):
        js = (SITE / "consent.js").read_text()
        self.assertEqual(js.count("https://static.ads-twitter.com/uwt.js"), 1)
        calls = re.findall(r"(?<![\w.])load\(\);", js)
        self.assertEqual(len(calls), 2, "load() should be reachable only from "
                         "a stored yes and the Allow button")
        self.assertIn('now === "granted") load();', js)
        self.assertIn('answer === "granted") { load();', js)
        self.assertIn("globalPrivacyControl", js)

    def test_csp_allows_the_pixel_and_nothing_broader(self):
        csp = next(l for l in (SITE / "_headers").read_text().splitlines()
                   if "Content-Security-Policy" in l)
        self.assertIn("https://static.ads-twitter.com", csp)
        self.assertNotIn("*", csp.replace("/*", ""), "no wildcard hosts")

    def test_privacy_page_describes_it(self):
        text = (SITE / "privacy.html").read_text()
        self.assertIn('id="ads"', text)
        self.assertIn("Global Privacy Control", text)
        for stale in ("GitHub Pages", "no backend", "no tracking pixels"):
            self.assertNotIn(stale, text)

    def test_server_never_sends_x_the_message_or_address(self):
        src = (SITE.parent / "worker" / "src" / "index.js").read_text()
        body = src[src.index("async function reportLead"):src.index("async function handleContact")]
        self.assertIn("form.measure !== true", body)
        for field in ("form.message", "form.email", "replyTo", "hashed_email"):
            self.assertNotIn(field, body)


if __name__ == "__main__":
    unittest.main()
