"""Every page has a markdown twin an AI agent can fetch, and says so.

scripts/build_md.py writes the twins at build time from each page's <main>;
these tests build them into a temporary folder, so a page added without one,
or a page whose markup the converter cannot read, fails here rather than
quietly missing from /llms-full.txt."""
import importlib.util
import pathlib
import re
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
SITE = ROOT / "site"


def _build_md():
    spec = importlib.util.spec_from_file_location("build_md", ROOT / "scripts" / "build_md.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


build_md = _build_md()


class MarkdownTwins(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.out = pathlib.Path(cls.tmp.name)
        cls.twins = {t["rel"]: t for t in build_md.build(cls.out)}

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_every_page_has_a_twin_or_a_reason(self):
        for page in sorted(SITE.rglob("*.html")):
            rel = page.relative_to(SITE).as_posix()
            if rel in build_md.SKIP:
                self.assertTrue(build_md.SKIP[rel].strip(), rel)
                continue
            self.assertIn(rel, self.twins, "%s has no markdown twin" % rel)
            self.assertTrue((self.out / (rel[:-len(".html")] + ".md")).is_file(), rel)

    def test_skipped_pages_are_not_indexed_or_not_prose(self):
        self.assertIn('name="robots" content="noindex"', (SITE / "404.html").read_text(encoding="utf-8"))
        self.assertNotIn("<main", (SITE / "example-report.html").read_text(encoding="utf-8"))

    def test_each_twin_opens_with_title_summary_and_canonical(self):
        for rel, twin in self.twins.items():
            lines = twin["markdown"].splitlines()
            self.assertTrue(lines[0].startswith("# ") and len(lines[0]) > 3, rel)
            self.assertEqual(lines[2], "> " + twin["summary"], rel)
            self.assertIn("Canonical: " + build_md.url_for(rel), twin["markdown"], rel)

    def test_twins_carry_the_page_and_no_markup(self):
        for rel, twin in self.twins.items():
            md = twin["markdown"]
            # Outside code blocks, no HTML tag survived the conversion.
            prose = re.sub(r"```.*?```", "", md, flags=re.S)
            prose = re.sub(r"`[^`]*`", "", prose)
            self.assertIsNone(re.search(r"</?(div|span|section|p|a|ul|li|table)[\s>]", prose), rel)
            self.assertGreater(len(md), 400, rel)
            self.assertNotIn("—", md, rel)
            # Links leave absolute, and point at the HTML page.
            for href in re.findall(r"\]\(([^)]+)\)", prose):
                self.assertRegex(href, r"^(https?:|mailto:)", (rel, href))
                self.assertFalse(href.startswith(build_md.ORIGIN) and href.endswith(".md"), (rel, href))

    def test_every_h2_on_a_page_is_in_its_twin(self):
        for rel, twin in self.twins.items():
            text = (SITE / rel).read_text(encoding="utf-8")
            main = re.search(r"<main[^>]*>(.*)</main>", text, re.S).group(1)
            for h2 in re.findall(r"<h2[^>]*>(.*?)</h2>", main, re.S):
                heading = " ".join(re.sub(r"<[^>]+>", "", h2).split())
                heading = build_md.html.unescape(heading)
                self.assertIn(heading, twin["markdown"].replace("`", ""), (rel, heading))

    def test_every_twinned_page_points_to_its_twin(self):
        for rel in self.twins:
            text = (SITE / rel).read_text(encoding="utf-8")
            alternate = '<link rel="alternate" type="text/markdown" href="%s">' % build_md.md_url_for(rel)
            self.assertEqual(text.count(alternate), 1, rel)
            summary = re.findall(r'<meta name="ai-summary" content="([^"]*)">', text)
            description = re.findall(r'<meta name="description" content="([^"]*)">', text)
            self.assertEqual(len(summary), 1, rel)
            self.assertEqual(summary, description, rel)

    def test_full_file_and_catalogue_cover_every_twin(self):
        full = (self.out / "llms-full.txt").read_text(encoding="utf-8")
        self.assertLess(len(full), build_md.FULL_WARN_CHARS)
        for rel, twin in self.twins.items():
            self.assertIn("<!-- source: %s -->" % twin["url"], full, rel)
        catalog = build_md.json.loads((self.out / "md-catalog.json").read_text(encoding="utf-8"))
        self.assertEqual(catalog["count"], len(self.twins))
        self.assertEqual({p["md"] for p in catalog["pages"]},
                         {t["md"] for t in self.twins.values()})

    def test_llms_txt_links_the_twins_that_exist(self):
        text = (SITE / "llms.txt").read_text(encoding="utf-8")
        mds = {t["md"] for t in self.twins.values()}
        linked = re.findall(r"\]\((%s/[^)]+\.md)\)" % re.escape(build_md.ORIGIN), text)
        self.assertTrue(linked)
        for href in linked:
            self.assertIn(href, mds, href)
        for name in ("llms-full.txt", "md-catalog.json", "ai.txt"):
            self.assertIn("%s/%s" % (build_md.ORIGIN, name), text)


if __name__ == "__main__":
    unittest.main()
