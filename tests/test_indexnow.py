"""scripts/indexnow.py sends only what the sitemap lists, under the key the
site serves. Nothing here touches the network: the opener is a stand-in."""
import importlib.util
import io
import json
import os
import pathlib
import unittest
import urllib.error

ROOT = pathlib.Path(__file__).resolve().parent.parent
SITE = ROOT / "site"


def _load():
    spec = importlib.util.spec_from_file_location("indexnow", ROOT / "scripts" / "indexnow.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


indexnow = _load()


class _Resp(io.BytesIO):
    def __init__(self, body=b"", status=200):
        super().__init__(body)
        self.status = status


class Opener:
    """Answers the key fetch with `live` and the submission with `status`."""

    def __init__(self, live, status=200):
        self.live, self.status, self.sent = live, status, []

    def __call__(self, req, timeout=None):
        if req.data is None:
            return _Resp(self.live.encode())
        self.sent.append(json.loads(req.data))
        if self.status >= 400:
            raise urllib.error.HTTPError(req.full_url, self.status, "", {}, None)
        return _Resp(status=self.status)


class KeyFile(unittest.TestCase):
    def test_one_key_file_holding_its_own_name(self):
        k = indexnow.key()
        self.assertEqual((SITE / (k + ".txt")).read_text(encoding="utf-8").strip(), k)

    def test_robots_and_llms_are_not_mistaken_for_keys(self):
        self.assertNotIn(indexnow.key(), ("robots", "llms"))


class Urls(unittest.TestCase):
    def test_page_files_map_to_their_canonical_urls(self):
        cases = {
            "site/index.html": "https://ranwhat.com/",
            "site/watch.html": "https://ranwhat.com/watch",
            "site/guides.html": "https://ranwhat.com/guides",
            "site/guides/claude-code-history.html": "https://ranwhat.com/guides/claude-code-history",
            "site/styles.css": None,
            "site/robots.txt": None,
            "README.md": None,
        }
        for path, url in cases.items():
            self.assertEqual(indexnow.url_for(path), url, path)

    def test_every_sitemap_url_is_a_page_in_the_repo(self):
        pages = {indexnow.url_for(str(p.relative_to(ROOT))) for p in SITE.rglob("*.html")}
        missing = [u for u in indexnow.sitemap_urls() if u not in pages]
        self.assertEqual(missing, [])

    def test_sitemap_urls_are_all_on_the_host(self):
        for u in indexnow.sitemap_urls():
            self.assertTrue(u.startswith("https://ranwhat.com/"), u)


class Send(unittest.TestCase):
    URLS = ["https://ranwhat.com/", "https://ranwhat.com/watch"]

    def test_payload_names_the_host_key_and_its_location(self):
        k = indexnow.key()
        opener = Opener(k)
        self.assertEqual(indexnow.send(self.URLS, k, opener), 200)
        self.assertEqual(opener.sent, [{
            "host": "ranwhat.com", "key": k,
            "keyLocation": "https://ranwhat.com/%s.txt" % k, "urlList": self.URLS}])

    def test_refuses_before_the_live_key_matches(self):
        opener = Opener("not-the-key")
        with self.assertRaisesRegex(indexnow.IndexNowError, "deploy"):
            indexnow.send(self.URLS, indexnow.key(), opener)
        self.assertEqual(opener.sent, [])

    def test_an_engine_refusal_says_why(self):
        k = indexnow.key()
        with self.assertRaisesRegex(indexnow.IndexNowError, "422"):
            indexnow.send(self.URLS, k, Opener(k, status=422))

    def test_without_send_nothing_leaves_the_machine(self):
        out = io.StringIO()
        from contextlib import redirect_stdout
        with redirect_stdout(out):
            self.assertEqual(indexnow.main([]), 0)
        self.assertIn("Nothing sent", out.getvalue())


if __name__ == "__main__":
    unittest.main()
