"""scripts/indexnow.py sends what the sitemap lists, and pages a push removed,
under the key the site serves. Nothing here touches the network: the opener
is a stand-in."""
import importlib.util
import io
import json
import os
import re
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


class Changed(unittest.TestCase):
    """--changed REV: what a push changed, what it removed, and what to do
    with a revision there is nothing to diff against."""

    def _run(self, argv):
        from contextlib import redirect_stdout, redirect_stderr
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = indexnow.main(argv)
        return code, out.getvalue(), err.getvalue()

    def test_a_first_push_or_a_run_by_hand_lists_every_page(self):
        for rev in ("0" * 40, ""):
            self.assertFalse(indexnow.known_commit(rev), rev)
        code, out, err = self._run(["--changed", "0" * 40])
        self.assertEqual(code, 0)
        self.assertIn("listing every sitemap page", err)
        for u in indexnow.sitemap_urls():
            self.assertIn(u, out)

    def test_a_commit_this_checkout_has_is_known(self):
        head = indexnow._git("rev-parse", "HEAD").strip()
        self.assertTrue(indexnow.known_commit(head))
        self.assertFalse(indexnow.known_commit("f" * 40))

    def test_removed_pages_are_sent_after_the_changed_ones(self):
        diffs = {"--diff-filter=d": "site/watch.html\nsite/styles.css\n",
                 "--diff-filter=D": "site/guides/old-guide.html\n"}

        def git(*args):
            if args[0] == "diff":
                return diffs[next(a for a in args if a.startswith("--diff-filter="))]
            return ""
        orig_git, orig_known = indexnow._git, indexnow.known_commit
        indexnow._git, indexnow.known_commit = (lambda *a, **k: git(*a)), (lambda rev: True)
        try:
            code, out, _ = self._run(["--changed", "abc123"])
        finally:
            indexnow._git, indexnow.known_commit = orig_git, orig_known
        self.assertEqual(code, 0)
        listed = [line for line in out.splitlines() if line.startswith("https://")]
        self.assertEqual(listed, ["https://ranwhat.com/watch",
                                  "https://ranwhat.com/guides/old-guide"])


class RenamesInARealRepository(unittest.TestCase):
    """A moved page is a new URL and a removed one, not a rename git hides."""

    def test_a_moved_page_sends_its_old_url_as_removed(self):
        import shutil, subprocess, tempfile
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)

        def git(*args):
            return subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.com"]
                                  + list(args), cwd=tmp, check=True,
                                  capture_output=True, text=True).stdout
        os.makedirs(os.path.join(tmp, "site", "guides"))
        page = "<html><body>" + "the same guide, word for word. " * 40 + "</body></html>\n"
        for name in ("guides/old-guide.html", "gone.html", "watch.html"):
            with open(os.path.join(tmp, "site", name), "w", encoding="utf-8") as fh:
                fh.write(page if name.startswith("guides") else name + "\n")
        git("init", "-q")
        git("add", "-A")
        git("commit", "-q", "-m", "first")
        first = git("rev-parse", "HEAD").strip()
        git("mv", "site/guides/old-guide.html", "site/guides/new-guide.html")
        git("rm", "-q", "site/gone.html")
        with open(os.path.join(tmp, "site", "watch.html"), "a", encoding="utf-8") as fh:
            fh.write("edited\n")
        git("commit", "-q", "-am", "second")

        changed, removed = indexnow.changed_since(first, cwd=tmp)
        self.assertEqual(changed, {"https://ranwhat.com/guides/new-guide",
                                   "https://ranwhat.com/watch"})
        self.assertEqual(removed, {"https://ranwhat.com/guides/old-guide",
                                   "https://ranwhat.com/gone"})


class Workflow(unittest.TestCase):
    PATH = ROOT / ".github" / "workflows" / "indexnow.yml"

    def test_it_waits_for_the_pages_deploy_before_sending(self):
        text = self.PATH.read_text(encoding="utf-8")
        self.assertLess(text.index('select(.name == "Cloudflare Pages")'),
                        text.index("scripts/indexnow.py --changed"))
        # A branch's preview deploy carries the same check name.
        self.assertIn('test("Branch Preview URL") | not', text)
        self.assertIn("if: github.ref == 'refs/heads/main'", text)

    def test_it_sends_since_the_last_run_that_succeeded(self):
        # Diffing only against the push's own previous head loses the pages
        # of any run that was cancelled, failed or timed out.
        text = self.PATH.read_text(encoding="utf-8")
        self.assertIn("status=success", text)
        self.assertIn("actions: read", text)

    def test_no_event_value_is_pasted_into_a_shell_command(self):
        # A run: block that interpolates ${{ }} runs whatever the value holds;
        # every value goes through env instead.
        text = self.PATH.read_text(encoding="utf-8")
        blocks = re.findall(r"run: \|\n((?:          .*\n|\n)+)", text)
        self.assertTrue(blocks)
        for block in blocks:
            self.assertNotIn("${{", block)


if __name__ == "__main__":
    unittest.main()
