"""Hints: a dim line under the output that makes it relevant, on a terminal
only, never with --json, once per process, and switched off by
RANWHAT_NO_HINTS. Today the only ones point at the catalogue feed, under a
scan or live that found scopes the bundled catalogue could not rate, and
under `update --status` with no feed. None under demo."""
import contextlib
import io
import json
import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import isolated_home  # noqa: E402,F401  ranwhat's state, never ~/.ranwhat
import ranwhat  # noqa: E402
from ranwhat import catalog, cli, feed, hints, term  # noqa: E402


class _Tty(io.StringIO):
    """A stream that says it is a terminal."""

    def isatty(self):
        return True


class _Closed(io.StringIO):
    def isatty(self):
        raise ValueError("I/O operation on closed file")


class _Broken(_Tty):
    def write(self, text):
        raise OSError("gone")


class _Clean(unittest.TestCase):
    """No hint shown yet, no token, no feed, and no colour, so what a test
    reads is the text alone."""

    def setUp(self):
        hints.reset()
        self.addCleanup(hints.reset)
        env = mock.patch.dict(os.environ, {"NO_COLOR": "1"})
        env.start()
        self.addCleanup(env.stop)
        for name in ("RANWHAT_NO_HINTS", "RANWHAT_TOKEN"):
            os.environ.pop(name, None)
        self.home = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.home, True)
        os.environ["RANWHAT_HOME"] = self.home
        catalog.reset_feed_cache()
        self.addCleanup(catalog.reset_feed_cache)


class Hint(_Clean):

    def test_a_terminal_gets_the_lines_once(self):
        tty = _Tty()
        self.assertTrue(hints.hint("k", ["  one", "  two"], stream=tty))
        self.assertFalse(hints.hint("k", ["  one", "  two"], stream=tty))
        self.assertEqual(tty.getvalue(), "  one\n  two\n")
        self.assertTrue(hints.hint("other", ["  three"], stream=tty))

    def test_they_are_dim_where_colour_is_allowed(self):
        tty = _Tty()
        # _escapes: on Windows a stream that is not a console reads none.
        with mock.patch.dict(os.environ, {"NO_COLOR": "", "TERM": "xterm"}), \
             mock.patch.object(term, "_escapes", return_value=True):
            hints.hint("k", ["  one"], stream=tty)
        self.assertEqual(tty.getvalue(), "\033[2m  one\033[0m\n")

    def test_a_pipe_or_a_file_gets_nothing(self):
        out = io.StringIO()
        self.assertFalse(hints.hint("k", ["  one"], stream=out))
        self.assertEqual(out.getvalue(), "")
        # Not spent: the same process may still reach a terminal.
        self.assertTrue(hints.hint("k", ["  one"], stream=_Tty()))

    def test_never_with_json(self):
        tty = _Tty()
        self.assertFalse(hints.hint("k", ["  one"], stream=tty, json=True))
        self.assertEqual(tty.getvalue(), "")

    def test_ranwhat_no_hints_turns_them_off(self):
        for value, shown in (("1", False), ("yes", False), ("0", True), ("", True)):
            with self.subTest(value=value), mock.patch.dict(os.environ, {"RANWHAT_NO_HINTS": value}):
                hints.reset()
                tty = _Tty()
                self.assertEqual(hints.hint("k", ["  one"], stream=tty), shown)
                self.assertEqual(bool(tty.getvalue()), shown)

    def test_stderr_by_default(self):
        err = _Tty()
        with contextlib.redirect_stderr(err):
            hints.hint("k", ["  one"])
        self.assertEqual(err.getvalue(), "  one\n")

    def test_a_stream_that_fails_costs_nothing(self):
        self.assertFalse(hints.hint("k", ["  one"], stream=_Closed()))
        self.assertTrue(hints.hint("k", ["  one"], stream=_Broken()))

    def test_nothing_to_say_says_nothing(self):
        tty = _Tty()
        self.assertFalse(hints.hint("k", [], stream=tty))
        self.assertEqual(tty.getvalue(), "")


def _entry(authority="write"):
    return {"label": "X", "authority": authority, "reversible": False,
            "blast": "data_egress", "why": "because"}


class FeedHints(_Clean):
    """Wired to the feed, which is live today, and to nothing else."""

    # Two AWS actions the bundled catalogue does not have, one it does.
    UNRATED = ("dynamodb:PutItem", "kinesis:PutRecord")

    def _profile(self, scopes=(), *more):
        """AWS holding `scopes`, then each credential in `more` as given."""
        path = os.path.join(self.home, "profile.json")
        creds = [{"provider": "aws", "scopes": list(scopes)}] if scopes else []
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({"agent": "t", "credentials": creds + list(more)}, fh)
        return path

    def _run(self, argv, tty=True):
        out, err = io.StringIO(), (_Tty() if tty else io.StringIO())
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = cli.main(argv)
        self.assertEqual(rc, 0)
        return out.getvalue(), err.getvalue()

    def _cache(self, catalogue):
        feed.save({"schema": feed.SCHEMA, "version": "t", "catalogue": catalogue,
                   "digest": feed.digest(catalogue)})
        catalog.reset_feed_cache()

    def test_scan_says_how_many_scopes_the_bundle_could_not_rate(self):
        out, err = self._run(["scan", self._profile(self.UNRATED + ("s3:GetObject",))])
        said = " ".join(err.split())
        self.assertIn("These 2 scopes are not in the catalogue bundled with %s."
                      % ranwhat.__version__, said)
        # Where to get it: without a token, `update` stops at "No token".
        self.assertIn("The Plus feed adds new scopes between releases: "
                      "https://ranwhat.com/pricing", said)
        self.assertNotIn("update", said)
        self.assertNotIn("Plus feed", out)

    def test_one_scope_is_one_scope(self):
        _, err = self._run(["scan", self._profile(self.UNRATED[:1])])
        self.assertIn("This scope is not in the catalogue", " ".join(err.split()))

    def test_one_scope_held_twice_is_still_one_scope(self):
        # The finding lists it once per credential; the hint counts scopes.
        path = self._profile(self.UNRATED[:1], {
            "provider": "aws", "label": "second", "scopes": list(self.UNRATED[:1])})
        out, err = self._run(["scan", path])
        self.assertEqual(out.count(self.UNRATED[0]), 2)
        self.assertIn("This scope is not in the catalogue", " ".join(err.split()))

    def test_nothing_for_scopes_no_feed_rates(self):
        # No provider is "generic", which has no catalogue, and neither has
        # one ranwhat does not know. The report still flags their scopes.
        for cred in ({"scopes": ["widgets.manage"]},
                     {"provider": "generic", "scopes": ["widgets:frobnicate"]},
                     {"provider": "acmecorp", "scopes": ["frob", "billing:admin"]}):
            with self.subTest(cred=cred):
                hints.reset()
                out, err = self._run(["scan", self._profile((), cred)])
                self.assertIn("Unclassified permissions", out)
                self.assertEqual(err, "")

    def test_only_scopes_a_feed_rates_are_counted(self):
        path = self._profile(self.UNRATED[:1], {"scopes": ["widgets.manage"]},
                             {"provider": "acmecorp", "scopes": ["frob"]})
        _, err = self._run(["scan", path])
        self.assertIn("This scope is not in the catalogue", " ".join(err.split()))

    def test_the_report_itself_is_unchanged(self):
        path = self._profile(self.UNRATED)
        with_hint, _ = self._run(["scan", path])
        hints.reset()
        without, err = self._run(["scan", path], tty=False)
        self.assertEqual(with_hint, without)
        self.assertEqual(err, "")

    def test_live_gets_it_too(self):
        cred = {"provider": "github", "label": "synthetic",
                "scopes": ["repo", "manage:widgets"], "scopes_used": None}
        with mock.patch.dict(cli.introspect.PROVIDERS,
                             {"github": lambda token: cred}, clear=True), \
             mock.patch.dict(os.environ, {"RANWHAT_GITHUB_TOKEN": "synthetic"}):
            _, err = self._run(["live"])
        self.assertIn("This scope is not in the catalogue bundled", " ".join(err.split()))

    def test_nothing_when_every_scope_is_rated(self):
        _, err = self._run(["scan", self._profile(["s3:GetObject"])])
        self.assertEqual(err, "")

    def test_never_under_demo(self):
        out, err = self._run(["demo"])
        self.assertIn("Unclassified permissions", out)    # the example has one
        self.assertEqual(err, "")

    def test_never_with_json(self):
        out, err = self._run(["scan", self._profile(self.UNRATED), "--json"])
        self.assertEqual(err, "")
        json.loads(out)

    def test_not_for_someone_with_a_token(self):
        path = self._profile(self.UNRATED)
        with mock.patch.dict(os.environ, {"RANWHAT_TOKEN": "t"}):
            self.assertEqual(self._run(["scan", path])[1], "")
        feed.save_token("t")
        self.assertEqual(self._run(["scan", path])[1], "")

    def test_a_token_file_that_cannot_be_read_costs_nothing(self):
        os.makedirs(self.home, exist_ok=True)
        with open(feed.token_path(), "wb") as fh:
            fh.write(b"\xff\xfe not utf-8")
        self.assertEqual(self._run(["scan", self._profile(self.UNRATED)])[1], "")
        self.assertEqual(self._run(["update", "--status"])[1], "")

    def test_not_for_a_feed_ahead_of_the_release(self):
        path = self._profile(self.UNRATED)
        self._cache({"aws": {"sqs:SendMessage": _entry()}})
        self.assertEqual(self._run(["scan", path])[1], "")

    def test_a_feed_no_newer_than_the_release_still_gets_it(self):
        # A cache from an older release, or this one's: nothing in it the
        # bundle lacks, so the feed has not been read since it moved on.
        self._cache({"aws": {"s3:GetObject": catalog.CATALOG["aws"]["s3:GetObject"]}})
        _, err = self._run(["scan", self._profile(self.UNRATED)])
        self.assertIn("These 2 scopes", " ".join(err.split()))

    def test_update_status_without_a_feed_names_the_bundled_catalogue(self):
        out, err = self._run(["update", "--status"])
        # The fact on stdout, for any reader, and Plus said once, in the hint.
        self.assertEqual(out, "  No feed cached. The catalogue bundled with %s "
                              "is in use.\n" % ranwhat.__version__)
        said = " ".join(err.split())
        self.assertIn("Plus gets new scopes the day they are added; the next "
                      "free release gets them too: https://ranwhat.com/pricing", said)

    def test_update_status_says_nothing_more_with_json_a_token_or_a_feed(self):
        self.assertEqual(self._run(["update", "--status", "--json"])[1], "")
        with mock.patch.dict(os.environ, {"RANWHAT_TOKEN": "t"}):
            self.assertEqual(self._run(["update", "--status"])[1], "")
        self._cache({"aws": {"sqs:SendMessage": _entry()}})
        out, err = self._run(["update", "--status"])
        self.assertIn("Feed t", out)
        self.assertEqual(err, "")

    def test_ranwhat_no_hints(self):
        with mock.patch.dict(os.environ, {"RANWHAT_NO_HINTS": "1"}):
            self.assertEqual(self._run(["scan", self._profile(self.UNRATED)])[1], "")
            self.assertEqual(self._run(["update", "--status"])[1], "")


if __name__ == "__main__":
    unittest.main()
