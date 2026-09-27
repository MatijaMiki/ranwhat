"""Regression tests for bugs found in the pre-release review.

Each of these was a real defect. Several were of the class this tool exists
to avoid: producing a confident answer with nothing behind it.
"""
import os
import sqlite3
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ranwhat import watch
from ranwhat.html_report import write_html
from ranwhat.score import ProfileError, scan


class RemediationIsVisible(unittest.TestCase):
    """The score must keep moving as permissions are dropped.

    A linear 100-minus-penalty hit zero at ~17 write scopes, so a customer who
    removed 40 permissions saw 0 both times and concluded the tool was broken.
    The scan/remediate/re-scan loop is the product; the curve has to move.
    """

    def _score(self, n):
        return scan({"agent": "t", "credentials": [
            {"provider": "g", "scopes": ["s%d:write" % i for i in range(n)]}],
            "controls": {}})["scores"]["authority"]

    def test_strictly_decreasing_and_never_pinned_at_zero(self):
        counts = [0, 5, 10, 20, 40, 80, 160]
        scores = [self._score(n) for n in counts]
        for a, b in zip(scores, scores[1:]):
            self.assertGreater(a, b, "score must fall as scopes are added: %s" % scores)
        self.assertGreater(scores[-1], 0, "160 scopes should still be distinguishable")

    def test_dropping_permissions_raises_the_score(self):
        self.assertGreater(self._score(10), self._score(30))


class MalformedProfilesAreRejected(unittest.TestCase):
    """Silently scoring a bad shape is worse than refusing it."""

    def test_scopes_as_a_bare_string(self):
        """"s3:*" iterates as four characters and yields a confident, wrong
        report of four permissions."""
        with self.assertRaises(ProfileError) as ctx:
            scan({"credentials": [{"provider": "aws", "scopes": "s3:*"}]})
        self.assertIn("list of strings", str(ctx.exception))

    def test_credentials_not_a_list(self):
        with self.assertRaises(ProfileError):
            scan({"credentials": {"a": 1}})

    def test_non_string_scope(self):
        with self.assertRaises(ProfileError):
            scan({"credentials": [{"provider": "aws", "scopes": [123]}]})

    def test_non_numeric_controls(self):
        with self.assertRaises(ProfileError):
            scan({"credentials": [], "controls": {"spend_cap_usd": "1000"}})
        with self.assertRaises(ProfileError):
            scan({"credentials": [], "controls": {"trace_retention_days": "90"}})

    def test_unknown_approval_mode(self):
        with self.assertRaises(ProfileError):
            scan({"credentials": [], "controls": {"human_approval": "maybe"}})

    def test_valid_profile_still_scores(self):
        r = scan({"credentials": [{"provider": "stripe",
                                   "scopes": ["refunds:write"]}],
                  "controls": {"spend_cap_usd": 0}})
        self.assertIn("$0 per action", r["blast_radius"]["monetary"])


class WatcherInputShapes(unittest.TestCase):

    def test_command_as_argv_list(self):
        """Some agents pass argv arrays rather than a shell string."""
        hits, _ = watch.evaluate("Bash", {"command": ["rm", "-rf", "~/archive"]})
        self.assertTrue(hits)

    def test_command_of_unexpected_type_does_not_raise(self):
        self.assertEqual(watch.evaluate("Bash", {"command": 42})[0], [])
        self.assertEqual(watch.evaluate("Bash", {"command": None})[0], [])

    def test_oversized_input_is_bounded(self):
        watch.evaluate("Bash", {"command": "echo " + "a" * 500000})


class OneBadFileDoesNotStopTheScan(unittest.TestCase):

    def _state_dir(self, text):
        root = tempfile.mkdtemp(prefix="oc-rb-")
        path = os.path.join(root, "agents", "a", "agent", "openclaw-agent.sqlite")
        os.makedirs(os.path.dirname(path))
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
        return root

    def _scan(self, root):
        # The warning is the behaviour under test, so it is captured and
        # checked rather than left to print over the suite's output.
        import contextlib
        import io
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            records, scanned = watch.scan_openclaw(state_dir=root)
        self.assertIn("warning: cannot read", err.getvalue())
        self.assertIn("file is not a database", err.getvalue())
        return records, scanned

    def test_corrupt_database_is_skipped_not_fatal(self):
        """sqlite3.connect is lazy, so a non-database only fails on first
        query -- which used to happen outside any handler."""
        root = self._state_dir("this is not a database")
        records, scanned = self._scan(root)
        self.assertEqual(records, [])
        self.assertEqual(scanned, 1)

    def test_good_database_beside_a_corrupt_one_still_reports(self):
        import json
        root = self._state_dir("garbage")
        good = os.path.join(root, "agents", "b", "agent", "openclaw-agent.sqlite")
        os.makedirs(os.path.dirname(good))
        conn = sqlite3.connect(good)
        conn.execute("CREATE TABLE t (body TEXT)")
        conn.execute("INSERT INTO t VALUES (?)", (json.dumps(
            {"name": "bash", "input": {"command": "rm -rf ~/gone"}}),))
        conn.commit()
        conn.close()
        records, scanned = self._scan(root)
        self.assertEqual(scanned, 2)
        self.assertEqual(len(records), 1, "the readable database must still report")


class OutputErrors(unittest.TestCase):

    def test_unwritable_html_path_is_a_message_not_a_traceback(self):
        result = scan({"agent": "t", "credentials": [], "controls": {}})
        with self.assertRaises(SystemExit):
            write_html(result, "/nonexistent-dir-xyz/out.html")


if __name__ == "__main__":
    unittest.main(verbosity=2)
