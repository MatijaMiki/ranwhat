"""Security regressions.

Threat model: this runs on a developer's machine, reads agent transcripts
whose contents an attacker may be able to influence through the agent, and
is handed live credentials. Each test here corresponds to a real finding.
"""
import os
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ranwhat import watch
from ranwhat.html_report import write_html
from ranwhat.score import scan


def _result():
    return scan({"agent": "t", "credentials": [
        {"provider": "aws", "scopes": ["s3:*"]}], "controls": {}})


class ReportsAreNotWorldReadable(unittest.TestCase):
    """A report maps an agent's entire authority surface: which permissions
    exist, which go unused, what the blast radius is. That is useful to an
    attacker, so it does not get mode 644."""

    @unittest.skipIf(os.name == "nt", "Windows has no owner-only mode bits")
    def test_written_owner_only(self):
        path = os.path.join(tempfile.mkdtemp(), "r.html")
        write_html(_result(), path)
        self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)

    @unittest.skipIf(os.name == "nt", "no O_NOFOLLOW on Windows")
    def test_refuses_to_write_through_a_symlink(self):
        d = tempfile.mkdtemp()
        target = os.path.join(d, "target.txt")
        link = os.path.join(d, "report.html")
        with open(target, "w", encoding="utf-8") as fh:
            fh.write("PROTECTED")
        os.symlink(target, link)
        with self.assertRaises(SystemExit):
            write_html(_result(), link)
        with open(target, encoding="utf-8") as fh:
            self.assertEqual(fh.read(), "PROTECTED")


class CredentialsNeedNotTouchArgv(unittest.TestCase):
    """Anything in argv is readable by every user on the machine through the
    process table, and is written to shell history besides."""

    class _Args(object):
        stripe = None

    def test_environment_variable_is_used(self):
        from ranwhat.cli import _token
        os.environ["RANWHAT_STRIPE_TOKEN"] = "from-env"
        try:
            self.assertEqual(_token(self._Args(), "stripe"), "from-env")
        finally:
            os.environ.pop("RANWHAT_STRIPE_TOKEN", None)

    def test_env_indirection_form(self):
        from ranwhat.cli import _token
        args = self._Args()
        args.stripe = "env:MY_SECRET_VAR"
        os.environ["MY_SECRET_VAR"] = "indirect"
        try:
            self.assertEqual(_token(args, "stripe"), "indirect")
        finally:
            os.environ.pop("MY_SECRET_VAR", None)

    def test_missing_indirect_variable_fails_loudly(self):
        from ranwhat.cli import _token
        args = self._Args()
        args.stripe = "env:DEFINITELY_NOT_SET_XYZ"
        with self.assertRaises(SystemExit):
            _token(args, "stripe")


class UntrustedTranscriptContent(unittest.TestCase):
    """Transcript contents are attacker-influenceable: anything that reaches
    an agent's context can end up in the text these patterns run against."""

    def test_no_catastrophic_backtracking(self):
        payloads = [
            "<<'A'\n" + "x" * 5000 + "\n" + "rm " + " -r" * 400,
            "rm -rf " + " ".join("f%d" % i for i in range(20000)),
            " ; ".join(["rm -rf ~/x"] * 5000),
            'bash -c "' * 200 + "rm -rf /" + '"' * 200,
            "rm " + "-" * 50000 + " x",
            "<<'E'\nx\nE\n" * 3000,
        ]
        for payload in payloads:
            start = time.time()
            watch.evaluate("Bash", {"command": payload})
            self.assertLess(time.time() - start, 5.0,
                            "possible ReDoS on %r" % payload[:40])

    def test_input_is_bounded(self):
        watch.evaluate("Bash", {"command": "echo " + "a" * 500_000})

    def test_deeply_nested_json_does_not_recurse_away(self):
        obj = {"a": 1}
        for _ in range(500):
            obj = {"n": obj}
        watch._find_tool_calls(obj)


class SqlIdentifiersAreEscapedNotStripped(unittest.TestCase):

    def test_quoted_table_name_is_read_and_not_executed(self):
        """Stripping quotes was safe but silently wrong -- the table became a
        name that does not exist and its rows were skipped in silence."""
        import json
        import sqlite3
        root = tempfile.mkdtemp()
        path = os.path.join(root, "agents", "a", "agent", "openclaw-agent.sqlite")
        os.makedirs(os.path.dirname(path))
        evil = 'x" ; DROP TABLE canary ; --'
        conn = sqlite3.connect(path)
        conn.execute("CREATE TABLE canary (x TEXT)")
        conn.execute('CREATE TABLE "%s" (body TEXT)' % evil.replace('"', '""'))
        conn.execute('INSERT INTO "%s" VALUES (?)' % evil.replace('"', '""'),
                     (json.dumps({"name": "bash",
                                  "input": {"command": "rm -rf ~/x"}}),))
        conn.commit()
        conn.close()

        records, _ = watch.scan_openclaw(state_dir=root)

        conn = sqlite3.connect(path)
        survived = [r for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE name='canary'")]
        conn.close()
        self.assertTrue(survived, "injection executed")
        self.assertEqual(len(records), 1, "rows were silently skipped")


class TempCopiesAreCleanedUp(unittest.TestCase):

    def test_no_temp_directories_left_behind(self):
        import json
        import sqlite3
        root = tempfile.mkdtemp()
        path = os.path.join(root, "agents", "a", "agent", "openclaw-agent.sqlite")
        os.makedirs(os.path.dirname(path))
        conn = sqlite3.connect(path)
        conn.execute("CREATE TABLE t (b TEXT)")
        conn.execute("INSERT INTO t VALUES (?)", (json.dumps(
            {"name": "bash", "input": {"command": "cat ~/.ssh/id_rsa"}}),))
        conn.commit()
        conn.close()

        before = set(os.listdir(tempfile.gettempdir()))
        watch.scan_openclaw(state_dir=root)
        after = set(os.listdir(tempfile.gettempdir()))
        self.assertFalse([x for x in after - before if x.startswith("ranwhat-")])



class TokensAreStrippedWhereverTheyComeFrom(unittest.TestCase):
    """A trailing \r from a CRLF .env made http.client quote the whole
    Authorization header, token included, into the printed error."""

    def _resolve(self, flag, env):
        from types import SimpleNamespace
        from unittest import mock
        from ranwhat.cli import _token
        with mock.patch.dict(os.environ, env, clear=False):
            return _token(SimpleNamespace(github=flag), "github")

    def test_environment_variable(self):
        self.assertEqual(self._resolve(None, {"RANWHAT_GITHUB_TOKEN": "ghp_x\r\n"}),
                         "ghp_x")

    def test_env_prefix(self):
        self.assertEqual(self._resolve("env:MY_TOK", {"MY_TOK": " ghp_y\r"}), "ghp_y")

    def test_blank_is_no_token(self):
        self.assertIsNone(self._resolve(None, {"RANWHAT_GITHUB_TOKEN": "\r\n"}))


if __name__ == "__main__":
    unittest.main(verbosity=2)
