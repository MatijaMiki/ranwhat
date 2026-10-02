"""Security regressions.

Threat model: this runs on a developer's machine, reads agent transcripts
whose contents an attacker may be able to influence through the agent, and
is handed live credentials. Each test here corresponds to a real finding.
"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import growth  # noqa: E402
import isolated_home  # noqa: E402,F401  ranwhat's state, never ~/.ranwhat
from ranwhat import watch  # noqa: E402
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


class UntrustedTranscriptContent(growth.Assertions, unittest.TestCase):
    """Transcript contents are attacker-influenceable: anything that reaches
    an agent's context can end up in the text these patterns run against."""

    def test_no_catastrophic_backtracking(self):
        payloads = [
            lambda n: "<<'A'\n" + "x" * n(5000) + "\n" + "rm " + " -r" * n(400),
            lambda n: "rm -rf " + " ".join("f%d" % i for i in range(n(20000))),
            lambda n: " ; ".join(["rm -rf ~/x"] * n(5000)),
            lambda n: 'bash -c "' * n(200) + "rm -rf /" + '"' * n(200),
            lambda n: "rm " + "-" * n(50000) + " x",
            lambda n: "<<'E'\nx\nE\n" * n(3000),
        ]
        for build in payloads:
            self.assertScalesLinearly(
                build, lambda payload: watch.evaluate("Bash", {"command": payload}),
                "possible ReDoS on %r" % build(growth.sized(1))[:40])

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


class ALineBreakInsideATokenIsNeverQuoted(unittest.TestCase):
    """Stripping takes a \\r off the ends only. A token with a line break
    inside it, a CRLF file with a second line read with $(cat file), still
    reached http.client, whose ValueError quotes the whole header, and
    _request passed str(e) on to stderr: the token, in the error. live and
    --pull-usage talk to GitHub, Slack, Stripe and Google this way."""

    # Not real credentials. Split so no scanner reads them as one.
    HEAD = "ghp_" "FAKEFAKEFAKE1234"
    TAIL = "SECONDLINE" "FAKE"
    STRIPE = "rk_" "test_" "FAKEFAKEFAKE5678"

    def setUp(self):
        from unittest import mock
        self.sent = []
        patch = mock.patch("urllib.request.urlopen", self._urlopen)
        patch.start()
        self.addCleanup(patch.stop)

    def _urlopen(self, req, *a, **kw):
        # http.client's own header check, run for real: putheader refuses the
        # value, quoting it, before anything connects.
        import http.client
        import urllib.error
        conn = http.client.HTTPConnection("127.0.0.1")
        try:
            conn.putrequest(req.get_method(), req.selector)
            for k, v in req.header_items():
                conn.putheader(k, v)
        finally:
            conn.close()
        self.sent.append(dict(req.header_items()))
        raise urllib.error.URLError("offline")

    def _tmp(self):
        import shutil
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        return d

    def _run(self, argv, tokens):
        import contextlib
        import io
        from unittest import mock
        from ranwhat import cli
        env = {k: v for k, v in os.environ.items() if not k.startswith("RANWHAT_")}
        env.update(tokens)
        env["RANWHAT_HOME"] = self._tmp()
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.dict(os.environ, env, clear=True), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = cli.main(argv)
        return rc, out.getvalue() + err.getvalue()

    def _assert_not_quoted(self, text, *parts):
        for part in parts:
            self.assertNotIn(part, text)

    def test_live_refuses_it_unsent_and_does_not_quote_it(self):
        for provider in ("github", "slack"):
            for brk in ("\n", "\r\n", "\r"):
                with self.subTest(provider=provider, brk=brk):
                    rc, text = self._run(["live"], {
                        "RANWHAT_%s_TOKEN" % provider.upper():
                            self.HEAD + brk + self.TAIL})
                    self.assertEqual(rc, 1)
                    self.assertIn("line break", text)
                    self._assert_not_quoted(text, self.HEAD, self.TAIL)
                    self.assertEqual(self.sent, [])

    def test_pull_usage_refuses_it_unsent_and_does_not_quote_it(self):
        import json
        path = os.path.join(self._tmp(), "profile.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({"agent": "t", "controls": {}, "credentials": [
                {"provider": "stripe", "scopes": ["charges:write"]}]}, fh)
        rc, text = self._run(["scan", path, "--pull-usage"], {
            "RANWHAT_STRIPE_TOKEN": self.STRIPE + "\r\n# note"})
        self.assertEqual(rc, 0, text)
        self.assertIn("usage: stripe   unavailable", text)
        self._assert_not_quoted(text, self.STRIPE, "# note")
        self.assertEqual(self.sent, [])

    def test_a_clean_token_is_still_sent_as_it_is(self):
        from ranwhat import introspect
        with self.assertRaises(introspect.IntrospectionError):
            introspect.github(self.HEAD)
        self.assertEqual(self.sent[0]["Authorization"], "Bearer " + self.HEAD)

    def test_a_header_refused_anyway_is_not_quoted(self):
        """Whatever else http.client refuses, its message quotes the value."""
        from unittest import mock
        from ranwhat import introspect

        def refuse(req, *a, **kw):
            raise ValueError("Invalid header value %r"
                             % req.get_header("Authorization"))
        with mock.patch("urllib.request.urlopen", refuse):
            with self.assertRaises(introspect.IntrospectionError) as caught:
                introspect.github(self.HEAD)
        self._assert_not_quoted(str(caught.exception), self.HEAD)
        self.assertTrue(caught.exception.__suppress_context__)


if __name__ == "__main__":
    unittest.main(verbosity=2)
