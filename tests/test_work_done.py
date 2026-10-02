"""Work the commands do, counted rather than timed.

The release bar is main's speed on the same input. Each case here was
work main did not do, or did once where this did it again and again:
asking the terminal about colour for every line of a report, importing
the network stack for commands that never use it, and reading a value
as a call before asking whether it could be a secret at all.
"""
import io
import os
import random
import re
import shutil
import subprocess
import tempfile
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import isolated_home  # noqa: E402,F401  ranwhat's state, never ~/.ranwhat
from ranwhat import clean, introspect, term, watch

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _finding(i):
    return {"fingerprint": "%012x" % i, "label": "DB_PASSWORD", "length": 20,
            "hint": "Ab…%02d" % (i % 100), "files": {"/x/s.jsonl"},
            "origins": {"api/.env"}, "projects": {"/x"}, "count": 1}


class _Terminal(io.StringIO):
    def isatty(self):
        return True


class AReportAsksAboutColourOnce(unittest.TestCase):
    """A report asks term about colour once, whatever the answer. painters()
    kept the answer only when it was no: on a terminal each painted piece
    asked again, 6,015 times for clean's report of a thousand findings and
    5,008 for watch's. Every CI runner but Windows's, whose stdout is a
    console, had answered no, so each render is drawn both ways here."""

    def render(self, draw, terminal):
        counted = mock.Mock(wraps=term._colour_depth)
        stdout = _Terminal() if terminal else io.StringIO()
        with mock.patch.object(term, "_colour_depth", counted), \
             mock.patch.dict(os.environ, {"TERM": "xterm"}), \
             mock.patch("sys.stdout", stdout):
            os.environ.pop("NO_COLOR", None)
            text = draw()
        # Asked, and answered as this stream would be.
        self.assertEqual("\033[" in text, terminal)
        return counted.call_count

    def test_clean_render(self):
        findings = {f["fingerprint"]: f for f in map(_finding, range(1000))}
        for terminal in (True, False):
            with self.subTest(terminal=terminal):
                self.assertLess(self.render(
                    lambda: clean.render(findings, 3, 0, False), terminal), 10)

    def test_watch_render(self):
        records = [{"source": "claude-code", "session": "s", "project": "-x",
                    "timestamp": "2026-10-01T10:00:00Z", "tool_name": "Bash",
                    "severity": watch.CRITICAL,
                    "hits": [{"rule": "fs.destructive", "severity": watch.CRITICAL,
                              "title": "Destructive filesystem operation",
                              "why": "Deletes files.",
                              "evidence": "rm -rf ~/Documents/p%d" % i}]}
                   for i in range(1000)]
        for terminal in (True, False):
            with self.subTest(terminal=terminal):
                self.assertLess(self.render(
                    lambda: watch.render(records, 1, 30), terminal), 10)


class AShapeIsLookedForOnlyWhereItsMarkIs(unittest.TestCase):
    """Each of sixteen shapes was searched for in every string worth
    scanning, a regex pass each: most of what watch spent masking a
    command, which main did a tenth as often."""

    def test_text_without_a_mark_is_not_searched(self):
        counting = [(mock.Mock(wraps=shape), name) for shape, name in clean._SHAPES_NAMED]
        with mock.patch.object(clean, "_SHAPES_NAMED", counting):
            clean.find_secrets("mysql -u root -pHq7xT2mVp9LwZr4kNd -e 'DROP DATABASE prod'")
        self.assertEqual([name for shape, name in counting
                          if shape.finditer.call_count or shape.search.call_count], [])

    def test_a_shape_is_still_found(self):
        key = "AKIA" + "Q7ZK2WPX4TRUE9KM"
        self.assertEqual(clean.find_secrets("export X=1 && echo " + key),
                         [(key, "AWS access key ID")])


class ACommandIsScannedOnce(unittest.TestCase):

    def test_evaluate(self):
        """The rules, the evidence and the payload each asked clean about
        the same command, and the payload's answer was never kept."""
        command = "mysql -u root -pHq7xT2mVp9LwZr4kNd -e 'DROP DATABASE prod'"
        watch._secret_spans.cache_clear()
        counted = mock.Mock(wraps=clean._scan)
        with mock.patch.object(clean, "_scan", counted):
            hits, payload = watch.evaluate("Bash", {"command": command})
        self.assertTrue(hits)
        self.assertNotIn("Hq7xT2mVp9LwZr4kNd", payload)
        self.assertEqual([c for c in counted.call_args_list if c[0][0] == command],
                         [mock.call(command)])


class RenderingRedoesNothing(unittest.TestCase):
    """watch's report masked each hit's evidence a third time, measured
    the terminal for each hit's why, and parsed each action's time three
    times over."""

    def test_watch_render(self):
        records = []
        for i in range(300):
            hits, _payload = watch.evaluate("Bash", {
                "command": "mysql -u root -pHq7xT2mVp9LwZr4kNd -e 'DROP TABLE t%d'" % i})
            records.append({"source": "claude-code", "session": "s", "project": "-x",
                            "timestamp": "2026-10-01T10:%02d:00Z" % (i % 60),
                            "tool_name": "Bash", "severity": watch.CRITICAL, "hits": hits})
        scans = mock.Mock(wraps=clean._scan)
        widths = mock.Mock(wraps=term.width)
        with mock.patch.object(clean, "_scan", scans), \
             mock.patch.object(term, "width", widths):
            out = watch.render(records, 1, 30)
        self.assertNotIn("Hq7xT2mVp9LwZr4kNd", out)
        self.assertIn("DROP TABLE t299", out)
        self.assertEqual(scans.call_count, 0)
        self.assertLess(widths.call_count, 10)

    def test_evidence_from_elsewhere_is_still_masked(self):
        record = {"source": "claude-code", "session": "s", "project": "-x",
                  "timestamp": "2026-10-01T10:00:00Z", "tool_name": "Bash",
                  "severity": watch.CRITICAL,
                  "hits": [{"rule": "cloud.destructive", "severity": watch.CRITICAL,
                            "title": "Cloud resource destroyed or modified", "why": "x",
                            "evidence": "DB_PASSWORD=Hq7xT2mVp9LwZr4kNd mysql -e 'DROP TABLE t'"}]}
        self.assertNotIn("Hq7xT2mVp9LwZr4kNd", watch.render([record], 1, 30))


class CommandsAreSplitAsBefore(unittest.TestCase):
    """The splitter now skips in C to where a match can start. It must split
    every command where the one it replaced did."""

    BEFORE = re.compile(
        r"""\$'(?:[^'\\]|\\[\s\S])*(?P<aq>')?|'[^']*(?P<sq>')?"""
        r"""|"(?:[^"\\]|\\[\s\S])*(?P<dq>")?|\\[\s\S]?"""
        r"""|(?<![^ \t\n;&|(])#[^\n]*"""
        r"""|(?P<op>(?:(?!\s)|(?<!\s))\s*(?:\|\||&&|;|\|&|(?<!>)\||\n)\s*)""")

    def test_the_same_spans_and_groups(self):
        rng = random.Random(20261002)
        alphabet = " \t\n;&|>#'\"$\\a(b)\r"
        for _ in range(60000):
            text = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 16)))
            with self.subTest(text=text):
                self.assertEqual(
                    [(m.span(), m.groupdict()) for m in watch._HIDING_OR_SEPARATOR.finditer(text)],
                    [(m.span(), m.groupdict()) for m in self.BEFORE.finditer(text)])


def _transcript(test, lines):
    import json
    root = tempfile.mkdtemp(prefix="work-")
    test.addCleanup(shutil.rmtree, root, True)
    path = os.path.join(root, "s.jsonl")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("".join(json.dumps(line) + "\n" for line in lines))
    return path


def _result(text):
    return {"type": "user", "message": {"content": [
        {"type": "tool_result", "tool_use_id": "t", "content": text}]}}


def _key_ids(n):
    rng = random.Random(20261002)
    return ["AKIA" + "".join(rng.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
                             for _ in range(15)) + "7" for _i in range(n)]


class ShapesAreNotCountedAgain(unittest.TestCase):
    """Each value a transcript holds was counted in all of it, a pass each,
    to find copies the rules did not. A shape is found wherever it is
    copied, by the rules themselves, so it needs no pass of its own, but
    where a string was too long to be read whole."""

    KEYS = _key_ids(300)

    def _asked(self, path):
        asked = []
        real = clean._copies_elsewhere

        def spy(texts, owners, size, values, found):
            asked.extend(values)
            return real(texts, owners, size, values, found)
        with mock.patch.object(clean, "_copies_elsewhere", spy):
            findings, _changed = clean.scan_file(path)
        return findings, asked

    def test_no_pass_for_a_shape(self):
        path = _transcript(self, [_result("".join("AWS_ACCESS_KEY_ID=%s\n" % k
                                                  for k in self.KEYS)),
                                  _result("again " + " ".join(self.KEYS[:5]))])
        findings, asked = self._asked(path)
        self.assertEqual(len(findings), 300)
        self.assertEqual(asked, [])
        self.assertEqual(sorted(f["count"] for f in findings.values())[-5:], [2] * 5)

    def test_a_string_too_long_to_read_whole_is_still_searched(self):
        key = self.KEYS[0]
        path = _transcript(self, [_result("AWS_ACCESS_KEY_ID=%s\n" % key),
                                  _result("x" * (clean.MAX_STRING + 10) + " " + key)])
        findings, asked = self._asked(path)
        (finding,) = findings.values()
        self.assertEqual(asked, [clean._fingerprint(key)])
        self.assertEqual(finding["count"], 2)


class ACallNamingNoFileIsNotWrittenOut(unittest.TestCase):

    def test_named_by_call(self):
        counted = mock.Mock(wraps=clean._origins)
        with mock.patch.object(clean, "_origins", counted):
            self.assertEqual(clean._named_by_call(
                {"input": {"command": "ls -la src", "timeout": 5}}), [])
            self.assertEqual(counted.call_count, 0)
            self.assertEqual(clean._named_by_call(
                {"input": {"command": "cat api/.env", "description": "x"}}), ["api/.env"])
            self.assertEqual(clean._named_by_call(
                {"input": {"file_path": "/a/b/.env.local"}}), ["/a/b/.env.local"])
            self.assertEqual(clean._named_by_call(
                {"input": {"edits": [{"file_path": "/a/b/.env"}]}}), ["/a/b/.env"])


class EvidenceShownWholeIsNotScannedAgain(unittest.TestCase):

    def test_a_short_command(self):
        command = "rm -rf ~/Documents/old-project"
        watch._secret_spans.cache_clear()
        counted = mock.Mock(wraps=clean._scan)
        with mock.patch.object(clean, "_scan", counted):
            hits, _payload = watch.evaluate("Bash", {"command": command})
        self.assertEqual(hits[0]["evidence"], command)
        self.assertEqual(counted.call_count, 1)

    def test_what_a_hint_stands_apart_from_is_still_read(self):
        """Once a value is masked, a second look reads what its hint now
        stands apart from: curl glued to a key ID is curl after the hint."""
        command = "AKIA" "Q7ZK2WPX4TRUE9KMcurl -u admin:Zq7KpWxVbNmTrLs9 -X DELETE https://h"
        hits, _payload = watch.evaluate("Bash", {"command": command})
        self.assertTrue(hits)
        for hit in hits:
            self.assertNotIn("Zq7KpWxVbNmTrLs9", hit["evidence"])

    def test_a_window_is_still_masked(self):
        command = "echo start && rm -rf /srv/" + "x" * 120 + " TOKEN=Hq7xT2mVp9LwZr4kNd"
        hits, _payload = watch.evaluate("Bash", {"command": command})
        self.assertTrue(hits)
        for hit in hits:
            self.assertNotIn("Hq7xT2mVp9LwZr4kNd", hit["evidence"])


class ReadingCommandsImportNoNetwork(unittest.TestCase):

    def test_check_watch_and_clean_import_no_network_module(self):
        code = ("import sys, io, contextlib\n"
                "from ranwhat import cli\n"
                "with contextlib.redirect_stdout(io.StringIO()):\n"
                "    for argv in (['watch'], ['clean', '--no-interactive'], ['check']):\n"
                "        try:\n"
                "            cli.main(argv + ['--root', sys.argv[1], '--state-dir', sys.argv[1]])\n"
                "        except SystemExit:\n"
                "            pass\n"
                "print(sorted(m for m in ('urllib.request', 'http.client', 'ssl',\n"
                "                         'ranwhat.introspect', 'ranwhat.feed') if m in sys.modules))\n")
        empty = os.path.join(ROOT, "tests")
        env = dict(os.environ, PYTHONPATH=ROOT, NO_COLOR="1")
        out = subprocess.run([sys.executable, "-c", code, os.path.join(empty, "no-such-root")],
                             capture_output=True, text=True, encoding="utf-8",
                             env=env, timeout=60).stdout
        self.assertEqual(out.strip(), "[]")

    def test_every_provider_has_its_flag(self):
        from ranwhat import cli, usage
        self.assertEqual(set(cli._PROVIDER_NAMES), set(introspect.PROVIDERS))
        self.assertEqual(cli._DEFAULT_WINDOW_DAYS, usage.DEFAULT_WINDOW_DAYS)


class AValueIsAskedTheCheapestQuestionFirst(unittest.TestCase):
    """A megabyte of near-miss calls, f((a+(a+...(a+#, cost a call's
    reading for each value; none of them could be a secret."""

    def test_no_call_is_read_in_a_value_that_could_not_be_a_secret(self):
        text = ("token=f(" + "(a+" * 166 + "# ") * 100
        counted = mock.Mock(wraps=clean._is_call_expression)
        with mock.patch.object(clean, "_is_call_expression", counted):
            self.assertEqual(clean.find_secrets(text), [])
        self.assertEqual(counted.call_count, 0)

    def test_a_reference_is_known_at_once(self):
        """An App Service reference was read as a call and as a phrase
        before what it starts with said it was a reference."""
        counted = mock.Mock(wraps=clean._is_call_expression)
        phrases = mock.Mock(wraps=clean._placeholder_phrase)
        with mock.patch.object(clean, "_is_call_expression", counted), \
             mock.patch.object(clean, "_placeholder_phrase", phrases):
            self.assertTrue(clean._is_placeholder(
                "@Microsoft.KeyVault(SecretUri=https://kv.vault.azure.net/secrets/Xk9mPq2v/)"))
        self.assertEqual((counted.call_count, phrases.call_count), (0, 0))

    def test_a_call_is_still_code(self):
        for text in ("token=hashlib.sha256(data+salt).hexdigest()",
                     "t.accessToken=o(e.code+t);return t"):
            with self.subTest(text=text):
                self.assertEqual(clean.find_secrets(text + " " * 20), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
