"""Every text file the tool reads or writes is UTF-8, whatever the locale.

The first Windows CI run showed the encoding left to the locale, which
there is cp1252. clean --apply would read a UTF-8 transcript as cp1252 and
write the result back, and the HTML report declared utf-8 without being
it. A descriptor from os.open is in text mode there too, so a backup
would gain a \\r on every line. None of it shows on a Mac or Linux, where
the locale is UTF-8 anyway.

So the file handling runs here under a locale that is not UTF-8, on any
platform, and the source is checked for text opens that name no encoding.

Every value here is synthetic.
"""
import ast
import glob
import json
import os
import subprocess
import sys
import tempfile
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

from ranwhat import cli
from ranwhat.clean import REDACTION

# (default mode, index of the mode argument) for each call that opens a file
OPENERS = {"open": ("r", 1), "fdopen": ("r", 1),
           "NamedTemporaryFile": ("w+b", 0), "TemporaryFile": ("w+b", 0)}


def _unnamed_encodings(path):
    """Line numbers of text-mode opens in `path` that leave the encoding to
    the locale. `x.open(...)` is not checked: in this code it is urllib's
    opener, or a Path opened in binary."""
    with open(path, encoding="utf-8") as fh:
        tree = ast.parse(fh.read(), path)
    lines = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Name) and func.id == "open":
            name = "open"
        elif isinstance(func, ast.Attribute) and func.attr != "open":
            name = func.attr
        else:
            continue
        keywords = {k.arg: k.value for k in node.keywords}
        if "encoding" in keywords:
            continue
        if name in ("read_text", "write_text"):
            lines.append(node.lineno)
            continue
        if name not in OPENERS:
            continue
        default, index = OPENERS[name]
        mode = keywords.get("mode")
        if mode is None and len(node.args) > index:
            mode = node.args[index]
        if mode is None:
            mode = ast.Constant(default)
        if not (isinstance(mode, ast.Constant) and isinstance(mode.value, str)
                and "b" in mode.value):
            lines.append(node.lineno)
    return sorted(lines)


class EveryTextOpenNamesItsEncoding(unittest.TestCase):

    def test_package_scripts_and_tests(self):
        paths = []
        for part in ("ranwhat", "scripts", "tests"):
            paths += sorted(glob.glob(os.path.join(REPO, part, "*.py")))
        self.assertGreater(len(paths), 20)
        found = {}
        for path in paths:
            lines = _unnamed_encodings(path)
            if lines:
                found[os.path.relpath(path, REPO)] = lines
        self.assertEqual(found, {}, "text opens with no encoding=")

    def test_the_check_sees_what_it_is_for(self):
        src = ('open(p)\nopen(p, "w")\nopen(p, "rb")\nos.fdopen(fd, "w")\n'
               'os.fdopen(fd, "wb")\nq.read_text()\nq.write_text(s)\n'
               'open(p, encoding="utf-8")\nopener.open(req)\n'
               'tempfile.NamedTemporaryFile("w")\ntempfile.TemporaryFile()\n')
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".py",
                                         delete=False) as fh:
            fh.write(src)
        self.addCleanup(os.unlink, fh.name)
        self.assertEqual(_unnamed_encodings(fh.name), [1, 2, 4, 6, 7, 10])


# Run in a child, since the locale's encoding is fixed at interpreter start.
CHILD = r"""
import json, locale, sys
from ranwhat import clean, cli, score, watch
from ranwhat.html_report import write_html

transcript, backups, report, profile = sys.argv[1:]
clean.BACKUP_ROOT = backups
findings, changed = clean.scan_file(transcript, apply=True)
evidence = [h["evidence"] for r in watch.scan_transcript(transcript)
            for h in r["hits"]]
loaded = cli._load(profile)
write_html(score.scan(loaded), report)
json.dump({"encoding": locale.getpreferredencoding(False),
           "fingerprints": sorted(findings), "changed": changed,
           "evidence": evidence, "agent": loaded["agent"]}, sys.stdout)
"""

SECRET = "8f3a9c2e1b7d4f6a0c5e8b2d7f1a4c9e"      # tests/test_clean.py
AGENT = "Agent ✓ café 日本"


def _row(i, content):
    return json.dumps({"timestamp": "2026-09-20T10:%02d:00Z" % i,
                       "message": {"role": "user", "content": [content]}},
                      ensure_ascii=False)


class UnderALocaleThatIsNotUtf8(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        d = tempfile.mkdtemp(prefix="locale-")
        cls.transcript = os.path.join(d, "s.jsonl")
        cls.backups = os.path.join(d, "backups")
        cls.report = os.path.join(d, "report.html")
        cls.profile = os.path.join(d, "agent.json")
        lines = [
            _row(1, {"type": "tool_use", "id": "t1", "name": "Bash",
                     "input": {"command": "rm -rf ~/Documents/café-日本"}}) + "\r\n",
            _row(2, {"type": "tool_result", "tool_use_id": "t1",
                     "content": "JWT_ACCESS_SECRET=%s naïve ✓" % SECRET}) + "\r\n",
            _row(3, {"type": "text", "text": "Ωmega, untouched"}) + "\r\n",
        ]
        cls.original = "".join(lines).encode("utf-8")
        with open(cls.transcript, "wb") as fh:
            fh.write(cls.original)
        # With the byte-order mark PowerShell 5 writes.
        with open(cls.profile, "wb") as fh:
            fh.write(b"\xef\xbb\xbf" + json.dumps(
                {"agent": AGENT, "credentials": [
                    {"provider": "aws", "scopes": ["s3:*"]}]},
                ensure_ascii=False).encode("utf-8"))
        env = dict(os.environ, LC_ALL="C", LANG="C", PYTHONUTF8="0",
                   PYTHONCOERCECLOCALE="0", PYTHONIOENCODING="utf-8",
                   PYTHONPATH=REPO)
        proc = subprocess.run(
            [sys.executable, "-c", CHILD, cls.transcript, cls.backups,
             cls.report, cls.profile],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, env=env, cwd=REPO, timeout=60)
        cls.stderr = proc.stderr.decode("utf-8", "replace")
        cls.out = json.loads(proc.stdout) if proc.returncode == 0 else None

    def setUp(self):
        self.assertIsNotNone(self.out, self.stderr)
        encoding = self.out["encoding"].lower().replace("-", "").replace("_", "")
        if encoding in ("utf8", "cp65001"):
            self.skipTest("Python here starts in UTF-8 whatever the locale")

    def read(self, path):
        with open(path, "rb") as fh:
            return fh.read()

    def test_the_transcript_changes_only_where_the_secret_was(self):
        (fp,) = self.out["fingerprints"]
        self.assertTrue(self.out["changed"])
        mask = (REDACTION % fp).encode("utf-8")
        self.assertEqual(self.read(self.transcript),
                         self.original.replace(SECRET.encode(), mask))

    def test_the_backup_is_the_original(self):
        backups = [os.path.join(base, f)
                   for base, _d, files in os.walk(self.backups) for f in files]
        self.assertEqual(len(backups), 1)
        self.assertEqual(self.read(backups[0]), self.original)

    def test_watch_quotes_the_command_as_it_ran(self):
        self.assertEqual(self.out["evidence"], ["rm -rf ~/Documents/café-日本"])

    def test_a_profile_with_a_byte_order_mark_loads(self):
        self.assertEqual(self.out["agent"], AGENT)

    def test_the_report_is_the_utf8_it_declares(self):
        raw = self.read(self.report)
        text = raw.decode("utf-8")
        self.assertIn('<meta charset="utf-8">', text)
        self.assertIn("<h1>%s</h1>" % AGENT, text)
        self.assertNotIn(b"\r\r\n", raw)


class ProfilesWithAByteOrderMark(unittest.TestCase):

    def test_load(self):
        with tempfile.NamedTemporaryFile("wb", suffix=".json",
                                         delete=False) as fh:
            fh.write(b"\xef\xbb\xbf" + json.dumps({"agent": AGENT},
                                                  ensure_ascii=False).encode("utf-8"))
        self.addCleanup(os.unlink, fh.name)
        self.assertEqual(cli._load(fh.name), {"agent": AGENT})

    def test_bytes_that_are_not_utf8_are_a_message(self):
        with tempfile.NamedTemporaryFile("wb", suffix=".json",
                                         delete=False) as fh:
            fh.write('{"agent": "x"}'.encode("utf-16"))
        self.addCleanup(os.unlink, fh.name)
        with self.assertRaises(SystemExit) as cm:
            cli._load(fh.name)
        self.assertIn("is not valid JSON", str(cm.exception.code))


if __name__ == "__main__":
    unittest.main(verbosity=2)
