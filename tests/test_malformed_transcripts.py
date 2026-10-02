"""One odd line in one transcript stopped the whole run with a traceback.

A line that is valid JSON but no object, a call whose id is an object,
nesting deep enough to exhaust the stack, and a lone half of a UTF-16
surrogate pair (Node writes one for an emoji cut in two) each ended watch,
check or clean, and with them every finding in every other transcript.
And a report piped into head or a pager ended in BrokenPipeError.

Each case runs on its own interpreter, as a user runs it. Every value here
is synthetic.
"""
import contextlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import traceback
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import isolated_home  # noqa: E402,F401  ranwhat's state, never ~/.ranwhat
from ranwhat import clean, cli, watch

HANG = 20
DAY = time.strftime("%Y-%m-%d", time.gmtime(time.time() - 86400))
KEY = "sk_" "live_" + "Zq8Lm3Np5Rt7Vx9Bc2Df4Gh6"


def _call(command, **block):
    return {"type": "assistant", "timestamp": DAY + "T10:00:00Z", "message": {
        "content": [dict({"type": "tool_use", "id": "a", "name": "Bash",
                          "input": {"command": command}}, **block)]}}


ODD_LINES = {
    "a list": json.dumps(["TOKEN=" + KEY]),
    "a string": json.dumps("TOKEN=" + KEY),
    "a number": "12",
    "an id that is an object": json.dumps(_call("rm -rf ~/x", id={"x": 1})),
    "a result for an id that is an object": json.dumps(
        {"type": "user", "message": {"content": [
            {"type": "tool_result", "tool_use_id": {"x": 1}, "content": "TOKEN=" + KEY}]}}),
    "a name that is an object": json.dumps(_call("rm -rf ~/x", name={"x": 1})),
    "a timestamp that is an object": json.dumps(dict(_call("rm -rf ~/x"), timestamp={"t": 1})),
    "deep nesting": '{"a":' * 900 + json.dumps("TOKEN=" + KEY) + "}" * 900,
    "deeper than json reads": "[" * 100000 + "]" * 100000,
    "a lone surrogate": json.dumps(_call("rm -rf ~/x \ud83d")),
    "a lone surrogate in a value": json.dumps(
        {"type": "user", "message": {"content": [
            {"type": "tool_result", "tool_use_id": "a",
             "content": "DB_PASSWORD=Xk9mPq2v\udc80Rt7wLz4b"}]}}),
}
COMMANDS = (["watch"], ["watch", "--json"], ["check"], ["check", "--json"],
            ["clean", "--json"], ["clean", "--no-interactive"])


def _run(argv, root, home, encoding="utf-8"):
    env = dict(os.environ, HOME=home, NO_COLOR="1", PYTHONIOENCODING=encoding,
               PYTHONPATH=REPO)
    env.pop("CLAUDE_CONFIG_DIR", None)
    try:
        return subprocess.run([sys.executable, "-m", "ranwhat"] + argv
                              + ["--root", root, "--days", "30",
                                 "--state-dir", os.path.join(home, "oc")]
                              if argv[0] != "clean" else
                              [sys.executable, "-m", "ranwhat"] + argv
                              + ["--root", root, "--days", "30"],
                              capture_output=True, timeout=HANG, env=env,
                              stdin=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        raise AssertionError("%s still running after %ds" % (argv, HANG))


def _in_process(argv, root, home):
    out, err = io.StringIO(), io.StringIO()
    extra = ["--state-dir", os.path.join(home, "oc")] if argv[0] != "clean" else []
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            rc = cli.main(argv + ["--root", root, "--days", "30"] + extra)
        except SystemExit as e:
            rc = e.code
        except Exception:
            traceback.print_exc()
            rc = 1
    return rc, out.getvalue(), err.getvalue()


class OddLinesAreSkipped(unittest.TestCase):

    def setUp(self):
        self.home = tempfile.mkdtemp(prefix="odd-")
        self.addCleanup(shutil.rmtree, self.home, ignore_errors=True)

    def transcript(self, odd):
        """A transcript holding the odd line between a deletion and a .env
        read, which every command must still report."""
        root = os.path.join(self.home, "projects")
        proj = os.path.join(root, "-tmp-odd")
        os.makedirs(proj, exist_ok=True)
        rows = [json.dumps(_call("rm -rf ~/Documents/archive")), odd,
                json.dumps({"type": "user", "timestamp": DAY + "T10:01:00Z",
                            "message": {"content": [{"type": "tool_result",
                                                     "tool_use_id": "a",
                                                     "content": "TOKEN=" + KEY}]}})]
        with open(os.path.join(proj, "s.jsonl"), "w", encoding="utf-8",
                  errors="surrogatepass") as fh:
            fh.write("\n".join(rows) + "\n")
        return root

    def test_every_command_reads_on(self):
        for name, odd in ODD_LINES.items():
            root = self.transcript(odd)
            # What only shows on a real stream, a character it cannot
            # encode, runs on its own interpreter; the rest here.
            alone = "surrogate" in name
            for argv in COMMANDS:
                with self.subTest(line=name, argv=argv):
                    if alone:
                        run = _run(argv, root, self.home)
                        rc, out, err = (run.returncode, run.stdout.decode("utf-8", "replace"),
                                        run.stderr.decode("utf-8", "replace"))
                    else:
                        rc, out, err = _in_process(argv, root, self.home)
                    self.assertNotIn("Traceback", err)
                    self.assertEqual(rc, 0, err[-400:])
                    self.assertNotIn(KEY, out + err)
                    if argv[0] != "clean":
                        self.assertIn("archive", out)
                    if argv[0] != "watch":
                        self.assertIn(clean._fingerprint(KEY) if "--json" in argv
                                      else clean._hint(KEY), out)

    def test_a_terminal_that_takes_only_ascii(self):
        root = self.transcript(ODD_LINES["a lone surrogate"])
        for argv in COMMANDS:
            with self.subTest(argv=argv):
                run = _run(argv, root, self.home, encoding="ascii")
                err = run.stderr.decode("utf-8", "replace")
                self.assertNotIn("Traceback", err)
                self.assertEqual(run.returncode, 0, err[-400:])

    def test_the_readers_skip_them(self):
        for name, odd in ODD_LINES.items():
            root = self.transcript(odd)
            path = os.path.join(root, "-tmp-odd", "s.jsonl")
            with self.subTest(line=name):
                records = watch.scan_transcript(path)
                self.assertIn("rm -rf ~/Documents/archive",
                              [r["hits"][0]["evidence"] for r in records])
                findings, _ = clean.scan_file(path)
                self.assertIn(clean._hint(KEY), [f["hint"] for f in findings.values()])


class APipeClosedEarly(unittest.TestCase):
    """`ranwhat check | head` ended in a BrokenPipeError traceback."""

    def test_what_a_closed_pipe_raises(self):
        """POSIX raises BrokenPipeError; Windows, writing to a pipe whose
        reader has gone, an OSError with EINVAL."""
        import errno
        from unittest import mock
        self.assertTrue(cli._closed_pipe(BrokenPipeError(), windows=False))
        self.assertTrue(cli._closed_pipe(OSError(errno.EINVAL, "x"), windows=True))
        self.assertFalse(cli._closed_pipe(OSError(errno.EINVAL, "x"), windows=False))
        self.assertFalse(cli._closed_pipe(OSError(errno.ENOENT, "x"), windows=True))
        for error in (BrokenPipeError(), OSError(errno.EINVAL, "x")):
            with mock.patch.object(cli, "_main", side_effect=error), \
                 mock.patch.object(cli, "_closed_pipe", return_value=True):
                self.assertEqual(cli.main(["watch"]), 1)
        with mock.patch.object(cli, "_main", side_effect=OSError(errno.ENOENT, "x")):
            with self.assertRaises(OSError):
                cli.main(["watch"])

    def test_head_takes_what_it_wants(self):
        home = tempfile.mkdtemp(prefix="pipe-")
        self.addCleanup(shutil.rmtree, home, ignore_errors=True)
        root = os.path.join(home, "projects")
        proj = os.path.join(root, "-tmp-pipe")
        os.makedirs(proj)
        with open(os.path.join(proj, "s.jsonl"), "w", encoding="utf-8") as fh:
            for i in range(3000):
                fh.write(json.dumps(_call("rm -rf ~/Documents/p%d" % i, id="t%d" % i)) + "\n")
        env = dict(os.environ, HOME=home, NO_COLOR="1", PYTHONPATH=REPO)
        env.pop("CLAUDE_CONFIG_DIR", None)
        for argv in COMMANDS:
            with self.subTest(argv=argv):
                extra = (["--state-dir", os.path.join(home, "oc")]
                         if argv[0] != "clean" else [])
                child = subprocess.Popen(
                    [sys.executable, "-m", "ranwhat"] + argv
                    + ["--root", root, "--days", "30"] + extra,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    stdin=subprocess.DEVNULL, env=env)
                child.stdout.readline()
                child.stdout.close()          # what head does after a line
                try:
                    err = child.stderr.read().decode("utf-8", "replace")
                    child.wait(timeout=HANG)
                except subprocess.TimeoutExpired:
                    child.kill()
                    raise AssertionError("still running after %ds" % HANG)
                self.assertNotIn("Traceback", err)
                self.assertNotIn("BrokenPipeError", err)


if __name__ == "__main__":
    unittest.main(verbosity=2)
