"""`check` prints one report, not two reports and a tail glued together.

It used to print watch's full report, then clean's, then its own tail: three
"Read locally" footers, "Run with --apply" beside a tail saying to run
`clean`, a row of 46 spaces left on the terminal by the progress line, and a
TypeError instead of JSON whenever a secret was found. The fix gates the
footer and advice blocks with keyword arguments. Nothing is filtered out of
rendered text, so most of this file pins that every finding still prints.

Every value here is synthetic, or already used elsewhere in this suite.
"""
import contextlib
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ranwhat import clean, cli, term, watch

try:
    import pty
except ImportError:         # Windows: tty needs termios, which it lacks
    pty = None

# The pinned output shows transcript times in the reader's zone. Only
# time.tzset can pin it to UTC, and Windows has none, so there the exact
# output holds only on a machine that is already on UTC, as CI's is.
PINNED_ZONE = unittest.skipUnless(
    hasattr(time, "tzset") or (time.timezone == 0 and not time.daylight),
    "needs time.tzset or a machine on UTC")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FOOTER = "  Read locally. Nothing was transmitted."
STRIPE = "STRIPE=sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc"     # tests/test_clean.py
DB_PASSWORD = "DB_PASSWORD=kzN8fJx2mQ4vB7nR5tY9wL3pZ6aS1dF0c2e="  # tests/test_clean.py
WIDTH = "60"
RULE = "  " + "-" * 56          # term.rule("-") at RANWHAT_WIDTH=60


def tool_use(cmd, i):
    return {"timestamp": "2026-09-20T10:%02d:00Z" % i,
            "message": {"role": "assistant", "content": [
                {"type": "tool_use", "id": "t%d" % i, "name": "Bash",
                 "input": {"command": cmd}}]}}


def tool_result(text, i):
    return {"timestamp": "2026-09-20T10:%02d:30Z" % i,
            "message": {"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": "t%d" % i,
                 "content": text}]}}


def make_root(rows):
    root = tempfile.mkdtemp(prefix="check-t-")
    proj = os.path.join(root, "-tmp-synthetic-proj")
    os.makedirs(proj)
    with open(os.path.join(proj, "s1.jsonl"), "w", encoding="utf-8") as fh:
        for r in rows:
            fh.write(json.dumps(r) + "\n")
    return root, tempfile.mkdtemp(prefix="check-oc-")


ACTION = [tool_use("rm -rf ~/Documents/archive", 1)]
SECRET = [tool_result(STRIPE + "\n", 2)]


def _refuse_apply(real):
    def scan(*a, **k):
        if k.get("apply") or (len(a) > 2 and a[2]):
            raise AssertionError("check must never mask")
        return real(*a, **k)
    return scan


class _Base(unittest.TestCase):

    def setUp(self):
        # watch prints transcript times in the reader's zone, so the zone is
        # pinned for the exact output pinned below.
        env = mock.patch.dict(os.environ, {"RANWHAT_WIDTH": WIDTH, "TZ": "UTC"})
        env.start()
        if hasattr(time, "tzset"):
            self.addCleanup(time.tzset)       # last, once TZ is restored
            time.tzset()
        self.addCleanup(env.stop)
        os.environ.pop("NO_COLOR", None)
        guard = mock.patch.object(clean, "scan", _refuse_apply(clean.scan))
        guard.start()
        self.addCleanup(guard.stop)

    def run_cli(self, argv, stderr=None):
        out = io.StringIO()
        err = io.StringIO() if stderr is None else stderr
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                rc = cli.main(argv)
            except SystemExit as e:
                rc = e.code
        return rc, out.getvalue(), (err.getvalue() if stderr is None else "")

    def check(self, rows, *extra, **kw):
        root, st = make_root(rows)
        return self.run_cli(["check", "--root", root, "--state-dir", st]
                            + list(extra), **kw)

    def lines(self, text):
        return text.split("\n")


class OneFooter(_Base):

    def test_every_combination_has_one_footer_and_three_rules(self):
        for rows in (ACTION + SECRET, ACTION, SECRET, [tool_use("ls", 1)]):
            rc, out, _ = self.check(rows)
            self.assertEqual(rc, 0)
            lines = self.lines(out)
            # Exact tool-authored lines, not substrings: evidence may quote them.
            self.assertEqual(lines.count(FOOTER), 1, out)
            self.assertEqual(lines.count(RULE), 3, out)
            self.assertEqual(lines[-4:], [RULE, FOOTER, "", ""], out)
            self.assertEqual(lines.count("  What to do with this"), 1)
            self.assertNotIn("  Dry run. Nothing was changed.", lines)
            self.assertFalse(any("Run with --apply" in l for l in lines))
            self.assertNotIn("\n\n\n", out)

    def test_read_only_is_said_once(self):
        for rows in (ACTION + SECRET, [tool_use("ls", 1)]):
            _, out, _ = self.check(rows)
            self.assertEqual(
                self.lines(out).count("  Nothing was changed. check only reads."), 1)

    def test_clean_step_appears_once_and_only_with_findings(self):
        _, out, _ = self.check(ACTION + SECRET)
        # Whitespace folded: on a narrow terminal the reason sits on the line
        # under its command instead of beside it.
        tail = " ".join(out.split("  What to do with this", 1)[1].split())
        steps = re.findall(r" clean review each secret, then mask it", tail)
        self.assertEqual(len(steps), 1, out)
        _, out, _ = self.check(ACTION)
        self.assertNotIn("review each secret", out)

    def test_sections_are_separated_by_one_blank_line(self):
        _, out, _ = self.check(ACTION + SECRET)
        self.assertTrue(out.startswith("\n  ranwhat watch"), out[:40])
        i = out.index("  ranwhat clean")
        self.assertEqual(out[i - 2:i], "\n\n")
        self.assertNotEqual(out[i - 3], "\n")


class NothingIsLost(_Base):

    def test_deletion_and_evidence(self):
        _, out, _ = self.check(ACTION)
        self.assertIn("Bulk or recursive deletion", out)
        self.assertIn("      rm -rf ~/Documents/archive", self.lines(out))

    def test_force_push(self):
        _, out, _ = self.check([tool_use("git push --force origin main", 1)])
        self.assertIn("Destructive git operation", out)

    def test_stripe_key_with_rotation_warning(self):
        # The diagnosis used sk_live_51HxAbCdEf..., which the fixture filter
        # now treats as a typed alphabet; this Stripe-shaped value is real.
        _, out, _ = self.check(SECRET)
        self.assertIn("Stripe live secret key", out)
        self.assertIn("sk_…dc", out)
        self.assertIn("  These must be rotated.", self.lines(out))

    def test_env_password_keeps_its_origin(self):
        rows = [tool_use("cat api/.env", 1), tool_result(DB_PASSWORD + "\n", 1)]
        _, out, _ = self.check(rows)
        self.assertIn("* DB_PASSWORD", out)
        self.assertIn("read from api/.env", out)

    def test_database_url_and_aws_key(self):
        rows = [tool_result(
            "DATABASE_URL=postgresql://admin:sup3rS3cretPw@db:5432/a\n", 1)]
        rc, out, _ = self.check(rows, "--json")
        self.assertEqual(rc, 0)
        self.assertEqual(len(json.loads(out)["secrets"]), 1)
        _, out, _ = self.check([tool_result("AWS=AKIAIOSFODNN7REALKEY\n", 1)])
        self.assertIn("AWS access key ID", out)

    def test_bullets_equal_json_counts(self):
        rows = ACTION + SECRET + [
            tool_use("git push --force origin main", 3),
            tool_use("cat api/.env", 4), tool_result(DB_PASSWORD + "\n", 4)]
        root, st = make_root(rows)
        args = ["--root", root, "--state-dir", st]
        _, text, _ = self.run_cli(["check"] + args)
        _, actions, _ = self.run_cli(["watch", "--json"] + args)
        _, found, _ = self.run_cli(["clean", "--json", "--no-interactive"] + args)
        expected = len(json.loads(actions)) + len(json.loads(found)["findings"])
        self.assertGreaterEqual(expected, 4)
        bullets = [l for l in self.lines(text) if l.startswith("  * ")]
        self.assertEqual(len(bullets), expected, text)

    # Evidence is cut to the terminal, so these run wide enough to show it.
    def test_evidence_quoting_the_footer_survives(self):
        cmd = 'rm -rf ~/Documents/"  Read locally. Nothing was transmitted."'
        with mock.patch.dict(os.environ, {"RANWHAT_WIDTH": "96"}):
            _, out, _ = self.check([tool_use(cmd, 1)])
        self.assertIn("Bulk or recursive deletion", out)
        self.assertIn("      " + cmd, self.lines(out))
        self.assertEqual(self.lines(out).count(FOOTER), 1)

    def test_evidence_quoting_the_advice_survives(self):
        cmd = 'rm -rf ~/Documents/"Dry run. Nothing was changed. Run with --apply"'
        with mock.patch.dict(os.environ, {"RANWHAT_WIDTH": "96"}):
            _, out, _ = self.check([tool_use(cmd, 1)])
        self.assertIn("Bulk or recursive deletion", out)
        self.assertIn("      " + cmd, self.lines(out))


class Json(_Base):

    def test_check_json_with_a_secret(self):
        rows = ACTION + [tool_use("cat api/.env", 2),
                         tool_result(DB_PASSWORD + "\n", 2)]
        root, st = make_root(rows)
        rc, out, err = self.run_cli(["check", "--json", "--root", root,
                                     "--state-dir", st])
        self.assertEqual(rc, 0)
        doc = json.loads(out)
        self.assertEqual(len(doc["secrets"]), 1)
        s = doc["secrets"][0]
        for k in ("files", "origins", "projects"):
            self.assertIsInstance(s[k], list)
        self.assertEqual(s["origins"], ["api/.env"])
        self.assertTrue(s["fingerprint"] and s["hint"])
        _, actions, _ = self.run_cli(["watch", "--json", "--root", root,
                                      "--state-dir", st])
        self.assertEqual(len(doc["actions"]), len(json.loads(actions)))
        for prose in ("Read locally", "What to do with this",
                      "reading transcripts"):
            self.assertNotIn(prose, out)
        self.assertEqual(err, "")

    def test_clean_json_with_a_secret(self):
        root, _ = make_root(SECRET)
        rc, out, _ = self.run_cli(["clean", "--json", "--no-interactive",
                                   "--root", root])
        self.assertEqual(rc, 0)
        self.assertEqual(len(json.loads(out)["findings"]), 1)

    def test_empty_json_is_unchanged(self):
        root, st = make_root([tool_use("ls", 1)])
        _, out, _ = self.run_cli(["check", "--json", "--root", root,
                                  "--state-dir", st])
        self.assertEqual(out, json.dumps(
            {"days": 30, "actions": [], "secrets": []}, indent=2) + "\n")


class Arguments(_Base):

    def test_days_below_one_is_an_error_not_an_all_clear(self):
        for days in ("0", "-1"):
            rc, out, err = self.check(ACTION + SECRET, "--days", days)
            self.assertEqual(rc, 2)
            self.assertIn("--days must be at least 1", err)
            self.assertNotIn("Nothing flagged", out)

    def test_apply_is_refused_before_anything_is_scanned(self):
        called = []
        with mock.patch.object(clean, "scan",
                               lambda *a, **k: called.append(k) or ({}, 0, [])):
            rc, out, err = self.check(SECRET, "--apply")
        self.assertEqual(rc, 2)
        self.assertEqual(called, [])
        self.assertIn("check never changes anything", err)
        self.assertEqual(out, "")


class NextSteps(_Base):
    """The tail suggested `scan profile.json`, which fails with "no such
    file" for anyone who has not written one, and nothing in the tool
    writes one. Every step it suggests has to run as printed."""

    def tail(self, rows, cmd="ranwhat"):
        root, st = make_root(rows)
        with mock.patch.object(cli, "invocation", return_value=cmd):
            _, out, _ = self.run_cli(["check", "--root", root,
                                      "--state-dir", st])
        tail = out.split("  What to do with this", 1)[1]
        steps = [re.split(r"\s{2,}", l.strip())[0]
                 for l in tail.split("\n") if l.startswith("    %s " % cmd)]
        return steps, root, st, out

    def test_every_step_runs_for_a_new_user(self):
        steps, root, st, out = self.tail(ACTION + SECRET)
        self.assertNotIn("profile.json", out)
        self.assertIn("ranwhat demo", steps)
        self.assertEqual(len(steps), 3, steps)
        for step in steps:
            argv = step.split()[1:] + ["--root", root, "--state-dir", st]
            with mock.patch("sys.stdin", io.StringIO()):
                rc, _, err = self.run_cli(argv)
            self.assertEqual(rc, 0, (step, err))

    def test_demo_is_offered_even_with_nothing_found(self):
        steps, _, _, _ = self.tail([tool_use("ls", 1)])
        self.assertEqual(steps, ["ranwhat demo"])

    def test_a_long_command_puts_its_reason_underneath(self):
        # uvx at 60 columns: "watch --json" and its reason do not fit on
        # one line, so every reason moves to the line below its command.
        steps, _, _, out = self.tail(ACTION + SECRET, cmd="uvx ranwhat")
        limit = term.width()
        self.assertEqual(steps, ["uvx ranwhat clean", "uvx ranwhat watch --json",
                                 "uvx ranwhat demo"])
        lines = self.lines(out.split("  What to do with this", 1)[1])
        for i, line in enumerate(lines):
            self.assertLessEqual(len(line), limit, line)
            if line.startswith("    uvx ranwhat "):
                self.assertEqual(line.strip(), steps.pop(0))
                self.assertTrue(lines[i + 1].startswith("      "), lines[i + 1])


class OneProgressWording(_Base):
    """check said "reading transcripts 1/4" and clean said "scanning 1/4
    -Users-you-Desktop-app", an internal directory slug. One wording, and
    no slug."""

    def progress(self, *argv):
        root, st = make_root(ACTION + SECRET)
        err = _FakeTTY()
        with mock.patch.dict(os.environ, {"TERM": "xterm"}), \
             mock.patch("sys.stdin", io.StringIO()):
            rc, out, _ = self.run_cli(list(argv) + ["--root", root,
                                                    "--state-dir", st],
                                      stderr=err)
        self.assertEqual(rc, 0)
        self.assertIn("Stripe live secret key", out)
        return err.getvalue()

    def test_check_and_clean_say_the_same_thing(self):
        expected = "\r  reading transcripts 1/1\033[K\r\033[K"
        self.assertEqual(self.progress("check"), expected)
        self.assertEqual(self.progress("clean", "--no-interactive"), expected)

    def test_no_slug_reaches_the_terminal(self):
        for argv in (["check"], ["clean", "--no-interactive"]):
            self.assertNotIn("synthetic-proj", self.progress(*argv))

    def test_clean_writes_nothing_off_a_terminal(self):
        root, _ = make_root(SECRET)
        _, out, err = self.run_cli(["clean", "--no-interactive", "--root", root])
        self.assertEqual(err, "")
        self.assertIn("Stripe live secret key", out)


class _BrokenTTY:
    """A terminal that has hung up: every write and flush fails."""

    def isatty(self):
        return True

    def fileno(self):
        raise OSError(5, "Input/output error")

    def write(self, s):
        raise OSError(5, "Input/output error")

    def flush(self):
        raise OSError(5, "Input/output error")


class _FakeTTY(io.StringIO):
    def isatty(self):
        return True


class ProgressNeverCostsTheReport(_Base):

    def test_not_a_tty_writes_nothing(self):
        _, out, err = self.check(ACTION + SECRET)
        self.assertEqual(err, "")
        self.assertIn("Stripe live secret key", out)

    def test_failing_stderr(self):
        rc, out, _ = self.check(SECRET, stderr=_BrokenTTY())
        self.assertEqual(rc, 0)
        self.assertIn("Stripe live secret key", out)
        self.assertIn("These must be rotated.", out)

    def test_closed_stderr(self):
        out = io.StringIO()
        root, st = make_root(SECRET)
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(None):
            rc = cli.main(["check", "--root", root, "--state-dir", st])
        self.assertEqual(rc, 0)
        self.assertIn("Stripe live secret key", out.getvalue())

    def test_progress_writes_and_erases_on_a_tty(self):
        s = _FakeTTY()
        with mock.patch.dict(os.environ, {"TERM": "xterm"}):
            bar = term.Progress(s)
            bar.update("  reading transcripts 1/2")
            bar.clear()
        self.assertEqual(s.getvalue(),
                         "\r  reading transcripts 1/2\033[K\r\033[K")

    def test_dumb_terminal_and_pipes_get_no_escapes(self):
        s = _FakeTTY()
        with mock.patch.dict(os.environ, {"TERM": "dumb"}):
            bar = term.Progress(s)
            bar.update("x")
            bar.clear()
        self.assertEqual(s.getvalue(), "")
        s = io.StringIO()
        bar = term.Progress(s)
        bar.update("x")
        bar.clear()
        self.assertEqual(s.getvalue(), "")

    def test_isatty_raising_disables_progress(self):
        class Closed(io.StringIO):
            def isatty(self):
                raise ValueError("I/O operation on closed file")
        self.assertFalse(term.Progress(Closed()).enabled)


# Standalone output must not move. Records and findings are built by hand so
# a change to a rule's wording elsewhere does not break this.
REC = {"severity": "high", "timestamp": "2026-09-20T10:01:00Z",
       "tool_name": "Bash",
       "hits": [{"title": "Synthetic rule", "evidence": "command synthetic",
                 "why": "Because."}]}
FIND = {"fp": {"fingerprint": "0123456789ab", "label": "Synthetic key",
               "length": 20, "hint": "syn…ey", "files": {"/x/s.jsonl"},
               "origins": {"api/.env"}, "projects": {"/p"}, "count": 2}}
ROTATE = ("  These must be rotated.\n"
          "  They have been written to disk in plaintext and sat in a model\n"
          "  context you do not control. Masking them here stops them leaking\n"
          "  again. It does not make them safe.\n")
WATCH_PLAIN = (
    "\n  ranwhat watch  · local agent flight recorder\n" + RULE + "\n"
    "  1 source(s) over 30 days\n\n  1 high\n\n"
    "  * Synthetic rule   2026-09-20 10:01:00  Bash\n"
    "      command synthetic\n      -> Because.\n\n"
    + RULE + "\n" + FOOTER + "\n")
CLEAN_PLAIN = (
    "\n  ranwhat clean  · secrets sitting in local transcripts\n" + RULE + "\n"
    "  1 transcript(s) scanned\n\n  1 distinct secret(s) in 2 place(s)\n\n"
    + ROTATE + "\n"
    "  * Synthetic key   syn…ey  20 chars  seen 2x\n"
    "      read from api/.env\n      in         /p\n\n"
    "  Dry run. Nothing was changed.\n"
    "  Run with --apply to mask them. Backups are written first.\n\n"
    + RULE + "\n" + FOOTER + "\n")


def _sgr(code, s):
    return "\033[%sm%s\033[0m" % (code, s)


B = lambda s: _sgr("1", s)
D = lambda s: _sgr("2", s)
WATCH_COLOUR = (
    "\n" + B("  ranwhat watch  ") + D("· local agent flight recorder") + "\n"
    + D(RULE) + "\n  1 source(s) over 30 days\n\n  " + _sgr("33", B("1 high"))
    + "\n\n  " + _sgr("33", "* ") + B("Synthetic rule")
    + D("   2026-09-20 10:01:00  Bash") + "\n" + D("      command synthetic")
    + "\n" + D("      -> Because.") + "\n\n" + D(RULE) + "\n" + D(FOOTER) + "\n")
CLEAN_COLOUR = (
    "\n" + B("  ranwhat clean  ") + D("· secrets sitting in local transcripts")
    + "\n" + D(RULE) + "\n  1 transcript(s) scanned\n\n  "
    + _sgr("31", B("1 distinct secret(s)")) + D(" in 2 place(s)") + "\n\n  "
    + B("These must be rotated.") + "\n"
    + "".join(D(l) + "\n" for l in ROTATE.split("\n")[1:-1]) + "\n  "
    + _sgr("31", "* ") + B("Synthetic key") + D("   syn…ey  20 chars  seen 2x")
    + "\n" + D("      read from ") + _sgr("36", "api/.env") + "\n"
    + D("      in         /p") + "\n\n  " + _sgr("33", "Dry run. Nothing was changed.")
    + "\n" + D("  Run with --apply to mask them. Backups are written first.")
    + "\n\n" + D(RULE) + "\n" + D(FOOTER) + "\n")


class StandaloneUnchanged(_Base):

    @PINNED_ZONE
    def test_plain(self):
        self.assertEqual(watch.render([REC], 1, 30), WATCH_PLAIN)
        self.assertEqual(clean.render(FIND, 1, [], False), CLEAN_PLAIN)

    def test_one_footer_each(self):
        self.assertEqual(WATCH_PLAIN.split("\n").count(FOOTER), 1)
        self.assertEqual(CLEAN_PLAIN.split("\n").count(FOOTER), 1)

    @PINNED_ZONE
    def test_gates_drop_only_their_lines(self):
        w = watch.render([REC], 1, 30, footer=False)
        self.assertEqual(w + "\n" + RULE + "\n" + FOOTER + "\n", WATCH_PLAIN)
        c = clean.render(FIND, 1, [], False, footer=False, advice=False)
        self.assertEqual(c + "\n", CLEAN_PLAIN.split("  Dry run.")[0])
        self.assertIn(ROTATE, c)
        self.assertIn("  * Synthetic key", c)

    def test_standalone_cli_keeps_advice_and_footer(self):
        root, _ = make_root(SECRET)
        _, out, _ = self.run_cli(["clean", "--no-interactive", "--root", root])
        lines = self.lines(out)
        self.assertIn("  Dry run. Nothing was changed.", lines)
        self.assertIn("  Run with --apply to mask them. Backups are written first.",
                      lines)
        self.assertEqual(lines.count(FOOTER), 1)
        root, st = make_root(ACTION)
        _, out, _ = self.run_cli(["watch", "--root", root, "--state-dir", st])
        self.assertEqual(self.lines(out).count(FOOTER), 1)

    @unittest.skipIf(os.name == "nt", "pseudo-terminals are POSIX only")
    def test_colour_in_a_pty(self):
        code = ("import sys\nfrom ranwhat import watch, clean\n"
                "REC = %r\nFIND = %r\n"
                "sys.stdout.write(watch.render([REC], 1, 30) + '|'"
                " + clean.render(FIND, 1, [], False))\n" % (REC, FIND))
        raw = _pty_run([sys.executable, "-c", code],
                       {"TERM": "xterm-256color"}, 80)
        watched, cleaned = raw.replace("\r\n", "\n").split("|")
        self.assertEqual(watched, WATCH_COLOUR)
        self.assertEqual(cleaned, CLEAN_COLOUR)


def _pty_run(argv, env_extra, cols):
    """Run argv with stdin/stdout/stderr all on a pty of `cols` columns."""
    import fcntl
    import struct
    import termios
    pid, fd = pty.fork()
    if pid == 0:
        try:
            env = dict(os.environ, RANWHAT_WIDTH=WIDTH, PYTHONPATH=REPO,
                       **env_extra)
            env.pop("NO_COLOR", None)
            os.chdir(REPO)
            os.execve(argv[0], argv, env)
        finally:
            os._exit(127)
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", 40, cols, 0, 0))
    data = b""
    while True:
        try:
            chunk = os.read(fd, 65536)
        except OSError:
            break
        if not chunk:
            break
        data += chunk
    os.waitpid(pid, 0)
    os.close(fd)
    return data.decode("utf-8", "replace")


def _screen(raw, cols):
    """What a terminal shows after these bytes: autowrap, CR, LF and EL."""
    rows, r, c, i = [[]], 0, 0, 0
    while i < len(raw):
        if raw.startswith("\033[K", i):
            del rows[r][c:]
            i += 3
            continue
        m = re.match(r"\033\[[0-9;]*m", raw[i:])
        if m:
            i += m.end()
            continue
        ch = raw[i]
        if ch == "\r":
            c = 0
        elif ch == "\n":
            r, c = r + 1, 0
            rows.append([]) if r == len(rows) else None
        else:
            if c >= cols:
                r, c = r + 1, 0
                rows.append([]) if r == len(rows) else None
            row = rows[r]
            row.extend(" " * (c - len(row)))
            if c < len(row):
                row[c] = ch
            else:
                row.append(ch)
            c += 1
        i += 1
    return ["".join(x) for x in rows]


@unittest.skipIf(os.name == "nt", "pseudo-terminals are POSIX only")
class RealTerminal(unittest.TestCase):

    def test_progress_shows_then_leaves_no_residue(self):
        root, st = make_root(ACTION + SECRET)
        argv = [sys.executable, "-m", "ranwhat", "check", "--root", root,
                "--state-dir", st]
        for cols in (80, 40):
            raw = _pty_run(argv, {"TERM": "xterm", "NO_COLOR": ""}, cols)
            self.assertIn("reading transcripts 1/1", raw)
            last = raw.rindex("reading transcripts")
            self.assertIn("\r\033[K", raw[last:])
            self.assertNotIn(" " * 46, raw)
            rows = _screen(raw.replace("\r\n", "\n"), cols)
            self.assertEqual(rows[0], "", rows[:3])
            self.assertTrue(rows[1].startswith("  ranwhat watch"), rows[:3])
            self.assertEqual(sum(r == FOOTER for r in rows), 1)
            self.assertIn("Stripe live secret key", raw)

    def test_narrow_stderr_with_stdout_redirected(self):
        # shutil.get_terminal_size() measures stdout, which here is a file,
        # so it answers 80; the line must be cut to the 20-column stderr.
        import fcntl
        import struct
        import termios
        root, st = make_root(ACTION + SECRET)
        master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 20, 0, 0))
        env = dict(os.environ, TERM="xterm", PYTHONPATH=REPO)
        env.pop("COLUMNS", None)
        with tempfile.TemporaryFile() as out:
            proc = subprocess.Popen(
                [sys.executable, "-m", "ranwhat", "check", "--root", root,
                 "--state-dir", st],
                stdin=subprocess.DEVNULL, stdout=out, stderr=slave, cwd=REPO,
                env=env)
            os.close(slave)
            raw = b""
            while True:
                try:
                    chunk = os.read(master, 65536)
                except OSError:
                    break
                if not chunk:
                    break
                raw += chunk
            proc.wait()
            os.close(master)
            out.seek(0)
            report = out.read().decode()
        err = raw.decode()
        self.assertIn("\r  reading transcrip\033[K", err)
        for piece in err.replace("\033[K", "").split("\r"):
            self.assertLessEqual(len(piece), 19, repr(err))
        self.assertEqual([r for r in _screen(err, 20) if r], [])
        self.assertIn("Stripe live secret key", report)


if __name__ == "__main__":
    unittest.main(verbosity=2)
