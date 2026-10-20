"""ranwhat ignore, --ignore and --no-ignore, through the command line.

ranwhat ignore lists the file, or adds to it: one action by its id (on a
terminal, every action like it if asked), every action listed now (all),
or every action in watch --json on stdin (-). watch and check leave out
what it names, and every report says so. The file is written 0600, under
a lock, through any symlink to it. Every value here is synthetic, and
every file is in a temp directory.
"""
import io
import json
import os
import stat
import sys
import threading
import unittest
from unittest import mock

TESTS = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(TESTS))
sys.path.insert(0, TESTS)

import isolated_home  # noqa: E402,F401  ranwhat's state, never ~/.ranwhat
import test_ignore_identity as ti  # noqa: E402
from ranwhat import cli, ignore  # noqa: E402

STRIPE = "sk_" "live_" "Fx7Qw2Er9Ty4Ui1Op6As3Df"


class _Cli(ti._Home):

    def setUp(self):
        super().setUp()
        self.state = os.path.join(self.tmp, "state")
        self.file = os.path.join(self.state, "ignore")
        self.mylib = os.path.join(self.home, "work", "mylib")
        patch = mock.patch.object(cli, "invocation", return_value="ranwhat")
        patch.start()
        self.addCleanup(patch.stop)

    def history(self, *commands, cwd=None):
        rows = [ti.bash("toolu_%d" % i, command, self.now + i, cwd=cwd)
                for i, command in enumerate(commands, 1)]
        self.transcript(rows)

    def cli(self, *argv, stdin="", replies=None):
        out, err = io.StringIO(), io.StringIO()
        fake = io.StringIO(stdin)
        patches = [mock.patch("sys.stdout", out), mock.patch("sys.stderr", err),
                   mock.patch("sys.stdin", fake)]
        if replies is not None:
            answers = iter(replies)
            fake.isatty = lambda: True
            patches.append(mock.patch("builtins.input",
                                      lambda prompt="": next(answers)))
        for p in patches:
            p.start()
        try:
            try:
                rc = cli.main(list(argv))
            except SystemExit as exit:
                rc = exit.code
        finally:
            for p in reversed(patches):
                p.stop()
        return rc, out.getvalue(), err.getvalue()

    def watched(self, *extra):
        rc, out, err = self.cli("watch", "--json", *(self.flags() + list(extra)))
        return json.loads(out), err

    def text(self):
        with open(self.file, encoding="utf-8") as fh:
            return fh.read()

    def entries(self):
        return [line for line in self.text().split("\n")
                if line and not line.startswith("#")]


class List(_Cli):

    def test_no_file(self):
        rc, out, _err = self.cli("ignore")
        self.assertEqual(rc, 0)
        self.assertIn("No ignore file: %s does not exist, so watch and check list "
                      "everything." % ignore.shown(self.file), " ".join(out.split()))

    def test_each_entry_and_block_with_what_it_lacks(self):
        os.makedirs(self.state, exist_ok=True)
        with open(self.file, "w", encoding="utf-8") as fh:
            fh.write(ignore.HEADER
                     + "publish 'npm publish' in=~/work/mylib until=2027-01-31\n"
                     + "exec.remote\n"
                     + "git.destructive 'git push -f *' until=2026-09-30\n"
                     + "publsh\n"
                     + "# ranwhat ignore all, 2026-10-20 14:02, last 30 days: 2 actions\n"
                     + "3fa9c2d81b7e4a06  # a\n0c1d2e3f4a5b6c7d  # b\n"
                     + "9c01d2e3f4a5b6c7 ack\n")
        rc, out, _err = self.cli("ignore")
        self.assertEqual(rc, 3)                # a skipped line
        said = " ".join(out.split())
        for text in ("4 entries, 3 action ids",
                     "line 20 publish 'npm publish' in=~/work/mylib until=2027-01-31",
                     "exec.remote medium and high only: it names no command",
                     "expired 2026-09-30",
                     "line 23 skipped: there is no rule publsh",
                     "lines 25-26 2 actions by id (ranwhat ignore all, 2026-10-20)",
                     "line 27 1 change to ranwhat's own settings, acknowledged",
                     "ranwhat ignore ID.", "ranwhat watch --no-ignore lists everything"):
            self.assertIn(text, said)
        rc, out, _err = self.cli("ignore", "--json")
        doc = json.loads(out)
        self.assertEqual(rc, 3)
        self.assertEqual((doc["used"], doc["ids"], doc["acks"]), (True, 3, 1))
        self.assertEqual(doc["skipped"], [{"line": 23, "why": "there is no rule publsh"}])
        first = doc["entries"][0]
        self.assertEqual(first, {"line": 20, "rule": "publish", "pattern": "npm publish",
                                 "in": "~/work/mylib", "until": "2027-01-31",
                                 "hides_critical": True, "missing": [],
                                 "expired": False})
        self.assertEqual(doc["entries"][1]["missing"], ["command", "in=", "until="])
        self.assertTrue(doc["entries"][2]["expired"])

    def test_a_named_file_that_is_not_there_is_an_error(self):
        rc, _out, err = self.cli("ignore", "--ignore", os.path.join(self.tmp, "nope"))
        self.assertEqual(rc, 1)
        self.assertIn("cannot use --ignore", err)


class OneAction(_Cli):

    def test_by_id_without_asking(self):
        self.history("git push --force origin main")
        (rec,), _err = self.watched()
        rc, out, _err = self.cli("ignore", rec["id"], "--no-interactive", *self.flags())
        self.assertEqual(rc, 0)
        said = " ".join(out.split())
        self.assertIn("Left out: Destructive git operation", said)
        self.assertIn("Added to %s (line 20)." % ignore.shown(self.file), said)
        self.assertIn("To leave out every `git push --force origin main` instead, add "
                      "this line: git.destructive 'git push --force origin main'", said)
        self.assertEqual(self.entries()[0].split("  # ")[0], rec["id"])
        self.assertEqual(self.watched()[0], [])
        # again: left out already
        rc, out, _err = self.cli("ignore", rec["id"], *self.flags())
        self.assertEqual((rc, out.strip()), (0, "Already left out by line 20 of %s."
                                             % ignore.shown(self.file)))
        rc, out, _err = self.cli("ignore", rec["id"], "--json", *self.flags())
        self.assertEqual(json.loads(out)["skipped"], {"guard": 0, "present": 1})

    def test_the_menu_on_a_terminal(self):
        self.history("npm publish", cwd=self.mylib)
        (rec,), _err = self.watched()
        rc, out, _err = self.cli("ignore", rec["id"], *self.flags(), replies=["x", "2"])
        self.assertEqual(rc, 0)
        said = " ".join(out.split())
        self.assertIn("1 this action only", said)
        self.assertIn("2 `npm publish` run in %s or below it, until"
                      % ignore.shown(self.mylib), said)
        self.assertIn("Answer 1, 2 or c.", said)
        line, = self.entries()
        self.assertRegex(line, r"\Apublish 'npm publish' in=~/work/mylib "
                               r"until=\d{4}-\d\d-\d\d\Z")
        self.assertEqual(self.watched()[0], [])
        # the same command elsewhere is still listed
        self.history("npm publish", "cd /tmp/evil && npm publish", cwd=self.mylib)
        listed, _err = self.watched()
        self.assertEqual([r["hits"][0]["evidence"] for r in listed], ["…npm publish"])

    def test_cancel_adds_nothing(self):
        self.history("git push --force origin main")
        (rec,), _err = self.watched()
        for replies in ([""], ["c"]):
            rc, out, _err = self.cli("ignore", rec["id"], *self.flags(), replies=replies)
            self.assertEqual(rc, 0)
            self.assertIn("Nothing was added.", out)
        self.assertFalse(os.path.exists(self.file))

    def test_a_change_to_ranwhats_settings_needs_a_terminal_and_an_ack(self):
        self.history("echo publish >> ~/.ranwhat/ignore")
        (rec,), _err = self.watched()
        rc, _out, err = self.cli("ignore", rec["id"], *self.flags())
        self.assertEqual(rc, 1)
        self.assertIn("ranwhat ignore: that action changed ranwhat's own settings; "
                      "acknowledge it on a terminal, with ranwhat ignore %s --root"
                      % rec["id"], " ".join(err.split()))
        rc, _out, _err = self.cli("ignore", rec["id"], "--no-interactive",
                                  *self.flags(), replies=["y"])
        self.assertEqual(rc, 1)
        rc, out, _err = self.cli("ignore", rec["id"], *self.flags(), replies=["n"])
        self.assertIn("Nothing was added.", out)
        rc, out, _err = self.cli("ignore", rec["id"], *self.flags(), replies=["y"])
        self.assertEqual(rc, 0)
        self.assertIn("This action changed what ranwhat reports.", " ".join(out.split()))
        line, = self.entries()
        self.assertTrue(line.startswith("%s ack  # agent.config" % rec["id"]), line)
        listed, err = self.watched()
        self.assertEqual(listed, [])
        rc, out, _err = self.cli("watch", *self.flags())
        self.assertIn("1 change an agent made to ranwhat's own settings is not listed: "
                      "you acknowledged it on line 20", " ".join(out.split()))

    def test_a_plain_id_line_does_not_acknowledge(self):
        self.history("echo publish >> ~/.ranwhat/ignore")
        (rec,), _err = self.watched()
        os.makedirs(self.state, exist_ok=True)
        with open(self.file, "w", encoding="utf-8") as fh:
            fh.write(rec["id"] + "\n")
        listed, err = self.watched()
        self.assertEqual(len(listed), 1)
        self.assertIn("is listed though", err)
        rc, out, _err = self.cli("ignore", rec["id"], *self.flags(), replies=["y"])
        self.assertEqual(rc, 0)
        self.assertIn("Acknowledged in", " ".join(out.split()))
        self.assertEqual(self.watched()[0], [])

    def test_a_secret_named_already_is_said_to_be_listed(self):
        self.history("rm -rf ~/Documents/x; echo %s" % STRIPE)
        (rec,), _err = self.watched()
        self.cli("ignore", rec["id"], "--no-interactive", *self.flags())
        rc, out, _err = self.cli("ignore", rec["id"], *self.flags())
        self.assertEqual(rc, 0)
        self.assertIn("and listed all the same: it holds a secret",
                      " ".join(out.split()))
        self.assertEqual(len(self.entries()), 1)

    def test_errors(self):
        self.history("git push --force origin main")
        rc, _out, err = self.cli("ignore", "3fa9", *self.flags())
        self.assertEqual(rc, 2)
        self.assertIn("3fa9 is not an action id: an id is the 16 characters watch "
                      "prints beside an action's time", err)
        rc, _out, err = self.cli("ignore", "publish", *self.flags())
        self.assertEqual(rc, 2)
        self.assertIn("not 'publish'", err)
        rc, _out, err = self.cli("ignore", "0123456789abcdef", *self.flags())
        self.assertEqual(rc, 1)
        self.assertIn("no action with id 0123456789abcdef in the last 30 days of "
                      "history; give the --days, --source and --path it was listed "
                      "with.", " ".join(err.split()))


class All(_Cli):

    def test_a_baseline(self):
        self.history("git push --force origin main", "npm publish",
                     "rm -rf ~/Documents/x; echo %s" % STRIPE,
                     "echo publish >> ~/.ranwhat/ignore")
        rc, out, _err = self.cli("ignore", "all", *self.flags())
        self.assertEqual(rc, 0)
        said = " ".join(out.split())
        self.assertIn("Left out 3 actions from the last 30 days (2 critical, 1 high).",
                      said)
        self.assertIn("Added to %s (lines 21-23)." % ignore.shown(self.file), said)
        self.assertIn("1 of them holds a secret, and stays listed until ranwhat clean "
                      "masks it", said)
        self.assertIn("1 action that changed ranwhat's own settings was not added: "
                      "acknowledge it on a terminal with ranwhat ignore", said)
        self.assertRegex(self.text(), r"\n# ranwhat ignore all, \d{4}-\d\d-\d\d "
                                      r"\d\d:\d\d, last 30 days: 3 actions\n")
        listed, err = self.watched()
        # the secret and the change to ranwhat's settings stay listed
        self.assertEqual(sorted(r["severity"] for r in listed), ["critical"] * 2)
        self.assertEqual(sorted(h["rule"] for r in listed for h in r["hits"]),
                         ["agent.config", "fs.destructive", "secret.literal"])
        self.assertIn("2 actions are not in this output", err)
        rc, out, _err = self.cli("ignore", "all", *self.flags())
        self.assertEqual(rc, 0)
        self.assertIn("Nothing to add: every other action from the last 30 days is "
                      "left out already.", " ".join(out.split()))
        self.assertEqual(len(self.entries()), 3)

    def test_every_copy_is_written(self):
        entry = ti.bash("toolu_1", "rm -rf ~/Documents/x", self.now)
        entry["message"]["content"].append(dict(entry["message"]["content"][0],
                                                id="toolu_2"))
        self.transcript([entry])
        (rec,), _err = self.watched()
        self.assertEqual(len(rec["ids"]), 2)
        self.cli("ignore", "all", *self.flags())
        line, = self.entries()
        self.assertTrue(line.startswith(" ".join(rec["ids"]) + "  # "), line)

    def test_nothing_read(self):
        rc, _out, err = self.cli("ignore", "all", *self.flags())
        self.assertEqual(rc, 2)
        self.assertIn("No transcripts found", err)
        self.assertFalse(os.path.exists(self.file))

    def test_end_to_end(self):
        self.history("git push --force origin main", "rm -rf ~/Documents/x")
        self.cli("ignore", "all", *self.flags())
        rc, out, _err = self.cli("watch", *self.flags())
        said = " ".join(out.split())
        self.assertIn("Nothing flagged that is not ignored.", said)
        self.assertIn("2 actions are not listed: %s leaves out 2 by id."
                      % ignore.shown(self.file), said)
        self.assertNotIn("Nothing flagged.", said)
        # one new action is listed alone
        self.history("git push --force origin main", "rm -rf ~/Documents/x",
                     "git reset --hard")
        listed, err = self.watched()
        self.assertEqual([r["hits"][0]["evidence"] for r in listed], ["git reset --hard"])
        self.assertIn("2 actions are not in this output", err)
        # and acknowledged by stdin, as a cron job does
        _rc, report, _err = self.cli("watch", "--json", *self.flags())
        rc, out, _err = self.cli("ignore", "-", *self.flags(), stdin=report)
        self.assertEqual(rc, 0)
        self.assertIn("Added 1 action to", out)
        self.assertEqual(self.watched()[0], [])


class Stdin(_Cli):

    def test_both_shapes_and_junk(self):
        self.history("git push --force origin main", "rm -rf ~/Documents/x",
                     "echo publish >> ~/.ranwhat/ignore")
        _rc, watched, _err = self.cli("watch", "--json", *self.flags())
        rc, out, _err = self.cli("ignore", "-", *self.flags(), stdin=watched)
        self.assertEqual(rc, 0)
        said = " ".join(out.split())
        self.assertIn("Added 2 actions to", said)
        self.assertIn("1 action that changed ranwhat's own settings was not added",
                      said)
        _rc, checked, _err = self.cli("check", "--json", "--no-ignore", *self.flags())
        rc, out, _err = self.cli("ignore", "-", "--json", *self.flags(), stdin=checked)
        self.assertEqual(json.loads(out), {"file": self.file, "added": 0, "lines": [],
                                           "skipped": {"guard": 1, "present": 2}})
        for junk in ("", "not json", "{}", '{"actions": 3}', "[1]"):
            rc, _out, err = self.cli("ignore", "-", *self.flags(), stdin=junk)
            self.assertEqual(rc, 1, junk)
            self.assertIn("stdin is not the JSON ranwhat watch --json or check --json "
                          "prints.", err)


class File(_Cli):

    @unittest.skipIf(os.name == "nt", "POSIX modes")
    def test_made_0600_in_a_0700_folder(self):
        ignore.add(self.file, [(["0" * 16], "0" * 16)], default=True)
        self.assertEqual(stat.S_IMODE(os.stat(self.state).st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(os.stat(self.file).st_mode), 0o600)
        # a folder there already is left as it is, and the file made 0600
        os.remove(self.file)
        os.chmod(self.state, 0o750)
        self.history("git push --force origin main")
        self.cli("ignore", "all", *self.flags())
        self.assertEqual(stat.S_IMODE(os.stat(self.state).st_mode), 0o750)
        self.assertEqual(stat.S_IMODE(os.stat(self.file).st_mode), 0o600)

    @unittest.skipIf(os.name == "nt", "symlinks")
    def test_a_linked_file_is_read_and_written_through(self):
        self.history("git push --force origin main", "rm -rf ~/Documents/x")
        os.makedirs(self.state, exist_ok=True)
        real = os.path.join(self.tmp, "dotfiles", "ranwhat-ignore")
        os.makedirs(os.path.dirname(real))
        with open(real, "w", encoding="utf-8") as fh:
            fh.write("git.destructive\n")
        os.symlink(real, self.file)
        listed, _err = self.watched()
        self.assertEqual([r["hits"][0]["rule"] for r in listed], ["fs.destructive"])
        self.cli("ignore", "all", *self.flags())
        self.assertTrue(os.path.islink(self.file))
        with open(real, encoding="utf-8") as fh:
            self.assertEqual(len([l for l in fh.read().split("\n") if l]), 3)
        self.assertEqual(self.watched()[0], [])

    @unittest.skipIf(os.name == "nt", "POSIX modes")
    def test_a_file_others_may_write_is_not_used(self):
        self.history("git push --force origin main")
        os.makedirs(self.state, exist_ok=True)
        with open(self.file, "w", encoding="utf-8") as fh:
            fh.write("git.destructive\n")
        os.chmod(self.file, 0o666)
        listed, err = self.watched()
        self.assertEqual(len(listed), 1)
        self.assertIn("can be written by other users, so it was not used: nothing is "
                      "ignored.", err)
        rc, out, _err = self.cli("watch", *self.flags())
        self.assertIn("so it was not used", " ".join(out.split()))
        rc, _out, err = self.cli("watch", "--ignore", self.file, *self.flags())
        self.assertEqual(rc, 1)
        self.assertIn("cannot use --ignore %s (it can be written by other users)"
                      % self.file, err)
        rc, _out, err = self.cli("ignore", "all", *self.flags())
        self.assertEqual(rc, 1)
        self.assertIn("chmod o-w it first. Nothing was added.", " ".join(err.split()))
        rc, _out, _err = self.cli("ignore", *self.flags())
        self.assertEqual(rc, 3)
        with mock.patch("os.geteuid", return_value=os.geteuid() + 1):
            os.chmod(self.file, 0o600)
            listed, err = self.watched()
        self.assertEqual(len(listed), 1)
        self.assertIn("belongs to another user", err)

    def test_an_oversize_file_is_not_used(self):
        self.history("git push --force origin main")
        os.makedirs(self.state, exist_ok=True)
        with open(self.file, "w", encoding="utf-8") as fh:
            fh.write("git.destructive\n")
        with mock.patch.object(ignore, "MAX_BYTES", 4):
            listed, err = self.watched()
            rc, _out, _err = self.cli("watch", "--ignore", self.file, *self.flags())
        self.assertEqual(len(listed), 1)
        self.assertIn("larger than", err)
        self.assertEqual(rc, 1)

    def test_two_adds_at_once_both_land_and_none_twice(self):
        ids = ["%016x" % n for n in range(40)]
        go = threading.Barrier(2)

        def adding(mine):
            go.wait()
            for i in mine:
                ignore.add(self.file, [([i], "%s  # x" % i)], default=True)
        threads = [threading.Thread(target=adding, args=(ids[k::2],)) for k in (0, 1)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(sorted(l.split()[0] for l in self.entries()), ids)
        first, last, there = ignore.add(self.file, [([ids[0]], ids[0])])
        self.assertEqual((first, last, there), (None, None, 1))
        self.assertEqual(len(self.entries()), 40)

    def test_a_lock_held_too_long(self):
        os.makedirs(self.state, exist_ok=True)
        with mock.patch.object(ignore.known, "_LOCK_WAIT", 0.1):
            with ignore.known._locked(os.path.realpath(self.file) + ".lock"):
                with self.assertRaises(ignore.IgnoreError) as raised:
                    ignore.add(self.file, [(["0" * 16], "0" * 16)])
        self.assertIn("another ranwhat is writing", str(raised.exception))


class Flags(_Cli):

    def test_who_takes_which(self):
        rc, _out, err = self.cli("clean", "--ignore", "x")
        self.assertEqual(rc, 2)
        self.assertIn("--ignore is only for check, watch, ignore and push; clean leaves a "
                      "secret alone with keep, in its review", err)
        for argv in (["ignore", "--no-ignore"], ["clean", "--no-ignore"],
                     ["sources", "--no-ignore"]):
            rc, _out, err = self.cli(*argv)
            self.assertEqual(rc, 2, argv)
            self.assertIn("--no-ignore is only for check and watch", err)
        for argv in (["ignore", "--fail-on", "high"], ["ignore", "--sarif", "x"]):
            rc, _out, err = self.cli(*argv)
            self.assertEqual(rc, 2, argv)
            self.assertIn("only for check, watch and clean", err)
        rc, _out, err = self.cli("ignore", "all", "--apply")
        self.assertEqual(rc, 2)
        self.assertIn("ignore takes only --days, --source, --path, --root, "
                      "--state-dir, --ignore, --no-interactive and --json, not --apply",
                      err)

    def test_ignore_and_no_ignore_mark(self):
        self.history("git push --force origin main", "rm -rf ~/Documents/x")
        committed = os.path.join(self.tmp, ".ranwhatignore")
        with open(committed, "w", encoding="utf-8") as fh:
            fh.write("git.destructive\n")
        listed, err = self.watched("--ignore", committed, "--no-ignore")
        self.assertEqual(len(listed), 2)
        marked = {r["hits"][0]["rule"]: r.get("ignored") for r in listed}
        self.assertEqual(marked, {"git.destructive": [1], "fs.destructive": None})
        self.assertEqual(err, "")
        rc, out, _err = self.cli("watch", "--ignore", committed, "--no-ignore",
                                 *self.flags())
        said = " ".join(out.split())
        self.assertIn("(ignored by line 1)", said)
        self.assertIn("--no-ignore: 1 action above is one %s leaves out; it is marked "
                      "with the line that does." % ignore.shown(committed), said)
        # the default file is not read when --ignore names one
        os.makedirs(self.state, exist_ok=True)
        with open(self.file, "w", encoding="utf-8") as fh:
            fh.write("fs.destructive\n")
        listed, _err = self.watched("--ignore", committed)
        self.assertEqual([r["hits"][0]["rule"] for r in listed], ["fs.destructive"])


class EveryLineFits(_Cli):
    """The id at the end of each action, the lines that would leave it out,
    the notes, the menu and the list all fit the narrowest terminal."""

    def test_at_every_width(self):
        self.history("npm publish", "git push --force origin main",
                     "rm -rf ~/Documents/x", "echo publish >> ~/.ranwhat/ignore",
                     cwd=self.mylib)
        listed, _err = self.watched()
        by_rule = {r["hits"][0]["rule"]: r for r in listed}
        publish, delete = by_rule["publish"], by_rule["fs.destructive"]
        guard = by_rule["agent.config"]
        os.makedirs(self.state, exist_ok=True)
        with open(self.file, "w", encoding="utf-8") as fh:
            fh.write("git.destructive 'git push --force origin main'\n"
                     "publish 'npm publish'\npublsh\n"
                     "fs.destructive until=2020-01-01\n%s\n%s ack\n"
                     % (delete["id"], guard["id"]))
        for width in ("46", "60", "80"):
            with mock.patch.dict(os.environ, {"RANWHAT_WIDTH": width}):
                limit = int(width) - 2 if int(width) > 48 else 46
                runs = [self.cli("watch", *self.flags()),
                        self.cli("watch", "--no-ignore", *self.flags()),
                        self.cli("check", *self.flags()),
                        self.cli("ignore", *self.flags()),
                        self.cli("ignore", publish["id"], *self.flags(),
                                 replies=["c"])]
                for rc, out, _err in runs:
                    for line in out.split("\n"):
                        if line.startswith("    ranwhat check --json"):
                            continue                # a command to paste
                        if line.strip().rstrip(":.") in (self.file,
                                                        ignore.shown(self.file)):
                            continue                # a path, never cut
                        self.assertLessEqual(len(line), limit, (width, line))
                self.assertIn("(ignored by line 1)", runs[1][1])
                self.assertIn("(ignored by line 5)", runs[1][1])
                self.assertIn("matches 1 critical action but does not leave it out",
                              " ".join(runs[0][1].split()))


class Reports(_Cli):

    def test_check_json_says_what_it_left_out_only_when_it_did(self):
        self.history("git push --force origin main", "npm publish")
        _rc, out, _err = self.cli("check", "--json", *self.flags())
        self.assertNotIn("ignored", json.loads(out))
        os.makedirs(self.state, exist_ok=True)
        with open(self.file, "w", encoding="utf-8") as fh:
            fh.write("git.destructive\npublish 'npm publish'\nbogus\n")
        rc, out, err = self.cli("check", "--json", *self.flags())
        doc = json.loads(out)
        self.assertEqual(rc, 0)
        self.assertEqual(len(doc["actions"]), 1)
        self.assertEqual(doc["ignored"], {
            "file": self.file, "applied": True, "actions": 1, "critical": 0,
            "by_id": 0, "acknowledged": 0,
            "entries": [{"line": 1, "entry": "git.destructive", "actions": 1}],
            "listed_anyway": [{"line": 2, "actions": 1, "missing": ["in=", "until="]}],
            "secret_listed": 0, "guard_listed": 0, "expired": [],
            "skipped": [{"line": 3, "why": "there is no rule bogus"}],
            "unused": None})

    def test_watch_json_stays_a_list_and_says_the_rest_on_stderr(self):
        self.history("git push --force origin main", "rm -rf ~/Documents/x")
        os.makedirs(self.state, exist_ok=True)
        with open(self.file, "w", encoding="utf-8") as fh:
            fh.write("git.destructive\n")
        rc, out, err = self.cli("watch", "--json", *self.flags())
        self.assertIsInstance(json.loads(out), list)
        self.assertEqual(err, "ranwhat: 1 action is not in this output: %s leaves it "
                              "out (1 by line 1). --no-ignore includes it.\n"
                         % ignore.shown(self.file))

    def test_the_text_report_counts_and_marks(self):
        self.history("git push --force origin main", "rm -rf ~/Documents/x")
        os.makedirs(self.state, exist_ok=True)
        with open(self.file, "w", encoding="utf-8") as fh:
            fh.write("git.destructive\n")
        rc, out, _err = self.cli("watch", *self.flags())
        said = " ".join(out.split())
        self.assertIn("1 high (1 ignored)", said)
        listed, _err = self.watched()
        self.assertIn(listed[0]["id"], out)
        rc, out, _err = self.cli("check", *self.flags())
        said = " ".join(out.split())
        self.assertIn("1 high (1 ignored)", said)
        self.assertIn("1 action is not listed: %s leaves it out by line 1 "
                      "(git.destructive). --no-ignore lists it."
                      % ignore.shown(self.file), said)

    def test_a_suggested_command_carries_the_file(self):
        self.history("git push --force origin main", "rm -rf ~/Documents/x")
        committed = os.path.join(self.tmp, "committed")
        with open(committed, "w", encoding="utf-8") as fh:
            fh.write("git.destructive\n")
        rc, out, _err = self.cli("check", "--ignore", committed, *self.flags())
        self.assertIn("check --json", out)
        self.assertIn("--ignore %s" % committed, " ".join(out.split()))


class ReviewRoundOne(_Cli):
    """What the first review of ranwhat ignore found, one test each."""

    def test_a_suggested_command_reads_and_writes_what_the_run_did(self):
        # Bare, `ignore all` after `watch --days 90` baselined 30 days, and
        # an ack after `--ignore X` was written to the default file.
        args = cli.argparse.Namespace(days=90, root=self.claude, state_dir=None,
                                      source=[], pointed={}, ignore=self.file,
                                      no_ignore=True)
        said = cli._ignore_cmd(args, "all")
        self.assertIn("ranwhat ignore all --days 90 --root", said)
        self.assertIn("--ignore %s" % self.file, said)
        self.assertNotIn("--no-ignore", said)         # ignore refuses it
        self.history("echo publish >> ~/.ranwhat/ignore")
        os.makedirs(self.state, exist_ok=True)
        with open(self.file, "w", encoding="utf-8") as fh:
            fh.write(ignore.HEADER)
        (rec,), _err = self.watched("--ignore", self.file)
        extra = ["--days", "90", "--ignore", self.file]
        rc, _out, err = self.cli("ignore", rec["id"], *(extra + self.flags()))
        self.assertEqual(rc, 1)
        self.assertIn("with ranwhat ignore %s --days 90 --root" % rec["id"],
                      " ".join(err.split()))
        self.assertIn("--ignore %s" % self.file, " ".join(err.split()))
        rc, out, _err = self.cli("ignore", "all", *(extra + self.flags()))
        self.assertIn("acknowledge it on a terminal with ranwhat ignore %s --days 90"
                      % rec["id"], " ".join(out.split()))

    def test_option_1_on_a_secret_does_not_say_it_is_no_longer_listed(self):
        self.history("rm -rf ~/Documents/x; echo %s" % STRIPE)
        (rec,), _err = self.watched()
        rc, out, _err = self.cli("ignore", rec["id"], *self.flags(), replies=["1"])
        said = " ".join(out.split())
        self.assertIn("1 this action only (it holds a secret, so it stays listed)", said)
        self.assertIn("It holds a secret, so watch and check list it until ranwhat "
                      "clean masks it", said)
        self.assertNotIn("no longer list this action", said)
        self.assertEqual(len(self.watched()[0]), 1)

    def test_ignore_all_says_what_it_left_listed_the_second_time(self):
        self.history("rm -rf ~/Documents/x; echo %s" % STRIPE)
        self.cli("ignore", "all", *self.flags())
        rc, out, _err = self.cli("ignore", "all", *self.flags())
        said = " ".join(out.split())
        self.assertIn("Nothing to add: every action from the last 30 days is left "
                      "out already.", said)
        self.assertIn("1 of them holds a secret, and stays listed until ranwhat "
                      "clean masks it", said)

    def test_the_list_folds_an_entry_and_never_cuts_it(self):
        os.makedirs(self.state, exist_ok=True)
        long_in = "~/work/mylib/packages/some/very/deeply/nested/package/folder"
        with open(self.file, "w", encoding="utf-8") as fh:
            fh.write(ignore.HEADER
                     + "publish 'npm publish --access public --tag latest' in=%s "
                       "until=2027-01-31\n" % long_in
                     + "exec.remote 'curl -s https://example.com/install.sh | sh' extra\n")
        rc, out, _err = self.cli("ignore")
        self.assertEqual(rc, 3)
        self.assertNotIn("\N{HORIZONTAL ELLIPSIS}", out)
        for line in out.split("\n"):
            if line.strip().rstrip(":.") in (self.file, ignore.shown(self.file)):
                continue                            # a path, never cut
            self.assertLessEqual(len(line), 80, line)
        said = " ".join(out.split())
        self.assertIn("in=%s until=2027-01-31" % long_in, said)
        rc, js, _err = self.cli("ignore", "--json")
        (skipped,) = json.loads(js)["skipped"]
        self.assertIn(skipped["why"], said)

    def test_a_report_names_the_actions_file_by_its_label_and_suggests_no_temp_path(self):
        self.history("git push --force origin main", "rm -rf ~/Documents/x")
        temp = os.path.join(self.tmp, "ranwhat-ignore.AbC123")
        with open(temp, "w", encoding="utf-8") as fh:
            fh.write("git.destructive\npubish x\n")
        env = {ignore.LABEL_ENV: ".ranwhatignore at 0123456789ab",
               ignore.LABEL_FILE_ENV: temp}
        with mock.patch.dict(os.environ, env):
            rc, out, _err = self.cli("check", "--ignore", temp, *self.flags())
        said = " ".join(out.split())
        self.assertIn("Line 2 of .ranwhatignore at 0123456789ab is not an entry", said)
        self.assertNotIn(temp, said)
        self.assertNotIn("--ignore", said)            # no temporary path to paste
        # not in the Action, or another file named in its args: the path
        rc, out, _err = self.cli("check", "--ignore", temp, *self.flags())
        self.assertIn("--ignore %s" % temp, " ".join(out.split()))
        other = temp + "2"
        with open(other, "w", encoding="utf-8") as fh:
            fh.write("pubish x\n")
        with mock.patch.dict(os.environ, env):
            rc, out, _err = self.cli("check", "--ignore", other, *self.flags())
        self.assertIn("Line 1 of %s is not an entry" % ignore.shown(other),
                      " ".join(out.split()))

    def test_a_file_of_junk_names_a_few_lines_and_counts_the_rest(self):
        self.history("git push --force origin main", "rm -rf ~/Documents/x")
        os.makedirs(self.state, exist_ok=True)
        with open(self.file, "w", encoding="utf-8") as fh:
            fh.write("".join("bogus%d x\n" % i for i in range(300)))
        rc, out, _err = self.cli("watch", *self.flags())
        said = " ".join(out.split())
        self.assertEqual(said.count("was skipped"), ignore.SKIPPED_SHOWN)
        self.assertIn("295 more lines of", said)
        self.assertLess(len(out.split("\n")), 120)
        rc, _out, err = self.cli("watch", "--json", *self.flags())
        self.assertLess(len(err.split("\n")), 20)
        rc, js, _err = self.cli("check", "--json", *self.flags())
        doc = json.loads(js)["ignored"]
        self.assertEqual((len(doc["skipped"]), doc["skipped_total"]),
                         (ignore.SKIPPED_KEPT, 300))


if __name__ == "__main__":
    unittest.main()
