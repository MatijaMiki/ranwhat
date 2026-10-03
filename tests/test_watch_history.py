"""Where watch looks, what it found there, and which actions it counts.

An empty report used to read as an all-clear: a mistyped --root, a fresh
machine, or Claude Code keeping its data under CLAUDE_CONFIG_DIR all printed
"Nothing flagged. Every tool call was read". Having nothing to read is not
the same as reading everything and finding nothing, so the two now say
different things, and the empty one says where it looked.

The header counted transcripts but called them sources, and its window was
the file's mtime, so a 2025 deletion in a transcript touched today was
listed under "over 1 days". Actions are now windowed by their own time.

Every value here is synthetic.
"""
import contextlib
import datetime
import io
import json
import os
import re
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
from ranwhat import cli, term, watch

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ANSI = re.compile(r"\033\[[0-9;]*m")

OLD = "2025-01-05T09:00:00Z"          # the repro: long before any window


def plain(text):
    return ANSI.sub("", text)


def utc(seconds_ago):
    return datetime.datetime.fromtimestamp(
        time.time() - seconds_ago, datetime.timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%S.000Z")


def tool_use(command, i, stamp):
    entry = {"message": {"role": "assistant", "content": [
        {"type": "tool_use", "id": "t%d" % i, "name": "Bash",
         "input": {"command": command}}]}}
    if stamp is not None:
        entry["timestamp"] = stamp
    return entry


def make_root(rows, age_days=0):
    root = tempfile.mkdtemp(prefix="watch-hist-")
    proj = os.path.join(root, "-tmp-synthetic")
    os.makedirs(proj)
    path = os.path.join(proj, "s.jsonl")
    with open(path, "w", encoding="utf-8") as fh:
        for r in rows:
            fh.write(json.dumps(r) + "\n")
    if age_days:
        then = time.time() - age_days * 86400
        os.utime(path, (then, then))
    return root


def make_openclaw(rows, time_col="createdAt"):
    """An OpenClaw state dir holding (command, epoch) rows."""
    state = tempfile.mkdtemp(prefix="watch-hist-oc-")
    path = os.path.join(state, "agents", "a1", "agent", "openclaw-agent.sqlite")
    os.makedirs(os.path.dirname(path))
    conn = sqlite3.connect(path)
    cols = '(id TEXT, body TEXT%s)' % (', "%s" INTEGER' % time_col
                                        if time_col else "")
    conn.execute("CREATE TABLE log " + cols)
    for i, (command, epoch) in enumerate(rows):
        body = json.dumps({"content": [{"type": "tool_use", "name": "bash",
                                        "input": {"command": command}}]})
        values = (str(i), body) + ((epoch,) if time_col else ())
        conn.execute("INSERT INTO log VALUES (%s)"
                     % ",".join("?" * len(values)), values)
    conn.commit()
    conn.close()
    return state


def commands(records):
    return sorted(h["evidence"] for r in records for h in r["hits"])


def run_cli(argv):
    out = io.StringIO()
    with contextlib.redirect_stdout(out), \
            contextlib.redirect_stderr(io.StringIO()):
        try:
            rc = cli.main(argv)
        except SystemExit as e:
            rc = e.code
    return rc, out.getvalue()


REC = {"severity": "high", "timestamp": utc(3600), "tool_name": "Bash",
       "hits": [{"title": "T", "severity": "high", "evidence": "e",
                 "why": "W."}]}


class _Width(unittest.TestCase):

    def setUp(self):
        env = mock.patch.dict(os.environ, {"RANWHAT_WIDTH": "60"})
        env.start()
        self.addCleanup(env.stop)

    def assertFits(self, text, width):
        for line in plain(text).split("\n"):
            self.assertLessEqual(len(line), width, repr(line))


class DefaultRoot(unittest.TestCase):
    """Claude Code keeps its data in $CLAUDE_CONFIG_DIR when that is set,
    and ranwhat read only ~/.claude/projects."""

    def env(self, **values):
        patch = mock.patch.dict(os.environ, values)
        patch.start()
        self.addCleanup(patch.stop)

    def home(self, path):
        """Home for ~, on POSIX ($HOME) and on Windows, where expanduser
        has read USERPROFILE and not HOME since Python 3.8."""
        self.env(HOME=path, USERPROFILE=path)

    def assertSamePath(self, a, b):
        """The same place, absolute as the adapter's location is: on
        Windows /synthetic is on the current drive."""
        self.assertEqual(a, os.path.abspath(b))

    def test_claude_config_dir_moves_the_projects_directory(self):
        self.env(CLAUDE_CONFIG_DIR="/synthetic/claude-config")
        self.assertSamePath(watch.claude_projects(),
                            os.path.join("/synthetic/claude-config", "projects"))

    def test_a_home_relative_config_dir_is_expanded(self):
        self.home("/synthetic/home")
        self.env(CLAUDE_CONFIG_DIR="~/elsewhere")
        self.assertSamePath(watch.claude_projects(),
                            os.path.join("/synthetic/home", "elsewhere", "projects"))

    def test_unset_or_empty_is_the_usual_place(self):
        self.home("/synthetic/home")
        self.env(CLAUDE_CONFIG_DIR="")
        usual = os.path.join("/synthetic/home", ".claude", "projects")
        self.assertSamePath(watch.claude_projects(), usual)
        os.environ.pop("CLAUDE_CONFIG_DIR")
        self.assertSamePath(watch.claude_projects(), usual)

    def test_scanning_with_no_root_reads_the_config_dir_when_asked(self):
        cfg = tempfile.mkdtemp(prefix="watch-hist-cfg-")
        os.rename(make_root([tool_use("rm -rf ~/Documents/a", 1, utc(60))]),
                  os.path.join(cfg, "projects"))
        self.env(CLAUDE_CONFIG_DIR=cfg, HOME=tempfile.mkdtemp())
        records, scanned = watch.scan_sources(sources=("claude-code",))
        self.assertEqual((scanned, len(records)), (1, 1))
        self.assertEqual(len(watch.discover()), 1)

    def test_watch_and_clean_both_follow_it_from_the_command_line(self):
        """Resolved when the process starts, so the --root default and
        clean's, which share watch.CLAUDE_PROJECTS, stay in step."""
        cfg = tempfile.mkdtemp(prefix="watch-hist-cfg-")
        os.rename(make_root([tool_use("rm -rf ~/Documents/a", 1, utc(60))]),
                  os.path.join(cfg, "projects"))
        env = dict(os.environ, CLAUDE_CONFIG_DIR=cfg, PYTHONPATH=REPO,
                   HOME=tempfile.mkdtemp(prefix="watch-hist-home-"),
                   OPENCLAW_STATE_DIR=tempfile.mkdtemp(prefix="watch-hist-oc-"))

        def run(*argv):
            return subprocess.run([sys.executable, "-m", "ranwhat"] + list(argv),
                                  env=env, cwd=REPO, capture_output=True,
                                  text=True, timeout=120)
        const = subprocess.run(
            [sys.executable, "-c", "from ranwhat import watch\n"
             "print(watch.CLAUDE_PROJECTS)"],
            env=env, cwd=REPO, capture_output=True, text=True, timeout=60)
        self.assertEqual(const.stdout.strip(), os.path.join(cfg, "projects"))
        watched = json.loads(run("watch", "--json").stdout)
        self.assertEqual(len(watched), 1)
        cleaned = json.loads(run("clean", "--json", "--no-interactive").stdout)
        self.assertEqual(cleaned["scanned"], 1)


class Locations(unittest.TestCase):

    def test_names_each_place_and_counts_what_is_there_whatever_its_age(self):
        root = make_root([tool_use("ls", 1, OLD)], age_days=400)
        state = make_openclaw([("ls", 1736067600)])
        found = watch.locations(root=root, state_dir=state)
        self.assertEqual(
            [(p["source"], p["path"], p["found"]) for p in found],
            [("claude-code", root, 1), ("openclaw", state, 1)])
        json.dumps(found)                 # usable as it is in --json

    def test_a_missing_place_is_zero_not_an_error(self):
        found = watch.locations(root="/nonexistent/ranwhat-root",
                                state_dir="/nonexistent/ranwhat-state")
        self.assertEqual([p["found"] for p in found], [0, 0])

    def test_only_the_sources_asked_for(self):
        found = watch.locations(sources=("openclaw",),
                                state_dir="/nonexistent/ranwhat-state")
        self.assertEqual([p["source"] for p in found], ["openclaw"])


class NothingToReadIsNotAnAllClear(_Width):

    NOWHERE = {"root": "/nonexistent/ranwhat-root",
               "state_dir": "/nonexistent/ranwhat-state"}

    def assertNotAllClear(self, text):
        self.assertNotIn("Nothing flagged", text)
        self.assertNotIn("Every call was read", text)

    def test_no_transcripts_says_so_and_where_it_looked(self):
        text = plain(watch.render([], 0, 30,
                                  locations=watch.locations(**self.NOWHERE)))
        self.assertNotAllClear(text)
        self.assertIn("No transcripts found", text)
        self.assertIn("/nonexistent/ranwhat-root", text)
        self.assertIn("/nonexistent/ranwhat-state", text)
        for hint in ("--root", "CLAUDE_CONFIG_DIR", "--state-dir"):
            self.assertIn(hint, text)

    def test_without_locations_it_still_is_not_an_all_clear(self):
        text = plain(watch.render([], 0, 30))
        self.assertNotAllClear(text)
        self.assertIn("No transcripts found", text)
        self.assertIn("--root", text)
        self.assertIn("CLAUDE_CONFIG_DIR", text)

    def test_advice_is_for_the_sources_asked_about(self):
        text = plain(watch.render([], 0, 30, locations=watch.locations(
            sources=("openclaw",), state_dir="/nonexistent/ranwhat-state")))
        self.assertIn("--state-dir", text)
        self.assertNotIn("CLAUDE_CONFIG_DIR", text)

    def test_older_transcripts_only_points_at_days_not_root(self):
        root = make_root([tool_use("rm -rf ~/Documents/a", 1, OLD)],
                         age_days=60)
        records, scanned = watch.scan_all(root=root, since_days=30)
        self.assertEqual((records, scanned), ([], 0))
        text = plain(watch.render(records, scanned, 30,
                                  locations=watch.locations(
                                      root=root, state_dir=self.NOWHERE[
                                          "state_dir"])))
        self.assertNotAllClear(text)
        self.assertNotIn("No transcripts found", text)
        self.assertIn("--days", text)
        self.assertIn("1 older transcript", text)

    def test_read_and_clean_is_still_an_all_clear(self):
        text = plain(watch.render([], 3, 30))
        self.assertIn("Nothing flagged.", text)
        self.assertNotIn("No transcripts found", text)

    def test_every_line_fits_however_long_the_path(self):
        deep = "/nonexistent/" + "a-rather-long-directory-name/" * 5
        for width in ("46", "60", "80"):
            with mock.patch.dict(os.environ, {"RANWHAT_WIDTH": width}):
                text = watch.render([], 0, 30, locations=watch.locations(
                    root=deep, state_dir=deep))
                self.assertFits(text, term.width())

    def test_no_em_dashes(self):
        text = watch.render([], 0, 30, locations=watch.locations(**self.NOWHERE))
        self.assertNotIn("\u2014", text)

    def test_the_commands_do_not_print_an_all_clear(self):
        for command in ("watch", "check"):
            _, out = run_cli([command, "--root", "/nonexistent/ranwhat-root",
                              "--state-dir", "/nonexistent/ranwhat-state"])
            self.assertNotAllClear(out)
            self.assertIn("No transcripts found", out)


class Header(_Width):

    def test_counts_transcripts_as_clean_does(self):
        text = plain(watch.render([REC], 4, 30))
        self.assertIn("  4 transcript(s) scanned, last 30 days\n", text)
        self.assertNotIn("source(s)", text)

    def test_one_day_is_singular(self):
        text = plain(watch.render([REC], 1, 1))
        self.assertIn("last 1 day\n", text)
        self.assertNotIn("1 days", text)


class WindowByActionTime(_Width):
    """--days is about when an action happened, not when its file was last
    written. mtime stays as a prefilter only."""

    def rows(self):
        return [tool_use("rm -rf ~/Documents/thesis", 1, OLD),
                tool_use("rm -rf ~/Documents/recent", 2, utc(3600)),
                tool_use("rm -rf ~/Documents/undated", 3, None),
                tool_use("rm -rf ~/Documents/odd", 4, "yesterday")]

    def test_an_old_action_in_a_fresh_file_is_outside_the_window(self):
        records, scanned = watch.scan_all(root=make_root(self.rows()),
                                          since_days=1)
        self.assertEqual(scanned, 1)
        found = " ".join(commands(records))
        self.assertNotIn("thesis", found)
        self.assertIn("recent", found)

    def test_actions_with_no_readable_time_are_kept(self):
        records, _ = watch.scan_all(root=make_root(self.rows()), since_days=1)
        found = " ".join(commands(records))
        self.assertIn("undated", found)
        self.assertIn("odd", found)

    def test_no_window_keeps_everything(self):
        records, _ = watch.scan_all(root=make_root(self.rows()))
        self.assertEqual(len(records), 4)

    def test_a_file_older_than_the_window_is_not_read(self):
        root = make_root([tool_use("rm -rf ~/Documents/a", 1, None)],
                         age_days=10)
        self.assertEqual(watch.scan_all(root=root, since_days=5), ([], 0))
        self.assertEqual(watch.scan_all(root=root, since_days=11)[1], 1)

    def test_openclaw_actions_are_windowed_too(self):
        state = make_openclaw([("rm -rf ~/Documents/thesis", 1736067600),
                               ("rm -rf ~/Documents/recent",
                                int(time.time()) - 3600)])
        records, n = watch.scan_sources(sources=("openclaw",),
                                        state_dir=state, since_days=1)
        self.assertEqual(n, 1)
        found = " ".join(commands(records))
        self.assertIn("recent", found)
        self.assertNotIn("thesis", found)

    def test_openclaw_rows_with_no_time_are_kept(self):
        state = make_openclaw([("rm -rf ~/Documents/undated", None)],
                              time_col=None)
        records, _ = watch.scan_sources(sources=("openclaw",),
                                        state_dir=state, since_days=1)
        self.assertEqual(len(records), 1)

    def test_the_repro_from_the_command_line(self):
        root = make_root([tool_use("rm -rf ~/Documents/thesis", 1, OLD)])
        state = tempfile.mkdtemp(prefix="watch-hist-oc-")
        _, out = run_cli(["watch", "--root", root, "--state-dir", state,
                          "--days", "1"])
        self.assertNotIn("thesis", out)
        self.assertNotIn("1 days", out)
        _, out = run_cli(["watch", "--json", "--root", root,
                          "--state-dir", state, "--days", "1"])
        self.assertEqual(json.loads(out), [])
        _, out = run_cli(["watch", "--json", "--root", root,
                          "--state-dir", state, "--days", "36500"])
        self.assertEqual(len(json.loads(out)), 1)

    def test_undated_actions_are_not_claimed_to_be_inside_the_window(self):
        undated = dict(REC, timestamp=None)
        text = plain(watch.render([undated, REC], 2, 30))
        self.assertIn("no readable time", text)
        self.assertFits(text, term.width())
        self.assertNotIn("no readable time", plain(watch.render([REC], 1, 30)))


if __name__ == "__main__":
    unittest.main()
