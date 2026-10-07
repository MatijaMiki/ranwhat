"""Every agent ranwhat reads, through the whole CLI (design 5.2 and 5.3).

The adapters' own tests read each agent's files through the adapter. These
run check, watch and clean over them as a user would, with --source and
--path, and look at what the reports and --json say: a dangerous shell
call and a credential read flagged and named by agent, a secret found with
the file it was read out of, masked in a file the agent lets ranwhat
rewrite and left byte for byte in one it does not, a store that does not
parse, the --days window, and a value found in one agent's history masked
where another's shows it.

Every value here is synthetic, and every file is in a temp directory: the
home directory each adapter defaults to is an empty one, so only the
folders --path names are read.
"""
import contextlib
import hashlib
import io
import json
import os
import re
import shutil
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

TESTS = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(TESTS)
sys.path.insert(0, REPO)
sys.path.insert(0, TESTS)

import isolated_home  # noqa: E402,F401  ranwhat's state, never ~/.ranwhat
import agents_fixtures as af  # noqa: E402
from ranwhat import agents, clean, cli, sources, term  # noqa: E402
from ranwhat.sources import _paths, _rewrite  # noqa: E402


def setUpModule():
    # The fake terminals here stand for one that reads escapes. On Windows
    # term asks the console itself whether it does (term._escapes), and a
    # StringIO is no console: it would get no colour and no progress line.
    global _console
    _console = mock.patch.object(term, "_escapes", lambda stream: True)
    _console.start()


def tearDownModule():
    _console.stop()


SECRET = "sk_" "live_" "Fx7Qw2Er9Ty4Ui1Op6As3Df"
OTHER = "sk_" "live_" "Mn3Bv5Cx7Zl9Kj2Hg4Fd6Sa"
# Passwords with no shape of their own, found where a key names them and
# typed elsewhere with nothing beside them (test_known_index's kind).
PW = "Hq7xT2mVp9LwZr4kNd"
PW2 = "Rw4KzQ8nVy2TmXp6Jh"
SCRIPT = "./deploy.sh prod xY3%s4Kq -e 'DROP DATABASE prod '"
WIDTHS = ("46", "60", "80")


def _sha(path):
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def _read(path):
    with open(path, "rb") as fh:
        return fh.read()


def _marker(value):
    return clean.REDACTION % clean._fingerprint(value)


def _claude_call(i, command, output, when):
    stamp = af.iso(when)
    return [{"type": "assistant", "timestamp": stamp, "message": {"content": [
        {"type": "tool_use", "id": "t%s" % i, "name": "Bash",
         "input": {"command": command}}]}},
        {"type": "user", "timestamp": stamp, "message": {"content": [
            {"type": "tool_result", "tool_use_id": "t%s" % i, "content": output}]}}]


class _Cli(unittest.TestCase):
    """A temp home that holds no agent's history, ranwhat's state and
    backups in temp folders, and a run of the CLI in this process."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="cli-agents-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.home = os.path.join(self.tmp, "home")
        os.makedirs(self.home)
        self.backups = os.path.join(self.tmp, "backups")
        env = {"HOME": self.home, "USERPROFILE": self.home,
               "RANWHAT_HOME": os.path.join(self.tmp, "state"),
               "NO_COLOR": "1", "RANWHAT_WIDTH": "80"}
        patches = [mock.patch.dict(os.environ, env),
                   mock.patch.object(_paths, "home", return_value=self.home),
                   mock.patch.object(clean, "BACKUP_ROOT", self.backups)]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        for name in af.AGENT_ENV:
            os.environ.pop(name, None)          # restored by patch.dict
        # Under the home directory, where a report shows them as ~/...,
        # and none where an agent keeps its history by default.
        self.claude = os.path.join(self.home, "claude", "projects")
        os.makedirs(self.claude)
        self.openclaw = os.path.join(self.home, "no-openclaw")
        self.now = time.time() - 600

    def run_cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch("sys.stdout", out), mock.patch("sys.stderr", err), \
                mock.patch("sys.stdin", io.StringIO()):
            try:
                rc = cli.main(list(argv))
            except SystemExit as exit:
                rc = exit.code
        return rc, out.getvalue(), err.getvalue()

    def base_flags(self):
        return ["--root", self.claude, "--state-dir", self.openclaw]

    def only(self, agent, root):
        return ["--source", agent.id, "--path", "%s=%s" % (agent.id, root)] \
            + self.base_flags()

    def agent_root(self, agent):
        """A short folder of its own under the home directory: a suggested
        command repeats it, and a path is never split across lines."""
        return agent.root(os.path.join(self.home, "a%d" % af.AGENTS.index(agent)))

    def claude_transcript(self, rows, name="s1"):
        path = os.path.join(self.claude, "-tmp-synthetic", name + ".jsonl")
        return af.write(path, [json.dumps(r) for r in rows])

    def backup_files(self):
        return [os.path.join(d, f) for d, _s, files in os.walk(self.backups)
                for f in files]

    def assertFits(self, text, width):
        """Every line fits but a command check suggests, which keeps a line
        of its own, whatever its length, to paste into any shell."""
        commands = ()
        if "  What to do with this" in text:
            head = "    %s " % cli.invocation()
            commands = [line for line in text.split("  What to do with this")[1]
                        .split("\n")
                        if line.startswith(head) and "  " not in line.strip()]
        for line in text.split("\n"):
            if line not in commands:
                self.assertLessEqual(len(line), width, repr(line))

    def assertAllMasked(self, text, *values):
        for value in values:
            for form in _rewrite.encodings(value):
                self.assertNotIn(form, text)


def _calls(now):
    return [("c1", "shell", "rm -rf ~/Documents/x", "removed\n", now),
            ("c2", "shell", "cat ~/.aws/credentials", "[default]\n", now + 1),
            ("c3", "read", "~/.ssh/id_rsa", "ok\n", now + 2),
            ("c4", "shell", "cat .env", "API_KEY=%s\n" % SECRET, now + 3)]


class EveryAgentWatched(_Cli):
    """5.2 items 4, 5 and 8, and the source field: what watch reports of
    each agent, named by it."""

    def test_dangerous_shell_calls_and_credential_reads_are_flagged(self):
        for agent in af.AGENTS:
            with self.subTest(agent=agent.id):
                root = self.agent_root(agent)
                agent.write(root, _calls(self.now))
                rc, out, err = self.run_cli("watch", "--json", *self.only(agent, root))
                self.assertEqual(rc, 0, err)
                records = json.loads(out)
                evidence = " ".join(h["evidence"] for r in records for h in r["hits"])
                rules = {h["rule"] for r in records for h in r["hits"]}
                self.assertIn("fs.destructive", rules)
                self.assertIn("cred.read", rules)
                self.assertIn("~/Documents/x", evidence)
                self.assertIn(".aws/credentials", evidence)
                self.assertIn(".ssh/id_rsa", evidence)
                self.assertEqual({r["source"] for r in records}, {agent.id})
                self.assertNotIn(SECRET, out)

    def test_the_report_names_the_agent_and_how_much_it_read(self):
        for agent in af.AGENTS:
            with self.subTest(agent=agent.id):
                root = self.agent_root(agent)
                agent.write(root, _calls(self.now))
                rc, out, _ = self.run_cli("watch", *self.only(agent, root))
                self.assertEqual(rc, 0)
                name = sources.get(agent.id).name
                self.assertIn("Read %s: 1 %s" % (name, agent.unit), out)
                self.assertNotIn("Claude Code", out)
                # each record's first line, or the line under it when the
                # time and tool do not fit beside its title
                lines = out.split("\n")
                flagged = [i for i, line in enumerate(lines)
                           if line.startswith("  * ")]
                self.assertTrue(flagged)
                for i in flagged:
                    self.assertIn(name, lines[i] + lines[i + 1])

    def test_every_source_is_read_by_default(self):
        roots = {}
        for agent in af.AGENTS:
            roots[agent.id] = root = self.agent_root(agent)
            agent.write(root, _calls(self.now)[:1])
        argv = ["watch", "--json"] + self.base_flags()
        for agent_id, root in roots.items():
            argv += ["--path", "%s=%s" % (agent_id, root)]
        rc, out, err = self.run_cli(*argv)
        self.assertEqual(rc, 0, err)
        self.assertEqual(sorted({r["source"] for r in json.loads(out)}),
                         sorted(roots))

    def test_a_store_that_does_not_parse_leaves_the_others_read(self):
        for agent in af.AGENTS:
            with self.subTest(agent=agent.id):
                root = self.agent_root(agent)
                agent.write(root, _calls(self.now)[:1])
                bad = agent.garbage(root)
                for command in (["watch", "--json"],
                                ["clean", "--json", "--no-interactive"]):
                    rc, out, err = self.run_cli(*(command + self.only(agent, root)))
                    self.assertEqual(rc, 0, err)
                    self.assertLessEqual(err.count(bad), 1, err)
                rc, out, err = self.run_cli("watch", "--json", *self.only(agent, root))
                self.assertEqual([h["rule"] for r in json.loads(out) for h in r["hits"]],
                                 ["fs.destructive"])

    def test_the_days_window(self):
        for agent in af.AGENTS:
            if not agent.timed:
                continue        # its calls are as old as their file
            with self.subTest(agent=agent.id):
                root = self.agent_root(agent)
                old = time.time() - 400 * 86400
                agent.write(root, [
                    ("c1", "shell", "rm -rf ~/Documents/old", "x\n", old),
                    ("c2", "shell", "rm -rf ~/Documents/new", "x\n", self.now)])
                rc, out, _ = self.run_cli("watch", "--json", "--days", "30",
                                          *self.only(agent, root))
                evidence = " ".join(h["evidence"] for r in json.loads(out)
                                    for h in r["hits"])
                self.assertIn("Documents/new", evidence)
                self.assertNotIn("Documents/old", evidence)
                rc, out, _ = self.run_cli("watch", "--json", "--days", "3650",
                                          *self.only(agent, root))
                evidence = " ".join(h["evidence"] for r in json.loads(out)
                                    for h in r["hits"])
                self.assertIn("Documents/old", evidence)


class EveryAgentCleaned(_Cli):
    """5.2 items 9, 10 and 11: what clean finds in each agent's history,
    and what it does to the files."""

    def finding(self, out, value):
        doc = json.loads(out)
        [found] = [f for f in doc["findings"]
                   if f["fingerprint"] == clean._fingerprint(value)]
        return found

    def test_a_secret_is_found_with_the_file_it_was_read_out_of(self):
        for agent in af.AGENTS:
            with self.subTest(agent=agent.id):
                root = self.agent_root(agent)
                path = agent.write(root, _calls(self.now))
                rc, out, err = self.run_cli("clean", "--json", "--no-interactive",
                                            *self.only(agent, root))
                self.assertEqual(rc, 0, err)
                self.assertNotIn(SECRET, out)
                found = self.finding(out, SECRET)
                self.assertEqual(found["origins"], [".env"])
                self.assertEqual(found["sources"], [agent.id])
                self.assertEqual(found["stores"], {path: agent.id})
                self.assertEqual(found["read_only"], [])
                self.assertEqual(json.loads(out)["scanned"], 1 + (agent.id == "grok"))

    def test_masking_round_trip(self):
        for agent in af.AGENTS:
            with self.subTest(agent=agent.id):
                root = self.agent_root(agent)
                path = agent.write(root, _calls(self.now))
                before = _read(path)
                mode = stat.S_IMODE(os.stat(path).st_mode)
                rc, out, err = self.run_cli("clean", "--apply", "--no-interactive",
                                            *self.only(agent, root))
                self.assertEqual(rc, 0, err)
                after = _read(path)
                text = after.decode("utf-8")
                self.assertAllMasked(text, SECRET)
                self.assertIn(_marker(SECRET), text)
                plan = _rewrite._plan([SECRET])
                self.assertEqual(text, _rewrite._replace_text(
                    before.decode("utf-8"), plan, agent.byte_arrays))
                if agent.json_lines:
                    for line in text.splitlines():
                        if line.strip():
                            json.loads(line)
                else:
                    json.loads(text)
                self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), mode)
                backups = [b for b in self.backup_files() if _read(b) == before]
                self.assertEqual(len(backups), 1)
                self.assertIn("Masked in 1 file(s).", out)
                # the calls are all still there, and a second run changes nothing
                rc, watched, _ = self.run_cli("watch", "--json",
                                              *self.only(agent, root))
                rules = sorted(h["rule"] for r in json.loads(watched) for h in r["hits"])
                self.assertEqual(rules, ["cred.read", "cred.read", "cred.read",
                                         "fs.destructive"])
                self.run_cli("clean", "--apply", "--no-interactive",
                             *self.only(agent, root))
                self.assertEqual(_read(path), after)
                shutil.rmtree(self.backups, True)

    def test_read_only_stores_are_left_byte_for_byte(self):
        agents = [a for a in af.AGENTS if a.has_read_only]
        self.assertEqual([a.id for a in agents], ["codex", "qwen"])
        for agent in agents:
            with self.subTest(agent=agent.id):
                root = self.agent_root(agent)
                agent.write(root, _calls(self.now)[:1])
                path = agent.read_only(root, OTHER)
                digest = _sha(path)
                rc, out, err = self.run_cli("clean", "--json", "--no-interactive",
                                            *self.only(agent, root))
                found = self.finding(out, OTHER)
                self.assertEqual(found["read_only"], [path])
                rc, out, err = self.run_cli("clean", "--apply", "--no-interactive",
                                            *self.only(agent, root))
                self.assertEqual(rc, 0, err)
                self.assertEqual(_sha(path), digest)
                self.assertNotIn(OTHER, out)
                self.assertIn("read only", out)
                self.assertEqual([b for b in self.backup_files()
                                  if _read(b) == _read(path)], [])

    def test_a_file_written_within_the_quiet_period_is_not_masked(self):
        agent = af.AGENTS[0]
        root = self.agent_root(agent)
        path = agent.write(root, _calls(self.now), age=5)
        before = _read(path)
        rc, out, err = self.run_cli("clean", "--apply", "--no-interactive",
                                    *self.only(agent, root))
        self.assertEqual(rc, 0, err)
        self.assertEqual(_read(path), before)
        self.assertIn("in use", out)


class KnownAcrossAgents(_Cli):
    """A value clean finds in one agent's history is masked wherever
    another agent's shows it (known.py indexes every source's stores)."""

    def test_a_codex_value_is_masked_in_claude_codes_actions_and_back(self):
        codex = af.AGENTS[0]
        root = self.agent_root(codex)
        codex.write(root, [
            ("c1", "shell", "cat .env", "DB_PASSWORD=%s\n" % PW, self.now),
            ("c2", "shell", SCRIPT % PW2, "ok\n", self.now + 1)])
        self.claude_transcript(
            _claude_call(1, SCRIPT % PW, "ok", self.now + 2)
            + _claude_call(2, "cat .env", "DB_PASSWORD=%s\n" % PW2, self.now + 3))
        flags = self.base_flags() + ["--path", "codex=" + root]
        for argv in (["watch", "--json"], ["check", "--json"], ["watch"], ["check"]):
            with self.subTest(argv=argv):
                rc, out, err = self.run_cli(*(argv + flags))
                self.assertEqual(rc, 0, err)
                self.assertIn("DROP DATABASE", out)
                self.assertNotIn(PW, out)
                self.assertNotIn(PW2, out)
        rc, out, _ = self.run_cli("watch", "--json", *flags)
        self.assertEqual(sorted({r["source"] for r in json.loads(out)}),
                         ["claude-code", "codex"])

    def test_a_value_found_only_by_codex_is_masked_with_source_claude_code(self):
        codex = af.AGENTS[0]
        root = self.agent_root(codex)
        codex.write(root, [("c1", "shell", "cat .env", "DB_PASSWORD=%s\n" % PW,
                            self.now)])
        self.claude_transcript(_claude_call(1, SCRIPT % PW, "ok", self.now + 2))
        rc, out, err = self.run_cli("watch", "--json", "--source", "claude-code",
                                    "--path", "codex=" + root, *self.base_flags())
        self.assertEqual(rc, 0, err)
        self.assertIn("DROP DATABASE", out)
        self.assertNotIn(PW, out)



class CleanAcrossAgents(_Cli):
    """A value the rules find in one agent's history is masked where
    another agent's files hold a copy the rules cannot see."""

    def test_a_value_codex_read_is_masked_where_claude_code_typed_it(self):
        codex = af.AGENTS[0]
        root = self.agent_root(codex)
        session = codex.write(root, [
            ("c1", "shell", "cat .env", "DB_PASSWORD=%s\n" % PW, self.now),
            ("c2", "shell", SCRIPT % PW2, "ok\n", self.now + 1)])
        transcript = self.claude_transcript(
            _claude_call(1, SCRIPT % PW, "ok", self.now + 2)
            + _claude_call(2, "cat .env", "DB_PASSWORD=%s\n" % PW2, self.now + 3))
        flags = self.base_flags() + ["--path", "codex=" + root]
        rc, out, err = self.run_cli("clean", "--json", "--no-interactive", *flags)
        doc = json.loads(out)
        [pw] = [f for f in doc["findings"] if f["fingerprint"] == clean._fingerprint(PW)]
        self.assertEqual(sorted(pw["sources"]), ["claude-code", "codex"])
        self.assertEqual(sorted(pw["files"]), sorted([session, transcript]))
        rc, out, err = self.run_cli("clean", "--apply", "--no-interactive", *flags)
        self.assertEqual(rc, 0, err)
        for path in (session, transcript):
            text = _read(path).decode("utf-8")
            self.assertAllMasked(text, PW, PW2)
            self.assertIn(_marker(PW), text)
            self.assertIn(_marker(PW2), text)


class StoresInPathOrder(_Cli):
    """A finding's "stores" was filled from a set, in an order Python's
    hash seed sets, so check --json and clean --json gave other bytes on
    every run of the same history. It is in path order."""

    def test_claude_code_keys_in_path_order(self):
        files, n = set(), 0
        while len(files) < 2 or list(files) == sorted(files):
            files.add("/p/s%d.jsonl" % n)
            n += 1
        findings = {"fp": {"files": set(files)}}
        clean._claude_code_keys(findings)
        self.assertEqual(list(findings["fp"]["stores"]), sorted(files))

    def test_written_in_path_order(self):
        finding = {"files": {"/c", "/a", "/b"},
                   "stores": {"/c": "codex", "/a": "claude-code",
                              "/b": "claude-code"}}
        self.assertEqual(list(cli._finding_json(finding)["stores"]),
                         ["/a", "/b", "/c"])

    def test_the_same_bytes_whatever_the_hash_seed(self):
        for n in range(8):
            self.claude_transcript(_claude_call(
                n, "export STRIPE=" + SECRET, "ok", self.now + n), name="s%d" % n)
        for argv, key in ((["check", "--json"], "secrets"),
                          (["clean", "--json", "--no-interactive"], "findings")):
            outs = set()
            for seed in ("1", "2", "3"):
                env = dict(os.environ, PYTHONHASHSEED=seed,
                           PYTHONIOENCODING="utf-8", RANWHAT_HOME=(
                               tempfile.mkdtemp(prefix="state-", dir=self.tmp)))
                done = subprocess.run(
                    [sys.executable, "-m", "ranwhat"] + argv + self.base_flags(),
                    cwd=REPO, env=env, capture_output=True, encoding="utf-8",
                    stdin=subprocess.DEVNULL, timeout=20)
                self.assertEqual(done.returncode, 0, done.stderr)
                [found] = json.loads(done.stdout)[key]
                self.assertEqual(len(found["stores"]), 8)
                self.assertEqual(list(found["stores"]), sorted(found["stores"]))
                outs.add(done.stdout)
            self.assertEqual(len(outs), 1, argv)


class Flags(_Cli):
    """design 4.1 and 5.3: --source and --path on every command that reads
    agent history, --root and --state-dir as their old names."""

    def argparse_error(self, *argv):
        rc, out, err = self.run_cli(*argv)
        self.assertEqual((rc, out), (2, ""))
        self.assertIn("error:", err)
        return " ".join(err.split())

    def test_the_source_choices_are_the_registry_ids(self):
        said = self.argparse_error("watch", "--source", "zed")
        listed = said.split("choose from ")[1].split(")")[0]
        self.assertEqual([c.strip(" '") for c in listed.split(",")],
                         list(sources.ids()))

    def test_every_id_on_every_command(self):
        for command in ("check", "watch", "clean"):
            for source_id in sources.ids():
                with self.subTest(command=command, source=source_id):
                    argv = [command, "--json", "--source", source_id]
                    if command == "clean":
                        argv.append("--no-interactive")
                    rc, out, err = self.run_cli(*(argv + self.base_flags()))
                    self.assertNotIn("error:", err)
                    json.loads(out)

    def test_a_bad_id_is_an_error_on_every_command(self):
        for command in ("check", "watch", "clean", "sources"):
            with self.subTest(command=command):
                self.assertIn("invalid choice", self.argparse_error(
                    command, "--source", "meta-muse"))

    def test_path_for_an_agent_ranwhat_does_not_know_is_an_error(self):
        said = self.argparse_error("watch", "--path", "zed=" + self.tmp)
        self.assertIn("no agent 'zed'", said)
        self.assertIn("codex", said)

    def test_path_takes_an_id_and_a_path(self):
        for given in (self.tmp, "codex=", "=" + self.tmp):
            with self.subTest(given=given):
                self.assertIn("ID=PATH", self.argparse_error(
                    "watch", "--path", given))

    def test_one_path_per_agent(self):
        self.assertIn("twice", self.argparse_error(
            "watch", "--path", "codex=" + self.tmp, "--path", "codex=" + self.home))

    def test_root_and_state_dir_are_the_ported_agents_paths(self):
        self.assertIn("give one", self.argparse_error(
            "watch", "--root", self.claude, "--path", "claude-code=" + self.claude))
        self.assertIn("give one", self.argparse_error(
            "watch", "--state-dir", self.openclaw,
            "--path", "openclaw=" + self.openclaw))
        self.claude_transcript(_claude_call(1, "rm -rf ~/Documents/x", "ok", self.now))
        for argv in (["--root", self.claude],
                     ["--path", "claude-code=" + self.claude]):
            with self.subTest(argv=argv):
                rc, out, err = self.run_cli(
                    "watch", "--json", "--state-dir", self.openclaw, *argv)
                self.assertEqual(rc, 0, err)
                self.assertEqual([r["source"] for r in json.loads(out)],
                                 ["claude-code"])

    def test_root_and_state_dir_expand_a_tilde_as_path_does(self):
        """--root=~/x and a quoted ~ reach ranwhat as they are written, as
        does any ~ in cmd and PowerShell. --path expanded it and --root and
        --state-dir did not: sources found the history there, watch read
        nothing, and check's clean half alone said what it held."""
        self.claude_transcript(_claude_call(1, "git push --force origin main",
                                            "ok", self.now))
        db = os.path.join(self.home, "oc", "agents", "a1", "agent",
                          "openclaw-agent.sqlite")
        os.makedirs(os.path.dirname(db))
        conn = sqlite3.connect(db)
        conn.execute("CREATE TABLE log (id TEXT, body TEXT, createdAt INTEGER)")
        conn.execute("INSERT INTO log VALUES ('1', ?, ?)", (json.dumps(
            {"content": [{"type": "tool_use", "name": "Bash",
                          "input": {"command": "rm -rf ~/Documents/o"}}]}),
            int(self.now)))
        conn.commit()
        conn.close()
        # expanduser("~/oc") keeps the "/" on Windows; join after "~".
        flags = ["--root=" + os.path.join("~", "claude", "projects"),
                 "--state-dir=" + os.path.join("~", "oc")]
        rc, out, err = self.run_cli("watch", "--json", *flags)
        self.assertEqual(rc, 0, err)
        self.assertEqual(sorted(r["source"] for r in json.loads(out)),
                         ["claude-code", "openclaw"])
        with mock.patch.object(cli, "invocation", return_value="ranwhat"):
            rc, out, err = self.run_cli("check", *flags)
        self.assertEqual(rc, 0, err)
        said = " ".join(out.split())
        for found in ("git push --force", "rm -rf ~/Documents/o",
                      "check --json --root %s --state-dir %s" % (
                          cli._shell_path(self.claude),
                          cli._shell_path(os.path.join(self.home, "oc")))):
            self.assertIn(found, said)

    def test_source_limits_every_section_of_check(self):
        codex = af.AGENTS[0]
        root = self.agent_root(codex)
        codex.write(root, _calls(self.now))
        self.claude_transcript(
            _claude_call(1, "rm -rf ~/Documents/c", "ok", self.now)
            + _claude_call(2, "cat .env", "API_KEY=%s\n" % OTHER, self.now))
        flags = self.base_flags() + ["--path", "codex=" + root]
        for chosen, other in (("codex", "claude-code"), ("claude-code", "codex")):
            with self.subTest(source=chosen):
                rc, out, err = self.run_cli("check", "--json", "--source", chosen,
                                            *flags)
                doc = json.loads(out)
                self.assertEqual({r["source"] for r in doc["actions"]}, {chosen})
                self.assertEqual({i for f in doc["secrets"] for i in f["sources"]},
                                 {chosen})

    def test_a_suggested_command_reads_what_this_one_read(self):
        codex = af.AGENTS[0]
        root = self.agent_root(codex)
        codex.write(root, _calls(self.now))
        rc, out, _ = self.run_cli("check", "--source", "codex",
                                  "--path", "codex=" + root, *self.base_flags())
        said = " ".join(out.replace("\\\n", " ").split())
        self.assertIn("clean --root %s --state-dir %s --source codex --path codex=%s"
                      % (cli._shell_path(self.claude), cli._shell_path(self.openclaw),
                         cli._shell_path(root)), said)


class Reports(_Cli):
    """Reports name each agent they read and how much, and no other."""

    def test_only_the_agents_read_are_named(self):
        codex, gemini = af.AGENTS[0], af.AGENTS[1]
        roots = {a.id: self.agent_root(a) for a in (codex, gemini)}
        codex.write(roots["codex"], _calls(self.now))
        self.claude_transcript(_claude_call(1, "rm -rf ~/Documents/c", "ok", self.now))
        flags = self.base_flags() + ["--path", "codex=" + roots["codex"],
                                     "--path", "gemini=" + roots["gemini"]]
        for argv in (["watch"], ["check"], ["clean", "--no-interactive"]):
            with self.subTest(argv=argv):
                rc, out, err = self.run_cli(*(argv + flags))
                self.assertEqual(rc, 0, err)
                text = " ".join(out.split())
                self.assertIn("Read Claude Code: 1 transcript; Codex: 1 session", text)
                self.assertNotIn("Gemini", text)
                self.assertNotIn("Qwen", text)

    def test_claude_code_alone_still_reads_as_before_but_for_its_name(self):
        self.claude_transcript(_claude_call(1, "rm -rf ~/Documents/c", "ok", self.now))
        rc, out, _ = self.run_cli("watch", *self.base_flags())
        self.assertIn("  Read Claude Code: 1 transcript, last 30 days\n", out)
        [line] = [l for l in out.split("\n") if l.startswith("  * ")]
        self.assertNotIn("Claude Code", line)

    def test_nothing_read_says_where_it_looked_and_names_no_absent_agent(self):
        for argv in (["watch"], ["check"], ["clean", "--no-interactive"]):
            with self.subTest(argv=argv):
                rc, out, _ = self.run_cli(*(argv + self.base_flags()))
                self.assertEqual(rc, 2)
                text = " ".join(out.split())
                self.assertIn("No transcripts found", text)
                self.assertIn(os.path.join("~", "claude", "projects"), out)
                self.assertIn("ranwhat sources", text)
                for name in ("Codex", "Gemini", "Copilot", "Droid", "Muse"):
                    self.assertNotIn(name, text)

    def test_checks_watch_half_says_why_when_only_clean_read(self):
        """With a prompt history in the window and every session older,
        check's watch half said only "No transcripts found" and the general
        hint, while watch said how many older ones there were and that a
        larger --days reads them."""
        codex = af.AGENTS[0]
        root = self.agent_root(codex)
        old = 60 * 86400
        codex.write(root, [("c1", "shell", "rm -rf ~/Documents/a", "ok",
                            self.now - old)], age=old)
        af.write(os.path.join(root, "history.jsonl"),
                 [af.cx.history_line("hello", ts=int(self.now))])
        argv = ["--source", "codex", "--path", "codex=" + root] + self.base_flags()
        _, alone, _ = self.run_cli("watch", *argv)
        rc, out, err = self.run_cli("check", *argv)
        self.assertEqual(rc, 0, err)
        said = " ".join(out.split())
        for line in ("1 older transcript(s) found. Pass a larger --days",
                     "Read Codex: 1 file"):
            self.assertIn(line, said)
        self.assertIn("1 older transcript(s) found", " ".join(alone.split()))
        self.assertNotIn("Nothing flagged", out)

    def test_an_agent_pointed_at_nothing_is_named(self):
        nowhere = os.path.join(self.home, "no-codex")
        rc, out, err = self.run_cli("watch", "--source", "codex",
                                    "--path", "codex=" + nowhere, *self.base_flags())
        self.assertEqual(rc, 2)
        text = " ".join(out.split())
        self.assertIn("Codex", text)
        self.assertIn(os.path.join("~", "no-codex"), text)
        self.assertIn("--path codex=PATH", text)
        rc, out, err = self.run_cli("watch", "--json", "--source", "codex",
                                    "--path", "codex=" + nowhere, *self.base_flags())
        self.assertEqual((rc, out.strip()), (2, "[]"))
        self.assertIn("--path codex=PATH", " ".join(err.split()))

    def assertSaysWhereItLooked(self, argv, agents, where):
        """A run that read nothing names, in its text and on --json's
        stderr, each agent --source asked for, where it looked, and how
        to point it elsewhere."""
        rc, out, err = self.run_cli(*argv)
        self.assertEqual(rc, 2, err)
        text = " ".join(out.split())
        for agent_id, name in agents:
            self.assertIn(name, text)
            self.assertIn("--path %s=PATH" % agent_id, text)
        for path in where:
            self.assertIn(path, text)
        json_argv = argv[:1] + ["--json"] + [a for a in argv[1:]
                                             if a != "--no-interactive"]
        rc, out, err = self.run_cli(*json_argv)
        self.assertEqual(rc, 2, err)
        said = " ".join(err.split())
        self.assertNotIn("in ,", said)
        for agent_id, name in agents:
            self.assertIn("(%s)" % name, said)
            self.assertIn("--path %s=PATH" % agent_id, said)
        for path in where:
            self.assertIn(path, said)

    def test_an_agent_asked_for_by_name_is_named_where_it_is_absent(self):
        # --source codex on a machine with no ~/.codex: the next step
        # `ranwhat sources` suggests read nothing, and said nowhere.
        codex = os.path.join("~", ".codex")
        for argv in (["watch"], ["check"], ["clean", "--no-interactive"]):
            with self.subTest(argv=argv):
                self.assertSaysWhereItLooked(argv + ["--source", "codex"],
                                             [("codex", "Codex")], [codex])
        # two of them, neither here
        self.assertSaysWhereItLooked(
            ["watch", "--source", "codex", "--source", "grok"],
            [("codex", "Codex"), ("grok", "Grok Build")],
            [codex, os.path.join("~", ".grok")])

    def test_an_agent_asked_for_where_its_folder_holds_no_history(self):
        # ~/.copilot holding only what the IDE extension keeps
        os.makedirs(os.path.join(self.home, ".copilot", "ide"))
        for argv in (["watch"], ["check"], ["clean", "--no-interactive"]):
            with self.subTest(argv=argv):
                self.assertSaysWhereItLooked(
                    argv + ["--source", "copilot-cli"],
                    [("copilot-cli", "GitHub Copilot CLI")],
                    [os.path.join("~", ".copilot")])

    def test_an_agent_asked_for_where_its_own_variable_points_nowhere(self):
        moved = os.path.join(self.home, "moved-codex")
        for target in ("missing", "file"):
            with self.subTest(target=target):
                if target == "file":
                    af.write(moved, "not a folder\n")
                with mock.patch.dict(os.environ, {"CODEX_HOME": moved}):
                    self.assertSaysWhereItLooked(
                        ["watch", "--source", "codex"], [("codex", "Codex")],
                        [os.path.join("~", "moved-codex")])

    def test_where_it_looked_fits_every_width(self):
        for width in WIDTHS:
            for argv in (["watch", "--source", "gemini", "--source", "droid"],
                         ["check", "--source", "pi"],
                         ["clean", "--no-interactive", "--source", "muse-code"]):
                with self.subTest(width=width, argv=argv), \
                        mock.patch.dict(os.environ, {"RANWHAT_WIDTH": width}):
                    rc, out, err = self.run_cli(*argv)
                    self.assertEqual(rc, 2, err)
                    self.assertIn("Looked in:", out)
                    self.assertFits(out, int(width))
                    self.assertNotIn("—", out + err)

    def test_what_could_not_be_read_is_said(self):
        codex = af.AGENTS[0]
        root = self.agent_root(codex)
        codex.write(root, _calls(self.now)[:1])
        codex.garbage(root)
        for argv in (["watch"], ["check"], ["clean", "--no-interactive"]):
            with self.subTest(argv=argv):
                rc, out, _ = self.run_cli(*(argv + self.only(codex, root)))
                self.assertIn("1 Codex file was not read: not JSON Lines.",
                              " ".join(out.split()))

    def test_records_of_other_agents_say_what_kind_of_call(self):
        codex = af.AGENTS[0]
        root = self.agent_root(codex)
        codex.write(root, _calls(self.now)[:1])
        self.claude_transcript(_claude_call(1, "rm -rf ~/Documents/c", "ok", self.now))
        rc, out, _ = self.run_cli("watch", "--json", "--path", "codex=" + root,
                                  *self.base_flags())
        by_source = {r["source"]: r for r in json.loads(out)}
        self.assertEqual(by_source["codex"]["kind"], "shell")
        self.assertEqual(by_source["codex"]["project"], "/home/dev/app")
        # Claude Code's records keep exactly the keys they had
        self.assertEqual(sorted(by_source["claude-code"]), sorted(
            ["source", "session", "project", "timestamp", "tool_name",
             "tool_call_id", "payload_hash", "severity", "hits"]))

    def test_every_line_fits(self):
        roots = {}
        for agent in af.AGENTS[:4]:
            roots[agent.id] = root = self.agent_root(agent)
            agent.write(root, _calls(self.now))
            agent.read_only(root, OTHER)
            agent.garbage(root)
        self.claude_transcript(_claude_call(1, "rm -rf ~/Documents/c", "ok", self.now))
        flags = list(self.base_flags())
        for agent_id, root in roots.items():
            flags += ["--path", "%s=%s" % (agent_id, root)]
        for width in WIDTHS:
            for argv in (["watch"], ["check"], ["clean", "--no-interactive"],
                         ["clean", "--apply", "--no-interactive"], ["sources"],
                         ["watch", "--path", "kimi=" + os.path.join(self.tmp, "x")]):
                with self.subTest(width=width, argv=argv), \
                        mock.patch.dict(os.environ, {"RANWHAT_WIDTH": width}):
                    rc, out, err = self.run_cli(*(argv + flags))
                    self.assertNotIn("error:", err)
                    self.assertFits(out, int(width))
                    self.assertNotIn("—", out + err)


class WhatWasNotReadIsNotCountedRead(_Cli):
    """A store found unreadable was counted among those read: "Read Codex:
    2 sessions" above "1 Codex file was not read". The adapter counted it
    once a run and never said which store it was."""

    def test_every_report_counts_only_what_it_read(self):
        """No report says a file was not read and counts it as read. Every
        reader of actions notes the garbage store, so watch, and check's
        watch section (its first header), read one. A reader of secrets
        that searches a line that is not JSON as text (Kimi CLI's) read
        both, and notes neither."""
        for agent in af.AGENTS:
            root = self.agent_root(agent)
            agent.write(root, _calls(self.now)[:1])
            agent.garbage(root)
            name = sources.get(agent.id).name
            for argv in (["watch"], ["check"], ["clean", "--no-interactive"]):
                with self.subTest(agent=agent.id, argv=argv):
                    rc, out, err = self.run_cli(*(argv + self.only(agent, root)))
                    said = " ".join(out.split())
                    self.assertEqual(rc, 0, err)
                    noted = "1 %s file was not read" % name in said
                    if argv[0] != "clean":
                        self.assertTrue(noted, said)
                    read = int(re.search(r"Read %s: (\d+)" % re.escape(name),
                                         said).group(1))
                    self.assertEqual(read, 1 if noted else 2, said)

    def test_with_nothing_read_the_report_says_why(self):
        """Only the unreadable store: not "no transcripts found"."""
        agent = af.AGENTS[0]
        root = self.agent_root(agent)
        agent.garbage(root)
        name = sources.get(agent.id).name
        for argv in (["watch"], ["check"], ["clean", "--no-interactive"]):
            with self.subTest(argv=argv):
                rc, out, err = self.run_cli(*(argv + self.only(agent, root)))
                said = " ".join(out.split())
                self.assertEqual(rc, 0, err)
                self.assertNotIn("nothing was checked", said)
                self.assertNotIn("Read %s" % name, said)
                self.assertIn("1 %s file was not read" % name, said)


class AllReadOnlyWhenItWas(_Cli):
    """With nothing flagged, check's watch section said every tool call
    was read when a store could not be, and watch said it above the note
    saying so. The sentence was also wider than 46 columns."""

    ALL_READ = "Every call was read; none tripped a rule."
    NOT_ALL = "some could not be read"

    def nothing_flagged(self, garbage):
        agent = af.AGENTS[0]
        root = self.agent_root(agent)
        agent.write(root, [("c1", "shell", "ls", "a.txt\n", self.now)])
        if garbage:
            agent.garbage(root)
        return self.only(agent, root)

    def test_a_store_not_read_withholds_the_claim(self):
        flags = self.nothing_flagged(garbage=True)
        for width in WIDTHS:
            for argv in (["watch"], ["check"]):
                with self.subTest(width=width, argv=argv), \
                        mock.patch.dict(os.environ, {"RANWHAT_WIDTH": width}):
                    rc, out, err = self.run_cli(*(argv + flags))
                    self.assertIn("Nothing flagged", out)
                    self.assertNotIn(self.ALL_READ, out)
                    self.assertIn(self.NOT_ALL, " ".join(out.split()))
                    self.assertFits(out, int(width))

    def test_everything_read_says_so_in_one_line(self):
        flags = self.nothing_flagged(garbage=False)
        for width in WIDTHS:
            for argv in (["watch"], ["check"]):
                with self.subTest(width=width, argv=argv), \
                        mock.patch.dict(os.environ, {"RANWHAT_WIDTH": width}):
                    rc, out, err = self.run_cli(*(argv + flags))
                    self.assertIn("  " + self.ALL_READ + "\n", out)
                    self.assertNotIn(self.NOT_ALL, out)
                    self.assertFits(out, int(width))


def _fails(source, store):
    """A reader that fails on its first item, saying what it was reading."""
    raise RuntimeError("held " + SECRET)
    yield                                   # a generator, as readers are


class AReaderThatFails(_Cli):
    """A reader that raised part way through a store was warned about with
    what the error said, which can quote what it was reading, and the report
    still said every call was read. Claude Code's and OpenClaw's readers had
    no guard at all: one error ended watch and check."""

    def assertNamedCountedAndQuiet(self, out, err, name):
        self.assertNotIn(SECRET, out + err)
        self.assertIn("RuntimeError", err)
        self.assertIn("1 %s file was not read" % name, " ".join(out.split()))

    def test_an_adapter_is_named_by_its_class_and_the_others_read(self):
        failing, other = af.AGENTS[0], af.AGENTS[1]
        flags = list(self.base_flags())
        for agent in (failing, other):
            root = self.agent_root(agent)
            agent.write(root, _calls(self.now))
            flags += ["--source", agent.id, "--path", "%s=%s" % (agent.id, root)]
        cls = type(sources.get(failing.id))
        with mock.patch.object(cls, "tool_calls", _fails), \
                mock.patch.object(cls, "secret_texts", _fails):
            for argv in (["watch"], ["check"], ["clean", "--no-interactive"]):
                with self.subTest(argv=argv):
                    rc, out, err = self.run_cli(*(argv + flags))
                    self.assertEqual(rc, 0, err)
                    self.assertNamedCountedAndQuiet(out, err, sources.get(failing.id).name)
                    if argv[0] != "clean":
                        self.assertIn("Documents/x", out)

    def test_with_nothing_flagged_the_claim_is_withheld(self):
        agent = af.AGENTS[0]
        root = self.agent_root(agent)
        agent.write(root, [("c1", "shell", "ls", "a.txt\n", self.now)])
        with mock.patch.object(type(sources.get(agent.id)), "tool_calls", _fails):
            rc, out, err = self.run_cli("watch", *self.only(agent, root))
        self.assertIn("Nothing flagged", out)
        self.assertIn(AllReadOnlyWhenItWas.NOT_ALL, " ".join(out.split()))

    def test_claude_codes_and_openclaws_readers_are_guarded_too(self):
        self.claude_transcript(_claude_call(1, "rm -rf ~/Documents/c", "ok", self.now))
        db = os.path.join(self.openclaw, "agents", "a1", "agent",
                          "openclaw-agent.sqlite")
        os.makedirs(os.path.dirname(db))
        conn = sqlite3.connect(db)
        conn.execute("CREATE TABLE log (id TEXT, body TEXT, createdAt INTEGER)")
        conn.execute("INSERT INTO log VALUES ('1', ?, ?)", (json.dumps(
            {"content": [{"type": "tool_use", "name": "Bash",
                          "input": {"command": "rm -rf ~/Documents/o"}}]}),
            int(self.now)))
        conn.commit()
        conn.close()
        for failing in ("claude-code", "openclaw"):
            with self.subTest(failing=failing), \
                    mock.patch.object(type(sources.get(failing)), "tool_calls",
                                      _fails):
                for argv in (["watch"], ["check"]):
                    rc, out, err = self.run_cli(*(argv + self.base_flags()))
                    self.assertEqual(rc, 0, err)
                    self.assertNamedCountedAndQuiet(out, err,
                                                    sources.get(failing).name)
                    still = "Documents/o" if failing == "claude-code" else "Documents/c"
                    self.assertIn(still, out)

    @unittest.skipIf(os.name == "nt" or (hasattr(os, "geteuid") and os.geteuid() == 0),
                     "a file its owner cannot open is POSIX, and not as root")
    def test_a_claude_code_transcript_that_cannot_be_opened_is_counted(self):
        path = self.claude_transcript(_claude_call(1, "ls", "a.txt", self.now))
        os.chmod(path, 0)
        self.addCleanup(os.chmod, path, stat.S_IRUSR | stat.S_IWUSR)
        rc, out, err = self.run_cli("watch", *self.base_flags())
        self.assertIn("1 Claude Code file was not read", " ".join(out.split()))
        self.assertNotIn(AllReadOnlyWhenItWas.ALL_READ, out)


class Progress(_Cli):
    """One count for every agent's files together, in each pass."""

    def test_each_pass_counts_every_agent(self):
        for agent in af.AGENTS[:2]:
            agent.write(self.agent_root(agent), _calls(self.now)[:1])
        self.claude_transcript(_claude_call(1, "rm -rf ~/Documents/c", "ok", self.now))
        flags = list(self.base_flags())
        for agent in af.AGENTS[:2]:
            flags += ["--path", "%s=%s" % (agent.id, self.agent_root(agent))]

        class TTY(io.StringIO):
            def isatty(self):
                return True
        for command, words in (("watch", "checking actions"),
                               ("check", "looking for secrets"),
                               ("check", "checking actions"),
                               ("clean", "looking for secrets")):
            with self.subTest(command=command, words=words):
                err = TTY()
                with mock.patch.dict(os.environ, {"TERM": "xterm"}), \
                        mock.patch("sys.stdout", io.StringIO()), \
                        mock.patch("sys.stderr", err), \
                        mock.patch("sys.stdin", io.StringIO()):
                    cli.main([command] + flags + (["--no-interactive"]
                                                  if command == "clean" else []))
                for i in (1, 2, 3):
                    self.assertIn("%s %d/3" % (words, i), err.getvalue())


class AbsentAgentsCostAStatOrTwo(_Cli):
    """Every run looks for every agent. One that is not on this machine
    costs a stat of each place it would be, and no listing: counted, not
    timed, as a stat costs microseconds (design: under 50 ms in all)."""

    def count(self, fn):
        import builtins
        counts = {"n": 0}
        real = {name: getattr(os, name) for name in ("stat", "lstat", "listdir",
                                                     "scandir")}
        real_open = builtins.open

        def counted(fn_):
            def inner(*a, **k):
                counts["n"] += 1
                return fn_(*a, **k)
            return inner
        patches = [mock.patch.object(os, name, counted(f)) for name, f in real.items()]
        patches.append(mock.patch.object(builtins, "open", counted(real_open)))
        for p in patches:
            p.start()
        try:
            fn()
        finally:
            for p in patches:
                p.stop()
        return counts["n"]

    def test_each_absent_agent(self):
        from ranwhat import agents
        for source in agents.adapters():
            with self.subTest(source=source.id):
                n = self.count(lambda: agents.discover(source))
                limit = 4
                if source.id == "aider":
                    # Aider writes into the repository it ran in, so it
                    # also looks at the current directory's git root: one
                    # stat of each folder on the way up to it.
                    limit += len(os.path.abspath(os.getcwd()).split(os.sep))
                self.assertLessEqual(n, limit)

    def test_a_whole_run(self):
        """check looks for them three times (its read for secrets, the
        index, its read for actions), and once more when nothing was read
        to say where it looked."""
        from ranwhat import agents
        n_agents = len(agents.adapters())
        before = self.count(lambda: self.run_cli("check", "--json",
                                                 "--source", "claude-code",
                                                 *self.base_flags()))
        every = self.count(lambda: self.run_cli("check", "--json",
                                                *self.base_flags()))
        self.assertLessEqual(every - before, 4 * 4 * n_agents)


class OpenClawIsLookedForOnce(_Cli):
    """With no OpenClaw on this machine, a command looks for it as little
    as it can: a stat of its state directory where clean and the index look
    (agents.discover keeps where an agent looks for the whole run, whatever
    --days), and one listing where watch reads its actions. watch listed
    its databases twice (once for the progress total), and check looked for
    the directory twice, for clean's --days and for the index's whole
    history."""

    def touches(self, *argv):
        """How many stats and listings of the OpenClaw state directory, or
        anything in it, one command makes."""
        n = [0]

        def counted(fn):
            def inner(*args, **kwargs):
                path = args[0] if args else kwargs.get("path")
                try:
                    path = os.fspath(path)
                except TypeError:
                    path = None
                if isinstance(path, str) and (
                        path == self.openclaw
                        or path.startswith(self.openclaw + os.sep)):
                    n[0] += 1
                return fn(*args, **kwargs)
            return inner

        with contextlib.ExitStack() as stack:
            for name in ("stat", "lstat", "scandir", "listdir"):
                stack.enter_context(mock.patch.object(
                    os, name, counted(getattr(os, name))))
            rc, _out, err = self.run_cli(*(list(argv) + self.base_flags()))
        self.assertEqual(rc, 0, err)
        return n[0]

    def test_each_command(self):
        self.claude_transcript(_claude_call(1, "rm -rf ~/Documents/x", "ok",
                                            self.now))
        for argv, most in ((["check", "--json"], 2), (["watch", "--json"], 2),
                           (["clean", "--json", "--no-interactive"], 1)):
            with self.subTest(argv=argv):
                self.assertLessEqual(self.touches(*argv), most)

    def test_where_an_agent_looks_is_worked_out_once_a_run(self):
        from ranwhat import agents
        for source in agents.chosen():
            with self.subTest(source=source.id):
                real = type(source).locations
                with mock.patch.object(type(source), "locations", autospec=True,
                                       side_effect=real) as where:
                    with agents.run():
                        agents.discover(source, None, 30)
                        agents.discover(source, None, None)
                        agents.discover(source, None, 30)
                self.assertEqual(where.call_count, 1)


class SourcesCommand(_Cli):
    """ranwhat sources: every agent, where it looked, what it found."""

    def entries(self, *argv):
        rc, out, err = self.run_cli("sources", "--json", *argv)
        self.assertEqual(rc, 0, err)
        return json.loads(out)

    def test_every_agent_in_registry_order_then_the_ones_it_cannot_read(self):
        entries = self.entries(*self.base_flags())
        ids = [e["id"] for e in entries if e["id"] is not None]
        self.assertEqual(ids, list(sources.ids()))
        self.assertEqual(ids[0], "claude-code")
        elsewhere = [(e["name"], e["status"]) for e in entries if e["id"] is None]
        self.assertEqual(elsewhere, [("Meta Muse", "cloud only"),
                                     ("Grok Bot", "cloud only"),
                                     ("Amp", "cloud only")])
        for entry in entries:
            if entry["id"] is not None:
                self.assertEqual(entry["status"], "not found")
                self.assertTrue(entry["locations"])

    def test_a_path_an_agent_notes_is_cut_to_fit(self):
        """Codex's note names the path it was pointed at whole, and a word
        longer than the line was given a line of its own past the edge,
        under a location line already cut to fit."""
        parts = ("some", "rather", "long", "directory", "name", "codex-home-file")
        af.write(os.path.join(self.home, *parts), "not a folder\n")
        for width in WIDTHS:
            with self.subTest(width=width), \
                    mock.patch.dict(os.environ, {"RANWHAT_WIDTH": width}):
                rc, out, err = self.run_cli("sources", "--source", "codex",
                                            "--path", "codex=~/" + "/".join(parts))
                self.assertEqual(rc, 0, err)
                self.assertIn("so Codex does not use it", " ".join(out.split()))
                self.assertIn("codex-home-file", out)
                self.assertFits(out, int(width))

    def test_a_found_agent(self):
        codex = af.AGENTS[0]
        root = self.agent_root(codex)
        codex.write(root, _calls(self.now))
        codex.read_only(root, OTHER)
        [entry] = self.entries("--source", "codex", "--path", "codex=" + root)
        self.assertEqual((entry["status"], entry["transcripts"],
                          entry["other_files"], entry["read_only_files"],
                          entry["masking"]), ("found", 1, 1, 1, "mixed"))
        self.assertEqual(entry["locations"][0]["path"], root)
        self.assertEqual(entry["locations"][0]["how"], "--path")
        rc, out, _ = self.run_cli("sources", "--source", "codex",
                                  "--path", "codex=" + root)
        text = " ".join(out.split())
        self.assertIn("Codex (codex): found, 1 session and 1 other file", text)
        self.assertIn("clean can mask 1 file; 1 file is read only", text)

    def test_what_clean_does_with_each(self):
        by_id = {e["id"]: e for e in self.entries(*self.base_flags())}
        # OpenClaw was "not searched" until design 3.9's follow-up
        self.assertNotIn("not searched", [e["masking"] for e in by_id.values()
                                          if e["id"] is not None])
        self.assertEqual(by_id["claude-code"]["locations"][0],
                         {"path": os.path.abspath(self.claude), "how": "--root",
                          "exists": True, "found": 0})
        rc, out, _ = self.run_cli("sources", *self.base_flags())
        text = " ".join(out.split())
        self.assertIn("Meta Muse:", text)
        self.assertIn("--source muse-code", text)
        self.assertIn("--source grok", text)
        self.assertIn("Amp:", text)
        self.assertIn("Cursor (cursor):", text)
        self.assertNotIn("clean does not search it", text)

    def test_openclaw_is_searched_read_only(self):
        import sqlite3
        path = os.path.join(self.openclaw, "agents", "a1", "agent",
                            "openclaw-agent.sqlite")
        os.makedirs(os.path.dirname(path))
        conn = sqlite3.connect(path)
        conn.execute("CREATE TABLE log (id TEXT, body TEXT, createdAt INTEGER)")
        conn.commit()
        conn.close()
        [entry] = self.entries("--source", "openclaw", *self.base_flags())
        self.assertEqual((entry["status"], entry["transcripts"],
                          entry["read_only_files"], entry["masking"]),
                         ("found", 1, 1, "read-only"))
        rc, out, _ = self.run_cli("sources", "--source", "openclaw",
                                  *self.base_flags())
        text = " ".join(out.split())
        self.assertIn("OpenClaw (openclaw): found, 1 database", text)
        self.assertIn("clean reads it only; it never changes these files", text)


class Review(_Cli):
    """The review's show, mask and rotate, for a finding in any agent's
    files."""

    def searched(self, *agents_and_roots):
        paths = {"claude-code": self.claude}
        paths.update(agents_and_roots)
        values = {}
        found = clean.scan_sources(sources=list(paths), root=self.claude,
                                   paths=paths, since_days=30, known=values)
        return found, values

    def review(self, found, values, *commands):
        out = io.StringIO()
        with mock.patch("builtins.input", side_effect=list(commands) + ["quit"]):
            clean.review(found.findings, found.scanned, stream=out,
                         values=values, paths=[], stores=found.stores)
        return out.getvalue()

    def test_show_names_the_agent_and_its_files(self):
        codex = af.AGENTS[0]
        root = self.agent_root(codex)
        path = codex.write(root, _calls(self.now))
        found, values = self.searched(("codex", root))
        text = self.review(found, values, "show 1")
        self.assertIn("agent      : Codex", text)
        self.assertIn(os.path.basename(path)[-20:], text)
        self.assertNotIn(SECRET, text)

    def test_mask_reaches_another_agents_file(self):
        codex = af.AGENTS[0]
        root = self.agent_root(codex)
        path = codex.write(root, _calls(self.now))
        found, values = self.searched(("codex", root))
        text = self.review(found, values, "mask 1")
        self.assertIn("masked in 1 file(s).", text)
        self.assertAllMasked(_read(path).decode("utf-8"), SECRET)

    def test_mask_of_a_read_only_finding_says_why_and_what_to_do(self):
        [qwen] = [a for a in af.AGENTS if a.id == "qwen"]
        root = self.agent_root(qwen)
        qwen.write(root, _calls(self.now)[:1])
        held = qwen.read_only(root, OTHER)
        digest = _sha(held)
        found, values = self.searched(("qwen", root))
        text = " ".join(self.review(found, values, "mask 1").split())
        self.assertIn("every file that holds it is read only", text)
        self.assertIn("remove it there", text)
        self.assertEqual(_sha(held), digest)

    def test_rotate_and_list(self):
        codex = af.AGENTS[0]
        root = self.agent_root(codex)
        codex.write(root, _calls(self.now))
        found, values = self.searched(("codex", root))
        text = self.review(found, values, "list", "rotate")
        self.assertIn("Stripe", text)
        self.assertNotIn(SECRET, text)



class ReadmeNamesEveryAgent(unittest.TestCase):
    """design 6: the README's Source / Location / Format table has a row
    for every adapter, in registry order, and the examples point at the
    flags that read them. (The site's table waits for its own change.)"""

    def readme(self):
        with open(os.path.join(REPO, "README.md"), encoding="utf-8") as fh:
            return fh.read()

    def test_the_table_is_the_registry_in_order(self):
        text = self.readme()
        table = text.split("| Source | Location | Format |", 1)[1].split("\n\n", 1)[0]
        rows = [line.split("|")[1].strip() for line in table.strip().split("\n")[1:]]
        names = [sources.get(i).name for i in sources.ids()]
        self.assertEqual([r.split(" (")[0] for r in rows], names)
        self.assertEqual(rows[-1], "OpenClaw")

    def test_the_examples(self):
        text = self.readme()
        for example in ("ranwhat watch --source codex", "ranwhat watch --path codex=",
                        "ranwhat sources"):
            self.assertIn(example, text)
        self.assertNotIn("--source openclaw", text)
        prose = " ".join(text.split())
        self.assertIn("Meta Muse runs in Meta's cloud", prose)
        self.assertIn("Muse Code, Meta's coding CLI, is supported", prose)
        self.assertIn("Grok Bot keeps its history in xAI's cloud", prose)
        self.assertIn("Grok Build, xAI's coding CLI, is supported", prose)
        self.assertNotIn("—", text)


if __name__ == "__main__":
    unittest.main()
