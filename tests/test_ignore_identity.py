"""Which action a record is: its id, the ids of the copies it stands for,
and where it ran (the ignore file's section 4).

ranwhat ignore names an action by the 16-character id watch gives it, so
an id must be the same on every run over the same history, whichever file
holding a copy of the call is read first, and must change when the call
is another one: run again, or flagged for something else. These read
histories through the scan watch and check run, and through the CLI.

Every value here is synthetic, and every file is in a temp directory.
"""
import io
import json
import os
import re
import shutil
import sqlite3
import sys
import tempfile
import time
import unittest
from unittest import mock

TESTS = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(TESTS))
sys.path.insert(0, TESTS)

import isolated_home  # noqa: E402,F401  ranwhat's state, never ~/.ranwhat
import agents_fixtures as af  # noqa: E402
from ranwhat import clean, cli, known, sources, watch  # noqa: E402
from ranwhat.sources import _paths  # noqa: E402
from ranwhat.sources.base import ToolCall  # noqa: E402

HEX16 = re.compile(r"[0-9a-f]{16}\Z")
KEYS = {"rule", "severity", "title", "why", "evidence"}
STRIPE = "sk_" "live_" "Fx7Qw2Er9Ty4Ui1Op6As3Df"
PW = "Hq7xT2mVp9LwZr4kNd"


def bash(tool_id, command, when, cwd=None):
    """A Claude Code assistant entry running one command."""
    entry = {"type": "assistant", "timestamp": af.iso(when), "message": {
        "content": [{"type": "tool_use", "id": tool_id, "name": "Bash",
                     "input": {"command": command}}]}}
    if cwd is not None:
        entry["cwd"] = cwd
    return entry


def record(stamp="2026-10-01T10:00:00Z", call_id="toolu_1", payload="p1",
           session="s1", hits=None, source="claude-code", tool="Bash"):
    """A record with only what action_id reads."""
    return {"source": source, "session": session, "timestamp": stamp,
            "tool_name": tool, "tool_call_id": call_id, "payload_hash": payload,
            "hits": hits if hits is not None else [
                {"rule": "fs.destructive", "severity": "high"}]}


class _Home(unittest.TestCase):
    """A temp home holding no agent's history, and ranwhat's state in a
    temp folder of its own."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="identity-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.home = os.path.join(self.tmp, "home")
        os.makedirs(self.home)
        env = {"HOME": self.home, "USERPROFILE": self.home,
               "RANWHAT_HOME": os.path.join(self.tmp, "state"),
               "NO_COLOR": "1", "RANWHAT_WIDTH": "80"}
        patches = [mock.patch.dict(os.environ, env),
                   mock.patch.object(_paths, "home", return_value=self.home),
                   mock.patch.object(clean, "BACKUP_ROOT",
                                     os.path.join(self.tmp, "backups"))]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        for name in af.AGENT_ENV:
            os.environ.pop(name, None)          # restored by patch.dict
        self.claude = os.path.join(self.tmp, "projects")
        os.makedirs(self.claude)
        self.nowhere = os.path.join(self.tmp, "no-openclaw")
        self.now = time.time() - 3 * 3600

    def transcript(self, rows, name="s1", age=3600):
        path = os.path.join(self.claude, "-home-dev-app", name + ".jsonl")
        return af.write(path, [json.dumps(r) for r in rows], age)

    def scan(self, ids=("claude-code",), paths=None, known_values=None,
             state_dir=None):
        for source in sources.sources():
            source.reset()
        records, _counts = watch.scan_sources_counted(
            sources=ids, root=self.claude, state_dir=state_dir or self.nowhere,
            paths=paths or {}, known=known_values)
        return records

    def run_cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch("sys.stdout", out), mock.patch("sys.stderr", err), \
                mock.patch("sys.stdin", io.StringIO()):
            try:
                rc = cli.main(list(argv))
            except SystemExit as exit:
                rc = exit.code
        return rc, out.getvalue(), err.getvalue()

    def flags(self):
        return ["--root", self.claude, "--state-dir", self.nowhere]


def _shown(records):
    """Each record's id and ids, as a baseline would hold them."""
    return sorted((r["id"], tuple(r.get("ids", ()))) for r in records)


def _age(path, seconds):
    when = time.time() - seconds
    os.utime(path, (when, when))


class Ids(_Home):

    def test_every_record_has_an_id_of_its_own(self):
        self.transcript([bash("toolu_1", "rm -rf ~/Documents/x", self.now),
                         bash("toolu_2", "cat ~/.ssh/id_rsa", self.now + 1),
                         bash("toolu_3", "git push --force origin main",
                              self.now + 2)])
        records = self.scan()
        self.assertEqual(len(records), 3)
        for r in records:
            self.assertRegex(r["id"], HEX16)
            self.assertNotIn("ids", r)       # one copy: no list of them
        self.assertEqual(len({r["id"] for r in records}), 3)

    def test_the_same_history_gives_the_same_ids_every_run(self):
        self.transcript([bash("toolu_1", "rm -rf ~/Documents/x", self.now),
                         bash("toolu_2", "cat ~/.ssh/id_rsa", self.now + 1)])
        self.assertEqual(_shown(self.scan()), _shown(self.scan()))

    def test_a_replayed_call_is_one_record_whichever_file_is_newer(self):
        # A resumed session copies every call before it, time and id alike.
        first = [bash("toolu_1", "rm -rf ~/Documents/x", self.now),
                 bash("toolu_2", "cat ~/.ssh/id_rsa", self.now + 1)]
        s1 = self.transcript(first, "s1", age=3600)
        s2 = self.transcript(first + [bash("toolu_3", "rm -rf ~/Documents/y",
                                           self.now + 9)], "s2", age=1800)
        before = self.scan()
        self.assertEqual(len(before), 3)
        kept = {r["id"]: r["session"] for r in before}
        _age(s1, 600)
        _age(s2, 7200)
        after = self.scan()
        self.assertEqual(_shown(before), _shown(after))
        self.assertEqual([r for r in before if "ids" in r], [])
        # the copy kept is the other one now, and the id did not follow it
        self.assertNotEqual(kept, {r["id"]: r["session"] for r in after})

    def test_the_same_command_run_again_is_another_action(self):
        self.transcript([bash("toolu_1", "rm -rf ~/Documents/x", self.now),
                         bash("toolu_2", "rm -rf ~/Documents/x", self.now + 60)])
        records = self.scan()
        self.assertEqual(len(records), 2)
        self.assertNotEqual(records[0]["id"], records[1]["id"])

    def test_a_call_id_keeps_the_id_when_the_index_learns_a_value(self):
        self.transcript([bash("toolu_1", "rm -rf ~/Documents/%s" % PW, self.now)])
        plain, = self.scan()
        learnt, = self.scan(known_values=known.Matcher.of([PW]))
        self.assertNotEqual(plain["payload_hash"], learnt["payload_hash"])
        self.assertEqual(plain["id"], learnt["id"])

    def test_clean_apply_keeps_the_id(self):
        self.transcript([bash("toolu_1", "rm -rf ~/Documents/x; echo %s" % STRIPE,
                              self.now)])
        watch_argv = ["watch", "--json", "--source", "claude-code"] + self.flags()
        rc, out, _err = self.run_cli(*watch_argv)
        before, = json.loads(out)
        self.assertIn("secret.literal", [h["rule"] for h in before["hits"]])
        rc, _out, _err = self.run_cli("clean", "--apply", "--no-interactive",
                                      "--source", "claude-code", *self.flags())
        self.assertEqual(rc, 0)
        rc, out, _err = self.run_cli(*watch_argv)
        after, = json.loads(out)
        self.assertNotIn("secret.literal", [h["rule"] for h in after["hits"]])
        self.assertNotEqual(before["payload_hash"], after["payload_hash"])
        self.assertEqual(before["id"], after["id"])

    def test_watch_and_check_give_the_same_ids(self):
        self.transcript([bash("toolu_1", "rm -rf ~/Documents/x", self.now),
                         bash("toolu_2", "cat .env", self.now + 1)])
        _rc, out, _err = self.run_cli("watch", "--json", *self.flags())
        watched = json.loads(out)
        _rc, out, _err = self.run_cli("check", "--json", *self.flags())
        checked = json.loads(out)["actions"]
        self.assertEqual(len(watched), 2)
        self.assertEqual(_shown(watched), _shown(checked))

    def test_with_a_call_id_the_input_is_no_part_of_it(self):
        self.assertEqual(watch.action_id(record(payload="a")),
                         watch.action_id(record(payload="b")))
        for empty in (None, "", [], {}):
            self.assertNotEqual(watch.action_id(record(call_id=empty, payload="a")),
                                watch.action_id(record(call_id=empty, payload="b")))

    def test_with_a_time_the_session_is_no_part_of_it(self):
        self.assertEqual(watch.action_id(record(session="s1")),
                         watch.action_id(record(session="s2")))
        for none in (None, ""):
            self.assertNotEqual(watch.action_id(record(stamp=none, session="s1")),
                                watch.action_id(record(stamp=none, session="s2")))

    def test_the_rules_and_their_severities_are_part_of_it(self):
        one = [{"rule": "fs.destructive", "severity": "high"}]
        base = watch.action_id(record(hits=one))
        self.assertNotEqual(base, watch.action_id(record(hits=[
            {"rule": "fs.destructive", "severity": "critical"}])))
        self.assertNotEqual(base, watch.action_id(record(hits=one + [
            {"rule": "cred.read", "severity": "critical"}])))
        # not their order, nor a secret clean may mask later
        self.assertEqual(watch.action_id(record(hits=one + [
            {"rule": "cred.read", "severity": "critical"}])),
            watch.action_id(record(hits=[
                {"rule": "cred.read", "severity": "critical"}] + one)))
        self.assertEqual(base, watch.action_id(record(hits=one + [
            {"rule": "secret.literal", "severity": "critical"}])))

    def test_the_agent_and_the_tool_are_part_of_it(self):
        base = watch.action_id(record())
        self.assertNotEqual(base, watch.action_id(record(source="codex")))
        self.assertNotEqual(base, watch.action_id(record(tool="exec")))

    def test_a_rule_rated_otherwise_lists_the_action_again(self):
        self.transcript([bash("toolu_1", "git push --force origin main",
                              self.now)])
        before, = self.scan()
        rule = next(r for r in watch.RULES if r.id == "git.destructive")
        with mock.patch.object(rule, "severity", watch.CRITICAL):
            after, = self.scan()
        self.assertEqual(after["severity"], watch.CRITICAL)
        self.assertNotEqual(before["id"], after["id"])

    def test_an_id_that_json_cannot_order_still_gives_an_id(self):
        odd = record(call_id={1: "a", "b": 2})
        self.assertRegex(watch.action_id(odd), HEX16)
        self.assertEqual(watch.action_id(odd), watch.action_id(dict(odd)))


class Aliases(_Home):
    """A record stands for every copy of its call that the scan kept it
    for, so that the ids it is known by are the same whichever copy was
    read first, and one copy more is something new."""

    def agent_stores(self, agent, names, base=None):
        root = agent.root(os.path.join(self.home, agent.id))
        calls = [("c1", "shell", "rm -rf ~/Documents/x", "ok\n", base or self.now),
                 ("c2", "shell", "git push --force origin main", "ok\n",
                  (base or self.now) + 1)]
        paths = [agent.write(root, calls, name=name, age=3600 - 600 * i)
                 for i, name in enumerate(names)]
        return root, paths

    def test_untimed_copies_settle_whichever_store_is_read_first(self):
        for agent in af.AGENTS:
            if agent.timed:
                continue
            with self.subTest(agent=agent.id):
                root, (a, b) = self.agent_stores(agent, "ab")
                paths = {agent.id: root}
                before = self.scan((agent.id,), paths)
                self.assertEqual(len(before), 2)
                for r in before:
                    self.assertEqual(len(r["ids"]), 2)
                    self.assertEqual(r["id"], r["ids"][0])
                    self.assertEqual(r["ids"], sorted(r["ids"]))
                    self.assertEqual(list(r)[:2], ["id", "ids"])
                sessions = {r["session"] for r in before}
                _age(a, 600)
                _age(b, 7200)
                after = self.scan((agent.id,), paths)
                self.assertEqual(_shown(before), _shown(after))
                self.assertNotEqual(sessions, {r["session"] for r in after})
                # a third copy is a new id among them: new to a baseline
                agent.write(root, [("c1", "shell", "rm -rf ~/Documents/x",
                                    "ok\n", self.now)], name="c", age=300)
                third = [r for r in self.scan((agent.id,), paths)
                         if "Documents" in r["hits"][0]["evidence"]]
                self.assertEqual(len(third[0]["ids"]), 3)
                old = [r for r in before if "Documents" in r["hits"][0]["evidence"]]
                self.assertTrue(set(old[0]["ids"]) < set(third[0]["ids"]))

    def test_timed_copies_are_one_id(self):
        for agent in af.AGENTS:
            if not agent.timed:
                continue
            with self.subTest(agent=agent.id):
                root, (a, b) = self.agent_stores(agent, "ab")
                paths = {agent.id: root}
                before = self.scan((agent.id,), paths)
                self.assertEqual(len(before), 2)
                self.assertEqual([r for r in before if "ids" in r], [])
                _age(a, 600)
                _age(b, 7200)
                self.assertEqual(_shown(before),
                                 _shown(self.scan((agent.id,), paths)))

    def openclaw(self, rows):
        """The records of one OpenClaw agent's database holding these
        (body, epoch) rows, in a state folder of its own."""
        state = tempfile.mkdtemp(prefix="oc-", dir=self.tmp)
        path = os.path.join(state, "agents", "a1", "agent", "openclaw-agent.sqlite")
        os.makedirs(os.path.dirname(path))
        conn = sqlite3.connect(path)
        conn.execute('CREATE TABLE "log" (id TEXT, body TEXT, createdAt INTEGER)')
        conn.executemany('INSERT INTO "log" VALUES (?, ?, ?)',
                         [(str(i), b, t) for i, (b, t) in enumerate(rows)])
        conn.commit()
        conn.close()
        return self.scan(("openclaw",), state_dir=state)

    def test_an_openclaw_call_run_again_has_the_id_of_every_run(self):
        body = json.dumps({"content": [{"type": "tool_use", "name": "bash",
                                        "input": {"command": "rm -rf ~/old"}}]})
        t = int(self.now)
        runs = [(body, t), (body, t + 60), (body, t + 120)]
        r, = self.openclaw(runs)
        self.assertEqual(len(r["ids"]), 3)
        self.assertEqual(r["id"], r["ids"][0])
        self.assertEqual(r["timestamp"], watch._as_iso(t + 120))  # the latest
        # in any order the rows are in
        self.assertEqual(_shown([r]), _shown(self.openclaw(runs[::-1])))
        # one run more: every id the record had, and a new one
        again, = self.openclaw(runs + [(body, t + 180)])
        self.assertEqual(len(again["ids"]), 4)
        self.assertTrue(set(r["ids"]) < set(again["ids"]))

    def test_two_calls_alike_in_one_message_are_one_record_with_both_ids(self):
        entry = bash("toolu_1", "rm -rf ~/Documents/x", self.now)
        entry["message"]["content"].append(
            dict(entry["message"]["content"][0], id="toolu_2"))
        self.transcript([entry])
        r, = self.scan()
        self.assertEqual(len(r["ids"]), 2)
        self.assertEqual(r["id"], min(r["ids"]))


class Baselines(_Home):
    """An action left out by its ids stays left out whichever copy of it a
    run reads first, and comes back only when it ran again."""

    def ignore_file(self):
        return os.path.join(self.tmp, "state", "ignore")

    def test_ignoring_a_replayed_call_hides_both_copies(self):
        first = [bash("toolu_1", "rm -rf ~/Documents/x", self.now)]
        s1 = self.transcript(first, "s1", age=3600)
        s2 = self.transcript(first, "s2", age=1800)
        rec, = self.scan()
        rc, _out, _err = self.run_cli("ignore", rec["id"], "--no-interactive",
                                      *self.flags())
        self.assertEqual(rc, 0)
        for older, newer in ((s1, s2), (s2, s1)):
            _age(older, 7200)
            _age(newer, 600)
            _rc, out, _err = self.run_cli("watch", "--json", *self.flags())
            self.assertEqual(json.loads(out), [])

    def test_untimed_copies_in_any_order_give_nothing_new(self):
        for agent in af.AGENTS:
            if agent.timed:
                continue
            with self.subTest(agent=agent.id):
                root = agent.root(os.path.join(self.home, agent.id))
                calls = [("c1", "shell", "rm -rf ~/Documents/x", "ok\n", self.now)]
                a = agent.write(root, calls, name="a", age=3600)
                b = agent.write(root, calls, name="b", age=1800)
                argv = ["--source", agent.id, "--path", "%s=%s" % (agent.id, root)]
                rc, _out, _err = self.run_cli("ignore", "all", *argv)
                self.assertEqual(rc, 0)
                _age(a, 600)
                _age(b, 7200)
                _rc, out, _err = self.run_cli("watch", "--json", *argv)
                self.assertEqual(json.loads(out), [])
                # a third copy is new
                agent.write(root, calls, name="c", age=300)
                _rc, out, _err = self.run_cli("watch", "--json", *argv)
                self.assertEqual(len(json.loads(out)), 1)
                os.remove(self.ignore_file())

    def test_an_openclaw_baseline_settles(self):
        # The regression: a baseline of the copy kept (the latest) left the
        # earlier copies' ids out, and a later run that kept another copy
        # listed it again. Every copy's id is in the baseline, so the call
        # is new only when it runs again.
        body = json.dumps({"content": [{"type": "tool_use", "name": "bash",
                                        "input": {"command": "rm -rf ~/old"}}]})
        t = int(self.now)

        def rows(runs):
            """A state folder of its own for each, so that no file a
            reader may still hold open is written over."""
            state = tempfile.mkdtemp(prefix="oc-", dir=self.tmp)
            path = os.path.join(state, "agents", "a1", "agent",
                                "openclaw-agent.sqlite")
            os.makedirs(os.path.dirname(path))
            conn = sqlite3.connect(path)
            conn.execute('CREATE TABLE "log" (id TEXT, body TEXT, createdAt INTEGER)')
            conn.executemany('INSERT INTO "log" VALUES (?, ?, ?)',
                             [(str(i), body, w) for i, w in enumerate(runs)])
            conn.commit()
            conn.close()
            return ["--source", "openclaw", "--state-dir", state]
        argv = rows([t, t + 60])
        rc, _out, _err = self.run_cli("ignore", "all", *argv)
        self.assertEqual(rc, 0)
        _rc, out, _err = self.run_cli("watch", "--json", *argv)
        self.assertEqual(json.loads(out), [])
        argv = rows([t + 60, t])                   # in another order
        _rc, out, _err = self.run_cli("watch", "--json", *argv)
        self.assertEqual(json.loads(out), [])
        argv = rows([t, t + 60, t + 120])          # run again
        _rc, out, _err = self.run_cli("watch", "--json", *argv)
        again, = json.loads(out)
        self.assertEqual(len(again["ids"]), 3)

    def test_the_ignore_commands_scan_gives_the_ids_watch_and_check_give(self):
        self.transcript([bash("toolu_1", "rm -rf ~/Documents/x", self.now),
                         bash("toolu_2", "cat .env", self.now + 1)])
        _rc, out, _err = self.run_cli("watch", "--json", *self.flags())
        watched = json.loads(out)
        _rc, out, _err = self.run_cli("check", "--json", *self.flags())
        checked = json.loads(out)["actions"]
        rc, _out, _err = self.run_cli("ignore", "all", *self.flags())
        self.assertEqual(rc, 0)
        with open(self.ignore_file(), encoding="utf-8") as fh:
            written = sorted(line.split()[0] for line in fh.read().split("\n")
                             if line and not line.startswith("#"))
        self.assertEqual(written, sorted(r["id"] for r in watched))
        self.assertEqual(_shown(watched), _shown(checked))


class WhereItRan(_Home):

    def test_claude_code_records_say_where_the_session_was(self):
        self.transcript([bash("toolu_1", "rm -rf ~/Documents/x", self.now,
                              cwd="/home/dev/app"),
                         bash("toolu_2", "rm -rf ~/Documents/y", self.now + 1)])
        by_id = {r["tool_call_id"]: r for r in self.scan()}
        self.assertEqual(by_id["toolu_1"]["cwd"], "/home/dev/app")
        self.assertNotIn("cwd", by_id["toolu_2"])
        self.assertEqual(list(by_id["toolu_1"])[:5],
                         ["id", "source", "session", "project", "cwd"])

    def test_the_directory_of_a_call(self):
        def cwd(source="codex", project=None, workdir=None):
            return watch._cwd_of(ToolCall(source, "/s", "Bash", {},
                                          project=project, workdir=workdir))
        self.assertEqual(cwd(workdir="/w"), "/w")
        self.assertEqual(cwd(project="/p", workdir="/w"), "/w")
        self.assertEqual(cwd(project="/p", workdir="sub"), "/p/sub")
        self.assertEqual(cwd(project="C:\\proj", workdir="sub"), "C:\\proj\\sub")
        self.assertEqual(cwd(workdir="C:/proj"), "C:/proj")
        self.assertEqual(cwd(project="/p"), "/p")
        self.assertEqual(cwd(project="\\\\server\\share"), "\\\\server\\share")
        self.assertIsNone(cwd(project="p", workdir="sub"))
        self.assertIsNone(cwd(project="table_name"))
        self.assertIsNone(cwd())
        self.assertIsNone(cwd(project=["/p"], workdir={"x": 1}))
        # a Claude Code project is a slug of the path, never the path
        self.assertIsNone(cwd("claude-code", project="/home-dev-app"))
        self.assertEqual(cwd("claude-code", project="-home-dev-app",
                             workdir="/home/dev/app"), "/home/dev/app")

    def test_the_verdict_does_not_change_with_it(self):
        for command in ("rm -rf ~/Documents/x", "cd /tmp && rm -rf build",
                        "cat .env"):
            calls = [ToolCall("claude-code", "/p", "Bash", {"command": command},
                              decode=False, workdir=w) for w in (None, "/tmp")]
            self.assertEqual(watch.judge(calls[0]), watch.judge(calls[1]))


class Json(_Home):
    """--json carries id, ids and cwd, and none of what the scan keeps for
    itself."""

    def test_watch_and_check_json(self):
        entry = bash("toolu_1", "cd /srv && npm publish", self.now,
                     cwd="/home/dev/app")
        twin = json.loads(json.dumps(entry))
        twin["message"]["content"][0]["id"] = "toolu_2"
        entry["message"]["content"] += twin["message"]["content"]
        self.transcript([entry, bash("toolu_3", "cat .env", self.now + 1)])
        _rc, out, _err = self.run_cli("watch", "--json", *self.flags())
        watched = json.loads(out)
        _rc, out, _err = self.run_cli("check", "--json", *self.flags())
        checked = json.loads(out)["actions"]
        for records in (watched, checked):
            publish, = [r for r in records if r["hits"][0]["rule"] == "publish"]
            self.assertEqual(len(publish["ids"]), 2)
            self.assertEqual(publish["cwd"], "/home/dev/app")
            for r in records:
                self.assertRegex(r["id"], HEX16)
                self.assertFalse([k for k in r if k.startswith("_")])
                for hit in r["hits"]:
                    self.assertEqual(set(hit), KEYS)

    def test_public_leaves_the_records_it_is_given(self):
        hits = [{"rule": "x", "evidence": "e", "_on": "command", "_subject": "s",
                 "_cd": ""}]
        records = [{"id": "0" * 16, "_private": 1, "hits": hits}]
        shown = watch.public(records)
        self.assertEqual(shown, [{"id": "0" * 16,
                                  "hits": [{"rule": "x", "evidence": "e"}]}])
        self.assertIn("_private", records[0])
        self.assertIn("_subject", records[0]["hits"][0])


if __name__ == "__main__":
    unittest.main()
