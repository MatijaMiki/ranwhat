"""ranwhat push (ranwhat/push.py): this machine's findings, as metadata.

What matters most is what is not in it. The document is built from five
facts (rule, severity, action id, agent, time) and counts, so these plant
a canary in every other field a record can hold, and every secret, command
and path a history can hold, and look for any of them in what would be
sent. The send path runs against a server on this machine, http.server in a
thread (the end-to-end run against the Worker itself is the Worker's own
test). No test reaches the network, and every token is made at run time.
Every value here is synthetic, and every file is in a temp directory.
"""
import calendar
import copy
import getpass
import io
import json
import os
import random
import re
import socket
import subprocess
import sys
import time
import unittest
from unittest import mock

TESTS = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(TESTS)
sys.path.insert(0, ROOT)
sys.path.insert(0, TESTS)

import isolated_home  # noqa: E402,F401  ranwhat's state, never ~/.ranwhat
import test_account as ta  # noqa: E402
import test_ignore_identity as ti  # noqa: E402
from ranwhat import account, cli, feed, push, sources, watch  # noqa: E402

NOW = 1792504800                      # 2026-10-20T14:00:00Z
STRIPE = "sk_" "live_" "Fx7Qw2Er9Ty4Ui1Op6As3Df"
PW = "Hq7xT2mVp9LwZr4kNd"
CANARY = "ZZCANARY"
RULES = sorted(r.id for r in watch.RULES)
AGENTS = list(sources.ids())


def hit(rule="cred.read", severity="critical", **extra):
    out = {"rule": rule, "severity": severity}
    out.update(extra)
    return out


def rec(n=1, hits=None, source="claude-code", at=None, **extra):
    """A record as watch makes one, with a canary in every field push must
    not read."""
    out = {
        "id": "%016x" % (0xA0B0C0D0E0F00000 + n),
        "source": source,
        "session": CANARY + "-session",
        "project": "/home/" + CANARY + "/project",
        "cwd": "/home/" + CANARY + "/cwd",
        "timestamp": at if at is not None else "2026-10-20T13:%02d:00Z" % (n % 60),
        "tool_name": CANARY + "-tool",
        "tool_call_id": CANARY + "-call",
        "payload_hash": CANARY + "-hash",
        "severity": "critical",
        "hits": hits if hits is not None else [hit(
            title=CANARY + " title", why=CANARY + " why",
            evidence=CANARY + " evidence " + STRIPE,
            _subject=CANARY + " subject", _on=CANARY + " on", _cd=CANARY)],
        "ids": [CANARY],
        "actor": CANARY, "kind": CANARY, "status": CANARY,
    }
    out.update(extra)
    return out


def build(records, **kw):
    args = dict(scanned={"claude-code": 5}, unread={}, ignored=0, days=30,
                version="0.8.0", now=NOW)
    args.update(kw)
    return push.build(records, **args)


class TheDocumentHoldsNothingButMetadata(unittest.TestCase):

    def test_no_canary_in_any_field_reaches_it(self):
        records = [rec(n) for n in range(1, 8)] + [
            rec(20, hits=[hit(), hit("publish", "high", evidence=CANARY)])]
        text = push.dumps(build(records))
        self.assertNotIn(CANARY, text)
        self.assertNotIn(STRIPE, text)
        push.check(json.loads(text), now=NOW)

    def test_a_field_added_to_a_record_or_a_hit_changes_nothing(self):
        plain = [rec(1), rec(2, source="codex")]
        more = copy.deepcopy(plain)
        for r in more:
            r["brand_new_field"] = CANARY
            r["nested"] = {"deep": [CANARY]}
            for h in r["hits"]:
                h["added_later"] = CANARY
                h["list"] = [CANARY]
        self.assertEqual(push.dumps(build(plain)), push.dumps(build(more)))

    def test_every_key_in_it_is_one_the_allow_list_names(self):
        doc = build([rec(1), rec(2, source="codex")])
        self.assertEqual(set(doc), {"v", "ranwhat", "generated_at", "window_days",
                                    "counts", "actions"})
        self.assertEqual(set(doc["counts"]), {
            "flagged", "ignored", "omitted", "unread", "severity", "rules",
            "agents", "scanned"})
        for action in doc["actions"]:
            self.assertEqual(set(action), {"id", "agent", "at", "hits"})
            for h in action["hits"]:
                self.assertEqual(set(h), {"rule", "severity"})

    def test_a_history_with_planted_secrets_commands_and_paths(self):
        """A real scan over a transcript that holds a secret in a command,
        a credential read, a destructive command and a publish, run in a
        project folder, from a working directory, under a session id."""
        class Home(ti._Home):
            def runTest(self):
                pass
        home = Home()
        home.setUp()
        self.addCleanup(home.doCleanups)
        cwd = os.path.join(home.home, "work", CANARY + "-client-x")
        rows = [
            ti.bash("toolu_1", "cat ~/.aws/credentials # " + CANARY + "-cmd", home.now + 1, cwd=cwd),
            ti.bash("toolu_2", "git push --force origin main # " + CANARY + "-cmd", home.now + 2, cwd=cwd),
            ti.bash("toolu_3", "npm publish --token " + STRIPE, home.now + 3, cwd=cwd),
            ti.bash("toolu_4", "echo password=" + PW + " >> /etc/" + CANARY + "-cfg", home.now + 4, cwd=cwd),
        ]
        home.transcript(rows, name=CANARY + "-session")
        records = home.scan()
        self.assertGreaterEqual(len(records), 3)
        records, _dropped = push.sendable(records)
        doc = build(records, now=time.time())
        text = push.dumps(doc, indent=2)
        for planted in (STRIPE, PW, CANARY, "aws", "credentials", "git push",
                        "npm", "publish --token", home.home, home.tmp, "/etc",
                        "work", getpass.getuser(), socket.gethostname(),
                        os.getcwd(), os.path.expanduser("~")):
            if planted in ("publish --token",):
                continue
            self.assertNotIn(planted, text.replace("cred.read", "")
                             .replace("publish", "").replace("secret.literal", ""),
                             planted)
        self.assertEqual({a["agent"] for a in doc["actions"]}, {"claude-code"})
        rules = {h["rule"] for a in doc["actions"] for h in a["hits"]}
        self.assertTrue({"cred.read", "git.destructive"} <= rules, rules)
        push.check(doc, now=time.time())


class BuildingIt(unittest.TestCase):

    def test_critical_first_newest_first_and_the_rest_counted(self):
        records = [rec(n, hits=[hit("publish", "medium")]) for n in range(1, 4)]
        records += [rec(10 + n, hits=[hit("cred.read", "critical")]) for n in range(1, 4)]
        records += [rec(20, hits=[hit("fs.destructive", "high")])]
        doc = build(records)
        order = [a["hits"][0]["severity"] for a in doc["actions"]]
        self.assertEqual(order, ["critical"] * 3 + ["high"] + ["medium"] * 3)
        crit = [a["at"] for a in doc["actions"][:3]]
        self.assertEqual(crit, sorted(crit, reverse=True))
        self.assertEqual(doc["counts"]["severity"], {"critical": 3, "high": 1, "medium": 3})
        self.assertEqual(doc["counts"]["flagged"], 7)
        self.assertEqual(doc["counts"]["rules"], {"publish": 3, "cred.read": 3,
                                                  "fs.destructive": 1})
        self.assertEqual(doc["counts"]["agents"], {"claude-code": 7})

    def test_more_than_the_cap_is_counted_and_not_listed(self):
        records = [rec(n, hits=[hit("publish", "medium")]) for n in range(1, 131)]
        records.append(rec(999, hits=[hit("cred.read", "critical")]))
        doc = build(records)
        self.assertEqual(len(doc["actions"]), push.MAX_ACTIONS)
        self.assertEqual(doc["counts"]["flagged"], 131)
        self.assertEqual(doc["counts"]["omitted"], 31)
        self.assertEqual(doc["actions"][0]["hits"][0]["severity"], "critical")
        push.check(doc, now=NOW)

    def test_a_body_past_what_the_server_takes_lists_fewer(self):
        every = [hit(r, "high") for r in RULES]
        records = [rec(n, hits=every) for n in range(1, 101)]
        doc = build(records)
        self.assertLessEqual(len(push.dumps(doc)), push.MAX_BODY)
        self.assertLess(len(doc["actions"]), 100)
        self.assertEqual(doc["counts"]["omitted"] + len(doc["actions"]), 100)
        push.check(doc, now=NOW)

    def test_a_rule_twice_counts_once_at_its_highest_severity(self):
        doc = build([rec(1, hits=[hit("cred.read", "high"), hit("cred.read", "critical"),
                                  hit("publish", "medium")])])
        (action,) = doc["actions"]
        self.assertEqual(action["hits"], [{"rule": "cred.read", "severity": "critical"},
                                          {"rule": "publish", "severity": "medium"}])
        self.assertEqual(doc["counts"]["severity"]["critical"], 1)

    def test_a_record_with_no_id_is_counted_and_not_listed(self):
        records = [rec(1), rec(2, id="NOT-HEX-" + CANARY)]
        doc = build(records)
        self.assertEqual(doc["counts"]["flagged"], 2)
        self.assertEqual(doc["counts"]["omitted"], 1)
        self.assertEqual(len(doc["actions"]), 1)
        self.assertNotIn(CANARY, push.dumps(doc))
        push.check(doc, now=NOW)

    def test_records_push_cannot_describe_are_set_aside(self):
        records = [rec(1), rec(2, source="no-such-agent"),
                   rec(3, hits=[hit("no.such.rule")]), rec(4, hits=[hit("publish", "urgent")]),
                   rec(5, hits=[]), "not a record"]
        kept, dropped = push.sendable(records)
        self.assertEqual(len(kept), 1)
        self.assertEqual(dropped, 5)

    def test_times_are_utc_to_the_second(self):
        cases = {
            "2026-10-20T13:58:02Z": "2026-10-20T13:58:02Z",
            "2026-10-20T13:58:02.789Z": "2026-10-20T13:58:02Z",
            "2026-10-20T15:58:02+02:00": "2026-10-20T13:58:02Z",
            "2026-10-20T08:58:02-05:00": "2026-10-20T13:58:02Z",
        }
        for stamp, want in cases.items():
            (action,) = build([rec(1, at=stamp)])["actions"]
            self.assertEqual(action["at"], want, stamp)

    def test_no_time_garbage_or_an_impossible_one_is_null(self):
        for stamp in (None, "", "yesterday", "9999-99-99", "2020-01-01T00:00:00Z",
                      "2030-01-01T00:00:00Z", 12345, {"a": 1}):
            doc = build([rec(1, timestamp=stamp)])
            self.assertIsNone(doc["actions"][0]["at"], stamp)
            push.check(doc, now=NOW)

    def test_a_stamp_with_no_zone_is_local_time_made_utc(self):
        if not hasattr(time, "tzset"):
            self.skipTest("no tzset")
        old = os.environ.get("TZ")
        self.addCleanup(lambda: (os.environ.__setitem__("TZ", old) if old
                                 else os.environ.pop("TZ", None), time.tzset()))
        for zone in ("America/New_York", "Asia/Kolkata", "UTC"):
            os.environ["TZ"] = zone
            time.tzset()
            local = time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(
                calendar.timegm((2026, 10, 20, 13, 0, 0))))
            (action,) = build([rec(1, at=local)])["actions"]
            self.assertEqual(action["at"], "2026-10-20T13:00:00Z", zone)

    def test_counts_of_ignored_unread_and_read(self):
        doc = build([rec(1)], ignored=3, unread={"claude-code": 2, "codex": 1},
                    scanned={"claude-code": 41, "codex": 7, "no-such": 9, "grok": 0})
        self.assertEqual(doc["counts"]["ignored"], 3)
        self.assertEqual(doc["counts"]["unread"], 3)
        self.assertEqual(doc["counts"]["scanned"], {"claude-code": 41, "codex": 7})
        self.assertEqual(doc["window_days"], 30)
        self.assertEqual(doc["ranwhat"], "0.8.0")
        self.assertEqual(doc["generated_at"], "2026-10-20T14:00:00Z")

    def test_nothing_flagged_is_a_zero_snapshot(self):
        doc = build([], scanned={"claude-code": 9}, ignored=2)
        self.assertEqual(doc["actions"], [])
        self.assertEqual(doc["counts"]["flagged"], 0)
        self.assertEqual(doc["counts"]["severity"], {"critical": 0, "high": 0, "medium": 0})
        self.assertEqual(doc["counts"]["rules"], {})
        push.check(doc, now=NOW)

    def test_what_build_makes_check_accepts(self):
        rng = random.Random(7)
        for round in range(200):
            records = []
            for n in range(rng.randint(0, 30)):
                hits = [hit(rng.choice(RULES), rng.choice(push.SEVERITIES))
                        for _ in range(rng.randint(1, 4))]
                records.append(rec(n + 1, hits=hits, source=rng.choice(AGENTS),
                                   at=rng.choice([None, "2026-10-19T12:00:00Z", "junk",
                                                  "2026-10-20T13:59:59+02:00"])))
            doc = build(records, ignored=rng.randint(0, 5), days=rng.randint(1, 365))
            push.check(json.loads(push.dumps(doc)), now=NOW)

    def test_the_text_dumps_are_one_document(self):
        doc = build([rec(1), rec(2)])
        self.assertEqual(json.loads(push.dumps(doc)), json.loads(push.dumps(doc, indent=2)))
        self.assertNotIn(" ", push.dumps(doc).replace("claude-code", ""))


class TheAllowListHere(unittest.TestCase):
    """check() is the client's copy of the server's rules: every object
    takes exactly its keys."""

    def good(self):
        return build([rec(1), rec(2, source="codex", hits=[hit("publish", "high")])])

    def bad(self, doc, field, reason):
        with self.assertRaises(push.Invalid) as caught:
            push.check(doc, now=NOW)
        self.assertEqual((caught.exception.field, caught.exception.reason), (field, reason))

    def test_accepts_the_good_one(self):
        push.check(self.good(), now=NOW)

    def test_an_unknown_key_at_every_level(self):
        # The pointer is the containing object's: a key name is request data.
        for path, field in ((("",), "/"), (("counts",), "/counts"),
                            (("counts", "severity"), "/counts/severity"),
                            (("actions", 0), "/actions/0"),
                            (("actions", 0, "hits", 0), "/actions/0/hits/0")):
            doc = self.good()
            node = doc
            for step in path:
                if step != "":
                    node = node[step]
            node["hostname"] = CANARY
            self.bad(doc, field, "unknown_key")

    def test_a_missing_key(self):
        doc = self.good()
        del doc["counts"]["ignored"]
        self.bad(doc, "/counts/ignored", "missing")

    def test_types_and_ranges(self):
        cases = [
            (lambda d: d.__setitem__("v", 2), "/v", "unsupported_version"),
            (lambda d: d.__setitem__("v", "1"), "/v", "type"),
            (lambda d: d.__setitem__("v", True), "/v", "type"),
            (lambda d: d.__setitem__("window_days", 0), "/window_days", "range"),
            (lambda d: d.__setitem__("window_days", 366), "/window_days", "range"),
            (lambda d: d.__setitem__("window_days", 1.5), "/window_days", "type"),
            (lambda d: d["counts"].__setitem__("ignored", -1), "/counts/ignored", "range"),
            (lambda d: d["counts"].__setitem__("unread", "3"), "/counts/unread", "type"),
            (lambda d: d.__setitem__("ranwhat", "v1"), "/ranwhat", "format"),
            (lambda d: d.__setitem__("generated_at", "2026-02-31T00:00:00Z"), "/generated_at", "format"),
            (lambda d: d.__setitem__("generated_at", "2026-10-20T14:00:00+01:00"), "/generated_at", "format"),
            (lambda d: d.__setitem__("generated_at", "2026-10-20t14:00:00z"), "/generated_at", "format"),
            (lambda d: d.__setitem__("generated_at", "2026-10-01T14:00:00Z"), "/generated_at", "range"),
            (lambda d: d.__setitem__("actions", {}), "/actions", "type"),
            (lambda d: d["actions"][0].__setitem__("id", "A" * 16), "/actions/0/id", "format"),
            (lambda d: d["actions"][0].__setitem__("id", "a" * 15), "/actions/0/id", "format"),
            (lambda d: d["actions"][0].__setitem__("id", "a" * 16 + "\n"), "/actions/0/id", "format"),
            (lambda d: d["actions"][0].__setitem__("agent", CANARY), "/actions/0/agent", "unknown_value"),
            (lambda d: d["actions"][0].__setitem__("at", "2024-01-01T00:00:00Z"), "/actions/0/at", "range"),
            (lambda d: d["actions"][0].__setitem__("hits", []), "/actions/0/hits", "range"),
            (lambda d: d["actions"][0]["hits"][0].__setitem__("rule", CANARY), "/actions/0/hits/0/rule", "unknown_value"),
            (lambda d: d["actions"][0]["hits"][0].__setitem__("severity", "low"), "/actions/0/hits/0/severity", "unknown_value"),
        ]
        for change, field, reason in cases:
            doc = self.good()
            change(doc)
            self.bad(doc, field, reason)

    def test_duplicates_and_sums(self):
        doc = self.good()
        doc["actions"][1]["id"] = doc["actions"][0]["id"]
        self.bad(doc, "/actions/1/id", "duplicate")
        doc = self.good()
        doc["actions"][0]["hits"].append(dict(doc["actions"][0]["hits"][0]))
        self.bad(doc, "/actions/0/hits/1/rule", "duplicate")
        doc = self.good()
        doc["counts"]["severity"]["high"] += 1
        self.bad(doc, "/counts/severity", "inconsistent")
        doc = self.good()
        doc["counts"]["agents"]["claude-code"] += 1
        doc["counts"]["flagged"] += 1
        doc["counts"]["severity"]["high"] += 1
        self.bad(doc, "/actions", "inconsistent")
        doc = self.good()
        doc["counts"]["omitted"] = 1
        self.bad(doc, "/actions", "inconsistent")

    def test_a_count_key_that_is_not_a_rule_or_an_agent(self):
        doc = self.good()
        doc["counts"]["rules"][CANARY] = 1
        self.bad(doc, "/counts/rules", "unknown_value")
        doc = self.good()
        doc["counts"]["scanned"][CANARY] = 1
        self.bad(doc, "/counts/scanned", "unknown_value")

    def test_every_rule_and_agent_the_cli_has_is_in_it(self):
        self.assertEqual(push.rule_ids(), frozenset(r.id for r in watch.RULES))
        self.assertEqual(push.agent_ids(), frozenset(sources.ids()))
        hits = [hit(r, "high") for r in RULES]
        doc = build([rec(n, hits=hits, source=a) for n, a in enumerate(AGENTS, 1)][:20],
                    scanned={a: 1 for a in AGENTS})
        push.check(doc, now=NOW)


# ---------- the command ----------

class _Terminal(io.StringIO):
    def isatty(self):
        return True


class _Cli(ti._Home):
    """A temp history, ranwhat's state, and a server on this machine."""

    def setUp(self):
        super().setUp()
        self.server = ta.Server()
        self.addCleanup(self.server.close)
        self.state = os.environ["RANWHAT_HOME"]
        self.token = ta.made()
        env = {"RANWHAT_ACCOUNT_URL": self.server.base, "RANWHAT_TOKEN": self.token}
        patch = mock.patch.dict(os.environ, env)
        patch.start()
        self.addCleanup(patch.stop)
        patch = mock.patch.object(cli, "invocation", return_value="ranwhat")
        patch.start()
        self.addCleanup(patch.stop)

    def history(self, *commands, cwd=None):
        rows = [ti.bash("toolu_%d" % i, command, self.now + i, cwd=cwd)
                for i, command in enumerate(commands, 1)]
        self.transcript(rows)

    BAD = ("cat ~/.aws/credentials", "git push --force origin main", "npm publish")

    def push(self, *argv, tty=False, answers=(), stdin_tty=None):
        out = _Terminal() if tty else io.StringIO()
        err = io.StringIO()
        stdin = _Terminal() if (tty if stdin_tty is None else stdin_tty) else io.StringIO()
        replies = iter(answers)

        def ask(prompt=""):
            out.write(prompt)
            try:
                return next(replies)
            except StopIteration:
                raise EOFError
        with mock.patch("sys.stdout", out), mock.patch("sys.stderr", err), \
                mock.patch("sys.stdin", stdin), mock.patch("builtins.input", ask):
            try:
                rc = cli.main(["push"] + list(argv) + self.flags())
            except SystemExit as exit:
                rc = exit.code
        return rc, out.getvalue(), err.getvalue()

    def stored(self, **extra):
        doc = {"ok": True, "v": 1, "status": "stored", "received_at": "2026-10-20T14:03:12Z",
               "org": "Acme", "machine": "Work laptop", "actions": 3,
               "keeps": {"latest": 1, "snapshots": 30, "days": 30}}
        doc.update(extra)
        self.server.on("POST", "/push", (200, doc))

    def sent(self):
        return self.server.requests("/push")


def flat(text):
    return " ".join(text.split())


class DryRun(_Cli):

    def test_stdout_is_the_json_alone_and_stderr_says_so(self):
        self.history(*self.BAD)
        rc, out, err = self.push("--dry-run")
        self.assertEqual(rc, 0)
        doc = json.loads(out)
        push.check(doc, now=time.time())
        self.assertEqual(doc["counts"]["flagged"], len(doc["actions"]))
        self.assertGreaterEqual(doc["counts"]["flagged"], 3)
        self.assertIn("Dry run: this is the exact JSON push would send. Nothing was sent.", err)
        self.assertEqual(self.sent(), [])

    def test_it_needs_no_token_and_opens_no_socket(self):
        self.history(*self.BAD)
        os.environ.pop("RANWHAT_TOKEN")
        with mock.patch.object(socket.socket, "connect", side_effect=AssertionError("connect")):
            rc, out, err = self.push("--dry-run")
        self.assertEqual(rc, 0, err)
        self.assertEqual(json.loads(out)["v"], 1)

    def test_json_changes_nothing(self):
        self.history(*self.BAD)
        a = self.push("--dry-run")
        b = self.push("--dry-run", "--json")
        self.assertEqual(json.loads(a[1])["actions"], json.loads(b[1])["actions"])
        self.assertEqual(a[0], b[0])

    def test_it_never_loads_the_network_stack(self):
        self.history(*self.BAD)
        code = ("import sys, io, contextlib\n"
                "from ranwhat import cli\n"
                "out = io.StringIO()\n"
                "with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):\n"
                "    rc = cli.main(['push', '--dry-run', '--root', sys.argv[1], '--state-dir', sys.argv[2]])\n"
                "print(rc, sorted(m for m in ('urllib.request', 'http.client', 'ssl',\n"
                "    'ranwhat.feed', 'ranwhat.account', 'ranwhat.introspect') if m in sys.modules))\n")
        env = dict(os.environ, PYTHONPATH=ROOT, NO_COLOR="1")
        got = subprocess.run([sys.executable, "-c", code, self.claude, self.nowhere],
                             capture_output=True, text=True, env=env, timeout=120)
        self.assertEqual(got.stdout.strip(), "0 []", got.stderr)

    def test_the_ignore_file_leaves_an_action_out_and_counts_it(self):
        self.history(*self.BAD)
        full = json.loads(self.push("--dry-run")[1])
        victim = full["actions"][0]
        ignore_file = os.path.join(self.tmp, "ignore-me")
        with open(ignore_file, "w", encoding="utf-8") as fh:
            fh.write("%s\n" % victim["id"])
        rc, out, err = self.push("--dry-run", "--ignore", ignore_file)
        self.assertEqual(rc, 0, err)
        doc = json.loads(out)
        self.assertNotIn(victim["id"], [a["id"] for a in doc["actions"]])
        self.assertEqual(doc["counts"]["ignored"], 1)
        self.assertEqual(doc["counts"]["flagged"], full["counts"]["flagged"] - 1)
        self.assertNotIn(victim["id"], out)

    def test_days_sets_the_window_and_the_read(self):
        self.history(*self.BAD)
        self.assertEqual(json.loads(self.push("--dry-run", "--days", "7")[1])["window_days"], 7)
        rc, out, err = self.push("--dry-run", "--days", "1")
        self.assertEqual(json.loads(out)["window_days"], 1)

    def test_a_secret_in_a_command_never_appears(self):
        self.history("npm publish --token " + STRIPE, "echo " + PW + " > ~/.aws/credentials",
                     "cat ~/.ssh/id_rsa")
        rc, out, err = self.push("--dry-run")
        self.assertEqual(rc, 0, err)
        for planted in (STRIPE, PW, "ssh", "credentials", "npm", "home", self.tmp):
            self.assertNotIn(planted, out)
            self.assertNotIn(planted, err)


class NothingToSend(_Cli):

    def test_no_history_exits_2_and_sends_nothing(self):
        rc, out, err = self.push("--yes")
        self.assertEqual(rc, 2)
        self.assertIn("Nothing was sent.", err)
        self.assertEqual(self.sent(), [])

    def test_history_nobody_could_read_exits_1(self):
        bad = os.path.join(self.claude, "-home-dev-app", "s1.jsonl")
        os.makedirs(os.path.dirname(bad))
        with mock.patch("ranwhat.cli._watch_scan",
                        return_value=([], {}, {"claude-code": 2}, None)):
            rc, out, err = self.push("--yes")
        self.assertEqual(rc, 1)
        self.assertIn("could read none of the 2 transcripts", flat(err))
        self.assertEqual(self.sent(), [])

    def test_a_clean_history_sends_a_zero_snapshot(self):
        self.history("ls", "echo hello", "python3 -m pytest")
        self.stored(actions=0)
        rc, out, err = self.push("--yes")
        self.assertEqual(rc, 0, err)
        (request,) = self.sent()
        body = json.loads(request["body"])
        self.assertEqual(body["counts"]["flagged"], 0)
        self.assertEqual(body["actions"], [])
        self.assertEqual(body["counts"]["scanned"], {"claude-code": 1})
        self.assertIn("Nothing flagged in the last 30 days (1 transcript read).", flat(out))
        self.assertIn("a clean snapshot", flat(out))


class Sending(_Cli):

    def test_the_server_gets_exactly_the_dry_run_document(self):
        self.history(*self.BAD)
        self.stored()
        dry = json.loads(self.push("--dry-run")[1])
        rc, out, err = self.push("--yes")
        self.assertEqual(rc, 0, err)
        (request,) = self.sent()
        self.assertEqual(request["method"], "POST")
        self.assertEqual(request["path"], "/v1/push")
        sent = json.loads(request["body"])
        for doc in (dry, sent):
            doc.pop("generated_at")
        self.assertEqual(sent, dry)
        headers = {k.lower(): v for k, v in request["headers"].items()}
        self.assertEqual(headers["authorization"], "Bearer " + self.token)
        self.assertEqual(headers["content-type"], "application/json")
        self.assertEqual(headers["user-agent"], "ranwhat-cli/1")
        self.assertNotIn("cookie", headers)
        self.assertEqual(request["body"], push.dumps(json.loads(request["body"])))
        self.assertIn('Sent to Acme as "Work laptop": ', out)
        self.assertIn("https://account.ranwhat.com/findings", out)

    def test_the_token_is_in_no_argv_url_stdout_or_stderr(self):
        self.history(*self.BAD)
        self.stored()
        rc, out, err = self.push("--yes")
        (request,) = self.sent()
        self.assertNotIn(self.token, request["path"])
        self.assertNotIn(self.token, request["body"])
        self.assertNotIn(self.token, out + err)

    def test_the_summary_says_what_it_sends_before_asking(self):
        self.history(*self.BAD)
        self.stored()
        rc, out, err = self.push("--yes")
        said = flat(out)
        for text in ("ranwhat push: findings from the last 30 days, as metadata only.",
                     "To feed.ranwhat.com, over HTTPS, with this machine's token:",
                     "flagged actions:", "For each flagged action, only these four things:",
                     "Never sent: commands, paths, evidence, working directories, "
                     "session ids, file contents, secrets, your hostname or your user name.",
                     "Everyone in the organisation this machine is linked to can read it at "
                     "https://account.ranwhat.com/findings. Plus keeps this machine's latest "
                     "push, and a summary of each push for 30 days."):
            self.assertIn(text, said)
        self.assertRegex(out, r"(?m)^    [0-9a-f]{16}  \d{4}-\d\d-\d\d \d\d:\d\d:\d\d UTC  claude-code  ")

    def test_the_ignore_line_appears_only_when_something_was_ignored(self):
        self.history(*self.BAD)
        self.stored()
        self.assertNotIn("ignore file", self.push("--yes")[1])
        first = json.loads(self.push("--dry-run")[1])["actions"][0]["id"]
        path = os.path.join(self.tmp, "ig")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(first + "\n")
        out = self.push("--yes", "--ignore", path)[1]
        self.assertIn("1 more is in your ignore file: counted, not listed", out)

    def test_unchanged_is_said(self):
        self.history(*self.BAD)
        self.stored(status="unchanged")
        rc, out, err = self.push("--yes")
        self.assertEqual(rc, 0)
        self.assertIn("Nothing changed since this machine last pushed", flat(out))

    def test_json_prints_one_object(self):
        self.history(*self.BAD)
        self.stored()
        rc, out, err = self.push("--yes", "--json")
        self.assertEqual(rc, 0, err)
        got = json.loads(out)
        self.assertEqual(got["sent"], True)
        self.assertEqual(got["status"], "stored")
        self.assertEqual((got["org"], got["machine"]), ("Acme", "Work laptop"))
        self.assertEqual(got["received_at"], "2026-10-20T14:03:12Z")
        self.assertEqual(set(got), {"sent", "status", "actions", "ignored", "org",
                                    "machine", "received_at"})

    def test_a_hostile_org_and_machine_lose_their_control_characters(self):
        self.history(*self.BAD)
        self.stored(org="Ac\x1b[2Jme\u202e", machine="lap\x07top")
        rc, out, err = self.push("--yes")
        self.assertNotIn("\x1b", out)
        self.assertNotIn("\x07", out)
        self.assertNotIn("\u202e", out)
        self.assertIn('Sent to Ac[2Jme as "laptop"', out)


class Confirming(_Cli):

    def test_a_pipe_without_yes_sends_nothing(self):
        self.history(*self.BAD)
        self.stored()
        rc, out, err = self.push()
        self.assertEqual(rc, 1)
        self.assertIn("Not a terminal, so push will not send without --yes. "
                      "--dry-run shows what it would send.", flat(err))
        self.assertEqual(self.sent(), [])

    def test_json_without_yes_sends_nothing_even_on_a_terminal(self):
        self.history(*self.BAD)
        rc, out, err = self.push("--json", tty=True, answers=["y"])
        self.assertEqual(rc, 1)
        self.assertEqual(self.sent(), [])

    def test_only_a_typed_yes_sends(self):
        self.history(*self.BAD)
        self.stored()
        for answer in ("y", "yes", "YES", " Y "):
            self.server.seen.clear()
            rc, out, err = self.push(tty=True, answers=[answer])
            self.assertEqual(rc, 0, (answer, err))
            self.assertEqual(len(self.sent()), 1, answer)
            self.assertIn("Send it? [y/N]", out)

    def test_anything_else_does_not(self):
        self.history(*self.BAD)
        self.stored()
        for answer in ("n", "", "no", "yep", "ok", "sure"):
            rc, out, err = self.push(tty=True, answers=[answer])
            self.assertEqual(rc, 1, answer)
            self.assertIn("Cancelled. Nothing was sent.", err)
        rc, out, err = self.push(tty=True, answers=[])          # end of input
        self.assertEqual(rc, 1)
        self.assertEqual(self.sent(), [])

    def test_ctrl_c_at_the_prompt_is_130_and_sends_nothing(self):
        self.history(*self.BAD)

        def interrupt(prompt=""):
            raise KeyboardInterrupt
        out, err = _Terminal(), io.StringIO()
        with mock.patch("sys.stdout", out), mock.patch("sys.stderr", err), \
                mock.patch("sys.stdin", _Terminal()), mock.patch("builtins.input", interrupt):
            rc = cli.main(["push"] + self.flags())
        self.assertEqual(rc, 130)
        self.assertIn("Cancelled. Nothing was sent.", flat(err.getvalue()))
        self.assertEqual(self.sent(), [])

    def test_ctrl_c_while_sending_says_it_may_have_arrived(self):
        self.history(*self.BAD)
        with mock.patch.object(account, "_call", side_effect=KeyboardInterrupt):
            rc, out, err = self.push("--yes")
        self.assertEqual(rc, 130)
        self.assertIn("Cancelled while sending. If it arrived, ranwhat push again says "
                      "nothing changed.", flat(err))


class WhatTheServerSays(_Cli):

    def answer(self, status, doc, headers=None):
        self.history(*self.BAD)
        answer = (status, doc) if headers is None else (status, doc, headers)
        self.server.on("POST", "/push", answer)
        return self.push("--yes")

    def check(self, status, doc, expect, headers=None, rc=1, absent=()):
        got_rc, out, err = self.answer(status, doc, headers)
        self.assertEqual(got_rc, rc, err)
        text = flat(err)
        self.assertIn(expect, text)
        for nope in absent:
            self.assertNotIn(nope, out + err)
        self.assertNotIn("Sent to", out)
        return text

    def test_free_organisation(self):
        self.check(403, {"error": "plus_required", "upgrade": "https://account.ranwhat.com/"},
                   "This machine's organisation is on Free. Push is part of Plus: "
                   "https://account.ranwhat.com/ Nothing was sent. ranwhat watch shows "
                   "the same findings here.")

    def test_a_hostile_upgrade_link_is_not_printed(self):
        self.check(403, {"error": "plus_required", "upgrade": "https://evil.example/x"},
                   "https://account.ranwhat.com/", absent=("evil.example",))

    def test_a_subscription_token(self):
        self.check(403, {"error": "machine_required"},
                   "This token is a shared subscription token, not a machine's.")

    def test_a_token_the_server_refuses(self):
        for status, doc in ((401, {"error": "token_required"}),
                            (403, {"error": "token_refused"}), (403, {})):
            self.check(status, doc, "The server did not accept that token: it was revoked, "
                       "has expired, or is not a ranwhat token. Run ranwhat login to link "
                       "this machine again. Nothing was sent.")

    def test_404(self):
        self.check(404, {"error": "Not found."},
                   "The server is not taking pushes just now (HTTP 404). Nothing was sent.")

    def test_429_with_and_without_retry_after(self):
        self.check(429, {"error": "rate_limited"}, "Too many pushes from this machine lately. "
                   "Try again in 5 minutes.", headers={"Retry-After": "300"})
        self.check(429, {"error": "rate_limited"}, "Try again in 1 minute.",
                   headers={"Retry-After": "5"})
        self.check(429, {"error": "rate_limited"}, "Try again in 1440 minutes.",
                   headers={"Retry-After": "999999"})
        self.check(429, {"error": "rate_limited"}, "Try again later.",
                   headers={"Retry-After": "soon"})
        self.check(429, {"error": "org_full"}, "already has as many machines pushing")

    def test_409_both_kinds(self):
        self.check(409, {"error": "stale"}, "The server already has a newer push from this "
                   "machine, so nothing was changed.")
        self.check(409, {"error": "busy"}, "Another push from this machine was being stored.")

    def test_413(self):
        self.check(413, {"error": "too_large"}, "That push is larger than the server takes. "
                   "That is a bug in ranwhat, not something you did. Nothing was stored.")

    def test_422_names_the_field_and_not_a_hostile_one(self):
        self.check(422, {"error": "invalid", "field": "/actions/3/hits/0/rule",
                         "reason": "unknown_value"},
                   "The server refused what push built (unknown_value at "
                   "/actions/3/hits/0/rule).")
        text = self.check(422, {"error": "invalid", "field": "\x1b]52;c;" + CANARY,
                                "reason": "unknown_value\x1b"},
                          "The server refused what push built (invalid).",
                          absent=(CANARY, "\x1b"))

    def test_a_server_error(self):
        self.check(500, {"error": "boom"}, "feed.ranwhat.com answered HTTP 500. Nothing is "
                   "known to be stored; running ranwhat push again is safe.")
        self.check(503, {"error": "unavailable"}, "answered HTTP 503")

    def test_some_other_refusal(self):
        self.check(415, {"error": "unsupported_media_type"},
                   "The server refused the push (HTTP 415, unsupported_media_type). Nothing was sent.")
        self.check(400, {"error": "x" * 200}, "The server refused the push (HTTP 400).")

    def test_a_200_that_is_not_an_answer(self):
        for doc in ({}, {"ok": True}, {"ok": True, "status": "weird"},
                    {"ok": False, "status": "stored"}, {"ok": 1, "status": "stored"}):
            self.check(200, doc, "The server's answer was not one ranwhat understands.")

    def test_a_malformed_200(self):
        self.check(200, b"<html>not json</html>", "not one ranwhat understands")

    def test_a_redirect_is_not_followed_with_the_token(self):
        other = ta.Server()
        self.addCleanup(other.close)
        other.on("POST", "/steal", (200, {"ok": True}))
        got = self.check(307, {}, "not following it with your token",
                         headers={"Location": other.base + "/steal"})
        self.assertEqual(other.seen, [])

    def test_an_answer_over_64_kib(self):
        self.check(200, b"{" + b" " * (70 * 1024) + b"}", "larger than any it sends")

    def test_connection_refused(self):
        self.history(*self.BAD)
        dead = socket.socket()
        dead.bind(("127.0.0.1", 0))
        port = dead.getsockname()[1]
        dead.close()
        with mock.patch.dict(os.environ, {"RANWHAT_ACCOUNT_URL": "http://127.0.0.1:%d/v1" % port}):
            rc, out, err = self.push("--yes")
        self.assertEqual(rc, 1)
        self.assertIn("Could not reach 127.0.0.1", err)
        self.assertIn("running ranwhat push again is safe", flat(err))

    def test_a_timeout(self):
        self.history(*self.BAD)
        quiet = socket.socket()
        quiet.bind(("127.0.0.1", 0))
        quiet.listen(1)
        self.addCleanup(quiet.close)
        with mock.patch.dict(os.environ, {"RANWHAT_ACCOUNT_URL":
                                          "http://127.0.0.1:%d/v1" % quiet.getsockname()[1]}), \
                mock.patch.object(push, "TIMEOUT", 0.3):
            rc, out, err = self.push("--yes")
        self.assertEqual(rc, 1)
        self.assertIn("Could not reach", err)


class WhereItGoes(_Cli):

    def test_only_feed_ranwhat_com_or_this_machine(self):
        self.history(*self.BAD)
        for url in ("https://example.com/v1", "http://example.com/v1",
                    "https://feed.ranwhat.com.evil.example/v1",
                    "https://evil.example/feed.ranwhat.com/v1",
                    "http://feed.ranwhat.com/v1"):
            with mock.patch.dict(os.environ, {"RANWHAT_ACCOUNT_URL": url}), \
                    mock.patch.object(socket.socket, "connect",
                                      side_effect=AssertionError("connected")):
                rc, out, err = self.push("--yes")
            self.assertEqual(rc, 1, url)
            self.assertIn("push only talks to feed.ranwhat.com", flat(err), url)

    def test_the_real_address_is_https_to_feed_ranwhat_com(self):
        self.assertTrue(push._endpoint_ok("https://feed.ranwhat.com/v1/push"))
        self.assertEqual(account.DEFAULT_API + "/push", "https://feed.ranwhat.com/v1/push")
        self.assertTrue(push._endpoint_ok(self.server.base + "/push"))
        self.assertFalse(push._endpoint_ok("http://feed.ranwhat.com/v1/push"))

    def test_the_token_is_never_sent_with_a_dry_run_or_to_check_and_watch(self):
        self.history(*self.BAD)
        with mock.patch.object(socket.socket, "connect", side_effect=AssertionError("connect")):
            self.push("--dry-run")
            for command in ("watch", "check"):
                out, err = io.StringIO(), io.StringIO()
                with mock.patch("sys.stdout", out), mock.patch("sys.stderr", err):
                    cli.main([command, "--json"] + self.flags() if command == "watch"
                             else [command] + self.flags())
        self.assertEqual(self.server.seen, [])


class TheToken(_Cli):

    def setUp(self):
        super().setUp()
        self.file = feed.token_path()

    def test_the_environment_beats_the_file(self):
        os.makedirs(os.path.dirname(self.file), exist_ok=True)
        with open(self.file, "w", encoding="utf-8") as fh:
            fh.write(ta.made() + "\n")
        self.assertEqual(push.token(), (self.token, "env"))

    def test_the_saved_file_with_a_carriage_return(self):
        os.environ.pop("RANWHAT_TOKEN")
        saved = ta.made()
        os.makedirs(os.path.dirname(self.file), exist_ok=True)
        with open(self.file, "wb") as fh:
            fh.write(saved.encode() + b"\r\n")
        self.assertEqual(push.token(), (saved, "ok"))
        self.history(*self.BAD)
        self.stored()
        rc, out, err = self.push("--yes")
        self.assertEqual(rc, 0, err)
        auth = {k.lower(): v for k, v in self.sent()[0]["headers"].items()}["authorization"]
        self.assertEqual(auth, "Bearer " + saved)

    def test_a_token_with_a_line_break_in_it_is_refused_unrepeated(self):
        os.environ["RANWHAT_TOKEN"] = "rw_m_abc\ndef" + "x" * 30
        self.history(*self.BAD)
        rc, out, err = self.push("--yes")
        self.assertEqual(rc, 1)
        self.assertNotIn("rw_m_abc", out + err)
        self.assertEqual(self.sent(), [])

    @unittest.skipUnless(ta.POSIX, "symlinks")
    def test_a_symlinked_token_file_is_not_read(self):
        os.environ.pop("RANWHAT_TOKEN")
        target = os.path.join(self.tmp, "elsewhere")
        with open(target, "w", encoding="utf-8") as fh:
            fh.write(ta.made())
        os.makedirs(os.path.dirname(self.file), exist_ok=True)
        os.symlink(target, self.file)
        self.history(*self.BAD)
        rc, out, err = self.push("--yes")
        self.assertEqual(rc, 1)
        self.assertIn("is a symlink; not reading a token through it. Nothing was sent.", flat(err))
        self.assertEqual(self.sent(), [])

    @unittest.skipUnless(ta.POSIX, "modes")
    def test_an_unreadable_token_file(self):
        os.environ.pop("RANWHAT_TOKEN")
        os.makedirs(os.path.dirname(self.file), exist_ok=True)
        with open(self.file, "w", encoding="utf-8") as fh:
            fh.write("   \n")
        rc, out, err = self.push("--yes")
        self.assertEqual(rc, 1)
        self.assertIn("holds no token ranwhat can read. Nothing was sent.", flat(err))

    def test_no_token_is_said_and_found_before_the_history_is_read(self):
        os.environ.pop("RANWHAT_TOKEN")
        with mock.patch("ranwhat.cli._watch_scan", side_effect=AssertionError("read")):
            rc, out, err = self.push("--yes")
        self.assertEqual(rc, 1)
        self.assertIn("Not logged in. push sends a machine's findings to the organisation "
                      "it is linked to, so run ranwhat login first. Nothing was sent.", flat(err))


class Arguments(_Cli):

    def refused(self, *argv):
        err = io.StringIO()
        with mock.patch("sys.stderr", err), mock.patch("sys.stdout", io.StringIO()):
            with self.assertRaises(SystemExit) as caught:
                cli.main(list(argv))
        self.assertEqual(caught.exception.code, 2, argv)
        return err.getvalue()

    def test_flags_push_refuses(self):
        for argv, said in ((["push", "--token", "x"], "--token is for update and whoami"),
                           (["push", "--no-ignore"], "push never sends what the ignore file"),
                           (["push", "--fail-on", "high"], "--fail-on is only for"),
                           (["push", "--sarif", "x.sarif"], "--sarif is only for"),
                           (["push", "--html", "x.html"], "--html is only for"),
                           (["push", "--apply"], None), (["push", "--days", "0"], "--days must be at least 1"),
                           (["push", "--days", "366"], "1 to 365"),
                           (["push", "somewhere"], "push takes no path")):
            text = self.refused(*argv)
            if said:
                self.assertIn(said, text, argv)

    def test_dry_run_and_yes_are_for_push_alone(self):
        for command in ("check", "watch", "clean", "sources", "login", "whoami", "hook", "update"):
            for flag in ("--dry-run", "--yes"):
                self.assertIn("%s is only for push" % flag, self.refused(command, flag), (command, flag))

    def test_it_is_a_command_the_help_and_the_overview_list(self):
        names = [name for name, _what in cli.COMMANDS]
        self.assertIn("push", names)
        self.assertNotIn("push", cli._ACCOUNT_COMMANDS)
        out = io.StringIO()
        with mock.patch("sys.stdout", out), self.assertRaises(SystemExit):
            cli.main(["--help"])
        help_text = flat(out.getvalue())
        for text in ("--dry-run", "--yes", "push: print the exact JSON that would be sent",
                     "update, login, whoami, logout and push talk only to ranwhat.com",
                     "push sends derived metadata only, and only when you run it"):
            self.assertIn(text, help_text)
        out = io.StringIO()
        with mock.patch("sys.stdout", out):
            cli.main([])
        self.assertIn("push     send this machine's findings to your account, as metadata only",
                      out.getvalue())


class NeverAutomatic(unittest.TestCase):

    def test_nothing_but_the_command_loads_or_calls_push(self):
        for name in ("hook.py", "watch.py", "check.py", "sources/__init__.py"):
            path = os.path.join(ROOT, "ranwhat", name)
            if not os.path.exists(path):
                continue
            with open(path, encoding="utf-8") as fh:
                text = fh.read()
            self.assertNotRegex(text, r"push_mod|from \. import push|import ranwhat\.push"
                                      r"|from \.push|\.push\.", name)
        with open(os.path.join(ROOT, "ranwhat", "cli.py"), encoding="utf-8") as fh:
            lines = [n for n, line in enumerate(fh, 1) if '"push_mod"' in line]
        self.assertTrue(lines)

    def test_the_hook_installs_nothing_that_mentions_push(self):
        from ranwhat import hook
        for text in (json.dumps(getattr(hook, "MODES", {})), repr(getattr(hook, "SCOPES", ()))):
            self.assertNotIn("push", text)
        cmds = [attr for attr in dir(hook) if "COMMAND" in attr.upper()]
        for attr in cmds:
            self.assertNotIn("ranwhat push", str(getattr(hook, attr)))


if __name__ == "__main__":
    unittest.main()
