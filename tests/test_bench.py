"""ranwhat bench: the benchmark's own guarantees.

bench scores ranwhat's detection on made-up data, so what is tested here is
the benchmark: that its values are repeatable and shaped like a provider's,
that every case it asks of the detectors passes today, that a detector
which breaks makes it fail with the documented status, that a planted value
never reaches anything it or ranwhat prints, and that it touches nothing
outside its own temporary directory.

Every value is made up by bench.build, and every file is in a temp
directory: HOME is a sentinel inside one, and the tests that say the real
home is never touched look at what the sentinel saw.
"""
import ast
import builtins
import contextlib
import hashlib
import io
import json
import os
import random
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import unittest
import urllib.request
from unittest import mock

TESTS = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(TESTS)
sys.path.insert(0, REPO)
sys.path.insert(0, TESTS)

import isolated_home  # noqa: E402,F401  ranwhat's state, never ~/.ranwhat
import agents_fixtures as af  # noqa: E402
from ranwhat import bench, clean, cli, known, sources, term, watch  # noqa: E402
from ranwhat.sources import _paths  # noqa: E402

SEEDS = (bench.DEFAULT_SEED, 7, 4242)
OTHER = 7

# The answer key, as this test file reads it: a removed or added case is a
# deliberate edit here, not something the key can do on its own.
SECRETS = {"secret." + n for n in (
    "aws-access-key-id aws-secret-access-key github-ghp github-gho "
    "stripe-live slack-bot openai-key db-password db-url-password npm-token "
    "jwt private-key").split()}
DECOYS = {"decoy." + n for n in (
    "git-sha sha256 uuid base64-prose aws-doc stripe-doc placeholder "
    "code-call env-lookup").split()}
RISKY = {"risky." + n for n in (
    "rm-rf-home git-force-push git-reset-hard npm-publish curl-pipe-sh "
    "chmod-777 s3-rm-recursive drop-table docker-prune-volumes "
    "imds-credentials crontab-install hook-uninstall agent-no-prompts "
    "ignore-file-append read-env read-aws-credentials read-ssh-key "
    "read-ssh-key-tool read-ranwhat-key stripe-payout "
    "history-clear upload-env secret-in-header secret-in-export "
    "password-on-command-line").split()}
BENIGN = {"benign." + n for n in (
    "ls git-status pytest npm-test cat-readme git-log sha256sum "
    "echo-quoted-rm grep-for-force-push rm-node-modules rm-tmp-scratch "
    "chmod-plus-x chmod-755 curl-jq force-with-lease git-rm-cached "
    "cat-env-example docker-ps cat-public-key ssh-with-key read-readme "
    "cat-ranwhat-ignore ranwhat-ignore-list write-script").split()}
GAPS = {"gap." + n for n in (
    "download-then-run env-grep-token docker-plain-prune "
    "git-push-plus-refspec rsync-delete python-rmtree python-imds "
    "base64-secret npmrc-read placeholder-key-prefix").split()}
PUBLISHED = ("decoy.aws-doc", "decoy.stripe-doc", "decoy.placeholder",
             "decoy.code-call", "decoy.env-lookup")
RANDOM = ("decoy.git-sha", "decoy.sha256", "decoy.uuid", "decoy.base64-prose")


def _value(seed, case):
    return [p.value for p in bench.build(seed).planted if p.id == case][0]


class _Bench(unittest.TestCase):
    """A temp directory that stands for the real home (HOME, USERPROFILE and
    the adapters' home all point at it), ranwhat's state and backups in temp
    folders, and a run of the CLI in this process."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="bench-test-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.home = os.path.join(self.tmp, "real-home")     # the sentinel
        os.makedirs(self.home)
        self.state = os.path.join(self.tmp, "state")
        self.backups = os.path.join(self.tmp, "backups")
        env = {"HOME": self.home, "USERPROFILE": self.home,
               "RANWHAT_HOME": self.state, "NO_COLOR": "1",
               "RANWHAT_WIDTH": "80"}
        for p in (mock.patch.dict(os.environ, env),
                  mock.patch.object(_paths, "home", return_value=self.home),
                  mock.patch.object(clean, "BACKUP_ROOT", self.backups)):
            p.start()
            self.addCleanup(p.stop)
        for name in af.AGENT_ENV:
            os.environ.pop(name, None)          # restored by patch.dict
        watch._secret_spans.cache_clear()
        self.addCleanup(watch._secret_spans.cache_clear)

    def run_cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch("sys.stdout", out), mock.patch("sys.stderr", err), \
                mock.patch("sys.stdin", io.StringIO()):
            try:
                rc = cli.main(list(argv))
            except SystemExit as exit:
                rc = exit.code
        return rc, out.getvalue(), err.getvalue()

    def width(self, columns):
        patch = mock.patch.dict(os.environ, {"RANWHAT_WIDTH": str(columns)})
        patch.start()
        self.addCleanup(patch.stop)

    def failing(self, result, case):
        return [c for c in result.cases if c["id"] == case][0]["outcome"] == "fail"


class Generation(_Bench):
    def test_the_same_seed_gives_the_same_case_list(self):
        for seed in (bench.DEFAULT_SEED, OTHER):
            a, b = bench.build(seed), bench.build(seed)
            self.assertEqual(a.listing(), b.listing())
            self.assertEqual(bench.transcript(a), bench.transcript(b))
            self.assertEqual(a.files, b.files)
            self.assertEqual(a, b)

    def test_a_different_seed_changes_every_secret_and_no_case(self):
        a, b = bench.build(bench.DEFAULT_SEED), bench.build(OTHER)
        self.assertEqual([c[:3] for c in a.listing()],
                         [c[:3] for c in b.listing()])
        self.assertEqual([r.id for r in a.rows], [r.id for r in b.rows])
        for p, q in zip(a.planted, b.planted):
            self.assertEqual(p.id, q.id)
            self.assertNotEqual(p.value, q.value, p.id)
        self.assertNotEqual(bench.transcript(a), bench.transcript(b))
        texts = dict((c[0], c[3]) for c in a.listing())
        other = dict((c[0], c[3]) for c in b.listing())
        for case in PUBLISHED:
            self.assertEqual(texts[case], other[case], case)
        for case in RANDOM:
            self.assertNotEqual(texts[case], other[case], case)

    def test_values_have_the_shape_of_their_provider(self):
        b62 = "[A-Za-z0-9]"
        shapes = {
            "secret.aws-access-key-id": r"AKIA[A-Z2-7]{16}",
            "secret.aws-secret-access-key": r"[A-Za-z0-9/+]{40}",
            "secret.github-ghp": "gh" "p_%s{36}" % b62,
            "secret.github-gho": "gh" "o_%s{36}" % b62,
            "secret.stripe-live": "sk_" "live_%s{24}" % b62,
            "secret.slack-bot": r"xo" r"xb-\d{12}-\d{13}-%s{24}" % b62,
            "secret.openai-key": "sk-%s{48}" % b62,
            "secret.db-password": "%s{20}" % b62,
            "secret.db-url-password": "%s{18}" % b62,
            "secret.npm-token": "npm_%s{36}" % b62,
            "secret.jwt": r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{43}",
        }
        for seed in range(25):
            for p in bench.build(seed).planted:
                if p.id == "secret.private-key":
                    lines = p.value.split("\n")
                    self.assertEqual(lines[0], "-----BEGIN " "OPENSSH PRIVATE KEY-----")
                    self.assertEqual(lines[-1], "-----END " "OPENSSH PRIVATE KEY-----")
                    self.assertEqual(len(lines), 8)
                    for line in lines[1:-1]:
                        self.assertRegex(line, r"\A[A-Za-z0-9+/]{70}\Z")
                else:
                    self.assertRegex(p.value, r"\A%s\Z" % shapes[p.id], p.id)

    def test_no_value_looks_like_a_fixture(self):
        # ranwhat ignores a letter-only password and a provider body with no
        # digit, so no value may have either, nor a run like 1234 or aaaa.
        def issued(body, alphabet):
            for lo, hi in (("A", "Z"), ("a", "z"), ("0", "9")):
                if any(lo <= c <= hi for c in alphabet):
                    self.assertGreaterEqual(
                        sum(1 for c in body if lo <= c <= hi), 2, body)
            for i in range(len(body) - 3):
                steps = set(ord(body[j + 1]) - ord(body[j])
                            for j in range(i, i + 3))
                self.assertFalse(len(steps) == 1 and steps <= {1, -1, 0}, body)
            self.assertGreaterEqual(len(set(body)), len(body) // 2, body)

        b62 = bench.B62
        for seed in range(100):
            by_id = dict((p.id, p.value) for p in bench.build(seed).planted)
            issued(by_id["secret.aws-access-key-id"][4:], bench.AWS_ID)
            issued(by_id["secret.aws-secret-access-key"], bench.AWS_SECRET)
            issued(by_id["secret.github-ghp"][4:], b62)
            issued(by_id["secret.github-gho"][4:], b62)
            issued(by_id["secret.stripe-live"][8:], b62)
            _, ids_a, ids_b, body = by_id["secret.slack-bot"].split("-", 3)
            issued(ids_a, "0123456789")
            issued(ids_b, "0123456789")
            issued(body, b62)
            issued(by_id["secret.openai-key"][3:], b62)
            issued(by_id["secret.db-password"], b62)
            issued(by_id["secret.db-url-password"], b62)
            issued(by_id["secret.npm-token"][4:], b62)
            _, payload, signature = by_id["secret.jwt"].split(".")
            issued(payload[3:], b62)
            issued(signature, bench.JWT_PART)
            for line in by_id["secret.private-key"].split("\n")[1:-1]:
                issued(line, bench.PEM_LINE)

    def test_draws_touch_neither_global_random_nor_secrets(self):
        random.seed(5)
        before = random.getstate()
        bench.build(bench.DEFAULT_SEED)
        self.assertEqual(random.getstate(), before)
        with open(bench.__file__, encoding="utf-8") as fh:
            tree = ast.parse(fh.read())
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(a.name.split(".")[0] for a in node.names)
            elif isinstance(node, ast.ImportFrom) and not node.level:
                imported.add((node.module or "").split(".")[0])
            elif isinstance(node, ast.Attribute):
                self.assertNotIn(node.attr, ("urandom", "SystemRandom"))
        for name in ("secrets", "uuid", "subprocess", "socket", "urllib",
                     "http", "unittest", "mock"):
            self.assertNotIn(name, imported)

    def test_the_default_seed_values_are_pinned(self):
        # Changes only when the generator, or the order it draws in, does:
        # then every seed's values change, and this is written again.
        values = [p.value for p in bench.build(bench.DEFAULT_SEED).planted]
        self.assertEqual(hashlib.sha256("\n".join(values).encode()).hexdigest(),
                         "4dd50b6657f676959551830da1d54635224e1484668e9d1f"
                         "4417b1bac79ca4b5")


class Scoring(_Bench):
    def test_every_must_case_passes_with_the_default_seed(self):
        result = bench.run()
        self.assertEqual([c["id"] for c in result.failed()], [])
        self.assertTrue(result.passed)
        self.assertEqual(result.checks, {"read_whole": True, "read_only": True,
                                         "quiet": True})
        self.assertEqual(result.leaks, [])
        self.assertEqual([(g["id"], g["passed"], g["total"])
                          for g in result.groups()],
                         [("secrets", 12, 12), ("decoys", 9, 9),
                          ("risky", 25, 25), ("benign", 24, 24)])

    def test_every_must_case_passes_with_two_other_seeds(self):
        for seed in (7, 4242):
            with self.subTest(seed=seed):
                result = bench.run(seed)
                self.assertEqual([c["id"] for c in result.failed()], [])
                self.assertTrue(result.passed)

    def test_a_hundred_seeds_pass(self):
        # The early warning for a change to a placeholder, fixture or name
        # heuristic that makes some value look like one: widen the draw's
        # guard, not the key.
        for seed in range(100):
            result = bench.run(seed)
            self.assertTrue(result.passed, (seed, [
                c["id"] for c in result.failed()], result.checks))

    def test_a_different_seed_has_the_same_pass_fail_shape(self):
        a, b = bench.run(bench.DEFAULT_SEED).as_json(), bench.run(OTHER).as_json()
        self.assertNotEqual(a["seed"], b["seed"])
        a.pop("seed"), b.pop("seed")
        self.assertEqual(a, b)
        self.assertEqual([c["found_as"] for c in a["cases"]],
                         [c["found_as"] for c in b["cases"]])

    def test_the_answer_key_has_what_the_brief_asks_for(self):
        ids = [c[0] for c in bench.build().listing()]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(set(ids), SECRETS | DECOYS | RISKY | BENIGN)
        self.assertEqual(len(ids), 70)
        self.assertEqual(set(g.id for g in bench.build().gaps), GAPS)

    def test_every_risky_case_names_a_real_rule_and_floor(self):
        rules = set(r.id for r in watch.RULES)
        for r in bench.build().risky:
            self.assertIn(r.rule, rules, r.id)
            self.assertIn(r.floor, ("medium", "high", "critical"), r.id)

    def test_a_password_inside_a_url_is_found_as_part_of_it(self):
        found = dict((c["id"], c["found_as"]) for c in bench.run().cases
                     if c["group"] == "secrets")
        for case, how in found.items():
            self.assertEqual(how, "part" if case == "secret.db-url-password"
                             else "value", case)


class Gaps(_Bench):
    def test_known_gaps_are_listed_and_never_counted(self):
        result = bench.run()
        self.assertEqual(set(g["id"] for g in result.gaps), GAPS)
        for g in result.gaps:
            self.assertIn(g["kind"], ("miss", "false_alarm"))
            self.assertIn(g["state"], ("missed", "caught", "quiet", "flagged"))
            self.assertTrue(g["why"].endswith("."), g["id"])
        self.assertEqual(sum(g["total"] for g in result.groups()), 70)
        self.assertFalse([c for c in result.cases if c["id"].startswith("gap.")])
        text = bench.render(result)
        self.assertIn("Not counted", text)
        flat = " ".join(text.split())
        for g in result.gaps:
            self.assertIn(g["label"], flat)

    def test_known_gaps_are_still_gaps(self):
        for g in bench.run().gaps:
            want = "flagged" if g["kind"] == "false_alarm" else "missed"
            self.assertEqual(g["state"], want,
                             "ranwhat now catches this, so move the case into "
                             "the key and delete the gap: %s" % g["id"])

    def test_a_gap_that_ranwhat_closes_does_not_fail_the_run(self):
        real = watch.evaluate

        def evaluate(tool_name, tool_input, known=None):
            hits, payload = real(tool_name, tool_input, known)
            if "grep -i token" in json.dumps(tool_input) and not hits:
                hits = [{"rule": "cred.read", "severity": "high",
                         "title": "Credential read", "why": "It reads one.",
                         "evidence": "env"}]
                payload = "env"
            return hits, payload
        with mock.patch.object(watch, "evaluate", evaluate):
            rc, out, err = self.run_cli("bench", "--json")
        doc = json.loads(out)
        self.assertEqual(rc, 0, err)
        self.assertTrue(doc["passed"])
        states = dict((g["id"], g["state"]) for g in doc["gaps"])
        self.assertEqual(states["gap.env-grep-token"], "caught")
        self.assertEqual([g["total"] for g in doc["groups"]], [12, 9, 25, 24])
        with mock.patch.object(watch, "evaluate", evaluate):
            rc, out, _ = self.run_cli("bench")
        self.assertIn("now caught", out)
        self.assertEqual(rc, 0)


class Leaks(_Bench):
    def test_no_planted_value_or_edge_of_one_is_in_any_output(self):
        result = bench.run()
        self.assertEqual(result.leaks, [])
        for columns in (46, 60, 80, 200):
            with mock.patch.dict(os.environ, {"RANWHAT_WIDTH": str(columns)}):
                self.assertEqual(result.leaks_in(bench.render(result)), [])
        self.assertEqual(result.leaks_in(cli._json_text(result.as_json())), [])

    def test_the_leak_check_catches_a_leak(self):
        value = _value(bench.DEFAULT_SEED, "secret.github-ghp")
        real = watch.render
        with mock.patch.object(watch, "render",
                               lambda *a, **k: real(*a, **k) + "\n" + value):
            result = bench.run()
            rc, out, err = self.run_cli("bench")
        self.assertIn({"case": "secret.github-ghp", "surface": "watch report",
                       "probe": "value"}, result.leaks)
        self.assertFalse(result.passed)
        self.assertEqual(rc, cli.FAIL_STATUS)
        self.assertNotIn(value, out + err)
        self.assertIn("LEAK", out)

    def test_the_edges_are_probed_too(self):
        value = _value(bench.DEFAULT_SEED, "secret.stripe-live")
        real = watch.render
        for edge, kind in ((value[:12], "leading"), (value[-12:], "trailing")):
            with mock.patch.object(watch, "render",
                                   lambda *a, **k: real(*a, **k) + "\n" + edge):
                result = bench.run()
            kinds = set(l["probe"] for l in result.leaks
                        if l["case"] == "secret.stripe-live")
            self.assertEqual(kinds, {kind})

    def test_the_real_check_prints_no_planted_value(self):
        syn = bench.build(bench.DEFAULT_SEED)
        home = os.path.join(self.tmp, "made-up-home")
        root = bench.write(syn, home)
        missing = os.path.join(self.tmp, "no-openclaw")
        probes = []
        for p in syn.planted + syn.typed:
            probes += [text for kind, text in p.probes()]
        for flags in (["--json"], []):
            rc, out, err = self.run_cli(
                "check", *(flags + ["--root", root, "--source", "claude-code",
                                    "--state-dir", missing, "--days", "36500"]))
            self.assertIn(rc, (0, 3), err)
            for probe in probes:
                self.assertNotIn(probe, out + err)

    def test_bench_refuses_to_print_a_report_that_holds_a_value(self):
        value = _value(bench.DEFAULT_SEED, "secret.npm-token")
        with mock.patch.object(bench, "render", lambda result: "x " + value):
            rc, out, err = self.run_cli("bench")
        self.assertEqual(rc, 1)
        self.assertEqual(out, "")
        self.assertIn("bug in bench", err)
        self.assertNotIn(value, err)


class Isolation(_Bench):
    def test_the_real_home_is_never_touched(self):
        sentinel = os.path.realpath(self.home)
        touched = []

        def spy(real):
            def wrapper(path, *args, **kwargs):
                try:
                    shown = path if isinstance(path, int) else os.fsdecode(path)
                except TypeError:
                    shown = None
                if isinstance(shown, str) and (
                        shown.startswith(sentinel) or shown.startswith(self.home)):
                    touched.append(shown)
                return real(path, *args, **kwargs)
            return wrapper
        with contextlib.ExitStack() as stack:
            for owner, name in ((os, "stat"), (os, "lstat"), (os, "scandir"),
                                (os, "listdir"), (os, "open"),
                                (builtins, "open")):
                stack.enter_context(mock.patch.object(
                    owner, name, spy(getattr(owner, name))))
            rc, out, err = self.run_cli("bench")
        self.assertEqual(rc, 0, err)
        self.assertEqual(touched, [])
        self.assertEqual(os.listdir(self.home), [])
        self.assertFalse(os.path.exists(self.state))

    def test_the_environment_is_restored(self):
        def snapshot():
            return (dict(os.environ), sys.stdout, sys.stderr, clean.BACKUP_ROOT)
        before = snapshot()
        bench.run()
        self.assertEqual(snapshot(), before)
        with mock.patch.object(watch, "scan_sources_counted",
                               side_effect=ValueError("no")):
            with self.assertRaises(ValueError):
                bench.run()
        self.assertEqual(snapshot(), before)

    def test_the_temporary_directory_is_removed(self):
        scratch = os.path.join(self.tmp, "scratch")
        os.makedirs(scratch)

        def left():
            return [n for n in os.listdir(scratch) if n.startswith("ranwhat-bench-")]
        with mock.patch.object(tempfile, "tempdir", scratch):
            bench.run()
            self.assertEqual(left(), [])
            with mock.patch.object(clean, "_found", lambda text: []):
                self.assertFalse(bench.run().passed)
            self.assertEqual(left(), [])
            with mock.patch.object(watch, "scan_sources_counted",
                                   side_effect=ValueError("no")):
                with self.assertRaises(ValueError):
                    bench.run()
            self.assertEqual(left(), [])
            with mock.patch.object(watch, "scan_sources_counted",
                                   side_effect=KeyboardInterrupt):
                with self.assertRaises(KeyboardInterrupt):
                    bench.run()
            self.assertEqual(left(), [])

    def test_detection_writes_nothing(self):
        def refuse(*args, **kwargs):
            raise AssertionError("a write")
        with mock.patch.object(clean, "_replace", refuse), \
                mock.patch.object(clean, "_backup", refuse), \
                mock.patch.object(known.Index, "open", refuse), \
                mock.patch.object(known.Kept, "open", refuse):
            result = bench.run()
        self.assertTrue(result.passed)
        self.assertTrue(result.checks["read_only"])

        real = clean.scan_sources

        def writing(*args, **kwargs):
            home = os.path.dirname(os.path.dirname(kwargs["root"]))
            with open(os.path.join(home, "stray.txt"), "w",
                      encoding="utf-8") as fh:
                fh.write("written by a detector")
            return real(*args, **kwargs)
        with mock.patch.object(clean, "scan_sources", writing):
            self.assertFalse(bench.run().checks["read_only"])
            rc, out, err = self.run_cli("bench")
        self.assertEqual(rc, cli.FAIL_STATUS)

    def test_no_network_no_subprocess(self):
        def refuse(*args, **kwargs):
            raise AssertionError("went out")
        with mock.patch.object(socket, "socket", refuse), \
                mock.patch.object(subprocess, "Popen", refuse), \
                mock.patch.object(urllib.request, "urlopen", refuse):
            self.assertTrue(bench.run().passed)

    def test_it_runs_the_detectors_check_runs(self):
        self.assertIs(bench.clean_mod, cli.clean_mod)
        self.assertIs(bench.watch_mod, cli.watch_mod)
        scratch = os.path.join(self.tmp, "scratch")
        os.makedirs(scratch)
        scanned = mock.Mock(wraps=clean.scan_sources)
        watched = mock.Mock(wraps=watch.scan_sources_counted)
        with mock.patch.object(tempfile, "tempdir", scratch), \
                mock.patch.object(clean, "scan_sources", scanned), \
                mock.patch.object(watch, "scan_sources_counted", watched):
            self.assertTrue(bench.run().passed)
        for call in (scanned, watched):
            self.assertEqual(call.call_count, 1)
            kwargs = call.call_args[1]
            self.assertEqual(kwargs["sources"], ("claude-code",))
            self.assertTrue(kwargs["root"].startswith(scratch))
        self.assertIs(scanned.call_args[1]["apply"], False)
        self.assertIsNone(watched.call_args[1]["known"])

    def test_the_synthetic_home_is_laid_out_as_claude_code_lays_it_out(self):
        syn = bench.build()
        home = os.path.join(self.tmp, "made-up-home")
        root = bench.write(syn, home)
        found = watch._transcripts(root)
        self.assertEqual(found, [os.path.join(
            root, bench.PROJECT, bench.SESSION + ".jsonl")])
        with open(found[0], encoding="utf-8") as fh:
            raw = fh.read()
        lines = [json.loads(line) for line in raw.splitlines()]
        self.assertEqual(len(lines), 2 * len(syn.rows))
        for call, result in zip(lines[::2], lines[1::2]):
            use = call["message"]["content"][0]
            self.assertEqual((call["type"], use["type"]), ("assistant", "tool_use"))
            back = result["message"]["content"][0]
            self.assertEqual((result["type"], back["type"]), ("user", "tool_result"))
            self.assertEqual(back["tool_use_id"], use["id"])
            self.assertEqual(call["timestamp"], result["timestamp"])
        self.assertEqual(len(set(l["timestamp"] for l in lines[::2])), len(syn.rows))
        rows = dict((r.id, r.output) for r in syn.rows)
        for rel, row in ((".aws/credentials", "aws-credentials"),
                         ("work/app/.env", "app-env"), (".npmrc", "npmrc"),
                         (".ssh/id_ed25519", "ssh-key")):
            path = os.path.join(home, *rel.split("/"))
            with open(path, encoding="utf-8") as fh:
                self.assertEqual(fh.read(), rows[row], rel)
            if os.name != "nt":
                self.assertEqual(os.stat(path).st_mode & 0o777, 0o600, rel)
        self.assertLess(len(raw.encode()), 64 * 1024)
        self.assertLess(len(syn.rows), 100)


class Failing(_Bench):
    def test_a_detector_that_finds_nothing_fails_with_status_3(self):
        with mock.patch.object(clean, "_found", lambda text: []), \
                mock.patch.object(watch, "RULES", []):
            rc, out, err = self.run_cli("bench", "--json")
            doc = json.loads(out)
            rc_text, text, _ = self.run_cli("bench")
        self.assertEqual(rc, cli.FAIL_STATUS)
        self.assertFalse(doc["passed"])
        self.assertEqual([(g["id"], g["passed"], g["total"])
                          for g in doc["groups"]],
                         [("secrets", 0, 12), ("decoys", 9, 9),
                          ("risky", 0, 25), ("benign", 24, 24)])
        self.assertEqual(rc_text, cli.FAIL_STATUS)
        self.assertIn("FAIL", text)
        self.assertIn("not met", err)

    def test_a_detector_that_flags_everything_fails_with_status_3(self):
        real = clean._found

        def greedy(text):
            found = list(real(text))
            found += [(m.group(0), "hex", m.start())
                      for m in re.finditer(r"[0-9a-f]{40,64}", text)]
            return found
        # clean skips a string with no "=", ":" or credential prefix before
        # it asks the rules anything (_worth_scanning), so that is widened
        # too: the digests are then all the greedy rule is shown.
        with mock.patch.object(clean, "_found", greedy), \
                mock.patch.object(clean, "_worth_scanning", lambda text: True):
            rc, out, _ = self.run_cli("bench", "--json")
        failed = [c["id"] for c in json.loads(out)["cases"]
                  if c["outcome"] == "fail"]
        self.assertEqual(rc, cli.FAIL_STATUS)
        self.assertEqual(sorted(failed), ["decoy.git-sha", "decoy.sha256"])

        def everything(tool_name, tool_input, known=None):
            return ([{"rule": "cred.read", "severity": "critical",
                      "title": "t", "why": "w", "evidence": "x"}], "x")
        with mock.patch.object(watch, "evaluate", everything):
            rc, out, _ = self.run_cli("bench", "--json")
        doc = json.loads(out)
        self.assertEqual(rc, cli.FAIL_STATUS)
        groups = dict((g["id"], g["passed"]) for g in doc["groups"])
        self.assertEqual(groups["benign"], 0)

    def test_a_failure_names_the_case_and_never_the_value(self):
        result = None
        with mock.patch.object(clean, "_found", lambda text: []), \
                mock.patch.object(watch, "RULES", []):
            result = bench.run()
            rc, text, _ = self.run_cli("bench")
            rc_json, doc, _ = self.run_cli("bench", "--json")
        self.assertEqual(result.leaks_in(text), [])
        self.assertEqual(result.leaks_in(doc), [])
        self.assertIn("secret.aws-access-key-id", doc)
        self.assertIn("wanted cred.read at critical or above", doc)
        self.assertIn("AWS access key ID", text)
        self.assertIn("not in what clean reported", text)

    def test_a_detector_error_exits_1_and_names_only_its_class(self):
        value = _value(bench.DEFAULT_SEED, "secret.slack-bot")
        with mock.patch.object(watch, "scan_sources_counted",
                               side_effect=ValueError(value)):
            rc, out, err = self.run_cli("bench")
        self.assertEqual(rc, 1)
        self.assertEqual(out, "")
        self.assertIn("ValueError", err)
        self.assertNotIn(value, err)

    def test_the_run_checks_fail_when_the_transcript_is_not_read_whole(self):
        with mock.patch.object(clean, "scan_sources",
                               lambda *a, **k: clean.Searched()):
            result = bench.run()
            rc, out, err = self.run_cli("bench")
        self.assertFalse(result.checks["read_whole"])
        self.assertEqual(rc, cli.FAIL_STATUS)

    def test_noise_fails_the_quiet_check(self):
        real = watch.scan_sources_counted

        def noisy(*args, **kwargs):
            sys.stderr.write("a stray line\n")
            return real(*args, **kwargs)
        with mock.patch.object(watch, "scan_sources_counted", noisy):
            result = bench.run()
            rc, out, err = self.run_cli("bench")
        self.assertFalse(result.checks["quiet"])
        self.assertEqual(rc, cli.FAIL_STATUS)


class Command(_Bench):
    def test_the_overview_and_help_name_bench(self):
        self.assertIn("bench", [n for n, _ in cli.COMMANDS])
        for columns in (46, 60, 80):
            with mock.patch.dict(os.environ, {"RANWHAT_WIDTH": str(columns)}):
                rc, out, _ = self.run_cli()
                lines = [l for l in out.splitlines() if l.startswith("  bench")]
                self.assertEqual(len(lines), 1)
                for line in out.splitlines():
                    self.assertLessEqual(len(line), term.width(), line)
        rc, out, _ = self.run_cli("--help")
        flat = " ".join(out.split())
        self.assertIn("--seed N", flat)
        self.assertIn("bench", flat)
        self.assertEqual(cli._BENCH_SEED, bench.DEFAULT_SEED)
        self.assertEqual(bench.FAIL_STATUS, cli.FAIL_STATUS)

    def test_json_is_valid_and_stable_in_shape(self):
        rc, out, err = self.run_cli("bench", "--json")
        rc2, again, _ = self.run_cli("bench", "--json")
        self.assertEqual((rc, rc2), (0, 0))
        self.assertEqual(out, again)
        doc = json.loads(out)
        self.assertEqual(list(doc), ["schema", "ranwhat", "seed", "passed",
                                     "groups", "cases", "gaps", "leak", "checks"])
        self.assertEqual(doc["schema"], 1)
        self.assertEqual(doc["seed"], bench.DEFAULT_SEED)
        ids = [c["id"] for c in doc["cases"]]
        self.assertEqual(len(ids), len(set(ids)))
        for c in doc["cases"]:
            self.assertEqual(list(c), ["id", "group", "label", "outcome",
                                       "detail", "found_as"])
        self.assertEqual(list(doc["leak"]), ["surfaces", "planted", "leaks"])
        self.assertEqual(doc["leak"]["surfaces"], list(bench.SURFACES))
        self.assertEqual(list(doc["checks"]), ["read_whole", "read_only", "quiet"])
        # The run's own temporary directory is named ranwhat-bench-..., so that
        # prefix is what a leak of it would show. The temp root itself (/tmp on
        # Linux) can appear legitimately, in a command the answer key quotes.
        self.assertNotIn("ranwhat-bench-", out)
        self.assertNotIn(self.tmp, out)
        for g in doc["gaps"]:
            self.assertEqual(list(g), ["id", "label", "kind", "state", "why"])

    def test_flags_it_does_not_take_are_refused(self):
        for argv, message in (
                (["bench", "--days", "3"], "bench takes only --seed and --json, not --days"),
                (["bench", "--fail-on", "high"], "bench takes only --seed and --json, not --fail-on"),
                (["bench", "--html", "x"], "bench takes only --seed and --json, not --html"),
                (["bench", "somewhere"], "bench takes no path"),
                (["bench", "--seed", "x"], "invalid int value"),
                (["bench", "--seed", "-1"], "--seed must be a whole number from 0 to"),
                (["bench", "--seed", "9007199254740992"], "--seed must be a whole number from 0 to"),
                (["check", "--seed", "1"], "--seed is only for bench"),
                (["hook", "install", "--seed", "1"],
                 "hook install does not take --seed"),
                (["revoke", "--seed", "1"],
                 "revoke takes only --scope, --apply and --json, not --seed")):
            rc, out, err = self.run_cli(*argv)
            self.assertEqual(rc, 2, argv)
            self.assertIn(message, err, argv)
            self.assertEqual(out, "", argv)
        rc, out, err = self.run_cli("bench", "--seed", "0")
        self.assertEqual(rc, 0, err)
        rc, out, err = self.run_cli("bench", "--seed", str(bench.MAX_SEED))
        self.assertEqual(rc, 0, err)

    def test_the_text_report(self):
        for columns in (46, 60, 80):
            with mock.patch.dict(os.environ, {"RANWHAT_WIDTH": str(columns)}):
                rc, out, err = self.run_cli("bench")
                again = self.run_cli("bench")[1]
                self.assertEqual(rc, 0, err)
                self.assertEqual(out, again)
                self.assertNotIn("\033", out)
                for line in out.splitlines():
                    self.assertLessEqual(len(line), term.width(), line)
                    self.assertEqual(line, line.rstrip(), repr(line))
                for label in ("Planted secrets found", "Decoys left alone",
                              "Risky calls rated", "Benign calls left alone",
                              "Not counted", "PASS"):
                    self.assertIn(label, out)

    def test_a_status_line_for_a_failed_run_says_how_many(self):
        with mock.patch.object(clean, "_found", lambda text: []):
            rc, out, err = self.run_cli("bench")
        self.assertEqual(rc, cli.FAIL_STATUS)
        self.assertRegex(out, r"FAIL  \d+ expectations? not met \(exit status 3\)")
        self.assertIn("Not met", out)


class Strictness(_Bench):
    """What a broken or careless detector, or run, must not get away with."""

    def blind(self, *rows):
        """bench.build, with what the named rows printed replaced by "ok":
        a detector shown none of those files."""
        real = bench.build

        def build(seed=bench.DEFAULT_SEED):
            syn = real(seed)
            for rid in rows:
                syn.by_id[rid].output = "ok"
            return syn
        return mock.patch.object(bench, "build", build)

    def test_a_secret_typed_in_a_command_is_not_the_one_in_a_file(self):
        syn = bench.build()
        self.assertEqual(len(syn.typed), 3)
        files = " ".join(syn.row_text(p.row) for p in syn.planted)
        for t in syn.typed:
            self.assertIn(t.value, syn.row_text(t.row), t.id)
            self.assertNotIn(t.value, files, t.id)
            self.assertNotIn(t.value, [p.value for p in syn.planted])
        with self.blind("app-env", "aws-credentials", "gh-auth-token",
                        "npmrc", "ssh-key"):
            result = bench.run()
        self.assertEqual([c["id"] for c in result.cases
                          if c["group"] == "secrets"
                          and c["outcome"] == "pass"], [])
        self.assertEqual([c["id"] for c in result.cases
                          if c["group"] == "risky"
                          and c["outcome"] == "fail"], [])

    def test_a_value_typed_in_a_command_is_a_leak_when_printed(self):
        typed = bench.build().typed[0]
        real = watch.render
        with mock.patch.object(watch, "render",
                               lambda *a, **k: real(*a, **k) + "\n" + typed.value):
            result = bench.run()
        self.assertIn(typed.id, [l["case"] for l in result.leaks])
        self.assertFalse(result.passed)

    def test_one_reported_blob_does_not_find_every_secret(self):
        real = clean.scan_sources

        def blob(*args, **kwargs):
            found = real(*args, **kwargs)
            found.values = {"fp": "\n".join(found.values.values())}
            return found
        with mock.patch.object(clean, "scan_sources", blob):
            result = bench.run()
        self.assertFalse(result.passed)
        passing = [c["id"] for c in result.cases
                   if c["group"] == "secrets" and c["outcome"] == "pass"]
        self.assertEqual(passing, [])

    def test_the_leak_check_looks_at_the_middle_and_at_a_key_whole(self):
        by = dict((p.id, p.value) for p in bench.build().planted)
        pem = by["secret.private-key"].split("\n")
        pieces = {
            "pem line 2": pem[2], "pem line 6": pem[6],
            "jwt payload": by["secret.jwt"].split(".")[1],
            "aws id middle": by["secret.aws-access-key-id"][3:-3],
            "ghp middle": by["secret.github-ghp"][10:-10],
            "db password middle": by["secret.db-password"][4:-4],
        }
        real = watch.render
        for name, piece in sorted(pieces.items()):
            with mock.patch.object(watch, "render",
                                   lambda *a, **k: real(*a, **k) + "\n" + piece):
                result = bench.run()
            self.assertTrue(result.leaks, name)
            self.assertFalse(result.passed, name)
            self.assertTrue(result.leaks_in(piece), name)

    def test_a_touch_or_a_chmod_counts_as_a_write(self):
        real = clean.scan_sources

        def transcripts(root):
            for here, _, names in os.walk(root):
                for name in names:
                    yield os.path.join(here, name)

        def touch(*args, **kwargs):
            for path in transcripts(kwargs["root"]):
                os.utime(path, (1, 1))
            return real(*args, **kwargs)

        def chmod(*args, **kwargs):
            for path in transcripts(kwargs["root"]):
                os.chmod(path, 0o644)
            return real(*args, **kwargs)
        # Windows keeps no mode bits to compare: os.chmod only toggles the
        # read-only flag, so a chmod to 0o644 changes nothing it could see.
        for tamper in ((touch,) if sys.platform == "win32" else (touch, chmod)):
            with mock.patch.object(clean, "scan_sources", tamper):
                result = bench.run()
            self.assertFalse(result.checks["read_only"], tamper.__name__)
            self.assertFalse(result.passed, tamper.__name__)

    def test_a_temporary_directory_that_will_not_go_is_an_error(self):
        scratch = os.path.join(self.tmp, "scratch")
        os.makedirs(scratch)
        self.addCleanup(shutil.rmtree, scratch, True)
        with mock.patch.object(tempfile, "tempdir", scratch), \
                mock.patch.object(shutil, "rmtree", lambda *a, **k: None):
            with self.assertRaises(bench.BenchError):
                bench.run()
            rc, out, err = self.run_cli("bench")
        self.assertEqual(rc, 1)
        self.assertEqual(out, "")
        self.assertIn("could not remove the temporary directory", err)

    @unittest.skipIf(sys.platform == "win32",
                     "os.kill with SIGTERM ends a Windows process outright, "
                     "so no handler runs and this would kill the test run")
    def test_sigterm_removes_the_temporary_directory(self):
        scratch = os.path.join(self.tmp, "scratch")
        os.makedirs(scratch)
        before = signal.getsignal(signal.SIGTERM)

        def killed(*args, **kwargs):
            os.kill(os.getpid(), signal.SIGTERM)
            raise AssertionError("SIGTERM did not stop the run")
        with mock.patch.object(tempfile, "tempdir", scratch), \
                mock.patch.object(watch, "scan_sources_counted", killed):
            with self.assertRaises(SystemExit) as stopped:
                bench.run()
        self.assertEqual(stopped.exception.code, 128 + signal.SIGTERM)
        self.assertEqual(os.listdir(scratch), [])
        self.assertIs(signal.getsignal(signal.SIGTERM), before)

    def test_a_failing_verdict_fits_the_width(self):
        # Ten or more unmet expectations used to push it one column over 46.
        with mock.patch.object(clean, "_found", lambda text: []), \
                mock.patch.object(watch, "RULES", []):
            result = bench.run()
        self.assertGreaterEqual(result.unmet, 10)
        for columns in (46, 60, 80):
            with mock.patch.dict(os.environ, {"RANWHAT_WIDTH": str(columns)}):
                text = bench.render(result)
                for line in text.splitlines():
                    self.assertLessEqual(len(line), columns, line)
                flat = " ".join(" ".join(text.split()).split())
                self.assertIn("FAIL %d expectations not met (exit status 3)"
                              % result.unmet, flat)

    def test_no_advice_to_move_a_gap_into_the_key_on_a_failed_run(self):
        with mock.patch.object(clean, "_found", lambda text: []), \
                mock.patch.object(watch, "RULES", []):
            result = bench.run()
        self.assertFalse(result.passed)
        self.assertIn("miss", [g["kind"] for g in result.gaps])
        self.assertNotIn("into the key", " ".join(bench.render(result).split()))

    def test_advice_for_a_closed_gap_says_what_closed(self):
        result = bench.run()
        self.assertTrue(result.passed)
        for g in result.gaps:
            g["state"] = "caught" if g["kind"] == "miss" else "quiet"
        text = " ".join(bench.render(result).split())
        self.assertIn("(now caught: move it into the key)", text)
        self.assertIn("(no longer reported: move it into the key)", text)
        self.assertEqual(text.count("now caught"),
                         sum(1 for g in result.gaps if g["kind"] == "miss"))


class PublicCopy(unittest.TestCase):
    def test_the_readme_documents_bench(self):
        with open(os.path.join(REPO, "README.md"), encoding="utf-8") as fh:
            text = fh.read()
        head = "### `ranwhat bench`"
        self.assertEqual(text.count(head), 1)
        section = text[text.index(head):]
        section = section[:section.index("\n## ")]
        for word in ("--seed", "--json", "0", "3", "1", "Exit status"):
            self.assertIn(word, section)
        self.assertRegex(" ".join(section.split()),
                         r"Exit status: 0 .* 3 .* 1 ")
        # As a claim ("the first", "the only"), not "read-only".
        self.assertNotRegex(section.lower(), r"(?<![-\w])(first|only)(?![-\w])")
        self.assertIn("`ranwhat bench` runs a public answer key against "
                      "these rules.", text)

    def test_the_commands_page_documents_bench(self):
        with open(os.path.join(REPO, "site", "commands.html"),
                  encoding="utf-8") as fh:
            text = fh.read()
        self.assertIn('id="bench"', text)
        self.assertIn('id="run-bench"', text)
        self.assertIn('<code id="flag-seed">--seed N</code>', text)
        row = text[text.index('id="flag-seed"'):]
        row = row[:row.index("</tr>")]
        self.assertIn('data-label="Commands">bench<', row)
        self.assertIn('data-label="What it does"', row)
        self.assertNotIn(chr(0x2014), text)


if __name__ == "__main__":
    unittest.main()
