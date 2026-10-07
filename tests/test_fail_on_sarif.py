"""--fail-on, --sarif, and a remembered keep in clean's review (F1c).

--fail-on SEVERITY makes check, watch and clean exit 3 when anything at or
above it is found, while 1 stays an error and 2 nothing read. --sarif PATH
writes what was found as SARIF 2.1.0, with every secret as the report
shows it, masked. `keep N` in clean's review is remembered by a keyed hash
under $RANWHAT_HOME/known/, so the value is neither reported nor masked on
the next run. Every value here is synthetic.
"""
import contextlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import isolated_home  # noqa: E402,F401  ranwhat's state, never ~/.ranwhat
from ranwhat import clean, cli, known, sarif, watch  # noqa: E402

DAY = time.strftime("%Y-%m-%d", time.gmtime(time.time() - 86400))
PASSWORD = "kzN8fJx2mQ4vB7nR5tY9wL3pZ6aS1dF0c2e="
STRIPE = "sk_" "live_" "4eC39HqLyjWDarjtT1zdp7dc"


def tool_use(cmd, i):
    return {"timestamp": DAY + "T10:%02d:00Z" % i,
            "message": {"role": "assistant", "content": [
                {"type": "tool_use", "id": "t%d" % i, "name": "Bash",
                 "input": {"command": cmd}}]}}


def tool_result(text, i):
    return {"timestamp": DAY + "T10:%02d:30Z" % i,
            "message": {"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": "t%d" % i,
                 "content": text}]}}


# rm -rf ~/Documents is high; cat .env is critical (cred.read).
DELETE = [tool_use("rm -rf ~/Documents/archive", 1)]
SECRETS = [tool_use("ls", 2),
           tool_result("DB_PASSWORD=%s\nSTRIPE=%s\n" % (PASSWORD, STRIPE), 2)]


class _Base(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="f1c-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        nowhere = os.path.join(self.tmp, "nowhere")
        os.makedirs(nowhere)
        for patch in (mock.patch.dict(os.environ, {
                          "RANWHAT_HOME": os.path.join(self.tmp, "home"),
                          "RANWHAT_WIDTH": "80", "NO_COLOR": "1",
                          "CLAUDE_CONFIG_DIR": nowhere,
                          "OPENCLAW_STATE_DIR": os.path.join(nowhere, "oc")}),
                      mock.patch.object(watch, "CLAUDE_PROJECTS",
                                        os.path.join(nowhere, "projects")),
                      mock.patch.object(clean, "BACKUP_ROOT",
                                        os.path.join(self.tmp, "backups"))):
            patch.start()
            self.addCleanup(patch.stop)
        self.state = os.path.join(self.tmp, "openclaw")

    def root(self, rows, aged=True):
        root = os.path.join(self.tmp, "projects")
        proj = os.path.join(root, "-tmp-synthetic-proj")
        os.makedirs(proj, exist_ok=True)
        self.transcript = os.path.join(proj, "s1.jsonl")
        with open(self.transcript, "w", encoding="utf-8") as fh:
            for row in rows:
                fh.write(json.dumps(row) + "\n")
        if aged:            # clean leaves a file written in the last 2 minutes
            then = time.time() - 600
            os.utime(self.transcript, (then, then))
        return root

    def run_cli(self, argv, replies=None):
        out, err = io.StringIO(), io.StringIO()
        patches = []
        if replies is not None:
            it = iter(replies)
            patches = [mock.patch("sys.stdin.isatty", lambda: True),
                       mock.patch("builtins.input", lambda prompt="": next(it))]
        with contextlib.ExitStack() as stack:
            for patch in patches:
                stack.enter_context(patch)
            stack.enter_context(contextlib.redirect_stdout(out))
            stack.enter_context(contextlib.redirect_stderr(err))
            try:
                rc = cli.main(argv)
            except SystemExit as e:
                rc = e.code
        return rc, out.getvalue(), err.getvalue()

    def cmd(self, command, root, *extra, **kw):
        argv = [command, "--root", root, "--state-dir", self.state]
        if command == "clean" and kw.get("replies") is None:
            argv.append("--no-interactive")
        return self.run_cli(argv + list(extra), **kw)

    def text(self, path):
        with open(path, encoding="utf-8") as fh:
            return fh.read()


class FailOn(_Base):

    def test_watch_exits_3_at_or_above_and_0_below(self):
        root = self.root(DELETE)            # one high action
        self.assertEqual(self.cmd("watch", root)[0], 0)
        self.assertEqual(self.cmd("watch", root, "--fail-on", "medium")[0], 3)
        rc, _out, err = self.cmd("watch", root, "--fail-on", "high")
        self.assertEqual(rc, 3)
        self.assertIn("1 finding at or above high (--fail-on high): exit "
                      "status 3.", " ".join(err.split()))
        self.assertEqual(self.cmd("watch", root, "--fail-on", "critical")[0], 0)

    def test_every_secret_clean_finds_is_critical(self):
        root = self.root(SECRETS)
        for floor in sarif.SEVERITIES:
            self.assertEqual(self.cmd("clean", root, "--fail-on", floor)[0], 3, floor)
        self.assertEqual(self.cmd("clean", root)[0], 0)

    def test_check_counts_both_halves(self):
        root = self.root(DELETE + SECRETS)
        rc, _out, err = self.cmd("check", root, "--fail-on", "high")
        self.assertEqual(rc, 3)
        self.assertIn("3 findings at or above high", " ".join(err.split()))
        rc, _out, err = self.cmd("check", root, "--fail-on", "critical")
        self.assertIn("2 findings at or above critical", " ".join(err.split()))

    def test_json_stays_json_and_still_fails(self):
        root = self.root(DELETE + SECRETS)
        for command in ("check", "watch", "clean"):
            rc, out, _err = self.cmd(command, root, "--json", "--fail-on", "high")
            self.assertEqual(rc, 3, command)
            json.loads(out)

    def test_nothing_read_stays_2(self):
        empty = os.path.join(self.tmp, "empty")
        os.makedirs(empty)
        for command in ("check", "watch", "clean"):
            self.assertEqual(self.cmd(command, empty, "--fail-on", "medium")[0],
                             2, command)
            self.assertEqual(self.cmd(command, empty, "--json",
                                      "--fail-on", "medium")[0], 2, command)

    def test_a_clean_history_passes(self):
        root = self.root([tool_use("ls -la", 1)])
        for command in ("check", "watch", "clean"):
            self.assertEqual(self.cmd(command, root, "--fail-on", "medium")[0],
                             0, command)

    def test_masked_secrets_still_fail(self):
        # Redaction is not remediation: --apply masks, the key is still out.
        root = self.root(SECRETS)
        rc, out, _err = self.cmd("clean", root, "--apply", "--fail-on", "critical")
        self.assertEqual(rc, 3)
        self.assertNotIn(STRIPE, self.text(self.transcript))

    def test_other_commands_refuse_it(self):
        for argv in (["demo", "--fail-on", "high"], ["sources", "--sarif", "x"],
                     ["--fail-on", "high"], ["update", "--status", "--sarif", "x"]):
            rc, _out, err = self.run_cli(argv)
            self.assertEqual(rc, 2, argv)
            self.assertIn("only for check, watch and clean", err)

    def test_an_unknown_severity_is_refused(self):
        rc, _out, err = self.run_cli(["check", "--fail-on", "low"])
        self.assertEqual(rc, 2)
        self.assertIn("invalid choice", err)

    def test_at_least(self):
        self.assertTrue(sarif.at_least("critical", "medium"))
        self.assertTrue(sarif.at_least("high", "high"))
        self.assertFalse(sarif.at_least("medium", "high"))
        self.assertFalse(sarif.at_least(None, "medium"))
        self.assertFalse(sarif.at_least("low", "medium"))


class Sarif(_Base):

    def sarif(self, command, rows, *extra):
        root = self.root(rows)
        path = os.path.join(self.tmp, "out.sarif")
        rc, out, err = self.cmd(command, root, "--sarif", path, *extra)
        with open(path, encoding="utf-8") as fh:
            raw = fh.read()
        return rc, raw, json.loads(raw)

    def assert_no_secret(self, raw):
        for value in (PASSWORD, STRIPE):
            self.assertNotIn(value, raw)
            # Not its unkeyed fingerprint, a dictionary oracle for a short
            # password, outside the mask clean writes into a transcript.
            self.assertNotIn(clean._fingerprint(value), raw)
            for cut in (value[:12], value[-12:]):
                self.assertNotIn(cut, raw)

    def test_check_writes_both_halves_masked(self):
        rc, raw, doc = self.sarif("check", DELETE + SECRETS)
        self.assertEqual(rc, 0)
        self.assertEqual(doc["version"], "2.1.0")
        self.assertIn("sarif-2.1.0", doc["$schema"])
        run, = doc["runs"]
        self.assertEqual(run["tool"]["driver"]["name"], "ranwhat")
        rules = [r["id"] for r in run["tool"]["driver"]["rules"]]
        self.assertEqual(rules, [r.id for r in watch.RULES] + [sarif.SECRET_RULE])
        ids = sorted(r["ruleId"] for r in run["results"])
        self.assertEqual(ids, ["fs.destructive", "secret.plaintext",
                               "secret.plaintext"])
        for result in run["results"]:
            self.assertEqual(rules[result["ruleIndex"]], result["ruleId"])
            self.assertIn(result["level"], ("error", "warning"))
            self.assertTrue(result["locations"])
            self.assertTrue(result["partialFingerprints"])
        self.assert_no_secret(raw)
        texts = " ".join(r["message"]["text"] for r in run["results"])
        self.assertIn("Stripe live secret key in plaintext: sk_…dc, 32 chars", texts)

    def test_watch_and_clean_write_their_own(self):
        rc, raw, doc = self.sarif("watch", DELETE + SECRETS)
        self.assertEqual({r["ruleId"] for r in doc["runs"][0]["results"]},
                         {"fs.destructive"})
        rc, raw, doc = self.sarif("clean", DELETE + SECRETS)
        self.assertEqual({r["ruleId"] for r in doc["runs"][0]["results"]},
                         {"secret.plaintext"})
        self.assert_no_secret(raw)
        uri = doc["runs"][0]["results"][0]["locations"][0][
            "physicalLocation"]["artifactLocation"]["uri"]
        self.assertTrue(uri.startswith("file:"), uri)
        self.assertTrue(uri.endswith("/s1.jsonl"), uri)

    def test_a_secret_typed_into_a_command_stays_masked(self):
        # watch's evidence for a command that types a value clean found
        # elsewhere is masked by the index: SARIF carries the masked form.
        rows = SECRETS + [tool_use("mysql -uroot -p%s app" % PASSWORD, 3)]
        rc, raw, doc = self.sarif("watch", rows)
        self.assert_no_secret(raw)
        rc, raw, doc = self.sarif("check", rows)
        self.assert_no_secret(raw)

    def test_an_empty_history_writes_an_empty_log(self):
        empty = os.path.join(self.tmp, "empty")
        os.makedirs(empty)
        path = os.path.join(self.tmp, "empty.sarif")
        rc, _out, _err = self.cmd("check", empty, "--sarif", path)
        self.assertEqual(rc, 2)
        with open(path, encoding="utf-8") as fh:
            self.assertEqual(json.load(fh)["runs"][0]["results"], [])

    def test_a_path_that_cannot_be_written_is_an_error(self):
        root = self.root(DELETE)
        path = os.path.join(self.tmp, "no", "such", "dir", "out.sarif")
        for extra in ((), ("--fail-on", "high")):
            rc, _out, err = self.cmd("watch", root, "--sarif", path, *extra)
            self.assertEqual(rc, 1)
            self.assertIn("cannot write", err)


class RememberedKeep(_Base):

    def keep_first(self, root):
        """Keep the finding listed first (the most seen, then as listed)."""
        rc, out, _err = self.cmd("clean", root, replies=["keep 1", "quit"])
        self.assertIn("kept, and not reported again on this machine.", out)
        return rc

    def kept_file(self):
        return os.path.join(known.index_dir(), known.KEPT_FILE)

    def test_a_kept_value_is_not_reported_next_run(self):
        root = self.root(SECRETS)
        _rc, before, _err = self.cmd("clean", root, "--json")
        first = json.loads(before)["findings"][0]["label"]
        self.keep_first(root)
        rc, out, _err = self.cmd("clean", root, "--json")
        doc = json.loads(out)
        self.assertEqual(len(doc["findings"]), 1)
        self.assertNotEqual(doc["findings"][0]["label"], first)
        self.assertEqual(doc["kept"], 1)
        rc, out, _err = self.cmd("clean", root)
        self.assertIn("1 secret you chose to keep in clean's review is not "
                      "listed.", " ".join(out.split()))
        rc, out, _err = self.cmd("check", root, "--json")
        self.assertEqual(len(json.loads(out)["secrets"]), 1)
        self.assertEqual(json.loads(out)["kept"], 1)

    def test_kept_ones_do_not_fail_the_build(self):
        root = self.root([tool_use("ls", 2),
                          tool_result("DB_PASSWORD=%s\n" % PASSWORD, 2)])
        self.assertEqual(self.cmd("clean", root, "--fail-on", "critical")[0], 3)
        # The review keeps it: the run that kept it passes, and so do later ones.
        rc, _out, _err = self.cmd("clean", root, "--fail-on", "critical",
                                  replies=["keep 1", "quit"])
        self.assertEqual(rc, 0)
        self.assertEqual(self.cmd("clean", root, "--fail-on", "critical")[0], 0)
        self.assertEqual(self.cmd("check", root, "--fail-on", "critical")[0], 0)

    def test_apply_leaves_a_kept_value_and_masks_the_rest(self):
        root = self.root(SECRETS)
        _rc, before, _err = self.cmd("clean", root, "--json")
        kept_label = json.loads(before)["findings"][0]["label"]
        self.keep_first(root)
        kept_value = PASSWORD if kept_label == "DB_PASSWORD" else STRIPE
        other = STRIPE if kept_value == PASSWORD else PASSWORD
        rc, _out, _err = self.cmd("clean", root, "--apply")
        text = self.text(self.transcript)
        self.assertIn(kept_value, text)
        self.assertNotIn(other, text)

    def test_apply_leaves_a_kept_value_in_another_transcript(self):
        # A copy in a second transcript, found by the cross-transcript
        # search, is spared there too.
        root = self.root(SECRETS)
        second = os.path.join(os.path.dirname(self.transcript), "s2.jsonl")
        with open(second, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(tool_result("again: %s and %s" % (PASSWORD, STRIPE),
                                            4)) + "\n")
        then = time.time() - 600
        os.utime(second, (then, then))
        known.Kept.add([PASSWORD])
        self.cmd("clean", root, "--apply")
        for path in (self.transcript, second):
            text = self.text(path)
            self.assertIn(PASSWORD, text, path)
            self.assertNotIn(STRIPE, text, path)

    def test_the_kept_file_holds_no_value_and_no_fingerprint(self):
        root = self.root(SECRETS)
        self.keep_first(root)
        raw = self.text(self.kept_file())
        for value in (PASSWORD, STRIPE):
            self.assertNotIn(value[:8], raw)
            self.assertNotIn(clean._fingerprint(value), raw)
        doc = json.loads(raw)
        self.assertEqual(doc["version"], known.KEPT_VERSION)
        self.assertEqual(len(doc["values"]), 1)
        if os.name != "nt":
            self.assertEqual(os.stat(self.kept_file()).st_mode & 0o777, 0o600)

    def test_another_key_forgets_what_was_kept(self):
        known.Kept.add([PASSWORD])
        self.assertIn(PASSWORD, known.Kept.open())
        os.unlink(os.path.join(known.index_dir(), "key"))
        known._store_key(known.index_dir(), os.urandom(32))
        self.assertNotIn(PASSWORD, known.Kept.open())
        self.assertFalse(known.Kept.open())

    def test_a_damaged_file_is_none_kept(self):
        known.Kept.add([PASSWORD])
        with open(self.kept_file(), "w", encoding="utf-8") as fh:
            fh.write("{not json")
        self.assertFalse(known.Kept.open())
        self.assertIsNotNone(known.Kept.add([STRIPE]))
        self.assertIn(STRIPE, known.Kept.open())

    def test_adding_keeps_what_was_kept_before(self):
        known.Kept.add([PASSWORD])
        known.Kept.add([STRIPE])
        kept = known.Kept.open()
        self.assertIn(PASSWORD, kept)
        self.assertIn(STRIPE, kept)
        self.assertEqual(len(kept), 2)

    def test_an_index_opened_first_does_not_replace_the_key(self):
        # check or watch opens the index before any key exists; a keep made
        # meanwhile stores one. The index's save must not write its own key
        # over it, which would forget what was kept.
        root = self.root(SECRETS)
        index = known.Index.open(root)
        known.Kept.add([PASSWORD])
        with open(os.path.join(known.index_dir(), "key"), "rb") as fh:
            key = fh.read()
        index.update()
        with open(os.path.join(known.index_dir(), "key"), "rb") as fh:
            self.assertEqual(fh.read(), key)
        self.assertIn(PASSWORD, known.Kept.open())
        # The next run indexes under the stored key.
        matcher = known.Index.open(root).update()
        self.assertEqual(matcher.mask("x " + PASSWORD), "x " + clean.mask_for_display(
            PASSWORD, [(0, len(PASSWORD))]))

    def test_nothing_writable_keeps_for_the_session_only(self):
        root = self.root(SECRETS)
        with mock.patch.object(known, "_store_key", return_value=False):
            rc, out, _err = self.cmd("clean", root, replies=["keep 1", "quit"])
        self.assertIn("kept for this session; it could not be remembered.", out)
        self.assertFalse(known.Kept.open())


class ReviewFixes(Sarif):
    """Regression tests for what the adversarial review proved."""

    def test_a_masked_lines_fingerprint_is_not_in_sarif(self):
        # After --apply the transcript holds <ranwhat:redacted:FP>, FP an
        # unkeyed hash of the value; watch's evidence quoted it.
        rows = [tool_use("curl https://api.stripe.com/v1/charges -u x:%s" % STRIPE, 1),
                tool_use("ls", 2), tool_result("STRIPE=%s\n" % STRIPE, 2)]
        root = self.root(rows)
        self.cmd("clean", root, "--apply")
        self.assertIn("ranwhat:redacted:", self.text(self.transcript))
        fp = clean._fingerprint(STRIPE)
        path = os.path.join(self.tmp, "after.sarif")
        for command in ("watch", "check"):
            self.cmd(command, root, "--sarif", path)
            raw = self.text(path)
            for cut in range(4, 13):
                self.assertNotIn(fp[-cut:], raw, (command, cut))
            self.assertNotIn(fp[:4], raw.replace("ranwhat:redacted", ""))

    def test_a_cut_mark_is_scrubbed(self):
        for text in ("x <ranwhat:redacted:78a08441f431> y", "\u2026a08441f431> y",
                     "\u2026ted:78a08441f431>", "\u2026<ranwhat:redacted:78a0"):
            self.assertNotIn("8441", sarif._unmarked(text), text)
            self.assertNotIn("78a0", sarif._unmarked(text), text)
        self.assertEqual(sarif._unmarked("sk_\u2026dc, 32 chars"), "sk_\u2026dc, 32 chars")

    def test_a_value_in_a_file_name_is_masked_before_it_is_a_uri(self):
        # as_uri() writes = as %3D, and the mask no longer found the value.
        root = self.root(SECRETS)
        named = os.path.join(os.path.dirname(self.transcript), "s-%s.jsonl" % PASSWORD)
        os.rename(self.transcript, named)
        path = os.path.join(self.tmp, "named.sarif")
        from urllib.parse import unquote
        for command, extra in (("clean", ()), ("clean", ("--json",)), ("check", ())):
            self.cmd(command, root, "--sarif", path, *extra)
            raw = unquote(self.text(path))
            self.assertNotIn(PASSWORD, raw, command)
            self.assertNotIn(PASSWORD[:12], raw, command)

    def test_a_kept_value_typed_into_a_call_is_no_finding(self):
        rows = [tool_use("ls", 1), tool_result("STRIPE=%s\n" % STRIPE, 1),
                tool_use("echo %s > /tmp/key.txt" % STRIPE, 2)]
        root = self.root(rows)
        rc, out, _err = self.cmd("watch", root, "--json")
        self.assertIn("secret.literal", out)
        self.assertEqual(self.cmd("check", root, "--fail-on", "critical")[0], 3)
        known.Kept.add([STRIPE])
        path = os.path.join(self.tmp, "kept.sarif")
        for command in ("watch", "check"):
            rc, _out, _err = self.cmd(command, root, "--fail-on", "critical",
                                      "--sarif", path)
            self.assertEqual(rc, 0, command)
            self.assertNotIn("secret.literal\"", self.text(path).split('"results"')[1])
        # Only for that run: another value is still flagged.
        self.assertIsNone(watch._SPARE)


class KeyAndLock(_Base):

    def test_a_key_is_never_written_over_another(self):
        where = known.index_dir()
        first, second = os.urandom(32), os.urandom(32)
        self.assertTrue(known._store_key(where, first))
        self.assertFalse(known._store_key(where, second))
        self.assertEqual(known._stored_key(where), first)

    def test_a_damaged_key_is_replaced(self):
        where = known.index_dir()
        os.makedirs(where)
        with open(os.path.join(where, "key"), "wb") as fh:
            fh.write(b"short")
        key = os.urandom(32)
        self.assertTrue(known._store_key(where, key))
        self.assertEqual(known._stored_key(where), key)

    def test_a_key_stored_while_an_index_waits_is_kept(self):
        # The index checks for a key, finds none, and another run stores
        # one before the index writes its own: the review showed the old
        # check-then-store lost everything kept under the other.
        root = self.root(SECRETS)
        index = known.Index.open(root)
        real = known._store_key

        def racing(where, key):
            if known._stored_key(where) is None:
                real(where, os.urandom(32))     # the other run, first
                known.Kept.add([PASSWORD])
            return real(where, key)
        with mock.patch.object(known, "_store_key", racing):
            index.update()
        self.assertIn(PASSWORD, known.Kept.open())

    def test_a_keep_waits_for_another(self):
        known.Kept.add([PASSWORD])
        lock = os.path.join(known.index_dir(), known.KEPT_FILE + ".lock")
        with mock.patch.object(known, "_LOCK_WAIT", 0.2):
            with known._locked(lock) as held:
                self.assertTrue(held)
                self.assertIsNone(known.Kept.add([STRIPE]))     # not lost: refused
        self.assertFalse(os.path.exists(lock))
        self.assertIsNotNone(known.Kept.add([STRIPE]))
        kept = known.Kept.open()
        self.assertIn(PASSWORD, kept)
        self.assertIn(STRIPE, kept)

    def test_a_stale_lock_is_taken(self):
        os.makedirs(known.index_dir(), exist_ok=True)
        lock = os.path.join(known.index_dir(), known.KEPT_FILE + ".lock")
        open(lock, "wb").close()
        then = time.time() - 3600
        os.utime(lock, (then, then))
        self.assertIsNotNone(known.Kept.add([PASSWORD]))


@unittest.skipIf(os.name == "nt" or not shutil.which("bash"), "needs bash")
class ActionSteps(_Base):
    """The action's own shell, run as the runner runs it."""

    def steps(self):
        here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(here, "action.yml"), encoding="utf-8") as fh:
            text = fh.read()
        bodies = re.findall(r"\n      run: \|\n((?:        .*\n|\n)+)", text)
        return here, ["\n".join(line[8:] for line in body.split("\n"))
                      for body in bodies]

    def act(self, root, **inputs):
        here, (run, gate) = self.steps()
        work = os.path.join(self.tmp, "work")
        os.makedirs(work, exist_ok=True)
        output = os.path.join(self.tmp, "github_output")
        env = dict(os.environ, GITHUB_OUTPUT=output, RANWHAT_ACTION_PATH=here,
                   RANWHAT_COMMAND="check", RANWHAT_FAIL_ON="high",
                   RANWHAT_DAYS="30", RANWHAT_SARIF="ranwhat.sarif",
                   RANWHAT_ARGS="--source claude-code --root %s" % root)
        env.update(inputs)
        open(output, "w", encoding="utf-8").close()
        done = subprocess.run(["bash", "-eo", "pipefail", "-c", run], cwd=work,
                              env=env, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, timeout=120)
        with open(output, encoding="utf-8") as fh:
            outputs = dict(line.split("=", 1) for line in fh.read().split())
        status = outputs.get("exit-code")
        gated = subprocess.run(["bash", "-eo", "pipefail", "-c", gate], env=dict(
            os.environ, RANWHAT_STATUS=status or "", RANWHAT_ALLOW_EMPTY=inputs.get(
                "allow_empty", "true")), stdout=subprocess.PIPE, timeout=60)
        return done.returncode, outputs, gated.returncode, work

    def test_findings_fail_with_3(self):
        rc, outputs, gate, work = self.act(self.root(DELETE))
        self.assertEqual((rc, outputs["exit-code"], gate), (0, "3", 3))
        self.assertTrue(os.path.exists(os.path.join(work, "ranwhat.sarif")))

    def test_a_refused_flag_is_an_error_not_an_empty_history(self):
        root = self.root(DELETE)
        work = os.path.join(self.tmp, "work")
        os.makedirs(work)
        with open(os.path.join(work, "ranwhat.sarif"), "w", encoding="utf-8") as fh:
            fh.write("{}")                      # a stale one, from before
        rc, outputs, gate, _work = self.act(root, RANWHAT_ARGS="--no-such-flag")
        self.assertEqual(outputs["exit-code"], "1")
        self.assertNotIn("sarif-file", outputs)
        self.assertEqual(gate, 1)               # allow-empty does not pass it

    def test_bad_inputs_are_refused(self):
        root = self.root(DELETE)
        for inputs in ({"RANWHAT_FAIL_ON": "hihg"}, {"RANWHAT_DAYS": ""},
                       {"RANWHAT_DAYS": "7d"}, {"RANWHAT_COMMAND": "demo"}):
            rc, outputs, _gate, _work = self.act(root, **inputs)
            self.assertEqual(rc, 1, inputs)
            self.assertNotIn("exit-code", outputs, inputs)

    def test_an_empty_history_passes_only_when_allowed(self):
        empty = os.path.join(self.tmp, "empty")
        os.makedirs(empty)
        _rc, outputs, gate, _work = self.act(empty)
        self.assertEqual((outputs["exit-code"], gate), ("2", 0))
        _rc, outputs, gate, _work = self.act(empty, allow_empty="false")
        self.assertEqual((outputs["exit-code"], gate), ("2", 2))


if __name__ == "__main__":
    unittest.main()
