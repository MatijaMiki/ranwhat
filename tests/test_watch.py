"""Precision tests for the local watcher.

The failure mode that matters is false positives. A watcher that fires on a
script *containing* a dangerous string, or on a grep searching *for* one,
gets muted within a day -- and a muted watcher records nothing anyone reads.
Every case here is a real pattern that tripped the naive implementation.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ranwhat import watch


def fires(command):
    return bool(watch.evaluate("Bash", {"command": command})[0])


class NoFalsePositives(unittest.TestCase):
    """Things that mention a dangerous action without performing one."""

    def test_searching_for_a_pattern(self):
        self.assertFalse(fires('grep -rn ".aws/credentials" .'))
        self.assertFalse(fires('rg "rm -rf" src/'))
        self.assertFalse(fires('find . -name "*.env"'))

    def test_foreign_interpreter_source(self):
        self.assertFalse(fires('python3 -c "print(\'rm -rf /\')"'))
        self.assertFalse(fires('node -e "x=\'git push --force\'"'))
        self.assertFalse(fires("sudo python3 -c 'rm -rf /'"))

    def test_interpreter_payload_containing_shell_operators(self):
        """The payload has its own ';' and '|', which must not split it."""
        self.assertFalse(fires('python3 -c "x=\'cat .env\'; y=\\"rm -rf\\""'))

    def test_heredoc_body_is_data_not_commands(self):
        self.assertFalse(fires("python3 - <<'EOF'\nrm -rf /\nEOF"))
        self.assertFalse(fires("cat > f.sh <<'EOF'\nrm -rf /\nEOF"))

    def test_file_content_is_not_an_action(self):
        self.assertEqual(watch.evaluate("Write", {"file_path": "a.sh",
                                                  "content": "rm -rf /"})[0], [])
        self.assertEqual(watch.evaluate("Edit", {"file_path": "a.sh",
                                                 "new_string": "npm publish"})[0], [])


class NoFalseNegatives(unittest.TestCase):
    """Things that really do perform the action."""

    def test_plain_destructive_command(self):
        self.assertTrue(fires("rm -rf ~/Documents/archive"))
        self.assertTrue(fires("cat ~/.aws/credentials"))

    def test_shell_interpreter_payload_is_recursed_into(self):
        """bash -c really does execute shell, unlike python -c."""
        self.assertTrue(fires("bash -c 'rm -rf ~/notes'"))

    def test_later_segment_of_a_chain(self):
        self.assertTrue(fires("echo hi && rm -rf ~/photos"))
        self.assertTrue(fires("python3 -c 'print(1)' && rm -rf ~/photos"))

    def test_find_with_an_action_is_not_a_search(self):
        self.assertTrue(fires('find . -name "*.tmp" -delete'))

    def test_secret_literal_fires_even_in_a_search(self):
        """A live key in a grep pattern is still a leaked key. (A sequential
        AKIA1234567890ABCDEF is a fixture, and is pinned the other way.)"""
        self.assertTrue(fires('grep -r "AKIA4TRUE7KEYX9QZ2WB" .'))


class Evidence(unittest.TestCase):

    def test_evidence_includes_the_target(self):
        """'rm -rf' alone is unjudgeable; the target is the whole point."""
        hits, _ = watch.evaluate("Bash", {"command": "rm -rf ~/client-archive"})
        self.assertIn("client-archive", hits[0]["evidence"])


if __name__ == "__main__":
    unittest.main(verbosity=2)


class DeletionSeverityFollowsTheTarget(unittest.TestCase):
    """The verb alone is not enough signal.

    On a real machine 11 of 15 findings were `rm -rf` against build and temp
    directories. All true, none worth an alert -- and a report that is 73%
    noise gets muted exactly as fast as one full of false positives.
    """

    def severity(self, command):
        hits, _ = watch.evaluate("Bash", {"command": command})
        return hits[0]["severity"] if hits else None

    def test_build_and_temp_directories_are_not_surfaced(self):
        for cmd in ("rm -rf build", "rm -rf dist", "rm -rf target",
                    "rm -rf node_modules && npm install",
                    "rm -rf /tmp/scratch", "rm -rf .venv",
                    "rm -rf __pycache__", "rm -rf build dist target"):
            self.assertIsNone(self.severity(cmd), cmd)

    def test_real_paths_still_surface(self):
        for cmd in ("rm -rf ~/Documents", 'rm -rf "$HOME/Desktop/work"',
                    "rm -rf /srv/uploads"):
            self.assertEqual(self.severity(cmd), watch.HIGH, cmd)

    def test_catastrophic_targets_escalate(self):
        for cmd in ("rm -rf /", "rm -rf / --no-preserve-root", "rm -rf ~",
                    "rm -rf $HOME", "rm -rf /usr", "rm -rf /etc"):
            self.assertEqual(self.severity(cmd), watch.CRITICAL, cmd)

    def test_root_is_not_lost_to_slash_trimming(self):
        """"/".rstrip("/") is the empty string, which silently dropped the one
        target that matters most."""
        self.assertEqual(self.severity("rm -rf /"), watch.CRITICAL)

    def test_a_mixed_deletion_is_judged_by_its_worst_target(self):
        self.assertEqual(self.severity("rm -rf /tmp/x ~/important"), watch.HIGH)

    def test_redirections_are_not_deletion_targets(self):
        """`2>/dev/null` trailing an rm is not a path being removed. Treating
        it as one made every quietened cleanup look like a real deletion."""
        self.assertEqual(watch._rm_targets("rm -rf build 2>/dev/null"), ["build"])
        self.assertEqual(watch._rm_targets("rm -rf build > /dev/null"), ["build"])
        self.assertIsNone(self.severity("rm -rf build dist 2>/dev/null"))

    def test_ephemeral_is_judged_on_every_path_component(self):
        """~/.cache/uv/git-v0 is cache, and node_modules/foo is still
        node_modules. Checking only the basename missed both."""
        self.assertIsNone(self.severity("rm -rf ~/.cache/uv/git-v0"))
        self.assertIsNone(self.severity("rm -rf node_modules/foo/bar"))
        self.assertIsNone(self.severity("rm -rf ~/projects/app/build/out"))
        self.assertEqual(self.severity("rm -rf ~/Documents/build-notes"),
                         watch.HIGH)

    def test_generated_directories_matched_by_suffix(self):
        self.assertIsNone(self.severity("rm -rf ranwhat.egg-info"))
        self.assertIsNone(self.severity("rm -rf build foo.egg-info 2>/dev/null"))


class ProseIsNotACommand(unittest.TestCase):

    def test_description_field_is_ignored(self):
        """The Bash tool carries a human-readable description. One that says
        "clean up the rm -rf targets" is prose, not a deletion."""
        hits, _ = watch.evaluate("Bash", {
            "command": "ls -la",
            "description": "Get rule breakdown and rm -rf target distribution"})
        self.assertEqual(hits, [])


class MentioningIsNotDoing(unittest.TestCase):
    """A command that prints, greps or comments a dangerous string has not
    performed it. Every case here was a live false positive found by probing
    the released build."""

    def sev(self, command):
        hits, _ = watch.evaluate("Bash", {"command": command})
        return hits[0]["severity"] if hits else None

    def test_echo_and_printf_arguments_are_literal_text(self):
        self.assertIsNone(self.sev('echo "rm -rf /"'))
        self.assertIsNone(self.sev("echo 'run rm -rf ~/x to clean up'"))
        self.assertIsNone(self.sev("printf 'rm -rf /' > script.sh"))
        self.assertIsNone(self.sev("echo npm publish"))
        self.assertIsNone(self.sev('echo "history -c"'))

    def test_comments_are_not_commands(self):
        self.assertIsNone(self.sev("# rm -rf ~/important"))
        self.assertIsNone(self.sev("ls -la # rm -rf ~/x"))

    def test_a_real_command_survives_its_own_trailing_comment(self):
        self.assertEqual(self.sev("rm -rf ~/x # cleanup"), watch.HIGH)

    def test_search_is_judged_per_segment(self):
        """`cat README | grep "rm -rf"` escaped suppression entirely, because
        whole-command matching required every segment to be a search."""
        self.assertIsNone(self.sev("cat README | grep 'rm -rf'"))
        self.assertIsNone(self.sev('grep -c "npm publish" build.log'))

    def test_git_rm_cached_does_not_touch_the_working_tree(self):
        self.assertIsNone(self.sev("git rm --cached secrets.txt"))
        self.assertIsNone(self.sev("git rm -r --cached ~/notes"))
        self.assertEqual(self.sev("git rm -r ~/notes"), watch.HIGH)

    def test_inert_segments_do_not_hide_a_real_one(self):
        self.assertEqual(self.sev("echo start; rm -rf ~/x; echo done"), watch.HIGH)
        self.assertEqual(self.sev('echo "#!/bin/sh" > s && rm -rf ~/y'), watch.HIGH)

    def test_shell_interpreters_are_still_recursed_into(self):
        self.assertIsNone(self.sev('sh -c \'echo "rm -rf /"\''))
        self.assertEqual(self.sev('bash -c "rm -rf ~/x"'), watch.HIGH)

    def test_a_leaked_key_fires_even_inside_a_search(self):
        """Presence is the finding for this rule, so it reads the raw text."""
        self.assertEqual(self.sev('grep -r "AKIA4TRUE7KEYX9QZ2WB" .'),
                         watch.CRITICAL)


class EnvironmentIsReadWhenAsked(unittest.TestCase):

    def test_openclaw_state_dir_honours_a_late_env_change(self):
        import os
        before = os.environ.get("OPENCLAW_STATE_DIR")
        try:
            os.environ["OPENCLAW_STATE_DIR"] = "/tmp/set-after-import"
            self.assertEqual(watch.openclaw_state_dir(), "/tmp/set-after-import")
        finally:
            if before is None:
                os.environ.pop("OPENCLAW_STATE_DIR", None)
            else:
                os.environ["OPENCLAW_STATE_DIR"] = before


class CredentialAccessIsJudgedByPathAndCommand(unittest.TestCase):
    """Every case here came from running against a working machine, where the
    rule fired 100+ times and was almost entirely wrong."""

    def sev(self, command):
        hits, _ = watch.evaluate("Bash", {"command": command})
        return hits[0]["severity"] if hits else None

    def test_templates_hold_placeholders_not_secrets(self):
        for cmd in ("cat .env.example", "sed -n 1,20p .env.example",
                    "cp .env.example .env && npx prisma generate",
                    "cat config.sample", "cat .env.template"):
            self.assertIsNone(self.sev(cmd), cmd)

    def test_public_keys_are_public(self):
        self.assertIsNone(self.sev("cat ~/.ssh/id_ed25519.pub"))
        self.assertEqual(self.sev("cat ~/.ssh/id_ed25519"), watch.CRITICAL)

    def test_commands_that_never_read_contents(self):
        for cmd in ("ls -la .env.local*", "ls .env* 2>/dev/null",
                    "cp .env.local .env.local.bak",
                    "mv .env.local.bak .env.local",
                    "git check-ignore .env.local",
                    "git ls-files --error-unmatch .env.local.example"):
            self.assertIsNone(self.sev(cmd), cmd)

    def test_naming_a_file_to_exclude_it_is_not_reading_it(self):
        self.assertIsNone(self.sev(
            "rsync -a --exclude .env --exclude '*.log' src/ dst/"))

    def test_redacting_while_reading_is_care_not_exposure(self):
        self.assertEqual(self.sev("sed -E 's/=.*/=<set>/' .env"), watch.MEDIUM)

    def test_actually_reading_a_secret_still_reports(self):
        for cmd in ("cat .env", "cat api/.env", "cat ~/.aws/credentials"):
            self.assertEqual(self.sev(cmd), watch.CRITICAL, cmd)


class RepeatedCallsAreReportedOnce(unittest.TestCase):

    def test_scan_all_deduplicates(self):
        """A resumed session or a sidechain replays the same tool call into
        another transcript, and it was reported once per copy."""
        import json
        import tempfile
        root = tempfile.mkdtemp(prefix="dedup-")
        entry = json.dumps({
            "timestamp": "2026-09-01T10:00:00Z",
            "message": {"content": [{"type": "tool_use", "name": "Bash",
                                     "input": {"command": "rm -rf ~/archive"}}]}})
        for name in ("a", "b"):
            d = os.path.join(root, "proj-%s" % name)
            os.makedirs(d)
            with open(os.path.join(d, "s.jsonl"), "w") as fh:
                fh.write(entry + "\n")
        records, scanned = watch.scan_all(root=root)
        self.assertEqual(scanned, 2)
        self.assertEqual(len(records), 1)
