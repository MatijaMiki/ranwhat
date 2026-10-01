"""Secret detection and masking in local transcripts.

The dangerous failure here is not missing a secret -- it is masking something
that was never one, because the file being rewritten is the user's own agent
history and a bad replacement is silent corruption.
"""
import io
import json
import ntpath
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ranwhat import clean
from ranwhat.clean import REDACTION, find_secrets, scan, scan_file


def n(text):
    return len(find_secrets(text))


class Detection(unittest.TestCase):

    def test_secret_shaped_values(self):
        # Not an alphabet run: that is a fixture, see test_fixtures.py.
        self.assertEqual(n("STRIPE=sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc"), 1)
        self.assertEqual(n("AWS=AKIAIOSFODNN7REALKEY"), 1)
        self.assertEqual(n("JWT_ACCESS_SECRET=8f3a9c2e1b7d4f6a0c5e8b2d7f1a4c9e"), 1)

    def test_connection_string_password(self):
        self.assertEqual(n("DATABASE_URL=postgresql://admin:sup3rS3cretPw@db:5432/a"), 1)

    def test_password_inside_a_url_is_not_reported_twice(self):
        """It is already covered by the URL that contains it."""
        found = find_secrets("DATABASE_URL=postgresql://u:pa55word11@h:5432/d")
        self.assertEqual(len(found), 1)

    def test_ordinary_config_is_left_alone(self):
        for text in ("NODE_ENV=production", "PORT=3100",
                     "NEXT_PUBLIC_URL=https://example.com",
                     "LOG_LEVEL=debug"):
            self.assertEqual(n(text), 0, text)

    def test_placeholders_are_not_secrets(self):
        for text in ("API_KEY=your-api-key-here", "TOKEN=replace-with-your-token",
                     "PASSWORD=insert_password_here", "SECRET=enter-your-secret",
                     "JWT_SECRET=changeme", "DATABASE_URL=<redacted>",
                     "KEY=xxxxxxxxxx", "SECRET=${MY_SECRET}"):
            self.assertEqual(n(text), 0, text)

    def test_short_values_are_ignored(self):
        self.assertEqual(n("PASSWORD=abc"), 0)


class OnlyLiteralsAreSecrets(unittest.TestCase):
    """Every case here came from a machine with a real agent history, where
    this rule reported 185 secrets and roughly two thirds were code."""

    def test_environment_references_are_not_values(self):
        for text in ("JWT_SECRET=process.env.JWT_ACCESS_SECRET",
                     "password: process.env.DB_PASSWORD",
                     "secret: os.environ['JWT_SECRET']",
                     "apiKey: import.meta.env.VITE_KEY"):
            self.assertEqual(n(text), 0, text)

    def test_function_calls_are_not_values(self):
        for text in ("const secret = crypto.randomBytes(32)",
                     "token = randomBytes(32).toString('hex')",
                     "secret: Buffer.from(raw)",
                     "token: headers.auth(h)",
                     "TOKEN=$(printf '%s' $x | cli)"):
            self.assertEqual(n(text), 0, text)

    def test_templates_regexes_and_paths(self):
        for text in ("token = `${env}-session-id`",
                     "pattern: token=[A-Z]{20}",
                     "DATABASE_URL=.*|postgres|mysql|",
                     "PWD=/Users/mikica/Desktop/cistimo"):
            self.assertEqual(n(text), 0, text)

    def test_identifiers_and_already_masked_values(self):
        for text in ("token: tokenAddress", "auth: Authorization",
                     "Token=gho_****************************"):
            self.assertEqual(n(text), 0, text)

    def test_low_entropy_prose_is_not_a_secret(self):
        self.assertEqual(n("bad_credentials: rate limit exceeded"), 0)

    def test_real_credentials_still_found(self):
        for text in ("DB_PASSWORD=kzN8fJx2mQ4vB7nR5tY9wL3pZ6aS1dF0c2e=",
                     "SESSION_SECRET=be1c4f7a9d2e6b8c0f3a5d7e9b1c4f6a8d0e2b5c7f9a1d3e6b8c0f2a4d5e6",
                     "APP_KEY=base64:Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MGFiY2RlZmdoaQ==",
                     "RENDER_API_KEY=zGK7pQ2mV9xR4tN8wL1bY6cF3jH5dS0aE60",
                     "AWS_ACCESS_KEY_ID=AKIA4TRUE7KEYX9QZ2WB",
                     "TURNSTILE_SECRET=0x4AAAAAAABkMYinukE8nzYSjRt2wLpF3Lc",
                     "DATABASE_URL=postgresql://buzz:Xk9mPq2vRt7@db.internal:5432/app"):
            self.assertEqual(n(text), 1, text)


def _transcript(body):
    root = tempfile.mkdtemp(prefix="clean-t-")
    d = os.path.join(root, "proj")
    os.makedirs(d)
    path = os.path.join(d, "s.jsonl")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(json.dumps({"type": "user", "message": {"content": [
            {"type": "tool_result", "content": body}]}}) + "\n")
    return root, path


class Masking(unittest.TestCase):

    BODY = ("DATABASE_URL=postgresql://admin:sup3rS3cretPw@db:5432/app\n"
            "JWT_ACCESS_SECRET=8f3a9c2e1b7d4f6a0c5e8b2d7f1a4c9e\n"
            "NODE_ENV=production\n")

    def test_dry_run_changes_nothing(self):
        root, path = _transcript(self.BODY)
        before = open(path, encoding="utf-8").read()
        findings, scanned, changed = scan(root=root, apply=False)
        self.assertEqual(len(findings), 2)
        self.assertEqual(changed, [])
        self.assertEqual(open(path, encoding="utf-8").read(), before)

    def test_apply_masks_and_leaves_valid_json(self):
        root, path = _transcript(self.BODY)
        scan(root=root, apply=True)
        for line in open(path, encoding="utf-8"):
            if line.strip():
                json.loads(line)          # must still parse
        text = open(path, encoding="utf-8").read()
        self.assertNotIn("sup3rS3cretPw", text)
        self.assertNotIn("8f3a9c2e1b7d4f6a0c5e8b2d7f1a4c9e", text)
        self.assertIn("NODE_ENV=production", text)
        self.assertIn("ranwhat:redacted:", text)

    def test_a_backup_is_written_before_changing_anything(self):
        from ranwhat.clean import BACKUP_ROOT
        root, path = _transcript(self.BODY)
        scan(root=root, apply=True)
        hits = []
        for base, _dirs, files in os.walk(BACKUP_ROOT):
            for f in files:
                if f == "s.jsonl":
                    hits.append(os.path.join(base, f))
        self.assertTrue(hits, "no backup was written")
        self.assertIn("sup3rS3cretPw", open(sorted(hits)[-1], encoding="utf-8").read())

    def test_running_twice_is_a_no_op(self):
        """A masked value must not be treated as a new secret to mask."""
        root, path = _transcript(self.BODY)
        scan(root=root, apply=True)
        after_first = open(path, encoding="utf-8").read()
        findings, _scanned, changed = scan(root=root, apply=True)
        self.assertEqual(findings, {})
        self.assertEqual(changed, [])
        self.assertEqual(open(path, encoding="utf-8").read(), after_first)

    def test_transcript_without_secrets_is_untouched(self):
        root, path = _transcript("NODE_ENV=production\nPORT=3100\n")
        before = open(path, encoding="utf-8").read()
        findings, _s, changed = scan(root=root, apply=True)
        self.assertEqual(findings, {})
        self.assertEqual(changed, [])
        self.assertEqual(open(path, encoding="utf-8").read(), before)


if __name__ == "__main__":
    unittest.main(verbosity=2)


class WhereDidItComeFrom(unittest.TestCase):
    """A 64-character string is useless without knowing which file it came
    out of and which project that file belongs to."""

    def _project(self, slug, rows):
        root = tempfile.mkdtemp(prefix="where-")
        d = os.path.join(root, slug)
        os.makedirs(d)
        with open(os.path.join(d, "s.jsonl"), "w", encoding="utf-8") as fh:
            for r in rows:
                fh.write(json.dumps(r) + "\n")
        return root

    def test_secret_is_attributed_to_the_file_it_was_read_from(self):
        rows = [
            {"message": {"content": [{"type": "tool_use", "name": "Bash",
                                      "input": {"command": "cat api/.env"}}]}},
            {"message": {"content": [{"type": "tool_result",
                "content": "AWS_ACCESS_KEY_ID=AKIA4TRUE7KEYX9QZ2WB\n"}]}},
        ]
        root = self._project("-Users-me-Desktop-app", rows)
        findings, _s, _c = scan(root=root)
        entry = list(findings.values())[0]
        self.assertIn("api/.env", entry["origins"])

    def test_templates_are_not_offered_as_the_origin(self):
        rows = [
            {"message": {"content": [{"type": "tool_use", "name": "Bash",
                                      "input": {"command": "cat .env.example"}}]}},
            {"message": {"content": [{"type": "tool_result",
                "content": "AWS_ACCESS_KEY_ID=AKIA4TRUE7KEYX9QZ2WB\n"}]}},
        ]
        root = self._project("-Users-me-Desktop-app", rows)
        findings, _s, _c = scan(root=root)
        self.assertEqual(list(findings.values())[0]["origins"], set())

    def test_project_slug_resolves_against_the_filesystem(self):
        from ranwhat.clean import project_path
        import tempfile as tf
        base = tf.mkdtemp()
        os.makedirs(os.path.join(base, "birthday-planner"))
        # Flattened as Claude Code does it: every separator, and the colon
        # after a Windows drive, becomes a dash.
        drive, rest = os.path.splitdrive(base)
        slug = (drive.replace(":", "-") + rest.replace(os.sep, "-")
                + "-birthday-planner")
        self.assertEqual(project_path(slug),
                         os.path.join(base, "birthday-planner"))

    def test_a_windows_slug_resolves_to_a_drive_path(self):
        dirs = {"C:\\", r"C:\Users", r"C:\Users\me",
                r"C:\Users\me\birthday-planner"}
        with mock.patch.object(clean.os, "name", "nt"), \
             mock.patch.object(clean.os, "path", ntpath), \
             mock.patch.object(ntpath, "isdir", dirs.__contains__):
            self.assertEqual(clean.project_path("C--Users-me-birthday-planner"),
                             r"C:\Users\me\birthday-planner")
            self.assertEqual(clean.project_path("C--Users-me-gone-app"),
                             r"C:\Users\me\gone-app")

    def test_a_drive_shaped_slug_is_left_alone_off_windows(self):
        with mock.patch.object(clean.os, "name", "posix"):
            self.assertEqual(clean.project_path("C--Users-me-app"),
                             "C--Users-me-app")

    def test_unknown_slug_keeps_dashes_rather_than_splitting_every_one(self):
        from ranwhat.clean import project_path
        out = project_path("-nonexistent-root-some-project-name")
        self.assertTrue(out.endswith("some-project-name"), out)


class MaskingDoesNotWidenExposure(unittest.TestCase):
    """clean exists to reduce where a secret can be read from. A rewrite
    that loosens the transcript's mode, or a backup anyone can read, makes
    it the opposite."""

    def setUp(self):
        from unittest import mock
        from ranwhat import clean
        self.root = os.path.join(tempfile.mkdtemp(prefix="bk-"), "backups")
        patch = mock.patch.object(clean, "BACKUP_ROOT", self.root)
        patch.start()
        self.addCleanup(patch.stop)

    def _backups(self):
        return [os.path.join(base, f) for base, _d, files in os.walk(self.root)
                for f in files]

    @unittest.skipIf(os.name == "nt", "Windows has no owner-only mode bits")
    def test_a_private_transcript_stays_private(self):
        root, path = _transcript(Masking.BODY)
        os.chmod(path, 0o600)
        scan(root=root, apply=True)
        self.assertIn("ranwhat:redacted:", open(path, encoding="utf-8").read())
        self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)

    @unittest.skipIf(os.name == "nt", "Windows has no owner-only mode bits")
    def test_the_original_mode_is_kept_not_tightened_either(self):
        root, path = _transcript(Masking.BODY)
        os.chmod(path, 0o640)
        scan(root=root, apply=True)
        self.assertEqual(os.stat(path).st_mode & 0o777, 0o640)

    @unittest.skipIf(os.name == "nt", "Windows has no owner-only mode bits")
    def test_backups_are_readable_only_by_the_owner(self):
        root, path = _transcript(Masking.BODY)
        os.chmod(path, 0o644)
        scan(root=root, apply=True)
        self.assertEqual(os.stat(self.root).st_mode & 0o777, 0o700)
        backups = self._backups()
        self.assertTrue(backups)
        for b in backups:
            self.assertEqual(os.stat(b).st_mode & 0o777, 0o600, b)

    def test_two_masks_in_one_second_keep_the_true_original(self):
        """Masking one finding and then another used to reuse the same
        backup path, so the second backup (already half masked) replaced
        the only unmasked copy."""
        root, path = _transcript(Masking.BODY)
        findings, _, _ = scan(root=root, apply=False)
        fps = sorted(findings)
        scan_file(path, apply=True, only={fps[0]})
        scan_file(path, apply=True, only={fps[1]})
        texts = [open(b, encoding="utf-8").read() for b in self._backups()]
        self.assertEqual(len(texts), 2)
        self.assertTrue(any("sup3rS3cretPw" in t and "8f3a9c2e" in t for t in texts),
                        "no backup still holds the fully unmasked original")

    def test_two_masks_in_one_clock_tick_keep_the_true_original(self):
        """Microseconds only separate backups if the clock ticks between
        them. On Windows before Python 3.13 it ticks every 1 to 16 ms, and
        O_EXCL refused the second backup with FileExistsError."""
        import datetime

        class Frozen(datetime.datetime):
            @classmethod
            def now(cls, tz=None):
                return cls(2026, 9, 27, 12, 0, 0, 0)

        root, path = _transcript(Masking.BODY)
        fps = sorted(scan(root=root, apply=False)[0])
        with mock.patch.object(clean.datetime, "datetime", Frozen):
            scan_file(path, apply=True, only={fps[0]})
            scan_file(path, apply=True, only={fps[1]})
            scan_file(path, apply=True)   # nothing left to mask, no backup
        self.assertEqual(sorted(os.listdir(self.root)),
                         ["20260927-120000-000000", "20260927-120000-000000-1"])
        first = [b for b in self._backups()
                 if os.path.relpath(b, self.root).split(os.sep)[0]
                 == "20260927-120000-000000"]
        text = open(first[0], encoding="utf-8").read()
        self.assertTrue("sup3rS3cretPw" in text and "8f3a9c2e" in text,
                        "the first backup is not the unmasked original")

    def test_no_temp_file_is_left_behind(self):
        root, path = _transcript(Masking.BODY)
        scan(root=root, apply=True)
        self.assertEqual(os.listdir(os.path.dirname(path)), ["s.jsonl"])

    def test_the_backup_is_the_original_byte_for_byte(self):
        """On Windows a descriptor from os.open is in text mode unless told
        otherwise, and a backup written through one would gain a \\r per
        line."""
        root, path = _transcript(Masking.BODY)
        with open(path, "rb") as fh:
            original = fh.read()
        scan(root=root, apply=True)
        backups = self._backups()
        self.assertEqual(len(backups), 1)
        with open(backups[0], "rb") as fh:
            self.assertEqual(fh.read(), original)


class WhereTheBackupGoes(unittest.TestCase):
    """The backup is the transcript's absolute path re-rooted under the
    backup directory. On Windows, joining C:\\... onto the root discarded
    the root, so the "backup" was the transcript itself, and O_EXCL was all
    that stopped clean --apply from truncating it."""

    def test_a_posix_path(self):
        import posixpath
        with mock.patch.object(clean.os, "path", posixpath):
            self.assertEqual(
                clean._backup_dest("/home/me/.ranwhat/backups", "20260927",
                                   "/home/me/.claude/projects/-app/s.jsonl"),
                "/home/me/.ranwhat/backups/20260927/home/me/.claude/projects/"
                "-app/s.jsonl")

    def test_a_windows_drive_becomes_a_directory(self):
        with mock.patch.object(clean.os, "path", ntpath):
            self.assertEqual(
                clean._backup_dest(r"C:\Users\me\.ranwhat\backups", "20260927",
                                   r"C:\Users\me\.claude\projects\C--app\s.jsonl"),
                r"C:\Users\me\.ranwhat\backups\20260927\C\Users\me"
                r"\.claude\projects\C--app\s.jsonl")

    def test_a_windows_share_becomes_directories(self):
        with mock.patch.object(clean.os, "path", ntpath):
            self.assertEqual(
                clean._backup_dest(r"C:\b", "20260927",
                                   r"\\server\share\p\s.jsonl"),
                r"C:\b\20260927\server\share\p\s.jsonl")


class RewriteKeepsEveryByteItDoesNotMask(unittest.TestCase):
    """Only the secret changes. Reading in text mode turned \\r\\n into \\n
    on every line of a rewritten transcript, and the locale's encoding
    (cp1252 on Windows) would have mangled everything outside ASCII."""

    SECRET = "8f3a9c2e1b7d4f6a0c5e8b2d7f1a4c9e"

    def setUp(self):
        backups = os.path.join(tempfile.mkdtemp(prefix="bk-"), "backups")
        patch = mock.patch.object(clean, "BACKUP_ROOT", backups)
        patch.start()
        self.addCleanup(patch.stop)

    def _line(self, text):
        return json.dumps({"type": "user", "message": {"content": [
            {"type": "tool_result", "content": text}]}}, ensure_ascii=False)

    def _apply(self, lines):
        d = tempfile.mkdtemp(prefix="bytes-")
        path = os.path.join(d, "s.jsonl")
        original = "".join(lines).encode("utf-8")
        with open(path, "wb") as fh:
            fh.write(original)
        findings, changed = scan_file(path, apply=True)
        self.assertTrue(changed)
        (fp,) = findings
        with open(path, "rb") as fh:
            after = fh.read()
        return original, after, (REDACTION % fp).encode("utf-8")

    def test_crlf_and_text_beyond_ascii_survive(self):
        lines = [self._line("Café ≠ café, 日本語 ✓") + "\r\n",
                 self._line("JWT_ACCESS_SECRET=%s naïve" % self.SECRET) + "\r\n",
                 self._line("Ωmega, untouched") + "\n",
                 self._line("last line, no ending ✓")]
        original, after, mask = self._apply(lines)
        self.assertEqual(after, original.replace(self.SECRET.encode(), mask))

    def test_a_masked_last_line_gains_no_ending(self):
        lines = [self._line("first ✓") + "\n",
                 self._line("JWT_ACCESS_SECRET=%s" % self.SECRET)]
        original, after, mask = self._apply(lines)
        self.assertEqual(after, original.replace(self.SECRET.encode(), mask))


class InteractiveReview(unittest.TestCase):
    """`ranwhat clean` on a terminal with findings and no --apply lands in
    review(). A mask there rewrote the file and then died on a NameError
    printing the backup note, so the session ended in a traceback."""

    def setUp(self):
        self.backups = os.path.join(tempfile.mkdtemp(prefix="bk-"), "backups")
        patch = mock.patch.object(clean, "BACKUP_ROOT", self.backups)
        patch.start()
        self.addCleanup(patch.stop)

    def _review(self, *commands):
        root, path = _transcript(Masking.BODY)
        findings, scanned, _ = scan(root=root, apply=False)
        replies = iter(commands)
        out = io.StringIO()
        with mock.patch("builtins.input", lambda prompt="": next(replies)):
            changed = clean.review(findings, scanned, stream=out)
        return path, changed, out.getvalue()

    def test_mask_one_finishes_and_counts_the_file(self):
        path, changed, out = self._review("mask 1", "quit")
        self.assertEqual(changed, 1)
        self.assertIn("masked in 1 file(s).", out)
        self.assertIn("They still hold every masked value.", out)
        self.assertEqual(open(path, encoding="utf-8").read().count(
            "ranwhat:redacted:"), 1)

    def test_mask_all_finishes_and_counts_the_file(self):
        path, changed, out = self._review("mask all", "quit")
        self.assertEqual(changed, 1)
        self.assertIn("masked in 1 file(s).", out)
        text = open(path, encoding="utf-8").read()
        self.assertNotIn("sup3rS3cretPw", text)
        self.assertNotIn("8f3a9c2e1b7d4f6a0c5e8b2d7f1a4c9e", text)

    def test_masks_add_up_across_commands(self):
        _path, changed, _out = self._review("mask 1", "mask 1", "quit")
        self.assertEqual(changed, 2)
