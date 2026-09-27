"""Secret detection and masking in local transcripts.

The dangerous failure here is not missing a secret -- it is masking something
that was never one, because the file being rewritten is the user's own agent
history and a bad replacement is silent corruption.
"""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ranwhat.clean import find_secrets, scan, scan_file


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
    with open(path, "w") as fh:
        fh.write(json.dumps({"type": "user", "message": {"content": [
            {"type": "tool_result", "content": body}]}}) + "\n")
    return root, path


class Masking(unittest.TestCase):

    BODY = ("DATABASE_URL=postgresql://admin:sup3rS3cretPw@db:5432/app\n"
            "JWT_ACCESS_SECRET=8f3a9c2e1b7d4f6a0c5e8b2d7f1a4c9e\n"
            "NODE_ENV=production\n")

    def test_dry_run_changes_nothing(self):
        root, path = _transcript(self.BODY)
        before = open(path).read()
        findings, scanned, changed = scan(root=root, apply=False)
        self.assertEqual(len(findings), 2)
        self.assertEqual(changed, [])
        self.assertEqual(open(path).read(), before)

    def test_apply_masks_and_leaves_valid_json(self):
        root, path = _transcript(self.BODY)
        scan(root=root, apply=True)
        for line in open(path):
            if line.strip():
                json.loads(line)          # must still parse
        text = open(path).read()
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
        self.assertIn("sup3rS3cretPw", open(sorted(hits)[-1]).read())

    def test_running_twice_is_a_no_op(self):
        """A masked value must not be treated as a new secret to mask."""
        root, path = _transcript(self.BODY)
        scan(root=root, apply=True)
        after_first = open(path).read()
        findings, _scanned, changed = scan(root=root, apply=True)
        self.assertEqual(findings, {})
        self.assertEqual(changed, [])
        self.assertEqual(open(path).read(), after_first)

    def test_transcript_without_secrets_is_untouched(self):
        root, path = _transcript("NODE_ENV=production\nPORT=3100\n")
        before = open(path).read()
        findings, _s, changed = scan(root=root, apply=True)
        self.assertEqual(findings, {})
        self.assertEqual(changed, [])
        self.assertEqual(open(path).read(), before)


if __name__ == "__main__":
    unittest.main(verbosity=2)


class WhereDidItComeFrom(unittest.TestCase):
    """A 64-character string is useless without knowing which file it came
    out of and which project that file belongs to."""

    def _project(self, slug, rows):
        root = tempfile.mkdtemp(prefix="where-")
        d = os.path.join(root, slug)
        os.makedirs(d)
        with open(os.path.join(d, "s.jsonl"), "w") as fh:
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
        slug = base.replace("/", "-") + "-birthday-planner"
        self.assertEqual(project_path(slug),
                         os.path.join(base, "birthday-planner"))

    def test_unknown_slug_keeps_dashes_rather_than_splitting_every_one(self):
        from ranwhat.clean import project_path
        out = project_path("-nonexistent-root-some-project-name")
        self.assertTrue(out.endswith("some-project-name"), out)
