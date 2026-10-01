"""Credentials the first rules walked past, and masking text for display.

Each case here was a real miss: an AWS secret key that happens to start with
a slash read as a path, a .env printed inside a JSON tool result read as
code, a service-account private key read as code for the same reason, and a
password left in plaintext because it also sat inside a URL that was masked.
Every value is synthetic.
"""
import json
import os
import random
import string
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ranwhat import clean
from ranwhat.clean import (REDACTION, _fingerprint, _hint, _looks_computed,
                           find_secrets, mask_for_display, scan_file)

# find_secrets skips strings shorter than any credential shape, so a short
# line on its own would pass for the wrong reason.
PAD = "\n# padding so the text clears the minimum scan length"

# AWS secret access keys are 40 characters of base64, so about one in 64
# starts with a slash, and some hold another one or a plus further in.
SLASH_KEYS = [
    "/q7Zk2WpX9vRt4mN8bL1yTsD6fH0jG5cVa3Ke9Uw",
    "/Rt4mN8bL1y/sD6fH0jG5cVa3Ke9Uwq7Zk2WpX9v",
    "/9vRt+4mN8bL1yTsD6fH0jG5cVa3Ke9Uwq7Zk2Wp",
    "/Hv3pdF/asze9s7NpmMG51pdFZ/MVKLGKl9TVCxz",
]

# Paths under key names that make a value a secret. A path is a chain of
# names: one case (usr, a hex digest) or whole words (Desktop, SanDisk128GB).
PATHS = [
    "/usr/local/bin/node",
    "./scripts/deploy.sh",
    "~/.ssh/id_rsa",
    "/Users/x/Desktop/app/.env",
    "/var/run/docker.sock",
    "/api/v1/users",
    "/Users/mikica/Desktop/cistimo",
    "/Users/Mike2/Projects/MyApp2",
    "/Volumes/SanDisk128GB/Photos2023/Backup",
    "/System/Library/PrivateFrameworks/CoreSymbolication",
    "/usr/libexec/AppleVirtualPlatformHIDBridge",
    "/usr/standalone/firmware/FUD/USBCAccessoryFirmwareUpdater",
    "/Users/x/Library/Caches/PassKit/PassAssetCache/"
    "9c1e4b7a2d5f8e0c3b6a9d2f5e8b1c4a7d0f3e6b",
    "/var/lib/docker/containers/"
    "4f2a8c9b1e3d7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b",
]

# A key pair and a database password, as a .env holds them.
AKID = "AKIA4TRUE7KEYX9QZ2WB"
AWS_SECRET = "wJq7Zk2WpX9vRt4mN8bL1yTsD6fH0jG5cVa3Ke9U"
DB_PASSWORD = "kzN8fJx2mQ4vB7nR5tY9wL3p"

# A PKCS#8 body with the fixed RSA header in front of random base64.
PEM_BODY = ("MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7q2Wp9vRt4mN8bL1y\n"
            "TsD6fH0jG5cVa3Ke9Uw2Qo7Ri4Zkx8Jm3Lp5Nq1Vr7Ts9Wu2Xy4Za6Bc8De0Fg2Hi4J\n"
            "k6Lm8No0Pq2Rs4Tu6Vw8Xy0Za1Bc3De5Fg7Hi9Jk1Lm3No5Pq7Rs9TuQ==\n")
PEM = ("-----BEGIN PRIVATE KEY-----\n" + PEM_BODY
       + "-----END PRIVATE KEY-----\n")
PEM_STUBS = ["...", "<your key>", "xxx", "", "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC..."]

STRIPE = "sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc"
JWT = ("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJzeW50aCJ9."
       "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJVadQssw5c")


def _service_account(pem):
    return json.dumps({"type": "service_account", "project_id": "synth",
                       "private_key_id": "0f3e6b9c1e4b7a2d5f8e0c3b6a9d2f5e8b1c4a7d",
                       "private_key": pem,
                       "client_email": "synth@synth.iam.gserviceaccount.com"},
                      indent=2)


_RNG = random.Random(20260926)


def _run(alphabet, k):
    return "".join(_RNG.choice(alphabet) for _ in range(k))


def _read(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def setUpModule():
    # scan_file(apply=True) backs a transcript up first; keep those with the
    # synthetic transcripts rather than in ~/.ranwhat
    global _backups
    _backups = mock.patch.object(clean, "BACKUP_ROOT",
                                 tempfile.mkdtemp(prefix="shapes-backups-"))
    _backups.start()


def tearDownModule():
    _backups.stop()


def _transcript(content):
    d = tempfile.mkdtemp(prefix="shapes-")
    path = os.path.join(d, "s.jsonl")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(json.dumps({"type": "user", "message": {"content": [
            {"type": "tool_result", "tool_use_id": "t1", "content": content}]}})
            + "\n")
    return path


class KeysThatStartWithASlash(unittest.TestCase):

    def test_the_synthetic_keys_are_key_shaped(self):
        for key in SLASH_KEYS:
            self.assertEqual(len(key), 40, key)

    def test_a_key_is_not_a_path(self):
        for key in SLASH_KEYS:
            with self.subTest(key=key):
                self.assertFalse(_looks_computed(key))
                found = find_secrets("AWS_SECRET_ACCESS_KEY=" + key + PAD)
                self.assertEqual(found, [(key, "AWS_SECRET_ACCESS_KEY")])

    def test_a_path_is_still_a_path(self):
        """Pinned on the rule itself too, so the entropy floor cannot make a
        path pass for the wrong reason."""
        for path in PATHS:
            with self.subTest(path=path):
                self.assertTrue(_looks_computed(path))
                for key in ("PWD", "SECRET", "private_key", "api_token",
                            "GOOGLE_APPLICATION_CREDENTIALS"):
                    self.assertEqual(find_secrets("%s=%s%s" % (key, path, PAD)), [])

    def test_openssl_base64_with_padding(self):
        # `openssl rand -base64 32` is 44 characters ending in =
        value = "/Q2vRt4mN8bL1yTsD6fH0jG5cVa3Ke9Uwq7Zk2WpX9s="
        self.assertEqual(len(value), 44)
        self.assertEqual(len(find_secrets("SESSION_SECRET=" + value + PAD)), 1)


class AssignmentsInsideEscapedJson(unittest.TestCase):
    """A tool result that is itself JSON: after the transcript line is
    decoded, its line breaks are still a backslash and an n."""

    STDOUT = json.dumps({"stdout": "AWS_SECRET_ACCESS_KEY=%s\nDB_PASSWORD=%s\n"
                                   % (AWS_SECRET, DB_PASSWORD)})

    def test_values_stop_at_an_escaped_line_break(self):
        found = sorted(find_secrets(self.STDOUT))
        self.assertEqual(found, sorted([(AWS_SECRET, "AWS_SECRET_ACCESS_KEY"),
                                        (DB_PASSWORD, "DB_PASSWORD")]))

    def test_other_escapes_end_a_value_too(self):
        for sep in ("\r\n", "\t", "\\"):
            text = json.dumps({"out": "DB_PASSWORD=%s%sAPI_TOKEN=%s%s"
                                      % (DB_PASSWORD, sep, AWS_SECRET, sep)})
            with self.subTest(sep=sep):
                self.assertEqual(sorted(find_secrets(text)),
                                 sorted([(DB_PASSWORD, "DB_PASSWORD"),
                                         (AWS_SECRET, "API_TOKEN")]))

    def test_escaped_quotes_delimit_a_value(self):
        # JSON inside a JSON string: {\"password\": \"...\"}
        inner = json.dumps({"password": DB_PASSWORD})
        text = json.dumps({"result": inner})
        self.assertEqual(find_secrets(text), [(DB_PASSWORD, "password")])
        text = json.dumps({"cmd": 'export DB_PASSWORD="%s"' % DB_PASSWORD})
        self.assertEqual(find_secrets(text), [(DB_PASSWORD, "DB_PASSWORD")])

    def test_a_quoted_value_that_is_itself_an_assignment(self):
        text = json.dumps({"stdout": "API_TOKEN=" + AWS_SECRET})
        self.assertEqual(find_secrets(text), [(AWS_SECRET, "API_TOKEN")])

    def test_code_with_escapes_is_still_code(self):
        for text in (json.dumps({"src": "const token = `${a}\\n${b}`;\n"}),
                     json.dumps({"src": 'secret: "\\\\d{4}[A-Z]"\n'}),
                     json.dumps({"src": "TOKEN=$(cat f)\nPASSWORD=${DB_PW}\n"})):
            with self.subTest(text=text):
                self.assertEqual(find_secrets(text + PAD), [])

    def test_found_and_masked_through_a_transcript(self):
        path = _transcript(self.STDOUT)
        findings, changed = scan_file(path)
        self.assertFalse(changed)
        self.assertEqual({f["label"] for f in findings.values()},
                         {"AWS_SECRET_ACCESS_KEY", "DB_PASSWORD"})

        findings, changed = scan_file(path, apply=True)
        self.assertTrue(changed)
        text = _read(path)
        self.assertNotIn(AWS_SECRET, text)
        self.assertNotIn(DB_PASSWORD, text)
        row = json.loads(text)
        inner = json.loads(row["message"]["content"][0]["content"])
        self.assertEqual(inner["stdout"],
                         "AWS_SECRET_ACCESS_KEY=%s\nDB_PASSWORD=%s\n"
                         % (REDACTION % _fingerprint(AWS_SECRET),
                            REDACTION % _fingerprint(DB_PASSWORD)))
        self.assertEqual(scan_file(path, apply=True), ({}, False))


class AssignmentScanStaysLinear(unittest.TestCase):
    """A key was tried at every letter of a run, and each try read to the
    end of the run: 20,000 characters took seconds and 200,000 took
    minutes. Reading inside quoted values would have spread that to every
    long JSON string, so a key now starts only where a run does."""

    MIXED = _run(string.ascii_letters + string.digits, 20000)
    HEX = _run("0123456789abcdef", 20000)

    def test_long_runs(self):
        for text in ("k=1 " + self.MIXED, json.dumps({"data": self.MIXED}),
                     "k=1 " + self.HEX, json.dumps({"bytecode": "0x" + self.HEX}),
                     "a=" * 10000, json.dumps({"q": "a=" * 10000})):
            with self.subTest(text=text[:16]):
                t = time.perf_counter()
                list(clean._ASSIGN.finditer(text))
                self.assertLess(time.perf_counter() - t, 0.05)

    def test_a_key_still_starts_after_digits_or_an_escape(self):
        for text, label in (("0API_TOKEN=" + AWS_SECRET, "API_TOKEN"),
                            ("\\nDB_PASSWORD=" + DB_PASSWORD, "DB_PASSWORD"),
                            ("x\\\\API_TOKEN=" + AWS_SECRET, "API_TOKEN")):
            with self.subTest(text=text[:16]):
                self.assertEqual([l for _v, l in find_secrets(text + PAD)], [label])


class EscapedPrivateKeys(unittest.TestCase):

    def test_a_service_account_key_is_found(self):
        found = find_secrets(_service_account(PEM))
        self.assertEqual([label for _v, label in found], ["private key"])
        self.assertTrue(found[0][0].startswith("-----BEGIN PRIVATE KEY-----\\n"))

    def test_a_raw_key_is_still_found(self):
        self.assertEqual([label for _v, label in find_secrets(PEM)], ["private key"])

    def test_stubs_are_not_keys(self):
        for stub in PEM_STUBS:
            pem = ("-----BEGIN PRIVATE KEY-----\n%s\n-----END PRIVATE KEY-----\n"
                   % stub)
            with self.subTest(stub=stub):
                self.assertEqual(find_secrets(_service_account(pem)), [])
                self.assertEqual(find_secrets(pem + PAD), [])

    def test_a_key_assembled_in_code_is_not_a_key(self):
        for text in ('key = "-----BEGIN PRIVATE KEY-----\\n" + body + '
                     '"\\n-----END PRIVATE KEY-----"',
                     "`-----BEGIN PRIVATE KEY-----\\n${base64Body}\\n"
                     "-----END PRIVATE KEY-----`"):
            with self.subTest(text=text):
                self.assertEqual(find_secrets(text), [])

    def test_masked_through_a_transcript(self):
        path = _transcript(_service_account(PEM))
        findings, changed = scan_file(path, apply=True)
        self.assertTrue(changed)
        self.assertEqual([f["label"] for f in findings.values()], ["private key"])
        text = _read(path)
        self.assertNotIn("2Qo7Ri4Zkx8Jm3Lp5Nq1Vr7Ts9Wu2Xy4", text)
        inner = json.loads(json.loads(text)["message"]["content"][0]["content"])
        self.assertTrue(inner["private_key"].startswith("<ranwhat:redacted:"))
        self.assertEqual(inner["client_email"], "synth@synth.iam.gserviceaccount.com")


class ASecretInsideAnother(unittest.TestCase):
    """A .env that reuses its database password inside DATABASE_URL. The
    password was dropped as a part of the URL, so masking the URL left the
    DB_PASSWORD line in plaintext. Once escaped values were read, the same
    happened inside JSON tool output."""

    ENV = ("DB_PASSWORD=Xk9mPq2vRt7wLz\n"
           "DATABASE_URL=postgresql://app:Xk9mPq2vRt7wLz@db:5432/app\n")

    def test_a_value_also_seen_on_its_own_is_reported(self):
        for text in (self.ENV, json.dumps({"stdout": self.ENV})):
            with self.subTest(escaped=text.startswith("{")):
                self.assertEqual(
                    sorted(label for _v, label in find_secrets(text)),
                    ["DATABASE_URL", "DB_PASSWORD"])

    def test_only_inside_the_bigger_one_is_still_reported_once(self):
        found = find_secrets("DATABASE_URL=postgresql://u:pa55word11@h:5432/d")
        self.assertEqual([label for _v, label in found], ["DATABASE_URL"])

    def test_masking_leaves_nothing_behind(self):
        for content in (self.ENV, json.dumps({"stdout": self.ENV})):
            path = _transcript(content)
            with self.subTest(escaped=content.startswith("{")):
                scan_file(path, apply=True)
                self.assertNotIn("Xk9mPq2vRt7wLz", _read(path))
                self.assertNotIn("Xk9mPq2vRt7wLz", mask_for_display(content))


class MaskForDisplay(unittest.TestCase):

    SECRETS = [
        ("export STRIPE_KEY=%s && deploy" % STRIPE, STRIPE),
        ("aws configure set aws_access_key_id %s" % AKID, AKID),
        ("DB_PASSWORD=kzN8fJx2mQ4vB7nR5tY9wL3pZ6aS1dF0c2e= npm start",
         "kzN8fJx2mQ4vB7nR5tY9wL3pZ6aS1dF0c2e="),
        ("printf '%s' > key.pem" % PEM, PEM.strip()),
        ('curl -H "Authorization: Bearer %s" https://api.synth' % JWT, JWT),
        ("AWS_SECRET_ACCESS_KEY=%s aws s3 ls" % SLASH_KEYS[0], SLASH_KEYS[0]),
        ("psql postgresql://admin:sup3rS3cretPw@db:5432/app", "sup3rS3cretPw"),
    ]

    def test_the_raw_value_never_survives(self):
        for text, secret in self.SECRETS:
            with self.subTest(text=text[:40]):
                shown = mask_for_display(text)
                self.assertNotIn(secret, shown)
                self.assertIn("<%s>" % _hint(secret), shown)

    def test_the_rest_of_the_text_is_kept(self):
        shown = mask_for_display("export STRIPE_KEY=%s && deploy" % STRIPE)
        self.assertEqual(shown, "export STRIPE_KEY=<%s> && deploy" % _hint(STRIPE))
        shown = mask_for_display("psql postgresql://admin:sup3rS3cretPw@db:5432/app")
        self.assertEqual(shown, "psql postgresql://admin:<s…w>@db:5432/app")

    def test_every_value_and_every_occurrence(self):
        text = "A=%s B=%s again %s" % (STRIPE, AKID, STRIPE)
        shown = mask_for_display(text)
        self.assertNotIn(STRIPE, shown)
        self.assertNotIn(AKID, shown)
        self.assertEqual(shown.count("<%s>" % _hint(STRIPE)), 2)

    def test_a_secret_inside_another_is_masked_once(self):
        text = "DATABASE_URL=postgresql://u:pa55word11@h:5432/d"
        shown = mask_for_display(text)
        self.assertNotIn("pa55word11", shown)
        self.assertEqual(shown.count("<"), 1)

    def test_fixtures_and_placeholders_are_shown_as_they_are(self):
        for text in ("aws configure set aws_access_key_id AKIAIOSFODNN7EXAMPLE",
                     "API_KEY=your-api-key-here npm start",
                     "export TOKEN=${MY_SECRET} && run",
                     "const token = process.env.API_TOKEN",
                     "ls -la /usr/local/bin/node",
                     "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----",
                     "", "short"):
            with self.subTest(text=text):
                self.assertEqual(mask_for_display(text), text)

    def test_masking_twice_changes_nothing(self):
        for text, _secret in self.SECRETS:
            once = mask_for_display(text)
            with self.subTest(text=text[:40]):
                self.assertEqual(mask_for_display(once), once)
                self.assertEqual(find_secrets(once + PAD), [])

    def test_same_rules_as_find_secrets(self):
        """Exactly what find_secrets reports is replaced, and nothing else."""
        text = "\n".join(t for t, _s in self.SECRETS) + "\nNODE_ENV=production"
        expected = text
        for value, _label in find_secrets(text):
            expected = expected.replace(value, "<%s>" % _hint(value))
        self.assertEqual(mask_for_display(text), expected)
        self.assertEqual(len(find_secrets(text)), len(self.SECRETS))


if __name__ == "__main__":
    unittest.main(verbosity=2)
