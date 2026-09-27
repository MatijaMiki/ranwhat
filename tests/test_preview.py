"""What a finding looks like in the preview, and which findings reach it.

The preview line `* token  …  10 chars  read from .environ.get` was three
bugs at once: an empty hint, `token = args.token` reported as a secret, and
os.environ read as a credential file. Every value here is synthetic.
"""
# Token-shaped fixtures are written as adjacent literals ("sk_" "live_...")
# so a secret scanner reading this source, GitHub push protection among
# them, does not take a fixture for a leak. Python joins them at compile
# time; the value under test is unchanged.

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ranwhat.clean import _hint, _is_member_access, _origins, find_secrets, scan_file

# find_secrets skips strings shorter than any credential shape, so a short
# line on its own would pass for the wrong reason.
PAD = "\n# padding so the text clears the minimum scan length"


def n(text):
    return len(find_secrets(text + PAD))


def _scan(body):
    d = tempfile.mkdtemp(prefix="preview-")
    path = os.path.join(d, "s.jsonl")
    with open(path, "w") as fh:
        fh.write(json.dumps({"type": "user", "message": {"content": [
            {"type": "tool_result", "content": body}]}}) + "\n")
    findings, _changed = scan_file(path, apply=False)
    return list(findings.values())


class ShortSecretHints(unittest.TestCase):

    def test_a_ten_character_secret_has_a_hint(self):
        found = _scan("TOKEN=Zq7Kp2Wx9v\n")
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["length"], 10)
        self.assertEqual(found[0]["hint"], "Z…")

    def test_the_hint_never_gives_away_a_meaningful_part(self):
        alphabet = "Zq7Kp2Wx9vB4mN8rT1yL3sD6fH0jG5cV"
        for size in range(1, 300):
            value = (alphabet * 10)[:size]
            hint = _hint(value)
            with self.subTest(size=size, hint=hint):
                self.assertNotIn(hint, ("", "…"))
                if size < 8:
                    self.assertFalse(any(c in alphabet for c in hint))
                    continue
                head, _, tail = hint.partition("…")
                self.assertTrue(value.startswith(head) and value.endswith(tail))
                self.assertGreaterEqual(len(head), 1)
                self.assertLessEqual(len(head) + len(tail), max(1, size // 6))

    def test_short_session_secret_is_still_reported_with_a_small_hint(self):
        # Mixed case and short is what a real session secret can look like,
        # so it stays a finding; only its hint shrinks.
        found = _scan("SESSION_SECRET=aB3xY9kL2mN8pQsT\n")
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["hint"], "a…T")

    def test_the_fingerprint_is_not_the_hint(self):
        found = _scan("TOKEN=Zq7Kp2Wx9vB4mN8rT1yL3sD6\n")
        self.assertNotIn(found[0]["fingerprint"], found[0]["hint"])


class KeyIdHints(unittest.TestCase):
    """A sixth of an AWS key ID is its fixed prefix, so two different key
    IDs both showed as AK…B. A key ID is not a secret on its own, so it
    shows its prefix and last four, as `aws configure list` does."""

    def test_two_key_ids_can_be_told_apart(self):
        self.assertEqual(_hint("AKIA4TRUE7KEYX9QZ2WB"), "AKIA…Z2WB")
        self.assertEqual(_hint("AKIA4TRUE7KEYX9QZ2WY"), "AKIA…Z2WY")
        self.assertEqual(_hint("ASIA2SYNTH7KEY3QZ5WB"), "ASIA…Z5WB")

    def test_the_hint_reaches_the_report(self):
        found = _scan("AWS_ACCESS_KEY_ID=AKIA4TRUE7KEYX9QZ2WB\n")
        self.assertEqual([f["hint"] for f in found], ["AKIA…Z2WB"])

    def test_other_values_keep_their_budget(self):
        # the secret half of the pair, and anything that only starts like
        # a key ID, still get a sixth
        self.assertEqual(_hint("wJq7Zk2WpX9vRt4mN8bL1yTsD6fH0jG5cVa3Ke9U"), "wJq…9U")
        self.assertEqual(_hint("AKIA4TRUE7KEYX9QZ2WBextra"), "AK…ra")
        self.assertEqual(_hint("sk_" "live_4eC39HqLyjWDarjtT1zdp7dc"), "sk_…dc")


# Code that reads a secret out of a variable, not the secret itself.
MEMBER_ACCESS = [
    "token = args.token",
    'token = args.token or os.environ.get("SYNTH_TOKEN")',
    "token = resp.token",
    "token: user.token,",
    "token: body.token",
    "password = user.password",
    "apiKey: config?.apiKey",
    "const token = req.headers.authorization",
    "let token = res.data.token",
    "token = creds.access_token",
    "f(token=args.token)",
]

# Literals, some of them dotted, some weak -- a weak password is still live.
LITERALS = [
    "DB_PASSWORD=kzN8fJx2mQ4vB7nR5tY9wL3pZ6aS1dF0c2e=",
    "SESSION_SECRET=be1c4f7a9d2e6b8c0f3a5d7e9b1c4f6a8d0e2b5c7f9a1d3e6b8c0f2a4d5e6",
    "APP_KEY=base64:Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MGFiY2RlZmdoaQ==",
    "RENDER_API_KEY=zGK7pQ2mV9xR4tN8wL1bY6cF3jH5dS0aE60",
    "TURNSTILE_SECRET=0x4AAAAAAABkMYinukE8nzYSjRt2wLpF3Lc",
    "AWS_ACCESS_KEY_ID=AKIA4TRUE7KEYX9QZ2WB",
    "DATABASE_URL=postgresql://buzz:Xk9mPq2vRt7@db.internal:5432/app",
    "PUSHER_APP_SECRET=b99f3c1e7a5d2b8f4c6e0a9d1b3f5c7e9a2d4f6b8c0e1a3d5f7b9c2e4f0a",
    "token = Zq7Kp2Wx9v",
    "token = 'Zq7Kp2Wx9v'",
    'password = "correct.horse.battery"',
    '"token": "user.token"',
    "DB_PASSWORD=correct.horse.battery",
    "API_TOKEN=args.token",
    "password: correct.horse.battery",
    "db_password = hunter.sunset.river",
    "token = quick.brown.fox",
    "token = oauth2.token",
    "token = Zq7Kp.Wx9vB",
    "token = eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJzeW50aCJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJVadQssw5c",
    "token = eyJhbGciOiJIUzIbNiJ.eyJzdWIiOiJzeWbaCJ.SflKxwRJSMeKKFQTfwpMeJfPOkyJVadQsswc",
    # not an alphabet run: that is a documentation fixture, see test_fixtures.py
    "apiKey = SG.q7Zk2WpX9vRt4mN8bL1yTs.D6fH0jG5cVa3Ke9Uw2Qo7Ri4",
    "token = MTA0NjQ4NzU2MzQ1NjM0.GhJkLm.aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456",
    # the last word only contains a secret word: monKEY, PASSport, AUTHor
    "password: Summer.Monkey",
    "password: Iloveyou.Monkey",
    "password = Blue.Whiskey",
    "pwd: Sunny.Turkey",
    "db_password = Red.Hockey",
    "password: Hunter.Passport",
    "password=Dragon.Jockey",
    "db.password=Summer.Monkey",                     # Java .properties
    "spring.datasource.password=Winter.Donkey",
    "password = Admin.Password",
    "secret: Purple.Compass",
    "token: Zebra.Keystone",
    "password: Correct.Horse.Author",
    "api_key: Quiet.River.Bypass",
    "password: Blue$ky.Pass",
    "password: Tiger.Sapphire.Passkey",
    "auth_token: kQzXvB.pWmRtY.nLsKey",
    "password: summer.monkey",
    "token: quiet.river.bypass",
    "password: tiger.sapphire.passkey",
]


class MemberAccessIsCode(unittest.TestCase):

    def test_reading_a_variable_is_not_a_secret(self):
        for text in MEMBER_ACCESS:
            with self.subTest(text=text):
                self.assertEqual(n(text), 0)

    def test_literals_are_still_secrets(self):
        for text in LITERALS:
            with self.subTest(text=text):
                self.assertEqual(n(text), 1)

    def test_literals_never_reach_the_member_access_rule(self):
        """Pinned on the rule itself, so an entropy or placeholder change
        elsewhere cannot make the list above pass for the wrong reason."""
        cases = [("password", "", "summer.monkey"), ("token", "", "quiet.river.bypass"),
                 ("password", "", "tiger.sapphire.passkey"),
                 ("password", "", "Summer.Monkey"), ("password", "", "Blue$ky.Pass"),
                 ("auth_token", "", "kQzXvB.pWmRtY.nLsKey"),
                 ("API_TOKEN", "", "args.token"), ("token", '"', "user.token"),
                 ("token", "", "oauth2.token"),
                 ("token", "", "eyJhbGciOiJIUzIbNiJ.eyJzdWIiOiJzeWbaCJ.sflKxwRJSMeKKFQTfwpMeJfPOkyJVadQsswc")]
        for key, quote, value in cases:
            with self.subTest(value=value):
                self.assertFalse(_is_member_access(key, quote, value))


class OriginOfThePreviewLine(unittest.TestCase):

    def test_environment_reads_in_code_are_not_files(self):
        for text in ('token = args.token or os.environ.get("X")',
                     "key = process.env.API_KEY",
                     "k = import.meta.env.VITE_KEY",
                     "k = Deno.env.get('K')"):
            with self.subTest(text=text):
                self.assertEqual(_origins(text), [])

    def test_a_real_env_file_is_still_named(self):
        self.assertEqual(_origins("cat api/.env"), ["api/.env"])

    def test_the_whole_preview_line_is_gone(self):
        body = ('    token = args.token or os.environ.get("SYNTH_TOKEN")\n'
                '    creds = load(Path("~/.config/app/credentials"))\n')
        self.assertEqual(_scan(body), [])

    def test_a_real_key_beside_os_environ_is_not_credited_to_it(self):
        body = ('key = os.environ.get("AWS_ACCESS_KEY_ID")\n'
                "AWS_ACCESS_KEY_ID=AKIA4TRUE7KEYX9QZ2WB\n")
        found = _scan(body)
        self.assertEqual(len(found), 1)
        self.assertFalse(any("environ" in o for o in found[0]["origins"]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
