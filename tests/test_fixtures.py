"""Documentation examples and test fixtures are not leaked credentials.

AWS's documentation key, a test file's AKIA1234567890ABCDEF and an alphabet
typed after sk_live_ were reported as live leaks by both clean and watch. The
fix must not buy that precision by hiding a real key, so most of this file
pins the other direction: real-format keys, human passwords, and deliberate
attempts to dress a real key up as a fixture all stay flagged.

Every value here is synthetic, or a published vendor documentation example.
"""
# Token-shaped fixtures are written as adjacent literals ("sk_" "live_...")
# so a secret scanner reading this source, GitHub push protection among
# them, does not take a fixture for a leak. Python joins them at compile
# time; the value under test is unchanged.

import json
import os
import random
import string
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ranwhat import clean, fixtures, watch
from ranwhat.fixtures import fixture_reason

B32 = string.ascii_uppercase + "234567"
B62 = string.ascii_letters + string.digits
B64URL = B62 + "-_"
HEX = "0123456789abcdef"

# A Stripe-shaped body used across the suite. Not a published live value.
REAL24 = "4eC39HqLyjWDarjtT1zdp7dc"
# The README's worked example: contains 9, which a real key ID cannot, and
# must still be reported.
REAL_AKIA = "AKIA4TRUE7KEYX9QZ2WB"


def rnd(rng, alphabet, k):
    return "".join(rng.choice(alphabet) for _ in range(k))


def n(text):
    return len(clean.find_secrets(text))


def literal_hits(command):
    hits, _ = watch.evaluate("Bash", {"command": command})
    return [h for h in hits if h["rule"] == "secret.literal"]


_RNG = random.Random(20260926)
GHP36 = rnd(_RNG, B62, 36)
SLACK = "xox" "b-%s-%s-%s" % (rnd(_RNG, string.digits, 12),
                           rnd(_RNG, string.digits, 13), rnd(_RNG, B62, 24))
AWS_RANDOM = "AKIA" + rnd(_RNG, B32, 16)
# The run QHGFEDCBA sits in the account-ID-encoded part of the key ID.
AWS_ACCOUNT_RUN = "AKIAQHGFEDCBA" + rnd(_RNG, B32, 7)
RANDOM32 = rnd(_RNG, B62, 32)
AWS_SECRET40 = rnd(_RNG, B62, 1) + rnd(_RNG, B62 + "/+", 39)
PEM = ("-----BEGIN RSA PRIVATE KEY-----\n%s\n-----END RSA PRIVATE KEY-----"
       % rnd(_RNG, B62 + "+/", 64))


KNOWN_FIXTURES = {
    "AKIA" "IOSFODNN7EXAMPLE": "published documentation example",
    "akiaiosfodnn7example": "published documentation example",
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY": "published documentation example",
    "AKIA" "I44QH8DHBEXAMPLE": "published documentation example",
    "je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY": "published documentation example",
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEKEY9": "EXAMPLE marker",
    "AKIA" "1234567890ABCDEF": "sequential run",
    "AKIA" "1234567890ABCDEF.": "sequential run",
    "sk_" "live_51HxAbCdEfGhIjKlMnOpQr": "sequential run",
    "sk_" "live_51HxAbCdEfGhIjKlMnOpQrStUv": "sequential run",
    "sk_" "live_aBcDeFgHiJkLmNoPqRsTuVwX": "sequential run",
    "gh" "p_aBcDeFgHiJkLmNoPqRsTuVwXyZ012345": "sequential run",
    "gh" "p_" + "Ab12" * 9: "repeated chunk",
    "my_example_token_9f8e7d": "placeholder wording",
    "xox" "b-1234567890-1234567890123-aBcDeFgHiJkLmNoPqRsTuVwX": "sequential run",
    "sk_" "live_ENVSECRET_xyz789": "placeholder name",
    "rk_" "live_TEST_KEY_abc123": "placeholder name",
    "gh" "p_YOUR_TOKEN_1": "placeholder name",
    "xox" "b-YourBotToken_here": "placeholder name",
    # Stripe's own documentation test keys, the current one and the one
    # before it, and an alphabet in test mode as in live.
    "sk_" "test_4eC39HqLyjWDarjtT1zdp7dc": "published documentation example",
    "sk_" "test_BQokikJOvBiI2HlWgH4olfQ2": "published documentation example",
    "sk_" "test_51ABCDEFGHIJKLMNOPQRSTUVWXYZ": "sequential run",
    "rk_" "test_aBcDeFgHiJkLmNoPqRsTuVwX": "sequential run",
    "sk_" "test_YOUR_SECRET_KEY": "placeholder name",
}


class Predicate(unittest.TestCase):

    def test_reasons_for_known_fixtures(self):
        cases = KNOWN_FIXTURES
        for value, reason in cases.items():
            self.assertEqual(fixture_reason(value), reason, value)
            self.assertTrue(fixtures.is_fixture(value), value)

    def test_real_shapes_are_not_fixtures(self):
        for value in (REAL_AKIA, "AKIA" "IOSFODNN7REALKEY", "sk_" "live_" + REAL24,
                      "gh" "p_" + GHP36, SLACK, AWS_RANDOM, AWS_ACCOUNT_RUN,
                      PEM, "sk_" "live_FAKEBODY1_abc456", ""):
            self.assertIsNone(fixture_reason(value), value)


class CleanStillFlags(unittest.TestCase):

    def test_real_format_keys(self):
        for text in ("AWS_ACCESS_KEY_ID=" + REAL_AKIA,
                     "AWS=AKIA" "IOSFODNN7REALKEY",
                     "export STRIPE_KEY=sk_" "live_" + REAL24 + " and done",
                     "GITHUB_TOKEN=gh" "p_" + GHP36,
                     PEM,
                     "AGENTSCAN_STRIPE_TOKEN=sk_" "live_FAKEBODY1_abc456",
                     "AWS_ACCESS_KEY_ID=" + AWS_ACCOUNT_RUN,
                     "STRIPE_SECRET_KEY=sk_" "test_" + RANDOM32[:24],
                     "STRIPE_SECRET_KEY=sk_" "test_" + REAL24 + "x",
                     "STRIPE_SECRET_KEY=sk_" "test_51" + RANDOM32 + RANDOM32):
            self.assertEqual(n(text), 1, text)

    def test_a_fixture_beside_a_real_key_hides_only_itself(self):
        found = clean.find_secrets(
            "fixture AKIA" "IOSFODNN7EXAMPLE and real %s" % AWS_RANDOM)
        self.assertEqual([v for v, _ in found], [AWS_RANDOM])

    def test_human_chosen_values_get_no_sequence_heuristics(self):
        for text in ("JWT_SECRET=abcdefghijklmnopqrstuvwxyz0123",
                     "DB_PASSWORD=Password123456789",
                     "DATABASE_URL=postgresql://app:abcd1234efgh5678@db.internal:5432/app",
                     "SESSION_SECRET=sk-abcdefghijklmnopqrstuvwxyz",
                     "OPENAI_API_KEY=sk-abcdefgh12345678wxyz9",
                     "LITELLM_API_KEY=sk-mycompany-abcdefgh-prod",
                     "PROXY_TOKEN=sk-Team7-12345678-Qz9x",
                     "echo sk-litellm-12345678-abcdefgh-k9Qz"):
            self.assertEqual(n(text), 1, text)

    def test_the_word_example_inside_a_human_password(self):
        for text in ("API_TOKEN=MyExample#2024Pass",
                     "DB_PASSWORD=Example_2024!",
                     "DB_PASSWORD=acme-example-prod-secret-8f7a9c",
                     "DB_PASSWORD=example.Prod.9f8e",
                     "API_TOKEN=prod_example_" + RANDOM32,
                     "AUTH_TOKEN=svc.example:" + RANDOM32,
                     "AWS_SECRET_ACCESS_KEY=" + AWS_SECRET40 + "EXAMPLE",
                     "AWS_SECRET_ACCESS_KEY=" + AWS_SECRET40[:30] + "EXAMPLEKEY"):
            self.assertEqual(n(text), 1, text)

    def test_connection_string_passwords_are_human_chosen(self):
        found = clean.find_secrets(
            'psql "postgresql://app:acme-example-prod-8f7a9c@db.internal/app"')
        self.assertEqual([label for _, label in found],
                         ["connection string password"])
        self.assertEqual(n("redis://default:Kx9#example-2024@cache:6379"), 1)

    def test_an_example_host_does_not_hide_the_url(self):
        found = clean.find_secrets(
            "DATABASE_URL=postgresql://admin:Xk9mPq2vRt7wQ@db.example.com:5432/app")
        self.assertEqual([label for _, label in found], ["DATABASE_URL"])

    def test_suffix_and_prefix_evasion(self):
        """Dressing a real key up as a fixture must not hide it."""
        s = "sk_" "live_" + REAL24
        for text in ("STRIPE=" + s + "EXAMPLE",
                     "STRIPE=" + s + "abcdefgh",
                     "STRIPE=" + s + "defghijk",       # continues from its last 'c'
                     "STRIPE=" + s + "T1zdp7dc",       # a copy of its own tail
                     "STRIPE=" + s + "cccccccc",
                     "STRIPE=sk_" "live_" + REAL24[:-1] + "E" + "XAMPLE",
                     "STRIPE=sk_" "live_" + REAL24[:8] + REAL24,
                     "STRIPE=sk_" "live_" + REAL24[:8] * 2 + REAL24,
                     "GITHUB_TOKEN=gh" "p_" + GHP36 + GHP36[-8:],
                     "SLACK_BOT_TOKEN=" + SLACK + "-EXAMPLE",
                     "token " + SLACK + "-abcdefghijkl here",
                     "token " + SLACK + "-00000000000 here"):
            self.assertEqual(n(text), 1, text)

    def test_a_rejected_shape_does_not_swallow_the_next_key(self):
        """AKIA+16 is fixed length, so a fixture glued to a real key would
        otherwise consume the real key's AKIA."""
        for prefix in ("AKIAABCDEFGH", "AKIAEXAMPLE12", "AKIA1234567890ABCDE"):
            self.assertGreaterEqual(n("key %s%s here" % (prefix, REAL_AKIA)), 1, prefix)
        found = clean.find_secrets("key AKIA1234567890ABCDE%s here" % REAL_AKIA)
        self.assertIn(REAL_AKIA, [v for v, _ in found])

    def test_every_value_the_existing_suite_calls_real(self):
        for text in ("DB_PASSWORD=kzN8fJx2mQ4vB7nR5tY9wL3pZ6aS1dF0c2e=",
                     "SESSION_SECRET=be1c4f7a9d2e6b8c0f3a5d7e9b1c4f6a8d0e2b5c7f9a1d3e6b8c0f2a4d5e6",
                     "APP_KEY=base64:Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MGFiY2RlZmdoaQ==",
                     "RENDER_API_KEY=zGK7pQ2mV9xR4tN8wL1bY6cF3jH5dS0aE60",
                     "AWS_ACCESS_KEY_ID=AKIA4TRUE7KEYX9QZ2WB",
                     "TURNSTILE_SECRET=0x4AAAAAAABkMYinukE8nzYSjRt2wLpF3Lc",
                     "DATABASE_URL=postgresql://buzz:Xk9mPq2vRt7@db.internal:5432/app"):
            self.assertEqual(n(text), 1, text)


class CleanIgnoresFixtures(unittest.TestCase):

    def test_documentation_examples(self):
        for text in ("AWS_ACCESS_KEY_ID=AKIA" "IOSFODNN7EXAMPLE",
                     "AWS_ACCESS_KEY_ID=akiaiosfodnn7example",
                     "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                     "Qk AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEKEY9",
                     "AWS_ACCESS_KEY_ID=AKIAI44QH8DHBEXAMPLE",
                     "AWS_SECRET_ACCESS_KEY=je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY",
                     "aws_access_key_id = AKIA" "IOSFODNN7EXAMPLE\n"
                     "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"):
            self.assertEqual(n(text), 0, text)

    def test_test_fixtures(self):
        for text in ("key AKIA1234567890ABCDEF here",
                     "AWS_ACCESS_KEY_ID=AKIA1234567890ABCDEF",
                     "API_KEY=AKIA1234567890ABCDEF.",
                     "STRIPE=sk_" "live_51HxAbCdEfGhIjKlMnOpQr",
                     "STRIPE=sk_" "live_51HxAbCdEfGhIjKlMnOpQrStUv",
                     "STRIPE=sk_" "live_aBcDeFgHiJkLmNoPqRsTuVwX",
                     "GITHUB_TOKEN=gh" "p_aBcDeFgHiJkLmNoPqRsTuVwXyZ012345",
                     "GITHUB_TOKEN=gh" "p_" + "Ab12" * 9,
                     "SLACK_BOT_TOKEN=xox" "b-1234567890-1234567890123-aBcDeFgHiJkLmNoPqRsTuVwX",
                     "API_TOKEN=my_example_token_9f8e7d"):
            self.assertEqual(n(text), 0, text)


# A fixture was silent or reported depending on the name beside it:
# "sk_" "live_ENVSECRET_xyz789" under STRIPE_KEY, which names no secret, went
# unreported, and under STRIPE_API_KEY it was a critical leak.
KEY_NAMES = ("STRIPE_KEY", "STRIPE_SECRET_KEY", "STRIPE_API_KEY", "STRIPE_SECRET",
             "API_TOKEN", "SECRET", "password", "client_secret", "apiKey",
             "auth_token", "private_key", "DSN", "DB_PASSWORD", "SECRET_KEY",
             "AWS_ACCESS_KEY_ID")
SYNTAXES = (lambda k, v: "%s=%s" % (k, v),
            lambda k, v: "export %s=%s && node app.js" % (k, v),
            lambda k, v: "%s: %s" % (k, v),
            lambda k, v: "%s='%s'" % (k, v),
            lambda k, v: json.dumps({k: v}))


class FixturesUnderAnyKeyName(unittest.TestCase):

    def test_every_recognised_fixture_is_silent_under_every_key(self):
        for value in KNOWN_FIXTURES:
            for key in KEY_NAMES:
                for syntax in SYNTAXES:
                    text = syntax(key, value)
                    with self.subTest(text=text):
                        self.assertEqual(clean.find_secrets(text), [])
                        self.assertEqual(literal_hits(text), [])

    def test_a_name_after_a_prefix_hides_only_a_name(self):
        """None of these providers issues an underscore in its body, so the
        value is not its key. It is still reported when a digit says the part after
        the prefix could be generated, when enough is left over to be a
        secret of its own, or when a whole key sits in front of the name."""
        for value in ("sk_" "live_FAKEBODY1_abc456",
                      "sk_" "live_ENVSECRET1_xyz789",
                      "sk_" "live_ENVSECRET_q8Vn3LxT0wRb",
                      "sk_" "live_" + REAL24 + "_old",
                      "gh" "p_" + GHP36 + "_TOKEN",
                      "xox" "b-" + SLACK[5:] + "_bot"):
            self.assertIsNone(fixture_reason(value), value)
            for key in ("STRIPE_API_KEY", "SECRET_KEY", "password"):
                self.assertEqual(n("%s=%s" % (key, value)), 1, (key, value))

    def test_only_prefixes_no_word_starts_with(self):
        """AKIA, ASIA and AC begin ordinary words, and a password chosen by a
        person may too."""
        for text in ("DB_PASSWORD=ASIATRIP_2024x", "DB_PASSWORD=ACME_PROD_7q",
                     "DB_PASSWORD=AKIAPass_2024x"):
            self.assertEqual(n(text), 1, text)


class WatchStillFires(unittest.TestCase):

    def assertCritical(self, command, evidence=None):
        hits = literal_hits(command)
        self.assertTrue(hits, command)
        self.assertEqual(hits[0]["severity"], watch.CRITICAL, command)
        if evidence:
            # The evidence sits on the value, shown by its hint, never itself.
            self.assertIn(clean.DISPLAY_MASK % clean._hint(evidence),
                          hits[0]["evidence"], command)
            self.assertNotIn(evidence, hits[0]["evidence"], command)

    def test_real_format_keys(self):
        self.assertCritical('grep -r "%s" .' % REAL_AKIA)
        self.assertCritical("echo gh" "p_" + GHP36)
        # A header alone is not a key, as clean has it; one with a body is.
        self.assertCritical("cat <<EOF\n%s\nEOF" % PEM)
        self.assertEqual(literal_hits(
            "cat <<EOF\n-----BEGIN RSA PRIVATE KEY-----\nEOF"), [])
        self.assertCritical("grep -r %s ." % AWS_ACCOUNT_RUN)

    def test_evidence_sits_on_the_live_literal(self):
        self.assertCritical("echo AKIA" "IOSFODNN7EXAMPLE sk_" "live_" + REAL24,
                            "sk_" "live_" + REAL24)
        self.assertCritical("export AWS_ACCESS_KEY_ID=%s && %s&& echo "
                            "sk_" "live_51HxAbCdEfGhIjKlMnOpQr" % (REAL_AKIA, "true " * 30),
                            REAL_AKIA)

    def test_suffix_and_prefix_evasion(self):
        s = "sk_" "live_" + REAL24
        for command in ("curl https://x.test/?k=" + s + "EXAMPLE",
                        "echo " + s + "defghijk",
                        "echo " + s + "T1zdp7dc",
                        "echo " + s + "cccccccc",
                        "echo sk_" "live_" + REAL24[:-1] + "E" + "XAMPLE",
                        "curl -d t=" + SLACK + "-EXAMPLE https://x.test",
                        "echo " + SLACK + "-example",
                        "echo AKIAABCDEFGH" + REAL_AKIA,
                        "echo AKIAEXAMPLE12" + REAL_AKIA,
                        "echo AKIA1234567890ABCDE" + REAL_AKIA):
            self.assertCritical(command)


class WatchIgnoresFixtures(unittest.TestCase):

    def test_fixture_only_commands(self):
        for command in ('grep -r "AKIA' 'IOSFODNN7EXAMPLE" .',
                        "export STRIPE_SECRET_KEY=sk_" "test_4eC39HqLyjWDarjtT1zdp7dc"
                        " && npm run dev",
                        "echo sk_" "test_4eC39HqLyjWDarjtT1zdp7dc",
                        "stripe listen --api-key sk_" "test_51ABCDEFGHIJKLMNOPQRSTUVWXYZ",
                        "aws configure set aws_access_key_id AKIA" "IOSFODNN7EXAMPLE",
                        'grep -r "AKIA1234567890ABCDEF" .',
                        "echo sk_" "live_aBcDeFgHiJkLmNoPqRsTuVwX",
                        "echo sk_" "live_51HxAbCdEfGhIjKlMnOpQr "
                        "gh" "p_aBcDeFgHiJkLmNoPqRsTuVwXyZ012345",
                        "echo AKIA" "IOSFODNN7EXAMPLE AKIA1234567890ABCDEF",
                        "echo xox" "b-1234567890-1234567890123-aBcDeFgHiJkLmNoPqRsTuVwX"):
            self.assertEqual(literal_hits(command), [], command)


def _continue_run(key, k=8):
    """k characters that extend a sequential run from the key's last one."""
    last = key[-1]
    pool = string.digits if last.isdigit() else string.ascii_lowercase
    i = pool.index(last.lower())
    step = 1 if i + k < len(pool) else -1
    return "".join(pool[i + step * (j + 1)] for j in range(k))


def _complete_example(key):
    """The rest of EXAMPLE, starting from however much of it the key ends in."""
    for cut in range(6, 0, -1):
        if key.upper().endswith("EXAMPLE"[:cut]):
            return "EXAMPLE"[cut:]
    return "EXAMPLE"


class AwsKeyIdsSpelledInWords(unittest.TestCase):
    """A key ID with words where its random body goes. Letters only, they
    stopped reading as a variable name, and EXAMPLE counts only past body
    character 8, where the account ID stops: on a working machine the one
    new finding was such a placeholder, AKIA…LEEX."""

    VALUES = ("AKIA" "EXAMPLEEXAMPLEEX", "AKIA" "FAKEFAKEFAKEFAKE",
              "AKIA" "TESTTESTTESTTEST", "AKIA" "YOURACCESSKEYIDX",
              "AKIA" "EXAMPLEKEYEXAMPL", "ASIA" "EXAMPLEEXAMPLEEX",
              "AKIA" "EXAMPLEXXXXXXXXX")

    def test_a_fixture(self):
        for value in self.VALUES:
            with self.subTest(value=value):
                self.assertIsNotNone(fixture_reason(value))

    def test_silent_in_clean_and_watch(self):
        for text in ("AWS_ACCESS_KEY_ID=AKIA" "EXAMPLEEXAMPLEEX",
                     "AWS_ACCESS_KEY_ID=AKIA" "FAKEFAKEFAKEFAKE",
                     "AWS_ACCESS_KEY_ID=AKIA" "TESTTESTTESTTEST",
                     "AWS_ACCESS_KEY_ID=AKIA" "YOURACCESSKEYIDXX",
                     "AWS_ACCESS_KEY_ID=AKIA" "EXAMPLEKEYEXAMPLE",
                     "aws configure set aws_access_key_id AKIA" "FAKEFAKEFAKEFAKE"):
            with self.subTest(text=text):
                self.assertEqual(n(text), 0)
                self.assertEqual(literal_hits(text), [])

    def test_random_letters_are_no_words(self):
        rng = random.Random(13)
        for _ in range(RandomKeysAreNeverFixtures.N):
            value = "AKIA" + rnd(rng, string.ascii_uppercase, 16)
            self.assertIsNone(fixture_reason(value), value)
        # EXAMPLE alone where the account ID goes leaves the rest a key
        value = "AKIAEXAMPLE" + rnd(rng, B32, 9)
        self.assertIsNone(fixture_reason(value), value)


class RandomKeysAreNeverFixtures(unittest.TestCase):
    """The arithmetic in fixtures.py says a random key trips a signal with
    probability around 1e-9. Seeded, so a failure reproduces."""

    N = 4000

    def test_random_provider_keys(self):
        rng = random.Random(7)
        makers = [
            lambda: "AKIA" + rnd(rng, B32, 16),
            lambda: "ASIA" + rnd(rng, B32, 16),
            lambda: "sk_" "live_" + rnd(rng, B62, 24),
            lambda: "sk_" "live_51" + rnd(rng, B62, 97),
            lambda: "sk_" "test_" + rnd(rng, B62, 24),
            lambda: "rk_" "test_51" + rnd(rng, B62, 97),
            lambda: "gh" "p_" + rnd(rng, B62, 36),
            lambda: "sk-ant-api03-" + rnd(rng, B64URL, 95),
            lambda: "sk-" + rnd(rng, HEX, 32),
            lambda: "AC" + rnd(rng, HEX, 32),
            lambda: "xox" "b-%s-%s-%s" % (rnd(rng, string.digits, 11),
                                       rnd(rng, string.digits, 13), rnd(rng, B62, 24)),
            lambda: "xoxp-%s-%s-%s-%s" % (rnd(rng, string.digits, 11),
                                          rnd(rng, string.digits, 11),
                                          rnd(rng, string.digits, 13), rnd(rng, HEX, 32)),
        ]
        for make in makers:
            for _ in range(self.N):
                value = make()
                self.assertIsNone(fixture_reason(value), value)

    def test_adversarial_dressing_of_random_keys(self):
        rng = random.Random(11)
        for _ in range(self.N // 4):
            for prefix, body in (("sk_" "live_", rnd(rng, B62, 24)),
                                 ("gh" "p_", rnd(rng, B62, 36))):
                key = prefix + body
                dressed = [key + _continue_run(body), key + _complete_example(body),
                           key + body[-1] * 8, prefix + body[:8] + body,
                           prefix + body[:8] * 2 + body]
                dressed += [key + body[-k:] for k in range(1, 9)]
                for value in dressed:
                    self.assertIsNone(fixture_reason(value), value)


class StaysLinear(unittest.TestCase):

    def test_watch_on_a_command_full_of_fixtures(self):
        command = ("echo AKIA1234567890ABCDEF sk_" "live_51HxAbCdEfGhIjKlMnOpQr " * 1200)[:64000]
        t = time.perf_counter()
        self.assertEqual(literal_hits(command), [])
        self.assertLess(time.perf_counter() - t, 1.0)

    def test_clean_on_a_megabyte_of_fixtures(self):
        text = ("AKIA1234567890ABCDEF gh" "p_" + "Ab12" * 9 + "\n") * 16000
        t = time.perf_counter()
        self.assertEqual(clean.find_secrets(text), [])
        self.assertLess(time.perf_counter() - t, 3.0)

    def test_long_bodies_skip_statistics_and_stay_flagged(self):
        self.assertIsNone(fixture_reason("sk_" "live_" + "abcdefgh" * 100))


if __name__ == "__main__":
    unittest.main()
