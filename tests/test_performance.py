"""Speed regressions in a scanner are correctness regressions in practice:
a first run that takes ninety seconds on one file is a first run nobody
finishes. These pin the two fixes that took a 39MB transcript from 89s to 2s.
"""
import json
import os
import random
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

from ranwhat import catalog, clean, feed, score

# What a quadratic pattern costs here is seconds (10s to 24s on the shapes
# below before the fix), so the budget only has to sit well under that. At
# 50ms it failed on a loaded machine while the full suite ran, which on CI
# is a red build for nothing. 0.5s still catches every regression these
# exist for by a factor of twenty.
BUDGET = 0.5


class Linear(unittest.TestCase):
    def test_origin_scan_does_not_go_quadratic_on_prose(self):
        """_ORIGIN rescans forward from every position on long word runs. 16k
        characters used to cost 1.7s; the literal prefilter makes it free."""
        text = "a" * 50000
        t = time.perf_counter()
        clean._origins(text)
        self.assertLess(time.perf_counter() - t, BUDGET)

    def test_origins_still_found_when_a_marker_is_present(self):
        self.assertIn("~/.ssh/id_rsa", clean._origins("then cat ~/.ssh/id_rsa here"))
        self.assertIn("api/.env", clean._origins("read api/.env"))

    def test_origins_skip_templates(self):
        self.assertEqual(clean._origins("cp .env.example .env.example"), [])

    def test_origin_scan_is_linear_when_a_marker_is_present(self):
        """The prefilter only helps lines with no marker, and ".key" or "id_"
        is in most lines of code. The old pattern took 10s on the first
        shape, 24s on the second and 17s on the base64 one. The b.env-c
        shape catches a stem and a suffix loop nested in one alternative."""
        shapes = [
            "cat .env " + "a" * 50000,
            "cat .env " + "a/" * 25000,
            "x.key " + "a." * 25000,
            "x a/" + "b.env-c" * 7000 + "/",
            "id_rsa " + "Ab3_cD-eF9" * 5000,
            "x " + "a\\" * 25000 + ".key",
            "x " + "a/\\" * 20000,
            "\\nhttp:" + "\\\\n" * 15000 + ".env",     # escaped \\ before n
            "cat " * 12500 + "x.key",
            " -a" * 16000 + " x.key",
            "'a.a.a" * 8000 + ".key",
        ]
        for text in shapes:
            with self.subTest(text=text[:24]):
                t = time.perf_counter()
                clean._origins(text)
                self.assertLess(time.perf_counter() - t, BUDGET)

    def test_a_very_long_path_still_resolves(self):
        text = " " + "a/" * 100000 + ".env"
        t = time.perf_counter()
        found = clean._origins(text)
        self.assertLess(time.perf_counter() - t, BUDGET)
        self.assertEqual(len(found), 1)
        self.assertTrue(found[0].endswith("/.env"))

    def test_a_long_json_line_of_code_is_fast_and_honest(self):
        line = 'x = d.key; cat api/.env; os.environ.get("K")\n' * 1100
        text = json.dumps({"c": line})
        t = time.perf_counter()
        found = clean._origins(text)
        self.assertLess(time.perf_counter() - t, BUDGET)
        self.assertEqual(set(found), {"api/.env"})


class OriginOfAResult(unittest.TestCase):
    KEY = "AKIA" "4TRUE7KEYX9QZ2WB"  # synthetic, as in tests/test_origins.py

    def test_a_value_repeated_along_one_long_line_is_cheap(self):
        """A result whose call named no file is credited by the grep prefix
        on the secret's own line. Looking back from every copy of the value
        for the start of its line was quadratic on one long line."""
        text = ("AWS_ACCESS_KEY_ID=%s " % self.KEY) * 20000
        self.assertIsNone(self._origin(text))

    def test_grep_prefixes_are_still_read(self):
        text = "x.py:1:y\n" * 5000 + "api/.env:3:AWS_ACCESS_KEY_ID=%s\n" % self.KEY
        self.assertEqual(self._origin(text), "api/.env")

    def _origin(self, text):
        """The grep origin of the one secret in text, timed."""
        (value, _label, copies), = clean._scan(text, spans=False, where=True)[0]
        self.assertEqual(value, self.KEY)
        t = time.perf_counter()
        origin = clean._GrepLines(text).origin(copies)
        self.assertLess(time.perf_counter() - t, BUDGET)
        return origin

    def test_a_command_full_of_shift_operators_is_linear(self):
        command = "python3 -c 'print(1 << x)'\n" * 20000
        t = time.perf_counter()
        clean._without_heredocs(command)
        self.assertLess(time.perf_counter() - t, BUDGET)


class EmbeddedImages(unittest.TestCase):
    PNG = "iVBORw0KGgoAAAANSUhEUgAA" + "A" * 300000

    def test_embedded_png_is_not_scanned(self):
        t = time.perf_counter()
        self.assertEqual(clean.find_secrets(self.PNG), [])
        self.assertLess(time.perf_counter() - t, BUDGET)

    def test_image_data_cannot_produce_a_false_positive(self):
        """Random-looking base64 can contain an AKIA-shaped run by chance."""
        # Not AWS's documentation key: that is a fixture and would be dropped
        # anyway, so the test could no longer see the image skip regress.
        planted = "iVBORw0KGgo" + "Q" * 5000 + "AKIA4TRUE7KEYX9QZ2WB" + "Q" * 5000
        self.assertEqual(clean.find_secrets(planted), [])

    def test_short_text_starting_like_an_image_is_still_scanned(self):
        """Only long whitespace-free blobs count as images."""
        # Not an edited copy of AWS's documentation key: that is a fixture.
        text = "Qk AWS_SECRET_ACCESS_KEY=" + "q8Vn3LxT0wRb/Kd7Pz2mYh9Gc+J4sEf6Ua1NtW5r"
        self.assertTrue(clean.find_secrets(text))

    def test_real_secret_in_ordinary_text_still_found(self):
        text = "export STRIPE_KEY=sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc" + " and done"
        labels = [label for _, label in clean.find_secrets(text)]
        self.assertTrue(labels, "a live-shaped key in prose was missed")


class FeedLookups(unittest.TestCase):
    """lookup() asks providers() for the merged catalogue once per grant, and
    the merge floors every feed scope of that provider with _no_lower, in
    Python. Rebuilt on every call that was grants times feed entries: 300
    grants against a 17,000-entry feed (2.4 MB, well under feed.MAX_BYTES)
    took 2.2s here, against 0.08s before the floor existed."""

    ENTRIES = 17000
    GRANTS = 300

    def setUp(self):
        home = tempfile.mkdtemp(prefix="ranwhat-perf-")
        self.addCleanup(shutil.rmtree, home, True)
        patch = mock.patch.dict(os.environ, {"RANWHAT_HOME": home})
        patch.start()
        self.addCleanup(patch.stop)
        entry = {"label": "Fed", "authority": "write", "reversible": True,
                 "blast": "data_egress", "why": "a large test feed"}
        cat = {"aws": {"svc%d:Action%d" % (i, i): dict(entry)
                       for i in range(self.ENTRIES)}}
        feed.save({"schema": feed.SCHEMA, "version": "t", "catalogue": cat,
                   "digest": feed.digest(cat)})
        catalog.reset_feed_cache()
        self.addCleanup(catalog.reset_feed_cache)

    def test_a_scan_against_a_large_feed_is_not_grants_times_entries(self):
        profile = {"agent": "perf", "credentials": [{
            "provider": "aws",
            "scopes": ["svc%d:Action%d" % (i, i) for i in range(self.GRANTS)]}]}
        # Reading the cache is once per process, whatever the grants; the
        # lookups are what went quadratic.
        self.assertIsNotNone(catalog._feed_catalogue(), "the feed is not in use")
        t = time.perf_counter()
        result = score.scan(profile)
        self.assertLess(time.perf_counter() - t, BUDGET)
        self.assertEqual(len(result["scopes"]), self.GRANTS)
        self.assertTrue(all(r["label"] == "Fed" for r in result["scopes"]))


# A quadratic scan on a megabyte does not take seconds but minutes, and run
# in the suite it holds the whole run, and the machine, for as long. Each of
# these runs on its own interpreter and is stopped after HANG seconds, which
# fails the test. Only the call itself is timed, not the interpreter's start
# or building the input.
HANG = 20
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MB = 1000000


def _seconds(setup, call):
    script = "\n".join([
        "import json, random, string, time",
        "from ranwhat import clean, watch",
        "rnd = random.Random(7)",
        "def r(alphabet, n): return ''.join(rnd.choice(alphabet) for _ in range(n))",
        setup,
        "t = time.perf_counter()",
        call,
        "print(time.perf_counter() - t)"])
    try:
        run = subprocess.run([sys.executable, "-c", script], cwd=REPO,
                             capture_output=True, encoding="utf-8",
                             timeout=HANG)
    except subprocess.TimeoutExpired:
        raise AssertionError("still running after %ds" % HANG)
    if run.returncode:
        raise AssertionError(run.stderr)
    return float(run.stdout.split()[-1])


class OneMegabyteOfAdversarialInput(unittest.TestCase):
    """Inputs built to make a scanner read the rest of the text again for
    every token in it. Each must cost one pass, well under a second."""

    def assertLinear(self, cases, call="clean.find_secrets(text)"):
        for name, expr in cases:
            with self.subTest(case=name):
                seconds = _seconds("text = " + expr + "\nassert len(text) <= %d" % MB,
                                   call)
                self.assertLess(seconds, BUDGET)

    def test_a_query_string_of_secret_named_parameters(self):
        """Each parameter whose name marks a secret took a copy of the rest
        of the value before cutting it at the next & or #: 2.5 seconds on
        a megabyte of &pwd=a, against 0.06 before the cut existed."""
        self.assertLinear([
            ("&pwd=a", "'u=' + '&pwd=a' * 166666"),
            ("&pwd=", "'u=' + '&pwd=' * 199999"),
            ("&x_token=a", "'https://x/?' + '&x_token=a' * 99998"),
            ("&token=abcdefgh", "'u=' + '&token=abcdefgh' * 66666"),
            ("&token=x", "'v=' + '&token=x' * 124999"),
            ("&access_token=x", "'v=' + '&access_token=x' * 66666"),
            ("?access_token=", "'GET /cb?access_token=' + 'a' * 20 + '&refresh_token=x' * 62000"),
        ])

    def test_a_shape_tried_again_and_again(self):
        """A shape ruled a placeholder was tried again from just past its
        start, and with no fixed length every try read to the end of the
        run. A JWT's first part, and a private key's search for its END
        line, did the same inside one regex. Minutes, each."""
        self.assertLinear([
            ("xoxb-xxxxxx", "('xox' 'b-xxxxxx') * 90909"),
            ("sk-xxxxxx", "('sk' '-xxxxxx') * 111111"),
            ("github_pat_xxxxxx", "('github_' 'pat_xxxxxx') * 58823"),
            ("eyJ", "'eyJ' * 333333"),
            ("eyJ and dots", "'eyJaaaaaaaaaaa.' * 66666"),
            ("BEGIN with no END", "'-----BEGIN RSA PRIVATE" " KEY-----\\n' * 31250"),
            ("BEGIN PRIVATE KEY-", "'-----BEGIN PRIVATE KEY-' * 43478"),
            ("BEGIN lines, one END",
             "'-----BEGIN RSA PRIVATE" " KEY-----\\n' * 31000"
             " + '-----END RSA PRIVATE KEY-----'"),
        ])

    DISTINCT = [
        ("AWS key IDs",
         "' '.join('AKIA' + r('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567', 16)"
         " for _ in range(47000))"),
        ("JSON api_key_N",
         "json.dumps({'api_key_%d' % i: r(string.ascii_letters + string.digits, 24)"
         " for i in range(25000)})[:1000000]"),
        ("a password inside each URL",
         "'\\n'.join('DATABASE_URL=postgres://u:%s@h/d'"
         " % r(string.ascii_letters + string.digits, 32) for _ in range(15800))"),
    ]

    def test_a_command_full_of_shift_operators(self):
        """A << is a here-document only when its terminator follows, and
        each one with none was looked for to the end of the command. watch
        strips here-documents before it cuts a command to MAX_SCAN_CHARS,
        so the whole megabyte was read once per <<."""
        self.assertLinear([("<<EOF lines", "'<<EOF\\n' * 166666")],
                          call="watch._strip_heredocs(text)")
        self.assertLinear([("1 << x in python -c",
                            "\"python3 -c 'print(1 << x)'\\n\" * 37000")],
                          call="watch.evaluate('Bash', {'command': text})")

    def test_one_long_command(self):
        """watch reduces a shell command to what runs before it cuts it to
        MAX_SCAN_CHARS, so a here-document keeps the terminator that marks
        its body as data. shlex builds each word a character at a time, so
        a megabyte inside one quote took eleven seconds, and every segment
        went through it whatever it held."""
        self.assertLinear([
            ("an unclosed quote", "\"'\" + 'a ' * 499999"),
            ("escaped characters", "'\\\\a' * 500000"),
            ("pipes", "'a | ' * 250000"),
            ("lines", "'ls\\n' * 333333"),
            ("deletions", "'rm -rf a ; ' * 90909"),
            ("quoted words", "\"'a|b' | \" * 125000"),
            ("options before a message", "'git ' + '-a b ' * 199000 + 'commit -m \"x; y\"'"),
            ("pipes into a path", "'|' + '/a' * 499999"),
            ("filters given files", "\"jq '.a' x | \" * 83000"),
            ("pipes of both streams", "'cat x |& ' * 110000"),
        ], call="watch.evaluate('Bash', {'command': text})")

    def test_long_runs_of_blanks(self):
        """A command was split at its separators by a pattern that took any
        blanks before one, and from every blank in a long run it read on to
        the end of the run looking for one: sixty thousand blanks took
        seventeen seconds. Blanking what a command only writes turns
        `cat .env | tee` and thirty thousand file names into such a run."""
        self.assertLinear([
            ("one run", "'cat .env' + ' ' * 999990 + 'x'"),
            ("tee's files", "'cat .env | tee ' + 'a ' * 499990"),
            ("redirections", "'cat .env ' + '>a ' * 333330"),
            ("runs before separators", "('x' + ' ' * 4999 + ';') * 199"),
        ], call="watch.evaluate('Bash', {'command': text})")
        self.assertLinear([("a git push across a run",
                            "'git push' + ' ' * 999980 + ' -f'")],
                          call="watch._evidence(text, (0, len(text)))")

    def test_a_rule_with_a_gap(self):
        """A rule that says `head, anything but a separator, tail` read on
        from every head to the end of its stretch looking for the tail:
        64,000 characters of `git push ` took three seconds, and of
        `curl -F ` as long. Two gaps, in sed's redaction test, are worse."""
        self.assertLinear([
            ("rm -rf", "'rm -rf ' * 142857"),
            ("git push", "'git push ' * 111111"),
            ("curl", "'curl ' * 199999"),
            ("curl -F", "'curl -F ' * 124999"),
            ("rm -rf .gi", "'rm -rf .gi ' * 90909"),
            ("rm -r -f", "'rm -r -f ' * 111111"),
            (" -rm", "' -rm' * 249999"),
            ("git rm", "'git rm ' * 142857"),
            ("rm .bash_hist", "'rm .bash_hist ' * 66666"),
            ("find beside a deletion", "'rm -rf ~/x ; ' + 'find ' * 199990"),
            ("sed beside a read", "'cat .env ' + 'sed s/ ' * 142000"),
            ("service accounts", "'cat x ' + 'service_account ' * 62000"),
        ], call="watch.evaluate('Bash', {'command': text})")

    def test_a_deletion_aimed_at_a_long_run(self):
        """A last part that matches everything in a directory was found by
        a regex with * in both its classes, so a run of * read the rest of
        the run again from every split: 64,000 did not finish in twenty
        seconds. And each ) a subshell closes was taken off a target by
        counting and copying the whole word again: a megabyte of them did
        not finish either."""
        self.assertLinear([
            ("stars", "'rm -rf /' + '*' * 63980 + 'x'"),
            ("stars in a subshell", "'(rm -rf /' + '*' * 63970 + 'x)'"),
            ("stars and dots", "'rm -rf ~/' + '*.' * 31990 + 'x'"),
            ("closing parentheses", "'rm -rf ' + ')' * 999990"),
            ("a substitution closed", "'x=$(rm -rf ~' + ')' * 999980"),
        ], call="watch.evaluate('Bash', {'command': text})")
        self.assertLinear([("one long target", "'/' + '*' * 999990 + 'x'")],
                          call="watch._as_absolute(text, '/Users/me')")

    def test_a_credential_path_with_two_runs(self):
        """A service-account file's name was read as any run, the words,
        then any run and .json, so each service_account in one long word
        read on to its end: 63K took two seconds."""
        self.assertLinear([
            ("one word", "'cat service_account.json ' + 'service_account' * 66000"),
            ("dashes", "'cat x.json ' + 'service-account' * 66000 + ' .json'"),
        ], call="watch.evaluate('Bash', {'command': text})")

    def test_flags_that_print_the_environment(self):
        """declare -p and typeset -x print the environment, and a run of
        flag letters could be split around the p or x in n squared ways:
        63,000 of them did not finish in twenty seconds. Only what fits in
        MAX_SCAN_CHARS is asked."""
        self.assertLinear([
            ("declare -ppp", "'source .env ; declare -' + 'p' * 63000 + '1'"),
            ("typeset -xxx", "'source .env ; typeset -' + 'x' * 63000 + '1'"),
        ], call="watch.evaluate('Bash', {'command': text})")

    def test_a_command_full_of_credential_files(self):
        """Each credential file a command names was looked for again in the
        whole command, by a regex built for it: whether it was excluded,
        and whether it was handed to a program. Five thousand ssh -i keys
        in the 64K that watch judges took three seconds."""
        self.assertLinear([
            ("identities", "'ssh ' + ' '.join('-i ~/.ssh/id_rsa%d' % i for i in range(45000))"),
            ("env files", "'docker run ' + ' '.join('--env-file x%d/.env' % i for i in range(43000))"),
            ("variables", "' '.join('K%d=x%d/.env' % (i, i) for i in range(53000))"),
            ("exclusions", "'rsync ' + ' '.join('--exclude .env.%d' % i for i in range(48000))"
                           " + ' src/ dst/ ; cat .env.1'"),
            (".env run", "'cat ' + '.env' * 249999"),
            ("a long path read back", "'F=' + 'a/' * 30000 + '.env; ' + 'cat $F ' * 100000"),
            ("a variable read back", "'F=.env; ' + 'cat \"$F\" ' * 110000"),
        ], call="watch.evaluate('Bash', {'command': text})")

    def test_a_megabyte_of_distinct_keys(self):
        """Each distinct value was looked for again in the whole text, once
        to decide whether it was only part of a longer one and once to mask
        it: 47,000 AWS key IDs took four seconds."""
        self.assertLinear(self.DISTINCT)
        self.assertLinear(self.DISTINCT, call="clean.mask_for_display(text)")


# A tool result whose call named no file: each secret in it is credited to
# the file grep printed in front of its own line. Half a megabyte of
# distinct values in each case.
_B62 = "string.ascii_letters + string.digits"
_DJANGO = "string.ascii_lowercase + string.digits + '!@#$%^&*(-_=+)'"
GREP_RESULTS = [
    ("password= by commas",
     "[','.join('password=%%s' %% r(%s, 12) for _ in range(22727))]" % _B62),
    ("a query string of tokens",
     "['https://x/?' + '&'.join('token=%%s' %% r(%s, 12) for _ in range(27777))]"
     % _B62),
    ("three blocks of API_TOKEN= lines",
     "['\\n'.join('API_TOKEN=%%s' %% r(%s, 50) for _ in range(5400))"
     " for _ in range(3)]" % _B62),
    ("Django keys line by line",
     "['\\n'.join(\"SECRET_KEY='%%s'\" %% r(%s, 50) for _ in range(7800))]"
     % _DJANGO),
]


class ATranscriptOfDistinctKeys(unittest.TestCase):
    """scan_file reads a transcript line by line. Crediting each secret on a
    line meant a search for it from the start of every string on the line,
    so half a megabyte of distinct values cost seconds while finding them
    cost a tenth of one."""

    SETUP = "\n".join([
        "import os, tempfile",
        "blocks = %s",
        "path = os.path.join(tempfile.mkdtemp(), 's.jsonl')",
        "call = {'type': 'assistant', 'message': {'content': [{'type': "
        "'tool_use', 'id': 'b', 'name': 'Bash', 'input': {'command': 'ls'}}]}}",
        "result = {'type': 'user', 'message': {'content': [{'type': "
        "'tool_result', 'tool_use_id': 'b', 'content': "
        "[{'type': 'text', 'text': b} for b in blocks]}]}}",
        "with open(path, 'w', encoding='utf-8') as fh:",
        "    fh.write(json.dumps(call) + '\\n' + json.dumps(result) + '\\n')",
    ])

    def test_crediting_each_secret_costs_no_more_than_finding_it(self):
        for name, blocks in GREP_RESULTS:
            with self.subTest(case=name):
                setup = self.SETUP % blocks
                finding = _seconds(setup, "[clean.find_secrets(b) for b in blocks]")
                scanning = _seconds(setup, "clean.scan_file(path)")
                self.assertLess(scanning, 2 * finding + BUDGET)



# A transcript: a tool reads a .env holding `pws`, then one more line holds
# a bare copy of each among `items` (a list of that many tiny nodes).
_COPIES = "\n".join([
    "import os, tempfile",
    "B62 = string.ascii_letters + string.digits",
    "pws = [r(B62, 32) for _ in range(600)]",
    "env = '\\n'.join('SVC%%s_PASSWORD=%%s' %% (r(string.ascii_uppercase, 4), p)"
    " for p in pws)",
    "path = os.path.join(tempfile.mkdtemp(), 's.jsonl')",
    "rows = [{'type': 'assistant', 'message': {'content': [{'type': 'tool_use',"
    " 'id': 'a', 'name': 'Bash', 'input': {'command': 'cat .env'}}]}},"
    " {'type': 'user', 'message': {'content': [{'type': 'tool_result',"
    " 'tool_use_id': 'a', 'content': env}]}},"
    " {'type': 'user', 'toolUseResult': {'items': %s, 'note': %s},"
    " 'message': {'content': 'ok'}}]",
    "with open(path, 'w', encoding='utf-8') as fh:",
    "    fh.write(''.join(json.dumps(o, separators=(',', ':')) + '\\n' for o in rows))",
    "assert os.path.getsize(path) <= %d" % MB,
])


class EveryCopyOfASecretIsCheap(unittest.TestCase):
    """scan_file counts, and masks, every copy of a value it found, in
    every string on every line that holds one. The count walked a line's
    nodes once per value it held: 600 values on a line of 470,000 numbers
    ran past twenty seconds on a megabyte, where finding them took a
    tenth of one. The second pass must cost about what the first does."""

    def test_a_line_of_many_nodes_holding_many_values(self):
        for items in ("[0] * 470000", "['x'] * 180000"):
            with self.subTest(items=items):
                bare = _seconds(_COPIES % (items, "''"), "clean.scan_file(path)")
                held = _seconds(_COPIES % (items, "' '.join(pws)"),
                                "f, _ = clean.scan_file(path)\n"
                                "assert len(f) == 600\n"
                                "assert sum(e['count'] == 2 for e in f.values()) > 500")
                self.assertLess(held, 2 * bare + BUDGET)

    def test_masking_them_is_as_cheap(self):
        bare = _seconds(_COPIES % ("['x'] * 180000", "''"),
                        "clean.scan_file(path, apply=True)")
        held = _seconds(_COPIES % ("['x'] * 180000", "' '.join(pws)"),
                        "clean.scan_file(path, apply=True)\n"
                        "text = open(path, encoding='utf-8').read()\n"
                        "assert not any(p in text for p in pws)")
        self.assertLess(held, 2 * bare + BUDGET)


# A .env read whose one value repeats a short run, and 400 deletions whose
# evidence ends in "…" just after a four-character piece of it.
_CUT_EVIDENCE = "\n".join([
    "import io, contextlib, os, tempfile",
    "from ranwhat import cli",
    "unit = r(string.ascii_letters + string.digits, 16)",
    "value = %s",
    "piece = unit[4:8]",
    "root = tempfile.mkdtemp()",
    "os.makedirs(os.path.join(root, 'p', '-tmp-x'))",
    "rows = [{'type': 'assistant', 'message': {'content': [{'type': 'tool_use',"
    " 'id': 'a', 'name': 'Bash', 'input': {'command': 'cat .env'}}]}},"
    " {'type': 'user', 'message': {'content': [{'type': 'tool_result',"
    " 'tool_use_id': 'a', 'content': 'TOKEN=' + value}]}}]",
    "for i in range(400):",
    "    for m in range(6):",
    "        cmd = 'rm -rf ~/d%%d ' %% i + '!' * m + ('!' + piece) * 40",
    "        hit = watch.evaluate('Bash', {'command': cmd})[0][0]",
    "        if hit['evidence'].endswith(piece + '\u2026'):",
    "            break",
    "    rows.append({'type': 'assistant', 'message': {'content': [{'type':"
    " 'tool_use', 'id': 't%%d' %% i, 'name': 'Bash', 'input': {'command': cmd}}]}})",
    "path = os.path.join(root, 'p', '-tmp-x', 's.jsonl')",
    "with open(path, 'w', encoding='utf-8') as fh:",
    "    fh.write(''.join(json.dumps(o, separators=(',', ':')) + '\\n' for o in rows))",
    "assert os.path.getsize(path) <= %d" % MB,
    "argv = ['check', '--json', '--days', '3650', '--root', os.path.join(root, 'p'),"
    " '--state-dir', os.path.join(root, 'oc')]",
])


class EvidenceCutInsideAKnownValue(unittest.TestCase):
    """check masks in its watch section every value clean found, as far as
    a window onto the command shows of it. For a window ending in "…" just
    after a short piece of a long value, every place the piece sat in the
    value was tried, each with a copy of the value up to it: quadratic in
    the value, and check ran past twenty seconds on half a megabyte."""

    def test_a_long_value_with_a_short_period(self):
        call = "with contextlib.redirect_stdout(io.StringIO()):\n    cli.main(argv)"
        plain = _seconds(_CUT_EVIDENCE % "r(string.ascii_letters, 640000)", call)
        periodic = _seconds(_CUT_EVIDENCE % "unit * 40000", call)
        self.assertLess(periodic, 2 * plain + BUDGET)

    def test_what_shows_of_it_is_still_masked(self):
        unit = "Xk9mPq2vRt7wLz4b"
        value = unit * 50
        shown = "rm -rf ~/d " + value[:200] + "\u2026"
        self.assertEqual(clean.mask_known(shown, [value]),
                         "rm -rf ~/d <%s>\u2026" % clean._hint(value))
        shown = "\u2026" + value[-100:] + " -e x"
        self.assertEqual(clean.mask_known(shown, [value]),
                         "\u2026<%s> -e x" % clean._hint(value))


# A megabyte of distinct AWS key IDs read out of a file, in a transcript
# whose project slug names a directory that exists, as every real one does.
_UNDER_A_PROJECT = "\n".join([
    "import io, contextlib, os, tempfile",
    "from ranwhat import cli",
    "root = os.path.realpath(tempfile.mkdtemp())",
    "work = os.path.join(root, 'work', 'my-app')",
    "os.makedirs(work)",
    "slug = %s",
    "proj = os.path.join(root, 'projects', slug)",
    "os.makedirs(proj)",
    "keys = ' '.join('AKIA' + r('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567', 16)"
    " for _ in range(%d))",
    "rows = [{'type': 'assistant', 'timestamp': '2026-10-01T10:00:00Z', 'message':"
    " {'content': [{'type': 'tool_use', 'id': 'a', 'name': 'Bash', 'input':"
    " {'command': 'cat keys.env'}}]}},"
    " {'type': 'user', 'timestamp': '2026-10-01T10:00:01Z', 'message':"
    " {'content': [{'type': 'tool_result', 'tool_use_id': 'a', 'content': keys}]}}]",
    "path = os.path.join(proj, 's.jsonl')",
    "with open(path, 'w', encoding='utf-8') as fh:",
    "    fh.write(''.join(json.dumps(o) + '\\n' for o in rows))",
    "assert os.path.getsize(path) <= %d" % MB,
    "argv = ['--json', '--days', '3650', '--root', os.path.join(root, 'projects'),"
    " '--state-dir', os.path.join(root, 'oc')]",
])


class DistinctKeysUnderARealProject(unittest.TestCase):
    """Each finding is credited to the project its transcript belongs to,
    and the slug was resolved against the filesystem again for every one,
    a hundred stat calls each: a megabyte of distinct key IDs under a
    project that exists took nine seconds in clean and in check."""

    def test_the_project_is_resolved_once_per_transcript(self):
        root = tempfile.mkdtemp(prefix="perf-project-")
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        proj = os.path.join(root, "-tmp-app")
        os.makedirs(proj)
        rnd = random.Random(5)
        keys = " ".join("AKIA" + "".join(rnd.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
                                         for _ in range(16)) for _ in range(300))
        path = os.path.join(proj, "s.jsonl")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(json.dumps({"type": "user", "message": {"content": [
                {"type": "tool_result", "tool_use_id": "a", "content": keys}]}}) + "\n")
        with mock.patch.object(clean, "project_path", wraps=clean.project_path) as resolve:
            findings, _ = clean.scan_file(path)
        self.assertEqual(len(findings), 300)
        self.assertEqual(resolve.call_count, 1)

    def test_clean_and_check_on_a_megabyte_of_them(self):
        """As fast under a project that exists as under one that does not."""
        for command in ("clean", "check"):
            with self.subTest(command=command):
                call = ("with contextlib.redirect_stdout(io.StringIO()):\n"
                        "    cli.main([%r] + argv)" % command)
                real = _seconds(_UNDER_A_PROJECT % ("work.replace(os.sep, '-')", 47000),
                                call)
                elsewhere = _seconds(_UNDER_A_PROJECT % ("'-nowhere-at-all'", 47000), call)
                self.assertLess(real, elsewhere + BUDGET)


# A .env of ten thousand passwords read, then thousands of deletions, in a
# megabyte: every action check lists is masked against every value clean
# found.
_KNOWN_AND_HITS = "\n".join([
    "import io, contextlib, os, tempfile",
    "from ranwhat import cli",
    "root = tempfile.mkdtemp()",
    "os.makedirs(os.path.join(root, 'p', '-tmp-x'))",
    "day = time.strftime('%%Y-%%m-%%d', time.gmtime(time.time() - 86400))",
    "def use(cmd, i): return {'timestamp': day + 'T10:%%02d:00Z' %% (i %% 60), 'message':"
    " {'content': [{'type': 'tool_use', 'id': 't%%d' %% i, 'name': 'Bash',"
    " 'input': {'command': cmd}}]}}",
    "pws = [r(string.ascii_letters + string.digits, 20) for _ in range(10000)]",
    "rows = [use('cat .env', 0), {'timestamp': day + 'T10:00:30Z', 'message':"
    " {'content': [{'type': 'tool_result', 'tool_use_id': 't0', 'content':"
    " '\\n'.join('DB_PASSWORD=' + p for p in pws)}]}}]",
    "rows += [use('rm -rf ~/Documents/proj%%d' %% i, i) for i in range(1, %d)]",
    "path = os.path.join(root, 'p', '-tmp-x', 's.jsonl')",
    "with open(path, 'w', encoding='utf-8') as fh:",
    "    fh.write(''.join(json.dumps(o) + '\\n' for o in rows))",
    "assert os.path.getsize(path) <= %d" % MB,
    "argv = ['--days', '30', '--root', os.path.join(root, 'p'),"
    " '--state-dir', os.path.join(root, 'oc')]",
])


class CheckMasksEveryActionCheaply(unittest.TestCase):
    """check masks each action's evidence against every value its clean
    section found, and asked each value of each action, sorting them all
    again every time: ten thousand values and 3,400 deletions doubled
    what watch and clean cost on their own."""

    def test_check_costs_what_watch_and_clean_do(self):
        def run(command):
            return _seconds(_KNOWN_AND_HITS % 3400,
                            "with contextlib.redirect_stdout(io.StringIO()):\n"
                            "    cli.main(%r + argv)" % command)
        watch_alone = run(["watch"])
        clean_alone = run(["clean", "--no-interactive"])
        for command in (["check"], ["check", "--json"]):
            with self.subTest(command=command):
                self.assertLess(run(command), watch_alone + clean_alone + BUDGET)


if __name__ == "__main__":
    unittest.main()
