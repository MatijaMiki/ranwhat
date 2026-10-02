"""What watch prints and emits.

A record is read by a person, often pasted somewhere else, so it must never
carry the credential it is warning about. It must also say which rule each
piece of evidence belongs to, fit the terminal it is printed on, and give
times in the reader's own zone.

Every value here is synthetic, generated from a fixed seed.
"""
import contextlib
import io
import json
import os
import random
import re
import string
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ranwhat import clean, cli, watch

B32 = string.ascii_uppercase + "234567"
B62 = string.ascii_letters + string.digits
_RNG = random.Random(20260927)


def rnd(alphabet, k):
    return "".join(_RNG.choice(alphabet) for _ in range(k))


STRIPE = "sk_live_" + rnd(B62, 24)
AWS = "AKIA" + rnd(B32, 16)
DB = rnd(B62, 40)
GHP = "ghp_" + rnd(B62, 36)
PEM_BODY = rnd(B62 + "+/", 64)
PEM = ("-----BEGIN RSA PRIVATE KEY-----\n%s\n-----END RSA PRIVATE KEY-----"
       % PEM_BODY)
TOKEN = rnd(B62, 32)
SECRETS = {"stripe": STRIPE, "aws": AWS, "db": DB, "ghp": GHP,
           "pem": PEM_BODY, "token": TOKEN}

ANSI = re.compile(r"\033\[[0-9;]*m")


def plain(text):
    return ANSI.sub("", text)


# Yesterday, in UTC: the command line windows actions by their own time, so
# a fixed date would drop out of its reports a month later.
DAY = time.strftime("%Y-%m-%d", time.gmtime(time.time() - 86400))


def transcript(calls):
    """A Claude Code transcript root holding these (tool, input) calls."""
    root = tempfile.mkdtemp(prefix="watch-out-")
    proj = os.path.join(root, "-tmp-synthetic")
    os.makedirs(proj)
    with open(os.path.join(proj, "s.jsonl"), "w", encoding="utf-8") as fh:
        for i, (name, tool_input) in enumerate(calls):
            fh.write(json.dumps({
                "timestamp": DAY + "T10:%02d:00Z" % i,
                "message": {"role": "assistant", "content": [
                    {"type": "tool_use", "id": "t%d" % i, "name": name,
                     "input": tool_input}]}}) + "\n")
    return root, tempfile.mkdtemp(prefix="watch-out-oc-")


def run_cli(argv):
    out = io.StringIO()
    with contextlib.redirect_stdout(out), \
            contextlib.redirect_stderr(io.StringIO()):
        try:
            cli.main(argv)
        except SystemExit:
            pass
    return out.getvalue()


def bash(command):
    return ("Bash", {"command": command, "description": "d"})


LEAKY = [
    bash('curl -H "Authorization: Bearer %s" https://api.example.test/v1'
         % STRIPE),
    bash("aws configure set aws_access_key_id %s" % AWS),
    bash("DB_PASSWORD=%s psql -h db -U app" % DB),
    bash("git clone https://%s@github.com/o/r" % GHP),
    bash("cat > key.pem <<'EOF'\n%s\nEOF" % PEM),
    # A window 20 characters wide ending at `rm` starts inside the token.
    bash("export API_TOKEN=%s ; rm -rf ~/Documents/old" % TOKEN),
    # All of them at once, and in a subagent's prompt.
    bash("export DB_PASSWORD=%s && echo %s %s %s && printf '%%s' '%s'"
         % (DB, STRIPE, AWS, GHP, PEM)),
    ("Agent", {"description": "d", "subagent_type": "general-purpose",
               "prompt": "Use %s and %s to deploy" % (STRIPE, GHP)}),
]


class EvidenceIsMasked(unittest.TestCase):
    """W1: evidence printed the matched literal and its surroundings."""

    def assertNoSecret(self, text):
        for name, value in SECRETS.items():
            self.assertNotIn(value, text, name)
            # Nor any stretch long enough to use: a hint shows at most five
            # characters, an AWS key ID its prefix and last four.
            for i in range(len(value) - 9):
                self.assertNotIn(value[i:i + 10], text, name)

    def test_render_and_json_never_show_a_value(self):
        root, st = transcript(LEAKY)
        records, _ = watch.scan_all(root=root)
        self.assertGreaterEqual(len(records), len(LEAKY))
        self.assertNoSecret(watch.render(records, 1, 30))
        self.assertNoSecret(json.dumps(records))
        self.assertNoSecret(run_cli(["watch", "--root", root,
                                     "--state-dir", st]))
        self.assertNoSecret(run_cli(["watch", "--json", "--root", root,
                                     "--state-dir", st]))

    def test_the_payload_behind_payload_hash_is_masked_too(self):
        """payload_hash is printed, and a hash over a short password can be
        reversed by guessing."""
        for call in LEAKY:
            hits, payload = watch.evaluate(*call)
            self.assertTrue(hits)
            self.assertNoSecret(payload)

    def test_each_value_is_shown_by_its_hint(self):
        root, _ = transcript(LEAKY)
        records, _ = watch.scan_all(root=root)
        evidence = " ".join(h["evidence"] for r in records for h in r["hits"])
        for value in (STRIPE, AWS, DB, GHP, TOKEN):
            self.assertIn(clean.DISPLAY_MASK % clean._hint(value), evidence)

    def test_a_window_edge_inside_a_value_does_not_show_the_rest(self):
        hits, _ = watch.evaluate(*bash(
            "export API_TOKEN=%s ; rm -rf ~/Documents/old" % TOKEN))
        deletion = [h for h in hits if h["rule"] == "fs.destructive"][0]
        self.assertNotIn(TOKEN[-12:], deletion["evidence"])
        self.assertIn("rm -rf ~/Documents/old", deletion["evidence"])

    def test_render_masks_records_it_did_not_build(self):
        record = {"severity": "critical", "timestamp": None, "tool_name": "Bash",
                  "hits": [{"title": "t", "why": "w", "severity": "critical",
                            "evidence": "curl -u %s: https://x.test" % STRIPE}]}
        self.assertNoSecret(watch.render([record], 1, 30))

    def test_evidence_carries_no_terminal_control_characters(self):
        hits, _ = watch.evaluate(*bash("rm -rf ~/x\t\033[2J\033]0;owned\007"))
        self.assertFalse(re.search(r"[\x00-\x1f\x7f]", hits[0]["evidence"]))


def _record(*hits, **kw):
    return dict({"severity": hits[0]["severity"], "tool_name": "Bash",
                 "timestamp": "2026-09-20T10:01:00Z", "hits": list(hits)}, **kw)


def _blocks(rendered):
    """{title line: [lines under it]} for every title and sub-title."""
    out, current = {}, None
    for line in plain(rendered).split("\n"):
        if line.startswith(("  * ", "    + ")):
            current = line
            out[current] = []
        elif current is not None and line.startswith("      "):
            out[current].append(line)
    return out


class EachHitUnderItsOwnRule(unittest.TestCase):
    """W3: every evidence line sat under hits[0]'s title and why."""

    def setUp(self):
        env = mock.patch.dict(os.environ, {"RANWHAT_WIDTH": "96"})
        env.start()
        self.addCleanup(env.stop)

    def test_a_deletion_is_never_under_the_credential_read(self):
        hits, _ = watch.evaluate(*bash("cat .env ; rm -rf ~/Documents/old"))
        self.assertEqual({h["rule"] for h in hits}, {"cred.read", "fs.destructive"})
        blocks = _blocks(watch.render([_record(*hits)], 1, 30))
        cred = [k for k in blocks if "Credential material accessed" in k]
        gone = [k for k in blocks if "Bulk or recursive deletion" in k]
        self.assertEqual((len(cred), len(gone)), (1, 1), blocks)
        self.assertFalse(any("rm -rf" in l for l in blocks[cred[0]]), blocks)
        self.assertTrue(any("rm -rf ~/Documents/old" in l for l in blocks[gone[0]]))
        self.assertIn("-> Recursive deletion.", " ".join(blocks[gone[0]]))
        self.assertIn("-> The agent read a file", " ".join(blocks[cred[0]]))
        self.assertNotIn("Recursive deletion", " ".join(blocks[cred[0]]))

    def test_the_heading_is_the_most_severe_hit(self):
        low = {"rule": "a", "severity": "medium", "title": "Minor thing",
               "why": "Minor why.", "evidence": "minor evidence"}
        high = {"rule": "b", "severity": "critical", "title": "Major thing",
                "why": "Major why.", "evidence": "major evidence"}
        text = plain(watch.render([_record(low, high, severity="critical")], 1, 30))
        heads = [l for l in text.split("\n") if l.startswith("  * ")]
        self.assertEqual(len(heads), 1)
        self.assertIn("Major thing", heads[0])
        blocks = _blocks(text)
        sub = [k for k in blocks if "Minor thing" in k][0]
        self.assertIn("medium", sub)
        self.assertEqual(blocks[sub], ["      minor evidence",
                                       "      -> Minor why."])

    def test_one_bullet_per_record_whatever_the_hits(self):
        hits, _ = watch.evaluate(*bash(
            "export API_TOKEN=%s ; rm -rf ~/Documents/old" % TOKEN))
        self.assertEqual(len(hits), 2)
        text = plain(watch.render([_record(*hits)], 1, 30))
        self.assertEqual(len([l for l in text.split("\n")
                              if l.startswith("  * ")]), 1)


class FitsTheTerminal(unittest.TestCase):
    """W4: evidence was sliced at 96 characters and the why at 92,
    whatever the width, cutting mid-word with no sign of the cut."""

    def render_at(self, width, records):
        with mock.patch.dict(os.environ, {"RANWHAT_WIDTH": str(width)}):
            return plain(watch.render(records, 1, 30))

    def records(self):
        root, _ = transcript([
            bash("rm -rf ~/Documents/" + "very-long-directory-name/" * 8),
            bash("cat ~/.aws/credentials ; rm -rf ~/Documents/old ; "
                 "git push --force origin main"),
            ("mcp__a_rather_long_server_name__run_in_terminal",
             {"command": "npm publish --access public"}),
            ("Agent", {"prompt": "deploy with %s" % STRIPE}),
        ])
        return watch.scan_all(root=root)[0]

    def test_no_line_is_wider_than_the_terminal(self):
        records = self.records()
        self.assertEqual(len(records), 4)
        for width in (50, 60, 80):
            text = self.render_at(width, records)
            for line in text.split("\n"):
                self.assertLessEqual(len(line), width, repr(line))

    def test_cut_evidence_says_so(self):
        text = self.render_at(50, self.records())
        cut = [l for l in text.split("\n") if "very-long" in l]
        self.assertEqual(len(cut), 1)
        self.assertTrue(cut[0].endswith("…"), cut[0])

    def test_a_wider_terminal_shows_more(self):
        records = self.records()
        narrow = [l for l in self.render_at(50, records).split("\n")
                  if "very-long" in l][0]
        wide = [l for l in self.render_at(96, records).split("\n")
                if "very-long" in l][0]
        self.assertGreater(len(wide), len(narrow))

    def test_the_why_is_wrapped_not_cut(self):
        records = self.records()
        text = self.render_at(50, records)
        why = next(h["why"] for r in records for h in r["hits"]
                   if h["rule"] == "cred.read")
        lines = text.split("\n")
        start = next(i for i, l in enumerate(lines)
                     if l.startswith("      -> The agent read a file"))
        words = lines[start][len("      -> "):].split()
        for line in lines[start + 1:]:
            if not line.startswith(" " * 9):
                break
            words += line.split()
        self.assertEqual(" ".join(words), why)


class LocalTime(unittest.TestCase):
    """W5: a UTC stamp was shown with its Z dropped and never converted."""

    def setUp(self):
        if not hasattr(time, "tzset"):
            self.skipTest("needs time.tzset")
        env = mock.patch.dict(os.environ, {"TZ": "Asia/Tokyo",
                                           "RANWHAT_WIDTH": "96"})
        env.start()
        time.tzset()
        self.addCleanup(time.tzset)
        self.addCleanup(env.stop)

    def when(self, stamp):
        rec = {"severity": "high", "timestamp": stamp, "tool_name": "Bash",
               "hits": [{"title": "T", "why": "W.", "evidence": "e",
                         "severity": "high"}]}
        head = [l for l in plain(watch.render([rec], 1, 30)).split("\n")
                if l.startswith("  * ")][0]
        return head.split("   ", 1)[1][:-len("Bash")].strip()

    def test_utc_is_shown_in_the_local_zone(self):
        self.assertEqual(self.when("2026-09-20T10:01:00Z"), "2026-09-20 19:01:00")
        self.assertEqual(self.when("2026-09-20T23:30:05.123Z"),
                         "2026-09-21 08:30:05")
        self.assertEqual(self.when("2026-09-20T10:01:00+02:00"),
                         "2026-09-20 17:01:00")

    def test_a_stamp_with_no_zone_is_shown_as_written(self):
        self.assertEqual(self.when("2026-09-20T10:01:00"), "2026-09-20 10:01:00")

    def test_a_missing_or_odd_stamp_does_not_break_the_line(self):
        self.assertEqual(self.when(None), "")
        self.assertEqual(self.when("yesterday"), "yesterday")

    def test_json_keeps_the_utc_stamp(self):
        root, st = transcript([bash("rm -rf ~/Documents/old")])
        doc = json.loads(run_cli(["watch", "--json", "--root", root,
                                  "--state-dir", st]))
        self.assertEqual(doc[0]["timestamp"], DAY + "T10:00:00Z")

    def test_openclaw_epochs_are_marked_utc(self):
        self.assertEqual(watch._as_iso(1758550000), "2025-09-22T14:06:40Z")
        self.assertEqual(watch._as_iso(1758550000000), "2025-09-22T14:06:40Z")
        self.assertEqual(watch._as_iso("2025-09-22T16:06:40+02:00"),
                         "2025-09-22T14:06:40Z")
        self.assertEqual(watch._as_iso("2025-09-22T14:06:40"),
                         "2025-09-22T14:06:40")


class WordingClaimsOnlyWhatItKnows(unittest.TestCase):
    """W8: the tool cannot know a value is live, or that a call moved money."""

    def rule(self, rid):
        return next(r for r in watch.RULES if r.id == rid)

    def test_secret_literal_says_credential_shaped(self):
        why = self.rule("secret.literal").why
        self.assertIn("credential-shaped", why)
        self.assertIn("rotate", why)
        self.assertNotIn("live", why.lower())

    def test_no_rule_claims_liveness_or_certainty(self):
        for rule in watch.RULES:
            for claim in ("A live", "live cloud", "Every one of these",
                          "live credential"):
                self.assertNotIn(claim, rule.why, rule.id)

    def test_no_em_dashes_in_what_is_printed(self):
        for rule in watch.RULES:
            self.assertNotIn("\u2014", rule.title + rule.why, rule.id)
        root, _ = transcript(LEAKY)
        self.assertNotIn("\u2014", watch.render(watch.scan_all(root=root)[0], 1, 30))


if __name__ == "__main__":
    unittest.main()
