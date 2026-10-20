"""The ignore file's format, and how an entry is matched (ignore.py).

A line it cannot read is skipped and named, and leaves nothing out. A
comment ranwhat writes can never become an entry, whatever the command it
quotes holds. Only * is special in a pattern, within one word, and a
pattern costs what it is long to match. Every value here is synthetic.
"""
import datetime
import os
import sys
import time
import unittest
from unittest import mock

TESTS = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(TESTS))
sys.path.insert(0, TESTS)

import isolated_home  # noqa: E402,F401  ranwhat's state, never ~/.ranwhat
from ranwhat import ignore, watch  # noqa: E402

TODAY = datetime.date(2026, 10, 20)
HOME = os.path.expanduser("~")


def parse(text):
    return ignore.parse(text, TODAY)


def record(rule="publish", severity="critical", subject="npm publish",
           on="command", cd="", cwd=None, ids=("3fa9c2d81b7e4a06",)):
    hit = {"rule": rule, "severity": severity, "title": "T", "why": "W",
           "evidence": subject, "_on": on, "_subject": subject}
    if on == "command":
        hit["_cd"] = cd
    out = {"id": ids[0], "source": "claude-code", "severity": severity,
           "timestamp": "2026-10-19T10:00:00Z", "hits": [hit]}
    if len(ids) > 1:
        out["ids"] = sorted(ids)
    if cwd:
        out["cwd"] = cwd
    return out


def hides(text, rec):
    found = ignore.Ignore(parsed=parse(text), today=TODAY, exists=True)
    return found.verdict(rec).hidden


class Lines(unittest.TestCase):

    def test_ids_alone_or_with_their_copies_and_ack(self):
        p = parse("3fa9c2d81b7e4a06\n"
                  "DF6AB917DF219E75 0c1d2e3f4a5b6c7d  # one action, two copies\n"
                  "9c01d2e3f4a5b6c7 ack\n")
        self.assertEqual(p.ids, {"3fa9c2d81b7e4a06": 1, "df6ab917df219e75": 2,
                                 "0c1d2e3f4a5b6c7d": 2})
        self.assertEqual(p.acks, {"9c01d2e3f4a5b6c7": 3})
        self.assertEqual((p.id_lines, p.ack_lines, p.skipped), (3, 1, []))

    def test_a_pattern_line_and_its_keys(self):
        p = parse("publish 'npm publish' in=~/work/mylib/ until=2027-01-31  # x\n"
                  'cred.read "~/work/my lib/.env" until=2027-04-01\n'
                  "exec.remote\n"
                  "persist in='~/x' \n")
        e1, e2, e3, e4 = p.entries
        self.assertEqual((e1.rule, e1.words, e1.until),
                         ("publish", ["npm", "publish"], datetime.date(2027, 1, 31)))
        self.assertEqual(e1.within, os.path.join(HOME, "work", "mylib").replace("\\", "/")
                         if os.name != "nt" else e1.within)
        self.assertEqual(e1.text, "publish 'npm publish' in=~/work/mylib/ until=2027-01-31")
        self.assertTrue(e2.path.endswith("/work/my lib/.env"))
        self.assertIsNone(e3.pattern)
        self.assertIsNone(e4.pattern)
        self.assertTrue(e4.within.endswith("/x"))
        self.assertEqual(p.skipped, [])

    def test_a_byte_order_mark_and_crlf_read_as_written(self):
        p = parse("\ufeffpublish 'npm publish'\r\n3fa9c2d81b7e4a06\r\n")
        self.assertEqual([e.words for e in p.entries], [["npm", "publish"]])
        self.assertEqual(p.ids, {"3fa9c2d81b7e4a06": 2})

    def test_a_hash_inside_a_word_is_no_comment(self):
        p = parse("publish 'rm#x'\npublish rm#x\npublish 'npm publish' # note\n"
                  "# a comment\n   # another\npublish \\#x\n")
        self.assertEqual([e.words for e in p.entries],
                         [["rm#x"], ["rm#x"], ["npm", "publish"], ["#x"]])
        self.assertEqual(p.skipped, [])

    def test_each_line_it_cannot_read_is_skipped_and_named(self):
        cases = {
            "publsh 'npm publish'": "there is no rule publsh",
            "secret.literal": "secrets are left alone with keep",
            "publish 'x' foo=1": "there is no foo=",
            "publish 'x' in=/a in=/b": "in= is given twice",
            "publish 'x' extra": "one word too many",
            "publish ''": "its command is empty",
            "publish 'x' in=work/app": "is not a folder from the root",
            "publish 'x' in=~other/app": "is not a folder from the root",
            "publish 'x' until=2027-13-01": "is not a date",
            "publish 'x' until=20270101": "is not a date",
            "publish 'npm publish": "a quote in it is not closed",
            "publish " + "x" * 9000: "longer than 8192",
            "publish '%s'" % ("x" * 1100): "longer than 1024",
            "publish '%s'" % " ".join(["w"] * 65): "more than 64 words",
            "3fa9c2d81b7e4a06 extra": "a line of ids holds ids alone",
        }
        for line, why in cases.items():
            with self.subTest(line=line[:50]):
                p = parse("# head\n" + line + "\n")
                self.assertEqual(p.entries, [])
                self.assertEqual(p.ids, {})
                (n, said), = p.skipped
                self.assertEqual(n, 2)
                self.assertIn(why, said)

    def test_a_skipped_line_hides_nothing(self):
        rec = record(rule="git.destructive", severity="high",
                     subject="git push --force")
        for line in ("git.destructive 'git push --force' bogus",
                     "git.destructive 'git push --force' until=never",
                     "git.destructive 'git push --force"):
            self.assertFalse(hides(line, rec), line)
        self.assertTrue(hides("git.destructive 'git push --force'", rec))

    def test_blocks_of_ids_and_their_heading(self):
        p = parse("# ranwhat ignore all, 2026-10-20 14:02, last 30 days: 2 actions\n"
                  "3fa9c2d81b7e4a06  # a\n0c1d2e3f4a5b6c7d  # b\n"
                  "9c01d2e3f4a5b6c7 ack\n\npublish\n1111111111111111\n")
        self.assertEqual(p.blocks, [[2, 3, 2, "ranwhat ignore all, 2026-10-20", False],
                                    [4, 4, 1, None, True], [7, 7, 1, None, False]])


class Injection(unittest.TestCase):
    """What ranwhat writes after an id quotes a command; that command can
    never make a line of its own, however it is spelt."""

    def test_a_line_separator_in_a_command_makes_no_entry(self):
        for sep in ("\u2028", "\u2029", "\x85", "\x0b", "\x0c", "\x1c", "\r", "\n"):
            rec = record(rule="fs.destructive", severity="high",
                         subject="rm -rf x%spublish" % sep)
            with self.subTest(sep=repr(sep)):
                line = ignore.id_line(rec)
                p = parse(line + "\n")
                self.assertEqual(p.entries, [])
                self.assertEqual(p.skipped, [])
                self.assertEqual(list(p.ids), ["3fa9c2d81b7e4a06"])
                self.assertNotIn(sep, line)
                found, why = ignore.proposal(rec, TODAY)
                self.assertIsNone(found)
                self.assertIn("control character", why)

    def test_a_comment_holds_the_command_masked_and_where_it_ran(self):
        rec = record(subject="npm publish", cwd=HOME + "/work/mylib")
        self.assertEqual(ignore.describe(rec),
                         "publish 'npm publish' in=~/work/mylib  (Claude Code, %s)"
                         % watch._local_time(rec["timestamp"])[:16])
        rec = record(rule="cred.read", on="path", subject="/srv/app/.env")
        self.assertTrue(ignore.describe(rec).startswith("cred.read /srv/app/.env  ("))
        long = record(subject="echo " + "x" * 300)
        self.assertTrue(ignore.describe(long).startswith("publish: echo xxx"))


class Glob(unittest.TestCase):

    def test_only_a_star_is_special(self):
        self.assertTrue(ignore.glob("[", "["))
        self.assertTrue(ignore.glob("?token=*", "?token=abc"))
        self.assertFalse(ignore.glob("?token=*", "xtoken=abc"))
        self.assertTrue(ignore.glob("[-f", "[-f"))
        self.assertFalse(ignore.glob("[a-z]", "a"))

    def test_anchored_at_both_ends(self):
        self.assertTrue(ignore.glob("v*", "v1.2"))
        self.assertFalse(ignore.glob("v*", "xv1.2"))
        self.assertFalse(ignore.glob("*.js", "a.jsx"))
        self.assertTrue(ignore.glob("a*b*c", "abc"))
        self.assertTrue(ignore.glob("a*b*c", "a-b-b-c"))
        self.assertFalse(ignore.glob("a*b*c", "a-c-b"))
        self.assertTrue(ignore.glob("*", ""))
        self.assertFalse(ignore.glob("a*a", "a"))

    def test_it_costs_what_it_is_long(self):
        start = time.perf_counter()
        self.assertFalse(ignore.glob("*a" * 200, "b" * 64000))
        self.assertFalse(ignore.glob("*a" * 200 + "*", "b" * 64000))
        self.assertFalse(ignore.glob("*ab" * 200 + "*", "a" * 64000))
        self.assertLess(time.perf_counter() - start, 0.05)


class Words(unittest.TestCase):

    def test_word_for_word(self):
        pw = ["npm", "publish"]
        self.assertTrue(ignore.match_words(pw, ["npm", "publish"]))
        self.assertFalse(ignore.match_words(pw, ["npm", "publish", "--registry", "x"]))
        self.assertFalse(ignore.match_words(pw, ["sudo", "npm", "publish"]))
        self.assertFalse(ignore.match_words(pw, None))

    def test_a_star_stays_in_its_word(self):
        pw = ["gh", "release", "create", "v*"]
        self.assertTrue(ignore.match_words(pw, ["gh", "release", "create", "v1.0"]))
        self.assertFalse(ignore.match_words(pw, ["gh", "release", "create", "v1",
                                                 "--notes", "x"]))

    def test_a_masked_value_matches_its_mask(self):
        rec = record(rule="publish", severity="high",
                     subject="GH_TOKEN=<ghp…89> gh release create v2.1")
        self.assertTrue(hides("publish 'GH_TOKEN=* gh release create v*'", rec))
        self.assertFalse(hides("publish 'gh release create v*'", rec))


class Paths(unittest.TestCase):

    def test_component_by_component(self):
        self.assertTrue(ignore.match_path("/a/b/.env", "/a/b/.env"))
        self.assertTrue(ignore.match_path("/a/*/.env", "/a/b/.env"))
        self.assertFalse(ignore.match_path("/a/*", "/a/b/.env"))
        self.assertFalse(ignore.match_path("/a/*/.env", "/a/b/c/.env"))
        self.assertTrue(ignore.match_path("~/x/.env", HOME + "/x/.env"))
        self.assertFalse(ignore.match_path("x/.env", "/w/x/.env"))     # relative pattern

    def test_a_relative_path_is_under_where_it_ran(self):
        self.assertTrue(ignore.match_path("/w/x/.env", "x/.env", "/w"))
        self.assertFalse(ignore.match_path("/w/x/.env", "x/.env"))
        self.assertFalse(ignore.match_path("/w/x/.env", "x/.env", "w"))

    def test_inside(self):
        self.assertTrue(ignore.inside("/w/mylib", "/w/mylib"))
        self.assertTrue(ignore.inside("/w/mylib/sub", "/w/mylib/"))
        self.assertFalse(ignore.inside("/w/mylib-old", "/w/mylib"))
        self.assertFalse(ignore.inside("/w", "/w/mylib"))
        self.assertTrue(ignore.inside("/w/a/../mylib", "/w/mylib"))
        self.assertTrue(ignore.inside("/anything", "/"))
        self.assertFalse(ignore.inside(None, "/w"))
        self.assertFalse(ignore.inside("w/mylib", "/w"))

    def test_windows_paths_compare_without_case(self):
        self.assertTrue(ignore.inside("C:\\Users\\Me\\Work\\lib", "c:/users/me/work"))
        self.assertTrue(ignore.inside("C:/proj\\sub", "C:\\proj"))
        self.assertFalse(ignore.inside("C:\\proj-old", "C:\\proj"))
        self.assertTrue(ignore.match_path("C:/Users/me/.env", "c:\\users\\ME\\.env"))
        p = parse("publish 'npm publish' in='C:\\Users\\me\\work' until=2027-01-01\n")
        self.assertEqual(p.entries[0].within, "c:/users/me/work")


class WhatIsWritten(unittest.TestCase):

    def test_a_proposal_reads_back_and_leaves_the_action_out(self):
        rec = record(subject="rm -rf '~/my docs/x'", rule="fs.destructive",
                     severity="high", cwd="/w")
        found, why = ignore.proposal(rec, TODAY)
        self.assertIsNone(why)
        self.assertEqual(found.lines, ["fs.destructive \"rm -rf '~/my docs/x'\" in=/w"])
        self.assertTrue(hides(found.lines[0], rec))

    def test_a_critical_one_is_scoped_and_expires(self):
        rec = record(cwd=HOME + "/work/mylib", cd="packages/a")
        found, _why = ignore.proposal(rec, TODAY)
        self.assertEqual(found.lines, ["publish 'npm publish' in=~/work/mylib/packages/a "
                                       "until=2027-10-20"])
        found, why = ignore.proposal(record(), TODAY)
        self.assertIsNone(found)
        self.assertIn("which folder it ran in", why)

    def test_no_proposal_for_a_decoded_or_a_secret_hit(self):
        decoded = record()
        decoded["hits"][0]["_on"] = "decoded"
        self.assertIn("decoded", ignore.proposal(decoded, TODAY)[1])
        secret = record(rule="secret.literal", on="raw")
        self.assertIn("secret", ignore.proposal(secret, TODAY)[1])

    def test_quoting(self):
        self.assertEqual(ignore.join_words(["rm", "-rf", "~/x", "*.log"]),
                         "rm -rf ~/x *.log")
        self.assertEqual(ignore.quote_command("echo 'a b'"), "\"echo 'a b'\"")
        self.assertEqual(ignore.dir_word(HOME + "/my work"), "'~/my work'")
        self.assertEqual(ignore.dir_word("/srv/app"), "/srv/app")
        for words in (["echo", "it's"], ['x"y', "z'"], ["a b", "c"], [""], ["#x"]):
            line = "publish %s" % ignore.quote_command(ignore.join_words(words))
            entry, = parse(line).entries
            self.assertEqual(entry.words, words)


class Usable(unittest.TestCase):

    def setUp(self):
        import tempfile
        self.tmp = tempfile.mkdtemp(prefix="ignore-fmt-")
        self.addCleanup(__import__("shutil").rmtree, self.tmp, True)
        self.path = os.path.join(self.tmp, "ignore")

    def write(self, data, mode=0o600):
        with open(self.path, "wb") as fh:
            fh.write(data)
        os.chmod(self.path, mode)

    def test_not_utf8_is_not_used(self):
        self.write(b"publish '\xff'\n")
        found = ignore.Ignore.open(self.path)
        self.assertIn("UTF-8", found.unused)
        with self.assertRaises(ignore.IgnoreError):
            ignore.Ignore.open(self.path, explicit=True)

    def test_too_large_is_not_used(self):
        self.write(b"x")
        with mock.patch.object(ignore, "MAX_BYTES", 0):
            self.assertIn("larger than", ignore.Ignore.open(self.path).unused)

    @unittest.skipIf(os.name == "nt", "POSIX permissions")
    def test_world_writable_or_foreign_is_not_used(self):
        self.write(b"publish\n", 0o666)
        self.assertEqual(ignore.Ignore.open(self.path).unused,
                         "can be written by other users")
        self.write(b"publish\n", 0o664)                 # a group may write it
        self.assertIsNone(ignore.Ignore.open(self.path).unused)
        with mock.patch("os.geteuid", return_value=os.geteuid() + 1):
            self.assertEqual(ignore.Ignore.open(self.path).unused,
                             "belongs to another user")

    def test_absent(self):
        found = ignore.Ignore.open(self.path)
        self.assertFalse(found.exists)
        self.assertEqual(found.notes(), [])
        with self.assertRaises(ignore.IgnoreError) as raised:
            ignore.Ignore.open(self.path, explicit=True)
        self.assertIn("No such file or directory", str(raised.exception))


if __name__ == "__main__":
    unittest.main()
