"""ranwhat ledger (ranwhat/ledger.py): a hash chain of what watch flagged.

What matters: a change to the file is found and named (an edited line, a
line taken out, two swapped, the end cut off, a line cut in half), a ledger
that fails is never extended, two ranwhat processes writing at once leave one
chain, and nothing but push's five facts reaches the file. Every value is
synthetic, every file is in a temp directory, and nothing reaches the network.
"""
import io
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

TESTS = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(TESTS)
sys.path.insert(0, ROOT)
sys.path.insert(0, TESTS)

import isolated_home  # noqa: E402,F401  ranwhat's state, never ~/.ranwhat
from ranwhat import cli, ledger, push  # noqa: E402

CANARY = "ZZCANARY"
STRIPE = "sk_" "live_" "Fx7Qw2Er9Ty4Ui1Op6As3Df"


def slurp(path, create=False):
    if create:
        with open(path, "w", encoding="utf-8"):
            return b""
    with open(path, "rb") as fh:
        return fh.read()


def item(n, rule="cred.read", severity="critical", agent="claude-code"):
    return {"id": "%016x" % (0xA0B0C0D0E0F00000 + n), "agent": agent,
            "at": "2026-10-20T13:%02d:00Z" % (n % 60),
            "hits": [{"rule": rule, "severity": severity}]}


def rec(n, **extra):
    out = {
        "id": "%016x" % (0xA0B0C0D0E0F00000 + n), "source": "claude-code",
        "timestamp": "2026-10-20T13:%02d:00Z" % (n % 60),
        "session": CANARY, "project": "/home/" + CANARY, "cwd": CANARY,
        "tool_name": CANARY, "tool_call_id": CANARY,
        "hits": [{"rule": "cred.read", "severity": "critical",
                  "evidence": CANARY + STRIPE, "title": CANARY,
                  "why": CANARY, "_subject": CANARY}]}
    out.update(extra)
    return out


class _Dir(unittest.TestCase):

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="ranwhat ledger ")   # a space in it
        self.path = os.path.join(self.dir, "ledger.jsonl")
        self.addCleanup(self.cleanup)

    def cleanup(self):
        import shutil
        shutil.rmtree(self.dir, ignore_errors=True)

    def make(self, count=5):
        ledger.record([item(n) for n in range(1, count + 1)], self.path)

    def lines(self):
        with open(self.path, "rb") as fh:
            return fh.read().split(b"\n")[:-1]

    def write(self, lines, end=b"\n"):
        with open(self.path, "wb") as fh:
            fh.write(b"\n".join(lines) + end)

    def edit(self, number, **changes):
        lines = self.lines()
        entry = json.loads(lines[number - 1])
        entry.update(changes)
        lines[number - 1] = ledger.dumps(entry).encode()
        self.write(lines)
        return entry


class AnUntouchedChain(_Dir):

    def test_it_verifies_and_the_head_is_the_last_hash(self):
        self.make(5)
        report = ledger.verify(self.path)
        self.assertTrue(report.ok)
        self.assertEqual(report.entries, 5)
        self.assertEqual(report.head, json.loads(self.lines()[-1])["hash"])

    def test_each_line_names_the_hash_of_the_one_before(self):
        self.make(4)
        previous = ledger.GENESIS
        for n, raw in enumerate(self.lines(), 1):
            entry = json.loads(raw)
            self.assertEqual(entry["prev"], previous)
            self.assertEqual(entry["n"], n)
            previous = entry["hash"]

    def test_a_missing_file_and_an_empty_one_verify(self):
        report = ledger.verify(self.path)
        self.assertTrue(report.ok)
        self.assertFalse(report.exists)
        open(self.path, "wb").close()
        report = ledger.verify(self.path)
        self.assertTrue(report.ok)
        self.assertEqual(report.entries, 0)

    def test_recording_again_adds_only_what_is_new(self):
        self.make(3)
        added, held, report = ledger.record(
            [item(n) for n in range(2, 6)], self.path)
        self.assertEqual((added, held, report.entries), (2, 2, 5))
        self.assertTrue(report.ok)
        added, held, report = ledger.record([item(1)], self.path)
        self.assertEqual((added, held, report.entries), (0, 1, 5))

    def test_the_same_items_make_the_same_bytes_wherever_they_are_hashed(self):
        entry = ledger.seal({"v": 1, "n": 1, "prev": ledger.GENESIS,
                             "time": "2026-11-02T00:00:00Z", "id": "a" * 16,
                             "agent": "codex", "at": None,
                             "hits": [{"rule": "x.y", "severity": "high"}]})
        self.assertEqual(
            entry["hash"],
            ledger.digest(json.loads(ledger.dumps(entry))))
        self.assertNotIn(b"\r", ledger.canonical(entry))

    def test_windows_paths_and_line_ends_are_no_trouble(self):
        self.make(3)
        with open(self.path, "rb") as fh:
            self.assertNotIn(b"\r", fh.read())
        # An editor or git that turned the line ends into CRLF has changed
        # nothing the chain holds.
        data = slurp(self.path).replace(b"\n", b"\r\n")
        with open(self.path, "wb") as fh:
            fh.write(data)
        self.assertTrue(ledger.verify(self.path).ok)


class ATamperedChain(_Dir):

    def test_a_changed_line_is_named(self):
        self.make(5)
        self.edit(3, hits=[{"rule": "cred.read", "severity": "medium"}])
        report = ledger.verify(self.path)
        self.assertFalse(report.ok)
        self.assertEqual(report.line, 3)
        self.assertIn("changed after it was written", report.why)
        self.assertEqual(report.entries, 2)

    def test_a_line_with_its_own_hash_made_again_breaks_the_next_one(self):
        self.make(5)
        entry = json.loads(self.lines()[2])
        entry["hits"] = [{"rule": "cred.read", "severity": "medium"}]
        entry = ledger.seal(entry)
        lines = self.lines()
        lines[2] = ledger.dumps(entry).encode()
        self.write(lines)
        report = ledger.verify(self.path)
        self.assertEqual(report.line, 4)
        self.assertIn("does not follow the line before it", report.why)

    def test_a_line_taken_out_is_found_at_the_line_after_it(self):
        self.make(5)
        lines = self.lines()
        del lines[1]
        self.write(lines)
        report = ledger.verify(self.path)
        self.assertEqual(report.line, 2)
        self.assertIn("taken out, put in, or moved", report.why)

    def test_the_first_line_taken_out_is_found(self):
        self.make(3)
        self.write(self.lines()[1:])
        self.assertEqual(ledger.verify(self.path).line, 1)

    def test_two_lines_swapped_are_found(self):
        self.make(5)
        lines = self.lines()
        lines[1], lines[2] = lines[2], lines[1]
        self.write(lines)
        report = ledger.verify(self.path)
        self.assertFalse(report.ok)
        self.assertEqual(report.line, 2)

    def test_a_line_put_in_is_found(self):
        self.make(4)
        lines = self.lines()
        lines.insert(2, lines[1])
        self.write(lines)
        self.assertFalse(ledger.verify(self.path).ok)

    def test_a_line_that_is_not_json_or_not_ours_is_named(self):
        self.make(3)
        for junk in (b"not json", b"[]", b"{}", b'{"v":1}', b"\xff\xfe"):
            lines = self.lines()[:2] + [junk]
            self.write(lines)
            report = ledger.verify(self.path)
            self.assertFalse(report.ok, junk)
            self.assertEqual(report.line, 3)

    def test_a_blank_line_is_named(self):
        self.make(3)
        lines = self.lines()
        lines.insert(1, b"")
        self.write(lines)
        report = ledger.verify(self.path)
        self.assertEqual((report.ok, report.line), (False, 2))

    def test_a_field_added_to_a_line_is_found(self):
        self.make(2)
        self.edit(1, note="added")
        self.assertEqual(ledger.verify(self.path).line, 1)

    def test_a_number_that_is_not_the_place_is_found(self):
        self.make(2)
        entry = json.loads(self.lines()[0])
        entry["n"] = 7
        entry = ledger.seal(entry)
        lines = self.lines()
        lines[0] = ledger.dumps(entry).encode()
        self.write(lines)
        self.assertEqual(ledger.verify(self.path).line, 1)
        self.assertIn("numbered", ledger.verify(self.path).why)

    def test_a_line_cut_in_half_is_named_after_the_whole_ones(self):
        self.make(3)
        data = slurp(self.path)
        with open(self.path, "wb") as fh:
            fh.write(data[:-30])
        report = ledger.verify(self.path)
        self.assertFalse(report.ok)
        self.assertEqual(report.line, 3)
        self.assertEqual(report.entries, 2)
        self.assertIn("cut short", report.why)

    def test_the_first_fault_is_the_one_named(self):
        self.make(6)
        self.edit(5, hits=[{"rule": "cred.read", "severity": "medium"}])
        self.edit(2, hits=[{"rule": "cred.read", "severity": "medium"}])
        self.assertEqual(ledger.verify(self.path).line, 2)

    def test_a_broken_ledger_is_not_extended_and_stays_as_it_is(self):
        self.make(3)
        self.edit(2, hits=[{"rule": "cred.read", "severity": "medium"}])
        before = slurp(self.path)
        with self.assertRaises(ledger.LedgerError) as caught:
            ledger.record([item(9)], self.path)
        self.assertIn("does not verify", str(caught.exception))
        self.assertEqual(slurp(self.path), before)


class TheEndOfTheChain(_Dir):

    def test_lines_cut_off_the_end_are_found_only_against_a_saved_head(self):
        self.make(5)
        head = ledger.verify(self.path).head
        self.write(self.lines()[:3])
        shorter = ledger.verify(self.path)
        self.assertTrue(shorter.ok)                   # nothing in it is wrong
        self.assertEqual(shorter.entries, 3)
        cut = ledger.verify(self.path, head=head)
        self.assertFalse(cut.ok)
        self.assertIn("cut off its end", cut.why)
        self.assertEqual(cut.line, 3)

    def test_the_saved_head_fits_the_untouched_file(self):
        self.make(5)
        head = ledger.verify(self.path).head
        self.assertTrue(ledger.verify(self.path, head=head).ok)

    def test_lines_added_to_the_end_are_found_against_a_saved_head(self):
        self.make(3)
        head = ledger.verify(self.path).head
        ledger.record([item(8)], self.path)
        self.assertFalse(ledger.verify(self.path, head=head).ok)

    def test_a_ledger_made_again_whole_verifies_and_the_head_gives_it_away(self):
        # What a chain cannot do: someone who can write the file can write
        # all of it. Said in the docs, and the saved head is the answer.
        self.make(4)
        head = ledger.verify(self.path).head
        os.unlink(self.path)
        ledger.record([item(n, severity="medium") for n in range(1, 5)],
                      self.path, now=1)
        self.assertTrue(ledger.verify(self.path).ok)
        self.assertFalse(ledger.verify(self.path, head=head).ok)

    def test_a_head_against_an_empty_file_does_not_fit(self):
        self.assertFalse(ledger.verify(self.path, head="a" * 64).ok)

    def test_a_head_that_is_not_a_hash_is_refused(self):
        for bad in ("", "abc", "g" * 64, "A" * 64):
            with self.assertRaises(ledger.LedgerError):
                ledger.verify(self.path, head=bad)


class WhatItHolds(_Dir):

    def test_nothing_but_the_five_facts_reaches_the_file(self):
        items = ledger.actions([rec(n) for n in range(1, 6)])
        ledger.record(items, self.path)
        text = slurp(self.path).decode()
        self.assertNotIn(CANARY, text)
        self.assertNotIn(STRIPE, text)
        for raw in text.splitlines():
            entry = json.loads(raw)
            self.assertEqual(set(entry), {"v", "n", "prev", "time", "id", "agent",
                                          "at", "hits", "hash"})
            self.assertEqual(set(entry["hits"][0]), {"rule", "severity"})

    def test_a_field_an_adapter_adds_tomorrow_changes_nothing(self):
        plain = ledger.actions([rec(1)])
        more = rec(1)
        more["brand_new"] = CANARY
        more["hits"][0]["added_later"] = CANARY
        self.assertEqual(plain, ledger.actions([more]))

    def test_unknown_agents_rules_and_ids_are_left_out(self):
        got = ledger.actions([
            rec(1, source="not-an-agent"),
            rec(2, id=None),
            rec(3, id="short"),
            rec(4, hits=[{"rule": "no.such.rule", "severity": "high"}]),
            rec(5, hits=[{"rule": "cred.read", "severity": "dire"}]),
            rec(6), rec(6)])
        self.assertEqual([a["id"] for a in got], [rec(6)["id"]])

    def test_an_action_with_no_time_is_recorded_with_null(self):
        (got,) = ledger.actions([rec(1, timestamp=None)])
        self.assertIsNone(got["at"])
        ledger.record([got], self.path)
        self.assertTrue(ledger.verify(self.path).ok)

    def test_the_file_is_private_on_a_system_that_has_modes(self):
        self.make(1)
        if os.name == "posix":
            self.assertEqual(os.stat(self.path).st_mode & 0o077, 0)


class WritingAtOnce(_Dir):

    def test_threads_leave_one_unbroken_chain(self):
        errors = []

        def work(start):
            try:
                for n in range(start, start + 10):
                    ledger.record([item(n)], self.path)
            except Exception as exc:        # pragma: no cover
                errors.append(exc)

        threads = [threading.Thread(target=work, args=(1 + 100 * t,))
                   for t in range(6)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])
        report = ledger.verify(self.path)
        self.assertTrue(report.ok, report.why)
        self.assertEqual(report.entries, 60)

    def test_processes_leave_one_unbroken_chain(self):
        code = (
            "import sys; sys.path.insert(0, %r)\n"
            "from ranwhat import ledger\n"
            "start = int(sys.argv[2])\n"
            "for n in range(start, start + 8):\n"
            "    ledger.record([{'id': '%%016x' %% n, 'agent': 'codex',\n"
            "                    'at': None, 'hits': [{'rule': 'cred.read',\n"
            "                                           'severity': 'high'}]}],\n"
            "                  sys.argv[1])\n" % ROOT)
        procs = [subprocess.Popen([sys.executable, "-I", "-c", code, self.path,
                                   str(1000 * (p + 1))],
                                  stderr=subprocess.PIPE) for p in range(4)]
        for proc in procs:
            _out, err = proc.communicate(timeout=120)
            self.assertEqual(proc.returncode, 0, err.decode())
        report = ledger.verify(self.path)
        self.assertTrue(report.ok, report.why)
        self.assertEqual(report.entries, 32)

    def test_a_lock_left_by_a_process_that_died_is_taken_over(self):
        self.make(1)
        lock = self.path + ".lock"
        open(lock, "wb").close()
        old = time.time() - ledger.LOCK_STALE - 5
        os.utime(lock, (old, old))
        ledger.record([item(2)], self.path)
        self.assertEqual(ledger.verify(self.path).entries, 2)
        self.assertFalse(os.path.exists(lock))

    def test_a_lock_held_now_makes_it_wait_and_then_say_so(self):
        self.make(1)
        lock = self.path + ".lock"
        open(lock, "wb").close()
        self.addCleanup(lambda: os.path.exists(lock) and os.unlink(lock))
        with mock.patch.object(ledger, "LOCK_WAIT", 0.2):
            with self.assertRaises(ledger.LedgerError) as caught:
                ledger.record([item(2)], self.path)
        self.assertIn("Nothing was recorded", str(caught.exception))
        self.assertEqual(ledger.verify(self.path).entries, 1)

    def _denied(self, times):
        """os.open that refuses the lock file `times` times, as Windows does
        while another process is deleting it."""
        real, left = os.open, [times]

        def fake(name, *args, **kwargs):
            if str(name).endswith(".lock") and left[0]:
                left[0] -= 1
                raise PermissionError(13, "Permission denied", name)
            return real(name, *args, **kwargs)
        return mock.patch("ranwhat.ledger.os.open", fake)

    def test_on_windows_a_lock_being_deleted_is_waited_for(self):
        self.make(1)
        with mock.patch.object(ledger, "_WINDOWS", True), self._denied(3):
            ledger.record([item(2)], self.path)
        self.assertEqual(ledger.verify(self.path).entries, 2)

    def test_on_windows_a_lock_denied_for_good_says_so_in_the_end(self):
        self.make(1)
        with mock.patch.object(ledger, "_WINDOWS", True), \
                mock.patch.object(ledger, "LOCK_WAIT", 0.1), self._denied(10**6):
            with self.assertRaises(ledger.LedgerError) as caught:
                ledger.record([item(2)], self.path)
        self.assertIn("cannot lock", str(caught.exception))
        self.assertEqual(ledger.verify(self.path).entries, 1)

    def test_elsewhere_a_denied_lock_is_an_error_at_once(self):
        self.make(1)
        with mock.patch.object(ledger, "_WINDOWS", False), self._denied(1):
            with self.assertRaises(ledger.LedgerError):
                ledger.record([item(2)], self.path)
        self.assertEqual(ledger.verify(self.path).entries, 1)

    def test_the_lock_is_let_go_when_the_ledger_is_refused(self):
        self.make(2)
        self.edit(1, hits=[{"rule": "cred.read", "severity": "medium"}])
        with self.assertRaises(ledger.LedgerError):
            ledger.record([item(9)], self.path)
        self.assertFalse(os.path.exists(self.path + ".lock"))


@unittest.skipUnless(hasattr(os, "symlink") and os.name == "posix", "symlinks")
class ASymlink(_Dir):

    def test_a_ledger_that_is_a_link_is_not_read_or_written_through(self):
        target = os.path.join(self.dir, "elsewhere")
        open(target, "wb").close()
        os.symlink(target, self.path)
        with self.assertRaises(ledger.LedgerError):
            ledger.verify(self.path)
        with self.assertRaises(ledger.LedgerError):
            ledger.record([item(1)], self.path)
        self.assertEqual(os.path.getsize(target), 0)


class TheCommand(_Dir):

    def setUp(self):
        super().setUp()
        self.home = tempfile.mkdtemp(prefix="ranwhat-ledger-home-")
        self.addCleanup(lambda: __import__("shutil").rmtree(
            self.home, ignore_errors=True))
        env = mock.patch.dict(os.environ, {"RANWHAT_HOME": self.home})
        env.start()
        self.addCleanup(env.stop)
        self.path = ledger.default_path()

    def run_cli(self, *argv, records=None, counts=None):
        out, err = io.StringIO(), io.StringIO()
        scan = (records if records is not None else [], counts if counts is not None else {"claude-code": 3},
                {}, None)
        with mock.patch("sys.stdout", out), mock.patch("sys.stderr", err), \
                mock.patch("ranwhat.cli._watch_scan", return_value=scan):
            try:
                rc = cli._main(list(argv))
            except SystemExit as exc:
                rc = exc.code
        return rc, out.getvalue(), err.getvalue()

    def test_it_is_listed_with_the_other_commands(self):
        self.assertIn("ledger", [name for name, _ in cli.COMMANDS])

    def test_record_then_verify_then_show(self):
        rc, out, err = self.run_cli("ledger", "record",
                                    records=[rec(1), rec(2)])
        self.assertEqual(rc, 0, err)
        self.assertIn("Recorded 2 new actions", out)
        head = ledger.verify().head
        self.assertIn(head, out)
        rc, out, err = self.run_cli("ledger", "verify")
        self.assertEqual(rc, 0)
        self.assertIn("2 lines", out)
        rc, out, err = self.run_cli("ledger", "verify", "--head", head)
        self.assertEqual(rc, 0)
        rc, out, err = self.run_cli("ledger", "show")
        self.assertEqual(rc, 0)
        self.assertIn("cred.read:critical", out)
        self.assertNotIn(CANARY, out)

    def test_bare_ledger_verifies(self):
        rc, out, err = self.run_cli("ledger")
        self.assertEqual(rc, 0)
        self.assertIn("no ledger yet", out)

    def test_a_broken_ledger_exits_3_and_json_says_where(self):
        self.run_cli("ledger", "record", records=[rec(1), rec(2), rec(3)])
        lines = slurp(self.path).split(b"\n")[:-1]
        del lines[1]
        with open(self.path, "wb") as fh:
            fh.write(b"\n".join(lines) + b"\n")
        rc, out, err = self.run_cli("ledger", "verify")
        self.assertEqual(rc, cli.FAIL_STATUS)
        self.assertIn("does not verify: line 2", out)
        rc, out, err = self.run_cli("ledger", "verify", "--json")
        self.assertEqual(rc, cli.FAIL_STATUS)
        doc = json.loads(out)
        self.assertEqual((doc["ok"], doc["broken_at_line"]), (False, 2))

    def test_a_cut_end_exits_3_against_the_saved_head(self):
        self.run_cli("ledger", "record", records=[rec(1), rec(2), rec(3)])
        head = ledger.verify().head
        lines = slurp(self.path).split(b"\n")[:-1]
        with open(self.path, "wb") as fh:
            fh.write(b"\n".join(lines[:2]) + b"\n")
        self.assertEqual(self.run_cli("ledger", "verify")[0], 0)
        self.assertEqual(self.run_cli("ledger", "verify", "--head", head)[0],
                         cli.FAIL_STATUS)

    def test_record_into_a_broken_ledger_exits_1_and_changes_nothing(self):
        self.run_cli("ledger", "record", records=[rec(1), rec(2)])
        with open(self.path, "ab") as fh:
            fh.write(b"junk\n")
        before = slurp(self.path)
        rc, out, err = self.run_cli("ledger", "record", records=[rec(5)])
        self.assertEqual(rc, 1)
        self.assertIn("nothing was added", err)
        self.assertEqual(slurp(self.path), before)

    def test_no_history_exits_2_and_writes_nothing(self):
        rc, out, err = self.run_cli("ledger", "record", counts={})
        self.assertEqual(rc, 2)
        self.assertIn("Nothing was recorded", err)
        self.assertFalse(os.path.exists(self.path))

    def test_the_ignore_file_keeps_an_action_out(self):
        ignore = os.path.join(self.home, "ign")
        slurp(ignore, create=True)
        keep = rec(1)
        with mock.patch("ranwhat.ignore.Ignore.split",
                        side_effect=lambda records: [
                            r for r in records if r["id"] != keep["id"]]):
            rc, out, err = self.run_cli("ledger", "record", "--ignore", ignore,
                                        records=[keep, rec(2)])
        self.assertEqual(rc, 0, err)
        self.assertEqual([e["id"] for e in ledger.entries()], [rec(2)["id"]])

    def test_the_wrong_word_or_flag_is_refused(self):
        for argv in (("ledger", "wipe"), ("ledger", "record", "--head", "a" * 64),
                     ("watch", "--head", "a" * 64),
                     ("ledger", "verify", "--ignore", "x"),
                     ("ledger", "record", "--apply")):
            rc, out, err = self.run_cli(*argv)
            self.assertEqual(rc, 2, argv)

    def test_watch_still_takes_no_path_but_ledger_takes_its_word(self):
        rc, out, err = self.run_cli("watch", "verify")
        self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
