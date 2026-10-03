"""What the generic masker (ranwhat/sources/_rewrite.py) checks before it
replaces a file, where the check used to give up and accept the change.

A line nested deeper than Python can read or walk was taken for one that
does not parse, and anything the mask did to it was installed: a line left
unreadable on 3.9, a key deleted on 3.14, a copy of the value left behind
on both. And on Windows a file with the read-only attribute was reported
as in use, which running clean again never changes.

Everything runs in temp directories with synthetic secrets, written as
adjacent literals.
"""
import json
import os
import shutil
import stat
import sys
import tempfile
import time
import unittest
from unittest import mock

TESTS = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(TESTS))

from ranwhat import clean  # noqa: E402
from ranwhat.sources import _rewrite  # noqa: E402
from ranwhat.sources.base import MaskResult  # noqa: E402

SECRET = "sk_" "live_" "Zq8vR2mT6yLp4WcN0sXe7HbJ"
# A quote, a backslash, non-ASCII and Go's escapes: every encoding differs.
PASSWORD = "pw" '"' "\\" "ä" "&<>" " " "Tq9" "vX2r"

# 600 levels: both Pythons' json read it, and neither walks it. 2000: 3.9's
# json cannot read it, 3.14's can.
DEPTHS = (600, 2000)
# 3.9 compares JSON in fewer levels than it opens it: from about 330 to 490
# levels of objects, JSON in a string can be opened and not compared.
OPENED_NOT_COMPARED = range(100, 1001, 15)


def _marker(value):
    return clean.REDACTION % clean._fingerprint(value)


def _nest(depth):
    return '{"a":' * depth + "1" + "}" * depth


def _bytes(value):
    """The value's UTF-8 bytes as the inside of a compact JSON list."""
    return ",".join(str(b) for b in value.encode("utf-8"))


class TooDeep(unittest.TestCase):

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="rw-checks-")
        self.addCleanup(shutil.rmtree, self.dir, True)
        p = mock.patch.object(clean, "BACKUP_ROOT", os.path.join(self.dir, "bk"))
        p.start()
        self.addCleanup(p.stop)

    def _write(self, data, name="deep.jsonl"):
        path = os.path.join(self.dir, name)
        with open(path, "wb") as fh:
            fh.write(data.encode("utf-8"))
        when = time.time() - 3600
        os.utime(path, (when, when))
        return path

    def _read(self, path):
        with open(path, "rb") as fh:
            return fh.read().decode("utf-8")

    def _refused(self, doc, values, byte_arrays=False):
        path = self._write(doc)
        result = _rewrite.rewrite_file(path, values, "jsonl", byte_arrays=byte_arrays)
        self.assertEqual((result.changed, result.skipped),
                         (False, _rewrite.ALTERED))
        # Not assertEqual: a diff of these lines is long.
        self.assertTrue(self._read(path) == doc, "the file changed")
        self.assertFalse(os.path.exists(clean.BACKUP_ROOT))

    def test_a_line_too_deep_for_json_to_read_is_refused_when_the_mask_breaks_it(self):
        """A value ending in a backslash, masked where an escaped quote
        follows its copy, leaves the line unreadable. On 3.9 json cannot
        read the line at 2000 levels, and it was installed broken."""
        value = "Qm7vX2pL9sK4" "\\"
        for depth in DEPTHS:
            with self.subTest(depth=depth):
                self._refused('{"key":%s}\n{"t":"Qm7vX2pL9sK4\\"tail","d":%s}\n'
                              % (json.dumps(value), _nest(depth)), [value])

    def test_a_string_holding_json_too_deep_to_walk_does_not_stop_the_line_being_checked(self):
        """A value spanning two strings, masked in the raw text, deletes a
        key. The line beside it held JSON too deep to walk, so the whole
        line went unchecked and the key was lost."""
        value = 'abc","b":"def-' "Qw7Zr"
        for inner in ("[" * 2000 + "]" * 2000, _nest(600), _nest(2000)):
            with self.subTest(depth=inner.count("[") or inner.count("{")):
                self._refused('{"a":"abc","b":"def-Qw7Zr","output":%s}\n'
                              % json.dumps(inner), [value])

    def test_a_copy_hidden_in_an_escape_on_a_line_too_deep_to_walk_is_noticed(self):
        """A copy whose first letter is written as an escape is in no
        encoding the mask replaces. On a line too deep to walk it was
        never looked for, and the file was called masked with it left."""
        hidden = "\\u0073" + SECRET[1:]
        for depth in DEPTHS:
            with self.subTest(depth=depth):
                self._refused('{"out":"KEY=%s"}\n{"s":"%s","d":%s}\n'
                              % (SECRET, hidden, _nest(depth)), [SECRET])

    def test_a_copy_in_a_byte_list_on_a_line_too_deep_to_walk_is_noticed(self):
        """Grok Build writes text as lists of bytes. One spaced out is in no
        form the mask replaces, and on a deep line it was never read."""
        spaced = "[%s]" % ", ".join(str(b) for b in SECRET.encode("ascii"))
        for depth in DEPTHS:
            with self.subTest(depth=depth):
                self._refused('{"out":"KEY=%s"}\n{"b":%s,"d":%s}\n'
                              % (SECRET, spaced, _nest(depth)), [SECRET],
                              byte_arrays=True)

    def test_a_string_holding_json_deep_enough_to_open_but_not_to_compare_is_masked(self):
        """Such a string was opened, then could not be compared, and the
        file was refused with the key left in it. It is compared as text."""
        for depth in OPENED_NOT_COMPARED:
            with self.subTest(depth=depth):
                doc = '{"out":%s,"s":"KEY=%s"}\n' % (json.dumps(_nest(depth)), SECRET)
                path = self._write(doc)
                result = _rewrite.rewrite_file(path, [SECRET], "jsonl")
                self.assertEqual((result.changed, result.skipped), (True, None))
                self.assertTrue(self._read(path) == doc.replace(
                    SECRET, _marker(SECRET)), "a byte other than the secret changed")

    def test_a_key_deleted_beside_json_deep_enough_to_open_but_not_to_compare_is_noticed(self):
        """Only that string is compared as text: in the JSON of another,
        a key the mask deletes is still noticed."""
        value = 'abc","b":"def-' "Qw7Zr"
        for depth in OPENED_NOT_COMPARED:
            with self.subTest(depth=depth):
                self._refused('{"out":%s,"args":%s}\n' % (
                    json.dumps(_nest(depth)),
                    json.dumps('{"a":"abc","b":"def-Qw7Zr"}')), [value])

    def test_a_line_too_deep_to_walk_is_masked_when_only_its_strings_change(self):
        """Checked without walking it, a deep line whose strings (and, for
        a byte-array format, lists of bytes) alone hold the value is still
        masked, byte for byte."""
        body = json.dumps(PASSWORD)[1:-1]
        for depth in DEPTHS + (100000,):
            for byte_arrays in (False, True):
                with self.subTest(depth=depth, byte_arrays=byte_arrays):
                    doc = ('{"note":"caf\\u00e9","s":"KEY=%s","b":[10,%s],"d":%s}\n'
                           '{"args":%s,"s":"PASS=%s"}\n'
                           % (body, _bytes(PASSWORD), _nest(depth),
                              json.dumps(_nest(depth)), body))
                    expected = doc.replace(body, _marker(PASSWORD))
                    if byte_arrays:
                        expected = expected.replace(_bytes(PASSWORD),
                                                    _bytes(_marker(PASSWORD)))
                    path = self._write(doc)
                    result = _rewrite.rewrite_file(path, [PASSWORD], "jsonl",
                                                   byte_arrays=byte_arrays)
                    self.assertEqual((result.changed, result.skipped), (True, None))
                    self.assertTrue(self._read(path) == expected,
                                    "a byte other than the secret changed")


class WindowsReadOnly(unittest.TestCase):
    """Windows' stat reports the read-only attribute as a mode with no
    write bits, and MoveFileEx will not replace such a file. Both are
    simulated here, so this runs everywhere."""

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="rw-checks-")
        self.addCleanup(shutil.rmtree, self.dir, True)
        p = mock.patch.object(clean, "BACKUP_ROOT", os.path.join(self.dir, "bk"))
        p.start()
        self.addCleanup(p.stop)
        self.path = os.path.join(self.dir, "ro.jsonl")
        self.doc = ('{"out":"KEY=%s"}\n' % SECRET).encode("ascii")
        with open(self.path, "wb") as fh:
            fh.write(self.doc)
        when = time.time() - 3600
        os.utime(self.path, (when, when))
        os.chmod(self.path, stat.S_IREAD)
        self.addCleanup(os.chmod, self.path, stat.S_IREAD | stat.S_IWRITE)

    def _read(self):
        with open(self.path, "rb") as fh:
            return fh.read()

    def _writable(self):
        return bool(os.stat(self.path).st_mode & stat.S_IWRITE)

    def test_a_read_only_file_is_masked_and_left_read_only(self):
        real = os.replace

        def move_file_ex(src, dst):
            if not os.stat(dst).st_mode & stat.S_IWRITE:
                raise PermissionError(13, "Access is denied")
            real(src, dst)
        with mock.patch.object(_rewrite, "_WINDOWS", True), \
                mock.patch.object(_rewrite.os, "replace", side_effect=move_file_ex):
            result = _rewrite.rewrite_file(self.path, [SECRET], "jsonl")
        self.assertEqual((result.changed, result.skipped), (True, None))
        self.assertEqual(self._read(), self.doc.replace(
            SECRET.encode("ascii"), _marker(SECRET).encode("ascii")))
        self.assertFalse(self._writable(), "the file is no longer read-only")

    def test_a_read_only_file_held_open_is_in_use_and_stays_read_only(self):
        with mock.patch.object(_rewrite, "_WINDOWS", True), \
                mock.patch.object(_rewrite.os, "replace",
                                  side_effect=PermissionError(13, "in use")):
            result = _rewrite.rewrite_file(self.path, [SECRET], "jsonl")
        self.assertEqual(result, MaskResult(self.path, skipped=_rewrite.IN_USE))
        self.assertEqual(self._read(), self.doc)
        self.assertFalse(self._writable(), "the file is no longer read-only")


if __name__ == "__main__":
    unittest.main()
