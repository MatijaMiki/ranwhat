"""check and watch never print a value clean finds anywhere in the history.

They knew such a value only through clean.known_values, which looked the
stretches of what they showed up in the transcripts, within a budget: on a
real history of 485 MB only 8 of about 195 stretches were looked up, and a
stretch could not isolate a value glued to letters, digits or ._- inside a
longer run. watch and watch --json printed 13 to 15 values that clean finds
and check masks. They now keep an index of every value clean finds in every
transcript, as salted fingerprints, and mask each copy of one wherever it
starts. Every value here is synthetic, and none holds four characters in a
row that a hex digest could hold, so no digest can look like a piece of one.
"""
import io
import json
import os
import random
import shutil
import stat
import string
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import growth  # noqa: E402
import isolated_home  # noqa: E402,F401
from ranwhat import clean, cli, known, watch  # noqa: E402

PW = "Hq7xT2mVp9LwZr4kNd"
PW2 = "Rw4KzQ8nVy2TmXp6Jh"
STRIPE = "sk_" "live_" "Tq9WzR4mXk7PvN2yHs8LgJ5c"
SCRIPT = "./deploy.sh prod %s -e 'DROP DATABASE prod '"
# Letters, digits and ._- on each side: one run, which no stretch split.
GLUES = (("xY3", "4Kq"), ("a.", ".b"), ("9_", "_9"), ("-", "-"),
         ("ab7._-", "-_.9z"), ("Q", "7"))


def _tempdir(test, prefix):
    d = tempfile.mkdtemp(prefix=prefix)
    test.addCleanup(shutil.rmtree, d, True)
    return d


def _stamp(age):
    return time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime(time.time() - age))


def _call(i, command, age):
    return {"type": "assistant", "timestamp": _stamp(age), "message": {"content": [
        {"type": "tool_use", "id": "t%s" % i, "name": "Bash",
         "input": {"command": command}}]}}


def _result(i, text, age):
    return {"type": "user", "timestamp": _stamp(age), "message": {"content": [
        {"type": "tool_result", "tool_use_id": "t%s" % i, "content": text}]}}


def _write(path, rows, age, mode="w"):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, mode, encoding="utf-8") as fh:
        fh.write("".join(json.dumps(row) + "\n" for row in rows))
    t = time.time() - age
    os.utime(path, (t, t))
    return path


def _read(name, value, age, key="DB_PASSWORD"):
    return [_call(name, "cat .env", age), _result(name, "%s=%s\n" % (key, value), age)]


def _typed(name, value, age, glue=GLUES[0]):
    return [_call(name, SCRIPT % (glue[0] + value + glue[1]), age),
            _result(name, "ok", age)]


def _run(argv):
    out, err = io.StringIO(), io.StringIO()
    with mock.patch("sys.stdout", out), mock.patch("sys.stderr", err):
        try:
            rc = cli.main(argv)
        except SystemExit as exit:
            rc = exit.code
    return rc, out.getvalue(), err.getvalue()


def _shown(out):
    try:
        return json.dumps(json.loads(out), ensure_ascii=False)
    except ValueError:
        return out


def _pieces(value, n):
    return {value[i:i + n] for i in range(len(value) - n + 1)}


class _FakeTTY(io.StringIO):
    def isatty(self):
        return True


class _Index(unittest.TestCase):
    """Each test with a state directory of its own, for its index."""

    def setUp(self):
        self.home = _tempdir(self, "known-home-")
        self.state = _tempdir(self, "known-oc-")
        backups = os.path.join(_tempdir(self, "known-bk-"), "backups")
        for patch in (mock.patch.dict(os.environ, {"RANWHAT_HOME": self.home,
                                                   "NO_COLOR": "1"}),
                      mock.patch.object(clean, "BACKUP_ROOT", backups)):
            patch.start()
            self.addCleanup(patch.stop)

    def root(self):
        root = _tempdir(self, "known-root-")
        return root, os.path.join(root, "-Users-a-app")

    def reports(self, root, *extra):
        where = ["--root", root, "--state-dir", self.state] + list(extra)
        return (["check"] + where, ["check", "--json"] + where,
                ["watch"] + where, ["watch", "--json"] + where)

    def assertNeverShown(self, root, value, *extra):
        masked = clean.DISPLAY_MASK % clean._hint(value)
        for argv in self.reports(root, *extra):
            with self.subTest(argv=argv[:2] + list(extra)):
                rc, out, err = _run(argv)
                self.assertIn(rc, (0, None))
                shown = out + err
                for piece in _pieces(value, 6):
                    self.assertNotIn(piece, shown)
                self.assertIn(masked, _shown(out))

    def rescans(self):
        """The transcripts the index reads again, run by run: by its own
        read (clean.values_in), or, for check, by clean's read for secrets,
        which it takes in place of one (known.Index.take)."""
        read = []
        real = known.Index.update

        def spy(index, *a, **k):
            before = dict(index.files)
            matcher = real(index, *a, **k)
            read.extend(sorted(os.path.basename(path) for path, entry in index.files.items()
                               if before.get(path, (None, None))[:2] != entry[:2]))
            return matcher
        patch = mock.patch.object(known.Index, "update", spy)
        patch.start()
        self.addCleanup(patch.stop)
        return read

    def index_files(self):
        found = []
        for top, _dirs, files in os.walk(self.home):
            found += [os.path.join(top, name) for name in files]
        return found


class GluedInsideALongerRun(_Index):
    """smbclient -U admin%PASSWORD and ./deploy.sh xY3PASSWORD4Kq: the value
    is one stretch with what is glued to it, and watch printed it whole."""

    def test_never_shown_whatever_is_glued_to_it(self):
        for glue in GLUES:
            root, project = self.root()
            _write(os.path.join(project, "sessA.jsonl"), _read(1, PW, 2000), 2000)
            _write(os.path.join(project, "sessB.jsonl"), _typed(2, PW, 600, glue), 600)
            with self.subTest(glue=glue):
                self.assertNeverShown(root, PW)

    def test_nor_in_the_same_transcript(self):
        for glue in GLUES:
            root, project = self.root()
            _write(os.path.join(project, "sess.jsonl"),
                   _read(1, PW, 2000) + _typed(2, PW, 600, glue), 600)
            with self.subTest(glue=glue):
                self.assertNeverShown(root, PW)


class FoundOnlyOutsideTheWindow(_Index):
    """Read in a transcript --days leaves out, typed glued in one it reads."""

    def test_never_shown(self):
        for read_age, days in ((45 * 86400, ()), (5 * 86400, ("--days", "1"))):
            root, project = self.root()
            _write(os.path.join(project, "old.jsonl"), _read(1, PW, read_age), read_age)
            _write(os.path.join(project, "new.jsonl"), _typed(2, PW, 600), 600)
            with self.subTest(days=days):
                self.assertNeverShown(root, PW, *days)


class KnownFromTheIndexAlone(_Index):
    """The transcript the value was found in is not read again: the index
    built on an earlier run is what knows it."""

    def test_a_file_untouched_since_the_index_was_built(self):
        root, project = self.root()
        _write(os.path.join(project, "sessA.jsonl"), _read(1, PW, 5 * 86400), 5 * 86400)
        _write(os.path.join(project, "other.jsonl"), [_call(3, "ls", 3000)], 3000)
        read = self.rescans()
        _run(["watch", "--root", root, "--state-dir", self.state])
        self.assertEqual(sorted(read), ["other.jsonl", "sessA.jsonl"])
        del read[:]
        _write(os.path.join(project, "sessB.jsonl"), _typed(2, PW, 600, ("ab7._-", "-_.9z")), 600)
        self.assertNeverShown(root, PW, "--days", "1")
        self.assertEqual(read, ["sessB.jsonl"])


class AChangedFileIsReadAgain(_Index):

    def test_appended(self):
        root, project = self.root()
        sess = _write(os.path.join(project, "sessA.jsonl"), _read(1, PW, 3000), 3000)
        read = self.rescans()
        _run(["watch", "--root", root, "--state-dir", self.state])
        self.assertEqual(read, ["sessA.jsonl"])
        del read[:]
        _write(sess, _read(2, PW2, 2000, key="API_TOKEN"), 2000, mode="a")
        _write(os.path.join(project, "sessB.jsonl"), _typed(3, PW2, 600, ("Q", "7")), 600)
        self.assertNeverShown(root, PW2)
        self.assertEqual(sorted(read), ["sessA.jsonl", "sessB.jsonl"])

    def test_masked_by_clean_apply(self):
        """clean --apply --days 1 masks the copy the value was found by and
        leaves the one typed in a transcript older than its window. The
        file it rewrote is read again, and its mask still says which
        value it took the place of."""
        root, project = self.root()
        old = _write(os.path.join(project, "old.jsonl"),
                     _typed(1, PW, 40 * 86400, ("xY3", "4Kq")), 40 * 86400)
        sess = _write(os.path.join(project, "sessA.jsonl"), _read(2, PW, 600), 600)
        read = self.rescans()
        _run(["watch", "--root", root, "--state-dir", self.state, "--days", "400"])
        self.assertEqual(sorted(read), ["old.jsonl", "sessA.jsonl"])
        del read[:]
        _run(["clean", "--apply", "--days", "1", "--root", root])
        with open(sess, encoding="utf-8") as fh:
            self.assertNotIn(PW, fh.read())
        with open(old, encoding="utf-8") as fh:
            self.assertIn(PW, fh.read())
        self.assertNeverShown(root, PW, "--days", "400")
        self.assertEqual(read, ["sessA.jsonl"])


class MaskedBeforeTheIndexKnewIt(_Index):
    """clean masks the copy a value was found by before check or watch
    ever ran, and leaves one typed glued in a transcript older than its
    window. Each mask it makes is kept in the index, by its fingerprint,
    so the first index of the history knows what the mask took the place
    of."""

    def masked_first(self, how):
        root, project = self.root()
        old = _write(os.path.join(project, "old.jsonl"),
                     _typed(1, PW, 40 * 86400, ("ab7._-", "-_.9z")), 40 * 86400)
        sess = _write(os.path.join(project, "sessA.jsonl"), _read(2, PW, 600), 600)
        if how == "apply":
            _run(["clean", "--apply", "--days", "1", "--root", root])
        else:
            replies = iter(("mask all", "quit"))
            with mock.patch("sys.stdin.isatty", return_value=True), \
                 mock.patch("builtins.input", lambda prompt="": next(replies)):
                _run(["clean", "--days", "1", "--root", root])
        with open(sess, encoding="utf-8") as fh:
            self.assertNotIn(PW, fh.read())
        with open(old, encoding="utf-8") as fh:
            self.assertIn(PW, fh.read())
        return root

    def test_clean_apply(self):
        self.assertNeverShown(self.masked_first("apply"), PW, "--days", "400")

    def test_the_review_s_mask(self):
        self.assertNeverShown(self.masked_first("review"), PW, "--days", "400")

    def test_a_dry_run_keeps_nothing(self):
        root, project = self.root()
        _write(os.path.join(project, "sessA.jsonl"), _read(2, PW, 600), 600)
        _run(["clean", "--no-interactive", "--root", root])
        self.assertEqual(self.index_files(), [])


class KeptWhileAMaskHoldsIt(_Index):
    """A transcript read while only its mask said a value was there, and
    the one the value was found in deleted since: the mask still holds it."""

    def test_the_transcript_it_was_found_in_is_deleted(self):
        root, project = self.root()
        mask = clean.REDACTION % clean._fingerprint(PW)
        _write(os.path.join(project, "masked.jsonl"), _read(1, mask, 3000), 3000)
        self.assertFalse(known.Index.open(root).update().spans("x9%sQ7" % PW))
        found = _write(os.path.join(project, "found.jsonl"), _read(2, PW, 2000), 2000)
        self.assertTrue(known.Index.open(root).update().spans("x9%sQ7" % PW))
        os.remove(found)
        index = known.Index.open(root)
        self.assertEqual(index.update().spans("x9%sQ7" % PW), [(2, 2 + len(PW))])
        self.assertEqual(index.rescanned, 0)


class TheIndexHoldsNoValue(_Index):

    def test_no_piece_of_any_value(self):
        root, project = self.root()
        _write(os.path.join(project, "sessA.jsonl"),
               _read(1, PW, 2000) + _read(2, PW2, 2000, key="API_TOKEN")
               + [_call(3, "cat config.env", 2000),
                  _result(3, "STRIPE_KEY=%s\n" % STRIPE, 2000)], 2000)
        _write(os.path.join(project, "sessB.jsonl"),
               _typed(4, PW, 600) + _typed(5, PW2, 600, ("Q", "7")), 600)
        for value in (PW, PW2, STRIPE):
            self.assertIn(value, [v for v, _l in clean.find_secrets(
                "DB_PASSWORD=%s and padding" % value)])
        for argv in self.reports(root):
            _run(argv)
        _run(["clean", "--apply", "--root", root])
        _run(["watch", "--root", root, "--state-dir", self.state])
        files = self.index_files()
        self.assertTrue(files)
        for path in files:
            with open(path, "rb") as fh:
                data = fh.read().decode("latin-1")
            for value in (PW, PW2, STRIPE):
                for piece in _pieces(value, 4):
                    with self.subTest(path=os.path.basename(path), piece=piece):
                        self.assertNotIn(piece, data)


class ADamagedIndexIsRebuilt(_Index):

    DAMAGE = (b"", b"{", b"not json at all", b"\x00\xff\xfe garbage", b"[]",
              b'{"version": 999}', b"null")

    def test_each_damage(self):
        root, project = self.root()
        _write(os.path.join(project, "sessA.jsonl"), _read(1, PW, 3000), 3000)
        _write(os.path.join(project, "sessB.jsonl"), _typed(2, PW, 600, ("9_", "_9")), 600)
        _run(["watch", "--root", root, "--state-dir", self.state])
        index = known.Index.open(root)
        with open(index.path, encoding="utf-8") as fh:
            good = json.load(fh)
        damaged = []
        for damage in self.DAMAGE:
            damaged.append(damage)
        for change in (lambda d: d.update(version=d["version"] + 1),
                       lambda d: d.update(key="00" * 8),
                       lambda d: d.update(values={"zz": 1}),
                       lambda d: d.update(files={"x": "y"}),
                       lambda d: d.update(files={k: [v[0], v[1], ["nope"], v[3]]
                                                 for k, v in d["files"].items()}),
                       lambda d: d.update(values={k: [v[0], True, v[2]]
                                                  for k, v in d["values"].items()})):
            doc = json.loads(json.dumps(good))
            change(doc)
            damaged.append(json.dumps(doc).encode("utf-8"))
        for damage in damaged:
            with open(index.path, "wb") as fh:
                fh.write(damage)
            with self.subTest(damage=damage[:40]):
                self.assertNeverShown(root, PW)
                with open(index.path, encoding="utf-8") as fh:
                    doc = json.load(fh)
                self.assertEqual(doc["version"], known.VERSION)
                self.assertEqual(len(doc["files"]), 2)

    def test_a_damaged_key(self):
        root, project = self.root()
        _write(os.path.join(project, "sessA.jsonl"), _read(1, PW, 3000), 3000)
        _write(os.path.join(project, "sessB.jsonl"), _typed(2, PW, 600), 600)
        _run(["watch", "--root", root, "--state-dir", self.state])
        key = os.path.join(known.index_dir(), "key")
        for damage in (b"", b"short", b"x" * 64):
            with open(key, "wb") as fh:
                fh.write(damage)
            with self.subTest(damage=damage):
                self.assertNeverShown(root, PW)
                with open(key, "rb") as fh:
                    self.assertEqual(len(fh.read()), 32)


class AStateDirThatCannotBeWritten(_Index):
    """Nothing can be kept: everything is read again, in memory, and the
    report says nothing about it."""

    def check_quiet(self, home):
        root, project = self.root()
        _write(os.path.join(project, "sessA.jsonl"), _read(1, PW, 3000), 3000)
        _write(os.path.join(project, "sessB.jsonl"), _typed(2, PW, 600), 600)
        with mock.patch.dict(os.environ, {"RANWHAT_HOME": home}):
            self.assertNeverShown(root, PW)
            for argv in self.reports(root):
                rc, out, err = _run(argv)
                self.assertEqual((rc, err), (0, ""))
                if "--json" in argv:
                    json.loads(out)

    def test_a_file_where_the_directory_would_be(self):
        home = os.path.join(_tempdir(self, "known-file-"), "home")
        with open(home, "w", encoding="utf-8") as fh:
            fh.write("not a directory")
        self.check_quiet(home)
        with open(home, encoding="utf-8") as fh:
            self.assertEqual(fh.read(), "not a directory")

    @unittest.skipIf(os.name == "nt" or (hasattr(os, "geteuid") and os.geteuid() == 0),
                     "needs POSIX permissions that bind this user")
    def test_a_directory_without_write_permission(self):
        home = _tempdir(self, "known-ro-")
        os.chmod(home, 0o500)
        self.addCleanup(os.chmod, home, 0o700)
        self.check_quiet(home)
        self.assertEqual(os.listdir(home), [])


class ASecondRunReadsNothingAgain(_Index):

    def test_counted(self):
        root, project = self.root()
        _write(os.path.join(project, "sessA.jsonl"), _read(1, PW, 3000), 3000)
        _write(os.path.join(project, "sessB.jsonl"), _typed(2, PW, 600), 600)
        read = self.rescans()
        _run(["watch", "--root", root, "--state-dir", self.state])
        self.assertEqual(len(read), 2)
        for argv in self.reports(root) + self.reports(root, "--days", "1"):
            del read[:]
            with self.subTest(argv=argv):
                _run(argv)
                self.assertEqual(read, [])


@unittest.skipIf(os.name == "nt", "POSIX modes")
class OnlyTheOwnerCanReadIt(_Index):

    def test_0600(self):
        root, project = self.root()
        _write(os.path.join(project, "sessA.jsonl"), _read(1, PW, 3000), 3000)
        _run(["watch", "--root", root, "--state-dir", self.state])
        files = self.index_files()
        self.assertEqual(len(files), 2)            # the key, and the index
        for path in files:
            self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600, path)
        self.assertEqual(stat.S_IMODE(os.stat(known.index_dir()).st_mode), 0o700)


class PayloadHashIsNoOracle(_Index):
    """payload_hash is a hash of the call. Over a call that types a known
    value, a guess at the value could be checked against it."""

    def test_hashed_masked(self):
        root, project = self.root()
        typed = SCRIPT % ("xY3" + PW + "4Kq")
        _write(os.path.join(project, "sessA.jsonl"), _read(1, PW, 3000), 3000)
        _write(os.path.join(project, "sessB.jsonl"), _typed(2, PW, 600), 600)
        oracle = watch._hash(json.dumps({"command": typed}, sort_keys=True,
                                        ensure_ascii=False))
        masked = typed.replace(PW, clean.DISPLAY_MASK % clean._hint(PW))
        expected = watch._hash(json.dumps({"command": masked}, sort_keys=True,
                                          ensure_ascii=False))
        for argv in (["watch", "--json"], ["check", "--json"]):
            _rc, out, _err = _run(argv + ["--root", root, "--state-dir", self.state])
            doc = json.loads(out)
            records = doc if isinstance(doc, list) else doc["actions"]
            hashes = [r["payload_hash"] for r in records if r["tool_name"] == "Bash"
                      and "DROP DATABASE" in r["hits"][0]["evidence"]]
            with self.subTest(argv=argv):
                self.assertEqual(hashes, [expected])
                self.assertNotEqual(hashes, [oracle])


class IndexingSaysWhatItIs(_Index):
    """The first run reads every transcript for its secrets, and says so."""

    def stderr(self, root, *argv):
        err = _FakeTTY()
        with mock.patch.dict(os.environ, {"TERM": "xterm"}), \
             mock.patch("sys.stdout", io.StringIO()), mock.patch("sys.stderr", err):
            cli.main(list(argv) + ["--root", root, "--state-dir", self.state])
        return err.getvalue()

    def test_first_run_then_none(self):
        root, project = self.root()
        _write(os.path.join(project, "sessA.jsonl"), _read(1, PW, 3000), 3000)
        _write(os.path.join(project, "sessB.jsonl"), _typed(2, PW, 600), 600)
        err = self.stderr(root, "watch")
        self.assertTrue(err.startswith(
            "\r  indexing secrets (first run) 1/2\033[K"
            "\r  indexing secrets (first run) 2/2\033[K"), repr(err))
        self.assertNotIn("indexing", self.stderr(root, "watch"))
        _write(os.path.join(project, "sessC.jsonl"), _typed(3, PW, 500), 500)
        err = self.stderr(root, "watch")
        self.assertTrue(err.startswith("\r  indexing secrets 1/1\033[K"), repr(err))

    def test_check_indexes_what_its_window_leaves_out(self):
        """check's read for secrets indexes each transcript in its window:
        only those older than --days are read for the index after it."""
        root, project = self.root()
        _write(os.path.join(project, "sessA.jsonl"), _read(1, PW, 3000), 3000)
        _write(os.path.join(project, "sessB.jsonl"), _typed(2, PW, 600), 600)
        _write(os.path.join(project, "old.jsonl"), _read(3, PW2, 40 * 86400), 40 * 86400)
        self.assertEqual(self.stderr(root, "check"),
                         "\r  looking for secrets 1/2\033[K\r  looking for secrets 2/2\033[K"
                         "\r  indexing secrets (first run) 1/1\033[K"
                         "\r  checking actions 1/2\033[K\r  checking actions 2/2\033[K\r\033[K")
        self.assertNotIn("indexing", self.stderr(root, "check"))
        _write(os.path.join(project, "sessC.jsonl"), _typed(3, PW, 500), 500)
        self.assertNotIn("indexing", self.stderr(root, "check"))
        _write(os.path.join(project, "old.jsonl"), _read(4, PW, 40 * 86400), 40 * 86400,
               mode="a")
        err = self.stderr(root, "check")
        self.assertIn("\r  looking for secrets 3/3\033[K\r  indexing secrets 1/1\033[K", err)

    def test_never_in_json_nor_off_a_terminal(self):
        root, project = self.root()
        _write(os.path.join(project, "sessA.jsonl"), _read(1, PW, 3000), 3000)
        self.assertEqual(self.stderr(root, "watch", "--json"), "")
        os.remove(known.Index.open(root).path)
        _rc, _out, err = _run(["watch", "--root", root, "--state-dir", self.state])
        self.assertEqual(err, "")


class TheMatcher(unittest.TestCase):
    """Every copy of every value, wherever it starts, longest first, and
    copies that overlap all masked."""

    def test_overlapping_and_glued(self):
        long_value, inner = "Kp7Wz" + PW + "Tx4Q", PW[3:15]
        m = known.Matcher.of([long_value, inner, PW2])
        text = "a%sb %s.c x-%s_y %s" % (long_value, inner, PW2, PW2[:-1])
        out = m.mask(text)
        for value in (long_value, inner, PW2):
            self.assertNotIn(value, out)
        self.assertIn(PW2[:-1], out)        # not the whole value: not one
        self.assertEqual(out.count("<"), 3)

    def test_shorter_than_the_prefix(self):
        m = known.Matcher.of(["Zq9", PW])
        self.assertEqual(m.mask("xZq9y"), "x<%s>y" % clean._hint("Zq9"))

    def test_none(self):
        m = known.Matcher.of([])
        self.assertFalse(m)
        self.assertEqual(m.mask("anything"), "anything")


class MaskingGrowsWithTheText(growth.Assertions, unittest.TestCase):
    """Each place a value could start is asked once, and a value of each
    length that starts so: the cost grows with the text, and not with the
    number of keys that start alike times the number shown."""

    KEY = b"k" * 32

    def test_a_long_text(self):
        def build(n):
            return (known.Matcher.of([PW, PW2, STRIPE], key=self.KEY),
                    ("rm -rf /srv/x%s7 && echo done; " % PW) * n(4000))
        out = self.assertScalesLinearly(build, lambda a: a[0].mask(a[1]),
                                        rebuild=True)
        self.assertNotIn(PW, out)

    def test_many_keys_that_start_alike(self):
        rng = random.Random(20261002)
        alphabet = string.ascii_letters + string.digits

        def build(n):
            keys = ["sk_" "live_" + "".join(rng.choice(alphabet) for _ in range(24))
                    for _ in range(n(800))]
            return known.Matcher.of(keys, key=self.KEY), " ".join(keys), keys
        matcher, text, keys = build(lambda k: 50)
        self.assertEqual(matcher.mask(text).count("<"), len(keys))
        self.assertScalesLinearly(build, lambda a: a[0].mask(a[1]), rebuild=True)


class _Killed(BaseException):
    """The terminal closed on the review: nothing after the reply it was
    waiting for runs, as for SIGHUP, SIGTERM or SIGKILL."""


def _review(root, answer, *days):
    """clean's review over root, on a terminal, answered by answer(prompt)."""
    with mock.patch("sys.stdin.isatty", return_value=True), \
         mock.patch("builtins.input", answer):
        return _run(["clean", "--root", root] + list(days))


class TheReviewSMaskIsKeptAtOnce(_Index):
    """mask N in the review was kept in the index only once the review
    returned. Ended any other way, the terminal closed or the process
    killed, or with check or watch run while it was still open, the index
    never learned the value: the mask left in the transcript was all that
    knew it, and a copy the mask did not reach, glued to letters, was
    printed whole by check and watch on every later run."""

    def layout(self):
        root, project = self.root()
        old = _write(os.path.join(project, "old.jsonl"),
                     _typed(1, PW, 5 * 86400, ("old", "9")), 5 * 86400)
        sess = _write(os.path.join(project, "sessA.jsonl"), _read(2, PW, 43200), 43200)
        return root, old, sess

    def assertMasked(self, old, sess):
        with open(sess, encoding="utf-8") as fh:
            self.assertNotIn(PW, fh.read())
        with open(old, encoding="utf-8") as fh:
            self.assertIn(PW, fh.read())

    def test_the_review_never_returns(self):
        for command in ("mask 1", "mask all"):
            root, old, sess = self.layout()
            replies = iter((command,))

            def answer(prompt=""):
                for reply in replies:
                    return reply
                raise _Killed()
            with self.subTest(command=command):
                with self.assertRaises(_Killed):
                    _review(root, answer, "--days", "1")
                self.assertMasked(old, sess)
                self.assertNeverShown(root, PW)

    def test_check_and_watch_while_it_is_open(self):
        root, old, sess = self.layout()
        replies = iter(("mask 1", "look", "quit"))
        looked = []

        def answer(prompt=""):
            reply = next(replies)
            if reply == "look":
                self.assertMasked(old, sess)
                self.assertNeverShown(root, PW)
                looked.append(True)
                return "list"
            return reply
        _review(root, answer, "--days", "1")
        self.assertEqual(looked, [True])

    def test_clean_apply_is_kept_before_it_writes(self):
        """The index learns each value before a transcript loses it."""
        root, old, sess = self.layout()
        real = clean._backup

        def killed(path):
            real(path)
            raise _Killed()
        with mock.patch.object(clean, "_backup", killed):
            with self.assertRaises(_Killed):
                _run(["clean", "--apply", "--days", "1", "--root", root])
        index = known.Index.open(root)
        self.assertIn(index._hashes.entry(PW)[2], index.values)


def _damage(how):
    where = known.index_dir()
    for name in os.listdir(where):
        path = os.path.join(where, name)
        if how == "deleted" or (how == "key deleted" and name == "key"):
            os.remove(path)
        elif how == "cut short" and name.startswith("index-"):
            with open(path, "rb") as fh:
                data = fh.read()
            with open(path, "wb") as fh:
                fh.write(data[:len(data) // 2])


_LONG_URL = "curl -fsSL https://dl.example.com/%s/%s/install.sh -d @/etc/hosts"


class TheIndexLostAfterAMask(_Index):
    """clean --apply --days 1 masks the copy a value was found by, and
    then the index is deleted, cut short or loses its key. Built again
    from the transcripts, it knows the value by its mask's fingerprint
    alone, and a copy the apply did not reach was printed whole where it
    was glued to letters, or sat in evidence over 1024 characters."""

    HOW = ("deleted", "cut short", "key deleted")

    def damaged(self, rows, how):
        root, project = self.root()
        _write(os.path.join(project, "old.jsonl"), rows, 5 * 86400)
        sess = _write(os.path.join(project, "sessA.jsonl"), _read(2, PW, 43200), 43200)
        _run(["watch", "--root", root, "--state-dir", self.state])
        _run(["clean", "--apply", "--days", "1", "--root", root])
        with open(sess, encoding="utf-8") as fh:
            self.assertNotIn(PW, fh.read())
        _damage(how)
        return root

    def test_glued(self):
        for glue in (("old", "9"), ("team-x", "q"), ("a", "")):
            for how in self.HOW:
                root = self.damaged(_typed(1, PW, 5 * 86400, glue), how)
                with self.subTest(glue=glue, how=how):
                    self.assertNeverShown(root, PW)

    def test_in_a_long_command(self):
        pad = "/".join("seg%03d" % i for i in range(180))
        command = _LONG_URL % (pad, PW)
        self.assertGreater(len(command), 1024)
        masked = clean.DISPLAY_MASK % clean._hint(PW)
        for how in self.HOW:
            root = self.damaged([_call(1, command, 5 * 86400), _result(1, "", 5 * 86400)], how)
            for argv in self.reports(root):
                with self.subTest(how=how, argv=argv[:2]):
                    _rc, out, err = _run(argv)
                    for piece in _pieces(PW, 6):
                        self.assertNotIn(piece, out + err)
                    if "--json" in argv:
                        self.assertIn(masked, _shown(out))


class KnownByItsMaskInALongCommand(_Index):
    """A value masked before the index knew it, by clean from an earlier
    release, so its mask's fingerprint is all that is left, and typed bare
    in a command over 1024 characters: c7ea0f0 masked it in what check and
    watch print, and the index only looked for it in shorter texts."""

    def test_git_push_with_many_refspecs(self):
        for refspecs in (10, 60):
            root, project = self.root()
            _write(os.path.join(project, "a.jsonl"),
                   _read(1, clean.REDACTION % clean._fingerprint(PW), 3000), 3000)
            command = "git push origin %s %s --force" % (PW, " ".join(
                "refs/heads/b%d:refs/heads/b%d" % (i, i) for i in range(refspecs)))
            _write(os.path.join(project, "b.jsonl"),
                   [_call(2, command, 600), _result(2, "ok", 600)], 600)
            with self.subTest(length=len(command)):
                self.assertNeverShown(root, PW)

    def test_glued_in_a_long_command(self):
        root, project = self.root()
        _write(os.path.join(project, "a.jsonl"),
               _read(1, clean.REDACTION % clean._fingerprint(PW), 3000), 3000)
        command = "git push origin x%s9 %s --force" % (PW, " ".join(
            "refs/heads/b%d:refs/heads/b%d" % (i, i) for i in range(60)))
        _write(os.path.join(project, "b.jsonl"),
               [_call(2, command, 600), _result(2, "ok", 600)], 600)
        self.assertNeverShown(root, PW)


class OrphansGrowWithTheText(growth.Assertions, unittest.TestCase):
    """A value known by its mask alone is looked for in text of any
    length, at a cost that grows with it: every piece of a run with many
    places to glue on, each as long as what follows it, was quadratic."""

    KEY = b"k" * 32

    def matcher(self):
        hashes = known._Hashes(self.KEY)
        return known.Matcher(hashes, [], [hashes.of_mask(clean._fingerprint(PW))])

    def test_a_long_run_with_many_places_to_glue_on(self):
        def build(n):
            return self.matcher(), "x" + "%a+b" * n(16000) + "%" + PW
        out = self.assertScalesLinearly(build, lambda a: a[0].mask(a[1]), rebuild=True)
        self.assertNotIn(PW, out)

    def test_a_long_command_shown(self):
        def build(n):
            return self.matcher(), "git push origin x%s9 %s" % (
                PW, "refs/heads/b:refs/heads/b " * n(2000))
        spans = self.assertScalesLinearly(
            build, lambda a: a[0].merged(a[1], shown=(0, len(a[1]))), rebuild=True)
        self.assertIn((17, 17 + len(PW)), spans)


class GluedWhereTheWindowEnds(unittest.TestCase):
    """A value known by its mask alone, glued to letters, where the window
    an action's evidence shows begins or ends: the window kept part of it,
    which no fingerprint knows, and printed that part."""

    def test_widened_over_it(self):
        hashes = known._Hashes(b"k" * 32)
        matcher = known.Matcher(hashes, [], [hashes.of_mask(clean._fingerprint(PW))])
        masked = clean.DISPLAY_MASK % clean._hint(PW)
        commands = (["rm -rf ~/Documents/archive %s q%s9z and some more words"
                     % ("a" * pad, PW) for pad in range(20, 64)]
                    + ["X=%sq%s9z%s rm -rf ~/Documents/archive" % ("b" * pad, PW, "c" * tail)
                       for pad in (0, 9, 30) for tail in range(0, 24)])
        cut = 0
        for command in commands:
            bare = watch.evaluate("Bash", {"command": command})[0][0]["evidence"]
            if PW in bare or not any(piece in bare for piece in _pieces(PW, 6)):
                continue
            cut += 1
            evidence = watch.evaluate("Bash", {"command": command}, known=matcher)[0][0]["evidence"]
            with self.subTest(command=command):
                for piece in _pieces(PW, 6):
                    self.assertNotIn(piece, evidence)
                self.assertIn(masked, evidence)
        self.assertGreater(cut, 20)


PW3 = "Zt8RmW3qXv6KpN2yLs"


class CleanShowsNoValueInAnotherFinding(_Index):
    """A value clean finds, inside another finding's label, the path a
    secret was read from, or a transcript's name, was printed whole by
    the clean report, clean --json and the review's show N. check masked
    each of them."""

    def layout(self, kind):
        root, project = self.root()
        _write(os.path.join(project, "read.jsonl"), _read(1, PW, 3000), 3000)
        if kind == "label":
            _write(os.path.join(project, "other.jsonl"),
                   _read(2, PW2, 2000, key=PW + "_API_TOKEN"), 2000)
        elif kind == "json key":
            _write(os.path.join(project, "other.jsonl"),
                   [_call(2, "cat config.json", 2000),
                    _result(2, json.dumps({PW + "_secret": PW2}), 2000)], 2000)
        elif kind == "origin":
            _write(os.path.join(project, "other.jsonl"),
                   [_call(2, "cat ~/svc/%s/.env" % PW, 2000),
                    _result(2, "API_TOKEN=%s\n" % PW2, 2000)], 2000)
        else:
            _write(os.path.join(project, PW + ".jsonl"),
                   _read(2, PW3, 1000, key="REDIS_PASSWORD"), 1000)
        return root

    def test_each_field(self):
        commands = ("list", "rotate", "show 1", "show 2", "show 3", "quit")
        for kind in ("label", "json key", "origin", "file name"):
            root = self.layout(kind)
            runs = [(argv, _run(argv + ["--root", root]))
                    for argv in (["clean", "--no-interactive"], ["clean", "--json"],
                                 ["check", "--state-dir", self.state],
                                 ["check", "--json", "--state-dir", self.state])]
            replies = iter(commands)
            runs.append((["review"], _review(root, lambda prompt="": next(replies))))
            for argv, (rc, out, err) in runs:
                with self.subTest(kind=kind, argv=argv):
                    self.assertIn(rc, (0, None))
                    self.assertIn(clean._hint(PW2 if kind != "file name" else PW3),
                                  _shown(out))
                    for piece in _pieces(PW, 6):
                        self.assertNotIn(piece, out + err)


class KeysAreMaskedToo(_Index):
    """A transcript whose tool_use id is an object keyed by a string that
    holds a value clean finds: watch --json and check --json printed the
    key whole, since only what a dict holds was masked, not its keys."""

    def test_an_id_keyed_by_a_value(self):
        root, project = self.root()
        _write(os.path.join(project, "read.jsonl"), _read(1, PW, 3000), 3000)
        call = _call(2, "rm -rf ~/w/cache", 600)
        call["message"]["content"][0]["id"] = {"x%sy" % PW: 1}
        _write(os.path.join(project, "typed.jsonl"), [call, _result(2, "", 600)], 600)
        masked = clean.DISPLAY_MASK % clean._hint(PW)
        for argv in (["watch", "--json"], ["check", "--json"]):
            rc, out, err = _run(argv + ["--root", root, "--state-dir", self.state])
            with self.subTest(argv=argv):
                self.assertEqual(rc, 0)
                self.assertIn("rm -rf ~/w/cache", out)
                self.assertIn("x%sy" % masked, _shown(out))
                for piece in _pieces(PW, 6):
                    self.assertNotIn(piece, out + err)

    def test_every_key(self):
        m = known.Matcher.of([PW])
        masked = "a%sb" % (clean.DISPLAY_MASK % clean._hint(PW))
        node = {"a%sb" % PW: [{"a%sb" % PW: "a%sb" % PW}], 3: {None: 1}}
        self.assertEqual(cli._masked_strings(node, m.mask),
                         {masked: [{masked: masked}], 3: {None: 1}})

    def test_the_payload_hash_is_of_masked_keys(self):
        m = known.Matcher.of([PW])
        masked = "x%sy" % (clean.DISPLAY_MASK % clean._hint(PW))
        self.assertEqual(watch._payload({"env": {"x%sy" % PW: "1"}}, known=m),
                         json.dumps({"env": {masked: "1"}}, sort_keys=True,
                                    ensure_ascii=False))


class CheckReadsEachTranscriptOnce(_Index):
    """check's first run read every transcript for its secrets twice: for
    the index, and for clean's findings. On a real history of 427
    transcripts, all in the window, it took 50 s where clean took 24 s.
    clean's read now feeds the index, which reads only what is left."""

    def reads(self):
        read = []
        values_in, scan_file = clean.values_in, clean.scan_file

        def by_index(path, *a, **k):
            read.append(os.path.basename(path))
            return values_in(path, *a, **k)

        def by_scan(path, *a, **k):
            read.append(os.path.basename(path))
            return scan_file(path, *a, **k)
        for patch in (mock.patch.object(clean, "values_in", by_index),
                      mock.patch.object(clean, "scan_file", by_scan)):
            patch.start()
            self.addCleanup(patch.stop)
        return read

    def test_first_run(self):
        root, project = self.root()
        _write(os.path.join(project, "sessA.jsonl"), _read(1, PW, 3000), 3000)
        _write(os.path.join(project, "sessB.jsonl"),
               _read(2, PW2, 2000, key="API_TOKEN"), 2000)
        _write(os.path.join(project, "sessC.jsonl"), [_call(4, "ls", 1000)], 1000)
        _write(os.path.join(project, "old.jsonl"), _read(5, PW3, 40 * 86400), 40 * 86400)
        read = self.reads()
        _run(["check", "--root", root, "--state-dir", self.state])
        self.assertEqual(sorted(read), ["old.jsonl", "sessA.jsonl", "sessB.jsonl",
                                        "sessC.jsonl"])
        del read[:]
        _write(os.path.join(project, "sessD.jsonl"), _typed(6, PW3, 500), 500)
        self.assertNeverShown(root, PW3)
        index = known.Index.open(root)
        index.update()
        self.assertEqual(index.rescanned, 0)

    def test_changed_after_clean_read_it(self):
        """What clean found in a transcript is kept under its size and
        time from before it was read: one written to after is read again."""
        root, project = self.root()
        sess = _write(os.path.join(project, "sessA.jsonl"), _read(1, PW, 3000), 3000)
        scan_file = clean.scan_file

        def written_after(path, *a, **k):
            found = scan_file(path, *a, **k)
            if path == sess and not k.get("only"):
                _write(sess, _read(2, PW2, 100, key="API_TOKEN"), 100, mode="a")
            return found
        with mock.patch.object(clean, "scan_file", written_after):
            _run(["check", "--root", root, "--state-dir", self.state])
        _write(os.path.join(project, "sessB.jsonl"), _typed(3, PW2, 50), 50)
        self.assertNeverShown(root, PW2)


class TheIndexKeepsAShortTag(_Index):
    """The index kept a keyed hash of each value's first six characters,
    with the key beside it: whoever reads the two could find those six on
    their own and then the rest, two small searches instead of one large
    one. It keeps 16 bits of that hash now, which many beginnings share,
    and every place they lead to is confirmed by the whole value's hash."""

    def test_sixteen_bits(self):
        root, project = self.root()
        _write(os.path.join(project, "sessA.jsonl"),
               _read(1, PW, 2000) + _read(2, PW2, 2000, key="API_TOKEN"), 2000)
        _run(["watch", "--root", root, "--state-dir", self.state])
        with open(known.Index.open(root).path, encoding="utf-8") as fh:
            doc = json.load(fh)
        self.assertEqual(doc["version"], known.VERSION)
        self.assertEqual(len(doc["values"]), 2)
        for head, _n, _mask in doc["values"].values():
            self.assertEqual(len(head), 4)

    def test_a_tag_every_place_shares(self):
        with mock.patch.object(known, "_TAG_SIZE", 0):
            m = known.Matcher.of([PW, PW2, "Zq9"])
            text = "x%sy %s %s Zq8 Zq9 %s" % (PW, PW[:-1], PW2[1:], PW2)
            out = m.mask(text)
        hint = lambda v: clean.DISPLAY_MASK % clean._hint(v)
        self.assertEqual(out, "x%sy %s %s Zq8 %s %s" % (
            hint(PW), PW[:-1], PW2[1:], hint("Zq9"), hint(PW2)))

    def test_an_index_of_the_first_format(self):
        """An index written with whole head hashes is read, cut to the
        tag and written again, and no transcript is read again for it."""
        root, project = self.root()
        _write(os.path.join(project, "sessA.jsonl"), _read(1, PW, 3000), 3000)
        _write(os.path.join(project, "sessB.jsonl"), _typed(2, PW, 600), 600)
        _run(["watch", "--root", root, "--state-dir", self.state])
        index = known.Index.open(root)
        with open(index.path, encoding="utf-8") as fh:
            doc = json.load(fh)
        head = index._hashes.head.copy()
        head.update(PW[:6].encode("utf-8"))
        (full, (_tag, n, mask)), = doc["values"].items()
        doc["version"], doc["values"] = 1, {full: [head.hexdigest(), n, mask]}
        with open(index.path, "w", encoding="utf-8") as fh:
            json.dump(doc, fh)
        read = self.rescans()
        self.assertNeverShown(root, PW)
        self.assertEqual(read, [])
        with open(index.path, encoding="utf-8") as fh:
            doc = json.load(fh)
        self.assertEqual(doc["version"], known.VERSION)
        self.assertEqual([len(v[0]) for v in doc["values"].values()], [4])


class OpenClawDatabasesAreIndexed(_Index):
    """OpenClaw's databases were the one store the index did not read, so a
    password clean finds in one was printed whole where a command typed it.
    They are read like every other agent's store now (design 3.9's
    follow-up), and read again when the database or its -wal changes: a
    live agent's newest rows are in its -wal while the database itself
    keeps its size and time."""

    def database(self, rows):
        """agents/a1/agent/openclaw-agent.sqlite under the state directory,
        in WAL mode with its writer left open, as a running agent keeps it."""
        import sqlite3
        path = os.path.join(self.state, "agents", "a1", "agent",
                            "openclaw-agent.sqlite")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        conn = sqlite3.connect(path)
        self.addCleanup(conn.close)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("CREATE TABLE log (id TEXT, body TEXT, createdAt INTEGER)")
        conn.commit()
        self.add(conn, rows)
        return path, conn

    def add(self, conn, rows):
        for row in rows:
            conn.execute("INSERT INTO log VALUES (?, ?, ?)", row)
            conn.commit()
        conn.execute("SELECT count(*) FROM log").fetchall()

    def rows(self, i, value, age, key="DB_PASSWORD", typed=None):
        when = int(time.time() - age)
        out = [("%d" % i, json.dumps({"content": [{
            "type": "tool_use", "name": "bash",
            "input": {"command": "cat .env"}}]}), when),
               ("%dr" % i, json.dumps({"content": [{
                   "type": "tool_result", "content": "%s=%s\n" % (key, value)}]}),
                when)]
        if typed:
            out.append(("%dt" % i, json.dumps({"content": [{
                "type": "tool_use", "name": "bash",
                "input": {"command": SCRIPT % (typed[0] + value + typed[1])}}]}),
                when))
        return out

    def test_typed_in_the_same_database(self):
        root, _project = self.root()
        self.database(self.rows(1, PW, 2000, typed=GLUES[0]))
        self.assertNeverShown(root, PW)

    def test_typed_by_another_agent(self):
        root, project = self.root()
        self.database(self.rows(1, PW, 2000))
        _write(os.path.join(project, "sessB.jsonl"), _typed(2, PW, 600), 600)
        self.assertNeverShown(root, PW)

    def test_a_row_in_its_wal_is_read_again(self):
        root, project = self.root()
        path, conn = self.database(self.rows(1, PW, 3000))
        read = self.rescans()
        _run(["watch", "--root", root, "--state-dir", self.state])
        self.assertEqual(read, ["openclaw-agent.sqlite"])
        del read[:]
        st = os.stat(path)
        self.add(conn, self.rows(2, PW2, 2000, key="API_TOKEN"))
        self.assertEqual((os.stat(path).st_size, os.stat(path).st_mtime_ns),
                         (st.st_size, st.st_mtime_ns))
        _write(os.path.join(project, "sessB.jsonl"), _typed(3, PW2, 600, ("Q", "7")), 600)
        self.assertNeverShown(root, PW2)
        self.assertEqual(sorted(read), ["openclaw-agent.sqlite", "sessB.jsonl"])

    def test_check_reads_it_once(self):
        root, _project = self.root()
        self.database(self.rows(1, PW, 3000, typed=GLUES[1]))
        read = []
        real = clean.scan_store

        def counted(source, store, values):
            read.append(os.path.basename(store.path))
            return real(source, store, values)
        with mock.patch.object(clean, "scan_store", counted):
            _run(["check", "--root", root, "--state-dir", self.state])
        self.assertEqual(read, ["openclaw-agent.sqlite"])

    def test_a_cell_that_is_not_utf8(self):
        """A cell whose bytes are not UTF-8 stopped the read at its row
        (on 3.9 and 3.10 at the row before), and the index kept that as all
        the database held: a password in it, and one in the row before,
        were printed whole wherever Claude Code typed them."""
        root, project = self.root()
        _path, conn = self.database(self.rows(1, PW2, 3000))
        conn.execute("INSERT INTO log VALUES (?, CAST(? AS TEXT), ?)", (
            "2", ("Saved DB_PASSWORD=%s\n" % PW).encode("utf-8")
            + b"\xed\xa0\xbd tail", int(time.time() - 2000)))
        conn.commit()
        _write(os.path.join(project, "sessB.jsonl"),
               _typed(2, PW, 600) + _typed(3, PW2, 500, GLUES[1]), 500)
        for value in (PW, PW2):
            self.assertNeverShown(root, value)
            self.assertNeverShown(root, value, "--source", "claude-code")

    def test_a_column_of_any_declared_type(self):
        """Only TEXT, BLOB, JSON, untyped and *CHAR* columns were read, so a
        password in a CLOB or an INTEGER column was printed whole wherever
        Claude Code typed it."""
        import sqlite3
        root, project = self.root()
        path = os.path.join(self.state, "agents", "a1", "agent",
                            "openclaw-agent.sqlite")
        os.makedirs(os.path.dirname(path))
        conn = sqlite3.connect(path)
        conn.execute("CREATE TABLE kv (a CLOB, b INTEGER)")
        conn.execute("INSERT INTO kv VALUES (?, ?)",
                     ("DB_PASSWORD=" + PW, "API_TOKEN=" + PW2))
        conn.commit()
        conn.close()
        _write(os.path.join(project, "sessB.jsonl"),
               _typed(2, PW, 600) + _typed(3, PW2, 500, GLUES[1]), 500)
        for value in (PW, PW2):
            self.assertNeverShown(root, value)


if __name__ == "__main__":
    unittest.main()
