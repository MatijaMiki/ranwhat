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
        """The paths clean's finder reads for the index, as they are read."""
        read = []
        real = clean.values_in

        def spy(path):
            read.append(os.path.basename(path))
            return real(path)
        patch = mock.patch.object(clean, "values_in", spy)
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
        for command in ("watch", "check"):
            root, project = self.root()
            _write(os.path.join(project, "sessA.jsonl"), _read(1, PW, 3000), 3000)
            _write(os.path.join(project, "sessB.jsonl"), _typed(2, PW, 600), 600)
            with self.subTest(command=command):
                err = self.stderr(root, command)
                self.assertTrue(err.startswith(
                    "\r  indexing secrets (first run) 1/2\033[K"
                    "\r  indexing secrets (first run) 2/2\033[K"), repr(err))
                self.assertNotIn("indexing", self.stderr(root, command))
                _write(os.path.join(project, "sessC.jsonl"), _typed(3, PW, 500), 500)
                err = self.stderr(root, command)
                self.assertTrue(err.startswith("\r  indexing secrets 1/1\033[K"), repr(err))

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


if __name__ == "__main__":
    unittest.main()
