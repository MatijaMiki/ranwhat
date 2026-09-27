"""The feed must not be able to break the three things the tool promises:
that it works offline, that it sends nothing, and that a bad payload can
never reach a report."""
import contextlib
import io
import json
import os
import platform
import shutil
import stat
import sys
import tempfile
import unittest
from unittest import mock

from ranwhat import catalog, cli, feed, score


def _entry(label="X", authority="write", reversible=False,
           blast="data_egress", why="because"):
    return {"label": label, "authority": authority, "reversible": reversible,
            "blast": blast, "why": why}


def _doc(catalogue=None, version="2026.09.26"):
    cat = catalogue if catalogue is not None else {"acme": {"acme:delete": _entry()}}
    return {"schema": feed.SCHEMA, "version": version, "catalogue": cat,
            "digest": feed.digest(cat)}


class FeedHome(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self._old = os.environ.get("RANWHAT_HOME")
        os.environ["RANWHAT_HOME"] = self.dir
        catalog.reset_feed_cache()

    def tearDown(self):
        if self._old is None:
            os.environ.pop("RANWHAT_HOME", None)
        else:
            os.environ["RANWHAT_HOME"] = self._old
        shutil.rmtree(self.dir, ignore_errors=True)
        catalog.reset_feed_cache()


class Validation(FeedHome):
    def test_rejects_wrong_schema(self):
        d = _doc(); d["schema"] = 999
        with self.assertRaises(feed.FeedError):
            feed.validate(d)

    def test_rejects_missing_field(self):
        bad = _entry(); del bad["why"]
        with self.assertRaises(feed.FeedError):
            feed.validate(_doc({"acme": {"acme:x": bad}}))

    def test_rejects_tampered_catalogue(self):
        d = _doc()
        d["catalogue"]["acme"]["acme:delete"]["authority"] = "read"
        with self.assertRaises(feed.FeedError):
            feed.validate(d)

    def test_rejects_empty_catalogue(self):
        with self.assertRaises(feed.FeedError):
            feed.validate(_doc({}))


class Offline(FeedHome):
    def test_no_feed_means_no_feed_not_an_error(self):
        self.assertIsNone(feed.load())
        self.assertFalse(feed.status()["active"])

    def test_corrupt_cache_degrades_silently(self):
        os.makedirs(os.path.dirname(feed.feed_path()), exist_ok=True)
        with open(feed.feed_path(), "w", encoding="utf-8") as fh:
            fh.write("{not json")
        self.assertIsNone(feed.load())

    def test_bundled_catalogue_still_resolves_without_a_feed(self):
        e = catalog.lookup("google", "https://www.googleapis.com/auth/gmail.send")
        self.assertTrue(e["known"])
        self.assertEqual(e["authority"], "write")


class Merging(FeedHome):
    def test_feed_adds_scopes_the_bundle_lacks(self):
        feed.save(_doc({"notion": {"notion:read_content": _entry("Read pages")}}))
        catalog.reset_feed_cache()
        e = catalog.lookup("notion", "notion:read_content")
        self.assertTrue(e["known"])
        self.assertEqual(e["label"], "Read pages")

    def test_feed_overrides_a_bundled_scope(self):
        scope = "https://www.googleapis.com/auth/gmail.send"
        feed.save(_doc({"google": {scope: _entry("Reclassified", "destructive")}}))
        catalog.reset_feed_cache()
        self.assertEqual(catalog.lookup("google", scope)["authority"], "destructive")

    def test_feed_cannot_remove_a_bundled_scope(self):
        """A feed that has not caught up must not delete local knowledge."""
        feed.save(_doc({"google": {"google:something_new": _entry()}}))
        catalog.reset_feed_cache()
        e = catalog.lookup("google", "https://www.googleapis.com/auth/gmail.send")
        self.assertTrue(e["known"], "bundled scope disappeared when a feed arrived")

    def test_narrow_scope_still_never_widened_to_a_wildcard(self):
        """The rule that makes reports trustworthy survives the feed."""
        feed.save(_doc({"aws": {"s3:*": _entry("All S3", "destructive")}}))
        catalog.reset_feed_cache()
        self.assertFalse(catalog.lookup("aws", "s3:ListBucket").get("known"))

    def test_the_merge_is_built_once_per_feed_read(self):
        """lookup() runs once per grant. Merging the provider's feed scopes
        on every call made a scan grants times feed entries."""
        feed.save(_doc({"acme": {"acme:x": _entry("First")}}))
        catalog.reset_feed_cache()
        with mock.patch.object(catalog, "_no_lower",
                               mock.Mock(wraps=catalog._no_lower)) as floor:
            for _ in range(50):
                catalog.lookup("acme", "acme:x")
        # Once to merge the provider, and once per lookup for the scope
        # itself when the bundle resolves it, which acme's never does.
        self.assertEqual(floor.call_count, 1)

    def test_a_new_feed_is_used_after_a_reset(self):
        """`update` resets the cache after saving; the merged view goes too."""
        feed.save(_doc({"acme": {"acme:x": _entry("First")}}))
        catalog.reset_feed_cache()
        self.assertEqual(catalog.lookup("acme", "acme:x")["label"], "First")
        feed.save(_doc({"acme": {"acme:x": _entry("Second")}}))
        catalog.reset_feed_cache()
        self.assertEqual(catalog.lookup("acme", "acme:x")["label"], "Second")

    def test_a_looked_up_entry_is_the_callers_to_change(self):
        feed.save(_doc({"acme": {"acme:x": _entry("First")}}))
        catalog.reset_feed_cache()
        catalog.lookup("acme", "acme:x")["label"] = "Changed"
        catalog.providers("acme")["acme:x"] = _entry("Replaced")
        self.assertEqual(catalog.lookup("acme", "acme:x")["label"], "First")


class TokenHandling(FeedHome):
    @unittest.skipIf(os.name == "nt", "Windows has no owner-only mode bits")
    def test_saved_token_is_not_world_readable(self):
        path = feed.save_token("tok_abc")
        self.assertEqual(oct(os.stat(path).st_mode & 0o777), oct(0o600))

    def test_the_file_holds_the_token_and_one_newline(self):
        # A descriptor from os.open is in text mode on Windows unless told
        # otherwise, and the newline went down as \r\n.
        with open(feed.save_token("tok_abc"), "rb") as fh:
            self.assertEqual(fh.read(), b"tok_abc\n")

    def test_environment_beats_the_file(self):
        feed.save_token("from_file")
        os.environ["RANWHAT_TOKEN"] = "from_env"
        try:
            self.assertEqual(feed.read_token(), "from_env")
        finally:
            os.environ.pop("RANWHAT_TOKEN", None)

    def test_no_token_is_not_an_error(self):
        self.assertIsNone(feed.read_token())


class SendsNothing(FeedHome):
    def test_request_carries_the_token_and_no_machine_detail(self):
        seen = {}

        class FakeResp:
            def read(self, n=-1): return json.dumps(_doc()).encode()
            def __enter__(self): return self
            def __exit__(self, *a): return False

        real = feed._open

        def spy(req, *a, **kw):
            seen["url"] = req.full_url
            seen["headers"] = dict(req.header_items())
            seen["body"] = req.data
            return FakeResp()

        feed._open = spy
        try:
            feed.fetch("tok_xyz", url="https://example.invalid/v1/catalogue")
        finally:
            feed._open = real

        self.assertIsNone(seen["body"], "update sent a request body")
        values = " ".join(str(v) for v in seen["headers"].values())
        self.assertIn("Bearer tok_xyz", values)
        # platform.node, not os.uname: Windows has no uname, and says "" when
        # it cannot tell, which is in every string.
        for leak in filter(None, (platform.node(), os.path.expanduser("~"))):
            self.assertNotIn(leak, values)
        self.assertNotIn("?", seen["url"], "no query string, so nothing smuggled in one")




class TokenIsNotWrittenThroughASymlink(FeedHome):

    @unittest.skipUnless(hasattr(os, "O_NOFOLLOW"), "POSIX only")
    def test_a_planted_symlink_is_refused(self):
        target = os.path.join(self.dir, "elsewhere")
        os.symlink(target, feed.token_path())
        with self.assertRaises(feed.FeedError):
            feed.save_token("tok_secret")
        self.assertFalse(os.path.exists(target), "token followed the symlink")

    @unittest.skipIf(os.name == "nt", "Windows has no owner-only mode bits")
    def test_an_existing_loose_file_is_tightened(self):
        with open(feed.token_path(), "w", encoding="utf-8") as fh:
            fh.write("old\n")
        os.chmod(feed.token_path(), 0o644)
        feed.save_token("tok_new")
        self.assertEqual(os.stat(feed.token_path()).st_mode & 0o777, 0o600)
        self.assertEqual(open(feed.token_path(), encoding="utf-8").read(), "tok_new\n")


@unittest.skipIf(os.name == "nt", "symlinks need privileges on Windows")
class TheCacheIsNotWrittenThroughASymlink(FeedHome):
    """save() wrote catalogue.json.tmp with open(tmp, "w"), which follows a
    symlink planted there: its target, any file the user owns, took the feed
    JSON, os.replace installed the link as the cache, and chmod(path, 0600)
    followed it to the target too. ~/.ranwhat is writable by the agents this
    tool audits, so that was ~/.zshrc overwritten on the next `update`."""

    RC = "export PATH=/usr/bin\n"

    def _plant(self, name, target):
        os.makedirs(os.path.dirname(feed.feed_path()), exist_ok=True)
        os.symlink(target, os.path.join(os.path.dirname(feed.feed_path()), name))

    def _victim(self):
        victim = os.path.join(self.dir, "victim_rc")
        with open(victim, "w", encoding="utf-8") as fh:
            fh.write(self.RC)
        os.chmod(victim, 0o644)
        return victim

    def _assert_cache_is_a_regular_0600_file(self):
        st = os.lstat(feed.feed_path())
        self.assertTrue(stat.S_ISREG(st.st_mode), "the cache is not a plain file")
        self.assertEqual(oct(st.st_mode & 0o777), oct(0o600))
        self.assertFalse(os.path.lexists(feed.feed_path() + ".tmp"))
        self.assertIsNotNone(feed.load())

    def test_a_symlink_at_the_temp_file_is_not_written_through(self):
        victim = self._victim()
        self._plant("catalogue.json.tmp", victim)
        feed.save(_doc())
        with open(victim, encoding="utf-8") as fh:
            self.assertEqual(fh.read(), self.RC, "the feed overwrote the target")
        self.assertEqual(oct(os.stat(victim).st_mode & 0o777), oct(0o644))
        self._assert_cache_is_a_regular_0600_file()

    def test_a_dangling_symlink_at_the_temp_file_creates_nothing(self):
        target = os.path.join(self.dir, "created_elsewhere")
        self._plant("catalogue.json.tmp", target)
        feed.save(_doc())
        self.assertFalse(os.path.lexists(target), "the feed followed the link")
        self._assert_cache_is_a_regular_0600_file()

    def test_a_symlink_at_the_cache_itself_is_replaced_not_followed(self):
        victim = self._victim()
        self._plant("catalogue.json", victim)
        feed.save(_doc())
        with open(victim, encoding="utf-8") as fh:
            self.assertEqual(fh.read(), self.RC)
        self.assertEqual(oct(os.stat(victim).st_mode & 0o777), oct(0o644))
        self._assert_cache_is_a_regular_0600_file()

    def test_mode_is_set_on_the_file_before_it_is_installed(self):
        """chmod by path after the replace follows whatever is at the path by
        then. The mode goes on the open file, before it has a public name."""
        with mock.patch.object(feed.os, "chmod",
                               mock.Mock(side_effect=AssertionError("chmod by path"))):
            feed.save(_doc())
        self._assert_cache_is_a_regular_0600_file()


class FeedCannotLowerARating(FeedHome):
    """The feed is not signed, and ~/.ranwhat is writable by the agents being
    audited. Whatever it says, it must not make a report look safer than the
    bundled catalogue already knows it is."""

    SCOPE = "https://www.googleapis.com/auth/gmail.send"

    def _fed(self, entry, provider="google", scope=None):
        feed.save(_doc({provider: {scope or self.SCOPE: entry}}))
        catalog.reset_feed_cache()
        return catalog.lookup(provider, scope or self.SCOPE)

    def test_a_downgrade_keeps_the_bundled_entry(self):
        bundled = catalog.CATALOG["google"][self.SCOPE]
        e = self._fed(_entry("Harmless", "read", True, "data_egress"))
        self.assertEqual(e["authority"], bundled["authority"])
        self.assertEqual(e["label"], bundled["label"])

    def test_bundled_irreversible_stays_irreversible(self):
        bundled = catalog.CATALOG["google"][self.SCOPE]
        self.assertFalse(bundled["reversible"])
        e = self._fed(_entry("Same", bundled["authority"], True, bundled["blast"]))
        self.assertFalse(e["reversible"])

    def test_extra_fields_cannot_reach_the_report_row(self):
        entry = dict(_entry("X", "destructive"), usage="used", scope="other",
                     provider="elsewhere")
        feed.save(_doc({"acme": {"acme:delete": entry}}))
        catalog.reset_feed_cache()
        e = catalog.lookup("acme", "acme:delete")
        for k in ("usage", "scope", "provider"):
            self.assertNotIn(k, e)

    def test_bad_values_reject_the_whole_feed(self):
        for bad in (_entry(authority="admin"), _entry(blast="everything"),
                    _entry(reversible="false"), _entry(label=None)):
            with self.assertRaises(feed.FeedError, msg=bad):
                feed.validate(_doc({"acme": {"acme:x": bad}}))

    def test_a_rejected_cache_falls_back_to_the_bundle(self):
        doc = _doc({"google": {self.SCOPE: _entry(authority="admin")}})
        os.makedirs(os.path.dirname(feed.feed_path()), exist_ok=True)
        with open(feed.feed_path(), "w", encoding="utf-8") as fh:
            json.dump(doc, fh)
        catalog.reset_feed_cache()
        self.assertEqual(catalog.lookup("google", self.SCOPE)["authority"],
                         catalog.CATALOG["google"][self.SCOPE]["authority"])


class FeedCannotLowerABlast(FeedHome):
    """Blast is a rating too. A feed that moves a Stripe charge from monetary
    to data_egress takes "Unbounded financial authority" out of the report
    while leaving the authority and reversible floors untouched."""

    def _fed(self, provider, scope, entry):
        feed.save(_doc({provider: {scope: entry}}))
        catalog.reset_feed_cache()
        return catalog.lookup(provider, scope)

    def _scan(self, provider, scope):
        return score.scan({"credentials": [
            {"provider": provider, "scopes": [scope]}]})

    def test_a_charge_stays_monetary(self):
        bundled = catalog.CATALOG["stripe"]["charges:write"]
        self.assertEqual(bundled["blast"], catalog.MONETARY)
        e = self._fed("stripe", "charges:write",
                      _entry("Harmless", "financial", False, "data_egress"))
        self.assertEqual(e["blast"], catalog.MONETARY)
        self.assertEqual(e["label"], bundled["label"],
                         "the feed's text was written for a blast it did not get")
        result = self._scan("stripe", "charges:write")
        self.assertEqual(result["blast_radius"]["monetary"], "unbounded")
        self.assertIn("Unbounded financial authority",
                      [f["title"] for f in result["findings"]])

    def test_a_read_scope_stays_data_egress(self):
        """Weighed by authority, not by name: the scorer drops a read scope
        whose blast is anything but data_egress, so for a read, monetary is
        the lower rating."""
        self.assertEqual(catalog.CATALOG["stripe"]["customers:read"]["blast"],
                         catalog.DATA_EGRESS)
        e = self._fed("stripe", "customers:read",
                      _entry("Harmless", "read", True, "monetary"))
        self.assertEqual(e["blast"], catalog.DATA_EGRESS)
        self.assertIn(catalog.DATA_EGRESS, self._scan(
            "stripe", "customers:read")["blast_radius"]["dimensions"])

    def test_a_sideways_move_keeps_the_bundled_dimension(self):
        """infrastructure and identity count the same, so moving one to the
        other only drops a dimension from the report."""
        bundled = catalog.CATALOG["aws"]["*"]
        self.assertEqual(bundled["blast"], catalog.INFRASTRUCTURE)
        e = self._fed("aws", "*", _entry("X", "destructive", False, "identity"))
        self.assertEqual(e["blast"], catalog.INFRASTRUCTURE)

    def test_a_feed_can_still_raise_a_blast(self):
        bundled = catalog.CATALOG["stripe"]["customers:write"]
        self.assertEqual(bundled["blast"], catalog.IDENTITY)
        e = self._fed("stripe", "customers:write",
                      _entry("Reclassified", "write", True, "monetary"))
        self.assertEqual(e["blast"], catalog.MONETARY)
        self.assertEqual(e["label"], "Reclassified")

    def test_a_raise_survives_a_refused_lowering(self):
        e = self._fed("stripe", "charges:write",
                      _entry("X", "destructive", False, "data_egress"))
        self.assertEqual(e["authority"], catalog.DESTRUCTIVE)
        self.assertEqual(e["blast"], catalog.MONETARY)

    def test_the_ordering_is_the_scorers(self):
        """If score.blast_radius starts counting blast differently, the
        ordering the merge keeps has to move with it."""
        for authority in catalog.AUTHORITY_RANK:
            for blast in feed.BLASTS:
                row = {"authority": authority, "blast": blast,
                       "reversible": True, "scope": "s"}
                ba = score.blast_radius([row], {})
                counted = 2 if ba["monetary"] else 1 if ba["dimensions"] else 0
                self.assertEqual(catalog.blast_weight(authority, blast),
                                 counted, (authority, blast))


class FeedCannotLowerWhatTheBundleResolves(FeedHome):
    """The floor used to hold only where the feed and the bundle used the
    same key. A longer feed wildcard beat the bundled one, because the
    longest pattern wins, and a new exact key for a wildcard grant was
    matched before any wildcard. Either made s3:Delete* a reversible read."""

    READ = _entry("List", "read", True, "identity", "x")
    PROFILE = {"agent": "a", "credentials": [
        {"provider": "aws", "label": "agent", "scopes": ["s3:Delete*", "iam:Put*"]}],
        "controls": {}}

    def _save(self, catalogue):
        feed.save(_doc(catalogue))
        catalog.reset_feed_cache()

    def _no_feed_scan(self):
        catalog.reset_feed_cache()
        self.assertIsNone(feed.load())
        return score.scan(self.PROFILE)

    def test_a_longer_feed_wildcard_does_not_beat_the_bundled_one(self):
        before = self._no_feed_scan()
        self.assertEqual(before["blast_radius"]["irreversible_actions"],
                         ["iam:Put*", "s3:Delete*"])
        self._save({"aws": {"s3:D*": self.READ, "iam:P*": self.READ}})
        e = catalog.lookup("aws", "s3:Delete*")
        self.assertEqual(e["authority"], catalog.DESTRUCTIVE)
        self.assertFalse(e["reversible"])
        self.assertIn("matched s3:*", e["label"],
                      "the feed's text was written for a rating it did not get")
        self.assertEqual(score.scan(self.PROFILE), before)

    def test_a_new_exact_key_for_a_wildcard_grant_does_not_either(self):
        before = self._no_feed_scan()
        self._save({"aws": {"s3:Delete*": self.READ, "iam:Put*": self.READ}})
        self.assertEqual(catalog.lookup("aws", "iam:Put*")["authority"],
                         catalog.DESTRUCTIVE)
        self.assertEqual(score.scan(self.PROFILE), before)

    def test_a_feed_wildcard_can_still_raise(self):
        self._save({"aws": {"s3:D*": _entry("Delete S3", "destructive", False,
                                            "monetary")}})
        e = catalog.lookup("aws", "s3:Delete*")
        self.assertEqual(e["blast"], catalog.MONETARY)
        self.assertIn("matched s3:D*", e["label"])


class FeedCannotLowerWhatTheNameSays(FeedHome):
    """A scope the bundle lacks is rated from its own name. When the name
    says something (a delete verb, a payment, a read), the feed may confirm
    or raise that, not contradict it: s3:DeleteBucket is not a read however
    the cache describes it. An entry that tries is ignored whole, and the
    scope stays unclassified, as it was with no feed."""

    READ = _entry("Harmless", "read", True, "data_egress", "x")
    SCOPES = ("s3:DeleteBucket", "dynamodb:DeleteTable")

    def _scan(self, provider, scopes):
        return score.scan({"credentials": [
            {"provider": provider, "scopes": list(scopes)}]})

    def _save(self, catalogue):
        feed.save(_doc(catalogue))
        catalog.reset_feed_cache()

    def test_a_delete_verb_stays_destructive(self):
        before = self._scan("aws", self.SCOPES)
        self.assertIn("Unclassified permissions",
                      [f["title"] for f in before["findings"]])
        self._save({"aws": {s: self.READ for s in self.SCOPES}})
        e = catalog.lookup("aws", "s3:DeleteBucket")
        self.assertEqual(e["authority"], catalog.DESTRUCTIVE)
        self.assertFalse(e["reversible"])
        self.assertFalse(e["known"])
        self.assertEqual(self._scan("aws", self.SCOPES), before)

    def test_a_payment_stays_monetary(self):
        scope = "payouts_v2:create"
        before = self._scan("stripe", [scope])
        self._save({"stripe": {scope: _entry("Harmless", "destructive", False,
                                             "data_egress")}})
        self.assertEqual(catalog.lookup("stripe", scope)["blast"], catalog.MONETARY)
        self.assertEqual(self._scan("stripe", [scope]), before)

    def test_a_read_verb_keeps_counting_as_egress(self):
        """The scorer drops a read whose blast is not data_egress."""
        scope = "s3:GetBucketTagging"
        self._save({"aws": {scope: _entry("Tags", "read", True, "identity")}})
        self.assertEqual(catalog.lookup("aws", scope)["blast"], catalog.DATA_EGRESS)

    def test_a_feed_may_rate_what_the_name_only_hints_at(self):
        """Agreeing on what the name says, it may still move the blast
        between dimensions the scorer counts the same, and name the scope."""
        self._save({"aws": {"iam:DeleteUser": _entry(
            "Delete IAM users", "destructive", False, "identity")}})
        e = catalog.lookup("aws", "iam:DeleteUser")
        self.assertTrue(e["known"])
        self.assertEqual((e["label"], e["blast"]), ("Delete IAM users", "identity"))

    def test_no_entry_under_any_key_lowers_a_scope(self):
        """Every rating a feed can give, under the scope's own key and under
        wildcards longer than the bundle's, against scopes the bundle rates
        exactly, by wildcard, and only by name."""
        grants = ("s3:Delete*", "s3:DeleteObject", "iam:Put*", "*",
                  "s3:DeleteBucket", "dynamodb:DeleteTable", "payouts:create",
                  "s3:GetBucketTagging")
        keys = grants + ("s3:D*", "s3:Del*", "iam:P*")
        before = {g: catalog.lookup("aws", g) for g in grants}
        for authority in catalog.AUTHORITY_RANK:
            for reversible in (True, False):
                for blast in feed.BLASTS:
                    fed = _entry("Fed", authority, reversible, blast)
                    self._save({"aws": {k: fed for k in keys}})
                    for g in grants:
                        with self.subTest(grant=g, fed=(authority, reversible, blast)):
                            self.assertFalse(catalog._below(
                                before[g], catalog.lookup("aws", g)))

    def test_a_name_that_says_nothing_is_the_feeds_to_rate(self):
        """The write guess for a verb nobody recognised is not evidence, and
        replacing guesses is what the feed is for."""
        self._save({"acme": {"acme:widgets": self.READ}})
        e = catalog.lookup("acme", "acme:widgets")
        self.assertTrue(e["known"])
        self.assertEqual(e["authority"], catalog.READ)


class AMalformedCacheIsNoFeed(FeedHome):
    """The cache is as untrusted as the network: anything running as this
    user, the agents being audited included, can write ~/.ranwhat. Valid JSON
    with the wrong type in any field must read as no feed, never as a
    traceback from `update --status` or from a scan."""

    WRONG = (None, True, 0, 1.5, "text", [], ["x"], {}, {"k": "v"})

    # Every field, and the values from WRONG that are right there.
    PATHS = {
        (): (),
        ("schema",): (),
        ("version",): (None, "text"),
        ("digest",): (None,),
        ("fetched_at",): (0, 1.5),
        ("catalogue",): (),
        ("catalogue", "acme"): ({},),
        ("catalogue", "acme", "acme:x"): (),
        ("catalogue", "acme", "acme:x", "label"): ("text",),
        ("catalogue", "acme", "acme:x", "authority"): (),
        ("catalogue", "acme", "acme:x", "reversible"): (True,),
        ("catalogue", "acme", "acme:x", "blast"): (),
        ("catalogue", "acme", "acme:x", "why"): ("text",),
    }

    # Numbers the status line cannot turn into a date.
    UNPRINTABLE = (10 ** 30, float("inf"), float("nan"))

    def _valid(self):
        return dict(_doc({"acme": {"acme:x": _entry()}}), fetched_at=1790000000)

    def _put(self, path, value):
        doc = self._valid()
        if not path:
            return value
        target = doc
        for key in path[:-1]:
            target = target[key]
        target[path[-1]] = value
        if path[0] == "catalogue":
            # Recomputed, so the only thing wrong is the type under test.
            doc["digest"] = feed.digest(doc["catalogue"])
        return doc

    def _write(self, doc):
        os.makedirs(os.path.dirname(feed.feed_path()), exist_ok=True)
        with open(feed.feed_path(), "w", encoding="utf-8") as fh:
            json.dump(doc, fh)
        catalog.reset_feed_cache()

    @staticmethod
    def _same(a, b):
        return type(a) is type(b) and a == b

    def test_the_unmodified_cache_is_active(self):
        """Or every case below would pass for the wrong reason."""
        self._write(self._valid())
        self.assertIsNotNone(feed.load())
        self.assertTrue(feed.status()["active"])
        self.assertTrue(catalog.lookup("acme", "acme:x")["known"])

    def test_a_wrong_type_anywhere_means_no_feed(self):
        for path, allowed in self.PATHS.items():
            wrong = [v for v in self.WRONG
                     if not any(self._same(v, a) for a in allowed)]
            if path == ("fetched_at",):
                wrong += self.UNPRINTABLE
            for value in wrong:
                with self.subTest(path=path, value=value):
                    doc = self._put(path, value)
                    self._write(doc)
                    self.assertIsNone(feed.load())
                    self.assertEqual(feed.status(), {"active": False})
                    self.assertFalse(catalog.lookup("acme", "acme:x")["known"])
                    if path != ("fetched_at",):
                        # the same check guards a payload from the server,
                        # where a TypeError would escape `update` as a traceback
                        with self.assertRaises(feed.FeedError):
                            feed.validate(doc)

    def test_the_allowed_values_really_are_allowed(self):
        for path, allowed in self.PATHS.items():
            for value in allowed:
                with self.subTest(path=path, value=value):
                    self._write(self._put(path, value))
                    self.assertTrue(feed.status()["active"])

    def test_a_cache_nested_past_the_recursion_limit_is_no_feed(self):
        os.makedirs(os.path.dirname(feed.feed_path()), exist_ok=True)
        with open(feed.feed_path(), "w", encoding="utf-8") as fh:
            fh.write("[" * 100000)
        self.assertIsNone(feed.load())

    def test_update_status_says_no_feed_instead_of_crashing(self):
        self._write(self._put(
            ("catalogue", "acme", "acme:x", "authority"), ["write"]))
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = cli.main(["update", "--status"])
        self.assertEqual(rc, 0)
        self.assertIn("No feed cached", out.getvalue())
        self.assertEqual(err.getvalue(), "")


class _Body:
    """What _open returns: a response that reads as `body`."""

    def __init__(self, body):
        self.body = body

    def read(self, n=-1):
        return self.body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class AHostileFeedBodyIsAFeedError(FeedHome):
    """The server is no more trusted than the cache. Whatever it answers,
    `update` says what went wrong; it never ends in a traceback."""

    URL = "https://example.invalid/v1/catalogue"

    def _fetch(self, body):
        with mock.patch.object(feed, "_open", lambda *a, **kw: _Body(body)):
            return feed.fetch("tok", url=self.URL)

    def test_a_body_nested_past_the_recursion_limit(self):
        with self.assertRaises(feed.FeedError):
            self._fetch(b"[" * 200000)

    def test_nesting_json_can_read_but_the_digest_cannot_write(self):
        """Nested a little shallower than json.loads gives up at, an extra
        field in an entry loads and passes every type check, and then the
        digest's json.dumps runs out of stack instead."""
        head = json.dumps(_entry())[:-1]

        def body(depth):
            return ('{"schema":1,"digest":"0","catalogue":{"a":{"a:x":%s,'
                    '"extra":%s%s}}}}' % (head, "[" * depth, "]" * depth))

        def loads(depth):
            try:
                json.loads(body(depth))
                return True
            except RecursionError:
                return False

        low, high = 1, 2
        while loads(high):
            low, high = high, high * 2
        while high - low > 1:
            mid = (low + high) // 2
            low, high = (mid, high) if loads(mid) else (low, mid)
        for depth in range(max(1, low - 40), low + 2):
            with self.subTest(depth=depth):
                with self.assertRaises(feed.FeedError):
                    self._fetch(body(depth).encode())

    def test_update_prints_a_message_not_a_traceback(self):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(feed, "_open", lambda *a, **kw: _Body(b"[" * 200000)), \
                mock.patch.dict(os.environ, {"RANWHAT_TOKEN": "tok"}), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = cli.main(["update"])
        self.assertEqual(rc, 1)
        self.assertIn("not JSON", err.getvalue())
        self.assertIsNone(feed.load(), "nothing was cached")


class _FeedText:
    """An entry rated exactly as the bundle rates github/workflow, cached or
    served, and the commands that print it."""

    def _bundled(self):
        return catalog.CATALOG["github"]["workflow"]

    def _doc(self, key="workflow", version="2026.09.26", **fields):
        """An entry rated exactly as the bundle rates it, so the floor keeps
        its text: only the characters under test can make it no feed."""
        b = self._bundled()
        entry = _entry(b["label"], b["authority"], b["reversible"], b["blast"],
                       b["why"])
        entry.update(fields)
        return _doc({"github": {key: entry}}, version=version)

    def _cache(self, doc):
        os.makedirs(os.path.dirname(feed.feed_path()), exist_ok=True)
        with open(feed.feed_path(), "w", encoding="utf-8") as fh:
            json.dump(dict(doc, fetched_at=1790000000), fh)
        catalog.reset_feed_cache()

    def _run(self, argv, body=None):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.ExitStack() as stack:
            if body is not None:
                stack.enter_context(mock.patch.object(
                    feed, "_open", lambda *a, **kw: _Body(body)))
                stack.enter_context(mock.patch.dict(os.environ, {"RANWHAT_TOKEN": "tok"}))
            stack.enter_context(contextlib.redirect_stdout(out))
            stack.enter_context(contextlib.redirect_stderr(err))
            rc = cli.main(argv)
        return rc, out.getvalue(), err.getvalue()


class FeedTextCannotDriveTheTerminal(_FeedText, FeedHome):
    """A feed entry that rates a scope as the bundle does keeps its own
    label, and the report writes that label to the terminal as it is. ESC
    sequences in it could move the cursor up and erase the scores and the
    findings above it, or through OSC 52 write the clipboard. The feed is
    unsigned and the cache is writable by the agents being audited, so text
    carrying the characters watch strips from transcripts is no feed."""

    ESC = "\x1b[999A\x1b[J\x1b]52;c;ZWNobyBwd25lZA==\x07"
    CONTROLS = ("\x1b", "\x9b", "\x07", "\x00", "\n", "\r", "\t", "\x7f")

    def test_the_same_entry_in_plain_text_is_used(self):
        """Or every case below would pass for the wrong reason."""
        self._cache(self._doc(label="Plain label", why="Plain why"))
        e = catalog.lookup("github", "workflow")
        self.assertEqual((e["label"], e["why"]), ("Plain label", "Plain why"))
        self.assertIn("Feed 2026.09.26", self._run(["update", "--status"])[1])

    def test_a_control_character_in_label_or_why_means_no_feed(self):
        for field in ("label", "why"):
            for ch in self.CONTROLS:
                with self.subTest(field=field, ch=ch):
                    doc = self._doc(**{field: "Update workflows%s[J" % ch})
                    with self.assertRaises(feed.FeedError):
                        feed.validate(doc)
                    self._cache(doc)
                    self.assertIsNone(feed.load())
                    e = catalog.lookup("github", "workflow")
                    self.assertEqual(e["label"], self._bundled()["label"])
                    self.assertEqual(e["why"], self._bundled()["why"])

    def test_a_control_character_in_a_scope_key_means_no_feed(self):
        """A wildcard key reaches the label as "(matched <key>)"."""
        doc = self._doc(key="repo\x1b[2J*")
        with self.assertRaises(feed.FeedError):
            feed.validate(doc)

    def test_the_report_carries_no_escape_from_a_cached_label(self):
        self._cache(self._doc(label="Update GitHub Actions workflows" + self.ESC))
        rc, out, _ = self._run(["demo"])
        self.assertEqual(rc, 0)
        self.assertIn(self._bundled()["label"].split()[0], out)
        self.assertNotIn("\x1b", out)
        self.assertNotIn("ZWNobyBwd25lZA", out)

    def test_update_status_carries_no_escape_from_the_version(self):
        doc = self._doc(version="2026.09.26\x1b[2J")
        with self.assertRaises(feed.FeedError):
            feed.validate(doc)
        self._cache(doc)
        rc, out, err = self._run(["update", "--status"])
        self.assertEqual(rc, 0)
        self.assertNotIn("\x1b", out + err)
        self.assertIn("No feed cached", out)

    def test_update_refuses_it_from_the_server_and_does_not_echo_it(self):
        body = json.dumps(self._doc(label="Update workflows" + self.ESC)).encode()
        rc, out, err = self._run(["update"], body=body)
        self.assertEqual(rc, 1)
        self.assertTrue(err.strip(), "update failed and said nothing")
        self.assertNotIn("\x1b", out + err)
        self.assertIsNone(feed.load(), "nothing was cached")


class FeedTextTheTerminalCannotEncodeIsNoFeed(_FeedText, FeedHome):
    """JSON can spell half of a UTF-16 surrogate pair on its own, "\\ud800",
    and json.loads turns it into a str no UTF-8 stream will write. It passed
    every check, save() escaped it back into the cache, and then every report
    showing that entry, the terminal and --html alike, ended in
    UnicodeEncodeError: a feed that stopped `demo` and `scan` for good."""

    SURROGATES = ("\ud800", "\udbff", "\udc00", "\udfff")

    def _printable(self, text):
        # What the terminal does with it. StringIO takes a lone surrogate
        # without complaint, so the capture alone would not notice.
        text.encode("utf-8")

    def test_a_lone_surrogate_in_label_or_why_means_no_feed(self):
        for field in ("label", "why"):
            for ch in self.SURROGATES:
                with self.subTest(field=field, ch=ch):
                    doc = self._doc(**{field: "Update workflows " + ch})
                    with self.assertRaises(feed.FeedError):
                        feed.validate(doc)
                    self._cache(doc)
                    self.assertIsNone(feed.load())
                    e = catalog.lookup("github", "workflow")
                    self.assertEqual(e["label"], self._bundled()["label"])
                    self.assertEqual(e["why"], self._bundled()["why"])

    def test_a_lone_surrogate_in_a_key_or_the_version_means_no_feed(self):
        b = self._bundled()
        entry = _entry(b["label"], b["authority"], b["reversible"], b["blast"],
                       b["why"])
        for where, doc in (
                ("scope", self._doc(key="workflow\ud800")),
                ("provider", _doc({"github\udfff": {"workflow": entry}})),
                ("version", self._doc(version="2026.09.26\ud800"))):
            with self.subTest(where=where):
                with self.assertRaises(feed.FeedError):
                    feed.validate(doc)
                self._cache(doc)
                self.assertIsNone(feed.load())

    def test_a_surrogate_pair_is_an_ordinary_character(self):
        """Escaped as a pair, as json.dump writes anything past U+FFFF, it
        loads as the one character it spells, and that is plain text."""
        self._cache(self._doc(label="Update workflows \U0001F512"))
        with open(feed.feed_path(), encoding="utf-8") as fh:
            self.assertIn("\\ud83d\\udd12", fh.read())
        self.assertIsNotNone(feed.load())
        self.assertEqual(catalog.lookup("github", "workflow")["label"],
                         "Update workflows \U0001F512")

    def test_demo_still_prints_and_writes_html(self):
        self._cache(self._doc(label="Update GitHub Actions workflows \ud800"))
        html = os.path.join(self.dir, "report.html")
        rc, out, err = self._run(["demo", "--html", html])
        self.assertEqual(rc, 0, err)
        self._printable(out + err)
        self.assertIn(self._bundled()["label"].split()[0], out)
        with open(html, encoding="utf-8") as fh:
            self.assertNotIn("\ud800", fh.read())

    def test_update_status_says_no_feed(self):
        self._cache(self._doc(version="2026.09.26\udc00"))
        rc, out, err = self._run(["update", "--status"])
        self.assertEqual(rc, 0, err)
        self._printable(out + err)
        self.assertIn("No feed cached", out)

    def test_update_refuses_it_from_the_server(self):
        for where, doc in (
                ("label", self._doc(label="Update workflows \ud800")),
                ("version", self._doc(version="2026.09.26\ud800"))):
            with self.subTest(where=where):
                body = json.dumps(doc).encode()
                self.assertIn(b"\\ud800", body)
                with mock.patch.object(feed, "_open",
                                       lambda *a, **kw: _Body(body)):
                    with self.assertRaises(feed.FeedError):
                        feed.fetch("tok", url="https://example.invalid/v1")
                rc, out, err = self._run(["update"], body=body)
                self.assertEqual(rc, 1)
                self.assertTrue(err.strip(), "update failed and said nothing")
                self._printable(out + err)
                self.assertIsNone(feed.load(), "nothing was cached")


class AFeedTooDeepToCacheIsAFeedError(FeedHome):
    """From Python 3.12 json.loads is bounded by the C stack, but save()
    wrote with json.dump(indent=1), which runs the pure-Python encoder,
    bounded by the recursion limit. A body nested between the two, in a
    field the digest never serializes, passed fetch() and validate(), and
    `update` then ended in a RecursionError from save() with
    catalogue.json.tmp left behind."""

    # Deeper than any encoder writes: the pure-Python one stops near the
    # recursion limit, the C one (3.14 with indent) at the C stack.
    TOO_DEEP = 200000

    def _nested(self, depth):
        value = []
        for _ in range(depth):
            value = [value]
        return value

    def _feed_dir(self):
        d = os.path.dirname(feed.feed_path())
        return sorted(os.listdir(d)) if os.path.isdir(d) else []

    def _update(self, body=None, doc=None):
        out, err = io.StringIO(), io.StringIO()
        if body is not None:
            patch = mock.patch.object(feed, "_open", lambda *a, **kw: _Body(body))
        else:
            patch = mock.patch.object(feed, "fetch", lambda *a, **kw: doc)
        with patch, mock.patch.dict(os.environ, {"RANWHAT_TOKEN": "tok"}), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = cli.main(["update"])
        return rc, err.getvalue()

    def _json_reads_up_to(self):
        """The deepest nesting json.loads accepts on this interpreter."""
        def loads(depth):
            try:
                json.loads("[" * depth + "]" * depth)
                return True
            except RecursionError:
                return False
        low, high = 1, 2
        while loads(high):
            low, high = high, high * 2
        while high - low > 1:
            mid = (low + high) // 2
            low, high = (mid, high) if loads(mid) else (low, mid)
        return low

    def _depths(self):
        # Past the recursion limit: inside the window on 3.12 and 3.13.
        # Just under what json reads: inside it on 3.14, where the C encoder
        # writes with indent and gives up a little before the decoder does.
        limit = self._json_reads_up_to()
        return sorted({sys.getrecursionlimit() + 100, limit - limit // 20})

    def _assert_all_or_nothing(self, rc, err):
        """Refused with a message and nothing on disk, or cached whole."""
        self.assertNotIn(".tmp", " ".join(self._feed_dir()))
        if rc == 1:
            self.assertTrue(err.strip(), "update failed and said nothing")
            self.assertEqual(self._feed_dir(), [])
        else:
            self.assertEqual(rc, 0, err)
            self.assertIsNotNone(feed.load())

    def test_save_refuses_it_and_writes_nothing(self):
        doc = _doc()
        doc["extra"] = self._nested(self.TOO_DEEP)
        with self.assertRaises(feed.FeedError):
            feed.save(doc)
        self.assertEqual(self._feed_dir(), [])

    def test_update_prints_a_message_when_fetch_let_it_through(self):
        doc = _doc()
        doc["extra"] = self._nested(self.TOO_DEEP)
        rc, err = self._update(doc=doc)
        self.assertEqual(rc, 1)
        self.assertIn("nested deeper", err)
        self.assertIsNone(feed.load())
        self.assertEqual(self._feed_dir(), [])

    def test_a_deep_top_level_field_the_digest_never_reads(self):
        cat = {"acme": {"acme:x": _entry()}}
        for depth in self._depths():
            with self.subTest(depth=depth):
                body = '{"schema":1,"catalogue":%s,"digest":"%s","extra":%s%s}' % (
                    json.dumps(cat), feed.digest(cat), "[" * depth, "]" * depth)
                self._assert_all_or_nothing(*self._update(body=body.encode()))
                shutil.rmtree(os.path.dirname(feed.feed_path()), ignore_errors=True)

    def test_a_deep_field_in_an_entry_with_no_digest(self):
        head = json.dumps(_entry())[:-1]
        for depth in self._depths():
            with self.subTest(depth=depth):
                body = ('{"schema":1,"catalogue":{"acme":{"acme:x":%s,'
                        '"extra":%s%s}}}}' % (head, "[" * depth, "]" * depth))
                self._assert_all_or_nothing(*self._update(body=body.encode()))
                shutil.rmtree(os.path.dirname(feed.feed_path()), ignore_errors=True)

    def test_a_write_that_fails_leaves_no_temp_file(self):
        with mock.patch.object(feed.os, "replace",
                               mock.Mock(side_effect=OSError("disk full"))):
            with self.assertRaises(OSError):
                feed.save(_doc())
        self.assertEqual(self._feed_dir(), [])


class ATokenNeverReachesTheErrorOutput(FeedHome):
    """http.client refuses a header value with a line break in it, and its
    ValueError quotes the header: "Bearer <token>", printed to stderr and to
    any log that keeps it. A trailing \\r from a CRLF file is enough."""

    # Not token-shaped, so nothing here reads as a credential.
    TOKEN = "FAKE" "_feed_token_1234"

    def setUp(self):
        super().setUp()
        self.sent = []
        patch = mock.patch.object(feed, "_open", self._open)
        patch.start()
        self.addCleanup(patch.stop)

    def _open(self, req, *a, **kw):
        # What http.client would do with the header, so the test sees the
        # same failure the real request would.
        value = req.get_header("Authorization")
        value.encode("latin-1")
        if "\r" in value or "\n" in value:
            raise ValueError("Invalid header value %r" % value.encode("latin-1"))
        self.sent.append(value)
        return _Body(json.dumps(_doc()).encode())

    def _update(self, argv=(), env=None):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.dict(os.environ, env or {}), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = cli.main(["update"] + list(argv))
        return rc, out.getvalue() + err.getvalue()

    def test_a_trailing_return_on_the_flag_is_stripped(self):
        rc, text = self._update(["--token", self.TOKEN + "\r"])
        self.assertEqual(rc, 0, text)
        self.assertEqual(self.sent, ["Bearer " + self.TOKEN])

    def test_a_line_break_inside_the_token_is_refused_unsent(self):
        for token in (self.TOKEN[:6] + "\n" + self.TOKEN[6:],
                      self.TOKEN[:6] + "\r" + self.TOKEN[6:],
                      self.TOKEN + "\x00", self.TOKEN + "\u0107"):
            routes = [(["--token", token], None)]
            if "\x00" not in token:   # the environment cannot hold one
                routes.append(((), {"RANWHAT_TOKEN": token}))
            for argv, env in routes:
                with self.subTest(token=token, env=bool(env)):
                    rc, text = self._update(argv, env)
                    self.assertEqual(rc, 1)
                    self.assertEqual(self.sent, [])
                    self.assertNotIn(self.TOKEN[6:], text)

    def test_a_header_refused_anyway_is_not_quoted(self):
        def refuse(req, *a, **kw):
            raise ValueError("Invalid header value %r"
                             % req.get_header("Authorization"))
        with mock.patch.object(feed, "_open", refuse):
            with self.assertRaises(feed.FeedError) as caught:
                feed.fetch(self.TOKEN, url="https://example.invalid/v1")
        self.assertNotIn(self.TOKEN, str(caught.exception))
        self.assertTrue(caught.exception.__suppress_context__)


class TheTokenOnlyTravelsOverTLS(unittest.TestCase):

    def test_plain_http_is_refused_before_anything_is_sent(self):
        for url in ("http://feed.example.com/v1", "file:///etc/passwd",
                    "ftp://feed.example.com/"):
            with self.assertRaises(feed.FeedError, msg=url):
                feed.fetch("tok", url=url)

    def test_http_to_this_machine_is_allowed_for_local_testing(self):
        feed._check_url("http://localhost:8787/v1/catalogue")
        feed._check_url("http://127.0.0.1:8787/v1/catalogue")

    def test_a_redirect_is_not_followed_with_the_token(self):
        import urllib.request
        h = feed._NoRedirect()
        req = urllib.request.Request("https://feed.ranwhat.com/v1/catalogue",
                                     headers={"Authorization": "Bearer tok"})
        with self.assertRaises(feed.FeedError):
            h.redirect_request(req, None, 302, "Found", {}, "http://evil.example/")


if __name__ == "__main__":
    unittest.main()
