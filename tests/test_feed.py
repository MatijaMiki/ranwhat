"""The feed must not be able to break the three things the tool promises:
that it works offline, that it sends nothing, and that a bad payload can
never reach a report."""
import json
import os
import shutil
import tempfile
import unittest

from ranwhat import catalog, feed, score


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
        with open(feed.feed_path(), "w") as fh:
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


class TokenHandling(FeedHome):
    def test_saved_token_is_not_world_readable(self):
        path = feed.save_token("tok_abc")
        self.assertEqual(oct(os.stat(path).st_mode & 0o777), oct(0o600))

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
        for leak in (os.uname().nodename, os.path.expanduser("~")):
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

    @unittest.skipUnless(hasattr(os, "fchmod"), "POSIX only")
    def test_an_existing_loose_file_is_tightened(self):
        with open(feed.token_path(), "w") as fh:
            fh.write("old\n")
        os.chmod(feed.token_path(), 0o644)
        feed.save_token("tok_new")
        self.assertEqual(os.stat(feed.token_path()).st_mode & 0o777, 0o600)
        self.assertEqual(open(feed.token_path()).read(), "tok_new\n")


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
        with open(feed.feed_path(), "w") as fh:
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
