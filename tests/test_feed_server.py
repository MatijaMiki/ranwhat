"""The feed server's side of `ranwhat update`.

The Worker (worker/src/feed.js) serves worker/feed/catalogue.json as it is,
so everything the client will check has to be true of that file:
worker/test/feed.test.mjs runs the real client against the Worker, and these
keep the file itself in step with ranwhat/catalog.py and its overlay, and
the token tool honest.
"""
import hashlib
import importlib.util
import json
import os
import pathlib
import re
import shutil
import tempfile
import unittest

import ranwhat
from ranwhat import catalog, feed

ROOT = pathlib.Path(__file__).resolve().parent.parent
PUBLISHED = ROOT / "worker" / "feed" / "catalogue.json"
RATINGS = ("authority", "reversible", "blast")


def _script(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / ("%s.py" % name))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class PublishedCatalogue(unittest.TestCase):

    def setUp(self):
        self.script = _script("feed")
        self.doc = feed.validate(json.loads(PUBLISHED.read_text(encoding="utf-8")))
        self.overlay = self.script.read_overlay()

    def test_it_is_what_the_script_makes_from_catalog_py_and_the_overlay(self):
        # After changing ranwhat/catalog.py or worker/feed/overlay.json:
        # python3 scripts/feed.py
        self.assertEqual(PUBLISHED.read_text(encoding="utf-8"), self.script.build())

    def test_the_client_accepts_it_and_its_digest(self):
        self.assertEqual(self.doc["digest"], feed.digest(self.doc["catalogue"]))
        self.assertTrue(self.doc["version"].startswith(ranwhat.__version__ + "+"))

    def test_it_contains_the_bundled_catalogue(self):
        # A subscriber never has less than the release: every bundled scope
        # is there, as bundled unless the overlay raises it.
        published = self.doc["catalogue"]
        for provider, scopes in catalog.CATALOG.items():
            self.assertIn(provider, published)
            for scope, entry in scopes.items():
                with self.subTest(provider=provider, scope=scope):
                    self.assertIn(scope, published[provider])
                    if scope not in self.overlay.get(provider, {}):
                        self.assertEqual(published[provider][scope], entry)

    def test_every_overlay_scope_is_new_or_raises_a_rating(self):
        published = self.doc["catalogue"]
        for provider, scopes in self.overlay.items():
            for scope, entry in scopes.items():
                with self.subTest(provider=provider, scope=scope):
                    fields = {k: entry[k] for k in feed.FIELDS}
                    self.assertEqual(published[provider][scope], fields)
                    bundle = catalog.CATALOG.get(provider, {})
                    bundled = bundle.get(scope)
                    if bundled is None:
                        # New, unless a bundled wildcard covers it: then the
                        # client floors it there, as it does an exact key.
                        floor = catalog._resolve(bundle, scope)
                        if floor is not None:
                            self.assertEqual(catalog._no_lower(floor, fields), fields,
                                             "the client would floor it")
                        continue
                    self.assertEqual(catalog._no_lower(bundled, fields), fields,
                                     "the client would floor it")
                    self.assertTrue(any(fields[k] != bundled[k] for k in RATINGS),
                                    "it raises no rating")

    def test_it_extends_this_release_or_holds_nothing(self):
        # At a release its entries move into catalog.py and "after" moves on;
        # a version bump that skipped that would not get this far.
        doc = json.loads((ROOT / "worker" / "feed" / "overlay.json").read_text(encoding="utf-8"))
        if any(doc["providers"].values()):
            self.assertEqual(doc["after"], ranwhat.__version__)

    def test_nothing_else_is_published(self):
        expected = {(p, s) for p, scopes in catalog.CATALOG.items() for s in scopes}
        expected |= {(p, s) for p, scopes in self.overlay.items() for s in scopes}
        self.assertEqual({(p, s) for p, scopes in self.doc["catalogue"].items() for s in scopes},
                         expected)

    def test_the_version_says_whether_the_feed_runs_past_the_release(self):
        base = "%s+%s" % (ranwhat.__version__, self.doc["digest"][:8])
        added = [e["added"] for scopes in self.overlay.values() for e in scopes.values()]
        self.assertEqual(self.doc["version"], base + ("." + max(added) if added else ""))

    def test_the_worker_serves_that_file_at_the_address_the_client_asks(self):
        src = (ROOT / "worker" / "src" / "feed.js").read_text(encoding="utf-8")
        self.assertIn('from "../feed/catalogue.json" with { type: "json" }', src)
        index = (ROOT / "worker" / "src" / "index.js").read_text(encoding="utf-8")
        self.assertIn('"/v1/catalogue": [catalogue, ["GET"]]', index)
        self.assertEqual(feed.DEFAULT_ENDPOINT, "https://feed.ranwhat.com/v1/catalogue")


def _entry(authority="write", reversible=False, blast="data_egress",
           added="2026-10-05", source="https://docs.example.com/scopes", **more):
    entry = {"label": "Manage widgets", "authority": authority, "reversible": reversible,
             "blast": blast, "why": "Can change every widget.", "added": added,
             "source": source}
    entry.update(more)
    return entry


class Overlay(unittest.TestCase):
    """The overlay is empty at each release, so the committed one says
    little about the merge. These build from overlays written here."""

    # A bundled scope with a rating left to raise: calendar events can be
    # deleted, so not every write through it can be undone.
    CALENDAR = "https://www.googleapis.com/auth/calendar"

    def setUp(self):
        self.script = _script("feed")
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, True)

    def _build(self, providers, after=ranwhat.__version__):
        path = os.path.join(self.dir, "overlay.json")
        doc = {"note": "test", "after": after, "providers": providers}
        if after is None:
            del doc["after"]
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(doc, fh)
        return feed.validate(json.loads(self.script.build(path)))

    def _refused(self, providers, says, **build):
        with self.assertRaisesRegex(self.script.OverlayError, says):
            self._build(providers, **build)

    def test_an_empty_overlay_publishes_the_release(self):
        doc = self._build({})
        self.assertEqual(doc["catalogue"], catalog.CATALOG)
        self.assertEqual(doc["version"], "%s+%s" % (ranwhat.__version__,
                                                    feed.digest(catalog.CATALOG)[:8]))

    def test_a_new_scope_is_published_without_its_date_and_source(self):
        doc = self._build({"github": {"manage:widgets": _entry()},
                           "acme": {"widgets:write": _entry(added="2026-10-06")}})
        self.assertEqual(doc["catalogue"]["github"]["manage:widgets"],
                         {k: _entry()[k] for k in feed.FIELDS})
        self.assertIn("widgets:write", doc["catalogue"]["acme"])
        # Dated by its newest entry, after the digest of what it serves.
        self.assertEqual(doc["version"], "%s+%s.2026-10-06" % (
            ranwhat.__version__, feed.digest(doc["catalogue"])[:8]))

    def test_a_raised_rating_is_published_as_written(self):
        raised = _entry(reversible=False, blast="external_comms")
        doc = self._build({"google": {self.CALENDAR: raised}})
        self.assertEqual(doc["catalogue"]["google"][self.CALENDAR],
                         {k: raised[k] for k in feed.FIELDS})

    def test_the_client_rates_each_published_scope_as_the_overlay_does(self):
        """What the build accepts, catalog.lookup() shows as written: the
        two apply the same floor."""
        new, raised = _entry(), _entry(reversible=False, blast="external_comms")
        # A new wildcard under the bundled s3:*, rated as s3:* is: the client
        # floors it there, and keeps its own label and why.
        under = _entry(authority="destructive", label="Write any S3 object")
        doc = self._build({"github": {"manage:widgets": new},
                           "google": {self.CALENDAR: raised},
                           "aws": {"s3:Put*": under}})
        old = os.environ.get("RANWHAT_HOME")
        os.environ["RANWHAT_HOME"] = self.dir
        catalog.reset_feed_cache()
        try:
            feed.save(doc)
            for provider, scope, entry in (("github", "manage:widgets", new),
                                           ("google", self.CALENDAR, raised),
                                           ("aws", "s3:Put*", under)):
                shown = catalog.lookup(provider, scope)
                self.assertTrue(shown.pop("known"))
                self.assertEqual(shown, {k: entry[k] for k in feed.FIELDS})
        finally:
            if old is None:
                os.environ.pop("RANWHAT_HOME", None)
            else:
                os.environ["RANWHAT_HOME"] = old
            catalog.reset_feed_cache()

    def test_it_cannot_lower_a_rating(self):
        self._refused({"github": {"delete_repo": _entry(authority="read", reversible=True)}},
                      "lower than the bundled entry")
        # Raising one rating does not carry the lowering of another.
        self._refused({"google": {self.CALENDAR: _entry(authority="read", reversible=False,
                                                        blast="external_comms")}},
                      "lower than the bundled entry")
        # A new key under a bundled wildcard, and one whose name is a delete verb.
        self._refused({"aws": {"s3:Get*": _entry(authority="read", reversible=True)}},
                      "bundled wildcard")
        self._refused({"aws": {"s3:DeleteBucket": _entry(authority="read", reversible=True)}},
                      "its own name")
        # A blast moved to a value that counts the same is not lower, but the
        # client keeps the bundled one, and the bundled text with it: under
        # s3:* (data_egress) and under * (infrastructure), as on a bundled key.
        for scope, blast in (("s3:Put*", "infrastructure"), ("ec2:*", "identity")):
            with self.subTest(scope=scope):
                self._refused({"aws": {scope: _entry(authority="destructive", blast=blast)}},
                              "bundled wildcard")
        self._refused({"github": {"delete_repo": _entry(authority="destructive",
                                                        blast="identity")}},
                      "lower than the bundled entry")

    def test_it_names_the_release_it_extends_and_stops_at_the_next(self):
        self._refused({}, '"after"', after=None)
        self._refused({}, '"after"', after=5)
        # Entries newer than an older release: the fold was skipped.
        self._refused({"github": {"manage:widgets": _entry()}}, "set \"after\" to %s"
                      % re.escape(ranwhat.__version__), after="0.0.1")
        # Empty, it may still name the last one; the next entry moves it on.
        self.assertEqual(self._build({}, after="0.0.1")["catalogue"], catalog.CATALOG)

    def test_an_entry_that_raises_nothing_waits_for_the_release(self):
        bundled = catalog.CATALOG["github"]["repo"]
        self._refused({"github": {"repo": _entry(**{k: bundled[k] for k in RATINGS})}},
                      "as the bundled entry does")

    def test_each_entry_says_when_it_was_added_and_where_it_is_documented(self):
        for bad in ({"added": "2026-13-01"}, {"added": "06/10/2026"}, {"added": 20261006},
                    {"source": "http://docs.example.com"}, {"source": "docs.example.com"},
                    {"source": None}):
            with self.subTest(bad=bad):
                self._refused({"github": {"manage:widgets": _entry(**bad)}}, "added|source")
        missing = _entry()
        del missing["source"]
        self._refused({"github": {"manage:widgets": missing}}, "missing source")
        self._refused({"github": {"manage:widgets": _entry(known=True)}}, "known")

    def test_the_client_checks_its_text_and_ratings(self):
        self._refused({"github": {"manage:widgets": _entry(label="Widgets\x1b[2J")}},
                      "control character")
        self._refused({"github": {"manage:widgets": _entry(authority="admin")}}, "authority")
        self._refused({"github": {"manage:widgets": _entry(reversible="false")}}, "reversible")


class TokenTool(unittest.TestCase):

    def setUp(self):
        self.tool = _script("feed_token")

    def test_tokens_are_long_random_and_the_shape_the_worker_accepts(self):
        worker = (ROOT / "worker" / "src" / "auth.js").read_text(encoding="utf-8")
        shape = re.search(r"const TOKEN = /\^Bearer \((.+)\)\$/;", worker).group(1)
        tokens = {self.tool.new_token() for _ in range(50)}
        self.assertEqual(len(tokens), 50)
        for token in tokens:
            self.assertRegex(token, "^%s$" % shape)
            self.assertGreaterEqual(len(token), 40)

    def test_the_database_gets_a_hash_and_never_the_token(self):
        token = self.tool.new_token()
        self.assertEqual(self.tool.token_hash(token), hashlib.sha256(token.encode()).hexdigest())

    def test_a_note_cannot_break_out_of_the_sql_or_the_shell(self):
        # The printed command is pasted into a shell and run as SQL: a note
        # carrying a quote, a semicolon or $( ) must arrive as plain text.
        import contextlib
        import io
        import sqlite3
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.tool.main(["feed_token.py", "new", "Ana'); DROP TABLE tokens; -- \"$(rm -rf ~)\""])
        command = re.search(r'--command "([^"]*)"', out.getvalue()).group(1)
        for char in ("$", "`", ";--", "\\"):
            self.assertNotIn(char, command)
        db = sqlite3.connect(":memory:")
        db.executescript(command)
        (note,) = db.execute("SELECT note FROM tokens").fetchone()
        self.assertNotIn("'", note)
        self.assertEqual(db.execute("SELECT count(*) FROM tokens").fetchone(), (1,))


if __name__ == "__main__":
    unittest.main()
