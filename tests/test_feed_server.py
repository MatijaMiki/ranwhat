"""The feed server's side of `ranwhat update`.

The Worker (worker/src/feed.js) serves worker/feed/catalogue.json as it is,
so everything the client will check has to be true of that file:
worker/test/feed.test.mjs runs the real client against the Worker, and these
keep the file itself in step with ranwhat/catalog.py and the token tool
honest.
"""
import hashlib
import importlib.util
import json
import pathlib
import re
import unittest

import ranwhat
from ranwhat import catalog, feed

ROOT = pathlib.Path(__file__).resolve().parent.parent
PUBLISHED = ROOT / "worker" / "feed" / "catalogue.json"


def _script(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / ("%s.py" % name))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class PublishedCatalogue(unittest.TestCase):

    def test_it_is_what_the_script_makes_from_catalog_py(self):
        # After changing ranwhat/catalog.py: python3 scripts/feed.py
        self.assertEqual(PUBLISHED.read_text(encoding="utf-8"), _script("feed").build())

    def test_the_client_accepts_it_and_its_digest(self):
        doc = feed.validate(json.loads(PUBLISHED.read_text(encoding="utf-8")))
        self.assertEqual(doc["catalogue"], catalog.CATALOG)
        self.assertEqual(doc["digest"], feed.digest(catalog.CATALOG))
        self.assertTrue(doc["version"].startswith(ranwhat.__version__ + "+"))

    def test_the_worker_serves_that_file_at_the_address_the_client_asks(self):
        src = (ROOT / "worker" / "src" / "feed.js").read_text(encoding="utf-8")
        self.assertIn('from "../feed/catalogue.json" with { type: "json" }', src)
        index = (ROOT / "worker" / "src" / "index.js").read_text(encoding="utf-8")
        self.assertIn('"/v1/catalogue": [catalogue, ["GET"]]', index)
        self.assertEqual(feed.DEFAULT_ENDPOINT, "https://feed.ranwhat.com/v1/catalogue")


class TokenTool(unittest.TestCase):

    def setUp(self):
        self.tool = _script("feed_token")

    def test_tokens_are_long_random_and_the_shape_the_worker_accepts(self):
        worker = (ROOT / "worker" / "src" / "feed.js").read_text(encoding="utf-8")
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
