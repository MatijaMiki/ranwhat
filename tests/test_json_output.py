"""--json writes the same text json.dumps(indent=2) does, faster.

The standard library writes indented JSON in pure Python, and for a
megabyte of distinct secrets clean --json and check --json spent a third
of their second writing it. Every value here is synthetic."""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ranwhat import cli


class SameTextAsTheStandardLibrary(unittest.TestCase):

    DOCS = [
        {"days": 30, "actions": [], "secrets": []},
        {"scanned": 0, "applied": False, "changed": [], "findings": []},
        [],
        {},
        {"a": None, "b": True, "c": False, "d": 0, "e": -12, "f": 1.5,
         "g": float("inf"), "h": float("nan"), "i": 10 ** 30, "j": "",
         "k": "… é \U0001F600 \"quoted\" back\\slash \n\t\x00\x1f",
         "l": [[], {}, [1, [2, [3]]], {"x": {"y": {}}}],
         "m": ("a", "b"), "n": [{"o": [None]}]},
        {1: "int key", 2.5: "float key", True: "bool key", None: "none key"},
        [{"fingerprint": "f9138bb91f0d", "label": "AWS access key ID", "length": 20,
          "hint": "AKIA…CZ4K", "files": ["/tmp/a b/s.jsonl"], "origins": [],
          "projects": ["/tmp/a b"], "count": 1}] * 3,
        "a bare string",
        12,
    ]

    def test_the_same_text(self):
        for doc in self.DOCS:
            with self.subTest(doc=repr(doc)[:60]):
                self.assertEqual(cli._json_text(doc), json.dumps(doc, indent=2))

    def test_what_it_cannot_write_fails_the_same_way(self):
        for doc in ({"x": object()}, {(1, 2): "tuple key"}, {"x": {1, 2}}):
            with self.subTest(doc=repr(doc)[:60]):
                with self.assertRaises(TypeError):
                    json.dumps(doc, indent=2)
                with self.assertRaises(TypeError):
                    cli._json_text(doc)


if __name__ == "__main__":
    unittest.main(verbosity=2)
