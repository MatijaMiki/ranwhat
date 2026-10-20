"""The allow-list the Worker holds for ranwhat push, and the client's copy of it.

worker/push/schema.json is generated from the CLI's rules and agents, and
worker/test/push-vectors.json is run by the Worker's tests against its
validator and here against push.check(): the two sides refuse the same
documents, at the same pointer, for the same reason.
"""
import importlib.util
import json
import pathlib
import re
import sys
import time
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import isolated_home  # noqa: E402,F401
from ranwhat import push  # noqa: E402

PUBLISHED = ROOT / "worker" / "push" / "schema.json"
VECTORS = json.loads((ROOT / "worker" / "test" / "push-vectors.json").read_text(encoding="utf-8"))


def _script():
    spec = importlib.util.spec_from_file_location("push_schema", ROOT / "scripts" / "push_schema.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def resolved(value, now):
    if isinstance(value, dict):
        return {k: resolved(v, now) for k, v in value.items()}
    if isinstance(value, list):
        return [resolved(v, now) for v in value]
    if isinstance(value, str) and value.startswith("@now"):
        m = re.fullmatch(r"@now(?:([+-])(\d+)([hd]))?", value)
        offset = 0
        if m.group(1):
            offset = int(m.group(2)) * (3600 if m.group(3) == "h" else 86400)
            offset *= 1 if m.group(1) == "+" else -1
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now + offset))
    return value


class Published(unittest.TestCase):

    def test_it_is_what_the_script_makes_from_the_cli(self):
        # After adding a rule or an agent: python3 scripts/push_schema.py
        self.assertEqual(PUBLISHED.read_text(encoding="utf-8"), _script().build())

    def test_the_client_and_the_server_know_the_same_ids(self):
        doc = json.loads(PUBLISHED.read_text(encoding="utf-8"))
        self.assertEqual(set(doc["rules"]), set(push.rule_ids()))
        self.assertEqual(set(doc["agents"]), set(push.agent_ids()))
        self.assertEqual(doc["v"], push.SCHEMA_V)
        self.assertEqual(tuple(doc["severities"]), push.SEVERITIES)


class SharedVectors(unittest.TestCase):

    def test_every_valid_document_passes_the_client_check(self):
        now = time.time()
        for case in VECTORS["valid"]:
            with self.subTest(case["name"]):
                push.check(resolved(case["doc"], now), now)

    def test_every_invalid_one_fails_where_and_why_the_server_says(self):
        now = time.time()
        for case in VECTORS["invalid"]:
            with self.subTest(case["name"]):
                if case.get("error") == "unsupported_version":
                    self.assertEqual(case["reason"], "unsupported_version")
                with self.assertRaises(push.Invalid) as got:
                    push.check(resolved(case["doc"], now), now)
                self.assertEqual((got.exception.field, got.exception.reason),
                                 (case["field"], case["reason"]))


if __name__ == "__main__":
    unittest.main()
