"""scripts/org_admin.py: the SQL it prints, run against the grants, orgs,
org_subscriptions and subscriptions tables exactly as worker/src/accounts.js
and worker/src/auth.js make them. What a grant or a link then does to an
organisation's plan is worker/test/plans.test.mjs's.
"""
import contextlib
import importlib.util
import io
import pathlib
import re
import sqlite3
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
ACCOUNTS = (ROOT / "worker" / "src" / "accounts.js").read_text(encoding="utf-8")
AUTH = (ROOT / "worker" / "src" / "auth.js").read_text(encoding="utf-8")
ORG = "0b6f6a52-6c1e-4f43-9d0e-5c2a7f3e9b10"
OTHER_ORG = "7d1c2e3f-4a5b-4c6d-8e9f-0a1b2c3d4e5f"
SUB = "sub_" + "test1abcdef"


def _script():
    spec = importlib.util.spec_from_file_location("org_admin", ROOT / "scripts" / "org_admin.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _table(name, source=ACCOUNTS):
    return re.search(r"`(CREATE TABLE IF NOT EXISTS %s \(.*?\))`" % name, source, re.S).group(1)


class OrgAdmin(unittest.TestCase):

    def setUp(self):
        self.tool = _script()
        self.db = sqlite3.connect(":memory:")
        self.db.executescript("%s; %s; %s; %s;" % (_table("orgs"), _table("grants"), _table("org_subscriptions"),
                                                   _table("subscriptions", AUTH)))
        for org in (ORG, OTHER_ORG):
            self.db.execute("INSERT INTO orgs (id, name, personal, created_at) VALUES (?, 'Acme', 0, 1)", (org,))
        self.db.execute("INSERT INTO subscriptions (id, customer, status, updated_at) "
                        "VALUES (?, 'cus_test1abcdef', 'active', 1)", (SUB,))

    def run_tool(self, *args):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(self.tool.main(["org_admin.py", *args]), 0)
        command = re.search(r'--command "([^"]*)"', out.getvalue()).group(1)
        self.assertIn("     %s\n" % command, out.getvalue(), "the console and wrangler get the same SQL")
        self.db.executescript(command)
        return out.getvalue()

    def grants(self):
        return self.db.execute("SELECT org_id, plan, until, note FROM grants ORDER BY id").fetchall()

    def test_team_and_comp_become_the_plans_the_worker_reads(self):
        self.run_tool("grant", "team", ORG, "contract: Acme")
        self.run_tool("grant", "comp", ORG.upper(), "press: Ana", "--days", "30")
        (team, comp) = self.grants()
        self.assertEqual(team, (ORG, "team", None, "contract: Acme"))
        self.assertEqual(comp[:2], (ORG, "plus"))
        start = self.db.execute("SELECT starts_at FROM grants WHERE plan = 'plus'").fetchone()[0]
        self.assertEqual(comp[2], start + 30 * 24 * 3600)

    def test_revoking_ends_the_grant_and_keeps_its_row(self):
        self.run_tool("grant", "team", ORG, "contract: Acme")
        self.run_tool("grant", "comp", ORG, "press")
        self.run_tool("revoke", "team", ORG)
        rows = self.db.execute("SELECT plan, until FROM grants ORDER BY id").fetchall()
        self.assertEqual(len(rows), 2)
        self.assertIsNotNone(rows[0][1], "team ended")
        self.assertIsNone(rows[1][1], "the comp is left alone")

    def test_a_mistyped_organisation_gets_nothing(self):
        self.run_tool("grant", "team", ORG.replace("0b6f", "1b6f"), "contract: Acme")
        self.assertEqual(self.grants(), [])
        for bad in ("acme", ORG + "'; DROP TABLE grants; --", ""):
            with self.assertRaises(SystemExit), contextlib.redirect_stdout(io.StringIO()):
                self.tool.main(["org_admin.py", "grant", "team", bad, "note"])

    def test_a_note_cannot_break_out_of_the_sql_or_the_shell(self):
        printed = self.run_tool("grant", "comp", ORG, "Ana'); DROP TABLE grants; -- \"$(rm -rf ~)\"")
        command = re.search(r'--command "([^"]*)"', printed).group(1)
        for char in ("$", "`", ";--", "\\"):
            self.assertNotIn(char, command)
        (row,) = self.grants()
        self.assertNotIn("'", row[3])

    def links(self):
        return self.db.execute("SELECT subscription, org_id, how FROM org_subscriptions").fetchall()

    def test_link_ties_a_subscription_to_an_organisation_once_and_never_moves_it(self):
        printed = self.run_tool("link", SUB, ORG.upper())
        self.assertIn("Links subscription %s to organisation %s" % (SUB, ORG), printed)
        self.assertEqual(self.links(), [(SUB, ORG, "script")])
        self.run_tool("link", SUB, OTHER_ORG)
        self.assertEqual(self.links(), [(SUB, ORG, "script")], "a linked subscription stays where it is")

    def test_a_mistyped_subscription_or_organisation_links_nothing(self):
        self.run_tool("link", SUB + "x", ORG)
        self.run_tool("link", SUB, ORG.replace("0b6f", "1b6f"))
        self.assertEqual(self.links(), [])
        for sub, org in ((SUB + "'; DROP TABLE org_subscriptions; --", ORG), ("cus_test1abcdef", ORG),
                         ("sub_", ORG), ("", ORG), (SUB, "acme"), (ORG, SUB)):
            out = io.StringIO()
            with self.assertRaises(SystemExit), contextlib.redirect_stdout(out):
                self.tool.main(["org_admin.py", "link", sub, org])
            self.assertNotIn("--command", out.getvalue(), sub)

    def test_wrong_use_prints_the_usage_and_writes_nothing(self):
        for args in (["grant", "plus", ORG, "note"], ["grant", "team", ORG, "  "],
                     ["grant", "team", ORG, "note", "--days", "0"], ["grant", "team", ORG, "note", "--days"],
                     ["revoke", "team", ORG, "--days", "3"], ["delete", "team", ORG],
                     ["link", SUB, ORG, "--days", "3"], ["link", SUB], ["link", SUB, ORG, "note"], []):
            out = io.StringIO()
            with self.assertRaises(SystemExit), contextlib.redirect_stdout(out):
                self.tool.main(["org_admin.py", *args])
            self.assertNotIn("--command", out.getvalue(), args)

    def test_it_sends_nothing(self):
        source = (ROOT / "scripts" / "org_admin.py").read_text(encoding="utf-8")
        self.assertIsNone(re.search(r"^\s*(import|from)\s+(urllib|http|socket|requests|subprocess)",
                                    source, re.M))


if __name__ == "__main__":
    unittest.main()
