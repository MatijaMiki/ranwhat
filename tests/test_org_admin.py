"""scripts/org_admin.py: the SQL it prints, run against the grants and orgs
tables exactly as worker/src/accounts.js makes them. What a grant then does
to an organisation's plan is worker/test/plans.test.mjs's.
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
ORG = "0b6f6a52-6c1e-4f43-9d0e-5c2a7f3e9b10"


def _script():
    spec = importlib.util.spec_from_file_location("org_admin", ROOT / "scripts" / "org_admin.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _table(name):
    return re.search(r"`(CREATE TABLE IF NOT EXISTS %s \(.*?\))`" % name, ACCOUNTS, re.S).group(1)


class OrgAdmin(unittest.TestCase):

    def setUp(self):
        self.tool = _script()
        self.db = sqlite3.connect(":memory:")
        self.db.executescript("%s; %s;" % (_table("orgs"), _table("grants")))
        self.db.execute("INSERT INTO orgs (id, name, personal, created_at) VALUES (?, 'Acme', 0, 1)", (ORG,))

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

    def test_wrong_use_prints_the_usage_and_writes_nothing(self):
        for args in (["grant", "plus", ORG, "note"], ["grant", "team", ORG, "  "],
                     ["grant", "team", ORG, "note", "--days", "0"], ["grant", "team", ORG, "note", "--days"],
                     ["revoke", "team", ORG, "--days", "3"], ["delete", "team", ORG], []):
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
