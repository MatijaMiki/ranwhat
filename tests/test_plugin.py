"""The Claude Code plugin in plugins/ranwhat wraps the CLI and nothing more.

It must not ship a hook (a plugin's hooks switch on at install, and the guard
is opt-in), and every command it runs must be one the CLI has.
"""
import json
import pathlib
import re
import unittest

from ranwhat import cli

ROOT = pathlib.Path(__file__).resolve().parent.parent
PLUGIN = ROOT / "plugins" / "ranwhat"


class ThePlugin(unittest.TestCase):
    def test_manifests_are_json_and_agree(self):
        market = json.loads((ROOT / ".claude-plugin" / "marketplace.json").read_text())
        manifest = json.loads((PLUGIN / ".claude-plugin" / "plugin.json").read_text())
        self.assertEqual(manifest["name"], "ranwhat")
        self.assertEqual([p["name"] for p in market["plugins"]], [manifest["name"]])
        self.assertTrue((ROOT / market["plugins"][0]["source"]).samefile(PLUGIN))

    def test_it_installs_no_hook(self):
        self.assertFalse((PLUGIN / "hooks").exists())
        self.assertNotIn("hooks", json.loads(
            (PLUGIN / ".claude-plugin" / "plugin.json").read_text()))

    def test_commands_run_only_real_subcommands(self):
        known = {name for name, _ in cli.COMMANDS}
        files = sorted(PLUGIN.rglob("*.md"))
        self.assertTrue(files)
        for f in files:
            for sub in re.findall(r"uvx ranwhat ([a-z]+)", f.read_text()):
                self.assertIn(sub, known, f)

    def test_nothing_that_changes_things_runs_unasked(self):
        for f in (PLUGIN / "commands").glob("*.md"):
            front = f.read_text().split("---")[1]
            if f.name != "guard.md":
                self.assertNotRegex(front, r"hook|--apply|revoke|clean")


if __name__ == "__main__":
    unittest.main()
