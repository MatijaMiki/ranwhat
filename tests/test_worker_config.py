"""The contact Worker's wrangler.toml is only read by Cloudflare's builds, so
nothing in this repo noticed when every branch build started failing on it.

Workers Builds runs `npx wrangler preview` for any branch that is not main,
and Wrangler refuses to run that without a `previews` block. main deploys with
`wrangler deploy`, which does not care, so the gap only shows up on a pull
request."""
import pathlib
import re
import unittest

try:
    import tomllib
except ImportError:  # Python < 3.11
    tomllib = None

WRANGLER = pathlib.Path(__file__).resolve().parent.parent / "worker" / "wrangler.toml"


def _uncommented():
    return "\n".join(line for line in WRANGLER.read_text(encoding="utf-8").splitlines()
                     if not line.lstrip().startswith("#"))


class BranchBuildsCanRun(unittest.TestCase):
    def test_previews_block_is_declared_at_top_level(self):
        # A key after the first [table] header belongs to that table, so
        # `previews = {}` under [[routes]] would not count.
        top = re.split(r"(?m)^\s*\[", _uncommented(), maxsplit=1)[0]
        self.assertRegex(top, r"(?m)^previews\s*=\s*\{\s*\}\s*$",
                         "wrangler.toml needs an empty top-level previews block")

    def test_a_branch_preview_gets_no_production_binding(self):
        # A Preview inherits nothing, so an empty block means a branch build
        # cannot send mail to the real inbox or report a lead to X.
        self.assertNotRegex(_uncommented(), r"(?m)^\s*\[+\s*previews\s*[.\]]",
                            "previews must stay empty")

    @unittest.skipIf(tomllib is None, "tomllib needs Python 3.11+")
    def test_parses_with_previews_empty_and_production_intact(self):
        with WRANGLER.open("rb") as fh:
            config = tomllib.load(fh)
        self.assertEqual(config["previews"], {})
        self.assertEqual(config["name"], "ranwhat-contact")
        self.assertEqual([b["name"] for b in config["send_email"]], ["CONTACT_EMAIL"])
        self.assertEqual([r["pattern"] for r in config["routes"]],
                         ["ranwhat.com/api/*", "feed.ranwhat.com/v1/*", "account.ranwhat.com/*",
                          "ranwhat.com/device*"])
        # Routes, not custom domains, so a deploy needs no DNS permission.
        for route in config["routes"]:
            self.assertEqual(route["zone_name"], "ranwhat.com")
            self.assertNotIn("custom_domain", route)

    @unittest.skipIf(tomllib is None, "tomllib needs Python 3.11+")
    def test_accounts_are_on_and_passwords_fit_the_runtime(self):
        with WRANGLER.open("rb") as fh:
            config = tomllib.load(fh)
        # Switched on at go-live (7 October 2026); src/accounts.js's
        # accountsOn() reads "1" or "true". Removing the line switches
        # accounts off again.
        self.assertEqual(config["vars"]["ACCOUNTS_ON"], "1")
        # Workers' WebCrypto refuses one PBKDF2 call above 100,000
        # iterations, so password.js runs its 600,000 as a chain of calls
        # within that. An override here could only lower the count.
        self.assertNotIn("PBKDF2_ITERATIONS", config["vars"])

    @unittest.skipIf(tomllib is None, "tomllib needs Python 3.11+")
    def test_device_codes_have_their_burst_limit(self):
        # src/device.js asks DEVICE_RL before it touches the database for a
        # device code. Workers takes a period of 10 or 60 seconds only.
        with WRANGLER.open("rb") as fh:
            config = tomllib.load(fh)
        limits = {r["name"]: r for r in config.get("ratelimits", [])}
        self.assertIn("DEVICE_RL", limits)
        self.assertRegex(limits["DEVICE_RL"]["namespace_id"], r"^[1-9][0-9]*$")
        self.assertIn(limits["DEVICE_RL"]["simple"]["period"], (10, 60))
        self.assertGreaterEqual(limits["DEVICE_RL"]["simple"]["limit"], 2)
        device = (WRANGLER.parent / "src" / "device.js").read_text(encoding="utf-8")
        self.assertIn("env.DEVICE_RL", device)

    @unittest.skipIf(tomllib is None, "tomllib needs Python 3.11+")
    def test_the_contact_binding_reaches_one_inbox(self):
        # The release list sends through Resend's API, not a binding, so the
        # only binding that can send mail still reaches one address.
        with WRANGLER.open("rb") as fh:
            self.assertEqual(tomllib.load(fh)["send_email"],
                             [{"name": "CONTACT_EMAIL", "destination_address": "ranwhatcom@gmail.com"}])

    @unittest.skipIf(tomllib is None, "tomllib needs Python 3.11+")
    def test_the_list_has_its_database_and_its_cron(self):
        with WRANGLER.open("rb") as fh:
            config = tomllib.load(fh)
        # No database_id: Wrangler creates the database on the first deploy.
        self.assertEqual(config["d1_databases"], [{"binding": "LIST", "database_name": "ranwhat-list"}])
        self.assertEqual(len(config["triggers"]["crons"]), 1)


if __name__ == "__main__":
    unittest.main()
