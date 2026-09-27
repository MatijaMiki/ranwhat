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
        self.assertEqual([r["pattern"] for r in config["routes"]], ["ranwhat.com/api/*"])


if __name__ == "__main__":
    unittest.main()
