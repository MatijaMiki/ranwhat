"""ranwhat reach: MCP servers, credential files an agent can read, and the
Claude Code deny rules that would cover them.

Each fixture is a home folder of its own, so nothing here reads the
machine running the tests. Token-shaped literals are split in two, so a
push of this file is not mistaken for a leak.
"""
import contextlib
import io
import json
import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import isolated_home  # noqa: E402,F401  ranwhat's state, never ~/.ranwhat
from ranwhat import cli, reach  # noqa: E402
from ranwhat.sources import _paths  # noqa: E402

GH = "ghp_" "KjDe8OR21NpsrTGY5aWtw5hESARqQFKIrIiK"
API = "k3J9xQ2mV8pL1zR7" "tY4wN6bH"
BEARER = "Qz7Rw2Lp9Xv4" "Nk8Ts1Hm6Jd3"
STRIPE = "sk_" "live_" "4eC39HqLyjWDarjtT1zdp7dc"
AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/" "bPxRfiCYzEXAMPLEKEY9"
DB_PASSWORD = "S3cr3tPassw0rd!x"


def write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text if isinstance(text, str) else json.dumps(text, indent=2))
    return path


class _Home(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="ranwhat-reach-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.home = os.path.join(self.tmp, "home")
        self.project = os.path.join(self.home, "code", "app")
        self.managed = os.path.join(self.tmp, "managed")
        os.makedirs(self.project)
        os.makedirs(self.managed)
        patcher = mock.patch.object(reach, "managed_dirs",
                                    return_value=[self.managed])
        patcher.start()
        self.addCleanup(patcher.stop)

    def claude_json(self, doc):
        return write(os.path.join(self.home, ".claude.json"), doc)

    def user_settings(self, doc):
        return write(os.path.join(self.home, ".claude", "settings.json"), doc)

    def audit(self, env=None, projects=None, cwd=None):
        return reach.audit(env=env or {}, home=self.home, cwd=cwd,
                           projects=[self.project] if projects is None else projects,
                           platform="linux")

    def server(self, result, name):
        found = [s for s in result["servers"] if s["name"] == name]
        self.assertEqual(len(found), 1, [s["name"] for s in result["servers"]])
        return found[0]

    def kinds(self, server):
        return sorted(r["kind"] for r in server["risks"])

    def paths(self, result):
        return sorted(os.path.relpath(f["path"], self.home) for f in result["files"])

    def run_cli(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(_paths, "home", return_value=self.home), \
             mock.patch.dict(os.environ, {"HOME": self.home}), \
             contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            for name in ("CLAUDE_CONFIG_DIR", "CODEX_HOME", "GEMINI_CLI_HOME",
                         "QWEN_HOME", "COPILOT_HOME", "KUBECONFIG",
                         "AWS_SHARED_CREDENTIALS_FILE"):
                os.environ.pop(name, None)
            try:
                rc = cli.main(argv)
            except SystemExit as e:
                rc = e.code
        return rc, out.getvalue(), err.getvalue()


class McpServers(_Home):

    def test_a_secret_inline_in_env_is_flagged_and_masked(self):
        self.claude_json({"mcpServers": {"github": {
            "command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"],
            "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": GH}}}})
        result = self.audit()
        s = self.server(result, "github")
        self.assertEqual(s["scope"], "user")
        self.assertIn("inline-secret", self.kinds(s))
        text = reach.render(result, self.home)
        self.assertNotIn(GH, text)
        self.assertIn("<ghp", text)
        self.assertIn("GITHUB_PERSONAL_ACCESS_TOKEN", text)
        doc = json.dumps(reach.as_json(result))
        self.assertNotIn(GH, doc)
        self.assertNotIn("secrets", reach.as_json(result))

    def test_as_json_leaves_the_result_as_it_was(self):
        self.claude_json({"mcpServers": {"g": {"command": "node",
                                               "env": {"GITHUB_TOKEN": GH}}}})
        result = self.audit()
        reach.as_json(result)
        self.assertEqual(self.server(result, "g")["risks"][0]["secret"], GH)

    def test_a_reference_is_not_a_secret(self):
        self.claude_json({"mcpServers": {"g": {
            "command": "node", "args": ["server.js", "--token", "${GITHUB_TOKEN}"],
            "env": {"GITHUB_TOKEN": "${GITHUB_TOKEN}", "API_KEY": "$API_KEY"},
            }, "h": {"type": "http", "url": "https://mcp.example.com/mcp",
                     "headers": {"Authorization": "Bearer ${TOKEN}"}}}})
        result = self.audit()
        self.assertNotIn("inline-secret", self.kinds(self.server(result, "g")))
        self.assertNotIn("inline-secret", self.kinds(self.server(result, "h")))

    def test_secrets_in_a_header_an_argument_and_the_url(self):
        self.claude_json({"mcpServers": {
            "hdr": {"type": "http", "url": "https://mcp.example.com/mcp",
                    "headers": {"Authorization": "Bearer " + BEARER}},
            "arg": {"command": "node", "args": ["s.js", "--api-key", API]},
            "argeq": {"command": "node", "args": ["s.js", "--api-key=" + API]},
            "url": {"type": "sse", "url": "https://mcp.example.com/sse?api_key=" + API},
            "db": {"command": "node", "args": [
                "postgresql://user:%s@db.example.com/app" % DB_PASSWORD]},
        }})
        result = self.audit()
        for name in ("hdr", "arg", "argeq", "url", "db"):
            secrets = [r for r in self.server(result, name)["risks"]
                       if r["kind"] == "inline-secret"]
            self.assertEqual(len(secrets), 1, (name, secrets))
        text = reach.render(result, self.home)
        doc = json.dumps(reach.as_json(result))
        for value in (BEARER, API, DB_PASSWORD):
            self.assertNotIn(value, text)
            self.assertNotIn(value, doc)

    def test_remote_unencrypted_and_local_urls(self):
        self.claude_json({"mcpServers": {
            "r": {"type": "http", "url": "https://mcp.stripe.com/"},
            "plain": {"type": "http", "url": "http://mcp.example.com/mcp"},
            "local": {"type": "http", "url": "http://localhost:8123/mcp"},
            "stdio": {"command": "/usr/local/bin/my-server"},
        }})
        result = self.audit()
        self.assertEqual(self.kinds(self.server(result, "r")), ["remote"])
        self.assertEqual(self.kinds(self.server(result, "plain")),
                         ["remote", "unencrypted"])
        self.assertEqual(self.kinds(self.server(result, "local")), ["local-url"])
        self.assertEqual(self.kinds(self.server(result, "stdio")), [])

    def test_local_scope_servers_in_claude_json(self):
        self.claude_json({"projects": {self.project: {"mcpServers": {
            "mine": {"command": "uvx", "args": ["mcp-server-fetch"]}}}}})
        s = self.server(self.audit(), "mine")
        self.assertEqual((s["scope"], s["project"]), ("local", self.project))

    def test_claude_config_dir_moves_claude_json(self):
        moved = os.path.join(self.tmp, "cfg")
        write(os.path.join(moved, ".claude.json"),
              {"mcpServers": {"moved": {"command": "node"}}})
        result = self.audit(env={"CLAUDE_CONFIG_DIR": moved})
        self.server(result, "moved")
        self.assertEqual(result["settings"], os.path.join(moved, "settings.json"))

    def test_project_mcp_json_started_without_asking(self):
        write(os.path.join(self.project, ".mcp.json"), {"mcpServers": {
            "a": {"command": "node"}, "b": {"command": "node"}}})
        write(os.path.join(self.project, ".claude", "settings.local.json"),
              {"enableAllProjectMcpServers": True,
               "disabledMcpjsonServers": ["b"]})
        result = self.audit()
        self.assertEqual(self.kinds(self.server(result, "a")), ["auto-approved"])
        b = self.server(result, "b")
        self.assertTrue(b["disabled"])
        self.assertEqual(self.kinds(b), [])

    def test_other_agents_configs(self):
        doc = {"mcpServers": {"x": {"command": "npx", "args": ["some-mcp"]}}}
        write(os.path.join(self.home, ".cursor", "mcp.json"), doc)
        write(os.path.join(self.home, ".gemini", "settings.json"), doc)
        write(os.path.join(self.home, ".copilot", "mcp-config.json"), doc)
        write(os.path.join(self.project, ".vscode", "mcp.json"),
              {"servers": {"x": {"command": "npx", "args": ["some-mcp"]}}})
        write(os.path.join(self.project, ".cursor", "mcp.json"),
              "// a comment\n" + json.dumps(doc) + "\n")
        agents = sorted(s["agent"] for s in self.audit()["servers"])
        self.assertEqual(agents, ["Cursor", "Cursor", "Gemini CLI",
                                  "GitHub Copilot CLI", "VS Code"])

    @unittest.skipIf(reach._tomllib() is None, "tomllib is Python 3.11+")
    def test_codex_config_toml(self):
        write(os.path.join(self.home, ".codex", "config.toml"),
              '[mcp_servers.docs]\ncommand = "npx"\nargs = ["-y", "docs-mcp"]\n'
              '[mcp_servers.docs.env]\nAPI_KEY = "%s"\n' % API)
        s = self.server(self.audit(), "docs")
        self.assertEqual(s["agent"], "Codex")
        self.assertEqual(self.kinds(s), ["inline-secret", "unpinned"])

    def test_codex_without_tomllib_says_so(self):
        write(os.path.join(self.home, ".codex", "config.toml"), "[mcp_servers]\n")
        with mock.patch.object(reach, "_tomllib", return_value=None):
            read = self.audit()["configs_read"]
        notes = [r.get("note") for r in read if r["agent"] == "Codex"]
        self.assertEqual(notes, ["needs Python 3.11 or later to read"])

    def test_a_broken_config_is_said_not_fatal(self):
        write(os.path.join(self.project, ".mcp.json"), "{not json")
        self.claude_json({"mcpServers": {"ok": {"command": "node"},
                                         "bad": "not an object",
                                         "env": {"command": "node", "env": {1: 2}}}})
        result = self.audit()
        self.assertEqual(sorted(s["name"] for s in result["servers"]), ["env", "ok"])
        self.assertIn("could not be parsed",
                      [r.get("note") for r in result["configs_read"]])


class Unpinned(unittest.TestCase):

    def check(self, command, args, expected):
        got = reach.unpinned({"command": command, "args": args})
        self.assertEqual(bool(got), expected, (command, args, got))

    def test_npm_runners(self):
        self.check("npx", ["-y", "@modelcontextprotocol/server-github"], True)
        self.check("npx", ["some-mcp@latest"], True)
        self.check("npx", ["some-mcp@^1.2.0"], True)
        self.check("npx", ["-y", "some-mcp@1.2.3"], False)
        self.check("npx", ["-y", "@scope/thing@1.2.3"], False)
        self.check("npx", ["--registry", "https://r.example.com", "some-mcp"], True)
        self.check("npx", ["-p", "some-mcp@2.0.0", "some-bin"], False)
        self.check("npx", ["--package=some-mcp", "some-bin"], True)
        self.check("npx", ["./local/server.js"], False)
        self.check("npx", ["github:owner/repo"], True)
        self.check("npx", ["github:owner/repo#" + "a" * 40], False)
        self.check("/usr/local/bin/npx", ["thing"], True)
        self.check("npx.cmd", ["thing"], True)
        self.check("cmd", ["/c", "npx", "-y", "thing"], True)
        self.check("pnpm", ["dlx", "thing"], True)
        self.check("bunx", ["thing@1.0.0"], False)
        self.check("npx -y thing", None, True)

    def test_python_runners(self):
        self.check("uvx", ["mcp-server-fetch"], True)
        self.check("uvx", ["mcp-server-fetch==1.2.3"], False)
        self.check("uvx", ["mcp-server-fetch@1.2.3"], False)
        self.check("uvx", ["mcp-server-fetch>=1.0"], True)
        self.check("uvx", ["--from", "pkg==1.0.0", "cmd"], False)
        self.check("uvx", ["--from", "pkg", "cmd"], True)
        self.check("uvx", ["--python", "3.12", "pkg==1.0.0"], False)
        self.check("uvx", ["--from", "git+https://github.com/o/r", "cmd"], True)
        self.check("uv", ["tool", "run", "pkg"], True)
        self.check("pipx", ["run", "--spec", "pkg==1.0.0", "cmd"], False)
        self.check("pipx", ["run", "pkg"], True)

    def test_not_a_runner(self):
        self.check("node", ["server.js"], False)
        self.check("docker", ["run", "-i", "image"], False)
        self.check("", [], False)


class CredentialFiles(_Home):

    def env(self, rel, text):
        return write(os.path.join(self.project, rel), text)

    def test_a_dot_env_holding_a_secret_is_reported_by_path_only(self):
        self.env(".env", "STRIPE_SECRET_KEY=%s\n" % STRIPE)
        result = self.audit()
        self.assertEqual(self.paths(result), [os.path.join("code", "app", ".env")])
        self.assertEqual(result["deny"], ["Read(//**/.env)"])
        out = reach.render(result, self.home) + json.dumps(reach.as_json(result))
        self.assertNotIn(STRIPE, out)

    def test_templates_and_files_without_a_secret_are_left_out(self):
        self.env(".env.example", "STRIPE_SECRET_KEY=%s\n" % STRIPE)
        self.env(".env.sample", "API_KEY=%s\n" % API)
        self.env(".env.plain", "PORT=3000\nDEBUG=1\n")
        self.env(".env.local", "API_KEY=changeme\nTOKEN=${TOKEN}\n")
        self.env("cert.pem", "-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----\n")
        self.env(".npmrc", "registry=https://registry.npmjs.org/\n")
        os.makedirs(os.path.join(self.project, ".env"))   # a virtualenv
        self.assertEqual(self.audit()["files"], [])

    def test_nested_files_but_not_in_node_modules(self):
        self.env(os.path.join("apps", "web", ".env.local"), "API_KEY=%s\n" % API)
        self.env(os.path.join("node_modules", "pkg", ".env"), "API_KEY=%s\n" % API)
        self.env(os.path.join("certs", "server.key"),
                 "-----BEGIN PRIVATE KEY-----\nMIIabc\n-----END PRIVATE KEY-----\n")
        self.assertEqual(self.paths(self.audit()), [
            os.path.join("code", "app", "apps", "web", ".env.local"),
            os.path.join("code", "app", "certs", "server.key")])

    def test_home_credential_files(self):
        write(os.path.join(self.home, ".aws", "credentials"),
              "[default]\naws_access_key_id = AKIA" "IOSFODNN7EXAMPLE\n"
              "aws_secret_access_key = %s\n" % AWS_SECRET)
        write(os.path.join(self.home, ".aws", "config"), "[default]\nregion = x\n")
        write(os.path.join(self.home, ".ssh", "id_ed25519"),
              "-----BEGIN OPENSSH PRIVATE KEY-----\nb3Blbg==\n-----END OPENSSH PRIVATE KEY-----\n")
        write(os.path.join(self.home, ".ssh", "id_ed25519.pub"), "ssh-ed25519 AAAA x\n")
        write(os.path.join(self.home, ".ssh", "known_hosts"), "host key\n")
        write(os.path.join(self.home, ".docker", "config.json"),
              '{"auths": {"https://index.docker.io/v1/": {"auth": "dXNlcjpwYXNz"}}}')
        write(os.path.join(self.home, ".kube", "config"),
              "users:\n- name: x\n  user:\n    exec:\n      command: aws\n")
        result = self.audit()
        self.assertEqual(self.paths(result), [
            os.path.join(".aws", "credentials"), os.path.join(".docker", "config.json"),
            os.path.join(".ssh", "id_ed25519")])
        self.assertEqual(result["deny"], ["Read(~/.aws/credentials)",
                                          "Read(~/.ssh/**)",
                                          "Read(~/.docker/config.json)"])
        out = reach.render(result, self.home)
        self.assertNotIn(AWS_SECRET, out)
        self.assertNotIn("dXNlcjpwYXNz", out)

    def test_the_project_is_not_walked_when_it_is_home(self):
        write(os.path.join(self.home, "deep", ".env"), "API_KEY=%s\n" % API)
        self.assertEqual(self.audit(projects=[self.home])["files"], [])

    def test_projects_come_from_claude_json_and_the_current_directory(self):
        other = os.path.join(self.home, "code", "other")
        write(os.path.join(other, ".env"), "API_KEY=%s\n" % API)
        self.env(".env", "API_KEY=%s\n" % API)
        self.claude_json({"projects": {other: {}, "/no/such/dir": {}}})
        result = reach.audit(env={}, home=self.home, cwd=self.project,
                             platform="linux")
        self.assertEqual(result["projects"], [self.project, other])
        self.assertEqual(len(result["files"]), 2)


class DenyRules(_Home):
    """Read deny rules, anchored as Claude Code's permissions reference
    and site/guides/claude-code-env-secrets.html lay them out."""

    def setUp(self):
        _Home.setUp(self)
        self.top = write(os.path.join(self.project, ".env"), "API_KEY=%s\n" % API)
        self.deep = write(os.path.join(self.project, "apps", "web", ".env"),
                          "API_KEY=%s\n" % API)
        self.example = write(os.path.join(self.project, ".env.local"),
                             "API_KEY=%s\n" % API)

    def left(self, user=None, project=None):
        if user is not None:
            self.user_settings({"permissions": {"deny": user}})
        if project is not None:
            write(os.path.join(self.project, ".claude", "settings.json"),
                  {"permissions": {"deny": project}})
        return sorted(os.path.relpath(f["path"], self.project)
                      for f in self.audit()["files"])

    def test_dot_slash_is_the_current_directory_only(self):
        self.assertEqual(self.left(project=["Read(./.env)"]),
                         [".env.local", os.path.join("apps", "web", ".env")])

    def test_a_bare_name_and_double_star_reach_any_depth(self):
        for rule in ("Read(.env)", "Read(**/.env)"):
            self.assertEqual(self.left(project=[rule]), [".env.local"], rule)

    def test_double_slash_is_the_filesystem_root(self):
        self.assertEqual(self.left(user=["Read(//**/.env)", "Read(//**/.env.*)"]), [])

    def test_a_single_slash_in_user_settings_is_under_claude_dir(self):
        # The trap the .env guide names: /code/** in ~/.claude/settings.json
        # is ~/.claude/code/**, not ~/code/**.
        self.assertEqual(len(self.left(user=["Read(/code/**)"])), 3)
        self.assertEqual(self.left(user=["Read(/../code/app/**)"]), [])

    def test_a_single_slash_in_project_settings_is_the_project(self):
        self.assertEqual(self.left(project=["Read(/apps/**)"]),
                         [".env", ".env.local"])

    def test_a_bang_carves_out_of_relative_rules_only(self):
        self.assertEqual(self.left(project=["Read(./.env*)", "Read(!.env.local)"]),
                         [".env.local", os.path.join("apps", "web", ".env")])
        self.assertEqual(self.left(user=["Read(//**/.env.local)"],
                                   project=["Read(!.env.local)"]), [
            ".env", os.path.join("apps", "web", ".env")])

    def test_a_directory_rule_covers_what_is_in_it(self):
        self.assertEqual(self.left(project=["Read(./apps)"]), [".env", ".env.local"])
        self.assertEqual(self.left(project=["Read(./apps/)"]), [".env", ".env.local"])

    def test_bare_read_denies_everything(self):
        self.assertEqual(self.left(user=["Read"]), [])

    def test_other_tools_do_not_count(self):
        self.assertEqual(len(self.left(user=["Bash(cat .env)", "Edit(.env)",
                                             "WebFetch"])), 3)

    def test_home_rules(self):
        write(os.path.join(self.home, ".aws", "credentials"),
              "aws_secret_access_key = %s\n" % AWS_SECRET)
        self.user_settings({"permissions": {"deny": ["Read(~/.aws/**)"]}})
        self.assertNotIn(os.path.join(self.home, ".aws", "credentials"),
                         [f["path"] for f in self.audit()["files"]])

    def test_the_rules_it_suggests_cover_what_it_found(self):
        # The invariant: paste the block, run again, and nothing is left.
        write(os.path.join(self.home, ".aws", "credentials"),
              "aws_secret_access_key = %s\n" % AWS_SECRET)
        write(os.path.join(self.home, ".ssh", "id_rsa"),
              "-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----\n")
        write(os.path.join(self.project, "odd [name]", "x.key"),
              "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\n")
        first = self.audit()
        self.assertEqual(len(first["files"]), 6)
        self.user_settings(json.loads(reach.snippet(first["deny"])))
        self.assertEqual(self.audit()["files"], [])


class ReviewFindings(_Home):
    """Each proven by a script in the adversarial review of reach."""

    def leaks(self, servers, *values):
        self.claude_json({"mcpServers": servers})
        result = self.audit()
        out = reach.render(result, self.home) + json.dumps(reach.as_json(result))
        return [v for v in values if v in out]

    def test_a_header_passed_as_an_argument_is_masked(self):
        # mcp-remote's shape: --header "Authorization: Bearer X".
        for args in (["--header", "Authorization: Bearer " + BEARER],
                     ["--header", "Authorization:Bearer " + BEARER],
                     ["--header", "X-API-Key: " + BEARER],
                     ["--header=X-API-Key:" + BEARER]):
            self.assertEqual(self.leaks({"r": {
                "command": "npx", "args": ["-y", "mcp-remote@0.1.29",
                                           "https://m.example.com/sse"] + args}},
                BEARER), [], args)

    def test_a_secret_holding_a_quote_is_masked_in_text(self):
        password = 'hunter2Passw0rdXy"x9'
        self.assertEqual(self.leaks({"p": {"command": "node", "args": [
            "postgresql://admin:%s@db.example.com/prod" % password]}},
            password, "hunter2Passw0rd"), [])

    def test_a_default_after_a_reference_and_a_secret_name_are_masked(self):
        self.assertEqual(self.leaks({
            "d": {"command": "node", "args": ["--token", "${GH:-%s}" % GH]},
            "e": {"command": "node", "args": ["{env:X}" + GH]},
            GH: {"command": "node"}}, GH), [])

    def test_a_git_spec_without_a_scheme_does_not_crash(self):
        self.assertTrue(reach.unpinned({"command": "uvx", "args": [
            "--from", "git+github.com/o/r", "cmd"]}))

    def test_a_malformed_deny_rule_does_not_crash(self):
        write(os.path.join(self.project, ".env"), "API_KEY=%s\n" % API)
        self.user_settings({"permissions": {"deny": ["Read(.env.[z-a])",
                                                     "Read(a[]b)"]}})
        self.assertEqual(len(self.audit()["files"]), 1)

    def test_a_config_it_could_not_read_is_said_in_text(self):
        write(os.path.join(self.home, ".codex", "config.toml"), "[mcp_servers]\n")
        write(os.path.join(self.project, ".mcp.json"), "{broken")
        with mock.patch.object(reach, "_tomllib", return_value=None):
            text = reach.render(self.audit(), self.home)
        self.assertIn("None found in 0 configuration files read.", text)
        self.assertIn("Not read: ~/.codex/config.toml (Codex), needs Python 3.11",
                      " ".join(text.split()))
        self.assertIn("could not be parsed", text)

    def test_deep_and_build_directories(self):
        deep = write(os.path.join(self.project, *("abcdefgh")), "API_KEY=%s\n" % API)
        os.rename(deep, os.path.join(os.path.dirname(deep), ".env"))
        write(os.path.join(self.project, "build", ".env.production"),
              "API_KEY=%s\n" % API)
        write(os.path.join(self.project, "dist", "deeper", ".env"), "API_KEY=%s\n" % API)
        result = self.audit()
        self.assertEqual(self.paths(result),
                         [os.path.join("code", "app", "build", ".env.production")])
        self.assertEqual(result["cut_short"], [{"project": self.project, "why": "depth"}])
        self.assertIn("deeper than %d levels" % reach.WALK_DEPTH,
                      " ".join(reach.render(result, self.home).split()))

    def test_a_dot_env_in_home(self):
        write(os.path.join(self.home, ".env"), "API_KEY=%s\n" % API)
        result = self.audit()
        self.assertEqual(self.paths(result), [".env"])
        self.assertEqual(result["deny"], ["Read(~/.env)"])

    def test_relative_paths_from_the_environment_round_trip(self):
        here = os.path.join(self.tmp, "cwd")
        write(os.path.join(here, "relkube"),
              "users:\n- user:\n    token: %s\n" % BEARER)
        old = os.getcwd()
        os.chdir(here)
        self.addCleanup(os.chdir, old)
        env = {"KUBECONFIG": "relkube"}
        first = self.audit(env=env)
        self.assertEqual([os.path.realpath(f["path"]) for f in first["files"]],
                         [os.path.realpath(os.path.join(here, "relkube"))])
        self.user_settings(json.loads(reach.snippet(first["deny"])))
        self.assertEqual(self.audit(env=env)["files"], [])

    @unittest.skipIf(os.name == "nt", "names Windows cannot hold")
    def test_odd_names_round_trip(self):
        for name in (".env.local ", ".env.back\\slash", ".env.[x]*?"):
            write(os.path.join(self.project, name), "API_KEY=%s\n" % API)
        first = self.audit()
        self.assertEqual(len(first["files"]), 3)
        self.user_settings(json.loads(reach.snippet(first["deny"])))
        self.assertEqual(self.audit()["files"], [])

    def test_a_token_under_a_yaml_header(self):
        path = write(os.path.join(self.home, ".config", "gh", "hosts.yml"),
                     "ghe.corp.example.com:\n    oauth_token: %s\n" % BEARER)
        self.assertTrue(reach.holds_credential(path, "credentials"))

    def test_exact_pypi_versions_and_more_runners(self):
        for spec in ("mcp-server-time==0.6", "pkg==1.0.0rc1", "pkg==2.0.0.post1"):
            self.assertIsNone(reach.unpinned({"command": "uvx", "args": [spec]}), spec)
        self.assertTrue(reach.unpinned({"command": "uvx", "args": ["pkg==1.*"]}))
        self.assertTrue(reach.unpinned({"command": "uv", "args": [
            "run", "--with", "mcp", "mcp", "run", "server.py"]}))
        self.assertIsNone(reach.unpinned({"command": "uv", "args": [
            "run", "--with", "mcp==1.2.0", "server.py"]}))
        self.assertIsNone(reach.unpinned({"command": "uv", "args": ["run", "server.py"]}))
        self.assertTrue(reach.unpinned({"command": "npx -y pkg", "args": ["--foo"]}))

    def test_a_flag_inside_a_command_string_is_masked(self):
        self.assertEqual(self.leaks({"c": {"command": "node server.js --api-key " + API,
                                           "args": ["--verbose"]}}, API), [])

    def test_a_key_or_token_in_a_hosted_server_url(self):
        self.assertEqual(self.leaks({
            "q": {"type": "sse", "url": "https://mcp.example.com/sse?key=" + BEARER},
            "z": {"type": "sse", "url": "https://actions.zapier.com/mcp/sk-ak-%s/sse"
                                        % BEARER}}, BEARER), [])
        for url in ("https://mcp.example.com/servers/"
                    "123e4567-e89b-12d3-a456-426614174000/sse",
                    "https://example.com/a/modelcontextprotocol-server-github2/sse",
                    "https://mcp.example.com/sse?key=changeme"):
            self.assertEqual(reach._url_secrets(url), [], url)

    def test_deeply_nested_toml_does_not_crash(self):
        write(os.path.join(self.home, ".codex", "config.toml"),
              "x = " + "[" * 100000 + "]" * 100000 + "\n")
        self.audit()


class Command(_Home):

    def test_it_writes_nothing(self):
        settings = self.user_settings({"permissions": {"deny": []}})
        write(os.path.join(self.project, ".env"), "API_KEY=%s\n" % API)
        before = sorted((dirpath, sorted(files)) for dirpath, _d, files
                        in os.walk(self.tmp))
        with open(settings, encoding="utf-8") as fh:
            text = fh.read()
        rc, out, _ = self.run_cli(["reach", self.project])
        self.assertEqual(rc, 0)
        self.assertIn('"Read(//**/.env)"', out)
        self.assertIn("nothing was", out)
        with open(settings, encoding="utf-8") as fh:
            self.assertEqual(fh.read(), text)
        self.assertEqual(sorted((dirpath, sorted(files)) for dirpath, _d, files
                                in os.walk(self.tmp)), before)

    def test_json_is_masked_and_parses(self):
        self.claude_json({"mcpServers": {"g": {"command": "node",
                                               "env": {"GITHUB_TOKEN": GH}}}})
        write(os.path.join(self.project, ".env"), "API_KEY=%s\n" % API)
        rc, out, _ = self.run_cli(["reach", self.project, "--json"])
        self.assertEqual(rc, 0)
        self.assertNotIn(GH, out)
        self.assertNotIn(API, out)
        doc = json.loads(out)
        self.assertEqual(doc["deny"], ["Read(//**/.env)"])
        self.assertEqual(doc["servers"][0]["risks"][0]["secret"][0], "<")

    def test_flags_it_does_not_take_are_refused(self):
        for flag in (["--apply"], ["--days", "5"], ["--source", "codex"],
                     ["--root", self.tmp], ["--no-interactive"]):
            rc, _, err = self.run_cli(["reach"] + flag)
            self.assertEqual(rc, 2, flag)
            self.assertIn("not for reach", err, flag)

    def test_a_path_that_is_not_a_directory(self):
        rc, _, err = self.run_cli(["reach", os.path.join(self.tmp, "nope")])
        self.assertEqual(rc, 2)
        self.assertIn("project directory", err)

    def test_listed_in_the_overview(self):
        self.assertIn("reach", [name for name, _ in cli.COMMANDS])


if __name__ == "__main__":
    unittest.main()
