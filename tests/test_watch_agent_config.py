"""agent.config: what an agent may do without asking, loosened.

The one kind of call that can switch off ranwhat's own guard. Critical when
the guard itself goes, or every hook, or every prompt of every session on
the machine; high for one agent launched with no approvals, a broad allow
rule, a deny rule taken out or a settings file removed; medium for set-up
that is often asked for (an MCP server or a hook added). And the look-alikes
it must leave alone: a docs page that mentions --dangerously-skip-permissions,
a deny rule added, settings read.
"""
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import growth  # noqa: E402
import isolated_home  # noqa: E402,F401  ranwhat's state, never ~/.ranwhat
from ranwhat import hook, revoke, watch  # noqa: E402
from ranwhat.sources import ToolCall  # noqa: E402

RULE = "agent.config"
CRITICAL, HIGH, MEDIUM = watch.CRITICAL, watch.HIGH, watch.MEDIUM


def found(tool, tool_input):
    if isinstance(tool_input, str):
        tool_input = {"command": tool_input}
    return next((h for h in watch.evaluate(tool, tool_input)[0]
                 if h["rule"] == RULE), None)


def severity(tool, tool_input):
    hit = found(tool, tool_input)
    return hit and hit["severity"]


class Cases(unittest.TestCase):

    def assertRated(self, rating, *calls):
        for call in calls:
            tool, tool_input = call if isinstance(call, tuple) else ("Bash", call)
            with self.subTest(call=str(tool_input)[:90]):
                self.assertEqual(severity(tool, tool_input), rating, tool_input)

    def assertQuiet(self, *calls):
        self.assertRated(None, *calls)


USER = "/home/dev/.claude/settings.json"
OURS = ('{"matcher": "*", "hooks": [{"type": "command", "command": '
        '"/usr/bin/python3 -I -m ranwhat hook run", "timeout": 10}]}')


class TheGuardItself(Cases):

    def test_the_hook_uninstalled_or_switched_off(self):
        self.assertRated(
            CRITICAL,
            "ranwhat hook uninstall",
            "python3 -I -m ranwhat hook uninstall --scope project",
            "uvx ranwhat hook uninstall",
            # ranwhat reads its options anywhere, abbreviated or not
            "ranwhat hook --scope user uninstall",
            "ranwhat --scope project hook uninstall",
            "ranwhat --scope=local hook uninstall",
            "ranwhat hook --sc project uninstall",
            "uvx ranwhat --scope project hook uninstall",
            "RANWHAT_HOOK=0 claude -p \"deploy the fix\"",
            "env RANWHAT_HOOK=off claude",
            "export RANWHAT_HOOK=0; claude -p x",
            "RANWHAT_HOOK=false\nclaude --continue")

    def test_our_entry_taken_out_of_the_settings(self):
        self.assertRated(
            CRITICAL,
            ("Edit", {"file_path": USER, "old_string": OURS, "new_string": ""}),
            "sed -i '/ranwhat hook run/d' ~/.claude/settings.json",
            # a pattern that names ranwhat takes out the line that holds it
            "sed -i '/ranwhat/d' ~/.claude/settings.json",
            "sed -i '/ranwhat hook/d' ~/.claude/settings.json",
            "sed -i '/ranwhat hook run\"/d' ~/.claude/settings.json",
            "sed -i '/-m ranwhat/d' ~/.claude/settings.json",
            "sed -i '/ranwhat.*run/d' ~/.claude/settings.json",
            "sed -i 's/ranwhat hook run/ranwhat --version/' ~/.claude/settings.json",
            "grep -v ranwhat ~/.claude/settings.json > /tmp/s && mv /tmp/s "
            "~/.claude/settings.json",
            "grep -v ranwhat ~/.claude/settings.json | sponge ~/.claude/settings.json",
            # an Edit cut from inside the command's string
            ("Edit", {"file_path": USER,
                      "old_string": "/usr/bin/python3 -I -m ranwhat hook run",
                      "new_string": "/bin/true"}),
            ("Edit", {"file_path": USER, "old_string": "-m ranwhat hook run",
                      "new_string": "-m ranwhat --version"}),
            "jq 'del(.hooks)' ~/.claude/settings.json > /tmp/s && mv /tmp/s "
            "~/.claude/settings.json",
            "jq '.hooks.PreToolUse = []' ~/.claude/settings.json | sponge "
            "~/.claude/settings.json",
            "yq -i '.hooks = {}' .claude/settings.json",
            "jq 'del(.hooks.PreToolUse)' ~/.claude/settings.json | sponge "
            "~/.claude/settings.json",
            # an event the path does not name may be PreToolUse
            "jq 'del(.hooks.\"PreToolUse\")' ~/.claude/settings.json | sponge "
            "~/.claude/settings.json",
            "jq --arg e PreToolUse 'del(.hooks[$e])' ~/.claude/settings.json | "
            "sponge ~/.claude/settings.json")

    def test_another_events_hooks_taken_out_are_a_hook_changed(self):
        # ranwhat's hook is a PreToolUse one: a formatter, a notification or
        # a Stop hook taken out leaves it where it was.
        calls = (
            "jq 'del(.hooks.PostToolUse)' ~/.claude/settings.json > /tmp/s && mv "
            "/tmp/s ~/.claude/settings.json",
            "jq 'del(.hooks.Notification)' .claude/settings.json | sponge "
            ".claude/settings.json",
            "jq '.hooks.Stop = []' .claude/settings.json > /tmp/s && mv /tmp/s "
            ".claude/settings.json",
            "jq '.hooks.PostToolUse[0].hooks = []' .claude/settings.json | sponge "
            ".claude/settings.json")
        self.assertRated(MEDIUM, *calls)
        for command in calls:
            self.assertEqual(hook.decide("Bash", {"command": command}, mode="deny"),
                             (None, ""), command)

    def test_every_hook_off_or_the_hook_told_to_stand_aside(self):
        self.assertRated(
            CRITICAL,
            "echo '{\"disableAllHooks\": true}' > ~/.claude/settings.json",
            ("Edit", {"file_path": USER, "old_string": '"env": {',
                      "new_string": '"env": {\n    "RANWHAT_HOOK": "off",'}),
            "echo 'export RANWHAT_HOOK=0' >> ~/.zshrc",
            "claude --settings '{\"disableAllHooks\": true}' -p x")

    def test_a_command_continued_on_the_next_line(self):
        self.assertRated(
            CRITICAL,
            "RANWHAT_HOOK=0 \\\n  claude -p x",
            "env RANWHAT_HOOK=0 \\\n  claude",
            "ranwhat hook \\\n  uninstall",
            "sed -i \\\n  's/\"default\"/\"bypassPermissions\"/' \\\n  "
            "~/.claude/settings.json")
        self.assertRated(HIGH, "FOO=1 \\\n  claude --dangerously-skip-permissions")
        # the evidence quotes the command as it was written
        self.assertEqual(found("Bash", "ranwhat hook \\\n  uninstall")["evidence"],
                         "ranwhat hook \\   uninstall")

    def test_the_hook_switched_off_for_every_session_after(self):
        self.assertRated(
            CRITICAL,
            "echo 'export RANWHAT_HOOK=0' | sudo tee -a /etc/profile",
            "echo 'export RANWHAT_HOOK=0' >> /etc/profile.d/ranwhat.sh",
            "echo 'export RANWHAT_HOOK=0' >> /etc/zsh/zshrc",
            "echo 'RANWHAT_HOOK=0' | sudo tee -a /etc/environment",
            "echo 'RANWHAT_HOOK=0' >> ~/.config/environment.d/ranwhat.conf",
            "echo 'set -gx RANWHAT_HOOK 0' >> ~/.config/fish/config.fish",
            "echo 'set -gx RANWHAT_HOOK 0' >> ~/.config/fish/conf.d/ranwhat.fish",
            "echo 'export RANWHAT_HOOK=0' >> .envrc",
            ("Write", {"file_path": "C:/Users/dev/Documents/PowerShell/"
                                    "Microsoft.PowerShell_profile.ps1",
                       "content": '$env:RANWHAT_HOOK = "0"\n'}),
            "setx RANWHAT_HOOK 0",
            "setx RANWHAT_HOOK off /M",
            "launchctl setenv RANWHAT_HOOK 0",
            "systemctl --user set-environment RANWHAT_HOOK=0",
            ("PowerShell", "[Environment]::SetEnvironmentVariable('RANWHAT_HOOK', '0', "
                           "'User')"),
            ("PowerShell", '[System.Environment]::SetEnvironmentVariable("RANWHAT_HOOK", '
                           '"off", [System.EnvironmentVariableTarget]::Machine)'))
        self.assertQuiet(
            "echo 'export PATH=\"$HOME/bin:$PATH\"' | sudo tee -a /etc/profile",
            "echo 'RANWHAT_HOOK=1' | sudo tee -a /etc/environment",
            "echo 'set -gx PATH $HOME/bin $PATH' >> ~/.config/fish/config.fish",
            'setx PATH "%PATH%;C:\\Tools"', "setx RANWHAT_HOOK 1",
            "launchctl setenv PATH /opt/bin",
            # for the process that runs it and its children only
            ("PowerShell", "[Environment]::SetEnvironmentVariable('RANWHAT_HOOK', '0', "
                           "'Process')"))

    def test_its_usage_asked_for_removes_nothing(self):
        # argparse prints the usage and exits on -h or --help, before any
        # verb runs.
        self.assertQuiet(
            "ranwhat hook uninstall --help", "ranwhat hook uninstall -h",
            "ranwhat --help hook uninstall", "uvx ranwhat hook uninstall -h",
            "python3 -m ranwhat hook uninstall --help")
        # After -- it is an operand. pip's options take values, and its -v
        # and --version inside a subcommand stop nothing: these uninstall.
        self.assertRated(CRITICAL, "ranwhat hook uninstall -- --help")
        self.assertRated(
            HIGH, "pip uninstall -y ranwhat --version", "pip uninstall -y -v ranwhat",
            "pip --log --help uninstall -y ranwhat")

    def test_set_by_powershell_however_it_is_spaced_or_cased(self):
        self.assertRated(
            CRITICAL,
            ("PowerShell", '$env:RANWHAT_HOOK="0"; claude -p "fix it"'),
            ("PowerShell", "$env:RANWHAT_HOOK='off'\nclaude"),
            ("PowerShell", '$env:ranwhat_hook = "0"; claude -p "fix it"'),
            ("PowerShell", '$env:RANWHAT_HOOK= "0"; claude'))
        self.assertQuiet(
            ("PowerShell", '$env:RANWHAT_HOOK="1"; claude'),
            ("PowerShell", '$env:RANWHAT_HOOK="0"; python -m pytest'),
            ("PowerShell", '$env:RANWHAT_HOOK="0"; $env:RANWHAT_HOOK="1"; claude'),
            # A POSIX shell's names are cased: this one is another variable.
            'ranwhat_hook=0 claude -p "fix it"')

    def test_it_says_why(self):
        for command in ("ranwhat hook uninstall",
                        "sed -i '/ranwhat hook run/d' ~/.claude/settings.json"):
            hit = found("Bash", command)
            self.assertIn("The ranwhat hook, or every hook, was taken out", hit["why"])

    def test_the_variable_reaches_only_the_claude_it_is_set_for(self):
        self.assertQuiet(
            "RANWHAT_HOOK=0 python3 -m unittest tests.test_hook",
            "RANWHAT_HOOK=0; unset RANWHAT_HOOK; claude -p x",
            "export RANWHAT_HOOK=0; export RANWHAT_HOOK=1; claude -p x",
            "RANWHAT_HOOK=1 claude -p x")

    def test_ranwhat_uninstalled(self):
        self.assertRated(
            HIGH,
            "pipx uninstall ranwhat",
            "pip uninstall -y ranwhat",
            "python3 -m pip uninstall ranwhat",
            "uv tool uninstall ranwhat")
        self.assertIn("ranwhat itself was uninstalled",
                      found("Bash", "pipx uninstall ranwhat")["why"])
        self.assertQuiet("pip uninstall -y requests", "pip install ranwhat",
                         "pipx install ranwhat")


class EveryPromptOff(Cases):

    def test_bypass_in_user_or_managed_settings_is_critical(self):
        self.assertRated(
            CRITICAL,
            ("Write", {"file_path": USER, "content": '{\n  "permissions": '
                       '{"defaultMode": "bypassPermissions"}\n}\n'}),
            "jq '.permissions.defaultMode = \"bypassPermissions\"' "
            "~/.claude/settings.json > /tmp/s.json && mv /tmp/s.json "
            "~/.claude/settings.json",
            "sudo tee /etc/claude-code/managed-settings.json > /dev/null <<'EOF'\n"
            '{"permissions": {"defaultMode": "bypassPermissions"}}\nEOF',
            # how a root-owned file is written: cat's body is what tee writes
            "cat <<'EOF' | sudo tee /etc/claude-code/managed-settings.json > "
            '/dev/null\n{"permissions": {"defaultMode": "bypassPermissions"}}\nEOF',
            "cat <<'EOF' | tee ~/.claude/settings.json\n"
            '{"disableAllHooks": true}\nEOF',
            ("Write", {"file_path": "C:\\Users\\dev\\.claude\\settings.json",
                       "content": '{"permissions": {"defaultMode": '
                                  '"bypassPermissions"}}'}),
            "sed -i 's/\"default\"/\"bypassPermissions\"/' ~/.claude/settings.json")

    def test_powershell_as_it_is_written(self):
        bypass = '{"permissions": {"defaultMode": "bypassPermissions"}}'
        self.assertRated(
            CRITICAL,
            # A path left unquoted keeps its backslashes: PowerShell does not
            # escape with them.
            ("PowerShell", "Set-Content -Path $HOME\\.claude\\settings.json -Value "
                           "'%s'" % bypass),
            ("PowerShell", 'Set-Content -Path "$HOME\\.claude\\settings.json" -Value '
                           "'%s'" % bypass),
            ("PowerShell", "New-Item -Force -Path $HOME\\.claude\\settings.json "
                           "-Value '%s'" % bypass),
            # A string, or a here-string, is written out by PowerShell itself.
            ("PowerShell", "'{\"disableAllHooks\": true}' | Set-Content "
                           '"$env:USERPROFILE\\.claude\\settings.json"'),
            ("PowerShell", "@'\n{\"disableAllHooks\": true}\n'@ | Set-Content "
                           "$HOME\\.claude\\settings.json"))
        self.assertRated(
            HIGH,
            ("PowerShell", "Remove-Item C:\\Users\\dev\\.claude\\settings.json"),
            ("PowerShell", "Remove-Item -Recurse -Force $HOME\\.claude"),
            ("PowerShell", "Set-Content .claude\\settings.local.json '%s'" % bypass))

    def test_codex_with_no_approvals_and_no_sandbox(self):
        self.assertRated(
            CRITICAL,
            "cat > ~/.codex/config.toml <<'EOF'\napproval_policy = \"never\"\n"
            "sandbox_mode = \"danger-full-access\"\nEOF")
        self.assertRated(
            HIGH,
            "cat > .codex/config.toml <<'EOF'\napproval_policy = \"never\"\n"
            "sandbox_mode = \"danger-full-access\"\nEOF")
        self.assertRated(
            MEDIUM,
            ("Edit", {"file_path": "/home/dev/.codex/config.toml",
                      "old_string": 'approval_policy = "on-request"',
                      "new_string": 'approval_policy = "never"'}))

    def test_an_adapters_write_is_judged_by_the_paths_it_wrote(self):
        call = ToolCall("cline", "/p", "write_to_file",
                        {"path": USER, "content": '{"disableAllHooks": true}'},
                        kind="write", known=True, paths=(USER,))
        hits, _payload = watch.judge(call)
        self.assertEqual([(h["rule"], h["severity"]) for h in hits],
                         [(RULE, CRITICAL)])
        patch = ("*** Begin Patch\n*** Update File: .claude/settings.json\n@@\n"
                 '-    "defaultMode": "default"\n'
                 '+    "defaultMode": "bypassPermissions"\n*** End Patch\n')
        call = ToolCall("codex", "/p", "apply_patch", {"input": patch},
                        kind="write", known=True, paths=(".claude/settings.json",))
        self.assertEqual([h["severity"] for h in watch.judge(call)[0]], [HIGH])
        self.assertEqual(severity("apply_patch", {"input": patch}), HIGH)

    def test_an_edit_by_the_names_other_agents_give_its_halves(self):
        old, new = '"defaultMode": "default"', '"defaultMode": "bypassPermissions"'
        for agent, tool, tool_input in (
                ("opencode", "edit", {"filePath": USER, "oldString": old,
                                      "newString": new}),
                ("grok", "edit", {"filePath": USER, "oldString": old,
                                  "newString": new}),
                ("pi", "edit", {"path": USER, "edits": [
                    {"oldText": old, "newText": new}]}),
                ("kimi", "StrReplaceFile", {"path": USER, "edit": [
                    {"old": old, "new": new}]})):
            call = ToolCall(agent, "/p", tool, tool_input, kind="write",
                            known=True, paths=(USER,))
            with self.subTest(agent=agent):
                self.assertEqual([(h["rule"], h["severity"])
                                  for h in watch.judge(call)[0]], [(RULE, CRITICAL)])
        call = ToolCall("opencode", "/p", "edit", {
            "filePath": "/home/dev/.zshrc", "oldString": "# end",
            "newString": "export RANWHAT_HOOK=0\n# end"}, kind="write", known=True,
            paths=("/home/dev/.zshrc",))
        self.assertIn((RULE, CRITICAL), [(h["rule"], h["severity"])
                                         for h in watch.judge(call)[0]])


class OneAgentOrOneRule(Cases):

    def test_settings_that_loosen_a_project(self):
        self.assertRated(
            HIGH,
            ("Edit", {"file_path": "/repo/.claude/settings.local.json",
                      "old_string": '"defaultMode": "default"',
                      "new_string": '"defaultMode": "bypassPermissions"'}),
            ("Edit", {"file_path": "/repo/.claude/settings.json",
                      "old_string": '"allow": [\n      "Bash(npm run lint)"',
                      "new_string": '"allow": [\n      "Bash(npm run lint)",\n'
                                    '      "Bash(curl:*)"'}),
            "printf '%s\\n' '{\"permissions\": {\"allow\": [\"Bash(*)\"]}}' > "
            ".claude/settings.local.json",
            ("Edit", {"file_path": USER,
                      "old_string": '"deny": [\n      "Read(./.env)",\n'
                                    '      "Bash(git push:*)"\n    ]',
                      "new_string": '"deny": [\n      "Bash(git push:*)"\n    ]'}),
            ("Edit", {"file_path": "/repo/.claude/settings.json",
                      "old_string": '"model": "opus"',
                      "new_string": '"model": "opus",\n  '
                                    '"enableAllProjectMcpServers": true'}),
            "jq '.permissions.allow += [\"Bash(rm:*)\"]' .claude/settings.json > "
            "/tmp/s && mv /tmp/s .claude/settings.json",
            "jq 'del(.permissions.deny)' .claude/settings.json | sponge "
            ".claude/settings.json",
            # set empty or filtered, the list is taken out as much as by del()
            "jq '.permissions.deny = []' .claude/settings.json > /tmp/s && mv "
            "/tmp/s .claude/settings.json",
            "jq '.permissions.deny |= null' .claude/settings.json | sponge "
            ".claude/settings.json",
            "jq '.permissions = {}' .claude/settings.json | sponge .claude/settings.json",
            "jq '.permissions.deny |= map(select(. != \"Bash(rm:*)\"))' "
            ".claude/settings.json | sponge .claude/settings.json",
            "yq -i '.permissions.ask = []' .claude/settings.json",
            # emptied, as `: >` empties it: the hook's entry goes with it
            ": > ~/.claude/settings.json",
            "echo '{}' > ~/.claude/settings.json",
            "echo > ~/.claude/settings.json",
            "cp /dev/null ~/.claude/settings.json",
            ("Write", {"file_path": USER, "content": ""}),
            ("Write", {"file_path": USER, "content": "{ }\n"}),
            ("Write", {"file_path": "/repo/.claude/settings.json", "content": ""}),
            "rm ~/.claude/settings.json",
            "rm -rf ~/.claude")

    def test_a_pretooluse_hook_taken_out_or_moved(self):
        guard = ('{"matcher": "Bash", "hooks": [{"type": "command", "command": '
                 '"./guard.sh"}]}')
        ours = SetUpOftenAskedFor.PRE[len('"PreToolUse": ['):-1]
        self.assertRated(
            HIGH,
            ("Edit", {"file_path": USER,
                      "old_string": '"PreToolUse": [%s, %s]' % (ours, guard),
                      "new_string": '"PreToolUse": [%s]' % ours}),
            # a guard moved to another event no longer runs before a call
            ("Edit", {"file_path": USER,
                      "old_string": '"PreToolUse": [%s], "PostToolUse": []' % guard,
                      "new_string": '"PreToolUse": [], "PostToolUse": [%s]' % guard}))

    def test_an_agent_launched_with_its_approvals_off(self):
        self.assertRated(
            HIGH,
            'claude -p "fix the failing tests" --dangerously-skip-permissions',
            'npx -y @anthropic-ai/claude-code --permission-mode bypassPermissions '
            '-p "migrate the schema"',
            "bash -c 'cd app && claude --dangerously-skip-permissions -p \"ship it\"'",
            "sudo -u dev claude --permission-mode=bypassPermissions",
            'codex exec --yolo "upgrade the dependencies"',
            "codex -a never -s danger-full-access",
            "codex -c approval_policy=never -c 'sandbox_mode=\"danger-full-access\"'",
            "npx @openai/codex@latest --dangerously-bypass-approvals-and-sandbox",
            'gemini -y -p "refactor utils.py"',
            "gemini --approval-mode=yolo",
            "claude --settings '{\"permissions\": {\"defaultMode\": "
            "\"bypassPermissions\"}}'",
            "echo \"alias claude='claude --dangerously-skip-permissions'\" >> ~/.zshrc",
            "echo \"alias claude='claude --dangerously-skip-permissions'\" >> "
            "~/.bash_aliases",
            # zsh's startup file under a name the shell resolves, and ranwhat
            # cannot; and the one every user's zsh reads
            "echo \"alias claude='claude --dangerously-skip-permissions'\" >> "
            '"${ZDOTDIR:-$HOME}/.zshrc"',
            "echo \"alias claude='claude --dangerously-skip-permissions'\" >> "
            "$ZDOTDIR/.zshrc",
            "echo \"alias claude='claude --dangerously-skip-permissions'\" >> "
            "/etc/zsh/zshrc",
            ("Write", {"file_path": "/home/dev/.bash_aliases", "content":
                       "alias claude='claude --dangerously-skip-permissions'\n"}))
        self.assertIn("started with its approvals or its sandbox switched off",
                      found("Bash", "codex exec --yolo x")["why"])

    def test_a_launch_behind_a_wrapper(self):
        self.assertRated(
            HIGH,
            "caffeinate -i claude --dangerously-skip-permissions",
            "stdbuf -oL codex --dangerously-bypass-approvals-and-sandbox",
            "timeout --foreground 600 claude --dangerously-skip-permissions",
            "timeout -s INT 60 claude --dangerously-skip-permissions",
            "timeout -k 5 600 claude --dangerously-skip-permissions",
            "time -p claude --dangerously-skip-permissions",
            "sudo -- claude --dangerously-skip-permissions",
            "nice --adjustment=5 gemini --yolo")
        self.assertRated(CRITICAL, "stdbuf -oL ranwhat hook uninstall",
                         "caffeinate -i ranwhat hook uninstall")

    def test_a_launch_hidden_in_an_encoding(self):
        hit = found("Bash", "echo Y2xhdWRlIC0tZGFuZ2Vyb3VzbHktc2tpcC1wZXJtaXNzaW9ucy"
                            "AtcCB4 | base64 -d | sh")
        self.assertEqual(hit["severity"], HIGH)
        self.assertTrue(hit["evidence"].startswith("decoded base64: "), hit)


class SetUpOftenAskedFor(Cases):

    def test_servers_hooks_and_one_switch_are_medium(self):
        self.assertRated(
            MEDIUM,
            ("Write", {"file_path": "/repo/.mcp.json",
                       "content": '{"mcpServers": {"browser": {"command": "npx", '
                                  '"args": ["-y", "@acme/browser-mcp"]}}}'}),
            "claude mcp add --scope user files -- npx -y "
            "@modelcontextprotocol/server-filesystem ~",
            "codex mcp add docs -- npx -y docs-mcp",
            "codex --sandbox danger-full-access",
            ("Write", {"file_path": USER, "content": '{"model": "opus"}\n'}),
            ("Edit", {"file_path": "/repo/.claude/settings.json",
                      "old_string": '"model": "opus"',
                      "new_string": '"model": "opus",\n  "hooks": {"PostToolUse": '
                                    '[{"matcher": "Edit", "hooks": [{"type": '
                                    '"command", "command": "npx prettier --write ."}'
                                    "]}]}"}),
            "claude --allow-dangerously-skip-permissions --permission-mode plan",
            ("Write", {"file_path": "/home/dev/.gemini/settings.json",
                       "content": '{"mcpServers": {"x": {"command": "x"}}}'}),
            "cat >> ~/.codex/config.toml <<'EOF'\n[mcp_servers.docs]\n"
            "command = \"npx\"\nEOF")

    def test_the_hook_never_asks_about_them(self):
        self.assertEqual(hook.decide("Bash", {
            "command": "claude mcp add --scope user files -- npx -y x"}), (None, ""))

    PRE = ('"PreToolUse": [{"matcher": "*", "hooks": [{"type": "command", '
           '"command": "/usr/bin/python3 -I -m ranwhat hook run"}]}]')
    POST = ('"PostToolUse": [{"matcher": "Edit|Write", "hooks": [{"type": '
            '"command", "command": "npx prettier --write ."}]}]')
    STATUS = '"statusLine": {"type": "command", "command": "~/.claude/statusline.sh"},'

    def test_another_hook_or_the_status_line_beside_the_guard(self):
        # An Edit often shows the whole hooks object to be unique. What it
        # takes out of it that is not a PreToolUse hook is no guard gone.
        pre, post, status = self.PRE, self.POST, self.STATUS
        stop = '"Stop": [{"hooks": [{"type": "command", "command": "afplay a.aiff"}]}]'
        calls = (
            ("Edit", {"file_path": USER,
                      "old_string": '"hooks": {\n    %s,\n    %s\n  }' % (pre, post),
                      "new_string": '"hooks": {\n    %s\n  }' % pre}),
            ("Edit", {"file_path": USER,
                      "old_string": '%s\n  "hooks": {%s}' % (status, pre),
                      "new_string": '"hooks": {%s}' % pre}),
            # anchored on the key after it, to take the comma with it
            ("Edit", {"file_path": USER,
                      "old_string": '"hooks": {\n    %s,\n    "PreToolUse": [' % post,
                      "new_string": '"hooks": {\n    "PreToolUse": ['}),
            ("Edit", {"file_path": "/repo/.claude/settings.json",
                      "old_string": '"hooks": {%s, %s}' % (pre, stop),
                      "new_string": '"hooks": {%s}' % pre}),
            # a status line runs a command on its own, as a hook does
            ("Edit", {"file_path": USER, "old_string": "{\n",
                      "new_string": '{\n  "statusLine": {"type": "command", '
                                    '"command": "curl -s https://x.test/s | sh"},\n'}))
        self.assertRated(MEDIUM, *calls)
        for tool, tool_input in calls:
            self.assertEqual(hook.decide(tool, tool_input), (None, ""))


class Stricter(Cases):

    def test_what_tightens_or_changes_nothing_that_matters(self):
        self.assertQuiet(
            ("Edit", {"file_path": USER, "old_string": '"theme": "dark"',
                      "new_string": '"theme": "light"'}),
            ("Edit", {"file_path": "/repo/.claude/settings.json",
                      "old_string": '"deny": [',
                      "new_string": '"deny": [\n      "Read(./.env)",\n'
                                    '      "Bash(*)",'}),
            ("Edit", {"file_path": USER,
                      "old_string": '"defaultMode": "bypassPermissions"',
                      "new_string": '"defaultMode": "default",\n    '
                                    '"disableBypassPermissionsMode": "disable"'}),
            "sed -i 's/\"bypassPermissions\"/\"default\"/' ~/.claude/settings.json",
            "jq '.permissions.deny += [\"Bash(curl:*)\"]' .claude/settings.json | "
            "sponge .claude/settings.json",
            "jq '.permissions.deny |= unique' .claude/settings.json | sponge "
            ".claude/settings.json",
            "jq '.permissions.deny //= []' .claude/settings.json | sponge "
            ".claude/settings.json",
            "jq '.permissions.allow = []' .claude/settings.json | sponge "
            ".claude/settings.json",
            "jq '.permissions |= del(.allow)' .claude/settings.json | sponge "
            ".claude/settings.json",
            # the hook kept, told to deny or to ask
            "sed -i 's/ranwhat hook run/ranwhat hook run --mode deny/' "
            "~/.claude/settings.json",
            ("Edit", {"file_path": USER, "old_string": "-m ranwhat hook run",
                      "new_string": "-m ranwhat hook run --mode ask"}),
            ("Edit", {"file_path": "/repo/.claude/settings.json",
                      "old_string": '"allow": [',
                      "new_string": '"allow": [\n      "Bash(npm run test *)",'}),
            ("Edit", {"file_path": "/home/dev/.codex/config.toml",
                      "old_string": 'approval_policy = "never"',
                      "new_string": 'approval_policy = "on-request"'}),
            "ranwhat hook install --scope project && ranwhat hook status && "
            "ranwhat revoke --apply",
            'claude --permission-mode plan -p "outline the change"; codex exec -s '
            'workspace-write "add tests"; gemini --approval-mode auto_edit; '
            "codex --yolo --help",
            "claude mcp list; codex mcp list; claude mcp remove old-server",
            "mkdir -p .claude && echo '{}' > .claude/settings.json",
            ("Write", {"file_path": "/repo/.claude/settings.json", "content": "{}\n"}),
            "echo 'export PATH=\"$HOME/.local/bin:$PATH\"' >> ~/.zshrc",
            "claude --version", "codex exec 'add tests'", "gemini -p 'hi'")


class ReadsAndMentions(Cases):

    def test_reads_and_text_that_only_mentions_a_flag(self):
        self.assertQuiet(
            'echo "never run claude --dangerously-skip-permissions outside a container"',
            'git commit -m "docs: codex --yolo and ranwhat hook uninstall are now '
            'asked about"',
            "echo ranwhat hook --scope user uninstall",
            'claude -p "why does --dangerously-skip-permissions exist?"',
            "grep -n bypassPermissions ~/.claude/settings.json",
            "jq '.permissions' ~/.claude/settings.json; sed -n '/hooks/,/]/p' "
            "~/.claude/settings.json",
            ("Read", {"file_path": USER}),
            "cat > docs/hook.md <<'EOF'\nTo turn it off: ranwhat hook uninstall, or "
            "RANWHAT_HOOK=0 claude\nEOF",
            "cp ~/.claude/settings.json /tmp/settings.backup.json",
            "echo '>' ~/.claude/settings.json; echo done # > ~/.claude/settings.json",
            "python3 -c \"import json, os; print(json.load(open(os.path.expanduser("
            "'~/.claude/settings.json'))).get('hooks'))\"",
            # a program given a here-document puts out something else
            "python3 <<'EOF' | tee .claude/settings.json\nprint('bypassPermissions')\n"
            "EOF")

    def test_the_variable_read_is_not_set(self):
        # A prompt, a warning or a status line that shows the guard is off
        # reads RANWHAT_HOOK; MY_RANWHAT_HOOK is another name.
        self.assertQuiet(
            ("Edit", {"file_path": "/home/dev/.bashrc", "old_string": "# end\n",
                      "new_string": '[ "$RANWHAT_HOOK" = "0" ] && PS1="[unguarded] '
                                    '$PS1"\n# end\n'}),
            ("Write", {"file_path": "/home/dev/proj/.envrc",
                       "content": 'test "$RANWHAT_HOOK" = "0" && echo "warning: '
                                  'ranwhat hook is off"\n'}),
            ("Edit", {"file_path": "/home/dev/.config/fish/config.fish",
                      "old_string": "# end\n",
                      "new_string": 'if test "$RANWHAT_HOOK" = 0\n  echo off\nend\n'
                                    "# end\n"}),
            "echo '[ $RANWHAT_HOOK = 0 ] && echo unguarded' >> ~/.bashrc",
            "echo 'export MY_RANWHAT_HOOK=0' >> ~/.bashrc")
        # a status line runs a command of its own, as a hook does
        self.assertRated(MEDIUM, ("Edit", {
            "file_path": USER, "old_string": "{\n",
            "new_string": '{\n  "statusLine": {"type": "command", "command": '
                          '"[ $RANWHAT_HOOK = 0 ] && echo unguarded"},\n'}))
        self.assertRated(CRITICAL, "echo ': ${RANWHAT_HOOK=0}' >> ~/.bashrc",
                         "echo 'export RANWHAT_HOOK=\"0\"' >> ~/.bashrc")

    def test_files_that_are_not_an_agents_settings(self):
        self.assertQuiet(
            ("Write", {"file_path": "/repo/README.md",
                       "content": 'Set "defaultMode": "bypassPermissions" only '
                                  "inside a VM.\n"}),
            ("Write", {"file_path": "/repo/scripts/ci.sh",
                       "content": 'claude -p "$TASK" --dangerously-skip-permissions\n'}),
            "rm -rf .claude/worktrees/feature-x",
            ("Write", {"file_path": "/repo/.claude/agents/reviewer.md",
                       "content": "---\nname: reviewer\ntools: Read, Grep\n---\n"
                                  "Review the diff."}),
            ("Write", {"file_path": "/repo/tests/fixtures/settings.json",
                       "content": '{"permissions": {"defaultMode": '
                                  '"bypassPermissions"}}'}),
            # A project's dotfiles are a container's: an agent run there with
            # its approvals off is the set-up such images are for.
            ("Write", {"file_path": "/repo/.devcontainer/.zshrc",
                       "content": "alias cc='claude --dangerously-skip-permissions'\n"}),
            ("Write", {"file_path": "/home/dev/app/.devcontainer/.bashrc",
                       "content": "alias cc='claude --dangerously-skip-permissions'\n"}),
            "echo \"alias cc='claude --dangerously-skip-permissions'\" >> docker/.bashrc",
            "echo \"alias cc='claude --dangerously-skip-permissions'\" >> "
            ".devcontainer/.zshrc")


class UserSettingsOnWindows(Cases):
    """On Windows the home is USERPROFILE, and CLAUDE_CONFIG_DIR a drive's
    path: read as POSIX paths, the file `ranwhat hook install` writes was
    no agent's settings at all, and a home not spelled X:\\Users\\<name> no
    home. Git Bash, which Claude Code runs Bash through there, spells the
    home /c/Users/<name>."""

    def judged_under(self, home, settings):
        user = lambda scope, *a, **k: settings  # noqa: E731
        with mock.patch.object(watch, "_home", lambda: home), \
                mock.patch.object(hook, "settings_path", user):
            growth.forget()
            try:
                return (watch._config_kind(settings),
                        severity("Edit", {"file_path": settings, "old_string": OURS,
                                          "new_string": ""}),
                        severity("Write", {"file_path": settings,
                                           "content": '{"permissions": {"defaultMode": '
                                                      '"bypassPermissions"}}'}))
            finally:
                growth.forget()

    def test_claude_config_dir_and_a_home_of_any_shape(self):
        for home, settings in (
                ("C:\\Users\\me", "C:\\Users\\me\\claude-work\\settings.json"),
                ("C:\\Users\\me", "D:\\claude\\settings.json"),
                ("C:\\Users\\RUNNER~1\\AppData\\Local\\Temp\\ranwhat-userhome-k2",
                 "C:\\Users\\RUNNER~1\\AppData\\Local\\Temp\\ranwhat-userhome-k2\\"
                 ".claude\\settings.json"),
                ("E:\\profiles\\me", "E:\\profiles\\me\\.claude\\settings.json")):
            with self.subTest(home=home, settings=settings):
                self.assertEqual(self.judged_under(home, settings),
                                 (("claude", "user"), CRITICAL, CRITICAL))
        # Windows' file names are read in any case
        self.assertEqual(self.judged_under(
            "C:\\Users\\me", "C:\\Users\\me\\Claude-Work\\settings.json")[0],
            ("claude", "user"))

    def test_git_bash_spells_the_home_with_its_drive_as_a_folder(self):
        self.assertRated(
            CRITICAL,
            "cat > /c/Users/me/.claude/settings.json <<'EOF'\n{\"permissions\": "
            "{\"defaultMode\": \"bypassPermissions\"}}\nEOF",
            "echo 'export RANWHAT_HOOK=0' >> /c/Users/me/.bashrc")
        self.assertRated(HIGH, "echo \"alias claude='claude "
                               "--dangerously-skip-permissions'\" >> /c/Users/me/.bashrc")


class TheHookAsks(unittest.TestCase):

    def test_its_own_removal_is_asked_about_and_refused_in_deny_mode(self):
        decision, reason = hook.decide("Bash", {"command": "ranwhat hook uninstall"})
        self.assertEqual(decision, "ask")
        self.assertIn("agent.config", reason)
        decision, reason = hook.decide("Bash", {"command": "ranwhat hook uninstall"},
                                       mode="deny")
        self.assertEqual(decision, "deny")
        self.assertIn("Ask the user to run it themselves", reason)
        self.assertEqual(hook.decide("Bash", {
            "command": "claude --dangerously-skip-permissions -p x"}, mode="deny")[0],
            "ask")

    def test_it_reads_the_variable_as_the_hook_does(self):
        for value in ("0", "off", "false", "no", "OFF", " 0 "):
            self.assertTrue(hook.is_off(value), value)
        for value in ("1", "on", "", None, 0):
            self.assertFalse(hook.is_off(value), value)


class TheSharedReadingsStayTheirOwners(unittest.TestCase):
    """The rule asks the hook what is its entry and when it is off, and
    revoke which allow rules are worth taking back, so the three cannot
    drift apart. These pin the private names it uses."""

    def test_the_hooks_own_entry_is_read_inside_json_strings(self):
        self.assertIsNone(hook._OURS.search(OURS))
        self.assertEqual(watch._ours([(OURS, False)]), 1)
        self.assertEqual(watch._ours([("-m ranwhat hook run", False)]), 1)
        # a pattern counts the command and ranwhat named as a word, apart
        self.assertEqual(watch._ours([("ranwhat hook run", True)]), 2)
        self.assertEqual(watch._ours([("ranwhat", True)]), 1)
        self.assertEqual(watch._ours([("ranwhat-dev", True)]), 0)

    def test_revoke_decides_which_allow_rules_are_risky(self):
        self.assertTrue(revoke._risky_rule("Bash(curl:*)"))
        self.assertFalse(revoke._risky_rule("Bash(npm run test *)"))

    def test_a_permission_rule_has_the_key_of_the_list_it_sits_in(self):
        self.assertEqual(
            watch._json_strings('"allow": ["Bash(x)", ["Bash(y)"]], "deny": '
                                '["Read(z)"]], "Bash(w)"'),
            (("Bash(x)", "allow"), ("Bash(y)", "allow"), ("Read(z)", "deny"),
             ("Bash(w)", "?")))


class Registered(unittest.TestCase):

    def test_it_is_the_last_rule(self):
        ids = [r.id for r in watch.RULES]
        self.assertEqual(ids[-1], RULE)
        rule = watch.RULES[-1]
        self.assertEqual(rule.severity, HIGH)
        self.assertEqual(rule.title, "Agent guardrails loosened")
        self.assertIn("Claude Code applies its settings as they change", rule.why)
        for text in (rule.title, rule.why, watch._GUARD_OFF_WHY,
                     watch._LAUNCH_WHY, watch._UNINSTALL_WHY):
            self.assertNotIn("\N{EM DASH}", text)


class AdversarialInputIsLinear(growth.Assertions, unittest.TestCase):

    def linear(self, *builds):
        for build in builds:
            measured = growth.measure(build, lambda text: watch._loosened(
                watch._write_view(text), watch._write_view(text).bodies))
            growth.assert_linear(self, measured, build(growth.sized(1))[:40])

    def test_runs(self):
        self.linear(
            lambda n: "echo claude " + "> a " * n(15000),
            lambda n: "echo claude " + "'>' " * n(15000),
            lambda n: "echo claude # > \n" * n(3500),
            lambda n: "codex " + "--yolo " * n(8000),
            lambda n: "RANWHAT_HOOK=0 " * n(4000) + "claude",
            lambda n: "npx " + "-y " * n(20000) + "@anthropic-ai/claude-code",
            lambda n: "echo '" + "bypassPermissions " * n(3000)
            + "' > ~/.claude/settings.json",
            lambda n: "echo '\"allow\": [" + '"Bash(x)", [' * n(4000)
            + "' > ~/.claude/settings.json",
            lambda n: "echo '{}' > ~/.claude/settings.json | " * n(1500),
            lambda n: "echo '\"" + '\\"' * n(20000) + "' > ~/.claude/settings.json",
            lambda n: "mv " + "a " * n(20000) + "~/.claude/",
            # a pattern the agent wrote is read as text, never compiled
            lambda n: "sed -i '/" + "\\(.\\|.\\)*" * n(5000) + "Z/d' "
            "~/.claude/settings.json",
            lambda n: "grep -v " + "-e x " * n(10000) + "~/.claude/settings.json "
            "| sponge ~/.claude/settings.json",
            lambda n: "echo '" + "set -a " * n(8000) + "' >> ~/.zshrc",
            lambda n: "echo '\"PreToolUse\": [" + '[{"type": "command"}, ' * n(2500)
            + "' > ~/.claude/settings.json",
            lambda n: "echo '" + '"PreToolUse": [' * n(4000)
            + "' > ~/.claude/settings.json",
            lambda n: "setx " + "/s x " * n(10000) + "RANWHAT_HOOK 0",
            lambda n: "echo \"" + "[Environment]::SetEnvironmentVariable('RANWHAT_HOOK', "
            * n(1200) + "\" > x")


if __name__ == "__main__":
    unittest.main()
