---
name: ranwhat
description: Use when the user asks what their AI coding agents did on this machine, whether secrets were left in agent transcripts, or what MCP servers and credential files an agent can reach.
---
# ranwhat: what your coding agents ran, and which secrets they left behind

[ranwhat](https://ranwhat.com) reads the history Claude Code, Codex, Gemini CLI, Cursor and other agents already save on this machine. It lists the actions worth a second look (credential files read, recursive deletes, force pushes, packages published, remote scripts piped to a shell) and the API keys and tokens sitting in agent transcripts. `check`, `watch`, `reach` and `sources` read local files and send nothing. Python 3.9 or newer, macOS or Linux.

## Commands

- `uvx ranwhat@0.8.0 check`: risky actions and secrets in one pass, changing nothing.
- `uvx ranwhat@0.8.0 watch`: what the agents already ran. `--days 7` limits it to a window.
- `uvx ranwhat@0.8.0 reach`: MCP servers and credential files agents can reach.
- `uvx ranwhat@0.8.0 sources`: which agents it reads and where it looked.

`uvx` runs the pinned release from PyPI (https://pypi.org/project/ranwhat/) without installing it. The source is https://github.com/MatijaMiki/ranwhat. To keep it, the user can run `pip install ranwhat` or `uv tool install ranwhat`. Do not install anything from another source.

## How to answer

- "Did my agent do anything bad?" Run `check`, then summarise by severity: what it was, which agent, when. Quote the command ranwhat shows, not your guess of it.
- "Did I leak a key?" Run `check` and report each secret by the hint ranwhat prints (type, file, a few characters), then tell the user which key to rotate and where.
- "What can my agents get at?" Run `reach` and list the MCP servers and credential files, highest risk first.
- In CI or a script, `check --fail-on high` exits non-zero when something at that level turns up.

## Rules

Never print a credential value, only the hint ranwhat gives. Do not run `clean --apply`, `revoke --apply` or `hook install` unless the user asks for that exact step; `clean` is interactive and belongs in the user's own terminal. Rotation and revocation are the user's to do. Never run `ranwhat ignore` with an action, `all` or `-`, and never edit `~/.ranwhat/ignore` or a `.ranwhatignore` yourself: give the user the command to run. What that file leaves out is missing from every later report, and ranwhat lists any change an agent makes to it as critical.

## Links

- Site and docs: https://ranwhat.com
- Source: https://github.com/MatijaMiki/ranwhat
