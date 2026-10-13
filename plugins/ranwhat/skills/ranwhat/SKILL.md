---
name: ranwhat
description: Use when the user asks what their AI coding agents did on this machine, whether secrets were left in agent transcripts, or what MCP servers and credential files an agent can reach.
---
ranwhat reads the local history of Claude Code, Codex, Gemini CLI and other agents. `check`, `watch`, `reach` and `sources` read local files and send nothing.

- `uvx ranwhat check`: risky actions and secrets in one pass, changing nothing.
- `uvx ranwhat watch`: what the agents already ran.
- `uvx ranwhat reach`: MCP servers and credential files agents can reach.
- `uvx ranwhat sources`: which agents it reads and where it looked.

Rules: never print a credential value, only the hint ranwhat gives. Do not run `clean --apply`, `revoke --apply` or `hook install` unless the user asks for that exact step; `clean` is interactive and belongs in the user's own terminal. Rotation and revocation are the user's to do.
