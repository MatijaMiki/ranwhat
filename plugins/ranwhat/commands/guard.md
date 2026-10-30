---
description: Opt in to ranwhat's guard, which asks before a high-risk Claude Code call runs
allowed-tools: Bash(uvx ranwhat@0.8.0 hook:*)
---
Only if the user has asked for this: explain in two sentences that the guard is a Claude Code PreToolUse hook which asks for confirmation before a call ranwhat rates high or critical, and that it fails open. Then run `uvx ranwhat@0.8.0 hook status`. If it is not installed and the user confirms, run `uvx ranwhat@0.8.0 hook install`. `uvx ranwhat@0.8.0 hook uninstall` removes it. Never install it without the user's yes.
