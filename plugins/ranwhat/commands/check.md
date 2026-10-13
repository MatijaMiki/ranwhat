---
description: Scan this machine's agent history for risky actions and leaked secrets (read-only)
allowed-tools: Bash(uvx ranwhat check:*)
---
Run `uvx ranwhat check` and show the result. It reads local agent transcripts and changes nothing. Summarise what it flagged, most severe first, and say which findings need action. Never print a secret value; use the hints ranwhat gives.
