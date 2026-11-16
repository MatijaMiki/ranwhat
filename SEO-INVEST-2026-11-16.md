# SEO invest pass, 2026-11-16

Based on Search Console data from 2026-10-17 to 2026-11-13: 2 clicks (both on the home page). Long-tail guides rank in the top 10, while broad "AI coding agent security" pages sit at positions 69 to 90.

## Titles, old to new

| URL | Old title | New title |
|---|---|---|
| /guides/ai-agent-token-scopes | AI agent token scopes and least privilege | AI agent token scopes: why prompts don't limit them |
| /guides/developer-opsec | Developer OPSEC: what laptops and AI agents leak | Developer OPSEC: agent transcripts keep what they read |
| /guides/mcp-server-security-coding-agents | MCP server security for coding agents: what they reach | MCP server security: it runs with your privileges |
| /guides/ai-coding-agent-history-locations | AI coding agent history: where each one stores it | AI coding agent history: where it lives, what it holds |
| /guides/claude-code-history | Where Claude Code history is stored and how to view it | Claude Code history: it deletes itself after 30 days |
| /guides/claude-code-audit-log | Claude Code audit log: every command it ran | Claude Code audit log: you already have one on disk |
| /guides/claude-code-hooks-security (demoted) | Claude Code hooks for security: block risky calls | Claude Code deny rules vs hooks: what each one stops |
| /guides/best-ai-coding-agent-security-tools (demoted) | Best AI coding agent security tools in 2026 | Coding agent security tools: 7 compared on five checks |
| /guides/ai-coding-agent-security (hub) | AI agent security: a checklist for coding agents | Coding agent security checklist: 14 steps, in order |
| /guides/claude-code-cleanupperioddays | (new) | Claude Code cleanupPeriodDays: 0 doesn't mean forever |
| /guides/cursor-chat-history | (new) | Cursor chat history: where it lives and what's in it |
| /guides/codex-cli-session-history | (new) | Codex CLI session history: no documented expiry date |

Every title ends in " | ranwhat" and is under 65 characters. Each hook is backed on its page:
- **cleanupPeriodDays:** the default is 30, and 0 fails validation (Claude Code settings reference).
- **Codex:** "no documented expiry": the docs give no retention period for rollouts.
- **MCP:** "your privileges": the MCP specification says a local server runs with the client's privileges.

## Invested (winners)

- **Four top-10 guides** (token scopes, developer OPSEC, MCP, history locations):
  - new title, description and hero lede that opens on the moment the problem hits
  - a visible "Common questions" block of 4 to 5 questions with one-line answers
  - more Related links between them
  - dateModified 2026-11-16
- **history-locations:** two H2s rephrased as the questions people type ("Where does each AI coding agent store chat history?", "How do I limit or delete coding agent history?").
- **claude-code-history:** title leads with "Claude Code history" and the 30-day fact. The lede opens on a session missing from /resume. It gains a new question about keeping history longer and links to the new cleanupPeriodDays guide.
- **claude-code-audit-log:** new title and lede, plus a questions block. One question is "What is cleanupperioddays?", aimed at the query that ranks 13, and it links to the dedicated guide.

## New guides (each written from ranwhat's own reader source and vendor docs, no filler)

- **/guides/claude-code-cleanupperioddays:**
  - default, minimum, 0 fails, how to raise it, what the sweep skips, how to check before deletion
  - the equivalent per agent: Claude Code, Gemini CLI, Codex, Cursor
- **/guides/cursor-chat-history:**
  - editor and CLI stores per OS, the cursorDiskKV keys, and a read-only sqlite3 recipe that works on a copy
  - what ranwhat watch and clean do for Cursor, and how to delete
  - sourced from ranwhat/sources/cursor.py and the open-source readers it cites
- **/guides/codex-cli-session-history:**
  - the store layout, what a rollout line holds, shell snapshots
  - retention settings, size commands, checking with ranwhat, and deleting
  - sourced from ranwhat/sources/codex.py and the Codex config docs

All three are in the sitemap, llms.txt, /guides, the shared footer, every guide's sidebar, the home page guide list and the checklist (step 10).

## Demoted (no URL removed)

- **claude-code-hooks-security:** narrowed to "deny rules vs hooks vs the sandbox":
  - new title, H1, breadcrumb, description and lede
  - the lede links to /guides/block-command-claude-code-pretooluse-hook so the two pages don't compete for the same query
- **best-ai-coding-agent-security-tools:** retitled to a named-tools comparison, with a new H1 and description.
- **Placement:** both moved to a new "More guides" group at the bottom of the sidebar, /guides and the footer, and removed from the home page guide list.
- **ai-coding-agent-security (hub):** title narrowed to the "checklist" long tail. It stays first on /guides and in "Start here", because test_site_claims makes it the hub every guide links to.

## GEO add-on

1. **H2s as questions:** all new-guide H2s, the history-locations H2s, and every FAQ h3.
2. **Answer first:** each new-guide H2 opens with a one-line answer lede.
3. **FAQ:** visible FAQ blocks on every changed or new guide. FAQPage JSON-LD was NOT added: test_site_claims.test_faq_markup_is_only_on_pages_with_questions_of_their_own allows it only on /faq and /, to follow Google's one-markup-per-question guidance.
4. **llms files:** llms.txt was updated by hand (3 new entries, hooks and tools entries renamed). llms-full.txt and the .md twins are generated by scripts/build_md.py at deploy (build.sh) and never committed. A local build gives 34 twins, including the 3 new ones.
5. **Per-agent sections:** cleanupPeriodDays has a per-agent table (Claude Code, Gemini CLI, Codex, Cursor), and the history-locations questions are per agent.

Not done: no per-agent page for Gemini CLI, Copilot CLI or Windsurf. Each would mostly repeat its history-locations row, so it would be thin.
