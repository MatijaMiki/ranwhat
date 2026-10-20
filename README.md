# ranwhat

**A flight recorder for AI agents, and a scanner for the authority they hold.**
AI coding agent security for Claude Code and twenty-nine other coding agents, run
on your own machine.
No account, no telemetry, no dependencies.

Website and docs: https://ranwhat.com

Your coding agent has your shell, your keys and your repo. `ranwhat` reads
what it actually ran and surfaces the handful of irreversible actions worth
knowing about.

```
$ ranwhat watch --days 90

  ranwhat watch  · local agent flight recorder
  ----------------------------------------------------------------------------
  Read Claude Code: 4 transcripts, last 90 days

  2 critical  2 high

  * Credential material accessed   2026-09-30 18:13:00  Bash  9c41e07b2d5a8f13
      cat ~/.ssh/id_rsa
      -> The agent read a file whose only purpose is to hold secrets. Whatever
         it read is now in a model context you do not control.

  * Bulk or recursive deletion   2026-09-28 14:42:00  Bash  51e3c6a43e946bf5
      …rm -rf '@'
      -> Recursive deletion. Recoverable only if something else was backing it
         up.

  * Package or release published   2026-09-21 11:05:00  Bash  3fa9c2d81b7e4a06
      npm publish
      -> Something was pushed to a registry other people may install from.
         Supply-chain reach, and usually irreversible.

  * Destructive git operation   2026-09-15 17:30:00  Bash  e181acd29cf199ab
      git push --force origin main
      -> History rewriting or branch deletion. This is the class of action
         that destroys the record of what else happened.

  ----------------------------------------------------------------------------
  Read locally. Nothing was transmitted.
```

Claude Code deletes the transcript of a session you have not used for longer
than
[`cleanupPeriodDays`](https://code.claude.com/docs/en/settings-reference#cleanupperioddays),
30 days by default. So `--days 90` finds more if you raised it, if a session
you resumed within that period has older actions in it, or for sessions
started or last continued in Claude Desktop or Cowork, which Claude Code
v2.1.248 and later
[keep at any age by default](https://code.claude.com/docs/en/claude-directory#cleaned-up-automatically).

## Install

Run it once, without installing anything:

```bash
uvx ranwhat check
```

Or put it on your path:

```bash
pipx install ranwhat
pip install ranwhat
```

Then `ranwhat demo` shows an authority scan on a bundled example.

### As a Claude Code plugin

```
/plugin marketplace add MatijaMiki/ranwhat
/plugin install ranwhat --marketplace MatijaMiki/ranwhat
```

That adds `/ranwhat:check`, `/ranwhat:watch`, `/ranwhat:reach` and `/ranwhat:guard`,
and a skill that tells Claude when to use them. The plugin installs no hook:
the guard stays off until you ask for it with `/ranwhat:guard`. It runs the
same `uvx ranwhat` commands, so it needs `uv` on your path.

Python 3.9+. No dependencies, and nothing is built on your machine.

## Commands

### `ranwhat check`: everything worth knowing, in one read-only pass

Runs watch and clean together and changes nothing. Its last lines suggest
`reach` for the MCP servers and credential files your agents can reach.

`check`, `watch` and `clean` exit with status 0 when they ran, 1 on an
error, and 2 when they found no agent history to read (argparse's usage
errors are 2 as well), so a script can tell a machine with nothing on it
from a clean one. With `--fail-on SEVERITY` they exit 3 when anything at
or above `medium`, `high` or `critical` is found: every action watch rates
that high or higher, and every secret clean finds, each of which is
`critical`. A secret masked with `--apply` still counts: it has to be
rotated. An error (1) or nothing read (2) wins over 3.

```bash
ranwhat check --fail-on high --sarif ranwhat.sarif
```

`--sarif PATH` also writes what was found as SARIF 2.1.0, for code
scanning: one result for each rule an action tripped, and one for each
secret. A secret is in it as the report shows it, masked (`sk_…dc  32
chars`), never its value or its fingerprint, and every value `clean`
finds is masked wherever else it shows up there, as in the report. Agent
history lives outside your repository, so each result points at the
transcript or project directory it came from on the machine that ran it.
An action's results carry its `id` (`actionId`), and fingerprints made from
it, so code scanning can follow a finding from one run to the next.

On a terminal, check, watch and clean keep one status line on stderr while
they read, counting transcripts through each pass: `indexing secrets`
(`(first run)` the first time), `checking actions`, `looking for secrets`.
Nothing is written there when stderr is not a terminal, or with `--json`.

### `ranwhat watch`: audit what Claude Code and your other agents ran

Reads what Claude Code and your other coding agents already wrote to disk.
No wrapper, no proxy, nothing in your critical path unless you install the
[hook](#ranwhat-hook-install-ask-before-a-high-risk-claude-code-call). Every agent below is
read by default, each from where it keeps its history (the variable in
brackets moves it, as it moves the agent itself); one that is not on your
machine is skipped.

| Source | Location | Format |
|---|---|---|
| Claude Code | `~/.claude/projects/*/*.jsonl` and each session's `subagents/**/agent-*.jsonl`, or the same under `$CLAUDE_CONFIG_DIR/projects` when set | JSONL |
| Codex (CLI, IDE extension, desktop app) | `~/.codex/sessions/YYYY/MM/DD/rollout-*.jsonl` and `archived_sessions/` (`$CODEX_HOME`); `history.jsonl`, `shell_snapshots/` and its SQLite thread index are searched for secrets | JSONL; SQLite read only; `.jsonl.zst` read only, on Python 3.14 or with the `zstd` command |
| Gemini CLI | `~/.gemini/tmp/<project>/chats/session-*.jsonl` and older `session-*.json` (`$GEMINI_CLI_HOME`) | JSONL, JSON |
| Antigravity (`agy`, the app and the IDE) | `~/.gemini/antigravity-cli/brain/<conversation>/.system_generated/logs/transcript_full.jsonl`, and the same under `~/.gemini/antigravity` and `~/.gemini/antigravity-ide` | JSONL |
| GitHub Copilot CLI | `~/.copilot/session-state/<session>/events.jsonl` (`$COPILOT_HOME`) | JSONL |
| GitHub Copilot in VS Code | `<editor>/User/workspaceStorage/<workspace>/chatSessions/<session>.jsonl` and `globalStorage/emptyWindowChatSessions/` (`$VSCODE_PORTABLE`, `$VSCODE_APPDATA`) | JSONL, JSON |
| Cursor (editor and `cursor-agent`) | the editor's `Cursor/User/globalStorage/state.vscdb` (under `~/Library/Application Support`, `%APPDATA%` or `~/.config`), and `~/.cursor/chats/*/*/store.db` | SQLite, read only |
| Windsurf | `~/.windsurf/transcripts/*.jsonl`, which Windsurf writes when its `post_cascade_response_with_transcript` hook is on; Cascade's own history (`~/.codeium/windsurf/cascade/*.pb`) is encrypted, so it is counted, not read | JSONL |
| Cline | `<editor>/User/globalStorage/saoudrizwan.claude-dev/tasks/<task>/`, and `~/.cline/data` (`$CLINE_DATA_DIR`) | JSON |
| Roo Code | `<editor>/User/globalStorage/rooveterinaryinc.roo-cline/tasks/<task>/` | JSON, text |
| Kilo Code (CLI and extensions) | `~/.local/share/kilo/kilo.db` and the older `storage/` JSON files (`$XDG_DATA_HOME/kilo`, `$KILO_DB`) | SQLite read only; JSON |
| OpenCode | `~/.local/share/opencode/opencode.db` and the older `storage/` JSON files (`$XDG_DATA_HOME/opencode`, `$OPENCODE_DB`) | SQLite read only; JSON |
| Continue (IDE extensions and `cn`) | `~/.continue/sessions/<session>.json` (`$CONTINUE_GLOBAL_DIR`) | JSON |
| Aider | `.aider.chat.history.md` and `.aider.input.history` in the repository you run ranwhat in, and in your home folder (`$AIDER_CHAT_HISTORY_FILE`) | Text |
| Goose (CLI and desktop) | `~/.local/share/goose/sessions/sessions.db` and older `*.jsonl` there (`$GOOSE_PATH_ROOT`; `%APPDATA%\Block\goose\data` on Windows) | SQLite read only; JSONL |
| Zed | `~/.local/share/zed/threads/threads.db` (`$XDG_DATA_HOME/zed`) | SQLite, read only; zstd-compressed threads need Python 3.14 or the `zstd` command |
| Warp | `~/.local/state/warp-terminal/warp.sqlite` (`$XDG_STATE_HOME`) | SQLite, read only |
| Amazon Q (IDE plugins and `q chat`) | `~/.aws/amazonq/history/chat-history-*.json`, and the CLI's `data.sqlite3` under `~/.local/share/amazon-q` (`$XDG_DATA_HOME`) | JSON, SQLite; both read only |
| Qwen Code | `~/.qwen/projects/<project>/chats/*.jsonl` and older `tmp/<hash>/chats/session-*.json` (`$QWEN_RUNTIME_DIR`, `$QWEN_HOME`) | JSONL, JSON |
| CodeBuddy | `~/.codebuddy/projects/<project>/<session>.jsonl` (`$CODEBUDDY_CONFIG_DIR`) | JSONL |
| Grok Build | `~/.grok/sessions/<folder>/<session>/updates.jsonl` (`$GROK_HOME`) | JSONL |
| Droid | `~/.factory/sessions/*.jsonl`, and `-<cwd>/*.jsonl` and `btw/*.jsonl` below it (`$FACTORY_HOME_OVERRIDE`) | JSONL |
| Kimi Code | `~/.kimi-code/sessions/<folder>/<session>/agents/*/wire.jsonl` (`$KIMI_CODE_HOME`) | JSONL |
| Kimi CLI | `~/.kimi/sessions/<folder>/<session>/wire.jsonl` and `context*.jsonl` (`$KIMI_SHARE_DIR`) | JSONL |
| Pi | `~/.pi/agent/sessions/--<cwd>--/*.jsonl` (`$PI_CODING_AGENT_DIR`) | JSONL |
| Oh My Pi | `~/.omp/agent/sessions/<project>/*.jsonl` (`$PI_CODING_AGENT_DIR`, `$PI_CONFIG_DIR`, `$XDG_DATA_HOME/omp`) | JSONL |
| Muse Code | `~/.local/share/muse/sessions/YYYY/MM/DD/<session>/session.jsonl` (`$XDG_DATA_HOME/muse`) | JSONL |
| Mistral Vibe | `~/.vibe/logs/session/unified/<session>/` and the older `session_*/messages.jsonl` (`$VIBE_HOME`) | JSON, JSONL; unified sessions read only |
| DeepSeek Harness (`dsh`) | `~/.dsh/sessions/<project>/<session>/session.jsonl.zstd` (`$DSH_HOME`) | JSONL; compressed read only, on Python 3.14 or with the `zstd` command |
| OpenClaw | `$OPENCLAW_STATE_DIR/agents/*/agent/openclaw-agent.sqlite` | SQLite, read only |

Meta Muse runs in Meta's cloud and keeps nothing on your machine, so there
is nothing to read; Muse Code, Meta's coding CLI, is supported.
Grok Bot keeps its history in xAI's cloud, even for commands it runs on your
machine; Grok Build, xAI's coding CLI, is supported. The current Amp keeps
its threads on ampcode.com.

Antigravity, GitHub Copilot in VS Code, Kilo Code, Zed, Warp, Amazon Q,
CodeBuddy, Oh My Pi, Mistral Vibe and DeepSeek Harness were written from each
agent's own source code (and its documentation where it has any), not from a
long-lived install: only Mistral Vibe and Antigravity's `agy` CLI were also
run, and none of the ten publishes its history format, so a release of the
agent can change it. Not checked on a real machine: Antigravity's app and
IDE folders and its Windows path, the Preview folders of Warp, VS Code
forks other than Code, and Flatpak Zed. A task that Kilo Code imported from
Roo Code is read under both, so it can be listed twice. Zed's compressed
threads and DeepSeek Harness's sessions need Python 3.14 or the `zstd`
command to be read; without either, `ranwhat sources` counts them as unread.

Sixteen rules: credential access, secret-shaped strings in tool calls, package
publishing, cloud resource changes, financial API calls, log tampering,
destructive git, recursive deletion, local files uploaded with curl, scripts
downloaded and run unread, files made writable by every user, container
volumes wiped, encoded commands decoded and run, an instance's credentials
asked of a cloud metadata service, jobs set to run at login, boot or on a
schedule, and an agent's guardrails loosened.
A command hidden in base64, hex or printf escapes and handed to a shell,
`eval` or an interpreter is decoded without being run, and what it decodes to
is judged by the same rules. A change to a shell startup file is medium; one
that runs `curl … | sh` in every new shell is high. An edit to an agent's
settings is judged by what it lets through: an MCP server added is medium,
`bypassPermissions` in your user settings, or an edit that takes the ranwhat
hook out, is critical. So is any change an agent makes to what ranwhat
itself reports: the secrets `clean` was told to keep, the key they are kept
under, the ignore file, or where ranwhat keeps them.
Each agent's tool calls are judged by the same rules; every action says
which agent ran it.

```bash
ranwhat watch --days 30
ranwhat watch --source codex                # one agent (repeatable)
ranwhat watch --path codex=~/work/.codex    # an agent's history elsewhere
ranwhat watch --json
ranwhat sources                             # every agent, where it looked, what it found
```

`--root` and `--state-dir` still work, as the names of
`--path claude-code=` and `--path openclaw=`.

Each action ends with its `id`: 16 characters, the same on every run
over the same history, and new for a call run again or flagged for
something more. A call read more than once with no time of its own (two
sessions holding it, or an OpenClaw call run again) is one action. With
`--json`, each action has its `id`, the id of each copy in `ids` where
there is more than one, and `cwd`, the directory it ran in, when the
agent wrote one down. An action you expected is left out of later
reports with [`ranwhat ignore`](#ranwhat-ignore-leave-out-what-you-expected).

### `ranwhat ignore`: leave out what you expected

A report that lists the same expected actions on every run stops being
read. `ranwhat ignore` names what to leave out, by the id at the end of
each action's line:

```bash
ranwhat ignore 3fa9c2d81b7e4a06   # that action, or on a terminal, every one like it
ranwhat ignore all                # everything listed now: later runs list only what is new
ranwhat ignore                    # what the file leaves out, line by line
```

On a terminal, `ranwhat ignore ID` asks whether to leave out that action
alone or every action like it: the same command, word for word, run in
the same folder or below it, and for a critical one until a date a year
away. `--no-interactive` adds the id without asking.

Both write `~/.ranwhat/ignore` (`$RANWHAT_HOME/ignore`), mode 0600, a
plain-text file you can read and edit. One entry a line, and `#` after a
blank starts a comment:

```
publish 'npm publish' in=~/work/mylib until=2027-01-31       # mylib releases
persist 'sudo systemctl enable docker'                        # docker at boot here
git.destructive 'git push --force origin gh-pages'
cred.read ~/work/mylib/.env.test until=2027-04-01             # fixture values only
exec.remote                                                   # medium and high only
3fa9c2d81b7e4a06  # publish 'npm publish' in=~/work/mylib  (Claude Code, 2026-09-21 11:05)
```

- An id leaves out that action. Several on a line are the copies of one
  call, as watch's `ids` lists them.
- `RULE 'COMMAND'` leaves out every action the rule flags whose command is
  COMMAND, word for word. It is matched against the whole command the
  action ran, not the evidence printed: `npm publish --registry
  https://registry.npmjs.evil.example/` is not `npm publish`, and `sudo npm
  publish` is not either. A `*` stands for any run of characters within one
  word. When the rule flagged a file a tool read or wrote, a path stands in
  for the command. With no command, every action the rule flags.
- `in=DIR` leaves out only what ran in DIR or below it, following a `cd`
  earlier in the same call; `until=YYYY-MM-DD` is the last day it applies.
- A line ranwhat cannot read is skipped, named in every report, and leaves
  nothing out. `ranwhat ignore` exits 3 when one is.

`--ignore PATH` makes check, watch and ignore use another file, such as a
repository's `.ranwhatignore`. ranwhat never picks one up from the working
tree on its own, which is what an agent writes most easily, and no variable
points at one, so a cron job and your terminal read the same file.

What is never left out:

- A secret. `clean` masks it, or keeps it in its review; an action that
  holds one stays listed until then.
- A critical action, but by its id, or by an entry that names its program
  in full, with `in=` and an `until=` no more than 400 days ahead. The
  report says when an entry matches a critical action and lacks those.
  An entry sees the words of the one command, not the state set before it
  in the call or by an earlier one (an `export`, `npm config set`, an
  `.npmrc` written a call ago), so a critical action you cannot afford to
  see redirected is better left out by its id than by a pattern.
- A change an agent made to what ranwhat reports (this file, the values
  `clean` was told to keep, the key, where ranwhat keeps them, or `ranwhat
  ignore` itself), until you acknowledge it on a terminal with `ranwhat
  ignore ID`, which writes the id with `ack`.
- What a call decoded from base64 or the like, but by its id.

Every report says how many actions the file left out, and by which line:
under the report, on stderr with `watch --json`, and as `"ignored"` in
`check --json`. `--no-ignore` lists them all again, each marked with the
line that would leave it out. `--fail-on` counts only what is listed, and
says how many at or above it were left out. A SARIF log leaves them out
too, which closes their alerts in code scanning. The hook does not read the
ignore file: what you ignore is left out of reports, and the hook still
asks.

**Only what is new.** `ranwhat ignore all` writes the id of every action
listed now, in one dated block. Give it the `--days` you run watch with: a
later `--days 365` lists older actions it never saw. `ranwhat ignore -`
reads the ids from `watch --json` or `check --json` on stdin, so a cron job
alerts on each new action once:

```bash
ranwhat ignore all --days 30                      # once: what is there now is known
# hourly:
ranwhat watch --days 30 --fail-on high --json > ~/ranwhat-new.json 2> ~/ranwhat-notes.txt
[ $? -eq 3 ] && mail -s "ranwhat: new actions" me < ~/ranwhat-new.json
ranwhat ignore - < ~/ranwhat-new.json             # each new action alerts once
```

A change to ranwhat's own settings is never added by `ignore all` or
`ignore -`, so it alerts on every run until you acknowledge it.

watch and the hook judge what a call shows, so a script that rewrites the
file is not seen. An id changes when a later ranwhat flags a call for
something more, or rates it otherwise, and the action is listed once more:
run `ranwhat ignore all` again after an upgrade for a fresh baseline. An
agent that records neither a call id nor a time for a call (Windsurf) is
named by what the call held, as ranwhat masks it, so its action is listed
once more if another agent's history later shows a value from its command;
`ranwhat ignore all` leaves it out again. The comment ranwhat writes after each id holds the command, masked as the
report masks it, and where it ran; read a `.ranwhatignore` before you
commit it.

### `ranwhat clean`: find secrets in Claude Code and other agents' transcripts

When an agent runs `cat .env`, the **output** is written into the transcript:
your database password, your JWT secret, your provider tokens, in plaintext,
in a file Claude Code keeps for 30 days by default.

```bash
ranwhat clean               # report, then open a review session
ranwhat clean --apply       # mask everything without asking
```

`clean` searches every agent's history, and masks a value only in a file
the agent lets it rewrite: a plain JSONL, JSON or text file nothing has
written to in the last two minutes. Databases (Codex's thread index,
OpenClaw's agent databases) and compressed files are read only: the report
names each one that holds a secret and how to remove it in the agent
instead.

Scanning a real history takes a while, so the session stays open on what it
just found rather than making you re-scan to act on it:

```
ranwhat> list           the findings again
ranwhat> show 3         where it appears, and what to roll it at
ranwhat> mask 3         mask just that one
ranwhat> mask all       mask everything listed
ranwhat> keep 3         leave it alone, and do not report it again
ranwhat> rotate         what to rotate, grouped by provider, with each page
ranwhat> open           open those pages in your browser (open 3: just that one)
ranwhat> revoke 3       revoke that token now, at GitHub, Slack or Google
```

`keep` is remembered: a value you keep is neither listed nor counted by
`clean`, `check` or `--fail-on` on later runs, and `clean --apply` leaves
it as it is. Each report says how many it left out. What is kept is a
keyed hash of each value in `~/.ranwhat/known/kept.json`, beside the
secrets index and under its key, never the value; delete that file to
have them all reported again.

Each finding says which project it was found in and, when the transcript
names it, the file it was read out of, because a 64-character string is
useless without knowing which `.env` it escaped:

```
* Stripe live secret key   sk_…dc  32 chars  seen 8x
      read from api/.env
      in         /Users/you/Desktop/app
```

**Redaction is not remediation.** Masking a value here does not un-expose it.
It was already on disk and already sat in a model context you do not control.
The rotation is the fix; masking only stops it leaking a second time. The
report says so rather than implying safety.

Only masks a value when the key beside it names it as a secret or the value
carries a recognisable credential shape. Placeholders, template files and
ordinary config are left alone, and so are published documentation examples
(AWS's `AKIAIOSFODNN7EXAMPLE`) and obvious test fixtures such as
`AKIA1234567890ABCDEF`. Backups go to `~/.ranwhat/backups`, and the
rewritten file is parsed back before it replaces the original.

A password typed into a command, with no key beside it, is found where the
command takes it: `mysql -pPASSWORD` (and mysqldump, mysqladmin, mariadb),
`sshpass -p`, `redis-cli -a`, `docker login -p`, `curl -u user:password`,
`--password`, and the same places in sqlcmd, mongosh, ldapsearch, htpasswd,
keytool, `ConvertTo-SecureString -AsPlainText` and smbclient. A variable
there, such as `-p$MYSQL_PWD`, is left alone.

### The secrets index

`check` and `watch` hide every secret `clean` finds anywhere in your
history, in every agent's, whatever `--days` and `--source` say, wherever
a copy of one shows up: a password read in a Codex session is hidden where
Claude Code typed it. To know them without reading every transcript on
every run, they keep an index in `~/.ranwhat/known/`
(`$RANWHAT_HOME/known/` when that is set), one file per Claude Code
transcript directory, and read a file again only when its size or
modification time changes. The first run reads them all, and says so.
`check` fills it from its own search for secrets, so no transcript is read
for them twice.

The index holds salted fingerprints, never a secret: for each, 16 bits of
a keyed BLAKE2b hash of its first six characters (a tag a great many
beginnings share, so it narrows a guess at them by no more than 16 bits),
its length, and keyed hashes of the whole value and of the fingerprint its
mask keeps. The key is random, made once per machine, and sits beside the
index. Both files are readable by you alone. `clean` adds each secret
before it masks it, so a copy it missed stays hidden too, however the
session ends.

If the index is deleted, damaged or loses its key, the next run builds it
again from the transcripts. A secret `clean` has already masked cannot be
learned again that way: the transcript keeps only its mask's fingerprint.
A copy the mask missed is then still hidden where it stands apart from
what is around it, and where it is glued into a command `check` or `watch`
shows, if it is no longer than 64 characters. Glued into anything else, it
is not. So keep the index unless you are starting over.

### `ranwhat reach`: MCP servers and credential files your agents can reach

Reads the configuration your agents keep on disk and reports two things,
then the Claude Code deny rules that would close what it found. It only
reads, and writes no settings.

**MCP servers.** Every server in Claude Code's `~/.claude.json` (user
scope, and each project's local scope), each project's `.mcp.json`, and
`managed-mcp.json`; plus Claude Desktop's `claude_desktop_config.json`,
Cursor's `~/.cursor/mcp.json` and `.cursor/mcp.json`, VS Code's
`.vscode/mcp.json`, Gemini CLI's and Qwen Code's `settings.json`, GitHub
Copilot CLI's `~/.copilot/mcp-config.json`, Windsurf's `mcp_config.json`
and Codex's `~/.codex/config.toml` (on Python 3.11 and later). For each:
what it runs or connects to, and

- a secret written inline, in `env`, an argument, a header or the URL,
  found by the rules `clean` uses and shown the way `clean` shows one
  (`<ghp…x4>`), never whole. `${VAR}` references are left alone.
- a package fetched at its newest version on every start: `npx`, `uvx`,
  `bunx`, `pnpm dlx`, `pipx run` and the like with no exact version
- a remote URL, plain `http`, or a URL on this machine
- a project `.mcp.json` whose servers Claude Code starts without asking,
  because `enableAllProjectMcpServers` is on

It reads the configuration, not the server: it does not inspect a
server's code or its tool descriptions for malicious content.

**Credential files.** `.env` and `.env.*` (not `.env.example` and other
templates), private keys, `.npmrc`, `.pypirc`, `.netrc` and
`.git-credentials` under the directories your agents work in (the current
one, every project in `~/.claude.json`, and `additionalDirectories`,
six levels deep, past `node_modules` and `.git` and into only the top of
`build/` and `dist/`; the report says when a project goes deeper), and
`~/.env`, `~/.aws/credentials`, `~/.ssh/id_*`, `~/.netrc`, `~/.npmrc`,
`~/.docker/config.json`, `~/.kube/config`, `~/.config/gh/hosts.yml` and
Google Cloud's application default credentials, each only when it holds a
credential and no Claude Code `Read(...)` deny rule covers it. Only paths
are printed, never what is in them.

```bash
ranwhat reach               # every project Claude Code knows, and the current directory
ranwhat reach ~/code/app    # one project
ranwhat reach --json
```

The report ends with a `permissions.deny` block to paste into
`~/.claude/settings.json`, one rule for each file found:

```json
{
  "permissions": {
    "deny": [
      "Read(~/.aws/credentials)",
      "Read(~/.ssh/**)",
      "Read(//**/.env.local)"
    ]
  }
}
```

A Read rule stops Claude's file tools and the Bash file commands Claude
Code recognises, not a script that opens the file itself; the
[`.env` guide](https://ranwhat.com/guides/claude-code-env-secrets) covers
the sandbox for that.

### In CI: the GitHub Action

`action.yml` at the root of this repository is a composite GitHub Action.
It runs `ranwhat check` (or `watch`, or `clean`, which there only
reports) over the agent history on the runner, with `--fail-on`, and
uploads the SARIF to code scanning with GitHub's own `upload-sarif`. It
runs ranwhat from the action's own checkout with the runner's Python, so
nothing is installed and nothing is fetched from PyPI. Put it after the
steps where an agent ran, in the same job: that is where the agent's
history is.

```yaml
permissions:
  contents: read
  security-events: write      # for the SARIF upload

steps:
  # ... the steps that run Claude Code or another agent ...
  - uses: MatijaMiki/ranwhat@main      # pin a commit SHA in production
    with:
      fail-on: high                    # medium, high, critical, or "" to never fail
      # command: check                 # or watch, or clean
      # days: "30"
      # args: --source claude-code     # any other flags
      # upload-sarif: "true"
      # sarif-file: ranwhat.sarif
      # allow-empty: "false"           # "true" passes when there is no history
      # ignore-file: .ranwhatignore    # what to leave out, as committed at the base
```

The step fails with ranwhat's exit status, which is also its `exit-code`
output: 3 for findings at or above `fail-on`, 2 when there was no agent
history to read (unless `allow-empty`), 1 on an error.

`ignore-file` names a [`ranwhat ignore`](#ranwhat-ignore-leave-out-what-you-expected)
file in the repository. The Action reads it as it was committed at the pull
request's base, or before the push, never as the job left it: neither a step
that ran an agent nor the pull request itself can widen it, and it warns
when the job changed it. Without the input nothing is left out, and the
runner's own `~/.ranwhat/ignore` is never read. `args: --ignore PATH` reads
a file as it is instead. On a self-hosted runner whose agent history
persists, build the file with `ranwhat ignore all --ignore .ranwhatignore`,
read it (its comments hold commands, masked), commit it, and give it an
owner in CODEOWNERS; a pull request job that runs `ranwhat ignore --ignore
.ranwhatignore` fails with exit status 3 on a line ranwhat cannot read.

### `ranwhat scan`: score what an agent's credentials can do

Reads the credentials an agent holds, read-only, and scores the three things
that determine exposure.

| Axis | Question |
|---|---|
| Authority | What is it allowed to do? |
| Observability | Can you reconstruct a named past action? |
| Reversibility | Can a wrong action be undone? |

Observability vetoes the overall verdict. An agent that cannot reconstruct its
own tool calls is indistinguishable from the worst case.

```bash
ranwhat demo                                # see it on a worked example
ranwhat scan profile.json --html report.html

read -rs RANWHAT_GITHUB_TOKEN                # paste it: not echoed, not saved to history
export RANWHAT_GITHUB_TOKEN
ranwhat live                                # read-only introspection
ranwhat callers --mine 198.51.100.0/24      # who used a key, from the provider's log
ranwhat revoke                              # grants that skip your yes; --apply takes them back

read -rs RANWHAT_STRIPE_TOKEN
export RANWHAT_STRIPE_TOKEN
ranwhat scan profile.json --pull-usage
```

Capability catalogues for Google, GitHub, GitLab, Microsoft 365, Slack, Discord, Stripe, Shopify, HubSpot, Atlassian, Sentry and AWS.
Unrecognised
scopes are classified by action verb and flagged unclassified, never assumed
safe.

A fine-grained GitHub token or a restricted Stripe key comes back from `live`
as a finding, not a score: neither provider lists its permissions through its
API. Copy them into a profile as that credential's `scopes` and `scan` it.

### `ranwhat update`: refresh the capability catalogue

`ranwhat update` refreshes the capability catalogue from ranwhat's feed. It
needs Plus, live now at €12 a month per organisation
([pricing](https://ranwhat.com/pricing)), and sends only your token: the one
`ranwhat login` saved for this machine, or one in `RANWHAT_TOKEN`.

On a terminal, `scan`, `live` and `update --status` may add one dim line
about the feed, on stderr and never with `--json`. `RANWHAT_NO_HINTS=1` turns
it off.

### Linking an account: `ranwhat login`, `whoami` and `logout`

Optional, and nothing else needs it. An account at
[account.ranwhat.com](https://account.ranwhat.com/) manages Plus for an
organisation: its members, its machines, CI tokens and billing.

```bash
uvx ranwhat login     # prints a code to type at https://ranwhat.com/device
uvx ranwhat whoami    # the account, organisation, role and plan
uvx ranwhat logout    # revokes this machine's token, then deletes it
```

- `login` uses the device flow `gh auth login` uses: it prints a code, you
  sign in at ranwhat.com/device, type the code there, name the machine and
  approve it, which asks for an emailed code typed in the last 15 minutes.
  The printed code is never in a link. The machine then has a token of its
  own, saved at `~/.ranwhat/token` (mode 0600, never through a symlink),
  which `update` reads. `--force` replaces a saved token and asks the server
  to revoke the old one; `--no-browser` only prints the page.
- `whoami` shows whose a token is: the one given with `--token`, otherwise
  `RANWHAT_TOKEN`, otherwise the saved one, the order `update` reads them in.
- `logout` asks the server to revoke this machine's token, then deletes it.
  A shared token, a subscription's or a CI token, is only deleted here.
  `--local` deletes it without asking the server.
- They send `feed.ranwhat.com` a code or the token, and never a hostname,
  operating system, user name or machine identifier. The server notes the day
  a linked machine's token was last used, and nothing finer. Beside the token,
  `~/.ranwhat/account.json` (mode 0600) keeps the plan, organisation and email
  last heard for it, under the token's SHA-256, so the hints about Plus are
  right; `logout` deletes both.

### `ranwhat push`: send this machine's findings to your account

Plus, and only ever something you run. `ranwhat push` reads what `watch`
reads, leaves out what your ignore file leaves out, and sends the result to
your organisation's account, so every linked machine's findings can be read
side by side at [account.ranwhat.com/findings](https://account.ranwhat.com/findings).
Nothing runs it for you: not the hook, `check` or `watch`.

```bash
uvx ranwhat push --dry-run   # print the exact JSON; sends nothing, needs no account
uvx ranwhat push             # say what it will send, ask, then send
```

- What it sends is derived metadata: for each flagged action (at most 100,
  most severe first) the rule id and severity of each rule it tripped, a
  16-character action id (a hash, not the action), the agent and the time in
  UTC; then counts, ranwhat's version and the window in days. Actions your
  ignore file leaves out are counted and not listed. The machine is the token
  that signs the request, and the body has no field for anything else.
- It never sends a command, a path, evidence, a working directory, a session
  id, file contents, a secret, your hostname or your user name. The document
  is built from those few facts and nothing else is read from a record, and
  the server refuses a body with any other field.
- It goes only to `feed.ranwhat.com`, over HTTPS, with this machine's token
  (`ranwhat login`) or a CI token in `RANWHAT_TOKEN`. An organisation on Free
  is refused, and nothing is stored. Without `--yes` it asks first, and on a
  pipe it refuses. `--days N` sets the window; `--json` prints the answer.
- Plus keeps each machine's latest push whole, and a summary of the counts of
  earlier pushes for 30 days, at most 30, and nothing past 90 days. That is
  not the 13-month record, a separate feature that is still being built. The
  same findings pushed again change nothing. Every member of the organisation
  can read them. `ranwhat logout`, or revoking the machine on the account
  page, deletes what that machine pushed.

### `ranwhat hook install`: ask before a high-risk Claude Code call

Every other command works after the fact, and the agent never knows.
The hook is the one opt-in exception. `ranwhat hook install` adds a
PreToolUse hook to Claude Code's settings, and from the next session each
tool call watch's rules rate high or critical waits for your yes before it
runs.

```bash
uv tool install ranwhat        # or pipx install ranwhat; uvx is refused
ranwhat hook install           # ~/.claude/settings.json, or $CLAUDE_CONFIG_DIR's
ranwhat hook status
ranwhat hook uninstall
```

- It judges each call on your machine and sends nothing anywhere. A call no
  rule rates high or critical gets no answer, so Claude Code decides as it would have without
  the hook.
- It fails open: if the hook itself breaks, the call goes ahead.
- `--mode deny` refuses critical calls outright and still asks for high
  ones, for an agent you check on only now and then.
- `--scope project` writes `.claude/settings.json` for everyone on the
  repository; `--scope local` writes `.claude/settings.local.json` for you.
- `RANWHAT_HOOK=0` in Claude Code's environment lets every call through.
- It asks before a call that shows it turning the hook off: `ranwhat hook
  uninstall`, `RANWHAT_HOOK=0 claude`, or an edit (Edit, `sed`, `jq`, `yq`, a
  removal) that takes its entry out of the settings or sets
  `disableAllHooks`. Claude Code applies a settings change as soon as the
  file changes, so before the call is the only time to ask. In deny mode such
  a call is refused, and the agent is told to ask you to run it yourself.
  A settings file rewritten whole with other settings, by a call that does
  not show what it replaced, is recorded as medium and not asked about, and
  a script that rewrites it is not seen: the hook judges what a call shows,
  and is no sandbox.
- It asks in the same way before a call that changes what ranwhat itself
  reports, since what such a change leaves out is missing from every report
  after it: a write to `~/.ranwhat/known/kept.json`, which holds the secrets
  `clean` was told to keep, or to the key beside it; a write to the ignore
  file, `~/.ranwhat/ignore` or a `.ranwhatignore` anywhere; anything copied,
  moved or linked into `~/.ranwhat`; `RANWHAT_HOME` set for good, in a
  startup file, in Claude Code's settings, or with `setx`, `launchctl
  setenv` or `systemctl set-environment`; and `ranwhat ignore` given an
  action to add. Reading the ignore file or `kept.json`, or taking one out,
  only means more is reported, and is not asked about; reading the key is,
  as a credential read (below). A one-off
  `RANWHAT_HOME=/tmp/x ranwhat watch`, which changes that run alone, is not
  asked about either. A
  state folder set with `RANWHAT_HOME` to a path without the word ranwhat in
  it is recognised in a file tool's path, and not in a shell command.
- The hook does not read the ignore file: what you ignore is left out of
  reports, and the hook still asks.
- Each check takes about a fifth of a second. The reason it gives Claude
  Code names the rule, never the value that tripped it.

### `ranwhat bench`: see what ranwhat catches, on made-up data

Builds a made-up agent home in a temporary directory: a Claude Code session
transcript and the credential files that session printed, with fake secrets
drawn from a seed. It runs the read-only detection `check`, `watch` and
`clean` use over it, in this process and offline, and scores the result
against an answer key: planted secrets `clean` must find (AWS, GitHub,
Stripe, Slack and OpenAI-style keys, an npm token, a database password and
URL, a JWT, a private key); decoys it must leave alone (git and SHA-256
digests, UUIDs, base64 of ordinary text, the AWS and Stripe documentation
keys, placeholders, code that fetches a password); risky calls `watch` must
rate, under which rule and at what severity; and ordinary calls it must not
flag. It also checks that no planted value, nor its leading, trailing or
middle characters, nor any line of a planted key, appears in what ranwhat
printed for the run (on the standard streams and in the reports it built;
a write that bypasses them is out of its sight), and that the run read the
transcript whole, changed nothing and printed nothing.

```bash
ranwhat bench             # a table; exit status 3 when an expectation is not met
ranwhat bench --seed 7    # other fake values, the same expectations
ranwhat bench --json
```

Under the table it lists what ranwhat is known not to catch, such as a
script downloaded to a file and run in a later call, `env | grep -i token`
and a plain `docker system prune`. Those are never counted as passes and
never fail the run, and one ranwhat later learns to catch is shown as
caught. The answer key is written by the people who wrote the detectors, so
a pass says that nothing on it has regressed, not how much of what is on
your machine ranwhat would catch. Exit status: 0 every expectation met, 3
at least one not, 1 an error. It reads and writes inside its own temporary
directory, which it deletes, and never opens your home directory or
`~/.ranwhat`.

## Precision is the feature

A watcher that cries wolf gets muted in a day, and a muted watcher records
nothing anyone reads. So these are **not** treated as actions:

| Not an action | Why |
|---|---|
| `grep "rm -rf" src/` | Searching for a string isn't running it |
| `python3 -c "print('rm -rf /')"` | The payload is Python source, not shell |
| `echo "rm -rf /"` | An echo argument is literal text |
| `cat > f.sh <<'EOF' … EOF` | A heredoc body is data being written |
| `git rm --cached x` | Unstages; never touches the working tree |
| `# rm -rf ~/x` | A comment |
| `rm -rf build` `rm -rf /tmp/x` | Deleting build output is not an incident |
| `base64 -d > key.pem`, `curl ... \| base64 -d \| jq` | Decoding is not running; decoded text handed to a shell, `eval` or an interpreter is |

`bash -c` is the exception: its payload really is shell, so the parser
recurses into it. And severity follows the **target**, not the verb:
`rm -rf /tmp/x` is silent, `rm -rf ~/Documents` is high, `rm -rf /` is
critical.

The grep, Python, heredoc and build rows came from running the tool on real
history and finding it wrong; the others came from probing a released build.
The first watch build flagged 6 findings, and 3 were false positives: a grep
for `rm -rf`, the same string inside a Python one-liner, and a heredoc being
written to a file. A later release reported 15 findings on one machine's
90-day history, and 11 were true deletions of build and temp directories that
nobody would want to read. Once deletions were ranked by target, the same
history gave 4, and all four were real.

`ranwhat bench` runs a public answer key against these rules.

## Handling credentials

Pass tokens through the environment, not the command line. Anything in argv is
readable by every user on the machine through the process table, and is written
to your shell history.

```bash
read -rs RANWHAT_STRIPE_TOKEN       # paste it: not echoed, not saved to history
export RANWHAT_STRIPE_TOKEN
ranwhat scan profile.json --pull-usage
```

Read it in and `export` it first, because `VAR=x ranwhat ...` on one line still
puts the value in that shell's own command line, and a typed `export VAR=x`
puts it in your shell history. `--stripe env:MY_VAR` and `--stripe -` (read one
line from stdin) also work. Passing a token as a flag value still works and
prints a warning saying why it shouldn't.

Reports are written mode `600` and never through a symlink: a report maps an
agent's entire authority surface, which is useful to somebody other than you.
The ignore file, `~/.ranwhat/ignore`, is written mode `600` as well, whole and
under a lock; a file other users can write is not used.

ranwhat keeps two secrets of its own, each mode `600`: its account token,
`~/.ranwhat/token`, and `~/.ranwhat/known/key`, the key the secrets index
and the values `clean` was told to keep are hashed under. Whoever holds the
key can write `kept.json` to keep any value out of every report. `watch`
rates an agent's read of either as credential material accessed, critical,
as it rates a read of `~/.aws/credentials`, and the hook asks before one.

## What goes online

No account needed. live, callers, --pull-usage and clean's revoke ask only the
provider that issued each token, and update, login, whoami, logout and push talk only to ranwhat.com.
push sends derived metadata only, and only when you run it. Everything else reads locally and sends nothing.

- Provider credentials are held in memory for one call and never written down. The only token ranwhat stores is your own ranwhat token, at `~/.ranwhat/token` (mode 0600): the machine token from `ranwhat login`, or a subscription token saved with `update --save-token`.
- Live introspection talks only to the credential's own issuer
- Scans never exercise a permission and never need a write-scoped token
- No runtime dependencies, so there is nothing to audit before you point this at your keys

## What it does not read yet

- The large tool outputs Claude Code stores in `<session>/tool-results/`
- `~/.claude/history.jsonl`
- Events OpenClaw stores compressed (`event_zstd`), and the cold
  transcript archives in `agents/<agentId>/sessions/cold/` under its
  state directory, which
  [its database layout](https://docs.openclaw.ai/reference/database-schemas/layout)
  says also hold history

When `CLAUDE_CONFIG_DIR` is set, transcripts are read from
`$CLAUDE_CONFIG_DIR/projects`, and `--root PATH` reads any other directory. A
run that reads nothing says that nothing was checked, rather than that nothing
was found.

## Say what you don't know

Usage evidence has three states, reported distinctly, because collapsing them
makes the report contradict itself:

| State | Meaning |
|---|---|
| Verified | Pulled from the provider's own audit trail |
| Self-attested | Declared in the profile, not independently pulled |
| Unverified | No evidence at all, and scopes are not assumed safe |

Usage pulls: AWS IAM service-last-accessed, Stripe events, Google Admin SDK,
GitHub org audit log. Slack has no usage pull, so Slack usage is only ever
self-attested or unverified.

## Status

Alpha, honestly. The local tools ship and are tested; hosted collection and
evidence retention are not built yet.

```bash
python3 -m unittest discover -s tests -v
```

The suite is written as invariants rather than expected output. Most tests
exist because something on this page was once wrong.

Links: [Website](https://ranwhat.com) ·
[Changelog](https://github.com/MatijaMiki/ranwhat/commits/main) ·
[Issues](https://github.com/MatijaMiki/ranwhat/issues)

## Licence

MIT. Built by cenner.
