# ranwhat

**A flight recorder for AI agents, and a scanner for the authority they hold.**
AI coding agent security for Claude Code, run on your own machine.
No account, no telemetry, no dependencies.

Website and docs: https://ranwhat.com

Your coding agent has your shell, your keys and your repo. `ranwhat` reads
what it actually ran and surfaces the handful of irreversible actions worth
knowing about.

```
$ ranwhat watch --days 90

  ranwhat watch  · local agent flight recorder
  ----------------------------------------------------------------------------
  4 transcript(s) scanned, last 90 days

  2 critical  2 high

  * Credential material accessed   2026-09-30 18:13:00  Bash
      cat ~/.ssh/id_rsa
      -> The agent read a file whose only purpose is to hold secrets. Whatever
         it read is now in a model context you do not control.

  * Bulk or recursive deletion   2026-09-28 14:42:00  Bash
      …rm -rf '@'
      -> Recursive deletion. Recoverable only if something else was backing it
         up.

  * Package or release published   2026-09-21 11:05:00  Bash
      npm publish
      -> Something was pushed to a registry other people may install from.
         Supply-chain reach, and usually irreversible.

  * Destructive git operation   2026-09-15 17:30:00  Bash
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

Python 3.9+. No dependencies, and nothing is built on your machine.

## Commands

### `ranwhat check`: everything worth knowing, in one read-only pass

Runs watch and clean together and changes nothing.

On a terminal, check, watch and clean keep one status line on stderr while
they read, counting transcripts through each pass: `indexing secrets`
(`(first run)` the first time), `checking actions`, `looking for secrets`.
Nothing is written there when stderr is not a terminal, or with `--json`.

### `ranwhat watch`: audit what Claude Code ran

Reads what Claude Code already wrote to disk. No wrapper, no proxy, nothing in
your critical path.

| Source | Location | Format |
|---|---|---|
| Claude Code | `~/.claude/projects/*/*.jsonl` and each session's `subagents/**/agent-*.jsonl`, or the same under `$CLAUDE_CONFIG_DIR/projects` when set | JSONL |
| OpenClaw | `$OPENCLAW_STATE_DIR/agents/*/agent/openclaw-agent.sqlite` | SQLite |

Nine rules: credential access, secret-shaped strings in tool calls, package
publishing, cloud resource changes, financial API calls, log tampering,
destructive git, recursive deletion, and local files uploaded with curl.

```bash
ranwhat watch --days 30
ranwhat watch --source claude-code
ranwhat watch --json
```

### `ranwhat clean`: find secrets in Claude Code transcripts

When an agent runs `cat .env`, the **output** is written into the transcript:
your database password, your JWT secret, your provider tokens, in plaintext,
in a file Claude Code keeps for 30 days by default.

```bash
ranwhat clean               # report, then open a review session
ranwhat clean --apply       # mask everything without asking
```

Scanning a real history takes a while, so the session stays open on what it
just found rather than making you re-scan to act on it:

```
ranwhat> list           the findings again
ranwhat> show 3         where it appears, and what to roll it at
ranwhat> mask 3         mask just that one
ranwhat> mask all       mask everything listed
ranwhat> keep 3         leave it alone
ranwhat> rotate         what to rotate, grouped by provider
```

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
history, whatever `--days` says, wherever a copy of one shows up. To know
them without reading every transcript on every run, they keep an index in
`~/.ranwhat/known/` (`$RANWHAT_HOME/known/` when that is set), one file per
transcript directory, and read a transcript again only when its size or
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
needs a Plus subscription, which is not available yet, and sends only the
subscription token.

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

## What goes online

No account needed. live and --pull-usage ask only the provider that issued
each token, and update only fetches the catalogue. Everything else reads
locally and sends nothing.

- Provider credentials are held in memory for one call and never written down. The only token ranwhat stores is your own subscription token, and only with `update --save-token` (mode 0600).
- Live introspection talks only to the credential's own issuer
- Scans never exercise a permission and never need a write-scoped token
- No runtime dependencies, so there is nothing to audit before you point this at your keys

## What it does not read yet

- The large tool outputs Claude Code stores in `<session>/tool-results/`
- `~/.claude/history.jsonl`
- Events the SQLite source stores compressed (`event_zstd`), and the cold
  transcript archives in `agents/<agentId>/sessions/cold/` under the same
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
