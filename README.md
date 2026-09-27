# ranwhat

**A flight recorder for AI agents, and a scanner for the authority they hold.**
Reads locally. Transmits nothing. No dependencies.

Your coding agent has your shell, your keys and your repo. `ranwhat` reads
what it actually ran and surfaces the handful of irreversible actions worth
knowing about.

```
$ ranwhat watch --days 90

  ranwhat watch  · local agent flight recorder
  --------------------------------------------------------------
  4 source(s) over 90 days

  1 critical  3 high

  * Credential material accessed          18:13  Bash
      cat ~/.ssh/id_rsa
      -> Whatever it read is now in a model context you do not control.

  * Bulk or recursive deletion            14:42  Bash
      mv '@/components/'*.tsx src/components/ ; rm -rf '@'
      -> Recursive deletion. Recoverable only if something else was
         backing it up.

  --------------------------------------------------------------
  Read locally. Nothing was transmitted.
```

## Install

```bash
uvx ranwhat watch --days 30
```

Or put it on your path:

```bash
pipx install ranwhat
```

Python 3.9+. No dependencies, and nothing is built on your machine.

## Two tools

### `ranwhat watch`: what your agents did

Reads transcripts your agents already wrote to disk. No wrapper, no proxy,
nothing in your critical path.

| Source | Location | Format |
|---|---|---|
| Claude Code | `~/.claude/projects/*/*.jsonl` | JSONL |
| OpenClaw | `$OPENCLAW_STATE_DIR/agents/*/agent/*.sqlite` | SQLite |

Nine rules: credential access, secret literals in commands, package
publishing, cloud destruction, financial API calls, log tampering, destructive
git, recursive deletion, exfiltration-shaped pipes.

```bash
ranwhat watch --days 30
ranwhat watch --source openclaw
ranwhat watch --json
```

### `ranwhat scan`: what they're allowed to do next

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
ranwhat live --github "$GH_TOKEN"           # read-only introspection
ranwhat scan profile.json --pull-usage --stripe "$STRIPE_KEY"
```

Capability catalogues for Google, GitHub, GitLab, Microsoft 365, Slack, Discord, Stripe, Shopify, HubSpot, Atlassian, Sentry and AWS.
Unrecognised
scopes are classified by action verb and flagged unclassified, never assumed
safe.

### `ranwhat clean`: secrets sitting in your transcripts

When an agent runs `cat .env`, the **output** is written into the transcript:
your database password, your JWT secret, your provider tokens, in plaintext,
in a file that is never rotated and gets read again by agents later.

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

Each finding says where it came from, the file it was read out of and the
project that file belongs to, because a 64-character string is useless
without knowing which `.env` it escaped:

```
* AWS access key ID   AKI…WB  20 chars  seen 8x
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

Every row above came from running the tool against a real machine and finding
it wrong. On that machine the first build reported 15 findings; 3 were false
positives and 11 were true deletions of build directories that nobody would
want to read. It reports 4 now, and all four are real.

## Handling credentials

Pass tokens through the environment, not the command line. Anything in argv is
readable by every user on the machine through the process table, and is written
to your shell history.

```bash
export RANWHAT_STRIPE_TOKEN="rk_live_..."
ranwhat scan profile.json --pull-usage
```

`export` it first, because `VAR=x ranwhat ...` on one line still puts the value in
that shell's own command line. `--stripe env:MY_VAR` and `--stripe -` (read one
line from stdin) also work. Passing a token as a flag value still works and
prints a warning saying why it shouldn't.

Reports are written mode `600` and never through a symlink: a report maps an
agent's entire authority surface, which is useful to somebody other than you.

## Nothing leaves the machine

Not a policy but an architecture:

- Credentials are held in memory for one call and never written down
- Live introspection talks only to the credential's own issuer
- Scans never exercise a permission and never need a write-scoped token
- No runtime dependencies, so there is nothing to audit before you point this at your keys

## Say what you don't know

Usage evidence has three states, reported distinctly, because collapsing them
makes the report contradict itself:

| State | Meaning |
|---|---|
| Verified | Pulled from the provider's own audit trail |
| Self-attested | Declared in the profile, not independently pulled |
| Unverified | No evidence at all, and scopes are not assumed safe |

Usage pulls: AWS IAM service-last-accessed, Stripe events, Google Admin SDK,
GitHub org audit log. Slack has no usable API below Enterprise Grid and says
so rather than returning an empty set.

## Status

Alpha, honestly. The local tools ship and are tested; hosted collection and
evidence retention are not built yet.

```bash
python3 -m unittest discover -s tests -v
```

102 tests, written as invariants rather than expected output. Most of them
exist because something on this page was once wrong.

## Licence

MIT. Built by cenner.
