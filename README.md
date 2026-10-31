# ranwhat

ranwhat checks whether any of your secrets have leaked into your coding
agents' history, and where. It also checks whether your agent ran anything
sketchy: read your SSH key, force-pushed, piped a script from the internet
into a shell, published a package.

It reads the history that Claude Code and twenty-nine other coding agents
already keep on your disk, including Codex, Gemini CLI, Cursor and GitHub
Copilot
([full list](https://github.com/MatijaMiki/ranwhat/blob/main/docs/reference.md#ranwhat-watch-audit-what-claude-code-and-your-other-agents-ran)).
It's open source (MIT), runs locally and has no dependencies. No account
needed, no telemetry.

## Install

Try it once without installing anything:

```bash
uvx ranwhat check
```

To keep it, install with `pip install ranwhat`, `uv tool install ranwhat` or
`brew install MatijaMiki/ranwhat/ranwhat`. Needs Python 3.9 or later.

## Quick start

```bash
ranwhat check
```

It changes none of your files. It lists the risky things your agents ran in
the last 30 days, and the secrets it finds in those transcripts and where
each one was found (`--days 365` looks further back):

```
  ranwhat watch  · local agent flight recorder
  ...
  * Credential material accessed   2026-09-30 18:13:00  Bash  9c41e07b2d5a8f13
      cat ~/.ssh/id_rsa
      -> The agent read a file whose only purpose is to hold secrets. Whatever
         it read is now in a model context you do not control.

  * Destructive git operation   2026-09-15 17:30:00  Bash  e181acd29cf199ab
      git push --force origin main
      -> History rewriting or branch deletion. This is the class of action
         that destroys the record of what else happened.

  ranwhat clean  · secrets sitting in local transcripts
  ...
  * Stripe live secret key   sk_…dc  32 chars  seen 8x
      read from api/.env
      in         /Users/you/Desktop/app
```

Then `ranwhat clean` walks you through the secrets it found. You can mask
the ones in plain transcript files, see what to rotate, and open each
provider's page to do it. Agents that keep a database, like Cursor, are only
read, and it tells you how to remove the secret there. Masking stops a key
leaking a second time but doesn't un-leak it, so rotate it.

If you want Claude Code to ask you before a high-risk command runs, there's
an opt-in hook: `ranwhat hook install`.

## Free and paid

Everything that runs on your machine is free and stays free. Plus is €12 a
month per organisation, for the things that need a server: findings from
all your machines and CI runners in one place (`ranwhat push`), CI tokens
and teammates on your account, and a catalogue of what each token scope
allows, kept up to date. See [pricing](https://ranwhat.com/pricing).

## More

- [ranwhat.com](https://ranwhat.com): docs and guides
- [Commands](https://ranwhat.com/commands): every command and flag
- [GitHub Action](https://github.com/MatijaMiki/ranwhat/blob/main/docs/reference.md#in-ci-the-github-action):
  run `ranwhat check` in CI after the steps where an agent ran; it can fail
  the job on findings and uploads SARIF
- [Full reference](https://github.com/MatijaMiki/ranwhat/blob/main/docs/reference.md):
  where each agent keeps its history, the rules, the ignore file, the Claude
  Code plugin and exactly what goes online
- [Issues](https://github.com/MatijaMiki/ranwhat/issues)

MIT licence. Built by cenner.
