# Security

ranwhat is pointed at your credentials and your agents' transcripts, so a
flaw in it matters more than in most tools. Reports are welcome and read by
the person who wrote the code.

## Reporting

Write to **hello@ranwhat.com** with `security` in the subject. Please do not
open a public issue first.

Say what you found, how to reproduce it, and which version (`ranwhat
--version`, or the commit). A proof of concept against a scratch transcript
or a throwaway token is ideal; please never send a real credential.

## What to expect

One person maintains this, so:

- an acknowledgement within a few days,
- a fix or a plan within two weeks for anything that exposes a secret, writes
  outside the files it says it touches, or lets transcript content change
  what the tool reports,
- credit in the commit and release notes, unless you would rather not.

## In scope

- The `ranwhat` package on PyPI and this repository.
- ranwhat.com and its contact form (`worker/`, `functions/`, `site/`).

Out of scope: findings that need an attacker who already runs code as you,
unless ranwhat makes their position meaningfully worse (for example by
writing a second copy of a secret somewhere they could not previously read).
