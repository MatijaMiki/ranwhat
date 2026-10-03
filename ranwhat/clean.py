"""
Find secrets sitting in local agent transcripts, and mask them.

When an agent runs `cat .env`, the *output* is written into the transcript --
your database password, your JWT secret, your provider tokens -- in plaintext,
in a file that is never rotated and gets read again by agents later.

Two things this is careful about:

Redaction is not remediation. Masking a value in a transcript does not
un-expose it; it was already written to disk and already sat in a model
context you do not control. The rotation is the fix. Masking only stops it
leaking a second time, and the report says so rather than implying safety.

Never guess. A value is masked only when the surrounding key names it as a
secret, or the value itself carries a recognisable credential shape.
Placeholders are left alone.
"""

from __future__ import annotations

import bisect
import collections
import datetime
import functools
import hashlib
import json
import math
import os
import re
import shutil
import string

from .watch import CLAUDE_PROJECTS, _fit, discover, transcript_place

from . import agents, fixtures, term
from . import sources as _registry

BACKUP_ROOT = os.path.join(os.path.expanduser("~"), ".ranwhat", "backups")
REDACTION = "<ranwhat:redacted:%s>"

# Key names that make the value beside them a secret. A name is read word by
# word, split at underscores and case changes, so SECRET_KEY, secretKey and
# SECRET_KEY_BASE read the way a person reads them. Requiring a listed word
# at the very end missed Django's SECRET_KEY and every camelCase JSON key.
#
# "key" alone names an index far more often than a credential (sort_key,
# cache_key, primary_key, idempotency_key), so it counts only after a word
# that says which kind of key. A name that says public is shipped to every
# browser (NEXT_PUBLIC_*, PUBLIC_KEY, STRIPE_PUBLISHABLE_KEY).
_NAME_WORDS = re.compile(r"[A-Z]?[a-z]+|[A-Z]+(?![a-z])|[0-9]+")
_SECRET_LAST_WORDS = frozenset((
    "secret", "secrets", "token", "tokens", "password", "passwords", "passwd",
    "pwd", "pass", "passphrase", "apikey", "apikeys", "credential",
    "credentials", "dsn", "auth"))
_SECRET_KINDS_OF_KEY = frozenset((
    "secret", "private", "api", "access", "signing", "app", "encryption",
    "master", "session", "hmac", "jwt", "auth", "admin", "service", "role",
    "server"))
_PUBLIC_WORDS = frozenset(("public", "publishable"))
# A page, sync or redirect token is a cursor an API hands back, not a
# credential. API responses are full of them (nextPageToken, NextToken,
# PaginationToken, $skipToken, searchAfterToken, Graph's deltaToken), and of
# tokens that make a call idempotent, hold a lock, cancel a request (axios's
# cancelToken) or name a task, a device or a form.
_CURSOR_KINDS_OF_TOKEN = frozenset((
    "page", "next", "continuation", "sync", "resume", "cursor", "redir",
    "redirect", "pagination", "start", "starting", "skip", "after", "before",
    "scroll", "marker", "change", "idempotency", "lock", "task",
    "cancellation", "cancel", "delta", "device", "csrf", "xsrf"))
# AWS names its idempotency token ClientToken (or ClientRequestToken), in
# PascalCase as all its JSON is. Vault's client_token is the credential a
# login hands back, so only the camel spelling is a cursor.
_CLIENT_TOKEN = re.compile(r"[Cc]lient(?:Request)?Tokens?$")
# A name in camelCase or PascalCase: a lower-case letter, then a capital,
# or an acronym before a word (IAMAuth). Code names its counts so
# (maxTokens, cacheReadTokens), and main read no such key at all, so a
# count or a flag named in the plural is no secret.
_MIXED_CASE = re.compile(r"[a-z][A-Z]|[A-Z]{2}[a-z]")
# PGPASSWORD is libpq's, read from the environment of the command it
# prefixes: PGPASSWORD=... psql -c 'DROP TABLE users'.
_SECRET_NAMES = frozenset(("database_url", "redis_url", "mongodb_uri",
                           "postgres_url", "db_password", "pgpassword"))


@functools.lru_cache(maxsize=4096)       # every KEY= on a line asks
def _names_a_secret(key):
    if key.lower() in _SECRET_NAMES:
        return True
    words = [w.lower() for w in _NAME_WORDS.findall(key)]
    if _PUBLIC_WORDS.intersection(words):
        return False
    while words and words[-1].isdigit():
        words.pop()                               # API_KEY_2
    if len(words) > 1 and words[-1] == "base":
        words.pop()                               # Rails' SECRET_KEY_BASE
    if not words:
        return False
    if (words[-1] in ("token", "tokens") and len(words) > 1
            and (words[-2] in _CURSOR_KINDS_OF_TOKEN or _CLIENT_TOKEN.search(key))):
        return False
    if words[-1] == "tokens" and len(words) > 1 and _MIXED_CASE.search(key):
        return False                              # maxTokens, reasoningTokens: counts
    if words[-1] in _SECRET_LAST_WORDS:
        return True
    return (words[-1] in ("key", "keys") and len(words) > 1
            and words[-2] in _SECRET_KINDS_OF_KEY)

class _Span(object):
    """A match that is not a regex's: the span, and group(0) for the text
    in it."""

    def __init__(self, text, start, end):
        self._text, self._start, self._end = text, start, end

    def start(self):
        return self._start

    def end(self):
        return self._end

    def group(self, _index=0):
        return self._text[self._start:self._end]


_B64URL_RUN = re.compile(r"[A-Za-z0-9_-]*")


class _Shape(object):
    """A shape that is not one regex: search(text, pos) is its own, and
    finditer() walks the matches the way a compiled regex's does."""

    def finditer(self, text, pos=0):
        while True:
            m = self.search(text, pos)
            if not m:
                return
            yield m
            pos = m.end()


class _JsonWebToken(_Shape):
    """A JWT, tried once per run of base64url.

    As one regex every eyJ read its run to the end looking for the dot after
    the first part, so a megabyte of "eyJ" took minutes. A later eyJ in the
    same run reads the same run to the same end, and the rest of the token
    is the same text, so when the first eyJ in a run starts no token, none
    after it in that run does."""

    pattern = (r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\."
               r"[A-Za-z0-9_-]{10,}")

    def __init__(self):
        self._token = re.compile(self.pattern)

    def search(self, text, pos=0):
        while True:
            at = text.find("eyJ", pos)
            if at == -1:
                return None
            m = self._token.match(text, at)
            if m:
                return m
            pos = _B64URL_RUN.match(text, at).end()


class _PrivateKey(_Shape):
    """A PEM private key: its BEGIN line, and the first END line after it.

    As one regex every BEGIN with no END after it read on to the end of the
    text, and a megabyte of BEGIN lines took minutes. With no END after the
    first BEGIN there is none after any later one either."""

    pattern = (r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]+?"
               r"-----END [A-Z ]*PRIVATE KEY-----")
    _BEGIN = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
    _END = re.compile(r"-----END [A-Z ]*PRIVATE KEY-----")

    def search(self, text, pos=0):
        begin = self._BEGIN.search(text, pos)
        if not begin:
            return None
        end = self._END.search(text, begin.end() + 1)
        return _Span(text, begin.start(), end.end()) if end else None


# Credential shapes that are secrets wherever they appear.
# Each shape is named, because "credential" tells you nothing about where to
# go and roll it. Each has search() and finditer(), as a compiled regex does.
_SHAPES_NAMED = [
    (re.compile(r"sk_live_[A-Za-z0-9]{12,}"), "Stripe live secret key"),
    (re.compile(r"rk_live_[A-Za-z0-9]{12,}"), "Stripe restricted key"),
    (re.compile(r"sk-[A-Za-z0-9_-]{20,}"), "OpenAI/Anthropic-style API key"),
    (re.compile(r"ghp_[A-Za-z0-9]{28,}"), "GitHub personal access token"),
    # `gh auth token` prints a gho_ token; an Actions job's GITHUB_TOKEN is
    # a ghs_ one.
    (re.compile(r"gho_[A-Za-z0-9]{36,}"), "GitHub OAuth token"),
    (re.compile(r"ghu_[A-Za-z0-9]{36,}"), "GitHub App user token"),
    (re.compile(r"ghs_[A-Za-z0-9]{36,}"), "GitHub App installation token"),
    (re.compile(r"ghr_[A-Za-z0-9]{36,}"), "GitHub refresh token"),
    (re.compile(r"github_pat_[A-Za-z0-9_]{40,}"), "GitHub fine-grained token"),
    (re.compile(r"xox[baprs]-[A-Za-z0-9-]{20,}"), "Slack token"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS access key ID"),
    (re.compile(r"ASIA[0-9A-Z]{16}"), "AWS temporary access key"),
    (re.compile(r"AC[0-9a-f]{32}"), "Twilio account SID"),
    (re.compile(r"SG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}"), "SendGrid API key"),
    (_PrivateKey(), "private key"),
    (_JsonWebToken(), "JSON Web Token"),
]

_SHAPES = [pattern for pattern, _name in _SHAPES_NAMED]
# A literal every match of each shape holds. A shape is looked for only in
# text that holds its mark: sixteen regex passes over every string worth
# scanning were most of what masking a command cost.
_SHAPE_MARKS = {
    "Stripe live secret key": "sk_live_", "Stripe restricted key": "rk_live_",
    "OpenAI/Anthropic-style API key": "sk-", "GitHub personal access token": "ghp_",
    "GitHub OAuth token": "gho_", "GitHub App user token": "ghu_",
    "GitHub App installation token": "ghs_", "GitHub refresh token": "ghr_",
    "GitHub fine-grained token": "github_pat_", "Slack token": "xox",
    "AWS access key ID": "AKIA", "AWS temporary access key": "ASIA",
    "Twilio account SID": "AC", "SendGrid API key": "SG.",
    "private key": "-----BEGIN ", "JSON Web Token": "eyJ",
}

# KEY=value / "key": "value" assignments.
#
# Tool output is often JSON held in a string ({"stdout": "KEY=...\nKEY=..."}),
# so once the transcript line is decoded its escapes are still two
# characters. A value stops at \n \r \t \" and \\ as it would at the
# character they stand for, a key starts after the escape and not on its
# letter (\nDB_PASSWORD is DB_PASSWORD), and \" quotes like ".
#
# A key starts only where a run of identifier characters does. Tried at
# every letter, each start read to the end of the run: 20,000 characters of
# hex took a second, and 200,000 of mixed case four and a half minutes.
#
# A ) does not end a value: Django draws its keys from an alphabet with
# both parentheses in it. One that closes a ( opened before the value,
# (export TOKEN=x) or f(password=x), is taken off it by _value_end.
#
# A name followed by :: is qualified (Aws::Credentials::Shared, Token::new),
# not given a value: read as one, the second colon started a value of code.
_KEY_START = r"(?:(?<![A-Za-z0-9_])(?!(?<=\\)[nrt])|(?<=\\[nrt]))[0-9]*"
_SEPARATOR = r"(?:=|:(?!:))"
_ASSIGN = re.compile(
    r"""(\\?["']|)""" + _KEY_START + r"""([A-Za-z_][A-Za-z0-9_]*)\1\s*"""
    + _SEPARATOR + r"""\s*"""
    r"""(\\?["']|)((?:[^\s"',;}\\]|\\(?![nrt"\\])){8,})\3""")

# _ASSIGN has no literal start, so a search for it tried a match at every
# character of a text: 13.9 seconds of a 31.2 second clean pass, and the
# slow half of watch's literal rule. A match's key, quotes and blanks hold
# no = or :, so its separator is the first one at or after its start, and
# it starts no earlier than the run of blanks, quotes and key characters
# before that separator. _assign_search tries the regex only there: its
# key part (_KEY_PART, up to and with the separator) is looked for in that
# run, read backwards from the separator (_KEY_BACK) no further than
# _KEY_BACK_MOST, and each place it starts is confirmed by _ASSIGN itself.
# Where separators are closer together than _SEPARATORS_CLOSE, the regex
# alone is faster: tried at every separator, a megabyte of : took nine
# times as long.
_KEY_PART = re.compile(r"""(\\?["']|)""" + _KEY_START
                       + r"""([A-Za-z_][A-Za-z0-9_]*)\1\s*""" + _SEPARATOR)
_KEY_BACK = re.compile(r"""\s*(?:["']\\?)?[A-Za-z0-9_]*(?:["']\\?)?""")
_KEY_BACK_MOST = 256
_SEPARATORS_CLOSE = 16


def _assign_search(text, pos, nxt):
    """_ASSIGN.search(text, pos), with the regex tried only where a match
    can start. `nxt` is where the next = and the next : are, [-2, -2] to
    begin with, for one text searched from positions that only grow."""
    while True:
        for i, ch in enumerate("=:"):
            if nxt[i] != -1 and nxt[i] < pos:
                nxt[i] = text.find(ch, pos)
        live = [j for j in nxt if j != -1]
        if not live:
            return None
        j = min(live)
        if j - pos < _SEPARATORS_CLOSE:
            return _ASSIGN.search(text, pos)
        lo = max(pos, j - _KEY_BACK_MOST)
        run = _KEY_BACK.match(text[lo:j][::-1]).end()
        start = pos if (run == j - lo and lo > pos) else j - run
        k = _KEY_PART.search(text, start, j + 1)
        while k:
            m = _ASSIGN.match(text, k.start())
            if m:
                return m
            k = _KEY_PART.search(text, k.start() + 1, j + 1)
        pos = j + 1


# A password embedded in a connection string.
#
# A scheme is tried once per run of scheme characters, from its first
# letter. Tried from every letter, each try read to the end of the run: a
# megabyte of hex after a colon took minutes. "://" can only follow the end
# of a run, so a later start in the same run finds nothing an earlier one
# did not.
_CONN = re.compile(r"(?<![a-z0-9+.-])[0-9+.-]*"
                   r"(?P<pre>[a-z][a-z0-9+.-]*://[^:/\s]+:)(?P<secret>[^@\s/]{4,})(?P<post>@)")

# Values that are deliberately not real, and templates for one: Python's
# %(DB_PASSWORD)s as much as ${DB_PASSWORD} and {{ db_password }}. A
# variable's name in capitals may hold a digit ($NPM_TOKEN2).
_PLACEHOLDER = re.compile(
    r"^(?:<[^>]*>|\{\{.*\}\}|\$\{?[A-Z_]+\}?|(?-i:\$\{?[A-Z_][A-Z0-9_]*\}?)|"
    r"%\([A-Za-z_][A-Za-z0-9_]*\)[a-z]|"
    r"x{3,}|\*{3,}|\.{3,}|-+|"
    r"none|null|true|false|undefined|redacted|secret|password|todo|fixme|"
    r"ranwhat:redacted:[0-9a-f]+)$",
    re.I)
# A placeholder phrase: one of these words, then a separator and anything
# (your-api-key-here, sample-api-key-abcdef123456), or right after it more
# words, a version or a short number (changeme123, exampleSecretValue123).
# Only a word: one hex secret in 4,096 starts with "add", and any base62
# one can start with "Test", and what follows those is no word and no
# separator.
_PLACEHOLDER_WORD = re.compile(
    r"(?:changeme|change[-_]me|your|placeholder|example|sample|test|dummy|"
    r"insert|replace|enter|add)(?=[-_ ]?[\w-]*$)", re.I)
_PHRASE_BREAK = re.compile(r"[-_ ]+")
_TRAILING_NUMBER = re.compile(r"[0-9]{1,8}$")
# The number typed after a phrase of words is a count from one (or nought)
# as often as it is a short one: my_super_secret_key_12345.
_COUNTING = frozenset(digits[:n] for digits in ("1234567890", "0123456789")
                      for n in range(5, 11))

# A phrase put where a secret goes, made only of words: the words name a
# secret and nothing else (super-secret-key, my-secret-password), or among
# three or more of them some say it is not one (django-insecure-change-me,
# dev-secret-key-not-for-production). Words alone are not enough: a
# passphrase is words, and so may be a key a proxy lets its users choose.
# So a word that only describes a value as no secret counts beside one
# that names a secret, or a provider's prefix (fake-jwt-secret,
# sk-ant-FAKE-TEST-LOCAL), while acme-example-prod and Unsafe-Harbor-Lights
# are somebody's password. A word that tells someone to put a secret there
# (changeme, placeholder) counts alone, and so does Django's own prefix
# for a key it made up for development, django-insecure-.
_SECRET_NAMING_WORDS = frozenset((
    "my", "your", "our", "the", "a", "super", "very", "secret", "secrets",
    "key", "password", "pass", "passwd", "token", "api", "app", "jwt",
    "session", "signing", "auth", "private", "encryption", "master"))
_SECRET_NOUNS = _SECRET_NAMING_WORDS - {"my", "your", "our", "the", "a", "super",
                                         "very"}
_NOT_A_SECRET_WORDS = frozenset((
    "insecure", "unsafe", "example", "sample", "dummy", "fake"))
# A phrase that starts with whose secret it is and ends naming one stands
# in for it, whatever is between: my-idp-secret in an example's
# clientSecret. "Do not" beside a word that names a secret says it is
# none: React's SECRET_DO_NOT_PASS_THIS_OR_YOU_WILL_BE_FIRED.
_POSSESSIVES = frozenset(("my", "your", "our"))
_PUT_A_SECRET_HERE = frozenset(("changeme", "placeholder", "notsecret"))
# The prefixes providers put on a key, read as the first word of a phrase.
_KEY_PREFIXES = frozenset(("sk", "rk", "pk", "ghp", "gho", "ghu", "ghs", "ghr",
                           "xoxb", "xoxp", "xoxa", "xoxr", "xoxs", "glpat", "npm"))
_NOT_A_SECRET_RUNS = (("change", "me"), ("replace", "me"), ("not", "for", "production"),
                      ("not", "for", "prod"), ("do", "not", "use"), ("not", "a", "secret"),
                      ("not", "secret"))


# A string can only hold a secret if it has an assignment, a connection
# string, a known credential prefix, or a command that takes a password
# (_TYPED: each rule's marker holds one of these, or it never runs). Most
# of a transcript is prose, and checking this first skips the regex
# battery on the overwhelming majority.
# Every shape in _SHAPES_NAMED must start with one of these, or text holding
# only that shape is never scanned (tests/test_clean_shapes.py checks).
_CHEAP = ("=", ":", "sk_", "rk_", "sk-", "ghp_", "gho_", "ghu_", "ghs_", "ghr_",
          "github_pat_", "xox", "AKIA", "ASIA", "AC", "SG.", "eyJ", "BEGIN",
          "mysql", "mariadb", "sshpass", "redis-cli", "-password", "docker login",
          "sqlcmd", "mongo", "ldap", "htpasswd", "storepass", "keypass",
          "SecureString", "smb", "rpcclient")

# A single string longer than this is a data blob -- a build log, a base64
# payload, a file dump. Secrets in the first megabyte are still found.
MAX_STRING = 1_000_000


# For a short string one regex pass asks for every token at once, in a
# fifth of the time; over a long one each token's own search is faster.
_CHEAP_ANY = re.compile("|".join(map(re.escape, _CHEAP)))
_CHEAP_SHORT = 256


def _worth_scanning(text):
    if len(text) < _CHEAP_SHORT:
        return _CHEAP_ANY.search(text) is not None
    return any(token in text for token in _CHEAP)


# Claude Code names a project directory by flattening its path with dashes,
# which is ambiguous the moment a directory name contains one: the slug
# -Users-me-Desktop-birthday-planner could be .../birthday-planner or
# .../birthday/planner. Resolved by asking the filesystem.
#
# On Windows the colon and backslash after the drive flatten too, so
# C:\Users\me\app arrives as C--Users-me-app.
_DRIVE_SLUG = re.compile(r"([A-Za-z])--(.*)")


def project_path(slug):
    drive = _DRIVE_SLUG.fullmatch(slug) if os.name == "nt" else None
    if drive:
        path, rest = drive.group(1) + ":" + os.path.sep, drive.group(2)
    elif slug.startswith("-"):
        path, rest = os.path.sep, slug[1:]
    else:
        return slug
    parts = rest.split("-")
    i = 0
    while i < len(parts):
        for take in range(len(parts) - i, 0, -1):
            candidate = os.path.join(path, "-".join(parts[i:i + take]))
            if os.path.isdir(candidate):
                path = candidate
                i += take
                break
        else:
            # Past the part that exists on this machine, the remainder is
            # most likely one directory name that happens to contain dashes.
            path = os.path.join(path, "-".join(parts[i:]))
            break
    return path


# Paths whose contents are credentials, used to attribute a secret to the
# file it was read out of. The text scanned is a raw JSONL line, so JSON's
# escapes are part of it: \\ is a Windows separator, and \n \t \" \uXXXX end
# the previous token.
#
# A wrong origin is worse than none, and code is full of names that look like
# credential files: os.environ, process.env.KEY, d.key, id_token,
# load_credentials. So every token needs a boundary on both sides, and the
# shapes code can also produce (bare x.key, bare "credentials") are only taken
# when something says they are files: a directory part, a quote around them,
# or a command or flag in front.
#
# Linearity, since Python 3.9 has no atomic groups: the left boundary lets a
# match start only at the first character of a run, and a stem quantifier
# ([\w.-]*) never shares an alternative with a suffix loop ((?:[.-]\w+)*).
# Nesting the two made "a/" + "b.env-c" * 7000 take five seconds.
_SEP = r"(?:/|\\\\|\\(?![nrt\"\\]|u[0-9a-fA-F]{4}))"
_LB = (r"(?:(?<![\w.$~/\\{}%-])"
       r"|(?<=(?<!\\)\\[nrt\"])|(?<=(?<!\\)\\u[0-9a-fA-F]{4})"
       r"|(?<=[\s\"'=]-[A-Za-z]))")          # ssh -i/home/u/.ssh/id_rsa
_RB = r"(?![\w/(-]|\.\w|\\\\|\\(?![nrt\"\\]|u[0-9a-fA-F]{4}))"
_DATA_EXT = r"(?:json|ya?ml|csv|ini|toml|txt|xml|conf|cfg|properties|db)"
_BACKUP = r"(?:\.(?:bak|old|orig|backup|enc)|~)?"   # a copy holds the same secret
_ENV_FILE = r"\.env(?:rc)?(?:[.-]\w+)*"
_SSH = r"id_(?:rsa|dsa|ecdsa|ed25519)"
_READER = (r"(?:(?:cat|less|more|head|tail|bat|type|vim?|nano)\s+"
           r"|-{1,2}\w[\w-]*[\s=]|<\s*)")
_ORIGIN = re.compile(_LB + r"(?P<path>"
    # with a directory part: attribute access never has a separator
    r"(?!-)(?:[A-Za-z]:)?(?:[\w.~${}%-]*" + _SEP + r")+(?:"
        + _ENV_FILE +
        r"|[\w.-]*\.env(?:rc)?"                   # secrets.env
        r"|(?:[\w.-]*credentials(?:\." + _DATA_EXT + r")?"
        r"|\.netrc|" + _SSH + r"(?:[_-][\w-]*)?(?:\.pub)?"
        r"|[\w.-]+\.(?:pem|key))" + _BACKUP +
    r")"
    # bare names: only shapes an identifier cannot take
    r"|" + _ENV_FILE +
    r"|(?:\.[\w-]+credentials(?:\." + _DATA_EXT + r")?"   # .git-credentials
    r"|[\w.-]*credentials\." + _DATA_EXT +
    r"|\.netrc|" + _SSH + r"(?:_sk)?(?:-cert)?(?:\.pub)?"
    r"|[\w.]*-[\w.-]*\.(?:pem|key)"                    # my-ec2-key.pem
    r"|(?<=['\"`])[\w.-]+\.(?:pem|key)" + _BACKUP + r"(?=\\?['\"`])"
    r")" + _BACKUP +
    # server.key is also what attribute access looks like; a reading
    # command or a flag in front of it says it is a file
    r"|" + _READER + r"(?P<bare>[\w.-]+\.(?:pem|key)" + _BACKUP + r")"
    r")" + _RB, re.I)


# Every branch of the pattern requires one of these literals, so for ASCII
# text a substring test that finds none proves the regex cannot match, in
# linear time and in C. (Under re.I two Turkish i's fold to "i" and lower()
# does not map them, so a homoglyph "İd_rsa" goes without an origin.)
# Agent transcripts are mostly prose, and a 39MB file took 59 seconds before
# this check existed.
_ORIGIN_MARKERS = (".env", "credential", ".netrc", "id_", ".pem", ".key")

# templates and public keys: named like credential files, holding none
_NOT_SECRET = (".example", ".sample", ".template", ".tmpl", ".dist",
               ".defaults", ".schema", ".pub")
_SOURCE_EXT = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".py", ".rb",
               ".go", ".rs", ".java", ".php", ".md", ".map")
_BACKUP_TAIL = re.compile(r"(?:\.(?:bak|old|orig|backup|enc)|~)$", re.I)
_ENV_VAR_NAME = re.compile(r"^\.env\.[A-Z][A-Z0-9_]*$")   # config .env.API_KEY
_WIN_ROOT = re.compile(r"(?:[A-Za-z]:|%\w+%|\.{1,2}|~|\$\{?\w+\}?)\\")
_VENV_BEFORE = re.compile(r"(?:venv|virtualenv)\s+$")     # a directory named .env


def _origins(text):
    if not text:
        return []
    lowered = text.lower()
    if not any(marker in lowered for marker in _ORIGIN_MARKERS):
        return []
    out = []
    for m in _ORIGIN.finditer(text):
        name = "bare" if m.group("bare") else "path"
        v, start = m.group(name), m.start(name)
        before = lowered[max(0, start - 12):start]
        if before.endswith(("http:", "https:")) or _VENV_BEFORE.search(before):
            continue
        v = v.replace("\\\\", "\\")
        # Deno\.env in a regex is an escaped dot, not a Windows path. A real
        # one starts at a root (C:, %USERPROFILE%, .) or goes deeper, and
        # never doubles its separator (that is a string literal in source).
        if "\\\\" in v or ("\\" in v and "/" not in v and v.count("\\") < 2
                             and not _WIN_ROOT.match(v)):
            continue
        parts = re.split(r"[/\\]", v)
        base = _BACKUP_TAIL.sub("", parts[-1]).lower()
        if base.endswith(_NOT_SECRET + _SOURCE_EXT):
            continue
        if _ENV_VAR_NAME.match(parts[-1]) or base in ("process.env", "meta.env"):
            continue
        # Extensionless "credentials" is a file under a dot-directory
        # (~/.aws/credentials). Anywhere else it is an import or a route.
        if base == "credentials" and not (
                len(parts) > 1 and re.match(r"\.\w", parts[-2])):
            continue
        out.append(v)
    return out


def _fingerprint(value):
    return hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:12]


_KEY_ID = re.compile(r"(?:AKIA|ASIA)[0-9A-Z]{16}")


def _hint(value):
    """What a finding looks like on screen: enough to recognise it, never
    enough to use it. A fixed 3+2 characters gave away 5 of an 11-character
    password and showed nothing at all at 10, so the budget is a sixth of
    the value, and below 8 characters (which the length beside it already
    narrows) nothing. Never the fingerprint: for a short human-chosen
    password that hash is a dictionary oracle.

    AWS key IDs are the exception. A sixth of one is its fixed prefix, so
    every key ID showed as AK…B, and a key ID is no secret without the
    secret key beside it. It shows the prefix and the last four, the same
    four `aws configure list` shows."""
    if _KEY_ID.fullmatch(value):
        return value[:4] + "…" + value[-4:]
    n = len(value)
    if n < 8:
        return "•" * 3
    k = min(5, max(1, n // 6))
    head = (k + 1) // 2 if k > 1 else 1
    tail = k - head
    return value[:head] + "…" + (value[-tail:] if tail else "")


# A secret is a literal. These are all things that merely *refer* to one, or
# compute one, or describe one -- and on a working machine they outnumbered
# real credentials roughly two to one.
#
# A parenthesis is code only in a call: a name joined by dots or by ::,
# its (, and nothing after but names, digits and more calls
# (os.environ.get( cut at its quote, std::env::var(, Config::get(,
# get_random_secret_key(), base64.b64encode(os.urandom(32))), or a
# command substitution, $( and a command's name. Anywhere else it is a
# character a generator drew, and most Django keys hold one.
_CODE = re.compile(r"[{}\[\]`<>|\\]|=>|\$\{")
_CALLED = r"(?:::)?[A-Za-z_$][\w$]*(?:(?:\.|::)[A-Za-z_$][\w$]*)*"
_CALL = re.compile(r"^(?:\$\([\w./-]*(?:\s|$)"
                   r"|\(*" + _CALLED + r"\([\w$.()=:/]*$"
                   r"|\(+" + _CALLED + r"\)*$)")
# And a call whose arguments are an expression: names and numbers, quoted
# strings and more calls, joined by operators, as compact and minified code
# writes them: hashlib.sha256(data+salt).hexdigest(), o(e.code+t),
# Buffer.from(a+b).toString( cut at its quote, load_key(path+ cut at one,
# or such an expression in parentheses, (e+t).slice(0).
# Read as a run of tokens, each where the one before allows it, from the
# first ( to the end of the value. A generated value holds operators too,
# but seldom all of it in that order, and its runs of letters and digits
# almost never read as names (_is_call_expression). Of 400,000 random
# 20-character passwords drawn with symbols, 22 read as such a call, where
# 5,177 already read as the plain call above; of 400,000 Django keys, none.
_OPERAND_NAME = r"[A-Za-z_$][\w$]*(?:(?:\?\.|\.|::)[A-Za-z_$][\w$]*)*"
_LITERAL = r"""(?:[0-9]+(?:\.[0-9]+)?(?![\w$])|'[^'\n]*'|"[^"\n]*")"""
_OPERATOR = r"(?: ?(?:\*\*|//|==|\?\?|&&|[-+*/%,=:?]) ?)"
_OPENS = r"[!-]?(?:" + _OPERAND_NAME + r")?\("                  # ( or f(
_OPERAND = (r"(?:[!-]?(?:" + _OPERAND_NAME + r"(?![\w$(])|" + _LITERAL
            + r")|\))")                                         # or the ) of f()
_CLOSES = r"\)(?:\." + _OPERAND_NAME + r"(?![\w$(]))?"           # ) or ).name
_JOINS = r"(?:" + _OPERATOR + r"|\)\." + _OPERAND_NAME + r"\()"  # + or ).f(
_CALL_EXPRESSION = re.compile(
    # f( or (a+b).f(. One ( and no more: _OPENS reads the rest, and two
    # ways to read a run of them made a megabyte of ( take minutes.
    r"(?:\(*" + _CALLED + r"\(|\()"
    r"(?:(?:%s)*%s(?:%s)*%s)*(?:%s)*(?:%s(?:%s)*)?\Z"
    % (_OPENS, _OPERAND, _CLOSES, _JOINS, _OPENS, _OPERAND, _CLOSES))
_CALL_NAME = re.compile(r"[A-Za-z_$][\w$]*")
# A value is cut at a blank, a comma or a semicolon, so such a call is
# short. Read whole, a megabyte of f(a(a(... took a tenth of a second
# more than main took to call it code at its first (.
_CALL_LONGEST = 512
_DIGITS_TWICE = re.compile(r"[0-9][A-Za-z_$]+[0-9]")
# Where a secret store keeps one is a reference too: a Vault path
# (vault:secret/data/app#key), a 1Password one (op://vault/item/field), an
# ARN, a Parameter Store or Secrets Manager name, or an Azure App Service
# setting's Key Vault or App Configuration reference
# (@Microsoft.KeyVault(SecretUri=...), @Microsoft.AppConfiguration(...)).
_REFERENCE = re.compile(
    r"^(?:process\.env|os\.environ|import\.meta|this\.|self\.|window\.|"
    r"globalThis\.|config\.|env\.|Deno\.env|ENV\[|"
    r"vault:|op://|arn:|ssm:|secretsmanager:|aws-?sm:|gcp-?sm:|azure-?kv:|"
    r"keyvault:|@Microsoft\.(?:KeyVault|AppConfiguration)\()", re.I)
# Where a path starts: the root, ./ or ../, a home (~/, ~deploy/), a drive,
# or a variable that holds a directory ($HOME/, ${HOME}/, %APPDATA%\).
_PATHLIKE = re.compile(
    r"^(?:\.{0,2}/|~[\w.-]*/|[A-Za-z]:[\\/]|\$\{?\w+\}?[\\/]|%\w+%[\\/])")
# A path relative to wherever it is read: names joined by / or \.
_RELATIVE_PATH = re.compile(r"^[\w.-]+(?:[\\/][\w.-]+)+[\\/]?$")
_PATH_SEPARATOR = re.compile(r"[\\/]")
# A file's own name, with or without a directory: keys/jwtRS256.key,
# service-account.json. No generated value ends in one of these.
_FILE_NAME = re.compile(
    r"^(?:[\w.-]+[\\/])*[\w.-]+\.(?:json|ya?ml|pem|key|crt|cer|der|p8|p12|pfx|"
    r"jks|keystore|txt|env|ini|toml|cfg|conf|properties|asc|gpg|pub|enc|db|"
    r"sqlite|kdbx)$", re.I)
_REGEXISH = re.compile(r"\.\*|\\[dwsb]|\{\d+(?:,\d*)?\}|\[[A-Za-z0-9-]+\]")
_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_DIGIT = re.compile(r"[0-9]")
# Only ever searched, so the shortest stretch of each says the same as
# any longer one, and in a sixth of the time. Three asterisks inside a long
# value are not enough: Django draws its keys from an alphabet with * in
# it, and one key in two thousand has three in a row. A display of a key
# (abcd***wxyz) is short; _looks_computed reads those.
_MASKED = re.compile(r"^\*\*\*|\*\*\*$|\*\*\*\*|xxxxxx|\u2026|______")
_SHORT_DISPLAY = 40
# Three dots at either end of a short stretch are a value cut short to show
# it, or to stand in for it: django-insecure-..., sk-proj-abc..., ...a8f3c2e9.
# After a longer one they are most of a secret, and it is still one: 31
# characters of an AWS secret key leave 9 to guess.
_CUT = re.compile(r"^\.{3,}[^.]|[^.]\.{3,}$")
_CUT_SHOWN = 16


try:
    from _collections import _count_elements   # what Counter counts with, in C
except ImportError:                              # pragma: no cover
    def _count_elements(mapping, iterable):
        for item in iterable:
            mapping[item] = mapping.get(item, 0) + 1


@functools.lru_cache(maxsize=64)
def _entropy_terms(n):
    """(c / n) * log2(c / n) for every count c in a value of length n, worked
    out as _entropy always has, so a sum of them is the same to the bit."""
    n = float(n)
    return [0.0] + [(c / n) * math.log(c / n, 2) for c in range(1, int(n) + 1)]


def _entropy(value):
    """Shannon entropy per character. Generated credentials sit well above
    three bits; words, names and code sit below. The terms for a length are
    worked out once: a megabyte of values each worked them out again."""
    if not value:
        return 0.0
    counts = {}
    _count_elements(counts, value)
    counts = counts.values()
    if len(value) > 4096:
        n = float(len(value))
        return -sum((c / n) * math.log(c / n, 2) for c in counts)
    return -sum(map(_entropy_terms(len(value)).__getitem__, counts))


# An AWS secret key is 40 characters of base64, so one in 64 starts with a
# slash and reads as an absolute path. What tells them apart is the run. A
# path is a chain of names, and a name is written in one case (usr, v1, a
# hex digest) or in whole words (Desktop, SanDisk128GB). A generated key
# flips between upper case, lower case and digits every character or two,
# and never holds a dot, a dash or an underscore.
_BASE64_PATH = re.compile(r"^/[A-Za-z0-9+/=]+$")
_NAME_PART = re.compile(r"[A-Z]?[a-z]+|[A-Z]+(?![a-z])|[0-9]+|[^A-Za-z0-9]")
# Characters that must read as generated before a slash value is a key.
# Measured: it misses about 1 in 2,200 random slash keys, and reads none of
# the 6,241 paths on a working Mac spelled only in these characters as one.
_GENERATED_MIN = 16


def _reads_as_name(segment):
    if segment == segment.lower() or segment == segment.upper():
        return True
    per_part = len(segment) / len(_NAME_PART.findall(segment))
    # A long name is a few long words. A random run that long averages three
    # characters a part now and then, and three and a half all but never.
    return per_part >= (3.5 if len(segment) >= 16 else 3.0)


def _generated_not_path(value):
    if not _BASE64_PATH.match(value):
        return False
    generated = sum(len(s) for s in value.split("/") if not _reads_as_name(s))
    return generated >= _GENERATED_MIN


# Asked of every value, so each set is one regex: code, a pattern or a
# masked stretch anywhere in it, and a call or a reference at its start.
_ANYWHERE = re.compile("|".join(p.pattern for p in (_CODE, _REGEXISH, _MASKED)))
_AT_START = re.compile("(?:%s)|(?:%s)" % (_CALL.pattern, _REFERENCE.pattern), re.I)


def _is_path(v):
    """Where a secret is kept, rather than the secret. A rooted path is
    one unless it is base64 that starts with a slash; a relative one has
    names in it, or ends in a file's name. GOOGLE_APPLICATION_CREDENTIALS is
    most often relative, and only absolute, ./ and ~/ were seen as paths."""
    if _PATHLIKE.match(v):
        return not _generated_not_path(v)
    if "." not in v and "/" not in v and "\\" not in v:
        return False
    if _FILE_NAME.match(v):
        return True
    # Base64 holds a slash too, but never a dot, a dash and an underscore
    # beside it, and its runs flip case where a directory's name does not.
    return bool(_RELATIVE_PATH.match(v)) and (
        any(c in v for c in "._-")
        or all(_reads_as_name(part) for part in _PATH_SEPARATOR.split(v) if part))


def _looks_computed(value):
    """True when the value is code, a reference, a path or a pattern rather
    than a literal credential."""
    v = value.strip().strip("\"'")
    if _ANYWHERE.search(v) or _AT_START.match(v) or _is_path(v):
        return True
    if len(v) < _SHORT_DISPLAY and "***" in v:
        return True               # what code prints of a key: abcd***wxyz
    return _reads_as_variable(v)


def _is_call_expression(v):
    """Whether v is a call whose arguments are code (_CALL_EXPRESSION), every
    name in it written as a name is: in words (_reads_as_name), with at most
    one run of digits (sha256, b64encode, x509). Django's lower-case keys
    read as names, and break that second rule. In such a call a number
    stands on its own, so two runs of digits with letters between are in
    one name (or in a quoted string, which is let go with it)."""
    return (len(v) <= _CALL_LONGEST and bool(_CALL_EXPRESSION.match(v))
            and not _DIGITS_TWICE.search(v)
            # letters in one case read as names whatever they are
            and (v.islower() or v.isupper()
                 or all(map(_reads_as_name, _CALL_NAME.findall(v)))))


def _reads_as_variable(v):
    """A bare identifier with no digits is a variable name, not a secret, when
    it reads as one: each part in one case or in whole words (API_TOKEN,
    userPassword). Letters a generator drew flip case every character or
    two, and a key with no digit in it is still a key: one Stripe body in
    sixty has none. Not an AWS key ID either: its body is base32, where
    only 6 characters in 32 are digits, so about one in 28 has none."""
    return bool(len(v) < 40 and _IDENTIFIER.match(v) and not _DIGIT.search(v)
                and not _KEY_ID.fullmatch(v)
                and all(_reads_as_name_part(part) for part in v.split("_") if part))


_TITLE_WORD = re.compile(r"[A-Z][a-z]+")
_VOWELS = frozenset("aeiouyAEIOUY")


def _reads_as_name_part(part):
    """_reads_as_name for a part of an identifier, which also reads as one
    when it is one word in title case (My, Db, Id), or words a few letters
    long, each an acronym or holding a vowel (apiKeyForTenantId,
    getAPIKeyForUser). Measured over random letters 16 to 39 long, the
    words let 5.8% read as names where 5.1% did; of 4,590 mixed-case
    names in code, 10 still read as drawn, where 25 did."""
    if _reads_as_name(part) or _TITLE_WORD.fullmatch(part):
        return True
    parts = _NAME_PART.findall(part)
    return (len(part) / len(parts) >= 3.0
            and all(p.isupper() or not _VOWELS.isdisjoint(p) for p in parts))


# `token = args.token`: a variable read off an object, which _REFERENCE only
# knows for a few fixed receivers. Deliberately narrow, because a dotted
# passphrase (password: summer.monkey, Summer.Monkey) has the same letters:
# after the receiver every segment starts lowercase or is a constant, no
# digits, and the attribute must be named for the very thing the key is,
# be named for a secret in words of its own (secret_key_base), or be read
# off a request's headers. A receiver may be capitalised, as Rails and
# Settings are.
_MEMBER_CHAIN = re.compile(r"^[A-Za-z_$][A-Za-z_]*(?:\??\.[a-z_][A-Za-z_]*)*"
                           r"\??\.(?:[a-z_][A-Za-z_]*|[A-Z][A-Z0-9_]*)$")
# A function named by its module path, django.utils.crypto.get_random_string:
# names in lower case, the last a verb and more words. Not any compound
# last word: correct.horse.battery_staple is a passphrase.
_MODULE_PATH = re.compile(
    r"^[a-z_][a-z0-9_]*(?:\.[a-z_][a-z0-9_]*)+\."
    r"(?:get|gen|generate|make|create|new|load|read|fetch|build|random)"
    r"(?:_[a-z]{2,})+$")
_WORDS = re.compile(r"[A-Z]?[a-z]+|[A-Z]+(?![a-z])")
# A constant's name, in capitals and underscores. One that names a secret
# itself (DJANGO_SECRET_KEY, DATABASE_PASSWORD) is code under any key: a
# generator never draws a run of capital words joined by underscores.
_CONSTANT = re.compile(r"[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+")
_SECRET_WORDS = {"token", "secret", "password", "passwd", "pwd", "pass",
                 "key", "apikey", "auth", "authorization", "credential",
                 "credentials", "dsn", "jwt", "bearer"}


def _last_word(name):
    words = _WORDS.findall(name)
    return words[-1].lower() if words else ""


# Under a key in camelCase or PascalCase, which main never read, a name
# read off an object is code more widely. C#, Go and the AWS SDK name a
# property in PascalCase (options.ClientSecret, data.Credentials.
# SecretAccessKey), TypeScript's output imports through index_1 and
# app$1, and minified code reads off e, t or X.prototype. So the receiver
# and every segment may be any name, and the value is code when the last
# names what the key does, word for word, or a secret in a word of its
# own (session.credential), or when a segment is a name a person writes
# in code: in camel or Pascal case and in words (mfaSession, ByteString),
# or an import's alias, or a minified receiver of a letter or two before
# a word. A dotted passphrase is plain words (Summer.Monkey,
# quiet.river.bypass) and stays a literal, and a shape never reads as
# code.
_CODE_CHAIN = re.compile(r"[A-Za-z_$][\w$]*(?:\??\.[A-Za-z_$][\w$]*)+")
_ALIAS = re.compile(r"[A-Za-z_$][A-Za-z$]*(?:_[A-Za-z]+)*(?:_[0-9]+|\$[0-9]+)")
_MINIFIED_RECEIVER = re.compile(r"[a-z_$][a-z0-9_$]?|[A-Z]")
_DIGIT_RUN = re.compile(r"[0-9]+")


def _name_words(name):
    return [w.lower() for w in _NAME_WORDS.findall(name)]


def _written_in_words(name):
    """Whether a name is words a person wrote: each holds a vowel or is a
    short acronym (GCPEnv, EMPTY_BYTE_STRING, prototype), a few letters
    long on average, with no digit. Letters a generator drew flip case
    every character or two, and few of those runs hold a vowel."""
    words = _NAME_WORDS.findall(name)
    return bool(words) and sum(map(len, words)) >= 3 * len(words) and all(
        w.isalpha() and (not _VOWELS.isdisjoint(w) or (w.isupper() and len(w) <= 5))
        for w in words)


def _reads_as_code_name(segment):
    return bool(_ALIAS.fullmatch(segment)
                or (_MIXED_CASE.search(segment) and _written_in_words(segment)))


def _is_camel_member_access(key, value):
    """_is_member_access for a key in camelCase or PascalCase."""
    if value == key:
        return True                   # exports.ChannelCredentials = ChannelCredentials
    if _IDENTIFIER.match(value):
        # A variable named for the key, perhaps with a version in it:
        # recaptchaToken: recaptchaV2Token.
        digits = _DIGIT_RUN.findall(value)
        return bool(len(digits) <= 1 and all(len(d) <= 2 for d in digits)
                    and set(_name_words(key)) <= set(_name_words(value))
                    and _written_in_words(_DIGIT_RUN.sub("", value)))
    if not _CODE_CHAIN.fullmatch(value) or any(p.search(value) for p in _SHAPES):
        return False
    segments = value.replace("?.", ".").split(".")
    attribute = _name_words(segments[-1])
    if attribute == _name_words(key) or (attribute and attribute[-1] in _SECRET_WORDS):
        return True                   # secretAccessKey: creds.SecretAccessKey,
                                      # idToken: session.credential
    if any(map(_reads_as_code_name, segments)):
        return True                   # privateKey: privateKeyResult.value
    return bool(_MINIFIED_RECEIVER.fullmatch(segments[0])
                and any(map(_written_in_words, segments[1:])))


def _is_member_access(key, quote, value):
    if quote or len(value) >= 64:
        return False                  # a quoted string is a literal
    if value[-1:] in (".", ":"):
        value = value[:-1]            # a sentence's stop, or a type's colon
    if _MIXED_CASE.search(key) and _is_camel_member_access(key, value):
        return True
    if not _MEMBER_CHAIN.match(value):
        return False
    if any(p.search(value) for p in _SHAPES):
        return False                  # letters-only JWTs fit the chain too
    segments = value.replace("?.", ".").split(".")
    if segments[-1].lower() == key.lower() or _MODULE_PATH.match(value):
        return True                   # SECRET_KEY = settings.SECRET_KEY
    if _CONSTANT.fullmatch(segments[-1]) and _names_a_secret(segments[-1]):
        return True                   # SECRET_KEY = settings.DJANGO_SECRET_KEY
    if _last_word(key) == "tokens":
        return True                   # inputTokens = usage.input_tokens: a count
    if not any(c.islower() for c in key):
        return False                  # API_TOKEN=args.token is a .env line
    attribute = segments[-1]
    if len(_NAME_WORDS.findall(attribute)) > 1 and _names_a_secret(attribute):
        return True                   # secret_key = app.secret_key_base
    word = _last_word(attribute)
    if word not in _SECRET_WORDS:
        return False                  # whisKEY, PASSport: whole words only
    return word == _last_word(key) or segments[-2].lower() == "headers"


# A private key is judged by its body, not by the text around it. Read out
# of a service-account JSON file, the body is still escaped ("\n" between
# lines), which the code check alone took for code. A stub ("...", "<your
# key>", "xxx") has no body, and one assembled in code (" + body + ") has
# only names. The shortest real body, an Ed25519 key's, is 64 characters of
# base64, and the first 30 or so of any body are a fixed header, so a body
# counts once it holds a generated run of 40.
_PEM = re.compile(r"^-----BEGIN [A-Z ]*PRIVATE KEY-----([\s\S]*)"
                  r"-----END [A-Z ]*PRIVATE KEY-----$")
_LINE_BREAKS = re.compile(r"\s+|\\+[nrt]")
_BASE64_RUN = re.compile(r"[A-Za-z0-9+/=]{40,}")


def _pem_has_body(body):
    for run in _BASE64_RUN.findall(_LINE_BREAKS.sub("", body)):
        if _entropy(run) >= 3.0 and not _MASKED.search(run):
            return True
    return False


def _reads_as_words(part):
    """Letters that read as a name, and perhaps a short number after them."""
    letters = _TRAILING_NUMBER.sub("", part)
    return bool(letters) and letters.isalpha() and _reads_as_name(letters)


def _stand_in_phrase(v, shape=False):
    """A value made only of words, that names a secret or says it is not
    one: see _SECRET_NAMING_WORDS. With shape, v starts with a provider's
    prefix, which names a secret as a word would."""
    parts = [p for p in _PHRASE_BREAK.split(v) if p]
    if (len(parts) > 1 and parts[-1].isdigit()
            and (len(parts[-1]) <= 4 or parts[-1] in _COUNTING)):
        parts.pop()                               # secret-key-2, secret_key_12345
    if len(parts) < 2 or not all(p.isalpha() and _reads_as_name(p) for p in parts):
        return False
    words = [p.lower() for p in parts]
    if set(words) <= _SECRET_NAMING_WORDS:
        return True
    if len(words) < 3:
        return False
    if _PUT_A_SECRET_HERE.intersection(words) or words[:2] == ["django", "insecure"]:
        return True
    if words[0] in _POSSESSIVES and words[-1] in _SECRET_NOUNS:
        return True               # my-idp-secret: one's own secret, in an example
    joined = " %s " % " ".join(words)
    if (_NOT_A_SECRET_WORDS.intersection(words) or " do not " in joined) and (
            shape or words[0] in _KEY_PREFIXES or _SECRET_NOUNS.intersection(words)):
        return True
    return any(" %s " % " ".join(run) in joined for run in _NOT_A_SECRET_RUNS)


def _placeholder_phrase(v):
    m = _PLACEHOLDER_WORD.match(v)
    if m:
        rest = v[m.end():]
        if rest[:1] in ("-", "_", " "):
            return True
        if all(len(part) <= 8 or _reads_as_words(part)
               for part in _PHRASE_BREAK.split(rest)):
            return True
    return _stand_in_phrase(v)


# A format string's verb, or a stand-in, where the value goes:
# token=%s&channel=general, #access_token=...&token_type=bearer. Only
# before the next parameter or the end, since a value drawn from an
# alphabet with % in it (Django's) can start with %s too.
_FORMAT_FIRST = re.compile(r"(?:%[sdrvq]|\.{3,}|\u2026)(?:$|&[A-Za-z_][\w]*=)")
# A verb at the end, with what code fills in after the fixed start:
# 'django-insecure-%s' % get_random_string(50).
_FORMAT_LAST = re.compile(r"%[sdrvqi]$")
# The fixed start of a value that code completes, with what joins the
# rest: DB_PASSWORD= + pw, 'django-insecure-' + key, postgresql://app: +
# password, api_key: + key. Only words come before it.
_UNFINISHED_END = "-_:=/"
_UNFINISHED_PARTS = re.compile(r"[-_.:=/]+")


def _unfinished(v):
    """Whether v is a template, or the start of a value code completes,
    made only of words: nothing in it was drawn."""
    templated = _FORMAT_LAST.search(v)
    if templated:
        v = v[:templated.start()]
    elif v[-1:] not in _UNFINISHED_END:
        return False
    parts = [p for p in _UNFINISHED_PARTS.split(v) if p]
    if not (len(parts) > 1 or templated or v.endswith("://")):
        return False              # one word and an =: base32 padding, too
    # A letter on its own is a name in code (s.secret_key_%s), but in a
    # value that only ends in a separator it may be drawn.
    least = 1 if templated else 2
    return (any(p.isalpha() for p in parts)
            and all(p.isdigit() or (len(p) >= least and p.isalpha() and _reads_as_name(p))
                    for p in parts))


def _is_placeholder(value):
    v = value.strip().strip("\"'")
    pem = _PEM.match(v)
    if pem:
        return not _pem_has_body(pem.group(1))
    if len(v) < 8:
        return True
    if _AT_START.match(v):
        return True                   # a call or a reference, asked early: cheap
    if "(" in v and _is_call_expression(v):
        return True                   # code: sha256(e+t), o(e.code+t)
    if _PLACEHOLDER.match(v) or _placeholder_phrase(v):
        return True
    if _FORMAT_FIRST.match(v) or _unfinished(v):
        return True
    if len(v) <= _CUT_SHOWN + 3 and _CUT.search(v):
        return True                   # cut short to show it: sk-proj-abc...
    if v.startswith("<ranwhat:redacted:"):
        return True
    if len(set(v)) <= 2:                      # aaaaaaaa, ********
        return True
    if _looks_computed(v):
        return True
    return False


def _is_placeholder_shape(value):
    """_is_placeholder for what a shape matched, asking only what can hold
    for one. Every shape but a private key starts with its own prefix and
    holds only letters, digits, _, - and ., so it is never short, a bare
    word, a template, a reference, a path, code or a pattern: of the rest
    only a masked stretch (xoxb-xxxxxx), a name where the key would be
    ("sk_" "live_YOURSTRIPEKEYHERE") and a phrase of words
    (sk-fake-key-example) can hold. A megabyte of distinct AWS key
    IDs asks this 47,000 times. tests/test_clean_shapes.py checks that the
    two agree on every shape."""
    if value.startswith("-----BEGIN"):
        return _is_placeholder(value)
    return (bool(_MASKED.search(value)) or _reads_as_variable(value)
            or (("-" in value or "_" in value) and _stand_in_phrase(value, shape=True)))


# Base64 signatures of image formats. Agent transcripts embed every screenshot
# a user pastes, as strings of several hundred kilobytes. Pixels cannot hold a
# credential in any sense that matters, and long random-looking base64 can
# coincidentally match a token shape, so scanning them only ever produced
# cost and false positives: 4.3 seconds on five screenshots in one file.
_IMAGE_PREFIXES = (
    "iVBORw0KGgo",   # PNG
    "/9j/",          # JPEG
    "R0lGOD",        # GIF
    "UklGR",         # WEBP (RIFF)
    "Qk",            # BMP
)
# No credential shape this module recognises is shorter than this.
_MIN_SECRET_LEN = 16


def _is_embedded_image(text):
    head = text.lstrip()[:16]
    if not head.startswith(_IMAGE_PREFIXES):
        return False
    # A real embedded image is long and contains no whitespace; a short string
    # that merely starts with these letters is still worth scanning.
    return len(text) > 1024 and not any(ch in text[:4096] for ch in " \n\t")


# A number under a key that names tokens in the plural counts them:
# inputTokens, input_tokens, cacheReadTokens, max_tokens.
_NUMBER = re.compile(r"[0-9]+")

# Two words in lower case joined by a hyphen, the way prose and code name a
# kind of thing: same-origin, read-only, fine-grained, cookie-based. A
# passphrase is words too (purple-monkey), so only a pair that says what
# kind: its second word a participle or one of these, or its first one of
# these. A generator never draws two such words.
_COMPOUND = re.compile(r"([a-z]{2,})-([a-z]{2,})")
_KIND_FIRST = frozenset((
    "read", "write", "same", "cross", "not", "non", "self", "auto", "per",
    "pre", "one", "multi", "single", "short", "long", "fine", "coarse",
    "client", "server", "opt"))
_KIND_LAST = frozenset((
    "only", "origin", "side", "level", "wide", "time", "term", "less", "free",
    "safe", "specific", "bound", "aware", "in", "out", "on", "off"))


def _names_a_kind(value):
    m = _COMPOUND.fullmatch(value)
    return bool(m) and (m.group(2).endswith("ed") or m.group(1) in _KIND_FIRST
                        or m.group(2) in _KIND_LAST)


# Minified code compares with no spaces around it, so the rest of == or
# === was read as a value, and ran on past the ) that ends the condition:
# if(cfg.token===undefined)continue gave "==undefined)continue". What is
# compared is a word, a number or a name read off an object, and what
# comes after it is code: the end of the value, ?, && or ||, or a ) and a
# statement. A generated value (one Django key in fifty starts with =)
# never holds a ? or a dot, and only by a fluke a ) and then a keyword.
_OPERAND = (r"!*(?:-?[0-9]+(?:\.[0-9]+)?|[A-Za-z_$][A-Za-z_$]*"
            r"(?:\??\.[A-Za-z_$][A-Za-z_$]*)*(?:\([\w$.,!]*\)?)?)")
_CHAIN = r"[A-Za-z_$][A-Za-z_$]*(?:\??\.[A-Za-z_$][A-Za-z_$]*)+"
_STATEMENT = (r"(?:continue|return|break|throw|if|else|for|while|do|switch|"
              r"case|try|var|let|const|new|delete|typeof|void|await|yield)\b")
_COMPARED = re.compile(
    r"=+" + _OPERAND + r"(?:$|\?|&&|\|\||\)+(?:$|&&|\|\||\?|" + _STATEMENT
    + r"|" + _CHAIN + r"))")
# And an expression of names read off objects: totalTokens =
# e.inputTokens+e.outputTokens, password = u.password??(await ...). Only
# with another such name, a call or a ( after the operator:
# summer.monkey+rain is a passphrase.
_EXPRESSION = re.compile(_CHAIN + r"(?:\?\?|&&|\|\||[?+*%])!*(?:\(|[A-Za-z_$][\w$]*\(|"
                         + _CHAIN + ")")
# Minified code chains assignments (c.setRsaPrivateKey=c.rsa.setPrivateKey=
# function..., a.token=b.token=c(d)), compares and defaults a name read off
# an object (r.skipToken===!0, s.maxTokens??void 0), and tests a bare name
# before one (e&&t?.gitAuth, r?this.opts.token:void). Each starts with a
# dot no generated value holds (Django's alphabet, base64 and hex have
# none) and an operator no passphrase is written with, and every name in
# that start reads as one.
_MINIFIED = re.compile(
    r"(?:" + _CODE_CHAIN.pattern + r"(?:=(?!=)|\?\?|[=!]==?)"
    r"|[A-Za-z_$][\w$]*(?:&&|\|\||\?\?|\?)!*" + _CODE_CHAIN.pattern + r")")


def _is_minified(value):
    m = _MINIFIED.match(value) if "." in value else None
    if not m:
        return False
    names = _CALL_NAME.findall(m.group())
    return (not _DIGITS_TWICE.search(m.group()) and all(map(_reads_as_name, names))
            and any(len(w) >= 3 and w.isalpha() and not _VOWELS.isdisjoint(w)
                    for n in names for w in _NAME_WORDS.findall(n)))


def _is_secret_value(key, quote, value):
    """Whether the value beside a key that names a secret is one. Every
    question here can only say no, so the cheapest that most often does
    is asked first: reading a value as a call costs a hundred times what
    counting its characters does."""
    if _entropy(value) < 3.0 and not any(p.search(value) for p in _SHAPES):
        return False          # prose or a word, not a generated credential
    if _is_placeholder(value):
        return False
    if not quote and (_COMPARED.match(value) or _EXPRESSION.match(value)
                      or _is_minified(value)):
        return False          # code: a comparison, or an expression
    if _NUMBER.fullmatch(value) and _last_word(key) == "tokens":
        return False          # a count of tokens
    if _names_a_kind(value):
        return False          # credentials: 'same-origin'
    if _is_member_access(key, quote, value):
        return False          # code reading a variable, not a literal
    if fixtures.is_fixture(value):
        return False          # a documentation example or a test fixture
    return True


# In a URL's query string a parameter ends at the next one, or at the
# fragment. A token there cannot hold a raw & or #, so this never cuts one.
_QUERY_END = re.compile(r"[&#]")
# The characters _CODE reads as code. None is in a generated value, Django's
# alphabet included, so a value that runs on into one is lost as code.
_CODE_CHAR = re.compile(r"[{}\[\]`<>|\\]")


_PAREN = re.compile(r"[()]")
# A ) right before a : or a ?, or before .name, closes what the value sits
# in: a call or a condition in minified code (t.pendingToken=
# e.pendingToken)):e.oauthToken&&...). No generated alphabet has a : or a
# ? after a ) (Django's has neither), and main ended every value at its
# first ), so a value ends there.
_CLOSED_BEFORE_CODE = re.compile(r"\)+(?=[:?]|\.[A-Za-z_$])")
_URL_WINDOW = 256
_SCHEME_END = "://"


def _in_url(text, at):
    """Whether the # at `at` is in a URL: a scheme's :// before it, with no
    blank or quote between. Looked for through a bounded window, so a long
    value costs no more; a longer URL is read as it always was."""
    lo = max(0, at - _URL_WINDOW)
    scheme = text.rfind(_SCHEME_END, lo, at)
    return scheme != -1 and not _BLANK_OR_QUOTE.search(text, scheme, at)


def _still_open(text, start, end):
    """How many ( between start and end are not closed before end. A count
    of each, taken one from the other, let a ) with no ( before it close
    one opened after it."""
    opened, closed = text.count("(", start, end), text.count(")", start, end)
    if not closed or not opened:
        return opened
    depth = 0
    for m in _PAREN.finditer(text, start, end):
        if m.group() == "(":
            depth += 1
        elif depth:
            depth -= 1
    return depth


def _value_end(text, key_at, start, end):
    """Where the unquoted value of the key at key_at, starting at start,
    ends: at end, or for a query parameter at the next & or #, and short of
    any ) at its end that closes a ( it did not open. That ) may have a
    sentence's stop after it, (password=x)., or markup and code,
    `(export TOKEN=x)` or [(token=x)](y): the value then ends at the ) before
    the first character that reads as code, which no secret holds.
    Searched in place: a copy of the rest of the value for each key, cut
    afterwards, made a query string of short parameters quadratic.

    A URL's fragment holds parameters too: an OAuth implicit grant hands
    the token back as #access_token=...&token_type=bearer."""
    if key_at and (text[key_at - 1] in "?&" or (text[key_at - 1] == "#"
                                                  and _in_url(text, key_at - 1))):
        cut = _QUERY_END.search(text, start, end)
        if cut:
            end = cut.start()
    if text.find(")", start, end) == -1:
        return end
    closed = _CLOSED_BEFORE_CODE.search(text, start, end)
    if closed:
        end = closed.start()
        if text.find(")", start, end) == -1:
            return end
    code = _CODE_CHAR.search(text, start, end)
    if code:
        # Nothing reads on past code, so any ) right before it may close a
        # ( opened before the value, whatever the value holds: a Django key
        # holds a ( as often as a ).
        stop = code.start()
        extra = stop - start
    else:
        stop = end
        while stop > max(start, end - 3) and text[stop - 1] in ".:!?":
            stop -= 1
        extra = text.count(")", start, stop) - text.count("(", start, stop)
    if extra > 0 and text[stop - 1] == ")":
        # Only as many as were opened before it, on its own line, and are
        # still open: a ) closed earlier, 1) or :) or main()), opens none.
        line = max(text.rfind("\n", max(0, start - 256), start) + 1, start - 256)
        extra = min(extra, _still_open(text, line, start))
        if extra > 0:
            end = stop
            while extra > 0 and end > start and text[end - 1] == ")":
                end -= 1
                extra -= 1
    return end


# A key inside the unquoted value of another: grep -rn output
# (api/.env:3:DB_PASSWORD=...), a log prefix (INFO: TOKEN=...), a URL's query
# string (https://x/cb?access_token=...), a header (Cookie: session=...).
#
# Every such key's value ends where the outer one does, so trying _ASSIGN
# again from each key would read "a:" * 500000 half a million times. The
# value is read once more instead, and only a key holding a word that can
# name a secret is looked at: every name _names_a_secret accepts has one.
_INNER_KEY = re.compile(_KEY_START + r"([A-Za-z_][A-Za-z0-9_]*)" + _SEPARATOR)
_SECRET_HINT = re.compile(r"secret|token|pass|pwd|key|auth|credential|dsn|_ur[il]",
                          re.I)
_KEY_CHARS = frozenset(string.ascii_letters + string.digits + "_")


def _in_userinfo(text, start, key_at, value_at, end):
    """https://x-access-token:TOKEN@github.com: the name before the colon is
    a URL's user, and what runs to the @ is its password, which _CONN reads.
    Read as a key, "token" took the host along with the password. Both sides
    are looked at through a bounded window, so a long value costs no more."""
    before = text[max(start, key_at - 256):key_at]
    slashes = before.rfind("//")
    if slashes == -1 or any(c in before[slashes + 2:] for c in "/?#@"):
        return False
    after = text[value_at:min(end, value_at + 256)]
    at = after.find("@")
    return at != -1 and not any(c in after[:at] for c in "/?#")


# An AWS ARN: arn:partition:service:region:account:resource, every part
# split from the next by a colon, the resource often by one too
# (secret:prod/db-AbCdEf). A part may be a CloudFormation ${AWS::Region}.
_ARN = re.compile(r"(?<![\w-])arn:(?:[\w-]|\$\{[^}]*\})*:(?:[\w-]|\$\{[^}]*\})*:")
_BLANK_OR_QUOTE = re.compile(r"[\s\"']")


def _in_arn(text, key_at):
    """Whether the name at key_at is a part of an ARN, as Secrets Manager's
    resource type "secret:" is, rather than a key. Read as one, a secret's
    name was reported as the secret. Looked for before the value it is in,
    since "arn" was the key that value belongs to."""
    at = text.rfind("arn:", max(0, key_at - 256), key_at)
    return (at != -1 and _ARN.match(text, at, key_at) is not None
            and not _BLANK_OR_QUOTE.search(text, at, key_at))


class _Labels(object):
    """The name a finding is shown under: the key beside it, with any
    credential in the key masked the way it is everywhere else. A query
    parameter or a JSON key can hold a token of its own, and the report
    and --json printed GET /cb?ghp_..._token=x with the token whole.

    A key is a name, so only a shape can sit in it, and every shape in the
    text has been found before any key is read. What lies inside the key
    is masked from those. Masking each key by scanning it on its own was a
    scan per key: a megabyte of names holding AWS key IDs took most of a
    second."""

    def __init__(self, text, shapes):
        self._text = text
        self._spans = sorted((at, at + len(value)) for value, _name, at in shapes)
        self._starts = [lo for lo, _hi in self._spans]

    def __call__(self, start, end):
        text, spans = self._text, self._spans
        if end - start < _MIN_SECRET_LEN or not spans:
            return text[start:end]
        inside = []
        i = bisect.bisect_left(self._starts, start)
        while i < len(spans) and spans[i][0] < end:
            lo, hi = spans[i]
            i += 1
            if hi > end:
                continue
            if inside and lo < inside[-1][1]:
                inside[-1][1] = max(inside[-1][1], hi)
            else:
                inside.append([lo, hi])
        out, pos = [], start
        for lo, hi in inside:
            out.append(text[pos:lo])
            out.append(DISPLAY_MASK % _hint(text[lo:hi]))
            pos = hi
        out.append(text[pos:end])
        return "".join(out)


def _inner_secrets(text, start, end, label):
    found = []
    pos = start
    for hint in _SECRET_HINT.finditer(text, start, end):
        at = hint.start()
        if at < pos:
            continue          # inside a key already looked at
        while at > pos and text[at - 1] in _KEY_CHARS:
            at -= 1           # back to the start of the name
        k = _INNER_KEY.match(text, at, end)
        if not k:
            # A word inside a value, not a key. The name it is in has no
            # [:=] after it, so no later word in it can start a key either.
            pos = hint.end()
            continue
        pos = k.end()
        key = k.group(1)
        if not _names_a_secret(key):
            continue
        if text[pos - 1] == ":" and (_in_userinfo(text, start, k.start(1), pos, end)
                                     or _in_arn(text, k.start(1))):
            continue
        stop = _value_end(text, k.start(1), pos, end)
        # Under eight characters is a placeholder (_is_placeholder) whatever
        # it holds, and a query string of short parameters is all of them.
        if stop - pos >= 8 and _is_secret_value(key, "", text[pos:stop]):
            found.append((text[pos:stop], label(k.start(1), k.end(1)), pos))
        if stop == end:
            return found      # the rest of the outer value is this key's
        pos = stop            # the next parameter of a query string
    return found


# A shape ruled a placeholder or a fixture is tried again from just past
# its start (see _found). For a shape with no fixed length, every such
# try inside one run of its characters ends where the first did, after
# reading the whole run again: "xoxb-xxxxxx" * 90909 took minutes. A few
# tries still find a real key glued on behind a fixture.
_RETRIES_TO_ONE_END = 4

# The longest values have every copy of them in the text looked for, for
# deciding what to keep and for masking, until that has read this many
# characters: 500 values in 64K, 32 in a megabyte. Past it a value's copies
# are the ones the scan found it at. One look is a pass over the text, and
# a megabyte of distinct keys asked for 47,000 of them, which took seconds.
_SEARCH_CHARS = 32 * MAX_STRING
# The shortest value a key or a connection string gives (_ASSIGN takes
# eight characters or more, and _is_placeholder calls any shorter one a
# stand-in), and so the shortest value clean returns.
_MIN_ASSIGNED = 8


_KEY_ID_LABELS = frozenset(("AWS access key ID", "AWS temporary access key"))
_ALPHANUMERIC = frozenset(string.ascii_letters + string.digits)


def _glued_letters(text, m):
    """A key ID with no digit after its prefix, inside a longer run of
    letters and digits: a piece of base64 (a wasm blob holds ASIA and
    sixteen capitals now and then), not a key ID, which is written on its
    own. main read every key ID with no digit as a variable's name; one on
    its own is still found, and one with a digit wherever it is."""
    start, end = m.start(), m.end()
    return ((start and text[start - 1] in _ALPHANUMERIC
             or end < len(text) and text[end] in _ALPHANUMERIC)
            and not _DIGIT.search(text, start + 4, end))


def _found(text):
    """[(value, label, start)] for every value the rules accept in text,
    shapes first, then assignments, then connection-string passwords."""
    found = []
    for shape, name in _SHAPES_NAMED:
        mark = _SHAPE_MARKS.get(name, "")      # a shape with none: everywhere
        if mark not in text:
            continue
        pos, last_end, retries = 0, -1, 0
        while pos is not None:
            matches, pos = shape.finditer(text, pos), None
            for m in matches:
                value = m.group(0)
                if not (_is_placeholder_shape(value)
                        or fixtures.is_fixture(value)
                        or (name in _KEY_ID_LABELS and _glued_letters(text, m))):
                    found.append((value, name, m.start()))
                    continue
                # Resume just past the start, not the end: a fixed-length shape
                # like AKIA+16 would otherwise swallow the "AKIA" of a real key
                # glued on right after a fixture.
                if m.end() != last_end:
                    last_end, retries = m.end(), 0
                    pos = m.start() + 1
                elif retries < _RETRIES_TO_ONE_END:
                    retries += 1
                    pos = m.start() + 1
                else:
                    pos = m.end()
                break

    # Neither pass can match without its separator, and a megabyte of
    # tokens with none is still read once for each, a run at a time.
    pos = 0 if ("=" in text or ":" in text) else None
    label = _Labels(text, found) if pos is not None else None
    nxt = [-2, -2]
    while pos is not None:
        m = _assign_search(text, pos, nxt)
        if not m:
            break
        pos = m.end()
        key, quote = m.group(2), m.group(3)
        if not _names_a_secret(key):
            if quote:
                # {"stdout": "API_TOKEN=..."}: a quoted value can hold an
                # assignment of its own. Quotes end a value, so this reads
                # each one at most twice.
                pos = m.start(4)
            else:
                found.extend(_inner_secrets(text, m.start(4), m.end(4), label))
            continue
        if ":" in text[m.end(2):m.start(3)] and _in_arn(text, m.start(2)):
            # arn:...:${AWS::AccountId}:secret:name. The } of a template
            # ends the value it is in, so "secret" is read as a key here.
            continue
        stop = m.end(4) if quote else _value_end(text, m.start(2), m.start(4),
                                                 m.end(4))
        value = text[m.start(4):stop]
        if _is_secret_value(key, quote, value):
            found.append((value, label(m.start(2), m.end(2)), m.start(4)))
        if stop < m.end(4):
            # The rest of a query string. Skipped with the whole value, a
            # second token after the first was never looked at.
            found.extend(_inner_secrets(text, stop, m.end(4), label))

    # No fixture check here: a connection-string password is chosen by a
    # person, and "acme-example-prod" is still that person's password.
    for m in _CONN.finditer(text) if "://" in text else ():
        value = m.group("secret")
        if not _is_placeholder(value):
            found.append((value, "connection string password", m.start("secret")))

    for marker, pattern, label in (
            _TYPED if len(text) >= _CHEAP_SHORT or _TYPED_ANY.search(text) else ()):
        if marker not in text:
            continue
        for m in pattern.finditer(text):
            group = "q" if m.group("q") is not None else (
                "d" if m.group("d") is not None else "v")
            value = m.group(group)
            if _is_secret_value("password", "", value):
                found.append((value, label, m.start(group)))
    return found


# Where a command takes its password, with no key beside it: mysql's -p
# with the password joined on, sshpass -p, redis-cli -a, docker login -p,
# curl -u's user:password, and --password before a blank. A copy typed so
# was masked only when the same value had been found somewhere else, so a
# password read in a session outside --days, or past the budget of the
# search of other transcripts, was printed whole by check and watch and
# stayed on disk after clean --apply. Each is read within the command the
# name starts, and the value judged as one beside a key named password is.
#
# The same held for sqlcmd -P, influx -password, mongosh -p, ldapsearch -w,
# htpasswd -b's last word, keytool -storepass, ConvertTo-SecureString
# -AsPlainText and the user%password smbclient takes after -U.
_TYPED_VALUE = (r"""(?:'(?P<q>[^'\s]+)'|"(?P<d>[^"\s]+)"|"""
                r"""(?P<v>(?!-)[^\s'"`;|&<>()\\]+))""")
_IN_COMMAND = r"\b[^\n|;&]{0,256}?\s"
# What _TYPED_VALUE takes, unnamed, and the end of the command after it:
# htpasswd -b takes its password as the last word.
_LAST_WORD = (r"""(?=(?:'[^'\s]+'|"[^"\s]+"|[^\s'"`;|&<>()\\]+)"""
              r"""\s*(?:$|[\n|;&]|[0-9]*>))""")
# smbclient -U user%password, rpcclient's too: the user and the % before
# the value, quoted or not, as curl's user and colon.
_SMB_USER = (r"""(?:-U\s*|--user(?:name)?[=\s]\s*)"""
             r"""(?:'[^'%\s]*%(?=[^'\s]+')|"[^"%\s]*%(?=[^"\s]+")|[^\s'"%]*%)""")


def _named(name):
    """A command's name not inside a longer word or path: the name first,
    then what comes before it, so the regex starts with a literal and is
    tried only where the name is (a lookbehind first tried every
    character of a string that held the name anywhere)."""
    return re.escape(name) + r"(?<![\w.-]" + re.escape(name) + ")"


_TYPED = [
    (marker, re.compile(pattern + _TYPED_VALUE), label)
    for marker, pattern, label in (
        ("mysql", _named("mysql") + r"(?:dump|admin|import|check|show|sh|binlog)?"
         + _IN_COMMAND + r"-p", "mysql password"),
        ("mariadb", _named("mariadb") + r"(?:-dump|-admin|-import|-check|-show)?"
         + _IN_COMMAND + r"-p", "mysql password"),
        ("sshpass", _named("sshpass") + r"\s+-p\s*", "sshpass password"),
        ("redis-cli", _named("redis-cli") + _IN_COMMAND + r"(?:-a|--pass)\s+",
         "redis password"),
        ("docker login", _named("docker") + r"\s+login" + _IN_COMMAND + r"-p\s+",
         "docker login password"),
        ("--password", r"(?<=\s)--password\s+", "--password argument"),
        ("curl", _named("curl") + _IN_COMMAND + r"(?:-u\s*|--user[=\s]\s*)"
         r"(?:'[^':\s]*:(?=[^'\s]+')|\"[^\":\s]*:(?=[^\"\s]+\")|[^\s'\":]*:)",
         "curl user password"),
        ("sqlcmd", _named("sqlcmd") + _IN_COMMAND + r"-P\s*", "SQL Server password"),
        ("-password", r"(?<=\s)-password\s+", "-password argument"),
        ("mongo", _named("mongo") + r"(?:sh|dump|restore|export|import|stat|top|files)?"
         + _IN_COMMAND + r"-p\s*", "mongo password"),
        ("ldap", _named("ldap") + r"(?:search|modify|add|delete|whoami|passwd|compare"
         r"|modrdn|exop|url)" + _IN_COMMAND + r"-w\s*", "LDAP bind password"),
        ("htpasswd", _named("htpasswd") + r"(?=[^\n|;&]{0,256}?\s-[A-Za-z]*b)"
         r"[^\n|;&]{0,256}?\s" + _LAST_WORD, "htpasswd password"),
        ("storepass", r"(?<=\s)-(?:src|dest)?storepass\s+", "keystore password"),
        ("keypass", r"(?<=\s)-(?:src|dest)?keypass\s+", "keystore password"),
        ("SecureString", r"(?i:(?<![\w.-])ConvertTo-SecureString"
         r"(?=[^\n|;]{0,256}?\s-AsPlainText\b)"
         r"(?:\s+-(?:AsPlainText|Force)\b)*(?:\s+-String)?)\s+",
         "PowerShell plain-text password"),
        ("smb", _named("smb") + r"(?:client|cacls|get|map|tree)" + _IN_COMMAND + _SMB_USER,
         "SMB password"),
        ("rpcclient", _named("rpcclient") + _IN_COMMAND + _SMB_USER, "SMB password"),
    )]
# Whether a short string holds any rule's marker, in one call: asking each
# in turn cost more than the rules, on every string clean reads. Over a
# long one each marker's own search is faster, as for _CHEAP_ANY.
_TYPED_ANY = re.compile("|".join(re.escape(marker) for marker, _p, _l in _TYPED))


def _scan(text, spans=True, where=False):
    """(find_secrets' answer, the merged (start, end) of every copy of each
    value it reports, or () without spans), so masking asks the rules
    once. With where, each answer is (value, label, copies): where in text
    the value's copies start, as far as they were looked for."""
    if not text or len(text) < _MIN_SECRET_LEN:
        return [], ()
    if _is_embedded_image(text) or not _worth_scanning(text):
        return [], ()
    scanned = text[:MAX_STRING]

    by_value, order = {}, []
    for value, label, start in _found(scanned):
        entry = by_value.get(value)
        if entry is None:
            entry = by_value[value] = (label, [])
            order.append(value)
        entry[1].append(start)
    # Longest first, so a JWT is masked before any substring of it -- and a
    # password that lives inside an already-matched connection string is not
    # reported a second time on its own. Only when it lives nowhere else: a
    # .env often repeats DB_PASSWORD inside DATABASE_URL, and dropping it for
    # that left its own line in plaintext after masking. So this replays the
    # masking in the same order and keeps what is still there to mask.
    #
    # A repeat of a value is one entry: its first copy either masks every
    # occurrence or finds none.
    order.sort(key=len, reverse=True)
    masked = bytearray(len(scanned))     # what masking the kept values replaces
    unique, copied = [], []
    searched = max(1, _SEARCH_CHARS // len(text))
    for rank, value in enumerate(order):
        label, starts = by_value[value]
        n = len(value)
        if rank < searched:
            copies, at = [], text.find(value)
            while at != -1:
                copies.append(at)
                at = text.find(value, at + 1)
        else:
            copies = starts if len(starts) == 1 else sorted(set(starts))
        # The copies str.replace would mask, left to right: each clear of
        # every value masked before it and of the copy before it.
        replaced, free = [], 0
        for at in copies:
            if at + n > len(scanned):
                break
            if at >= free and masked.find(1, at, at + n) == -1:
                replaced.append(at)
                free = at + n
        if not replaced and rank < searched:
            continue          # every copy lies inside a longer value
        # Past the search a copy the scan did not find is never looked for,
        # so a value is kept even when its copies were all inside others.
        for at in replaced:
            masked[at:at + n] = b"\1" * n
        unique.append((value, label, copies) if where else (value, label))
        if spans:
            copied += [(at, at + n) for at in copies]
    if not spans:
        return unique, ()

    merged = []
    for lo, hi in sorted(copied):
        if merged and lo < merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], hi)
        else:
            merged.append([lo, hi])
    return unique, tuple((lo, hi) for lo, hi in merged)


def find_secrets(text):
    """Return [(secret_value, label)] found in a blob of text."""
    return _scan(text, spans=False)[0]


def secret_spans(text):
    """The merged (start, end) of every copy in text of every value
    find_secrets reports, in order."""
    return _scan(text)[1]


# How a secret looks in text shown to the reader: its hint in angle brackets,
# the way a placeholder is written, so it reads as removed and a second pass
# finds nothing to mask.
DISPLAY_MASK = "<%s>"


def mask_for_display(text, spans=None):
    """`text` with every value find_secrets would report replaced by its
    hint, for printing a command or its output without printing the
    credential again. The same rules decide, so fixtures and placeholders
    are shown as they are. Every occurrence is masked, and where two found
    values overlap the whole stretch goes under one hint. `spans`, when
    given, is what secret_spans(text) said already."""
    if spans is None:
        spans = secret_spans(text)
    if not spans:
        return text
    out, pos = [], 0
    for lo, hi in spans:
        out.append(text[pos:lo])
        out.append(DISPLAY_MASK % _hint(text[lo:hi]))
        pos = hi
    out.append(text[pos:])
    return "".join(out)


# A value cut by the … of a window onto a longer text is masked as far as
# it shows, when at least this much of it does.
_SHOWN_PART = 4
_ELLIPSIS = "\u2026"
_FIRST_WORD = re.compile(r"\S+")


class KnownValues(object):
    """Values found elsewhere, made ready once to be masked in many texts
    (mask_known). Each text sorted every value again and was asked about
    each of them: ten thousand values and 3,400 actions in check cost a
    second and a half. A text is asked only about the values whose first
    characters it holds, and a window's edge only about the values whose
    end, or start, holds what shows there."""

    _HEAD = 8
    _EDGE = 512

    def __init__(self, values):
        # Longest first, and in one order whatever order a set has.
        self.ordered = sorted({v for v in values if v}, key=lambda v: (-len(v), v))
        self._k = min([self._HEAD] + [len(v) for v in self.ordered])
        self._heads = {}
        for i, value in enumerate(self.ordered):
            self._heads.setdefault(value[:self._k], []).append(i)
        self._edges = {}

    def _held(self, text):
        """The indexes of the values text may hold, longest first."""
        k = self._k
        if len(text) < k:
            return []
        grams = {text[i:i + k] for i in range(len(text) - k + 1)}
        return sorted(i for gram in self._heads.keys() & grams
                      for i in self._heads[gram])

    def _at_edge(self, piece, word, tail):
        """The values, longest first, whose end (tail) or start holds piece
        within as much of it as word is long: all of them for a word
        longer than the stretch each is indexed by."""
        if len(word) > self._EDGE:
            return self.ordered
        if tail not in self._edges:
            parts = [v[-self._EDGE:] if tail else v[:self._EDGE] for v in self.ordered]
            starts, at = [], 0
            for part in parts:
                starts.append(at)
                at += len(part) + 1
            self._edges[tail] = ("\0".join(parts), starts)
        joined, starts = self._edges[tail]
        found, at = [], joined.find(piece)
        while at != -1:
            i = bisect.bisect_right(starts, at) - 1
            found.append(self.ordered[i])
            if i + 1 == len(starts):
                break
            at = joined.find(piece, starts[i + 1])
        return found

    def mask(self, text):
        for i in self._held(text):
            value = self.ordered[i]
            if value in text:
                text = text.replace(value, DISPLAY_MASK % _hint(value))
        if text.startswith(_ELLIPSIS):
            m = _FIRST_WORD.match(text, 1)
            word = m.group() if m else ""
            shown, value = _shown_end(
                word, self._at_edge(word[:_SHOWN_PART], word, True)
                if len(word) >= _SHOWN_PART else ())
            if shown:
                text = _ELLIPSIS + DISPLAY_MASK % _hint(value) + text[1 + shown:]
        if text.endswith(_ELLIPSIS):
            words = text[:-1].split()
            word = words[-1] if words and not text[-2:-1].isspace() else ""
            shown, value = _shown_start(
                word, self._at_edge(word[-_SHOWN_PART:], word, False)
                if len(word) >= _SHOWN_PART else ())
            if shown:
                text = text[:-1 - shown] + DISPLAY_MASK % _hint(value) + _ELLIPSIS
        return text


# A value clean has masked everywhere it found it, before the index
# (known.py) knew it, is known only by the fingerprint its mask keeps: a
# copy typed where no rule reads it, past a copy budget, was left by every
# mask step, and check and watch printed it whole. Such a copy is found
# where a piece of what they show is all of it: a run between blanks and
# quotes, the pieces between the separators a command puts around a value
# (user:VALUE@host), after a flag (-pVALUE), or where one may be glued on.
_EVIDENCE_RUN = re.compile(r"[^\s\"'`]+")
_EVIDENCE_SEPARATORS = re.compile(r"[=:@/,;|&<>(){}\[\]]+")
_EVIDENCE_EDGES = ".,;:!?()[]{}<>\u2026"


# Where else in a stretch a value may start or end: after or before any
# character but a letter, a digit or one of ._- (which values hold), as
# smbclient -U admin%PASSWORD joins one to the user. The pieces between
# two of them are asked too, for a value glued on at both ends, as long
# as there are no more than this many: past it, only what starts at one
# and runs to the end, or runs from the start to one, and no longer than
# _GLUED_LONGEST. Each of those was as long as the rest of the stretch:
# for a run of 64,000 characters with a + in every other one, a gigabyte
# to hash, and check and watch ask about texts that long.
_GLUE = re.compile(r"[^A-Za-z0-9._-]")
_GLUE_PAIRED = 8
_GLUED_LONGEST = 256


def _glued(piece):
    """The stretches of piece that start or end where something may be
    glued to a value."""
    at = [m.start() for m in _GLUE.finditer(piece)]
    if not at:
        return ()
    starts, ends = [0] + [k + 1 for k in at], at + [len(piece)]
    if len(at) > _GLUE_PAIRED:
        n = len(piece)
        return ([piece[k:] for k in starts if n - k <= _GLUED_LONGEST]
                + [piece[:k] for k in ends if k <= _GLUED_LONGEST])
    return [piece[i:j] for i in starts for j in ends if j - i >= _MIN_ASSIGNED]


def _pieces(text, urls=False):
    """Each stretch of text a value may be, of _MIN_ASSIGNED characters or
    more: a run between blanks and quotes, and its pieces between the
    separators a command puts around a value, and where one may be glued
    on. Not a run holding a URL, but with urls: what in one is a secret,
    a password or a parameter, the rules find in it."""
    out = set()
    for run in _EVIDENCE_RUN.findall(text):
        run = run.strip(_EVIDENCE_EDGES)
        if len(run) < _MIN_ASSIGNED or (_SCHEME_END in run and not urls):
            continue
        pieces = {run}
        if run[0] == "-" and run[1:2].isalpha():
            pieces.add(run[2:])                   # -pVALUE
        pieces.update(_EVIDENCE_SEPARATORS.split(run))
        for piece in list(pieces):
            pieces.update(_glued(piece))          # admin%VALUE
        for piece in pieces:
            piece = piece.strip(_EVIDENCE_EDGES)
            if len(piece) >= _MIN_ASSIGNED and _ELLIPSIS not in piece:
                out.add(piece)
    return out


# A mask keeps the fingerprint of the value it took the place of.
_MASK_MARK = "ranwhat:redacted:"
_MASKS = re.compile(r"ranwhat:redacted:([0-9a-f]{12})")


def values_in(path):
    """(every value the rules find in the transcript at path, the
    fingerprint each mask in it keeps), read as scan_file reads it and
    never written: for the index check and watch keep of the values clean
    finds (known.py). None when it cannot be read. A value scan_file
    counts in a transcript it was not found in is found in another, so
    the values of every transcript are every value clean finds."""
    values, masks = set(), set()

    def collect(value, _label, _text, _copies):
        values.add(value)
    try:
        with open(path, "r", encoding="utf-8", errors="replace",
                  newline="") as fh:
            for line in fh:
                stripped = line.strip()
                if not stripped:
                    continue
                if _MASK_MARK in stripped:
                    masks.update(_MASKS.findall(stripped))
                try:
                    obj = json.loads(stripped)
                except (ValueError, RecursionError):
                    continue          # not JSON, or deeper than it reads
                _walk(obj, collect)
    except OSError:
        return None
    return values, masks


def values_in_store(source, store):
    """values_in, for a file of an agent read through its adapter: (every
    value the rules find in it, the fingerprint each mask in it keeps), or
    None when it cannot be read."""
    if not os.path.exists(store.path):
        return None
    values = {}
    findings, masks = scan_store(source, store, values)
    return {values[fp] for fp in findings}, masks


def mask_known(text, values):
    """text with every copy of each of `values` masked as mask_for_display
    masks one, longest first. These are values found elsewhere: typed into
    a command with no key beside it (mysql -pPASSWORD, curl -u
    admin:PASSWORD), nothing in text says it is a secret. A value cut by an
    … at either end of text is masked as far as it shows. For many texts,
    pass KnownValues(values), made once."""
    if not isinstance(values, KnownValues):
        values = KnownValues(values)
    return values.mask(text)


# What shows of a value at a window's edge is no longer than the word it
# is in, so only that much of the value's end, or of its start, is looked
# at. Every place a short piece sat in the whole value was tried, each with
# a copy of the value up to it: quadratic in the value, and check ran past
# twenty seconds on half a megabyte. The most that shows is masked.


def _shown_end(word, values):
    """(how much of word, from its start, is the end of a value, the value)."""
    if len(word) >= _SHOWN_PART:
        piece = word[:_SHOWN_PART]
        for value in values:
            at = value.find(piece, max(0, len(value) - len(word)))
            while at != -1:
                if word.startswith(value[at:]):
                    return len(value) - at, value
                at = value.find(piece, at + 1)
    return 0, None


def _shown_start(word, values):
    """(how much of word, to its end, is the start of a value, the value)."""
    if len(word) >= _SHOWN_PART:
        piece = word[-_SHOWN_PART:]
        for value in values:
            at = value.rfind(piece, 0, len(word))
            while at != -1:
                if word.endswith(value[:at + _SHOWN_PART]):
                    return at + _SHOWN_PART, value
                at = value.rfind(piece, 0, at + _SHOWN_PART - 1)
    return 0, None


def _strings(node):
    """(container, key, string) for every string in a decoded JSON
    structure, in the order it is written: (None, None, node) for a node
    that is a string. Walked with a stack of its own, since a line can be
    nested deeper than Python's: 900 levels ended the run in RecursionError.
    A container's string may be replaced through container[key] meanwhile."""
    if isinstance(node, str):
        yield None, None, node
        return
    if not isinstance(node, (list, dict)):
        return
    stack = [(node, iter(node.items() if isinstance(node, dict) else enumerate(node)))]
    while stack:
        container, entries = stack[-1]
        for key, value in entries:
            if isinstance(value, str):
                yield container, key, value
            elif isinstance(value, (list, dict)):
                stack.append((value, iter(value.items() if isinstance(value, dict)
                                          else enumerate(value))))
                break
        else:
            stack.pop()


def _each_string(node, change):
    """(node, whether anything changed) with every string in it put through
    change, in place in node's own containers: they are decoded from a
    line, and nothing else holds them."""
    changed = False
    for container, key, text in _strings(node):
        new = change(text)
        if new != text:
            changed = True
            if container is None:
                node = new
            else:
                container[key] = new
    return node, changed


def _walk(node, collect, replace=None, only=None, seen=None):
    """Visit every string in a decoded JSON structure, and with replace
    mask in it what was found: (node, whether anything changed).

    `only` limits masking to a set of fingerprints, so acting on one finding
    does not rewrite every other secret in the same file.

    collect is called with each value, its label, the string it is in and
    where in that string its copies start. `seen`, a list, is given each
    string long enough to hold a value, as it was read.
    """
    def visit(text):
        if seen is not None and len(text) >= _MIN_ASSIGNED:
            seen.append(text)
        secrets = _scan(text, spans=False, where=True)[0]
        for value, label, copies in secrets:
            collect(value, label, text, copies)
        if replace:
            for value, _label, _copies in secrets:
                if only is None or _fingerprint(value) in only:
                    text = text.replace(value, REDACTION % _fingerprint(value))
        return text
    return _each_string(node, visit)


# A value is found where a key or its shape marks it. A copy with neither
# beside it, typed into a later command (-pPASSWORD) or quoted in a reply,
# was left in plaintext by masking, and the next scan said "No secrets
# found". So each value found in a transcript is counted in all of it, and
# one with more copies than were found has the rest looked for line by
# line. Longest first, until this many characters have been read: past it
# a value is masked and counted where it was found, as it always was.
_COPY_SEARCH_CHARS = 512 * MAX_STRING


def _written(value):
    """Each way a transcript's JSON may write value: as it is, and with
    the escapes json.dumps gives it with and without ensure_ascii."""
    return {value, json.dumps(value)[1:-1],
            json.dumps(value, ensure_ascii=False)[1:-1]}


# Another JSON writer may escape what json.dumps writes as it is: / as \/,
# a printable character as \u0041, or any as \uXXXX in capitals. A reader
# decodes the same string, but a copy written so was never found by a
# look for the forms of _written: clean --apply left it, and once the copy
# it was found by was masked, check and watch printed it whole. A text
# holding an escape json.dumps without ensure_ascii would not write (any
# but a control character's, in small letters, that has no short form) is
# looked in with each escape as that writes it (_as_dumps). A writer that
# escapes some characters past ASCII and not others is covered so too.
_ODD_ESCAPE = re.compile(r"\\(?:/|u(?!00[01][0-9a-f])[0-9a-fA-F]{4}|u000[89acd])")
_ODD_ESCAPE_BYTES = re.compile(_ODD_ESCAPE.pattern.encode("ascii"))
_JSON_ESCAPE = re.compile(r"\\(?:u([dD][89abAB][0-9a-fA-F]{2})\\u([dD][c-fC-F][0-9a-fA-F]{2})"
                          r"|u([0-9a-fA-F]{4})|(.))", re.S)


def _dumps_escape(m):
    if m.group(1):
        high, low = int(m.group(1), 16), int(m.group(2), 16)
        return chr(0x10000 + ((high - 0xD800) << 10) + (low - 0xDC00))
    if m.group(3):
        code = int(m.group(3), 16)
        if 0xD800 <= code <= 0xDFFF:
            return "\\u%04x" % code             # half a pair: as dumps writes it
        return json.dumps(chr(code), ensure_ascii=False)[1:-1]
    return "/" if m.group(4) == "/" else m.group(0)


def _odd_escape_in(text):
    """Whether JSON text (str or bytes) holds an escape json.dumps would
    have written otherwise. \\\\/ is an escaped backslash and a /, and in
    a real history every match was one of those: so an escape counts only
    where the backslashes before it leave it one of its own."""
    pattern, slash = ((_ODD_ESCAPE, "\\") if isinstance(text, str)
                      else (_ODD_ESCAPE_BYTES, b"\\"))
    for m in pattern.finditer(text):
        k = m.start()
        while k and text[k - 1:k] == slash:
            k -= 1
        if (m.start() - k) % 2 == 0:
            return True
    return False


def _as_dumps(text):
    """JSON text with every escape as json.dumps(ensure_ascii=False)
    writes it, when it holds one written otherwise: the same JSON to a
    reader, and a copy of a value in it is in one of _written's forms.
    Escapes are read from the start, so \\\\u0041 stays a backslash and
    u0041."""
    if not _odd_escape_in(text):
        return text
    return _JSON_ESCAPE.sub(_dumps_escape, text)


def _copies_elsewhere(texts, owners, size, values, found):
    """({fingerprint: indexes of the lines holding a copy}, characters read)
    for each value with more copies in the file than the `found` copies
    the rules found it at. `texts` are the file's strings as decoded, each
    long enough to hold a value, and `owners` the index of the line each
    is on. They are what a copy can be in, and the decoded value is what
    it is: the raw lines, searched as JSON writes each value two ways, are
    half again as long and their keys, ids and times hold none. Each value
    costs a pass over the transcript, of `size` characters, as it did."""
    starts, at = [], 0
    for text in texts:
        starts.append(at)
        at += len(text) + 1
    joined = _JOIN.join(texts)
    out, spent = {}, 0
    # The values found here first, so one brought from another transcript
    # never takes the reading their copies had before.
    for fp in sorted(values, key=lambda f: (not found[f], -len(values[f]))):
        value = values[fp]
        if spent + size > _COPY_SEARCH_CHARS:
            break
        spent += size
        if _JOIN in value:
            held = {owners[k] for k, text in enumerate(texts) if value in text}
            if sum(text.count(value) for text in texts) > found[fp]:
                out[fp] = held
            continue
        if joined.count(value) <= found[fp]:
            continue
        held, p = set(), joined.find(value)
        while p != -1:
            k = bisect.bisect_right(starts, p) - 1
            held.add(owners[k])
            p = joined.find(value, starts[k + 1]) if k + 1 < len(starts) else -1
        out[fp] = held
    return out, spent


def _content_blocks(obj):
    msg = obj.get("message") if isinstance(obj, dict) else None
    content = msg.get("content") if isinstance(msg, dict) else None
    if not isinstance(content, list):
        return []
    return [b for b in content if isinstance(b, dict)]


# Attachments that hold a file's own text: @api/.env in a prompt, or a file
# changed outside the session. Each names the file it holds.
_FILE_ATTACHMENTS = ("file", "edited_text_file")

# grep -r and rg print each match after the file it is in, and its line
# number with -n: api/.env:3:DB_PASSWORD=... A YAML key has a space after
# its colon (id_rsa: ...), which grep's prefix never has.
_GREP_PREFIX = re.compile(r"([^\s:]+):(?:[0-9]+:)?(?!\s)")

# Returned for a result whose call named no file: each secret is credited to
# the file grep printed in front of its own line, if any.
_GREP_LINE = object()
# A grep line that holds a credential is short, and a few copies of a value
# say which file it is.
_GREP_BACK = 4096
_GREP_COPIES = 16
# A line starts after a newline, or after one still escaped, or where the
# text does.
_LINE_BREAK = re.compile(r"\n|\\n")


class _GrepLines(object):
    """The lines of one string, for crediting each secret in it to the file
    grep printed in front of its own line.

    Each secret is looked for only where the scan found its copies, and
    each line's prefix read once. Searching every string on the transcript
    line for every value, from the start, was quadratic: half a megabyte
    of distinct values took seconds to credit and a tenth of one to find."""

    def __init__(self, text):
        self.text = text
        breaks = list(_LINE_BREAK.finditer(text))
        self.starts = [0] + [m.end() for m in breaks]
        self.ends = [m.start() for m in breaks] + [len(text)]
        self.prefixes = {}            # line start -> (origin, prefix end)

    def _prefix(self, i):
        start = self.starts[i]
        if start not in self.prefixes:
            m = _GREP_PREFIX.match(self.text, start, self.ends[i])
            named = (_origins(json.dumps(m.group(1), ensure_ascii=False))
                     if m else None)
            self.prefixes[start] = (named[-1], m.end()) if named else (None, 0)
        return self.prefixes[start]

    def origin(self, copies):
        """The credential file grep printed in front of the line that holds
        one of these copies, or None."""
        for at in copies[:_GREP_COPIES]:
            i = bisect.bisect_right(self.starts, at) - 1
            if at - self.starts[i] > _GREP_BACK:
                continue              # no start close enough: not a grep line
            origin, end = self._prefix(i)
            if origin and end <= at:
                return origin
        return None


# A here-document is what a command writes, not what it reads: `cat > t.py
# <<'EOF'` followed by source that mentions .env. Read line by line, so a
# stray << (C++ in a python -c string) costs one pass, never a search.
_HEREDOC = re.compile(r"(?<!<)<<-?\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1")


def _without_heredocs(command):
    out, marker = [], None
    for line in command.split("\n"):
        if marker is not None:
            if line.strip() == marker:
                marker = None
            continue
        out.append(line)
        m = _HEREDOC.search(line)
        if m:
            marker = m.group(2)
    return "\n".join(out)


def _named_by_call(block):
    """The credential files a tool call's input names. Most name none, and
    say so in their strings before any is written out as JSON."""
    args = block.get("input")
    if isinstance(args, dict) and not _may_name_a_file(args):
        return []
    if isinstance(args, dict) and isinstance(args.get("command"), str):
        args = dict(args, command=_without_heredocs(args["command"]))
    try:
        return _origins(json.dumps(args, ensure_ascii=False))
    except RecursionError:
        # Nested too deep to write out, as a line too deep to read: it
        # names no file, and the rest of the transcript is read on.
        return []


def _named_by_input(call):
    """_named_by_call for a sources.ToolCall (design 3.6): the credential
    files its input names, with the keys its adapter turned into its
    command replaced by that command, heredocs stripped. A ported source's
    call (Claude Code's, kind None) has no command of its own, and names
    what _named_by_call names for the same input."""
    args = call.tool_input
    if call.command is None or not isinstance(args, dict):
        return _named_by_call({"input": args})
    named = {k: v for k, v in args.items() if k not in call.consumed}
    if "command" not in named:
        named["command"] = call.command
    else:                         # kept as recorded, and the command beside it
        named["_command"] = _without_heredocs(call.command)
    return _named_by_call({"input": named})


def _may_name_a_file(args):
    """False only when no key or string in args holds a marker _origins
    needs (_ORIGIN_MARKERS). JSON's escapes add a backslash and letters or
    hex digits, which make none of them. Anything but strings, numbers and
    None is asked whole."""
    for key, value in args.items():
        if isinstance(value, str):
            texts = (str(key), value)
        elif isinstance(value, (int, float, bool)) or value is None:
            texts = (str(key),)
        else:
            return True
        for text in texts:
            lowered = text.lower()
            if any(marker in lowered for marker in _ORIGIN_MARKERS):
                return True
    return False


def _origin_for_line(obj, last_call, call_origins):
    """The credential file a secret on this line was read out of: a path,
    None, or _GREP_LINE to look at the secret's own line.

    Only a tool result, or a file attached whole, is read out of a file. A
    result belongs to the call that produced it: the one its tool_use_id
    names, or in a format with no ids the call just before it. So the output
    of `ls` gets no origin because `cat api/.env` ran three calls earlier, a
    key someone pasted gets none because a message two lines up mentioned
    "d.key", and a value typed into a command gets none because the command
    also mentions a .env. `last_call` holds the paths the latest call named,
    and is updated here.
    """
    if isinstance(obj, dict) and obj.get("type") == "attachment":
        att = obj.get("attachment")
        if (isinstance(att, dict) and att.get("type") in _FILE_ATTACHMENTS
                and isinstance(att.get("filename"), str)):
            named = _origins(json.dumps(att["filename"], ensure_ascii=False))
            return named[-1] if named else None
        return None
    result_ids, calls = [], []
    for block in _content_blocks(obj):
        if block.get("type") == "tool_use":
            named = _named_by_call(block)
            calls.append(named)
            if block.get("id") and isinstance(block["id"], str):
                call_origins[block["id"]] = named
        elif block.get("type") == "tool_result":
            # An id is a string. Any other, an object, could not be looked up.
            i = block.get("tool_use_id")
            result_ids.append(i if isinstance(i, str) else None)
    if calls:
        last_call[:] = [o for named in calls for o in named]
        return None               # typed into the call, not read by it
    if not result_ids:
        return None               # typed or said, not read out of a file
    named = []
    for i in result_ids:
        named += call_origins.get(i, []) if i else last_call
    if named:
        return named[-1]
    # A call that named nothing can still have read a credential file:
    # grep -r output says which file each of its lines came from. Any
    # other mention of a file in the output is just text.
    return _GREP_LINE


# Half an emoji, from a string Node cut inside one, is written as an escape
# (\ud83d) that json reads as a lone surrogate, which UTF-8 cannot write.
_LONE_SURROGATE = re.compile("[\ud800-\udfff]")


def _dumped(obj, line):
    """obj written back as the line it was read from, with that line's
    ending, or None when it is nested too deep for json.dumps to write:
    3.14's json reads far deeper than it writes. That line is kept as it
    was read, as one json cannot read is, and the rest masked. A lone
    surrogate is written as the escape it was read as."""
    try:
        text = json.dumps(obj, ensure_ascii=False)
    except RecursionError:
        return None
    text = _LONE_SURROGATE.sub(lambda m: "\\u%04x" % ord(m.group()), text)
    return text + line[len(line.rstrip("\r\n")):]


def scan_file(path, apply=False, only=None, known=None, extra=None, read=None,
              remember=None):
    """Find (and optionally mask) secrets in one transcript.

    Returns (findings, changed). Each finding is a dict describing one
    distinct secret value and where it was seen. A value found anywhere in
    the transcript is counted, and masked, in every string that holds it,
    whether or not the rules would find it there. `known`, a dict, is given
    each value found, by its fingerprint: never written anywhere, for
    masking what other reports show (mask_known).

    `extra`, {fingerprint: value}, are values the rules found in other
    transcripts: each is counted and masked here like a copy, wherever it
    is. One found only that way has a finding with no label of its own;
    the caller holds the one it was found under.

    `read`, once the whole transcript has been read, is called with what
    values_in(path) would return for it: the values the rules find and
    the fingerprint each mask in it keeps (for known.Index.take). Not
    when it could not be read. `remember`, with apply, is called with the
    values about to be masked before the transcript is rewritten (for
    known.Index.remember).
    """
    findings = {}
    rewritten = []
    changed = False

    last_call = []              # credential paths the latest call named
    call_origins = {}           # tool_use id -> credential paths in its input
    origin_now = [None]         # what a secret on the current line is credited to
    lines_now = [None]          # _GrepLines of the string being walked

    values = {}                 # fingerprint -> the value it was taken of
    found = {}                  # fingerprint -> copies the rules found
    masks = set()               # the fingerprint each mask here keeps
    # The project every finding here belongs to. Resolving a slug asks the
    # filesystem a hundred times, and asked once per finding a megabyte of
    # distinct key IDs took nine seconds.
    project = []

    def collect(value, label, text, copies):
        fp = _fingerprint(value)
        values[fp] = value
        found[fp] = found.get(fp, 0) + len(copies)
        entry = findings.setdefault(fp, {
            "fingerprint": fp,
            "label": label,
            "length": len(value),
            "hint": _hint(value),
            "files": set(),
            "origins": set(),
            "projects": set(),
            "count": 0,
        })
        entry["files"].add(path)
        if not project:
            project.append(project_path(transcript_place(path)[0]))
        entry["projects"].add(project[0])
        origin = origin_now[0]
        if origin is _GREP_LINE:
            if lines_now[0] is None or lines_now[0].text is not text:
                lines_now[0] = _GrepLines(text)
            origin = lines_now[0].origin(copies)
        if origin:
            entry["origins"].add(origin)
        entry["count"] += 1

    # UTF-8 whatever the locale says: Windows would otherwise decode as
    # cp1252 and write the mojibake back. newline="" hands each line over
    # with its own ending, so a rewrite keeps \r\n where it found \r\n.
    lines = []
    texts, owners = [], []      # each string long enough to hold a value, its line
    try:
        with open(path, "r", encoding="utf-8", errors="replace",
                  newline="") as fh:
            for line in fh:
                lines.append(line)
                stripped = line.strip()
                if not stripped:
                    rewritten.append(line)
                    continue
                if read is not None and _MASK_MARK in stripped:
                    masks.update(_MASKS.findall(stripped))
                try:
                    obj = json.loads(stripped)
                except (ValueError, RecursionError):
                    rewritten.append(line)      # not JSON, or deeper than it reads
                    continue
                lines_now[0] = None
                origin_now[0] = _origin_for_line(obj, last_call, call_origins)
                before = len(texts)
                new, masked = _walk(obj, collect, replace=apply, only=only,
                                    seen=texts)
                owners.extend([len(lines) - 1] * (len(texts) - before))
                written = _dumped(new, line) if apply and masked else None
                if written is not None:
                    changed = True
                    rewritten.append(written)
                else:
                    rewritten.append(line)
    except OSError:
        return {}, False
    if read is not None:
        read(set(values.values()), masks)

    for fp, value in (extra or {}).items():
        if value and fp not in values:
            values[fp], found[fp] = value, 0
    # Each string holding a copy is a place the value was seen, and with
    # apply each copy is masked, longest value first. A shape is found
    # wherever it is copied, by the rules themselves, so it is looked for
    # only when a string was too long for them to read whole.
    asked = values
    if not any(len(line) > MAX_STRING for line in lines):
        asked = {fp: v for fp, v in values.items()
                 if fp not in findings or findings[fp]["label"] not in _SHAPE_LABELS}
    if only is not None:
        # Only these are masked, or counted by the caller: seventy longer
        # keys found here spent the budget before the one being masked.
        asked = {fp: v for fp, v in asked.items() if fp in only}
    elsewhere, spent = (_copies_elsewhere(texts, owners, sum(map(len, lines)), asked, found)
                        if asked else ({}, 0))
    masking = {fp for fp in elsewhere if only is None or fp in only} if apply else ()
    places = dict.fromkeys(elsewhere, 0)
    on_line = {}
    for fp, held in elsewhere.items():
        for i in held:
            on_line.setdefault(i, []).append(fp)
    for i in sorted(on_line):
        held = sorted(on_line[i], key=lambda f: -len(values[f]))
        spent += len(held) * len(lines[i])
        if spent > 2 * _COPY_SEARCH_CHARS:
            break
        try:
            original = json.loads(lines[i].strip())
        except (ValueError, RecursionError):
            continue
        strings = _Strings(original)
        holding = {}              # index of a string -> the values it holds
        for fp in held:
            found_in = strings.holding(values[fp])
            places[fp] += len(found_in)
            spent += len(found_in) * _PER_STRING_FOUND
            for k in found_in:
                holding.setdefault(k, []).append(fp)
        mask = {k: [fp for fp in fps if fp in masking] for k, fps in holding.items()}
        mask = {k: fps for k, fps in mask.items() if fps}
        if not mask:
            continue
        try:
            now = json.loads(rewritten[i].strip())
        except (ValueError, RecursionError):
            continue
        # The rewrite has the shape of the original, so its strings come
        # in the same order, and only those that held a value are asked.
        visit = iter(range(len(strings.texts)))

        def change(text):
            fps = mask.get(next(visit, None))
            return _masked_copies(text, fps, values) if fps else text
        new, masked = _each_string(now, change)
        written = _dumped(new, lines[i]) if masked else None
        if written is not None:
            changed = True
            rewritten[i] = written
    for fp, n in places.items():
        if fp not in findings:
            if not n:
                continue          # a value from elsewhere, not here
            if not project:
                project.append(project_path(transcript_place(path)[0]))
            findings[fp] = {"fingerprint": fp, "label": None,
                            "length": len(values[fp]), "hint": _hint(values[fp]),
                            "files": {path}, "origins": set(),
                            "projects": {project[0]}, "count": 0}
        findings[fp]["count"] = max(findings[fp]["count"], n)
    if known is not None:
        known.update(values)

    if apply and changed:
        if remember is not None:
            remember([v for fp, v in values.items() if only is None or fp in only])
        _backup(path)
        tmp = path + ".ranwhat-tmp"
        try:
            _write_like(path, tmp, rewritten)
            # Refuse to install a file we cannot read back. Only the lines
            # written anew are asked: one kept as it was read may never
            # have been JSON, or be deeper than json reads.
            with open(tmp, encoding="utf-8", newline="") as fh:
                for line, was in zip(fh, lines):
                    if line != was:
                        json.loads(line)
            os.replace(tmp, path)
        finally:
            if os.path.lexists(tmp):
                os.unlink(tmp)

    return findings, changed


# What finding a string that holds a value costs, as characters read, in
# the budget the second pass of scan_file spends: a few lookups in Python.
_PER_STRING_FOUND = 256
# Joins a line's strings, so each value is looked for in all of them at
# once. A value holding it is looked for string by string instead.
_JOIN = "\0"


class _Strings(object):
    """Every string in a decoded line, in the order _each_string visits
    them, walked once. Asking each value of the line's nodes walked them
    once per value: 600 values on a line of 470,000 numbers took longer
    than twenty seconds."""

    def __init__(self, node):
        self.texts = [text for _container, _key, text in _strings(node)]
        self.joined = _JOIN.join(self.texts)
        self.starts, at = [], 0
        for text in self.texts:
            self.starts.append(at)
            at += len(text) + 1

    def holding(self, value):
        """The index of each string that holds value, in order."""
        if not value:
            return []
        if _JOIN in value:
            return [k for k, text in enumerate(self.texts) if value in text]
        found, joined, starts = [], self.joined, self.starts
        at = joined.find(value)
        while at != -1:
            k = bisect.bisect_right(starts, at) - 1
            found.append(k)
            if k + 1 == len(starts):
                break
            at = joined.find(value, starts[k + 1])
        return found


def _masked_copies(text, fingerprints, values):
    for fp in fingerprints:
        if values[fp] in text:
            text = text.replace(values[fp], REDACTION % fp)
    return text


# O_NOFOLLOW where the platform has it: a symlink planted at a path we are
# about to create must fail the write, not redirect it. O_BINARY on Windows,
# where a descriptor from os.open is otherwise in text mode and every \n
# written through it gains a \r: a backup would no longer be the original.
_CREATE = (os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
           | getattr(os, "O_BINARY", 0))


def _write_like(original, tmp, lines):
    """Write the rewritten transcript with the original's permissions.

    open(tmp, "w") took the umask default, so a 0600 transcript came back
    0644 after masking: the one command meant to reduce exposure widened it.
    The file is created 0600 and only then given the original's mode, so it
    is never readable by anyone the original was not. A stale tmp from an
    interrupted run is removed first rather than written through.

    Lines are written exactly as given, endings included. Windows has no
    mode bits to carry, only a read-only flag, which would leave a tmp that
    could not be removed if the replace failed; there the new file takes
    its directory's permissions."""
    mode = os.stat(original).st_mode & 0o777
    if os.path.lexists(tmp):
        os.unlink(tmp)
    fd = os.open(tmp, _CREATE, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8", newline="") as fh:
        fh.writelines(lines)
        if os.name != "nt":
            os.fchmod(fh.fileno(), mode)


def _backup_dest(root, stamp, path):
    """Where the backup of `path` goes: its absolute path, re-rooted under
    root/stamp. Joining C:\\Users\\... onto the root would discard the root
    and name the transcript itself, so on Windows the drive (or a UNC
    server and share) becomes a directory of its own."""
    drive, rest = os.path.splitdrive(os.path.abspath(path))
    parts = [p for p in re.split(r"[\\/:?]+", drive) if p.strip(".")]
    rest = rest.lstrip(os.path.sep + (os.path.altsep or ""))
    return os.path.join(root, stamp, *parts, rest)


def _backup(path):
    """Copy the unmasked transcript aside before rewriting it.

    The backup holds every secret the rewrite removes, so it is written the
    way a secret should be: 0600, under a 0700 root nobody else can list.
    copy2 used to carry the source's mode across and makedirs left the tree
    0755. Microseconds in the stamp, and O_EXCL, keep two masks in the same
    second from overwriting the true original with a half-masked copy.

    Microseconds are only as fine as the clock: on Windows before Python
    3.13 it ticks every 1 to 16 ms. A stamp already taken gets a counter,
    stamp-1, stamp-2, rather than failing the mask."""
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    os.makedirs(BACKUP_ROOT, mode=0o700, exist_ok=True)
    os.chmod(BACKUP_ROOT, 0o700)
    for attempt in range(100):
        name = "%s-%d" % (stamp, attempt) if attempt else stamp
        dest = _backup_dest(BACKUP_ROOT, name, path)
        os.makedirs(os.path.dirname(dest), mode=0o700, exist_ok=True)
        try:
            fd = os.open(dest, _CREATE, 0o600)
            break
        except FileExistsError:
            if attempt == 99:
                raise
    with open(path, "rb") as src, os.fdopen(fd, "wb") as out:
        shutil.copyfileobj(src, out)
    return dest


def scan(root=CLAUDE_PROJECTS, since_days=None, apply=False, progress=None,
         known=None, copies=True, read=None, remember=None):
    """Scan every transcript. Returns (merged_findings, files_scanned, files_changed).

    `progress` is called with (index, total, path) before each file. A large
    history takes a couple of minutes, and a run that prints nothing for that
    long is indistinguishable from one that has hung.

    With `copies`, a value the rules found in one transcript is also looked
    for in the others (_copies_in_other_transcripts), counted there, and
    with apply masked there. Only `known` is wanted without it.

    `read` is called with (path, its os.stat from before it was read, the
    values the rules find there, the fingerprints of its masks) for each
    transcript read whole: check's index takes them (known.Index.take)
    rather than read each transcript a second time. `remember`, with
    apply, is given each value before a transcript loses it to a mask.
    """
    merged, scanned, changed_files = {}, 0, []
    values = {}
    paths = discover(root, since_days)
    for index, path in enumerate(paths, 1):
        if progress:
            progress(index, len(paths), path)
        scanned += 1
        took = None
        if read is not None:
            try:
                st = os.stat(path)
            except OSError:
                st = None
            if st is not None:
                def took(found, masks, path=path, st=st):
                    read(path, st, found, masks)
        findings, changed = scan_file(path, apply=apply, known=values, read=took,
                                      remember=remember)
        if changed:
            changed_files.append(path)
        _merge(merged, findings)
    if copies and merged:
        _copies_in_other_transcripts(paths, merged, values, apply, changed_files,
                                     remember=remember)
    if known is not None:
        known.update(values)
    return merged, scanned, changed_files


def _merge(merged, findings, only=None):
    for fp, entry in findings.items():
        if only is not None and fp not in only:
            continue
        if fp in merged:
            merged[fp]["files"] |= entry["files"]
            merged[fp]["origins"] |= entry["origins"]
            merged[fp]["projects"] |= entry["projects"]
            merged[fp]["count"] += entry["count"]
            # Which agents hold it, in which of their files, and which of
            # those cannot be masked (scan_sources; not in scan's own).
            for key in ("sources", "read_only"):
                if key in entry:
                    merged[fp].setdefault(key, set()).update(entry[key])
            if "stores" in entry:
                merged[fp].setdefault("stores", {}).update(entry["stores"])
        else:
            merged[fp] = entry


# A password read in one session (cat .env) is typed in another, or by a
# subagent (mysql -pPASSWORD), with no key beside it. Masked only where the
# rules found it, the copy stayed in plaintext, and since nothing said it
# was a secret any more, check and watch printed it whole and clean said
# "No secrets found". So each value is looked for in every other
# transcript read, newest first, longest value first, until this many
# characters have been read (about a second), and no more than so many
# for each character of the transcripts: past it a value is counted and
# masked where it was found, as within a transcript past
# _COPY_SEARCH_CHARS. A megabyte of distinct passwords beside a second
# transcript would otherwise read it once for each.
_CROSS_SEARCH_CHARS = 4096 * MAX_STRING
_CROSS_SEARCH_PER_CHAR = 64
_CROSS_LOOK = 256
# A shape is found wherever it is copied, by the rules themselves.
_SHAPE_LABELS = frozenset(name for _shape, name in _SHAPES_NAMED)


def _copies_in_other_transcripts(paths, merged, values, apply, changed_files,
                                 remember=None, least=2):
    """Count, and with apply mask, each value of `merged` in the transcripts
    of `paths` it was not found in. Each look costs what it reads, and a
    little more for asking at all, so a thousand small transcripts and ten
    thousand values stop at the budget too. `remember` as scan_file takes
    it. With fewer than `least` transcripts there is none to look in: the
    values were found in them (least=1: found in another agent's files)."""
    order = sorted((fp for fp, f in merged.items()
                    if fp in values and f["label"] not in _SHAPE_LABELS),
                   key=lambda fp: (-len(values[fp]), fp))
    if not order or len(paths) < least:
        return
    size = 0
    for path in paths:
        try:
            size += os.path.getsize(path)
        except OSError:
            pass
    budget = min(_CROSS_SEARCH_CHARS, _CROSS_SEARCH_PER_CHAR * size)
    forms = {}
    for path in paths:
        content, present = None, {}
        for fp in order:
            if path in merged[fp]["files"]:
                continue
            if content is None:
                try:
                    with open(path, encoding="utf-8", errors="replace") as fh:
                        content = _as_dumps(fh.read())
                except OSError:
                    break
            if fp not in forms:
                forms[fp] = tuple(_written(values[fp]))
            written = forms[fp]
            budget -= len(written) * len(content) + _CROSS_LOOK
            if budget < 0:
                break
            if (written[0] in content if len(written) == 1
                    else any(form in content for form in written)):
                present[fp] = values[fp]
        if present:
            findings, changed = scan_file(path, apply=apply, only=set(present),
                                          extra=present, remember=remember)
            if changed and path not in changed_files:
                changed_files.append(path)
            _merge(merged, {fp: f for fp, f in findings.items() if f["count"]},
                   only=present)
        if budget < 0:
            return


# ---------------------------------------------------------------------------
# Every agent's history (design 3.6). Claude Code is read by scan above, as
# before; every other agent through its adapter's secret_texts, and masked
# only where the adapter says its file can be rewritten.
# ---------------------------------------------------------------------------

class Searched(object):
    """What scan_sources found and did."""

    def __init__(self):
        self.findings = {}          # fingerprint -> finding
        self.counts = {}            # source id -> transcripts searched
        self.others = {}            # source id -> other files searched
        self.changed = []           # files masked
        self.read_only = {}         # read-only file holding a finding -> Store
        self.skipped = {}           # file not masked -> (source id, why)
        self.stores = {}            # path -> Store, each adapter file searched
        self.values = {}            # fingerprint -> value

    @property
    def scanned(self):
        """Every file searched, all agents together."""
        return sum(self.counts.values()) + sum(self.others.values())


def _origin_of(text):
    """What a secret in one SecretText was read out of, as
    _origin_for_line answers it for a Claude Code line: the file it is
    the content of; for a call's output, the last credential file the
    call names, else the file grep printed in front of the secret's own
    line (_GREP_LINE); otherwise nothing (typed, said, or unknown)."""
    if text.attached:
        named = _origins(json.dumps(text.attached, ensure_ascii=False))
        return named[-1] if named else None
    if text.call is not None:
        named = _named_by_input(text.call)
        return named[-1] if named else _GREP_LINE
    return None


def _store_finding(value, label):
    """A new finding, as scan_file starts one, with the keys only a
    finding from scan_sources has."""
    return {"fingerprint": _fingerprint(value), "label": label,
            "length": len(value), "hint": _hint(value), "files": set(),
            "origins": set(), "projects": set(), "count": 0,
            "sources": set(), "stores": {}, "read_only": set()}


def _held_by(entry, source, store):
    """Note in a finding that this store of this agent holds its value."""
    entry["files"].add(store.path)
    entry["sources"].add(source.id)
    entry["stores"][store.path] = source.id
    if store.masking == "read-only":
        entry["read_only"].add(store.path)
    if store.project:
        entry["projects"].add(store.project)


def scan_store(source, store, values):
    """(findings, mask fingerprints) for one store of an adapter, as
    scan_file gives them for a transcript: each value the rules find in
    it, once, with the files it was read out of. `values`
    ({fingerprint: value}) is given each value found. Never raises: an
    adapter that fails part way warns, and what it gave until then is
    kept."""
    findings = {}
    masks = set()
    origin_now = [None]
    lines_now = [None]

    def collect(value, label, text, copies):
        fp = _fingerprint(value)
        values[fp] = value
        entry = findings.get(fp)
        if entry is None:
            entry = findings[fp] = _store_finding(value, label)
            _held_by(entry, source, store)
        origin = origin_now[0]
        if origin is _GREP_LINE:
            if lines_now[0] is None or lines_now[0].text is not text:
                lines_now[0] = _GrepLines(text)
            origin = lines_now[0].origin(copies)
        if origin:
            entry["origins"].add(origin)
        entry["count"] += 1

    try:
        for text in source.secret_texts(store):
            origin_now[0] = _origin_of(text)
            lines_now[0] = None
            for _container, _key, string_ in _strings(text.node):
                if _MASK_MARK in string_:
                    masks.update(_MASKS.findall(string_))
            _walk(text.node, collect)
    except Exception as error:          # one adapter must not stop the others
        source.warn(("secrets", store.path), "could not read %s %s (%s)"
                    % (source.name, store.path, error))
    return findings, masks


# The files a search for copies reads as text. A database or a compressed
# file is searched by its adapter only.
_STORE_SEARCH_FORMATS = ("jsonl", "json", "text")


def _copies_in_stores(stores, merged, values, sources_by_id):
    """Count each value of `merged` in the files of `stores` where the
    rules did not find it: typed into a command with nothing beside it, or
    quoted in a reply. Each file is read once, as text, and each value
    looked for in every form it can take there (_rewrite.encodings), in
    the budget _copies_in_other_transcripts spends on Claude Code's.
    Databases and compressed files are not read this way."""
    from .sources import _rewrite
    order = sorted((fp for fp, f in merged.items()
                    if fp in values and f["label"] not in _SHAPE_LABELS),
                   key=lambda fp: (-len(values[fp]), fp))
    stores = [s for s in stores if s.format in _STORE_SEARCH_FORMATS]
    if not order or not stores:
        return
    size = 0
    for store in stores:
        try:
            size += os.path.getsize(store.path)
        except OSError:
            pass
    budget = min(_CROSS_SEARCH_CHARS, _CROSS_SEARCH_PER_CHAR * size)
    forms = {}
    for store in stores:
        content = None
        for fp in order:
            if store.path in merged[fp]["files"]:
                continue
            if content is None:
                try:
                    with open(store.path, "rb") as fh:
                        content = fh.read().decode("utf-8", "surrogateescape")
                except OSError:
                    break
            if fp not in forms:
                forms[fp] = _rewrite.encodings(values[fp])
            budget -= len(forms[fp]) * len(content) + _CROSS_LOOK
            if budget < 0:
                return
            if any(form in content for form in forms[fp]):
                entry = merged[fp]
                for key in ("sources", "read_only"):
                    entry.setdefault(key, set())
                entry.setdefault("stores", {})
                _held_by(entry, sources_by_id[store.source], store)
                entry["count"] += 1


def _claude_code_keys(findings):
    """Give findings from Claude Code's own scan the keys every finding
    has now: which agents hold it, in which files, and which of those
    cannot be masked (none of Claude Code's). Files in path order: in a
    set's order, the same history gave other --json on every run."""
    for entry in findings.values():
        entry.setdefault("sources", set())
        entry.setdefault("stores", {})
        entry.setdefault("read_only", set())
        for path in sorted(entry["files"]):
            if path not in entry["stores"]:
                entry["stores"][path] = "claude-code"
                entry["sources"].add("claude-code")


def scan_sources(sources=None, root=None, paths=None, since_days=None,
                 apply=False, progress=None, known=None, read=None,
                 remember=None):
    """Find (and with apply mask) the secrets in every requested agent's
    history: a Searched.

    Claude Code is read by scan, as before. Every other agent is read
    through its adapter (scan_store), OpenClaw's databases too, read only
    (design 3.9's follow-up), and a value found in one agent's
    files is looked for in the others' (_copies_in_stores, and
    _copies_in_other_transcripts for Claude Code's). A finding also says
    which agents hold it ("sources"), in which files ("stores", {path: id})
    and which of those are never rewritten ("read_only").

    With apply each value is masked where it was found, in a file its
    adapter can rewrite (Store.masking "rewrite"; mask()); a database, a
    compressed file, or one written to in the last two minutes is left as
    it is, and said so (read_only, skipped). `progress`, `known`, `read`
    and `remember` are scan's, for every agent's files: `read` is called
    with (path, its signature or os.stat, values, mask fingerprints)."""
    paths = dict(paths or {})
    root = root or paths.get("claude-code") or CLAUDE_PROJECTS
    selected = list(_registry.ids() if sources is None else sources)
    out = Searched()
    values = {}
    others = []
    for source in agents.searched(selected):
        _locations, stores = agents.discover(source, paths.get(source.id),
                                             since_days)
        if stores:                  # an agent not on this machine is not named
            others.append((source, stores))
    extra = sum(len(stores) for _source, stores in others)
    done = 0
    claude_paths = []
    if "claude-code" in selected:
        step = progress
        if progress and extra:
            def step(i, total, path):
                progress(i, total + extra, path)
        merged, scanned, changed = scan(root, since_days, apply=apply,
                                        progress=step, known=values, read=read,
                                        remember=remember)
        _claude_code_keys(merged)
        out.findings.update(merged)
        out.counts["claude-code"] = done = scanned
        out.changed += list(changed or ())
        claude_paths = discover(root, since_days) if scanned else []
    total = done + extra
    by_id = {}
    for source, stores in others:
        by_id[source.id] = source
        out.counts[source.id] = len(agents.transcripts(stores))
        out.others[source.id] = len(stores) - out.counts[source.id]
        for store in stores:
            done += 1
            if progress:
                progress(done, total, store.path)
            out.stores[store.path] = store
            signed = agents.signature(store.path, store.format)
            findings, masks = scan_store(source, store, values)
            if read is not None and signed is not None:
                read(store.path, signed,
                     {values[fp] for fp in findings}, masks)
            _merge(out.findings, findings)

    if out.findings and out.stores:
        _copies_in_stores(list(out.stores.values()), out.findings, values, by_id)
        # A value found only in another agent's files, typed or quoted in
        # a Claude Code transcript.
        elsewhere = {fp: f for fp, f in out.findings.items()
                     if "claude-code" not in f["sources"]}
        if elsewhere and claude_paths:
            if apply and remember is not None:
                remember([values[fp] for fp in elsewhere if fp in values])
            _copies_in_other_transcripts(claude_paths, elsewhere, values, apply,
                                         out.changed, remember=remember, least=1)
            _claude_code_keys(elsewhere)

    for entry in out.findings.values():
        for path in entry["read_only"]:
            store = out.stores.get(path)
            if store is not None:
                out.read_only[path] = store
    if apply:
        _mask_stores(out, values, by_id, remember)
    out.values = values
    if known is not None:
        known.update(values)
    return out


def _mask_stores(out, values, by_id, remember=None):
    """Mask, in each adapter file a finding is in, every value found there
    that the adapter lets ranwhat rewrite, and say what was left."""
    plan = {}
    for fp, entry in out.findings.items():
        for path, source_id in entry["stores"].items():
            if source_id in by_id and fp in values:
                plan.setdefault(path, []).append(values[fp])
    if not plan:
        return
    if remember is not None:
        remember(sorted({v for vals in plan.values() for v in vals}))
    for path in sorted(plan):
        store = out.stores[path]
        if store.masking != "rewrite":
            continue
        why = _mask_one(by_id[store.source], store, plan[path])
        if why is None:
            out.changed.append(path)
        elif why == "read-only":
            out.read_only[path] = store
        elif why:
            out.skipped[path] = (store.source, why)


# Why a file was not masked, as the report says it.
NOT_WRITTEN = "could not be written"


def _mask_one(source, store, values):
    """Mask values in one adapter file: None when it changed, "" when
    there was nothing to change, or why it was not masked (MaskResult's
    reasons, or NOT_WRITTEN)."""
    try:
        result = source.mask(store, values)
    except OSError as error:
        source.warn(("mask", store.path), "could not mask %s (%s)"
                    % (store.path, error.strerror or error))
        return NOT_WRITTEN
    if result.changed:
        return None
    return result.skipped or ""


# Paths on screen. The end of a path names the file, so that is what
# survives a narrow terminal, marked where it was cut, and cut at a
# separator when one is close enough not to cost most of the room.
def _path_tail(path, limit):
    room = max(0, limit - 1)
    tail = path[-room:] if room else ""
    seps = [i for i in (tail.find("/"), tail.find("\\")) if i >= 0]
    if seps and min(seps) <= room // 2:
        tail = tail[min(seps):]
    return "…" + tail


def _fit_path(path, limit, middle=False):
    """`path` in at most `limit` columns. With `middle`, the start is kept
    as well as the file name, for a transcript, whose start says which
    history it is in."""
    if len(path) <= limit:
        return path
    at = max(path.rfind("/"), path.rfind("\\"))
    room = limit - 1 - (len(path) - at)          # for the start, beside the name
    if middle and at > 0 and room >= 8:
        head = path[:room]
        cut = max(head.rfind("/"), head.rfind("\\")) + 1
        return (head[:cut] if cut > room // 2 else head) + "…" + path[at:]
    return _path_tail(path, limit)


def _home_short(path):
    """~ for the home directory, in a path the reader may type back."""
    home = os.path.expanduser("~")
    if home not in ("", "/", "~") and (path == home
                                       or path.startswith(home + os.sep)):
        return "~" + path[len(home):]
    return path


def _sentences(*sentences):
    """Short sentences on one line when they fit it, otherwise a line each,
    so a narrow terminal never strands a word on a line of its own."""
    whole = term.wrap(" ".join(sentences))
    if len(whole) <= 1:
        return whole
    return [line for s in sentences for line in term.wrap(s)]


def _painted(line, paint):
    """A wrapped line with its indent left unpainted."""
    text = line.lstrip(" ")
    return line[:len(line) - len(text)] + paint(text)


_TITLE = "  ranwhat clean  "
_TAGLINE = "· secrets sitting in local transcripts"
# Said under every "Backups:" line: a backup is the transcript as it was.
_BACKUPS_HOLD = ("They still hold every masked value.",
                 "Delete them once the transcripts look right.")
_ROTATE_WHY = ("They have been written to disk in plaintext and sat in a model "
              "context you do not control. Masking them here stops them "
              "leaking again. It does not make them safe.")


def render(findings, scanned, changed_files, applied, footer=True,
           advice=True, shown=None, others=None, read_only=None,
           skipped=None, notes=None):
    """check passes footer=False and advice=False: it prints one footer for
    all sections, and its own next step, since "Run with --apply" is wrong
    there. They gate only those lines; the rotation warning and every finding
    always print. Every line fits the terminal: prose is wrapped, a row too
    wide for one line puts its details on the next, and paths are cut.

    `shown`, when given, masks each label and path before it is printed:
    a value found may sit in another finding's key name or in the path
    another was read from (known.Matcher.mask).

    `scanned` is a count of transcripts, or what scan_sources read of each
    agent ({id: n}, Searched.counts), with `others` the other files it
    read of each (Searched.others). Then the report names each agent it
    read, and each finding the agents that hold it. `read_only`
    ({path: Store}) and `skipped` ({path: why}) are the files a finding is
    in that were not masked, and `notes` sentences to print under the
    findings."""
    from .report import painters
    BOLD, DIM, RED, YEL, GRN, CYA = painters()
    shown = shown or _as_it_is

    width = term.width()
    if len(_TITLE + _TAGLINE) <= width:
        L = ["", BOLD(_TITLE) + DIM(_TAGLINE)]
    else:
        L = ["", BOLD(_TITLE.rstrip()), DIM("  " + _TAGLINE[2:])]
    said = agents.read_words(scanned, others) if isinstance(scanned, dict) else None
    labelled = isinstance(scanned, dict) and any(
        n for source, n in list(scanned.items()) + list((others or {}).items())
        if source != "claude-code")
    if said:
        L += [DIM(term.rule("-"))] + term.wrap(said) + [""]
    else:
        count = sum(scanned.values()) if isinstance(scanned, dict) else scanned
        L += [DIM(term.rule("-")), "  %d transcript(s) scanned" % count, ""]

    notes = [DIM(line) for note in notes or () for line in term.wrap(note)]
    if not findings:
        L += ["  " + GRN("No secrets found.")]
        if notes:
            L += [""] + notes
        return "\n".join(L + [""])

    total = sum(f["count"] for f in findings.values())
    L.append("  " + RED(BOLD("%d distinct secret(s)" % len(findings)))
             + DIM(" in %d place(s)" % total))
    L.append("")
    L.append("  " + BOLD("These must be rotated."))
    L += [DIM(line) for line in term.wrap(_ROTATE_WHY)]
    L.append("")

    for f in sorted(findings.values(), key=lambda x: -x["count"]):
        meta = "%s  %d chars  seen %dx" % (f["hint"], f["length"], f["count"])
        label = shown(f["label"])
        if len("  * %s   %s" % (label, meta)) <= width:
            L.append("  " + RED("* ") + BOLD(label) + DIM("   " + meta))
        else:
            L.append("  " + RED("* ") + BOLD(_fit(label, width - 4)))
            L.append(DIM(_fit("      " + meta, width)))
        for origin in sorted(map(shown, f.get("origins") or []))[:2]:
            L.append(DIM("      read from ") + CYA(_fit_path(origin, width - 16)))
        projects = sorted(map(shown, f.get("projects") or []))
        for proj in projects[:2]:
            L.append(DIM("      in         %s" % _fit_path(proj, width - 17)))
        if len(projects) > 2:
            L.append(DIM("      in         … and %d more project(s)" % (len(projects) - 2)))
        if labelled and f.get("sources"):
            L += [DIM(line) for line in term.wrap(
                ", ".join(_agent_names(f["sources"])), indent=" " * 17,
                first="      agent      ")]
        held = [p for p in f.get("read_only") or () if p not in changed_files]
        if held:
            L.append(DIM(_fit("      read only  %s, not masked (below)"
                              % _files(len(held)), width)))
    L.append("")
    if read_only:
        L += _read_only_lines(read_only, DIM, width) + [""]

    if applied:
        L.append("  " + GRN("Masked in %d file(s)." % len(changed_files)))
        L.append(DIM("  Backups: %s" % _fit_path(_home_short(BACKUP_ROOT),
                                                 width - 11)))
        L += [DIM(line) for line in _sentences(*_BACKUPS_HOLD)]
        if skipped:
            L += _skipped_lines(skipped, YEL, width)
    elif advice:
        L.append("  " + YEL("Dry run. Nothing was changed."))
        L += [DIM(line) for line in _sentences(
            "Run with --apply to mask them.", "Backups are written first.")]
    if notes:
        if L[-1]:
            L.append("")
        L += notes
    if footer:
        if L[-1]:
            L.append("")
        L += [DIM(term.rule("-")), DIM(term.FOOTER), ""]
    return "\n".join(L)


def _files(n):
    return agents.plural(n, "file")


def _agent_names(ids):
    """Agents' names in registry order."""
    order = list(_registry.ids())
    return [agents.name(i) for i in sorted(
        ids, key=lambda i: (order.index(i) if i in order else len(order), i))]


# What an adapter's own Store says when it gives no reason of its own: the
# remedy is the agent's, not ranwhat's.
_DELETE_THERE = "To remove it, delete the session in %s."


def _read_only_lines(read_only, DIM, width):
    """Under the findings: the files that hold one and that ranwhat never
    rewrites, a sentence for each kind of them, agent by agent, and what
    to do instead."""
    from .sources.base import WHY_READ_ONLY
    groups = {}
    for path, store in read_only.items():
        why = store.why_read_only or WHY_READ_ONLY.get(store.format, "")
        if why in WHY_READ_ONLY.values():
            why += " " + _DELETE_THERE % agents.name(store.source)
        groups.setdefault((store.source, why), []).append(path)
    L = [DIM(line) for line in term.wrap(
        "Read only: ranwhat reads these files and never changes them.")]
    for (source, why), held in sorted(groups.items()):
        L += [DIM(line) for line in term.wrap(
            "%s, %s: %s" % (agents.name(source), _files(len(held)), why),
            indent="      ", first="    ")]
    return L


# What the report says of a file that was not masked, by why (MaskResult).
_NOT_MASKED = {
    "in use": "in use, not masked. Run clean --apply again once %s is "
              "closed, or two minutes after it last wrote.",
    "changed while reading": "changed while it was read, not masked. Run "
                             "clean --apply again.",
    "would alter more than the secret": "not masked: masking would have "
                                        "changed more than the secret.",
    NOT_WRITTEN: "could not be written, not masked.",
}


def _skipped_lines(skipped, YEL, width):
    """For each reason a file was not masked: how many, and what to do.
    `skipped` is {path: (source id, why)}."""
    groups = {}
    for path, (source, why) in skipped.items():
        groups.setdefault(why, []).append(source)
    L = []
    for why, held in sorted(groups.items()):
        text = _NOT_MASKED.get(why, "not masked (%s)." % why)
        if "%s" in text:
            text = text % " or ".join(_agent_names(set(held)))
        L += [_painted(line, YEL) for line in term.wrap(
            "%s %s" % (_files(len(held)), text))]
    return L


# ---------------------------------------------------------------------------
# Interactive review.
#
# Scanning a real history takes a while, and the findings are already in
# memory when the report prints. Making the user re-run the whole command to
# act on what they just read wastes that, so the session stays open.
# ---------------------------------------------------------------------------

_COMMANDS = (
    ("list", "show the findings again"),
    ("show <n>", "where that secret appears, and what it looks like"),
    ("mask <n>", "mask just that one"),
    ("mask all", "mask everything listed"),
    ("keep <n>", "leave it alone, drop it from the list"),
    ("rotate", "what to rotate, grouped by provider"),
    ("quit", "leave (nothing is masked unless you asked)"),
)


def _help():
    # Descriptions start at column 26, or as close to the commands as they
    # can when one would not fit beside them there.
    col = 26
    if any(col + len(what) > term.width() for _command, what in _COMMANDS):
        col = 4 + max(len(command) for command, _what in _COMMANDS) + 2
    L = ["  commands"]
    for command, what in _COMMANDS:
        L += term.wrap(what, indent=" " * col, first=("    " + command).ljust(col))
    return "\n".join(L) + "\n"


# Which provider a key name points at, for the rotation checklist.
_PROVIDER = [
    (re.compile(r"aws|akia|asia", re.I), "AWS: IAM console, deactivate then delete the old key"),
    (re.compile(r"openai|anthropic", re.I), "OpenAI / Anthropic: dashboard > API keys > revoke"),
    (re.compile(r"slack", re.I), "Slack: api.slack.com > your app > reinstall"),
    (re.compile(r"sendgrid", re.I), "SendGrid: Settings > API keys"),
    (re.compile(r"json web token|jwt", re.I),
     "JWT: signed by your own secret; rotate the signing secret"),
    (re.compile(r"private key", re.I), "Private key: regenerate the pair and redeploy the public half"),
    (re.compile(r"stripe|sk_live|rk_live", re.I), "Stripe: Developers > API keys > roll"),
    (re.compile(r"twilio|^ac[0-9a-f]{32}", re.I), "Twilio: Console > Account > API keys"),
    (re.compile(r"meta|facebook|pusher", re.I), "Meta / Pusher: app dashboard > regenerate"),
    (re.compile(r"github|ghp_|gho_", re.I), "GitHub: Settings > Developer settings > tokens"),
    (re.compile(r"render", re.I), "Render: Account settings > API keys"),
    (re.compile(r"turnstile|cloudflare", re.I), "Cloudflare: dashboard > the relevant service"),
    (re.compile(r"telegram", re.I), "Telegram: BotFather > /revoke"),
    (re.compile(r"database_url|postgres|redis|db_password|mongo|mysql|pgpassword|sql server",
                re.I),
     "Database: change the password, then update every consumer"),
    (re.compile(r"jwt|session|cron|app_key|signing", re.I),
     "Application secret: you generate this one; rotating invalidates sessions"),
]


def _provider_for(label):
    for pattern, advice in _PROVIDER:
        if pattern.search(label):
            return advice
    return "Unknown: find where this key lives and roll it there"


def _numbered(findings):
    return sorted(findings.values(), key=lambda x: -x["count"])


def _as_it_is(text):
    return text


def review(findings, scanned, stream=None, values=None, paths=None, shown=None,
           remember=None, stores=None):
    """Interactive review of an already-completed scan. Returns the number of
    files changed. Every line fits the terminal, as in render().

    `values`, {fingerprint: value} as scan(known=...) gives them, lets a
    mask reach the copies of a value in transcripts where the rules did
    not find it. Without them each is read back from where they did.
    `paths`, the transcripts the scan read, are where a mask looks for
    them, past where the scan counted them (_mask). `shown` masks each
    label and path before it is printed, as render's does. `remember` is
    given the values of each mask before any transcript is rewritten
    (known.Index.remember), so what a mask took the place of is known
    however the session ends. `stores` ({path: Store}, Searched.stores)
    are the other agents' files the scan read: a mask reaches a finding
    in them through each one's adapter, and one that cannot be rewritten
    is named, with what to do instead."""
    import sys as _sys
    from .report import BOLD, DIM, RED, GRN, YEL

    out = stream or _sys.stdout
    items = _numbered(findings)
    shown = shown or _as_it_is
    changed_total = 0

    def _print(text=""):
        out.write(text + "\n")

    _print(DIM("  %d finding(s). Type 'help' for commands." % len(items)))
    _print()

    while True:
        try:
            raw = input("  ranwhat> ").strip()
        except (EOFError, KeyboardInterrupt):
            _print()
            return changed_total
        if not raw:
            continue

        parts = raw.split()
        cmd, arg = parts[0].lower(), (parts[1] if len(parts) > 1 else None)
        width = term.width()

        if cmd in ("quit", "exit", "q"):
            return changed_total

        if cmd in ("help", "?"):
            _print(_help())
            continue

        if cmd == "list":
            lead = len("  %3d " % len(items))
            labels = [shown(f["label"]) for f in items]
            pad = max(map(len, labels), default=0)
            rests = ["%s %d chars, seen %dx" % (f["hint"], f["length"], f["count"])
                     for f in items]
            # One column of labels when every row fits beside it. Otherwise
            # each row's details go on the line under its label.
            aligned = all(lead + pad + 1 + len(r) <= width for r in rests)
            for i, (f, label) in enumerate(zip(items, labels), 1):
                rest = DIM(f["hint"]) + " %d chars, seen %dx" % (f["length"], f["count"])
                if aligned:
                    _print("  %s %s %s" % (BOLD("%3d" % i), label.ljust(pad), rest))
                else:
                    _print("  %s %s" % (BOLD("%3d" % i),
                                        _fit(label, width - lead)))
                    _print(" " * lead + rest)
            _print()
            continue

        if cmd == "rotate":
            groups = {}
            for f in items:
                groups.setdefault(_provider_for(f["label"]), []).append(f)
            for advice, group in sorted(groups.items()):
                for line in term.wrap(advice, indent="    ", first="  "):
                    _print(_painted(line, BOLD))
                labels = [shown(f["label"]) for f in group]
                pad = max(map(len, labels))
                seen = ["seen %dx" % f["count"] for f in group]
                aligned = all(6 + pad + 1 + len(s) <= width for s in seen)
                for label, s in zip(labels, seen):
                    if aligned:
                        _print(DIM("      %s %s" % (label.ljust(pad), s)))
                    else:
                        _print(DIM("      " + _fit(label, width - 6)))
                        _print(DIM("        " + s))
                _print()
            continue

        if cmd in ("show", "mask", "keep"):
            if cmd == "mask" and arg == "all":
                changed_total += _mask(items, scanned, _print, GRN, RED, DIM,
                                       values, paths=paths, remember=remember,
                                       stores=stores)
                items = []
                continue
            if not arg or not arg.isdigit() or not (1 <= int(arg) <= len(items)):
                _print(RED("  need a number from 1 to %d" % len(items)))
                continue
            target = items[int(arg) - 1]

            if cmd == "show":
                _print("  " + BOLD(_fit(shown(target["label"]), width - 2)))
                _print(DIM("      looks like : %s" % target["hint"]))
                _print(DIM("      length     : %d characters" % target["length"]))
                _print(DIM("      occurrences: %d" % target["count"]))
                for line in term.wrap(_provider_for(target["label"]),
                                      indent=" " * 19,
                                      first="      rotate at  : "):
                    _print(DIM(line))
                for origin in sorted(map(shown, target.get("origins") or [])):
                    _print(DIM("      read from  : ")
                           + _fit_path(origin, width - 19))
                for proj in sorted(map(shown, target.get("projects") or [])):
                    _print(DIM("      project    : %s" % _fit_path(proj, width - 19)))
                held = target.get("sources") or {"claude-code"}
                if held != {"claude-code"}:
                    for line in term.wrap(", ".join(_agent_names(held)),
                                          indent=" " * 19,
                                          first="      agent      : "):
                        _print(DIM(line))
                _print(DIM("      transcripts:" if held == {"claude-code"}
                           else "      files      :"))
                read_only = target.get("read_only") or ()
                for path in sorted(target["files"], key=shown):
                    mark = "  (read only)" if path in read_only else ""
                    _print(DIM("        %s%s" % (_fit_path(
                        shown(path), width - 8 - len(mark), middle=True), mark)))
                _print()
            elif cmd == "keep":
                items.remove(target)
                _print(DIM("  kept. %d left." % len(items)))
            else:
                changed_total += _mask([target], scanned, _print, GRN, RED, DIM,
                                       values, paths=paths, remember=remember,
                                       stores=stores)
                items.remove(target)
            continue

        _print(RED("  unknown command: %s" % _fit(cmd, width - 33))
               + DIM("  (try 'help')"))


def _mask(targets, scanned, _print, GRN, RED, DIM, values=None, paths=None,
          remember=None, stores=None):
    """Re-walk only the files that hold these secrets, masking just them.
    A file may hold a copy the rules do not find there, typed with no key
    beside it, so each value goes with the walk (scan_file's extra): read
    back first, before anything is masked, from where the rules found it.

    The scan counted a value's copies in other transcripts only until its
    search ran out of budget, and mask N left a copy it never got to. So
    with `paths`, the transcripts the scan read, these values are looked
    for in all of them again (_copies_in_other_transcripts): one value
    costs a pass over them, many share its budget.

    `remember` is given the values once they are read back, before the
    first transcript is rewritten.

    A finding in another agent's files (`stores`, {path: Store}) is masked
    there through that agent's adapter, where it can rewrite the file. A
    file it cannot rewrite is named with why and what to do instead, and
    one written to in the last two minutes is left for later."""
    stores = stores or {}
    wanted = {t["fingerprint"] for t in targets}
    everywhere = paths

    def adapter_file(path, t):
        return (t.get("stores") or {}).get(path, "claude-code") != "claude-code"
    paths, others = set(), set()
    for t in targets:
        for path in t["files"]:
            (others if adapter_file(path, t) else paths).add(path)
    paths, others = sorted(paths), sorted(others)
    known = {fp: v for fp, v in (values or {}).items() if fp in wanted}
    for path in paths:
        if len(known) == len(wanted):
            break
        found = {}
        scan_file(path, known=found)
        known.update((fp, v) for fp, v in found.items() if fp in wanted)
    for path in others:
        if len(known) == len(wanted):
            break
        store = stores.get(path)
        if store is not None:
            found = {}
            scan_store(_registry.get(store.source), store, found)
            known.update((fp, v) for fp, v in found.items() if fp in wanted)
    if remember is not None and known:
        remember(list(known.values()))

    changed = 0
    for path in paths:
        here = {t["fingerprint"] for t in targets if path in t["files"]}
        found, did = scan_file(path, apply=True, only=wanted,
                               extra={fp: v for fp, v in known.items() if fp in here})
        if did:
            changed += 1
    left = {}                       # path -> (source id, why it was not masked)
    for path in others:
        store = stores.get(path)
        here = [known[t["fingerprint"]] for t in targets
                if path in t["files"] and t["fingerprint"] in known]
        if store is None or not here:
            continue
        if store.masking != "rewrite":
            left[path] = (store.source, "read-only")
            continue
        why = _mask_one(_registry.get(store.source), store, here)
        if why is None:
            changed += 1
        elif why:
            left[path] = (store.source, why)
    if everywhere and known:
        elsewhere = []
        _copies_in_other_transcripts(
            everywhere, {t["fingerprint"]: t for t in targets}, known, True, elsewhere)
        changed += len(set(elsewhere) - set(paths))
    if changed:
        _print(GRN("  masked in %d file(s)." % changed))
        _print(DIM("  Backups: %s" % _fit_path(_home_short(BACKUP_ROOT),
                                               term.width() - 11)))
        for line in _sentences(*_BACKUPS_HOLD):
            _print(DIM(line))
    elif not left:
        _print(RED("  nothing changed."))
    read_only = {p: stores[p] for p, (_i, why) in left.items() if why == "read-only"}
    if read_only:
        if not changed:
            _print(RED("  nothing changed: every file that holds it is read only."))
        for line in _read_only_lines(read_only, DIM, term.width()):
            _print(line)
    skipped = {p: v for p, v in left.items() if v[1] != "read-only"}
    if skipped:
        for line in _skipped_lines(skipped, _as_it_is, term.width()):
            _print(DIM(line))
    return changed
