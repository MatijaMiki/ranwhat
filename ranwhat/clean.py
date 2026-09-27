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

import datetime
import hashlib
import json
import os
import re
import shutil

from .watch import CLAUDE_PROJECTS, discover

from . import fixtures, term

BACKUP_ROOT = os.path.expanduser("~/.ranwhat/backups")
REDACTION = "<ranwhat:redacted:%s>"

# Key names that make the value beside them a secret.
_SECRET_KEY = re.compile(
    r"(?:^|[_-])(?:secret|token|password|passwd|pwd|apikey|api_key|"
    r"access_key|private_key|client_secret|auth|credential|dsn|"
    r"session_secret|app_key|signing_key)s?$|"
    r"^(?:database_url|redis_url|mongodb_uri|postgres_url|db_password)$",
    re.I)

# Credential shapes that are secrets wherever they appear.
# Each shape is named, because "credential" tells you nothing about where to
# go and roll it.
_SHAPES_NAMED = [
    (re.compile(r"sk_live_[A-Za-z0-9]{12,}"), "Stripe live secret key"),
    (re.compile(r"rk_live_[A-Za-z0-9]{12,}"), "Stripe restricted key"),
    (re.compile(r"sk-[A-Za-z0-9_-]{20,}"), "OpenAI/Anthropic-style API key"),
    (re.compile(r"ghp_[A-Za-z0-9]{28,}"), "GitHub personal access token"),
    (re.compile(r"github_pat_[A-Za-z0-9_]{40,}"), "GitHub fine-grained token"),
    (re.compile(r"xox[baprs]-[A-Za-z0-9-]{20,}"), "Slack token"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS access key ID"),
    (re.compile(r"ASIA[0-9A-Z]{16}"), "AWS temporary access key"),
    (re.compile(r"AC[0-9a-f]{32}"), "Twilio account SID"),
    (re.compile(r"SG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}"), "SendGrid API key"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]+?-----END [A-Z ]*PRIVATE KEY-----"),
     "private key"),
    (re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
     "JSON Web Token"),
]

_SHAPES = [pattern for pattern, _name in _SHAPES_NAMED]

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
_KEY_START = r"(?:(?<![A-Za-z0-9_])(?!(?<=\\)[nrt])|(?<=\\[nrt]))[0-9]*"
_ASSIGN = re.compile(
    r"""(\\?["']|)""" + _KEY_START + r"""([A-Za-z_][A-Za-z0-9_]*)\1\s*[:=]\s*"""
    r"""(\\?["']|)((?:[^\s"',;}\)\\]|\\(?![nrt"\\])){8,})\3""")

# A password embedded in a connection string.
_CONN = re.compile(r"(?P<pre>[a-z][a-z0-9+.-]*://[^:/\s]+:)(?P<secret>[^@\s/]{4,})(?P<post>@)")

# Values that are deliberately not real.
_PLACEHOLDER = re.compile(
    r"^(?:<[^>]*>|\{\{.*\}\}|\$\{?[A-Z_]+\}?|x{3,}|\*{3,}|\.{3,}|-+|"
    r"(?:changeme|change[-_]me|your|placeholder|example|sample|test|dummy|"
    r"insert|replace|enter|add)[-_ ]?[\w-]*|"
    r"none|null|true|false|undefined|redacted|secret|password|todo|fixme|"
    r"ranwhat:redacted:[0-9a-f]+)$",
    re.I)


# A string can only hold a secret if it has an assignment, a connection
# string, or a known credential prefix. Most of a transcript is prose, and
# checking this first skips the regex battery on the overwhelming majority.
_CHEAP = ("=", ":", "sk_", "rk_", "sk-", "ghp_", "github_pat_", "xox",
          "AKIA", "AC", "SG.", "eyJ", "BEGIN")

# A single string longer than this is a data blob -- a build log, a base64
# payload, a file dump. Secrets in the first megabyte are still found.
MAX_STRING = 1_000_000


def _worth_scanning(text):
    return any(token in text for token in _CHEAP)


# Claude Code names a project directory by flattening its path with dashes,
# which is ambiguous the moment a directory name contains one: the slug
# -Users-me-Desktop-birthday-planner could be .../birthday-planner or
# .../birthday/planner. Resolved by asking the filesystem.
def project_path(slug):
    if not slug.startswith("-"):
        return slug
    parts = slug[1:].split("-")
    path = ""
    i = 0
    while i < len(parts):
        for take in range(len(parts) - i, 0, -1):
            candidate = path + "/" + "-".join(parts[i:i + take])
            if os.path.isdir(candidate):
                path = candidate
                i += take
                break
        else:
            # Past the part that exists on this machine, the remainder is
            # most likely one directory name that happens to contain dashes.
            path = path + "/" + "-".join(parts[i:])
            break
    return path or slug


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
_CODE = re.compile(r"[(){}\[\]`<>|\\]|=>|\$\{|\$\(")
_REFERENCE = re.compile(
    r"^(?:process\.env|os\.environ|import\.meta|this\.|self\.|window\.|"
    r"globalThis\.|config\.|env\.|Deno\.env|ENV\[)", re.I)
_PATHLIKE = re.compile(r"^(?:[~.]?/|[A-Za-z]:\\)")
_REGEXISH = re.compile(r"\.\*|\\[dwsb]|\{\d+(?:,\d*)?\}|\[[A-Za-z0-9-]+\]")
_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_MASKED = re.compile(r"\*{3,}|x{6,}|\u2026|_{6,}")


def _entropy(value):
    """Shannon entropy per character. Generated credentials sit well above
    three bits; words, names and code sit below."""
    if not value:
        return 0.0
    import math
    counts = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    n = float(len(value))
    return -sum((c / n) * math.log(c / n, 2) for c in counts.values())


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


def _looks_computed(value):
    """True when the value is code, a reference, a path or a pattern rather
    than a literal credential."""
    v = value.strip().strip("\"'")
    if _CODE.search(v) or _REFERENCE.match(v):
        return True
    if _PATHLIKE.match(v) and not _generated_not_path(v):
        return True
    if _REGEXISH.search(v) or _MASKED.search(v):
        return True
    # A bare identifier with no digits is a variable name, not a secret.
    if _IDENTIFIER.match(v) and not any(c.isdigit() for c in v) and len(v) < 40:
        return True
    return False


# `token = args.token`: a variable read off an object, which _REFERENCE only
# knows for a few fixed receivers. Deliberately narrow, because a dotted
# lowercase passphrase (password: summer.monkey) has the same letters: every
# segment starts lowercase, no digits, and the attribute must be named for
# the very thing the key is, or be read off a request's headers.
_MEMBER_CHAIN = re.compile(r"^[a-z_$][A-Za-z_]*(?:\??\.[a-z_][A-Za-z_]*)+$")
_WORDS = re.compile(r"[A-Z]?[a-z]+|[A-Z]+(?![a-z])")
_SECRET_WORDS = {"token", "secret", "password", "passwd", "pwd", "pass",
                 "key", "apikey", "auth", "authorization", "credential",
                 "credentials", "dsn", "jwt", "bearer"}


def _last_word(name):
    words = _WORDS.findall(name)
    return words[-1].lower() if words else ""


def _is_member_access(key, quote, value):
    if quote or len(value) >= 64:
        return False                  # a quoted string is a literal
    if not any(c.islower() for c in key):
        return False                  # API_TOKEN=args.token is a .env line
    if not _MEMBER_CHAIN.match(value):
        return False
    if any(p.search(value) for p in _SHAPES):
        return False                  # letters-only JWTs fit the chain too
    segments = value.replace("?.", ".").split(".")
    word = _last_word(segments[-1])
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


def _is_placeholder(value):
    v = value.strip().strip("\"'")
    pem = _PEM.match(v)
    if pem:
        return not _pem_has_body(pem.group(1))
    if len(v) < 8:
        return True
    if _PLACEHOLDER.match(v):
        return True
    if v.startswith("<ranwhat:redacted:"):
        return True
    if len(set(v)) <= 2:                      # aaaaaaaa, ********
        return True
    if _looks_computed(v):
        return True
    return False


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


def find_secrets(text):
    """Return [(secret_value, label)] found in a blob of text."""
    found = []
    if not text or len(text) < _MIN_SECRET_LEN:
        return found
    if _is_embedded_image(text):
        return found
    if not _worth_scanning(text):
        return found
    if len(text) > MAX_STRING:
        text = text[:MAX_STRING]

    for pattern, name in _SHAPES_NAMED:
        pos = 0
        while True:
            m = pattern.search(text, pos)
            if not m:
                break
            value = m.group(0)
            if _is_placeholder(value) or fixtures.is_fixture(value):
                # Resume just past the start, not the end: a fixed-length shape
                # like AKIA+16 would otherwise swallow the "AKIA" of a real key
                # glued on right after a fixture.
                pos = m.start() + 1
                continue
            found.append((value, name))
            pos = m.end()

    pos = 0
    while True:
        m = _ASSIGN.search(text, pos)
        if not m:
            break
        pos = m.end()
        key, value = m.group(2), m.group(4)
        if not _SECRET_KEY.search(key):
            if m.group(3):
                # {"stdout": "API_TOKEN=..."}: a quoted value can hold an
                # assignment of its own. Quotes end a value, so this reads
                # each one at most twice.
                pos = m.start(4)
            continue
        if _is_placeholder(value):
            continue
        if _is_member_access(key, m.group(3), value):
            continue          # code reading a variable, not a literal
        if fixtures.is_fixture(value):
            continue          # a documentation example or a test fixture
        if _entropy(value) < 3.0 and not any(p.search(value) for p in _SHAPES):
            continue          # prose or a word, not a generated credential
        found.append((value, key))

    # No fixture check here: a connection-string password is chosen by a
    # person, and "acme-example-prod" is still that person's password.
    for m in _CONN.finditer(text):
        value = m.group("secret")
        if not _is_placeholder(value):
            found.append((value, "connection string password"))

    # Longest first, so a JWT is masked before any substring of it -- and a
    # password that lives inside an already-matched connection string is not
    # reported a second time on its own. Only when it lives nowhere else: a
    # .env often repeats DB_PASSWORD inside DATABASE_URL, and dropping it for
    # that left its own line in plaintext after masking. So this replays the
    # masking in the same order and keeps what is still there to mask.
    rest, unique = text, []
    for value, label in sorted(found, key=lambda p: len(p[0]), reverse=True):
        if value not in rest:
            continue
        rest = rest.replace(value, "\0")
        unique.append((value, label))
    return unique


# How a secret looks in text shown to the reader: its hint in angle brackets,
# the way a placeholder is written, so it reads as removed and a second pass
# finds nothing to mask.
DISPLAY_MASK = "<%s>"


def mask_for_display(text):
    """`text` with every value find_secrets would report replaced by its
    hint, for printing a command or its output without printing the
    credential again. The same rules decide, so fixtures and placeholders
    are shown as they are. Every occurrence is masked, and where two found
    values overlap the whole stretch goes under one hint."""
    spans = []
    for value, _label in find_secrets(text):
        at = text.find(value)
        while at != -1:
            spans.append((at, at + len(value)))
            at = text.find(value, at + 1)
    if not spans:
        return text
    merged = []
    for lo, hi in sorted(spans):
        if merged and lo < merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], hi)
        else:
            merged.append([lo, hi])
    out, pos = [], 0
    for lo, hi in merged:
        out.append(text[pos:lo])
        out.append(DISPLAY_MASK % _hint(text[lo:hi]))
        pos = hi
    out.append(text[pos:])
    return "".join(out)


def _walk(node, collect, replace=None, only=None):
    """Visit every string in a decoded JSON structure.

    `only` limits masking to a set of fingerprints, so acting on one finding
    does not rewrite every other secret in the same file.
    """
    if isinstance(node, str):
        secrets = find_secrets(node)
        for value, label in secrets:
            collect(value, label)
        if replace and secrets:
            out = node
            for value, _ in secrets:
                if only is not None and _fingerprint(value) not in only:
                    continue
                out = out.replace(value, REDACTION % _fingerprint(value))
            return out
        return node
    if isinstance(node, list):
        return [_walk(v, collect, replace, only) for v in node]
    if isinstance(node, dict):
        return {k: _walk(v, collect, replace, only) for k, v in node.items()}
    return node


def _content_blocks(obj):
    msg = obj.get("message") if isinstance(obj, dict) else None
    content = msg.get("content") if isinstance(msg, dict) else None
    if not isinstance(content, list):
        return []
    return [b for b in content if isinstance(b, dict)]


def _origin_for_line(obj, here, recent, call_origins):
    """The credential file a secret on this line was read out of, or None.

    A tool result belongs to the call that produced it, so when the call is
    known its own input decides: the output of `ls` gets no origin just
    because `cat api/.env` ran three calls earlier. A call is judged by its
    own input the same way. Anything else (prose, attachments, formats with
    no call ids) falls back to the most recent credential path in the file.
    """
    result_ids, calls = [], False
    for block in _content_blocks(obj):
        if block.get("type") == "tool_use":
            calls = True
            if block.get("id"):
                call_origins[block["id"]] = _origins(
                    json.dumps(block.get("input"), ensure_ascii=False))
        elif block.get("type") == "tool_result":
            result_ids.append(block.get("tool_use_id"))
    if calls:
        # a secret in a call's own input goes with the paths that call names
        return here[-1] if here else None
    if result_ids and all(i in call_origins for i in result_ids):
        # grep -r output names its own file ("api/.env:KEY=..."), so the
        # result's own text counts when the call named nothing
        named = [o for i in result_ids for o in call_origins[i]] or here
        return named[-1] if named else None
    return recent[-1] if recent else None


def scan_file(path, apply=False, only=None):
    """Find (and optionally mask) secrets in one transcript.

    Returns (findings, changed). Each finding is a dict describing one
    distinct secret value and where it was seen.
    """
    findings = {}
    rewritten = []
    changed = False

    recent_origin = []          # most recent credential path seen in this file
    call_origins = {}           # tool_use id -> credential paths in its input
    origin_now = [None]         # what a secret on the current line is credited to

    def collect(value, label):
        entry = findings.setdefault(_fingerprint(value), {
            "fingerprint": _fingerprint(value),
            "label": label,
            "length": len(value),
            "hint": _hint(value),
            "files": set(),
            "origins": set(),
            "projects": set(),
            "count": 0,
        })
        entry["files"].add(path)
        entry["projects"].add(project_path(os.path.basename(os.path.dirname(path))))
        if origin_now[0]:
            entry["origins"].add(origin_now[0])
        entry["count"] += 1

    # UTF-8 whatever the locale says: Windows would otherwise decode as
    # cp1252 and write the mojibake back. newline="" hands each line over
    # with its own ending, so a rewrite keeps \r\n where it found \r\n.
    try:
        with open(path, "r", encoding="utf-8", errors="replace",
                  newline="") as fh:
            for line in fh:
                stripped = line.strip()
                if not stripped:
                    rewritten.append(line)
                    continue
                try:
                    obj = json.loads(stripped)
                except ValueError:
                    rewritten.append(line)
                    continue
                here = _origins(stripped)
                recent_origin.extend(here)
                del recent_origin[:-4]
                origin_now[0] = _origin_for_line(obj, here, recent_origin,
                                                 call_origins)
                new = _walk(obj, collect, replace=apply, only=only)
                if apply and new != obj:
                    changed = True
                    ending = line[len(line.rstrip("\r\n")):]
                    rewritten.append(json.dumps(new, ensure_ascii=False) + ending)
                else:
                    rewritten.append(line)
    except OSError:
        return {}, False

    if apply and changed:
        _backup(path)
        tmp = path + ".ranwhat-tmp"
        try:
            _write_like(path, tmp, rewritten)
            # refuse to install a file we cannot read back
            with open(tmp, encoding="utf-8") as fh:
                for line in fh:
                    if line.strip():
                        json.loads(line)
            os.replace(tmp, path)
        finally:
            if os.path.lexists(tmp):
                os.unlink(tmp)

    return findings, changed


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


def _backup(path):
    """Copy the unmasked transcript aside before rewriting it.

    The backup holds every secret the rewrite removes, so it is written the
    way a secret should be: 0600, under a 0700 root nobody else can list.
    copy2 used to carry the source's mode across and makedirs left the tree
    0755. Microseconds in the stamp, and O_EXCL, keep two masks in the same
    second from overwriting the true original with a half-masked copy."""
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    os.makedirs(BACKUP_ROOT, mode=0o700, exist_ok=True)
    os.chmod(BACKUP_ROOT, 0o700)
    dest = os.path.join(BACKUP_ROOT, stamp, path.lstrip("/"))
    os.makedirs(os.path.dirname(dest), mode=0o700, exist_ok=True)
    fd = os.open(dest, _CREATE, 0o600)
    with open(path, "rb") as src, os.fdopen(fd, "wb") as out:
        shutil.copyfileobj(src, out)
    return dest


def scan(root=CLAUDE_PROJECTS, since_days=None, apply=False, progress=None):
    """Scan every transcript. Returns (merged_findings, files_scanned, files_changed).

    `progress` is called with (index, total, path) before each file. A large
    history takes a couple of minutes, and a run that prints nothing for that
    long is indistinguishable from one that has hung.
    """
    merged, scanned, changed_files = {}, 0, []
    paths = discover(root, since_days)
    for index, path in enumerate(paths, 1):
        if progress:
            progress(index, len(paths), path)
        scanned += 1
        findings, changed = scan_file(path, apply=apply)
        if changed:
            changed_files.append(path)
        for fp, entry in findings.items():
            if fp in merged:
                merged[fp]["files"] |= entry["files"]
                merged[fp]["origins"] |= entry["origins"]
                merged[fp]["projects"] |= entry["projects"]
                merged[fp]["count"] += entry["count"]
            else:
                merged[fp] = entry
    return merged, scanned, changed_files


def render(findings, scanned, changed_files, applied, footer=True,
           advice=True):
    """check passes footer=False and advice=False: it prints one footer for
    all sections, and its own next step, since "Run with --apply" is wrong
    there. They gate only those lines; the rotation warning and every finding
    always print."""
    from .report import BOLD, DIM, RED, YEL, GRN, CYA

    L = ["", BOLD("  ranwhat clean  ") + DIM("· secrets sitting in local transcripts"),
         DIM(term.rule("-")),
         "  %d transcript(s) scanned" % scanned, ""]

    if not findings:
        L += ["  " + GRN("No secrets found."), ""]
        return "\n".join(L)

    total = sum(f["count"] for f in findings.values())
    L.append("  " + RED(BOLD("%d distinct secret(s)" % len(findings)))
             + DIM(" in %d place(s)" % total))
    L.append("")
    L.append("  " + BOLD("These must be rotated."))
    for line in ("They have been written to disk in plaintext and sat in a model",
                 "context you do not control. Masking them here stops them leaking",
                 "again. It does not make them safe."):
        L.append(DIM("  " + line))
    L.append("")

    for f in sorted(findings.values(), key=lambda x: -x["count"]):
        L.append("  " + RED("* ") + BOLD(f["label"])
                 + DIM("   %s  %d chars  seen %dx" % (f["hint"], f["length"], f["count"])))
        for origin in sorted(f.get("origins") or [])[:2]:
            L.append(DIM("      read from ") + CYA(origin))
        projects = sorted(f.get("projects") or [])
        for proj in projects[:2]:
            L.append(DIM("      in         %s" % proj))
        if len(projects) > 2:
            L.append(DIM("      in         … and %d more project(s)" % (len(projects) - 2)))
    L.append("")

    if applied:
        L.append("  " + GRN("Masked in %d file(s)." % len(changed_files)))
        L.append(DIM("  Backups: %s" % BACKUP_ROOT))
        L.append(DIM("  They still hold every masked value. Delete them once"
                     " the transcripts look right."))
    elif advice:
        L.append("  " + YEL("Dry run. Nothing was changed."))
        L.append(DIM("  Run with --apply to mask them. Backups are written first."))
    if footer:
        if L[-1]:
            L.append("")
        L += [DIM(term.rule("-")), DIM(term.FOOTER), ""]
    return "\n".join(L)


# ---------------------------------------------------------------------------
# Interactive review.
#
# Scanning a real history takes a while, and the findings are already in
# memory when the report prints. Making the user re-run the whole command to
# act on what they just read wastes that, so the session stays open.
# ---------------------------------------------------------------------------

HELP = """  commands
    list                  show the findings again
    show <n>              where that secret appears, and what it looks like
    mask <n>              mask just that one
    mask all              mask everything listed
    keep <n>              leave it alone, drop it from the list
    rotate                what to rotate, grouped by provider
    quit                  leave (nothing is masked unless you asked)
"""

# Which provider a key name points at, for the rotation checklist.
_PROVIDER = [
    (re.compile(r"aws|akia|asia", re.I), "AWS — IAM console, deactivate then delete the old key"),
    (re.compile(r"openai|anthropic", re.I), "OpenAI / Anthropic — dashboard > API keys > revoke"),
    (re.compile(r"slack", re.I), "Slack — api.slack.com > your app > reinstall"),
    (re.compile(r"sendgrid", re.I), "SendGrid — Settings > API keys"),
    (re.compile(r"json web token|jwt", re.I),
     "JWT — signed by your own secret; rotate the signing secret"),
    (re.compile(r"private key", re.I), "Private key — regenerate the pair and redeploy the public half"),
    (re.compile(r"stripe|sk_live|rk_live", re.I), "Stripe — Developers > API keys > roll"),
    (re.compile(r"twilio|^ac[0-9a-f]{32}", re.I), "Twilio — Console > Account > API keys"),
    (re.compile(r"meta|facebook|pusher", re.I), "Meta / Pusher — app dashboard > regenerate"),
    (re.compile(r"github|ghp_|gho_", re.I), "GitHub — Settings > Developer settings > tokens"),
    (re.compile(r"render", re.I), "Render — Account settings > API keys"),
    (re.compile(r"turnstile|cloudflare", re.I), "Cloudflare — dashboard > the relevant service"),
    (re.compile(r"telegram", re.I), "Telegram — BotFather > /revoke"),
    (re.compile(r"database_url|postgres|redis|db_password|mongo", re.I),
     "Database — change the password, then update every consumer"),
    (re.compile(r"jwt|session|cron|app_key|signing", re.I),
     "Application secret — you generate this one; rotating invalidates sessions"),
]


def _provider_for(label):
    for pattern, advice in _PROVIDER:
        if pattern.search(label):
            return advice
    return "Unknown — find where this key lives and roll it there"


def _numbered(findings):
    return sorted(findings.values(), key=lambda x: -x["count"])


def review(findings, scanned, stream=None):
    """Interactive review of an already-completed scan. Returns the number of
    files changed."""
    import sys as _sys
    from .report import BOLD, DIM, RED, GRN, YEL

    out = stream or _sys.stdout
    items = _numbered(findings)
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

        if cmd in ("quit", "exit", "q"):
            return changed_total

        if cmd in ("help", "?"):
            _print(HELP)
            continue

        if cmd == "list":
            for i, f in enumerate(items, 1):
                _print("  %s %-24s %s %d chars, seen %dx"
                       % (BOLD("%3d" % i), f["label"], DIM(f["hint"]),
                          f["length"], f["count"]))
            _print()
            continue

        if cmd == "rotate":
            groups = {}
            for f in items:
                groups.setdefault(_provider_for(f["label"]), []).append(f)
            for advice, group in sorted(groups.items()):
                _print("  " + BOLD(advice))
                for f in group:
                    _print(DIM("      %-24s seen %dx" % (f["label"], f["count"])))
                _print()
            continue

        if cmd in ("show", "mask", "keep"):
            if cmd == "mask" and arg == "all":
                changed_total += _mask(items, scanned, _print, GRN, RED)
                items = []
                continue
            if not arg or not arg.isdigit() or not (1 <= int(arg) <= len(items)):
                _print(RED("  need a number from 1 to %d" % len(items)))
                continue
            target = items[int(arg) - 1]

            if cmd == "show":
                _print("  " + BOLD(target["label"]))
                _print(DIM("      looks like : %s" % target["hint"]))
                _print(DIM("      length     : %d characters" % target["length"]))
                _print(DIM("      occurrences: %d" % target["count"]))
                _print(DIM("      rotate at  : %s" % _provider_for(target["label"])))
                for origin in sorted(target.get("origins") or []):
                    _print(DIM("      read from  : ") + origin)
                for proj in sorted(target.get("projects") or []):
                    _print(DIM("      project    : %s" % proj))
                _print(DIM("      transcripts:"))
                for path in sorted(target["files"]):
                    _print(DIM("        %s" % path))
                _print()
            elif cmd == "keep":
                items.remove(target)
                _print(DIM("  kept. %d left." % len(items)))
            else:
                changed_total += _mask([target], scanned, _print, GRN, RED)
                items.remove(target)
            continue

        _print(RED("  unknown command: %s" % cmd) + DIM("  (try 'help')"))


def _mask(targets, scanned, _print, GRN, RED):
    """Re-walk only the files that hold these secrets, masking just them."""
    wanted = {t["fingerprint"] for t in targets}
    paths = set()
    for t in targets:
        paths |= set(t["files"])

    changed = 0
    for path in sorted(paths):
        found, did = scan_file(path, apply=True, only=wanted)
        if did:
            changed += 1
    if changed:
        _print(GRN("  masked in %d file(s)." % changed)
               + (" Backups: %s" % BACKUP_ROOT))
        _print(DIM("  They still hold every masked value. Delete them once"
                   " the transcripts look right."))
    else:
        _print(RED("  nothing changed."))
    return changed
