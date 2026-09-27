"""
Is this credential-shaped value an obvious fixture or a published example?

Shared by clean and watch, so the two commands agree on what is not a real
secret. AWS's own documentation key, a test file's AKIA1234567890ABCDEF and an
alphabet typed after sk_live_ were all reported as live leaks, in both
commands, and a finding that is never real teaches people to skip the report.

The failure that matters is the other one: hiding a real key. So every rule
here is written to fail towards flagging.

- Published documentation values match exactly, never by prefix or stem.
- Statistics (sequential runs, repeated chunks) apply only to
  provider-generated formats, recognised by a full match on a fixed prefix.
  A human-chosen password that happens to be abcdefgh12345678 is weak, but it
  is still a password, so free-form values never get them. They get only the
  documentation list, a capitalised EXAMPLE, and "my_example_..." wording,
  and only when too little else is left to be a secret.
- A signal must cover most of every key-length window of the value. A real
  key with a run or EXAMPLE appended, prepended or overlapping one edge still
  has a window that is the real key, and that window is unexplained.
"""

from __future__ import annotations

import functools
import re

# Published vendor documentation examples: full-value matches only. The AWS
# stems (AKIAIOSFODNN7...) are deliberately not matched on their own, because
# AKIAIOSFODNN7REALKEY is not a published value.
_DOC_EXAMPLES = (
    "AKIAIOSFODNN7EXAMPLE",
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "AKIAI44QH8DHBEXAMPLE",
    "je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY",
)
_DOCS = frozenset(v.casefold() for v in _DOC_EXAMPLES)
# The part of each documentation value before its EXAMPLE marker. Counted
# only alongside the marker itself, for edited copies of the doc secret key.
_DOC_STEMS = tuple(re.compile(re.escape(v[:v.index("EXAMPLE")]))
                   for v in _DOC_EXAMPLES)

# Provider formats whose bodies are generated, never typed by a person.
# (name, full-match regex with a body group, minimum real body length, kind)
#
# The body is everything after the fixed prefix, never a sub-segment: judging
# only Slack's final dash segment let "<real token>-EXAMPLE" hide a real one.
#
# The minimum is the window size for the verdict below. Where the real length
# is uncertain (github_pat_, Slack, SendGrid) it is set low, which only makes
# suppression harder.
#
# "sk-" is absent on purpose: LiteLLM and similar proxies require user-chosen
# keys to start with it, so the prefix is no evidence the body was generated.
# JWT and PEM are absent because their contents are structured.
_FORMATS = (
    ("aws", re.compile(r"(?:AKIA|ASIA)(?P<body>[A-Z0-9]{16})"), 16, "aws"),
    ("stripe", re.compile(r"(?:sk|rk)_live_(?P<body>[A-Za-z0-9]+)"), 24, "b62"),
    ("github", re.compile(r"gh[pousr]_(?P<body>[A-Za-z0-9]+)"), 36, "b62"),
    ("github_pat", re.compile(r"github_pat_(?P<body>[A-Za-z0-9_]+)"), 40, "b62"),
    ("slack", re.compile(r"xox[baprs]-(?P<body>[A-Za-z0-9-]+)"), 20, "b62"),
    ("twilio", re.compile(r"AC(?P<body>[0-9a-f]{32})"), 32, "hex"),
    ("sendgrid", re.compile(r"SG\.(?P<body>[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)"), 40, "b62"),
)

# Minimum length of a sequential run, and of the repeated stretch of a
# periodic chunk. The chance a random character continues a run is about
# 1/32 for base32, 2/62 for mixed-case base62 (either case of the next
# letter), 1/16 for hex. Union bound for a run somewhere in n characters:
# 2(n-L+1)p^(L-1). AWS n=16, L=8: 5e-10. Stripe n=24: 1e-9. GitHub n=36:
# 2e-9. Hex n=32, L=10: 7e-10. Hex bodies under a base62 row (a Slack
# token's hex tail) are bounded by the window rule instead.
_RUN = {"aws": 8, "b62": 8, "hex": 10}
_PERIOD_MAX = 8

# A key-length window counts as explained only if at least this many of its
# characters are. Below one full signal (8), so a genuine fixture passes;
# above what an attacker can borrow from a real key's edge by appending a run
# or a copy that happens to continue it (one or two characters).
_MIN_EXPLAINED = 7

# Statistics are skipped past this length: nothing real is this long, the
# check stays linear, and the answer is to keep flagging.
_MAX_BODY = 512

# Free-form values may be human-chosen. Only EXAMPLE in capitals counts as a
# marker there ("MyExample#2024Pass" and "acme-example-prod" are passwords),
# and only when too little else is left to be a secret on its own.
_FREEFORM_REST = 12
_EXAMPLE_CAPS = re.compile(r"EXAMPLE")
_EXAMPLE_ANY = re.compile(r"example", re.I)
# "my_example_token_9f8e7d": a placeholder phrase, the way _PLACEHOLDER in
# clean already treats "example_..." and "your_...".
_PHRASE = re.compile(r"(?:my|our|the|an?|some)[-_]example(?:[-_][A-Za-z0-9_-]*)?", re.I)

# AWS key IDs are base32 (A-Z, 2-7). Body characters 0-7, and one bit of
# character 8, encode the account ID, so a run that lands there would repeat
# in every key that account ever issues: a permanent miss that no
# uniform-random test can reveal. A signal there counts only if it also holds
# a character a real key ID cannot contain.
_AWS_IMPOSSIBLE = frozenset("0189")
_AWS_RANDOM_FROM = 8


def _normalise(value):
    v = value.strip().strip("\"'").strip()
    # Sentence punctuation after a pasted key. Never "=", "/" or "+", which
    # are part of base64 values.
    return v.rstrip(".,;:")


def _step(a, b):
    """+1 or -1 when b follows a in 0-9 or in a-z (any case), else 0."""
    if a.isdigit() and b.isdigit():
        d = ord(b) - ord(a)
    elif a.isascii() and b.isascii() and a.isalpha() and b.isalpha():
        d = ord(b.lower()) - ord(a.lower())
    else:
        return 0
    return d if d in (1, -1) else 0


def _runs(body, min_len):
    """Spans of consecutive characters stepping by one in a single direction:
    0123456789, abcdefgh, AbCdEfGh."""
    spans, start, direction = [], 0, 0
    for i in range(1, len(body)):
        d = _step(body[i - 1], body[i])
        if d and direction in (0, d):
            direction = d
            continue
        if i - start >= min_len:
            spans.append((start, i))
        # A run broken by a turn starts again at the previous character.
        start, direction = (i - 1, d) if d else (i, 0)
    if len(body) - start >= min_len:
        spans.append((start, len(body)))
    return spans


def _repeats(body, min_len):
    """Interior of periodic stretches, e.g. Ab12Ab12Ab12...

    The first and last period are never counted. Otherwise a copy of a real
    key's first or last chunk, placed beside it, would mark the real key's
    own characters as explained.
    """
    spans = []
    n = len(body)
    for q in range(1, _PERIOD_MAX + 1):
        i = q
        while i < n:
            if body[i] != body[i - q]:
                i += 1
                continue
            j = i
            while j < n and body[j] == body[j - q]:
                j += 1
            # The periodic region is [i - q, j); its interior drops a period
            # from each end.
            lo, hi = i, j - q
            if hi - lo >= min_len:
                spans.append((lo, hi))
            i = j
    return spans


def _markers(body):
    return [(m.start(), m.end()) for m in _EXAMPLE_ANY.finditer(body)]


def _aws_gate(body, spans):
    out = []
    for lo, hi in spans:
        if any(c in _AWS_IMPOSSIBLE for c in body[lo:hi]):
            out.append((lo, hi))
        elif hi > _AWS_RANDOM_FROM:
            out.append((max(lo, _AWS_RANDOM_FROM), hi))
    return out


def _generated_reason(body, min_len, kind):
    if len(body) > _MAX_BODY:
        return None
    signals = (("EXAMPLE marker", _markers(body)),
               ("sequential run", _runs(body, _RUN[kind])),
               ("repeated chunk", _repeats(body, _RUN[kind])))
    explained = [False] * len(body)
    reasons = []
    for reason, spans in signals:
        if kind == "aws":
            spans = _aws_gate(body, spans)
        for lo, hi in spans:
            for k in range(lo, hi):
                explained[k] = True
        if spans:
            reasons.append(reason)
    if not reasons:
        return None
    # Every window as long as a real key must be mostly explained. A real key
    # sits in one such window whatever is appended or prepended to it.
    w = min(min_len, len(body))
    count = sum(explained[:w])
    if count < _MIN_EXPLAINED:
        return None
    for i in range(w, len(body)):
        count += explained[i] - explained[i - w]
        if count < _MIN_EXPLAINED:
            return None
    return " + ".join(reasons)


def _freeform_reason(v):
    if "://" in v:
        # A URL is judged by its parts: clean reads the password out of it.
        return None
    if _PHRASE.fullmatch(v):
        rest = v[v.lower().index("example") + len("example"):]
        if sum(c.isalnum() for c in rest) < _FREEFORM_REST:
            return "placeholder wording"
    if "EXAMPLE" not in v:
        return None
    explained = [False] * len(v)
    for pattern in (_EXAMPLE_CAPS,) + _DOC_STEMS:
        for m in pattern.finditer(v):
            for k in range(m.start(), m.end()):
                explained[k] = True
    rest = sum(1 for k, c in enumerate(v) if c.isalnum() and not explained[k])
    if rest < _FREEFORM_REST:
        return "EXAMPLE marker"
    return None


@functools.lru_cache(maxsize=4096)
def fixture_reason(value):
    """Why this value is a fixture or documentation example, or None.

    None means "treat it as real".
    """
    if not value:
        return None
    v = _normalise(value)
    if v.casefold() in _DOCS:
        return "published documentation example"
    for _name, pattern, min_len, kind in _FORMATS:
        m = pattern.fullmatch(v)
        if m:
            return _generated_reason(m.group("body"), min_len, kind)
    return _freeform_reason(v)


def is_fixture(value):
    return fixture_reason(value) is not None
