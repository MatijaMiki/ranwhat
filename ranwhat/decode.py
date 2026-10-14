"""
Inert decoding: what a command hides in an encoding, read and never run.

watch's exec.encoded rule uses this to see through the common encodings that
carry a command past the rules that read its text: base64, base32 and hex,
printf escapes and reversed text, and a PowerShell -EncodedCommand. A
decoder here only turns text into bytes. Nothing it is given is evaluated,
compiled, imported or opened as a path, and none of it raises on any string:
what cannot be decoded strictly is None, which the caller reads as "not
decodable", never as an error.

Every limit is a length, so the work is bounded by the input: a literal past
MAX_ENCODED_CHARS, a result past MAX_DECODED_BYTES and a chain past
MAX_LEVELS decode to nothing.

Imports nothing from ranwhat: watch imports this, never the reverse.
"""

from __future__ import annotations

import base64
import re
from typing import Optional, Sequence, Tuple

MAX_ENCODED_CHARS = 64 * 1024     # a literal this long or longer is not read
MAX_DECODED_BYTES = 64 * 1024
MAX_LEVELS = 2                    # decode operations along one path
MIN_ESCAPES = 2                   # printable escapes that make printf a decoder

LABELS = {"base64": "base64", "base64url": "base64 (URL-safe)",
          "base32": "base32", "hex": "hex", "printf": "printf escapes",
          "rev": "reversed text", "utf16b64": "PowerShell base64"}

# Where a one-liner's source is read to: the same cut watch makes.
_SOURCE_CHARS = 64000

_LINE_BREAKS = re.compile(r"[\r\n]+")
_BASE64 = re.compile(r"[A-Za-z0-9+/]+={0,2}")
_BASE64_URL = re.compile(r"[A-Za-z0-9_-]+={0,2}")
_BASE32 = re.compile(r"[A-Z2-7]+={0,6}")
_HEX = re.compile(r"(?:[0-9A-Fa-f]{2})+")
_BLANKS = re.compile(r"\s+")
# What is not text: control characters other than tab, newline and return.
_BINARY = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def base64_bytes(text: str, urlsafe: bool = False) -> Optional[bytes]:
    """The bytes a strict base64 decoder gives for text, or None. Only line
    breaks are removed: a space inside, a missing or extra pad and a
    character of the other alphabet are what `base64 -d` rejects or
    garbles, and a payload it would not run is not judged as if it ran."""
    try:
        s = _LINE_BREAKS.sub("", text)
        if not 4 <= len(s) < MAX_ENCODED_CHARS or len(s) % 4:
            return None
        if not (_BASE64_URL if urlsafe else _BASE64).fullmatch(s):
            return None
        if urlsafe:
            return base64.urlsafe_b64decode(s)
        return base64.b64decode(s, validate=True)
    except Exception:
        return None


def base32_bytes(text: str) -> Optional[bytes]:
    try:
        s = _LINE_BREAKS.sub("", text)
        if not 8 <= len(s) < MAX_ENCODED_CHARS or len(s) % 8:
            return None
        if not _BASE32.fullmatch(s):
            return None
        return base64.b32decode(s)
    except Exception:
        return None


def hex_bytes(text: str) -> Optional[bytes]:
    try:
        s = _BLANKS.sub("", text)
        if not 2 <= len(s) < MAX_ENCODED_CHARS or not _HEX.fullmatch(s):
            return None
        return bytes.fromhex(s)
    except Exception:
        return None


# printf's and echo -e's escapes, in one pass. The alternatives start with
# different characters, so the regex skips plain text in C and never reads a
# stretch twice.
_ESCAPE = re.compile(
    r"\\(?:x([0-9A-Fa-f]{1,2})|u([0-9A-Fa-f]{4})|U([0-9A-Fa-f]{8})"
    r"|0?([0-7]{1,3})|([\\abefnrtv'\"?])|([\s\S]))|(%%?)")
_SIMPLE_ESCAPES = {"a": 7, "b": 8, "e": 27, "f": 12, "n": 10, "r": 13,
                   "t": 9, "v": 11}


def unescape(fmt: str) -> Tuple[Optional[bytes], int]:
    """(bytes, count) of what printf would print for the format `fmt`.
    bytes is None where it holds a conversion other than %% (its value is
    an argument), or a code point that is no character. count is the number
    of hex, octal and unicode escapes in it that stand for a printable ASCII
    byte: the ones that spell out letters, where \\033 and \\n only format."""
    try:
        if len(fmt) > MAX_ENCODED_CHARS:
            return None, 0
        out, pos, printable, bad = bytearray(), 0, 0, False
        for m in _ESCAPE.finditer(fmt):
            out += fmt[pos:m.start()].encode("utf-8", "surrogatepass")
            pos = m.end()
            hexa, u4, u8, octal, simple, other, percent = m.groups()
            if hexa is not None or octal is not None:
                value = int(hexa, 16) if hexa is not None else int(octal, 8) & 255
                out.append(value)
                if 0x20 <= value <= 0x7e:
                    printable += 1
            elif u4 is not None or u8 is not None:
                code = int(u4 or u8, 16)
                if code > 0x10FFFF or 0xD800 <= code <= 0xDFFF:
                    bad = True
                    printable += 1
                else:
                    out += chr(code).encode("utf-8")
                    if 0x20 <= code <= 0x7e:
                        printable += 1
            elif simple is not None:
                if simple in _SIMPLE_ESCAPES:
                    out.append(_SIMPLE_ESCAPES[simple])
                else:
                    out += simple.encode("utf-8")
            elif other is not None:
                out += ("\\" + other).encode("utf-8", "surrogatepass")
            elif percent == "%%":
                out.append(37)
            else:
                bad = True
        out += fmt[pos:].encode("utf-8", "surrogatepass")
        return (None if bad else bytes(out)), printable
    except Exception:
        return None, 0


def reverse_lines(text: str) -> Optional[bytes]:
    """What `rev` prints for text: each line reversed."""
    try:
        if len(text) > MAX_ENCODED_CHARS:
            return None
        return "\n".join(line[::-1] for line in text.split("\n")).encode(
            "utf-8", "surrogatepass")
    except Exception:
        return None


def utf16_base64(text: str) -> Optional[bytes]:
    """PowerShell's -EncodedCommand: base64 of UTF-16LE text, as UTF-8."""
    raw = base64_bytes(text)
    if raw is None:
        return None
    try:
        return raw.decode("utf-16-le").encode("utf-8")
    except Exception:
        return None


def text_of(data: Optional[bytes]) -> Optional[str]:
    """data as text a person could have typed, or None: strict UTF-8, no
    control characters but tab, newline and return, not blank, and no more
    than MAX_DECODED_BYTES. Binary and non-UTF-8 payloads are not text."""
    if data is None or len(data) > MAX_DECODED_BYTES:
        return None
    try:
        text = data.decode("utf-8")
    except Exception:
        return None
    if _BINARY.search(text) or not text.strip():
        return None
    return text


def decode_step(kind: str, text: str) -> Optional[bytes]:
    """One decoding of text, by kind, or None."""
    try:
        if kind == "base64":
            return base64_bytes(text)
        if kind == "base64url":
            return base64_bytes(text, urlsafe=True)
        if kind == "base32":
            return base32_bytes(text)
        if kind == "hex":
            return hex_bytes(text)
        if kind == "printf":
            return unescape(text)[0]
        if kind == "rev":
            return reverse_lines(text)
        if kind == "utf16b64":
            return utf16_base64(text)
    except Exception:
        return None
    return None


def decode_via(kinds: Sequence[str], literal: Optional[str]) -> Optional[str]:
    """The text literal decodes to through the decoders in kinds, in order, or
    None. Each stage between must itself be text: it is what the next one
    reads."""
    try:
        if literal is None or not kinds or len(kinds) > MAX_LEVELS:
            return None
        current = literal
        data = None
        for kind in kinds:
            data = decode_step(kind, current)
            if data is None or len(data) > MAX_DECODED_BYTES:
                return None
            current = data.decode("utf-8")
        return text_of(data)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# One-liner source: python -c, perl -e, node -e, ruby -e, php -r.
#
# A decoded value handed to a call that runs or evaluates it, inside that
# call's own parentheses. The source is tokenised once: strings and comments
# are skipped as units, so a name inside one is no code, and every other
# token is a name or a bracket. Nothing here parses a language; it keeps two
# numbers (how deep the innermost sink's parenthesis and the innermost other
# bracket are), which a stack restores at each close, so the cost is the
# number of tokens however deeply the brackets nest.
# ---------------------------------------------------------------------------

_TOKEN = re.compile(
    r"""(?P<string>'(?:[^'\\]|\\[\s\S])*'?|"(?:[^"\\]|\\[\s\S])*"?"""
    r"""|`(?:[^`\\]|\\[\s\S])*`?)"""
    r"""|(?P<comment>\#[^\n]*|//[^\n]*|/\*[\s\S]*?(?:\*/|\Z))"""
    r"""|(?P<name>[A-Za-z_$][\w$]*)"""
    r"""|(?P<open>[(\[{])|(?P<close>[)\]}])""")

# Calls that run what they are given, by exact name.
_SINKS = frozenset((
    "exec", "eval", "system", "popen", "spawn", "execSync", "execFile",
    "spawnSync", "Function", "runInThisContext", "runInNewContext",
    "shell_exec", "passthru", "proc_open", "check_output", "check_call",
    "getoutput", "getstatusoutput"))
_SUBPROCESS_CALLS = frozenset(("run", "call", "Popen", "check_output",
                               "check_call", "getoutput"))
_DECODERS = {
    "b64decode": "base64", "standard_b64decode": "base64",
    "decodebytes": "base64", "decodestring": "base64",
    "a2b_base64": "base64", "base64_decode": "base64",
    "decode_base64": "base64", "decode64": "base64",
    "strict_decode64": "base64", "atob": "base64",
    "FromBase64String": "base64",
    "urlsafe_b64decode": "base64url", "urlsafe_decode64": "base64url",
    "b32decode": "base32",
    "fromhex": "hex", "unhexlify": "hex", "a2b_hex": "hex", "hex2bin": "hex"}
_NODE_ENCODINGS = {"base64": "base64", "base64url": "base64", "hex": "hex"}
_LITERAL_DECODERS = {"base64": base64_bytes, "hex": hex_bytes,
                     "base64url": lambda s: base64_bytes(s, urlsafe=True),
                     "base32": base32_bytes}
_MAX_STRINGS = 64
_MIN_LITERAL = 8


def scan_source(source: str) -> Optional[Tuple[str, Optional[str]]]:
    """(kind, literal) when source hands a decoded value to a call that runs
    it, or None. literal is the first string in the source of the length of
    a payload that kind decodes to text, None when there is none."""
    try:
        return _scan_source(source[:_SOURCE_CHARS])
    except Exception:
        return None


def _scan_source(source):
    stack = []            # (opened a sink call, opened a [ or {, saved depths)
    last_sink = last_bracket = -1
    pending = False       # the last token was a sink's name
    previous = ""         # the last name
    buffer_seen = False
    kind = None
    strings = []
    count = 0
    for m in _TOKEN.finditer(source):
        group = m.lastgroup
        if group == "comment":
            continue
        text = m.group()
        if group == "string":
            count += 1
            body = text[1:-1] if len(text) > 1 and text[-1] == text[0] else text[1:]
            if count <= _MAX_STRINGS and _MIN_LITERAL <= len(body) < MAX_ENCODED_CHARS:
                strings.append(body)
            pending = False
            if (kind is None and buffer_seen and body in _NODE_ENCODINGS
                    and last_sink > last_bracket):
                kind = _NODE_ENCODINGS[body]
            continue
        if group == "name":
            inside = last_sink > last_bracket
            if pending and text in _DECODERS and kind is None:
                kind = _DECODERS[text]      # eval decode_base64(...)
            elif inside and text in _DECODERS and kind is None:
                kind = _DECODERS[text]
            if text == "Buffer":
                buffer_seen = True
            pending = (text in _SINKS or
                       (previous == "subprocess" and text in _SUBPROCESS_CALLS))
            previous = text
            continue
        previous = ""
        if group == "open":
            sink = pending and text == "("
            pending = False
            stack.append((last_sink, last_bracket))
            if sink:
                last_sink = len(stack) - 1
            elif text != "(":
                last_bracket = len(stack) - 1
            continue
        pending = False
        if stack:
            last_sink, last_bracket = stack.pop()
    if kind is None:
        return None
    check = _LITERAL_DECODERS.get(kind)
    for body in strings:
        if check is not None and text_of(check(body)) is not None:
            return kind, body
    return kind, None
