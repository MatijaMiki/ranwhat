"""Where a flagged command's words were seen before it ran.

A watch record says what ran. This adds the question a reader asks next:
did the agent get this from somewhere? When a long, distinctive piece of the
flagged call (a URL, a host, a path, a package name) also appears earlier in
the same session, in a tool's output or in the user's own message, the record
says so and names the nearest such place.

This reports a shared piece of text, not a cause. The agent may have
reasoned its way there from something else, and it may have copied the text
from a page and then had a good reason to use it. So the wording is "also
appeared in", the evidence is one short piece of text, and a record with no
shared piece gets no line at all.

Claude Code transcripts only, for now: they are the ones that keep each
tool's output beside the call that made it. Nothing here reads anything but
the transcript a record came from, and nothing leaves the machine.

Output text is never quoted. What is kept is the shared piece (masked like
all evidence), the tool whose output held it, and what that tool was asked
for (its URL, path or command, cut short and masked).
"""

from __future__ import annotations

import json
import re

# Pieces shorter than this are too common to say anything: "--recursive",
# "package.json", "/usr/bin".
MIN_PIECE = 10
# At most this many of the call's pieces are looked up, longest first, and
# each is looked for in at most this many earlier items, nearest first. A
# session is read once; these bound the work done per flagged record.
MAX_PIECES = 6
MAX_LOOKBACK = 80
# Text read from one earlier item, and from the flagged call's own input.
# The rest is not searched: a 40 MB log is not where a command came from.
MAX_ITEM = 400000
MAX_INPUT = 20000

# A run of characters with no space, quote, or shell punctuation in it.
# Linear: one character class and a counted tail, no alternation.
_PIECE = re.compile(r"[^\s'\"`$();|&<>{}\[\],\\]{%d,}" % MIN_PIECE)

# Names so common in commands that sharing one proves nothing.
_COMMON = frozenset((
    "/dev/null", "/usr/local", "/usr/bin/env", "package.json",
    "package-lock.json", "node_modules", "--recursive", "--force",
    "--no-verify", "--production", "requirements.txt", "/etc/hosts",
))

_EXTERNAL = re.compile(r"(?:^|[\s;&|(])(?:curl|wget|http|fetch)\b|https?://",
                       re.I)
_WEB_TOOLS = frozenset(("WebFetch", "WebSearch"))
_ABOUT_KEYS = ("url", "file_path", "path", "command", "query", "pattern")
_ABOUT_LIMIT = 80


def _strings(value, out, depth=0, room=None):
    """Every string in a decoded JSON value, into `out`, within `room`
    characters in all."""
    if room is None:
        room = [MAX_INPUT]
    if room[0] <= 0 or depth > 4:
        return out
    if isinstance(value, str):
        out.append(value[:room[0]])
        room[0] -= len(value)
    elif isinstance(value, dict):
        for item in value.values():
            _strings(item, out, depth + 1, room)
    elif isinstance(value, list):
        for item in value[:64]:
            _strings(item, out, depth + 1, room)
    return out


def _text_of(content):
    """The text of a message's content: a string, or the text blocks and
    tool results in a list."""
    if isinstance(content, str):
        return content[:MAX_ITEM]
    parts = []
    if isinstance(content, list):
        for block in content[:256]:
            if isinstance(block, str):
                parts.append(block)
            elif isinstance(block, dict):
                text = block.get("text")
                if isinstance(text, str):
                    parts.append(text)
                else:
                    inner = block.get("content")
                    if inner is not None and block.get("type") == "tool_result":
                        parts.append(_text_of(inner))
    return "\n".join(parts)[:MAX_ITEM]


def pieces(tool_input):
    """The distinctive pieces of a call's input, longest first."""
    seen, found = set(), []
    for text in _strings(tool_input, []):
        for match in _PIECE.finditer(text):
            piece = match.group().strip(".,:;!?")
            if (len(piece) < MIN_PIECE or piece.startswith("-")
                    or piece in _COMMON or piece in seen):
                continue
            seen.add(piece)
            found.append(piece)
    found.sort(key=lambda p: (-len(p), p))
    return found[:MAX_PIECES]


def _about(tool_input):
    """What an earlier call was asked for, in a few words."""
    if isinstance(tool_input, dict):
        for key in _ABOUT_KEYS:
            value = tool_input.get(key)
            if isinstance(value, str) and value.strip():
                line = " ".join(value.split())
                if len(line) > _ABOUT_LIMIT:
                    line = line[:_ABOUT_LIMIT - 1] + "…"
                return line
    return ""


def _is_external(name, tool_input):
    if name in _WEB_TOOLS:
        return True
    if isinstance(tool_input, dict) and isinstance(tool_input.get("command"), str):
        return bool(_EXTERNAL.search(tool_input["command"][:MAX_INPUT]))
    return False


def _can_inform(name, tool_input, piece):
    """Whether this tool's output can have told the agent something. What
    the agent itself wrote or ran (Write, Edit, a plain Bash command) only
    repeats its own words back, and a path inside the project turns up in
    nearly every result, so neither is a source. What can be: the web, an
    MCP tool, a file it read, and a shell command that reached out."""
    if not isinstance(name, str):
        return False
    external = _is_external(name, tool_input)
    if external or name.startswith("mcp__"):
        return True
    if name == "Read":
        return not piece.startswith(("/", "~", "."))
    return False


def read_session(path):
    """The session in order, as a list of items:
        ("use", id, name, input, time)       a tool_use block
        ("result", id, text, time)           a tool_result block, by the use's id
        ("prompt", text, time)               something the user typed
    A line that is not JSON, or has no message, is skipped."""
    items = []
    try:
        fh = open(path, "r", encoding="utf-8", errors="replace")
    except OSError:
        return items
    with fh:
        for line in fh:
            try:
                entry = json.loads(line)
            except (ValueError, RecursionError):
                continue
            if not isinstance(entry, dict):
                continue
            msg = entry.get("message")
            if not isinstance(msg, dict):
                continue
            content = msg.get("content")
            stamp = entry.get("timestamp")
            stamp = stamp if isinstance(stamp, str) else None
            if msg.get("role") == "user" and not isinstance(content, list):
                if isinstance(content, str) and content.strip():
                    items.append(("prompt", content[:MAX_ITEM], stamp))
                continue
            if not isinstance(content, list):
                continue
            typed = []
            for block in content:
                if not isinstance(block, dict):
                    continue
                kind = block.get("type")
                if kind == "tool_use":
                    items.append(("use", block.get("id"), block.get("name"),
                                  block.get("input"), stamp))
                elif kind == "tool_result":
                    items.append(("result", block.get("tool_use_id"),
                                  _text_of(block.get("content")), stamp))
                elif kind == "text" and msg.get("role") == "user":
                    typed.append(block)
            if typed:
                text = _text_of(typed)
                if text.strip():
                    items.append(("prompt", text, stamp))
    return items


def trace(items, call_id):
    """How the call `call_id` links back, or None.

    {"origin": "tool_output" | "prompt", "piece": text, "steps_back": n,
     and for a tool: "tool", "about", "timestamp", "external"}.
    Nothing is returned when no earlier item shares a piece with the call,
    or when the call is not in the session."""
    at = None
    for i, item in enumerate(items):
        if item[0] == "use" and item[1] == call_id:
            at = i
            break
    if at is None:
        return None
    wanted = pieces(items[at][3])
    if not wanted:
        return None
    uses = {item[1]: item for item in items[:at] if item[0] == "use"}
    for piece in wanted:
        looked = 0
        for back in range(at - 1, -1, -1):
            item = items[back]
            if item[0] == "use":
                continue
            looked += 1
            if looked > MAX_LOOKBACK:
                break
            text = item[2] if item[0] == "result" else item[1]
            if piece not in text:
                continue
            steps = sum(1 for x in items[back + 1:at] if x[0] == "use")
            if item[0] == "prompt":
                return {"origin": "prompt", "piece": piece,
                        "steps_back": steps, "timestamp": item[2]}
            made = uses.get(item[1])
            if made is None or not _can_inform(made[2], made[3], piece):
                continue
            return {"origin": "tool_output", "piece": piece,
                    "steps_back": steps, "timestamp": item[3],
                    "tool": made[2] if isinstance(made[2], str) else "?",
                    "about": _about(made[3]),
                    "external": _is_external(made[2], made[3])}
    return None


def attach(path, records, masked):
    """Add "provenance" to each record that has a link, in place.

    `records` are the Action Records watch built from this transcript, and
    `masked` a function that masks the text it is given the way evidence is
    masked; every string kept goes through it. The session is read again
    only when there is a record to look at."""
    if not records:
        return
    items = read_session(path)
    for record in records:
        call_id = record.get("tool_call_id")
        if not isinstance(call_id, str):
            continue
        link = trace(items, call_id)
        if link is None:
            continue
        piece = masked(link["piece"])
        if piece != link["piece"]:
            # A piece that held a credential is not repeated, even masked.
            continue
        link["piece"] = piece
        if "about" in link:
            link["about"] = masked(link["about"])
        record["provenance"] = link
