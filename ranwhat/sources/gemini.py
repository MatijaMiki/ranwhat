"""Gemini CLI: the chats it keeps under ~/.gemini/tmp/<project>/chats.

Design section 7.4, checked against Gemini CLI v0.62.0, and the two older
layouts it migrated from:

- since v0.39.0, one append-only JSON Lines replay log per session,
  tmp/<slug>/chats/session-*.jsonl. A message is appended again whenever
  it changes (a tool call gains its result), {"$set": {...}} updates the
  header (and with a "messages" list replaces the whole history), and
  {"$rewindTo": id} drops a message and everything after it on replay;
- up to v0.38, the same ConversationRecord as one pretty JSON document,
  tmp/<slug>/chats/session-*.json, rewritten whole;
- up to v0.28, the project folder was named by the sha256 of the project
  root instead of a slug. The slug migration copied rather than moved, so
  the same session can be on disk twice; the core's dedupe merges them.
  Sessions from before v0.14.0 name read_file's file absolute_path and
  run_shell_command's folder directory; both are read.

Four things the CLI writes that the plain schema does not say:

- After a history sync (core/geminiChat.ts: on start or resume, on
  setHistory, and on a rollback after an aborted or failed request), each
  tool call's result holds the whole user turn: the functionResponse of
  every call made in parallel with it. A part belongs to the call whose id
  it carries (result_owners).
- A call the user denied is recorded with status "cancelled" and an
  "[Operation Cancelled] Reason: ..." error; two exact reasons mean it never
  ran, and only those are reported as declined (DECLINED_ERRORS).
- Shell output shown in the CLI's terminal view (the default) is stored as
  an AnsiOutput grid, cut into rows at the terminal width, so a long key
  can sit in two tokens on two rows. clean gets the rows joined back into
  the lines that were printed (ansi_text), and mask() rewrites the tokens
  that hold a value that crosses them (rewrite_grids).
- background-processes/background-<pid>.log stays open for writing as long
  as process <pid> runs, so it is in use until then (in_use).

ChatReader reads that schema for any source. Qwen Code is a Gemini CLI
fork whose v0.3.x files are the legacy JSON with message type "qwen"; its
adapter reuses ChatReader with its own model type and tool mapping.

What is never opened: .env files, settings, OAuth and account files under
the root, the shadow git repositories under history/, tmp/<slug>/logs/
(format unverified), and anything else not listed in STORES. projects.json
and .project_root are read only to name the project a folder belongs to.
"""

from __future__ import annotations

import glob
import hashlib
import json
import os
import re
import stat
import subprocess
import time

from . import _lines, _paths, _rewrite, _stamps
from .base import (MaskResult, SecretText, Source, ToolCall, decode_input,
                   newest_first)

# The message type that carries tool calls. Qwen Code's legacy files say
# "qwen" here instead.
MODEL_TYPES = ("gemini",)

# Every tool name the spec verified, and its kind. Any other name is not
# known, and watch judges it by its name. That includes MCP tools, which
# Gemini CLI names mcp_<server>_<tool> (tools/mcp-tool.ts). watch takes a
# tool's base name after a "__" or a ".", so it does not see the "bash" in
# mcp_ops_bash, and an MCP tool that runs shell commands is not judged as a
# shell. The server and tool cannot be told apart here (both may hold "_"),
# so that gap is left for the core to close.
TOOL_KINDS = {
    "run_shell_command": "shell",
    "read_file": "read",
    "write_file": "write",
    "replace": "write",
    "web_fetch": "fetch",
    "google_web_search": "fetch",
    "glob": "other",
    "grep_search": "other",
    "search_file_content": "other",
    "list_directory": "other",
    "read_many_files": "other",
    "write_todos": "other",
    "activate_skill": "other",
    "ask_user": "other",
    "enter_plan_mode": "other",
    "exit_plan_mode": "other",
    "invoke_agent": "other",
    "read_mcp_resource": "other",
    "list_mcp_resources": "other",
}

# How every MCP tool name starts (mcp-tool.ts generateValidName), for a rule
# in the core that closes the gap above.
MCP_PREFIX = "mcp_"

# Where a tool call names its file or folder, current key first. v0.14.0
# renamed read_file's absolute_path to file_path and run_shell_command's
# directory to dir_path. Older sessions are still on disk in the sha256
# folders, which the slug migration copied (config/storageMigration.ts).
READ_PATH_KEYS = ("file_path", "absolute_path")
SHELL_DIR_KEYS = ("dir_path", "directory")

# The parts of a ToolCallRecord that hold what the tool returned.
OUTPUT_FIELDS = ("result", "resultDisplay")

# The error a call's own functionResponse carries when the user declined
# it (scheduler/scheduler.ts, state-manager.ts toCancelled): the call the
# user denied, and the calls still queued behind it, which the denial
# cancels before they start. Any other cancellation is left alone: Ctrl+C
# while a call ran ("Operation cancelled by user", or the executor's own
# "[Operation Cancelled] User cancelled tool execution.") may have let it
# partly run, and an abort before it started ("Reason: Operation
# cancelled") is not a decision. The two strings mean the same from
# v0.30.0 to v0.62.0; v0.25.0 and earlier (core/coreToolScheduler.ts) used
# other words for all of these, so their records are left alone too. One
# case these strings cannot tell apart: a call that a user's AfterTool hook
# chains on to one that ran (a tail call) keeps that call's id, name and
# arguments, so denying the tail call records the first call as declined.
DECLINED_ERRORS = (
    "[Operation Cancelled] Reason: User denied execution.",
    "[Operation Cancelled] Reason: User cancelled operation",
)

# Under each project folder in <root>/tmp: (glob parts, format, role, the
# file name is the session id). The session-* glob also matches the newer
# collision-suffixed names, session-<ts>-<n>-<id8>.jsonl. A subagent's chat
# sits in a folder named after its parent session, as <its own id>.jsonl;
# legacy subagent .json files were one folder down too, under names the
# research did not verify, so their stem is not taken for a session id.
STORES = (
    (("chats", "session-*.jsonl"), "jsonl", "transcript", False),
    (("chats", "session-*.json"), "json", "transcript", False),
    (("chats", "*", "*.jsonl"), "jsonl", "transcript", True),
    (("chats", "*", "*.json"), "json", "transcript", False),
    (("logs.json",), "json", "side", False),
    (("checkpoint-*.json",), "json", "side", False),
    (("checkpoints", "*.json"), "json", "side", False),
    # Full tool output past the inline limit. The session-<id> folder is
    # added only when the CLI knows the session (fileUtils.ts), so files
    # directly in tool-outputs/ are read too.
    (("tool-outputs", "session-*", "*.txt"), "text", "side", False),
    (("tool-outputs", "*.txt"), "text", "side", False),
    # Commands typed in ! mode. Never fed to watch: they have no times, and
    # the user ran them by hand.
    (("shell_history",), "text", "side", False),
)

# Directly under <root>/tmp: output of backgrounded commands. The CLI holds
# background-<pid>.log open for writing for as long as process <pid> runs
# (services/shellExecutionService.ts).
BACKGROUND_DIR = "background-processes"
BACKGROUND = ((BACKGROUND_DIR, "background-*.log"), "text", "side", False)
_BACKGROUND_LOG = re.compile(r"background-([0-9]+)\.log\Z")

SIDE_UNIT = "file"

# Text stores are handed to clean in pieces of whole lines about this long,
# so a large log is not cut at clean's per-string limit after its first
# megabyte. A single line longer than this stays whole.
TEXT_CHUNK = 256 * 1024

_HEX64 = re.compile(r"[0-9a-f]{64}\Z")

# .project_root holds one absolute path; nothing past this is read.
_PROJECT_ROOT_MAX = 4096

# A chat's projectHash, read from the start of the file only when a 64-hex
# folder is not named otherwise. Inside a string the quotes are escaped, so
# only the header's own key matches.
_HEADER_MAX = 4096
_HEADER_HASH = re.compile(r'"projectHash"\s*:\s*"([0-9a-f]{64})"')

# Patched by tests. On Windows os.kill(pid, 0) does not test a process: it
# terminates it.
_WINDOWS = os.name == "nt"


class _Unparsed(Exception):
    """A store with content, none of which parses."""


def _first_string(args, keys):
    """(key, value) for the first of `keys` holding a non-empty string."""
    for key in keys:
        value = args.get(key)
        if isinstance(value, str) and value:
            return key, value
    return None


def normalise(name, args):
    """What watch needs from one Gemini CLI tool call: {"kind", "known"}
    and, where the spec says so, "command", "workdir", "paths" and
    "consumed". `args` is the decoded input."""
    kind = TOOL_KINDS.get(name)
    if kind is None:
        return {"kind": "other", "known": False}
    out = {"kind": kind, "known": True}
    if name == "run_shell_command":
        command = args.get("command")
        if isinstance(command, str) and command.strip():
            out["command"] = command
            out["consumed"] = ("command",)
        # dir_path is relative to the project root; the older directory was
        # absolute. Kept as recorded: watch only needs to know the call ran
        # somewhere other than the project root.
        found = _first_string(args, SHELL_DIR_KEYS)
        if found:
            out["workdir"] = found[1]
    elif name == "read_file":
        found = _first_string(args, READ_PATH_KEYS)
        if found:
            out["paths"] = (found[1],)
            out["consumed"] = (found[0],)
    elif name in ("write_file", "replace"):
        # file_path in every release that kept chats.
        path = args.get("file_path")
        if isinstance(path, str) and path:
            out["paths"] = (path,)
    return out


# -- whose result is it -------------------------------------------------------

def _function_response(part):
    response = part.get("functionResponse") if isinstance(part, dict) else None
    return response if isinstance(response, dict) else None


def _response_id(part):
    response = _function_response(part)
    call_id = response.get("id") if response is not None else None
    return call_id if isinstance(call_id, str) else None


def result_owners(result, own_id):
    """[(part, owner)] for a ToolCallRecord's result. owner is True for the
    record's own part, the id of another call for that call's
    functionResponse, and None when it cannot be known.

    A history sync stores the whole user turn as the result of each call
    in it (chatRecordingService.ts, updateMessagesFromHistory), and the
    CLI moves every functionResponse ahead of a turn's other parts
    (utils/historyHardening.ts). So once a result holds another call's
    response, a part with no id of its own (inlineData, say) cannot be
    placed, and has no owner."""
    if not isinstance(result, list):
        return [(result, True)]
    if not isinstance(own_id, str):
        return [(part, True) for part in result]
    ids = [_response_id(part) for part in result]
    shared = any(i is not None and i != own_id for i in ids)
    out = []
    for part, part_id in zip(result, ids):
        if part_id is not None:
            out.append((part, True if part_id == own_id else part_id))
        else:
            out.append((part, None if shared else True))
    return out


def _own_parts(record):
    return [part for part, owner in result_owners(record.get("result"),
                                                  record.get("id"))
            if owner is True]


def call_output(record):
    """The text a ToolCallRecord returned: the output of each of its own
    functionResponse parts, else its resultDisplay as text, else None. The
    shell's <untrusted_context> wrapping is kept as it is: its layout
    changes between versions."""
    texts = []
    for part in _own_parts(record):
        if isinstance(part, str):
            texts.append(part)
            continue
        response = _function_response(part)
        body = response.get("response") if response is not None else None
        output = body.get("output") if isinstance(body, dict) else None
        if isinstance(output, str):
            texts.append(output)
    if texts:
        return "\n".join(texts)
    display = record.get("resultDisplay")
    if isinstance(display, str):
        return display
    return ansi_text(display)


def declined(record):
    """True when a ToolCallRecord says the call never ran: status
    "cancelled" and its own functionResponse carries one of
    DECLINED_ERRORS."""
    if record.get("status") != "cancelled":
        return False
    for part in _own_parts(record):
        response = _function_response(part)
        body = response.get("response") if response is not None else None
        if isinstance(body, dict) and body.get("error") in DECLINED_ERRORS:
            return True
    return False


# -- terminal output (AnsiOutput) ---------------------------------------------
#
# A shell call run in the CLI's terminal view (tools.shell.
# enableInteractiveShell, on by default) stores its resultDisplay as the
# terminal's cells: a list of rows, each a list of tokens {text, bold,
# italic, underline, dim, inverse, isUninitialized, fg, bg}, a new token
# wherever the cell style changes (utils/terminalSerializer.ts). Every row
# covers the whole width (80 unless the CLI knows its window's), blank
# cells as spaces, so a line that was longer is cut into several rows, and
# a value that crossed the edge sits in tokens on two rows. The grid does
# not say which rows wrapped. A row whose last cell was written and is not
# a space is taken to go on in the next: true of every wrapped row, and
# also of a printed line exactly as wide as the terminal, which is then
# joined to the line after it.

GRID_KEY = "resultDisplay"
_GRID_MARK = '"%s"' % GRID_KEY


def is_ansi_output(value):
    """True for an AnsiOutput grid with at least one token."""
    if not isinstance(value, list):
        return False
    seen = False
    for row in value:
        if not isinstance(row, list):
            return False
        for token in row:
            if not isinstance(token, dict) or not isinstance(token.get("text"), str):
                return False
            seen = True
    return seen


def _continues(row):
    if not row or row[-1].get("isUninitialized") is True:
        return False
    text = "".join(token["text"] for token in row)
    return bool(text) and text[-1] != " "


def _line_groups(grid):
    """[[(row, token), ...]]: the tokens of each printed line, in order."""
    groups, current = [], []
    for r, row in enumerate(grid):
        current.extend((r, t) for t in range(len(row)))
        if not _continues(row):
            groups.append(current)
            current = []
    if current:
        groups.append(current)
    return groups


def _group_text(grid, group):
    return "".join(grid[r][t]["text"] for r, t in group).rstrip(" ")


def _grid_text(grid, groups):
    return "\n".join(_group_text(grid, group) for group in groups)


def ansi_text(value):
    """The text of an AnsiOutput grid as it was printed: rows joined back
    into lines, the blank cells after each line dropped, lines joined by
    newlines. None when `value` is not a grid."""
    if not is_ansi_output(value):
        return None
    return _grid_text(value, _line_groups(value))


def _grid_holders(node):
    """(dict, grid) for every AnsiOutput grid stored under a resultDisplay
    key in decoded JSON, in document order."""
    stack = [node]
    while stack:
        item = stack.pop()
        if isinstance(item, dict):
            children = []
            for key, value in item.items():
                if key == GRID_KEY and is_ansi_output(value):
                    yield item, value
                elif isinstance(value, (dict, list)):
                    children.append(value)
            stack.extend(reversed(children))
        elif isinstance(item, list):
            stack.extend(reversed([v for v in item if isinstance(v, (dict, list))]))


def _grids(node):
    """Every AnsiOutput grid stored under a resultDisplay key in decoded
    JSON, in document order."""
    for _holder, grid in _grid_holders(node):
        yield grid


def _shown(node):
    """Decoded JSON with each of its grids replaced, in place, by the text
    it shows (ansi_text), so clean reads a key the terminal cut in two
    whole, and not the piece on each row."""
    for holder, grid in list(_grid_holders(node)):
        holder[GRID_KEY] = ansi_text(grid)
    return node


def _layout(grid, groups):
    """(text, owners): _grid_text, and for each of its characters the
    (row, token, offset) it came from, or None for a newline between
    lines."""
    chars, owners = [], []
    for n, group in enumerate(groups):
        if n:
            chars.append("\n")
            owners.append(None)
        line, where = [], []
        for r, t in group:
            text = grid[r][t]["text"]
            line.append(text)
            where.extend((r, t, k) for k in range(len(text)))
        line = "".join(line)
        kept = len(line.rstrip(" "))
        chars.append(line[:kept])
        owners.extend(where[:kept])
    return "".join(chars), owners


def _claims(text, plan):
    """[(start, end, marker)] for every occurrence of each value in
    `text`, longest value first, never overlapping, in order."""
    claimed = []
    for value, marker in plan:
        i = text.find(value)
        while i != -1:
            end = i + len(value)
            if any(a < end and i < b for a, b, _m in claimed):
                i = text.find(value, i + 1)
                continue
            claimed.append((i, end, marker))
            i = text.find(value, end)
    claimed.sort()
    return claimed


def _crosses(owners, start, end):
    """True when text[start:end] is not all in one token."""
    first = owners[start]
    if first is None:
        return True
    for owner in owners[start + 1:end]:
        if owner is None or owner[:2] != first[:2]:
            return True
    return False


def _mask_grid(grid, plan):
    """Mask every value in one grid, in place, and return True when it
    changed; None when it cannot be done. Each value's marker goes where
    the value began, and the rest of the value is cut from the tokens that
    held it. Checked: read with the grid's old lines, the new text is the
    old text with each value replaced by its marker, keeping the line
    breaks a value spanned (the rows themselves stay)."""
    groups = _line_groups(grid)
    if not _holds_value(_grid_text(grid, groups), plan):
        return False
    text, owners = _layout(grid, groups)
    claims = _claims(text, plan)
    drop, insert = set(), {}
    for start, end, marker in claims:
        if owners[start] is None:
            return None
        insert[owners[start]] = marker
        drop.update(o for o in owners[start:end] if o is not None)
    for r, t in sorted(set(o[:2] for o in drop)):
        token = grid[r][t]
        pieces = []
        for k, ch in enumerate(token["text"]):
            if (r, t, k) in insert:
                pieces.append(insert[(r, t, k)])
            if (r, t, k) not in drop:
                pieces.append(ch)
        token["text"] = "".join(pieces)
    expected, at = [], 0
    for start, end, marker in claims:
        expected.append(text[at:start])
        expected.append(marker + "\n" * text.count("\n", start, end))
        at = end
    expected.append(text[at:])
    if _grid_text(grid, groups) != "".join(expected):
        return None
    return True


def _value_in_grids(node, plan):
    """True when any value is in the text of any grid in `node`, or in any
    one of its tokens."""
    for grid in _grids(node):
        texts = [ansi_text(grid)] + [token["text"] for row in grid for token in row]
        if any(_holds_value(text, plan) for text in texts):
            return True
    return False


def _holds_value(text, plan):
    return any(value in text for value, _m in plan)


def _crossing_value(node, plan):
    """True when a value in a grid in `node` is not all in one token."""
    for grid in _grids(node):
        groups = _line_groups(grid)
        if not _holds_value(_grid_text(grid, groups), plan):
            continue
        text, owners = _layout(grid, groups)
        if any(_crosses(owners, a, b) for a, b, _m in _claims(text, plan)):
            return True
    return False


def _blank_grid_texts(node):
    for grid in _grids(node):
        for row in grid:
            for token in row:
                token["text"] = None
    return node


def _compact(node):
    """As JSON.stringify(record) writes a chat line."""
    return json.dumps(node, ensure_ascii=False, separators=(",", ":"))


def _pretty(node):
    """As JSON.stringify(record, null, 2) wrote a legacy .json session."""
    return json.dumps(node, ensure_ascii=False, indent=2)


def _crossing(text, plan):
    """The decoded JSON document `text` when a value in one of its grids
    crosses tokens, else None (raw replacement reaches every other copy)."""
    if _GRID_MARK not in text:
        return None
    try:
        node = json.loads(text)
    except (ValueError, RecursionError):
        return None
    return node if _crossing_value(node, plan) else None


def _remasked(node, text, dump, plan):
    """`text`, the JSON document `node` was decoded from, with the values
    masked in its grids; None when that would change more than the secret.

    The document is written out again with `dump`, so this is done only
    where dumping it unchanged gives back exactly the bytes on disk. Then
    nothing outside the grids' token texts can move, which is checked too.
    A document nested too deep to write out or compare is refused as well:
    Python 3.14 parses far deeper than it can do either."""
    try:
        if dump(node) != text:
            return None
        for grid in _grids(node):
            if _mask_grid(grid, plan) is None:
                return None
        new = dump(node)
        if (_blank_grid_texts(json.loads(new)) != _blank_grid_texts(json.loads(text))
                or _value_in_grids(node, plan)):
            return None
    except (ValueError, UnicodeError, RecursionError):
        return None
    return new


def rewrite_grids(path, values, kind, now=None):
    """Mask `values` in a chat file where one of them crosses the tokens of
    an AnsiOutput grid, and return a MaskResult; None when none does, and
    the generic rewrite can do the whole file.

    Raw replacement cannot reach a value cut in two, so each line (or the
    legacy document) holding one is written out again with its grids
    masked (_remasked). The rest is masked raw, and then _rewrite's own
    checks, quiet period, backup and replace apply, as in rewrite_file. A
    file where that cannot be done is refused as "would alter more than
    the secret", so a masked file never keeps a value in a grid."""
    if kind not in ("jsonl", "json"):
        return None
    plan = _rewrite._plan(values)
    if not plan:
        return None
    real = os.path.realpath(path)
    st0 = os.stat(real)
    if not stat.S_ISREG(st0.st_mode):
        return None
    with open(real, "rb") as fh:
        old = fh.read().decode("utf-8", "surrogateescape")
    if _GRID_MARK not in old:
        return None
    bom = _lines.BOM if old.startswith(_lines.BOM) else ""
    body = old[len(bom):]
    if kind == "jsonl":
        units = body.split("\n")
        dump = _compact
    else:
        doc = body.rstrip("\r\n")
        units, tail = [doc], body[len(doc):]
        dump = _pretty
    crossing = [(i, node) for i, node in
                ((i, _crossing(unit, plan)) for i, unit in enumerate(units))
                if node is not None]
    if not crossing:
        return None
    if (time.time() if now is None else now) - st0.st_mtime < _rewrite.QUIET_SECONDS:
        return MaskResult(path, skipped=_rewrite.IN_USE)
    for i, node in crossing:
        new = _remasked(node, units[i], dump, plan)
        if new is None:
            return MaskResult(path, skipped=_rewrite.ALTERED)
        units[i] = new
    pre = bom + ("\n".join(units) if kind == "jsonl" else units[0] + tail)
    new = _rewrite._replace_text(pre, plan, False)
    if not _rewrite._verify(kind, pre, new, plan, False):
        return MaskResult(path, skipped=_rewrite.ALTERED)
    for unit in (new[len(bom):].split("\n") if kind == "jsonl" else [new[len(bom):]]):
        if _GRID_MARK not in unit:
            continue
        try:
            node = json.loads(unit)
        except (ValueError, RecursionError):
            continue
        if _value_in_grids(node, plan):
            return MaskResult(path, skipped=_rewrite.ALTERED)
    from .. import clean            # not at import: sources never import clean
    backup = clean._backup(real)
    try:
        reason = _rewrite._install(real, st0,
                                   new.encode("utf-8", "surrogateescape"))
    except BaseException:
        _rewrite._discard(backup)
        raise
    if reason:
        _rewrite._discard(backup)
        return MaskResult(path, skipped=reason)
    return MaskResult(path, changed=True, backup=backup)


# -- reading ------------------------------------------------------------------

def _is_message(obj):
    return isinstance(obj, dict) and isinstance(obj.get("id"), str)


def _split_messages(items):
    """(messages, the rest) of a messages list."""
    messages = [m for m in items if _is_message(m)]
    rest = [m for m in items if not _is_message(m)]
    return messages, rest


def classify(record):
    """(kind, messages, rest) for one record, in the CLI's own order
    (loadConversationRecord): "rewind", "message", "set", "header" or
    "unknown". `messages` are the message records it carries; `rest` is
    everything else in it, for clean (None when the record is only a
    message)."""
    if not isinstance(record, dict):
        return "unknown", [], record
    if isinstance(record.get("$rewindTo"), str):
        return "rewind", [], record
    if _is_message(record):
        return "message", [record], None
    update = record.get("$set")
    if isinstance(update, dict):
        if isinstance(update.get("messages"), list):
            messages, others = _split_messages(update["messages"])
            rest = {k: v for k, v in update.items() if k != "messages"}
            if others:
                rest["messages"] = others
            return "set", messages, {"$set": rest}
        return "set", [], record
    if (isinstance(record.get("sessionId"), str)
            and isinstance(record.get("projectHash"), str)):
        # A header line, or a whole legacy ConversationRecord (a .json
        # file, or one written on a single line), which also has messages.
        if isinstance(record.get("messages"), list):
            messages, others = _split_messages(record["messages"])
            rest = {k: v for k, v in record.items() if k != "messages"}
            if others:
                rest["messages"] = others
            return "header", messages, rest
        return "header", [], record
    return "unknown", [], record


class ChatReader(object):
    """Reads chat files in the Gemini CLI schema on behalf of `source`
    (its id, counters and warnings).

    model_types: the message types that carry toolCalls. normalise: a
    function (name, decoded args) -> the dict normalise() returns, so a fork
    can map its own tool names. declined: a function (ToolCallRecord) ->
    True when the call never ran, or None for a fork whose records say
    nothing verified about that."""

    def __init__(self, source, model_types=MODEL_TYPES, normalise=normalise,
                 declined=declined):
        self.source = source
        self.model_types = tuple(model_types)
        self.normalise = normalise
        self.declined = declined
        self.noted = set()      # stores already counted this run

    # -- reading ------------------------------------------------------------

    def _noting(self, store):
        """True the first time a store is read in a run: its skipped lines
        and records are counted then, and not again by the other pass."""
        if store.path in self.noted:
            return False
        self.noted.add(store.path)
        return True

    def records(self, store, noting=False):
        """Yield (where, record) for every record in a JSON Lines or JSON
        store. Raises OSError when the file cannot be read, and _Unparsed
        when it has content and none of it parses."""
        if store.format == "jsonl":
            local = {}
            parsed = 0
            for line_no, obj in _lines.iter_json_lines(store.path, local):
                parsed += 1
                yield "line %d" % line_no, obj
            bad = local.get("unparsed", 0)
            if noting and bad:
                self.source.count("unparsed", bad)
            if bad and not parsed:
                raise _Unparsed()
            return
        with open(store.path, "rb") as fh:
            text = fh.read().decode("utf-8", "surrogateescape")
        if text.startswith(_lines.BOM):
            text = text[1:]
        if not text.strip():
            return              # being created: nothing in it yet
        try:
            doc = json.loads(text)
        except (ValueError, RecursionError):
            raise _Unparsed() from None
        yield "file", doc

    def _failed(self, store, noting, error):
        name = self.source.name or self.source.id
        if isinstance(error, _Unparsed):
            reason, why = "did not parse", "it is not valid JSON"
        else:
            reason, why = "could not be opened", str(error)
        if noting:
            self.source.unreadable_store(reason)
        self.source.warn(store.path, "%s: could not read %s (%s)"
                         % (name, store.path, why))

    def _model_calls(self, message):
        """(index, ToolCallRecord) for each tool call a message carries."""
        if message.get("type") not in self.model_types:
            return []
        calls = message.get("toolCalls")
        if not isinstance(calls, list):
            return []
        return [(i, c) for i, c in enumerate(calls) if isinstance(c, dict)]

    def call(self, store, record, message_time, session):
        """The ToolCall for one ToolCallRecord."""
        name = record.get("name")
        if not isinstance(name, str) or not name:
            name = "?"
        args = decode_input(record.get("args"))
        fields = self.normalise(name, args)
        stamp = (_stamps.iso_utc(record.get("timestamp"), "iso")
                 or _stamps.iso_utc(message_time, "iso"))
        call_id = record.get("id")
        never_ran = self.declined is not None and self.declined(record)
        return ToolCall(
            self.source.id, store.path, name, args,
            kind=fields["kind"], known=fields["known"],
            session=session, project=store.project, timestamp=stamp,
            tool_call_id=call_id if isinstance(call_id, str) else None,
            status="declined" if never_ran else None,
            not_after=None if stamp else _stamps.iso_utc(store.mtime, "s"),
            command=fields.get("command"), workdir=fields.get("workdir"),
            paths=fields.get("paths", ()), consumed=fields.get("consumed", ()),
            output=call_output(record))

    # -- watch --------------------------------------------------------------

    def tool_calls(self, store):
        """Every distinct call in a transcript, once, in the order it was
        first made. A message is appended again each time it changes, so a
        call is kept by its id and its last version wins (it has the
        result). A call removed by $rewindTo still ran, so it is kept."""
        if store.role != "transcript" or store.format not in ("jsonl", "json"):
            return
        noting = self._noting(store)
        session, calls = None, {}
        try:
            for where, record in self.records(store, noting):
                kind, messages, _rest = classify(record)
                if kind == "header" and session is None:
                    session = record["sessionId"]
                elif kind == "unknown" and noting:
                    self.source.count("unknown")
                for message in messages:
                    for index, call in self._model_calls(message):
                        key = call.get("id")
                        if not isinstance(key, str):
                            key = (message["id"], index)
                        calls[key] = (call, message.get("timestamp"))
        except (OSError, _Unparsed) as e:
            self._failed(store, noting, e)
            return
        for call, message_time in calls.values():
            yield self.call(store, call, message_time, session)

    # -- clean --------------------------------------------------------------

    def secret_texts(self, store):
        """Every string on disk, superseded and rewound copies included.
        Each part of a tool call's result comes with the call it belongs
        to, and its resultDisplay with that call (a terminal grid as the
        text it shows); a functionResponse repeated in a later message
        comes with the call whose id it carries; everything else comes with
        no call. Side stores come whole, with no call, each terminal grid
        as the text it shows: a checkpoint keeps the CLI's own view of the
        history, grids included."""
        noting = self._noting(store)
        try:
            if store.format == "text":
                for st in self._text(store):
                    yield st
                return
            if store.role != "transcript":
                for where, record in self.records(store, noting):
                    yield SecretText(_shown(record), where=where)
                return
            session, by_id = None, {}
            for where, record in self.records(store, noting):
                kind, messages, rest = classify(record)
                if kind == "header" and session is None:
                    session = record["sessionId"]
                elif kind == "unknown" and noting:
                    self.source.count("unknown")
                in_list = kind != "message"
                for n, message in enumerate(messages, 1):
                    here = "%s, message %d" % (where, n) if in_list else where
                    for st in self._message_texts(store, message, here,
                                                  session, by_id):
                        yield st
                if rest is not None:
                    yield SecretText(rest, where=where)
        except (OSError, _Unparsed) as e:
            self._failed(store, noting, e)

    def _message_texts(self, store, message, where, session, by_id):
        has_calls = (message.get("type") in self.model_types
                     and isinstance(message.get("toolCalls"), list))
        rest = {}
        for key, value in message.items():
            if key == "toolCalls" and has_calls:
                # Every call in the message first: a result can hold the
                # response of a call listed after it.
                made = []
                for record in value:
                    if isinstance(record, dict):
                        call = self.call(store, record, message.get("timestamp"),
                                         session)
                        if call.tool_call_id:
                            by_id[call.tool_call_id] = call
                        made.append(call)
                made = iter(made)
                kept = []
                for record in value:
                    if not isinstance(record, dict):
                        kept.append(record)
                        continue
                    call = next(made)
                    if record.get("result") is not None:
                        for part, owner in result_owners(record["result"],
                                                         call.tool_call_id):
                            if owner is not True:
                                owner = by_id.get(owner) if owner else None
                            yield SecretText(part, call=call if owner is True
                                             else owner, where=where)
                    display = record.get("resultDisplay")
                    if display is not None:
                        shown = ansi_text(display)
                        yield SecretText(display if shown is None else shown,
                                         call=call, where=where)
                    kept.append({k: v for k, v in record.items()
                                 if k not in OUTPUT_FIELDS})
                rest[key] = kept
            elif key == "content" and isinstance(value, list):
                kept = []
                for part in value:
                    if _function_response(part) is not None:
                        call_id = _response_id(part)
                        yield SecretText(part, call=by_id.get(call_id)
                                         if call_id else None, where=where)
                    else:
                        kept.append(part)
                rest[key] = kept
            else:
                rest[key] = value
        yield SecretText(rest, where=where)

    def _text(self, store):
        """A text file in runs of whole lines, about TEXT_CHUNK long."""
        with open(store.path, "rb") as fh:
            buf, size, first, line_no = [], 0, 1, 0
            for line_no, raw in enumerate(fh, 1):
                text = raw.decode("utf-8", "surrogateescape")
                buf.append(text)
                size += len(text)
                if size >= TEXT_CHUNK:
                    yield SecretText("".join(buf), where=_lines_where(first, line_no))
                    buf, size, first = [], 0, line_no + 1
            if buf:
                yield SecretText("".join(buf), where=_lines_where(first, line_no))


def _lines_where(first, last):
    return "line %d" % first if first == last else "lines %d-%d" % (first, last)


def _read_project_root(path):
    """The path in a .project_root file, or None."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read(_PROJECT_ROOT_MAX)
    except OSError:
        return None
    lines = text.splitlines()
    value = lines[0].rstrip("\r\n") if lines else ""
    return value if value.strip() else None


def _read_registry(path):
    """[(project path, slug)] from projects.json, {"projects": {path: slug}};
    [] when it is missing or not that shape. Nothing else in it is kept."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, ValueError, RecursionError):
        return []
    projects = doc.get("projects") if isinstance(doc, dict) else None
    if not isinstance(projects, dict):
        return []
    return [(p, s) for p, s in projects.items()
            if isinstance(p, str) and p and isinstance(s, str) and s]


def _sha256(text):
    return hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()


def _header_hashes(folder):
    """The projectHash in the header of each chat directly in a project
    folder's chats/. The header comes first in both layouts, so only the
    start of each file is read."""
    out = set()
    for pattern in ("session-*.jsonl", "session-*.json"):
        for path in glob.glob(os.path.join(glob.escape(folder), "chats", pattern)):
            try:
                with open(path, "rb") as fh:
                    head = fh.read(_HEADER_MAX).decode("utf-8", "replace")
            except OSError:
                continue
            match = _HEADER_HASH.search(head)
            if match:
                out.add(match.group(1))
    return out


def project_map(root, tmp, names):
    """{folder name: project root or None} for the folders in root/tmp.

    A slug folder: the text of its .project_root, else the path
    projects.json maps to that slug. A 64-hex folder (v0.28 and earlier):
    the known project path whose sha256 is the folder name, else the
    project of a slug folder whose chat headers carry that digest. The
    second is needed on Windows, where the registry keeps every path in
    lower case but the folder was named by the root in the case the CLI
    was started with; a header's projectHash is that same digest, and
    cannot be reversed."""
    roots = {}
    for name in names:
        value = _read_project_root(os.path.join(tmp, name, ".project_root"))
        if value:
            roots[name] = value
    registry = _read_registry(os.path.join(root, "projects.json"))
    by_slug = {}
    for path, slug in registry:
        by_slug.setdefault(slug, path)
    by_hash = {}
    for path in list(roots.values()) + [p for p, _s in registry]:
        by_hash.setdefault(_sha256(path), path)
    out = {}
    for name in names:
        if _HEX64.match(name):
            out[name] = by_hash.get(name)
        else:
            out[name] = roots.get(name) or by_slug.get(name)
    missing = {n for n in names if out[n] is None and _HEX64.match(n)}
    for name in names:
        if missing and out[name] is not None and not _HEX64.match(name):
            for digest in _header_hashes(os.path.join(tmp, name)) & missing:
                out[digest] = out[name]
                missing.discard(digest)
    return out


# -- in use -------------------------------------------------------------------

def _tasklist():
    system = os.environ.get("SystemRoot") or os.environ.get("SYSTEMROOT")
    if system:
        exe = os.path.join(system, "System32", "tasklist.exe")
        if os.path.isfile(exe):
            return exe
    return "tasklist"


def _pid_alive(pid):
    """Whether a process with this id is running. Not knowing counts as
    running: that only makes clean more careful."""
    if not 0 < pid <= 0xFFFFFFFF:
        return False
    if _WINDOWS:
        # tasklist, never os.kill: on Windows that terminates the process.
        try:
            done = subprocess.run(
                [_tasklist(), "/FI", "PID eq %d" % pid, "/NH", "/FO", "CSV"],
                capture_output=True, timeout=10,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        except (OSError, subprocess.SubprocessError):
            return True
        if done.returncode != 0:
            return True
        return ('"%d"' % pid) in done.stdout.decode("ascii", "replace")
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True                 # running, as another user
    except (OverflowError, ValueError):
        return False                # no process can have this id
    except OSError:
        return True
    return True


class GeminiSource(Source):
    id = "gemini"
    name = "Gemini CLI"
    unit = "session"
    env = ("GEMINI_CLI_HOME",)
    path_means = "a .gemini directory (the one holding tmp/)"
    checked = "v0.62.0"
    # For the clean report.
    clean_note = ("Gemini CLI deletes chats older than 30 days by default; "
                  "logs.json, checkpoints and shell_history are never deleted.")
    # Said after masking (design 3.7). A running CLI appends whole messages
    # from memory (a changed message, a history sync, a rewind), and writes
    # shell_history out whole from memory on the next ! command.
    mask_note = ("If Gemini CLI is open in this project, close it first, or "
                 "it may write the value back: it keeps the conversation and "
                 "its ! command history in memory and saves them again.")

    def __init__(self):
        self.reader = ChatReader(self)
        Source.__init__(self)

    def reset(self):
        Source.reset(self)
        reader = getattr(self, "reader", None)
        if reader is not None:
            reader.noted.clear()

    def default_paths(self, env, home, platform):
        """$GEMINI_CLI_HOME replaces the home directory when set. Under it:
        .gemini, and .cache/.gemini, where the CLI keeps everything when it
        runs in the macOS Seatbelt sandbox (SANDBOX=sandbox-exec). That
        variable is never set when ranwhat runs, so the folder is always
        probed; on a machine that never used the sandbox it costs one stat."""
        override = env.get("GEMINI_CLI_HOME")
        if isinstance(override, str) and override:
            base, how = override, "env GEMINI_CLI_HOME"
        else:
            base, how = home, "default"
        j = _paths.pathmod(platform).join
        return [(j(base, ".gemini"), how),
                (j(base, ".cache", ".gemini"), how + ", sandbox")]

    def stores(self, locations, since_days=None):
        found = []
        for loc in locations:
            found.extend(self._stores_under(loc.path))
        return newest_first(found, since_days)

    def _stores_under(self, root):
        tmp = os.path.join(root, "tmp")
        try:
            names = sorted(n for n in os.listdir(tmp)
                           if os.path.isdir(os.path.join(tmp, n)))
        except OSError:
            return []
        projects = project_map(root, tmp, names)
        out = []
        for name in names:
            folder = os.path.join(tmp, name)
            for spec in STORES:
                out.extend(self._glob(folder, spec, projects.get(name)))
        out.extend(self._glob(tmp, BACKGROUND, None))
        return out

    def _glob(self, folder, spec, project):
        parts, fmt, role, named = spec
        pattern = os.path.join(glob.escape(folder), *parts)
        out = []
        for path in sorted(glob.glob(pattern)):
            if not os.path.isfile(path):
                continue
            session = (os.path.splitext(os.path.basename(path))[0]
                       if named else None)
            store = self.store(path, fmt, role=role, project=project,
                               session=session,
                               unit=self.unit if role == "transcript" else SIDE_UNIT)
            if store is not None:
                out.append(store)
        return out

    def tool_calls(self, store):
        return self.reader.tool_calls(store)

    def secret_texts(self, store):
        return self.reader.secret_texts(store)

    def in_use(self, store):
        """A background command's log while its process runs: the CLI keeps
        writing to the file it opened, and would go on writing to the old
        one after a replace."""
        path = store.path
        match = _BACKGROUND_LOG.match(os.path.basename(path))
        if (match is None or store.format != "text"
                or os.path.basename(os.path.dirname(path)) != BACKGROUND_DIR):
            return False
        return _pid_alive(int(match.group(1)))

    def mask(self, store, values):
        """The generic rewrite, except where a value crosses the tokens of
        a terminal grid in a chat file (rewrite_grids)."""
        if store.masking != "rewrite":
            return MaskResult(store.path, skipped="read-only")
        if self.in_use(store):
            return MaskResult(store.path, skipped="in use")
        result = rewrite_grids(store.path, values, store.format)
        if result is not None:
            return result
        return _rewrite.rewrite_file(store.path, values, store.format)
