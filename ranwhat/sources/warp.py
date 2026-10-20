"""Warp: the agent built into the Warp terminal (the app, warp-tui and
`warp agent`), on the Stable, Preview and OSS channels.

Checked against the open-source client (warpdotdev/warp @ cd4b970e6331,
2026-10-20: app/src/persistence, crates/persistence/src/schema.rs and
migrations, crates/warp_core/src/paths.rs) and the protobuf schema it
pins (warpdotdev/warp-proto-apis @ c5aa18336af0, apis/multi_agent/v1/
task.proto, input_context.proto, file_content.proto), and against Warp's
session-restoration docs for the Stable paths. Current Stable when
checked: 0.2026.10.14.08.27.stable_01. Two researchers read the source
independently; the field numbers below were read again from the .proto
files when this module was written.

Where. Every front end keeps one plain SQLite file, warp.sqlite, in WAL
mode (no encryption) in the channel's state folder
(app_database_file_path, sqlite.rs):
- Linux: ${XDG_STATE_HOME:-~/.local/state}/warp-terminal (Stable),
  warp-terminal-preview (Preview), warp-oss (OSS). XDG_STATE_HOME is read
  only when absolute, as the directories crate reads it.
- macOS: the App Group container, ~/Library/Group Containers/
  2BBY89MBSN.dev.warp/Library/Application Support/<bundle id>, with
  dev.warp.Warp-Stable, dev.warp.Warp-Preview and dev.warp.WarpOss (and
  the internal dev.warp.Warp-Dev and dev.warp.Warp-Local), and the old
  ~/Library/Application Support/<bundle id> an older build wrote before it
  moved the file (migrate_old_sqlite_into_secure_container_if_needed).
- Windows: %LOCALAPPDATA%\\warp\\Warp\\data (Stable), WarpPreview\\data,
  WarpOss\\data, and WarpDev\\data.
- warp-tui keeps its own database one folder down, <state folder>/tui/
  warp.sqlite (tui_state_dir): every folder above is searched for it too.
  OSS warp-tui has its own application id, dev.warp.WarpTui, so
  warp-terminal-tui (Linux) and WarpTui\\data (Windows) are probed as well.
  `warp agent` uses the app scope and shares the app's database.
No release build has a variable that moves the file: WARP_DATA_PROFILE
adds a suffix to the folder in debug builds only, and is not read.
Unverified, so probed and never assumed: the Preview folders on Linux and
Windows (derived from the application ids, whose Stable and Preview values
come from a generator that is not in the repository) and where Stable
warp-tui keeps its file on macOS. A folder the macOS privacy rules refuse
us (Sequoia asks before another program reads an App Group container) is
counted as a store not read, not as an empty one.

What is read. SQLite is opened through _sqlite (read-only; the -wal is
read through a copy when it cannot be opened in place; nothing is made
beside the file; every table and column is looked up first, so an older
database simply lacks some). Only the tables named here are opened:
Warp's other tables (its cloud objects, settings and the rest) are not.
- agent_tasks(conversation_id, task_id, task, last_modified_at): the whole
  transcript. task is a protobuf warp.multi_agent.v1.Task, one row per
  task, rewritten whole at each save, so a call is in exactly one
  snapshot. The standard wire format is decoded here by hand (no
  dependency). Field numbers, from task.proto: Task{id 1, description 2,
  dependencies 3, messages 5, summary 6}; Message{id 1, user_query 2
  {query 1, context 2 {directory 1 {pwd 1}}}, agent_output 3 {text 1},
  tool_call 4, tool_call_result 5, task_id 11, request_id 13, timestamp 14
  {seconds 1, nanos 2}}; ToolCall{tool_call_id 1 and one of
  run_shell_command 2 {command 1}, search_codebase 3, read_files 5
  {files 1 {name 1}}, apply_file_diffs 6, grep 9 {queries 1, path 2},
  file_glob 10, read_mcp_resource 11, call_mcp_tool 12 {name 1, args 2
  (google.protobuf.Struct), server_id 3}, write_to_long_running_shell_
  command 13 {input 1 (bytes), command_id 3}, file_glob_v2 15
  {patterns 1, search_dir 2}, use_computer 24 {action_summary 3}, and 24
  others, listed in TOOLS}; apply_file_diffs{summary 1, diffs 2
  {file_path 1, search 2, replace 3}, new_files 3 {file_path 1, content 2,
  allow_overwrite 3}, deleted_files 4 {file_path 1}, v4a_updates 5
  {file_path 1, move_to 2, hunks 3 {change_context 1, pre_context 2, old 3,
  new 4, post_context 5}}}; ToolCallResult{tool_call_id 1, context 11
  (an InputContext), and one of run_shell_command 2, read_files 5,
  apply_file_diffs 6, cancel 14, call_mcp_tool 16, ...};
  RunShellCommandResult{command 3 (what ran, which the user may have
  edited), long_running_command_snapshot 4 {output 1, command_id 3},
  command_finished 5, permission_denied 6, terminal_busy 7};
  ShellCommandFinished{output 1, exit_code 2, command_id 3, start_ts 4,
  finish_ts 5}; ApplyFileDiffsResult{success 1, error 2 {message 1}};
  ReadFilesResult{text_files_success 1 {files 1 {file_path 1, content 2}},
  error 2}; CallMCPToolResult{success 1 {results 1 {text 1 {text 1}}},
  error 2 {message 1}}. The LongRunningShellCommandSnapshot message is
  not in the files read; its two fields are the researchers'.
  An edit appears only here (never in `commands`), as apply_file_diffs
  with the paths it names, its search and replace texts and new files'
  content.
- agent_conversations(conversation_id, summary, last_modified_at): the
  title, initial_query and initial_working_directory in summary (JSON,
  from July 2026) name a conversation's project; a call's own directory
  (the pwd of the query or result before it) is used first. conversation_
  data (server tokens, run ids) is not read: it holds no typed text.
- commands(id, command, start_ts, pwd, session_id, workflow_command,
  is_agent_executed): every command written to the PTY, Warp's agent's
  and the user's. A row is the agent's only when is_agent_executed is 1
  (set for CommandExecutionSource::AI: a RunShellCommand the agent ran,
  auto or approved). The column exists from March 2026; older rows hold
  NULL and an older database lacks it, and those rows are not read as
  calls (agent_tasks has the same commands). A row that agent_tasks
  already gave is not given again: the two are matched, one to one, by the
  command's text and its start (ShellCommandFinished.start_ts and
  commands.start_ts are the same instant by the source; no real database
  has been compared, so a match within two seconds counts). A command
  that matches nothing is read from the row. Times are naive UTC text
  ('%F %T%.f'), read as UTC. FIFO capped at 10,000 rows by Warp.
- ai_queries(input, working_directory), blocks(stylized_command,
  stylized_output): the user's prompts, and the terminal blocks kept for
  session restore (ANSI text, truncated by Warp). Their encoding is not
  documented beyond that, so they are only searched for secrets, as text.

A call that never ran is "declined": the result is permission_denied (a
denylisted command), terminal_busy, or cancel (the user, or the end of the
conversation). An edit whose result is an error is not declined: Warp
tried it.

Tool names are the .proto field names. The ones judged by what they do
(kind, command, paths) are run_shell_command and write_to_long_running_
shell_command (shell: the second types into a program that is running),
read_files and grep (read), apply_file_diffs (write); use_computer, the
glob, document and codebase tools are known and "other". An MCP call is
named mcp__<server_id>__<name>, as Claude Code names one, and judged by
name. A tool whose fields were not read from the schema (the rest of
TOOLS) is passed on by name with every string in it as "_strings"; a
field number not in TOOLS is counted as unknown.

Limits. Warp keeps at most 200 conversations (a whole orchestration tree
is dropped at a time), 10,000 commands, and 100 blocks per pane; logging
out deletes the database; agent_tasks and agent_conversations are written
only while the "restore windows, tabs and panes" setting is on (default
on), `commands` either way. A task blob over MAX_BLOB, or a string over
MAX_TEXT, is cut: a blob is skipped and counted (unreadable_calls), a
string is kept to its first MAX_TEXT characters (watch) and handed to
clean in MAX_TEXT pieces. Warp's own agent_sdk harnesses for Claude Code,
Codex, Gemini and Pi map those agents' calls into the same tasks, and a
transcript of a cloud agent viewed here is stored too; run_id, is_remote_
child and orchestration_harness_type in conversation_data hint at both but
are not verified as a test, so such a call may be seen twice, once here
and once through that agent's own history.

Not read: the other tables, Warp's login, and conversation_data.
Text that is not UTF-8 is kept by surrogateescape.
"""

from __future__ import annotations

import contextlib
import datetime
import json
import os
import sqlite3
import stat

from . import _paths, _sqlite, _stamps, base
from .base import SecretText, Source, ToolCall

ENV = "XDG_STATE_HOME"

DB = "warp.sqlite"
TUI = "tui"
GROUP = "2BBY89MBSN.dev.warp"

# Folders under the state folder (Linux): Stable, Preview, OSS, OSS warp-tui.
LINUX_FOLDERS = (("warp-terminal", "default"),
                 ("warp-terminal-preview", "probed"),
                 ("warp-oss", "probed"),
                 ("warp-terminal-tui", "probed"))
# Bundle ids (macOS), from app/Cargo.toml [package.metadata.bundle.bin.*].
MAC_BUNDLES = (("dev.warp.Warp-Stable", "default"),
               ("dev.warp.Warp-Preview", "probed"),
               ("dev.warp.WarpOss", "probed"),
               ("dev.warp.Warp-Dev", "probed"),
               ("dev.warp.Warp-Local", "probed"))
# App names (Windows), login_item/windows.rs and warp_tui's oss.rs.
WIN_NAMES = (("Warp", "default"), ("WarpPreview", "probed"),
             ("WarpOss", "probed"), ("WarpDev", "probed"),
             ("WarpTui", "probed"))

WHY_READ_ONLY = ("Warp keeps this in a database; delete the conversation in "
                 "Warp, or clear its history.")
BLOCKED = ("macOS would not let ranwhat in (Warp's folder is protected: "
           "allow Full Disk Access for your terminal)")

NOT_OPENED = "could not be opened"
NOT_DATABASE = "not a readable SQLite database"
DAMAGED = "part of it is damaged"

DECLINED = "declined"

# Bigger than this, a task is not read; longer than this, a string is cut.
MAX_BLOB = 64 << 20
MAX_TEXT = 1000000
# A command row and an agent call are the same when this close.
SAME_RUN = 2.0
# How deep a Struct, and how many strings of an unread tool, are kept.
MAX_DEPTH = 24
MAX_LOOSE = 32

TABLES = ("agent_tasks", "agent_conversations", "commands", "ai_queries",
          "blocks")

# ToolCall's oneof (task.proto).
TOOLS = {
    2: "run_shell_command", 3: "search_codebase", 4: "server",
    5: "read_files", 6: "apply_file_diffs", 7: "suggest_plan",
    8: "suggest_create_plan", 9: "grep", 10: "file_glob",
    11: "read_mcp_resource", 12: "call_mcp_tool",
    13: "write_to_long_running_shell_command",
    14: "suggest_new_conversation", 15: "file_glob_v2", 16: "suggest_prompt",
    17: "open_code_review", 18: "init_project", 19: "subagent",
    20: "read_documents", 21: "edit_documents", 22: "create_documents",
    23: "read_shell_command_output", 24: "use_computer",
    25: "insert_review_comments", 26: "read_skill",
    27: "request_computer_use", 28: "fetch_conversation",
    30: "send_message_to_agent", 31: "transfer_shell_command_control_to_user",
    32: "ask_user_question", 34: "upload_file_artifact", 35: "run_agents",
    36: "wait_for_events", 37: "start_recording", 38: "stop_recording"}

# ToolCallResult's oneof numbers this module reads.
R_SHELL, R_READ, R_DIFFS, R_CANCEL, R_MCP, R_LONG = 2, 5, 6, 14, 16, 17


# -- protobuf, by hand -------------------------------------------------------

class _Bad(Exception):
    """Bytes that are not protobuf."""


def _varint(buf, pos, end):
    result = shift = 0
    while True:
        if pos >= end:
            raise _Bad("truncated")
        byte = buf[pos]
        pos += 1
        result |= (byte & 0x7f) << shift
        if byte < 0x80:
            return result, pos
        shift += 7
        if shift >= 70:
            raise _Bad("overlong varint")


def _parse(buf, pos, end):
    """({field: [values]}, complete) for the message at buf[pos:end]. A
    varint, fixed32 or fixed64 is an int; a length-delimited field is
    (start, stop). On bytes that are not a message, what was read before
    them is returned, with complete False. Groups are not used by the
    schema and end the read."""
    out = {}
    try:
        while pos < end:
            key, pos = _varint(buf, pos, end)
            number, wire = key >> 3, key & 7
            if number == 0:
                raise _Bad("field 0")
            if wire == 0:
                value, pos = _varint(buf, pos, end)
            elif wire == 1 or wire == 5:
                size = 8 if wire == 1 else 4
                if pos + size > end:
                    raise _Bad("truncated")
                value = int.from_bytes(buf[pos:pos + size], "little")
                pos += size
            elif wire == 2:
                size, pos = _varint(buf, pos, end)
                if pos + size > end:
                    raise _Bad("truncated")
                value = (pos, pos + size)
                pos += size
            else:
                raise _Bad("wire type %d" % wire)
            out.setdefault(number, []).append(value)
    except _Bad:
        return out, False
    return out, True


def _first(fields, number):
    values = fields.get(number)
    return values[0] if values else None


def _ranges(fields, number):
    return [v for v in fields.get(number, ()) if isinstance(v, tuple)]


def _range(fields, number):
    value = _first(fields, number)
    return value if isinstance(value, tuple) else None


def _sub(buf, fields, number):
    """The fields of an embedded message, {} when absent or damaged."""
    rng = _range(fields, number)
    return _parse(buf, rng[0], rng[1])[0] if rng else {}


def _subs(buf, fields, number):
    return [_parse(buf, s, e)[0] for s, e in _ranges(fields, number)]


def _str(buf, fields, number):
    """A string field, "" when absent. Cut at MAX_TEXT characters."""
    rng = _range(fields, number)
    if rng is None:
        return ""
    return buf[rng[0]:rng[1]].decode("utf-8", "surrogateescape")[:MAX_TEXT]


def _strs(buf, fields, number):
    return [buf[s:e].decode("utf-8", "surrogateescape")[:MAX_TEXT]
            for s, e in _ranges(fields, number)]


def _int(fields, number, signed=False):
    value = _first(fields, number)
    if isinstance(value, tuple) or value is None:
        return 0
    if signed and value >= 1 << 63:
        value -= 1 << 64
    return value


def _flag(fields, number):
    return number in fields


def _double(bits):
    """An IEEE 754 double from its 64 bits, without struct."""
    sign = -1.0 if bits >> 63 else 1.0
    exponent = (bits >> 52) & 0x7ff
    mantissa = bits & ((1 << 52) - 1)
    if exponent == 0x7ff:
        return None if mantissa else sign * float("inf")
    if exponent == 0:
        return sign * mantissa * 2.0 ** -1074
    return sign * (1 + mantissa / 4503599627370496.0) * 2.0 ** (exponent - 1023)


def _value(buf, fields, depth):
    """A google.protobuf.Value as JSON would show it."""
    if depth > MAX_DEPTH:
        return None
    if 3 in fields:
        return _str(buf, fields, 3)
    if 4 in fields:
        return bool(_int(fields, 4))
    if 2 in fields:
        number = _first(fields, 2)
        return _double(number) if not isinstance(number, tuple) else None
    if 5 in fields:
        return _struct(buf, _sub(buf, fields, 5), depth + 1)
    if 6 in fields:
        items = _sub(buf, fields, 6)
        return [_value(buf, f, depth + 1) for f in _subs(buf, items, 1)]
    return None


def _struct(buf, fields, depth=0):
    """A google.protobuf.Struct as a dict: field 1 is its map entries."""
    out = {}
    if depth > MAX_DEPTH:
        return out
    for entry in _subs(buf, fields, 1):
        key = _str(buf, entry, 1)
        out[key] = _value(buf, _sub(buf, entry, 2), depth + 1)
    return out


def _printable(text):
    return all(c >= " " or c in "\n\r\t\x1b" for c in text) and "\x7f" not in text


def _loose(buf, start, end, depth=0, out=None, limit=None):
    """Every string in bytes of a message this module has no schema for:
    a length-delimited field that is clean UTF-8 text is a string; one that
    parses whole as a message is walked; anything else that is valid UTF-8
    is a string too. Not exact, and meant for searching, not for judging."""
    out = [] if out is None else out
    fields, _ok = _parse(buf, start, end)
    for values in fields.values():
        for value in values:
            if limit is not None and len(out) >= limit:
                return out
            if not isinstance(value, tuple) or value[1] == value[0]:
                continue
            raw = buf[value[0]:value[1]]
            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError:
                text = None
            if text is not None and _printable(text):
                out.append(text)
                continue
            if depth < MAX_DEPTH:
                inner, complete = _parse(buf, value[0], value[1])
                if inner and complete:
                    _loose(buf, value[0], value[1], depth + 1, out, limit)
                    continue
            if text is not None:
                out.append(text)
    return out


# -- values -----------------------------------------------------------------

def _string(value):
    return value if isinstance(value, str) and value else None


def _isabs(value, platform):
    return _paths.pathmod(platform).isabs(value)


def _cell(value):
    """A cell as text: a BLOB where TEXT is expected is read as UTF-8."""
    if isinstance(value, (bytes, memoryview)):
        return bytes(value).decode("utf-8", "surrogateescape")
    return value


def _when(text):
    """A naive-UTC datetime for Warp's text times ('2026-10-20
    09:14:03.512345'; a zone, if one is written, is honoured), or None."""
    if not isinstance(text, str):
        return None
    when, zoned = _stamps.parse_stamp(text)
    if when is None:
        return None
    try:
        if zoned:
            when = when.astimezone(datetime.timezone.utc).replace(tzinfo=None)
    except (ValueError, OverflowError):
        return None
    return when


def _iso(when):
    try:
        return when.strftime("%Y-%m-%dT%H:%M:%SZ") if when else None
    except ValueError:
        return None


def _epoch(when):
    try:
        return when.replace(tzinfo=datetime.timezone.utc).timestamp()
    except (ValueError, OverflowError, OSError):
        return None


def _stamp_fields(fields):
    """(seconds as float, ISO) of a google.protobuf.Timestamp field, or
    (None, None) when absent or not a time."""
    seconds = _int(fields, 1, signed=True)
    nanos = _int(fields, 2, signed=True)
    iso = _stamps.iso_utc(seconds, "s") if fields else None
    if iso is None:
        return None, None
    return seconds + nanos / 1e9, iso


def _timestamp(buf, message, number):
    return _stamp_fields(_sub(buf, message, number))


def _pieces(text):
    """A long string in pieces clean can search whole (clean.MAX_STRING)."""
    if len(text) <= MAX_TEXT:
        return [text]
    return [text[i:i + MAX_TEXT] for i in range(0, len(text), MAX_TEXT)]


def _json(text):
    """Decoded JSON for text that is an object or list, else the text."""
    if isinstance(text, str) and text[:1] in ("{", "["):
        try:
            return json.loads(text)
        except (ValueError, RecursionError):
            pass
    return text


# -- one tool call ------------------------------------------------------------

class _Tool(object):
    """What a tool call's fields say: how watch should judge it."""
    __slots__ = ("name", "kind", "known", "command", "paths", "consumed",
                 "input")

    def __init__(self, name, kind="other", known=False, command=None,
                 paths=(), consumed=(), input=None):
        self.name = name
        self.kind = kind
        self.known = known
        self.command = command
        self.paths = tuple(paths)
        self.consumed = tuple(consumed)
        self.input = input if input is not None else {}


def _file_edit(buf, call):
    """apply_file_diffs: the edit, and every path it names."""
    out, paths = {}, []

    def path(value):
        if value:
            paths.append(value)
        return value

    summary = _str(buf, call, 1)
    if summary:
        out["summary"] = summary
    diffs = [{"file_path": path(_str(buf, f, 1)), "search": _str(buf, f, 2),
              "replace": _str(buf, f, 3)} for f in _subs(buf, call, 2)]
    if diffs:
        out["diffs"] = diffs
    files = [{"file_path": path(_str(buf, f, 1)), "content": _str(buf, f, 2),
              "allow_overwrite": bool(_int(f, 3))}
             for f in _subs(buf, call, 3)]
    if files:
        out["new_files"] = files
    deleted = [{"file_path": path(_str(buf, f, 1))}
               for f in _subs(buf, call, 4)]
    if deleted:
        out["deleted_files"] = deleted
    updates = []
    for f in _subs(buf, call, 5):
        update = {"file_path": path(_str(buf, f, 1))}
        if _str(buf, f, 2):
            update["move_to"] = path(_str(buf, f, 2))
        update["hunks"] = [
            {"change_context": _strs(buf, h, 1),
             "pre_context": _str(buf, h, 2), "old": _str(buf, h, 3),
             "new": _str(buf, h, 4), "post_context": _str(buf, h, 5)}
            for h in _subs(buf, f, 3)]
        updates.append(update)
    if updates:
        out["v4a_updates"] = updates
    return _Tool("apply_file_diffs", "write", True, paths=paths, input=out)


def _tool(buf, number, rng):
    """The _Tool for the ToolCall oneof member `number` at rng."""
    name = TOOLS.get(number)
    if name is None:
        return _Tool("unknown_tool_%d" % number)
    fields = _parse(buf, rng[0], rng[1])[0]
    if number == 2:
        command = _string(_str(buf, fields, 1))
        return _Tool(name, "shell", True, command=command,
                     consumed=("command",) if command else (),
                     input={"command": _str(buf, fields, 1)})
    if number == 13:
        raw = _range(fields, 1)
        typed = (buf[raw[0]:raw[1]].decode("utf-8", "surrogateescape")
                 [:MAX_TEXT] if raw else "")
        command = typed if typed.strip() else None
        return _Tool(name, "shell", True, command=command,
                     consumed=("input",) if command else (),
                     input={"input": typed,
                            "command_id": _str(buf, fields, 3)})
    if number == 5:
        names = [n for n in (_str(buf, f, 1) for f in _subs(buf, fields, 1))
                 if n]
        return _Tool(name, "read", True, paths=names,
                     consumed=("files",) if names else (),
                     input={"files": names})
    if number == 6:
        return _file_edit(buf, fields)
    if number == 9:
        path = _string(_str(buf, fields, 2))
        return _Tool(name, "read", True, paths=(path,) if path else (),
                     consumed=("path",) if path else (),
                     input={"queries": _strs(buf, fields, 1),
                            "path": _str(buf, fields, 2)})
    if number == 10:
        return _Tool(name, "other", True,
                     input={"patterns": _strs(buf, fields, 1),
                            "path": _str(buf, fields, 2)})
    if number == 15:
        return _Tool(name, "other", True,
                     input={"patterns": _strs(buf, fields, 1),
                            "search_dir": _str(buf, fields, 2)})
    if number == 3:
        return _Tool(name, "other", True,
                     input={"query": _str(buf, fields, 1),
                            "path_filters": _strs(buf, fields, 2),
                            "codebase_path": _str(buf, fields, 3)})
    if number == 12:
        server = _str(buf, fields, 3)
        tool = _str(buf, fields, 1) or "call_mcp_tool"
        return _Tool("mcp__%s__%s" % (server, tool) if server else tool,
                     input={"name": tool, "server_id": server,
                            "args": _struct(buf, _sub(buf, fields, 2))})
    if number == 11:
        return _Tool(name, "other", False,
                     input={"uri": _str(buf, fields, 1),
                            "server_id": _str(buf, fields, 2)})
    if number == 24:
        return _Tool(name, "other", True,
                     input={"action_summary": _str(buf, fields, 3)})
    if number == 22:
        return _Tool(name, "other", True, input={"documents": [
            {"title": _str(buf, d, 2), "content": _str(buf, d, 1)}
            for d in _subs(buf, fields, 1)]})
    if number == 21:
        return _Tool(name, "other", True, input={"diffs": [
            {"document_id": _str(buf, d, 1), "search": _str(buf, d, 2),
             "replace": _str(buf, d, 3)} for d in _subs(buf, fields, 1)]})
    if number == 20:
        return _Tool(name, "other", True, input={"documents": [
            _str(buf, d, 1) for d in _subs(buf, fields, 1)]})
    # Not read from the schema: every string, for rules that read them all.
    strings = [t[:MAX_TEXT] for t in _loose(buf, rng[0], rng[1],
                                            limit=MAX_LOOSE)]
    return _Tool(name, "other", False,
                 input={"_strings": strings} if strings else {})


# -- the source ----------------------------------------------------------------

class WarpSource(Source):
    id = "warp"
    name = "Warp"
    unit = "database"
    env = (ENV,)
    path_means = ("a Warp state folder (the one holding warp.sqlite), or the "
                  "warp.sqlite file")
    read_only = True        # SQLite, every store of it
    checked = "source cd4b970e6331; Stable 0.2026.10.14"

    def reset(self):
        Source.reset(self)
        self._bad = set()           # stores already counted as unreadable
        self._tallied = set()       # stores whose odd records are counted

    # -- where to look ------------------------------------------------------

    def default_paths(self, env, home, platform):
        """The state folders of Warp's channels on this platform (see the
        module notes). Folders, not files: stores() looks for warp.sqlite
        and tui/warp.sqlite in each."""
        plat = _paths.platform_name(platform)
        join = _paths.pathmod(plat).join
        out = []
        if plat == "win32":
            base_dir = join(_paths.localappdata(env, home), "warp")
            for app, how in WIN_NAMES:
                out.append((join(base_dir, app, "data"), how))
            return out
        if plat == "darwin":
            group = join(home, "Library", "Group Containers", GROUP,
                         "Library", "Application Support")
            for bundle, how in MAC_BUNDLES:
                out.append((join(group, bundle), how))
            for bundle, _how in MAC_BUNDLES:
                out.append((join(_paths.application_support(home), bundle),
                            "probed"))
            return out
        state = env.get(ENV)
        moved = isinstance(state, str) and state and _isabs(state, plat)
        if not moved:
            state = join(home, ".local", "state")
        for folder, how in LINUX_FOLDERS:
            out.append((join(state, folder),
                        "env " + ENV if moved else how))
        return out

    def stores(self, locations, since_days=None):
        """warp.sqlite, and tui/warp.sqlite beside it, in each location;
        a location that is a file is the store itself. Whatever their
        mtime (base.newest_first keeps a database: its newest rows can sit
        in its -wal)."""
        found, seen = [], set()
        for loc in locations:
            for path in self._candidates(loc.path):
                key = os.path.normcase(os.path.abspath(path))
                if key in seen:
                    continue
                seen.add(key)
                store = self.store(path, "sqlite", unit=self.unit,
                                   why_read_only=WHY_READ_ONLY)
                if store is not None:
                    found.append(store)
        return base.newest_first(found, since_days)

    def _candidates(self, path):
        """The database files a location holds."""
        try:
            info = os.stat(path)
        except FileNotFoundError:
            return []
        except PermissionError:
            self._bad_path(path, BLOCKED, "cannot read %s (%s)"
                           % (path, BLOCKED))
            return []
        except OSError:
            return []
        if stat.S_ISREG(info.st_mode):
            return [path]
        if not stat.S_ISDIR(info.st_mode):
            return []
        out = []
        for rel in ((DB,), (TUI, DB)):
            candidate = os.path.join(path, *rel)
            try:
                if stat.S_ISREG(os.stat(candidate).st_mode):
                    out.append(candidate)
            except PermissionError:
                self._bad_path(candidate, BLOCKED, "cannot read %s (%s)"
                               % (candidate, BLOCKED))
            except OSError:
                continue
        return out

    # -- bookkeeping --------------------------------------------------------

    def _bad_path(self, path, reason, message=None):
        """Count a database that could not be read, or not to its end, once
        a run, and warn once. The message never holds what SQLite said: an
        error can quote a cell."""
        if path not in self._bad:
            self._bad.add(path)
            self.unreadable_store(reason, path)
        self.warn(path, message or "could not read Warp database %s (%s)"
                  % (path, reason))

    def _bad_store(self, store, reason, message=None):
        self._bad_path(store.path, reason, message)

    def _first(self, store):
        """True the first time a store is read this run: watch and clean
        both read it, and what they skip is counted once."""
        first = store.path not in self._tallied
        self._tallied.add(store.path)
        return first

    def notes(self, locations=None, platform=None):
        out = []
        n = self.counts.get("unreadable_calls", 0)
        if n:
            out.append("%d Warp conversation task%s over %d MiB %s not read."
                       % (n, "" if n == 1 else "s", MAX_BLOB >> 20,
                          "was" if n == 1 else "were"))
        return out

    # -- the database -------------------------------------------------------

    def _is_database(self, store):
        """True when the file starts as a SQLite database does; a file that
        is not one is said so without opening it in SQLite. An empty file
        holds nothing."""
        try:
            with open(store.path, "rb") as fh:
                magic = fh.read(len(_sqlite.SQLITE_MAGIC))
        except FileNotFoundError:
            return False
        except OSError as e:
            self._bad_store(store, NOT_OPENED, "cannot read %s (%s)%s"
                            % (store.path, type(e).__name__,
                               "; " + BLOCKED if isinstance(
                                   e, PermissionError) else ""))
            return False
        if not magic:
            return False
        if magic != _sqlite.SQLITE_MAGIC:
            self._bad_store(store, NOT_DATABASE, "cannot read %s: %s"
                            % (store.path, NOT_DATABASE))
            return False
        return True

    @contextlib.contextmanager
    def _open(self, store, tally=False):
        """(connection, {table: [columns]}) for the tables read here, or
        None when the store cannot be read. The temp copy of a locked
        database is removed however the caller stops."""
        if not self._is_database(store):
            yield None
            return
        with _sqlite.readonly(store.path) as conn:
            if conn is None:
                self._bad_store(store, NOT_OPENED, "could not open %s "
                                "(permissions, or Warp holds it locked)"
                                % store.path)
                yield None
                return
            try:
                present = set(_sqlite.tables(conn))
                layout = {t: _sqlite.columns(conn, t)
                          for t in TABLES if t in present}
            except sqlite3.Error as e:
                self._bad_store(store, NOT_DATABASE, "cannot read %s: %s (%s)"
                                % (store.path, NOT_DATABASE,
                                   type(e).__name__))
                yield None
                return
            if not layout and tally and present:
                self.count("unknown")
            yield conn, layout

    def _rows(self, store, conn, layout, table, wanted, where="", params=()):
        """{column: value} for each row of `table`, asking only for the
        columns that exist, from a cursor. SQLite failing part way warns,
        counts the store, and keeps what was read."""
        cols = [c for c in wanted if c in layout.get(table, ())]
        if not cols:
            return
        try:
            for row in _sqlite.iter_rows(conn, table, cols, where, params):
                yield row
        except sqlite3.Error as e:
            self._bad_store(store, DAMAGED, "stopped reading table %s of %s "
                            "(%s)" % (table, store.path, type(e).__name__))

    def _conversations(self, store, conn, layout):
        """{conversation_id: initial working directory} from the summaries."""
        out = {}
        for row in self._rows(store, conn, layout, "agent_conversations",
                              ("conversation_id", "summary")):
            cid = row.get("conversation_id")
            summary = _json(row.get("summary"))
            if isinstance(cid, str) and isinstance(summary, dict):
                out[cid] = _string(summary.get("initial_working_directory"))
        return out

    def _tasks(self, store, conn, layout):
        """(row, blob) for every agent_tasks row whose task is bytes of a
        size read here; the others are counted. The size is asked of SQLite
        first, so an oversize blob is never loaded."""
        if "task" not in layout.get("agent_tasks", ()):
            return
        try:
            big = conn.execute('SELECT count(*) FROM "agent_tasks" WHERE '
                               'length("task") > ?', (MAX_BLOB,)).fetchone()
        except sqlite3.Error:
            big = None
        if big and big[0] and self._first_big(store):
            self.count("unreadable_calls", big[0])
            self.warn(("big", store.path), "%d Warp task%s in %s over %d MiB "
                      "not read" % (big[0], "" if big[0] == 1 else "s",
                                    store.path, MAX_BLOB >> 20))
        for row in self._rows(
                store, conn, layout, "agent_tasks",
                ("conversation_id", "task_id", "task", "last_modified_at"),
                'length("task") <= ?', (MAX_BLOB,)):
            blob = row.get("task")
            if isinstance(blob, memoryview):
                blob = bytes(blob)
            yield row, blob if isinstance(blob, bytes) else None

    def _first_big(self, store):
        key = ("big", store.path)
        first = key not in self._tallied
        self._tallied.add(key)
        return first

    # -- calls --------------------------------------------------------------

    def tool_calls(self, store):
        """Every call the agent made, once: from the transcript (agent_tasks)
        with its result's output, and declined when it never ran; then the
        commands Warp's agent ran that the transcript does not hold. Never
        raises: a store that cannot be read warns and is counted."""
        try:
            for call in self._tool_calls(store):
                yield call
        except Exception as e:      # never raise: say so and go on
            self.stopped(store, e)

    def _tool_calls(self, store):
        tally = self._first(store)
        with self._open(store, tally) as opened:
            if opened is None:
                return
            conn, layout = opened
            ran = {}                # command -> [start (epoch) or None]
            projects = self._conversations(store, conn, layout)
            seen = set()
            for row, blob in self._tasks(store, conn, layout):
                if blob is None:
                    if tally:
                        self.count("unparsed")
                    continue
                cid = row.get("conversation_id")
                for call in self._task_calls(store, blob, row, projects.get(
                        cid), tally, ran):
                    key = (cid, call.tool_call_id)
                    if call.tool_call_id and key in seen:
                        continue
                    seen.add(key)
                    yield call
            for call in self._command_calls(store, conn, layout, ran):
                yield call

    def _task_calls(self, store, buf, row, project, tally, ran):
        """The calls in one Task blob, each when its result arrives, the
        rest at the end."""
        fields, complete = _parse(buf, 0, len(buf))
        if not complete and tally:
            self.count("unparsed")
        cid = row.get("conversation_id")
        modified = _iso(_when(row.get("last_modified_at")))
        pwd = project
        pending = {}
        for start, stop in _ranges(fields, 5):
            message, ok = _parse(buf, start, stop)
            if not ok:
                if tally:
                    self.count("unparsed")
                continue
            if 2 in message:
                query = _sub(buf, message, 2)
                here = _string(_str(buf, _sub(buf, _sub(buf, query, 2), 1), 1))
                pwd = here or pwd
            elif 4 in message:
                call = self._call(store, buf, message, cid, pwd, modified,
                                  tally)
                if call is None:
                    continue
                if call.tool_call_id:
                    pending.setdefault(call.tool_call_id, call)
                else:
                    self._note_run(call, None, ran)
                    yield call
            elif 5 in message:
                result = _sub(buf, message, 5)
                call = pending.pop(_str(buf, result, 1), None)
                if call is None:
                    continue
                start = self._answer(buf, call, result)
                self._note_run(call, start, ran)
                yield call
        for call in pending.values():
            self._note_run(call, None, ran)
            yield call

    def _call(self, store, buf, message, cid, pwd, modified, tally):
        call = _sub(buf, message, 4)
        members = [n for n in call if n != 1]
        if not members:
            return None
        if members[0] not in TOOLS and tally:
            self.count("unknown")
        tool = _tool(buf, members[0], _range(call, members[0]) or (0, 0))
        _seconds, stamp = _timestamp(buf, message, 14)
        tcid = _str(buf, call, 1)
        return ToolCall(
            self.id, store.path, tool.name, tool.input, kind=tool.kind,
            known=tool.known, session=cid, project=pwd, timestamp=stamp,
            not_after=None if stamp else (modified or _iso(
                _when_mtime(store.mtime))),
            tool_call_id=tcid or None, command=tool.command,
            workdir=pwd if tool.kind == "shell" else None, paths=tool.paths,
            consumed=tool.consumed)

    def _answer(self, buf, call, result):
        """Fold a ToolCallResult into its call: output, declined, what
        really ran, and the directory it ran in. Returns when a shell
        command started (epoch seconds), or None."""
        here = _string(_str(buf, _sub(buf, _sub(buf, result, 11), 1), 1))
        if here and call.kind == "shell":
            call.workdir = here
            call.project = here
        if R_CANCEL in result:
            call.status = DECLINED
            return None
        if R_SHELL in result or R_LONG in result:
            shell = _sub(buf, result, R_SHELL if R_SHELL in result else R_LONG)
            if R_SHELL in result:
                if 6 in shell or 7 in shell:        # denylisted, busy
                    call.status = DECLINED
                ran = _string(_str(buf, shell, 3))
                if ran and call.kind == "shell" and call.command != ran:
                    call.tool_input = dict(
                        call.tool_input, requested_command=call.command or "",
                        command=ran)
                    call.command = ran
                    call.consumed = frozenset(["command"])
                finished = _sub(buf, shell, 5)
                snapshot = _sub(buf, shell, 4)
            else:
                finished = _sub(buf, shell, 2)
                snapshot = _sub(buf, shell, 1)
            start = None
            if finished:
                call.output = _str(buf, finished, 1)
                start, stamp = _timestamp(buf, finished, 4)
                if call.timestamp is None and stamp:
                    call.timestamp, call.not_after = stamp, None
            elif snapshot:
                call.output = _str(buf, snapshot, 1)
            return start
        if R_DIFFS in result:
            error = _sub(buf, _sub(buf, result, R_DIFFS), 2)
            if error:
                call.output = _str(buf, error, 1)
            return None
        if R_READ in result:
            read = _sub(buf, result, R_READ)
            texts = [_str(buf, f, 2) for f in _subs(
                buf, _sub(buf, read, 1), 1)]
            error = _sub(buf, read, 2)
            if texts:
                call.output = "\n".join(texts)[:MAX_TEXT]
            elif error:
                call.output = _str(buf, error, 1)
            return None
        if R_MCP in result:
            mcp = _sub(buf, result, R_MCP)
            texts = [_str(buf, _sub(buf, r, 1), 1)
                     for r in _subs(buf, _sub(buf, mcp, 1), 1) if 1 in r]
            error = _sub(buf, mcp, 2)
            if texts:
                call.output = "\n".join(texts)[:MAX_TEXT]
            elif error:
                call.output = _str(buf, error, 1)
        return None

    @staticmethod
    def _note_run(call, start, ran):
        """Remember a shell command that ran, so its `commands` row is not
        given a second time. Typing into a running program makes no row."""
        if call.tool_name == "run_shell_command" and call.command \
                and call.status is None:
            ran.setdefault(call.command, []).append(start)

    def _command_calls(self, store, conn, layout, ran):
        """Commands Warp's agent ran that no transcript call accounts for."""
        cols = layout.get("commands", ())
        if "is_agent_executed" not in cols or "command" not in cols:
            return
        for row in self._rows(
                store, conn, layout, "commands",
                ("id", "command", "start_ts", "pwd", "session_id",
                 "is_agent_executed"), '"is_agent_executed" = 1'):
            command = _string(_cell(row.get("command")))
            if command is None:
                continue
            when = _when(row.get("start_ts"))
            if self._covered(ran, command, _epoch(when) if when else None):
                continue
            pwd = _string(_cell(row.get("pwd")))
            session = row.get("session_id")
            stamp = _iso(when)
            yield ToolCall(
                self.id, store.path, "run_shell_command", {"command": command},
                kind="shell", known=True,
                session=str(session) if session is not None else None,
                project=pwd, timestamp=stamp,
                not_after=None if stamp else _iso(_when_mtime(store.mtime)),
                tool_call_id="command:%s" % row.get("id"), command=command,
                workdir=pwd, consumed=("command",))

    @staticmethod
    def _covered(ran, command, epoch):
        """True, and the match used up, when an agent call ran this command
        at this time (or at none known)."""
        starts = ran.get(command)
        if not starts:
            return False
        best = None
        for index, start in enumerate(starts):
            if start is None or epoch is None:
                near = best is None
                if near:
                    best = index
            elif abs(start - epoch) <= SAME_RUN:
                best = index
                break
        if best is None:
            return False
        starts.pop(best)
        return True

    # -- text ---------------------------------------------------------------

    def secret_texts(self, store):
        """Every string Warp holds that a person or an agent wrote: the
        transcript (queries, replies, each call's input and its output tied
        to it, and every string of the messages not read from the schema),
        conversation titles and first queries, the prompts of ai_queries,
        every command in `commands` (the user's too) and the terminal
        blocks kept for restore. Never raises."""
        try:
            for text in self._secret_texts(store):
                yield text
        except Exception as e:      # never raise: say so and go on
            self.stopped(store, e)

    def _secret_texts(self, store):
        tally = self._first(store)
        with self._open(store, tally) as opened:
            if opened is None:
                return
            conn, layout = opened
            for row in self._rows(store, conn, layout, "agent_conversations",
                                  ("conversation_id", "summary")):
                summary = _json(row.get("summary"))
                where = "agent_conversations %s" % row.get("conversation_id")
                if isinstance(summary, dict):
                    node = {k: summary[k] for k in
                            ("title", "initial_query",
                             "initial_working_directory")
                            if isinstance(summary.get(k), str)}
                    if node:
                        yield SecretText(node, where=where)
                elif isinstance(summary, str) and summary:
                    yield SecretText(summary, where=where)
            for row, blob in self._tasks(store, conn, layout):
                if blob is None:
                    if tally:
                        self.count("unparsed")
                    continue
                for text in self._task_texts(store, blob, row, tally):
                    yield text
            for table, columns in (("ai_queries", ("input",
                                                   "working_directory")),
                                   ("commands", ("command",
                                                 "workflow_command")),
                                   ("blocks", ("stylized_command",
                                               "stylized_output"))):
                for row in self._rows(store, conn, layout, table,
                                      ("id",) + columns):
                    where = "%s row %s" % (table, row.get("id"))
                    for col in columns:
                        cell = row.get(col)
                        if isinstance(cell, (bytes, memoryview)):
                            cell = bytes(cell).decode("utf-8", "surrogateescape")
                        if not isinstance(cell, str) or not cell:
                            continue
                        node = _json(cell)
                        for piece in (_pieces(node) if isinstance(node, str)
                                      else [node]):
                            yield SecretText(piece, where="%s, %s"
                                             % (where, col))

    def _task_texts(self, store, buf, row, tally):
        fields, _ok = _parse(buf, 0, len(buf))
        task = row.get("task_id")
        calls = {}
        pwd = None
        for index, (start, stop) in enumerate(_ranges(fields, 5), 1):
            message, ok = _parse(buf, start, stop)
            if not ok or not message:
                continue
            where = "agent_tasks %s, message %d" % (task, index)
            if 4 in message:
                made = self._call(store, buf, message, row.get(
                    "conversation_id"), pwd, None, False)
                if made is not None:
                    if made.tool_call_id:
                        calls.setdefault(made.tool_call_id, made)
                    yield SecretText(made.tool_input, call=made, where=where)
                if stop - start > MAX_TEXT:     # _str cut a long string
                    for text in _loose(buf, start, stop):
                        for piece in _pieces(text):
                            yield SecretText(piece, where=where)
                continue
            if 5 in message:
                result = _sub(buf, message, 5)
                made = calls.get(_str(buf, result, 1))
                if made is not None:
                    self._answer(buf, made, result)
                    for piece in _pieces(made.output or ""):
                        if piece:
                            yield SecretText(piece, call=made, where=where)
                    if any(n in result for n in (R_SHELL, R_LONG, R_MCP,
                                                 R_READ)) \
                            and stop - start <= MAX_TEXT:
                        continue
            for text in _loose(buf, start, stop):
                for piece in _pieces(text):
                    yield SecretText(piece, where=where)


def _when_mtime(mtime):
    try:
        return datetime.datetime.fromtimestamp(
            mtime, datetime.timezone.utc).replace(tzinfo=None)
    except (OverflowError, OSError, ValueError, TypeError):
        return None
