"""Grok Build: xAI's official `grok` CLI (design 7.7). Source id "grok".

The Rust agent at github.com/xai-org/grok-build keeps one folder per
session under $GROK_HOME (default ~/.grok, %USERPROFILE%\\.grok on
Windows). In each sessions/<encoded cwd>/<session uuid>/ folder:

    updates.jsonl           transcript
    chat_history.jsonl      side; the transcript only when updates.jsonl
                            is missing in that folder
    summary.json            side, and the session map: {info: {id, cwd}, ...}
    terminal/<id>.log       side: a command's full output, untruncated, one
                            plain-text file per call (<id> is the call's
                            toolCallId); terminal/monitor-<id>.log for the
                            monitor tool
    compaction/segment_NNN.md, compaction/INDEX.md
                            side: the turns a compaction dropped, tool
                            output included, as Markdown
    compaction_checkpoints/<id>.json, compaction_requests/<id>.json,
    recap_requests/<id>.json
                            side: copies of the conversation, tool output
                            included
    mcp/<id>.json, mcp/<id>.txt
                            side: an MCP output saved whole for being over
                            the limit

Subagent and worktree child sessions sit in the same tree. The <encoded
cwd> folder name is never decoded (it can be a slug plus a hash): the
working directory is summary.json's info.cwd.

Nothing else is opened: not config.toml, not logs/, not any other session
file (plan.json, rewind_points.jsonl, subagents/, ...). The
community grok-cli keeps grok.db in the same ~/.grok; this adapter tells
the two apart by file, so grok.db alone is zero stores here.

updates.jsonl lines are ACP session/update envelopes (or, in old sessions,
the bare notification with no envelope). A tool call is assembled from its
lines by toolCallId. The `tool_call` line names it
(update._meta["x.ai/tool"].name, else that line's title; never a later
title, which is display text such as "Execute `ls`") and holds the model's
arguments as rawInput. The next `tool_call_update` carries the canonical
input (x.ai/tool.input, which the first line never has) and rawInput as the
typed input, tagged with "variant". Later lines carry status, content[] and
rawOutput. Bash rawOutput.output is a JSON array of byte values, which is
why this source declares byte_arrays: clean masks a value inside such an
array too.

A command the user typed with `!` (bash mode) is its own call: toolCallId
"bash-mode-<uuid>", _meta {"bash_mode": true}, and x.ai/tool only when the
session's toolset has a shell. It is a shell call the user ran.

Checked against the source at commit 2bdd1d6a (main, after v1.0), not
against a real install.
"""

from __future__ import annotations

import collections
import json
import os
import stat

from . import _lines, _paths, _stamps
from .base import SecretText, Source, ToolCall, decode_input, newest_first

ENV = "GROK_HOME"

SESSIONS = "sessions"
UPDATES = "updates.jsonl"
CHAT_HISTORY = "chat_history.jsonl"
SUMMARY = "summary.json"

# Every agent shell call's full, untruncated output, one plain-text file per
# call in the session folder: terminal/<toolCallId>.log (grok_build and
# opencode bash), terminal/monitor-<toolCallId>.log (the monitor tool).
# Bash-mode commands have none. Kept until storage.cleanup_ttl_days prunes
# the session.
TERMINAL = "terminal"
LOG_SUFFIX = ".log"
MONITOR_LOG_PREFIX = "monitor-"

# Each compaction writes compaction/segment_NNN.md (the dropped turns,
# tool_response bodies included) and appends a row to compaction/INDEX.md
# (xai-compaction-transcript).
COMPACTION = "compaction"
COMPACTION_INDEX = "INDEX.md"
SEGMENT_PREFIX = "segment_"
SEGMENT_SUFFIX = ".md"

# Copies of the conversation, tool output included, each <id>.json written
# once and pretty-printed (notification.rs): the compacted history a rewind
# restores, and the whole history sent for a compaction or a recap.
HISTORY_COPIES = ("compaction_checkpoints", "compaction_requests", "recap_requests")
# An MCP output over the limit, saved whole as mcp/<call id>.json when it
# is JSON, else .txt (mcp_truncate.rs).
MCP = "mcp"

# Both are written: the standard ACP method and xAI's extension. Old
# sessions also hold lines with no envelope, the notification itself
# {"sessionId", "update"}, which the reader still replays (storage/mod.rs
# SessionUpdateEnvelope::from_str). A line with any other method is not
# written by Grok Build and is counted as unknown; see _update.
METHODS = ("session/update", "_x.ai/session/update")
CALL_UPDATES = ("tool_call", "tool_call_update")
XAI_TOOL = "x.ai/tool"
# Written when a background command exits, with the task id its
# BackgroundTaskStarted gave (notification_bridge.rs).
TASK_COMPLETED = "task_completed"

# A command the user typed with `!` (bash mode) is written as its own
# tool_call: toolCallId "bash-mode-<uuid>", _meta {"bash_mode": true}, and
# x.ai/tool only when the toolset has an execute tool (tool_dispatch.rs).
# With no x.ai/tool, its title is display text ("Execute `cmd`"), so the
# call is named by the marker instead.
BASH_MODE = "bash_mode"
BASH_MODE_ID_PREFIX = "bash-mode-"

# Wire tool names (xai-grok-tools tool_taxonomy.rs, xai-grok-agent
# config.rs), mapped per 7.7.
SHELL_NAMES = ("run_terminal_cmd", "bash", "run_terminal_command")
# The monitor tool (core toolsets; kind "monitor") runs rawInput.command in
# the background and reports each stdout line (monitor/types.rs).
MONITOR_NAMES = ("monitor",)
# read_file (grok_build, concise and codex toolsets) and hashline_read (the
# hashline toolset; kind read, the same ReadFileInput as read_file).
READ_NAMES = ("read_file", "hashline_read")
SEARCH_REPLACE = "search_replace"
PATH_WRITE_NAMES = ("apply_patch", "write", "edit", "hashline_edit")
OTHER_NAMES = ("todo_write",)

# Grok's own kinds (x.ai/tool.kind) for a name the table does not list:
# these run a command.
SHELL_KINDS = ("execute", "monitor")

# Where a read tool's rawInput names its file: target_file (ReadFileInput:
# grok_build, concise, hashline), file_path (codex read_file), filePath
# (opencode read, whose input is camelCase).
_READ_KEYS = ("target_file", "file_path", "filePath")

# Where a write tool's rawInput names its file when there is no canonical
# input.path: file_path (opencode write, hashline_edit, and the typed
# SearchReplace input opencode edit becomes), filePath (opencode edit's own
# camelCase arguments). apply_patch names none.
_WRITE_KEYS = ("file_path", "filePath")

# Where a canonical input (x.ai/tool.input) gives a shell its directory,
# after rawOutput.current_dir. Tolerated per 7.7: the first-party Bash
# projection at the checked commit carries only command and description.
_CANON_DIRS = ("cwd", "directory")

# chat_history.jsonl item types (xai-grok-sampling-types conversation.rs).
# Only assistant items carry tool calls; the rest are clean-only.
CHAT_TYPES = ("user", "assistant", "tool_result", "system",
              "backend_tool_call", "reasoning")

# The same bound as clean.MAX_STRING, kept here because sources never
# import clean at module level: a tool's output is cut to this many
# characters on a ToolCall. clean reads the full text from secret_texts.
MAX_OUTPUT = 1_000_000

# summary.json is a few hundred bytes. One far larger is not read for the
# session map (secret_texts still reads it whole for clean).
_SUMMARY_MAX = 4 * 1024 * 1024

# A plain-text store is given to clean in pieces of about this many bytes,
# each starting this many bytes before the last one ended, so a value (a
# private key block too) that crosses a boundary is whole in one of them.
_TEXT_CHUNK = 256 * 1024
_TEXT_OVERLAP = 8 * 1024

# How many sessions' calls are kept for crediting their terminal logs.
_CALL_CACHE = 8


def _text(value):
    """`value` when it is a non-empty string, else None."""
    return value if isinstance(value, str) and value else None


def _dict(value):
    return value if isinstance(value, dict) else {}


def _byte_text(values):
    """A Bash `output` byte array as text, or None when it is not one.
    Decoded the way 7.7 says, with "replace"."""
    if isinstance(values, str):
        return values
    if not isinstance(values, list):
        return None
    if not all(type(v) is int and 0 <= v <= 255 for v in values):
        return None
    return bytes(values).decode("utf-8", "replace")


def _content_text(content):
    """The text of ACP content blocks {type: "content", content: {type:
    "text", text}}, joined by newlines, or None. Diff blocks are not
    output."""
    if not isinstance(content, list):
        return None
    parts = []
    for block in content:
        if not isinstance(block, dict) or block.get("type") != "content":
            continue
        inner = block.get("content")
        if isinstance(inner, dict) and inner.get("type") == "text":
            text = inner.get("text")
            if isinstance(text, str):
                parts.append(text)
    return "\n".join(parts) if parts else None


def _cut(text):
    return text[:MAX_OUTPUT] if isinstance(text, str) else None


def _regular(path):
    try:
        return stat.S_ISREG(os.stat(path).st_mode)
    except (OSError, ValueError):
        return False


def _subdirs(path):
    """The directories in `path`, by name, or [] when it cannot be listed."""
    out = []
    try:
        with os.scandir(path) as it:
            for entry in it:
                try:
                    if entry.is_dir():
                        out.append(entry.path)
                except OSError:
                    continue
    except (OSError, ValueError):
        return []
    return sorted(out)


def _files(path, wanted):
    """The regular files (not links) in `path` whose name `wanted` accepts,
    by name, or [] when it cannot be listed."""
    out = []
    try:
        with os.scandir(path) as it:
            for entry in it:
                try:
                    if wanted(entry.name) and entry.is_file(follow_symlinks=False):
                        out.append(entry.path)
                except OSError:
                    continue
    except (OSError, ValueError):
        return []
    return sorted(out)


def _is_log(name):
    return name.endswith(LOG_SUFFIX) and len(name) > len(LOG_SUFFIX)


def _is_compaction(name):
    """INDEX.md, or segment_NNN.md as xai-compaction-transcript names it."""
    if name == COMPACTION_INDEX:
        return True
    if not (name.startswith(SEGMENT_PREFIX) and name.endswith(SEGMENT_SUFFIX)):
        return False
    number = name[len(SEGMENT_PREFIX):-len(SEGMENT_SUFFIX)]
    return number.isdigit() and number.isascii()


def _is_json(name):
    return name.endswith(".json") and len(name) > len(".json")


def _is_mcp_dump(name):
    return _is_json(name) or (name.endswith(".txt") and len(name) > len(".txt"))


def _log_call_id(path):
    """(toolCallId, monitor) for a terminal log's file name."""
    stem = os.path.basename(path)[:-len(LOG_SUFFIX)]
    if stem.startswith(MONITOR_LOG_PREFIX) and len(stem) > len(MONITOR_LOG_PREFIX):
        return stem[len(MONITOR_LOG_PREFIX):], True
    return stem, False


def _read_summary(path):
    """(info.id, info.cwd) from a summary.json, each None when absent."""
    try:
        if os.path.getsize(path) > _SUMMARY_MAX:
            return None, None
        with open(path, encoding="utf-8", errors="replace") as fh:
            doc = json.loads(fh.read().lstrip("﻿"))
    except (OSError, ValueError, RecursionError):
        return None, None
    info = _dict(_dict(doc).get("info"))
    return _text(info.get("id")), _text(info.get("cwd"))


def _distinct(values):
    """The non-empty strings in `values`, each once, in order."""
    out = []
    for value in values:
        if _text(value) and value not in out:
            out.append(value)
    return out


def _zero(value):
    return type(value) is int and value == 0


def _starts_in_background(raw):
    """True when a shell call's input asks for the background: is_background,
    or a timeout or block_until_ms of 0 (BashToolInput)."""
    raw = _dict(raw)
    return (raw.get("is_background") is True or _zero(raw.get("timeout"))
            or _zero(raw.get("block_until_ms")))


def shape(name, xai_kind, raw, canon, out_dir=None, out_path=None,
          bash_mode=False):
    """How one call is judged, per the 7.7 table: a dict of the ToolCall
    fields kind, known, command, workdir, paths and consumed.

    name is the wire tool name; xai_kind is x.ai/tool.kind (Grok's own
    classification; None in chat_history.jsonl); raw is the decoded rawInput
    (or arguments); canon is x.ai/tool.input, from whichever line of the
    call carried it (upstream writes it from the second line on); out_dir
    and out_path are rawOutput's current_dir and the ReadFile absolute_path,
    when present. bash_mode: the user typed this command with `!`, so it is
    a shell call whatever the name."""
    raw, canon = _dict(raw), _dict(canon)

    def command():
        return _text(raw.get("command")) or _text(canon.get("command"))

    def workdir():
        found = _text(out_dir)
        for key in _CANON_DIRS:
            found = found or _text(canon.get(key))
        return found

    def shell(cmd):
        return {"kind": "shell", "known": True, "command": cmd,
                "workdir": workdir() if cmd else None, "paths": (),
                "consumed": ("command",)}

    def plain(kind, paths=(), consumed=()):
        return {"kind": kind, "known": True, "command": None, "workdir": None,
                "paths": tuple(_distinct(paths)), "consumed": consumed}

    def read():
        """The rawInput file (consumed), the canonical path, then the
        absolute path the tool resolved it to."""
        taken = [k for k in _READ_KEYS if _text(raw.get(k))]
        paths = [raw[k] for k in taken] + [canon.get("path"), out_path]
        return plain("read", paths, tuple(taken))

    if bash_mode or name in SHELL_NAMES or name in MONITOR_NAMES:
        return shell(command())
    if name in READ_NAMES:
        return read()
    if name == SEARCH_REPLACE:
        return plain("write", [raw.get("file_path"), canon.get("path")])
    if name in PATH_WRITE_NAMES:
        return plain("write", [canon.get("path")] + [raw.get(k) for k in _WRITE_KEYS])
    if name in OTHER_NAMES:
        return plain("other")
    if xai_kind in SHELL_KINDS and command():
        return shell(command())
    if xai_kind == "read":
        found = read()
        if found["paths"]:
            return found
    return {"kind": "other", "known": False, "command": None,
            "workdir": None, "paths": (), "consumed": ()}


class _Pending(object):
    """One call being assembled from its updates.jsonl lines."""
    __slots__ = ("id", "started", "name", "xai_kind", "canon", "raw_input",
                 "timestamp", "session", "out_dir", "out_path", "primary",
                 "content", "fallback", "bash_mode", "backgrounded", "task")

    def __init__(self, call_id):
        self.id = call_id
        self.started = False
        self.name = None
        self.xai_kind = None
        self.canon = {}
        self.raw_input = None
        self.timestamp = None
        self.session = None
        self.out_dir = None         # rawOutput.current_dir
        self.out_path = None        # rawOutput.FileContent.absolute_path
        self.primary = None         # output_for_prompt, else decoded output
        self.content = None         # the text of content[]
        self.fallback = None        # FileContent.content, tool_output_for_prompt
        self.bash_mode = call_id.startswith(BASH_MODE_ID_PREFIX)
        self.backgrounded = False   # the output says it moved to the background
        self.task = None            # BackgroundTaskStarted.task_id

    def start(self, envelope, params, update):
        """The step-1 `tool_call` line: name, time and session come from it
        and from no later line."""
        self.started = True
        meta = _dict(update.get("_meta"))
        tool = _dict(meta.get(XAI_TOOL))
        if meta.get(BASH_MODE) is True:
            self.bash_mode = True
        self.name = _text(tool.get("name"))
        if self.name is None:
            # A bash-mode call's title is display text: "Execute `cmd`".
            self.name = BASH_MODE if self.bash_mode else _text(update.get("title"))
        stamps = _dict(params.get("_meta"))
        self.timestamp = (_stamps.iso_utc(stamps.get("agentTimestampMs"), "ms")
                          or _stamps.iso_utc(envelope.get("timestamp"), "s"))
        self.session = _text(params.get("sessionId"))

    def merge(self, update):
        """Any line of this call: Grok's kind and the canonical input from
        any line that has them (the latest input wins), the latest rawInput,
        content and rawOutput. content on a line that also carries the input
        (the description shown for a command) is not output. Only what a
        ToolCall needs is kept, so a session full of large outputs is not
        held in memory as byte lists."""
        meta = _dict(update.get("_meta"))
        if meta.get(BASH_MODE) is True:
            self.bash_mode = True
        tool = _dict(meta.get(XAI_TOOL))
        self.xai_kind = self.xai_kind or _text(tool.get("kind"))
        if isinstance(tool.get("input"), dict):
            self.canon = tool["input"]
        carries_input = update.get("rawInput") is not None
        if carries_input:
            self.raw_input = update["rawInput"]
        if not carries_input and update.get("sessionUpdate") != "tool_call":
            content = _content_text(update.get("content"))
            if content is not None:
                self.content = _cut(content)
        out = update.get("rawOutput")
        if not isinstance(out, dict):
            return
        # A foreground run moved there by Ctrl+G or by running past its wait
        # ends in BackgroundTaskStarted (bash/mod.rs), its input unchanged.
        if (out.get("signal") == "backgrounded"
                or out.get("type") == "BackgroundTaskStarted"):
            self.backgrounded = True
            self.task = _text(out.get("task_id")) or self.task
        self.out_dir = _text(out.get("current_dir")) or self.out_dir
        found = _dict(out.get("FileContent"))
        self.out_path = _text(found.get("absolute_path")) or self.out_path
        primary = out.get("output_for_prompt")
        if not isinstance(primary, str):
            primary = _byte_text(out.get("output"))
        if primary is not None:
            self.primary = _cut(primary)
        fallback = found.get("content")
        if not isinstance(fallback, str):
            fallback = _dict(out.get("EditsApplied")).get("tool_output_for_prompt")
        if isinstance(fallback, str):
            self.fallback = _cut(fallback)

    def output(self):
        for text in (self.primary, self.content, self.fallback):
            if text is not None:
                return text
        return None


class GrokBuildSource(Source):
    id = "grok"
    name = "Grok Build"
    unit = "session"
    env = (ENV,)
    path_means = "a Grok Build home, the folder GROK_HOME names (default ~/.grok)"
    checked = "source at commit 2bdd1d6a (main, after v1.0)"
    byte_arrays = True
    # For the clean report after masking (7.7): the Bash rawOutput keeps
    # its total_bytes, which no longer matches the masked output.
    mask_note = "byte counts in masked Grok Build output no longer match"

    # -- per run -------------------------------------------------------------

    def reset(self):
        super(GrokBuildSource, self).reset()
        self._tallied = set()       # store paths whose lines were counted
        self._summaries = {}        # summary.json path -> (stat key, info)
        # transcript path -> (stat key, {call id: ToolCall}, background ids),
        # the most recently used last
        self._session_calls = collections.OrderedDict()

    def _tally(self, path, local):
        """Add one pass's counters, once per store per run: tool_calls and
        secret_texts both read a store, and a line is counted once."""
        if path in self._tallied:
            return
        self._tallied.add(path)
        for name, n in local.items():
            if n:
                self.count(name, n)

    def _cannot_read(self, store, reason):
        key = store.path
        if key in self._warned:
            return
        self.unreadable_store(reason, store.path)
        self.warn(key, "cannot read Grok Build %s %s (%s)"
                  % (os.path.basename(store.path), store.path, reason))

    # -- where to look -------------------------------------------------------

    def default_paths(self, env, home, platform):
        """GROK_HOME when set and not empty, else ~/.grok. On Windows Grok
        Build takes the home from USERPROFILE, which is what
        _paths.home() returns there."""
        moved = _text(env.get(ENV))
        if moved:
            return [(moved, "env " + ENV)]
        return [(_paths.join(platform, home, ".grok"), "default")]

    def stores(self, locations, since_days=None):
        found = []
        for loc in locations:
            for folder in _subdirs(os.path.join(loc.path, SESSIONS)):
                for session_dir in _subdirs(folder):
                    found.extend(self._session_stores(session_dir))
        return newest_first(found, since_days)

    def _summary(self, path):
        """(id, cwd) from summary.json, read once per version of the file."""
        try:
            st = os.stat(path)
        except (OSError, ValueError):
            return None, None
        key = (st.st_mtime_ns, st.st_size)
        hit = self._summaries.get(path)
        if hit is None or hit[0] != key:
            hit = self._summaries[path] = (key, _read_summary(path))
        return hit[1]

    def _session_fields(self, session_dir):
        summary = os.path.join(session_dir, SUMMARY)
        sid, cwd = self._summary(summary) if _regular(summary) else (None, None)
        return {"session": sid or os.path.basename(session_dir), "project": cwd}

    def _session_stores(self, session_dir):
        updates = os.path.join(session_dir, UPDATES)
        chat = os.path.join(session_dir, CHAT_HISTORY)
        summary = os.path.join(session_dir, SUMMARY)
        has_updates = _regular(updates)
        has_chat = _regular(chat)
        has_summary = _regular(summary)
        if not (has_updates or has_chat or has_summary):
            return []
        fields = self._session_fields(session_dir)
        out = []
        if has_updates:
            out.append(self.store(updates, "jsonl", role="transcript", **fields))
        if has_chat:
            out.append(self.store(chat, "jsonl", role="side" if has_updates
                                  else "transcript", **fields))
        if has_summary:
            out.append(self.store(summary, "json", role="side", **fields))
        for path in _files(os.path.join(session_dir, TERMINAL), _is_log):
            out.append(self.store(path, "text", role="side",
                                  unit="terminal log", **fields))
        for path in _files(os.path.join(session_dir, COMPACTION), _is_compaction):
            out.append(self.store(path, "text", role="side",
                                  unit="compaction record", **fields))
        for folder in HISTORY_COPIES:
            for path in _files(os.path.join(session_dir, folder), _is_json):
                out.append(self.store(path, "json", role="side",
                                      unit="history copy", **fields))
        for path in _files(os.path.join(session_dir, MCP), _is_mcp_dump):
            kind = "json" if path.endswith(".json") else "text"
            out.append(self.store(path, kind, role="side", unit="tool output",
                                  **fields))
        return [s for s in out if s is not None]

    # -- tool calls ----------------------------------------------------------

    def tool_calls(self, store):
        """updates.jsonl, or chat_history.jsonl when it is the transcript
        (no updates.jsonl beside it). Side stores yield nothing."""
        if store.role != "transcript":
            return
        try:
            calls, _background = self._assemble(store)
        except Exception as e:      # one store must not stop the others
            self._cannot_read(store, str(e) or type(e).__name__)
            return
        for call in calls.values():
            yield call

    def _assemble(self, store):
        """({call id: ToolCall} in the order the calls began, the ids of the
        calls that ran in the background and are not recorded as finished);
        empty for a store that does not hold calls."""
        base_name = os.path.basename(store.path)
        if base_name == UPDATES:
            return self._updates(store)
        if base_name == CHAT_HISTORY:
            return self._chat(store)
        return {}, frozenset()

    def _not_after(self, store):
        return _stamps.iso_utc(store.mtime, "s")

    def _json_lines(self, store, local):
        """iter_json_lines over the store, noticing a file in which not one
        complete line was JSON (garbage): that warns once and reads as
        empty. A last line still being written is not that."""
        parsed = 0
        for line_no, obj in _lines.iter_json_lines(store.path, local):
            parsed += 1
            yield line_no, obj
        if not parsed and local.get("unparsed"):
            self._cannot_read(store, "not JSON Lines")

    def _updates(self, store):
        local = {"unparsed": 0, "unknown": 0, "unreadable_calls": 0}
        pending, finished = {}, set()
        for _line_no, obj in self._json_lines(store, local):
            update, params = _update(obj)
            if update is None:
                local["unknown"] += 1
                continue
            if update.get("sessionUpdate") == TASK_COMPLETED:
                finished.add(_text(_dict(update.get("task_snapshot")).get("task_id")))
                continue
            if update.get("sessionUpdate") not in CALL_UPDATES:
                continue            # messages, plans, xAI extras: clean only
            call_id = _text(update.get("toolCallId"))
            if call_id is None:
                local["unreadable_calls"] += 1
                continue
            state = pending.get(call_id)
            if state is None:
                state = pending[call_id] = _Pending(call_id)
            if update.get("sessionUpdate") == "tool_call" and not state.started:
                state.start(obj, params, update)
            state.merge(update)
        calls, background = {}, set()
        for call_id, state in pending.items():
            if not state.name:
                # Updates whose tool_call line is not in the file: nothing
                # says which tool ran, and a later title is display text.
                local["unreadable_calls"] += 1
                continue
            raw = decode_input(state.raw_input) if state.raw_input is not None else {}
            tool_input = state.raw_input if state.raw_input is not None else state.canon
            fields = shape(state.name, state.xai_kind, raw, state.canon,
                           state.out_dir, state.out_path, bash_mode=state.bash_mode)
            calls[call_id] = ToolCall(
                self.id, store.path, state.name, tool_input,
                session=state.session or store.session, project=store.project,
                timestamp=state.timestamp, tool_call_id=call_id,
                actor="user" if state.bash_mode else "agent",
                not_after=None if state.timestamp else self._not_after(store),
                output=state.output(), **fields)
            if (state.task or call_id) in finished:
                continue            # its command has exited
            if (state.backgrounded or state.name in MONITOR_NAMES
                    or (fields["kind"] == "shell" and _starts_in_background(raw))):
                background.add(call_id)
        self._tally(store.path, local)
        return calls, frozenset(background)

    def _chat(self, store):
        """chat_history.jsonl: assistant items' tool_calls [{id, name,
        arguments}], outputs from tool_result items. No times: every call
        is undated, not_after the file's last write."""
        local = {"unparsed": 0, "unknown": 0, "unreadable_calls": 0}
        order, outputs = [], {}
        seen = set()
        for _line_no, obj in self._json_lines(store, local):
            kind = obj.get("type") if isinstance(obj, dict) else None
            if kind not in CHAT_TYPES:
                local["unknown"] += 1
                continue
            if kind == "tool_result":
                call_id = _text(obj.get("tool_call_id"))
                if call_id and isinstance(obj.get("content"), str):
                    outputs[call_id] = _cut(obj["content"])
                continue
            if kind != "assistant" or not isinstance(obj.get("tool_calls"), list):
                continue
            for item in obj["tool_calls"]:
                item = _dict(item)
                call_id = _text(item.get("id"))
                if call_id is not None:
                    if call_id in seen:
                        continue
                    seen.add(call_id)
                order.append((call_id, item))
        calls, background = {}, set()
        not_after = self._not_after(store)
        for index, (call_id, item) in enumerate(order):
            name = _text(item.get("name"))
            if name is None:
                local["unreadable_calls"] += 1
                continue
            tool_input = decode_input(item.get("arguments"))
            fields = shape(name, None, tool_input, {})
            calls[call_id if call_id else ("#%d" % index)] = ToolCall(
                self.id, store.path, name, tool_input, session=store.session,
                project=store.project, tool_call_id=call_id,
                not_after=not_after, output=outputs.get(call_id), **fields)
            if call_id and (name in MONITOR_NAMES or (
                    fields["kind"] == "shell" and _starts_in_background(tool_input))):
                background.add(call_id)
        self._tally(store.path, local)
        return calls, frozenset(background)

    def _calls_of_session(self, session_dir):
        """({call id: ToolCall}, background ids) from the session's
        transcript (updates.jsonl, else chat_history.jsonl), for crediting
        and judging its terminal logs. Kept for the few sessions used last;
        the calls are kept without their output. Empty when there is no
        transcript or it cannot be read (that store warns on its own)."""
        for name in (UPDATES, CHAT_HISTORY):
            path = os.path.join(session_dir, name)
            if _regular(path):
                break
        else:
            return {}, frozenset()
        try:
            st = os.stat(path)
        except (OSError, ValueError):
            return {}, frozenset()
        key = (st.st_mtime_ns, st.st_size)
        hit = self._session_calls.get(path)
        if hit is not None and hit[0] == key:
            self._session_calls.move_to_end(path)
            return hit[1], hit[2]
        store = self.store(path, "jsonl", role="transcript",
                           **self._session_fields(session_dir))
        if store is None:
            return {}, frozenset()
        try:
            calls, background = self._assemble(store)
        except Exception as e:
            self._cannot_read(store, str(e) or type(e).__name__)
            return {}, frozenset()
        by_id = {}
        for call in calls.values():
            if call.tool_call_id:
                call.output = None
                by_id[call.tool_call_id] = call
        self._session_calls[path] = (key, by_id, background)
        while len(self._session_calls) > _CALL_CACHE:
            self._session_calls.popitem(last=False)
        return by_id, background

    # -- masking -------------------------------------------------------------

    def in_use(self, store):
        """A terminal log of a command that ran in the background (a monitor,
        or a shell call started or moved there and not recorded as finished):
        the command may still be writing to it, and Grok Build told the
        model to read its output there, so it is not replaced. Every other
        store: the default rule (QUIET_SECONDS) only."""
        if not self._is_terminal_log(store.path):
            return False
        call_id, monitor = _log_call_id(store.path)
        if monitor:
            return True
        session_dir = os.path.dirname(os.path.dirname(store.path))
        _calls, background = self._calls_of_session(session_dir)
        return call_id in background

    @staticmethod
    def _is_terminal_log(path):
        return (os.path.basename(os.path.dirname(path)) == TERMINAL
                and _is_log(os.path.basename(path)))

    # -- clean ---------------------------------------------------------------

    def secret_texts(self, store):
        """Every line of updates.jsonl and chat_history.jsonl, the whole of
        summary.json and of each history copy and saved MCP output, and every
        terminal log and compaction record. A call's
        output (rawOutput and content; a tool_result; its terminal log)
        carries that call, so clean can credit the file it was read from. A
        Bash output byte array is given as its decoded text."""
        base_name = os.path.basename(store.path)
        try:
            if store.format == "text":
                texts = self._plain_texts(store)
            elif store.format == "json":
                texts = self._json_texts(store)
            elif base_name in (UPDATES, CHAT_HISTORY):
                calls, _background = self._assemble(store)
                if base_name == UPDATES:
                    texts = self._update_texts(store, calls)
                else:
                    texts = self._chat_texts(store, calls)
            else:
                return
            for text in texts:
                yield text
        except Exception as e:      # one store must not stop the others
            self._cannot_read(store, str(e) or type(e).__name__)

    def _json_texts(self, store):
        with open(store.path, "rb") as fh:
            raw = fh.read()
        try:
            doc = json.loads(raw.decode("utf-8", "surrogateescape").lstrip("﻿"))
        except (ValueError, RecursionError):
            self._cannot_read(store, "not JSON")
            return
        yield SecretText(doc, where=os.path.basename(store.path))

    def _plain_texts(self, store):
        """A terminal log, credited to the call whose output it is, or a
        compaction record, credited to none (it mixes many turns)."""
        call = None
        if self._is_terminal_log(store.path):
            call_id, _monitor = _log_call_id(store.path)
            session_dir = os.path.dirname(os.path.dirname(store.path))
            calls, _background = self._calls_of_session(session_dir)
            call = calls.get(call_id)
        for first, last, text in _text_pieces(store.path):
            where = "line %d" % first if first == last else "lines %d-%d" % (first, last)
            yield SecretText(text, call=call, where=where)

    def _update_texts(self, store, calls):
        for line_no, obj in _lines.iter_json_lines(store.path):
            where = "line %d" % line_no
            update, params = _update(obj)
            output = _output_of(update)
            if output is None:
                yield SecretText(obj, where=where)
                continue
            call = calls.get(_text(update.get("toolCallId")))
            yield SecretText(output, call=call, where=where)
            stripped = {k: v for k, v in update.items() if k not in output}
            rest = dict(obj)
            if params is obj:           # an old line with no envelope
                rest["update"] = stripped
            else:
                rest["params"] = dict(params)
                rest["params"]["update"] = stripped
            yield SecretText(rest, where=where)

    def _chat_texts(self, store, calls):
        by_id = {c.tool_call_id: c for c in calls.values() if c.tool_call_id}
        for line_no, obj in _lines.iter_json_lines(store.path):
            where = "line %d" % line_no
            kind = obj.get("type") if isinstance(obj, dict) else None
            if kind == "tool_result":
                yield SecretText(obj, call=by_id.get(_text(obj.get("tool_call_id"))),
                                 where=where)
            elif kind == "assistant" and isinstance(obj.get("tool_calls"), list):
                # arguments is a JSON string: given decoded, so a value in
                # it is found as written, not in its escaped form.
                item = dict(obj)
                item["tool_calls"] = [_decoded_arguments(c) for c in obj["tool_calls"]]
                yield SecretText(item, where=where)
            else:
                yield SecretText(obj, where=where)


def _update(obj):
    """(params.update, params) of a session/update line, or (None, None) for
    any other line.

    An envelope {timestamp, method, params} is read when its method is one
    Grok Build writes, or absent. An old line with no envelope is the
    notification itself, {sessionId, update, _meta?}: params is then `obj`.
    A line with another method is not one Grok Build writes, and is left
    for the unknown count."""
    if not isinstance(obj, dict):
        return None, None
    if "method" in obj or "params" in obj:
        if obj.get("method") is not None and obj.get("method") not in METHODS:
            return None, None
        params = obj.get("params")
    else:
        params = obj
    update = params.get("update") if isinstance(params, dict) else None
    if not isinstance(update, dict) or not isinstance(update.get("sessionUpdate"), str):
        return None, None
    return update, params


def _output_of(update):
    """The output parts of a tool call line, {rawOutput?, content?} (a Bash
    byte array given as its text), or None when the line has none. content
    on a line that carries the call's input is display text derived from
    that input (a command's description), not output."""
    if update is None or update.get("sessionUpdate") not in CALL_UPDATES:
        return None
    output = {}
    if "rawOutput" in update:
        output["rawOutput"] = _decoded_output(update["rawOutput"])
    if ("content" in update and update.get("rawInput") is None
            and update.get("sessionUpdate") != "tool_call"):
        output["content"] = update["content"]
    return output or None


def _decoded_output(out):
    """rawOutput with a Bash output (and output_delta) byte array replaced
    by its text."""
    if not isinstance(out, dict) or out.get("type") != "Bash":
        return out
    decoded = None
    for key in ("output", "output_delta"):
        value = out.get(key)
        if isinstance(value, str):
            continue
        text = _byte_text(value)
        if text is not None:
            decoded = dict(out) if decoded is None else decoded
            decoded[key] = text
    return out if decoded is None else decoded


def _decoded_arguments(call):
    if not isinstance(call, dict) or not isinstance(call.get("arguments"), str):
        return call
    try:
        decoded = json.loads(call["arguments"])
    except (ValueError, RecursionError):
        return call
    call = dict(call)
    call["arguments"] = decoded
    return call


def _text_pieces(path):
    """(first line, last line, text) for a plain-text file, in pieces of
    about _TEXT_CHUNK bytes.

    A piece ends at the end of a line, so a value on one line is never cut
    in two (a cut value would be reported as a second, shorter one). A line
    longer than a piece is cut after its last space or tab inside the
    piece, else where the piece ends. Each piece after the first starts with
    the whole lines, up to _TEXT_OVERLAP bytes, that ended the one before,
    so a value spanning lines (a private key block) is whole in one of
    them. Bytes that are not UTF-8 are decoded with surrogateescape, as the
    masker reads them. Never holds more than about one piece in memory,
    however long a line is."""
    with open(path, "rb") as fh:
        frags, size, fresh = [], 0, False     # [(line number, bytes)]
        line_no = 1
        while True:
            seg = fh.readline(_TEXT_CHUNK)
            if not seg:
                break
            if len(seg) == _TEXT_CHUNK and not seg.endswith(b"\n"):
                cut = max(seg.rfind(b" "), seg.rfind(b"\t"), seg.rfind(b"\r"))
                if cut > 0:
                    fh.seek(cut + 1 - len(seg), os.SEEK_CUR)
                    seg = seg[:cut + 1]
            if fresh and size + len(seg) > _TEXT_CHUNK:
                yield _piece(frags)
                frags, size = _tail(frags, _TEXT_OVERLAP)
                fresh = False
            frags.append((line_no, seg))
            size += len(seg)
            fresh = True
            if seg.endswith(b"\n"):
                line_no += 1
        if fresh:
            yield _piece(frags)


def _piece(frags):
    text = b"".join(seg for _line, seg in frags).decode("utf-8", "surrogateescape")
    return frags[0][0], frags[-1][0], text


def _tail(frags, limit):
    """The last fragments of a piece that are whole lines and together fit
    in `limit` bytes, and their size."""
    kept, size = [], 0
    for line_no, seg in reversed(frags):
        if size + len(seg) > limit or not seg.endswith(b"\n"):
            break
        kept.append((line_no, seg))
        size += len(seg)
    kept.reverse()
    return kept, size
