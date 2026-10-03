"""Kimi CLI, the legacy Python agent (MoonshotAI/kimi-cli, archived).

Design section 7.9, checked against release 1.52.0, the last before the
project was archived and replaced by Kimi Code. Its migration guide says
~/.kimi is never modified or deleted, so the files stay on disk and the
format is frozen.

Under the share directory (KIMI_SHARE_DIR, else ~/.kimi), where <folder>
is a session folder, sessions/<dir>/<session_id>/ or
imported_sessions/<id>/:

    kimi.json                             work_dirs, to name projects (map only)
    <folder>/wire.jsonl                   events with times (transcript)
    <folder>/context.jsonl                LLM messages, no times: the transcript
                                          when the folder has no wire.jsonl,
                                          else side
    <folder>/context_<N>.jsonl            contexts rotated on /clear, revert or
                                          compaction (side)
    <folder>/context_sub_<N>.jsonl        a Task subagent's context, before 1.25
                                          (side)
    <folder>/context_sub_<N>_<M>.jsonl    that context, rotated by a compaction
                                          inside the subagent (side)
    <folder>/tasks/<task_id>/output.log   what a background command printed
                                          (side, plain text)
    <folder>/tasks/<task_id>/spec.json    that command (side, JSON)
    <folder>/subagents/<agent_id>/        1.25 on: wire.jsonl, context.jsonl and
                                          context_<N>.jsonl as above, and
                                          prompt.txt and output (side, plain
                                          text)
    sessions/<dir>/<session_id>.jsonl     context format, before v0.59
    user-history/<md5>.jsonl              typed prompts (side)

<dir> is the md5 hex of the work directory's path, or <kaos>_<md5> for a
non-local KAOS backend. An imported session is a whole session folder: the
vis ZIP download packs every file under the folder, and the import unpacks
all of it. Nothing else is opened: not state.json, the other task files,
subagents/*/meta.json or logs/. The one exception is a task's runtime.json,
read only by in_use(), for its "status", before its output.log is masked.

Beyond design 7.9, each checked against the 0.56, 1.24.0 and 1.52.0
sources:

- A call the user rejected is "declined" by its result, not only by an
  ApprovalResponse. From 1.25.0 the interactive shell publishes approvals
  only to the in-memory root hub (approval_runtime/runtime.py), so its
  wire.jsonl holds no approval records at all. In every version the
  result of a rejected call is a ToolRejectedError, whose message starts
  "The tool call is rejected by the user." (tools/utils.py,
  soul/approval.py); Kimi itself tells a rejection by that type.
- Before 1.25 a Task subagent ran with no wire file of its own: its calls
  are on disk only as SubagentEvent records in the main wire.jsonl,
  {"task_tool_call_id", "event": {"type", "payload"}}
  (tools/multiagent/task.py), and in context_sub_<N>.jsonl. Those records
  are read. From 1.25 on, a SubagentEvent carries agent_id and copies
  subagents/<id>/wire.jsonl, which is read for itself; those are skipped.
- A Shell call with run_in_background=true returns only a "task started"
  block; what the command printed goes to tasks/<task_id>/output.log
  (background/store.py, worker.py), and only a short tail reaches the
  context. spec.json beside it holds the command. A subagent's prompt.txt
  is the prompt it was given, and its output file the text and summary it
  wrote (subagents/core.py, output.py). All four hold copies of secrets
  that clean masks elsewhere, so they are searched and masked too.
- A session saved before 0.59 as sessions/<dir>/<id>.jsonl is moved to
  <id>/context.jsonl when Kimi lists or opens it (session.py
  _migrate_session_context_file), and wire.jsonl only starts when the
  session is resumed. So a folder's context files can hold calls its
  wire.jsonl never saw: those are read too, undated (see tool_calls).
- Up to 0.56 the shell tool was Bash (CMD on Windows), {command, timeout},
  and PatchFile {path, diff} edited files (tools/bash, tools/file/patch.py;
  CHANGELOG 0.57 renames Bash/CMD to Shell and removes PatchFile).
- The recorder merges a ToolCall with the ToolCallPart records streamed
  after it, but any other record flushes it first (wire/__init__.py
  WireSoulSide): a parallel call's result, a subagent's event, a status
  update. The call is then written with only the start of its arguments,
  and the rest follows in ToolCallPart records, which add to the latest
  call of the same agent. The pieces are read as one call (see _Pieces).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections import OrderedDict

from . import _lines, _paths, _rewrite, _stamps
from .base import (MaskResult, SecretText, Source, ToolCall, decode_input,
                   newest_first)

ENV = "KIMI_SHARE_DIR"

WIRE = "wire.jsonl"
CONTEXT = "context.jsonl"
SUFFIX = ".jsonl"

# Contexts rotated by next_available_rotation: context_<N>.jsonl beside
# context.jsonl; before 1.25 a Task subagent's context_sub_<N>.jsonl, which
# a compaction inside that subagent rotates once more to
# context_sub_<N>_<M>.jsonl.
_ROTATED = re.compile(r"context_([0-9]+)\.jsonl\Z")
_SUB_CONTEXT = re.compile(r"context_sub_([0-9]+)(?:_([0-9]+))?\.jsonl\Z")
_MD5 = re.compile(r"[0-9a-f]{32}\Z")

SUBAGENTS = "subagents"
TASKS = "tasks"
TASK_OUTPUT = "output.log"
TASK_SPEC = "spec.json"
TASK_RUNTIME = "runtime.json"
SUB_PROMPT = "prompt.txt"
SUB_OUTPUT = "output"

# A task whose runtime.json names one of these has stopped; any other
# status means its worker may still hold output.log open
# (background/models.py TERMINAL_TASK_STATUSES, 1.24.0 and 1.52.0).
_TASK_DONE = ("completed", "failed", "killed", "lost")

# A plain text store is searched in pieces of whole lines about this long
# (bytes). A longer line is cut every _PIECE bytes; clean cuts any one
# string at a million characters anyway.
_PIECE = 256 * 1024

# Tool name (exactly as the writer names it) -> (kind, the input key that
# holds the command or the path, whether that key is consumed). Every other
# name (Glob, Grep, the web and agent tools) is unverified: known=False.
TOOLS = {
    "Shell": ("shell", "command", True),
    # Up to 0.56 the shell tool was Bash, or CMD on Windows: {command,
    # timeout} (tools/bash/__init__.py). 0.57 renamed it Shell.
    "Bash": ("shell", "command", True),
    "CMD": ("shell", "command", True),
    "ReadFile": ("read", "path", True),
    "WriteFile": ("write", "path", False),
    "StrReplaceFile": ("write", "path", False),
    # Up to 0.56: {path, diff} (tools/file/patch.py). 0.57 removed it.
    "PatchFile": ("write", "path", False),
}

APPROVAL_REQUEST = "ApprovalRequest"
# ApprovalRequestResolved is the legacy name of ApprovalResponse.
APPROVAL_RESPONSES = ("ApprovalResponse", "ApprovalRequestResolved")
REJECT = "reject"
SUBAGENT_EVENT = "SubagentEvent"
# The wire records a call is read from, the ToolCallPart pieces included.
CALL_RECORDS = ("ToolCall", "ToolCallPart", "ToolResult")

# Every ToolRejectedError message starts with this: with or without the
# user's feedback, for the main agent or a subagent, 0.56 to 1.52 alike.
REJECTED = "The tool call is rejected by the user."

# A tool message's text starts with this part, which Kimi adds for the model.
_SYSTEM_OPEN, _SYSTEM_CLOSE = "<system>", "</system>"
# ...and for an error, the part is "<system>ERROR: <message></system>"
# (soul/message.py tool_result_to_message).
_REJECTED_PART = _SYSTEM_OPEN + "ERROR: " + REJECTED

# The conversation a context file belongs to: the main agent's, or (an int)
# the Task subagent numbered by its context_sub_<N>.jsonl.
_MAIN = "main"

# Decoded JSON is followed this deep when tool arguments are decoded for clean.
_DEPTH = 64

_NOT_JSON = object()


def _id(value):
    """An id as recorded, or None when there is none to match on."""
    return value if isinstance(value, str) and value else None


def _md5(text):
    try:
        data = text.encode("utf-8")
    except UnicodeEncodeError:      # a lone surrogate from a JSON escape
        return None
    return hashlib.md5(data, usedforsecurity=False).hexdigest()


def folder_md5(name):
    """The md5 a sessions/ folder (or user-history file stem) is named by:
    the name itself, or the 32 hex characters after the last "_" of
    <kaos>_<md5>. None when the name holds no md5."""
    tail = name.rsplit("_", 1)[-1]
    return tail if _MD5.match(tail) else None


def _entries(path):
    """The directory's entries sorted by name, or [] when it cannot be listed."""
    try:
        with os.scandir(path) as it:
            return sorted(it, key=lambda e: e.name)
    except OSError:
        return []


def _is_file(entry):
    try:
        return entry.is_file()
    except OSError:
        return False


def _is_dir(entry):
    try:
        return entry.is_dir()
    except OSError:
        return False


def _load_json(path):
    """A small JSON file's content, or None when it is missing or not JSON."""
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError, RecursionError):
        return None


def _other_contexts(folder, top):
    """[(path, conversation)] for the context files of a session folder
    other than context.jsonl: the rotated context_<N>.jsonl (the main
    conversation), and in a top-level session folder each Task subagent's
    context_sub_<N>.jsonl and its rotations (conversation N). Oldest
    rotation first within a conversation."""
    out = []
    for entry in _entries(folder):
        rotated = _ROTATED.match(entry.name)
        sub = None if rotated or not top else _SUB_CONTEXT.match(entry.name)
        if not (rotated or sub) or not _is_file(entry):
            continue
        if rotated:
            order, conversation = (0, int(rotated.group(1)), 0), _MAIN
        else:
            n, m = int(sub.group(1)), sub.group(2)
            order, conversation = (1, n, int(m) if m else -1), n
        out.append((order, entry.path, conversation))
    out.sort(key=lambda item: item[0])
    return [(path, conversation) for _order, path, conversation in out]


def _output_text(output):
    """A ToolResult's output as text: a string as it is, a list of parts as
    the text of its text parts. None when there is no text."""
    if isinstance(output, str):
        return output
    if isinstance(output, list):
        texts = [p.get("text") for p in output
                 if isinstance(p, dict) and p.get("type") == "text"
                 and isinstance(p.get("text"), str)]
        return "".join(texts) if texts else None
    return None


def _is_system(text):
    return text.startswith(_SYSTEM_OPEN) and text.rstrip().endswith(_SYSTEM_CLOSE)


def _tool_message_text(content):
    """A context.jsonl tool message's output: its text without the leading
    <system>...</system> part Kimi adds for the model."""
    if isinstance(content, str):
        if content.startswith(_SYSTEM_OPEN):
            end = content.find(_SYSTEM_CLOSE)
            if end != -1:
                return content[end + len(_SYSTEM_CLOSE):]
        return content
    if isinstance(content, list):
        texts = [p.get("text") for p in content
                 if isinstance(p, dict) and p.get("type") == "text"
                 and isinstance(p.get("text"), str)]
        if not texts:
            return None
        if _is_system(texts[0]):
            texts = texts[1:]
        return "".join(texts)
    return None


def _rejected_result(value):
    """Whether a wire ToolResult's return_value is a ToolRejectedError: the
    user rejected the call, so it never ran."""
    if not isinstance(value, dict) or value.get("is_error") is not True:
        return False
    message = value.get("message")
    return isinstance(message, str) and message.startswith(REJECTED)


def _rejected_message(content):
    """Whether a context.jsonl tool message is the answer to a call the
    user rejected: its first part is "<system>ERROR: The tool call is
    rejected by the user. ...". One text part is written as a plain string,
    more as a list of parts."""
    if isinstance(content, list):
        first = content[0] if content else None
        if not (isinstance(first, dict) and first.get("type") == "text"):
            return False
        content = first.get("text")
    return isinstance(content, str) and content.startswith(_REJECTED_PART)


def _call_key(record):
    """What makes two copies of a call in different files the same call:
    its id, name and arguments. Kimi's ids ("Shell:0") count within one
    conversation, so after /clear the same call can come back with the
    same key; within one file every call is read (see _Pending). A digest,
    so a long file's set of seen calls stays small. None for a call with
    no id."""
    cid = _id(record.get("id"))
    if cid is None:
        return None
    fn = record.get("function")
    fn = fn if isinstance(fn, dict) else {}
    try:
        text = json.dumps([cid, fn.get("name"), fn.get("arguments")],
                          sort_keys=True, default=str)
    except RecursionError:
        # Arguments nested too deep to encode: told apart by id and name
        # alone, as watch._payload calls every such input "unhashable".
        text = json.dumps([cid, fn.get("name"), "unhashable"], default=str)
    return hashlib.sha256(text.encode("utf-8", "surrogatepass")).digest()


def _readable(node, depth=0):
    """`node` with each "arguments" string that holds JSON decoded, so clean
    reads a command's values as the shell got them rather than with a
    second level of JSON escapes. The original is not changed."""
    if depth > _DEPTH:
        return node
    if isinstance(node, dict):
        out = {}
        for key, value in node.items():
            if key == "arguments" and isinstance(value, str):
                try:
                    decoded = json.loads(value)
                except (ValueError, RecursionError):
                    decoded = None
                if isinstance(decoded, (dict, list)):
                    out[key] = _readable(decoded, depth + 1)
                    continue
            out[key] = _readable(value, depth + 1)
        return out
    if isinstance(node, list):
        return [_readable(v, depth + 1) for v in node]
    return node


class _Pending(object):
    """Calls waiting for their result, in the order they were made, with
    the records they were read from. `seen` holds the _call_key of every
    call read, and may be shared, so that copies already yielded from
    another file of the same conversation are skipped here.

    A context file can hold a copy of a call; a wire.jsonl (`copies`
    False) records each call once, so there every call is read, and one
    whose key was seen is a new call made after /clear. Its key is taken
    when it leaves, since a ToolCallPart may still add to its arguments."""

    def __init__(self, seen=None, copies=True):
        self.calls = OrderedDict()
        self.records = {}
        self.seen = set() if seen is None else seen
        self.copies = copies

    def add(self, call, record):
        """The calls to yield now: none for a copy already seen; the call
        itself when it has no id (no result can find it); and an earlier
        call still waiting under the same id (a reused id after /clear)."""
        if self.copies:
            key = _call_key(record)
            if key is not None:
                if key in self.seen:
                    return []
                self.seen.add(key)
        cid = call.tool_call_id
        if cid is None:
            return [call]
        out = [self._pop(cid)] if cid in self.calls else []
        self.calls[cid] = call
        self.records[cid] = record
        return out

    def _pop(self, cid):
        record = self.records.pop(cid)
        if not self.copies:
            key = _call_key(record)
            if key is not None:
                self.seen.add(key)
        return self.calls.pop(cid)

    def result(self, cid, output, rejected=False):
        call = self._pop(cid) if cid in self.calls else None
        if call is not None:
            call.output = output
            if rejected:
                call.status = "declined"
        return call

    def rest(self):
        return [self._pop(cid) for cid in list(self.calls)]


class _Pieces(object):
    """The latest call of each agent in a wire.jsonl, while ToolCallPart
    records may still add to its arguments: until its result, the same
    agent's next call, or the end of the file. `scope` names the agent:
    None for the main one, else a subagent's agent_id or its Task call's
    id. Each call is a copy of its record, whose arguments are joined from
    their pieces once, when it is whole. `line` is what the call's own line
    is searched as, kept for when the call turns out to be in one piece."""

    def __init__(self):
        # scope -> [first line, last line, record, pieces, line]
        self.latest = {}

    def call(self, scope, payload, line_no=None, line=None):
        """(The copy of a ToolCall's payload that its pieces will add to;
        the agent's call before it, now whole, as close() gives it.)"""
        before = self.close(scope)
        record = dict(payload)
        fn = payload.get("function")
        args = fn.get("arguments") if isinstance(fn, dict) else None
        if isinstance(fn, dict) and (args is None or isinstance(args, str)):
            record["function"] = dict(fn)
            self.latest[scope] = [line_no, line_no, record, [args or ""], line]
        return record, before

    def part(self, scope, payload, line_no=None):
        """Add a ToolCallPart's arguments_part to the agent's latest call.
        True when it did."""
        entry = self.latest.get(scope)
        piece = payload.get("arguments_part")
        if entry is None or not isinstance(piece, str) or not piece:
            return False
        entry[1] = line_no
        entry[3].append(piece)
        return True

    def close(self, scope):
        """The agent's latest call, which nothing adds to any more, as
        [first line, last line, record, pieces, line], its arguments
        joined when it came in pieces; None when there is none."""
        entry = self.latest.pop(scope, None)
        if entry is not None and len(entry[3]) > 1:
            entry[2]["function"]["arguments"] = "".join(entry[3])
        return entry

    def answered(self, scope, cid):
        """close(), when the agent's latest call is the one a result with
        id `cid` answers."""
        entry = self.latest.get(scope)
        if cid is None or entry is None or _id(entry[2].get("id")) != cid:
            return None
        return self.close(scope)

    def rest(self):
        """Each agent's latest call, at the end (see close)."""
        return [self.close(scope) for scope in list(self.latest)]


def _scope_event(obj):
    """(scope, type, payload) of a wire record, the event inside a
    SubagentEvent scoped by its agent_id (1.25 on) or Task call's id (see
    _Pieces). (None, None, None) when it holds no event with a payload."""
    message = obj.get("message") if isinstance(obj, dict) else None
    if not isinstance(message, dict):
        return None, None, None
    scope, mtype, payload = None, message.get("type"), message.get("payload")
    if mtype == SUBAGENT_EVENT and isinstance(payload, dict):
        scope = _id(payload.get("agent_id")) or _id(
            payload.get("task_tool_call_id"))
        event = payload.get("event")
        if scope is None or not isinstance(event, dict):
            return None, None, None
        mtype, payload = event.get("type"), event.get("payload")
    if not isinstance(payload, dict):
        return None, None, None
    return scope, mtype, payload


class KimiSource(Source):
    id = "kimi"
    name = "Kimi CLI"
    unit = "session"
    env = (ENV,)
    path_means = "a Kimi CLI share directory (what KIMI_SHARE_DIR names)"
    checked = "1.52.0"

    side_unit = "file"

    # -- where to look ------------------------------------------------------

    def default_paths(self, env, home, platform):
        share = env.get(ENV)
        if isinstance(share, str) and share:
            return [(share, "env " + ENV)]
        return [(_paths.join(platform, home, ".kimi"), "default")]

    def projects(self, root):
        """{md5 hex: work directory} from kimi.json's work_dirs. Only each
        entry's path is read. {} when the file is missing or not JSON."""
        try:
            with open(os.path.join(root, "kimi.json"), encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, ValueError, RecursionError):
            return {}
        dirs = data.get("work_dirs") if isinstance(data, dict) else None
        out = {}
        for entry in dirs if isinstance(dirs, list) else ():
            path = entry.get("path") if isinstance(entry, dict) else None
            if isinstance(path, str) and path:
                digest = _md5(path)
                if digest:
                    out[digest] = path
        return out

    def stores(self, locations, since_days=None):
        found = []
        for loc in locations:
            root = loc.path
            if not os.path.isdir(root):
                continue
            projects = self.projects(root)
            for work_dir in _entries(os.path.join(root, "sessions")):
                if not _is_dir(work_dir):
                    continue
                project = projects.get(folder_md5(work_dir.name))
                for entry in _entries(work_dir.path):
                    if _is_dir(entry):
                        self._folder(found, entry.path, entry.name, project,
                                     top=True)
                    elif entry.name.endswith(SUFFIX) and _is_file(entry):
                        # before v0.59: one context-format file per session
                        self._add(found, entry.path, "transcript",
                                  entry.name[:-len(SUFFIX)], project)
            # A whole session folder, as the vis ZIP download packed it.
            for entry in _entries(os.path.join(root, "imported_sessions")):
                if _is_dir(entry):
                    self._folder(found, entry.path, entry.name, None, top=True)
            for entry in _entries(os.path.join(root, "user-history")):
                if entry.name.endswith(SUFFIX) and _is_file(entry):
                    md5 = folder_md5(entry.name[:-len(SUFFIX)])
                    self._add(found, entry.path, "side", None,
                              projects.get(md5))
        return newest_first(found, since_days)

    def _folder(self, found, folder, session, project, top):
        """A session folder's stores, or (top False) a 1.25 subagent's
        folder inside one. wire.jsonl is the transcript when it is there,
        context.jsonl when it is not; every other file is a side store. The
        Task subagent contexts, the background tasks and the subagents'
        folders belong to a session folder; prompt.txt and output to a
        subagent's."""
        wire = os.path.join(folder, WIRE)
        has_wire = os.path.isfile(wire)
        if has_wire:
            self._add(found, wire, "transcript", session, project)
        context = os.path.join(folder, CONTEXT)
        if os.path.isfile(context):
            self._add(found, context, "side" if has_wire else "transcript",
                      session, project)
        for path, _conversation in _other_contexts(folder, top):
            self._add(found, path, "side", session, project)
        if not top:
            for name in (SUB_PROMPT, SUB_OUTPUT):
                path = os.path.join(folder, name)
                if os.path.isfile(path):
                    self._add(found, path, "side", session, project,
                              format="text")
            return
        for task in _entries(os.path.join(folder, TASKS)):
            if not _is_dir(task):
                continue
            for name, format in ((TASK_OUTPUT, "text"), (TASK_SPEC, "json")):
                path = os.path.join(task.path, name)
                if os.path.isfile(path):
                    self._add(found, path, "side", session, project,
                              format=format)
        for entry in _entries(os.path.join(folder, SUBAGENTS)):
            if _is_dir(entry):
                self._folder(found, entry.path, session, project, top=False)

    def _add(self, found, path, role, session, project, format="jsonl"):
        unit = self.unit if role == "transcript" else self.side_unit
        store = self.store(path, format, role=role, unit=unit,
                           session=session, project=project)
        if store is not None:
            found.append(store)

    # -- tool calls ---------------------------------------------------------

    def _call(self, store, record, timestamp=None, not_after=None,
              count=True):
        """A ToolCall from a {type: "function", id, function: {name,
        arguments}} record (a wire ToolCall payload, or one entry of a
        context message's tool_calls). None, counted, when it names no tool."""
        fn = record.get("function") if isinstance(record, dict) else None
        name = fn.get("name") if isinstance(fn, dict) else None
        if not isinstance(name, str) or not name:
            if count:
                self.count("unreadable_calls")
            return None
        tool_input = decode_input(fn.get("arguments"))
        fields = dict(tool_input=tool_input, session=store.session,
                      project=store.project, timestamp=timestamp,
                      not_after=None if timestamp else not_after,
                      tool_call_id=_id(record.get("id")))
        spec = TOOLS.get(name)
        if spec is None:
            return ToolCall(self.id, store.path, name, kind="other",
                            known=False, **fields)
        kind, key, consume = spec
        value = tool_input.get(key)
        if isinstance(value, str) and value:
            if kind == "shell":
                fields["command"] = value
            else:
                fields["paths"] = (value,)
            if consume:
                fields["consumed"] = (key,)
        return ToolCall(self.id, store.path, name, kind=kind, known=True,
                        **fields)

    def tool_calls(self, store):
        """Every call in a transcript store, once, each with its output,
        whether the user rejected it, and (wire only) its time. A pre-1.25
        Task subagent's calls come from the SubagentEvent records of the
        main wire.jsonl.

        A side store yields none of its own. A session folder's transcript
        also yields the calls its other context files hold and it does not:
        a session saved before 0.59 and resumed later keeps its older calls
        only in context.jsonl (or, after a /clear, a rotated context), since
        wire.jsonl starts at the resume. Those are undated, with the store
        they came from. Where wire.jsonl recorded everything, as it does from
        0.59 on, they are all copies and none is yielded."""
        if store.role != "transcript":
            return
        reader = (self._wire_calls if os.path.basename(store.path) == WIRE
                  else self._context_calls)
        parsed = [0]
        before = self.counts.get("unparsed", 0)
        try:
            for call in reader(store, parsed):
                yield call
        except Exception as e:      # one store must not stop the others
            self.unreadable_store("could not be read", store.path)
            self.warn(store.path, "cannot read Kimi CLI history %s (%s)"
                      % (store.path, e))
            return
        if not parsed[0] and self.counts.get("unparsed", 0) > before:
            self.unreadable_store("not JSON lines", store.path)
            self.warn(store.path, "Kimi CLI history %s is not JSON lines; "
                      "nothing in it was read" % store.path)

    def _wire_calls(self, store, parsed):
        # Every wire record has a time; a call that somehow has none is no
        # later than the file's last write.
        not_after = _stamps.iso_utc(store.mtime, "s")
        pending = _Pending(copies=False)
        pieces = _Pieces()
        # A pre-1.25 Task subagent's calls, by the Task call's id: its ids
        # count from Shell:0 again, so they are matched apart from the main
        # agent's.
        subs = OrderedDict()
        approvals = {}          # approval request id -> tool call id
        for _no, obj in _lines.iter_json_lines(store.path, self.counts):
            parsed[0] += 1
            message = obj.get("message") if isinstance(obj, dict) else None
            mtype = message.get("type") if isinstance(message, dict) else None
            if not isinstance(mtype, str):
                if not (isinstance(obj, dict) and obj.get("type") == "metadata"):
                    self.count("unknown")
                continue
            payload = message.get("payload")
            payload = payload if isinstance(payload, dict) else {}
            if mtype in CALL_RECORDS:
                for call in self._wire_event(store, mtype, payload, pending,
                                             pieces, None, obj.get("timestamp"),
                                             not_after):
                    yield call
            elif mtype == SUBAGENT_EVENT:
                task = _id(payload.get("task_tool_call_id"))
                event = payload.get("event")
                if task is None or payload.get("agent_id") is not None \
                        or not isinstance(event, dict):
                    # 1.25 on (agent_id set): a copy of the subagent's own
                    # wire.jsonl, which is read for itself.
                    continue
                etype, epayload = event.get("type"), event.get("payload")
                if etype in CALL_RECORDS and isinstance(epayload, dict):
                    sub = subs.setdefault(task, _Pending(copies=False))
                    for call in self._wire_event(store, etype, epayload, sub,
                                                 pieces, task,
                                                 obj.get("timestamp"),
                                                 not_after):
                        yield call
            elif mtype == APPROVAL_REQUEST:
                rid, cid = _id(payload.get("id")), _id(payload.get("tool_call_id"))
                # agent_id (1.25 on) names a subagent: the call is in that
                # subagent's own wire.jsonl, not here.
                if rid is not None and cid is not None \
                        and payload.get("agent_id") is None:
                    approvals[rid] = cid
            elif mtype in APPROVAL_RESPONSES:
                cid = approvals.pop(_id(payload.get("request_id")), None)
                if payload.get("response") == REJECT and cid is not None:
                    # Before 1.25 a Task subagent's request reached this wire
                    # as it was, under the subagent's own call id. When that
                    # id is waiting in more than one conversation the
                    # request is not matched; the call's result still tells.
                    owners = [p for p in [pending] + list(subs.values())
                              if cid in p.calls]
                    if len(owners) == 1:
                        owners[0].calls[cid].status = "declined"
            # TurnBegin, StepBegin, ContentPart, StatusUpdate and the rest
            # carry no call.
        for scope, waiting in [(None, pending)] + list(subs.items()):
            self._whole(store, waiting, pieces.close(scope))
            for call in waiting.rest():
                yield call
        sub_seen = set()
        for sub in subs.values():
            sub_seen |= sub.seen
        for call in self._folder_extras(store, pending.seen, sub_seen):
            yield call

    def _wire_event(self, store, mtype, payload, pending, pieces, scope,
                    stamp, not_after):
        """The calls a ToolCall, ToolCallPart or ToolResult payload of one
        agent (`scope`, see _Pieces) finishes. A piece adds to the agent's
        latest call, read again once it is whole. A result that is a
        ToolRejectedError makes its call declined."""
        if mtype == "ToolCallPart":
            pieces.part(scope, payload)
            return []
        if mtype == "ToolCall":
            record, before = pieces.call(scope, payload)
            self._whole(store, pending, before)
            call = self._call(store, record, timestamp=_stamps.iso_utc(
                stamp, "s"), not_after=not_after)
            return pending.add(call, record) if call is not None else []
        cid = _id(payload.get("tool_call_id"))
        self._whole(store, pending, pieces.answered(scope, cid))
        value = payload.get("return_value")
        output = (_output_text(value.get("output"))
                  if isinstance(value, dict) else None)
        call = pending.result(cid, output, rejected=_rejected_result(value))
        return [call] if call is not None else []

    def _whole(self, store, pending, entry):
        """Read again, from its whole arguments, a call that came in pieces
        (`entry`, see _Pieces.close) while it waits for its result."""
        record = entry[2] if entry is not None and len(entry[3]) > 1 else None
        cid = _id(record.get("id")) if record is not None else None
        if cid is not None and pending.records.get(cid) is record:
            old = pending.calls[cid]
            call = self._call(store, record, timestamp=old.timestamp,
                              not_after=old.not_after)
            call.status = old.status
            pending.calls[cid] = call

    def _context_calls(self, store, parsed):
        """Calls in a context-format file. It holds no times: each call is
        undated, no later than the file's last write. A session folder's
        context.jsonl also brings in its folder's other context files."""
        not_after = _stamps.iso_utc(store.mtime, "s")
        pending = _Pending()
        for _no, obj in _lines.iter_json_lines(store.path, self.counts):
            parsed[0] += 1
            if not isinstance(obj, dict) or not isinstance(obj.get("role"), str):
                self.count("unknown")
                continue
            for call in self._context_record(store, obj, pending, not_after):
                yield call
        for call in pending.rest():
            yield call
        if os.path.basename(store.path) == CONTEXT:
            for call in self._folder_extras(store, pending.seen, set()):
                yield call

    def _context_record(self, store, obj, pending, not_after):
        """The calls one context message finishes."""
        role = obj.get("role")
        if role == "assistant":
            records = obj.get("tool_calls")
            for record in records if isinstance(records, list) else ():
                call = self._call(store, record, not_after=not_after)
                if call is not None:
                    for done in pending.add(call, record):
                        yield done
        elif role == "tool":
            content = obj.get("content")
            call = pending.result(_id(obj.get("tool_call_id")),
                                  _tool_message_text(content),
                                  rejected=_rejected_message(content))
            if call is not None:
                yield call

    def _folder_extras(self, transcript, main_seen, sub_seen):
        """The calls the other context files of the transcript's folder hold
        that the transcript does not. `main_seen` and `sub_seen` are the
        keys of the calls the transcript held for the main agent and for
        pre-1.25 Task subagents. Each context file is matched within its own
        conversation, and a copy in two of them is yielded once."""
        folder = os.path.dirname(transcript.path)
        top = os.path.basename(os.path.dirname(folder)) != SUBAGENTS
        files = _other_contexts(folder, top)
        if os.path.basename(transcript.path) == WIRE:
            files.insert(0, (os.path.join(folder, CONTEXT), _MAIN))
        seen = {_MAIN: main_seen}
        for path, conversation in files:
            if conversation not in seen:
                seen[conversation] = set(sub_seen)
            for call in self._extra_calls(transcript, path,
                                          seen[conversation]):
                yield call

    def _extra_calls(self, transcript, path, seen):
        """The calls in one context file whose keys are not in `seen`, with
        their results. Only lines that can hold a call, or the result of one
        still waiting, are parsed. A file that cannot be read gives none
        here; clean warns when it reads it for itself."""
        store = self.store(path, "jsonl", role="side", unit=self.side_unit,
                           session=transcript.session,
                           project=transcript.project)
        if store is None:
            return
        not_after = _stamps.iso_utc(store.mtime, "s")
        pending = _Pending(seen)
        try:
            with open(path, "rb") as fh:
                for index, raw in enumerate(fh, 1):
                    if b'"tool_calls"' not in raw and not (
                            pending.calls and b'"tool"' in raw):
                        continue
                    try:
                        obj = json.loads(_lines.decode_line(raw, index == 1))
                    except (ValueError, RecursionError):
                        continue
                    if isinstance(obj, dict):
                        for call in self._context_record(store, obj, pending,
                                                         not_after):
                            yield call
        except OSError:
            pass
        for call in pending.rest():
            yield call

    # -- secrets ------------------------------------------------------------

    def secret_texts(self, store):
        """Every line of the store, the system prompt and rotated contexts
        included. A ToolResult or tool message carries the call it answers;
        a call's own line carries none (what was typed has no origin). A
        call a wire.jsonl holds in pieces (see _Pieces) is given whole, in
        place of the lines of its pieces, so a value cut in two by them is
        found, and found once, not also its start as a value of its own.
        A line that is not JSON is searched as text. A plain text store
        (output.log, prompt.txt, output) is searched in pieces of whole
        lines; a background task's output.log carries the Shell call its
        spec.json names. spec.json is searched as one document."""
        if store.format == "text":
            call = (self._task_call(store)
                    if os.path.basename(store.path) == TASK_OUTPUT else None)
            try:
                for line_no, text in _text_pieces(store.path):
                    yield SecretText(text, call=call, where="line %d" % line_no)
            except OSError as e:
                self.warn(store.path, "cannot read Kimi CLI file %s (%s)"
                          % (store.path, e))
            return
        if store.format == "json":
            try:
                with open(store.path, "rb") as fh:
                    text = fh.read().decode("utf-8", "surrogateescape")
            except OSError as e:
                self.warn(store.path, "cannot read Kimi CLI file %s (%s)"
                          % (store.path, e))
                return
            text = text[1:] if text.startswith(_lines.BOM) else text
            try:
                node = json.loads(text)
            except (ValueError, RecursionError):
                node = text
            yield SecretText(node, where="the whole file")
            return
        name = os.path.basename(store.path)
        shape = ("history" if os.path.basename(os.path.dirname(store.path))
                 == "user-history" else "wire" if name == WIRE else "context")
        calls = {}
        pieces = _Pieces()
        try:
            for line_no, obj, text in _raw_lines(store.path):
                where = "line %d" % line_no
                if obj is _NOT_JSON:
                    yield SecretText(text, where=where)
                    continue
                answered = None
                node = _readable(obj) if '"arguments"' in text else obj
                if shape == "wire":
                    answered, whole, held = self._wire_answers(
                        store, obj, calls, pieces, line_no, node)
                    if whole is not None:
                        yield _whole_text(whole)
                    if held:
                        continue
                elif shape == "context":
                    answered = self._context_answers(store, obj, calls)
                yield SecretText(node, call=answered, where=where)
            for whole in pieces.rest():
                yield _whole_text(whole)
        except OSError as e:
            self.warn(store.path, "cannot read Kimi CLI history %s (%s)"
                      % (store.path, e))

    def _task_call(self, log):
        """The background Shell call whose output `log` holds, from the
        task's spec.json: its command and call id (background/models.py
        TaskSpec). None when spec.json is missing or not JSON, or names no
        command (an agent task)."""
        path = os.path.join(os.path.dirname(log.path), TASK_SPEC)
        spec = _load_json(path)
        command = spec.get("command") if isinstance(spec, dict) else None
        if not isinstance(command, str) or not command:
            return None
        return ToolCall(self.id, path, "Shell", tool_input={"command": command},
                        kind="shell", known=True, session=log.session,
                        project=log.project,
                        tool_call_id=_id(spec.get("tool_call_id")),
                        command=command, consumed=("command",))

    def _wire_answers(self, store, obj, calls, pieces, line_no, node):
        """(The call a wire line's result answers, or None; a call this
        line makes whole, as _Pieces.close gives it, or None; whether the
        line, `node` as it is searched, is held to be given with its call
        when that is whole.) A subagent's call and result are matched
        within that subagent. `calls` holds each call's record, by scope
        and id, until its result."""
        scope, mtype, payload = _scope_event(obj)
        if mtype == "ToolCall":
            record, before = pieces.call(scope, payload, line_no, node)
            cid = _id(record.get("id"))
            if cid is not None:
                calls[(scope, cid)] = record
            return None, before, scope in pieces.latest
        if mtype == "ToolCallPart":
            return None, None, pieces.part(scope, payload, line_no)
        if mtype == "ToolResult":
            cid = _id(payload.get("tool_call_id"))
            whole = pieces.answered(scope, cid)
            record = calls.pop((scope, cid), None)
            if record is not None:
                return self._call(store, record, count=False), whole, False
            return None, whole, False
        return None, None, False

    def _context_answers(self, store, obj, calls):
        role = obj.get("role") if isinstance(obj, dict) else None
        if role == "assistant":
            records = obj.get("tool_calls")
            for record in records if isinstance(records, list) else ():
                call = self._call(store, record, count=False)
                if call is not None and call.tool_call_id is not None:
                    calls[call.tool_call_id] = call
            return None
        if role == "tool":
            return calls.pop(_id(obj.get("tool_call_id")), None)
        return None

    # -- masking ------------------------------------------------------------

    def in_use(self, store):
        """A background task's output.log while its runtime.json says the
        task has not stopped. Its worker holds the file open and appends
        what the command prints (background/worker.py), so a file put in its
        place would miss everything printed after, however long the command
        was quiet. Only "status" is read. Every other store is opened per
        write, or written whole, by Kimi."""
        if store.format != "text" or os.path.basename(store.path) != TASK_OUTPUT:
            return False
        runtime = _load_json(os.path.join(os.path.dirname(store.path),
                                          TASK_RUNTIME))
        status = runtime.get("status") if isinstance(runtime, dict) else None
        return isinstance(status, str) and status not in _TASK_DONE

    def mask(self, store, values):
        """The generic rewrite, but a wire.jsonl where a value is cut in two
        by the pieces of a call (see _Pieces) is refused as a file whose
        masking would change more than the secret. Raw replacement cannot
        reach that value, and the file would pass for masked with it still
        there."""
        if (store.masking == "rewrite" and os.path.basename(store.path) == WIRE
                and _cut_in_pieces(store.path, values)):
            return MaskResult(store.path, skipped=_rewrite.ALTERED)
        return Source.mask(self, store, values)


def _whole_text(entry):
    """A call held by _Pieces, as one SecretText: its own line when it came
    in one piece, else its whole record."""
    first, last, record, pieces, line = entry
    if len(pieces) == 1:
        return SecretText(line, where="line %d" % first)
    return SecretText(_readable(record), where="lines %d-%d" % (first, last))


def _cut_in_pieces(path, values):
    """True when one of `values`, in any form it takes in JSON text, runs
    from one piece of a call's arguments into the next. Only the lines
    that can hold a call or a piece are parsed."""
    forms = set()
    for value in values:
        if isinstance(value, str) and value:
            forms.update(_rewrite.encodings(value))
    if not forms:
        return False
    pieces = _Pieces()
    with open(path, "rb") as fh:
        for index, raw in enumerate(fh, 1):
            if b'"ToolCall' not in raw:
                continue
            try:
                obj = json.loads(_lines.decode_line(raw, index == 1))
            except (ValueError, RecursionError):
                continue
            scope, mtype, payload = _scope_event(obj)
            if mtype == "ToolCall":
                before = pieces.call(scope, payload)[1]
                if before is not None and _crosses(before[3], forms):
                    return True
            elif mtype == "ToolCallPart":
                pieces.part(scope, payload)
    return any(_crosses(entry[3], forms) for entry in pieces.rest())


def _crosses(pieces, forms):
    """True when one of `forms` in the joined `pieces` starts in one piece
    and ends in another."""
    if len(pieces) < 2:
        return False
    whole = "".join(pieces)
    ends, at = [], 0
    for piece in pieces[:-1]:
        at += len(piece)
        ends.append(at)
    for form in forms:
        start = whole.find(form)
        while start != -1:
            if any(start < end < start + len(form) for end in ends):
                return True
            start = whole.find(form, start + 1)
    return False


def _text_pieces(path):
    """(line_no, text) for a plain text file, in pieces of whole lines of
    about _PIECE bytes, read a line at a time so a large log is never held
    whole. A line longer than _PIECE bytes is cut every _PIECE bytes. Bytes
    that are not UTF-8 come back by surrogateescape."""
    with open(path, "rb") as fh:
        parts, size, first, line_no = [], 0, 1, 1
        for raw in iter(lambda: fh.readline(_PIECE), b""):
            if not parts:
                first = line_no
            parts.append(raw)
            size += len(raw)
            if raw.endswith(b"\n"):
                line_no += 1
            if size >= _PIECE:
                yield first, b"".join(parts).decode("utf-8", "surrogateescape")
                parts, size = [], 0
        if parts:
            yield first, b"".join(parts).decode("utf-8", "surrogateescape")


def _raw_lines(path):
    """(line_no, decoded JSON or _NOT_JSON, text) for every non-blank line,
    split on b"\\n" only, as _lines.iter_json_lines splits them."""
    with open(path, "rb") as fh:
        for index, raw in enumerate(fh, 1):
            text = _lines.decode_line(raw, first=index == 1)
            if not text.strip():
                continue
            try:
                obj = json.loads(text)
            except (ValueError, RecursionError):
                obj = _NOT_JSON
            yield index, obj, text
