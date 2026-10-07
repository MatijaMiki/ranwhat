"""Continue: the IDE extension (continuedev/continue) and its `cn` CLI.

Checked against tag v2.1.0-vscode (commit b238c1f, 2026-06-18; the files
named here are the same on main as of 2026-07-20), with v1.0.8-vscode for
the legacy shapes. The module is continue_dev because `continue` is a
Python keyword.

Where: CONTINUE_GLOBAL_DIR when it is set and not empty, else
<home>/.continue on every platform, Windows included (core/util/paths.ts
CONTINUE_GLOBAL_DIR; os.homedir(), no APPDATA variant). Continue resolves a
relative value against its own working directory, which is not known here;
Source.locations resolves it against ranwhat's. The CLI's
CONTINUE_CLI_TEST switch (session.ts getSessionDir) is for its tests and is
not read. The IDE extension and `cn` share the folder and the format: the
CLI saves through core's HistoryManager (extensions/cli/src/session.ts).

A session is <global>/sessions/<sessionId>.json, one JSON document
pretty-printed with JSON.stringify(x, undefined, 2) and rewritten whole,
in place, on every save (core/util/history.ts; no temp file, so a file can
be caught half written: it then fails to parse, warns and is skipped). Top
level keys, in this order: sessionId, title, workspaceDirectory, history,
then mode, chatModelTitle and usage when set. workspaceDirectory is a URI
("file:///home/u/proj") in the IDE and process.cwd() in the CLI; a file://
URI is turned into a path here. history is a list of ChatHistoryItem
(core/index.d.ts): {message: {role, content, toolCalls?, toolCallId?},
contextItems, editorState?, promptLogs?, toolCallStates?, reasoning?, ...}.

A tool call is a ToolCallState in an assistant item's toolCallStates (a
list; a single toolCallState object in v1.0.x): {toolCallId, toolCall: {id,
type, function: {name, arguments: <JSON string>}}, status, parsedArgs,
processedArgs?, output?: ContextItem[], tool?}. The arguments are read from
the JSON string, else from parsedArgs (the string may be partial for a call
cut off while it was generated). An id in message.toolCalls with no state
is read from there. The output is the state's output items' content,
joined as Continue renders them (core/util/messageContent.ts
renderContextItems), else the content of the IDE's separate {"message":
{"role": "tool", "toolCallId", "content"}} item for that id
(gui/src/redux/thunks/streamResponseAfterToolCall.ts). The CLI keeps no
such item and puts one {"content", "name": "Tool Result", "description":
"Tool execution result"} on the state (ChatHistoryService.addToolResult).

Tool names: the IDE's (core/tools/builtIn.ts; "builtin_" in front in
v1.0.x) and the CLI's (extensions/cli/src/tools/builtInToolNames.ts, plus
CheckBackgroundJob). The IDE's tools take "filepath"; the CLI's Read and
Write take "filepath", its Edit and MultiEdit "file_path". MCP tools keep
their own names and are judged by them.

No message carries a time. A call's time is the file's last write
(not_after), except a command the user ran with "!" in the CLI: that is an
assistant item with empty content and a Bash call whose id is
shell-<Date.now()>-<random> (extensions/cli/src/ui/hooks/
useChat.shellMode.ts), so it is the user's ("actor" user) and its id gives
the time it was run.

Declined: status "canceled" covers more than a refusal, so a call is
"declined" only when the record shows it did not run:
- the CLI cancels a call only when permission is refused, and then writes
  "Permission denied by user" or "Command blocked by security policy" as
  its output (stream/streamChatResponse.helpers.ts);
- the IDE cancels a call the user rejected (sessionSlice cancelToolCall),
  writing no output, or with ui.continueAfterToolRejection one hidden
  "Tool Call Rejected" item (thunks/cancelToolCall.ts); a pending
  generated or generating call left behind when a new message is sent is
  canceled the same way, with no output (sessionSlice.ts); an edit whose
  diff the user rejected is canceled with none either
  (AcceptRejectDiffButtons.tsx).
But the IDE's stop button also cancels a terminal command that is already
running (LumpToolbar.tsx), whose streamed output is on the state by then;
so a canceled call with any other output did run, and is not declined.
"errored" was attempted; "generating", "generated" and "calling" are a
session cut off part way, and nothing is said about them.

sessions/sessions.json is the index (sessionId, title, dateCreated,
workspaceDirectory, messageCount), not a transcript: it is searched for
secrets only (a title is text the user typed), as a side store.

Not read: everything in the Continue folder outside sessions/. Its config
files (config.yaml, config.json, config.ts, out/, .env, .configs/,
sharedConfig.json, .continuerc.json) hold API keys, and the CLI's
auth.json holds its login tokens: login material is never searched. Also
not read, a known limit: dev_data/ (telemetry JSONL with every tool call's
arguments, output and an ISO timestamp, joinable by toolCallId, and full
prompts) and logs/ (core.log, prompt.log): secrets echoed there are not
found by clean.
"""

from __future__ import annotations

import json
import os
import re
from urllib.parse import unquote

from . import _lines, _paths, _stamps, base
from .base import SecretText, Source, ToolCall

ENV = "CONTINUE_GLOBAL_DIR"
ROOT = ".continue"
SESSIONS = "sessions"
INDEX = "sessions.json"
SUFFIX = ".json"

DECLINED = "declined"
CANCELED = "canceled"

# The IDE extension's tools (core/tools/builtIn.ts at v2.1.0). Before 1.1
# each name had "builtin_" in front (LEGACY_PREFIX).
IDE_TOOLS = {
    "run_terminal_command": "shell",
    "read_file": "read",
    "read_file_range": "read",
    "create_new_file": "write",
    "edit_existing_file": "write",
    "single_find_and_replace": "write",
    "multi_edit": "write",
    "fetch_url_content": "fetch",
    "search_web": "fetch",
    "read_currently_open_file": "other",     # no path in its arguments
    "ls": "other",
    "file_glob_search": "other",
    "grep_search": "other",
    "view_diff": "other",
    "codebase": "other",
    "create_rule_block": "other",
    "request_rule": "other",
    "read_skill": "other",
    "view_repo_map": "other",
    "view_subdirectory": "other",
}
LEGACY_PREFIX = "builtin_"

# The `cn` CLI's tools (extensions/cli/src/tools/builtInToolNames.ts, and
# tools/checkBackgroundJob.ts).
CLI_TOOLS = {
    "Bash": "shell",
    "Read": "read",
    "Write": "write",
    "Edit": "write",
    "MultiEdit": "write",
    "Fetch": "fetch",
    "List": "other",
    "Search": "other",
    "Diff": "other",
    "CheckBackgroundJob": "other",
    "Skills": "other",
    "Subagent": "other",
    "AskQuestion": "other",
    "Exit": "other",
    "ReportFailure": "other",
    "Status": "other",
    "UploadArtifact": "other",
    "Checklist": "other",
}

# Where a read or write names its file: "filepath" in the IDE and in the
# CLI's Read and Write, "file_path" in the CLI's Edit and MultiEdit.
PATH_KEYS = ("filepath", "file_path")

# A command the user ran with "!" in the CLI (useChat.shellMode.ts).
USER_SHELL_TOOL = "Bash"
_USER_SHELL_ID = re.compile(r"shell-([0-9]{10,16})-[0-9a-z]*\Z")

# The outputs a canceled call gets when it never ran (see the module notes).
REFUSED_TEXTS = ("Permission denied by user",
                 "Command blocked by security policy")
REJECTED_ITEM = "Tool Call Rejected"

# ChatMessageRole (core/index.d.ts). Other roles are counted.
ROLES = ("user", "assistant", "thinking", "system", "tool")

# How much of a session file is read to name its session and project when
# it is found; the rest is read when it is searched.
_HEAD_MAX = 1 << 16

# A top-level key of the pretty-printed document: two spaces in, at the
# start of a line. A newline inside a JSON string is always escaped, so
# nothing deeper, and nothing inside a title, matches.
_TOP_KEY = r'\n  "%s": ("(?:[^"\\\n]|\\.)*")'
_HEAD_KEYS = {k: re.compile(_TOP_KEY % k)
              for k in ("sessionId", "workspaceDirectory")}

_WIN_DRIVE = re.compile(r"/[A-Za-z]:")


def _string(value):
    return value if isinstance(value, str) and value else None


def _dict(value):
    return value if isinstance(value, dict) else {}


def uri_path(value):
    """A file:// URI as a path, the way VS Code writes one
    ("file:///c%3A/Users/u" is "c:/Users/u"; a host is a UNC share).
    Anything else, a plain path or another scheme, as it is."""
    if not isinstance(value, str) or not value[:7].lower() == "file://":
        return value
    rest = value[7:]
    host, sep, path = rest.partition("/")
    path = unquote(sep + path)
    if _WIN_DRIVE.match(path):
        path = path[1:]
    host = unquote(host)
    if host and host.lower() != "localhost":
        return "//" + host + path
    return path or value


def _classify(name):
    """(kind, known) for a tool name: the IDE's (with or without the legacy
    prefix) and the CLI's from their sources, anything else unknown."""
    if name in CLI_TOOLS:
        return CLI_TOOLS[name], True
    if name.startswith(LEGACY_PREFIX):
        name = name[len(LEGACY_PREFIX):]
    if name in IDE_TOOLS:
        return IDE_TOOLS[name], True
    return "other", False


def _paths_in(arguments):
    """(paths, keys) for the PATH_KEYS a call's arguments hold."""
    paths, keys = [], []
    for key in PATH_KEYS:
        value = _string(arguments.get(key))
        if value:
            paths.append(uri_path(value))
            keys.append(key)
    return tuple(paths), tuple(keys)


def _arguments(state_call, state):
    """A call's arguments as a dict: function.arguments when it is JSON for
    an object, else parsedArgs when that is one, else what decode_input
    makes of the string."""
    raw = _dict(_dict(state_call).get("function")).get("arguments")
    decoded = base.decode_input(raw)
    if isinstance(raw, dict) or (isinstance(raw, str)
                                 and "_raw" not in decoded
                                 and "_value" not in decoded):
        return decoded
    parsed = state.get("parsedArgs") if isinstance(state, dict) else None
    if isinstance(parsed, dict):
        return parsed
    return decoded


def _content_text(content):
    """A message's content as text: a string, or its text parts joined."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        texts = [p.get("text") for p in content
                 if isinstance(p, dict) and isinstance(p.get("text"), str)]
        if texts:
            return "\n".join(texts)
    return None


def _output_items(state):
    output = state.get("output")
    return [i for i in output if isinstance(i, dict)] \
        if isinstance(output, list) else []


def _output_text(state):
    """The state's output as Continue renders it, or None when it has none."""
    texts = [i["content"] for i in _output_items(state)
             if isinstance(i.get("content"), str)]
    return "\n\n".join(texts) if texts else None


def _never_ran(state, answer):
    """True for a canceled call whose record shows it did not run (see the
    module notes): no output at all, or only the IDE's rejection item, or
    only the CLI's refusal text. `answer` is the IDE tool item's content."""
    if state.get("status") != CANCELED:
        return False
    output = state.get("output")
    if output is None or output == []:
        return not answer
    items = _output_items(state)
    if not isinstance(output, list) or len(items) != 1 or len(output) != 1:
        return False
    item = items[0]
    if item.get("name") == REJECTED_ITEM:
        return True
    return item.get("content") in REFUSED_TEXTS


def _states(item):
    """The ToolCallStates of a history item: toolCallStates, or the single
    toolCallState of v1.0.x."""
    states = item.get("toolCallStates")
    if isinstance(states, list):
        return [s for s in states if isinstance(s, dict)]
    state = item.get("toolCallState")
    return [state] if isinstance(state, dict) else []


def _deltas(item):
    """message.toolCalls entries of a history item."""
    message = _dict(item.get("message"))
    calls = message.get("toolCalls")
    return [c for c in calls if isinstance(c, dict)] \
        if isinstance(calls, list) else []


def _read_head(path):
    """{key: value} for the head keys of a session file, from its first
    _HEAD_MAX bytes."""
    try:
        with open(path, "rb") as fh:
            head = fh.read(_HEAD_MAX)
    except OSError:
        return {}
    text = head.decode("utf-8", "replace")
    found = {}
    for key, pattern in _HEAD_KEYS.items():
        m = pattern.search(text)
        if not m:
            continue
        try:
            value = json.loads(m.group(1))
        except (ValueError, RecursionError):
            continue
        if _string(value):
            found[key] = value
    return found


def _files(folder):
    """Every *.json file directly in `folder` (not dot-files), as the CLI
    lists them (session.ts loadSession)."""
    try:
        entries = list(os.scandir(folder))
    except OSError:
        return []
    out = []
    for entry in entries:
        if entry.name.startswith(".") or not entry.name.endswith(SUFFIX):
            continue
        try:
            if entry.is_file():
                out.append(entry.path)
        except OSError:
            continue
    return sorted(out)


class ContinueSource(Source):
    id = "continue"
    name = "Continue"
    unit = "session"
    env = (ENV,)
    path_means = "a Continue folder (what CONTINUE_GLOBAL_DIR means)"
    checked = "2.1.0"
    # Said after masking. Continue keeps an open session in memory and
    # writes the whole file from there on its next save.
    mask_note = ("If Continue or cn has this session open, close it first: "
                 "it rewrites the whole file from memory on its next save, "
                 "value included.")

    def reset(self):
        Source.reset(self)
        self._bad = set()       # stores already counted as unreadable
        self._tallied = set()   # stores whose unknown items are counted

    # -- where to look ------------------------------------------------------

    def default_paths(self, env, home, platform):
        """CONTINUE_GLOBAL_DIR when set and not empty, else ~/.continue."""
        moved = _string(env.get(ENV))
        if moved:
            return [(moved, "env " + ENV)]
        return [(_paths.join(platform, home, ROOT), "default")]

    def stores(self, locations, since_days=None):
        found, seen = [], set()
        for loc in locations:
            for path in _files(os.path.join(loc.path, SESSIONS)):
                key = os.path.normcase(os.path.abspath(path))
                if key in seen:
                    continue
                seen.add(key)
                if os.path.basename(path) == INDEX:
                    store = self.store(path, "json", role="side",
                                       unit="session index")
                else:
                    head = _read_head(path)
                    stem = os.path.basename(path)[:-len(SUFFIX)]
                    store = self.store(
                        path, "json", role="transcript",
                        session=head.get("sessionId") or stem,
                        project=uri_path(head.get("workspaceDirectory")))
                if store is not None:
                    found.append(store)
        return base.newest_first(found, since_days)

    # -- reading ------------------------------------------------------------

    def _bad_store(self, store, reason):
        if store.path not in self._bad:
            self._bad.add(store.path)
            self.unreadable_store(reason, store.path)
        self.warn(store.path, "could not read Continue %s %s (%s)"
                  % (store.unit, store.path, reason))

    def _load(self, store):
        """The decoded document, or None (warned once) when the file cannot
        be read or is not JSON."""
        try:
            with open(store.path, "rb") as fh:
                text = fh.read().decode("utf-8", "surrogateescape")
        except OSError as e:
            self._bad_store(store, e.strerror or type(e).__name__)
            return None
        if text.startswith(_lines.BOM):
            text = text[1:]
        try:
            return json.loads(text)
        except (ValueError, RecursionError):
            self._bad_store(store, "not JSON")
            return None

    def _history(self, store, doc):
        """The history list of a session document, counting (once per store
        per run) a document or item of a shape the format does not have."""
        tally = store.path not in self._tallied
        self._tallied.add(store.path)
        history = doc.get("history") if isinstance(doc, dict) else None
        if not isinstance(history, list):
            if tally:
                self.count("unknown")
            return []
        if tally:
            for item in history:
                message = item.get("message") if isinstance(item, dict) else None
                if not (isinstance(message, dict)
                        and message.get("role") in ROLES):
                    self.count("unknown")
        return history

    @staticmethod
    def _answers(history):
        """{toolCallId: content} of the IDE's role "tool" items, first copy."""
        out = {}
        for item in history:
            message = _dict(item.get("message")) if isinstance(item, dict) else {}
            cid = _string(message.get("toolCallId"))
            if message.get("role") == "tool" and cid and cid not in out:
                out[cid] = _content_text(message.get("content"))
        return out

    def _call(self, store, doc, state_call, state, answers):
        """The ToolCall for one state (or a bare toolCalls entry, state {})."""
        state_call = _dict(state_call)
        name = _string(_dict(state_call.get("function")).get("name")) or ""
        cid = _string(state.get("toolCallId")) or _string(state_call.get("id"))
        arguments = _arguments(state_call, state)
        kind, known = _classify(name)
        command, paths, consumed = None, (), ()
        if kind == "shell":
            command = _string(arguments.get("command"))
            consumed = ("command",) if command else ()
        elif kind == "read":
            paths, consumed = _paths_in(arguments)
        elif kind == "write":
            paths, _keys = _paths_in(arguments)
        answer = answers.get(cid) if cid else None
        output = _output_text(state)
        if output is None and answer:
            output = answer
        actor, timestamp = "agent", None
        m = _USER_SHELL_ID.match(cid) if cid and name == USER_SHELL_TOOL else None
        if m:
            actor = "user"
            timestamp = _stamps.iso_utc(int(m.group(1)), "ms")
        doc = _dict(doc)
        return ToolCall(
            self.id, store.path, name, arguments, kind=kind, known=known,
            session=_string(doc.get("sessionId")) or store.session,
            project=uri_path(_string(doc.get("workspaceDirectory")))
            or store.project,
            timestamp=timestamp,
            not_after=None if timestamp else _stamps.iso_utc(store.mtime, "s"),
            tool_call_id=cid, actor=actor,
            status=DECLINED if _never_ran(state, answer) else None,
            command=command, paths=paths, consumed=consumed, output=output)

    def _calls(self, store, doc, history):
        """[(item index, ToolCall)] for every call, each id once (its first
        copy): each state, then each toolCalls entry with no state."""
        answers = self._answers(history)
        out, seen = [], set()
        for index, item in enumerate(history):
            if not isinstance(item, dict):
                continue
            pairs = [(s.get("toolCall"), s) for s in _states(item)]
            pairs += [(d, {}) for d in _deltas(item)]
            for state_call, state in pairs:
                call = self._call(store, doc, state_call, state, answers)
                cid = call.tool_call_id
                if cid is not None:
                    if cid in seen:
                        continue
                    seen.add(cid)
                out.append((index, call))
        return out

    def tool_calls(self, store):
        """Every call in a session file, once per id, with its output."""
        if store.role != "transcript":
            return
        doc = self._load(store)
        if doc is None:
            return
        for _index, call in self._calls(store, doc, self._history(store, doc)):
            yield call

    def secret_texts(self, store):
        """Every string in the file. A call's output (its state's output,
        and the IDE's role "tool" item for it) is handed over on its own,
        tied to the call; a file the user attached to a message (a context
        item with a file uri) is handed over as that file's content; the
        rest of each item, and of the document, with neither."""
        doc = self._load(store)
        if doc is None:
            return
        if store.role != "transcript":
            yield SecretText(doc, where="file")
            return
        history = self._history(store, doc)
        if not isinstance(doc, dict) or not history:
            yield SecretText(doc, where="file")
            return
        yield SecretText({k: v for k, v in doc.items() if k != "history"},
                         where="file")
        calls = {}
        for _index, call in self._calls(store, doc, history):
            if call.tool_call_id is not None:
                calls.setdefault(call.tool_call_id, call)
        for index, item in enumerate(history):
            where = "message %d" % (index + 1)
            if not isinstance(item, dict):
                yield SecretText(item, where=where)
                continue
            for text in self._item_texts(item, calls, where):
                yield text

    def _item_texts(self, item, calls, where):
        rest = dict(item)
        split = []                  # (node, call, attached)
        message = item.get("message")
        if isinstance(message, dict) and message.get("role") == "tool":
            call = calls.get(_string(message.get("toolCallId")) or "")
            if "content" in message:
                rest["message"] = {k: v for k, v in message.items()
                                   if k != "content"}
                split.append((message["content"], call, None))
            if "contextItems" in item:
                rest.pop("contextItems")
                split.append((item["contextItems"], call, None))
        else:
            for key in ("toolCallStates", "toolCallState"):
                value = item.get(key)
                if key not in item:
                    continue
                states = value if isinstance(value, list) else [value]
                kept = []
                for state in states:
                    if isinstance(state, dict) and "output" in state:
                        cid = (_string(state.get("toolCallId"))
                               or _string(_dict(state.get("toolCall")).get("id")))
                        split.append((state["output"], calls.get(cid or ""),
                                      None))
                        state = {k: v for k, v in state.items()
                                 if k != "output"}
                    kept.append(state)
                rest[key] = kept if isinstance(value, list) else kept[0]
            context = item.get("contextItems")
            if isinstance(context, list):
                kept = []
                for ci in context:
                    uri = _dict(ci.get("uri")) if isinstance(ci, dict) else {}
                    named = (uri_path(_string(uri.get("value")))
                             if uri.get("type") == "file" else None)
                    if named:
                        split.append((ci, None, named))
                    else:
                        kept.append(ci)
                rest["contextItems"] = kept
        yield SecretText(rest, where=where)
        for node, call, attached in split:
            yield SecretText(node, call=call, attached=attached, where=where)
