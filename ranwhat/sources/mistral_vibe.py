"""Mistral Vibe (`vibe` CLI, vibe-acp for VS Code, Zed and JetBrains, and
Vibe Desktop, which drive the same app server): one adapter that reads both
layouts the agent has written. Checked against mistralai/mistral-vibe
v3.0.0 (source, and a real `vibe -p` 3.0.0 run against a mock model) and
v2.26.1.

Where: the save folder is session_logging.save_dir, by default
$VIBE_HOME/logs/session, and VIBE_HOME is ~/.vibe (the user's home
directory on every system, vibe/utils/vibe_home.py; a leading ~ in the
variable is expanded). Only the default and VIBE_HOME are looked at. A
save_dir set in $VIBE_HOME/config.toml, in a project's .vibe/config.toml or
by managed config is not (TOML is not read here); point `--path` at that
folder instead. `--path` takes the save folder, or a VIBE_HOME that holds
logs/session. With session_logging.enabled = false Vibe writes to a
throwaway folder it deletes at exit, so there is nothing to read.

Under the save folder:

    unified/<session id>/              the 3.0 Unified store, the only writer
                                       for new sessions since 2.26.0
        CURRENT                        pointer: generation, store_format
        generations/<16 digits>/       manifest, projection-state,
                                       checkpoint, runtime-state (.json)
        journal/<16 digits>.jsonl      records since the generation
        chunks/<sha256>.json           pooled runs of history entries
        meta.json, scheduled-loops.json
    <prefix>_<YYYYmmdd_HHMMSS>_<id>/   the 2.x layout (prefix "session"):
        meta.json, messages.jsonl      read as they are; 3.0 only imports
                                       them into a new unified session

Not read: active/ (live-session leases), plugins/, unified/.session-index.json,
a unified session's scratchpad/, anything else under the save folder, and
the ACP wire log ~/.vibe/logs/acp/messages.jsonl (off unless
VIBE_ACP_LOGGING_ENABLED=1; its format is raw JSON-RPC and was not checked).

The Unified store (RFC 8785 canonical JSON, store_format
"mistral.vibe.unified-session-store/v1", minor 9 at 3.0.0). Mistral calls
it runtime-private (docs/adr/0006), so the layout can change; the entries
read here are its public projection, which Mistral's own end-to-end test
also reads from disk. The history is rebuilt the way Vibe rebuilds it
(_storage.py _load, apply_projection_delta):

1. CURRENT names the generation. Only the two newest generations are
   kept, so a read that finds one gone reads CURRENT again, once.
2. generations/<g>/manifest.json names projection-state.json and, when
   its "chunks" is a list, the pooled chunks/<sha256>.json whose JSON
   arrays, concatenated in that order, are the history (the file's own
   snapshot.history.entries is then empty). A null "chunks" means the
   entries are in the file.
3. The journal segment the manifest names holds what happened since. A
   projection_delta or session_relocated record carries a "delta" of ops,
   {"op": "append_entry", "entry"}, {"op": "replace_entry", "id",
   "entry"}, {"op": "remove_entry", "id"}, {"op": "set_history_entries",
   "entries"} and {"op": "set_envelope"}; a projection_advanced record
   carries a whole snapshot. While a turn runs its tool calls exist only
   there. Every other record type (action_intent, whose line can be 64 MiB
   because it holds the model's whole input, action_result, core_input,
   receipts, ...) is skipped without being parsed. A last line with no
   newline is a record being written: skipped, as Vibe skips it.

Not used for history: checkpoint.json (its messages are replaced when the
context is compacted) and runtime-state.json (settled request and result
bodies are pruned from it). A session imported from 2.x or from another
agent holds only user and assistant text in the projection, so it adds no
tool call, and nothing is counted twice.

A tool call is an entry {"type": "effect", "id": "effect-<action id>",
"createdAt" (Unix ms), "detail": {"kind": "tool", "toolName", "input"},
"state": {"status", "decision", "outputText", "output": {"structured_content":
{"stdout", "stderr", "returncode"}}, ...}}. Keys are camelCase; the nested
tool result is snake_case. The model's shell tool is "bash" but is stored as
"file_system.bash"; the others are file_system.read_file, write_file and
search_replace, process.start (input.command, cwd), process.write, output,
list and stop, agents.spawn (detail.kind "subagent"), skill.read, web_fetch,
web_search, connector_web_search.*, grep, todo, vibe.todo, vibe.cron and
ui.ask_user_question, and MCP or connector tools as "<group>.<tool>". The
model's own call id is not in the projection (it is only in the journal's
action_intent), so the effect id is the tool_call_id. A command the user
ran with `!` is a host-authored effect, detail.kind "shell" and toolName
"shell" (MANUAL_SHELL_TOOL_NAME), input {"command"}: actor "user". A call
Vibe did not run has state.status "skipped" (error code tool_skipped) or
state.decision "skip" (ToolResultEvent.decision is "execute" or "skip"):
declined. One that was running when the file was written, or cancelled, is
reported as a call: it may have run. An entry that a rewind removed is not
in the history any more and is not reported.

The 2.x layout: messages.jsonl is one LLMMessage per line (model_dump,
exclude_none): an assistant row with tool_calls [{"id", "function":
{"name", "arguments": a JSON string}}], then a tool row {"role": "tool",
"name", "tool_call_id", "content"}. Rows have no time; meta.json has
start_time and end_time, and a call's not_after is end_time. The tools are
the bare names (bash, read_file, write_file, search_replace, grep, ...)
with the argument file_path. A `!` command is a row with "manual_shell"
{command, cwd, stdout, stderr, exit_code, created_at in ms}. How 2.x
records a call the user refused is not in anything checked, so none is
declined there. The 1.x layout (one JSON file per session, up to
2026-01) is no longer supported by Vibe and not read.

Masking: a unified session is read-only here. Its manifest and CURRENT
carry SHA-256 digests of the files and of the journal records, so changing
a byte would make Vibe reject the session. clean still finds secrets in it
(every generation, chunk, journal record and meta file), and says so. The
2.x files carry no digests and are rewritten like any JSON Lines file.
Nothing is ever written to a store; no file is opened for writing.

Defences: files over MAX_DOC (Vibe's own limit for one document) are not
read, a journal line over MAX_LINE is streamed past in 1 MiB steps and its
type decides whether a call may be missing, symlinked folders and files
are not followed, every name taken from a file is checked against the
shape Vibe writes before it is joined to a path, a store_format other
than v1 is unreadable and a minor above CHECKED_MINOR is read with a
warning.
"""

from __future__ import annotations

import json
import os
import re

from . import _lines, _paths, _stamps
from .base import SecretText, Source, ToolCall, decode_input, newest_first

ENV = "VIBE_HOME"
HOME_DIR = ".vibe"
SAVE_PARTS = ("logs", "session")
UNIFIED = "unified"
MESSAGES = "messages.jsonl"
META = "meta.json"

STORE_FORMAT = "mistral.vibe.unified-session-store/v1"
STORE_FAMILY = "mistral.vibe.unified-session-store/"
CHECKED_MINOR = 9

# One document is at most this long (_storage.py _MAX_DOCUMENT_BYTES).
MAX_DOC = 64 * 1024 * 1024
# A journal line is read whole up to this; a longer one is streamed past.
MAX_LINE = 64 * 1024 * 1024
_STEP = 1 << 20
_TAIL = 160
# meta.json and CURRENT are small; a bigger one is not what Vibe wrote.
MAX_META = 4 * 1024 * 1024

# Stored output kept on a ToolCall is cut here, as clean cuts any string
# (clean.MAX_STRING; sources do not import clean).
OUTPUT_MAX = 1000000

_SESSION_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}\Z")
_GENERATION = re.compile(r"[0-9]{16}\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_CHUNK_FILE = re.compile(r"[0-9a-f]{64}\.json\Z")
_JOURNAL_FILE = re.compile(r"[0-9]{16}\.jsonl\Z")
_DOC_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.json\Z")
_RECORD_TYPE = re.compile(rb'"type":"([a-z_]{1,64})"\}\s*\Z')

# The generation files, by the name Vibe gives them.
GENERATION_DOCS = ("manifest.json", "projection-state.json",
                   "checkpoint.json", "runtime-state.json")

# Journal records that change the projection. Every other type is skipped.
_REPLAYED = frozenset(("projection_delta", "projection_advanced",
                       "session_relocated"))

# Folders of the save folder that are not 2.x sessions.
_NOT_SESSIONS = frozenset((UNIFIED, "active", "plugins"))

WHY_SEALED = ("Vibe seals each unified session with SHA-256 digests; "
              "changing a byte would make it refuse the session. "
              "ranwhat only reads it.")

# Tool names, by what they do. A name not here is judged by watch by name:
# MCP and connector tools, process.write (it types into a running process),
# vibe.cron (it schedules prompts) and anything newer. Names are as stored
# in the unified projection ("file_system." in front of the model's own)
# and as 2.x wrote them.
_KINDS = {
    "file_system.bash": "shell",
    "bash": "shell",
    "process.start": "shell",
    "shell": "shell",
    "file_system.read_file": "read",
    "read_file": "read",
    "file_system.write_file": "write",
    "write_file": "write",
    "file_system.search_replace": "write",
    "search_replace": "write",
    "web_fetch": "fetch",
    "web_search": "fetch",
    "connector_web_search.web_search": "fetch",
    "connector_web_search.open_url": "fetch",
    "grep": "other",
    "skill.read": "other",
    "process.output": "other",
    "process.list": "other",
    "process.stop": "other",
    "agents.spawn": "other",
    "search_tool_functions": "other",
    "todo": "other",
    "vibe.todo": "other",
    "ui.ask_user_question": "other",
}

# Where a read or write names its file: the unified tools take "path"
# (read_file, write_file) and "file_path" (search_replace); 2.x took
# "file_path" for all three.
PATH_KEYS = ("path", "file_path")

MANUAL_SHELL = "shell"
DECLINED = "declined"


def _set(env, name):
    value = env.get(name)
    return value if isinstance(value, str) and value else None


def _expand(value, home, platform):
    """`value` with a leading ~ made the home directory, as Python's
    Path.expanduser does it for Vibe: "~" and "~/..." everywhere, "~\\..."
    on Windows too."""
    win = _paths.platform_name(platform) == "win32"
    if value == "~":
        return home
    if value.startswith("~/") or (win and value.startswith("~\\")):
        return _paths.join(platform, home, value[2:])
    return value


def _scandir(path):
    """Entries of a directory, or none when it cannot be listed."""
    try:
        with os.scandir(path) as it:
            return sorted(it, key=lambda e: e.name)
    except OSError:
        return []


def _is_dir(entry):
    try:
        return entry.is_dir(follow_symlinks=False)
    except OSError:
        return False


def _is_file(entry):
    try:
        return entry.is_file(follow_symlinks=False)
    except OSError:
        return False


def _string(value):
    return value if isinstance(value, str) and value else None


class _Bad(Exception):
    """A store that is not in a shape this adapter reads (the message is
    the one-line reason a report gives)."""


class _Gone(Exception):
    """A file the store names that is not there now: a generation Vibe
    collected while it was being read."""


def _read_bytes(path, limit):
    """The bytes of a regular file, not a symlink, at most `limit` long.
    OSError when it cannot be opened; _Bad when it is longer."""
    st = os.lstat(path)
    if not os.path.isfile(path) or os.path.islink(path):
        raise OSError("not a regular file")
    if st.st_size > limit:
        raise _Bad("a file over %d MiB" % (limit >> 20))
    with open(path, "rb") as fh:
        data = fh.read(limit + 1)
    if len(data) > limit:
        raise _Bad("a file over %d MiB" % (limit >> 20))
    return data


def _load_json(path, limit=None):
    """A JSON document: OSError when unreadable, ValueError when not JSON,
    _Bad when too long."""
    data = _read_bytes(path, MAX_DOC if limit is None else limit)
    text = data.decode("utf-8", "surrogateescape")
    if text.startswith(_lines.BOM):
        text = text[1:]
    try:
        return json.loads(text)
    except RecursionError:
        raise ValueError("nested too deeply")


def _text_of(value):
    """A string as it is, or the text parts of a content-part list joined
    by newlines. None when there is no text."""
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        parts = []
        for p in value:
            if isinstance(p, dict) and isinstance(p.get("text"), str):
                parts.append(p["text"])
            elif isinstance(p, str):
                parts.append(p)
        if parts:
            return "\n".join(parts)
    return None


def _cut(text):
    return None if text is None else text[:OUTPUT_MAX]


def _output_of(state):
    """The text a finished effect printed: outputText, else the stdout and
    stderr of the tool result (structured_content in a tool's, stdout and
    stderr beside output in a `!` command's), else its text content, else
    the error message."""
    if not isinstance(state, dict):
        return None
    text = state.get("outputText")
    if isinstance(text, str) and text:
        return _cut(text)
    out = state.get("output")
    if isinstance(out, dict):
        shell = out.get("output")
        if isinstance(shell, str) and shell:
            return _cut(shell)
        sc = out.get("structured_content")
        if isinstance(sc, dict):
            parts = [sc.get(k) for k in ("stdout", "stderr")]
            parts = [p for p in parts if isinstance(p, str) and p]
            if parts:
                return _cut("\n".join(parts))
        else:
            parts = [out.get(k) for k in ("stdout", "stderr")]
            parts = [p for p in parts if isinstance(p, str) and p]
            if parts:
                return _cut("\n".join(parts))
        text = _text_of(out.get("content"))
        if text:
            return _cut(text)
    error = state.get("error")
    if isinstance(error, dict) and isinstance(error.get("message"), str):
        return _cut(error["message"])
    return None


def _paths_in(arguments):
    paths, keys = [], []
    for key in PATH_KEYS:
        value = arguments.get(key)
        if isinstance(value, str) and value:
            paths.append(value)
            keys.append(key)
    return tuple(paths), tuple(keys)


def _classify(name, arguments):
    """(kind, known, command, workdir, paths, consumed) for a call to the
    tool `name` with these (decoded) arguments."""
    kind = _KINDS.get(name) if isinstance(name, str) else None
    if kind is None:
        return "other", False, None, None, (), ()
    command = workdir = None
    paths, consumed = (), ()
    if kind == "shell":
        value = arguments.get("command")
        if isinstance(value, str) and value:
            command, consumed = value, ("command",)
        cwd = arguments.get("cwd")
        if isinstance(cwd, str) and cwd:
            workdir = cwd
    elif kind in ("read", "write"):
        paths, keys = _paths_in(arguments)
        if kind == "read":
            consumed = keys
    return kind, True, command, workdir, paths, consumed


def _is_effect(entry):
    return (isinstance(entry, dict) and entry.get("type") == "effect"
            and isinstance(entry.get("id"), str))


class _History(object):
    """The effect entries of a projection, in order, kept as Vibe keeps the
    whole history: a list, with replace and remove by id. Other entries
    (messages, notices) are not kept; an op that names one finds nothing."""

    def __init__(self):
        self.entries = []
        self.index = {}

    def _reindex(self):
        self.index = {}
        for i, entry in enumerate(self.entries):
            self.index.setdefault(entry["id"], i)

    def reset(self, entries):
        self.entries = [e for e in entries if _is_effect(e)]
        self._reindex()

    def append(self, entry):
        if _is_effect(entry):
            self.entries.append(entry)
            self.index.setdefault(entry["id"], len(self.entries) - 1)

    def remove(self, entry_id):
        if entry_id in self.index:
            self.entries = [e for e in self.entries if e["id"] != entry_id]
            self._reindex()

    def replace(self, entry_id, entry):
        i = self.index.get(entry_id)
        if i is None:
            return
        if _is_effect(entry):
            self.entries[i] = entry
            if entry["id"] != entry_id:
                self._reindex()
        else:
            self.remove(entry_id)


def _record_type(tail):
    """The type of a journal record from the end of its line, where the
    canonical form puts it: the last key. None when the line does not end
    that way."""
    m = _RECORD_TYPE.search(tail)
    return m.group(1).decode("ascii") if m else None


def _journal_lines(path):
    """Yield (line number, raw bytes or None, tail, complete) for each line
    of a journal. raw is None for a line over MAX_LINE, which is read past
    in steps and never held; tail is its last _TAIL bytes."""
    with open(path, "rb") as fh:
        number = 0
        while True:
            raw = fh.readline(MAX_LINE + 1)
            if not raw:
                return
            number += 1
            if len(raw) > MAX_LINE and not raw.endswith(b"\n"):
                tail = raw[-_TAIL:]
                complete = False
                while True:
                    chunk = fh.readline(_STEP)
                    if not chunk:
                        break
                    tail = (tail + chunk)[-_TAIL:]
                    if chunk.endswith(b"\n"):
                        complete = True
                        break
                yield number, None, tail.rstrip(b"\r\n"), complete
                continue
            yield (number, raw, raw[-_TAIL:].rstrip(b"\r\n"),
                   raw.endswith(b"\n"))


class _Session(object):
    """What one read of a unified session gives."""
    __slots__ = ("calls", "entries")

    def __init__(self, calls, entries):
        self.calls = calls
        self.entries = entries


class MistralVibeSource(Source):
    id = "mistral-vibe"
    name = "Mistral Vibe"
    unit = "session"
    env = (ENV,)
    path_means = ("a Mistral Vibe save folder (VIBE_HOME/logs/session, "
                  "default ~/.vibe/logs/session) or a VIBE_HOME")
    checked = "3.0.0"
    mask_note = ("If Vibe has this session open, close it first: it keeps "
                 "appending to the file.")

    def reset(self):
        super().reset()
        self._tallied = set()

    # -- where to look ------------------------------------------------------

    def default_paths(self, env, home, platform):
        moved = _set(env, ENV)
        if moved:
            root = _expand(moved, home, platform)
            how = "env " + ENV
        else:
            root = _paths.join(platform, home, HOME_DIR)
            how = "default"
        return [(_paths.join(platform, root, *SAVE_PARTS), how)]

    def stores(self, locations, since_days=None):
        found, seen = [], set()

        def add(store):
            if store is not None:
                key = os.path.normcase(os.path.abspath(store.path))
                if key not in seen:
                    seen.add(key)
                    found.append(store)

        for loc in locations:
            bases = [loc.path, os.path.join(loc.path, *SAVE_PARTS)]
            for base in bases:
                if not os.path.isdir(base):
                    continue
                for entry in _scandir(os.path.join(base, UNIFIED)):
                    if _is_dir(entry) and _SESSION_ID.match(entry.name):
                        add(self._unified_store(entry.path, entry.name))
                for entry in _scandir(base):
                    if (_is_dir(entry) and entry.name not in _NOT_SESSIONS
                            and not entry.name.startswith(".")):
                        for store in self._legacy_stores(entry.path,
                                                         entry.name):
                            add(store)
        return newest_first(found, since_days)

    @staticmethod
    def _meta(folder):
        """meta.json of a session folder as a dict, or {}."""
        try:
            doc = _load_json(os.path.join(folder, META), MAX_META)
        except (OSError, ValueError, _Bad):
            return {}
        return doc if isinstance(doc, dict) else {}

    @staticmethod
    def _project(meta):
        env = meta.get("environment")
        for value in (env.get("working_directory") if isinstance(env, dict)
                      else None, meta.get("origin_directory")):
            if _string(value):
                return value
        return None

    def _unified_store(self, folder, name):
        current = os.path.join(folder, "CURRENT")
        try:
            if not (os.path.isfile(current) and not os.path.islink(current)):
                return None
        except OSError:
            return None
        meta = self._meta(folder)
        store = self.store(current, "json", session=name,
                           project=self._project(meta), masking="read-only",
                           why_read_only=WHY_SEALED)
        if store is None:
            return None
        # CURRENT only moves when a generation is published; a running
        # turn appends to the journal. The newest write to either is the
        # session's last.
        for entry in _scandir(os.path.join(folder, "journal")):
            if _JOURNAL_FILE.match(entry.name):
                try:
                    store.mtime = max(store.mtime, entry.stat().st_mtime)
                except OSError:
                    pass
        return store

    def _legacy_stores(self, folder, name):
        messages = os.path.join(folder, MESSAGES)
        try:
            if not (os.path.isfile(messages) and not os.path.islink(messages)):
                return []
        except OSError:
            return []
        meta = self._meta(folder)
        session = _string(meta.get("session_id")) or name
        project = self._project(meta)
        out = [self.store(messages, "jsonl", session=session,
                          project=project)]
        meta_path = os.path.join(folder, META)
        if os.path.isfile(meta_path) and not os.path.islink(meta_path):
            out.append(self.store(meta_path, "json", role="side",
                                  session=session, project=project))
        return [s for s in out if s is not None]

    # -- bookkeeping --------------------------------------------------------

    def _once(self, key):
        """True the first time a key is seen in a run: counts are taken on
        the first pass over a store only, as watch and clean both read it."""
        if key in self._tallied:
            return False
        self._tallied.add(key)
        return True

    def _unreadable(self, store, reason):
        key = ("unreadable", os.path.normcase(store.path))
        if key in self._warned:
            return
        self.unreadable_store(reason, store.path)
        self.warn(key, "could not read Mistral Vibe %s %s (%s)"
                  % (store.unit if store.role == "transcript" else "file",
                     store.path, reason))

    # -- the unified store --------------------------------------------------

    def _current(self, root):
        """(generation, raw bytes of CURRENT) from a session's CURRENT."""
        path = os.path.join(root, "CURRENT")
        raw = _read_bytes(path, MAX_META)
        try:
            doc = json.loads(raw.decode("utf-8", "surrogateescape"))
        except (ValueError, RecursionError):
            raise _Bad("CURRENT is not JSON")
        if not isinstance(doc, dict):
            raise _Bad("CURRENT is not a Vibe session pointer")
        fmt = doc.get("store_format")
        if not isinstance(fmt, str) or not fmt.startswith(STORE_FAMILY):
            raise _Bad("not a Vibe session store")
        if fmt != STORE_FORMAT:
            raise _Bad("a newer Vibe session store format")
        minor = doc.get("store_format_minor")
        if (isinstance(minor, int) and not isinstance(minor, bool)
                and minor > CHECKED_MINOR):
            self.warn(("minor", minor),
                      "Mistral Vibe store format minor %d is newer than %d, "
                      "which this was checked against; reading it as it is"
                      % (minor, CHECKED_MINOR))
        generation = doc.get("generation")
        if not isinstance(generation, str) or not _GENERATION.match(generation):
            raise _Bad("CURRENT names no generation")
        return generation, raw

    @staticmethod
    def _chunks(root, digests):
        """The entries of the pooled chunks, in order. _Bad when a name is
        not a digest or a chunk is not a list; OSError when one is gone."""
        out = []
        for digest in digests:
            if not isinstance(digest, str) or not _DIGEST.match(digest):
                raise _Bad("a chunk name that is not a digest")
            chunk = _load_json(os.path.join(root, "chunks", digest + ".json"))
            if not isinstance(chunk, list):
                raise _Bad("a chunk that is not a list")
            out.extend(chunk)
        return out

    @staticmethod
    def _document(generation_dir, descriptor, default):
        """The path of a file a manifest descriptor names, else `default`."""
        name = descriptor.get("path") if isinstance(descriptor, dict) else None
        if isinstance(name, str) and _DOC_NAME.match(name):
            return os.path.join(generation_dir, name)
        return os.path.join(generation_dir, default)

    def _load_once(self, store, first):
        """The _History of a unified session at its CURRENT generation and
        end of journal, or an exception: OSError and _Gone for a file that
        vanished, _Bad for one that is not what Vibe writes."""
        root = os.path.dirname(store.path)
        generation, _raw = self._current(root)
        generation_dir = os.path.join(root, "generations", generation)
        manifest = _load_json(os.path.join(generation_dir, "manifest.json"))
        if not isinstance(manifest, dict):
            raise _Bad("a manifest that is not an object")
        descriptor = manifest.get("projection_state")
        projection = _load_json(self._document(
            generation_dir, descriptor, "projection-state.json"))
        snapshot = projection.get("snapshot") if isinstance(projection, dict) \
            else None
        hist = snapshot.get("history") if isinstance(snapshot, dict) else None
        if not isinstance(hist, dict):
            raise _Bad("a projection with no history")
        chunks = descriptor.get("chunks") if isinstance(descriptor, dict) \
            else None
        history = _History()
        if isinstance(chunks, list):
            history.reset(self._chunks(root, chunks))
        else:
            entries = hist.get("entries")
            history.reset(entries if isinstance(entries, list) else [])
        segment = manifest.get("recovery_journal_segment")
        name = segment.get("path") if isinstance(segment, dict) else None
        parts = name.split("/") if isinstance(name, str) else []
        if len(parts) == 2 and parts[0] == "journal" \
                and _JOURNAL_FILE.match(parts[1]):
            journal = os.path.join(root, "journal", parts[1])
            if os.path.isfile(journal) and not os.path.islink(journal):
                self._replay(journal, history, first)
        return history

    def _replay(self, journal, history, first):
        """Apply the journal's projection records to `history`."""
        for line_no, raw, tail, complete in _journal_lines(journal):
            rtype = _record_type(tail)
            if rtype is not None and rtype not in _REPLAYED:
                continue
            if raw is None:
                if first and rtype in _REPLAYED:
                    self.count("unreadable_calls")
                continue
            if not complete:
                continue                # a record being written
            try:
                obj = json.loads(_lines.decode_line(raw))
            except (ValueError, RecursionError):
                if first:
                    self.count("unparsed")
                continue
            if not isinstance(obj, dict) or obj.get("type") not in _REPLAYED:
                continue
            payload = obj.get("payload")
            if not isinstance(payload, dict):
                if first:
                    self.count("unknown")
                continue
            if obj["type"] == "projection_advanced":
                snap = payload.get("snapshot")
                h = snap.get("history") if isinstance(snap, dict) else None
                entries = h.get("entries") if isinstance(h, dict) else None
                if isinstance(entries, list):
                    history.reset(entries)
                elif first:
                    self.count("unknown")
            else:
                self._apply(history, payload.get("delta"), first)

    def _apply(self, history, ops, first):
        if not isinstance(ops, list):
            if first:
                self.count("unknown")
            return
        for op in ops:
            kind = op.get("op") if isinstance(op, dict) else None
            if kind == "append_entry":
                history.append(op.get("entry"))
            elif kind == "replace_entry":
                if isinstance(op.get("id"), str):
                    history.replace(op["id"], op.get("entry"))
            elif kind == "remove_entry":
                if isinstance(op.get("id"), str):
                    history.remove(op["id"])
            elif kind == "set_history_entries":
                entries = op.get("entries")
                history.reset(entries if isinstance(entries, list) else [])
            elif kind != "set_envelope" and first:
                self.count("unknown")

    def _load(self, store, first):
        """_load_once, and once more when CURRENT moved or a file it names
        was collected under the read (Vibe keeps two generations)."""
        path = os.path.join(os.path.dirname(store.path), "CURRENT")
        try:
            before = _read_bytes(path, MAX_META)
        except OSError:
            before = None
        try:
            return self._load_once(store, first)
        except (OSError, ValueError, _Bad):
            try:
                after = _read_bytes(path, MAX_META)
            except OSError:
                after = None
            if after is None or after == before:
                raise
            return self._load_once(store, first)

    def _effect_call(self, store, entry, first):
        """The ToolCall for one effect entry, or None for an effect that is
        no tool call (the worktree record)."""
        detail = entry.get("detail")
        state = entry.get("state")
        if not isinstance(detail, dict):
            detail = {}
            if first:
                self.count("unreadable_calls")
        kind = detail.get("kind")
        if kind == "worktree":
            return None
        name = _string(detail.get("toolName")) or _string(entry.get("title")) \
            or ""
        arguments = decode_input(detail.get("input"))
        k, known, command, workdir, paths, consumed = _classify(name, arguments)
        if k == "shell" and command is None and first and detail:
            self.count("unreadable_calls")
        stamp = _stamps.iso_utc(entry.get("createdAt"), "ms")
        status = None
        if isinstance(state, dict) and (state.get("status") == "skipped"
                                        or state.get("decision") == "skip"):
            status = DECLINED
        user = kind == "shell" and name == MANUAL_SHELL
        return ToolCall(
            self.id, store.path, name, arguments, kind=k, known=known,
            session=store.session, project=store.project, timestamp=stamp,
            tool_call_id=entry["id"], actor="user" if user else "agent",
            status=status, not_after=None if stamp else
            _stamps.iso_utc(store.mtime, "s"), command=command,
            workdir=workdir, paths=paths, consumed=consumed,
            output=_output_of(state))

    def _unified(self, store):
        first = self._once(("calls", os.path.normcase(store.path)))
        history = self._load(store, first)
        calls = []
        for entry in history.entries:
            call = self._effect_call(store, entry, first)
            if call is not None:
                calls.append(call)
        return _Session(calls, history.entries)

    # -- the 2.x layout -----------------------------------------------------

    def _legacy_call(self, store, name, raw_args, cid, not_after, actor="agent",
                     arguments=None):
        arguments = decode_input(raw_args) if arguments is None else arguments
        k, known, command, workdir, paths, consumed = _classify(name, arguments)
        return ToolCall(
            self.id, store.path, name if isinstance(name, str) else "",
            arguments, kind=k, known=known, session=store.session,
            project=store.project, tool_call_id=cid, actor=actor,
            not_after=not_after, command=command, workdir=workdir,
            paths=paths, consumed=consumed)

    def _legacy(self, store):
        """(calls in file order, {line number: call it answers}) for a 2.x
        messages.jsonl."""
        first = self._once(("calls", os.path.normcase(store.path)))
        meta = self._meta(os.path.dirname(store.path))
        not_after = _stamps.iso_utc(meta.get("end_time"), "iso") \
            or _stamps.iso_utc(store.mtime, "s")
        calls, latest, owners = [], {}, {}
        skipped = {}
        for line_no, obj in _lines.iter_json_lines(store.path, skipped):
            if not isinstance(obj, dict):
                if first:
                    self.count("unknown")
                continue
            shell = obj.get("manual_shell")
            if isinstance(shell, dict):
                command = _string(shell.get("command"))
                if command is None:
                    if first:
                        self.count("unreadable_calls")
                    continue
                call = self._legacy_call(
                    store, MANUAL_SHELL, None, None, None, actor="user",
                    arguments={"command": command, **(
                        {"cwd": shell["cwd"]} if _string(shell.get("cwd"))
                        else {})})
                stamp = _stamps.iso_utc(shell.get("created_at"), "ms")
                call.timestamp = stamp
                call.not_after = None if stamp else not_after
                parts = [shell.get(k) for k in ("stdout", "stderr")]
                parts = [p for p in parts if isinstance(p, str) and p]
                call.output = _cut("\n".join(parts)) if parts else None
                calls.append(call)
                owners[line_no] = call
                continue
            role = obj.get("role")
            if role == "tool":
                cid = _string(obj.get("tool_call_id"))
                call = latest.get(cid) if cid else None
                if call is not None:
                    owners[line_no] = call
                    if call.output is None:
                        call.output = _cut(_text_of(obj.get("content")))
                continue
            tool_calls = obj.get("tool_calls")
            if not isinstance(tool_calls, list):
                continue
            for tc in tool_calls:
                if not isinstance(tc, dict):
                    if first:
                        self.count("unknown")
                    continue
                fn = tc.get("function")
                fn = fn if isinstance(fn, dict) else {}
                cid = _string(tc.get("id"))
                if cid and cid in latest:
                    continue            # the same call written again
                call = self._legacy_call(store, fn.get("name"),
                                         fn.get("arguments"), cid, not_after)
                if not _string(fn.get("name")) and first:
                    self.count("unreadable_calls")
                calls.append(call)
                if cid:
                    latest[cid] = call
        if first:
            self.count("unparsed", skipped.get("unparsed", 0))
        return calls, owners

    # -- what is in a store -------------------------------------------------

    def tool_calls(self, store):
        if store.role != "transcript":
            return
        try:
            if store.format == "jsonl":
                calls, _owners = self._legacy(store)
            else:
                calls = self._unified(store).calls
        except OSError as e:
            self._unreadable(store, e.strerror or type(e).__name__)
            return
        except (_Bad, ValueError) as e:
            self._unreadable(store, str(e) or "not a Vibe session store")
            return
        for call in calls:
            yield call

    def secret_texts(self, store):
        try:
            if store.role != "transcript":
                items = self._doc_texts(store, store.path,
                                        os.path.basename(store.path), {})
            elif store.format == "jsonl":
                items = self._legacy_texts(store)
            else:
                items = self._unified_texts(store)
            for item in items:
                yield item
        except OSError as e:
            self._unreadable(store, e.strerror or type(e).__name__)

    def _legacy_texts(self, store):
        _calls, owners = self._legacy(store)
        for line_no, obj in _lines.iter_json_lines(store.path):
            yield SecretText(obj, call=owners.get(line_no),
                             where="line %d" % line_no)

    def _doc_texts(self, store, path, where, calls, entries_at=None):
        """The text of one JSON document: whole, or with its effect entries
        split into what the call was and what it printed."""
        try:
            doc = _load_json(path)
        except OSError:
            return                  # collected while being read
        except (ValueError, _Bad):
            if self._once(("doc", os.path.normcase(path))):
                self.count("unparsed")
            return
        if entries_at is not None:
            entries = entries_at(doc)
            if isinstance(entries, list):
                for entry in entries:
                    for text in self._entry_texts(entry, calls, where):
                        yield text
                return
        yield SecretText(doc, where=where)

    @staticmethod
    def _entry_texts(entry, calls, where):
        """An effect entry as two texts, its state credited to its call (a
        call's own input never is), or the entry whole."""
        call = calls.get(entry.get("id")) if isinstance(entry, dict) else None
        if call is not None and isinstance(entry.get("state"), dict):
            rest = dict((k, v) for k, v in entry.items() if k != "state")
            yield SecretText(rest, where=where)
            yield SecretText(entry["state"], call=call, where=where)
        else:
            yield SecretText(entry, where=where)

    def _unified_texts(self, store):
        """Every file of a unified session: meta, the loops file, every
        generation's four documents, every chunk and every journal record,
        including generations and chunks Vibe no longer replays."""
        root = os.path.dirname(store.path)
        calls = {}
        try:
            for call in self._unified(store).calls:
                calls[call.tool_call_id] = call
        except (OSError, ValueError, _Bad):
            pass                    # the files are searched all the same
        for name in (META, "scheduled-loops.json"):
            path = os.path.join(root, name)
            if os.path.isfile(path) and not os.path.islink(path):
                for text in self._doc_texts(store, path, name, calls):
                    yield text
        for gen in _scandir(os.path.join(root, "generations")):
            if not (_is_dir(gen) and _GENERATION.match(gen.name)):
                continue
            for name in GENERATION_DOCS:
                path = os.path.join(gen.path, name)
                if not os.path.isfile(path) or os.path.islink(path):
                    continue
                where = "generation %s %s" % (gen.name, name)
                at = _inline_entries if name == "projection-state.json" \
                    else None
                for text in self._doc_texts(store, path, where, calls, at):
                    yield text
        for chunk in _scandir(os.path.join(root, "chunks")):
            if _CHUNK_FILE.match(chunk.name) and _is_file(chunk):
                where = "chunk " + chunk.name[:-5]
                for text in self._doc_texts(store, chunk.path, where, calls,
                                            _whole_list):
                    yield text
        for entry in _scandir(os.path.join(root, "journal")):
            if _JOURNAL_FILE.match(entry.name) and _is_file(entry):
                for text in self._journal_texts(store, entry):
                    yield text

    def _journal_texts(self, store, entry):
        for line_no, raw, _tail, complete in _journal_lines(entry.path):
            where = "journal %s line %d" % (entry.name, line_no)
            if raw is None:
                if self._once(("long", entry.path, line_no)):
                    self.warn(("long", entry.path, line_no),
                              "a line of %s in Mistral Vibe session %s is "
                              "too long to search" % (entry.name,
                                                      store.session))
                continue
            try:
                obj = json.loads(_lines.decode_line(raw))
            except (ValueError, RecursionError):
                if complete and self._once(("line", entry.path, line_no)):
                    self.count("unparsed")
                continue
            yield SecretText(obj, where=where)


def _whole_list(doc):
    return doc if isinstance(doc, list) else None


def _inline_entries(doc):
    """The entries a projection-state.json holds itself: none when Vibe
    pooled them into chunks (those are read as chunks)."""
    snap = doc.get("snapshot") if isinstance(doc, dict) else None
    hist = snap.get("history") if isinstance(snap, dict) else None
    entries = hist.get("entries") if isinstance(hist, dict) else None
    if isinstance(entries, list) and entries:
        return entries
    return None
