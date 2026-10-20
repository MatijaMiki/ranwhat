"""Google Antigravity: the agy CLI, the Antigravity 2.0 App, the Antigravity
IDE and the google-antigravity Python SDK harness, which all run the same
"cortex" agent engine.

Each conversation has a folder of its own, <app data>/brain/<conversationId>/,
and in it .system_generated/logs/ holds:
- transcript_full.jsonl: one JSON object per trajectory step, complete.
- transcript.jsonl: the compact copy. Its lines map 1:1 to the full file,
  but large fields are cut ("truncated_fields" names them) and every tool
  argument value is a JSON-encoded string ("CommandLine":"\\"npm test\\"").
  It is read as the transcript only when the full file is missing; beside
  the full one it is a side store, searched for secrets and never counted
  as calls.
- chunks/transcript/00000000.jsonl and chunks/transcript_full/
  00000000.jsonl: byte-identical copies of the two. Side stores only, so a
  call is never counted twice.
Tool output also goes to .system_generated/steps/<step index>/output.txt,
a side store of plain text.

<app data> is ~/.gemini/antigravity-cli (agy), ~/.gemini/antigravity (the
App) or ~/.gemini/antigravity-ide (the IDE), under the user's home on
Linux, macOS and Windows (%USERPROFILE%). The SDK's save_dir and app_data_dir
are the caller's own and not found here; --path takes one. There is no
documented environment variable for any of them (HOME moves them all), so
this adapter has none.

Where each fact came from:
- The three folders, the brain/.../transcript.jsonl path and the
  run_command arguments: Antigravity's hooks documentation
  (antigravity.google/docs/hooks), re-read for this adapter.
- The line schema: not documented. It is the field list in the system
  prompt the vendor ships inside the agy 1.4.3 binary ("fields such as"),
  and the files agy 1.4.3 and the SDK harness 0.1.22 wrote with no hook
  configured. It is closed source and may drift; every field is read
  defensively and nothing outside this list is guessed.
- The Windows path is inferred from the documentation (.gemini under
  %USERPROFILE%) and was not run. Nor were the App and the IDE: their
  folders rest on the documentation alone.

A line has step_index, source (USER_EXPLICIT, MODEL, SYSTEM), type (the
CORTEX_STEP_TYPE_* names without the prefix: USER_INPUT, PLANNER_RESPONSE,
RUN_COMMAND, VIEW_FILE, CODE_ACTION, READ_URL_CONTENT, ERROR_MESSAGE,
GENERIC, ...), status (DONE, ERROR, INVALID, ...), created_at (ISO 8601 UTC),
content, thinking, error, exit_code, token counts, media and, on
PLANNER_RESPONSE steps only, tool_calls: [{"name", "args"}].

Facts of the format that shape this reader:
- A call has no id. A PLANNER_RESPONSE at step k with n tool_calls is
  followed by its n result steps, k+1 to k+n, in call order. So lines are
  sorted by step_index (they are not always written in order) and call i
  is paired with step k+1+i, skipping steps that are never a result
  (EPHEMERAL_MESSAGE, CHECKPOINT and the like, see NON_RESULT) and
  stopping at the next PLANNER_RESPONSE or USER_INPUT. The adjacency was
  observed only for the listed step types; skipping the others is a
  defensive choice, not documented behaviour. The id given to a call here is
  "<session>:<step>:<i>".
- Two tool-name families, by model path. Default cortex tools: run_command
  {CommandLine, Cwd, WaitMsBeforeAsync}, view_file {AbsolutePath},
  write_to_file {TargetFile, CodeContent}, replace_file_content and
  multi_replace_file_content {TargetFile}, list_dir, find_by_name,
  grep_search, read_url_content {Url}, search_web {query}. With
  GEMINI_API_KEY, agy uses read_file {Path}, write_file {Path, Content},
  edit_file {Path, Target, Replacement} and run_command without Cwd. The
  second family's results are GENERIC steps whose exit code is only in the
  text; nothing here needs it.
- Outcomes: an INVALID step is a call that never ran; an ERROR_MESSAGE
  step whose error starts "denied" is a call a policy or hook refused.
  Both are "declined". A call with no result step at all, while later
  steps exist and every line of the file read, is also "declined": that is
  what agy leaves when headless mode refuses an action without
  --dangerously-skip-permissions. That last rule was seen in the vendor
  binary's runs, not in its documentation. A call at the very end of the
  file, whose result may be still to come, is not.
- The file is rewritten on context compaction (agy 1.1.13 fixed a race
  with it). A presence/<conversationId>.lock file in the app data folder is
  taken as "in use", which stops masking; its format is unverified, so
  its mere presence counts.

Format versions: there is none in the file. Steps with no tool_calls, a
different tool-name family or extra fields all read the same way. The
transcript exists since agy 1.1.12; 1.2.4 began writing terminal ERROR steps
to it (earlier files lack them, so a refused call there has no result and
reads as declined).

Project: the Cwd argument of a command when it has one; otherwise the first
workspace_uris entry of the conversation in conversation_summaries.db
(<app data>/conversation_summaries.db, plain SQLite, opened read-only). The
table's name is not documented, so the table that has both a
conversation_id and a workspace_uris column is used. The status line's
transcript_path is wrong for the CLI (issue #744) and is never used.

Not read: conversations/<id>.db (SQLite whose step payloads are protobuf
blobs with no published schema; they may hold copies of what the
transcript does, which masking cannot reach), cache/, log/, settings.json
and the credentials in the system keyring.
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
from urllib.parse import unquote

from . import _lines, _paths, _sqlite, _stamps, base
from .base import SecretText, Source, ToolCall

APP_DIRS = ("antigravity-cli", "antigravity", "antigravity-ide")
PARENT = ".gemini"
BRAIN = "brain"
LOGS = (".system_generated", "logs")
STEPS = (".system_generated", "steps")
FULL = "transcript_full.jsonl"
COMPACT = "transcript.jsonl"
CHUNKS = ("chunks", "transcript_full"), ("chunks", "transcript")
OUTPUT = "output.txt"
SUMMARIES = "conversation_summaries.db"
PRESENCE = "presence"

# tool name -> kind, as the hooks documentation and the vendor binary's
# runs name them. Paths: the argument keys that name a file.
SHELL = {"run_command": "CommandLine"}
READ = {"view_file": ("AbsolutePath",), "read_file": ("Path",)}
WRITE = {"write_to_file": ("TargetFile",),
         "replace_file_content": ("TargetFile",),
         "multi_replace_file_content": ("TargetFile",),
         "write_file": ("Path",), "edit_file": ("Path",)}
FETCH = {"read_url_content", "search_web"}
OTHER = {"list_dir", "find_by_name", "grep_search"}

DECLINED = "declined"
PLANNER = "PLANNER_RESPONSE"
USER = "USER_INPUT"
# Step types the format lists; others are counted as unknown (the list is
# "such as", so a rise in the count is a hint, not an error).
TYPES = (USER, PLANNER, "RUN_COMMAND", "VIEW_FILE", "CODE_ACTION",
         "READ_URL_CONTENT", "ERROR_MESSAGE", "GENERIC")

# Steps that are never a tool's result. The type list is "such as", so
# these are skipped when pairing instead of being taken as the answer; any
# other type (a tool's own result type, or one not yet known) can be one.
NON_RESULT = (USER, PLANNER, "EPHEMERAL_MESSAGE", "CHECKPOINT",
              "CONVERSATION_HISTORY", "KNOWLEDGE_ARTIFACTS", "SYSTEM_MESSAGE")


def _results(steps, k, n, last):
    """[(step index, step)] for the first n result steps after step k, in
    order, skipping NON_RESULT steps; the run ends at the next PLANNER or
    USER step, which starts another turn. Linear: each step is visited by
    the one planner that precedes it."""
    out = []
    at = k
    while len(out) < n and at < last:
        at += 1
        step = steps.get(at)
        if step is None:
            # a gap keeps its place: the missing step's call is unanswered
            out.append((at, None))
            continue
        kind = step.get("type")
        if kind in (PLANNER, USER):
            break
        if kind in NON_RESULT:
            continue
        out.append((at, step))
    return out


# A line longer than this is not read as a record (a transcript line is a
# step; this is far beyond any tool result agy keeps). It is skipped,
# counted as unparsed, and its rest never held in memory.
MAX_LINE = 32 << 20
# Side text files are read in pieces of this size, overlapping so a value
# cut at a boundary still sits whole in one piece.
_CHUNK = 1 << 20
_OVERLAP = 4096
# Rows read from the summaries database.
_MAX_ROWS = 200000

_BAD = object()         # a line that is not JSON
_DRIVE = re.compile(r"/[A-Za-z]:[/\\]")


def _string(value):
    return value if isinstance(value, str) and value else None


def _entries(folder):
    try:
        return list(os.scandir(folder))
    except OSError:
        return []


def _dirs(folder):
    out = []
    for entry in _entries(folder):
        try:
            if not entry.name.startswith(".") and entry.is_dir():
                out.append(entry)
        except OSError:
            continue
    return out


def _file(path):
    try:
        return os.path.isfile(path)
    except OSError:
        return False


def _uri_path(uri):
    """The local path a file:// URI names, or None."""
    if not isinstance(uri, str) or not uri.startswith("file://"):
        return None
    path = unquote(uri[len("file://"):])
    if path.startswith("localhost/"):
        path = path[len("localhost"):]
    if _DRIVE.match(path):
        path = path[1:]
    return path or None


def _app_dir(path):
    """The app data folder above a store's path (the parent of brain/), or
    None."""
    here = os.path.dirname(path)
    for _ in range(12):
        parent = os.path.dirname(here)
        if os.path.basename(here) == BRAIN:
            return parent
        if parent == here:
            return None
        here = parent
    return None


def _decode_compact(args):
    """transcript.jsonl stores every argument value as a JSON string; give
    back the value. A value that is not JSON (cut short) stays as it is."""
    out = {}
    for key, value in args.items():
        if isinstance(value, str):
            try:
                value = json.loads(value)
            except (ValueError, RecursionError):
                pass
        out[key] = value
    return out


def _classify(name, args):
    """(kind, known, command, paths, consumed, workdir)."""
    if name in SHELL:
        command = _string(args.get(SHELL[name]))
        return ("shell", True, command, (),
                (SHELL[name],) if command else (), _string(args.get("Cwd")))
    keys = READ.get(name) or WRITE.get(name)
    if keys is not None:
        found, used = [], []
        for key in keys:
            value = args.get(key)
            if isinstance(value, str) and value:
                found.append(value)
                used.append(key)
        kind = "read" if name in READ else "write"
        return kind, True, None, tuple(found), tuple(used) if kind == "read" else (), None
    if name in FETCH:
        return "fetch", True, None, (), (), None
    if name in OTHER:
        return "other", True, None, (), (), None
    return "other", False, None, (), (), None


def _text_pieces(fh):
    """The text of a file as pieces of at most _CHUNK bytes, cut after a
    line end where the piece holds one and overlapping by _OVERLAP bytes
    otherwise, as (line_no, text)."""
    buf, line_no, end = b"", 1, False
    while buf or not end:
        if end and not buf:
            return
        if not end and len(buf) <= _CHUNK:
            block = fh.read(_CHUNK)
            end = not block
            buf += block
            continue
        if len(buf) > _CHUNK:
            cut = buf.rfind(b"\n", _CHUNK // 2, _CHUNK) + 1 or _CHUNK
            start = cut - _OVERLAP
        else:
            cut = start = len(buf)
        yield line_no, buf[:cut].decode("utf-8", "surrogateescape")
        if cut == len(buf):
            return
        line_no += buf.count(b"\n", 0, start)
        buf = buf[start:]


class AntigravitySource(Source):
    id = "antigravity"
    name = "Antigravity"
    unit = "conversation"
    env = ()
    path_means = ("an Antigravity app data folder (~/.gemini/antigravity-cli, "
                  "antigravity or antigravity-ide)")
    checked = "agy 1.4.3, SDK 0.1.22"

    def reset(self):
        Source.reset(self)
        self._bad = set()
        self._tallied = set()
        self._paired = {}

    # -- where to look ------------------------------------------------------

    def default_paths(self, env, home, platform):
        """~/.gemini/antigravity-cli, antigravity and antigravity-ide (under
        %USERPROFILE% on Windows). No environment variable moves them."""
        return [(_paths.join(platform, home, PARENT, name), "default")
                for name in APP_DIRS]

    def _projects(self, app):
        """{conversation id: first workspace path} from the app folder's
        conversation_summaries.db, read-only. {} when there is none."""
        path = os.path.join(app, SUMMARIES)
        out = {}
        if not _file(path):
            return out
        try:
            with open(path, "rb") as fh:
                if fh.read(len(_sqlite.SQLITE_MAGIC)) != _sqlite.SQLITE_MAGIC:
                    return out
            with _sqlite.readonly(path) as conn:
                if conn is None:
                    return out
                for table in _sqlite.tables(conn):
                    cols = _sqlite.columns(conn, table)
                    if "conversation_id" not in cols or "workspace_uris" not in cols:
                        continue
                    n = 0
                    for row in _sqlite.iter_rows(
                            conn, table, ("conversation_id", "workspace_uris")):
                        n += 1
                        if n > _MAX_ROWS:
                            break
                        project = self._first_workspace(row["workspace_uris"])
                        cid = _string(row["conversation_id"])
                        if cid and project:
                            out.setdefault(cid, project)
                    break
        except (OSError, sqlite3.Error, ValueError):
            self.warn(path, "could not read %s" % path)
        return out

    @staticmethod
    def _first_workspace(value):
        if isinstance(value, bytes):
            value = value.decode("utf-8", "surrogateescape")
        try:
            items = json.loads(value) if isinstance(value, str) else value
        except (ValueError, RecursionError):
            return None
        if isinstance(items, str):
            items = [items]
        if isinstance(items, list):
            for item in items:
                path = _uri_path(item)
                if path:
                    return path
        return None

    def stores(self, locations, since_days=None):
        found, seen = [], set()

        def add(path, format, **kw):
            key = os.path.normcase(os.path.abspath(path))
            if key in seen:
                return
            seen.add(key)
            store = self.store(path, format, **kw)
            if store is not None:
                found.append(store)

        for loc in locations:
            projects = None
            for conv in _dirs(os.path.join(loc.path, BRAIN)):
                logs = os.path.join(conv.path, *LOGS)
                full = os.path.join(logs, FULL)
                compact = os.path.join(logs, COMPACT)
                if _file(full):
                    main, side = full, [compact]
                else:
                    main, side = compact, []
                if not _file(main):
                    main = None
                session = conv.name
                if main is not None:
                    if projects is None:
                        projects = self._projects(loc.path)
                    add(main, "jsonl", role="transcript", session=session,
                        project=projects.get(session))
                for path in side:
                    if _file(path):
                        add(path, "jsonl", role="side", unit="compact copy",
                            session=session)
                for parts in CHUNKS:
                    for entry in _entries(os.path.join(logs, *parts)):
                        if entry.name.endswith(".jsonl") and _file(entry.path):
                            add(entry.path, "jsonl", role="side",
                                unit="copy", session=session)
                for step in _dirs(os.path.join(conv.path, *STEPS)):
                    path = os.path.join(step.path, OUTPUT)
                    if _file(path):
                        add(path, "text", role="side", unit="tool output",
                            session=session)
        return base.newest_first(found, since_days)

    # -- reading ------------------------------------------------------------

    def _bad_store(self, store, reason):
        if store.path not in self._bad:
            self._bad.add(store.path)
            self.unreadable_store(reason, store.path)
        self.warn(store.path, "could not read Antigravity %s %s (%s)"
                  % (store.unit, store.path, reason))

    def _records(self, store):
        """(line_no, obj, text): obj is _BAD for a line that is not JSON or
        too long (text is then "" for a too long one). Complete lines that
        fail are counted once per store; a last line with no newline is a
        record still being written."""
        first = store.path not in self._tallied
        self._tallied.add(store.path)
        parsed = bad = 0
        try:
            with open(store.path, "rb") as fh:
                line_no = 0
                while True:
                    raw = fh.readline(MAX_LINE + 1)
                    if not raw:
                        break
                    line_no += 1
                    if len(raw) > MAX_LINE and not raw.endswith(b"\n"):
                        while True:
                            rest = fh.readline(_CHUNK)
                            if not rest or rest.endswith(b"\n"):
                                break
                        bad += 1
                        self.warn((store.path, line_no),
                                  "a line of Antigravity %s %s is too long "
                                  "to read" % (store.unit, store.path))
                        yield line_no, _BAD, ""
                        continue
                    text = _lines.decode_line(raw, first=line_no == 1)
                    if not text.strip():
                        continue
                    try:
                        obj = json.loads(text)
                    except (ValueError, RecursionError):
                        if raw.endswith(b"\n"):
                            bad += 1
                        yield line_no, _BAD, text
                        continue
                    parsed += 1
                    if first and not self._known(obj):
                        self.count("unknown")
                    yield line_no, obj, text
        except OSError as e:
            self._bad_store(store, e.strerror or str(e))
            return
        finally:
            if first:
                self.count("unparsed", bad)
        if bad and not parsed:
            self._bad_store(store, "not JSON Lines")

    @staticmethod
    def _known(obj):
        return (isinstance(obj, dict) and obj.get("type") in TYPES
                and isinstance(obj.get("step_index"), int)
                and not isinstance(obj.get("step_index"), bool))

    @staticmethod
    def _slim(obj):
        keep = ("type", "status", "created_at", "error", "content",
                "tool_calls")
        out = {k: obj[k] for k in keep if k in obj}
        if obj.get("type") == PLANNER:
            out.pop("content", None)
        return out

    def _pair(self, store):
        """([(call, result step index or None)], read cleanly): every call
        in the file in step order, once, with its result paired by
        position. Cached for the run, since tool_calls and secret_texts
        both need it."""
        key = store.path
        if key in self._paired:
            return self._paired[key]
        steps = {}
        marks = {"bad": False}
        for _n, obj, _t in self._records(store):
            if obj is _BAD:
                marks["bad"] = True
                continue
            if not isinstance(obj, dict):
                continue
            index = obj.get("step_index")
            if not isinstance(index, int) or isinstance(index, bool):
                continue
            steps.setdefault(index, self._slim(obj))
        last = max(steps) if steps else -1
        compact = os.path.basename(store.path) == COMPACT
        calls = []
        for k in sorted(steps):
            step = steps[k]
            planned = step.get("tool_calls")
            if step.get("type") != PLANNER or not isinstance(planned, list):
                continue
            results = _results(steps, k, len(planned), last)
            for i, item in enumerate(planned):
                if not isinstance(item, dict):
                    self.count("unknown")
                    continue
                result_at = k + 1 + i
                result = None
                if i < len(results):
                    result_at, result = results[i]
                calls.append((self._call(store, k, i, step, item, result,
                                         result_at, last, marks["bad"],
                                         compact),
                              result_at if result is not None else None))
        self._paired[key] = calls
        return calls

    def _call(self, store, k, i, step, item, result, result_at, last, bad,
              compact):
        name = _string(item.get("name")) or ""
        args = base.decode_input(item.get("args"))
        if compact:
            args = _decode_compact(args)
        kind, known, command, paths, consumed, workdir = _classify(name, args)
        status = None
        output = None
        if result is not None:
            error = _string(result.get("error"))
            content = result.get("content")
            output = content if isinstance(content, str) else error
            if result.get("status") == "INVALID":
                status = DECLINED
            elif (result.get("type") == "ERROR_MESSAGE" and error
                  and error.lower().startswith("denied")):
                status = DECLINED
        elif last > result_at and not bad:
            status = DECLINED
        stamp = _stamps.iso_utc(step.get("created_at"), "iso")
        return ToolCall(
            self.id, store.path, name, args, kind=kind, known=known,
            session=store.session, project=store.project or workdir,
            timestamp=stamp,
            not_after=None if stamp else _stamps.iso_utc(store.mtime, "s"),
            tool_call_id="%s:%d:%d" % (store.session, k, i), status=status,
            command=command, workdir=workdir, paths=paths, consumed=consumed,
            output=output)

    def tool_calls(self, store):
        """Every call in the transcript, in step order, once, each with its
        result's text as output. Side stores hold copies and yield none."""
        if store.role != "transcript":
            return
        for call, _at in self._pair(store):
            yield call

    def secret_texts(self, store):
        """Every line of every file. In a transcript, a result step's
        content is handed over on its own, tied to the call it answers."""
        if store.format == "text":
            for item in self._text_texts(store):
                yield item
            return
        by_result = {}
        if store.role == "transcript":
            by_result = {at: call for call, at in self._pair(store)
                         if at is not None}
        for line_no, obj, text in self._records(store):
            where = "line %d" % line_no
            if obj is _BAD:
                if text:
                    yield SecretText(text, where=where)
                continue
            index = obj.get("step_index") if isinstance(obj, dict) else None
            call = by_result.get(index) if isinstance(index, int) else None
            if call is not None and "content" in obj:
                yield SecretText({k: v for k, v in obj.items()
                                  if k != "content"}, where=where)
                yield SecretText(obj["content"], call=call, where=where)
                continue
            yield SecretText(obj, where=where)

    def _text_texts(self, store):
        try:
            with open(store.path, "rb") as fh:
                for line_no, text in _text_pieces(fh):
                    yield SecretText(text, where="line %d" % line_no)
        except OSError as e:
            self._bad_store(store, e.strerror or str(e))

    # -- masking ------------------------------------------------------------

    def in_use(self, store):
        """True when presence/<conversation>.lock exists in the app data
        folder (see the module notes: its format is unverified)."""
        app = _app_dir(store.path)
        if app is None or not store.session:
            return False
        return os.path.exists(os.path.join(app, PRESENCE,
                                           store.session + ".lock"))
