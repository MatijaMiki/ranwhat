"""Meta Muse Code: Meta's `muse` coding CLI (design section 7.12).

Not Meta Muse, the consumer agent, which keeps everything in Meta's cloud
and leaves nothing on the machine to read.

Muse Code writes one JSON Lines file per session under
$XDG_DATA_HOME/muse (else ~/.local/share/muse, on Windows as well):

    sessions/YYYY/MM/DD/<session uuid>/session.jsonl
    sessions/YYYY/MM/DD/<session uuid>/subagent/<id>/session.jsonl
    .../subagent/<id>/subagent/<id2>/session.jsonl   (nested subagents)

A subagent's log names no workspace (a third party reports; a log that
does have a metadata record with one is taken at its word), so its project
is the nearest enclosing session's.

Every line is an envelope {schema_version, id, stream: {kind, id},
sequence, recorded_at, record_type, durability, causation_id,
payload_type, payload_schema_version, payload}, and recorded_at is in
microseconds since the epoch, or a retained frame that batches envelopes:

    {"retained_frame": "session_permission_transaction",
     "frame_schema_version": 1, "outer_log_ordinal", "transaction_id",
     "children": [{"child_index", "record_json": "<one envelope as JSON>"}],
     "content_sha256"}

A session's first line is such a frame in the 1.4.0 capture (permission
records inside). Each child is read as if it were a line of its own, at the
frame's line number. Three payloads matter here:

- runtime.session.metadata: payload.record.workspace_root is the working
  directory of the session.
- runtime.session with payload.kind "run" and payload.event.kind
  "assistant_tool_calls_committed": event.tool_calls[] = {args, call_id,
  id, name}, args a JSON string.
- runtime.session with event.kind "tool_result_batch_committed":
  event.results[] = {text, tool_call_id, tool_call_index}.

Everything else (text deltas, model_completed, tool_batch.effect.*, user
prompts) yields no call; clean still reads every line. Meta's SDK says these
shapes carry no cross-language stability promise, so a line that is neither
an envelope nor a frame of the one known kind and version is skipped and
counted, never guessed at.

The CLI is closed source. The layout and record shapes are from Meta's blog
and docs and its MIT-licensed SDK schema (meta-models/muse-code-sdk). What
the research could not verify, and how this module copes:

- the key a `bash` call keeps its command under: `command` or `cmd` is
  read; a call with neither stays a shell call with no command, is judged
  for secret literals only, and is counted (notes() says how many);
- the keys inside `write_file` and `edit_file` arguments: watch's own path
  keys only;
- the Windows folder: %USERPROFILE%\\.local\\share\\muse, from a third
  party that checked it on a Windows host, not from Meta; probed, as is
  $XDG_DATA_HOME\\muse when that is set there;
- whether frames ever hold tool calls or results: the capture shows
  permission records only, so every child is read the way a line is;
- how deep subagents nest: up to SUBAGENT_DEPTH levels are read;
- the `.session.lock` content: `pid=<n>` is looked for, and a lock this
  module cannot read a live-or-dead answer from counts as in use.

Never opened: session-index.db (a running muse holds it; design 3.8),
~/.config/muse/settings.json, <repo>/.muse/hooks.json,
<repo>/.agents/memory/MEMORY.md, history checkpoints and the prompt-history
file. `.session.lock` is read only for the in-use check.
"""

from __future__ import annotations

import json
import os
import re
import subprocess

from . import _lines, _paths, _shell, _stamps, base
from .base import SecretText, Source, ToolCall

ENV = "XDG_DATA_HOME"
FOLDER = "muse"                     # under XDG_DATA_HOME or ~/.local/share
SESSIONS = "sessions"
SESSION_FILE = "session.jsonl"
SUBAGENT = "subagent"
LOCK = ".session.lock"

# The one retained frame this module unwraps, and its version.
FRAME = "session_permission_transaction"
FRAME_VERSION = 1

# Subagent logs are read this many subagent/<id> levels deep. Each level is
# one more folder down, so a loop cannot occur without a symlink, and
# symlinked folders are not followed; the bound is a backstop.
SUBAGENT_DEPTH = 8

# payload_type values, and the run event kinds that carry calls.
METADATA = "runtime.session.metadata"
SESSION = "runtime.session"
CALLS = "assistant_tool_calls_committed"
RESULTS = "tool_result_batch_committed"

# Tool names, matched exactly as the spec writes them.
SHELL = "bash"
READ = "read_file"
WRITE = ("write_file", "edit_file")

# Where a bash call may keep its command. Neither is verified; nothing else
# is tried.
COMMAND_KEYS = ("command", "cmd")

# A shell call's own working directory (design 3.5), when its input has one.
WORKDIR_KEYS = ("workdir", "cwd", "dir_path", "directory", "cd", "working_dir")

# watch._PATH_KEYS, mirrored: the sources package never imports watch at
# import time. tests/test_source_muse_code.py pins the two together.
PATH_KEYS = ("file_path", "path", "notebook_path", "filePath", "file",
             "filename", "paths")

_YEAR = re.compile(r"[0-9]{4}\Z")
_TWO = re.compile(r"[0-9]{2}\Z")

# The metadata record is looked for in the first few lines only, each read
# up to _HEAD_MAX bytes (a longer line, a large frame, is passed over), and
# never more than _HEAD_BUDGET bytes in all: a session's project is not
# worth reading a file for.
_HEAD_LINES = 8
_HEAD_MAX = 1 << 16
_HEAD_BUDGET = 1 << 20

# A lock file is a few bytes. Anything past this is not read.
_LOCK_MAX = 4096
_PID = re.compile(rb"\bpid\s*=\s*([0-9]+)")


def _string(value):
    return value if isinstance(value, str) and value else None


def _list(value):
    return value if isinstance(value, list) else []


def _envelope(obj):
    """True for a line shaped like Muse Code's record envelope: an object
    with a payload_type string and a payload object."""
    return (isinstance(obj, dict) and isinstance(obj.get("payload_type"), str)
            and isinstance(obj.get("payload"), dict))


def _whole(value, number):
    """True when value is the integer `number` (and not a bool)."""
    return type(value) is int and value == number


def _frame_children(obj):
    """The children of a retained frame of the one known kind and version,
    in child_index order when every child has a whole-number index (else as
    written), or None when obj is not such a frame."""
    if not (isinstance(obj, dict) and obj.get("retained_frame") == FRAME
            and _whole(obj.get("frame_schema_version"), FRAME_VERSION)
            and isinstance(obj.get("children"), list)):
        return None
    children = obj["children"]
    if all(isinstance(c, dict) and type(c.get("child_index")) is int
           for c in children):
        children = sorted(children, key=lambda c: c["child_index"])
    return children


def _child_record(child):
    """(record, text) for one frame child: its record_json decoded, or
    (None, the string) when that is not JSON, or (None, None) when the
    child has no record_json string."""
    text = child.get("record_json") if isinstance(child, dict) else None
    if not isinstance(text, str):
        return None, None
    try:
        return json.loads(text), None
    except (ValueError, RecursionError):
        return None, text


def _frame_shell(obj):
    """A frame without its children's record_json strings, which are read
    one by one: what is left for clean (ids, ordinal, hash)."""
    return dict(obj, children=[
        {k: v for k, v in c.items() if k != "record_json"}
        if isinstance(c, dict) and isinstance(c.get("record_json"), str) else c
        for c in obj["children"]])


def _records(obj):
    """The records a decoded line holds: a frame's decoded children, else
    the line itself."""
    children = _frame_children(obj)
    if children is None:
        return [obj]
    out = []
    for child in children:
        record, _text = _child_record(child)
        if record is not None:
            out.append(record)
    return out


def _stream_id(record):
    stream = record.get("stream")
    return _string(stream.get("id")) if isinstance(stream, dict) else None


def _workspace_root(record):
    """payload.record.workspace_root of a metadata envelope, or None."""
    if record.get("payload_type") != METADATA:
        return None
    meta = record["payload"].get("record")
    return _string(meta.get("workspace_root")) if isinstance(meta, dict) else None


def _run_event(record):
    """payload.event of a runtime.session "run" envelope, or None."""
    if record.get("payload_type") != SESSION:
        return None
    payload = record["payload"]
    if payload.get("kind") != "run":
        return None
    event = payload.get("event")
    return event if isinstance(event, dict) else None


def _command(args):
    """(command, key) from a bash call's decoded args, or (None, None).
    A list under the key is an argv and is turned back into one command."""
    for key in COMMAND_KEYS:
        value = args.get(key)
        if isinstance(value, str) and value.strip():
            return value, key
        if (isinstance(value, list) and value
                and all(isinstance(w, str) for w in value)):
            command = _shell.argv_to_command(value)
            if command.strip():
                return command, key
    return None, None


def _path_values(args):
    """Every path under watch's path keys, in key order."""
    out = []
    for key in PATH_KEYS:
        value = args.get(key)
        for path in (value if isinstance(value, list) else [value]):
            if isinstance(path, str) and path:
                out.append(path)
    return tuple(out)


def _decoded_args(item):
    """A tool_calls entry with its args string decoded, when that string is
    a JSON object or array, so clean reads each value as the tool got it
    rather than with a second level of escapes. Else the entry itself."""
    if not isinstance(item, dict) or not isinstance(item.get("args"), str):
        return item
    try:
        decoded = json.loads(item["args"])
    except (ValueError, RecursionError):
        return item
    if not isinstance(decoded, (dict, list)):
        return item
    return dict(item, args=decoded)


def _read_project(path):
    """workspace_root from the metadata record near the top of `path`
    (inside a frame or not), or None. Only complete lines are read, a few
    at most; a line longer than _HEAD_MAX is passed over."""
    try:
        with open(path, "rb") as fh:
            budget = _HEAD_BUDGET
            for index in range(1, _HEAD_LINES + 1):
                raw = fh.readline(_HEAD_MAX)
                budget -= len(raw)
                if not raw.endswith(b"\n"):
                    if len(raw) < _HEAD_MAX:
                        return None     # end of file, or a line being written
                    while not raw.endswith(b"\n"):     # pass a long line over
                        if budget <= 0:
                            return None
                        raw = fh.readline(_HEAD_MAX)
                        if not raw:
                            return None
                        budget -= len(raw)
                    continue
                try:
                    obj = json.loads(_lines.decode_line(raw, first=index == 1))
                except (ValueError, RecursionError):
                    continue
                for record in _records(obj):
                    if _envelope(record) and record["payload_type"] == METADATA:
                        return _workspace_root(record)
    except OSError:
        return None
    return None


def _subdirs(folder, match=None, follow=True):
    """(name, path) of the folders directly in `folder` whose names match,
    leaving out dot-folders (and symlinks, unless `follow`). [] when the
    folder cannot be listed."""
    out = []
    try:
        entries = list(os.scandir(folder))
    except OSError:
        return out
    for entry in entries:
        if entry.name.startswith("."):
            continue
        if match is not None and not match.match(entry.name):
            continue
        try:
            if entry.is_dir(follow_symlinks=follow):
                out.append((entry.name, entry.path))
        except OSError:
            continue
    return out


def _is_file(path):
    try:
        return os.path.isfile(path)
    except (OSError, ValueError):
        return False


def _subagent_files(folder, out, depth=1):
    """Add (path, subagent id) for every subagent log under a session
    folder: subagent/<id>/session.jsonl, and the logs of that subagent's
    own subagents, one more subagent/<id> per level, SUBAGENT_DEPTH levels
    at most. Symlinks are not followed, so every log found is inside the
    session folder."""
    if depth > SUBAGENT_DEPTH:
        return
    parent = os.path.join(folder, SUBAGENT)
    subs = _subdirs(parent, follow=False)
    if not subs or os.path.islink(parent):
        return
    for name, sub in subs:
        path = os.path.join(sub, SESSION_FILE)
        if _is_file(path):
            out.append((path, name))
        _subagent_files(sub, out, depth + 1)


def session_files(sessions):
    """(path, session folder name) for every session.jsonl under a
    sessions/ folder: sessions/YYYY/MM/DD/<uuid>/session.jsonl and the
    subagent logs under it (.../<uuid>/subagent/<id>/session.jsonl, nested
    subagents one subagent/<id> deeper per level)."""
    out = []
    for _y, year in _subdirs(sessions, _YEAR):
        for _m, month in _subdirs(year, _TWO):
            for _d, day in _subdirs(month, _TWO):
                for name, folder in _subdirs(day):
                    path = os.path.join(folder, SESSION_FILE)
                    if _is_file(path):
                        out.append((path, name))
                    _subagent_files(folder, out)
    return out


def ancestor_folders(path):
    """The session folders enclosing a subagent's log, nearest first: for
    .../<uuid>/subagent/a/subagent/b/session.jsonl, the folders of a and of
    <uuid>. [] for a session's own log."""
    out = []
    folder = os.path.dirname(path)
    for _ in range(SUBAGENT_DEPTH):
        parent = os.path.dirname(folder)
        if os.path.basename(parent) != SUBAGENT:
            break
        folder = os.path.dirname(parent)
        out.append(folder)
    return out


def lock_folders(path):
    """The folders whose .session.lock says whether `path` is open: its own
    session folder and, for a subagent's log, every enclosing session's."""
    return [os.path.dirname(path)] + ancestor_folders(path)


def _pid_alive(pid):
    """Whether a process with this id is running. Unsure counts as alive:
    a lock file can only make clean more careful."""
    if pid <= 0 or pid > 0xFFFFFFFF:
        return False
    if os.name == "nt":
        return _pid_alive_windows(pid)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True                 # running, as another user
    except (OverflowError, ValueError):
        return False                # not a number any process can have
    except OSError:
        return True
    return True


def _pid_alive_windows(pid):
    """os.kill(pid, 0) would terminate the process on Windows, so ask
    tasklist (as the Copilot CLI adapter does). Unsure counts as alive."""
    try:
        out = subprocess.run(
            ["tasklist", "/FI", "PID eq %d" % pid, "/NH", "/FO", "CSV"],
            capture_output=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return True
    if out.returncode != 0:
        return True
    return ('"%d"' % pid) in out.stdout.decode("ascii", "replace")


class MuseCodeSource(Source):
    id = "muse-code"
    name = "Muse Code"
    unit = "session"
    env = (ENV,)
    path_means = "the muse data folder, the one holding sessions/"
    checked = "1.4.2"

    def reset(self):
        Source.reset(self)
        self._bad = set()           # stores already counted as unreadable
        self._tallied = set()       # stores whose skipped lines are counted
        self._calls_tallied = set()  # stores whose unreadable calls are counted

    # -- where to look ------------------------------------------------------

    def default_paths(self, env, home, platform):
        """$XDG_DATA_HOME/muse, else ~/.local/share/muse. Verified on Linux;
        probed on macOS, which is likely the same. On Windows a third party
        found %USERPROFILE%\\.local\\share\\muse on a Windows host: it is
        probed, and so is %XDG_DATA_HOME%\\muse when that is set, since
        whether muse reads XDG_DATA_HOME there is not known."""
        plat = _paths.platform_name(platform)
        j = _paths.pathmod(plat).join
        default = j(home, ".local", "share", FOLDER)
        moved = env.get(ENV)
        moved = j(moved, FOLDER) if isinstance(moved, str) and moved else None
        if plat == "win32":
            return ([(moved, "env " + ENV)] if moved else []) + [(default, "probed")]
        if moved:
            return [(moved, "env " + ENV)]
        return [(default, "default" if plat == "linux" else "probed")]

    @staticmethod
    def sessions_folders(path):
        """The sessions/ folders a location stands for: the one inside it
        (what --path muse-code= means) and, when it is itself named
        sessions, the location."""
        out = [os.path.join(path, SESSIONS)]
        if os.path.basename(os.path.normpath(path)) == SESSIONS:
            out.append(path)
        return out

    def stores(self, locations, since_days=None):
        found, seen, projects = [], set(), {}

        def project_of(path):
            key = os.path.normcase(os.path.abspath(path))
            if key not in projects:
                projects[key] = _read_project(path)
            return projects[key]

        for loc in locations:
            for sessions in self.sessions_folders(loc.path):
                for path, session in session_files(sessions):
                    key = os.path.normcase(os.path.abspath(path))
                    if key in seen:
                        continue
                    seen.add(key)
                    # A subagent's log is reported to name no workspace;
                    # then the nearest enclosing session's is its project.
                    project = project_of(path)
                    for folder in ancestor_folders(path):
                        if project is not None:
                            break
                        project = project_of(os.path.join(folder, SESSION_FILE))
                    store = self.store(path, "jsonl", role="transcript",
                                       session=session, project=project)
                    if store is not None:
                        found.append(store)
        return base.newest_first(found, since_days)

    def notes(self, locations=None, platform=None):
        """Lines for `ranwhat sources` and the reports: shell calls this run
        could not read. (locations and platform are taken as every adapter's
        notes() takes them; nothing here depends on them now that the
        Windows folder is probed.)"""
        out = []
        n = self.counts.get("unreadable_calls", 0)
        if n == 1:
            out.append("1 Muse Code shell call could not be read: its "
                       "argument names are not documented yet.")
        elif n:
            out.append("%d Muse Code shell calls could not be read: their "
                       "argument names are not documented yet." % n)
        return out

    # -- reading ------------------------------------------------------------

    def _bad_store(self, store, reason):
        if store.path not in self._bad:
            self._bad.add(store.path)
            self.unreadable_store(reason)
        self.warn(store.path, "could not read Muse Code %s %s (%s)"
                  % (store.unit, store.path, reason))

    @staticmethod
    def _first(store, tallied):
        """True the first time a store is read this run: watch and clean
        both read it, and what it skipped is counted once."""
        first = store.path not in tallied
        tallied.add(store.path)
        return first

    def _lines(self, store, raw_text=False):
        """(line_no, obj, text) for every record of a transcript: obj is a
        decoded line, or a record decoded from a frame child (given the
        frame's line number); or obj is None for a complete line, or a
        child's record_json, that is not JSON, whose text is then given when
        raw_text is set. With raw_text, a frame also yields itself without
        its children's record_json (clean reads it all the same). Lines and
        children that do not parse, and records that are not envelopes, are
        counted once per run; a frame of the known kind is not. A store
        with lines but no JSON warns once; a store that cannot be opened
        warns once and yields nothing. A last line still being written is
        skipped quietly."""
        tally = self._first(store, self._tallied)
        parsed = unparsed = 0
        try:
            with open(store.path, "rb") as fh:
                for index, raw in enumerate(fh, 1):
                    text = _lines.decode_line(raw, first=index == 1)
                    if not text.strip():
                        continue
                    try:
                        obj = json.loads(text)
                    except (ValueError, RecursionError):
                        if not raw.endswith(b"\n"):
                            continue        # still being written
                        unparsed += 1
                        if raw_text:
                            yield index, None, text
                        continue
                    parsed += 1
                    children = _frame_children(obj)
                    if children is None:
                        if tally and not _envelope(obj):
                            self.count("unknown")
                        yield index, obj, None
                        continue
                    if raw_text:
                        yield index, _frame_shell(obj), None
                    for child in children:
                        record, bad = _child_record(child)
                        if record is None:
                            if bad is not None:
                                unparsed += 1
                                if raw_text:
                                    yield index, None, bad
                            elif tally:
                                self.count("unknown")   # left in the shell
                            continue
                        if tally and not _envelope(record):
                            self.count("unknown")
                        yield index, record, None
        except OSError as e:
            self._bad_store(store, e.strerror or str(e))
            return
        finally:
            if tally:
                self.count("unparsed", unparsed)
        if not parsed and unparsed:
            self._bad_store(store, "not JSON Lines")

    def _call(self, store, item, record, project):
        """The ToolCall for one tool_calls entry, or None when the entry has
        no name (a shape the spec does not describe)."""
        name = item.get("name") if isinstance(item, dict) else None
        if not isinstance(name, str) or not name:
            return None
        tool_input = base.decode_input(item.get("args"))
        kind, known = "other", False
        command = workdir = None
        paths, consumed = (), ()
        if name == SHELL:
            kind, known = "shell", True
            command, key = _command(tool_input)
            if command is not None:
                consumed = (key,)
                for wkey in WORKDIR_KEYS:
                    workdir = _string(tool_input.get(wkey))
                    if workdir:
                        break
        elif name == READ:
            kind, known = "read", True
            path = _string(tool_input.get("path"))
            if path:
                paths, consumed = (path,), ("path",)
        elif name in WRITE:
            kind, known = "write", True
            paths = _path_values(tool_input)
        timestamp = _stamps.iso_utc(record.get("recorded_at"), "us")
        not_after = None
        if timestamp is None:
            not_after = _stamps.iso_utc(store.mtime, "s")
        return ToolCall(
            self.id, store.path, name, tool_input, kind=kind, known=known,
            session=_stream_id(record) or store.session, project=project,
            timestamp=timestamp, tool_call_id=_string(item.get("call_id")),
            not_after=not_after, command=command, workdir=workdir,
            paths=paths, consumed=consumed)

    @staticmethod
    def shell_unread(call):
        """True for a bash call whose command this adapter could not find."""
        return call.kind == "shell" and call.known and call.command is None

    def tool_calls(self, store):
        """Every committed tool call, once per call_id (the first copy),
        with the text of its result as output when the file holds one.

        A call is yielded when its result arrives, and calls still waiting
        for one at the end of the file are yielded then, so a long session
        is not held in memory whole."""
        if store.role != "transcript":
            return
        tally = self._first(store, self._calls_tallied)
        project = store.project
        pending = {}            # call_id -> ToolCall waiting for its result
        done = set()            # call_ids already yielded

        def counted(call):
            if tally and self.shell_unread(call):
                self.count("unreadable_calls")
            return call

        for _line_no, obj, _text in self._lines(store):
            if not _envelope(obj):
                continue
            project = _workspace_root(obj) or project
            event = _run_event(obj)
            if event is None:
                continue
            kind = event.get("kind")
            if kind == CALLS:
                for item in _list(event.get("tool_calls")):
                    call = self._call(store, item, obj, project)
                    if call is None:
                        if tally:
                            self.count("unknown")
                        continue
                    cid = call.tool_call_id
                    if cid is None:
                        yield counted(call)     # nothing to pair it with
                    elif cid not in done and cid not in pending:
                        pending[cid] = call
            elif kind == RESULTS:
                for res in _list(event.get("results")):
                    cid = res.get("tool_call_id") if isinstance(res, dict) else None
                    call = pending.pop(cid, None) if isinstance(cid, str) else None
                    if call is None:
                        continue
                    text = res.get("text")
                    call.output = text if isinstance(text, str) else None
                    done.add(cid)
                    yield counted(call)
        for call in pending.values():
            yield counted(call)

    def secret_texts(self, store):
        """Every line, whatever its type, and every record inside a frame.
        Call arguments are handed over decoded, and each result's text on
        its own, tied to the call whose call_id it answers (wherever the
        call and the result sit, in a frame or not)."""
        if store.role != "transcript":
            return
        project = store.project
        calls = {}              # call_id -> ToolCall, first copy
        for line_no, obj, text in self._lines(store, raw_text=True):
            where = "line %d" % line_no
            if obj is None:
                yield SecretText(text, where=where)
                continue
            if not _envelope(obj):
                yield SecretText(obj, where=where)
                continue
            project = _workspace_root(obj) or project
            event = _run_event(obj)
            kind = event.get("kind") if event is not None else None
            if kind == CALLS:
                for item in _list(event.get("tool_calls")):
                    call = self._call(store, item, obj, project)
                    cid = call.tool_call_id if call is not None else None
                    if cid is not None and cid not in calls:
                        calls[cid] = call
                tool_calls = event.get("tool_calls")
                if isinstance(tool_calls, list):
                    yield SecretText(self._with_event(obj, dict(
                        event, tool_calls=[_decoded_args(i) for i in tool_calls])),
                        where=where)
                    continue
            elif kind == RESULTS and isinstance(event.get("results"), list):
                results = event["results"]
                # The line without its results' text, then each result's
                # text with the call it answers.
                yield SecretText(self._with_event(obj, dict(event, results=[
                    {k: v for k, v in r.items() if k != "text"}
                    if isinstance(r, dict) else r for r in results])),
                    where=where)
                for res in results:
                    if not isinstance(res, dict) or "text" not in res:
                        continue
                    cid = res.get("tool_call_id")
                    call = calls.get(cid) if isinstance(cid, str) else None
                    yield SecretText(res["text"], call=call, where=where)
                continue
            yield SecretText(obj, where=where)

    @staticmethod
    def _with_event(record, event):
        """A copy of a run envelope with its payload.event replaced."""
        return dict(record, payload=dict(record["payload"], event=event))

    # -- masking ------------------------------------------------------------

    def in_use(self, store):
        """True when a .session.lock in the store's session folder (or, for
        a subagent, any enclosing session's) names a live process. A lock that
        cannot be read, or holds no pid=<n>, counts as in use: it can only
        make clean more careful. The 120-second rule applies as well."""
        for folder in lock_folders(store.path):
            lock = os.path.join(folder, LOCK)
            try:
                with open(lock, "rb") as fh:
                    data = fh.read(_LOCK_MAX)
            except (FileNotFoundError, NotADirectoryError):
                continue
            except OSError:
                return True
            m = _PID.search(data)
            if m is None or _pid_alive(int(m.group(1))):
                return True
        return False
