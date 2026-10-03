"""GitHub Copilot CLI: the session-state event logs under COPILOT_HOME.

The same store is written by the Copilot CLI, the GitHub Copilot desktop
app and VS Code's Copilot CLI harness, so one adapter covers all three.
Checked against Copilot CLI 1.0.90. The CLI is closed source; the event
schema is GitHub's open-source copilot-sdk (session-events.ts).

Stores:

- <root>/session-state/<sessionId>/events.jsonl: the event log, one JSON
  record per line (transcript). Lines can hold raw U+2028, so lines are
  split on "\\n" only.
- a large tool output the CLI saved to its own file, found only where a
  result says "Saved to: <path>" and only when the file's base name is
  <digits>-copilot-tool-output-<id>.txt (side, text). It is never looked
  for anywhere else, and that path is looked up only when, as a string,
  it lies inside the OS temp folder or the session-state folder holding
  the log (a session file system saves it in session-state/temp), so a
  result never makes ranwhat touch a network share.

Never opened: session-store.db (the CLI's own index, rebuilt from
session-state by /chronicle reindex), workspace.yaml, plan.md,
checkpoints/, files/, logs/, command-history-state/. Entries in
history-session-state/ (the layout before 0.0.342, format unverified) are
counted as not read.
"""

from __future__ import annotations

import json
import os
import re
import stat
import subprocess
import tempfile

from . import _lines, _paths, _stamps
from .base import SecretText, Source, ToolCall, decode_input, newest_first

SESSIONS = "session-state"
EVENTS = "events.jsonl"
LEGACY = "history-session-state"

# Events that name the session's working directory. session.start and
# session.resume hold it at data.context.cwd (StartData.context,
# ResumeData.context). session.context_changed, written after /cd or /cwd,
# carries the context itself as its data, so its directory is data.cwd
# (copilot-sdk session-events.ts: ContextChangedEvent.data is a
# WorkingDirectoryContext, whose cwd is at its top level). The schema says
# a change is sent first with pendingGitContext true, before the git
# context is resolved, and then again settled. Both carry the new cwd, so
# both are read: skipping the first would credit a call logged between the
# two to the old folder, and lose the change in a log that ends before the
# settled event.
CONTEXT_EVENTS = ("session.start", "session.resume")
CONTEXT_CHANGED = "session.context_changed"
CWD_EVENTS = CONTEXT_EVENTS + (CONTEXT_CHANGED,)

# Tool names from the spec, matched exactly.
SHELL_TOOLS = ("bash", "powershell")
TOOL_KINDS = {
    "bash": "shell", "powershell": "shell",
    "view": "read",
    "create": "write", "edit": "write", "apply_patch": "write",
    "web_fetch": "fetch",
}
# Input sent to a shell that is already running: the process may be a REPL
# as easily as a shell, so these are not shell calls (design 3.5).
for _verb in ("read", "write", "stop", "list"):
    for _shell in SHELL_TOOLS:
        TOOL_KINDS["%s_%s" % (_verb, _shell)] = "other"
for _name in ("grep", "glob", "task", "skill", "sql", "ask_user",
              "report_intent"):
    TOOL_KINDS[_name] = "other"
del _verb, _shell, _name

# A shell call's own working directory, when its input carries one (3.5).
WORKDIR_KEYS = ("workdir", "cwd", "dir_path", "directory", "cd", "working_dir")

# Where a large output went: "... Saved to: <path>" up to the end of the
# line. The file name is <epoch ms>-copilot-tool-output-<id>.txt, for
# example 1774637043987-copilot-tool-output-tk7puw.txt (copilot-sdk's test
# harness matches it as \d+-copilot-tool-output-[a-z0-9.]+). Upper-case
# letters in the id are let through as well. The whole base name must have
# that form, and the pattern is checked with fullmatch: it has no part that
# can match the marker, so a line that repeats the marker costs one pass.
SAVED_TO = re.compile(r"Saved to:[ \t]*([^\r\n]+)")
SIDE_NAME = re.compile(r"[0-9]+-copilot-tool-output-[A-Za-z0-9.]+\.txt")
SIDE_MARK = b"-copilot-tool-output-"
SAVED_MARK = b"Saved to:"

# inuse.<pid>.lock in a session folder while a process has it open.
LOCK = re.compile(r"inuse\.([0-9]+)\.lock\Z")

# A side file this size or smaller is searched as one string. A larger one
# is searched in pieces of at most SIDE_PIECE bytes (so at most SIDE_PIECE
# characters, well under clean.MAX_STRING), cut at a line end when there is
# one in the piece's second half and else between two UTF-8 characters, so
# a file that is one long line (minified JSON) is cut too. Each piece after
# the first starts at least SIDE_OVERLAP bytes before the one before it
# ended, so a secret up to SIDE_OVERLAP long lies whole in some piece. No
# finite overlap covers every pattern clean has (a few are unbounded), but
# real credentials are far shorter: a 4096-bit RSA private key in PEM is
# about 3.2 KB.
SIDE_WHOLE = 900000
SIDE_PIECE = 512 * 1024
SIDE_OVERLAP = 64 * 1024

_CHUNK = 1 << 20
_HEAD_LIMIT = 1 << 20


def _cwd(etype, data):
    """The working directory an event of type `etype` names, or None:
    data.context.cwd for session.start and session.resume, data.cwd for
    session.context_changed. No other key is tried."""
    if not isinstance(data, dict):
        return None
    if etype == CONTEXT_CHANGED:
        cwd = data.get("cwd")
    elif etype in CONTEXT_EVENTS:
        context = data.get("context")
        cwd = context.get("cwd") if isinstance(context, dict) else None
    else:
        return None
    return cwd if isinstance(cwd, str) and cwd else None


def _call_id(value):
    return value if isinstance(value, str) and value else None


def _output(data):
    """The stored output of a tool.execution_complete: result.content,
    result.detailedContent, and the text and outputPreview of each
    result.contents block, each distinct piece once, in that order."""
    result = data.get("result") if isinstance(data, dict) else None
    if not isinstance(result, dict):
        return None
    pieces = [result.get("content"), result.get("detailedContent")]
    contents = result.get("contents")
    if isinstance(contents, list):
        for block in contents:
            if isinstance(block, dict):
                pieces.append(block.get("text"))
                pieces.append(block.get("outputPreview"))
    out, seen = [], set()
    for piece in pieces:
        if isinstance(piece, str) and piece and piece not in seen:
            seen.add(piece)
            out.append(piece)
    return "\n".join(out) if out else None


def _without_output(call):
    """A copy of the call with no output."""
    return ToolCall(call.source, call.store, call.tool_name, call.tool_input,
                    kind=call.kind, known=call.known, session=call.session,
                    project=call.project, timestamp=call.timestamp,
                    tool_call_id=call.tool_call_id, actor=call.actor,
                    status=call.status, not_after=call.not_after,
                    command=call.command, workdir=call.workdir,
                    paths=call.paths, consumed=call.consumed)


def _basename(path):
    """The last part of a path written with either separator."""
    return re.split(r"[\\/]", path)[-1]


def saved_paths(text):
    """The large-output files a result names as "Saved to: <path>", when
    the base name is a Copilot tool-output file. Any other path is not
    followed."""
    if not isinstance(text, str) or "Saved to:" not in text:
        return []
    out, seen = [], set()
    for m in SAVED_TO.finditer(text):
        path = m.group(1).strip()
        if path and path not in seen and SIDE_NAME.fullmatch(_basename(path)):
            seen.add(path)
            out.append(path)
    return out


def _mentions(path, marker):
    """True when the file's bytes contain `marker`. Read in pieces, so a
    large log costs one pass and little memory."""
    keep = len(marker) - 1
    tail = b""
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(_CHUNK)
            if not chunk:
                return False
            if marker in tail + chunk:
                return True
            tail = chunk[-keep:]


def _char_start(data, at):
    """`at`, moved back past at most three UTF-8 continuation bytes, so a
    cut there does not split a character."""
    for _ in range(3):
        if 0 < at < len(data) and 0x80 <= data[at] <= 0xBF:
            at -= 1
    return at


def side_pieces(fh):
    """Yield (bytes, first line, last line) for a file opened "rb", in
    pieces of at most SIDE_PIECE bytes that together cover all of it.

    A piece ends just after the last line end in its second half, or, when
    there is none (a line longer than half a piece), between two UTF-8
    characters at SIDE_PIECE. The next piece starts at least SIDE_OVERLAP
    bytes before that end: at the start of a line in the SIDE_OVERLAP bytes
    before that point when there is one, else between two characters right
    there. So pieces overlap by SIDE_OVERLAP to 2 * SIDE_OVERLAP bytes, and
    a secret no longer than SIDE_OVERLAP is never cut in two."""
    buf = b""
    line = 1                # the line buf[0] is on
    eof = False
    while True:
        while not eof and len(buf) <= SIDE_PIECE:
            more = fh.read(SIDE_PIECE + 1 - len(buf))
            if more:
                buf += more
            else:
                eof = True
        if not buf:
            return
        if len(buf) <= SIDE_PIECE:          # the rest of the file
            yield buf, line, line + buf.count(b"\n", 0, len(buf) - 1)
            return
        end = buf.rfind(b"\n", SIDE_PIECE // 2, SIDE_PIECE) + 1
        if end <= 0:
            end = _char_start(buf, SIDE_PIECE)
        yield buf[:end], line, line + buf.count(b"\n", 0, end - 1)
        floor = end - SIDE_OVERLAP
        start = buf.rfind(b"\n", floor - SIDE_OVERLAP, floor) + 1
        if start <= 0:
            start = _char_start(buf, floor)
        line += buf.count(b"\n", 0, start)
        buf = buf[start:]


def _inside(path, folders):
    """`path`, absolute, made normal when it lies inside one of `folders`.
    Else None. Compared as strings, nothing looked up: a path in a result
    can name a network share (\\\\host\\share), and on Windows only looking
    it up sends the user's credentials to that host. What is looked up
    after is the normal form, the one that was checked."""
    if not os.path.isabs(path):
        return None
    path = os.path.abspath(path)
    for folder in folders:
        root = os.path.join(os.path.normcase(os.path.abspath(folder)), "")
        if os.path.normcase(path).startswith(root):
            return path
    return None


def _regular_file(path):
    """True for a regular file that is not a symlink."""
    try:
        return stat.S_ISREG(os.lstat(path).st_mode)
    except (OSError, ValueError):
        return False


def _pid_alive(pid):
    """Whether a process with this id is running. Unsure counts as alive:
    a lock file can only make clean more careful."""
    if pid <= 0:
        return False
    if os.name == "nt":
        # os.kill(pid, 0) would terminate the process on Windows.
        try:
            out = subprocess.run(
                ["tasklist", "/FI", "PID eq %d" % pid, "/NH", "/FO", "CSV"],
                capture_output=True, timeout=10)
        except (OSError, subprocess.SubprocessError):
            return True
        if out.returncode != 0:
            return True
        return ('"%d"' % pid) in out.stdout.decode("ascii", "replace")
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


class CopilotCliSource(Source):
    id = "copilot-cli"
    name = "GitHub Copilot CLI"
    unit = "session"
    env = ("COPILOT_HOME",)
    path_means = "a COPILOT_HOME folder (the one holding session-state)"
    checked = "1.0.90"

    # For the report after masking a Copilot session.
    mask_note = ("Copilot syncs sessions to your GitHub account by default; "
                 "the copy there is unchanged. Run /chronicle reindex so "
                 "Copilot's local search index is rebuilt from the masked "
                 "session.")
    legacy_reason = ("in history-session-state, the layout before Copilot "
                     "CLI 0.0.342, which is not read")

    def reset(self):
        Source.reset(self)
        self._legacy_seen = set()
        self._owners = {}       # side file -> (transcript Store, toolCallId)
        self._wanted = {}       # transcript path -> {toolCallId of its sides}
        self._owner_calls = {}  # transcript path -> {toolCallId: ToolCall}

    # -- where to look ------------------------------------------------------

    def default_paths(self, env, home, platform):
        moved = env.get("COPILOT_HOME")
        if isinstance(moved, str) and moved:
            return [(moved, "env COPILOT_HOME")]
        return [(_paths.join(platform, home, ".copilot"), "default")]

    def stores(self, locations, since_days=None):
        transcripts = []
        for loc in locations:
            self._count_legacy(loc.path)
            try:
                entries = sorted(os.scandir(os.path.join(loc.path, SESSIONS)),
                                 key=lambda e: e.name)
            except OSError:
                continue
            for entry in entries:
                try:
                    if not entry.is_dir():
                        continue
                except OSError:
                    continue
                path = os.path.join(entry.path, EVENTS)
                if not os.path.isfile(path):
                    continue
                store = self.store(path, "jsonl", role="transcript",
                                   session=entry.name,
                                   project=self._head_project(path))
                if store:
                    transcripts.append(store)
        transcripts = newest_first(transcripts, since_days)
        sides, seen = [], set()
        for owner in transcripts:
            for path, call_id in self._saved_files(owner.path):
                key = os.path.normcase(os.path.abspath(path))
                if key in seen:
                    continue
                seen.add(key)
                store = self.store(path, "text", role="side",
                                   session=owner.session, project=owner.project)
                if store:
                    sides.append(store)
                    self._owners[key] = (owner, call_id)
                    wanted = self._wanted.setdefault(owner.path, set())
                    if call_id and call_id not in wanted:
                        wanted.add(call_id)
                        # Read the log again for the calls, with this one.
                        self._owner_calls.pop(owner.path, None)
        return newest_first(transcripts + sides, since_days)

    def _count_legacy(self, root):
        """Count each entry of history-session-state once per run: its
        format is unverified, so it is reported as not read."""
        folder = os.path.join(root, LEGACY)
        try:
            names = os.listdir(folder)
        except OSError:
            return
        for name in names:
            key = os.path.normcase(os.path.join(folder, name))
            if key not in self._legacy_seen:
                self._legacy_seen.add(key)
                self.unreadable_store(self.legacy_reason)

    @staticmethod
    def _head_project(path):
        """The working directory the first record names, read from the
        first line only; None when it names none."""
        try:
            with open(path, "rb") as fh:
                raw = fh.readline(_HEAD_LIMIT)
        except OSError:
            return None
        try:
            obj = json.loads(_lines.decode_line(raw, first=True))
        except (ValueError, RecursionError):
            return None
        if isinstance(obj, dict):
            return _cwd(obj.get("type"), obj.get("data"))
        return None

    @staticmethod
    def _saved_files(path):
        """[(path, toolCallId)] for each large-output file a result in
        this log names, when it is a regular file on disk inside the OS
        temp folder or the session-state folder holding the log."""
        found = []
        folders = (tempfile.gettempdir(),
                   os.path.dirname(os.path.dirname(path)))
        try:
            if not _mentions(path, SIDE_MARK):
                return found
            with open(path, "rb") as fh:
                for index, raw in enumerate(fh, 1):
                    if SAVED_MARK not in raw or SIDE_MARK not in raw:
                        continue
                    try:
                        obj = json.loads(_lines.decode_line(raw, index == 1))
                    except (ValueError, RecursionError):
                        continue
                    if (not isinstance(obj, dict)
                            or obj.get("type") != "tool.execution_complete"
                            or not isinstance(obj.get("data"), dict)):
                        continue
                    data = obj["data"]
                    for side in saved_paths(_output(data)):
                        side = _inside(side, folders)
                        if side is not None and _regular_file(side):
                            found.append((side, _call_id(data.get("toolCallId"))))
        except OSError:
            return found
        return found

    # -- what is in a store -------------------------------------------------

    def tool_calls(self, store):
        if store.role != "transcript":
            return
        for kind, item in self._scan(store, texts=False, counting=True):
            if kind == "call":
                yield item

    def secret_texts(self, store):
        if store.role == "side":
            for item in self._side_texts(store):
                yield item
            return
        for kind, item in self._scan(store, texts=True, counting=False):
            if kind == "text":
                yield item

    def _cannot_read(self, store, reason, detail):
        if store.path not in self._warned:
            self.unreadable_store(reason)
        self.warn(store.path, "cannot read %s (%s)" % (store.path, detail))

    def _call(self, store, name, arguments, mcp, call_id, stamp, project,
              counting):
        """A ToolCall for one tool use, from tool.execution_start or from a
        toolRequests entry."""
        args = decode_input(arguments)
        name = name if isinstance(name, str) else ""
        not_after = None
        if stamp is None:
            not_after = _stamps.iso_utc(store.mtime, "s")
        common = dict(session=store.session, project=project,
                      timestamp=stamp, tool_call_id=call_id,
                      not_after=not_after)
        kind = TOOL_KINDS.get(name)
        if kind is None or (isinstance(mcp, str) and mcp):
            return ToolCall(self.id, store.path, name, args, kind="other",
                            known=False, **common)
        command, paths, consumed, workdir = None, (), (), None
        if kind == "shell":
            text = args.get("command")
            if isinstance(text, str) and text:
                command, consumed = text, ("command",)
            elif counting:
                self.count("unreadable_calls")
            for key in WORKDIR_KEYS:
                if isinstance(args.get(key), str) and args[key]:
                    workdir = args[key]
                    break
        elif kind in ("read", "write") and name != "apply_patch":
            target = args.get("path")
            if isinstance(target, str) and target:
                paths = (target,)
                if kind == "read":
                    consumed = ("path",)
        return ToolCall(self.id, store.path, name, args, kind=kind,
                        known=True, command=command, workdir=workdir,
                        paths=paths, consumed=consumed, **common)

    def _scan(self, store, texts, counting):
        """One pass over an event log. Yields ("call", ToolCall) for each
        distinct call, once, and with texts=True ("text", SecretText) for
        every line. A call is yielded when its tool.execution_complete is
        read (with its output), or at the end of the file when it never
        completed; a toolRequests entry with no execution_start is yielded
        at the end of the file."""
        session_project = None
        requests = {}       # toolCallId -> (request, stamp, project)
        started = {}        # toolCallId -> ToolCall waiting for its output
        finished = {}       # toolCallId -> the call, for repeated results
        records = bad = 0
        try:
            fh = open(store.path, "rb")
        except OSError as e:
            self._cannot_read(store, "could not be opened", e)
            return
        with fh:
            try:
                for index, raw in enumerate(fh, 1):
                    text = _lines.decode_line(raw, first=index == 1)
                    if not text.strip():
                        continue
                    where = "line %d" % index
                    try:
                        obj = json.loads(text)
                    except (ValueError, RecursionError):
                        if raw.endswith(b"\n"):
                            bad += 1
                            if counting:
                                self.count("unparsed")
                        if texts:
                            yield "text", SecretText(text, where=where)
                        continue
                    if not isinstance(obj, dict) or not isinstance(
                            obj.get("type"), str):
                        if counting:
                            self.count("unknown")
                        if texts:
                            yield "text", SecretText(obj, where=where)
                        continue
                    records += 1
                    etype = obj["type"]
                    data = obj.get("data")
                    data = data if isinstance(data, dict) else {}
                    stamp = _stamps.iso_utc(obj.get("timestamp"), "iso")
                    owner = None
                    if etype in CWD_EVENTS:
                        session_project = _cwd(etype, data) or session_project
                    elif etype == "assistant.message":
                        wanted = data.get("toolRequests")
                        for req in wanted if isinstance(wanted, list) else ():
                            if not isinstance(req, dict):
                                continue
                            cid = _call_id(req.get("toolCallId"))
                            if (cid and cid not in requests
                                    and cid not in started
                                    and cid not in finished):
                                requests[cid] = (req, stamp, session_project)
                    elif etype == "tool.execution_start":
                        cid = _call_id(data.get("toolCallId"))
                        if cid is None or (cid not in started
                                           and cid not in finished):
                            call = self._call(
                                store, data.get("toolName"),
                                data.get("arguments"),
                                data.get("mcpServerName"), cid, stamp,
                                session_project, counting)
                            if cid is None:
                                yield "call", call      # cannot be matched
                            else:
                                requests.pop(cid, None)
                                started[cid] = call
                    elif etype == "tool.execution_complete":
                        cid = _call_id(data.get("toolCallId"))
                        if cid in finished:
                            owner = finished[cid]   # a repeated result
                        elif cid:
                            owner = started.pop(cid, None)
                            if owner is None and cid in requests:
                                req, rstamp, rproject = requests.pop(cid)
                                owner = self._call(
                                    store, req.get("name"),
                                    req.get("arguments"),
                                    req.get("mcpServerName"), cid, rstamp,
                                    rproject, counting)
                            if owner is not None:
                                owner.output = _output(data)
                                # Only the input is kept for a repeat: the
                                # outputs of a whole log need not stay in
                                # memory.
                                finished[cid] = (_without_output(owner)
                                                 if texts else None)
                                yield "call", owner
                    if texts:
                        yield "text", SecretText(obj, call=owner, where=where)
            except OSError as e:
                self._cannot_read(store, "could not be read", e)
                return
        for call in started.values():
            yield "call", call
        for cid, (req, rstamp, rproject) in requests.items():
            yield "call", self._call(store, req.get("name"),
                                     req.get("arguments"),
                                     req.get("mcpServerName"), cid, rstamp,
                                     rproject, counting)
        if bad and not records:
            self._cannot_read(store, "not a Copilot session log",
                              "not a Copilot session log")

    def _side_texts(self, store):
        """A saved large output: the whole file as one string, or, when it
        is large, overlapping pieces of at most SIDE_PIECE bytes (see
        side_pieces). Credited to the call whose result named it, when that
        call is known."""
        call = self._owner_call(store)
        try:
            with open(store.path, "rb") as fh:
                data = fh.read(SIDE_WHOLE + 1)
                if len(data) <= SIDE_WHOLE:
                    if data:
                        yield SecretText(
                            data.decode("utf-8", "surrogateescape"),
                            call=call, where="whole file")
                    return
                fh.seek(0)
                for piece, first, last in side_pieces(fh):
                    yield SecretText(piece.decode("utf-8", "surrogateescape"),
                                     call=call,
                                     where="lines %d-%d" % (first, last))
        except OSError as e:
            self._cannot_read(store, "could not be read", e)

    def _owner_call(self, store):
        """The call whose result named this side file; None when not known.
        A session log is read once per run for every side file it names,
        not once for each: the calls those files need are kept, without
        their output."""
        key = os.path.normcase(os.path.abspath(store.path))
        owner, call_id = self._owners.get(key, (None, None))
        if owner is None or call_id is None:
            return None
        calls = self._owner_calls.get(owner.path)
        if calls is None:
            wanted = self._wanted.get(owner.path, ())
            calls = {}
            for kind, item in self._scan(owner, texts=False, counting=False):
                if (kind == "call" and item.tool_call_id in wanted
                        and item.tool_call_id not in calls):
                    calls[item.tool_call_id] = _without_output(item)
            self._owner_calls[owner.path] = calls
        return calls.get(call_id)

    # -- masking ------------------------------------------------------------

    def in_use(self, store):
        """A session folder holding inuse.<pid>.lock for a live process is
        open in Copilot. (The lock file is reported by third parties only;
        honouring it can only make clean more careful.)"""
        if store.role != "transcript":
            return False
        try:
            names = os.listdir(os.path.dirname(store.path))
        except OSError:
            return False
        for name in names:
            m = LOCK.match(name)
            if m and _pid_alive(int(m.group(1))):
                return True
        return False
