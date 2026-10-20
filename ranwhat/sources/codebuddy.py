"""Tencent CodeBuddy Code: the `codebuddy` / `cbc` CLI (npm
@tencent-ai/codebuddy-code).

CodeBuddy Code keeps one JSON Lines file per session under its home folder:
<home>/projects/<enc>/<sessionId>.jsonl for a main session and
<home>/projects/<enc>/<parentSessionId>/subagents/agent-<id>.jsonl for a
subagent. <home> is $CODEBUDDY_CONFIG_DIR when that is set and not blank,
else ~/.codebuddy (%USERPROFILE%\\.codebuddy on Windows; there is no XDG,
APPDATA or Library variant). <enc> is the working directory, realpath'd,
with "/", "\\" and ":" turned into "-", leading and trailing dashes cut and
runs of dashes collapsed ("/home/alice/app" is home-alice-app); a name over
255 UTF-8 bytes is cut to 180 bytes plus "-" plus a djb2 hash in base 36.
The mapping is lossy, so it is never decoded: every record carries its own
cwd. Before 2.140.0 the folder was named from the path as typed, so old
sessions sit in symlink-path folders; reading every folder under projects/
covers both.

Each line is one item in the @openai/agents-core "AgentInputItem" shape, not
Claude Code's message/tool_use shape. Every item has id, timestamp (epoch
milliseconds, a number; lines written before 2.121.0 may have none), type,
optional parentId / logicalParentId, and cwd (on every type but summary and
topic). Types read here:
- function_call: {callId, name, arguments, status}. `arguments` is a JSON
  string (a dict is taken too).
- function_call_result: {callId, name, status, output, providerData}.
  output is {type: "text", text}, a string, or a list of such parts;
  function_call_output, the name the ACP bridge also checks for, is read the
  same way. A Bash result's text is "Command: ..\\nStdout: ..\\nStderr: ..\\n
  Exit Code: N\\nSignal: ..".
- message (role user, assistant or system), reasoning, summary, topic,
  ai-title, session-meta, file-history-snapshot: no call. Anything else is
  counted as unknown.
A user message whose text is <bash-input>cmd</bash-input> is a command the
user ran with "!"; the output follows in a message holding <bash-stdout> and
<bash-stderr>. Those are the user's own shell calls (actor "user").

Tool names (the bundle's tool enum): Bash and PowerShell run a command
(arguments.command); Read, Write, Edit and MultiEdit take arguments.file_path
and NotebookEdit takes notebook_path (all from the tools' schemas in the
2.170.0 bundle); WebFetch takes url and WebSearch query; LS, Glob, Grep,
BashOutput, KillShell, TodoWrite, Agent and the like are known and "other".
mcp__<server>__<tool> and any other name is unknown, so watch judges it by
name. NotebookRead and LS are not given paths: their argument names were not
verified.

DeferExecuteTool is the wrapper through which a deferred tool is called when
deferred tool loading is on: arguments {toolName, params}. It is unwrapped,
so the call is judged and read as the inner tool (tool name toolName,
arguments params); with no usable toolName it stays an unknown call. REPL
is not mapped and so is unknown. Read from the 2.170.0 bundle, not from a
captured record.

/fork and /branch write a new <newId>.jsonl whose items are structured
clones of the parent's (same callId and timestamp, new ids) and whose
session-meta line carries forkedFrom and forkedAt; its subagent files are
copied too. Read from the 2.170.0 bundle, not from a captured record. A
call stamped at or before forkedAt in such a session (or in the subagents
under it) is a copy and is not reported again: the parent's file reports
it. A call with no timestamp cannot be told and is kept. Clean still
searches every copy.

A call is "declined" (it never ran) when its result says so in the agent's
own fields: status "incomplete" with providerData.skipRun true (a rejection
or interruption), or providerData.toolResult.terminal.reason
"policy-denied". A call with no result at all is reported, not declined.

An output over CODEBUDDY_TOOL_RESULT_THRESHOLD_KB (default 50) is replaced in
the transcript by a <persisted-output> stub and written whole to
projects/<enc>/<sessionId>/tool-results/<callId>.txt (subagents:
<parent>/subagents/<agentId>/tool-results/). Those files, and the prompt
history <home>/history.jsonl ({display, pastedContents, timestamp,
project}), are side stores clean searches. They are not tied to a call.

Not read: *.meta.json sidecars (2.37.2), file-history/ (rewind backups),
traces/ (OTel spans), blobs/ (images moved out of transcripts), memory/,
settings and logs. The IDE extension (Tencent-Cloud.coding-copilot) keeps a
separate per-message store under CodeBuddyExtension/Data/ and is not read.
White-label builds can rename the home folder through a customization.json
in their install root; that cannot be seen from here, so use --path or
CODEBUDDY_CONFIG_DIR for one. WORKBUDDY_CONFIG_DIR does not move sessions.
The sensitive-data protection feature may leave "[REDACTED]" or an encrypted
projection in tool records; its exact shape was not verified and nothing
here depends on it. Sessions are deleted after cleanupPeriodDays (30) in
interactive use.

The CLI is closed source. Facts are from the npm tarball for
@tencent-ai/codebuddy-code 2.170.0 (dist/codebuddy.js and CHANGELOG.md) and
the vendor's docs; bundle symbols are not a stable API, so only the on-disk
format is relied on, and fields not listed above are not read.
"""

from __future__ import annotations

import datetime
import json
import os
import re

from . import _lines, _paths, _stamps, base
from .base import SecretText, Source, ToolCall

ENV = "CODEBUDDY_CONFIG_DIR"
HOME_DIR = ".codebuddy"
PROJECTS = "projects"
HISTORY = "history.jsonl"
SUBAGENTS = "subagents"
TOOL_RESULTS = "tool-results"

SHELL = {"Bash", "PowerShell"}
READ = {"Read"}
WRITE_WITH_PATH = {"Write", "Edit", "MultiEdit"}
NOTEBOOK_WRITE = {"NotebookEdit"}
FETCH = {"WebFetch", "WebSearch"}
OTHER = {"LS", "Glob", "Grep", "NotebookRead", "BashOutput", "KillShell",
         "TodoWrite", "Agent", "TaskOutput", "Skill", "AskUserQuestion",
         "EnterPlanMode", "ExitPlanMode", "SlashCommand", "ToolSearch"}

TYPES = ("message", "assistant", "function_call", "function_call_result",
         "function_call_output", "reasoning", "summary", "topic", "ai-title",
         "session-meta", "file-history-snapshot")
RESULTS = ("function_call_result", "function_call_output")

DEFER = "DeferExecuteTool"      # wraps a deferred tool: {toolName, params}
USER_SHELL = "bash_input"       # the tool name of a command the user ran
_INPUT = re.compile(r"<bash-input>(.*?)</bash-input>", re.S)
_STDOUT = re.compile(r"<bash-stdout>(.*?)</bash-stdout>", re.S)
_STDERR = re.compile(r"<bash-stderr>(.*?)</bash-stderr>", re.S)

# A line longer than this is not parsed (and counted), however large the
# file: readline is bounded, so one huge line never sits in memory whole.
LINE_MAX = 64 << 20
# The first lines are read for the store's working directory.
_HEAD_LINES = 50
_HEAD_BYTES = 1 << 16
# A tool output kept on a ToolCall is cut here, as clean cuts any string.
OUTPUT_MAX = 1000000
# A text file is searched in pieces of this size; each starts OVERLAP bytes
# before the last ended, so a value shorter than that lies whole in one.
CHUNK = 256 * 1024
OVERLAP = 32 * 1024


def _set(env, name):
    value = env.get(name)
    return value if isinstance(value, str) and value.strip() else None


def _string(value):
    return value if isinstance(value, str) and value else None


def _kind(name):
    """(kind, known) for a tool name."""
    if name in SHELL:
        return "shell", True
    if name in READ:
        return "read", True
    if name in WRITE_WITH_PATH or name in NOTEBOOK_WRITE:
        return "write", True
    if name in FETCH:
        return "fetch", True
    if name in OTHER:
        return "other", True
    return "other", False


def output_text(value):
    """The text of a result's output: a string as it is, {type, text}, or
    a list of those joined by newlines. None when there is no text."""
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        text = value.get("text")
        return text if isinstance(text, str) else None
    if isinstance(value, list):
        texts = [p.get("text") if isinstance(p, dict) else p for p in value]
        texts = [t for t in texts if isinstance(t, str)]
        if texts:
            return "\n".join(texts)
    return None


def _entries(folder):
    try:
        with os.scandir(folder) as it:
            return sorted(it, key=lambda e: e.name)
    except OSError:
        return []


def _is(entry, want):
    try:
        return entry.is_dir() if want == "dir" else entry.is_file()
    except OSError:
        return False


def _files(folder, suffix):
    return [e.path for e in _entries(folder)
            if not e.name.startswith(".") and e.name.endswith(suffix)
            and _is(e, "file")]


def _dirs(folder):
    return [e for e in _entries(folder)
            if not e.name.startswith(".") and _is(e, "dir")]


def _line_reader(fh):
    """(raw, complete) for every line of a binary file, a line over
    LINE_MAX as (None, True) once its end is passed."""
    while True:
        raw = fh.readline(LINE_MAX + 1)
        if not raw:
            return
        if len(raw) > LINE_MAX and not raw.endswith(b"\n"):
            done = False
            while True:
                rest = fh.readline(1 << 20)
                if not rest:
                    break
                if rest.endswith(b"\n"):
                    done = True
                    break
            yield None, done
            continue
        yield raw, raw.endswith(b"\n")


def _ms(value):
    """An epoch-millisecond number, digit string or ISO string as
    milliseconds since the epoch, or None."""
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    try:
        return float(text)
    except ValueError:
        pass
    try:
        when = datetime.datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=datetime.timezone.utc)
    try:
        return when.timestamp() * 1000
    except (OverflowError, OSError, ValueError):
        return None


def _fork_cut(path):
    """forkedAt (ms) from the session-meta line among the first lines of
    the transcript at `path` when it names forkedFrom, else None."""
    try:
        with open(path, "rb") as fh:
            for index in range(_HEAD_LINES):
                raw = fh.readline(_HEAD_BYTES)
                if not raw:
                    break
                if not raw.endswith(b"\n") and len(raw) >= _HEAD_BYTES:
                    continue
                try:
                    obj = json.loads(_lines.decode_line(raw, first=index == 0))
                except (ValueError, RecursionError):
                    continue
                if isinstance(obj, dict) and obj.get("type") == "session-meta":
                    meta = obj
                    for key in ("data", "meta", "metadata"):
                        if isinstance(obj.get(key), dict) and (
                                "forkedFrom" in obj[key]):
                            meta = obj[key]
                    if meta.get("forkedFrom") is not None:
                        return _ms(meta.get("forkedAt"))
    except OSError:
        pass
    return None


def _cwd_of(path):
    """The first cwd among the first lines of a transcript, or None."""
    try:
        with open(path, "rb") as fh:
            for index in range(_HEAD_LINES):
                raw = fh.readline(_HEAD_BYTES)
                if not raw:
                    break
                if not raw.endswith(b"\n") and len(raw) >= _HEAD_BYTES:
                    continue
                try:
                    obj = json.loads(_lines.decode_line(raw, first=index == 0))
                except (ValueError, RecursionError):
                    continue
                if isinstance(obj, dict) and _string(obj.get("cwd")):
                    return obj["cwd"]
    except OSError:
        pass
    return None


class CodeBuddySource(Source):
    id = "codebuddy"
    name = "CodeBuddy"
    unit = "session"
    env = (ENV,)
    path_means = ("a CodeBuddy home folder (what CODEBUDDY_CONFIG_DIR means), "
                  "or its projects folder")
    checked = "2.170.0"

    def reset(self):
        Source.reset(self)
        self._bad = set()
        self._tallied = set()

    # -- where to look ------------------------------------------------------

    def default_paths(self, env, home, platform):
        """$CODEBUDDY_CONFIG_DIR when set and not blank, else ~/.codebuddy
        (%USERPROFILE%\\.codebuddy on Windows). No XDG or APPDATA variant."""
        moved = _set(env, ENV)
        if moved:
            return [(moved, "env " + ENV)]
        return [(_paths.join(platform, home, HOME_DIR), "default")]

    @staticmethod
    def roots(path):
        """(home, projects folder) for a location: a folder named projects
        is the projects folder itself, any other is a home."""
        norm = os.path.normpath(path)
        if os.path.basename(norm) == PROJECTS:
            return None, norm
        return norm, os.path.join(norm, PROJECTS)

    def stores(self, locations, since_days=None):
        """Every main and subagent transcript, tool-result file and the
        prompt history under the locations, newest first."""
        found, seen = [], set()

        def add(path, format, **fields):
            key = os.path.normcase(os.path.abspath(path))
            if key in seen:
                return
            seen.add(key)
            store = self.store(path, format, **fields)
            if store is not None:
                found.append(store)

        for loc in locations:
            home, projects = self.roots(loc.path)
            for enc in _dirs(projects):
                for path in _files(enc.path, ".jsonl"):
                    stem = os.path.splitext(os.path.basename(path))[0]
                    add(path, "jsonl", session=stem, project=_cwd_of(path))
                for sess in _dirs(enc.path):
                    self._session_dir(add, sess)
            if home:
                path = os.path.join(home, HISTORY)
                if os.path.isfile(path):
                    add(path, "jsonl", role="side", unit="prompt history")
        return base.newest_first(found, since_days)

    def _session_dir(self, add, sess):
        """The stores inside projects/<enc>/<sessionId>/."""
        for path in _files(os.path.join(sess.path, TOOL_RESULTS), ".txt"):
            add(path, "text", role="side", unit="tool output",
                session=sess.name)
        subs = os.path.join(sess.path, SUBAGENTS)
        for path in _files(subs, ".jsonl"):
            add(path, "jsonl", session=sess.name, unit="subagent",
                project=_cwd_of(path))
        for agent in _dirs(subs):
            for path in _files(os.path.join(agent.path, TOOL_RESULTS), ".txt"):
                add(path, "text", role="side", unit="tool output",
                    session=sess.name)

    # -- reading ------------------------------------------------------------

    def _bad_store(self, store, reason):
        if store.path not in self._bad:
            self._bad.add(store.path)
            self.unreadable_store(reason, store.path)
        self.warn(store.path, "could not read CodeBuddy %s %s (%s)"
                  % (store.unit, store.path, reason))

    def _records(self, store):
        """(line_no, record) for every JSON line of a JSONL store. Lines
        that do not parse (or are over LINE_MAX) and types the spec does not
        list are counted once a run; a last line still being written is
        skipped quietly; a store that cannot be opened warns once."""
        tally = store.path not in self._tallied
        self._tallied.add(store.path)
        unparsed = parsed = 0
        try:
            with open(store.path, "rb") as fh:
                for index, (raw, complete) in enumerate(_line_reader(fh), 1):
                    if raw is None:
                        unparsed += 1
                        continue
                    text = _lines.decode_line(raw, first=index == 1)
                    if not text.strip():
                        continue
                    try:
                        obj = json.loads(text)
                    except (ValueError, RecursionError):
                        if complete:
                            unparsed += 1
                        continue
                    parsed += 1
                    if tally and store.role == "transcript" and (
                            not isinstance(obj, dict)
                            or obj.get("type") not in TYPES):
                        self.count("unknown")
                    if isinstance(obj, dict):
                        yield index, obj
        except OSError as e:
            self._bad_store(store, e.strerror or str(e))
            return
        finally:
            if tally:
                self.count("unparsed", unparsed)
        if not parsed and unparsed:
            self._bad_store(store, "not JSON Lines")

    @staticmethod
    def _declined(item):
        data = item.get("providerData")
        if not isinstance(data, dict):
            return False
        if item.get("status") == "incomplete" and data.get("skipRun") is True:
            return True
        tool = data.get("toolResult")
        terminal = tool.get("terminal") if isinstance(tool, dict) else None
        return (isinstance(terminal, dict)
                and terminal.get("reason") == "policy-denied")

    def _call(self, store, item):
        """The ToolCall for one function_call item."""
        name = item.get("name")
        name = name if isinstance(name, str) else ""
        args = base.decode_input(item.get("arguments"))
        if name == DEFER:
            inner = args.get("toolName")
            if isinstance(inner, str) and inner.strip():
                name = inner.strip()
                args = base.decode_input(args.get("params"))
        kind, known = _kind(name)
        cwd = _string(item.get("cwd"))
        command, paths, consumed, workdir = None, (), (), None
        if name in SHELL:
            command = _string(args.get("command"))
            if command:
                consumed = ("command",)
                workdir = cwd
            else:
                self.count("unreadable_calls")
        elif name in READ or name in WRITE_WITH_PATH or name in NOTEBOOK_WRITE:
            key = "notebook_path" if name in NOTEBOOK_WRITE else "file_path"
            path = _string(args.get(key))
            if path:
                paths = (path,)
                if name in READ:
                    consumed = (key,)
        return ToolCall(
            self.id, store.path, name, args, kind=kind, known=known,
            tool_call_id=_string(item.get("callId")), command=command,
            workdir=workdir, paths=paths, consumed=consumed,
            **self._where(store, item))

    @staticmethod
    def _where(store, item):
        stamp = _stamps.iso_utc(item.get("timestamp"), "ms")
        return {"session": store.session,
                "project": _string(item.get("cwd")) or store.project,
                "timestamp": stamp,
                "not_after": (None if stamp
                              else _stamps.iso_utc(store.mtime, "s"))}

    @staticmethod
    def _user_text(item):
        """The text of a user message, or None."""
        if item.get("type") != "message" or item.get("role") != "user":
            return None
        content = item.get("content")
        if isinstance(content, str):
            return content
        if isinstance(content, list):
            texts = [p.get("text") for p in content if isinstance(p, dict)
                     and isinstance(p.get("text"), str)]
            return "\n".join(texts) if texts else None
        return None

    def _user_call(self, store, item, command):
        return ToolCall(
            self.id, store.path, USER_SHELL, {"command": command},
            kind="shell", known=True, actor="user",
            tool_call_id=_string(item.get("id")), command=command,
            workdir=_string(item.get("cwd")), consumed=("command",),
            **self._where(store, item))

    @staticmethod
    def _cut(store):
        """forkedAt for a forked session's transcript (or a subagent's, by
        the main transcript beside its folder), else None."""
        path = store.path
        if store.unit == "subagent":
            parent = os.path.dirname(os.path.dirname(os.path.dirname(path)))
            path = os.path.join(parent, (store.session or "") + ".jsonl")
        return _fork_cut(path)

    @staticmethod
    def _copied(item, cut):
        """True for an item stamped at or before the fork: a copy."""
        if cut is None:
            return False
        stamp = _ms(item.get("timestamp"))
        return stamp is not None and stamp <= cut

    def tool_calls(self, store):
        """Every function_call of a transcript, once per callId (the first
        copy), with its result's text as output; and every command the user
        ran with "!", with its stdout and stderr. A call is yielded when its
        result arrives, and calls still waiting at the end of the file then,
        so a long session is not held in memory whole."""
        if store.role != "transcript":
            return
        pending = {}
        done = set()
        cut = self._cut(store)
        shell = None            # a user command waiting for its output
        for _line_no, item in self._records(store):
            kind = item.get("type")
            text = self._user_text(item)
            if shell is not None:
                out = [m.group(1) for rx in (_STDOUT, _STDERR)
                       for m in [rx.search(text)] if m] if text else []
                if out:
                    shell.output = "\n".join(o for o in out if o)[:OUTPUT_MAX]
                    yield shell
                    shell = None
                    continue
                yield shell
                shell = None
            if kind == "function_call":
                if self._copied(item, cut):
                    continue
                call = self._call(store, item)
                cid = call.tool_call_id
                if cid is None:
                    yield call
                elif cid not in done and cid not in pending:
                    pending[cid] = call
            elif kind in RESULTS:
                cid = item.get("callId")
                call = pending.pop(cid, None) if isinstance(cid, str) else None
                if call is not None:
                    out = output_text(item.get("output"))
                    call.output = out[:OUTPUT_MAX] if out is not None else None
                    if self._declined(item):
                        call.status = "declined"
                    done.add(cid)
                    yield call
            elif text is not None:
                m = _INPUT.search(text) if "<bash-input>" in text else None
                if (m and m.group(1).strip()
                        and not self._copied(item, cut)):
                    shell = self._user_call(store, item, m.group(1).strip())
        if shell is not None:
            yield shell
        for call in pending.values():
            yield call

    def secret_texts(self, store):
        """Every string the store holds. In a transcript that is every line,
        with each result's output (and the display copy in
        providerData.toolResult) handed over on its own, tied to its call."""
        if store.format == "text":
            return self._chunks(store)
        if store.role != "transcript":
            return self._side_lines(store)
        return self._transcript_texts(store)

    def _side_lines(self, store):
        for line_no, obj in self._records(store):
            yield SecretText(obj, where="line %d" % line_no)

    def _transcript_texts(self, store):
        calls = {}
        for line_no, item in self._records(store):
            where = "line %d" % line_no
            if item.get("type") == "function_call":
                cid = item.get("callId")
                if isinstance(cid, str) and cid and cid not in calls:
                    calls[cid] = self._call(store, item)
            if item.get("type") not in RESULTS:
                yield SecretText(item, where=where)
                continue
            cid = item.get("callId")
            call = calls.get(cid) if isinstance(cid, str) else None
            rest = {k: v for k, v in item.items() if k != "output"}
            data = item.get("providerData")
            shown = None
            if isinstance(data, dict) and "toolResult" in data:
                shown = data["toolResult"]
                rest["providerData"] = {k: v for k, v in data.items()
                                        if k != "toolResult"}
            yield SecretText(rest, where=where)
            if "output" in item:
                yield SecretText(item["output"], call=call, where=where)
            if shown is not None:
                yield SecretText(shown, call=call, where=where)

    def _chunks(self, store):
        """A tool-result file in overlapping pieces, so one larger than
        clean's per-string limit is searched to its end."""
        try:
            with open(store.path, "rb") as fh:
                pos = 0
                while True:
                    fh.seek(pos)
                    data = fh.read(CHUNK)
                    if not data:
                        break
                    yield SecretText(
                        data.decode("utf-8", "surrogateescape"),
                        where="bytes %d-%d" % (pos, pos + len(data)))
                    if len(data) < CHUNK:
                        break
                    pos += CHUNK - OVERLAP
        except OSError as e:
            self._bad_store(store, e.strerror or str(e))
