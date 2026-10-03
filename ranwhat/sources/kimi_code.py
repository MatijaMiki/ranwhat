"""Kimi Code CLI (`kimi`, npm @moonshot-ai/kimi-code) and its VS Code
extension, which runs the same Node SDK and shares sessions with the CLI
when both resolve to the same KIMI_CODE_HOME. Design section 7.8.

Layout under the root (KIMI_CODE_HOME, else ~/.kimi-code):

    sessions/<workDirKey>/<sessionId>/agents/main/wire.jsonl       transcript
    sessions/<workDirKey>/<sessionId>/agents/agent-<n>/wire.jsonl  sub-agents
    sessions/<workDirKey>/<sessionId>/state.json                   side
    sessions/<workDirKey>/<sessionId>/logs/kimi-code.log[.<n>]     side
    user-history/<md5(workDir)>.jsonl                              side
    logs/kimi-code.log[.<n>]                                       side
    session_index.jsonl            map only: sessionId -> workDir

Logs rotate: kimi-code.log.1 and up are the older parts of the same log.

A tool result too long to keep whole names the file that holds all of it,
on a line "output_path: <path>". That file is followed only when it has
the shape Kimi Code gives a spill file, inside the transcript's own session
folder and the root:

    agents/<agentId>/tool-results/<tool>-<call id>-<uuid>.txt
    agents/<agentId>/tasks/<taskId>/output.log       Bash and TaskOutput
    tasks/<taskId>/output.log                        the main agent, older

Nothing else is opened, whatever a transcript names: not credentials/ (the
CLI's OAuth tokens), config.toml or mcp.json (provider keys and MCP
tokens), plans, cron, goal queues, task records or file-history blobs.
<workDirKey> is wd_<slug>_<12 hex of a sha256> and cannot be reversed, so a
session's working directory comes from session_index.jsonl or not at all.

wire.jsonl is an event journal: a metadata line, then one record per line
with a millisecond "time". Tool calls are context.append_loop_event records
whose event is a tool.call (args already parsed) or a tool.result (output
a string or a list of content parts). Messages come from the context
journal (context.append_message, the message at record.message) and from
the loop engine's journal (agent.message.appended, older files
human.agent.message.appended), which holds a history entry {message, meta}
at record.message, so the message is record.message.message. A message's
toolCalls (arguments a JSON string, or null) are read only for an id no
tool.call event carries; sessions migrated from the Python Kimi CLI
(protocol 1.0) have nothing else, in the shape {type, id, function: {name,
arguments}}, with their outputs in tool messages. Kimi Code writes a
call's tool.call event when it dispatches the call, so one it never
dispatched, a turn interrupted while the call waited for approval, is only
in a message too: its result is the note Kimi Code fills in for an
interrupted or aborted call, and it is declined. A command the user typed
in shell mode is a user message wrapped in <bash-input>, and its output is
the next shell message. A call whose approval the user rejected or
cancelled is recorded too, but never ran. Undo, compaction and branch
switches are recorded in the same file; calls on abandoned branches still
ran and are reported.

A tool call id is not unique within a file: after a clear, an undo or a
compaction, a new call can carry an old call's id (see _collect).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import time

from . import _lines, _paths, _stamps
from .base import SecretText, Source, ToolCall, decode_input, newest_first

ENV = "KIMI_CODE_HOME"
HOME_DIR = ".kimi-code"

# Tool names and argument keys from the official tools reference.
_KINDS = {
    "Bash": "shell",
    "Read": "read",
    "Write": "write",
    "Edit": "write",
    "FetchURL": "fetch",
    "WebSearch": "fetch",
    "Grep": "other",
    "Glob": "other",
    "ReadMediaFile": "other",
    "Agent": "other",
    "AgentSwarm": "other",
    "TaskOutput": "other",
    "CronCreate": "other",
}

# Records that carry a message. The context journal's holds it at
# record.message. The loop engine's own journal of the same messages
# ("agent." + its event name; older files "human.agent.") holds a history
# entry {message, meta} there (human/agent/events.ts, historySchema.ts), so
# its message is record.message.message. A message may hold toolCalls, or
# be a tool message whose toolCallId names the call it answers.
CONTEXT_MESSAGE = "context.append_message"
_ENGINE_MESSAGES = frozenset(("agent.message.appended",
                              "human.agent.message.appended"))
LOOP_EVENT = "context.append_loop_event"
APPROVAL = "permission.record_approval_result"

# The loop events a context.append_loop_event record can hold.
_LOOP_EVENTS = frozenset(("step.begin", "step.end", "content.part",
                          "tool.call", "tool.result"))

# Every other record type Kimi Code writes to wire.jsonl, none of which
# holds a tool call: the durable event types of agent-core-v2 (64, less the
# three read above), the metadata line, and the two records the wire layer
# writes itself on an undo. A type outside these is counted as unknown, so
# a format change shows up as a jump and ordinary activity does not.
_NO_CALL_TYPES = frozenset((
    "metadata", "agent.switched", "context.undone",
    "config.update", "context.apply_compaction", "context.clear",
    "context.undo", "cron.add", "cron.cursor", "cron.delete",
    "file_history.checkpoint", "file_history.tracked", "forked",
    "full_compaction.begin", "full_compaction.cancel",
    "full_compaction.complete", "goal.clear", "goal.create", "goal.update",
    "interaction.request", "interaction.resolved",
    "interruptionReminder.recorded", "llm.request", "llm.tools_snapshot",
    "mcp.tools_discovered", "permission.set_mode", "plan.revision",
    "plan_mode.cancel", "plan_mode.enter", "plan_mode.exit",
    "plugin.session_start", "profile.bind", "prompt.aborted",
    "prompt.completed", "prompt.steered", "runtime.set_binding",
    "subagent.cancelled", "subagent.completed", "subagent.failed",
    "subagent.spawned", "subagent.started", "swarm_mode.enter",
    "swarm_mode.exit", "task.started", "task.terminated",
    "task.waitDelivered", "token_counting.measured", "token_counting.rebased",
    "token_counting.truncated", "token_counting.turn_recorded",
    "tools.register_user_tool", "tools.reset_active_tools",
    "tools.set_active_tools", "tools.unregister_user_tool",
    "tools.update_store", "tower_mode.enter", "tower_mode.exit",
    "turn.cancel", "turn.ended", "turn.prompt", "turn.steer",
    "turn.step.interrupted", "turn.step.retrying", "usage.record",
))

# The loop engine's events, journalled as "agent.<event>" or, in older
# files, "human.agent.<event>". message.appended is read as a message.
_ENGINE_PREFIXES = ("agent.", "human.agent.")
_ENGINE_EVENTS = frozenset((
    "agent.closed", "agent.opened", "agent.switched", "compaction.cancelled",
    "compaction.completed", "compaction.started", "input.cancelled",
    "input.drained", "input.notified", "input.reminded", "input.steered",
    "input.submitted", "message.appended", "notifications.drained",
    "queue.drained", "session.meta_updated", "state.updated", "turn.ended",
    "turn.started",
))

# An approval answered with one of these vetoes the call: Kimi Code still
# records it, with a result saying it was not run.
_NOT_RUN = frozenset(("rejected", "cancelled"))

# After one of these, the next turn can give a new call an old call's id:
# each turn seeds its ids from the context as it is then (human/agent/
# turn.ts, human/llm/toolCallIdNormalizer.ts), and these take calls out.
_RESETS = frozenset(("context.clear", "context.undo",
                     "context.apply_compaction"))

# The result Kimi Code fills in for a call a turn was interrupted or
# aborted before (agent/toolExecutor/toolExecutorService.ts
# abortedToolOutput), by the call's tool name: the start of the first, all
# of the second.
_INTERRUPTED = ('The user manually interrupted "%s" (and anything else '
                'running at the same time).')
_ABORTED = 'Tool "%s" was aborted'

# Shell mode: what the user typed, XML-escaped (& < > ") inside this
# wrapper, recorded as a user message.
_SHELL_HEAD = "<bash-input>\n"
_SHELL_TAIL = "\n</bash-input>"
_XML_ENTITY = re.compile(r"&(amp|lt|gt|quot);")
_XML_CHARS = {"amp": "&", "lt": "<", "gt": ">", "quot": '"'}

INDEX = "session_index.jsonl"
WIRE = "wire.jsonl"
_LOG = re.compile(r"kimi-code\.log(?:\.[0-9]+)?\Z")

# A tool result names its spill file on a line of its own text, the path
# after "output_path: ".
_OUTPUT_PATH = re.compile(r"output_path:[ \t]*([^\r\n]+)")
_OUTPUT_PATH_BYTES = b"output_path:"

# The only files a spill path may name, by their parts below a session
# folder. A spill file is <tool>-<call id> with every character outside
# [A-Za-z0-9._-] made "_", cut to 80, then "-<random uuid>.txt"; a task id
# is <kind>-<8 of [0-9a-z]>; an agent folder is main or agent-<n>.
_AGENT_DIR = re.compile(r"(?:main|agent-[0-9]+)\Z")
_SPILL_FILE = re.compile(r"[A-Za-z0-9._-]{1,80}-[0-9a-f]{8}-[0-9a-f]{4}-"
                         r"[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.txt\Z")
_TASK_ID = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*-[0-9a-z]{8}\Z")
TOOL_RESULTS = "tool-results"
TASKS = "tasks"
TASK_LOG = "output.log"

# Stored output kept on a ToolCall is cut here, as clean cuts any string
# (clean.MAX_STRING; sources do not import clean).
OUTPUT_MAX = 1000000

# Text side stores (logs, spill files) are searched in blocks of whole
# lines about this long, so one huge log is not one huge string and a
# multi-line key in it usually stays in one piece.
BLOCK_CHARS = 200000

_MD5 = re.compile(r"[0-9a-fA-F]{32}\Z")


def _set(env, name):
    value = env.get(name)
    return value if isinstance(value, str) and value else None


def _scandir(path):
    """Entries of a directory, or none when it cannot be listed."""
    try:
        with os.scandir(path) as it:
            return sorted(it, key=lambda e: e.name)
    except OSError:
        return []


def _is_dir(entry):
    try:
        return entry.is_dir()
    except OSError:
        return False


def _is_file(entry):
    try:
        return entry.is_file()
    except OSError:
        return False


def _text_of(value):
    """A string as it is, or the text parts of a content-part list joined
    by newlines. Images are not text. None when there is no text."""
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        parts = [p.get("text") for p in value
                 if isinstance(p, dict) and p.get("type") == "text"
                 and isinstance(p.get("text"), str)]
        if parts:
            return "\n".join(parts)
    return None


def _output_text(value):
    """A tool's output as text, cut at OUTPUT_MAX."""
    text = _text_of(value)
    return None if text is None else text[:OUTPUT_MAX]


def _strings(node, depth=0):
    """Every string in a decoded JSON structure (values, not keys)."""
    if depth > 32:
        return
    if isinstance(node, str):
        yield node
    elif isinstance(node, list):
        for item in node:
            for s in _strings(item, depth + 1):
                yield s
    elif isinstance(node, dict):
        for value in node.values():
            for s in _strings(value, depth + 1):
                yield s


def _id(value):
    return value if isinstance(value, str) and value else None


def _type(node):
    """A record's or event's "type" when it is a string, else None. (A
    list there must not reach a set lookup: it cannot be hashed.)"""
    value = node.get("type") if isinstance(node, dict) else None
    return value if isinstance(value, str) else None


def _message_of(obj, kind):
    """The message a message record of type `kind` carries: record.message
    in the context journal, record.message.message in the loop engine's.
    None when it is not an object there (no other place is tried)."""
    node = obj.get("message")
    if kind in _ENGINE_MESSAGES:
        node = node.get("message") if isinstance(node, dict) else None
    return node if isinstance(node, dict) else None


def _same(a, b):
    """True when two calls with one id have the same name and input: one
    call recorded twice, not a new call that reused the id. Input nested
    too deep for Python to compare is taken for a new call: a copy
    reported twice is better than a call missed."""
    try:
        return a.tool_name == b.tool_name and a.tool_input == b.tool_input
    except RecursionError:
        return False


def _never_dispatched(call):
    """True when a call only a message holds has for its result the note
    Kimi Code fills in for a call interrupted or aborted before it ran
    (loopService.ts backfillAbortedToolResults): it never got a tool.call
    event, so it was never dispatched."""
    text, name = call.output, call.tool_name
    return isinstance(text, str) and (text.startswith(_INTERRUPTED % name)
                                      or text == _ABORTED % name)


def _no_call_type(kind):
    """True for a record type that is verified to hold no tool call."""
    if kind in _NO_CALL_TYPES:
        return True
    for prefix in _ENGINE_PREFIXES:
        if kind.startswith(prefix) and kind[len(prefix):] in _ENGINE_EVENTS:
            return True
    return False


def _shell_command(message):
    """The command a shell-mode input message holds, unescaped; None when
    the message is not in the shape Kimi Code writes."""
    text = _text_of(message.get("content"))
    if (text is None or len(text) < len(_SHELL_HEAD) + len(_SHELL_TAIL)
            or not text.startswith(_SHELL_HEAD)
            or not text.endswith(_SHELL_TAIL)):
        return None
    inner = text[len(_SHELL_HEAD):len(text) - len(_SHELL_TAIL)]
    return _XML_ENTITY.sub(lambda m: _XML_CHARS[m.group(1)], inner)


def _md5_of(work_dir):
    """The md5 Kimi Code names a working directory's prompt history by.
    Node hashes the UTF-8 form, in which a lone UTF-16 surrogate (a Windows
    folder name can hold one; JSON keeps it as an escape) is U+FFFD. None
    when it cannot be worked out."""
    try:
        data = (work_dir.encode("utf-16-le", "surrogatepass")
                .decode("utf-16-le", "replace").encode("utf-8"))
        return hashlib.md5(data, usedforsecurity=False).hexdigest()
    except (UnicodeError, ValueError):
        return None


def _candidates(text):
    """Paths named after "output_path:" in a piece of text: the rest of the
    line, and its first word when that differs (the line may go on)."""
    for m in _OUTPUT_PATH.finditer(text):
        rest = m.group(1).strip().strip("`'\"")
        if rest:
            yield rest
            words = rest.split()
            if words and words[0] != rest:
                yield words[0].strip("`'\"")


def _key(path):
    return os.path.normcase(os.path.normpath(path))


def _inside(path, root):
    """True when `path` is strictly under `root`; both already absolute."""
    root = _key(root)
    path = _key(path)
    if not root.endswith(os.sep):
        root += os.sep
    return path.startswith(root)


def _spill_shape(path, session):
    """True when `path`, strictly under the session folder `session`, is
    where Kimi Code writes a spill file. Strings only, nothing looked up."""
    parts = os.path.relpath(path, session).split(os.sep)
    if len(parts) == 3:
        return (parts[0] == TASKS and parts[2] == TASK_LOG
                and _TASK_ID.match(parts[1]) is not None)
    if len(parts) < 4 or parts[0] != "agents" or not _AGENT_DIR.match(parts[1]):
        return False
    if len(parts) == 4:
        return parts[2] == TOOL_RESULTS and _SPILL_FILE.match(parts[3]) is not None
    return (len(parts) == 5 and parts[2] == TASKS and parts[4] == TASK_LOG
            and _TASK_ID.match(parts[3]) is not None)


class _Parsed(object):
    """What one read of a wire.jsonl gives: every distinct call, and the
    lines that hold a call's output (a tool.result event, a tool message,
    a shell-mode command's output), by line number, with the call each
    belongs to."""
    __slots__ = ("calls", "owners")

    def __init__(self, calls, owners):
        self.calls = calls
        self.owners = owners


class KimiCodeSource(Source):
    id = "kimi-code"
    name = "Kimi Code"
    unit = "session"
    env = (ENV,)
    path_means = "a Kimi Code home directory (KIMI_CODE_HOME, default ~/.kimi-code)"
    checked = "2.1.1"

    def reset(self):
        super().reset()
        # (path, size, mtime_ns) -> [(spill path, line number)]: a
        # transcript is read for spill paths once per run, not once per
        # locations() and once per stores().
        self._spill_cache = {}
        # spill path key -> (transcript Store, line number of the line that
        # named it), so the spill's text is credited to the call whose
        # output that line is. (By line, not by id: ids are reused.)
        self._spill_of = {}
        # (path, size, mtime_ns) -> {line number: ToolCall}, only the lines
        # that name a spill file: the transcript is read once for all of
        # them, not once per spill file.
        self._spill_calls = {}
        # transcripts whose skipped lines are already counted this run
        self._counted = set()

    # -- where to look ------------------------------------------------------

    def default_paths(self, env, home, platform):
        moved = _set(env, ENV)
        if moved:
            return [(moved, "env " + ENV)]
        return [(_paths.join(platform, home, HOME_DIR), "default")]

    def stores(self, locations, since_days=None):
        found, seen, spilled = [], set(), set()

        def add(store):
            if store is not None and _key(store.path) not in seen:
                seen.add(_key(store.path))
                found.append(store)
                return store
            return None

        for loc in locations:
            root = loc.path
            if not os.path.isdir(root):
                continue
            index = self._index(root)
            transcripts = []
            sessions = os.path.join(root, "sessions")
            for key_dir in _scandir(sessions):
                if not _is_dir(key_dir):
                    continue
                for session_dir in _scandir(key_dir.path):
                    if not _is_dir(session_dir):
                        continue
                    sid = session_dir.name
                    project = index.get(sid)
                    for agent in _scandir(os.path.join(session_dir.path, "agents")):
                        if not (agent.name == "main"
                                or agent.name.startswith("agent-")):
                            continue
                        wire = os.path.join(agent.path, WIRE)
                        if os.path.isfile(wire):
                            store = add(self.store(wire, "jsonl", session=sid,
                                                   project=project))
                            if store is not None:
                                transcripts.append(store)
                    state = os.path.join(session_dir.path, "state.json")
                    if os.path.isfile(state):
                        add(self.store(state, "json", role="side", session=sid,
                                       project=project))
                    for log in self._logs(os.path.join(session_dir.path, "logs")):
                        add(self.store(log, "text", role="side", session=sid,
                                       project=project))
            by_md5 = {}
            for work_dir in index.values():
                digest = _md5_of(work_dir)
                if digest is not None:
                    by_md5.setdefault(digest, work_dir)
            for entry in _scandir(os.path.join(root, "user-history")):
                stem, ext = os.path.splitext(entry.name)
                if ext != ".jsonl" or not os.path.isfile(entry.path):
                    continue
                project = by_md5.get(stem.lower()) if _MD5.match(stem) else None
                add(self.store(entry.path, "jsonl", role="side",
                               project=project))
            for log in self._logs(os.path.join(root, "logs")):
                add(self.store(log, "text", role="side"))
            for spill, real, transcript, line_no in self._spills(
                    root, transcripts, since_days):
                if _key(real) in spilled:
                    continue        # one file, named twice or two ways
                spilled.add(_key(real))
                store = add(self.store(spill, "text", role="side",
                                       session=transcript.session,
                                       project=transcript.project))
                if store is not None:
                    self._spill_of[_key(spill)] = (transcript, line_no)
        return newest_first(found, since_days)

    @staticmethod
    def _logs(folder):
        """kimi-code.log in `folder` and its rotated parts, .1 and up."""
        return [e.path for e in _scandir(folder)
                if _LOG.match(e.name) and _is_file(e)]

    def _index(self, root):
        """{sessionId: workDir} from session_index.jsonl. The index can be
        incomplete (the session picker lists folders directly), so a
        session missing from it has no project, which is normal."""
        out = {}
        try:
            for _n, obj in _lines.iter_json_lines(os.path.join(root, INDEX)):
                if not isinstance(obj, dict):
                    continue
                sid, work_dir = obj.get("sessionId"), obj.get("workDir")
                if isinstance(sid, str) and sid and isinstance(work_dir, str) \
                        and work_dir:
                    out[sid] = work_dir
        except OSError:
            pass
        return out

    def _spills(self, root, transcripts, since_days):
        """(spill path as written, its real path, transcript store, number
        of the line that named it) for every spill file a transcript names
        that may be opened (see _spill)."""
        cutoff = time.time() - since_days * 86400 if since_days else None
        real_root = os.path.realpath(root)
        for store in transcripts:
            if cutoff is not None and store.mtime < cutoff:
                continue            # a spill is never newer than its result
            # <session>/agents/<agentId>/wire.jsonl
            session = os.path.dirname(os.path.dirname(os.path.dirname(store.path)))
            real_session = os.path.realpath(session)
            for candidate, line_no in self._named_spills(store.path):
                spill = self._spill(candidate, session, real_session, real_root)
                if spill:
                    yield spill[0], spill[1], store, line_no

    def _named_spills(self, path):
        """[(path as written, line number)] named by "output_path:" in a
        transcript, cached by the file's size and mtime. Lines are numbered
        as _lines.iter_json_lines numbers them."""
        try:
            st = os.stat(path)
        except OSError:
            return []
        cache_key = (_key(path), st.st_size, st.st_mtime_ns)
        cached = self._spill_cache.get(cache_key)
        if cached is not None:
            return cached
        named = []
        try:
            with open(path, "rb") as fh:
                for line_no, raw in enumerate(fh, 1):
                    if _OUTPUT_PATH_BYTES not in raw:
                        continue
                    try:
                        obj = json.loads(_lines.decode_line(raw, first=line_no == 1))
                    except (ValueError, RecursionError):
                        continue
                    if not isinstance(obj, dict):
                        continue
                    for text in _strings(obj):
                        if "output_path:" in text:
                            for candidate in _candidates(text):
                                named.append((candidate, line_no))
        except OSError:
            named = []
        self._spill_cache[cache_key] = named
        return named

    @staticmethod
    def _spill(candidate, session, real_session, real_root):
        """(path as written, real path) of a spill file a transcript named,
        or None.

        Text a tool printed (a fetched page, a cat, a grep) can say
        "output_path:" too, so a named path is opened only when it is a
        spill file Kimi Code itself would write for this transcript's
        session: absolute; under the session folder as written, and in one
        of the shapes in _spill_shape, before anything is looked up; then,
        with symlinks resolved, still in that shape under the session
        folder and the root; and a regular file. The store keeps the path
        as the agent wrote it."""
        if not os.path.isabs(candidate):
            return None
        written = os.path.normpath(os.path.abspath(candidate))
        for base in (os.path.abspath(session), real_session):
            if _inside(written, base):
                break
        else:
            return None
        if not _spill_shape(written, base):
            return None
        real = os.path.realpath(written)
        if not (_inside(real, real_session) and _inside(real, real_root)
                and _spill_shape(real, real_session)):
            return None
        if not os.path.isfile(real):
            return None
        return written, real

    # -- what is in a store -------------------------------------------------

    def _unreadable(self, store, reason):
        """Count and warn once per store per run."""
        key = ("unreadable", _key(store.path))
        if key in self._warned:
            return
        self.unreadable_store(reason)
        self.warn(key, "could not read Kimi Code %s %s (%s)"
                  % (store.unit if store.role == "transcript" else "file",
                     store.path, reason))

    def _call(self, store, name, raw_input, cid, stamp, actor="agent"):
        tool_input = decode_input(raw_input)
        kind = _KINDS.get(name) if isinstance(name, str) else None
        command = workdir = None
        paths = consumed = ()
        if kind == "shell":
            value = tool_input.get("command")
            if isinstance(value, str) and value:
                command, consumed = value, ("command",)
            cwd = tool_input.get("cwd")
            if isinstance(cwd, str) and cwd:
                workdir = cwd
        elif kind in ("read", "write"):
            value = tool_input.get("path")
            if isinstance(value, str) and value:
                paths = (value,)
                if kind == "read":
                    consumed = ("path",)
        not_after = None
        if stamp is None:
            not_after = _stamps.iso_utc(store.mtime, "s")
        return ToolCall(
            self.id, store.path, name if isinstance(name, str) else "",
            tool_input, kind=kind or "other", known=kind is not None,
            session=store.session, project=store.project, timestamp=stamp,
            tool_call_id=cid, actor=actor, not_after=not_after,
            command=command, workdir=workdir, paths=paths, consumed=consumed)

    def _collect(self, store):
        """A _Parsed for a wire.jsonl: {key: ToolCall} for every distinct
        call, in file order, with outputs and status attached, and the call
        each output line belongs to. A key is ("event", line), ("message",
        line, index) or ("shell", line): unique even when ids are not.

        A toolCallId is not unique within a file. Kimi Code keeps a
        provider's id unless it has already seen it, and each turn seeds
        what it has seen from the context as it is then
        (human/agent/turn.ts, human/llm/toolCallIdNormalizer.ts); Kimi K2
        numbers its ids functions.<name>:<n> over the conversation it sees.
        After a clear, an undo or a compaction (_RESETS), a new call can
        carry an old call's id, and the same name and args. So:

        - a tool.call event is the call an earlier event with its id made,
          recorded again, only when its name and args are that call's and
          no reset came between them; otherwise it is a new call, and both
          are reported;
        - a call in a message is a copy when an event has carried its id
          (the event wins, whatever the message's arguments say) or when
          the latest call with its id came from a message and has the same
          name and arguments; otherwise it is a call of its own. An event
          replaces a message's call with its id while that call has no
          output yet and no reset came between them. A call only a message
          holds whose result is Kimi Code's note that it was interrupted
          or aborted was never dispatched, so never ran: it is declined;
        - a tool.result or a tool message belongs to the latest call before
          it with its id; a call's output is the first it gets;
        - an approval answer is recorded just before the tool.call event of
          the call it gates, a vetoed call included
          (toolApproval/toolApprovalService.ts records it in the
          before-execute hook, then toolExecutor/toolExecutorService.ts
          dispatches the call), so it is held for the next tool.call event
          with its id. One still held at a reset or at the end goes to the
          latest call with its id when only a message made that call (an id
          no event carries); otherwise it gated a call that was never
          dispatched, and is dropped.

        Raises OSError when the file cannot be opened."""
        first = _key(store.path) not in self._counted
        self._counted.add(_key(store.path))
        calls = {}          # key -> ToolCall, in file order
        latest = {}         # toolCallId -> key of the latest call with it
        by_event = {}       # toolCallId -> key of the latest call an event made
        outputs = {}        # key -> text of its first tool.result
        replies = {}        # key -> text of its first tool message
        answered = set()    # keys a tool.result or tool message has named
        decisions = {}      # key -> every approval decision for it
        held = {}           # toolCallId -> decisions no call has taken yet
        resets = 0          # _RESETS records so far
        made = {}           # key -> resets before its call was made
        owner_keys = {}     # line number -> key of the call it answers
        owners = {}         # line number -> the call whose output it holds
        shell = None        # the last shell-mode command, until its output
        parsed = 0
        skipped = {}

        def unknown():
            if first:
                self.count("unknown")

        def settle():
            """Give each answer still held to the call only a message made
            with its id; the rest gated calls never dispatched."""
            for cid, said in held.items():
                key = latest.get(cid)
                if key is not None and cid not in by_event:
                    decisions.setdefault(key, set()).update(said)
            held.clear()

        def answer(cid, line_no):
            """The key of the call a result line for `cid` answers."""
            key = latest.get(cid) if cid else None
            if key is not None:
                owner_keys[line_no] = key
                answered.add(key)
            return key

        for line_no, obj in _lines.iter_json_lines(store.path, skipped):
            parsed += 1
            if not isinstance(obj, dict):
                unknown()
                continue
            kind = _type(obj)
            stamp = _stamps.iso_utc(obj.get("time"), "ms")
            if kind == LOOP_EVENT:
                event = obj.get("event")
                etype = _type(event)
                if etype == "tool.call":
                    cid = _id(event.get("toolCallId"))
                    call = self._call(store, event.get("name"),
                                      event.get("args"), cid, stamp)
                    if cid is None:
                        calls[("event", line_no)] = call
                        continue
                    key = by_event.get(cid)
                    if key is None or made[key] != resets \
                            or not _same(calls[key], call):
                        prior = latest.get(cid)
                        if key is None and prior is not None \
                                and prior not in answered \
                                and made[prior] == resets:
                            # an event wins over a message's copy of the
                            # same call
                            del calls[prior]
                        key = ("event", line_no)
                        calls[key] = call
                        made[key] = resets
                        by_event[cid] = latest[cid] = key
                    # else: the same call recorded again
                    for said in held.pop(cid, ()):
                        decisions.setdefault(key, set()).add(said)
                elif etype == "tool.result":
                    key = answer(_id(event.get("toolCallId")), line_no)
                    result = event.get("result")
                    if key is not None and key not in outputs \
                            and isinstance(result, dict):
                        text = _output_text(result.get("output"))
                        if text is not None:
                            outputs[key] = text
                elif etype not in _LOOP_EVENTS:
                    unknown()
            elif kind == CONTEXT_MESSAGE or kind in _ENGINE_MESSAGES:
                message = _message_of(obj, kind)
                if message is None:
                    unknown()
                    continue
                origin = message.get("origin")
                if (kind == CONTEXT_MESSAGE and isinstance(origin, dict)
                        and origin.get("kind") == "shell_command"):
                    phase = origin.get("phase")
                    if phase == "input":
                        shell = self._shell_call(store, message, stamp, first)
                        if shell is not None:
                            calls[("shell", line_no)] = shell
                    elif phase == "output" and shell is not None:
                        text = _output_text(message.get("content"))
                        if text is not None:
                            shell.output = text
                        owners[line_no] = shell
                        shell = None
                    continue
                tool_calls = message.get("toolCalls")
                for index, tc in enumerate(tool_calls if isinstance(tool_calls, list)
                                           else ()):
                    if not isinstance(tc, dict):
                        continue
                    cid = _id(tc.get("id"))
                    if not cid or cid in by_event:
                        continue            # the copy of an event's call
                    name, arguments = tc.get("name"), tc.get("arguments")
                    fn = tc.get("function")
                    if "name" not in tc and "arguments" not in tc \
                            and isinstance(fn, dict):
                        # protocol 1.0, as the Kimi CLI migrator writes it
                        name, arguments = fn.get("name"), fn.get("arguments")
                    call = self._call(store, name, arguments, cid, stamp)
                    prior = latest.get(cid)
                    if prior is not None and _same(calls[prior], call):
                        continue            # another copy of that message
                    key = ("message", line_no, index)
                    calls[key] = call
                    made[key] = resets
                    latest[cid] = key
                key = answer(_id(message.get("toolCallId")), line_no)
                if key is not None and key not in replies:
                    text = _output_text(message.get("content"))
                    if text is not None:
                        replies[key] = text
            elif kind == APPROVAL:
                cid = _id(obj.get("toolCallId"))
                result = obj.get("result")
                if cid and isinstance(result, dict):
                    said = result.get("decision")
                    held.setdefault(cid, []).append(
                        said if isinstance(said, str) else None)
            elif kind in _RESETS:
                resets += 1
                settle()
            elif kind is not None and _no_call_type(kind):
                continue
            else:
                unknown()
        if first:
            self.count("unparsed", skipped.get("unparsed", 0))
        if not parsed and skipped.get("unparsed"):
            self._unreadable(store, "not JSON lines")
        settle()
        for key, call in calls.items():
            if key in outputs:
                call.output = outputs[key]
            elif key in replies:
                call.output = replies[key]
            # Declined only when every answer to its approval said no: a
            # call approved even once may have run.
            said = decisions.get(key)
            if (said and said <= _NOT_RUN) or (
                    key[0] == "message" and _never_dispatched(call)):
                call.status = "declined"
        for line_no, key in owner_keys.items():
            if key in calls:
                owners[line_no] = calls[key]
        return _Parsed(calls, owners)

    def _shell_call(self, store, message, stamp, first):
        """The ToolCall for a command the user typed in shell mode. Kimi
        Code runs it through its Bash tool."""
        command = _shell_command(message)
        if command is None:
            if first:
                self.count("unreadable_calls")
            return None
        if not command.strip():
            return None
        return self._call(store, "Bash", {"command": command}, None, stamp,
                          actor="user")

    def tool_calls(self, store):
        if store.role != "transcript":
            return
        try:
            parsed = self._collect(store)
        except OSError as e:
            self._unreadable(store, e.strerror or type(e).__name__)
            return
        for call in parsed.calls.values():
            yield call

    def secret_texts(self, store):
        try:
            if store.role == "transcript":
                items = self._wire_texts(store)
            elif store.format == "jsonl":
                items = self._json_lines(store)
            elif store.format == "json":
                items = self._json_document(store)
            else:
                items = self._text(store)
            for item in items:
                yield item
        except OSError as e:
            self._unreadable(store, e.strerror or type(e).__name__)

    def _wire_texts(self, store):
        """Every line of a transcript. A tool result (a tool.result event,
        or a message carrying a toolCallId) and a shell-mode command's
        output are credited to their call; a call's own input never is."""
        parsed = self._collect(store)
        for line_no, obj in _lines.iter_json_lines(store.path):
            yield SecretText(obj, call=parsed.owners.get(line_no),
                             where="line %d" % line_no)

    def _json_lines(self, store):
        """user-history: the migrator copies the legacy {"content"} lines;
        Kimi Code's own writer is unverified, so every line is walked as
        whatever JSON it holds."""
        for line_no, obj in _lines.iter_json_lines(store.path, self.counts):
            yield SecretText(obj, where="line %d" % line_no)

    def _json_document(self, store):
        with open(store.path, "rb") as fh:
            text = fh.read().decode("utf-8", "surrogateescape")
        try:
            doc = json.loads(text.lstrip(_lines.BOM))
        except (ValueError, RecursionError):
            if text.strip():
                self.count("unparsed")
                self._unreadable(store, "not JSON")
            return
        yield SecretText(doc, where=os.path.basename(store.path))

    def _spill_call(self, transcript, line_no):
        """The call a spill file is the output of: the call whose output is
        the transcript line that named it, or None when that line is not a
        call's output. The transcript is read once for every spill it names
        (cached by size and mtime), and only those lines are kept."""
        try:
            st = os.stat(transcript.path)
        except OSError:
            return None
        cache_key = (_key(transcript.path), st.st_size, st.st_mtime_ns)
        owners = self._spill_calls.get(cache_key)
        if owners is None:
            wanted = set(n for _p, n in self._named_spills(transcript.path))
            owners = {}
            try:
                parsed = self._collect(transcript)
            except OSError:
                parsed = None
            if parsed is not None:
                owners = dict((n, call) for n, call in parsed.owners.items()
                              if n in wanted)
            self._spill_calls[cache_key] = owners
        return owners.get(line_no)

    def _text(self, store):
        """A log or spill file, in blocks of whole lines. A spill file is a
        tool's full output, so it is credited to that call."""
        call = None
        spilled = self._spill_of.get(_key(store.path))
        if spilled:
            call = self._spill_call(*spilled)
        block, chars, first, line_no = [], 0, 1, 0
        with open(store.path, "rb") as fh:
            for line_no, raw in enumerate(fh, 1):
                if not block:
                    first = line_no
                text = raw.decode("utf-8", "surrogateescape")
                block.append(text)
                chars += len(text)
                if chars >= BLOCK_CHARS:
                    yield SecretText("".join(block), call=call,
                                     where=_lines_where(first, line_no))
                    block, chars = [], 0
        if block:
            yield SecretText("".join(block), call=call,
                             where=_lines_where(first, line_no))


def _lines_where(first, last):
    return "line %d" % first if first == last else "lines %d-%d" % (first, last)
