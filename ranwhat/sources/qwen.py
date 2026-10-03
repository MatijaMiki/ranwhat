"""Qwen Code (design 7.6): JSONL chat records, and the v0.3.x legacy JSON.

Qwen Code is a Gemini CLI fork. Since v0.4.0 every session is a JSONL file
of ChatRecords under projects/<sanitized>/chats/, appended to and fsynced a
line at a time. A tool call is a functionCall part of an "assistant"
record; its result is a later "tool_result" record that carries the same
id three times over (functionCall.id, functionResponse.id and
toolCallResult.callId). Before v0.4.0 a session was one Gemini-style JSON
document under tmp/<sha256>/chats/, rewritten whole.

The base folder is the first of QWEN_RUNTIME_DIR, QWEN_HOME and ~/.qwen.
The CLI also takes those two variables from the .env files in its home
folder and in the user's home (see dotenv()), so those files are read too,
for exactly those two names and nothing else. The settings key
advanced.runtimeOutputDir is not read: where its settings file lives was
not part of the research. Edit backups (file-history/) live under
QWEN_HOME or ~/.qwen even when the runtime folder is elsewhere.

Everything is read-only except mask(). file-history/ is never rewritten:
those are Qwen Code's own copies of files it edited, kept for /rewind. Nor
is a background shell's output, which may still be being written. A
session whose writer lock is held (see in_use()) is not rewritten either:
since v0.24 the CLI checks before every append that its transcript still
has the inode and length it left, and stops recording the session for good
when it does not.
"""

from __future__ import annotations

import glob
import json
import os
import re
import stat
import subprocess
import sys
from urllib.parse import quote

from . import _keyfile, _lines, _paths, _stamps
from .base import SecretText, Source, ToolCall, decode_input, newest_first

# The variables that move the folders, in the order they win.
RUNTIME_DIR = "QWEN_RUNTIME_DIR"
HOME_DIR = "QWEN_HOME"
NAMES = (RUNTIME_DIR, HOME_DIR)

# Tool names from the spec (tools/tool-names.ts), matched exactly. `exec`
# is code mode, not a shell: watch would take it for OpenClaw's shell if it
# were judged by name, so it is known and "other". `monitor` runs a
# long-lived shell command ({command, directory?, ...}, tools/monitor.ts)
# and is read exactly as run_shell_command is.
TOOLS = {
    "run_shell_command": "shell",
    "monitor": "shell",
    "read_file": "read",
    "write_file": "write",
    "edit": "write",
    "web_fetch": "fetch",
    "web_search": "fetch",
    "exec": "other",
    "grep_search": "other",
    "glob": "other",
    "list_directory": "other",
    "todo_write": "other",
    "save_memory": "other",
    "agent": "other",
    "skill": "other",
}

# Record types the spec describes. "user" and "system" hold no tool call.
RECORD_TYPES = ("user", "assistant", "tool_result", "system")

# Message types in a v0.3.x session file that hold tool calls: Gemini's
# "gemini", renamed.
LEGACY_TYPES = ("qwen",)

# A session file is named by its UUID. This keeps out <id>.ledger.jsonl,
# <id>.runtime.json and the temporary *.jsonl.stream files.
_SESSION_FILE = re.compile(r"[0-9a-fA-F-]{32,36}\.jsonl\Z")
# The pre-v0.4 project folder: the sha256 of the project root.
_PROJECT_HASH = re.compile(r"[0-9a-fA-F]{64}\Z")

# clean.MAX_STRING, which this package must not import at load time: an
# edit backup is read up to this many bytes, and a text store is handed to
# clean in pieces of about this many characters.
MAX_TEXT = 1000000

FILE_HISTORY_WHY = ("Qwen Code keeps these copies of files it edited so "
                    "/rewind can restore them. The secret is in the file "
                    "itself; remove it there.")

# A backgrounded shell's full output (tools/shell.ts executeBackground, and
# a foreground shell moved to the background): written as a stream for as
# long as the shell runs, and kept after. Nothing verified on disk says
# when the shell has stopped, and a replaced file would no longer get the
# rest of its output, so it is never rewritten.
BACKGROUND_SHELLS = "background-shells"
BACKGROUND_WHY = ("A shell Qwen Code started in the background may still be "
                  "writing to it, so ranwhat only reads it; stop that shell, "
                  "then delete the file.")

# read_file's path key. It was absolute_path up to v0.12.x (the v0.3.x
# legacy JSON and the first JSONL releases), file_path from v0.13.0.
READ_PATH_KEYS = ("file_path", "absolute_path")

# Where a session's writer lock lives, under the base folder its transcript
# is in (services/session-writer-lease.ts getSessionWriterLockPath):
# <base>/tmp/session-writer-locks/<encodeURIComponent(sessionId)>.lock.
LOCK_DIR = ("tmp", "session-writer-locks")
# A lock record is a few hundred bytes of JSON.
_LOCK_MAX = 1 << 16
# Characters encodeURIComponent leaves as they are, past letters, digits
# and "_.-~", which quote() never escapes.
_URI_SAFE = "!*'()"
# process_start_identity on Linux: linux:<boot id>:<start ticks>.
_LINUX_START = re.compile(r"linux:([0-9a-fA-F-]+):\d+\Z")

# dotenv 17's line grammar (lib/main.js LINE; the CLI depends on dotenv
# ^17.1.0, locked at 17.4.2), applied one line at a time: optional leading
# whitespace and `export `, then `=` or `: `, then a value that is quoted
# (', " or `) or runs to a `#` or the end of the line.
_DOTENV_LINE = re.compile(
    r"\s*(?:export\s+)?([\w.-]+)(?:\s*=\s*?|:\s+?)"
    r"(\s*'(?:\\'|[^'])*'|\s*\"(?:\\\"|[^\"])*\"|\s*`(?:\\`|[^`])*`"
    r"|[^#\r\n]+)?\s*(?:#.*)?\Z", re.ASCII)
_DOTENV_QUOTED = re.compile(r"(['\"`])(.*)\1\Z", re.DOTALL)


def _text(value):
    """The value when it is a non-empty string, else None."""
    return value if isinstance(value, str) and value else None


def _glob(base, *parts):
    """Paths matching parts under base, with base taken literally (a home
    directory may hold [ or *)."""
    return sorted(glob.glob(os.path.join(glob.escape(base), *parts)))


def _parts(record):
    """The parts of a record's message, or []."""
    message = record.get("message")
    parts = message.get("parts") if isinstance(message, dict) else None
    if not isinstance(parts, list):
        return []
    return [p for p in parts if isinstance(p, dict)]


def _response_id(part):
    """The id of a functionResponse part, or None."""
    response = part.get("functionResponse") if isinstance(part, dict) else None
    call_id = response.get("id") if isinstance(response, dict) else None
    return call_id if isinstance(call_id, str) else None


def _response_output(part):
    """The text a functionResponse part carried: response.output, else
    response.error. None when it holds neither as a string."""
    response = part.get("functionResponse")
    inner = response.get("response") if isinstance(response, dict) else None
    if isinstance(inner, dict):
        for key in ("output", "error"):
            value = inner.get(key)
            if isinstance(value, str):
                return value
    return None


def _lines_where(first, last):
    if first == last:
        return "line %d" % first
    return "lines %d-%d" % (first, last)


# -- the .env files the CLI reads at start ---------------------------------

def _dotenv_keys(path, names):
    """{name: value} for each of `names` that `path` sets, read as dotenv
    17 reads it: leading whitespace and an `export ` prefix are allowed,
    quotes (', " or `) are stripped, an unquoted value ends at `#`, a
    double-quoted one has \\n and \\r expanded, and the last setting of a
    name wins. Only lines that hold one of the names are matched; nothing
    else in the file is kept, logged or printed. (dotenv also lets a quoted
    value run over several lines; this reads one line at a time.) A file
    that cannot be read gives {}."""
    wanted = [n for n in names if n]
    found = {}
    if not wanted:
        return found
    try:
        with open(path, "r", encoding="utf-8", errors="replace",
                  newline="") as fh:
            text = fh.read(_keyfile.MAX_BYTES)
    except (OSError, ValueError):
        return found
    if text.startswith("\ufeff"):
        text = text[1:]         # JavaScript's \s takes it for a space
    for line in text.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        if not any(name in line for name in wanted):
            continue
        m = _DOTENV_LINE.match(line)
        if m is None or m.group(1) not in wanted:
            continue
        value = (m.group(2) or "").strip()
        quoted = _DOTENV_QUOTED.match(value)
        if quoted:
            value = quoted.group(2)
            if quoted.group(1) == '"':
                value = value.replace("\\n", "\n").replace("\\r", "\r")
        found[m.group(1)] = value
    return found


def _qwen_dir(value, home, platform):
    """A QWEN_HOME value as the CLI resolves it (Storage.resolvePath): a
    leading ~ is the home directory. A relative path is left relative, so
    it is taken from the current directory, as the CLI takes it."""
    if value == "~" or value.startswith("~/") or value.startswith("~\\"):
        parts = [p for p in re.split(r"[/\\]+", value[2:]) if p]
        return _paths.join(platform, home, *parts)
    return value


def _same_dir(a, b, platform):
    mod = _paths.pathmod(platform)
    return mod.normcase(mod.normpath(a)) == mod.normcase(mod.normpath(b))


# -- whether a session's writer is alive -----------------------------------

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
    tasklist (as the Copilot CLI and Muse Code adapters do). Unsure counts
    as alive."""
    try:
        out = subprocess.run(
            ["tasklist", "/FI", "PID eq %d" % pid, "/NH", "/FO", "CSV"],
            executable=_paths.system32("tasklist"),
            capture_output=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return True
    if out.returncode != 0:
        return True
    return ('"%d"' % pid) in out.stdout.decode("ascii", "replace")


def _hostname():
    """This machine's name as the CLI records it (Node's os.hostname(), that
    is gethostname()), or None. uname's nodename is the same name on Linux
    and macOS; Windows has no uname, and its hostname command prints
    gethostname()."""
    if hasattr(os, "uname"):
        return os.uname().nodename or None
    try:
        out = subprocess.run(["hostname"],
                             executable=_paths.system32("hostname"),
                             capture_output=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return None
    if out.returncode != 0:
        return None
    return out.stdout.decode("utf-8", "replace").strip() or None


def _boot_id():
    """This Linux boot's id (utils/process-liveness.ts readLocalBootId), or
    None."""
    try:
        with open("/proc/sys/kernel/random/boot_id", "r",
                  encoding="utf-8") as fh:
            value = fh.read(256).strip()
    except (OSError, ValueError):
        return None
    return value if re.match(r"[0-9a-fA-F-]+\Z", value) else None


def _pid_namespace():
    """This process's Linux pid namespace id (readPidNamespaceId), or
    None."""
    try:
        return os.stat("/proc/self/ns/pid").st_ino
    except (OSError, ValueError):
        return None


def _writer_live(record, platform=None):
    """Whether the writer an active lock record names may still be running,
    judged as Qwen Code judges it before it reclaims a lock
    (lockStateForRecord): a lock taken on another host, or on Linux in
    another boot or pid namespace, is live; otherwise it is live while its
    pid is. (Qwen Code also takes a reused pid for stale; here a running
    pid is enough, which can only make clean more careful.)"""
    if record["hostname"] != _hostname():
        return True
    platform = sys.platform if platform is None else platform
    if platform.startswith("linux"):
        boot, namespace = _boot_id(), _pid_namespace()
        identity = record.get("process_start_identity")
        m = _LINUX_START.match(identity) if isinstance(identity, str) else None
        recorded = record.get("pid_namespace_id")
        if (boot is None or namespace is None or m is None
                or m.group(1).lower() != boot.lower()
                or isinstance(recorded, bool) or recorded != namespace):
            return True
    return _pid_alive(record["pid"])


class QwenSource(Source):
    id = "qwen"
    name = "Qwen Code"
    unit = "session"
    env = NAMES
    path_means = "a Qwen Code folder (the one holding projects/ and tmp/)"
    checked = "v0.24.7"

    # -- where to look ------------------------------------------------------

    def default_paths(self, env, home, platform, dotenv=None):
        """Pure. [(path, how)]: the runtime folder (QWEN_RUNTIME_DIR, else
        QWEN_HOME, else ~/.qwen), then the home folder that keeps edit
        backups (QWEN_HOME, else ~/.qwen), then ~/.qwen itself; repeats
        dropped. ~/.qwen is always probed: sessions written before a
        variable was set stay there.

        dotenv is {name: (value, file)} from dotenv(); a variable set in the
        environment wins over the same one in a file."""
        dotenv = dotenv or {}

        def setting(name):
            value = _text(env.get(name))
            if value:
                return value, "env %s" % name
            value, where = dotenv.get(name, (None, None))
            if _text(value):
                return value, "%s in %s" % (name, where)
            return None

        default = (_paths.join(platform, home, ".qwen"), "default")
        qwen_home = setting(HOME_DIR) or default
        runtime = setting(RUNTIME_DIR) or qwen_home
        out = []
        for path, how in (runtime, qwen_home, default):
            if path not in [p for p, _h in out]:
                out.append((path, how))
        return out

    def dotenv(self, home, platform=None, env=None):
        """{name: (value, file)} for QWEN_RUNTIME_DIR and QWEN_HOME as the
        CLI takes them from .env files when they are not set (or are empty)
        in `env` (default os.environ). Only lines that hold one of those two
        names are matched (_dotenv_keys); nothing else is kept.

        The files, in the order the CLI reads them, the first to set a name
        winning (packages/cli/src/config/environment.ts):
        - QWEN_HOME not set: ~/.qwen/.env, then ~/.env
          (preResolveHomeEnvOverrides); and when one of those set QWEN_HOME,
          the .env in that folder.
        - QWEN_HOME set: $QWEN_HOME/.env (preResolveHomeEnvOverrides), then
          ~/.qwen/.env when that is another folder, then ~/.env
          (loadEnvironment, which reads the same user-level files later in
          start-up).
        A project's own .env never sets either name (the CLI refuses
        them there), so none is read. With both names set, no file is."""
        env = os.environ if env is None else env
        if all(_text(env.get(name)) for name in NAMES):
            return {}
        default = _paths.join(platform, home, ".qwen")
        set_home = _text(env.get(HOME_DIR))
        first = _qwen_dir(set_home, home, platform) if set_home else default
        files = [_paths.join(platform, first, ".env")]
        if set_home and not _same_dir(first, default, platform):
            files.append(_paths.join(platform, default, ".env"))
        files.append(_paths.join(platform, home, ".env"))

        found = {}

        def read(path):
            for name, value in _dotenv_keys(path, NAMES).items():
                if (_text(value) and name not in found
                        and not _text(env.get(name))):
                    found[name] = (value, path)

        for path in files:
            read(path)
        if HOME_DIR in found:
            found_home = _qwen_dir(found[HOME_DIR][0], home, platform)
            if not _same_dir(found_home, first, platform):
                read(_paths.join(platform, found_home, ".env"))
        return found

    def locations(self, override=None, projects=()):
        """As Source.locations, with the two variables also taken from the
        .env files the CLI reads them from, at call time."""
        if override:
            return Source.locations(self, override, projects)
        try:
            home = _paths.home()
            platform = _paths.platform_name()
            pairs = self.default_paths(os.environ, home, platform,
                                       self.dotenv(home, platform, os.environ))
        except Exception as e:      # one adapter must not stop the others
            self.warn("locations", "could not work out where %s keeps its "
                      "history (%s)" % (self.name, e))
            return []
        # The base class expands, de-duplicates, stats and counts; only the
        # reason each path is looked at is put back.
        found = Source.locations(self, [p for p, _how in pairs])
        how = {}
        for path, why in pairs:
            key = os.path.normcase(os.path.abspath(os.path.expanduser(path)))
            how.setdefault(key, why)
        for loc in found:
            loc.how = how.get(os.path.normcase(loc.path), loc.how)
        return found

    # -- stores -------------------------------------------------------------

    def stores(self, locations, since_days=None):
        found, seen = [], set()

        def add(path, format, **fields):
            key = os.path.normcase(os.path.realpath(path))
            if key in seen or not os.path.isfile(path):
                return
            seen.add(key)
            store = self.store(path, format, **fields)
            if store:
                found.append(store)

        for loc in locations:
            base = loc.path
            if not os.path.isdir(base):
                continue
            for chats in (("chats",), ("chats", "archive")):
                for path in _glob(base, "projects", "*", *chats + ("*.jsonl",)):
                    name = os.path.basename(path)
                    if _SESSION_FILE.match(name):
                        add(path, "jsonl", session=name[:-len(".jsonl")])
            for path in _glob(base, "projects", "*", "subagents", "*",
                              "agent-*.jsonl"):
                add(path, "jsonl",
                    session=os.path.basename(os.path.dirname(path)))
            for folder in _glob(base, "tmp", "*"):
                if (not _PROJECT_HASH.match(os.path.basename(folder))
                        or not os.path.isdir(folder)):
                    continue
                for path in _glob(folder, "chats", "session-*.json"):
                    add(path, "json")
                # <tool name>_<12 hex>.output: the full output of any tool
                # whose result was cut short (tools/truncation.ts), not only
                # run_shell_command's.
                for pattern in ("*.output",
                                os.path.join("tool-results", "*.txt"),
                                "shell_history"):
                    for path in _glob(folder, pattern):
                        add(path, "text", role="side", unit="file")
                for path in _glob(folder, BACKGROUND_SHELLS, "*", "shell-*.output"):
                    add(path, "text", role="side", unit="file",
                        session=os.path.basename(os.path.dirname(path)),
                        masking="read-only", why_read_only=BACKGROUND_WHY)
                # checkpoints/*.json: with checkpointing on, the history and
                # the pending call, saved before each file-changing tool runs
                # (storage.ts getProjectTempCheckpointsDir; /restore reads
                # the .json files there).
                for pattern in ("logs.json", "checkpoint-*.json",
                                os.path.join("checkpoints", "*.json")):
                    for path in _glob(folder, pattern):
                        add(path, "json", role="side", unit="file")
            for path in _glob(base, "debug", "*.txt"):
                add(path, "text", role="side", unit="file",
                    session=os.path.basename(path)[:-len(".txt")])
            for folder in _glob(base, "file-history", "*"):
                if os.path.islink(folder) or not os.path.isdir(folder):
                    continue
                session = os.path.basename(folder)
                for path in self._backups(folder):
                    add(path, "text", role="side", unit="file",
                        session=session, masking="read-only",
                        why_read_only=FILE_HISTORY_WHY)
        return newest_first(found, since_days)

    @staticmethod
    def _backups(folder):
        """Every regular file under one session's file-history folder. The
        layout below it is unverified, so all of it; symlinks are not
        followed out of it."""
        for top, dirs, files in os.walk(folder):
            dirs[:] = sorted(d for d in dirs
                             if not os.path.islink(os.path.join(top, d)))
            for name in sorted(files):
                path = os.path.join(top, name)
                try:
                    if stat.S_ISREG(os.lstat(path).st_mode):
                        yield path
                except OSError:
                    continue

    # -- tool calls ---------------------------------------------------------

    def _call(self, store, function_call, session, project, stamp):
        """A ToolCall for one functionCall {id, name, args}, or None when it
        has no name. A call with no time gets the last write of its file as
        the latest it can have happened."""
        name = _text(function_call.get("name"))
        if name is None:
            self.count("unreadable_calls")
            return None
        args = decode_input(function_call.get("args"))
        kind = TOOLS.get(name)
        command = workdir = None
        paths, consumed = (), ()
        if kind == "shell":
            command = _text(args.get("command"))
            if command:
                consumed = ("command",)
            workdir = _text(args.get("directory"))
        elif kind == "read":
            for key in READ_PATH_KEYS:
                path = _text(args.get(key))
                if path:
                    paths, consumed = (path,), (key,)
                    break
        elif kind == "write":
            path = _text(args.get("file_path"))
            if path:
                paths = (path,)
        call_id = function_call.get("id")
        return ToolCall(
            self.id, store.path, name, args,
            kind=kind or "other", known=kind is not None,
            session=session, project=project, timestamp=stamp,
            not_after=None if stamp else self._undated(store),
            tool_call_id=call_id if isinstance(call_id, str) else None,
            command=command, workdir=workdir, paths=paths, consumed=consumed)

    def _undated(self, store):
        """For a call with no time of its own: the last write of its file."""
        return _stamps.iso_utc(store.mtime, "s") if store.mtime else None

    def _unreadable(self, store, reason, detail):
        """Warn once per store and count it once per run."""
        if store.path not in self._warned:
            self.unreadable_store(reason, store.path)
        self.warn(store.path, "cannot read %s (%s)" % (store.path, detail))

    def _failed(self, store, error):
        """A store that could not be opened, or a whole-file store that is
        not JSON."""
        if isinstance(error, OSError):
            self._unreadable(store, "could not be read", error)
        else:
            self._unreadable(store, "not JSON", "not JSON")

    def _records(self, store):
        """Yield (line_no, value) for every line that is JSON, counting the
        ones that are not a record of a type the spec describes. Warns when
        no line parses at all: the file is not JSON Lines."""
        before = self.counts.get("unparsed", 0)
        parsed = 0
        for line_no, record in _lines.iter_json_lines(store.path, self.counts):
            parsed += 1
            if (not isinstance(record, dict)
                    or record.get("type") not in RECORD_TYPES):
                self.count("unknown")
            yield line_no, record
        if not parsed and self.counts.get("unparsed", 0) > before:
            self._unreadable(store, "not JSON Lines", "not JSON Lines")

    def _record_call(self, store, record, part):
        """The ToolCall for a functionCall part of a ChatRecord."""
        return self._call(
            store, part["functionCall"],
            _text(record.get("sessionId")) or store.session,
            _text(record.get("cwd")) or store.project,
            _stamps.iso_utc(record.get("timestamp"), "iso"))

    def tool_calls(self, store):
        if store.role != "transcript":
            return
        try:
            if store.format == "json":
                calls = self._legacy_calls(store)
            else:
                calls = self._jsonl_calls(store)
        except (OSError, ValueError, RecursionError) as e:
            self._failed(store, e)
            return
        for call in calls:
            yield call

    def _jsonl_calls(self, store):
        """Every call in a JSONL session, each id once, with its output."""
        calls, by_id = [], {}
        for _line_no, record in self._records(store):
            if not isinstance(record, dict):
                continue
            kind = record.get("type")
            if kind == "assistant":
                for part in _parts(record):
                    if not isinstance(part.get("functionCall"), dict):
                        continue
                    call = self._record_call(store, record, part)
                    if call is None:
                        continue
                    if call.tool_call_id is not None:
                        if call.tool_call_id in by_id:
                            continue        # a replayed or copied record
                        by_id[call.tool_call_id] = call
                    calls.append(call)
            elif kind == "tool_result":
                for call_id, text in self._outputs(record):
                    call = by_id.get(call_id)
                    if call is not None and call.output is None:
                        call.output = text
        return calls

    @staticmethod
    def _outputs(record):
        """[(call id, text)] from a tool_result record: each
        functionResponse's output, then toolCallResult.resultDisplay when it
        is a string."""
        out = []
        for part in _parts(record):
            call_id, text = _response_id(part), _response_output(part)
            if call_id is not None and text is not None:
                out.append((call_id, text))
        result = record.get("toolCallResult")
        if isinstance(result, dict) and isinstance(result.get("callId"), str):
            display = result.get("resultDisplay")
            if isinstance(display, str):
                out.append((result["callId"], display))
        return out

    # -- the v0.3.x layout --------------------------------------------------

    def _load(self, store):
        """The decoded JSON document of a whole-file store."""
        with open(store.path, "rb") as fh:
            text = fh.read().decode("utf-8", "surrogateescape")
        return json.loads(text[1:] if text.startswith(_lines.BOM) else text)

    @staticmethod
    def _legacy_messages(doc):
        """Yield (index, message, entries) for each message of a v0.3.x
        session document; entries is its toolCalls list when the message is
        of a type that carries calls, else None."""
        for index, message in enumerate(doc.get("messages") or ()):
            entries = None
            if isinstance(message, dict) and message.get("type") in LEGACY_TYPES:
                entries = message.get("toolCalls")
            yield index, message, entries if isinstance(entries, list) else None

    def _legacy_call(self, store, session, message, entry):
        """The ToolCall for one toolCalls entry {id, name, args, timestamp}:
        its own time, else its message's."""
        stamp = (_stamps.iso_utc(entry.get("timestamp"), "iso")
                 or _stamps.iso_utc(message.get("timestamp"), "iso"))
        return self._call(store, entry, session, store.project, stamp)

    def _legacy_calls(self, store):
        doc = self._load(store)
        if not isinstance(doc, dict) or not isinstance(doc.get("messages"), list):
            self.count("unknown")
            return []
        session = _text(doc.get("sessionId")) or store.session
        calls, seen = [], set()
        for _index, message, entries in self._legacy_messages(doc):
            for entry in entries or ():
                if not isinstance(entry, dict):
                    continue
                call = self._legacy_call(store, session, message, entry)
                if call is None:
                    continue
                if call.tool_call_id is not None:
                    if call.tool_call_id in seen:
                        continue
                    seen.add(call.tool_call_id)
                call.output = self._legacy_output(entry)
                calls.append(call)
        return calls

    @staticmethod
    def _legacy_output(entry):
        """result[i].functionResponse.response.output (or error), else
        resultDisplay when it is a string."""
        result = entry.get("result")
        for part in result if isinstance(result, list) else ():
            if not isinstance(part, dict):
                continue
            text = _response_output(part)
            if text is not None:
                return text
        display = entry.get("resultDisplay")
        return display if isinstance(display, str) else None

    # -- secrets ------------------------------------------------------------

    def secret_texts(self, store):
        try:
            if store.format == "jsonl":
                texts = self._jsonl_texts(store)
            elif store.format == "json" and store.role == "transcript":
                texts = self._legacy_texts(store)
            elif store.format == "json":
                texts = iter([SecretText(self._load(store), where="file")])
            elif store.why_read_only == FILE_HISTORY_WHY:
                texts = self._head_texts(store)
            else:
                texts = self._line_texts(store)
            for text in texts:
                yield text
        except (OSError, ValueError, RecursionError) as e:
            self._failed(store, e)

    def _jsonl_texts(self, store):
        """Every line. A tool_result record's parts and toolCallResult go
        with the call they answer; everything else, a call's own input
        included, goes with no call."""
        calls = {}
        for line_no, record in self._records(store):
            where = "line %d" % line_no
            if not isinstance(record, dict) or record.get("type") != "tool_result":
                if isinstance(record, dict) and record.get("type") == "assistant":
                    for part in _parts(record):
                        if isinstance(part.get("functionCall"), dict):
                            call = self._record_call(store, record, part)
                            if call is not None and call.tool_call_id is not None:
                                calls.setdefault(call.tool_call_id, call)
                yield SecretText(record, where=where)
                continue
            result = record.get("toolCallResult")
            answered = None
            if isinstance(result, dict) and isinstance(result.get("callId"), str):
                answered = calls.get(result["callId"])
            rest = {k: v for k, v in record.items()
                    if k not in ("message", "toolCallResult")}
            message = record.get("message")
            parts = message.get("parts") if isinstance(message, dict) else None
            if isinstance(parts, list):
                rest["message"] = {k: v for k, v in message.items()
                                   if k != "parts"}
            else:
                rest["message"] = message
                parts = []
            yield SecretText(rest, where=where)
            for part in parts:
                call = calls.get(_response_id(part)) or answered
                yield SecretText(part, call=call, where=where)
            if result is not None:
                yield SecretText(result, call=answered, where=where)

    def _legacy_texts(self, store):
        """A v0.3.x session: each call's result and resultDisplay with that
        call; the rest of the document, the calls' own input included, with
        no call."""
        doc = self._load(store)
        if not isinstance(doc, dict) or not isinstance(doc.get("messages"), list):
            yield SecretText(doc, where="file")
            return
        yield SecretText({k: v for k, v in doc.items() if k != "messages"},
                         where="file")
        session = _text(doc.get("sessionId")) or store.session
        for index, message, entries in self._legacy_messages(doc):
            where = "message %d" % (index + 1)
            if entries is None:
                yield SecretText(message, where=where)
                continue
            yield SecretText({k: v for k, v in message.items()
                              if k != "toolCalls"}, where=where)
            for entry in entries:
                if not isinstance(entry, dict):
                    yield SecretText(entry, where=where)
                    continue
                output = {k: entry[k] for k in ("result", "resultDisplay")
                          if k in entry}
                yield SecretText({k: v for k, v in entry.items()
                                  if k not in output}, where=where)
                if output:
                    call = self._legacy_call(store, session, message, entry)
                    yield SecretText(output, call=call, where=where)

    def _line_texts(self, store):
        """A text store in pieces of whole lines, about MAX_TEXT characters
        each, so a large spill file is never one string."""
        with open(store.path, "rb") as fh:
            piece, size, first = [], 0, 1
            for line_no, raw in enumerate(fh, 1):
                text = raw.decode("utf-8", "surrogateescape")
                if piece and size + len(text) > MAX_TEXT:
                    yield SecretText("".join(piece),
                                     where=_lines_where(first, line_no - 1))
                    piece, size, first = [], 0, line_no
                piece.append(text)
                size += len(text)
            if piece:
                yield SecretText("".join(piece), where=_lines_where(
                    first, first + len(piece) - 1))

    def _head_texts(self, store):
        """An edit backup: its first MAX_TEXT bytes, as text."""
        with open(store.path, "rb") as fh:
            data = fh.read(MAX_TEXT)
        if data:
            yield SecretText(data.decode("utf-8", "surrogateescape"),
                             where="file")

    # -- masking ------------------------------------------------------------

    @staticmethod
    def lock_path(path):
        """The writer lock of the session a JSONL transcript belongs to, or
        None for any other file. A session's own file
        (projects/<p>/chats/<id>.jsonl, or chats/archive/) and its
        subagents' (projects/<p>/subagents/<id>/agent-*.jsonl) share the
        session's lock, which sits under the same base folder:
        <base>/tmp/session-writer-locks/<encodeURIComponent(id)>.lock."""
        if not path.endswith(".jsonl"):
            return None
        folder = os.path.dirname(path)
        if os.path.basename(folder) == "chats":
            session = os.path.basename(path)[:-len(".jsonl")]
            project = os.path.dirname(folder)
        elif (os.path.basename(folder) == "archive"
                and os.path.basename(os.path.dirname(folder)) == "chats"):
            session = os.path.basename(path)[:-len(".jsonl")]
            project = os.path.dirname(os.path.dirname(folder))
        elif os.path.basename(os.path.dirname(folder)) == "subagents":
            session = os.path.basename(folder)
            project = os.path.dirname(os.path.dirname(folder))
        else:
            return None
        projects = os.path.dirname(project)
        if os.path.basename(projects) != "projects" or not session:
            return None
        try:
            name = quote(session, safe=_URI_SAFE) + ".lock"
        except (UnicodeError, TypeError):
            return None             # no lock can have been named for it
        return os.path.join(os.path.dirname(projects), *LOCK_DIR + (name,))

    def in_use(self, store):
        """True while Qwen Code holds the writer lock of the store's session.

        Since v0.24 every append goes through a writer lease that first
        checks the transcript still has the inode and length it left after
        the previous write; a rewrite changes both, and the CLI then drops
        every later record of the session. So a transcript whose lock
        exists is in use when the lock is active and its writer may be
        alive (_writer_live), when it is sealed for a hand-over (the next
        writer checks the transcript's length and sha256 against the seal),
        and when it cannot be read or is not a lock record: unsure counts
        as in use, as it can only make clean more careful. The 120-second
        rule applies as well. Legacy JSON and side stores have no lease."""
        if store.format != "jsonl" or store.role != "transcript":
            return False
        lock = self.lock_path(store.path)
        if lock is None:
            return False
        try:
            st = os.lstat(lock)
        except (FileNotFoundError, NotADirectoryError):
            return False
        except OSError:
            return True
        if not stat.S_ISREG(st.st_mode):
            return True             # the CLI refuses such a lock too
        try:
            with open(lock, "rb") as fh:
                data = fh.read(_LOCK_MAX)
        except FileNotFoundError:
            return False            # released since
        except OSError:
            return True
        try:
            record = json.loads(data.decode("utf-8", "replace"))
        except (ValueError, RecursionError):
            return True
        if (not isinstance(record, dict)
                or record.get("state") not in (None, "active")):
            return True             # sealed, or not a lock record
        pid, host = record.get("pid"), record.get("hostname")
        if (isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0
                or not _text(host)):
            return True
        return _writer_live(record)
