"""OpenAI Codex: the Rust CLI, its IDE extension and desktop app.

All three write the same store under CODEX_HOME (default ~/.codex):

- sessions/YYYY/MM/DD/rollout-*.jsonl, one thread per file, append-only.
  A line is {"timestamp", "type", "payload"} (plus "ordinal" in paginated
  files). Older files are older shapes: early Rust builds wrote a flat
  sessions/rollout-*.jsonl of bare items under a bare {id, timestamp,
  instructions} header, and the TypeScript CLI one JSON document
  sessions/rollout-*.json, {"session": {...}, "items": [...]}.
- rollout-*.jsonl.zst, when Codex compressed a thread idle for a week.
  Read when a zstd decoder exists, never rewritten.
- archived_sessions/rollout-*, a flat folder of archived threads.
- history.jsonl (typed prompts) and shell_snapshots/*.sh, *.ps1 (the
  user's exported variables): for clean only.
- thread_history_1.sqlite and state_5.sqlite in the SQLite home
  (config.toml's sqlite_home, else CODEX_SQLITE_HOME, else CODEX_HOME,
  the order Codex itself uses): for clean only, read-only.

Never opened: auth.json, session_index.jsonl, logs_2.sqlite, the legacy
log/codex-tui.log, and every other file. config.toml is parsed for the
one key sqlite_home, with tomllib, so only on Python 3.11 and later.
thread-writer-locks/<thread id>.lock is stat'ed, never opened: Codex
holds it while it can still append to that thread's rollout.

Two things a rollout holds are not this thread's own calls: a copy of an
ancestor's history (a fork made from a rollout path, a subagent given its
parent's context), which Codex writes with the time of the copy; and the
user message that records a command the user ran with `!`, which is the
only record of it in the default (legacy) history mode.

Checked against rust-v0.159.3 (design section 7.3).
"""

from __future__ import annotations

import collections
import glob
import hashlib
import importlib
import io
import json
import os
import re
import sqlite3

from . import _keyfile, _lines, _paths, _shell, _sqlite, _stamps, _zstd, base
from .base import Location, MaskResult, SecretText, Source, ToolCall

SESSION_TYPES = ("session_meta", "turn_context", "response_item", "event_msg",
                 "compacted")
# Envelope types the current release writes that never hold a tool call:
# read by clean like every line, and not counted as unknown.
QUIET_TYPES = ("inter_agent_communication", "inter_agent_communication_metadata",
               "token_usage_record", "world_state", "retained_context",
               "security_risk_score", "realtime_item")

# ResponseItem types that are calls, and the outputs that answer them.
CALL_ITEMS = ("function_call", "custom_tool_call", "local_shell_call",
              "web_search_call")
OUTPUT_ITEMS = ("function_call_output", "custom_tool_call_output")
# ResponseItem types that are neither: not counted as unknown.
# "compaction_summary" is an older name of "compaction". A user "message"
# can still record a command the user ran (USER_SHELL_MARKERS).
OTHER_ITEMS = ("message", "reasoning", "compaction", "compaction_summary",
               "agent_message", "tool_search_call", "tool_search_output",
               "image_generation_call", "configuration_update",
               "context_compaction")

# A command the user ran with `!` is recorded as a user message whose text
# is "<user_shell_command>\n<command>\nCMD\n</command>\n<result>\nExit code:
# N\nDuration: S seconds\nOutput:\nOUT\n</result>\n</user_shell_command>",
# classified "shell.user_command" by releases that classify content.
USER_SHELL_KIND = "shell.user_command"
USER_SHELL_MARKERS = ("<user_shell_command>", "</user_shell_command>")
_COMMAND_OPEN = "\n<command>\n"
_COMMAND_CLOSE = "\n</command>\n<result>\n"
_RESULT_OUTPUT = "\nOutput:\n"
_RESULT_CLOSE = "\n</result>"

# The fields of a CommandExecution item that hold what the command printed.
OUTPUT_FIELDS = ("stdout", "stderr", "aggregated_output", "formatted_output")

# <CODEX_HOME>/thread-writer-locks/<thread id>.lock: present while a Codex
# process owns that thread and may append to its rollout.
LOCK_DIR = "thread-writer-locks"

# From this release on, a copy of an ancestor's history ends with a
# thread_settings_applied event that carries the copying thread's own id.
# Copies written by older releases have no such end and are left as they
# are (their calls are still reported).
COPY_MARKER_SINCE = (0, 152, 0)

# function_call names whose arguments carry a shell command, and the key
# that carries it. shell (rust-v0.50 to 0.80) carries an argv.
SHELL_FUNCTIONS = {"exec_command": "cmd", "shell": "command",
                   "shell_command": "command"}

# The SQLite home's files, the one table each is read from, and its columns.
DATABASES = (("thread_history_1.sqlite", "thread_items", ("item_json",)),
             ("state_5.sqlite", "threads", ("title", "first_user_message")))

ENCRYPTED = "encrypted_content"

SQLITE_MAGIC = b"SQLite format 3\x00"

WHY_ZST = ("Compressed by Codex. Resume the thread in Codex, which restores "
           "it as plain JSONL, then run clean again.")
WHY_SNAPSHOT = ("Codex's snapshot of your shell's exported variables, deleted "
                "after 3 days. The value is set in your shell environment; "
                "remove it there and rotate it.")
WHY_SQLITE = ("Codex's own index of this thread. Delete or archive the thread "
              "in Codex to remove it.")

NOT_DECOMPRESSED = "compressed, and the zstd data could not be decompressed"
NOT_JSONL = "not JSON Lines"
NOT_JSON = "not a Codex session document"
NOT_DATABASE = "not a readable SQLite database"

_UUID = r"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}"
_THREAD_ID = re.compile(_UUID + r"\Z")
# rollout-2026-10-01T14-00-00-<uuid>.jsonl, and the post-revert
# rollout-<ts>-<uuid>_<rollout uuid>.jsonl: the first uuid is the thread.
_ROLLOUT_NAME = re.compile(
    r"rollout-\d{4}-\d\d-\d\dT\d\d-\d\d-\d\d-(" + _UUID + r")")
# shell_snapshots/<thread_id>.<nonce>.sh
_SNAPSHOT_NAME = re.compile(r"(" + _UUID + r")\.")
# session_meta.cli_version: "0.159.3", or a pre-release "0.152.0-alpha.3".
_VERSION = re.compile(r"(\d+)\.(\d+)\.(\d+)(-\S*)?\Z")

# A config.toml past this is not one. A session_meta line past this is read
# no further when looking for a store's working directory.
CONFIG_MAX = 1 << 20
HEAD_MAX = 4 << 20
SNAPSHOT_MAX = 16 << 20

# encrypted_content is dropped this deep and no deeper: past it a structure
# is not anything Codex wrote.
_STRIP_DEPTH = 64

_BAD = object()     # a line that is not JSON


def _env(env, name, strip=False):
    """The variable when set and not empty. Codex trims CODEX_SQLITE_HOME
    (strip=True) but takes CODEX_HOME as it is."""
    value = env.get(name)
    if isinstance(value, str) and strip:
        value = value.strip()
    return value if isinstance(value, str) and value else None


def _is_int(value):
    return isinstance(value, int) and not isinstance(value, bool)


def _release_at_least(text, floor):
    """True when `text` names a Codex release at or after `floor`. A
    pre-release comes before its release, and a build that does not say
    (or says 0.0.0, a local build) is not trusted."""
    match = _VERSION.match(text.strip()) if isinstance(text, str) else None
    if not match:
        return False
    version = tuple(int(part) for part in match.groups()[:3])
    return version > floor if match.group(4) else version >= floor


def _codex_home_of(path):
    """The CODEX_HOME a rollout sits in: the folder that holds its
    sessions/ (date folders or flat) or archived_sessions/. None when the
    path is not laid out that way."""
    folder = os.path.dirname(os.path.abspath(path))
    for _depth in range(4):         # sessions/YYYY/MM/DD at most
        if os.path.basename(folder) in ("sessions", "archived_sessions"):
            return os.path.dirname(folder)
        folder = os.path.dirname(folder)
    return None


def _resolve_config_path(value, base_dir, home):
    """A path from config.toml as Codex reads it: a leading ~ or ~/ is the
    home directory; a relative path is taken from the folder that holds
    config.toml; .. is folded away."""
    if value.startswith("~"):
        rest = value[1:]
        if not rest:
            value = home
        elif rest[0] == "/":
            value = os.path.join(home, rest.lstrip("/"))
        elif os.name == "nt" and rest[0] == "\\":
            value = os.path.join(home, rest.lstrip("\\"))
    if not os.path.isabs(value):
        value = os.path.join(base_dir, value)
    return os.path.normpath(value)


def _user_shell_command(text):
    """(command, split) when `text` is Codex's record of a command the user
    ran with `!`: the command, and where the text of its result begins (the
    exit code, duration and output, none of which the user typed). None
    for any other text."""
    if not isinstance(text, str):
        return None
    opener, closer = USER_SHELL_MARKERS
    stripped = text.strip()
    if (len(stripped) < len(opener) + len(closer)
            or stripped[:len(opener)].lower() != opener
            or stripped[-len(closer):].lower() != closer):
        return None
    start = text.find(_COMMAND_OPEN)
    if start < 0:
        return None
    start += len(_COMMAND_OPEN)
    end = text.find(_COMMAND_CLOSE, start)
    if end <= start:
        return None
    return text[start:end], end + len("\n</command>\n")


def _result_output(result):
    """What the command printed, from the result part of a user shell
    record; the whole part when it is not laid out as Codex writes it."""
    start = result.find(_RESULT_OUTPUT)
    end = result.rfind(_RESULT_CLOSE)
    if start < 0 or end < start + len(_RESULT_OUTPUT):
        return result
    return result[start + len(_RESULT_OUTPUT):end]


def _user_shell_records(item):
    """[(index, command, split)] for each content entry of a user message
    that records a command the user ran. When the message says what each
    entry is (content_item_kinds), only an entry marked shell.user_command
    counts; older messages are recognised by their markers alone."""
    if item.get("role") != "user" or not isinstance(item.get("content"), list):
        return []
    passthrough = item.get("internal_chat_message_metadata_passthrough")
    kinds = (passthrough.get("content_item_kinds")
             if isinstance(passthrough, dict) else None)
    kinds = kinds if isinstance(kinds, list) else None
    out = []
    for index, entry in enumerate(item["content"]):
        if not (isinstance(entry, dict) and entry.get("type") == "input_text"):
            continue
        if kinds is not None and (index >= len(kinds)
                                  or kinds[index] != USER_SHELL_KIND):
            continue
        found = _user_shell_command(entry.get("text"))
        if found:
            out.append((index,) + found)
    return out


def _script(command):
    """The script a user shell command ran: Codex puts it last in the argv
    for every shell it runs (sh -lc, pwsh -Command, cmd /c)."""
    if isinstance(command, (list, tuple)) and command and isinstance(command[-1], str):
        return command[-1]
    return command if isinstance(command, str) else None


def _tomllib():
    """The standard library's TOML reader (Python 3.11+), or None."""
    try:
        return importlib.import_module("tomllib")
    except ImportError:
        return None


def _str(value):
    return value if isinstance(value, str) and value else None


def _is_db_home(loc):
    return loc.how == "env CODEX_SQLITE_HOME" or loc.how.startswith("config ")


def _without_encrypted(node, depth=0):
    """`node` with every value under a key named encrypted_content left
    out: opaque data the server encrypted, never a readable secret."""
    if depth > _STRIP_DEPTH:
        return node
    if isinstance(node, dict):
        return {k: _without_encrypted(v, depth + 1)
                for k, v in node.items() if k != ENCRYPTED}
    if isinstance(node, list):
        return [_without_encrypted(v, depth + 1) for v in node]
    return node


def _json_value(text):
    """A string that is a JSON object or array, decoded; else None."""
    if not isinstance(text, str) or text.lstrip()[:1] not in ("{", "["):
        return None
    try:
        value = json.loads(text)
    except (ValueError, RecursionError):
        return None
    return value if isinstance(value, (dict, list)) else None


def output_text(output):
    """The text of a function_call_output or custom_tool_call_output.

    A string, or (rust-v0.50) a string holding {"output": ..., "metadata":
    {...}}, whose output is used; or a list of input_text items, joined.
    None for anything else."""
    if isinstance(output, str):
        decoded = _json_value(output)
        if (isinstance(decoded, dict) and isinstance(decoded.get("output"), str)
                and isinstance(decoded.get("metadata"), dict)):
            return decoded["output"]
        return output
    if isinstance(output, list):
        texts = [item["text"] for item in output
                 if isinstance(item, dict) and item.get("type") == "input_text"
                 and isinstance(item.get("text"), str)]
        return "\n".join(texts) if texts else None
    return None


def _local_path(cwd):
    """A CommandExecution cwd (a file:// URI) as a path. A plain path is
    kept as it is; any other URI is not a local path."""
    if not isinstance(cwd, str) or not cwd:
        return None
    if cwd[:5].lower() == "file:":
        return _shell.file_uri_to_path(cwd)
    return None if "://" in cwd else cwd


def _enveloped(obj):
    return isinstance(obj.get("type"), str) and "payload" in obj


class _Thread(object):
    """What one store has said so far: whose thread, and where, and whether
    the line being read is a copy of an ancestor's history."""
    __slots__ = ("store", "session", "session_cwd", "cwd", "mtime_iso",
                 "first", "start_ordinal", "marks_copies", "copying")

    def __init__(self, store):
        self.store = store
        self.session = store.session
        self.session_cwd = None
        self.cwd = None
        self.mtime_iso = _stamps.iso_utc(store.mtime, "s")
        self.first = True           # no session header seen yet
        self.start_ordinal = None   # a paginated subagent's first own ordinal
        self.marks_copies = False   # its release ends a copy with a marker
        self.copying = False        # inside a copy of an ancestor's history

    @property
    def project(self):
        return self.cwd or self.session_cwd

    def meta(self, payload):
        """session_meta: the first one names the thread. A later one is the
        first line of a copy of an ancestor's rollout (a fork made from a
        rollout path, a subagent handed its parent's history): every line
        from there to this thread's own thread_settings_applied is the
        ancestor's, written again with the time of the copy."""
        if not isinstance(payload, dict):
            return
        if not self.first:
            other = _str(payload.get("id"))
            if self.marks_copies and other and other != self.session:
                self.copying = True
            return
        self.first = False
        self.session = _str(payload.get("id")) or self.session
        self.session_cwd = _str(payload.get("cwd"))
        start = payload.get("subagent_history_start_ordinal")
        self.start_ordinal = start if _is_int(start) else None
        self.marks_copies = _release_at_least(payload.get("cli_version"),
                                              COPY_MARKER_SINCE)

    def settings(self, payload):
        """thread_settings_applied. The one that carries this thread's own
        id ends a copy; a copied one keeps its original owner's id."""
        if self.copying and payload.get("thread_id") == self.session:
            self.copying = False

    def inherited(self, obj):
        """True for a line this thread holds only as a copy of an
        ancestor's history: inside a copy, or (a paginated subagent) before
        the first ordinal of its own history."""
        if self.copying:
            return True
        ordinal = obj.get("ordinal")
        return (self.start_ordinal is not None and _is_int(ordinal)
                and ordinal < self.start_ordinal)

    def header(self, obj):
        """The bare {id, timestamp, instructions} line 1 of an early Rust
        rollout, or the TypeScript document's "session"."""
        if self.first and isinstance(obj, dict):
            self.first = False
            self.session = _str(obj.get("id")) or self.session

    def turn(self, payload):
        if isinstance(payload, dict) and _str(payload.get("cwd")):
            self.cwd = payload["cwd"]


class CodexSource(Source):
    id = "codex"
    name = "Codex"
    unit = "session"
    env = ("CODEX_HOME", "CODEX_SQLITE_HOME")
    path_means = "a CODEX_HOME directory (default ~/.codex)"
    checked = "rust-v0.159.3"

    def reset(self):
        Source.reset(self)
        self._tallied = set()       # (path, what) already counted this run

    def _first(self, path, what):
        """True the first time this run that `what` is counted for `path`,
        so reading a store for watch and again for clean counts it once."""
        key = (path, what)
        if key in self._tallied:
            return False
        self._tallied.add(key)
        return True

    def _unreadable(self, path, reason, message=None):
        if self._first(path, "unreadable"):
            self.unreadable_store(reason)
        if message:
            self.warn(path, message)

    # -- where to look ------------------------------------------------------

    def default_paths(self, env, home, platform):
        """CODEX_HOME when set, else ~/.codex (%USERPROFILE%\\.codex on
        Windows). CODEX_SQLITE_HOME (trimmed, as Codex trims it), when set,
        is where the databases are, unless config.toml's sqlite_home says
        otherwise: Codex takes that first, and locations() reads it."""
        root = _env(env, "CODEX_HOME")
        out = [(root, "env CODEX_HOME") if root else
               (_paths.join(platform, home, ".codex"), "default")]
        databases = _env(env, "CODEX_SQLITE_HOME", strip=True)
        if databases:
            out.append((databases, "env CODEX_SQLITE_HOME"))
        return out

    def config_sqlite_home(self, root):
        """(sqlite_home, config path) from root/config.toml, or (None, path).
        Only that key is kept; nothing else in the file is used. Needs
        tomllib (Python 3.11+). The value is resolved as Codex resolves it:
        ~ is the home directory, and a relative path is taken from root,
        the folder that holds config.toml."""
        config = os.path.join(root, "config.toml")
        toml = _tomllib()
        if toml is None or not os.path.isfile(config):
            return None, config
        try:
            with open(config, "rb") as fh:
                data = fh.read(CONFIG_MAX + 1)
            if len(data) > CONFIG_MAX:
                return None, config
            value = toml.loads(data.decode("utf-8")).get("sqlite_home")
        except (OSError, ValueError, UnicodeDecodeError, AttributeError,
                RecursionError):
            # RecursionError: tomllib recurses once per level of nesting,
            # and a few hundred levels end it.
            return None, config
        if not isinstance(value, str):
            return None, config
        return _resolve_config_path(value, root, _paths.home()), config

    def _locate(self, pairs):
        out, seen = [], set()
        for path, how in pairs:
            if not path:
                continue
            path = os.path.abspath(os.path.expanduser(path))
            key = os.path.normcase(path)
            if key in seen:
                continue
            seen.add(key)
            # Codex refuses a CODEX_HOME that is not a directory, and so
            # does this: a file there holds no sessions.
            out.append(Location(self.id, path, how, exists=os.path.isdir(path)))
        return out

    def locations(self, override=None, projects=()):
        """`override` (from --path) is a CODEX_HOME: CODEX_SQLITE_HOME,
        which describes the live install, does not apply to it, but its
        config.toml does. Otherwise the defaults, read now.

        The databases are where Codex looks for them: config.toml's
        sqlite_home first, then CODEX_SQLITE_HOME, then CODEX_HOME itself.
        A relative CODEX_SQLITE_HOME is taken from the current folder, as
        Codex takes it from its own."""
        try:
            if override:
                items = [override] if isinstance(override, str) else list(override)
                pairs = [(p, "--path") for p in items]
            else:
                pairs = list(self.default_paths(
                    os.environ, _paths.home(), _paths.platform_name()))
            roots = [p for p in pairs if p[1] != "env CODEX_SQLITE_HOME"]
            from_env = [p for p in pairs if p[1] == "env CODEX_SQLITE_HOME"]
            from_config = []
            for loc in self._locate(roots):
                if loc.exists:
                    home, config = self.config_sqlite_home(loc.path)
                    if home:
                        from_config.append((home, "config " + config))
            locs = self._locate(roots + (from_config or from_env))
            separate = any(_is_db_home(loc) for loc in locs)
            for loc in locs:
                if loc.exists:
                    loc.found = len(self._stores_at(loc, separate, heads=False))
            return locs
        except Exception as e:      # one adapter must not stop the others
            self.warn("locations", "could not work out where %s keeps its "
                      "history (%s)" % (self.name, e))
            return []

    def notes(self, locations):
        """Lines for `ranwhat sources` about what was not looked at, and why."""
        out = []
        for loc in locations:
            if _is_db_home(loc):
                continue
            if os.path.exists(loc.path) and not os.path.isdir(loc.path):
                out.append("%s is not a directory, so Codex does not use it "
                           "and it was not read." % loc.path)
            elif loc.exists and _tomllib() is None:
                config = os.path.join(loc.path, "config.toml")
                if _keyfile.read_keys(config, ["sqlite_home"]):
                    out.append("%s sets sqlite_home, which ranwhat reads on "
                               "Python 3.11 and later only; set "
                               "CODEX_SQLITE_HOME to the same folder to have "
                               "it read." % config)
        return out

    # -- stores -------------------------------------------------------------

    def stores(self, locations, since_days=None):
        locations = list(locations)
        separate = any(_is_db_home(loc) for loc in locations)
        found, seen = [], set()
        for loc in locations:
            for store in self._stores_at(loc, separate):
                key = os.path.normcase(os.path.abspath(store.path))
                if key not in seen:
                    seen.add(key)
                    found.append(store)
        return base.newest_first(found, since_days)

    def _stores_at(self, loc, separate, heads=True):
        root = loc.path
        if not os.path.isdir(root):
            return []
        if _is_db_home(loc):
            return self._databases(root)
        g = glob.escape(root)
        out = []
        patterns = []
        for folder in (os.path.join(g, "sessions", "*", "*", "*"),
                       os.path.join(g, "sessions"),
                       os.path.join(g, "archived_sessions")):
            patterns.append((os.path.join(folder, "rollout-*.jsonl"), "jsonl"))
            patterns.append((os.path.join(folder, "rollout-*.jsonl.zst"),
                             "jsonl.zst"))
        patterns.append((os.path.join(g, "sessions", "rollout-*.json"), "json"))
        for pattern, fmt in patterns:
            for path in sorted(glob.glob(pattern)):
                if not os.path.isfile(path):
                    continue
                match = _ROLLOUT_NAME.match(os.path.basename(path))
                session = match.group(1) if match else None
                project = None
                if heads and fmt == "jsonl":
                    session, project = self._head(path, session)
                fields = {"role": "transcript", "session": session,
                          "project": project}
                if fmt == "jsonl.zst":
                    fields["why_read_only"] = WHY_ZST
                store = self.store(path, fmt, **fields)
                if store:
                    out.append(store)
        history = os.path.join(root, "history.jsonl")
        if os.path.isfile(history):
            store = self.store(history, "jsonl", role="side",
                               unit="prompt history")
            if store:
                out.append(store)
        for suffix in ("*.sh", "*.ps1"):
            for path in sorted(glob.glob(os.path.join(g, "shell_snapshots",
                                                      suffix))):
                if not os.path.isfile(path):
                    continue
                match = _SNAPSHOT_NAME.match(os.path.basename(path))
                store = self.store(path, "text", role="side",
                                   unit="shell snapshot",
                                   session=match.group(1) if match else None,
                                   masking="read-only",
                                   why_read_only=WHY_SNAPSHOT)
                if store:
                    out.append(store)
        if not separate:
            out.extend(self._databases(root))
        return out

    def _databases(self, folder):
        out = []
        for name, _table, _cols in DATABASES:
            path = os.path.join(folder, name)
            if os.path.isfile(path):
                store = self.store(path, "sqlite", role="side", unit="database",
                                   why_read_only=WHY_SQLITE)
                if store:
                    out.append(store)
        return out

    def _head(self, path, session):
        """(session, working directory) from a rollout's session_meta, which
        is always its first line; (session, None) when it says neither."""
        try:
            with open(path, "rb") as fh:
                raw = fh.readline(HEAD_MAX)
        except OSError:
            return session, None
        try:
            obj = json.loads(_lines.decode_line(raw, first=True))
        except (ValueError, RecursionError):
            return session, None
        if not isinstance(obj, dict):
            return session, None
        if obj.get("type") == "session_meta" and isinstance(obj.get("payload"), dict):
            payload = obj["payload"]
            return (_str(payload.get("id")) or session, _str(payload.get("cwd")))
        if "type" not in obj and "payload" not in obj:
            return _str(obj.get("id")) or session, None
        return session, None

    # -- reading ------------------------------------------------------------

    def _records(self, store):
        """Yield (where, obj, text) for each record of a transcript or
        history file: obj is _BAD for a line that is not JSON. A .jsonl that
        became a .jsonl.zst while we looked (Codex compresses idle threads,
        and restores them on resume) is read under its other name; if that
        is gone too, nothing is said."""
        if store.format == "json":
            for record in self._document(store):
                yield record
            return
        path, fmt = store.path, store.format
        for attempt in (0, 1):
            try:
                if fmt == "jsonl":
                    fh = open(path, "rb")
                else:
                    fh = self._decompressed(path)
                    if fh is None:
                        return
            except FileNotFoundError:
                if attempt:
                    return
                if fmt == "jsonl" and path.endswith(".jsonl"):
                    path, fmt = path + ".zst", "jsonl.zst"
                elif fmt == "jsonl.zst" and path.endswith(".zst"):
                    path, fmt = path[:-4], "jsonl"
                else:
                    return
                continue
            except OSError as e:
                self._unreadable(path, "could not be opened",
                                 "cannot read %s (%s)" % (path, e))
                return
            try:
                with fh:
                    for record in self._json_lines(fh, path):
                        yield record
            except OSError as e:
                self.warn(path, "stopped reading %s (%s)" % (path, e))
            return

    def _decompressed(self, path):
        """The decompressed file as a binary stream, or None (counted).
        FileNotFoundError is the caller's: the file may have just been
        restored as plain JSONL."""
        os.stat(path)
        if not _zstd.available():
            self._unreadable(path, "compressed, " + _zstd.NEEDS)
            return None
        with open(path, "rb") as fh:
            data = fh.read()
        plain = _zstd.decompress(data)
        if plain is None:
            self._unreadable(path, NOT_DECOMPRESSED,
                             "cannot decompress %s" % path)
            return None
        return io.BytesIO(plain)

    def _json_lines(self, fh, path):
        """Like _lines.iter_json_lines, but a line that is not JSON is
        yielded too (as _BAD with its text), for clean. A complete bad line
        is counted; a last line with no newline is one Codex is still
        writing, and is not. A file in which nothing parses warns once."""
        counting = self._first(path, "lines")
        parsed = bad = 0
        for index, raw in enumerate(fh, 1):
            text = _lines.decode_line(raw, first=index == 1)
            if not text.strip():
                continue
            try:
                obj = json.loads(text)
            except (ValueError, RecursionError):
                if raw.endswith(b"\n"):
                    bad += 1
                yield "line %d" % index, _BAD, text
                continue
            parsed += 1
            yield "line %d" % index, obj, text
        if counting and bad:
            self.count("unparsed", bad)
        if bad and not parsed:
            self._unreadable(path, NOT_JSONL,
                             "%s is not JSON Lines; nothing in it was read" % path)

    def _document(self, store):
        """The TypeScript CLI's rollout-*.json: yield ("session", header,
        None), then ("item N", item, None) for each item."""
        path = store.path
        try:
            with open(path, "rb") as fh:
                raw = fh.read()
        except FileNotFoundError:
            return
        except OSError as e:
            self._unreadable(path, "could not be opened",
                             "cannot read %s (%s)" % (path, e))
            return
        text = raw.decode("utf-8", "surrogateescape").lstrip(_lines.BOM)
        try:
            doc = json.loads(text)
        except (ValueError, RecursionError):
            doc = None
        if not (isinstance(doc, dict) and isinstance(doc.get("items"), list)):
            if self._first(path, "lines"):
                self.count("unparsed")
            self._unreadable(path, NOT_JSON, "%s does not parse as a Codex "
                             "session; nothing in it was read" % path)
            yield "whole file", _BAD, text
            return
        yield "session", doc.get("session"), None
        for index, item in enumerate(doc["items"], 1):
            yield "item %d" % index, item, None

    # -- tool calls ---------------------------------------------------------

    def _call(self, item, thread, timestamp, not_after):
        """A ToolCall for one ResponseItem, or None when it is not a call."""
        kind_of = item.get("type")
        cid = _str(item.get("call_id"))
        common = dict(session=thread.session, project=thread.project,
                      timestamp=timestamp, not_after=not_after,
                      tool_call_id=cid)
        if kind_of == "function_call":
            name = _str(item.get("name"))
            args = base.decode_input(item.get("arguments"))
            if name in SHELL_FUNCTIONS:
                key = SHELL_FUNCTIONS[name]
                if name == "shell":
                    value = args.get(key)
                    command = (_shell.argv_to_command(value)
                               if isinstance(value, (list, tuple, str)) else "")
                else:
                    command = args.get(key) if isinstance(args.get(key), str) else ""
                return ToolCall(self.id, thread.store.path, name, args,
                                kind="shell", known=True,
                                command=command or None,
                                workdir=_str(args.get("workdir")),
                                consumed=(key,) if command else (), **common)
            if name == "write_stdin":
                return ToolCall(self.id, thread.store.path, name, args,
                                kind="other", known=True, **common)
            if name == "apply_patch":
                return ToolCall(self.id, thread.store.path, name, args,
                                kind="write", known=True, **common)
            return ToolCall(self.id, thread.store.path, self._display(item),
                            args, kind="other", known=False, **common)
        if kind_of == "custom_tool_call":
            raw = item.get("input")
            if _str(item.get("name")) == "apply_patch":
                return ToolCall(self.id, thread.store.path, "apply_patch",
                                {"input": raw}, kind="write", known=True,
                                **common)
            return ToolCall(self.id, thread.store.path, self._display(item),
                            raw, kind="other", known=False, **common)
        if kind_of == "local_shell_call":
            action = item.get("action")
            action = action if isinstance(action, dict) else {}
            command = _shell.argv_to_command(action.get("command"))
            return ToolCall(self.id, thread.store.path, "local_shell_call",
                            action, kind="shell", known=True,
                            command=command or None,
                            workdir=_str(action.get("working_directory")),
                            consumed=("command",) if command else (), **common)
        if kind_of == "web_search_call":
            return ToolCall(self.id, thread.store.path, "web_search_call",
                            {k: v for k, v in item.items() if k != "type"},
                            kind="fetch", known=True, **common)
        return None

    @staticmethod
    def _display(item):
        """namespace.name for an MCP tool that carries a namespace."""
        name = _str(item.get("name")) or str(item.get("type"))
        namespace = _str(item.get("namespace"))
        return "%s.%s" % (namespace, name) if namespace else name

    def _shell_event(self, thread, command, cwd, workdir, user, timestamp,
                     tool_name, cid=None, status=None):
        """A shell call from an event: the user's own (actor "user"), or an
        agent command's twin, used only to give its output an origin."""
        text = _shell.argv_to_command(command)
        tool_input = {"command": command}
        if cwd is not None:
            tool_input["cwd"] = cwd
        return ToolCall(self.id, thread.store.path, tool_name, tool_input,
                        kind="shell", known=True, session=thread.session,
                        project=thread.project, timestamp=timestamp,
                        tool_call_id=cid, actor="user" if user else "agent",
                        status=status, command=text or None, workdir=workdir,
                        consumed=("command",) if text else ())

    def _item_completed(self, payload, thread, timestamp):
        """(item, ToolCall) for a CommandExecution item, else (None, None).
        The call is the user's for a user_shell item, else the agent
        command's twin (not reported: its function_call line is)."""
        item = payload.get("item")
        if not (isinstance(item, dict) and item.get("type") == "CommandExecution"):
            return None, None
        user = item.get("source") == "user_shell"
        when = _stamps.iso_utc(payload.get("completed_at_ms"), "ms") or timestamp
        call = self._shell_event(
            thread, item.get("command"), item.get("cwd"),
            _local_path(item.get("cwd")), user, when,
            "user_shell" if user else "CommandExecution",
            cid=_str(item.get("id")),
            status="declined" if user and item.get("status") == "declined"
            else None)
        for key in ("aggregated_output", "formatted_output", "stdout"):
            if isinstance(item.get(key), str):
                call.output = item[key]
                break
        return item, call

    def _exec_end(self, payload, thread, timestamp):
        """The ToolCall for an exec_command_end event (older Extended mode).
        That its source uses the same values as CommandExecution's is
        assumed, as the design says."""
        user = payload.get("source") == "user_shell"
        cwd = payload.get("cwd")
        return self._shell_event(thread, payload.get("command"), cwd,
                                 _str(cwd), user, timestamp,
                                 "user_shell" if user else "exec_command_end")

    def _recorded_calls(self, item, thread, timestamp, not_after):
        """[(index, split, ToolCall)] for each command a user message records
        the user ran with `!` (USER_SHELL_MARKERS). The call's output is
        what the record says the command printed."""
        out = []
        for index, command, split in _user_shell_records(item):
            text = item["content"][index]["text"]
            call = ToolCall(self.id, thread.store.path, "user_shell",
                            {"command": command}, kind="shell", known=True,
                            session=thread.session, project=thread.project,
                            timestamp=timestamp, not_after=not_after,
                            actor="user", command=command,
                            consumed=("command",),
                            output=_result_output(text[split:]))
            out.append((index, split, call))
        return out

    def _events(self, store):
        """Yield ("call", ToolCall, replayed, awaits_output, inherited,
        recorded) and ("output", call_id, text) for every call in the store,
        in file order. inherited: the line is a copy of an ancestor's
        history. recorded: a command the user ran, read from the message
        that records it. A record whose shape is not what the spec says, or
        that is nested deeper than the stack can follow (a command's argv
        made into text), is counted and skipped; the rest of the file is
        still read."""
        thread = _Thread(store)
        counting = self._first(store.path, "records")
        for where, obj, _text in self._records(store):
            if obj is _BAD:
                continue
            try:
                events = self._line_events(where, obj, thread, counting)
            except (AttributeError, KeyError, TypeError, ValueError,
                    RecursionError):
                if counting:
                    self.count("unreadable_calls")
                continue
            for event in events:
                yield event

    def _line_events(self, where, obj, thread, counting):
        if where == "session":
            thread.header(obj)
            return []
        if not isinstance(obj, dict):
            if counting:
                self.count("unknown")
            return []
        if not _enveloped(obj):
            if thread.first and "type" not in obj and "id" in obj:
                thread.header(obj)
                return []
            return self._item_events(obj, thread, None, thread.mtime_iso,
                                     False, False, counting)
        kind, payload = obj["type"], obj["payload"]
        if kind in QUIET_TYPES:
            return []
        timestamp = _stamps.iso_utc(obj.get("timestamp"), "iso")
        if kind not in SESSION_TYPES or not isinstance(payload, dict):
            if counting:
                self.count("unknown")
            return []
        inherited = thread.inherited(obj)
        if kind == "session_meta":
            thread.meta(payload)
        elif kind == "turn_context":
            thread.turn(payload)
        elif kind == "response_item":
            return self._item_events(payload, thread, timestamp,
                                     None if timestamp else thread.mtime_iso,
                                     False, inherited, counting)
        elif kind == "compacted":
            events = []
            history = payload.get("replacement_history")
            for item in history if isinstance(history, list) else ():
                # A copy of an earlier item: no time of its own, and no
                # later than the compaction that wrote it.
                events += self._item_events(item, thread, None,
                                            timestamp or thread.mtime_iso,
                                            True, inherited, counting)
            return events
        elif kind == "event_msg":
            sub = payload.get("type")
            call = None
            if sub == "thread_settings_applied":
                thread.settings(payload)
            elif sub == "item_completed":
                _item, call = self._item_completed(payload, thread, timestamp)
            elif sub == "exec_command_end":
                call = self._exec_end(payload, thread, timestamp)
            if call is not None and call.actor == "user":
                return [("call", call, False, False, inherited, False)]
        return []

    def _item_events(self, item, thread, timestamp, not_after, replayed,
                     inherited, counting):
        if not isinstance(item, dict):
            if counting:
                self.count("unknown")
            return []
        kind_of = item.get("type")
        if kind_of in CALL_ITEMS:
            call = self._call(item, thread, timestamp, not_after)
            return [("call", call, replayed, kind_of != "web_search_call",
                     inherited, False)] if call else []
        if kind_of in OUTPUT_ITEMS:
            cid = _str(item.get("call_id"))
            return [("output", cid, output_text(item.get("output")))] if cid else []
        if kind_of == "message":
            return [("call", call, replayed, False, inherited, True)
                    for _index, _split, call
                    in self._recorded_calls(item, thread, timestamp, not_after)]
        if kind_of not in OTHER_ITEMS and counting:
            self.count("unknown")
        return []

    def tool_calls(self, store):
        """Every distinct call, once, with its output when the store has it.
        Dedupe is by call_id within the file (first seen wins), and by
        content for copies in compacted.replacement_history.

        A copy of an ancestor's history is not this thread's: its calls are
        not reported, and a later copy of one (a compaction) is known for
        what it is. A command the user ran is reported from its
        CommandExecution item when the file has one (paginated mode writes
        that and the message), else from the message that records it (all
        the default legacy mode writes)."""
        if store.role != "transcript":
            return
        seen_ids, seen_items, pending = set(), set(), {}
        recorded, ran = [], collections.Counter()
        try:
            for event in self._events(store):
                if event[0] == "output":
                    call = pending.pop(event[1], None)
                    if call is not None:
                        call.output = event[2]
                        yield call
                    continue
                _kind, call, replayed, awaits, inherited, from_record = event
                cid = call.tool_call_id
                if cid:
                    if cid in seen_ids:
                        continue
                    seen_ids.add(cid)
                else:
                    # No id (web_search_call, a user command): a copy in
                    # replacement_history is told apart by what it holds.
                    fingerprint = self._fingerprint(call)
                    if replayed and fingerprint in seen_items:
                        continue
                    seen_items.add(fingerprint)
                if inherited:
                    continue
                if from_record:
                    recorded.append(call)   # until every item is known
                    continue
                if call.actor == "user" and call.status != "declined":
                    ran[_script(call.tool_input.get("command"))] += 1
                if cid and awaits:
                    pending[cid] = call     # until its output line
                    continue
                yield call
        except Exception as e:      # never raise: say so and go on
            self.warn(store.path, "stopped reading %s (%s: %s)"
                      % (store.path, type(e).__name__, e))
        for call in pending.values():
            yield call
        for call in recorded:
            if ran[call.command] > 0:
                ran[call.command] -= 1      # reported from its item
                continue
            yield call

    @staticmethod
    def _fingerprint(call):
        try:
            body = json.dumps([call.tool_name, call.actor, call.tool_input],
                              sort_keys=True, default=str)
        except (TypeError, ValueError, RecursionError):
            # As watch._payload, and not repr, which fails wherever
            # json.dumps does. These calls share one fingerprint, so a
            # replayed copy of any of them counts as seen.
            body = "unhashable"
        return hashlib.sha256(body.encode("utf-8", "surrogatepass")).digest()

    # -- secrets ------------------------------------------------------------

    def secret_texts(self, store):
        """Every string the store holds, encrypted_content aside. The output
        of a call carries that call, so clean can tell what file it came
        from; a call's own input carries none (it was typed)."""
        try:
            if store.format == "sqlite":
                texts = self._database_texts(store)
            elif store.format == "text":
                texts = self._snapshot_texts(store)
            elif store.role == "side":
                texts = self._history_texts(store)
            else:
                texts = self._transcript_texts(store)
            for text in texts:
                yield text
        except Exception as e:      # never raise: say so and go on
            self.warn(store.path, "stopped reading %s (%s: %s)"
                      % (store.path, type(e).__name__, e))

    def _history_texts(self, store):
        for where, obj, text in self._records(store):
            yield SecretText(text if obj is _BAD else obj, where=where)

    def _snapshot_texts(self, store):
        try:
            with open(store.path, "r", encoding="utf-8",
                      errors="surrogateescape", newline="") as fh:
                text = fh.read(SNAPSHOT_MAX)
        except FileNotFoundError:
            return
        except OSError as e:
            self._unreadable(store.path, "could not be opened",
                             "cannot read %s (%s)" % (store.path, e))
            return
        yield SecretText(text, where="whole file")

    def _database_texts(self, store):
        name = os.path.basename(store.path)
        spec = [(table, cols) for n, table, cols in DATABASES if n == name]
        if not spec:
            return
        table, wanted = spec[0]
        # A file that is not a database is said so without opening it in
        # SQLite, which would copy it to a temp folder first. An empty file
        # holds nothing to read.
        try:
            with open(store.path, "rb") as fh:
                magic = fh.read(len(SQLITE_MAGIC))
        except FileNotFoundError:
            return
        except OSError as e:
            self._unreadable(store.path, NOT_DATABASE,
                             "cannot read %s (%s)" % (store.path, e))
            return
        if not magic:
            return
        if magic != SQLITE_MAGIC:
            self._unreadable(store.path, NOT_DATABASE,
                             "%s is not a SQLite database" % store.path)
            return
        with _sqlite.readonly(store.path) as conn:
            if conn is None:
                self._unreadable(store.path, NOT_DATABASE,
                                 "cannot open %s" % store.path)
                return
            try:
                have = _sqlite.columns(conn, table)
                cols = [c for c in wanted if c in have]
                if not cols:
                    if self._first(store.path, "records"):
                        self.count("unknown")
                    return
                for index, row in enumerate(
                        _sqlite.iter_rows(conn, table, cols), 1):
                    for col in cols:
                        value = row[col]
                        if isinstance(value, bytes):
                            value = value.decode("utf-8", "surrogateescape")
                        if not isinstance(value, str) or not value:
                            continue
                        node = value
                        if col == "item_json":
                            decoded = _json_value(value)
                            if decoded is not None:
                                node = _without_encrypted(decoded)
                        yield SecretText(node, where="%s row %d, %s"
                                         % (table, index, col))
            except sqlite3.Error as e:
                # The class only: what an error says can quote a cell.
                self._unreadable(store.path, NOT_DATABASE,
                                 "cannot read %s (%s)"
                                 % (store.path, type(e).__name__))

    def _transcript_texts(self, store):
        thread = _Thread(store)
        calls = {}                  # call_id -> ToolCall, until its output
        for where, obj, text in self._records(store):
            if obj is _BAD:
                yield SecretText(text, where=where)
                continue
            if text is None or ENCRYPTED in text:
                obj = _without_encrypted(obj)
            try:
                found = self._line_texts(where, obj, thread, calls)
            except (AttributeError, KeyError, TypeError, ValueError,
                    RecursionError):
                # Not the shape the spec says, or nested past the stack:
                # still searched, as it is (clean walks it with its own).
                found = [SecretText(obj, where=where)]
            for item in found:
                yield item

    def _line_texts(self, where, obj, thread, calls):
        if where == "session":
            thread.header(obj)
            return [SecretText(obj, where=where)] if obj is not None else []
        if not isinstance(obj, dict):
            return [SecretText(obj, where=where)]
        if not _enveloped(obj):
            if thread.first and "type" not in obj and "id" in obj:
                thread.header(obj)
                return [SecretText(obj, where=where)]
            return self._item_texts(obj, thread, None, where, calls)
        kind, payload = obj["type"], obj["payload"]
        timestamp = _stamps.iso_utc(obj.get("timestamp"), "iso")
        if not isinstance(payload, dict):
            return [SecretText(obj, where=where)]
        if kind == "session_meta":
            thread.meta(payload)
        elif kind == "turn_context":
            thread.turn(payload)
        elif kind == "response_item":
            return self._item_texts(payload, thread, timestamp, where, calls,
                                    line=obj)
        elif kind == "compacted":
            history = payload.get("replacement_history")
            rest = {k: v for k, v in payload.items()
                    if k != "replacement_history"}
            out = [SecretText(dict(obj, payload=rest), where=where)]
            for index, item in enumerate(
                    history if isinstance(history, list) else (), 1):
                out += self._item_texts(item, thread, None,
                                        "%s, item %d" % (where, index), calls)
            return out
        elif kind == "event_msg":
            return self._event_texts(obj, payload, thread, timestamp, where)
        return [SecretText(obj, where=where)]

    def _item_texts(self, item, thread, timestamp, where, calls, line=None):
        """SecretTexts for one ResponseItem. JSON held in a string (a
        function call's arguments, a rust-v0.50 output) is decoded, so each
        value is read as it was, not with a second level of escapes."""
        if not isinstance(item, dict):
            return [SecretText(item, where=where)]
        kind_of = item.get("type")
        node = item
        call = None
        if kind_of in CALL_ITEMS:
            made = self._call(item, thread, timestamp, None)
            if made is not None and made.tool_call_id:
                calls[made.tool_call_id] = made
            args = _json_value(item.get("arguments"))
            if args is not None:
                node = dict(item, arguments=args)
        elif kind_of in OUTPUT_ITEMS:
            call = calls.pop(_str(item.get("call_id")), None)
            decoded = _json_value(item.get("output"))
            if decoded is not None:
                node = dict(item, output=decoded)
        elif kind_of == "message":
            return self._message_texts(item, thread, timestamp, where, line)
        if line is not None:
            node = dict(line, payload=node)
        return [SecretText(node, call=call, where=where)]

    def _message_texts(self, item, thread, timestamp, where, line):
        """A message as it is, except that the result of a command the user
        ran with `!` is yielded apart from what the user typed, with that
        command as its call, so a key it printed is credited to the file
        the command read."""
        records = self._recorded_calls(item, thread, timestamp, None)
        if not records:
            node = item if line is None else dict(line, payload=item)
            return [SecretText(node, where=where)]
        content = list(item["content"])
        results = []
        for index, split, call in records:
            text = content[index]["text"]
            content[index] = dict(content[index], text=text[:split])
            results.append(SecretText(text[split:], call=call, where=where))
        node = dict(item, content=content)
        if line is not None:
            node = dict(line, payload=node)
        return [SecretText(node, where=where)] + results

    def _event_texts(self, obj, payload, thread, timestamp, where):
        """A command's output in an event (stdout, stderr, aggregated and
        formatted output: Codex keeps all four for a command the user ran)
        is yielded apart from the command, with the call that ran it;
        everything else as it is."""
        sub = payload.get("type")
        if sub == "item_completed":
            item, call = self._item_completed(payload, thread, timestamp)
            if item is not None and any(k in item for k in OUTPUT_FIELDS):
                printed = {k: item[k] for k in OUTPUT_FIELDS if k in item}
                rest = {k: v for k, v in item.items() if k not in printed}
                return [SecretText(dict(obj, payload=dict(payload, item=rest)),
                                   where=where),
                        SecretText(printed, call=call, where=where)]
        elif sub == "exec_command_end":
            call = self._exec_end(payload, thread, timestamp)
            typed = {k: payload[k] for k in ("command", "cwd") if k in payload}
            rest = {k: v for k, v in payload.items() if k not in typed}
            return [SecretText(dict(obj, payload=typed), where=where),
                    SecretText(rest, call=call, where=where)]
        return [SecretText(obj, where=where)]

    # -- masking ------------------------------------------------------------

    def in_use(self, store):
        """True when a Codex process may still append to this rollout: it
        holds <CODEX_HOME>/thread-writer-locks/<thread id>.lock for as long
        as it owns the thread (an idle TUI too), and removes it when it lets
        go. Codex itself will not compress a thread while it is held. The
        lock is only stat'ed, never opened or locked; a lock a crashed
        Codex left behind keeps the rollout unmasked until Codex next
        starts and clears it."""
        if store.role != "transcript":
            return False
        root = _codex_home_of(store.path)
        if root is None:
            return False
        match = _ROLLOUT_NAME.match(os.path.basename(store.path))
        ids = set(i for i in (store.session, match.group(1) if match else None)
                  if isinstance(i, str) and _THREAD_ID.match(i))
        locks = os.path.join(root, LOCK_DIR)
        return any(os.path.lexists(os.path.join(locks, i + ".lock"))
                   for i in sorted(ids))

    def mask(self, store, values):
        """The generic rewrite, for .jsonl and .json; everything else is
        read-only. A .jsonl that Codex compressed since it was found is
        read-only now; one that is gone is left alone."""
        try:
            return Source.mask(self, store, values)
        except FileNotFoundError:
            if store.format == "jsonl" and os.path.exists(store.path + ".zst"):
                return MaskResult(store.path, skipped="read-only")
            return MaskResult(store.path)
