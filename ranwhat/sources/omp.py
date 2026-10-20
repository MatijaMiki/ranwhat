"""Oh My Pi, "omp" (can1357/oh-my-pi, npm @oh-my-pi/pi-coding-agent).

omp is a fork of Pi (pi.py) and keeps the same history: one JSON Lines file
per session, a tree of entries (id, parentId), format version 3. Everything
below was read from the agent's own source and docs (tag v18.12.3, commit
53a0377, and the main branch for dirs.ts, session-paths.ts and
docs/session.md); where this module differs from pi.py, it says why.

Where the files are (packages/utils/src/dirs.ts DirResolver,
coding-agent/src/session/session-paths.ts):
- <agent>/sessions/<bucket>/<timestamp>_<sessionId>.jsonl, where <agent> is
  ~/.omp/agent (the same under the home directory on Windows:
  %USERPROFILE%\\.omp\\agent) and <sessionId> is a UUIDv7. <bucket> is the
  working directory with "/", "\\" and ":" turned into "-", in one of three
  spellings; it is not decoded here, the project is the header's cwd.
- PI_CONFIG_DIR replaces the ".omp" folder name; it is always joined under
  the home directory.
- PI_CODING_AGENT_DIR replaces <agent> (default profile only; it is
  resolved with path.resolve, so "~" is not expanded by omp). It also turns
  off XDG.
- On Linux and macOS, when XDG_DATA_HOME is set and $XDG_DATA_HOME/omp
  exists, <agent> is $XDG_DATA_HOME/omp itself (the "agent/" part is left
  out): $XDG_DATA_HOME/omp/sessions. Sessions written before that move stay
  under ~/.omp/agent, so both are read.
- A named profile (OMP_PROFILE, or the legacy PI_PROFILE) has its own agent
  folder, ~/.omp/profiles/<name>/agent (under XDG:
  $XDG_DATA_HOME/omp/profiles/<name>). The profile is chosen per run, so
  every profile folder is read, not the one the environment names now.
- PI_CODING_AGENT_SESSION_DIR (or --session-dir) puts new sessions flat in
  another folder: <dir>/<timestamp>_<sessionId>.jsonl.
- Every transcript outside the managed sessions folder is recorded as one
  marker file, <agent>/custom-session-files/<hash> (under XDG:
  $XDG_STATE_HOME/omp/custom-session-files), whose content is the
  transcript's absolute path. Those paths are read too, so a --session-dir
  or --session file is found without the variable.
- A subagent's transcript, and the advisor's, sit in the session's artifact
  folder, the session path without ".jsonl": <bucket>/<timestamp>_<id>/
  <agentId>.jsonl (nested subagents have dotted ids in the same folder).
  They hold the bash calls the task tool's subagents made, so the folder
  one level down is read as well.

The format, where it is not Pi's:
- Line 1 of a file written since v16.2.3 is a fixed-width title slot of
  exactly 256 bytes with its newline: {"type":"title","v":1,"title",
  "source"?,"updatedAt","pad":"<spaces>"}. omp rewrites it in place at
  offset 0 when the title changes. The session header
  {"type":"session","version":3,"id","timestamp","cwd"} is then line 2.
  Earlier files begin with the header. Both are read here.
- Entry types: message, model_usage, thinking_level_change, model_change,
  service_tier_change, compaction, branch_summary, reset_boundary, custom,
  custom_message, label, title_change, ttsr_injection, credential_pin,
  session_init, mode_change (docs/session.md), and the title slot. Others
  are counted as unknown.
- Message roles: user, developer, assistant, toolResult, bashExecution,
  pythonExecution, hookMessage, fileMention; "custom" is reconstructed from
  custom_message entries. bashExecution is a command the user ran with "!"
  ({command, output, exitCode, cancelled, truncated}); pythonExecution is
  Python the user ran with "$" ({code, output, exitCode, ...}).
- Tool calls are {"type":"toolCall","id","name","arguments"} blocks in an
  assistant message, answered by a toolResult message ({toolCallId,
  toolName, content[], details?, isError}). There is no nestedCalls field.
  Tools mapped here: bash {command, cwd?, ...} (shell; cwd is the call's
  workdir), eval {language, code} (shell: it runs code), read {path} (the
  path may end in a selector ":N-M", ":-N", ":raw", ":img" or ":conflicts",
  dropped here; an internal URI such as artifact:// or local:// names no
  file, and an http(s) URL is a fetch), write {path, content}, and edit,
  which has several forms: {path, old_string, new_string}, {path, edits:
  [{op?, rename?, diff?}]}, or {input} (the apply_patch, hashline and
  sloppy modes). For {input} only the "*** Add|Update|Delete File:" and
  "*** Move to:" lines of an apply_patch body are read as paths; the
  hashline and sloppy bodies are not documented in the sources read, so an
  edit in those modes is a write with no path. Every other name
  (ast_grep, ast_edit, grep, glob, find, lsp, task, web_search, mcp__...)
  is unknown and judged by name.
- A call that never ran: omp answers it with a synthetic toolResult whose
  details are {"__synthetic": true, "source": "assistant_stop_aborted" |
  "assistant_stop_error" | "assistant_stop_length" | "assistant_stop_skipped"
  | "interrupt_skipped", "executed": false} (agent/src/agent-loop.ts), so
  such a call is "declined" by details.executed === false. A call
  interrupted after it started has {"__interrupted": true, "execution":
  "started"} and did run. "Tool X not found" may end with ". Did you mean
  Y?" or ". Closest available: ..."; that is declined too. The validation
  and "Tool execution was blocked" texts are Pi's, and pi.py handles them.
  As in Pi, an assistant message stopped by "aborted" or "error" is saved
  with its calls, none of which ran.
- Format versions: 3 is current (the one the research found throughout).
  Version 2 says "hookMessage" where 3 says "custom"; version 1 has no
  "version" in its header and no id or parentId on its entries; omp
  migrates a file when it loads it, and one it has not loaded since is
  read as it is. A PI-compatible file without a title slot is read the same.
- Copies of a command or path are kept elsewhere in the file: "custom"
  entries named tool_execution_start (data.args) and session_exit
  (data.pendingToolCalls), written before and after a call. They prove
  nothing about whether it ran, so they are not read as calls; clean reads
  every line whole, so a secret in them is found and masked like any other.
- Strings over 500,000 characters are cut by omp and end with "[Session
  persistence truncated large content]"; image payloads are replaced by
  "blob:sha256:<hash>" (blobs/<hash>, not read).

Shared with Pi: PI_CODING_AGENT_DIR and PI_CODING_AGENT_SESSION_DIR are
Pi's variables as well, and when either is set both tools may write into the
same folder. In those two places a file is omp's only when its first line is
the title slot; one without a slot (a Pi file, or an omp file from before
v16.2.3) is left to Pi. pi.py has to skip the files that do have the slot
(is_title_slot_file below); until it does, such a file is read by both.
Files under ~/.omp, a profile, XDG or a custom-session-files marker are
omp's whatever their first line says. Builds of omp from before
v3.0.1337 (January 2026) wrote to ~/.pi like Pi and cannot be told apart
from Pi's files; pi.py reads those.

Masking: omp holds an OS lease on a session it writes and checks the
file's size while it does, so only closed sessions are masked (the usual
quiet period applies, and the note below says to close omp). Line 1 is a
slot of exactly 256 bytes that omp overwrites in place at offset 0; a mask
that changed its length would corrupt the header after it, so a file whose
title slot holds a value to mask is refused ("would alter more than the
secret"), not rewritten.

Spilled tool output, <session folder>/<n>.<tool>.log, is a side store
(plain text): it is scanned for secrets and masked, but not tied to the
call that produced it (the artifact id link is not verified). In a folder
shared with Pi it is taken only beside a session file that starts with the
title slot. A file under omp's own default root, a profile or XDG folder is
omp's even when PI_CODING_AGENT_DIR names the same folder.

Not read: gzip archives (archive/sessions/**/*.jsonl.gz, written only by
the opt-in `omp gc --apply`), history.db (prompt history, SQLite), blobs/,
and the other files beside a session's artifacts (<id>.md; draft.txt).
A call omp refused before running is declined: "Tool was not executed
because the run was aborted", 'Validation failed for tool "x":', "The tool
was not run." (all with isError), or details {isError, error} equal to the
text (agent-loop.ts, validation.ts). A read path is split on ";" (and on
"," or white space, keeping the whole too), a file:// URI is a local file,
and selectors may be comma lists. Still unverifiable and handled
defensively: the exact validation text for other failures, taken from Pi.
"""

from __future__ import annotations

import json
import os
import re
from urllib.parse import unquote

from . import _lines, _paths, _rewrite, base, pi
from .base import MaskResult, SecretText, Source, ToolCall
from .pi import PiSource

ENV = "PI_CODING_AGENT_DIR"
SESSION_ENV = "PI_CODING_AGENT_SESSION_DIR"
CONFIG_ENV = "PI_CONFIG_DIR"
XDG_DATA = "XDG_DATA_HOME"
XDG_STATE = "XDG_STATE_HOME"

CONFIG_DIR = ".omp"
AGENT = "agent"
SESSIONS = "sessions"
PROFILES = "profiles"
REGISTRY = "custom-session-files"
APP = "omp"
SUFFIX = ".jsonl"

HOW_AGENT = "env " + ENV
HOW_SESSION = "env " + SESSION_ENV
HOW_XDG = "env " + XDG_DATA
HOW_XDG_STATE = "env " + XDG_STATE
HOW_PROFILES = "default profiles"
HOW_XDG_PROFILES = "env " + XDG_DATA + " profiles"

# The two variables Pi reads as well: a file there is omp's only when it
# starts with the title slot.
SHARED = (HOW_AGENT, HOW_SESSION)

# watch._PATH_KEYS, as pi.PATH_KEYS (tests/test_source_omp.py checks it).
PATH_KEYS = pi.PATH_KEYS

SHELL = "bash"
EVAL = "eval"
READ = "read"
WRITE = "write"
EDIT = "edit"
USER_SHELL = pi.USER_SHELL          # bashExecution
USER_PYTHON = "pythonExecution"
USER_RUNS = (USER_SHELL, USER_PYTHON)

DECLINED = pi.DECLINED

# The title slot at the start of a file (session-title-slot.ts).
SLOT_TYPE = "title"
SLOT_BYTES = 256

# Entry types docs/session.md lists, and the title slot. Others are counted.
TYPES = (SLOT_TYPE, "session", "message", "model_usage",
         "thinking_level_change", "model_change", "service_tier_change",
         "compaction", "branch_summary", "reset_boundary", "custom",
         "custom_message", "label", "title_change", "ttsr_injection",
         "credential_pin", "session_init", "mode_change")

# Message roles omp writes (docs/session.md); "hookMessage" is the version 2
# name of "custom". Others are counted.
ROLES = ("user", "developer", "assistant", "toolResult", USER_SHELL,
         USER_PYTHON, "hookMessage", "fileMention", "custom")

# How omp spells a call it could not find (agent-loop.ts, v18.12.3).
NOT_FOUND = pi.NOT_FOUND
ABORTED_BEFORE = "Tool was not executed because the run was aborted"
VALIDATION = 'Validation failed for tool "'
NOT_RUN = "The tool was not run."
NOT_FOUND_TAIL = (". Did you mean", ". Closest available")

# A selector at the end of a read path (tools/read.ts).
_SELECTOR = re.compile(
    r":(?:-?\d+(?:[-+]\d*)?(?:,\d+(?:[-+]\d*)?)*|raw|img|conflicts)$")
_SELECTORS_MAX = 4
_SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://")
_WEB = re.compile(r"^https?://", re.IGNORECASE)
_FILE_URL = re.compile(r"^file://", re.IGNORECASE)
# omp splits a read path on ";" and, when the literal path is not a file,
# on "," and white space (read.ts, path-utils.ts); each piece is a target.
_SPLIT_HARD = ";"
_SPLIT_SOFT = re.compile(r"[,\s]+")
_PIECES_MAX = 64

# Lines of an apply_patch body that name a file.
_PATCH_HEADS = ("*** Add File:", "*** Update File:", "*** Delete File:",
                "*** Move to:")
_PATCH_PATHS_MAX = 256

# The registry marker holds one path; a longer file is not one.
_MARKER_MAX = 4096

_HEAD_MAX = 1 << 16
_LOG_CHUNK = 1 << 20
_LOG_OVERLAP = 1 << 12


def _string(value):
    return value if isinstance(value, str) and value else None


def _read_head(path):
    """(slot, header) of the file at `path`: whether it starts with the
    title slot, and the session header on line 1 or, after a slot, line 2
    ({} when there is none)."""
    try:
        with open(path, "rb") as fh:
            rows = [fh.readline(_HEAD_MAX), fh.readline(_HEAD_MAX)]
    except OSError:
        return False, {}
    objs = []
    for index, raw in enumerate(rows):
        try:
            obj = json.loads(_lines.decode_line(raw, first=index == 0))
        except (ValueError, RecursionError):
            obj = None
        objs.append(obj if isinstance(obj, dict) else {})
    if objs[0].get("type") == SLOT_TYPE:
        return True, objs[1] if objs[1].get("type") == "session" else {}
    return False, objs[0] if objs[0].get("type") == "session" else {}


def is_title_slot_file(path):
    """True when the file at `path` starts with omp's title slot, which no
    Pi version writes: the file is omp's. pi.py skips such a file."""
    return _read_head(path)[0]


def session_in_folder(folder):
    """The session id a subagent's folder <timestamp>_<id> stands for."""
    return pi.session_from_name(folder.rstrip("/\\") + SUFFIX)


# -- how a call's arguments are read ------------------------------------------

def _file_url_path(value):
    """The local path a file:// URI stands for (omp's stripFileUrl)."""
    rest = unquote(value[len("file://"):])
    if rest.lower().startswith("localhost/"):
        rest = rest[len("localhost"):]
    if re.match(r"^/[A-Za-z]:[\\/]", rest):
        rest = rest[1:]                 # file:///C:/x
    return rest


def _strip_selectors(value):
    for _ in range(_SELECTORS_MAX):
        stripped = _SELECTOR.sub("", value)
        if stripped == value:
            break
        value = stripped
    return value


def _one_target(value, out):
    """Add the file `value` names (one piece) to `out`; True for a web URL."""
    value = value.strip()
    if _WEB.match(value):
        return True
    if _FILE_URL.match(value):
        value = _file_url_path(value)
    elif _SCHEME.match(value):
        return False
    value = _strip_selectors(value)
    for path in ([value, value[1:]] if value.startswith("@")
                 and len(value) > 1 else [value]):
        if path and path not in out:
            out.append(path)
    return False


def _clean_path(value):
    """The file(s) a read or edit names: the value without a trailing
    selector. Returns (paths, web): the paths ("@x" as written and as Pi
    resolves it, since omp is a Pi fork and the sources read do not say
    whether it drops the "@"), and True for an http(s) URL. file:// is a
    local file; a ";" separates several targets, and "," or white space
    may (omp decides by whether the literal path exists, which is not known
    here, so the whole value and its pieces are all kept). Internal URIs
    (artifact://, local://, agent://, history://) name no file."""
    if _WEB.match(value):
        return (), True
    out, web = [], False
    pieces = value.split(_SPLIT_HARD)[:_PIECES_MAX]
    for piece in pieces:
        web = _one_target(piece, out) or web
        if _WEB.match(piece.strip()) or _SCHEME.match(piece.strip()) \
                and not _FILE_URL.match(piece.strip()):
            continue
        clean = _strip_selectors(piece.strip())
        if _SPLIT_SOFT.search(clean):
            for sub in _SPLIT_SOFT.split(clean)[:_PIECES_MAX]:
                if sub:
                    _one_target(sub, out)
    return tuple(out), web and not out


def _paths_in(arguments, selectors):
    """(paths, keys, web): the values of PATH_KEYS in a call's arguments."""
    paths, keys, web = [], [], False
    for key in PATH_KEYS:
        value = arguments.get(key)
        found = []
        for item in (value if isinstance(value, (list, tuple)) else [value]):
            if not isinstance(item, str) or not item:
                continue
            if selectors:
                got, is_web = _clean_path(item)
                web = web or is_web
                found.extend(got)
            else:
                found.append(item)
        if found:
            for path in found:
                if path not in paths:
                    paths.append(path)
            keys.append(key)
    return tuple(paths), tuple(keys), web


def _patch_paths(text):
    """File names on the header lines of an apply_patch body, read line by
    line (linear in the text, whatever the spaces on a line)."""
    out = []
    for line in text.split("\n"):
        if not line.startswith("*** "):
            continue
        for head in _PATCH_HEADS:
            if line.startswith(head):
                name = line[len(head):].strip()
                if name and name not in out:
                    out.append(name)
                break
        if len(out) >= _PATCH_PATHS_MAX:
            break
    return out


def classify(name, arguments):
    """(kind, known, command, paths, consumed, workdir) for a call to the
    tool `name` with these (decoded) arguments."""
    if name == SHELL:
        command = _string(arguments.get("command"))
        return ("shell", True, command, (),
                ("command",) if command else (), _string(arguments.get("cwd")))
    if name == EVAL:
        code = _string(arguments.get("code"))
        return "shell", True, code, (), ("code",) if code else (), None
    if name == READ:
        paths, keys, web = _paths_in(arguments, True)
        if web and not paths:
            return "fetch", True, None, (), (), None
        return "read", True, None, paths, keys, None
    if name == WRITE:
        paths, _keys, _web = _paths_in(arguments, False)
        return "write", True, None, paths, (), None
    if name == EDIT:
        paths, _keys, _web = _paths_in(arguments, False)
        paths = list(paths)
        edits = arguments.get("edits")
        for item in edits if isinstance(edits, list) else ():
            rename = item.get("rename") if isinstance(item, dict) else None
            if isinstance(rename, str) and rename and rename not in paths:
                paths.append(rename)
        patch = arguments.get("input")
        if isinstance(patch, str):
            paths.extend(p for p in _patch_paths(patch) if p not in paths)
        return "write", True, None, tuple(paths), (), None
    return "other", False, None, (), (), None


def _walk(folder):
    """(files, folders) directly in `folder`: *.jsonl files and
    sub-folders, none of them dot-entries."""
    files, folders = [], []
    for entry in pi._entries(folder):
        if entry.name.startswith("."):
            continue
        try:
            if entry.is_dir():
                folders.append(entry.path)
            elif entry.name.endswith(SUFFIX) and entry.is_file():
                files.append(entry.path)
        except OSError:
            continue
    return files, folders


_ARTIFACT_LOG = re.compile(r"^\d+\..+\.log$")


def _artifact_logs(folder):
    """[(path, session id, session file)] for the spilled tool output
    (<n>.<tool>.log) in each session's artifact folder under `folder`."""
    out = []
    for sub in _walk(folder)[1]:
        for entry in pi._entries(sub):
            try:
                if (_ARTIFACT_LOG.match(entry.name) and entry.is_file()
                        and not entry.is_symlink()):
                    out.append((entry.path, session_in_folder(
                        os.path.basename(sub)), sub + SUFFIX))
            except OSError:
                continue
    return out


def _transcripts(folder):
    """[(path, parent)] for the session files in `folder` and, one level
    down, in each session's artifact folder (parent is that session's id,
    or None for a file directly in `folder`)."""
    files, folders = _walk(folder)
    out = [(path, None) for path in files]
    for sub in folders:
        out.extend((path, session_in_folder(os.path.basename(sub)))
                   for path in _walk(sub)[0])
    return out


class OhMyPiSource(PiSource):
    id = "omp"
    name = "Oh My Pi"
    unit = "session"
    env = (ENV, SESSION_ENV, CONFIG_ENV, XDG_DATA, XDG_STATE)
    path_means = "an Oh My Pi agent folder (what PI_CODING_AGENT_DIR means)"
    checked = "18.12.3"
    mask_note = ("If Oh My Pi is open on this session, close it first: it "
                 "holds the file and checks its size, and a fork made from "
                 "it later is copied from memory, value included.")

    # -- where to look ------------------------------------------------------

    def default_paths(self, env, home, platform):
        """The agent folders omp can write to, in the order omp prefers
        them: PI_CODING_AGENT_DIR; $XDG_DATA_HOME/omp (Linux and macOS);
        ~/.omp/agent (or PI_CONFIG_DIR instead of .omp); the profile
        folders under ~/.omp and under XDG; PI_CODING_AGENT_SESSION_DIR; and
        the XDG state folder, where the custom-session-files registry
        moves to."""
        pm = _paths.pathmod(platform)
        win = _paths.platform_name(platform) == "win32"
        config = _string(env.get(CONFIG_ENV)) or CONFIG_DIR
        root = pm.normpath(home + pm.sep + config)
        agent = _string(env.get(ENV))
        data = None if win else _string(env.get(XDG_DATA))
        state = None if win else _string(env.get(XDG_STATE))
        out = []
        if agent:
            out.append((agent, HOW_AGENT))
        elif data:
            out.append((pm.join(data, APP), HOW_XDG))
        out.append((pm.join(root, AGENT), "default"))
        out.append((pm.join(root, PROFILES), HOW_PROFILES))
        if data:
            out.append((pm.join(data, APP, PROFILES), HOW_XDG_PROFILES))
        flat = _string(env.get(SESSION_ENV))
        if flat:
            out.append((flat, HOW_SESSION))
        if state:
            out.append((pm.join(state, APP), HOW_XDG_STATE))
        return out

    @staticmethod
    def agent_folders(location):
        """The agent folders a location stands for: itself, or for a
        profiles folder each profile in it (<name>/agent, or <name> under
        XDG)."""
        if location.how in (HOW_PROFILES, HOW_XDG_PROFILES):
            out = []
            for sub in pi._folders(location.path):
                out.append(os.path.join(sub, AGENT))
                out.append(sub)
            return out
        if location.how in (HOW_SESSION, HOW_XDG_STATE):
            return []
        return [location.path]

    def session_folders(self, location):
        """The folders whose *.jsonl files (and artifact folders) are
        sessions."""
        out = []
        if location.how == HOW_SESSION:
            out.append(location.path)
        for agent in self.agent_folders(location):
            out.extend(pi._folders(os.path.join(agent, SESSIONS)))
        if location.how != HOW_SESSION and pi._is_session_dir(location.path):
            out.append(location.path)
        return out

    @staticmethod
    def registry_paths(location):
        """The transcripts custom-session-files markers name. A marker is
        one small file holding an absolute path."""
        folders = ([location.path] if location.how == HOW_XDG_STATE
                   else OhMyPiSource.agent_folders(location))
        out = []
        for folder in folders:
            for entry in pi._entries(os.path.join(folder, REGISTRY)):
                try:
                    if entry.name.startswith(".") or not entry.is_file():
                        continue
                    with open(entry.path, "rb") as fh:
                        raw = fh.read(_MARKER_MAX + 1)
                except OSError:
                    continue
                if len(raw) > _MARKER_MAX:
                    continue
                target = raw.decode("utf-8", "replace").strip()
                if (target and "\n" not in target and os.path.isabs(target)
                        and target.endswith(SUFFIX)
                        and os.path.isfile(target)):
                    out.append(target)
        return out

    def _candidates(self, location):
        """[(path, parent session, shared)] for one location."""
        shared = location.how in SHARED
        out = []
        for folder in self.session_folders(location):
            out.extend((path, parent, shared, None)
                       for path, parent in _transcripts(folder))
            out.extend((path, session, shared, owner)
                       for path, session, owner in _artifact_logs(folder))
        # A marker is omp's own record of the file, whatever its first line.
        out.extend((path, None, False, None)
                   for path in self.registry_paths(location))
        return out

    def _own_roots(self, locations):
        """The folders whose files are omp's whatever their first line says:
        the default root, profiles and XDG folders omp would look in now
        (even when a location for them was dropped as a repeat of
        PI_CODING_AGENT_DIR) and every given location that is not shared
        with Pi."""
        out = []
        try:
            pairs = self.default_paths(os.environ, _paths.home(),
                                       _paths.platform_name())
        except Exception:
            pairs = []
        for path, how in pairs:
            if path and how not in SHARED:
                out.append(path)
        out.extend(loc.path for loc in locations if loc.how not in SHARED)
        return [os.path.normcase(os.path.abspath(os.path.expanduser(p)))
                for p in out]

    @staticmethod
    def _under(path, roots):
        key = os.path.normcase(os.path.abspath(path))
        return any(key == r or key.startswith(r.rstrip("\\/") + os.sep)
                   for r in roots)

    def stores(self, locations, since_days=None):
        found, seen = [], set()
        roots = self._own_roots(locations)
        for loc in locations:
            for path, parent, shared, owner in self._candidates(loc):
                key = os.path.normcase(os.path.abspath(path))
                if key in seen:
                    continue
                if shared and self._under(path, roots):
                    shared = False  # under omp's own folder: omp's
                if owner is not None:
                    # spilled output: the store of the session that spilled
                    # it, when that session is omp's
                    if shared and not _read_head(owner)[0]:
                        continue
                    if not os.path.isfile(owner) and not parent:
                        continue
                    seen.add(key)
                    store = self.store(path, "text", role="side",
                                       unit="tool output", session=parent)
                    if store is not None:
                        found.append(store)
                    continue
                slot, header = _read_head(path)
                if shared and not slot:
                    continue        # Pi's, or from before the title slot
                seen.add(key)
                session = (_string(header.get("id")) or parent
                           or pi.session_from_name(path))
                store = self.store(path, "jsonl", role="transcript",
                                   session=session,
                                   project=_string(header.get("cwd")))
                if store is not None:
                    found.append(store)
        return base.newest_first(found, since_days)

    # -- reading ------------------------------------------------------------

    @staticmethod
    def _unknown(obj):
        if not isinstance(obj, dict) or obj.get("type") not in TYPES:
            return True
        if obj.get("type") == "message":
            message = obj.get("message")
            return not (isinstance(message, dict)
                        and message.get("role") in ROLES)
        return False

    def _call(self, store, block, entry, header, message):
        call = PiSource._call(self, store, block, entry, header, message)
        if not _string(block.get("namespace")):
            (call.kind, call.known, call.command, paths, consumed,
             call.workdir) = classify(call.tool_name, call.tool_input)
            call.paths = tuple(paths)
            call.consumed = frozenset(consumed)
        return call

    @staticmethod
    def _not_executed(message, output, name):
        """True for the result omp writes instead of running a call:
        details.executed is false (a synthetic result), "Tool X not found"
        with or without omp's suggestion, or Pi's text for "length"."""
        details = message.get("details")
        if isinstance(details, dict):
            if details.get("executed") is False:
                return True
            if (details.get("__synthetic") is True
                    and details.get("executed") is not True
                    and not details.get("__interrupted")):
                return True
        if message.get("isError") is True and isinstance(output, str):
            # agent-loop.ts / validation.ts: a call refused before it ran
            if (output.startswith(ABORTED_BEFORE)
                    or output.startswith(VALIDATION)
                    or NOT_RUN in output):
                return True
            if (isinstance(details, dict) and details.get("isError") is True
                    and details.get("error") == output):
                return True
        tool = _string(message.get("toolName"))
        if (tool and message.get("isError") is True
                and isinstance(output, str)):
            text = NOT_FOUND % tool
            if output == text or any(output.startswith(text + tail)
                                     for tail in NOT_FOUND_TAIL):
                return True
        return PiSource._not_executed(message, output, name)

    def _user_run(self, store, entry, header, message):
        """The ToolCall for a bashExecution or pythonExecution message: what
        the user ran, its output in the same message. A cancelled run still
        ran."""
        if message.get("role") == USER_SHELL:
            return self._user_shell(store, entry, header, message)
        code = _string(message.get("code"))
        output = message.get("output")
        return ToolCall(
            self.id, store.path, USER_PYTHON,
            {"code": code} if "code" in message else {}, kind="shell",
            known=True, actor="user", tool_call_id=_string(entry.get("id")),
            command=code, consumed=("code",) if code else (),
            output=output if isinstance(output, str) else None,
            **self._base(store, entry, header, message))

    def tool_calls(self, store):
        """Every call in the file, on every branch of its tree, once per id,
        with its result's text as output when the file holds one. A call is
        yielded when its result arrives, and calls still waiting at the end
        of the file are yielded then. A call that never ran is "declined"
        (see the module notes). What the user ran with "!" or "$" is a call
        with actor "user". The title slot and entries of other types are
        passed over."""
        if store.role != "transcript":
            return
        header = {}
        pending = {}            # toolCall id -> ToolCall awaiting its result
        done = set()            # ids already yielded
        cut = {}                # toolCall id -> name, its message hit "length"
        for _line_no, obj, _text in self._records(store):
            if obj is pi._BAD:
                continue
            if isinstance(obj, dict) and obj.get("type") == "session":
                if not header:
                    header = obj
                continue
            message = self._message(obj)
            if message is None:
                continue
            role = message.get("role")
            if role in USER_RUNS:
                eid = _string(obj.get("id"))
                if eid is None or eid not in done:
                    if eid is not None:
                        done.add(eid)
                    yield self._user_run(store, obj, header, message)
                continue
            if role == "toolResult":
                cid = message.get("toolCallId")
                call = pending.pop(cid, None) if isinstance(cid, str) else None
                if call is not None:
                    call.output = pi.output_text(message.get("content"))
                    refused = message.get("isError") is True and pi._refused(
                        call.output, _string(message.get("toolName")))
                    if self._not_executed(message, call.output,
                                          cut.pop(cid, None)) or refused:
                        call.status = DECLINED
                    done.add(cid)
                    yield call
                continue
            length = message.get("stopReason") == pi.LENGTH
            for block in self._tool_calls_in(message):
                call = self._call(store, block, obj, header, message)
                cid = call.tool_call_id
                if cid is None:
                    yield call
                elif cid not in done and cid not in pending:
                    pending[cid] = call
                    if length:
                        cut[cid] = _string(block.get("name")) or ""
        for call in pending.values():
            yield call

    def secret_texts(self, store):
        """Every line of the file, whatever its type, the title slot
        included. A tool result's content, and the output of a "!" or "$"
        run, are handed over on their own and tied to the call that
        produced them; the rest of that line is handed over without them.
        A line that is not JSON is handed over as text. The copies of a
        command in tool_execution_start and session_exit entries are in the
        whole line."""
        if store.role == "side":
            yield from self._log_texts(store)
            return
        if store.role != "transcript":
            return
        header = {}
        calls = {}              # toolCall id -> ToolCall, first copy
        for line_no, obj, text in self._records(store):
            where = "line %d" % line_no
            if obj is pi._BAD:
                yield SecretText(text, where=where)
                continue
            if (not header and isinstance(obj, dict)
                    and obj.get("type") == "session"):
                header = obj
            message = self._message(obj)
            role = message.get("role") if message is not None else None
            if role == "toolResult" and "content" in message:
                cid = message.get("toolCallId")
                call = calls.get(cid) if isinstance(cid, str) else None
                yield SecretText(self._without(obj, message, "content"),
                                 where=where)
                yield SecretText(message["content"], call=call, where=where)
                continue
            if role in USER_RUNS and "output" in message:
                call = self._user_run(store, obj, header, message)
                yield SecretText(self._without(obj, message, "output"),
                                 where=where)
                yield SecretText(message["output"], call=call, where=where)
                continue
            if message is not None:
                for block in self._tool_calls_in(message):
                    call = self._call(store, block, obj, header, message)
                    cid = call.tool_call_id
                    if cid is not None and cid not in calls:
                        calls[cid] = call
            yield SecretText(obj, where=where)

    def _log_texts(self, store):
        """A spilled tool output log, in overlapping chunks so that a value
        split by a chunk boundary is still whole in one of them (it is not
        tied to a call: the artifact id that links them is not verified)."""
        try:
            fh = open(store.path, "rb")
        except OSError as e:
            self._bad_store(store, e.strerror or str(e))
            return
        with fh:
            tail, offset = b"", 0
            while True:
                try:
                    block = fh.read(_LOG_CHUNK)
                except OSError as e:
                    self._bad_store(store, e.strerror or str(e))
                    return
                if not block:
                    break
                data = tail + block
                yield SecretText(data.decode("utf-8", "surrogateescape"),
                                 where="offset %d" % max(0, offset))
                offset += len(block)
                tail = data[-_LOG_OVERLAP:]
            if offset == 0:
                return

    # -- masking ------------------------------------------------------------

    @staticmethod
    def _slot_text(path):
        """The title slot at the start of the file, as text, or None."""
        try:
            with open(path, "rb") as fh:
                raw = fh.readline(_HEAD_MAX)
        except OSError:
            return None
        text = _lines.decode_line(raw, first=True)
        try:
            obj = json.loads(text)
        except (ValueError, RecursionError):
            return None
        if isinstance(obj, dict) and obj.get("type") == SLOT_TYPE:
            return text
        return None

    def mask(self, store, values):
        """As the base does, except that a file whose title slot holds one
        of the values is refused: the slot is 256 bytes that omp writes over
        in place, and masking would change its length."""
        if store.masking == "rewrite":
            slot = self._slot_text(store.path)
            if slot is not None and any(
                    form in slot for value in values if value
                    for form in _rewrite.encodings(value)):
                return MaskResult(store.path, skipped=_rewrite.ALTERED)
        return Source.mask(self, store, values)
