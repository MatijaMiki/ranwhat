"""Kilo Code (Kilo-Org/kilocode): the kilo CLI (@kilocode/cli), the VS Code
extension kilocode.kilo-code and the JetBrains plugin, all three on one
backend.

Verified from Kilo's own source at v7.8.15 (commit 5cc65d1, 2026-10-19, built
on OpenCode v1.18.26) and v1.0.25 (the JSON-file era). Nothing of it was
run; the fixtures in the tests are written field for field from that source.

Where: one data folder, join(xdg-basedir data home, "kilo"): $XDG_DATA_HOME/
kilo, else ~/.local/share/kilo, on every system, Windows (%USERPROFILE%\\
.local\\share\\kilo) and macOS included (core global.ts; xdg-basedir does not
branch by OS; the docs page session-history.md says the same). The 7.0.26
changelog's "%APPDATA% on windows" contradicts the code and the current docs
and is not followed. Both IDE extensions start the bundled CLI, so all three
write the same database, and VS Code Remote SSH writes it on the remote host.
KILO_DB names the database: an absolute path as it is, ":memory:" none at all,
anything else under the data folder (core database/database.ts path(), the
same logic as opencode/src/storage/db.ts getPath). Without it the file is
kilo.db (channel latest, beta or prod, or KILO_DISABLE_CHANNEL_DB 1 or true,
which both extensions set), else kilo-<channel>.db, or the older
opencode-<channel>.db when only that exists. So every kilo*.db and
opencode-*.db in the data folder is read, and the file KILO_DB names when it
is set. The data folder is searched, not guessed: `kilo db path` prints the
file in use.

The database (SQLite, WAL mode) is OpenCode v1.18's. It is read by
opencode.py's reader, which this module extends: its v1 tables (session,
message, part; core session/sql.ts) hold every tool call as a part
{"type": "tool", "callID", "tool", "state": {"status", "input", "output"?,
"error"?, "metadata"?, "time"}} (schema v1/session.ts ToolPart), the message
carrying path.cwd. What differs from OpenCode:
- the names above (folder kilo, KILO_DB, kilo*.db), and the tool names below;
- session_message, whose foreign key points at session, not session_v2, and
  whose seq may be NULL (migration 20260714141136_session-message-legacy-
  writer-compat), which only changes the order its rows are read in. It is
  written only when KILO_EXPERIMENTAL(_EVENT_SYSTEM) is on, with v1.18's early
  shape (shell rows {callID, command, output string, time}); Kilo writes each
  with the call id of its bash part, so the call is read once. Kilo does not
  use v2's runner, so no assistant rows appear there. The partial indexes on
  json_valid/json_extract need an SQLite with JSON functions to open the
  schema; Python's builds have them, and a build without them is counted
  unreadable, not guessed at;
- calls imported from older extensions (below).

Older stores, both read:
- Kilo CLI 1.0.x to 7.0.25 (an OpenCode 1.x fork, app "kilo"; v1.0.25
  global/index.ts and storage/storage.ts): JSON files under <data>/storage,
  session/<projectID>/<sessionID>.json, message/<sessionID>/<messageID>.json,
  part/<messageID>/<partID>.json, the layout opencode.py documents. 7.0.26
  copied them into kilo.db once and left them in place
  (kilocode/storage/json-migration.ts), so a session the database holds gives
  from its files only the calls it does not hold, by call id.
- <data>/tool-output/tool_*: the whole output of a tool Kilo cut short, plain
  text (tool/truncation-dir.ts), searched for secrets.

Tool names (every Tool.define of opencode/src/tool and opencode/src/kilocode
at v7.8.15):
- shell: bash {command, timeout?, workdir?, description?}, and Kilo's
  background_process {action, command?, workdir?, id?, description?} when
  action is "start" or "monitor" (kilocode/tool/background-process.ts): its
  workdir is resolved against the project directory, so a relative one is
  joined to the message's cwd, else the session's directory. Its other
  actions (list, status, logs, stop, restart) run nothing new.
- read: read {filePath}, notebook_read {path}, send_file {path} (sends a local
  file to the Kilo mobile app, so the file is read, and away).
- write: write {filePath, content}, edit and apply_patch as in OpenCode,
  generate_image {prompt, path (written), image? (read)}, notebook_edit
  {path, action, ...}, notebook_execute {path, expected_revision, index}
  (runs a cell and stores its output in the notebook).
- fetch: webfetch, websearch, browser_open {url}, repo_clone {repository,
  branch?, refresh?} (a clone from the network).
- others, with no path or command: glob, grep, task, todowrite, question,
  skill, lsp, invalid, plan_exit, execute (code mode: its nested calls are
  read by name, as opencode.py does), repo_overview, semantic_search,
  kilo_local_recall, kilo_memory_recall, kilo_memory_save, agent_manager,
  agent_manager_models, board_read, board_post, goal, goal_report,
  get_context_info, compact, chart, cron_create, cron_list, cron_delete,
  schedule_wakeup, cancel_wakeup, link_pr, notify_user, open_plan, suggest.
MCP tools are named <server>_<tool> after sanitizing; any other name is not
known, and judged by name.

Tasks imported from Roo and from the 4.x/5.x extension (kilo-vscode
legacy-migration/sessions/lib/parts/parts-builder.ts, merge-tools.ts, ids.ts;
roo-import/service.ts): each tool_use block becomes a part with the tool name
and input copied verbatim (execute_command {command, cwd}, read_file,
write_to_file, ...), callID the tool_use id, status always "completed" (a
denied call shows as completed), ids ses_migrated_/msg_migrated_/prt_migrated_
plus a sha1 prefix. Calls of tasks written with the old XML protocol get no
part. Those names are classified with roo.py's table; the 5.x names themselves
were not checked against a 5.x tag (none exists in the repository), so a name
not in that table is not known. Roo's own copies of these tasks are read by
the roo source, so a task imported from Roo is seen twice, once per source;
nothing here drops a session by id.

The 4.x/5.x extension's own task folders (<editor>/User/globalStorage/
kilocode.kilo-code/tasks/<taskId>/api_conversation_history.json, the
Cline/Roo format) are not read here: the 7.x extension imports them into
kilo.db and keeps them. Point --path roo=<that folder> at one to have the Roo
reader read it.

Declined calls: the texts and errors are OpenCode v1's (core v1/permission.ts:
"The user rejected permission to use this specific tool call.", "... with the
following feedback: ...", "The user has specified a rule which prevents you
from using this specific tool call."), and "Tool execution aborted" of a call
never started (Kilo adds metadata.interrupted; a call that did run is not
taken for declined). Commands the user runs with "!" are a synthetic user
text, "The following tool was executed by the user", then an assistant
message with one bash part (prompt.ts shellImpl; Kilo gives that part a ulid
call id); actor "user".

Timestamps are milliseconds since 1970. A call's session is its session id,
its project the session's directory. Windows directories are stored with
forward slashes (as upstream).

Not read: the credential, account, account_state and control_account tables
(tokens), session_share (share secrets), event, project, permission, the
Kilo-only data_migration and the others not listed in SEARCHED_TABLES;
<data>/log/ and background-process/ (logs and manifests of processes, in the
data folder and in $XDG_STATE_HOME/kilo), worktree-pool/ (git checkouts), the
-wal and -shm files themselves (SQLite reads them) and the kilo.db.json-
migration marker. Session retention is off unless kilo.json turns it on, in
which case old sessions are gone before this sees them. The database is opened
read-only, and nothing is written beside it.
"""

from __future__ import annotations

import os

from . import _cline_tasks as T
from . import _paths, base, roo
from . import opencode as oc
from .base import ToolCall

DB_ENV = "KILO_DB"
DATA_ENV = oc.DATA_ENV
FOLDER = "kilo"
MEMORY = oc.MEMORY

DB_PREFIXES = ("kilo", "opencode-")
DB_SUFFIX = oc.DB_SUFFIX

SHELL = oc.SHELL
BACKGROUND = "background_process"
BACKGROUND_RUNS = ("start", "monitor")
READ = oc.READ + ("notebook_read", "send_file")
WRITE = oc.WRITE + ("generate_image", "notebook_edit", "notebook_execute")
FETCH = oc.FETCH + ("browser_open", "repo_clone")
OTHER = oc.OTHER + (
    "background_process", "repo_overview", "semantic_search",
    "kilo_local_recall", "kilo_memory_recall", "kilo_memory_save",
    "agent_manager", "agent_manager_models", "board_read", "board_post",
    "goal", "goal_report", "get_context_info", "compact", "chart",
    "cron_create", "cron_list", "cron_delete", "schedule_wakeup",
    "cancel_wakeup", "link_pr", "notify_user", "open_plan", "suggest")

# Kilo's own tools that name one file at "path".
KILO_PATHS = ("generate_image", "notebook_read", "notebook_edit",
              "notebook_execute", "send_file")


def _string(value):
    return value if isinstance(value, str) and value else None


def databases(folder):
    """Every kilo*.db and opencode-*.db file in the data folder, by name."""
    out = set()
    for prefix in DB_PREFIXES:
        out.update(oc._files(folder, DB_SUFFIX, prefix))
    return sorted(out)


def env_database(data, env=None):
    """The file KILO_DB names, for the data folder `data`, or None (unset,
    empty, or ":memory:")."""
    env = os.environ if env is None else env
    value = _string(env.get(DB_ENV))
    if not value or value == MEMORY:
        return None
    return os.path.normpath(os.path.join(data, value))


def classify(name, arguments, cwd=None):
    """(kind, known, command, paths, consumed, workdir) for a call to the
    Kilo tool `name` with these (decoded) arguments; `cwd` is where a
    relative workdir of background_process is resolved from."""
    if name == BACKGROUND:
        command = _string(arguments.get("command"))
        if arguments.get("action") in BACKGROUND_RUNS and command:
            return ("shell", True, command, (), ("command",),
                    T.join_cwd(cwd, _string(arguments.get("workdir"))))
        return "other", True, None, (), (), None
    if name in KILO_PATHS:
        path = _string(arguments.get("path"))
        paths = (path,) if path else ()
        kind = "read" if name in READ else "write"
        consumed = ("path",) if path and kind == "read" else ()
        image = _string(arguments.get("image")) \
            if name == "generate_image" else None
        if image:       # an existing file, sent to the image model
            paths += (image,)
            consumed += ("image",)
        return kind, True, None, paths, consumed, None
    if name in oc.SHELL or name in oc.READ or name in oc.WRITE \
            or name in oc.FETCH or name in oc.OTHER:
        return _opencode(name, arguments)
    if name in FETCH:
        return "fetch", True, None, (), (), None
    if name in OTHER:
        return "other", True, None, (), (), None
    kind = roo.TOOLS.get(name)
    if kind is not None:
        return _imported(name, kind, arguments, cwd)
    return "other", False, None, (), (), None


def _opencode(name, arguments):
    """OpenCode's reading of a tool both it and the older extensions have:
    a call imported from Roo or 4.x/5.x keeps its own argument names (path,
    file_path, files, patch), tried when the OpenCode ones name nothing."""
    kind, known, command, paths, consumed, workdir = oc.classify(name,
                                                                 arguments)
    if kind in ("read", "write") and not paths:
        found, keys = roo._paths_in(arguments)
        paths = tuple(found) or T.patch_paths(arguments.get("patch"))
        if kind == "read":
            consumed = tuple(keys)
    return kind, known, command, paths, consumed, workdir


def _imported(name, kind, args, cwd):
    """A call imported from Roo or the 4.x/5.x extension, by roo.py's table:
    its names and inputs are copied verbatim."""
    if kind == "shell":
        command = _string(args.get("command"))
        return ("shell", True, command, (), ("command",) if command else (),
                T.join_cwd(cwd, _string(args.get("cwd"))))
    if name == "apply_patch":
        return "write", True, None, T.patch_paths(args.get("patch")), (), None
    if kind in ("read", "write"):
        paths, keys = roo._paths_in(args)
        return kind, True, None, tuple(paths), \
            tuple(keys) if kind == "read" else (), None
    return kind, True, None, (), (), None


class KiloSource(oc.OpenCodeSource):
    id = "kilo"
    name = "Kilo Code"
    unit = "file"           # one database holds many sessions; see agents.amount
    env = (DB_ENV,)
    path_means = ("a Kilo data folder (~/.local/share/kilo), or its database "
                  "file")
    checked = "7.8.15 and 1.0.25"
    # OpenCode's tables plus the Kilo-only free text: the agents' board posts
    # (kilo_board_message.body) and a board's objective.
    SEARCHED_TABLES = oc.SEARCHED_TABLES + (
        ("kilo_board_message", ("body",)), ("kilo_board", ("objective",)))

    # -- where to look ------------------------------------------------------

    def default_paths(self, env, home, platform):
        """$XDG_DATA_HOME/kilo, else ~/.local/share/kilo, on every system;
        and the database KILO_DB names, when it is set and is not ":memory:"
        (an absolute path as it is, else under the data folder)."""
        plat = _paths.platform_name(platform)
        pm = _paths.pathmod(plat)
        moved = _string(env.get(DATA_ENV))
        data = pm.join(_paths.xdg_data_home(env, home, plat), FOLDER)
        out = [(data, "env " + DATA_ENV if moved else "default")]
        db = _string(env.get(DB_ENV))
        if db and db != MEMORY:
            out.append((pm.join(data, db), "env " + DB_ENV))
        return out

    def stores(self, locations, since_days=None):
        found, seen = [], set()

        def add(store):
            if store is None:
                return None
            key = os.path.normcase(os.path.abspath(store.path))
            if key in seen:
                return None
            seen.add(key)
            found.append(store)
            return store

        for loc in locations:
            path = loc.path
            if oc._regular(path):
                add(self._database(path))
                continue
            if not os.path.isdir(path):
                continue
            for db in databases(path):
                add(self._database(db))
            self._storage(path, add)
            for out in oc._files(os.path.join(path, oc.TOOL_OUTPUT), "",
                                 oc.TOOL_OUTPUT_PREFIX):
                add(self.store(out, "text", role="side", unit="tool output"))
        return base.newest_first(found, since_days)

    @staticmethod
    def _db_paths(data):
        paths = databases(data)
        named = env_database(data)
        if named and named not in paths:
            paths.append(named)
        return paths

    # -- building calls -----------------------------------------------------

    def _call(self, store, name, arguments, call_id, ms, fallback_ms,
              session, project, cwd=None, actor="agent", status=None,
              output=None):
        arguments = base.decode_input(arguments)
        base_dir = cwd or project
        kind, known, command, paths, consumed, workdir = classify(
            name, arguments, base_dir)
        if kind == "shell" and not workdir:
            workdir = cwd
        timestamp = oc._ms(ms) or oc._ms(fallback_ms)
        return ToolCall(
            self.id, store.path, name, arguments, kind=kind, known=known,
            session=session, project=project, timestamp=timestamp,
            tool_call_id=call_id, actor=actor, status=status,
            not_after=None if timestamp else oc._stamps.iso_utc(store.mtime,
                                                                "s"),
            command=command, workdir=workdir, paths=paths, consumed=consumed,
            output=output)
