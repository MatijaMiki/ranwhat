"""Cline (cline/cline): the VS Code extension saoudrizwan.claude-dev, its
JetBrains plugin and its CLI.

Checked against v4.1.23 (commit afaf4f2, 2026-10-07) and v3.89.2 (commit
e1bdeef, the last 3.x, which 4.x still ships as its "legacy" bundle), with
v3.0.0 and v3.20.0 for older shapes. Paths below are under apps/vscode/src
(C3/C4) and sdk/packages (SDK) of those tags.

Cline writes two formats, and since 4.x one install can write both: the
4.x VSIX holds both runtimes and picks one per window
(apps/vscode-rollout/README.md), and the 4.x SDK still reads the old
tasks. Both are read on every version.

1. Task folders (Cline 3.x, the 4.x legacy bundle, the JetBrains plugin
   and the pre-4 CLI): <storage>/tasks/<taskId>/ with
   api_conversation_history.json (the transcript), ui_messages.json (the
   chat log; a side store) and claude_messages.json (its Claude Dev name),
   read as _cline_tasks.py describes. The task id is Date.now() as text
   (C3/core/controller/index.ts). <storage> is
   <editor>/User/globalStorage/saoudrizwan.claude-dev under the editor
   parent folder, for VS Code and the forks _paths probes (VS Code
   lower-cases the publisher; C3/core/storage/disk.ts
   ensureTaskDirectoryExists, the host's globalStorageFsPath; a remote
   editor's ~/.vscode-server is not probed: --path reaches it),
   saoudrizwan.cline-nightly for the nightly build
   (apps/vscode-rollout/scripts/nightlify.mjs), or, for the JetBrains
   plugin and older CLI, the data folder below
   (C3/standalone/vscode-context.ts). Cline has no setting that moves it.
   Tool names (C3/shared/tools.ts ClineDefaultTool, a superset of v3.0.0's
   and v3.20.0's lists) and XML parameter names (C3/core/assistant-message/
   index.ts toolParamNames) are the same in both protocols:
   execute_command{command, requires_approval, timeout?}, read_file{path},
   write_to_file{path, content}, replace_in_file{path, diff},
   new_rule{path, content} (written by the write_to_file handler,
   ToolExecutorCoordinator.ts), apply_patch{input} (the paths are in the
   patch), web_fetch{url}, web_search{query}, browser_action{action, url?}.
   In a multi-root workspace a path may start "@<workspace>:" (core/
   workspace/utils/parseWorkspaceInlinePath.ts); that hint is dropped.
   Besides the shared "never ran" texts, a call refused by .clineignore or
   CLINE_COMMAND_PERMISSIONS never ran: its result is toolError() of
   clineIgnoreError or permissionDeniedError (C3/core/prompts/responses.ts).
   The working directory is cwdOnTaskInitialization in the task index,
   <storage>/state/taskHistory.json (C3/core/storage/disk.ts; a JSON array
   of HistoryItem), else the environment details.

2. SDK sessions (Cline 4.x extension and CLI): <data>/sessions/<sessionId>/
   holds <sessionId>.json, the manifest ({session_id, cwd, workspace_root,
   started_at, ...}; SDK/core/src/session/models/session-manifest.ts), and
   <sessionId>.messages.json ({version, updated_at, agent, sessionId,
   messages: [...], ...}; SDK/core/src/services/session-data.ts), plus
   <agentId>.messages.json and <agentId>__<teamTaskId>.messages.json for
   sub-agents and teammates in the same folder
   (SDK/core/src/services/session-artifacts.ts). A bare messages array is
   read too, as the SDK reads it (runtime/host/runtime-host-support.ts).
   Both are JSON.stringify(x, null, 2), written in place, not through a
   temp file (session/stores/session-manifest-store.ts): a file caught half
   written does not parse, warns, and is counted as not read. The session
   id is <ms>_<nanoid>. Calls are native only: tool_use / tool_result
   blocks, the result also carrying "name" and "is_error", its content a
   string, a JSON string of an object, or an array of ToolOperationResult
   {query, result, error?, success} (session/persisted-tool-result-
   content.ts). Tools (SDK/core/src/extensions/tools/constants.ts,
   schemas.ts): run_commands {commands: [...]}, which runs each command,
   so each is a call here, with the id "<tool_use id>#<n>" when there is
   more than one, and the n-th result entry as its output; every input
   shape RunCommandsInputUnionSchema takes is read (a string, a list,
   {command, args} run without a shell, {cmd}), split heredocs joined back
   as the tool joins them (definitions.ts coalesceAdjacentStringHeredocs),
   and {command, args} rendered as formatRunCommandQuery renders it
   (helpers.ts). read_files {files: [{path}]} and its aliases (file_path,
   filePath, paths, file_paths, a string, a list); editor {path, old_text?,
   new_text} (creates a missing file: a write); apply_patch {input} or a
   string; fetch_web_content {requests: [{url, prompt}]}; search_codebase,
   skills, ask_question and submit_and_exit. A call never ran when its
   result is {"error": ...} with a reason the runtime writes instead of
   running it: a refused approval ("<reason> -- NOT a tool or system
   failure. Clarify with user before proceeding.", USER_REJECTED_TOOL_REASON
   among them, SDK/shared/src/llms/tools.ts), 'Tool "<name>" is disabled
   by policy', "Unknown tool: <name>" or "Tool <name> was blocked by a
   runtime hook" (SDK/agents/src/agent-runtime.ts). The working directory is
   the manifest's cwd. sessions.db beside it indexes the same data and is
   not read; <sessionId>.compaction.json is not read.

The data folder is CLINE_DATA_DIR (trimmed) when set, else $CLINE_DIR/data,
else ~/.cline/data (C4/shared/storage/storage-context.ts,
SDK/shared/src/storage/paths.ts); the sessions folder is
CLINE_SESSION_DATA_DIR when set, else <data>/sessions. The default is
looked at beside a folder a variable names: the editor is usually started
without the shell's variables.

Not read, ever: <data>/secrets.json (API keys and OAuth tokens in plain
text), <data>/settings/ (providers.json holds keys and tokens,
cline_mcp_settings.json MCP servers' env), <data>/db/ (connectors.db,
sessions.db), globalState.json, workspaces/, and in the editor's folder
anything but tasks/ and state/taskHistory.json (checkpoints/, cache/,
settings/). Login material is never searched.
"""

from __future__ import annotations

import json
import os
import re

from . import _cline_tasks as T
from . import _paths, base
from .base import SecretText

DATA_ENV = "CLINE_DATA_DIR"
DIR_ENV = "CLINE_DIR"
SESSION_ENV = "CLINE_SESSION_DATA_DIR"

IDS = ("saoudrizwan.claude-dev", "saoudrizwan.cline-nightly")
ROOT = (".cline", "data")
SESSIONS = "sessions"
INDEX = ("state", "taskHistory.json")
MESSAGES = ".messages.json"

# The task index can be large; one past this is not read for working
# directories (the environment details are read instead).
_INDEX_MAX = 64 << 20
_MANIFEST_MAX = 8 << 20

# Classic tool names (task folders), both protocols.
TOOLS = {
    "execute_command": "shell",
    "read_file": "read",
    "write_to_file": "write",
    "replace_in_file": "write",
    "new_rule": "write",
    "apply_patch": "write",
    "web_fetch": "fetch",
    "web_search": "fetch",
    "browser_action": "fetch",
    "search_files": "other",
    "list_files": "other",
    "list_code_definition_names": "other",
    "use_mcp_tool": "other",
    "access_mcp_resource": "other",
    "load_mcp_documentation": "other",
    "ask_followup_question": "other",
    "attempt_completion": "other",
    "new_task": "other",
    "plan_mode_respond": "other",
    "act_mode_respond": "other",
    "focus_chain": "other",
    "condense": "other",
    "summarize_task": "other",
    "report_bug": "other",
    "generate_explanation": "other",
    "use_skill": "other",
    "use_subagents": "other",
}

# XML parameter names (C3/core/assistant-message/index.ts toolParamNames).
PARAMS = ("command", "requires_approval", "path", "absolutePath", "content",
          "diff", "regex", "file_pattern", "recursive", "action", "url",
          "coordinate", "text", "query", "allowed_domains", "blocked_domains",
          "prompt", "server_name", "tool_name", "arguments", "uri", "question",
          "options", "response", "result", "context", "title", "what_happened",
          "steps_to_reproduce", "api_request_output", "additional_context",
          "needs_more_exploration", "task_progress", "timeout", "input",
          "from_ref", "to_ref", "skill_name", "prompt_1", "prompt_2",
          "prompt_3", "prompt_4", "prompt_5", "start_line", "end_line")

PATH_KEYS = ("path", "absolutePath")

# SDK tool names (sessions).
SDK_TOOLS = {
    "run_commands": "shell",
    "read_files": "read",
    "editor": "write",
    "apply_patch": "write",
    "fetch_web_content": "fetch",
    "search_codebase": "other",
    "skills": "other",
    "ask_question": "other",
    "submit_and_exit": "other",
}

# What a classic call's result says when Cline refused to run it.
TOOL_ERROR = "The tool execution failed with the following error:\n<error>\n"
IGNORED = "is blocked by the .clineignore file settings."
NOT_PERMITTED = "Command execution blocked by CLINE_COMMAND_PERMISSIONS: "

# What an SDK call's result says when the runtime did not run it.
REJECTED_SUFFIX = ("-- NOT a tool or system failure. Clarify with user "
                   "before proceeding.")
DISABLED = 'Tool "%s" is disabled by policy'
UNKNOWN_TOOL = "Unknown tool: %s"
HOOK_BLOCKED = "Tool %s was blocked by a runtime hook"

_HINT = re.compile(r"@[^:]+:")
_HEREDOC = re.compile(r"(?<![<])<<-?\s*(?:\"([^\"]+)\"|'([^']+)'|"
                      r"([A-Za-z0-9_./-]+))")
_ARG_QUOTE = re.compile(r"[\s\"]")


def _string(value):
    return value if isinstance(value, str) and value else None


def _strip_hint(path):
    """A path without Cline's multi-root "@<workspace>:" hint."""
    m = _HINT.match(path)
    return path[m.end():].strip() if m else path


def _payload(raw):
    """(payload, key): what an SDK tool's input holds, and the key watch's
    decoded input keeps it under when it is not an object ("_raw" for a
    string that is not JSON, "_value" for any other value)."""
    decoded = base.decode_input(raw)
    if set(decoded) == {"_raw"}:
        return decoded["_raw"], "_raw"
    if set(decoded) == {"_value"}:
        return decoded["_value"], "_value"
    return decoded, None


def render_command(command):
    """One run_commands entry as the tool renders it (helpers.ts
    formatRunCommandQuery), or None."""
    if isinstance(command, str):
        return command
    if not isinstance(command, dict) or not _string(command.get("command")):
        return None
    args = command.get("args")
    args = [a for a in args if isinstance(a, str)] if isinstance(args, list) else []
    if not args:
        return command["command"]
    rendered = [json.dumps(a, ensure_ascii=False) if _ARG_QUOTE.search(a) else a
                for a in args]
    return "%s %s" % (command["command"], " ".join(rendered))


def _coalesce(commands):
    """Adjacent string commands split inside a heredoc joined back into one,
    as definitions.ts coalesceSplitHeredocCommands joins them."""
    out, run = [], []

    def flush():
        i = 0
        while i < len(run):
            command = run[i]
            m = _HEREDOC.search(command)
            delimiter = m and (m.group(1) or m.group(2) or m.group(3))
            end = -1
            if delimiter:
                for k in range(i + 1, len(run)):
                    if run[k].strip() == delimiter:
                        end = k
                        break
            if end == -1:
                out.append(command)
                i += 1
                continue
            out.append("\n".join(run[i:end + 1]))
            i = end + 1
        del run[:]

    for command in commands:
        if isinstance(command, str):
            run.append(command)
        else:
            flush()
            out.append(command)
    flush()
    return out


def run_commands(raw):
    """([command text], consumed keys) for a run_commands input, each
    command as it ran (see the module notes)."""
    payload, key = _payload(raw)
    consumed = (key,) if key else ()
    if isinstance(payload, str):
        entries = [payload]
    elif isinstance(payload, list):
        entries = payload
    elif isinstance(payload, dict):
        if "commands" in payload:
            value = payload["commands"]
            entries = value if isinstance(value, list) else [value]
            consumed = ("commands",)
        elif "command" in payload:
            if "args" in payload:
                entries, consumed = [payload], ("command", "args")
            else:
                entries, consumed = [payload["command"]], ("command",)
        elif "cmd" in payload:
            entries, consumed = [payload["cmd"]], ("cmd",)
        else:
            entries = []
    else:
        entries = []
    entries = [e for e in entries if isinstance(e, (str, dict))]
    rendered = [render_command(e) for e in _coalesce(entries)]
    return [c for c in rendered if c], consumed


def _read_path(entry):
    if isinstance(entry, str):
        return entry
    if isinstance(entry, dict):
        for key in ("path", "file_path", "filePath"):
            if _string(entry.get(key)):
                return entry[key]
    return None


def read_files(raw):
    """(paths, consumed keys) for a read_files input, in every shape
    ReadFilesInputUnionSchema takes."""
    payload, key = _payload(raw)
    consumed = (key,) if key else ()
    if isinstance(payload, (str, list)):
        items = payload if isinstance(payload, list) else [payload]
    elif isinstance(payload, dict):
        items = []
        for name in ("files", "file_paths", "paths"):
            if name in payload:
                value = payload[name]
                items = value if isinstance(value, list) else [value]
                consumed = (name,)
                break
        else:
            for name in ("path", "file_path", "filePath"):
                if _string(payload.get(name)):
                    items, consumed = [payload], (name,)
                    break
    else:
        items = []
    paths = tuple(p for p in (_read_path(i) for i in items) if p)
    return paths, consumed if paths else ()


def _operation_text(element):
    """The text of one ToolOperationResult (or text block)."""
    if isinstance(element, str):
        return element
    if not isinstance(element, dict):
        return None
    if isinstance(element.get("text"), str):
        return element["text"]
    parts = [element[k] for k in ("result", "error")
             if isinstance(element.get(k), str) and element[k]]
    return "\n".join(parts) if parts else None


def sdk_text(content):
    """An SDK tool result's content as text."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        texts = [t for t in (_operation_text(e) for e in content) if t]
        return "\n".join(texts) if texts else None
    return None


def _sdk_never_ran(text, block, name):
    """True for the {"error": ...} result the SDK runtime writes in place
    of running a call (see the module notes)."""
    if isinstance(block, dict) and block.get("is_error") is False:
        return False
    if not isinstance(text, str) or not text.lstrip().startswith("{"):
        return False
    try:
        obj = json.loads(text)
    except (ValueError, RecursionError):
        return False
    error = obj.get("error") if isinstance(obj, dict) else None
    if not isinstance(error, str) or set(obj) != {"error"}:
        return False
    return (error.endswith(REJECTED_SUFFIX) or error == DISABLED % name
            or error == UNKNOWN_TOOL % name or error == HOOK_BLOCKED % name)


class ClineSource(T.TaskSource):
    id = "cline"
    name = "Cline"
    unit = "task"
    env = (DATA_ENV, DIR_ENV, SESSION_ENV)
    path_means = ("a Cline data folder (what CLINE_DATA_DIR means) or an "
                  "editor's globalStorage/saoudrizwan.claude-dev folder")
    checked = "4.1.23"
    mask_note = ("If Cline has this task open, close it first: it keeps the "
                 "conversation in memory and writes the whole file again on "
                 "its next save, value included.")

    TOOLS = dict(TOOLS)
    TOOL_TAGS = T.alternation(TOOLS)
    PARAM_TAGS = T.alternation(PARAMS)

    # -- where to look ------------------------------------------------------

    def default_paths(self, env, home, platform):
        """The data folder (CLINE_DATA_DIR, else $CLINE_DIR/data, then
        ~/.cline/data), CLINE_SESSION_DATA_DIR when set, and the editor
        parent folder, in which stores() probes each editor's
        User/globalStorage folder for Cline and Cline Nightly."""
        j = _paths.join
        out = []
        moved = (env.get(DATA_ENV) or "").strip() \
            if isinstance(env.get(DATA_ENV), str) else ""
        top = env.get(DIR_ENV) if isinstance(env.get(DIR_ENV), str) else ""
        if moved:
            out.append((moved, "env " + DATA_ENV))
        elif top:
            out.append((j(platform, top, "data"), "env " + DIR_ENV))
        out.append((j(platform, home, *ROOT), "default"))
        flat = env.get(SESSION_ENV)
        if isinstance(flat, str) and flat:
            out.append((flat, "env " + SESSION_ENV))
        out += T.editor_locations(env, home, platform, IDS[0])
        return out

    def stores(self, locations, since_days=None):
        found, seen = [], set()

        def add(store):
            if store is None:
                return
            key = os.path.normcase(os.path.abspath(store.path))
            if key not in seen:
                seen.add(key)
                found.append(store)

        for loc in locations:
            if loc.how == "env " + SESSION_ENV:
                roots, folders = [], T.subdirs(loc.path)
            else:
                roots, folders = T.task_roots(loc.path, IDS), []
            for root in roots:
                folders += T.subdirs(os.path.join(root, SESSIONS))
                tasks = T.subdirs(os.path.join(root, T.TASKS))
                index = self._index(root) if tasks else {}
                for task in tasks:
                    for store in self._task_stores(task, index):
                        add(store)
            for folder in folders:
                for store in self._session_stores(folder):
                    add(store)
        return base.newest_first(found, since_days)

    @staticmethod
    def _index(root):
        """{task id: working directory} from the task index, when it reads."""
        doc = T.read_json(os.path.join(root, *INDEX), limit=_INDEX_MAX)
        out = {}
        for item in doc if isinstance(doc, list) else ():
            if isinstance(item, dict) and isinstance(item.get("id"), str):
                cwd = _string(item.get("cwdOnTaskInitialization"))
                if cwd:
                    out[item["id"]] = cwd
        return out

    def _task_stores(self, task, index):
        tid = os.path.basename(task)
        api = os.path.join(task, T.API)
        cwd = index.get(tid)
        if T.is_file(api):
            yield self.store(api, "json", role="transcript", session=tid,
                             project=cwd or T.cwd_from_head(api))
        for name in (T.UI, T.OLD_UI):
            path = os.path.join(task, name)
            if T.is_file(path):
                yield self.store(path, "json", role="side", unit="task log",
                                 session=tid, project=cwd)

    def _session_stores(self, folder):
        sid = os.path.basename(folder)
        manifest = T.read_json(os.path.join(folder, sid + ".json"),
                               limit=_MANIFEST_MAX)
        manifest = manifest if isinstance(manifest, dict) else {}
        cwd = _string(manifest.get("cwd")) or _string(manifest.get("workspace_root"))
        for entry in T.entries(folder):
            name = entry.name
            if name.startswith(".") or not name.endswith(MESSAGES):
                continue
            try:
                if not entry.is_file():
                    continue
            except OSError:
                continue
            yield self.store(entry.path, "json", role="transcript",
                             unit="session", session=name[:-len(MESSAGES)],
                             project=cwd)

    # -- classifying --------------------------------------------------------

    def classify(self, name, arguments, cwd):
        if self._sdk:
            return self._classify_sdk(name, arguments, cwd)
        kind = TOOLS.get(name)
        if kind is None:
            return [dict(kind="other", known=False)]
        args = base.decode_input(arguments)
        if kind == "shell":
            command = _string(args.get("command"))
            return [dict(kind=kind, known=True, command=command, workdir=cwd,
                         consumed=("command",) if command else ())]
        if kind in ("read", "write"):
            if name == "apply_patch":
                return [dict(kind=kind, known=True,
                             paths=T.patch_paths(args.get("input")))]
            paths, keys = [], []
            for key in PATH_KEYS:
                value = _string(args.get(key))
                if value:
                    paths.append(_strip_hint(value))
                    keys.append(key)
                    break
            return [dict(kind=kind, known=True, paths=tuple(paths),
                         consumed=tuple(keys) if kind == "read" else ())]
        return [dict(kind=kind, known=True)]

    def _classify_sdk(self, name, raw, cwd):
        kind = SDK_TOOLS.get(name)
        if kind is None:
            return [dict(kind="other", known=False)]
        if name == "run_commands":
            commands, consumed = run_commands(raw)
            if not commands:
                return [dict(kind="shell", known=True)]
            return [dict(kind="shell", known=True, command=c, workdir=cwd,
                         consumed=consumed) for c in commands]
        if name == "read_files":
            paths, consumed = read_files(raw)
            return [dict(kind="read", known=True, paths=paths,
                         consumed=consumed)]
        payload, _key = _payload(raw)
        if name == "editor":
            path = _string(payload.get("path")) if isinstance(payload, dict) else None
            return [dict(kind="write", known=True,
                         paths=(path,) if path else ())]
        if name == "apply_patch":
            patch = payload.get("input") if isinstance(payload, dict) else payload
            return [dict(kind="write", known=True, paths=T.patch_paths(patch))]
        return [dict(kind=kind, known=True)]

    def declined_result(self, text, block, name):
        if self._sdk:
            return _sdk_never_ran(text, block, name)
        if T.TaskSource.declined_result(self, text, block, name):
            return True
        body = self.body_of(text)
        if isinstance(body, str) and body.startswith(TOOL_ERROR):
            rest = body[len(TOOL_ERROR):]
            return ((rest.startswith("Access to ") and IGNORED in rest)
                    or rest.startswith(NOT_PERMITTED))
        return False

    def result_of(self, i, j, block, made, found):
        if not self._sdk:
            return T.TaskSource.result_of(self, i, j, block, made, found)
        content = block.get("content")
        name = made[0].tool_name
        text = sdk_text(content)
        declined = _sdk_never_ran(text, block, name)
        found.ties[(i, j)] = made[0]
        if (len(made) > 1 and isinstance(content, list)
                and len(content) == len(made)):
            for k, (call, element) in enumerate(zip(made, content)):
                call.output = _operation_text(element)
                found.ties[(i, j, k)] = call
            return
        for call in made:
            call.output = text
            if declined:
                call.status = T.DECLINED

    # -- reading ------------------------------------------------------------

    def reset(self):
        T.TaskSource.reset(self)
        self._sdk = False

    @staticmethod
    def is_session(store):
        return store.path.endswith(MESSAGES)

    def _transcript(self, store):
        """(document, messages, cwd, paired) of a transcript, or None."""
        doc = self.load(store)
        if doc is None:
            return None
        sdk = self.is_session(store)
        if sdk:
            raw = doc.get("messages") if isinstance(doc, dict) else doc
            messages = self.messages_of(store, raw)
        else:
            messages = self.messages_of(store, doc)
        cwd = store.project or T.cwd_from_messages(messages)
        self._sdk = sdk
        try:
            paired = self.pair(store, messages, cwd, xml=not sdk)
        finally:
            self._sdk = False
        return doc, messages, cwd, paired

    def tool_calls(self, store):
        """Every call in a transcript, once per id, with its output; a call
        Cline did not run is "declined" (see the module notes)."""
        if store.role != "transcript":
            return
        read = self._transcript(store)
        if read is None:
            return
        for call in read[3].calls:
            yield call

    def secret_texts(self, store):
        """Every string of the store. In a transcript, each result is handed
        over on its own, tied to its call; the rest of each message, and an
        SDK file's other fields, without it."""
        if store.role != "transcript":
            for text in self.side_texts(store):
                yield text
            return
        read = self._transcript(store)
        if read is None:
            return
        doc, messages, _cwd, paired = read
        if isinstance(doc, dict):
            yield SecretText({k: v for k, v in doc.items() if k != "messages"},
                             where="file")
        elif not isinstance(doc, list):
            yield SecretText(doc, where="file")
        for text in self.message_texts(messages, paired):
            yield text
