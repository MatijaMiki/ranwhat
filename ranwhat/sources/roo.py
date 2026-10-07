"""Roo Code (RooCodeInc/Roo-Code), the VS Code extension
RooVeterinaryInc.roo-cline, and the Roo CLI.

Checked against v3.54.0 (commit 27001b2, 2026-05-15; its CHANGELOG calls
it the last Roo Code release), with v3.36.0 and v3.20.0 for the XML
protocol, whose code 3.43 removed. Paths below are under src/ (R) and
packages/types/src (RT) of those tags.

Roo keeps the task folders _cline_tasks.py describes, under its storage
folder: <editor>/User/globalStorage/rooveterinaryinc.roo-cline under the
editor parent folder, for VS Code and the forks _paths probes (VS Code
lower-cases the id; R/utils/storage.ts getStorageBasePath), or the
folder the roo-cline.customStoragePath setting names (R/package.json;
it lives in the editor's settings.json, which is not parsed here: point
--path roo=<that folder> at it). Other ids Roo has had
(rooveterinaryinc.roo-code-nightly, roovscode.*, which Kilo Code's Roo
importer lists) are not in Roo's own source and are not probed; neither
is a remote editor's ~/.vscode-server: point --path at either. The
Roo CLI runs the extension in a shim whose storage folder is
~/.vscode-mock/global-storage (apps/cli/src/lib/task-history/index.ts;
packages/vscode-shim/src/context/ExtensionContext.ts). No variable moves either.

A task folder tasks/<taskId>/ (a UUIDv7, R/core/task/Task.ts) holds:
- api_conversation_history.json: the transcript, ApiMessage[] (R/core/
  task-persistence/apiMessages.ts), compact JSON written by safeWriteJson
  (R/utils/safeWriteJson.ts: a temp file renamed into place while a
  proper-lockfile folder <file>.lock is held; a file with that folder
  beside it is in use and is not masked);
- ui_messages.json (and Claude Dev's claude_messages.json): side stores;
- command-output/cmd-<ts>.txt: the whole output of a command too long for
  the result, which keeps a preview and "Artifact ID: cmd-<ts>.txt"
  (R/core/tools/ExecuteCommandTool.ts formatPersistedOutput,
  R/integrations/terminal/OutputInterceptor.ts). A side text store, tied
  to the call whose result names it;
- history_item.json: this task's HistoryItem (RT/history.ts); its
  "workspace" is the task's working directory (R/core/task-persistence/
  TaskHistoryStore.ts). Read for that only.
tasks/_index.json (an index file inside tasks/), checkpoints/ (a shadow git
repository of the workspace) and task_metadata.json are not read.

Tool calls are native tool_use blocks since 3.36.13 (forced in 3.37.0) and
XML in text before (see _cline_tasks.py). Tool names: the union of
RT/tool.ts toolNames at 3.20.0, 3.36.0 and 3.54.0. Inputs (R/core/prompts/
tools/native-tools/*.ts, and the XML parameters of R/shared/tools.ts
toolParamNames at 3.20.0 and 3.36.0): execute_command{command, cwd?,
timeout?}, whose cwd, relative to the task's, is the command's workdir
(ExecuteCommandTool.ts); read_file{path} (3.54), {files: [{path, ...}]}
(native, 3.36) or XML {args: "<file><path>...</path></file>..."}
(several files); write_to_file{path, content}; apply_diff{path, diff} or
XML {args} like read_file's; insert_content{path, line, content};
search_and_replace{path, ...}; edit, search_replace and edit_file
{file_path, old_string, new_string}; apply_patch{patch} (the paths are in
the patch); generate_image{prompt, path, image?} (writes path);
browser_action{action, url?}. MCP tools are native calls named
mcp--<server>--<tool> (R/utils/mcp-name.ts), not Roo's own: judged by
name. A native result has no "[tool] Result:" header
(R/core/assistant-message/presentAssistantMessage.ts); one the user
approved with a comment starts with {"status": "approved", "feedback"}.

Besides the shared "never ran" texts, Roo writes {"status": "denied",
"message"?: ..., "feedback"?: ...} for a call the user denied, and
{"status": "error", "type": "access_denied", ...} for one .rooignore
blocked (R/core/prompts/responses.ts toolDenied, toolDeniedWithFeedback,
rooIgnoreError); "Task was interrupted before this tool call could be
completed." (Task.ts) may follow a call that did run, and is not taken for
one. Roo has no commands the user runs through it.

The working directory is history_item.json's workspace, else the
environment details' "# Current Workspace Directory (<cwd>) Files".

Not read, ever: the Roo CLI's ~/.vscode-mock/global-storage/secrets.json
(API keys in plain text, right beside tasks/; packages/vscode-shim/src/
storage/SecretStorage.ts) and global-state.json, the storage folder's
settings/ (mcp_settings.json holds MCP servers' env, custom_modes.yaml),
cache/, and the CLI's ~/.roo/. The extension keeps its keys in the
editor's secret storage, which is not read either.

Kilo Code is not read here: up to 5.x it wrote this same format under
globalStorage/kilocode.kilo-code, and 7.x is built on OpenCode and keeps
its sessions in a SQLite database (~/.local/share/kilo/kilo.db).
"""

from __future__ import annotations

import json
import os
import re

from . import _cline_tasks as T
from . import _paths, base
from .base import SecretText

IDS = ("rooveterinaryinc.roo-cline",)
CLI_ROOT = (".vscode-mock", "global-storage")
HISTORY_ITEM = "history_item.json"
OUTPUTS = "command-output"
_OUTPUT_NAME = re.compile(r"cmd-[0-9A-Za-z_.-]+\.txt\Z")
_ARTIFACT = re.compile(r"Artifact ID: (cmd-[0-9A-Za-z_.-]+\.txt)")

_HISTORY_MAX = 4 << 20

TOOLS = {
    "execute_command": "shell",
    "read_file": "read",
    "write_to_file": "write",
    "apply_diff": "write",
    "insert_content": "write",
    "search_and_replace": "write",
    "edit": "write",
    "search_replace": "write",
    "edit_file": "write",
    "apply_patch": "write",
    "generate_image": "write",
    "browser_action": "fetch",
    "read_command_output": "other",
    "search_files": "other",
    "list_files": "other",
    "list_code_definition_names": "other",
    "use_mcp_tool": "other",
    "access_mcp_resource": "other",
    "ask_followup_question": "other",
    "attempt_completion": "other",
    "switch_mode": "other",
    "new_task": "other",
    "fetch_instructions": "other",
    "codebase_search": "other",
    "update_todo_list": "other",
    "run_slash_command": "other",
    "skill": "other",
    "custom_tool": "other",
}

# XML parameter names, toolParamNames at 3.20.0 and 3.36.0.
PARAMS = ("command", "path", "content", "line_count", "regex", "file_pattern",
          "recursive", "action", "url", "coordinate", "text", "server_name",
          "tool_name", "arguments", "uri", "question", "result", "diff",
          "mode_slug", "reason", "line", "mode", "message", "cwd", "follow_up",
          "task", "size", "search", "replace", "use_regex", "ignore_case",
          "args", "start_line", "end_line", "query", "todos", "prompt",
          "image", "files", "operations", "patch")

PATH_KEYS = ("path", "file_path")



def _args_paths(xml):
    """The <path> values of an XML args string, stripped. Found with str.find:
    a lazy regex between \\s* runs was cubic on whitespace and quadratic on
    unclosed tags."""
    out, pos = [], 0
    while True:
        start = xml.find("<path>", pos)
        if start == -1:
            return out
        start += len("<path>")
        end = xml.find("</path>", start)
        if end == -1:
            return out
        out.append(xml[start:end].strip())
        pos = end + len("</path>")


def _string(value):
    return value if isinstance(value, str) and value else None


def _paths_in(args):
    """(paths, keys) a read or write names: path or file_path; native
    3.36's files[].path; XML's <args><file><path>."""
    for key in PATH_KEYS:
        value = _string(args.get(key))
        if value:
            return (value,), (key,)
    files = args.get("files")
    if isinstance(files, list):
        found = tuple(f["path"] for f in files
                      if isinstance(f, dict) and _string(f.get("path")))
        if found:
            return found, ("files",)
    xml = args.get("args")
    if isinstance(xml, str):
        found = tuple(p for p in _args_paths(xml) if p)
        if found:
            return found, ("args",)
    return (), ()


def _status(text):
    """The "status" of a result that is one JSON object, else None."""
    if not isinstance(text, str) or not text.lstrip().startswith("{"):
        return None, {}
    try:
        obj = json.loads(text)
    except (ValueError, RecursionError):
        return None, {}
    if not isinstance(obj, dict):
        return None, {}
    return obj.get("status"), obj


class RooSource(T.TaskSource):
    id = "roo"
    name = "Roo Code"
    unit = "task"
    env = ()
    path_means = ("a Roo Code storage folder, the one holding tasks/ "
                  "(globalStorage/rooveterinaryinc.roo-cline, or what "
                  "roo-cline.customStoragePath names)")
    checked = "3.54.0"
    mask_note = ("If Roo Code has this task open, close it first: it keeps "
                 "the conversation in memory and writes the whole file again "
                 "on its next save, value included.")

    TOOLS = dict(TOOLS)
    TOOL_TAGS = T.alternation(TOOLS)
    PARAM_TAGS = T.alternation(PARAMS)
    NEWLINE_CONTENT = True
    # Roo parses XML only in an XML-protocol request (Task.ts at 3.36.0
    # creates no AssistantMessageParser for a native one).
    XML_BESIDE_NATIVE = False

    # -- where to look ------------------------------------------------------

    def default_paths(self, env, home, platform):
        """The editor parent folder, in which stores() probes each editor's
        User/globalStorage/rooveterinaryinc.roo-cline, and the Roo CLI's
        ~/.vscode-mock/global-storage."""
        out = T.editor_locations(env, home, platform, IDS[0])
        out.append((_paths.join(platform, home, *CLI_ROOT), "default"))
        return out

    def stores(self, locations, since_days=None):
        found, seen = [], set()
        roots = [r for loc in locations for r in T.task_roots(loc.path, IDS)]
        for root in roots:
            for task in T.subdirs(os.path.join(root, T.TASKS)):
                for store in self._task_stores(task):
                    if store is None:
                        continue
                    key = os.path.normcase(os.path.abspath(store.path))
                    if key not in seen:
                        seen.add(key)
                        found.append(store)
        return base.newest_first(found, since_days)

    def _task_stores(self, task):
        tid = os.path.basename(task)
        item = T.read_json(os.path.join(task, HISTORY_ITEM), limit=_HISTORY_MAX)
        cwd = _string(item.get("workspace")) if isinstance(item, dict) else None
        api = os.path.join(task, T.API)
        if T.is_file(api):
            cwd = cwd or T.cwd_from_head(api)
            yield self.store(api, "json", role="transcript", session=tid,
                             project=cwd)
        for name in (T.UI, T.OLD_UI):
            path = os.path.join(task, name)
            if T.is_file(path):
                yield self.store(path, "json", role="side", unit="task log",
                                 session=tid, project=cwd)
        for entry in T.entries(os.path.join(task, OUTPUTS)):
            if not _OUTPUT_NAME.match(entry.name):
                continue
            try:
                if not entry.is_file():
                    continue
            except OSError:
                continue
            yield self.store(entry.path, "text", role="side",
                             unit="command output", session=tid, project=cwd)

    # -- classifying --------------------------------------------------------

    def classify(self, name, arguments, cwd):
        kind = TOOLS.get(name)
        if kind is None:
            return [dict(kind="other", known=False)]
        args = base.decode_input(arguments)
        if kind == "shell":
            command = _string(args.get("command"))
            return [dict(kind=kind, known=True, command=command,
                         workdir=T.join_cwd(cwd, _string(args.get("cwd"))),
                         consumed=("command",) if command else ())]
        if name == "apply_patch":
            return [dict(kind=kind, known=True,
                         paths=T.patch_paths(args.get("patch")))]
        if kind in ("read", "write"):
            paths, keys = _paths_in(args)
            return [dict(kind=kind, known=True, paths=paths,
                         consumed=keys if kind == "read" else ())]
        return [dict(kind=kind, known=True)]

    def declined_result(self, text, block, name):
        if T.TaskSource.declined_result(self, text, block, name):
            return True
        status, obj = _status(self.body_of(text))
        return status == "denied" or (status == "error"
                                      and obj.get("type") == "access_denied")

    # -- reading ------------------------------------------------------------

    def reset(self):
        T.TaskSource.reset(self)
        self._named = {}        # API history path -> {output file: ToolCall}

    def in_use(self, store):
        """True while Roo holds the lock it takes to write the file
        (safeWriteJson: a <file>.lock folder beside it). Only stat'ed."""
        return os.path.lexists(store.path + ".lock")

    def _transcript(self, store, warn=True):
        """(messages, paired) of an API history, or None."""
        doc = self.load(store)
        if doc is None:
            return None
        messages = self.messages_of(store, doc)
        cwd = store.project or T.cwd_from_messages(messages)
        return messages, self.pair(store, messages, cwd)

    def tool_calls(self, store):
        """Every call in a transcript, once per id, with its output; a call
        Roo did not run is "declined" (see the module notes)."""
        if store.role != "transcript":
            return
        read = self._transcript(store)
        if read is None:
            return
        for call in read[1].calls:
            yield call

    def secret_texts(self, store):
        """Every string of the store. In a transcript each result is handed
        over on its own, tied to its call; a command's spilled output is
        tied to the call whose result names it."""
        if store.format == "text":
            for text in self._output_texts(store):
                yield text
            return
        if store.role != "transcript":
            for text in self.side_texts(store):
                yield text
            return
        read = self._transcript(store)
        if read is None:
            return
        messages, paired = read
        for text in self.message_texts(messages, paired):
            yield text

    def _output_texts(self, store):
        try:
            with open(store.path, "rb") as fh:
                text = fh.read().decode("utf-8", "surrogateescape")
        except (OSError, ValueError) as e:
            self._bad_store(store, getattr(e, "strerror", None)
                            or type(e).__name__)
            return
        yield SecretText(text, call=self._caller(store), where="file")

    def _caller(self, store):
        """The call whose result names this output file, or None. The API
        history beside it is read quietly (it is a store of its own, and
        warns there), once a run for all of its task's output files."""
        task = os.path.dirname(os.path.dirname(store.path))
        path = os.path.join(task, T.API)
        if path not in self._named:
            self._named[path] = self._outputs_named(store, path)
        return self._named[path].get(os.path.basename(store.path))

    def _outputs_named(self, store, path):
        """{output file name: the call whose result names it} for one API
        history."""
        api = self.store(path, "json", role="transcript",
                         session=store.session, project=store.project)
        doc = T.read_json(path) if api is not None else None
        if not isinstance(doc, list):
            return {}
        cwd = store.project or T.cwd_from_messages(doc)
        named = {}
        for call in self.pair(api, doc, cwd).calls:
            if isinstance(call.output, str) and "Artifact ID: " in call.output:
                for name in _ARTIFACT.findall(call.output):
                    named.setdefault(name, call)
        return named
