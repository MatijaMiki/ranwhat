"""GitHub Copilot agent mode in VS Code (registry id "vscode-copilot").

This is the chat that the GitHub Copilot Chat extension (GitHub.copilot-chat,
built into VS Code from 1.142 as extensions/copilot) runs inside the editor:
Agent mode, Ask and Edit. It is not Copilot CLI (copilot_cli.py reads that,
and the chats VS Code runs on the Agent Host Copilot SDK, which write to
$COPILOT_HOME/session-state). Every fact below was read from the source of
microsoft/vscode at tag 1.142.0 (commit d956e8a6, 2026-10-14), with the
older shapes from the tags named under "Format versions". Nothing here was
observed on a live machine, and VS Code documents none of it: the format is
internal and can change in any weekly release.

Where: the "User" folder of the editor (userDataPath/User; environmentService.ts
appSettingsHome), which _paths.editor_user_dirs already works
out: VSCODE_PORTABLE (<dir>/user-data/User), VSCODE_APPDATA
(<dir>/Code/User), else %APPDATA%\\Code\\User on Windows,
~/Library/Application Support/Code/User on macOS and
${XDG_CONFIG_HOME:-~/.config}/Code/User on Linux, and the same under the
folder names of the forks that helper probes ("Code - Insiders", VSCodium,
...; those names are not verified for Copilot). The --user-data-dir flag
moves it too, and ranwhat cannot see that flag: `--path vscode-copilot=DIR`
takes the User folder. Under it (chatSessionStore.ts):
- workspaceStorage/<workspaceId>/chatSessions/<sessionId>.jsonl, one folder
  per workspace (a folder window or a multi-root window);
- globalStorage/emptyWindowChatSessions/<sessionId>.jsonl, for a window with
  no folder open;
- workspaceStorage/no-workspace/chatSessions/<sessionId>.json, the old
  root for those (a plain folder of the same shape, read like the rest);
- globalStorage/transferredChatSessions/<sessionId>.json, a hand-off between
  windows that VS Code deletes after reading it (or after five minutes).
  Whatever is still there is a copy of a session kept elsewhere.
The window's state.vscdb (key chat.ChatSessionStore.index) only holds
titles and times, and is not read.

A session also exists as <sessionId>.json beside, or instead of, the
.jsonl: the flat file VS Code wrote before 1.109 and writes again when
chat.useLogSessionStorage is false. VS Code reads the .jsonl first, so a
stale .json can sit next to a live .jsonl. Session files are never pruned
by VS Code, and when a window changes workspace they are copied, not moved,
so one sessionId can be in two workspaceStorage folders. Every file is a
store, so clean finds the secret in each. Per sessionId one is the
"transcript" (a .jsonl over a .json, then the newest) and the others are
"side": tool_calls reads only the transcript, so a session is not judged
twice. A hooks transcript (below) is always "side".

Project: workspaceStorage/<workspaceId>/workspace.json, which VS Code writes
(best effort, when it first creates the folder) as {"folder": "<URI>"} or
{"workspace": "<URI of the .code-workspace file>"} (storageMain.ts). The
workspaceId is an md5 that cannot be reversed. A file: URI becomes a local
path; another scheme (vscode-remote://ssh-remote+host/path, for a remote or
WSL window, whose chats are still stored on this machine) is kept as the URI.
A multi-root window's project is the folder of its .code-workspace file.
A window with no folder has no project: a call's own working directory
(below) stands in for it.

Format of a .jsonl (objectMutationLog.ts, read() and write()): an
append-only log, one JSON entry per line, replayed in order into one
object:
- {"kind":0,"v":<state>}: Initial, the state is replaced by v;
- {"kind":1,"k":[path...],"v":x}: Set, parent[last] = x (an empty path does
  nothing);
- {"kind":2,"k":[path...],"v":[items],"i":n}: Push, the array at the path is
  cut to n items when "i" is there (0 is a value, not absent), then v is
  appended;
- {"kind":3,"k":[path...]}: Delete, parent[last] is removed.
A path step is an object key or an array index. The log is diffed
positionally, so a tool call that changes is written again as a Push with
"i", and the same call is on several lines: it is replayed here, not
searched for. After 1024 entries (chatSessionOperationLog.ts) the next
write replaces the whole file with one kind-0 line, so a file can shrink. A
last line torn by a crash is skipped; a complete line that is not JSON, or
an entry whose path does not lead anywhere, is skipped and counted, and
replay goes on (VS Code itself stops at the first bad line). The replayed
object is the same one a flat .json holds (chatModel.ts
ISerializableChatData, version 3): {version, sessionId, creationDate (ms),
customTitle?, requests[], workingDirectory?, ...}. A request holds
requestId, timestamp (ms), message, modelId, response[], modelState
{value: 0 pending, 1 complete, 2 cancelled, 3 failed, 4 needs input},
and result {errorDetails?, metadata?}.

A tool call is a response[] part {"kind":"toolInvocationSerialized"}
(chatService.ts IChatToolInvocationSerialized; chatToolInvocation.ts
toJSON): toolId, toolCallId, isConfirmed, resultError, resultDetails,
toolSpecificData, source {type: internal, extension, mcp, user, external},
subAgentInvocationId. The part carries no raw input for most tools. The
Copilot extension keeps every model tool call in
request.result.metadata.toolCallRounds[].toolCalls[] = {name (the
model-facing name, read_file or run_in_terminal), arguments (a JSON
string), id} with the round's timestamp, and the results in
metadata.toolCallResults{id: result} (conversation.ts, intents.ts). They
are joined on toolCalls[].id.split("__vscode")[0] == toolCallId
(toolCallRound.ts). The arguments come from there; failing that, from
toolSpecificData.rawInput (kind "input", stored for tools that always show
their input, MCP tools among them) and, for an MCP tool, from
resultDetails.input (a JSON string).

run_in_terminal has toolSpecificData {kind: "terminal", commandLine
{original, userEdited?, toolEdited?, forDisplay?}, cwd (a URI), language,
isBackground, terminalCommandOutput {text}, terminalCommandState {exitCode?,
timestamp (ms), duration (ms)}}. The command run is userEdited, else
toolEdited, else original (runInTerminalTool.ts); toolEdited can be a
sandbox wrapper or the command with its cd removed, so this reads
userEdited when the user changed the command and the model's own text
otherwise, which is also what the arguments hold. exitCode is -1 on a
cancel and missing for background, timeout or alt-buffer runs.

URIs are serialized as {"$mid":1, "path", "scheme", "authority"?, and the
caches "fsPath" and "external"}. The path is built from scheme, authority
and path only: VS Code's own import code says not to trust the caches.

Tool names (extensions/copilot/.../toolNames.ts, 1.142.0). The toolId of a
part is the core name (run_in_terminal) or the contributed name
(copilot_readFile); both are mapped to the core name, which is the
ToolCall's tool_name. Argument names are from the tools' parameter
interfaces: filePath (read_file, create_file, replace_string_in_file,
insert_edit_into_file, edit_notebook_file), path (list_dir), dirPath
(create_directory), replacements[].filePath (multi_replace_string_in_file),
input, a patch with "*** Add File: <path>", "*** Update File: <path>",
"*** Delete File: <path>" and "*** Move to: <path>" lines (apply_patch).
See TOOLS for the kind of each. A name not listed there is not known, and
is judged by name; so is every tool that runs something this adapter cannot
read (run_notebook_cell, create_and_run_task, run_task, send_to_terminal,
runSubagent, run_vscode_command, install_extension, the browser tools,
MCP tools).

A call that did not run is "declined": isConfirmed.type 0 (denied) or 5
(skipped), or isConfirmed false (a boolean before 1.104; that false means
denied is the research reading and was not confirmed on data). A
terminalCommandState in the part is proof the command ran, and wins. A call
that is only in toolCallRounds (no part, so nothing says it was shown to
the user) is yielded with the status its result gives: "declined" when
toolCallResults holds no result for it. Exit code, duration, the
sandbox/approval fields and the approval source (user, hook, setting) are
not carried into the ToolCall.

Format versions (all read):
- 1.100 (May 2025, copilot-chat 0.29): chatSessions/<id>.json flat files,
  emptyWindowChatSessions and no-workspace already exist; the terminal data
  is the legacy {kind:"terminal", command, language} under toolId
  copilot_runInTerminal; isConfirmed is a boolean.
- 1.104: toolSpecificData.commandLine {original, userEdited, toolEdited};
  isConfirmed becomes an object {type: 0..5, ...}; no cwd or exit code.
- 1.109 (2026-02-04): the .jsonl mutation log, transferredChatSessions,
  terminalCommandState.exitCode, terminalCommandOutput and cwd.
- 1.142 (current): the same, session version 3. A version 1 or 2 session
  is normalised by VS Code on load (normalizeSerializableChatData); its
  differences are not known here, so one is read as far as it matches the
  shape above and counted as unknown. Before about 1.100 sessions lived in
  state.vscdb under interactive.sessions; VS Code moves them on first open,
  and that key is not read.

Hooks transcript (off unless the user configured Copilot agent hooks):
workspaceStorage/<workspaceId>/GitHub.copilot-chat/transcripts/
<sessionId>.jsonl, one event per line {type, data, id, timestamp, parentId}
(sessionTranscriptService.ts). Its tool requests (assistant.message
toolRequests) repeat what the chat session holds, and no tool.execution_*
event is logged by 1.142, so it is a "side" store: its text is searched for
secrets, its calls are not judged.

Not read: state.vscdb, the Copilot extension's other storage, the Agent
Host Copilot, Claude and Codex harnesses (their own agents' adapters read
those), VS Code for the Web (browser storage), request.editedFileEvents and
textEditGroup parts (the tool call that made the edit is the record of
it), inputState, repoData, and the contents of attachments.

The store lags the UI: VS Code flushes on a 60 second idle timer, on
closing the chat and on shutdown, so watch sees a call about a minute late.

Limits: a store larger than MAX_BYTES is not replayed (counted as
unreadable); a single line longer than LINE_MAX is skipped and counted
(oversized). Time and memory are linear in the file.
"""

from __future__ import annotations

import json
import os
import re
import urllib.parse

from . import _lines, _paths, _shell, _stamps, base
from .base import SecretText, Source, ToolCall

ENV_PORTABLE = "VSCODE_PORTABLE"
ENV_APPDATA = "VSCODE_APPDATA"

WORKSPACES = "workspaceStorage"
GLOBAL = "globalStorage"
CHAT_DIR = "chatSessions"
EMPTY_WINDOW = "emptyWindowChatSessions"
TRANSFERRED = "transferredChatSessions"
HOOKS = ("GitHub.copilot-chat", "transcripts")
WORKSPACE_JSON = "workspace.json"
JSONL = ".jsonl"
JSON = ".json"

# Mutation kinds (objectMutationLog.ts EntryKind).
INITIAL, SET, PUSH, DELETE = 0, 1, 2, 3

# Session versions this reads (chatModel.ts; 1 and 2 are normalised by VS
# Code, and read here only as far as they match 3).
VERSIONS = (1, 2, 3)

PART = "toolInvocationSerialized"
TERMINAL = "terminal"
INPUT = "input"
VSCODE_SUFFIX = "__vscode"

# isConfirmed.type values after which the tool did not run (chatService.ts
# ToolConfirmKind): Denied and Skipped.
NOT_RUN = (0, 5)

DECLINED = "declined"

# A store larger than this is not replayed or parsed; a longer line is
# skipped. Both are module attributes so tests can lower them.
MAX_BYTES = 256 << 20
LINE_MAX = 128 << 20
_WORKSPACE_MAX = 1 << 16

OVERSIZED = "oversized"

# A copy of watch._PATH_KEYS, plus Copilot's dirPath (create_directory).
PATH_KEYS = ("file_path", "path", "notebook_path", "filePath", "file",
             "filename", "paths", "dirPath")

# The contributed tool names, mapped to the core names the model uses
# (toolNames.ts ContributedToolName; copilot_runInTerminal is the 1.100
# name of run_in_terminal).
CONTRIBUTED = {
    "copilot_applyPatch": "apply_patch",
    "copilot_searchCodebase": "semantic_search",
    "copilot_searchWorkspaceSymbols": "search_workspace_symbols",
    "copilot_getVSCodeAPI": "get_vscode_api",
    "copilot_findFiles": "file_search",
    "copilot_findTextInFiles": "grep_search",
    "copilot_readFile": "read_file",
    "copilot_viewImage": "view_image",
    "copilot_listDirectory": "list_dir",
    "copilot_getErrors": "get_errors",
    "copilot_getChangedFiles": "get_changed_files",
    "copilot_readProjectStructure": "read_project_structure",
    "copilot_createNewWorkspace": "create_new_workspace",
    "copilot_createNewJupyterNotebook": "create_new_jupyter_notebook",
    "copilot_insertEdit": "insert_edit_into_file",
    "copilot_createFile": "create_file",
    "copilot_replaceString": "replace_string_in_file",
    "copilot_multiReplaceString": "multi_replace_string_in_file",
    "copilot_editNotebook": "edit_notebook_file",
    "copilot_runNotebookCell": "run_notebook_cell",
    "copilot_readNotebookCellOutput": "read_notebook_cell_output",
    "copilot_installExtension": "install_extension",
    "copilot_fetchWebPage": "fetch_webpage",
    "copilot_memory": "memory",
    "copilot_findTestFiles": "test_search",
    "copilot_githubRepo": "github_repo",
    "copilot_githubTextSearch": "github_text_search",
    "copilot_createDirectory": "create_directory",
    "copilot_runVscodeCommand": "run_vscode_command",
    "copilot_editFiles": "edit_files",
    "copilot_switchAgent": "switch_agent",
    "copilot_resolveMemoryFileUri": "resolve_memory_file_uri",
    "copilot_sessionStoreSql": "session_store_sql",
    "copilot_runInTerminal": "run_in_terminal",
}

SHELL = "run_in_terminal"

# The kind of each tool this adapter knows (core names). The tools that run
# something it cannot read are left out on purpose (see the module notes).
TOOLS = {
    "run_in_terminal": "shell",
    "read_file": "read",
    "view_image": "read",
    "list_dir": "read",
    "create_file": "write",
    "replace_string_in_file": "write",
    "multi_replace_string_in_file": "write",
    "insert_edit_into_file": "write",
    "apply_patch": "write",
    "edit_notebook_file": "write",
    "create_directory": "write",
    "fetch_webpage": "fetch",
    "github_repo": "fetch",
    "github_text_search": "fetch",
    "semantic_search": "other",
    "grep_search": "other",
    "file_search": "other",
    "search_workspace_symbols": "other",
    "test_search": "other",
    "get_errors": "other",
    "get_changed_files": "other",
    "manage_todo_list": "other",
    "get_terminal_output": "other",
    "kill_terminal": "other",
    "terminal_selection": "other",
    "terminal_last_command": "other",
}

# apply_patch's file headers (applyPatchTool.tsx, the patch grammar).
_PATCH_FILE = re.compile(
    r"^\*\*\* (?:Add File|Update File|Delete File|Move to): (.+?)\s*$",
    re.M)


def _string(value):
    return value if isinstance(value, str) and value else None


def _first_string(*values):
    for value in values:
        if isinstance(value, str) and value:
            return value
    return None


def _is_int(value):
    return isinstance(value, int) and not isinstance(value, bool)


def core_name(name):
    """The core tool name for a toolId or a model-facing name."""
    return CONTRIBUTED.get(name, name)


def _base_id(value):
    """A tool call id without VS Code's "__vscode-<n>" suffix."""
    if isinstance(value, str):
        return value.split(VSCODE_SUFFIX, 1)[0]
    return None


def uri_parts(value):
    """(scheme, authority, path) of a URI as VS Code serialized it (a dict
    with "scheme", "authority" and "path"; the fsPath and external caches
    are not used), or of a URI string; None when it is neither."""
    if isinstance(value, dict):
        path = value.get("path")
        if not isinstance(path, str):
            return None
        scheme = value.get("scheme")
        authority = value.get("authority")
        return (scheme if isinstance(scheme, str) and scheme else "file",
                authority if isinstance(authority, str) else "", path)
    if isinstance(value, str) and value:
        try:
            parts = urllib.parse.urlsplit(value.strip())
        except ValueError:
            return None
        if len(parts.scheme) < 2:       # none, or a Windows drive letter
            return None
        return (parts.scheme.lower(), urllib.parse.unquote(parts.netloc),
                urllib.parse.unquote(parts.path))
    return None


def uri_to_path(value, platform=None):
    """A URI as the path of the file on the machine that ran the call: a
    local file: URI as a local path, any other scheme (vscode-remote://, a
    remote or WSL window) as its path part, which is a path on that host.
    None when `value` is not a URI."""
    parts = uri_parts(value)
    if parts is None:
        return None
    scheme, authority, path = parts
    if scheme == "file":
        quoted = "file://%s%s" % (urllib.parse.quote(authority, safe=""),
                                  urllib.parse.quote(path, safe="/:"))
        return _shell.file_uri_to_path(quoted, platform) or None
    return path or None


def uri_text(value, platform=None):
    """A URI as a local path when it is a file: URI, else as the URI text
    (scheme://authority/path), so a remote window's project keeps its
    host."""
    parts = uri_parts(value)
    if parts is None:
        return None
    scheme, authority, path = parts
    if scheme == "file":
        return uri_to_path(value, platform)
    return "%s://%s%s" % (scheme, authority, path)


# -- replaying the mutation log ----------------------------------------------

def _child(node, key):
    if isinstance(node, dict) and isinstance(key, str):
        return node.get(key)
    if isinstance(node, list) and _is_int(key) and 0 <= key < len(node):
        return node[key]
    return None


def _parent(state, path):
    node = state
    for step in path[:-1]:
        node = _child(node, step)
        if node is None:
            return None
    return node


def apply_entry(state, entry):
    """(state, ok): the replayed object after one log entry. ok is False for
    an entry that could not be applied (an unknown kind, a path that leads
    nowhere); the state is then unchanged. Initial replaces the state with
    v; Set, Push and Delete work on the node the path names, as
    objectMutationLog.ts does."""
    if not isinstance(entry, dict):
        return state, False
    kind = entry.get("kind")
    if kind == INITIAL:
        value = entry.get("v")
        if isinstance(value, dict):
            return value, True
        return state, False
    if not isinstance(state, dict):
        return state, False
    path = entry.get("k")
    if not isinstance(path, list):
        return state, False
    if not path:
        return state, kind in (SET, DELETE)      # no-ops in VS Code too
    last = path[-1]
    parent = _parent(state, path)
    if kind == SET:
        if isinstance(parent, dict) and isinstance(last, str):
            parent[last] = entry.get("v")
            return state, True
        if (isinstance(parent, list) and _is_int(last)
                and 0 <= last <= len(parent)):
            if last == len(parent):
                parent.append(entry.get("v"))
            else:
                parent[last] = entry.get("v")
            return state, True
        return state, False
    if kind == DELETE:
        if isinstance(parent, dict) and isinstance(last, str):
            parent.pop(last, None)
            return state, True
        if isinstance(parent, list) and _is_int(last) and 0 <= last < len(parent):
            parent[last] = None
            return state, True
        return state, False
    if kind == PUSH:
        if isinstance(parent, dict) and isinstance(last, str):
            target = parent.get(last)
            if not isinstance(target, list):
                target = []
                parent[last] = target
        elif (isinstance(parent, list) and _is_int(last)
              and 0 <= last < len(parent)):
            target = parent[last]
            if not isinstance(target, list):
                target = []
                parent[last] = target
        else:
            return state, False
        if "i" in entry:
            cut = entry.get("i")
            if not _is_int(cut) or cut < 0:
                return state, False
            del target[cut:]
        items = entry.get("v")
        if isinstance(items, list):
            target.extend(items)
        return state, True
    return state, False


# -- reading what a call holds -----------------------------------------------

def _paths_in(arguments):
    """(paths, keys): the values of PATH_KEYS in a call's arguments, and the
    keys they came from."""
    paths, keys = [], []
    for key in PATH_KEYS:
        value = arguments.get(key)
        found = [p for p in (value if isinstance(value, (list, tuple))
                             else [value]) if isinstance(p, str) and p]
        if found:
            paths.extend(found)
            keys.append(key)
    return tuple(paths), tuple(keys)


def _write_paths(name, arguments):
    """The files a write names: the usual path keys, each replacement of a
    multi_replace_string_in_file, and the file headers of an apply_patch."""
    paths, _keys = _paths_in(arguments)
    paths = list(paths)
    if name == "multi_replace_string_in_file":
        items = arguments.get("replacements")
        if isinstance(items, list):
            for item in items:
                if isinstance(item, dict):
                    value = item.get("filePath")
                    if isinstance(value, str) and value:
                        paths.append(value)
    if name == "apply_patch":
        patch = arguments.get("input")
        if isinstance(patch, str):
            paths.extend(_PATCH_FILE.findall(patch))
    return tuple(paths)


def _result_paths(details):
    """Paths in a read tool's resultDetails: a list of URIs or Locations
    ({uri, range})."""
    out = []
    if isinstance(details, list):
        for item in details:
            if isinstance(item, dict) and "uri" in item:
                item = item["uri"]
            path = uri_to_path(item)
            if path:
                out.append(path)
    return tuple(out)


def _mcp_output(details):
    """The text of an MCP tool's resultDetails.output ({type: "embed",
    value, isText}), joined by newlines, or None."""
    if not isinstance(details, dict):
        return None
    output = details.get("output")
    if not isinstance(output, list):
        return None
    texts = [o["value"] for o in output
             if isinstance(o, dict) and o.get("type") == "embed"
             and isinstance(o.get("value"), str)]
    return "\n".join(texts) if texts else None


def _not_run(confirmed):
    """True when isConfirmed says the tool did not run: type 0 or 5, or the
    boolean false that data from before 1.104 holds."""
    if confirmed is False:
        return True
    return (isinstance(confirmed, dict) and _is_int(confirmed.get("type"))
            and confirmed["type"] in NOT_RUN)


def _classify(name, arguments, command=None):
    """(kind, known, command, paths, consumed) for a call to the core tool
    `name` with these (decoded) arguments."""
    kind = TOOLS.get(name)
    if kind is None:
        return "other", False, None, (), ()
    if kind == "shell":
        command = command or _string(arguments.get("command"))
        return kind, True, command, (), ("command",) if command else ()
    if kind == "read":
        paths, keys = _paths_in(arguments)
        return kind, True, None, paths, keys
    if kind == "write":
        return kind, True, None, _write_paths(name, arguments), ()
    return kind, True, None, (), ()


def _command_of(tsd):
    """The command a terminal part ran: userEdited, else the model's own
    original, else forDisplay, else toolEdited (see the module notes); the
    1.100 shape holds it as "command"."""
    line = tsd.get("commandLine")
    if isinstance(line, dict):
        return _first_string(line.get("userEdited"), line.get("original"),
                             line.get("forDisplay"), line.get("toolEdited"))
    return _first_string(line, tsd.get("command"))


def _working_dir(value):
    if isinstance(value, str) and value:
        return uri_to_path(value) or value
    return uri_to_path(value)


class VSCodeCopilotSource(Source):
    id = "vscode-copilot"
    name = "GitHub Copilot in VS Code"
    unit = "session"
    env = (ENV_PORTABLE, ENV_APPDATA)
    path_means = ("a VS Code user data folder, the one holding "
                  "workspaceStorage and globalStorage (<user data>/User)")
    checked = "1.142.0"
    # Said after masking. VS Code holds an open chat in memory and writes it
    # back, and a mutation log is replaced whole when it is compacted.
    mask_note = ("If VS Code has this chat open, close the window first: it "
                 "keeps the chat in memory and writes it back, value "
                 "included.")

    def reset(self):
        Source.reset(self)
        self.counts.setdefault(OVERSIZED, 0)
        self._bad = set()
        self._tallied = set()

    def notes(self, locations=None, platform=None):
        out = []
        n = self.counts.get(OVERSIZED, 0)
        if n:
            out.append("%d line%s in GitHub Copilot's VS Code history %s "
                       "longer than %d MiB and was not read."
                       % (n, "" if n == 1 else "s", "was" if n == 1 else
                          "were", LINE_MAX >> 20))
        return out

    # -- where to look ------------------------------------------------------

    def default_paths(self, env, home, platform):
        """Every VS Code-family User folder _paths.editor_user_dirs gives:
        VSCODE_PORTABLE, VSCODE_APPDATA, the platform default and the forks
        probed beside it."""
        return list(_paths.editor_user_dirs(env, home, platform))

    @staticmethod
    def _entries(folder):
        try:
            return sorted(os.scandir(folder), key=lambda e: e.name)
        except OSError:
            return []

    @staticmethod
    def _is_dir(entry):
        try:
            return entry.is_dir()
        except OSError:
            return False

    @staticmethod
    def _is_file(entry):
        try:
            return entry.is_file()
        except OSError:
            return False

    def _session_files(self, folder, suffixes=(JSONL, JSON)):
        """(path, suffix) for every session file directly in `folder`."""
        out = []
        for entry in self._entries(folder):
            if entry.name.startswith("."):
                continue
            for suffix in suffixes:
                if entry.name.endswith(suffix) and len(entry.name) > len(suffix):
                    if self._is_file(entry):
                        out.append((entry.path, suffix))
                    break
        return out

    @staticmethod
    def _project_of(workspace_dir):
        """The project a workspaceStorage folder's workspace.json names, or
        None."""
        try:
            with open(os.path.join(workspace_dir, WORKSPACE_JSON), "rb") as fh:
                raw = fh.read(_WORKSPACE_MAX)
            doc = json.loads(raw.decode("utf-8", "replace"))
        except (OSError, ValueError, RecursionError):
            return None
        if not isinstance(doc, dict):
            return None
        folder = doc.get("folder")
        if isinstance(folder, str) and folder:
            return uri_text(folder) or folder
        workspace = doc.get("workspace")
        if isinstance(workspace, str) and workspace:
            parts = uri_parts(workspace)
            if parts is None:
                return None
            scheme, authority, path = parts
            where = os.path.dirname(uri_to_path(workspace) or path)
            if scheme == "file":
                return where or None
            return "%s://%s%s" % (scheme, authority, where)
        return None

    def _candidates(self, user_dir):
        """[(path, suffix, project, role_hint)] for one User folder: role_hint
        is "side" for a copy or a hooks transcript, else "transcript"."""
        found = []
        workspaces = os.path.join(user_dir, WORKSPACES)
        for entry in self._entries(workspaces):
            if entry.name.startswith(".") or not self._is_dir(entry):
                continue
            project = None
            chats = self._session_files(os.path.join(entry.path, CHAT_DIR))
            hooks = self._session_files(os.path.join(entry.path, *HOOKS),
                                        (JSONL,))
            if chats or hooks:
                project = self._project_of(entry.path)
            for path, suffix in chats:
                found.append((path, suffix, project, "transcript"))
            for path, suffix in hooks:
                found.append((path, suffix, project, "side"))
        glob = os.path.join(user_dir, GLOBAL)
        for path, suffix in self._session_files(os.path.join(glob,
                                                             EMPTY_WINDOW)):
            found.append((path, suffix, None, "transcript"))
        for path, suffix in self._session_files(os.path.join(glob, TRANSFERRED)):
            found.append((path, suffix, None, "side"))
        return found

    def stores(self, locations, since_days=None):
        candidates, seen = [], set()
        for loc in locations:
            for item in self._candidates(loc.path):
                key = os.path.normcase(os.path.abspath(item[0]))
                if key in seen:
                    continue
                seen.add(key)
                candidates.append(item)
        # One store per file; per sessionId the best is the transcript.
        rated = []
        for path, suffix, project, role in candidates:
            try:
                mtime = os.stat(path).st_mtime
            except OSError:
                continue
            session = os.path.basename(path)[:-len(suffix)]
            rated.append((path, suffix, project, role, session, mtime))
        best = {}
        for path, suffix, project, role, session, mtime in rated:
            if role != "transcript":
                continue
            rank = (suffix == JSONL, mtime, path)
            if session not in best or rank > best[session][0]:
                best[session] = (rank, path)
        found = []
        for path, suffix, project, role, session, _mtime in rated:
            if role == "transcript" and best[session][1] != path:
                role = "side"
            store = self.store(path, "jsonl" if suffix == JSONL else "json",
                               role=role, session=session, project=project)
            if store is not None:
                found.append(store)
        return base.newest_first(found, since_days)

    # -- reading ------------------------------------------------------------

    def _bad_store(self, store, reason):
        if store.path not in self._bad:
            self._bad.add(store.path)
            self.unreadable_store(reason, store.path)
        self.warn(store.path, "could not read GitHub Copilot's VS Code chat "
                  "%s (%s)" % (store.path, reason))

    def _first(self, store, tag):
        key = (tag, store.path)
        first = key not in self._tallied
        self._tallied.add(key)
        return first

    @staticmethod
    def _raw_lines(fh):
        """(line_no, raw) for every line; raw is None for a line longer than
        LINE_MAX, which is read past and not kept."""
        line_no = 0
        while True:
            raw = fh.readline(LINE_MAX + 1)
            if not raw:
                return
            line_no += 1
            if len(raw) > LINE_MAX and not raw.endswith(b"\n"):
                while True:
                    more = fh.readline(1 << 20)
                    if not more or more.endswith(b"\n"):
                        break
                yield line_no, None
                continue
            yield line_no, raw

    def _too_big(self, store):
        try:
            return os.path.getsize(store.path) > MAX_BYTES
        except OSError:
            return False

    def _log(self, store, tally):
        """The state a mutation log replays to, or None. Counts lines that
        are not JSON, entries that cannot be applied and lines too long."""
        state = None
        bad = skipped = 0
        try:
            with open(store.path, "rb") as fh:
                for line_no, raw in self._raw_lines(fh):
                    if raw is None:
                        if tally:
                            self.count(OVERSIZED)
                        continue
                    text = _lines.decode_line(raw, first=line_no == 1)
                    if not text.strip():
                        continue
                    try:
                        entry = json.loads(text)
                    except (ValueError, RecursionError):
                        if raw.endswith(b"\n"):
                            bad += 1
                        continue
                    state, ok = apply_entry(state, entry)
                    if not ok:
                        skipped += 1
        except OSError as e:
            self._bad_store(store, e.strerror or str(e))
            return None
        if tally:
            self.count("unparsed", bad)
            self.count("unknown", skipped)
        return state

    def _document(self, store, tally):
        """The object in a flat .json, or None."""
        try:
            with open(store.path, "rb") as fh:
                data = fh.read(MAX_BYTES + 1)
        except OSError as e:
            self._bad_store(store, e.strerror or str(e))
            return None
        try:
            doc = json.loads(_lines.decode_line(data, first=True))
        except (ValueError, RecursionError):
            if tally:
                self.count("unparsed")
            return None
        return doc if isinstance(doc, dict) else None

    def _state(self, store):
        """The session object of a store, or None. A store over MAX_BYTES is
        counted as not read."""
        tally = self._first(store, "tally")
        if self._too_big(store):
            self._bad_store(store, "larger than %d MiB" % (MAX_BYTES >> 20))
            return None
        state = (self._document(store, tally) if store.format == "json"
                 else self._log(store, tally))
        if state is not None and tally:
            version = state.get("version")
            if version is not None and version not in VERSIONS:
                self.count("unknown")
        return state

    # -- tool calls ---------------------------------------------------------

    @staticmethod
    def _rounds(request):
        """({id: {name, arguments, timestamp}}, results) from a request's
        result.metadata: the model-side record of its tool calls, and the
        ids that have a result."""
        result = request.get("result")
        meta = result.get("metadata") if isinstance(result, dict) else None
        rounds, results = {}, set()
        if not isinstance(meta, dict):
            return rounds, results
        items = meta.get("toolCallRounds")
        for rnd in items if isinstance(items, list) else []:
            if not isinstance(rnd, dict):
                continue
            calls = rnd.get("toolCalls")
            for call in calls if isinstance(calls, list) else []:
                if not isinstance(call, dict):
                    continue
                cid = _base_id(call.get("id"))
                if cid and cid not in rounds:
                    rounds[cid] = {"name": call.get("name"),
                                   "arguments": call.get("arguments"),
                                   "has_arguments": "arguments" in call,
                                   "timestamp": rnd.get("timestamp")}
        done = meta.get("toolCallResults")
        if isinstance(done, dict):
            results = {_base_id(k) for k in done}
        return rounds, results

    def _stamp(self, *values):
        for value in values:
            stamp = _stamps.iso_utc(value, "ms")
            if stamp:
                return stamp
        return None

    def _shared(self, store, state, request, when):
        stamp = self._stamp(*when, request.get("timestamp"))
        return dict(
            session=_string(state.get("sessionId")) or store.session,
            timestamp=stamp,
            not_after=None if stamp else _stamps.iso_utc(store.mtime, "s"))

    def _part_call(self, store, state, request, part, rounds, fallback):
        cid = _string(part.get("toolCallId"))
        info = rounds.get(_base_id(cid)) or {}
        tool_id = _string(part.get("toolId")) or ""
        name = core_name(_string(info.get("name")) or tool_id)
        tsd = part.get("toolSpecificData")
        tsd = tsd if isinstance(tsd, dict) else {}
        details = part.get("resultDetails")
        if info.get("has_arguments"):
            arguments = base.decode_input(info.get("arguments"))
        elif tsd.get("kind") == INPUT and "rawInput" in tsd:
            arguments = base.decode_input(tsd.get("rawInput"))
        elif isinstance(details, dict) and "input" in details:
            arguments = base.decode_input(details.get("input"))
        else:
            arguments = {}
        command = None
        workdir = None
        output = None
        run = {}
        if name == SHELL and tsd.get("kind") == TERMINAL:
            command = _command_of(tsd)
            workdir = _working_dir(tsd.get("cwd"))
            out = tsd.get("terminalCommandOutput")
            if isinstance(out, dict) and isinstance(out.get("text"), str):
                output = out["text"]
            state_ = tsd.get("terminalCommandState")
            run = state_ if isinstance(state_, dict) else {}
        if output is None:
            output = _mcp_output(details)
        kind, known, command, paths, consumed = _classify(name, arguments,
                                                          command)
        if known and name == SHELL and command and "command" not in arguments:
            arguments = dict(arguments, command=command)
            consumed = ("command",)
        if kind == "read" and not paths:
            paths = _result_paths(details)
        status = DECLINED if _not_run(part.get("isConfirmed")) else None
        if run and (_is_int(run.get("exitCode")) or _is_int(run.get("timestamp"))):
            status = None               # it ran
        project = store.project or fallback or workdir
        return ToolCall(
            self.id, store.path, name, arguments, kind=kind, known=known,
            tool_call_id=cid, command=command, workdir=workdir, paths=paths,
            consumed=consumed, status=status, output=output, project=project,
            **self._shared(store, state, request,
                           (run.get("timestamp"), info.get("timestamp"))))

    def _round_call(self, store, state, request, cid, info, results, fallback):
        name = core_name(_string(info.get("name")) or "")
        arguments = base.decode_input(info.get("arguments"))
        kind, known, command, paths, consumed = _classify(name, arguments)
        return ToolCall(
            self.id, store.path, name, arguments, kind=kind, known=known,
            tool_call_id=cid, command=command, paths=paths, consumed=consumed,
            status=None if cid in results else DECLINED,
            project=store.project or fallback,
            **self._shared(store, state, request, (info.get("timestamp"),)))

    def _state_calls(self, store, state):
        requests = state.get("requests")
        if not isinstance(requests, list):
            return
        fallback = _working_dir(state.get("workingDirectory"))
        for request in requests:
            if not isinstance(request, dict):
                self.count("unknown")
                continue
            rounds, results = self._rounds(request)
            matched = set()
            response = request.get("response")
            for part in response if isinstance(response, list) else []:
                if not isinstance(part, dict) or part.get("kind") != PART:
                    continue
                call = self._part_call(store, state, request, part, rounds,
                                       fallback)
                matched.add(_base_id(call.tool_call_id))
                yield call
            for cid, info in rounds.items():
                if cid in matched:
                    continue
                yield self._round_call(store, state, request, cid, info,
                                       results, fallback)

    def tool_calls(self, store):
        """Every tool call in a session's final state, once. A .jsonl is
        replayed first. Only the transcript of a session is read (see the
        module notes); a copy or a hooks transcript yields nothing."""
        if store.role != "transcript":
            return
        state = self._state(store)
        if state is None:
            return
        for call in self._state_calls(store, state):
            yield call

    # -- text for clean -----------------------------------------------------

    def secret_texts(self, store):
        """Every line of a .jsonl, as it is written (each version of a call
        the log holds, copies the agent no longer replays among them); a
        flat .json as the session without its requests, then each request.
        A line that is not JSON is handed over as text."""
        if store.format == "json":
            for text in self._document_texts(store):
                yield text
            return
        tally = self._first(store, "tally")
        parsed = bad = 0
        try:
            with open(store.path, "rb") as fh:
                for line_no, raw in self._raw_lines(fh):
                    if raw is None:
                        if tally:
                            self.count(OVERSIZED)
                        continue
                    text = _lines.decode_line(raw, first=line_no == 1)
                    if not text.strip():
                        continue
                    where = "line %d" % line_no
                    try:
                        obj = json.loads(text)
                    except (ValueError, RecursionError):
                        if raw.endswith(b"\n"):
                            bad += 1
                        yield SecretText(text, where=where)
                        continue
                    parsed += 1
                    yield SecretText(obj, where=where)
        except OSError as e:
            self._bad_store(store, e.strerror or str(e))
            return
        finally:
            if tally:
                self.count("unparsed", bad)
        if bad and not parsed:
            self._bad_store(store, "not JSON Lines")

    def _document_texts(self, store):
        tally = self._first(store, "tally")
        if self._too_big(store):
            self._bad_store(store, "larger than %d MiB" % (MAX_BYTES >> 20))
            return
        doc = self._document(store, tally)
        if doc is None:
            return
        requests = doc.get("requests")
        if isinstance(requests, list):
            rest = {k: v for k, v in doc.items() if k != "requests"}
            yield SecretText(rest, where="session")
            for index, request in enumerate(requests):
                yield SecretText(request, where="request %d" % (index + 1))
        else:
            yield SecretText(doc, where="session")
