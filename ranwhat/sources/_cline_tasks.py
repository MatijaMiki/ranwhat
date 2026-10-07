"""The task folder Cline and Roo Code both keep, read once for both.

Roo Code forked Cline, and both still write one folder per task under
their storage folder: tasks/<taskId>/ holding
- api_conversation_history.json: the conversation as sent to the model, a
  JSON array of Anthropic MessageParam objects ({"role", "content"}) with
  the agent's own extras (ts in ms on most messages, id, modelInfo,
  metrics; Roo also isSummary, condenseId and the like). Compact JSON,
  written whole through a temp file and a rename (Cline v3.89.2
  core/storage/disk.ts atomicWriteFile; Roo v3.54.0 utils/safeWriteJson.ts,
  which also holds a proper-lockfile directory <file>.lock while it
  writes).
- ui_messages.json: what the chat panel showed, a JSON array of
  ClineMessage {ts, type: "ask"|"say", ask?, say?, text?, ...}. Cline's
  say "api_req_started" carries the whole request (tool results, file
  contents) again in its text; Roo's does not.
- claude_messages.json: the name ui_messages.json had in Claude Dev, the
  extension Cline was. Both agents delete it once they load the task; one
  never opened since is still there. Read as a side store (Roo v3.54.0
  task-persistence/apiMessages.ts takes it for an old API history; Cline
  v3.89.2 disk.ts getSavedClineMessages for the old UI log; its shape
  decides nothing here, it is only searched).

Tool calls are in the API history in one of two protocols, chosen per
request, so one task can hold both:
- native: an assistant {"type": "tool_use", "id", "name", "input"} block,
  answered by a user {"type": "tool_result", "tool_use_id", "content"}
  block (a string, or a list of text and image blocks);
- XML: the tool written as tags inside an assistant text block, e.g.
  <execute_command>\\n<command>ls</command>\\n</execute_command>. The
  agents' own parsers (Cline parse-assistant-message.ts
  parseAssistantMessageV2; Roo v3.36.0 AssistantMessageParser.ts, removed
  in 3.43) find an opening tag of one of their own tool names anywhere in
  the text, then the opening tags of their own parameter names inside it,
  each parameter running to its own closing tag, and the tool to its
  closing tag. They are mirrored here with each agent's own tag sets: a
  tag of any other name is text. A tool left open at the end of the text
  ran too, when it had a parameter (the agents present a partial block
  once the stream ends). An XML call has no id; it is given
  "xml-<message>-<block>-<n>" (its place in the file), which is stable
  across reads. Its result is plain text in the next user message:
  "[<tool> for '<arg>'] Result:\\n<result>" in one block (Cline 3.2x and
  later, ToolResultUtils.ts), or "[<tool> for '<arg>'] Result:" and the
  result in the next block (Cline 3.0, Roo). A result is given to the
  first unanswered call of that name in the assistant message before it.

A call never ran ("declined") when its result is the agent's own text for
that:
- "The user denied this operation." (Cline core/prompts/responses.ts
  toolDenied; Roo's XML era, and "...and provided the following
  feedback" after it);
- {"status": "denied", ...} (Roo native, core/prompts/responses.ts);
- "Skipping tool ... due to user rejecting a previous tool.", "... was
  interrupted and not executed due to user rejecting a previous tool.",
  and "Tool [<name>] was not executed because a tool has already been
  used in this message." (Cline ToolExecutor.ts and responses.ts
  toolAlreadyUsed; Roo presentAssistantMessage.ts), which come as a
  tool_result or as a plain text block.
Each agent adds its own on top (see cline.py and roo.py).

Time: an assistant message's ts (ms) is the time of its calls, written
when the model's response was saved (Cline index.ts, Roo Task.ts
addToApiConversationHistory). Without one, the next user message's ts,
written when the results were sent back, is a time the call ran before
(not_after); without that, the file's last write. --days can then only
keep a call it should have dropped, never drop one it should keep.

Paths in tool inputs are as the model wrote them, relative to the task's
working directory: each call's project, and a shell call's workdir, is
that directory, from the agent's own task index when it has one, else
from the first "# Current Working Directory (<cwd>) Files" (Cline) or
"# Current Workspace Directory (<cwd>) Files" (Roo) line of the
environment details it sent the model.

What is never opened: anything in the storage folder outside tasks/<id>/
and the files named above (settings/, cache/, state/ except Cline's task
index, the Roo CLI's secrets.json beside tasks/), and in a task folder
checkpoints/ (a shadow git repository of the workspace), task_metadata.json,
context_history.json and settings.json.
"""

from __future__ import annotations

import json
import ntpath
import os
import posixpath
import re

from . import _lines, _paths, _stamps
from .base import SecretText, Source, ToolCall

TASKS = "tasks"
API = "api_conversation_history.json"
UI = "ui_messages.json"
OLD_UI = "claude_messages.json"
GLOBAL_STORAGE = "globalStorage"

DECLINED = "declined"

# Message roles the API history holds. "tool" is the role a Cline SDK
# message has before it is stored as "user"; it is read the same way.
ROLES = ("user", "assistant", "system", "tool")
UI_TYPES = ("ask", "say")

# The VS Code-family editors whose User folders are probed under the
# editor parent folder (_paths.editor_parent): VS Code's own folder name,
# then the forks _paths probes. Looked at only inside stores(), once the
# parent is known to exist, so an absent editor costs nothing more.
EDITORS = (_paths.EDITOR_VERIFIED,) + tuple(_paths.EDITORS_PROBED)

# A tool result's header, as both agents write it in XML mode: the tool's
# name in brackets, then " for '...'", " in ...", " to ..." or "]".
_HEADER = re.compile(r"\[([A-Za-z0-9_.:\-]+)(?:\]| )")
RESULT = "] Result:"

# The texts the agents put in place of a call they did not run.
DENIED = "The user denied this operation"
NOT_RUN = ("due to user rejecting a previous tool.",
           "was not executed because a tool has already been used in this "
           "message.")

# The environment details' working directory line (see the module notes),
# searched in the JSON text of a file's head, so inside a JSON string.
_CWD_JSON = re.compile(r"# Current (?:Working|Workspace) Directory \("
                       r"((?:[^\"\\]|\\[^n])*?)\) Files\\n")
_CWD_TEXT = re.compile(r"# Current (?:Working|Workspace) Directory \((.*?)\)"
                       r" Files\n")
_HEAD_MAX = 1 << 18

# apply_patch's own grammar names its files on these lines.
_PATCH_FILE = re.compile(r"^\*\*\* (?:(?:Add|Update|Delete) File|Move to): "
                         r"(.+?)\s*$", re.M)

_WIN_ABS = re.compile(r"(?:[A-Za-z]:[\\/]|\\\\)")


def string(value):
    return value if isinstance(value, str) and value else None


def dict_of(value):
    return value if isinstance(value, dict) else {}


# --------------------------------------------------------------------------
# Where
# --------------------------------------------------------------------------

def editor_locations(env, home, platform, ext):
    """[(path, how)] where an extension's globalStorage folders are looked
    for, one Location each: the editor parent folder (each editor's
    <parent>/<editor>/User/globalStorage/<ext> is probed in it by
    editor_roots), VSCODE_APPDATA (another such parent) and VSCODE_PORTABLE
    (whose globalStorage/<ext> is named directly), when set. Pure."""
    j = _paths.pathmod(platform).join
    out = []
    portable = _paths._set(env, "VSCODE_PORTABLE")
    if portable:
        out.append((j(portable, "user-data", "User", GLOBAL_STORAGE, ext),
                    "env VSCODE_PORTABLE"))
    moved = _paths._set(env, "VSCODE_APPDATA")
    if moved:
        out.append((moved, "env VSCODE_APPDATA"))
    out.append((_paths.editor_parent(env, home, platform), "default"))
    return out


def task_roots(folder, ids):
    """The storage folders at a location: the folder itself when it holds
    tasks/ or sessions/ (a globalStorage/<id> folder, a Cline data folder,
    a --path), else each <folder>/<editor>/User/globalStorage/<id> that
    exists, for an editor parent folder."""
    if any(os.path.isdir(os.path.join(folder, d)) for d in (TASKS, "sessions")):
        return [folder]
    out = []
    for editor in EDITORS:
        for ext in ids:
            root = os.path.join(folder, editor, "User", GLOBAL_STORAGE, ext)
            if os.path.isdir(root):
                out.append(root)
    return out


def entries(folder):
    try:
        return list(os.scandir(folder))
    except OSError:
        return []


def subdirs(folder):
    """The folders directly in `folder`, not dot-folders and not
    proper-lockfile's <name>.lock folders."""
    out = []
    for entry in entries(folder):
        if entry.name.startswith(".") or entry.name.endswith(".lock"):
            continue
        try:
            if entry.is_dir():
                out.append(entry.path)
        except OSError:
            continue
    return sorted(out)


def is_file(path):
    try:
        return os.path.isfile(path)
    except (OSError, ValueError):
        return False


def read_json(path, limit=None):
    """The decoded JSON in `path`, or None: never raises."""
    try:
        with open(path, "rb") as fh:
            raw = fh.read() if limit is None else fh.read(limit + 1)
    except (OSError, ValueError):
        return None
    if limit is not None and len(raw) > limit:
        return None
    text = raw.decode("utf-8", "surrogateescape")
    if text.startswith(_lines.BOM):
        text = text[1:]
    try:
        return json.loads(text)
    except (ValueError, RecursionError):
        return None


def _absolute(value):
    return bool(value) and (value.startswith("/") or bool(_WIN_ABS.match(value)))


def cwd_from_head(path):
    """The working directory named in the environment details near the
    start of an API history file, or None."""
    try:
        with open(path, "rb") as fh:
            head = fh.read(_HEAD_MAX).decode("utf-8", "replace")
    except (OSError, ValueError):
        return None
    m = _CWD_JSON.search(head)
    if not m:
        return None
    try:
        value = json.loads('"%s"' % m.group(1))
    except (ValueError, RecursionError):
        return None
    return value if isinstance(value, str) and _absolute(value) else None


def cwd_from_messages(messages):
    """The same, from decoded messages: the first that names one."""
    for message in messages[:8] if isinstance(messages, list) else ():
        for _j, block in blocks(message):
            text = block.get("text")
            if isinstance(text, str):
                m = _CWD_TEXT.search(text)
                if m and _absolute(m.group(1)):
                    return m.group(1)
    return None


def join_cwd(cwd, rel):
    """`rel` against the directory `cwd`, the way Node's path.resolve does
    on the system `cwd` is from: an absolute `rel` as it is."""
    if not rel:
        return cwd
    if _absolute(rel) or not cwd:
        return rel
    mod = ntpath if (_WIN_ABS.match(cwd) or "\\" in cwd) else posixpath
    return mod.normpath(mod.join(cwd, rel))


def patch_paths(patch):
    """The files an apply_patch payload names, in order."""
    if not isinstance(patch, str):
        return ()
    return tuple(m.group(1) for m in _PATCH_FILE.finditer(patch))


# --------------------------------------------------------------------------
# Messages
# --------------------------------------------------------------------------

def blocks(message):
    """[(index, block)] of a message's content blocks; a string content is
    one text block at index 0."""
    if not isinstance(message, dict):
        return []
    content = message.get("content")
    if isinstance(content, str):
        return [(0, {"type": "text", "text": content})]
    if not isinstance(content, list):
        return []
    return [(j, b) for j, b in enumerate(content) if isinstance(b, dict)]


def block_text(content):
    """A tool result's content as text: a string as it is, else the text
    blocks (or "text" fields) of a list joined by newlines; None when there
    is no text."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        texts = [b.get("text") for b in content if isinstance(b, dict)
                 and isinstance(b.get("text"), str)]
        if texts:
            return "\n".join(texts)
    return None


def parse_xml(text, tools, params, newline_content=False):
    """[(name, params, closed)] for the tool calls written as XML in `text`,
    the way the agents' own parsers read them (see the module notes).
    `tools` and `params` are compiled alternations of the agent's tool and
    parameter names. A parameter's value is trimmed; with newline_content,
    Roo's rule for "content": one leading and one trailing newline only.
    write_to_file's content runs to the last </content> in the tool, as
    both agents read it."""
    out = []
    pos, n = 0, len(text)
    while pos < n:
        m = tools.search(text, pos)
        if not m:
            break
        name = m.group(1)
        start = pos = m.end()
        close = "</%s>" % name
        found = {}
        closed = False
        # The first closing tag at or after pos, found again only once pos
        # has passed it: looking for it from every parameter made a tool
        # with many parameters and no closing tag quadratic.
        c = text.find(close, pos)
        while pos < n:
            p = params.search(text, pos)
            if c != -1 and c < pos:
                c = text.find(close, pos)
            if c != -1 and (p is None or c < p.start()):
                body = text[start:c]
                if name == "write_to_file" and "<content>" in body:
                    a = body.find("<content>") + len("<content>")
                    b = body.rfind("</content>")
                    if b > a:
                        found["content"] = _trim(body[a:b], "content",
                                                 newline_content)
                pos = c + len(close)
                closed = True
                break
            if p is None:
                pos = n
                break
            pname = p.group(1)
            end = text.find("</%s>" % pname, p.end())
            if end == -1:
                found[pname] = _trim(text[p.end():], pname, newline_content)
                pos = n
                break
            found[pname] = _trim(text[p.end():end], pname, newline_content)
            pos = end + len(pname) + 3
        if closed or found:
            out.append((name, found, closed))
    return out


def _trim(value, name, newline_content):
    if newline_content and name == "content":
        if value.startswith("\n"):
            value = value[1:]
        if value.endswith("\n"):
            value = value[:-1]
        return value
    return value.strip()


def alternation(names):
    """A compiled <(name|...)> for these tag names, longest first."""
    names = sorted(set(names), key=lambda s: (-len(s), s))
    return re.compile("<(%s)>" % "|".join(re.escape(s) for s in names))


def result_body(text):
    """(name, body) for a result text that starts with the XML-mode header
    "[<tool> ...] Result:", body being what follows it ("" when the result
    is in the next block); else (None, None)."""
    if not text.startswith("["):
        return None, None
    m = _HEADER.match(text)
    i = text.find(RESULT)
    first = text.find("\n")
    if not m or i == -1 or (first != -1 and i > first):
        return None, None
    body = text[i + len(RESULT):]
    if body.startswith("\n"):
        body = body[1:]
    return m.group(1), body


def not_run_name(text):
    """The tool name in one of the agents' "not executed" texts (NOT_RUN),
    or None when `text` is not one."""
    head = text.split("\n", 1)[0]
    if not any(marker in head for marker in NOT_RUN):
        return None
    m = re.search(r"\[([A-Za-z0-9_.:\-]+)", head)
    return m.group(1) if m else ""


class Paired(object):
    """What one read of an API history found: its calls in file order,
    and which content block (or element of one) is a call's result."""
    __slots__ = ("calls", "ties")

    def __init__(self):
        self.calls = []
        self.ties = {}      # (msg, block) or (msg, block, element) -> ToolCall


# --------------------------------------------------------------------------
# The shared source
# --------------------------------------------------------------------------

class TaskSource(Source):
    """A Source over task folders. A subclass sets the tool tables and
    classify(), and adds what its agent has besides."""

    unit = "task"
    TOOLS = {}              # tool name -> kind, for XML and native calls
    TOOL_TAGS = None        # alternation(...) of the XML tool names
    PARAM_TAGS = None       # alternation(...) of the XML parameter names
    NEWLINE_CONTENT = False

    def reset(self):
        Source.reset(self)
        self._bad = set()       # stores counted as unreadable
        self._tallied = set()   # stores whose unknown records are counted

    # -- reading ------------------------------------------------------------

    def _bad_store(self, store, reason):
        if store.path not in self._bad:
            self._bad.add(store.path)
            self.unreadable_store(reason, store.path)
        self.warn(store.path, "could not read %s %s %s (%s)"
                  % (self.name, store.unit, store.path, reason))

    def load(self, store):
        """The decoded document, or None (warned and counted once) when the
        file cannot be read or is not JSON: a file caught half written
        (the Cline SDK's are written in place) is one."""
        try:
            with open(store.path, "rb") as fh:
                text = fh.read().decode("utf-8", "surrogateescape")
        except (OSError, ValueError) as e:
            self._bad_store(store, getattr(e, "strerror", None)
                            or type(e).__name__)
            return None
        if text.startswith(_lines.BOM):
            text = text[1:]
        try:
            return json.loads(text)
        except (ValueError, RecursionError):
            self._bad_store(store, "not JSON")
            return None

    def first(self, store):
        """True the first time a store is read this run."""
        first = store.path not in self._tallied
        self._tallied.add(store.path)
        return first

    def messages_of(self, store, doc):
        """The message list of an API history document (counting, once per
        store per run, a document or message of a shape it does not
        have)."""
        tally = self.first(store)
        messages = doc if isinstance(doc, list) else None
        if messages is None:
            if tally:
                self.count("unknown")
            return []
        if tally:
            for message in messages:
                if not (isinstance(message, dict)
                        and message.get("role") in ROLES):
                    self.count("unknown")
        return messages

    def ui_of(self, store, doc):
        tally = self.first(store)
        if not isinstance(doc, list):
            if tally:
                self.count("unknown")
            return []
        if tally:
            for item in doc:
                if not (isinstance(item, dict) and item.get("type") in UI_TYPES):
                    self.count("unknown")
        return doc

    # -- one call -----------------------------------------------------------

    def classify(self, name, arguments, cwd):
        """[dict(kind, known, command, paths, consumed, workdir)] for a call
        to `name` with these decoded arguments: one entry per call it
        stands for (a Cline SDK run_commands is one per command)."""
        kind = self.TOOLS.get(name)
        if kind is None:
            return [dict(kind="other", known=False)]
        return [dict(kind=kind, known=True)]

    def declined_result(self, text, block, name):
        """True when a result's text (and its tool_result block, or None for
        plain text) says the call never ran (see the module notes)."""
        text = self.body_of(text)
        if not isinstance(text, str):
            return False
        stripped = text.lstrip()
        if stripped.startswith(DENIED):
            return True
        if not_run_name(stripped) is not None:
            return True
        return False

    def body_of(self, text):
        """A result's text without the XML-mode header, when it has one."""
        if isinstance(text, str):
            _name, body = result_body(text)
            if body is not None:
                return body
        return text

    def make_calls(self, store, name, arguments, cid, timestamp, cwd, extra):
        """The ToolCalls one recorded call stands for."""
        made = []
        shapes = self.classify(name, arguments, cwd)
        for n, shape in enumerate(shapes):
            kind = shape.get("kind", "other")
            known = shape.get("known", False)
            call_id = cid
            if cid is not None and len(shapes) > 1:
                call_id = "%s#%d" % (cid, n + 1)
            made.append(ToolCall(
                self.id, store.path, name, arguments, kind=kind, known=known,
                session=extra.get("session") or store.session,
                project=cwd, timestamp=timestamp, tool_call_id=call_id,
                command=shape.get("command"), workdir=shape.get("workdir"),
                paths=shape.get("paths", ()),
                consumed=shape.get("consumed", ())))
        return made

    # -- pairing ------------------------------------------------------------

    def pair(self, store, messages, cwd, extra=None, xml=True):
        """Paired for an API history's messages (see the module notes):
        each call once per id, first copy, with its output and status and
        the time it was made or ran before. xml False reads native calls
        only (the Cline SDK has no XML protocol)."""
        extra = extra or {}
        found = Paired()
        seen = set()
        pending = {}            # tool_use id -> [ToolCall]
        open_calls = []         # [(name, [ToolCall])] of the last assistant
        for i, message in enumerate(messages):
            if not isinstance(message, dict):
                continue
            role = message.get("role")
            when = _stamps.iso_utc(message.get("ts"), "ms")
            if role == "assistant":
                open_calls = self._assistant(store, i, message, when, cwd,
                                             extra, seen, pending, found, xml)
            elif role in ("user", "tool"):
                self._answers(i, message, pending, open_calls, found)
                if when:
                    for _name, made in open_calls:
                        for call in made:
                            if call.timestamp is None and call.not_after is None:
                                call.not_after = when
                open_calls = []
        fallback = _stamps.iso_utc(store.mtime, "s")
        for call in found.calls:
            if call.timestamp is None and call.not_after is None:
                call.not_after = fallback
        return found

    def _assistant(self, store, i, message, when, cwd, extra, seen, pending,
                   found, xml):
        out = []
        for j, block in blocks(message):
            kind = block.get("type")
            if kind == "tool_use":
                name = string(block.get("name")) or ""
                cid = string(block.get("id"))
                if cid is not None:
                    if cid in seen:
                        continue
                    seen.add(cid)
                made = self.make_calls(store, name, self.input_of(block),
                                       cid, when, cwd, extra)
                if cid is not None:
                    pending[cid] = made
                found.calls.extend(made)
                out.append((name, made))
            elif kind == "text" and isinstance(block.get("text"), str) \
                    and xml and self.TOOL_TAGS is not None:
                parsed = parse_xml(block["text"], self.TOOL_TAGS,
                                   self.PARAM_TAGS, self.NEWLINE_CONTENT)
                for k, (name, params, _closed) in enumerate(parsed):
                    cid = "xml-%d-%d-%d" % (i, j, k)
                    if cid in seen:
                        continue
                    seen.add(cid)
                    made = self.make_calls(store, name, params, cid, when,
                                           cwd, extra)
                    found.calls.extend(made)
                    out.append((name, made))
        return out

    @staticmethod
    def input_of(block):
        """A tool_use block's input, kept as recorded when it is not an
        object (decode_input shapes it for watch)."""
        return block.get("input")

    def _answers(self, i, message, pending, open_calls, found):
        """Give each call answered in this user message its output, its
        status and its result block."""
        answered = set()
        items = blocks(message)
        skip = set()
        for pos, (j, block) in enumerate(items):
            if j in skip:
                continue
            kind = block.get("type")
            if kind == "tool_result":
                cid = block.get("tool_use_id")
                made = pending.pop(cid, None) if isinstance(cid, str) else None
                if not made:
                    continue
                for call in made:
                    answered.add(id(call))
                self.result_of(i, j, block, made, found)
                continue
            text = block.get("text") if kind == "text" else None
            if not isinstance(text, str):
                continue
            name, body = result_body(text)
            tied = [(i, j)]
            if name is None:
                name = not_run_name(text)
                if name is None:
                    continue
                body = text
            elif body == "" and pos + 1 < len(items):
                nj, nblock = items[pos + 1]
                ntext = nblock.get("text") if nblock.get("type") == "text" else None
                if isinstance(ntext, str) and result_body(ntext)[0] is None \
                        and not_run_name(ntext) is None:
                    body = ntext
                    tied.append((i, nj))
                    skip.add(nj)
            made = self._next_open(open_calls, name, answered)
            if not made:
                continue
            for call in made:
                answered.add(id(call))
                if call.output is None:
                    call.output = body
                if self.declined_result(body, None, name):
                    call.status = DECLINED
            for key in tied:
                found.ties[key] = made[0]

    @staticmethod
    def _next_open(open_calls, name, answered):
        for cname, made in open_calls:
            if made and (cname == name or not name) \
                    and id(made[0]) not in answered:
                return made
        return None

    def result_of(self, i, j, block, made, found):
        """Fill in the calls of one tool_result block."""
        content = block.get("content")
        text = block_text(content)
        name = made[0].tool_name
        for call in made:
            call.output = self.body_of(text)
            if self.declined_result(text, block, name):
                call.status = DECLINED
        found.ties[(i, j)] = made[0]

    # -- secret_texts helpers -----------------------------------------------

    def message_texts(self, messages, paired):
        """SecretTexts for every message: the message without its content,
        then each content block, a result tied to its call."""
        for i, message in enumerate(messages):
            where = "message %d" % (i + 1)
            if not isinstance(message, dict) or "content" not in message:
                yield SecretText(message, where=where)
                continue
            yield SecretText({k: v for k, v in message.items()
                              if k != "content"}, where=where)
            content = message["content"]
            if not isinstance(content, list):
                yield SecretText(content, call=paired.ties.get((i, 0)),
                                 where=where)
                continue
            for j, block in enumerate(content):
                split = self._elements(i, j, block, paired)
                if split is None:
                    yield SecretText(block, call=paired.ties.get((i, j)),
                                     where=where)
                    continue
                for node, call in split:
                    yield SecretText(node, call=call, where=where)

    @staticmethod
    def _elements(i, j, block, paired):
        """A tool_result whose content's elements are tied to different
        calls, as [(node, call)]: the block without its content first.
        None for any other block."""
        if not isinstance(block, dict) or (i, j, 0) not in paired.ties:
            return None
        content = block.get("content")
        out = [({k: v for k, v in block.items() if k != "content"},
                paired.ties.get((i, j)))]
        for k, element in enumerate(content):
            out.append((element, paired.ties.get((i, j, k),
                                                 paired.ties.get((i, j)))))
        return out

    def ui_texts(self, items):
        for n, item in enumerate(items):
            yield SecretText(item, where="message %d" % (n + 1))

    def side_texts(self, store):
        """Every string of a side JSON store, one SecretText per element of
        a list (a UI log), else the whole document."""
        doc = self.load(store)
        if doc is None:
            return
        if isinstance(doc, list):
            for text in self.ui_texts(self.ui_of(store, doc)):
                yield text
        else:
            if self.first(store):
                self.count("unknown")
            yield SecretText(doc, where="file")
