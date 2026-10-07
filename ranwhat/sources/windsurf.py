"""Windsurf (Cascade, in Windsurf and Devin Desktop, its renamed successor).

Windsurf keeps its Cascade conversations in ~/.codeium/windsurf/cascade/
<cascade_id>.pb (Insiders and Next builds under windsurf-insiders and
windsurf-next), and those files are encrypted (AES-256-GCM around a
protobuf). ranwhat does not decrypt them: the standard library has no
AES-GCM, and the key is a vendor secret others pulled out of the language
server with a debugger. notes() says how many there are, and how to have
Windsurf write a copy ranwhat can read; nothing else in that folder is
opened.

That copy is what this adapter reads. Windsurf's hook
post_cascade_response_with_transcript (docs.windsurf.com/windsurf/cascade/
hooks.md, now docs.devin.ai/desktop/cascade/hooks, as of 2026-10-07), once
any hook is configured for it, writes after every Cascade response the
whole conversation so far, from its beginning, to
~/.windsurf/transcripts/{trajectory_id}.jsonl, with 0600 permissions, and
keeps at most 100 such files, pruning the oldest by mtime. The file name is
the conversation's trajectory id. The docs give no other location and no
variable to move it.

Each line is one step of the conversation: {"type": T, "status": "done" or
"error", T: {...}}, compact, keys sorted and <, > and & escaped as \\u003c
and so on, as Go's encoding/json writes them. The docs say the exact shape
"may change". Step types, from the docs' example and the one real
transcript published (git-ai-project/git-ai @ 0670e7e, tests/fixtures/
windsurf-session-simple.jsonl):

- user_input {user_response, rules_applied?} and planner_response
  {response}: no call;
- run_command {command, cwd, exit_code, output?, user_rejected}: a shell
  command; user_rejected true means the user refused it, so it never ran
  ("declined"); output is absent when the command printed nothing;
- view_file {path, content, start_line, end_line}: a read; path is a
  file:// URI in the real transcript;
- code_action {path, new_content, original_content, acknowledgement_type}:
  a write; path a plain path in the docs' example, a file:// URI in the
  real transcript;
- find {pattern, search_directory, output, total_results}, grep_search
  {query, search_path, total_results}, list_directory {path} and
  list_resources {server_name} (MCP): known, kind "other".

Any other type is counted as unknown and still handed to watch, judged by
its name and every string in it. Steps carry no timestamp, model, call id
or session id, so a call's not_after is the file's mtime and its session
the file name. A step is written once per file, so nothing is deduplicated.
A command's working directory is its own cwd; for the other calls the
project is the cwd of the last command before them, when there was one.

A file:// path is read as the local path it names (percent-escapes
decoded, a Windows drive's leading "/" dropped), and the call's input
holds that path in its place, so watch judges, and clean credits, the
file Cascade opened, not a URL. secret_texts hands over the line as
recorded.

Not read: the encrypted .pb files (only counted, in notes()), the editor's
state.vscdb (titles only), Devin Local's sessions.db, and anything holding
a login (Windsurf's auth in the editor's secret storage, hooks.json).
"""

from __future__ import annotations

import json
import os
import re

from urllib.parse import unquote

from . import _lines, _paths, _stamps, base
from .base import SecretText, Source, ToolCall

ROOT = (".windsurf", "transcripts")
SUFFIX = ".jsonl"

# Where Windsurf keeps its encrypted Cascade conversations, under the home
# directory on every system, one folder per release channel.
CASCADE = (".codeium",)
CHANNELS = ("windsurf", "windsurf-next", "windsurf-insiders")
CASCADE_DIR = "cascade"
ENCRYPTED = ".pb"

HOOK = "post_cascade_response_with_transcript"

SHELL = "run_command"
READ = "view_file"
WRITE = "code_action"
OTHERS = ("find", "grep_search", "list_directory", "list_resources")
SAID = ("user_input", "planner_response")       # no call
TYPES = (SHELL, READ, WRITE) + OTHERS + SAID

# The key of each step type that holds what the call returned, not what it
# was asked: handed over as the call's output and left out of its input,
# so watch does not judge a file's content or a command's output as the
# call. code_action's original_content is the file before the write, not
# part of it either; it is handed to clean, and left out of the input.
OUTPUT = {SHELL: "output", READ: "content", "find": "output"}
NOT_INPUT = {WRITE: ("original_content",)}

DECLINED = "declined"

_BAD = object()         # a line that is not JSON
_DRIVE = re.compile(r"/[A-Za-z]:[/\\]")


def _string(value):
    return value if isinstance(value, str) and value else None


def local_path(value):
    """The local path a recorded path names: a file:// URI made a path
    (file:///x/y and file://localhost/x/y; percent-escapes decoded; a
    Windows drive's leading "/" dropped; file://host/share/x, a Windows
    network share or \\\\wsl.localhost, as the UNC path //host/share/x),
    anything else as it is. None for an empty value."""
    value = _string(value)
    if value is None or not value.lower().startswith("file://"):
        return value
    rest = value[len("file://"):]
    if rest.lower().startswith("localhost/"):
        rest = rest[len("localhost"):]
    if not rest.startswith("/"):
        host, sep, tail = rest.partition("/")
        path = unquote(sep + tail)
        return "//" + unquote(host) + path if host and path else None
    path = unquote(rest)
    if _DRIVE.match(path):
        path = path[1:]
    return path or None


def session_from_name(path):
    """The trajectory id: the file name without .jsonl."""
    stem = os.path.basename(path)
    return stem[:-len(SUFFIX)] if stem.endswith(SUFFIX) else stem


def _files(folder):
    """Transcripts directly in `folder` (*.jsonl regular files, not
    dot-files)."""
    try:
        entries = list(os.scandir(folder))
    except OSError:
        return []
    out = []
    for entry in entries:
        if entry.name.startswith(".") or not entry.name.endswith(SUFFIX):
            continue
        try:
            if entry.is_file():
                out.append(entry.path)
        except OSError:
            continue
    return out


def _count_encrypted(folder):
    """How many *.pb files are directly in `folder`; 0 when it cannot be
    listed. Only names are read."""
    try:
        entries = list(os.scandir(folder))
    except OSError:
        return 0
    n = 0
    for entry in entries:
        if not entry.name.endswith(ENCRYPTED):
            continue
        try:
            if entry.is_file():
                n += 1
        except OSError:
            continue
    return n


class WindsurfSource(Source):
    id = "windsurf"
    name = "Windsurf"
    unit = "transcript"
    env = ()
    path_means = "a Windsurf transcripts folder (~/.windsurf/transcripts)"
    checked = ("the hooks docs as of 2026-10-07 and git-ai's sample "
               "transcript; neither names a Windsurf version")
    # Said after masking (design 3.7). Windsurf writes the whole transcript
    # again after each response, from its own encrypted copy.
    mask_note = ("Windsurf writes a conversation's whole transcript again "
                 "after each Cascade response, from its own encrypted copy, "
                 "which ranwhat does not change: if that conversation goes "
                 "on, the value comes back.")

    def reset(self):
        Source.reset(self)
        self._bad = set()       # stores already counted as unreadable
        self._tallied = set()   # stores whose skipped lines are counted

    # -- where to look ------------------------------------------------------

    def default_paths(self, env, home, platform):
        """~/.windsurf/transcripts, on every system (%USERPROFILE% on
        Windows). Windsurf has no variable that moves it."""
        return [(_paths.join(platform, home, *ROOT), "default")]

    @staticmethod
    def cascade_folders(home, platform=None):
        """Pure: the folders Windsurf keeps its encrypted Cascade
        conversations in, one per release channel."""
        return [_paths.join(platform, home, *(CASCADE + (c, CASCADE_DIR)))
                for c in CHANNELS]

    def notes(self, locations=None, platform=None):
        """Lines for `ranwhat sources` and the reports: how many Cascade
        conversations are kept encrypted and were not read, and how to have
        Windsurf write them where ranwhat reads them."""
        out = []
        read_any = any(getattr(loc, "found", 0) for loc in (locations or ()))
        for folder in self.cascade_folders(_paths.home(), platform):
            n = _count_encrypted(folder)
            if not n:
                continue
            said = ("1 Windsurf Cascade conversation in %s is" % folder
                    if n == 1 else
                    "%d Windsurf Cascade conversations in %s are" % (n, folder))
            them = "it" if n == 1 else "them"
            if read_any:
                out.append(
                    "%s kept encrypted, so ranwhat did not read %s there. "
                    "It read the plaintext transcripts Windsurf's %s hook "
                    "writes to ~/.windsurf/transcripts, which hold only "
                    "conversations had while the hook was on, the latest 100 "
                    "at most." % (said, them, HOOK))
            else:
                out.append(
                    "%s kept encrypted, so ranwhat did not read %s. Turning "
                    "on Windsurf's %s hook makes Windsurf write each "
                    "conversation as a plaintext transcript to "
                    "~/.windsurf/transcripts, which ranwhat reads."
                    % (said, them, HOOK))
        return out

    def stores(self, locations, since_days=None):
        found, seen = [], set()
        for loc in locations:
            path = loc.path
            if os.path.isdir(path):
                paths = _files(path)
            elif path.endswith(SUFFIX) and os.path.isfile(path):
                paths = [path]          # --path naming one transcript
            else:
                paths = []
            for path in paths:
                key = os.path.normcase(os.path.abspath(path))
                if key in seen:
                    continue
                seen.add(key)
                store = self.store(path, "jsonl", role="transcript",
                                   session=session_from_name(path))
                if store is not None:
                    found.append(store)
        return base.newest_first(found, since_days)

    # -- reading ------------------------------------------------------------

    def _bad_store(self, store, reason):
        if store.path not in self._bad:
            self._bad.add(store.path)
            self.unreadable_store(reason, store.path)
        self.warn(store.path, "could not read Windsurf %s %s (%s)"
                  % (store.unit, store.path, reason))

    @staticmethod
    def _first(store, tallied):
        """True the first time a store is read this run: watch and clean
        both read it, and what it skipped is counted once."""
        first = store.path not in tallied
        tallied.add(store.path)
        return first

    def _records(self, store):
        """(line_no, obj, text) for every line with something on it. obj is
        _BAD for a line that is not JSON (counted when it is complete; a
        last line with no newline is one still being written). A step of a
        type, or a shape, the format does not list is counted as unknown.
        A store that cannot be opened warns once and yields nothing; one
        with lines but none of them JSON warns once when it has been
        read."""
        tally = self._first(store, self._tallied)
        parsed = bad = 0
        try:
            with open(store.path, "rb") as fh:
                for line_no, raw in enumerate(fh, 1):
                    text = _lines.decode_line(raw, first=line_no == 1)
                    if not text.strip():
                        continue
                    try:
                        obj = json.loads(text)
                    except (ValueError, RecursionError):
                        if raw.endswith(b"\n"):
                            bad += 1
                        yield line_no, _BAD, text
                        continue
                    parsed += 1
                    if tally and self._unknown(obj):
                        self.count("unknown")
                    yield line_no, obj, text
        except OSError as e:
            self._bad_store(store, e.strerror or type(e).__name__)
            return
        finally:
            if tally:
                self.count("unparsed", bad)
        if bad and not parsed:
            self._bad_store(store, "not JSON Lines")

    @staticmethod
    def _unknown(obj):
        """True for a line that is not a step of a type the format lists
        with its payload an object."""
        if not isinstance(obj, dict):
            return True
        kind = obj.get("type")
        if kind not in TYPES:
            return True
        return not isinstance(obj.get(kind), dict)

    @staticmethod
    def _step(obj):
        """(type, payload) of a step that may be a call: a type that is not
        conversation (SAID) with an object under its own name; else
        None."""
        if not isinstance(obj, dict):
            return None
        kind = obj.get("type")
        if not isinstance(kind, str) or not kind or kind in SAID:
            return None
        payload = obj.get(kind)
        if not isinstance(payload, dict):
            return None
        return kind, payload

    def _call(self, store, line_no, kind, payload, project):
        """The ToolCall for one step, and the working directory it
        records (run_command's cwd), or None."""
        output = None
        out_key = OUTPUT.get(kind)
        drop = NOT_INPUT.get(kind, ()) + ((out_key,) if out_key else ())
        if out_key is not None and isinstance(payload.get(out_key), str):
            output = payload[out_key]
        tool_input = {k: v for k, v in payload.items() if k not in drop}
        fields = dict(session=store.session, project=project,
                      not_after=_stamps.iso_utc(store.mtime, "s"))
        cwd = None
        if kind == SHELL:
            command = _string(payload.get("command"))
            cwd = _string(payload.get("cwd"))
            if cwd:
                fields["project"] = cwd
            call = ToolCall(
                self.id, store.path, kind, tool_input, kind="shell",
                known=True, command=command, workdir=cwd,
                consumed=("command",) if command else (),
                status=DECLINED if payload.get("user_rejected") is True
                else None, output=output, **fields)
        elif kind in (READ, WRITE):
            path = local_path(payload.get("path"))
            paths = (path,) if path else ()
            if path and path != payload.get("path"):
                tool_input["path"] = path       # the file, not its URI
            call = ToolCall(
                self.id, store.path, kind, tool_input,
                kind="read" if kind == READ else "write", known=True,
                paths=paths,
                consumed=("path",) if paths and kind == READ else (),
                output=output, **fields)
        elif kind in OTHERS:
            call = ToolCall(self.id, store.path, kind, tool_input,
                            kind="other", known=True, output=output, **fields)
        else:
            call = ToolCall(self.id, store.path, kind, tool_input,
                            kind="other", known=False, **fields)
        return call, cwd

    def tool_calls(self, store):
        """Every call step in the transcript, in order, with its output
        when the step holds one. A command the user refused is
        "declined"."""
        if store.role != "transcript":
            return
        project = None
        for line_no, obj, _text in self._records(store):
            step = self._step(obj) if obj is not _BAD else None
            if step is None:
                continue
            call, cwd = self._call(store, line_no, step[0], step[1], project)
            if cwd:
                project = cwd
            yield call

    def secret_texts(self, store):
        """Every line of the file, whatever its type. A step's output
        (a command's output, a file's content, find's results) is handed
        over on its own and tied to its call; the rest of the line without
        it. What a code_action wrote, and what the file held before, are
        handed over as the content of the file it names. A line that is
        not JSON is handed over as text."""
        if store.role != "transcript":
            return
        project = None
        for line_no, obj, text in self._records(store):
            where = "line %d" % line_no
            if obj is _BAD:
                yield SecretText(text, where=where)
                continue
            step = self._step(obj)
            if step is None:
                yield SecretText(obj, where=where)
                continue
            kind, payload = step
            call, cwd = self._call(store, line_no, kind, payload, project)
            if cwd:
                project = cwd
            pulled = []
            out_key = OUTPUT.get(kind)
            if out_key in payload:
                pulled.append((out_key, dict(call=call)))
            if kind == WRITE and call.paths:
                for key in ("new_content", "original_content"):
                    if key in payload:
                        pulled.append((key, dict(attached=call.paths[0])))
            if not pulled:
                yield SecretText(obj, where=where)
                continue
            keys = set(k for k, _how in pulled)
            rest = dict(obj)
            rest[kind] = {k: v for k, v in payload.items() if k not in keys}
            yield SecretText(rest, where=where)
            for key, how in pulled:
                yield SecretText(payload[key], where=where, **how)
