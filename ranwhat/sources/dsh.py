"""DeepSeek Harness, "dsh" (npm @deepseek-ai/dsh, and the Electron app
@deepseek-ai/dsh-desktop).

dsh (github.com/deepseek-ai/deepseek-harness, TypeScript) keeps one
append-only log per session. The CLI, `dsh web`, `dsh tui` and the desktop
app share one store. Everything below was read from the source at tag
dsh-v0.2.1-rc.2 (commit 687f282): core/session/src/types.ts,
session-persistence-jsonl (format.ts, zstd.ts, README.md), session-format
(filename.ts), util/home-paths, bundle/base/cordis.patch.yml, shell/tool-bash,
interaction/user-approval/src/types.ts, and the repository's own fixtures
(snapshots/sdk/persistent-tools/session.v4.jsonl). No dsh install was
available to check it against.

Where: <DSH_HOME>/sessions, with DSH_HOME the environment variable when it
is set and not blank (a leading ~ is expanded), else ~/.dsh. The same on
Linux, macOS (/Users/<user>/.dsh) and Windows (%USERPROFILE%\\.dsh). A
profile or `--patch` layer can move the root; that is not read here, use
--path. The layout is
  sessions/<projectKey(cwd)>/<session id>/session[.vN].jsonl[.zstd]
with sessions that have no cwd under sessions/_no-cwd. The project folder
name is a lossy encoding of the cwd, so the cwd is read from the header.
Files directly in a project folder (an unsupported pre-release layout),
session.lock, and *.tmp files are not read.

The file: the default is `.jsonl.zstd`, a plain concatenation of
independent standard zstd frames (checksummed, no dictionary). Frame 1
holds the header line; each later frame holds one fsync'd batch of
newline-terminated rows. A crash can leave the last frame cut off; it is
skipped, the way dsh itself keeps only complete lines. With
compression "none" the file is plain `.jsonl`. Decompression needs
Python 3.14 or the zstd command (_zstd.py); without either the store is
counted unreadable, and says so.

Generations: a session folder can hold several (session.jsonl,
session.v3.jsonl.zstd, session.v4.jsonl.zstd), because a write-open
publishes a successor and leaves the old file as it was. Only the highest
is read for tool calls, or each call would count twice. The older ones are
role "side" stores: clean searches them for secrets, watch does not.

Forks: a session whose header has isSeeded true (parentSession set) starts
with a verbatim copy of the parent's events (buildForkSeed, core/session/src/
fork.ts), ended by a `session/end-seed` {inherited:true} row. Those rows are
the parent's, already counted under the parent's own session, so tool_calls
skips everything up to the last such marker (secret_texts still reads them,
the file holds them). Without the marker nothing is skipped.

Rows: line 1 is {"type":"session","version":V,"id","createdAt" (ms),
"cwd"?,"parentSession"?,"origin"?,...}. Every later row is an event
{"type","data":{...},"seq","time" (ms),...}. A row with no integer "seq"
is not an event (version 0 packs assistant chunks as such rows) and is
skipped. Unknown event types are skipped.
- tool/call: data {turn, step, callId, name, arguments}, with arguments
  the model's raw JSON string. The same in every version.
- tool/result: data {message, error?, meta?}. Version 4 has message =
  {role:"tool", toolCallId, content:[{type:"text",text}], isError}.
  Versions 0 to 3 have message = {role:"user", content:[{type:
  "tool-result", toolCallId, content:[...], isError}]}. Both are read;
  sourceEventSeqs (the call's seq) pairs a result whose id is missing.
- approval/asked {id, toolName, callId?} and approval/decided {id,
  outcome}, outcome one of allowed-once, rejected, cancelled,
  unavailable. A call whose approval ended in anything but allowed-once
  did not run: "declined".
- run_code (PTC) makes calls inside a call. They are not tool/call rows:
  tool/ptc-dispatch (versions 3 and 4) and tool/code-dispatch (0 to 2) hold
  {rootCallId, parentCallId, subCallId, name, arguments (an object), ...},
  and a "-start" record comes first. Each is a call, once per subCallId.

Tools: "bash" and "pwsh" {description, command, timeoutMs?, workdir?,
run_in_background?, ...} are shell calls; read and read_image are reads,
write and edit {file_path, ...} are writes, all keyed by file_path. The
shell result is text: stdout, "[stderr]" and more, then "[exit code: N]"
when N is not 0 (the structured exit code is not stored). The directory
the command ran in is the result's meta.cwd; it is the call's workdir, else
the call's own workdir argument, else the session's cwd (the header's, or
the last working-directory/change).

Format versions: 4 is current (SESSION_FORMAT_VERSION; written since
v0.1.7-alpha.1). 3, 2 and 0 are read as written (v1 was never released and
is the same layout as 0). The README in session-persistence-jsonl still
says v3 is current in two places; the code and docs/session-format-status.md
say 4.

Not verified, so handled defensively: the "arguments" of a tool/call that
is not a JSON string is used as it is; an error in general is not a
refusal, only the codes ABORTED_BEFORE_DISPATCH, TOOL_NOT_STARTED and
UNKNOWN_TOOL in a tool/result's data.error.code (the call never ran) are
"declined", as is a call whose approval/decided outcome says so (a run_code
sub-call is paired by its subCallId); the content of a PTC result is read as text when it is a string or
a list of text blocks. Not read: a torn last frame, rows of unknown types,
the assistant/message streams (they repeat the tool-call blocks),
/slash command rows (command/run), anything outside sessions/.
"""

from __future__ import annotations

import json
import ntpath
import os
import posixpath
import re

from . import _lines, _paths, _stamps, _zstd, base
from .base import SecretText, Source, ToolCall

ENV = "DSH_HOME"
ROOT = ".dsh"
SESSIONS = "sessions"

GENERATION = re.compile(r"session(?:\.v([1-9][0-9]*))?\.jsonl(\.zstd)?\Z")

SHELLS = ("bash", "pwsh")
READS = ("read", "read_image")
WRITES = ("write", "edit")

# Where a read or write names its file. dsh's own is file_path; the rest are
# watch's keys, as the other adapters take them.
PATH_KEYS = ("file_path", "path", "notebook_path", "filePath", "file",
             "filename", "paths")

CALL = "tool/call"
RESULT = "tool/result"
PTC_START = ("tool/ptc-dispatch-start", "tool/code-dispatch-start")
PTC_DONE = ("tool/ptc-dispatch", "tool/code-dispatch")
ASKED = "approval/asked"
DECIDED = "approval/decided"
CWD_CHANGE = "working-directory/change"

# ApprovalOutcome values after which the call did not run.
DECLINED = "declined"
NOT_RUN = ("rejected", "cancelled", "unavailable")
# tool/result error codes (core/tools/src/index.ts, core/session/src/repair.ts)
# of a call whose body never ran: the turn was cancelled before dispatch, a
# crash or fork closer found it never started, or the tool does not exist.
# TOOL_OUTCOME_UNKNOWN and ABORTED are left alone: the tool may have run.
NEVER_RAN = ("ABORTED_BEFORE_DISPATCH", "TOOL_NOT_STARTED", "UNKNOWN_TOOL")
END_SEED = "session/end-seed"

VERSIONS = (0, 1, 2, 3, 4)

# Largest compressed file read into memory, largest decompressed text taken
# from one file, and the longest line parsed. A real session is far smaller;
# more is a corrupt or hostile file.
MAX_COMPRESSED = 512 << 20
MAX_PLAIN = _zstd.MAX_OUTPUT
MAX_LINE = 32 << 20
# Frames are handed to the decoder together, up to this many bytes, so a
# session of thousands of appends does not start a process for each.
GROUP = 16 << 20
HEAD = 1 << 16

NOT_ZSTD = "compressed, and not valid zstd data"
TOO_BIG = "larger than ranwhat reads"

_MAGIC = 0xFD2FB528
_SKIPPABLE = 0x184D2A50

_BAD = object()                 # a line that is not JSON


def _string(value):
    return value if isinstance(value, str) and value else None


def _expand(value, home, platform):
    win = _paths.platform_name(platform) == "win32"
    if value == "~":
        return home
    if value.startswith("~/") or (win and value.startswith("~\\")):
        return _paths.join(platform, home, value[2:])
    return value


# -- zstd frames --------------------------------------------------------------

def scan_frames(data):
    """(frames, torn, error) for zstd `data`: [(start, end)] of every complete
    frame in order, the offset where a cut-off last frame begins (or None),
    and a message when the bytes stop being zstd (or None). Nothing is
    decompressed. A port of scanZstdFrames (zstd.ts): magic, frame header
    descriptor, 3-byte block headers, the optional 4-byte checksum."""
    frames, pos, n = [], 0, len(data)
    while pos < n:
        start = pos
        if n - pos < 4:
            return frames, start, None
        magic = int.from_bytes(data[pos:pos + 4], "little")
        pos += 4
        if magic & 0xFFFFFFF0 == _SKIPPABLE:
            if n - pos < 4:
                return frames, start, None
            size = int.from_bytes(data[pos:pos + 4], "little")
            pos += 4 + size
            if pos > n:
                return frames, start, None
            frames.append((start, pos))
            continue
        if magic != _MAGIC:
            return frames, None, "not a zstd frame at byte %d" % start
        if pos >= n:
            return frames, start, None
        desc = data[pos]
        pos += 1
        if desc & 0x08:
            return frames, None, "reserved bit set in the frame at byte %d" % start
        single = bool(desc & 0x20)
        fcs = (0, 2, 4, 8)[desc >> 6]
        if fcs == 0 and single:
            fcs = 1
        dict_id = (0, 1, 2, 4)[desc & 3]
        pos += (0 if single else 1) + dict_id + fcs
        if pos > n:
            return frames, start, None
        while True:
            if n - pos < 3:
                return frames, start, None
            head = data[pos] | data[pos + 1] << 8 | data[pos + 2] << 16
            pos += 3
            last, kind, size = head & 1, (head >> 1) & 3, head >> 3
            if kind == 3:
                return frames, None, "reserved block type at byte %d" % (pos - 3)
            pos += 1 if kind == 1 else size
            if pos > n:
                return frames, start, None
            if last:
                break
        if desc & 0x04:
            pos += 4
            if pos > n:
                return frames, start, None
        frames.append((start, pos))
    return frames, None, None


def _groups(frames, limit=GROUP):
    """[(start, end)] runs of consecutive frames, each about `limit` bytes
    at most (a bigger single frame is its own group)."""
    out = []
    for start, end in frames:
        if out and end - out[-1][0] <= limit:
            out[-1] = (out[-1][0], end)
        else:
            out.append((start, end))
    return out


# -- file names ----------------------------------------------------------------

def generation(name):
    """(version, compressed) for a canonical log file name, else None."""
    m = GENERATION.match(name)
    if not m:
        return None
    return (int(m.group(1)) if m.group(1) else 0), bool(m.group(2))


def _entries(folder):
    try:
        return list(os.scandir(folder))
    except OSError:
        return []


def _dirs(folder):
    out = []
    for entry in _entries(folder):
        if entry.name.startswith("."):
            continue
        try:
            if entry.is_dir():
                out.append(entry.path)
        except OSError:
            continue
    return out


def _logs(folder):
    """[(version, mtime, compressed, path)] of the canonical logs in a
    session folder, not by name alone: a directory called session.jsonl is
    not one."""
    out = []
    for entry in _entries(folder):
        gen = generation(entry.name)
        if gen is None:
            continue
        try:
            if not entry.is_file():
                continue
            mtime = entry.stat().st_mtime
        except OSError:
            continue
        out.append((gen[0], mtime, gen[1], entry.path))
    return out


def _first_line(path, compressed):
    """The header object on the first line of a log, or None. For a
    compressed log: the first frame, when it is complete and there is a
    decoder."""
    try:
        with open(path, "rb") as fh:
            raw = fh.read(HEAD) if compressed else fh.readline(HEAD)
    except OSError:
        return None
    if compressed:
        frames, _torn, _err = scan_frames(raw)
        if not frames or not _zstd.available():
            return None
        raw = _zstd.decompress(raw[:frames[0][1]], limit=HEAD * 16)
        if raw is None:
            return None
        raw = raw.split(b"\n", 1)[0]
    try:
        obj = json.loads(_lines.decode_line(raw, first=True))
    except (ValueError, RecursionError):
        return None
    if isinstance(obj, dict) and obj.get("type") == "session":
        return obj
    return None


def output_text(content):
    """The text of a result's content: the text blocks joined by newlines,
    or a string as it is. None when there is none."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        texts = [b.get("text") for b in content
                 if isinstance(b, dict) and b.get("type") == "text"
                 and isinstance(b.get("text"), str)]
        if texts:
            return "\n".join(texts)
    return None


def _is_abs(path):
    return (path.startswith(("/", "\\", "~"))
            or bool(re.match(r"[A-Za-z]:[\\/]", path)))


def _resolve(workdir, cwd):
    """`workdir` against the session's cwd when it is relative."""
    if _is_abs(workdir) or not cwd:
        return workdir
    mod = ntpath if ("\\" in cwd or re.match(r"[A-Za-z]:", cwd)) else posixpath
    return mod.normpath(mod.join(cwd, workdir))


def _paths_in(arguments):
    paths, keys = [], []
    for key in PATH_KEYS:
        value = arguments.get(key)
        found = [v for v in (value if isinstance(value, (list, tuple))
                             else [value]) if isinstance(v, str) and v]
        if found:
            paths.extend(found)
            keys.append(key)
    return tuple(paths), tuple(keys)


def _classify(name, arguments):
    """(kind, known, command, paths, consumed) for dsh's tool `name`."""
    if name in SHELLS:
        command = _string(arguments.get("command"))
        return "shell", True, command, (), ("command",) if command else ()
    if name in READS:
        paths, keys = _paths_in(arguments)
        return "read", True, None, paths, keys
    if name in WRITES:
        paths, _keys = _paths_in(arguments)
        return "write", True, None, paths, ()
    return "other", False, None, (), ()


def _results_of(data):
    """[(call id, output)] a tool/result row answers. Version 4 puts the id
    on the message; earlier versions wrap one or more tool-result blocks in
    a user message."""
    message = data.get("message")
    if not isinstance(message, dict):
        return []
    cid = message.get("toolCallId")
    if isinstance(cid, str) and cid:
        return [(cid, output_text(message.get("content")))]
    out = []
    content = message.get("content")
    if isinstance(content, list):
        for block in content:
            if (isinstance(block, dict) and block.get("type") == "tool-result"
                    and isinstance(block.get("toolCallId"), str)):
                out.append((block["toolCallId"],
                            output_text(block.get("content"))))
    return out


def _never_ran(data):
    """True when a tool/result (or PTC dispatch) row carries one of the
    error codes of a call that did not run."""
    for holder in (data, data.get("message")):
        err = holder.get("error") if isinstance(holder, dict) else None
        if isinstance(err, dict) and err.get("code") in NEVER_RAN:
            return True
    return False


def _seqs(value):
    """The sequence numbers in a sourceEventSeqs value: numbers and
    inclusive [start, end] pairs (runs of three or more), capped."""
    out = []
    if not isinstance(value, list):
        return out
    for item in value:
        if isinstance(item, int) and not isinstance(item, bool):
            out.append(item)
        elif (isinstance(item, list) and len(item) == 2
              and all(isinstance(i, int) and not isinstance(i, bool)
                      for i in item)):
            out.extend(range(item[0], min(item[1], item[0] + 1024) + 1))
        if len(out) > 4096:
            break
    return out


class DshSource(Source):
    id = "dsh"
    name = "DeepSeek Harness"
    unit = "session"
    env = (ENV,)
    path_means = "a dsh sessions folder (what $DSH_HOME/sessions means)"
    checked = "0.2.1-rc.2"
    mask_note = ("If dsh is open on this session, close it first: it "
                 "appends to the file it has open.")

    def reset(self):
        Source.reset(self)
        self._bad = set()
        self._tallied = set()
        self._calls_tallied = set()

    # -- where to look ------------------------------------------------------

    def default_paths(self, env, home, platform):
        """$DSH_HOME/sessions when DSH_HOME is set and not blank, else
        ~/.dsh/sessions, on every system."""
        moved = env.get(ENV)
        moved = moved.strip() if isinstance(moved, str) else ""
        if moved:
            return [(_paths.join(platform, _expand(moved, home, platform),
                                 SESSIONS), "env " + ENV)]
        return [(_paths.join(platform, home, ROOT, SESSIONS), "default")]

    def stores(self, locations, since_days=None):
        found, seen = [], set()
        for loc in locations:
            root = loc.path
            inner = os.path.join(root, SESSIONS)
            if os.path.basename(root) != SESSIONS and os.path.isdir(inner):
                root = inner                    # --path ~/.dsh
            for project in _dirs(root):
                for folder in _dirs(project):
                    found.extend(self._session(folder, seen))
        return base.newest_first(found, since_days)

    def _session(self, folder, seen):
        logs = _logs(folder)
        if not logs:
            return []
        logs.sort(key=lambda x: (x[0], x[1]), reverse=True)
        out = []
        session = header = None
        for index, (_version, _mtime, compressed, path) in enumerate(logs):
            key = os.path.normcase(os.path.abspath(path))
            if key in seen:
                continue
            seen.add(key)
            if index == 0:
                header = _first_line(path, compressed) or {}
                session = (_string(header.get("id"))
                           or os.path.basename(folder))
            store = self.store(
                path, "jsonl.zst" if compressed else "jsonl",
                role="transcript" if index == 0 else "side",
                session=session, project=_string(header.get("cwd")))
            if store is not None:
                out.append(store)
        return out

    # -- reading ------------------------------------------------------------

    def _bad_store(self, store, reason, quiet=False):
        if store.path not in self._bad:
            self._bad.add(store.path)
            self.unreadable_store(reason, store.path)
        if not quiet:
            self.warn(store.path, "could not read dsh %s %s (%s)"
                      % (store.unit, store.path, reason))

    @staticmethod
    def _first(store, tallied):
        first = store.path not in tallied
        tallied.add(store.path)
        return first

    def _raw_lines(self, store, tally):
        """Yield the raw bytes of each line of the log, newline kept. A
        line over MAX_LINE is skipped and counted. A compressed log is
        decoded frame group by frame group; a cut-off last frame is left
        out. A store that cannot be read is counted and yields nothing."""
        if store.format == "jsonl.zst":
            chunks = self._decoded(store, tally)
        else:
            chunks = self._plain(store)
        carry = b""
        for chunk in chunks:
            data = carry + chunk
            parts = data.split(b"\n")
            carry = parts.pop()
            for part in parts:
                if len(part) > MAX_LINE:
                    if tally:
                        self.count("unparsed")
                    continue
                yield part + b"\n"
            if len(carry) > MAX_LINE:
                carry = b""
                if tally:
                    self.count("unparsed")
        if carry and len(carry) <= MAX_LINE:
            yield carry                     # no newline: still being written

    def _plain(self, store):
        try:
            with open(store.path, "rb") as fh:
                while True:
                    chunk = fh.read(1 << 20)
                    if not chunk:
                        return
                    yield chunk
        except OSError as e:
            self._bad_store(store, e.strerror or str(e))

    def _decoded(self, store, tally):
        try:
            size = os.path.getsize(store.path)
            if size > MAX_COMPRESSED:
                self._bad_store(store, TOO_BIG)
                return
            if not _zstd.available():
                self._bad_store(store, "compressed, " + _zstd.NEEDS)
                return
            with open(store.path, "rb") as fh:
                data = fh.read()
        except OSError as e:
            self._bad_store(store, e.strerror or str(e))
            return
        frames, _torn, error = scan_frames(data)
        if error is not None and not frames:
            self._bad_store(store, NOT_ZSTD)
            return
        if error is not None and tally:
            self.count("unparsed")
        total = 0
        for start, end in _groups(frames):
            plain = _zstd.decompress(data[start:end], MAX_PLAIN - total)
            pieces = [plain]
            if plain is None:
                pieces = []
                for one in (f for f in frames if start <= f[0] < end):
                    part = _zstd.decompress(data[one[0]:one[1]],
                                            MAX_PLAIN - total)
                    if part is None:
                        if tally:
                            self.count("unparsed")
                    else:
                        pieces.append(part)
            for piece in pieces:
                total += len(piece)
                if total > MAX_PLAIN:
                    self._bad_store(store, TOO_BIG)
                    return
                yield piece

    def _records(self, store, tallied):
        """(line_no, obj, text) for every line with something on it; obj is
        _BAD for a line that is not JSON (counted when complete)."""
        tally = self._first(store, tallied)
        parsed = bad = 0
        line_no = 0
        try:
            for raw in self._raw_lines(store, tally):
                line_no += 1
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
                if tally and self._unknown(obj, line_no):
                    self.count("unknown")
                yield line_no, obj, text
        finally:
            if tally:
                self.count("unparsed", bad)
        if bad and not parsed:
            self._bad_store(store, "not JSON Lines")

    @staticmethod
    def _unknown(obj, line_no):
        if not isinstance(obj, dict) or not isinstance(obj.get("type"), str):
            return True
        if obj["type"] == "session" and line_no == 1:
            return obj.get("version") not in VERSIONS
        return False

    @staticmethod
    def _event(obj):
        """The data of an event row, or None (the header, a packed v0 chunk
        row with no seq, an unknown shape)."""
        if (not isinstance(obj, dict) or obj.get("type") == "session"
                or not isinstance(obj.get("seq"), int)
                or isinstance(obj.get("seq"), bool)
                or not isinstance(obj.get("type"), str)):
            return None
        data = obj.get("data")
        return data if isinstance(data, dict) else None

    def _base(self, store, obj, header, cwd):
        stamp = _stamps.iso_utc(obj.get("time"), "ms")
        return dict(
            session=_string(header.get("id")) or store.session,
            project=cwd or _string(header.get("cwd")) or store.project,
            timestamp=stamp,
            not_after=None if stamp else _stamps.iso_utc(store.mtime, "s"))

    def _call(self, store, obj, data, header, cwd):
        name = _string(data.get("name")) or ""
        arguments = base.decode_input(data.get("arguments"))
        kind, known, command, paths, consumed = _classify(name, arguments)
        workdir = None
        if kind == "shell":
            workdir = _string(arguments.get("workdir"))
        return ToolCall(
            self.id, store.path, name, arguments, kind=kind, known=known,
            tool_call_id=_string(data.get("callId")), command=command,
            workdir=workdir and _resolve(workdir, cwd), paths=paths,
            consumed=consumed, **self._base(store, obj, header, cwd))

    def _ptc(self, store, obj, data, header, cwd):
        name = _string(data.get("name")) or ""
        arguments = base.decode_input(data.get("arguments"))
        kind, known, command, paths, consumed = _classify(name, arguments)
        content = data.get("content")
        return ToolCall(
            self.id, store.path, name, arguments, kind=kind, known=known,
            tool_call_id=_string(data.get("subCallId")), command=command,
            paths=paths, consumed=consumed,
            output=output_text(content) if content is not None else None,
            **self._base(store, obj, header, cwd))

    def _seed_end(self, store):
        """The line number of the last session/end-seed row with inherited
        true (0 when there is none): everything up to it is copied from the
        parent. One more pass over the file, no counting."""
        end = 0
        for line_no, obj, _text in self._records(store, self._calls_tallied):
            if (isinstance(obj, dict) and obj.get("type") == END_SEED
                    and isinstance(obj.get("data"), dict)
                    and obj["data"].get("inherited") is True):
                end = line_no
        return end

    def tool_calls(self, store):
        """Every call once, with its result's text as output: a call is
        yielded when its result arrives, and those still waiting at the end
        of the file after it. Calls made inside run_code are yielded when
        their dispatch settles. Only the newest generation of a session is
        read (role "transcript")."""
        if store.role != "transcript":
            return
        header = {}
        cwd = None
        pending, done, seqs = {}, set(), {}
        asked, refused = {}, set()
        ptc_open, ptc_done = {}, set()
        seed_end = 0
        for line_no, obj, _text in self._records(store, self._calls_tallied):
            if obj is _BAD:
                continue
            if isinstance(obj, dict) and obj.get("type") == "session":
                if not header:
                    header = obj
                    cwd = _string(obj.get("cwd"))
                    if obj.get("isSeeded") is True:
                        seed_end = self._seed_end(store)
                continue
            data = self._event(obj)
            if data is None:
                continue
            kind = obj["type"]
            if line_no <= seed_end:
                # The parent's events, copied in; its calls are its own.
                if kind == CWD_CHANGE:
                    cwd = _string(data.get("cwd")) or cwd
                continue
            if kind == CWD_CHANGE:
                cwd = _string(data.get("cwd")) or cwd
            elif kind == ASKED:
                if _string(data.get("id")) and _string(data.get("callId")):
                    asked[data["id"]] = data["callId"]
            elif kind == DECIDED:
                cid = asked.get(data.get("id")) if isinstance(
                    data.get("id"), str) else None
                if cid and data.get("outcome") in NOT_RUN:
                    refused.add(cid)
            elif kind == CALL:
                call = self._call(store, obj, data, header, cwd)
                cid = call.tool_call_id
                if cid is None:
                    yield call
                    continue
                # An id can be reused once its call is answered (dsh falls
                # back to call-<index> per response).
                done.discard(cid)
                old = pending.get(cid)
                if old is not None and (old.tool_name, old.tool_input) == (
                        call.tool_name, call.tool_input):
                    continue            # the same call written twice
                if old is not None:
                    yield old           # a different call took the id
                pending[cid] = call
                seqs[obj["seq"]] = cid
            elif kind == RESULT:
                answered = _results_of(data)
                if not answered:
                    for seq in _seqs(obj.get("sourceEventSeqs")):
                        if seq in seqs:
                            answered.append((seqs[seq], output_text(
                                (data.get("message") or {}).get("content"))
                                if isinstance(data.get("message"), dict)
                                else None))
                meta = data.get("meta")
                ran_in = _string(meta.get("cwd")) if isinstance(
                    meta, dict) else None
                for cid, output in answered:
                    call = pending.pop(cid, None)
                    if call is None:
                        continue
                    call.output = output
                    if call.kind == "shell" and ran_in:
                        call.workdir = ran_in
                    if cid in refused or _never_ran(data):
                        call.status = DECLINED
                    done.add(cid)
                    yield call
            elif kind in PTC_START:
                sub = _string(data.get("subCallId"))
                if sub and sub not in ptc_done and sub not in ptc_open:
                    ptc_open[sub] = self._ptc(store, obj, data, header, cwd)
            elif kind in PTC_DONE:
                sub = _string(data.get("subCallId"))
                if sub is not None:
                    if sub in ptc_done:
                        continue
                    ptc_done.add(sub)
                    ptc_open.pop(sub, None)
                made = self._ptc(store, obj, data, header, cwd)
                if (sub in refused) or _never_ran(data):
                    made.status = DECLINED
                yield made
        for cid, call in pending.items():
            if cid in refused:
                call.status = DECLINED
            yield call
        for sub, call in ptc_open.items():
            if sub in refused:
                call.status = DECLINED
            yield call

    def secret_texts(self, store):
        """Every row of the log, newest generation or not. A tool/result row
        is tied to the call it answers; a line that is not JSON is handed
        over as text."""
        calls = {}
        header = {}
        for line_no, obj, text in self._records(store, self._tallied):
            where = "line %d" % line_no
            if obj is _BAD:
                yield SecretText(text, where=where)
                continue
            if (not header and isinstance(obj, dict)
                    and obj.get("type") == "session"):
                header = obj
            data = self._event(obj)
            call = None
            if data is not None and obj["type"] == CALL:
                made = self._call(store, obj, data, header, None)
                if made.tool_call_id and made.tool_call_id not in calls:
                    calls[made.tool_call_id] = made
            elif data is not None and obj["type"] == RESULT:
                ids = [cid for cid, _o in _results_of(data)]
                call = calls.get(ids[0]) if len(ids) == 1 else None
            yield SecretText(obj, call=call, where=where)
