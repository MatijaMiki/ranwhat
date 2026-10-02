"""The Meta Muse Code adapter (ranwhat/sources/muse_code.py, design 7.12).

Fixtures are built field for field from the spec's sample: every line an
envelope, a runtime.session.metadata record, and runtime.session "run"
events committing tool calls and their result batches. Fields the spec does
not list are left out. The key inside `bash` args is unverified, so calls
are built with "command" (the spec's sample), with "cmd", and with neither.

Two shapes come from beyond the spec. The retained frame is built key for
key from line 1 of a real Muse 1.4.0 capture (dardant/firstmate,
tests/captures/muse-1.4.0/session.jsonl): {retained_frame:
"session_permission_transaction", frame_schema_version: 1,
outer_log_ordinal, transaction_id, children: [{child_index, record_json}],
content_sha256}, with permission records inside. Subagent logs carry no
metadata record: a third party (stablyai/orca #22379) reports they record
no workspace, so the fixtures leave it out.

Everything runs in temp directories: the home directory, XDG_DATA_HOME and
clean's backup root all point there, and the real home is never read.
Every secret is synthetic, and token-shaped ones are written as adjacent
literals.

watch.judge and clean.scan_sources are wired in later. Until then, judge()
and findings() below follow design 3.5 and 3.6 to the letter, over
watch.evaluate and clean's own _walk and _origins.
"""
import builtins
import contextlib
import glob
import hashlib
import io
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

TESTS = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(TESTS)
sys.path.insert(0, REPO)

from ranwhat import clean, sources, watch  # noqa: E402
from ranwhat.sources import _paths, _rewrite, muse_code  # noqa: E402
from ranwhat.sources.base import MaskResult, ToolCall  # noqa: E402
from ranwhat.sources.muse_code import MuseCodeSource  # noqa: E402

ENV = "XDG_DATA_HOME"
WINDOWS = os.name == "nt"

SECRET = "sk_" "live_" "Zq8vR2mT6yLp4WcN0sXe7HbJ"
TYPED = "Hq3nV8xKp2" "Lw7RtY9mZc4BfD"           # an API_TOKEN typed by hand
SPEC_VALUE = "EXAMPLE_NOT_A_REAL_KEY"           # the spec sample's value

SID = "11111111-1111-4111-8111-111111111111"
RUN = "22222222-2222-4222-8222-222222222222"
MID = "33333333-3333-4333-8333-333333333333"
DAY = "2026/09/21"
T0 = 1790000000000000           # microseconds: 2026-09-21T14:13:20Z
MISSING = object()

# The spec's fixture, exactly as written there.
SPEC_LINES = [
    '{"schema_version":1,"id":"00000000-0000-4000-8000-000000000001","stream":{"kind":"session","id":"11111111-1111-4111-8111-111111111111"},"sequence":1,"recorded_at":1790000000000000,"record_type":"event","durability":"durable","causation_id":null,"payload_type":"runtime.session.metadata","payload_schema_version":1,"payload":{"kind":"metadata","record":{"build":{"semver":"1.4.2","sha":"0000000000"},"model_id":"meta/muse-glimmer-30b","provider_id":"meta","workspace_root":"/home/dev/app"}}}',
    '{"schema_version":1,"id":"00000000-0000-4000-8000-000000000002","stream":{"kind":"session","id":"11111111-1111-4111-8111-111111111111"},"sequence":2,"recorded_at":1790000000100000,"record_type":"event","durability":"durable","causation_id":null,"payload_type":"runtime.session","payload_schema_version":1,"payload":{"event":{"kind":"assistant_tool_calls_committed","message_id":"33333333-3333-4333-8333-333333333333","response_id":"resp_1","tool_calls":[{"args":"{\\"command\\":\\"cat .env\\"}","call_id":"call_1","id":"fc_call_1","name":"bash"}]},"kind":"run","run_id":"22222222-2222-4222-8222-222222222222"}}',
    '{"schema_version":1,"id":"00000000-0000-4000-8000-000000000003","stream":{"kind":"session","id":"11111111-1111-4111-8111-111111111111"},"sequence":3,"recorded_at":1790000000200000,"record_type":"event","durability":"durable","causation_id":null,"payload_type":"runtime.session","payload_schema_version":1,"payload":{"event":{"batch_id":"33333333-3333-4333-8333-333333333333","kind":"tool_result_batch_committed","results":[{"text":"API_KEY=EXAMPLE_NOT_A_REAL_KEY","tool_call_id":"call_1","tool_call_index":0}]},"kind":"run","run_id":"22222222-2222-4222-8222-222222222222"}}',
]


# --------------------------------------------------------------------------
# Fixture builders: the spec's envelope, compact like the sample
# --------------------------------------------------------------------------

def _dump(obj):
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False)


def envelope(seq, payload_type, payload, recorded_at=None, sid=SID):
    """One line: the envelope in the spec's key order. recorded_at defaults
    to T0 plus 0.1 s per sequence number; MISSING leaves it out."""
    line = {"schema_version": 1, "id": "00000000-0000-4000-8000-%012d" % seq,
            "stream": {"kind": "session", "id": sid}, "sequence": seq,
            "recorded_at": T0 + (seq - 1) * 100000 if recorded_at is None
            else recorded_at,
            "record_type": "event", "durability": "durable",
            "causation_id": None, "payload_type": payload_type,
            "payload_schema_version": 1, "payload": payload}
    if recorded_at is MISSING:
        del line["recorded_at"]
    return line


def metadata(seq=1, root="/home/dev/app", sid=SID, **kw):
    record = {"build": {"semver": "1.4.2", "sha": "0000000000"},
              "model_id": "meta/muse-glimmer-30b", "provider_id": "meta"}
    if root is not None:
        record["workspace_root"] = root
    return envelope(seq, "runtime.session.metadata",
                    {"kind": "metadata", "record": record}, sid=sid, **kw)


def run(seq, event, **kw):
    return envelope(seq, "runtime.session",
                    {"event": event, "kind": "run", "run_id": RUN}, **kw)


def tool_call(cid, name, args):
    """One tool_calls entry; args is a dict (stored as a compact JSON
    string, as the sample shows) or a string stored as it is."""
    text = args if isinstance(args, str) else _dump(args)
    return {"args": text, "call_id": cid, "id": "fc_" + cid, "name": name}


def committed(seq, calls, message_id=MID, **kw):
    return run(seq, {"kind": "assistant_tool_calls_committed",
                     "message_id": message_id, "response_id": "resp_1",
                     "tool_calls": calls}, **kw)


def results(seq, pairs, batch_id=MID, **kw):
    """A result batch: pairs of (call_id, text)."""
    return run(seq, {"batch_id": batch_id,
                     "kind": "tool_result_batch_committed",
                     "results": [{"text": text, "tool_call_id": cid,
                                  "tool_call_index": index}
                                 for index, (cid, text) in enumerate(pairs)]},
               **kw)


def call_lines(seq, cid, name, args, output=None, **kw):
    """The two lines the sample shows for one call: committed, then its
    result batch when output is given."""
    message_id = "44444444-0000-4000-8000-%012d" % seq
    lines = [committed(seq, [tool_call(cid, name, args)],
                       message_id=message_id, **kw)]
    if output is not None:
        lines.append(results(seq + 1, [(cid, output)], batch_id=message_id,
                             **kw))
    return lines


def user_intent(seq, text, **kw):
    return envelope(seq, "runtime.user_intent.accepted",
                    {"model_messages": [{"content": [{"kind": "text",
                                                      "text": text}]}]}, **kw)


def frame(ordinal, records):
    """A retained frame, key for key as the 1.4.0 capture's first line:
    each record a child, its record_json the record as compact JSON (a
    string is stored as it is)."""
    return {"retained_frame": "session_permission_transaction",
            "frame_schema_version": 1, "outer_log_ordinal": ordinal,
            "transaction_id": "55555555-0000-4000-8000-%012d" % ordinal,
            "children": [{"child_index": index,
                          "record_json": r if isinstance(r, str) else _dump(r)}
                         for index, r in enumerate(records)],
            "content_sha256": "sha256:" + "0" * 64}


def permission_format(seq, **kw):
    """The first record inside the capture's first frame."""
    return envelope(seq, "runtime.session.permission_format_declared",
                    {"format": "profile_v1", "schema_version": 1}, **kw)


def spec_sample():
    return [metadata(),
            committed(2, [tool_call("call_1", "bash", {"command": "cat .env"})]),
            results(3, [("call_1", "API_KEY=" + SPEC_VALUE)])]


# --------------------------------------------------------------------------
# watch and clean as design 3.5 and 3.6 describe them
# --------------------------------------------------------------------------

NEUTRAL = "ranwhat:%s"


def judge(call):
    """(hits, payload) for one ToolCall: watch.judge once it exists, else
    design 3.5's judge() over today's watch.evaluate."""
    real = getattr(watch, "judge", None)
    if real is not None:
        return real(call)
    if call.kind is None or not call.known:
        return watch.evaluate(call.tool_name, call.tool_input)
    rest = {k: v for k, v in call.tool_input.items() if k not in call.consumed}
    if call.kind == "shell" and call.command:
        judged = dict(rest, command=call.command)
        if call.workdir:
            judged["workdir"] = call.workdir
        return watch.evaluate("Bash", judged)
    if call.kind == "read" and call.paths:
        return watch.evaluate("Read", dict(rest, paths=list(call.paths)))
    return watch.evaluate(NEUTRAL % call.kind, call.tool_input)


def rules(call):
    return [(h["rule"], h["evidence"]) for h in judge(call)[0]]


def _named_by_input(call):
    """Design 3.6: the call's input with its consumed keys replaced by the
    normalised command (heredocs stripped) or the paths it read."""
    rest = {k: v for k, v in call.tool_input.items() if k not in call.consumed}
    if call.command:
        rest["command"] = watch._strip_heredocs(call.command)
    if call.kind == "read" and call.paths:
        rest["paths"] = list(call.paths)
    return clean._origins(json.dumps(rest, ensure_ascii=False))


def findings(source, stores):
    """{value: {"origins", "count", "stores", "where"}} for every secret in
    these stores, crediting origins the way design 3.6 says."""
    found = {}
    for store in stores:
        for text in source.secret_texts(store):
            origin = None
            if text.attached:
                origin = text.attached
            elif text.call is not None:
                named = _named_by_input(text.call)
                origin = named[-1] if named else None

            def collect(value, label, origin=origin, store=store, text=text):
                entry = found.setdefault(value, {"origins": set(), "count": 0,
                                                 "stores": set(), "where": []})
                entry["count"] += 1
                entry["stores"].add(store.path)
                entry["where"].append(text.where)
                if origin:
                    entry["origins"].add(origin)
            clean._walk(text.node, collect)
    return found


def _strings(node):
    """Every string value in a decoded JSON structure (keys aside). A string
    that is itself a JSON object or array (call args) stands for the
    strings inside it."""
    if isinstance(node, str):
        if node[:1] in ("{", "["):
            try:
                inner = json.loads(node)
            except ValueError:
                inner = None
            if isinstance(inner, (dict, list)):
                yield from _strings(inner)
                return
        yield node
    elif isinstance(node, list):
        for item in node:
            yield from _strings(item)
    elif isinstance(node, dict):
        for value in node.values():
            yield from _strings(value)


def _sha(path):
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def _marker(value):
    return clean.REDACTION % clean._fingerprint(value)


def _tempdir(case, prefix):
    """A temp directory removed when the test ends."""
    path = tempfile.mkdtemp(prefix=prefix)
    case.addCleanup(shutil.rmtree, path, True)
    return path


def _dead_pid():
    """The id of a process that has exited."""
    proc = subprocess.Popen([sys.executable, "-c", "pass"])
    proc.wait(timeout=20)
    return proc.pid


_REAL_PLATFORM = _paths.platform_name


def _as_linux(platform=None):
    """platform_name, with the running system taken for Linux, the one
    platform whose Muse Code folder is "default" rather than "probed"."""
    return "linux" if platform is None else _REAL_PLATFORM(platform)


def _sub_rel(sub):
    """"" for a session's own log; "subagent/a/subagent/b/" for "a/b"."""
    return "".join("subagent/%s/" % part for part in sub.split("/")) if sub else ""


# --------------------------------------------------------------------------
# Common setup
# --------------------------------------------------------------------------

class MuseCase(unittest.TestCase):

    def setUp(self):
        self.home = _tempdir(self, "muse-home-")
        patches = [mock.patch.dict(os.environ, {"HOME": self.home,
                                                "USERPROFILE": self.home}),
                   mock.patch.object(_paths, "home", return_value=self.home),
                   mock.patch.object(_paths, "platform_name",
                                     side_effect=_as_linux)]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        os.environ.pop(ENV, None)
        self.backups = os.path.join(_tempdir(self, "muse-bk-"), "b")
        p = mock.patch.object(clean, "BACKUP_ROOT", self.backups)
        p.start()
        self.addCleanup(p.stop)
        self.data = os.path.join(self.home, ".local", "share", "muse")
        self.muse = MuseCodeSource()

    def write(self, rel, lines, age=3600, root=None, mode=None, raw=None):
        """Write JSON lines (or raw bytes) at root/rel, aged `age` seconds."""
        path = os.path.join(root or self.data, *rel.split("/"))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        data = raw if raw is not None else "".join(
            _dump(line) + "\n" for line in lines).encode("utf-8")
        with open(path, "wb") as fh:
            fh.write(data)
        if mode is not None and not WINDOWS:
            os.chmod(path, mode)
        when = time.time() - age
        os.utime(path, (when, when))
        return path

    def session(self, lines, sid=SID, day=DAY, sub=None, **kw):
        """A session's log, or with `sub` a subagent's: "kid" is
        subagent/kid, "kid/grandkid" is subagent/kid/subagent/grandkid."""
        rel = "sessions/%s/%s/%s" % (day, sid, _sub_rel(sub)) + "session.jsonl"
        return self.write(rel, lines, **kw)

    def lock(self, sid=SID, day=DAY, sub=None, text=None):
        folder = os.path.join(self.data, "sessions", *day.split("/"))
        folder = os.path.join(folder, sid, *_sub_rel(sub).split("/"))
        os.makedirs(folder, exist_ok=True)
        path = os.path.join(folder, ".session.lock")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("pid=%d\n" % os.getpid() if text is None else text)
        return path

    def stores(self, override=None, since_days=None):
        return self.muse.stores(self.muse.locations(override=override),
                                since_days=since_days)

    def store(self, path):
        for store in self.stores():
            if store.path == path:
                return store
        self.fail("%s is not a store" % path)

    def calls(self, path):
        return list(self.muse.tool_calls(self.store(path)))

    def by_id(self, path):
        return {c.tool_call_id: c for c in self.calls(path)}


# --------------------------------------------------------------------------
# 1, 2, 3: where Muse Code keeps its history
# --------------------------------------------------------------------------

class DefaultPaths(unittest.TestCase):

    def test_each_platform(self):
        m = MuseCodeSource()
        self.assertEqual(m.default_paths({}, "/home/u", "linux"),
                         [("/home/u/.local/share/muse", "default")])
        # macOS is likely the same, and probed
        self.assertEqual(m.default_paths({}, "/Users/u", "darwin"),
                         [("/Users/u/.local/share/muse", "probed")])
        # Windows: the folder a third party found on a Windows host, probed
        self.assertEqual(m.default_paths({}, "C:\\Users\\u", "win32"),
                         [("C:\\Users\\u\\.local\\share\\muse", "probed")])
        # whether muse reads XDG_DATA_HOME on Windows is not known: both
        self.assertEqual(m.default_paths({ENV: "D:\\data"}, "C:\\Users\\u",
                                         "win32"),
                         [("D:\\data\\muse", "env XDG_DATA_HOME"),
                          ("C:\\Users\\u\\.local\\share\\muse", "probed")])
        self.assertEqual(m.default_paths({ENV: ""}, "C:\\Users\\u", "win32"),
                         [("C:\\Users\\u\\.local\\share\\muse", "probed")])

    def test_xdg_data_home(self):
        m = MuseCodeSource()
        how = "env XDG_DATA_HOME"
        self.assertEqual(m.default_paths({ENV: "/srv/data"}, "/home/u", "linux"),
                         [("/srv/data/muse", how)])
        self.assertEqual(m.default_paths({ENV: "/srv/data"}, "/Users/u", "darwin"),
                         [("/srv/data/muse", how)])
        # set but empty is not set
        self.assertEqual(m.default_paths({ENV: ""}, "/home/u", "linux"),
                         [("/home/u/.local/share/muse", "default")])

    def test_what_every_report_needs(self):
        m = MuseCodeSource()
        self.assertEqual((m.id, m.name, m.unit, m.env, m.checked),
                         ("muse-code", "Muse Code", "session",
                          ("XDG_DATA_HOME",), "1.4.2"))
        self.assertIn("sessions", m.path_means)
        self.assertNotIn("\u2014", m.path_means)
        # wired into the registry (ranwhat.sources.ADAPTERS)
        self.assertIn("muse-code", sources.ids())
        self.assertIsInstance(sources.get("muse-code"), MuseCodeSource)

    def test_path_keys_mirror_watch(self):
        self.assertEqual(muse_code.PATH_KEYS, watch._PATH_KEYS)

    def test_importing_it_imports_neither_watch_nor_clean(self):
        code = ("import sys; sys.path.insert(0, sys.argv[1]); "
                "import ranwhat.sources.muse_code; "
                "print('ranwhat.watch' in sys.modules, "
                "'ranwhat.clean' in sys.modules)")
        proc = subprocess.run([sys.executable, "-c", code, REPO],
                              capture_output=True, text=True, timeout=20)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stdout.split(), ["False", "False"])


class Discovery(MuseCase):

    def test_xdg_data_home_is_read_at_call_time(self):
        first = self.muse.locations()
        self.assertEqual([(l.path, l.how, l.exists, l.found) for l in first],
                         [(self.data, "default", False, 0)])
        moved = _tempdir(self, "muse-xdg-")
        path = self.session(spec_sample(), root=os.path.join(moved, "muse"))
        os.environ[ENV] = moved             # after import and construction
        locs = self.muse.locations()
        self.assertEqual([(l.path, l.how, l.exists, l.found) for l in locs],
                         [(os.path.join(moved, "muse"), "env " + ENV, True, 1)])
        self.assertEqual([s.path for s in self.muse.stores(locs)], [path])

    def test_sessions_and_subagents_are_found_newest_first(self):
        old = self.session(spec_sample(), sid="aaaaaaaa-0000-4000-8000-000000000001",
                           day="2026/08/05", age=500)
        main = self.session(spec_sample(), age=400)
        sub = self.session(spec_sample(), sub="sub_1", age=300)
        sub2 = self.session(spec_sample(), sub="sub_2", age=200)
        # a subagent's own subagent, one subagent/<id> deeper
        grand = self.session(spec_sample(), sub="sub_1/grand", age=150)
        other_day = self.session(spec_sample(), sid="bbbbbbbb-0000-4000-8000-000000000002",
                                 day="2026/09/30", age=100)
        # not stores: the index the running muse holds, the lock, files at
        # other depths or with other names, folders that are not dates,
        # config and repository files
        self.write("session-index.db", None, raw=b"SQLite format 3\0")
        self.write("sessions/%s/%s/.session.lock" % (DAY, SID), None, raw=b"pid=1\n")
        self.write("sessions/%s/%s/session.jsonl.bak" % (DAY, SID), spec_sample())
        self.write("sessions/%s/%s/history.jsonl" % (DAY, SID), spec_sample())
        self.write("sessions/%s/session.jsonl" % DAY, spec_sample())
        self.write("sessions/2026/09/session.jsonl", spec_sample())
        self.write("sessions/latest/09/21/x/session.jsonl", spec_sample())
        self.write("sessions/2026/9/21/x/session.jsonl", spec_sample())
        self.write("sessions/%s/.hidden/session.jsonl" % DAY, spec_sample())
        self.write("sessions/%s/%s/subagent/session.jsonl" % (DAY, SID), spec_sample())
        self.write("sessions/%s/%s/subagent/s/deeper/session.jsonl" % (DAY, SID),
                   spec_sample())
        self.write("sessions/%s/%s/subagent/sub_1/subagent/session.jsonl"
                   % (DAY, SID), spec_sample())
        self.write("session.jsonl", spec_sample())
        self.write("settings.json", None,
                   root=os.path.join(self.home, ".config", "muse"), raw=b"{}")

        found = self.stores()
        self.assertEqual([s.path for s in found],
                         [other_day, grand, sub2, sub, main, old])
        self.assertEqual(self.store(grand).session, "grand")
        for store in found:
            self.assertEqual((store.format, store.role, store.unit, store.masking),
                             ("jsonl", "transcript", "session", "rewrite"))
        self.assertEqual(self.muse.locations()[0].found, 6)

    def test_nested_subagents_are_found_to_a_bound(self):
        chain = "/".join("s%d" % n for n in range(1, muse_code.SUBAGENT_DEPTH + 2))
        paths = {}
        for depth in range(1, muse_code.SUBAGENT_DEPTH + 2):
            sub = "/".join(chain.split("/")[:depth])
            paths[depth] = self.session(spec_sample(), sub=sub)
        got = {s.path for s in self.stores()}
        for depth, path in paths.items():
            self.assertEqual(path in got, depth <= muse_code.SUBAGENT_DEPTH, depth)

    @unittest.skipIf(WINDOWS, "symlinks need privileges on Windows")
    def test_symlinked_subagent_folders_are_not_followed(self):
        main = self.session(spec_sample())
        folder = os.path.dirname(main)
        outside = os.path.dirname(self.write("x/outside/session.jsonl",
                                             spec_sample(),
                                             root=_tempdir(self, "muse-out-")))
        os.makedirs(os.path.join(folder, "subagent"))
        # a loop back to the session folder, and a folder elsewhere
        os.symlink(folder, os.path.join(folder, "subagent", "loop"))
        os.symlink(outside, os.path.join(folder, "subagent", "away"))
        self.assertEqual([s.path for s in self.stores()], [main])
        # nor is a subagent folder that is itself a symlink
        other = self.session(spec_sample(), sid="cccccccc-0000-4000-8000-000000000003")
        os.symlink(os.path.dirname(outside),        # holds outside/session.jsonl
                   os.path.join(os.path.dirname(other), "subagent"))
        self.assertEqual(sorted(s.path for s in self.stores()), sorted([main, other]))

    def test_session_and_project_of_a_store(self):
        main = self.session(spec_sample())
        # subagent logs name no workspace: the enclosing session's is theirs,
        # however deep they nest
        sub = self.session(spec_sample()[1:], sub="sub_1")
        grand = self.session(spec_sample()[1:], sub="sub_1/grand")
        # no metadata at all: no project
        bare_sid = "cccccccc-0000-4000-8000-000000000003"
        bare = self.session(spec_sample()[1:], sid=bare_sid)
        bare_sub = self.session(spec_sample()[1:], sid=bare_sid, sub="k")
        # metadata after a few other records is still found
        late = self.session([user_intent(1, "hi"), user_intent(2, "again"),
                             metadata(3, root="/home/dev/late")],
                            sid="dddddddd-0000-4000-8000-000000000004")
        got = {s.path: (s.session, s.project) for s in self.stores()}
        self.assertEqual(got[main], (SID, "/home/dev/app"))
        self.assertEqual(got[sub], ("sub_1", "/home/dev/app"))
        self.assertEqual(got[grand], ("grand", "/home/dev/app"))
        self.assertEqual(got[bare], (bare_sid, None))
        self.assertEqual(got[bare_sub], ("k", None))
        self.assertEqual(got[late], ("dddddddd-0000-4000-8000-000000000004",
                                     "/home/dev/late"))

    def test_a_subagent_takes_the_nearest_workspace_it_can_find(self):
        # Not seen in a real log: a subagent log with a metadata record of
        # its own (a worktree, say) is taken at its word, and the nearest
        # enclosing session that names a workspace lends it otherwise.
        sid = "eeeeeeee-0000-4000-8000-00000000000e"
        self.session(spec_sample(), sid=sid)
        own = self.session([metadata(root="/home/dev/wt")], sid=sid, sub="a")
        under_own = self.session(spec_sample()[1:], sid=sid, sub="a/b")
        # a subagent folder with no log of its own: its parent's is used
        orphan = self.session(spec_sample()[1:], sid=sid, sub="c/d")
        got = {s.path: s.project for s in self.stores()}
        self.assertEqual((got[own], got[under_own], got[orphan]),
                         ("/home/dev/wt", "/home/dev/wt", "/home/dev/app"))

    def test_metadata_after_a_frame_is_found(self):
        # the capture's order: a permission frame, then the metadata record
        lines = [frame(1, [permission_format(1)]), metadata(2)] + spec_sample()[1:]
        self.assertEqual(self.store(self.session(lines)).project, "/home/dev/app")
        # metadata inside a frame, and after a frame too long to read whole
        inside = self.session([frame(1, [permission_format(1), metadata(2)])],
                              sid="aaaaaaaa-0000-4000-8000-00000000000a")
        self.assertEqual(self.store(inside).project, "/home/dev/app")
        big = frame(1, [permission_format(1)] * 1000)
        self.assertGreater(len(_dump(big)), muse_code._HEAD_MAX)
        after_big = self.session([big, metadata(2, root="/home/dev/big")],
                                 sid="bbbbbbbb-0000-4000-8000-00000000000b")
        self.assertEqual(self.store(after_big).project, "/home/dev/big")

    def test_path_means_the_muse_data_folder(self):
        elsewhere = _tempdir(self, "muse-path-")
        path = self.session(spec_sample(), root=elsewhere)
        self.session(spec_sample())                  # the default: not read
        [loc] = self.muse.locations(override=elsewhere)
        self.assertEqual((loc.path, loc.how, loc.exists, loc.found),
                         (elsewhere, "--path", True, 1))
        self.assertEqual([s.path for s in self.stores(override=elsewhere)], [path])
        # pointing at its sessions folder works too
        direct = os.path.join(elsewhere, "sessions")
        self.assertEqual([s.path for s in self.stores(override=direct)], [path])

    def test_a_missing_root_is_zero_stores(self):
        self.assertEqual(self.stores(), [])
        self.assertEqual(self.stores(override=os.path.join(self.home, "nope")), [])
        os.makedirs(os.path.join(self.data, "sessions", "2026", "09", "21"))
        self.assertEqual(self.stores(), [])

    def test_days_prefilter_by_last_write(self):
        new = self.session(spec_sample(), age=60)
        self.session(spec_sample(), sid="eeeeeeee-0000-4000-8000-000000000005",
                     age=90 * 86400)
        self.assertEqual([s.path for s in self.stores(since_days=30)], [new])

    def test_windows_is_probed_with_no_note(self):
        path = self.session(spec_sample())
        with mock.patch.object(_paths, "platform_name",
                               side_effect=lambda p=None: "win32" if p is None
                               else _REAL_PLATFORM(p)):
            locs = self.muse.locations()
            note = self.muse.notes(locs, platform="win32")
        self.assertEqual([l.how for l in locs], ["probed"])
        self.assertEqual(note, [])
        if WINDOWS:     # elsewhere the backslashes are not separators
            self.assertEqual(os.path.normcase(locs[0].path),
                             os.path.normcase(self.data))
            self.assertEqual((locs[0].exists, locs[0].found), (True, 1))
            self.assertEqual([s.path for s in self.muse.stores(locs)], [path])
        else:
            self.assertTrue(locs[0].path.endswith("\\.local\\share\\muse"))

    def test_only_session_files_and_locks_are_opened(self):
        main = self.session(spec_sample())
        sub = self.session(spec_sample()[1:], sub="sub_1")
        self.write("session-index.db", None, raw=b"SQLite format 3\0")
        self.write("sessions/%s/%s/notes.md" % (DAY, SID), None, raw=b"x")
        lock = self.lock()
        opened = []
        real_open = builtins.open

        def spy(file, *args, **kwargs):
            fh = real_open(file, *args, **kwargs)
            opened.append(os.path.abspath(file))
            return fh

        with mock.patch.object(muse_code, "open", spy, create=True):
            for store in self.stores():
                list(self.muse.tool_calls(store))
                list(self.muse.secret_texts(store))
                self.muse.in_use(store)
        self.assertEqual(set(opened), {main, sub, lock})


# --------------------------------------------------------------------------
# Tool calls: kinds, outputs, time, dedupe
# --------------------------------------------------------------------------

class ToolCalls(MuseCase):

    def test_the_fixture_is_the_spec_sample(self):
        self.assertEqual([_dump(l) for l in spec_sample()], SPEC_LINES)

    def test_the_spec_sample(self):
        path = self.session(None, raw=("\n".join(SPEC_LINES) + "\n").encode("utf-8"))
        self.assertEqual(self.calls(path), [ToolCall(
            "muse-code", path, "bash", {"command": "cat .env"}, kind="shell",
            known=True, session=SID, project="/home/dev/app",
            timestamp="2026-09-21T14:13:20Z", tool_call_id="call_1",
            command="cat .env", consumed=("command",),
            output="API_KEY=" + SPEC_VALUE)])
        self.assertEqual(self.muse.counts["unreadable_calls"], 0)
        self.assertEqual(self.muse.counts["unknown"], 0)

    def test_every_tool_in_the_spec_maps_to_its_kind(self):
        # args other than bash's command and read_file's path are stand-ins
        # for names the spec marks unverified
        rows = [
            ("c1", "bash", {"command": "ls -la"},
             ("shell", True, "ls -la", (), {"command"})),
            ("c2", "bash", {"cmd": "pwd"},
             ("shell", True, "pwd", (), {"cmd"})),
            ("c3", "bash", {"command": ["bash", "-lc", "cat .env"]},
             ("shell", True, "cat .env", (), {"command"})),
            ("c4", "read_file", {"path": "/home/dev/app/a.py"},
             ("read", True, None, ("/home/dev/app/a.py",), {"path"})),
            ("c5", "write_file", {"path": "/home/dev/app/b.py", "content": "x"},
             ("write", True, None, ("/home/dev/app/b.py",), set())),
            ("c6", "edit_file", {"file_path": "/home/dev/app/a.py"},
             ("write", True, None, ("/home/dev/app/a.py",), set())),
            ("c7", "edit_file", {"paths": ["/p/a", "/p/b"]},
             ("write", True, None, ("/p/a", "/p/b"), set())),
            ("c8", "write_file", {}, ("write", True, None, (), set())),
            # names the spec does not list are judged by name, matched exactly
            ("c9", "Bash", {}, ("other", False, None, (), set())),
            ("c10", "mcp__srv__bash", {}, ("other", False, None, (), set())),
            ("c11", "glob", {}, ("other", False, None, (), set())),
            ("c12", "web_search", {}, ("other", False, None, (), set())),
        ]
        lines = [metadata()]
        for n, (cid, name, args, _want) in enumerate(rows):
            lines += call_lines(10 + 2 * n, cid, name, args, output="ok")
        got = self.by_id(self.session(lines))
        self.assertEqual(len(got), len(rows))
        for cid, name, args, want in rows:
            call = got[cid]
            self.assertEqual((call.tool_name, call.tool_input), (name, args))
            self.assertEqual((call.kind, call.known, call.command, call.paths,
                              set(call.consumed)), want, name)
            self.assertEqual(call.output, "ok")
            self.assertEqual((call.actor, call.status), ("agent", None))
        self.assertEqual(self.muse.counts["unreadable_calls"], 0)

    def test_a_shell_call_with_an_unknown_key_is_counted(self):
        lines = [metadata()]
        lines += call_lines(10, "a", "bash", {"script": "rm -rf ~/Documents/x"},
                            output="")
        lines += call_lines(12, "b", "bash", {"command": ""}, output="")
        lines += call_lines(14, "c", "bash", "not json at all", output="")
        lines += call_lines(16, "d", "bash", {"command": "ls"}, output="")
        path = self.session(lines)
        got = self.by_id(path)
        for cid in "abc":
            self.assertEqual((got[cid].kind, got[cid].known, got[cid].command,
                              got[cid].consumed), ("shell", True, None, frozenset()))
        self.assertEqual(got["c"].tool_input, {"_raw": "not json at all"})
        self.assertEqual(self.muse.counts["unreadable_calls"], 3)
        self.assertEqual(self.muse.notes(), [
            "3 Muse Code shell calls could not be read: their argument names "
            "are not documented yet."])
        # read again in the same run (clean after watch): counted once
        list(self.muse.tool_calls(self.store(path)))
        list(self.muse.secret_texts(self.store(path)))
        self.assertEqual(self.muse.counts["unreadable_calls"], 3)
        self.muse.reset()
        self.assertEqual(self.muse.notes(), [])
        self.session([metadata()] + call_lines(10, "a", "bash", {"x": "y"}),
                     sid="ffffffff-0000-4000-8000-000000000006")
        for store in self.stores():
            list(self.muse.tool_calls(store))
        self.assertEqual(self.muse.notes(), [
            "4 Muse Code shell calls could not be read: their argument names "
            "are not documented yet."])
        self.muse.reset()
        list(self.muse.tool_calls(self.store(self.session(
            [metadata()] + call_lines(10, "a", "bash", {"x": "y"}),
            sid="ffffffff-0000-4000-8000-000000000006"))))
        self.assertEqual(self.muse.notes(), [
            "1 Muse Code shell call could not be read: its argument names are "
            "not documented yet."])

    def test_a_working_directory_in_a_shell_call(self):
        lines = [metadata()]
        lines += call_lines(10, "a", "bash", {"command": "rm -rf build",
                                              "cwd": "/home/dev/app/sub"})
        lines += call_lines(12, "b", "bash", {"command": "ls"})
        got = self.by_id(self.session(lines))
        self.assertEqual(got["a"].workdir, "/home/dev/app/sub")
        self.assertIsNone(got["b"].workdir)
        self.assertEqual(got["b"].project, "/home/dev/app")

    def test_outputs_and_result_batches(self):
        lines = [metadata()]
        # two calls in one message, answered in one batch, out of order
        lines.append(committed(10, [tool_call("x", "bash", {"command": "ls"}),
                                    tool_call("y", "read_file", {"path": "a"})]))
        lines.append(results(11, [("y", "file body"), ("x", "a\nb")]))
        # a call with no result yet
        lines += call_lines(12, "z", "bash", {"command": "sleep 100"})
        # a result whose text is not a string, and one for no call
        lines += call_lines(14, "w", "bash", {"command": "true"}, output=None)
        lines.append(results(15, [("w", None), ("ghost", "no call")]))
        got = self.by_id(self.session(lines))
        self.assertEqual(sorted(got), ["w", "x", "y", "z"])
        self.assertEqual((got["x"].output, got["y"].output), ("a\nb", "file body"))
        self.assertIsNone(got["z"].output)
        self.assertIsNone(got["w"].output)

    def test_recorded_at_microseconds_become_the_right_utc_second(self):
        lines = [metadata()]
        lines += call_lines(10, "a", "bash", {"command": "a"}, recorded_at=T0)
        lines += call_lines(12, "b", "bash", {"command": "b"},
                            recorded_at=T0 + 999999)
        lines += call_lines(14, "c", "bash", {"command": "c"},
                            recorded_at=T0 + 86400 * 10 ** 6 + 1)
        lines += call_lines(16, "d", "bash", {"command": "d"},
                            recorded_at=1790000000)     # seconds: not a time in us
        lines += call_lines(18, "e", "bash", {"command": "e"}, recorded_at=MISSING)
        path = self.session(lines, age=7200)
        got = self.by_id(path)
        self.assertEqual(got["a"].timestamp, "2026-09-21T14:13:20Z")
        self.assertEqual(got["b"].timestamp, "2026-09-21T14:13:20Z")
        self.assertEqual(got["c"].timestamp, "2026-09-22T14:13:20Z")
        mtime = time.strftime("%Y-%m-%dT%H:%M:%SZ",
                              time.gmtime(os.stat(path).st_mtime))
        for cid in "de":
            self.assertEqual((got[cid].timestamp, got[cid].not_after),
                             (None, mtime), cid)
        self.assertIsNone(got["a"].not_after)

    def test_session_and_project(self):
        main = self.session([metadata()] + call_lines(10, "a", "bash",
                                                      {"command": "pwd"}))
        # a subagent log names no workspace: its session's is the project
        sub = self.session(call_lines(10, "b", "bash", {"command": "pwd"},
                                      sid="sub_1"), sub="sub_1")
        grand = self.session(call_lines(10, "g", "bash", {"command": "pwd"},
                                        sid="g_1"), sub="sub_1/g_1")
        # a record with no stream: the store's session; no metadata: no project
        nostream = [dict(l) for l in call_lines(10, "c", "bash", {"command": "pwd"})]
        del nostream[0]["stream"]
        bare = self.session(nostream, sid="cccccccc-0000-4000-8000-000000000003")
        # metadata written after the call still names the project of later calls
        late = self.session(call_lines(10, "d", "bash", {"command": "pwd"})
                            + [metadata(20, root="/home/dev/late")]
                            + call_lines(30, "e", "bash", {"command": "pwd"}),
                            sid="dddddddd-0000-4000-8000-000000000004")
        [a] = self.calls(main)
        self.assertEqual((a.session, a.project), (SID, "/home/dev/app"))
        [b] = self.calls(sub)
        self.assertEqual((b.session, b.project), ("sub_1", "/home/dev/app"))
        [g] = self.calls(grand)
        self.assertEqual((g.session, g.project), ("g_1", "/home/dev/app"))
        [c] = self.calls(bare)
        self.assertEqual((c.session, c.project),
                         ("cccccccc-0000-4000-8000-000000000003", None))
        got = self.by_id(late)
        self.assertEqual((got["d"].project, got["e"].project),
                         ("/home/dev/late", "/home/dev/late"))

    def test_dedupe_by_call_id(self):
        lines = [metadata()]
        lines += call_lines(10, "call_A", "bash", {"command": "cat .env"},
                            output="first")
        # a replayed copy of the same call and result
        lines += call_lines(20, "call_A", "bash", {"command": "cat .env"},
                            output="second")
        # the call committed twice before its result arrives
        lines += call_lines(30, "call_B", "read_file", {"path": "a"})
        lines += call_lines(32, "call_B", "read_file", {"path": "a"})
        lines.append(results(34, [("call_B", "text"), ("call_B", "again")]))
        calls = self.calls(self.session(lines))
        self.assertEqual(sorted(c.tool_call_id for c in calls), ["call_A", "call_B"])
        got = {c.tool_call_id: c for c in calls}
        self.assertEqual(got["call_A"].output, "first")
        self.assertEqual(got["call_A"].timestamp, "2026-09-21T14:13:20Z")
        self.assertEqual(got["call_B"].output, "text")

    def test_a_call_with_no_call_id_is_kept(self):
        item = tool_call("x", "bash", {"command": "ls"})
        del item["call_id"]
        [call] = self.calls(self.session([metadata(), committed(10, [item])]))
        self.assertEqual((call.tool_call_id, call.command), (None, "ls"))

    def test_args_stored_decoded_are_read_too(self):
        item = tool_call("x", "bash", {"command": "ls"})
        item["args"] = {"command": "ls"}
        [call] = self.calls(self.session([metadata(), committed(10, [item])]))
        self.assertEqual(call.command, "ls")

    def test_a_subagent_session_is_read(self):
        self.session(spec_sample())
        path = self.session(call_lines(10, "s1", "bash",
                                       {"command": "rm -rf ~/Documents/x"},
                                       output="", sid="sub_9"),
                            sub="sub_9")
        [call] = self.calls(path)
        self.assertEqual((call.session, call.project, call.command, call.store),
                         ("sub_9", "/home/dev/app", "rm -rf ~/Documents/x", path))
        self.assertEqual(rules(call), [("fs.destructive", "rm -rf ~/Documents/x")])

    def test_a_nested_subagent_session_is_read(self):
        self.session(spec_sample())
        self.session(call_lines(10, "k1", "bash", {"command": "ls"}), sub="kid")
        path = self.session(call_lines(10, "g1", "bash",
                                       {"command": "rm -rf ~/Documents/grandchild"},
                                       output="", sid="grandkid"),
                            sub="kid/grandkid")
        [call] = self.calls(path)
        self.assertEqual((call.session, call.project, call.store),
                         ("grandkid", "/home/dev/app", path))
        self.assertEqual(rules(call), [("fs.destructive",
                                        "rm -rf ~/Documents/grandchild")])


# --------------------------------------------------------------------------
# Retained frames: records batched inside one line
# --------------------------------------------------------------------------

class Frames(MuseCase):

    def _framed_session(self, output="STRIPE=" + SECRET):
        """The shape of a 1.4 session: a permission frame first, then the
        metadata, then a call committed inside a frame and its result
        committed outside one."""
        call = committed(3, [tool_call("c1", "bash",
                                       {"command": "rm -rf ~/Documents/x"})])
        return [frame(1, [permission_format(1)]), metadata(2), frame(2, [call]),
                results(4, [("c1", output)])]

    def test_a_permission_frame_is_known(self):
        path = self.session([frame(1, [permission_format(1)])] + spec_sample())
        [call] = self.calls(path)
        self.assertEqual((call.tool_call_id, call.project, call.output),
                         ("call_1", "/home/dev/app", "API_KEY=" + SPEC_VALUE))
        self.assertEqual(self.muse.counts["unknown"], 0)
        self.assertEqual(self.muse.counts["unparsed"], 0)

    def test_a_call_inside_a_frame_is_read_and_its_result_tied(self):
        path = self.session(self._framed_session())
        [call] = self.calls(path)
        self.assertEqual((call.tool_call_id, call.command, call.project,
                          call.session, call.timestamp, call.output),
                         ("c1", "rm -rf ~/Documents/x", "/home/dev/app", SID,
                          "2026-09-21T14:13:20Z", "STRIPE=" + SECRET))
        self.assertEqual(rules(call), [("fs.destructive", "rm -rf ~/Documents/x")])
        self.assertEqual(self.muse.counts["unknown"], 0)
        tied = [t for t in self.muse.secret_texts(self.store(path))
                if t.call is not None]
        self.assertEqual([(t.node, t.call.tool_call_id, t.where) for t in tied],
                         [("STRIPE=" + SECRET, "c1", "line 4")])
        found = findings(self.muse, [self.store(path)])
        self.assertEqual(found[SECRET]["origins"], set())   # rm names no file

    def test_a_result_inside_a_frame_is_tied_to_its_call(self):
        lines = [metadata()]
        lines += call_lines(10, "cat", "bash", {"command": "cat .env"})
        lines.append(frame(1, [permission_format(12),
                               results(13, [("cat", "STRIPE_KEY=" + SECRET)])]))
        path = self.session(lines)
        [call] = self.calls(path)
        self.assertEqual(call.output, "STRIPE_KEY=" + SECRET)
        found = findings(self.muse, [self.store(path)])
        self.assertEqual(found[SECRET]["origins"], {".env"})
        self.assertEqual(found[SECRET]["where"], ["line 3"])

    def test_children_are_read_in_child_index_order(self):
        call = committed(3, [tool_call("c1", "bash", {"command": "ls"})])
        result = results(4, [("c1", "a.py")])
        line = frame(1, [call, result])
        line["children"].reverse()          # written out of index order
        [got] = self.calls(self.session([metadata(), line]))
        self.assertEqual(got.output, "a.py")
        # an index that is not a whole number: the order as written
        line = frame(1, [call, result])
        line["children"][0]["child_index"] = True
        [got] = self.calls(self.session([metadata(), line],
                                        sid="aaaaaaaa-0000-4000-8000-00000000000a"))
        self.assertEqual(got.output, "a.py")

    def test_frames_of_another_kind_or_version_are_not_opened(self):
        inner = committed(3, [tool_call("w", "bash", {"command": "rm -rf ~/x"})])
        odd = []
        for key, value in (("frame_schema_version", 2),
                           ("frame_schema_version", True),
                           ("frame_schema_version", "1"),
                           ("frame_schema_version", MISSING),
                           ("retained_frame", "some_other_transaction"),
                           ("children", "not a list")):
            line = frame(1, [inner])
            if value is MISSING:
                del line[key]
            else:
                line[key] = value
            odd.append(line)
        path = self.session(spec_sample() + odd)
        self.assertEqual([c.tool_call_id for c in self.calls(path)], ["call_1"])
        self.assertEqual(self.muse.counts["unknown"], len(odd))
        # clean still reads every one of them whole
        got = set()
        for text in self.muse.secret_texts(self.store(path)):
            got.update(_strings(text.node))
        self.assertIn("rm -rf ~/x", got)

    def test_damaged_children_lose_only_themselves(self):
        good = committed(3, [tool_call("ok", "bash", {"command": "ls"})])
        line = frame(1, [good, '{"payload_type": "runtime.session", "payl',
                         "TOKEN=" + TYPED + " not json"])
        line["children"].append({"child_index": 3, "record_json": 5})
        line["children"].append("not a child")
        line["children"].append({"child_index": 5, "record_json": "[1, 2]"})
        path = self.session([metadata(), line])
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual([c.tool_call_id for c in self.calls(path)], ["ok"])
            texts = list(self.muse.secret_texts(self.store(path)))
        self.assertEqual(err.getvalue(), "")
        # two record_json strings that are not JSON; a child with no
        # record_json string, one that is not an object, and a record that
        # is not an envelope
        self.assertEqual(self.muse.counts["unparsed"], 2)
        self.assertEqual(self.muse.counts["unknown"], 3)
        got = set()
        for text in texts:
            got.update(_strings(text.node))
        self.assertTrue({"TOKEN=" + TYPED + " not json", "not a child",
                         "session_permission_transaction"} <= got)
        self.assertEqual(set(findings(self.muse, [self.store(path)])), {TYPED})

    def test_the_reported_session_is_read_whole(self):
        # the review's failing input, line for line
        path = self.session(self._framed_session())
        self.assertEqual([(c.tool_call_id, c.command) for c in self.calls(path)],
                         [("c1", "rm -rf ~/Documents/x")])
        self.assertEqual(self.muse.counts, {"unparsed": 0, "unknown": 0,
                                            "unreadable_stores": 0,
                                            "unreadable_calls": 0})


# --------------------------------------------------------------------------
# 4, 5, 6: judged the way watch judges every agent
# --------------------------------------------------------------------------

class Judged(MuseCase):

    def _calls(self, *specs):
        lines = [metadata()]
        for n, (cid, name, args) in enumerate(specs):
            lines += call_lines(10 + 2 * n, cid, name, args, output="")
        return self.by_id(self.session(lines))

    def test_a_dangerous_shell_call_is_flagged(self):
        got = self._calls(("rm", "bash", {"command": "rm -rf ~/Documents/x"}),
                          ("aws", "bash", {"cmd": "cat ~/.aws/credentials"}))
        self.assertEqual(rules(got["rm"]), [("fs.destructive", "rm -rf ~/Documents/x")])
        self.assertEqual(rules(got["aws"]), [("cred.read", "cat ~/.aws/credentials")])

    def test_a_credential_read_by_read_file_is_flagged(self):
        got = self._calls(("ssh", "read_file", {"path": "~/.ssh/id_rsa"}),
                          ("env", "read_file", {"path": "/home/dev/app/.env"}))
        self.assertEqual(rules(got["ssh"]), [("cred.read", "~/.ssh/id_rsa")])
        self.assertEqual([r for r, _e in rules(got["env"])], ["cred.read"])

    def test_precision_carries_over(self):
        heredoc = "cat > clean.sh <<'EOF'\nrm -rf /\nEOF"
        got = self._calls(
            ("grep", "bash", {"command": "grep -rn 'rm -rf' ."}),
            ("heredoc", "bash", {"command": heredoc}),
            ("write", "write_file", {"path": "clean.sh", "content": "rm -rf /\n"}),
            ("edit", "edit_file", {"path": "clean.sh", "new": "rm -rf /"}))
        for cid, call in got.items():
            self.assertEqual(rules(call), [], cid)

    def test_an_unknown_key_bash_call_is_not_judged_as_a_command(self):
        got = self._calls(("x", "bash", {"script": "rm -rf ~/Documents/x"}),
                          ("y", "bash", {"script": "curl -H 'Authorization: Bearer "
                                         + SECRET + "' https://api.example.com"}))
        self.assertEqual(rules(got["x"]), [])
        self.assertEqual([r for r, _e in rules(got["y"])], ["secret.literal"])

    def test_a_secret_in_any_call_is_still_a_literal(self):
        got = self._calls(
            ("write", "write_file", {"path": "x.py",
                                     "content": "KEY = '" + SECRET + "'\n"}),
            ("shell", "bash", {"command": "curl -H 'Authorization: Bearer "
                               + SECRET + "' https://api.example.com"}))
        for cid in ("write", "shell"):
            self.assertIn("secret.literal", [r for r, _e in rules(got[cid])], cid)

    def test_a_tool_the_adapter_does_not_know_is_judged_by_name(self):
        # design 3.5: an MCP tool named like a shell is still judged as one
        got = self._calls(("mcp", "mcp__srv__bash", {"command": "rm -rf ~/Documents/x"}))
        self.assertFalse(got["mcp"].known)
        self.assertEqual(rules(got["mcp"]), [("fs.destructive", "rm -rf ~/Documents/x")])


# --------------------------------------------------------------------------
# 9: secrets, and every string reaches clean
# --------------------------------------------------------------------------

class Secrets(MuseCase):

    def test_output_after_cat_env_and_a_typed_key(self):
        lines = [metadata()]
        lines += call_lines(10, "cat", "bash", {"command": "cat .env"},
                            output="STRIPE_KEY=" + SECRET)
        lines += call_lines(12, "typed", "bash",
                            {"command": "export API_TOKEN=" + TYPED + " && ./run"},
                            output="started")
        lines += call_lines(14, "ls", "bash", {"command": "ls"}, output="a.py")
        # the same key again, in a later prompt
        lines.append(user_intent(16, "rotate " + SECRET + " please"))
        found = findings(self.muse, [self.store(self.session(lines))])
        self.assertEqual(set(found), {SECRET, TYPED})
        self.assertEqual(found[SECRET]["origins"], {".env"})
        self.assertEqual(found[SECRET]["count"], 2)
        self.assertEqual(found[TYPED]["origins"], set())
        self.assertEqual(found[TYPED]["count"], 1)

    def test_the_spec_samples_placeholder_is_not_a_secret(self):
        # clean leaves EXAMPLE_NOT_A_REAL_KEY alone; the shape is what counts
        path = self.session(spec_sample())
        self.assertEqual(findings(self.muse, [self.store(path)]), {})
        lines = spec_sample()
        lines[2] = results(3, [("call_1", "API_KEY=" + SECRET)])
        found = findings(self.muse, [self.store(self.session(lines))])
        self.assertEqual(set(found), {SECRET})
        self.assertEqual(found[SECRET]["origins"], {".env"})
        self.assertEqual(found[SECRET]["where"], ["line 3"])

    def test_the_result_is_tied_to_its_call(self):
        lines = [metadata()] + call_lines(10, "cat", "bash",
                                          {"command": "cat .env"}, output="X=1")
        texts = list(self.muse.secret_texts(self.store(self.session(lines))))
        tied = [t for t in texts if t.call is not None]
        self.assertEqual(len(tied), 1)
        self.assertEqual((tied[0].node, tied[0].call.command,
                          tied[0].call.tool_call_id, tied[0].where),
                         ("X=1", "cat .env", "cat", "line 3"))
        # the call's arguments are handed over decoded
        [call_line] = [t for t in texts if t.where == "line 2"]
        [item] = call_line.node["payload"]["event"]["tool_calls"]
        self.assertEqual(item["args"], {"command": "cat .env"})

    def test_every_string_in_a_transcript_reaches_clean(self):
        lines = spec_sample()
        lines.append(user_intent(4, "deploy with " + SECRET))
        lines.append(run(5, {"kind": "text_delta", "note": "an event this "
                             "adapter does not read"}))
        lines.append(envelope(6, "tool_batch.effect.applied",
                              {"anything": ["unknown payload"]}))
        lines.append(frame(1, [permission_format(7),
                               user_intent(7, "a prompt inside a frame")]))
        lines.append([1, "a bare array line"])
        lines.append(committed(8, [tool_call("t9", "write_file",
                                             {"path": "f", "content": "body"}),
                                   "not an entry", {"args": "{}", "call_id": "n"}]))
        lines.append(results(9, [("t9", "created")]))
        lines.append(run(10, {"kind": "tool_result_batch_committed",
                              "results": ["odd", {"tool_call_id": "t9"}]}))
        lines.append(run(11, {"kind": "assistant_tool_calls_committed",
                              "tool_calls": "not a list"}))
        path = self.session(lines)
        with open(path, "ab") as fh:
            fh.write(b"{not json but holds TOKEN=" + TYPED.encode() + b"\n")
        expected = set()
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                try:
                    expected.update(_strings(json.loads(line)))
                except ValueError:
                    expected.add(line.rstrip("\n"))
        got = set()
        for text in self.muse.secret_texts(self.store(path)):
            got.update(_strings(text.node))
        self.assertEqual(expected - got, set())
        found = findings(self.muse, [self.store(path)])
        self.assertEqual(found[SECRET]["where"], ["line 4"])
        self.assertEqual(found[TYPED]["where"], ["line 13"])


# --------------------------------------------------------------------------
# 10, 13: masking round trip, a file in use, and .session.lock
# --------------------------------------------------------------------------

class Masking(MuseCase):

    def _session_with_secrets(self, sub=None, **kw):
        lines = [metadata()]
        lines += call_lines(10, "cat", "bash", {"command": "cat .env"},
                            output="STRIPE_KEY=" + SECRET)
        lines += call_lines(12, "json", "bash", {"command": "cat config.json"},
                            output=json.dumps({"token": SECRET, "n": 1}))
        # two JSON levels deep: inside args, a JSON string inside the line
        lines += call_lines(14, "typed", "bash",
                            {"command": "curl -u \"me:" + SECRET + "\" https://x.example"},
                            output="caf\u00e9 \u2028 ok")
        lines.append(user_intent(16, "key " + SECRET))
        return self.session(lines, sub=sub, mode=0o600, **kw)

    def _assert_masked(self, path, original, value, result, mode=0o600):
        self.assertEqual((result.path, result.changed, result.skipped),
                         (path, True, None))
        with open(path, "rb") as fh:
            after = fh.read()
        marker = _marker(value)
        self.assertEqual(after, original.replace(value.encode("utf-8"),
                                                 marker.encode("utf-8")))
        text = after.decode("utf-8")
        self.assertEqual([f for f in _rewrite.encodings(value) if f in text], [])
        with open(result.backup, "rb") as fh:
            self.assertEqual(fh.read(), original)
        if not WINDOWS:
            self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), mode)
            self.assertEqual(stat.S_IMODE(os.stat(result.backup).st_mode), 0o600)
        self.assertEqual(glob.glob(os.path.join(os.path.dirname(path),
                                                "*.ranwhat-tmp")), [])
        return after

    def test_round_trip(self):
        path = self._session_with_secrets()
        with open(path, "rb") as fh:
            original = fh.read()
        store = self.store(path)
        before = list(self.muse.tool_calls(store))
        result = self.muse.mask(store, [SECRET])
        after = self._assert_masked(path, original, SECRET, result)
        m = _marker(SECRET)
        # every line still parses (split on \n only: an output holds a raw
        # U+2028), and the JSON inside args and inside an output still does
        lines = [json.loads(l) for l in after.decode("utf-8").split("\n") if l]
        args = lines[5]["payload"]["event"]["tool_calls"][0]["args"]
        self.assertEqual(json.loads(args),
                         {"command": "curl -u \"me:" + m + "\" https://x.example"})
        output = lines[4]["payload"]["event"]["results"][0]["text"]
        self.assertEqual(json.loads(output), {"token": m, "n": 1})
        # the adapter reads the same calls, the secret masked in each
        again = list(self.muse.tool_calls(self.store(path)))
        self.assertEqual(
            [(c.tool_call_id, c.tool_name, c.kind, c.timestamp, c.session)
             for c in again],
            [(c.tool_call_id, c.tool_name, c.kind, c.timestamp, c.session)
             for c in before])
        self.assertEqual([c.command for c in again],
                         [c.command.replace(SECRET, m) for c in before])
        self.assertEqual([c.output for c in again],
                         [c.output.replace(SECRET, m) for c in before])
        self.assertEqual(findings(self.muse, [self.store(path)]), {})
        # a second run changes nothing and makes no second backup
        self.assertEqual(self.muse.mask(self.store(path), [SECRET]), MaskResult(path))
        with open(path, "rb") as fh:
            self.assertEqual(fh.read(), after)
        backups = [f for _d, _s, fs in os.walk(self.backups) for f in fs]
        self.assertEqual(len(backups), 1)

    def test_round_trip_through_frames(self):
        lines = [frame(1, [permission_format(1)]), metadata(2)]
        lines.append(frame(2, [committed(3, [tool_call(
            "typed", "bash",
            {"command": "curl -u \"me:" + SECRET + "\" https://x.example"})])]))
        lines.append(frame(3, [results(4, [("typed", "ok")]),
                               user_intent(5, "key " + SECRET)]))
        lines += call_lines(10, "cat", "bash", {"command": "cat .env"})
        lines.append(frame(4, [results(11, [("cat", json.dumps(
            {"token": SECRET, "n": 1}))])]))
        path = self.session(lines, mode=0o600)
        with open(path, "rb") as fh:
            original = fh.read()
        before = list(self.muse.tool_calls(self.store(path)))
        self.assertEqual(len(findings(self.muse, [self.store(path)])), 1)
        result = self.muse.mask(self.store(path), [SECRET])
        after = self._assert_masked(path, original, SECRET, result)
        m = _marker(SECRET)
        # every frame, every record_json in it, and the JSON inside those
        # still parse
        decoded = [json.loads(l) for l in after.decode("utf-8").split("\n") if l]
        record = json.loads(decoded[2]["children"][0]["record_json"])
        args = record["payload"]["event"]["tool_calls"][0]["args"]
        self.assertEqual(json.loads(args),
                         {"command": "curl -u \"me:" + m + "\" https://x.example"})
        record = json.loads(decoded[5]["children"][0]["record_json"])
        self.assertEqual(json.loads(record["payload"]["event"]["results"][0]["text"]),
                         {"token": m, "n": 1})
        again = list(self.muse.tool_calls(self.store(path)))
        self.assertEqual([(c.tool_call_id, c.timestamp) for c in again],
                         [(c.tool_call_id, c.timestamp) for c in before])
        self.assertEqual([c.output for c in again],
                         [c.output.replace(SECRET, m) for c in before])
        self.assertEqual(findings(self.muse, [self.store(path)]), {})

    def test_round_trip_of_the_spec_sample(self):
        path = self.session(spec_sample(), mode=0o644)
        with open(path, "rb") as fh:
            original = fh.read()
        result = self.muse.mask(self.store(path), [SPEC_VALUE])
        after = self._assert_masked(path, original, SPEC_VALUE, result, mode=0o644)
        self.assertEqual(len(after.split(b"\n")), 4)

    def test_a_file_written_just_now_is_in_use(self):
        path = self._session_with_secrets(age=5)
        digest = _sha(path)
        result = self.muse.mask(self.store(path), [SECRET])
        self.assertEqual(result, MaskResult(path, skipped="in use"))
        self.assertEqual(_sha(path), digest)
        self.assertFalse(os.path.exists(self.backups))

    def test_a_live_session_lock_blocks_masking(self):
        path = self._session_with_secrets()
        self.lock()                             # this test's own pid: alive
        digest = _sha(path)
        store = self.store(path)
        self.assertTrue(self.muse.in_use(store))
        self.assertEqual(self.muse.mask(store, [SECRET]),
                         MaskResult(path, skipped="in use"))
        self.assertEqual(_sha(path), digest)
        self.assertFalse(os.path.exists(self.backups))

    def test_a_dead_pid_does_not_block_masking(self):
        path = self._session_with_secrets()
        self.lock(text="pid=%d\n" % _dead_pid())
        store = self.store(path)
        self.assertFalse(self.muse.in_use(store))
        self.assertTrue(self.muse.mask(store, [SECRET]).changed)

    def test_a_subagent_is_in_use_while_its_parent_session_is(self):
        path = self._session_with_secrets(sub="sub_1")
        self.lock()                             # the parent session's lock
        self.assertTrue(self.muse.in_use(self.store(path)))
        self.assertEqual(self.muse.mask(self.store(path), [SECRET]).skipped, "in use")
        os.unlink(self.lock())
        self.lock(sub="sub_1")                  # its own
        self.assertTrue(self.muse.in_use(self.store(path)))
        os.unlink(self.lock(sub="sub_1"))
        self.assertFalse(self.muse.in_use(self.store(path)))

    def test_a_nested_subagent_is_in_use_while_any_enclosing_session_is(self):
        path = self._session_with_secrets(sub="kid/grandkid")
        self.assertFalse(self.muse.in_use(self.store(path)))
        for sub in (None, "kid", "kid/grandkid"):
            lock = self.lock(sub=sub)
            self.assertTrue(self.muse.in_use(self.store(path)), sub)
            self.assertEqual(self.muse.mask(self.store(path), [SECRET]).skipped,
                             "in use", sub)
            os.unlink(lock)
        # a sibling's lock is not this log's
        lock = self.lock(sub="other")
        self.assertFalse(self.muse.in_use(self.store(path)))
        self.assertEqual(muse_code.lock_folders(path), [
            os.path.dirname(path),
            os.path.dirname(os.path.dirname(os.path.dirname(path))),
            os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(
                os.path.dirname(path)))))])

    def test_a_lock_with_no_pid_counts_as_in_use(self):
        path = self._session_with_secrets()
        lock = self.lock(text="")
        self.assertTrue(self.muse.in_use(self.store(path)))
        with open(lock, "w", encoding="utf-8") as fh:
            fh.write('{"owner": "someone"}')
        self.assertTrue(self.muse.in_use(self.store(path)))
        # only the session's own lock counts: another session's does not
        os.unlink(lock)
        self.lock(sid="99999999-0000-4000-8000-000000000009")
        self.assertFalse(self.muse.in_use(self.store(path)))

    def test_pid_edge_cases(self):
        self.assertTrue(muse_code._pid_alive(os.getpid()))
        self.assertFalse(muse_code._pid_alive(0))
        self.assertFalse(muse_code._pid_alive(-5))
        self.assertFalse(muse_code._pid_alive(2 ** 40))

    def test_the_windows_check_never_signals_the_process(self):
        # os.kill(pid, 0) would end the process on Windows: tasklist instead
        def answer(stdout, code=0):
            return subprocess.CompletedProcess([], code, stdout=stdout, stderr=b"")
        cases = [
            (answer(b'"muse.exe","4242","Console","1","51,000 K"\r\n'), True),
            (answer(b"INFO: No tasks are running which match the criteria.\r\n"),
             False),
            (answer(b'"x.exe","42420","Console","1","1 K"\r\n'), False),
            (answer(b"", code=1), True),            # unsure: alive
            (OSError("no tasklist"), True),
        ]
        for outcome, alive in cases:
            kw = ({"side_effect": outcome} if isinstance(outcome, Exception)
                  else {"return_value": outcome})
            with mock.patch.object(muse_code.subprocess, "run", **kw) as run_, \
                    mock.patch.object(muse_code.os, "kill") as kill:
                with mock.patch.object(muse_code.os, "name", "nt"):
                    self.assertEqual(muse_code._pid_alive(4242), alive, outcome)
                kill.assert_not_called()
                self.assertEqual(run_.call_args[0][0][:3],
                                 ["tasklist", "/FI", "PID eq 4242"])


# --------------------------------------------------------------------------
# 12, 14: files that do not parse, and the --days window
# --------------------------------------------------------------------------

class Damaged(MuseCase):

    def test_a_truncated_last_line_is_skipped_quietly(self):
        good = "".join(_dump(l) + "\n" for l in spec_sample())
        partial = _dump(committed(9, [tool_call("call_Z", "bash",
                                                {"command": "rm -rf ~/x"})]))
        path = self.session(None, raw=(good + partial[:60]).encode("utf-8"))
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            calls = self.calls(path)
            list(self.muse.secret_texts(self.store(path)))
        self.assertEqual([c.tool_call_id for c in calls], ["call_1"])
        self.assertEqual(err.getvalue(), "")
        self.assertEqual(self.muse.counts["unparsed"], 0)

    def test_garbage_warns_once_and_other_stores_are_still_read(self):
        garbage = self.session(None, sid="aaaaaaaa-0000-4000-8000-00000000000a",
                               raw=b"\x00\xff\xfe not json\n\x89PNG\r\n\x1a\n" * 20)
        good = self.session(spec_sample(), age=7200)
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            for store in self.stores():
                list(self.muse.tool_calls(store))
                list(self.muse.secret_texts(store))
                list(self.muse.tool_calls(store))
            self.assertEqual([c.tool_call_id for c in self.calls(good)], ["call_1"])
        warnings = err.getvalue().splitlines()
        self.assertEqual(len(warnings), 1, warnings)
        self.assertIn(garbage, warnings[0])
        self.assertNotIn("\u2014", warnings[0])
        self.assertEqual(self.muse.counts["unreadable_stores"], 1)
        self.assertEqual(self.muse.unreadable, {"not JSON Lines": 1})

    def test_lines_that_are_not_envelopes_are_ignored_and_counted(self):
        # a frame of a version this module does not know is not opened
        wrapped = frame(1, [committed(5, [tool_call(
            "w", "bash", {"command": "rm -rf ~/x"})])])
        wrapped["frame_schema_version"] = 2
        lines = spec_sample() + [
            wrapped,
            [1, 2, 3],
            {"payload_type": "runtime.session", "payload": "not an object"},
            run(6, {"kind": "text_delta", "delta": "hello"}),
            envelope(7, "runtime.session", {"kind": "other", "event": {
                "kind": "assistant_tool_calls_committed",
                "tool_calls": [tool_call("o", "bash", {"command": "rm -rf ~/y"})]}}),
            committed(8, ["not a call", {"call_id": "nameless", "args": "{}"}]),
        ]
        path = self.session(lines)
        self.assertEqual([c.tool_call_id for c in self.calls(path)], ["call_1"])
        # three lines that are not envelopes, one tool_calls entry with no
        # name and one that is not an object
        self.assertEqual(self.muse.counts["unknown"], 5)
        list(self.muse.secret_texts(self.store(path)))
        self.assertEqual(self.muse.counts["unknown"], 5)
        self.muse.reset()
        list(self.muse.secret_texts(self.store(path)))
        self.assertEqual(self.muse.counts["unknown"], 3)

    def test_a_bad_line_in_the_middle_is_counted_not_fatal(self):
        good = [_dump(l) + "\n" for l in spec_sample()]
        raw = "".join(good[:2]) + "{not json\n" + "".join(good[2:])
        path = self.session(None, raw=raw.encode("utf-8"))
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            [call] = self.calls(path)
        self.assertEqual(call.output, "API_KEY=" + SPEC_VALUE)
        self.assertEqual(err.getvalue(), "")
        self.assertEqual(self.muse.counts["unparsed"], 1)

    def test_a_byte_order_mark_and_crlf_are_tolerated(self):
        raw = "\ufeff" + "".join(_dump(l) + "\r\n" for l in spec_sample())
        path = self.session(None, raw=raw.encode("utf-8"))
        self.assertEqual(self.store(path).project, "/home/dev/app")
        [call] = self.calls(path)
        self.assertEqual(call.project, "/home/dev/app")

    def test_a_store_that_vanished_warns_once(self):
        path = self.session(spec_sample())
        store = self.store(path)
        os.unlink(path)
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(list(self.muse.tool_calls(store)), [])
            self.assertEqual(list(self.muse.secret_texts(store)), [])
        self.assertEqual(err.getvalue().count("warning:"), 1)
        self.assertEqual(self.muse.counts["unreadable_stores"], 1)


class Window(MuseCase):

    def test_an_old_call_in_a_new_file_and_an_undated_one(self):
        recent = int((time.time() - 3600) * 10 ** 6)
        lines = [metadata()]
        lines += call_lines(10, "old", "bash", {"command": "rm -rf ~/Documents/x"},
                            output="", recorded_at=1735787045 * 10 ** 6)  # 2025-01-02
        lines += call_lines(12, "recent", "bash", {"command": "rm -rf ~/Documents/y"},
                            output="", recorded_at=recent)
        lines += call_lines(14, "undated", "bash", {"command": "rm -rf ~/Documents/z"},
                            recorded_at=MISSING)
        path = self.session(lines, age=60)
        [store] = self.stores(since_days=30)
        self.assertEqual(store.path, path)
        cutoff = time.strftime("%Y-%m-%dT%H:%M:%SZ",
                               time.gmtime(time.time() - 30 * 86400))
        kept, undated = [], 0
        for call in self.muse.tool_calls(store):
            # design 3.5: a dated call by its own time; an undated one is
            # kept unless the last write of its store is before the cutoff
            if call.timestamp:
                if call.timestamp >= cutoff:
                    kept.append(call.tool_call_id)
            elif call.not_after and call.not_after >= cutoff:
                kept.append(call.tool_call_id)
                undated += 1
        self.assertEqual(sorted(kept), ["recent", "undated"])
        self.assertEqual(undated, 1)


# --------------------------------------------------------------------------
# A large session, timed in its own process
# --------------------------------------------------------------------------

TIMED = r"""
import json, sys, time
sys.path.insert(0, sys.argv[1])
from ranwhat.sources.muse_code import MuseCodeSource
m = MuseCodeSource()
t = time.perf_counter()
stores = m.stores(m.locations(override=sys.argv[2]))
calls = sum(1 for s in stores for _ in m.tool_calls(s))
texts = sum(1 for s in stores for _ in m.secret_texts(s))
print(json.dumps({"seconds": time.perf_counter() - t, "stores": len(stores),
                  "calls": calls, "texts": texts, "counts": m.counts}))
"""

# Generous: about a second here for 30 MB. A quadratic slip costs minutes.
BUDGET = 10.0


class Performance(unittest.TestCase):

    def test_a_30mb_session_reads_well_within_budget(self):
        data = _tempdir(self, "muse-perf-")
        folder = os.path.join(data, "sessions", "2026", "09", "21", SID)
        os.makedirs(folder)
        path = os.path.join(folder, "session.jsonl")
        out = ("lorem ipsum dolor sit amet " * 24 + "\n") * 2
        n = 0
        with open(path, "w", encoding="utf-8", newline="") as fh:
            fh.write(_dump(frame(1, [permission_format(1)])) + "\n")
            fh.write(_dump(metadata()) + "\n")
            while fh.tell() < 30 * 1024 * 1024:
                lines = call_lines(n + 2, "call_%08d" % n, "bash",
                                   {"command": "grep -rn foo src/%d" % n},
                                   output=out)
                if n % 20 == 0:             # every tenth call in a frame
                    lines = [frame(n, lines)]
                for line in lines:
                    fh.write(_dump(line) + "\n")
                n += 2
        env = dict(os.environ, HOME=data, USERPROFILE=data)
        env.pop(ENV, None)
        proc = subprocess.run([sys.executable, "-c", TIMED, REPO, data], env=env,
                              capture_output=True, text=True, encoding="utf-8",
                              timeout=20)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        report = json.loads(proc.stdout)
        self.assertEqual(report["stores"], 1)
        self.assertEqual(report["calls"], n // 2)
        self.assertEqual(report["counts"]["unparsed"], 0)
        self.assertEqual(report["counts"]["unknown"], 0)
        self.assertLess(report["seconds"], BUDGET, report)


if __name__ == "__main__":
    unittest.main()
