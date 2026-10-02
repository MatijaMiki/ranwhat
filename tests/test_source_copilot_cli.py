"""The GitHub Copilot CLI adapter (ranwhat/sources/copilot_cli.py).

Fixtures follow the sample in design section 7.5, field for field: the
event envelope {type, data, id, timestamp, parentId} and the data fields
the spec lists, nothing more. Values are synthetic. Every secret is
written as adjacent literals, so a scanner reading the repository does not
take a fixture for a leak.

Everything runs in temp directories: HOME, USERPROFILE, COPILOT_HOME and
clean's backup root all point there. Nothing touches the real home.

watch.judge and clean's source scanner are wired in later. Until then,
judge() below is design 3.5 written out, and origins() is the part of
design 3.6 that credits a secret in a call's output to the file the call
named.
"""
import base64
import contextlib
import hashlib
import io
import json
import os
import random
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

from ranwhat import clean, watch  # noqa: E402
from ranwhat.sources import _paths, _rewrite  # noqa: E402
from ranwhat.sources import copilot_cli  # noqa: E402
from ranwhat.sources.base import MaskResult, Store  # noqa: E402
from ranwhat.sources.copilot_cli import CopilotCliSource  # noqa: E402

WINDOWS = os.name == "nt"

SECRET = "sk_" "live_" "Hq3vT8mW2yLp6RcN4sXe9BjZ"
TYPED = "sk_" "live_" "Pa7wK1nV5tQz3XcM8rLd2FgY"

SID = "3f2b6c1e-8a4d-4f1e-9c2a-1b2c3d4e5f60"
EVENT_ID = "0b6f1c3e-0000-4000-8000-%012d"
MESSAGE_ID = "5d1e7a90-0000-4000-8000-%012d"
T0 = "2026-10-01T09:00:00.000Z"


def judge(call):
    """Design 3.5's judge, until watch has its own."""
    if hasattr(watch, "judge"):
        return watch.judge(call)
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
    return watch.evaluate("ranwhat:%s" % call.kind, call.tool_input)


def rules(call):
    return [hit["rule"] for hit in judge(call)[0]]


def origins(text):
    """The credential files a SecretText's secrets are credited to: the
    paths its call's input names, with the consumed keys replaced by the
    normalised command (heredocs stripped). No call, no origin."""
    call = text.call
    if call is None:
        return []
    named = {k: v for k, v in call.tool_input.items() if k not in call.consumed}
    if call.command:
        named["command"] = watch._strip_heredocs(call.command)
    if call.paths:
        named["paths"] = list(call.paths)
    return clean._origins(json.dumps(named, ensure_ascii=False))


def findings(texts):
    """{secret value: set of origins} over SecretTexts, as clean walks them."""
    out = {}
    for text in texts:
        found = []
        clean._walk(text.node, lambda value, label: found.append(value))
        named = origins(text)
        for value in found:
            out.setdefault(value, set()).update(named[-1:])
    return out


def _sha(path):
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def _tree(root):
    """{relative path: sha256} for every file under root."""
    out = {}
    for folder, _dirs, files in os.walk(root):
        for name in files:
            path = os.path.join(folder, name)
            if os.path.islink(path):
                out[os.path.relpath(path, root)] = "link"
            else:
                out[os.path.relpath(path, root)] = _sha(path)
    return out


class Log(object):
    """An events.jsonl in the making: each event gets the next id, and
    parentId chains to the one before it."""

    def __init__(self):
        self.events = []

    def add(self, etype, data, ts):
        n = len(self.events) + 1
        parent = self.events[-1]["id"] if self.events else None
        self.events.append({"type": etype, "data": data, "id": EVENT_ID % n,
                            "timestamp": ts, "parentId": parent})
        return self

    def start(self, ts=T0, cwd="/home/dev/app", sid=SID):
        return self.add("session.start", {
            "sessionId": sid, "version": 1, "producer": "copilot-agent",
            "copilotVersion": "1.0.90", "startTime": ts,
            "context": {"cwd": cwd}}, ts)

    def user(self, text, ts):
        return self.add("user.message", {"content": text}, ts)

    def ask(self, ts, *requests):
        n = len(self.events) + 1
        return self.add("assistant.message", {
            "messageId": MESSAGE_ID % n, "content": "",
            "toolRequests": list(requests)}, ts)

    def run(self, ts, cid, name, arguments, **extra):
        data = {"toolCallId": cid, "toolName": name, "arguments": arguments}
        data.update(extra)
        return self.add("tool.execution_start", data, ts)

    def done(self, ts, cid, content=None, success=True, **extra):
        data = {"toolCallId": cid, "success": success}
        if content is not None:
            data["result"] = {"content": content}
        data.update(extra)
        return self.add("tool.execution_complete", data, ts)

    def call(self, cid, name, arguments, content, ts="2026-10-01T09:00:07.000Z",
             **extra):
        """A whole call: the request, its start and its result."""
        self.ask(ts, request(cid, name, arguments))
        self.run(ts, cid, name, arguments, **extra)
        return self.done(ts, cid, content)

    def data(self):
        return b"".join(line(e) for e in self.events)


def request(cid, name, arguments, **extra):
    out = {"toolCallId": cid, "name": name, "arguments": arguments}
    out.update(extra)
    return out


def line(event):
    """One record as the CLI writes it: compact, non-ASCII and U+2028 raw
    (JavaScript's JSON.stringify escapes neither)."""
    return (json.dumps(event, separators=(",", ":"), ensure_ascii=False)
            + "\n").encode("utf-8")


def spec_sample(secret=SECRET):
    """The fixture of design 7.5, with a synthetic token-shaped key."""
    return (Log().start()
            .user("what is in .env?", "2026-10-01T09:00:05.000Z")
            .ask("2026-10-01T09:00:07.000Z",
                 request("call_1", "bash", {"command": "cat .env",
                                            "description": "Show the env file"}))
            .run("2026-10-01T09:00:07.100Z", "call_1", "bash",
                 {"command": "cat .env", "description": "Show the env file"})
            .done("2026-10-01T09:00:07.400Z", "call_1",
                  "API_KEY=" + secret + "\n<exited with exit code 0>"))


class CopilotCase(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="copilot-test-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.home = os.path.join(self.tmp, "home")
        os.makedirs(self.home)
        patches = [mock.patch.dict(os.environ, {"HOME": self.home,
                                                "USERPROFILE": self.home}),
                   mock.patch.object(_paths, "home", return_value=self.home),
                   mock.patch.object(clean, "BACKUP_ROOT",
                                     os.path.join(self.tmp, "backups"))]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        os.environ.pop("COPILOT_HOME", None)
        self.root = os.path.join(self.home, ".copilot")
        self.src = CopilotCliSource()

    def write(self, data, sid=SID, age=3600, root=None):
        folder = os.path.join(root or self.root, "session-state", sid)
        os.makedirs(folder, exist_ok=True)
        path = os.path.join(folder, "events.jsonl")
        with open(path, "wb") as fh:
            fh.write(data.data() if isinstance(data, Log) else data)
        self.age(path, age)
        return path

    @staticmethod
    def age(path, seconds):
        when = time.time() - seconds
        os.utime(path, (when, when))

    def stores(self, **kw):
        return self.src.stores(self.src.locations(), **kw)

    def only_store(self):
        [store] = [s for s in self.stores() if s.role == "transcript"]
        return store

    def calls(self, store=None):
        return list(self.src.tool_calls(store or self.only_store()))

    def one_call(self, log):
        self.write(log)
        [call] = self.calls()
        return call


# --------------------------------------------------------------------------
# Where to look
# --------------------------------------------------------------------------

class DefaultPaths(CopilotCase):

    def test_every_platform(self):
        src = self.src
        self.assertEqual(src.default_paths({}, "/Users/u", "darwin"),
                         [("/Users/u/.copilot", "default")])
        self.assertEqual(src.default_paths({}, "/home/u", "linux"),
                         [("/home/u/.copilot", "default")])
        self.assertEqual(src.default_paths({}, "C:\\Users\\u", "win32"),
                         [("C:\\Users\\u\\.copilot", "default")])

    def test_copilot_home_replaces_the_default(self):
        src = self.src
        self.assertEqual(src.default_paths({"COPILOT_HOME": "/srv/cp"},
                                           "/home/u", "linux"),
                         [("/srv/cp", "env COPILOT_HOME")])
        self.assertEqual(src.default_paths({"COPILOT_HOME": "D:\\cp"},
                                           "C:\\Users\\u", "win32"),
                         [("D:\\cp", "env COPILOT_HOME")])
        self.assertEqual(src.default_paths({"COPILOT_HOME": ""}, "/home/u",
                                           "linux"),
                         [("/home/u/.copilot", "default")])

    def test_what_reports_need(self):
        self.assertEqual(self.src.id, "copilot-cli")
        for field in ("name", "unit", "path_means", "checked"):
            self.assertTrue(getattr(self.src, field), field)
        self.assertEqual(self.src.env, ("COPILOT_HOME",))
        for text in (self.src.name, self.src.path_means, self.src.mask_note,
                     self.src.legacy_reason):
            self.assertNotIn("\u2014", text)

    def test_override_variable_is_read_at_call_time(self):
        [loc] = self.src.locations()
        self.assertEqual((loc.path, loc.how, loc.exists, loc.found),
                         (self.root, "default", False, 0))
        moved = os.path.join(self.tmp, "moved")
        self.write(spec_sample(), root=moved)
        os.environ["COPILOT_HOME"] = moved      # after construction
        [loc] = self.src.locations()
        self.assertEqual((loc.path, loc.how, loc.exists, loc.found),
                         (moved, "env COPILOT_HOME", True, 1))

    def test_path_override(self):
        moved = os.path.join(self.tmp, "cfg")
        self.write(spec_sample(), root=moved)
        [loc] = self.src.locations(override=moved)
        self.assertEqual((loc.how, loc.found), ("--path", 1))
        self.assertEqual(len(self.src.stores([loc])), 1)


class Discovery(CopilotCase):

    def test_sessions_newest_first_and_nothing_else(self):
        old = self.write(spec_sample(), sid="a-old", age=7200)
        new = self.write(spec_sample(), sid="b-new", age=60)
        folder = os.path.dirname(new)
        # Files the spec does not list are never stores.
        for rel in ("workspace.yaml", "plan.md", "checkpoints/index.md",
                    "files/notes.txt", "logs/session.log"):
            path = os.path.join(folder, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("API_KEY=" + SECRET + "\n")
        os.makedirs(os.path.join(self.root, "session-state", "c-empty"))
        os.makedirs(os.path.join(self.root, "command-history-state"))
        with open(os.path.join(self.root, "command-history-state", "h.jsonl"),
                  "w", encoding="utf-8") as fh:
            fh.write('{"command": "cat .env"}\n')
        with open(os.path.join(self.root, "session-store.db"), "wb") as fh:
            fh.write(b"SQLite format 3\x00")
        stores = self.stores()
        self.assertEqual([s.path for s in stores], [new, old])
        self.assertEqual([(s.format, s.role, s.unit, s.session, s.project,
                           s.masking, s.source) for s in stores],
                         [("jsonl", "transcript", "session", "b-new",
                           "/home/dev/app", "rewrite", "copilot-cli"),
                          ("jsonl", "transcript", "session", "a-old",
                           "/home/dev/app", "rewrite", "copilot-cli")])
        self.assertEqual([s.path for s in self.stores(since_days=0.05)], [new])

    def test_a_missing_root_is_no_stores(self):
        self.assertEqual(self.stores(), [])
        self.assertEqual(self.src.stores(self.src.locations(
            override=os.path.join(self.tmp, "nowhere"))), [])

    def test_legacy_history_is_counted_and_not_read(self):
        self.write(spec_sample())
        legacy = os.path.join(self.root, "history-session-state")
        os.makedirs(legacy)
        for name in ("session_1.json", "session_2.json"):
            with open(os.path.join(legacy, name), "w", encoding="utf-8") as fh:
                fh.write('{"output": "API_KEY=%s"}' % SECRET)
        spy = _OpenSpy()
        with spy:
            self.src.locations()
            stores = self.stores()
        self.assertEqual(len(stores), 1)
        self.assertFalse([p for p in spy.paths if legacy in p])
        self.assertEqual(self.src.counts["unreadable_stores"], 2)
        self.assertEqual(self.src.unreadable, {self.src.legacy_reason: 2})

    def test_session_store_db_is_never_opened(self):
        path = self.write(spec_sample())
        db = os.path.join(self.root, "session-store.db")
        with open(db, "wb") as fh:
            fh.write(b"SQLite format 3\x00" + SECRET.encode())
        before = _sha(db)
        spy = _OpenSpy()
        with spy:
            stores = self.stores()
            for store in stores:
                list(self.src.tool_calls(store))
                list(self.src.secret_texts(store))
        self.assertNotIn(db, spy.paths)
        self.assertEqual([s.path for s in stores], [path])
        self.assertEqual(_sha(db), before)


class _OpenSpy(object):
    """Records every path passed to open() while active."""

    def __init__(self):
        self.paths = []
        self._real = open

    def _open(self, file, *args, **kwargs):
        self.paths.append(os.fspath(file) if not isinstance(file, int) else file)
        return self._real(file, *args, **kwargs)

    def __enter__(self):
        self._patch = mock.patch("builtins.open", self._open)
        self._patch.start()
        return self

    def __exit__(self, *exc):
        self._patch.stop()


# --------------------------------------------------------------------------
# Large-output side files
# --------------------------------------------------------------------------

def large_output(path):
    """A result naming a saved file, in the CLI's own words (copilot-sdk
    snapshot should_map_large_output_handling_into_sessionfs)."""
    return ("Output too large to read at once (97.7 KB). Saved to: %s\n"
            "Consider using tools like grep (for searching), head/tail (for "
            "viewing start/end), view with view_range (for specific "
            "sections), or jq (for JSON) to examine portions of the output."
            "\n\nPreview (first 500 chars):\nAPI_KEY=" % path)


class SideFiles(CopilotCase):

    def setUp(self):
        CopilotCase.setUp(self)
        self.out = os.path.join(self.tmp, "tmp")
        os.makedirs(self.out)

    def saved(self, name, body):
        path = os.path.join(self.out, name)
        with open(path, "wb") as fh:
            fh.write(body)
        self.age(path, 3600)
        return path

    def test_a_saved_output_is_a_side_store_credited_to_its_call(self):
        side = self.saved("1790000000000-copilot-tool-output-tk7puw.txt",
                          ("x" * 5000 + "\nAPI_KEY=" + SECRET + "\n").encode())
        log = Log().start().call("call_1", "bash", {"command": "cat .env",
                                                    "description": "env"},
                                 large_output(side))
        path = self.write(log)
        stores = self.stores()
        self.assertEqual(sorted((s.path, s.role, s.format, s.session, s.project,
                                 s.masking) for s in stores),
                         sorted([(path, "transcript", "jsonl", SID,
                                  "/home/dev/app", "rewrite"),
                                 (side, "side", "text", SID, "/home/dev/app",
                                  "rewrite")]))
        [side_store] = [s for s in stores if s.role == "side"]
        self.assertEqual(list(self.src.tool_calls(side_store)), [])
        texts = list(self.src.secret_texts(side_store))
        self.assertEqual(len(texts), 1)
        self.assertEqual(texts[0].call.command, "cat .env")
        self.assertEqual(findings(texts), {SECRET: {".env"}})
        [loc] = self.src.locations()
        self.assertEqual(loc.found, 2)

    def test_a_session_log_is_read_once_for_all_its_saved_outputs(self):
        sides = [self.saved("17900000000%02d-copilot-tool-output-n%d.txt"
                            % (i, i), ("API_KEY=" + SECRET + "\n").encode())
                 for i in range(5)]
        log = Log().start()
        for i, side in enumerate(sides):
            log.call("call_%d" % i, "bash", {"command": "cat app%d/.env" % i},
                     large_output(side))
        path = self.write(log)
        side_stores = [s for s in self.stores() if s.role == "side"]
        self.assertEqual(len(side_stores), 5)
        spy = _OpenSpy()
        with spy:
            got = {}
            for store in side_stores:
                [text] = self.src.secret_texts(store)
                got[store.path] = (text.call.tool_call_id, text.call.command,
                                   text.call.output)
        self.assertEqual(spy.paths.count(path), 1)
        self.assertEqual(got, {side: ("call_%d" % i, "cat app%d/.env" % i, None)
                               for i, side in enumerate(sides)})

    def test_a_saved_output_found_later_in_the_run_is_still_credited(self):
        first = self.saved("1790000000010-copilot-tool-output-a.txt",
                           ("API_KEY=" + SECRET).encode())
        later = os.path.join(self.out, "1790000000011-copilot-tool-output-b.txt")
        self.write(Log().start()
                   .call("call_1", "bash", {"command": "cat a/.env"},
                         large_output(first))
                   .call("call_2", "bash", {"command": "cat b/.env"},
                         large_output(later)))
        [store] = [s for s in self.stores() if s.role == "side"]
        [text] = self.src.secret_texts(store)
        self.assertEqual(text.call.command, "cat a/.env")
        self.saved(os.path.basename(later), ("API_KEY=" + SECRET).encode())
        [store] = [s for s in self.stores() if s.path == later]
        [text] = self.src.secret_texts(store)
        self.assertEqual(text.call.command, "cat b/.env")

    def side_texts(self, body, command="cat .env", name=None):
        """The SecretTexts of one saved output holding `body` (bytes)."""
        side = self.saved(name or "1790000000001-copilot-tool-output-abc123.txt",
                          body)
        self.write(Log().start().call("call_1", "bash", {"command": command},
                                      large_output(side)))
        [side_store] = [s for s in self.stores() if s.role == "side"]
        return list(self.src.secret_texts(side_store))

    def assert_covered(self, body, texts):
        """The pieces are in file order, each at most SIDE_PIECE bytes, the
        first at the start and the last at the end, and each overlaps the
        one before it by at least SIDE_OVERLAP bytes. `body` must be ASCII
        and no piece may occur in it twice."""
        self.assertGreater(len(texts), 1)
        prev_start = prev_end = None
        for text in texts:
            self.assertLessEqual(len(text.node.encode("utf-8")),
                                 copilot_cli.SIDE_PIECE)
            self.assertLess(len(text.node), clean.MAX_STRING)
            start = body.find(text.node)
            self.assertNotEqual(start, -1)
            if prev_start is None:
                self.assertEqual(start, 0)
            else:
                self.assertGreater(start, prev_start)
                self.assertGreaterEqual(prev_end - start,
                                        copilot_cli.SIDE_OVERLAP)
            first = body.count("\n", 0, start) + 1
            last = first + text.node.count("\n", 0, len(text.node) - 1)
            self.assertEqual(text.where, "lines %d-%d" % (first, last))
            prev_start, prev_end = start, start + len(text.node)
        self.assertEqual(prev_end, len(body))

    def test_a_large_side_file_is_searched_in_pieces(self):
        body = "".join("%07d %s\n" % (i, "y" * 91) for i in range(12000))
        body += "API_KEY=" + SECRET + "\n"           # 1.2 MB in all
        texts = self.side_texts(body.encode())
        self.assert_covered(body, texts)
        for text in texts:                          # cut at line ends
            start = body.find(text.node)
            self.assertTrue(start == 0 or body[start - 1] == "\n")
            self.assertTrue(text.node.endswith("\n"))
        self.assertEqual(findings(texts), {SECRET: {".env"}})

    def test_a_side_file_that_is_one_long_line_is_cut_too(self):
        # Minified JSON from curl or jq: no line end anywhere, and the key
        # is past the first 1,000,000 characters clean searches in a string.
        items = ",".join('{"id":%d,"name":"item%d"}' % (i, i)
                         for i in range(70000))
        body = '[%s,{"apiKey":"%s"}]' % (items, SECRET)
        self.assertGreater(len(body), 1700000)
        texts = self.side_texts(body.encode(), "curl -s https://example.com/x")
        self.assert_covered(body, texts)
        self.assertEqual(findings(texts), {SECRET: set()})

    def test_a_key_across_a_cut_is_found_whole(self):
        piece = copilot_cli.SIDE_PIECE
        filler = "".join("w%06d " % i for i in range(200000))
        body = filler[:piece - 12] + SECRET + " " + filler[:600000]
        texts = self.side_texts(body.encode())
        self.assert_covered(body, texts)
        self.assertNotIn(SECRET, texts[0].node)       # the first cut splits it
        self.assertEqual(findings(texts), {SECRET: {".env"}})

    def test_a_private_key_across_a_line_cut_is_found_whole(self):
        rand = random.Random(7)
        b64 = base64.b64encode(bytes(rand.randrange(256)
                                     for _ in range(1200))).decode("ascii")
        pem = ("-----BEGIN " "PRIVATE KEY-----\n"
               + "\n".join(b64[i:i + 64] for i in range(0, len(b64), 64))
               + "\n-----END " "PRIVATE KEY-----")
        head = "".join("%07d %s\n" % (i, "z" * 91) for i in range(5233))
        body = head + pem + "\n" + head.replace("z", "q")
        at = len(head)
        self.assertLess(at, copilot_cli.SIDE_PIECE)
        self.assertGreater(at + len(pem), copilot_cli.SIDE_PIECE)
        texts = self.side_texts(body.encode(), "cat ~/.ssh/id_rsa")
        self.assert_covered(body, texts)
        self.assertNotIn(pem, texts[0].node)
        self.assertEqual(findings(texts), {pem: {"~/.ssh/id_rsa"}})

    def test_a_multibyte_character_is_never_cut(self):
        # One ASCII byte first, so the cuts do not fall on whole characters
        # by luck. No line end anywhere, about 1.2 MB each.
        for n, char in enumerate(("é", "€", "\U0001F600")):
            size = len(char.encode("utf-8"))
            body = "x" + char * (1200000 // size)
            texts = self.side_texts(
                body.encode("utf-8"),
                name="179000000002%d-copilot-tool-output-u.txt" % n)
            self.assertGreater(len(texts), 1)
            for text in texts:
                self.assertLessEqual(set(text.node), {"x", char}, char)
            self.assertEqual(texts[0].node[0], "x")

    def test_only_a_copilot_output_file_named_in_a_result_is_opened(self):
        outside = self.saved("notes.txt", ("API_KEY=" + SECRET).encode())
        wrong_ext = self.saved("1790000000002-copilot-tool-output-q.log",
                               ("API_KEY=" + SECRET).encode())
        in_prose = self.saved("1790000000003-copilot-tool-output-p.txt",
                              ("API_KEY=" + SECRET).encode())
        missing = os.path.join(self.out, "1790000000004-copilot-tool-output-m.txt")
        log = (Log().start()
               .call("call_1", "bash", {"command": "ls"}, large_output(outside))
               .call("call_2", "bash", {"command": "ls"}, large_output(wrong_ext))
               .call("call_3", "bash", {"command": "ls"}, large_output(missing))
               .call("call_4", "bash", {"command": "ls"}, large_output(
                   "1790000000005-copilot-tool-output-r.txt"))   # relative
               .user("Saved to: " + in_prose, "2026-10-01T09:01:00.000Z"))
        self.write(log)
        spy = _OpenSpy()
        with spy:
            stores = self.stores()
            for store in stores:
                list(self.src.secret_texts(store))
        self.assertEqual([s.role for s in stores], ["transcript"])
        for path in (outside, wrong_ext, in_prose, missing):
            self.assertNotIn(path, spy.paths)

    def test_the_saved_path_runs_to_the_end_of_its_line(self):
        win = ("C:\\Users\\Jo Doe\\AppData\\Local\\Temp\\"
               "1774637043987-copilot-tool-output-tk7puw.txt")
        self.assertEqual(copilot_cli.saved_paths(large_output(win)), [win])
        posix = "/tmp/a b/1774637043987-copilot-tool-output-tk7puw.txt"
        self.assertEqual(copilot_cli.saved_paths(large_output(posix) + "\r\n"),
                         [posix])
        for other in ("/tmp/1774637043987-copilot-tool-output-tk7puw.txt.bak",
                      "/tmp/copilot-tool-output.txt", "/tmp/notes.txt",
                      # not <digits>-copilot-tool-output-<id>.txt
                      "/tmp/x-copilot-tool-output-tk7puw.txt",
                      "/tmp/-copilot-tool-output-tk7puw.txt",
                      "/tmp/1774637043987-copilot-tool-output-.txt",
                      "/tmp/1774637043987-copilot-tool-output-a b.txt",
                      "/tmp/1774637043987-copilot-tool-output-a"
                      "-copilot-tool-output-b.txt",
                      "/tmp/1774637043987-copilot-tool-output-tk7puw.TXT"):
            self.assertEqual(copilot_cli.saved_paths(large_output(other)), [],
                             other)
        upper = "/tmp/1774637043987-copilot-tool-output-Tk7.Puw.txt"
        self.assertEqual(copilot_cli.saved_paths(large_output(upper)), [upper])
        self.assertEqual(copilot_cli.saved_paths(None), [])

    def test_a_line_repeating_the_marker_costs_one_pass(self):
        # Every call that reads a result's saved paths, on a line of about
        # 2 MB that names "Saved to:" and then repeats the file-name marker
        # without ending in .txt.
        root = os.path.join(self.tmp, "marker")
        content = "Saved to: /" + "-copilot-tool-output-" * 100000 + "x"
        self.write(Log().start().call("call_1", "bash", {"command": "ls"},
                                      content), root=root)
        stores, calls, texts = _timed(self, root)
        self.assertEqual((stores, calls, texts), (1, 1, 4))

    @unittest.skipIf(WINDOWS, "symlinks need privileges on Windows")
    def test_a_symlink_is_not_followed(self):
        target = self.saved("secret.txt", ("API_KEY=" + SECRET).encode())
        link = os.path.join(self.out, "1790000000006-copilot-tool-output-s.txt")
        os.symlink(target, link)
        self.write(Log().start().call("call_1", "bash", {"command": "ls"},
                                      large_output(link)))
        self.assertEqual([s.role for s in self.stores()], ["transcript"])

    def test_side_file_masking_round_trip(self):
        body = ("line one\nAPI_KEY=" + SECRET + "\nlast\n").encode()
        side = self.saved("1790000000007-copilot-tool-output-k.txt", body)
        if not WINDOWS:
            os.chmod(side, 0o600)
            self.age(side, 3600)
        self.write(Log().start().call("call_1", "bash", {"command": "cat .env"},
                                      large_output(side)))
        [store] = [s for s in self.stores() if s.role == "side"]
        result = self.src.mask(store, [SECRET])
        self.assertTrue(result.changed, result)
        marker = clean.REDACTION % clean._fingerprint(SECRET)
        with open(side, "rb") as fh:
            self.assertEqual(fh.read(), body.replace(SECRET.encode(),
                                                     marker.encode()))
        with open(result.backup, "rb") as fh:
            self.assertEqual(fh.read(), body)
        if not WINDOWS:
            self.assertEqual(stat.S_IMODE(os.stat(side).st_mode), 0o600)


# --------------------------------------------------------------------------
# Tool calls
# --------------------------------------------------------------------------

class ToolCalls(CopilotCase):

    def test_the_spec_sample(self):
        call = self.one_call(spec_sample())
        self.assertEqual(
            (call.source, call.tool_name, call.kind, call.known, call.command,
             call.consumed, call.paths, call.workdir, call.tool_call_id,
             call.session, call.project, call.timestamp, call.actor,
             call.status, call.not_after),
            ("copilot-cli", "bash", "shell", True, "cat .env",
             frozenset({"command"}), (), None, "call_1", SID, "/home/dev/app",
             "2026-10-01T09:00:07Z", "agent", None, None))
        self.assertEqual(call.tool_input, {"command": "cat .env",
                                           "description": "Show the env file"})
        self.assertEqual(call.output,
                         "API_KEY=" + SECRET + "\n<exited with exit code 0>")
        self.assertIn("cred.read", rules(call))

    def test_a_dangerous_shell_call_is_flagged_with_its_target(self):
        log = (Log().start()
               .call("c1", "bash", {"command": "rm -rf ~/Documents/x",
                                    "description": "Remove it"}, "")
               .call("c2", "bash", {"command": "cat ~/.aws/credentials",
                                    "description": "Show creds"}, ""))
        self.write(log)
        found = {c.tool_call_id: judge(c)[0] for c in self.calls()}
        [rm] = found["c1"]
        self.assertEqual(rm["rule"], "fs.destructive")
        self.assertIn("~/Documents/x", rm["evidence"])
        [cat] = found["c2"]
        self.assertEqual(cat["rule"], "cred.read")
        self.assertIn("~/.aws/credentials", cat["evidence"])

    def test_view_of_a_private_key_is_flagged(self):
        call = self.one_call(Log().start().call(
            "c1", "view", {"path": "~/.ssh/id_rsa"}, "-----BEGIN"))
        self.assertEqual((call.kind, call.known, call.paths, call.consumed),
                         ("read", True, ("~/.ssh/id_rsa",), frozenset({"path"})))
        [hit] = judge(call)[0]
        self.assertEqual(hit["rule"], "cred.read")
        self.assertIn("~/.ssh/id_rsa", hit["evidence"])

    def test_precision_carries_over(self):
        log = (Log().start()
               .call("c1", "bash", {"command": "grep -rn 'rm -rf' .",
                                    "description": "Find rm -rf"}, "")
               .call("c2", "bash", {"command": "cat > notes.md <<'EOF'\n"
                                               "rm -rf /\nEOF",
                                    "description": "Write notes"}, "")
               .call("c3", "create", {"path": "/home/dev/app/clean.sh",
                                      "file_text": "#!/bin/sh\nrm -rf /\n"}, "")
               .call("c4", "edit", {"path": "/home/dev/app/clean.sh",
                                    "old_str": "echo", "new_str": "rm -rf /"},
                     ""))
        self.write(log)
        calls = self.calls()
        self.assertEqual(len(calls), 4)
        for call in calls:
            self.assertEqual(rules(call), [], call.tool_call_id)
        writes = [c for c in calls if c.kind == "write"]
        self.assertEqual([(c.paths, c.consumed) for c in writes],
                         [(("/home/dev/app/clean.sh",), frozenset())] * 2)

    def test_every_tool_name_in_the_spec(self):
        expected = {
            "bash": "shell", "powershell": "shell",
            "read_bash": "other", "write_bash": "other", "stop_bash": "other",
            "list_bash": "other", "read_powershell": "other",
            "write_powershell": "other", "stop_powershell": "other",
            "list_powershell": "other", "view": "read", "create": "write",
            "edit": "write", "apply_patch": "write", "web_fetch": "fetch",
            "grep": "other", "glob": "other", "task": "other",
            "skill": "other", "sql": "other", "ask_user": "other",
            "report_intent": "other"}
        args = {"command": "ls", "path": "/home/dev/app/a.txt",
                "file_text": "x", "old_str": "a", "new_str": "b",
                "url": "https://example.com", "pattern": "x"}
        log = Log().start()
        for i, name in enumerate(sorted(expected)):
            log.call("c%02d" % i, name, args, "ok")
        log.call("c99", "read_agent", {"agent_id": "a1"}, "ok")
        self.write(log)
        got = {c.tool_name: c for c in self.calls()}
        for name, kind in expected.items():
            self.assertEqual((got[name].kind, got[name].known), (kind, True),
                             name)
        self.assertEqual((got["read_agent"].kind, got["read_agent"].known),
                         ("other", False))
        self.assertEqual(got["apply_patch"].paths, ())      # arguments unverified
        self.assertEqual(got["web_fetch"].paths, ())
        self.assertEqual(got["write_bash"].command, None)
        self.assertEqual(got["bash"].command, "ls")

    def test_an_mcp_tool_named_bash_is_judged_by_name(self):
        args = {"command": "rm -rf ~/Documents/x"}
        log = Log().start()
        log.ask(T0, request("m1", "bash", args, mcpServerName="acme-tools",
                            mcpToolName="bash"))
        log.run(T0, "m1", "bash", args, mcpServerName="acme-tools",
                mcpToolName="bash")
        log.done(T0, "m1", "removed")
        call = self.one_call(log)
        self.assertEqual((call.kind, call.known, call.command, call.consumed),
                         ("other", False, None, frozenset()))
        self.assertEqual(rules(call), ["fs.destructive"])

    def test_a_request_with_no_execution_start_is_reported(self):
        log = (Log().start()
               .ask("2026-10-01T09:00:07.000Z",
                    request("call_9", "bash", {"command": "rm -rf ~/Documents/x",
                                               "description": "Remove"}))
               .user("stop", "2026-10-01T09:00:09.000Z"))
        call = self.one_call(log)
        self.assertEqual((call.tool_call_id, call.kind, call.command,
                          call.timestamp, call.status, call.output),
                         ("call_9", "shell", "rm -rf ~/Documents/x",
                          "2026-10-01T09:00:07Z", None, None))
        self.assertEqual(rules(call), ["fs.destructive"])

    def test_a_request_completed_without_a_start_gets_its_output(self):
        log = (Log().start()
               .ask("2026-10-01T09:00:07.000Z",
                    request("call_2", "view", {"path": "/home/dev/app/.env"}))
               .done("2026-10-01T09:00:08.000Z", "call_2", "API_KEY=1"))
        call = self.one_call(log)
        self.assertEqual((call.kind, call.output), ("read", "API_KEY=1"))

    def test_a_started_call_that_never_completed(self):
        log = Log().start().run("2026-10-01T09:00:07.000Z", "call_3", "bash",
                                {"command": "sleep 100"})
        call = self.one_call(log)
        self.assertEqual((call.command, call.output), ("sleep 100", None))

    def test_one_record_per_call_id(self):
        args = {"command": "cat .env", "description": "env"}
        log = (Log().start()
               .ask("2026-10-01T09:00:07.000Z", request("call_1", "bash", args))
               .run("2026-10-01T09:00:07.100Z", "call_1", "bash", args)
               .run("2026-10-01T09:00:07.200Z", "call_1", "bash", args)
               .done("2026-10-01T09:00:07.400Z", "call_1", "first")
               .done("2026-10-01T09:00:07.500Z", "call_1", "second")
               .ask("2026-10-01T09:00:08.000Z", request("call_1", "bash", args)))
        call = self.one_call(log)
        self.assertEqual((call.timestamp, call.output),
                         ("2026-10-01T09:00:07Z", "first"))

    def test_project_follows_the_latest_context(self):
        # session.start and session.resume hold the folder at
        # data.context.cwd. session.context_changed (after /cd or /cwd) has
        # the context itself as its data, so the folder is data.cwd
        # (copilot-sdk session-events.ts: ContextChangedEvent.data is a
        # WorkingDirectoryContext).
        log = (Log().start(cwd="/home/dev/app")
               .call("c1", "bash", {"command": "ls"}, "")
               .add("session.context_changed", {"cwd": "/home/dev/lib"}, T0)
               .call("c2", "bash", {"command": "ls"}, "")
               .add("session.resume", {"context": {"cwd": "/home/dev/api"}}, T0)
               .call("c3", "bash", {"command": "ls"}, "")
               .add("session.resume", {}, T0)
               .call("c4", "bash", {"command": "ls"}, "")
               # Not a context_changed's shape: no other key is tried.
               .add("session.context_changed",
                    {"context": {"cwd": "/home/dev/other"}}, T0)
               .call("c5", "bash", {"command": "ls"}, ""))
        self.write(log)
        self.assertEqual(self.only_store().project, "/home/dev/app")
        self.assertEqual([(c.tool_call_id, c.project) for c in self.calls()],
                         [("c1", "/home/dev/app"), ("c2", "/home/dev/lib"),
                          ("c3", "/home/dev/api"), ("c4", "/home/dev/api"),
                          ("c5", "/home/dev/api")])

    def test_a_change_of_folder_is_credited_to_the_next_call(self):
        log = (Log().start(cwd="/home/dev/app")
               .add("session.context_changed", {"cwd": "/home/dev/lib"}, T0)
               .call("c1", "bash", {"command": "ls"}, ""))
        self.assertEqual(self.one_call(log).project, "/home/dev/lib")

    def test_a_preliminary_change_already_names_the_new_folder(self):
        # A change of folder is sent twice: first with pendingGitContext
        # true, before the git context is resolved, then settled with it
        # (WorkingDirectoryContext.pendingGitContext). Both carry the new
        # cwd, so a call logged between the two is credited to the new
        # folder, and a log that ends before the settled event still has
        # the change.
        log = (Log().start(cwd="/home/dev/app")
               .add("session.context_changed",
                    {"cwd": "/home/dev/lib", "pendingGitContext": True}, T0)
               .call("c1", "bash", {"command": "ls"}, "")
               .add("session.context_changed",
                    {"cwd": "/home/dev/lib", "gitRoot": "/home/dev/lib",
                     "branch": "main"}, T0)
               .call("c2", "bash", {"command": "ls"}, "")
               .add("session.context_changed",
                    {"cwd": "/home/dev/api", "pendingGitContext": True}, T0)
               .call("c3", "bash", {"command": "ls"}, ""))
        self.write(log)
        self.assertEqual([(c.tool_call_id, c.project) for c in self.calls()],
                         [("c1", "/home/dev/lib"), ("c2", "/home/dev/lib"),
                          ("c3", "/home/dev/api")])

    def test_times_are_utc(self):
        log = Log().start()
        log.call("c1", "bash", {"command": "ls"}, "",
                 ts="2026-10-01T11:00:07.250+02:00")
        call = self.one_call(log)
        self.assertEqual(call.timestamp, "2026-10-01T09:00:07Z")

    def test_outputs_from_every_place_a_result_keeps_text(self):
        log = Log().start().run(T0, "c1", "bash", {"command": "make"})
        log.add("tool.execution_complete", {
            "toolCallId": "c1", "success": True,
            "result": {"content": "short", "detailedContent": "long form",
                       "contents": [{"type": "text", "text": "block"},
                                    {"type": "shell_exit", "exitCode": 0,
                                     "outputPreview": "preview"},
                                    {"type": "text", "text": "short"}]},
            "shellExecution": {"exitCode": 0}}, T0)
        log.run(T0, "c2", "bash", {"command": "false"})
        log.add("tool.execution_complete", {
            "toolCallId": "c2", "success": False,
            "error": {"message": "failed", "code": "E1"}}, T0)
        self.write(log)
        got = {c.tool_call_id: c.output for c in self.calls()}
        self.assertEqual(got, {"c1": "short\nlong form\nblock\npreview",
                               "c2": None})

    def test_many_output_blocks_cost_one_pass(self):
        # An MCP tool can return many blocks; each distinct one is kept
        # once, without comparing it to every block before it.
        def result(n):
            blocks = [{"type": "text", "text": "%07d" % i} for i in range(n)]
            blocks.append({"type": "text", "text": "%07d" % 0})
            return {"toolCallId": "c1", "success": True,
                    "result": {"content": "%07d" % 1, "contents": blocks}}
        self.assertEqual(copilot_cli._output(result(50)),
                         "\n".join("%07d" % i
                                   for i in [1, 0] + list(range(2, 50))))
        data = result(100000)
        root = os.path.join(self.tmp, "blocks")
        log = Log().start().run(T0, "c1", "bash", {"command": "ls"})
        log.add("tool.execution_complete", data, T0)
        self.write(log, root=root)
        self.assertEqual(_timed(self, root), (1, 1, 3))

    def test_powershell_on_windows(self):
        log = Log().start(cwd="C:\\Users\\dev\\app")
        log.call("c1", "powershell", {"command": "Get-Content .env",
                                      "description": "Show env"},
                 "API_KEY=1\r\n<exited with exit code 0>")
        log.call("c2", "read_powershell", {"sessionId": "s1"}, "")
        self.write(log)
        calls = {c.tool_call_id: c for c in self.calls()}
        ps = calls["c1"]
        self.assertEqual((ps.kind, ps.command, ps.project),
                         ("shell", "Get-Content .env", "C:\\Users\\dev\\app"))
        self.assertEqual(rules(ps), ["cred.read"])
        self.assertEqual((calls["c2"].kind, calls["c2"].known), ("other", True))

    def test_a_raw_line_separator_does_not_split_a_record(self):
        command = "echo 'a\u2028b\u2029c' > notes.txt"
        log = Log().start().call("c1", "bash", {"command": command}, "ok")
        path = self.write(log)
        with open(path, "rb") as fh:
            self.assertIn("\u2028".encode("utf-8"), fh.read())
        call = self.one_call(log)
        self.assertEqual(call.command, command)
        self.assertEqual(self.src.counts["unparsed"], 0)

    def test_a_shell_call_without_a_command_is_counted(self):
        log = Log().start().call("c1", "bash", {"description": "nothing"}, "")
        call = self.one_call(log)
        self.assertEqual((call.kind, call.known, call.command), ("shell", True,
                                                                  None))
        self.assertEqual(rules(call), [])
        self.assertEqual(self.src.counts["unreadable_calls"], 1)

    def test_arguments_given_as_a_json_string_are_decoded(self):
        log = Log().start().call("c1", "bash", json.dumps({"command": "ls"}), "")
        self.assertEqual(self.one_call(log).command, "ls")


# --------------------------------------------------------------------------
# Secrets
# --------------------------------------------------------------------------

class Secrets(CopilotCase):

    def test_a_key_read_from_env_is_found_once_with_its_origin(self):
        log = spec_sample()
        log.call("call_2", "bash", {"command": "cat .env | head -1"},
                 "API_KEY=" + SECRET)
        log.call("call_3", "bash",
                 {"command": "export STRIPE_KEY=" + TYPED + " && npm test"}, "ok")
        self.write(log)
        texts = list(self.src.secret_texts(self.only_store()))
        self.assertEqual(findings(texts), {SECRET: {".env"}, TYPED: set()})
        typed = [t for t in texts if TYPED in json.dumps(t.node)]
        self.assertTrue(typed)
        self.assertTrue(all(t.call is None for t in typed))

    def test_every_line_is_yielded(self):
        log = spec_sample().add("session.compaction_complete",
                                {"summary": "TOKEN=" + SECRET}, T0)
        data = log.data() + b"not json " + SECRET.encode() + b"\n[1, 2]\n"
        self.write(data)
        texts = list(self.src.secret_texts(self.only_store()))
        self.assertEqual([t.where for t in texts],
                         ["line %d" % n for n in range(1, 9)])
        self.assertEqual(texts[6].node, "not json " + SECRET)
        self.assertEqual(texts[4].call.tool_call_id, "call_1")
        self.assertEqual(texts[4].call.output,
                         "API_KEY=" + SECRET + "\n<exited with exit code 0>")
        self.assertIsNone(texts[5].call)
        self.assertEqual(self.src.counts, dict.fromkeys(self.src.counts, 0))

    def test_a_repeated_result_is_still_credited_to_its_call(self):
        log = spec_sample().done(T0, "call_1", "API_KEY=" + SECRET)
        self.write(log)
        texts = list(self.src.secret_texts(self.only_store()))
        self.assertEqual(texts[-1].call.command, "cat .env")
        self.assertIsNone(texts[-1].call.output)
        self.assertEqual(findings(texts), {SECRET: {".env"}})


# --------------------------------------------------------------------------
# Masking
# --------------------------------------------------------------------------

class Masking(CopilotCase):

    def masked_session(self):
        log = (spec_sample()
               .user("keep this\u2028line " + SECRET, "2026-10-01T09:01:00.000Z")
               .call("call_2", "view", {"path": "/home/dev/app/.env"},
                     "1. API_KEY=" + SECRET + "\n2. caf\u00e9"))
        return log.data()

    def test_round_trip(self):
        original = self.masked_session()
        path = self.write(original)
        if not WINDOWS:
            os.chmod(path, 0o640)
            self.age(path, 3600)
        store = self.only_store()
        before = self.calls(store)
        result = self.src.mask(store, [SECRET])
        self.assertEqual((result.path, result.changed, result.skipped),
                         (path, True, None))
        marker = clean.REDACTION % clean._fingerprint(SECRET)
        with open(path, "rb") as fh:
            after = fh.read()
        self.assertEqual(after, original.replace(SECRET.encode(),
                                                 marker.encode()))
        text = after.decode("utf-8")
        self.assertEqual([f for f in _rewrite.encodings(SECRET) if f in text], [])
        for raw in after.split(b"\n")[:-1]:
            json.loads(raw.decode("utf-8"))
        self.assertEqual(after.count(b"\n"), original.count(b"\n"))
        calls = self.calls(store)
        self.assertEqual(
            [(c.tool_call_id, c.tool_name, c.kind, c.command, c.paths,
              c.timestamp, c.project) for c in calls],
            [(c.tool_call_id, c.tool_name, c.kind, c.command, c.paths,
              c.timestamp, c.project) for c in before])
        self.assertEqual([c.output for c in calls],
                         [c.output.replace(SECRET, marker) for c in before])
        with open(result.backup, "rb") as fh:
            self.assertEqual(fh.read(), original)
        if not WINDOWS:
            self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o640)
        self.assertEqual(self.src.mask(store, [SECRET]), MaskResult(path))
        with open(path, "rb") as fh:
            self.assertEqual(fh.read(), after)

    def test_a_file_written_in_the_last_two_minutes_is_in_use(self):
        path = self.write(self.masked_session(), age=5)
        digest = _sha(path)
        result = self.src.mask(self.only_store(), [SECRET])
        self.assertEqual(result, MaskResult(path, skipped="in use"))
        self.assertEqual(_sha(path), digest)

    def test_a_live_lock_blocks_masking_and_a_dead_one_does_not(self):
        path = self.write(self.masked_session())
        digest = _sha(path)
        folder = os.path.dirname(path)
        live = os.path.join(folder, "inuse.%d.lock" % os.getpid())
        with open(live, "wb"):
            pass
        store = self.only_store()
        self.assertTrue(self.src.in_use(store))
        self.assertEqual(self.src.mask(store, [SECRET]),
                         MaskResult(path, skipped="in use"))
        self.assertEqual(_sha(path), digest)
        os.unlink(live)
        dead = subprocess.Popen([sys.executable, "-c", "pass"])
        dead.wait(timeout=20)
        with open(os.path.join(folder, "inuse.%d.lock" % dead.pid), "wb"):
            pass
        self.assertFalse(self.src.in_use(store))
        self.assertTrue(self.src.mask(store, [SECRET]).changed)

    def test_a_side_store_is_never_in_use_by_lock(self):
        store = Store("copilot-cli", os.path.join(self.tmp, "x.txt"), "text",
                      role="side")
        self.assertFalse(self.src.in_use(store))


# --------------------------------------------------------------------------
# Files that do not parse, and reading only
# --------------------------------------------------------------------------

class Robustness(CopilotCase):

    def test_a_partial_last_line_is_skipped_quietly(self):
        data = spec_sample().data() + b'{"type":"tool.execution_start","data":{"tool'
        self.write(data)
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            calls = self.calls()
            texts = list(self.src.secret_texts(self.only_store()))
        self.assertEqual([c.tool_call_id for c in calls], ["call_1"])
        self.assertEqual(len(texts), 6)
        self.assertEqual(err.getvalue(), "")
        self.assertEqual(self.src.counts["unparsed"], 0)

    def test_a_garbage_store_warns_once_and_the_others_are_read(self):
        self.write(b"\x00\xff garbage {not json\n" * 50, sid="a-bad", age=60)
        self.write(spec_sample(), sid="b-good", age=120)
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            found = {}
            for store in self.stores():
                found[store.session] = [c.tool_call_id
                                        for c in self.src.tool_calls(store)]
                list(self.src.secret_texts(store))
        self.assertEqual(found, {"a-bad": [], "b-good": ["call_1"]})
        self.assertEqual(err.getvalue().count("warning:"), 1)
        self.assertEqual(self.src.counts["unparsed"], 50)
        self.assertEqual(self.src.counts["unreadable_stores"], 1)

    def test_a_store_that_cannot_be_opened_warns_once(self):
        gone = Store("copilot-cli", os.path.join(self.tmp, "gone.jsonl"), "jsonl")
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(list(self.src.tool_calls(gone)), [])
            self.assertEqual(list(self.src.secret_texts(gone)), [])
        self.assertEqual(err.getvalue().count("warning:"), 1)

    def test_unknown_records_are_ignored(self):
        log = spec_sample().add("assistant.reasoning", {"content": "hm"}, T0)
        data = log.data() + b'["not", "an", "event"]\n{"data": {}}\n'
        self.write(data)
        self.assertEqual([c.tool_call_id for c in self.calls()], ["call_1"])
        self.assertEqual(self.src.counts["unknown"], 2)

    def test_reading_changes_nothing(self):
        side = os.path.join(self.tmp, "1790000000008-copilot-tool-output-z.txt")
        with open(side, "wb") as fh:
            fh.write(("API_KEY=" + SECRET).encode())
        path = self.write(spec_sample().call("c2", "bash", {"command": "ls"},
                                             large_output(side)))
        with open(os.path.join(os.path.dirname(path),
                               "inuse.%d.lock" % os.getpid()), "wb"):
            pass
        before, side_before = _tree(self.root), _sha(side)
        listing = sorted(os.listdir(self.tmp))
        self.src.locations()
        for store in self.stores():
            list(self.src.tool_calls(store))
            list(self.src.secret_texts(store))
            self.src.in_use(store)
        self.assertEqual(_tree(self.root), before)
        self.assertEqual(_sha(side), side_before)
        self.assertEqual(sorted(os.listdir(self.tmp)), listing)


# --------------------------------------------------------------------------
# The --days window
# --------------------------------------------------------------------------

class Window(CopilotCase):

    def test_each_call_keeps_its_own_time(self):
        log = Log().start(ts="2025-01-05T10:00:00.000Z")
        log.call("old", "bash", {"command": "ls"}, "",
                 ts="2025-01-05T10:00:01.000Z")
        log.call("new", "bash", {"command": "ls"}, "",
                 ts="2026-10-01T09:00:00.000Z")
        log.run(None, "undated", "bash", {"command": "pwd"})
        path = self.write(log, age=60)
        [store] = self.stores(since_days=30)       # written a minute ago
        calls = {c.tool_call_id: c for c in self.src.tool_calls(store)}
        self.assertEqual(calls["old"].timestamp, "2025-01-05T10:00:01Z")
        self.assertEqual(calls["new"].timestamp, "2026-10-01T09:00:00Z")
        undated = calls["undated"]
        self.assertIsNone(undated.timestamp)
        self.assertEqual(undated.not_after,
                         time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                       time.gmtime(os.stat(path).st_mtime)))
        self.assertIsNone(calls["old"].not_after)


# --------------------------------------------------------------------------
# A large session log
# --------------------------------------------------------------------------

_TIMED = r"""
import os, sys, time
sys.path.insert(0, sys.argv[1])
from ranwhat.sources.copilot_cli import CopilotCliSource
src = CopilotCliSource()
t0 = time.time()
stores = src.stores(src.locations(override=sys.argv[2]))
calls = sum(1 for s in stores for c in src.tool_calls(s))
texts = sum(1 for s in stores for t in src.secret_texts(s))
print(len(stores), calls, texts, round(time.time() - t0, 2))
"""


def _timed(case, root):
    """(stores, calls, texts) from _TIMED run on `root` in a subprocess
    that must finish within 20 seconds."""
    env = dict(os.environ, HOME=case.home, USERPROFILE=case.home)
    env.pop("COPILOT_HOME", None)
    try:
        done = subprocess.run([sys.executable, "-c", _TIMED, REPO, root],
                              capture_output=True, text=True, encoding="utf-8",
                              env=env, timeout=20)
    except subprocess.TimeoutExpired:
        case.fail("reading %s took more than 20 seconds" % root)
    case.assertEqual(done.returncode, 0, done.stderr)
    stores, calls, texts, _seconds = done.stdout.split()
    return int(stores), int(calls), int(texts)


class LargeFile(CopilotCase):

    def test_a_large_log_is_read_in_time(self):
        root = os.path.join(self.tmp, "big")
        folder = os.path.join(root, "session-state", SID)
        os.makedirs(folder)
        n = 12000
        out = ("x" * 700 + "\n") * 2 + "API_KEY=" + SECRET
        with open(os.path.join(folder, "events.jsonl"), "wb") as fh:
            log = Log().start()
            fh.write(log.data())
            for i in range(n):
                args = {"command": "cat file%d.txt" % i, "description": "Read"}
                cid = "call_%d" % i
                ts = "2026-10-01T09:00:07.000Z"
                event = Log()
                event.ask(ts, request(cid, "bash", args))
                event.run(ts, cid, "bash", args)
                event.done(ts, cid, out)
                fh.write(event.data())
        size = os.path.getsize(os.path.join(folder, "events.jsonl"))
        self.assertGreater(size, 20 * 1024 * 1024)
        env = dict(os.environ, HOME=self.home, USERPROFILE=self.home)
        done = subprocess.run([sys.executable, "-c", _TIMED, REPO, root],
                              capture_output=True, text=True, encoding="utf-8",
                              env=env, timeout=20)
        self.assertEqual(done.returncode, 0, done.stderr)
        stores, calls, texts, _seconds = done.stdout.split()
        self.assertEqual((stores, calls, texts),
                         ("1", str(n), str(1 + 3 * n)))


if __name__ == "__main__":
    unittest.main()
