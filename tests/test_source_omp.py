"""The Oh My Pi adapter (ranwhat/sources/omp.py).

Fixtures are built field for field from omp's own sources and docs (tag
v18.12.3 and main: docs/session.md, session-title-slot.ts, session-paths.ts,
dirs.ts, agent-loop.ts, tools/bash.ts, read.ts, write.ts, edit/schemas.ts):
a 256-byte title slot, the version 3 header on line 2, "message" entries of
a tree whose assistant messages hold toolCall blocks and whose toolResult
messages answer them, bashExecution and pythonExecution messages, and the
"custom" entries (tool_execution_start, session_exit) that copy a call's
arguments elsewhere in the file. Older format versions are built as omp
migrates them: version 2 says "hookMessage" where 3 says "custom", version
1 has no version, id or parentId, and a file from before v16.2.3 has no
title slot. The builders are test_source_pi's, which are Pi's, the format
omp forked.

Everything runs in temp directories: the home directory, omp's own
environment variables and clean's backup root all point there, and the real
home is never read. Every secret is synthetic.
"""
import json
import os
import sys
import time
import unittest
from unittest import mock

TESTS = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(TESTS)
sys.path.insert(0, REPO)
sys.path.insert(0, TESTS)

import test_source_pi as tp  # noqa: E402
from ranwhat import watch  # noqa: E402
from ranwhat.sources import _rewrite  # noqa: E402
from ranwhat.sources import omp as omp_module  # noqa: E402
from ranwhat.sources.base import MaskResult  # noqa: E402
from ranwhat.sources.omp import OhMyPiSource, classify  # noqa: E402
from ranwhat.sources.pi import PiSource  # noqa: E402

ENV = "PI_CODING_AGENT_DIR"
SESSION_ENV = "PI_CODING_AGENT_SESSION_DIR"
CONFIG_ENV = "PI_CONFIG_DIR"
XDG_DATA = "XDG_DATA_HOME"
XDG_STATE = "XDG_STATE_HOME"
WINDOWS = os.name == "nt"

SECRET = tp.SECRET
SID = "019a0b1c-7d2e-7000-8000-3f6a1c2b9d10"
FOLDER = "--home-alice-work-api--"
NAME = "2026-10-20T09-14-03-112Z_" + SID + ".jsonl"
CWD = "/home/alice/work/api"
BASE_MS = tp.BASE_MS

dump = tp._dump
entry = tp.entry
assistant = tp.assistant
tool_call = tp.tool_call
tool_result = tp.tool_result
call_lines = tp.call_lines
header = tp.header
eid = tp.eid


def slot(title="FIX: failing auth tests"):
    """The title slot, as serializeTitleSlot writes it: one JSON object,
    padded with spaces so that the line is 255 bytes and its newline makes
    256 (session-title-slot.ts)."""
    row = {"type": "title", "v": 1, "title": title, "source": "auto",
           "updatedAt": tp._iso(BASE_MS), "pad": ""}
    row["pad"] = " " * (255 - len(dump(row).encode("utf-8")))
    line = dump(row)
    assert len(line.encode("utf-8")) == 255, len(line.encode("utf-8"))
    return line


def head(**kw):
    """The slot and the header, the two first lines of a current file."""
    return [slot(), header(sid=SID, cwd=CWD, **kw)]


def synthetic(cid, name, source, ms, text="Tool call was not executed because "
              "the assistant ended its turn."):
    """The result agent-loop.ts writes for a call it will not run."""
    return tool_result(cid, name, text, ms, is_error=True, details={
        "__synthetic": True, "source": source, "executed": False})


def python_execution(code, output, ms, exit_code=0):
    """Python the user ran with "$" (tui/src/chat/messages.ts)."""
    return {"role": "pythonExecution", "code": code, "output": output,
            "exitCode": exit_code, "cancelled": False, "truncated": False,
            "timestamp": ms}


def custom(n, kind, data):
    """A "custom" entry (agent-session.ts, exit-diagnostics.ts)."""
    return {"type": "custom", "id": eid(n), "parentId": eid(n - 1),
            "timestamp": tp._iso(BASE_MS + n * 1000), "customType": kind,
            "data": data}


def sample():
    """The example in the research, from the source: a bash call with its
    result, a start record, a write that never ran, a "!" command."""
    return head() + [
        entry(1, assistant([tool_call("toolu_01AbC", "bash", {
            "command": "npm test -- auth", "cwd": "packages/api"})],
            BASE_MS + 1000)),
        custom(2, "tool_execution_start", {
            "toolCallId": "toolu_01AbC", "toolName": "bash",
            "startedAt": tp._iso(BASE_MS + 2000),
            "args": {"command": "npm test -- auth"}}),
        entry(3, tool_result("toolu_01AbC", "bash", "PASS auth.test.ts ...",
                             BASE_MS + 3000, details={"wallTimeMs": 4851})),
        entry(4, assistant([tool_call("toolu_01XyZ", "write", {
            "path": "src/auth.ts", "content": "x"})], BASE_MS + 4000)),
        entry(5, synthetic("toolu_01XyZ", "write", "assistant_stop_skipped",
                           BASE_MS + 5000)),
        entry(6, tp.bash_execution("git status", "On branch main ...",
                                   BASE_MS + 6000)),
    ]


class OmpCase(tp.PiCase):

    def setUp(self):
        tp.PiCase.setUp(self)
        for name in (CONFIG_ENV, XDG_DATA, XDG_STATE, "OMP_PROFILE",
                     "PI_PROFILE"):
            os.environ.pop(name, None)
        self.root = os.path.join(self.home, ".omp", "agent")
        self.omp = OhMyPiSource()
        self.pi = self.omp          # the helpers of PiCase read self.pi

    def other(self, name):
        """A temp directory beside the home directory."""
        return tp._tempdir(self, name)


# --------------------------------------------------------------------------
# where omp keeps its history
# --------------------------------------------------------------------------

class DefaultPaths(unittest.TestCase):

    def test_each_platform(self):
        p = OhMyPiSource()
        self.assertEqual(p.default_paths({}, "/Users/u", "darwin")[0],
                         ("/Users/u/.omp/agent", "default"))
        self.assertEqual(p.default_paths({}, "/home/u", "linux")[0],
                         ("/home/u/.omp/agent", "default"))
        self.assertEqual(p.default_paths({}, "C:\\Users\\u", "win32")[0],
                         ("C:\\Users\\u\\.omp\\agent", "default"))

    def test_profiles_are_looked_at_beside_the_default(self):
        p = OhMyPiSource()
        self.assertEqual(
            p.default_paths({}, "/home/u", "linux"),
            [("/home/u/.omp/agent", "default"),
             ("/home/u/.omp/profiles", "default profiles")])
        self.assertEqual(
            p.default_paths({}, "C:\\Users\\u", "win32")[1],
            ("C:\\Users\\u\\.omp\\profiles", "default profiles"))

    def test_the_config_dir_variable_replaces_the_folder_name(self):
        p = OhMyPiSource()
        got = p.default_paths({CONFIG_ENV: ".omp-work"}, "/home/u", "linux")
        self.assertEqual(got[0], ("/home/u/.omp-work/agent", "default"))
        self.assertEqual(got[1], ("/home/u/.omp-work/profiles",
                                  "default profiles"))
        got = p.default_paths({CONFIG_ENV: ".omp-work"}, "C:\\Users\\u",
                              "win32")
        self.assertEqual(got[0], ("C:\\Users\\u\\.omp-work\\agent", "default"))
        # always joined under home, as Node's path.join does
        got = p.default_paths({CONFIG_ENV: "/srv/omp"}, "/home/u", "linux")
        self.assertEqual(got[0][0], "/home/u/srv/omp/agent")

    def test_the_agent_dir_variable_comes_first_and_is_not_expanded(self):
        p = OhMyPiSource()
        how = "env " + ENV
        got = p.default_paths({ENV: "/srv/omp"}, "/home/u", "linux")
        self.assertEqual(got[0], ("/srv/omp", how))
        self.assertIn(("/home/u/.omp/agent", "default"), got)
        self.assertEqual(
            p.default_paths({ENV: "D:\\omp"}, "C:\\Users\\u", "win32")[0],
            ("D:\\omp", how))
        # omp uses path.resolve: a "~" is kept as written
        self.assertEqual(
            p.default_paths({ENV: "~/omp"}, "/home/u", "linux")[0],
            ("~/omp", how))

    def test_the_session_dir_variable_is_looked_at_beside_the_agent_folder(self):
        p = OhMyPiSource()
        got = p.default_paths({SESSION_ENV: "/srv/s"}, "/home/u", "linux")
        self.assertEqual(got[-1], ("/srv/s", "env " + SESSION_ENV))
        self.assertEqual(got[0], ("/home/u/.omp/agent", "default"))
        got = p.default_paths({SESSION_ENV: "E:\\s"}, "C:\\Users\\u", "win32")
        self.assertEqual(got[-1], ("E:\\s", "env " + SESSION_ENV))

    def test_xdg_on_linux_and_macos_when_the_variable_is_set(self):
        p = OhMyPiSource()
        env = {XDG_DATA: "/x/data", XDG_STATE: "/x/state"}
        for platform in ("linux", "darwin"):
            self.assertEqual(
                p.default_paths(env, "/home/u", platform),
                [("/x/data/omp", "env " + XDG_DATA),
                 ("/home/u/.omp/agent", "default"),
                 ("/home/u/.omp/profiles", "default profiles"),
                 ("/x/data/omp/profiles", "env " + XDG_DATA + " profiles"),
                 ("/x/state/omp", "env " + XDG_STATE)])

    def test_xdg_is_never_applied_on_windows(self):
        got = OhMyPiSource().default_paths(
            {XDG_DATA: "C:\\d", XDG_STATE: "C:\\s"}, "C:\\Users\\u", "win32")
        self.assertEqual([how for _p, how in got],
                         ["default", "default profiles"])

    def test_the_agent_dir_variable_turns_xdg_off_for_the_default_profile(self):
        got = OhMyPiSource().default_paths(
            {ENV: "/srv/omp", XDG_DATA: "/x/data"}, "/home/u", "linux")
        self.assertNotIn(("/x/data/omp", "env " + XDG_DATA), got)
        self.assertIn(("/x/data/omp/profiles", "env " + XDG_DATA + " profiles"),
                      got)

    def test_an_empty_variable_is_not_set(self):
        env = {ENV: "", SESSION_ENV: "", CONFIG_ENV: "", XDG_DATA: "",
               XDG_STATE: ""}
        self.assertEqual(
            [how for _p, how in
             OhMyPiSource().default_paths(env, "/home/u", "linux")],
            ["default", "default profiles"])
        self.assertEqual(
            OhMyPiSource().default_paths(env, "/home/u", "linux")[0][0],
            "/home/u/.omp/agent")

    def test_what_every_report_needs(self):
        p = OhMyPiSource()
        self.assertEqual((p.id, p.name, p.unit), ("omp", "Oh My Pi",
                                                  "session"))
        for name in (ENV, SESSION_ENV, CONFIG_ENV, XDG_DATA):
            self.assertIn(name, p.env)
        self.assertIn(ENV, p.path_means)
        self.assertEqual(p.checked, "18.12.3")
        for text in (p.path_means, p.mask_note):
            self.assertNotIn("\u2014", text)
        self.assertIn("close", p.mask_note)

    def test_path_keys_are_watchs_own(self):
        self.assertEqual(omp_module.PATH_KEYS, watch._PATH_KEYS)


class Discovery(OmpCase):

    def test_a_current_session_is_found_with_its_header_on_line_2(self):
        path = self.write("sessions/%s/%s" % (FOLDER, NAME), sample())
        [store] = self.stores()
        self.assertEqual((store.path, store.source, store.format, store.role,
                          store.unit, store.session, store.project,
                          store.masking),
                         (path, "omp", "jsonl", "transcript", "session",
                          SID, CWD, "rewrite"))

    def test_a_file_from_before_the_title_slot_is_found_too(self):
        self.write("sessions/%s/%s" % (FOLDER, NAME),
                   [header(sid=SID, cwd=CWD)])
        [store] = self.stores()
        self.assertEqual((store.session, store.project), (SID, CWD))

    def test_the_session_comes_from_the_name_when_there_is_no_header(self):
        self.write("sessions/%s/%s" % (FOLDER, NAME), [slot()])
        [store] = self.stores()
        self.assertEqual((store.session, store.project), (SID, None))

    def test_the_agent_dir_variable_is_read_at_call_time(self):
        elsewhere = self.other("omp-agent-")
        self.write("sessions/%s/%s" % (FOLDER, NAME), head(), root=elsewhere)
        self.assertEqual(self.stores(), [])
        os.environ[ENV] = elsewhere
        [store] = self.stores()
        self.assertTrue(store.path.startswith(elsewhere))
        self.assertEqual([l.how for l in self.omp.locations()][0],
                         "env " + ENV)

    def test_the_config_dir_variable_moves_the_default(self):
        root = os.path.join(self.home, ".omp-work", "agent")
        self.write("sessions/%s/%s" % (FOLDER, NAME), head(), root=root)
        self.assertEqual(self.stores(), [])
        os.environ[CONFIG_ENV] = ".omp-work"
        self.assertEqual(len(self.stores()), 1)

    @unittest.skipIf(WINDOWS, "XDG is never applied on Windows")
    def test_xdg_data_home_drops_the_agent_prefix_and_keeps_the_old_folder(self):
        xdg = self.other("omp-xdg-")
        moved = os.path.join(xdg, "omp")
        self.write("sessions/%s/%s" % (FOLDER, NAME), head(), root=moved)
        old = "2026-09-01T09-00-00-000Z_old.jsonl"
        self.write("sessions/%s/%s" % (FOLDER, old), head())
        os.environ[XDG_DATA] = xdg
        got = sorted(s.session for s in self.stores())
        self.assertEqual(got, sorted([SID, SID]))
        self.assertEqual(len(self.stores()), 2)
        hows = [l.how for l in self.omp.locations() if l.found]
        self.assertEqual(sorted(hows), sorted(["env " + XDG_DATA, "default"]))

    @unittest.skipIf(WINDOWS, "XDG is never applied on Windows")
    def test_an_xdg_folder_that_does_not_exist_is_not_a_store(self):
        os.environ[XDG_DATA] = os.path.join(self.home, "nowhere")
        by_how = {l.how: l for l in self.omp.locations()}
        self.assertFalse(by_how["env " + XDG_DATA].exists)
        self.assertEqual(self.stores(), [])

    def test_every_profile_is_read(self):
        for name in ("work", "play"):
            root = os.path.join(self.home, ".omp", "profiles", name, "agent")
            self.write("sessions/%s/2026-10-20T09-14-03-112Z_%s.jsonl"
                       % (FOLDER, name), head(), root=root)
        self.write("sessions/%s/%s" % (FOLDER, NAME), head())
        self.assertEqual(sorted(s.session for s in self.stores()),
                         sorted([SID, SID, SID]))
        paths = sorted(s.path for s in self.stores())
        self.assertEqual(len([p for p in paths if os.sep + "profiles" + os.sep
                              in p]), 2)

    @unittest.skipIf(WINDOWS, "XDG is never applied on Windows")
    def test_profiles_under_xdg_have_no_agent_folder(self):
        xdg = self.other("omp-xdg-")
        root = os.path.join(xdg, "omp", "profiles", "work")
        self.write("sessions/%s/%s" % (FOLDER, NAME), head(), root=root)
        os.environ[XDG_DATA] = xdg
        self.assertEqual(len(self.stores()), 1)

    def test_subagent_transcripts_in_the_artifact_folder_are_found(self):
        stem = NAME[:-len(".jsonl")]
        self.write("sessions/%s/%s" % (FOLDER, NAME), head())
        sub = "sessions/%s/%s/" % (FOLDER, stem)
        self.write(sub + "Explore.jsonl", [header(sid="sub-1", cwd=CWD)])
        self.write(sub + "Explore.Review.jsonl", [header(sid=None, cwd=CWD)])
        self.write(sub + "__advisor.jsonl", [])
        self.write(sub + "1.bash.log", ["not a transcript"])   # a side store
        self.write(sub + "abc.md", ["# not a transcript"])
        self.write(sub + "draft.txt", ["x"])
        names = sorted(os.path.basename(s.path) for s in self.stores()
                       if s.role == "transcript")
        self.assertEqual(names, sorted([NAME, "Explore.jsonl",
                                        "Explore.Review.jsonl",
                                        "__advisor.jsonl"]))
        by = {os.path.basename(s.path): s for s in self.stores()}
        self.assertEqual(by["Explore.jsonl"].session, "sub-1")
        # no header id: the session it belongs to
        self.assertEqual(by["Explore.Review.jsonl"].session, SID)
        self.assertEqual(by["__advisor.jsonl"].session, SID)

    def test_a_subagent_call_is_read_like_any_other(self):
        stem = NAME[:-len(".jsonl")]
        path = self.write(
            "sessions/%s/%s/Explore.jsonl" % (FOLDER, stem),
            [header(sid="sub-1", cwd=CWD)] + call_lines(
                1, "c1", "bash", {"command": "ls -la"}, output="x"))
        [call] = self.calls(path)
        self.assertEqual((call.command, call.session, call.project),
                         ("ls -la", "sub-1", CWD))

    def test_dot_files_and_other_suffixes_are_not_sessions(self):
        self.write("sessions/%s/.hidden.jsonl" % FOLDER, head())
        self.write("sessions/%s/notes.txt" % FOLDER, ["x"])
        self.write("sessions/%s/%s.gz" % (FOLDER, NAME), ["x"])
        self.write("blobs/abcdef", ["x"])
        self.write("history.db", ["x"])
        self.write("archive/sessions/%s/%s.gz" % (FOLDER, NAME), ["x"])
        self.assertEqual(self.stores(), [])

    def test_sessions_are_found_newest_first(self):
        old = self.write("sessions/%s/2026-01-01T00-00-00-000Z_a.jsonl"
                         % FOLDER, head(), age=9 * 86400)
        new = self.write("sessions/%s/2026-10-01T00-00-00-000Z_b.jsonl"
                         % FOLDER, head(), age=60)
        self.assertEqual([s.path for s in self.stores()], [new, old])
        self.assertEqual([s.path for s in self.stores(since_days=2)], [new])

    def test_a_missing_root_is_zero_stores(self):
        locations = self.omp.locations()
        self.assertTrue(locations)
        self.assertFalse(any(l.exists for l in locations))
        self.assertEqual(self.stores(), [])

    def test_an_empty_store_is_a_store_with_no_calls(self):
        path = self.write("sessions/%s/%s" % (FOLDER, NAME), [])
        self.assertEqual(self.calls(path), [])
        self.assertEqual(list(self.omp.secret_texts(self.store(path))), [])

    def test_the_path_option_is_an_agent_folder(self):
        elsewhere = self.other("omp-given-")
        self.write("sessions/%s/%s" % (FOLDER, NAME), head(), root=elsewhere)
        # a file without a slot is omp's too when the user names the folder
        self.write("sessions/%s/2026-01-01T00-00-00-000Z_b.jsonl" % FOLDER,
                   [header(sid="b")], root=elsewhere)
        self.assertEqual(len(self.stores(override=elsewhere)), 2)


class SharedWithPi(OmpCase):
    """PI_CODING_AGENT_DIR and PI_CODING_AGENT_SESSION_DIR are Pi's too: in
    those folders a file is omp's only when it starts with the slot."""

    def test_a_flat_session_dir_takes_only_files_with_the_slot(self):
        flat = self.other("omp-flat-")
        mine = self.write(NAME, head(), root=flat)
        self.write("2026-10-01T09-00-00-000Z_pi.jsonl",
                   [header(sid="pi-1", cwd=CWD)], root=flat)
        self.write("2026-10-02T09-00-00-000Z_old.jsonl", [], root=flat)
        os.environ[SESSION_ENV] = flat
        self.assertEqual([s.path for s in self.stores()], [mine])
        self.assertTrue(omp_module.is_title_slot_file(mine))
        self.assertFalse(omp_module.is_title_slot_file(
            os.path.join(flat, "2026-10-01T09-00-00-000Z_pi.jsonl")))
        self.assertFalse(omp_module.is_title_slot_file(
            os.path.join(flat, "missing.jsonl")))

    def test_a_shared_agent_dir_takes_only_files_with_the_slot(self):
        shared = self.other("omp-shared-")
        mine = self.write("sessions/%s/%s" % (FOLDER, NAME), head(),
                          root=shared)
        self.write("sessions/%s/2026-10-01T09-00-00-000Z_pi.jsonl" % FOLDER,
                   [header(sid="pi-1", cwd=CWD)], root=shared)
        os.environ[ENV] = shared
        self.assertEqual([s.path for s in self.stores()], [mine])

    def test_the_session_dir_may_name_the_agent_folder(self):
        shared = self.other("omp-shared-")
        mine = self.write("sessions/%s/%s" % (FOLDER, NAME), head(),
                          root=shared)
        flat = self.write(NAME.replace("112Z", "999Z"), head(), root=shared)
        os.environ[ENV] = shared
        os.environ[SESSION_ENV] = shared
        self.assertEqual(sorted(s.path for s in self.stores()),
                         sorted([mine, flat]))

    def test_the_default_folder_is_omps_whatever_its_first_line(self):
        self.write("sessions/%s/%s" % (FOLDER, NAME), [header(sid=SID)])
        self.assertEqual(len(self.stores()), 1)

    def test_pi_still_reads_its_own_folder_and_not_omps(self):
        self.write("sessions/%s/%s" % (FOLDER, NAME), head())
        self.assertEqual(PiSource().stores(PiSource().locations()), [])


class CustomSessionFiles(OmpCase):

    def marker(self, name, text, root=None):
        return self.write("custom-session-files/" + name, [], root=root,
                          raw=text.encode("utf-8"))

    def test_a_transcript_outside_the_sessions_folder_is_found_by_its_marker(self):
        elsewhere = self.other("omp-custom-")
        target = self.write(NAME, [header(sid=SID, cwd=CWD)], root=elsewhere)
        self.marker("h1", target)
        [store] = self.stores()
        self.assertEqual((store.path, store.session, store.project),
                         (target, SID, CWD))

    def test_a_marker_for_a_file_already_found_adds_nothing(self):
        flat = self.other("omp-flat-")
        target = self.write(NAME, head(), root=flat)
        self.marker("h1", target)
        os.environ[SESSION_ENV] = flat
        self.assertEqual([s.path for s in self.stores()], [target])

    def test_markers_that_name_nothing_usable_are_ignored(self):
        elsewhere = self.other("omp-custom-")
        real = self.write("x.jsonl", head(), root=elsewhere)
        self.marker("gone", os.path.join(elsewhere, "gone.jsonl"))
        self.marker("relative", "x.jsonl")
        self.marker("not-jsonl", os.path.join(elsewhere, "x.txt"))
        self.marker("big", real + " " * 5000)
        self.marker("multi", real + "\nfoo")
        self.marker("empty", "")
        self.assertEqual(self.stores(), [])
        self.marker("good", real + "\n")
        self.assertEqual([s.path for s in self.stores()], [real])

    @unittest.skipIf(WINDOWS, "XDG is never applied on Windows")
    def test_the_marker_folder_moves_to_xdg_state(self):
        state = self.other("omp-state-")
        elsewhere = self.other("omp-custom-")
        target = self.write(NAME, head(), root=elsewhere)
        self.marker("h1", target, root=os.path.join(state, "omp"))
        os.environ[XDG_STATE] = state
        self.assertEqual([s.path for s in self.stores()], [target])


# --------------------------------------------------------------------------
# tool calls
# --------------------------------------------------------------------------

class ToolCalls(OmpCase):

    def test_the_source_derived_sample(self):
        path = self.write("sessions/%s/%s" % (FOLDER, NAME), sample())
        calls = self.calls(path)
        self.assertEqual([(c.tool_call_id, c.tool_name, c.kind, c.actor,
                           c.status) for c in calls],
                         [("toolu_01AbC", "bash", "shell", "agent", None),
                          ("toolu_01XyZ", "write", "write", "agent",
                           "declined"),
                          (eid(6), "bashExecution", "shell", "user", None)])
        first = calls[0]
        self.assertEqual((first.command, first.workdir, first.output,
                          first.consumed, first.known, first.source),
                         ("npm test -- auth", "packages/api",
                          "PASS auth.test.ts ...", frozenset(["command"]),
                          True, "omp"))
        self.assertEqual((first.session, first.project, first.timestamp),
                         (SID, CWD, "2026-10-01T09:00:01Z"))
        self.assertEqual(calls[1].paths, ("src/auth.ts",))
        self.assertEqual((calls[2].command, calls[2].output),
                         ("git status", "On branch main ..."))

    def test_the_tool_execution_start_copy_is_not_a_call(self):
        lines = head() + [
            custom(1, "tool_execution_start", {
                "toolCallId": "t1", "toolName": "bash",
                "args": {"command": "rm -rf /"}}),
            custom(2, "session_exit", {
                "reason": "sigint", "kind": "signal", "recordedAt": "x",
                "pendingToolCalls": [{"toolCallId": "t1", "toolName": "bash",
                                      "args": {"command": "rm -rf /"}}]})]
        path = self.write("sessions/%s/%s" % (FOLDER, NAME), lines)
        self.assertEqual(self.calls(path), [])
        self.assertEqual(self.omp.counts["unknown"], 0)

    def test_a_call_with_no_result_is_still_reported(self):
        path = self.write("sessions/%s/%s" % (FOLDER, NAME), head() +
                          call_lines(1, "c1", "bash", {"command": "make"}))
        [call] = self.calls(path)
        self.assertEqual((call.command, call.output, call.status),
                         ("make", None, None))

    def test_every_mapped_tool(self):
        for name, args, expect in (
                ("bash", {"command": "ls"}, ("shell", "ls", ())),
                ("eval", {"language": "py", "code": "print(1)"},
                 ("shell", "print(1)", ())),
                ("read", {"path": "a.txt"}, ("read", None, ("a.txt",))),
                ("write", {"path": "a.txt", "content": "x"},
                 ("write", None, ("a.txt",))),
                ("edit", {"path": "a.txt", "old_string": "a",
                          "new_string": "b"}, ("write", None, ("a.txt",)))):
            kind, known, command, paths, _consumed, _wd = classify(name, args)
            self.assertEqual((kind, command, paths), expect, name)
            self.assertTrue(known)

    def test_a_tool_the_adapter_does_not_know_is_other(self):
        for name in ("grep", "ast_edit", "task", "web_search",
                     "mcp__github_create_issue", "lsp"):
            kind, known, command, paths, consumed, wd = classify(
                name, {"command": "x", "path": "y"})
            self.assertEqual((kind, known, command, paths, consumed, wd),
                             ("other", False, None, (), (), None))

    def test_a_bash_call_without_a_command(self):
        kind, known, command, _p, consumed, wd = classify("bash", {})
        self.assertEqual((kind, known, command, consumed, wd),
                         ("shell", True, None, (), None))
        self.assertEqual(classify("bash", {"command": 5})[2], None)
        self.assertEqual(classify("eval", {"code": ""})[2], None)

    def test_read_selectors_are_dropped(self):
        for given, expect in (
                ("src/a.ts:10-20", ("src/a.ts",)),
                ("src/a.ts:-5", ("src/a.ts",)),
                ("src/a.ts:12", ("src/a.ts",)),
                ("src/a.ts:raw", ("src/a.ts",)),
                ("logo.png:img", ("logo.png",)),
                ("src/a.ts:conflicts", ("src/a.ts",)),
                ("src/a.ts:10-20:raw", ("src/a.ts",)),
                (".env:1-3", (".env",)),
                ("C:\\work\\a.ts:5-9", ("C:\\work\\a.ts",)),
                ("C:\\work\\a.ts", ("C:\\work\\a.ts",)),
                ("a:b.txt", ("a:b.txt",)),
                ("@.env", ("@.env", ".env")),
                ("@.env:1-2", ("@.env", ".env"))):
            self.assertEqual(classify("read", {"path": given})[3], expect,
                             given)

    def test_internal_uris_name_no_file_and_urls_are_fetches(self):
        for uri in ("artifact://12", "local://notes.md", "agent://Explore",
                    "history://3"):
            kind, known, _c, paths, _k, _w = classify("read", {"path": uri})
            self.assertEqual((kind, known, paths), ("read", True, ()), uri)
        kind, known, _c, paths, _k, _w = classify(
            "read", {"path": "https://example.com/a"})
        self.assertEqual((kind, known, paths), ("fetch", True, ()))

    def test_a_read_takes_whichever_of_watchs_path_keys_it_holds(self):
        paths = classify("read", {"file_path": "a", "paths": ["b", "c:1-2"],
                                  "path": "d"})[3]
        self.assertEqual(paths, ("a", "d", "b", "c"))
        self.assertEqual(classify("read", {})[3], ())

    def test_the_edit_forms(self):
        self.assertEqual(
            classify("edit", {"path": "a.py", "edits": [
                {"op": "update", "diff": "@@"},
                {"op": "update", "rename": "b.py", "diff": "@@"},
                {"op": "delete"}, "junk", None]})[3], ("a.py", "b.py"))
        patch = ("*** Begin Patch\n*** Add File: new.txt\n+hi\n"
                 "*** Update File: src/a.py\n*** Move to: src/b.py\n"
                 "*** Delete File: old.txt\n*** End Patch\n")
        kind, known, _c, paths, _k, _w = classify("edit", {"input": patch})
        self.assertEqual((kind, known, paths), (
            "write", True, ("new.txt", "src/a.py", "src/b.py", "old.txt")))
        # hashline and sloppy bodies are not documented: a write, no path
        kind, known, _c, paths, _k, _w = classify(
            "edit", {"input": "some other body"})
        self.assertEqual((kind, known, paths), ("write", True, ()))

    def test_a_huge_patch_is_read_in_linear_time_and_capped(self):
        patch = "".join("*** Add File: f%d\n" % i for i in range(5000))
        paths = classify("edit", {"input": patch})[3]
        self.assertEqual(len(paths), 256)
        t = time.time()
        classify("edit", {"input": "*** Update File: " + "x" * 2000000})
        classify("read", {"path": "a" + ":1" * 200000})
        self.assertLess(time.time() - t, 5)

    def test_arguments_stored_as_a_string_are_decoded(self):
        lines = head() + call_lines(1, "c1", "bash",
                                    json.dumps({"command": "id"}),
                                    output="uid")
        path = self.write("sessions/%s/%s" % (FOLDER, NAME), lines)
        [call] = self.calls(path)
        self.assertEqual((call.command, call.tool_input), (
            "id", {"command": "id"}))

    def test_a_call_in_each_tool_end_to_end(self):
        lines = head()
        lines += call_lines(1, "r", "read", {"path": ".env:1-4"}, output="K=1")
        lines += call_lines(3, "w", "write", {"path": "a.txt", "content": "x"},
                            output="ok")
        lines += call_lines(5, "e", "edit", {"path": "a.txt",
                                             "old_string": "x",
                                             "new_string": "y"}, output="ok")
        lines += call_lines(7, "v", "eval", {"language": "py",
                                             "code": "open('x')"}, output="")
        lines += call_lines(9, "g", "grep", {"pattern": "x"}, output="a:1")
        path = self.write("sessions/%s/%s" % (FOLDER, NAME), lines)
        by = self.by_id(path)
        self.assertEqual(by["r"].paths, (".env",))
        self.assertEqual(by["r"].kind, "read")
        self.assertEqual(by["w"].kind, "write")
        self.assertEqual(by["e"].paths, ("a.txt",))
        self.assertEqual((by["v"].kind, by["v"].command), ("shell",
                                                            "open('x')"))
        self.assertEqual((by["g"].kind, by["g"].known), ("other", False))

    def test_a_command_the_user_ran_with_a_bang_and_a_dollar(self):
        lines = head() + [
            entry(1, tp.bash_execution("cat .env", "K=1", BASE_MS + 1000,
                                       exit_code=1, cancelled=True)),
            entry(2, python_execution("import os\nos.system('id')", "uid=0",
                                      BASE_MS + 2000)),
            entry(3, python_execution("print(1)", None, BASE_MS + 3000,
                                      exit_code=None))]
        path = self.write("sessions/%s/%s" % (FOLDER, NAME), lines)
        bang, dollar, bare = self.calls(path)
        self.assertEqual((bang.tool_name, bang.actor, bang.kind, bang.command,
                          bang.output, bang.status),
                         ("bashExecution", "user", "shell", "cat .env", "K=1",
                          None))
        self.assertEqual((dollar.tool_name, dollar.actor, dollar.kind,
                          dollar.command, dollar.output,
                          dollar.consumed, dollar.tool_input),
                         ("pythonExecution", "user", "shell",
                          "import os\nos.system('id')", "uid=0",
                          frozenset(["code"]),
                          {"code": "import os\nos.system('id')"}))
        self.assertEqual(bare.output, None)
        self.assertEqual(self.omp.counts["unknown"], 0)

    def test_both_branches_of_a_tree_and_dedupe_by_id(self):
        lines = head() + call_lines(1, "c1", "bash", {"command": "a"},
                                    output="1")
        lines += call_lines(3, "c2", "bash", {"command": "b"}, output="2",
                            parent=eid(1))
        lines += call_lines(5, "c1", "bash", {"command": "a"}, output="1")
        path = self.write("sessions/%s/%s" % (FOLDER, NAME), lines)
        self.assertEqual([c.tool_call_id for c in self.calls(path)],
                         ["c1", "c2"])

    def test_time_is_utc_with_the_message_time_as_a_fallback(self):
        lines = head() + [
            entry(1, assistant([tool_call("a", "bash", {"command": "x"})],
                               BASE_MS + 1000)),
            entry(2, assistant([tool_call("b", "bash", {"command": "y"})],
                               BASE_MS + 2000), ts=False)]
        path = self.write("sessions/%s/%s" % (FOLDER, NAME), lines)
        by = self.by_id(path)
        self.assertEqual(by["a"].timestamp, "2026-10-01T09:00:01Z")
        self.assertEqual(by["b"].timestamp, "2026-10-01T09:00:02Z")

    def test_nothing_else_in_the_file_is_a_call(self):
        lines = head() + [
            {"type": "model_usage", "id": eid(1), "parentId": None},
            {"type": "service_tier_change", "id": eid(2), "parentId": eid(1)},
            {"type": "reset_boundary", "id": eid(3), "parentId": eid(2)},
            {"type": "title_change", "id": eid(4), "parentId": eid(3),
             "title": "t", "source": "auto"},
            {"type": "ttsr_injection", "id": eid(5), "parentId": eid(4)},
            {"type": "credential_pin", "id": eid(6), "parentId": eid(5)},
            {"type": "session_init", "id": eid(7), "parentId": eid(6)},
            {"type": "mode_change", "id": eid(8), "parentId": eid(7)},
            {"type": "model_change", "id": eid(9), "parentId": eid(8)},
            {"type": "thinking_level_change", "id": eid(10)},
            {"type": "compaction", "id": eid(11), "summary": "s"},
            {"type": "branch_summary", "id": eid(12), "summary": "s"},
            {"type": "label", "id": eid(13)},
            {"type": "custom_message", "id": eid(14)},
            entry(15, tp.user("hi", BASE_MS)),
            entry(16, {"role": "developer", "content": "be nice",
                       "timestamp": BASE_MS}),
            entry(17, {"role": "fileMention", "files": [],
                       "timestamp": BASE_MS}),
            entry(18, {"role": "custom", "customType": "x", "content": "c",
                       "timestamp": BASE_MS})]
        path = self.write("sessions/%s/%s" % (FOLDER, NAME), lines)
        self.assertEqual(self.calls(path), [])
        self.assertEqual(self.omp.counts["unknown"], 0)

    def test_pi_only_types_and_new_roles_are_counted_unknown(self):
        lines = head() + [
            {"type": "usage", "id": eid(1)},
            {"type": "session_info", "id": eid(2)},
            {"type": "context_edit", "id": eid(3)},
            {"type": "brand_new", "id": eid(4)},
            entry(5, {"role": "robot", "timestamp": BASE_MS}),
            ["not", "an", "object"]]
        path = self.write("sessions/%s/%s" % (FOLDER, NAME), lines)
        self.calls(path)
        self.assertEqual(self.omp.counts["unknown"], 6)


class FormatVersions(OmpCase):

    def test_version_3_with_and_without_the_title_slot(self):
        for first in (head(), [header(sid=SID, cwd=CWD)]):
            path = self.write("sessions/%s/%s" % (FOLDER, NAME), first +
                              call_lines(1, "c", "bash", {"command": "ls"},
                                         output="x"))
            [call] = self.calls(path)
            self.assertEqual((call.command, call.session, call.project),
                             ("ls", SID, CWD))

    def test_version_2_says_hook_message_where_3_says_custom(self):
        lines = head(version=2) + [
            entry(1, {"role": "hookMessage", "customType": "x",
                      "content": "c", "display": True,
                      "timestamp": BASE_MS})] + call_lines(
            2, "c", "bash", {"command": "ls"}, output="x")
        path = self.write("sessions/%s/%s" % (FOLDER, NAME), lines)
        [call] = self.calls(path)
        self.assertEqual(call.command, "ls")
        self.assertEqual(self.omp.counts["unknown"], 0)

    def test_version_1_has_no_version_id_or_parent(self):
        lines = [header(sid=SID, cwd=CWD, version=None)] + call_lines(
            1, "c", "bash", {"command": "ls"}, output="x", tree=False)
        path = self.write("sessions/%s/%s" % (FOLDER, NAME), lines)
        [call] = self.calls(path)
        self.assertEqual((call.command, call.output, call.session),
                         ("ls", "x", SID))

    def test_a_version_1_file_with_a_slot_in_front(self):
        lines = head(version=None) + call_lines(
            1, "c", "bash", {"command": "ls"}, output="x", tree=False)
        path = self.write("sessions/%s/%s" % (FOLDER, NAME), lines)
        self.assertEqual(len(self.calls(path)), 1)


# --------------------------------------------------------------------------
# calls that never ran
# --------------------------------------------------------------------------

class Declined(OmpCase):

    def run_one(self, result, stop="toolUse", name="write", args=None):
        args = args or {"path": "a.txt", "content": "x"}
        lines = head() + [
            entry(1, assistant([tool_call("c1", name, args)], BASE_MS, stop=stop)),
            entry(2, result)]
        path = self.write("sessions/%s/%s" % (FOLDER, NAME), lines)
        return self.by_id(path)["c1"]

    def test_every_synthetic_source_is_declined(self):
        for source in ("assistant_stop_aborted", "assistant_stop_error",
                       "assistant_stop_length", "assistant_stop_skipped",
                       "interrupt_skipped"):
            call = self.run_one(synthetic("c1", "write", source, BASE_MS))
            self.assertEqual(call.status, "declined", source)

    def test_executed_false_alone_is_declined(self):
        call = self.run_one(tool_result("c1", "write", "no", BASE_MS,
                                        is_error=True,
                                        details={"executed": False}))
        self.assertEqual(call.status, "declined")

    def test_a_call_interrupted_after_it_started_did_run(self):
        call = self.run_one(tool_result(
            "c1", "bash", "Command interrupted", BASE_MS, is_error=True,
            details={"__interrupted": True, "source": "interrupt_skipped",
                     "execution": "started"}), name="bash",
            args={"command": "sleep 100"})
        self.assertEqual(call.status, None)

    def test_a_synthetic_result_that_says_it_ran_did(self):
        call = self.run_one(tool_result("c1", "write", "x", BASE_MS,
                                        details={"__synthetic": True,
                                                 "executed": True}))
        self.assertEqual(call.status, None)

    def test_a_normal_result_with_unrelated_details_ran(self):
        call = self.run_one(tool_result("c1", "write", "wrote", BASE_MS,
                                        details={"wallTimeMs": 3}))
        self.assertEqual(call.status, None)
        call = self.run_one(tool_result("c1", "write", "oops", BASE_MS,
                                        is_error=True))
        self.assertEqual(call.status, None)

    def test_tool_not_found_with_and_without_a_suggestion(self):
        for text, declined in (
                ("Tool frobnicate not found", True),
                ("Tool frobnicate not found. Did you mean grep?", True),
                ("Tool frobnicate not found. Closest available: grep, find",
                 True),
                ("Tool frobnicate not foundation", False),
                ("Tool other not found", False)):
            call = self.run_one(tool_result("c1", "frobnicate", text, BASE_MS,
                                            is_error=True), name="frobnicate",
                                args={})
            self.assertEqual(call.status, "declined" if declined else None,
                             text)

    def test_a_not_found_text_that_a_command_printed_ran(self):
        call = self.run_one(tool_result(
            "c1", "bash", "Tool bash not found", BASE_MS, is_error=False),
            name="bash", args={"command": "echo 'Tool bash not found'"})
        self.assertEqual(call.status, None)

    def test_pi_s_own_texts_are_still_declined(self):
        call = self.run_one(tool_result(
            "c1", "write", "Tool execution was blocked", BASE_MS,
            is_error=True))
        self.assertEqual(call.status, "declined")
        call = self.run_one(tool_result(
            "c1", "write",
            'Tool call "write" was not executed: the response hit the output '
            'token limit, so its arguments may be truncated.', BASE_MS,
            is_error=True), stop="length")
        self.assertEqual(call.status, "declined")

    def test_a_message_stopped_by_an_abort_or_an_error_ran_nothing(self):
        for stop in ("aborted", "error"):
            call = self.run_one(tool_result("c1", "write", "x", BASE_MS),
                                stop=stop)
            self.assertEqual(call.status, "declined", stop)

    def test_a_declined_call_is_still_judged_by_its_input(self):
        call = self.run_one(synthetic("c1", "bash", "assistant_stop_skipped",
                                      BASE_MS), name="bash",
                            args={"command": "rm -rf /"})
        self.assertEqual(call.status, "declined")
        self.assertTrue(tp.rules(call))


class Judged(OmpCase):

    def one(self, name, args, output="x"):
        lines = head() + call_lines(1, "c", name, args, output=output)
        path = self.write("sessions/%s/%s" % (FOLDER, NAME), lines)
        return self.calls(path)[0]

    def test_a_dangerous_shell_call_is_flagged(self):
        self.assertTrue(tp.rules(self.one("bash", {"command": "rm -rf /"})))

    def test_a_credential_read_with_a_selector_is_flagged(self):
        self.assertTrue(tp.rules(self.one("read", {"path": ".env:1-4"})))
        self.assertTrue(tp.rules(self.one("read", {"path": "@.env"})))
        self.assertTrue(tp.rules(self.one(
            "read", {"path": "/home/alice/.ssh/id_rsa:raw"})))

    def test_a_dangerous_eval_is_flagged_as_code_that_runs(self):
        call = self.one("eval", {"language": "py", "code":
                                 "import os; os.system('rm -rf /')"})
        self.assertTrue(tp.rules(call))

    def test_a_dangerous_python_the_user_ran_is_flagged(self):
        lines = head() + [entry(1, python_execution(
            "import os; os.system('rm -rf /')", "", BASE_MS))]
        path = self.write("sessions/%s/%s" % (FOLDER, NAME), lines)
        [call] = self.calls(path)
        self.assertTrue(tp.rules(call))

    def test_a_harmless_call_is_not(self):
        self.assertEqual(tp.rules(self.one("bash", {"command": "ls"})), [])
        self.assertEqual(tp.rules(self.one("read", {"path": "src/a.ts:5"})),
                         [])


# --------------------------------------------------------------------------
# secrets and masking
# --------------------------------------------------------------------------

class Secrets(OmpCase):

    def lines(self):
        return head() + call_lines(
            1, "c", "bash", {"command": "cat .env"},
            output="STRIPE_KEY=" + SECRET) + [
            custom(3, "tool_execution_start", {
                "toolCallId": "c", "toolName": "bash",
                "args": {"command": "curl -u me:" + SECRET}}),
            custom(4, "session_exit", {
                "reason": "x", "kind": "y", "recordedAt": "z",
                "pendingToolCalls": [{"toolCallId": "d", "toolName": "bash",
                                      "args": {"command": "echo " + SECRET}}]}),
            entry(5, tp.bash_execution("cat .env", "K=" + SECRET,
                                       BASE_MS + 5000)),
            entry(6, python_execution("print(open('.env').read())",
                                      "K=" + SECRET, BASE_MS + 6000))]

    def test_output_after_cat_env_is_tied_to_its_call(self):
        path = self.write("sessions/%s/%s" % (FOLDER, NAME), self.lines())
        found = tp.findings(self.omp, [self.store(path)])
        self.assertIn(SECRET, found)
        self.assertGreaterEqual(found[SECRET]["count"], 4)
        self.assertIn(".env", found[SECRET]["origins"])

    def test_every_line_reaches_clean_including_the_copies_and_the_slot(self):
        path = self.write("sessions/%s/%s" % (FOLDER, NAME), self.lines())
        texts = list(self.omp.secret_texts(self.store(path)))
        wheres = [t.where for t in texts]
        self.assertIn("line 1", wheres)             # the title slot
        self.assertIn("line 2", wheres)             # the header
        joined = json.dumps([t.node for t in texts])
        self.assertIn("curl -u me:", joined)        # tool_execution_start
        self.assertIn("pendingToolCalls", joined)   # session_exit
        tied = [t for t in texts if t.call is not None]
        self.assertEqual(sorted(t.call.tool_name for t in tied),
                         ["bash", "bashExecution", "pythonExecution"])

    def test_a_line_that_is_not_json_is_handed_over_as_text(self):
        path = self.write("sessions/%s/%s" % (FOLDER, NAME), head() + [
            "garbage " + SECRET])
        texts = list(self.omp.secret_texts(self.store(path)))
        self.assertIn("garbage " + SECRET, [t.node for t in texts])


class Masking(OmpCase):

    def session(self, lines=None, **kw):
        return self.write("sessions/%s/%s" % (FOLDER, NAME),
                          lines if lines is not None else Secrets.lines(self),
                          mode=0o600, **kw)

    def test_round_trip_keeps_the_slot_byte_for_byte(self):
        path = self.session()
        with open(path, "rb") as fh:
            original = fh.read()
        self.assertEqual(original.index(b"\n") + 1, 256)
        before = list(self.omp.tool_calls(self.store(path)))
        result = self.omp.mask(self.store(path), [SECRET])
        self.assertEqual((result.path, result.changed, result.skipped),
                         (path, True, None))
        with open(path, "rb") as fh:
            after = fh.read()
        marker = tp._marker(SECRET)
        self.assertEqual(after, original.replace(SECRET.encode(),
                                                 marker.encode()))
        self.assertEqual(after[:256], original[:256])
        self.assertEqual(after.index(b"\n") + 1, 256)
        for line in after.decode("utf-8").split("\n"):
            if line:
                json.loads(line)
        self.assertEqual([f for f in _rewrite.encodings(SECRET)
                          if f in after.decode("utf-8")], [])
        again = list(self.omp.tool_calls(self.store(path)))
        self.assertEqual([c.tool_call_id for c in again],
                         [c.tool_call_id for c in before])
        self.assertEqual(tp.findings(self.omp, [self.store(path)]), {})
        with open(result.backup, "rb") as fh:
            self.assertEqual(fh.read(), original)
        # a second run changes nothing
        self.assertEqual(self.omp.mask(self.store(path), [SECRET]),
                         MaskResult(path))

    def test_a_secret_in_the_title_slot_refuses_the_file(self):
        lines = [slot("fix " + SECRET)] + self.lines_without_slot()
        path = self.session(lines)
        digest = tp._sha(path)
        result = self.omp.mask(self.store(path), [SECRET])
        self.assertEqual(result, MaskResult(
            path, skipped="would alter more than the secret"))
        self.assertEqual(tp._sha(path), digest)
        self.assertFalse(os.path.exists(self.backups))

    def lines_without_slot(self):
        return Secrets.lines(self)[1:]

    def test_a_value_that_is_not_in_the_slot_masks_the_rest(self):
        lines = [slot("fix auth")] + self.lines_without_slot()
        path = self.session(lines)
        self.assertTrue(self.omp.mask(self.store(path), [SECRET]).changed)
        with open(path, "rb") as fh:
            self.assertIn(b'"title":"fix auth"', fh.read(256))

    def test_a_file_written_just_now_is_in_use(self):
        path = self.session(age=5)
        digest = tp._sha(path)
        self.assertEqual(self.omp.mask(self.store(path), [SECRET]),
                         MaskResult(path, skipped="in use"))
        self.assertEqual(tp._sha(path), digest)

    def test_a_file_without_a_slot_masks_as_pi_does(self):
        path = self.session(self.lines_without_slot())
        self.assertTrue(self.omp.mask(self.store(path), [SECRET]).changed)

    def test_nothing_to_mask_is_a_no_op(self):
        path = self.session()
        digest = tp._sha(path)
        self.assertEqual(self.omp.mask(self.store(path), []),
                         MaskResult(path))
        self.assertEqual(self.omp.mask(self.store(path), ["", None]),
                         MaskResult(path))
        self.assertEqual(tp._sha(path), digest)


# --------------------------------------------------------------------------
# damaged, huge and odd files
# --------------------------------------------------------------------------

class Damaged(OmpCase):

    def good(self):
        return [l if isinstance(l, str) else dump(l) for l in
                head() + call_lines(1, "c1", "bash", {"command": "ls"},
                                    output="x")]

    def test_a_malformed_line_in_the_middle_is_counted_not_fatal(self):
        lines = self.good()
        lines.insert(3, '{"type":"message","id":')
        lines += [dump(l) for l in call_lines(3, "c2", "bash",
                                              {"command": "pwd"}, output="/")]
        path = self.write("sessions/%s/%s" % (FOLDER, NAME), lines)
        self.assertEqual([c.command for c in self.calls(path)], ["ls", "pwd"])
        self.assertEqual(self.omp.counts["unparsed"], 1)

    def test_a_truncated_last_line_is_skipped_quietly(self):
        text = "".join(l + "\n" for l in self.good())
        extra = dump(call_lines(3, "c2", "bash", {"command": "pwd"})[0])
        path = self.write("sessions/%s/%s" % (FOLDER, NAME), [],
                          raw=(text + extra[:len(extra) // 2]).encode())
        self.assertEqual([c.command for c in self.calls(path)], ["ls"])
        self.assertEqual(self.omp.counts["unparsed"], 0)

    def test_a_file_cut_inside_the_title_slot(self):
        path = self.write("sessions/%s/%s" % (FOLDER, NAME), [],
                          raw=slot().encode()[:100])
        [store] = self.stores()
        self.assertEqual(store.session, SID)
        self.assertEqual(self.calls(path), [])

    def test_a_file_cut_in_the_header(self):
        path = self.write("sessions/%s/%s" % (FOLDER, NAME), [],
                          raw=(slot() + "\n" + dump(header(sid=SID))[:20])
                          .encode())
        [store] = self.stores()
        self.assertEqual((store.session, store.project), (SID, None))
        self.assertEqual(self.calls(path), [])

    def test_garbage_warns_once_and_other_stores_are_still_read(self):
        bad = self.write("sessions/%s/2026-10-01T00-00-00-000Z_bad.jsonl"
                         % FOLDER, [], raw=b"\x00\xff\xfe garbage\n{no\n" * 4)
        ok = self.write("sessions/%s/%s" % (FOLDER, NAME), self.good())
        import contextlib
        import io
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(self.calls(bad), [])
            self.assertEqual(self.calls(bad), [])
        self.assertEqual(err.getvalue().count("warning"), 1)
        self.assertEqual(len(self.calls(ok)), 1)
        self.assertEqual(self.omp.counts["unreadable_stores"], 1)

    def test_non_utf8_bytes_are_read_and_survive_masking(self):
        raw = ((slot() + "\n").encode() + (dump(header(sid=SID)) + "\n").encode()
               + (dump(call_lines(1, "c", "bash", {"command": "cat f"})[0])
                  + "\n").encode()
               + (dump(call_lines(1, "c", "bash", {"command": "x"},
                                  output="bad \x00 " + SECRET)[1])
                  + "\n").encode().replace(b"bad", b"b\xff\xfed"))
        path = self.write("sessions/%s/%s" % (FOLDER, NAME), [], raw=raw,
                          mode=0o600)
        [call] = self.calls(path)
        self.assertEqual(call.command, "cat f")
        self.assertIn(SECRET, call.output)
        self.assertTrue(self.omp.mask(self.store(path), [SECRET]).changed)
        with open(path, "rb") as fh:
            self.assertIn(b"b\xff\xfed", fh.read())

    def test_a_byte_order_mark_and_crlf_endings_are_read(self):
        text = "\ufeff" + "\r\n".join(self.good()) + "\r\n"
        path = self.write("sessions/%s/%s" % (FOLDER, NAME), [],
                          raw=text.encode("utf-8"))
        self.assertEqual([c.command for c in self.calls(path)], ["ls"])

    def test_a_vanished_store_warns_once(self):
        path = self.write("sessions/%s/%s" % (FOLDER, NAME), self.good())
        store = self.store(path)
        os.unlink(path)
        import contextlib
        import io
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(list(self.omp.tool_calls(store)), [])
            self.assertEqual(list(self.omp.tool_calls(store)), [])
        self.assertEqual(err.getvalue().count("warning"), 1)

    def test_a_directory_named_like_a_session_is_not_a_store(self):
        os.makedirs(os.path.join(self.root, "sessions", FOLDER,
                                 "x.jsonl"))
        self.assertEqual(self.stores(), [])

    def test_an_oversized_line_and_an_oversized_first_line(self):
        big = "x" * (6 * 1024 * 1024)
        lines = [slot(), dump(header(sid=SID, cwd=CWD))]
        lines += [dump(l) for l in call_lines(1, "c1", "bash",
                                              {"command": "cat big"},
                                              output=big)]
        lines += [dump(l) for l in call_lines(3, "c2", "bash",
                                              {"command": "pwd"}, output="/")]
        path = self.write("sessions/%s/%s" % (FOLDER, NAME), lines)
        t = time.time()
        by = self.by_id(path)
        self.assertEqual(len(by["c1"].output), len(big))
        self.assertEqual(by["c2"].command, "pwd")
        self.assertLess(time.time() - t, 20)
        # a first line longer than the header reader looks at: the session
        # still comes from the name, the transcript is still read
        path2 = self.write(
            "sessions/%s/2026-10-02T00-00-00-000Z_long.jsonl" % FOLDER, [],
            raw=(("{\"type\":\"title\",\"pad\":\"" + " " * 200000 + "\"}\n")
                 + dump(header(sid="h")) + "\n").encode())
        by_path = {s.path: s for s in self.stores()}
        self.assertEqual(by_path[path2].session, "long")

    def test_deeply_nested_json_does_not_stop_the_read(self):
        deep = "[" * 100000 + "]" * 100000
        lines = self.good()
        lines.insert(3, '{"type":"message","message":' + deep + "}")
        path = self.write("sessions/%s/%s" % (FOLDER, NAME), lines)
        self.assertEqual(len(self.calls(path)), 1)

    def test_an_empty_first_line_and_blank_lines(self):
        path = self.write("sessions/%s/%s" % (FOLDER, NAME),
                          [""] + self.good() + ["", "   "])
        self.assertEqual(len(self.calls(path)), 1)


class Environment(OmpCase):

    def test_no_home_directory_and_no_variables_is_not_an_error(self):
        with mock.patch.dict(os.environ, {"HOME": "/nonexistent/x"}):
            self.assertTrue(self.omp.locations())
            self.assertEqual(self.stores(), [])

    def test_a_variable_pointing_nowhere_is_a_location_that_does_not_exist(self):
        os.environ[ENV] = os.path.join(self.home, "nowhere")
        os.environ[SESSION_ENV] = os.path.join(self.home, "nowhere2")
        locations = self.omp.locations()
        self.assertEqual(self.stores(), [])
        self.assertFalse(any(l.exists for l in locations))
        self.assertEqual(locations[0].how, "env " + ENV)

    def test_a_variable_naming_a_file_is_not_an_error(self):
        path = self.write("afile", ["x"])
        os.environ[ENV] = path
        os.environ[SESSION_ENV] = path
        self.assertEqual(self.stores(), [])


class Performance(OmpCase):

    def test_a_20mb_session_is_read_in_linear_time(self):
        path = os.path.join(self.root, "sessions", FOLDER, NAME)
        os.makedirs(os.path.dirname(path))
        out = ("lorem ipsum dolor sit amet " * 24 + "\n") * 2
        n = 0
        with open(path, "w", encoding="utf-8", newline="") as fh:
            fh.write(slot() + "\n" + dump(header(sid=SID, cwd=CWD)) + "\n")
            while fh.tell() < 20 * 1024 * 1024:
                for line in call_lines(n + 1, "call_%08d" % n, "bash",
                                       {"command": "grep -rn foo src/%d" % n},
                                       output=out):
                    fh.write(dump(line) + "\n")
                n += 2
        t = time.time()
        calls = list(self.omp.tool_calls(self.store(path)))
        texts = list(self.omp.secret_texts(self.store(path)))
        elapsed = time.time() - t
        self.assertEqual(len(calls), n // 2)
        self.assertEqual(len(texts), 2 + 3 * (n // 2))
        self.assertLess(elapsed, 30)


class ReviewFindings(OmpCase):
    """Regressions for the review of the first version."""

    def session(self, lines=None, **kw):
        return self.write("sessions/%s/%s" % (FOLDER, NAME),
                          lines if lines is not None else head(), **kw)

    def test_env_dir_equal_to_the_default_folder_keeps_old_files(self):
        self.write("sessions/%s/%s" % (FOLDER, NAME), [header(sid=SID)])
        self.assertEqual(len(self.stores()), 1)
        os.environ[ENV] = self.root
        locs = self.omp.locations()
        self.assertEqual(locs[0].how, "env " + ENV)
        self.assertEqual(len(self.omp.stores(locs)), 1)

    def test_a_pi_file_in_a_shared_dir_outside_omp_folders_is_still_skipped(self):
        shared = self.other("omp-shared-")
        self.write("sessions/%s/%s" % (FOLDER, NAME), [header(sid=SID)],
                   root=shared)
        os.environ[ENV] = shared
        self.assertEqual(self.stores(), [])

    def test_a_long_space_run_in_a_patch_is_linear(self):
        import time
        start = time.time()
        for _ in range(3):
            kind, _k, _c, paths, _x, _w = omp_module.classify(
                "edit", {"input": "*** Add File: a" + " " * 200000 + "x\n"})
        self.assertLess(time.time() - start, 3)
        self.assertEqual(kind, "write")
        self.assertEqual(len(paths), 1)

    def test_patch_headers_are_read_stripped(self):
        got = omp_module.classify("edit", {"input": (
            "*** Begin Patch\n*** Add File:  a.py  \n+x\n"
            "*** Update File: b.py\n*** Move to: c.py\n"
            "*** Delete File: d.py\n")})[3]
        self.assertEqual(got, ("a.py", "b.py", "c.py", "d.py"))

    def test_read_of_a_file_url_names_the_file(self):
        got = omp_module.classify(
            "read", {"path": "file:///home/u/.ssh/id_rsa"})
        self.assertEqual((got[0], got[3]), ("read", ("/home/u/.ssh/id_rsa",)))
        got = omp_module.classify(
            "read", {"path": "file:///home/u/my%20file.txt:3-4"})
        self.assertEqual(got[3], ("/home/u/my file.txt",))
        self.assertEqual(omp_module.classify(
            "read", {"path": "artifact://3"})[3], ())

    def test_read_splits_semicolon_lists_and_comma_selectors(self):
        got = omp_module.classify(
            "read", {"path": "~/.ssh/id_rsa;~/.aws/credentials"})[3]
        self.assertEqual(got, ("~/.ssh/id_rsa", "~/.aws/credentials"))
        got = omp_module.classify("read", {"path": "a.ts:1-5;b.env:2"})[3]
        self.assertEqual(got, ("a.ts", "b.env"))
        self.assertEqual(omp_module.classify(
            "read", {"path": "a.py:1-10,20-30"})[3], ("a.py",))
        got = omp_module.classify("read", {"path": "a.env, b.env"})[3]
        self.assertIn("a.env", got)
        self.assertIn("b.env", got)

    def test_calls_refused_before_they_ran_are_declined(self):
        texts = (
            "Tool was not executed because the run was aborted: user cancelled.",
            'Validation failed for tool "write":\nTool call arguments are '
            "not valid JSON.\nParse Error: x\nRaw JSON: {",
            "`i` is a short intent label, at most 80 characters. The tool "
            "was not run.")
        for text in texts:
            lines = head() + [
                entry(1, assistant([tool_call("c1", "write", {
                    "path": "a", "content": "x"})], BASE_MS)),
                entry(2, tool_result("c1", "write", text, BASE_MS,
                                     is_error=True, details={}))]
            call = self.by_id(self.session(lines))["c1"]
            self.assertEqual(call.status, "declined", text)
        lines = head() + [
            entry(1, assistant([tool_call("c1", "write", {
                "path": "a", "content": "x"})], BASE_MS)),
            entry(2, tool_result("c1", "write", "bad args", BASE_MS,
                                 is_error=True, details={
                                     "isError": True, "error": "bad args"}))]
        self.assertEqual(self.by_id(self.session(lines))["c1"].status,
                         "declined")

    def test_an_ordinary_error_still_ran(self):
        lines = head() + [
            entry(1, assistant([tool_call("c1", "bash", {"command": "false"})],
                               BASE_MS)),
            entry(2, tool_result("c1", "bash", "exit 1", BASE_MS,
                                 is_error=True, details={}))]
        self.assertEqual(self.by_id(self.session(lines))["c1"].status, None)

    def test_spilled_tool_output_is_scanned_and_masked(self):
        stem = NAME[:-len(".jsonl")]
        path = self.session()
        log = self.write("sessions/%s/%s/1.bash.log" % (FOLDER, stem), [],
                         raw=(b"x" * 3000000 + b" " + SECRET.encode() + b"\n"),
                         mode=0o600)
        stores = {s.path: s for s in self.stores()}
        self.assertIn(log, stores)
        store = stores[log]
        self.assertEqual((store.role, store.format, store.session),
                         ("side", "text", SID))
        found = "".join(t.node for t in self.omp.secret_texts(store)
                        if isinstance(t.node, str))
        self.assertIn(SECRET, found)
        result = self.omp.mask(store, [SECRET])
        self.assertFalse(result.skipped)
        with open(log, "rb") as fh:
            self.assertNotIn(SECRET.encode(), fh.read())
        self.assertEqual(list(self.omp.tool_calls(store)), [])

    def test_a_log_beside_a_pi_file_in_a_shared_dir_is_left_alone(self):
        shared = self.other("omp-shared-")
        pi_name = "2026-10-01T09-00-00-000Z_pi.jsonl"
        self.write("sessions/%s/%s" % (FOLDER, pi_name),
                   [header(sid="pi-1", cwd=CWD)], root=shared)
        self.write("sessions/%s/%s/1.bash.log" % (FOLDER, pi_name[:-6]), [],
                   raw=b"hi\n", root=shared)
        os.environ[ENV] = shared
        self.assertEqual(self.stores(), [])


if __name__ == "__main__":
    unittest.main()
