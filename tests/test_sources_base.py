"""The shared base of the agent adapter layer (ranwhat/sources).

Covers the helpers every adapter is built on, the Source interface and its
data types, the registry, and the generic masking rewrite: a round trip
that changes nothing but the secret, and refusal when the file was written
recently or when anything but the secret would change.

Everything runs in temp directories. The home directory, the agent's own
override variable and the backup root are all pointed there. Every secret
is synthetic and written as adjacent literals.
"""
import ast
import contextlib
import glob
import hashlib
import io
import json
import ntpath
import os
import re
import shutil
import sqlite3
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
sys.path.insert(0, TESTS)

from ranwhat import clean  # noqa: E402
from ranwhat import sources  # noqa: E402
from ranwhat.sources import (_jsonc, _keyfile, _lines, _paths, _rewrite,  # noqa: E402
                             _shell, _sqlite, _stamps, _zstd, base)
from ranwhat.sources.base import (Location, MaskResult, SecretText,  # noqa: E402
                                  Source, Store, ToolCall)

PACKAGE = os.path.join(REPO, "ranwhat", "sources")
MODULES = sorted(glob.glob(os.path.join(PACKAGE, "*.py")))

SECRET = "sk_" "live_" "Zq8vR2mT6yLp4WcN0sXe7HbJ"
# A password with every character JSON, Go and a second level of JSON
# escape differently: a quote, a backslash, non-ASCII, & < > and U+2028.
PASSWORD = "pw" '"' "\\" "\u00e4" "&<>" "\u2028" "Tq9" "vX2r"

WINDOWS = os.name == "nt"

# Every temp file and folder these tests make (and any the code under test
# makes) goes in one folder, removed when the module is done.
_TEMP_ROOT = None
_TEMP_BEFORE = None


def setUpModule():
    global _TEMP_ROOT, _TEMP_BEFORE
    _TEMP_ROOT = tempfile.mkdtemp(prefix="srcbase-run-")
    _TEMP_BEFORE = tempfile.tempdir
    tempfile.tempdir = _TEMP_ROOT


def tearDownModule():
    tempfile.tempdir = _TEMP_BEFORE
    shutil.rmtree(_TEMP_ROOT, ignore_errors=True)


def _sha(path):
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def _open_files():
    """How many files this process has open, where /dev/fd lists them
    (Linux, macOS); None elsewhere."""
    return len(os.listdir("/dev/fd")) if os.path.isdir("/dev/fd") else None


def _ranwhat_temp_dirs():
    return set(x for x in os.listdir(tempfile.gettempdir())
               if x.startswith("ranwhat-"))


# --------------------------------------------------------------------------
# Package rules
# --------------------------------------------------------------------------

STDLIB = {"__future__", "ast", "collections", "compression", "contextlib",
          "datetime", "glob", "hashlib", "importlib", "io", "json", "ntpath",
          "os", "posixpath", "re", "shlex", "shutil", "sqlite3", "stat",
          "subprocess", "sys", "tempfile", "threading", "time", "urllib",
          "weakref"}


class PackageRules(unittest.TestCase):

    def test_package_has_the_shared_modules(self):
        names = set(os.path.basename(p) for p in MODULES)
        for name in ("__init__.py", "base.py", "_paths.py", "_lines.py",
                     "_sqlite.py", "_zstd.py", "_shell.py", "_stamps.py",
                     "_rewrite.py", "_keyfile.py", "_jsonc.py"):
            self.assertIn(name, names)

    def test_importing_the_package_imports_neither_watch_nor_clean(self):
        code = ("import sys, ranwhat.sources\n"
                "from ranwhat.sources import _paths, _lines, _sqlite, _zstd, "
                "_shell, _stamps, _rewrite, _keyfile, _jsonc, base\n"
                "print(sorted(m for m in sys.modules if m in "
                "('ranwhat.watch', 'ranwhat.clean')))\n")
        home = tempfile.mkdtemp(prefix="srcbase-home-")
        env = dict(os.environ, HOME=home, USERPROFILE=home)
        out = subprocess.run([sys.executable, "-c", code], cwd=REPO, env=env,
                             capture_output=True, text=True, encoding="utf-8",
                             timeout=20)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(out.stdout.strip(), "[]")

    def test_standard_library_only(self):
        """No runtime dependency, and the zstd helper in particular imports
        nothing outside the standard library (compression is 3.14's)."""
        for path in MODULES:
            with open(path, encoding="utf-8") as fh:
                tree = ast.parse(fh.read(), path)
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    names = [a.name for a in node.names]
                elif isinstance(node, ast.ImportFrom) and not node.level:
                    names = [node.module]
                else:
                    continue
                for name in names:
                    self.assertIn(name.split(".")[0], STDLIB,
                                  "%s imports %s" % (path, name))

    def test_every_text_open_names_its_encoding(self):
        # tests/test_text_encoding.py globs ranwhat/*.py only, so the
        # subpackage is checked here until that glob covers it.
        from test_text_encoding import _unnamed_encodings
        found = {os.path.basename(p): _unnamed_encodings(p) for p in MODULES}
        self.assertEqual({k: v for k, v in found.items() if v}, {})

    def test_no_em_dashes(self):
        for path in MODULES:
            with open(path, encoding="utf-8") as fh:
                self.assertNotIn("\u2014", fh.read(), path)


# --------------------------------------------------------------------------
# Registry
# --------------------------------------------------------------------------

class _Toy(Source):
    """A throwaway adapter: TOY_HOME, else ~/.toy; one store per *.jsonl."""
    id = "toy-agent"
    name = "Toy Agent"
    unit = "session"
    env = ("TOY_HOME",)
    path_means = "a Toy Agent home directory"

    def default_paths(self, env, home, platform):
        if env.get("TOY_HOME"):
            return [(env["TOY_HOME"], "env TOY_HOME")]
        return [(_paths.join(platform, home, ".toy"), "default")]

    def stores(self, locations, since_days=None):
        found = []
        for loc in locations:
            for path in glob.glob(os.path.join(loc.path, "*.jsonl")):
                store = self.store(path, "jsonl")
                if store:
                    found.append(store)
        return base.newest_first(found, since_days)

    def tool_calls(self, store):
        try:
            for line_no, obj in _lines.iter_json_lines(store.path, self.counts):
                if not isinstance(obj, dict) or obj.get("type") != "call":
                    self.count("unknown")
                    continue
                known = obj.get("name") == "shell"
                yield ToolCall(self.id, store.path, obj.get("name"),
                               obj.get("args"), kind="shell" if known else
                               "other", known=known,
                               command=obj.get("args", {}).get("cmd")
                               if known else None,
                               consumed=("cmd",) if known else (),
                               timestamp=_stamps.iso_utc(obj.get("t"), "ms"))
        except OSError as e:
            self.warn(store.path, "cannot read %s (%s)" % (store.path, e))


class Registry(unittest.TestCase):

    def tearDown(self):
        sources.unregister("toy-agent")

    def test_registry_follows_adapters_in_order(self):
        self.assertEqual(len(sources.ids()), len(set(sources.ids())))
        self.assertEqual(len(sources.ids()), len(sources.ADAPTERS))
        for (module, cls), sid in zip(sources.ADAPTERS, sources.ids()):
            mod = __import__("ranwhat.sources." + module, fromlist=[cls])
            self.assertEqual(getattr(mod, cls).id, sid)

    # Design 4.2: the order agents are listed everywhere. OpenClaw sits near
    # the end on purpose (decision 7); grok-dev is last.
    ORDER = ("claude-code", "codex", "gemini", "copilot-cli", "vscode-copilot",
             "cline", "roo", "kilo", "opencode", "continue", "aider", "goose",
             "zed", "qwen", "grok", "droid", "amp", "crush", "kimi-code",
             "kimi", "pi", "muse-code", "vibe", "zoo", "cecli", "openclaw",
             "grok-dev")
    WAVE_1 = ("codex", "gemini", "copilot-cli", "qwen", "grok", "droid",
              "kimi-code", "kimi", "pi", "muse-code")

    def test_wave_1_is_wired_in(self):
        for sid in self.WAVE_1:
            self.assertIn(sid, sources.ids())

    def test_registry_order_is_the_designs(self):
        # Ids not in the design's list are named here so a new adapter
        # cannot slip in without a place in the order.
        stray = [s for s in sources.ids() if s not in self.ORDER]
        self.assertEqual(stray, [])
        ranks = [self.ORDER.index(s) for s in sources.ids()]
        self.assertEqual(ranks, sorted(ranks), sources.ids())

    def test_every_registered_source_says_what_reports_need(self):
        for source in sources.sources():
            self.assertIsInstance(source, Source)
            for field in ("id", "name", "unit", "path_means"):
                self.assertTrue(getattr(source, field), (source.id, field))

    def test_every_default_path_on_windows_is_a_windows_path(self):
        # A "/" joined in reads on Windows, but it is not the path the
        # report names or compares with: C:\Users\u/.claude\projects.
        windows = {"USERPROFILE": "C:\\Users\\u",
                   "APPDATA": "C:\\Users\\u\\AppData\\Roaming",
                   "LOCALAPPDATA": "C:\\Users\\u\\AppData\\Local"}
        for source in sources.sources():
            set_ = dict(windows, **{v: "D:\\set\\" + v for v in source.env})
            for env in (windows, set_):
                pairs = source.default_paths(env, "C:\\Users\\u", "win32")
                self.assertTrue(pairs, source.id)
                for path, how in pairs:
                    self.assertNotIn("/", path, (source.id, how))
                    self.assertTrue(ntpath.isabs(path), (source.id, path))

    def test_claude_codes_projects_directory_on_windows(self):
        # What watch reads by default, worked out by ntpath as Windows does.
        from ranwhat.sources import claude_code
        fake_os = mock.Mock(path=ntpath, environ={})
        with mock.patch.dict(os.environ, {"USERPROFILE": "C:\\Users\\u"}), \
                mock.patch.object(claude_code, "os", fake_os):
            self.assertEqual(claude_code.projects_dir(),
                             "C:\\Users\\u\\.claude\\projects")
            for value in ("D:\\claude", "D:/claude"):
                fake_os.environ = {"CLAUDE_CONFIG_DIR": value}
                self.assertEqual(claude_code.projects_dir(),
                                 "D:\\claude\\projects")

    def test_no_path_is_expanded_from_a_slash_after_the_tilde(self):
        # expanduser("~/.x") keeps the "/" on Windows; join after "~".
        tilde = re.compile(r"""expanduser\(\s*["']~[/\\]""")
        found = []
        for path in glob.glob(os.path.join(REPO, "ranwhat", "**", "*.py"),
                              recursive=True):
            with open(path, encoding="utf-8") as fh:
                found += ["%s:%d" % (os.path.relpath(path, REPO), n)
                          for n, line in enumerate(fh, 1) if tilde.search(line)]
        self.assertEqual(found, [])

    def test_register_get_and_unregister(self):
        before = sources.ids()
        self.assertIs(sources.register(_Toy), _Toy)
        self.assertEqual(sources.ids(), before + ("toy-agent",))
        self.assertIsInstance(sources.get("toy-agent"), _Toy)
        self.assertEqual([s.id for s in sources.sources(["toy-agent"])],
                         ["toy-agent"])
        sources.unregister("toy-agent")
        self.assertEqual(sources.ids(), before)

    def test_a_duplicate_id_is_refused(self):
        sources.register(_Toy())
        with self.assertRaises(ValueError):
            sources.register(_Toy())

    def test_a_source_missing_what_reports_need_is_refused(self):
        for field, value in (("id", ""), ("id", "Toy Agent"), ("name", ""),
                             ("unit", ""), ("path_means", "")):
            bad = type("Bad", (_Toy,), {field: value})
            with self.assertRaises(ValueError, msg=field):
                sources.register(bad)
        with self.assertRaises(ValueError):
            sources.register(object())

    def test_unknown_id_names_the_known_ones(self):
        sources.register(_Toy)
        with self.assertRaises(KeyError) as caught:
            sources.get("no-such-agent")
        self.assertIn("toy-agent", str(caught.exception))


# --------------------------------------------------------------------------
# _paths: pure default paths on all three platforms
# --------------------------------------------------------------------------

class Paths(unittest.TestCase):

    def test_home_is_expanduser(self):
        self.assertEqual(_paths.home(), os.path.expanduser("~"))

    def test_platform_names(self):
        self.assertEqual(_paths.platform_name("win32"), "win32")
        self.assertEqual(_paths.platform_name("darwin"), "darwin")
        self.assertEqual(_paths.platform_name("linux"), "linux")
        self.assertEqual(_paths.platform_name("freebsd14"), "linux")
        self.assertEqual(_paths.platform_name("cygwin"), "linux")

    def test_xdg_defaults_and_overrides(self):
        self.assertEqual(_paths.xdg_data_home({}, "/home/u", "linux"),
                         "/home/u/.local/share")
        self.assertEqual(_paths.xdg_state_home({}, "/home/u", "linux"),
                         "/home/u/.local/state")
        self.assertEqual(_paths.xdg_config_home({}, "/Users/u", "darwin"),
                         "/Users/u/.config")
        self.assertEqual(_paths.xdg_cache_home({}, "/home/u", "linux"),
                         "/home/u/.cache")
        self.assertEqual(_paths.xdg_data_home({}, "C:\\Users\\u", "win32"),
                         "C:\\Users\\u\\.local\\share")
        self.assertEqual(_paths.xdg_data_home(
            {"XDG_DATA_HOME": "/data"}, "/home/u", "linux"), "/data")
        self.assertEqual(_paths.xdg_data_home(
            {"XDG_DATA_HOME": ""}, "/home/u", "linux"), "/home/u/.local/share")

    def test_windows_appdata(self):
        home = "C:\\Users\\u"
        self.assertEqual(_paths.appdata({}, home), "C:\\Users\\u\\AppData\\Roaming")
        self.assertEqual(_paths.localappdata({}, home),
                         "C:\\Users\\u\\AppData\\Local")
        self.assertEqual(_paths.appdata({"APPDATA": "D:\\Roam"}, home), "D:\\Roam")
        self.assertEqual(_paths.localappdata({"LOCALAPPDATA": "D:\\Loc"}, home),
                         "D:\\Loc")

    def test_editor_user_dirs_macos(self):
        self.assertEqual(_paths.editor_user_dirs({}, "/Users/u", "darwin"), [
            ("/Users/u/Library/Application Support/Code/User", "default"),
            ("/Users/u/Library/Application Support/Code - Insiders/User", "probed"),
            ("/Users/u/Library/Application Support/VSCodium/User", "probed"),
            ("/Users/u/Library/Application Support/Cursor/User", "probed"),
            ("/Users/u/Library/Application Support/Windsurf/User", "probed"),
            ("/Users/u/Library/Application Support/Devin/User", "probed"),
        ])

    def test_editor_user_dirs_linux(self):
        dirs = _paths.editor_user_dirs({}, "/home/u", "linux")
        self.assertEqual(dirs[0], ("/home/u/.config/Code/User", "default"))
        self.assertEqual(dirs[-1], ("/home/u/.config/Devin/User", "probed"))
        dirs = _paths.editor_user_dirs({"XDG_CONFIG_HOME": "/cfg"}, "/home/u",
                                       "linux")
        self.assertEqual(dirs[0], ("/cfg/Code/User", "default"))

    def test_editor_user_dirs_windows(self):
        dirs = _paths.editor_user_dirs({}, "C:\\Users\\u", "win32")
        self.assertEqual(dirs[0], ("C:\\Users\\u\\AppData\\Roaming\\Code\\User",
                                   "default"))
        self.assertEqual(dirs[1], (
            "C:\\Users\\u\\AppData\\Roaming\\Code - Insiders\\User", "probed"))
        dirs = _paths.editor_user_dirs({"APPDATA": "D:\\R"}, "C:\\Users\\u",
                                       "win32")
        self.assertEqual(dirs[0], ("D:\\R\\Code\\User", "default"))

    def test_editor_overrides_come_first_and_keep_the_default(self):
        env = {"VSCODE_PORTABLE": "/opt/vsc/data", "VSCODE_APPDATA": "/appdata"}
        dirs = _paths.editor_user_dirs(env, "/home/u", "linux")
        self.assertEqual(dirs[:3], [
            ("/opt/vsc/data/user-data/User", "env VSCODE_PORTABLE"),
            ("/appdata/Code/User", "env VSCODE_APPDATA"),
            ("/home/u/.config/Code/User", "default"),
        ])
        dirs = _paths.editor_user_dirs({"VSCODE_APPDATA": "E:\\vs"},
                                       "C:\\Users\\u", "win32")
        self.assertEqual(dirs[0], ("E:\\vs\\Code\\User", "env VSCODE_APPDATA"))

    def test_pure(self):
        """No I/O: a home that does not exist, on a platform this is not."""
        with mock.patch("os.stat", side_effect=AssertionError("stat")), \
                mock.patch("os.path.exists", side_effect=AssertionError("exists")):
            _paths.editor_user_dirs({}, "/nowhere/u", "linux")
            _paths.editor_user_dirs({}, "C:\\nowhere", "win32")
            _Toy().default_paths({}, "/nowhere", "darwin")


# --------------------------------------------------------------------------
# _lines.iter_json_lines
# --------------------------------------------------------------------------

class JsonLines(unittest.TestCase):

    def _file(self, data):
        fd, path = tempfile.mkstemp(prefix="srcbase-lines-", suffix=".jsonl")
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        return path

    def test_line_separators_inside_a_record_do_not_split_it(self):
        text = json.dumps({"out": "a\u2028b\u2029c\x1cd\x85e"},
                          ensure_ascii=False)
        self.assertGreater(len(text.splitlines()), 1, "the hazard is real")
        path = self._file((text + "\n" + '{"n":2}\n').encode("utf-8"))
        rows = list(_lines.iter_json_lines(path))
        self.assertEqual(rows, [(1, {"out": "a\u2028b\u2029c\x1cd\x85e"}),
                                (2, {"n": 2})])

    def test_line_numbers_blank_lines_and_crlf(self):
        path = self._file(b'{"a":1}\r\n\r\n   \n{"b":2}\r\n')
        self.assertEqual(list(_lines.iter_json_lines(path)),
                         [(1, {"a": 1}), (4, {"b": 2})])

    def test_bad_line_is_counted_and_partial_last_line_is_not(self):
        path = self._file(b'{"a":1}\nnot json\n{"b":2}\n{"c":')
        counts = {}
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            rows = list(_lines.iter_json_lines(path, counts))
        self.assertEqual(rows, [(1, {"a": 1}), (3, {"b": 2})])
        self.assertEqual(counts, {"unparsed": 1})
        self.assertEqual(err.getvalue(), "")

    def test_complete_last_line_without_newline_is_read(self):
        path = self._file(b'{"a":1}\n{"b":2}')
        self.assertEqual(list(_lines.iter_json_lines(path)),
                         [(1, {"a": 1}), (2, {"b": 2})])

    def test_bytes_that_are_not_utf8_survive(self):
        path = self._file(b'{"x":"caf\xff"}\n')
        [(_, obj)] = list(_lines.iter_json_lines(path))
        self.assertEqual(obj["x"].encode("utf-8", "surrogateescape"), b"caf\xff")

    def test_byte_order_mark(self):
        path = self._file(b'\xef\xbb\xbf{"a":1}\n')
        self.assertEqual(list(_lines.iter_json_lines(path)), [(1, {"a": 1})])

    def test_absurd_nesting_is_skipped_not_fatal(self):
        path = self._file(b"[" * 100000 + b"\n" + b'{"ok":1}\n')
        counts = {}
        self.assertEqual(list(_lines.iter_json_lines(path, counts)),
                         [(2, {"ok": 1})])
        self.assertEqual(counts["unparsed"], 1)

    def test_json_nested_past_the_stack_is_read_or_skipped_never_raised(self):
        """3.9's json gives up on it; 3.14's reads it. Either way the other
        lines are read, and a call's input or a settings file holding it
        comes back as what json made of it, or as text it could not."""
        deep = "[" * 100000 + "]" * 100000
        path = self._file(('{"a":1}\n' + deep + '\n{"b":2}\n').encode("utf-8"))
        counts = {}
        rows = list(_lines.iter_json_lines(path, counts))
        self.assertEqual([r for r in rows if r[0] != 2], [(1, {"a": 1}), (3, {"b": 2})])
        self.assertEqual(len(rows) - 2 + counts.get("unparsed", 0), 1)
        self.assertIn(set(base.decode_input(deep)), ({"_raw"}, {"_value"}))
        self.assertIn(type(_jsonc.loads(deep)), (type(None), list))

    def test_missing_file_raises_for_the_caller(self):
        with self.assertRaises(OSError):
            list(_lines.iter_json_lines(os.path.join(
                tempfile.mkdtemp(prefix="srcbase-"), "missing.jsonl")))


# --------------------------------------------------------------------------
# _stamps
# --------------------------------------------------------------------------

class Stamps(unittest.TestCase):

    def test_each_unit(self):
        want = "2026-09-21T14:13:20Z"
        self.assertEqual(_stamps.iso_utc(1790000000, "s"), want)
        self.assertEqual(_stamps.iso_utc(1790000000.75, "s"), want)
        self.assertEqual(_stamps.iso_utc(1790000000000, "ms"), want)
        self.assertEqual(_stamps.iso_utc(1790000000000000, "us"), want)
        self.assertEqual(_stamps.iso_utc("1790000000000", "ms"), want)

    def test_microseconds_are_not_the_year_58000(self):
        from ranwhat import watch
        self.assertIsNone(watch._as_iso(1.79e15), "the bug this replaces")
        self.assertEqual(_stamps.iso_utc(1.79e15, "us"), "2026-09-21T14:13:20Z")

    def test_not_a_time(self):
        for value in (None, "", "soon", True, False, 0, -5, float("nan"),
                      float("inf"), 10 ** 30, [1], {"t": 1}):
            for unit in ("s", "ms", "us"):
                self.assertIsNone(_stamps.iso_utc(value, unit), (value, unit))
        # seconds given as milliseconds land in 1970: not taken for a time
        self.assertIsNone(_stamps.iso_utc(1790000000, "ms"))

    def test_iso_strings(self):
        self.assertEqual(_stamps.iso_utc("2026-10-01T09:14:31.123+02:00", "iso"),
                         "2026-10-01T07:14:31Z")
        self.assertEqual(_stamps.iso_utc("2026-10-01T09:14:31Z", "iso"),
                         "2026-10-01T09:14:31Z")
        self.assertEqual(_stamps.iso_utc("2026-10-01 09:14:58.412345", "iso"),
                         "2026-10-01 09:14:58.412345")
        self.assertIsNone(_stamps.iso_utc("yesterday", "iso"))
        self.assertIsNone(_stamps.iso_utc(1790000000, "iso"))

    def test_unknown_unit_is_a_programming_error(self):
        with self.assertRaises(ValueError):
            _stamps.iso_utc(1790000000, "seconds")

    def test_parse_stamp_matches_watch(self):
        from ranwhat import watch
        for stamp in ("2026-10-01T09:14:31Z", "2026-10-01 09:14:31",
                      "2026-10-01T09:14:31.5-0330", "2026-13-01T00:00:00Z",
                      "nope", None, 5):
            self.assertEqual(_stamps.parse_stamp(stamp),
                             watch._parse_stamp(stamp), stamp)


# --------------------------------------------------------------------------
# _shell
# --------------------------------------------------------------------------

class Shell(unittest.TestCase):

    def test_a_shell_running_a_script_is_the_script(self):
        a2c = _shell.argv_to_command
        self.assertEqual(a2c(["bash", "-lc", "rm -rf build && ls"]),
                         "rm -rf build && ls")
        self.assertEqual(a2c(["/bin/zsh", "-lc", "cat .env"]), "cat .env")
        self.assertEqual(a2c(["sh", "-c", "echo 'a b'", "arg0"]), "echo 'a b'")
        self.assertEqual(a2c(["dash", "-ic", "x"]), "x")
        self.assertEqual(a2c(["pwsh", "-Command", "Remove-Item -Recurse x"]),
                         "Remove-Item -Recurse x")
        self.assertEqual(a2c(["C:\\Windows\\System32\\WindowsPowerShell\\v1.0"
                              "\\powershell.exe", "-Command", "dir"]), "dir")

    def test_anything_else_is_quoted_back_into_one_command(self):
        a2c = _shell.argv_to_command
        self.assertEqual(a2c(["ls", "-la", "my dir"]), "ls -la 'my dir'")
        self.assertEqual(a2c(["bash", "script.sh"]), "bash script.sh")
        self.assertEqual(a2c(["bash", "-c"]), "bash -c")
        self.assertEqual(a2c(["bash", "-x", "-c", "ls"]), "bash -x -c ls")
        self.assertEqual(a2c(["python3", "-c", "print(1)"]),
                         "python3 -c 'print(1)'")
        self.assertEqual(a2c(["echo", 5, None]), "echo 5 None")
        self.assertEqual(a2c([]), "")
        self.assertEqual(a2c("already text"), "already text")
        self.assertEqual(a2c(None), "")

    def test_file_uris(self):
        f2p = _shell.file_uri_to_path
        self.assertEqual(f2p("file:///Users/me/proj", "darwin"), "/Users/me/proj")
        self.assertEqual(f2p("file:///home/me/my%20proj%23", "linux"),
                         "/home/me/my proj#")
        self.assertEqual(f2p("file://localhost/etc/x", "linux"), "/etc/x")
        self.assertEqual(f2p("file:///C:/x/y", "win32"), "C:\\x\\y")
        self.assertEqual(f2p("file:///c%3A/Users/me", "win32"), "c:\\Users\\me")
        self.assertEqual(f2p("file:///C:", "win32"), "C:\\")
        self.assertEqual(f2p("file://server/share/x", "win32"),
                         "\\\\server\\share\\x")
        self.assertIsNone(f2p("file://server/share/x", "linux"))
        self.assertIsNone(f2p("vscode-remote://ssh-remote+box/home/me", "linux"))
        self.assertIsNone(f2p("/plain/path", "linux"))
        self.assertIsNone(f2p(None, "linux"))
        self.assertIsNone(f2p("file://", "linux"))


# --------------------------------------------------------------------------
# _sqlite
# --------------------------------------------------------------------------

class Sqlite(unittest.TestCase):

    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="srcbase-sql-")
        self.before = _ranwhat_temp_dirs()

    def tearDown(self):
        self.assertEqual(_ranwhat_temp_dirs() - self.before, set(),
                         "a ranwhat-* temp directory was left behind")

    def _db(self, path, rows=3):
        conn = sqlite3.connect(path)
        conn.execute("CREATE TABLE part (id TEXT, data TEXT, time_created INTEGER)")
        conn.executemany("INSERT INTO part VALUES (?, ?, ?)", [
            ("p%d" % i, json.dumps({"type": "tool", "n": i}), 1790000000000 + i)
            for i in range(rows)])
        conn.commit()
        return conn

    def test_rows_still_in_the_wal_are_read_and_nothing_changes(self):
        path = os.path.join(self.root, "agent.db")
        writer = sqlite3.connect(path)
        writer.execute("PRAGMA journal_mode=WAL")
        writer.execute("PRAGMA wal_autocheckpoint=0")
        writer.close()
        writer = self._db(path, rows=5)          # stays open: rows in the -wal
        try:
            self.assertGreater(os.path.getsize(path + "-wal"), 0)
            hashes = {p: _sha(p) for p in (path, path + "-wal")}
            with open(path + "-shm", "rb") as fh:
                shm = fh.read()
            with _sqlite.readonly(path) as conn:
                self.assertIsNotNone(conn)
                self.assertEqual(_sqlite.tables(conn), ["part"])
                rows = list(_sqlite.iter_rows(conn, "part", ["id", "data"]))
                self.assertEqual([r["id"] for r in rows],
                                 ["p0", "p1", "p2", "p3", "p4"])
                with self.assertRaises(sqlite3.OperationalError):
                    conn.execute("DELETE FROM part")
            self.assertEqual({p: _sha(p) for p in hashes}, hashes)
            # The -shm is SQLite's shared-memory WAL index, not data. Every
            # reader, mode=ro included, takes a read mark in it (aReadMark,
            # bytes 100 to 119); nothing else in it may change.
            with open(path + "-shm", "rb") as fh:
                after = fh.read()
            self.assertEqual(len(after), len(shm))
            changed = [i for i in range(len(shm)) if shm[i] != after[i]]
            self.assertTrue(all(100 <= i < 120 for i in changed), changed)
        finally:
            writer.close()

    def test_a_path_with_uri_characters_opens_that_file(self):
        # Windows forbids ? in a file name; # and % still need escaping there.
        weird = os.path.join(self.root, "a#c%d" if WINDOWS else "a?b#c%d")
        os.makedirs(weird)
        self._db(os.path.join(weird, "x.db")).close()
        # what an unescaped URI would have opened instead
        self._db(os.path.join(self.root, "a"), rows=0).close()
        with _sqlite.readonly(os.path.join(weird, "x.db")) as conn:
            self.assertEqual(len(list(_sqlite.iter_rows(conn, "part", ["id"]))), 3)

    def test_not_a_database_fails_on_first_query(self):
        path = os.path.join(self.root, "garbage.db")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("this is not a database")
        with _sqlite.readonly(path) as conn:
            self.assertIsNotNone(conn)
            with self.assertRaises(sqlite3.DatabaseError) as caught:
                _sqlite.tables(conn)
        self.assertIn("not a database", str(caught.exception))

    def test_missing_file_is_none_and_leaves_nothing(self):
        conn, tmp = _sqlite.open_readonly(os.path.join(self.root, "none.db"))
        self.assertEqual((conn, tmp), (None, None))
        self.assertFalse(os.path.exists(os.path.join(self.root, "none.db")))

    def test_falls_back_to_a_copy_and_removes_it(self):
        path = os.path.join(self.root, "locked.db")
        self._db(path).close()
        real = sqlite3.connect
        calls = []

        def flaky(*args, **kwargs):
            calls.append(args[0])
            if len(calls) == 1:
                raise sqlite3.OperationalError("database is locked")
            return real(*args, **kwargs)

        with mock.patch.object(_sqlite.sqlite3, "connect", side_effect=flaky):
            conn, tmp = _sqlite.open_readonly(path)
        try:
            self.assertTrue(tmp and os.path.isdir(tmp))
            # The copy is ranwhat's own file, opened as one: mode=ro on a
            # copy of a WAL database with no -shm fails on Apple's SQLite.
            self.assertTrue(calls[1].endswith("?mode=rw"), calls[1])
            self.assertNotIn(_sqlite._url_path(self.root), calls[1])
            self.assertEqual(len(list(_sqlite.iter_rows(conn, "part", ["id"]))), 3)
        finally:
            _sqlite.close(conn, tmp)
        self.assertFalse(os.path.exists(tmp))

    def test_a_reader_stopped_mid_table_lets_go_of_the_copy(self):
        # From Python 3.11 a connection closed while a cursor is still open
        # keeps its file open until the cursor goes, and Windows cannot
        # remove an open file: the copy was left behind.
        path = os.path.join(self.root, "locked.db")
        self._db(path).close()
        real, refused = sqlite3.connect, []

        def flaky(*args, **kwargs):
            if not refused:
                refused.append(args[0])
                raise sqlite3.OperationalError("database is locked")
            return real(*args, **kwargs)

        before = _open_files()
        with mock.patch.object(_sqlite.sqlite3, "connect", side_effect=flaky):
            conn, tmp = _sqlite.open_readonly(path)
        self.assertTrue(tmp)
        rows = _sqlite.iter_rows(conn, "part", ["id"])
        cursor = conn.execute("SELECT id FROM part")
        next(rows), next(cursor)
        _sqlite.close(conn, tmp)
        self.assertFalse(os.path.exists(tmp))
        self.assertEqual(_open_files(), before)

    def _listing(self, folder):
        """{name: sha256} of every file in folder."""
        return {name: _sha(os.path.join(folder, name))
                for name in sorted(os.listdir(folder))}

    def _closed_wal(self, folder, rows=3):
        """agent.db in folder in WAL mode, its writer closed, as an agent
        leaves it: SQLite removes the -wal and the -shm on a clean close."""
        path = os.path.join(folder, "agent.db")
        writer = sqlite3.connect(path)
        writer.execute("PRAGMA journal_mode=WAL")
        writer.close()
        self._db(path, rows).close()
        for suffix in ("-wal", "-shm"):
            if os.path.exists(path + suffix):
                os.remove(path + suffix)
        with open(path, "rb") as fh:
            self.assertEqual(fh.read(20)[18:20], b"\x02\x02")    # WAL mode
        return path

    def test_a_closed_wal_database_is_read_and_nothing_is_made(self):
        """Opened mode=ro with no -wal or no -shm beside it, stock SQLite
        makes them (an empty -wal, a 32 KB -shm) in the agent's folder,
        and Apple's cannot open it at all. Neither may happen: with no
        -wal there is nothing in one to read."""
        for keep in ((), ("-shm",)):
            with self.subTest(keep=keep):
                folder = tempfile.mkdtemp(dir=self.root)
                path = self._closed_wal(folder)
                for suffix in keep:
                    with open(path + suffix, "wb") as fh:
                        fh.write(b"\x00" * 32768)
                before = self._listing(folder)
                with _sqlite.readonly(path) as conn:
                    self.assertIsNotNone(conn)
                    rows = list(_sqlite.iter_rows(conn, "part", ["id"]))
                self.assertEqual([r["id"] for r in rows], ["p0", "p1", "p2"])
                self.assertEqual(self._listing(folder), before)

    def test_a_wal_with_no_shm_beside_it_is_read_from_a_copy(self):
        """A -wal with no -shm (left by a crash, or by a writer in
        exclusive locking mode) holds rows the database does not. They are
        read from a copy, where SQLite makes its -shm."""
        live = os.path.join(tempfile.mkdtemp(dir=self.root), "live.db")
        writer = sqlite3.connect(live)
        writer.execute("PRAGMA journal_mode=WAL")
        writer.execute("PRAGMA wal_autocheckpoint=0")
        writer.close()
        writer = self._db(live, rows=4)          # open: its rows in the -wal
        folder = tempfile.mkdtemp(dir=self.root)
        path = os.path.join(folder, "agent.db")
        try:
            for suffix in ("", "-wal"):
                shutil.copy2(live + suffix, path + suffix)
        finally:
            writer.close()
        self.assertGreater(os.path.getsize(path + "-wal"), 0)
        before = self._listing(folder)
        with _sqlite.readonly(path) as conn:
            self.assertIsNotNone(conn)
            rows = list(_sqlite.iter_rows(conn, "part", ["id"]))
        self.assertEqual([r["id"] for r in rows], ["p0", "p1", "p2", "p3"])
        self.assertEqual(self._listing(folder), before)

    def test_text_that_is_not_utf8_is_read_as_it_is(self):
        """A TEXT cell whose bytes are not UTF-8 (a JS writer's string cut
        between the halves of a surrogate pair) made Python's sqlite3 raise
        an error that quoted the cell, whatever secret was in it. It is
        read with surrogateescape, as every adapter reads a file, through
        the copy too."""
        path = os.path.join(self.root, "bytes.db")
        conn = sqlite3.connect(path)
        conn.execute("CREATE TABLE t (body TEXT)")
        raw = b"ok \xed\xa0\xbd \xff end"
        conn.execute("INSERT INTO t VALUES (CAST(? AS TEXT))", (raw,))
        conn.commit()
        conn.close()
        real = sqlite3.connect
        for locked in (False, True):
            with self.subTest(copy=locked):
                calls = []

                def connect(*args, **kwargs):
                    calls.append(args[0])
                    if locked and len(calls) == 1:
                        raise sqlite3.OperationalError("database is locked")
                    return real(*args, **kwargs)

                with mock.patch.object(_sqlite.sqlite3, "connect",
                                       side_effect=connect):
                    with _sqlite.readonly(path) as ro:
                        [row] = list(_sqlite.iter_rows(ro, "t", ["body"]))
                self.assertEqual(len(calls), 2 if locked else 1)
                self.assertEqual(row["body"], "ok \udced\udca0\udcbd \udcff end")
                self.assertEqual(row["body"].encode("utf-8", "surrogateescape"),
                                 raw)

    def test_immutable_only_with_no_wal(self):
        """immutable=1 skips the -wal, where a live database's newest rows
        are: only one with no -wal is opened so."""
        uri = _sqlite._uri(os.path.join(self.root, "x.db"))
        self.assertTrue(uri.startswith("file:") and uri.endswith("?mode=ro"))
        self.assertNotIn("immutable", uri)
        path = os.path.join(tempfile.mkdtemp(dir=self.root), "live.db")
        writer = sqlite3.connect(path)
        writer.execute("PRAGMA journal_mode=WAL")
        writer.close()
        writer = self._db(path)                 # open: a -wal and a -shm
        real, uris = sqlite3.connect, []

        def connect(*args, **kwargs):
            uris.append(args[0])
            return real(*args, **kwargs)

        try:
            with mock.patch.object(_sqlite.sqlite3, "connect",
                                   side_effect=connect):
                with _sqlite.readonly(path) as conn:
                    self.assertEqual(len(list(_sqlite.iter_rows(
                        conn, "part", ["id"]))), 3)
        finally:
            writer.close()
        self.assertEqual(len(uris), 1)
        self.assertNotIn("immutable", uris[0])

    def test_identifiers_columns_and_filtered_rows(self):
        path = os.path.join(self.root, "q.db")
        conn = sqlite3.connect(path)
        conn.execute('CREATE TABLE "we""ird" ("co""l" TEXT, n INTEGER)')
        conn.executemany('INSERT INTO "we""ird" VALUES (?, ?)',
                         [("tool call", 1), ("prose", 2), ("tool again", 3)])
        conn.commit()
        conn.close()
        self.assertEqual(_sqlite.quote_ident('we"ird'), '"we""ird"')
        with _sqlite.readonly(path) as ro:
            self.assertEqual(_sqlite.tables(ro), ['we"ird'])
            self.assertEqual(_sqlite.columns(ro, 'we"ird'), ['co"l', "n"])
            self.assertEqual(_sqlite.column_types(ro, 'we"ird'),
                             {'co"l': "TEXT", "n": "INTEGER"})
            self.assertEqual(_sqlite.columns(ro, "absent"), [])
            rows = list(_sqlite.iter_rows(ro, 'we"ird', ['co"l', "n"],
                                          '"co""l" LIKE ?', ("tool%",)))
            self.assertEqual(rows, [{'co"l': "tool call", "n": 1},
                                    {'co"l': "tool again", "n": 3}])


# --------------------------------------------------------------------------
# _zstd
# --------------------------------------------------------------------------

ZSTD_COMMAND = __import__("shutil").which("zstd")


def _compress_with_command(data):
    return subprocess.run([ZSTD_COMMAND, "-q", "-c", "--"], input=data,
                          capture_output=True, timeout=20, check=True).stdout


class Zstd(unittest.TestCase):

    DATA = b'{"type":"session_meta"}\n' * 2000

    def test_available_says_whether_there_is_a_decoder(self):
        self.assertEqual(_zstd.available(), _zstd._stdlib is not None
                         or _zstd._command() is not None)
        with mock.patch.object(_zstd, "_stdlib", None), \
                mock.patch.object(_zstd.shutil, "which", return_value=None):
            self.assertFalse(_zstd.available())
            self.assertIsNone(_zstd.decompress(b"anything"))

    @unittest.skipUnless(ZSTD_COMMAND, "no zstd command")
    def test_round_trip_through_the_command(self):
        packed = _compress_with_command(self.DATA)
        with mock.patch.object(_zstd, "_stdlib", None):
            self.assertEqual(_zstd.decompress(packed), self.DATA)
            self.assertEqual(_zstd.decompress(packed + packed), self.DATA * 2)
            self.assertIsNone(_zstd.decompress(b"not zstd at all"))
            self.assertIsNone(_zstd.decompress(packed[:-8]))
            self.assertIsNone(_zstd.decompress(packed, limit=1000))

    @unittest.skipUnless(_zstd._stdlib, "Python before 3.14")
    def test_round_trip_through_the_standard_library(self):
        packed = _zstd._stdlib.compress(self.DATA)
        self.assertEqual(_zstd.decompress(packed), self.DATA)
        self.assertEqual(_zstd.decompress(packed + packed), self.DATA * 2)
        self.assertIsNone(_zstd.decompress(b"not zstd at all"))
        self.assertIsNone(_zstd.decompress(packed[:-8]))
        self.assertIsNone(_zstd.decompress(packed, limit=1000))


# --------------------------------------------------------------------------
# _keyfile
# --------------------------------------------------------------------------

class KeyFile(unittest.TestCase):

    def _file(self, text, newline="\n"):
        fd, path = tempfile.mkstemp(prefix="srcbase-key-")
        with os.fdopen(fd, "wb") as fh:
            fh.write(text.replace("\n", newline).encode("utf-8"))
        return path

    def test_dotenv(self):
        path = self._file(
            "\ufeffQWEN_HOME=/srv/qwen\n"
            "OPENAI_API_KEY=" "sk-" "proj-" "Hn3kQ8vZ2mXr7TpL\n"
            "QWEN_HOME_EXTRA=/nope\n"
            "  QWEN_RUNTIME_DIR=/indented\n"
            "export QWEN_RUNTIME_DIR=/exported\n"
            "QWEN_RUNTIME_DIR = '/rt dir' # a comment\n", newline="\r\n")
        self.assertEqual(_keyfile.read_keys(path, ["QWEN_HOME", "QWEN_RUNTIME_DIR"]),
                         {"QWEN_HOME": "/srv/qwen", "QWEN_RUNTIME_DIR": "/rt dir"})

    def test_only_the_names_asked_for_and_the_last_one_wins(self):
        path = self._file('A="1"\nB=2\nA=3 # later\nC=4\n')
        self.assertEqual(_keyfile.read_keys(path, ["A"]), {"A": "3"})
        self.assertEqual(_keyfile.read_keys(path, []), {})

    def test_simple_yaml(self):
        path = self._file(
            "chat-history-file: .aider.chat.history.md\n"
            "input-history-file: \"hist file.txt\"  # quoted\n"
            "llm-history-file:/no-space\n"
            "nested:\n"
            "  chat-history-file: /nested\n")
        self.assertEqual(_keyfile.read_keys(path, [
            "chat-history-file", "input-history-file", "llm-history-file"]), {
            "chat-history-file": ".aider.chat.history.md",
            "input-history-file": "hist file.txt"})

    def test_unreadable_is_empty(self):
        self.assertEqual(_keyfile.read_keys(
            os.path.join(tempfile.mkdtemp(prefix="srcbase-"), "none"), ["A"]), {})


# --------------------------------------------------------------------------
# _jsonc
# --------------------------------------------------------------------------

class Jsonc(unittest.TestCase):

    def test_comments_and_trailing_commas(self):
        text = ('\ufeff{\n'
                '  // a line comment\n'
                '  "roo-cline.customStoragePath": "/data/roo", /* block\n'
                '  comment */\n'
                '  "url": "http://x//y /* not a comment */",\n'
                '  "quoted": "a \\" // still a string,]",\n'
                '  "list": [1, 2, /* c */ ],\n'
                '}\n')
        self.assertEqual(_jsonc.loads(text), {
            "roo-cline.customStoragePath": "/data/roo",
            "url": "http://x//y /* not a comment */",
            "quoted": 'a " // still a string,]',
            "list": [1, 2]})

    def test_one_setting_from_a_file(self):
        fd, path = tempfile.mkstemp(prefix="srcbase-settings-", suffix=".json")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write('{"kilo-code.customStoragePath": "~/kilo", // moved\n}')
        self.assertEqual(_jsonc.setting(path, "kilo-code.customStoragePath"),
                         "~/kilo")
        self.assertIsNone(_jsonc.setting(path, "absent"))

    def test_what_is_not_json_is_none(self):
        self.assertIsNone(_jsonc.loads('{"a": 1 /* never closed'))
        self.assertIsNone(_jsonc.loads('{"a": }'))
        self.assertIsNone(_jsonc.loads(None))
        self.assertIsNone(_jsonc.load(os.path.join(
            tempfile.mkdtemp(prefix="srcbase-"), "settings.json")))


# --------------------------------------------------------------------------
# Data types
# --------------------------------------------------------------------------

class DataTypes(unittest.TestCase):

    def test_fixed_fields(self):
        for record in (Location("x", "/p", "default"),
                       Store("x", "/p", "jsonl"),
                       ToolCall("x", "/p", "Bash"),
                       SecretText("text"),
                       MaskResult("/p")):
            with self.assertRaises(AttributeError):
                record.surprise = 1
            json.dumps(record.as_dict(), default=repr)

    def test_store_masking_follows_the_format(self):
        self.assertEqual(Store("x", "/p", "jsonl").masking, "rewrite")
        self.assertIsNone(Store("x", "/p", "json").why_read_only)
        for fmt in ("sqlite", "jsonl.zst"):
            store = Store("x", "/p", fmt)
            self.assertEqual(store.masking, "read-only")
            self.assertTrue(store.why_read_only)
            self.assertNotIn("\u2014", store.why_read_only)
            with self.assertRaises(ValueError):
                Store("x", "/p", fmt, masking="rewrite")
        own = Store("x", "/p", "jsonl", masking="read-only",
                    why_read_only="Delete the session in Toy instead.")
        self.assertEqual(own.why_read_only, "Delete the session in Toy instead.")
        for bad in ({"format": "xml"}, {"role": "log"}, {"masking": "maybe"}):
            fields = dict({"format": "jsonl"}, **bad)
            with self.assertRaises(ValueError, msg=bad):
                Store("x", "/p", **fields)

    def test_tool_input_is_decoded(self):
        def call(value):
            return ToolCall("x", "/p", "exec_command", value).tool_input
        self.assertEqual(call('{"cmd": ["bash", "-lc", "ls"]}'),
                         {"cmd": ["bash", "-lc", "ls"]})
        self.assertEqual(call("ls -la {"), {"_raw": "ls -la {"})
        self.assertEqual(call('["a"]'), {"_value": ["a"]})
        self.assertEqual(call(["a"]), {"_value": ["a"]})
        self.assertEqual(call(None), {})
        self.assertEqual(call({"k": 1}), {"k": 1})

    def test_tool_call_kinds(self):
        ported = ToolCall("claude-code", "/p", "Bash", {"command": "ls"})
        self.assertIsNone(ported.kind)
        self.assertFalse(ported.known)
        shell = ToolCall("x", "/p", "exec_command", {"cmd": "ls", "workdir": "/w"},
                         kind="shell", known=True, command="ls", workdir="/w",
                         consumed="cmd", paths="/a")
        self.assertEqual(shell.consumed, frozenset(["cmd"]))
        self.assertEqual(shell.paths, ("/a",))
        self.assertEqual(shell.actor, "agent")
        ToolCall("x", "/p", "mcp__x__thing", kind="other", known=False)
        ToolCall("x", "/p", "!", kind="shell", known=True, actor="user",
                 status="declined")
        with self.assertRaises(ValueError):
            ToolCall("x", "/p", "Bash", kind="shell")          # unknown name
        with self.assertRaises(ValueError):
            ToolCall("x", "/p", "Bash", known=True)            # known, no kind
        with self.assertRaises(ValueError):
            ToolCall("x", "/p", "Bash", kind="exec", known=True)
        with self.assertRaises(ValueError):
            ToolCall("x", "/p", "Bash", actor="model")
        with self.assertRaises(ValueError):
            ToolCall("x", "/p", "Bash", status="failed")

    def test_mask_result_reasons(self):
        for reason in base.SKIPPED:
            MaskResult("/p", skipped=reason)
        with self.assertRaises(ValueError):
            MaskResult("/p", skipped="busy")

    def test_equal_by_value(self):
        self.assertEqual(Location("x", "/p", "default", True, 2),
                         Location("x", "/p", "default", True, 2))
        self.assertNotEqual(Location("x", "/p", "default", True, 2),
                            Location("x", "/p", "default", True, 3))


# --------------------------------------------------------------------------
# The Source interface
# --------------------------------------------------------------------------

class SourceContract(unittest.TestCase):

    def setUp(self):
        self.home = tempfile.mkdtemp(prefix="srcbase-home-")
        patches = [mock.patch.dict(os.environ, {"HOME": self.home,
                                                "USERPROFILE": self.home}),
                   mock.patch.object(_paths, "home", return_value=self.home)]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        os.environ.pop("TOY_HOME", None)
        self.backups = os.path.join(tempfile.mkdtemp(prefix="srcbase-bk-"), "b")
        p = mock.patch.object(clean, "BACKUP_ROOT", self.backups)
        p.start()
        self.addCleanup(p.stop)

    def _session(self, root, name, lines, age=0):
        os.makedirs(root, exist_ok=True)
        path = os.path.join(root, name)
        with open(path, "w", encoding="utf-8", newline="") as fh:
            for line in lines:
                fh.write(json.dumps(line) + "\n")
        when = time.time() - age
        os.utime(path, (when, when))
        return path

    def test_default_paths_on_every_platform(self):
        toy = _Toy()
        self.assertEqual(toy.default_paths({}, "/Users/u", "darwin"),
                         [("/Users/u/.toy", "default")])
        self.assertEqual(toy.default_paths({}, "/home/u", "linux"),
                         [("/home/u/.toy", "default")])
        self.assertEqual(toy.default_paths({}, "C:\\Users\\u", "win32"),
                         [("C:\\Users\\u\\.toy", "default")])
        self.assertEqual(toy.default_paths({"TOY_HOME": "/t"}, "/home/u", "linux"),
                         [("/t", "env TOY_HOME")])

    def test_override_variable_is_read_at_call_time(self):
        toy = _Toy()
        [loc] = toy.locations()
        self.assertEqual((loc.path, loc.how, loc.exists, loc.found),
                         (os.path.join(self.home, ".toy"), "default", False, 0))
        moved = os.path.join(self.home, "elsewhere")
        self._session(moved, "a.jsonl", [{"type": "call"}])
        os.environ["TOY_HOME"] = moved          # after import and construction
        [loc] = toy.locations()
        self.assertEqual((loc.path, loc.how, loc.exists, loc.found),
                         (moved, "env TOY_HOME", True, 1))
        self.assertEqual(loc.source, "toy-agent")

    def test_path_override_wins_and_is_expanded(self):
        toy = _Toy()
        self._session(os.path.join(self.home, "p1"), "a.jsonl", [], age=400 * 86400)
        locs = toy.locations(override=["~/p1", os.path.join(self.home, "p1"),
                                       "~/p2"])
        self.assertEqual([(l.path, l.how, l.exists, l.found) for l in locs], [
            (os.path.join(self.home, "p1"), "--path", True, 1),
            (os.path.join(self.home, "p2"), "--path", False, 0)])
        [loc] = toy.locations(override="~/p1")
        self.assertEqual(loc.path, os.path.join(self.home, "p1"))

    def test_locations_never_raise(self):
        class Broken(_Toy):
            def default_paths(self, env, home, platform):
                raise KeyError("HOME")
        broken = Broken()
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(broken.locations(), [])
            self.assertEqual(broken.locations(), [])
        self.assertEqual(err.getvalue().count("warning:"), 1)
        self.assertIn("Toy Agent", err.getvalue())

    def test_stores_newest_first_and_a_missing_root_is_none(self):
        toy = _Toy()
        root = os.path.join(self.home, ".toy")
        old = self._session(root, "old.jsonl", [], age=90 * 86400)
        new = self._session(root, "new.jsonl", [], age=60)
        self.assertEqual([s.path for s in toy.stores(toy.locations())], [new, old])
        self.assertEqual([s.path for s in toy.stores(toy.locations(), since_days=30)],
                         [new])
        self.assertEqual(toy.stores(toy.locations(override="~/missing")), [])

    def test_the_days_prefilter_never_drops_a_database(self):
        now = time.time()
        stores = [Store("x", "/old.db", "sqlite", mtime=now - 400 * 86400),
                  Store("x", "/old.jsonl", "jsonl", mtime=now - 400 * 86400),
                  Store("x", "/new.json", "json", mtime=now)]
        self.assertEqual([s.path for s in base.newest_first(stores, 30)],
                         ["/new.json", "/old.db"])

    def test_tool_calls_and_counters(self):
        toy = _Toy()
        root = os.path.join(self.home, ".toy")
        path = os.path.join(root, "s.jsonl")
        os.makedirs(root)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(json.dumps({"type": "call", "name": "shell",
                                 "args": {"cmd": "rm -rf ~/x", "cwd": "/w"},
                                 "t": 1790000000000}) + "\n")
            fh.write(json.dumps({"type": "call", "name": "mcp__x__y",
                                 "args": "{\"q\": 1}"}) + "\n")
            fh.write('{"type": "note"}\nnot json\n{"type": "ca')
        [store] = toy.stores(toy.locations())
        calls = list(toy.tool_calls(store))
        self.assertEqual([(c.kind, c.known, c.command, c.timestamp) for c in calls], [
            ("shell", True, "rm -rf ~/x", "2026-09-21T14:13:20Z"),
            ("other", False, None, None)])
        self.assertEqual(calls[1].tool_input, {"q": 1})
        self.assertEqual(toy.counts["unknown"], 1)
        self.assertEqual(toy.counts["unparsed"], 1)
        toy.unreadable_store("compressed, needs Python 3.14 or the zstd command")
        self.assertEqual(toy.counts["unreadable_stores"], 1)
        toy.reset()
        self.assertEqual(set(toy.counts.values()), {0})
        self.assertEqual(toy.unreadable, {})

    def test_an_unreadable_store_warns_once_and_yields_nothing(self):
        toy = _Toy()
        gone = Store("toy-agent", os.path.join(self.home, "gone.jsonl"), "jsonl")
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(list(toy.tool_calls(gone)), [])
            self.assertEqual(list(toy.tool_calls(gone)), [])
        self.assertEqual(err.getvalue().count("warning:"), 1)

    def test_base_defaults_yield_nothing(self):
        plain = Source()
        store = Store("x", "/p", "jsonl")
        self.assertEqual(plain.default_paths({}, "/h", "linux"), [])
        self.assertEqual(plain.stores([]), [])
        self.assertEqual(list(plain.tool_calls(store)), [])
        self.assertEqual(list(plain.secret_texts(store)), [])
        self.assertFalse(plain.in_use(store))

    def test_mask_refuses_read_only_and_in_use_without_writing(self):
        toy = _Toy()
        root = os.path.join(self.home, ".toy")
        path = self._session(root, "s.jsonl", [{"out": SECRET}], age=3600)
        digest = _sha(path)
        ro = toy.store(path, "jsonl", masking="read-only")
        self.assertEqual(toy.mask(ro, [SECRET]),
                         MaskResult(path, skipped="read-only"))

        class Busy(_Toy):
            def in_use(self, store):
                return True
        self.assertEqual(Busy().mask(toy.store(path, "jsonl"), [SECRET]),
                         MaskResult(path, skipped="in use"))
        self.assertEqual(_sha(path), digest)
        self.assertFalse(os.path.exists(self.backups))

        result = toy.mask(toy.store(path, "jsonl"), [SECRET])
        self.assertTrue(result.changed)
        with open(path, encoding="utf-8") as fh:
            self.assertNotIn(SECRET, fh.read())

    def test_a_text_nested_past_the_stack_does_not_stop_the_rest_of_the_store(self):
        """clean wrote a call's input out as JSON to find the file it read.
        One nested past the stack raised there, and clean gave up on the
        store: neither the secret beside it nor any after it was found."""
        deep = "TOKEN=" + SECRET
        for _ in range(100000):         # as an adapter's json.loads hands it over
            deep = {"a": deep}
        password = "Xk9mPq2v" "Rt7wLz4b"

        class Deep(_Toy):
            def secret_texts(self, store):
                call = ToolCall(self.id, store.path, "Bash", {"x": deep})
                yield SecretText({"in": deep}, call=call, where="line 1")
                yield SecretText("DB_PASSWORD=" + password, where="line 2")
        toy = Deep()
        path = self._session(os.path.join(self.home, ".toy"), "s.jsonl", [{}])
        values = {}
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            clean.scan_store(toy, toy.store(path, "jsonl"), values)
        self.assertEqual(sorted(values.values()), sorted([SECRET, password]))
        self.assertEqual(err.getvalue(), "")


# --------------------------------------------------------------------------
# _rewrite: the generic masker
# --------------------------------------------------------------------------

def _marker(value):
    return clean.REDACTION % clean._fingerprint(value)


def _go(value):
    body = json.dumps(value, ensure_ascii=False)[1:-1]
    for raw, escaped in (("&", "\\u0026"), ("<", "\\u003c"), (">", "\\u003e"),
                         ("\u2028", "\\u2028"), ("\u2029", "\\u2029")):
        body = body.replace(raw, escaped)
    return body


# Each line holds the value in one of the encodings a writer can give it.
# The file is lines_for(value); the expected result is lines_for(marker),
# built independently of the code under test, so "nothing but the secret
# changed" is a byte comparison. The marker needs no JSON escape, so every
# slot holds it as is; Go's slot too, since the marker replaces the whole
# Go-escaped value.
def _lines_for(value, masked=False):
    def nested(ascii_only):
        inner = json.dumps({"cmd": "echo " + value}, ensure_ascii=ascii_only)
        return json.dumps(inner, ensure_ascii=ascii_only)[1:-1]
    unicode_body = json.dumps(value, ensure_ascii=False)[1:-1]
    return [
        '{"type":"session_meta","cwd":"/w/caf\u00e9"}',
        '{"type":"function_call_output", "output":"KEY=%s\\nOTHER=1"}'
        % unicode_body,
        '{ "z": 1,  "a": "\u2615",   "s": "%s" }' % json.dumps(value)[1:-1],
        '{"go":"PASS=%s"}' % (unicode_body if masked else _go(value)),
        '{"type":"function_call","arguments":"%s"}' % nested(True),
        '{"arguments":"%s"}' % nested(False),
        '{"type":"unrelated","text":"no secret, a \\u00e9 escape"}',
    ]


class Rewrite(unittest.TestCase):

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="srcbase-rw-")
        self.backups = os.path.join(tempfile.mkdtemp(prefix="srcbase-bk-"), "b")
        p = mock.patch.object(clean, "BACKUP_ROOT", self.backups)
        p.start()
        self.addCleanup(p.stop)

    def _write(self, name, data, mode=0o640, age=3600):
        path = os.path.join(self.dir, name)
        with open(path, "wb") as fh:
            fh.write(data)
        if not WINDOWS:
            os.chmod(path, mode)
        when = time.time() - age
        os.utime(path, (when, when))
        return path

    def _read(self, path):
        with open(path, "rb") as fh:
            return fh.read()

    def _backups(self):
        return [os.path.join(d, f) for d, _s, files in os.walk(self.backups)
                for f in files]

    def _no_tmp(self):
        self.assertEqual(glob.glob(os.path.join(self.dir, "*.ranwhat-tmp")), [])

    def _encodings_left(self, data, value):
        text = data.decode("utf-8", "surrogateescape")
        return [form for form in _rewrite.encodings(value) if form in text]

    def _jsonl(self, value):
        """(original, expected): CRLF and LF lines, a line that is not
        JSON, and a last line the agent is still writing."""
        def build(lines, v):
            return ("\r\n".join(lines[:2]) + "\r\n" + "\n".join(lines[2:])
                    + "\nnot json at all " + v + "\n"
                    + '{"partial":"' + v).encode("utf-8")
        m = _marker(value)
        return (build(_lines_for(value), value),
                build(_lines_for(m, masked=True), m))

    def _round_trip(self, value):
        original, expected = self._jsonl(value)
        path = self._write("rollout.jsonl", original)
        result = _rewrite.rewrite_file(path, [value], "jsonl")
        self.assertEqual((result.path, result.changed, result.skipped),
                         (path, True, None))
        after = self._read(path)
        self.assertEqual(after, expected, "a byte other than the secret changed")
        self.assertEqual(self._encodings_left(after, value), [])
        # the file still parses, line for line, and the inner JSON too
        lines = after.decode("utf-8").split("\n")
        for line in lines[:-2]:
            if line.strip():
                json.loads(line)
        inner = json.loads(json.loads(lines[4])["arguments"])
        self.assertEqual(inner, {"cmd": "echo " + _marker(value)})
        # the backup is the original, byte for byte, and private
        self.assertEqual(self._backups(), [result.backup])
        self.assertEqual(self._read(result.backup), original)
        if not WINDOWS:
            self.assertEqual(stat.S_IMODE(os.stat(result.backup).st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o640)
        self._no_tmp()
        # a second run changes nothing, even right after the first
        again = _rewrite.rewrite_file(path, [value], "jsonl")
        self.assertEqual(again, MaskResult(path))
        self.assertEqual(self._read(path), expected)
        self.assertEqual(len(self._backups()), 1)

    def test_round_trip_plain_token(self):
        self._round_trip(SECRET)

    def test_round_trip_every_escape(self):
        self._round_trip(PASSWORD)

    def test_several_values_longest_first(self):
        short = SECRET[:20]
        path = self._write("s.jsonl", ('{"a":"%s","b":"%s only"}\n'
                                       % (SECRET, short)).encode("utf-8"))
        result = _rewrite.rewrite_file(path, [short, SECRET, "", None], "jsonl")
        self.assertTrue(result.changed)
        self.assertEqual(json.loads(self._read(path)), {
            "a": _marker(SECRET), "b": _marker(short) + " only"})

    def test_json_document(self):
        doc = ('{\n  "messages": [\n    {"say": "command_output",\n'
               '     "text": "TOKEN=%s"}\n  ],\n  "ts": 1790000000000\n}\n'
               % json.dumps(PASSWORD)[1:-1])
        path = self._write("ui_messages.json", doc.encode("utf-8"))
        result = _rewrite.rewrite_file(path, [PASSWORD], "json")
        self.assertTrue(result.changed)
        self.assertEqual(self._read(path).decode("utf-8"),
                         doc.replace(json.dumps(PASSWORD)[1:-1], _marker(PASSWORD)))

    def test_text_file(self):
        text = "# aider chat\n> cat .env\nKEY=%s\n\nDone.\n" % SECRET
        path = self._write("history.md", text.encode("utf-8"))
        result = _rewrite.rewrite_file(path, [SECRET], "text")
        self.assertTrue(result.changed)
        self.assertEqual(self._read(path).decode("utf-8"),
                         text.replace(SECRET, _marker(SECRET)))

    def test_byte_arrays(self):
        payload = list(("cat .env\nKEY=" + SECRET + "\n").encode("utf-8"))
        line = '{"type":"tool_output","stdout":%s,"note":"%s"}\n' % (
            json.dumps(payload, separators=(",", ":")), SECRET)
        path = self._write("updates.jsonl", line.encode("utf-8"))
        self.assertTrue(_rewrite.rewrite_file(path, [SECRET], "jsonl").changed)
        obj = json.loads(self._read(path))
        self.assertIn(SECRET, bytes(obj["stdout"]).decode("utf-8"),
                      "byte arrays are left alone unless the format has them")
        self.assertEqual(obj["note"], _marker(SECRET))

        path = self._write("updates2.jsonl", line.encode("utf-8"))
        self.assertTrue(_rewrite.rewrite_file(path, [SECRET], "jsonl",
                                              byte_arrays=True).changed)
        obj = json.loads(self._read(path))
        self.assertEqual(bytes(obj["stdout"]).decode("utf-8"),
                         "cat .env\nKEY=" + _marker(SECRET) + "\n")

    def test_a_lone_surrogate_does_not_crash_the_byte_array_form(self):
        value = "tok-\ud83d-" + SECRET            # from a "\ud83d" JSON escape
        line = '{"t":"%s","b":[1,2]}\n' % json.dumps(value)[1:-1]
        path = self._write("u.jsonl", line.encode("ascii"))
        result = _rewrite.rewrite_file(path, [value], "jsonl", byte_arrays=True)
        self.assertTrue(result.changed)
        self.assertEqual(json.loads(self._read(path)),
                         {"t": _marker(value), "b": [1, 2]})

    def test_a_line_nested_past_the_stack_does_not_stop_the_rest_being_masked(self):
        """3.14's json reads a line far deeper than the check can walk, and
        3.9's cannot read it at all. On 3.14 one such line refused the
        whole file, the secret on another line too; on 3.9 a string holding
        JSON that deep did. Each is now what a line json cannot read is:
        only its raw text is masked, and every other line is checked."""
        for depth in (2000, 100000):
            nest = '{"a":' * depth + "1" + "}" * depth
            lines = ['{"note":"an \\u00e9 escape","d":%s}' % nest,
                     '{"out":"KEY=%s"}' % SECRET,
                     '{"s":"KEY=%s","d":%s}' % (SECRET, nest),
                     '{"args":"%s","s":"KEY=%s"}' % ("[" * depth + "]" * depth, SECRET)]
            original = ("\n".join(lines) + "\n").encode("utf-8")
            expected = original.replace(SECRET.encode(), _marker(SECRET).encode())
            for byte_arrays in (False, True):
                with self.subTest(depth=depth, byte_arrays=byte_arrays):
                    path = self._write("deep.jsonl", original)
                    result = _rewrite.rewrite_file(path, [SECRET], "jsonl",
                                                   byte_arrays=byte_arrays)
                    self.assertEqual((result.changed, result.skipped), (True, None))
                    # Not assertEqual: a diff of these lines is megabytes.
                    self.assertTrue(self._read(path) == expected,
                                    "a byte other than the secret changed")

    def test_a_document_nested_past_the_stack_is_refused_whole(self):
        """A .json file is one document, checked whole: one too deep for the
        check is left as it is, as one json cannot read, never half checked."""
        for depth in (2000, 100000):
            with self.subTest(depth=depth):
                doc = ('{"s":"KEY=%s","d":%s}\n' % (
                    SECRET, '{"a":' * depth + "1" + "}" * depth)).encode("utf-8")
                path = self._write("deep.json", doc)
                result = _rewrite.rewrite_file(path, [SECRET], "json")
                self.assertEqual((result.changed, result.skipped),
                                 (False, _rewrite.ALTERED))
                self.assertTrue(self._read(path) == doc, "the document changed")
                self.assertEqual(self._backups(), [])

    # -- one pass, as replacing each form in turn did ---------------------

    # Characters that overlap each other's forms (quotes, backslashes, a
    # newline, non-ASCII, Go's escapes) and none of a marker's, so a value
    # never meets a marker put in before it.
    _ALPHABET = 'xyzXYZ"\\\n/é&_  '

    def _random_case(self, rnd):
        """(values, text): values short and long, some inside others or
        sharing a prefix, and a text of their forms, byte lists and noise."""
        def word(lo, hi):
            return "".join(rnd.choice(self._ALPHABET)
                           for _ in range(rnd.randint(lo, hi)))
        values = [word(1, 40) for _ in range(rnd.randint(1, 5))]
        for _ in range(rnd.randint(0, 3)):
            v = rnd.choice(values)
            values.append(rnd.choice([v[:rnd.randint(1, len(v))],
                                      v + word(1, 9), word(1, 3) + v]))
        pieces = []
        for _ in range(rnd.randint(1, 30)):
            v = rnd.choice(values)
            pieces.append(rnd.choice(
                [v, rnd.choice(_rewrite.encodings(v)), word(0, 12),
                 "[%s]" % _rewrite._byte_list(v),
                 "[1,%s,2]" % _rewrite._byte_list(v)]))
        return values, "".join(pieces)

    def test_one_pass_makes_what_replacing_each_form_in_turn_made(self):
        import random
        import re

        def in_turn(text, plan, byte_arrays):
            for value, marker in plan:
                for form in _rewrite.encodings(value):
                    text = text.replace(form, marker)
                if byte_arrays:
                    text = re.sub(r"(?<=[\[,])" + re.escape(_rewrite._byte_list(value))
                                  + r"(?=[,\]])", _rewrite._byte_list(marker), text)
            return text

        def any_left(text, plan, byte_arrays):
            return any(
                any(form in text for form in _rewrite.encodings(value))
                or (byte_arrays and re.search(
                    r"(?<=[\[,])" + re.escape(_rewrite._byte_list(value))
                    + r"(?=[,\]])", text) is not None)
                for value, _m in plan)

        rnd = random.Random(11)
        for case in range(400):
            values, text = self._random_case(rnd)
            plan = _rewrite._plan(values)
            for byte_arrays in (False, True):
                with self.subTest(case=case, byte_arrays=byte_arrays):
                    want = in_turn(text, plan, byte_arrays)
                    self.assertEqual(_rewrite._replace_text(text, plan, byte_arrays),
                                     want)
                    for sample in (text, want, text[:len(text) // 2]):
                        self.assertEqual(_rewrite._leftover(sample, plan, byte_arrays),
                                         any_left(sample, plan, byte_arrays))

    def test_strings_are_masked_as_masking_each_in_turn_did(self):
        import random

        def in_turn(node, plan, byte_arrays):
            def one(text):
                for value, marker in plan:
                    text = text.replace(value, marker)
                return text
            if isinstance(node, str):
                return one(node)
            if isinstance(node, list):
                if byte_arrays and _rewrite._is_byte_array(node):
                    return list(_rewrite._utf8(one(
                        bytes(node).decode("utf-8", "surrogateescape"))))
                return [in_turn(v, plan, byte_arrays) for v in node]
            if isinstance(node, tuple) and node[0] == "obj":
                return ("obj", tuple((one(k), in_turn(v, plan, byte_arrays))
                                     for k, v in node[1]))
            if isinstance(node, tuple) and node[0] == "json":
                return ("json", in_turn(node[1], plan, byte_arrays))
            return node

        rnd = random.Random(12)
        for case in range(300):
            values, text = self._random_case(rnd)
            v = rnd.choice(values)
            doc = {text: [text[::-1], 7, {"inner": json.dumps({v: [v, text]})}],
                   "bytes": list(("pre " + v).encode("utf-8")), v: v + v}
            node = _rewrite._expand(_rewrite._decode(json.dumps(doc)))
            plan = _rewrite._plan(values)
            for byte_arrays in (False, True):
                with self.subTest(case=case, byte_arrays=byte_arrays):
                    self.assertEqual(
                        _rewrite._mask(node, _rewrite._Forms.raw(plan), byte_arrays),
                        in_turn(node, plan, byte_arrays))

    # -- refusals -------------------------------------------------------

    def _refused(self, path, reason, **kwargs):
        before, mtime = self._read(path), os.stat(path).st_mtime_ns
        result = _rewrite.rewrite_file(path, **kwargs)
        self.assertEqual(result, MaskResult(path, skipped=reason))
        self.assertEqual(self._read(path), before)
        self.assertEqual(os.stat(path).st_mtime_ns, mtime)
        self.assertEqual(self._backups(), [])
        self._no_tmp()

    def test_refused_when_written_recently(self):
        original, _expected = self._jsonl(SECRET)
        path = self._write("live.jsonl", original, age=5)
        self._refused(path, "in use", values=[SECRET], kind="jsonl")
        path = self._write("future.jsonl", original, age=-600)  # clock skew
        self._refused(path, "in use", values=[SECRET], kind="jsonl")
        path = self._write("quiet.jsonl", original,
                           age=_rewrite.QUIET_SECONDS + 5)
        self.assertTrue(_rewrite.rewrite_file(path, [SECRET], "jsonl").changed)

    def test_refused_when_a_number_would_change(self):
        value = "4111222233334444"
        path = self._write("n.jsonl", ('{"n": %s5, "s": "card %s"}\n'
                                       % (value, value)).encode("utf-8"))
        self._refused(path, "would alter more than the secret",
                      values=[value], kind="jsonl")

    def test_refused_when_the_structure_would_change(self):
        # Raw, the value spans two JSON strings and the key between them.
        value = 'abc' '","b":"' 'def-Qw7Zr'
        data = '{"a":"abc","b":"def-Qw7Zr"}\n'.encode("utf-8")
        path = self._write("s.jsonl", data)
        self._refused(path, "would alter more than the secret",
                      values=[value], kind="jsonl")
        path = self._write("s.json", data)
        self._refused(path, "would alter more than the secret",
                      values=[value], kind="json")

    def test_refused_when_a_copy_is_in_a_form_it_cannot_mask(self):
        # Upper-case hex escapes are valid JSON but not an encoding any
        # writer here produces: the copy would survive, so nothing is done.
        value = "caf\u00e9-" + SECRET
        odd = json.dumps(value)[1:-1].replace("\\u00e9", "\\u00E9")
        data = ('{"a":"%s"}\n{"b":"%s"}\n' % (value, odd)).encode("utf-8")
        path = self._write("odd.jsonl", data)
        self._refused(path, "would alter more than the secret",
                      values=[value], kind="jsonl")

    def test_refused_when_a_text_file_would_lose_lines(self):
        pem = "-----BEGIN KEY-----\nQk9HVVMgS0VZ\n-----END KEY-----"
        path = self._write("h.md", ("> cat key\n%s\n" % pem).encode("utf-8"))
        self._refused(path, "would alter more than the secret",
                      values=[pem], kind="text")

    def test_read_only_formats_are_never_opened(self):
        path = self._write("x.db", b"SQLite format 3\x00" + SECRET.encode("ascii"))
        for kind in ("sqlite", "jsonl.zst"):
            with mock.patch("builtins.open", side_effect=AssertionError("open")):
                self.assertEqual(_rewrite.rewrite_file(path, [SECRET], kind),
                                 MaskResult(path, skipped="read-only"))

    @unittest.skipUnless(hasattr(os, "mkfifo"), "no FIFOs here")
    def test_not_a_regular_file(self):
        path = os.path.join(self.dir, "fifo.jsonl")
        os.mkfifo(path)
        self.assertEqual(_rewrite.rewrite_file(path, [SECRET], "jsonl"),
                         MaskResult(path, skipped="read-only"))

    def test_nothing_to_mask(self):
        path = self._write("c.jsonl", b'{"a":"clean"}\n', age=0)
        self.assertEqual(_rewrite.rewrite_file(path, [SECRET], "jsonl"),
                         MaskResult(path))
        self.assertEqual(_rewrite.rewrite_file(path, ["", None], "jsonl"),
                         MaskResult(path))
        self.assertEqual(self._backups(), [])

    def test_refused_when_the_file_changes_while_masking(self):
        original, _expected = self._jsonl(SECRET)
        path = self._write("grow.jsonl", original)
        real_backup = clean._backup

        def backup_then_agent_writes(p):
            dest = real_backup(p)
            with open(p, "ab") as fh:
                fh.write(b'{"type":"new turn"}\n')
            return dest

        with mock.patch.object(clean, "_backup", backup_then_agent_writes):
            result = _rewrite.rewrite_file(path, [SECRET], "jsonl")
        self.assertEqual(result, MaskResult(path, skipped="changed while reading"))
        self.assertEqual(self._read(path), original + b'{"type":"new turn"}\n')
        self.assertEqual(self._backups(), [], "an unused backup is removed")
        self._no_tmp()

    def test_windows_file_held_open_is_in_use(self):
        original, _expected = self._jsonl(SECRET)
        path = self._write("held.jsonl", original)
        with mock.patch.object(_rewrite, "_WINDOWS", True), \
                mock.patch.object(_rewrite.os, "replace",
                                  side_effect=PermissionError("in use")):
            result = _rewrite.rewrite_file(path, [SECRET], "jsonl")
        self.assertEqual(result, MaskResult(path, skipped="in use"))
        self.assertEqual(self._read(path), original)
        self.assertEqual(self._backups(), [])
        self._no_tmp()

    def test_other_permission_errors_are_raised(self):
        original, _expected = self._jsonl(SECRET)
        path = self._write("perm.jsonl", original)
        with mock.patch.object(_rewrite, "_WINDOWS", False), \
                mock.patch.object(_rewrite.os, "replace",
                                  side_effect=PermissionError("sticky dir")):
            with self.assertRaises(PermissionError):
                _rewrite.rewrite_file(path, [SECRET], "jsonl")
        self.assertEqual(self._read(path), original)
        self.assertEqual(self._backups(), [])
        self._no_tmp()

    @unittest.skipIf(WINDOWS, "symlinks need privileges on Windows")
    def test_a_symlinked_store_masks_the_file_it_points_to(self):
        target = self._write("real.jsonl", ('{"a":"%s"}\n' % SECRET).encode("utf-8"))
        link = os.path.join(self.dir, "link.jsonl")
        os.symlink(target, link)
        result = _rewrite.rewrite_file(link, [SECRET], "jsonl")
        self.assertEqual((result.path, result.changed), (link, True))
        self.assertTrue(os.path.islink(link))
        self.assertNotIn(SECRET.encode("ascii"), self._read(target))


if __name__ == "__main__":
    unittest.main(verbosity=2)
