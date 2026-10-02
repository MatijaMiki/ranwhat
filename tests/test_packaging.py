"""Packaging metadata.

Old setuptools silently builds a wheel named UNKNOWN-0.0.0 when it cannot
read PEP 621 metadata, which installs without error and provides no command.
These check the declared metadata stays intact and in sync.
"""
import os
import re
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import isolated_home  # noqa: E402,F401  ranwhat's state, never ~/.ranwhat
import ranwhat


def pyproject():
    with open(os.path.join(ROOT, "pyproject.toml"), encoding="utf-8") as fh:
        return fh.read()


class Metadata(unittest.TestCase):

    def test_version_matches_package(self):
        declared = re.search(r'^version\s*=\s*"([^"]+)"', pyproject(),
                             re.M).group(1)
        self.assertEqual(declared, ranwhat.__version__)

    def test_console_script_target_is_importable(self):
        target = re.search(r'^ranwhat\s*=\s*"([^"]+)"', pyproject(),
                           re.M).group(1)
        module, _, attr = target.partition(":")
        mod = __import__(module, fromlist=[attr])
        self.assertTrue(callable(getattr(mod, attr)))

    def test_no_runtime_dependencies(self):
        """This gets pointed at the user's own credentials. A dependency tree
        is something a reviewer has to audit before that is reasonable."""
        deps = re.search(r"^dependencies\s*=\s*\[(.*?)\]", pyproject(),
                         re.M | re.S).group(1).strip()
        self.assertEqual(deps, "")

    def test_bundled_demo_data_is_inside_the_package(self):
        """It previously installed to site-packages/demo/, a top-level
        directory that would collide with any other package shipping one."""
        self.assertIn('ranwhat = ["demo/*.json"]', pyproject())
        self.assertTrue(os.path.isfile(
            os.path.join(ROOT, "ranwhat", "demo", "support-copilot.json")))

    def test_every_package_is_listed(self):
        """setuptools builds only the packages named, so a subpackage left
        out installs without error and fails on its first import."""
        listed = re.search(r"^packages\s*=\s*\[(.*?)\]", pyproject(),
                           re.M | re.S).group(1)
        listed = set(re.findall(r'"([^"]+)"', listed))
        found = set()
        for folder, _dirs, files in os.walk(os.path.join(ROOT, "ranwhat")):
            if "__init__.py" in files:
                rel = os.path.relpath(folder, ROOT)
                found.add(rel.replace(os.sep, "."))
        self.assertIn("ranwhat.sources", found)
        self.assertEqual(listed, found)

    def test_demo_loads_through_the_package(self):
        from ranwhat.cli import _bundled
        self.assertEqual(_bundled("support-copilot.json")["agent"],
                         "support-copilot")


if __name__ == "__main__":
    unittest.main(verbosity=2)


@unittest.skipIf(os.name == "nt", "POSIX environment layouts")
class SuggestedCommands(unittest.TestCase):
    """The overview and the `check` tail suggest follow-up commands. They have
    to work in the user's shell after this process exits.

    These build real directory trees and use the real shutil.which. The first
    version stubbed which() to return None under uvx, which is exactly what
    never happens: uvx prepends its throwaway bin to PATH, so the lookup found
    us and every uvx user was told to run a command that does not exist."""

    def setUp(self):
        import tempfile
        self._tmp = tempfile.TemporaryDirectory()
        self.t = os.path.realpath(self._tmp.name)
        self.home = self.mkdir("home")

    def tearDown(self):
        self._tmp.cleanup()

    def mkdir(self, *parts):
        path = os.path.join(self.t, *parts)
        os.makedirs(path, exist_ok=True)
        return path

    def exe(self, path):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("#!/bin/sh\n")
        os.chmod(path, 0o755)
        return path

    def entry(self, root):
        return self.exe(os.path.join(root, "bin", "ranwhat"))

    def env(self, path, **extra):
        # clear=True drops the machine's own UV, UV_CACHE_DIR, XDG_*, PIPX_HOME
        # and VIRTUAL_ENV; the suite itself may be running from a uv cache.
        env = {"HOME": self.home, "USERPROFILE": self.home,
               "PATH": os.pathsep.join(path)}
        env.update(extra)
        return env

    def invoke(self, argv0, prefix, path, executable="/synthetic/python3",
               argv=None, **extra):
        from unittest import mock
        from ranwhat import cli
        with mock.patch.dict(os.environ, self.env(path, **extra), clear=True), \
             mock.patch.object(sys, "argv", [argv0] if argv is None else argv), \
             mock.patch.object(sys, "prefix", prefix), \
             mock.patch.object(sys, "executable", executable):
            return cli.invocation()

    def uvx(self, root, path_tail=("/usr/bin", "/bin"), **extra):
        """A uvx child as uv really builds it: its own bin FIRST on PATH."""
        argv0 = self.entry(root)
        path = [os.path.join(root, "bin")] + list(path_tail)
        extra.setdefault("UV", "/synthetic/uv")
        with_env = self.env(path, **extra)
        import shutil as _shutil
        # The premise the old test got wrong: under uvx, which() finds us.
        self.assertEqual(os.path.realpath(_shutil.which(
            "ranwhat", path=with_env["PATH"])), os.path.realpath(argv0))
        return self.invoke(argv0, root, path, **extra)

    # -- throwaway environments: must not suggest the bare command ----------

    def test_uvx_default_cache_with_its_bin_prepended(self):
        root = self.mkdir("home", ".cache", "uv", "archive-v0", "WXo1")
        self.assertEqual(self.uvx(root), "uvx ranwhat")

    def test_uvx_with_uv_cache_dir(self):
        root = self.mkdir("custom-uv", "archive-v0", "AAA")
        self.assertEqual(self.uvx(root, UV_CACHE_DIR=os.path.join(self.t, "custom-uv")),
                         "uvx ranwhat")

    def test_uvx_with_xdg_cache_home(self):
        root = self.mkdir("xdg", "uv", "archive-v0", "BBB")
        self.assertEqual(self.uvx(root, XDG_CACHE_HOME=os.path.join(self.t, "xdg")),
                         "uvx ranwhat")

    def test_uvx_cache_dir_flag_found_by_cachedir_tag(self):
        root = self.mkdir("cli-cache", "archive-v3", "CCC")
        open(os.path.join(self.t, "cli-cache", "CACHEDIR.TAG"), "w",
             encoding="utf-8").close()
        self.assertEqual(self.uvx(root), "uvx ranwhat")

    def test_uvx_cache_found_without_uv_on_the_env(self):
        # Layout alone, so no help from the PATH rule: bin prepended, UV unset,
        # and UV_CACHE_DIR left unexpanded the way a quoted value arrives.
        root = self.mkdir("home", "c", "archive-v0", "ID")
        self.assertEqual(self.uvx(root, UV="", UV_CACHE_DIR="~/c"), "uvx ranwhat")

    def test_uvx_reached_through_an_environments_symlink(self):
        self.mkdir("home", ".cache", "uv", "archive-v0", "WXo1")
        self.mkdir("home", ".cache", "uv", "environments-v2", "h1")
        link = os.path.join(self.home, ".cache", "uv", "environments-v2", "h1", "k1")
        os.symlink(os.path.join("..", "..", "archive-v0", "WXo1"), link)
        self.assertEqual(self.uvx(link), "uvx ranwhat")

    def test_uv_temp_env_in_another_bucket(self):
        root = self.mkdir("home", ".cache", "uv", "builds-v0", ".tmpXYZ")
        self.assertEqual(self.uvx(root), "uvx ranwhat")

    def test_uvx_running_python_m_stays_uvx(self):
        root = self.mkdir("home", ".cache", "uv", "archive-v0", "WXo1")
        python = self.exe(os.path.join(root, "bin", "python"))
        got = self.invoke("/x/site-packages/ranwhat/__main__.py", root,
                          [os.path.join(root, "bin"), "/usr/bin"],
                          executable=python, UV="/synthetic/uv")
        self.assertEqual(got, "uvx ranwhat")

    def test_uvx_from_a_cache_at_an_unknown_root(self):
        # No known root and no CACHEDIR.TAG: only stripping uv's prepend helps.
        root = self.mkdir("weird", "archive-v0", "ID")
        self.assertEqual(self.uvx(root), "uvx ranwhat")

    def test_uvx_reusing_a_uv_tool_install_whose_bin_is_not_on_path(self):
        root = self.mkdir("home", ".local", "share", "uv", "tools", "ranwhat")
        self.mkdir("home", ".local", "bin")
        os.symlink(os.path.join(root, "bin", "ranwhat"),
                   os.path.join(self.home, ".local", "bin", "ranwhat"))
        self.assertEqual(self.uvx(root), "uvx ranwhat")

    def test_uv_run_in_an_unactivated_project_venv(self):
        venv = self.mkdir("proj", ".venv")
        got = self.uvx(venv, path_tail=("/usr/bin",), VIRTUAL_ENV=venv)
        self.assertNotEqual(got, "ranwhat")
        self.assertEqual(got, "uvx ranwhat")

    def test_pipx_run_legacy_home(self):
        root = self.mkdir("home", ".local", "pipx", ".cache", "d1g3st")
        self.assertEqual(self.invoke(self.entry(root), root, ["/usr/bin"]),
                         "pipx run ranwhat")

    def test_pipx_run_with_pipx_home(self):
        root = self.mkdir("ph", ".cache", "d2")
        got = self.invoke(self.entry(root), root, ["/usr/bin"],
                          PIPX_HOME=os.path.join(self.t, "ph"))
        self.assertEqual(got, "pipx run ranwhat")

    def test_pipx_run_platform_cache_dirs(self):
        # pipx >= 1.3 without PIPX_HOME: platformdirs' user cache dir.
        for parts in ((".cache", "pipx", "d3"), ("Library", "Caches", "pipx", "d4")):
            root = self.mkdir("home", *parts)
            self.assertEqual(self.invoke(self.entry(root), root, ["/usr/bin"]),
                             "pipx run ranwhat", parts)

    # -- python -m ----------------------------------------------------------

    def test_python_m_from_a_checkout(self):
        python = self.exe(os.path.join(self.t, "pybin", "python3"))
        got = self.invoke("/src/ranwhat/__main__.py", self.mkdir("pybase"),
                          [os.path.join(self.t, "pybin"), "/usr/bin"],
                          executable=python)
        self.assertEqual(got, "python3 -m ranwhat")

    def test_python_m_with_the_interpreter_off_path(self):
        import shlex
        python = self.exe(os.path.join(self.t, "hidden bin", "python3.12"))
        got = self.invoke("/src/ranwhat/__main__.py", self.mkdir("pybase"),
                          [self.mkdir("emptybin")], executable=python)
        self.assertEqual(got, shlex.quote(python) + " -m ranwhat")

    def test_python_m_from_a_venv_whose_python_links_to_one_on_path(self):
        import shlex
        base = self.exe(os.path.join(self.t, "base", "python3"))
        venv = self.mkdir("v")
        self.mkdir("v", "bin")
        python = os.path.join(venv, "bin", "python3")
        os.symlink(base, python)
        got = self.invoke("/src/ranwhat/__main__.py", venv,
                          [os.path.join(self.t, "base"), "/usr/bin"],
                          executable=python)
        self.assertEqual(got, shlex.quote(python) + " -m ranwhat")

    def test_uv_run_python_m_does_not_trust_the_prepended_python(self):
        import shlex
        venv = self.mkdir("proj", ".venv")
        python = self.exe(os.path.join(venv, "bin", "python3"))
        self.exe(os.path.join(self.t, "base", "python3"))
        got = self.invoke("/src/ranwhat/__main__.py", venv,
                          [os.path.join(venv, "bin"), os.path.join(self.t, "base")],
                          executable=python, UV="/synthetic/uv", VIRTUAL_ENV=venv)
        self.assertEqual(got, shlex.quote(python) + " -m ranwhat")

    def launcher(self, path, starts):
        """A `python3` that is not the interpreter but starts it, the way
        macOS's /usr/bin/python3 starts the Command Line Tools' copy. Asked
        for sys.executable, it answers with the interpreter it runs."""
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("#!/bin/sh\nprintf '%%s' '%s'\n" % starts)
        os.chmod(path, 0o755)
        return path

    def test_python_m_through_a_launcher_on_path(self):
        # Was "/Library/Developer/CommandLineTools/usr/bin/python3 -m ranwhat"
        # for someone who had typed `python3 -m ranwhat`.
        python = self.exe(os.path.join(self.t, "CLT", "usr", "bin", "python3"))
        usrbin = os.path.join(self.t, "usrbin")
        self.launcher(os.path.join(usrbin, "python3"), python)
        got = self.invoke("/src/ranwhat/__main__.py", self.mkdir("pybase"),
                          [usrbin], executable=python)
        self.assertEqual(got, "python3 -m ranwhat")

    def test_python_m_when_python3_starts_another_interpreter(self):
        import shlex
        python = self.exe(os.path.join(self.t, "CLT", "usr", "bin", "python3"))
        usrbin = os.path.join(self.t, "usrbin")
        self.launcher(os.path.join(usrbin, "python3"),
                      os.path.join(self.t, "other", "python3"))
        got = self.invoke("/src/ranwhat/__main__.py", self.mkdir("pybase"),
                          [usrbin], executable=python)
        self.assertEqual(got, shlex.quote(python) + " -m ranwhat")

    def test_python_m_under_a_versioned_name_offers_python3(self):
        python = self.exe(os.path.join(self.t, "opt", "bin", "python3.12"))
        usrbin = os.path.join(self.t, "usrbin")
        self.launcher(os.path.join(usrbin, "python3"), python)
        got = self.invoke("/src/ranwhat/__main__.py", self.mkdir("pybase"),
                          [usrbin], executable=python)
        self.assertEqual(got, "python3 -m ranwhat")

    def test_a_launcher_that_hangs_falls_back_to_the_full_path(self):
        import shlex
        import subprocess
        from unittest import mock
        python = self.exe(os.path.join(self.t, "CLT", "usr", "bin", "python3"))
        usrbin = os.path.join(self.t, "usrbin")
        self.launcher(os.path.join(usrbin, "python3"), python)
        with mock.patch("subprocess.run",
                        side_effect=subprocess.TimeoutExpired("python3", 3)):
            got = self.invoke("/src/ranwhat/__main__.py", self.mkdir("pybase"),
                              [usrbin], executable=python)
        self.assertEqual(got, shlex.quote(python) + " -m ranwhat")

    # -- lasting installs: the bare command is right -------------------------

    def test_uv_tool_install(self):
        tools = self.mkdir("home", ".local", "share", "uv", "tools", "ranwhat")
        target = self.entry(tools)
        link = os.path.join(self.mkdir("home", ".local", "bin"), "ranwhat")
        os.symlink(target, link)
        got = self.invoke(link, tools,
                          [os.path.join(self.home, ".local", "bin"), "/usr/bin"])
        self.assertEqual(got, "ranwhat")

    def test_uvx_reusing_a_uv_tool_install_whose_bin_is_on_path(self):
        root = self.mkdir("home", ".local", "share", "uv", "tools", "ranwhat")
        self.mkdir("home", ".local", "bin")
        os.symlink(os.path.join(root, "bin", "ranwhat"),
                   os.path.join(self.home, ".local", "bin", "ranwhat"))
        got = self.uvx(root, path_tail=(os.path.join(self.home, ".local", "bin"),
                                        "/usr/bin"))
        self.assertEqual(got, "ranwhat")

    def test_pipx_install(self):
        venv = self.mkdir("home", ".local", "pipx", "venvs", "ranwhat")
        link = os.path.join(self.mkdir("home", ".local", "bin"), "ranwhat")
        os.symlink(self.entry(venv), link)
        got = self.invoke(link, venv,
                          [os.path.join(self.home, ".local", "bin"), "/usr/bin"])
        self.assertEqual(got, "ranwhat")

    def activated(self, venv, **extra):
        extra.setdefault("VIRTUAL_ENV", venv)
        return self.invoke(self.entry(venv), venv,
                           [os.path.join(venv, "bin"), "/usr/bin"], **extra)

    def test_venv_beside_the_uv_cache_is_not_inside_it(self):
        venv = self.mkdir("home", ".cache", "uv-sibling", "venv")
        self.assertEqual(self.activated(venv), "ranwhat")

    def test_user_venv_named_like_a_uv_bucket(self):
        venv = self.mkdir("home", "proj", "archive-v0", "venv")
        self.assertEqual(self.activated(venv), "ranwhat")

    def test_venv_under_some_other_dot_cache(self):
        venv = self.mkdir("home", "work", ".cache", "venv")
        self.assertEqual(self.activated(venv), "ranwhat")

    def test_activated_venv_without_uv(self):
        venv = self.mkdir("v")
        self.assertEqual(self.activated(venv, VIRTUAL_ENV=""), "ranwhat")

    def test_uv_on_the_env_alone_does_not_mean_throwaway(self):
        # Only a leading PATH entry that is our own bin is treated as uv's.
        venv = self.mkdir("home", "proj", ".venv")
        got = self.invoke(self.entry(venv), venv,
                          [self.mkdir("home", "bin"), os.path.join(venv, "bin"),
                           "/usr/bin"],
                          UV="/synthetic/uv", VIRTUAL_ENV=venv)
        self.assertEqual(got, "ranwhat")

    def test_not_on_path_and_not_cached_still_says_uvx(self):
        root = self.mkdir("elsewhere")
        self.assertEqual(self.invoke(self.entry(root), root, ["/usr/bin"]),
                         "uvx ranwhat")

    # -- never raises ----------------------------------------------------------

    def test_never_raises(self):
        from unittest import mock
        prefix = self.mkdir("elsewhere")
        self.assertEqual(self.invoke("", prefix, ["/usr/bin"]), "uvx ranwhat")
        self.assertEqual(self.invoke("", prefix, ["/usr/bin"], argv=[]),
                         "uvx ranwhat")
        with mock.patch("os.path.commonpath", side_effect=ValueError("drives")):
            self.assertEqual(self.invoke(self.entry(prefix), prefix, ["/usr/bin"]),
                             "uvx ranwhat")
        with mock.patch("shutil.which", side_effect=OSError("boom")):
            self.assertEqual(self.invoke(self.entry(prefix), prefix, ["/usr/bin"]),
                             "uvx ranwhat")
        got = self.invoke("/src/ranwhat/__main__.py", prefix, ["/usr/bin"],
                          executable=None)
        self.assertIsInstance(got, str)

    # -- what the reader actually sees -----------------------------------------

    def in_uvx(self, fn):
        import io, contextlib
        from unittest import mock
        root = self.mkdir("home", ".cache", "uv", "archive-v0", "WXo1")
        argv0 = self.entry(root)
        buf = io.StringIO()
        # A fixed width, so the tail's layout does not follow the terminal
        # the suite happens to run in.
        env = self.env([os.path.join(root, "bin"), "/usr/bin", "/bin"],
                       UV="/synthetic/uv", RANWHAT_WIDTH="80")
        with mock.patch.dict(os.environ, env, clear=True), \
             mock.patch.object(sys, "argv", [argv0]), \
             mock.patch.object(sys, "prefix", root), \
             contextlib.redirect_stdout(buf):
            fn()
        return buf.getvalue()

    def test_overview_never_prints_a_command_the_reader_cannot_run(self):
        from ranwhat import cli
        text = self.in_uvx(lambda: cli._overview(None))
        commands = [l.strip() for l in text.splitlines()
                    if "ranwhat check" in l or "ranwhat demo" in l or "--help" in l]
        self.assertEqual(len(commands), 3, text)
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith("ranwhat ") and not stripped.startswith("ranwhat  "):
                self.fail("overview told a uvx user to run %r" % stripped)
        for c in commands:
            self.assertIn("uvx ranwhat", c)

    def test_check_tail_suggests_uvx_clean_and_never_apply(self):
        import argparse
        from unittest import mock
        from ranwhat import cli
        args = argparse.Namespace(root=self.t, state_dir=self.t, days=30, json=False)
        finding = {"fp": {"files": {"/synthetic/t.jsonl"}}}
        with mock.patch.object(cli.watch_mod, "scan_sources_counted",
                               return_value=([{"synthetic": 1}], {})), \
             mock.patch.object(cli.clean_mod, "scan",
                               return_value=(finding, 1, 0)), \
             mock.patch.object(cli.watch_mod, "render", return_value=""), \
             mock.patch.object(cli.clean_mod, "render", return_value=""), \
             mock.patch("sys.stderr"):
            text = self.in_uvx(lambda: cli._check(args))
        self.assertIn("uvx ranwhat clean ", text)
        self.assertNotIn("--apply", text)
        for line in text.splitlines():
            if line.strip().startswith("ranwhat "):
                self.fail("check told a uvx user to run %r" % line.strip())
