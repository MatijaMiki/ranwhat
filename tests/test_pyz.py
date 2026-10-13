"""scripts/build_pyz.py: one file that runs ranwhat, the same bytes every build."""
import importlib.util
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("build_pyz", ROOT / "scripts" / "build_pyz.py")
build_pyz = importlib.util.module_from_spec(spec)
spec.loader.exec_module(build_pyz)


class TheSingleFile(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="ranwhat-pyz-")
        cls.a = os.path.join(cls.tmp, "a", "ranwhat.pyz")
        cls.b = os.path.join(cls.tmp, "b", "ranwhat.pyz")
        cls.sha_a = build_pyz.build(cls.a)
        cls.sha_b = build_pyz.build(cls.b)

    def run_pyz(self, *args):
        env = dict(os.environ, RANWHAT_HOME=self.tmp, PYTHONDONTWRITEBYTECODE="1")
        return subprocess.run([sys.executable, self.a] + list(args), env=env,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              universal_newlines=True, cwd=self.tmp)

    def test_the_same_source_gives_the_same_bytes(self):
        self.assertEqual(self.sha_a, self.sha_b)

    def test_it_starts_with_a_shebang(self):
        with open(self.a, "rb") as f:
            self.assertEqual(f.readline(), b"#!/usr/bin/env python3\n")

    def test_it_runs_the_cli_and_finds_its_bundled_demo(self):
        r = self.run_pyz("demo")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(r.stdout.strip())

    def test_it_has_no_bytecode_or_stray_files(self):
        import zipfile
        names = zipfile.ZipFile(self.a).namelist()
        self.assertIn("__main__.py", names)
        self.assertIn("ranwhat/cli.py", names)
        self.assertFalse([n for n in names if "__pycache__" in n or n.endswith(".pyc")])


if __name__ == "__main__":
    unittest.main()
