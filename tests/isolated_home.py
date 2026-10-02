"""ranwhat's own state, for the whole test run, in a directory of its own.

check and watch keep an index of the values clean finds under RANWHAT_HOME,
~/.ranwhat when it is unset. No test may write there, so each module that
runs them imports this first: RANWHAT_HOME is then a temporary directory
for every test in the process and every command it starts, and is removed
at exit. A test that sets RANWHAT_HOME itself still gets its own.
"""
import atexit
import os
import shutil
import tempfile

HOME = tempfile.mkdtemp(prefix="ranwhat-home-")
os.environ["RANWHAT_HOME"] = HOME
atexit.register(shutil.rmtree, HOME, True)
