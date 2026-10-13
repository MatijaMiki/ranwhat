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

# The user's own home too: a test that reads "nowhere" must not find the
# Cursor or OpenClaw data of the machine it runs on (CI has none, a laptop does).
USER_HOME = tempfile.mkdtemp(prefix="ranwhat-userhome-")
os.environ["HOME"] = USER_HOME
os.environ["USERPROFILE"] = USER_HOME
atexit.register(shutil.rmtree, USER_HOME, True)
