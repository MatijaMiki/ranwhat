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
# Not under /tmp: deleting /tmp would then be deleting an ancestor of home,
# which the deletion-context tests (rightly) rate differently.
USER_HOME = tempfile.mkdtemp(
    prefix="ranwhat-userhome-",
    dir="/var/tmp" if os.path.isdir("/var/tmp") else None)
os.environ["HOME"] = USER_HOME
os.environ["USERPROFILE"] = USER_HOME
atexit.register(shutil.rmtree, USER_HOME, True)
