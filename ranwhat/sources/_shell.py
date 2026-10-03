"""Turning what an agent recorded back into what the shell ran."""

from __future__ import annotations

import re
import shlex
import urllib.parse

from . import _paths

SHELLS = ("sh", "bash", "zsh", "dash", "ksh", "fish", "pwsh", "powershell")
SCRIPT_FLAGS = ("-c", "-lc", "-ic", "-Command")

_EXE = re.compile(r"\.exe\Z", re.I)
_DRIVE = re.compile(r"[A-Za-z]:\Z")
_DRIVE_PATH = re.compile(r"/[A-Za-z]:(?:/|\Z)")


def _basename(program):
    """The program's name without its directory (either separator) and
    without a Windows .exe suffix."""
    name = re.split(r"[\\/]", program)[-1]
    return _EXE.sub("", name)


def argv_to_command(argv):
    """The command text an argv ran, as one string.

    ["bash", "-lc", "cat .env"] ran the script "cat .env", so that script is
    returned: joining the argv with spaces loses the quoting that marks it.
    Any other argv is quoted back into one command with shlex.join. A string
    is returned as it is; anything that is not a list or tuple is ""."""
    if isinstance(argv, str):
        return argv
    if not isinstance(argv, (list, tuple)):
        return ""
    words = [w if isinstance(w, str) else str(w) for w in argv]
    if (len(words) >= 3 and _basename(words[0]) in SHELLS
            and words[1] in SCRIPT_FLAGS):
        return words[2]
    return shlex.join(words)


def file_uri_to_path(uri, platform=None):
    """A file:// URI as a local path, percent-decoded, or None.

    file:///Users/me/proj is /Users/me/proj. On Windows file:///C:/x and
    VS Code's file:///c%3A/x are C:\\x and c:\\x, and file://server/share/x
    is the UNC path \\\\server\\share\\x. A URI with another scheme
    (vscode-remote://, http://) is not a local path: None. So is a file URI
    naming another host anywhere but Windows."""
    if not isinstance(uri, str):
        return None
    try:
        parts = urllib.parse.urlsplit(uri.strip())
    except ValueError:
        return None
    if parts.scheme.lower() != "file":
        return None
    path = urllib.parse.unquote(parts.path)
    host = urllib.parse.unquote(parts.netloc)
    if host.lower() == "localhost":
        host = ""
    if _paths.platform_name(platform) == "win32":
        if _DRIVE.match(host):              # file://C:/x, one slash short
            path, host = "/" + host + path, ""
        if host:
            return "\\\\" + host + path.replace("/", "\\")
        if _DRIVE_PATH.match(path):
            path = path[1:]
            if len(path) == 2:
                path += "/"
        return path.replace("/", "\\") or None
    if host:
        return None
    return path or None
