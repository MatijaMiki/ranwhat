"""Where agents keep things, worked out without touching the disk.

Every function here except home() is pure: it takes an environment mapping,
a home directory and a platform name, and returns strings. Joins use
ntpath for "win32" and posixpath otherwise, so a test on a Mac can assert a
Windows path exactly, backslashes and all.

home() is the one function tests patch to move every adapter at once.
"""

from __future__ import annotations

import ntpath
import os
import posixpath
import sys


def home():
    """The user's home directory: USERPROFILE on Windows, HOME elsewhere."""
    return os.path.expanduser("~")


def platform_name(platform=None):
    """"darwin", "linux" or "win32" for `platform` (default sys.platform).
    Every other POSIX system (the BSDs, cygwin) lays out its folders the way
    Linux does, so it is treated as "linux"."""
    name = sys.platform if platform is None else platform
    if name.startswith("win"):
        return "win32"
    if name == "darwin":
        return "darwin"
    return "linux"


def pathmod(platform=None):
    """ntpath for Windows, posixpath for everything else."""
    return ntpath if platform_name(platform) == "win32" else posixpath


def join(platform, *parts):
    return pathmod(platform).join(*parts)


def _set(env, name):
    """The variable's value when it is set and not empty, else None."""
    value = env.get(name)
    return value if isinstance(value, str) and value else None


def xdg_data_home(env, home, platform=None):
    """$XDG_DATA_HOME when set and non-empty, else home/.local/share."""
    return _set(env, "XDG_DATA_HOME") or join(platform, home, ".local", "share")


def xdg_state_home(env, home, platform=None):
    """$XDG_STATE_HOME when set and non-empty, else home/.local/state."""
    return _set(env, "XDG_STATE_HOME") or join(platform, home, ".local", "state")


def xdg_config_home(env, home, platform=None):
    """$XDG_CONFIG_HOME when set and non-empty, else home/.config."""
    return _set(env, "XDG_CONFIG_HOME") or join(platform, home, ".config")


def xdg_cache_home(env, home, platform=None):
    """$XDG_CACHE_HOME when set and non-empty, else home/.cache."""
    return _set(env, "XDG_CACHE_HOME") or join(platform, home, ".cache")


def appdata(env, home):
    """%APPDATA% when set, else home\\AppData\\Roaming. Windows only."""
    return _set(env, "APPDATA") or ntpath.join(home, "AppData", "Roaming")


def localappdata(env, home):
    """%LOCALAPPDATA% when set, else home\\AppData\\Local. Windows only."""
    return _set(env, "LOCALAPPDATA") or ntpath.join(home, "AppData", "Local")


def application_support(home):
    """~/Library/Application Support. macOS only."""
    return posixpath.join(home, "Library", "Application Support")


# The VS Code user-data folder name is verified for stable VS Code only
# (VS Code userDataPath.ts). These forks are probed under the same parent;
# their folder names are unverified for the extensions that use them, and a
# missing folder costs one stat.
EDITOR_VERIFIED = "Code"
EDITORS_PROBED = ("Code - Insiders", "VSCodium", "Cursor", "Windsurf", "Devin")


def editor_parent(env, home, platform):
    """The folder VS Code-family editors keep their user data under:
    %APPDATA% (Windows), ~/Library/Application Support (macOS),
    ${XDG_CONFIG_HOME:-~/.config} (Linux)."""
    plat = platform_name(platform)
    if plat == "win32":
        return appdata(env, home)
    if plat == "darwin":
        return application_support(home)
    return xdg_config_home(env, home, plat)


def editor_user_dirs(env, home, platform):
    """[(path, how)] for every VS Code-family `User` directory to probe.

    VSCODE_PORTABLE and VSCODE_APPDATA come first, in VS Code's own order.
    The platform default follows them rather than being replaced: the editor
    is usually started from a dock or menu, not from the shell ranwhat runs
    in, so a variable set here may not be one the editor saw."""
    plat = platform_name(platform)
    j = pathmod(plat).join
    out = []
    portable = _set(env, "VSCODE_PORTABLE")
    if portable:
        out.append((j(portable, "user-data", "User"), "env VSCODE_PORTABLE"))
    moved = _set(env, "VSCODE_APPDATA")
    if moved:
        out.append((j(moved, EDITOR_VERIFIED, "User"), "env VSCODE_APPDATA"))
    parent = editor_parent(env, home, plat)
    out.append((j(parent, EDITOR_VERIFIED, "User"), "default"))
    for name in EDITORS_PROBED:
        out.append((j(parent, name, "User"), "probed"))
    return out
