"""
An opt-in guard for Claude Code: watch's rules, asked before a call runs.

Everything else ranwhat does reads what an agent already wrote, after the
fact, and the agent never knows. This is the one exception, and only once
someone runs `ranwhat hook install`: Claude Code then hands each tool call
to `ranwhat hook run` as a PreToolUse hook, before it runs, and the call
watch would flag waits for the user's yes, or is refused.

It fails open. A guard that stops an agent because the guard itself broke
gets uninstalled the same day, so anything it cannot read or judge is let
through without a word, as it would have been without the hook.

Nothing here touches the network. `run` reads stdin and writes stdout;
`install` and `uninstall` change one settings file, and nothing else.
"""

from __future__ import annotations

import json
import os
import re
import sys
import tempfile

# What a flagged call gets, by mode. "ask" is the default: every call watch
# would flag waits for the user. "deny" refuses the critical ones outright,
# which is what someone running an agent unattended wants, and still asks
# for the rest. A medium hit is never stopped; watch reports it later.
MODES = {
    "ask": {"critical": "ask", "high": "ask"},
    "deny": {"critical": "deny", "high": "ask"},
}
DEFAULT_MODE = "ask"

SCOPES = ("user", "project", "local")
DEFAULT_SCOPE = "user"

# The words that make a settings entry ours, wherever ranwhat was installed:
# install and uninstall find their own entry by them and nothing else.
_OURS = re.compile(r"(?:^|\s)ranwhat\s+hook\s+run(?:\s|$)")

# Seconds Claude Code gives the hook before going on without it. A judgement
# takes a fifth of a second; this is for a machine under load.
TIMEOUT = 10

# Set to 0 to let every call through without uninstalling, for one session.
OFF_ENV = "RANWHAT_HOOK"


class SettingsError(Exception):
    """A settings file the hook will not write to, and why."""


def settings_path(scope, cwd=None, env=None):
    """The Claude Code settings file for scope. user is CLAUDE_CONFIG_DIR's
    settings.json (~/.claude by default), project the shared
    .claude/settings.json in cwd, local the uncommitted
    .claude/settings.local.json beside it."""
    env = os.environ if env is None else env
    if scope == "user":
        base = env.get("CLAUDE_CONFIG_DIR") or os.path.join("~", ".claude")
        return os.path.abspath(os.path.join(os.path.expanduser(base),
                                            "settings.json"))
    name = "settings.local.json" if scope == "local" else "settings.json"
    return os.path.abspath(os.path.join(cwd or os.getcwd(), ".claude", name))


def command_for(mode, executable=None, windows=None):
    """The command Claude Code runs: this interpreter, by its full path, so
    the hook works whatever PATH Claude Code was started with.

    Claude Code runs a hook's command through a POSIX shell, Git Bash on
    Windows, where a bare C:\\Users\\... loses its backslashes. So on
    Windows the path is written with forward slashes, which Windows takes
    too, inside double quotes."""
    executable = executable or sys.executable
    if windows is None:
        windows = os.name == "nt"
    if windows:
        program = '"%s"' % executable.replace("\\", "/").replace('"', "")
    else:
        import shlex
        program = shlex.quote(executable)
    words = [program, "-m", "ranwhat", "hook", "run"]
    if mode != DEFAULT_MODE:
        words += ["--mode", mode]
    return " ".join(words)


def _read(path):
    """The settings in path as a dict, {} when there is no file."""
    try:
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
    except FileNotFoundError:
        return {}
    except OSError as error:
        raise SettingsError("cannot read %s: %s" % (path, error.strerror or error))
    if not text.strip():
        return {}
    try:
        settings = json.loads(text)
    except ValueError as error:
        # Rewritten from what could be parsed, everything after the error
        # would be gone. Claude Code would refuse the file too.
        raise SettingsError("%s is not valid JSON (%s); fix it first, then "
                            "run this again" % (path, error))
    if not isinstance(settings, dict):
        raise SettingsError("%s does not hold a JSON object" % path)
    return settings


def _write(path, settings):
    """Write settings to path through a file beside it, so an interrupted
    write leaves the old file whole. The old file's permissions are kept."""
    folder = os.path.dirname(path)
    os.makedirs(folder, exist_ok=True)
    try:
        mode = os.stat(path).st_mode & 0o7777
    except FileNotFoundError:
        mode = None
    fd, tmp = tempfile.mkstemp(prefix=".settings.", suffix=".tmp", dir=folder)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(json.dumps(settings, indent=2, ensure_ascii=False) + "\n")
        if mode is not None:
            os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _groups(settings, path):
    """settings' PreToolUse list, checked to be the shape Claude Code reads."""
    hooks = settings.get("hooks", {})
    if not isinstance(hooks, dict):
        raise SettingsError("\"hooks\" in %s is not an object" % path)
    groups = hooks.get("PreToolUse", [])
    if not isinstance(groups, list):
        raise SettingsError("\"hooks.PreToolUse\" in %s is not a list" % path)
    return groups


def _is_ours(hook):
    return (isinstance(hook, dict) and isinstance(hook.get("command"), str)
            and bool(_OURS.search(hook["command"])))


def _without_ours(groups):
    """groups with every hook of ours taken out, and any group that held
    only ours with it. (groups, how many were taken out)."""
    kept, removed = [], 0
    for group in groups:
        inner = group.get("hooks") if isinstance(group, dict) else None
        if not isinstance(inner, list):
            kept.append(group)
            continue
        mine = [h for h in inner if _is_ours(h)]
        if not mine:
            kept.append(group)
            continue
        removed += len(mine)
        rest = [h for h in inner if not _is_ours(h)]
        if rest:
            kept.append(dict(group, hooks=rest))
    return kept, removed


def installed(path):
    """The command of each hook of ours in path's settings; [] when there
    is none, or no file."""
    try:
        groups = _groups(_read(path), path)
    except SettingsError:
        return []
    return [h["command"] for g in groups if isinstance(g, dict)
            and isinstance(g.get("hooks"), list)
            for h in g["hooks"] if _is_ours(h)]


def install(path, command):
    """Put our hook in path's settings, replacing any earlier one of ours,
    and leave everything else as it was. True when the file changed."""
    settings = _read(path)
    groups, _ = _without_ours(_groups(settings, path))
    entry = {"matcher": "*",
             "hooks": [{"type": "command", "command": command,
                        "timeout": TIMEOUT}]}
    before = json.dumps(settings, sort_keys=True)
    hooks = dict(settings.get("hooks", {}))
    hooks["PreToolUse"] = groups + [entry]
    settings = dict(settings, hooks=hooks)
    if json.dumps(settings, sort_keys=True) == before:
        return False
    _write(path, settings)
    return True


def uninstall(path):
    """Take every hook of ours out of path's settings, and the keys left
    empty by it. The number taken out; the file is untouched at 0."""
    if not os.path.exists(path):
        return 0
    settings = _read(path)
    groups, removed = _without_ours(_groups(settings, path))
    if not removed:
        return 0
    hooks = dict(settings["hooks"])
    if groups:
        hooks["PreToolUse"] = groups
    else:
        del hooks["PreToolUse"]
    settings = dict(settings, hooks=hooks)
    if not hooks:
        del settings["hooks"]
    _write(path, settings)
    return removed


def decide(tool_name, tool_input, mode=DEFAULT_MODE):
    """(decision, reason) for one call: decision is "ask" or "deny", or None
    to let it run as Claude Code would have without the hook."""
    from . import watch
    hits, _payload = watch.evaluate(tool_name, tool_input)
    order = ["medium", "high", "critical"]
    policy = MODES.get(mode, MODES[DEFAULT_MODE])
    flagged = [h for h in hits if policy.get(h["severity"])]
    if not flagged:
        return None, ""
    worst = max(flagged, key=lambda h: order.index(h["severity"]))
    decision = policy[worst["severity"]]
    # Each rule once, worst first. No evidence: it may quote a secret, and
    # the reason is shown to the model as well as to the user.
    lines = ["ranwhat watch would flag this call: %s (%s, %s). %s"
             % (h["title"], h["rule"], h["severity"], h["why"])
             for h in sorted(flagged, key=lambda h: -order.index(h["severity"]))]
    if decision == "deny":
        lines.append("Refused by the ranwhat hook. Ask the user to run it "
                     "themselves if it is meant.")
    return decision, "\n".join(lines)


def run(stdin=None, stdout=None, mode=DEFAULT_MODE, env=None):
    """The hook itself: one PreToolUse event on stdin, Claude Code's JSON
    answer on stdout when the call is flagged, nothing otherwise. Always
    returns 0, so no failure of ours ever stops the agent."""
    stdin = sys.stdin if stdin is None else stdin
    stdout = sys.stdout if stdout is None else stdout
    env = os.environ if env is None else env
    try:
        if env.get(OFF_ENV, "").strip().lower() in ("0", "off", "false", "no"):
            return 0
        event = json.loads(stdin.read())
        if not isinstance(event, dict):
            return 0
        if event.get("hook_event_name", "PreToolUse") != "PreToolUse":
            return 0
        tool_name = event.get("tool_name")
        if not isinstance(tool_name, str):
            return 0
        decision, reason = decide(tool_name, event.get("tool_input") or {}, mode)
        if decision is None:
            return 0
        stdout.write(json.dumps({"hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
            "permissionDecisionReason": reason}}) + "\n")
        stdout.flush()
    except Exception:
        pass                      # fail open: see the module docstring
    return 0


def main(argv):
    """`ranwhat hook run [--mode MODE]`, parsed by hand: argparse and the
    rest of the command line cost a tenth of a second on every tool call.
    An argument it does not know is ignored rather than refused, since a
    refusal here would be a failure of ours in the agent's path."""
    mode = DEFAULT_MODE
    for i, arg in enumerate(argv):
        if arg == "--mode" and i + 1 < len(argv):
            mode = argv[i + 1]
        elif arg.startswith("--mode="):
            mode = arg.split("=", 1)[1]
    return run(mode=mode if mode in MODES else DEFAULT_MODE)
