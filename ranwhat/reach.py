"""ranwhat reach: what a coding agent on this machine can reach.

Two halves, both read from disk and nothing else:

- The MCP servers agents keep in their configuration, what each one
  launches or connects to, and the shapes worth a second look: a secret
  written inline (in env, args, headers or the URL), a package fetched
  from a registry at whatever version is newest (npx, uvx and the like
  with no exact version), a remote URL, and a project's .mcp.json whose
  servers Claude Code starts without asking.
- Credential files an agent could read from the directories it works in,
  and in the home folder, that no Claude Code Read deny rule covers. Only
  the path is ever printed, never a value.

Then the Read deny rules that would cover those files, for the user to
paste into Claude Code's settings. Nothing is written: reach only reads.

Every string printed from an MCP configuration goes through the rules
clean uses, so a secret found there is shown the way clean shows one
(its hint in angle brackets), never whole.
"""
from __future__ import annotations

import importlib
import json
import os
import posixpath
import re
import stat

from . import clean as clean_mod
from .sources import _jsonc, _paths

# A configuration file is kilobytes; ~/.claude.json grows to megabytes with
# its per-project state. Past this it is not one.
MAX_CONFIG = 64 << 20
# Read from a candidate credential file to decide whether it holds one.
MAX_CREDENTIAL = 1 << 20

# How deep under a project directory credential files are looked for, and
# how many directories at most in one project: a monorepo keeps the .env
# with the live keys in apps/web/, not at the top, but a walk of every
# node_modules would take minutes.
WALK_DEPTH = 6
WALK_DIRS = 2000
# Dependencies and version control: what is under them is someone else's.
SKIP_DIRS = frozenset((
    ".git", ".hg", ".svn", "node_modules", ".venv", "venv", "__pycache__",
    ".tox", ".nox", ".mypy_cache", ".pytest_cache", ".ruff_cache", ".turbo",
    ".cache", "site-packages", ".gradle", ".idea", ".terraform",
))
# Build output: a deploy step copies .env.production into dist/, so the
# files directly inside are looked at, but not the tree below them.
SHALLOW_DIRS = frozenset((
    "dist", "build", "target", "out", ".next", ".nuxt", "vendor", "coverage",
))

GUIDE = "https://ranwhat.com/guides/claude-code-env-secrets"


# ----------------------------------------------------------------------
# Reading configuration files

def _load_json(path):
    """The decoded JSON (or JSON with comments) at path, else None."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read(MAX_CONFIG + 1)
    except (OSError, ValueError):
        return None
    if len(text) > MAX_CONFIG:
        return None
    try:
        return json.loads(text[1:] if text.startswith("\ufeff") else text)
    except (ValueError, RecursionError):
        return _jsonc.loads(text)


def _tomllib():
    """The standard library's TOML reader (Python 3.11+), or None."""
    try:
        return importlib.import_module("tomllib")
    except ImportError:
        return None


def _load_toml(path):
    toml = _tomllib()
    if toml is None:
        return None
    try:
        with open(path, "rb") as fh:
            data = fh.read(MAX_CONFIG + 1)
        if len(data) > MAX_CONFIG:
            return None
        return toml.loads(data.decode("utf-8", "replace"))
    except (OSError, ValueError, RecursionError):
        return None


def _isfile(path):
    try:
        return stat.S_ISREG(os.stat(path).st_mode)
    except (OSError, ValueError):
        return False


def _isdir(path):
    try:
        return stat.S_ISDIR(os.stat(path).st_mode)
    except (OSError, ValueError):
        return False


def _env(env, name):
    value = env.get(name)
    return value if isinstance(value, str) and value else None


def claude_dir(env, home):
    """Where Claude Code keeps settings.json: $CLAUDE_CONFIG_DIR, else
    ~/.claude."""
    return _env(env, "CLAUDE_CONFIG_DIR") or os.path.join(home, ".claude")


def claude_json(env, home):
    """~/.claude.json, or $CLAUDE_CONFIG_DIR/.claude.json when that is set."""
    moved = _env(env, "CLAUDE_CONFIG_DIR")
    return os.path.join(moved or home, ".claude.json")


def managed_dirs(platform=None):
    """Where Claude Code reads managed (administrator) settings and
    managed-mcp.json on this platform."""
    name = _paths.platform_name(platform)
    if name == "darwin":
        return ["/Library/Application Support/ClaudeCode"]
    if name == "win32":
        return ["C:\\Program Files\\ClaudeCode"]
    return ["/etc/claude-code"]


def _desktop_config(env, home, platform=None):
    name = _paths.platform_name(platform)
    if name == "darwin":
        base = os.path.join(home, "Library", "Application Support", "Claude")
    elif name == "win32":
        base = os.path.join(_env(env, "APPDATA")
                            or os.path.join(home, "AppData", "Roaming"), "Claude")
    else:
        base = os.path.join(_env(env, "XDG_CONFIG_HOME")
                            or os.path.join(home, ".config"), "Claude")
    return os.path.join(base, "claude_desktop_config.json")


def user_configs(env, home, platform=None):
    """(agent, scope, path, format, key) for each user-level MCP
    configuration an agent documents. key is where the servers sit:
    "mcpServers" in most, "servers" in VS Code's, "mcp_servers" in Codex's
    TOML."""
    gemini = _env(env, "GEMINI_CLI_HOME") or home
    qwen = _env(env, "QWEN_HOME") or os.path.join(home, ".qwen")
    copilot = _env(env, "COPILOT_HOME") or os.path.join(home, ".copilot")
    codex = _env(env, "CODEX_HOME") or os.path.join(home, ".codex")
    out = [("Claude Code", "user", claude_json(env, home), "json", "mcpServers")]
    out += [("Claude Code", "managed", os.path.join(d, "managed-mcp.json"),
             "json", "mcpServers") for d in managed_dirs(platform)]
    out += [
        ("Claude Desktop", "user", _desktop_config(env, home, platform),
         "json", "mcpServers"),
        ("Cursor", "user", os.path.join(home, ".cursor", "mcp.json"),
         "json", "mcpServers"),
        ("Gemini CLI", "user", os.path.join(gemini, ".gemini", "settings.json"),
         "json", "mcpServers"),
        ("Qwen Code", "user", os.path.join(qwen, "settings.json"),
         "json", "mcpServers"),
        ("GitHub Copilot CLI", "user", os.path.join(copilot, "mcp-config.json"),
         "json", "mcpServers"),
        ("Windsurf", "user", os.path.join(home, ".codeium", "windsurf",
                                          "mcp_config.json"),
         "json", "mcpServers"),
        ("Codex", "user", os.path.join(codex, "config.toml"),
         "toml", "mcp_servers"),
    ]
    return out


# Relative to a project directory.
PROJECT_CONFIGS = (
    ("Claude Code", "project", ".mcp.json", "mcpServers"),
    ("Cursor", "project", os.path.join(".cursor", "mcp.json"), "mcpServers"),
    ("VS Code", "project", os.path.join(".vscode", "mcp.json"), "servers"),
    ("Gemini CLI", "project", os.path.join(".gemini", "settings.json"),
     "mcpServers"),
    ("Qwen Code", "project", os.path.join(".qwen", "settings.json"),
     "mcpServers"),
)


# ----------------------------------------------------------------------
# Secrets in an MCP server's definition, found by clean's rules

_REFERENCE = re.compile(r"^(?:\$\{?[A-Za-z_][A-Za-z0-9_]*\}?|\$\{(?:env|input):[^}]*\}|\{env:[^}]*\})$")
# ${VAR:-default}: the default is a literal, and may be the secret itself.
_DEFAULTED = re.compile(r"^\$\{[A-Za-z_][A-Za-z0-9_]*:?-([^}]*)\}$")
_HEADER = re.compile(r"^([A-Za-z][A-Za-z0-9_-]*)\s*:\s*(\S.*)$", re.S)
_AUTH_SCHEME = re.compile(r"^\s*(?:Bearer|Basic|Token|token|bearer|basic)\s+(\S+)\s*$")
_FLAG = re.compile(r"^--?([A-Za-z][A-Za-z0-9_-]*)(?:=(.*))?$", re.S)


def _as_key(name):
    """A header or flag name as an environment-style key (X-API-Key ->
    X_API_KEY), so clean reads it as it reads KEY=value."""
    return re.sub(r"[^A-Za-z0-9]+", "_", name).strip("_")


def _secrets_in(key, value):
    """[(value, label)] clean finds in value, read as the value of key."""
    if not isinstance(value, str) or not value or _REFERENCE.match(value):
        return []
    defaulted = _DEFAULTED.match(value)
    if defaulted:
        value = defaulted.group(1)
        if not value:
            return []
    found = []
    if key:
        found = clean_mod.find_secrets("%s=%s" % (_as_key(key), value))
    found += clean_mod.find_secrets(value)
    seen, out = set(), []
    for v, label in found:
        if v not in seen:
            seen.add(v)
            out.append((v, label))
    return out


def _header_secrets(name, value):
    if not isinstance(value, str):
        return []
    m = _AUTH_SCHEME.match(value)
    if m and not _REFERENCE.match(m.group(1)):
        # "Authorization: Bearer X": clean reads no header, so X is read as
        # a token's value.
        found = _secrets_in("AUTHORIZATION_TOKEN", m.group(1))
        if found:
            return [(v, "%s credential" % value.split()[0].lower())
                    for v, _label in found]
    return _secrets_in(name, value)


def _value_secrets(key, value):
    """_secrets_in, but a value shaped as a header ("Authorization: Bearer
    X", "X-API-Key: X", as mcp-remote's --header takes one) is read as
    that header."""
    header = _HEADER.match(value)
    if header and "://" not in value:
        found = _header_secrets(header.group(1), header.group(2))
        if found:
            return found
    return _secrets_in(key, value)


_QUERY = re.compile(r"[?&#]([A-Za-z0-9_.-]+)=([^&#\s]+)")
_SEGMENT = re.compile(r"(?<=/)([A-Za-z0-9_-]{20,})(?=/|\?|#|$)")


def _url_secrets(url):
    """What clean misses in a hosted MCP server's URL, judged by clean's
    rules all the same: ?key=X, which clean leaves alone as an index's
    name, and a token as a path segment (https://host/mcp/TOKEN/sse)."""
    out = []
    path = url.split("://", 1)[-1]
    path = path[path.find("/"):] if "/" in path else ""
    for name, value in _QUERY.findall(url):
        if name.lower() in ("key", "k", "auth", "access", "sig", "signature"):
            out += [(v, "key in URL") for v, _l in _secrets_in("API_KEY", value)]
    for segment in _SEGMENT.findall(path.split("?", 1)[0].split("#", 1)[0]):
        # One unbroken run of 16 or more, letters and digits mixed: not a
        # slug (server-github2) and not a UUID, whose parts are 12 at most.
        if any(len(part) >= 16 and re.search(r"[0-9]", part)
               and re.search(r"[A-Za-z]", part)
               for part in re.split(r"[-_]", segment)):
            out += [(v, "token in URL path")
                    for v, _l in _secrets_in("ACCESS_TOKEN", segment)]
    return out


def _arg_secrets(args):
    """[(where, value, label)] in a server's args: --api-key=X, --api-key X,
    and anything clean finds in an argument on its own."""
    out = []
    for i, arg in enumerate(args):
        if not isinstance(arg, str):
            continue
        m = _FLAG.match(arg)
        if m and m.group(2) is not None:
            found = _value_secrets(m.group(1), m.group(2))
        elif m and i + 1 < len(args) and isinstance(args[i + 1], str) \
                and not args[i + 1].startswith("-"):
            found = _value_secrets(m.group(1), args[i + 1])
        else:
            found = _value_secrets(None, arg)
        out += [("arg %s" % arg.split("=", 1)[0] if m else "args", v, label)
                for v, label in found]
    return out


# ----------------------------------------------------------------------
# Packages fetched at whatever version is newest

_EXACT_VERSION = re.compile(r"^v?\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.+-]+)?$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")

# (words that start the runner, flags that take a value, flags naming the
# package, ecosystem)
_NPM_VALUE_FLAGS = ("-p", "--package", "--registry", "--cache", "--userconfig",
                    "-c", "--call", "--prefix", "-w", "--workspace")
_UV_VALUE_FLAGS = ("--from", "--with", "--with-editable", "--with-requirements",
                   "-p", "--python", "--index", "--index-url", "-i",
                   "--extra-index-url", "--default-index", "--find-links", "-f",
                   "--constraints", "-c", "--overrides", "--directory",
                   "--project", "--config-file", "--cache-dir")
_PIPX_VALUE_FLAGS = ("--spec", "--python", "--index-url", "-i", "--pip-args",
                     "--backend")
_RUNNERS = (
    (("npx",), _NPM_VALUE_FLAGS, ("-p", "--package"), "npm"),
    (("pnpx",), _NPM_VALUE_FLAGS, ("-p", "--package"), "npm"),
    (("bunx",), _NPM_VALUE_FLAGS, ("-p", "--package"), "npm"),
    (("npm", "exec"), _NPM_VALUE_FLAGS, ("-p", "--package"), "npm"),
    (("pnpm", "dlx"), _NPM_VALUE_FLAGS, ("-p", "--package"), "npm"),
    (("pnpm", "exec"), _NPM_VALUE_FLAGS, ("-p", "--package"), "npm"),
    (("yarn", "dlx"), _NPM_VALUE_FLAGS, ("-p", "--package"), "npm"),
    (("bun", "x"), _NPM_VALUE_FLAGS, ("-p", "--package"), "npm"),
    (("uvx",), _UV_VALUE_FLAGS, ("--from",), "pypi"),
    (("uv", "tool", "run"), _UV_VALUE_FLAGS, ("--from",), "pypi"),
    (("uv", "tool", "x"), _UV_VALUE_FLAGS, ("--from",), "pypi"),
    (("pipx", "run"), _PIPX_VALUE_FLAGS, ("--spec",), "pypi"),
    # What the Python MCP SDK's `mcp install` writes: uv run --with mcp ...
    (("uv", "run"), _UV_VALUE_FLAGS, ("--with",), "pypi"),
)


def _program(word):
    name = re.split(r"[\\/]", word)[-1].lower()
    for ext in (".exe", ".cmd", ".bat", ".ps1"):
        if name.endswith(ext):
            return name[:-len(ext)]
    return name


def _argv(server):
    command = server.get("command")
    args = server.get("args")
    if isinstance(command, list):          # a few clients take argv whole
        words = [w for w in command if isinstance(w, str)]
    elif isinstance(command, str) and command:
        # A command written with its arguments in one string.
        # A path with a space in it (C:\\Program Files\\...) is one word.
        words = [command] if os.path.isabs(command) or re.match(
            r"^[A-Za-z]:[\\/]", command) else command.split()
    else:
        words = []
    if isinstance(args, list):
        words += [a for a in args if isinstance(a, str)]
    # cmd /c npx ..., the shape Windows set-up guides give.
    if len(words) > 2 and _program(words[0]) == "cmd" and words[1].lower() in ("/c", "/k"):
        words = words[2:]
    return words


def _npm_pinned(spec):
    if spec.startswith((".", "/", "~", "file:")) or re.match(r"^[A-Za-z]:[\\/]", spec):
        return True                         # a local path: nothing is fetched
    if spec.startswith(("git+", "git:", "github:", "gitlab:", "bitbucket:", "http:", "https:")) \
            or re.match(r"^[\w.-]+/[\w.-]+(?:#.*)?$", spec):
        ref = spec.rsplit("#", 1)[1] if "#" in spec else ""
        return bool(_COMMIT.match(ref))
    name_end = spec.find("@", 1)            # @scope/name@version
    if name_end == -1:
        return False
    return bool(_EXACT_VERSION.match(spec[name_end + 1:]))


def _pypi_pinned(spec):
    if spec.startswith((".", "/", "~", "file:")) or re.match(r"^[A-Za-z]:[\\/]", spec):
        return True
    if spec.startswith("git+") or "://" in spec:
        ref = spec.rsplit("@", 1)[1] if "@" in spec.split("://", 1)[-1] else ""
        return bool(_COMMIT.match(ref))
    m = re.match(r"^[A-Za-z0-9._-]+(?:\[[^\]]*\])?\s*(===?|@)\s*(\S+)$", spec)
    if not m or "*" in m.group(2) or "," in m.group(2):
        return False
    # == (PEP 440) is exact whatever the version looks like: 0.6, 1.0rc1.
    return m.group(1) != "@" or bool(re.match(r"^v?\d+(?:\.\d+)*\S*$", m.group(2)))


def unpinned(server):
    """(runner, package) when the server starts by fetching a package from a
    registry without an exact version, else None: each start then runs
    whatever version is newest, and a release pushed by whoever holds the
    package runs with the agent's access."""
    words = _argv(server)
    if not words:
        return None
    lowered = [_program(words[0])] + [w.lower() for w in words[1:]]
    for start, value_flags, package_flags, ecosystem in _RUNNERS:
        if tuple(lowered[:len(start)]) != start:
            continue
        rest = words[len(start):]
        spec, i = None, 0
        while i < len(rest):
            word = rest[i]
            flag, _, inline = word.partition("=")
            if flag in package_flags:
                spec = inline if inline else (rest[i + 1] if i + 1 < len(rest) else None)
                break
            if word == "--":
                spec = rest[i + 1] if i + 1 < len(rest) else None
                break
            if word.startswith("-"):
                i += 2 if (flag in value_flags and not inline) else 1
                continue
            if start == ("uv", "run"):
                break         # uv run's word is a script or a command, not a package
            spec = word
            break
        if not spec:
            return None
        pinned = _npm_pinned(spec) if ecosystem == "npm" else _pypi_pinned(spec)
        return None if pinned else (" ".join(start), spec)
    return None


# ----------------------------------------------------------------------
# Remote servers

_LOCAL_HOSTS = ("localhost", "127.0.0.1", "::1", "[::1]", "0.0.0.0")


def _host(url):
    m = re.match(r"^([A-Za-z][A-Za-z0-9+.-]*)://(?:[^@/?#]*@)?(\[[^\]]*\]|[^:/?#]*)", url)
    return (m.group(1).lower(), m.group(2).lower()) if m else (None, None)


def _url(server):
    for key in ("url", "httpUrl", "serverUrl"):
        value = server.get(key)
        if isinstance(value, str) and value:
            return value
    return None


# ----------------------------------------------------------------------
# One server

def _servers_in(doc, key):
    servers = doc.get(key) if isinstance(doc, dict) else None
    if not isinstance(servers, dict):
        return []
    return [(name, s) for name, s in servers.items()
            if isinstance(name, str) and isinstance(s, dict)]


def describe(name, server, agent, scope, path, project=None):
    """A server as reach reports it: what it launches or connects to, and
    its risks. Every value clean would call a secret is in `values`, for
    the caller to mask in whatever it prints."""
    risks, values = [], []
    url = _url(server)
    words = _argv(server)

    env = server.get("env")
    if isinstance(env, dict):
        for key, value in env.items():
            if not isinstance(key, str):
                continue
            for v, label in _secrets_in(key, value):
                values.append(v)
                risks.append({"kind": "inline-secret", "where": "env %s" % key,
                              "secret": v, "label": label})
    for where, v, label in _arg_secrets(words):
        values.append(v)
        risks.append({"kind": "inline-secret", "where": where, "secret": v,
                      "label": label})
    for field in ("headers", "http_headers", "requestInit"):
        headers = server.get(field)
        if field == "requestInit" and isinstance(headers, dict):
            headers = headers.get("headers")
        if isinstance(headers, dict):
            for key, value in headers.items():
                if not isinstance(key, str):
                    continue
                for v, label in _header_secrets(key, value):
                    values.append(v)
                    risks.append({"kind": "inline-secret",
                                  "where": "header %s" % key, "secret": v,
                                  "label": label})
    token = server.get("bearer_token")        # Codex, before bearer_token_env_var
    for v, label in _secrets_in("BEARER_TOKEN", token):
        values.append(v)
        risks.append({"kind": "inline-secret", "where": "bearer_token",
                      "secret": v, "label": label})
    if url:
        for v, label in _secrets_in(None, url) + _url_secrets(url):
            values.append(v)
            risks.append({"kind": "inline-secret", "where": "url", "secret": v,
                          "label": label})
        scheme, host = _host(url)
        if host in _LOCAL_HOSTS:
            risks.append({"kind": "local-url", "where": "url",
                          "detail": "connects to %s on this machine" % host})
        else:
            risks.append({"kind": "remote", "where": "url",
                          "detail": "connects to %s" % (host or url)})
            if scheme == "http":
                risks.append({"kind": "unencrypted", "where": "url",
                              "detail": "plain http to %s" % host})
    fetched = unpinned(server)
    if fetched:
        risks.append({"kind": "unpinned", "where": "command",
                      "detail": "%s fetches %s at its newest version on every "
                                "start" % fetched,
                      "runner": fetched[0], "package": fetched[1]})
    # One entry per secret: --token X is read as the flag's value and
    # again as an argument on its own.
    kept, seen = [], set()
    for r in risks:
        if "secret" in r:
            if r["secret"] in seen:
                continue
            seen.add(r["secret"])
        kept.append(r)
    risks = kept
    transport = server.get("type") or server.get("transport")
    if not isinstance(transport, str):
        transport = "http" if url else "stdio"
    return {
        "name": name, "agent": agent, "scope": scope, "file": path,
        "project": project, "transport": transport,
        "command": words, "url": url,
        "env": sorted(k for k in env if isinstance(k, str)) if isinstance(env, dict) else [],
        "disabled": bool(server.get("disabled")) or server.get("enabled") is False,
        "risks": risks, "values": values,
    }


# ----------------------------------------------------------------------
# Claude Code's Read deny rules

class Rule(object):
    """One Read(...) deny rule, resolved to where it is anchored.

    The prefix decides the anchor, as Claude Code's permissions reference
    lays out: // the filesystem root, ~/ the home folder, / the directory
    the settings file applies to (the project for project settings,
    ~/.claude for user settings), ./ or none the directory Claude Code was
    started in. Patterns are gitignore's: one with no slash but a trailing
    one matches at any depth, * stays inside a directory, ** crosses them,
    and a pattern that matches a directory covers what is in it."""

    def __init__(self, spec, settings_dir):
        self.spec = spec
        self.negated = spec.startswith("!")
        body = spec[1:] if self.negated else spec
        self.relative = not (body.startswith("//") or body.startswith("~/")
                             or body == "~")
        self.settings_dir = settings_dir
        self.body = body

    def pattern(self, cwd, home):
        """An absolute, /-separated glob, or None when this rule cannot be
        placed (a relative rule with no current directory)."""
        body = self.body
        if body.startswith("//"):
            return "/" + body[2:].lstrip("/")
        if body == "~" or body.startswith("~/"):
            return _slashed(home) + "/" + body[2:]
        if body.startswith("/"):
            if self.settings_dir is None:
                return None
            return _slashed(self.settings_dir) + body
        if cwd is None:
            return None
        if body.startswith("./"):
            return _slashed(cwd) + "/" + body[2:]
        if "/" not in body.rstrip("/"):
            return _slashed(cwd) + "/**/" + body
        return _slashed(cwd) + "/" + body


def _slashed(path):
    """path with / between its parts, and a Windows drive as /c, the way
    Claude Code writes an absolute path in a rule (//c/Users/...)."""
    if os.sep == "\\":
        path = path.replace("\\", "/")
    m = re.match(r"^([A-Za-z]):(/.*)?$", path)
    if m:
        path = "/" + m.group(1).lower() + (m.group(2) or "")
    return path.rstrip("/") or "/"


_GLOB_CACHE = {}


def _glob_regex(pattern):
    cached = _GLOB_CACHE.get(pattern)
    if cached is not None:
        return cached
    out, i, n = [], 0, len(pattern)
    while i < n:
        c = pattern[i]
        if pattern.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif pattern.startswith("**", i):
            out.append(".*")
            i += 2
        elif c == "*":
            out.append("[^/]*")
            i += 1
        elif c == "?":
            out.append("[^/]")
            i += 1
        elif c == "[":
            end = pattern.find("]", i + 1)
            if end == -1:
                out.append(re.escape(c))
                i += 1
            else:
                inner = pattern[i + 1:end]
                if inner.startswith("!"):
                    inner = "^" + inner[1:]
                cls = "[" + inner.replace("\\", "\\\\") + "]"
                try:
                    re.compile(cls)
                except re.error:
                    # [z-a], []: not a class Claude Code could match either;
                    # read as the characters written.
                    cls = re.escape(pattern[i:end + 1])
                out.append(cls)
                i = end + 1
        elif c == "\\" and i + 1 < n:
            out.append(re.escape(pattern[i + 1]))
            i += 2
        else:
            out.append(re.escape(c))
            i += 1
    regex = re.compile("^" + "".join(out).rstrip("/") + "(?:/.*)?$")
    _GLOB_CACHE[pattern] = regex
    return regex


def rule_matches(rule, path, cwd, home):
    pattern = rule.pattern(cwd, home)
    if pattern is None:
        return False
    return bool(_glob_regex(posixpath.normpath(pattern)).match(
        _slashed(os.path.abspath(path))))


def read_rules(settings):
    """[(spec, settings_dir)] for every Read deny rule in settings, a list
    of (path, settings_dir) in the order Claude Code merges them. A bare
    Read, or Read(**) at the root, denies every read."""
    rules, read = [], []
    for path, settings_dir in settings:
        doc = _load_json(path) if _isfile(path) else None
        if not isinstance(doc, dict):
            continue
        read.append(path)
        perms = doc.get("permissions")
        deny = perms.get("deny") if isinstance(perms, dict) else None
        if not isinstance(deny, list):
            continue
        for entry in deny:
            if not isinstance(entry, str):
                continue
            entry = entry.strip()
            if entry == "Read":
                rules.append(Rule("//**", settings_dir))
                continue
            m = re.match(r"^Read\((.*)\)$", entry, re.S)
            if m and m.group(1).strip():
                rules.append(Rule(m.group(1), settings_dir))
    return rules, read


def denied(rules, path, cwd, home):
    """Whether rules deny a read of path for Claude Code started in cwd.
    A ! rule carves a file back out of the relative rules before it, and
    never out of a // or ~/ rule."""
    relative = False
    for rule in rules:
        if rule.negated:
            if relative and rule.relative and rule_matches(rule, path, cwd, home):
                relative = False
            continue
        if rule_matches(rule, path, cwd, home):
            if not rule.relative:
                return True
            relative = True
    return relative


# ----------------------------------------------------------------------
# Credential files

_ENV_TEMPLATES = clean_mod._NOT_SECRET
_ASSIGN = re.compile(r"""^[ \t]*(?:export[ \t]+)?([A-Za-z_][A-Za-z0-9_.-]*)[ \t]*[=:][ \t]*(.*?)[ \t]*$""",
                     re.M)
_PRIVATE_KEY = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
_NETRC_PASSWORD = re.compile(r"(?:^|\s)password\s+\S", re.M)
_DOCKER_AUTH = re.compile(r'"(?:auth|identitytoken|registrytoken)"\s*:\s*"[^"]+"')
_KUBE_SECRET = re.compile(r"^\s*(?:client-key-data|token|password)\s*:\s*\S", re.M)
_AWS_SECRET = re.compile(r"^\s*aws_secret_access_key\s*=\s*\S", re.M | re.I)
_GCLOUD_SECRET = re.compile(r'"(?:refresh_token|private_key)"\s*:\s*"[^"]+"')
_GIT_CREDENTIAL = re.compile(r"^[a-z][a-z0-9+.-]*://[^:/@\s]+:[^@\s]+@", re.M)


def _read_head(path):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read(MAX_CREDENTIAL)
    except (OSError, ValueError):
        return None


def _holds_assigned_secret(text):
    """Whether text holds a KEY=value clean would call a secret, or a value
    clean finds on its own."""
    if clean_mod.find_secrets(text):
        return True
    for m in _ASSIGN.finditer(text):
        key, value = m.group(1), m.group(2).strip().strip("\"'")
        if value and clean_mod._names_a_secret(_as_key(key)) \
                and not _REFERENCE.match(value) \
                and not clean_mod._is_placeholder(value):
            return True
    return False


def _is_env_name(name):
    if name in (".env", ".envrc"):
        return True
    if not name.startswith(".env.") and not name.startswith(".env-"):
        return False
    return not name.lower().endswith(_ENV_TEMPLATES)


_KEY_NAMES = re.compile(r"^id_(?:rsa|dsa|ecdsa|ed25519)(?:_sk)?$")
_KEY_EXTS = (".pem", ".key", ".p8")


def project_kind(name):
    """What a file of this name in a project would be, if it is a
    credential file, else None."""
    if _is_env_name(name):
        return "env file"
    if _KEY_NAMES.match(name) or name.lower().endswith(_KEY_EXTS):
        return "private key"
    if name in (".npmrc", ".pypirc", ".netrc", "_netrc", ".git-credentials"):
        return "credentials"
    return None


def holds_credential(path, kind):
    """Whether the file at path holds what its kind promises. A .env of
    PORT=3000 and a public certificate named .pem are left out."""
    text = _read_head(path)
    if not text:
        return False
    if kind == "private key":
        return bool(_PRIVATE_KEY.search(text))
    if kind == "aws":
        return bool(_AWS_SECRET.search(text))
    if kind == "docker":
        return bool(_DOCKER_AUTH.search(text))
    if kind == "kubeconfig":
        return bool(_KUBE_SECRET.search(text))
    if kind == "gcloud":
        return bool(_GCLOUD_SECRET.search(text))
    name = os.path.basename(path)
    if name in (".netrc", "_netrc") and _NETRC_PASSWORD.search(text):
        return True
    if name == ".git-credentials":
        return bool(_GIT_CREDENTIAL.search(text))
    return _holds_assigned_secret(text)


def home_candidates(env, home):
    """(path, kind, rule) for each credential file kept under the home
    folder by a tool an agent may drive. rule is the Read deny rule to
    suggest for it."""
    out = []
    aws = _env(env, "AWS_SHARED_CREDENTIALS_FILE")
    aws = os.path.abspath(os.path.expanduser(aws)) if aws \
        else os.path.join(home, ".aws", "credentials")
    out.append((aws, "aws", None))
    ssh = os.path.join(home, ".ssh")
    try:
        names = sorted(os.listdir(ssh))
    except OSError:
        names = []
    for name in names:
        if name.startswith("id_") and not name.endswith(".pub"):
            out.append((os.path.join(ssh, name), "private key", "Read(~/.ssh/**)"))
    try:
        top = sorted(os.listdir(home))
    except OSError:
        top = []
    for name in top:
        if _is_env_name(name):
            out.append((os.path.join(home, name), "env file", None))
    for parts, kind in (((".netrc",), "credentials"), (("_netrc",), "credentials"),
                        ((".git-credentials",), "credentials"),
                        ((".npmrc",), "credentials"), ((".pypirc",), "credentials"),
                        ((".docker", "config.json"), "docker"),
                        ((".kube", "config"), "kubeconfig"),
                        ((".config", "gh", "hosts.yml"), "credentials"),
                        ((".config", "gcloud", "application_default_credentials.json"), "gcloud"),
                        ((".terraform.d", "credentials.tfrc.json"), "credentials")):
        out.append((os.path.join(home, *parts), kind, None))
    kube = _env(env, "KUBECONFIG")
    if kube:
        for path in kube.split(os.pathsep):
            path = os.path.abspath(os.path.expanduser(path)) if path else path
            if path and path != os.path.join(home, ".kube", "config"):
                out.append((path, "kubeconfig", None))
    return out


def _home_rule(path, home):
    slashed, h = _slashed(path), _slashed(home)
    if slashed.startswith(h + "/"):
        return "Read(~/%s)" % _glob_escape(slashed[len(h) + 1:])
    return "Read(/%s)" % _glob_escape(slashed)


def _glob_escape(text):
    return re.sub(r"([*?\[\]\\])", r"\\\1", text)


def walk_project(root, depth=WALK_DEPTH, limit=WALK_DIRS):
    """(path, kind) for each candidate credential file under root, and
    why the walk did not see everything: "dirs" when it stopped at its
    limit, "depth" when a directory was deeper than it looks, else None."""
    found, seen, cut = [], 0, None
    stack = [(root, 0)]
    while stack:
        folder, level = stack.pop()
        seen += 1
        if seen > limit:
            cut = "dirs"
            break
        try:
            entries = sorted(os.scandir(folder), key=lambda e: e.name)
        except (OSError, ValueError):
            continue
        subdirs = []
        for entry in entries:
            try:
                if entry.is_dir(follow_symlinks=False):
                    if entry.name in SKIP_DIRS or level < 0:
                        continue
                    if level + 1 >= depth:
                        cut = cut or "depth"
                        continue
                    subdirs.append((entry.path, -1 if entry.name in SHALLOW_DIRS
                                    else level + 1))
                    continue
                if not entry.is_file():
                    continue
            except OSError:
                continue
            kind = project_kind(entry.name)
            if kind:
                found.append((entry.path, kind))
        stack.extend(reversed(subdirs))
    return found, cut


# ----------------------------------------------------------------------
# The whole picture

def _project_dirs(doc, cwd, given, home, extra):
    """Directories an agent works in: the one asked for, else the current
    one and every project Claude Code keeps state for, and the
    additionalDirectories its settings grant."""
    dirs = []
    if given:
        dirs = list(given)
    else:
        if cwd:
            dirs.append(cwd)
        projects = doc.get("projects") if isinstance(doc, dict) else None
        if isinstance(projects, dict):
            dirs += [p for p in projects if isinstance(p, str)]
    dirs += extra
    out, seen = [], set()
    for d in dirs:
        d = os.path.abspath(os.path.expanduser(d)) if d.startswith("~") \
            else os.path.abspath(d)
        key = os.path.normcase(os.path.realpath(d))
        if key in seen or not _isdir(d):
            continue
        seen.add(key)
        out.append(d)
    return out


def _additional(paths, home):
    out = []
    for path in paths:
        doc = _load_json(path) if _isfile(path) else None
        perms = doc.get("permissions") if isinstance(doc, dict) else None
        extra = perms.get("additionalDirectories") if isinstance(perms, dict) else None
        if isinstance(extra, list):
            for d in extra:
                if isinstance(d, str) and d:
                    out.append(os.path.join(home, d[2:]) if d.startswith("~/") else d)
    return out


def _flag(docs, name):
    return any(isinstance(d, dict) and d.get(name) is True for d in docs)


def _names(docs, name):
    out = set()
    for d in docs:
        value = d.get(name) if isinstance(d, dict) else None
        if isinstance(value, list):
            out.update(v for v in value if isinstance(v, str))
    return out


def audit(env=None, home=None, cwd=None, projects=None, platform=None):
    """Everything reach reports, as a dict. projects, when given, is the
    list of directories to look at in place of the current one and those
    Claude Code knows."""
    env = os.environ if env is None else env
    home = _paths.home() if home is None else home
    if cwd is None:
        try:
            cwd = os.getcwd()
        except OSError:
            cwd = None
    cdir = claude_dir(env, home)
    managed = managed_dirs(platform)
    user_settings = [(os.path.join(d, "managed-settings.json"), None) for d in managed]
    user_settings.append((os.path.join(cdir, "settings.json"), cdir))

    cj_path = claude_json(env, home)
    cj = _load_json(cj_path) if _isfile(cj_path) else None
    dirs = _project_dirs(cj, cwd, projects, home,
                         _additional([p for p, _ in user_settings], home))
    read = []

    # MCP servers ------------------------------------------------------
    servers = []
    for agent, scope, path, fmt, key in user_configs(env, home, platform):
        if not _isfile(path):
            continue
        doc = _load_toml(path) if fmt == "toml" else _load_json(path)
        if doc is None:
            read.append({"file": path, "agent": agent,
                         "note": ("needs Python 3.11 or later to read"
                                  if fmt == "toml" and _tomllib() is None
                                  else "could not be parsed")})
            continue
        read.append({"file": path, "agent": agent})
        for name, s in _servers_in(doc, key):
            servers.append(describe(name, s, agent, scope, path))
        if agent == "Claude Code" and scope == "user" and isinstance(doc, dict):
            # Local scope: servers kept per project in ~/.claude.json.
            projects_doc = doc.get("projects")
            if isinstance(projects_doc, dict):
                for project, entry in projects_doc.items():
                    for name, s in _servers_in(entry, "mcpServers"):
                        servers.append(describe(name, s, agent, "local", path,
                                                project=project))

    user_docs = [_load_json(p) for p, _ in user_settings if _isfile(p)]
    for project in dirs:
        settings = [os.path.join(project, ".claude", "settings.json"),
                    os.path.join(project, ".claude", "settings.local.json")]
        entry = (cj.get("projects") or {}).get(project) if isinstance(cj, dict) \
            and isinstance(cj.get("projects"), dict) else None
        docs = user_docs + [_load_json(p) for p in settings if _isfile(p)] + [entry]
        enabled_all = _flag(docs, "enableAllProjectMcpServers")
        enabled = _names(docs, "enabledMcpjsonServers")
        disabled = _names(docs, "disabledMcpjsonServers")
        for agent, scope, rel, key in PROJECT_CONFIGS:
            path = os.path.join(project, rel)
            if not _isfile(path):
                continue
            doc = _load_json(path)
            if doc is None:
                read.append({"file": path, "agent": agent, "note": "could not be parsed"})
                continue
            read.append({"file": path, "agent": agent})
            for name, s in _servers_in(doc, key):
                d = describe(name, s, agent, scope, path, project=project)
                if agent == "Claude Code":
                    if name in disabled:
                        d["disabled"] = True
                    elif enabled_all:
                        d["risks"].append({
                            "kind": "auto-approved", "where": "settings",
                            "detail": "enableAllProjectMcpServers starts every "
                                      "server in this .mcp.json without asking"})
                    elif name in enabled:
                        d["approved"] = True
                servers.append(d)

    # Credential files ---------------------------------------------------
    user_rules, settings_read = read_rules(user_settings)
    files, rules_wanted, cut_short = [], [], []
    for path, kind, rule in home_candidates(env, home):
        if not _isfile(path) or not holds_credential(path, kind):
            continue
        if denied(user_rules, path, None, home):
            continue
        files.append({"path": path, "kind": _KIND_NAMES.get(kind, kind),
                      "where": "home"})
        rules_wanted.append(rule or _home_rule(path, home))
    seen = {os.path.normcase(os.path.realpath(f["path"])) for f in files}
    for project in dirs:
        if _contains(project, home):
            continue          # home is looked at above, and not walked whole
        project_settings = [(os.path.join(project, ".claude", name), project)
                            for name in ("settings.json", "settings.local.json")]
        rules, read_here = read_rules(project_settings)
        rules = user_rules + rules
        settings_read += read_here
        found, cut = walk_project(project)
        if cut:
            cut_short.append({"project": project, "why": cut})
        for path, kind in found:
            key = os.path.normcase(os.path.realpath(path))
            if key in seen or not holds_credential(path, kind):
                continue
            if denied(rules, path, project, home):
                continue
            seen.add(key)
            files.append({"path": path, "kind": kind, "where": "project",
                          "project": project})
            rules_wanted.append("Read(//**/%s)" % _glob_escape(os.path.basename(path)))

    deny = []
    for rule in rules_wanted:
        if rule not in deny:
            deny.append(rule)
    values = []
    for s in servers:
        values += s.pop("values")
    return {
        "servers": servers, "files": files, "deny": deny,
        "settings": os.path.join(cdir, "settings.json"),
        "configs_read": read, "settings_read": settings_read,
        "projects": dirs, "cut_short": cut_short,
        "secrets": values,
    }


_KIND_NAMES = {"aws": "AWS credentials", "docker": "Docker registry login",
               "kubeconfig": "Kubernetes credentials",
               "gcloud": "Google Cloud credentials"}


def _contains(outer, inner):
    """Whether outer is inner or a directory above it."""
    try:
        a = os.path.normcase(os.path.realpath(outer))
        b = os.path.normcase(os.path.realpath(inner))
    except (OSError, ValueError):
        return False
    return a == b or b.startswith(a.rstrip(os.sep) + os.sep)


# ----------------------------------------------------------------------
# Masking and output

def masker(values):
    """A function that replaces every copy of each value with its hint, as
    clean shows a secret. Longest first, so a value inside another is
    never left half shown."""
    ordered = sorted(set(v for v in values if v), key=len, reverse=True)

    def mask(text):
        if not isinstance(text, str):
            return text
        for v in ordered:
            if v in text:
                text = text.replace(v, clean_mod.DISPLAY_MASK % clean_mod._hint(v))
        return clean_mod.mask_for_display(text)
    return mask


def _masked(node, mask):
    if isinstance(node, str):
        return mask(node)
    if isinstance(node, dict):
        return {(mask(k) if isinstance(k, str) else k): _masked(v, mask)
                for k, v in node.items()}
    if isinstance(node, list):
        return [_masked(v, mask) for v in node]
    return node


def as_json(result):
    """result with every secret shown as its hint, and the raw values
    gone: what --json prints."""
    mask = masker(result["secrets"])
    doc = json.loads(json.dumps({k: v for k, v in result.items()
                                 if k != "secrets"}))
    for s in doc["servers"]:
        for r in s["risks"]:
            if "secret" in r:
                r["secret"] = clean_mod.DISPLAY_MASK % clean_mod._hint(r.pop("secret"))
    return _masked(doc, mask)


def snippet(deny):
    """The permissions block to paste, as JSON text."""
    return json.dumps({"permissions": {"deny": deny}}, indent=2)


TITLE = ("  ranwhat reach  ", "\u00b7 what your agents can reach")

_RISK_WORDS = {
    "inline-secret": "secret inline",
    "unpinned": "unpinned",
    "remote": "remote",
    "unencrypted": "unencrypted",
    "local-url": "local URL",
    "auto-approved": "auto-approved",
}


def _short(path, home):
    if home and home not in ("/", "") and (path == home or path.startswith(home + os.sep)):
        return "~" + path[len(home):]
    return path


def _quote_word(word):
    return word if word and not re.search(r"\s|[\"'$`\\]", word) else json.dumps(word)


def render(result, home=None):
    """The report as text, every secret in it shown as its hint."""
    from . import term
    from .report import BOLD, DIM, RED, YEL
    home = _paths.home() if home is None else home
    mask = masker(result["secrets"])
    width = term.width()
    title, tagline = TITLE
    if len(title + tagline) <= width:
        L = ["", BOLD(title) + DIM(tagline)]
    else:
        L = ["", BOLD(title.rstrip()), DIM("  " + tagline[2:])]
    L += [DIM(term.rule("-")), ""]

    servers = result["servers"]
    L.append(BOLD("  MCP servers") + DIM("  %d" % len(servers)))
    read = [c for c in result["configs_read"] if not c.get("note")]
    unread = [c for c in result["configs_read"] if c.get("note")]
    if not servers:
        L += [DIM(line) for line in term.wrap(
            "None found in %d configuration file%s read."
            % (len(read), "" if len(read) == 1 else "s"), indent="    ")]
    for c in unread:
        L += [YEL(line) for line in term.wrap(
            "Not read: %s (%s), %s." % (_short(c["file"], home), c["agent"],
                                        c["note"]), indent="    ")]
    for s in servers:
        where = "%s, %s scope" % (s["agent"], s["scope"])
        if s["scope"] == "local" and s.get("project"):
            where += " for " + _short(mask(s["project"]), home)
        if s.get("disabled"):
            where += ", disabled"
        L.append("")
        L += term.wrap(where, first="    %s  " % mask(s["name"]), indent="      ")
        L += [DIM(line) for line in term.wrap(
            _short(mask(s["file"]), home), indent="      ")]
        if s["url"]:
            what = "connects to " + mask(s["url"])
        elif s["command"]:
            what = "runs " + " ".join(_quote_word(mask(w)) for w in s["command"])
        else:
            what = "launches nothing ranwhat can read"
        L += term.wrap(what, indent="        ", first="      ")
        if s["env"]:
            L += [DIM(line) for line in term.wrap(
                "env: " + ", ".join(mask(k) for k in s["env"]),
                indent="        ", first="      ")]
        for r in s["risks"]:
            word = _RISK_WORDS.get(r["kind"], r["kind"])
            if r["kind"] == "inline-secret":
                text = "%s in %s: %s (%s). Move it to the environment and rotate it." % (
                    word, mask(r["where"]),
                    clean_mod.DISPLAY_MASK % clean_mod._hint(r["secret"]),
                    r["label"])
                colour = RED
            elif r["kind"] in ("unpinned", "unencrypted", "auto-approved"):
                text, colour = "%s: %s" % (word, mask(r["detail"])), YEL
            else:
                text, colour = "%s: %s" % (word, mask(r["detail"])), DIM
            lines = term.wrap(text, indent="        ", first="      ! ")
            L += [colour(line) for line in lines]
    L.append("")

    files = result["files"]
    L.append(BOLD("  Credential files an agent can read") + DIM("  %d" % len(files)))
    if not files:
        L += [DIM(line) for line in term.wrap(
            "None that a Claude Code Read deny rule leaves open, in the home "
            "folder or in %d project director%s."
            % (len(result["projects"]),
               "y" if len(result["projects"]) == 1 else "ies"), indent="    ")]
    else:
        L += [DIM(line) for line in term.wrap(
            "No Read deny rule in Claude Code's settings covers these. Only "
            "the path is shown; nothing in them was printed.", indent="    ")]
        for f in files:
            L += term.wrap(f["kind"], first="    %s  " % _short(f["path"], home),
                           indent="      ")
    for cut in result["cut_short"]:
        if cut["why"] == "dirs":
            why = ("holds more than %d directories; only the first were "
                   "looked in." % WALK_DIRS)
        else:
            why = "goes deeper than %d levels; nothing below that was looked in." % WALK_DEPTH
        L += [DIM(line) for line in term.wrap(
            "%s %s" % (_short(cut["project"], home), why), indent="    ")]
    L.append("")

    if result["deny"]:
        L.append(BOLD("  Deny them"))
        L += term.wrap("Add these to permissions.deny in %s (nothing was "
                       "written):" % _short(result["settings"], home), indent="    ")
        L.append("")
        L += ["    " + line for line in snippet(result["deny"]).splitlines()]
        L.append("")
        L += [DIM(line) for line in term.wrap(
            "A Read rule stops Claude's file tools and the Bash file commands "
            "Claude Code recognises, not a script that opens the file itself: "
            "turn on /sandbox for that. %s" % GUIDE, indent="    ")]
        L.append("")
    L += [DIM(term.rule("-")),
          DIM("  Read locally. Nothing was transmitted, and nothing changed."), ""]
    return "\n".join(L)
