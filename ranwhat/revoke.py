"""
Revoke: take back what an agent was given.

Two halves, and both change something, which is why both ask first.

Local: `ranwhat revoke` reads Claude Code's settings files and lists the
grants that let an agent act without asking, such as bypassPermissions as
the default mode, every project MCP server approved up front, a Bash rule
that allows anything, or an allow rule for curl, rm or a credential file.
It changes nothing until --apply, and then keeps a copy of each file it
rewrites beside it.

Provider: a token that leaked is revoked where it was issued. Three
providers let anyone holding a token revoke it with one call, and those
are the ones here: GitHub (its public credential-revocation endpoint, which
also tells the owner), Slack (auth.revoke) and Google (its OAuth revocation
endpoint). Each token goes to its own issuer and nowhere else. Every other
provider is rolled in its dashboard, which clean's `open` takes you to.
"""

from __future__ import annotations

import json
import os
import re
import shutil

from . import hook as hook_mod

BACKUP_SUFFIX = ".ranwhat-backup"
SCOPES = ("user", "project", "local")

# --------------------------------------------------------------------------
# Local: Claude Code settings
# --------------------------------------------------------------------------

# Programs whose allow rule lets the agent reach the network, delete,
# publish, change a remote or act as root without a prompt: the kinds of
# call watch rates high.
_RISKY_COMMANDS = (
    "curl", "wget", "nc", "ncat", "ssh", "scp", "rsync", "sftp",
    "rm", "sudo", "su", "chmod", "chown", "dd", "mkfs",
    "git push", "git reset --hard", "git clean",
    "npm publish", "yarn publish", "pnpm publish", "twine upload",
    "cargo publish", "gem push", "docker", "kubectl", "terraform",
    "aws", "gcloud", "az", "gh", "eval", "sh -c", "bash -c", "zsh -c",
)

# Paths whose read or edit rule hands the agent a credential.
_CREDENTIAL_PATHS = (".env", ".ssh", ".aws", ".gnupg", ".netrc", ".npmrc",
                     ".pypirc", ".docker/config.json", ".kube",
                     "credentials", "id_rsa", "id_ed25519", ".pem")

_RULE = re.compile(r"^\s*([A-Za-z]+)\s*(?:\((.*)\))?\s*$", re.S)
_EVERYTHING = ("", "*", "**", "*:*", ":*", "//**", "~/**", "/**")


def _risky_rule(rule):
    """Why an allow rule is worth taking back, or None."""
    if not isinstance(rule, str):
        return None
    m = _RULE.match(rule)
    if not m:
        return None
    tool, spec = m.group(1).lower(), (m.group(2) or "").strip()
    if tool == "bash":
        if spec in _EVERYTHING:
            return "allows every shell command without asking"
        # "Bash(curl:*)" and "Bash(curl *)" both name curl.
        command = " ".join(spec.split(":")[0].replace("*", " ").split()).lower()
        for risky in _RISKY_COMMANDS:
            if command == risky or command.startswith(risky + " "):
                return "runs %s without asking" % risky
        return None
    if tool in ("read", "edit", "write", "multiedit"):
        verb = "reads" if tool == "read" else "edits"
        if spec in _EVERYTHING:
            return "%s every file without asking" % verb
        low = spec.lower()
        for path in _CREDENTIAL_PATHS:
            if path in low:
                return "%s a credential file (%s) without asking" % (verb, path)
    return None


def plan(path):
    """What to take back in one settings file: a list of
    {"what", "why", "key"} dicts. key says how apply removes it."""
    settings = hook_mod._read(path)
    items = []
    perms = settings.get("permissions")
    if isinstance(perms, dict):
        if perms.get("defaultMode") == "bypassPermissions":
            items.append({"what": 'permissions.defaultMode "bypassPermissions"',
                          "why": "every tool call runs without a prompt",
                          "key": ["defaultMode", None]})
        allow = perms.get("allow")
        if isinstance(allow, list):
            for rule in allow:
                why = _risky_rule(rule)
                if why:
                    items.append({"what": "allow %s" % rule, "why": why,
                                  "key": ["allow", rule]})
    if settings.get("enableAllProjectMcpServers") is True:
        items.append({"what": "enableAllProjectMcpServers true",
                      "why": "starts every server a project's .mcp.json "
                             "names, without asking",
                      "key": ["enableAllProjectMcpServers", None]})
    return items


def apply(path, items):
    """Take back items (from plan) in path. A copy of the file as it was is
    kept beside it first. Returns the backup's path, or None when there was
    nothing to take back."""
    if not items:
        return None
    settings = hook_mod._read(path)
    real = os.path.realpath(path)
    backup = real + BACKUP_SUFFIX
    shutil.copy2(real, backup)
    perms = settings.get("permissions")
    for item in items:
        kind, value = item["key"]
        if kind == "defaultMode" and isinstance(perms, dict):
            perms.pop("defaultMode", None)
        elif kind == "allow" and isinstance(perms, dict) \
                and isinstance(perms.get("allow"), list):
            perms["allow"] = [r for r in perms["allow"] if r != value]
        elif kind == "enableAllProjectMcpServers":
            settings["enableAllProjectMcpServers"] = False
    hook_mod._write(path, settings)
    return backup


def local(scopes=SCOPES, cwd=None, env=None):
    """[{scope, path, exists, items, error}] for each settings file."""
    out = []
    for scope in scopes:
        path = hook_mod.settings_path(scope, cwd=cwd, env=env)
        entry = {"scope": scope, "path": path, "exists": os.path.isfile(path),
                 "items": [], "error": None}
        if entry["exists"]:
            try:
                entry["items"] = plan(path)
            except hook_mod.SettingsError as e:
                entry["error"] = str(e)
        out.append(entry)
    return out


TITLE = ("  ranwhat revoke", "  · take back what your agents were allowed")


def render_local(entries, applied=False, home=None):
    from . import term
    from .report import BOLD, DIM, GRN, RED, YEL
    home = os.path.expanduser("~") if home is None else home

    def short(path):
        return "~" + path[len(home):] if path.startswith(home + os.sep) else path

    width = term.width()
    title, tagline = TITLE
    L = (["", BOLD(title) + DIM(tagline)] if len(title + tagline) <= width
         else ["", BOLD(title.rstrip()), DIM("  " + tagline[2:])])
    L += [DIM(term.rule("-")), ""]
    total = 0
    for e in entries:
        head = "  Claude Code, %s settings" % e["scope"]
        if not e["exists"]:
            L.append(BOLD(head) + DIM("  no file"))
            L += [DIM(x) for x in term.wrap(short(e["path"]), indent="    ")]
            L.append("")
            continue
        if e["error"]:
            L.append(BOLD(head) + YEL("  not read"))
            L += [YEL(x) for x in term.wrap(e["error"], indent="    ")]
            L.append("")
            continue
        n = len(e["items"])
        total += n
        if not n:
            L.append(BOLD(head) + DIM("  nothing to take back"))
        else:
            state = ("took back %d" % n) if applied else ("%d to take back" % n)
            L.append(BOLD(head) + (GRN if applied else RED)("  " + state))
        L += [DIM(x) for x in term.wrap(short(e["path"]), indent="    ")]
        for item in e["items"]:
            L += term.wrap(item["what"], first="    - ", indent="      ")
            L += [DIM(x) for x in term.wrap(item["why"], indent="      ")]
        if applied and e.get("backup"):
            L += [DIM(x) for x in term.wrap("As it was: %s" % short(e["backup"]),
                                            indent="    ")]
        L.append("")
    if total and not applied:
        L += term.wrap("Nothing was changed. ranwhat revoke --apply takes "
                       "these back, keeping a copy of each file beside it "
                       "first. A leaked token is revoked from clean's "
                       "review, with revoke N.")
    elif total:
        L += term.wrap("Restart Claude Code for this to take effect. What "
                       "was allowed before now asks you first.")
    else:
        L += [DIM(x) for x in term.wrap(
            "Nothing found that lets an agent act without asking.")]
    L.append("")
    return "\n".join(L)


# --------------------------------------------------------------------------
# Provider: revoke a leaked token where it was issued
# --------------------------------------------------------------------------

_GITHUB = re.compile(r"^(ghp_|github_pat_|gho_|ghu_|ghr_)[A-Za-z0-9_]+$")
_SLACK = re.compile(r"^xox[abposr]-[A-Za-z0-9-]+$")
_GOOGLE = re.compile(r"^(ya29\.[A-Za-z0-9._-]+|1//[A-Za-z0-9._-]+)$")

NAMES = {"github": "GitHub", "slack": "Slack", "google": "Google"}


def provider_for(value):
    """github, slack or google when value is a token that provider lets
    anyone holding it revoke with one call; None otherwise."""
    value = (value or "").strip()
    if _GITHUB.match(value):
        return "github"
    if _SLACK.match(value):
        return "slack"
    if _GOOGLE.match(value):
        return "google"
    return None


class RevokeError(Exception):
    """The provider did not confirm the revocation, and why. Never holds
    the token."""


def _post(url, body, headers):
    """(status, text). Its own small POST: GitHub wants a JSON body, which
    introspect's form-encoding helper does not send."""
    import urllib.error
    import urllib.request
    from . import __version__
    from .introspect import TIMEOUT
    req = urllib.request.Request(url, data=body, method="POST")
    # Not introspect's agent, which says read-only: this one is not.
    req.add_header("User-Agent", "ranwhat/%s (revoke)" % __version__)
    for k, v in headers.items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except (urllib.error.URLError, OSError, ValueError) as e:
        # ValueError: http.client refusing a header, and its message would
        # quote the header, token and all. Said without it.
        raise RevokeError("could not reach the provider (%s)"
                          % type(e).__name__)


def revoke_token(value, post=None):
    """Revoke value at its issuer. Returns the provider's display name;
    raises RevokeError when the provider did not confirm it. The value is
    sent to that provider alone."""
    import urllib.parse
    post = post or _post
    value = (value or "").strip()
    provider = provider_for(value)
    if provider == "github":
        # Unauthenticated, as GitHub requires: it refuses this endpoint
        # with a token in the header. It revokes, and tells the owner.
        status, _ = post("https://api.github.com/credentials/revoke",
                         json.dumps({"credentials": [value]}).encode(),
                         {"Accept": "application/vnd.github+json",
                          "Content-Type": "application/json"})
        if status != 202:
            raise RevokeError("GitHub answered %s, not 202 Accepted" % status)
    elif provider == "slack":
        status, text = post("https://slack.com/api/auth.revoke", b"",
                            {"Authorization": "Bearer %s" % value,
                             "Content-Type": "application/x-www-form-urlencoded"})
        try:
            reply = json.loads(text)
        except ValueError:
            reply = {}
        if status != 200 or not isinstance(reply, dict) or not reply.get("ok"):
            raise RevokeError("Slack did not revoke it (%s)" % (
                reply.get("error") if isinstance(reply, dict)
                and reply.get("error") else "HTTP %s" % status))
    elif provider == "google":
        status, _ = post("https://oauth2.googleapis.com/revoke",
                         urllib.parse.urlencode({"token": value}).encode(),
                         {"Content-Type": "application/x-www-form-urlencoded"})
        if status != 200:
            raise RevokeError("Google answered %s; the token may have "
                              "expired already" % status)
    else:
        raise RevokeError("no provider lets this be revoked with one call")
    return NAMES[provider]
