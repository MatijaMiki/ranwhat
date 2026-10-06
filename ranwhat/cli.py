"""ranwhat CLI.

  ranwhat demo                        run against the bundled example
  ranwhat scan profile.json           score a declared profile
  ranwhat live --google $TOK ...      introspect real credentials locally
  ranwhat scan profile.json --html out.html

Live mode never transmits a token anywhere except the issuing provider.
"""
from __future__ import annotations

import argparse
import errno
import io
import json
import os
import re
import shlex
import shutil
import sys
import time

from . import __version__
from .score import (scan as _run_scan, ProfileError, UNCLASSIFIED,
                    _validate as _validate_profile)
from .report import render
from . import watch as watch_mod
from . import clean as clean_mod
from . import known as known_mod
from . import catalog as catalog_mod
from . import agents as agents_mod
from . import sources as sources_mod
from . import hints
from . import term

# introspect, usage and feed talk to providers and to the feed, and import
# urllib's HTTP stack to do it: a fifth of the time `watch` took to start.
# Only live, scan --pull-usage and update use them, so each is imported
# there, and cli.introspect, cli.usage_mod and cli.feed_mod still name them.
_LAZY = {"introspect": "introspect", "usage_mod": "usage", "feed_mod": "feed"}
# introspect.PROVIDERS, named here for the flags each takes, and usage's
# default window (tests/test_work_done.py checks that they agree).
_PROVIDER_NAMES = ("google", "github", "slack", "stripe")
_DEFAULT_WINDOW_DAYS = 90


def _module(name):
    import importlib
    return importlib.import_module("." + _LAZY[name], __package__)


def __getattr__(name):
    if name in _LAZY:
        return _module(name)
    raise AttributeError("module %r has no attribute %r" % (__name__, name))


def _token(args, provider):
    """Resolve a credential without requiring it on the command line.

    Anything in argv is world-readable through the process table for as long
    as the process runs, and is written to shell history besides. The
    environment variable is the documented path; a literal flag still works
    but says so.
    """
    env_name = "RANWHAT_%s_TOKEN" % provider.upper()
    value = getattr(args, provider, None)

    if value == "-":
        value = sys.stdin.readline().strip()
    elif value and value.startswith("env:"):
        var = value[4:]
        value = os.environ.get(var)
        if not value:
            raise SystemExit("ranwhat: %s is empty or unset" % var)
    elif value:
        print("  warning: --%s put a credential in this machine's process "
              "table. Use %s instead." % (provider, env_name), file=sys.stderr)

    # Stripped on every path, not only stdin. A token copied out of a CRLF
    # .env keeps its \r, http.client rejects the header, and the ValueError
    # it raises quotes the whole header, token included, into the error the
    # user sees.
    value = (value or os.environ.get(env_name) or "").strip()
    return value or None


def run_scan(profile, path=None, pulled=False):
    """Score a profile, turning a malformed one into a message. `path` is the
    file it came from, and `pulled` whether --pull-usage ran, for advice
    that has to name the one and not repeat the other."""
    try:
        return _run_scan(profile, path=path, pulled=pulled)
    except ProfileError as e:
        raise SystemExit("ranwhat: %s" % e)


def _load(path):
    """Read a profile, failing with a message rather than a traceback.

    UTF-8, not the locale's encoding, and a leading byte-order mark allowed:
    PowerShell 5 and older Notepad write one, and json refuses it."""
    try:
        with open(path, encoding="utf-8-sig") as fh:
            return json.load(fh)
    except FileNotFoundError:
        raise SystemExit("ranwhat: no such file: %s" % path)
    except IsADirectoryError:
        raise SystemExit("ranwhat: not a file: %s" % path)
    except PermissionError:
        raise SystemExit("ranwhat: cannot read (permission denied): %s" % path)
    except ValueError as e:
        raise SystemExit("ranwhat: %s is not valid JSON (%s)" % (path, e))
    except OSError as e:
        # A name Windows refuses (profile?.json is EINVAL), and the rest.
        raise SystemExit("ranwhat: cannot read %s (%s)" % (path, e.strerror or e))


def _bundled(name):
    """Load data shipped inside the package."""
    try:
        from importlib.resources import files
        return json.loads(files("ranwhat").joinpath("demo", name)
                          .read_text(encoding="utf-8"))
    except Exception:
        here = os.path.dirname(os.path.abspath(__file__))
        return _load(os.path.join(here, "demo", name))


def _usage_line(provider, text):
    """One provider's line about its usage pull, on stderr, folded under
    its own column."""
    for line in term.wrap(text, indent=" " * 18,
                          first="  usage: %-8s " % provider):
        print(line, file=sys.stderr)


def _pull_usage(profile, args):
    """Best-effort usage pulls. A provider that cannot report usage is left
    explicitly unverified rather than silently empty, and every provider
    that is not asked says why: skipped in silence, the report went on
    advising the very command that had just skipped it.

    Returns the profile and whether any provider was asked, which decides
    whether the report may say nothing was transmitted.

    The profile is checked first, as the scan would check it: the
    providers were read from it before that, and a provider of 5 beside
    "openai" ended the run in a traceback."""
    try:
        _validate_profile(profile)
    except ProfileError as e:
        raise SystemExit("ranwhat: %s" % e)
    usage_mod, introspect = _module("usage_mod"), _module("introspect")
    results, asked = {}, False
    providers = {c.get("provider") for c in profile.get("credentials", [])}
    providers.discard(None)

    for provider in sorted(providers - set(usage_mod.PULLS)):
        _usage_line(provider, "no usage pull, so it stays as declared")
    for provider in sorted(providers & set(usage_mod.PULLS)):
        if provider == "aws":
            # aws reads the AWS CLI's own credentials, so it needs the CLI.
            # Without it nothing is sent, and the footer must not say so.
            if not shutil.which("aws"):
                _usage_line(provider, "skipped, the aws CLI is not on PATH")
                continue
            token = None
        else:
            token = _token(args, provider)
            if not token:
                _usage_line(provider, "skipped, set RANWHAT_%s_TOKEN to "
                                      "pull it" % provider.upper())
                continue
            if provider == "github" and not args.github_org:
                # GitHub keeps usage only in an organisation's audit log,
                # and github_usage sends nothing without one.
                _usage_line(provider, "skipped, pass --github-org ORG to "
                                      "pull it from that organisation's "
                                      "audit log")
                continue
        asked = True
        try:
            if provider == "aws":
                results["aws"] = usage_mod.aws_usage(
                    profile=args.aws_profile, window_days=args.window_days)
            elif provider == "github":
                results["github"] = usage_mod.github_usage(
                    token, org=args.github_org, window_days=args.window_days)
            else:
                results[provider] = usage_mod.PULLS[provider](
                    token, window_days=args.window_days)
            _usage_line(provider, results[provider][1].level)
        except introspect.IntrospectionError as e:
            _usage_line(provider, "unavailable (%s)" % e)

    if results:
        usage_mod.apply_usage(profile, results)
    return profile, asked


def _emit(result, args, online=False):
    """`online` when a provider's API was asked, by live or --pull-usage."""
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(render(result, online=online))
    if args.html:
        from .html_report import write_html
        write_html(result, args.html)
        # After JSON on stdout, one more line there stops it parsing.
        print("  html report: %s\n" % args.html,
              file=sys.stderr if args.json else sys.stdout)


TAGLINE = "Flight recorder and authority scanner for AI agents."

# What reaches the network, said once for the overview and --help. "Nothing is
# transmitted" was false for live and --pull-usage, which send each token to
# the provider that issued it, and for update, which fetches the catalogue.
NETWORK = ("No account needed. live and --pull-usage ask only the provider "
           "that issued each token, and update only fetches the catalogue. "
           "Everything else reads locally and sends nothing.")

# Descriptions wrap under their own column on a narrow terminal, rather than
# being folded again by the terminal into ragged half-lines.
COMMANDS = (
    ("check", "watch and clean in one pass, changing nothing"),
    ("watch", "what your agents already ran on this machine"),
    ("clean", "credentials sitting in plaintext in agent transcripts"),
    ("sources", "every agent ranwhat reads, and where it looked"),
    ("scan", "the authority a set of credentials carries"),
    ("live", "the same, asked of each token's own provider"),
    ("demo", "see the output without setting anything up"),
    ("update", "refresh the capability catalogue (needs a subscription)"),
)

# The commands whose report html_report can write.
_HTML_COMMANDS = ("demo", "scan", "live")

# --days when it is not given. A suggested command repeats any other value.
DEFAULT_DAYS = 30


_UV_BUCKET = re.compile(r"^archive-v\d+$")


def _real(p):
    return os.path.normcase(os.path.realpath(os.path.abspath(p)))


def _inside(path, root):
    # Component-wise, so ~/.cache/uv-sibling is not inside ~/.cache/uv.
    try:
        return os.path.commonpath([path, root]) == root
    except ValueError:            # different drives on Windows
        return False


def _uv_caches(env, home):
    roots = [env.get("UV_CACHE_DIR"),
             env.get("XDG_CACHE_HOME") and os.path.join(env["XDG_CACHE_HOME"], "uv"),
             os.path.join(home, ".cache", "uv"),
             env.get("LOCALAPPDATA") and os.path.join(env["LOCALAPPDATA"], "uv", "cache")]
    return [_real(os.path.expanduser(r)) for r in roots if r]


def _pipx_caches(env, home):
    """Where `pipx run` keeps its throwaway venvs, per pipx's paths.py.

    With PIPX_HOME set it is $PIPX_HOME/.cache; otherwise platformdirs'
    user cache dir. pipx before 1.3 used ~/.local/pipx/.cache."""
    xdg = env.get("XDG_CACHE_HOME") or os.path.join(home, ".cache")
    roots = [env.get("PIPX_HOME") and os.path.join(env["PIPX_HOME"], ".cache"),
             os.path.join(home, ".local", "pipx", ".cache"),
             os.path.join(xdg, "pipx"),
             os.path.join(home, "Library", "Caches", "pipx"),
             env.get("LOCALAPPDATA") and os.path.join(
                 env["LOCALAPPDATA"], "pipx", "pipx", "Cache")]
    return [_real(os.path.expanduser(r)) for r in roots if r]


def _ephemeral(env_root, env, home):
    """The command for a throwaway environment, or None for a lasting one."""
    bucket = os.path.dirname(env_root)
    uv = _uv_caches(env, home)
    # <cache>/archive-vN/<id>. uv tags every cache it creates, which catches
    # a --cache-dir given on the command line where no variable says so.
    if _UV_BUCKET.match(os.path.basename(bucket)):
        cache = os.path.dirname(bucket)
        if cache in uv or os.path.isfile(os.path.join(cache, "CACHEDIR.TAG")):
            return "uvx ranwhat"
    if any(_inside(env_root, root) for root in uv):
        return "uvx ranwhat"                  # builds-v0 temp envs and the like
    if bucket in _pipx_caches(env, home):
        return "pipx run ranwhat"             # a pipx-only user may not have uv
    return None


def _user_path(env, prefix, argv0):
    """PATH as the user's shell will have it once this process exits.

    uv prepends the environment's own bin directory to PATH for the child
    (uvx, `uv run`, and uvx reusing a `uv tool install`), and leaves the
    parent's PATH intact after it. Without stripping that, the bare command
    always resolves to us and the check below proves nothing."""
    entries = env.get("PATH", "").split(os.pathsep)
    if not env.get("UV"):
        return entries
    ours = {_real(os.path.join(prefix, "bin")),
            _real(os.path.join(prefix, "Scripts"))}
    if argv0:
        ours.add(os.path.dirname(_real(argv0)))
    caches = _uv_caches(env, os.path.expanduser("~"))
    while entries and entries[0] and (
            _real(entries[0]) in ours
            or any(_inside(_real(entries[0]), c) for c in caches)):
        entries = entries[1:]
    return entries


# Neither cmd nor PowerShell gives any of these a meaning of its own,
# wherever it is in a word.
_PLAIN_ON_WINDOWS = re.compile(r"[\w.:\\/~+-]+")


def _quote(arg, windows=None):
    """One argument, quoted for the shell the user is in.

    On Windows that is cmd or PowerShell, and one spelling serves both. A
    word of letters, digits and . : \\ / ~ + - _ means nothing to either
    and is left as it is. Anything else goes in double quotes, inside which
    both hand every character on as it is, but for what each still expands
    there: % in cmd, $ and ` in PowerShell. No quoting the two share holds
    those, so a path with them is quoted the same way, for cmd.
    subprocess.list2cmdline quoted only for a blank: C:\\R&D ran D as a
    second command in cmd, and O'Brien opened a string in PowerShell."""
    if windows is None:
        windows = os.name == "nt"
    if not windows:
        return shlex.quote(arg)
    if _PLAIN_ON_WINDOWS.fullmatch(arg):
        return arg
    if '"' in arg:                    # in no Windows path
        import subprocess
        return subprocess.list2cmdline([arg])
    # The C runtime splitting the program's command line reads a backslash
    # before the closing quote as escaping it, and two as one.
    return '"%s"' % (arg + "\\" * (len(arg) - len(arg.rstrip("\\"))))


def _same_file(a, b):
    return os.path.normcase(os.path.abspath(a)) == os.path.normcase(
        os.path.abspath(b))


def _launches(found, executable):
    """Whether running `found` starts this interpreter.

    macOS's /usr/bin/python3 is not a link but a launcher for the Command Line
    Tools' copy, so no comparison of paths can tell; only asking it can."""
    import subprocess
    probe = subprocess.run(
        [found, "-I", "-S", "-c", "import sys; sys.stdout.write(sys.executable)"],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL, timeout=3, check=False)
    started = probe.stdout.decode("utf-8", "replace").strip()
    return bool(started) and _same_file(started, executable)


def _python_m(executable, path, windows=None):
    """`python -m ranwhat` is running a checkout or venv, not the PyPI build.

    Spelled with the bare name when that name, looked up on the user's PATH,
    starts this interpreter, and with the full path otherwise. python3 is
    tried after the interpreter's own name, since python3.12 may be what ran
    but python3 is what people type.

    On Windows neither name is run to ask, since either on PATH may be the
    Store's alias, which opens the Store. Nor is the interpreter named by a
    quoted first word: PowerShell reads one as a string, not a command, and
    every step suggested after `py -m ranwhat` failed there. py, when it
    starts this interpreter, is next, then a path that needs no quotes,
    then uvx."""
    if windows is None:
        windows = os.name == "nt"
    for name in dict.fromkeys((os.path.basename(executable), "python3")):
        try:
            found = shutil.which(name, path=path)
            # abspath, not realpath: a venv's bin/python is a symlink to the
            # base interpreter, which does not have ranwhat.
            if found and (_same_file(found, executable) or (
                    not windows and _launches(found, executable))):
                return "%s -m ranwhat" % name
        except Exception:
            continue          # a launcher that hangs or fails is not ours
    if not windows:
        return "%s -m ranwhat" % _quote(executable, windows=False)
    try:
        found = shutil.which("py", path=path)
        if found and _launches(found, executable):
            return "py -m ranwhat"
    except Exception:
        pass
    word = _quote(executable, windows=True)
    return "%s -m ranwhat" % word if word == executable else "uvx ranwhat"


def invocation():
    """How to spell a follow-up command so it still works after this exits.

    Asking whether `ranwhat` on PATH is this file is not enough: uvx PREPENDS
    its throwaway environment's bin to PATH for the child, so under uvx the
    lookup always finds us and the user was told to run `ranwhat check`,
    which is command-not-found in their shell. So first look at where the
    environment lives, then check against the PATH the user will be left with.
    Never raises: _check() calls this after findings have printed.
    """
    try:
        env = os.environ
        home = os.path.expanduser("~")
        argv0 = sys.argv[0] if sys.argv else ""
        prefix = sys.prefix
        roots = [_real(prefix)]
        if argv0:
            # bin/ranwhat or Scripts\ranwhat.exe -> the environment root
            roots.append(os.path.dirname(os.path.dirname(_real(argv0))))
        for root in roots:
            kind = _ephemeral(root, env, home)
            if kind:
                return kind
        path = os.pathsep.join(_user_path(env, prefix, argv0))
        executable = sys.executable
        if os.path.basename(argv0) == "__main__.py" and executable:
            return _python_m(executable, path)
        on_path = shutil.which("ranwhat", path=path)
        if argv0 and on_path and _real(on_path) == _real(argv0):
            return "ranwhat"
    except Exception:
        pass
    return "uvx ranwhat"


def _overview(parser):
    """Shown for a bare `ranwhat`, instead of an argparse usage error."""
    cmd = invocation()
    L = term.wrap("find out what your AI agents actually did",
                  indent=" " * 13, first="  ranwhat  \u00b7 ")
    L.append("")
    for name, what in COMMANDS:
        L += term.wrap(what, indent=" " * 11, first="  %-8s " % name)
    L += ["", "  Start here:", "    %s check" % cmd, "    %s demo" % cmd, ""]
    L += term.wrap(NETWORK)
    L.append("  Full options: %s --help" % cmd)
    sys.stdout.write("\n".join(L) + "\n")


def _update(args):
    """Fetch the subscribed catalogue, or report what is cached.

    One of three things that go online, with live and --pull-usage, and the
    only one that talks to ranwhat's own server. It sends the subscription
    token and nothing else. --status reads the cache and stays offline.
    """
    feed_mod = _module("feed_mod")
    if args.status:
        st = feed_mod.status()
        if not st["active"]:
            # The fact only, for any reader. Plus is left to the hint: on a
            # terminal, once, and not to someone with a token, who needs
            # `update` rather than a subscription.
            sys.stdout.write(
                "  No feed cached. The catalogue bundled with %s is in use.\n"
                % __version__)
            if hints.allowed("bundled-catalogue", json=args.json) and not _has_plus():
                hints.hint("bundled-catalogue", term.wrap(
                    "Plus gets new scopes the day they are added; the next "
                    "free release gets them too: https://ranwhat.com/pricing",
                    stream=sys.stderr), json=args.json)
            return 0
        when = time.strftime("%Y-%m-%d %H:%M", time.localtime(st["fetched_at"]))
        sys.stdout.write(
            "  Feed %s\n  %d providers, %d scopes\n  fetched %s\n"
            % (st.get("version") or "?", st["providers"], st["scopes"], when))
        return 0

    # Stripped as every other token is: a \r from a CRLF file would make
    # http.client quote the header, token and all, into its error.
    token = (args.token or "").strip() or feed_mod.read_token()
    if not token:
        sys.stderr.write(
            "  No token. Set RANWHAT_TOKEN, or pass --token with --save-token\n"
            "  to store it at ~/.ranwhat/token.\n\n"
            "  Everything else works without one; the feed only keeps the\n"
            "  capability catalogue current. https://ranwhat.com/pricing\n")
        return 1
    if args.token:
        sys.stderr.write(
            "  Warning: a token in the command line is readable by every user\n"
            "  on this machine through the process table, and is written to\n"
            "  your shell history. Prefer RANWHAT_TOKEN.\n\n")

    # save() too: a body can load and still be nested too deep to write.
    try:
        doc = feed_mod.fetch(token)
        feed_mod.save(doc)
    except feed_mod.FeedError as exc:
        sys.stderr.write("  %s\n" % exc)
        return 1

    if args.save_token:
        try:
            path = feed_mod.save_token(token)
        except feed_mod.FeedError as exc:
            sys.stderr.write("  %s\n" % exc)
            return 1
        sys.stdout.write("  Token saved to %s (0600)\n" % path)
    catalog_mod.reset_feed_cache()

    cat = doc.get("catalogue", {})
    sys.stdout.write(
        "  Updated to feed %s\n  %d providers, %d scopes\n"
        % (doc.get("version") or "?", len(cat), sum(len(v) for v in cat.values())))
    return 0


def _has_plus():
    """A token, in the environment or saved, or a cached feed with a scope
    this release lacks: someone a hint about the feed would only repeat
    itself to. Read from this machine; the server is never asked."""
    try:
        return bool(_module("feed_mod").read_token()) or catalog_mod.feed_adds_scopes()
    except Exception:
        # A token file that cannot be read (not UTF-8, say) is still one.
        # The hint is skipped, and nothing fails after a report has printed.
        return True


def _catalogue_hint(result, args):
    """Under a scan or live report on a terminal: how many scopes the
    bundled catalogue could not rate, and that the feed rates new ones
    before the next release does. Not for demo, whose unclassified scope is
    part of the example, and never under --json.

    Only scopes of a provider the bundle rates count, each once however many
    credentials hold it. "generic" (a credential that names no provider, or
    an RFC 7662 issuer) has no catalogue for the feed to add to, and neither
    has a provider ranwhat does not know, so a hint for their scopes would
    sell the feed for something it does not cover."""
    if not any(f["title"] == UNCLASSIFIED for f in result["findings"]):
        return
    unrated = {(r["provider"], r["scope"]) for r in result["scopes"]
               if not r["known"] and catalog_mod.CATALOG.get(r["provider"])}
    if (not unrated or not hints.allowed("unclassified-scopes", json=args.json)
            or _has_plus()):
        return
    n = len(unrated)
    # Pricing, not `update`: without a token, which is who this reaches,
    # update stops at "No token".
    hints.hint("unclassified-scopes", term.wrap(
        "%s not in the catalogue bundled with %s. The Plus feed adds new "
        "scopes between releases: https://ranwhat.com/pricing"
        % ("This scope is" if n == 1 else "These %d scopes are" % n,
           __version__), stream=sys.stderr), json=args.json)


def _finding_json(f):
    """A clean finding as JSON. files, origins and projects are sets in
    memory, and so are sources and read_only; converting only files made
    check --json and clean --json crash on the first secret found, which
    hid every secret from automation. stores, {path: agent}, is in path
    order, so the same history gives the same bytes on every run."""
    out = dict(f)
    for k in ("files", "origins", "projects", "sources", "read_only"):
        v = f.get(k)
        if isinstance(v, (set, frozenset)):
            out[k] = sorted(v) if len(v) > 1 else list(v)
    if isinstance(f.get("stores"), dict):
        out["stores"] = dict(sorted(f["stores"].items()))
    return out


_ESCAPE = json.encoder.encode_basestring_ascii


def _json_float(v):
    if v != v:
        return "NaN"
    if v in (float("inf"), float("-inf")):
        return "Infinity" if v > 0 else "-Infinity"
    return float.__repr__(v)


def _json_key(k):
    if isinstance(k, str):
        return k
    if isinstance(k, float):
        return _json_float(k)
    if k is True or k is False or k is None:
        return json.dumps(k)
    if isinstance(k, int):
        return int.__repr__(k)
    raise TypeError("keys must be str, int, float, bool or None, not %s"
                    % k.__class__.__name__)


def _json_text(doc, pad=""):
    """json.dumps(doc, indent=2), the same text. The standard library
    writes indented JSON in pure Python, one piece at a time, and a
    megabyte of distinct secrets spent a third of a second there."""
    if isinstance(doc, str):
        return _ESCAPE(doc)
    if doc is None or doc is True or doc is False:
        return json.dumps(doc)
    if isinstance(doc, int):
        return int.__repr__(doc)
    if isinstance(doc, float):
        return _json_float(doc)
    inner = pad + "  "
    if isinstance(doc, (list, tuple)):
        if not doc:
            return "[]"
        return "[\n%s%s\n%s]" % (inner, (",\n" + inner).join(
            [_ESCAPE(v) if v.__class__ is str else _json_text(v, inner)
             for v in doc]), pad)
    return _json_object(doc, pad, inner)


def _json_object(doc, pad, inner):
    """_json_text for a dict, and anything else json would refuse."""
    if isinstance(doc, dict):
        if not doc:
            return "{}"
        # A string or a whole number, most values, is written here rather
        # than by a call each.
        deeper = inner + "  "
        return "{\n%s%s\n%s}" % (inner, (",\n" + inner).join(
            [_ESCAPE(k if k.__class__ is str else _json_key(k)) + ": "
             + (_ESCAPE(v) if v.__class__ is str
                else int.__repr__(v) if v.__class__ is int
                # a finding's files: a list of one string, as often as not
                else "[\n%s%s\n%s]" % (deeper, _ESCAPE(v[0]), inner)
                if v.__class__ is list and len(v) == 1 and v[0].__class__ is str
                else _json_text(v, inner))
             for k, v in doc.items()]), pad)
    return json.dumps(doc)            # raises the TypeError json would


def _mask_known(records, known):
    """Mask in each action's evidence every value clean found, `known`.

    watch masks what a call shows to be a secret. A password clean found
    in a tool's output is shown nowhere as one when a later command types
    it with no key beside it (mysql -pPASSWORD), and check listed it by
    its hint in one section and whole in the other."""
    if known and any(record.get("hits") for record in records):
        known = clean_mod.KnownValues(known.values())
        for record in records:
            for hit in record.get("hits", ()):
                hit["evidence"] = known.mask(hit.get("evidence") or "")


def _known(args, step, index=None):
    """Every value clean finds in the transcripts under --root, and in
    every other agent's history, in all of it whatever --days and --source
    say, as a known.Matcher for masking what check and watch print: a
    password read in a session older than the window, or by another agent,
    is no less a password where a command types it. The index keeps them
    between runs (known.py), so only a file new or changed since the last
    run is read for them, with its own line of progress, and not one clean
    has just read for check (`index`, which took what it found)."""
    index = index or known_mod.Index.open(args.root, args.paths)
    return index.update(progress=step(_INDEXING_FIRST if index.first else _INDEXING))


def _remembering(args):
    """For clean: keeps in the index of --root each value it is about to
    mask, before any transcript loses it (known.Index.remember). A copy
    the mask does not reach, typed glued where no rule reads it, is still
    known by the fingerprint the mask keeps, when check or watch next
    index the history. Kept as each mask is made, not once clean returns:
    a review ended by closing its terminal, or a check run while it was
    still open, left the index knowing nothing of what it had masked."""
    def remember(values):
        known_mod.Index.open(args.root, args.paths).remember(values)
    return remember


def _masked_strings(node, mask):
    """node with every string in it, in lists, dicts (their keys too),
    sets and tuples, put through mask: what check and watch print or
    hand on as JSON. A transcript may give an id as an object, keyed by
    whatever it holds."""
    if isinstance(node, str):
        return mask(node)
    if isinstance(node, dict):
        return {(mask(k) if isinstance(k, str) else k): _masked_strings(v, mask)
                for k, v in node.items()}
    if isinstance(node, (list, tuple)):
        return type(node)(_masked_strings(v, mask) for v in node)
    if isinstance(node, (set, frozenset)):
        return type(node)(_masked_strings(v, mask) for v in node)
    return node


def _check(args):
    """Everything this machine can tell us, in one read-only pass.

    `watch` and `clean` answer two halves of the same question and most people
    want both on a first run. Asking them to know that, and to run two
    commands in the right order with the right flags, is knowledge the tool
    should not require. Nothing is modified: masking stays an explicit choice
    under `clean`.
    """
    _agent_defaults(args)
    # Up from the first transcript, and down before anything is printed:
    # reading every transcript for its actions took five seconds on a real
    # history, and showed nothing.
    bar, step = _progress_line(args)
    known = {}
    try:
        # clean's read for secrets first, handing the index what it finds
        # in each transcript, so the index reads only those outside the
        # window or changed since. Indexed first, every transcript was
        # read for its secrets twice on a first run: 50 s on a history
        # clean read in 24.
        index = known_mod.Index.open(args.root, args.paths)
        searched = clean_mod.scan_sources(
            sources=args.sources, root=args.root, paths=args.paths,
            since_days=args.days, apply=False, progress=step(_SECRETS),
            known=known, read=index.take)
        findings = searched.findings
        everywhere = _known(args, step, index)
        unread = {}
        records, counts = watch_mod.scan_sources_counted(
            sources=args.sources, root=args.root,
            state_dir=args.state_dir, since_days=args.days,
            progress=step(_ACTIONS), known=everywhere, paths=args.paths,
            unread=unread)
        _mask_known(records, known)
        # Then every value clean finds anywhere, in all that is printed:
        # each action's evidence was masked as it was read, and this masks
        # what else a record or a finding holds.
        if everywhere:
            records = _masked_strings(records, everywhere.mask)
            findings = _masked_strings(findings, everywhere.mask)
    finally:
        bar.clear()
    # What each half found to read, read or not: one that could read
    # nothing it found says why in its notes, not that nothing was there.
    sources = sum(counts.values()) + sum(unread.values())
    scanned = searched.found

    # Where watch looked, whenever it read nothing, though clean read a
    # prompt history: without it watch's section gave the general hint,
    # not that every session there was older than --days.
    places = None if sources else watch_mod.locations(
        args.sources, root=args.root, state_dir=args.state_dir,
        paths=args.paths, asked=args.source)
    nothing = places is not None and not scanned
    if args.json:
        print(_json_text({
            "days": args.days,
            "actions": records,
            "secrets": [_finding_json(f) for f in findings.values()],
        }))
        return _said_nothing_read(places if nothing else None, args.days)

    from .report import DIM
    # Each section once, then one tail. Printing the two standalone reports
    # back to back gave three footers and two conflicting next steps. With
    # nothing read, watch's section is the whole report above the tail, so
    # it goes under check's own name.
    print(watch_mod.render(records, counts, args.days, footer=False,
                           locations=places,
                           title=_CHECK_TITLE if nothing else watch_mod.TITLE,
                           complete=agents_mod.all_read(args.sources),
                           unread=sum(unread.values())).rstrip("\n"))
    if scanned:
        print(clean_mod.render(findings, searched.counts, [], False, footer=False,
                               advice=False, others=searched.others,
                               read_only=searched.read_only,
                               notes=_clean_notes(args, searched)).rstrip("\n"))
    elif sources:
        # watch read something clean did not: "No secrets found" here
        # would be an all-clear on history nobody searched. With nothing
        # read at all, watch's section has already said where it looked.
        print(_clean_nothing_read(args).rstrip("\n"))
    print()

    cmd = invocation()
    steps = []
    if findings:
        # Bare `clean` on a terminal opens the review over these findings.
        steps.append((["clean"] + _carried(args, "days", "root", "state_dir",
                                           "source", "path"),
                      "review each secret, then mask it"))
    if records:
        # Not `watch --json`: watch masks what a call shows to be a secret,
        # and only check masks too what clean found elsewhere. Suggested
        # here, it printed whole the passwords this report had just hidden.
        steps.append((["check", "--json"]
                      + _carried(args, "days", "root", "state_dir", "source",
                                 "path"),
                      "the actions and secrets, machine readable"))
    # Not `scan profile.json`: nothing writes one, so on a first run it
    # failed with "no such file". demo runs anywhere.
    steps.append((["demo"], "an authority scan, on an example"))
    # clean's "Dry run" line is gone from this report, so say here that
    # nothing was masked, or a reader may assume check handled the secrets.
    tail = ["  " + term.brand("What to do with this"),
            DIM("  Nothing was changed. check only reads."), ""]
    pad = max(len(" ".join(words)) for words, _ in steps)
    rows = ["    %s %-*s  %s" % (cmd, pad, " ".join(words), why)
            for words, why in steps]
    if all(len(r) <= term.width() for r in rows):
        tail += rows
    else:
        # Too narrow for two columns: each reason goes under its command.
        for words, why in steps:
            tail += _command_lines(cmd, words)
            tail += term.wrap(why, indent="      ")
    tail += ["", term.rule("-"), term.FOOTER, ""]
    print("\n".join(tail))
    return 2 if nothing else 0


# The header of check's report when it read nothing: watch's section,
# under check's name, is all of it.
_CHECK_TITLE = ("  ranwhat check  ", "· watch and clean in one pass")


def _notes(args):
    """Sentences on what each agent read this run held that could not be
    read: files that did not parse or are compressed, calls whose
    arguments were not kept."""
    return agents_mod.notes(args.sources)


def _carried(args, *names):
    """This run's own --days, --root, --state-dir, --source and --path, as
    shell words, so a suggested command reads what this one read. Dropped,
    `clean` after `check --days 365 --root X` opened its review on other
    secrets than the ones just listed. Only values other than the default
    are carried, so a plain run suggests plain commands."""
    words = []
    if "days" in names and args.days != DEFAULT_DAYS:
        words += ["--days", str(args.days)]
    if "root" in names and args.root != watch_mod.CLAUDE_PROJECTS:
        words += ["--root", _shell_path(args.root)]
    if "state_dir" in names and args.state_dir:
        words += ["--state-dir", _shell_path(args.state_dir)]
    if "source" in names:
        for source_id in args.source or ():
            words += ["--source", source_id]
    if "path" in names:
        for source_id, path in sorted(args.pointed.items()):
            # ~ there is expanded by ranwhat, whether or not the shell does.
            words += ["--path", "%s=%s" % (source_id, _shell_path(path))]
    return words


def _shell_path(path):
    """A path as one shell word, under ~ when it is inside the home
    directory, which keeps a suggested command short enough to fit. A
    quoted ~ is not expanded, so only what follows it is quoted."""
    home = os.path.expanduser("~")
    if os.name != "nt" and home not in ("", "/", "~"):
        if path == home:
            return "~"
        if path.startswith(home + os.sep):
            return "~/" + _quote(path[len(home) + 1:])
    return _quote(path)


def _command_lines(cmd, words, indent="    "):
    """`cmd` and its words as one line to paste, whatever its length. Each
    shell continues a line differently (a backslash in POSIX shells, ^ in
    cmd, a backtick in PowerShell), so a folded command pastes into one of
    them only. A word is never split."""
    return [indent + " ".join([cmd] + list(words))]


_POINT_ELSEWHERE = {
    "claude-code": watch_mod.ELSEWHERE.replace(" set ", " "),
    "openclaw": "--state-dir PATH or OPENCLAW_STATE_DIR",
}


def _point_elsewhere(source_id):
    """How to point one agent's reader somewhere else."""
    if source_id in _POINT_ELSEWHERE:
        return _POINT_ELSEWHERE[source_id]
    return "--path %s=PATH for %s" % (source_id, agents_mod.name(source_id))


def _said_nothing_read(places, days):
    """For --json, whose [] or zeros cannot tell "read, and nothing found"
    from "nothing there to read": when `places` is not None, one message on
    stderr saying where it looked and how to point it elsewhere, and exit
    status 2. Otherwise 0, and nothing is said."""
    if places is None:
        return 0
    found = sum(p["found"] for p in places)
    # A path is one word, and term.wrap gives a word longer than the line
    # a line of its own, past the edge: each is cut to the line instead,
    # in the middle, as the text report's "Looked in:" cuts it.
    room = term.width() - 2
    if found:
        text = ("No transcripts from the last %s, so nothing was checked. "
                "%d older transcript(s) found; pass a larger --days to read "
                "them." % (watch_mod._days(days), found))
    else:
        where = " or ".join(
            "%s (%s)" % (watch_mod._shown_path(p["path"], room),
                         watch_mod._SOURCE_NAMES.get(p["source"], p["source"]))
            for p in places)
        inner = [p for p in places if p.get("projects")]
        point = ", and ".join(dict.fromkeys(
            _point_elsewhere(p["source"]) for p in places if p not in inner))
        text = "No transcripts found in %s, so nothing was checked." % where
        text += "".join(" " + watch_mod.projects_hint(p, room) for p in inner)
        if point:
            text += " Point it elsewhere with %s." % point
    sys.stderr.write("\n".join(term.wrap(text)) + "\n")
    return 2


def _clean_nothing_read(args):
    """clean's section for a run with no transcript to read. clean.render
    says "No secrets found" for that, an all-clear on nothing read, so its
    header is followed by where it looked instead, in watch's words."""
    from .report import BOLD, DIM
    width = term.width()
    title, tagline = clean_mod._TITLE, clean_mod._TAGLINE
    if len(title + tagline) <= width:
        L = ["", BOLD(title) + DIM(tagline)]
    else:
        L = ["", BOLD(title.rstrip()), DIM("  " + tagline[2:])]
    L += [DIM(term.rule("-")), "  0 transcript(s) scanned", ""]
    places = watch_mod.locations(args.sources, root=args.root,
                                 state_dir=args.state_dir, paths=args.paths,
                                 asked=args.source)
    return "\n".join(L + watch_mod._nothing_read(args.days, places, width))


# What each pass over the transcripts says while it runs, the same words
# for the same pass in every command: the read for the values clean finds,
# kept in the index (on a first run every transcript, and later only those
# new or changed), watch's read for actions, and clean's for secrets. Each
# its own, so a count going back to 1 reads as the next pass, not a restart.
_INDEXING = "indexing secrets"
_INDEXING_FIRST = "indexing secrets (first run)"
_ACTIONS = "checking actions"
_SECRETS = "looking for secrets"


def _progress_line(args):
    """One status line on stderr, for check, watch and clean: (the line,
    a function that gives each pass its progress callback, in its words).
    Never with --json. It never names the transcript: its directory is an
    internal slug of a project path, no use to a reader and longer than
    most terminals."""
    bar = term.Progress(sys.stderr)

    def step(words):
        def progress(i, total, path):
            if not args.json:
                bar.update("  %s %d/%d" % (words, i, total))
        return progress
    return bar, step


def _takes_no_path(command, path):
    """The error for a path given to a command other than scan. For one
    that reads transcripts, which flag reads that path: --root, or --root
    with its projects directory when that is where the transcripts are."""
    said = "%s takes no path" % command
    if command not in ("check", "watch", "clean"):
        return said
    root = _root_for(path)
    if os.path.isdir(root) and watch_mod._transcripts(root):
        if _same_file(root, path):
            return ("%s. To read the transcripts in %s, pass --root %s"
                    % (said, path, _quote(root)))
        return ("%s. To read the transcripts in %s, pass the projects directory "
                "that holds them: --root %s" % (said, path, _quote(root)))
    # Nothing there or near it is a transcript: a project's source, a path
    # that does not exist, an empty project directory. Pointed at with
    # --root, each read nothing and exited 2, so the step offered is the
    # projects directory a run with no path reads, when that holds any.
    none = "%s. No Claude Code transcripts are in or near %s" % (said, path)
    default = watch_mod.CLAUDE_PROJECTS
    if _same_file(default, path):
        return none + ", where Claude Code keeps them."
    if os.path.isdir(default) and watch_mod._transcripts(default):
        return none + ". Run %s with no path to read the ones in %s." % (
            command, _shell_path(default))
    return none + ", nor in %s, where Claude Code keeps them." % _shell_path(default)


def _holds_projects(path):
    """Whether path is a projects directory: transcripts in the directories
    under it. A session's directory has them too, in its subagents/."""
    own = os.path.join(path, "subagents")
    return any(os.path.dirname(t) != own for t in watch_mod._transcripts(path))


# How far above a path the projects directory holding it may be: a
# workflow's subagent sits at <project>/<session>/subagents/workflows/<run>.
_ROOT_ABOVE = 6


def _root_for(path):
    """The --root that reads the transcripts at path. --root takes the
    projects directory and reads <root>/*/*.jsonl, so for a project's
    directory, a session's or a transcript, it is the one above that holds
    it, and for a home or config directory the projects directory inside.
    Suggested as given, each read nothing and said "No transcripts found"."""
    full = os.path.abspath(path)
    if os.path.isfile(full):
        project, _session = watch_mod.transcript_place(full)
        parts = full.split(os.sep)[:-1]
        if not full.endswith(".jsonl") or project not in parts:
            return path
        at = len(parts) - 1 - parts[::-1].index(project)     # the last one
        root = os.sep.join(parts[:at]) or os.sep
        return root if _holds_projects(root) else path
    if not os.path.isdir(full):
        return path
    if _holds_projects(full):
        return path
    for inner in (os.path.join(full, "projects"),
                  os.path.join(full, ".claude", "projects")):
        if _holds_projects(inner):
            return inner
    above = full
    for _ in range(_ROOT_ABOVE):
        parent = os.path.dirname(above)
        if parent == above:
            break
        above = parent
        if any(_inside(os.path.abspath(t), full) for t in watch_mod._transcripts(above)):
            return above
    return path


def _agent_flags(p, args):
    """--source, --path, --root and --state-dir as every command that
    reads agent history takes them (design 4.1):

    - args.sources: the ids to read, in registry order (default all);
    - args.paths: {id: path} for each agent pointed somewhere, Claude
      Code's and OpenClaw's included;
    - args.pointed: the ones --path pointed, but for those two, which a
      suggested command carries as --root and --state-dir;
    - args.root and args.state_dir, as before.

    --root and --state-dir stay as the names for --path claude-code= and
    --path openclaw=, so giving one and its --path both is an error, as is
    an agent ranwhat does not know, and a second --path for one agent."""
    paths = {}
    for given in args.path or ():
        source_id, sep, path = given.partition("=")
        if not sep or not source_id or not path:
            p.error("--path takes ID=PATH, such as --path codex=~/.codex")
        if source_id not in sources_mod.REGISTRY:
            p.error("--path %s=...: there is no agent %r. ranwhat sources "
                    "lists them: %s" % (source_id, source_id,
                                        ", ".join(sources_mod.ids())))
        if source_id in paths:
            p.error("--path %s= is given twice; give one" % source_id)
        paths[source_id] = os.path.expanduser(path)
    for flag, name, source_id in (("--root", "root", "claude-code"),
                                  ("--state-dir", "state_dir", "openclaw")):
        if getattr(args, name) is not None and source_id in paths:
            p.error("%s and --path %s= both point %s elsewhere; give one"
                    % (flag, source_id, agents_mod.name(source_id)))
        # Expanded as --path is: --root=~/x, a quoted ~, and any ~ in cmd
        # or PowerShell reach ranwhat as written, and read nothing.
        if getattr(args, name):
            setattr(args, name, os.path.expanduser(getattr(args, name)))
    args.path_ids = tuple(paths)
    args.pointed = {i: v for i, v in paths.items() if i not in agents_mod.PORTED}
    args.root = args.root or paths.get("claude-code") or watch_mod.CLAUDE_PROJECTS
    args.state_dir = args.state_dir or paths.get("openclaw")
    paths["claude-code"] = args.root
    if args.state_dir:
        paths["openclaw"] = args.state_dir
    args.paths = paths
    args.sources = tuple(i for i in sources_mod.ids()
                         if not args.source or i in args.source)


def _agent_defaults(args):
    """What _agent_flags sets, for a Namespace made some other way (a
    test's, or a caller's): every agent, each in its default place."""
    paths = {"claude-code": args.root}
    if getattr(args, "state_dir", None):
        paths["openclaw"] = args.state_dir
    for name, value in (("source", None), ("path", []), ("path_ids", ()),
                        ("pointed", {}), ("paths", paths),
                        ("sources", tuple(sources_mod.ids()))):
        if not hasattr(args, name):
            setattr(args, name, value)


def _sentence(text):
    """text as a sentence: a capital first, a full stop last."""
    text = text.strip()
    if not text:
        return text
    text = text[0].upper() + text[1:]
    return text if text.endswith((".", "!", "?")) else text + "."


def _clean_notes(args, searched):
    """_notes, and for each agent that holds a finding what its adapter
    says of it (clean_note), and for each whose files were masked what to
    do next (mask_note): an editor that rewrites the file from memory, a
    copy kept in the agent's cloud."""
    notes = _notes(args)
    holding = {i for f in searched.findings.values() for i in f.get("sources", ())}
    masked = {searched.stores[path].source for path in searched.changed
              if path in searched.stores}
    for source in agents_mod.searched(args.sources):
        if source.id in holding and getattr(source, "clean_note", ""):
            notes.append(_sentence(source.clean_note))
        if source.id in masked and getattr(source, "mask_note", ""):
            notes.append(_sentence(source.mask_note))
    return notes


# What `ranwhat sources` says of what clean does with an agent's files.
_MASKING = {
    "rewrite": "clean can mask it",
    "read-only": "clean reads it only; it never changes these files",
    "mixed": "clean can mask %s; %s read only",
    "not searched": "clean does not search it for secrets yet",
}


def _source_entry(source, args):
    """What `ranwhat sources --json` says of one adapter."""
    flag = "--path"
    if source.id == "claude-code":
        override = args.root if args.root != watch_mod.CLAUDE_PROJECTS else None
        flag = "--path" if "claude-code" in (args.path_ids or ()) else "--root"
    elif source.id == "openclaw":
        override = args.state_dir
        flag = "--path" if "openclaw" in (args.path_ids or ()) else "--state-dir"
    else:
        override = args.paths.get(source.id)
    locations, stores = agents_mod.discover(source, override)
    for loc in locations:
        if loc.how == "--path":
            loc.how = flag
    transcripts = agents_mod.transcripts(stores)
    read_only = [s for s in stores if s.masking == "read-only"]
    if not source.searched:
        masking = "not searched"
    elif source.read_only or (stores and len(read_only) == len(stores)):
        # What clean can do with an agent whose every store is read-only
        # does not wait on finding one: the site says it of OpenClaw.
        masking = "read-only"
    elif read_only:
        masking = "mixed"
    else:
        masking = "rewrite"
    notes = list(agents_mod.notes([source.id], {source.id: locations}))
    return {"id": source.id, "name": source.name,
            "status": "found" if stores else "not found",
            "locations": [{"path": loc.path, "how": loc.how,
                           "exists": loc.exists, "found": loc.found}
                          for loc in locations],
            "unit": source.unit,
            "transcripts": len(transcripts),
            "other_files": len(stores) - len(transcripts),
            "read_only_files": len(read_only),
            "masking": masking, "path_means": source.path_means,
            "counts": dict(source.counts), "unreadable": dict(source.unreadable),
            "notes": notes}


def _sources(args):
    """ranwhat sources: every agent ranwhat knows, in registry order:
    where it looked for each, whether it found any history and how much,
    and what clean can do with it. Then the agents with nothing on this
    machine to read, and the one that is next."""
    entries = [_source_entry(source, args) for source in agents_mod.chosen(
        args.sources)]
    if not args.source:
        entries += [{"id": None, "name": name, "status": "cloud only",
                     "note": note} for name, note in sources_mod.CLOUD_ONLY]
        entries += [{"id": None, "name": name, "status": "next", "note": note}
                    for name, note in sources_mod.NEXT]
    if args.json:
        print(_json_text(entries))
        return 0
    from .report import BOLD, DIM, GRN
    width = term.width()
    title, tagline = "  ranwhat sources  ", "· the agents ranwhat reads"
    if len(title + tagline) <= width:
        L = ["", BOLD(title) + DIM(tagline)]
    else:
        L = ["", BOLD(title.rstrip()), DIM("  " + tagline[2:])]
    L += [DIM(term.rule("-")), ""]
    for entry in entries:
        if entry["id"] is None:
            continue
        if entry["status"] == "found":
            amount = agents_mod.amount({entry["id"]: entry["transcripts"]},
                                       {entry["id"]: entry["other_files"]})
            status = GRN("found") + ", " + amount.split(": ", 1)[1]
        else:
            status = DIM("not found")
        head = "  %s (%s): " % (entry["name"], entry["id"])
        L += _status_lines(head, status, width)
        for loc in entry["locations"]:
            room = max(16, width - 8 - len(loc["how"]))
            L.append(DIM(_fit_line("    %s (%s)" % (
                watch_mod._shown_path(loc["path"], room), loc["how"]), width)))
        masking = entry["masking"]
        what = _MASKING[masking]
        if masking == "mixed":
            n = entry["transcripts"] + entry["other_files"]
            what = what % (_n_files(n - entry["read_only_files"]),
                           _n_files(entry["read_only_files"]) + " "
                           + ("is" if entry["read_only_files"] == 1 else "are"))
        if entry["status"] == "found" or masking == "not searched":
            L += [DIM(line) for line in term.wrap(what, indent="    ")]
        for note in entry["notes"]:
            # A path in a note as the location lines show it, under ~ and
            # cut to the line: term.wrap gives a word longer than the line
            # a line of its own, past the edge.
            note = " ".join(watch_mod._shown_path(word, width - 4)
                            for word in note.split())
            L += [DIM(line) for line in term.wrap(note, indent="    ")]
        L.append("")
    for status, heading in (("cloud only", "Cloud only, nothing on this "
                                          "machine to read:"),
                            ("next", "Next:")):
        listed = [e for e in entries if e["id"] is None and e["status"] == status]
        if listed:
            L += term.wrap(heading)
            for entry in listed:
                L += term.wrap("%s: %s" % (entry["name"], entry["note"]),
                               indent="      ", first="    ")
            L.append("")
    L += term.wrap("Point an agent elsewhere with --path ID=PATH; --source "
                   "ID reads only that one.")
    L += ["", DIM(term.rule("-")), DIM(term.FOOTER), ""]
    print("\n".join(L))
    return 0


def _n_files(n):
    return agents_mod.plural(n, "file")


def _fit_line(text, width):
    return watch_mod._fit(text, width)


def _status_lines(head, status, width):
    """An agent's name and what was found of it, on one line when they
    fit, else the status on the line under the name."""
    plain = re.sub(r"\033\[[0-9;]*m", "", status)
    if len(head) + len(plain) <= width:
        return [head + status]
    return [_fit_line(head.rstrip().rstrip(":") + ":", width), "    " + status]


def main(argv=None):
    """The command line. A report piped into head or a pager that closes
    early ended in a BrokenPipeError traceback; it ends quietly instead.
    And a character the terminal cannot show (a lone half of a surrogate
    pair a transcript spelled, or anything past ASCII on a terminal that
    takes only that) is shown as "?" rather than ending the run."""
    for stream in (sys.stdout, sys.stderr):
        try:
            if stream.errors == "strict":
                stream.reconfigure(errors="replace")
        except (AttributeError, ValueError, io.UnsupportedOperation):
            pass                      # not a text stream we may change
    try:
        with agents_mod.run():
            status = _main(argv)
        sys.stdout.flush()            # a closed pipe says so here, not at exit
        return status
    except OSError as error:
        if not _closed_pipe(error):
            raise
        _quiet_stdout()
        return 1


def _closed_pipe(error, windows=os.name == "nt"):
    """Whether error is a write to a pipe whose reader has gone: a
    BrokenPipeError, or on Windows an OSError with EINVAL that names no
    file. Windows gives EINVAL too for a file name holding ? * < > |, and
    taken for the pipe, that error ended the run with nothing said."""
    return isinstance(error, BrokenPipeError) or (
        windows and error.errno == errno.EINVAL and error.filename is None)


def _quiet_stdout():
    """Send what is left to say to nowhere, so Python's own flush at exit
    meets no closed pipe either."""
    try:
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())
    except (AttributeError, OSError, ValueError, io.UnsupportedOperation):
        pass


def _main(argv=None):
    # The opt-out is said where someone who saw a hint would look for it.
    p = argparse.ArgumentParser(prog="ranwhat",
                                description=TAGLINE + " " + NETWORK,
                                epilog="RANWHAT_NO_HINTS=1 turns off the dim "
                                       "one-line hints some commands print on "
                                       "a terminal. None is printed with --json.")
    p.add_argument("command", nargs="?",
                   choices=["check", "demo", "scan", "live", "watch",
                            "clean", "sources", "update"])
    p.add_argument("profile", nargs="?", help="path to a profile JSON")
    p.add_argument("--json", action="store_true", help="emit raw JSON")
    p.add_argument("--html", metavar="PATH",
                   help="demo, scan, live: also write the report as HTML")
    for name in _PROVIDER_NAMES:
        p.add_argument("--%s" % name, metavar="TOKEN",
                       help="%s credential. Prefer RANWHAT_%s_TOKEN in the "
                            "environment: a value passed here is visible to "
                            "every user on this machine via ps, and lands in "
                            "your shell history."
                            % (name, name.upper()))
    p.add_argument("--controls", metavar="PATH",
                   help="controls JSON to pair with live introspection")
    p.add_argument("--pull-usage", action="store_true",
                   help="pull real usage data to establish which granted "
                        "permissions were actually exercised (read-only)")
    p.add_argument("--aws-profile", metavar="NAME", help="AWS CLI profile for usage pull")
    p.add_argument("--github-org", metavar="ORG", help="GitHub org for audit-log usage pull")
    p.add_argument("--window-days", type=int, default=_DEFAULT_WINDOW_DAYS,
                   help="usage lookback window (default 90)")
    p.add_argument("--days", type=int, default=DEFAULT_DAYS,
                   help="check, watch, clean: how far back to read local "
                        "agent history (default 30)")
    p.add_argument("--root", metavar="PATH",
                   help="check, watch, clean: Claude Code transcript directory "
                        "(default ~/.claude/projects); the same as "
                        "--path claude-code=PATH")
    p.add_argument("--state-dir", metavar="PATH",
                   help="check, watch, clean: OpenClaw state directory "
                        "(default ~/.openclaw); the same as "
                        "--path openclaw=PATH")
    p.add_argument("--source", action="append", choices=list(sources_mod.ids()),
                   metavar="ID",
                   help="check, watch, clean, sources: read only this agent "
                        "(repeatable; default every one). IDs: %s"
                        % ", ".join(sources_mod.ids()))
    p.add_argument("--path", action="append", metavar="ID=PATH", default=[],
                   help="check, watch, clean, sources: read this agent's "
                        "history from PATH instead of its default place "
                        "(repeatable, one per agent; ranwhat sources says "
                        "what each PATH is)")
    p.add_argument("--apply", action="store_true",
                   help="clean: mask everything found without asking. Without "
                        "it, clean reports and then opens a review session.")
    p.add_argument("--no-interactive", action="store_true",
                   help="clean: report and exit instead of opening the review "
                        "session")
    p.add_argument("--token", metavar="TOKEN",
                   help="update: subscription token. Prefer RANWHAT_TOKEN in "
                        "the environment, or run update once to save it: a "
                        "value passed here is visible to every user on this "
                        "machine via ps, and lands in your shell history.")
    p.add_argument("--save-token", action="store_true",
                   help="update: write the token to ~/.ranwhat/token (0600) "
                        "so later runs need no flag")
    p.add_argument("--status", action="store_true",
                   help="update: report the cached feed and exit without "
                        "touching the network")
    # Intermixed, so a flag may come before scan's path: on Python 3.9,
    # `scan --json profile.json` ended the positionals at --json and then
    # refused the path as an unrecognized argument.
    args = p.parse_intermixed_args(argv)

    if args.profile is not None and args.command != "scan":
        # Taken and ignored, `check DIR` reported on the default history as
        # if it were DIR, and `clean DIR --apply` would have masked it.
        p.error(_takes_no_path(args.command, args.profile))

    if args.html and args.command not in _HTML_COMMANDS:
        # Accepted and ignored, it exited 0 and left no file behind.
        p.error("--html is only for demo, scan and live"
                + ("; %s has no HTML report" % args.command
                   if args.command else ""))

    if args.command is None:
        _overview(p)
        return 0

    if args.command == "update":
        return _update(args)

    if args.days is not None and args.days < 1:
        p.error("--days must be at least 1")
    if args.window_days is not None and args.window_days < 1:
        p.error("--window-days must be at least 1")

    _agent_flags(p, args)
    for source in sources_mod.sources():
        source.reset()              # each run counts what it could not read

    if args.command == "sources":
        return _sources(args)

    # After the --days check: check dispatched first scanned the future for
    # --days -1 and printed an all-clear.
    if args.command == "check":
        if args.apply:
            # check is read-only by contract. Accepting the flag and ignoring
            # it printed "Run with --apply" back at someone who just had.
            p.error("check never changes anything; mask with `clean`")
        return _check(args)

    if args.command == "clean":
        bar, step = _progress_line(args)
        known = {}            # for the review: never written anywhere
        remember = _remembering(args)
        try:
            searched = clean_mod.scan_sources(
                sources=args.sources, root=args.root, paths=args.paths,
                since_days=args.days, apply=args.apply,
                progress=step(_SECRETS), known=known,
                remember=remember if args.apply else None)
        finally:
            bar.clear()
        findings, scanned, changed = (searched.findings, searched.scanned,
                                      searched.changed)
        # Zero found is not "No secrets found": it is a wrong --root, a
        # fresh machine, or history kept somewhere else.
        places = None if searched.found else watch_mod.locations(
            args.sources, root=args.root, state_dir=args.state_dir,
            paths=args.paths, asked=args.source)
        # Every value found is masked in what clean prints, as check masks
        # it: one may sit in another finding's key name, in the path
        # another was read from, or in a transcript's name, and the report,
        # --json and the review's show N printed it whole there.
        shown = known_mod.Matcher.of(known.values()).mask if known else None
        if args.json:
            doc = {"scanned": scanned, "applied": args.apply, "changed": changed,
                   "findings": [_finding_json(f) for f in findings.values()]}
            if args.apply:
                # The files holding a finding that were left as they are:
                # {path: "read-only", "in use", ...}.
                doc["not_masked"] = dict(
                    [(path, "read-only") for path in searched.read_only]
                    + [(path, why) for path, (_i, why) in searched.skipped.items()])
            print(_json_text(_masked_strings(doc, shown) if shown else doc))
            return _said_nothing_read(places, args.days)
        if places is not None:
            print(_clean_nothing_read(args))
            return 2
        print(clean_mod.render(findings, searched.counts, changed, args.apply,
                               shown=shown, others=searched.others,
                               read_only=searched.read_only,
                               skipped=searched.skipped,
                               notes=_clean_notes(args, searched)))
        # The findings are already in memory; making someone re-scan a
        # large history just to act on what they read is wasteful.
        if (findings and not args.apply and not args.no_interactive
                and sys.stdin.isatty()):
            clean_mod.review(findings, scanned, values=known,
                             paths=(clean_mod.discover(args.root, args.days)
                                    if "claude-code" in args.sources else []),
                             shown=shown, remember=remember,
                             stores=searched.stores)
        return 0

    if args.command == "watch":
        sources = args.sources
        bar, step = _progress_line(args)
        try:
            everywhere = _known(args, step)
            unread = {}
            records, counts = watch_mod.scan_sources_counted(
                sources=sources, root=args.root, state_dir=args.state_dir,
                since_days=args.days, progress=step(_ACTIONS), known=everywhere,
                paths=args.paths, unread=unread)
            if everywhere:
                records = _masked_strings(records, everywhere.mask)
        finally:
            bar.clear()
        n = sum(counts.values()) + sum(unread.values())
        places = None if n else watch_mod.locations(
            sources, root=args.root, state_dir=args.state_dir, paths=args.paths,
            asked=args.source)
        if args.json:
            print(_json_text(records))
            return _said_nothing_read(places, args.days)
        print(watch_mod.render(records, counts, args.days, locations=places,
                               notes=_notes(args),
                               complete=agents_mod.all_read(args.sources),
                               unread=sum(unread.values())))
        return 2 if places is not None else 0

    if args.command == "demo":
        _emit(run_scan(_bundled("support-copilot.json")), args)
        return 0

    if args.command == "scan":
        if not args.profile:
            p.error("scan requires a profile path")
        profile, online = _load(args.profile), False
        if args.pull_usage:
            profile, online = _pull_usage(profile, args)
        result = run_scan(profile, args.profile, pulled=args.pull_usage)
        _emit(result, args, online=online)
        _catalogue_hint(result, args)
        return 0

    # live
    creds, errors = [], []
    introspect = _module("introspect")
    for name, fn in introspect.PROVIDERS.items():
        token = _token(args, name)
        if not token:
            continue
        try:
            creds.append(fn(token))
        except introspect.IntrospectionError as e:
            errors.append("%s: %s" % (name, e))
    if not creds:
        print("No credentials introspected. %s" % ("; ".join(errors) or
              "Set RANWHAT_<PROVIDER>_TOKEN, or pass --google/--github/"
              "--slack/--stripe."),
              file=sys.stderr)
        return 1
    for e in errors:
        print("  warning: %s" % e, file=sys.stderr)

    controls = _load(args.controls) if args.controls else {}
    profile = {"agent": "live-scan", "credentials": creds, "controls": controls}
    if args.pull_usage:
        profile, _ = _pull_usage(profile, args)
    result = run_scan(profile, pulled=args.pull_usage)
    _emit(result, args, online=True)
    _catalogue_hint(result, args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
