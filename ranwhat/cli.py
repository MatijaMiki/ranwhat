"""ranwhat CLI.

  ranwhat demo                        run against the bundled example
  ranwhat scan profile.json           score a declared profile
  ranwhat live --google $TOK ...      introspect real credentials locally
  ranwhat scan profile.json --html out.html

Live mode never transmits a token anywhere except the issuing provider.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import shutil
import sys
import time

from .score import scan as _run_scan, ProfileError
from .report import render
from . import introspect
from . import usage as usage_mod
from . import watch as watch_mod
from . import clean as clean_mod
from . import feed as feed_mod
from . import catalog as catalog_mod
from . import term


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


def run_scan(profile, path=None):
    """Score a profile, turning a malformed one into a message. `path` is the
    file it came from, for advice that has to name it."""
    try:
        return _run_scan(profile, path=path)
    except ProfileError as e:
        raise SystemExit("ranwhat: %s" % e)


def _load(path):
    """Read a profile, failing with a message rather than a traceback."""
    try:
        with open(path) as fh:
            return json.load(fh)
    except FileNotFoundError:
        raise SystemExit("ranwhat: no such file: %s" % path)
    except IsADirectoryError:
        raise SystemExit("ranwhat: not a file: %s" % path)
    except PermissionError:
        raise SystemExit("ranwhat: cannot read (permission denied): %s" % path)
    except ValueError as e:
        raise SystemExit("ranwhat: %s is not valid JSON (%s)" % (path, e))


def _bundled(name):
    """Load data shipped inside the package."""
    try:
        from importlib.resources import files
        return json.loads(files("ranwhat").joinpath("demo", name).read_text())
    except Exception:
        here = os.path.dirname(os.path.abspath(__file__))
        return _load(os.path.join(here, "demo", name))


def _pull_usage(profile, args):
    """Best-effort usage pulls. A provider that cannot report usage is left
    explicitly unverified rather than silently empty.

    Returns the profile and whether any provider was asked, which decides
    whether the report may say nothing was transmitted."""
    results, asked = {}, False
    providers = {c.get("provider") for c in profile.get("credentials", [])}

    for provider in sorted(providers & set(usage_mod.PULLS)):
        token = _token(args, provider)
        # aws reads the AWS CLI's own credentials; every other pull needs one.
        if provider != "aws" and not token:
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
            print("  usage: %-8s %s" % (provider, results[provider][1].level),
                  file=sys.stderr)
        except introspect.IntrospectionError as e:
            print("  usage: %-8s unavailable (%s)" % (provider, e), file=sys.stderr)

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
        print("  html report: %s\n" % args.html)


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
    ("check", "everything on this machine worth knowing about"),
    ("watch", "what your agents already ran on this machine"),
    ("clean", "credentials sitting in plaintext in agent transcripts"),
    ("scan", "the authority a set of credentials carries"),
    ("live", "the same, asked of each token's own provider"),
    ("demo", "see the output without setting anything up"),
    ("update", "refresh the capability catalogue (needs a subscription)"),
)


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


def _quote(arg):
    """One argument, quoted for the shell the user is in."""
    if os.name == "nt":
        import subprocess
        return subprocess.list2cmdline([arg])
    return shlex.quote(arg)


def _same_file(a, b):
    return os.path.normcase(os.path.abspath(a)) == os.path.normcase(
        os.path.abspath(b))


def _launches(found, executable):
    """Whether running `found` starts this interpreter.

    macOS's /usr/bin/python3 is not a link but a launcher for the Command Line
    Tools' copy, so no comparison of paths can tell; only asking it can. POSIX
    only: on Windows, python3 on PATH may be the Store alias."""
    if os.name == "nt":
        return False
    import subprocess
    probe = subprocess.run(
        [found, "-I", "-S", "-c", "import sys; sys.stdout.write(sys.executable)"],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL, timeout=3, check=False)
    started = probe.stdout.decode("utf-8", "replace").strip()
    return bool(started) and _same_file(started, executable)


def _python_m(executable, path):
    """`python -m ranwhat` is running a checkout or venv, not the PyPI build.

    Spelled with the bare name when that name, looked up on the user's PATH,
    starts this interpreter, and with the full path otherwise. python3 is
    tried after the interpreter's own name, since python3.12 may be what ran
    but python3 is what people type."""
    for name in dict.fromkeys((os.path.basename(executable), "python3")):
        try:
            found = shutil.which(name, path=path)
            # abspath, not realpath: a venv's bin/python is a symlink to the
            # base interpreter, which does not have ranwhat.
            if found and (_same_file(found, executable)
                          or _launches(found, executable)):
                return "%s -m ranwhat" % name
        except Exception:
            continue          # a launcher that hangs or fails is not ours
    return "%s -m ranwhat" % _quote(executable)


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
    if args.status:
        st = feed_mod.status()
        if not st["active"]:
            sys.stdout.write(
                "  No feed cached. The bundled catalogue is in use.\n"
                "  A subscription adds providers as they ship new scopes:\n"
                "  https://ranwhat.com/pricing\n")
            return 0
        when = time.strftime("%Y-%m-%d %H:%M", time.localtime(st["fetched_at"]))
        sys.stdout.write(
            "  Feed %s\n  %d providers, %d scopes\n  fetched %s\n"
            % (st.get("version") or "?", st["providers"], st["scopes"], when))
        return 0

    token = args.token or feed_mod.read_token()
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

    try:
        doc = feed_mod.fetch(token)
    except feed_mod.FeedError as exc:
        sys.stderr.write("  %s\n" % exc)
        return 1

    feed_mod.save(doc)
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

def _finding_json(f):
    """A clean finding as JSON. files, origins and projects are sets in
    memory; converting only files made check --json and clean --json crash
    on the first secret found, which hid every secret from automation."""
    return dict(f, **{k: sorted(f[k]) for k in ("files", "origins", "projects")
                      if isinstance(f.get(k), (set, frozenset))})


def _check(args):
    """Everything this machine can tell us, in one read-only pass.

    `watch` and `clean` answer two halves of the same question and most people
    want both on a first run. Asking them to know that, and to run two
    commands in the right order with the right flags, is knowledge the tool
    should not require. Nothing is modified: masking stays an explicit choice
    under `clean`.
    """
    records, sources = watch_mod.scan_sources(
        sources=watch_mod.SOURCES, root=args.root,
        state_dir=args.state_dir, since_days=args.days)

    bar, _progress = _progress_line(args)
    try:
        findings, scanned, _ = clean_mod.scan(
            root=args.root, since_days=args.days, apply=False,
            progress=_progress)
    finally:
        bar.clear()

    if args.json:
        print(json.dumps({
            "days": args.days,
            "actions": records,
            "secrets": [_finding_json(f) for f in findings.values()],
        }, indent=2))
        return 0

    from .report import DIM
    # Each section once, then one tail. Printing the two standalone reports
    # back to back gave three footers and two conflicting next steps.
    print(watch_mod.render(records, sources, args.days,
                           footer=False).rstrip("\n"))
    print(clean_mod.render(findings, scanned, 0, False,
                           footer=False, advice=False).rstrip("\n"))
    print()

    cmd = invocation()
    steps = []
    if findings:
        # Bare `clean` on a terminal opens the review over these findings.
        steps.append(("clean", "review each secret, then mask it"))
    if records:
        steps.append(("watch --json", "the actions, machine readable"))
    # Not `scan profile.json`: nothing writes one, so on a first run it
    # failed with "no such file". demo runs anywhere.
    steps.append(("demo", "an authority scan, on an example"))
    pad = max(len(c) for c, _ in steps)
    # clean's "Dry run" line is gone from this report, so say here that
    # nothing was masked, or a reader may assume check handled the secrets.
    tail = ["  " + term.brand("What to do with this"),
            DIM("  Nothing was changed. check only reads."), ""]
    rows = ["    %s %-*s  %s" % (cmd, pad, c, why) for c, why in steps]
    if all(len(r) <= term.width() for r in rows):
        tail += rows
    else:
        # Too narrow for two columns: each reason goes under its command.
        for c, why in steps:
            tail.append("    %s %s" % (cmd, c))
            tail += term.wrap(why, indent="      ")
    tail += ["", term.rule("-"), term.FOOTER, ""]
    print("\n".join(tail))
    return 0

def _progress_line(args):
    """One status line for check and clean, in the same words. It never names
    the transcript: its directory is an internal slug of a project path, no
    use to a reader and longer than most terminals."""
    bar = term.Progress(sys.stderr)

    def progress(i, total, path):
        if not args.json:
            bar.update("  reading transcripts %d/%d" % (i, total))
    return bar, progress


def main(argv=None):
    p = argparse.ArgumentParser(prog="ranwhat",
                                description=TAGLINE + " " + NETWORK)
    p.add_argument("command", nargs="?",
                   choices=["check", "demo", "scan", "live", "watch",
                            "clean", "update"])
    p.add_argument("profile", nargs="?", help="path to a profile JSON")
    p.add_argument("--json", action="store_true", help="emit raw JSON")
    p.add_argument("--html", metavar="PATH", help="also write an HTML report")
    for name in introspect.PROVIDERS:
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
    p.add_argument("--window-days", type=int, default=usage_mod.DEFAULT_WINDOW_DAYS,
                   help="usage lookback window (default 90)")
    p.add_argument("--days", type=int, default=30,
                   help="check, watch, clean: how far back to read local "
                        "agent history (default 30)")
    p.add_argument("--root", metavar="PATH", default=watch_mod.CLAUDE_PROJECTS,
                   help="check, watch, clean: Claude Code transcript directory")
    p.add_argument("--state-dir", metavar="PATH",
                   help="check, watch: OpenClaw state directory "
                        "(default ~/.openclaw)")
    p.add_argument("--source", action="append", choices=list(watch_mod.SOURCES),
                   help="watch: limit to a source (repeatable; default all)")
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
    args = p.parse_args(argv)

    if args.command is None:
        _overview(p)
        return 0

    if args.command == "update":
        return _update(args)

    if args.days is not None and args.days < 1:
        p.error("--days must be at least 1")
    if args.window_days is not None and args.window_days < 1:
        p.error("--window-days must be at least 1")

    # After the --days check: check dispatched first scanned the future for
    # --days -1 and printed an all-clear.
    if args.command == "check":
        if args.apply:
            # check is read-only by contract. Accepting the flag and ignoring
            # it printed "Run with --apply" back at someone who just had.
            p.error("check never changes anything; mask with `clean`")
        return _check(args)

    if args.command == "clean":
        bar, _progress = _progress_line(args)
        try:
            findings, scanned, changed = clean_mod.scan(
                root=args.root, since_days=args.days, apply=args.apply,
                progress=_progress)
        finally:
            bar.clear()
        if args.json:
            print(json.dumps({"scanned": scanned, "applied": args.apply,
                              "changed": changed,
                              "findings": [_finding_json(f)
                                           for f in findings.values()]}, indent=2))
        else:
            print(clean_mod.render(findings, scanned, changed, args.apply))
            # The findings are already in memory; making someone re-scan a
            # large history just to act on what they read is wasteful.
            if (findings and not args.apply and not args.no_interactive
                    and sys.stdin.isatty()):
                clean_mod.review(findings, scanned)
        return 0

    if args.command == "watch":
        records, n = watch_mod.scan_sources(
            sources=args.source or watch_mod.SOURCES,
            root=args.root, state_dir=args.state_dir, since_days=args.days)
        if args.json:
            print(json.dumps(records, indent=2))
        else:
            print(watch_mod.render(records, n, args.days))
        return 0

    if args.command == "demo":
        _emit(run_scan(_bundled("support-copilot.json")), args)
        return 0

    if args.command == "scan":
        if not args.profile:
            p.error("scan requires a profile path")
        profile, online = _load(args.profile), False
        if args.pull_usage:
            profile, online = _pull_usage(profile, args)
        _emit(run_scan(profile, args.profile), args, online=online)
        return 0

    # live
    creds, errors = [], []
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
    _emit(run_scan(profile), args, online=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
