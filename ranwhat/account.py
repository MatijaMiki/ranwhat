"""Linking this machine to a ranwhat.com account: login, whoami, logout.

Three opt-in commands, and with `update` the only ones that talk to
ranwhat's own server. None of the others needs an account. check, watch,
clean and sources never load this module or the HTTP stack it uses. scan,
live and `update --status` may load it, with feed.py, to read the plan
cache below for the hints about Plus (cli._has_plus), and ask the server
nothing.

  login   RFC 8628's device authorization grant, as `gh auth login` does
          it. The server hands out a device code to poll with and a user
          code for a person to type; this prints the user code and
          https://ranwhat.com/device, and the person types the code there,
          signed in, and approves. The code is never carried in a link:
          none is printed or opened with it, so a link someone else sends
          cannot approve a terminal in one click. The first poll after
          approval returns this machine's own token, which is saved where
          `update` reads it (0600, never written through a symlink). With
          --force it replaces a token already saved there, and then asks
          the server to revoke the one it replaced, as logout would.
  whoami  the account, organisation and plan a token belongs to.
  logout  asks the server to revoke this machine's token, then deletes it;
          when the server cannot say it did, keeps it and exits 1, and
          with --local deletes it without asking.

What is sent: client_id=ranwhat-cli to ask for a code, the device code to
poll with, and the token, as a Bearer header, to whoami and logout. No
hostname, operating system, user name or machine identifier: a machine is
named on the web, by its person, never by what it says about itself. The
token never goes in argv or a URL.

What is kept: the token, in ~/.ranwhat/token, and in ~/.ranwhat/account.json
(0600) the plan, organisation and email last heard for it and for the few
tokens last used before it (one from RANWHAT_TOKEN or --token, say), each
under the token's SHA-256 and never the token, so that a machine linked to
a Free organisation still sees the hints about Plus (cli._has_plus).

Everything the server says is shown only after it is checked: text loses
any terminal control character, a link is printed or opened only when it is
ranwhat's own device page, and a token is saved only when it has a token's
shape.
"""
from __future__ import annotations

import hashlib
import http.client
import json
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

from . import feed

DEFAULT_API = "https://feed.ranwhat.com/v1"
DEVICE_PAGE = "https://ranwhat.com/device"
ACCOUNT_PAGE = "https://account.ranwhat.com/"
CLIENT_ID = "ranwhat-cli"
GRANT_TYPE = "urn:ietf:params:oauth:grant-type:device_code"
USER_AGENT = "ranwhat-cli/1"
TIMEOUT = 20

# Every answer here is a few hundred bytes of JSON. Past this it is not
# one, and is not read into memory to find out.
MAX_BYTES = 64 * 1024

PLANS = {"free": "Free", "plus": "Plus", "team": "Team"}

# auth.js's TOKEN: anything else is not a feed token, and is not saved.
_TOKEN = re.compile(r"rw_[A-Za-z0-9_-]{20,200}\Z")
# Letters and digits in dash-separated groups (the server sends XXXX-XXXX).
_USER_CODE = re.compile(r"[A-Z0-9]{2,8}(?:-[A-Z0-9]{2,8}){0,3}\Z")
_DEVICE_CODE = re.compile(r"[A-Za-z0-9._~+/=-]{16,512}\Z")
# Shown text loses terminal control characters (feed.py's class) and the
# invisible ones that reorder or hide what is around them: an organisation
# named with U+202E could make the line it is on read as something else.
# Written as escapes: the characters themselves in source would reorder the
# line for whoever reads it (Trojan Source, CVE-2021-42574).
_HIDDEN = re.compile("[\u200b-\u200f\u202a-\u202e\u2060-\u2069\ufeff]")
_LOCAL = ("localhost", "127.0.0.1", "::1")
_SSH = ("SSH_CONNECTION", "SSH_CLIENT", "SSH_TTY")

SLOWER = 5            # seconds added by each slow_down (RFC 8628 section 3.5)
MAX_INTERVAL = 120
MAX_FAILURES = 5      # transient failures in a row before polling gives up

# Indirection for the tests, which run the clock instead of waiting on it.
_sleep = time.sleep
_clock = time.monotonic


class AccountError(feed.FeedError):
    pass


class Unreachable(AccountError):
    """The server could not be asked: no connection, a timeout, or no
    answer that HTTP could read."""


class Rejected(AccountError):
    """The server read the token and refused it: revoked, expired, or
    never one of its own."""


# ---------- paths and the plan cache ----------

def api_base():
    """The feed host's /v1, or RANWHAT_ACCOUNT_URL (for testing against a
    server on this machine, as RANWHAT_FEED_URL is for the feed)."""
    return (os.environ.get("RANWHAT_ACCOUNT_URL") or DEFAULT_API).rstrip("/")


def cache_path():
    return os.path.join(feed.home(), "account.json")


def _sha256(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _write_private(path, text):
    """0600 from the start, never through a symlink, and whole or not at
    all: written beside the path and moved over it, as feed.save() does."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    try:
        if os.path.lexists(tmp):
            os.unlink(tmp)
        fd = os.open(tmp, feed._CREATE, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            if hasattr(os, "fchmod"):
                os.fchmod(fh.fileno(), 0o600)
            fh.write(text)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


# Tokens the plan cache keeps an entry for, the latest first: the saved one,
# and one or two used beside it with RANWHAT_TOKEN or --token, so that
# using another token never costs the saved one what was heard for it.
CACHE_ENTRIES = 4


def _entries():
    """The plan cache's entries, each a dict with a token_sha256 and a
    known plan; [] for a cache that is missing or not one. Never raises."""
    try:
        with open(cache_path(), encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, ValueError, RecursionError):
        return []
    entries = doc.get("tokens") if isinstance(doc, dict) else None
    if not isinstance(entries, list):
        return []
    return [e for e in entries if isinstance(e, dict)
            and isinstance(e.get("token_sha256"), str) and e.get("plan") in PLANS]


def remember(token, plan, org=None, email=None):
    """Note the plan last heard for `token`, beside what was heard for the
    few tokens before it. A convenience for the hints only: a cache that
    cannot be written is no cache, never an error."""
    if plan not in PLANS:
        return
    key = _sha256(token)
    entry = {"token_sha256": key, "plan": plan, "org": org, "email": email}
    kept = [e for e in _entries() if e["token_sha256"] != key]
    doc = {"tokens": [entry] + kept[:CACHE_ENTRIES - 1]}
    try:
        _write_private(cache_path(), json.dumps(doc, indent=1, sort_keys=True))
    except OSError:
        pass


def cached(token):
    """What remember() kept for this token, or None. Never raises."""
    key = _sha256(token)
    for entry in _entries():
        if entry["token_sha256"] == key:
            return entry
    return None


def cached_plan(token):
    doc = cached(token)
    return doc["plan"] if doc else None


def _forget():
    """Delete the plan cache. A cache: one that cannot be deleted is left,
    never an error."""
    try:
        os.unlink(cache_path())
    except OSError:
        pass


# ---------- what the server says ----------

def _shown(value, limit=120):
    """Server text as it may reach the terminal, or None."""
    if not isinstance(value, str):
        return None
    text = _HIDDEN.sub("", feed._CONTROL.sub("", value)).strip()
    return text[:limit] or None


def _int(value, default):
    return value if isinstance(value, int) and not isinstance(value, bool) else default


def _device_page(uri):
    """Where to type the code: the address the server gave when it is
    ranwhat's own device page (or one on this machine, for testing), and
    https://ranwhat.com/device otherwise. Never one with a query, a
    fragment or anything after /device, where a code could be carried."""
    if not isinstance(uri, str) or len(uri) > 200 or not feed._plain(uri):
        return DEVICE_PAGE
    try:
        parts = urllib.parse.urlsplit(uri)
        host = parts.hostname or ""
        port = parts.port
    except ValueError:
        return DEVICE_PAGE
    if (parts.query or parts.fragment or parts.username or parts.password
            or parts.path not in ("/device", "/device/") or "?" in uri or "#" in uri):
        return DEVICE_PAGE
    if parts.scheme == "https" and port is None and (
            host == "ranwhat.com" or host.endswith(".ranwhat.com")):
        return uri
    if parts.scheme in ("http", "https") and host in _LOCAL:
        return uri
    return DEVICE_PAGE


def _refusal(status, doc, doing):
    """A sentence for an answer that is neither success nor one the caller
    handles: the server's own (an OAuth error_description, or the sentence
    the feed host puts in `error`), or one made from the status."""
    if status == 404:
        # Every account path answers 404 until accounts are switched on.
        return "The server does not link terminals yet (HTTP 404)."
    said = _shown(doc.get("error_description"), 200) or _shown(doc.get("error"), 200)
    if said and " " in said:
        return said
    if status == 429:
        return "Too many requests from your network %s. Try again later." % doing
    return "The server answered HTTP %d %s." % (status, doing)


def _call(path, form=None, token=None, timeout=TIMEOUT):
    """(status, JSON object) for one request: a POST of `form` when there
    is one, a GET otherwise. Unreachable when there was no answer; any HTTP
    answer, error or not, is returned for the caller to read."""
    url = api_base() + path
    feed._check_url(url)
    headers = {"Accept": "application/json", "User-Agent": USER_AGENT}
    if token is not None:
        feed._check_token(token)
        headers["Authorization"] = "Bearer %s" % token
    data = None
    if form is not None:
        data = urllib.parse.urlencode(form).encode("ascii")
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    req = urllib.request.Request(url, data=data, headers=headers,
                                 method="GET" if data is None else "POST")
    host = urllib.parse.urlsplit(url).hostname
    try:
        with feed._open(req, timeout, ssl.create_default_context()) as resp:
            status, body = resp.status, resp.read(MAX_BYTES + 1)
    except urllib.error.HTTPError as exc:
        status = exc.code
        try:
            body = exc.read(MAX_BYTES + 1)
        except (OSError, http.client.HTTPException):
            body = b""
        finally:
            exc.close()
    except urllib.error.URLError as exc:
        reason = exc.reason if isinstance(exc.reason, str) else (
            getattr(exc.reason, "strerror", None) or type(exc.reason).__name__)
        raise Unreachable("Could not reach %s: %s" % (host, _shown(str(reason)) or "no answer"))
    except (OSError, http.client.HTTPException) as exc:
        raise Unreachable("Could not reach %s: %s" % (host, type(exc).__name__))
    except ValueError:
        # Whatever else http.client refuses in a header, its message quotes
        # the header, token included. from None: not shown as the cause.
        raise AccountError("The request to %s could not be sent." % host) from None
    if len(body) > MAX_BYTES:
        raise AccountError("The answer from %s is larger than any it sends; "
                           "not reading it." % host)
    try:
        doc = json.loads(body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError, RecursionError):
        doc = None
    return status, doc if isinstance(doc, dict) else {}


# ---------- the device grant ----------

def request_code():
    """POST device/code: what to show and how to poll. client_id and
    nothing else is sent."""
    status, doc = _call("/device/code", form={"client_id": CLIENT_ID})
    if status != 200:
        raise AccountError(_refusal(status, doc, "when asked for a code"))
    user_code = doc.get("user_code")
    device_code = doc.get("device_code")
    if not (isinstance(user_code, str) and _USER_CODE.match(user_code)
            and isinstance(device_code, str) and _DEVICE_CODE.match(device_code)):
        raise AccountError("The server's answer was not a code ranwhat can show. "
                           "Update ranwhat and try again.")
    return {
        "device_code": device_code,
        "user_code": user_code,
        "page": _device_page(doc.get("verification_uri")),
        "interval": min(max(_int(doc.get("interval"), 5), 1), MAX_INTERVAL),
        "expires_in": min(max(_int(doc.get("expires_in"), 600), 1), 3600),
    }


def _granted(doc):
    token = doc.get("access_token")
    if not (isinstance(token, str) and _TOKEN.match(token)):
        raise AccountError("The server's answer held no token ranwhat can use. "
                           "Update ranwhat and try again.")
    kind = doc.get("token_type")
    if kind is not None and (not isinstance(kind, str) or kind.lower() != "bearer"):
        raise AccountError("The server sent a token of a kind ranwhat cannot use.")
    plan = doc.get("plan")
    return {"token": token, "email": _shown(doc.get("email")),
            "org": _shown(doc.get("org")), "plan": plan if plan in PLANS else None}


def poll(code):
    """Poll device/token as RFC 8628 says until the code is approved,
    denied or expired: every `interval` seconds, five more after each
    slow_down. A failure to connect, or a 5xx, is waited out a few times
    in a row before it is given up on."""
    interval = code["interval"]
    deadline = _clock() + code["expires_in"]
    failures = 0
    expired = AccountError("The code expired before it was approved. "
                           "Run ranwhat login again.")
    form = {"client_id": CLIENT_ID, "grant_type": GRANT_TYPE,
            "device_code": code["device_code"]}
    while True:
        _sleep(interval)
        if _clock() > deadline:
            raise expired
        try:
            status, doc = _call("/device/token", form=form)
        except Unreachable:
            failures += 1
            if failures >= MAX_FAILURES:
                raise
            continue
        if status == 200:
            return _granted(doc)
        error = doc.get("error")
        if error == "authorization_pending":
            failures = 0
            continue
        if error == "slow_down":
            failures = 0
            interval = min(max(interval + SLOWER, _int(doc.get("interval"), 0)),
                           MAX_INTERVAL)
            continue
        if error == "access_denied":
            raise AccountError("It was not approved, so nothing was linked.")
        if error == "expired_token":
            raise expired
        if status >= 500 or error == "temporarily_unavailable":
            failures += 1
            if failures >= MAX_FAILURES:
                raise AccountError(_refusal(status, doc, "while waiting for approval"))
            continue
        raise AccountError(_refusal(status, doc, "while waiting for approval"))


def describe(token):
    """GET whoami for `token`: the server's answer, checked for type."""
    status, doc = _call("/whoami", token=token)
    if status in (401, 403):
        raise Rejected("The server did not accept that token: it was revoked, "
                       "has expired, or is not a ranwhat token.")
    if status != 200:
        raise AccountError(_refusal(status, doc, "when asked whose the token is"))
    return doc


def revoke(token):
    """POST logout: 'revoked' for a terminal's own token, 'shared' for one
    the server leaves alone (a subscription's, a hand-issued or a CI
    token)."""
    status, doc = _call("/logout", form={}, token=token)
    if status in (401, 403):
        raise Rejected("The server no longer accepts that token.")
    if status != 200:
        raise AccountError(_refusal(status, doc, "when asked to revoke the token"))
    if doc.get("revoked") is True:
        return "revoked"
    return "shared"


# ---------- the saved token ----------

def _saved_token():
    """(token, why) for the token saved on this machine: feed.saved_token(),
    which never reads through a symlink."""
    return feed.saved_token()


def _plan_name(plan):
    return PLANS.get(plan, "an unknown plan")


def _who(doc):
    """'ana@example.com, Acme, Plus' from what login or whoami heard."""
    parts = [p for p in (_shown(doc.get("email")), _shown(doc.get("org"))) if p]
    if doc.get("kind") == "subscription":
        parts.insert(0, "a shared subscription token")
    elif doc.get("kind") == "hand":
        parts.insert(0, "a hand-issued token")
    elif doc.get("kind") == "ci":
        parts.insert(0, "a CI token")
    parts.append(_plan_name(doc.get("plan")))
    return ", ".join(parts)


def _whose_saved(token):
    if token is None:
        return ""
    try:
        return " (%s)" % _who(describe(token))
    except Rejected:
        return " (one the server no longer accepts)"
    except feed.FeedError:
        return " (the server could not be asked whose it is)"


def _needs_plus(out):
    out.write("  The catalogue feed and the other server features need Plus:\n"
              "  %s\n"
              "  Everything that runs on this machine stays free, with or without\n"
              "  an account.\n" % feed.UPGRADE)


def _env_note(out):
    if os.environ.get("RANWHAT_TOKEN"):
        out.write("\n  RANWHAT_TOKEN is set, and update and whoami use it before the\n"
                  "  token saved on this machine. Unset it to use this machine's own.\n")


# ---------- the private parts of `ranwhat login` ----------

def _may_open(url, no_browser, stream, environ=None, platform=None):
    """Whether to open a browser at `url`: only ranwhat's own device page
    (or one on this machine, for testing), only when asked of a terminal,
    and never over SSH or without a display, where a browser would open on
    another screen or not at all, or with --no-browser."""
    environ = os.environ if environ is None else environ
    platform = sys.platform if platform is None else platform
    if no_browser or _device_page(url) != url:
        return False
    try:
        if not stream.isatty():
            return False
    except (AttributeError, ValueError):
        return False
    if any(environ.get(name) for name in _SSH):
        return False
    if platform == "darwin" or platform.startswith(("win", "cygwin")):
        return True
    return bool(environ.get("DISPLAY") or environ.get("WAYLAND_DISPLAY"))


def _open_browser(url):
    try:
        import webbrowser
        return bool(webbrowser.open(url, new=2))
    except Exception:
        return False


def _revoke_replaced(token, out, err):
    """login --force: revoke the token the new one replaced, as logout
    would. The server revokes a terminal's own token only; a shared one (a
    subscription's or a CI token) is left as it is, and said to be."""
    try:
        said = revoke(token)
    except Rejected:
        out.write("  The token this machine had before was no longer accepted, so there\n"
                  "  was nothing to revoke.\n")
        return
    except (feed.FeedError, KeyboardInterrupt):
        err.write("  The token this machine had before could not be revoked, so it may\n"
                  "  still work. Revoke it at %s\n" % ACCOUNT_PAGE)
        return
    if said == "revoked":
        out.write("  The token this machine had before is revoked.\n")
    else:
        out.write("  The token this machine had before is a shared one (a subscription's\n"
                  "  or a CI token), so it was not revoked and still works wherever else\n"
                  "  it is used.\n")


# ---------- the commands ----------

def login(force=False, no_browser=False, out=None, err=None):
    out = sys.stdout if out is None else out
    err = sys.stderr if err is None else err
    path = feed.token_path()
    if os.path.islink(path):
        err.write("  %s is a symlink; not writing a token through it.\n"
                  "  Remove it, then run ranwhat login again.\n" % path)
        return 1
    if os.path.lexists(path) and not force:
        token, _why = _saved_token()
        err.write("  This machine already has a saved token%s.\n"
                  "  Run ranwhat logout first, or ranwhat login --force to replace it.\n"
                  % _whose_saved(token))
        return 1
    # With --force, the token being replaced: revoked once the new one is
    # saved, so that linking a machine again, because its token may have
    # leaked, leaves no copy of the old one working.
    replaced = _saved_token()[0] if force else None
    try:
        code = request_code()
        out.write(
            "\n  To link this machine to your ranwhat.com account, open\n\n"
            "    %s\n\n"
            "  in a browser, sign in, and type this code there:\n\n"
            "    %s\n\n"
            "  Type it only on that page, and only because you ran ranwhat login\n"
            "  just now. Nobody from ranwhat will ever ask you for it.\n"
            % (code["page"], code["user_code"]))
        if _may_open(code["page"], no_browser, out) and _open_browser(code["page"]):
            out.write("  The page is open in your browser.\n")
        out.write("\n  Waiting for approval (Ctrl-C cancels)...\n")
        out.flush()
        got = poll(code)
    except KeyboardInterrupt:
        out.write("\n")
        err.write("  Cancelled. Nothing was linked, and the code expires on its own.\n")
        return 130
    except feed.FeedError as exc:
        err.write("  %s\n" % exc)
        return 1

    try:
        feed.save_token(got["token"])
    except KeyboardInterrupt:
        out.write("\n")
        err.write("  Cancelled after the machine was linked, perhaps before its token was\n"
                  "  saved. If ranwhat whoami says this machine is not logged in, revoke\n"
                  "  the new token at %s and run ranwhat login again.\n" % ACCOUNT_PAGE)
        return 130
    except (feed.FeedError, OSError) as exc:
        err.write("  The machine was linked, but its token could not be saved: %s\n"
                  "  Revoke it at %s and run ranwhat login again.\n"
                  % (_shown(str(exc), 200) or type(exc).__name__, ACCOUNT_PAGE))
        return 1
    remember(got["token"], got["plan"], got["org"], got["email"])
    out.write("\n  Linked to %s as %s (%s).\n"
              % (got["org"] or "your organisation", got["email"] or "you",
                 _plan_name(got["plan"])))
    out.write("  Name this machine, or unlink it, at %s\n" % ACCOUNT_PAGE)
    if replaced is not None and replaced != got["token"]:
        _revoke_replaced(replaced, out, err)
    if got["plan"] == "free":
        out.write("\n")
        _needs_plus(out)
    _env_note(out)
    return 0


def whoami(token=None, out=None, err=None):
    """`token`: one given with --token. Otherwise RANWHAT_TOKEN, then the
    saved token, the order update reads them in."""
    out = sys.stdout if out is None else out
    err = sys.stderr if err is None else err
    source = "--token" if token else None
    if not token and os.environ.get("RANWHAT_TOKEN", "").strip():
        token, source = os.environ["RANWHAT_TOKEN"].strip(), "RANWHAT_TOKEN"
    if not token:
        token, why = _saved_token()
        if why == "symlink":
            err.write("  %s is a symlink; not reading a token through it.\n"
                      % feed.token_path())
            return 1
        if why == "unreadable":
            err.write("  %s holds no token ranwhat can read.\n" % feed.token_path())
            return 1
    if not token:
        err.write("  Not logged in. Run ranwhat login to link this machine to an\n"
                  "  account; nothing that runs locally needs one.\n")
        return 1
    try:
        doc = describe(token)
    except Rejected as exc:
        err.write("  %s\n  Run ranwhat login to link this machine again.\n" % exc)
        return 1
    except feed.FeedError as exc:
        err.write("  %s\n" % exc)
        return 1

    kind = doc.get("kind")
    plan = doc.get("plan") if doc.get("plan") in PLANS else None
    rows = []
    if kind in ("device", "ci"):
        # A CI token belongs to its organisation; the server never names
        # the person who made it, so there is no account or role to show.
        if kind == "device":
            rows.append(("Account", _shown(doc.get("email")) or "unknown"))
        rows.append(("Organisation", _shown(doc.get("org")) or "unknown"))
        if kind == "device":
            rows.append(("Role", _shown(doc.get("role"), 20) or "unknown"))
        rows.append(("Plan", _plan_name(plan)))
        machine = doc.get("machine") if isinstance(doc.get("machine"), dict) else {}
        label = _shown(machine.get("label"), 80)
        rows.append(("Machine" if kind == "device" else "CI token",
                     label or "not named yet; name it at %s" % ACCOUNT_PAGE))
        linked = _int(machine.get("created_at"), None)
        if linked is not None:
            try:
                rows.append(("Linked", time.strftime("%Y-%m-%d", time.gmtime(linked))))
            except (OverflowError, OSError, ValueError):
                pass
    elif kind in ("subscription", "hand"):
        rows.append(("Token", "a shared subscription token" if kind == "subscription"
                     else "a hand-issued token"))
        if _shown(doc.get("org")):
            rows.append(("Organisation", _shown(doc.get("org"))))
        rows.append(("Plan", _plan_name(plan)))
    else:
        rows += [("Token", "a kind this version of ranwhat does not know"),
                 ("Plan", _plan_name(plan))]
    if source:
        rows.append(("From", source))
    for name, value in rows:
        out.write("  %-13s %s\n" % (name, value))
    if plan:
        remember(token, plan, _shown(doc.get("org")), _shown(doc.get("email")))
    if plan == "free":
        out.write("\n")
        _needs_plus(out)
    if source == "RANWHAT_TOKEN" and os.path.lexists(feed.token_path()):
        out.write("\n  The token saved at %s is not used while RANWHAT_TOKEN is set.\n"
                  % feed.token_path())
    return 0


def logout(local=False, out=None, err=None):
    """Revoke and delete the token saved on this machine. One in
    RANWHAT_TOKEN is the environment's, and is left as it is.

    The token is deleted only once it is dead or shared: revoked now, no
    longer accepted, or one the server leaves alone. When the server cannot
    be asked, or answers anything else (an error, a redirect, or not
    linking terminals yet), it would still work, and this is its only copy
    here: it is kept, and logout exits 1, to be run again. local=True
    (--local) deletes it without asking the server."""
    out = sys.stdout if out is None else out
    err = sys.stderr if err is None else err
    path = feed.token_path()
    token, why = _saved_token()
    if why == "none":
        _forget()
        err.write("  Not logged in: there is no saved token to remove.\n")
        if os.environ.get("RANWHAT_TOKEN"):
            err.write("  RANWHAT_TOKEN is set in the environment; logout leaves it alone.\n")
        return 1

    revoked = None
    note = None
    if why == "symlink":
        note = ("It was a symlink: the link was removed, and what it points to was\n"
                "  neither read nor changed. Nothing was revoked on the server.")
    elif token is None:
        note = "It could not be read, so nothing was revoked on the server."
    elif local:
        note = ("The server was not asked, so nothing was revoked: the machine stays\n"
                "  listed, and its token keeps working, until you revoke it at\n"
                "  %s" % ACCOUNT_PAGE)
    else:
        try:
            revoked = revoke(token)
        except KeyboardInterrupt:
            out.write("\n")
            err.write("  Cancelled before the server answered, so the token may still work.\n"
                      "  It is kept at %s; run ranwhat logout again.\n" % path)
            return 130
        except Rejected:
            note = "The server no longer accepted it, so there was nothing to revoke."
        except feed.FeedError as exc:
            err.write("  %s\n"
                      "  The server did not say it revoked the token, so it may still work,\n"
                      "  and it is kept at %s.\n"
                      "  Run ranwhat logout again once the server answers, or revoke it at\n"
                      "  %s and then run ranwhat logout --local\n"
                      "  to delete it here without asking.\n"
                      % (exc, path, ACCOUNT_PAGE))
            return 1

    try:
        feed.delete_token()
    except (OSError, KeyboardInterrupt) as exc:
        stopped = isinstance(exc, KeyboardInterrupt)
        if revoked == "revoked":
            err.write("  The token is revoked on the server, but %s was not deleted%s.\n"
                      "  Run ranwhat logout --local to delete it.\n"
                      % (path, " (cancelled)" if stopped else ": " + type(exc).__name__))
        else:
            err.write("  Could not delete %s: %s\n"
                      % (path, "cancelled" if stopped else type(exc).__name__))
        return 130 if stopped else 1
    _forget()
    if revoked == "revoked":
        out.write("  Logged out. This machine's token is revoked and deleted.\n")
    elif revoked == "shared":
        out.write("  Deleted the saved token from this machine. It is a shared token\n"
                  "  (a subscription's or a CI token), so it was not revoked and still\n"
                  "  works wherever else it is used.\n")
    else:
        out.write("  Deleted the saved token from this machine.\n")
        err.write("  %s\n" % note)
    if os.environ.get("RANWHAT_TOKEN"):
        out.write("  RANWHAT_TOKEN is still set in the environment; logout leaves it alone.\n")
    return 0
