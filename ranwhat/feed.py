"""The subscription catalogue feed.

The bundled catalogue in catalog.py is a snapshot: correct on the day the
version shipped, and steadily less complete as providers add scopes. The feed
is the same structure kept current, fetched from a server and cached on disk.

Three properties this module has to hold to, because the whole tool is sold on
them:

  It never phones home. `update` sends a token and nothing else. No machine
  identifier, no scope list, no usage counts. What is on this machine is not
  the feed server's business.

  It is never required. Every command works with no feed, no token and no
  network. A missing or stale feed degrades to the bundled snapshot, silently.

  It never blocks. Nothing outside `ranwhat update` touches the network, so a
  feed server that is down or slow cannot make a scan hang.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request

from . import catalog

DEFAULT_ENDPOINT = "https://feed.ranwhat.com/v1/catalogue"
USER_AGENT = "ranwhat-feed/1"
TIMEOUT = 20

SCHEMA = 1

# A catalogue is a few hundred kilobytes. Anything past this is not one, and
# reading it all into memory first would let a hostile server exhaust it.
MAX_BYTES = 8 * 1024 * 1024

# The fields a feed entry may carry. Anything else is dropped rather than
# merged, so a feed cannot overwrite a report row's scope, usage or provider.
FIELDS = ("label", "authority", "reversible", "blast", "why")
BLASTS = frozenset((catalog.MONETARY, catalog.EXTERNAL_COMMS, catalog.DATA_EGRESS,
                    catalog.INFRASTRUCTURE, catalog.IDENTITY))

# Terminal control characters: the class watch strips from transcripts. A
# label is written to the terminal as it is, and one carrying ESC can move the
# cursor up and erase the scores above it, or write the clipboard through
# OSC 52. No catalogue text needs one, so text with any is no feed.
_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f]")

# The cache's temp file, as clean creates its own: O_EXCL and O_NOFOLLOW so a
# symlink planted at the path fails the write rather than redirecting it.
# O_BINARY: on Windows the descriptor is otherwise in text mode.
_CREATE = (os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
           | getattr(os, "O_BINARY", 0))


def home():
    return os.environ.get("RANWHAT_HOME") or os.path.join(
        os.path.expanduser("~"), ".ranwhat")


def feed_path():
    return os.path.join(home(), "feed", "catalogue.json")


def token_path():
    return os.path.join(home(), "token")


def endpoint():
    return os.environ.get("RANWHAT_FEED_URL") or DEFAULT_ENDPOINT


def read_token():
    """Environment first, then the file, so a token never has to be in argv."""
    tok = os.environ.get("RANWHAT_TOKEN")
    if tok:
        return tok.strip()
    try:
        with open(token_path(), encoding="utf-8") as fh:
            return fh.read().strip() or None
    except OSError:
        return None


def save_token(token):
    d = home()
    os.makedirs(d, exist_ok=True)
    path = token_path()
    # 0600 before anything is written: a token readable by other users on the
    # machine is the problem this tool exists to report.
    # O_NOFOLLOW: a symlink planted at ~/.ranwhat/token would otherwise send
    # the token wherever it points, and chmod would follow it too. O_BINARY:
    # on Windows the descriptor is otherwise in text mode and adds a \r.
    flags = (os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
             | getattr(os, "O_BINARY", 0))
    try:
        fd = os.open(path, flags, 0o600)
    except OSError as exc:
        if os.path.islink(path):
            raise FeedError("%s is a symlink; not writing a token through it." % path)
        raise
    try:
        if hasattr(os, "fchmod"):   # an existing file keeps its old mode otherwise
            os.fchmod(fd, 0o600)
        os.write(fd, (token.strip() + "\n").encode("utf-8"))
    finally:
        os.close(fd)
    return path


def digest(payload):
    """Hash over the catalogue only, so metadata can change without breaking it."""
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


class FeedError(Exception):
    pass


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """urllib copies every request header onto a redirect, Authorization
    included, to whatever host the Location names, and will follow https to
    http. The feed has one address; a redirect away from it is refused."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise FeedError("The feed server redirected to %s; not following it "
                        "with your token." % newurl)


def _check_url(url):
    """https only. Plain http is allowed to this machine alone, for testing a
    feed server locally; anywhere else it would send the token in clear."""
    parts = urllib.parse.urlsplit(url)
    if parts.scheme == "https" and parts.hostname:
        return
    if parts.scheme == "http" and parts.hostname in ("localhost", "127.0.0.1", "::1"):
        return
    raise FeedError("The feed URL must be https: %s" % url)


def _open(req, timeout, context):
    opener = urllib.request.build_opener(
        _NoRedirect, urllib.request.HTTPSHandler(context=context))
    return opener.open(req, timeout=timeout)


def _check_token(token):
    """http.client refuses a header value with a line break in it, or one
    latin-1 cannot encode, and the error it raises quotes the header: the
    token, printed to stderr and to any log that keeps it. A \\r left by a
    CRLF file is enough. Refused here, and the message does not repeat it."""
    if not all(" " <= c <= "~" or "\xa0" <= c <= "\xff" for c in token):
        raise FeedError(
            "The token contains a line break or another character a request "
            "header cannot carry. Check how it was copied.")


def fetch(token, url=None, timeout=TIMEOUT):
    """Ask the server for the current catalogue.

    Sends the token and nothing else. Authenticity rests on TLS: the payload
    carries a digest of itself, which catches truncation and corruption but is
    not a signature, and the docstring says so rather than implying more.
    """
    url = url or endpoint()
    _check_url(url)
    _check_token(token)
    req = urllib.request.Request(url, headers={
        "Authorization": "Bearer %s" % token,
        "Accept": "application/json",
        "User-Agent": USER_AGENT,
    })
    ctx = ssl.create_default_context()
    try:
        with _open(req, timeout, ctx) as resp:
            body = resp.read(MAX_BYTES + 1)
    except urllib.error.HTTPError as exc:
        if exc.code in (401, 403):
            raise FeedError(
                "That token was not accepted. Check it at ranwhat.com/contact.")
        if exc.code == 404:
            raise FeedError("The feed endpoint returned 404: %s" % url)
        raise FeedError("The feed server returned HTTP %s." % exc.code)
    except urllib.error.URLError as exc:
        raise FeedError("Could not reach the feed: %s" % exc.reason)
    except ValueError:
        # Whatever else http.client refuses in a header, its message quotes
        # the header, token included. from None: not shown as the cause.
        raise FeedError("The request to the feed could not be sent.") from None
    if len(body) > MAX_BYTES:
        raise FeedError("The feed is larger than any catalogue; not reading it.")

    # RecursionError, as in load(): json gives up on nesting deeper than the
    # stack, and the digest's json.dumps can give up on nesting that loaded.
    try:
        doc = json.loads(body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError, RecursionError):
        raise FeedError("The feed returned something that is not JSON.")
    try:
        return validate(doc)
    except RecursionError:
        raise FeedError("The feed is nested deeper than any catalogue.")


def validate(doc):
    """Reject anything malformed before it can reach a report."""
    # Every check is on type before value. A list or object where a string
    # belongs is valid JSON, and a membership test on it raises TypeError,
    # which neither `update` nor load() would have caught.
    if not isinstance(doc, dict):
        raise FeedError("Feed payload is not an object.")
    schema = doc.get("schema")
    # isinstance, not only ==: true == 1 in Python.
    if not _is_int(schema) or schema != SCHEMA:
        raise FeedError(
            "This feed needs ranwhat with schema %s support; got %r. Upgrade "
            "with: uvx ranwhat" % (SCHEMA, schema))
    if doc.get("version") is not None and not _plain(doc["version"]):
        raise FeedError("Feed version is not plain text.")
    catalogue = doc.get("catalogue")
    if not isinstance(catalogue, dict) or not catalogue:
        raise FeedError("Feed contains no catalogue.")
    for provider, scopes in catalogue.items():
        if not isinstance(scopes, dict):
            raise FeedError("Provider %r is not an object." % provider)
        if not _plain(provider):
            raise FeedError("Provider %r is not plain text." % provider)
        for scope, entry in scopes.items():
            if not isinstance(entry, dict):
                raise FeedError("Scope %r/%r is not an object." % (provider, scope))
            # A wildcard key reaches the report as "(matched <key>)".
            if not _plain(scope):
                raise FeedError("Scope %r/%r is not plain text." % (provider, scope))
            for field in FIELDS:
                if field not in entry:
                    raise FeedError(
                        "Scope %r/%r is missing %r." % (provider, scope, field))
            for field in ("label", "authority", "blast", "why"):
                if not isinstance(entry[field], str):
                    raise FeedError("Scope %r/%r has a non-text %s." % (
                        provider, scope, field))
            # %r in the message: it names the scope without replaying it.
            for field in ("label", "why"):
                if not _plain(entry[field]):
                    raise FeedError("Scope %r/%r has a control character in "
                                    "its %s." % (provider, scope, field))
            # Checked here, not trusted later: an authority the scorer has no
            # cost for raised KeyError in every scan until the cache was
            # deleted, and a string "false" is truthy.
            if entry["authority"] not in catalog.AUTHORITY_RANK:
                raise FeedError("Scope %r/%r has authority %r." % (
                    provider, scope, entry["authority"]))
            if entry["blast"] not in BLASTS:
                raise FeedError("Scope %r/%r has blast %r." % (
                    provider, scope, entry["blast"]))
            if not isinstance(entry["reversible"], bool):
                raise FeedError("Scope %r/%r has a non-boolean reversible." % (
                    provider, scope))
    # Absent is allowed. Present is checked, whatever it is: a truth test let
    # 0, [] or {} skip the comparison.
    stated = doc.get("digest")
    if stated is not None and stated != digest(catalogue):
        raise FeedError("Feed digest does not match its catalogue.")
    return doc


def _plain(value):
    """Text with no terminal control character in it."""
    return isinstance(value, str) and not _CONTROL.search(value)


def _is_int(value):
    return isinstance(value, int) and not isinstance(value, bool)


def _check_fetched_at(value):
    """save() writes an int. `update --status` hands it to time.localtime,
    which raises on anything else, and on a number past the platform's range."""
    if not (_is_int(value) or isinstance(value, float)):
        raise FeedError("The cached feed has no fetch time.")
    try:
        time.localtime(value)
    except (OverflowError, OSError, ValueError):
        raise FeedError("The cached feed's fetch time is out of range.")


def save(doc):
    path = feed_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    doc = dict(doc)
    doc["fetched_at"] = int(time.time())
    # Built before anything is opened. From Python 3.12 json.loads and the
    # digest's encoder are bounded by the C stack, but up to 3.13 indent=1
    # runs the pure-Python encoder, bounded by the recursion limit, and on
    # 3.14 the C encoder with indent gives up a little before the decoder.
    # A body nested between the two gets through fetch() and fails here.
    try:
        text = json.dumps(doc, indent=1, sort_keys=True)
    except RecursionError:
        raise FeedError("The feed is nested deeper than any catalogue.")
    tmp = path + ".tmp"
    try:
        # Removed, never written through. open(tmp, "w") followed a symlink
        # planted here, the feed overwrote its target, and os.replace then
        # installed the link as the cache. The mode goes on the descriptor,
        # not the path: chmod(path) after the replace followed the link too.
        if os.path.lexists(tmp):
            os.unlink(tmp)
        fd = os.open(tmp, _CREATE, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            if hasattr(os, "fchmod"):   # the umask may have taken the write bit
                os.fchmod(fh.fileno(), 0o600)
            fh.write(text)
        os.replace(tmp, path)   # atomic: a killed update never leaves a half file
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return path


def load():
    """Return the cached feed, or None. Never raises, never touches the network.

    The cache is no more trusted than the network: anything running as this
    user can write it. So a cache that is not what save() writes, down to the
    type of every field, is no feed rather than an error.
    """
    try:
        with open(feed_path(), encoding="utf-8") as fh:
            doc = validate(json.load(fh))
        _check_fetched_at(doc.get("fetched_at"))
        return doc
    # RecursionError: json gives up on nesting deeper than the stack, and a
    # cache of a hundred thousand "[" is still a file anyone could write.
    except (OSError, ValueError, RecursionError, FeedError):
        return None


def status():
    doc = load()
    if not doc:
        return {"active": False}
    cat = doc.get("catalogue", {})
    return {
        "active": True,
        "version": doc.get("version"),
        "fetched_at": doc.get("fetched_at"),
        "providers": len(cat),
        "scopes": sum(len(v) for v in cat.values()),
    }
