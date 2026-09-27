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
        with open(token_path()) as fh:
            return fh.read().strip() or None
    except OSError:
        return None


def save_token(token):
    d = home()
    os.makedirs(d, exist_ok=True)
    path = token_path()
    # 0600 before anything is written: a token readable by other users on the
    # machine is the problem this tool exists to report.
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(path, flags, 0o600)
    try:
        os.write(fd, (token.strip() + "\n").encode())
    finally:
        os.close(fd)
    os.chmod(path, 0o600)
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


def fetch(token, url=None, timeout=TIMEOUT):
    """Ask the server for the current catalogue.

    Sends the token and nothing else. Authenticity rests on TLS: the payload
    carries a digest of itself, which catches truncation and corruption but is
    not a signature, and the docstring says so rather than implying more.
    """
    url = url or endpoint()
    _check_url(url)
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
    if len(body) > MAX_BYTES:
        raise FeedError("The feed is larger than any catalogue; not reading it.")

    try:
        doc = json.loads(body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise FeedError("The feed returned something that is not JSON.")

    return validate(doc)


def validate(doc):
    """Reject anything malformed before it can reach a report."""
    if not isinstance(doc, dict):
        raise FeedError("Feed payload is not an object.")
    if doc.get("schema") != SCHEMA:
        raise FeedError(
            "This feed needs ranwhat with schema %s support; got %r. Upgrade "
            "with: uvx ranwhat" % (SCHEMA, doc.get("schema")))
    catalogue = doc.get("catalogue")
    if not isinstance(catalogue, dict) or not catalogue:
        raise FeedError("Feed contains no catalogue.")
    for provider, scopes in catalogue.items():
        if not isinstance(scopes, dict):
            raise FeedError("Provider %r is not an object." % provider)
        for scope, entry in scopes.items():
            if not isinstance(entry, dict):
                raise FeedError("Scope %r/%r is not an object." % (provider, scope))
            for field in FIELDS:
                if field not in entry:
                    raise FeedError(
                        "Scope %r/%r is missing %r." % (provider, scope, field))
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
            for field in ("label", "why"):
                if not isinstance(entry[field], str):
                    raise FeedError("Scope %r/%r has a non-text %s." % (
                        provider, scope, field))
    stated = doc.get("digest")
    if stated and stated != digest(catalogue):
        raise FeedError("Feed digest does not match its catalogue.")
    return doc


def save(doc):
    path = feed_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    doc = dict(doc)
    doc["fetched_at"] = int(time.time())
    tmp = path + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(doc, fh, indent=1, sort_keys=True)
    os.replace(tmp, path)   # atomic: a killed update never leaves a half file
    os.chmod(path, 0o600)
    return path


def load():
    """Return the cached feed, or None. Never raises, never touches the network."""
    try:
        with open(feed_path()) as fh:
            doc = json.load(fh)
        return validate(doc)
    except (OSError, ValueError, FeedError):
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
