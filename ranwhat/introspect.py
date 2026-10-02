"""
Live credential introspection. Read-only, always.

Every call here is a metadata read: "what is this token allowed to do".
Nothing in this module exercises a granted permission, and nothing writes.
Tokens are held in memory for the duration of a call and are never logged,
persisted, or transmitted anywhere except to the issuing provider.

A provider that will not say what a token may do gets "scopes_known": False
and a "note" saying where to look instead. An empty list alone reads as a
token that may do nothing, and scored as the safest credential there is.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.parse
import urllib.request

TIMEOUT = 15


class IntrospectionError(Exception):
    pass


def _header_safe(value):
    """Printable latin-1 with no line break, which is all a credential needs.
    http.client refuses a line break, or a character latin-1 cannot encode,
    with a ValueError that quotes the whole value."""
    return all(" " <= c <= "~" or "\xa0" <= c <= "\xff" for c in value)


def _headers(message):
    """Response headers by lower-cased name. HTTP names are case-blind, and
    a plain dict of them is not: X-OAuth-Scopes sent as x-oauth-scopes
    read as absent."""
    return {k.lower(): v for k, v in (message or {}).items()}


def _request(url, method="GET", headers=None, data=None):
    """(status, headers by lower-cased name, body)."""
    body = None
    if data is not None:
        body = urllib.parse.urlencode(data).encode()
    req = urllib.request.Request(url, data=body, method=method)
    req.add_header("User-Agent", "ranwhat/0.1 (read-only introspection)")
    for k, v in (headers or {}).items():
        # Stripping a token takes a \r off its ends, not a line break inside
        # it: a CRLF file with a second line, read with $(cat file). Refused
        # here, and the message does not repeat it.
        if not _header_safe(v):
            raise IntrospectionError(
                "the credential contains a line break or another character "
                "a request header cannot carry, so nothing was sent. Check "
                "how it was copied.")
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            raw = resp.read().decode("utf-8", "replace")
            return resp.status, _headers(resp.headers), raw
    except urllib.error.HTTPError as e:
        return e.code, _headers(e.headers), e.read().decode("utf-8", "replace")
    except ValueError:
        # Whatever else http.client refuses in a header or the URL, its
        # message quotes it, token included. from None: not shown as the cause.
        raise IntrospectionError(
            "the request could not be sent: a header or the address holds a "
            "character HTTP cannot carry.") from None
    except Exception as e:
        raise IntrospectionError(str(e))


def google(access_token):
    """Google OAuth2 tokeninfo. Returns granted scopes."""
    url = "https://oauth2.googleapis.com/tokeninfo?" + urllib.parse.urlencode(
        {"access_token": access_token})
    status, _, raw = _request(url)
    if status != 200:
        raise IntrospectionError("google tokeninfo returned %s: %s" % (status, raw[:200]))
    payload = json.loads(raw)
    return {
        "provider": "google",
        "label": payload.get("email") or "google-oauth",
        "scopes": (payload.get("scope") or "").split(),
        "expires_in": payload.get("expires_in"),
    }


# Classic personal access tokens and OAuth app tokens, and the 40 hex
# characters both were before 2021: for these the scopes header is complete.
_GITHUB_CLASSIC = re.compile(r"(?:gh[po]_[A-Za-z0-9]+|[0-9a-f]{40})\Z")


def github(token):
    """GitHub returns granted scopes in a response header on any authed call,
    for classic tokens. For a fine-grained one the header is empty."""
    status, headers, raw = _request(
        "https://api.github.com/user",
        headers={"Authorization": "Bearer %s" % token,
                 "Accept": "application/vnd.github+json"},
    )
    if status != 200:
        raise IntrospectionError("github returned %s: %s" % (status, raw[:200]))
    scopes_header = headers.get("x-oauth-scopes")
    scopes = [s.strip() for s in (scopes_header or "").split(",") if s.strip()]
    login = json.loads(raw).get("login", "github")
    if scopes or (scopes_header is not None and _GITHUB_CLASSIC.match(token)):
        # A classic token sent with an empty header was given no scope,
        # and reads public data only. That is known, and is nothing.
        return {"provider": "github", "label": login, "scopes": scopes}
    if token.startswith("github_pat_"):
        note = ("Fine-grained token. GitHub does not list its permissions "
                "through the API. They are on the token's page under "
                "Settings, Developer settings.")
    else:
        note = ("GitHub did not list this token's permissions. It lists "
                "them only for classic tokens; any other kind has them where "
                "it was made, such as a GitHub App's settings.")
    return {"provider": "github", "label": login, "scopes": [],
            "scopes_known": False, "note": note}


def slack(token):
    status, headers, raw = _request(
        "https://slack.com/api/auth.test",
        method="POST",
        headers={"Authorization": "Bearer %s" % token},
    )
    payload = json.loads(raw) if raw else {}
    if status != 200 or not payload.get("ok"):
        raise IntrospectionError("slack auth.test failed: %s" % payload.get("error", status))
    scopes = [s.strip() for s in headers.get("x-oauth-scopes", "").split(",") if s.strip()]
    return {
        "provider": "slack",
        "label": payload.get("team", "slack"),
        "scopes": scopes,
    }


def stripe(api_key):
    """Stripe has no scope introspection endpoint. The key prefix is the
    strongest available signal, and an unrestricted live key is itself the
    finding: the catalogue's "all" says what it can do."""
    prefix = api_key[:3]
    if prefix == "sk_":
        return {
            "provider": "stripe",
            "label": "stripe-secret-key",
            "scopes": ["all"],
        }
    if prefix == "rk_":
        # There is no --scopes flag. A profile that declares them is the
        # way to score what the key can do.
        return {
            "provider": "stripe",
            "label": "stripe-restricted-key",
            "scopes": [],
            "scopes_known": False,
            "note": "Restricted key. Stripe does not list its permissions "
                    "through the API. They are on the key's page in the "
                    "Dashboard, under Developers, API keys.",
        }
    raise IntrospectionError("unrecognised Stripe key format")


def rfc7662(token, endpoint, client_id, client_secret):
    """Generic OAuth 2.0 Token Introspection (RFC 7662)."""
    import base64
    basic = base64.b64encode(
        ("%s:%s" % (client_id, client_secret)).encode()).decode()
    status, _, raw = _request(
        endpoint,
        method="POST",
        headers={"Authorization": "Basic %s" % basic,
                 "Content-Type": "application/x-www-form-urlencoded"},
        data={"token": token, "token_type_hint": "access_token"},
    )
    if status != 200:
        raise IntrospectionError("introspection returned %s: %s" % (status, raw[:200]))
    payload = json.loads(raw)
    if not payload.get("active", False):
        raise IntrospectionError("token is not active")
    return {
        "provider": "generic",
        "label": payload.get("client_id") or payload.get("sub") or "oauth-token",
        "scopes": (payload.get("scope") or "").split(),
        "expires_at": payload.get("exp"),
    }


PROVIDERS = {
    "google": google,
    "github": github,
    "slack": slack,
    "stripe": stripe,
}
