"""
Callers: who used a key, from where, according to the provider's own log.

`clean` says a key leaked. The next question is whether anyone used it, and
only the provider can answer that: a request made with the key from
somewhere else leaves no trace on this machine. So this asks the provider's
log for the calls made with one key and groups them by where they came from.

Everything here is read-only, and degrades the way usage.py does: a provider
that keeps no caller log, or will not show it at this account's tier, comes
back as an explicit gap with where to look instead, never as an empty list.
An empty list would read as "nobody used it", which is the one answer this
command must not give without evidence.

What counts as "yours" is for the user to say (--mine CIDR). Without it every
caller is listed and none is called foreign, because ranwhat cannot know
which addresses are yours without asking a third party, and it does not.
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import ipaddress
import json
import subprocess
import urllib.parse

from .introspect import _request, IntrospectionError
from .usage import Coverage, _aws, DEFAULT_WINDOW_DAYS

# Where a provider with no readable caller log keeps one a person can read.
ELSEWHERE = {
    "stripe": "Stripe's API does not say which address made a request. The "
              "request logs in the Dashboard (Developers, then Logs) do.",
    "google": "Google's admin reports list OAuth grants by app, not calls "
              "made with one key. A Workspace admin can see token events in "
              "the Admin console.",
    "slack": "Slack keeps access logs for workspace admins, by user and "
             "address, not by token.",
}

# The labels a caller can get.
MINE = "yours"
SERVICE = "provider service"
OTHER = "not on your list"
UNLABELLED = "unlabelled"


class Call(object):
    """One request made with the key, as the provider logged it."""

    __slots__ = ("when", "ip", "agent", "action", "region", "error")

    def __init__(self, when, ip, agent, action, region=None, error=None):
        self.when = when
        self.ip = ip or ""
        self.agent = agent or ""
        self.action = action or ""
        self.region = region
        self.error = error


# --------------------------------------------------------------------------
# AWS -- CloudTrail LookupEvents, by access key ID. Management events only,
# the last 90 days, one region per call. IAM and STS calls are logged in
# us-east-1, so that region is always asked as well as the configured one.
# --------------------------------------------------------------------------

AWS_MAX_ITEMS = 1000
AWS_MAX_DAYS = 90


def aws_key_id(profile=None):
    """The access key ID the AWS CLI profile signs with, or None for a
    profile without a static key (SSO, a role). The ID is not secret: it
    names the key, as a username names an account."""
    cmd = ["aws", "configure", "get", "aws_access_key_id"]
    if profile:
        cmd += ["--profile", profile]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    except FileNotFoundError:
        raise IntrospectionError("aws CLI not found on PATH")
    except subprocess.TimeoutExpired:
        raise IntrospectionError("aws CLI timed out")
    return out.stdout.strip() or None if out.returncode == 0 else None


def aws_calls(key_id, profile=None, regions=None,
              window_days=DEFAULT_WINDOW_DAYS):
    if not key_id:
        raise IntrospectionError(
            "no access key ID: pass --aws-key-id, or use a profile with a "
            "static key")
    window = min(window_days, AWS_MAX_DAYS)
    start = (datetime.datetime.now(datetime.timezone.utc)
             - datetime.timedelta(days=window)).strftime("%Y-%m-%dT%H:%M:%SZ")
    asked, seen, calls = [], set(), []
    for region in (list(regions) if regions else [None]) + ["us-east-1"]:
        if region in asked:
            continue
        asked.append(region)
        args = ["cloudtrail", "lookup-events",
                "--lookup-attributes",
                "AttributeKey=AccessKeyId,AttributeValue=%s" % key_id,
                "--start-time", start,
                "--max-items", str(AWS_MAX_ITEMS)]
        if region:
            args += ["--region", region]
        out = _aws(args, profile)
        for ev in out.get("Events", []):
            if ev.get("EventId") in seen:
                continue
            seen.add(ev.get("EventId"))
            calls.append(_aws_call(ev))
    where = ", ".join(r or "the profile's region" for r in asked)
    return calls, Coverage(
        "aws", Coverage.WRITES_ONLY,
        "From CloudTrail management events in %s, the last %d days. Data "
        "events, such as S3 object reads, are there only if a trail records "
        "them." % (where, window), window)


def _aws_call(ev):
    detail = {}
    try:
        detail = json.loads(ev.get("CloudTrailEvent") or "{}")
    except ValueError:
        pass
    service = str(detail.get("eventSource", "")).split(".")[0]
    name = ev.get("EventName") or detail.get("eventName") or ""
    return Call(when=_when(ev.get("EventTime") or detail.get("eventTime")),
                ip=detail.get("sourceIPAddress"),
                agent=detail.get("userAgent"),
                action="%s:%s" % (service, name) if service else name,
                region=detail.get("awsRegion"),
                error=detail.get("errorCode"))


# --------------------------------------------------------------------------
# GitHub -- the organisation audit log, searched by the token's hash.
# Enterprise Cloud only, and addresses appear only where the enterprise has
# turned on IP disclosure.
# --------------------------------------------------------------------------

def hashed_token(token):
    """The form GitHub's audit log stores a token in: SHA-256, base64. Only
    the hash goes into the search; the token itself authenticates the
    request, as it would for any API call."""
    return base64.b64encode(hashlib.sha256(token.encode("utf-8"))
                            .digest()).decode("ascii")


def github_calls(token, org=None, window_days=DEFAULT_WINDOW_DAYS):
    if not org:
        return [], Coverage(
            "github", Coverage.NONE,
            "No organisation given. GitHub keeps the calls made with a token "
            "only in an organisation's audit log: pass --github-org ORG.",
            window_days)
    since = (datetime.datetime.now(datetime.timezone.utc)
             - datetime.timedelta(days=window_days)).strftime("%Y-%m-%d")
    phrase = 'hashed_token:"%s" created:>=%s' % (hashed_token(token), since)
    url = ("https://api.github.com/orgs/%s/audit-log?"
           % urllib.parse.quote(org, safe="")) + urllib.parse.urlencode(
        {"phrase": phrase, "per_page": 100})
    status, _, raw = _request(url, headers={
        "Authorization": "Bearer %s" % token,
        "Accept": "application/vnd.github+json"})
    if status in (403, 404):
        return [], Coverage(
            "github", Coverage.NONE,
            "Audit log unavailable. Searching it by token needs GitHub "
            "Enterprise Cloud and a token with read:audit_log.", window_days)
    if status != 200:
        raise IntrospectionError("github audit log returned %s: %s"
                                 % (status, raw[:200]))
    calls = []
    for entry in json.loads(raw):
        stamp = entry.get("@timestamp") or entry.get("created_at")
        if isinstance(stamp, (int, float)):
            stamp = datetime.datetime.fromtimestamp(
                stamp / 1000.0, datetime.timezone.utc)
        calls.append(Call(when=_when(stamp), ip=entry.get("actor_ip"),
                          agent=entry.get("user_agent"),
                          action=entry.get("action")))
    note = "From the organisation audit log, the last %d days." % window_days
    if calls and not any(c.ip for c in calls):
        note += (" No addresses: the enterprise has not turned on IP "
                 "disclosure for its audit log.")
    return calls, Coverage("github", Coverage.FULL, note, window_days)


# --------------------------------------------------------------------------

PULLS = ("aws", "github")


def _when(value):
    if not value:
        return None
    if isinstance(value, datetime.datetime):
        when = value
    else:
        try:
            when = datetime.datetime.fromisoformat(
                str(value).replace("Z", "+00:00"))
        except ValueError:
            return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=datetime.timezone.utc)
    return when


def parse_mine(values):
    """--mine values to networks. A bare address is a /32 or /128, and a
    value may hold several, separated by commas."""
    nets = []
    for value in values or ():
        for part in str(value).split(","):
            part = part.strip()
            if not part:
                continue
            try:
                nets.append(ipaddress.ip_network(part, strict=False))
            except ValueError:
                raise ValueError("--mine: %r is not an address or a CIDR "
                                 "range" % part)
    return nets


def label(ip, mine):
    if not ip:
        return UNLABELLED
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        # CloudTrail names the service, not an address, when one AWS service
        # calls another on the key's behalf (lambda.amazonaws.com).
        return SERVICE if ip.endswith(".amazonaws.com") else UNLABELLED
    if not mine:
        return UNLABELLED
    return MINE if any(addr in net for net in mine
                       if addr.version == net.version) else OTHER


_ORDER = {OTHER: 0, UNLABELLED: 1, SERVICE: 2, MINE: 3}


def group(calls, mine=None):
    """Calls grouped by where they came from and what sent them, those not
    on the user's list first, then the busiest."""
    groups = {}
    for call in calls:
        key = (call.ip, call.agent)
        g = groups.get(key)
        if g is None:
            g = groups[key] = {"ip": call.ip, "agent": call.agent,
                               "label": label(call.ip, mine), "calls": 0,
                               "errors": 0, "first": None, "last": None,
                               "actions": {}}
        g["calls"] += 1
        if call.error:
            g["errors"] += 1
        if call.when:
            iso = call.when.astimezone(datetime.timezone.utc).isoformat()
            g["first"] = min(g["first"] or iso, iso)
            g["last"] = max(g["last"] or iso, iso)
        if call.action:
            g["actions"][call.action] = g["actions"].get(call.action, 0) + 1
    out = []
    for g in groups.values():
        g["actions"] = [a for a, _ in sorted(g["actions"].items(),
                                             key=lambda kv: (-kv[1], kv[0]))]
        out.append(g)
    out.sort(key=lambda g: (_ORDER[g["label"]], -g["calls"], g["ip"],
                            g["agent"]))
    return out


def report(results, mine=None, gaps=None):
    """results: {provider: (calls, Coverage)}; gaps: {provider: note} for
    the providers that were not asked -> a JSON-ready dict."""
    providers = []
    for provider in sorted(results):
        calls, cov = results[provider]
        groups = group(calls, mine)
        providers.append({
            "provider": provider,
            "coverage": cov.as_dict(),
            "calls": len(calls),
            "callers": groups,
            "not_on_your_list": sum(1 for g in groups if g["label"] == OTHER),
        })
    return {"providers": providers,
            "not_asked": dict(sorted((gaps or {}).items())),
            "mine": [str(n) for n in (mine or [])]}


TITLE = ("  ranwhat callers", "  · who used a key, from the provider's own log")


def hint(key_id):
    """A key ID shortened for the screen. AWS key IDs are not secret, but a
    report is pasted into tickets and chats, and the ends are enough to tell
    two keys apart."""
    key_id = str(key_id or "")
    return key_id if len(key_id) <= 8 else "%s...%s" % (key_id[:4], key_id[-4:])


def _day(iso):
    return iso[:10] if iso else "?"


def render(result, keys=None):
    """The report as text. keys: {provider: what was asked about}."""
    from . import term
    from .report import BOLD, DIM, RED, YEL
    width = term.width()
    title, tagline = TITLE
    if len(title + tagline) <= width:
        L = ["", BOLD(title) + DIM(tagline)]
    else:
        L = ["", BOLD(title.rstrip()), DIM("  " + tagline[2:])]
    L += [DIM(term.rule("-")), ""]
    keys = keys or {}
    for p in result["providers"]:
        head = "  %s" % p["provider"]
        if keys.get(p["provider"]):
            head += "  " + keys[p["provider"]]
        cov = p["coverage"]
        if cov["level"] == Coverage.NONE:
            L.append(BOLD(head) + DIM("  not available"))
            L += [DIM(x) for x in term.wrap(cov["note"], indent="    ")]
            L.append("")
            continue
        L.append(BOLD(head) + DIM("  %d call%s" % (p["calls"],
                                                    "" if p["calls"] == 1 else "s")))
        if not p["callers"]:
            L += term.wrap("No calls made with this key in the window. That "
                           "covers what the log below records, nothing more.",
                           indent="    ")
        for g in p["callers"]:
            where = g["ip"] or "no address logged"
            tag = g["label"]
            paint = RED if tag == OTHER else (DIM if tag == MINE else YEL
                                              if tag == UNLABELLED else DIM)
            first, last = _day(g["first"]), _day(g["last"])
            line = "%s \u00b7 %s, %d call%s, %s" % (
                where, tag, g["calls"], "" if g["calls"] == 1 else "s",
                first if first == last else "%s to %s" % (first, last))
            if g["errors"]:
                line += ", %d refused" % g["errors"]
            L += [paint(x) if i == 0 else x for i, x in
                  enumerate(term.wrap(line, first="    ", indent="      "))]
            if g["agent"] and g["agent"] != g["ip"]:
                L += [DIM(x) for x in term.wrap(g["agent"], indent="      ")]
            if g["actions"]:
                acts = ", ".join(g["actions"][:6])
                if len(g["actions"]) > 6:
                    acts += " and %d more" % (len(g["actions"]) - 6)
                L += [DIM(x) for x in term.wrap(acts, indent="      ")]
        L += [DIM(x) for x in term.wrap(cov["note"], indent="    ")]
        L.append("")
    for provider, note in result.get("not_asked", {}).items():
        L.append(BOLD("  %s" % provider) + DIM("  not asked"))
        L += [DIM(x) for x in term.wrap(note, indent="    ")]
        L.append("")
    flagged = sum(p["not_on_your_list"] for p in result["providers"])
    if result["mine"]:
        if flagged:
            L += [RED(x) for x in term.wrap(
                "%d caller%s not on your list. If you do not recognise %s, "
                "treat the key as compromised: rotate it at the provider "
                "first, then look at what %s did."
                % (flagged, "" if flagged == 1 else "s",
                   "it" if flagged == 1 else "them",
                   "it" if flagged == 1 else "they"))]
        else:
            L += term.wrap("Every logged caller is on your list.")
    elif any(p["callers"] for p in result["providers"]):
        L += [DIM(x) for x in term.wrap(
            "Pass --mine with your addresses or ranges (an office, a VPN, CI) "
            "to mark the callers that are not yours. ranwhat does not look up "
            "your address itself, since that would mean asking someone else.")]
    L.append("")
    return "\n".join(L)
