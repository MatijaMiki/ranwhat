"""ranwhat push: send this machine's findings to your account, as metadata.

One opt-in command, run by a person, and never by the hook, watch or check.
It reads what `watch` reads, applies the ignore file as `watch` does, and
sends feed.ranwhat.com (over HTTPS, with this machine's Bearer token) a
document that holds, for each flagged action, only:

  id      the 16 hex characters of watch.action_id: a hash, not the action
  agent   which agent ran it (one of ranwhat sources' ids)
  at      when, as UTC to the second, or null when the agent wrote no time
  hits    the rule id and severity of each rule it tripped

and, for the run as a whole, counts: flagged, ignored (in the ignore file,
counted and never listed), omitted (flagged, but past the cap on what is
listed), unread transcripts, severity, rule, agent and per-agent transcripts
read, the window in days and ranwhat's version. The machine is the token
that signs the request, and the body has no field to name it by anything
else: no hostname, user name, organisation or machine id.

Never in it: a command, a path, evidence, a working directory, a session
id, a project, a tool name or a call id, file contents, a secret.

build() is a constructor, not a filter. It writes the document field by
field from the five values above and reads nothing else from a record, so a
field an adapter adds tomorrow cannot reach the wire: there is nothing to
forget to delete. check() is the same rules the server's allow-list applies
(worker/src/push_schema.js), run here first, so a bug that would make the
server refuse a push is found before anything is sent, and a field that is
not in the allow-list cannot be sent.

This module imports the standard library and watch and sources only. The
HTTP stack (account, feed) is imported inside send() and token(), so
--dry-run, which shows the exact document and sends nothing, never loads it.
"""
from __future__ import annotations

import calendar
import functools
import json
import os
import re
import time
import urllib.parse

from . import sources as sources_mod
from . import term
from . import watch

SCHEMA_V = 1

# push_schema.js's LIMITS.
MAX_BODY = 32768
MAX_ACTIONS = 100
MAX_HITS = 15
MAX_RULE_KEYS = 32
MAX_AGENT_KEYS = 40
MAX_COUNT = 1000000

# What the server keeps and says it keeps (worker/src/push.js RETENTION): the
# latest push whole, and a counts-only summary of earlier ones. Said before
# sending; the server's own answer is what is true.
KEEPS_DAYS = 30
KEEPS_SNAPSHOTS = 30

HOST = "feed.ranwhat.com"
FINDINGS_PAGE = "https://account.ranwhat.com/findings"
TIMEOUT = 20

SEVERITIES = ("medium", "high", "critical")
RANK = {"medium": 1, "high": 2, "critical": 3}

_ID = re.compile(r"[0-9a-f]{16}\Z")
_VERSION = re.compile(r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}[a-z0-9.+-]{0,16}\Z")
_STAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
_FIELD = re.compile(r"/[A-Za-z0-9_/.-]{0,80}\Z")
_LOOPBACK = ("localhost", "127.0.0.1", "::1")

DAY = 86400


class Invalid(Exception):
    """A document the server's allow-list would refuse: a bug in build(),
    found before anything was sent. `field` is a JSON pointer, `reason`
    one of the server's closed set."""

    def __init__(self, field, reason):
        self.field, self.reason = field, reason
        super().__init__("%s at %s" % (reason, field or "/"))


class Refused(Exception):
    """Something stopped the push, and the message says what and what it
    left: whole sentences, for the terminal."""


@functools.lru_cache(maxsize=None)
def rule_ids():
    return frozenset(rule.id for rule in watch.RULES)


@functools.lru_cache(maxsize=None)
def agent_ids():
    return frozenset(sources_mod.ids())


# ---------- building the document ----------

def _utc(epoch):
    """'2026-10-20T13:58:02Z' for seconds since the epoch, or None."""
    try:
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(int(epoch)))
    except (OverflowError, OSError, ValueError, TypeError):
        return None


def _seconds(stamp):
    """Seconds since the epoch of a 'YYYY-MM-DDTHH:MM:SSZ' stamp."""
    return calendar.timegm(time.strptime(stamp, "%Y-%m-%dT%H:%M:%SZ"))


def _hits(record, rules):
    """The valid hits of one record as {rule: severity}, the highest
    severity where a rule appears twice. The rule and the severity of each
    hit, and nothing else of it, is read."""
    found = {}
    hits = record.get("hits")
    for hit in hits if isinstance(hits, list) else ():
        if not isinstance(hit, dict):
            continue
        rule, severity = hit.get("rule"), hit.get("severity")
        if not (isinstance(rule, str) and rule in rules
                and isinstance(severity, str) and severity in RANK):
            continue
        if rule not in found or RANK[severity] > RANK[found[rule]]:
            found[rule] = severity
    return found


def is_fixed(text):
    """Whether a string is one of the fixed words a push is made of: a rule
    id, a severity, an agent id or an action id. cli._watch_scan leaves
    these out of the mask that hides secrets in what it reads, since a mask
    built from fingerprints can match one by its shape alone."""
    return (text in SEVERITIES or text in rule_ids() or text in agent_ids()
            or bool(_ID.match(text)))


def sendable(records):
    """(the records push can describe, how many it cannot): a record whose
    agent is not one ranwhat knows, or with no hit of a known rule and
    severity, is not described, since the server would refuse it."""
    rules, agents = rule_ids(), agent_ids()
    kept, dropped = [], 0
    for record in records:
        if (isinstance(record, dict) and record.get("source") in agents
                and _hits(record, rules)):
            kept.append(record)
        else:
            dropped += 1
    return kept, dropped


def _count(value):
    return value if isinstance(value, int) and not isinstance(value, bool) and value > 0 else 0


def build(records, scanned, unread, ignored, days, version, now=None):
    """The document push sends, from the records `watch` found (after the
    ignore file), the transcripts it read per agent, the ones it could not
    read per agent, how many actions the ignore file left out, the window
    and ranwhat's version. `now` is seconds since the epoch.

    Constructed from scratch: for each record this reads `source`, `id`,
    `timestamp` and, of each hit, `rule` and `severity`, and nothing else."""
    now = time.time() if now is None else now
    generated = _utc(now)
    rules, agents = rule_ids(), agent_ids()
    lo, hi = now - 366 * DAY, now + DAY

    flagged, seen = [], set()
    for record in records:
        if not isinstance(record, dict) or record.get("source") not in agents:
            continue
        hits = _hits(record, rules)
        if not hits:
            continue
        rid = record.get("id")
        rid = rid if isinstance(rid, str) and _ID.match(rid) else None
        if rid is not None:
            if rid in seen:
                continue
            seen.add(rid)
        if len(hits) > MAX_HITS:
            # The allow-list takes at most 15 hits to an action: the highest
            # severities, by rule id inside one.
            keep = sorted(hits, key=lambda r: (-RANK[hits[r]], r))[:MAX_HITS]
            hits = {r: hits[r] for r in keep}
        epoch = watch._epoch(record.get("timestamp"))
        at = _utc(epoch) if epoch is not None else None
        if at is not None and not (lo <= _seconds(at) <= hi):
            at = None            # a clock the server would refuse; not sent
        flagged.append({
            "id": rid, "agent": record["source"], "at": at,
            "hits": [{"rule": r, "severity": hits[r]} for r in sorted(hits)],
            "top": max(RANK[s] for s in hits.values())})

    severity = {"critical": 0, "high": 0, "medium": 0}
    by_rule, by_agent = {}, {}
    for item in flagged:
        for name, rank in RANK.items():
            if rank == item["top"]:
                severity[name] += 1
        by_agent[item["agent"]] = by_agent.get(item["agent"], 0) + 1
        for hit in item["hits"]:
            by_rule[hit["rule"]] = by_rule.get(hit["rule"], 0) + 1

    # Critical before volume, newest first inside a severity, no time last.
    listable = [i for i in flagged if i["id"] is not None]
    listable.sort(key=lambda i: (-i["top"], i["at"] is None,
                                 "" if i["at"] is None else _flip(i["at"]), i["id"]))
    scanned = {a: _count(n) for a, n in (scanned or {}).items()
               if a in agents and _count(n)}

    def document(listed):
        return {
            "v": SCHEMA_V,
            "ranwhat": version,
            "generated_at": generated,
            "window_days": days,
            "counts": {
                "flagged": len(flagged),
                "ignored": _count(ignored),
                "omitted": len(flagged) - len(listed),
                "unread": sum(_count(n) for n in (unread or {}).values()),
                "severity": dict(severity),
                "rules": dict(by_rule),
                "agents": dict(by_agent),
                "scanned": dict(scanned),
            },
            "actions": [{"id": i["id"], "agent": i["agent"], "at": i["at"],
                         "hits": i["hits"]} for i in listed],
        }

    listed = listable[:MAX_ACTIONS]
    doc = document(listed)
    # 100 actions with every rule each can run past the body the server
    # takes. The least severe are counted and not listed, as past the cap.
    while listed and len(dumps(doc)) > MAX_BODY:
        listed = listed[:-1]
        doc = document(listed)
    return doc


def _flip(stamp):
    """A sort key that puts later stamps first inside an ascending sort:
    each digit replaced by its complement (stamps are fixed-width)."""
    return "".join(chr(ord("0") + 9 - int(c)) if c.isdigit() else c for c in stamp)


def dumps(doc, indent=None):
    """The document as text. Compact and sorted when sent, indented when
    --dry-run shows it: the same document, whitespace aside."""
    if indent:
        return json.dumps(doc, sort_keys=True, indent=indent, ensure_ascii=True)
    return json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


# ---------- the allow-list, client copy ----------

def _is_int(value):
    return isinstance(value, int) and not isinstance(value, bool)


def _keys(obj, names, path):
    if not isinstance(obj, dict):
        raise Invalid(path, "type")
    for key in obj:
        if key not in names:
            raise Invalid("%s/%s" % (path, key) if _FIELD.match("%s/%s" % (path, key)) else path,
                          "unknown_key")
    for key in names:
        if key not in obj:
            raise Invalid("%s/%s" % (path, key), "missing")


def _int(value, path, lo, hi):
    if not _is_int(value):
        raise Invalid(path, "type")
    if value < lo or value > hi:
        raise Invalid(path, "range")


def _stamp(value, path):
    if not isinstance(value, str):
        raise Invalid(path, "type")
    if not _STAMP.match(value):
        raise Invalid(path, "format")
    try:
        if _utc(_seconds(value)) != value:
            raise Invalid(path, "format")
    except ValueError:
        raise Invalid(path, "format")
    return _seconds(value)


def _map(value, path, names, limit):
    if not isinstance(value, dict):
        raise Invalid(path, "type")
    if len(value) > limit:
        raise Invalid(path, "too_many")
    for key, n in value.items():
        if key not in names:
            raise Invalid(path, "unknown_value")
        _int(n, "%s/%s" % (path, key), 1, MAX_COUNT)


def check(doc, now=None):
    """Raise Invalid for a document the server's allow-list would refuse.
    Every object takes exactly its keys, no more and no fewer; ids are
    enumerated; the sums agree. The same rules, in the same order, as
    worker/src/push_schema.js validate()."""
    rules, agents = rule_ids(), agent_ids()
    _keys(doc, ("v", "ranwhat", "generated_at", "window_days", "counts", "actions"), "")
    if not _is_int(doc["v"]):
        raise Invalid("/v", "type")
    if doc["v"] != SCHEMA_V:
        raise Invalid("/v", "unsupported_version")
    version = doc["ranwhat"]
    if not isinstance(version, str):
        raise Invalid("/ranwhat", "type")
    if len(version) > 24 or not _VERSION.match(version):
        raise Invalid("/ranwhat", "format")
    generated = _stamp(doc["generated_at"], "/generated_at")
    if now is not None and not (now - 7 * DAY <= generated <= now + DAY):
        raise Invalid("/generated_at", "range")
    _int(doc["window_days"], "/window_days", 1, 365)

    counts = doc["counts"]
    _keys(counts, ("flagged", "ignored", "omitted", "unread", "severity",
                   "rules", "agents", "scanned"), "/counts")
    for name in ("flagged", "ignored", "omitted", "unread"):
        _int(counts[name], "/counts/" + name, 0, MAX_COUNT)
    sev = counts["severity"]
    _keys(sev, ("critical", "high", "medium"), "/counts/severity")
    for name in ("critical", "high", "medium"):
        _int(sev[name], "/counts/severity/" + name, 0, MAX_COUNT)
    if sum(sev.values()) != counts["flagged"]:
        raise Invalid("/counts/severity", "inconsistent")
    _map(counts["rules"], "/counts/rules", rules, MAX_RULE_KEYS)
    _map(counts["agents"], "/counts/agents", agents, MAX_AGENT_KEYS)
    if sum(counts["agents"].values()) != counts["flagged"]:
        raise Invalid("/counts/agents", "inconsistent")
    _map(counts["scanned"], "/counts/scanned", agents, MAX_AGENT_KEYS)

    actions = doc["actions"]
    if not isinstance(actions, list):
        raise Invalid("/actions", "type")
    if len(actions) > MAX_ACTIONS:
        raise Invalid("/actions", "too_many")
    if len(actions) + counts["omitted"] != counts["flagged"]:
        raise Invalid("/actions", "inconsistent")
    ids = set()
    for n, action in enumerate(actions):
        path = "/actions/%d" % n
        _keys(action, ("id", "agent", "at", "hits"), path)
        if not isinstance(action["id"], str):
            raise Invalid(path + "/id", "type")
        if not _ID.match(action["id"]):
            raise Invalid(path + "/id", "format")
        if action["id"] in ids:
            raise Invalid(path + "/id", "duplicate")
        ids.add(action["id"])
        if not isinstance(action["agent"], str):
            raise Invalid(path + "/agent", "type")
        if action["agent"] not in agents:
            raise Invalid(path + "/agent", "unknown_value")
        if action["at"] is not None:
            at = _stamp(action["at"], path + "/at")
            if not (generated - 366 * DAY <= at <= generated + DAY):
                raise Invalid(path + "/at", "range")
        hits = action["hits"]
        if not isinstance(hits, list):
            raise Invalid(path + "/hits", "type")
        if not 1 <= len(hits) <= MAX_HITS:
            raise Invalid(path + "/hits", "too_many" if hits else "range")
        seen = set()
        for m, hit in enumerate(hits):
            hpath = "%s/hits/%d" % (path, m)
            _keys(hit, ("rule", "severity"), hpath)
            if not isinstance(hit["rule"], str):
                raise Invalid(hpath + "/rule", "type")
            if hit["rule"] not in rules:
                raise Invalid(hpath + "/rule", "unknown_value")
            if hit["rule"] in seen:
                raise Invalid(hpath + "/rule", "duplicate")
            seen.add(hit["rule"])
            if not isinstance(hit["severity"], str):
                raise Invalid(hpath + "/severity", "type")
            if hit["severity"] not in RANK:
                raise Invalid(hpath + "/severity", "unknown_value")
    if len(dumps(doc)) > MAX_BODY:
        raise Invalid("", "range")


# ---------- the token ----------

def token():
    """(token, why): RANWHAT_TOKEN, then the token saved by ranwhat login,
    as update reads them. why is 'env' or 'ok' with a token, and for none:
    'none', 'symlink' (never read through) or 'unreadable'. A trailing
    carriage return, from a token copied out of a Windows file, is
    stripped as feed.py strips it."""
    from . import feed
    env = os.environ.get("RANWHAT_TOKEN", "").strip()
    if env:
        return env, "env"
    return feed.saved_token()


# ---------- what is shown ----------

def _days(days):
    return "the last day" if days == 1 else "the last %d days" % days


def _plural(n, one, many):
    return "%d %s" % (n, one if n == 1 else many)


def _clock(stamp):
    return "%s %s UTC" % (stamp[:10], stamp[11:19])


def _rules_text(hits):
    return ", ".join("%s %s" % (h["rule"], h["severity"]) for h in hits)


def render_summary(doc, limit=12, width=None):
    """What push will send, in words, for the person asked to say yes."""
    width = width or term.width()
    counts, actions = doc["counts"], doc["actions"]
    days = doc["window_days"]
    out = ["", "  ranwhat push: findings from %s, as metadata only." % _days(days), "",
           "  To %s, over HTTPS, with this machine's token:" % HOST, ""]
    flagged = counts["flagged"]
    read = sum(counts["scanned"].values())
    if flagged:
        sev = counts["severity"]
        parts = ["%d %s" % (sev[n], n) for n in ("critical", "high", "medium") if sev[n]]
        out.append("    %s: %s" % (_plural(flagged, "flagged action", "flagged actions"),
                                   ", ".join(parts)))
    else:
        out.append("    Nothing flagged in %s (%s read)."
                   % (_days(days), _plural(read, "transcript", "transcripts")))
    if counts["ignored"]:
        n = counts["ignored"]
        out.append("    %d more %s in your ignore file: counted, not listed"
                   % (n, "is" if n == 1 else "are"))
    if counts["omitted"]:
        out.append("    %d flagged are counted, not listed (at most %d actions, the most "
                   "severe first, are listed)" % (counts["omitted"], len(actions)))
    if flagged and counts["scanned"]:
        top = sorted(counts["scanned"].items(), key=lambda kv: (-kv[1], kv[0]))
        text = ", ".join("%s %d" % kv for kv in top[:6])
        if len(top) > 6:
            text += " and %d more" % (len(top) - 6)
        out.append("    Read: " + text)
    out.append("")
    if flagged:
        out += ["  For each flagged action, only these four things:", ""]
        agent_w = max([len(a["agent"]) for a in actions] or [0])
        for action in actions[:limit]:
            when = _clock(action["at"]) if action["at"] else "time unknown".ljust(23)
            head = "    %s  %s  %s  " % (action["id"], when, action["agent"].ljust(agent_w))
            out += term.wrap(_rules_text(action["hits"]), indent=" " * len(head),
                             first=head, limit=width)
        if len(actions) > limit:
            out.append("    ... and %d more. --dry-run prints every one." % (len(actions) - limit))
    else:
        out += term.wrap("That is sent as it is: a clean snapshot, so the page shows "
                         "this machine as clean as of now.", limit=width)
    out.append("")
    out += term.wrap("Never sent: commands, paths, evidence, working directories, "
                     "session ids, file contents, secrets, your hostname or your "
                     "user name.", limit=width)
    out.append("")
    out += term.wrap("Everyone in the organisation this machine is linked to can read "
                     "it at %s. Plus keeps this machine's latest push, and a summary "
                     "of each push for %d days." % (FINDINGS_PAGE, KEEPS_DAYS), limit=width)
    out.append("")
    return "\n".join(out) + "\n"


# ---------- sending ----------

def _endpoint_ok(url):
    """Only feed.ranwhat.com, over HTTPS, or a server on this machine (for
    testing). This request carries a token and a document, not only a
    code, so unlike the other account calls any other host is refused
    before the token is read into a header."""
    try:
        parts = urllib.parse.urlsplit(url)
        host = parts.hostname
    except ValueError:
        return False
    if parts.scheme == "https" and host == HOST:
        return True
    return parts.scheme in ("http", "https") and host in _LOOPBACK


def _tail(said):
    return said + " Nothing was sent."


def _minutes(value):
    try:
        seconds = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    return min(max((seconds + 59) // 60, 1), 1440)


def _says(error):
    return error if isinstance(error, str) and re.match(r"[a-z_]{1,40}\Z", error) else None


def send(doc, tok, timeout=None):
    """POST the document and return the server's answer (a dict with
    status 'stored' or 'unchanged'). Raises Refused, with the sentences
    to print, for anything else."""
    from . import account, feed
    url = account.api_base() + "/push"
    if not _endpoint_ok(url):
        raise Refused("push only talks to %s. RANWHAT_ACCOUNT_URL points "
                      "somewhere else, so nothing was sent." % HOST)
    body = dumps(doc).encode("ascii")
    heard = {}
    try:
        status, reply = account._call("/push", token=tok, payload=body,
                                      timeout=timeout or TIMEOUT, headers_out=heard)
    except account.Unreachable as exc:
        raise Refused("%s. Nothing is known to be stored; running ranwhat push "
                      "again is safe, and says nothing changed if it had arrived."
                      % account._shown(str(exc), 200))
    except feed.FeedError as exc:
        raise Refused("%s Nothing is known to be stored."
                      % (account._shown(str(exc), 200) or "The push could not be sent."))
    error = reply.get("error")
    if status == 200:
        if reply.get("ok") is True and reply.get("status") in ("stored", "unchanged"):
            return reply
        raise Refused("The server's answer was not one ranwhat understands. "
                      "Nothing is known to be stored; running it again is safe.")
    if status == 403 and error in ("plus_required", "team_required"):
        needs = "Plus" if error == "plus_required" else "Team"
        raise Refused("This machine's organisation is on Free. Push is part of "
                      "%s: %s Nothing was sent. ranwhat watch shows the same "
                      "findings here." % (needs, feed._upgrade_link(reply.get("upgrade"))))
    if status == 403 and error == "machine_required":
        raise Refused(_tail("This token is a shared subscription token, not a "
                            "machine's. Push needs a machine linked with ranwhat "
                            "login, or a CI token."))
    if status == 401 or (status == 403 and error in (None, "token_refused", "token_required")):
        raise Refused(_tail("The server did not accept that token: it was revoked, "
                            "has expired, or is not a ranwhat token. Run ranwhat "
                            "login to link this machine again."))
    if status == 404:
        raise Refused(_tail("The server is not taking pushes just now (HTTP 404)."))
    if status == 429:
        if error == "org_full":
            raise Refused(_tail("This organisation already has as many machines "
                                "pushing as the server takes."))
        minutes = _minutes(heard.get("retry-after"))
        when = ("Try again in %s." % _plural(minutes, "minute", "minutes")
                if minutes else "Try again later.")
        raise Refused(_tail("Too many pushes from this machine lately. %s" % when))
    if status == 409 and error == "stale":
        raise Refused("The server already has a newer push from this machine, so "
                      "nothing was changed.")
    if status == 409:
        raise Refused("Another push from this machine was being stored. Try again "
                      "in a moment. Nothing was stored.")
    if status == 413:
        raise Refused("That push is larger than the server takes. That is a bug in "
                      "ranwhat, not something you did. Nothing was stored.")
    if status == 422:
        field = reply.get("field")
        reason = _says(reply.get("reason"))
        where = " at %s" % field if isinstance(field, str) and _FIELD.match(field) else ""
        raise Refused("The server refused what push built (%s%s). That is a version "
                      "mismatch or a bug, not something you did. Run uvx ranwhat for "
                      "the latest release, or write to hello@ranwhat.com. Nothing "
                      "was stored." % (reason or "invalid", where))
    if status >= 500:
        raise Refused("%s answered HTTP %d. Nothing is known to be stored; running "
                      "ranwhat push again is safe." % (HOST, status))
    code = _says(error)
    raise Refused(_tail("The server refused the push (HTTP %d%s)."
                        % (status, ", " + code if code else "")))
