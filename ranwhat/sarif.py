"""SARIF 2.1.0 for what watch and clean find, for code scanning in CI.

check, watch and clean write it with --sarif PATH. Each action watch flags
is one result per rule it tripped, and each secret clean finds is one
result. Nothing goes in that the report does not print: a secret is given
by its hint and length, never by any part of its value past the hint nor
by its fingerprint (for a short password, that unkeyed hash is a
dictionary oracle), and every string of the document is put through the
same masking as what check, watch and clean print.

Agent history lives outside the repository, so a result's location is the
file or project directory it was found in, as a file URI on the machine
that ran it, with the agent and session as its logical location.
"""

from __future__ import annotations

import hashlib
import json
import os
import re

from . import __version__
from . import watch as watch_mod

SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
VERSION = "2.1.0"

# The severities watch gives, lowest first; clean's every finding is
# CRITICAL, as watch's own secret.literal is: a credential in plaintext in
# a file an agent read into a model context.
SEVERITIES = (watch_mod.MEDIUM, watch_mod.HIGH, watch_mod.CRITICAL)
SECRET = watch_mod.CRITICAL

SECRET_RULE = "secret.plaintext"
_SECRET_TITLE = "Secret in plaintext in agent history"
_SECRET_WHY = ("A credential was written to an agent's transcript in "
               "plaintext, and sat in a model context you do not control. "
               "Rotate it: masking stops it leaking again, it does not make "
               "it safe.")

# SARIF's levels, and the security-severity GitHub code scanning ranks by
# (critical from 9.0, high from 7.0, medium from 4.0).
_LEVEL = {watch_mod.CRITICAL: "error", watch_mod.HIGH: "error",
          watch_mod.MEDIUM: "warning"}
_SECURITY_SEVERITY = {watch_mod.CRITICAL: "9.5", watch_mod.HIGH: "8.0",
                      watch_mod.MEDIUM: "5.5"}


def at_least(severity, floor):
    """Whether severity is floor or above it."""
    return (severity in SEVERITIES and floor in SEVERITIES
            and SEVERITIES.index(severity) >= SEVERITIES.index(floor))


def _rule(rid, severity, title, why):
    return {"id": rid, "name": rid,
            "shortDescription": {"text": title},
            "fullDescription": {"text": why},
            "helpUri": "https://ranwhat.com/watch" if rid != SECRET_RULE
                       else "https://ranwhat.com/clean",
            "defaultConfiguration": {"level": _LEVEL[severity]},
            "properties": {"tags": ["security"],
                           "security-severity": _SECURITY_SEVERITY[severity],
                           "problem.severity": severity}}


def _rules():
    rules = [_rule(r.id, r.severity, r.title, r.why) for r in watch_mod.RULES]
    rules.append(_rule(SECRET_RULE, SECRET, _SECRET_TITLE, _SECRET_WHY))
    return rules


def _uri(path):
    """A file URI for an absolute path, or the path as a relative URI."""
    from urllib.parse import quote
    try:
        if os.path.isabs(path):
            import pathlib
            return pathlib.Path(path).as_uri()
    except ValueError:
        pass
    return quote(path.replace(os.sep, "/"))


def _physical(path, mask=None):
    """A location for path, masked before it is made a URI: percent-encoded,
    a value in a file name (s-PASSWORD.jsonl, = as %3D) was not found by the
    mask any more."""
    if mask is not None:
        path = mask(path)
    return {"physicalLocation": {"artifactLocation": {"uri": _uri(path)}}}


# The mask clean writes in a transcript keeps the value's fingerprint, an
# unkeyed hash that is a dictionary oracle for a short password: evidence
# quoting a masked line carries it, whole, or cut at the window's start
# anywhere in "<ranwhat:redacted:" or its hex.
_MARK = "<ranwhat:redacted:"
_WHOLE = re.compile(r"ranwhat:redacted:[0-9a-f]*")
_CUT = re.compile("\u2026([^\\s\u2026]{0,%d}?)[0-9a-f]{1,12}>" % len(_MARK))


def _unmarked(node):
    if isinstance(node, str):
        node = _WHOLE.sub("ranwhat:redacted", node)
        return _CUT.sub(lambda m: ("\u2026" + m.group(1) + ">")
                        if _MARK.endswith(m.group(1)) else m.group(), node)
    if isinstance(node, dict):
        return {_unmarked(k): _unmarked(v) for k, v in node.items()}
    if isinstance(node, list):
        return [_unmarked(v) for v in node]
    return node


def _project_dir(source, project):
    """The directory an action ran in, as watch's report names it: Claude
    Code keeps it as a slug of the path, which is resolved. None where it
    is no absolute path."""
    if not isinstance(project, str) or not project:
        return None
    if source == "claude-code":
        from .clean import project_path
        project = project_path(project)
    return project if os.path.isabs(project) else None


def _id(*parts):
    """A stable id for a result across runs, of what the report already
    prints: never of a value."""
    text = "\0".join("" if p is None else json.dumps(p, sort_keys=True,
                                                      default=str)
                     for p in parts)
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()


def _action_results(records, index, mask=None):
    out = []
    for record in records:
        source = record.get("source") or "claude-code"
        name = watch_mod._SOURCE_NAMES.get(source, source)
        project = record.get("project")
        where = _project_dir(source, project)
        if where:
            project = where
        session = record.get("session")
        when = record.get("timestamp")
        logical = [{"name": str(session), "kind": "session",
                    "fullyQualifiedName": "%s/%s" % (source, session)}] \
            if session else [{"name": source, "kind": "agent"}]
        for hit in record.get("hits", ()):
            severity = hit.get("severity")
            if severity not in _LEVEL:
                continue
            text = "%s (%s), by %s%s%s: %s Evidence: %s" % (
                hit.get("title"), severity, name,
                " in %s" % project if project else "",
                " at %s" % when if when else "",
                hit.get("why"), hit.get("evidence") or "")
            location = {"logicalLocations": logical}
            if where:
                location.update(_physical(where, mask))
            out.append({
                "ruleId": hit.get("rule"),
                "ruleIndex": index.get(hit.get("rule"), -1),
                "level": _LEVEL[severity],
                "message": {"text": text},
                "locations": [location],
                "partialFingerprints": {"ranwhatAction/v1": _id(
                    source, session, when, record.get("tool_call_id"),
                    record.get("tool_name"), hit.get("rule"))},
                "properties": {"severity": severity, "agent": source,
                               "tool": record.get("tool_name")},
            })
    return out


def _secret_results(findings, index, mask=None):
    out = []
    for f in findings:
        label = f.get("label") or "Secret"
        sources = sorted(f.get("sources") or ["claude-code"])
        text = "%s in plaintext: %s, %d chars, seen %dx. Rotate it." % (
            label, f.get("hint"), f.get("length") or 0, f.get("count") or 0)
        origins = sorted(f.get("origins") or ())
        if origins:
            text += " Read from %s." % ", ".join(origins)
        files = sorted(f.get("files") or ())
        # Up to ten, as GitHub code scanning shows them.
        locations = [_physical(path, mask) for path in files[:10]] or [
            {"logicalLocations": [{"name": s, "kind": "agent"} for s in sources]}]
        out.append({
            "ruleId": SECRET_RULE,
            "ruleIndex": index[SECRET_RULE],
            "level": _LEVEL[SECRET],
            "message": {"text": text},
            "locations": locations,
            "partialFingerprints": {"ranwhatSecret/v1": _id(
                label, f.get("hint"), f.get("length"),
                sorted(f.get("projects") or ()))},
            "properties": {"severity": SECRET, "agents": sources},
        })
    return out


def document(records=(), findings=(), mask=None):
    """The SARIF log for watch's records and clean's findings (each a
    finding as cli._finding_json gives it, or as clean keeps it), every
    string in it put through mask."""
    rules = _rules()
    index = {r["id"]: i for i, r in enumerate(rules)}
    results = (_action_results(records, index, mask)
               + _secret_results(findings, index, mask))
    doc = {"$schema": SCHEMA, "version": VERSION, "runs": [{
        "tool": {"driver": {"name": "ranwhat", "version": __version__,
                            "semanticVersion": __version__,
                            "informationUri": "https://ranwhat.com",
                            "rules": rules}},
        "results": results,
        "columnKind": "unicodeCodePoints",
    }]}
    if mask is not None:
        from .cli import _masked_strings
        doc = _masked_strings(doc, mask)
    return _unmarked(doc)


def write(path, records=(), findings=(), mask=None):
    """Write the SARIF log to path. Raises OSError where it cannot."""
    doc = document(records, findings, mask)
    data = json.dumps(doc, indent=2, ensure_ascii=False) + "\n"
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(data)
