"""Write worker/feed/catalogue.json: the document the feed server sends to
`ranwhat update`, made from the catalogue in ranwhat/catalog.py and the
overlay in worker/feed/overlay.json.

    python3 scripts/feed.py

The Worker serves the file as it is, so everything the client checks is
settled here, by the client's own code: the schema, every entry's fields,
and the digest, which feed.digest() computes over Python's own JSON
encoding. A test rebuilds the file and fails when the committed copy
differs, so a catalogue change cannot reach main without reaching the feed.

The overlay is what puts the feed ahead of the release: scopes written
since the last one, which subscribers get the day they are added and
everyone else in the next version. It holds catalogue data only, never a
rule, so every rule still ships in the package and runs locally. It is
merged the way catalog.providers() merges a feed, adding scopes and
raising ratings, never lowering one. An entry the client would floor, or
one that rates a bundled scope exactly as the bundle does, is refused here
rather than published to be quietly ignored.

The version names the release the catalogue was last cut from, then the
digest, so subscribers can tell a catalogue that changed between releases.
When the overlay holds anything, the date of its newest entry follows, so
`ranwhat update --status` shows how far past the release the feed runs.
Deterministic: running it twice changes nothing.

At each release, move every overlay entry into ranwhat/catalog.py (its
added and source fields stay behind), empty the overlay's "providers", set
its "after" to the new version, and run this again. The feed then matches
the release until the next scope is written. The overlay's "after" names the
release its entries are newer than, and this refuses to build while it
holds entries and names any other, so a version bump cannot skip the fold.
"""
import datetime
import json
import os
import re
import sys
import urllib.parse

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import ranwhat  # noqa: E402
from ranwhat import catalog, feed  # noqa: E402

OUT = os.path.join(ROOT, "worker", "feed", "catalogue.json")
OVERLAY = os.path.join(ROOT, "worker", "feed", "overlay.json")

# What an overlay entry carries past a catalog.py entry: the day it was
# written, which dates the feed's version, and where the provider documents
# the scope, so whoever folds it into a release can check it again. Neither
# is published; the client keeps only feed.FIELDS.
EXTRA = ("added", "source")
RATINGS = ("authority", "reversible", "blast")
DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


class OverlayError(ValueError):
    pass


def read_overlay(path=OVERLAY):
    """The overlay's providers: provider -> scope -> entry, as written."""
    with open(path, encoding="utf-8") as fh:
        doc = json.load(fh)
    name = os.path.basename(path)
    if not isinstance(doc, dict) or not isinstance(doc.get("providers"), dict):
        raise OverlayError('%s needs a "providers" object.' % name)
    if not isinstance(doc.get("after"), str):
        raise OverlayError('%s needs "after": the release its entries are '
                           'newer than.' % name)
    for provider, scopes in doc["providers"].items():
        if not isinstance(scopes, dict):
            raise OverlayError("Overlay provider %r is not an object." % provider)
    # The fold at each release is otherwise a step someone has to remember:
    # a version bump with entries still here would ship a free release
    # without them, and a feed whose version reads as ahead of it.
    if any(doc["providers"].values()) and doc["after"] != ranwhat.__version__:
        raise OverlayError(
            "%s holds entries newer than %s, and this is %s. Move them into "
            'ranwhat/catalog.py, empty "providers" and set "after" to %s.'
            % (name, doc["after"], ranwhat.__version__, ranwhat.__version__))
    return doc["providers"]


def _dated(where, entry):
    """The two fields catalog.py has no place for, and nothing else."""
    if not isinstance(entry, dict):
        raise OverlayError("Overlay %s is not an object." % where)
    unknown = sorted(set(entry) - set(feed.FIELDS) - set(EXTRA))
    if unknown:
        raise OverlayError("Overlay %s has %s, which no catalogue entry carries."
                           % (where, ", ".join(unknown)))
    missing = [k for k in feed.FIELDS + EXTRA if k not in entry]
    if missing:
        raise OverlayError("Overlay %s is missing %s." % (where, ", ".join(missing)))
    added = entry["added"]
    try:
        if not isinstance(added, str) or not DATE.match(added):
            raise ValueError
        datetime.date(*map(int, added.split("-")))
    except ValueError:
        raise OverlayError("Overlay %s: added must be a date, YYYY-MM-DD." % where)
    source = entry["source"]
    parts = urllib.parse.urlsplit(source) if isinstance(source, str) else None
    if not parts or parts.scheme != "https" or not parts.hostname or re.search(r"\s", source):
        raise OverlayError("Overlay %s: source must be an https link to the "
                           "provider's documentation." % where)


def _rated(where, provider, scope, fields):
    """Refuse what the client would not show as written. These are
    catalog.lookup()'s own rules, so the build and the client cannot
    disagree about what a subscriber sees."""
    bundle = catalog.CATALOG.get(provider, {})
    bundled = bundle.get(scope)
    if bundled is not None:
        _floored(where, bundled, fields, "the bundled entry")
        if all(fields[k] == bundled[k] for k in RATINGS):
            raise OverlayError(
                "Overlay %s rates it as the bundled entry does. New wording "
                "waits for the release." % where)
        return
    # A new key is still floored. Under a bundled wildcard, lookup() floors
    # it at that entry as it floors an exact key, with _no_lower: a blast
    # moved to a value of the same weight is put back, and the bundled label
    # and why with it. _below, which allows that move, is only for a key the
    # bundle cannot resolve and whose own name rates it.
    floor = catalog._resolve(bundle, scope)
    if floor is not None:
        _floored(where, floor, fields, "the bundled wildcard it falls under")
    elif catalog._from_name(scope) and catalog._below(catalog._infer(provider, scope), fields):
        raise OverlayError("Overlay %s rates lower than its own name says. The "
                           "feed can raise a rating, never lower one." % where)


def _floored(where, floor, fields, what):
    """Refuse an entry the client would rewrite at `floor`: one that rates
    lower on any of RATINGS, or moves the blast to a value that counts the
    same, which the client keeps as bundled along with the bundled text."""
    if catalog._no_lower(floor, fields) != fields:
        raise OverlayError(
            "Overlay %s rates lower than %s on at least one of %s, or moves its "
            "blast to one that counts the same, so the client would keep the "
            "bundled rating. The feed can raise a rating, never lower one."
            % (where, what, ", ".join(RATINGS)))


def merge(providers):
    """catalog.CATALOG with the overlay's entries over it, and the newest
    added date among them, or None when there are none. catalog.CATALOG
    itself is not changed."""
    entries = {p: scopes for p, scopes in providers.items() if scopes}
    for provider, scopes in entries.items():
        for scope, entry in scopes.items():
            _dated("%s/%s" % (provider, scope), entry)
    if not entries:
        return {p: dict(scopes) for p, scopes in catalog.CATALOG.items()}, None
    fields = {p: {s: {k: e[k] for k in feed.FIELDS} for s, e in scopes.items()}
              for p, scopes in entries.items()}
    # The client's own checks first, on the entries alone: text, types and
    # the values each rating may take, before any rating is compared.
    try:
        feed.validate({"schema": feed.SCHEMA, "catalogue": fields})
    except feed.FeedError as exc:
        raise OverlayError("Overlay: %s" % exc)
    merged = {p: dict(scopes) for p, scopes in catalog.CATALOG.items()}
    for provider, scopes in fields.items():
        for scope, entry in scopes.items():
            _rated("%s/%s" % (provider, scope), provider, scope, entry)
            # As written: _rated refused anything the client's floor
            # (catalog._no_lower) would have changed.
            merged.setdefault(provider, {})[scope] = entry
    newest = max(e["added"] for scopes in entries.values() for e in scopes.values())
    return merged, newest


def build(overlay=OVERLAY):
    merged, newest = merge(read_overlay(overlay))
    digest = feed.digest(merged)
    version = "%s+%s" % (ranwhat.__version__, digest[:8])
    if newest:
        version += "." + newest
    doc = {
        "schema": feed.SCHEMA,
        "version": version,
        "catalogue": merged,
        "digest": digest,
    }
    feed.validate(doc)          # what the client would refuse never ships
    return json.dumps(doc, indent=1, sort_keys=True, ensure_ascii=False) + "\n"


if __name__ == "__main__":
    try:
        text = build()
    except OverlayError as exc:
        sys.exit("feed.py: %s" % exc)
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)
    print("wrote", os.path.relpath(OUT, ROOT))
