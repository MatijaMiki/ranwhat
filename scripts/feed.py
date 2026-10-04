"""Write worker/feed/catalogue.json: the document the feed server sends to
`ranwhat update`, made from the catalogue in ranwhat/catalog.py.

    python3 scripts/feed.py

The Worker serves the file as it is, so everything the client checks is
settled here, by the client's own code: the schema, every entry's fields,
and the digest, which feed.digest() computes over Python's own JSON
encoding. A test rebuilds the file and fails when the committed copy
differs, so a catalogue change cannot reach main without reaching the feed.

The version names the release the catalogue was last cut from, then the
digest, so subscribers can tell a catalogue that changed between releases.
Deterministic: running it twice changes nothing.
"""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import ranwhat  # noqa: E402
from ranwhat import catalog, feed  # noqa: E402

OUT = os.path.join(ROOT, "worker", "feed", "catalogue.json")


def build():
    digest = feed.digest(catalog.CATALOG)
    doc = {
        "schema": feed.SCHEMA,
        "version": "%s+%s" % (ranwhat.__version__, digest[:8]),
        "catalogue": catalog.CATALOG,
        "digest": digest,
    }
    feed.validate(doc)          # what the client would refuse never ships
    return json.dumps(doc, indent=1, sort_keys=True, ensure_ascii=False) + "\n"


if __name__ == "__main__":
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(build())
    print("wrote", os.path.relpath(OUT, ROOT))
