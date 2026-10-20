"""Write worker/push/schema.json: the allow-list the Worker's push endpoint
validates against, made from the CLI's own rule and agent lists.

    python3 scripts/push_schema.py

`rules` maps each id in ranwhat/watch.py RULES to its title (the findings
page draws titles from here, never from stored text); `agents` maps each id
in ranwhat/sources.py ids() to its name. Rule and agent ids are enumerated
rather than pattern-matched, so a client bug cannot put a secret in an
agent field. A test rebuilds the file and fails on drift, so a rule or
agent added to the CLI cannot reach main without reaching the allow-list.
Deploy the Worker before releasing a client that knows a new one.
Deterministic, in the format scripts/feed.py writes.
"""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
OUT = os.path.join(ROOT, "worker", "push", "schema.json")

from ranwhat import sources, watch  # noqa: E402


def build():
    doc = {
        "v": 1,
        "severities": ["medium", "high", "critical"],
        "rules": {rule.id: rule.title for rule in watch.RULES},
        "agents": {source.id: source.name for source in
                   (sources.get(i) for i in sources.ids())},
    }
    return json.dumps(doc, indent=1, sort_keys=True, ensure_ascii=False) + "\n"


if __name__ == "__main__":
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(build())
    print("wrote", os.path.relpath(OUT, ROOT))
