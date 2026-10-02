"""Every local coding agent ranwhat reads, one adapter per agent.

REGISTRY holds them in registry order, which is the order agents are
listed everywhere: `ranwhat sources`, report sentences, --help and the
site's table. ADAPTERS names each adapter by module and class, in that
order, and importing this package registers every one of them.

Nothing here imports ranwhat.watch or ranwhat.clean: watch imports this
package, and clean imports watch.
"""

from __future__ import annotations

import importlib
import re
from collections import OrderedDict

from .base import (Location, MaskResult, SecretText, Source, Store,
                   ToolCall)

__all__ = ["ADAPTERS", "REGISTRY", "Location", "MaskResult", "SecretText",
           "Source", "Store", "ToolCall", "get", "ids", "register",
           "sources", "unregister"]

# (module, class) under ranwhat.sources, in registry order (design 4.2):
#   Claude Code, Codex, Gemini CLI, Copilot CLI, VS Code Copilot, Cline,
#   Roo Code, Kilo Code, OpenCode, Continue, Aider, Goose, Zed, Qwen Code,
#   Grok Build, Droid, Amp, Crush, Kimi Code, Kimi CLI, Pi, Muse Code,
#   Mistral Vibe, Zoo Code, cecli, OpenClaw, grok-dev.
# Only the adapters that exist are listed; a later one goes in at its place
# in that order, not at the end. Claude Code and OpenClaw are not ported yet.
ADAPTERS = (
    ("codex", "CodexSource"),
    ("gemini", "GeminiSource"),
    ("copilot_cli", "CopilotCliSource"),
    ("qwen", "QwenSource"),
    ("grok", "GrokBuildSource"),
    ("droid", "DroidSource"),
    ("kimi_code", "KimiCodeSource"),
    ("kimi", "KimiSource"),
    ("pi", "PiSource"),
    ("muse_code", "MuseCodeSource"),
)

REGISTRY = OrderedDict()

_ID = re.compile(r"[a-z][a-z0-9-]*\Z")


def register(source):
    """Add an adapter (a Source instance or subclass) at the end of the
    registry and return it. Raises ValueError for a duplicate id or a
    source missing what every report needs (id, name, unit, path_means)."""
    instance = source() if isinstance(source, type) else source
    if not isinstance(instance, Source):
        raise ValueError("%r is not a Source" % (source,))
    if not _ID.match(instance.id or ""):
        raise ValueError("source id %r must be lower case letters, digits "
                         "and dashes" % (instance.id,))
    for field in ("name", "unit", "path_means"):
        if not getattr(instance, field, ""):
            raise ValueError("source %r has no %s" % (instance.id, field))
    if instance.id in REGISTRY:
        raise ValueError("source id %r is registered twice" % instance.id)
    REGISTRY[instance.id] = instance
    return source


def unregister(source_id):
    """Remove an adapter (tests register throwaway ones)."""
    REGISTRY.pop(source_id, None)


def get(source_id):
    """The adapter with this id. KeyError names the ids there are."""
    try:
        return REGISTRY[source_id]
    except KeyError:
        raise KeyError("no source %r; known: %s"
                       % (source_id, ", ".join(REGISTRY) or "none")) from None


def ids():
    """Every adapter id, in registry order."""
    return tuple(REGISTRY)


def sources(selected=None):
    """The adapters in registry order, limited to `selected` ids if given."""
    if selected is None:
        return list(REGISTRY.values())
    wanted = set(selected)
    return [s for s in REGISTRY.values() if s.id in wanted]


def _load():
    for module, cls in ADAPTERS:
        register(getattr(importlib.import_module("." + module, __name__), cls))


_load()
