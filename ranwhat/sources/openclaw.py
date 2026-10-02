"""OpenClaw: per-agent SQLite stores (design 3.9 and 7.2).

OpenClaw keeps per-agent transcripts in SQLite at
  $OPENCLAW_STATE_DIR/agents/<agentId>/agent/openclaw-agent.sqlite
documented only as "append-only, tree-structured (id + parentId)" holding
conversation, tool calls and compaction summaries. The table and column
names are not documented, and pinning them from a guess would break on the
next release. So the schema is discovered at runtime and tool calls are
recognised by shape rather than by column name.

The database is opened read-only. It belongs to a running agent.

Ported from watch with no change in what is read; watch keeps its names
(openclaw_state_dir, openclaw_databases, scan_openclaw_db, _find_tool_calls,
_as_iso) for these. It is not searched for secrets yet (searched = False):
check says so under its report, as before.

Nothing here imports watch or clean at import time.
"""

from __future__ import annotations

import datetime
import glob
import json
import os
import re
import sqlite3

from . import _paths, _sqlite, _stamps
from .base import Source, Store, ToolCall, newest_first

ENV = "OPENCLAW_STATE_DIR"

# Resolved once, at import, as watch resolved it.
STATE_DEFAULT = os.path.expanduser("~/.openclaw")


def state_dir():
    """Read the env var when asked, not at import time -- a caller that sets
    OPENCLAW_STATE_DIR after importing was silently ignored."""
    return os.environ.get(ENV, STATE_DEFAULT)


# Keys that carry a tool's name, and keys that carry its arguments, across the
# shapes in circulation (Anthropic tool_use, OpenAI function calls, and the
# various framework wrappers).
NAME_KEYS = ("name", "toolName", "tool_name", "tool", "function_name")
ARG_KEYS = ("input", "arguments", "args", "params", "parameters", "toolInput")


def databases(state_dir_=None):
    """Every agent's database under the state directory (default:
    state_dir()), in name order."""
    root = state_dir_ or state_dir()
    return sorted(glob.glob(os.path.join(
        root, "agents", "*", "agent", "openclaw-agent.sqlite")))


def agent_id(path):
    """The agent a database belongs to: the directory under agents/."""
    marker = os.sep + "agents" + os.sep
    return path.split(marker)[-1].split(os.sep)[0] if marker in path else "openclaw"


TIME_COL = re.compile(r"^(created_?at|timestamp|ts|time|updated_?at|date)$", re.I)


def time_columns(conn, table):
    return [r[1] for r in conn.execute("PRAGMA table_info(%s)"
                                       % _sqlite.quote_ident(table))
            if TIME_COL.match(r[1] or "")]


def as_iso(value):
    """Rows carry epoch seconds, epoch millis or an ISO string depending on
    the writer. Normalise what we can and drop what we cannot.

    Kept as it was: a number above 1e11 is taken for milliseconds, which is
    right for OpenClaw and wrong for microseconds (_stamps.iso_utc takes
    each adapter's own unit instead)."""
    if value in (None, ""):
        return None
    if isinstance(value, str):
        if not value[:4].isdigit():
            return None
        # Converted to UTC and marked so, as Claude Code's stamps are, so
        # render can show it in the reader's zone. A stamp with no zone is
        # left without one: which zone it meant is not known.
        when, zoned = _stamps.parse_stamp(value)
        if zoned:
            try:
                return when.astimezone(datetime.timezone.utc).strftime(
                    "%Y-%m-%dT%H:%M:%SZ")
            except (ValueError, OverflowError):
                pass
        return value[:19]
    try:
        n = float(value)
    except (TypeError, ValueError):
        return None
    if n > 1e11:          # milliseconds
        n /= 1000.0
    if n < 1e8:           # not a plausible epoch
        return None
    try:
        return datetime.datetime.fromtimestamp(
            n, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (ValueError, OverflowError, OSError):
        return None


def text_columns(conn, table):
    cols = []
    for row in conn.execute("PRAGMA table_info(%s)" % _sqlite.quote_ident(table)):
        name, ctype = row[1], (row[2] or "").upper()
        if ctype in ("", "TEXT", "BLOB", "JSON") or "CHAR" in ctype:
            cols.append(name)
    return cols


def find_tool_calls(obj, depth=0):
    """Recognise tool calls by shape, anywhere in a decoded JSON structure.

    Deduplicated: an OpenAI-style {"function": {...}} matches both the explicit
    branch and the generic walk that recurses into it.
    """
    found = _find_tool_calls_raw(obj, depth)
    out, seen = [], set()
    for name, args in found:
        key = (name, json.dumps(args, sort_keys=True, default=str)[:512])
        if key not in seen:
            seen.add(key)
            out.append((name, args))
    return out


def _find_tool_calls_raw(obj, depth=0):
    found = []
    if depth > 8:
        return found
    if isinstance(obj, list):
        for item in obj:
            found.extend(_find_tool_calls_raw(item, depth + 1))
        return found
    if not isinstance(obj, dict):
        return found

    # OpenAI-style: {"function": {"name": ..., "arguments": "<json string>"}}
    fn = obj.get("function")
    if isinstance(fn, dict) and any(k in fn for k in NAME_KEYS):
        args = fn.get("arguments")
        if isinstance(args, str):
            try:
                args = json.loads(args)
            except ValueError:
                args = {"_raw": args}
        found.append((str(next(fn[k] for k in NAME_KEYS if k in fn)), args or {}))

    name = next((obj[k] for k in NAME_KEYS if isinstance(obj.get(k), str)), None)
    args = next((obj[k] for k in ARG_KEYS if isinstance(obj.get(k), (dict, str))), None)
    if name and args is not None:
        if isinstance(args, str):
            try:
                args = json.loads(args)
            except ValueError:
                args = {"_raw": args}
        if obj.get("type") in (None, "tool_use", "tool_call", "function_call", "tool"):
            found.append((name, args))

    for value in obj.values():
        if isinstance(value, (dict, list)):
            found.extend(_find_tool_calls_raw(value, depth + 1))
        elif isinstance(value, str) and value[:1] in ("{", "["):
            try:
                found.extend(_find_tool_calls_raw(json.loads(value), depth + 1))
            except ValueError:
                pass
    return found


class OpenClawSource(Source):
    id = "openclaw"
    name = "OpenClaw"
    unit = "database"
    env = (ENV,)
    path_means = ("an OpenClaw state directory, the one --state-dir takes "
                  "(default ~/.openclaw)")
    searched = False

    def default_paths(self, env, home, platform):
        """$OPENCLAW_STATE_DIR when set, else ~/.openclaw: what state_dir()
        reads."""
        if ENV in env:
            return [(env[ENV], "env " + ENV)]
        return [(_paths.join(platform, home, ".openclaw"), "default")]

    def store_at(self, path):
        """The Store for one database, whether or not it can be stat'ed: one
        that cannot be opened is warned about when it is read, as before."""
        try:
            mtime = os.path.getmtime(path)
        except OSError:
            mtime = 0.0
        return Store(self.id, path, "sqlite", unit=self.unit,
                     session=agent_id(path), mtime=mtime)

    def stores(self, locations, since_days=None):
        """Every database, whatever its mtime: a live agent's recent rows
        can sit in its -wal file while the database itself looks old."""
        found = []
        for loc in locations:
            found += [self.store_at(path) for path in databases(loc.path)]
        return newest_first(found, since_days)

    def tool_calls(self, store):
        """Every tool call found by shape in a JSON text cell, in table and
        row order, with the row's time (as_iso of its first time column
        that reads as one). session is the agent, project the table. An
        input that is not an object is {"_value": input}, as watch has
        always judged it. A database that cannot be opened or read warns
        and yields nothing; the copy a locked one is read from is removed."""
        path = store.path
        conn, tmpdir = _sqlite.open_readonly(path)
        if conn is None:
            self.warn(path, "could not open %s (permissions, or the agent "
                            "holds it locked)" % path)
            return
        agent = agent_id(path)
        try:
            try:
                tables = [r[0] for r in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' "
                    "AND name NOT LIKE 'sqlite_%'")]
            except sqlite3.Error as e:
                # Not a database, encrypted, or truncated mid-write. One bad
                # file must not take the rest of the scan down with it.
                self.warn(path, "cannot read %s (%s)" % (path, e))
                return
            for table in tables:
                cols = text_columns(conn, table)
                if not cols:
                    continue
                tcols = time_columns(conn, table)
                quoted = ", ".join(_sqlite.quote_ident(c) for c in cols + tcols)
                try:
                    rows = conn.execute("SELECT %s FROM %s"
                                        % (quoted, _sqlite.quote_ident(table)))
                except sqlite3.Error:
                    continue
                n_text = len(cols)
                for row in rows:
                    stamp = next((as_iso(v) for v in row[n_text:]
                                  if as_iso(v)), None)
                    for cell in row[:n_text]:
                        if not isinstance(cell, (str, bytes)):
                            continue
                        if isinstance(cell, bytes):
                            try:
                                cell = cell.decode("utf-8")
                            except UnicodeDecodeError:
                                continue
                        if cell[:1] not in ("{", "["):
                            continue
                        try:
                            payload = json.loads(cell)
                        except ValueError:
                            continue
                        for tool, tool_input in find_tool_calls(payload):
                            if not isinstance(tool_input, dict):
                                tool_input = {"_value": tool_input}
                            yield ToolCall(self.id, path, tool, tool_input,
                                           session=agent, project=table,
                                           timestamp=stamp)
        finally:
            _sqlite.close(conn, tmpdir)
