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
_as_iso) for these. clean searches it for secrets too (design 3.9's
follow-up): every text cell of every table, whatever its column's declared
type, through the same read-only open. It is never masked: a database is
read only.

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
from .base import SecretText, Source, Store, ToolCall, newest_first

ENV = "OPENCLAW_STATE_DIR"

# Resolved once, at import, as watch resolved it.
STATE_DEFAULT = os.path.join(os.path.expanduser("~"), ".openclaw")


def _from_env(env):
    """OPENCLAW_STATE_DIR as OpenClaw reads it: trimmed, and unset when that
    leaves nothing. An empty one was read as the current directory."""
    return (env.get(ENV) or "").strip() or None


def state_dir():
    """Read the env var when asked, not at import time -- a caller that sets
    OPENCLAW_STATE_DIR after importing was silently ignored. "~" is
    expanded, as OpenClaw expands it."""
    value = _from_env(os.environ)
    return os.path.expanduser(value) if value else STATE_DEFAULT


# Keys that carry a tool's name, and keys that carry its arguments, across the
# shapes in circulation (Anthropic tool_use, OpenAI function calls, and the
# various framework wrappers).
NAME_KEYS = ("name", "toolName", "tool_name", "tool", "function_name")
ARG_KEYS = ("input", "arguments", "args", "params", "parameters", "toolInput")

# What clean's report says of a database that holds a secret: why it is
# left as it is, and what to do instead.
WHY_READ_ONLY = ("OpenClaw keeps this in a database; delete the session in "
                 "OpenClaw.")

# Why a database was not read, as the report's notes give it ("1 OpenClaw
# file was not read: not a readable SQLite database.").
NOT_OPENED = "could not be opened"
NOT_DATABASE = "not a readable SQLite database"
DAMAGED = "part of it is damaged"


def databases(state_dir_=None):
    """Every agent's database under the state directory (default:
    state_dir()), in name order. A "~" in it is expanded, as --path's is,
    and its name is matched as it is: "--state-dir ~/oc", which zsh and
    Windows pass on as typed, and "oc [x]" read nothing."""
    root = os.path.expanduser(state_dir_ or state_dir())
    return sorted(glob.glob(os.path.join(
        glob.escape(root), "agents", "*", "agent", "openclaw-agent.sqlite")))


def agent_id(path):
    """The agent a database belongs to: the directory under agents/."""
    marker = os.sep + "agents" + os.sep
    return path.split(marker)[-1].split(os.sep)[0] if marker in path else "openclaw"


TIME_COL = re.compile(r"^(created_?at|timestamp|ts|time|updated_?at|date)$", re.I)


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


def find_tool_calls(obj, depth=0):
    """Recognise tool calls by shape, anywhere in a decoded JSON structure.

    Deduplicated: an OpenAI-style {"function": {...}} matches both the explicit
    branch and the generic walk that recurses into it.
    """
    found = _find_tool_calls_raw(obj, depth)
    out, seen = [], set()
    for name, args in found:
        try:
            dumped = json.dumps(args, sort_keys=True, default=str)[:512]
        except RecursionError:
            # Arguments nested past the stack, which 3.14 decodes, key
            # alike: the OpenAI shape still counts once, at the cost of
            # keeping only the first of two such calls of one name in a cell.
            dumped = "unhashable"
        key = (name, dumped)
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
            except (ValueError, RecursionError):
                args = {"_raw": args}
        try:
            found.append((str(next(fn[k] for k in NAME_KEYS if k in fn)),
                          args or {}))
        except RecursionError:
            pass        # a name nested past the stack is no tool's name

    name = next((obj[k] for k in NAME_KEYS if isinstance(obj.get(k), str)), None)
    args = next((obj[k] for k in ARG_KEYS if isinstance(obj.get(k), (dict, str))), None)
    if name and args is not None:
        if isinstance(args, str):
            try:
                args = json.loads(args)
            except (ValueError, RecursionError):
                args = {"_raw": args}
        if obj.get("type") in (None, "tool_use", "tool_call", "function_call", "tool"):
            found.append((name, args))

    for value in obj.values():
        if isinstance(value, (dict, list)):
            found.extend(_find_tool_calls_raw(value, depth + 1))
        elif isinstance(value, str) and value[:1] in ("{", "["):
            try:
                found.extend(_find_tool_calls_raw(json.loads(value), depth + 1))
            except (ValueError, RecursionError):
                pass
    return found


class OpenClawSource(Source):
    id = "openclaw"
    name = "OpenClaw"
    unit = "database"
    env = (ENV,)
    path_means = ("an OpenClaw state directory, the one --state-dir takes "
                  "(default ~/.openclaw)")
    read_only = True        # SQLite, every store of it

    def default_paths(self, env, home, platform):
        """$OPENCLAW_STATE_DIR when set and not empty, else ~/.openclaw:
        what state_dir() reads."""
        value = _from_env(env)
        if value:
            return [(value, "env " + ENV)]
        return [(_paths.join(platform, home, ".openclaw"), "default")]

    def reset(self):
        Source.reset(self)
        self._unread = set()        # databases counted unreadable this run

    def _unreadable(self, path, reason, message):
        """Count a database that could not be read, or not to its end,
        once a run (watch and clean both read it), and warn once. The
        message never holds what SQLite said: an error can quote a cell."""
        if path not in self._unread:
            self._unread.add(path)
            self.unreadable_store(reason)
        self.warn(path, message)

    def store_at(self, path):
        """The Store for one database, whether or not it can be stat'ed: one
        that cannot be opened is warned about when it is read, as before."""
        try:
            mtime = os.path.getmtime(path)
        except OSError:
            mtime = 0.0
        return Store(self.id, path, "sqlite", unit=self.unit,
                     session=agent_id(path), mtime=mtime,
                     why_read_only=WHY_READ_ONLY)

    def stores(self, locations, since_days=None):
        """Every database, whatever its mtime: a live agent's recent rows
        can sit in its -wal file while the database itself looks old."""
        found = []
        for loc in locations:
            found += [self.store_at(path) for path in databases(loc.path)]
        return newest_first(found, since_days)

    def _rows(self, path):
        """(table, row number, its columns, its cells, its time cells) for
        every row of every table, read through a read-only open of the
        database (_sqlite.open_readonly), from a cursor. Every column is
        read: SQLite keeps text in a column of any declared type, so a cell
        is judged by what it holds. A database that cannot be opened or
        read, or a table that cannot be read to its end, warns, is counted
        (_unreadable), and what was read before it is kept; the next table
        is still read. A virtual table whose module this SQLite lacks is
        passed over: what it holds is in its shadow tables. The copy a
        locked one is read from is removed however the reader stops."""
        conn, tmpdir = _sqlite.open_readonly(path)
        if conn is None:
            self._unreadable(path, NOT_OPENED, "could not open %s "
                             "(permissions, or the agent holds it locked)"
                             % path)
            return
        try:
            try:
                tables = list(conn.execute(
                    "SELECT name, sql FROM sqlite_master WHERE type='table' "
                    "AND name NOT LIKE 'sqlite_%'"))
            except sqlite3.Error as e:
                # Not a database, encrypted, or truncated mid-write. One bad
                # file must not take the rest of the scan down with it.
                self._unreadable(path, NOT_DATABASE, "cannot read %s: %s (%s)"
                                 % (path, NOT_DATABASE, type(e).__name__))
                return
            for table, sql in tables:
                virtual = (sql or "").lstrip()[:14].upper() == "CREATE VIRTUAL"
                index = 0
                try:
                    cols = _sqlite.columns(conn, table)
                    if not cols:
                        continue
                    times = [i for i, c in enumerate(cols)
                             if TIME_COL.match(c or "")]
                    rows = conn.execute("SELECT %s FROM %s" % (
                        ", ".join(_sqlite.quote_ident(c) for c in cols),
                        _sqlite.quote_ident(table)))
                    for row in rows:
                        index += 1
                        yield table, index, cols, row, [row[i] for i in times]
                except sqlite3.Error as e:
                    if virtual and not index:
                        continue
                    self._unreadable(path, DAMAGED,
                                     "stopped reading table %s of %s after "
                                     "%d rows (%s)" % (table, path, index,
                                                       type(e).__name__))
        finally:
            _sqlite.close(conn, tmpdir)

    def tool_calls(self, store):
        """Every tool call found by shape in a JSON text cell, in table and
        row order, with the row's time (as_iso of its first time column
        that reads as one). session is the agent, project the table. An
        input that is not an object is {"_value": input}, as watch has
        always judged it. A database that cannot be opened or read warns,
        is counted and yields nothing; the copy a locked one is read from is
        removed."""
        path = store.path
        agent = agent_id(path)
        rows = self._rows(path)
        try:
            for table, _index, _cols, cells, stamps in rows:
                stamp = next((as_iso(v) for v in stamps if as_iso(v)), None)
                for cell in cells:
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
                    except (ValueError, RecursionError):
                        continue
                    for tool, tool_input in find_tool_calls(payload):
                        if not isinstance(tool_input, dict):
                            tool_input = {"_value": tool_input}
                        yield ToolCall(self.id, path, tool, tool_input,
                                       session=agent, project=table,
                                       timestamp=stamp)
        finally:
            rows.close()

    def secret_texts(self, store):
        """Every text cell of every table (_rows), in table and row order:
        the JSON it holds, decoded, or else the text itself (a BLOB, and
        TEXT, read as UTF-8, any byte that is not UTF-8 kept as it is).
        "where" is "<table> row <n>, <column>". The schema is not
        documented, so no cell is known to be a call's output, and none
        names a file a value was read out of. Never raises: a database that
        cannot be read warns and is counted."""
        rows = self._rows(store.path)
        try:
            for table, index, cols, cells, _stamps in rows:
                for col, cell in zip(cols, cells):
                    if isinstance(cell, bytes):
                        cell = cell.decode("utf-8", "surrogateescape")
                    if not isinstance(cell, str) or not cell:
                        continue
                    node = cell
                    if cell[:1] in ("{", "["):
                        try:
                            node = json.loads(cell)
                        except (ValueError, RecursionError):
                            node = cell
                    yield SecretText(node, where="%s row %d, %s"
                                     % (table, index, col))
        except Exception as e:      # never raise: say so and go on
            # The class only: what an error says can quote a cell.
            self.warn(store.path, "stopped reading %s (%s)"
                      % (store.path, type(e).__name__))
        finally:
            rows.close()
