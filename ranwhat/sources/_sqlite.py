"""Reading an agent's SQLite database without ever writing to it.

The database belongs to a running agent. It is opened with mode=ro, never
immutable=1: immutable tells SQLite the file cannot change, so it skips the
-wal file, and a live database's newest turns are in the -wal. Rows are
read from a cursor, never fetchall(). SQLite's JSON1 functions are not
used: filter in Python after a cheap LIKE.
"""

from __future__ import annotations

import contextlib
import os
import shutil
import sqlite3
import tempfile
import urllib.request


def _uri(path):
    """A read-only SQLite URI for `path`. Percent-encoding the path means a
    ?, # or % in it names the file instead of starting a query, a fragment
    or an escape."""
    return "file:%s?mode=ro" % urllib.request.pathname2url(os.path.abspath(path))


def open_readonly(path):
    """(connection, tmpdir), or (None, None) when it cannot be opened.

    Moved from watch._open_readonly. When the read-only open fails (the
    agent holds a lock, or a WAL database whose -shm cannot be created), the
    database, -wal and -shm are copied to a fresh ranwhat-* temp directory
    and the copy is opened instead; tmpdir is that directory, and the caller
    removes it (close() does). A connection to a file that is not a database
    is still returned, as before: SQLite only notices on the first query,
    and the caller's warning names the reason."""
    try:
        conn = sqlite3.connect(_uri(path), uri=True, timeout=5)
        conn.execute("SELECT 1 FROM sqlite_master LIMIT 1")
        return conn, None
    except (sqlite3.Error, ValueError):
        # ValueError: a file name that is not valid UTF-8 cannot be put in
        # a URI. The copy below has a plain name.
        pass
    tmp = tempfile.mkdtemp(prefix="ranwhat-")
    copy = os.path.join(tmp, "store.db")
    try:
        shutil.copy2(path, copy)
        for suffix in ("-wal", "-shm"):
            if os.path.exists(path + suffix):
                shutil.copy2(path + suffix, copy + suffix)
        return sqlite3.connect(_uri(copy), uri=True), tmp
    except (OSError, sqlite3.Error, ValueError):
        # watch._open_readonly returned the directory here, and its caller
        # did not remove it. Nothing is left behind now.
        shutil.rmtree(tmp, ignore_errors=True)
        return None, None


def close(conn, tmpdir):
    """Close what open_readonly returned and remove its temp copy."""
    try:
        if conn is not None:
            conn.close()
    finally:
        if tmpdir:
            shutil.rmtree(tmpdir, ignore_errors=True)


@contextlib.contextmanager
def readonly(path):
    """with readonly(path) as conn: ... conn is None when it cannot be
    opened. The temp copy, if one was made, is removed on the way out."""
    conn, tmpdir = open_readonly(path)
    try:
        yield conn
    finally:
        close(conn, tmpdir)


def quote_ident(name):
    """Escape a SQLite identifier by doubling quotes (watch._quote_ident)."""
    return '"%s"' % name.replace('"', '""')


def tables(conn):
    """Names of the user tables. Raises sqlite3.Error (DatabaseError for a
    file that is not a database) for the caller to report."""
    return [row[0] for row in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' "
        "AND name NOT LIKE 'sqlite_%'")]


def columns(conn, table):
    """Column names of `table`, in order; [] when there is no such table."""
    return [row[1] for row in conn.execute(
        "PRAGMA table_info(%s)" % quote_ident(table))]


def column_types(conn, table):
    """{column: declared type, upper-cased} for `table`."""
    return {row[1]: (row[2] or "").upper() for row in conn.execute(
        "PRAGMA table_info(%s)" % quote_ident(table))}


def iter_rows(conn, table, cols, where="", params=()):
    """Yield one {column: value} dict per row of `table`, read from a cursor.

    `cols` are quoted here. `where` is SQL the adapter wrote itself (a
    constant such as "data LIKE ?"), with its values in `params`; nothing
    read from a store goes into it."""
    sql = "SELECT %s FROM %s" % (", ".join(quote_ident(c) for c in cols),
                                 quote_ident(table))
    if where:
        sql += " WHERE " + where
    names = list(cols)
    for row in conn.execute(sql, tuple(params)):
        yield dict(zip(names, row))
