"""Reading an agent's SQLite database without ever writing to it.

The database belongs to a running agent. It is opened with mode=ro, and
immutable=1 only when it has no -wal: immutable tells SQLite the file
cannot change, so it skips the -wal file, and a live database's newest
turns are in the -wal. Rows are read from a cursor, never fetchall().
SQLite's JSON1 functions are not used: filter in Python after a cheap LIKE.

Text is read as every adapter reads a file: UTF-8, with any byte that is
not UTF-8 kept by surrogateescape. Python's own decoding raised an error
that quoted the whole cell, whatever secret was in it, and stopped the read.
"""

from __future__ import annotations

import contextlib
import os
import shutil
import sqlite3
import tempfile
import weakref
from urllib.parse import quote


def _url_path(path, windows=None):
    """An absolute path as a file: URI's path, percent-encoded, without
    importing urllib.request: check, watch and clean import no network
    module. On Windows, C:\\x\\a b.db is ///C:/x/a%20b.db and
    \\\\server\\share\\x is ////server/share/x. SQLite refuses any URI
    authority but an empty one or localhost, so a UNC path keeps four
    slashes, where Python 3.12 and later's pathname2url gives two."""
    if windows is None:
        windows = os.name == "nt"
    if not windows:
        return quote(path)
    path = path.replace("\\", "/")
    if not path.startswith("//"):
        path = "/" + path
    return "//" + quote(path, safe="/:")


def _uri(path, mode="ro", immutable=False):
    """A SQLite URI for `path`, read-only unless `mode` says otherwise.
    Percent-encoding the path means a ?, # or % in it names the file
    instead of starting a query, a fragment or an escape."""
    uri = "file:%s?mode=%s" % (_url_path(os.path.abspath(path)), mode)
    return uri + "&immutable=1" if immutable else uri


SQLITE_MAGIC = b"SQLite format 3\x00"


def _text(raw):
    """A TEXT cell as a str (the connection's text_factory)."""
    return raw.decode("utf-8", "surrogateescape")


class _Connection(sqlite3.Connection):
    """A connection that closes its cursors when it closes. From Python
    3.11, a connection closed while a cursor is still open (a reader
    stopped mid-table) keeps its file open until the cursor goes, and
    Windows cannot remove a temp copy that is open."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._cursors = weakref.WeakSet()

    def cursor(self, *args, **kwargs):
        cursor = super().cursor(*args, **kwargs)
        self._cursors.add(cursor)
        return cursor

    def execute(self, *args):
        return self.cursor().execute(*args)

    def close(self):
        for cursor in list(self._cursors):
            cursor.close()
        super().close()


def _connect(uri):
    conn = sqlite3.connect(uri, uri=True, timeout=5, factory=_Connection)
    conn.text_factory = _text
    return conn


def _wal_state(path):
    """For a database in WAL mode (byte 18 or 19 of its header is 2):
    "no wal" when its -wal is not there, "no shm" when its -wal is but its
    -shm is not. "empty" for a file with no bytes: SQLite deletes a -wal it
    finds beside one, even on a read-only connection. None when it has
    both, is not in WAL mode, or cannot be read here.

    An agent's SQLite removes both on a clean close. Opened mode=ro then,
    stock SQLite makes them in the agent's folder (a file the agent may not
    be able to open again, made by another user), and Apple's cannot open
    it at all."""
    try:
        with open(path, "rb") as fh:
            head = fh.read(20)
    except OSError:
        return None
    if not head:
        return "empty"
    if len(head) < 20 or not head.startswith(SQLITE_MAGIC):
        return None
    if 2 not in (head[18], head[19]):
        return None
    if not os.path.exists(path + "-wal"):
        return "no wal"
    if not os.path.exists(path + "-shm"):
        return "no shm"
    return None


def _probe(path, immutable):
    """A read-only connection to path that has read the schema, or None."""
    conn = None
    try:
        conn = _connect(_uri(path, immutable=immutable))
        conn.execute("SELECT 1 FROM sqlite_master LIMIT 1")
        return conn
    except (sqlite3.Error, ValueError):
        # ValueError: a file name that is not valid UTF-8 cannot be put in
        # a URI. The copy below has a plain name.
        if conn is not None:
            conn.close()
        return None


def open_readonly(path):
    """(connection, tmpdir), or (None, None) when it cannot be opened.

    Moved from watch._open_readonly. Nothing is ever made beside the
    database: one in WAL mode with no -wal holds all it has in itself, and
    is opened immutable=1 as well, so SQLite neither looks for nor makes a
    -wal or a -shm. So is an empty file, which holds nothing to read and
    beside which SQLite would delete a -wal. When the read-only open fails (the agent holds a lock,
    or a WAL database whose -shm cannot be made), or a -wal has no -shm
    beside it, the database, -wal and -shm are copied to a fresh ranwhat-*
    temp directory and the copy is opened instead, mode=rw, as ranwhat's
    own file: SQLite makes the copy's -shm there. tmpdir is that directory,
    and the caller removes it (close() does). A connection to a file that
    is not a database is still returned, as before: SQLite only notices on
    the first query, and the caller's warning names the reason."""
    state = _wal_state(path)
    if state != "no shm":
        conn = _probe(path, state in ("no wal", "empty"))
        if conn is not None:
            return conn, None
    tmp = tempfile.mkdtemp(prefix="ranwhat-")
    copy = os.path.join(tmp, "store.db")
    try:
        shutil.copy2(path, copy)
        for suffix in ("-wal", "-shm"):
            if os.path.exists(path + suffix):
                shutil.copy2(path + suffix, copy + suffix)
        return _connect(_uri(copy, mode="rw")), tmp
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
