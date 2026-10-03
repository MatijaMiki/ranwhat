"""Decompressing zstd, with no dependency.

Python 3.14 has compression.zstd in the standard library. Before that the
`zstd` command is used when one is on PATH, in a folder named in full: never
one in the current directory (_paths.program). Without either, decompress()
returns None, and the adapter counts the store as unreadable and says why:
"needs Python 3.14 or the zstd command". Nothing here compresses anything.
"""

from __future__ import annotations

import subprocess
import threading

from . import _paths

try:                                            # Python 3.14+
    from compression import zstd as _stdlib     # type: ignore
except ImportError:                             # pragma: no cover - by version
    _stdlib = None

# A store is a session transcript, not an archive. More than this after
# decompression is a corrupt or hostile file, and reading it all would
# take the machine's memory with it.
MAX_OUTPUT = 1 << 30

# Seconds the zstd command may take. A transcript decompresses in well under
# a second; a command that hangs must not hang the scan.
TIMEOUT = 120

NEEDS = "needs Python 3.14 or the zstd command"


def _command():
    return _paths.program("zstd")


def available():
    """True when decompress() can work on this machine."""
    return _stdlib is not None or _command() is not None


def decompress(data, limit=MAX_OUTPUT):
    """The decompressed bytes, or None (no decoder, not zstd, truncated, or
    more than `limit` bytes)."""
    if _stdlib is not None:
        return _with_stdlib(data, limit)
    exe = _command()
    if exe is None:
        return None
    return _with_command(exe, data, limit)


def _with_stdlib(data, limit):
    """Frame by frame, so the output is bounded as it is produced."""
    out, total, rest = [], 0, bytes(data)
    if not rest:
        return None
    try:
        while rest:
            d = _stdlib.ZstdDecompressor()
            chunk = d.decompress(rest, max_length=limit - total + 1)
            total += len(chunk)
            if total > limit or not d.eof:
                return None
            out.append(chunk)
            rest = d.unused_data
    except Exception:                   # ZstdError, and anything else it raises
        return None
    return b"".join(out)


def _with_command(exe, data, limit):
    """`zstd -dc --`, fed on a thread and read in chunks, so neither side
    blocks the other and the output is bounded as it arrives."""
    try:
        proc = subprocess.Popen([exe, "-dc", "--"], stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL)
    except (OSError, ValueError):
        return None

    def feed():
        try:
            proc.stdin.write(data)
        except (OSError, ValueError):
            pass
        finally:
            try:
                proc.stdin.close()
            except (OSError, ValueError):
                pass

    feeder = threading.Thread(target=feed, daemon=True)
    timer = threading.Timer(TIMEOUT, proc.kill)
    feeder.start()
    timer.start()
    chunks, total, ok = [], 0, True
    try:
        while True:
            chunk = proc.stdout.read(1 << 16)
            if not chunk:
                break
            total += len(chunk)
            if total > limit:
                ok = False
                proc.kill()
                break
            chunks.append(chunk)
        proc.stdout.close()
        proc.wait()
    except (OSError, ValueError):
        ok = False
        proc.kill()
        proc.wait()
    finally:
        timer.cancel()
        feeder.join(5)
    if not ok or proc.returncode != 0:
        return None
    return b"".join(chunks)
