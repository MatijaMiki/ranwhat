"""Claude Code: JSONL session transcripts (design 3.9 and 7.1).

Ported from watch with no change in what is read. watch keeps its names
for each piece (claude_projects, discover, _transcripts, transcript_place,
_iter_claude_tool_calls) as these same functions, and judges each call
exactly as before: kind None, its input as recorded. clean still reads a
transcript for secrets with its own scan_file, which credits each secret
to the file it was read out of and masks by re-serialising each line;
mask() here goes through it too.

Nothing here imports watch or clean at import time.
"""

from __future__ import annotations

import glob
import json
import os
import time

from . import _paths
from .base import MaskResult, SecretText, Source, Store, ToolCall, newest_first

ENV = "CLAUDE_CONFIG_DIR"


def projects_dir():
    """Where Claude Code keeps its transcripts. CLAUDE_CONFIG_DIR is Claude
    Code's own override for ~/.claude, and projects/ sits inside it
    wherever it is. Read when asked, like OPENCLAW_STATE_DIR: reading only
    ~/.claude/projects found nothing on such a machine, and said all clear.
    Absolute and joined by os.path, as locations() gives it: on Windows,
    "~/.claude" was C:\\Users\\u/.claude."""
    base = os.environ.get(ENV) or os.path.join("~", ".claude")
    return os.path.abspath(os.path.join(os.path.expanduser(base), "projects"))


def transcripts(root):
    """Every transcript under root: each session's, and each one its
    subagents wrote, under <session>/subagents/ and a workflow's run below
    it. Read only at the first level, everything a subagent ran or saw went
    unread, and check said all clear. Nothing else there is a transcript:
    a workflow's journal.jsonl holds the results its agents returned.
    A "~" in root is expanded, as --path's is, and its name is matched as
    it is: "--root=~/x", which zsh and Windows pass on as typed, and
    "work [old]" read nothing."""
    root = glob.escape(os.path.expanduser(root))
    return (glob.glob(os.path.join(root, "*", "*.jsonl"))
            + glob.glob(os.path.join(root, "*", "*", "subagents", "**",
                                     "agent-*.jsonl"), recursive=True))


def discover(root=None, since_days=None):
    """Transcripts under root (default: projects_dir()), newest first.

    With since_days, only files written inside the window. That is a
    prefilter, not the window itself: a file older than the window cannot
    hold an action inside it, but a recent one can hold old actions, so
    scan_all judges each action by its own time as well.

    One that cannot be stat'ed, a link to nothing or a transcript Claude
    Code removed after it was listed, is passed over, as stores() does:
    it stopped watch, check and clean with a traceback."""
    found = []
    for path in transcripts(root or projects_dir()):
        try:
            found.append((os.path.getmtime(path), path))
        except OSError:
            continue
    found.sort(key=lambda f: f[0], reverse=True)
    cutoff = time.time() - since_days * 86400 if since_days else None
    return [p for mtime, p in found if cutoff is None or mtime >= cutoff]


def place(path):
    """(project, session) a transcript belongs to: the directory it sits in
    under the projects root, and its own name. A subagent's transcript sits
    under <project>/<session>/subagents/, and belongs to that session."""
    parts = os.path.normpath(path).split(os.sep)
    if parts[-1].startswith("agent-") and "subagents" in parts[:-1]:
        at = len(parts) - 2 - parts[-2::-1].index("subagents")   # the last one
        if at >= 2:
            return parts[at - 2], parts[at - 1]
    return (os.path.basename(os.path.dirname(path)),
            os.path.splitext(os.path.basename(path))[0])


def tool_uses(path, unopened=None):
    """(entry, block) for every tool_use block in the transcript, in order.
    A line that is not JSON, not an object, or holds no list of content is
    skipped; a transcript that cannot be opened yields nothing, and is
    handed to `unopened` with the error, when that is given."""
    try:
        fh = open(path, "r", encoding="utf-8", errors="replace")
    except OSError as error:
        if unopened is not None:
            unopened(error)
        return
    with fh:
        for line in fh:
            try:
                entry = json.loads(line)
            except (ValueError, RecursionError):
                continue              # not JSON, or deeper than it reads
            if not isinstance(entry, dict):
                continue              # JSON, but a list or a string: no entry
            msg = entry.get("message")
            if not isinstance(msg, dict):
                continue
            content = msg.get("content")
            if not isinstance(content, list):
                continue
            for block in content:
                if isinstance(block, dict) and block.get("type") == "tool_use":
                    yield entry, block


class ClaudeCodeSource(Source):
    id = "claude-code"
    name = "Claude Code"
    unit = "transcript"
    env = (ENV,)
    path_means = ("a Claude Code projects directory, the one --root takes "
                  "(default ~/.claude/projects)")

    def default_paths(self, env, home, platform):
        """$CLAUDE_CONFIG_DIR/projects when the variable is set and not
        empty, else ~/.claude/projects: what projects_dir() reads."""
        base = env.get(ENV)
        if base:
            return [(_paths.join(platform, base, "projects"), "env " + ENV)]
        return [(_paths.join(platform, home, ".claude", "projects"), "default")]

    def _store(self, path, mtime):
        project, session = place(path)
        return Store(self.id, path, "jsonl", unit=self.unit, session=session,
                     project=project, mtime=mtime)

    def store_at(self, path):
        """The Store for one transcript, whether or not it can be stat'ed:
        one that cannot be read yields no calls, as before the port."""
        try:
            mtime = os.path.getmtime(path)
        except OSError:
            mtime = 0.0
        return self._store(path, mtime)

    def stores(self, locations, since_days=None):
        """Every transcript at those locations (transcripts()), newest
        first. A transcript last written before the window holds nothing
        inside it, so since_days drops it by its mtime, as discover does."""
        found = []
        for loc in locations:
            for path in transcripts(loc.path):
                try:
                    found.append(self._store(path, os.path.getmtime(path)))
                except OSError:
                    continue          # gone since it was listed
        return newest_first(found, since_days)

    def tool_calls(self, store):
        """Every tool_use block, as recorded: kind None, so watch judges it
        by its name exactly as it did before the port, and its input not
        decoded. A name that is not a string is "?", and a time that is not
        one is None: an object there could not be told apart from another."""
        project, session = place(store.path)
        for entry, block in tool_uses(store.path,
                                      lambda e: self.unopened(store, e)):
            tool = block.get("name", "?")
            if not isinstance(tool, str):
                tool = "?"
            stamp = entry.get("timestamp")
            yield ToolCall(self.id, store.path, tool, block.get("input", {}),
                           decode=False, session=session, project=project,
                           timestamp=stamp if isinstance(stamp, str) else None,
                           tool_call_id=block.get("id"))

    def unopened(self, store, error):
        """A transcript that cannot be opened: counted once a run as a file
        not read, and warned about once, whether watch or clean (which
        reads transcripts itself) met it. One deleted since it was listed
        (as Claude Code deletes old ones) has nothing left to read."""
        if isinstance(error, FileNotFoundError):
            return
        reason = error.strerror or type(error).__name__
        if ("open", store.path) not in self._warned:
            self.unreadable_store(reason, store.path)
        self.warn(("open", store.path), "could not read Claude Code "
                  "transcript %s (%s)" % (store.path, reason))

    def secret_texts(self, store):
        """Each line that is JSON, decoded, for a reader that wants every
        string in the transcript. clean does not search Claude Code through
        this: its scan_file credits each secret to the file it was read out
        of, line by line, which needs the calls before it."""
        try:
            fh = open(store.path, "r", encoding="utf-8", errors="replace")
        except OSError:
            return
        with fh:
            for number, line in enumerate(fh, 1):
                try:
                    node = json.loads(line)
                except (ValueError, RecursionError):
                    continue
                yield SecretText(node, where="line %d" % number)

    def mask(self, store, values):
        """Mask these values with clean's own scan_file, which rewrites each
        line it changes by re-serialising it, backs the transcript up
        first, and refuses to install a file it cannot read back."""
        from .. import clean
        wanted = {clean._fingerprint(v): v for v in values if v}
        if not wanted:
            return MaskResult(store.path)
        _findings, changed = clean.scan_file(store.path, apply=True,
                                             only=set(wanted), extra=wanted)
        return MaskResult(store.path, changed=changed)
