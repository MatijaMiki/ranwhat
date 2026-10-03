"""One session for each agent ranwhat reads through an adapter, written
the way that agent writes it, for the tests that run the whole CLI over
it (design 5.2 and 5.3).

Each Agent writes, under a folder `--path <id>=` takes, a transcript of
the calls it is given: (call id, "shell" or "read", the command or the
path, the output or None, when, in seconds since the epoch). An agent with
no read tool of its own (Codex) runs `cat` on the path instead. The
builders are the adapters' own test modules' builders, which follow each
agent's spec field for field (design 5.1).

Every value is synthetic, and every file is in a temp directory.
"""
import hashlib
import json
import os
import time

import test_source_codex as cx
import test_source_copilot_cli as cp
import test_source_droid as dr
import test_source_gemini as gm
import test_source_grok as gk
import test_source_kimi as km
import test_source_kimi_code as kc
import test_source_muse_code as mu
import test_source_pi as pi
import test_source_qwen as qw

GARBAGE = b"\x00\xff\xfe garbage\n\x89PNG\r\n\x1a\nmore {not json\n" * 4


def iso(when):
    """ISO 8601 in UTC with milliseconds and Z, as the JSON writers give it."""
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(when)) + \
        ".%03dZ" % int(round((when % 1) * 1000) % 1000)


def write(path, data, age=3600):
    """Write `data` (bytes, text, or a list of lines) at path, last
    written `age` seconds ago: past clean's quiet period, so it can be
    masked."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if isinstance(data, list):
        data = "".join(line + "\n" for line in data)
    if isinstance(data, str):
        data = data.encode("utf-8")
    with open(path, "wb") as fh:
        fh.write(data)
    when = time.time() - age
    os.utime(path, (when, when))
    return path


def _uuid(name, n=0):
    digest = hashlib.sha256(("%s:%d" % (name, n)).encode("ascii")).hexdigest()
    return "%s-%s-4%s-8%s-%s" % (digest[:8], digest[8:12], digest[13:16],
                                 digest[17:20], digest[20:32])


class Agent(object):
    id = None
    unit = "session"
    read_tool = True                # False: a read is `cat PATH` in a shell
    byte_arrays = False
    has_read_only = False           # read_only() writes a store

    def root(self, base):
        """The folder `--path <id>=` takes, under base."""
        raise NotImplementedError

    def write(self, root, calls, name="a", age=3600):
        """The transcript holding these calls; its path."""
        raise NotImplementedError

    def garbage(self, root, name="z"):
        """A store the adapter lists that holds garbage; its path."""
        raise NotImplementedError

    def read_only(self, root, secret):
        """A store clean reads and never masks, holding `secret` where a
        key names it; its path, or None when the agent keeps none."""
        return None

    def _as_shell(self, kind, text):
        if kind == "read" and not self.read_tool:
            return "shell", "cat " + text
        return kind, text


class Codex(Agent):
    id = "codex"
    read_tool = False
    has_read_only = True
    DAY = "sessions/2026/10/01/rollout-2026-10-01T14-00-00-%s.jsonl"

    def root(self, base):
        return os.path.join(base, ".codex")

    def _path(self, root, name):
        return os.path.join(root, *(self.DAY % _uuid("codex", ord(name[0])))
                            .split("/"))

    def write(self, root, calls, name="a", age=3600):
        thread = _uuid("codex", ord(name[0]))
        first = min(c[4] for c in calls) - 5 if calls else time.time() - age
        lines = [cx.line(iso(first), "session_meta", cx.meta(thread=thread))]
        for cid, kind, text, output, when in calls:
            kind, text = self._as_shell(kind, text)
            lines.append(cx.line(iso(when), "response_item", cx.fcall(
                "exec_command", {"cmd": text, "workdir": "/home/dev/app"}, cid)))
            if output is not None:
                lines.append(cx.line(iso(when), "response_item",
                                     cx.fout(cid, output)))
        return write(self._path(root, name), lines, age)

    def garbage(self, root, name="z"):
        return write(self._path(root, name), GARBAGE)

    def read_only(self, root, secret):
        """A shell snapshot: Codex's copy of the user's exported variables."""
        return write(os.path.join(root, "shell_snapshots",
                                  _uuid("codex", 97) + ".1a2b3c.sh"),
                     "# exports (native declarations)\nexport GITHUB_TOKEN=%s\n"
                     % secret)


class Gemini(Agent):
    id = "gemini"

    def root(self, base):
        return os.path.join(base, ".gemini")

    def _path(self, root, name):
        return os.path.join(root, "tmp", "proj", "chats",
                            "session-2026-09-30T10-15-%s.jsonl"
                            % _uuid("gemini", ord(name[0]))[:8])

    def write(self, root, calls, name="a", age=3600):
        records = [gm.header(session=_uuid("gemini", ord(name[0])))]
        for cid, kind, text, output, when in calls:
            tool, args = (("run_shell_command", {"command": text})
                          if kind == "shell" else ("read_file", {"file_path": text}))
            records.append(gm.model("m-" + cid, [gm.tool_call(
                cid, tool, args, ts=iso(when), output=output)], ts=iso(when)))
        write(os.path.join(root, "tmp", "proj", ".project_root"), "/Users/alice/proj")
        return write(self._path(root, name), [gm._dump(r) for r in records], age)

    def garbage(self, root, name="z"):
        return write(self._path(root, name), GARBAGE)


class CopilotCli(Agent):
    id = "copilot-cli"

    def root(self, base):
        return os.path.join(base, ".copilot")

    def _path(self, root, name):
        return os.path.join(root, "session-state", _uuid("copilot", ord(name[0])),
                            "events.jsonl")

    def write(self, root, calls, name="a", age=3600):
        first = min(c[4] for c in calls) - 5 if calls else time.time() - age
        log = cp.Log().start(ts=iso(first), sid=_uuid("copilot", ord(name[0])))
        for cid, kind, text, output, when in calls:
            tool, args = (("bash", {"command": text}) if kind == "shell"
                          else ("view", {"path": text}))
            log.call(cid, tool, args, output, ts=iso(when))
        return write(self._path(root, name), log.data(), age)

    def garbage(self, root, name="z"):
        return write(self._path(root, name), GARBAGE)


class Qwen(Agent):
    id = "qwen"
    has_read_only = True

    def root(self, base):
        return os.path.join(base, ".qwen")

    def _path(self, root, name):
        return os.path.join(root, "projects", qw.SANITIZED, "chats",
                            _uuid("qwen", ord(name[0])) + ".jsonl")

    def write(self, root, calls, name="a", age=3600):
        session = _uuid("qwen", ord(name[0]))
        first = min(c[4] for c in calls) - 5 if calls else time.time() - age
        records = [qw.user(1, iso(first), "tidy up", session=session)]
        n = 2
        for cid, kind, text, output, when in calls:
            if kind == "shell":
                tool, args = "run_shell_command", {"command": text}
                shown = None if output is None else qw.shell_output(text, output)
            else:
                tool, args, shown = "read_file", {"file_path": text}, output
            records.append(qw.assistant(n, iso(when), (cid, tool, args),
                                        session=session))
            if output is not None:
                records.append(qw.tool_result(n + 1, iso(when), cid, tool, shown,
                                              session=session))
            n += 2
        return write(self._path(root, name),
                     [json.dumps(r, separators=(",", ":")) for r in records], age)

    def garbage(self, root, name="z"):
        return write(self._path(root, name), GARBAGE)

    def read_only(self, root, secret):
        """An edit backup in file-history/: Qwen Code's own copy of a file
        it changed, kept for /rewind."""
        return write(os.path.join(root, "file-history", _uuid("qwen", 1),
                                  "backup-1"), "API_KEY=%s\n" % secret)


class GrokBuild(Agent):
    id = "grok"
    byte_arrays = True

    def root(self, base):
        return os.path.join(base, ".grok")

    def _folder(self, root, name):
        return os.path.join(root, "sessions", gk.ENC, _uuid("grok", ord(name[0])))

    def write(self, root, calls, name="a", age=3600):
        lines = []
        for cid, kind, text, output, when in calls:
            if kind == "shell":
                built = gk.shell_lines(cid, text, int(when), output=output or "")
            else:
                built = gk.read_lines(cid, text, int(when), content=output or "")
            lines += [gk.line(obj) for obj in built]
        folder = self._folder(root, name)
        write(os.path.join(folder, "summary.json"), json.dumps(
            {"info": {"id": _uuid("grok", ord(name[0])), "cwd": gk.CWD}}), age)
        return write(os.path.join(folder, "updates.jsonl"), lines, age)

    def garbage(self, root, name="z"):
        folder = self._folder(root, name)
        write(os.path.join(folder, "summary.json"), json.dumps(
            {"info": {"id": _uuid("grok", ord(name[0])), "cwd": gk.CWD}}))
        return write(os.path.join(folder, "updates.jsonl"), GARBAGE)


class Droid(Agent):
    id = "droid"

    def root(self, base):
        return os.path.join(base, "droid-home")      # the folder holding .factory

    def _path(self, root, name):
        return os.path.join(root, ".factory", "sessions", "-Users-me-proj",
                            _uuid("droid", ord(name[0])) + ".jsonl")

    def write(self, root, calls, name="a", age=3600):
        records = [dr.header(sid=_uuid("droid", ord(name[0])))]
        n = 1
        for cid, kind, text, output, when in calls:
            tool, args = (("Execute", {"command": text}) if kind == "shell"
                          else ("Read", {"file_path": text}))
            records += dr.call_lines(n, cid, tool, args, output, ts=iso(when))
            n += 2
        return write(self._path(root, name), [dr._dump(r) for r in records], age)

    def garbage(self, root, name="z"):
        return write(self._path(root, name), GARBAGE)


class KimiCode(Agent):
    id = "kimi-code"

    def root(self, base):
        return os.path.join(base, ".kimi-code")

    def _path(self, root, name):
        return os.path.join(root, "sessions", kc.KEY, "s_" + name * 8, "agents",
                            "main", "wire.jsonl")

    def write(self, root, calls, name="a", age=3600):
        first = min(c[4] for c in calls) - 5 if calls else time.time() - age
        records = [kc._meta(int(first * 1000))]
        for cid, kind, text, output, when in calls:
            tool, args = (("Bash", {"command": text}) if kind == "shell"
                          else ("Read", {"path": text}))
            ms = int(when * 1000)
            records.append(kc._call(cid, tool, args, ms))
            if output is not None:
                records.append(kc._result(cid, output, ms + 1))
        return write(self._path(root, name), [kc._j(r) for r in records], age)

    def garbage(self, root, name="z"):
        return write(self._path(root, name), GARBAGE)


class Kimi(Agent):
    id = "kimi"

    def root(self, base):
        return os.path.join(base, ".kimi")

    def _path(self, root, name):
        return os.path.join(root, "sessions", km.md5(km.PROJECT),
                            _uuid("kimi", ord(name[0])), "wire.jsonl")

    def write(self, root, calls, name="a", age=3600):
        lines = [km.WIRE_HEAD]
        for cid, kind, text, output, when in calls:
            tool, args = (("Shell", {"command": text}) if kind == "shell"
                          else ("ReadFile", {"path": text}))
            lines.append(km.wire_call(when, cid, tool, args))
            if output is not None:
                lines.append(km.wire_result(when + 0.5, cid, output))
        return write(self._path(root, name), lines, age)

    def garbage(self, root, name="z"):
        return write(self._path(root, name), GARBAGE)


class Pi(Agent):
    id = "pi"

    def root(self, base):
        return os.path.join(base, ".pi", "agent")

    def _path(self, root, name):
        return os.path.join(root, "sessions", pi.FOLDER,
                            "2026-10-01T09-00-00-000Z_%s.jsonl"
                            % _uuid("pi", ord(name[0])))

    def write(self, root, calls, name="a", age=3600):
        first = min(c[4] for c in calls) - 5 if calls else time.time() - age
        records = [pi.header(sid=_uuid("pi", ord(name[0])), ms=int(first * 1000))]
        n = 1
        for cid, kind, text, output, when in calls:
            tool, args = (("bash", {"command": text}) if kind == "shell"
                          else ("read", {"path": text}))
            ms = int(when * 1000)
            records.append(pi.entry(n, pi.assistant([pi.tool_call(cid, tool, args)],
                                                     ms), ms=ms))
            if output is not None:
                records.append(pi.entry(n + 1, pi.tool_result(cid, tool, output,
                                                              ms + 1), ms=ms + 1))
            n += 2
        return write(self._path(root, name), [pi._dump(r) for r in records], age)

    def garbage(self, root, name="z"):
        return write(self._path(root, name), GARBAGE)


class MuseCode(Agent):
    id = "muse-code"

    def root(self, base):
        return os.path.join(base, "muse")         # the data folder holding sessions/

    def _path(self, root, name):
        return os.path.join(root, "sessions", "2026", "09", "21",
                            _uuid("muse", ord(name[0])), "session.jsonl")

    def write(self, root, calls, name="a", age=3600):
        sid = _uuid("muse", ord(name[0]))
        first = min(c[4] for c in calls) - 5 if calls else time.time() - age
        records = [mu.metadata(1, sid=sid, recorded_at=int(first * 1e6))]
        seq = 2
        for cid, kind, text, output, when in calls:
            tool, args = (("bash", {"command": text}) if kind == "shell"
                          else ("read_file", {"path": text}))
            us = int(when * 1e6)
            message = "44444444-0000-4000-8000-%012d" % seq
            records.append(mu.committed(seq, [mu.tool_call(cid, tool, args)],
                                        message_id=message, recorded_at=us, sid=sid))
            if output is not None:
                records.append(mu.results(seq + 1, [(cid, output)], batch_id=message,
                                          recorded_at=us + 1, sid=sid))
            seq += 2
        return write(self._path(root, name), [mu._dump(r) for r in records], age)

    def garbage(self, root, name="z"):
        return write(self._path(root, name), GARBAGE)


# In registry order.
AGENTS = (Codex(), Gemini(), CopilotCli(), Qwen(), GrokBuild(), Droid(),
          KimiCode(), Kimi(), Pi(), MuseCode())

# The environment variables any adapter reads to find its folder, unset for
# every test that runs the CLI, so only --path points anywhere.
AGENT_ENV = ("CLAUDE_CONFIG_DIR", "OPENCLAW_STATE_DIR", "CODEX_HOME",
             "CODEX_SQLITE_HOME", "GEMINI_CLI_HOME", "COPILOT_HOME",
             "QWEN_HOME", "QWEN_RUNTIME_DIR", "GROK_HOME",
             "FACTORY_HOME_OVERRIDE", "KIMI_CODE_HOME", "KIMI_SHARE_DIR",
             "PI_CODING_AGENT_DIR", "PI_CODING_AGENT_SESSION_DIR",
             "XDG_DATA_HOME", "XDG_CONFIG_HOME", "XDG_STATE_HOME",
             "XDG_CACHE_HOME", "APPDATA", "LOCALAPPDATA")
