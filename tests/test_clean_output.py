"""What the clean report and its review look like on a terminal.

At RANWHAT_WIDTH=50 the clean section printed 19 lines wider than the
terminal: the header, the rotation paragraph, the finding rows and the paths
under them. The review wrapped nothing either: `show` printed a
103-character transcript path at width 80, and `list` padded labels to 24
columns, so a longer label pushed its row out of line. The rotation advice
was written with em dashes. Every value here is synthetic.
"""
import io
import json
import os
import re
import shutil
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import isolated_home  # noqa: E402,F401  ranwhat's state, never ~/.ranwhat
import agents_fixtures as af  # noqa: E402
from ranwhat import clean, term

ANSI = re.compile(r"\033\[[0-9;]*m")
EM_DASH = "\u2014"

TRANSCRIPT = ("/Users/someone/.claude/projects/-Users-someone-Desktop-a-fairly-"
              "long-project-name/0b8e7a1c-2f3d-4e5f-8a9b-0c1d2e3f4a5b.jsonl")
LONG_LABEL = "SUPER_LONG_APPLICATION_SIGNING_SECRET_KEY_FOR_PRODUCTION_USE"


def _finding(n, label, hint, length, count, origins=(), projects=("/p",),
             files=("/x/s.jsonl",)):
    return {"fingerprint": "%012x" % n, "label": label, "length": length,
            "hint": hint, "files": set(files), "origins": set(origins),
            "projects": set(projects), "count": count}


def _findings(*rows):
    return {f["fingerprint"]: f for f in rows}


FINDINGS = _findings(
    _finding(1, "OpenAI/Anthropic-style API key", "sk-…83", 33, 6,
             origins=("/Users/someone/Desktop/WebScraper/services/api/.env",
                      "C:\\Users\\someone\\projects\\service\\.aws\\credentials"),
             projects=("/Users/someone/Desktop/WebScraper",
                       "/Users/someone/Desktop/a-fairly-long-project-name/nested",
                       "/p/three"),
             files=(TRANSCRIPT, "/x/s.jsonl")),
    _finding(2, LONG_LABEL, "b9…a", 64, 2, origins=("api/.env",)),
    _finding(3, "AWS access key ID", "AKIA…Z2WB", 20, 1),
    _finding(4, "connection string password", "Xk…7", 11, 1),
    _finding(5, "SOMETHING_ELSE_TOKEN", "q…x", 24, 1),
)

# Every review command that prints, and a mistyped one that echoes back.
COMMANDS = ["help", "list", "rotate", "show 1", "show 2", "show 3", "show 5",
            "show 99", "frobnicate-" * 8]


def _lines(text):
    return ANSI.sub("", text).split("\n")


def _review(findings, commands, width):
    out = io.StringIO()
    with mock.patch.dict(os.environ, {"RANWHAT_WIDTH": width}), \
         mock.patch("builtins.input",
                    side_effect=list(commands) + [EOFError()]):
        clean.review(findings, 1, stream=out)
    return out.getvalue()


def _render(width, *args, **kw):
    with mock.patch.dict(os.environ, {"RANWHAT_WIDTH": width}):
        return clean.render(*args, **kw)


class _Width(unittest.TestCase):

    WIDTHS = ("50", "80")

    def assertFits(self, text, width):
        with mock.patch.dict(os.environ, {"RANWHAT_WIDTH": width}):
            limit = term.width()
        for line in _lines(text):
            self.assertLessEqual(len(line), limit, (width, line))
            self.assertEqual(line, line.rstrip(), (width, line))


class ReportFitsTheTerminal(_Width):

    def test_dry_run(self):
        for width in self.WIDTHS:
            self.assertFits(_render(width, FINDINGS, 5, [], False), width)

    def test_as_check_prints_it(self):
        for width in self.WIDTHS:
            self.assertFits(_render(width, FINDINGS, 5, 0, False,
                                    footer=False, advice=False), width)

    def test_applied_with_a_long_backup_path(self):
        backups = "/Users/someone/Library/Application Support/ranwhat/backups"
        with mock.patch.object(clean, "BACKUP_ROOT", backups):
            for width in self.WIDTHS:
                text = _render(width, FINDINGS, 5, ["/a", "/b"], True)
                self.assertFits(text, width)
                self.assertIn("backups", text)

    def test_applied_says_the_backups_still_hold_the_values(self):
        # The warning came in as one 82-column line; it is wrapped like
        # every other, down to the narrowest terminal.
        for width in ("46",) + self.WIDTHS:
            text = _render(width, FINDINGS, 5, ["/a"], True)
            self.assertFits(text, width)
            folded = " ".join(" ".join(_lines(text)).split())
            self.assertIn("They still hold every masked value. Delete them "
                          "once the transcripts look right.", folded)

    def test_nothing_found(self):
        for width in self.WIDTHS:
            self.assertFits(_render(width, {}, 5, [], False), width)

    def test_each_read_only_file_is_named(self):
        """The report said how many read-only files of an agent held a
        secret, and which to delete only in --json and the review."""
        from ranwhat.sources.base import Store
        snapshot = ("/Users/someone/.codex/shell_snapshots/"
                    "0b8e7a1c-2f3d-4e5f-8a9b-0c1d2e3f4a5b.1a2b3c.sh")
        database = ("/Users/someone/.openclaw/agents/a-rather-long-agent-name/"
                    "agent/openclaw-agent.sqlite")
        read_only = {
            snapshot: Store("codex", snapshot, "text", role="side",
                            masking="read-only",
                            why_read_only="Codex's snapshot of your shell."),
            database: Store("openclaw", database, "sqlite")}
        for width in ("46", "60", "80"):
            text = _render(width, FINDINGS, 5, [], False, read_only=read_only)
            self.assertFits(text, width)
            lines = _lines(text)
            for path in (snapshot, database):
                named = [l for l in lines if l.startswith("      ")
                         and l.strip().endswith(path[-20:])]
                self.assertEqual(len(named), 1, (width, path))

    def test_no_backups_are_named_when_nothing_was_masked(self):
        text = _render("80", FINDINGS, 5, [], True)
        self.assertIn("Masked in 0 file(s).", text)
        self.assertNotIn("Backups:", text)
        self.assertNotIn("They still hold every masked value.", text)

    def test_the_cli_at_both_widths(self):
        root = tempfile.mkdtemp(prefix="clean-out-")
        self.addCleanup(shutil.rmtree, root, True)
        proj = os.path.join(root, "-Users-someone-Desktop-a-fairly-long-"
                                  "project-name-with-several-more-parts")
        os.makedirs(proj)
        rows = [{"message": {"content": [{
                    "type": "tool_use", "id": "t1", "name": "Bash",
                    "input": {"command": "cat /Users/someone/Desktop/"
                                         "WebScraper/services/api/.env"}}]}},
                {"message": {"content": [{
                    "type": "tool_result", "tool_use_id": "t1",
                    "content": "OPENAI_API_KEY=sk-" + "Zq8Lr2Vt6Xp4Nm1Kb7Hc3Jd9Fw5\n"
                               "AWS_ACCESS_KEY_ID=AKIA" "4TRUE7KEYX9QZ2WB\n"}]}}]
        with open(os.path.join(proj, "s.jsonl"), "w", encoding="utf-8") as fh:
            for r in rows:
                fh.write(json.dumps(r) + "\n")
        from ranwhat import cli
        import contextlib
        for width in self.WIDTHS:
            out = io.StringIO()
            with mock.patch.dict(os.environ, {"RANWHAT_WIDTH": width}), \
                 contextlib.redirect_stdout(out):
                cli.main(["clean", "--no-interactive", "--root", root])
            self.assertFits(out.getvalue(), width)
            self.assertIn("OpenAI/Anthropic-style API key", out.getvalue())


class NothingIsLostToTheWidth(unittest.TestCase):

    def test_a_wide_terminal_keeps_one_line_header(self):
        lines = _lines(_render("80", FINDINGS, 5, [], False))
        self.assertIn("  ranwhat clean  · secrets sitting in local transcripts",
                      lines)

    def test_a_narrow_one_moves_the_tagline_under_it(self):
        lines = _lines(_render("50", FINDINGS, 5, [], False))
        i = lines.index("  ranwhat clean")
        self.assertEqual(lines[i + 1], "  secrets sitting in local transcripts")

    def test_the_rotation_warning_is_whole(self):
        prose = " ".join(_render("50", FINDINGS, 5, [], False).split())
        self.assertIn("These must be rotated. They have been written to disk "
                      "in plaintext and sat in a model context you do not "
                      "control. Masking them here stops them leaking again. "
                      "It does not make them safe.", prose)

    def test_a_row_too_wide_puts_its_details_under_the_label(self):
        lines = _lines(_render("50", FINDINGS, 5, [], False))
        i = lines.index("  * OpenAI/Anthropic-style API key")
        self.assertEqual(lines[i + 1], "      sk-…83  33 chars  seen 6x")

    def test_a_label_wider_than_the_line_is_cut_and_marked(self):
        lines = _lines(_render("50", FINDINGS, 5, [], False))
        cut = [l for l in lines if l.startswith("  * SUPER_LONG")]
        self.assertEqual(len(cut), 1)
        self.assertTrue(cut[0].endswith("…"), cut[0])

    def test_paths_keep_their_end(self):
        lines = _lines(_render("50", FINDINGS, 5, [], False))
        read = [l for l in lines if l.startswith("      read from ")]
        self.assertIn("      read from api/.env", read)
        self.assertTrue(any(l.startswith("      read from …")
                            and l.endswith("/services/api/.env") for l in read),
                        read)
        self.assertTrue(any(l.endswith("\\.aws\\credentials") for l in read),
                        read)
        inside = [l for l in lines if l.startswith("      in ")]
        self.assertTrue(any(l.endswith("/nested") and "…" in l for l in inside),
                        inside)

    def test_show_keeps_the_start_and_end_of_a_transcript(self):
        lines = _lines(_review(FINDINGS, ["show 1"], "80"))
        i = lines.index("      transcripts:")
        path = lines[i + 1].strip()
        self.assertIn("…", path)
        self.assertTrue(path.startswith("/Users/someone/"), path)
        self.assertTrue(path.endswith("-0c1d2e3f4a5b.jsonl"), path)

    def test_list_lines_its_columns_up(self):
        rows = _findings(
            _finding(1, "OpenAI/Anthropic-style API key", "sk-…83", 33, 6),
            _finding(2, "AWS access key ID", "AKIA…Z2WB", 20, 2),
            _finding(3, "DB_PASSWORD", "kz…=", 36, 1))
        lines = [l for l in _lines(_review(rows, ["list"], "80"))
                 if re.match(r"^ +[0-9]+ ", l) and "finding(s)" not in l]
        self.assertEqual(len(lines), 3)
        starts = {l.index(f["hint"]) for l, f in
                  zip(lines, sorted(rows.values(), key=lambda f: -f["count"]))}
        self.assertEqual(len(starts), 1, lines)

    def test_list_on_a_narrow_terminal_keeps_every_label_and_hint(self):
        text = "\n".join(_lines(_review(FINDINGS, ["list"], "50")))
        for f in FINDINGS.values():
            self.assertIn(f["hint"], text)
            if f["label"] != LONG_LABEL:
                self.assertIn(f["label"], text)


class ReviewFitsTheTerminal(_Width):

    def test_every_command(self):
        for width in self.WIDTHS:
            self.assertFits(_review(FINDINGS, COMMANDS, width), width)

    def test_masking_one(self):
        root = tempfile.mkdtemp(prefix="clean-out-mask-")
        self.addCleanup(shutil.rmtree, root, True)
        # Masking backs the transcript up first; not into ~/.ranwhat.
        backups = os.path.join(root, "a-rather-long-directory-name-for-backups",
                               "and-another-one", "backups")
        patch = mock.patch.object(clean, "BACKUP_ROOT", backups)
        patch.start()
        self.addCleanup(patch.stop)
        for width in self.WIDTHS:
            path = af.write(os.path.join(root, "s%s.jsonl" % width), [json.dumps(
                {"message": {"content": [{
                    "type": "tool_result",
                    "content": "AWS_ACCESS_KEY_ID=AKIA" "4TRUE7KEYX9QZ2WB\n"}]}})])
            findings, _changed = clean.scan_file(path)
            text = _review(findings, ["mask 1"], width)
            self.assertFits(text, width)
            self.assertIn("masked in 1 file(s).", text)
            self.assertIn("backups", text)


class NoEmDashInRotationAdvice(unittest.TestCase):

    def test_rotate_and_show(self):
        text = _review(FINDINGS, ["rotate"] + ["show %d" % i for i in range(1, 6)],
                       "96")
        self.assertIn("Unknown", text)
        self.assertNotIn(EM_DASH, text)

    def test_every_provider(self):
        for _pattern, advice in clean._PROVIDER:
            self.assertNotIn(EM_DASH, advice)
        self.assertNotIn(EM_DASH, clean._provider_for("nothing matches this"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
