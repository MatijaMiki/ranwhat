"""Deletion targets resolved through the command's own earlier statements.

`SB=/private/tmp/.../bs ; rm -rf "$SB"` and `cd /tmp ; rm -rf iconlab` came
from a real machine and both delete a temp directory, yet read as HIGH
because the target alone looks real. Resolving that context is only worth
doing if it can never hide a real deletion, so most of this file is the
other direction: commands that must keep flagging. All values are synthetic.
"""
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import growth  # noqa: E402
from ranwhat import watch  # noqa: E402

H, C = watch.HIGH, watch.CRITICAL


def severity(tool_input):
    """fs.destructive severity for a Bash call shaped like Claude Code's."""
    if isinstance(tool_input, str):
        tool_input = {"command": tool_input, "description": "d",
                      "timeout": 120000}
    hits, _ = watch.evaluate("Bash", tool_input)
    found = [h["severity"] for h in hits if h["rule"] == "fs.destructive"]
    return found[0] if found else None


class Harness(unittest.TestCase):

    def assertSilent(self, cases):
        for cmd in cases:
            with self.subTest(cmd=cmd):
                self.assertIsNone(severity(cmd))

    def assertFlagged(self, cases, level=H):
        for cmd in cases:
            with self.subTest(cmd=cmd):
                self.assertEqual(severity(cmd), level)


class TempDeletionsResolvedFromContextAreSilent(Harness):

    def test_the_real_records(self):
        self.assertSilent([
            'SB=/private/tmp/claude-501/-Users-example/0000/scratchpad/bs ; '
            'rm -rf "$SB" ; mkdir -p "$SB" ; cp -R site build.sh "$SB/"',
            'SB="/private/tmp/claude-501/-Users-example/0000/scratchpad/fp"; '
            'rm -rf "$SB"; mkdir -p "$SB"',
            "cd /tmp ; rm -rf iconlab ; mkdir iconlab ; cd iconlab",
            # The real record writes a heredoc after the rm: that must not
            # block a downgrade it cannot affect.
            "cd /tmp ; rm -rf iconlab ; mkdir iconlab ; cd iconlab ; "
            "cat > notes.txt <<'EOF'\nhello\nEOF",
        ])

    def test_variable_forms(self):
        self.assertSilent([
            "SB='/tmp/work'; rm -rf $SB",
            "D=/tmp/x; rm -rf ${D}",
            'D=/tmp/x; rm -rf "${D}"',
            'D=/tmp/x && rm -rf "$D"',
            'D=/tmp/x\nrm -rf "$D"',
            'set -e; D=/tmp/x; rm -rf "$D"',
            'D=/var/folders/ab/cd/T/tmp.1; rm -rf "$D"',
            'D=/private/var/folders/ab/cd/T/x; rm -rf "$D/sub"',
            'SB=/tmp/x; rm -rf "$SB"/*',
            'SB=/tmp/x; sudo rm -rf "$SB"',
            'SB=/tmp/x; rm -rf "$SB" 2>/dev/null',
            'SB=/tmp/x; ls; rm -rf "$SB"',
            'SB=/tmp/x; rm -rf "$SB"; rm -rf "$SB/y"',
            # An interpreter AFTER the rm cannot have changed what it hit.
            "SB=/tmp/x; rm -rf \"$SB\"; python3 -c 'print(1)'",
        ])

    def test_cd_forms(self):
        self.assertSilent([
            "cd /tmp && rm -rf iconlab && mkdir iconlab",
            "cd /tmp\nrm -rf iconlab",
            "cd /tmp &&\nrm -rf iconlab",
            "cd /tmp ; ls ; rm -rf iconlab",
            "cd /tmp && rm -rf a b c",
            "cd /private/tmp && rm -rf iconlab",
            "cd /tmp/work && rm -rf out2",
            'D=/tmp; cd "$D" && rm -rf iconlab',
        ])

    def test_other_keys_no_longer_bleed_into_the_targets(self):
        """The flattened text ends in `timeout 120000`, which read as two more
        deletion targets, so `rm -rf /tmp/x` from a real Bash call was HIGH
        although the README promises it is silent."""
        self.assertSilent([
            "rm -rf /tmp/x",
            {"command": "rm -rf /tmp/x", "timeout": 60000},
            {"command": "rm -rf /tmp/x", "run_in_background": True,
             "description": "clean"},
            {"timeout": 60000, "command": "rm -rf /tmp/x"},
            {"command": "cd /tmp && rm -rf iconlab", "timeout": 120000},
        ])


class DeletionContextIsResolvedConservatively(Harness):
    """A wrong resolution hides a real deletion, which is worse than noise."""

    def test_real_non_temp_deletions_stay_flagged(self):
        self.assertFlagged([
            "rm -rf .frames ; git add -A",
            "cd /Users/example/code/studio ; rm -rf studio ; npm install",
            "mv '@/components/'*.tsx src/components/ ; rm -rf '@'",
            "rm -rf site/_parts ; ls site/*.html",
            'rm -rf "$HOME/Desktop/.claude-skills-synctest"',
        ])

    def test_values_that_are_not_clean_temp_literals(self):
        self.assertFlagged([
            'rm -rf "$SB"',
            'SB=/Users/example/work; rm -rf "$SB"',
            'SB=~/tmpwork; rm -rf "$SB"',
            'SB=$HOME/x; rm -rf "$SB"',
            'SB=$(mktemp -d); rm -rf "$SB"',
            'SB=`pwd`; rm -rf "$SB"',
            'SB=/tmp/$USER; rm -rf "$SB"',
            'SB=/tmp/../Users/example; rm -rf "$SB"',
            'SB="/tmp/a b"; rm -rf $SB',
            'SB=/tmp; rm -rf "$SB"',
            'SB=/tmp; rm -rf "$SB"/*',
        ])

    def test_uses_that_do_not_expand_to_the_assigned_value(self):
        self.assertFlagged([
            'SB=/tmp/x rm -rf "$SB"',            # prefix: old value expands
            'rm -rf "$SB"; SB=/tmp/x',
            "SB=/tmp/x; rm -rf '$SB'",
            'SB=/tmp/x; rm -rf "$SB2"',
            'SB=/tmp; rm -rf "$SB"2',
            'SB=/tmp/x; rm -rf "$SB"/../../Users/example',
            'SB=/tmp/x; IFS=/; rm -rf $SB',
            'REF=EVIL; EVIL=/etc; rm -rf "${!REF}"',
            'SB=/etc; rm -rf "${SB/etc/tmp}"',
            'SB=/etc; rm -rf "${SB^^}"',
            'SB=/tmp/xEVIL; rm -rf "${SB:0:4}"',
        ])

    def test_reassignment_in_any_form_forgets_the_value(self):
        self.assertFlagged([
            'SB=/tmp/x; SB=/Users/example/work; rm -rf "$SB"',
            'SB=/tmp/x; SB=$(pwd); rm -rf "$SB"',
            'SB=/tmp/x; read SB; rm -rf "$SB"',
            'SB=/tmp/x; unset SB; rm -rf "$SB"',
            'SB=/tmp/x; for SB in ~/a; do :; done; rm -rf "$SB"',
            'SB=/tmp/x; printf -v SB /etc; rm -rf "$SB"',
            'SB=/tmp/x; mapfile SB < f; rm -rf "$SB"',
            'SB=/tmp/x; SB[0]=/etc; rm -rf "$SB"',
            # Escaped or quote-split names are still the name to the shell.
            'SB=/tmp/x; read S\\B <<< /Users/example/proj; rm -rf "$SB"',
            "SB=/tmp/x; read S''B <<< /Users/example/proj; rm -rf \"$SB\"",
            'SB=/tmp/x; export S\\B=/Users/example/proj; rm -rf "$SB"',
            "SB=/tmp/x; typeset S''B=/Users/example/proj; rm -rf \"$SB\"",
            'SB=/tmp/x; printf -v S\\B %s /Users/example/proj; rm -rf "$SB"',
            'SB=/tmp/x; getopts a S\\B; rm -rf "$SB"',
        ])

    def test_declarations_are_not_plain_assignments(self):
        self.assertFlagged([
            'declare SB=/tmp/x; rm -rf "$SB"',
            'local SB=/tmp/x; rm -rf "$SB"',
            'export SB=/tmp/x; rm -rf "$SB"',
        ])

    def test_assignments_that_may_not_have_run(self):
        self.assertFlagged([
            'true || SB=/tmp/x; rm -rf "$SB"',
            'false && SB=/tmp/x; rm -rf "$SB"',
            'SB=/tmp/x | rm -rf "$SB"',
            '(SB=/tmp/x); rm -rf "$SB"',
            'if false; then\nSB=/tmp/x\nfi\nrm -rf "$SB"',
            'SB=/tmp/x; eval "$CMD"; rm -rf "$SB"',
            'SB=/tmp/x; source ./env.sh; rm -rf "$SB"',
        ])

    def test_shell_special_names_are_never_resolved(self):
        """$DIRSTACK is the cwd in bash and zsh ignores USERNAME=..., so the
        assignment says nothing about what the name expands to."""
        self.assertFlagged([
            'HOME=/tmp/fake; rm -rf "$HOME/Documents"',
            'PWD=/tmp/x; rm -rf "$PWD"',
            'DIRSTACK=/tmp/x; rm -rf "$DIRSTACK"',
            'USERNAME=/tmp/x; rm -rf "$USERNAME"',
            '_=/tmp/x; rm -rf "$_"',
        ])
        self.assertEqual(severity('HOME=/tmp/fake; rm -rf "$HOME"'), C)

    def test_a_mixed_deletion_is_judged_by_its_worst_target(self):
        self.assertFlagged([
            'SB=/tmp/x; rm -rf "$SB" ~/Documents',
            "cd /tmp && rm -rf iconlab ~/Documents",
        ])


class CdIsTrustedOnlyWhenItCertainlyRan(Harness):

    def test_only_tmp_and_var_tmp_are_trusted_across_a_semicolon(self):
        """/tmp and /var/tmp exist on every macOS and Linux box; anything else
        may not, and a failed `cd x ; rm -rf y` deletes ./y. This is the one
        relaxation, and it must not widen."""
        self.assertIsNone(severity("cd /tmp ; rm -rf iconlab"))
        self.assertIsNone(severity("cd /var/tmp ; rm -rf iconlab"))
        self.assertFlagged([
            "cd /private/tmp; rm -rf iconlab",   # no /private/tmp on Linux
            "cd /tmp/work ; rm -rf out2",
            "cd /opt/app ; rm -rf build2",
            "cd proj ; rm -rf iconlab",
        ])

    def test_cd_that_may_not_have_run(self):
        self.assertFlagged([
            "cd /tmp/work || true ; rm -rf out2",
            "cd /tmp || rm -rf iconlab",
            "cd /tmp | rm -rf iconlab",
            "cd /tmp & rm -rf iconlab",
            "true || cd /tmp && rm -rf iconlab",
            "false && cd /tmp ; rm -rf iconlab",
            "cd /tmp/work && true ; rm -rf out2",
            "cd /tmp/work && true || rm -rf out2",
            "(cd /tmp) ; rm -rf iconlab",
            "(\ncd /tmp\n)\nrm -rf iconlab",
            "X=$(true; cd /tmp; true) ; rm -rf iconlab",
            'echo "x\ncd /tmp\n" ; rm -rf iconlab',
            "cd() { true; }; cd /tmp; rm -rf iconlab",
            "trap 'cd ~' DEBUG; cd /tmp; rm -rf iconlab",
        ])

    def test_cd_that_was_undone_or_unknown(self):
        self.assertFlagged([
            "cd /tmp ; cd - ; rm -rf iconlab",
            "cd /tmp && cd - && rm -rf src",
            "cd /tmp ; cd ~/proj ; rm -rf iconlab",
            "cd /tmp ; cd ; rm -rf iconlab",
            "cd /tmp ; cd proj ; rm -rf iconlab",
            "cd /tmp ; popd ; rm -rf iconlab",
            "pushd /tmp ; rm -rf iconlab",
            "cd ~ ; rm -rf iconlab",
            "cd $TMPDIR ; rm -rf iconlab",
            'cd "$TMPDIR" && rm -rf iconlab',
            "cd /tmp ; rm -rf iconlab\ncd ~/proj ; rm -rf src",
            # c\d, c''d and c""d are all cd to the shell.
            "cd /tmp; c\\d /Users/example/proj; rm -rf src",
            "cd /tmp; c''d /Users/example/proj; rm -rf src",
            'cd /tmp; c""d /Users/example/proj; rm -rf src',
        ])

    def test_unknown_commands_may_cd(self):
        """oh-my-zsh aliases `-` to `cd -` and zoxide defines `z`: functions
        and aliases from the shell snapshot are invisible in the transcript."""
        self.assertFlagged([
            "cd /tmp ; - ; rm -rf src",
            "cd /tmp && z proj && rm -rf src",
            'SB=/tmp/x; SB=/Users/example/proj bash -c true; rm -rf "$SB"',
        ])

    def test_relative_targets_that_leave_the_directory(self):
        self.assertFlagged([
            "cd /tmp && rm -rf ../Users/example/Documents",
            "cd /tmp && rm -rf .",
            "cd /tmp && rm -rf *",
            "cd /tmp && rm -rf iconlab*",
            "cd /tmp && rm -rf =iconlab",            # zsh: =cmd is a path
        ])

    def test_sudo_does_not_carry_the_cwd(self):
        """sudoers `runcwd` can start sudo in another directory."""
        self.assertFlagged(["cd /tmp && sudo rm -rf iconlab"])


class RmMustBeTheCommandWord(Harness):
    """After `cd /tmp`, an rm run somewhere else is still a real deletion."""

    def test_remote_and_redirected_deletions(self):
        self.assertFlagged([
            "cd /tmp && ssh deploy@example.com rm -rf app",
            'cd /tmp && ssh deploy@example.com "rm -rf app"',
            "cd /tmp && docker exec web rm -rf uploads",
            "cd /tmp && kubectl exec pod -- rm -rf data",
            "cd /tmp && git -C /Users/example/proj rm -rf src",
            "cd /tmp && env -C /Users/example/proj rm -rf src",
            "cd /tmp && sudo -D /Users/example/proj rm -rf src",
            "cd /tmp && sudo -iu example rm -rf Documents",
            'cd /tmp && su - example -c "rm -rf Documents"',
            "cd /tmp && chroot /Users/example/jail rm -rf data",
        ])

    def test_shell_payloads_start_a_fresh_scope(self):
        self.assertFlagged([
            'cd /tmp && bash -c "cd ~ && rm -rf iconlab"',
            # The outer shell expands $SB before bash -c ever sees it.
            'SB=/Users/x; bash -c "SB=/tmp/x; rm -rf $SB"',
        ])


class HiddenTextCannotFakeContext(Harness):
    """The heredoc and interpreter strippers ignore comments and quotes, so
    they can hide a real cd or reassignment from a naive walker."""

    def test_fake_heredoc_inside_a_comment(self):
        self.assertFlagged([
            "cd /tmp\n# <<true\ncd /Users/example/proj\ntrue\nrm -rf src",
            'SB=/tmp/x\n# <<true\nSB=/Users/example/proj\ntrue\nrm -rf "$SB"',
        ])

    def test_fake_interpreter_payload_inside_quotes(self):
        self.assertFlagged([
            "cd /tmp; echo ' python3 -c \"'; cd /Users/example/proj; "
            "echo '\"'; rm -rf src",
            "SB=/tmp/x; echo ' python3 -c \"'; SB=/Users/example/proj; "
            "echo '\"'; rm -rf \"$SB\"",
        ])

    def test_characters_python_strips_but_the_shell_does_not(self):
        """`cd $'/tmp\\r'` fails, and the rm then runs in the project."""
        self.assertFlagged([
            "cd /tmp\r ; rm -rf src",
            "cd /tmp\r\nrm -rf src",
            "cd /tmp ; rm -rf src",
            "cd /tmp\x0c; rm -rf src",
            "cd /tmp\x0b; rm -rf src",
            "cd /tmp ; rm -rf src",
        ])


class AliasesAndOtherDeletions(Harness):

    def test_a_link_made_in_the_same_command(self):
        self.assertFlagged([
            "cd /tmp && ln -s ~ h && rm -rf h/Documents",
            'SB=/tmp/h; ln -sfn ~/Documents "$SB"; rm -rf "$SB"/',
            # Was silent before: the literal /tmp target hid the link.
            "ln -s ~ /tmp/h; rm -rf /tmp/h/Documents",
            'SB=/tmp/h; mv /Users/example/proj "$SB"; rm -rf "$SB"',
            "cd /tmp && python3 -c 'import os;os.symlink(\"/Users/example\","
            "\"h\")' && rm -rf h/proj",
        ])

    def test_an_interpreter_before_the_rm_blocks_resolution(self):
        """It can plant a symlink the walker cannot see. Deliberately
        stricter than the original proposal, which had this silent."""
        self.assertFlagged([
            "python3 -c \"import os; os.chdir('/')\" ; cd /tmp ; rm -rf iconlab",
        ])

    def test_a_temp_rm_does_not_hide_a_deletion_it_cannot_judge(self):
        """The refiner judges rm targets only. A find -delete or shred next to
        a temp rm used to disappear with it."""
        self.assertFlagged([
            "cd /tmp && rm -rf iconlab && find /Users/example/proj -delete",
            'SB=/tmp/x; rm -rf "$SB"; shred -u /Users/example/proj/db',
            "cd /tmp && rm -rf iconlab && git -C /Users/example/proj rm -r src",
            "rm -rf /tmp/x ; find /Users/example/proj -delete",
        ])


class ToolInputShapes(Harness):

    def test_only_scalar_siblings_let_the_command_speak_alone(self):
        self.assertFlagged([
            {"command": ["rm", "-rf", "$SB"]},
            {"command": "rm -rf /tmp/x", "args": "~/Documents"},
            # An argv key continues the command, so it can change what runs.
            {"command": "cd /tmp", "args": "; rm -rf iconlab"},
            {"pre": "x; SB=/tmp/y;", "command": 'rm -rf "$SB"'},
        ])

    def test_argv_list_is_never_resolved(self):
        self.assertEqual(severity({"command": ["sh", "-c",
                                               'SB=/tmp/x; rm -rf "$SB"']}), H)


class PathEscapes(Harness):
    """`..` climbs out of the directory the path names. These were silent."""

    CASES = ["rm -rf /tmp/../Users/example/Documents", "rm -rf build/../src",
             "rm -rf node_modules/../../Documents"]

    def test_through_evaluate(self):
        self.assertFlagged(self.CASES)

    def test_without_tool_input(self):
        for cmd in self.CASES:
            with self.subTest(cmd=cmd):
                self.assertEqual(watch._refine_deletion(cmd, H), H)
                self.assertFalse(watch._is_ephemeral(cmd.split()[-1]))

    def test_without_tool_input_temp_is_still_silent(self):
        self.assertIsNone(watch._refine_deletion("rm -rf /tmp/x", H))


class ResolvedCatastrophicTargetsEscalate(Harness):

    def test_catastrophic(self):
        self.assertFlagged([
            'D=/usr; rm -rf "$D"', "cd / && rm -rf usr",
            "rm -rf /", "rm -rf ~", "rm -rf $HOME",
            "cd /tmp && rm -rf ~", "cd /tmp && rm -rf /",
            'SB=/tmp/x; rm -rf "$SB" /',
        ], level=C)


class TheHomeDirectoryHoweverSpelled(Harness):
    """rm -rf ~ was critical and rm -rf /Users/<you>, the same directory,
    only high; ~/.., which is /Users, was high while /Users was critical.
    The target was matched as written, with no home and no .. resolved."""

    HOME = "/Users/someone"

    def setUp(self):
        patch = mock.patch.object(watch, "_home", return_value=self.HOME)
        patch.start()
        self.addCleanup(patch.stop)

    def test_every_spelling_of_home_or_above_is_critical(self):
        self.assertFlagged([
            "rm -rf /Users/someone", "rm -rf /Users/someone/", "rm -rf /Users/someone/*",
            "rm -rf ~/..", "rm -rf ~/../", "rm -rf ~/./", "rm -rf $HOME/..",
            'rm -rf "$HOME"/..', "rm -rf ${HOME}/..", "rm -rf /Users/someone/..",
            "rm -rf /Users/someone/Documents/..", "rm -rf /Users/someone/Documents/../..",
            "cd /tmp && rm -rf /Users/someone",
        ], level=C)

    def test_what_is_inside_it_is_still_high(self):
        self.assertFlagged([
            "rm -rf /Users/someone/Documents", "rm -rf ~/Documents/old/..",
            "rm -rf ~/../other", "rm -rf /Users/someone2",
        ])

    def test_the_spellings_a_shell_also_reads_as_home(self):
        """\\rm skips an rm -i alias and was not read as rm at all; a
        subshell's ), ${HOME:?}, a brace that lists everything in it, a
        doubled leading slash and ~name were each high."""
        self.assertFlagged([
            "\\rm -rf ~", "\\rm -rf /Users/someone", "(rm -rf ~)", "$(rm -rf ~)",
            'rm -rf "${HOME:?}/"', "rm -rf ${HOME:?}", "rm -rf ${HOME:-/tmp}",
            "rm -rf ~/{*,.*}", "rm -rf ~/.*", "rm -rf //Users/someone",
            "rm -rf ~someone", "rm -rf ~someone/",
        ], level=C)
        self.assertFlagged([
            "\\rm -rf ~/Documents", "(rm -rf ~/Documents)", "rm -rf ~/{a,b}",
            "rm -rf ~someone/Documents", "rm -rf ~other",
        ])


class OtherRulesAreUntouched(unittest.TestCase):

    def test_credential_reads_still_report_through_evaluate(self):
        """evaluate now hands tool_input to every refiner; a refiner that did
        not accept it would raise and stop cred.read from ever reporting."""
        for cmd in ("cat ~/.aws/credentials", "cat .env",
                    'SB=/tmp/x; rm -rf "$SB"; cat ~/.ssh/id_rsa'):
            with self.subTest(cmd=cmd):
                hits, _ = watch.evaluate("Bash", {"command": cmd, "timeout": 1})
                self.assertIn("cred.read", [h["rule"] for h in hits])
        self.assertIsNone(watch._refine_credential("cat .env.example", C, {}))

    def test_a_live_key_next_to_a_temp_deletion_still_reports(self):
        key = "AKIA" + "Q7ZL4MNB2XRT9WVC"
        hits, _ = watch.evaluate("Bash", {
            "command": 'SB=/tmp/x; rm -rf "$SB"; aws configure set k ' + key,
            "timeout": 1})
        rules = [h["rule"] for h in hits]
        self.assertIn("secret.literal", rules)
        self.assertNotIn("fs.destructive", rules)


def _judged(cmd):
    return watch.evaluate("Bash", {"command": cmd, "timeout": 1})


class ResolutionIsLinear(growth.Assertions, unittest.TestCase):

    def test_many_assignments(self):
        """One regex per tracked name per segment took 189s on this shape."""
        self.assertScalesLinearly(
            lambda n: "; ".join("V%d=/tmp/v%d" % (i, i) for i in range(n(3000)))
            + '; rm -rf "$V1"', _judged)

    def test_many_deletions(self):
        self.assertScalesLinearly(
            lambda n: "SB=/tmp/x; " + " ; ".join('rm -rf "$SB"' for _ in range(n(3000))),
            _judged)


class UnderTemp(unittest.TestCase):

    def test_strictly_inside_a_temp_root(self):
        for p in ("/tmp/x", "/tmp/x/*", "/private/tmp/a/b", "/var/tmp/x",
                  "/var/folders/ab/cd", "/private/var/folders/ab"):
            self.assertTrue(watch._under_temp(p), p)
        for p in ("/tmp", "/tmp/", "/tmp/.", "/tmp/*", "/tmp/x*", "/tmp/../x",
                  "/tmp/a/../../Users", "tmp/x", "/Users/x/tmp/y",
                  "/tmp/a b", "/tmp/*/x"):
            self.assertFalse(watch._under_temp(p), p)


if __name__ == "__main__":
    unittest.main(verbosity=2)
