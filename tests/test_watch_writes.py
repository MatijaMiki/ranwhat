"""Writing a credential file is not reading it.

`cat > .env <<'EOF'` was reported as "Credential material accessed", with a
why about secrets now sitting in a model context, and evidence quoting the
internal placeholder `<<REDACTED_HEREDOC`. It was medium rather than
critical only because that placeholder happened to look like redaction.
A write is not a read; a real secret in the body is still reported by
secret.literal, masked; and evidence quotes the command as it was written.

Every value here is synthetic.
"""
# Token-shaped fixtures are written as adjacent literals ("sk_" "live_...")
# so a secret scanner reading this source, GitHub push protection among
# them, does not take a fixture for a leak. Python joins them at compile
# time; the value under test is unchanged.

import os
import random
import string
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ranwhat import clean, watch

B62 = string.ascii_letters + string.digits
_RNG = random.Random(20260929)
STRIPE = "sk_" "live_" + "".join(_RNG.choice(B62) for _ in range(24))

PLACEHOLDERS = ("REDACTED", "FOREIGN_SOURCE")


def hits(command):
    return watch.evaluate("Bash", {"command": command, "description": "d"})[0]


def rules(command):
    return sorted(h["rule"] for h in hits(command))


def cred(command):
    found = [h for h in hits(command) if h["rule"] == "cred.read"]
    return found[0] if found else None


WRITES = [
    "cat > .env <<'EOF'\nPORT=3000\nEOF",
    "cat > .env <<EOF\nPORT=3000\nEOF",
    "cat >.env << \"EOF\"\nPORT=3000\nEOF",
    "cat >> .env <<-EOF\n\tPORT=3000\n\tEOF",
    "cat > api/.env.local <<'EOF'\nPORT=3000\nEOF",
    "tee .env <<EOF\nPORT=3000\nEOF",
    "tee -a .env.local <<'EOF'\nPORT=3000\nEOF",
    "sudo tee /etc/app/.env > /dev/null <<'EOF'\nPORT=3000\nEOF",
    "echo PORT=3000 | tee .env",
    "echo PORT=3000 | tee -a .env .env.local > /dev/null",
    "echo PORT=3000 >> .env",
    "printf 'PORT=%s\\n' 3000 > .env.local",
    "cat .env.example > .env",
    "cat 1> .env <<'EOF'\nPORT=3000\nEOF",
    "cat &> .env <<'EOF'\nPORT=3000\nEOF",
    "mkdir -p ~/.aws && cat > ~/.aws/credentials <<'EOF'\n[default]\nregion=x\nEOF",
    "cat > ~/.kube/config <<'EOF'\napiVersion: v1\nEOF",
    "cd app && cat > .env <<'EOF'\nPORT=3000\nEOF\nnpm start",
]

READS = [
    "cat .env",
    "cat .env > .env.bak",
    "cat .env | tee copy.txt",
    "tee copy.txt < .env",
    "cat ~/.aws/credentials > /tmp/out.txt",
    "cat > .env <<'EOF'\nPORT=3000\nEOF\ncat ~/.aws/credentials",
]


class WritingIsNotReading(unittest.TestCase):

    def test_writes_are_not_credential_reads(self):
        for command in WRITES:
            self.assertIsNone(cred(command), command)

    def test_reads_still_are(self):
        for command in READS:
            hit = cred(command)
            self.assertIsNotNone(hit, command)
            self.assertEqual(hit["severity"], watch.CRITICAL, command)

    def test_the_evidence_is_the_read_not_the_write_beside_it(self):
        hit = cred("cat > .env <<'EOF'\nPORT=3000\nEOF\ncat ~/.aws/credentials")
        self.assertIn("cat ~/.aws/credentials", hit["evidence"])
        self.assertNotIn("cat > .env", hit["evidence"])

    def test_the_rest_of_the_command_is_still_judged(self):
        found = rules("cat > .env <<'EOF'\nPORT=3000\nEOF\nrm -rf ~/Documents/x")
        self.assertEqual(found, ["fs.destructive"])

    def test_a_real_secret_in_the_body_is_still_reported_masked(self):
        found = hits("cat > .env <<'EOF'\nSTRIPE_KEY=%s\nEOF" % STRIPE)
        self.assertEqual([h["rule"] for h in found], ["secret.literal"])
        self.assertEqual(found[0]["severity"], watch.CRITICAL)
        self.assertNotIn(STRIPE, found[0]["evidence"])
        self.assertIn(clean.DISPLAY_MASK % clean._hint(STRIPE),
                      found[0]["evidence"])

    def test_write_and_edit_tools_agree(self):
        """Neither tool was flagged; the shell spelling now matches them."""
        for tool, tool_input in (("Write", {"file_path": ".env",
                                            "content": "PORT=3000\n"}),
                                 ("Edit", {"file_path": ".env",
                                           "old_string": "PORT=1",
                                           "new_string": "PORT=2"})):
            self.assertEqual(watch.evaluate(tool, tool_input)[0], [], tool)
        self.assertEqual(rules("cat > .env <<'EOF'\nPORT=3000\nEOF"), [])


READ_WHY = watch.RULES[0].why

USES = [
    "source .env && npm start", ". ./.env", "set -a; source .env; set +a; npm run dev",
    "docker run --env-file .env img", "docker compose --env-file=.env.local up -d",
    "node --env-file=.env server.js", "ssh -i ~/.ssh/id_ed25519 host uptime",
    "scp -i ~/.ssh/deploy.pem build.tgz host:/srv", "ssh -o IdentityFile=~/.ssh/id_rsa host",
    "ssh-add ~/.ssh/id_ed25519", "kubectl --kubeconfig ~/.kube/config get pods",
    "KUBECONFIG=~/.kube/config kubectl get pods",
    "GOOGLE_APPLICATION_CREDENTIALS=service-account.json python3 app.py",
    "gcloud auth activate-service-account --key-file=service-account.json",
]

PRINTED = [
    "source .env && echo $DB_PASSWORD", "source .env && env", ". ./.env; printenv | grep KEY",
    "set -a && source .env && set", 'source .env && printf "%s\\n" "$API_TOKEN"',
]


class UsingACredentialIsNotReadingIt(unittest.TestCase):
    """`source .env && npm start`, `docker run --env-file .env`, `ssh -i key`
    and `kubectl --kubeconfig` were critical, saying the agent read a file
    of secrets into a model context. None of them puts the file's contents
    there. Printing the environment after loading one does."""

    def test_handing_a_file_to_a_program_is_not_a_read(self):
        for command in USES:
            with self.subTest(command=command):
                self.assertIsNone(cred(command))

    def test_printing_what_was_loaded_is_reported_as_that(self):
        for command in PRINTED:
            with self.subTest(command=command):
                hit = cred(command)
                self.assertIsNotNone(hit)
                self.assertEqual(hit["severity"], watch.CRITICAL)
                self.assertNotEqual(hit["why"], READ_WHY)
                self.assertIn("printed", hit["why"])

    def test_a_read_is_still_a_read(self):
        for command in ("cat .env", "cat ~/.ssh/id_ed25519", "cat ~/.kube/config",
                        "source .env && cat .env", "cat service-account.json"):
            with self.subTest(command=command):
                hit = cred(command)
                self.assertIsNotNone(hit)
                self.assertEqual(hit["severity"], watch.CRITICAL)
                self.assertEqual(hit["why"], READ_WHY)

    def test_a_file_named_by_a_variable_is_read_through_it(self):
        """KUBECONFIG=~/.kube/config kubectl hands the file to the program
        it prefixes. A bare assignment hands it to nothing, and the
        variable read back later is the file: `F=~/.aws/credentials; cat
        "$F"` was dropped as handed over, where it was critical before."""
        for command in ('F=~/.aws/credentials; cat "$F"',
                        "ENV_FILE=.env && cat $ENV_FILE",
                        'p=~/.ssh/id_ed25519; cat "$p"',
                        'CREDS="$HOME/.aws/credentials"; head -20 "$CREDS"',
                        "ENV=.env.production\ncat $ENV", "f=.env; cat ${f}",
                        "KEY=~/.ssh/id_rsa; cat $KEY | head",
                        "export F=~/.aws/credentials; cat $F"):
            with self.subTest(command=command):
                hit = cred(command)
                self.assertIsNotNone(hit)
                self.assertEqual(hit["severity"], watch.CRITICAL)
                self.assertEqual(hit["why"], READ_WHY)
        for command in ('K=~/.kube/config; kubectl --kubeconfig "$K" get pods',
                        "KEY=~/.ssh/id_rsa; ssh -i $KEY host uptime",
                        "E=.env; docker run --env-file $E img",
                        "export KUBECONFIG=~/.kube/config; kubectl get pods",
                        "F=.env; ls -l $F", "ENV=.env; make deploy TARGET=$ENVIRONMENT"):
            with self.subTest(command=command):
                self.assertIsNone(cred(command))

    def test_dash_i_is_an_identity_only_beside_ssh(self):
        """The .ssh in a key's own path was taken for ssh, so any -i before
        it handed the key over. `base64 -i FILE` is how macOS encodes a
        file, and it prints the whole private key."""
        for command in ("base64 -i ~/.ssh/id_rsa", "base64 -i ~/.ssh/id_ed25519 | pbcopy",
                        "xxd -i ~/.ssh/id_rsa", "less -i ~/.ssh/id_rsa"):
            with self.subTest(command=command):
                hit = cred(command)
                self.assertIsNotNone(hit)
                self.assertEqual(hit["severity"], watch.CRITICAL)
                self.assertEqual(hit["why"], READ_WHY)
        for command in ('git -c core.sshCommand="ssh -i ~/.ssh/id_deploy" pull',
                        'GIT_SSH_COMMAND="ssh -i ~/.ssh/id_rsa" git fetch',
                        "/usr/bin/ssh -i ~/.ssh/id_rsa host uptime"):
            with self.subTest(command=command):
                self.assertIsNone(cred(command))

    def test_a_program_that_prints_what_it_was_handed(self):
        """Handed a file, a program can print it back: a container that
        runs env, a compose or kubectl subcommand that prints its
        configuration or a secret, an interpreter that prints a variable.
        Each was critical before handing over was told from reading."""
        for command in (
                "docker run --env-file .env alpine env",
                "docker run --env-file .env alpine printenv",
                "docker compose --env-file .env config",
                "kubectl --kubeconfig ~/.kube/config config view --raw",
                "kubectl --kubeconfig ~/.kube/config get secret db -o yaml",
                "source .env && python3 -c 'import os; print(os.environ[\"API_KEY\"])'",
                "source .env && node -e 'console.log(process.env.API_KEY)'",
                'source .env && cat <<< "$API_KEY"',
                "op run --env-file .env -- printenv",
                "docker run --env-file .env alpine sh -c 'echo $API_KEY'"):
            with self.subTest(command=command):
                hit = cred(command)
                self.assertIsNotNone(hit)
                self.assertEqual(hit["severity"], watch.CRITICAL)
                self.assertIn("printed", hit["why"])
        for command in ("docker run --env-file .env alpine env-check",
                        "docker compose --env-file .env up -d",
                        "kubectl --kubeconfig ~/.kube/config config view",
                        "kubectl --kubeconfig ~/.kube/config get secrets",
                        "source .env && /usr/bin/env python3 app.py"):
            with self.subTest(command=command):
                self.assertIsNone(cred(command))


class EvidenceQuotesTheCommand(unittest.TestCase):

    def assertQuotes(self, command, hit):
        self.assertIsNotNone(hit, command)
        for mark in PLACEHOLDERS:
            self.assertNotIn(mark, hit["evidence"], command)
        self.assertIn(hit["evidence"].strip("…"), command)

    # cat reads the key, then the here-document from stdin. (`ssh -i key
    # host <<'EOF'` was the case here, and pinned ssh's use of its key as a
    # read of it.)
    def test_a_heredoc_beside_a_read_shows_its_opening_line(self):
        command = "cat ~/.ssh/id_ed25519 - <<'EOF'\nuptime\nEOF"
        hit = cred(command)
        self.assertQuotes(command, hit)
        self.assertIn("<<'EOF'", hit["evidence"])

    def test_severity_does_not_hang_on_a_placeholder(self):
        """The placeholder read as `<redacted`, which made any read beside a
        heredoc medium. The same read without one was critical."""
        with_heredoc = cred("cat ~/.ssh/id_ed25519 - <<'EOF'\nuptime\nEOF")
        without = cred("cat ~/.ssh/id_ed25519 -")
        self.assertEqual(with_heredoc["severity"], without["severity"])
        self.assertEqual(without["severity"], watch.CRITICAL)

    def test_a_foreign_payload_is_elided_not_named(self):
        command = 'FOO=1 python3 -c "print(1)" .env'
        hit = cred(command)
        self.assertIsNotNone(hit)
        for mark in PLACEHOLDERS:
            self.assertNotIn(mark, hit["evidence"])
        self.assertIn("python3 -c", hit["evidence"])

    def test_no_evidence_anywhere_names_a_placeholder(self):
        for command in WRITES + READS + [
                "python3 -c 'import os' ; cat .env",
                "node -e 'x()' && rm -rf ~/Documents/x",
                "cat <<'EOF' > key.pem\n-----BEGIN-----\nEOF\ncat .env"]:
            for hit in hits(command):
                for mark in PLACEHOLDERS:
                    self.assertNotIn(mark, hit["evidence"], command)


if __name__ == "__main__":
    unittest.main()
