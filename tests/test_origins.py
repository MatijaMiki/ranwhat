"""Which file a secret was read out of.

The origin is shown as "read from <path>", so a wrong one sends the user to
rotate the wrong thing. Code is full of names shaped like credential files
(os.environ, process.env.KEY, d.key, id_token, load_credentials), and an
honest "no origin" beats a confident wrong one. Every value here is
synthetic.
"""
import json
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ranwhat.clean import _ORIGIN_MARKERS, _origins, scan_file

KEY = "AKIA4TRUE7KEYX9QZ2WB"      # synthetic, shaped like an AWS key id

# (text as it appears in a transcript line, the origins it must yield)
READS = [
    ("cat .env", [".env"]),
    ("cat api/.env", ["api/.env"]),
    ("cat .env.local", [".env.local"]),
    ("cat .env.production", [".env.production"]),
    ("cat .env.development.local", [".env.development.local"]),
    ("cat /Users/me/app/.env", ["/Users/me/app/.env"]),
    ("source ./.env", ["./.env"]),
    ('cat "$HOME/.env"', ["$HOME/.env"]),
    ("cat ${HOME}/.env", ["${HOME}/.env"]),
    ("docker run --env-file=.env img", [".env"]),
    ("export $(cat .env | xargs)", [".env"]),
    ("load_dotenv('.env')", [".env"]),
    ("cat .envrc", [".envrc"]),
    ("cat config/secrets.env", ["config/secrets.env"]),
    ("read .env.", [".env"]),
    ("cat <.env", [".env"]),
    ("DOTENV_CONFIG_PATH=./config/.env node app.js", ["./config/.env"]),
    ("cat ~/.aws/credentials", ["~/.aws/credentials"]),
    ("cat .aws/credentials", [".aws/credentials"]),
    ("cat /root/.aws/credentials", ["/root/.aws/credentials"]),
    ("cat ~/.aws/credentials.bak", ["~/.aws/credentials.bak"]),
    ("cat credentials.json", ["credentials.json"]),
    ("cat application_default_credentials.json",
     ["application_default_credentials.json"]),
    ("cat ~/.config/gcloud/application_default_credentials.json",
     ["~/.config/gcloud/application_default_credentials.json"]),
    ("cat credentials.yml.enc", ["credentials.yml.enc"]),
    ("cat ~/.git-credentials", ["~/.git-credentials"]),
    ("cat ~/.netrc", ["~/.netrc"]),
    ("cat ~/.ssh/id_rsa", ["~/.ssh/id_rsa"]),
    ("cat ~/.ssh/id_dsa", ["~/.ssh/id_dsa"]),
    ("cat ~/.ssh/id_ecdsa", ["~/.ssh/id_ecdsa"]),
    ("cat ~/.ssh/id_ed25519", ["~/.ssh/id_ed25519"]),
    ("cat ~/.ssh/id_ecdsa_sk", ["~/.ssh/id_ecdsa_sk"]),
    ("cat ~/.ssh/id_ed25519_sk", ["~/.ssh/id_ed25519_sk"]),
    ("cat ~/.ssh/id_rsa.bak", ["~/.ssh/id_rsa.bak"]),
    ("cat ~/.ssh/id_rsa~", ["~/.ssh/id_rsa~"]),
    ("cat id_rsa", ["id_rsa"]),
    ("scp host:~/.ssh/id_ed25519 .", ["~/.ssh/id_ed25519"]),
    ("ssh -i/home/u/.ssh/id_rsa host", ["/home/u/.ssh/id_rsa"]),
    ("scp -i~/.ssh/id_ed25519 a b", ["~/.ssh/id_ed25519"]),
    ("cat certs/tls.key", ["certs/tls.key"]),
    ("cat ./server.key", ["./server.key"]),
    ("cat ~/keys/d.key", ["~/keys/d.key"]),
    ("openssl rsa -in /etc/ssl/private/server.pem",
     ["/etc/ssl/private/server.pem"]),
    ("ssh -i my-ec2-key.pem ec2-user@host", ["my-ec2-key.pem"]),
    # bare key names: a reading command, a flag or quotes make them files
    ("cat server.key", ["server.key"]),
    ("cat key.pem", ["key.pem"]),
    ("cat privkey.pem", ["privkey.pem"]),
    ("cat server.key.bak", ["server.key.bak"]),
    ("cat -n server.key", ["server.key"]),
    ("openssl genrsa -out server.key", ["server.key"]),
    ("fs.readFileSync('private.key')", ["private.key"]),
    ('open("server.key")', ["server.key"]),
    (json.dumps({"c": 'open("server.key")'}), ["server.key"]),
    # the raw JSONL line is what gets scanned, escapes and all
    (json.dumps({"file_path": "/Users/me/app/.env"}), ["/Users/me/app/.env"]),
    (json.dumps({"content": "./.env\n./api/.env\n"}), ["./.env", "./api/.env"]),
    (json.dumps({"c": "x\tapi/.env"}), ["api/.env"]),
    (json.dumps({"c": "\u2026/Users/me/app/.env"}, ensure_ascii=True),
     ["/Users/me/app/.env"]),
    (json.dumps({"c": "C:\\users\\me\\.env"}), ["C:\\users\\me\\.env"]),
    (json.dumps({"file_path": "C:\\Users\\me\\.aws\\credentials"}),
     ["C:\\Users\\me\\.aws\\credentials"]),
    ("type %USERPROFILE%\\.aws\\credentials",
     ["%USERPROFILE%\\.aws\\credentials"]),
    ("type C:\\certs\\server.key", ["C:\\certs\\server.key"]),
    (json.dumps({"command": "type C:\\certs\\privkey.pem"}),
     ["C:\\certs\\privkey.pem"]),
    (json.dumps({"command": "type .\\certs\\tls.key"}), [".\\certs\\tls.key"]),
]

# The call reads the file but other words are around it; the origin must be
# among the results.
READS_AMONG = [
    ("then cat ~/.ssh/id_rsa here", "~/.ssh/id_rsa"),
    ("read api/.env", "api/.env"),
    ("openssl rsa -in private.key -out x", "private.key"),
    ("openssl x509 -in cert.pem -noout", "cert.pem"),
]

NOT_READS = [
    # environment variables in code, which the old pattern read as files
    # (".environ", ".environ.get", ".env.CENNER_API_KEY")
    "key = os.environ['OPENAI_API_KEY']",
    "key = os.environ.get('OPENAI_API_KEY')",
    "const k = process.env.CENNER_API_KEY;",
    "const k = import.meta.env.VITE_KEY;",
    "const { KEY } = process.env",
    "Deno.env.get('KEY')",
    "Deno\\.env",                                  # a regex, escaped dot
    json.dumps({"c": "Deno\\.env"}),
    json.dumps({"c": "Deno\\\\.env"}),            # a regex in a Python string
    json.dumps({"c": "process\\.env\\.KEY"}),
    json.dumps({"c": "\\.pem$"}),
    "import.meta.env.VITE_ID_RSA",
    "config .env.API_KEY",
    " .env.KEY",
    "x = src/utils/process.env",
    "a/process.env",
    'e.key==="Enter"&&process.env.NODE_ENV',
    json.dumps({"c": "const x = process.env.API_KEY\nlet k = obj.key"}),
    json.dumps({"c": 'e.key==="Enter"'}),
    # identifiers that merely start like an SSH key name
    "with open(path) as f: id_json = json.load(f)",
    "id_token = resp['id_token']",
    "grid_size = 3; valid_until = x; android_id_x",
    "id_rsa_key = 1",
    "def id_dsa_support(): pass",
    # attribute access
    "for d in items: print(d.key)",
    "x = d.key",
    "if (event.key === 'Enter') {}",
    "Object.keys(obj)",
    "this.props.key",
    "cert = obj.pem",
    "result.key and obj.pem_data",
    # the word credentials in prose, code, imports and routes
    "You need to set up your credentials first.",
    "Store credentials in the vault",
    "Credentials: none",
    "def load_credentials(): pass",
    "self.credentials = creds",
    "obj .credentials",
    ".credentials = x",
    "creds = credentials.json()",
    "src/auth/credentials.ts",
    "src/utils/get_credentials.py",
    "import { load } from './credentials'",
    "const c = require('../auth/credentials')",
    "from .credentials import load",
    "See https://docs.example.com/iam/credentials",
    "GET /api/credentials",
    # a virtualenv directory named .env, and names that only start with it
    "source .env/bin/activate",
    "source .env\\bin\\activate",
    "python -m venv .env",
    "cat .environment",
    # source files and templates named after .env
    "cat src/.env.d.ts",
    "types/.env.d.ts",
    'import cfg from "./.env.ts"',
    "cat .env.example",
    "cp .env.example .env.example",
    "cat .env.schema",
    "cat .env.dist",
    "cat .env.defaults",
    "cat .env.tmpl",
    # public keys hold nothing secret
    "cat ~/.ssh/id_rsa.pub",
    "cat ~/.ssh/id_ed25519.pub",
    "cat ~/.ssh/id_rsa-cert.pub",
]


class OriginNames(unittest.TestCase):

    def test_credential_files_are_named(self):
        for text, want in READS:
            with self.subTest(text=text):
                self.assertEqual(_origins(text), want)

    def test_credential_files_are_found_among_other_words(self):
        for text, want in READS_AMONG:
            with self.subTest(text=text):
                self.assertIn(want, _origins(text))

    def test_code_and_prose_are_not_files(self):
        for text in NOT_READS:
            with self.subTest(text=text):
                self.assertEqual(_origins(text), [])

    def test_every_origin_carries_a_prefilter_marker(self):
        """_origins skips a line with none of the markers. A future branch
        without one would be skipped silently; this is the tripwire."""
        for text, want in READS:
            for origin in want:
                with self.subTest(origin=origin):
                    self.assertTrue(
                        any(m in origin.lower() for m in _ORIGIN_MARKERS))


def _call(cmd, call_id=None, tool="Bash"):
    block = {"type": "tool_use", "name": tool,
             "input": {"file_path": cmd} if tool == "Read" else {"command": cmd}}
    if call_id:
        block["id"] = call_id
    return {"message": {"content": [block]}}


def _result(text, call_id=None):
    block = {"type": "tool_result", "content": text}
    if call_id:
        block["tool_use_id"] = call_id
    return {"message": {"content": [block]}}


def _text(text):
    return {"message": {"content": [{"type": "text", "text": text}]}}


def _typed(text):
    """What the user typed, which Claude Code writes as a plain string."""
    return {"type": "user", "message": {"role": "user", "content": text}}


def _queued(text):
    """A message typed while the agent was busy."""
    return {"type": "queue-operation", "operation": "enqueue", "content": text}


class OriginOfAFinding(unittest.TestCase):
    """End to end through scan_file: the secret is always found, and the
    origin it is credited to is the right one or none."""

    def _scan(self, rows):
        d = tempfile.mkdtemp(prefix="origin-")
        self.addCleanup(shutil.rmtree, d, True)
        path = os.path.join(d, "s.jsonl")
        with open(path, "w", encoding="utf-8") as fh:
            for r in rows:
                fh.write(json.dumps(r) + "\n")
        findings, changed = scan_file(path)
        self.assertFalse(changed)
        self.assertEqual(len(findings), 1, "the secret must still be found")
        return list(findings.values())[0]["origins"]

    def test_code_mentioning_environ_does_not_replace_the_real_file(self):
        rows = [_call("cat api/.env"),
                _text("key = os.environ.get('AWS_ACCESS_KEY_ID')"),
                _result("AWS_ACCESS_KEY_ID=%s\n" % KEY)]
        self.assertEqual(self._scan(rows), {"api/.env"})

    def test_process_env_is_not_an_origin(self):
        rows = [_text("const k = process.env.CENNER_API_KEY;"),
                _result("AWS_ACCESS_KEY_ID=%s\n" % KEY)]
        self.assertEqual(self._scan(rows), set())

    def test_a_bare_key_file_read_after_an_env_file_is_credited(self):
        rows = [_call("cat api/.env"), _result("DEBUG=1\n"),
                _call("cat server.key"), _result("AWS_ACCESS_KEY_ID=%s\n" % KEY)]
        self.assertEqual(self._scan(rows), {"server.key"})

    def test_windows_credentials_file_keeps_its_path(self):
        rows = [_call("C:\\Users\\me\\.aws\\credentials", tool="Read"),
                _result("aws_access_key_id = %s\n" % KEY)]
        origins = self._scan(rows)
        self.assertTrue(origins)
        self.assertTrue(all(o.endswith("credentials") for o in origins), origins)

    def test_windows_read_after_an_env_file_is_credited(self):
        rows = [_call("cat api/.env"), _result("DEBUG=1\n"),
                _call("type %USERPROFILE%\\.aws\\credentials"),
                _result("aws_access_key_id = %s\n" % KEY)]
        self.assertEqual(self._scan(rows), {"%USERPROFILE%\\.aws\\credentials"})

    def test_docs_url_is_not_an_origin(self):
        rows = [_text("See https://docs.example.com/iam/credentials"),
                _result("AWS_ACCESS_KEY_ID=%s\n" % KEY)]
        self.assertEqual(self._scan(rows), set())

    def test_module_import_is_not_an_origin(self):
        rows = [_text("import { load } from './credentials'"),
                _result("AWS_ACCESS_KEY_ID=%s\n" % KEY)]
        self.assertEqual(self._scan(rows), set())

    def test_a_result_belongs_to_its_own_call(self):
        """With call ids, the output of `env` is not credited to the .env file
        read two calls earlier."""
        rows = [_call("cat api/.env", "t1"), _result("DEBUG=1\n", "t1"),
                _call("env", "t2"), _result("AWS_ACCESS_KEY_ID=%s\n" % KEY, "t2")]
        self.assertEqual(self._scan(rows), set())

    def test_a_result_is_credited_to_the_file_its_call_read(self):
        rows = [_call("cat api/.env", "t1"), _call("ls", "t2"),
                _result("a b c\n", "t2"),
                _result("AWS_ACCESS_KEY_ID=%s\n" % KEY, "t1")]
        self.assertEqual(self._scan(rows), {"api/.env"})

    def test_a_result_that_names_its_file_is_credited_to_it(self):
        rows = [_call("grep -r AWS_ACCESS_KEY_ID .", "t1"),
                _result("./api/.env:AWS_ACCESS_KEY_ID=%s\n" % KEY, "t1")]
        self.assertEqual(self._scan(rows), {"./api/.env"})

    # Only a tool result is read out of a file. Two real AWS key IDs, pasted
    # in a user message, showed "read from d.key": the name came from prose
    # two lines up explaining that d.key was attribute access.

    def test_pasted_text_is_not_credited_to_a_name_in_earlier_prose(self):
        said = _text('Note that "server.key" in that code is attribute access')
        for pasted in (_typed, _queued, _text):
            with self.subTest(pasted=pasted.__name__):
                rows = [said, pasted("AWS_ACCESS_KEY_ID=%s" % KEY)]
                self.assertEqual(self._scan(rows), set())

    def test_pasted_text_is_not_credited_to_a_file_read_earlier(self):
        rows = [_call("cat api/.env", "t1"), _result("DEBUG=1\n", "t1"),
                _typed("AWS_ACCESS_KEY_ID=%s" % KEY)]
        self.assertEqual(self._scan(rows), set())

    def test_prose_naming_a_file_beside_the_value_is_not_an_origin(self):
        rows = [_typed('"server.key" is attribute access. '
                       "AWS_ACCESS_KEY_ID=%s" % KEY)]
        self.assertEqual(self._scan(rows), set())

    def test_a_result_whose_call_is_not_in_the_file_gets_no_origin(self):
        rows = [_call("cat api/.env", "t1"), _result("DEBUG=1\n", "t1"),
                _result("AWS_ACCESS_KEY_ID=%s\n" % KEY, "t9")]
        self.assertEqual(self._scan(rows), set())

    def test_without_ids_a_result_goes_with_the_call_just_before_it(self):
        rows = [_call("cat api/.env"), _result("DEBUG=1\n"),
                _call("env"), _result("AWS_ACCESS_KEY_ID=%s\n" % KEY)]
        self.assertEqual(self._scan(rows), set())

    def test_a_value_typed_into_a_call_is_not_read_from_what_it_names(self):
        """On a working machine every secret credited from a call's own
        input was typed into a command that also mentioned api/.env."""
        rows = [_call("python3 -c \"rows = [call('cat api/.env')]; "
                      "key = '%s'\"" % KEY, "t1")]
        self.assertEqual(self._scan(rows), set())

    def test_a_file_a_command_writes_is_not_what_it_read(self):
        """`cat > f <<'EOF'` writes what follows. On a working machine every
        origin left after the fix above came from source written this way
        that mentioned .env, by a command whose tests then printed a key."""
        write = ("cat > tests/t.py <<'PYEOF'\nrows = [call('cat api/.env')]\n"
                 "PYEOF\npython3 -m unittest tests.t")
        rows = [_call(write, "t1"), _result("KEY = %s\n" % KEY, "t1")]
        self.assertEqual(self._scan(rows), set())
        after = "cat > notes.txt <<EOF\nhello\nEOF\ncat api/.env"
        rows = [_call(after, "t1"), _result("AWS_ACCESS_KEY_ID=%s\n" % KEY, "t1")]
        self.assertEqual(self._scan(rows), {"api/.env"})

    def test_output_that_merely_mentions_a_file_is_not_read_from_it(self):
        listing = ('READS = [\n    ("cat .env", [".env"]),\n]\n'
                   'KEY = "%s"\n' % KEY)
        rows = [_call("sed -n 1,40p tests/test_origins.py", "t1"),
                _result(listing, "t1")]
        self.assertEqual(self._scan(rows), set())

    def test_grep_output_is_credited_line_by_line(self):
        out = ("./api/.env:3:DEBUG=1\n"
               "./src/app.py:9:AWS_ACCESS_KEY_ID=%s\n" % KEY)
        rows = [_call("grep -rn AWS_ACCESS_KEY_ID .", "t1"), _result(out, "t1")]
        self.assertEqual(self._scan(rows), set())
        for out, want in (("api/.env:3:AWS_ACCESS_KEY_ID=%s\n" % KEY, "api/.env"),
                          ("x.py:1:y\n.env:AWS_ACCESS_KEY_ID=%s\n" % KEY, ".env")):
            with self.subTest(out=out):
                rows = [_call("rg -n AWS_ACCESS_KEY_ID", "t1"), _result(out, "t1")]
                self.assertEqual(self._scan(rows), {want})

    def test_a_yaml_key_is_not_a_grep_prefix(self):
        rows = [_call("kubectl get secret app -o yaml", "t1"),
                _result("id_rsa: %s\n" % KEY, "t1")]
        self.assertEqual(self._scan(rows), set())

    def test_a_file_the_user_attached_is_credited_to_that_file(self):
        """@api/.env in a prompt puts the file into the transcript as an
        attachment that names it, which is as much a read as `cat`."""
        for kind, body in (("file", "content"), ("edited_text_file", "snippet")):
            with self.subTest(kind=kind):
                rows = [_text('Note that "server.key" is attribute access'),
                        {"type": "attachment", "attachment": {
                            "type": kind, "filename": "/Users/me/app/api/.env",
                            "displayPath": "api/.env",
                            body: "AWS_ACCESS_KEY_ID=%s\n" % KEY}}]
                self.assertEqual(self._scan(rows), {"/Users/me/app/api/.env"})

    def test_without_ids_prose_between_a_call_and_its_result_changes_nothing(self):
        rows = [_call("cat api/.env"),
                _text('Note that "server.key" in that code is attribute access'),
                _result("AWS_ACCESS_KEY_ID=%s\n" % KEY)]
        self.assertEqual(self._scan(rows), {"api/.env"})


if __name__ == "__main__":
    unittest.main()
