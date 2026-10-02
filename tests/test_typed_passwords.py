"""A password typed into a command, with no key beside it.

mysql -u root -pPASSWORD -e 'DROP DATABASE prod' names no secret, so the
copy was masked only when the same value had been found elsewhere: in the
transcripts --days read, and within the budget the search of other
transcripts has. A password read outside the window, or in a history
long enough to spend the budget first, was printed whole by check and
watch, and stayed on disk after clean --apply. Where a command takes its
password is a place a secret sits, as a key is. Every value is synthetic.
"""
import io
import json
import os
import shutil
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ranwhat import clean, watch
from ranwhat.clean import find_secrets

PW = "Hq7xT2mVp9LwZr4kNd"


def _tempdir(test, prefix):
    d = tempfile.mkdtemp(prefix=prefix)
    test.addCleanup(shutil.rmtree, d, True)
    return d


class WhereACommandTakesItsPassword(unittest.TestCase):

    def test_found_where_it_is_typed(self):
        for command in (
                "mysql -u root -p%s -e 'DROP DATABASE prod'",
                "mysqldump -uroot -p%s prod > dump.sql",
                "mysqladmin -u root -p%s drop prod",
                "mariadb -h db -u app -p'%s' prod",
                'mysql -u root -p"%s" prod',
                "docker exec db mysql -uroot -p%s -e 'DROP TABLE users'",
                "sshpass -p %s ssh root@prod 'rm -rf /var/www'",
                "sshpass -p'%s' scp dump.sql root@prod:/tmp",
                "redis-cli -h cache -a %s FLUSHALL",
                "curl -u admin:%s -X DELETE https://api.example.test/v1/users/1",
                "curl --user admin:%s https://api.example.test",
                "docker login -u me --password %s registry.example.test",
                "docker login -u me -p %s registry.example.test",
                "PGPASSWORD=%s psql -h db -U app -c 'DROP TABLE users'",
                "MYSQL_PWD=%s mysql -u root prod",
                "REDISCLI_AUTH=%s redis-cli FLUSHALL"):
            text = command % PW
            with self.subTest(command=command):
                self.assertEqual([v for v, _l in find_secrets(text)], [PW])

    def test_no_password_typed(self):
        for text in (
                "mysql -u root -p -e 'DROP DATABASE prod'",
                "mysql -u root -p$MYSQL_ROOT_PASSWORD prod",
                'mysql -u root -p"$DB_PASSWORD" prod',
                "mysql -u root -p${DB_PASSWORD} prod",
                "mysql -uroot -ppassword prod",
                "mysql -u root -p<password> prod",
                "mkdir -p build/release/output && ls",
                "ssh -p 2222 deploy@prod.example.test uptime",
                "docker run -p 8080:80 -p 8443:443 nginx:latest",
                "python -m pytest -p no:cacheprovider tests/",
                "curl -u $API_USER:$API_TOKEN https://api.example.test",
                'sshpass -p "$SSHPASS" ssh root@prod uptime',
                'redis-cli -a "$REDIS_PASSWORD" ping',
                "docker login -u me --password-stdin registry.example.test",
                "git log -p --stat HEAD~3"):
            with self.subTest(text=text):
                self.assertEqual(find_secrets(text + "\n# padding padding padding"), [])

    def test_found_where_more_commands_take_it(self):
        for command in (
                'sqlcmd -S prod -U sa -P %s -Q "DROP DATABASE prod"',
                "sqlcmd -S prod -U sa -P'%s' -i drop.sql",
                "influx -username admin -password %s -execute 'DROP DATABASE prod'",
                "mongosh -u admin -p %s --eval 'db.dropDatabase()'",
                "mongodump --uri mongodb://db/prod -u admin -p'%s' --out dump",
                "ldapsearch -x -D cn=admin,dc=corp -w %s -b dc=corp",
                "ldapmodify -x -D cn=admin,dc=corp -w '%s' -f change.ldif",
                "htpasswd -b .htpasswd admin %s",
                "htpasswd -bc /etc/nginx/.htpasswd admin '%s' && nginx -s reload",
                "htpasswd -nbB admin %s",
                "keytool -list -keystore prod.jks -storepass %s",
                "keytool -importkeystore -srckeystore a.p12 -srcstorepass %s"
                " -destkeystore b.jks",
                "jarsigner -keystore prod.jks -keypass %s app.jar release",
                "$c = ConvertTo-SecureString '%s' -AsPlainText -Force",
                'ConvertTo-SecureString -String "%s" -AsPlainText -Force',
                "ConvertTo-SecureString -AsPlainText -Force -String '%s'",
                "smbclient //files/share -U admin%%%s -c 'get .env'",
                "smbclient -U 'CORP\\admin%%%s' //files/share",
                "rpcclient -U admin%%%s dc01 -c enumdomusers"):
            text = command % PW
            with self.subTest(command=command):
                self.assertEqual([v for v, _l in find_secrets(text)], [PW])

    def test_every_command_is_worth_scanning(self):
        """A string holding none of clean._CHEAP is never asked, so each
        rule's marker must hold one, or the rule never runs."""
        for marker, _pattern, _label in clean._TYPED:
            with self.subTest(marker=marker):
                # curl's rule reads user:password, and every colon is asked.
                self.assertTrue(marker == "curl" or any(t in marker for t in clean._CHEAP))

    def test_no_password_typed_to_more_commands(self):
        for text in (
                "sqlcmd -S prod -E -Q 'SELECT 1'",
                "sqlcmd -S prod -U sa -P $SA_PASSWORD -Q 'SELECT 1'",
                "rsync -avP build/ deploy@prod.example.test:/srv/app/",
                "influx -username admin -password '' -execute 'SHOW DATABASES'",
                "mongosh --port 27017 prod --eval 'db.stats()'",
                "ldapsearch -x -W -D cn=admin,dc=corp -b dc=corp",
                "ldapsearch -x -D cn=admin,dc=corp -y /run/secrets/ldap -b dc=corp",
                "htpasswd -c .htpasswd admin",
                "htpasswd -b .htpasswd admin $HTPASSWD",
                "keytool -list -keystore prod.jks -storepass:env STOREPASS",
                "keytool -list -keystore prod.jks -storepass:file pass.txt",
                "ConvertTo-SecureString $plain -AsPlainText -Force",
                "smbclient -L //files -U admin",
                "smbclient //files/share -U admin%$SMB_PASSWORD",
                "net use Z: \\\\files\\share /persistent:no"):
            with self.subTest(text=text):
                self.assertEqual(find_secrets(text + "\n# padding padding padding"), [])

    def test_watch_masks_it_in_the_evidence(self):
        command = "mysql -u root -p%s -e 'DROP DATABASE prod'" % PW
        hits, payload = watch.evaluate("Bash", {"command": command})
        self.assertTrue(hits)
        for hit in hits:
            self.assertNotIn(PW, hit["evidence"])
        self.assertNotIn(PW, payload)


def _call(i, command, stamp):
    return {"type": "assistant", "timestamp": stamp, "message": {"content": [
        {"type": "tool_use", "id": "t%s" % i, "name": "Bash", "input": {"command": command}}]}}


def _result(i, text, stamp):
    return {"type": "user", "timestamp": stamp, "message": {"content": [
        {"type": "tool_result", "tool_use_id": "t%s" % i, "content": text}]}}


def _stamp(age):
    return time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime(time.time() - age))


def _write(path, lines, age):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("".join(json.dumps(line) + "\n" for line in lines))
    t = time.time() - age
    os.utime(path, (t, t))


def _cli(argv):
    from ranwhat import cli
    out, err = io.StringIO(), io.StringIO()
    with mock.patch("sys.stdout", out), mock.patch("sys.stderr", err):
        try:
            cli.main(argv)
        except SystemExit:
            pass
    return out.getvalue() + err.getvalue()


class _Reports(unittest.TestCase):

    def setUp(self):
        backups = os.path.join(_tempdir(self, "bk-"), "backups")
        for patch in (mock.patch.object(clean, "BACKUP_ROOT", backups),
                      mock.patch.dict(os.environ, {"NO_COLOR": "1"})):
            patch.start()
            self.addCleanup(patch.stop)
        self.state = _tempdir(self, "oc-")

    def reports(self, root, *extra):
        where = ["--root", root] + list(extra)
        return (["check"] + where + ["--state-dir", self.state],
                ["check", "--json"] + where + ["--state-dir", self.state],
                ["watch"] + where + ["--state-dir", self.state],
                ["watch", "--json"] + where + ["--state-dir", self.state])

    def plaintext(self, root):
        held = []
        for top, _dirs, files in os.walk(root):
            for name in files:
                with open(os.path.join(top, name), encoding="utf-8") as fh:
                    if PW in fh.read():
                        held.append(name)
        return held


class ReadOutsideTheWindow(_Reports):
    """Read in a session older than --days, typed in one inside it."""

    def test_check_and_watch_never_print_it(self):
        root = _tempdir(self, "window-")
        project = os.path.join(root, "-Users-a-app")
        _write(os.path.join(project, "sessA.jsonl"),
               [_call(1, "cat .env", _stamp(5 * 86400)),
                _result(1, "DB_PASSWORD=%s\n" % PW, _stamp(5 * 86400))], 5 * 86400)
        _write(os.path.join(project, "sessB.jsonl"),
               [_call(2, "mysql -u root -p%s -e 'DROP DATABASE prod'" % PW, _stamp(600)),
                _result(2, "ok", _stamp(600))], 600)
        for days in ([], ["--days", "1"]):
            for argv in self.reports(root, *days):
                with self.subTest(argv=argv[:2] + days):
                    out = _cli(argv)
                    self.assertIn("DROP DATABASE", out)
                    self.assertNotIn(PW, out)


# Each command watch reports, with the password inside the evidence it
# prints: the places a command takes one that no rule read but mysql's -p.
REPORTED = {
    "sqlcmd": 'sqlcmd -S prod -U sa -P %s -Q "DROP DATABASE prod "',
    "influx": "influx -username admin -password %s -execute 'DROP DATABASE prod '",
    "mongosh": "mongosh -u admin -p %s --eval 'DROP DATABASE prod '",
    "ldapsearch": "ldapsearch -x -D cn=admin,dc=corp -w %s -b dc=corp -f .env",
    "htpasswd": "htpasswd -b .env.htpasswd admin %s",
    "keytool": "keytool -list -keystore .env.jks -storepass %s",
    "pwsh": "pwsh -File .env.ps1 -Command \"$p = ConvertTo-SecureString '%s'"
            " -AsPlainText -Force\"",
    "smbclient": "smbclient //files/share -U admin%%%s -c 'get .env'",
}
# A script's own argument: no rule can say it is a password.
SCRIPT = "./deploy.sh prod %s -e 'DROP DATABASE prod '"


# The evidence shows the password by its hint, as a reader sees it in
# either form: the action was reported, and the value masked in it.
_MASKED = clean.DISPLAY_MASK % clean._hint(PW)


def _shown(out):
    try:
        return json.dumps(json.loads(out), ensure_ascii=False)
    except ValueError:
        return out


def _read_then_typed(test, typed, read_age, typed_age=600):
    """A root where one session reads the password from .env, read_age
    seconds ago, and another types it, typed_age seconds ago."""
    root = _tempdir(test, "typed-")
    project = os.path.join(root, "-Users-a-app")
    _write(os.path.join(project, "sessA.jsonl"),
           [_call(1, "cat .env", _stamp(read_age)),
            _result(1, "DB_PASSWORD=%s\n" % PW, _stamp(read_age))], read_age)
    _write(os.path.join(project, "sessB.jsonl"),
           [_call(2, typed % PW, _stamp(typed_age)),
            _result(2, "ok", _stamp(typed_age))], typed_age)
    return root


class TypedWhereMoreCommandsTakeIt(_Reports):
    """sqlcmd -P, influx -password, mongosh -p, ldapsearch -w, htpasswd -b,
    keytool -storepass, ConvertTo-SecureString -AsPlainText and smbclient's
    -U user%password. Read in a session --days 1 leaves out, the copy typed
    in the window was printed whole by check, watch and their --json forms,
    and clean --apply left it on disk."""

    def test_check_and_watch_never_print_it(self):
        for name, typed in REPORTED.items():
            root = _read_then_typed(self, typed, 5 * 86400)
            for argv in self.reports(root, "--days", "1"):
                with self.subTest(position=name, argv=argv[:2]):
                    out = _cli(argv)
                    self.assertNotIn(PW, out)
                    self.assertIn(_MASKED, _shown(out))

    def test_clean_masks_it_where_it_is_typed(self):
        for name, typed in REPORTED.items():
            root = _read_then_typed(self, typed, 5 * 86400)
            with self.subTest(position=name):
                _cli(["clean", "--apply", "--days", "1", "--root", root])
                self.assertEqual(self.plaintext(root), ["sessA.jsonl"])


class ReadBeforeTheWindowTypedAsAnArgument(_Reports):
    """No rule can say a script's argument is a password. check and watch
    knew the values clean finds only in the transcripts --days reads, so
    one read before the window and typed in it was printed whole, by the
    `check --json --days 1` check suggests too. With the read 45 days old
    the default window did the same, and clean --apply, reading only the
    window, left it for the next report to print again."""

    def test_check_and_watch_never_print_it(self):
        for read_age, days in ((5 * 86400, ["--days", "1"]), (45 * 86400, [])):
            root = _read_then_typed(self, SCRIPT, read_age)
            for argv in self.reports(root, *days):
                with self.subTest(argv=argv[:2] + days):
                    out = _cli(argv)
                    self.assertNotIn(PW, out)
                    self.assertIn(_MASKED, _shown(out))

    def test_nor_after_clean_reads_the_window(self):
        root = _read_then_typed(self, SCRIPT, 45 * 86400)
        self.assertNotIn(PW, _cli(["clean", "--apply", "--root", root]))
        for argv in self.reports(root):
            with self.subTest(argv=argv[:2]):
                self.assertNotIn(PW, _cli(argv))

    def test_the_window_still_bounds_what_is_reported(self):
        """Only the masking looks past --days: the report is the window's."""
        root = _read_then_typed(self, SCRIPT, 5 * 86400)
        out = _cli(["check", "--days", "1", "--root", root,
                    "--state-dir", self.state])
        self.assertIn("1 transcript(s) scanned", out)
        doc = json.loads(_cli(["check", "--json", "--days", "1", "--root", root,
                               "--state-dir", self.state]))
        self.assertEqual(doc["secrets"], [])


class GluedToWhatIsBeforeIt(_Reports):
    """-U admin%PASSWORD joins the password to the user with a %, which
    split no stretch: watch looked for admin%PASSWORD, which no transcript
    holds, and printed the value clean found in the .env read, the export
    or the JSON config whole. check, reading everything, masked it."""

    GLUED = "./share.sh //files/share -U admin%%%s -c 'get .env'"

    def exposures(self):
        config = json.dumps({"database": {"host": "db.internal", "password": PW}},
                            indent=2)
        return {
            "env": [_call(1, "cat .env", _stamp(2000)),
                    _result(1, "DB_PASSWORD=%s\n" % PW, _stamp(2000))],
            "export": [_call(1, "export DB_PASSWORD=%s" % PW, _stamp(2000)),
                       _result(1, "", _stamp(2000))],
            "json config": [_call(1, "cat config/settings.json", _stamp(2000)),
                            _result(1, config, _stamp(2000))],
        }

    def test_watch_never_prints_it(self):
        typed = [_call(2, self.GLUED % PW, _stamp(600)), _result(2, "ok", _stamp(600))]
        for exposure, read in self.exposures().items():
            for same in (True, False):
                root = _tempdir(self, "glued-")
                project = os.path.join(root, "-Users-a-app")
                if same:
                    _write(os.path.join(project, "sess.jsonl"), read + typed, 600)
                else:
                    _write(os.path.join(project, "sessA.jsonl"), read, 2000)
                    _write(os.path.join(project, "sessB.jsonl"), typed, 600)
                for argv in self.reports(root):
                    with self.subTest(exposure=exposure, same=same, argv=argv[:2]):
                        out = _cli(argv)
                        self.assertNotIn(PW, out)
                        self.assertIn(_MASKED, _shown(out))

    def test_each_place_a_value_can_start_or_end(self):
        stretches = clean._stretches("./share.sh -U admin%%%s+x9 -c x" % PW)
        self.assertIn(PW, stretches)
        self.assertIn(PW + "+x9", stretches)


class TypedManyTimesBeforeTheRead(_Reports):
    """watch read the first 64 lines holding a stretch, and no more. Typed
    in 70 calls before the .env read clean finds it in, the password was
    never looked up, and watch printed it whole. check masked it."""

    def test_watch_never_prints_it(self):
        for vary in (False, True):
            root = _tempdir(self, "lines-")
            rows = []
            for k in range(70):
                typed = SCRIPT.replace("prod ", "prod%d " % k if vary else "prod ", 1)
                rows += [_call(k, typed % PW, _stamp(600)), _result(k, "ok", _stamp(600))]
            rows += [_call(99, "cat .env", _stamp(600)),
                     _result(99, "DB_PASSWORD=%s\n" % PW, _stamp(600))]
            _write(os.path.join(root, "-Users-a-app", "sess.jsonl"), rows, 600)
            for argv in self.reports(root):
                with self.subTest(vary=vary, argv=argv[:2]):
                    out = _cli(argv)
                    self.assertNotIn(PW, out)
                    self.assertIn(_MASKED, _shown(out))

    def test_lines_that_read_alike_are_read_once(self):
        """A stretch in every line, after the same words (a session's id),
        is no secret's: its lines are not each decoded and asked."""
        root = _tempdir(self, "alike-")
        stretch = "Qz7mWx2KpL9vRt4N"
        rows = [{"type": "user", "sessionId": stretch, "message": {"content": "line %d" % k}}
                for k in range(3000)]
        _write(os.path.join(root, "-Users-a-app", "sess.jsonl"), rows, 600)
        decoded = mock.Mock(wraps=json.loads)
        with mock.patch.object(clean.json, "loads", decoded):
            self.assertEqual(clean.known_values(["rm -rf /srv/%s" % stretch], root=root), {})
        self.assertLess(decoded.call_count, 10)


class ALongHistory(_Reports):
    """The newest transcript is long, and the session that read the
    password read many keys with it: the search of other transcripts ran
    out of budget in the newest, and never reached the oldest, where the
    password was typed. clean --apply left that copy, and every report
    printed it."""

    def test_nothing_shows_it_after_masking(self):
        root = _tempdir(self, "budget-")
        project = os.path.join(root, "-Users-a-app")
        _write(os.path.join(project, "sessB.jsonl"),
               [_call(2, "mysql -u root -p%s -e 'DROP DATABASE prod'" % PW, _stamp(3000)),
                _result(2, "ok", _stamp(3000))], 3000)
        keys = "".join("SERVICE_%d_API_KEY=%s\n" % (i, ("Zx8Qm4Lp9Vb2Rt7Kc3Wn%02dQm4Lp9Vb2Rt7Kc3W" % i))
                       for i in range(70))
        _write(os.path.join(project, "sessA.jsonl"),
               [_call(1, "cat .env", _stamp(2000)),
                _result(1, keys + "DB_PASSWORD=%s\n" % PW, _stamp(2000))], 2000)
        build = [line for i in range(40) for line in (
            _call(100 + i, "npm run build -- --step %d" % i, _stamp(100)),
            _result(100 + i, "Compiling module %d, nothing to see here. " % i * 150,
                    _stamp(100)))]
        _write(os.path.join(project, "sessC.jsonl"), build, 100)
        self.assertNotIn("No secrets found", _cli(["clean", "--apply", "--root", root]))
        self.assertEqual(self.plaintext(root), [])
        for argv in self.reports(root):
            with self.subTest(argv=argv[:2]):
                self.assertNotIn(PW, _cli(argv))


if __name__ == "__main__":
    unittest.main(verbosity=2)
