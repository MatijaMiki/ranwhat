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
