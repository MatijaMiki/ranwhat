"""ranwhat login, whoami and logout (ranwhat/account.py), and what linking
a machine changes for update and the hints.

Every request goes to a server on this machine, http.server in a thread,
answering from a script as worker/src/device.js answers (the end-to-end
run against the Worker itself is in worker/test/device.test.mjs). No
proxy is used and nothing reaches the network. The clock is the test's:
polling sleeps on it rather than waiting. ranwhat's home is a temporary
directory, and every token is made at run time, so nothing token-shaped
sits in this file.
"""
import ast
import contextlib
import http.server
import io
import json
import os
import secrets
import shutil
import socket
import stat
import sys
import tempfile
import threading
import unittest
import urllib.parse
import urllib.request
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import isolated_home  # noqa: E402,F401  ranwhat's state, never ~/.ranwhat
from ranwhat import account, catalog, cli, feed  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
POSIX = os.name == "posix"
CODE = "BCDF-GHJK"
PAGE = "https://ranwhat.com/device"


def made(prefix="rw_" "m_"):
    """A token as the Worker makes one: a prefix and 32 random bytes."""
    return prefix + secrets.token_urlsafe(32)


def code_answer(**extra):
    doc = {"device_code": secrets.token_urlsafe(32), "user_code": CODE,
           "verification_uri": PAGE, "expires_in": 600, "interval": 5}
    doc.update(extra)
    return 200, doc


def granted(token, plan="plus", **extra):
    doc = {"access_token": token, "token_type": "Bearer",
           "email": "ana@example.com", "org": "Acme", "plan": plan}
    doc.update(extra)
    return 200, doc


PENDING = (400, {"error": "authorization_pending",
                 "error_description": "Waiting for the code to be typed."})


def device_doc(plan="plus", label="laptop", kind="device"):
    return {"kind": kind, "email": "ana@example.com", "org": "Acme",
            "role": "owner", "plan": plan,
            "machine": {"label": label, "created_at": 1791331200}}


class Server:
    """Answers from a script: each (method, path) has a list of (status,
    body) answers, given in turn, the last one for good. Records every
    request it is sent."""

    def __init__(self):
        self.script = {}
        self.seen = []
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def _answer(self):
                n = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(n).decode("utf-8") if n else ""
                outer.seen.append({"method": self.command, "path": self.path,
                                   "headers": dict(self.headers.items()),
                                   "body": body})
                answers = outer.script.get((self.command, self.path))
                if not answers:
                    status, doc = 404, {"error": "Not found"}
                else:
                    status, doc = answers.pop(0) if len(answers) > 1 else answers[0]
                data = doc if isinstance(doc, bytes) else json.dumps(doc).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            do_GET = do_POST = _answer

            def log_message(self, *a):
                pass

        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.httpd.serve_forever,
                                       kwargs={"poll_interval": 0.02}, daemon=True)
        self.thread.start()

    @property
    def base(self):
        return "http://127.0.0.1:%d/v1" % self.httpd.server_port

    def on(self, method, path, *answers):
        self.script[(method, "/v1" + path)] = list(answers)

    def requests(self, path):
        return [r for r in self.seen if r["path"] == "/v1" + path]

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join()


class Clock:
    """time.monotonic and time.sleep for account.py, moved by sleeping."""

    def __init__(self):
        self.now = 1000.0
        self.sleeps = []
        self.interrupt_at = None

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        if self.interrupt_at is not None and len(self.sleeps) >= self.interrupt_at:
            raise KeyboardInterrupt
        self.now += seconds

    def __call__(self):
        return self.now


class Tty(io.StringIO):
    def isatty(self):
        return True


def closed_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class AccountCase(unittest.TestCase):

    def setUp(self):
        self.home = tempfile.mkdtemp(prefix="ranwhat-account-")
        self.addCleanup(shutil.rmtree, self.home, True)
        self.server = Server()
        self.addCleanup(self.server.close)
        env = mock.patch.dict(os.environ, {
            "RANWHAT_HOME": os.path.join(self.home, ".ranwhat"),
            "HOME": self.home, "USERPROFILE": self.home,
            "RANWHAT_ACCOUNT_URL": self.server.base,
            "RANWHAT_FEED_URL": self.server.base + "/catalogue",
            "RANWHAT_NO_HINTS": "1", "NO_COLOR": "1"})
        env.start()
        self.addCleanup(env.stop)
        for name in ("RANWHAT_TOKEN", "SSH_CONNECTION", "SSH_CLIENT", "SSH_TTY"):
            os.environ.pop(name, None)     # put back by env.stop
        # No proxy from the environment or the system: every request goes
        # to the server above and nowhere else.
        for target, name, value in ((urllib.request, "getproxies", dict),):
            patcher = mock.patch.object(target, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.clock = Clock()
        for name, value in (("_sleep", self.clock.sleep), ("_clock", self.clock)):
            patcher = mock.patch.object(account, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        patcher = mock.patch.object(account, "_open_browser", return_value=True)
        self.browser = patcher.start()
        self.addCleanup(patcher.stop)
        catalog.reset_feed_cache()
        self.addCleanup(catalog.reset_feed_cache)

    # helpers

    def run_cli(self, *argv, tty=False):
        out, err = (Tty() if tty else io.StringIO()), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            status = cli.main(list(argv))
        return status, out.getvalue(), err.getvalue()

    def token_file(self):
        return feed.token_path()

    def saved(self):
        with open(self.token_file(), encoding="utf-8") as fh:
            return fh.read()

    def save(self, token):
        feed.save_token(token)
        return token

    def assertNotShown(self, secret, *texts):
        for text in texts:
            self.assertNotIn(secret, text)
            self.assertNotIn(secret[len("rw_m_"):], text)

    def symlink_or_skip(self, target, link):
        try:
            os.symlink(target, link)
        except (OSError, NotImplementedError, AttributeError):
            self.skipTest("symlinks cannot be made here")


# ---------- login ----------

class Login(AccountCase):

    def link(self, token, *answers, argv=("login",), tty=False):
        self.server.on("POST", "/device/code", code_answer())
        self.server.on("POST", "/device/token", *(answers or (PENDING, granted(token))))
        return self.run_cli(*argv, tty=tty)

    def test_it_saves_the_token_where_update_reads_it_and_says_where_it_is_linked(self):
        token = made()
        status, out, err = self.link(token, PENDING, PENDING, granted(token))
        self.assertEqual(status, 0, err)
        self.assertEqual(self.saved(), token + "\n")
        self.assertEqual(feed.read_token(), token)
        self.assertIn(CODE, out)
        self.assertIn(PAGE, out)
        self.assertIn("Linked to Acme as ana@example.com (Plus).", out)
        self.assertNotIn("need Plus", out)
        self.assertNotShown(token, out, err)
        self.assertEqual(self.clock.sleeps, [5, 5, 5])

    def test_it_sends_the_client_id_and_the_device_code_and_nothing_about_the_machine(self):
        token = made()
        status, _out, err = self.link(token)
        self.assertEqual(status, 0, err)
        asked = self.server.requests("/device/code")
        self.assertEqual([r["body"] for r in asked], ["client_id=ranwhat-cli"])
        polls = self.server.requests("/device/token")
        self.assertEqual(len(polls), 2)
        for r in polls:
            form = urllib.parse.parse_qs(r["body"])
            self.assertEqual(set(form), {"client_id", "grant_type", "device_code"})
            self.assertEqual(form["grant_type"],
                             ["urn:ietf:params:oauth:grant-type:device_code"])
        machine = {socket.gethostname(), os.path.basename(self.home)}
        try:
            import getpass
            machine.add(getpass.getuser())
        except Exception:
            pass
        allowed = {"host", "accept", "user-agent", "content-type", "content-length",
                   "connection", "accept-encoding"}
        for r in self.server.seen:
            self.assertLessEqual({k.lower() for k in r["headers"]}, allowed, r["path"])
            self.assertNotIn("authorization", {k.lower() for k in r["headers"]})
            self.assertEqual(r["headers"].get("User-Agent"), "ranwhat-cli/1")
            for value in list(r["headers"].values()) + [r["body"], r["path"]]:
                for word in machine:
                    if len(word) > 3:
                        self.assertNotIn(word, value)
                self.assertNotIn(sys.platform, value)

    def test_the_code_is_never_carried_in_a_link(self):
        token = made()
        evil = [PAGE + "?user_code=" + CODE, PAGE + "/" + CODE, PAGE + "#" + CODE,
                "https://ranwhat.com.evil.example/device", "https://evil.example/device",
                "http://ranwhat.com/device", "https://ranwhat.com:8443/device",
                "https://user@ranwhat.com/device", "javascript:alert(1)", 42, None]
        for uri in evil:
            with self.subTest(uri=uri):
                self.browser.reset_mock()
                os.environ["DISPLAY"] = ":0"
                self.server.on("POST", "/device/code", code_answer(
                    verification_uri=uri, verification_uri_complete=PAGE + "?code=" + CODE))
                self.server.on("POST", "/device/token", granted(token))
                status, out, err = self.run_cli("login", "--force", tty=True)
                self.assertEqual(status, 0, err)
                for line in out.splitlines():
                    if "http" in line or "ranwhat.com" in line:
                        self.assertNotIn(CODE, line)
                        self.assertNotIn("evil", line)
                self.assertIn("    %s\n" % PAGE, out)
                self.assertIn("    %s\n" % CODE, out)
                for call in self.browser.call_args_list:
                    self.assertEqual(call.args, (PAGE,))

    def test_a_staging_device_page_is_shown_as_the_server_names_it(self):
        token = made()
        page = "https://staging.ranwhat.com/device"
        self.server.on("POST", "/device/code", code_answer(verification_uri=page))
        self.server.on("POST", "/device/token", granted(token))
        status, out, err = self.run_cli("login")
        self.assertEqual(status, 0, err)
        self.assertIn("    %s\n" % page, out)

    def test_slow_down_adds_five_seconds_or_what_the_server_asks(self):
        token = made()
        slow = (400, {"error": "slow_down", "interval": 12})
        slower = (400, {"error": "slow_down"})
        status, _out, err = self.link(token, PENDING, slow, slower, PENDING, granted(token))
        self.assertEqual(status, 0, err)
        self.assertEqual(self.clock.sleeps, [5, 5, 12, 17, 17])

    def test_denied_expired_and_unknown_codes_end_it_with_nothing_saved(self):
        cases = [
            ((400, {"error": "access_denied"}), "not approved"),
            ((400, {"error": "expired_token"}), "expired"),
            ((400, {"error": "invalid_grant", "error_description":
                    "That device code is not known, or was already used."}),
             "not known"),
            ((400, {"error": "invalid_client"}), "HTTP 400"),
        ]
        for answer, said in cases:
            with self.subTest(said=said):
                status, out, err = self.link(made(), PENDING, answer)
                self.assertEqual(status, 1)
                self.assertIn(said, err)
                self.assertFalse(os.path.lexists(self.token_file()))
                self.assertNotIn("Linked", out)

    def test_it_stops_when_the_code_runs_out_whatever_the_server_says(self):
        self.server.on("POST", "/device/code", code_answer(expires_in=12))
        self.server.on("POST", "/device/token", PENDING)
        status, _out, err = self.run_cli("login")
        self.assertEqual(status, 1)
        self.assertIn("expired before it was approved", err)
        self.assertEqual(len(self.server.requests("/device/token")), 2)
        self.assertFalse(os.path.lexists(self.token_file()))

    def test_ctrl_c_cancels_cleanly(self):
        self.clock.interrupt_at = 2
        status, out, err = self.link(made(), PENDING, PENDING)
        self.assertEqual(status, 130)
        self.assertIn("Cancelled. Nothing was linked", err)
        self.assertNotIn("Traceback", out + err)
        self.assertFalse(os.path.lexists(self.token_file()))

    def test_a_server_that_is_briefly_unavailable_is_waited_out(self):
        token = made()
        busy = (503, {"error": "temporarily_unavailable"})
        status, _out, err = self.link(token, busy, (502, b"<html>bad gateway</html>"),
                                      PENDING, granted(token))
        self.assertEqual(status, 0, err)
        self.assertEqual(self.saved(), token + "\n")

    def test_one_that_stays_unavailable_is_given_up_on(self):
        busy = (503, {"error": "temporarily_unavailable",
                      "error_description": "Linking a terminal is not available just now."})
        status, _out, err = self.link(made(), busy)
        self.assertEqual(status, 1)
        self.assertIn("not available just now", err)
        self.assertEqual(len(self.server.requests("/device/token")), account.MAX_FAILURES)

    def test_no_server_no_code(self):
        os.environ["RANWHAT_ACCOUNT_URL"] = "http://127.0.0.1:%d/v1" % closed_port()
        status, out, err = self.run_cli("login")
        self.assertEqual(status, 1)
        self.assertIn("Could not reach 127.0.0.1", err)
        self.assertNotIn(CODE, out)

    def test_accounts_not_switched_on_yet(self):
        # The Worker answers 404 on every device path until ACCOUNTS_ON.
        status, _out, err = self.run_cli("login")
        self.assertEqual(status, 1)
        self.assertIn("does not link terminals yet", err)

    def test_plain_http_is_refused_anywhere_but_this_machine(self):
        os.environ["RANWHAT_ACCOUNT_URL"] = "http://feed.ranwhat.com/v1"
        status, _out, err = self.run_cli("login")
        self.assertEqual(status, 1)
        self.assertIn("must be https", err)
        self.assertEqual(self.server.seen, [])

    def test_a_token_without_a_tokens_shape_is_not_saved(self):
        for bad in ("rw_" "m_short", "xx_" + "a" * 43, "rw_" "m_" + "a" * 40 + "\n" + "b" * 3,
                    "rw_" "m_" + "a" * 40 + "\x1b[2J", 12, None):
            with self.subTest(bad=bad):
                status, _out, err = self.link(None, (200, {"access_token": bad, "plan": "plus"}))
                self.assertEqual(status, 1)
                self.assertIn("no token ranwhat can use", err)
                self.assertFalse(os.path.lexists(self.token_file()))

    def test_a_code_with_a_control_character_is_not_shown(self):
        self.server.on("POST", "/device/code", code_answer(user_code="BCDF\x1b[2J-GHJK"))
        status, out, err = self.run_cli("login")
        self.assertEqual(status, 1)
        self.assertNotIn("\x1b", out + err)
        self.assertEqual(self.server.requests("/device/token"), [])

    def test_what_the_server_says_is_shown_without_control_characters(self):
        token = made()
        status, out, err = self.link(token, granted(
            token, org="Ac\x1b[2Jme‮", email="ana@example.com\x07\r\x1b]52;c;eA==\x07"))
        self.assertEqual(status, 0, err)
        self.assertIn("Linked to Ac[2Jme as ana@example.com]52;c;eA== (Plus).", out)
        for c in ("\x1b", "\x07", "\r", "‮"):
            self.assertNotIn(c, out + err)
        description = "Wait\x1b[1A\x1b[2K, then try again."
        status, out, err = self.link(made(), (400, {"error": "x", "error_description": description}),
                                     argv=("login", "--force"))
        self.assertEqual(status, 1)
        self.assertIn("Wait[1A[2K, then try again.", err)
        self.assertNotIn("\x1b", out + err)

    def test_a_free_organisation_is_told_what_needs_plus(self):
        token = made()
        status, out, err = self.link(token, granted(token, plan="free"))
        self.assertEqual(status, 0, err)
        self.assertIn("Linked to Acme as ana@example.com (Free).", out)
        self.assertIn("need Plus", out)
        self.assertIn("https://account.ranwhat.com/", out)
        self.assertEqual(account.cached_plan(token), "free")

    def test_an_existing_token_is_kept_without_force_and_named(self):
        old = self.save(made())
        self.server.on("GET", "/whoami", (200, device_doc()))
        status, out, err = self.link(made())
        self.assertEqual(status, 1)
        self.assertIn("already has a saved token (ana@example.com, Acme, Plus)", err)
        self.assertIn("--force", err)
        self.assertEqual(self.saved(), old + "\n")
        self.assertEqual(self.server.requests("/device/code"), [])
        self.assertEqual(self.server.requests("/whoami")[0]["headers"]["Authorization"],
                         "Bearer " + old)
        self.assertNotShown(old, out, err)

    def test_one_the_server_no_longer_accepts_or_cannot_name_is_kept_too(self):
        self.save(made())
        for answer, said in (((403, {"error": "That token was not accepted."}),
                              "one the server no longer accepts"),
                             ((503, {}), "could not be asked")):
            with self.subTest(said=said):
                self.server.on("GET", "/whoami", answer)
                status, _out, err = self.link(made())
                self.assertEqual(status, 1)
                self.assertIn(said, err)

    def test_force_replaces_it(self):
        self.save(made())
        token = made()
        self.server.on("GET", "/whoami", (200, device_doc()))
        status, out, err = self.link(token, argv=("login", "--force"))
        self.assertEqual(status, 0, err)
        self.assertEqual(self.saved(), token + "\n")
        self.assertEqual(self.server.requests("/whoami"), [])

    def test_a_symlink_at_the_token_path_is_never_written_through(self):
        os.makedirs(os.path.dirname(self.token_file()), exist_ok=True)
        target = os.path.join(self.home, "elsewhere")
        with open(target, "w", encoding="utf-8") as fh:
            fh.write("untouched\n")
        self.symlink_or_skip(target, self.token_file())
        for argv in (("login",), ("login", "--force")):
            with self.subTest(argv=argv):
                status, _out, err = self.link(made(), argv=argv)
                self.assertEqual(status, 1)
                self.assertIn("is a symlink", err)
                with open(target, encoding="utf-8") as fh:
                    self.assertEqual(fh.read(), "untouched\n")
                self.assertTrue(os.path.islink(self.token_file()))
                self.assertEqual(self.server.seen, [])

    def test_ranwhat_token_in_the_environment_is_warned_about(self):
        os.environ["RANWHAT_TOKEN"] = made("rw_")
        token = made()
        status, out, err = self.link(token)
        self.assertEqual(status, 0, err)
        self.assertIn("RANWHAT_TOKEN is set", out)
        self.assertEqual(self.saved(), token + "\n")
        self.assertNotShown(os.environ["RANWHAT_TOKEN"], out, err)

    @unittest.skipUnless(POSIX, "file modes are POSIX")
    def test_the_token_and_the_plan_cache_are_the_owners_alone(self):
        os.makedirs(os.path.dirname(self.token_file()), exist_ok=True)
        old = os.umask(0)
        try:
            token = made()
            status, _out, err = self.link(token)
        finally:
            os.umask(old)
        self.assertEqual(status, 0, err)
        for path in (self.token_file(), account.cache_path()):
            with self.subTest(path=path):
                self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)

    def test_the_plan_cache_holds_the_tokens_hash_never_the_token(self):
        token = made()
        status, _out, err = self.link(token)
        self.assertEqual(status, 0, err)
        with open(account.cache_path(), encoding="utf-8") as fh:
            text = fh.read()
        self.assertNotIn(token, text)
        self.assertNotIn(token[len("rw_m_"):], text)
        doc = json.loads(text)
        self.assertEqual(doc["plan"], "plus")
        self.assertEqual(doc["org"], "Acme")
        self.assertEqual(doc["email"], "ana@example.com")
        self.assertEqual(len(doc["token_sha256"]), 64)


class TheBrowser(AccountCase):
    """Opened only for ranwhat's own page, on a terminal, with a display,
    not over SSH, and not with --no-browser."""

    def may(self, url=PAGE, no_browser=False, tty=True, environ=None, platform="linux"):
        stream = Tty() if tty else io.StringIO()
        env = {"DISPLAY": ":0"} if environ is None else environ
        return account._may_open(url, no_browser, stream, environ=env, platform=platform)

    def test_the_rules(self):
        self.assertTrue(self.may())
        self.assertTrue(self.may(environ={"WAYLAND_DISPLAY": "wayland-0"}))
        self.assertTrue(self.may(environ={}, platform="darwin"))
        self.assertTrue(self.may(environ={}, platform="win32"))
        self.assertTrue(self.may("http://127.0.0.1:8787/device"))
        self.assertFalse(self.may(environ={}), "no display")
        self.assertFalse(self.may(tty=False))
        self.assertFalse(self.may(no_browser=True))
        for name in ("SSH_CONNECTION", "SSH_CLIENT", "SSH_TTY"):
            self.assertFalse(self.may(environ={"DISPLAY": ":0", name: "x"}), name)
            self.assertFalse(self.may(environ={name: "x"}, platform="darwin"), name)
        for url in ("https://evil.example/device", PAGE + "?code=" + CODE,
                    PAGE + "/" + CODE, "http://ranwhat.com/device", "file:///etc/passwd"):
            self.assertFalse(self.may(url), url)

    def test_login_opens_the_page_without_the_code_on_a_terminal(self):
        os.environ["DISPLAY"] = ":0"
        token = made()
        self.server.on("POST", "/device/code", code_answer())
        self.server.on("POST", "/device/token", granted(token))
        # A display on Linux, and always one on macOS and Windows.
        status, out, err = self.run_cli("login", tty=True)
        self.assertEqual(status, 0, err)
        self.browser.assert_called_once_with(PAGE)
        self.assertIn("open in your browser", out)

    def test_not_with_no_browser_nor_off_a_terminal_nor_over_ssh(self):
        os.environ["DISPLAY"] = ":0"
        for argv, tty, env in ((("login", "--no-browser"), True, {}),
                               (("login",), False, {}),
                               (("login",), True, {"SSH_CONNECTION": "10.0.0.1 22 10.0.0.2 22"}),
                               (("login",), True, {"SSH_TTY": "/dev/pts/1"})):
            with self.subTest(argv=argv, tty=tty, env=env):
                self.browser.reset_mock()
                with mock.patch.dict(os.environ, env):
                    if os.path.lexists(self.token_file()):
                        feed.delete_token()
                    self.server.on("POST", "/device/code", code_answer())
                    self.server.on("POST", "/device/token", granted(made()))
                    status, out, err = self.run_cli(*argv, tty=tty)
                self.assertEqual(status, 0, err)
                self.browser.assert_not_called()
                self.assertIn(PAGE, out)


# ---------- whoami ----------

class Whoami(AccountCase):

    def test_not_logged_in(self):
        status, out, err = self.run_cli("whoami")
        self.assertEqual(status, 1)
        self.assertIn("Not logged in", err)
        self.assertEqual(out, "")
        self.assertEqual(self.server.seen, [])

    def test_a_machine_token_names_the_account_organisation_plan_and_machine(self):
        token = self.save(made())
        self.server.on("GET", "/whoami", (200, device_doc()))
        status, out, err = self.run_cli("whoami")
        self.assertEqual(status, 0, err)
        lines = [" ".join(l.split()) for l in out.splitlines()]
        for line in ("Account ana@example.com", "Organisation Acme", "Role owner",
                     "Plan Plus", "Machine laptop", "Linked 2026-10-07"):
            self.assertIn(line, lines)
        asked = self.server.requests("/whoami")
        self.assertEqual([(r["method"], r["headers"]["Authorization"]) for r in asked],
                         [("GET", "Bearer " + token)])
        self.assertNotShown(token, out, err)
        self.assertEqual(account.cached_plan(token), "plus")

    def test_an_unnamed_machine_says_where_to_name_it(self):
        self.save(made())
        self.server.on("GET", "/whoami", (200, device_doc(label=None)))
        status, out, err = self.run_cli("whoami")
        self.assertEqual(status, 0, err)
        self.assertIn("not named yet; name it at https://account.ranwhat.com/", out)

    def test_a_ci_token(self):
        self.save(made("rw_" "c_"))
        self.server.on("GET", "/whoami", (200, device_doc(kind="ci", label="deploy")))
        status, out, _err = self.run_cli("whoami")
        self.assertEqual(status, 0)
        self.assertIn("CI token", out)
        self.assertIn("deploy", out)

    def test_shared_and_hand_issued_tokens(self):
        self.save(made("rw_"))
        for doc, said in (({"kind": "subscription", "org": None, "plan": "plus"},
                           "a shared subscription token"),
                          ({"kind": "subscription", "org": "Acme", "plan": "team"},
                           "a shared subscription token"),
                          ({"kind": "hand", "plan": "plus"}, "a hand-issued token")):
            with self.subTest(doc=doc):
                self.server.on("GET", "/whoami", (200, doc))
                status, out, err = self.run_cli("whoami")
                self.assertEqual(status, 0, err)
                self.assertIn(said, out)
                self.assertIn(account.PLANS[doc["plan"]], out)

    def test_a_free_organisation_is_told_what_needs_plus(self):
        token = self.save(made())
        self.server.on("GET", "/whoami", (200, device_doc(plan="free")))
        status, out, _err = self.run_cli("whoami")
        self.assertEqual(status, 0)
        self.assertIn("Plan          Free", out)
        self.assertIn("need Plus", out)
        self.assertIn("https://account.ranwhat.com/", out)
        self.assertEqual(account.cached_plan(token), "free")

    def test_a_revoked_token(self):
        self.save(made())
        self.server.on("GET", "/whoami", (403, {"error": "That token was not accepted."}))
        status, out, err = self.run_cli("whoami")
        self.assertEqual(status, 1)
        self.assertIn("did not accept", err)
        self.assertIn("ranwhat login", err)
        self.assertEqual(out, "")

    def test_no_server(self):
        self.save(made())
        os.environ["RANWHAT_ACCOUNT_URL"] = "http://127.0.0.1:%d/v1" % closed_port()
        status, _out, err = self.run_cli("whoami")
        self.assertEqual(status, 1)
        self.assertIn("Could not reach", err)

    def test_ranwhat_token_comes_first_as_it_does_for_update(self):
        saved = self.save(made())
        env = os.environ["RANWHAT_TOKEN"] = made("rw_" "c_")
        self.server.on("GET", "/whoami", (200, device_doc(kind="ci")))
        status, out, err = self.run_cli("whoami")
        self.assertEqual(status, 0, err)
        self.assertEqual(self.server.seen[0]["headers"]["Authorization"], "Bearer " + env)
        self.assertIn("RANWHAT_TOKEN", out)
        self.assertIn("is not used while RANWHAT_TOKEN is set", out)
        self.assertNotShown(env, out, err)
        self.assertNotShown(saved, out, err)

    def test_token_flag_is_warned_about_and_used(self):
        token = made("rw_" "c_")
        self.server.on("GET", "/whoami", (200, device_doc(kind="ci")))
        status, out, err = self.run_cli("whoami", "--token", token)
        self.assertEqual(status, 0, err)
        self.assertIn("readable by every user", err)
        self.assertEqual(self.server.seen[0]["headers"]["Authorization"], "Bearer " + token)
        self.assertNotShown(token, out, err)

    def test_a_symlinked_token_is_not_read_through(self):
        os.makedirs(os.path.dirname(self.token_file()), exist_ok=True)
        target = os.path.join(self.home, "elsewhere")
        with open(target, "w", encoding="utf-8") as fh:
            fh.write(made() + "\n")
        self.symlink_or_skip(target, self.token_file())
        status, _out, err = self.run_cli("whoami")
        self.assertEqual(status, 1)
        self.assertIn("symlink", err)
        self.assertEqual(self.server.seen, [])

    def test_what_the_server_says_is_shown_without_control_characters(self):
        self.save(made())
        self.server.on("GET", "/whoami", (200, {
            "kind": "device", "email": "a\x1b[31m@b", "org": "\x1b]0;title\x07Org",
            "role": "owner\x1b[0m", "plan": "plus",
            "machine": {"label": "lap‮top\x1b[2J", "created_at": "soon"}}))
        status, out, err = self.run_cli("whoami")
        self.assertEqual(status, 0, err)
        for c in ("\x1b", "\x07", "‮"):
            self.assertNotIn(c, out + err)
        self.assertIn("laptop[2J", out)
        self.assertNotIn("Linked", out)


# ---------- logout ----------

class Logout(AccountCase):

    def test_a_terminals_token_is_revoked_then_deleted(self):
        token = self.save(made())
        account.remember(token, "plus", "Acme", "ana@example.com")
        self.server.on("POST", "/logout", (200, {"revoked": True}))
        status, out, err = self.run_cli("logout")
        self.assertEqual(status, 0, err)
        self.assertIn("revoked and deleted", out)
        self.assertFalse(os.path.lexists(self.token_file()))
        self.assertFalse(os.path.lexists(account.cache_path()))
        asked = self.server.requests("/logout")
        self.assertEqual([(r["method"], r["headers"]["Authorization"]) for r in asked],
                         [("POST", "Bearer " + token)])
        self.assertNotShown(token, out, err)

    def test_a_shared_token_is_only_deleted_here(self):
        self.save(made("rw_"))
        self.server.on("POST", "/logout", (200, {"revoked": False, "shared": True}))
        status, out, _err = self.run_cli("logout")
        self.assertEqual(status, 0)
        self.assertIn("shared token", out)
        self.assertIn("still", out)
        self.assertFalse(os.path.lexists(self.token_file()))

    def test_with_no_server_it_is_deleted_here_and_said_to_stay_listed(self):
        for base in ("http://127.0.0.1:%d/v1" % closed_port(), None):
            with self.subTest(base=base):
                self.save(made())
                if base:
                    os.environ["RANWHAT_ACCOUNT_URL"] = base
                else:
                    # Up, but not answering for accounts (ACCOUNTS_ON unset).
                    os.environ["RANWHAT_ACCOUNT_URL"] = self.server.base
                    self.server.on("POST", "/logout", (404, {"error": "Not found"}))
                status, out, err = self.run_cli("logout")
                self.assertEqual(status, 0)
                self.assertIn("Deleted the saved token", out)
                self.assertIn("stays listed", err)
                self.assertIn("https://account.ranwhat.com/", err)
                self.assertFalse(os.path.lexists(self.token_file()))

    def test_one_the_server_no_longer_accepts_is_deleted(self):
        self.save(made())
        self.server.on("POST", "/logout", (403, {"error": "That token was not accepted."}))
        status, out, err = self.run_cli("logout")
        self.assertEqual(status, 0)
        self.assertIn("Deleted the saved token", out)
        self.assertIn("no longer accepted", err)
        self.assertFalse(os.path.lexists(self.token_file()))

    def test_not_logged_in(self):
        status, _out, err = self.run_cli("logout")
        self.assertEqual(status, 1)
        self.assertIn("Not logged in", err)
        self.assertEqual(self.server.seen, [])

    def test_a_symlink_is_removed_never_followed(self):
        os.makedirs(os.path.dirname(self.token_file()), exist_ok=True)
        target = os.path.join(self.home, "elsewhere")
        secret = made()
        with open(target, "w", encoding="utf-8") as fh:
            fh.write(secret + "\n")
        self.symlink_or_skip(target, self.token_file())
        status, out, err = self.run_cli("logout")
        self.assertEqual(status, 0, err)
        self.assertFalse(os.path.lexists(self.token_file()))
        with open(target, encoding="utf-8") as fh:
            self.assertEqual(fh.read(), secret + "\n")
        self.assertEqual(self.server.seen, [], "what the link points to was never sent")
        self.assertIn("symlink", err)

    def test_ranwhat_token_is_left_alone(self):
        saved = self.save(made())
        os.environ["RANWHAT_TOKEN"] = made("rw_" "c_")
        self.server.on("POST", "/logout", (200, {"revoked": True}))
        status, out, err = self.run_cli("logout")
        self.assertEqual(status, 0, err)
        self.assertEqual(self.server.seen[0]["headers"]["Authorization"], "Bearer " + saved)
        self.assertIn("RANWHAT_TOKEN is still set", out)


# ---------- update, the hints and the flags ----------

class UpdateOnAFreeOrganisation(AccountCase):

    def test_plus_required_names_the_plan_and_the_upgrade_link(self):
        token = self.save(made())
        account.remember(token, "plus", "Acme", "ana@example.com")
        self.server.on("GET", "/catalogue", (403, {"error": "plus_required",
                                                   "upgrade": "https://account.ranwhat.com/"}))
        status, _out, err = self.run_cli("update")
        self.assertEqual(status, 1)
        self.assertIn("linked to Acme, which is on Free", " ".join(err.split()))
        self.assertIn("part of Plus: https://account.ranwhat.com/", " ".join(err.split()))
        self.assertEqual(account.cached_plan(token), "free")
        self.assertNotShown(token, err)

    def test_an_upgrade_link_off_ranwhat_com_is_not_printed(self):
        self.save(made())
        for link in ("https://evil.example/pay", "http://account.ranwhat.com/",
                     "https://account.ranwhat.com.evil.example/", "https://account.ranwhat.com/\x1b[2J",
                     ["https://account.ranwhat.com/"]):
            with self.subTest(link=link):
                self.server.on("GET", "/catalogue", (403, {"error": "plus_required", "upgrade": link}))
                status, _out, err = self.run_cli("update")
                self.assertEqual(status, 1)
                self.assertIn("https://account.ranwhat.com/\n", err)
                self.assertNotIn("evil", err)
                self.assertNotIn("\x1b", err)
        self.assertEqual(feed._upgrade_link("https://account.ranwhat.com/upgrade"),
                         "https://account.ranwhat.com/upgrade")

    def test_a_0_5_0_style_refusal_is_the_refusal_it_always_was(self):
        self.save(made("rw_"))
        for body in ({"error": "That token was not accepted."}, b"", b"forbidden",
                     {"error": "plus_required_but_not_quite"}):
            with self.subTest(body=body):
                self.server.on("GET", "/catalogue", (403, body))
                status, _out, err = self.run_cli("update")
                self.assertEqual(status, 1)
                self.assertIn("That token was not accepted", err)

    def test_a_feed_served_means_not_free_any_more(self):
        token = self.save(made())
        account.remember(token, "free", "Acme", "ana@example.com")
        cat = {"acme": {"acme:delete": {"label": "X", "authority": "write",
                                        "reversible": False, "blast": "data_egress",
                                        "why": "because"}}}
        self.server.on("GET", "/catalogue", (200, {"schema": feed.SCHEMA, "version": "t",
                                                   "catalogue": cat, "digest": feed.digest(cat)}))
        status, _out, err = self.run_cli("update")
        self.assertEqual(status, 0, err)
        self.assertEqual(account.cached_plan(token), "plus")


class HasPlus(AccountCase):

    def test_a_cached_free_plan_still_sees_the_hints(self):
        token = self.save(made())
        with mock.patch.object(catalog, "feed_adds_scopes", return_value=False):
            self.assertTrue(cli._has_plus(), "a token it has no cache for")
            account.remember(token, "free", "Acme", "ana@example.com")
            self.assertFalse(cli._has_plus())
            account.remember(token, "plus", "Acme", "ana@example.com")
            self.assertTrue(cli._has_plus())
            account.remember(made(), "free")
            self.assertTrue(cli._has_plus(), "the cache is another token's")
            feed.delete_token()
            self.assertFalse(cli._has_plus())

    def test_a_cache_that_is_not_one_is_none(self):
        token = made()
        os.makedirs(os.path.dirname(account.cache_path()), exist_ok=True)
        for text in ("", "[]", "{", '{"plan": "free"}', '{"token_sha256": 1, "plan": "free"}',
                     json.dumps({"token_sha256": account._sha256(token), "plan": "gold"})):
            with self.subTest(text=text):
                with open(account.cache_path(), "w", encoding="utf-8") as fh:
                    fh.write(text)
                self.assertIsNone(account.cached_plan(token))


class Flags(AccountCase):

    def test_each_flag_is_refused_where_it_means_nothing(self):
        for argv in (("whoami", "--force"), ("logout", "--no-browser"), ("update", "--force"),
                     ("login", "--token", "x"), ("logout", "--token", "x"),
                     ("login", "somewhere")):
            with self.subTest(argv=argv):
                with self.assertRaises(SystemExit) as caught:
                    self.run_cli(*argv)
                self.assertEqual(caught.exception.code, 2)
        self.assertEqual(self.server.seen, [])

    def test_the_overview_lists_them(self):
        names = [name for name, _what in cli.COMMANDS]
        for name in ("login", "whoami", "logout"):
            self.assertIn(name, names)
        self.assertIn("login, whoami and logout", cli.NETWORK)


class TheModule(unittest.TestCase):

    def test_it_imports_the_standard_library_only(self):
        path = os.path.join(ROOT, "ranwhat", "account.py")
        with open(path, encoding="utf-8") as fh:
            tree = ast.parse(fh.read())
        stdlib = getattr(sys, "stdlib_module_names", None)
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                if node.level:
                    continue
                names = [node.module]
            elif isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            else:
                continue
            for name in names:
                top = name.split(".")[0]
                if stdlib is not None:
                    self.assertIn(top, stdlib, name)
                else:
                    self.assertIn(top, {"__future__", "hashlib", "http", "json", "os",
                                        "re", "ssl", "sys", "time", "urllib",
                                        "webbrowser"}, name)


if __name__ == "__main__":
    unittest.main()
