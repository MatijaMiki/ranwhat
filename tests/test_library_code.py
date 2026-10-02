"""Library code read out of node_modules, a bundle or an SDK helper, and
the chosen passwords that look like it.

Once camelCase and PascalCase keys named secrets, code that only reads a
property or re-exports a name was listed by clean as a secret to rotate,
and raised by watch as a critical secret.literal when an agent wrote it:
secretAccessKey: data.Credentials.SecretAccessKey, exports.AuthCredential
= index.AuthCredential, minified ternaries and chained assignments,
React's prop-types constant. main read none of those keys, and was silent
on every one. Each line here is from public library code or written the
way it is; every value is synthetic.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ranwhat import clean, watch
from ranwhat.clean import find_secrets

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PAD = "\n# padding so the text clears the minimum scan length"


def _literal(text):
    return [h for h in watch.evaluate("Bash", {"command": text})[0]
            if h["rule"] == "secret.literal"]


def _written(text, path="/a/src/x.ts"):
    return [h for h in watch.evaluate("Write", {"file_path": path, "content": text})[0]
            if h["rule"] == "secret.literal"]


class Silent(object):

    def assertSilent(self, texts):
        for text in texts:
            with self.subTest(text=text):
                self.assertEqual(find_secrets(text + PAD), [])
                self.assertEqual(find_secrets(text), [])
                self.assertEqual(_literal(text), [])
                self.assertEqual(_written(text), [])

    def assertFound(self, cases):
        for text, value in cases:
            with self.subTest(text=text):
                self.assertEqual([v for v, _l in find_secrets(text + PAD)], [value])


class PropertyReads(Silent, unittest.TestCase):
    """C#, Go, the AWS SDK and TypeScript's CommonJS output read a
    property named as the key is, in PascalCase, or off a receiver that is
    plainly a variable's name."""

    def test_a_property_named_as_the_key_is_code(self):
        self.assertSilent([
            "ClientSecret = options.ClientSecret,",
            "ClientSecret = settings.AzureAd.ClientSecret,",
            "AccessToken: tok.AccessToken,",
            "SessionToken: creds.SessionToken,",
            "SecretAccessKey: creds.SecretAccessKey,",
            "secretAccessKey: data.Credentials.SecretAccessKey,",
            "sessionToken: data.Credentials.SessionToken,",
            "sessionToken: credentials.SessionToken,",
            "PrivateKey: key.PrivateKey,",
            "refreshToken: res.RefreshToken,",
            "this.accessToken = response.AccessToken;",
            "this.secretKey = options.SecretKey;",
            "export const SecretKey = impl.SecretKey;",
            "exports.AuthCredential = index.AuthCredential;",
            "exports.EmailAuthCredential = totp.EmailAuthCredential;",
            "AuthCredential: exp__namespace.AuthCredential,",
            "credential.refreshToken = index_1.refreshToken;",
            "Storage.HmacKey = hmacKey_js_1.HmacKey;",
            "accessKeyId: awsCreds.AccessKeyId, secretAccessKey: awsCreds.SecretAccessKey,",
        ])

    def test_a_property_of_a_named_variable_is_code(self):
        self.assertSilent([
            "idToken: userCredential.credential,",
            "idToken: mfaSession.credential,",
            "idToken: session.credential,",
            "privateKey: privateKeyResult.value",
            "streamToken = t.base64EncodedStreamToken;",
            "this.serverAppAppCheckToken = app$1.settings.appCheckToken;",
            "this.subjectToken = responseJson.saml_response;",
            "this.sessionToken=ByteString.EMPTY_BYTE_STRING}getSessionToken(e){",
            "class eE{constructor(){this.sessionToken=py.EMPTY_BYTE_STRING}getSessionToken(e){",
            "recaptchaToken: recaptchaV2Token,",
            "maxTokens: +obj.maxTokens.toFixed(3),",
        ])

    def test_re_exports_are_code(self):
        self.assertSilent([
            "exports.EmailAuthCredential = exports.AuthCredential = void 0;",
            "exports.ImpersonatedServiceAccountCredential = exports.RefreshTokenCredential"
            " = exports.ComputeEngineCredential = exports.ServiceAccountCredential = void 0;",
            "exports.IAMAuth = exports.GCPEnv = exports.Compute = void 0;",
            "exports.ChannelCredentials = exports.makeUUID = exports.fallback = void 0;",
            "exports.createCertificateProviderChannelCredentials = "
            "createCertificateProviderChannelCredentials;",
        ])

    def test_the_aws_sts_helper_is_code(self):
        content = (
            'import { STSClient, AssumeRoleCommand } from "@aws-sdk/client-sts";\n'
            "export async function assume(roleArn) {\n"
            "  const { Credentials: credentials } = await new STSClient({}).send(\n"
            '    new AssumeRoleCommand({ RoleArn: roleArn, RoleSessionName: "app" }));\n'
            "  return {\n"
            "    accessKeyId: credentials.AccessKeyId,\n"
            "    secretAccessKey: credentials.SecretAccessKey,\n"
            "    sessionToken: credentials.SessionToken,\n"
            "  };\n"
            "}\n")
        self.assertEqual(find_secrets(content), [])
        self.assertEqual(_written(content, "/a/app/src/sts.ts"), [])


class MinifiedBundles(Silent, unittest.TestCase):
    """Minified code chains assignments, and joins names with ?:, &&, ??
    and ===, none of which a generated value is written in."""

    def test_chained_assignments_are_code(self):
        self.assertSilent([
            "c.setRsaPrivateKey=c.rsa.setPrivateKey=function(e,t,r,n,i,s,o,u){var l={n:e}}",
            "a.token=b.token=c(d)",
            "node -e 'a.token=b.token=c(d);console.log(a)'",
            "X.prototype.setWithCredentials=X.prototype.Fa,te=X}).apply(void 0",
            "y.TOKEN=y.STRICT_TOKEN=y.HEX=y.URL_CHAR=y.STRICT_URL_CHAR=y.USERINFO_CHARS="
            "y.MARK=y.ALPHANUM=y.NUM=y.HEX_MAP=y.NUM_MAP=y.ALPHA=y.FINISH=void 0",
        ])

    def test_conditions_and_defaults_are_code(self):
        self.assertSilent([
            "(t.nonce=e.nonce),e.pendingToken&&(t.pendingToken=e.pendingToken)):e.oauthToken"
            "&&e.oauthTokenSecret?(t.accessToken=e.oauthToken,t.secret=e.oauthTokenSecret)"
            ':_fail("argument-error"),t}',
            "maxPromptTokens:s.maxPromptTokens??void 0,"
            "maxContextWindowTokens:s.maxContextWindowTokens??void 0,",
            "cacheReadTokens:o.cacheReadTokens,reasoningTokens:o.reasoningTokens??0}));",
            "r={useLimitedUseAppCheckTokens:n?.useLimitedUseAppCheckTokens??!1},i=1",
            "this.authToken_=h&&h.accessToken,this.appCheckToken_=null",
            "or:o}:Ci(o):(u={token:a.token},await fi(i,s.token=a)):u=Ci(o),l&&Ti(i,u),u}",
            "return{injectGitAuth:e&&t?.gitAuth===!0,injectGhAuth:e&&t?.ghAuth===!0}",
            "skipCachedAccessToken:r.skipCachedAccessToken===!0,includeExistingToken:!1",
            "responsesMaxOutputTokens:r?this.clientOptions.maxOutputTokens:void 0,",
            'currentToken:r?.currentToken??"",hasTrailingSpace:!1',
            "getToken:t.getToken??ot,signal:t.signal",
            '&&e.hasOwnProperty("streamToken")&&(r.streamToken=t.bytes===String?'
            "i.base64.encode(e.streamToken,0,e.streamToken.length):e.streamToken)",
        ])

    def test_a_key_id_shape_inside_base64_is_not_one(self):
        """A wasm blob is base64, and sixteen capitals after ASIA turn up
        in it. A key ID is written on its own; one with no digit in it
        glued inside a longer run is a piece of that run."""
        blob = ("x tBDGoQ5gEgAkUEQCAAEHAMAQsgACACEGAhFiAAKALYAS" "IAKAIAIAJBACAAKAIE"
                "EQEAGgsgC0EgaiQAIBYL y")
        self.assertEqual(find_secrets(blob), [])
        self.assertEqual(_literal(blob), [])


class StandIns(Silent, unittest.TestCase):

    def test_a_constant_that_says_not_to_use_it(self):
        self.assertSilent([
            "var ReactPropTypesSecret = 'SECRET_DO_NOT_PASS_THIS_OR_YOU_WILL_BE_FIRED';",
            "node_modules/prop-types/lib/ReactPropTypesSecret.js:10:var ReactPropTypesSecret"
            " = 'SECRET_DO_NOT_PASS_THIS_OR_YOU_WILL_BE_FIRED';",
        ])

    def test_documentation_examples_of_ones_own_secret(self):
        self.assertSilent([
            " *             clientSecret: 'my-idp-secret',",
            " *     clientSecret: 'my-mcp-secret'",
        ])


class AppConfigurationReferences(Silent, unittest.TestCase):

    def test_app_configuration_references_are_silent(self):
        """App Service resolves an App Configuration reference as it does a
        Key Vault one."""
        self.assertSilent([
            "TOKEN=@Microsoft.AppConfiguration(Endpoint=https://myconfig.azconfig.io;"
            " Key=myAppConfigKey; Label=myKeysLabel)",
            "DB_PASSWORD=@Microsoft.AppConfiguration(Endpoint=https://x.azconfig.io;Key=db)",
        ])


class LiteralsStayFound(Silent, unittest.TestCase):
    """Passwords and keys written beside the same keys are still found."""

    def test_literals_under_camel_case_keys(self):
        self.assertFound([
            ("dbPassword: Summer.Monkey", "Summer.Monkey"),
            ("clientSecret: quiet.river.bypass", "quiet.river.bypass"),
            ("secretAccessKey: wJalrXUtnFEMI.K7MDENGbPxRfiCYzq", "wJalrXUtnFEMI.K7MDENGbPxRfiCYzq"),
            ('"clientSecret": "Xk9mPq2vRt7wLz4bQ8nT"', "Xk9mPq2vRt7wLz4bQ8nT"),
            ("refreshToken: Zq7KpWxVbNmTrLs", "Zq7KpWxVbNmTrLs"),
            ("DB_PASSWORD=my-dog-rex-2019", "my-dog-rex-2019"),
            ("DB_PASSWORD=summer.monkey+rain", "summer.monkey+rain"),
            ("DB_PASSWORD=my.pass?word", "my.pass?word"),
            ("apiKey: Kq8.Zr3?Wm5:Lp2", "Kq8.Zr3?Wm5:Lp2"),
        ])

    def test_a_key_id_on_its_own_is_still_found(self):
        key = "ASIA" + "KQZVBWPRTMXNHJLD"
        for text in ("aws_session=" + key, "key " + key + " here", '"' + key + '"'):
            with self.subTest(text=text):
                self.assertEqual(find_secrets(text + PAD),
                                 [(key, "AWS temporary access key")])


class EndToEnd(unittest.TestCase):
    """clean and watch, run as a person runs them, on a session that wrote
    the AWS SDK helper and read a re-export file."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.home = os.path.join(self.tmp, "home")
        os.makedirs(self.home)
        proj = os.path.join(self.tmp, "projects", "-a-app")
        os.makedirs(proj)
        write = {"file_path": "/a/app/src/sts.ts", "content": (
            "  return {\n    accessKeyId: credentials.AccessKeyId,\n"
            "    secretAccessKey: credentials.SecretAccessKey,\n"
            "    sessionToken: credentials.SessionToken,\n  };\n")}
        read = ("'use strict';\nvar index = require('./index-abc.js');\n"
                "exports.AuthCredential = index.AuthCredential;\n"
                "exports.EmailAuthCredential = index.EmailAuthCredential;\n"
                "var ReactPropTypesSecret = 'SECRET_DO_NOT_PASS_THIS_OR_YOU_WILL_BE_FIRED';\n")
        lines = [
            {"type": "assistant", "timestamp": "2026-10-01T10:00:00Z", "message": {"content": [
                {"type": "tool_use", "id": "t1", "name": "Write", "input": write}]}},
            {"type": "user", "timestamp": "2026-10-01T10:00:01Z", "message": {"content": [
                {"type": "tool_result", "tool_use_id": "t1", "content": "ok"}]}},
            {"type": "assistant", "timestamp": "2026-10-01T10:00:02Z", "message": {"content": [
                {"type": "tool_use", "id": "t2", "name": "Bash",
                 "input": {"command": "cat node_modules/@firebase/auth/dist/node/index.js"}}]}},
            {"type": "user", "timestamp": "2026-10-01T10:00:03Z", "message": {"content": [
                {"type": "tool_result", "tool_use_id": "t2", "content": read}]}},
        ]
        with open(os.path.join(proj, "s.jsonl"), "w", encoding="utf-8") as fh:
            fh.write("".join(json.dumps(line) + "\n" for line in lines))
        self.root = os.path.join(self.tmp, "projects")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _run(self, *args):
        env = dict(os.environ, HOME=self.home, NO_COLOR="1", PYTHONPATH=ROOT)
        env.pop("CLAUDE_CONFIG_DIR", None)
        p = subprocess.run([sys.executable, "-m", "ranwhat"] + list(args)
                           + ["--root", self.root, "--days", "3650"],
                           capture_output=True, text=True, encoding="utf-8",
                           env=env, timeout=60, stdin=subprocess.DEVNULL)
        return p.stdout + p.stderr

    def test_clean_finds_nothing(self):
        out = self._run("clean", "--no-interactive")
        self.assertIn("No secrets found", out)

    def test_watch_raises_no_secret(self):
        out = self._run("watch")
        self.assertNotIn("Secret-shaped string", out)


if __name__ == "__main__":
    unittest.main(verbosity=2)
