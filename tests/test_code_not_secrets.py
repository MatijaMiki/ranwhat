"""Code, templates and references beside a secret's name, and the chosen
passwords that look like them.

Once a ) could sit in a value (Django draws its keys from an alphabet with
both parentheses) and camelCase keys named secrets, minified JavaScript
read as secrets: if(cfg.token===undefined)continue gave the value
"==undefined)continue", reported by clean and check and raised as a
critical secret.literal by watch whenever an agent wrote or read a bundle.
Each case here was seen on a working machine. Every value is synthetic.
"""
import os
import random
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ranwhat import clean, fixtures, watch
from ranwhat.clean import find_secrets

# find_secrets skips strings shorter than any credential shape.
PAD = "\n# padding so the text clears the minimum scan length"

DJANGO = "abcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*(-_=+)"


def _literal(text):
    return [h for h in watch.evaluate("Bash", {"command": text})[0]
            if h["rule"] == "secret.literal"]


def _written(text, path="/a/dist/x.js"):
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


class CompactComparisons(Silent, unittest.TestCase):
    """A comparison written with no spaces, as minified code is: the value
    after = was the rest of ==, and ran on past the ) that closes the
    condition."""

    def test_minified_comparisons_are_code(self):
        self.assertSilent([
            "if(Q.usage.totalInputTokens===0)continue;",
            "if(cfg.token===undefined)continue;",
            "while(n.accessToken==null)continue;",
            "function f(e){return e.accessToken===undefined?null:e.accessToken}",
            "for(const t of e)if(t.token===r.token)return t;",
            "function f(e){return e.accessToken===u.accessToken}",
            "if(this.accessToken===null)return",
            "if(t.token===null)n.push(1)",
            "if(e.apiKey===this.apiKey)return!0",
            "x=e.secretKey==null?a:b",
            "if(o.token==!0)break;",
            "if(a.token===b.token&&c)d();",
        ])

    def test_minified_expressions_are_code(self):
        self.assertSilent([
            "totalTokens=e.inputTokens+e.outputTokens",
            "o.password=u.password??(await prompt('pw'))",
            "o.password=u.password?u.password:(await ask(u.name)):",
            "c.token=n.token||r.token",
            "o.password=u.password?askFor(u.password):null",
        ])

    def test_a_scope_operator_is_not_a_separator(self):
        """Ruby, Rust and C++ qualify a name with ::, and the second colon
        was read as the start of a value."""
        self.assertSilent([
            "creds = Aws::Credentials::SharedCredentials.new(profile)",
            "let t = Token::Bearer.parse(raw)",
            "Password::Hasher.new(cost)",
        ])

    def test_a_value_that_starts_with_an_equals_sign_is_still_found(self):
        """A .env value can start with =, and one Django key in fifty does."""
        key = "k9vx#2m!p$7q^w@3z&8r*v5t)b_n=c+4hj6s1d0f!g%y2eu7"
        self.assertFound([
            ("DB_PASSWORD==Xk9mPq2vRt7wLz4b", "=Xk9mPq2vRt7wLz4b"),
            ("DJANGO_SECRET_KEY==" + key, "=" + key),
            ("export SECRET_KEY==" + key, "=" + key),
        ])

    def test_generated_keys_that_start_with_one(self):
        rng = random.Random(20261002)
        for _ in range(500):
            key = "=" + "".join(rng.choice(DJANGO) for _ in range(49))
            text = "DJANGO_SECRET_KEY=" + key
            with self.subTest(text=text):
                self.assertEqual([v for v, _l in find_secrets(text + PAD)], [key])

    def test_a_dotted_passphrase_is_still_found(self):
        self.assertFound([("password: summer.monkey.Rain7", "summer.monkey.Rain7"),
                          ("DB_PASSWORD=Xk9mPq2v+Rt7wLz4b", "Xk9mPq2v+Rt7wLz4b"),
                          ("DB_PASSWORD=summer.monkey+rain", "summer.monkey+rain"),
                          ("DB_PASSWORD=my.pass?word", "my.pass?word")])


class WordPasswords(Silent, unittest.TestCase):
    """A password of three or more words with example, fake, unsafe and
    the like among them was dropped as a placeholder, a connection
    string's included. Those words say a phrase is no secret only beside
    words that name one."""

    def test_chosen_words_are_a_password(self):
        self.assertFound([
            ("DB_PASSWORD=acme-example-prod", "acme-example-prod"),
            ("DB_PASSWORD=Unsafe-Harbor-Lights", "Unsafe-Harbor-Lights"),
            ("DB_PASSWORD=summer-fake-rainbow", "summer-fake-rainbow"),
        ])
        for text in ("postgres://app:" "acme-example-prod@db.internal:5432/app",
                     "mysql://root:" "Unsafe-Harbor-Lights@db/app"):
            with self.subTest(text=text):
                self.assertEqual([(v, l) for v, l in find_secrets(text + PAD)
                                  if l == "connection string password"],
                                 [(text.split(":")[2].split("@")[0],
                                   "connection string password")])

    def test_phrases_that_say_they_are_none_stay_silent(self):
        self.assertSilent([
            "SECRET_KEY=django-insecure-change-me",
            "SECRET_KEY=dev-secret-key-not-for-production",
            "SECRET_KEY=insecure-dev-key-do-not-use",
            "JWT_SECRET=fake-jwt-secret",
            "API_KEY=my-example-api-key",
            "SECRET_KEY=unsafe-dev-secret",
            "SECRET_KEY=my_super_secret_key_12345",
            "SECRET_KEY=super-secret-key-123456789",
            "SECRET_KEY=django-insecure-changeme",
            "SECRET_KEY=django-insecure-dev-only",
            "DB_PASSWORD=placeholder-river-stone",
            "OPENAI_API_KEY=sk-" "ant-FAKE-TEST-LOCAL",
            "echo sk-" "proj-dummy-demo-value",
        ])

    def test_a_long_number_after_words_is_still_a_password(self):
        self.assertFound([("DB_PASSWORD=secret-key-83920174", "secret-key-83920174")])


class Templates(Silent, unittest.TestCase):
    """A format string, or the fixed start of a value code completes, is
    no secret: SECRET_KEY = 'django-insecure-%s' % get_random_string(50)."""

    def test_templates_are_silent(self):
        self.assertSilent([
            "SECRET_KEY = 'django-insecure-%s' % get_random_string(50)",
            "SECRET_KEY = 'django-insecure-' + get_random_string(50)",
            "SECRET_KEY = 'secret-key-for-testing-%d' % i",
            "SECRET_KEY = settings.SECRET_KEY_PREFIX_%s",
            "SECRET_KEY = s.p.app_secret_%s",
            'u = "https://example.com/cb#access_token=%s&token_type=bearer" % v',
            "url = 'https://x.io/api?token=%s&channel=general' % t",
            "token=%s&channel=general",
            'line = {"password": "DB_PASSWORD=" + pw}',
            'cmd = "export API_TOKEN=" + token',
            "a_token = 'api_key:' + key",
            'DATABASE_URL = "postgresql://app:" + pw + "@db/app"',
            'DATABASE_URL = "postgres://" + user',
            "the token comes back as #access_token=...&token_type=bearer.",
            "grep -n token ranwhat/clean.py:",
            "tokens: tests/test_clean_shapes.py:123:",
        ])

    def test_a_fragment_token_ends_at_the_next_parameter(self):
        token = "Zx8Qm4Lp9Vb2Rt7Kc3Wn"
        self.assertFound([
            ("https://example.com/cb#access_token=%s&token_type=bearer&expires_in=3600"
             % token, token),
        ])

    def test_a_secret_with_a_percent_in_it_is_still_found(self):
        self.assertFound([
            ("DB_PASSWORD=Xk9m%sPq2vRt7wLz4b", "Xk9m%sPq2vRt7wLz4b"),
            ("API_KEY=%2Fq7Zk2WpX9vRt4mN8bL1y", "%2Fq7Zk2WpX9vRt4mN8bL1y"),
            ("SECRET_KEY=Xk9mPq2vRt7wLz4b%s", "Xk9mPq2vRt7wLz4b%s"),
        ])


class CallsWithOperators(Silent, unittest.TestCase):
    """A call was code only while its arguments held names, digits and
    more calls. An operator, a quote or a % in them made the whole call a
    literal: compact and minified code that hashes or encodes into a
    variable named for a secret was listed to rotate by clean, and raised
    as a critical secret.literal by watch. main read every ( as code."""

    def test_calls_with_operators_are_code(self):
        self.assertSilent([
            "token=hashlib.sha256(data+salt).hexdigest()",
            "a.password=hash(e.password+t.salt)",
            "t.accessToken=o(e.code+t);return t",
            "password=bcrypt.hash(pw+salt)",
            "const token=createHmac(secret+body)",
            "token=sha256(e+t)",
            "var token=sha256(e+t)",
            "password=hash(pw+salt)",
            'token=Buffer.from(a+b).toString("base64")',
            'n.token=Buffer.from(a+b).toString("base64")',
            'api_key=load_key(path+".pem")',
            "secret=sha1(id*2)",
            "password=encodeURIComponent(password+salt)",
            "token=md5(user+time)",
            "token=fmt(a%b)",
            "secret=sprintf('%s-%s',a,b)",
            'password=hash(pw+"pepper")',
            "token=jwt.sign(e,t,'HS256')",
            "secret=derive(a, b)",
            "token=b64(key-1)",
            "apiKey=(e+t).slice(0)",
            "password=(pw+salt).trim()",
            "token=(a.b+c)",
            "function n(e,t){t.accessToken=o(e.code+t);return t}",
            "function n(e,t){t.accessToken=o(e.code+t);return t}\n"
            "a.password=hash(e.password+t.salt);",
            "export function sign(e,t){const token=sha256(e+t);return token}",
            'python3 -c "import hashlib; token=hashlib.sha256(data+salt).hexdigest()"',
        ])

    def test_a_password_with_a_parenthesis_is_still_found(self):
        """A value whose ( comes after a word reads as a call only when all
        of it is code: names and numbers joined by operators, ended where
        code is cut (at ), at ( or after an operator)."""
        self.assertFound([
            ("DB_PASSWORD=Xk9m(Pq2v+Rt7wLz4b", "Xk9m(Pq2v+Rt7wLz4b"),
            ("API_KEY=Ab3(x9+Qz)Lm7Kp2Vn8", "Ab3(x9+Qz)Lm7Kp2Vn8"),
            ("SECRET_KEY=k9vx(2m+p7q^w@3z&8r*v5t)", "k9vx(2m+p7q^w@3z&8r*v5t)"),
            ("DB_PASSWORD=Summer(2024)+Rain!x", "Summer(2024)+Rain!x"),
        ])

    def test_generated_keys_do_not_read_as_one(self):
        """Django draws 50 characters from an alphabet with both
        parentheses and four operators in it; a password generator draws
        from much the same. Those the plain call shape reads as code (one
        in eighty drawn with symbols) are left to it, as main read every
        value with a parenthesis as code; this shape takes none of them."""
        rng = random.Random(20261003)
        symbols = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+"
        for alphabet, length in ((DJANGO, 50), (symbols, 24), (symbols, 32)):
            for _ in range(6000):
                key = "".join(rng.choice(alphabet) for _ in range(length))
                if "(" not in key or clean._CALL.match(key):
                    continue
                with self.subTest(key=key):
                    self.assertFalse(clean._is_call_expression(key))
                    if "***" not in key and not key.startswith("="):
                        self.assertEqual(
                            [v for v, _l in find_secrets("SECRET_KEY='%s'" % key + PAD)],
                            [key])


class References(Silent, unittest.TestCase):
    """Where a secret is kept is not the secret: a Vault path, an ARN, a
    1Password reference, an Azure Key Vault reference."""

    def test_references_are_silent(self):
        self.assertSilent([
            "SECRET_KEY=vault:secret/data/app#apikey",
            "DB_PASSWORD=vault:secret/data/db#password9X2",
            "OPENAI_API_KEY=op://Private/OpenAI/credential",
            '{"secret": "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/db-AbCdEf"}',
            "DB_PASSWORD=ssm:/prod/db/password",
        ])

    def test_azure_key_vault_references_are_silent(self):
        """App Service and Functions settings name a Key Vault secret this
        way, and resolve it when the app starts."""
        self.assertSilent([
            "API_KEY=@Microsoft.KeyVault(SecretUri=https://kv.vault.azure.net/secrets/api-key/)",
            "API_KEY=@Microsoft.KeyVault(VaultName=myvault;SecretName=mysecret)",
            "DB_PASSWORD=@Microsoft.KeyVault(SecretUri=https://kv.vault.azure.net/secrets/db/"
            "ec96f02080254f109c51a1f14cdb1931)",
            "DB_PASSWORD=@Microsoft.KeyVault(VaultName=myvault;SecretName=db;"
            "SecretVersion=ec96f02080254f109c51a1f14cdb1931)",
            '{"Values": {"API_KEY": "@Microsoft.KeyVault(SecretUri='
            'https://myvault.vault.azure.net/secrets/api-key/)"}}',
            "az webapp config appsettings set -g rg -n app --settings "
            "DB_PASSWORD=@Microsoft.KeyVault(SecretUri=https://kv.vault.azure.net/secrets/db/)",
            "token: '@microsoft.keyvault(secreturi=https://kv.vault.azure.net/secrets/t/)'",
        ])


class NamesThatAreNotSecrets(Silent, unittest.TestCase):

    def test_cursors_and_fixtures(self):
        self.assertSilent([
            '{"cancelToken": "source.token"}',
            '{"deltaToken": "dIrQm4Lp9Vb2Rt7Kc3WnQm4Lp9Vb2R"}',
            "AWS_ACCESS_KEY_ID=AKIA" + "AKIAAKIAAKIAAKIA",
            "aws_access_key_id = AKIA" + "ABCDABCDABCDABCD",
            "aws_secret_access_key = wJalrXUtnFEMI",
            "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG",
            "token=$NPM_TOKEN2",
        ])

    def test_a_periodic_key_id_after_a_real_account_part_is_still_found(self):
        akid = "AKIA" + "ABABABAB" + "Q7ZK2WPX"
        self.assertEqual(fixtures.fixture_reason(akid), None)
        self.assertFound([("AWS_ACCESS_KEY_ID=" + akid, akid)])


if __name__ == "__main__":
    unittest.main(verbosity=2)
