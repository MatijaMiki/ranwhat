"""Make or revoke a feed token, the key `ranwhat update` sends.

    python3 scripts/feed_token.py new "early access: Ana"
    python3 scripts/feed_token.py revoke rw_...

The feed server keeps only a SHA-256 of each token, so the token itself is
printed here once and stored nowhere: give it to the subscriber, then run the
command printed under it, which adds its hash to the Worker's D1 database.
Nothing is sent anywhere by this script.

Until checkout exists this is how a token is issued. Stripe's webhook will
do the same insert.
"""
import hashlib
import re
import secrets
import sys
import time

DATABASE = "ranwhat-list"
TABLE = ("CREATE TABLE IF NOT EXISTS tokens (hash TEXT PRIMARY KEY, note TEXT NOT NULL, "
         "created_at INTEGER NOT NULL, expires_at INTEGER, revoked_at INTEGER)")


def token_hash(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def new_token():
    return "rw_" + secrets.token_urlsafe(32)


def command(sql):
    return ('cd worker && npx wrangler d1 execute %s --remote --command "%s"'
            % (DATABASE, sql))


def main(argv):
    if len(argv) == 3 and argv[1] == "new":
        # The note lands inside SQL and a shell's double quotes: kept to
        # characters that mean nothing to either.
        note = re.sub(r"[^A-Za-z0-9 .,:@_-]", "", argv[2]).strip()[:120]
        if not note:
            sys.exit("Give the token a note, e.g. who it is for.")
        token = new_token()
        sql = "%s; INSERT INTO tokens (hash, note, created_at) VALUES ('%s', '%s', %d)" % (
            TABLE, token_hash(token), note, int(time.time()))
        print("Token (give it to the subscriber; it is not stored anywhere):\n")
        print("  %s\n" % token)
        print("Then switch it on, from the repository root:\n")
        print("  %s\n" % command(sql))
        print("They use it with:  RANWHAT_TOKEN=... uvx ranwhat update --save-token")
        return 0
    if len(argv) == 3 and argv[1] == "revoke":
        token = argv[2].strip()
        if not re.fullmatch(r"rw_[A-Za-z0-9_-]{20,}", token):
            sys.exit("That does not look like a feed token (rw_...).")
        sql = "UPDATE tokens SET revoked_at = %d WHERE hash = '%s'" % (
            int(time.time()), token_hash(token))
        print("Run, from the repository root:\n")
        print("  %s" % command(sql))
        return 0
    sys.exit(__doc__.strip().split("\n\n")[0])


if __name__ == "__main__":
    sys.exit(main(sys.argv))
