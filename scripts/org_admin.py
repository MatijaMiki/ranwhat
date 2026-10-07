"""Give an organisation Team or a comped Plus, or take it back, or link a
Stripe subscription to it.

    python3 scripts/org_admin.py grant team ORG_ID "contract: Acme" [--days N]
    python3 scripts/org_admin.py grant comp ORG_ID "press: Ana" [--days N]
    python3 scripts/org_admin.py revoke team ORG_ID
    python3 scripts/org_admin.py revoke comp ORG_ID
    python3 scripts/org_admin.py link SUB_ID ORG_ID

ORG_ID is the organisation's id from the orgs table. Team is never sold
through checkout: it is a grant, written here once a contract is agreed.
A comp is Plus given by hand: press, a partner, the holder of a hand-made
feed token who now has an account. Without --days a grant has no end date.

link ties a Stripe subscription (SUB_ID, sub_..., from the subscriptions
table or Stripe) to an organisation, which then has Plus while the
subscription is live. It is the only way a subscription bought on the
pricing page without an account becomes an organisation's: the account
page has no way to do it, and once accounts are on and ready,
/api/checkout sends every buyer to the account's upgrade instead, so these
are the ones bought before. Link one when whoever paid asks, by email from
the address Stripe has for it. A
subscription is linked once and never moved, so linking one that already
has an organisation changes nothing. It lists the subscription's emailed
tokens that are not revoked among the organisation's machines (kind
legacy), where they can be revoked, and logs the link in the
organisation's audit log, once. A token the welcome page or the email has
not made yet is listed by running link again once it has. The
organisation's own Stripe customer is left as it is, so whoever paid keeps
Stripe's billing-page login to their own subscription and gets none to the
organisation's. Nothing is sent: tell the subscriber yourself, by email to
the address Stripe has for them, that their subscription is now attached.

This writes nothing and sends nothing: it prints the SQL, to paste into the
database's console in the Cloudflare dashboard or to run with the printed
wrangler command, as scripts/feed_token.py does. The Worker works out each
organisation's plan from its grants on every request (plan() in
worker/src/auth.js) and never stores it, so a grant or a revocation counts
from the next request. A revocation ends the grant now and keeps its row,
so what an organisation was given, and when, stays on record.
"""
import re
import sys
import time

DATABASE = "ranwhat-list"
DAY = 24 * 3600

# What the command line says, and the plan the grants table holds for it.
PLANS = {"team": "team", "comp": "plus"}

# crypto.randomUUID(), which is how accounts.js names an organisation.
ORG_ID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")

# A Stripe subscription id, as worker/src/stripe.js accepts one.
SUB_ID = re.compile(r"sub_[A-Za-z0-9]{6,250}")


def command(sql):
    return ('cd worker && npx wrangler d1 execute %s --remote --command "%s"'
            % (DATABASE, sql))


def switch_on(sql):
    print("Run it on the feed's database, either way:\n")
    print("  a) Cloudflare dashboard > Storage & databases > D1 > %s > Console," % DATABASE)
    print("     paste:\n")
    print("     %s\n" % sql)
    print("  b) or, with wrangler logged in, from the repository root:\n")
    print("     %s\n" % command(sql))


def org_id(text):
    org = text.strip().lower()
    if not ORG_ID.fullmatch(org):
        sys.exit("That does not look like an organisation id (from the orgs table).")
    return org


def sub_id(text):
    sub = text.strip()
    if not SUB_ID.fullmatch(sub):
        sys.exit("That does not look like a Stripe subscription id (sub_...).")
    return sub


def grant_sql(kind, org, note, days=None, now=None):
    """One grant, written only if the organisation exists, so a mistyped id
    changes nothing."""
    t = int(time.time()) if now is None else now
    until = "NULL" if days is None else "%d" % (t + days * DAY)
    return ("INSERT INTO grants (org_id, plan, starts_at, until, note, created_at) "
            "SELECT '%s', '%s', %d, %s, '%s', %d WHERE EXISTS (SELECT 1 FROM orgs WHERE id = '%s')"
            % (org, PLANS[kind], t, until, note, t, org))


def revoke_sql(kind, org, now=None):
    """Ends every grant of that plan still in force for the organisation."""
    t = int(time.time()) if now is None else now
    return ("UPDATE grants SET until = %d WHERE org_id = '%s' AND plan = '%s' "
            "AND (until IS NULL OR until > %d)" % (t, org, PLANS[kind], t))


# A machine's id, shaped as crypto.randomUUID() makes them, which is what
# worker/src/machines.js accepts in a form.
MACHINE_ID = ("lower(substr(h, 1, 8) || '-' || substr(h, 9, 4) || '-' || substr(h, 13, 4) || '-' "
              "|| substr(h, 17, 4) || '-' || substr(h, 21, 12))")


def link_sql(sub, org, now=None):
    """One link, written only if both the subscription and the organisation
    exist, and never over a link the subscription already has. Then, only
    while the subscription is linked to this organisation, its unrevoked
    tokens as legacy machines (each once: machines.hash is unique), and,
    for a link this script made, one entry in the audit log."""
    t = int(time.time()) if now is None else now
    here = "EXISTS (SELECT 1 FROM org_subscriptions WHERE subscription = '%s' AND org_id = '%s')" % (sub, org)
    by_script = ("EXISTS (SELECT 1 FROM org_subscriptions WHERE subscription = '%s' AND org_id = '%s' "
                 "AND how = 'script')" % (sub, org))
    return "; ".join([
        "INSERT INTO org_subscriptions (subscription, org_id, how, linked_at) "
        "SELECT '%s', '%s', 'script', %d WHERE EXISTS (SELECT 1 FROM orgs WHERE id = '%s') "
        "AND EXISTS (SELECT 1 FROM subscriptions WHERE id = '%s') "
        "ON CONFLICT(subscription) DO NOTHING" % (sub, org, t, org, sub),
        "INSERT OR IGNORE INTO machines (id, hash, org_id, user_id, kind, label, created_at) "
        "SELECT %s, hash, '%s', NULL, 'legacy', '', %d FROM (SELECT hex(randomblob(16)) AS h, l.hash AS hash "
        "FROM token_subscriptions l JOIN tokens k ON k.hash = l.hash "
        "WHERE l.subscription = '%s' AND k.revoked_at IS NULL) WHERE %s" % (MACHINE_ID, org, t, sub, here),
        "INSERT INTO auth_events (org_id, user_id, event, subject, at) "
        "SELECT '%s', NULL, 'plus_linked_script', '%s', %d WHERE %s AND NOT EXISTS (SELECT 1 FROM auth_events "
        "WHERE org_id = '%s' AND event = 'plus_linked_script' AND subject = '%s')"
        % (org, sub, t, by_script, org, sub),
    ])


def usage():
    sys.exit(__doc__.strip().split("\n\n")[0])


def main(argv):
    args = argv[1:]
    days = None
    if "--days" in args:
        at = args.index("--days")
        try:
            days = int(args[at + 1])
        except (IndexError, ValueError):
            sys.exit("--days takes a whole number of days.")
        if not 1 <= days <= 3660:
            sys.exit("--days is 1 to 3660.")
        del args[at:at + 2]
    if len(args) == 4 and args[0] == "grant" and args[1] in PLANS:
        org = org_id(args[2])
        # The note lands inside SQL and a shell's double quotes: kept to
        # characters that mean nothing to either.
        note = re.sub(r"[^A-Za-z0-9 .,:@_-]", "", args[3]).strip()[:120]
        if not note:
            sys.exit("Give the grant a note, e.g. the contract or who it is for.")
        what = "Team" if args[1] == "team" else "Plus (comp)"
        print("Gives organisation %s %s, %s.\n"
              % (org, what, "for %d days" % days if days else "with no end date"))
        switch_on(grant_sql(args[1], org, note, days))
        return 0
    if len(args) == 3 and args[0] == "link" and days is None:
        sub, org = sub_id(args[1]), org_id(args[2])
        print("Links subscription %s to organisation %s, unless it is linked to one already, and lists its"
              " emailed tokens among the organisation's machines.\n" % (sub, org))
        switch_on(link_sql(sub, org))
        print("This sends nothing: email the subscriber, at the address Stripe has for them, that the"
              " subscription is now attached to the organisation.")
        return 0
    if len(args) == 3 and args[0] == "revoke" and args[1] in PLANS and days is None:
        org = org_id(args[2])
        print("Ends organisation %s's %s grants now.\n" % (org, "Team" if args[1] == "team" else "comped Plus"))
        switch_on(revoke_sql(args[1], org))
        return 0
    usage()


if __name__ == "__main__":
    sys.exit(main(sys.argv))
