"""
Scope catalog: what each granted permission actually lets an agent do.

This is the core of the scan. Introspection tells you an agent holds
"https://www.googleapis.com/auth/gmail.send". It does not tell you that this
is an irreversible, externally-visible write that no underwriter will price
without a human-approval gate. That mapping lives here.

Fields per scope:
  label        human-readable capability
  authority    read | write | financial | destructive
  reversible   can the action be undone after the fact
  blast        which blast-radius dimension it opens
  why          the sentence that goes in the report
"""

from __future__ import annotations

READ, WRITE, FINANCIAL, DESTRUCTIVE = "read", "write", "financial", "destructive"

AUTHORITY_RANK = {READ: 0, WRITE: 1, FINANCIAL: 2, DESTRUCTIVE: 3}

# blast-radius dimensions
MONETARY = "monetary"
EXTERNAL_COMMS = "external_comms"
DATA_EGRESS = "data_egress"
INFRASTRUCTURE = "infrastructure"
IDENTITY = "identity"


def _s(label, authority, reversible, blast, why):
    return {
        "label": label,
        "authority": authority,
        "reversible": reversible,
        "blast": blast,
        "why": why,
    }


CATALOG = {
    "google": {
        "https://www.googleapis.com/auth/gmail.readonly": _s(
            "Read all mail", READ, True, DATA_EGRESS,
            "Full mailbox read. Every message the agent can see is exfiltratable "
            "by a prompt injection delivered in any one of them."),
        "https://www.googleapis.com/auth/gmail.send": _s(
            "Send mail as the user", WRITE, False, EXTERNAL_COMMS,
            "Can email any external party as the user. Sent mail cannot be recalled."),
        "https://www.googleapis.com/auth/gmail.modify": _s(
            "Read, send, modify and label mail", WRITE, False, EXTERNAL_COMMS,
            "Superset of read+send. Can also hide its own activity by "
            "relabelling or archiving the evidence."),
        "https://mail.google.com/": _s(
            "Full mailbox control including permanent delete", DESTRUCTIVE, False, DATA_EGRESS,
            "Total mailbox authority including irreversible deletion. This is the "
            "broadest Gmail scope that exists."),
        "https://www.googleapis.com/auth/calendar": _s(
            "Read/write calendar", WRITE, True, EXTERNAL_COMMS,
            "Can create events that email external attendees."),
        "https://www.googleapis.com/auth/calendar.readonly": _s(
            "Read calendar", READ, True, DATA_EGRESS,
            "Reveals meeting topics, attendees and internal org structure."),
        "https://www.googleapis.com/auth/drive": _s(
            "Full Drive access", DESTRUCTIVE, False, DATA_EGRESS,
            "Read, write, share and permanently delete any file. Sharing is an "
            "egress path that leaves no trace in most DLP tooling."),
        "https://www.googleapis.com/auth/drive.file": _s(
            "Drive access limited to files the app created", WRITE, True, DATA_EGRESS,
            "Correctly scoped. This is what most Drive integrations should use."),
        "https://www.googleapis.com/auth/drive.readonly": _s(
            "Read all Drive files", READ, True, DATA_EGRESS,
            "Full document corpus is readable, and therefore summarisable into "
            "any outbound channel the agent also holds."),
        "https://www.googleapis.com/auth/contacts": _s(
            "Read/write contacts", WRITE, True, DATA_EGRESS,
            "Contact list is the target list for any outbound abuse."),
        "https://www.googleapis.com/auth/cloud-platform": _s(
            "Full Google Cloud control", DESTRUCTIVE, False, INFRASTRUCTURE,
            "Complete control of the GCP project including billing, IAM and "
            "resource deletion."),
    },
    "github": {
        "repo": _s(
            "Full control of private repositories", WRITE, False, DATA_EGRESS,
            "Read and write all private source. Includes force-push, which can "
            "rewrite history and destroy the audit trail."),
        "public_repo": _s(
            "Write access to public repositories", WRITE, False, DATA_EGRESS,
            "Can publish to public repos. A misdirected commit is a permanent "
            "public disclosure."),
        "delete_repo": _s(
            "Delete repositories", DESTRUCTIVE, False, INFRASTRUCTURE,
            "Irreversible destruction of a repository. Almost never needed by an agent."),
        "admin:org": _s(
            "Full organisation administration", DESTRUCTIVE, False, IDENTITY,
            "Can add and remove org members, i.e. can grant persistence to an attacker."),
        "workflow": _s(
            "Update GitHub Actions workflows", DESTRUCTIVE, False, INFRASTRUCTURE,
            "Can modify CI. A workflow edit is arbitrary code execution with your "
            "CI secrets attached."),
        "write:packages": _s(
            "Publish packages", WRITE, False, INFRASTRUCTURE,
            "Can publish artifacts consumed downstream. Supply-chain reach."),
        "read:org": _s(
            "Read org membership", READ, True, IDENTITY,
            "Low risk on its own."),
        "gist": _s(
            "Create gists", WRITE, False, DATA_EGRESS,
            "A public gist is a one-call exfiltration primitive."),
    },
    "slack": {
        "chat:write": _s(
            "Post messages", WRITE, False, EXTERNAL_COMMS,
            "Can post as the app into any channel it is in. Messages are seen "
            "before they can be deleted."),
        "channels:history": _s(
            "Read public channel history", READ, True, DATA_EGRESS,
            "Full public conversation history is readable."),
        "groups:history": _s(
            "Read private channel history", READ, True, DATA_EGRESS,
            "Private channel content. Usually the most sensitive text in a company."),
        "im:history": _s(
            "Read direct messages", READ, True, DATA_EGRESS,
            "DM content. Rarely justifiable for an agent."),
        "files:read": _s(
            "Read files", READ, True, DATA_EGRESS,
            "All shared files including exports and credentials pasted as snippets."),
        "users:read.email": _s(
            "Read user email addresses", READ, True, IDENTITY,
            "Directory of addressable humans."),
        "admin": _s(
            "Workspace administration", DESTRUCTIVE, False, IDENTITY,
            "Full workspace control."),
    },
    "stripe": {
        "charges:write": _s(
            "Create and capture charges", FINANCIAL, False, MONETARY,
            "Can move customer money. Settled charges are reversible only via "
            "refund, which is a separate, slower, partially-fee-bearing action."),
        "refunds:write": _s(
            "Issue refunds", FINANCIAL, False, MONETARY,
            "Can pay money out. This is the single most commonly abused agent "
            "capability in reported incidents."),
        "transfers:write": _s(
            "Move money to connected accounts", FINANCIAL, False, MONETARY,
            "Outbound transfer authority. Effectively irreversible once settled."),
        "payment_intents:write": _s(
            "Create payment intents", FINANCIAL, True, MONETARY,
            "Initiates payment flows."),
        "customers:read": _s(
            "Read customer records", READ, True, DATA_EGRESS,
            "PII and payment metadata for the full customer base."),
        "customers:write": _s(
            "Modify customer records", WRITE, True, IDENTITY,
            "Can change the email on a customer record, which is an account-takeover "
            "primitive in most billing flows."),
        "all": _s(
            "Unrestricted secret key", DESTRUCTIVE, False, MONETARY,
            "A live secret key with no restrictions. Every Stripe capability, "
            "including payouts, is available to whatever holds this."),
    },
    "aws": {
        "*": _s(
            "Full AWS administrator", DESTRUCTIVE, False, INFRASTRUCTURE,
            "Unrestricted control of the account including IAM, billing and deletion."),
        "s3:*": _s(
            "Full S3 control", DESTRUCTIVE, False, DATA_EGRESS,
            "Read, write, make-public and delete every bucket. Covers both the "
            "egress path and the destruction of the logs that would record it."),
        "s3:GetObject": _s(
            "Read objects", READ, True, DATA_EGRESS,
            "Object read."),
        "s3:PutObject": _s(
            "Write objects", WRITE, True, DATA_EGRESS,
            "Object write."),
        "s3:DeleteObject": _s(
            "Delete objects", DESTRUCTIVE, False, DATA_EGRESS,
            "Irreversible unless versioning is on."),
        "iam:*": _s(
            "Full IAM control", DESTRUCTIVE, False, IDENTITY,
            "Can grant itself any other permission. This makes every other scope "
            "limit on this credential decorative."),
        "ses:SendEmail": _s(
            "Send email", WRITE, False, EXTERNAL_COMMS,
            "Outbound email from your verified domain."),
        "lambda:InvokeFunction": _s(
            "Invoke functions", WRITE, True, INFRASTRUCTURE,
            "Arbitrary invocation of deployed code."),
    },
    # Scope strings verified against developer.atlassian.com, September 2026.
    "atlassian": {
        "read:jira-user": _s(
            "Read user profiles and groups", READ, True, IDENTITY,
            "Enumerates the org chart: who exists, which teams they are in, "
            "who reports where. Useful reconnaissance for a social attack."),
        "read:jira-work": _s(
            "Read all issues, comments and attachments", READ, True, DATA_EGRESS,
            "Issue trackers hold incident write-ups, customer names and "
            "credentials pasted into comments by people in a hurry."),
        "write:jira-work": _s(
            "Create and edit issues, comments and worklogs", WRITE, True, DATA_EGRESS,
            "Comments notify watchers by email, so a write here reaches people "
            "outside the tool."),
        "delete:issue:jira": _s(
            "Delete issues", DESTRUCTIVE, False, DATA_EGRESS,
            "Deletes the ticket and its history. If the agent's own work was "
            "tracked there, this removes the record of what it was asked to do."),
        "delete:comment:jira": _s(
            "Delete comments", DESTRUCTIVE, False, DATA_EGRESS,
            "Comment deletion is how an actor removes the discussion that "
            "would explain a change, while leaving the change in place."),
        "delete:project:jira": _s(
            "Delete entire projects", DESTRUCTIVE, False, DATA_EGRESS,
            "Removes every issue, attachment and worklog in a project at once. "
            "Recovery depends on a backup nobody has tested."),
        "manage:jira-project": _s(
            "Administer projects, roles and permissions", DESTRUCTIVE, False, IDENTITY,
            "Can grant itself or others access to projects it could not "
            "previously read. Permission changes are rarely alerted on."),
        "manage:jira-configuration": _s(
            "Administer site-wide Jira configuration", DESTRUCTIVE, False, INFRASTRUCTURE,
            "Site-wide authority including workflows and schemes. The broadest "
            "Jira scope short of full site admin."),
        "delete:webhook:jira": _s(
            "Delete webhooks", DESTRUCTIVE, False, INFRASTRUCTURE,
            "Webhooks are often what feeds an external audit trail. Deleting "
            "one silences the downstream record without touching Jira itself."),
    },

    # Verified against learn.microsoft.com/graph/permissions-reference, Sept 2026.
    "microsoft": {
        "Mail.Read": _s(
            "Read the user's mail", READ, True, DATA_EGRESS,
            "Full mailbox read. Every message is a possible prompt-injection "
            "carrier and every attachment is exfiltratable."),
        "Mail.Send": _s(
            "Send mail as the user", WRITE, False, EXTERNAL_COMMS,
            "Sends as a real person to any external party. Sent mail cannot "
            "be recalled once it leaves the tenant."),
        "Mail.ReadWrite": _s(
            "Read, write and delete the user's mail", DESTRUCTIVE, False, DATA_EGRESS,
            "Superset of read and send that can also delete. An agent can "
            "remove the message that shows what it was told to do."),
        "Calendars.ReadWrite": _s(
            "Full access to the user's calendars", WRITE, True, EXTERNAL_COMMS,
            "Creating an event emails every attendee, including external ones, "
            "so a calendar write is an outbound message."),
        "Files.ReadWrite.All": _s(
            "Read and write all files the user can access", DESTRUCTIVE, False, DATA_EGRESS,
            "Covers OneDrive and every SharePoint site the user can reach. "
            "Includes sharing, which is an egress path most DLP misses."),
        "Sites.FullControl.All": _s(
            "Full control of all SharePoint sites", DESTRUCTIVE, False, DATA_EGRESS,
            "Total authority over every site collection in the tenant, "
            "including permissions and retention settings."),
        "Directory.ReadWrite.All": _s(
            "Read and write directory data", DESTRUCTIVE, False, IDENTITY,
            "Entra ID write. Can create accounts, change group membership and "
            "alter who has access to everything else in the tenant."),
        "User.Read": _s(
            "Sign in and read the user's profile", READ, True, IDENTITY,
            "The baseline sign-in scope. Low authority on its own."),
    },

    # Verified against docs.sentry.io/api/permissions, September 2026.
    "sentry": {
        "org:read": _s(
            "Read organisation settings and membership", READ, True, IDENTITY,
            "Reveals projects, teams and who belongs to them."),
        "org:admin": _s(
            "Administer and delete the organisation", DESTRUCTIVE, False, INFRASTRUCTURE,
            "The broadest Sentry authority. Includes deleting the organisation "
            "and every project and event inside it."),
        "project:read": _s(
            "Read project settings", READ, True, DATA_EGRESS,
            "Includes DSNs and configuration that describe your deployment."),
        "project:write": _s(
            "Modify project settings", WRITE, True, INFRASTRUCTURE,
            "Can change alert rules and data-scrubbing settings, so it can turn "
            "off the filtering that keeps secrets out of captured events."),
        "project:admin": _s(
            "Delete projects", DESTRUCTIVE, False, INFRASTRUCTURE,
            "Deletes a project and all its history. This is deletion of the "
            "observability record itself."),
        "event:read": _s(
            "Read captured events", READ, True, DATA_EGRESS,
            "Error events routinely contain request bodies, headers and tokens "
            "that were live at the moment of the exception."),
        "event:admin": _s(
            "Delete issues and their events", DESTRUCTIVE, False, DATA_EGRESS,
            "Events are immutable, so this deletes whole issues. An agent that "
            "caused errors can erase the trace of having caused them."),
        "member:admin": _s(
            "Add, change and remove members", DESTRUCTIVE, False, IDENTITY,
            "Can grant access to whoever it likes, including itself."),
    },

    # Verified against shopify.dev/docs/api/usage/access-scopes, September 2026.
    "shopify": {
        "read_orders": _s(
            "Read orders", READ, True, DATA_EGRESS,
            "Orders carry names, addresses, contact details and what people "
            "bought. A customer-data breach in one call."),
        "write_orders": _s(
            "Create and modify orders", FINANCIAL, False, MONETARY,
            "Editing an order moves money and changes what gets shipped. "
            "Refunds and cancellations are not reversible by re-editing."),
        "read_all_orders": _s(
            "Read orders beyond the 60-day window", READ, True, DATA_EGRESS,
            "Shopify gates this behind approval because it exposes the full "
            "historical customer record rather than recent activity."),
        "write_draft_orders": _s(
            "Create and modify draft orders", FINANCIAL, True, MONETARY,
            "Draft orders can be turned into invoices emailed to customers, so "
            "this both creates a financial document and sends it outward."),
        "read_customers": _s(
            "Read customer records", READ, True, DATA_EGRESS,
            "The customer list is usually the most valuable personal data a "
            "shop holds, and the most regulated."),
        "write_customers": _s(
            "Create and modify customer records", WRITE, False, IDENTITY,
            "Can alter the email address an order confirmation is sent to, "
            "which redirects both goods and correspondence."),
        "read_customer_payment_methods": _s(
            "Read stored customer payment methods", FINANCIAL, True, MONETARY,
            "Approval-gated by Shopify. Reveals which payment instruments a "
            "customer has on file."),
        "write_products": _s(
            "Create and modify products", WRITE, True, MONETARY,
            "Includes price. A wrong price is a real loss for as long as it is "
            "live, and the orders taken at it are already binding."),
    },

    # Verified against developers.hubspot.com, September 2026.
    "hubspot": {
        "crm.objects.contacts.read": _s(
            "Read contact records", READ, True, DATA_EGRESS,
            "The contact database is the company's relationship list: names, "
            "emails, phone numbers and every logged interaction."),
        "crm.objects.contacts.write": _s(
            "Create and modify contacts", WRITE, False, IDENTITY,
            "Can change the email address on a contact, which redirects every "
            "subsequent automated message to an address of its choosing."),
        "crm.objects.companies.read": _s(
            "Read company records", READ, True, DATA_EGRESS,
            "Reveals the customer list, which for most B2B companies is the "
            "single most commercially sensitive dataset they hold."),
        "crm.objects.companies.write": _s(
            "Create and modify companies", WRITE, True, DATA_EGRESS,
            "Ownership and lifecycle changes reroute who is alerted about an "
            "account and which automations fire."),
        "crm.objects.deals.read": _s(
            "Read deals", READ, True, DATA_EGRESS,
            "Deal records carry contract values and close dates: the pipeline "
            "numbers a competitor would most like to have."),
        "crm.objects.deals.write": _s(
            "Create and modify deals", FINANCIAL, True, MONETARY,
            "Deal amounts and stages drive forecasting and commission. Editing "
            "them changes what the business believes about its own revenue."),
        "crm.objects.quotes.read": _s(
            "Read quotes", READ, True, MONETARY,
            "Quotes are priced offers, including any discount given."),
        "crm.objects.quotes.write": _s(
            "Create and modify quotes", FINANCIAL, False, MONETARY,
            "A quote is a priced offer sent to a customer. Once delivered it "
            "has been seen, whatever is edited afterwards."),
        "crm.objects.line_items.write": _s(
            "Create and modify line items", FINANCIAL, True, MONETARY,
            "Line items are what a deal is actually charging for, so this is "
            "price authority one level below the deal total."),
        "settings.users.write": _s(
            "Create and modify portal users", DESTRUCTIVE, False, IDENTITY,
            "Can add users and change permissions, including granting access "
            "broader than the integration itself holds."),
        "settings.billing.write": _s(
            "Change billing settings", FINANCIAL, False, MONETARY,
            "Alters the subscription the company is charged for."),
        "files": _s(
            "Read and write files", WRITE, False, DATA_EGRESS,
            "HubSpot-hosted files are served from public URLs by default, so "
            "an upload here is a publishing action."),
    },

    # Verified against docs.discord.com/developers/topics/oauth2, September 2026.
    "discord": {
        "identify": _s(
            "Read the user's account", READ, True, IDENTITY,
            "Baseline identity: user id, username and avatar, without email."),
        "email": _s(
            "Read the user's email address", READ, True, IDENTITY,
            "Turns a pseudonymous Discord identity into a contactable person."),
        "guilds": _s(
            "List the servers the user belongs to", READ, True, DATA_EGRESS,
            "Server membership maps someone's employer, communities and "
            "interests. Useful for targeting, harmless-looking on a consent screen."),
        "guilds.join": _s(
            "Add the user to servers", WRITE, True, EXTERNAL_COMMS,
            "Places a real account into a server without a further prompt. "
            "Whatever that server can see, it can now see about them."),
        "bot": _s(
            "Install a bot into a server", WRITE, False, EXTERNAL_COMMS,
            "The bot then acts under its own permission set, which is granted "
            "separately and is frequently far broader than this scope suggests."),
        "webhook.incoming": _s(
            "Create a webhook that posts into a channel", WRITE, False, EXTERNAL_COMMS,
            "A standing, unauthenticated URL that posts messages to a channel. "
            "It keeps working after the token is revoked and is rarely audited."),
        "messages.read": _s(
            "Read messages in channels the user can see", READ, True, DATA_EGRESS,
            "Private conversation history, and a delivery route for prompt "
            "injection from anyone who can post in those channels."),
        "applications.commands": _s(
            "Add slash commands to a server", WRITE, True, EXTERNAL_COMMS,
            "Commands appear to members as a legitimate part of the server."),
        "role_connections.write": _s(
            "Update the user's connection metadata", WRITE, True, IDENTITY,
            "Metadata other servers use to grant roles, so writing it can "
            "change access the user has elsewhere."),
    },

    # Verified against docs.gitlab.com/security/tokens/access_token_scopes, Sept 2026.
    "gitlab": {
        "api": _s(
            "Complete read and write API access", DESTRUCTIVE, False, INFRASTRUCTURE,
            "The broadest GitLab token scope. Includes deleting projects, "
            "rewriting CI configuration and reading every variable a pipeline "
            "holds, which is where deployment credentials live."),
        "read_api": _s(
            "Read-only API access", READ, True, DATA_EGRESS,
            "Reads source, issues and pipeline configuration across everything "
            "the token's owner can reach."),
        "read_repository": _s(
            "Clone repositories", READ, True, DATA_EGRESS,
            "Full source history. Secrets committed and later removed are "
            "still present in the history this can read."),
        "write_repository": _s(
            "Push to repositories", WRITE, False, INFRASTRUCTURE,
            "A push can alter CI configuration, and CI runs with credentials "
            "the pusher may not otherwise hold. Force-push destroys history."),
        "read_registry": _s(
            "Pull container images", READ, True, DATA_EGRESS,
            "Built images routinely contain baked-in configuration and, too "
            "often, the credentials used at build time."),
        "write_registry": _s(
            "Push container images", WRITE, False, INFRASTRUCTURE,
            "Overwriting a tag changes what deploys next, with no source "
            "change to review."),
        "sudo": _s(
            "Act as any user on the instance", DESTRUCTIVE, False, IDENTITY,
            "Impersonation. Every action is attributed to the impersonated "
            "user, so the audit trail names the wrong person."),
        "admin_mode": _s(
            "Perform administrative API actions", DESTRUCTIVE, False, INFRASTRUCTURE,
            "Instance administration on self-managed GitLab: users, groups, "
            "settings and the audit configuration itself."),
        "ai_features": _s(
            "Use GitLab Duo APIs", WRITE, True, DATA_EGRESS,
            "Sends source code to a model endpoint for completion and chat."),
    },

    "generic": {},
}


# Verb inference for scopes not in the catalog. Cloud providers mint new
# actions constantly; guessing from the verb is far more accurate than
# inheriting the severity of a broad wildcard entry.
_READ_VERBS = ("get", "list", "describe", "read", "view", "search", "query", "head")
_DESTRUCTIVE_VERBS = ("delete", "terminate", "destroy", "remove", "purge", "revoke", "drop")
_FINANCIAL_HINTS = ("payment", "charge", "refund", "payout", "transfer", "invoice", "billing")


def _infer(provider, scope):
    """Classify an unrecognised scope from its action verb."""
    tail = scope.split(":")[-1].split(".")[-1].split("/")[-1].lower()
    lowered = scope.lower()

    if any(h in lowered for h in _FINANCIAL_HINTS) and not tail.startswith(_READ_VERBS):
        authority, reversible, blast = FINANCIAL, False, MONETARY
    elif tail.startswith(_DESTRUCTIVE_VERBS):
        authority, reversible, blast = DESTRUCTIVE, False, INFRASTRUCTURE
    elif tail.startswith(_READ_VERBS):
        authority, reversible, blast = READ, True, DATA_EGRESS
    else:
        authority, reversible, blast = WRITE, False, DATA_EGRESS

    entry = _s(
        scope, authority, reversible, blast,
        "Not in the capability catalog. Classified as %s from its action verb. "
        "Confirm this manually before relying on the score." % authority,
    )
    entry["known"] = False
    return entry


_FEED_CACHE = []   # one slot; [] means "not looked yet", [None] means "no feed"


def _feed_catalogue():
    """The subscribed catalogue if one is cached, else None.

    Read once per process and never over the network: a scan must not depend
    on a server being reachable, and must not slow down because one is not.
    """
    if not _FEED_CACHE:
        try:
            from . import feed
            doc = feed.load()
            _FEED_CACHE.append(doc.get("catalogue") if doc else None)
        except Exception:
            _FEED_CACHE.append(None)
    return _FEED_CACHE[0]


def reset_feed_cache():
    """Drop the memoised feed. For tests, and after `ranwhat update`."""
    del _FEED_CACHE[:]


def providers(provider):
    """Bundled entries for a provider, overlaid with any feed entries.

    The feed wins per scope rather than per provider, so a feed that has not
    caught up with a locally known scope cannot remove it.

    It can add scopes and raise a rating, never lower one. A feed that says
    delete_repo is a read, that a bundled irreversible action can be undone,
    or that a Stripe charge risks data rather than money, is either wrong or
    tampered with, and the report would state it with the confidence of the
    whole catalogue. The feed is not signed, and ~/.ranwhat is writable by
    the agents this tool audits, so the bundled rating is the floor.
    """
    merged = dict(CATALOG.get(provider, {}))
    fed = _feed_catalogue()
    if fed:
        for scope, entry in fed.get(provider, {}).items():
            merged[scope] = _no_lower(merged.get(scope), entry)
    return merged


def blast_weight(authority, blast):
    """How much a blast value counts in score.blast_radius, for a scope of
    this authority. Read off that function, and a test holds the two together.

    Not a ranking of the values alone, because the scorer counts the same
    value differently by authority: it skips a read scope unless its blast is
    data_egress, so for a read, monetary counts for nothing. Past that,
    monetary is the one value that also yields the monetary result and its
    "Unbounded financial authority" finding, and the rest each open one
    dimension and count the same.
    """
    if authority == READ and blast != DATA_EGRESS:
        return 0
    if blast == MONETARY:
        return 2
    return 1


def _no_lower(bundled, fed):
    """A feed entry over a bundled one: the more severe of the two on each
    rating, so raising one rating cannot carry the lowering of another."""
    fed = {k: fed[k] for k in ("label", "authority", "reversible", "blast", "why")
           if k in fed}
    if bundled is None:
        return fed
    merged = dict(fed)
    if AUTHORITY_RANK[fed["authority"]] < AUTHORITY_RANK[bundled["authority"]]:
        merged["authority"] = bundled["authority"]
    merged["reversible"] = bundled["reversible"] and fed["reversible"]
    # Weighed at the authority the scorer will see. A tie keeps the bundled
    # value: infrastructure moved to identity counts the same, and only drops
    # a dimension from the report.
    at = merged["authority"]
    if blast_weight(at, fed["blast"]) <= blast_weight(at, bundled["blast"]):
        merged["blast"] = bundled["blast"]
    if any(merged[k] != fed[k] for k in ("authority", "reversible", "blast")):
        # The feed's text describes ratings it was not given.
        merged["label"], merged["why"] = bundled["label"], bundled["why"]
    return merged


def lookup(provider, scope):
    """Resolve a granted scope to its capability entry.

    An exact catalog hit wins. A granted scope that is itself a wildcard
    (e.g. "s3:*") matches the catalog wildcard. A narrow granted scope is
    NEVER widened to a broad wildcard entry -- being granted s3:ListBucket
    is not the same as being granted s3:*, and scoring it that way would
    make the whole report untrustworthy.

    A subscribed feed entry overrides the bundled one for the same scope, and
    adds scopes the bundle never had. Everything below is unchanged by that:
    the feed supplies data, not different rules.
    """
    prov = providers(provider)
    if scope in prov:
        entry = dict(prov[scope])
        entry["known"] = True
        return entry

    if scope.endswith("*"):
        wildcards = sorted([s for s in prov if s.endswith("*")], key=len, reverse=True)
        for pattern in wildcards:
            if scope.startswith(pattern[:-1]):
                entry = dict(prov[pattern])
                entry["known"] = True
                entry["label"] = "%s (matched %s)" % (entry["label"], pattern)
                return entry

    return _infer(provider, scope)
