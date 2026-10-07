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
        "https://www.googleapis.com/auth/gmail.compose": _s(
            "Manage drafts and send mail", WRITE, False, EXTERNAL_COMMS,
            "Sends mail as the user, as gmail.send does, and reads and rewrites every "
            "draft, which often holds text not yet meant to leave."),
        "https://www.googleapis.com/auth/spreadsheets": _s(
            "Full access to every Google Sheets spreadsheet", DESTRUCTIVE, False, DATA_EGRESS,
            "Reads, edits and deletes every spreadsheet the user can open, not only "
            "ones the app made. Finance, payroll and customer lists often live there."),
        "https://www.googleapis.com/auth/admin.directory.user": _s(
            "Manage every user account in the Workspace domain", DESTRUCTIVE, False, IDENTITY,
            "Creates and deletes any account in the domain, and can make any user a "
            "super administrator. It covers every user, not only the one who granted "
            "it."),
        "https://www.googleapis.com/auth/admin.directory.rolemanagement": _s(
            "Create admin roles and assign them", DESTRUCTIVE, False, IDENTITY,
            "Creates admin roles and assigns them to any user or security group in "
            "the organisation, the account the agent runs as included. A role can "
            "carry any Admin console privilege, so with a super admin signed in it "
            "can hand out control of the whole domain."),
        "https://www.googleapis.com/auth/admin.directory.user.security": _s(
            "Manage users' backup codes, app passwords and OAuth tokens",
            DESTRUCTIVE, False, IDENTITY,
            "Reads any user's valid backup verification codes, which sign in past "
            "2-Step Verification, and lists and deletes their app passwords and OAuth "
            "tokens. Revoking tokens also cuts off integrations people depend on."),
        "https://www.googleapis.com/auth/gmail.settings.sharing": _s(
            "Manage mail forwarding and delegates", WRITE, False, DATA_EGRESS,
            "Turns on auto-forwarding and adds delegates marked accepted without any "
            "verification email. It works only through domain-wide delegation, so it "
            "reaches any mailbox in the domain."),
        "https://www.googleapis.com/auth/gmail.settings.basic": _s(
            "Manage Gmail settings and filters", WRITE, False, DATA_EGRESS,
            "Creates filters that from then on forward matching mail to an already "
            "verified address, or archive or trash it. A standing rule like that can "
            "hide security alerts from the user long after the session that made it."),
        "https://www.googleapis.com/auth/devstorage.full_control": _s(
            "Full control of Cloud Storage, including access policies",
            DESTRUCTIVE, False, DATA_EGRESS,
            "Reads, overwrites and deletes every object, and changes bucket IAM "
            "policies, so it can make a bucket public. devstorage.read_write cannot "
            "touch access control; this can."),
        "https://www.googleapis.com/auth/cloud-billing": _s(
            "Manage Cloud billing accounts", FINANCIAL, False, MONETARY,
            "Links projects to billing accounts, which decides what gets charged and "
            "to whom. Removing a project's billing account stops its paid services."),
        "https://www.googleapis.com/auth/script.projects": _s(
            "Create and rewrite Apps Script projects", DESTRUCTIVE, False, INFRASTRUCTURE,
            "Replaces a script's code, which then runs from the script's triggers and "
            "test deployments with whatever access the script was already granted. "
            "The update clears every existing file in the project."),
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
        "admin:public_key": _s(
            "Full control of the user's SSH keys", DESTRUCTIVE, False, IDENTITY,
            "An added SSH key pushes and pulls as the user, to every repository they "
            "can reach, whatever else this token was limited to. Deleting keys locks "
            "out the machines that use them."),
        "admin:repo_hook": _s(
            "Manage repository webhooks", WRITE, False, DATA_EGRESS,
            "A webhook sends the repository's events, pushes and pull requests among "
            "them, to any URL it names, until someone removes it. Narrower than repo, "
            "which covers hooks too."),
        "admin:org_hook": _s(
            "Manage organisation webhooks", WRITE, False, DATA_EGRESS,
            "An organisation webhook is sent events from every repository in the "
            "organisation. The token manages only hooks its own app or user created, "
            "so it can add one but not remove anyone else's."),
        "delete:packages": _s(
            "Delete packages", DESTRUCTIVE, False, INFRASTRUCTURE,
            "Removes a published package or version that builds and deploys may pin. "
            "GitHub restores one only within 30 days, and only while nothing new has "
            "taken its name."),
        "scim:enterprise": _s(
            "Provision and delete enterprise accounts through SCIM", DESTRUCTIVE, False, IDENTITY,
            "Creates, suspends and deletes the managed user accounts of an "
            "enterprise. GitHub documents deleting one as irreversible: it erases the "
            "user's data, keys and tokens."),
        "admin:enterprise": _s(
            "Full control of an enterprise", DESTRUCTIVE, False, INFRASTRUCTURE,
            "Can set the GitHub Actions policy every organisation in the enterprise "
            "inherits, such as which actions may run and what the default workflow "
            "token may do. Also includes full control of the enterprise's self-hosted "
            "runners and read/write access to its billing."),
        "manage_runners:enterprise": _s(
            "Full control of the enterprise's self-hosted runners",
            DESTRUCTIVE, False, INFRASTRUCTURE,
            "A runner it registers is sent the jobs whose labels it claims, from "
            "every organisation its runner group serves, and it can widen a group to "
            "every organisation in the enterprise. Those jobs bring the secrets they "
            "use. Removing runners stops the builds and deploys that depend on them."),
        "manage_billing:enterprise": _s(
            "Read and write enterprise billing", FINANCIAL, False, MONETARY,
            "Billing settings decide what metered Actions, Codespaces and Copilot "
            "usage may cost the enterprise. Charges run up under a changed setting "
            "are still owed after it is changed back."),
        "manage_billing:copilot": _s(
            "Add and remove paid Copilot seats", FINANCIAL, False, MONETARY,
            "Every seat it adds is billed to the organisation, pro rata to the end of "
            "the billing cycle. A removed seat stays billed until that cycle ends, so "
            "a mistaken bulk assignment is paid for even once it is undone."),
        "codespace": _s(
            "Create, manage and delete codespaces", DESTRUCTIVE, False, INFRASTRUCTURE,
            "A codespace is a billed cloud machine with the repository checked out. "
            "GitHub warns that the GITHUB_TOKEN inside it may hold scopes this token "
            "lacks. Deleting a codespace discards any work that was not pushed."),
        "admin:gpg_key": _s(
            "Full control of the user's GPG keys", DESTRUCTIVE, False, IDENTITY,
            "Commits signed with a key it adds show as Verified under the user's name "
            "and pass rules that require signed commits. They stay Verified after the "
            "key is deleted, because GitHub does not re-check old signatures."),
        "security_events": _s(
            "Read and dismiss code scanning alerts", WRITE, True, DATA_EGRESS,
            "Reads the list of known, unfixed vulnerabilities in the code, which is "
            "an attacker's shortlist. It can also dismiss alerts, so the people who "
            "would fix them stop seeing them."),
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
        "files:write": _s(
            "Upload, edit and delete files", WRITE, False, DATA_EGRESS,
            "Shares a file into any channel the app is in, and with a user token "
            "turns a file into a public link that opens without signing in to Slack."),
        "chat:write.customize": _s(
            "Post under any name and avatar", WRITE, False, IDENTITY,
            "Messages can carry any display name and picture, a colleague's or an "
            "executive's. Combined with chat:write, which it requires, that is "
            "impersonation inside the company's own workspace."),
        "chat:write.public": _s(
            "Post in channels the app was not added to", WRITE, False, EXTERNAL_COMMS,
            "Posts into any public channel without being invited, so the channels the "
            "app was added to no longer bound where it can speak."),
        "incoming-webhook": _s(
            "Post into one channel through a webhook URL", WRITE, False, EXTERNAL_COMMS,
            "Installing with this scope returns a URL that posts into the channel "
            "picked at install, and only that channel. Whoever holds the URL can "
            "post, with no token, and it tends to be pasted into config and CI "
            "settings where nobody treats it as a secret."),
        "search:read": _s(
            "Search everything the user can see", READ, True, DATA_EGRESS,
            "One query reaches every message and file the user can open, private "
            "channels and DMs included. Finding a pasted password takes one search, "
            "not a read of every channel."),
        "admin.users:write": _s(
            "Add, remove and promote users across the org", DESTRUCTIVE, False, IDENTITY,
            "Across the whole Enterprise org: invites and removes users, makes them "
            "admins or owners, and ends their sessions. Adding an admin gives an "
            "attacker persistence, and removing the real ones locks them out."),
        "admin.apps:write": _s(
            "Approve, restrict and uninstall apps across the org", DESTRUCTIVE, False, IDENTITY,
            "Approving an app clears it to be installed with every scope it asked "
            "for, on one workspace or the whole Enterprise org, so this hands out "
            "access it does not itself hold. Once an admin app manages approvals, "
            "Slack turns off approving apps in the UI."),
        "admin.conversations:write": _s(
            "Delete, archive and change any channel in the org", DESTRUCTIVE, False, DATA_EGRESS,
            "Includes bulk delete, message retention settings and turning a private "
            "channel public. A deleted channel takes its messages with it for good, "
            "and a private channel made public is readable by everyone in the "
            "workspace at once."),
    },
    # Stripe has no scope strings an API reports: a restricted key is given
    # Read or Write per resource in the Dashboard, and a profile lists them.
    # These keys are ranwhat's resource:verb names for those permissions
    # (Payouts: Write is payouts:write). Stripe Apps names the same ones
    # payout_write and so on, which is what its permissions reference shows.
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
        "payouts:write": _s(
            "Pay out the Stripe balance", FINANCIAL, False, MONETARY,
            "Sends the Stripe balance to any bank account or debit card already on "
            "the account, instantly where the account is eligible. Money paid out is "
            "no longer there to cover refunds and disputes."),
        "issuing_cards:write": _s(
            "Create and manage issued cards", FINANCIAL, False, MONETARY,
            "Creates cards that spend the business's Issuing balance and raises a "
            "card's own spending limits. It can also set a card's PIN and change "
            "where a physical card ships. Purchases made on a card stay made, and "
            "cancelling a card is permanent."),
        "credit_notes:write": _s(
            "Issue and void credit notes", FINANCIAL, False, MONETARY,
            "Reduces what a customer owes on a finalised invoice and credits their "
            "balance for future invoices. Stripe also creates a refund on the "
            "invoice's charge when a credit note asks for one."),
        "files:write": _s(
            "Upload files and create file links", WRITE, False, DATA_EGRESS,
            "A file link is a URL that opens the file without signing in, and links "
            "can be made to identity documents, selfies, dispute evidence, financial "
            "report runs and Sigma query results. A link with no expiry date works "
            "until someone expires it, and whoever fetched it keeps the file."),
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
        "iam:PassRole": _s(
            "Pass IAM roles to AWS services", DESTRUCTIVE, False, IDENTITY,
            "Gives a role to a service the agent controls, such as a Lambda function "
            "or an EC2 instance, which then acts with that role's permissions instead "
            "of the agent's own. AWS logs no event for the pass itself."),
        "iam:CreateAccessKey": _s(
            "Create access keys for IAM users", DESTRUCTIVE, False, IDENTITY,
            "Mints a long-lived key for any IAM user the policy covers, including "
            "users with more access than the agent. The key keeps working after the "
            "agent's own credential is revoked."),
        "iam:AttachUserPolicy": _s(
            "Attach managed policies to IAM users", DESTRUCTIVE, False, IDENTITY,
            "Can attach AdministratorAccess to any IAM user, including the one a user "
            "access key belongs to. Unless a permissions boundary caps that user, "
            "every other limit on the key is then decorative."),
        "secretsmanager:GetSecretValue": _s(
            "Read secret values", READ, True, DATA_EGRESS,
            "Returns secrets in plaintext: database passwords, API keys and other "
            "systems' credentials. A value read here keeps working outside AWS, where "
            "revoking this permission does not reach it; only rotating the secret "
            "does."),
        "s3:PutBucketPolicy": _s(
            "Add or replace bucket policies", DESTRUCTIVE, False, DATA_EGRESS,
            "A bucket policy can grant read to everyone or to another account, and "
            "unless Block Public Access is on, one call publishes the whole bucket. "
            "Only the bucket's own account can call this, and there a bucket policy "
            "needs no matching IAM allow, so the holder can also grant itself every "
            "S3 action on the bucket, deletion included."),
        "cloudtrail:StopLogging": _s(
            "Stop CloudTrail logging", DESTRUCTIVE, False, INFRASTRUCTURE,
            "Stops a trail recording API calls and delivering its log files. Logging "
            "can be started again, but data events in the gap are never recorded, and "
            "management events survive only in the 90-day event history."),
        "ssm:SendCommand": _s(
            "Run commands on managed instances", DESTRUCTIVE, False, INFRASTRUCTURE,
            "Runs arbitrary commands on every managed server the policy covers, many "
            "at once. Each of those servers holds credentials of its own."),
        "ec2:RunInstances": _s(
            "Launch EC2 instances", WRITE, False, MONETARY,
            "Compute is billed from launch, and terminating an instance does not "
            "refund the time it already ran. A loop or a hijacked agent turns into a "
            "bill."),
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
        "write:confluence-space": _s(
            "Create, update and permanently delete spaces", DESTRUCTIVE, False, DATA_EGRESS,
            "Deleting a space through the API skips the trash. Every page, attachment "
            "and page history in the space is gone at once, and Atlassian documents "
            "the deletion as permanent."),
        "manage:confluence-configuration": _s(
            "Change site-wide Confluence look and feel", WRITE, True, INFRASTRUCTURE,
            "Sets the global theme and look and feel that every space inherits, so "
            "one change is seen by everyone on the site. The defaults can be restored "
            "with a reset, and the scope does not reach content, spaces or "
            "permissions."),
        "write:confluence-groups": _s(
            "Create, change and remove user groups and their members",
            DESTRUCTIVE, False, IDENTITY,
            "Adds and removes group members, and groups are how Confluence grants "
            "access to spaces. Held by a site admin, it can put any account, "
            "including one it controls, into whichever group already has access to "
            "the spaces it wants."),
        "read:confluence-content.all": _s(
            "Read all Confluence content, including page bodies", READ, True, DATA_EGRESS,
            "Full page bodies across every space the user can see. Wikis hold "
            "runbooks, architecture notes and credentials pasted in for a colleague, "
            "and any page can carry injected instructions."),
        "write:permission-scheme:jira": _s(
            "Create and update permission schemes", DESTRUCTIVE, False, IDENTITY,
            "A permission scheme decides who may browse, edit and delete in every "
            "project that uses it. An update that sends a list of grants replaces all "
            "the existing ones, so one call can open those projects to anonymous "
            "users or lock their project admins out."),
        "write:group:jira": _s(
            "Create user groups and change their members", DESTRUCTIVE, False, IDENTITY,
            "Covers adding users to groups, and Jira grants product access and "
            "project permissions through groups. Adding an account to a group gives "
            "it everything that group can reach."),
        "write:servicedesk-request": _s(
            "Create, approve, comment on and share customer requests",
            WRITE, False, EXTERNAL_COMMS,
            "Service desk customers are usually outside the company. A public comment "
            "reaches them in the user's name, and adding a participant shares the "
            "request with someone new. It can also approve requests waiting on the "
            "user, which in many desks is how access and changes are signed off."),
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
        "User.ReadWrite.All": _s(
            "Read and write all users' full profiles", DESTRUCTIVE, False, IDENTITY,
            "Writes the profile, manager and reports of every user in the tenant. "
            "With a User Administrator signed in, it is also what creates and deletes "
            "accounts."),
        "Group.ReadWrite.All": _s(
            "Read and write all groups", DESTRUCTIVE, False, IDENTITY,
            "Creates groups and changes the membership of those the user owns. "
            "Membership decides who reaches a team's chats, files and sites, so "
            "changing it changes access."),
        "Chat.ReadWrite": _s(
            "Read and write the user's Teams chats", WRITE, False, EXTERNAL_COMMS,
            "Every one-to-one and group chat the user is in, read and posted to as "
            "them. Microsoft does not require admin consent for it, so a user can "
            "grant it alone."),
        "Files.Read.All": _s(
            "Read all files the user can access", READ, True, DATA_EGRESS,
            "Every OneDrive and SharePoint file the user can open, not only their "
            "own. Microsoft does not require admin consent for it."),
        "RoleManagement.ReadWrite.Directory": _s(
            "Assign Entra ID directory roles", DESTRUCTIVE, False, IDENTITY,
            "Can add any account, its own service principal included, to Global "
            "Administrator. Microsoft's own reference warns that it lets an app grant "
            "additional privileges to itself."),
        "AppRoleAssignment.ReadWrite.All": _s(
            "Grant application permissions to any app", DESTRUCTIVE, False, IDENTITY,
            "Can grant any app, itself included, any application permission on "
            "Microsoft Graph or any other API. Holding this one permission amounts to "
            "holding all of them."),
        "Application.ReadWrite.All": _s(
            "Create, change and delete all app registrations and service principals",
            DESTRUCTIVE, False, IDENTITY,
            "Can add a new secret to almost any app in the tenant and then sign in as "
            "that app, with every permission it holds. A secret added this way keeps "
            "working after the agent's own token is revoked."),
        "Policy.ReadWrite.ConditionalAccess": _s(
            "Read and write Conditional Access policies", DESTRUCTIVE, False, IDENTITY,
            "Conditional Access is where MFA, device and location requirements are "
            "enforced. Turning a policy off drops those checks for everyone it "
            "covered, and excluding an account drops them for that account, without "
            "any change to the account itself."),
        "MailboxSettings.ReadWrite": _s(
            "Manage mailbox settings and inbox rules", DESTRUCTIVE, False, DATA_EGRESS,
            "Inbox rules are a mailbox setting. One rule can forward or redirect "
            "every arriving message to an outside address, or permanently delete it, "
            "and it keeps running after the token is revoked."),
        "Mail.Send.Shared": _s(
            "Send mail as the user and on behalf of others", WRITE, False, EXTERNAL_COMMS,
            "Sends from shared mailboxes and colleagues' mailboxes the user may send "
            "for, so a message can arrive from a team address or another person. Sent "
            "mail cannot be recalled once it leaves the tenant."),
        "Sites.ReadWrite.All": _s(
            "Edit and delete items in all SharePoint sites", DESTRUCTIVE, False, DATA_EGRESS,
            "Edits and deletes documents and list items on every SharePoint site the "
            "user can open, not only their own. Microsoft does not require admin "
            "consent for it, and permanentDelete skips the recycle bin, so a deletion "
            "cannot be restored."),
        "ChannelMessage.Send": _s(
            "Send Teams channel messages as the user", WRITE, False, EXTERNAL_COMMS,
            "Posts into any Teams channel the user belongs to, under their name. "
            "Colleagues trust a message from a known person, and it is seen before it "
            "can be deleted."),
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
        "member:write": _s(
            "Invite members and change their roles", DESTRUCTIVE, False, IDENTITY,
            "Invites any email address into the organisation at a role up to the "
            "token holder's own, and on a user auth token changes existing members' "
            "roles within the same limit. Access granted this way outlives the token."),
        "org:write": _s(
            "Change organisation settings", WRITE, False, DATA_EGRESS,
            "Controls org-wide data scrubbing, anonymous issue sharing, the "
            "two-factor requirement and open team membership. Events stored while "
            "scrubbing was off keep the passwords and tokens it would have removed."),
        "event:write": _s(
            "Update issues, including making them public", WRITE, False, DATA_EGRESS,
            "Can publish an issue, which makes a link anyone outside the organisation "
            "can open, and can resolve or ignore issues so they stop alerting. "
            "Whoever opened the public link keeps what they saw after it is made "
            "private again."),
        "alerts:write": _s(
            "Create, edit and delete alert rules", WRITE, False, INFRASTRUCTURE,
            "Deleting or muting a rule stops the notification that would have told "
            "someone about a fault, including one the agent caused. Alerts not sent "
            "while a rule was gone are not sent later."),
        "org:integrations": _s(
            "Manage and remove the organisation's integrations",
            DESTRUCTIVE, False, INFRASTRUCTURE,
            "Removes the Slack, PagerDuty, Jira or source-code integration that "
            "alerts and issue links go through. Reinstalling one is a manual setup, "
            "not an undo."),
        "team:admin": _s(
            "Delete teams", DESTRUCTIVE, False, IDENTITY,
            "Teams decide which members reach which projects and who issues are "
            "assigned to. Deleting one removes that membership and ownership at once."),
        "project:releases": _s(
            "Create, modify and delete releases", DESTRUCTIVE, False, INFRASTRUCTURE,
            "Deletes a release and every file uploaded to it, which Sentry calls "
            "permanent. It refuses only a release that an issue was first seen in or "
            "that has release-health data, so any other release and its files can go."),
        "org:ci": _s(
            "Create releases and upload source maps", WRITE, True, INFRASTRUCTURE,
            "Meant for CI, across the whole organisation: creates releases, uploads "
            "source maps and manages code mappings. A wrong source map or code "
            "mapping points a stack trace at code that did not fail."),
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
        "write_discounts": _s(
            "Create and modify discounts", FINANCIAL, False, MONETARY,
            "A discount code works for anyone who has it. A 100% code, or one with no "
            "usage limit, gives goods away until it is found and deleted, and orders "
            "already placed with it keep the discount."),
        "write_gift_cards": _s(
            "Issue and modify gift cards", FINANCIAL, False, MONETARY,
            "Issues gift cards with a value of its choosing, which spend like cash in "
            "the shop. What was spent before a card is deactivated stays spent."),
        "write_inventory": _s(
            "Modify inventory", WRITE, True, MONETARY,
            "Stock levels decide what can be sold. Set to zero, a product stops "
            "selling; set too high, the shop takes orders it cannot fill."),
        "write_themes": _s(
            "Edit, publish and delete themes", DESTRUCTIVE, False, INFRASTRUCTURE,
            "Theme code runs in every shopper's browser on the shop's own domain, so "
            "a theme edit is code execution with the shop's name on it. It can also "
            "publish a different theme or delete one."),
        "write_script_tags": _s(
            "Load remote scripts into the storefront", WRITE, False, DATA_EGRESS,
            "Loads JavaScript from a URL it names into the shop's pages, so the code "
            "that runs for shoppers can change after anyone reviewed it. Shopify now "
            "runs script tags only on vintage themes."),
        "write_store_credit_account_transactions": _s(
            "Issue and debit customer store credit", FINANCIAL, False, MONETARY,
            "Can add store credit to any customer's account, which they spend at "
            "checkout like money, or debit balance they already hold. Credit spent "
            "before it is debited back stays spent."),
        "write_returns": _s(
            "Process returns and refund them", FINANCIAL, False, MONETARY,
            "Processing a return can refund it at the same time, shipping and duties "
            "included. A refund paid out is not taken back by editing the return."),
        "write_order_edits": _s(
            "Edit placed orders", FINANCIAL, False, MONETARY,
            "Changes what a placed order contains and costs: items, quantities, "
            "discounts and shipping. A changed total leaves the customer owing a "
            "balance or due a refund, and the customer can be notified before anyone "
            "checks."),
        "write_customer_merge": _s(
            "Merge customer profiles", DESTRUCTIVE, False, IDENTITY,
            "Combines two customer profiles into one and chooses whose email address "
            "survives, which decides who holds that customer's order history and "
            "account from then on. Shopify says a merge can't be reversed."),
        "write_customer_data_erasure": _s(
            "Erase a customer's personal data", DESTRUCTIVE, False, DATA_EGRESS,
            "Queues erasure of a customer's name, address and other personal details "
            "from the shop and from the apps and sales channels installed in it. A "
            "pending request can be cancelled; once it has run, the details are gone."),
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
        "crm.export": _s(
            "Export CRM records of any type", READ, True, DATA_EGRESS,
            "Bulk-exports any CRM object type, contacts, companies and deals among "
            "them, to a file whose download link needs no further authorization until "
            "it expires. HubSpot only lets a Super Admin grant it, so holding it "
            "means one did."),
        "crm.import": _s(
            "Import records of any CRM type", FINANCIAL, False, MONETARY,
            "Creates and overwrites records of every CRM type in bulk, deals "
            "included. One file can rewrite the deal amounts that forecasts and "
            "commission rest on, or the email address on thousands of contacts, "
            "redirecting whatever HubSpot sends them next."),
        "transactional-email": _s(
            "Send transactional email and create SMTP logins", WRITE, False, EXTERNAL_COMMS,
            "Sends email in the company's name, and creates SMTP logins of its own "
            "that stay valid for twelve months. Those are separate credentials, "
            "outside anything this token's grants show."),
        "marketing-email": _s(
            "Read and send marketing email", WRITE, False, EXTERNAL_COMMS,
            "Sends marketing email to contact lists in the company's name. A send to "
            "a whole list cannot be recalled, whatever is corrected afterwards."),
        "automation": _s(
            "Create workflows and custom workflow actions", WRITE, False, DATA_EGRESS,
            "Workflows run on their own once made, enrolling records and acting on "
            "them. A custom action posts each record it runs on, with whichever "
            "properties the app asks for, to a URL the app chooses, which is a "
            "standing feed of CRM data."),
        "communication_preferences.write": _s(
            "Subscribe and unsubscribe contacts", WRITE, False, EXTERNAL_COMMS,
            "Can opt contacts into the company's marketing email with whatever legal "
            "basis it states, so people who never agreed to it get mailed, and can "
            "opt contacts out of all email in a batch. HubSpot documents no API call "
            "that reverses an opt-out of all email, so the token that made one cannot "
            "put it back."),
        "files.delete": _s(
            "Delete files in the file manager", DESTRUCTIVE, False, INFRASTRUCTURE,
            "Pages, emails and other sites link to HubSpot files by URL, and a "
            "deleted file breaks every one of them. The Trash restores one only "
            "within 30 days, and not while another file has taken its name."),
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
        "guilds.members.read": _s(
            "Read the user's member details in each server", READ, True, DATA_EGRESS,
            "Nickname, roles and join date in any server the user belongs to. Roles "
            "show where they moderate or administer, and so whose account is worth "
            "taking."),
        "sdk.social_layer": _s(
            "Send messages as the user in DMs, lobbies and linked channels",
            WRITE, False, EXTERNAL_COMMS,
            "Sends messages as the user in direct messages, game lobbies and the "
            "Discord channels linked to them. Discord asks that each send follow a "
            "user action, but that is a policy the app keeps, not a limit the token "
            "enforces."),
        "rpc": _s(
            "Control the user's Discord client", WRITE, False, DATA_EGRESS,
            "Local control of the desktop client, up to moving the user into a voice "
            "channel, which puts their microphone in a room the app chooses. Approved "
            "partners only, so a grant is rare and worth asking about."),
        "rpc.notifications.read": _s(
            "Receive the user's notifications", READ, True, DATA_EGRESS,
            "Each notification carries the full message that generated it, so "
            "mentions and new messages the user is notified about reach the app as "
            "they reach the user. Local RPC, approved partners only."),
        "voice": _s(
            "Join voice as the user", WRITE, False, DATA_EGRESS,
            "Connects to voice on the user's behalf and lists who is in the channel. "
            "Whatever is said there while it is connected has been heard. Approved "
            "partners only."),
        "applications.commands.permissions.update": _s(
            "Change who may use the app's commands in a server", WRITE, True, IDENTITY,
            "Rewrites which roles, members and channels may run the app's commands, "
            "using the server permissions of the user who granted it. The risk is an "
            "admin-only command opened to every member."),
        "connections": _s(
            "Read the user's linked accounts", READ, True, IDENTITY,
            "Linked accounts such as Steam, GitHub or YouTube, many under a real "
            "name, which ties a pseudonymous Discord account to a person."),
        "relationships.read": _s(
            "Read friends, friend requests and blocked users", READ, True, DATA_EGRESS,
            "The user's social graph and their block list. A block list can reveal "
            "who someone is avoiding, which is sensitive in a way a friends list is "
            "not."),
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
        "k8s_proxy": _s(
            "Call Kubernetes APIs through the GitLab agent", DESTRUCTIVE, False, INFRASTRUCTURE,
            "Reaches every cluster whose agent gives the token's owner access, often "
            "as the agent's own service account. What it can delete is decided by "
            "that account's cluster role, not by the token."),
        "manage_runner": _s(
            "Manage, reconfigure and delete runners", DESTRUCTIVE, False, INFRASTRUCTURE,
            "It can unprotect a runner, so jobs from any branch run on a machine "
            "trusted with deploy credentials. It can also reset a runner's "
            "authentication token to take over the runner's jobs, or delete runners "
            "and stop CI."),
        "create_runner": _s(
            "Register new runners", WRITE, False, INFRASTRUCTURE,
            "A runner it creates can claim the tags a project's jobs ask for. It then "
            "competes with the real runners for those jobs and is sent the ones it "
            "picks up, with their CI/CD variables, which is where deployment "
            "credentials live."),
        "write_virtual_registry": _s(
            "Write and delete images in the dependency proxy cache", WRITE, False, INFRASTRUCTURE,
            "Pipelines that pull images through the dependency proxy run whatever it "
            "has cached, so a push here changes the next build with no source change "
            "to review. Deleting only drops cached copies, which are fetched again "
            "from upstream."),
        "write_package_registry": _s(
            "Publish packages", WRITE, False, INFRASTRUCTURE,
            "A deploy-token scope. It publishes into the project's package registry, "
            "and downstream builds install from that registry without review. "
            "Supply-chain reach."),
        "self_rotate": _s(
            "Rotate its own token", WRITE, False, IDENTITY,
            "Each rotation revokes the old token and issues a new one, so a leaked "
            "token can keep renewing itself past its expiry date. Whoever rotates "
            "first locks the other holder out, and a later rotation attempt with the "
            "revoked token revokes the whole token family."),
    },

    "generic": {},
}


# Verb inference for scopes not in the catalog. Cloud providers mint new
# actions constantly; guessing from the verb is far more accurate than
# inheriting the severity of a broad wildcard entry.
_READ_VERBS = ("get", "list", "describe", "read", "view", "search", "query", "head")
_DESTRUCTIVE_VERBS = ("delete", "terminate", "destroy", "remove", "purge", "revoke", "drop")
_FINANCIAL_HINTS = ("payment", "charge", "refund", "payout", "transfer", "invoice", "billing")


def _from_name(scope):
    """What a scope's own name says it does: (authority, reversible, blast)
    for a payment, a destructive verb or a read verb, else None."""
    tail = scope.split(":")[-1].split(".")[-1].split("/")[-1].lower()
    lowered = scope.lower()

    if any(h in lowered for h in _FINANCIAL_HINTS) and not tail.startswith(_READ_VERBS):
        return FINANCIAL, False, MONETARY
    if tail.startswith(_DESTRUCTIVE_VERBS):
        return DESTRUCTIVE, False, INFRASTRUCTURE
    if tail.startswith(_READ_VERBS):
        return READ, True, DATA_EGRESS
    return None


def _infer(provider, scope):
    """Classify an unrecognised scope from its action verb. A name that says
    nothing is guessed to be an irreversible write."""
    authority, reversible, blast = _from_name(scope) or (WRITE, False, DATA_EGRESS)

    entry = _s(
        scope, authority, reversible, blast,
        "Not in the capability catalog. Classified as %s from its action verb. "
        "Confirm this manually before relying on the score." % authority,
    )
    entry["known"] = False
    return entry


_FEED_CACHE = []   # one slot; [] means "not looked yet", [None] means "no feed"
_MERGED = {}       # provider -> its bundled entries under the feed's, floored


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


def feed_adds_scopes():
    """Whether the cached feed has a scope the bundled catalogue does not,
    the one sense in which it can be newer than the release: it may raise a
    bundled rating, never lower one. Read as lookup() reads it, once per
    process and never over the network."""
    fed = _feed_catalogue()
    return bool(fed) and any(
        scope not in CATALOG.get(provider, {})
        for provider, scopes in fed.items() for scope in scopes)


def reset_feed_cache():
    """Drop the memoised feed, and every merge built from it. For tests, and
    after `ranwhat update`."""
    del _FEED_CACHE[:]
    _MERGED.clear()


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

    This merge floors only a key the bundle also has. lookup() applies the
    same floor to whatever the bundle resolves a scope to, which may be a
    wildcard entry the feed never named.
    """
    return dict(_merged(provider))


def _merged(provider):
    """providers(provider), built once per read of the feed and not copied.

    lookup() asks for it once per grant, and the floor runs in Python over
    every feed scope of the provider: rebuilt on each call, a scan cost
    grants times feed entries, 2.2s for 300 grants against 17,000 entries.
    Callers must not change what it returns; _resolve copies what it hands
    on, and providers() hands out a copy.
    """
    fed = _feed_catalogue()
    if not fed:
        return CATALOG.get(provider, {})
    if provider not in _MERGED:
        merged = dict(CATALOG.get(provider, {}))
        for scope, entry in fed.get(provider, {}).items():
            merged[scope] = _no_lower(merged.get(scope), entry)
        _MERGED[provider] = merged
    return _MERGED[provider]


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


def _resolve(entries, scope):
    """The entry a granted scope resolves to among `entries`, or None.

    An exact hit wins. A granted scope that is itself a wildcard (e.g.
    "s3:*") matches the longest catalog wildcard it falls under. A narrow
    granted scope is never widened to a wildcard entry.
    """
    if scope in entries:
        return dict(entries[scope])
    if scope.endswith("*"):
        wildcards = sorted([s for s in entries if s.endswith("*")], key=len, reverse=True)
        for pattern in wildcards:
            if scope.startswith(pattern[:-1]):
                entry = dict(entries[pattern])
                entry["label"] = "%s (matched %s)" % (entry["label"], pattern)
                return entry
    return None


def _below(floor, entry):
    """Whether entry rates lower than floor on any rating, blast weighed as
    the scorer weighs it. Unlike _no_lower, moving the blast to a dimension
    that counts the same is not lower."""
    if AUTHORITY_RANK[entry["authority"]] < AUTHORITY_RANK[floor["authority"]]:
        return True
    if entry["reversible"] and not floor["reversible"]:
        return True
    at = entry["authority"]
    return blast_weight(at, entry["blast"]) < blast_weight(at, floor["blast"])


def lookup(provider, scope):
    """Resolve a granted scope to its capability entry.

    An exact catalog hit wins. A granted scope that is itself a wildcard
    (e.g. "s3:*") matches the catalog wildcard. A narrow granted scope is
    NEVER widened to a broad wildcard entry -- being granted s3:ListBucket
    is not the same as being granted s3:*, and scoring it that way would
    make the whole report untrustworthy.

    A subscribed feed entry overrides the bundled one for the same scope, and
    adds scopes the bundle never had. It never rates a scope below what the
    report would say without it:

      Where the bundle resolves the scope, what the feed resolves it to is
      floored at that entry, rating by rating. The bundle's key and the
      feed's need not be the same: a longer feed wildcard, or a feed key
      equal to a wildcard grant, is matched before the bundled wildcard.

      Where only the scope's name rates it (a delete verb, a payment, a
      read), a feed entry that rates it lower is ignored whole: nothing it
      says about a scope it has wrong is used, and the scope stays
      unclassified. A name that says nothing is only a guess, and the feed
      may rate that scope as it likes; replacing guesses is what it is for.
    """
    bundled = _resolve(CATALOG.get(provider, {}), scope)
    entry = _resolve(_merged(provider), scope)
    if entry is None:
        return _infer(provider, scope)
    if bundled is not None:
        entry = _no_lower(bundled, entry)
    else:
        guess = _infer(provider, scope)
        if _from_name(scope) and _below(guess, entry):
            return guess
    entry["known"] = True
    return entry
