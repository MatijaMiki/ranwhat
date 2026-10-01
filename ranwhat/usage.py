"""
Usage pulls: determine which granted permissions were actually exercised.

Design note that shapes everything here: we only need to confirm *writes*.
An unused read scope is a low-severity finding; the ones that matter --
financial, destructive, irreversible writes -- are exactly the ones that
leave a record in an event stream or audit log. So partial coverage is not
a partial product.

Every pull is read-only and degrades honestly: if a provider cannot report
usage at the tier the customer is on, that is returned as an explicit
coverage gap rather than an empty set. An empty set would silently read as
"nothing was used", which would turn every scope into a false critical.
"""

from __future__ import annotations

import datetime
import json
import subprocess
import urllib.parse

from .introspect import _request, IntrospectionError

DEFAULT_WINDOW_DAYS = 90


class Coverage(object):
    """What a pull could and could not establish."""

    FULL = "full"            # writes and reads both observable
    WRITES_ONLY = "writes"   # mutations observable, reads not
    NONE = "none"            # provider cannot report usage here

    def __init__(self, provider, level, note, window_days=None):
        self.provider = provider
        self.level = level
        self.note = note
        self.window_days = window_days

    def as_dict(self):
        return {"provider": self.provider, "level": self.level,
                "note": self.note, "window_days": self.window_days}


# --------------------------------------------------------------------------
# Stripe -- /v1/events. Events are mutations, so this establishes writes.
# --------------------------------------------------------------------------

_STRIPE_EVENT_SCOPES = {
    "charge.succeeded": "charges:write",
    "charge.captured": "charges:write",
    "charge.updated": "charges:write",
    "charge.refunded": "refunds:write",
    "refund.created": "refunds:write",
    "refund.updated": "refunds:write",
    "transfer.created": "transfers:write",
    "transfer.updated": "transfers:write",
    "payout.created": "transfers:write",
    "payout.paid": "transfers:write",
    "payment_intent.created": "payment_intents:write",
    "payment_intent.succeeded": "payment_intents:write",
    "customer.created": "customers:write",
    "customer.updated": "customers:write",
    "customer.deleted": "customers:write",
}


def stripe_usage(api_key, window_days=DEFAULT_WINDOW_DAYS):
    since = int((datetime.datetime.now(datetime.timezone.utc)
                 - datetime.timedelta(days=window_days)).timestamp())
    used = set()
    starting_after = None
    pages = 0

    while pages < 10:
        params = {"limit": 100, "created[gte]": since}
        if starting_after:
            params["starting_after"] = starting_after
        url = "https://api.stripe.com/v1/events?" + urllib.parse.urlencode(params)
        status, _, raw = _request(url, headers={"Authorization": "Bearer %s" % api_key})
        if status != 200:
            raise IntrospectionError("stripe events returned %s: %s" % (status, raw[:200]))
        payload = json.loads(raw)
        data = payload.get("data", [])
        for ev in data:
            scope = _STRIPE_EVENT_SCOPES.get(ev.get("type"))
            if scope:
                used.add(scope)
        if not payload.get("has_more") or not data:
            break
        starting_after = data[-1]["id"]
        pages += 1

    return sorted(used), Coverage(
        "stripe", Coverage.WRITES_ONLY,
        "Derived from the event stream, which records mutations only. "
        "Read scopes cannot be confirmed as used or unused.",
        window_days)


# --------------------------------------------------------------------------
# AWS -- IAM service-last-accessed. Shells out to the AWS CLI rather than
# hand-rolling SigV4; anyone with an agent role already has the CLI.
# --------------------------------------------------------------------------

_AWS_SERVICE_PREFIX = {
    "s3": "s3", "iam": "iam", "lambda": "lambda", "dynamodb": "dynamodb",
    "ses": "ses", "sns": "sns", "sqs": "sqs", "ec2": "ec2", "kms": "kms",
    "secretsmanager": "secretsmanager", "bedrock": "bedrock",
}


def _aws(args, profile=None):
    cmd = ["aws"] + args + ["--output", "json"]
    if profile:
        cmd += ["--profile", profile]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    except FileNotFoundError:
        raise IntrospectionError("aws CLI not found on PATH")
    except subprocess.TimeoutExpired:
        raise IntrospectionError("aws CLI timed out")
    if out.returncode != 0:
        raise IntrospectionError((out.stderr or "aws CLI failed").strip()[:300])
    return json.loads(out.stdout) if out.stdout.strip() else {}


def aws_usage(principal_arn=None, profile=None, window_days=DEFAULT_WINDOW_DAYS):
    """Returns scope prefixes observed as used, e.g. ["s3:*", "lambda:*"].

    IAM reports last-accessed at service granularity, not per-action, so a
    service seen at all marks that whole service's scopes as used. That is
    deliberately generous -- it under-reports unused permissions rather than
    over-reporting them, because a false "never used" on a scope someone
    depends on destroys trust in the report.
    """
    if not principal_arn:
        # Same profile as every call below. Without it the principal came
        # from the default profile while the usage was pulled for another,
        # and the report scored one account's usage against another's grants.
        principal_arn = _aws(["sts", "get-caller-identity"], profile).get("Arn", "")
        # sts returns an assumed-role ARN; convert to the role ARN IAM wants
        if ":assumed-role/" in principal_arn:
            acct = principal_arn.split(":")[4]
            role = principal_arn.split(":assumed-role/")[1].split("/")[0]
            principal_arn = "arn:aws:iam::%s:role/%s" % (acct, role)
    if not principal_arn:
        raise IntrospectionError("could not determine AWS principal ARN")

    job = _aws(["iam", "generate-service-last-accessed-details",
                "--arn", principal_arn], profile)
    job_id = job.get("JobId")
    if not job_id:
        raise IntrospectionError("IAM did not return a job id")

    details = None
    for _ in range(20):
        details = _aws(["iam", "get-service-last-accessed-details",
                        "--job-id", job_id], profile)
        if details.get("JobStatus") != "IN_PROGRESS":
            break
        import time
        time.sleep(1)

    if not details or details.get("JobStatus") != "COMPLETED":
        raise IntrospectionError("IAM last-accessed job did not complete")

    cutoff = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=window_days)
    used = set()
    for svc in details.get("ServicesLastAccessed", []):
        last = svc.get("LastAuthenticated")
        if not last:
            continue
        try:
            when = datetime.datetime.fromisoformat(last.replace("Z", "+00:00"))
        except ValueError:
            continue
        if when < cutoff:
            continue
        prefix = svc.get("ServiceNamespace")
        if prefix:
            used.add("%s:*" % prefix)

    return sorted(used), Coverage(
        "aws", Coverage.FULL,
        "From IAM service-last-accessed. Granularity is per-service, not "
        "per-action, so a used service marks all of its scopes used.",
        window_days)


# --------------------------------------------------------------------------
# Google -- Admin SDK Reports, OAuth token activity. Needs an admin token.
# --------------------------------------------------------------------------

_GOOGLE_APP_SCOPES = {
    "gmail": ["https://www.googleapis.com/auth/gmail.send",
              "https://www.googleapis.com/auth/gmail.modify",
              "https://www.googleapis.com/auth/gmail.readonly",
              "https://mail.google.com/"],
    "drive": ["https://www.googleapis.com/auth/drive",
              "https://www.googleapis.com/auth/drive.file",
              "https://www.googleapis.com/auth/drive.readonly"],
    "calendar": ["https://www.googleapis.com/auth/calendar",
                 "https://www.googleapis.com/auth/calendar.readonly"],
}


def google_usage(admin_token, window_days=DEFAULT_WINDOW_DAYS):
    start = (datetime.datetime.now(datetime.timezone.utc)
             - datetime.timedelta(days=window_days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    url = ("https://admin.googleapis.com/admin/reports/v1/activity/users/all/"
           "applications/token?" + urllib.parse.urlencode(
               {"startTime": start, "maxResults": 1000}))
    status, _, raw = _request(url, headers={"Authorization": "Bearer %s" % admin_token})

    if status == 403:
        return [], Coverage(
            "google", Coverage.NONE,
            "Token lacks admin.reports.audit.readonly, or the account is not "
            "a Workspace admin. OAuth grant activity is only exposed to admins.",
            window_days)
    if status != 200:
        raise IntrospectionError("google reports returned %s: %s" % (status, raw[:200]))

    used = set()
    for item in json.loads(raw).get("items", []):
        for event in item.get("events", []):
            for param in event.get("parameters", []):
                if param.get("name") == "scope":
                    for value in (param.get("multiValue") or
                                  ([param["value"]] if param.get("value") else [])):
                        used.add(value)
                elif param.get("name") == "app_name":
                    for key, scopes in _GOOGLE_APP_SCOPES.items():
                        if key in str(param.get("value", "")).lower():
                            used.update(scopes)

    return sorted(used), Coverage(
        "google", Coverage.FULL,
        "From Admin SDK token activity reports.", window_days)


# --------------------------------------------------------------------------
# GitHub -- org audit log. Enterprise Cloud only; degrades honestly.
# --------------------------------------------------------------------------

_GH_ACTION_SCOPES = {
    "git.push": "repo", "git.clone": "repo", "repo.create": "repo",
    "repo.destroy": "delete_repo", "workflows.": "workflow",
    "gist.": "gist", "org.": "read:org", "packages.": "write:packages",
}


def github_usage(token, org=None, window_days=DEFAULT_WINDOW_DAYS):
    if not org:
        return [], Coverage(
            "github", Coverage.NONE,
            "No organisation supplied. GitHub exposes usage only via the org "
            "audit log; personal tokens have no usage endpoint.", window_days)

    since = (datetime.datetime.now(datetime.timezone.utc)
             - datetime.timedelta(days=window_days)).strftime("%Y-%m-%d")
    # Quoted whole, so an org name can only ever be one path segment.
    url = ("https://api.github.com/orgs/%s/audit-log?"
           % urllib.parse.quote(org, safe="")) + urllib.parse.urlencode(
        {"phrase": "created:>=%s" % since, "per_page": 100})
    status, _, raw = _request(url, headers={
        "Authorization": "Bearer %s" % token,
        "Accept": "application/vnd.github+json"})

    if status in (403, 404):
        return [], Coverage(
            "github", Coverage.NONE,
            "Audit log unavailable. It requires GitHub Enterprise Cloud and a "
            "token with read:audit_log.", window_days)
    if status != 200:
        raise IntrospectionError("github audit log returned %s: %s" % (status, raw[:200]))

    used = set()
    for entry in json.loads(raw):
        action = str(entry.get("action", ""))
        for prefix, scope in _GH_ACTION_SCOPES.items():
            if action.startswith(prefix):
                used.add(scope)

    return sorted(used), Coverage(
        "github", Coverage.FULL, "From the organisation audit log.", window_days)


# --------------------------------------------------------------------------

PULLS = {
    "stripe": stripe_usage,
    "aws": aws_usage,
    "google": google_usage,
    "github": github_usage,
}


def apply_usage(profile, results):
    """Merge pulled usage into a profile's credentials in place.

    results: {provider: (used_scopes, Coverage)}
    """
    coverage = []
    for cred in profile.get("credentials", []):
        provider = cred.get("provider")
        if provider not in results:
            continue
        used, cov = results[provider]
        if cov.level == Coverage.NONE:
            cred.pop("scopes_used", None)   # leave usage unknown, do not fake it
            continue

        granted = cred.get("scopes", [])
        matched = set()
        for scope in granted:
            if scope in used:
                matched.add(scope)
                continue
            # AWS reports per-service; match a granted action to its service
            for u in used:
                if u.endswith(":*") and scope.startswith(u[:-1]):
                    matched.add(scope)
                    break
        if cov.level == Coverage.WRITES_ONLY:
            # reads are unverifiable here; credit them so they are not
            # reported as never-used on evidence we do not have
            from .catalog import lookup, READ
            for scope in granted:
                if lookup(provider, scope)["authority"] == READ:
                    matched.add(scope)
        cred["scopes_used"] = sorted(matched)

    for _, (_used, cov) in results.items():
        coverage.append(cov.as_dict())
    profile["usage_coverage"] = coverage
    return profile
