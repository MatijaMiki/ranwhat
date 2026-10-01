"""A usage pull must be about the credential it was asked about. Pulling one
account's history and scoring it against another's grants produces a report
that is confidently about nobody."""
import json
import unittest
from unittest import mock

from ranwhat import usage


class AwsUsesOneProfileThroughout(unittest.TestCase):

    def test_every_aws_call_carries_the_profile(self):
        calls = []

        def fake_run(cmd, **kw):
            calls.append(cmd)
            if cmd[1:3] == ["sts", "get-caller-identity"]:
                out = {"Arn": "arn:aws:sts::111122223333:assumed-role/agent/s"}
            elif cmd[2] == "generate-service-last-accessed-details":
                out = {"JobId": "j"}
            else:
                out = {"JobStatus": "COMPLETED", "ServicesLastAccessed": []}
            return mock.Mock(returncode=0, stdout=json.dumps(out), stderr="")

        with mock.patch.object(usage.subprocess, "run", fake_run):
            usage.aws_usage(profile="agent-prod")
        self.assertEqual(len(calls), 3)
        for cmd in calls:
            self.assertIn("--profile", cmd, cmd)
            self.assertEqual(cmd[cmd.index("--profile") + 1], "agent-prod")


class GithubOrgIsOnePathSegment(unittest.TestCase):

    def test_org_cannot_change_the_path(self):
        seen = []

        def fake_request(url, headers=None, **kw):
            seen.append(url)
            return 404, {}, b""

        with mock.patch.object(usage, "_request", fake_request):
            usage.github_usage("tok", org="../../user/repos?x=1#")
        path = seen[0].split("?")[0]
        self.assertEqual(path, "https://api.github.com/orgs/..%2F..%2Fuser%2Frepos%3Fx%3D1%23/audit-log")

    def test_ordinary_org_is_unchanged(self):
        seen = []
        with mock.patch.object(usage, "_request",
                               lambda url, **kw: (seen.append(url), (404, {}, b""))[1]):
            usage.github_usage("tok", org="acme-inc")
        self.assertTrue(seen[0].startswith("https://api.github.com/orgs/acme-inc/audit-log?"))


if __name__ == "__main__":
    unittest.main()
