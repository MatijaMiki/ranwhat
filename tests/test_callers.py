"""ranwhat callers: who used a key, from the provider's own log.

The one answer it must never give without evidence is "nobody used it", so
most of these are about the gaps: a provider that cannot say, a log that
only covers part of the window, an address ranwhat has no way to call yours.
"""
import base64
import contextlib
import hashlib
import io
import json
import unittest
from unittest import mock

from ranwhat import callers, cli
from ranwhat.usage import Coverage

# Split, so push protection never sees a whole key-shaped literal.
KEY = "AKIA" "IOSFODNN7EXAMPLE"


def trail(*events):
    """A CloudTrail lookup-events reply holding these (id, ip, agent,
    source, name, error) events."""
    out = []
    for eid, ip, agent, source, name, error in events:
        detail = {"sourceIPAddress": ip, "userAgent": agent,
                  "eventSource": source, "eventName": name,
                  "awsRegion": "eu-west-1",
                  "eventTime": "2026-10-0%sT10:00:00Z" % (len(out) % 9 + 1)}
        if error:
            detail["errorCode"] = error
        out.append({"EventId": eid, "EventName": name,
                    "CloudTrailEvent": json.dumps(detail)})
    return {"Events": out}


class AwsCallsComeFromCloudTrail(unittest.TestCase):

    def run_with(self, reply, **kw):
        asked = []

        def fake_aws(args, profile=None):
            asked.append((args, profile))
            return reply
        with mock.patch.object(callers, "_aws", fake_aws):
            calls, cov = callers.aws_calls(KEY, **kw)
        return calls, cov, asked

    def test_looks_up_by_access_key_id_with_the_profile(self):
        _, _, asked = self.run_with({"Events": []}, profile="agent-prod")
        for args, profile in asked:
            self.assertEqual(profile, "agent-prod")
            self.assertIn("AttributeKey=AccessKeyId,AttributeValue=" + KEY, args)
            self.assertEqual(args[:2], ["cloudtrail", "lookup-events"])

    def test_us_east_1_is_always_read_for_iam_and_sts(self):
        _, _, asked = self.run_with({"Events": []}, regions=["eu-west-1"])
        regions = [a[a.index("--region") + 1] for a, _ in asked if "--region" in a]
        self.assertEqual(regions, ["eu-west-1", "us-east-1"])

    def test_a_region_given_twice_is_read_once(self):
        _, _, asked = self.run_with({"Events": []}, regions=["us-east-1"])
        self.assertEqual(len(asked), 1)

    def test_an_event_seen_in_two_regions_counts_once(self):
        reply = trail(("e1", "203.0.113.9", "aws-cli/2", "s3.amazonaws.com",
                       "ListBuckets", None))
        calls, _, _ = self.run_with(reply, regions=["eu-west-1"])
        self.assertEqual(len(calls), 1)

    def test_reads_address_agent_action_and_refusals(self):
        reply = trail(("e1", "203.0.113.9", "aws-cli/2", "iam.amazonaws.com",
                       "CreateUser", "AccessDenied"))
        calls, _, _ = self.run_with(reply)
        c = calls[0]
        self.assertEqual((c.ip, c.agent, c.action, c.error),
                         ("203.0.113.9", "aws-cli/2", "iam:CreateUser",
                          "AccessDenied"))

    def test_the_window_is_capped_at_cloudtrails_90_days(self):
        _, cov, _ = self.run_with({"Events": []}, window_days=400)
        self.assertEqual(cov.window_days, 90)

    def test_coverage_says_data_events_may_be_missing(self):
        _, cov, _ = self.run_with({"Events": []})
        self.assertEqual(cov.level, Coverage.WRITES_ONLY)
        self.assertIn("Data events", cov.note)

    def test_no_key_id_is_an_error_not_an_empty_answer(self):
        with self.assertRaises(callers.IntrospectionError):
            callers.aws_calls(None)


class GithubSearchesByTokenHash(unittest.TestCase):

    def test_the_hash_is_sha256_base64(self):
        want = base64.b64encode(hashlib.sha256(b"tok").digest()).decode()
        self.assertEqual(callers.hashed_token("tok"), want)

    def test_the_query_holds_the_hash_and_never_the_token(self):
        seen = []

        def fake_request(url, headers=None, **kw):
            seen.append(url)
            return 200, {}, b"[]"
        with mock.patch.object(callers, "_request", fake_request):
            callers.github_calls("secret-token-value", org="acme")
        self.assertNotIn("secret-token-value", seen[0])
        self.assertIn("hashed_token", seen[0])

    def test_no_org_is_a_gap(self):
        calls, cov = callers.github_calls("tok")
        self.assertEqual((calls, cov.level), ([], Coverage.NONE))

    def test_no_enterprise_audit_log_is_a_gap(self):
        with mock.patch.object(callers, "_request",
                               lambda *a, **k: (404, {}, b"")):
            calls, cov = callers.github_calls("tok", org="acme")
        self.assertEqual((calls, cov.level), ([], Coverage.NONE))

    def test_says_when_addresses_are_hidden(self):
        body = json.dumps([{"action": "git.clone", "@timestamp": 1790000000000,
                            "user_agent": "git/2.4"}]).encode()
        with mock.patch.object(callers, "_request",
                               lambda *a, **k: (200, {}, body)):
            calls, cov = callers.github_calls("tok", org="acme")
        self.assertEqual(calls[0].action, "git.clone")
        self.assertIn("IP disclosure", cov.note)


class Labels(unittest.TestCase):

    def test_without_mine_nobody_is_called_foreign(self):
        self.assertEqual(callers.label("203.0.113.9", []), callers.UNLABELLED)

    def test_inside_and_outside_your_ranges(self):
        mine = callers.parse_mine(["198.51.100.0/24", "2001:db8::1"])
        self.assertEqual(callers.label("198.51.100.7", mine), callers.MINE)
        self.assertEqual(callers.label("2001:db8::1", mine), callers.MINE)
        self.assertEqual(callers.label("203.0.113.9", mine), callers.OTHER)

    def test_an_aws_service_is_not_a_stranger(self):
        mine = callers.parse_mine(["198.51.100.0/24"])
        self.assertEqual(callers.label("lambda.amazonaws.com", mine),
                         callers.SERVICE)

    def test_comma_separated_and_bad_values(self):
        self.assertEqual(len(callers.parse_mine(["10.0.0.1, 10.0.1.0/24"])), 2)
        with self.assertRaises(ValueError):
            callers.parse_mine(["not-an-address"])


class Grouping(unittest.TestCase):

    def calls(self):
        t = callers._when
        return [
            callers.Call(t("2026-10-01T00:00:00Z"), "198.51.100.7", "cli", "s3:List"),
            callers.Call(t("2026-10-03T00:00:00Z"), "198.51.100.7", "cli", "s3:List"),
            callers.Call(t("2026-10-02T00:00:00Z"), "203.0.113.9", "curl",
                         "iam:CreateUser", error="AccessDenied"),
        ]

    def test_strangers_first_with_counts_and_dates(self):
        mine = callers.parse_mine(["198.51.100.0/24"])
        groups = callers.group(self.calls(), mine)
        self.assertEqual([g["label"] for g in groups],
                         [callers.OTHER, callers.MINE])
        self.assertEqual(groups[0]["errors"], 1)
        self.assertEqual((groups[1]["calls"], groups[1]["first"][:10],
                          groups[1]["last"][:10]), (2, "2026-10-01", "2026-10-03"))

    def test_report_counts_the_callers_not_on_your_list(self):
        mine = callers.parse_mine(["198.51.100.0/24"])
        cov = Coverage("aws", Coverage.WRITES_ONLY, "note", 90)
        r = callers.report({"aws": (self.calls(), cov)}, mine=mine)
        self.assertEqual(r["providers"][0]["not_on_your_list"], 1)
        self.assertEqual(r["mine"], ["198.51.100.0/24"])


class Render(unittest.TestCase):

    def test_an_empty_log_is_not_called_clean_beyond_what_it_covers(self):
        cov = Coverage("aws", Coverage.WRITES_ONLY, "From CloudTrail.", 90)
        text = callers.render(callers.report({"aws": ([], cov)}))
        self.assertIn("covers what the log below records", " ".join(text.split()))

    def test_a_gap_says_where_to_look_instead(self):
        r = callers.report({}, gaps={"stripe": callers.ELSEWHERE["stripe"]})
        self.assertIn("Dashboard", callers.render(r))

    def test_the_key_is_shown_by_its_ends(self):
        self.assertEqual(callers.hint(KEY), "AKIA...MPLE")


class Cli(unittest.TestCase):

    def run_cli(self, argv, env=None):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.dict("os.environ", env or {}, clear=False), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                code = cli._main(argv)
            except SystemExit as e:
                code = e.code
        return code, out.getvalue(), err.getvalue()

    def test_nothing_to_look_up_exits_2_and_says_how(self):
        with mock.patch.object(cli.shutil, "which", lambda name: None):
            code, _, err = self.run_cli(["callers"],
                                        env={"RANWHAT_GITHUB_TOKEN": ""})
        self.assertEqual(code, 2)
        self.assertIn("--aws-key-id", err)

    def test_flags_are_only_for_callers(self):
        for flag in (["--mine", "10.0.0.1"], ["--aws-key-id", KEY],
                     ["--aws-region", "eu-west-1"]):
            code, _, err = self.run_cli(["watch"] + flag)
            self.assertEqual(code, 2, flag)
            self.assertIn("only for callers", err)

    def test_json_report_for_a_key(self):
        reply = trail(("e1", "203.0.113.9", "curl/8", "iam.amazonaws.com",
                       "CreateUser", None))
        with mock.patch.object(cli.shutil, "which", lambda name: "/bin/aws"), \
                mock.patch.object(callers, "_aws", lambda *a, **k: reply):
            code, out, _ = self.run_cli(
                ["callers", "--aws-key-id", KEY, "--mine", "198.51.100.0/24",
                 "--json"], env={"RANWHAT_GITHUB_TOKEN": ""})
        self.assertEqual(code, 0)
        result = json.loads(out)
        self.assertEqual(result["providers"][0]["not_on_your_list"], 1)

    def test_a_bad_range_is_a_usage_error(self):
        code, _, err = self.run_cli(["callers", "--mine", "nope"])
        self.assertEqual(code, 2)
        self.assertIn("--mine", err)


if __name__ == "__main__":
    unittest.main()
