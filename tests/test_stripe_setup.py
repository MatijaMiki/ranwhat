"""scripts/stripe_setup.py against a stand-in for Stripe's API, and the
script and the Worker agreeing on what one makes and the other looks for.

worker/test/stripe.test.mjs covers the Worker's side: checkout, the
webhook, the welcome page and the feed switching off with the subscription.
"""
import contextlib
import http.server
import importlib.util
import io
import json
import os
import pathlib
import re
import threading
import unittest
import urllib.parse
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parent.parent
WORKER = (ROOT / "worker" / "src" / "stripe.js").read_text(encoding="utf-8")


def _script():
    spec = importlib.util.spec_from_file_location("stripe_setup", ROOT / "scripts" / "stripe_setup.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FakeStripe(http.server.BaseHTTPRequestHandler):
    """Products, prices, webhook endpoints and portal configurations, kept in
    memory; every call recorded."""
    state = None

    def log_message(self, *args):
        pass

    def _reply(self, status, body):
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _handle(self, method):
        s = self.state
        url = urllib.parse.urlsplit(self.path)
        if method == "GET":
            pairs = urllib.parse.parse_qsl(url.query)
        else:
            pairs = urllib.parse.parse_qsl(self.rfile.read(int(self.headers["Content-Length"] or 0)).decode())
        s["calls"].append({"method": method, "path": url.path, "params": pairs})
        if self.headers["Authorization"] != "Bearer sk_test_key":
            return self._reply(401, {"error": {"type": "invalid_request_error", "message": "Invalid API Key"}})
        form = dict(pairs)
        lists = lambda prefix: [v for k, v in pairs if re.fullmatch(re.escape(prefix) + r"\[\d+\]", k)]
        path = url.path

        if method == "GET" and path.startswith("/v1/products/"):
            pid = path.rsplit("/", 1)[1]
            if pid in s["products"]:
                return self._reply(200, s["products"][pid])
            return self._reply(404, {"error": {"type": "invalid_request_error", "code": "resource_missing"}})
        if method == "POST" and path == "/v1/products":
            s["products"][form["id"]] = {"id": form["id"], "name": form["name"]}
            return self._reply(200, s["products"][form["id"]])
        if method == "GET" and path == "/v1/prices":
            keys = lists("lookup_keys")
            return self._reply(200, {"data": [p for p in s["prices"] if p["lookup_key"] in keys and p["active"]]})
        if method == "POST" and path == "/v1/prices":
            price = {"id": "price_%d" % len(s["prices"]), "lookup_key": form["lookup_key"], "active": True,
                     "unit_amount": int(form["unit_amount"]), "currency": form["currency"],
                     "recurring": {"interval": form["recurring[interval]"]}, "product": form["product"],
                     "tax_behavior": form["tax_behavior"]}
            s["prices"].append(price)
            return self._reply(200, price)
        if method == "GET" and path == "/v1/webhook_endpoints":
            return self._reply(200, {"data": s["webhooks"]})
        if method == "POST" and path == "/v1/webhook_endpoints":
            hook = {"id": "we_%d" % len(s["webhooks"]), "url": form["url"], "enabled_events": lists("enabled_events"),
                    "secret": "whsec_made_%d" % len(s["webhooks"])}
            s["webhooks"].append(hook)
            return self._reply(200, hook)
        if method == "POST" and path.startswith("/v1/webhook_endpoints/"):
            hook = next(w for w in s["webhooks"] if w["id"] == path.rsplit("/", 1)[1])
            hook["enabled_events"] = lists("enabled_events")
            return self._reply(200, {k: v for k, v in hook.items() if k != "secret"})
        if method == "GET" and path == "/v1/billing_portal/configurations":
            return self._reply(200, {"data": s["portals"]})
        if method == "POST" and path.startswith("/v1/billing_portal/configurations"):
            if path.endswith("/configurations"):
                cfg = {"id": "bpc_%d" % len(s["portals"])}
                s["portals"].append(cfg)
            else:
                cfg = next(c for c in s["portals"] if c["id"] == path.rsplit("/", 1)[1])
            cfg["metadata"] = {"product": form.get("metadata[product]")}
            cfg["form"] = form
            cfg["login_page"] = {"enabled": form.get("login_page[enabled]") == "true",
                                 "url": "https://billing.stripe.com/p/login/test_%s" % cfg["id"]}
            return self._reply(200, cfg)
        return self._reply(404, {"error": {"type": "invalid_request_error", "message": "no such route"}})

    def do_GET(self):
        self._handle("GET")

    def do_POST(self):
        self._handle("POST")


class SetupScript(unittest.TestCase):

    def setUp(self):
        FakeStripe.state = {"calls": [], "products": {}, "prices": [], "webhooks": [], "portals": []}
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), FakeStripe)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        env = {"STRIPE_API_BASE": "http://127.0.0.1:%d" % self.server.server_port,
               "NO_PROXY": "127.0.0.1", "no_proxy": "127.0.0.1"}
        patcher = mock.patch.dict(os.environ, env)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.tool = _script()

    def tearDown(self):
        # STRIPE_CALLS=<file>: every call, for checking against Stripe's OpenAPI spec.
        out = os.environ.get("STRIPE_CALLS")
        if out:
            kept = json.loads(pathlib.Path(out).read_text(encoding="utf-8")) if os.path.exists(out) else []
            with open(out, "w", encoding="utf-8") as fh:
                json.dump(kept + FakeStripe.state["calls"], fh)

    def run_tool(self, key="sk_test_key"):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(self.tool.main(key), 0)
        return out.getvalue()

    def test_a_first_run_makes_everything_the_worker_looks_for(self):
        out = self.run_tool()
        s = FakeStripe.state
        self.assertEqual(list(s["products"]), ["ranwhat_plus"])
        self.assertEqual(sorted((p["lookup_key"], p["unit_amount"], p["currency"], p["recurring"]["interval"])
                                for p in s["prices"]),
                         [("ranwhat_plus_annual", 12000, "eur", "year"),
                          ("ranwhat_plus_monthly", 1200, "eur", "month")])
        self.assertTrue(all(p["product"] == "ranwhat_plus" for p in s["prices"]))
        [hook] = s["webhooks"]
        self.assertEqual(hook["url"], "https://ranwhat.com/api/stripe")
        self.assertIn("whsec_made_0", out, "the signing secret is shown the one time Stripe gives it")
        [cfg] = s["portals"]
        self.assertEqual(cfg["metadata"], {"product": "ranwhat-plus"})
        self.assertEqual(cfg["form"]["login_page[enabled]"], "true")
        self.assertEqual(cfg["form"]["features[subscription_cancel][mode]"], "at_period_end")
        self.assertEqual(sorted(v for k, v in cfg["form"].items()
                                if k.startswith("features[subscription_update][products][0][prices]")),
                         sorted(p["id"] for p in s["prices"]))
        self.assertIn(cfg["login_page"]["url"], out)
        self.assertIn("4242 4242 4242 4242", out)

    def test_a_second_run_makes_nothing_new_and_shows_no_secret(self):
        self.run_tool()
        out = self.run_tool()
        s = FakeStripe.state
        self.assertEqual((len(s["products"]), len(s["prices"]), len(s["webhooks"]), len(s["portals"])), (1, 2, 1, 1))
        self.assertNotIn("whsec_", out)
        self.assertIn("Reveal", out)
        made = [c for c in s["calls"][len(s["calls"]) // 2:] if c["method"] == "POST"
                and c["path"] in ("/v1/products", "/v1/prices", "/v1/webhook_endpoints")]
        self.assertEqual(made, [])

    def test_a_price_that_differs_is_reported_and_left_alone(self):
        FakeStripe.state["prices"].append({"id": "price_old", "lookup_key": "ranwhat_plus_monthly", "active": True,
                                           "unit_amount": 900, "currency": "eur",
                                           "recurring": {"interval": "month"}})
        out = self.run_tool()
        self.assertIn("ranwhat_plus_monthly is 900 eur a month, not EUR 12 a month", out)
        self.assertEqual(sum(p["lookup_key"] == "ranwhat_plus_monthly" for p in FakeStripe.state["prices"]), 1)

    def test_only_a_stripe_secret_key_is_accepted_and_errors_stop_it(self):
        with self.assertRaises(SystemExit):
            self.tool.main("pk_test_publishable")
        with contextlib.redirect_stdout(io.StringIO()), self.assertRaises(self.tool.StripeError) as caught:
            self.tool.main("sk_test_wrong")
        self.assertEqual(caught.exception.status, 401)
        self.assertEqual(FakeStripe.state["products"], {})


class ScriptAndWorkerAgree(unittest.TestCase):

    def setUp(self):
        self.tool = _script()

    def test_lookup_keys_and_the_product_tag(self):
        plans = re.search(r"export const PLANS = (\{[^}]+\});", WORKER).group(1)
        self.assertEqual(sorted(re.findall(r'"(ranwhat_plus_\w+)"', plans)),
                         sorted(key for key, *_ in self.tool.PRICES))
        self.assertIn('export const PRODUCT = "%s";' % self.tool.TAG["product"], WORKER)

    def test_the_webhook_url_is_a_route_the_worker_answers(self):
        index = (ROOT / "worker" / "src" / "index.js").read_text(encoding="utf-8")
        self.assertEqual(self.tool.WEBHOOK, "https://ranwhat.com/api/stripe")
        self.assertIn('"/api/stripe": [webhook, ["POST"]]', index)

    def test_every_event_it_asks_for_is_one_the_worker_handles(self):
        for event in self.tool.EVENTS:
            handled = ('type === "%s"' % event) in WORKER or (
                event.startswith("customer.subscription.") and 'type.startsWith("customer.subscription.")' in WORKER)
            self.assertTrue(handled, event)

    def test_the_prices_are_the_ones_on_the_pricing_page(self):
        page = (ROOT / "site" / "pricing.html").read_text(encoding="utf-8")
        cents = {key: c for key, c, *_ in self.tool.PRICES}
        self.assertIn("&euro;%d" % (cents["ranwhat_plus_monthly"] // 100), page)
        self.assertIn("&euro;%d" % (cents["ranwhat_plus_annual"] // 1200), page)
        self.assertIn("&euro;%d" % (cents["ranwhat_plus_annual"] // 100), page)


if __name__ == "__main__":
    unittest.main()
