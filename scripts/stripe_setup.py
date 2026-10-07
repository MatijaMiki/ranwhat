"""Set up ranwhat Plus in Stripe: the product, its two prices, the webhook
the Worker listens on, and the customer portal subscribers manage billing in.

    python3 scripts/stripe_setup.py

It asks for a Stripe secret key and sends it to api.stripe.com and nowhere
else. Run it once with a test key (sk_test_...) and, when checkout works in
test mode, once with the live key: Stripe keeps the two modes apart, so each
needs its own product, prices, webhook and portal.

Safe to run again: it finds what is there by its fixed id, lookup key, URL
or metadata, and only makes what is missing. It never changes a price that
exists (a price's amount cannot be changed in Stripe), and says so when one
differs from what is below.

What it makes, and what worker/src/stripe.js expects to find:
  product   id ranwhat_plus, tax code SaaS for business use
  prices    EUR 12 a month (lookup key ranwhat_plus_monthly) and
            EUR 120 a year (ranwhat_plus_annual), tax-inclusive
  webhook   https://ranwhat.com/api/stripe, for the events in EVENTS
  portal    change plan, card, billing details; invoices; cancel at the end
            of the period; with Stripe's hosted login page switched on
Everything carries metadata product=ranwhat-plus.
"""
import getpass
import json
import os
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

API = os.environ.get("STRIPE_API_BASE", "https://api.stripe.com")
PRODUCT_ID = "ranwhat_plus"
# Software as a service, business use: what Stripe Tax and Managed Payments
# tax it as. Managed Payments refuses a product without an eligible code, and
# the business/personal split only matters for sales in the US.
TAX_CODE = "txcd_10103001"
TAG = {"product": "ranwhat-plus"}
ORIGIN = "https://ranwhat.com"
WEBHOOK = ORIGIN + "/api/stripe"
PRICES = [
    # lookup key, cents, interval, nickname
    ("ranwhat_plus_monthly", 1200, "month", "Plus, monthly"),
    ("ranwhat_plus_annual", 12000, "year", "Plus, yearly"),
]
EVENTS = [
    "checkout.session.completed",
    "checkout.session.async_payment_succeeded",
    "customer.subscription.created",
    "customer.subscription.updated",
    "customer.subscription.deleted",
    "customer.subscription.paused",
    "customer.subscription.resumed",
]


class StripeError(Exception):
    def __init__(self, status, error):
        self.status = status
        self.error = error
        super().__init__("Stripe %s: %s" % (status, error.get("message") or error.get("code") or error))


def encode(params, prefix="", out=None):
    """Stripe's form encoding: nested keys in brackets, a[b][0]=c."""
    out = [] if out is None else out
    items = enumerate(params) if isinstance(params, list) else params.items()
    for k, v in items:
        key = "%s[%s]" % (prefix, k) if prefix else str(k)
        if isinstance(v, (dict, list)):
            encode(v, key, out)
        elif isinstance(v, bool):
            out.append((key, "true" if v else "false"))
        elif v is not None:
            out.append((key, str(v)))
    return out


class Stripe:
    def __init__(self, key):
        self.key = key

    def __call__(self, method, path, params=None):
        form = urllib.parse.urlencode(encode(params or {}))
        url = API + path + ("?" + form if method == "GET" and form else "")
        req = urllib.request.Request(url, method=method,
                                     data=form.encode() if method != "GET" else None)
        req.add_header("Authorization", "Bearer " + self.key)
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
        try:
            with urllib.request.urlopen(req, timeout=30) as res:
                return json.load(res)
        except urllib.error.HTTPError as exc:
            try:
                error = json.load(exc).get("error", {})
            except ValueError:
                error = {}
            raise StripeError(exc.code, error) from None


def product(stripe):
    try:
        found = stripe("GET", "/v1/products/" + PRODUCT_ID)
    except StripeError as exc:
        if exc.status != 404:
            raise
        found = None
    if found:
        if found.get("tax_code") != TAX_CODE:
            stripe("POST", "/v1/products/" + PRODUCT_ID, {"tax_code": TAX_CODE})
            print("  product   %s (already there; tax code set to %s)" % (found["id"], TAX_CODE))
        else:
            print("  product   %s (already there)" % found["id"])
        return found["id"]
    made = stripe("POST", "/v1/products", {
        "id": PRODUCT_ID,
        "name": "ranwhat Plus",
        "description": "The current capability catalogue for ranwhat, as providers add scopes.",
        "tax_code": TAX_CODE,
        "metadata": TAG,
    })
    print("  product   %s (made)" % made["id"])
    return made["id"]


def prices(stripe, product_id):
    ids = []
    for key, cents, interval, nickname in PRICES:
        found = stripe("GET", "/v1/prices", {"lookup_keys": [key], "active": True}).get("data", [])
        if found:
            price = found[0]
            recurring = price.get("recurring") or {}
            if (price.get("unit_amount"), price.get("currency"), recurring.get("interval")) != (cents, "eur", interval):
                print("  price     %s is %s %s a %s, not EUR %s a %s. Left as it is: make a new"
                      % (key, price.get("unit_amount"), price.get("currency"), recurring.get("interval"),
                         cents // 100, interval))
                print("            price in the dashboard with lookup key %s, and tick" % key)
                print("            \"transfer lookup key\", to change it.")
            else:
                print("  price     %s, EUR %d a %s (already there)" % (key, cents // 100, interval))
            ids.append(price["id"])
            continue
        made = stripe("POST", "/v1/prices", {
            "product": product_id,
            "currency": "eur",
            "unit_amount": cents,
            "recurring": {"interval": interval},
            "lookup_key": key,
            "nickname": nickname,
            "tax_behavior": "inclusive",
            "metadata": TAG,
        })
        print("  price     %s, EUR %d a %s (made)" % (key, cents // 100, interval))
        ids.append(made["id"])
    return ids


def webhook(stripe):
    """The endpoint's signing secret, when it was made just now; else None."""
    endpoints = stripe("GET", "/v1/webhook_endpoints", {"limit": 100}).get("data", [])
    found = next((w for w in endpoints if w.get("url") == WEBHOOK), None)
    if found:
        stripe("POST", "/v1/webhook_endpoints/" + found["id"], {"enabled_events": EVENTS, "disabled": False})
        print("  webhook   %s (already there; its events brought up to date)" % WEBHOOK)
        return None
    made = stripe("POST", "/v1/webhook_endpoints", {
        "url": WEBHOOK,
        "enabled_events": EVENTS,
        "description": "ranwhat Plus: tokens for the feed (worker/src/stripe.js)",
        "metadata": TAG,
    })
    print("  webhook   %s (made)" % WEBHOOK)
    return made.get("secret")


def portal(stripe, product_id, price_ids):
    settings = {
        "business_profile": {
            "headline": "ranwhat Plus",
            "privacy_policy_url": ORIGIN + "/privacy",
            "terms_of_service_url": ORIGIN + "/terms",
        },
        "default_return_url": ORIGIN + "/",
        "features": {
            "customer_update": {"enabled": True, "allowed_updates": ["email", "name", "address", "tax_id"]},
            "invoice_history": {"enabled": True},
            "payment_method_update": {"enabled": True},
            "subscription_cancel": {"enabled": True, "mode": "at_period_end"},
            "subscription_update": {
                "enabled": True,
                "default_allowed_updates": ["price"],
                "products": [{"product": product_id, "prices": price_ids}],
                "proration_behavior": "create_prorations",
            },
        },
        "login_page": {"enabled": True},
        "metadata": TAG,
    }
    configs = stripe("GET", "/v1/billing_portal/configurations", {"limit": 100}).get("data", [])
    found = next((c for c in configs if (c.get("metadata") or {}).get("product") == TAG["product"]), None)
    if found:
        settings["active"] = True
        done = stripe("POST", "/v1/billing_portal/configurations/" + found["id"], settings)
        print("  portal    %s (already there; brought up to date)" % done["id"])
    else:
        done = stripe("POST", "/v1/billing_portal/configurations", settings)
        print("  portal    %s (made)" % done["id"])
    return (done.get("login_page") or {}).get("url")


def main(key):
    if not key.startswith(("sk_test_", "sk_live_", "rk_test_", "rk_live_")):
        sys.exit("That is not a Stripe secret key (sk_test_... or sk_live_...).")
    live = "_live_" in key
    print("\nSetting up ranwhat Plus in Stripe, %s mode:\n" % ("LIVE" if live else "test"))
    stripe = Stripe(key)
    product_id = product(stripe)
    price_ids = prices(stripe, product_id)
    secret = webhook(stripe)
    login = portal(stripe, product_id, price_ids)

    print("\nDone. In Cloudflare: Workers & Pages > ranwhat-contact > Settings >")
    print("Variables and Secrets, add two of type Secret:\n")
    print("  STRIPE_SECRET_KEY      the %s secret key (or a restricted key with" % ("live" if live else "test"))
    print("                         Checkout Sessions, Customers and Customer portal:")
    print("                         Write, and Prices and Subscriptions: Read. The account")
    print("                         page makes each organisation a Stripe customer, reads")
    print("                         customers to attach a subscription, and makes portal")
    print("                         sessions; Write includes Read)")
    if secret:
        print("  STRIPE_WEBHOOK_SECRET  %s" % secret)
        print("\n  Stripe shows that signing secret once, here. Add it now.")
    else:
        print("  STRIPE_WEBHOOK_SECRET  the webhook's signing secret: Stripe dashboard >")
        print("                         Developers > Webhooks > %s > Reveal" % WEBHOOK)
    if login:
        print("\nSubscribers manage billing at %s/api/billing, which" % ORIGIN)
        print("sends them to %s" % login)
    if not live:
        print("\nTest it on ranwhat.com/pricing with the card 4242 4242 4242 4242, any future")
        print("date and any CVC. Then run this again with the live key, and swap both secrets.")
    return 0


if __name__ == "__main__":
    key = os.environ.get("STRIPE_SECRET_KEY") or getpass.getpass("Stripe secret key (input hidden): ")
    try:
        sys.exit(main(key.strip()))
    except StripeError as exc:
        sys.exit("\n%s\nNothing after that step was made. Fix it and run this again." % exc)
    except urllib.error.URLError as exc:
        if isinstance(exc.reason, ssl.SSLCertVerificationError):
            sys.exit("\nPython could not check api.stripe.com's certificate. With Python from"
                     "\npython.org on a Mac, run its Install Certificates.command once"
                     "\n(in /Applications/Python 3.x/), then run this again.")
        sys.exit("\nCould not reach Stripe: %s" % exc.reason)
