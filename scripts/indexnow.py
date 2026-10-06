"""Tell Bing and the other IndexNow engines which pages changed.

    python3 scripts/indexnow.py                  # list every sitemap URL, send nothing
    python3 scripts/indexnow.py --changed REV    # list only pages changed since REV
    python3 scripts/indexnow.py --send [...]     # submit them

Bing Webmaster Tools only knew the four URLs pasted into it by hand on 27
September; the sitemap lists every page, and a crawler reads it when it gets
round to it. IndexNow is the push side: one POST names the URLs, and Bing,
Yandex, Seznam, Naver and Yep share what each of them is told. Google does
not take part, and reads the sitemap.

The key is public by design. It sits at https://ranwhat.com/<key>.txt and
proves the request comes from whoever controls the site; it grants nothing
else. A submission is refused until the live key file says the same as the
local one, so a run before the deploy reaches ranwhat.com fails here with a
reason rather than at the engine with a 403.

Only URLs in site/sitemap.xml are ever sent: a page left out of the sitemap
is left out on purpose. Standard library only, like the rest of the repo.
"""
import argparse
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SITE = os.path.join(ROOT, "site")
SITEMAP = os.path.join(SITE, "sitemap.xml")
HOST = "ranwhat.com"
ORIGIN = "https://" + HOST
ENDPOINT = "https://api.indexnow.org/indexnow"
USER_AGENT = "ranwhat-indexnow (+https://ranwhat.com)"

# IndexNow's own rule for a key: 8 to 128 of these characters.
KEY_FILE = re.compile(r"^([A-Za-z0-9-]{8,128})\.txt$")
LOC = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>")

# What each answer from the endpoint means, from indexnow.org/documentation.
STATUS = {
    200: "accepted",
    202: "accepted; the key is still being validated",
    400: "bad request: the payload is malformed",
    403: "key not valid: the key file is missing or does not match",
    422: "URLs do not belong to the host, or the key does not match the schema",
    429: "too many requests: wait before sending again",
}


class IndexNowError(Exception):
    pass


def key():
    """The one key file at the top of site/. Two would leave which one the
    engines trust to whichever they fetched first."""
    found = [m.group(1) for m in map(KEY_FILE.match, sorted(os.listdir(SITE))) if m
             and _read(os.path.join(SITE, m.group(0))).strip() == m.group(1)]
    if len(found) != 1:
        raise IndexNowError("expected one IndexNow key file in site/, found %d" % len(found))
    return found[0]


def _read(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def sitemap_urls(text=None):
    return LOC.findall(_read(SITEMAP) if text is None else text)


def url_for(path):
    """The canonical URL of a page file under site/, or None for anything that
    is not a page. Pages are served without .html, and index.html is /."""
    rel = os.path.relpath(os.path.join(ROOT, path), SITE).replace(os.sep, "/")
    if rel.startswith("../") or not rel.endswith(".html"):
        return None
    rel = rel[:-len(".html")]
    if rel == "index":
        return ORIGIN + "/"
    if rel.endswith("/index"):
        rel = rel[:-len("index")]
    return ORIGIN + "/" + rel


def changed_since(rev):
    out = subprocess.run(["git", "diff", "--name-only", rev, "--", "site"], cwd=ROOT,
                         check=True, capture_output=True, text=True).stdout
    return {u for u in map(url_for, out.split()) if u}


def payload(urls, k):
    return {"host": HOST, "key": k, "keyLocation": "%s/%s.txt" % (ORIGIN, k), "urlList": urls}


def _request(url, data=None):
    headers = {"User-Agent": USER_AGENT}
    if data is not None:
        headers["Content-Type"] = "application/json; charset=utf-8"
    return urllib.request.Request(url, data=data, headers=headers)


def check_live_key(k, opener=urllib.request.urlopen):
    location = "%s/%s.txt" % (ORIGIN, k)
    try:
        with opener(_request(location), timeout=20) as resp:
            live = resp.read().decode("utf-8", "replace").strip()
    except urllib.error.HTTPError as e:
        raise IndexNowError("%s answered %d; deploy the key file before sending" % (location, e.code))
    except urllib.error.URLError as e:
        raise IndexNowError("could not fetch %s: %s" % (location, e.reason))
    if live != k:
        raise IndexNowError("%s does not hold the local key; deploy before sending" % location)


def send(urls, k, opener=urllib.request.urlopen):
    check_live_key(k, opener)
    body = json.dumps(payload(urls, k)).encode("utf-8")
    try:
        with opener(_request(ENDPOINT, body), timeout=30) as resp:
            code = resp.status
    except urllib.error.HTTPError as e:
        code = e.code
    except urllib.error.URLError as e:
        raise IndexNowError("could not reach %s: %s" % (ENDPOINT, e.reason))
    if code not in (200, 202):
        raise IndexNowError("IndexNow answered %d: %s" % (code, STATUS.get(code, "unexpected")))
    return code


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--changed", metavar="REV",
                    help="only pages whose files changed since this git revision")
    ap.add_argument("--send", action="store_true", help="submit; without it nothing is sent")
    args = ap.parse_args(argv)

    try:
        k = key()
        urls = sitemap_urls()
        if args.changed:
            changed = changed_since(args.changed)
            urls = [u for u in urls if u in changed]
        if not urls:
            print("No sitemap pages to submit.")
            return 0
        for u in urls:
            print(u)
        if not args.send:
            print("\n%d URLs. Nothing sent; add --send to submit them." % len(urls))
            return 0
        code = send(urls, k)
    except (IndexNowError, subprocess.CalledProcessError) as e:
        print("indexnow: %s" % e, file=sys.stderr)
        return 1
    print("\n%d URLs submitted: %s." % (len(urls), STATUS[code]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
