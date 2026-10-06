"""Directory badges: each snippet on the home page exactly as its directory
gave it, its image host allowed by the CSP, and named on the privacy page.

Two have failed on the live site already. MarketingDB's checker found no link
while our <a> carried a class before href, and Maidensail's would not confirm
a byte-identical copy of its image served from ranwhat.com. A listing comes
down when its check fails, so a snippet here is data, never markup to tidy.

To add one: pbpaste | python3 scripts/badges.py add "Name"
"""
import contextlib
import hashlib
import importlib.util
import io
import pathlib
import re
import shutil
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
SITE = ROOT / "site"

# What img-src allows besides the badges: the site itself, data: URIs, and
# the X pixel and Google Analytics, which load only after consent. A host in
# img-src that is in neither this set nor badges.json was most likely left
# behind by a badge removed by hand; one that belongs to something else goes
# here.
NOT_BADGES = {"'self'", "data:", "https://t.co", "https://analytics.twitter.com",
              "https://ads-twitter.com", "https://*.google-analytics.com",
              "https://*.googletagmanager.com"}


def _tool():
    spec = importlib.util.spec_from_file_location("badges", ROOT / "scripts" / "badges.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def read(path):
    # read_text turns a Windows checkout's CRLF into LF, as the tool does.
    return pathlib.Path(path).read_text(encoding="utf-8")


class DirectoryBadges(unittest.TestCase):
    """The repository as it stands."""

    @classmethod
    def setUpClass(cls):
        cls.tool = _tool()
        cls.files = cls.tool.Files(ROOT)
        cls.badges = cls.tool.load(cls.files)

    def test_there_are_badges_and_each_is_listed_once(self):
        self.assertTrue(self.badges)
        names = [b["name"].casefold() for b in self.badges]
        self.assertEqual(len(names), len(set(names)), "a directory listed twice")
        snippets = [b["snippet"] for b in self.badges]
        self.assertEqual(len(snippets), len(set(snippets)), "a snippet listed twice")

    def test_each_snippet_is_the_one_its_directory_gave(self):
        for b in self.badges:
            with self.subTest(badge=b["name"]):
                self.assertEqual(hashlib.sha256(b["snippet"].encode("utf-8")).hexdigest(),
                                 b["sha256"], "edited after it was added; re-add it instead")
                self.assertEqual(self.tool.validate(b["snippet"]), [])

    def test_each_badge_was_checked_for_cookies(self):
        # The privacy page says so of every badge. add stamps the date when
        # it fetched the image and saw no cookie; add --offline leaves it to
        # check.
        for b in self.badges:
            with self.subTest(badge=b["name"]):
                self.assertRegex(b.get("checked", ""), r"^\d{4}-\d{2}-\d{2}$",
                                 "run python3 scripts/badges.py check")

    def test_the_home_page_carries_what_badges_json_says(self):
        index = read(self.files.index)
        indent = self.tool.marker_indent(index, self.tool.INDEX_MARKS)
        self.assertEqual(self.tool.region(index, self.tool.INDEX_MARKS),
                         self.tool.render_index(self.badges, indent),
                         "run python3 scripts/badges.py sync")

    def test_each_snippet_is_on_the_home_page_once_byte_for_byte(self):
        index = read(self.files.index)
        block = self.tool.region(index, self.tool.INDEX_MARKS)
        for b in self.badges:
            with self.subTest(badge=b["name"]):
                # Once on the whole page, and that once inside the block: no
                # stale copy elsewhere, as when they sat beside the Follow
                # heading, and nothing added to the tags.
                # A self-hosted badge differs from its snippet only in the
                # image src, which served() swaps for the copy kept here.
                shown = self.tool.served(b)
                self.assertEqual(index.count(shown), 1)
                self.assertIn(">%s</li>" % shown, block)

    def test_a_self_hosted_image_is_the_file_that_was_checked(self):
        self.assertEqual(self.tool.local_problems(self.files, self.badges), [])

    def test_every_badge_image_host_is_allowed_by_img_src(self):
        img = self.tool.img_src(self.tool.csp_line(read(self.files.headers)))
        for b in self.badges:
            for host in self.tool.hosts(b):
                with self.subTest(badge=b["name"], host=host):
                    self.assertIn(host, img)

    def test_img_src_allows_no_host_that_no_badge_uses(self):
        img = set(self.tool.img_src(self.tool.csp_line(read(self.files.headers))))
        left = img - set(self.tool.all_hosts(self.badges)) - NOT_BADGES
        self.assertEqual(left, set(), "img-src hosts that no badge uses; a removed "
                         "badge should take its host with it (badges.py remove)")

    def test_the_csp_line_stays_under_cloudflares_limit(self):
        # Pages skips a _headers line over 2,000 characters with a build-log
        # warning, and the site would ship with no CSP. At about 26
        # characters a host, that leaves room for roughly forty more badges.
        line = self.tool.csp_line(read(self.files.headers))
        self.assertLessEqual(len(line), self.tool.CSP_LINE_MAX)

    def test_the_privacy_page_names_every_directory_and_host(self):
        privacy = read(self.files.privacy)
        self.assertIn('id="badges"', privacy)
        listed = self.tool.region(privacy, self.tool.PRIVACY_MARKS)
        self.assertEqual(listed, self.tool.render_privacy(self.badges),
                         "run python3 scripts/badges.py sync")
        for b in self.badges:
            with self.subTest(badge=b["name"]):
                self.assertIn(b["name"], listed)
                for host in self.tool.hosts(b):
                    self.assertIn("(%s" % host.split("://", 1)[1], listed)

    def test_the_three_files_agree_with_badges_json(self):
        self.assertEqual(self.tool.drift(self.files, self.badges), [],
                         "run python3 scripts/badges.py sync")

    def test_the_section_says_where_the_badges_come_from(self):
        index = read(self.files.index)
        section = re.search(r'<section[^>]*id="listed">(.*?)</section>', index, re.S)
        self.assertIsNotNone(section, "the home page has lost its listed section")
        self.assertIn('href="/privacy#badges"', section.group(1))
        self.assertIn(self.tool.INDEX_MARKS[0], section.group(1))


class TheTool(unittest.TestCase):
    """add, remove and sync, run on a copy of the four files they touch."""

    EXAMPLE = ('<a href="https://example.dir/p/ranwhat" target="_blank">'
               '<img src="https://cdn.example.dir/badge.svg" alt="Listed on Example" '
               'width="200" height="50"></a>')

    def setUp(self):
        self.tool = _tool()
        # No network here: every image answers 200 with no cookie, and every
        # listing's link is up.
        self.tool.probe = lambda snippet: ([], [], [])
        self.tool._link_status = lambda snippet: ("https://example.dir/", 200)
        self.tmp = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, str(self.tmp), True)
        real = self.tool.Files(ROOT)
        self.files = self.tool.Files(self.tmp)
        for name in ("data", "index", "privacy", "headers"):
            dest = getattr(self.files, name)
            dest.parent.mkdir(parents=True, exist_ok=True)
            # Through read() so a CRLF checkout starts the copy as LF.
            dest.write_bytes(read(getattr(real, name)).encode("utf-8"))
        if (real.site / "badges").is_dir():
            shutil.copytree(str(real.site / "badges"), str(self.files.site / "badges"))
        self.before = self.snapshot()

    def snapshot(self):
        return {n: getattr(self.files, n).read_bytes()
                for n in ("data", "index", "privacy", "headers")}

    def run_tool(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            self.tool.main(list(argv), self.files)
        return out.getvalue()

    def add(self, name, snippet, *flags):
        path = self.tmp / "snippet.html"
        path.write_text(snippet + "\n", encoding="utf-8")
        return self.run_tool("add", name, "--file", str(path), *flags)

    def check(self):
        with self.assertRaises(SystemExit) as done:
            self.run_tool("check")
        return done.exception.code

    def test_sync_on_files_already_in_step_changes_nothing(self):
        badges = self.tool.load(self.files)
        self.assertEqual(self.tool.sync(self.files, badges), [])
        self.assertEqual(self.snapshot(), self.before)

    def test_add_writes_all_three_files_and_remove_undoes_it(self):
        self.add("Example", self.EXAMPLE)
        index, privacy = read(self.files.index), read(self.files.privacy)
        img = self.tool.img_src(self.tool.csp_line(read(self.files.headers)))
        # Exactly as given, first in the list, its host allowed and named.
        self.assertEqual(index.count(self.EXAMPLE), 1)
        block = self.tool.region(index, self.tool.INDEX_MARKS)
        self.assertLess(block.index(self.EXAMPLE), block.index("maidensail.com"))
        self.assertIn("https://cdn.example.dir", img)
        self.assertEqual(img[:2], ["'self'", "data:"])
        hosts = [t for t in img if t.startswith("https://") and "*" not in t][:3]
        self.assertEqual(hosts, sorted(hosts), "badge hosts stay sorted")
        self.assertIn("Example (cdn.example.dir)", privacy)
        self.assertEqual(self.tool.load(self.files)[0]["name"], "Example")
        self.assertEqual(self.tool.drift(self.files, self.tool.load(self.files)), [])

        self.run_tool("remove", "example")
        self.assertEqual(self.snapshot(), self.before)

    def test_adding_the_same_snippet_again_changes_nothing(self):
        self.add("Example", self.EXAMPLE)
        once = self.snapshot()
        self.add("Example", self.EXAMPLE)
        self.assertEqual(self.snapshot(), once)

    def test_a_listed_name_with_a_new_snippet_is_refused(self):
        self.add("Example", self.EXAMPLE)
        once = self.snapshot()
        with self.assertRaises(SystemExit):
            self.add("example", self.EXAMPLE.replace("badge.svg", "badge-2.svg"))
        self.assertEqual(self.snapshot(), once)

    def test_a_refused_snippet_writes_nothing(self):
        with self.assertRaises(SystemExit):
            self.add("Bad", '<script src="https://example.dir/widget.js"></script>')
        self.assertEqual(self.snapshot(), self.before)

    def test_an_add_stamps_the_check_it_made(self):
        self.add("Example", self.EXAMPLE)
        self.assertRegex(self.tool.load(self.files)[0]["checked"], r"^\d{4}-\d{2}-\d{2}$")

    def test_an_image_that_sets_a_cookie_is_not_added(self):
        self.tool.probe = lambda snippet: ([], [], ["it sets a cookie"])
        with self.assertRaises(SystemExit):
            self.add("Example", self.EXAMPLE)
        self.assertEqual(self.snapshot(), self.before)

    def test_an_offline_add_stays_off_the_page_until_check_passes(self):
        self.add("Example", self.EXAMPLE, "--offline")
        listed = self.tool.load(self.files)[0]
        self.assertEqual(listed["name"], "Example")
        self.assertNotIn("checked", listed)
        after = self.snapshot()
        for name in ("index", "privacy", "headers"):
            self.assertEqual(after[name], self.before[name], name)
        # Nothing writes the page while a badge is unchecked.
        with self.assertRaises(SystemExit):
            self.run_tool("sync")
        self.assertEqual(self.snapshot(), after)

        self.assertEqual(self.check(), 0)
        self.assertRegex(self.tool.load(self.files)[0]["checked"], r"^\d{4}-\d{2}-\d{2}$")
        self.assertEqual(read(self.files.index).count(self.EXAMPLE), 1)
        self.assertIn("Example (cdn.example.dir)", read(self.files.privacy))
        self.assertEqual(self.tool.drift(self.files, self.tool.load(self.files)), [])

    def test_check_does_not_stamp_an_image_that_fails(self):
        self.add("Example", self.EXAMPLE, "--offline")
        after = self.snapshot()
        self.tool.probe = lambda snippet: (
            ([], [], ["it sets a cookie"]) if "example.dir" in snippet else ([], [], []))
        self.assertEqual(self.check(), 1)
        self.assertEqual(self.snapshot(), after)

    def test_an_image_from_another_site_is_pointed_out(self):
        elsewhere = self.EXAMPLE.replace("https://cdn.example.dir/", "https://badges.example.net/")
        self.assertIn("note: the image comes from badges.example.net",
                      self.add("Example", elsewhere))
        self.assertNotIn("note:", self.add("Other", self.EXAMPLE))

    def test_end_puts_it_last(self):
        self.add("Example", self.EXAMPLE, "--end")
        self.assertEqual(self.tool.load(self.files)[-1]["name"], "Example")

    def test_past_twelve_the_rest_sit_behind_a_disclosure_still_in_the_html(self):
        many = [{"name": "Dir %d" % i, "snippet": self.EXAMPLE.replace(
            "example.dir/p/", "example.dir/p%d/" % i)} for i in range(14)]
        out = self.tool.render_index(many, "")
        open_part, _, closed = out.partition("<details")
        self.assertEqual(open_part.count("<li>"), self.tool.VISIBLE)
        self.assertIn('class="reveal listed-more"', "<details" + closed)
        self.assertIn("<summary>2 more listings</summary>", closed)
        self.assertEqual(closed.count("<li>"), 2)
        for b in many:
            self.assertEqual(out.count(b["snippet"]), 1)

    def test_the_privacy_sentence_agrees_with_the_count(self):
        one = [{"name": "Example", "snippet": self.EXAMPLE}]
        self.assertEqual(self.tool.render_privacy(one),
                         "The directory is Example (cdn.example.dir).")
        self.assertEqual(self.tool.render_privacy([]), "There are none at present.")


class TheValidator(unittest.TestCase):
    """Or the tests above pass for the wrong reason."""

    GOOD = TheTool.EXAMPLE

    def setUp(self):
        self.tool = _tool()

    def test_a_plain_badge_passes(self):
        self.assertEqual(self.tool.validate(self.GOOD), [])
        self.assertEqual(self.tool.hosts({"snippet": self.GOOD}), ["https://cdn.example.dir"])
        self.assertTrue(self.tool.followed(self.GOOD))

    def test_both_live_snippets_pass_as_given(self):
        # Maidensail's rel="dofollow" and MarketingDB's self-closing img are
        # theirs, and both stay.
        for b in self.tool.load(self.tool.Files(ROOT)):
            with self.subTest(badge=b["name"]):
                self.assertEqual(self.tool.validate(b["snippet"]), [])

    def test_what_would_break_the_page_or_the_privacy_page_is_refused(self):
        bad = {
            "script": self.GOOD + '<script src="https://example.dir/w.js"></script>',
            "handler": self.GOOD.replace("<img ", '<img onerror="x()" '),
            "javascript url": self.GOOD.replace("https://example.dir/p/ranwhat",
                                                "javascript:alert(1)"),
            "http image": self.GOOD.replace("https://cdn", "http://cdn"),
            "no alt": self.GOOD.replace(' alt="Listed on Example"', ""),
            "empty alt": self.GOOD.replace('alt="Listed on Example"', 'alt=""'),
            "em dash": self.GOOD.replace("Listed on", "Listed — on"),
            "comment": "<!-- badge -->" + self.GOOD,
            "iframe": '<iframe src="https://example.dir/embed"></iframe>',
            "two links": self.GOOD + self.GOOD,
            "image outside the link": ('<a href="https://example.dir/">Example</a>'
                                       '<img src="https://cdn.example.dir/b.svg" alt="x">'),
            "full referrer": self.GOOD.replace("<img ", '<img referrerpolicy="unsafe-url" '),
            "whitespace": self.GOOD + "\n",
            "empty": "",
            "unclosed link": self.GOOD.replace("</a>", ""),
            "self-closed link": self.GOOD.replace('target="_blank">', 'target="_blank"/>'
                                                  ).replace("</a>", ""),
            "stray </ul>": self.GOOD + "</li></ul>",
            "stray </a>": self.GOOD + "</a>",
            "out of order": self.GOOD.replace("<img ", "<span><img ").replace(
                "</a>", "</a></span>"),
            "unclosed span": self.GOOD.replace("<img ", "<span><img "),
        }
        for why, snippet in bad.items():
            with self.subTest(why=why):
                self.assertNotEqual(self.tool.validate(snippet), [])

    def test_srcset_hosts_count(self):
        s = self.GOOD.replace("<img ", '<img srcset="https://img2.example.dir/b@2x.png 2x" ')
        self.assertEqual(sorted(self.tool.hosts({"snippet": s})),
                         ["https://cdn.example.dir", "https://img2.example.dir"])

    def test_a_redirect_host_recorded_at_add_time_counts(self):
        badge = {"snippet": self.GOOD, "extra_hosts": ["https://img.cdn.example"]}
        self.assertEqual(self.tool.hosts(badge),
                         ["https://cdn.example.dir", "https://img.cdn.example"])

    def test_rel_dofollow_is_still_a_followed_link(self):
        self.assertTrue(self.tool.followed(self.GOOD.replace("<a ", '<a rel="dofollow" ')))
        self.assertFalse(self.tool.followed(
            self.GOOD.replace("<a ", '<a rel="noopener nofollow sponsored" ')))

    def test_img_src_keeps_what_is_not_a_badge(self):
        line = ("  Content-Security-Policy: default-src 'none'; img-src 'self' data: "
                "https://old.example https://t.co; font-src 'self'")
        out = self.tool.with_hosts(line, ["https://new.example"],
                                   dropped={"https://old.example"})
        self.assertEqual(out, "  Content-Security-Policy: default-src 'none'; img-src "
                              "'self' data: https://new.example https://t.co; font-src 'self'")
        self.assertEqual(self.tool.with_hosts(out, ["https://new.example"]), out)


class SelfHosted(unittest.TestCase):
    """--self-host: the directory's image saved here, its snippet kept as given."""

    SNIPPET = ('<a href="https://noon.example/product/ranwhat" rel="dofollow">\n'
               '  <img src="https://noon.example/badges/ranwhat.svg"\n'
               '       alt="Featured on Example" width="220" height="60" />\n</a>')
    CLEAN = (b'<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">'
             b'<rect width="10" height="10" fill="#fff"/>'
             b'<image xlink:href="data:image/png;base64,AAAA"/></svg>')

    def setUp(self):
        self.tool = _tool()
        self.tool._link_status = lambda snippet: ("https://noon.example/", 200)
        # serve() replaces urlopen on the shared urllib module; put the real
        # one back afterwards, or every later test in the run gets the stub.
        real_urlopen = self.tool.urllib.request.urlopen
        self.addCleanup(setattr, self.tool.urllib.request, "urlopen", real_urlopen)
        self.tmp = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, str(self.tmp), True)
        real = self.tool.Files(ROOT)
        self.files = self.tool.Files(self.tmp)
        for name in ("data", "index", "privacy", "headers"):
            dest = getattr(self.files, name)
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(read(getattr(real, name)).encode("utf-8"))
        if (real.site / "badges").is_dir():
            shutil.copytree(str(real.site / "badges"), str(self.files.site / "badges"))

    def serve(self, body, kind="image/svg+xml"):
        class Response(io.BytesIO):
            headers = {"Content-Type": kind, "Set-Cookie": "session=1"}
            def __enter__(self): return self
            def __exit__(self, *a): return False
        self.tool.urllib.request.urlopen = lambda request, timeout=None: Response(body)

    def add(self):
        path = self.tmp / "snippet.html"
        path.write_text(self.SNIPPET, encoding="utf-8")
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.tool.main(["add", "Example", "--file", str(path), "--self-host"], self.files)
        return out.getvalue()

    def test_the_page_serves_the_copy_and_the_snippet_stays_as_given(self):
        self.serve(self.CLEAN)
        self.add()
        badge = [b for b in self.tool.load(self.files) if b["name"] == "Example"][0]
        self.assertEqual(badge["snippet"], self.SNIPPET)
        self.assertEqual(badge["sha256"], self.tool.digest(self.SNIPPET))
        self.assertEqual((self.files.site / "badges" / "example.svg").read_bytes(), self.CLEAN)
        index = read(self.files.index)
        self.assertIn('src="/badges/example.svg"', index)
        self.assertNotIn("https://noon.example/badges/ranwhat.svg", index)
        self.assertIn('href="https://noon.example/product/ranwhat" rel="dofollow"', index)
        # Nothing for img-src to allow, and the privacy page says where it is served.
        self.assertEqual(self.tool.hosts(badge), [])
        self.assertNotIn("noon.example", self.tool.csp_line(read(self.files.headers)))
        self.assertIn("Example (its image served from ranwhat.com)", read(self.files.privacy))

    def test_an_svg_that_could_run_or_call_out_is_refused(self):
        for bad in (b'<svg><script>alert(1)</script></svg>',
                    b'<svg onload="x()"></svg>',
                    b'<svg><foreignObject></foreignObject></svg>',
                    b'<svg><image href="https://tracker.example/p.png"/></svg>',
                    b'<svg><rect style="fill:url(https://x.example/a)"/></svg>'):
            with self.subTest(svg=bad):
                self.serve(bad)
                with self.assertRaises(SystemExit):
                    self.add()
                self.assertFalse((self.files.site / "badges" / "example.svg").exists())

    def test_an_edited_copy_stops_the_page_being_written(self):
        self.serve(self.CLEAN)
        self.add()
        (self.files.site / "badges" / "example.svg").write_bytes(self.CLEAN + b"<!-- -->")
        self.assertTrue(self.tool.local_problems(self.files, self.tool.load(self.files)))
        with self.assertRaises(SystemExit):
            self.tool.sync(self.files, self.tool.load(self.files))

    def test_remove_deletes_the_copy(self):
        self.serve(self.CLEAN)
        self.add()
        with contextlib.redirect_stdout(io.StringIO()):
            self.tool.main(["remove", "Example"], self.files)
        self.assertFalse((self.files.site / "badges" / "example.svg").exists())


if __name__ == "__main__":
    unittest.main()
