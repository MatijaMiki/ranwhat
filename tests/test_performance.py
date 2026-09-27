"""Speed regressions in a scanner are correctness regressions in practice:
a first run that takes ninety seconds on one file is a first run nobody
finishes. These pin the two fixes that took a 39MB transcript from 89s to 2s.
"""
import json
import time
import unittest

from ranwhat import clean

# What a quadratic pattern costs here is seconds (10s to 24s on the shapes
# below before the fix), so the budget only has to sit well under that. At
# 50ms it failed on a loaded machine while the full suite ran, which on CI
# is a red build for nothing. 0.5s still catches every regression these
# exist for by a factor of twenty.
BUDGET = 0.5


class Linear(unittest.TestCase):
    def test_origin_scan_does_not_go_quadratic_on_prose(self):
        """_ORIGIN rescans forward from every position on long word runs. 16k
        characters used to cost 1.7s; the literal prefilter makes it free."""
        text = "a" * 50000
        t = time.perf_counter()
        clean._origins(text)
        self.assertLess(time.perf_counter() - t, BUDGET)

    def test_origins_still_found_when_a_marker_is_present(self):
        self.assertIn("~/.ssh/id_rsa", clean._origins("then cat ~/.ssh/id_rsa here"))
        self.assertIn("api/.env", clean._origins("read api/.env"))

    def test_origins_skip_templates(self):
        self.assertEqual(clean._origins("cp .env.example .env.example"), [])

    def test_origin_scan_is_linear_when_a_marker_is_present(self):
        """The prefilter only helps lines with no marker, and ".key" or "id_"
        is in most lines of code. The old pattern took 10s on the first
        shape, 24s on the second and 17s on the base64 one. The b.env-c
        shape catches a stem and a suffix loop nested in one alternative."""
        shapes = [
            "cat .env " + "a" * 50000,
            "cat .env " + "a/" * 25000,
            "x.key " + "a." * 25000,
            "x a/" + "b.env-c" * 7000 + "/",
            "id_rsa " + "Ab3_cD-eF9" * 5000,
            "x " + "a\\" * 25000 + ".key",
            "x " + "a/\\" * 20000,
            "\\nhttp:" + "\\\\n" * 15000 + ".env",     # escaped \\ before n
            "cat " * 12500 + "x.key",
            " -a" * 16000 + " x.key",
            "'a.a.a" * 8000 + ".key",
        ]
        for text in shapes:
            with self.subTest(text=text[:24]):
                t = time.perf_counter()
                clean._origins(text)
                self.assertLess(time.perf_counter() - t, BUDGET)

    def test_a_very_long_path_still_resolves(self):
        text = " " + "a/" * 100000 + ".env"
        t = time.perf_counter()
        found = clean._origins(text)
        self.assertLess(time.perf_counter() - t, BUDGET)
        self.assertEqual(len(found), 1)
        self.assertTrue(found[0].endswith("/.env"))

    def test_a_long_json_line_of_code_is_fast_and_honest(self):
        line = 'x = d.key; cat api/.env; os.environ.get("K")\n' * 1100
        text = json.dumps({"c": line})
        t = time.perf_counter()
        found = clean._origins(text)
        self.assertLess(time.perf_counter() - t, BUDGET)
        self.assertEqual(set(found), {"api/.env"})


class EmbeddedImages(unittest.TestCase):
    PNG = "iVBORw0KGgoAAAANSUhEUgAA" + "A" * 300000

    def test_embedded_png_is_not_scanned(self):
        t = time.perf_counter()
        self.assertEqual(clean.find_secrets(self.PNG), [])
        self.assertLess(time.perf_counter() - t, BUDGET)

    def test_image_data_cannot_produce_a_false_positive(self):
        """Random-looking base64 can contain an AKIA-shaped run by chance."""
        # Not AWS's documentation key: that is a fixture and would be dropped
        # anyway, so the test could no longer see the image skip regress.
        planted = "iVBORw0KGgo" + "Q" * 5000 + "AKIA4TRUE7KEYX9QZ2WB" + "Q" * 5000
        self.assertEqual(clean.find_secrets(planted), [])

    def test_short_text_starting_like_an_image_is_still_scanned(self):
        """Only long whitespace-free blobs count as images."""
        # Not an edited copy of AWS's documentation key: that is a fixture.
        text = "Qk AWS_SECRET_ACCESS_KEY=" + "q8Vn3LxT0wRb/Kd7Pz2mYh9Gc+J4sEf6Ua1NtW5r"
        self.assertTrue(clean.find_secrets(text))

    def test_real_secret_in_ordinary_text_still_found(self):
        text = "export STRIPE_KEY=sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc" + " and done"
        labels = [label for _, label in clean.find_secrets(text)]
        self.assertTrue(labels, "a live-shaped key in prose was missed")


if __name__ == "__main__":
    unittest.main()
