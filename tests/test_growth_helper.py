"""growth.py reads how a cost grows from times a shared runner can disturb.
These pin how it reads them, with the clock replaced by a script."""
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import growth  # noqa: E402


def scripted(times):
    """A growth.seconds that returns these (scale -> seconds) in order."""
    queue = list(times)

    def seconds(call, arg):
        return queue.pop(0), None
    return seconds


class ReadingGrowth(unittest.TestCase):

    def measure(self, times):
        with mock.patch.object(growth, "seconds", scripted(times)):
            return growth.measure(lambda n: n(4), lambda arg: None)

    def test_a_slow_spell_over_the_large_size_is_not_a_quadratic(self):
        # A try times the quarter size, then the full one. The quarter size
        # had one quiet moment (0.068s) and the full size none, so the best
        # times read past 8, as on a macOS runner, while the second try,
        # whose two runs shared a slow spell, reads 4.
        m = self.measure([0.068, 1.20, 0.30, 1.25, 0.14, 0.62,
                          0.15, 0.60, 0.137, 0.549])
        self.assertGreaterEqual(growth.growth(m.best[1.0], m.best[0.25]), 8)
        self.assertLess(m.growth(1.0, 0.25), growth.LIMIT)
        growth.assert_linear(self, m)

    def test_a_quadratic_cost_still_fails(self):
        m = self.measure([0.05, 0.80, 0.04, 0.70, 0.06, 0.95, 0.05, 0.81,
                          0.05, 0.80])
        with self.assertRaises(AssertionError):
            growth.assert_linear(self, m)

    def test_a_quarter_size_shorter_than_a_time_slice_is_not_a_quadratic(self):
        # A Linux runner's five tries of a case that grows 3.8 times. The
        # quarter size fit in a time slice and ran untouched in each, and
        # the full size shared a busy core in each, so every try read past
        # 8 when a time under 0.002s was the only one read as noise.
        tries = [0.00362, 0.0384, 0.0037, 0.0402, 0.00365, 0.0389,
                 0.0041, 0.0436, 0.00368, 0.0395]
        with mock.patch.object(growth, "FLOOR", 0.002):
            self.assertGreaterEqual(
                self.measure(tries).growth(1.0, 0.25), growth.LIMIT)
        m = self.measure(tries)
        self.assertEqual(len(m.runs), 1)
        growth.assert_linear(self, m)

    def test_a_quadratic_cost_with_a_short_quarter_size_still_fails(self):
        # 6ms at a quarter of the size, 16 times that at full size.
        m = self.measure([0.006, 0.096] * growth.TRIES)
        with self.assertRaises(AssertionError):
            growth.assert_linear(self, m)

    def test_a_linear_cost_stops_after_one_try(self):
        m = self.measure([0.05, 0.20])
        self.assertEqual(len(m.runs), 1)
        growth.assert_linear(self, m)

    def test_runs_survive_json(self):
        m = self.measure([0.05, 0.20])
        back = growth.Measured.from_json(m.as_json())
        self.assertEqual(back.runs, m.runs)
        self.assertEqual(back.growth(1.0, 0.25), m.growth(1.0, 0.25))
        # an older child script's JSON has no runs
        old = growth.Measured.from_json({"best": [[1.0, 0.2], [0.25, 0.05]],
                                         "pairs": [[1.0, 0.25]]})
        self.assertEqual(old.runs, [])


# The child script measure_apart runs: its clock is the script below, the
# same one that slowed the large size above, so the best times read past 8
# and only a try's own runs read 4.
_SCRIPTED_CHILD = """
queue = [0.068, 1.20, 0.30, 1.25, 0.14, 0.62, 0.15, 0.60, 0.137, 0.549]

def _seconds(call, arg):
    return queue.pop(0), arg

growth.seconds = _seconds

def call(arg):
    return arg
"""


class ReadingGrowthApart(unittest.TestCase):

    def test_each_try_comes_back_from_the_child(self):
        measured, full = growth.measure_apart(lambda n: n(4), _SCRIPTED_CHILD)
        self.assertEqual(full, 4)
        self.assertEqual(measured.result, 4)
        self.assertEqual(measured.runs[0], {0.25: 0.068, 1.0: 1.20})
        self.assertEqual(len(measured.runs), 2)
        self.assertGreaterEqual(
            growth.growth(measured.best[1.0], measured.best[0.25]), 8)
        self.assertLess(measured.growth(1.0, 0.25), growth.LIMIT)
        growth.assert_linear(self, measured)


if __name__ == "__main__":
    unittest.main()
