"""How a cost grows with its input, for tests that must catch a quadratic
regression on whatever machine runs them.

A budget in seconds measures the machine as much as the code: 0.5s held
here with room to spare (under 0.3s) and failed on every CI runner, which
took 0.51s to 0.8s on the same input. What a quadratic regression changes
is how a cost grows, and that is the same on a slow machine as on a fast
one. So a case is measured at two sizes, the smaller a quarter of the
larger: a linear cost grows four times, a quadratic one sixteen, and the
test fails past LIMIT, between the two. A ceiling in seconds remains, far
above any of these cases, for one so slow that its growth no longer
matters.

Each size is timed up to TRIES times, with every cache in ranwhat emptied
first and the garbage collector off, as timeit does. A try times the sizes
back to back, so a slow spell on a shared runner tends to slow both of
them: the growth read is the smaller of the growth between the best times
and the growth within the most even try. On a macOS runner the best times
alone once read 8.1 for a case that grows 4.0 here, because the small size
had one quiet moment and the large size none. The tries stop as soon as the
growth is in proportion, so a linear case usually costs one run at each
size, and only a case that a busy machine slowed is measured again. A
quadratic one never gets there: it grows about sixteen times in every try.

Where a test compares two costs at one size instead (this one costs no
more than that one), settle() gives it the same best-of-TRIES, so that a
margin can be a proportion rather than a number of seconds.

Where the input is a file tree too large to build twice in one run (a
transcript of tens of megabytes), measure_apart() builds it here at each
size and measures the call on its own interpreter, stopped after HANG.

Imported by the tests, and by the scripts they run in a fresh interpreter;
it needs nothing but the standard library.
"""
import gc
import json
import os
import subprocess
import sys
import time

SCALE = 4          # the larger size over the smaller
LIMIT = 8          # a linear cost grows SCALE times, a quadratic SCALE ** 2
TRIES = 5
CEILING = 10.0     # seconds at the larger size, whatever the growth
# A time under this is read as this much: a case too fast to measure cannot
# fail on its growth. It is longer than a scheduler's time slice. On a core
# something else wants too, a call shorter than a slice can run to its end
# before it is made to share, and a longer one is shared all the way: the
# best of five tries then pits the short call's one quiet run against the
# long call's every run. Pinned to a core with two busy processes, a case
# that grows 3.8 times ran its 3.1ms quarter size untouched in a try, and
# never its 12ms full size in under 36: 11.6 times. A Linux runner read
# 0.004s against 0.038s in all five tries. Under the same load, 6ms of work
# never ran in under 9.8: from 10ms up, both sizes share the core alike.
# A quadratic still fails where its quarter size takes 5ms or more.
FLOOR = 0.01

QUARTER = ((1.0, 1.0 / SCALE),)


def sized(scale):
    """n(k): the count k at this scale, and at least 1."""
    return lambda k: max(1, int(round(k * scale)))


def forget():
    """Empty every functools cache in ranwhat, so that running a call again
    costs what running it the first time did."""
    for name, module in list(sys.modules.items()):
        if module is None or not (name == "ranwhat" or name.startswith("ranwhat.")):
            continue
        for value in list(vars(module).values()):
            clear = getattr(value, "cache_clear", None)
            if callable(clear):
                clear()


def seconds(call, arg):
    """How long call(arg) takes, and what it returns."""
    forget()
    gc.collect()
    enabled = gc.isenabled()
    gc.disable()
    try:
        start = time.perf_counter()
        result = call(arg)
        return time.perf_counter() - start, result
    finally:
        if enabled:
            gc.enable()


def growth(large, small):
    """How many times the cost grew from small to large."""
    return large / max(small, FLOOR)


def least_growth(best, runs, large, small):
    """The growth from small to large: between the best times, or within the
    try whose two times are most in proportion, whichever is less."""
    least = growth(best[large], best[small])
    for run in runs:
        if large in run and small in run:
            least = min(least, growth(run[large], run[small]))
    return least


def in_proportion(best, pairs, runs=()):
    return all(least_growth(best, runs, a, b) < LIMIT for a, b in pairs)


class Measured:
    """The best seconds at each scale, the pairs of scales to compare, and
    what the call returned at the largest scale."""

    def __init__(self, best, pairs, result=None, runs=()):
        self.best = best
        self.pairs = [tuple(p) for p in pairs]
        self.result = result
        # one {scale: seconds} per try, its scales timed back to back
        self.runs = [dict(r) for r in runs]

    def growth(self, large, small):
        return least_growth(self.best, self.runs, large, small)

    def as_json(self):
        return {"best": [[s, t] for s, t in self.best.items()],
                "pairs": [list(p) for p in self.pairs],
                "runs": [[[s, t] for s, t in r.items()] for r in self.runs]}

    @classmethod
    def from_json(cls, doc):
        return cls({s: t for s, t in doc["best"]}, doc["pairs"],
                   runs=[{s: t for s, t in r} for r in doc.get("runs", [])])


def measure(build, call, pairs=QUARTER, rebuild=False, inputs=None):
    """Time call(build(n)) at each scale named in pairs, as a Measured.

    build(n) makes the input at a scale: n(k) is the count k there, so
    `"a=" * n(500000)` is half a million at full size and a quarter of
    that at a quarter. The input is made once per scale, unless rebuild:
    then before every run, for a call that changes its input or depends on
    state build sets up. `inputs`, {scale: input}, are ones already made."""
    scales = sorted({s for pair in pairs for s in pair})
    inputs = dict(inputs or {})

    def arg(scale):
        if rebuild or scale not in inputs:
            inputs[scale] = build(sized(scale))
        return inputs[scale]

    # Whatever a first call does once (an import, a lazy compile) is done
    # here, on an input too small to time, and timed for no one.
    call(build(sized(scales[0] / SCALE)))
    best = dict.fromkeys(scales, float("inf"))
    runs = []
    result, spent = None, 0.0
    for _ in range(TRIES):
        run = {}
        for scale in scales:
            took, out = seconds(call, arg(scale))
            run[scale] = took
            best[scale] = min(best[scale], took)
            spent += took
            if scale == scales[-1]:
                result = out
        runs.append(run)
        if (in_proportion(best, pairs, runs) or best[scales[-1]] >= CEILING
                or spent >= CEILING):
            break
    return Measured(best, pairs, result, runs)


def assert_linear(test, measured, what=""):
    """Fail `test` where a cost grew as a quadratic one does, or took longer
    than CEILING at its larger size."""
    best = measured.best
    for large, small in measured.pairs:
        times = measured.growth(large, small)
        said = ("%s%.3fs, against %.3fs at %g of the size: %.1f times, where "
                "a linear cost grows %d times and a quadratic one %d"
                % (what + ": " if what else "", best[large], best[small],
                   small / large, times, SCALE, SCALE ** 2))
        test.assertLess(best[large], CEILING, said)
        test.assertLess(times, LIMIT, said)


class Assertions:
    """For a TestCase measured in this process."""

    def assertScalesLinearly(self, build, call, what="", pairs=QUARTER,
                             rebuild=False):
        """measure() and assert_linear(); what the call returned at full size."""
        measured = measure(build, call, pairs, rebuild)
        assert_linear(self, measured, what)
        return measured.result


def settle(once, fine):
    """The elementwise best of up to TRIES runs of once(), a tuple of
    seconds, stopping as soon as fine(*best) holds."""
    best = None
    for _ in range(TRIES):
        now = once()
        best = now if best is None else tuple(map(min, best, now))
        if fine(*best):
            break
    return best


# measure() stops trying once it has spent CEILING, so a linear case is
# done within about twice that even on a slow machine; past HANG the run
# is taken for one that would never finish, and fails.
HANG = 3 * CEILING
HERE = os.path.dirname(os.path.abspath(__file__))

_APART = """
import json, sys
sys.path[:0] = json.loads(sys.argv[1])
import growth
<call>
first, inputs = json.loads(sys.argv[2])
measured = growth.measure(lambda n: first, call,
                          inputs=dict((s, x) for s, x in inputs))
print(json.dumps({"measured": measured.as_json(), "result": measured.result}))
"""


def measure_apart(build, call, env=None, hang=HANG):
    """measure() on a fresh interpreter: `call` is the source of a module
    that defines call(input), and build(n) makes each input here, once per
    size, in JSON (the root of a file tree, usually). What call returns
    must be JSON too. Returns the Measured, its result what call returned
    at full size, and the input at full size. The Measured carries each
    try's runs back from the child too, so its growth is read as
    measure()'s is: a slow spell over one size is not a quadratic here
    either."""
    scales = sorted({s for pair in QUARTER for s in pair}, reverse=True)
    inputs = [(scale, build(sized(scale))) for scale in scales]
    first = build(sized(scales[-1] / SCALE))
    script = _APART.replace("<call>", call, 1)
    try:
        run = subprocess.run(
            [sys.executable, "-c", script,
             json.dumps([HERE, os.path.dirname(HERE)]),
             json.dumps([first, inputs])],
            env=env, capture_output=True, encoding="utf-8", timeout=hang)
    except subprocess.TimeoutExpired:
        raise AssertionError("still running after %ds" % hang)
    if run.returncode:
        raise AssertionError(run.stderr)
    doc = json.loads(run.stdout.splitlines()[-1])
    measured = Measured.from_json(doc["measured"])
    measured.result = doc["result"]
    return measured, inputs[0][1]
