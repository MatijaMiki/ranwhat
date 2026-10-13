"""Build ranwhat as one file: a zipapp that runs wherever Python 3.9+ does.

    python3 scripts/build_pyz.py                 writes dist/ranwhat.pyz
    python3 scripts/build_pyz.py --out PATH      somewhere else

The file is the ranwhat package (its demo data too) and a __main__.py that
runs it the way `python -m ranwhat` does, behind a `#!/usr/bin/env python3`
line, so `./ranwhat.pyz check` works once it is executable. Nothing is
fetched and nothing is installed: the package has no dependencies.

The build is reproducible. Files go in sorted, with one fixed timestamp and
one mode, so the same source gives the same bytes and the same sha256 on any
machine. A release can publish that hash and anyone can rebuild it.

Standard library only.
"""
import argparse
import hashlib
import os
import pathlib
import stat
import sys
import zipfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
SHEBANG = b"#!/usr/bin/env python3\n"
STAMP = (1980, 1, 1, 0, 0, 0)       # the earliest a zip can say
MAIN = (
    '"""Run the ranwhat package in this archive, as `python -m ranwhat` does."""\n'
    "import runpy\n"
    'runpy.run_module("ranwhat", run_name="__main__", alter_sys=True)\n'
)
SKIP_DIRS = {"__pycache__"}
SKIP_SUFFIXES = (".pyc", ".pyo")


def sources(root=ROOT):
    """[(archive name, path)] for every file of the package, in order."""
    out = []
    for base, dirs, files in os.walk(str(root / "ranwhat")):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        for name in sorted(files):
            if name.endswith(SKIP_SUFFIXES):
                continue
            path = pathlib.Path(base) / name
            out.append((path.relative_to(root).as_posix(), path))
    return out


def build(out, root=ROOT):
    """Write the archive to `out`; return its sha256."""
    out = pathlib.Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = out.with_name(out.name + ".part")
    with open(str(tmp), "wb") as raw:
        raw.write(SHEBANG)
        with zipfile.ZipFile(raw, "w", zipfile.ZIP_DEFLATED) as z:
            def add(name, data):
                info = zipfile.ZipInfo(name, STAMP)
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = (stat.S_IFREG | 0o644) << 16
                z.writestr(info, data)
            add("__main__.py", MAIN.encode("utf-8"))
            for name, path in sources(root):
                add(name, path.read_bytes())
    os.replace(str(tmp), str(out))
    out.chmod(0o755)
    return hashlib.sha256(out.read_bytes()).hexdigest()


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--out", default=str(ROOT / "dist" / "ranwhat.pyz"))
    args = ap.parse_args(argv)
    digest = build(args.out)
    print("%s  %s" % (digest, args.out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
