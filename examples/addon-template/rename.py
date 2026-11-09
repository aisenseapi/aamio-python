"""Give the add-on its own name, once, on a fresh copy of the template.

    python rename.py weather

The template's name, example, is replaced in every file that carries it, the
Python package is moved to its new name, and check.py runs. The new name is 1
to 32 lowercase letters and digits, starting with a letter. It becomes the
command aamio addon NAME, the tools aamio_addon_NAME_*, the Python package
aamio_NAME, the distribution aamio-NAME, the PHP namespace AamioName and the
Composer package your-vendor/aamio-NAME, where your-vendor is yours to set in
composer.json. README.md and LICENSE are left as they are: write your own.
"""

import glob
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
OLD = "example"
NEW = re.compile(r"[a-z][a-z0-9]{0,31}")
TAKEN = ("list", "enable", "disable", "run", OLD)
FILES = (
    "aamio-addon.json", "composer.json", "autoload.php", "process.php", "src/Process.php", "tests/run.php",
    "python/pyproject.toml", "python/README.md",
    "python/src/aamio_example/__init__.py", "python/src/aamio_example/aamio-addon.json", "python/src/aamio_example/process.py",
    "python/tests/test_process.py",
)


def _name_in(path):
    """The name a manifest gives, or None when it cannot be read."""
    try:
        with open(path, encoding="utf-8") as handle:
            name = json.load(handle).get("name")
    except (OSError, ValueError, AttributeError):
        return None
    return name if isinstance(name, str) else None


def _halves(here):
    """The name in the manifest of each half this copy has: the PHP half at the top, with composer.json, and the Python half under python/."""
    found = {}
    if os.path.exists(os.path.join(here, "composer.json")):
        found["PHP"] = _name_in(os.path.join(here, "aamio-addon.json"))
    if os.path.isdir(os.path.join(here, "python")):
        manifests = glob.glob(os.path.join(here, "python", "src", "aamio_*", "aamio-addon.json"))
        found["Python"] = _name_in(manifests[0]) if len(manifests) == 1 else None
    return found


def main(argv):
    if len(argv) != 1 or NEW.fullmatch(argv[0]) is None or argv[0] in TAKEN:
        print("Give the new name: 1 to 32 lowercase letters and digits, starting with a letter, and not %s." % ", ".join(TAKEN), file=sys.stderr)
        return 2
    new = argv[0]
    package = os.path.join(HERE, "python", "src", "aamio_" + OLD)
    # Each half there is must still be the template's own, named example in its
    # manifest, before a file is touched: a copy renamed once has no example
    # left to replace, and a second run would say it gave the new name while
    # the add-on kept the first.
    halves = _halves(HERE)
    if not halves:
        print("This copy has neither half, PHP or Python: nothing was changed.", file=sys.stderr)
        return 2
    named = ["the %s half is named %s" % (half, name) if name else "the %s half has no manifest that can be read" % half
             for half, name in sorted(halves.items()) if name != OLD]
    if named:
        print("Nothing was changed: rename.py names a fresh copy of the template, once, and here %s. Rename by hand, or start again from a fresh copy." % " and ".join(named), file=sys.stderr)
        return 2
    pairs = (("AamioExample", "Aamio" + new.capitalize()), ("aamio_addon_%s_" % OLD, "aamio_addon_%s_" % new), ("aamio_" + OLD, "aamio_" + new), ("aamio-" + OLD, "aamio-" + new))
    changed = 0
    for name in FILES:
        path = os.path.join(HERE, *name.split("/"))
        if not os.path.exists(path):
            continue
        with open(path, encoding="utf-8", newline="") as handle:
            text = handle.read()
        renamed = text
        for old, replacement in pairs:
            renamed = renamed.replace(old, replacement)
        renamed = re.sub(r"\b%s\b" % OLD, new, renamed)
        if renamed != text:
            with open(path, "w", encoding="utf-8", newline="") as handle:
                handle.write(renamed)
            changed += 1
    if os.path.isdir(package):
        os.rename(package, os.path.join(HERE, "python", "src", "aamio_" + new))
    print("%s is %s now, in %d files. check.py says:\n" % (OLD, new, changed))
    return subprocess.call([sys.executable, os.path.join(HERE, "check.py")])


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
