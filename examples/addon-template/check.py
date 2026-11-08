"""Do the name and the version agree in every place? Run it after renaming, and before a release.

    python check.py

An add-on's short name and version are written in several files, and one that
disagrees makes an add-on the core refuses, or never finds. This reads them
all and says which one is off. Either half may be left out: a repository with
only the Python half, or only the PHP half, is checked for that half. It needs
nothing but Python 3.
"""

import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SHORT = re.compile(r"[a-z0-9][a-z0-9_-]{0,31}")
RESERVED = ("list", "enable", "disable", "run")


class Report:
    def __init__(self):
        self.good = []
        self.bad = []

    def check(self, ok, said, fix):
        (self.good if ok else self.bad).append(said if ok else "%s: %s" % (said, fix))
        return ok


def read(*parts):
    path = os.path.join(HERE, *parts)
    with open(path, encoding="utf-8") as handle:
        return handle.read()


def exists(*parts):
    return os.path.exists(os.path.join(HERE, *parts))


def manifest_rules(report, manifest, where):
    name = manifest.get("name")
    report.check(manifest.get("aamio_addon") == 2, "%s is on contract 2" % where, 'set "aamio_addon": 2')
    report.check(isinstance(name, str) and SHORT.fullmatch(name) is not None and name not in RESERVED, "%s has a short name the core takes" % where,
                 "name is 1 to 32 characters of a-z, 0-9, dash and underscore, and not list, enable, disable or run")
    report.check(isinstance(manifest.get("version"), str) and manifest.get("version") != "", "%s has a version" % where, "set version, as 0.1.0")
    for tool in manifest.get("tools", []):
        report.check(str(tool.get("name", "")).startswith("aamio_addon_%s_" % name), "the tool %s carries the add-on's name" % tool.get("name"), "a tool is called aamio_addon_%s_SOMETHING" % name)
    return name, manifest.get("version")


def main():
    report = Report()
    python_half = exists("python", "pyproject.toml")
    php_half = exists("composer.json")
    if not python_half and not php_half:
        print("Neither python/pyproject.toml nor composer.json is here, so there is no add-on to check.")
        return 1
    copies = {}

    if python_half:
        pyproject = read("python", "pyproject.toml")
        entry = re.search(r'\[project\.entry-points\."aamio\.addons"\]\s*\n(?:\s*#[^\n]*\n)*\s*([A-Za-z0-9_-]+)\s*=\s*"([A-Za-z0-9_.]+)"', pyproject)
        if report.check(entry is not None, "python/pyproject.toml has an entry point in aamio.addons", 'add [project.entry-points."aamio.addons"] with NAME = "aamio_NAME"'):
            short, package = entry.group(1), entry.group(2).split(".")[0]
            if report.check(exists("python", "src", package, "aamio-addon.json"), "python/src/%s holds the manifest" % package, "the entry point names the package that carries aamio-addon.json"):
                text = read("python", "src", package, "aamio-addon.json")
                copies["python/src/%s/aamio-addon.json" % package] = text
                manifest = json.loads(text)
                name, version = manifest_rules(report, manifest, "the Python manifest")
                report.check(short == name, "the entry point is called %s, as the manifest's name" % short, "the name left of = in the entry point is the manifest's name")
                report.check(re.search(r'\b%s\s*=\s*\[[^\]]*"aamio-addon\.json"' % re.escape(package), pyproject) is not None, "the manifest goes into the package", "list aamio-addon.json under [tool.setuptools.package-data] for %s" % package)
                init = read("python", "src", package, "__init__.py") if exists("python", "src", package, "__init__.py") else ""
                found_name = re.search(r'^NAME\s*=\s*"([^"]*)"', init, re.M)
                found_version = re.search(r'^__version__\s*=\s*"([^"]*)"', init, re.M)
                report.check(found_name is not None and found_name.group(1) == name, "NAME in %s/__init__.py is %s" % (package, name), "set NAME = \"%s\"" % name)
                report.check(found_version is not None and found_version.group(1) == version, "__version__ in %s/__init__.py is %s" % (package, version), "set __version__ = \"%s\"" % version)
                module = (manifest.get("process") or {}).get("python")
                report.check(isinstance(module, str) and exists("python", "src", *(module.split(".")[:-1] + [module.split(".")[-1] + ".py"])), "process.python names a module that is there", "process.python is the module the core runs, as %s.process" % package)

    if php_half:
        composer = json.loads(read("composer.json"))
        extra = (composer.get("extra") or {}).get("aamio-addon") or {}
        report.check(composer.get("type") == "aamio-addon", "composer.json is of type aamio-addon", 'set "type": "aamio-addon"')
        if report.check(exists("aamio-addon.json"), "aamio-addon.json is at the root, beside composer.json", "the PHP package carries its manifest at its root"):
            text = read("aamio-addon.json")
            copies["aamio-addon.json"] = text
            manifest = json.loads(text)
            name, version = manifest_rules(report, manifest, "the PHP manifest")
            report.check(extra.get("name") == name and extra.get("contract") == 2, "composer.json says name %s and contract 2" % name, 'set "extra": {"aamio-addon": {"name": "%s", "contract": 2}}' % name)
            script = (manifest.get("process") or {}).get("php")
            report.check(isinstance(script, str) and exists(script), "process.php names a file that is there", "process.php is the file the core runs, as process.php")
            classes = [read("src", item) for item in sorted(os.listdir(os.path.join(HERE, "src"))) if item.endswith(".php")] if exists("src") else []
            names = [found.group(1) for text_ in classes for found in [re.search(r"const NAME = '([^']*)'", text_)] if found]
            versions = [found.group(1) for text_ in classes for found in [re.search(r"const VERSION = '([^']*)'", text_)] if found]
            report.check(names == [name], "NAME in src/ is %s" % name, "set const NAME = '%s' in the process class" % name)
            report.check(versions == [version], "VERSION in src/ is %s" % version, "set const VERSION = '%s' in the process class" % version)

    if len(copies) == 2:
        first, second = list(copies)
        report.check(copies[first] == copies[second], "the two copies of aamio-addon.json are the same", "copy %s over %s, or the other way round: the two runtimes must say the same" % (first, second))

    for line in report.good:
        print("  ok    " + line)
    for line in report.bad:
        print("  FIX   " + line)
    print("\n%d in order, %d to fix" % (len(report.good), len(report.bad)))
    return 0 if not report.bad else 1


if __name__ == "__main__":
    sys.exit(main())
