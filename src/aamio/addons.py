"""Add-ons: what a runtime can do beyond the core, installed one by one and enabled by name.

The core is the rendezvous: keys, inbox, presence, the board, receipts. Other
things are add-ons, each a distribution of its own that depends on aamio and
declares an entry point in the group aamio.addons naming a module, so that
installing one is the user's choice and `pip install aamio` stays what it was.
The entry point's name is the add-on's short name. The module says:

    NAME = "domain"               the short name, the same as the entry point's
    __version__ = "0.1.0"
    add_commands(parser)          its commands, as subparsers of aamio addon NAME
    early(args)                   an exit code for a command that needs no home, else None
    command(args, runtime)        the command, with the runtime: an exit code
    TOOLS                         its MCP tools, as aamio.mcp_server.tool makes them
    dispatch(runtime, name, arguments, ask)   one tool call, or None for a tool not its own

Installed is not enabled. The core imports an add-on only when the user has
named it: with `aamio addon enable NAME`, kept in addons.json in the home, or
in AAMIO_ADDONS for a checkout that is not installed. What is installed and not
enabled is listed from the package's metadata, without running any of it, with
the command that enables it. An add-on that runs here runs in this process,
with the key and the home: enabling says which code runs, it is not a boundary
around what that code can do.

The core owns the names. Two add-ons with one short name, or two tools with one
name, stop the start and say so, rather than let the order they were found in
decide which one runs. An add-on that cannot be imported stops the start too:
a broken install is not a quiet absence. `aamio addon disable NAME` takes a
broken one out again.
"""

import argparse
import importlib
import json
import os
import re
from importlib import metadata

from .runtime import home_dir

GROUP = "aamio.addons"
ENABLED_FILE = "addons.json"
HOOKS = ("NAME", "__version__", "add_commands", "early", "command", "TOOLS", "dispatch")
RESERVED = ("list", "enable", "disable")

_cache = {"key": None, "addons": []}
_home = None


class AddonError(RuntimeError):
    """An add-on that cannot be used as one, with what to do about it."""


def use_home(home):
    """The home the command line was given, before the parser is built: the enabled list is kept in it."""
    global _home
    _home = home
    _cache["key"] = None


def home(given=None):
    return given or _home or home_dir()


def _normal(name):
    """A distribution name as pip compares it: lower case, and one dash for any run of dashes, dots and underscores."""
    return re.sub(r"[-_.]+", "-", name).lower()


# ------------------------------------------------------------------ enabled

def enabled_file(given=None):
    return os.path.join(home(given), ENABLED_FILE)


def enabled(given=None):
    """The distributions enabled in this home, in the order they were enabled, as the file spells them."""
    path = enabled_file(given)
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
    except FileNotFoundError:
        return []
    except (OSError, ValueError) as error:
        raise AddonError("%s could not be read: %s. Fix or remove the file; it lists the add-ons enabled here, one distribution name each under \"enabled\"." % (path, error)) from None
    names = data.get("enabled") if isinstance(data, dict) else None
    if not isinstance(names, list) or not all(isinstance(name, str) for name in names):
        raise AddonError("%s is not a list of enabled add-ons. Fix or remove the file; it has one distribution name each under \"enabled\"." % path)
    return names


def _write_enabled(given, names):
    folder = home(given)
    if not os.path.isdir(folder):
        os.makedirs(folder, mode=0o700, exist_ok=True)
    path = enabled_file(given)
    with open(path + ".tmp", "w", encoding="utf-8") as handle:
        json.dump({"enabled": names}, handle, indent=2)
        handle.write("\n")
    os.replace(path + ".tmp", path)
    _cache["key"] = None


# ---------------------------------------------------------------- installed

def installed():
    """Every add-on installed beside aamio, from its metadata and without running any of it.

    One row per entry point: the short name is the entry point's name, the
    distribution is what pip installed and what `enable` records.
    """
    rows = []
    for point in metadata.entry_points(group=GROUP):
        dist = point.dist
        rows.append({"name": point.name, "distribution": dist.name if dist is not None else None, "version": dist.version if dist is not None else None, "module": point.value, "point": point})
    return rows


def _is_enabled(row, wanted):
    return row["distribution"] is not None and _normal(row["distribution"]) in {_normal(name) for name in wanted}


def pick(which, given=None):
    """The installed add-on `which` names, by short name or by distribution: its distribution, refused when none or two fit."""
    hits = [row for row in installed() if row["name"] == which or (row["distribution"] is not None and _normal(row["distribution"]) == _normal(which))]
    distributions = sorted({row["distribution"] for row in hits if row["distribution"] is not None})
    if not distributions:
        raise AddonError("no installed add-on is called %s. aamio addon list says which are installed; an add-on is installed first, as pip install \"aamio[domain-keys]\" for Domain Keys." % which)
    if len(distributions) > 1:
        raise AddonError("two installed add-ons are called %s: %s. Enable one by its distribution name." % (which, " and ".join(distributions)))
    return distributions[0]


# ------------------------------------------------------------------- loaded

def _import(point, name, fix):
    try:
        return point.load() if point is not None else importlib.import_module(name)
    except Exception as error:
        raise AddonError("the add-on %s could not be loaded: %s: %s. Reinstall it, or %s to go on without it." % (name, error.__class__.__name__, error, fix)) from None


def _hooks(module, fix):
    for hook in HOOKS:
        if not hasattr(module, hook):
            raise AddonError("%s cannot be used as an add-on: it has no %s. Reinstall it, or %s to go on without it." % (module.__name__, hook, fix))
    if module.NAME in RESERVED:
        raise AddonError("%s cannot be called %s: that is a command of aamio addon itself. To go on without it: %s." % (module.__name__, module.NAME, fix))


def _load(env, wanted):
    """The modules of the enabled add-ons and of what AAMIO_ADDONS names, each checked; nothing cached."""
    found = []
    for row in installed():
        if not _is_enabled(row, wanted):
            continue
        fix = "aamio addon disable %s" % row["distribution"]
        module = _import(row["point"], row["distribution"], fix)
        if module in found:
            continue
        _hooks(module, fix)
        if module.NAME != row["name"]:
            raise AddonError("the add-on %s is called %s in its metadata and %s in its module. Reinstall it, or %s to go on without it." % (row["distribution"], row["name"], module.NAME, fix))
        found.append(module)
    for name in env.split(","):
        if name.strip():
            module = _import(None, name.strip(), "uninstall it")
            if module in found:
                continue
            _hooks(module, "uninstall it")
            found.append(module)
    names = {}
    for module in found:
        other = names.get(module.NAME)
        if other is not None:
            raise AddonError("two add-ons are called %s: %s and %s. Uninstall one, or the order they were found in would decide which one runs." % (module.NAME, other.__name__, module.__name__))
        names[module.NAME] = module
    # The tools too, here and not first when a server lists them: `aamio addon
    # list` and `aamio serve` have to agree on whether this installation works.
    from . import mcp_server

    tools(mcp_server.TOOLS, found)
    return found


def loaded(given=None):
    """Every add-on this installation runs: the enabled ones and what AAMIO_ADDONS names, checked once for what an add-on must have and for its name."""
    env = os.environ.get("AAMIO_ADDONS") or ""
    key = (env, home(given))
    if _cache["key"] != key:
        _cache.update(key=key, addons=_load(env, enabled(given)))
    return list(_cache["addons"])


def by_name(name):
    for module in loaded():
        if module.NAME == name:
            return module
    raise LookupError("no add-on is called %s" % name)


# ----------------------------------------------------------- enable, disable

def enable(which, given=None):
    """Lets an installed add-on run here, once it has been loaded clean: a broken one is refused, not recorded."""
    distribution = pick(which, given)
    names = enabled(given)
    if not any(_normal(name) == _normal(distribution) for name in names):
        _load(os.environ.get("AAMIO_ADDONS") or "", names + [distribution])
        _write_enabled(given, names + [distribution])
    answer = describe(given)
    answer["note"] = "%s runs here from now on, in aamio's own process and with its key and home: it can do what aamio itself can." % distribution
    return answer


def disable(which, given=None):
    """Takes an add-on out of the enabled list, by short name or by distribution, loading nothing to do it."""
    distributions = {_normal(row["distribution"]) for row in installed() if row["name"] == which and row["distribution"] is not None}
    distributions.add(_normal(which))
    names = enabled(given)
    kept = [name for name in names if _normal(name) not in distributions]
    if len(kept) != len(names):
        _write_enabled(given, kept)
    answer = describe(given)
    if len(kept) == len(names):
        answer["note"] = "%s was not enabled; nothing changed." % which
    return answer


# ----------------------------------------------------------------- describe

def commands_of(module):
    """The commands an add-on adds, read out of the parser it builds."""
    parser = argparse.ArgumentParser(prog="aamio addon " + module.NAME)
    module.add_commands(parser)
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            return sorted(action.choices)
    return []


def _running(module):
    return {"version": module.__version__, "module": module.__name__, "commands": commands_of(module), "mcp_tools": [tool["name"] for tool in module.TOOLS]}


def describe(given=None):
    """What aamio addon list answers: every add-on installed or named, whether it runs here, and for one that runs its commands and tools.

    When an enabled add-on cannot be loaded, the list still answers, from the
    metadata, with the error and the command that takes the add-on out: a
    broken add-on must not hide itself or the others.
    """
    try:
        running = {module.NAME: module for module in loaded(given)}
        error = None
    except AddonError as failure:
        running, error = {}, str(failure)
    wanted = enabled(given)
    rows = []
    seen = set()
    for row in installed():
        entry = {"name": row["name"], "version": row["version"], "distribution": row["distribution"], "enabled": _is_enabled(row, wanted)}
        module = running.get(row["name"])
        if not entry["enabled"] and module is not None and module.__name__ == row["module"].split(":")[0]:
            # Installed, and running because AAMIO_ADDONS names the same module:
            # one row, saying how it came to run.
            entry["enabled"] = True
            entry["named_in"] = "AAMIO_ADDONS"
        if entry["enabled"]:
            seen.add(row["name"])
            if module is not None:
                entry.update(_running(module))
            else:
                entry["loaded"] = False
        else:
            same = [other for other in installed() if other["name"] == row["name"] and other["distribution"] != row["distribution"]]
            entry["fix"] = "aamio addon enable %s" % (row["distribution"] if same else row["name"])
        rows.append(entry)
    for module in running.values():
        if module.NAME not in seen:
            rows.append(dict({"name": module.NAME, "distribution": None, "enabled": True}, named_in="AAMIO_ADDONS", **_running(module)))
    answer = {"addons": rows}
    missing = [name for name in wanted if not any(row["distribution"] is not None and _normal(row["distribution"]) == _normal(name) for row in installed())]
    if missing:
        answer["enabled_but_not_installed"] = missing
    if error is not None:
        answer["error"] = error
    if not rows and error is None:
        answer["note"] = "No add-on is installed. An add-on is a package of its own, installed beside aamio and then enabled by name: pip install \"aamio[domain-keys]\" and aamio addon enable domain for Domain Keys."
    return answer


# -------------------------------------------------------------------- tools

def tools(core, among=None):
    """Every tool the add-ons bring, refused when a name is taken already."""
    taken = {tool["name"]: "the core" for tool in core}
    found = []
    for module in loaded() if among is None else among:
        for tool in module.TOOLS:
            if tool["name"] in taken:
                raise AddonError("the tool %s is offered by %s and by %s. Uninstall one, or the order they were found in would decide which one runs." % (tool["name"], taken[tool["name"]], module.__name__))
            taken[tool["name"]] = module.__name__
            found.append(tool)
    return found


def dispatch(runtime, name, arguments, ask):
    """One tool call, to the add-on that has the tool, or None when none does."""
    for module in loaded():
        if any(tool["name"] == name for tool in module.TOOLS):
            return module.dispatch(runtime, name, arguments, ask)
    return None
