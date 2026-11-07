"""Add-ons: what a runtime can do beyond the core, installed one by one.

The core is the rendezvous: keys, inbox, presence, the board, receipts. Other
things are add-ons, each a distribution of its own that depends on aamio and
declares an entry point in the group aamio.addons naming a module, so that
installing one is the user's choice and `pip install aamio` stays what it was.
The module says:

    NAME = "domain"               the short name, its command under aamio addon
    __version__ = "0.1.0"
    add_commands(parser)          its commands, as subparsers of aamio addon NAME
    early(args)                   an exit code for a command that needs no home, else None
    command(args, runtime)        the command, with the runtime: an exit code
    TOOLS                         its MCP tools, as aamio.mcp_server.tool makes them
    dispatch(runtime, name, arguments, ask)   one tool call, or None for a tool not its own

The core owns the names. Two add-ons with one short name, or two tools with one
name, stop the start and say so, rather than let the order they were found in
decide which one runs. An add-on that cannot be imported stops the start too:
a broken install is not a quiet absence. For a checkout that is not installed,
AAMIO_ADDONS names the modules to load, comma separated; installed add-ons are
found by themselves.
"""

import argparse
import importlib
import os
from importlib import metadata

GROUP = "aamio.addons"
HOOKS = ("NAME", "__version__", "add_commands", "early", "command", "TOOLS", "dispatch")

_cache = {"key": None, "addons": []}


class AddonError(RuntimeError):
    """An add-on that cannot be used as one, with what to do about it."""


def _import(point, name):
    try:
        return point.load() if point is not None else importlib.import_module(name)
    except Exception as error:
        raise AddonError("the add-on %s could not be loaded: %s: %s. Reinstall it, or uninstall it to go on without it." % (name, error.__class__.__name__, error)) from None


def _found():
    modules = []
    for point in metadata.entry_points(group=GROUP):
        modules.append(_import(point, point.value))
    for name in (os.environ.get("AAMIO_ADDONS") or "").split(","):
        if name.strip():
            modules.append(_import(None, name.strip()))
    return modules


def loaded():
    """Every add-on this installation has, checked once for what an add-on must have and for its name."""
    key = os.environ.get("AAMIO_ADDONS") or ""
    if _cache["key"] != key:
        found = []
        for module in _found():
            if module in found:
                continue
            for hook in HOOKS:
                if not hasattr(module, hook):
                    raise AddonError("%s cannot be used as an add-on: it has no %s. Reinstall it, or uninstall it to go on without it." % (module.__name__, hook))
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
        _cache.update(key=key, addons=found)
    return list(_cache["addons"])


def by_name(name):
    for module in loaded():
        if module.NAME == name:
            return module
    raise LookupError("no add-on is called %s" % name)


def commands_of(module):
    """The commands an add-on adds, read out of the parser it builds."""
    parser = argparse.ArgumentParser(prog="aamio addon " + module.NAME)
    module.add_commands(parser)
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            return sorted(action.choices)
    return []


def describe():
    """What aamio addon list answers: each add-on, its version, its commands and its tools."""
    rows = [{"name": module.NAME, "version": module.__version__, "module": module.__name__, "commands": commands_of(module), "mcp_tools": [tool["name"] for tool in module.TOOLS]} for module in loaded()]
    answer = {"addons": rows}
    if not rows:
        answer["note"] = "No add-on is installed. An add-on is a package of its own, installed beside aamio: pip install \"aamio[domain-keys]\" for Domain Keys."
    return answer


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
