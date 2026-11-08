"""Add-ons: found by themselves, run only when named, and never a quiet absence.

The core finds an add-on through its entry point, or through AAMIO_ADDONS for a
checkout that is not installed, puts its commands under aamio addon NAME and
its tools beside the core's. Installed is not enabled: an installed add-on is
listed from its metadata and nothing of it runs until `aamio addon enable`
names it, in the home the command was given, by the distribution and not by the
short name. What is tried here is the registry around that: nothing installed
is said plainly, two add-ons with one name or one tool name stop the start with
both names, an add-on that cannot be loaded stops it with the reason and can
still be listed and disabled, and the three ways into the runtime an add-on has.
"""

import io
import json
import os
import sys
import time
import textwrap

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "addons", "domain-keys", "src"))

from aamio import addon_process, addons, cli, mcp_server
from aamio.runtime import Runtime

DEMO = '''
NAME = %(name)r
__version__ = "0.0.1"
TOOLS = [{"name": %(tool)r, "description": "answers pong", "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False}}]


def add_commands(parser):
    sub = parser.add_subparsers(dest="demo_command", required=True)
    sub.add_parser("ping")
    sub.add_parser("dry")


def early(args):
    if args.demo_command == "dry":
        print('{"dry": true}')
        return 7
    return None


def command(args, runtime):
    print('{"pong": true, "home": %%s}' %% ("null" if runtime is None else '"held"'))
    return 0


def dispatch(runtime, name, arguments, ask):
    if name == TOOLS[0]["name"]:
        return {"content": [{"type": "text", "text": "pong"}], "structuredContent": {"pong": True}, "isError": False}
    return None
'''


def write_addon(folder, module, name="demo", tool="aamio_addon_demo_ping", text=None):
    folder.mkdir(exist_ok=True)
    (folder / (module + ".py")).write_text(textwrap.dedent(text if text is not None else DEMO % {"name": name, "tool": tool}), encoding="utf-8")


@pytest.fixture
def loaded(tmp_path, monkeypatch):
    """Add-ons by module name, written to a folder of their own, as AAMIO_ADDONS names them."""
    monkeypatch.syspath_prepend(str(tmp_path / "addons"))
    # Each test writes modules of these names anew, so none may come from the
    # test before: not from Python's import cache, and not from the registry's.
    for module in ("demo_addon", "other_addon", "shadow_addon", "broken_addon", "half_addon"):
        sys.modules.pop(module, None)
    monkeypatch.setattr(addons, "_cache", {})
    # A home of this test's own, and nothing installed: what pip put on this
    # machine's path is not under test here.
    monkeypatch.setenv("AAMIO_HOME", str(tmp_path / "home"))
    monkeypatch.setattr(addons, "_home", None)
    monkeypatch.setattr(addons, "installed", lambda: [])

    def use(*modules):
        monkeypatch.setenv("AAMIO_ADDONS", ",".join(modules))

    return use


def main(argv, monkeypatch):
    out, err = io.StringIO(), io.StringIO()
    monkeypatch.setattr(sys, "stdout", out)
    monkeypatch.setattr(sys, "stderr", err)
    try:
        code = cli.main(argv)
    except SystemExit as stop:
        code = stop.code
    return code, out.getvalue(), err.getvalue()


def test_nothing_installed_is_said_and_the_core_is_whole(loaded, monkeypatch):
    loaded()
    code, out, _ = main(["addon", "list"], monkeypatch)
    said = json.loads(out)

    assert code == 0 and said["addons"] == [] and "No add-on is installed" in said["note"] and "aamio[domain-keys]" in said["note"]
    assert mcp_server.tools() == mcp_server.TOOLS and len(mcp_server.TOOLS) == 24
    code, _, err = main(["addon", "domain", "list"], monkeypatch)
    assert code == 2 and "invalid choice: 'domain'" in err, "an add-on that is not installed is not a command"


def test_an_add_on_is_listed_once_with_its_commands_and_tools(tmp_path, loaded):
    write_addon(tmp_path / "addons", "demo_addon")
    loaded("demo_addon", "demo_addon")

    said = addons.describe()

    assert said["addons"] == [{"name": "demo", "distribution": None, "enabled": True, "named_in": "AAMIO_ADDONS", "version": "0.0.1", "contract": 1, "module": "demo_addon", "commands": ["dry", "ping"], "mcp_tools": ["aamio_addon_demo_ping"]}]
    assert "note" not in said
    assert [t["name"] for t in mcp_server.tools()] == [t["name"] for t in mcp_server.TOOLS] + ["aamio_addon_demo_ping"]


def test_its_commands_run_under_aamio_addon_name(tmp_path, loaded, monkeypatch):
    write_addon(tmp_path / "addons", "demo_addon")
    loaded("demo_addon")

    code, out, _ = main(["--home", str(tmp_path / "home"), "--host", "https://fake.test", "--no-archive", "addon", "demo", "ping"], monkeypatch)
    assert code == 0 and json.loads(out) == {"pong": True, "home": "held"}, "with the runtime, as the command asked"
    code, out, _ = main(["--home", str(tmp_path / "nowhere"), "--no-archive", "addon", "demo", "dry"], monkeypatch)
    assert code == 7 and json.loads(out) == {"dry": True} and not os.path.exists(str(tmp_path / "nowhere")), "early: before any home is made or locked"


def test_its_tool_is_called_through_the_server(tmp_path, loaded):
    write_addon(tmp_path / "addons", "demo_addon")
    loaded("demo_addon")

    reply = mcp_server.handle(None, {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "aamio_addon_demo_ping", "arguments": {}}})
    assert reply["result"]["structuredContent"] == {"pong": True} and reply["result"]["isError"] is False
    listed = mcp_server.handle(None, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    assert listed["result"]["tools"][-1]["name"] == "aamio_addon_demo_ping"
    unknown = mcp_server.handle(None, {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "aamio_addon_nothing", "arguments": {}}})
    assert unknown["error"]["code"] == -32602


def test_two_add_ons_with_one_name_stop_the_start_with_both_names(tmp_path, loaded, monkeypatch):
    write_addon(tmp_path / "addons", "demo_addon")
    write_addon(tmp_path / "addons", "other_addon", tool="aamio_addon_other_ping")
    loaded("demo_addon", "other_addon")

    code, out, _ = main(["addon", "list"], monkeypatch)
    err = json.loads(out)["error"]
    assert code == 1 and "two add-ons are called demo" in err and "demo_addon" in err and "other_addon" in err and "Uninstall one" in err, "the list answers with the error, so it is never a quiet absence"
    assert "note" not in json.loads(out), "and does not also say that nothing is installed"
    with pytest.raises(addons.AddonError):
        mcp_server.tools()


def test_a_tool_name_taken_already_stops_the_start(tmp_path, loaded, monkeypatch):
    write_addon(tmp_path / "addons", "demo_addon")
    write_addon(tmp_path / "addons", "other_addon", name="other", tool="aamio_addon_demo_ping")
    loaded("demo_addon", "other_addon")
    code, out, _ = main(["addon", "list"], monkeypatch)
    err = json.loads(out)["error"]
    assert code == 1 and "aamio_addon_demo_ping" in err and "demo_addon" in err and "other_addon" in err

    write_addon(tmp_path / "addons", "shadow_addon", name="shadow", tool="aamio_whoami")
    loaded("shadow_addon")
    code, out, _ = main(["addon", "list"], monkeypatch)
    err = json.loads(out)["error"]
    assert code == 1 and "aamio_whoami" in err and "the core" in err, "nor may an add-on stand in front of the core's tools"


def test_an_add_on_that_cannot_be_loaded_is_not_a_quiet_absence(tmp_path, loaded, monkeypatch):
    write_addon(tmp_path / "addons", "broken_addon", text="raise ImportError('no such library')\n")
    loaded("broken_addon")
    code, out, _ = main(["addon", "list"], monkeypatch)
    err = json.loads(out)["error"]
    assert code == 1 and "broken_addon could not be loaded" in err and "ImportError" in err and "Reinstall it, or uninstall it" in err

    loaded("no_such_module_anywhere")
    code, _, err = main(["whoami"], monkeypatch)
    assert code == 1 and "no_such_module_anywhere could not be loaded" in err, "and every command stops, not only the add-on's"

    write_addon(tmp_path / "addons", "half_addon", text='NAME = "half"\n__version__ = "0"\n')
    loaded("half_addon")
    code, out, _ = main(["addon", "list"], monkeypatch)
    assert code == 1 and "half_addon cannot be used as an add-on: it has no add_commands" in json.loads(out)["error"]


def test_the_domain_keys_add_on_is_one(monkeypatch):
    monkeypatch.setenv("AAMIO_ADDONS", "aamio_domain_keys")
    said = addons.describe()["addons"]

    assert [row["name"] for row in said] == ["domain"] and said[0]["mcp_tools"] == ["aamio_addon_domain_check"]
    assert said[0]["commands"] == ["allow", "check", "file", "forget", "list", "validate"]
    code, out, _ = main(["addon", "domain", "--help"], monkeypatch)
    assert code == 0 and "aamio addon domain check DOMAIN --partner NAME" in out


def test_the_three_ways_into_the_runtime(tmp_path):
    runtime = Runtime(home=str(tmp_path / "home"), host="https://fake.test", archive=False)
    try:
        assert runtime.home_file("mine.json") == os.path.join(runtime.home, "mine.json")
        runtime.save_json("mine.json", {"kept": True})
        with open(runtime.home_file("mine.json"), encoding="utf-8") as handle:
            assert json.load(handle) == {"kept": True}

        channel = runtime.ensure_inbox if False else None  # no network here: a channel is made by hand below
        from aamio.runtime import Channel

        one = Channel("one", "a" * 26, "b" * 20, 10 ** 10)
        two = Channel("two", "c" * 26, "d" * 20, 10 ** 10)
        runtime.channels.update(one=one, two=two)
        one.observed[1] = {"seq": 1, "sha256": "e" * 64, "verified": True, "from_key": "K1"}
        one.observed[2] = {"seq": 2, "sha256": "e" * 64, "verified": False, "from_key": "K2"}
        two.observed[1] = {"seq": 1, "sha256": "e" * 64, "verified": True, "from_key": "K1"}
        two.observed[2] = {"seq": 2, "sha256": "e" * 64, "verified": True, "from_key": "K3"}
        two.observed[3] = {"seq": 3, "sha256": "f" * 64, "verified": True, "from_key": "K4"}

        assert runtime.verified_signers("e" * 64) == ["K1", "K3"], "verified only, once each, across every channel"
        assert runtime.verified_signers("f" * 64) == ["K4"] and runtime.verified_signers("0" * 64) == []
    finally:
        runtime.close()


# ------------------------------------------------------- installed, enabled

@pytest.fixture
def site(tmp_path, monkeypatch):
    """Installed add-ons: a module and a .dist-info for each, as pip leaves them, on the path, with a home of this test's own.

    Each module writes a marker when it is imported, so a test can say whether
    any of it ran.
    """
    folder = tmp_path / "site"
    folder.mkdir()
    monkeypatch.syspath_prepend(str(folder))
    monkeypatch.setenv("AAMIO_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("AAMIO_ADDONS", "")
    monkeypatch.setattr(addons, "_home", None)
    monkeypatch.setattr(addons, "_cache", {})
    for module in ("demo_pkg", "other_pkg", "wrong_pkg", "broken_pkg", "list_pkg", "twice_pkg"):
        sys.modules.pop(module, None)

    def install(distribution, module, name="demo", version="0.0.1", tool="aamio_addon_demo_ping", text=None, module_name=None):
        marker = folder / (module + ".ran")
        body = "open(%r, 'w').close()\n" % str(marker) + textwrap.dedent(text if text is not None else DEMO % {"name": module_name or name, "tool": tool})
        (folder / (module + ".py")).write_text(body, encoding="utf-8")
        info = folder / ("%s-%s.dist-info" % (distribution.replace("-", "_"), version))
        info.mkdir()
        (info / "METADATA").write_text("Metadata-Version: 2.1\nName: %s\nVersion: %s\n" % (distribution, version), encoding="utf-8")
        (info / "entry_points.txt").write_text("[aamio.addons]\n%s = %s\n" % (name, module), encoding="utf-8")
        return marker

    return install


def enabled_in(tmp_path):
    with open(tmp_path / "home" / "addons.json", encoding="utf-8") as handle:
        return json.load(handle)


def test_installed_is_not_enabled(site, monkeypatch):
    ran = site("demo-pkg", "demo_pkg")

    code, out, _ = main(["addon", "list"], monkeypatch)
    said = json.loads(out)
    assert code == 0 and said["addons"] == [{"name": "demo", "version": "0.0.1", "distribution": "demo-pkg", "enabled": False, "contract": 1, "fix": "aamio addon enable demo"}]
    assert "note" not in said and not ran.exists(), "listed from its metadata: nothing of it ran"
    assert len(mcp_server.tools()) == 24, "and the local MCP has the core's tools and no more"
    code, _, err = main(["addon", "demo", "ping"], monkeypatch)
    assert code == 2 and "the add-on demo is installed and not enabled" in err and "aamio addon enable demo" in err and not ran.exists()


def test_enable_lets_it_run_and_disable_takes_it_out(site, monkeypatch, tmp_path):
    ran = site("demo-pkg", "demo_pkg")

    code, out, _ = main(["addon", "enable", "demo"], monkeypatch)
    said = json.loads(out)
    assert code == 0 and said["addons"][0]["enabled"] is True and said["addons"][0]["commands"] == ["dry", "ping"] and said["addons"][0]["mcp_tools"] == ["aamio_addon_demo_ping"]
    assert "demo-pkg runs here from now on" in said["note"] and "with its key and home" in said["note"], "what was agreed to is said"
    assert enabled_in(tmp_path) == {"enabled": ["demo-pkg"]} and ran.exists(), "recorded by distribution, and loaded"
    assert [tool["name"] for tool in mcp_server.tools()][-1] == "aamio_addon_demo_ping"
    code, out, _ = main(["--host", "https://fake.test", "--no-archive", "addon", "demo", "ping"], monkeypatch)
    assert code == 0 and json.loads(out) == {"pong": True, "home": "held"}

    code, out, _ = main(["addon", "enable", "Demo_Pkg"], monkeypatch)
    assert code == 0 and enabled_in(tmp_path) == {"enabled": ["demo-pkg"]}, "by distribution too, as pip spells it, and once is once"

    code, out, _ = main(["addon", "disable", "demo"], monkeypatch)
    said = json.loads(out)
    assert code == 0 and said["addons"][0]["enabled"] is False and said["addons"][0]["fix"] == "aamio addon enable demo" and enabled_in(tmp_path) == {"enabled": []}
    assert len(mcp_server.tools()) == 24
    code, out, _ = main(["addon", "disable", "demo"], monkeypatch)
    assert code == 0 and "demo was not enabled" in json.loads(out)["note"]


def test_the_choice_is_the_home_s(site, monkeypatch, tmp_path):
    site("demo-pkg", "demo_pkg")

    code, out, _ = main(["--home", str(tmp_path / "a"), "addon", "enable", "demo"], monkeypatch)
    assert code == 0 and json.loads(out)["addons"][0]["enabled"] is True
    code, out, _ = main(["--home", str(tmp_path / "b"), "addon", "list"], monkeypatch)
    assert code == 0 and json.loads(out)["addons"][0]["enabled"] is False, "enabled in one home, not in another"
    code, out, _ = main(["--home", str(tmp_path / "a"), "addon", "list"], monkeypatch)
    assert json.loads(out)["addons"][0]["enabled"] is True
    assert not os.path.exists(str(tmp_path / "b")), "listing made no home"


def test_the_choice_is_the_distribution_s_not_the_name_s(site, monkeypatch):
    site("demo-pkg", "demo_pkg")
    site("other-pkg", "other_pkg", tool="aamio_addon_other_ping")

    code, _, err = main(["addon", "enable", "demo"], monkeypatch)
    assert code == 2 and "two installed add-ons are called demo: demo-pkg and other-pkg" in err and "by its distribution name" in err
    code, out, _ = main(["addon", "list"], monkeypatch)
    rows = sorted(json.loads(out)["addons"], key=lambda row: row["distribution"])
    assert [row["fix"] for row in rows] == ["aamio addon enable demo-pkg", "aamio addon enable other-pkg"], "each by its distribution, since the name says nothing"

    code, out, _ = main(["addon", "enable", "demo-pkg"], monkeypatch)
    rows = sorted(json.loads(out)["addons"], key=lambda row: row["distribution"])
    assert code == 0 and [(row["distribution"], row["enabled"]) for row in rows] == [("demo-pkg", True), ("other-pkg", False)]
    assert [tool["name"] for tool in mcp_server.tools()][-1:] == ["aamio_addon_demo_ping"], "the one chosen runs; the other, with the same name, does not inherit the choice"
    code, _, err = main(["addon", "enable", "nothing"], monkeypatch)
    assert code == 2 and "no installed add-on is called nothing" in err and "aamio addon list" in err


def test_enable_refuses_what_does_not_load(site, monkeypatch, tmp_path):
    site("broken-pkg", "broken_pkg", name="broken", text="raise ImportError('no such library')\n")
    site("wrong-pkg", "wrong_pkg", name="right", module_name="demo")
    site("list-pkg", "list_pkg", name="list", tool="aamio_addon_list_ping")

    code, _, err = main(["addon", "enable", "broken"], monkeypatch)
    assert code == 2 and "the add-on broken-pkg could not be loaded: ImportError" in err and "aamio addon disable broken-pkg" in err
    code, _, err = main(["addon", "enable", "right"], monkeypatch)
    assert code == 2 and "wrong-pkg is called right in its metadata and demo in its module" in err
    code, _, err = main(["addon", "enable", "list-pkg"], monkeypatch)
    assert code == 2 and "cannot be called list: that is a command of aamio addon itself" in err
    assert not os.path.exists(str(tmp_path / "home" / "addons.json")), "none was recorded"
    assert len(mcp_server.tools()) == 24


def test_a_broken_enabled_add_on_is_listed_and_can_be_disabled(site, monkeypatch, tmp_path):
    site("demo-pkg", "demo_pkg")
    assert main(["addon", "enable", "demo"], monkeypatch)[0] == 0
    # The next version of it does not import.
    (tmp_path / "site" / "demo_pkg.py").write_text("raise ImportError('no such library')\n", encoding="utf-8")
    sys.modules.pop("demo_pkg", None)
    addons._cache.clear()

    code, _, err = main(["whoami"], monkeypatch)
    assert code == 1 and "the add-on demo-pkg could not be loaded" in err and "aamio addon disable demo-pkg" in err, "every command stops, and says how to go on"
    code, out, _ = main(["addon", "list"], monkeypatch)
    said = json.loads(out)
    assert code == 1 and said["addons"][0]["enabled"] is True and said["addons"][0]["loaded"] is False and "demo-pkg could not be loaded" in said["error"], "the list still answers, from the metadata"
    code, out, _ = main(["addon", "disable", "demo"], monkeypatch)
    assert code == 0 and json.loads(out)["addons"][0]["enabled"] is False and enabled_in(tmp_path) == {"enabled": []}
    assert main(["addon", "list"], monkeypatch)[0] == 0 and len(mcp_server.tools()) == 24


def test_what_the_file_says_and_cannot_say(site, monkeypatch, tmp_path):
    site("demo-pkg", "demo_pkg")
    (tmp_path / "home").mkdir()
    (tmp_path / "home" / "addons.json").write_text('{"enabled": ["gone-pkg"]}', encoding="utf-8")

    code, out, _ = main(["addon", "list"], monkeypatch)
    said = json.loads(out)
    assert code == 0 and said["enabled_but_not_installed"] == ["gone-pkg"] and said["addons"][0]["enabled"] is False, "enabled once, uninstalled since: said, and not a failure"
    code, out, _ = main(["addon", "disable", "gone-pkg"], monkeypatch)
    assert code == 0 and "enabled_but_not_installed" not in json.loads(out) and enabled_in(tmp_path) == {"enabled": []}

    (tmp_path / "home" / "addons.json").write_text("{not json", encoding="utf-8")
    addons._cache.clear()
    code, _, err = main(["whoami"], monkeypatch)
    assert code == 1 and "addons.json could not be read" in err and "Fix or remove the file" in err
    code, _, err = main(["addon", "list"], monkeypatch)
    assert code == 1 and "addons.json could not be read" in err
    (tmp_path / "home" / "addons.json").write_text('{"enabled": "demo-pkg"}', encoding="utf-8")
    code, _, err = main(["whoami"], monkeypatch)
    assert code == 1 and "is not a list of enabled add-ons" in err


def test_installed_and_named_in_the_environment_is_one_row(site, monkeypatch):
    site("demo-pkg", "demo_pkg")
    monkeypatch.setenv("AAMIO_ADDONS", "demo_pkg")

    code, out, _ = main(["addon", "list"], monkeypatch)
    said = json.loads(out)
    assert code == 0 and len(said["addons"]) == 1 and said["addons"][0]["enabled"] is True and said["addons"][0]["named_in"] == "AAMIO_ADDONS" and said["addons"][0]["distribution"] == "demo-pkg"
    assert said["addons"][0]["commands"] == ["dry", "ping"], "a checkout that is also installed: running because it was named, said once"


# --------------------------------------------- the review of the enable step

def test_the_server_uses_the_home_of_its_runtime(site, monkeypatch, tmp_path):
    """Enabled in home a only: a server built on a runtime for home b offers and runs the core alone, whatever the command line's home was."""
    site("demo-pkg", "demo_pkg")
    assert main(["--home", str(tmp_path / "a"), "addon", "enable", "demo"], monkeypatch)[0] == 0
    a = Runtime(home=str(tmp_path / "a"), host="https://fake.test", archive=False)
    b = Runtime(home=str(tmp_path / "b"), host="https://fake.test", archive=False)
    try:
        listing = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
        call = {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "aamio_addon_demo_ping", "arguments": {}}}
        for _ in range(2):
            assert len(mcp_server.handle(b, listing)["result"]["tools"]) == 24, "the server on b, where nothing is enabled, offers the core's tools"
            assert mcp_server.handle(a, listing)["result"]["tools"][-1]["name"] == "aamio_addon_demo_ping", "the server on a offers the add-on's, in alternation"
        assert mcp_server.handle(b, call)["error"]["code"] == -32602, "and a call through b is refused as a tool nobody has"
        assert mcp_server.handle(a, call)["result"]["structuredContent"] == {"pong": True}
    finally:
        a.close()
        b.close()


def test_help_and_bad_arguments_change_nothing(site, monkeypatch, tmp_path):
    site("demo-pkg", "demo_pkg")
    assert main(["addon", "enable", "demo"], monkeypatch)[0] == 0
    path = tmp_path / "home" / "addons.json"
    before = path.read_bytes()

    code, out, _ = main(["addon", "disable", "demo", "--help"], monkeypatch)
    assert code == 0 and "usage: aamio addon disable" in out and path.read_bytes() == before, "help is help, not a disable"
    code, out, _ = main(["addon", "disable", "--help"], monkeypatch)
    assert code == 0 and "usage:" in out and path.read_bytes() == before
    code, _, err = main(["addon", "disable", "demo", "extra"], monkeypatch)
    assert code == 2 and "unrecognized arguments" in err and path.read_bytes() == before
    code, _, _ = main(["addon", "disable", "demo", "--bogus"], monkeypatch)
    assert code == 2 and path.read_bytes() == before
    code, out, _ = main(["addon", "enable", "demo", "--help"], monkeypatch)
    assert code == 0 and "usage: aamio addon enable" in out and path.read_bytes() == before
    code, _, _ = main(["addon", "enable", "demo", "--bogus"], monkeypatch)
    assert code == 2 and path.read_bytes() == before
    code, _, err = main(["addon", "disable", "demo", "--home"], monkeypatch)
    assert code == 2 and "--home" in err and "expected one argument" in err and path.read_bytes() == before, "--home without a folder is not the default home"
    code, _, err = main(["--home=", "addon", "disable", "demo"], monkeypatch)
    assert code == 2 and "--home needs a value" in err and path.read_bytes() == before, "an empty --home is not the default home either"
    code, _, err = main(["--home", "", "addon", "enable", "demo"], monkeypatch)
    assert code == 2 and "--home needs a value" in err and path.read_bytes() == before
    code, _, err = main(["addon", "disable", "demo", "--home", " "], monkeypatch)
    assert code == 2 and "--home needs a value" in err and path.read_bytes() == before
    code, _, err = main(["--host=", "addon", "list"], monkeypatch)
    assert code == 2 and "--host needs a value" in err
    other = tmp_path / "other-home"
    code, _, _ = main(["--home", str(other), "addon", "enable", "demo"], monkeypatch)
    assert code == 0 and json.loads((other / "addons.json").read_text(encoding="utf-8")) == {"enabled": ["demo-pkg"]} and path.read_bytes() == before, "a path names a home, and that home is the one that changes"

    # Once the enabled add-on is broken, the shortcut past the loading is exactly `addon disable NAME`.
    (tmp_path / "site" / "demo_pkg.py").write_text("raise ImportError('no such library')\n", encoding="utf-8")
    sys.modules.pop("demo_pkg", None)
    addons._cache.clear()
    code, _, err = main(["addon", "disable", "demo", "--help"], monkeypatch)
    assert code == 1 and "could not be loaded" in err and path.read_bytes() == before, "help with a broken add-on is the error, and no change"
    assert main(["addon", "disable", "demo"], monkeypatch)[0] == 0 and path.read_bytes() != before


def test_two_changes_at_once_keep_both(site, monkeypatch, tmp_path):
    """Two commands enable two add-ons at the same moment: each takes its turn, and both stand."""
    import subprocess

    site("demo-pkg", "demo_pkg")
    site("other-pkg", "other_pkg", name="other", tool="aamio_addon_other_ping")
    env = dict(os.environ, PYTHONPATH=os.pathsep.join([os.path.join(os.path.dirname(__file__), "..", "src"), str(tmp_path / "site")]), AAMIO_HOME=str(tmp_path / "home"), AAMIO_ADDONS="")
    program = "import sys; from aamio import cli; raise SystemExit(cli.main(sys.argv[1:]))"
    for _ in range(3):
        for name in ("demo", "other"):
            main(["addon", "disable", name], monkeypatch)
        first = subprocess.Popen([sys.executable, "-c", program, "addon", "enable", "demo"], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        second = subprocess.Popen([sys.executable, "-c", program, "addon", "enable", "other"], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        errors = [proc.communicate(timeout=120)[1].decode("utf-8", "replace") for proc in (first, second)]
        assert first.returncode == 0 and second.returncode == 0, errors
        assert sorted(enabled_in(tmp_path)["enabled"]) == ["demo-pkg", "other-pkg"], "both changes stand"
    addons._cache.clear()
    assert len(mcp_server.tools()) == 26


def test_a_change_waits_for_another_and_says_so(site, monkeypatch, tmp_path):
    from aamio import storage

    site("demo-pkg", "demo_pkg")
    (tmp_path / "home").mkdir()
    held = storage.hold(str(tmp_path / "home" / "addons.json.lock"))
    assert held is not None
    monkeypatch.setattr(addons, "LOCK_WAIT", 0.3)
    try:
        code, _, err = main(["addon", "enable", "demo"], monkeypatch)
        assert code == 2 and "addons.json is being changed by another aamio" in err and "Nothing changed" in err and not os.path.exists(str(tmp_path / "home" / "addons.json"))
    finally:
        storage.let_go(held)
    assert main(["addon", "enable", "demo"], monkeypatch)[0] == 0 and enabled_in(tmp_path) == {"enabled": ["demo-pkg"]}, "and once the other is done, the change goes through"


def test_enable_refuses_an_add_on_whose_commands_do_not_build(site, monkeypatch, tmp_path):
    twice = DEMO.replace('    sub.add_parser("dry")', '    sub.add_parser("dry")\n    parser.add_argument("--same")\n    parser.add_argument("--same")')
    site("twice-pkg", "twice_pkg", name="twice", tool="aamio_addon_twice_ping", text=twice % {"name": "twice", "tool": "aamio_addon_twice_ping"})

    code, _, err = main(["addon", "enable", "twice"], monkeypatch)
    assert code == 2 and "the add-on twice_pkg could not build its commands: ArgumentError" in err and "aamio addon disable twice-pkg" in err
    assert not os.path.exists(str(tmp_path / "home" / "addons.json")), "nothing was recorded"
    code, out, _ = main(["addon", "list"], monkeypatch)
    assert code == 0 and json.loads(out)["addons"][0]["enabled"] is False and len(mcp_server.tools()) == 24


def test_disable_says_when_the_environment_holds_the_add_on(site, monkeypatch, tmp_path):
    site("demo-pkg", "demo_pkg")
    monkeypatch.setenv("AAMIO_ADDONS", "demo_pkg")

    code, out, _ = main(["addon", "disable", "demo"], monkeypatch)
    said = json.loads(out)
    assert code == 0 and "demo was not enabled" in said["note"] and "demo still runs: AAMIO_ADDONS names demo_pkg" in said["note"] and "Unset AAMIO_ADDONS" in said["note"]
    assert said["addons"][0]["enabled"] is True and said["addons"][0]["named_in"] == "AAMIO_ADDONS", "and it does run"
    code, out, _ = main(["addon", "enable", "demo"], monkeypatch)
    assert code == 0 and "start it again" in json.loads(out)["note"], "a running server keeps its tools: said on enable"
    code, out, _ = main(["addon", "disable", "demo"], monkeypatch)
    said = json.loads(out)
    assert code == 0 and "demo is disabled" in said["note"] and "start it again" in said["note"] and "still runs" in said["note"]


# ------------------------------------------------------------- contract 2 --
#
# An add-on in a process of its own: the manifest says what it offers, the
# core reads it without running anything, and each call is a child process
# with one request and one answer.

PROCESS = """
import base64, json, os, sys, time
request = json.loads(sys.stdin.read())
here = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(here, "process.ran"), "a", encoding="utf-8") as marker:
    marker.write(request["kind"] + " " + request["name"] + "\\n")
if request["kind"] == "probe":
    if os.environ.get("AAMIO_TEST_PASSTHRU") is not None:
        print(json.dumps({"result": {"ok": False, "reason": "addon_failed", "fix": "the probe was given AAMIO_TEST_PASSTHRU, which only a call may get"}}))
        sys.exit(0)
    print(json.dumps({"result": {"ok": True, "name": %(name)r, "version": %(version)r, "aamio_addon": 2}}))
    sys.exit(0)
short = request["name"].rsplit("_", 1)[-1]
if short == "sleep":
    time.sleep(30)
if short == "crash":
    sys.exit(3)
if short == "garbage":
    print("not json")
    sys.exit(0)
if short == "bytes":
    print(json.dumps({"raw": base64.b64encode(b"raw\\n").decode("ascii")}))
    sys.exit(0)
if short == "fail":
    print(json.dumps({"result": {"status": "no", "fix": "x"}, "exit_code": 3, "is_error": True, "stderr": "a note from the add-on"}))
    sys.exit(3)
if short == "flood":
    sys.stdout.write("x" * 5000)
    sys.stdout.flush()
    time.sleep(5)
    sys.exit(0)
if short == "noisy":
    sys.stderr.write("y" * 5000)
    sys.stderr.flush()
    time.sleep(5)
    sys.exit(0)
if short == "spill":
    sys.stdout.write("x" * 5000)
    sys.exit(0)
if short == "grumble":
    sys.stderr.write("y" * 5000)
    sys.stderr.flush()
    print(json.dumps({"result": {"pong": True}}))
    sys.exit(0)
if short == "mutter":
    sys.stderr.write("y" * 500)
    sys.stderr.flush()
    print(json.dumps({"result": {"pong": True}}))
    sys.exit(0)
print(json.dumps({"result": {"pong": True, "name": request["name"], "arguments": request["arguments"], "subject": request["subject"], "own_key": request["own_key"], "state_dir": request["state_dir"], "home_env": os.environ.get("AAMIO_HOME"), "addon_env": os.environ.get("AAMIO_ADDON"), "secret_env": os.environ.get("AAMIO_TEST_SECRET"), "passthru_env": os.environ.get("AAMIO_TEST_PASSTHRU"), "path_env": bool(os.environ.get("PATH"))}}))
"""


def manifest_for(name, package, deadline=2, hosts=True, environment=None):
    data = {
        "aamio_addon": 2,
        "name": name,
        "version": "0.0.2",
        "process": {"python": package + ".process"},
        "deadline_seconds": deadline,
        "commands": {
            "ping": {"help": "answers pong", "arguments": [{"name": "--word", "help": "a word to carry"}]},
            "check": {"help": "a website and a partner", "arguments": [{"name": "site", "help": "the website", "host": True}, {"name": "--partner", "help": "a name in the address book", "required": True, "subject": "partner"}]},
            "file": {"help": "the runtime's own key", "needs": ["own_key"]},
            "local": {"help": "no home needed", "runtime": False, "arguments": [{"name": "path"}]},
            "sleep": {"help": "never answers"},
            "crash": {"help": "dies"},
            "garbage": {"help": "talks nonsense"},
            "bytes": {"help": "raw bytes"},
            "fail": {"help": "a refusal"},
            "flood": {"help": "writes without end"},
            "noisy": {"help": "complains without end"},
            "spill": {"help": "a big answer, at once"},
            "grumble": {"help": "too much on standard error, at once"},
            "mutter": {"help": "exactly the limit on standard error"},
        },
        "tools": [
            {"name": "aamio_addon_%s_ping" % name, "description": "answers pong", "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False}},
            {"name": "aamio_addon_%s_check" % name, "description": "a website and a subject", "inputSchema": {"type": "object", "properties": {"site": {"type": "string"}, "partner": {"type": "string"}, "message": {"type": "string"}}, "required": ["site"], "additionalProperties": False}, "host": "site", "subject": {"partner": "partner", "message": "message"}},
            {"name": "aamio_addon_%s_sleep" % name, "description": "never answers", "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False}},
        ],
    }
    if environment is not None:
        data["environment"] = environment
    if hosts:
        data["hosts"] = {"legacy_file": "old-hosts.json"}
    else:
        del data["commands"]["check"]
        data["tools"] = [data["tools"][0], data["tools"][2]]
    return data


@pytest.fixture
def process_site(tmp_path, monkeypatch):
    """A contract-2 add-on as pip leaves it: a package with its manifest and process module, and a .dist-info with the entry point, on the path of this process and of its children."""
    folder = tmp_path / "site"
    folder.mkdir()
    # An editable install's source tree, beside the site directory and on the path as its .pth puts it.
    checkout = folder / "checkout"
    checkout.mkdir()
    monkeypatch.syspath_prepend(str(folder))
    monkeypatch.syspath_prepend(str(checkout))
    monkeypatch.setenv("PYTHONPATH", str(checkout) + os.pathsep + str(folder) + os.pathsep + os.environ.get("PYTHONPATH", ""))
    monkeypatch.setenv("AAMIO_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("AAMIO_ADDONS", "")
    monkeypatch.setenv("AAMIO_TEST_SECRET", "not for the add-on")
    monkeypatch.setattr(addons, "_home", None)
    monkeypatch.setattr(addons, "_cache", {})
    monkeypatch.setattr(addon_process, "_limits", {})
    for module in ("demo2_pkg", "demo2_pkg.process"):
        sys.modules.pop(module, None)

    def install(distribution="demo2-pkg", package="demo2_pkg", name="demo2", version="0.0.2", manifest=None, entry=None, editable=False):
        pkg = (checkout if editable else folder) / package
        pkg.mkdir()
        if entry is not None and "." in entry:
            (pkg / (entry.split(".", 1)[1] + ".py")).write_text("", encoding="utf-8")
        # Importing the package leaves a marker named by the process that did it.
        (pkg / "__init__.py").write_text("import os\nopen(%r + '.imported.%%d' %% os.getpid(), 'w').close()\n" % str(pkg), encoding="utf-8")
        (pkg / "process.py").write_text(PROCESS % {"name": name, "version": version}, encoding="utf-8")
        (pkg / "aamio-addon.json").write_text(json.dumps(manifest if manifest is not None else manifest_for(name, package)), encoding="utf-8")
        stem = "%s-%s" % (distribution.replace("-", "_"), version)
        info = folder / (stem + ".dist-info")
        info.mkdir()
        (info / "METADATA").write_text("Metadata-Version: 2.1\nName: %s\nVersion: %s\n" % (distribution, version), encoding="utf-8")
        (info / "entry_points.txt").write_text("[aamio.addons]\n%s = %s\n" % (name, entry or package), encoding="utf-8")
        # RECORD as pip writes it, relative to the site directory: the package's files for an
        # ordinary install; for pip install -e, the .pth that puts the checkout on the path and
        # direct_url.json saying editable, and nothing of the source tree.
        listed = [info.name + "/METADATA", info.name + "/entry_points.txt", info.name + "/RECORD"]
        if editable:
            (folder / ("__editable__.%s.pth" % stem)).write_text(str(checkout) + "\n", encoding="utf-8")
            (info / "direct_url.json").write_text(json.dumps({"url": checkout.as_uri(), "dir_info": {"editable": True}}), encoding="utf-8")
            listed += ["__editable__.%s.pth" % stem, info.name + "/direct_url.json"]
        else:
            listed += ["%s/%s" % (package, item.name) for item in sorted(pkg.iterdir())]
        (info / "RECORD").write_text("".join("%s,,\n" % item for item in listed), encoding="utf-8")
        return pkg / "process.ran", pkg.parent / ("%s.imported.%d" % (package, os.getpid()))

    return install


def test_contract_two_is_listed_from_its_manifest_and_runs_nothing(process_site, monkeypatch, tmp_path):
    ran, imported = process_site()
    code, out, _ = main(["addon", "list"], monkeypatch)
    said = json.loads(out)
    assert code == 0 and said["addons"] == [{"name": "demo2", "version": "0.0.2", "distribution": "demo2-pkg", "enabled": False, "contract": 2, "fix": "aamio addon enable demo2"}]
    assert not ran.exists() and not imported.exists(), "listed from the manifest: nothing of it ran, here or in a process of its own"
    assert len(mcp_server.tools()) == 24
    code, _, err = main(["addon", "demo2", "ping"], monkeypatch)
    assert code == 2 and "the add-on demo2 is installed and not enabled" in err and not ran.exists()


def test_contract_two_enable_probes_and_the_commands_go_through_the_process(process_site, monkeypatch, tmp_path):
    ran, imported = process_site()
    code, out, _ = main(["addon", "enable", "demo2"], monkeypatch)
    said = json.loads(out)
    assert code == 0 and ran.read_text(encoding="utf-8") == "probe probe\n", "enable asked the process who it is, and nothing else of it ran"
    row = said["addons"][0]
    assert row["enabled"] is True and row["contract"] == 2 and row["version"] == "0.0.2"
    assert row["commands"] == ["allow", "bytes", "check", "crash", "fail", "file", "flood", "forget", "garbage", "grumble", "list", "local", "mutter", "noisy", "ping", "sleep", "spill"], "the manifest's commands, and the three the core gives an add-on with hosts"
    assert row["mcp_tools"] == ["aamio_addon_demo2_ping", "aamio_addon_demo2_check", "aamio_addon_demo2_sleep"]
    assert "a process of its own" in said["note"] and "never the home's key" in said["note"]
    assert enabled_in(tmp_path) == {"enabled": ["demo2-pkg"]} and not imported.exists(), "recorded by distribution, and this process imported none of it"

    code, out, _ = main(["addon", "demo2", "--help"], monkeypatch)
    assert code == 0 and "ping" in out and "allow" in out and ran.read_text(encoding="utf-8") == "probe probe\n", "help comes from the manifest"

    code, out, err = main(["addon", "demo2", "ping", "--word", "hi"], monkeypatch)
    got = json.loads(out)
    assert code == 0 and got["pong"] is True and got["arguments"] == {"word": "hi"} and got["subject"] is None and got["own_key"] is None
    assert got["state_dir"] == os.path.join(str(tmp_path / "home"), "addons", "demo2") and os.path.isdir(got["state_dir"]), "a directory of its own under the home"
    assert got["home_env"] is None and got["addon_env"] == "2", "the process sees no AAMIO_HOME, and knows what it is"
    assert got["secret_env"] is None and got["path_env"] is True, "a token in the user's environment is not handed on; the path is"
    assert ran.read_text(encoding="utf-8") == "probe probe\ncommand ping\n"

    runtime = Runtime(home=str(tmp_path / "home"), host="https://fake.test", archive=False)
    try:
        own = runtime.keys.public
    finally:
        runtime.close()
    code, out, _ = main(["addon", "demo2", "file"], monkeypatch)
    assert code == 0 and json.loads(out)["own_key"] == own, "needs own_key gives the public key, and nothing else of the key"

    code, out, err = main(["addon", "demo2", "fail"], monkeypatch)
    assert code == 3 and json.loads(out) == {"status": "no", "fix": "x"} and "a note from the add-on" in err, "the add-on's result, code and note come back as they are"

    code, out, _ = main(["addon", "demo2", "bytes"], monkeypatch)
    assert code == 0 and out == "raw\n", "raw bytes reach standard output as they are"

    code, out, _ = main(["addon", "demo2", "local", "somewhere"], monkeypatch)
    got = json.loads(out)
    assert code == 0 and got["state_dir"] is None and got["arguments"] == {"path": "somewhere"}, "a command that needs no home runs in the process too, with no directory"


def test_contract_two_timeout_crash_and_garbage_leave_the_server_standing(process_site, monkeypatch, tmp_path):
    process_site()
    assert main(["addon", "enable", "demo2"], monkeypatch)[0] == 0
    started = time.monotonic()
    code, out, _ = main(["addon", "demo2", "sleep"], monkeypatch)
    said = json.loads(out)
    assert code == 5 and said["status"] == "unreachable" and said["reason"] == "addon_timeout" and "2 seconds" in said["fix"] and said["addon"] == "demo2"
    assert time.monotonic() - started < 15, "stopped at the deadline, not when it felt like answering"
    code, out, _ = main(["addon", "demo2", "crash"], monkeypatch)
    said = json.loads(out)
    assert code == 5 and said["reason"] == "addon_failed" and "code 3" in said["fix"]
    code, out, _ = main(["addon", "demo2", "garbage"], monkeypatch)
    assert code == 5 and json.loads(out)["reason"] == "addon_failed"
    # The acceptance from the review of 8 November: a tool that hangs is stopped
    # at its deadline, and the same server answers the next request.
    runtime = Runtime(home=str(tmp_path / "home"), host="https://fake.test", archive=False)
    try:
        reply = mcp_server.handle(runtime, {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "aamio_addon_demo2_sleep", "arguments": {}}})
        assert reply["result"]["isError"] is True and reply["result"]["structuredContent"]["reason"] == "addon_timeout"
        listed = mcp_server.handle(runtime, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        assert len(listed["result"]["tools"]) == 27
        pong = mcp_server.handle(runtime, {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "aamio_addon_demo2_ping", "arguments": {}}})
        assert pong["result"]["isError"] is False and pong["result"]["structuredContent"]["pong"] is True
    finally:
        runtime.close()


def test_contract_two_hosts_are_the_core_s_consent(process_site, monkeypatch, tmp_path):
    ran, _ = process_site()
    assert main(["addon", "enable", "demo2"], monkeypatch)[0] == 0
    code, out, _ = main(["addon", "demo2", "check", "Example.ORG", "--partner", "bob"], monkeypatch)
    said = json.loads(out)
    assert code == 2 and said["reason"] == "host_not_allowed" and "aamio addon demo2 allow example.org" in said["fix"] and "aamio_addon_demo2_check asks them" in said["fix"]
    assert ran.read_text(encoding="utf-8") == "probe probe\n", "refused before the process started"
    key = "A" * 43
    assert main(["partner", "add", "bob", key], monkeypatch)[0] == 0
    code, out, _ = main(["addon", "demo2", "allow", "Example.ORG"], monkeypatch)
    said = json.loads(out)
    assert code == 0 and said["host"] == "example.org" and said["added"] is True and said["hosts"] == ["example.org"] and "Nothing was read now" in said["note"]
    assert json.loads((tmp_path / "home" / "addons" / "demo2.hosts.json").read_text(encoding="utf-8")) == ["example.org"], "kept beside the add-on's directory, not in it"
    code, out, _ = main(["addon", "demo2", "check", "EXAMPLE.org", "--partner", "bob"], monkeypatch)
    got = json.loads(out)
    assert code == 0 and got["arguments"] == {"site": "example.org", "partner": "bob"}
    assert got["subject"] == {"key": key, "subject_source": "partner", "partner": "bob", "signature_checked_locally": None}, "the core resolved the partner to a key; the add-on got the key and never the book"
    code, out, _ = main(["addon", "demo2", "check", "example.org", "--partner", "nobody"], monkeypatch)
    assert code == 2 and json.loads(out)["reason"] == "partner_unavailable"
    code, out, _ = main(["addon", "demo2", "allow", "localhost"], monkeypatch)
    assert code == 2 and json.loads(out)["reason"] == "invalid_host"
    code, out, _ = main(["addon", "demo2", "forget", "example.org"], monkeypatch)
    assert code == 0 and json.loads(out)["removed"] is True and json.loads(out)["hosts"] == []
    assert json.loads(main(["addon", "demo2", "list"], monkeypatch)[1]) == {"hosts": []}


def test_contract_two_reads_the_list_an_earlier_version_kept_once(process_site, monkeypatch, tmp_path):
    process_site()
    (tmp_path / "home").mkdir()
    (tmp_path / "home" / "old-hosts.json").write_text('["legacy.example"]', encoding="utf-8")
    assert main(["addon", "enable", "demo2"], monkeypatch)[0] == 0
    assert json.loads(main(["addon", "demo2", "list"], monkeypatch)[1]) == {"hosts": ["legacy.example"]}
    assert json.loads((tmp_path / "home" / "addons" / "demo2.hosts.json").read_text(encoding="utf-8")) == ["legacy.example"]
    (tmp_path / "home" / "old-hosts.json").write_text('["other.example"]', encoding="utf-8")
    assert json.loads(main(["addon", "demo2", "list"], monkeypatch)[1]) == {"hosts": ["legacy.example"]}, "read once: from then on the list is the core's"


def test_contract_two_over_mcp_asks_the_user_for_a_website(process_site, monkeypatch, tmp_path):
    process_site()
    assert main(["addon", "enable", "demo2"], monkeypatch)[0] == 0
    key = "B" * 43
    assert main(["partner", "add", "bob", key], monkeypatch)[0] == 0
    runtime = Runtime(home=str(tmp_path / "home"), host="https://fake.test", archive=False)
    try:
        manifest = addons.by_name("demo2", runtime.home)
        refused = addons.dispatch(runtime, "aamio_addon_demo2_check", {"site": "example.org", "partner": "bob"}, None)
        assert refused["isError"] is True and refused["structuredContent"]["reason"] == "host_not_allowed" and "stop this server" in refused["structuredContent"]["fix"]
        asked = []

        def declines(question, about, tool_name, key_name):
            asked.append((question, about, tool_name, key_name))
            return {"action": "decline"}

        declined = addons.dispatch(runtime, "aamio_addon_demo2_check", {"site": "example.org", "partner": "bob"}, declines)
        assert declined["structuredContent"]["reason"] == "host_declined" and asked[0][2] == "aamio_addon_demo2_check" and asked[0][3] == addon_process.HOST_QUESTION
        assert "your partner bob" in asked[0][0]["message"] and "example.org" not in asked[0][0]["message"], "the user is told who, and types the website themselves"
        other = addons.dispatch(runtime, "aamio_addon_demo2_check", {"site": "example.org", "partner": "bob"}, lambda *a: {"action": "accept", "content": {"domain": "examp1e.org"}})
        assert other["structuredContent"]["reason"] == "host_not_confirmed" and addon_process.allowed_hosts(runtime, manifest) == []
        done = addons.dispatch(runtime, "aamio_addon_demo2_check", {"site": "example.org", "partner": "bob"}, lambda *a: {"action": "accept", "content": {"domain": "Example.org"}})
        got = done["structuredContent"]
        assert done["isError"] is False and got["arguments"] == {"site": "example.org", "partner": "bob"} and got["subject"]["key"] == key
        assert addon_process.allowed_hosts(runtime, manifest) == ["example.org"], "the user's yes is kept"
        both = addons.dispatch(runtime, "aamio_addon_demo2_check", {"site": "example.org", "partner": "bob", "message": "a" * 64}, None)
        assert both["structuredContent"]["reason"] == "choose_subject"
        extra = addons.dispatch(runtime, "aamio_addon_demo2_check", {"site": "example.org", "partner": "bob", "key": "x"}, None)
        assert extra["isError"] is True and extra["structuredContent"]["given"] == ["key"], "a key beside the rest is refused, not passed over"
    finally:
        runtime.close()


def test_a_contract_this_aamio_does_not_know_is_said_and_can_be_taken_out(process_site, monkeypatch, tmp_path):
    ran, _ = process_site(manifest=dict(manifest_for("demo2", "demo2_pkg"), aamio_addon=3))
    code, out, _ = main(["addon", "list"], monkeypatch)
    row = json.loads(out)["addons"][0]
    assert code == 0 and row["enabled"] is False and "contract 3" in row["error"] and "knows 1 and 2" in row["error"] and "contract" not in row
    code, _, err = main(["addon", "enable", "demo2"], monkeypatch)
    assert code == 2 and "contract 3" in err and not ran.exists() and not (tmp_path / "home" / "addons.json").exists()
    # Enabled by an older aamio, say: the list says what is wrong, and disable works.
    (tmp_path / "home").mkdir(exist_ok=True)
    (tmp_path / "home" / "addons.json").write_text('{"enabled": ["demo2-pkg"]}', encoding="utf-8")
    code, out, _ = main(["addon", "list"], monkeypatch)
    assert code == 1 and "contract 3" in json.loads(out)["error"]
    assert main(["addon", "disable", "demo2"], monkeypatch)[0] == 0 and enabled_in(tmp_path) == {"enabled": []} and not ran.exists()


def test_enable_refuses_a_process_that_is_not_the_add_on_the_manifest_says(process_site, monkeypatch, tmp_path):
    ran, _ = process_site(manifest=dict(manifest_for("demo2", "demo2_pkg"), version="9.9.9"))
    code, _, err = main(["addon", "enable", "demo2"], monkeypatch)
    assert code == 2 and "answered the probe as demo2 0.0.2" in err and "9.9.9" in err and not (tmp_path / "home" / "addons.json").exists()
    assert ran.read_text(encoding="utf-8") == "probe probe\n"


def test_a_module_that_claims_another_contract_without_a_manifest_is_refused(site, monkeypatch, tmp_path):
    site("demo-pkg", "demo_pkg", text=DEMO % {"name": "demo", "tool": "aamio_addon_demo_ping"} + "\nCONTRACT = 2\n")
    code, _, err = main(["addon", "enable", "demo"], monkeypatch)
    assert code == 2 and "contract 2" in err and "aamio-addon.json" in err and not (tmp_path / "home" / "addons.json").exists()


def test_the_example_add_on_hello_runs_as_the_page_says(tmp_path, monkeypatch):
    """examples/hello is the example on https://aamio.at/docs/addons: a manifest and a dozen lines of process, named by AAMIO_ADDONS."""
    here = os.path.dirname(os.path.abspath(__file__))
    monkeypatch.setenv("AAMIO_ADDONS", "aamio_hello")
    monkeypatch.setenv("PYTHONPATH", os.path.join(here, "..", "examples", "hello", "src") + os.pathsep + os.environ.get("PYTHONPATH", ""))
    monkeypatch.setenv("AAMIO_HOME", str(tmp_path / "home"))
    monkeypatch.setattr(addons, "_home", None)
    monkeypatch.setattr(addons, "_cache", {})
    monkeypatch.setattr(addon_process, "_limits", {})
    code, out, _ = main(["addon", "list"], monkeypatch)
    row = json.loads(out)["addons"][0]
    assert code == 0 and row["name"] == "hello" and row["contract"] == 2 and row["commands"] == ["wave"] and row["mcp_tools"] == ["aamio_addon_hello_wave"]
    code, out, _ = main(["addon", "hello", "wave", "--to", "Kari"], monkeypatch)
    assert code == 0 and json.loads(out) == {"hello": "Kari"}
    code, out, _ = main(["addon", "hello", "wave"], monkeypatch)
    assert code == 0 and json.loads(out) == {"hello": "world"}
    runtime = Runtime(home=str(tmp_path / "home"), host="https://fake.test", archive=False)
    try:
        reply = mcp_server.handle(runtime, {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "aamio_addon_hello_wave", "arguments": {"to": "Ola"}}})
        assert reply["result"]["isError"] is False and reply["result"]["structuredContent"] == {"hello": "Ola"}
    finally:
        runtime.close()


def test_contract_two_passes_only_the_environment_the_manifest_declares(process_site, monkeypatch, tmp_path):
    ran, _ = process_site(manifest=manifest_for("demo2", "demo2_pkg", environment=["AAMIO_TEST_PASSTHRU"]))
    monkeypatch.setenv("AAMIO_TEST_PASSTHRU", "yes please")
    passive = json.loads(main(["addon", "list"], monkeypatch)[1])["addons"][0]
    assert passive["enabled"] is False and passive["environment"] == ["AAMIO_TEST_PASSTHRU"] and not ran.exists(), "the list says which variables the add-on asks for before it is enabled, running nothing"
    # The fake process refuses the probe when it is given the variable: the probe gets the short list alone.
    code, out, err = main(["addon", "enable", "demo2"], monkeypatch)
    assert code == 0, err
    assert ran.read_text(encoding="utf-8") == "probe probe\n" and "AAMIO_TEST_PASSTHRU, which its manifest asks for" in json.loads(out)["note"], "the probe ran without it, and the note names it"
    code, out, _ = main(["addon", "demo2", "ping"], monkeypatch)
    got = json.loads(out)
    assert code == 0 and got["passthru_env"] == "yes please" and got["secret_env"] is None, "what the manifest declares comes through at a call; the rest of the user's environment does not"
    assert json.loads(main(["addon", "list"], monkeypatch)[1])["addons"][0]["environment"] == ["AAMIO_TEST_PASSTHRU"], "and the list says what the add-on asked for"


def test_a_manifest_may_not_ask_for_the_home_or_use_bad_names(process_site, monkeypatch, tmp_path):
    process_site(manifest=manifest_for("demo2", "demo2_pkg", environment=["AAMIO_HOME"]))
    process_site(distribution="other-pkg", package="other_pkg", name="other", manifest=manifest_for("other", "other_pkg", environment=["lower-case"]))
    code, _, err = main(["addon", "enable", "demo2"], monkeypatch)
    assert code == 2 and "AAMIO_HOME" in err and "no add-on gets" in err
    code, _, err = main(["addon", "enable", "other"], monkeypatch)
    assert code == 2 and "not a list of variable names" in err
    assert not (tmp_path / "home" / "addons.json").exists()


def test_listing_a_nested_entry_point_imports_nothing(process_site, monkeypatch, tmp_path):
    ran, imported = process_site(entry="demo2_pkg.sub")
    code, out, _ = main(["addon", "list"], monkeypatch)
    assert code == 0 and json.loads(out)["addons"][0]["contract"] == 2
    assert "demo2_pkg" not in sys.modules and "demo2_pkg.sub" not in sys.modules and not imported.exists() and not ran.exists(), "the manifest was found without importing the parent package"
    code, out, _ = main(["addon", "enable", "demo2"], monkeypatch)
    assert code == 0 and json.loads(out)["addons"][0]["enabled"] is True and "demo2_pkg" not in sys.modules, "and enable runs the process, importing nothing here either"


def test_a_process_that_floods_is_stopped_while_it_runs(process_site, monkeypatch, tmp_path):
    process_site()
    assert main(["addon", "enable", "demo2"], monkeypatch)[0] == 0
    monkeypatch.setattr(addon_process, "MAX_ANSWER_BYTES", 1000)
    monkeypatch.setattr(addon_process, "MAX_STDERR_BYTES", 500)
    started = time.monotonic()
    code, out, _ = main(["addon", "demo2", "flood"], monkeypatch)
    said = json.loads(out)
    assert code == 5 and said["reason"] == "addon_failed" and "wrote more than the 1000 bytes" in said["fix"] and time.monotonic() - started < 4, "stopped at the size, not at the deadline"
    started = time.monotonic()
    code, out, err = main(["addon", "demo2", "noisy"], monkeypatch)
    said = json.loads(out)
    assert code == 5 and "standard error" in said["fix"] and time.monotonic() - started < 4 and len(err) < 600, "standard error has its limit too, and is not relayed when the process was stopped"
    runtime = Runtime(home=str(tmp_path / "home"), host="https://fake.test", archive=False)
    try:
        pong = mcp_server.handle(runtime, {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "aamio_addon_demo2_ping", "arguments": {}}})
        assert pong["result"]["structuredContent"]["pong"] is True, "and the next call goes through"
    finally:
        runtime.close()


def test_an_editable_install_is_found_in_its_source_tree(process_site, monkeypatch, tmp_path):
    """pip install -e: the distribution's files are the installation's own metadata, and the manifest is in the checkout."""
    ran, imported = process_site(editable=True)
    code, out, _ = main(["addon", "list"], monkeypatch)
    assert code == 0 and json.loads(out)["addons"][0] == {"name": "demo2", "version": "0.0.2", "distribution": "demo2-pkg", "enabled": False, "contract": 2, "fix": "aamio addon enable demo2"}
    assert not imported.exists() and "demo2_pkg" not in sys.modules, "found through the finder, importing nothing"
    code, out, err = main(["addon", "enable", "demo2"], monkeypatch)
    assert code == 0 and json.loads(out)["addons"][0]["enabled"] is True and ran.read_text(encoding="utf-8") == "probe probe\n", err
    code, out, _ = main(["addon", "demo2", "ping"], monkeypatch)
    assert code == 0 and json.loads(out)["pong"] is True


def test_a_manifest_the_distribution_does_not_list_is_not_its_own(process_site, monkeypatch, tmp_path):
    """An ordinary install lists its files: a manifest beside them that the list does not have is a stray, and the add-on is on contract 1."""
    ran, imported = process_site()
    record = tmp_path / "site" / "demo2_pkg-0.0.2.dist-info" / "RECORD"
    record.write_text("".join(line for line in record.read_text(encoding="utf-8").splitlines(keepends=True) if "aamio-addon.json" not in line), encoding="utf-8")
    code, out, _ = main(["addon", "list"], monkeypatch)
    assert code == 0 and json.loads(out)["addons"][0]["contract"] == 1 and not imported.exists() and not ran.exists()


def test_the_limits_hold_when_the_process_exits_at_once(process_site, monkeypatch, tmp_path):
    """The same answer whether the process was still writing at the next look or had already exited."""
    process_site()
    assert main(["addon", "enable", "demo2"], monkeypatch)[0] == 0
    monkeypatch.setattr(addon_process, "MAX_ANSWER_BYTES", 1000)
    monkeypatch.setattr(addon_process, "MAX_STDERR_BYTES", 500)
    code, out, _ = main(["addon", "demo2", "spill"], monkeypatch)
    said = json.loads(out)
    assert code == 5 and said["reason"] == "addon_failed" and "bytes an answer may be" in said["fix"], "an answer past the limit from a process that exited at once is refused the same"
    code, out, err = main(["addon", "demo2", "grumble"], monkeypatch)
    said = json.loads(out)
    assert code == 5 and said["reason"] == "addon_failed" and "standard error" in said["fix"] and "y" * 100 not in err, "a valid answer beside too much standard error is refused, and the error is not relayed"
    code, out, err = main(["addon", "demo2", "mutter"], monkeypatch)
    assert code == 0 and json.loads(out)["pong"] is True and "y" * 500 in err and "y" * 501 not in err, "exactly the limit passes, and is relayed whole"
