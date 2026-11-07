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
import textwrap

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "addons", "domain-keys", "src"))

from aamio import addons, cli, mcp_server
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
    monkeypatch.setitem(addons._cache, "key", None)
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

    assert said["addons"] == [{"name": "demo", "distribution": None, "enabled": True, "named_in": "AAMIO_ADDONS", "version": "0.0.1", "module": "demo_addon", "commands": ["dry", "ping"], "mcp_tools": ["aamio_addon_demo_ping"]}]
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
    monkeypatch.setitem(addons._cache, "key", None)
    for module in ("demo_pkg", "other_pkg", "wrong_pkg", "broken_pkg", "list_pkg"):
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
    assert code == 0 and said["addons"] == [{"name": "demo", "version": "0.0.1", "distribution": "demo-pkg", "enabled": False, "fix": "aamio addon enable demo"}]
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
    addons._cache["key"] = None

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
    addons._cache["key"] = None
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
