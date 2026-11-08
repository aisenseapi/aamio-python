"""The Python half's tests: the process on its own, and through aamio's core when aamio is installed.

    cd python && python -m pytest
"""

import json
import os
import subprocess
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "..", "src")
sys.path.insert(0, SRC)

from aamio_example import NAME, __version__, process  # noqa: E402

MANIFEST = json.load(open(os.path.join(SRC, "aamio_" + NAME, "aamio-addon.json"), encoding="utf-8"))


def request(kind, call, **arguments):
    return {"aamio_addon": 2, "kind": kind, "name": call, "arguments": arguments, "subject": None, "own_key": None, "state_dir": None,
            "deadline_seconds": 10, "aamio": {"version": "0.6.27", "runtime": "python"}}


def test_the_probe_says_who_this_is_as_the_manifest_does():
    assert process.handle(request("probe", "probe")) == {"result": {"ok": True, "name": MANIFEST["name"], "version": MANIFEST["version"], "aamio_addon": 2}, "exit_code": 0, "is_error": False}
    assert NAME == MANIFEST["name"] and __version__ == MANIFEST["version"]


def test_the_command_and_the_tool_answer():
    assert process.handle(request("command", "wave", to="Kari"))["result"] == {"hello": "Kari"}
    assert process.handle(request("command", "wave"))["result"] == {"hello": "world"}
    assert process.handle(request("tool", "aamio_addon_%s_wave" % NAME, to="Ola"))["result"] == {"hello": "Ola"}


def test_a_refusal_has_a_fix_and_the_unknown_is_refused():
    said = process.handle(request("command", "wave", to="x" * 65))
    assert said["exit_code"] == 2 and said["is_error"] is True and said["result"]["fix"]
    assert process.handle(request("command", "shout"))["result"]["reason"] == "unknown_call"
    assert process.handle({"aamio_addon": 3})["result"]["reason"] == "not_contract_2"


def test_run_as_aamio_runs_it_it_writes_one_json_answer_and_nothing_else():
    done = subprocess.run([sys.executable, "-m", "aamio_%s.process" % NAME], input=json.dumps(request("command", "wave", to="Kari")),
                          capture_output=True, text=True, env=dict(os.environ, PYTHONPATH=SRC), timeout=30)
    assert done.returncode == 0 and json.loads(done.stdout) == {"result": {"hello": "Kari"}, "exit_code": 0, "is_error": False}


def test_through_aamio_s_core(tmp_path):
    pytest.importorskip("aamio")
    env = dict(os.environ, AAMIO_ADDONS="aamio_" + NAME, PYTHONPATH=SRC + os.pathsep + os.environ.get("PYTHONPATH", ""), AAMIO_HOME=str(tmp_path / "home"))
    listed = subprocess.run([sys.executable, "-m", "aamio", "--no-archive", "addon", "list"], capture_output=True, text=True, env=env, timeout=60)
    row = json.loads(listed.stdout)["addons"][0]
    assert row["name"] == NAME and row["contract"] == 2 and row["commands"] == ["wave"], listed.stderr
    waved = subprocess.run([sys.executable, "-m", "aamio", "--no-archive", "addon", NAME, "wave", "--to", "Kari"], capture_output=True, text=True, env=env, timeout=60)
    assert waved.returncode == 0 and json.loads(waved.stdout) == {"hello": "Kari"}, waved.stderr
