"""Get-Acl is not on every Windows, and the check named its own way out without taking it.

`aamio doctor` reads the folder's access control list with Get-Acl, which lives in
`Microsoft.PowerShell.Security`. Where that module does not load there is no such
command, and `check()` answered `private: None`, `findings: []`, and a `fix`
telling the reader to run `icacls` by hand.

That is honest -- a None is never reported as a yes -- and it means the one check
about who can read the decrypted archive is off on an unknown number of machines,
while the code names the tool that would have worked. It matters more since a
finding from this check reaches a caller through `attention`: a reader with
nothing to deliver.

`icacls` is an .exe and needs no module. It is asked for SDDL rather than for what
it prints, because what it prints is translated -- this machine says
`NT-MYNDIGHET\\Godkjente brukere` where an English one says
`NT AUTHORITY\\Authenticated Users` -- and SDDL gives the SIDs the first path
already compares.
"""

import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import subprocess
import sys
import threading

sys.path.insert(0, "src")

import pytest

from aamio import storage

windows_only = pytest.mark.skipif(not storage.is_windows(),
                                  reason="the access control list is a Windows thing")


def get_acl_is_gone(path):
    raise OSError("The term 'Get-Acl' is not recognized as the name of a cmdlet")


@windows_only
def test_the_fallback_finds_what_get_acl_finds(tmp_path, monkeypatch):
    home = str(tmp_path)
    with_powershell = storage.check(home)

    monkeypatch.setattr(storage, "_windows_rules", get_acl_is_gone)
    with_icacls = storage.check(home)

    assert with_icacls["private"] == with_powershell["private"], (
        "the two ways to read one folder disagreed about whether it is private: %r vs %r"
        % (with_icacls["private"], with_powershell["private"]))
    assert ([f["who"] for f in with_icacls["findings"]]
            == [f["who"] for f in with_powershell["findings"]]), (
        "they named different accounts: %r vs %r"
        % ([f["who"] for f in with_icacls["findings"]],
           [f["who"] for f in with_powershell["findings"]]))


@windows_only
def test_the_fallback_says_which_way_it_read_the_folder(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "_windows_rules", get_acl_is_gone)
    found = storage.check(str(tmp_path))

    assert "icacls" in (found["how"] or ""), found["how"]
    assert "not checked" not in (found["how"] or ""), (
        "it read the folder and still said it had not: " + (found["how"] or ""))
    assert found["private"] is not None, "a folder it could read must not answer None"


@windows_only
def test_names_come_from_sids_and_not_from_what_icacls_prints(tmp_path, monkeypatch):
    """The reason for SDDL. icacls prints account names in the machine's language."""
    monkeypatch.setattr(storage, "_windows_rules", get_acl_is_gone)
    found = storage.check(str(tmp_path))

    for finding in found["findings"]:
        assert "\\" not in finding["who"], (
            "that is a printed account name, not a SID translated here: " + finding["who"])


@windows_only
def test_both_ways_failing_is_still_a_no_answer_and_not_a_yes(tmp_path, monkeypatch):
    """The rule that started all of this: a None is never reported as a yes."""
    monkeypatch.setattr(storage, "_windows_rules", get_acl_is_gone)
    monkeypatch.setattr(storage, "_windows_rules_icacls", get_acl_is_gone)
    found = storage.check(str(tmp_path))

    assert found["private"] is None, found["private"]
    assert found["findings"] == []
    assert "not checked" in (found["how"] or ""), found["how"]
    assert "Get-Acl" in (found["how"] or "") or "icacls" in (found["how"] or ""), found["how"]
    assert "icacls" in (found.get("fix") or ""), "the fix still tells the reader what to run"


@windows_only
def test_a_folder_that_is_not_there_is_not_read_by_either(monkeypatch):
    monkeypatch.setattr(storage, "_windows_rules", get_acl_is_gone)
    found = storage.check(os.path.join("P:", "tmp", "claude", "no-such-folder-here"))

    assert found["private"] is None
    assert "no such folder" in (found["how"] or ""), found["how"]


def simulated_export(monkeypatch, exporter):
    """Exercise check and its real fallback, without changing any Windows ACL."""
    monkeypatch.setattr(storage, "is_windows", lambda: True)
    monkeypatch.setattr(storage, "_windows_rules", get_acl_is_gone)

    def run(args, **kwargs):
        if args[0] == "whoami.exe":
            return subprocess.CompletedProcess(args, 0, '"tester","S-1-5-21-123"\n', "")
        assert args[0] == "icacls"
        return exporter(args, Path(args[3]))

    monkeypatch.setattr(storage.subprocess, "run", run)


def write_export(saved, target, dacl):
    saved.write_bytes((os.path.basename(os.path.normpath(target)) + "\r\n"
                       + dacl + "\r\n").encode("utf-16"))


@pytest.mark.parametrize("same_name", [False, True])
def test_concurrent_checks_never_read_each_others_export(tmp_path, monkeypatch, same_name):
    exposed = tmp_path / "exposed" / "home" if same_name else tmp_path / "exposed"
    private = tmp_path / "private" / "home" if same_name else tmp_path / "private"
    exposed.mkdir(parents=True)
    private.mkdir(parents=True)
    exposed_written = threading.Event()
    private_written = threading.Event()
    exposed_finished = threading.Event()
    exports = []

    def exporter(args, saved):
        exports.append(saved)
        if Path(args[1]) == exposed:
            write_export(saved, args[1], "D:(A;;FA;;;WD)")
            exposed_written.set()
            assert private_written.wait(10), "second export never arrived"
        else:
            assert Path(args[1]) == private
            assert exposed_written.wait(10), "first export never arrived"
            write_export(saved, args[1], "D:(A;;FA;;;S-1-5-21-123)")
            private_written.set()
            assert exposed_finished.wait(10), "first check never finished"
        return subprocess.CompletedProcess(args, 0, "", "")

    simulated_export(monkeypatch, exporter)

    def check_exposed():
        try:
            return storage.check(str(exposed))
        finally:
            exposed_finished.set()

    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(check_exposed)
        second = pool.submit(storage.check, str(private))
        exposed_result, private_result = first.result(), second.result()

    assert exposed_result["private"] is False, exposed_result
    assert [f["who"] for f in exposed_result["findings"]] == ["Everyone"]
    assert private_result["private"] is True, private_result
    assert len(set(exports)) == 2, "each call needs its own export"
    assert all(not saved.exists() for saved in exports)
    assert all(not saved.parent.exists() for saved in exports)


@pytest.mark.parametrize("dacl, expected", [
    ("D:", True),
    ("D:P(D;;FA;;;WD)", True),
    ("D:AI(A;OICI;FA;;;SY)(A;;FA;;;OW)", True),
    ("D:PAI(A;;FA;;;WD)", False),
    ("D:ARAI(A;;FA;;;SY)S:P(ML;OINPIO;NW;;;HI)", True),
])
def test_complete_supported_exports_keep_the_same_findings(tmp_path, monkeypatch, dacl, expected):
    def exporter(args, saved):
        assert saved.parent.is_dir()
        write_export(saved, args[1], dacl)
        return subprocess.CompletedProcess(args, 0, "", "")

    simulated_export(monkeypatch, exporter)
    assert storage.check(str(tmp_path))["private"] is expected


@pytest.mark.parametrize("failure", [
    "exit", "missing", "timeout", "encoding", "empty", "wrong_target",
    "many_targets", "no_dacl", "broken_ace", "broken_fields", "unknown_ace",
    "null_dacl", "garbage",
])
def test_incomplete_or_ambiguous_exports_are_unknown(tmp_path, monkeypatch, failure):
    exports = []

    def exporter(args, saved):
        exports.append(saved)
        if failure == "exit":
            return subprocess.CompletedProcess(args, 1, "", "access denied")
        if failure == "timeout":
            raise subprocess.TimeoutExpired(args, 30)
        if failure != "missing":
            name = os.path.basename(os.path.normpath(args[1]))
            record = {
                "encoding": b"\xff\xfe\x00",
                "empty": "",
                "wrong_target": "some-other-folder\r\nD:(A;;FA;;;SY)\r\n",
                "many_targets": name + "\r\nD:(A;;FA;;;SY)\r\nother\r\nD:(A;;FA;;;SY)\r\n",
                "no_dacl": name + "\r\nO:SY\r\n",
                "broken_ace": name + "\r\nD:(A;;FA;;;SY\r\n",
                "broken_fields": name + "\r\nD:(A;;FA;;;)\r\n",
                "unknown_ace": name + "\r\nD:(ZA;;FA;;;SY)\r\n",
                "null_dacl": name + "\r\nD:NO_ACCESS_CONTROL\r\n",
                "garbage": name + "\r\nD:this is not a DACL\r\n",
            }[failure]
            saved.write_bytes(record if isinstance(record, bytes) else record.encode("utf-16"))
        return subprocess.CompletedProcess(args, 0, "", "")

    simulated_export(monkeypatch, exporter)
    result = storage.check(str(tmp_path))

    assert result["private"] is None, result
    assert result["findings"] == []
    assert "not checked" in result["how"]
    assert all(not saved.exists() for saved in exports)
    assert all(not saved.parent.exists() for saved in exports)


@windows_only
def test_real_export_accepts_absolute_relative_and_root_targets(tmp_path, monkeypatch):
    child = tmp_path / "a folder"
    child.mkdir()
    monkeypatch.chdir(tmp_path)
    absolute = storage._windows_rules_icacls(str(child))
    assert storage._windows_rules_icacls("a folder") == absolute
    assert storage._windows_rules_icacls(".\\a folder\\") == absolute
    # Read only the drive root's own ACL, not its children; no ACL is modified.
    me, rules = storage._windows_rules_icacls(tmp_path.anchor)
    assert me.startswith("S-1-")
    assert rules


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
