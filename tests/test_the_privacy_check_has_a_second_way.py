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
import sys

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


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
