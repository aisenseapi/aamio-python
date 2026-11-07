"""Domain keys, the format only: the parser, the match, the generator and the domain syntax.

Run against tests/domain_keys_vectors.json, the vectors every client that takes
the format up is to answer the same way. Nothing here reads a domain, and the
module must not be able to: there is no hardened fetch yet, and a parser that
passes is not a domain check.
"""

import base64
import json
import os
import pathlib
import socket
import subprocess
import sys

import pytest

sys.path.insert(0, "src")
sys.path.insert(0, os.path.join("addons", "domain-keys", "src"))

from aamio_domain_keys import lists
from aamio_domain_keys.__main__ import main as command_line
from aamio_domain_keys.lists import InvalidDocument, make, match, normalise_domain, parse, url_for

VECTORS = json.loads((pathlib.Path(__file__).parent / "domain_keys_vectors.json").read_text(encoding="utf-8"))
SOURCE = pathlib.Path(lists.__file__)


def raw_of(case):
    return base64.b64decode(case["b64"]) if "b64" in case else case["text"].encode("utf-8")


@pytest.mark.parametrize("case", VECTORS["documents"], ids=lambda case: case["case"])
def test_documents(case):
    if case["valid"]:
        assert len(parse(raw_of(case))) == case["keys"]
    else:
        with pytest.raises(InvalidDocument):
            parse(raw_of(case))


@pytest.mark.parametrize("case", VECTORS["matches"], ids=lambda case: case["case"])
def test_matches(case):
    result = match(raw_of(case), case["key"], case.get("name"))

    assert result["status"] == case["status"]
    if case["status"] == "listed":
        assert result["matched_name"] == case["matched_name"]
    if "document_sha256" in case:
        assert result["document_sha256"] == case["document_sha256"]
    if "reason" in case:
        assert result["reason"] == case["reason"]


@pytest.mark.parametrize("given,expected", VECTORS["domains"]["valid"])
def test_domains_that_are_host_names(given, expected):
    assert normalise_domain(given) == expected
    assert url_for(given) == "https://" + expected + "/.well-known/aamio-keys.json"


@pytest.mark.parametrize("given", VECTORS["domains"]["invalid"])
def test_domains_that_are_not(given):
    with pytest.raises(ValueError):
        normalise_domain(given)


@pytest.mark.parametrize("case", VECTORS["generated"], ids=lambda case: case["case"])
def test_the_generator_writes_the_same_bytes_every_client_writes(case):
    raw = make(case["entries"])

    assert raw == case["text"].encode("ascii")
    assert [entry["key"] for entry in parse(raw)] == [entry["key"] for entry in case["entries"]]


@pytest.mark.parametrize("case", VECTORS["refused"], ids=lambda case: case["case"])
def test_the_generator_refuses_what_the_parser_would(case):
    with pytest.raises(InvalidDocument):
        make(case["entries"])


def test_a_bad_entry_spoils_the_whole_list_and_nothing_is_filtered():
    good, bad = VECTORS["matches"][0]["key"], "A" * 42
    raw = json.dumps({"aamio_keys": 1, "keys": [{"key": good}, {"key": bad}]}).encode()

    assert match(raw, good)["status"] == "invalid"


def test_a_result_says_what_was_seen_and_grants_nothing():
    case = VECTORS["matches"][1]
    result = match(raw_of(case), case["key"], case["name"])

    # No verdict on the sender, no trust, nothing to act on: what the list said.
    assert set(result) == {"status", "reason", "matched_name", "document_sha256"}
    assert not {"verified", "trusted", "approved", "allow"} & set(result)


def test_the_module_cannot_reach_the_network():
    text = SOURCE.read_text(encoding="utf-8")

    for module in ("socket", "urllib", "http", "ssl", "requests", ".client"):
        assert "import " + module not in text and "from " + module not in text


def test_nothing_opens_a_connection(monkeypatch, tmp_path):
    def refuse(*args, **kwargs):
        raise AssertionError("the format opened a connection")

    monkeypatch.setattr(socket, "socket", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket, "getaddrinfo", refuse)

    case = VECTORS["generated"][0]
    path = tmp_path / "aamio-keys.json"
    path.write_bytes(make(case["entries"]))

    assert command_line(["check", str(path), "--key", case["entries"][0]["key"], "--name", "support"]) == 0
    assert url_for("example.org").startswith("https://")


def run(*args):
    environment = dict(os.environ, PYTHONPATH=os.pathsep.join([str(SOURCE.parent.parent), os.path.abspath("src")]))
    return subprocess.run([sys.executable, "-m", "aamio_domain_keys", *args], capture_output=True, env=environment)


def test_the_command_checks_a_local_file_and_says_it_read_no_domain(tmp_path):
    case = VECTORS["generated"][0]
    good = tmp_path / "aamio-keys.json"
    good.write_bytes(case["text"].encode("ascii"))
    broken = tmp_path / "broken.json"
    broken.write_bytes(b'{"aamio_keys":2,"keys":[]}')

    valid = run("check", str(good))
    listed = run("check", str(good), "--key", case["entries"][0]["key"], "--name", "support")
    other_name = run("check", str(good), "--key", case["entries"][0]["key"], "--name", "billing")
    invalid = run("check", str(broken))

    assert valid.returncode == 0 and json.loads(valid.stdout) == {"format_valid": True, "keys": 2, "source": "local_file", "domain_checked": False}
    assert listed.returncode == 0 and json.loads(listed.stdout)["status"] == "listed"
    assert other_name.returncode == 3 and json.loads(other_name.stdout)["status"] == "not_listed"
    assert invalid.returncode == 2 and json.loads(invalid.stdout)["format_valid"] is False
    assert all(json.loads(done.stdout)["domain_checked"] is False for done in (valid, listed, other_name, invalid))


def test_the_command_writes_the_file_and_an_empty_one_only_on_purpose():
    case = VECTORS["generated"][0]
    entries = [entry["key"] + (":" + entry["name"] if "name" in entry else "") for entry in case["entries"]]

    made = run("make", *entries)
    empty = run("make", "--empty")
    nothing = run("make")
    refused = run("make", case["entries"][0]["key"], case["entries"][0]["key"])

    assert made.returncode == 0 and made.stdout == case["text"].encode("ascii")
    assert empty.returncode == 0 and empty.stdout == VECTORS["generated"][1]["text"].encode("ascii")
    assert nothing.returncode == 2 and nothing.stdout == b""
    assert refused.returncode == 2 and refused.stdout == b"" and json.loads(refused.stderr)["error"] == "duplicate_key"
