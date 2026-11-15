"""The sessions of aamio-carry-v1 against the scenarios in its vectors, kept in a real file.

Every scenario in tests/carry_v1_vectors.json is run step by step with one
CarryState per party, kept in a file of its own under tmp_path, so a restart
in a scenario is a new CarryState on the same file: what was written survives,
and what hung on the monotonic clock does not. Every result, code and reply is
compared with the vectors, byte for byte.
"""

import json
import pathlib

import pytest

from aamio import carry, carry_state
from aamio.carry import CarryRefused
from aamio.crypto import Keys

VECTORS = json.loads((pathlib.Path(__file__).parent / "carry_v1_vectors.json").read_text(encoding="utf-8"))
PARTIES = VECTORS["parties"]


def pk(name):
    return bytes.fromhex(PARTIES[name]["pk"])


def profile_of(row):
    p = row["profile"]
    return carry_state.profile(mode=p["mode"], challenge=p["challenge"], accept_unchallenged=p["accept_unchallenged"],
                               lifetime=p["lifetime"], challenge_window=p["challenge_window"], clock_trusted=p["clock_trusted"])


@pytest.mark.parametrize("scenario", VECTORS["scenarios"], ids=lambda scenario: scenario["name"])
def test_every_scenario_step_by_step(scenario, tmp_path):
    parties = {}
    for row in scenario["parties"]:
        parties[row["name"]] = {
            "state": carry_state.CarryState(Keys(bytes.fromhex(PARTIES[row["name"]]["seed"])), str(tmp_path / row["name"] / "carry.json")),
            "known": [pk(name) for name in row["known"]],
            "profile": profile_of(row),
        }
    for number, step in enumerate(scenario["steps"]):
        party = parties[step["party"]]
        state, profile = party["state"], party["profile"]
        where = "step %d: %r" % (number, {key: value for key, value in step.items() if key not in ("envelope", "reply")})
        op = step["op"]
        if op == "restart":
            party["state"] = carry_state.CarryState(state.keys, state.path)
        elif op == "prune":
            state.prune(step["now"])
        elif op == "ask":
            session, envelope = state.ask(pk(step["to"]), profile, step["mono"], session=bytes.fromhex(step["session"]),
                                          rnd=bytes.fromhex(step["seal_rnd"]) if "seal_rnd" in step else None)
            assert envelope.hex() == step["envelope"], where
        elif op == "send":
            envelope = state.send(pk(step["to"]), bytes.fromhex(step["session"]), bytes.fromhex(step["content"]), profile,
                                  deadline=step["deadline"], rnd=bytes.fromhex(step["seal_rnd"]) if "seal_rnd" in step else None)
            assert envelope.hex() == step["envelope"], where
        elif op == "sent":
            state.remember_sent(pk(step["to"]), bytes.fromhex(step["session"]), step["counter"], bytes.fromhex(step["envelope"]))
        else:
            try:
                result, reply, _ = state.deliver(bytes.fromhex(step["envelope"]), party["known"], profile, step["mono"], step["now"],
                                                 rnd=bytes.fromhex(step["rnd"]) if "rnd" in step else None,
                                                 seal_rnd=bytes.fromhex(step["seal_rnd"]) if "seal_rnd" in step else None)
            except CarryRefused as refused:
                assert ("refused", refused.code) == (step["result"], step.get("code")), where
            else:
                assert result == step["result"], where
                assert (reply.hex() if reply is not None else None) == step.get("reply"), where


def test_a_state_that_cannot_be_read_stops_everything_rather_than_start_from_nothing(tmp_path):
    """Starting from nothing would forget which messages were taken, and a copy of one could be taken again."""
    path = tmp_path / "carry.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(CarryRefused) as refused:
        carry_state.CarryState(Keys(bytes(range(32))), str(path))
    assert refused.value.code == "carry_state_unreadable"


EMPTY = {"version": 1, "floor": None, "challenges": 0, "incoming": {}, "used": [], "stored": {}, "outgoing": {}, "outbox": {}}
# What is changed, and what is left out.
OTHER_SHAPES = {
    "an empty map written as a list": ({"incoming": []}, ()),
    "a list where a map goes": ({"outgoing": ["a"]}, ()),
    "a record that is not one": ({"incoming": {"a:b": "x"}}, ()),
    "a hash that is a number": ({"stored": {"a:b:1": 5}}, ()),
    "used as a map": ({"used": {}}, ()),
    "used with a number": ({"used": [1]}, ()),
    "a floor as text": ({"floor": "1794700000"}, ()),
    "a floor below zero": ({"floor": -1}, ()),
    "a count that is true": ({"challenges": True}, ()),
    "no outbox": ({}, ("outbox",)),
    "no floor": ({}, ("floor",)),
}


@pytest.mark.parametrize("change, missing", OTHER_SHAPES.values(), ids=OTHER_SHAPES.keys())
def test_a_state_of_another_shape_is_refused_whole_rather_than_read_in_part(tmp_path, change, missing):
    """Another runtime may have written it: read in part, what was not read would be written away at the next save."""
    path = tmp_path / "carry.json"
    path.write_text(json.dumps(EMPTY), encoding="utf-8")
    carry_state.CarryState(Keys(bytes(range(32))), str(path)).prune(1_794_700_000)
    assert json.loads(path.read_text(encoding="utf-8")) == dict(EMPTY, floor=1_794_700_000), "the maps are written as objects"
    other = {key: value for key, value in dict(EMPTY, **change).items() if key not in missing}
    path.write_text(json.dumps(other), encoding="utf-8")
    with pytest.raises(CarryRefused) as refused:
        carry_state.CarryState(Keys(bytes(range(32))), str(path))
    assert refused.value.code == "carry_state_unreadable"


def test_a_write_that_fails_gives_no_receipt(tmp_path):
    """A6.6, step 8: no receipt without the message and its mark kept first."""
    a, b = Keys(bytes(range(32))), Keys(bytes(range(32, 64)))
    receiver = carry_state.CarryState(b, str(tmp_path / "file-in-the-way" / "carry.json"))
    (tmp_path / "file-in-the-way").write_text("not a folder", encoding="utf-8")
    one_way = carry_state.profile(challenge=False, accept_unchallenged=True, mode="readable")
    envelope = carry.write(a, b.public_raw, carry.READABLE, carry.MESSAGE, 0, bytes(8), 1, 1_794_700_300, b"hei")
    with pytest.raises(CarryRefused) as refused:
        receiver.deliver(envelope, [a.public_raw], one_way, 0, 1_794_700_000)
    assert refused.value.code == "carry_storage_failed"


def test_two_parties_over_a_store_that_is_full_refuse_without_deleting(tmp_path, monkeypatch):
    """When the state holds as much as it may, a new session is refused, and nothing kept against a replay goes."""
    monkeypatch.setattr(carry_state, "MAX_RECORDS", 3)
    a, b = Keys(bytes(range(32))), Keys(bytes(range(32, 64)))
    receiver = carry_state.CarryState(b, str(tmp_path / "carry.json"))
    one_way = carry_state.profile(challenge=False, accept_unchallenged=True, mode="readable")
    first = carry.write(a, b.public_raw, carry.READABLE, carry.MESSAGE, 0, bytes(8), 1, 1_794_700_300, b"en")
    assert receiver.deliver(first, [a.public_raw], one_way, 0, 1_794_700_000)[0] == "accepted"
    second = carry.write(a, b.public_raw, carry.READABLE, carry.MESSAGE, 0, bytes([1]) * 8, 1, 1_794_700_300, b"to")
    with pytest.raises(CarryRefused) as refused:
        receiver.deliver(second, [a.public_raw], one_way, 1, 1_794_700_001)
    assert refused.value.code == "carry_storage_full"
    assert receiver.deliver(first, [a.public_raw], one_way, 2, 1_794_700_002)[0] == "duplicate"
