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
            # The scenarios are about the guard against replays, and no program in them takes a message. A session with
            # a message nobody has taken is kept whatever its age, so the program takes what has come before it tidies.
            for key, *_ in state.pending():
                state.handed_over(key)
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
PAIR = "aa" * 32 + ":" + "bb" * 8
SESSION = {"challenged": False, "nonce": None, "highest": 1, "closed": False, "deadline": 1_794_700_300, "opened": None,
           "closed_at": None, "lifetime": None}
SENT = {"sha256": "cc" * 32, "envelope": "00", "receipt": False, "tries": 1, "most": 30}
KEPT = {"sha256": "cc" * 32, "content": None, "sealed": True, "at": 1_794_700_000}
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
    "a field more at the top": ({"extra": 1}, ()),
    "a session with only closed": ({"used": [PAIR], "incoming": {PAIR: {"closed": False}}}, ()),
    "a session with a field more": ({"used": [PAIR], "incoming": {PAIR: dict(SESSION, extra=1)}}, ()),
    "a session whose id is not among the used": ({"incoming": {PAIR: SESSION}}, ()),
    "a session with a counter past four bytes": ({"used": [PAIR], "incoming": {PAIR: dict(SESSION, highest=2 ** 32)}}, ()),
    "a closed session without when": ({"used": [PAIR], "incoming": {PAIR: dict(SESSION, closed=True)}}, ()),
    "a session key that is not hex": ({"used": ["zz" + PAIR[2:]], "incoming": {"zz" + PAIR[2:]: SESSION}}, ()),
    "a mark of no session kept": ({"stored": {PAIR + ":1": dict(KEPT, content=None)}}, ()),
    "content that is not hex": ({"used": [PAIR], "incoming": {PAIR: SESSION}, "stored": {PAIR + ":1": dict(KEPT, content="zz")}}, ()),
    "a hash of the wrong length": ({"used": [PAIR], "incoming": {PAIR: SESSION}, "stored": {PAIR + ":1": dict(KEPT, sha256="cc")}}, ()),
    "a message kept without how it came": ({"used": [PAIR], "incoming": {PAIR: SESSION}, "stored": {PAIR + ":1": {"sha256": "cc" * 32, "content": None, "at": 1}}}, ()),
    "a message kept without when": ({"used": [PAIR], "incoming": {PAIR: SESSION}, "stored": {PAIR + ":1": {"sha256": "cc" * 32, "content": None, "sealed": True}}}, ()),
    "sealed as a number": ({"used": [PAIR], "incoming": {PAIR: SESSION}, "stored": {PAIR + ":1": dict(KEPT, sealed=1)}}, ()),
    "when as text": ({"used": [PAIR], "incoming": {PAIR: SESSION}, "stored": {PAIR + ":1": dict(KEPT, at="1")}}, ()),
    "a receipt with its bytes still kept": ({"outbox": {PAIR + ":1": dict(SENT, receipt=True)}}, ()),
    "more tries than the budget": ({"outbox": {PAIR + ":1": dict(SENT, tries=31)}}, ()),
    "a count of challenges past 2^53 - 1": ({"challenges": 2 ** 53}, ()),
    "an id used twice": ({"used": [PAIR, PAIR]}, ()),
}


def test_a_state_of_the_shape_every_runtime_writes_is_read(tmp_path):
    path = tmp_path / "carry.json"
    whole = dict(EMPTY, used=[PAIR], incoming={PAIR: SESSION}, stored={PAIR + ":1": dict(KEPT, content="6869")},
                 outbox={PAIR + ":1": SENT})
    path.write_text(json.dumps(whole), encoding="utf-8")
    state = carry_state.CarryState(Keys(bytes(range(32))), str(path))
    assert state.pending() == [(PAIR + ":1", bytes.fromhex("aa" * 32), bytes.fromhex("bb" * 8), 1, b"hi")]
    assert state.outcome(PAIR + ":1") == "waiting"


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


# ------------------------------------------------------------------ the review of 2026-11-15, findings 1 to 13

A, B = Keys(bytes(range(32))), Keys(bytes(range(32, 64)))
T = 1_794_700_000
ONE_WAY = carry_state.profile(challenge=False, accept_unchallenged=True, mode="readable")
CHALLENGED = carry_state.profile(mode="readable")


def opened(at_a, at_b, profile=CHALLENGED, mono=0.0, now=T):
    """A asks B for a session, B challenges, A opens: A's session towards B, open at both ends."""
    session, ask = at_a.ask(B.public_raw, profile, mono)
    _, challenge, _ = at_b.deliver(ask, [A.public_raw], profile, mono, now)
    _, opening, _ = at_a.deliver(challenge, [B.public_raw], profile, mono, now)
    assert at_b.deliver(opening, [A.public_raw], profile, mono, now)[0] == "accepted"
    return session


def refused_with(code, call, *args):
    with pytest.raises(CarryRefused) as refused:
        call(*args)
    assert refused.value.code == code
    return refused.value


def test_a_message_is_kept_with_its_content_until_the_program_says_it_has_it(tmp_path):
    """Finding 1: the receipt says kept, so the content is kept; a crash before the program has it offers it again."""
    path = str(tmp_path / "b.json")
    sender = carry_state.CarryState(A)
    session = sender.one_way(B.public_raw, T + 300)
    envelope = sender.send(B.public_raw, session, b"hei", ONE_WAY)
    result, receipt, _ = carry_state.CarryState(B, path).deliver(envelope, [A.public_raw], ONE_WAY, 0, T)
    assert result == "accepted" and receipt is not None
    key = carry_state.mark(A.public_raw, session, 1)
    again = carry_state.CarryState(B, path)
    assert again.pending() == [(key, A.public_raw, session, 1, b"hei")]
    assert again.pending() == [(key, A.public_raw, session, 1, b"hei")], "reading is not taking"
    again.handed_over(key)
    after = carry_state.CarryState(B, path)
    assert after.pending() == []
    result, receipt, _ = after.deliver(envelope, [A.public_raw], ONE_WAY, 0, T)
    assert (result, receipt is not None, after.pending()) == ("duplicate", True, []), "the mark stays: a copy gets its receipt, and is not offered again"


def test_a_message_sent_keeps_its_bytes_and_tries_until_its_receipt_and_a_late_receipt_still_counts(tmp_path):
    """Finding 1, the sender: the same bytes and the tries left after a restart; used up is unknown, a late receipt confirms."""
    path = str(tmp_path / "a.json")
    at_a, receiver = carry_state.CarryState(A, path), carry_state.CarryState(B)
    session = at_a.one_way(B.public_raw, T + 300)
    envelope = at_a.send(B.public_raw, session, b"hei", ONE_WAY, most=3)
    key = carry_state.mark(B.public_raw, session, 1)
    again = carry_state.CarryState(A, path)
    assert (again.outcome(key), again.unconfirmed()) == ("waiting", [(key, B.public_raw, session, 1, envelope)])
    assert again.tried(key) and again.tried(key)
    assert carry_state.CarryState(A, path).durable["outbox"][key]["tries"] == 3, "a restart gives back no tries"
    assert not again.tried(key)
    assert (again.outcome(key), again.unconfirmed(), again.durable["outbox"][key]["envelope"]) == ("unknown", [], None)
    _, receipt, _ = receiver.deliver(envelope, [A.public_raw], ONE_WAY, 0, T)
    assert again.deliver(receipt, [B.public_raw], ONE_WAY, 0, T)[0] == "accepted"
    assert carry_state.CarryState(A, path).outcome(key) == "confirmed"


def test_after_a_write_fails_nothing_is_answered_until_the_state_is_read_again(tmp_path):
    """Finding 2: a failed write never turns into a duplicate with a receipt for what was never kept."""
    receiver = carry_state.CarryState(B, str(tmp_path / "in-the-way" / "carry.json"))
    (tmp_path / "in-the-way").write_text("not a folder", encoding="utf-8")
    envelope = carry.write(A, B.public_raw, carry.READABLE, carry.MESSAGE, 0, bytes(8), 1, T + 300, b"hei")
    for _ in range(2):
        refused_with("carry_storage_failed", receiver.deliver, envelope, [A.public_raw], ONE_WAY, 0, T)
    refused_with("carry_storage_failed", receiver.prune, T)


def test_the_time_floor_is_kept_also_when_what_came_is_refused(tmp_path):
    """Finding 3: a higher floor is kept before the answer, so a passed deadline never comes back after a restart."""
    path = str(tmp_path / "b.json")
    at_b = carry_state.CarryState(B, path)
    at_b.prune(T)
    sender = carry_state.CarryState(A)
    session = sender.one_way(B.public_raw, T + 300)
    envelope = sender.send(B.public_raw, session, b"sent", ONE_WAY)
    refused_with("carry_deadline_passed", at_b.deliver, envelope, [A.public_raw], ONE_WAY, 0, T + 421)
    again = carry_state.CarryState(B, path)
    assert again.durable["floor"] == T + 421
    refused_with("carry_deadline_passed", again.deliver, envelope, [A.public_raw], ONE_WAY, 0, T)
    # A clock that jumps ahead within one second of the monotonic clock: kept at once, even for bytes that are no envelope.
    refused_with("carry_bad_magic", again.deliver, b"XXXX" + bytes(200), [A.public_raw], ONE_WAY, 0, T + 900)
    assert carry_state.CarryState(B, path).durable["floor"] == T + 900


def test_sixty_messages_a_minute_from_one_partner_copies_too(tmp_path):
    """Finding 7: A10 has no exception for copies, since each is answered with a receipt."""
    at_b, sender = carry_state.CarryState(B), carry_state.CarryState(A)
    session = sender.one_way(B.public_raw, T + 3000)
    first = sender.send(B.public_raw, session, b"0", ONE_WAY)
    assert at_b.deliver(first, [A.public_raw], ONE_WAY, 0.0, T)[0] == "accepted"
    for _ in range(59):
        assert at_b.deliver(first, [A.public_raw], ONE_WAY, 0.5, T)[0] == "duplicate"
    refused_with("carry_rate_limited", at_b.deliver, first, [A.public_raw], ONE_WAY, 0.5, T)
    second = sender.send(B.public_raw, session, b"1", ONE_WAY)
    refused_with("carry_rate_limited", at_b.deliver, second, [A.public_raw], ONE_WAY, 59.9, T)
    assert at_b.deliver(second, [A.public_raw], ONE_WAY, 60.0, T)[0] == "accepted", "the first went out of the minute"


def test_256_kib_a_minute_from_one_partner(tmp_path):
    at_b, sender = carry_state.CarryState(B), carry_state.CarryState(A)
    session = sender.one_way(B.public_raw, T + 3000)
    envelopes = [sender.send(B.public_raw, session, bytes([n]) * 60_000, ONE_WAY) for n in range(5)]
    for envelope in envelopes[:4]:
        assert at_b.deliver(envelope, [A.public_raw], ONE_WAY, 1.0, T)[0] == "accepted"
    assert sum(len(envelope) for envelope in envelopes[:5]) > carry_state.BYTES_PER_MINUTE >= sum(len(envelope) for envelope in envelopes[:4])
    refused_with("carry_rate_limited", at_b.deliver, envelopes[4], [A.public_raw], ONE_WAY, 2.0, T)


def test_ten_asks_a_minute_from_one_partner(tmp_path):
    at_a, at_b = carry_state.CarryState(A), carry_state.CarryState(B)
    for n in range(10):
        opened(at_a, at_b, mono=float(n))
    _, ask = at_a.ask(B.public_raw, CHALLENGED, 10.0)
    refused_with("carry_rate_limited", at_b.deliver, ask, [A.public_raw], CHALLENGED, 10.0, T)
    _, ask = at_a.ask(B.public_raw, CHALLENGED, 61.0)
    assert at_b.deliver(ask, [A.public_raw], CHALLENGED, 61.0, T)[0] == "accepted"


def test_challenges_used_or_past_their_window_do_not_fill_the_limit(tmp_path):
    """Finding 8: only challenges that wait, inside their window, count against 8 per partner and 64 in all."""
    at_a, at_b = carry_state.CarryState(A), carry_state.CarryState(B)
    for n in range(9):
        _, ask = at_a.ask(B.public_raw, CHALLENGED, 100.0 * n)
        assert at_b.deliver(ask, [A.public_raw], CHALLENGED, 100.0 * n, T)[0] == "accepted"
    for n in range(8):
        _, ask = at_a.ask(B.public_raw, CHALLENGED, 1000.0)
        at_b.deliver(ask, [A.public_raw], CHALLENGED, 1000.0, T)
    _, ask = at_a.ask(B.public_raw, CHALLENGED, 1000.0)
    refused_with("carry_rate_limited", at_b.deliver, ask, [A.public_raw], CHALLENGED, 1000.0, T)


def test_a_spent_challenge_has_its_own_code_while_it_is_remembered_and_is_unknown_after(tmp_path):
    """Finding 8: 64 spent challenges are remembered per partner; an open for one forgotten is nonce_unknown, refused either way."""
    at_a, at_b = carry_state.CarryState(A), carry_state.CarryState(B)
    session, ask = at_a.ask(B.public_raw, CHALLENGED, 0.0)
    _, challenge, _ = at_b.deliver(ask, [A.public_raw], CHALLENGED, 0.0, T)
    _, opening, _ = at_a.deliver(challenge, [B.public_raw], CHALLENGED, 0.0, T)
    refused_with("carry_nonce_expired", at_b.deliver, opening, [A.public_raw], CHALLENGED, 61.0, T)
    for n in range(1, carry_state.SPENT_KEPT_PER_PARTNER + 1):
        _, ask = at_a.ask(B.public_raw, CHALLENGED, 61.0 * n)
        at_b.deliver(ask, [A.public_raw], CHALLENGED, 61.0 * n, T)
    refused_with("carry_nonce_expired", at_b.deliver, opening, [A.public_raw], CHALLENGED, 61.0 * 65, T)
    _, ask = at_a.ask(B.public_raw, CHALLENGED, 61.0 * 66)
    at_b.deliver(ask, [A.public_raw], CHALLENGED, 61.0 * 66, T)
    refused_with("carry_nonce_unknown", at_b.deliver, opening, [A.public_raw], CHALLENGED, 61.0 * 66, T)
    assert carry_state._pair(A.public_raw, session) in at_b.used, "the session id stays used"


def test_the_count_of_challenges_stops_at_two_to_the_fifty_three_less_one(tmp_path):
    """Finding 10: the last value is reached, the next is refused, never rounded or wrapped."""
    path = tmp_path / "b.json"
    path.write_text(json.dumps(dict(EMPTY, challenges=carry_state.SAFE - 1)), encoding="utf-8")
    at_a, at_b = carry_state.CarryState(A), carry_state.CarryState(B, str(path))
    _, ask = at_a.ask(B.public_raw, CHALLENGED, 0.0)
    assert at_b.deliver(ask, [A.public_raw], CHALLENGED, 0.0, T)[0] == "accepted"
    assert json.loads(path.read_text(encoding="utf-8"))["challenges"] == carry_state.SAFE
    _, ask = at_a.ask(B.public_raw, CHALLENGED, 1.0)
    refused_with("carry_storage_full", at_b.deliver, ask, [A.public_raw], CHALLENGED, 1.0, T)
    assert carry_state.CarryState(B, str(path)).durable["challenges"] == carry_state.SAFE


@pytest.mark.parametrize("counter, deadline", [(2 ** 32, 0), (-1, 0), (1, 2 ** 32), (True, 0), (1, 1.5)])
def test_numbers_outside_their_four_bytes_are_refused_not_cut_down(counter, deadline):
    """Finding 11."""
    with pytest.raises(ValueError):
        carry.write(A, B.public_raw, carry.READABLE, carry.MESSAGE, 0, bytes(8), counter, deadline, b"x")


def test_a_deadline_outside_its_four_bytes_changes_nothing_in_the_state():
    at_a, at_b = carry_state.CarryState(A), carry_state.CarryState(B)
    session = opened(at_a, at_b)
    with pytest.raises(ValueError):
        at_a.send(B.public_raw, session, b"x", CHALLENGED, deadline=2 ** 32)
    assert (at_a.counter_of(B.public_raw, session), at_a.durable["outbox"]) == (0, {})


def test_the_first_message_without_a_challenge_needs_room_for_its_three_records(tmp_path, monkeypatch):
    """Finding 12: the session, its used id and the message's mark."""
    sender = carry_state.CarryState(A)
    session = sender.one_way(B.public_raw, T + 300)
    envelope = sender.send(B.public_raw, session, b"hei", ONE_WAY)
    monkeypatch.setattr(carry_state, "MAX_RECORDS", 2)
    at_b = carry_state.CarryState(B, str(tmp_path / "b.json"))
    refused_with("carry_storage_full", at_b.deliver, envelope, [A.public_raw], ONE_WAY, 0, T)
    assert at_b.durable["incoming"] == {} and at_b.used == set()
    monkeypatch.setattr(carry_state, "MAX_RECORDS", 3)
    assert at_b.deliver(envelope, [A.public_raw], ONE_WAY, 0, T)[0] == "accepted"


def test_a_session_keeps_the_lifetime_it_was_opened_with(tmp_path):
    """Finding 13: a profile changed later can shorten the lifetime, never lengthen it."""
    short, long_ = carry_state.profile(mode="readable", lifetime=600), carry_state.profile(mode="readable", lifetime=86_400)
    at_a, at_b = carry_state.CarryState(A), carry_state.CarryState(B)
    session = opened(at_a, at_b, short, mono=0.0)
    envelope = at_a.send(B.public_raw, session, b"x", short)
    refused_with("carry_session_expired", at_b.deliver, envelope, [A.public_raw], long_, 601.0, T)
    session = opened(at_a, at_b, long_, mono=1000.0)
    envelope = at_a.send(B.public_raw, session, b"y", long_)
    refused_with("carry_session_expired", at_b.deliver, envelope, [A.public_raw], short, 1601.0, T)
    assert at_b.deliver(envelope, [A.public_raw], long_, 1601.0, T)[0] == "accepted"


def test_a_sealed_receipt_for_the_same_message_has_the_same_bytes_every_time():
    """So on a medium that loses frames, the frames of several copies of the receipt add up; another message, another receipt."""
    sealed = carry_state.profile(mode="sealed", challenge=False, accept_unchallenged=True)
    sender, at_b = carry_state.CarryState(A), carry_state.CarryState(B)
    session = sender.one_way(B.public_raw, T + 300)
    first, second = (sender.send(B.public_raw, session, text, sealed) for text in (b"en", b"to"))
    receipts = [at_b.deliver(first, [A.public_raw], sealed, 0.0, T)[1], at_b.deliver(first, [A.public_raw], sealed, 1.0, T)[1]]
    assert receipts[0] == receipts[1]
    assert at_b.deliver(second, [A.public_raw], sealed, 2.0, T)[1] != receipts[0]


# ------------------------------------------------------------------ the follow-up check of 2026-11-15, findings 2, 3, 4 and 10

def test_a_message_nobody_has_taken_outlives_the_guard_against_replays(tmp_path):
    """Finding 3: tidying takes what guards against a replay when its time is up, never a message the program has not taken."""
    path = str(tmp_path / "b.json")
    sender = carry_state.CarryState(A)
    session = sender.one_way(B.public_raw, T + 300)
    envelope = sender.send(B.public_raw, session, b"hei", ONE_WAY)
    at_b = carry_state.CarryState(B, path)
    assert at_b.deliver(envelope, [A.public_raw], ONE_WAY, 0, T)[0] == "accepted"
    key = carry_state.mark(A.public_raw, session, 1)
    at_b.prune(T + 300 + carry_state.SKEW)
    assert carry_state.CarryState(B, path).pending() == [(key, A.public_raw, session, 1, b"hei")]
    at_b.prune(T + 300 + carry_state.SKEW + 1)
    again = carry_state.CarryState(B, path)
    assert again.pending() == [(key, A.public_raw, session, 1, b"hei")], "the receipt said it was kept, and the program has not said it has it"
    assert again.deliver(envelope, [A.public_raw], ONE_WAY, 0, T + 300 + carry_state.SKEW + 1)[0] == "duplicate", "kept with its session, so a copy is still known as one"
    again.handed_over(key)
    again.prune(T + 300 + carry_state.SKEW + 1)
    after = carry_state.CarryState(B, path)
    assert (after.pending(), after.durable["incoming"], after.durable["stored"]) == ([], {}, {}), "taken, it goes with its session at the next tidying"
    refused_with("carry_deadline_passed", after.deliver, envelope, [A.public_raw], ONE_WAY, 0, T)


def test_after_a_write_fails_nothing_is_read_from_memory_either(tmp_path):
    """Finding 4: a receipt whose save failed is not shown as confirmed; outcome, unconfirmed, pending and kept refuse as deliver does."""
    path = tmp_path / "a.json"
    at_a, receiver = carry_state.CarryState(A, str(path)), carry_state.CarryState(B)
    session = at_a.one_way(B.public_raw, T + 300)
    envelope = at_a.send(B.public_raw, session, b"hei", ONE_WAY)
    key = carry_state.mark(B.public_raw, session, 1)
    _, receipt, _ = receiver.deliver(envelope, [A.public_raw], ONE_WAY, 0, T)
    (tmp_path / "a.json.tmp").mkdir()
    refused_with("carry_storage_failed", at_a.deliver, receipt, [B.public_raw], ONE_WAY, 0, T)
    for call, args in ((at_a.outcome, (key,)), (at_a.unconfirmed, ()), (at_a.pending, ()), (at_a.kept, (key,)), (at_a.give_up, (key,))):
        refused_with("carry_storage_failed", call, *args)
    (tmp_path / "a.json.tmp").rmdir()
    assert carry_state.CarryState(A, str(path)).outcome(key) == "waiting", "what the file holds: the receipt never reached it"
    at_a.restart()
    assert at_a.outcome(key) == "waiting" and at_a.deliver(receipt, [B.public_raw], ONE_WAY, 0, T)[0] == "accepted"
    assert carry_state.CarryState(A, str(path)).outcome(key) == "confirmed"


def test_a_message_that_was_not_kept_is_not_listed_as_waiting_after_the_write_failed(tmp_path):
    """Finding 4, the receiver: deliver refuses with carry_storage_failed, and pending shows nothing of what never reached the file."""
    receiver = carry_state.CarryState(B, str(tmp_path / "in-the-way" / "carry.json"))
    (tmp_path / "in-the-way").write_text("not a folder", encoding="utf-8")
    envelope = carry.write(A, B.public_raw, carry.READABLE, carry.MESSAGE, 0, bytes(8), 1, T + 300, b"hei")
    refused_with("carry_storage_failed", receiver.deliver, envelope, [A.public_raw], ONE_WAY, 0, T)
    refused_with("carry_storage_failed", receiver.pending)


def test_a_message_given_up_keeps_its_mark_for_a_late_receipt(tmp_path):
    """Finding 2, in the state: given up, the bytes go and the outcome is unknown; the hash stays, so a late receipt confirms it."""
    path = str(tmp_path / "a.json")
    at_a, receiver = carry_state.CarryState(A, path), carry_state.CarryState(B)
    session = at_a.one_way(B.public_raw, T + 300)
    envelope = at_a.send(B.public_raw, session, b"hei", ONE_WAY)
    key = carry_state.mark(B.public_raw, session, 1)
    assert at_a.give_up(key) and not at_a.give_up(key)
    again = carry_state.CarryState(A, path)
    assert (again.outcome(key), again.unconfirmed(), again.durable["outbox"][key]["envelope"]) == ("unknown", [], None)
    assert not again.tried(key), "never sent again"
    _, receipt, _ = receiver.deliver(envelope, [A.public_raw], ONE_WAY, 0, T)
    assert again.deliver(receipt, [B.public_raw], ONE_WAY, 0, T)[0] == "accepted" and again.outcome(key) == "confirmed"


def test_every_challenge_waits_in_the_window_it_was_given_under(tmp_path):
    """Finding 10: the 64 in all are counted with each challenge's own window, not with the window of the one who asks now."""
    wide = carry_state.profile(mode="readable", challenge_window=600, lifetime=3600)
    narrow = carry_state.profile(mode="readable", challenge_window=60, lifetime=600)
    partners = [Keys(bytes([n]) * 32) for n in range(1, 10)]
    ninth = partners[8]
    known = [partner.public_raw for partner in partners]
    at_b = carry_state.CarryState(B)
    profile_of = lambda sender: narrow if sender == ninth.public_raw else wide
    openings = []
    for partner in partners[:8]:
        state = carry_state.CarryState(partner)
        for _ in range(carry_state.MAX_WAITING_PER_PARTNER):
            _, ask = state.ask(B.public_raw, wide, 0.0)
            result, challenge, _ = at_b.deliver(ask, known, profile_of, 0.0, T)
            assert result == "accepted"
        openings.append((state, challenge))
    late = carry_state.CarryState(ninth)
    _, ask = late.ask(B.public_raw, narrow, 100.0)
    refused_with("carry_rate_limited", at_b.deliver, ask, known, profile_of, 100.0, T)
    # The 64 still wait: an open for one of them is taken at the same moment.
    state, challenge = openings[0]
    _, opening, _ = state.deliver(challenge, [B.public_raw], wide, 100.0, T)
    assert at_b.deliver(opening, known, profile_of, 100.0, T)[0] == "accepted"
    # One is used now, so there is room for one more.
    _, ask = late.ask(B.public_raw, narrow, 100.0)
    assert at_b.deliver(ask, known, profile_of, 100.0, T)[0] == "accepted"
    # And past their own window the old ones no longer count, whatever window the asker has.
    for n in range(carry_state.MAX_WAITING_PER_PARTNER - 1):
        _, ask = late.ask(B.public_raw, narrow, 700.0)
        assert at_b.deliver(ask, known, profile_of, 700.0, T)[0] == "accepted"


def test_an_open_is_taken_in_the_window_its_challenge_was_given_under():
    """The check of 16 November 2026: the quota counted a challenge in the window it was given under, and an open was
    taken in the window of the profile now. Given with 60 seconds, a challenge was refused at 61 under that profile and
    taken under one of 600, while the quota no longer counted it."""
    narrow = carry_state.profile(mode="readable", challenge_window=60, lifetime=600)
    wide = carry_state.profile(mode="readable", challenge_window=600, lifetime=3600)
    at_a, at_b = carry_state.CarryState(A), carry_state.CarryState(B)
    _, ask = at_a.ask(B.public_raw, narrow, 0.0)
    _, challenge, _ = at_b.deliver(ask, [A.public_raw], narrow, 0.0, T)
    _, opening, _ = at_a.deliver(challenge, [B.public_raw], narrow, 1.0, T)
    refused_with("carry_nonce_expired", at_b.deliver, opening, [A.public_raw], wide, 61.0, T)
    # What was given stands the other way too: given with 600 seconds, it is taken at 61 under a profile of 60.
    _, ask = at_a.ask(B.public_raw, wide, 100.0)
    _, challenge, _ = at_b.deliver(ask, [A.public_raw], wide, 100.0, T)
    _, opening, _ = at_a.deliver(challenge, [B.public_raw], wide, 101.0, T)
    assert at_b.deliver(opening, [A.public_raw], narrow, 161.0, T)[0] == "accepted"


def test_a_challenge_the_quota_no_longer_counts_opens_no_session():
    """The same, as the quota sees it: 64 challenges given with 60 seconds are out of the count at 61, a new one is
    given under a profile of 600, and none of the 64 opens a session then."""
    narrow = carry_state.profile(mode="readable", challenge_window=60, lifetime=600)
    wide = carry_state.profile(mode="readable", challenge_window=600, lifetime=3600)
    partners = [Keys(bytes([n]) * 32) for n in range(1, 10)]
    known = [partner.public_raw for partner in partners]
    at_b = carry_state.CarryState(B)
    given = []
    for partner in partners[:8]:
        state = carry_state.CarryState(partner)
        for _ in range(carry_state.MAX_WAITING_PER_PARTNER):
            _, ask = state.ask(B.public_raw, narrow, 0.0)
            result, challenge, _ = at_b.deliver(ask, known, narrow, 0.0, T)
            assert result == "accepted"
        given.append((state, challenge))
    late = carry_state.CarryState(partners[8])
    _, ask = late.ask(B.public_raw, wide, 61.0)
    assert at_b.deliver(ask, known, wide, 61.0, T)[0] == "accepted", "the 64 are past their window, and no longer counted"
    for state, challenge in given:
        _, opening, _ = state.deliver(challenge, [B.public_raw], narrow, 1.0, T)
        refused_with("carry_nonce_expired", at_b.deliver, opening, known, wide, 61.0, T)
