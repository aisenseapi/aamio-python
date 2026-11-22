"""What a carrier refuses is said where the user sees it, and never answered over the medium.

Contract 3, A7: refusals stay with the receiver, and are logged and shown
there. Until 22 November 2026 every refusal went into a list that only tests
read, and the user heard nothing, also of a message refused because the session
it came in had expired with a restart, so that it was not stored (A6.8). A
refusal from a verified sender is now said once for each partner, session and
code, one in an expired session goes to attention, and what was turned away
before a sender was known is counted and said at most once a minute, since
anyone in range can send it.
"""

from aamio import carry, carry_state
from aamio.carrier import REFUSALS_KEPT, Carrier
from aamio.carry_state import CarryState
from aamio.crypto import Keys

A, B, C = Keys(bytes(range(32))), Keys(bytes(range(32, 64))), Keys(bytes(range(64, 96)))
NOW = 1_794_700_000
PROFILE = carry_state.profile(mode="sealed")


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


class Medium:
    """What a carrier asks of its transport, with frames handed to it as if they had been heard. Nothing goes out."""

    name = "stub"
    properties = {"max_frame_up": 4096, "max_frame_down": 4096}

    def __init__(self):
        self.heard = []

    def poll(self, timeout=0.0):
        heard, self.heard = self.heard, []
        return [("received", None, frame) for frame in heard]

    def room(self):
        return 0

    def check_time(self):
        pass

    def waiting_for_room(self, waiting):
        pass


def receiver(state, clock):
    lines, notes, medium = [], [], Medium()
    carrier = Carrier(state, medium, PROFILE, [A.public_raw], clock=clock, wall=lambda: NOW, log=lines.append,
                      name_of=lambda pk: "alice" if pk == A.public_raw else pk.hex()[:8],
                      attention=lambda state, text: notes.append((state, text)))
    return carrier, medium, lines, notes


def hear(carrier, medium, envelope):
    medium.heard.extend(carry.split(envelope, Medium.properties["max_frame_up"]))
    carrier.pump(timeout=0)


def asked_and_challenged():
    """A has asked B for a session and has B's challenge: the open it answers with, and A's state."""
    a, b = CarryState(A), CarryState(B)
    session, ask = a.ask(B.public_raw, PROFILE, 0.0)
    _, challenge, _ = b.deliver(ask, [A.public_raw], PROFILE, 0.0, NOW)
    _, opening, _ = a.deliver(challenge, [B.public_raw], PROFILE, 0.0, NOW)
    return a, b, session, opening


def test_a_message_in_a_session_that_expired_with_a_restart_goes_to_attention_once_and_nothing_is_answered():
    a, b, session, opening = asked_and_challenged()
    assert b.deliver(opening, [A.public_raw], PROFILE, 0.0, NOW)[0] == "accepted"
    b.restart()
    carrier, medium, lines, notes = receiver(b, Clock())
    envelope = a.send(B.public_raw, session, b"hei", PROFILE)

    hear(carrier, medium, envelope)

    assert carrier.refused == ["carry_session_expired"]
    assert [state for state, _ in notes] == ["session_expired"], notes
    said = notes[0][1]
    assert "alice" in said and "not stored" in said and "sent again" in said and "A6.8" in said, said
    assert carrier.queue == [] and carrier.inbox == [], "nothing is answered over the medium, and nothing was taken"

    hear(carrier, medium, envelope)
    second = a.send(B.public_raw, session, b"igjen", PROFILE)
    hear(carrier, medium, second)

    assert carrier.refused == ["carry_session_expired"] * 3
    assert len(notes) == 1, "a copy, and another message in the same session, are not said again: %s" % notes


def test_another_refusal_from_a_known_partner_is_logged_once_with_its_kind_and_code():
    _a, b, _session, opening = asked_and_challenged()
    b.restart()  # the challenge that waited goes with the restart (A6.8), so the open matches nothing
    carrier, medium, lines, notes = receiver(b, Clock())

    hear(carrier, medium, opening)
    hear(carrier, medium, opening)

    assert carrier.refused == ["carry_nonce_unknown"] * 2
    said = [line for line in lines if "carry_nonce_unknown" in line]
    assert len(said) == 1, lines
    assert "an open from alice" in said[0] and "not answered over the medium" in said[0] and "transport stub" in said[0], said
    assert notes == [] and carrier.queue == []


def test_what_was_turned_away_before_a_sender_was_known_is_counted_and_said_at_most_once_a_minute():
    stranger, clock = CarryState(C), Clock()
    carrier, medium, lines, notes = receiver(CarryState(B), clock)

    def said():
        return [line for line in lines if "before a sender was known" in line]

    hear(carrier, medium, stranger.ask(B.public_raw, PROFILE, 0.0)[1])
    assert said() == ["transport stub: turned away before a sender was known, said at most once a minute: carry_unknown_sender 1"], lines

    for _ in range(3):
        hear(carrier, medium, stranger.ask(B.public_raw, PROFILE, 0.0)[1])
    medium.heard.append(b"x")
    carrier.pump(timeout=0)
    assert len(said()) == 1, "within the minute they are counted, not said: %s" % lines

    clock.now += 61
    carrier.pump(timeout=0)

    assert said()[-1] == "transport stub: turned away before a sender was known, said at most once a minute: carry_unknown_sender 3, frame_bad_length 1"
    carrier.pump(timeout=0)
    assert len(said()) == 2, "nothing new, nothing said"
    assert notes == [] and carrier.queue == [] and "alice" not in " ".join(lines)


def test_the_list_of_refusal_codes_keeps_only_the_newest():
    carrier, medium, lines, _ = receiver(CarryState(B), Clock())
    medium.heard.extend([b"x"] * (REFUSALS_KEPT + 5))

    carrier.pump(timeout=0)

    assert carrier.refused == ["frame_bad_length"] * REFUSALS_KEPT, "a long aamio serve kept every code for as long as it ran"
    assert len([line for line in lines if "before a sender was known" in line]) == 1
