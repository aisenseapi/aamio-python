"""A partner is never a guess between names that differ only in case.

Finding 1 of the review of 9 November 2026, found in the Node runtime and
present here as well: a name was matched without regard to case and the first
partner in the book won, a key given was turned into its name and looked up
again, and the first partner presence answered for was taken whichever was
asked for. With Ada and ADA in the book, a message meant for ADA could be
sealed to Ada's key, or written to the inbox of the one who could not open it.
"""

import base64
import sys
import threading

import pytest

sys.path.insert(0, "src")

from aamio.runtime import AmbiguousPartner, Runtime, key_hash


def key(n):
    return base64.urlsafe_b64encode(bytes([n]) * 32).decode().rstrip("=")


ADA, ADA_UPPER, OTHER = key(1), key(2), key(3)
INBOX = {ADA: "adalowerinboxaaaaaaa", ADA_UPPER: "adaupperinboxaaaaaaa"}


class Presence:
    """Both partners online, answered in the book's order or the other way round."""

    def __init__(self, reverse):
        self.reverse = reverse

    def presence_lookup(self, prefixes, wait=0):
        matches = [{"key": k, "hash": key_hash(k), "w": w, "tags": []} for k, w in INBOX.items() if key_hash(k)[:8] in prefixes]
        return 200, {"matches": list(reversed(matches)) if self.reverse else matches}


def build(partners, reverse=False):
    runtime = object.__new__(Runtime)
    runtime.lock = threading.RLock()
    runtime.peers = {}
    runtime.partners = [dict(p) for p in partners]
    runtime.channels = {}
    runtime.attention = {}
    runtime.log = lambda line: None
    runtime.save_state = lambda: None
    runtime._save_json = lambda name, data: None
    runtime._inbox_after_change = lambda reason, outcome: outcome
    runtime.client = Presence(reverse)
    return runtime


@pytest.mark.parametrize("reverse", [False, True])
def test_a_key_or_an_exact_name_reaches_that_partner_whatever_order_presence_answers_in(reverse):
    runtime = build([{"name": "Ada", "key": ADA}, {"name": "ADA", "key": ADA_UPPER}], reverse)

    assert runtime._recipient(ADA_UPPER) == (INBOX[ADA_UPPER], ADA_UPPER, "ADA"), "a key given is the key the message goes to"
    assert runtime._recipient("ADA") == (INBOX[ADA_UPPER], ADA_UPPER, "ADA")
    assert runtime._recipient("Ada") == (INBOX[ADA], ADA, "Ada")
    assert runtime._recipient(ADA) == (INBOX[ADA], ADA, "Ada")

    with pytest.raises(AmbiguousPartner) as guess:
        runtime._recipient("ada")
    assert "Ada, ADA" in str(guess.value) and "exactly" in str(guess.value)


def test_a_name_that_differs_only_in_case_from_another_partner_is_refused_and_the_exact_name_replaces_the_key():
    runtime = build([{"name": "Ada", "key": ADA}])

    with pytest.raises(AmbiguousPartner):
        runtime.partner_add("ada", OTHER)
    assert runtime.partners == [{"name": "Ada", "key": ADA}], "nothing was added"

    runtime.partner_add("Ada", OTHER)
    assert runtime.partners == [{"name": "Ada", "key": OTHER}], "the exact name replaces its key"

    runtime.partner_add("ada", OTHER)
    assert runtime.partners == [{"name": "ada", "key": OTHER}], "one key is one partner, under its latest name"


def test_a_single_partner_is_still_found_whatever_the_case():
    runtime = build([{"name": "Ada", "key": ADA}])

    assert runtime.partner_by_name("ADA") == {"name": "Ada", "key": ADA}
    assert runtime._recipient("ada") == (INBOX[ADA], ADA, "Ada")


class Down:
    """A service that cannot answer a lookup just now."""

    def presence_lookup(self, prefixes, wait=0):
        return 503, {"error": "the store could not be read just now"}


def test_a_lookup_that_fails_still_says_which_names_are_nobodys():
    runtime = build([{"name": "Ada", "key": ADA}])
    runtime.client = Down()

    found = runtime.lookup(["Ada", "nobody"])

    assert found["online"] == [] and found["offline"] == ["Ada"] and "503" in found["error"]
    assert found["unknown"] == ["nobody"], "settled here before the service was asked, and said"
