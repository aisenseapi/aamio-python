"""The card of earshot and qrcast against card_vectors.json, the file aamio-php and aamio-js are tested against as well.

A card heard and a card seen are one thing: the same text from the same input, and the same reading of the same text,
in both add-ons and all three runtimes. The file is made from the reference here; a change to the card is a change to
the file, and the other two editions follow it.
"""

import json
import os
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "addons", "earshot", "src"))
sys.path.insert(0, os.path.join(HERE, "..", "addons", "qrcast", "src"))

from aamio_earshot import card as earshot_card  # noqa: E402
from aamio_qrcast import card as qrcast_card  # noqa: E402

with open(os.path.join(HERE, "card_vectors.json"), encoding="utf-8") as handle:
    VECTORS = json.load(handle)

CARDS = {"earshot": earshot_card, "qrcast": qrcast_card}


@pytest.mark.parametrize("module", sorted(CARDS))
@pytest.mark.parametrize("case", VECTORS["make"], ids=[case["about"] for case in VECTORS["make"]])
def test_make(module, case):
    card = CARDS[module]
    if "card" in case:
        text = card.make(case["address"], case["name"], case["expires"], case["via"], case["key"])
        assert text == case["card"] and len(text.encode("utf-8")) == case["bytes"] <= VECTORS["max_bytes"]
    else:
        with pytest.raises(card.Refused) as refused:
            card.make(case["address"], case["name"], case["expires"], case["via"], case["key"])
        assert refused.value.reason == case["refused"]


@pytest.mark.parametrize("module", sorted(CARDS))
@pytest.mark.parametrize("case", VECTORS["read"], ids=[case["about"] for case in VECTORS["read"]])
def test_read(module, case):
    card = CARDS[module]
    if "card" in case:
        assert card.read(case["text"]) == case["card"]
    else:
        with pytest.raises(card.NotUnderstood) as why:
            card.read(case["text"])
        assert why.value.reason == case["not_understood"]


def test_the_vectors_cover_where_a_medium_is_reached_both_ways():
    made = [case["card"] for case in VECTORS["make"] if "card" in case]
    assert any("v=bt:8C:1D:55:03:7B:53" in text for text in made) and any("v=lan:192.168.2.22:47474,internet" in text for text in made)
    assert {case.get("refused") for case in VECTORS["make"]} >= {"invalid_via", "key_needed", "card_too_long", "invalid_key", "a_key_not_a_public_key"}
    assert max(case["bytes"] for case in VECTORS["make"] if "card" in case) == VECTORS["max_bytes"] == 128
