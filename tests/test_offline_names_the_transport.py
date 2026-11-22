"""A partner not found over the internet is said with the way over a transport, when one is enabled here and the partner
is bound to none, and with why the lookup failed, when it did.

Found in a field test over sound, Bluetooth, QR and LoRa on 22 November 2026:
a send to a device in earshot that was bound to no transport went to presence
at aamio.at, and said only that the device was not online. A lookup that failed
said the same, here and in aamio-php, while aamio for Node said why.
"""

from types import SimpleNamespace

import pytest

from aamio.errors import CodedLookupError
from aamio.runtime import Runtime

ADA = {"name": "ada", "key": "k" * 43}


def runtime_with(enabled=(), bound=False, failed=None):
    """A runtime that finds nobody online, with these transports enabled, and ada bound to one or not."""
    runtime = object.__new__(Runtime)
    runtime.lookup = lambda names: dict({"online": [], "offline": list(names)}, **({"error": failed} if failed else {}))
    runtime.transport_service = lambda: SimpleNamespace(manifests=lambda: {name: object() for name in enabled})
    runtime._bound_partner = lambda to: ADA if bound else None
    return runtime


def refused(runtime):
    with pytest.raises(CodedLookupError) as caught:
        runtime.address_for(ADA)
    assert caught.value.error_code == "partner_offline"
    return str(caught.value)


def test_with_no_transport_enabled_it_says_what_it_said_before():
    assert refused(runtime_with()) == "ada is not online right now"


def test_with_one_transport_enabled_and_ada_bound_to_none_it_gives_the_command():
    said = refused(runtime_with(enabled=["lan"]))

    assert said == ("ada is not online right now. ada is bound to no transport, so it was only looked up over the internet. "
                    "To reach ada over lan, which is enabled here: aamio transport bind ada lan")


def test_with_several_enabled_it_names_them():
    said = refused(runtime_with(enabled=["lan", "earshot-link"]))

    assert said.endswith("To reach ada over one of the transports enabled here, lan, earshot-link: aamio transport bind ada NAME"), said


def test_a_partner_bound_to_a_transport_gets_no_advice_to_bind():
    assert refused(runtime_with(enabled=["lan"], bound=True)) == "ada is not online right now"


def test_a_lookup_that_failed_says_why_as_the_node_runtime_does():
    said = refused(runtime_with(failed="lookup failed: 0 no answer"))

    assert said == "ada is not online right now: lookup failed: 0 no answer"


def test_the_advice_never_stands_in_the_way_of_the_refusal():
    runtime = runtime_with(enabled=["lan"])

    def unreadable():
        raise RuntimeError("the enabled list could not be read")

    runtime.transport_service = lambda: SimpleNamespace(manifests=unreadable)
    assert refused(runtime) == "ada is not online right now"
