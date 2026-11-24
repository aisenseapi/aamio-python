"""A partner not found over the internet is said with the way over a transport, when one is enabled here and the partner
is bound to none, and with why the lookup failed, when it did.

Found in a field test over sound, Bluetooth, QR and LoRa on 22 November 2026:
a send to a device in earshot that was bound to no transport went to presence
at aamio.at, and said only that the device was not online. A lookup that failed
said the same, here and in aamio-php, while aamio for Node said why.
"""

import base64
import json
import os
import subprocess
import sys
from types import SimpleNamespace

import pytest

from aamio.errors import CodedLookupError
from aamio.runtime import Runtime

ADA = {"name": "ada", "key": "k" * 43}
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def runtime_with(enabled=(), bound=False, failed=None):
    """A runtime that finds nobody online, with these transports enabled, and ada bound to one or not."""
    runtime = object.__new__(Runtime)
    runtime.lookup = lambda names: dict({"online": [], "offline": list(names)}, **({"error": failed} if failed else {}))
    runtime.transport_service = lambda: SimpleNamespace(manifests=lambda: {name: object() for name in enabled})
    runtime._bound_partner = lambda to: ADA if bound else None
    return runtime


def refused(runtime, partner=ADA):
    with pytest.raises(CodedLookupError) as caught:
        runtime.address_for(partner)
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


# A partner's name is 1 to 64 characters with no control characters, so it may hold what a shell splits or reads as its
# own. The command gave such a name as it was: aamio transport bind Ada Lovelace lan is four words to bind, not three
# (the review of 23 November 2026). The key goes in its place.
NOT_ONE_WORD = ["Ada Lovelace", "O'Hara", 'say "hi"', "$HOME;ls", "Åse", "-ada", "1kb", "ada,bob", "a`b", "ada&bob"]


@pytest.mark.parametrize("name", NOT_ONE_WORD)
def test_a_name_a_shell_would_not_take_as_one_word_is_given_by_its_key(name):
    partner = {"name": name, "key": "--" + "q" * 41}

    said = refused(runtime_with(enabled=["lan"]), partner)

    assert said.endswith(". To reach %s over lan, which is enabled here, naming the partner by its key: aamio transport bind %s lan" % (name, partner["key"])), said
    several = refused(runtime_with(enabled=["lan", "bt"]), partner)
    assert several.endswith(", lan, bt, naming the partner by its key: aamio transport bind %s NAME" % partner["key"]), several


@pytest.mark.parametrize("name", ["ada", "Ada.Lovelace", "ada-l_2", "a" * 64])
def test_a_name_of_letters_digits_dots_dashes_and_underscores_after_a_letter_is_given_as_it_is(name):
    said = refused(runtime_with(enabled=["lan"]), {"name": name, "key": "k" * 43})

    assert said.endswith("To reach %s over lan, which is enabled here: aamio transport bind %s lan" % (name, name)), said


def test_the_command_it_gives_binds_the_partner_when_it_is_run(tmp_path):
    """The advice in a refusal is a command an agent runs: run here as it is given, split at its spaces, it binds the
    partner it names, also with a name of two words and a key that begins with two dashes."""
    env = dict(os.environ, PYTHONPATH=os.pathsep.join([os.path.join(ROOT, "src"), os.path.join(ROOT, "addons", "lan", "src")]),
               AAMIO_HOST="http://127.0.0.1:9", PYTHONIOENCODING="utf-8", AAMIO_ADDONS="aamio_lan",
               LOCALAPPDATA=str(tmp_path / "state"), XDG_STATE_HOME=str(tmp_path / "state"))
    key = base64.urlsafe_b64encode(bytes([0xFB, 0xEF]) + bytes(range(30))).decode().rstrip("=")
    assert key.startswith("--")

    def cli(*words):
        done = subprocess.run([sys.executable, "-m", "aamio", "--home", str(tmp_path / "home")] + list(words), capture_output=True, env=env, timeout=60)
        return done.returncode, done.stdout.decode("utf-8"), done.stderr.decode("utf-8")

    assert cli("partner", "add", "Ada Lovelace", key)[0] == 0
    code, out, err = cli("send", "Ada Lovelace", "hei")
    told = json.loads(out)
    assert code == 1 and told["error_code"] == "partner_offline", (out, err)
    words = told["error"].rsplit(": ", 1)[1].split(" ")
    assert words == ["aamio", "transport", "bind", key, "lan"], told

    code, out, err = cli(*words[1:])

    assert code == 0, (out, err)
    bound = json.loads(out)
    assert bound["partner"] == "Ada Lovelace" and bound["key"] == key and [route["transport"] for route in bound["routes"]] == ["lan"], bound
