"""The TCP transport in the runtime: a home that listens and a home that connects out to it exchange messages with
aamio.at out of reach.

As aamio serve runs it: the core starts the transport from its manifest, and passes it only the variables the manifest
lists, taken from the service's own environment. The listener's port, where it is reached and the name the other side
gives itself all have to come that way, so a variable left out of the manifest would stop the test, as it would stop a
home in the field. The service is at http://127.0.0.1:9, where nobody answers: what arrives came over the transport.
"""

import os
import pathlib
import socket
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
SRC = ROOT / "src"
TCP = ROOT / "addons" / "tcp" / "src"
sys.path.insert(0, str(SRC))
sys.path.insert(0, str(TCP))

from aamio import addons, mcp_server, transports
from aamio.runtime import Runtime

NOWHERE = "http://127.0.0.1:9"


def free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


@pytest.fixture
def tcp_env(tmp_path, monkeypatch):
    """tcp named in AAMIO_ADDONS, the transports' folders under tmp_path, and the packages on the path a child process gets."""
    monkeypatch.syspath_prepend(str(TCP))
    monkeypatch.setenv("AAMIO_ADDONS", "aamio_tcp")
    monkeypatch.setenv("PYTHONPATH", os.pathsep.join([str(SRC), str(TCP)]))
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "state"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    for key in [key for key in os.environ if key.startswith("AAMIO_TCP_")] + ["AAMIO_HOST"]:
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setattr(addons, "_home", None)
    monkeypatch.setattr(addons, "_cache", {})
    return tmp_path


def test_a_home_that_listens_and_one_behind_a_firewall_a_message_each_way_with_the_service_out_of_reach(tcp_env):
    port = free_port()
    listener = "tcp:127.0.0.1:%d" % port
    p = Runtime(home=str(tcp_env / "p"), host=NOWHERE, archive=False)
    f = Runtime(home=str(tcp_env / "f"), host=NOWHERE, archive=False)
    try:
        p.partner_add("f", f.keys.public)
        f.partner_add("p", p.keys.public)
        # P is bound without an address: it learns where F is from F's first envelope.
        transports.bind(p, "f", "tcp")
        transports.bind(f, "p", "tcp", address=listener)
        p.transport_service().environ = dict(os.environ, AAMIO_TCP_LISTEN="127.0.0.1:%d" % port, AAMIO_TCP_HERE=listener)
        f.transport_service().environ = dict(os.environ, AAMIO_TCP_PEERS=listener, AAMIO_TCP_NAME="fbehindwall01")
        # P as serve runs it: a listener, which cannot reach its inbox, and the transports beside it.
        p.start(require_inbox=False)
        sent = f.send("p", "hei gjennom brannmuren")
        assert sent["status"] == "confirmed" and sent["via"] == "tcp" and sent["to"] == "p", sent
        got = p.read(wait=10)
        assert [message["body"].get("text") for message in got] == ["hei gjennom brannmuren"], got
        assert got[0]["channel"] == "tcp" and got[0]["verified"] is True and got[0]["known_contact"] is True

        # The answer goes back over the connection F keeps, from the runtime with the listener, as a model sends it.
        answered = mcp_server.dispatch(p, "aamio_send", {"to": "f", "text": "svar til F", "re": got[0]["sha256"]})
        said = answered["structuredContent"]
        assert answered["isError"] is False and said["status"] == "confirmed" and said["via"] == "tcp", said
        back = f.read(wait=10)
        assert [message["body"].get("text") for message in back] == ["svar til F"], back
        assert p.outbox == {} and f.outbox == {}, "nothing went to the HTTPS outbox"

        # Where each is reached, as aamio transport list shows it: P heard F by the name F gave itself, and P's
        # listener says where it is reached, for a card.
        at_p = transports.listing(p)
        row = next(row for row in at_p["bindings"] if row["partner"] == "f")
        assert row["addresses"]["tcp"]["address"] == "tcp:@fbehindwall01" and row["addresses"]["tcp"]["from"] == "heard"
        assert next(item for item in at_p["transports"] if item["name"] == "tcp")["here"] == [listener]
    finally:
        f.close()
        p.close()
