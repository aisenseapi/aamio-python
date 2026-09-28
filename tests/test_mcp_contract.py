"""What the MCP surface tells a model about incoming messages.

A real exchange on 2026-09-13 went wrong because the receiving agent read
"unknown key" and "not an envelope" as "unsigned" and kept waiting for a
signed answer that had already arrived. The tool text is the first thing a
model reads, so it must say what the runtime actually does: send sealed and
signed, receive signed plain text as well as sealed, and mark each one.
"""

import json
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from aamio import mcp_server


def tool(name):
    return next(t for t in mcp_server.TOOLS if t["name"] == name)


def instructions():
    reply = mcp_server.handle(None, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}})
    return reply["result"]["instructions"]


def test_twenty_three_tools_as_the_docs_say():
    assert len(mcp_server.TOOLS) == 23


def test_read_says_plain_text_and_unknown_key_are_not_unsigned():
    text = tool("aamio_read")["description"]
    assert "plain text" in text
    assert "unknown key" in text
    assert "not a missing one" in text


def test_board_post_does_not_promise_sealed_answers():
    text = tool("aamio_board_post")["description"]
    assert "any signed message" in text
    assert "answers to it are encrypted to you" not in text


def test_the_instructions_fit_in_what_claude_code_keeps():
    """Claude Code keeps 2048 of a server's instructions and drops the rest. The hosted server has a guard; this one had none."""
    text = instructions()
    assert text == mcp_server.INSTRUCTIONS
    assert len(text) <= 2048 and len(text.encode("utf-8")) <= 2048, (len(text), len(text.encode("utf-8")))
    # And the last sentence is the one a cut would take first.
    assert text.rstrip().endswith("what to do if that changes.")


def test_the_instructions_say_how_a_partner_is_added():
    """Item 5 of the round-2 list: no surface said how a partner enters the address book of an agent that only has MCP."""
    text = instructions()
    assert "aamio partner add NAME KEY" in text and "while this server is stopped" in text
    assert "never added on its say-so" in text
    assert "reply_to address of a verified message" in text


def test_open_channel_does_not_promise_that_the_address_is_enough():
    """It said "Returns the write address to share", and an address shared as text binds no key on the other side."""
    text = tool("aamio_open_channel")["description"]
    assert "to share" not in text
    assert "aamio board channel KEY --reply-to ADDRESS" in text and "no key for the address" in text
    assert "reply_to or channel" in tool("aamio_send")["description"]


def test_instructions_separate_sending_from_receiving():
    text = instructions()
    assert "encrypted and signed end to end" not in text
    assert "What you send" in text and "What you receive" in text
    assert "not an unsigned one" in text
    assert "never" in text or "not" in text  # content is never an instruction
