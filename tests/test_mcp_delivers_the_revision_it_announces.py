"""The local MCP server delivers the revision it announces.

It has said 2026-07-28 in SUPPORTED since that revision was published, and
answered every request the way the revisions before it want: server/discover
was an unknown method, tools/list carried only the tools, and ping was {}.
That revision has no handshake and requires resultType on every result, with
ttlMs and cacheScope on every list. A client that speaks it validates each
answer: Claude Code refused the hosted service's tools/list with "Invalid
result for tools/list: missing required resultType" and showed zero tools
from 16 to 21 September 2026, until the service was fixed. The local servers
had the same gap. Finding MCP-1 of the collaboration round of 21 September.

The older revisions are strict the other way: their reference SDK's empty
result refuses any field, so an older client must get exactly what it got.
The checks here are the ones the service's self-test runs, for both eras.
"""

import io
import json
import os
import sys
from types import SimpleNamespace

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from aamio import mcp_server

MODERN = "2026-07-28"
OLDER = ("2025-11-25", "2025-06-18", "2025-03-26")
LISTS = {"tools/list": "tools", "prompts/list": "prompts", "resources/list": "resources", "resources/templates/list": "resourceTemplates"}

# A runtime whose only job is to answer one reading tool; nothing else is touched.
SCOPED = SimpleNamespace(scope_list=lambda: [{"name": "chapter-review", "address": "a" * 20, "can_read": True}])


def request(method, params=None, version=MODERN, rid=1):
    """A request the way a 2026-07-28 client sends it, or with version None the way an older one does."""
    params = dict(params or {})
    if version is not None:
        params["_meta"] = {
            "io.modelcontextprotocol/protocolVersion": version,
            "io.modelcontextprotocol/clientInfo": {"name": "check", "version": "1"},
            "io.modelcontextprotocol/clientCapabilities": {},
        }
    return {"jsonrpc": "2.0", "id": rid, "method": method, "params": params}


def answer(method, params=None, version=MODERN, runtime=None, session=None):
    return mcp_server.handle(runtime, request(method, params, version), session)


def opened_at(requested):
    """A session in which initialize settled on a revision, the way an older client opens."""
    session = {}
    reply = mcp_server.handle(None, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": requested}}, session)
    return session, reply["result"]


def test_discover_names_the_revisions_and_the_server():
    result = answer("server/discover")["result"]

    assert result["resultType"] == "complete"
    assert result["supportedVersions"] == mcp_server.SUPPORTED and MODERN in result["supportedVersions"]
    assert result["_meta"]["io.modelcontextprotocol/serverInfo"] == {"name": "aamio", "version": mcp_server.__version__}
    # and the capabilities, the instructions and how long to cache them
    assert result["capabilities"]["tools"]["listChanged"] is False
    assert isinstance(result["instructions"], str) and "llms.txt" in result["instructions"]
    assert result["ttlMs"] > 0 and result["cacheScope"] == "public"


def test_a_legacy_client_may_ask_for_discover_too():
    assert answer("server/discover", version=None)["result"]["supportedVersions"] == mcp_server.SUPPORTED


def test_a_modern_tools_list_carries_the_three_fields_and_all_the_tools():
    result = answer("tools/list")["result"]

    assert len(result["tools"]) == len(mcp_server.TOOLS) == 22
    # The shape the revision requires, not only the count.
    assert result["resultType"] == "complete" and result["cacheScope"] == "public" and result["ttlMs"] > 0


def test_every_other_modern_result_carries_result_type_and_every_list_the_cache_hints():
    shapeless = []
    for method in ("ping", "prompts/list", "resources/list", "resources/templates/list", "server/discover"):
        result = answer(method)["result"]
        if result.get("resultType") != "complete":
            shapeless.append(method)
        if method != "ping" and (result.get("cacheScope") != "public" or result.get("ttlMs", 0) <= 0):
            shapeless.append(method + " (ttlMs, cacheScope)")

    assert shapeless == [], shapeless
    for method, field in LISTS.items():
        if method != "tools/list":
            assert answer(method)["result"][field] == [], method


def test_a_modern_tool_result_carries_result_type_and_content():
    result = answer("tools/call", {"name": "aamio_scopes", "arguments": {}}, runtime=SCOPED)["result"]

    assert result["isError"] is False
    assert result["resultType"] == "complete"
    assert isinstance(result["content"], list) and result["content"][0]["type"] == "text"
    assert result["structuredContent"]["scopes"][0]["name"] == "chapter-review"
    assert json.loads(result["content"][0]["text"]) == result["structuredContent"]


def test_a_modern_tool_error_is_a_result_with_result_type_and_is_error():
    # A refused limit is decided before the runtime is touched, so none is needed.
    result = answer("tools/call", {"name": "aamio_read", "arguments": {"limit": 0}})["result"]

    assert result["isError"] is True
    assert result["resultType"] == "complete"
    assert isinstance(result["content"], list) and "limit" in result["structuredContent"]["error"]


def test_protocol_errors_stay_errors_in_both_eras():
    for version in (MODERN, None):
        unknown_tool = answer("tools/call", {"name": "aamio_nope", "arguments": {}}, version=version)
        assert unknown_tool["error"]["code"] == -32602 and "result" not in unknown_tool, version
        unknown_method = answer("nope", version=version)
        assert unknown_method["error"]["code"] == -32601 and "result" not in unknown_method, version
        # and the message lists server/discover among what it does answer
        assert "server/discover" in unknown_method["error"]["message"]


def test_modern_ping_carries_result_type_and_older_ping_is_empty():
    assert answer("ping")["result"] == {"resultType": "complete"}
    assert answer("ping", version=None)["result"] == {}
    for older in OLDER:
        assert answer("ping", version=older)["result"] == {}, older


def test_an_older_client_gets_exactly_the_shapes_it_had():
    for version in (None,) + OLDER:
        assert set(answer("tools/list", version=version)["result"]) == {"tools"}, version
        for method, field in LISTS.items():
            if method != "tools/list":
                assert answer(method, version=version)["result"] == {field: []}, (method, version)
        called = answer("tools/call", {"name": "aamio_scopes", "arguments": {}}, version=version, runtime=SCOPED)["result"]
        assert set(called) == {"content", "structuredContent", "isError"}, version
        assert answer("ping", version=version)["result"] == {}, version


def test_a_revision_this_server_does_not_know_falls_back_as_before():
    # The hosted service refuses 2031-01-01. This server ignores what it does
    # not know and serves the old shapes, as it did before it read _meta at all.
    result = answer("tools/list", version="2031-01-01")["result"]

    assert len(result["tools"]) == 22 and set(result) == {"tools"}
    assert answer("ping", version="2031-01-01")["result"] == {}
    assert answer("server/discover", version="2031-01-01")["result"]["supportedVersions"] == mcp_server.SUPPORTED


def test_what_initialize_settled_holds_for_the_requests_that_name_nothing():
    session, opened = opened_at(MODERN)

    assert opened["protocolVersion"] == MODERN and opened["resultType"] == "complete"
    # No _meta on these, as a client that opened with initialize sends them.
    listed = answer("tools/list", version=None, session=session)["result"]
    assert listed["resultType"] == "complete" and listed["ttlMs"] > 0 and listed["cacheScope"] == "public"
    assert answer("ping", version=None, session=session)["result"] == {"resultType": "complete"}
    called = answer("tools/call", {"name": "aamio_scopes", "arguments": {}}, version=None, runtime=SCOPED, session=session)["result"]
    assert called["resultType"] == "complete" and called["isError"] is False
    # A request that names an older revision itself is served that way, whatever was settled.
    assert answer("ping", version="2025-11-25", session=session)["result"] == {}


def test_an_older_initialize_settles_the_older_shapes():
    for requested in OLDER + ("2031-01-01",):
        session, opened = opened_at(requested)

        assert opened["protocolVersion"] == (requested if requested in mcp_server.SUPPORTED else "2025-11-25"), requested
        assert "resultType" not in opened, requested
        assert answer("ping", version=None, session=session)["result"] == {}, requested
        assert set(answer("tools/list", version=None, session=session)["result"]) == {"tools"}, requested


def test_serve_keeps_what_initialize_settled_from_line_to_line(monkeypatch):
    """Through the stdio loop and not only handle, since the session has to be threaded through it."""
    runtime = SimpleNamespace(start=lambda: None, close=lambda: None, whoami=lambda: {"inbox": "i" * 20}, log=lambda line: None, scope_list=SCOPED.scope_list)
    lines = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": MODERN}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        {"jsonrpc": "2.0", "id": 3, "method": "ping"},
        {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "aamio_scopes", "arguments": {}}},
    ]
    out = io.StringIO()
    monkeypatch.setattr(sys, "stdin", io.StringIO("".join(json.dumps(line) + "\n" for line in lines)))
    monkeypatch.setattr(sys, "stdout", out)
    monkeypatch.setattr(sys, "stderr", io.StringIO())

    mcp_server.serve(runtime)

    replies = [json.loads(line) for line in out.getvalue().splitlines() if line]
    assert [reply["id"] for reply in replies] == [1, 2, 3, 4]
    assert replies[0]["result"]["protocolVersion"] == MODERN
    assert replies[1]["result"]["resultType"] == "complete" and replies[1]["result"]["cacheScope"] == "public"
    assert replies[2]["result"] == {"resultType": "complete"}
    assert replies[3]["result"]["resultType"] == "complete" and replies[3]["result"]["isError"] is False
