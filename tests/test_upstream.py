# SPDX-License-Identifier: AGPL-3.0-or-later
"""Upstream wire-format handling (spec §4.1).

Playwright MCP answers over SSE rather than JSON, including for `initialize`.
These cover the decoding, because getting it wrong surfaces as an unparseable
body rather than as anything that names the cause.
"""

from __future__ import annotations

import json

import pytest

from sentry_mcp.upstream import UpstreamError, _decode, evaluate_payload, parse_sse

SSE = (
    b"event: message\n"
    b'data: {"result":{"protocolVersion":"2025-06-18"},"jsonrpc":"2.0","id":1}\n'
    b"\n"
)


def test_parse_sse_extracts_the_envelope():
    envelopes = parse_sse(SSE)
    assert len(envelopes) == 1
    assert envelopes[0]["id"] == 1


def test_decode_prefers_the_matching_id():
    body = (
        b'data: {"jsonrpc":"2.0","id":1,"result":"first"}\n'
        b'data: {"jsonrpc":"2.0","id":2,"result":"second"}\n'
    )
    assert _decode(body, "text/event-stream", "tools/call", 2)["result"] == "second"


def test_decode_falls_back_to_the_last_event_when_no_id_matches():
    body = b'data: {"jsonrpc":"2.0","result":"unlabelled"}\n'
    assert _decode(body, "text/event-stream", "initialize", 7)["result"] == "unlabelled"


def test_decode_still_handles_plain_json():
    assert _decode(b'{"jsonrpc":"2.0","id":1,"result":1}', "application/json", "x", 1)["id"] == 1


def test_empty_event_stream_is_an_error_not_an_empty_result():
    with pytest.raises(UpstreamError, match="no JSON-RPC data"):
        _decode(b"event: ping\n\n", "text/event-stream", "initialize", 1)


def test_unparseable_json_names_what_it_saw():
    with pytest.raises(UpstreamError, match="unparseable"):
        _decode(b"<html>nope</html>", "application/json", "tools/list", 1)


def test_non_json_data_lines_are_skipped_not_fatal():
    body = b'data: keepalive\ndata: {"jsonrpc":"2.0","id":1,"result":"ok"}\n'
    assert _decode(body, "text/event-stream", "x", 1)["result"] == "ok"


# --- browser_evaluate payloads -----------------------------------------------

# Playwright MCP answers an evaluate with prose for a human reader, so the value
# has to be cut back out. These cases are the ones a live page can actually
# produce; the shape is from Playwright MCP 1.63.0-alpha-2026-08-05.
_REPLY = (
    '### Result\n{\n  "html": "<p>hi</p>",\n  "lang": "en"\n}\n'
    "### Ran Playwright code\n```js\nawait page.evaluate('…');\n```"
)


def _result(text: str) -> dict:
    return {"content": [{"type": "text", "text": text}]}


def test_evaluate_payload_reads_the_value_out_of_the_result_section():
    assert evaluate_payload(_result(_REPLY)) == {"html": "<p>hi</p>", "lang": "en"}


def test_evaluate_payload_stops_at_the_next_heading():
    # The echoed script section is not part of the value and must not be parsed
    # as though it were.
    assert "Ran Playwright code" not in json.dumps(evaluate_payload(_result(_REPLY)))


def test_evaluate_payload_returns_none_for_undefined():
    # A function returning undefined is a page that gave us no view, not a crash.
    assert evaluate_payload(_result("### Result\nundefined")) is None


def test_evaluate_payload_returns_none_when_there_is_no_result_section():
    assert evaluate_payload(_result("### Ran Playwright code\n```js\n```")) is None


def test_evaluate_payload_returns_none_for_a_result_free_tool_result():
    assert evaluate_payload({"content": []}) is None
