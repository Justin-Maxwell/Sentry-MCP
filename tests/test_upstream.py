# SPDX-License-Identifier: AGPL-3.0-or-later
"""Upstream wire-format handling (spec §4.1).

Playwright MCP answers over SSE rather than JSON, including for `initialize`.
These cover the decoding, because getting it wrong surfaces as an unparseable
body rather than as anything that names the cause.
"""

from __future__ import annotations

import pytest

from sentry_mcp.upstream import UpstreamError, _decode, parse_sse

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
