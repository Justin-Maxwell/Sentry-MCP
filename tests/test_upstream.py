# SPDX-License-Identifier: AGPL-3.0-or-later
"""Upstream wire-format handling (spec §4.1).

Playwright MCP answers over SSE rather than JSON, including for `initialize`.
These cover the decoding, because getting it wrong surfaces as an unparseable
body rather than as anything that names the cause.
"""

from __future__ import annotations

import json

import pytest

from sentry_mcp.upstream import (
    UpstreamError,
    UpstreamMCP,
    _decode,
    evaluate_payload,
    parse_sse,
)

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


# --- session expiry ----------------------------------------------------------

# Playwright MCP drops sessions abruptly under heavy pages. Both faces of it are
# covered here, because a retry that does not re-handshake cannot help with
# either — the id is gone, not merely unlucky.


class _FakeUpstream(UpstreamMCP):
    """Records calls and replays a scripted sequence of outcomes."""

    def __init__(self, outcomes):
        super().__init__(session=None, url="http://upstream.invalid/mcp")
        self.outcomes = list(outcomes)
        self.calls: list[str] = []
        self.handshakes = 0

    async def initialize(self):
        if not self._initialised:
            self.handshakes += 1
            self._initialised = True
            self._session_id = f"session-{self.handshakes}"
        return {}

    async def _rpc(self, method, params=None):
        self.calls.append(self._session_id)
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


def _expired(message="gone"):
    return UpstreamError(message, session_expired=True)


def _run(coro):
    import asyncio

    return asyncio.run(coro)


def test_an_expired_session_is_retried_on_a_fresh_one():
    up = _FakeUpstream([_expired(), {"content": [{"type": "text", "text": "ok"}]}])
    result = _run(up.call_tool("browser_snapshot"))
    assert result["content"][0]["text"] == "ok"
    assert up.handshakes == 2, "the retry must re-handshake, not reuse the dead id"
    assert up.calls == ["session-1", "session-2"]


def test_the_retry_happens_at_most_once():
    up = _FakeUpstream([_expired("first"), _expired("second")])
    with pytest.raises(UpstreamError, match="second"):
        _run(up.call_tool("browser_snapshot"))
    assert up.handshakes == 2


def test_an_ordinary_error_is_not_retried():
    # A tool that genuinely failed must surface, not be run twice.
    up = _FakeUpstream([UpstreamError("bad arguments", code=-32602)])
    with pytest.raises(UpstreamError, match="bad arguments"):
        _run(up.call_tool("browser_navigate"))
    assert up.handshakes == 1
    assert len(up.calls) == 1


def test_reset_forces_a_fresh_handshake():
    up = _FakeUpstream([{"ok": 1}, {"ok": 2}])
    _run(up.call_tool("browser_snapshot"))
    up.reset()
    _run(up.call_tool("browser_snapshot"))
    assert up.handshakes == 2
    assert up.calls == ["session-1", "session-2"]
