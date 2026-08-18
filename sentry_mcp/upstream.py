# SPDX-License-Identifier: AGPL-3.0-or-later
"""Minimal MCP client for the upstream fetch/render server (spec §2.3, §4.1).

HTTP out to Playwright MCP on port 8931 — settled in §12.1, not stdio.

Only what the proxy actually needs: the handshake, `tools/list`, and
`tools/call`. This is not a general MCP client and should not grow into one;
anything beyond those three verbs belongs to the pass-through path in
`server.py`, which relays bytes without understanding them.

Session handling follows streamable HTTP: the server may return an
`Mcp-Session-Id` on initialize, and every later request must carry it. We store
whatever we are given and echo it back, without interpreting it.

**Upstream tool names are unconfirmed.** §4.2 says the names in the spec are
illustrative and must be checked against a live Playwright MCP at implementation
time. No Playwright instance exists on the VPS yet, so `DEFAULT_NAVIGATE_TOOL`
and `DEFAULT_SNAPSHOT_TOOL` are the documented guesses, overridable by config,
and `verify_tools` exists to check them against a live server rather than
assuming.
"""

from __future__ import annotations

import json
import re
from typing import Any

import aiohttp

PROTOCOL_VERSION = "2025-06-18"

# A ceiling on one unterminated event, so a stream that never sends a newline
# cannot grow without bound. Well above any real page's HTML — the largest
# measured is under 500KB — and far below anything that threatens the host.
MAX_EVENT_BYTES = 32 * 1024 * 1024

DEFAULT_NAVIGATE_TOOL = "browser_navigate"
DEFAULT_SNAPSHOT_TOOL = "browser_snapshot"
DEFAULT_EVALUATE_TOOL = "browser_evaluate"


class UpstreamError(Exception):
    """The upstream could not be reached, or answered with an error.

    Carries an optional JSON-RPC error code so the proxy can relay a faithful
    error rather than flattening every upstream failure into one (§4.1).
    """

    def __init__(self, message: str, *, code: int | None = None) -> None:
        self.code = code
        super().__init__(message)


class UpstreamMCP:
    """One conversation with the upstream MCP server."""

    def __init__(
        self,
        session: aiohttp.ClientSession,
        url: str,
        *,
        client_name: str = "sentry-mcp",
        client_version: str = "0.1.0",
    ) -> None:
        self._session = session
        self._url = url
        self._client = {"name": client_name, "version": client_version}
        self._session_id: str | None = None
        self._initialised = False
        self._next_id = 0

    def _id(self) -> int:
        self._next_id += 1
        return self._next_id

    def _headers(self) -> dict[str, str]:
        headers = {
            "Content-Type": "application/json",
            # Streamable HTTP servers may answer either way; we only parse JSON,
            # but refusing to advertise SSE makes some servers 406 outright.
            "Accept": "application/json, text/event-stream",
            "MCP-Protocol-Version": PROTOCOL_VERSION,
        }
        if self._session_id:
            headers["Mcp-Session-Id"] = self._session_id
        return headers

    async def _rpc(self, method: str, params: dict | None = None) -> Any:
        payload = {"jsonrpc": "2.0", "id": self._id(), "method": method}
        if params is not None:
            payload["params"] = params

        try:
            async with self._session.post(
                self._url, data=json.dumps(payload), headers=self._headers()
            ) as response:
                session_id = response.headers.get("Mcp-Session-Id")
                if session_id:
                    self._session_id = session_id
                content_type = response.headers.get("Content-Type", "")

                if response.status < 400 and "text/event-stream" in content_type.lower():
                    # Read the stream rather than the body. An earlier version
                    # called .read() and parsed the result whole, which works
                    # only when the whole answer is already there. Playwright
                    # streams a slow navigation — keepalives and progress first,
                    # the result when it has one — so a heavy page produced a
                    # body with no JSON-RPC data in it and the fetch failed on
                    # precisely the pages worth fetching.
                    return await self._read_stream(response, payload["id"], method)

                body = await response.read()
                if response.status >= 400:
                    detail = body[:120].decode("utf-8", "replace").strip()
                    raise UpstreamError(
                        f"upstream returned HTTP {response.status} for {method}"
                        + (f": {detail}" if detail else "")
                    )
        except aiohttp.ClientError as exc:
            raise UpstreamError(
                f"upstream unreachable: {type(exc).__name__}"
            ) from exc
        except TimeoutError as exc:
            raise UpstreamError(f"upstream timed out on {method}") from exc

        envelope = _decode(body, content_type, method, payload["id"])

        if isinstance(envelope, list):
            raise UpstreamError(f"upstream sent a batch response for {method}")
        if "error" in envelope:
            err = envelope["error"] or {}
            raise UpstreamError(
                f"upstream error on {method}: {err.get('message', 'no message')}",
                code=err.get("code"),
            )
        return envelope.get("result")

    def _line(self, raw: bytes) -> dict | None:
        """One SSE line as a JSON-RPC envelope, or None if it is not one."""
        line = raw.decode("utf-8", "replace").strip()
        if not line.startswith("data:"):
            return None
        chunk = line[len("data:") :].strip()
        if not chunk:
            return None
        try:
            parsed = json.loads(chunk)
        except json.JSONDecodeError:
            return None
        if not isinstance(parsed, dict):
            return None
        return parsed if ("error" in parsed or "result" in parsed) else None

    @staticmethod
    def _unwrap(envelope: dict, method: str) -> Any:
        if "error" in envelope:
            err = envelope["error"] or {}
            raise UpstreamError(
                f"upstream error on {method}: {err.get('message', 'no message')}",
                code=err.get("code"),
            )
        return envelope.get("result")

    async def _read_stream(self, response, request_id: int, method: str) -> Any:
        """Consume an event stream until the answer to `request_id` arrives.

        Returns as soon as a matching envelope appears, so a fetch is not held
        open for whatever the server sends afterwards. Keepalives, comments and
        progress events are skipped rather than treated as content.

        The overall deadline is the session timeout; this loop adds no second
        one, because two timeouts on one operation is how a request ends up
        failing for a reason neither of them names.

        **Split on newlines by hand rather than calling `readline()`.** SSE puts
        one whole JSON-RPC envelope on one `data:` line, and since the §5.1
        second view landed, one of those envelopes carries the page's entire
        HTML — 420KB on an ordinary Wikipedia article. `readline()` caps a line
        at 128KB and raises `LineTooLong`, which is not an `aiohttp.ClientError`
        and so escaped this module's error handling entirely, failing the fetch
        with a traceback rather than a message. Found 2026-08-18 by fetching a
        real page; no fixture was large enough to show it.
        """
        last: dict | None = None
        buffer = bytearray()

        async for chunk in response.content.iter_any():
            buffer.extend(chunk)
            if len(buffer) > MAX_EVENT_BYTES:
                raise UpstreamError(
                    f"upstream sent more than {MAX_EVENT_BYTES} bytes for "
                    f"{method} without completing an event"
                )
            while (newline := buffer.find(b"\n")) != -1:
                raw = bytes(buffer[:newline])
                del buffer[: newline + 1]
                parsed = self._line(raw)
                if parsed is None:
                    continue
                last = parsed
                if parsed.get("id") == request_id:
                    return self._unwrap(parsed, method)

        # A final event with no trailing newline is still an event.
        if buffer:
            parsed = self._line(bytes(buffer))
            if parsed is not None:
                last = parsed
                if parsed.get("id") == request_id:
                    return self._unwrap(parsed, method)

        if last is not None:
            # Answered without echoing our id; only one request is in flight
            # per call here, so this is still our answer.
            return self._unwrap(last, method)

        raise UpstreamError(
            f"upstream closed the event stream for {method} without answering"
        )

    async def initialize(self) -> dict:
        """Complete the handshake. Idempotent — safe to call per request."""
        if self._initialised:
            return {}
        result = await self._rpc(
            "initialize",
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": self._client,
            },
        )
        self._initialised = True
        # The notification is fire-and-forget; a server that rejects it is not
        # a reason to fail the fetch that follows.
        try:
            await self._notify("notifications/initialized")
        except UpstreamError:
            pass
        return result or {}

    async def _notify(self, method: str) -> None:
        payload = {"jsonrpc": "2.0", "method": method}
        try:
            async with self._session.post(
                self._url, data=json.dumps(payload), headers=self._headers()
            ):
                pass
        except (aiohttp.ClientError, TimeoutError) as exc:
            raise UpstreamError(f"notification {method} failed") from exc

    async def list_tools(self) -> list[dict]:
        await self.initialize()
        result = await self._rpc("tools/list")
        return (result or {}).get("tools", [])

    async def call_tool(self, name: str, arguments: dict | None = None) -> dict:
        await self.initialize()
        result = await self._rpc(
            "tools/call", {"name": name, "arguments": arguments or {}}
        )
        return result or {}

    async def verify_tools(self, *names: str) -> dict[str, bool]:
        """Check that the named upstream tools actually exist.

        §4.2 requires the tool names to be confirmed against a live server
        rather than assumed. Call this at startup once an upstream is running,
        so a rename surfaces as a clear message instead of an empty fetch.
        """
        available = {tool.get("name") for tool in await self.list_tools()}
        return {name: name in available for name in names}


def parse_sse(body: bytes) -> list[dict]:
    """Pull JSON-RPC envelopes out of a `text/event-stream` body.

    Streamable HTTP lets a server answer a single request over SSE, and
    Playwright MCP does exactly that — every reply, including `initialize`,
    arrives as `event: message` / `data: {...}` rather than as a JSON body. The
    response is still complete and finite here (Content-Length is set and the
    stream ends), so this parses the whole body rather than streaming it.

    Long-lived streams with server-initiated notifications are still unhandled;
    that needs a different shape entirely and is not what a fetch requires.
    """
    envelopes: list[dict] = []
    for raw_line in body.decode("utf-8", "replace").splitlines():
        line = raw_line.strip()
        if not line.startswith("data:"):
            continue
        chunk = line[len("data:") :].strip()
        if not chunk:
            continue
        try:
            parsed = json.loads(chunk)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            envelopes.append(parsed)
    return envelopes


def _decode(body: bytes, content_type: str, method: str, request_id: int) -> Any:
    """Return the JSON-RPC envelope for `request_id`, whatever the wire format."""
    if "text/event-stream" in content_type.lower():
        envelopes = parse_sse(body)
        if not envelopes:
            raise UpstreamError(
                f"upstream sent an event stream for {method} carrying no JSON-RPC data"
            )
        for envelope in envelopes:
            if envelope.get("id") == request_id:
                return envelope
        # No id match: a server that answers with a single unlabelled event is
        # still answering us, since one request is in flight per call here.
        return envelopes[-1]

    try:
        return json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        head = body[:60].decode("utf-8", "replace")
        raise UpstreamError(
            f"upstream sent an unparseable body for {method} (starts {head!r})"
        ) from exc


def text_blocks(tool_result: dict) -> list[str]:
    """Every text payload in an MCP tool result.

    Tool results carry a list of typed content blocks. Only text is extracted
    here; image blocks belong to tier 3 (§5.5), which is not implemented, and
    silently flattening them into text would misreport what was scanned.
    """
    blocks = tool_result.get("content")
    if not isinstance(blocks, list):
        return []
    return [
        b["text"]
        for b in blocks
        if isinstance(b, dict) and b.get("type") == "text" and isinstance(b.get("text"), str)
    ]


# What `browser_evaluate` wraps its return value in. The tool answers with prose
# for a human reader — a `### Result` section holding the JSON-encoded value,
# then a `### Ran Playwright code` section echoing the script — so the value has
# to be cut back out of the text. Confirmed against Playwright MCP
# 1.63.0-alpha-2026-08-05, 2026-08-18.
_EVAL_RESULT_RE = re.compile(r"^### Result\s*$", re.MULTILINE)


def evaluate_payload(tool_result: dict) -> Any:
    """The value an evaluate call returned, or None if it returned nothing usable.

    None covers every shape of not-a-value in one: no result section, a
    JavaScript `undefined`, or output this parser does not recognise. The caller
    treats all of them the same way — as a view it did not get — so telling them
    apart would buy nothing and would invite a second failure mode.
    """
    for block in text_blocks(tool_result):
        match = _EVAL_RESULT_RE.search(block)
        if not match:
            continue
        body = block[match.end() :]
        # The result section runs until the next heading.
        end = body.find("\n### ")
        if end != -1:
            body = body[:end]
        try:
            return json.loads(body.strip())
        except json.JSONDecodeError:
            return None
    return None


def has_non_text_blocks(tool_result: dict) -> bool:
    blocks = tool_result.get("content")
    if not isinstance(blocks, list):
        return False
    return any(
        isinstance(b, dict) and b.get("type") not in (None, "text") for b in blocks
    )
