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
from typing import Any

import aiohttp

PROTOCOL_VERSION = "2025-06-18"

DEFAULT_NAVIGATE_TOOL = "browser_navigate"
DEFAULT_SNAPSHOT_TOOL = "browser_snapshot"


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
                body = await response.read()
                if response.status >= 400:
                    raise UpstreamError(
                        f"upstream returned HTTP {response.status} for {method}"
                    )
        except aiohttp.ClientError as exc:
            raise UpstreamError(
                f"upstream unreachable: {type(exc).__name__}"
            ) from exc
        except TimeoutError as exc:
            raise UpstreamError(f"upstream timed out on {method}") from exc

        try:
            envelope = json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            # An SSE body lands here. Named explicitly rather than reported as
            # generic malformed JSON, because the fix is different.
            head = body[:40].decode("utf-8", "replace")
            raise UpstreamError(
                f"upstream sent a non-JSON body for {method} (starts {head!r}); "
                "streamable-HTTP event streams are not yet handled"
            ) from exc

        if isinstance(envelope, list):
            raise UpstreamError(f"upstream sent a batch response for {method}")
        if "error" in envelope:
            err = envelope["error"] or {}
            raise UpstreamError(
                f"upstream error on {method}: {err.get('message', 'no message')}",
                code=err.get("code"),
            )
        return envelope.get("result")

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


def has_non_text_blocks(tool_result: dict) -> bool:
    blocks = tool_result.get("content")
    if not isinstance(blocks, list):
        return False
    return any(
        isinstance(b, dict) and b.get("type") not in (None, "text") for b in blocks
    )
