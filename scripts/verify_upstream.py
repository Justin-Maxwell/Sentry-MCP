#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Check the configured upstream tool names against the live server (spec §4.2).

§4.2 says the tool names in the spec are illustrative and must be confirmed
against a running Playwright MCP at implementation time. Until this script ran,
`browser_navigate` and `browser_snapshot` were documented guesses that happened
to work — which is not the same as verified, and would have failed silently as
an empty fetch if upstream renamed either.

Run it on the host, against the local upstream:

    /opt/sentry-mcp/.venv/bin/python scripts/verify_upstream.py

Exits non-zero if a configured tool is missing, so it is usable as a
deployment check rather than only as a report.
"""

from __future__ import annotations

import asyncio
import os
import sys

import aiohttp

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sentry_mcp.server import Config  # noqa: E402
from sentry_mcp.upstream import UpstreamError, UpstreamMCP  # noqa: E402


async def main() -> int:
    cfg = Config.from_env()
    print(f"upstream: {cfg.upstream_url}")

    async with aiohttp.ClientSession(
        timeout=aiohttp.ClientTimeout(total=cfg.upstream_timeout_s)
    ) as session:
        upstream = UpstreamMCP(session, cfg.upstream_url)
        try:
            info = await upstream.initialize()
            server = info.get("serverInfo", {})
            print(f"server:   {server.get('name')} {server.get('version')}")
            print(f"protocol: {info.get('protocolVersion')}")
            tools = await upstream.list_tools()
        except UpstreamError as exc:
            print(f"FAILED: {exc}")
            return 1

        names = sorted(t.get("name", "") for t in tools)
        print(f"\n{len(names)} tools advertised:")
        for name in names:
            print(f"  {name}")

        required = {
            "navigate_tool": cfg.navigate_tool,
            "snapshot_tool": cfg.snapshot_tool,
        }
        print("\nconfigured:")
        missing = []
        for label, name in required.items():
            ok = name in names
            print(f"  {label:<14} {name:<24} {'OK' if ok else 'MISSING'}")
            if not ok:
                missing.append(name)

        if missing:
            print(f"\nFAILED: {', '.join(missing)} not advertised by the upstream")
            return 1

    print("\nVERIFIED: configured tool names exist on the live upstream")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
