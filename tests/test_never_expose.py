# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tools that are never proxied, however the config is set (spec §2.1, §4.1).

The upstream advertises 24 tools, four of which reach past the fetched page and
at the host. Hiding them by default is not enough: the escape hatch that exists
for driving the browser directly must not also hand out code execution, and a
caller can name a tool it was never shown.
"""

from __future__ import annotations

import json

from sentry_mcp.server import NEVER_EXPOSE

from test_server_routing import LIST, StubJudge, call, run


def test_dangerous_tools_are_absent_even_when_upstream_is_exposed():
    body, _ = run(StubJudge(), LIST, expose=True)
    names = {t["name"] for t in body["result"]["tools"]}
    assert names & NEVER_EXPOSE == set()
    # The benign ones still come through, so this is a filter and not a switch.
    assert "browser_navigate" in names


def test_naming_a_hidden_tool_directly_is_refused():
    # Advertising is not the only route to a tool.
    body, calls = run(StubJudge(), call(name="browser_run_code_unsafe"), expose=True)
    assert body["error"]["code"] == -32000
    assert "never proxied" in body["error"]["message"]
    assert calls == []


def test_refusal_does_not_depend_on_the_exposure_flag():
    body, calls = run(StubJudge(), call(name="browser_network_request"), expose=False)
    assert "result" not in body
    assert calls == []


def test_the_denylist_names_what_it_should():
    assert NEVER_EXPOSE == {
        "browser_run_code_unsafe",
        "browser_evaluate",
        "browser_network_request",
        "browser_file_upload",
    }


def test_health_publishes_the_denylist():
    # An operator should be able to see what is withheld without reading source.
    import asyncio

    from aiohttp import ClientSession, web

    from sentry_mcp.server import Config, create_app

    async def go():
        runner = web.AppRunner(create_app(Config(port=0), StubJudge()))
        await runner.setup()
        site = web.TCPSite(runner, "127.0.0.1", 0)
        await site.start()
        port = runner.addresses[0][1]
        try:
            async with ClientSession() as s:
                async with s.get(f"http://127.0.0.1:{port}/health") as r:
                    return await r.json()
        finally:
            await runner.cleanup()

    body = asyncio.run(go())
    assert set(body["never_exposed"]) == NEVER_EXPOSE
    assert "upstream_tool_names_verified" not in json.dumps(body)
