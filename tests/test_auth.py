# SPDX-License-Identifier: AGPL-3.0-or-later
"""Shared-secret authentication on /mcp.

Required before the listener is published through the tunnel. While it binds
127.0.0.1 the check is optional, which is why an unset token disables it rather
than refusing to start — but `auth_required` is reported so the state is never
a guess.
"""

from __future__ import annotations

import asyncio
import json

from aiohttp import ClientSession, web

from sentry_mcp.server import Config, create_app

from test_server_routing import StubJudge, make_fake_upstream

TOKEN = "s3cret-token-value"


async def _request(cfg_kw, headers=None, path="/mcp", method="POST"):
    upstream_app, _ = make_fake_upstream()
    up_runner = web.AppRunner(upstream_app)
    await up_runner.setup()
    up_site = web.TCPSite(up_runner, "127.0.0.1", 0)
    await up_site.start()
    up_port = up_runner.addresses[0][1]

    cfg = Config(port=0, upstream=f"http://127.0.0.1:{up_port}", **cfg_kw)
    runner = web.AppRunner(create_app(cfg, StubJudge()))
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = runner.addresses[0][1]
    try:
        async with ClientSession() as session:
            body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
            fn = session.post if method == "POST" else session.get
            kw = {"data": body} if method == "POST" else {}
            async with fn(f"http://127.0.0.1:{port}{path}", headers=headers or {}, **kw) as r:
                return r.status, await r.text()
    finally:
        await runner.cleanup()
        await up_runner.cleanup()


def run(**kw):
    return asyncio.run(_request(**kw))


def test_no_token_configured_leaves_the_door_open():
    # Correct while bound to loopback; the tunnel is what makes it wrong.
    status, _ = run(cfg_kw={})
    assert status == 200


def test_configured_token_rejects_a_request_without_one():
    status, _ = run(cfg_kw={"token": TOKEN})
    assert status == 404


def test_bearer_token_is_accepted():
    status, body = run(
        cfg_kw={"token": TOKEN}, headers={"Authorization": f"Bearer {TOKEN}"}
    )
    assert status == 200
    assert "fetch_rendered" in body


def test_custom_header_is_accepted():
    status, _ = run(cfg_kw={"token": TOKEN}, headers={"X-Sentry-Token": TOKEN})
    assert status == 200


def test_wrong_token_is_rejected():
    status, _ = run(cfg_kw={"token": TOKEN}, headers={"X-Sentry-Token": "nope"})
    assert status == 404


def test_rejection_is_404_not_401():
    # A 401 tells claude.ai this is an OAuth-protected resource and sends it
    # into discovery against /.well-known paths this server does not serve.
    status, _ = run(cfg_kw={"token": TOKEN})
    assert status != 401


def test_query_parameter_is_not_an_accepted_channel():
    # It would be written to the access log on every request.
    status, _ = run(cfg_kw={"token": TOKEN}, path=f"/mcp?token={TOKEN}")
    assert status == 404


def test_health_reports_whether_auth_is_on_but_not_the_secret():
    status, body = run(cfg_kw={"token": TOKEN}, path="/health", method="GET")
    assert status == 200
    assert json.loads(body)["auth_required"] is True
    assert TOKEN not in body
