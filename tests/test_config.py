# SPDX-License-Identifier: AGPL-3.0-or-later
"""Config parsing (spec §3).

No network, no event loop. These cover the one thing that decides whether the
service comes up where the Funnel expects it, and the one case where being
lenient would cost an operator an afternoon: a malformed number.
"""

from __future__ import annotations

import pytest

from sentry_mcp.server import Config


def test_defaults_match_the_deploy_unit():
    # deploy/sentry-mcp.service pins these; a drift here is a drift there.
    cfg = Config()
    assert cfg.port == 8264
    # localhost, not 127.0.0.1. Playwright MCP's DNS-rebinding guard matches the
    # Host header literally and 403s the dotted form.
    assert cfg.upstream == "http://localhost:8931"


def test_env_overrides_are_applied():
    cfg = Config.from_env(
        {
            "SENTRY_MCP_HOST": "0.0.0.0",
            "SENTRY_MCP_PORT": "9001",
            "SENTRY_MCP_UPSTREAM": "http://10.0.0.5:8931",
        }
    )
    assert (cfg.host, cfg.port, cfg.upstream) == ("0.0.0.0", 9001, "http://10.0.0.5:8931")


def test_empty_env_falls_back_to_defaults():
    # systemd writes Environment=FOO= as an empty string, not an absent key.
    cfg = Config.from_env({"SENTRY_MCP_PORT": "", "SENTRY_MCP_HOST": ""})
    assert cfg.port == 8264
    assert cfg.host == "127.0.0.1"


def test_malformed_port_refuses_rather_than_defaulting():
    # Silently starting on 8264 after a typo sends the operator to debug a
    # Funnel route that was never wrong.
    with pytest.raises(ValueError, match="SENTRY_MCP_PORT"):
        Config.from_env({"SENTRY_MCP_PORT": "82 64"})


def test_upstream_url_joins_without_doubling_the_slash():
    cfg = Config.from_env({"SENTRY_MCP_UPSTREAM": "http://127.0.0.1:8931/"})
    assert cfg.upstream_url == "http://127.0.0.1:8931/mcp"
