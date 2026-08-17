# SPDX-License-Identifier: AGPL-3.0-or-later
"""Process entrypoint — what `python -m sentry_mcp` runs.

`deploy/sentry-mcp.service` has named this module in its ExecStart since the
unit was written. Until this file existed, the unit could not start the thing it
declared, and `systemctl start` would have failed at exec.

Startup is fail-closed, extending the reasoning already written into the unit's
EnvironmentFile line. A judge with no API key cannot screen anything, and since
judge failure is terminal (§5.2) there is no degraded mode to fall into — so a
missing key is a refusal to boot, with a configuration exit code, rather than a
service that comes up healthy-looking and refuses every request. The operator
learns at boot, which is the only moment they are watching.
"""

from __future__ import annotations

import logging
import os
import sys

from aiohttp import web

from .judge import AnthropicJudge, JudgeUnavailable
from .server import Config, create_app

# sysexits.h. systemd shows the code in `systemctl status`, so a config refusal
# is distinguishable from a crash without reading the journal.
EX_CONFIG = 78

log = logging.getLogger("sentry_mcp")


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(
        level=os.environ.get("SENTRY_MCP_LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
    )

    try:
        config = Config.from_env()
    except ValueError as exc:
        log.error("refusing to start — bad configuration: %s", exc)
        return EX_CONFIG

    judge = AnthropicJudge()
    try:
        judge.require_available()
    except JudgeUnavailable as exc:
        log.error("refusing to start — %s", exc)
        return EX_CONFIG

    app = create_app(config, judge)

    log.info(
        "listening on %s:%d, upstream %s, judge %s",
        config.host,
        config.port,
        config.upstream_url,
        judge.model,
    )
    # This line said "scanning is NOT active" until 2026-08-17, long after the
    # pipeline was wired in. It contradicted /health in the same boot, which is
    # the worst kind of stale log: one that reassures or alarms wrongly about
    # the single property an operator checks.
    log.info(
        "scanning active — layer 1 heuristics, then %s on every delivered "
        "response; tier 1 only, no boilerplate removal and no image scanning",
        judge.model,
    )
    log.warning(
        "judge egress: fetched page content is sent to the Anthropic API on "
        "every delivered response (spec section 5.2). Running this proxy means "
        "accepting that. A judge failure refuses the response outright."
    )

    # access_log=None on purpose. The tunnel-facing route carries the shared
    # secret in its path (see server._authorised), and an access log would
    # write that secret to the journal on every request, where it would
    # outlive any rotation. Per-fetch outcomes are logged by the server itself
    # — URL, risk, coverage — which is the part worth keeping.
    web.run_app(app, host=config.host, port=config.port, print=None, access_log=None)
    return 0


if __name__ == "__main__":
    sys.exit(main())
