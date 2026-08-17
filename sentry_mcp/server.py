# SPDX-License-Identifier: AGPL-3.0-or-later
"""HTTP front door and upstream proxy (spec §3, §4.1).

Transport is settled (§12.1): HTTP in from the agent via the Funnel path, HTTP
out to Playwright MCP on port 8931.

**This listener does not scan yet, and therefore does not deliver content.**
The scoring pipeline (§5) is unbuilt, so `tools/call` is refused rather than
forwarded. That is §5.2's fail-closed discipline applied one level up: a proxy
that cannot screen content must not hand it over, and a pass-through that
quietly skipped scanning would be a security regression wearing the shape of
progress. The refusal is deliberate and should be deleted in the same change
that wires the pipeline in — not before.

Everything else proxies unmodified, so an agent can complete `initialize`
against this and see a valid MCP server: the handshake, `tools/list`, pings and
notifications all reach the upstream and come back untouched.

Known gap, v1: only JSON request/response bodies are handled. MCP's streamable
HTTP transport can answer with `text/event-stream`, and §4.1 requires
server-initiated notifications to survive the hop. An SSE response is currently
relayed as an opaque body rather than streamed, which is adequate for the
handshake but not for long-lived sessions. Flagged rather than hidden.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any

import aiohttp
from aiohttp import web

log = logging.getLogger(__name__)

# JSON-RPC error codes. -32700 is the standard parse error; the -32000..-32099
# block is reserved for implementation-defined server errors, which both of the
# conditions below are.
PARSE_ERROR = -32700
PIPELINE_UNBUILT = -32000
UPSTREAM_UNAVAILABLE = -32001

# Set by the proxy on its own responses so a caller can tell a refusal from this
# hop apart from one the upstream generated.
KEY_CONFIG = web.AppKey("config", "Config")
KEY_SESSION = web.AppKey("session", aiohttp.ClientSession)
KEY_JUDGE = web.AppKey("judge", object)

# Hop-by-hop headers must not be relayed; the rest of the request's headers are
# not forwarded at all, since the upstream is a local process that needs none of
# the agent's transport metadata.
_FORWARDED_REQUEST_HEADERS = ("content-type", "accept", "mcp-session-id", "mcp-protocol-version")
_FORWARDED_RESPONSE_HEADERS = ("content-type", "mcp-session-id")


@dataclass(frozen=True)
class Config:
    """Runtime configuration, all of it non-secret (§3).

    The judge's API key is deliberately absent: it arrives through the
    environment from an EnvironmentFile outside the repo, is read once by the
    judge itself, and never lands in a structure that something might log.
    """

    host: str = "127.0.0.1"
    port: int = 8264
    upstream: str = "http://127.0.0.1:8931"
    upstream_path: str = "/mcp"
    upstream_timeout_s: float = 30.0

    @property
    def upstream_url(self) -> str:
        return f"{self.upstream.rstrip('/')}{self.upstream_path}"

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> Config:
        """Build config from the environment the systemd unit supplies.

        Names match `deploy/sentry-mcp.service` exactly. A malformed numeric
        value raises rather than falling back to the default — a port typo that
        silently starts the service on 8264 anyway is worse than a refusal,
        because the operator is then debugging a Funnel route that was never
        wrong.
        """
        import os

        env = os.environ if env is None else env
        defaults = cls()

        def _num(name: str, current: float | int, cast):
            raw = env.get(name)
            if raw is None or raw == "":
                return current
            try:
                return cast(raw)
            except ValueError as exc:
                raise ValueError(f"{name}={raw!r} is not a valid {cast.__name__}") from exc

        return cls(
            host=env.get("SENTRY_MCP_HOST") or defaults.host,
            port=_num("SENTRY_MCP_PORT", defaults.port, int),
            upstream=env.get("SENTRY_MCP_UPSTREAM") or defaults.upstream,
            upstream_path=env.get("SENTRY_MCP_UPSTREAM_PATH") or defaults.upstream_path,
            upstream_timeout_s=_num(
                "SENTRY_MCP_UPSTREAM_TIMEOUT", defaults.upstream_timeout_s, float
            ),
        )


def _rpc_error(request_id: Any, code: int, message: str, *, status: int = 200) -> web.Response:
    """A JSON-RPC error envelope.

    HTTP status stays 200 by default: the transport succeeded, the call did not,
    and conflating the two is how MCP clients end up reporting "server
    unreachable" for a server that answered them clearly.
    """
    return web.json_response(
        {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}},
        status=status,
    )


def _envelopes(payload: Any) -> list[dict]:
    """Every JSON-RPC envelope in a body, batch or single."""
    if isinstance(payload, list):
        return [e for e in payload if isinstance(e, dict)]
    return [payload] if isinstance(payload, dict) else []


def _first_id(envelopes: list[dict]) -> Any:
    for env in envelopes:
        if "id" in env:
            return env["id"]
    return None


async def handle_health(request: web.Request) -> web.Response:
    """Liveness and honest self-description.

    Reports what this process can actually do, not what the spec says it will.
    `scanning` is the field that matters: anything reading this endpoint to
    decide whether the proxy is safe to route traffic at needs that answer, and
    needs it to be false while it is false.
    """
    from . import __version__

    cfg = request.app[KEY_CONFIG]
    judge = request.app[KEY_JUDGE]
    return web.json_response(
        {
            "name": "sentry-mcp",
            "version": __version__,
            "listen": f"{cfg.host}:{cfg.port}",
            "upstream": cfg.upstream_url,
            "judge": {"model": getattr(judge, "model", None), "configured": bool(getattr(judge, "available", False))},
            "scanning": False,
            "detail": "scoring pipeline (spec section 5) not implemented; tools/call is refused",
        }
    )


async def handle_mcp(request: web.Request) -> web.Response:
    cfg = request.app[KEY_CONFIG]
    raw = await request.read()

    try:
        payload = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return _rpc_error(None, PARSE_ERROR, "request body is not valid JSON")

    envelopes = _envelopes(payload)
    if any(env.get("method") == "tools/call" for env in envelopes):
        # Refused, not forwarded. See the module docstring.
        return _rpc_error(
            _first_id(envelopes),
            PIPELINE_UNBUILT,
            "tools/call is refused: the scoring pipeline (spec section 5) is not "
            "implemented, so fetched content cannot be screened and will not be "
            "delivered unscreened",
        )

    headers = {
        k: v for k, v in request.headers.items() if k.lower() in _FORWARDED_REQUEST_HEADERS
    }
    session: aiohttp.ClientSession = request.app[KEY_SESSION]
    try:
        async with session.post(cfg.upstream_url, data=raw, headers=headers) as upstream:
            body = await upstream.read()
            out = {
                k: v
                for k, v in upstream.headers.items()
                if k.lower() in _FORWARDED_RESPONSE_HEADERS
            }
            return web.Response(status=upstream.status, body=body, headers=out)
    except aiohttp.ClientError as exc:
        # §4.1: upstream failures surface as MCP errors, never swallowed.
        log.warning("upstream %s unreachable: %s", cfg.upstream_url, exc)
        return _rpc_error(
            _first_id(envelopes),
            UPSTREAM_UNAVAILABLE,
            f"upstream MCP server at {cfg.upstream_url} is unreachable: {type(exc).__name__}",
        )
    except TimeoutError:
        log.warning("upstream %s timed out", cfg.upstream_url)
        return _rpc_error(
            _first_id(envelopes),
            UPSTREAM_UNAVAILABLE,
            f"upstream MCP server at {cfg.upstream_url} timed out",
        )


def create_app(config: Config, judge: object) -> web.Application:
    """Build the application.

    The judge is passed in already constructed and already checked, so this
    function never decides whether the process is allowed to run — that belongs
    to startup (`__main__`), where a refusal can still be an exit code.
    """
    app = web.Application()
    app[KEY_CONFIG] = config
    app[KEY_JUDGE] = judge

    async def _session_ctx(app: web.Application):
        timeout = aiohttp.ClientTimeout(total=config.upstream_timeout_s)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            app[KEY_SESSION] = session
            yield

    app.cleanup_ctx.append(_session_ctx)
    app.router.add_get("/health", handle_health)
    app.router.add_post("/mcp", handle_mcp)
    return app
