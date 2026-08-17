# SPDX-License-Identifier: AGPL-3.0-or-later
"""Anthropic-backed Layer 2 judge (spec §5.2).

Async, to match the aiohttp deployment idiom of the VPS this shares (§3).

Failure discipline: a timeout, transport error, or reply that does not match
the schema raises `JudgeUnavailable`. There is no degraded result and no policy
knob. The judge reads attacker-controlled text and does most of the detection
work, so any runtime path that delivers content after the judge failed is a
switch the attacker can flip. If the judge is offline, the proxy is offline.

Absence of an API key is a different thing entirely — a configuration state,
decided before any page was fetched, and not reachable from page content. It is
checked once at startup (`require_available`) rather than being discovered
per-request.
"""

from __future__ import annotations

import asyncio
import logging
import os
import time

from .prompt import (
    SYSTEM_PROMPT,
    TOOL_DESCRIPTION,
    TOOL_NAME,
    TOOL_SCHEMA,
    build_user_message,
)
from .types import (
    JudgeResult,
    JudgeStatus,
    JudgeUnavailable,
    Verdict,
    risk_from_verdict,
)

log = logging.getLogger(__name__)

DEFAULT_MODEL = "claude-haiku-4-5"
DEFAULT_TIMEOUT_S = 15.0
DEFAULT_MAX_TOKENS = 256

# Upstream measurement on this model class (n=20, 2026-05-19) put p50 at 1324ms
# for 200 input tokens and 1699ms for 8000 — essentially flat across that range.
# Latency is therefore a poor reason to truncate aggressively, and truncation
# costs coverage (§5.1). 24k characters is roughly 6k tokens: comfortably inside
# the measured flat region, and six times the upstream cap.
DEFAULT_MAX_INPUT_CHARS = 24_000

# After this many consecutive failures, stop paying the full timeout on every
# request and fail immediately. This is a latency and cost guard only — the
# outcome is identical either way, because every failure already refuses the
# response. It does not decide anything.
DEFAULT_TRIP_AFTER = 3


class AnthropicJudge:
    """Classifies fetched content for injection, one page at a time."""

    modality = "text"

    def __init__(
        self,
        *,
        api_key: str | None = None,
        model: str = DEFAULT_MODEL,
        timeout_s: float = DEFAULT_TIMEOUT_S,
        max_input_chars: int = DEFAULT_MAX_INPUT_CHARS,
        max_tokens: int = DEFAULT_MAX_TOKENS,
        trip_after: int = DEFAULT_TRIP_AFTER,
    ) -> None:
        self._api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        self.model = model
        self.timeout_s = timeout_s
        self.max_input_chars = max_input_chars
        self.max_tokens = max_tokens
        self.trip_after = trip_after
        self._consecutive_failures = 0
        self._client = None

    @property
    def available(self) -> bool:
        """Whether an API key is configured."""
        return bool(self._api_key)

    @property
    def tripped(self) -> bool:
        """Whether the fast-fail guard is currently open."""
        return self._consecutive_failures >= self.trip_after

    def require_available(self) -> None:
        """Startup check (§5.2).

        Call once, at construction of the proxy. A judge with no key cannot
        screen anything, and since failure is terminal there is no useful
        degraded mode to fall into — so this is a refusal to start, not a
        per-request condition. Discovering it at request time would make every
        fetch fail for a reason the operator could have been told about at boot.
        """
        if not self.available:
            raise JudgeUnavailable(
                JudgeStatus.UNAVAILABLE,
                "no API key configured (set ANTHROPIC_API_KEY)",
            )

    def _get_client(self):
        if self._client is None:
            from anthropic import AsyncAnthropic  # imported lazily: optional dep

            self._client = AsyncAnthropic(api_key=self._api_key)
        return self._client

    async def judge(
        self,
        content: str,
        *,
        url: str | None = None,
        tool_name: str | None = None,
        tier: int | None = None,
    ) -> JudgeResult:
        """Classify `content`.

        Returns a verdict, or raises `JudgeUnavailable`. There is no third
        outcome — a caller that does not handle the exception cannot
        accidentally forward unscreened content.
        """
        self.require_available()

        if self.tripped:
            raise JudgeUnavailable(
                JudgeStatus.ERROR,
                f"fast-fail after {self._consecutive_failures} consecutive failures",
            )

        truncated = len(content) > self.max_input_chars
        payload = content[: self.max_input_chars] if truncated else content

        message = build_user_message(
            payload,
            url=url,
            tool_name=tool_name,
            tier=tier,
            truncated=truncated,
        )

        started = time.monotonic()
        try:
            response = await asyncio.wait_for(
                self._get_client().messages.create(
                    model=self.model,
                    max_tokens=self.max_tokens,
                    system=SYSTEM_PROMPT,
                    tools=[
                        {
                            "name": TOOL_NAME,
                            "description": TOOL_DESCRIPTION,
                            "input_schema": TOOL_SCHEMA,
                        }
                    ],
                    tool_choice={"type": "tool", "name": TOOL_NAME},
                    messages=[{"role": "user", "content": message}],
                ),
                timeout=self.timeout_s,
            )
        except asyncio.TimeoutError:
            self._record_failure()
            raise JudgeUnavailable(
                JudgeStatus.TIMEOUT, f"no verdict within {self.timeout_s}s"
            ) from None
        except Exception as exc:
            # Deliberately broad: a provider outage, a rate limit, a network
            # blip and an SDK bug are all "no verdict", and all of them refuse.
            #
            # The *outcome* is identical, but the *diagnosis* is not, and an
            # earlier version raised only `type(exc).__name__`. That made a
            # malformed request, an expired key and a rate limit indistinguishable
            # from each other in the one place an operator looks. The provider's
            # message is included, truncated: it is written by the API, not by
            # the page, and without it a fail-closed system gives no way to find
            # out why it closed.
            self._record_failure()
            detail = f"{type(exc).__name__}: {exc}".strip()
            if len(detail) > 300:
                detail = detail[:299] + "…"
            log.warning("judge call failed: %s", detail)
            raise JudgeUnavailable(JudgeStatus.ERROR, detail) from exc

        block = next(
            (
                b
                for b in getattr(response, "content", [])
                if getattr(b, "type", None) == "tool_use"
                and getattr(b, "name", None) == TOOL_NAME
            ),
            None,
        )
        if block is None or not isinstance(getattr(block, "input", None), dict):
            self._record_failure()
            raise JudgeUnavailable(
                JudgeStatus.UNPARSEABLE, "no submit_verdict tool_use in reply"
            )

        self._consecutive_failures = 0
        return normalise(
            block.input,
            model=self.model,
            elapsed_ms=round((time.monotonic() - started) * 1000),
            truncated=truncated,
            modality=self.modality,
        )

    def _record_failure(self) -> None:
        self._consecutive_failures += 1


def normalise(
    raw: dict,
    *,
    model: str = "",
    elapsed_ms: int = 0,
    truncated: bool = False,
    modality: str = "text",
) -> JudgeResult:
    """Coerce a tool-use payload into a JudgeResult, failing safe.

    Forced tool use plus a strict schema means a well-behaved provider cannot
    send anything else. This exists for the case where one does anyway: an
    unrecognised verdict becomes SUSPICIOUS rather than CLEAN, and a missing or
    non-numeric confidence becomes 0.5. Degrading toward caution is the whole
    point — a malformed field must never read as an all-clear.

    A reply missing the tool call entirely is a different case and never
    reaches here; that raises `JudgeUnavailable`.
    """
    try:
        verdict = Verdict(str(raw.get("verdict", "")).strip().lower())
    except ValueError:
        verdict = Verdict.SUSPICIOUS

    confidence_raw = raw.get("confidence")
    if (
        isinstance(confidence_raw, (int, float))
        and not isinstance(confidence_raw, bool)
        and confidence_raw == confidence_raw  # excludes NaN
    ):
        confidence = min(1.0, max(0.0, float(confidence_raw)))
    else:
        confidence = 0.5

    reason = raw.get("reasoning")
    reason = (
        reason.strip()
        if isinstance(reason, str) and reason.strip()
        else "no reasoning provided"
    )

    patterns_raw = raw.get("detected_patterns")
    patterns = (
        [p for p in patterns_raw if isinstance(p, str) and p.strip()]
        if isinstance(patterns_raw, list)
        else []
    )

    return JudgeResult(
        verdict=verdict,
        confidence=confidence,
        risk=risk_from_verdict(verdict, confidence),
        reason=reason,
        patterns=patterns,
        modality=modality,
        model=model,
        elapsed_ms=elapsed_ms,
        truncated=truncated,
    )
