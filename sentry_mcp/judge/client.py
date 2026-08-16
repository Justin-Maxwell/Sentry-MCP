# SPDX-License-Identifier: AGPL-3.0-or-later
"""Anthropic-backed Layer 2 judge (spec §5.2).

Async, to match the aiohttp deployment idiom of the VPS this shares (§3).

Failure discipline, per §5.2: a timeout, transport error, missing key, or reply
that does not match the schema is recorded as a *failure* with no risk value.
It is never reported as a clean verdict, and it never blocks the response — the
caller falls back to the heuristic score and records the judge failure in scan
metadata (§6).
"""

from __future__ import annotations

import asyncio
import os
import time

from .prompt import (
    SYSTEM_PROMPT,
    TOOL_DESCRIPTION,
    TOOL_NAME,
    TOOL_SCHEMA,
    build_user_message,
)
from .types import JudgeResult, JudgeStatus, Verdict, risk_from_verdict

DEFAULT_MODEL = "claude-haiku-4-5"
DEFAULT_TIMEOUT_S = 15.0
DEFAULT_MAX_TOKENS = 256

# Upstream measurement on this model class (n=20, 2026-05-19) put p50 at 1324ms
# for 200 input tokens and 1699ms for 8000 — essentially flat across that range.
# Latency is therefore a poor reason to truncate aggressively, and truncation
# costs coverage (§5.1). 24k characters is roughly 6k tokens: comfortably inside
# the measured flat region, and six times the upstream cap.
DEFAULT_MAX_INPUT_CHARS = 24_000


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
    ) -> None:
        self._api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        self.model = model
        self.timeout_s = timeout_s
        self.max_input_chars = max_input_chars
        self.max_tokens = max_tokens
        self._client = None

    @property
    def available(self) -> bool:
        """Whether a key is configured.

        When false the whole layer is skipped and the heuristic score stands
        alone — a supported posture, not a degraded one (§5.2). Keeping the
        judge unconfigured is also the way to keep page content on the VPS.
        """
        return bool(self._api_key)

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
        """Classify `content`. Never raises; failures come back as a status."""
        if not self.available:
            return JudgeResult(status=JudgeStatus.UNAVAILABLE, model=self.model)

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
            return self._failure(JudgeStatus.TIMEOUT, started, truncated)
        except Exception:
            # Deliberately broad: a provider outage, a rate limit, a network
            # blip and an SDK bug are all "no verdict available", and none of
            # them may take down the fetch they were screening.
            return self._failure(JudgeStatus.ERROR, started, truncated)

        return self._parse(response, started, truncated)

    def _failure(
        self, status: JudgeStatus, started: float, truncated: bool
    ) -> JudgeResult:
        return JudgeResult(
            status=status,
            model=self.model,
            elapsed_ms=round((time.monotonic() - started) * 1000),
            truncated=truncated,
        )

    def _parse(self, response, started: float, truncated: bool) -> JudgeResult:
        elapsed_ms = round((time.monotonic() - started) * 1000)

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
            return JudgeResult(
                status=JudgeStatus.UNPARSEABLE,
                model=self.model,
                elapsed_ms=elapsed_ms,
                truncated=truncated,
            )

        return normalise(
            block.input,
            model=self.model,
            elapsed_ms=elapsed_ms,
            truncated=truncated,
            modality=self.modality,
        )


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
    point — a malformed reply must never read as an all-clear.
    """
    try:
        verdict = Verdict(str(raw.get("verdict", "")).strip().lower())
    except ValueError:
        verdict = Verdict.SUSPICIOUS

    confidence_raw = raw.get("confidence")
    if isinstance(confidence_raw, (int, float)) and confidence_raw == confidence_raw:
        confidence = min(1.0, max(0.0, float(confidence_raw)))
    else:
        confidence = 0.5

    reason = raw.get("reasoning")
    reason = reason.strip() if isinstance(reason, str) and reason.strip() else "no reasoning provided"

    patterns_raw = raw.get("detected_patterns")
    patterns = (
        [p for p in patterns_raw if isinstance(p, str) and p.strip()]
        if isinstance(patterns_raw, list)
        else []
    )

    return JudgeResult(
        status=JudgeStatus.OK,
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
