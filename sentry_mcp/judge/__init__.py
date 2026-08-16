# SPDX-License-Identifier: AGPL-3.0-or-later
"""Layer 2 of the scoring pipeline — the LLM judge (spec §5.2).

Failure is terminal: `judge()` returns a verdict or raises `JudgeUnavailable`.
There is no degraded result and no fallback policy.
"""

from .client import AnthropicJudge, normalise
from .prompt import SYSTEM_PROMPT, TOOL_NAME, TOOL_SCHEMA, build_user_message
from .types import (
    JudgeResult,
    JudgeStatus,
    JudgeUnavailable,
    Verdict,
    risk_from_verdict,
)

__all__ = [
    "AnthropicJudge",
    "JudgeResult",
    "JudgeStatus",
    "JudgeUnavailable",
    "SYSTEM_PROMPT",
    "TOOL_NAME",
    "TOOL_SCHEMA",
    "Verdict",
    "build_user_message",
    "normalise",
    "risk_from_verdict",
]
