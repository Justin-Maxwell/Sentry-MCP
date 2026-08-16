# SPDX-License-Identifier: AGPL-3.0-or-later
"""Layer 2 of the scoring pipeline — the LLM judge (spec §5.2)."""

from .client import AnthropicJudge, normalise
from .health import JudgeHealth
from .prompt import SYSTEM_PROMPT, TOOL_NAME, TOOL_SCHEMA, build_user_message
from .types import (
    Disposition,
    FailurePolicy,
    JudgeResult,
    JudgeStatus,
    Verdict,
    risk_from_verdict,
)

__all__ = [
    "AnthropicJudge",
    "Disposition",
    "FailurePolicy",
    "JudgeHealth",
    "JudgeResult",
    "JudgeStatus",
    "SYSTEM_PROMPT",
    "TOOL_NAME",
    "TOOL_SCHEMA",
    "Verdict",
    "build_user_message",
    "normalise",
    "risk_from_verdict",
]
