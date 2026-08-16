# SPDX-License-Identifier: AGPL-3.0-or-later
"""Fail-closed contract for the Layer 2 judge (§5.2).

One property, asserted from several directions: there is no path through this
module that yields a deliverable result when the judge did not return a verdict.
Any runtime fallback would be a switch the attacker gets to flip, because the
judge's input is their text.
"""

from __future__ import annotations

import asyncio

import pytest

from sentry_mcp.judge import (
    AnthropicJudge,
    JudgeResult,
    JudgeStatus,
    JudgeUnavailable,
    Verdict,
)


def _run(coro):
    return asyncio.run(coro)


# --- no key is a startup condition, not a request-time fallback --------------


def test_missing_key_refuses_at_startup():
    judge = AnthropicJudge(api_key="")
    assert not judge.available
    with pytest.raises(JudgeUnavailable) as exc:
        judge.require_available()
    assert exc.value.status is JudgeStatus.UNAVAILABLE


def test_missing_key_also_refuses_per_request():
    # Belt and braces: even if require_available() was never called.
    judge = AnthropicJudge(api_key="")
    with pytest.raises(JudgeUnavailable):
        _run(judge.judge("anything"))


def test_configured_judge_passes_the_startup_check():
    AnthropicJudge(api_key="sk-test").require_available()


def test_missing_key_is_not_content_reachable():
    # The one distinction still worth drawing: an operator's configuration
    # state versus a failure a crafted page could have caused.
    assert not JudgeStatus.UNAVAILABLE.is_inducible


@pytest.mark.parametrize(
    "status", [JudgeStatus.TIMEOUT, JudgeStatus.ERROR, JudgeStatus.UNPARSEABLE]
)
def test_runtime_failures_are_content_reachable(status):
    assert status.is_inducible


# --- every runtime failure raises -------------------------------------------


class _Boom:
    """Stands in for the SDK, failing however the test asks."""

    def __init__(self, exc: BaseException | None = None, content=None):
        self._exc = exc
        self._content = content
        self.messages = self

    async def create(self, **_):
        if self._exc is not None:
            raise self._exc
        return type("Resp", (), {"content": self._content or []})()


def _judge_with(stub) -> AnthropicJudge:
    judge = AnthropicJudge(api_key="sk-test")
    judge._client = stub
    return judge


def test_timeout_raises():
    judge = AnthropicJudge(api_key="sk-test", timeout_s=0.01)

    class _Slow:
        def __init__(self):
            self.messages = self

        async def create(self, **_):
            await asyncio.sleep(1)

    judge._client = _Slow()
    with pytest.raises(JudgeUnavailable) as exc:
        _run(judge.judge("content"))
    assert exc.value.status is JudgeStatus.TIMEOUT


def test_transport_error_raises():
    judge = _judge_with(_Boom(exc=ConnectionError("no route")))
    with pytest.raises(JudgeUnavailable) as exc:
        _run(judge.judge("content"))
    assert exc.value.status is JudgeStatus.ERROR


def test_reply_without_the_tool_call_raises():
    judge = _judge_with(_Boom(content=[type("B", (), {"type": "text"})()]))
    with pytest.raises(JudgeUnavailable) as exc:
        _run(judge.judge("content"))
    assert exc.value.status is JudgeStatus.UNPARSEABLE


def test_tool_call_with_non_dict_input_raises():
    block = type("B", (), {"type": "tool_use", "name": "submit_verdict", "input": "nope"})()
    judge = _judge_with(_Boom(content=[block]))
    with pytest.raises(JudgeUnavailable):
        _run(judge.judge("content"))


# --- fast-fail guard changes latency, never outcome -------------------------


def test_guard_trips_after_repeated_failures():
    judge = _judge_with(_Boom(exc=ConnectionError("down")))
    for _ in range(judge.trip_after):
        with pytest.raises(JudgeUnavailable):
            _run(judge.judge("content"))
    assert judge.tripped
    # Still refuses — the guard saves the timeout, it does not change the answer.
    with pytest.raises(JudgeUnavailable):
        _run(judge.judge("content"))


def test_success_resets_the_guard():
    block = type(
        "B",
        (),
        {
            "type": "tool_use",
            "name": "submit_verdict",
            "input": {
                "verdict": "clean",
                "confidence": 1.0,
                "reasoning": "fine",
                "detected_patterns": [],
            },
        },
    )()
    judge = _judge_with(_Boom(exc=ConnectionError("down")))
    with pytest.raises(JudgeUnavailable):
        _run(judge.judge("content"))
    judge._client = _Boom(content=[block])
    result = _run(judge.judge("content"))
    assert result.verdict is Verdict.CLEAN
    assert not judge.tripped


# --- the shape of a result forecloses mishandling ----------------------------


def test_a_result_can_only_describe_a_verdict():
    # There is no failed JudgeResult to forward by accident: the dataclass has
    # no status field and requires a verdict, a confidence and a risk.
    fields = JudgeResult.__dataclass_fields__
    assert "status" not in fields
    for required in ("verdict", "confidence", "risk"):
        assert required in fields
