# SPDX-License-Identifier: AGPL-3.0-or-later
"""Judge mapping, normalisation and envelope tests.

No network. Everything here is the deterministic half of §5.2 — the part that
must behave identically whether or not a provider is reachable.
"""

from __future__ import annotations

import math

import pytest

from sentry_mcp.judge import (
    JudgeStatus,
    Verdict,
    build_user_message,
    normalise,
    risk_from_verdict,
)


# --- risk_from_verdict: bands ------------------------------------------------


def test_confident_clean_is_zero_risk():
    assert risk_from_verdict(Verdict.CLEAN, 1.0) == 0


def test_unconfident_clean_still_carries_risk():
    # "The judge looked and shrugged" is not "nothing here".
    assert risk_from_verdict(Verdict.CLEAN, 0.0) == 25


def test_confident_malicious_is_maximum_risk():
    assert risk_from_verdict(Verdict.MALICIOUS, 1.0) == 100


def test_unconfident_malicious_stays_high():
    # A malicious verdict must not fall into the clean band however unsure.
    assert risk_from_verdict(Verdict.MALICIOUS, 0.0) == 70


def test_suspicious_occupies_the_middle():
    assert risk_from_verdict(Verdict.SUSPICIOUS, 0.0) == 30
    assert risk_from_verdict(Verdict.SUSPICIOUS, 1.0) == 70


@pytest.mark.parametrize("confidence", [0.0, 0.25, 0.5, 0.75, 1.0])
def test_bands_never_overlap(confidence):
    clean = risk_from_verdict(Verdict.CLEAN, confidence)
    suspicious = risk_from_verdict(Verdict.SUSPICIOUS, confidence)
    malicious = risk_from_verdict(Verdict.MALICIOUS, confidence)
    assert clean <= 25 < suspicious <= 70 <= malicious


@pytest.mark.parametrize("confidence", [-5.0, 1.5, 99.0])
def test_confidence_is_clamped(confidence):
    assert 0 <= risk_from_verdict(Verdict.SUSPICIOUS, confidence) <= 100


# --- normalise: fails safe ---------------------------------------------------


def _payload(**overrides):
    base = {
        "verdict": "clean",
        "confidence": 0.9,
        "reasoning": "Ordinary article text.",
        "detected_patterns": [],
    }
    base.update(overrides)
    return base


def test_wellformed_payload_passes_through():
    result = normalise(_payload(verdict="malicious", confidence=0.8))
    assert result.status is JudgeStatus.OK
    assert result.verdict is Verdict.MALICIOUS
    assert result.risk == 94
    assert result.usable


def test_unknown_verdict_becomes_suspicious_not_clean():
    result = normalise(_payload(verdict="definitely_fine"))
    assert result.verdict is Verdict.SUSPICIOUS


def test_empty_verdict_becomes_suspicious():
    assert normalise(_payload(verdict="")).verdict is Verdict.SUSPICIOUS


def test_verdict_is_case_and_space_insensitive():
    assert normalise(_payload(verdict="  MALICIOUS ")).verdict is Verdict.MALICIOUS


@pytest.mark.parametrize("bad", [None, "high", [], {}, math.nan])
def test_bad_confidence_defaults_to_one_half(bad):
    assert normalise(_payload(confidence=bad)).confidence == 0.5


def test_missing_fields_do_not_raise():
    result = normalise({})
    assert result.status is JudgeStatus.OK
    assert result.verdict is Verdict.SUSPICIOUS
    assert result.confidence == 0.5
    assert result.patterns == []


def test_blank_reasoning_gets_a_placeholder():
    assert normalise(_payload(reasoning="   ")).reason == "no reasoning provided"


@pytest.mark.parametrize("bad", [None, "instruction_override", 42])
def test_non_list_patterns_become_empty(bad):
    assert normalise(_payload(detected_patterns=bad)).patterns == []


def test_non_string_pattern_entries_are_dropped():
    result = normalise(_payload(detected_patterns=["ok", 3, None, "  ", "also_ok"]))
    assert result.patterns == ["ok", "also_ok"]


def test_garbage_never_produces_a_clean_verdict():
    # The central failure-safety property of §5.2.
    for junk in ({}, {"verdict": None}, {"verdict": 0}, {"verdict": "CLEAN?"}):
        assert normalise(junk).verdict is not Verdict.CLEAN


# --- envelope ----------------------------------------------------------------


def test_content_sits_inside_the_sentinels():
    msg = build_user_message("payload text", nonce="deadbeef")
    assert "<<<SENTRY-DATA-deadbeef>>>" in msg
    assert "<<<END-SENTRY-DATA-deadbeef>>>" in msg
    start = msg.index("<<<SENTRY-DATA-deadbeef>>>")
    end = msg.index("<<<END-SENTRY-DATA-deadbeef>>>")
    assert start < msg.index("payload text") < end


def test_nonce_differs_between_calls():
    # A fixed sentinel could be closed early by content that simply contains it.
    a = build_user_message("x")
    b = build_user_message("x")
    assert a != b


def test_context_stays_outside_the_envelope():
    msg = build_user_message(
        "body",
        url="https://example.com/a",
        tool_name="fetch_rendered",
        tier=1,
        nonce="cafe",
    )
    opening = msg.index("<<<SENTRY-DATA-cafe>>>")
    assert msg.index("https://example.com/a") < opening
    assert msg.index("fetch_rendered") < opening


def test_truncation_is_declared_to_the_judge():
    msg = build_user_message("body", truncated=True, nonce="f00d")
    assert "truncated" in msg.lower()
    assert "coverage is reduced" in msg


def test_content_is_not_defanged():
    # Zero-width and BIDI characters are evidence; defanging is for excerpts
    # travelling onward to the agent (§6), never for judge input.
    payload = "before​after‮"
    msg = build_user_message(payload, nonce="beef")
    assert "​" in msg
    assert "‮" in msg
