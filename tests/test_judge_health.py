# SPDX-License-Identifier: AGPL-3.0-or-later
"""Attack-versus-outage classification (§5.2).

The property under test: a judge failure on an otherwise healthy judge is
treated as adversarial, and a judge failing across the board is treated as an
outage. Collapsing those two into one "judge failed" branch is what makes
fail-open exploitable.
"""

from __future__ import annotations

import pytest

from sentry_mcp.judge import Disposition, JudgeHealth, JudgeResult, JudgeStatus


def _healthy(successes: int = 10) -> JudgeHealth:
    h = JudgeHealth()
    for _ in range(successes):
        h.record(JudgeStatus.OK)
    return h


# --- classification ----------------------------------------------------------


def test_success_is_not_a_failure():
    assert _healthy().classify(JudgeStatus.OK) is Disposition.NOT_APPLICABLE


def test_isolated_failure_on_healthy_judge_is_local():
    # The signal that matters: everything else works, this page does not.
    assert _healthy().classify(JudgeStatus.TIMEOUT) is Disposition.LOCAL


def test_cold_start_admits_ignorance():
    # A fresh process genuinely cannot tell an attack from an outage.
    assert JudgeHealth().classify(JudgeStatus.TIMEOUT) is Disposition.UNKNOWN


def test_consecutive_failures_read_as_outage():
    h = _healthy()
    for _ in range(3):
        h.record(JudgeStatus.ERROR)
    assert h.classify(JudgeStatus.ERROR) is Disposition.SYSTEMIC


def test_majority_failure_window_reads_as_outage():
    h = JudgeHealth()
    for _ in range(3):
        h.record(JudgeStatus.OK)
    for _ in range(3):
        h.record(JudgeStatus.ERROR)
    # Alternating keeps consecutive_failures low, so the ratio must catch it.
    h.record(JudgeStatus.OK)
    h.record(JudgeStatus.ERROR)
    assert h.classify(JudgeStatus.ERROR) is Disposition.SYSTEMIC


def test_unconfigured_judge_is_systemic_not_an_attack():
    # An operator choice made before any page was fetched.
    assert _healthy().classify(JudgeStatus.UNAVAILABLE) is Disposition.SYSTEMIC


def test_recovery_clears_the_consecutive_counter():
    h = _healthy()
    for _ in range(3):
        h.record(JudgeStatus.ERROR)
    h.record(JudgeStatus.OK)
    assert h.consecutive_failures == 0
    assert h.classify(JudgeStatus.TIMEOUT) is not Disposition.SYSTEMIC


# --- which failures content can induce ---------------------------------------


@pytest.mark.parametrize(
    "status", [JudgeStatus.TIMEOUT, JudgeStatus.ERROR, JudgeStatus.UNPARSEABLE]
)
def test_content_reachable_failures_are_marked_inducible(status):
    assert status.is_inducible


def test_missing_key_is_not_content_reachable():
    assert not JudgeStatus.UNAVAILABLE.is_inducible


# --- coverage consequences ---------------------------------------------------


def test_successful_judge_permits_full_coverage():
    r = JudgeResult(status=JudgeStatus.OK, risk=10)
    assert r.coverage_ceiling == 100


def test_local_failure_collapses_coverage_to_zero():
    # Without this, a failed judge leaves a low heuristic risk beside a high
    # coverage that was never earned — a false all-clear (§5.1).
    r = JudgeResult(status=JudgeStatus.TIMEOUT, disposition=Disposition.LOCAL)
    assert r.coverage_ceiling == 0


def test_outage_still_caps_coverage():
    # An outage is not the page's fault, but the response is still unscreened.
    r = JudgeResult(status=JudgeStatus.ERROR, disposition=Disposition.SYSTEMIC)
    assert r.coverage_ceiling == 25


def test_unconfigured_judge_caps_coverage():
    r = JudgeResult(status=JudgeStatus.UNAVAILABLE, disposition=Disposition.SYSTEMIC)
    assert r.coverage_ceiling == 25
    assert not r.invoked


def test_suspicious_failure_flags_only_the_targeted_case():
    targeted = JudgeResult(status=JudgeStatus.TIMEOUT, disposition=Disposition.LOCAL)
    outage = JudgeResult(status=JudgeStatus.TIMEOUT, disposition=Disposition.SYSTEMIC)
    unconfigured = JudgeResult(
        status=JudgeStatus.UNAVAILABLE, disposition=Disposition.SYSTEMIC
    )
    assert targeted.suspicious_failure
    assert not outage.suspicious_failure
    assert not unconfigured.suspicious_failure


def test_no_failure_result_is_ever_usable():
    for status in (
        JudgeStatus.TIMEOUT,
        JudgeStatus.ERROR,
        JudgeStatus.UNPARSEABLE,
        JudgeStatus.UNAVAILABLE,
    ):
        assert not JudgeResult(status=status).usable
