# SPDX-License-Identifier: AGPL-3.0-or-later
"""Judge health tracking — telling an attack apart from an outage (§5.2).

The judge does most of the detection work, and it reads attacker-controlled
text. That makes "break the judge" a downgrade attack: succeed and the response
falls back to heuristics that catch well under half of attacks.

Failing closed on every judge error is not the answer either — it hands anyone
who can disrupt the provider a total denial of service.

What distinguishes the two cases is history. A judge that fails on one page
while handling its neighbours fine is being attacked. A judge failing on
everything is broken. This module keeps just enough state to tell them apart.
"""

from __future__ import annotations

from collections import deque

from .types import Disposition, JudgeStatus

DEFAULT_WINDOW = 20
DEFAULT_MIN_HISTORY = 5
DEFAULT_SYSTEMIC_RATIO = 0.5
DEFAULT_CONSECUTIVE_SYSTEMIC = 3


class JudgeHealth:
    """A rolling record of recent judge outcomes.

    Not persisted. A restart forgets history and reports UNKNOWN until the
    window refills, which is the honest answer — a fresh process genuinely
    cannot tell an attack from an outage yet.
    """

    def __init__(
        self,
        *,
        window: int = DEFAULT_WINDOW,
        min_history: int = DEFAULT_MIN_HISTORY,
        systemic_ratio: float = DEFAULT_SYSTEMIC_RATIO,
        consecutive_systemic: int = DEFAULT_CONSECUTIVE_SYSTEMIC,
    ) -> None:
        self._outcomes: deque[bool] = deque(maxlen=window)
        self._consecutive_failures = 0
        self.min_history = min_history
        self.systemic_ratio = systemic_ratio
        self.consecutive_systemic = consecutive_systemic

    def record(self, status: JudgeStatus) -> None:
        """Note one outcome. Call for successes too — they are the baseline."""
        ok = status is JudgeStatus.OK
        self._outcomes.append(ok)
        self._consecutive_failures = 0 if ok else self._consecutive_failures + 1

    def classify(self, status: JudgeStatus) -> Disposition:
        """Judge a failure against recent history.

        Call *before* `record`, so the current failure is assessed against what
        came before it rather than against itself.
        """
        if not status.is_failure:
            return Disposition.NOT_APPLICABLE

        # An unconfigured judge is a standing operator choice, not an event.
        if status is JudgeStatus.UNAVAILABLE:
            return Disposition.SYSTEMIC

        if self._consecutive_failures >= self.consecutive_systemic:
            return Disposition.SYSTEMIC

        if len(self._outcomes) < self.min_history:
            return Disposition.UNKNOWN

        failures = sum(1 for ok in self._outcomes if not ok)
        if failures / len(self._outcomes) >= self.systemic_ratio:
            return Disposition.SYSTEMIC

        # The judge is broadly healthy and this page is the exception.
        return Disposition.LOCAL

    @property
    def samples(self) -> int:
        return len(self._outcomes)

    @property
    def success_rate(self) -> float | None:
        if not self._outcomes:
            return None
        return sum(1 for ok in self._outcomes if ok) / len(self._outcomes)

    @property
    def consecutive_failures(self) -> int:
        return self._consecutive_failures
