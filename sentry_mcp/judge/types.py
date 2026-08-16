# SPDX-License-Identifier: AGPL-3.0-or-later
"""Types for the Layer 2 judge (spec §5.2).

The judge answers with an enum verdict plus a confidence, not a raw 0-100
number. Models calibrate a three-way choice far better than they calibrate a
percentage, and the mapping to the spec's `risk` axis is then deterministic and
reproducible (§5.3) rather than being another thing the model has to guess.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Verdict(str, Enum):
    """The judge's three-way classification."""

    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"


class JudgeStatus(str, Enum):
    """Why a judge result looks the way it does.

    A failure is never silently a clean verdict — §5.2 requires that an
    unparseable or absent reply is recorded as a failure, not a score of zero.
    """

    OK = "ok"
    TIMEOUT = "timeout"
    UNAVAILABLE = "unavailable"        # no API key configured
    UNPARSEABLE = "unparseable"        # reply did not match the schema
    ERROR = "error"                    # transport or provider failure


@dataclass(frozen=True)
class JudgeResult:
    """One judge invocation.

    `risk` is on the spec's 0-100 scale, ascending with danger (§5.3). It is
    derived from `verdict` and `confidence` by `risk_from_verdict`, never
    returned directly by the model.
    """

    status: JudgeStatus
    verdict: Verdict | None = None
    confidence: float | None = None
    risk: int | None = None
    reason: str = ""
    patterns: list[str] = field(default_factory=list)
    modality: str = "text"
    model: str = ""
    elapsed_ms: int = 0
    truncated: bool = False

    @property
    def invoked(self) -> bool:
        """True when the judge actually ran, whatever the outcome."""
        return self.status is not JudgeStatus.UNAVAILABLE

    @property
    def usable(self) -> bool:
        """True when `risk` carries a real verdict."""
        return self.status is JudgeStatus.OK and self.risk is not None


# Band edges for the verdict -> risk mapping. Deliberately aligned with the
# warning_level buckets in §7 so a `malicious` verdict never lands below the
# `elevated` band no matter how unconfident the model was.
_BANDS: dict[Verdict, tuple[int, int]] = {
    # A confident `clean` is 0; an unconfident one still carries a little risk,
    # because "the judge looked and shrugged" is not the same as "nothing here".
    Verdict.CLEAN: (25, 0),
    Verdict.SUSPICIOUS: (30, 70),
    Verdict.MALICIOUS: (70, 100),
}


def risk_from_verdict(verdict: Verdict, confidence: float) -> int:
    """Map a verdict and confidence onto the 0-100 `risk` axis.

    Confidence scales within the verdict's band. For CLEAN the band runs
    downward, so higher confidence means lower risk; for the other two it runs
    upward. Bands do not overlap, so the verdict alone always determines which
    third of the scale the result lands in.
    """
    lo, hi = _BANDS[verdict]
    c = min(1.0, max(0.0, confidence))
    return round(lo + (hi - lo) * c)
