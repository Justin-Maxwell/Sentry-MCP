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

    @property
    def is_failure(self) -> bool:
        return self is not JudgeStatus.OK

    @property
    def is_inducible(self) -> bool:
        """Whether page content could plausibly have caused this failure.

        The judge reads attacker-controlled text, so a failure it can be *made*
        to have is a downgrade attack: the heuristics alone catch well under
        half of attacks, so an attacker who reliably breaks the judge has bought
        themselves that gap. Timeouts, provider-side errors and unparseable
        replies are all reachable from crafted content. A missing API key is
        not — that is an operator choice made before any page was fetched.
        """
        return self in (
            JudgeStatus.TIMEOUT,
            JudgeStatus.ERROR,
            JudgeStatus.UNPARSEABLE,
        )


class Disposition(str, Enum):
    """Whether a failure looks aimed at us or merely broken.

    The distinction is the whole defence. A judge failing on one page while
    succeeding on its neighbours is being attacked; a judge failing on
    everything is an outage. Treating those identically is what makes
    fail-open exploitable — an attacker gets to hide inside the noise of a
    genuine outage, and a genuine outage gets treated as an attack.
    """

    NOT_APPLICABLE = "not_applicable"   # the call succeeded
    LOCAL = "local"                     # this page failed; others are fine
    SYSTEMIC = "systemic"               # the judge is failing broadly
    UNKNOWN = "unknown"                 # too little history to say


class FailurePolicy(str, Enum):
    """What the proxy does when the judge could not return a verdict.

    Configurable per §7, because the right answer depends on the deployment.
    `MARK` is the default: deliver the content, collapse coverage, and make the
    absence of screening loud rather than a boolean nobody reads.
    """

    MARK = "mark"       # deliver, coverage collapses, loud marker
    BLOCK = "block"     # refuse the response entirely
    PASS = "pass"       # deliver with a metadata note only — legacy behaviour


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
    disposition: Disposition = Disposition.NOT_APPLICABLE

    @property
    def invoked(self) -> bool:
        """True when the judge actually ran, whatever the outcome."""
        return self.status is not JudgeStatus.UNAVAILABLE

    @property
    def usable(self) -> bool:
        """True when `risk` carries a real verdict."""
        return self.status is JudgeStatus.OK and self.risk is not None

    @property
    def coverage_ceiling(self) -> int:
        """Upper bound this result places on the response's `coverage` (§5.3).

        A response the judge could not screen has not been fully checked, and
        the coverage axis is where that must show up. Without this, a failed
        judge call produces a low `risk` from the heuristics alone and a high
        coverage that was never earned — which reads downstream as "we looked
        hard and found nothing", the exact false all-clear §5.1 forbids.
        """
        if self.status is JudgeStatus.OK:
            return 100
        if self.disposition is Disposition.LOCAL:
            # Failed here while succeeding elsewhere. Treat as adversarial.
            return 0
        # An outage or an unconfigured judge is still an unscreened response.
        return 25

    @property
    def suspicious_failure(self) -> bool:
        """A failure that content could have induced, on an otherwise healthy judge.

        This is the signal worth acting on: not "the judge broke" but "the judge
        broke on *this page* and nothing else". Callers should treat it as
        evidence in its own right, not as absence of evidence.
        """
        return self.status.is_inducible and self.disposition is Disposition.LOCAL


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
