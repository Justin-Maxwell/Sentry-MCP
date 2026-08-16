# SPDX-License-Identifier: AGPL-3.0-or-later
"""Types for the Layer 2 judge (spec §5.2).

The judge answers with an enum verdict plus a confidence, not a raw 0-100
number. Models calibrate a three-way choice far better than they calibrate a
percentage, and the mapping to the spec's `risk` axis is then deterministic and
reproducible (§5.3) rather than being another thing the model has to guess.

**Failure is terminal.** A judge that cannot return a verdict does not produce a
degraded response; it produces no response. There is no policy knob and no
fallback to heuristics-only, because any runtime fallback is a switch the
attacker gets to flip — the judge reads their text, and the heuristics alone
catch well under half of attacks. If the judge is offline, the proxy is offline.
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
    """Why a judge result looks the way it does."""

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

        This is the one distinction still worth drawing, and it is a
        *startup-versus-runtime* line, not a severity one. Timeouts, provider
        errors and unparseable replies are reachable from crafted content, so
        they are refused at runtime. A missing API key is not reachable from
        content at all — it is a configuration state, decided before any page
        was fetched, and belongs to §5.2's startup check rather than to the
        request path.
        """
        return self in (
            JudgeStatus.TIMEOUT,
            JudgeStatus.ERROR,
            JudgeStatus.UNPARSEABLE,
        )


class JudgeUnavailable(Exception):
    """The judge could not return a verdict, so the response must not be sent.

    Raised rather than returned, so that a caller has to handle it deliberately.
    An earlier design returned a result object carrying a failure status, which
    made "forward it anyway" the path of least resistance — exactly the mistake
    this exception exists to prevent.
    """

    def __init__(self, status: JudgeStatus, detail: str = "") -> None:
        self.status = status
        self.detail = detail
        super().__init__(f"judge unavailable ({status.value}){f': {detail}' if detail else ''}")


@dataclass(frozen=True)
class JudgeResult:
    """One *successful* judge invocation.

    A JudgeResult only ever describes a verdict. Failures raise
    `JudgeUnavailable`; there is no failed JudgeResult to mishandle.

    `risk` is on the spec's 0-100 scale, ascending with danger (§5.3). It is
    derived from `verdict` and `confidence` by `risk_from_verdict`, never
    returned directly by the model.
    """

    verdict: Verdict
    confidence: float
    risk: int
    reason: str = ""
    patterns: list[str] = field(default_factory=list)
    modality: str = "text"
    model: str = ""
    elapsed_ms: int = 0
    truncated: bool = False


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
