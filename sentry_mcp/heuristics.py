# SPDX-License-Identifier: AGPL-3.0-or-later
"""Layer 1 — heuristics (spec §5.1).

Always runs, no external calls, bounded work. Seven independently-scored
signals, each returning 0-1 or *not applicable*, combined by a configurable
weighted sum onto the `risk` axis (§5.3).

Two properties this module exists to preserve, both easy to lose by accident:

**Exclusions land on `coverage`, not on `risk`.** A signal whose inputs are
missing is excluded from the weighted sum rather than scored 0 — scoring it 0
would let a page with four unrunnable signals look exactly as safe as a page
where all seven ran clean. Every exclusion reduces `coverage` instead, so the
caller can see how much checking actually happened (§5.1, §5.3).

**Both axes ascend with the quantity named.** High `risk` means dangerous; high
`coverage` means well-checked. Nothing here is named `trust` or `safety`,
per §5.3 — a high-is-good field beside a high-is-bad field is how a fail-open
gets written.

The vendored corpus (`corpus/injection-patterns.json`) is deliberately *not* an
input here. It holds 200 complete attack sentences for embedding similarity,
which is a layer v1 does not implement (§5). Feeding whole sentences to a
substring matcher would detect only verbatim copies. It is used in the tests
instead, as labelled material this layer should score above prose.

HTML is examined by regex, not parsed. This is a heuristic pre-filter whose
misses are covered by the judge, and a parser dependency buys accuracy this
layer does not need. Where that limitation bites, it bites toward false
negatives, which the judge then sees.
"""

from __future__ import annotations

import re
import time
import unicodedata
from dataclasses import dataclass, field

# --- configuration -----------------------------------------------------------

# Weights are tunable config, not hardcoded policy (§5.1). They are relative;
# the combiner normalises by the weight that actually applied.
DEFAULT_WEIGHTS: dict[str, float] = {
    "instruction_override": 1.0,
    "role_hijack": 0.9,
    "invisible_unicode": 0.8,
    "screen_reader_only": 1.0,
    "visible_mismatch": 1.0,
    "structural_placement": 0.7,
    "prose_comments": 0.6,
}

# Bounded work (§5.1). Exceeding either cap yields a scored response over the
# truncated content plus an explicit marker — never an unbounded scan, never a
# silent pass.
DEFAULT_MAX_CHARS = 200_000
DEFAULT_MAX_ELAPSED_S = 2.0


# --- results -----------------------------------------------------------------


@dataclass(frozen=True)
class SignalResult:
    """One signal's contribution.

    `score` is None exactly when `applicable` is False. The two are kept as
    separate fields rather than inferring one from the other because the
    metadata envelope (§6) reports both, and a reader of stored scan logs should
    not have to know the invariant to interpret them.
    """

    name: str
    applicable: bool
    score: float | None
    detail: str = ""
    hits: list[str] = field(default_factory=list)

    @property
    def excluded_reason(self) -> str:
        return "" if self.applicable else (self.detail or "inputs unavailable")


@dataclass(frozen=True)
class HeuristicResult:
    """Layer 1's output — deterministic and replayable (§5.3).

    Kept separate from any judge verdict so that stored scans can be re-scored
    against new weights without re-fetching the page.
    """

    risk: int
    coverage: int
    signals: list[SignalResult]
    truncated: bool = False
    elapsed_ms: int = 0
    scanned_chars: int = 0

    @property
    def applied(self) -> list[SignalResult]:
        return [s for s in self.signals if s.applicable]

    @property
    def excluded(self) -> list[SignalResult]:
        return [s for s in self.signals if not s.applicable]

    def breakdown(self) -> dict[str, object]:
        """Per-signal detail for the metadata envelope (§6)."""
        return {
            s.name: (
                {"score": s.score, "hits": s.hits[:5]}
                if s.applicable
                else {"score": None, "excluded": s.excluded_reason}
            )
            for s in self.signals
        }


@dataclass(frozen=True)
class Content:
    """What Layer 1 was given to look at.

    `text` is what the agent would receive and is the only required view. `html`
    and `visible_text` are the extra views some upstream tools expose; their
    absence disables signals rather than passing them.
    """

    text: str
    html: str | None = None
    visible_text: str | None = None
    language: str | None = None  # None means "not determined"


# --- signal implementations --------------------------------------------------

# Imperative instruction phrases (§5.1 row 1). A maintained list, matched
# case-insensitively. Kept as phrases rather than clever patterns: every entry
# should be readable by someone deciding whether to add or remove it.
_INSTRUCTION_PHRASES = [
    r"ignore (?:all |any )?(?:previous|prior|above|preceding) (?:instructions?|prompts?|directions?)",
    r"disregard (?:all |any )?(?:previous|prior|the above|preceding)",
    r"forget (?:everything|all)(?: you| that)?(?: were told| know)?",
    r"new instructions?\s*[:\-]",
    r"updated? instructions?\s*[:\-]",
    r"system prompt",
    r"</?(?:system|instructions?)>",
    r"\[\s*(?:system|instruction)\s*\]",
    r"do not (?:tell|inform|mention to) the user",
    r"without (?:telling|informing|alerting) the user",
    r"reveal (?:your|the) (?:system )?(?:prompt|instructions?)",
    r"print (?:your|the) (?:system )?(?:prompt|instructions?)",
    r"repeat (?:the |your )?(?:text |words )?above",
    r"override (?:your|the|all) (?:previous |prior )?(?:instructions?|rules?|settings?)",
    r"developer mode",
    r"admin(?:istrator)? (?:mode|override|access)",
]

# Role-play / persona reassignment (§5.1 row 5). Separated from the list above
# because it is a distinct tactic that warrants its own weight, not because the
# matching differs.
_ROLE_PHRASES = [
    r"you are now (?:a|an|the)\b",
    r"you are (?:a|an) [a-z ]{0,24}(?:assistant|ai|model|agent|bot)\b",
    r"from now on,? you",
    r"act as (?:a|an|the)\b",
    r"pretend (?:to be|you are)\b",
    r"roleplay as\b",
    r"your new (?:role|purpose|task|identity|goal) is",
    r"stay in character",
    r"you must (?:now )?(?:obey|comply|follow)",
    r"\bDAN\b mode",
]

_INSTRUCTION_RE = [re.compile(p, re.IGNORECASE) for p in _INSTRUCTION_PHRASES]
_ROLE_RE = [re.compile(p, re.IGNORECASE) for p in _ROLE_PHRASES]

# Codepoints that carry no visible glyph and no legitimate business in fetched
# prose. Tag characters (U+E0000-E007F) matter most: they render as nothing at
# all yet survive copy-paste into a model's context, which is precisely the
# property an attacker wants.
_INVISIBLE_CHARS = {
    "​",  # zero-width space
    "‌",  # zero-width non-joiner
    "‍",  # zero-width joiner
    "⁠",  # word joiner
    "﻿",  # zero-width no-break space / BOM
    "­",  # soft hyphen
    "᠎",  # Mongolian vowel separator
}
_BIDI_CONTROLS = {chr(c) for c in range(0x202A, 0x202F)} | {chr(c) for c in range(0x2066, 0x206A)}


def _match_phrases(text: str, patterns: list[re.Pattern[str]]) -> list[str]:
    hits: list[str] = []
    for pat in patterns:
        m = pat.search(text)
        if m:
            hits.append(m.group(0)[:80])
    return hits


def _saturating(count: int, full: int) -> float:
    """Map a hit count onto 0-1, reaching 1.0 at `full` distinct hits.

    Deliberately saturating rather than linear-unbounded: the difference between
    one injection phrase and two is meaningful, the difference between nine and
    ten is not, and an unbounded count would let a page of quoted security
    research outrank an actual attack.
    """
    if count <= 0:
        return 0.0
    return min(1.0, count / full)


def signal_instruction_override(content: Content) -> SignalResult:
    hits = _match_phrases(content.text, _INSTRUCTION_RE)
    return SignalResult(
        name="instruction_override",
        applicable=True,
        score=_saturating(len(hits), 3),
        detail=f"{len(hits)} distinct imperative phrase(s)",
        hits=hits,
    )


def signal_role_hijack(content: Content) -> SignalResult:
    hits = _match_phrases(content.text, _ROLE_RE)
    return SignalResult(
        name="role_hijack",
        applicable=True,
        score=_saturating(len(hits), 2),
        detail=f"{len(hits)} distinct persona-reassignment phrase(s)",
        hits=hits,
    )


def signal_invisible_unicode(content: Content) -> SignalResult:
    """Zero-width, bidi and format characters (§5.1 row 4).

    Scored on density and on clustering. A lone soft hyphen in a long article is
    typography; a run of them is a payload, and a handful in a short snippet is
    disproportionate either way.
    """
    text = content.text
    if not text:
        return SignalResult("invisible_unicode", True, 0.0, "empty content")

    found: list[str] = []
    count = 0
    longest_run = 0
    run = 0
    for ch in text:
        suspicious = (
            ch in _INVISIBLE_CHARS
            or ch in _BIDI_CONTROLS
            or 0xE0000 <= ord(ch) <= 0xE007F
            or (unicodedata.category(ch) == "Cf")
        )
        if suspicious:
            count += 1
            run += 1
            longest_run = max(longest_run, run)
            if len(found) < 8:
                found.append(f"U+{ord(ch):04X}")
        else:
            run = 0

    if count == 0:
        return SignalResult("invisible_unicode", True, 0.0, "none found")

    density = count / max(len(text), 1)
    # 1 in 500 characters invisible is already well past incidental typography.
    density_score = min(1.0, density * 500)
    cluster_score = min(1.0, longest_run / 4)
    return SignalResult(
        name="invisible_unicode",
        applicable=True,
        score=max(density_score, cluster_score),
        detail=f"{count} invisible codepoint(s), longest run {longest_run}",
        hits=sorted(set(found)),
    )


_ARIA_ATTR_RE = re.compile(
    r"""(?:aria-label|aria-description|aria-roledescription|alt|title)\s*=\s*["']([^"']{12,400})["']""",
    re.IGNORECASE,
)
_SR_ONLY_RE = re.compile(
    r"""class\s*=\s*["'][^"']*\b(?:sr-only|visually-hidden|screen-reader-text|a11y-hidden)\b[^"']*["'][^>]*>([^<]{12,400})""",
    re.IGNORECASE,
)


def signal_screen_reader_only(content: Content) -> SignalResult:
    """Instruction-shaped prose in the accessibility layer (§5.1 row 2).

    The accessibility tree inverts the usual hiding problem: `display:none`,
    `visibility:hidden` and the `hidden` attribute are excluded from Playwright's
    snapshot, so crude hiding never reaches the agent. What survives is the
    sophisticated half — aria attributes, alt text, and the off-screen
    `.sr-only` pattern: text a screen reader speaks and a sighted reader never
    sees. This signal looks only at that half.
    """
    if content.html is None:
        return SignalResult(
            "screen_reader_only", False, None, "no raw HTML available"
        )

    candidates = [m.group(1) for m in _ARIA_ATTR_RE.finditer(content.html)]
    candidates += [m.group(1) for m in _SR_ONLY_RE.finditer(content.html)]

    hits: list[str] = []
    for value in candidates:
        if _match_phrases(value, _INSTRUCTION_RE) or _match_phrases(value, _ROLE_RE):
            hits.append(value.strip()[:80])

    return SignalResult(
        name="screen_reader_only",
        applicable=True,
        score=_saturating(len(hits), 2),
        detail=f"{len(hits)} instruction-shaped value(s) across {len(candidates)} candidate(s)",
        hits=hits,
    )


def signal_visible_mismatch(content: Content) -> SignalResult:
    """Text the agent receives that a viewer never saw (§5.1 row 3).

    Structural rather than keyword-based: it does not care what the extra text
    says, only that it was delivered without being displayed.
    """
    if content.visible_text is None:
        return SignalResult(
            "visible_mismatch", False, None, "no rendered visible text to compare against"
        )

    visible = set(_normalise_words(content.visible_text))
    extracted = _normalise_words(content.text)
    if not extracted:
        return SignalResult("visible_mismatch", True, 0.0, "no extracted text")

    unseen = [w for w in extracted if w not in visible]
    ratio = len(unseen) / len(extracted)
    # Some divergence is normal — the extraction carries link text, table
    # structure and ordering the rendered view flattens. A third is not.
    score = min(1.0, max(0.0, (ratio - 0.10) / 0.30))
    return SignalResult(
        name="visible_mismatch",
        applicable=True,
        score=score,
        detail=f"{ratio:.0%} of extracted words absent from the visible view",
        hits=unseen[:8],
    )


def _normalise_words(text: str) -> list[str]:
    return [w for w in re.split(r"\W+", text.lower()) if len(w) > 2]


_META_RE = re.compile(
    r"""<meta\b[^>]*\bcontent\s*=\s*["']([^"']{12,600})["']""", re.IGNORECASE
)
_TITLE_RE = re.compile(r"<title[^>]*>([^<]{12,600})</title>", re.IGNORECASE)


def signal_structural_placement(content: Content) -> SignalResult:
    """Injection-shaped text outside the main content region (§5.1 row 6).

    Injected text often does not need to render correctly, only to be present in
    what gets extracted — so `<meta>` and `<title>` are cheap places to put it.
    """
    if content.html is None:
        return SignalResult(
            "structural_placement", False, None, "no raw HTML available"
        )

    regions = [("meta", m.group(1)) for m in _META_RE.finditer(content.html)]
    regions += [("title", m.group(1)) for m in _TITLE_RE.finditer(content.html)]

    hits = [
        f"{where}: {value.strip()[:60]}"
        for where, value in regions
        if _match_phrases(value, _INSTRUCTION_RE) or _match_phrases(value, _ROLE_RE)
    ]
    return SignalResult(
        name="structural_placement",
        applicable=True,
        score=_saturating(len(hits), 2),
        detail=f"{len(hits)} instruction-shaped value(s) in {len(regions)} out-of-band region(s)",
        hits=hits,
    )


_COMMENT_RE = re.compile(r"<!--(.*?)-->", re.DOTALL)


def signal_prose_comments(content: Content) -> SignalResult:
    """HTML comments carrying prose (§5.1 row 7).

    Comments exist for notes to developers and for build-tool markers. A comment
    containing full imperative sentences is neither, and comments are a standard
    hiding spot because they never render.
    """
    if content.html is None:
        return SignalResult("prose_comments", False, None, "no raw HTML available")

    comments = [c.strip() for c in _COMMENT_RE.findall(content.html)]
    if not comments:
        return SignalResult("prose_comments", True, 0.0, "no HTML comments")

    flagged: list[str] = []
    prose = 0
    for c in comments:
        words = c.split()
        looks_like_prose = len(words) >= 8 and c.count(" ") > c.count("<")
        if looks_like_prose:
            prose += 1
        if _match_phrases(c, _INSTRUCTION_RE) or _match_phrases(c, _ROLE_RE):
            flagged.append(c[:80])

    # An instruction-bearing comment is the finding. Prose-heavy comments alone
    # are weak corroboration, so they cannot reach the top of the range by
    # themselves.
    score = max(_saturating(len(flagged), 1), min(0.4, _saturating(prose, 4) * 0.4))
    return SignalResult(
        name="prose_comments",
        applicable=True,
        score=score,
        detail=f"{len(comments)} comment(s), {prose} prose-shaped, {len(flagged)} instruction-shaped",
        hits=flagged,
    )


SIGNALS = (
    signal_instruction_override,
    signal_role_hijack,
    signal_invisible_unicode,
    signal_screen_reader_only,
    signal_visible_mismatch,
    signal_structural_placement,
    signal_prose_comments,
)


# --- combination -------------------------------------------------------------


def scan(
    content: Content,
    *,
    weights: dict[str, float] | None = None,
    max_chars: int = DEFAULT_MAX_CHARS,
    max_elapsed_s: float = DEFAULT_MAX_ELAPSED_S,
) -> HeuristicResult:
    """Run Layer 1 and combine the signals.

    `risk` combines the applied signals as a weighted **noisy-OR**:

        risk = 100 * (1 - product over applied i of (1 - score_i * weight_i / max_weight))

    **This deviates from §5.1's "weighted sum", deliberately, and the spec
    should be amended to match.** A weighted mean is dilutable by the attacker,
    who controls the page: with all seven signals running, a maximally confident
    `instruction_override` hit and six clean siblings averages to 17/100, which
    lands in the low-risk band and — at the high coverage those six clean
    signals just earned — is classified "genuinely clean, no judge call" by
    §5.2's matrix. Padding a page with innocuous markup would therefore suppress
    a blatant injection. Noisy-OR has the property the table actually wants:
    the signals are independent evidence of one thing, a clean signal
    contributes a factor of 1 and so cannot dilute, and corroborating hits
    compound. Weights stay configurable and are normalised against the heaviest
    applied signal, so any single full-weight signal at score 1.0 alone reaches
    100.

    Exclusions are charged to `coverage` rather than to `risk`, per §5.1:

        coverage = 100 * (applied_weight / total_weight) * penalties

    where penalties account for truncation and for content whose language was
    not determined — §8's known monolingual gap made visible rather than silent.
    """
    weights = {**DEFAULT_WEIGHTS, **(weights or {})}
    started = time.monotonic()

    truncated = len(content.text) > max_chars or (
        content.html is not None and len(content.html) > max_chars
    )
    if truncated:
        content = Content(
            text=content.text[:max_chars],
            html=content.html[:max_chars] if content.html is not None else None,
            visible_text=(
                content.visible_text[:max_chars]
                if content.visible_text is not None
                else None
            ),
            language=content.language,
        )

    results: list[SignalResult] = []
    for fn in SIGNALS:
        if time.monotonic() - started > max_elapsed_s:
            # Out of budget: remaining signals are excluded, which costs
            # coverage. They are never silently scored 0.
            results.append(
                SignalResult(
                    fn.__name__.removeprefix("signal_"),
                    False,
                    None,
                    "scan time budget exhausted",
                )
            )
            continue
        results.append(fn(content))

    applied = [s for s in results if s.applicable]
    applied_weight = sum(weights.get(s.name, 0.0) for s in applied)
    total_weight = sum(weights.get(s.name, 0.0) for s in results)

    max_weight = max((weights.get(s.name, 0.0) for s in applied), default=0.0)
    if max_weight <= 0:
        risk = 0
    else:
        survival = 1.0
        for s in applied:
            contribution = (s.score or 0.0) * weights.get(s.name, 0.0) / max_weight
            survival *= 1.0 - min(1.0, max(0.0, contribution))
        risk = round(100 * (1.0 - survival))

    coverage_ratio = (applied_weight / total_weight) if total_weight else 0.0
    if truncated:
        coverage_ratio *= 0.7
    if content.language is None:
        coverage_ratio *= 0.85
    elif not content.language.lower().startswith("en"):
        coverage_ratio *= 0.5

    return HeuristicResult(
        risk=max(0, min(100, risk)),
        coverage=max(0, min(100, round(100 * coverage_ratio))),
        signals=results,
        truncated=truncated,
        elapsed_ms=round((time.monotonic() - started) * 1000),
        scanned_chars=len(content.text),
    )
