# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tier 3 layer 1 — OCR (spec §5.5).

Text lifted off a screenshot goes through the Layer 1 signals unchanged. That
is the whole design: no per-image cost, nothing leaves the VPS, and the
heuristics are reused rather than reimplemented for pixels.

**OCR-first is an egress decision, not a cost one.** A screenshot discloses far
more than a flagged text span — the whole page, including whatever the browser
session happens to show. §5.5 puts OCR first so most images never leave the
host at all, and only the ones it cannot read escalate to the vision judge.

**A missing engine is a coverage fact, not a failure.** `available` is False
when no OCR backend is installed, `text()` returns nothing, and the caller
records `ocr_unavailable` and escalates — which is the same path an image that
defeats OCR takes anyway (§5.5: OCR-hostile images register as low coverage and
route to the judge). The consequence is more egress, not less screening, and it
is reported rather than inferred.
"""

from __future__ import annotations

import logging
import shutil
from dataclasses import dataclass

log = logging.getLogger(__name__)

# Tesseract is the assumed backend: it is the only widely-packaged local engine
# that needs no model download and no network. It is a system package, not a
# wheel, which is why its absence is handled rather than declared away in
# pyproject.
_BINARY = "tesseract"


@dataclass(frozen=True)
class OCRResult:
    """What OCR could read, and how much of it there was.

    `chars` is reported separately from the text because the caller needs to
    judge whether a near-empty read means a clean image or an unreadable one,
    and it must make that call without holding the text.
    """

    text: str
    engine: str
    chars: int

    @property
    def usable(self) -> bool:
        # An image that yields almost nothing has not been screened by this
        # layer, whatever the reason. Treating a blank read as "clean" is the
        # confident-silence failure the whole spec is written against.
        return self.chars >= MIN_USABLE_CHARS


# Below this, the read is treated as having failed rather than as a clean page.
# A screenshot of a real page carries far more; a handful of characters means
# the engine found edges, not words.
MIN_USABLE_CHARS = 40


def engine_available() -> bool:
    """Whether a local OCR backend can be invoked at all."""
    if shutil.which(_BINARY) is None:
        return False
    try:
        import pytesseract  # noqa: F401
    except ImportError:
        return False
    return True


def read(image: bytes) -> OCRResult | None:
    """Text from a screenshot, or None when no local engine could read it.

    None covers both "no engine installed" and "engine failed", because the
    caller does the same thing with either — escalate, and say `ocr_unavailable`
    — and a distinction that changes no decision is a branch waiting to rot.
    The cause is logged, where it belongs.
    """
    if shutil.which(_BINARY) is None:
        log.info("no %s binary on PATH; tier 3 will escalate to the vision judge", _BINARY)
        return None

    try:
        import io

        import pytesseract
        from PIL import Image
    except ImportError as exc:
        log.info("OCR unavailable (%s); tier 3 will escalate to the vision judge", exc)
        return None

    try:
        with Image.open(io.BytesIO(image)) as img:
            img.load()
            text = pytesseract.image_to_string(img)
    except Exception as exc:  # noqa: BLE001 - any engine failure is one outcome
        log.warning("OCR failed, escalating to the vision judge: %s", exc)
        return None

    cleaned = "\n".join(line.rstrip() for line in text.splitlines() if line.strip())
    return OCRResult(text=cleaned, engine=_BINARY, chars=len(cleaned.strip()))
