# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tier 3 image handling — resolution parity (spec §5.5).

**One artefact, judged and delivered.** §5.5's parity rule is not a tunable and
this module exists to make it structural: `downscale` returns a single image,
and the caller has nothing else to hand out. A judge reading a 1568px render
can otherwise be shown text that is illegible to it and legible to an agent
reading the same page at 2576px — a gap the page controls and can aim at.

So the rule is enforced by having no second copy to get out of step. Any change
that raises delivered fidelity has to raise `PARITY_LONG_EDGE`, which raises it
for the judge in the same breath, because both read what this returns.

Downscaling also cuts agent-side cost roughly threefold on a large capture
(4784 → 1560 visual tokens for a 4K screenshot). The fidelity loss is accepted:
§5.5's position is that a caller needing fine detail crops and pastes it
directly rather than routing it through this proxy.

Pillow is the one imaging dependency. It is imported lazily so that a
deployment without it fails at the point of use, with a message naming the
missing package, rather than refusing to start a service whose text tiers are
unaffected.
"""

from __future__ import annotations

import base64
import io
import logging
from dataclasses import dataclass

log = logging.getLogger(__name__)

# The standard resolution tier's long edge, in pixels. Both the judge and the
# agent read an image bounded by this. Raising it is a deliberate act with a
# cost on both sides — see the module docstring.
PARITY_LONG_EDGE = 1568

# Re-encode quality for the delivered artefact. PNG in, JPEG out on anything
# photographic would change bytes for no benefit here, so the format is
# preserved and only the dimensions move.
_FORMAT = "PNG"


class ImagingUnavailable(Exception):
    """Pillow is not installed, so no image can be brought to parity."""


@dataclass(frozen=True)
class Screenshot:
    """One capture, already at parity. There is deliberately no other copy."""

    data: bytes
    media_type: str
    width: int
    height: int
    original_width: int
    original_height: int

    @property
    def downscaled(self) -> bool:
        return (self.width, self.height) != (self.original_width, self.original_height)

    def as_base64(self) -> str:
        return base64.b64encode(self.data).decode("ascii")

    def metadata(self) -> dict:
        return {
            "width": self.width,
            "height": self.height,
            "original_width": self.original_width,
            "original_height": self.original_height,
            "downscaled": self.downscaled,
            "parity_long_edge": PARITY_LONG_EDGE,
            "note": (
                "The judge read this exact image. Nothing legible to a reader "
                "of this artefact was illegible to the judge."
            ),
        }


def _pillow():
    try:
        from PIL import Image
    except ImportError as exc:  # pragma: no cover - exercised by deployment
        raise ImagingUnavailable(
            "Pillow is required for tier 3 image handling; install `pillow`"
        ) from exc
    return Image


def downscale(data: bytes, *, long_edge: int = PARITY_LONG_EDGE) -> Screenshot:
    """Bring a capture to the parity bound. Never upscales.

    A capture already inside the bound is returned re-encoded but unresized,
    so the delivered bytes are always the bytes that were judged, whether or
    not any resizing happened. Returning the original untouched in that case
    would be cheaper and would create exactly the second copy this module is
    written to avoid.
    """
    Image = _pillow()

    with Image.open(io.BytesIO(data)) as img:
        img.load()
        original = img.size
        width, height = original

        longest = max(width, height)
        if longest > long_edge:
            scale = long_edge / longest
            width = max(1, round(width * scale))
            height = max(1, round(height * scale))
            img = img.resize((width, height), Image.LANCZOS)

        if img.mode not in ("RGB", "RGBA", "L"):
            img = img.convert("RGB")

        out = io.BytesIO()
        img.save(out, format=_FORMAT, optimize=True)

    return Screenshot(
        data=out.getvalue(),
        media_type="image/png",
        width=width,
        height=height,
        original_width=original[0],
        original_height=original[1],
    )
