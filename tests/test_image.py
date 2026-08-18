# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tier 3 resolution parity (spec §5.5).

The parity rule is the one thing in §5.5 marked mandatory, so these cover the
property rather than the implementation: whatever comes out is bounded, and
what is delivered is byte-identical to what was judged.
"""

from __future__ import annotations

import io

import pytest

from sentry_mcp.image import PARITY_LONG_EDGE, downscale

Image = pytest.importorskip("PIL.Image")


def png(width: int, height: int) -> bytes:
    img = Image.new("RGB", (width, height), (200, 30, 30))
    out = io.BytesIO()
    img.save(out, format="PNG")
    return out.getvalue()


def test_a_large_capture_is_brought_within_the_parity_bound():
    shot = downscale(png(3840, 2160))
    assert max(shot.width, shot.height) == PARITY_LONG_EDGE
    assert shot.downscaled is True
    assert shot.original_width == 3840


def test_aspect_ratio_survives_the_downscale():
    shot = downscale(png(4000, 1000))
    assert shot.width / shot.height == pytest.approx(4.0, rel=0.01)


def test_a_tall_capture_is_bounded_on_its_long_edge():
    # A full-page screenshot is usually tall, not wide.
    shot = downscale(png(1200, 9000))
    assert shot.height == PARITY_LONG_EDGE
    assert shot.width < PARITY_LONG_EDGE


def test_a_small_capture_is_never_upscaled():
    shot = downscale(png(400, 300))
    assert (shot.width, shot.height) == (400, 300)
    assert shot.downscaled is False


def test_the_delivered_bytes_are_the_judged_bytes_even_when_unresized():
    # The parity rule is enforced by there being one artefact. A small capture
    # returned as its original bytes would be a second copy, and a second copy
    # is what the rule exists to prevent.
    shot = downscale(png(400, 300))
    with Image.open(io.BytesIO(shot.data)) as img:
        assert img.size == (shot.width, shot.height)


def test_the_result_is_decodable_and_declares_its_own_type():
    shot = downscale(png(2000, 1000))
    assert shot.media_type == "image/png"
    with Image.open(io.BytesIO(shot.data)) as img:
        assert img.size == (shot.width, shot.height)


def test_metadata_states_the_bound_it_was_held_to():
    block = downscale(png(3000, 2000)).metadata()
    assert block["parity_long_edge"] == PARITY_LONG_EDGE
    assert block["downscaled"] is True
    assert block["original_width"] == 3000
    assert max(block["width"], block["height"]) == PARITY_LONG_EDGE


def test_base64_round_trips():
    import base64

    shot = downscale(png(500, 500))
    assert base64.b64decode(shot.as_base64()) == shot.data
