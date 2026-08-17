# SPDX-License-Identifier: AGPL-3.0-or-later
"""Bot-verification and error pages (spec §1.2, §6).

A challenge page is a successful exchange returning the wrong document. Every
scoring layer correctly calls it clean, which is exactly why it needs its own
label: `risk 0` on a CAPTCHA reads as "here is your page, it is safe".

Nothing here attempts to get past a challenge. Detection is by
self-announcement — these pages say what they are, because they are written for
a human to read.
"""

from __future__ import annotations

import pytest

from sentry_mcp.fetch import _summary, detect_challenge

CLOUDFLARE = """### Page
- Page URL: https://example.com/thing
- Page Title: Just a moment...
- HTTP status: 403
### Snapshot
```yaml
- generic: Enable JavaScript and cookies to continue
```"""

ALIEXPRESS = """### Page
- Page URL: https://www.aliexpress.com/item/1.html
- Page Title: Robot Check
### Snapshot
```yaml
- generic: Please slide to verify
```"""

GOOD = """### Page
- Page URL: https://example.com/thing
- Page Title: Widgets for sale
### Snapshot
```yaml
- heading "Widgets"
```"""


def test_cloudflare_interstitial_is_flagged():
    out = detect_challenge(CLOUDFLARE)
    assert out["ok"] is False
    assert out["reason"] == "bot_challenge"
    assert "Just a moment" in out["detail"]


def test_captcha_page_is_flagged_by_title():
    assert detect_challenge(ALIEXPRESS)["reason"] == "bot_challenge"


def test_body_interstitial_is_caught_without_a_matching_title():
    text = GOOD.replace("- heading \"Widgets\"", "- generic: Verify you are human")
    assert detect_challenge(text)["ok"] is False


def test_an_ordinary_page_passes():
    out = detect_challenge(GOOD)
    assert out["ok"] is True
    assert out["http_status"] == 200


@pytest.mark.parametrize("status,reason", [(403, "access_denied"), (429, "access_denied"), (500, "http_error")])
def test_error_statuses_are_named(status, reason):
    text = GOOD.replace("- Page Title: Widgets for sale", f"- Page Title: Widgets\n- HTTP status: {status}")
    assert detect_challenge(text)["reason"] == reason


def test_summary_leads_with_the_warning_not_the_scores():
    block = {
        "risk": 0,
        "coverage": 38,
        "warning_level": "none",
        "tier": 1,
        "llm_judge": {"invoked": True, "verdict": "clean", "reason": "r", "model": "m"},
        "heuristics": {"risk": 0, "signals": {}, "coverage_reductions": []},
        "retrieval": detect_challenge(CLOUDFLARE),
        "flagged_spans": [],
    }
    out = _summary(block).splitlines()
    assert "NOT THE REQUESTED PAGE" in out[1]
    assert "Do not summarise it as if it were" in out[1]


def test_summary_stays_quiet_when_retrieval_is_fine():
    block = {
        "risk": 0,
        "coverage": 38,
        "warning_level": "none",
        "tier": 1,
        "llm_judge": {"invoked": True, "verdict": "clean", "reason": "r", "model": "m"},
        "heuristics": {"risk": 0, "signals": {}, "coverage_reductions": []},
        "retrieval": {"ok": True},
        "flagged_spans": [],
    }
    assert "NOT THE REQUESTED PAGE" not in _summary(block)
