# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tier 2 — chaff removal (spec §1.2 rung 2, §5.4).

Sponsored padding, navigation and footers are what the caller did not ask for,
and they are where injected payloads preferentially sit. Removing them is a
usability feature that doubles as a defence.

**The extract is never what gets scanned.** §5.4's carve-out against §8 is
exact: scan the full page, deliver the extract, let one verdict cover both.
Scanning only the extract would hand an attacker a blind spot with a published
address — put the payload in the footer and the scanner never opens it. This
module therefore returns a *delivery* view and nothing else; it is called after
the pipeline has already scored the whole page.

**Why the accessibility snapshot rather than the raw HTML.** Readability-style
extraction from HTML would produce better prose, and since the §5.1 second view
landed the HTML is available. It is still the wrong input here, for a reason
that is structural rather than aesthetic: the agent receives the snapshot, so
an HTML-derived extract would be text in a form that was never scanned in that
form. The snapshot's own ARIA landmarks — `main`, `banner`, `navigation`,
`contentinfo`, `complementary`, `search` — already mark the chaff explicitly,
by the page's own declaration, and pruning them yields a strict subset of what
Layer 1 and the judge both read. A subset needs no second verdict.

The snapshot is not YAML despite its fence — `- link "x" [ref=f1e2]:` parses as
neither scalar nor mapping — so this walks it by indentation. That is also why
there is no parser dependency: the only structure needed is which lines are
inside which.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field

# Landmarks a reader did not ask for. Every one is the page's own declaration
# about itself, which is why this is not guesswork — a site that labels its
# footer `contentinfo` has told us it is a footer.
#
# `region` is deliberately absent: it is a generic labelled section, and on the
# pages measured it carries the article's own subsections.
CHAFF_ROLES = frozenset(
    {
        "banner",  # masthead
        "contentinfo",  # footer
        "navigation",  # nav bars, breadcrumbs, page tools
        "complementary",  # sidebars, related-content rails
        "search",  # site search widgets
    }
)

MAIN_ROLE = "main"

# Below this, the extract is not worth delivering and the full page goes out
# instead. A page pruned to almost nothing is a failure of the pruner, not a
# page with almost nothing on it, and delivering the remnant would misreport
# the page as empty.
MIN_BODY_CHARS = 120

_FENCE_RE = re.compile(r"^\s*```")
_ROLE_RE = re.compile(r"^-\s+([^\s\[\]\"]+)")


@dataclass
class _Node:
    indent: int
    text: str
    children: list["_Node"] = field(default_factory=list)


@dataclass(frozen=True)
class Extraction:
    """One delivery view, plus what it cost to build.

    `dropped` is reported rather than summarised: an agent told only that
    "chaff was removed" cannot tell a footer from the article, and §6's whole
    posture is that the caller is told what happened to the content.
    """

    text: str
    dropped: dict[str, int]
    kept_chars: int
    original_chars: int
    scoped_to_main: bool

    def metadata(self) -> dict:
        return {
            "applied": True,
            "tier": 2,
            "scoped_to_main": self.scoped_to_main,
            "dropped_landmarks": dict(sorted(self.dropped.items())),
            "kept_chars": self.kept_chars,
            "original_chars": self.original_chars,
            "note": (
                "Chaff was removed from the delivered text. The full page was "
                "scanned, and the scores describe the full page."
            ),
        }


def not_applied(reason: str) -> dict:
    """The §6 block for a fetch that stayed at tier 1.

    Present even when nothing happened, and carrying the cause, so a caller
    reading two scans side by side can tell "no chaff found" from "extraction
    was skipped" without inferring it from a missing key.
    """
    return {"applied": False, "tier": 1, "reason": reason}


def _role(line: str) -> str:
    match = _ROLE_RE.match(line.strip())
    return match.group(1) if match else ""


def _split(text: str) -> tuple[list[str], list[str], list[str]]:
    """Header, fenced body, and trailer — the snapshot's three parts.

    The header carries `- Page URL:` and `- Page Title:`, which the challenge
    detector reads and a caller needs regardless of pruning, so it is passed
    through untouched rather than parsed.
    """
    lines = text.splitlines()
    open_at = None
    for i, line in enumerate(lines):
        if _FENCE_RE.match(line):
            open_at = i
            break
    if open_at is None:
        return lines, [], []

    close_at = None
    for i in range(open_at + 1, len(lines)):
        if _FENCE_RE.match(lines[i]):
            close_at = i
            break
    if close_at is None:
        return lines[: open_at + 1], lines[open_at + 1 :], []
    return lines[: open_at + 1], lines[open_at + 1 : close_at], lines[close_at:]


def _tree(lines: list[str]) -> list[_Node]:
    roots: list[_Node] = []
    stack: list[_Node] = []
    for line in lines:
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip())
        node = _Node(indent, line)
        while stack and stack[-1].indent >= indent:
            stack.pop()
        if stack:
            stack[-1].children.append(node)
        else:
            roots.append(node)
        stack.append(node)
    return roots


def _find_main(nodes: list[_Node]) -> _Node | None:
    for node in nodes:
        if _role(node.text) == MAIN_ROLE:
            return node
        found = _find_main(node.children)
        if found is not None:
            return found
    return None


def _prune(nodes: list[_Node]) -> list[_Node]:
    kept: list[_Node] = []
    for node in nodes:
        if _role(node.text) in CHAFF_ROLES:
            continue
        node.children = _prune(node.children)
        kept.append(node)
    return kept


def _count_chaff(nodes: list[_Node]) -> Counter:
    """Chaff landmarks anywhere beneath `nodes`.

    Counted before and after rather than tallied during the prune, because
    scoping to `main` discards the masthead and the footer without the pruner
    ever visiting them. Tallying inside the prune under-reported exactly the
    two landmarks a reader is most likely to ask about.
    """
    found: Counter = Counter()
    for node in nodes:
        role = _role(node.text)
        if role in CHAFF_ROLES:
            found[role] += 1
        found.update(_count_chaff(node.children))
    return found


def _render(nodes: list[_Node], dedent: int) -> list[str]:
    out: list[str] = []
    for node in nodes:
        out.append(" " * max(0, node.indent - dedent) + node.text.lstrip())
        out.extend(_render(node.children, dedent))
    return out


def strip_chaff(text: str) -> Extraction | None:
    """Prune a snapshot to its content. None when there is nothing worth doing.

    None is not an error. It means the page carried no landmark chaff and no
    `main` — a plain document, already all content — and the caller should
    deliver the original and stay at tier 1.
    """
    header, body, trailer = _split(text)
    if not body:
        return None

    roots = _tree(body)
    before = _count_chaff(roots)
    main = _find_main(roots)

    if main is not None:
        # The page named its own content region. Everything outside it is
        # chaff by the page's own account, so scope to it and prune within —
        # `main` routinely contains its own page-tools navigation.
        kept = _prune([main])
        dedent = main.indent
        scoped = True
    else:
        kept = _prune(roots)
        dedent = 0
        scoped = False
        if not before:
            return None

    dropped = before - _count_chaff(kept)

    rendered = _render(kept, dedent)
    body_chars = sum(len(line.strip()) for line in rendered)
    if body_chars < MIN_BODY_CHARS:
        return None

    out = "\n".join([*header, *rendered, *trailer])
    return Extraction(
        text=out,
        dropped=dict(dropped),
        kept_chars=len(out),
        original_chars=len(text),
        scoped_to_main=scoped,
    )
