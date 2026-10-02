"""Internal links and anchors in the user-facing documents resolve.

Prose has no assertion to fail, so a document can claim a section is reachable
when it is not, and the reader only finds out when a click does nothing. That is
the same defect class as citing a test that does not exist
(``docs/lessons-learned.md`` §28) and is caught the same cheap way: look.

Anchors are validated against GitHub's slugger rather than a simplified one. The
subtlety that bit during development: ``-`` is substituted **per space character**,
not per whitespace run, so an em dash sitting between two spaces is stripped as
punctuation and leaves a *double* hyphen behind. A checker that collapses runs
reports those anchors as broken when they are the ones GitHub actually serves,
which would push an edit onto a working link.
"""

from __future__ import annotations

import pathlib
import re

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]

#: Every document a reader follows links inside. ARCHITECTURE.md, ROADMAP.md and
#: the PRD are excluded: they are the canonical records, they are not navigated by
#: anchors, and a layout validator already covers ARCHITECTURE.md against disk.
DOCS = (
    "README.md",
    "docs/runbook.md",
    "docs/offline-install.md",
    "docs/ci-triage-protocol.md",
)

LINK = re.compile(r"\[([^\]]*)\]\(([^)]+)\)")
#: MULTILINE is load-bearing. Without it `^` matches only the first line of the
#: document, `anchors_in()` returns an almost-empty set, and every anchor in every
#: document is reported broken. That failure is loud, which is the only reason it
#: was found immediately rather than being trusted as a real finding.
HEADING = re.compile(r"^#{1,6} (.+)$", re.M)


def slugify(heading: str) -> str:
    """GitHub's heading -> anchor conversion, for the subset these documents use."""
    text = heading.strip().lower()
    text = re.sub(r"`([^`]*)`", r"\1", text)
    text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", text)
    text = re.sub(r"[*_]", "", text)
    text = re.sub(r"[^\w\s-]", "", text, flags=re.UNICODE)
    return re.sub(r"\s", "-", text).strip("-")


def fenced_lines(text: str) -> set[int]:
    """1-indexed line numbers inside fenced code blocks.

    A ``#`` starting a shell comment inside a fence is not a heading and not a
    link target; including them would produce findings that cannot be fixed by
    editing prose.
    """
    inside = False
    fenced: set[int] = set()
    for number, line in enumerate(text.splitlines(), 1):
        if line.startswith("```"):
            inside = not inside
        elif inside:
            fenced.add(number)
    return fenced


def anchors_in(text: str) -> set[str]:
    return {slugify(m.group(1)) for m in HEADING.finditer(text)}


def links_in(text: str, skip: set[int]) -> list[tuple[int, str]]:
    found: list[tuple[int, str]] = []
    for number, line in enumerate(text.splitlines(), 1):
        if number in skip:
            continue
        found.extend((number, target) for _label, target in LINK.findall(line))
    return found


@pytest.mark.parametrize("doc", DOCS)
def test_internal_links_and_anchors_resolve(doc: str) -> None:
    """Every relative link points at a file that exists, and every anchor at a heading."""
    path = REPO_ROOT / doc
    text = path.read_text(encoding="utf-8")
    local = anchors_in(text)
    skip = fenced_lines(text)

    broken: list[str] = []
    for line_no, target in links_in(text, skip):
        if target.startswith(("http://", "https://", "mailto:")):
            continue
        if target.startswith("#"):
            if target[1:] and target[1:] not in local:
                broken.append(f"line {line_no}: anchor {target!r}")
            continue
        file_part, _, fragment = target.partition("#")
        target_path = (path.parent / file_part).resolve()
        if not target_path.exists():
            broken.append(f"line {line_no}: {file_part!r} does not exist")
        elif fragment and fragment not in anchors_in(
            target_path.read_text(encoding="utf-8")
        ):
            broken.append(f"line {line_no}: {target!r} has no matching heading")

    assert not broken, "broken internal links in {}:\n  {}".format(
        doc, "\n  ".join(broken)
    )


def test_control_detects_a_planted_broken_anchor() -> None:
    """Proves the anchor check can fail.

    Without this, a slugifier that strips the whole heading, or a comparison
    against an empty anchor set, would report every document clean and this file
    would be a green light wired to nothing.

    The planted text is a link to an anchor no heading in the repository produces.
    It is a *real* edit to an in-memory copy: the check is re-implemented against
    mutated text, exactly as it runs against the real file.
    """
    path = REPO_ROOT / "docs/runbook.md"
    original = path.read_text(encoding="utf-8")
    planted = original + "\n[see the missing section](#no-such-heading-anywhere)\n"

    skip = fenced_lines(planted)
    available = anchors_in(planted)
    dangling = [
        target
        for _line, target in links_in(planted, skip)
        if target.startswith("#") and target[1:] not in available
    ]

    assert dangling == ["#no-such-heading-anywhere"], (
        "the planted dangling anchor was not detected, so "
        "test_internal_links_and_anchors_resolve proves nothing"
    )

    # And the unplanted text must come back clean, so the control is not merely
    # asserting that everything looks broken.
    clean = [
        target
        for _line, target in links_in(original, skip)
        if target.startswith("#") and target[1:] not in available
    ]
    assert not clean, f"the real document reports dangling anchors: {clean}"


def test_control_slugifier_reproduces_a_double_hyphen_anchor() -> None:
    """Pins the subtlety this file's module docstring is about.

    An em dash between two spaces is removed as punctuation, leaving two spaces,
    and each becomes a hyphen. A slugifier that collapses whitespace runs reports
    the real anchor as broken, which is how a working link gets "fixed" into a
    broken one by the very guard meant to protect it.
    """
    assert slugify("Mechanism B is now executable — and still unverified") == (
        "mechanism-b-is-now-executable--and-still-unverified"
    )
