"""Guard against platform-dependent ``type: ignore`` comments.

A ``# type: ignore`` is *needed* on one platform and *reported as dead* on the
other whenever it papers over something that only exists on one of them. With
``warn_unused_ignores = True`` in ``setup.cfg`` (which the charter's G6 requires),
that turns into a gate that passes on the development host and fails on CI, or
the reverse.

This is not hypothetical. ``agent/sandbox.py`` carried::

    os.setsid()  # type: ignore[attr-defined]

``setsid`` is absent from typeshed on Windows and present on Linux. The ignore was
therefore *used* on the windows/arm64 development host and *unused* on
``ubuntu-latest`` - so G6 passed locally and failed on CI with no other signal.

The rule this test enforces: **an ignore must not sit on a line whose correctness
depends on the host platform.** The reliable fix is not a second ignore but a
construct that type-checks identically everywhere, which in this case was
``getattr(os, "setsid", None)``.

The patterns below are deliberately narrow. They flag ignores on lines that
mention a platform-sensitive module, not every ignore - ``classifier.py`` and the
tests legitimately ignore ``operator``/``arg-type``/``misc`` errors that are
identical on every platform.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Final

_AGENT_DIR: Final[Path] = Path(__file__).resolve().parents[1]

#: Modules whose attributes genuinely differ between platforms and runtimes.
_PLATFORM_SENSITIVE: Final[tuple[str, ...]] = (
    "os.",
    "resource.",
    "sys.platform",
    "os.name",
    "signal.",
    "fcntl.",
    "pwd.",
    "grp.",
    "termios.",
    "pty.",
    "mmap.",
)

_IGNORE: Final[re.Pattern[str]] = re.compile(r"#\s*type:\s*ignore(\[[^\]]*\])?")


def _sources() -> list[Path]:
    return sorted(
        path
        for path in _AGENT_DIR.rglob("*.py")
        if "__pycache__" not in path.parts and path.name != "test_compat_platform.py"
    )


def _code_lines(text: str) -> list[tuple[int, str]]:
    """Lines that are code, with comment-only lines dropped.

    A ``type: ignore`` mentioned inside prose or a docstring is documentation,
    not a directive, and must not be flagged.
    """
    out: list[tuple[int, str]] = []
    in_docstring = False
    for number, raw in enumerate(text.splitlines(), 1):
        stripped = raw.strip()
        if in_docstring:
            if stripped.endswith('"""') or stripped.endswith("'''"):
                in_docstring = False
            continue
        if stripped.startswith(('"""', "'''")):
            in_docstring = not (
                stripped.startswith('"""')
                and stripped.endswith('"""')
                and len(stripped) > 5
            )
            continue
        if stripped.startswith("#") or not stripped:
            continue
        out.append((number, raw))
    return out


class TestNoPlatformDependentIgnores:
    def test_no_ignore_sits_on_a_platform_sensitive_line(self) -> None:
        offenders: list[str] = []
        for path in _sources():
            for number, line in _code_lines(path.read_text(encoding="utf-8")):
                if not _IGNORE.search(line):
                    continue
                for token in _PLATFORM_SENSITIVE:
                    if token in line:
                        offenders.append(
                            f"{path.name}:{number}: ignore on a line using {token!r}\n"
                            f"      {line.strip()}"
                        )
                        break
        assert not offenders, (
            "these type: ignore comments are needed on one platform and reported "
            "as dead on the other, so the gate passes locally and fails on CI. "
            "Use a construct that type-checks identically everywhere - e.g. "
            "getattr(os, 'setsid', None) instead of a bare os.setsid():\n"
            + "\n".join(offenders)
        )

    def test_the_scan_actually_detects_a_platform_dependent_ignore(self) -> None:
        """Negative control.

        Without this, the test above could pass because the scan is broken - and
        a guard that cannot fail is not a guard. The planted line is exactly the
        shape that broke CI, so if the detector is working it must be reported.
        """
        planted = (
            "def _apply() -> None:\n" "    os.setsid()  # type: ignore[attr-defined]\n"
        )
        found = [
            token
            for token in _PLATFORM_SENSITIVE
            for number, line in _code_lines(planted)
            if _IGNORE.search(line) and token in line
        ]
        assert found, "the detector failed to find a planted platform-dependent ignore"

    def test_an_ignore_inside_a_docstring_is_not_flagged(self) -> None:
        """Prose about an ignore is documentation, not a directive."""
        documented = (
            "def f() -> None:\n"
            '    """Historical note:\n'
            "    os.setsid()  # type: ignore[attr-defined]\n"
            "    was replaced with a getattr call.\n"
            '    """\n'
        )
        flagged = [
            token
            for token in _PLATFORM_SENSITIVE
            for number, line in _code_lines(documented)
            if _IGNORE.search(line) and token in line
        ]
        assert not flagged, "a docstring mentioning an ignore must not be flagged"


def test_unused_ignores_are_configured_on() -> None:
    """The setting that turns a dead ignore into a gate failure.

    If this ever goes off, a platform-dependent ignore becomes a silent no-op
    rather than a caught defect, and the guard above stops mattering.
    """
    setup_cfg = _AGENT_DIR.parent / "setup.cfg"
    text = setup_cfg.read_text(encoding="utf-8")
    assert (
        "warn_unused_ignores = True" in text
    ), "setup.cfg must keep warn_unused_ignores = True for this guard to have teeth"
