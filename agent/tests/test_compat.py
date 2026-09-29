"""Interpreter-compatibility guards (AGENTS.md §2: Python 3.11-slim).

The runtime image is ``python:3.11-slim`` and CI pins Python 3.11 exactly, but
the development host is often newer. That gap has a specific failure mode: a
file can pass every local gate and still fail CI's G5, because a newer
interpreter accepts syntax that 3.11 rejects.

This is not hypothetical. ``test_api.py`` contained an f-string with a
backslash inside its expression part - PEP 701, valid from 3.12. On the 3.14
development host that parsed fine, so black, flake8, mypy and pytest were all
green locally; on CI's 3.11 it was ``SyntaxError: f-string expression part
cannot include a backslash``, and G5 failed with E999 while G4 passed.

The point of this module is that **the local gate must fail first.** A gate
that only breaks on CI is not a gate, it is a notification.

Why a textual scan rather than ``compile()`` or ``ast.parse(feature_version=)``
: both of those are evaluated by the *running* interpreter, so on 3.14 they
report success for precisely the syntax CI rejects. ``ast.parse`` with
``feature_version=(3, 11)`` does not help either - it gates only a handful of
grammar features and does not gate PEP 701. The constructs below are therefore
detected by scanning the source text, which is version-independent.

This is a lint, not a replacement for the interpreter check. The authoritative
verification is still CI on real 3.11, and :func:`_compile_on_target_if_available`
additionally compiles every source with a real 3.11 whenever one is present.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Final

import pytest

#: AGENTS.md §2 and the runtime image. This is the interpreter that must accept
#: every line of the agent, so it is the version all checks below target.
TARGET_PYTHON: Final[tuple[int, int]] = (3, 11)

_AGENT_DIR: Final[Path] = Path(__file__).resolve().parents[1]
_REPO_ROOT: Final[Path] = _AGENT_DIR.parent

_VERSION_BRANCH_MESSAGE: Final[str] = (
    "runtime branching on the interpreter version is not allowed: {locations}"
)


#: Directories whose Python sources must parse on 3.11.
#:
#: ``agent/`` because that is what the image ships. ``tests/`` because both of
#: its subtrees were added to the black/flake8/mypy gates for Milestone 4, and a
#: gate that covers a file inconsistently is worse than one that does not cover
#: it at all - the omission is invisible at the call site.
#:
#: The reason this matters is measured, not assumed. ``mypy --strict`` catches
#: PEP 695 but **silently accepts PEP 701** - a probe with a backslash inside an
#: f-string expression reported ``Success`` under ``--python-version 3.11``,
#: because mypy's parser is the host interpreter's. So extending the type gate
#: did not extend the 3.11 protection; only this scan does.
#:
#: Add a directory here only alongside adding it to the CI gate invocations.
#: A source list and a gate list that disagree produce a file that one of them
#: silently omits.
_GATED_DIRS: Final[tuple[Path, ...]] = (
    _AGENT_DIR,
    _REPO_ROOT / "tests" / "benchmarks",
    _REPO_ROOT / "tests" / "e2e",
)


def _sources() -> list[Path]:
    """Every gated module, excluding caches and this test's siblings."""
    return sorted(
        path
        for directory in _GATED_DIRS
        for path in directory.rglob("*.py")
        if "__pycache__" not in path.parts and path.name != "test_compat.py"
    )


#: ``label -> pattern``. Each pattern matches a construct that a Python older
#: than :data:`TARGET_PYTHON` cannot compile.
#:
#: The backslash case is the important one: PEP 701 lifted the restriction that
#: an f-string expression part could not contain a backslash, and lifted the ban
#: on reusing the enclosing quote inside the expression. Both are invisible to
#: every ``ast``-based check and are the single most likely way for this project
#: to break its own CI.
_BANNED: Final[tuple[tuple[str, re.Pattern[str]], ...]] = (
    (
        "backslash in f-string expression (PEP 701, 3.12+)",
        re.compile(r"""f["'][^"'\n]*\{[^}\n]*\\"""),
    ),
    (
        "f-string reusing its enclosing quote (PEP 701, 3.12+)",
        re.compile(r"""f"[^"\n]*\{[^}\n]*"[^}\n]*\}"""),
    ),
    (
        "match statement (3.10+ soft keyword, rejected before 3.10)",
        re.compile(r"^\s*match\s+.*:\s*$", re.MULTILINE),
    ),
    (
        "PEP 695 type alias (3.12+)",
        re.compile(r"^\s*type\s+[A-Za-z_]\w*\s*=", re.MULTILINE),
    ),
    (
        "PEP 695 generic function (3.12+)",
        re.compile(r"^\s*(?:async\s+)?def\s+[A-Za-z_]\w*\[", re.MULTILINE),
    ),
    (
        "PEP 695 generic class (3.12+)",
        re.compile(r"^\s*class\s+[A-Za-z_]\w*\[", re.MULTILINE),
    ),
    (
        "except* group (3.11+, fine here but flagged so the floor is explicit)",
        re.compile(r"^\s*except\*", re.MULTILINE),
    ),
)


class TestTargetInterpreterCompatibility:
    def test_no_construct_newer_than_the_target_python(self) -> None:
        """Every shipped source must parse on the runtime interpreter."""
        violations: list[str] = []
        for path in _sources():
            for lineno, line in enumerate(
                path.read_text(encoding="utf-8").splitlines(), 1
            ):
                for label, pattern in _BANNED:
                    if pattern.search(line):
                        violations.append(
                            f"{path.relative_to(_REPO_ROOT)}:{lineno}: {label}\n"
                            f"      {line.strip()}"
                        )
        assert not violations, (
            "source uses syntax newer than "
            f"Python {TARGET_PYTHON[0]}.{TARGET_PYTHON[1]}, which is the runtime "
            "image (AGENTS.md §2) and the interpreter CI pins. It will pass every "
            "local gate on a newer host and fail CI's G5 with E999:\n"
            + "\n".join(violations)
        )

    def test_every_source_compiles(self) -> None:
        """A plain sanity check on the running interpreter.

        Cheap, and it turns a file that only one tool happens to parse into an
        immediate, obvious failure.
        """
        for path in _sources():
            compile(path.read_text(encoding="utf-8"), str(path), "exec")


class TestRealTargetInterpreter:
    """Compile every source with an actual Python 3.11, when one is present.

    This is the check that would have caught the original bug on the day it was
    written, rather than in CI. It is skipped when no 3.11 is reachable so the
    suite still runs on a machine that only has one interpreter installed.
    """

    @staticmethod
    def _target_interpreter() -> str | None:
        """Locate a real 3.11, preferring one on PATH."""
        for candidate in ("python3.11", "python3.12", "python3.13"):
            found = shutil.which(candidate)
            if found:
                return found
        # uv-managed interpreters, if uv is installed.
        uv = shutil.which("uv")
        if uv:
            try:
                completed = subprocess.run(
                    [uv, "python", "find", "3.11"],
                    capture_output=True,
                    text=True,
                    timeout=60,
                    check=False,
                )
            except (OSError, subprocess.SubprocessError):
                return None
            if completed.returncode == 0:
                candidate = completed.stdout.strip()
                if candidate:
                    return candidate
        return None

    def test_sources_compile_under_a_real_target_interpreter(self) -> None:
        interpreter = self._target_interpreter()
        if interpreter is None:
            pytest.skip("no Python 3.11 reachable; CI remains the authority")

        version = subprocess.run(
            [interpreter, "--version"],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        assert f"3.{TARGET_PYTHON[1]}." in version.stdout, (
            f"expected a {TARGET_PYTHON[0]}.{TARGET_PYTHON[1]} interpreter, "
            f"got {version.stdout.strip()}"
        )

        checker = (
            "import pathlib, sys\n"
            "bad = 0\n"
            "for f in sorted(p for p in pathlib.Path(sys.argv[1]).rglob('*.py')\n"
            "               if '__pycache__' not in p.parts):\n"
            "    try:\n"
            "        compile(f.read_text(encoding='utf-8'), str(f), 'exec')\n"
            "    except SyntaxError as e:\n"
            "        bad += 1\n"
            "        print(f'{f}:{e.lineno}: {e.msg}')\n"
            "sys.exit(1 if bad else 0)\n"
        )
        completed = subprocess.run(
            [interpreter, "-c", checker, str(_AGENT_DIR)],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        assert completed.returncode == 0, (
            "these sources do not compile on the runtime interpreter "
            f"(Python {TARGET_PYTHON[0]}.{TARGET_PYTHON[1]}):\n"
            f"{completed.stdout}{completed.stderr}"
        )


class TestNoUnpinnedInterpreterFeatures:
    def test_agent_does_not_read_sys_version_at_runtime(self) -> None:
        """Version-dependent runtime branching cannot be tested here.

        A branch on ``sys.version_info`` would make behaviour differ between the
        development host and the image, so it is rejected rather than reviewed.
        """
        offenders: list[str] = []
        for path in _sources():
            for lineno, line in enumerate(
                path.read_text(encoding="utf-8").splitlines(), 1
            ):
                if "sys.version_info" in line:
                    offenders.append(f"{path.relative_to(_REPO_ROOT)}:{lineno}")
        # The message is bound to a name rather than inlined in the assert.
        # black splits an inline `assert x, ("a" + ", ".join(y))` differently
        # depending on the host interpreter's inferred target version, which is
        # a formatting difference between otherwise identical tool versions.
        assert not offenders, _VERSION_BRANCH_MESSAGE.format(
            locations=", ".join(offenders)
        )

    def test_running_interpreter_is_reported_for_the_record(self) -> None:
        """Not a gate - a note, so a surprising local pass is explainable."""
        if sys.version_info[:2] != TARGET_PYTHON:
            pytest.skip(
                f"running {sys.version_info[0]}.{sys.version_info[1]}; "
                f"the runtime image is {TARGET_PYTHON[0]}.{TARGET_PYTHON[1]}, "
                "so TestRealTargetInterpreter is the meaningful check here"
            )
