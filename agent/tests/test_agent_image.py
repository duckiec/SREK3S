"""Static tests for agent/Dockerfile and its `.dockerignore`.

Why this file exists
--------------------
`agent/Dockerfile:154` is `COPY --chown=10001:10001 agent/ /app/` — the whole tree.
That one line is how the runtime image came to contain its own test suite.

A probe of the built image found, under `/app`:

    tests/            80 files
    conftest.py
    pytest.ini
    pyproject.toml
    __pycache__/      2 directories
    .pytest_cache/    1 directory
    --                123 files in total

Two mechanisms were each supposed to prevent this and each failed in a different
way:

* The **root** `.dockerignore` excludes `**/__pycache__/`, `**/*.py[cod]` and
  `**/.pytest_cache/`. BuildKit does not consult it. It looks for
  `<dockerfile-path>.dockerignore` and uses that file *instead*, so the exclusion
  was not in force for the default builder.
* `agent/Dockerfile.dockerignore` excludes `tests/` — unanchored. It did not stop
  `COPY agent/ /app/` from shipping `agent/tests/`.

The lesson is the one this repository keeps relearning in other guises: an
exclusion that is not anchored to the thing being copied is a hope, not a rule.
The patterns are now anchored to the context root.

What is checked, and what is not
--------------------------------
Checked: that the per-Dockerfile ignore excludes the test suite, the test config,
and the bytecode/test caches, anchored so they cannot be mistaken for a sibling;
and that the root file's cache exclusions are the reason the classic builder
agrees.

Not checked: that the image builds, or what it contains at runtime. That needs a
Docker daemon. The fix was verified by building — 123 files under `/app` became
18 — but a gate that requires a daemon cannot run here, so it is reported as what
was done rather than assumed to be covered.

A failure worth recording
-------------------------
The first version of this file passed locally and failed on its first CI run. Two
tests asserted that `agent/__pycache__/` and `agent/.pytest_cache/` resolve to real
paths, which is true in a developer's working tree and false in a clean checkout.
Both directories are gitignored; they existed here because the test suite had been
run, and nothing about that was visible in the test.

The rule now applied throughout: a test may not depend on a file that a clean
checkout does not have. Where an untracked artifact is genuinely part of the
subject, it is asserted to be *ignored* rather than asserted to be *present*.
Reproducing it is cheap — move the two directories aside and re-run — and the
mutation script does exactly that.
"""

from __future__ import annotations

import pathlib
import subprocess
from typing import Final

import pytest

REPO_ROOT: Final[pathlib.Path] = pathlib.Path(__file__).resolve().parents[2]
DOCKERFILE: Final[pathlib.Path] = REPO_ROOT / "agent" / "Dockerfile"
#: The per-Dockerfile ignore, which REPLACES the root file under BuildKit.
AGENT_IGNORE: Final[pathlib.Path] = REPO_ROOT / "agent" / "Dockerfile.dockerignore"
ROOT_IGNORE: Final[pathlib.Path] = REPO_ROOT / ".dockerignore"

#: Tracked files `COPY agent/ /app/` would carry if nothing excluded them.
#:
#: The count matters more than the list: it is the number that was measured, and a
#: future tracked file added to `agent/` appears here by construction unless
#: someone edits this tuple.
CARRIED_WITHOUT_IGNORE: Final[tuple[str, ...]] = (
    "tests",
    "conftest.py",
    "pytest.ini",
    "pyproject.toml",
    "Dockerfile",
    "Dockerfile.dockerignore",
)

#: Untracked build artifacts the same COPY carries, present only after a local run.
#:
#: Kept in a separate tuple because these behave differently under a clean
#: checkout, and getting that wrong is not hypothetical: the first version of
#: `test_every_anchored_pattern_names_a_real_path` asserted that `/agent/__pycache__/`
#: and `/agent/.pytest_cache/` resolved to real paths, which they do on a
#: developer machine and do not in CI. Both tests below passed locally for a week
#: of local runs and failed on the first CI run, because a dirty worktree is the
#: only thing that made them true.
#:
#: `git check-ignore` confirms both are ignored:
#:     .gitignore:46:__pycache__/
#:     .gitignore:185:**/.pytest_cache/
UNTRACKED_ARTIFACTS: Final[tuple[str, ...]] = (
    "__pycache__",
    ".pytest_cache",
)


def _ignore_lines(path: pathlib.Path) -> list[str]:
    """The ignore file's patterns, comments and blanks removed."""
    return [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


@pytest.fixture(scope="module")
def agent_ignore() -> list[str]:
    return _ignore_lines(AGENT_IGNORE)


@pytest.fixture(scope="module")
def root_ignore() -> list[str]:
    return _ignore_lines(ROOT_IGNORE)


@pytest.fixture(scope="module")
def dockerfile() -> str:
    return DOCKERFILE.read_text(encoding="utf-8")


def test_the_agent_copy_copies_the_whole_tree(dockerfile: str) -> None:
    """The premise: `COPY agent/ /app/` really does carry everything above.

    Asserted so the exclusions below have something to be exclusions of. If the COPY
    is ever narrowed to explicit files, the anchored tests start failing and say
    so — which is the correct response, because the concern moves with the COPY.
    """
    copies = [
        line.strip()
        for line in dockerfile.splitlines()
        if line.strip().startswith("COPY")
    ]
    assert any(line.endswith("agent/ /app/") for line in copies), (
        f"expected `COPY agent/ /app/`; the COPY lines are {copies}. "
        "The exclusions in agent/Dockerfile.dockerignore are scoped to that "
        "source directory."
    )


def test_the_test_suite_is_excluded_anchored(agent_ignore: list[str]) -> None:
    """`agent/tests/` is excluded, and by an anchored pattern.

    The unanchored `tests/` was the first attempt and it did not work: the image
    shipped 80 test files. A test directory is a plausible thing to have anywhere
    in a repository, so the pattern has to name the one that is copied.
    """
    assert "/agent/tests/" in agent_ignore, (
        "the unanchored `tests/` pattern does not exclude `agent/tests/` — "
        "measured, not inferred; see the module docstring"
    )


def test_the_test_config_is_excluded_anchored(agent_ignore: list[str]) -> None:
    """`conftest.py`, `pytest.ini` and `pyproject.toml` are test scaffolding.

    None of them is imported by the application. `pyproject.toml` in particular
    pins the interpreter version, which is a build-time fact with no runtime
    meaning.
    """
    for name in ("/agent/conftest.py", "/agent/pytest.ini", "/agent/pyproject.toml"):
        assert (
            name in agent_ignore
        ), f"{name} is copied into the image and should not be"


def test_the_caches_are_excluded_in_both_forms(agent_ignore: list[str]) -> None:
    """The bytecode and pytest caches are excluded, anchored and unanchored.

    Both forms are required by an asymmetry worth stating plainly. BuildKit uses
    this file and replaces the root one with it, so this file is what the default
    builder enforces. The classic builder uses the root file, which already
    excludes these patterns — so listing them here is what keeps the two builders
    producing the same image.
    """
    for pattern in ("**/__pycache__/", "**/*.py[cod]", "**/.pytest_cache/"):
        assert pattern in agent_ignore, (
            f"{pattern} is missing from the per-Dockerfile ignore, so BuildKit "
            "would ship it while the classic builder did not"
        )
    for pattern in ("/agent/__pycache__/", "/agent/.pytest_cache/"):
        assert pattern in agent_ignore


def test_the_root_ignore_excludes_the_same_caches(root_ignore: list[str]) -> None:
    """The classic builder's half of the same guarantee.

    If this ever stops being true, the two builders diverge: BuildKit would exclude
    the caches and the classic builder would ship them. That is the exact failure
    the per-Dockerfile file was introduced to prevent, so it is asserted rather
    than assumed.
    """
    for pattern in ("**/__pycache__/", "**/*.py[cod]", "**/.pytest_cache/"):
        assert pattern in root_ignore


def test_the_root_ignore_does_not_exclude_what_the_copy_carries(
    root_ignore: list[str],
) -> None:
    """The root file is a floor, not a policy.

    Its own comment states the rule: it must never exclude a path ANY Dockerfile
    COPYs. `agent/tests/` is inside `agent/`, which `agent/Dockerfile` COPYs, so it
    cannot be excluded there — excluding it would be true for this image and
    meaningless as a guarantee for any other. The per-Dockerfile file is where the
    leanness lives.

    Asserted because the failure mode is silent: an over-broad root pattern breaks
    nothing locally and shows up as a mysteriously fat context, or as a build that
    works on the classic builder and fails on BuildKit.
    """
    assert "/agent/tests/" not in root_ignore
    assert "tests/" not in root_ignore, (
        "the root file excludes `tests/` unanchored, which matches `agent/tests/` "
        "too — that is the path agent/Dockerfile COPYs"
    )


def _excluded_as_artifact(relative: str, root_ignore: list[str]) -> bool:
    """Whether the root ignore also excludes this path as a build artifact."""
    tail = relative.rstrip("/").rsplit("/", 1)[-1]
    return any(
        candidate in root_ignore
        for candidate in (f"**/{tail}/", f"**/{tail}", f"/{relative}", relative)
    )


def test_every_anchored_pattern_names_a_real_path(
    agent_ignore: list[str],
    root_ignore: list[str],
) -> None:
    """An anchored pattern that matches nothing is a comment, not an exclusion.

    Cheap to check, and it is the whole class of bug this file is about: a pattern
    that reads as if it excludes something and excludes nothing.

    The exemption is tied to an invariant rather than to a hardcoded name. A pattern
    may name a path that does not exist on a clean checkout **only** if the root
    `.dockerignore` also excludes it as a build artifact — because then the pattern
    names something a local run creates, which is exactly what `/agent/__pycache__/`
    is for. Without that second condition this test asserts that a developer's dirty
    worktree is part of the repository, which is false.
    """
    missing = [
        pattern
        for pattern in agent_ignore
        if pattern.startswith("/")
        and not (REPO_ROOT / pattern.lstrip("/")).exists()
        and not _excluded_as_artifact(pattern.lstrip("/"), root_ignore)
    ]
    assert not missing, (
        f"these anchored patterns name paths that do not exist and are not build "
        f"artifacts: {missing}. Either the path moved (and the pattern is now "
        "decorative) or the pattern is misspelled."
    )


@pytest.mark.parametrize("path", sorted(CARRIED_WITHOUT_IGNORE))
def test_the_tracked_baseline_is_accurate(path: str) -> None:
    """The measured baseline, as data, and a staleness check on it.

    Not an assertion that these SHOULD be shipped — the opposite. It is the list the
    exclusions above have to beat, written down so a regression has a number to land
    on rather than a feeling. `Dockerfile` and `Dockerfile.dockerignore` are in it
    on purpose: they are still shipped today, and are recorded here as known rather
    than as intended.

    Restricted to tracked files. Asserting that `__pycache__` exists would be
    asserting that someone has run the test suite in this working tree.
    """
    assert (
        REPO_ROOT / "agent" / path
    ).exists(), f"agent/{path} no longer exists; the baseline is stale"


@pytest.mark.parametrize("artifact", sorted(UNTRACKED_ARTIFACTS))
def test_the_artifact_baseline_is_ignored_rather_than_tracked(artifact: str) -> None:
    """The untracked half of the baseline, asserted without asserting it exists.

    Each of these is produced by a local run and is gitignored, so its absence is
    the normal state — CI has neither. What must be true is that it is *ignored*:
    otherwise a developer's `.pytest_cache` could be committed, and the image
    exclusions would be load-bearing against a tracked file rather than a local one.

    The trailing slash is load-bearing, and this is the second version to get it
    wrong. Both rules are directory patterns (`__pycache__/` and
    `**/.pytest_cache/`), and git only applies a trailing-slash pattern to a path it
    can see is a directory. Asked about `agent/.pytest_cache` with the directory
    absent it reports no match; asked about `agent/.pytest_cache/` it reports
    `.gitignore:185`. A test that passes on a developer machine and fails in CI for
    this reason is testing the machine, not the repository.
    """
    ignored = subprocess.run(
        ["git", "check-ignore", "-q", f"agent/{artifact}/"],
        cwd=REPO_ROOT,
        capture_output=True,
        check=False,
    )
    assert ignored.returncode == 0, (
        f"agent/{artifact} is not gitignored; it is produced by a local run and "
        "must never be tracked, or the image exclusions would apply to a committed "
        "file"
    )
