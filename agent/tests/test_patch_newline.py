"""The trailing-newline defect, and the gate that used to hide it.

Added after a P0 found during Milestone 4 pre-flight. `build_diff` returned a
unified diff with no terminating newline. Real ``git apply --check`` rejects such
a diff - "corrupt patch", non-zero exit - so **every** Tier-1 remediation the
agent could emit was unapplyable by a GitOps pipeline.

It shipped because `git_apply_check` appended the missing newline before running
git. The gate verified a *repaired* copy of the artifact while the agent shipped
the broken original, and cheerfully reported "I-B2 satisfied". An existing test
(`TestGitApplyCheck::test_a_good_patch_passes`) already fed raw `build_diff`
output to the checker and passed - because the checker forgave it.

The two tests below are the pair that closes that gap:

* a **negative control** asserting the gate *fails* on an unterminated diff. This
  is the one that would have caught the P0, and its absence is why 410 green
  tests coexisted with a broken generator.
* a **positive** assertion that raw `build_diff` output passes untouched.

A verifier that edits its input is not a verifier, and the negative control is
what distinguishes "the gate is strict" from "the gate is strict about the things
we happened to test".
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Final

import patch as patch_engine
import triage

from test_ib2 import fixture_manifest, requires_git

NEW_LIMIT: Final[str] = "512Mi"


def _generated_diff() -> str:
    manifest = fixture_manifest()
    target = patch_engine.find_container_memory_limit(manifest, "checkout-api")
    assert target is not None
    return patch_engine.build_diff(manifest, target, NEW_LIMIT, triage.TARGET_MANIFEST)


# ---------------------------------------------------------------------------
# 1. The generator
# ---------------------------------------------------------------------------


class TestBuildDiffIsNewlineTerminated:
    def test_generated_diff_ends_with_a_newline(self) -> None:
        """The defect itself, asserted directly.

        Small, obvious, and it was missing for a full milestone. A test this
        simple does not need git, a cluster, or a fixture: if the last character
        of a diff is not "\\n", no conforming ``git apply`` will read it.
        """
        diff = _generated_diff()
        assert diff.endswith("\n"), (
            f"the diff ends with {diff[-1]!r}, not a newline; git apply rejects "
            f"an unterminated diff as corrupt"
        )

    def test_the_diff_terminates_exactly_one_line(self) -> None:
        """Terminated, but not padded.

        The mirror failure: appending a blank line to satisfy the terminator
        would make the hunk body one line longer than the header claims, which
        git also reports as a corrupt patch. Both ends of this are real errors and
        they fail differently, so both are asserted.
        """
        diff = _generated_diff()
        assert not diff.endswith("\n\n"), "the diff is padded with a blank line"
        assert diff.splitlines()[-1] != "", "the final line is empty"

    def test_no_line_carries_a_carriage_return(self) -> None:
        """POSIX newlines, not the host's.

        A CRLF diff puts a ``\\r`` on every context line, which cannot match an
        LF-terminated manifest. The bug this replaces was a diff nobody could
        apply; emitting ``os.linesep`` would have been the same bug wearing a
        different hat.
        """
        diff = _generated_diff()
        assert "\r" not in diff, "the diff contains a carriage return"


# ---------------------------------------------------------------------------
# 2. The gate must not forgive
# ---------------------------------------------------------------------------


class TestGitApplyCheckDoesNotForgiveAnUnterminatedDiff:
    """The negative control for the whole P0."""

    @requires_git
    def test_an_unterminated_diff_is_rejected(self) -> None:
        """The gate must FAIL on a diff missing its final newline.

        This is the assertion whose absence let the defect ship. Before the fix
        this returned ``passed=True`` for the malformed diff, because the checker
        appended the newline itself.
        """
        diff = _generated_diff()
        unterminated = diff[:-1]  # strip exactly the terminator
        assert not unterminated.endswith("\n")

        ok, reason = patch_engine.git_apply_check(
            fixture_manifest(), unterminated, triage.TARGET_MANIFEST
        )
        assert not ok, (
            "git_apply_check passed a diff with no trailing newline. The gate is "
            "repairing its input, so it cannot fail on the defect it exists to "
            f"catch. reason={reason!r}"
        )

    @requires_git
    def test_real_git_rejects_what_the_gate_now_rejects(self) -> None:
        """Confirm the gate's verdict matches git's, on the same bytes.

        Without this, "the gate fails" and "git fails" are two separate claims
        and a regression in either would not be caught by the other.
        """
        diff = _generated_diff()
        unterminated = diff[:-1]

        with tempfile.TemporaryDirectory(prefix="srek3s-newline-") as tmp:
            root = Path(tmp)
            target = root / triage.TARGET_MANIFEST
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(fixture_manifest(), encoding="utf-8", newline="")
            patch_file = root / "candidate.patch"
            patch_file.write_text(unterminated, encoding="utf-8", newline="")

            for args in (
                ["git", "init", "-q"],
                ["git", "config", "user.email", "t@srek3s.local"],
                ["git", "config", "user.name", "srek3s"],
                ["git", "add", "-A"],
                ["git", "commit", "-q", "-m", "baseline"],
            ):
                subprocess.run(args, cwd=root, check=True, capture_output=True)

            git = shutil.which("git")
            assert git is not None
            completed = subprocess.run(
                [git, "apply", "--check", "--whitespace=nowarn", str(patch_file)],
                cwd=root,
                capture_output=True,
                text=True,
                check=False,
            )
            assert completed.returncode != 0, (
                "real git accepted an unterminated diff; if git has changed its "
                "tolerance the premise of this module needs revisiting"
            )


# ---------------------------------------------------------------------------
# 3. Raw generator output must pass
# ---------------------------------------------------------------------------


class TestRawGeneratorOutputPasses:
    @requires_git
    def test_gate_accepts_raw_build_diff_output(self) -> None:
        """The positive case, and the one that was passing for the wrong reason.

        ``test_a_good_patch_passes`` in test_ib2.py already asserted this shape
        and was green throughout the defect. The difference now is that the
        generator is correct, so the pass reflects the artifact rather than the
        checker's leniency.
        """
        diff = _generated_diff()
        ok, reason = patch_engine.git_apply_check(
            fixture_manifest(),
            diff,
            (
                triage.TARGET_MANEFEST
                if hasattr(triage, "TARGET_MANEFEST")
                else triage.TARGET_MANIFEST
            ),
        )
        assert ok, f"git_apply_check rejected a well-formed generated diff: {reason}"

    @requires_git
    def test_real_git_accepts_raw_build_diff_output(self) -> None:
        """End to end: generate, write the exact bytes, let real git decide.

        The test that was missing entirely. Every previous check of this shape
        either used a hand-written diff or went through the checker, so nothing
        ever asked git about a diff the generator had actually produced.
        """
        diff = _generated_diff()

        with tempfile.TemporaryDirectory(prefix="srek3s-e2e-patch-") as tmp:
            root = Path(tmp)
            target = root / triage.TARGET_MANIFEST
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(fixture_manifest(), encoding="utf-8", newline="")
            patch_file = root / "generated.patch"
            patch_file.write_text(diff, encoding="utf-8", newline="")

            for args in (
                ["git", "init", "-q"],
                ["git", "config", "user.email", "t@srek3s.local"],
                ["git", "config", "user.name", "srek3s"],
                ["git", "add", "-A"],
                ["git", "commit", "-q", "-m", "baseline"],
            ):
                subprocess.run(args, cwd=root, check=True, capture_output=True)

            git = shutil.which("git")
            assert git is not None
            completed = subprocess.run(
                [git, "apply", "--check", "--whitespace=nowarn", str(patch_file)],
                cwd=root,
                capture_output=True,
                text=True,
                check=False,
            )
            assert completed.returncode == 0, (
                "real git rejected a diff produced by build_diff:\n"
                f"{completed.stderr.strip()}"
            )

    def test_generated_diff_round_trips_through_our_own_applier(self) -> None:
        """The structural layer, on the same bytes the gate sees.

        Cheap, needs no git, and catches a generator change that produces a diff
        neither git nor our applier can consume.
        """
        manifest = fixture_manifest()
        diff = _generated_diff()
        patched = patch_engine.apply_unified_diff(manifest, diff)
        assert patched is not None, "our own applier cannot apply our own diff"
        assert NEW_LIMIT in patched
        assert 'memory: "256Mi"' in manifest, "the fixture's original limit is gone"


# ---------------------------------------------------------------------------
# 4. The gate must still be able to fail for the right reason
# ---------------------------------------------------------------------------


class TestGateStillRejectsGenuinelyBadPatches:
    """Guards against fixing P0 by making the gate permissive.

    The obvious wrong repair for "the gate forgave a bad diff" is to stop
    checking. These assert the gate still rejects real defects, so a future
    change cannot buy the P0 fix by weakening I-B2.
    """

    @requires_git
    def test_a_drifted_manifest_is_still_rejected(self) -> None:
        diff = _generated_diff()
        drifted = fixture_manifest().replace('memory: "256Mi"', 'memory: "999Mi"', 1)
        ok, _ = patch_engine.git_apply_check(drifted, diff, triage.TARGET_MANIFEST)
        assert not ok, (
            "the gate accepted a patch against a manifest it was not built from; "
            "I-B2 verifies against the real file, not a similar one"
        )

    @requires_git
    def test_inconsistent_hunk_counts_are_still_rejected(self) -> None:
        """Corrupt the declared line *counts*, not the start line.

        The first version of this control shifted the hunk's start line
        (`@@ -11,...` to `@@ -911,...`) and the gate correctly passed it. That
        was my control being wrong rather than the gate being lenient: `git apply`
        searches outward for the context and applies a pure offset, so a shifted
        start is well-formed input, not a defect.

        Inconsistent counts are different in kind. The header then claims a body
        length the hunk does not have, which git reports as a corrupt patch with
        no offset search that can rescue it. That is the case worth pinning, and
        test_ib2.py covers the same ground; the duplication is deliberate here
        because it sits next to the negative control and the two together are
        what make "the gate still fails" a claim rather than an assumption.
        """
        diff = _generated_diff()
        import re

        match = re.search(r"@@ -(\d+),(\d+) \+(\d+),(\d+) @@", diff)
        assert match is not None, f"no hunk header in {diff!r}"
        old_count = int(match.group(2))
        corrupted = (
            diff[: match.start()]
            + match.group(0).replace(f",{old_count} ", f",{old_count - 1} ", 1)
            + diff[match.end() :]
        )
        assert corrupted != diff, "the corruption did not change the header"

        ok, _ = patch_engine.git_apply_check(
            fixture_manifest(), corrupted, triage.TARGET_MANIFEST
        )
        assert not ok, "the gate accepted a diff whose hunk counts are inconsistent"

    def test_the_gate_does_not_mutate_its_argument(self) -> None:
        """The structural form of the P0, with no git required.

        If the gate ever writes back to the caller's string, the second call with
        the same object would see different bytes. ``str`` is immutable so this
        cannot happen today - which is exactly why it is worth pinning, because
        the P0 was a mutation of the *file* rather than the string, and the same
        mistake in a mutable buffer would be invisible to this test.
        """
        diff = _generated_diff()
        before = diff
        patch_engine.git_apply_check(fixture_manifest(), diff, triage.TARGET_MANIFEST)
        assert diff == before, "git_apply_check mutated its argument"
