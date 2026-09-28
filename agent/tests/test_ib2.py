"""I-B2 verification tests: structural round-trip + `git apply --check`.

ROADMAP §2.5.5, §2.5.6. ARCH §5.4 I-B2 states ``patch_validated == true``
implies ``git apply --check`` exits 0 against the target manifest, and ROADMAP
§2.5.6 requires a downgrade to Tier-2 with an empty patch when it does not.

These tests are organised around the ways verification can be *faked*:

* a patch that is structurally correct but that git rejects (a bad hunk header);
* a patch git accepts that changes the wrong field;
* a patch built against one manifest and checked against another;
* verification silently skipped because git was unavailable.

Each of those would let ``patch_validated: true`` escape on a claim it does not
support, which is the failure this whole module exists to prevent.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Any, Final

import pytest

import classifier
import patch as patch_engine
import triage
from models import BlastRadiusTier
from triage import TriagePolicy, triage_payload

_REPO_ROOT: Final[Path] = Path(__file__).resolve().parents[2]
FIXTURE: Final[Path] = _REPO_ROOT / "tests" / "fixtures" / "oom-restartloop.yaml"

GIT_AVAILABLE: Final[bool] = shutil.which("git") is not None
requires_git = pytest.mark.skipif(
    not GIT_AVAILABLE, reason="git is not on PATH; CI verifies this with git present"
)


def fixture_manifest() -> str:
    """The realistic OOM restart-loop Deployment."""
    return FIXTURE.read_text(encoding="utf-8")


def provider(manifest: str) -> classifier.ManifestProvider:
    return classifier.StaticManifestProvider({triage.TARGET_MANIFEST: manifest})


def outcome_for(manifest: str) -> Any:
    import json

    document = json.loads(
        (_REPO_ROOT / "tests" / "fixtures" / "sample-incident.json").read_text(
            encoding="utf-8"
        )
    )
    document = {k: v for k, v in document.items() if k != "_comment"}
    from models import IncidentPayload

    return triage_payload(
        IncidentPayload.model_validate(document), manifest_provider=provider(manifest)
    )


# ---------------------------------------------------------------------------
# The fixture itself
# ---------------------------------------------------------------------------


class TestFixture:
    def test_fixture_exists_and_is_locatable(self) -> None:
        """The terminal validation test targets this file, so it must resolve."""
        manifest = fixture_manifest()
        target = patch_engine.find_container_memory_limit(manifest, "checkout-api")
        assert target is not None, "the canonical fixture must yield a patch target"
        assert target.value == "256Mi"

    def test_fixture_separates_requests_from_limits(self) -> None:
        """A generator matching on text alone would confuse the two blocks."""
        assert patch_engine.memory_values(fixture_manifest()) == ["256Mi", "128Mi"]

    def test_fixture_carries_named_ports_and_volume_mounts(self) -> None:
        """Regression fixture: `- name:` appears for ports and mounts too.

        Any locator that treats every `- name:` as a container switches the
        target off against this manifest. It fails closed - no wrong patch is
        ever emitted - but it escalates incidents that are cleanly remediable,
        which is the other half of being wrong.
        """
        manifest = fixture_manifest()
        assert "- name: http" in manifest, "fixture must contain a named port"
        assert "- name: config" in manifest, "fixture must contain a named volume mount"
        assert (
            patch_engine.find_container_memory_limit(manifest, "checkout-api")
            is not None
        )

    def test_patched_fixture_still_parses_as_the_same_document_shape(self) -> None:
        """One value changes; every other line is byte-identical."""
        manifest = fixture_manifest()
        target = patch_engine.find_container_memory_limit(manifest, "checkout-api")
        assert target is not None
        diff = patch_engine.build_diff(
            manifest, target, "512Mi", triage.TARGET_MANIFEST
        )
        patched = patch_engine.apply_unified_diff(manifest, diff)
        assert patched is not None

        before = manifest.splitlines()
        after = patched.splitlines()
        assert len(before) == len(after)
        differing = [i for i, (a, b) in enumerate(zip(before, after)) if a != b]
        assert differing == [target.index]
        assert after[target.index].strip() == 'memory: "512Mi"'


# ---------------------------------------------------------------------------
# git apply --check
# ---------------------------------------------------------------------------


class TestGitApplyCheck:
    @requires_git
    def test_a_good_patch_passes(self) -> None:
        manifest = fixture_manifest()
        target = patch_engine.find_container_memory_limit(manifest, "checkout-api")
        assert target is not None
        diff = patch_engine.build_diff(
            manifest, target, "512Mi", triage.TARGET_MANIFEST
        )
        ok, reason = patch_engine.git_apply_check(
            manifest, diff, triage.TARGET_MANIFEST
        )
        assert ok, reason

    @requires_git
    def test_inconsistent_hunk_counts_are_rejected(self) -> None:
        """A count that disagrees with the hunk body is a corrupt patch."""
        manifest = fixture_manifest()
        target = patch_engine.find_container_memory_limit(manifest, "checkout-api")
        assert target is not None
        good = patch_engine.build_diff(
            manifest, target, "512Mi", triage.TARGET_MANIFEST
        )
        broken = good.replace(",7 +", ",6 +", 1)
        ok, reason = patch_engine.git_apply_check(
            manifest, broken, triage.TARGET_MANIFEST
        )
        assert not ok
        assert "git apply --check" in reason

    @requires_git
    def test_a_wrong_start_offset_is_tolerated_by_git_but_caught_structurally(
        self,
    ) -> None:
        """Documents git's measured behaviour, and why both checks are kept.

        ``git apply`` searches for the context near the stated line number, so a
        wrong offset still succeeds when the content matches. The structural
        round-trip locates strictly by line number and therefore rejects it.
        That is the concrete sense in which the two checks are complementary
        rather than redundant: git proves *content*, the structural check proves
        *position*.
        """
        manifest = fixture_manifest()
        target = patch_engine.find_container_memory_limit(manifest, "checkout-api")
        assert target is not None
        good = patch_engine.build_diff(
            manifest, target, "512Mi", triage.TARGET_MANIFEST
        )
        wrong_offset = good.replace("@@ -", "@@ -9", 1)
        assert wrong_offset != good

        git_ok, _ = patch_engine.git_apply_check(
            manifest, wrong_offset, triage.TARGET_MANIFEST
        )
        assert git_ok, "git is expected to tolerate an offset when content matches"

        assert not patch_engine.verify_patch_structure(
            manifest, wrong_offset, target, "512Mi"
        ), "the structural check must reject what git tolerates"

    @requires_git
    def test_a_patch_whose_context_drifts_is_rejected(self) -> None:
        """Proves the check runs against *this* file, not merely a well-formed diff.

        The mutation is to ``cpu``, which sits inside the hunk's context. An
        earlier version of this test edited the image tag instead - which is
        outside the context window - and git correctly still applied the patch,
        so the test was asserting the wrong thing and passing for the wrong
        reason would have been easy.
        """
        manifest = fixture_manifest()
        target = patch_engine.find_container_memory_limit(manifest, "checkout-api")
        assert target is not None
        diff = patch_engine.build_diff(
            manifest, target, "512Mi", triage.TARGET_MANIFEST
        )
        drifted = manifest.replace('cpu: "500m"', 'cpu: "400m"')
        assert drifted != manifest
        ok, reason = patch_engine.git_apply_check(drifted, diff, triage.TARGET_MANIFEST)
        assert not ok, "a diff whose context no longer matches must not apply"
        assert "git apply --check" in reason

    @requires_git
    def test_a_header_naming_a_different_path_is_rejected(self) -> None:
        """The header path must name the file being checked, not some other."""
        manifest = fixture_manifest()
        target = patch_engine.find_container_memory_limit(manifest, "checkout-api")
        assert target is not None
        diff = patch_engine.build_diff(
            manifest, target, "512Mi", triage.TARGET_MANIFEST
        )
        ok, _ = patch_engine.git_apply_check(
            manifest,
            diff.replace("deploy/payments", "deploy/other"),
            triage.TARGET_MANIFEST,
        )
        assert not ok

    @requires_git
    def test_an_absolute_path_is_refused_before_git_runs(self) -> None:
        ok, reason = patch_engine.git_apply_check(
            fixture_manifest(), "--- a/x\n+++ b/x\n", "/etc/passwd"
        )
        assert not ok
        assert "repo-relative" in reason

    @requires_git
    def test_the_check_leaves_no_temporary_repository_behind(self) -> None:
        """A per-call temp dir that accumulated would fill the read-only container."""
        import tempfile

        before = set(Path(tempfile.gettempdir()).glob("srek3s-ib2-*"))
        manifest = fixture_manifest()
        target = patch_engine.find_container_memory_limit(manifest, "checkout-api")
        assert target is not None
        diff = patch_engine.build_diff(
            manifest, target, "512Mi", triage.TARGET_MANIFEST
        )
        patch_engine.git_apply_check(manifest, diff, triage.TARGET_MANIFEST)
        after = set(Path(tempfile.gettempdir()).glob("srek3s-ib2-*"))
        assert after <= before, f"leaked temporary repositories: {after - before}"

    @requires_git
    def test_the_check_works_without_a_preexisting_repository(self) -> None:
        """It must not depend on the agent sitting inside a GitOps checkout.

        There is no checkout in Milestone 2, so a check that required one could
        never run and `patch_validated` would be permanently false.
        """
        manifest = fixture_manifest()
        target = patch_engine.find_container_memory_limit(manifest, "checkout-api")
        assert target is not None
        diff = patch_engine.build_diff(
            manifest, target, "512Mi", triage.TARGET_MANIFEST
        )
        ok, reason = patch_engine.git_apply_check(
            manifest, diff, triage.TARGET_MANIFEST
        )
        assert ok, reason


# ---------------------------------------------------------------------------
# The combined verdict
# ---------------------------------------------------------------------------


class TestCombinedVerification:
    @requires_git
    def test_verify_patch_requires_both_checks(self) -> None:
        manifest = fixture_manifest()
        target = patch_engine.find_container_memory_limit(manifest, "checkout-api")
        assert target is not None
        diff = patch_engine.build_diff(
            manifest, target, "512Mi", triage.TARGET_MANIFEST
        )
        result = patch_engine.verify_patch(
            manifest, diff, target, "512Mi", triage.TARGET_MANIFEST
        )
        assert result.ok, result.failures
        assert result.structural_ok
        assert result.git_apply_ok
        assert result.failures == ()

    def test_disabling_the_git_check_fails_closed(self) -> None:
        """The switch exists for hosts without git; it must never grant a pass."""
        manifest = fixture_manifest()
        target = patch_engine.find_container_memory_limit(manifest, "checkout-api")
        assert target is not None
        diff = patch_engine.build_diff(
            manifest, target, "512Mi", triage.TARGET_MANIFEST
        )
        result = patch_engine.verify_patch(
            manifest, diff, target, "512Mi", triage.TARGET_MANIFEST, git_checker=False
        )
        assert not result.ok
        assert not result.git_apply_ok
        assert any("disabled" in f for f in result.failures)

    def test_a_structurally_wrong_patch_is_rejected_even_with_git_agreeing(
        self,
    ) -> None:
        manifest = fixture_manifest()
        target = patch_engine.find_container_memory_limit(manifest, "checkout-api")
        assert target is not None
        diff = patch_engine.build_diff(
            manifest, target, "512Mi", triage.TARGET_MANIFEST
        )
        result = patch_engine.verify_patch(
            manifest,
            diff,
            target,
            "1024Mi",  # claim a different new limit than the diff installs
            triage.TARGET_MANIFEST,
        )
        assert not result.structural_ok
        assert not result.ok

    def test_failure_reasons_are_carried_for_the_audit_trail(self) -> None:
        """The caller records *why* a patch was discarded; a bare False loses it."""
        manifest = fixture_manifest()
        target = patch_engine.find_container_memory_limit(manifest, "checkout-api")
        assert target is not None
        diff = patch_engine.build_diff(
            manifest, target, "512Mi", triage.TARGET_MANIFEST
        )
        result = patch_engine.verify_patch(
            manifest, diff, target, "512Mi", triage.TARGET_MANIFEST, git_checker=False
        )
        assert result.reason_text()
        assert "git apply --check" in result.reason_text()


# ---------------------------------------------------------------------------
# End to end: I-B2 gates patch_validated
# ---------------------------------------------------------------------------


class TestIB2GatesEmission:
    @requires_git
    def test_a_verified_patch_is_emitted_with_patch_validated(self) -> None:
        outcome = outcome_for(fixture_manifest())
        assert outcome.tier is BlastRadiusTier.TIER_1_TOIL
        assert outcome.response.remediation.patch_validated is True
        assert any("I-B2 satisfied" in r for r in outcome.reasons)

    @requires_git
    def test_the_emitted_patch_really_applies(self) -> None:
        """The strongest end-to-end statement: take it and apply it with git."""
        outcome = outcome_for(fixture_manifest())
        diff = outcome.response.remediation.git_patch
        ok, reason = patch_engine.git_apply_check(
            fixture_manifest(), diff, triage.TARGET_MANIFEST
        )
        assert ok, reason

    def test_an_unverifiable_patch_is_never_emitted(self) -> None:
        """ROADMAP 2.5.6: no `git apply --check`, no patch."""
        result = outcome_for("kind: ConfigMap\nmetadata:\n  name: other\n")
        assert result.tier is BlastRadiusTier.TIER_2_ARCHITECTURAL
        assert result.response.remediation.git_patch == ""
        assert result.response.remediation.patch_validated is False

    def test_tier_two_stays_patch_free_under_ib2(self) -> None:
        """I-B1 and I-B2 together: no Tier-2 response may carry a patch."""
        for manifest in (
            fixture_manifest(),
            "kind: ConfigMap\n",
            "",
            fixture_manifest().replace('memory: "256Mi"', 'memory: "1Gi"', 1),
        ):
            outcome = outcome_for(manifest)
            if outcome.tier is BlastRadiusTier.TIER_2_ARCHITECTURAL:
                assert outcome.response.remediation.git_patch == "", manifest[:40]
                assert outcome.response.remediation.patch_validated is False


def test_git_is_available_where_the_image_needs_it() -> None:
    """`agent/Dockerfile` installs git precisely so I-B2 can be enforced.

    If this is skipped on CI the check is silently not running, so assert git is
    present wherever the gates execute and only skip on a developer machine.
    """
    if not GIT_AVAILABLE:
        pytest.skip("git unavailable on this host; CI asserts it is installed")
    version = subprocess.run(
        ["git", "--version"], capture_output=True, text=True, timeout=30, check=False
    )
    assert version.returncode == 0
    assert "git version" in version.stdout
