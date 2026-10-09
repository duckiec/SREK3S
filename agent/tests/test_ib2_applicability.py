"""I-B2 applicability: the diff must apply to the file the agent observed.

The property under test is not "the diff applies to the string it was derived
from". That is self-consistency, and it is strictly weaker: nothing ties the
string to a real file, so a provider that returns a truncated read yields a diff
with a shrunken trailing context which applies perfectly to the truncated bytes
and not at all to the manifest it names.

The agent reads its manifests from a just-in-time clone (``agent/gitops.py``),
so the file on disk is the state a GitOps pipeline will apply. That is what
``patch_validated: true`` has to mean.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any, Final

import pytest

import classifier
import patch as patch_engine
import triage
from models import BlastRadiusTier, IncidentPayload

_REPO_ROOT: Final[Path] = Path(__file__).resolve().parents[2]
FIXTURE: Final[Path] = _REPO_ROOT / "tests" / "fixtures" / "oom-restartloop.yaml"

GIT_AVAILABLE: Final[bool] = shutil.which("git") is not None
requires_git = pytest.mark.skipif(
    not GIT_AVAILABLE, reason="git is not on PATH; the agent image installs it"
)


def checkout_with(manifest: str, path: str = triage.TARGET_MANIFEST) -> Path:
    """A GitOps-shaped root holding one manifest, as the JIT clone would."""
    root = Path(pytest.importorskip("tempfile").mkdtemp(prefix="srek3s-ib2-"))
    target = root / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(manifest, encoding="utf-8", newline="")
    return root


def incident() -> IncidentPayload:
    document = json.loads(
        (_REPO_ROOT / "tests" / "fixtures" / "sample-incident.json").read_text(
            encoding="utf-8"
        )
    )
    return IncidentPayload.model_validate(
        {k: v for k, v in document.items() if k != "_comment"}
    )


def triage_against(manifest: str, provider: Any) -> Any:
    return triage.triage_payload(incident(), manifest_provider=provider)


@requires_git
class TestAgainstTheObservedCheckout:
    def test_a_patch_that_does_not_apply_to_the_real_file_is_refused(self) -> None:
        """The defect: a perfect diff, validated against a truncated read.

        The diff below is well-formed, its hunk header matches the truncated
        bytes, and it applies to them exactly. It does not apply to the manifest
        it names, because the manifest has four more lines after the hunk. Under
        the old check this reported ``patch_validated: true``.
        """
        real = FIXTURE.read_text(encoding="utf-8")
        marker = 'memory: "256Mi"'
        cut = real.index(marker) + len(marker) + 1
        truncated = real[:cut]
        root = checkout_with(real)

        # A provider that hands back a truncated read, as a short read would.
        class TruncatingProvider(classifier.FileManifestProvider):
            def read_manifest(self, path: str) -> str | None:
                return truncated

        provider = TruncatingProvider(root)
        outcome = triage_against(real, provider)

        assert outcome.tier is BlastRadiusTier.TIER_2_ARCHITECTURAL
        assert outcome.response.remediation.git_patch == ""
        assert outcome.response.remediation.patch_validated is False
        assert outcome.response.remediation.target_manifest == triage.TARGET_MANIFEST
        assert any("no longer matches" in r for r in outcome.reasons), outcome.reasons

    def test_an_intact_checkout_still_produces_a_tier_one_patch(self) -> None:
        """The control. Without it the test above proves only that Tier-1 is dead."""
        real = FIXTURE.read_text(encoding="utf-8")
        root = checkout_with(real)
        provider = classifier.FileManifestProvider(root)

        outcome = triage_against(real, provider)

        assert outcome.tier is BlastRadiusTier.TIER_1_TOIL
        assert outcome.response.remediation.patch_validated is True
        diff = outcome.response.remediation.git_patch
        ok, reason = patch_engine.git_apply_check(
            real, diff, triage.TARGET_MANIFEST, checkout_root=str(root)
        )
        assert ok, reason

    def test_a_diff_built_for_another_manifest_cannot_pass(self) -> None:
        """The hallucination shape: valid YAML diff, wrong context lines.

        The diff changes a memory limit, parses as YAML, and would apply to a
        manifest that looks similar. It does not apply to the one on disk, and a
        GitOps pipeline would reject it - so the agent must, rather than hand a
        human a patch that cannot merge.
        """
        real = FIXTURE.read_text(encoding="utf-8")
        root = checkout_with(real)

        target = patch_engine.find_container_memory_limit(real, "checkout-api")
        assert target is not None
        # Derived from a manifest whose *context lines* differ, which is not an offset
        # git can forgive: a patch built against it carries context that does not
        # exist in the checkout. This is the shape a model produces when it
        # reasons over a plausible manifest instead of the one it was given.
        elsewhere = real.replace('cpu: "500m"', 'cpu: "250m"', 1)
        assert elsewhere != real, "fixture no longer has the cpu context line"
        elsewhere_target = patch_engine.find_container_memory_limit(
            elsewhere, "checkout-api"
        )
        assert elsewhere_target is not None
        hallucinated = patch_engine.build_diff(
            elsewhere, elsewhere_target, "512Mi", triage.TARGET_MANIFEST
        )

        ok, reason = patch_engine.git_apply_check(
            real,
            hallucinated,
            triage.TARGET_MANIFEST,
            checkout_root=str(root),
        )
        assert not ok, "a diff for a different file must not pass the checkout check"

    def test_an_unreadable_target_fails_closed_rather_than_raising(self) -> None:
        real = FIXTURE.read_text(encoding="utf-8")
        root = checkout_with(real)
        ok, reason = patch_engine.git_apply_check(
            real,
            "--- a/nope.yaml\n+++ b/nope.yaml\n@@ -1 +1 @@\n-a\n+b\n",
            "does/not/exist.yaml",
            checkout_root=str(root),
        )
        assert not ok
        assert "cannot supply" in reason

    def test_a_root_that_is_not_a_directory_fails_closed(self) -> None:
        real = FIXTURE.read_text(encoding="utf-8")
        ok, reason = patch_engine.git_apply_check(
            real, "--- a/x\n+++ b/x\n", "x.yaml", checkout_root="/nonexistent/root"
        )
        assert not ok
        assert "cannot supply" in reason


class TestCheckoutRootOf:
    def test_a_filesystem_provider_reports_its_root(self) -> None:
        root = checkout_with(FIXTURE.read_text(encoding="utf-8"))
        assert classifier.checkout_root_of(
            classifier.FileManifestProvider(root)
        ) == str(root)

    def test_a_static_provider_reports_none(self) -> None:
        provider = classifier.StaticManifestProvider({"a.yaml": "kind: ConfigMap\n"})
        assert classifier.checkout_root_of(provider) is None

    def test_no_provider_reports_none(self) -> None:
        assert classifier.checkout_root_of(None) is None


@requires_git
def test_the_check_runs_real_git_against_the_checkout() -> None:
    """Not a mock, and not the provider's copy.

    Staging the checkout's own bytes and asking real git is the only way to learn
    whether the attestation is load-bearing; a stubbed check would pass regardless.
    """
    real = FIXTURE.read_text(encoding="utf-8")
    root = checkout_with(real)
    subprocess.run(["git", "init", "-q"], cwd=root, capture_output=True, check=False)
    target = patch_engine.find_container_memory_limit(real, "checkout-api")
    assert target is not None
    diff = patch_engine.build_diff(real, target, "512Mi", triage.TARGET_MANIFEST)

    ok, _ = patch_engine.git_apply_check(
        real, diff, triage.TARGET_MANIFEST, checkout_root=str(root)
    )
    assert ok

    # Corrupt the checkout after the diff was built: the check must now refuse,
    # because the file it names no longer matches what the agent read.
    (root / triage.TARGET_MANIFEST).write_text(real + "\n# drifted\n", encoding="utf-8")
    ok, reason = patch_engine.git_apply_check(
        real, diff, triage.TARGET_MANIFEST, checkout_root=str(root)
    )
    assert not ok
    assert "no longer matches" in reason
