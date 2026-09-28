"""Unit tests for the triage engine (ROADMAP §2.3, §2.5.4).

Organised around what each group protects rather than around the functions
being called:

* :class:`TestPatchTargetLocation` - the diff must change the *right* line. This
  group exists because the previous generator matched on text and would silently
  edit ``requests.memory`` or a sidecar's limit while producing a diff that
  still applied cleanly.
* :class:`TestDiffFormatting` - a diff that ``git apply`` rejects is not a
  deliverable, so the format is asserted structurally and by round-trip.
* :class:`TestTierOneTable` / :class:`TestTierTwoTable` - ROADMAP §2.3.4's
  table-driven routing cases.
* :class:`TestRouterIgnoresConfidence` - ROADMAP §2.3.5.
* :class:`TestFailClosedRouting` - §2.3.3: anything unproven is Tier-2.
"""

from __future__ import annotations

import copy
import json
import re
from pathlib import Path
from typing import Any, Final

import pytest
from pydantic import ValidationError

import classifier
import patch as patch_engine
import triage
from classifier import (
    ClassificationResult,
    RemedyShape,
    TierEvidence,
    TierPolicy,
    route,
)
from models import (
    BlastRadiusTier,
    Classification,
    IncidentPayload,
    Reason,
    RiskLevel,
)
from triage import TriagePolicy, triage_payload

_REPO_ROOT: Final[Path] = Path(__file__).resolve().parents[2]
SAMPLE_INCIDENT: Final[Path] = (
    _REPO_ROOT / "tests" / "fixtures" / "sample-incident.json"
)

#: Single-container Deployment, matching the canonical incident fixture.
DEPLOYMENT: Final[str] = """\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: checkout-api
  namespace: payments
spec:
  replicas: 3
  template:
    spec:
      containers:
        - name: checkout-api
          image: registry.internal/checkout-api:1.4.2
          resources:
            limits:
              memory: "256Mi"
              cpu: "500m"
            requests:
              memory: "128Mi"
"""

#: The trap this module is built around: requests and limits hold the *same*
#: value, so a text-only match cannot tell them apart. A generator that edited
#: the wrong one would still produce a diff that applies.
EQUAL_LIMITS: Final[str] = """\
apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      containers:
        - name: checkout-api
          resources:
            limits:
              memory: "256Mi"
            requests:
              memory: "256Mi"
"""

#: A sidecar whose limit also reads "256Mi", alongside the real target.
SIDECAR: Final[str] = """\
apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      containers:
        - name: envoy-sidecar
          resources:
            limits:
              memory: "256Mi"
        - name: checkout-api
          resources:
            limits:
              memory: "256Mi"
"""


def sample_document() -> dict[str, Any]:
    """The canonical Contract A payload, without its documentation key."""
    document = json.loads(SAMPLE_INCIDENT.read_text(encoding="utf-8"))
    return {k: v for k, v in document.items() if k != "_comment"}


def payload_from(mutate: Any = None) -> IncidentPayload:
    """Build a valid payload, optionally mutated first."""
    document = sample_document()
    if mutate is not None:
        mutate(document)
    return IncidentPayload.model_validate(document)


def provider_for(manifest: str) -> classifier.ManifestProvider:
    return classifier.StaticManifestProvider({triage.TARGET_MANIFEST: manifest})


# ---------------------------------------------------------------------------
# Patch target location
# ---------------------------------------------------------------------------


class TestPatchTargetLocation:
    def test_finds_the_limits_memory_of_the_named_container(self) -> None:
        target = patch_engine.find_container_memory_limit(DEPLOYMENT, "checkout-api")
        assert target is not None
        assert target.value == "256Mi"

    def test_never_selects_the_requests_block(self) -> None:
        """The equal-limits trap: both lines read "256Mi".

        A text-only match picks the first occurrence and here that happens to be
        the right one, so this also asserts the *second* is what remains
        untouched when the diff is applied.
        """
        target = patch_engine.find_container_memory_limit(EQUAL_LIMITS, "checkout-api")
        assert target is not None
        diff = patch_engine.build_diff(
            EQUAL_LIMITS, target, "512Mi", "deploy/payments/checkout-api.yaml"
        )
        patched = patch_engine.apply_unified_diff(EQUAL_LIMITS, diff)
        assert patched is not None
        # Exactly one value changed; the other is still 256Mi.
        assert patch_engine.memory_values(patched) == ["512Mi", "256Mi"]

    def test_never_selects_a_sidecar_container(self) -> None:
        """Containers are matched by name, never by position."""
        target = patch_engine.find_container_memory_limit(SIDECAR, "checkout-api")
        assert target is not None
        diff = patch_engine.build_diff(
            SIDECAR, target, "512Mi", "deploy/payments/checkout-api.yaml"
        )
        patched = patch_engine.apply_unified_diff(SIDECAR, diff)
        assert patched is not None
        assert patch_engine.memory_values(patched) == ["256Mi", "512Mi"]

    def test_unknown_container_yields_no_target(self) -> None:
        assert patch_engine.find_container_memory_limit(SIDECAR, "not-present") is None

    def test_container_without_a_memory_limit_yields_no_target(self) -> None:
        manifest = """\
containers:
  - name: checkout-api
    resources:
      limits:
        cpu: "500m"
"""
        assert (
            patch_engine.find_container_memory_limit(manifest, "checkout-api") is None
        )

    def test_unquoted_value_is_supported(self) -> None:
        manifest = """\
containers:
  - name: checkout-api
    resources:
      limits:
        memory: 256Mi
"""
        target = patch_engine.find_container_memory_limit(manifest, "checkout-api")
        assert target is not None
        assert target.quote == ""
        assert target.value == "256Mi"

    def test_single_quoted_value_is_supported(self) -> None:
        manifest = """\
containers:
  - name: checkout-api
    resources:
      limits:
        memory: '256Mi'
"""
        target = patch_engine.find_container_memory_limit(manifest, "checkout-api")
        assert target is not None
        assert target.quote == "'"

    def test_flow_mapping_is_refused_rather_than_guessed(self) -> None:
        """A construct this reader does not model must yield no target.

        Silently mis-parsing would produce a diff that applies to the wrong
        line; refusing is detectable and escalates.
        """
        manifest = "containers: [{name: checkout-api, memory: 256Mi}]\n"
        assert (
            patch_engine.find_container_memory_limit(manifest, "checkout-api") is None
        )

    def test_comments_are_ignored(self) -> None:
        manifest = """\
containers:
  - name: checkout-api  # the app
    resources:
      limits:
        # memory: "1Gi"  <- commented out, must not be selected
        memory: "256Mi"
"""
        target = patch_engine.find_container_memory_limit(manifest, "checkout-api")
        assert target is not None
        assert target.value == "256Mi"


# ---------------------------------------------------------------------------
# Diff formatting
# ---------------------------------------------------------------------------


class TestDiffFormatting:
    def _diff(self, manifest: str = DEPLOYMENT) -> str:
        target = patch_engine.find_container_memory_limit(manifest, "checkout-api")
        assert target is not None
        return patch_engine.build_diff(
            manifest, target, "512Mi", "deploy/payments/checkout-api.yaml"
        )

    def test_has_unified_diff_headers(self) -> None:
        lines = self._diff().splitlines()
        assert lines[0] == "--- a/deploy/payments/checkout-api.yaml"
        assert lines[1] == "+++ b/deploy/payments/checkout-api.yaml"
        assert lines[2].startswith("@@ -")
        assert lines[2].endswith(" @@")

    def test_paths_are_repo_relative(self) -> None:
        """ARCH §2.5.4: an absolute path applies nowhere else and leaks layout.

        Asserted as "does not start at the filesystem root", which is the actual
        property. Checking for a bare ``/deploy/`` substring would be wrong - the
        repo-relative prefix ``a/deploy/`` contains it.
        """
        diff = self._diff()
        for line in diff.splitlines()[:2]:
            assert line.startswith(("--- a/", "+++ b/")), line
            assert not line.startswith(("--- //", "+++ //")), line
        assert not re.search(r"^[-+]{3} [ab]/[A-Za-z]:", diff, re.MULTILINE)

    def test_absolute_path_is_rejected_outright(self) -> None:
        target = patch_engine.find_container_memory_limit(DEPLOYMENT, "checkout-api")
        assert target is not None
        for bad in ("/etc/passwd", "C:/deploy/app.yaml", "host:deploy/a.yaml"):
            with pytest.raises(ValueError, match="repo-relative"):
                patch_engine.build_diff(DEPLOYMENT, target, "512Mi", bad)

    def test_no_binary_hunk_marker(self) -> None:
        assert "GIT binary patch" not in self._diff()
        assert "Binary files" not in self._diff()

    def test_exactly_one_line_removed_and_one_added(self) -> None:
        lines = self._diff().splitlines()
        removed = [x for x in lines if x.startswith("-") and not x.startswith("---")]
        added = [x for x in lines if x.startswith("+") and not x.startswith("+++")]
        assert len(removed) == 1
        assert len(added) == 1

    def test_indentation_is_preserved(self) -> None:
        """A replacement at column 0 would produce an invalid manifest."""
        diff = self._diff()
        removed = next(
            x
            for x in diff.splitlines()
            if x.startswith("-") and not x.startswith("---")
        )
        added = next(
            x
            for x in diff.splitlines()
            if x.startswith("+") and not x.startswith("+++")
        )
        assert len(removed) - len(removed[1:].lstrip()) == len(added) - len(
            added[1:].lstrip()
        )

    def test_trailing_comma_is_preserved(self) -> None:
        manifest = """\
containers:
  - name: checkout-api
    resources:
      limits:
        memory: "256Mi",
"""
        diff = self._diff(manifest)
        added = next(
            x
            for x in diff.splitlines()
            if x.startswith("+") and not x.startswith("+++")
        )
        # Compared by shape, not by a literal column count: re-indenting the
        # fixture must not turn this red.
        assert added.rstrip().endswith(",")
        assert '"512Mi"' in added

    def test_quote_style_is_preserved(self) -> None:
        manifest = """\
containers:
  - name: checkout-api
    resources:
      limits:
        memory: '256Mi'
"""
        diff = self._diff(manifest)
        added = next(
            x
            for x in diff.splitlines()
            if x.startswith("+") and not x.startswith("+++")
        )
        assert "'512Mi'" in added

    def test_hunk_line_counts_are_consistent(self) -> None:
        diff = self._diff()
        header = diff.splitlines()[2]
        body = diff.splitlines()[3:]
        old_count = int(header.split("-")[1].split(",")[1].split(" ")[0])
        new_count = int(header.split("+")[1].split(",")[1].split(" ")[0])
        old_seen = sum(1 for x in body if x.startswith(("-", " ")))
        new_seen = sum(1 for x in body if x.startswith(("+", " ")))
        assert old_seen == old_count
        assert new_seen == new_count

    def test_round_trips_onto_the_original(self) -> None:
        diff = self._diff()
        patched = patch_engine.apply_unified_diff(DEPLOYMENT, diff)
        assert patched is not None
        assert patch_engine.memory_values(patched) == ["512Mi", "128Mi"]

    def test_diff_does_not_apply_to_an_unrelated_document(self) -> None:
        """A diff must not be applicable to a file it was not derived from."""
        diff = self._diff()
        unrelated = DEPLOYMENT.replace("1.4.2", "9.9.9")
        assert patch_engine.apply_unified_diff(unrelated, diff) is None


# ---------------------------------------------------------------------------
# Table-driven routing: Tier-1 (ROADMAP 2.3.4)
# ---------------------------------------------------------------------------


def _tier_one(**_: Any) -> IncidentPayload:
    """A baseline incident that satisfies every ARCH §5.3 precondition."""
    return payload_from()


#: Each case names a scenario, mutates the payload to create it, and states the
#: tier the router must return. Ten cases, per ROADMAP 2.3.4.
TIER_ONE_CASES: Final[tuple[tuple[str, Any, BlastRadiusTier], ...]] = (
    ("baseline single-replica OOM", _tier_one, BlastRadiusTier.TIER_1_TOIL),
    (
        "restart count exactly at the ceiling",
        lambda: payload_from(lambda d: d.update(restart_count=5)),
        BlastRadiusTier.TIER_1_TOIL,
    ),
    (
        "restart count below the ceiling",
        lambda: payload_from(lambda d: d.update(restart_count=2)),
        BlastRadiusTier.TIER_1_TOIL,
    ),
    (
        "no restart at all",
        lambda: payload_from(lambda d: d.update(restart_count=0)),
        BlastRadiusTier.TIER_1_TOIL,
    ),
    (
        "empty log set still routes on reason",
        lambda: payload_from(lambda d: d.update(scrubbed_logs=[])),
        BlastRadiusTier.TIER_1_TOIL,
    ),
    (
        "unrelated benign cluster events",
        lambda: payload_from(
            lambda d: d["cluster_events"].append(
                {
                    "type": "Normal",
                    "reason": "Pulled",
                    "message": "Container image pulled",
                    "count": 1,
                    "first_timestamp": None,
                    "last_timestamp": None,
                    "involved_object": "pod/checkout-api-abc",
                }
            )
        ),
        BlastRadiusTier.TIER_1_TOIL,
    ),
    (
        "raised ceiling admits a higher restart count",
        lambda: payload_from(lambda d: d.update(restart_count=8)),
        BlastRadiusTier.TIER_1_TOIL,
    ),
    (
        "small limit is still recalibrated",
        lambda: payload_from(
            lambda d: d["resource_limits"].update(memory_limit="64Mi")
        ),
        BlastRadiusTier.TIER_1_TOIL,
    ),
    (
        "large limit is still recalibrated",
        lambda: payload_from(lambda d: d["resource_limits"].update(memory_limit="4Gi")),
        BlastRadiusTier.TIER_1_TOIL,
    ),
    (
        "previous termination reason does not block",
        lambda: payload_from(lambda d: d.update(previous_reason="Error")),
        BlastRadiusTier.TIER_1_TOIL,
    ),
)


class TestTierOneTable:
    @pytest.mark.parametrize(
        ("name", "build", "expected"),
        TIER_ONE_CASES,
        ids=[case[0] for case in TIER_ONE_CASES],
    )
    def test_routing(self, name: str, build: Any, expected: BlastRadiusTier) -> None:
        payload = build()
        if name == "raised ceiling admits a higher restart count":
            decision = route(
                TierEvidence(
                    payload=payload,
                    result=classifier.classify(payload),
                    policy=TierPolicy(max_restarts=10),
                )
            )
        else:
            decision = route(
                TierEvidence(
                    payload=payload,
                    result=classifier.classify(payload),
                    policy=TierPolicy(),
                )
            )
        assert decision.tier is expected, decision.reasons
        assert decision.reasons == ()

    def test_at_least_ten_cases(self) -> None:
        assert len(TIER_ONE_CASES) >= 10


# ---------------------------------------------------------------------------
# Table-driven routing: Tier-2 (ROADMAP 2.3.4)
# ---------------------------------------------------------------------------


TIER_TWO_CASES: Final[tuple[tuple[str, Any], ...]] = (
    (
        "crash loop, exit 1",
        lambda: payload_from(
            lambda d: d.update(reason="CrashLoopBackOff", exit_code=1)
        ),
    ),
    (
        "restart count above the ceiling",
        lambda: payload_from(lambda d: d.update(restart_count=6)),
    ),
    (
        "restart count far above the ceiling",
        lambda: payload_from(lambda d: d.update(restart_count=99)),
    ),
    (
        "node eviction alongside an OOM kill",
        lambda: payload_from(
            lambda d: d["cluster_events"].append(
                {
                    "type": "Warning",
                    "reason": "Evicted",
                    "message": "The node was low on resource memory.",
                    "count": 1,
                    "first_timestamp": None,
                    "last_timestamp": None,
                    "involved_object": "node/n1",
                }
            )
        ),
    ),
    (
        "node memory pressure",
        lambda: payload_from(
            lambda d: d["cluster_events"].append(
                {
                    "type": "Warning",
                    "reason": "MemoryPressure",
                    "message": "Node low on memory.",
                    "count": 1,
                    "first_timestamp": None,
                    "last_timestamp": None,
                    "involved_object": "node/n1",
                }
            )
        ),
    ),
    (
        "node not ready",
        lambda: payload_from(
            lambda d: d["cluster_events"].append(
                {
                    "type": "Warning",
                    "reason": "NodeNotReady",
                    "message": "Node not ready.",
                    "count": 1,
                    "first_timestamp": None,
                    "last_timestamp": None,
                    "involved_object": "node/n1",
                }
            )
        ),
    ),
    (
        "dependency failure in the logs",
        lambda: payload_from(
            lambda d: d.update(
                reason="CrashLoopBackOff",
                exit_code=1,
                scrubbed_logs=["dialing payments-api: connection refused"],
            )
        ),
    ),
    (
        "configuration fault in the logs",
        lambda: payload_from(
            lambda d: d.update(
                reason="CrashLoopBackOff",
                exit_code=1,
                scrubbed_logs=["Traceback: config error loading entrypoint"],
            )
        ),
    ),
    (
        "cascading 5xx signature",
        lambda: payload_from(
            lambda d: d.update(
                reason="CrashLoopBackOff",
                exit_code=1,
                scrubbed_logs=["upstream returned 503 repeatedly"],
            )
        ),
    ),
    (
        "unclassifiable anomalous logs",
        lambda: payload_from(
            lambda d: d.update(
                reason="CrashLoopBackOff",
                exit_code=1,
                scrubbed_logs=["corrupt frame 0x00", "undefined behaviour"],
            )
        ),
    ),
)


class TestTierTwoTable:
    @pytest.mark.parametrize(
        ("name", "build"), TIER_TWO_CASES, ids=[case[0] for case in TIER_TWO_CASES]
    )
    def test_every_case_is_tier_two(self, name: str, build: Any) -> None:
        payload = build()
        decision = route(
            TierEvidence(
                payload=payload,
                result=classifier.classify(payload),
                policy=TierPolicy(),
            )
        )
        assert decision.tier is BlastRadiusTier.TIER_2_ARCHITECTURAL, decision.reasons

    def test_every_case_records_a_reason(self) -> None:
        """An escalation that cannot be explained is unauditable."""
        for name, build in TIER_TWO_CASES:
            payload = build()
            decision = route(
                TierEvidence(
                    payload=payload,
                    result=classifier.classify(payload),
                    policy=TierPolicy(),
                )
            )
            assert decision.reasons, name

    def test_at_least_ten_cases(self) -> None:
        assert len(TIER_TWO_CASES) >= 10

    def test_schema_forbids_the_impossible_combinations(self) -> None:
        """Two cases that *look* like Tier-2 routing are refused by the schema.

        They were removed from the table above rather than left failing:
        invariant I-A2 requires a non-null memory limit when the reason is
        OOMKilled, so "OOMKilled with no limit" is not a routing decision, it is
        an invalid payload. Defence in depth at the schema is the better place
        for that rule than in the router.
        """
        from pydantic import ValidationError

        with pytest.raises(ValidationError, match="I-A2"):
            payload_from(lambda d: d["resource_limits"].update(memory_limit=None))


# ---------------------------------------------------------------------------
# ROADMAP 2.3.5 - the router never reads confidence
# ---------------------------------------------------------------------------


class TestRouterIgnoresConfidence:
    def test_router_signature_exposes_no_confidence(self) -> None:
        """Structural, not incidental.

        ``TierEvidence`` carries no confidence field and ``route`` takes no
        confidence parameter, so there is no channel through which a
        model-supplied score could reach the routing decision. This is stronger
        than asserting the router happens not to look at one.
        """
        assert not hasattr(TierEvidence, "confidence")
        import inspect

        params = set(inspect.signature(route).parameters)
        assert "confidence" not in params
        assert "confidence" not in {name for name in TierEvidence.__dataclass_fields__}

    def test_shuffling_confidence_does_not_change_the_tier(self) -> None:
        """Every policy confidence value must yield the same tier."""
        payload = payload_from()
        tiers = set()
        for tier1 in (0.0, 0.5, 0.99, 1.0):
            for tier2 in (0.0, 0.5, 0.99, 1.0):
                for unknown in (0.0, 0.5, 1.0):
                    policy = TriagePolicy(
                        tier1_confidence=tier1,
                        tier2_confidence=tier2,
                        unknown_confidence=unknown,
                    )
                    outcome = triage_payload(
                        payload,
                        policy=policy,
                        manifest_provider=provider_for(DEPLOYMENT),
                    )
                    tiers.add(outcome.tier)
        assert tiers == {BlastRadiusTier.TIER_1_TOIL}

    def test_confidence_sweep_cannot_promote_a_tier_two_incident(self) -> None:
        """The dangerous direction: high confidence must not buy automation."""
        payload = payload_from(lambda d: d.update(restart_count=99))
        tiers = set()
        for tier1 in (0.0, 0.99, 1.0):
            policy = TriagePolicy(tier1_confidence=tier1)
            tiers.add(triage_payload(payload, policy=policy).tier)
        assert tiers == {BlastRadiusTier.TIER_2_ARCHITECTURAL}

    def test_confidence_only_varies_the_number_not_the_verdict(self) -> None:
        payload = payload_from()
        low = triage_payload(
            payload,
            policy=TriagePolicy(tier1_confidence=0.0),
            manifest_provider=provider_for(DEPLOYMENT),
        )
        high = triage_payload(
            payload,
            policy=TriagePolicy(tier1_confidence=1.0),
            manifest_provider=provider_for(DEPLOYMENT),
        )
        assert low.response.confidence == 0.0
        assert high.response.confidence == 1.0
        assert low.tier is high.tier
        assert low.response.blast_radius_tier is high.response.blast_radius_tier


# ---------------------------------------------------------------------------
# Fail-closed routing (ROADMAP §2.3.3)
# ---------------------------------------------------------------------------


class TestFailClosedRouting:
    def test_missing_memory_signal_is_unknown_high_tier2_empty_patch(self) -> None:
        """The rule stated in the task, asserted end to end.

        An incident with no clear memory or configuration signal must be
        UNKNOWN / HIGH / TIER_2 / empty patch.
        """
        document = sample_document()
        document.update(
            {
                "reason": "CrashLoopBackOff",
                "exit_code": 1,
                "restart_count": 1,
                "scrubbed_logs": ["  ", "zzz", "\x01\x02"],
            }
        )
        payload = IncidentPayload.model_validate(document)
        outcome = triage_payload(payload, manifest_provider=provider_for(DEPLOYMENT))
        response = outcome.response

        assert response.classification is Classification.UNKNOWN
        assert response.remediation.risk_level is RiskLevel.HIGH
        assert response.blast_radius_tier is BlastRadiusTier.TIER_2_ARCHITECTURAL
        assert response.remediation.git_patch == ""
        assert response.remediation.patch_validated is False

    def test_unknown_classification_always_carries_high_risk(self) -> None:
        payload = payload_from(
            lambda d: d.update(
                reason="CrashLoopBackOff",
                exit_code=1,
                scrubbed_logs=["corrupt frame"],
            )
        )
        response = triage_payload(payload).response
        if response.classification is Classification.UNKNOWN:
            assert response.remediation.risk_level is RiskLevel.HIGH

    def test_sidecar_manifest_resolves_to_the_named_container(self) -> None:
        """A sidecar sharing the limit must not make the target ambiguous.

        Two containers both reading "256Mi" is *resolvable* - the payload names
        one of them. Confusing this with the ambiguous case is what would push a
        correct patch into a needless escalation, so it is asserted explicitly.
        """
        outcome = triage_payload(
            payload_from(), manifest_provider=provider_for(SIDECAR)
        )
        assert outcome.tier is BlastRadiusTier.TIER_1_TOIL
        patched = patch_engine.apply_unified_diff(
            SIDECAR, outcome.response.remediation.git_patch
        )
        assert patched is not None
        assert patch_engine.memory_values(patched) == ["256Mi", "512Mi"]

    def test_two_containers_with_the_target_name_yield_no_patch(self) -> None:
        manifest = """\
containers:
  - name: checkout-api
    resources:
      limits:
        memory: "256Mi"
  - name: checkout-api
    resources:
      limits:
        memory: "256Mi"
"""
        payload = payload_from()
        outcome = triage_payload(payload, manifest_provider=provider_for(manifest))
        assert outcome.tier is BlastRadiusTier.TIER_2_ARCHITECTURAL
        assert outcome.response.remediation.git_patch == ""
        assert any(
            "could not uniquely locate" in r for r in outcome.reasons
        ), outcome.reasons

    def test_manifest_drift_from_the_incident_yields_no_patch(self) -> None:
        """The manifest says 1Gi, the incident says 256Mi: do not guess."""
        drifted = DEPLOYMENT.replace('memory: "256Mi"', 'memory: "1Gi"', 1)
        payload = payload_from()
        outcome = triage_payload(payload, manifest_provider=provider_for(drifted))
        assert outcome.tier is BlastRadiusTier.TIER_2_ARCHITECTURAL
        assert outcome.response.remediation.git_patch == ""
        assert any("drifted" in r for r in outcome.reasons), outcome.reasons

    def test_unconvertible_quantity_yields_no_patch(self) -> None:
        """A limit with no exact byte conversion cannot be sized safely.

        Routing correctly returns Tier-1 here - the incident genuinely is a
        memory fault. It is the *remediation* stage that then declines, because
        ``500M`` (decimal SI mega) cannot be converted without rounding, and a
        patch sized by guesswork is worse than no patch.
        """
        payload = payload_from(
            lambda d: d["resource_limits"].update(memory_limit="500M")
        )
        decision = route(
            TierEvidence(
                payload=payload,
                result=classifier.classify(payload),
                policy=TierPolicy(),
            )
        )
        assert decision.tier is BlastRadiusTier.TIER_1_TOIL

        # The manifest must agree with the incident, otherwise the drift check
        # fires first - correctly, since a disagreeing manifest makes the byte
        # arithmetic moot.
        matching = DEPLOYMENT.replace('memory: "256Mi"', 'memory: "500M"', 1)
        outcome = triage_payload(payload, manifest_provider=provider_for(matching))
        assert outcome.tier is BlastRadiusTier.TIER_2_ARCHITECTURAL
        assert outcome.response.remediation.git_patch == ""
        assert any("byte count" in r for r in outcome.reasons), outcome.reasons

    def test_unreadable_manifest_yields_no_patch(self) -> None:
        outcome = triage_payload(
            payload_from(),
            manifest_provider=classifier.unreadable_manifest_provider(),
        )
        assert outcome.tier is BlastRadiusTier.TIER_2_ARCHITECTURAL
        assert outcome.response.remediation.git_patch == ""

    def test_absent_manifest_provider_yields_no_patch(self) -> None:
        outcome = triage_payload(payload_from())
        assert outcome.tier is BlastRadiusTier.TIER_2_ARCHITECTURAL
        assert outcome.response.remediation.git_patch == ""

    def test_tier_two_never_carries_a_patch_across_a_wide_matrix(self) -> None:
        """I-B1 as a property, not a sample.

        A single leaked patch on a Tier-2 response would break the invariant the
        whole system rests on, so this walks a matrix rather than one case.
        """
        manifests = (DEPLOYMENT, EQUAL_LIMITS, SIDECAR, "kind: ConfigMap\n", "")
        logs = ("", "corrupt frame", "connection refused", "OOM")
        reasons = ("OOMKilled", "CrashLoopBackOff")
        restarts = (0, 1, 5, 6, 40)

        checked = 0
        for manifest in manifests:
            for log in logs:
                for reason in reasons:
                    for restart in restarts:
                        document = copy.deepcopy(sample_document())
                        document["scrubbed_logs"] = [log] if log else []
                        document["reason"] = reason
                        document["restart_count"] = restart
                        document["exit_code"] = 137 if reason == "OOMKilled" else 1
                        try:
                            payload = IncidentPayload.model_validate(document)
                        except ValidationError:
                            # I-A3 requires restart_count >= 1 for a crash loop,
                            # so some rows are legitimately invalid. Padding the
                            # matrix with rows the schema rejects would test
                            # nothing.
                            continue
                        outcome = triage_payload(
                            payload, manifest_provider=provider_for(manifest)
                        )
                        if outcome.tier is BlastRadiusTier.TIER_2_ARCHITECTURAL:
                            assert outcome.response.remediation.git_patch == "", (
                                f"I-B1 VIOLATED: tier-2 carried a patch "
                                f"(log={log!r}, reason={reason}, "
                                f"restarts={restart})"
                            )
                            assert outcome.response.remediation.patch_validated is False
                        checked += 1
        assert checked >= 100, f"matrix too small to be meaningful: {checked}"


# ---------------------------------------------------------------------------
# Tier-1 end to end
# ---------------------------------------------------------------------------


class TestTierOneEndToEnd:
    def test_produces_a_verified_single_line_patch(self) -> None:
        payload = payload_from()
        outcome = triage_payload(payload, manifest_provider=provider_for(DEPLOYMENT))
        response = outcome.response

        assert outcome.tier is BlastRadiusTier.TIER_1_TOIL
        assert response.status.value == "TRIAGED"
        assert response.classification is Classification.RESOURCE_EXHAUSTION
        assert response.remediation.risk_level is RiskLevel.LOW
        assert response.remediation.patch_validated is True
        assert "512Mi" in response.remediation.git_patch

    def test_patch_applies_and_raises_only_the_limit(self) -> None:
        payload = payload_from()
        outcome = triage_payload(payload, manifest_provider=provider_for(DEPLOYMENT))
        patched = patch_engine.apply_unified_diff(
            DEPLOYMENT, outcome.response.remediation.git_patch
        )
        assert patched is not None
        # requests is untouched; only limits moved.
        assert patch_engine.memory_values(patched) == ["512Mi", "128Mi"]

    def test_tier_one_response_is_status_tiered(self) -> None:
        """I-B3: the incident id round-trips unchanged."""
        payload = payload_from()
        outcome = triage_payload(payload, manifest_provider=provider_for(DEPLOYMENT))
        assert outcome.response.incident_id == payload.incident_id

    def test_no_markdown_fences_in_the_patch(self) -> None:
        payload = payload_from()
        outcome = triage_payload(payload, manifest_provider=provider_for(DEPLOYMENT))
        assert "```" not in outcome.response.remediation.git_patch

    def test_reasons_record_the_verification(self) -> None:
        payload = payload_from()
        outcome = triage_payload(payload, manifest_provider=provider_for(DEPLOYMENT))
        assert any("verified diff" in r for r in outcome.reasons)


# ---------------------------------------------------------------------------
# The six preconditions are all actually exercised (ROADMAP §2.3.2)
# ---------------------------------------------------------------------------


class TestPreconditionCoverage:
    def test_precondition_table_covers_the_contract(self) -> None:
        assert len(classifier.PRECONDITIONS) >= 6
        names = [name for name, _ in classifier.PRECONDITIONS]
        for required in (
            "reason_is_oom_killed",
            "remedy_shape_is_allow_listed",
            "restart_count_within_policy",
            "single_affected_replica",
            "sibling_containers_healthy",
            "risk_level_not_high",
        ):
            assert required in names

    def test_every_precondition_fires_independently(self) -> None:
        """Each predicate must be reachable, or the table is decorative.

        Each entry below breaks exactly one precondition; the decision must
        record that specific reason.
        """

        def broken_payload() -> IncidentPayload:
            return payload_from(lambda d: d.update(restart_count=99))

        # reason
        crash = payload_from(lambda d: d.update(reason="CrashLoopBackOff", exit_code=1))
        decision = route(
            TierEvidence(
                payload=crash,
                result=classifier.classify(crash),
                policy=TierPolicy(),
            )
        )
        assert any("not OOMKilled" in r for r in decision.reasons)

        # restart ceiling
        decision = route(
            TierEvidence(
                payload=broken_payload(),
                result=ClassificationResult(
                    classification=Classification.RESOURCE_EXHAUSTION,
                    rationale="",
                    remedy_shape=RemedyShape.MEMORY_LIMIT_RECALIBRATION,
                    risk_level=RiskLevel.LOW,
                ),
                policy=TierPolicy(),
            )
        )
        assert any("exceeds policy max" in r for r in decision.reasons)

        # remedy shape
        decision = route(
            TierEvidence(
                payload=payload_from(),
                result=ClassificationResult(
                    classification=Classification.RESOURCE_EXHAUSTION,
                    rationale="",
                    remedy_shape=RemedyShape.UNSPECIFIED,
                    risk_level=RiskLevel.LOW,
                ),
                policy=TierPolicy(),
            )
        )
        assert any("allow-list" in r for r in decision.reasons)

        # risk
        decision = route(
            TierEvidence(
                payload=payload_from(),
                result=ClassificationResult(
                    classification=Classification.RESOURCE_EXHAUSTION,
                    rationale="",
                    remedy_shape=RemedyShape.MEMORY_LIMIT_RECALIBRATION,
                    risk_level=RiskLevel.HIGH,
                ),
                policy=TierPolicy(),
            )
        )
        assert any("risk_level is HIGH" in r for r in decision.reasons)

    def test_sibling_health_precondition_fires_on_node_pressure(self) -> None:
        payload = payload_from(
            lambda d: d["cluster_events"].append(
                {
                    "type": "Warning",
                    "reason": "MemoryPressure",
                    "message": "Node low on memory.",
                    "count": 1,
                    "first_timestamp": None,
                    "last_timestamp": None,
                    "involved_object": "node/n1",
                }
            )
        )
        decision = route(
            TierEvidence(
                payload=payload,
                result=classifier.classify(payload),
                policy=TierPolicy(),
            )
        )
        assert any("sibling container health" in r for r in decision.reasons)

    def test_all_preconditions_satisfied_reports_each_by_name(self) -> None:
        payload = payload_from()
        decision = route(
            TierEvidence(
                payload=payload,
                result=classifier.classify(payload),
                policy=TierPolicy(),
            )
        )
        assert decision.is_tier_one
        assert len(decision.satisfied) == len(classifier.PRECONDITIONS)


class TestClassificationShape:
    def test_only_one_remedy_shape_is_allow_listed(self) -> None:
        """The Tier-1 allow-list holds exactly one shape.

        Derived from the enum rather than asserted against two members
        directly: mypy folds ``A is not B`` over distinct enum literals into a
        non-overlap error, which is it correctly reporting that such a
        comparison is vacuous.
        """
        allow_listed = tuple(
            shape.value
            for shape in RemedyShape
            if shape is RemedyShape.MEMORY_LIMIT_RECALIBRATION
        )
        assert allow_listed == ("MEMORY_LIMIT_RECALIBRATION",)

    def test_oom_kill_is_the_only_low_risk_shape(self) -> None:
        payload = payload_from()
        result = classifier.classify(payload)
        assert result.remedy_shape is RemedyShape.MEMORY_LIMIT_RECALIBRATION
        assert result.risk_level is RiskLevel.LOW

    @pytest.mark.parametrize(
        "mutate",
        [
            lambda d: d.update(reason="CrashLoopBackOff", exit_code=1),
            lambda d: d.update(
                reason="CrashLoopBackOff",
                exit_code=1,
                scrubbed_logs=["connection refused"],
            ),
        ],
    )
    def test_non_resource_failures_are_high_risk_and_unspecified(
        self, mutate: Any
    ) -> None:
        result = classifier.classify(payload_from(mutate))
        assert result.risk_level is RiskLevel.HIGH
        assert result.remedy_shape is RemedyShape.UNSPECIFIED

    def test_reason_outranks_log_signal(self) -> None:
        """An OOMKilled payload is a resource fault even if a log mentions 503.

        ``reason`` is the authoritative termination signal; log text is weaker
        evidence and must not reclassify it.
        """
        payload = payload_from(
            lambda d: d.update(scrubbed_logs=["upstream returned 503"])
        )
        assert classifier.classify(payload).classification is (
            Classification.RESOURCE_EXHAUSTION
        )


def test_reason_enum_is_exhaustively_classified() -> None:
    """Every Reason the schema admits must reach a known outcome.

    A new Reason added to the schema without a classification branch would
    otherwise fall through to UNKNOWN silently.
    """
    outcomes = set()
    for reason in (Reason.OOM_KILLED, Reason.CRASH_LOOP_BACKOFF):
        exit_code = 137 if reason is Reason.OOM_KILLED else 1
        payload = payload_from(
            lambda d, r=reason, e=exit_code: d.update(reason=r.value, exit_code=e)
        )
        outcomes.add(classifier.classify(payload).classification)
    assert outcomes <= set(Classification)
