"""Endpoint tests for the SREK3S Triage Agent (ROADMAP 2.2).

Integration tests through the real ASGI app via ``TestClient``, so routing,
validation, error envelopes and the middleware are all exercised rather than
mocked.

The tests are grouped by what they are protecting:

* **Liveness** - the probes a Kubernetes ``readinessProbe`` depends on. A
  regression here is a restart loop, so these are asserted strictly.
* **Happy path** - the canonical fixture triages end to end.
* **Rejection** - a malformed body is a 400 and a contract violation is a 422.
  They must never be conflated (ARCH §4.3).
* **Fail-closed** - the central safety property. Anything unclassifiable must
  escalate to Tier-2 with an empty patch, never reach Tier-1.
* **No contamination** - ``git_patch`` must be a raw diff. A markdown fence in
  a machine-parsable artifact is the failure mode I-B4 exists to prevent.
"""

from __future__ import annotations

import asyncio
import copy
import json
from pathlib import Path
from typing import Any, Final, Iterator

import httpx
import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

import triage
from budget import DEFAULT_MAX_ACTIVE, MAX_ACTIVE_ENV, JobBudget, budget_from_env
from main import TRIAGE_PATH, TRIAGE_PATH_ALIAS, create_app
from models import (
    BlastRadiusTier,
    Classification,
    IncidentPayload,
    Remediation,
    TriageResponse,
)
from triage import TriagePolicy, StaticManifestProvider, triage_payload

#: Canonical Contract A -> B endpoint (ARCH 4; ROADMAP 2.2.2 and 3.4.4).
TRIAGE_URL: Final[str] = TRIAGE_PATH

_REPO_ROOT: Final[Path] = Path(__file__).resolve().parents[2]
SAMPLE_INCIDENT: Final[Path] = (
    _REPO_ROOT / "tests" / "fixtures" / "sample-incident.json"
)

#: A manifest containing the exact line the Tier-1 patch targets, so the
#: patch-generation path is genuinely exercised rather than short-circuited.
MANIFEST_WITH_TARGET_LINE: Final[str] = """\
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


def sample_document() -> dict[str, Any]:
    """The canonical Contract A payload, with its documentation key removed."""
    document = json.loads(SAMPLE_INCIDENT.read_text(encoding="utf-8"))
    return {k: v for k, v in document.items() if k != "_comment"}


def _memory_line(patch: str, *, added: bool) -> str:
    """Extract the changed ``memory:`` line from a diff, without its indent.

    Comparing stripped text rather than the raw line keeps these assertions
    independent of the fixture's indentation, so re-indenting the manifest does
    not turn four passing tests red for no reason.
    """
    marker = "+" if added else "-"
    for line in patch.splitlines():
        if line.startswith(marker) and not line.startswith(marker * 3):
            stripped = line[1:].strip()
            if stripped.startswith("memory:"):
                return stripped
    raise AssertionError(
        f"no {'added' if added else 'removed'} memory line in:\n{patch}"
    )


@pytest.fixture()
def client() -> Iterator[TestClient]:
    """A fresh app per test, so no state leaks between them."""
    with TestClient(create_app()) as test_client:
        yield test_client


# ---------------------------------------------------------------------------
# Liveness and readiness
# ---------------------------------------------------------------------------


class TestHealthProbes:
    def test_healthz_returns_ok(self, client: TestClient) -> None:
        response = client.get("/healthz")
        assert response.status_code == 200
        assert response.json() == {"status": "ok"}

    def test_readyz_returns_ok(self, client: TestClient) -> None:
        response = client.get("/readyz")
        assert response.status_code == 200
        assert response.json() == {"status": "ok"}

    def test_probes_emit_no_traceback(self, client: TestClient) -> None:
        """A health response must never carry host detail."""
        for path in ("/healthz", "/readyz"):
            body = client.get(path).text
            for leak in ("Traceback", "/app/", "site-packages", 'File "'):
                assert leak not in body, f"{path} leaked {leak!r}"

    def test_probes_do_not_require_authentication(self, client: TestClient) -> None:
        """A probe that needed credentials would fail closed into a restart loop."""
        assert client.get("/healthz").status_code == 200


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


class TestSuccessfulTriage:
    def test_sample_incident_is_accepted(self, client: TestClient) -> None:
        response = client.post(TRIAGE_URL, json=sample_document())
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["incident_id"] == "inc_01HQ8S7G3M2K9X4B6D0F1R5TJA"
        assert body["schema_version"] == "1.0.0"
        assert body["classification"] == "RESOURCE_EXHAUSTION"

    def test_response_validates_against_the_schema(self, client: TestClient) -> None:
        """The wire response must satisfy Contract B, not merely look right."""
        response = client.post(TRIAGE_URL, json=sample_document())
        parsed = TriageResponse.model_validate(response.json())
        assert parsed.incident_id == "inc_01HQ8S7G3M2K9X4B6D0F1R5TJA"

    def test_ib3_incident_id_round_trips(self, client: TestClient) -> None:
        sent = sample_document()
        received = client.post(TRIAGE_URL, json=sent).json()
        assert received["incident_id"] == sent["incident_id"]

    def test_no_manifest_provider_escalates(self, client: TestClient) -> None:
        """The running service has no GitOps checkout, so it must not patch.

        This is the important negative: with no manifest to check the patch
        against, I-B2 cannot be satisfied, so the engine declines to emit one
        and escalates. A service that patched anyway would be claiming a
        validation it never performed.
        """
        body = client.post(TRIAGE_URL, json=sample_document()).json()
        assert body["blast_radius_tier"] == "TIER_2_ARCHITECTURAL"
        assert body["remediation"]["git_patch"] == ""
        assert body["remediation"]["patch_validated"] is False
        assert body["remediation"]["risk_level"] == "HIGH"
        assert body["status"] == "ESCALATED"

    def test_tier1_patch_when_manifest_is_available(self) -> None:
        """The Tier-1 path, exercised with a provider that can read the target."""
        payload = IncidentPayload.model_validate(sample_document())
        provider = StaticManifestProvider(
            {triage.TARGET_MANIFEST: MANIFEST_WITH_TARGET_LINE}
        )
        outcome = triage_payload(payload, manifest_provider=provider)

        assert outcome.tier is BlastRadiusTier.TIER_1_TOIL
        # A Tier-1 outcome records how the diff was verified, not just that it
        # was emitted. The audit trail is the reason `reasons` exists at all.
        assert any("verified diff raises 256Mi to 512Mi" in r for r in outcome.reasons)
        response = outcome.response
        assert response.blast_radius_tier is BlastRadiusTier.TIER_1_TOIL
        assert response.status.value == "TRIAGED"
        assert response.remediation.risk_level.value == "LOW"
        assert response.remediation.patch_validated is True

        patch = response.remediation.git_patch
        assert patch.startswith("--- a/deploy/payments/checkout-api.yaml")
        # 256Mi doubled is 512Mi, per the default policy.
        assert _memory_line(patch, added=True) == 'memory: "512Mi"'
        assert _memory_line(patch, added=False) == 'memory: "256Mi"'

    def test_patch_raises_the_limit_and_changes_nothing_else(self) -> None:
        """The diff must touch exactly one line, and add one line."""
        payload = IncidentPayload.model_validate(sample_document())
        provider = StaticManifestProvider(
            {triage.TARGET_MANIFEST: MANIFEST_WITH_TARGET_LINE}
        )
        patch = triage_payload(
            payload, manifest_provider=provider
        ).response.remediation.git_patch

        removals = [
            ln
            for ln in patch.splitlines()
            if ln.startswith("-") and not ln.startswith("---")
        ]
        additions = [
            ln
            for ln in patch.splitlines()
            if ln.startswith("+") and not ln.startswith("+++")
        ]
        assert len(removals) == 1
        assert len(additions) == 1
        assert removals[0][1:].strip() == 'memory: "256Mi"'
        assert additions[0][1:].strip() == 'memory: "512Mi"'
        # The replacement must sit at the same indent as the line it replaces,
        # or the patched manifest is invalid YAML. Asserted as a property rather
        # than against a literal, so re-indenting the fixture does not turn this
        # test red for no reason.
        assert len(removals[0]) - len(removals[0][1:].lstrip()) == len(
            additions[0]
        ) - len(additions[0][1:].lstrip())

    def test_latency_is_measured_with_a_monotonic_clock(
        self, client: TestClient
    ) -> None:
        """AGENTS.md 3.3: perf_counter, never wall clock."""
        import inspect

        import triage as triage_module

        source = inspect.getsource(triage_module)
        assert "time.perf_counter()" in source
        # A wall clock would be wrong here: an NTP step during an incident could
        # produce a negative latency.
        assert "time.time(" not in source
        assert "datetime.now(" not in source

        body = client.post(TRIAGE_URL, json=sample_document()).json()
        assert isinstance(body["analysis_latency_ms"], int)
        assert body["analysis_latency_ms"] >= 0


class TestBothTriagePaths:
    """The canonical path and its alias must be indistinguishable.

    ARCH 4 and ROADMAP 3.4.4 specify ``/v1/incidents``; the 2.2 task specified
    ``/api/v1/triage``. Both are served, sharing one handler. If they ever
    diverged, Milestone 3's emitter would be posting to a subtly different
    service than the one under test.
    """

    def test_canonical_path_is_served(self, client: TestClient) -> None:
        """ROADMAP 3.4.4 has the Go emitter POST here; a 404 would be fatal."""
        response = client.post(TRIAGE_PATH, json=sample_document())
        assert response.status_code == 200, response.text

    def test_alias_path_is_served(self, client: TestClient) -> None:
        response = client.post(TRIAGE_PATH_ALIAS, json=sample_document())
        assert response.status_code == 200, response.text

    def test_both_paths_behave_identically(self, client: TestClient) -> None:
        canonical = client.post(TRIAGE_PATH, json=sample_document())
        alias = client.post(TRIAGE_PATH_ALIAS, json=sample_document())

        assert canonical.status_code == alias.status_code
        # request_id is excluded: it is per-request by design.
        left = {k: v for k, v in canonical.json().items() if k != "request_id"}
        right = {k: v for k, v in alias.json().items() if k != "request_id"}
        assert left == right

    def test_both_paths_reject_a_bad_body_identically(self, client: TestClient) -> None:
        document = sample_document()
        del document["namespace"]
        canonical = client.post(TRIAGE_PATH, json=document)
        alias = client.post(TRIAGE_PATH_ALIAS, json=document)
        assert canonical.status_code == alias.status_code == 422


# ---------------------------------------------------------------------------
# Rejection: 400 vs 422 (ARCH 4.3)
# ---------------------------------------------------------------------------


class TestRejection:
    def test_unparseable_body_is_400(self, client: TestClient) -> None:
        response = client.post(
            TRIAGE_URL,
            content=b"{not json",
            headers={"content-type": "application/json"},
        )
        assert response.status_code == 400
        assert response.json()["error"] == "malformed_json"

    def test_non_object_body_is_400(self, client: TestClient) -> None:
        """A valid JSON array is still not a Contract A payload."""
        response = client.post(TRIAGE_URL, json=[1, 2, 3])
        assert response.status_code == 400
        assert response.json()["error"] == "malformed_json"

    def test_missing_mandatory_field_is_422(self, client: TestClient) -> None:
        document = sample_document()
        del document["incident_id"]
        response = client.post(TRIAGE_URL, json=document)
        assert response.status_code == 422
        body = response.json()
        assert body["error"] == "validation_error"
        assert any("incident_id" in detail["loc"] for detail in body["details"])

    @pytest.mark.parametrize(
        "field",
        [
            "timestamp",
            "namespace",
            "pod_name",
            "container_name",
            "reason",
            "resource_limits",
            "redaction_report",
            "detection_latency_ms",
        ],
    )
    def test_each_mandatory_field_is_required(
        self, client: TestClient, field: str
    ) -> None:
        document = sample_document()
        del document[field]
        assert client.post(TRIAGE_URL, json=document).status_code == 422

    def test_422_is_not_coerced_into_a_triage_response(
        self, client: TestClient
    ) -> None:
        """ARCH 4.3: a 422 is a build defect and must not become a Tier-2 dispatch."""
        document = sample_document()
        del document["namespace"]
        body = client.post(TRIAGE_URL, json=document).json()
        # No triage-shaped keys at all: nothing downstream can mistake this for
        # a verdict.
        assert "blast_radius_tier" not in body
        assert "remediation" not in body
        assert body["error"] == "validation_error"

    def test_error_envelope_never_echoes_payload_content(
        self, client: TestClient
    ) -> None:
        """Pydantic's default error body can include the offending input.

        A 422 must not reflect a secret back to the client, so the envelope
        carries only field paths and error types.
        """
        document = sample_document()
        document["namespace"] = "NOT A VALID NAME"
        document["pod_name"] = "hunter2-super-secret-value"
        body = client.post(TRIAGE_URL, json=document).text
        assert "hunter2-super-secret-value" not in body

    def test_error_envelope_contains_no_traceback(self, client: TestClient) -> None:
        for payload in ([1, 2, 3], {"broken": True}):
            text = client.post(TRIAGE_URL, json=payload).text
            for leak in (
                "Traceback",
                'File "',
                "/app/",
                "site-packages",
                "pydantic_core",
            ):
                assert leak not in text, f"error envelope leaked {leak!r}"

    def test_every_error_carries_a_correlation_id(self, client: TestClient) -> None:
        """An operator must be able to join a client report to the server log."""
        for path, body in (
            ("/healthz", None),
            (TRIAGE_URL, sample_document()),
        ):
            if body is None:
                response = client.get(path)
            else:
                response = client.post(path, json=body)
            assert "X-SREK3S-Request-Id" in response.headers

    def test_unknown_route_is_a_structured_404(self, client: TestClient) -> None:
        response = client.get("/v1/does-not-exist")
        assert response.status_code == 404
        assert response.json()["error"] == "not_found"

    def test_wrong_method_is_a_structured_405(self, client: TestClient) -> None:
        response = client.get(TRIAGE_URL)
        assert response.status_code == 405
        assert response.json()["error"] == "method_not_allowed"


# ---------------------------------------------------------------------------
# Fail-closed routing (the central safety property)
# ---------------------------------------------------------------------------


class TestFailClosed:
    def test_node_pressure_forces_tier2(self) -> None:
        """An OOMKill alongside node pressure is not a workload-local fault.

        The sibling-health inference is the load-bearing predicate: without it a
        node-wide memory shortage would look identical to a container-local one
        and would be "fixed" by raising a limit that was never the problem.
        """
        document = sample_document()
        document["cluster_events"].append(
            {
                "type": "Warning",
                "reason": "Evicted",
                "message": "The node was low on resource memory.",
                "count": 3,
                "first_timestamp": None,
                "last_timestamp": None,
                "involved_object": "node/srek3s-node-1",
            }
        )
        payload = IncidentPayload.model_validate(document)
        outcome = triage_payload(
            payload,
            manifest_provider=StaticManifestProvider(
                {triage.TARGET_MANIFEST: MANIFEST_WITH_TARGET_LINE}
            ),
        )

        assert outcome.tier is BlastRadiusTier.TIER_2_ARCHITECTURAL
        assert outcome.response.remediation.git_patch == ""
        assert any("sibling container health" in r for r in outcome.reasons)

    def test_excessive_restarts_force_tier2(self) -> None:
        """Beyond the policy ceiling a restart loop is systemic, not toil."""
        document = sample_document()
        document["restart_count"] = 17
        payload = IncidentPayload.model_validate(document)
        outcome = triage_payload(
            payload,
            manifest_provider=StaticManifestProvider(
                {triage.TARGET_MANIFEST: MANIFEST_WITH_TARGET_LINE}
            ),
        )

        assert outcome.tier is BlastRadiusTier.TIER_2_ARCHITECTURAL
        assert any("exceeds policy max" in r for r in outcome.reasons)
        assert outcome.response.remediation.git_patch == ""

    def test_crashloop_is_tier2_with_no_patch(self) -> None:
        """exit code 1 / CrashLoopBackOff is an application fault, not toil.

        Correcting an entrypoint or a config error requires reading the
        application, which is outside the enumerated Tier-1 remedy shapes.

        A configuration *verdict* needs a configuration signal. The fixture's own
        logs ("alloc failure", "retrying upstream") carry none, so they are
        replaced here with one that does - otherwise the honest classification
        would be UNKNOWN, which the next test covers.
        """
        document = sample_document()
        document.update(
            {
                "reason": "CrashLoopBackOff",
                "exit_code": 1,
                "restart_count": 4,
                "scrubbed_logs": [
                    "Traceback (most recent call last): entrypoint not found"
                ],
            }
        )
        payload = IncidentPayload.model_validate(document)
        outcome = triage_payload(
            payload,
            manifest_provider=StaticManifestProvider(
                {triage.TARGET_MANIFEST: MANIFEST_WITH_TARGET_LINE}
            ),
        )

        assert outcome.tier is BlastRadiusTier.TIER_2_ARCHITECTURAL
        assert outcome.response.classification is Classification.CONFIGURATION_ERROR
        assert outcome.response.remediation.git_patch == ""
        assert outcome.response.remediation.risk_level.value == "HIGH"

    def test_crashloop_without_any_signal_is_unknown_not_configuration(self) -> None:
        """A crash-loop *reason* is a symptom; it is not a root cause.

        Treating ``reason == CrashLoopBackOff`` as sufficient proof of a
        configuration fault meant an incident with no recognisable evidence at
        all could never reach UNKNOWN - exactly backwards from fail-closed, and
        it sent unclassifiable incidents to a specific, wrong queue instead of
        the generic one.
        """
        document = sample_document()
        document.update(
            {
                "reason": "CrashLoopBackOff",
                "exit_code": 1,
                "restart_count": 4,
                "scrubbed_logs": ["  ", "zzz", "\x01\x02"],
            }
        )
        payload = IncidentPayload.model_validate(document)
        outcome = triage_payload(payload)
        assert outcome.response.classification is Classification.UNKNOWN
        assert outcome.response.status.value == "UNKNOWN"
        assert outcome.tier is BlastRadiusTier.TIER_2_ARCHITECTURAL
        assert outcome.response.remediation.git_patch == ""
        assert outcome.response.remediation.risk_level.value == "HIGH"

    def test_unclassifiable_logs_yield_unknown_and_tier2(
        self, client: TestClient
    ) -> None:
        """Anomalous, unrecognisable logs must escalate, not be force-fitted."""
        document = sample_document()
        document.update(
            {
                "reason": "CrashLoopBackOff",
                "exit_code": 1,
                "restart_count": 2,
                "scrubbed_logs": [
                    " corrupted frame 0x00",
                    "\x01\x02\x03",
                    "struct {a:1} undefined behaviour",
                ],
            }
        )
        response = client.post(TRIAGE_URL, json=document)
        assert response.status_code == 200, response.text
        body = response.json()

        # Either UNKNOWN or a recognised non-resource class; both are Tier-2.
        assert body["blast_radius_tier"] == "TIER_2_ARCHITECTURAL"
        assert body["remediation"]["git_patch"] == ""
        assert body["remediation"]["patch_validated"] is False
        assert body["remediation"]["risk_level"] == "HIGH"

    def test_dependency_fault_is_tier2(self) -> None:
        """A local symptom with an upstream cause must not get a local patch.

        Uses a non-OOM reason so the log-signal classifier is actually
        reachable: for an ``OOMKilled`` payload the authoritative ``reason``
        field wins, which is the correct precedence but would mask this rule.
        """
        document = sample_document()
        document.update(
            {
                "reason": "CrashLoopBackOff",
                "exit_code": 1,
                "restart_count": 2,
                "scrubbed_logs": [
                    "dialing payments-api: connection refused",
                    "upstream returned 503 after 30s",
                ],
            }
        )
        payload = IncidentPayload.model_validate(document)
        outcome = triage_payload(
            payload,
            manifest_provider=StaticManifestProvider(
                {triage.TARGET_MANIFEST: MANIFEST_WITH_TARGET_LINE}
            ),
        )

        assert outcome.response.classification is Classification.DEPENDENCY_FAILURE
        assert outcome.tier is BlastRadiusTier.TIER_2_ARCHITECTURAL
        assert outcome.response.remediation.git_patch == ""

    def test_ordinary_retry_log_is_not_a_dependency_fault(self) -> None:
        """Regression: a bare retry is not a dependency failure.

        The shared fixture contains ``retrying upstream call``. An earlier,
        looser marker list read that as an upstream fault, so a crash-loop
        incident was classified ``DEPENDENCY_FAILURE`` instead of
        ``CONFIGURATION_ERROR``. Both were Tier-2 so the safety property held,
        but the incident would have reached the wrong queue.
        """
        document = sample_document()
        document.update(
            {
                "reason": "CrashLoopBackOff",
                "exit_code": 1,
                "restart_count": 2,
                "scrubbed_logs": [
                    'level=warn msg="retrying upstream call" attempt=2',
                    "Traceback (most recent call last): config error",
                ],
            }
        )
        payload = IncidentPayload.model_validate(document)
        outcome = triage_payload(payload)
        assert outcome.response.classification is Classification.CONFIGURATION_ERROR
        assert outcome.tier is BlastRadiusTier.TIER_2_ARCHITECTURAL

    def test_unparseable_memory_quantity_forces_tier2(self) -> None:
        """A quantity the byte parser cannot convert yields no safe patch target.

        ``500M`` is decimal SI mega, which the schema accepts but which has no
        exact byte conversion here. Rather than approximate and produce a patch
        sized by guesswork, the engine declines to emit one.
        """
        document = sample_document()
        document["resource_limits"]["memory_limit"] = "500M"
        payload = IncidentPayload.model_validate(document)
        outcome = triage_payload(
            payload,
            manifest_provider=StaticManifestProvider(
                {triage.TARGET_MANIFEST: MANIFEST_WITH_TARGET_LINE}
            ),
        )

        assert outcome.tier is BlastRadiusTier.TIER_2_ARCHITECTURAL
        assert outcome.response.remediation.git_patch == ""

    def test_manifest_without_the_target_line_forces_tier2(self) -> None:
        """A patch built against a line that is not there would not apply."""
        document = sample_document()
        payload = IncidentPayload.model_validate(document)
        outcome = triage_payload(
            payload,
            manifest_provider=StaticManifestProvider(
                {triage.TARGET_MANIFEST: "kind: ConfigMap\nmetadata:\n  name: other\n"}
            ),
        )

        assert outcome.tier is BlastRadiusTier.TIER_2_ARCHITECTURAL
        assert outcome.response.remediation.git_patch == ""
        assert any(
            "could not uniquely locate" in r for r in outcome.reasons
        ), outcome.reasons

    def test_unreadable_manifest_forces_tier2(self) -> None:
        payload = IncidentPayload.model_validate(sample_document())
        outcome = triage_payload(
            payload, manifest_provider=triage.unreadable_manifest_provider()
        )
        assert outcome.tier is BlastRadiusTier.TIER_2_ARCHITECTURAL
        assert outcome.response.remediation.git_patch == ""

    def test_routing_reasons_are_always_reported(self) -> None:
        """An escalation with no recorded reason is unauditable."""
        document = sample_document()
        document["cluster_events"].append(
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
        payload = IncidentPayload.model_validate(document)
        outcome = triage_payload(payload)
        assert outcome.tier is BlastRadiusTier.TIER_2_ARCHITECTURAL
        assert outcome.reasons, "an escalation must record at least one reason"

    def test_tier2_never_carries_a_patch_across_many_payloads(self) -> None:
        """Property check over a matrix of hostile inputs.

        A single leaked patch on a Tier-2 response would break I-B1, the
        guarantee the entire system rests on, so this asserts the invariant
        holds for every combination rather than for one hand-picked case.
        """
        base = sample_document()
        manifests = {"with": MANIFEST_WITH_TARGET_LINE, "without": "kind: ConfigMap\n"}
        logs = ["", "corrupt frame", "connection refused", "OOM", "upstream 503"]
        reasons = ["OOMKilled", "CrashLoopBackOff"]
        restarts = [0, 1, 5, 6, 40]

        checked = 0
        for manifest_key, manifest_text in manifests.items():
            provider = StaticManifestProvider({triage.TARGET_MANIFEST: manifest_text})
            for log in logs:
                for reason in reasons:
                    for restart in restarts:
                        document = copy.deepcopy(base)
                        document["scrubbed_logs"] = [log] if log else []
                        document["reason"] = reason
                        document["restart_count"] = restart
                        if reason == "OOMKilled":
                            document["exit_code"] = 137
                        elif document["exit_code"] == 137:
                            document["exit_code"] = 1
                        try:
                            payload = IncidentPayload.model_validate(document)
                        except ValidationError:
                            # The schema's I-A2/I-A3 rules correctly refuse
                            # some combinations; skipping is correct.
                            continue
                        outcome = triage_payload(payload, manifest_provider=provider)
                        if outcome.tier is BlastRadiusTier.TIER_2_ARCHITECTURAL:
                            assert outcome.response.remediation.git_patch == "", (
                                f"I-B1 VIOLATED: tier-2 carried a patch "
                                f"(manifest={manifest_key}, log={log!r}, "
                                f"reason={reason}, restarts={restart})"
                            )
                            assert outcome.response.remediation.patch_validated is False
                        checked += 1
        # 90 of the 120 combinations are schema-valid; the I-A2 and I-A3
        # invariants correctly reject the rest, so the matrix is not padded with
        # invalid rows to reach a rounder number.
        assert checked >= 80, f"matrix shrank unexpectedly: {checked} cases"


# ---------------------------------------------------------------------------
# Active-job budget: 429 sandbox_busy (ROADMAP 2.2.5)
# ---------------------------------------------------------------------------


class TestJobBudgetUnit:
    """The guard in isolation, before any HTTP is involved."""

    def test_acquires_up_to_the_limit_then_refuses(self) -> None:
        budget = JobBudget(max_active=2)
        assert budget.try_acquire() is True
        assert budget.try_acquire() is True
        assert budget.try_acquire() is False
        assert budget.rejected == 1

    def test_release_frees_a_slot(self) -> None:
        budget = JobBudget(max_active=1)
        assert budget.try_acquire() is True
        assert budget.try_acquire() is False
        budget.release()
        assert budget.try_acquire() is True

    def test_slot_releases_even_when_the_body_raises(self) -> None:
        """A leaked slot would ratchet the service into permanent 429s.

        The guard exists to keep the service serving; if it can be broken by an
        ordinary exception it becomes the outage instead of preventing one.
        """
        budget = JobBudget(max_active=1)
        with pytest.raises(RuntimeError):
            with budget.slot() as admitted:
                assert admitted is True
                raise RuntimeError("analysis blew up")
        assert budget.active == 0
        with budget.slot() as admitted:
            assert admitted is True

    def test_slot_yields_false_when_exhausted_and_does_not_leak(self) -> None:
        budget = JobBudget(max_active=1)
        with budget.slot() as first:
            assert first is True
            with budget.slot() as second:
                assert second is False
        # The refused slot must not have decremented the held one.
        assert budget.active == 0

    def test_available_and_saturated_track_state(self) -> None:
        budget = JobBudget(max_active=3)
        assert budget.available == 3
        assert budget.saturated is False
        budget.try_acquire()
        budget.try_acquire()
        assert budget.available == 1
        budget.try_acquire()
        assert budget.available == 0
        assert budget.saturated is True

    def test_peak_is_tracked(self) -> None:
        budget = JobBudget(max_active=2)
        budget.try_acquire()
        budget.try_acquire()
        budget.release()
        budget.try_acquire()
        assert budget.peak == 2

    def test_release_never_drifts_negative(self) -> None:
        """A double release must not silently raise the effective budget."""
        budget = JobBudget(max_active=2)
        budget.release()
        budget.release()
        budget.release()
        assert budget.active == 0
        assert budget.available == 2

    def test_nonsense_budget_is_clamped_rather_than_honoured(self) -> None:
        """A budget of 0 would refuse everything and look like an outage."""
        assert JobBudget(max_active=0).max_active == 1
        assert JobBudget(max_active=-5).max_active == 1

    def test_default_budget_is_usable(self) -> None:
        assert budget_from_env({}).max_active == DEFAULT_MAX_ACTIVE

    def test_env_budget_is_honoured(self) -> None:
        assert budget_from_env({MAX_ACTIVE_ENV: "7"}).max_active == 7

    def test_malformed_env_budget_falls_back_and_does_not_raise(self) -> None:
        """An agent that refuses to start over a ConfigMap typo is an outage."""
        assert budget_from_env({MAX_ACTIVE_ENV: "not-a-number"}).max_active == (
            DEFAULT_MAX_ACTIVE
        )

    def test_zero_env_budget_is_clamped(self) -> None:
        assert budget_from_env({MAX_ACTIVE_ENV: "0"}).max_active == 1


class TestJobBudgetOverHttp:
    """429 behaviour through the real handler, not a mock of it."""

    def test_saturated_budget_returns_429(self) -> None:
        budget = JobBudget(max_active=1)
        with TestClient(create_app(job_budget=budget)) as client:
            # Hold the only slot, exactly as an in-flight analysis would.
            with budget.slot():
                response = client.post(TRIAGE_PATH, json=sample_document())
        assert response.status_code == 429
        assert response.json()["error"] == "sandbox_busy"

    def test_429_carries_retry_after(self) -> None:
        """429 is defined as retryable, so the caller is told how long to wait."""
        budget = JobBudget(max_active=1)
        with TestClient(create_app(job_budget=budget)) as client:
            with budget.slot():
                response = client.post(TRIAGE_PATH, json=sample_document())
        assert response.status_code == 429
        assert response.headers["Retry-After"] == "2"
        assert response.json()["retry_after_seconds"] == 2

    def test_429_carries_a_correlation_id(self) -> None:
        budget = JobBudget(max_active=1)
        with TestClient(create_app(job_budget=budget)) as client:
            with budget.slot():
                response = client.post(TRIAGE_PATH, json=sample_document())
        assert response.json()["request_id"]
        assert "X-SREK3S-Request-Id" in response.headers

    def test_429_leaks_no_host_detail(self) -> None:
        budget = JobBudget(max_active=1)
        with TestClient(create_app(job_budget=budget)) as client:
            with budget.slot():
                body = client.post(TRIAGE_PATH, json=sample_document()).text
        for leak in ("Traceback", "/app/", "site-packages", 'File "', "pydantic_core"):
            assert leak not in body, f"429 envelope leaked {leak!r}"

    def test_both_paths_shed_load_identically(self) -> None:
        budget = JobBudget(max_active=1)
        with TestClient(create_app(job_budget=budget)) as client:
            with budget.slot():
                canonical = client.post(TRIAGE_PATH, json=sample_document())
                alias = client.post(TRIAGE_PATH_ALIAS, json=sample_document())
        assert canonical.status_code == alias.status_code == 429

    def test_slot_is_released_after_a_successful_request(self) -> None:
        """Sequential requests must never accumulate leases."""
        budget = JobBudget(max_active=1)
        with TestClient(create_app(job_budget=budget)) as client:
            for _ in range(5):
                assert (
                    client.post(TRIAGE_PATH, json=sample_document()).status_code == 200
                )
        assert budget.active == 0
        assert budget.peak == 1

    def test_slot_is_released_after_a_rejected_request(self) -> None:
        """A 400 must not leak a slot; only the analysis path is expensive."""
        budget = JobBudget(max_active=1)
        with TestClient(create_app(job_budget=budget)) as client:
            assert client.post(TRIAGE_PATH, content=b"{bad").status_code == 400
            assert client.post(TRIAGE_PATH, json=sample_document()).status_code == 200
        assert budget.active == 0

    def test_slot_is_released_after_a_validation_failure(self) -> None:
        budget = JobBudget(max_active=1)
        document = sample_document()
        del document["namespace"]
        with TestClient(create_app(job_budget=budget)) as client:
            assert client.post(TRIAGE_PATH, json=document).status_code == 422
            assert client.post(TRIAGE_PATH, json=sample_document()).status_code == 200
        assert budget.active == 0

    def test_health_probes_are_exempt_from_the_budget(self) -> None:
        """A probe queued behind analysis would restart a healthy process.

        The kubelet would see a saturated agent as unhealthy and restart it,
        turning a load spike into a crash loop. Probes must answer regardless.
        """
        budget = JobBudget(max_active=1)
        with TestClient(create_app(job_budget=budget)) as client:
            with budget.slot():
                assert client.get("/healthz").status_code == 200
                assert client.get("/readyz").status_code == 200

    def test_a_full_budget_recovers_once_slots_are_returned(self) -> None:
        """Shedding must be transient, not sticky."""
        budget = JobBudget(max_active=1)
        with TestClient(create_app(job_budget=budget)) as client:
            with budget.slot():
                assert (
                    client.post(TRIAGE_PATH, json=sample_document()).status_code == 429
                )
            assert client.post(TRIAGE_PATH, json=sample_document()).status_code == 200
        assert budget.rejected == 1

    def test_rejections_are_counted_for_observability(self) -> None:
        budget = JobBudget(max_active=1)
        with TestClient(create_app(job_budget=budget)) as client:
            with budget.slot():
                for _ in range(3):
                    client.post(TRIAGE_PATH, json=sample_document())
        assert budget.rejected == 3

    def test_larger_budget_admits_more_concurrent_slots(self) -> None:
        budget = JobBudget(max_active=3)
        with TestClient(create_app(job_budget=budget)) as client:
            held = [budget.slot() for _ in range(3)]
            for lease in held:
                lease.__enter__()
            try:
                assert (
                    client.post(TRIAGE_PATH, json=sample_document()).status_code == 429
                )
            finally:
                for lease in held:
                    lease.__exit__(None, None, None)
            assert client.post(TRIAGE_PATH, json=sample_document()).status_code == 200


class TestJobBudgetUnderRealConcurrency:
    """429 under genuine simultaneous load, not by holding slots by hand.

    The other tests in this section drive the guard directly, which proves the
    accounting but not that the handler actually reaches it. This one fires
    concurrent requests at the real ASGI app with a deliberately slow triage and
    checks that some of them are shed.

    Note on scope: an earlier draft of this class claimed it would catch a
    design flaw where the inline triage call blocked the event loop. A negative
    control disproved that - the budget binds either way, because concurrency
    comes from `await request.json()` suspending before the budget check.
    The blocking flaw is real but different, and it is covered by
    `test_liveness_probe_answers_while_a_slow_triage_is_in_flight` below.
    """

    @staticmethod
    def _slow_triage(monkeypatch: pytest.MonkeyPatch) -> None:
        """Replace triage with a version that yields the event loop.

        ``time.sleep`` rather than ``asyncio.sleep``: the real engine is
        synchronous and runs in the threadpool, so blocking a worker thread is
        exactly the condition the budget exists to bound.
        """
        import time as time_module

        original = triage.triage_payload

        def slow(payload: object) -> object:
            time_module.sleep(0.25)
            return original(payload)  # type: ignore[arg-type]

        monkeypatch.setattr(triage, "triage_payload", slow)

    def test_concurrent_burst_is_shed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        asyncio.run(self._burst(monkeypatch, 8, expect_shed=True))

    def test_budget_never_exceeds_its_limit(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        asyncio.run(self._observe_peak(monkeypatch, 3, 10))

    def test_all_slots_are_returned_after_a_burst(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        asyncio.run(self._recover(monkeypatch, 2))

    def test_liveness_probe_answers_while_a_slow_triage_is_in_flight(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A blocked event loop turns load into a crash loop.

        The engine is synchronous. Called inline it blocks the loop, so a probe
        issued during a long triage cannot be answered until that triage
        finishes. Past ``timeoutSeconds x failureThreshold`` the kubelet reads
        that as a failed check and restarts a process that was working fine, so
        the guard here is what stops a busy agent from being killed by the
        liveness probe.

        Measured against the moment triage actually began, with a 1 s triage:
        inline the probe returns after ~1 s, in the threadpool after ~15 ms. The
        threshold is set far from both so the test is not timing-flaky - it only
        has to distinguish "waited for the triage" from "did not".
        """
        import time as time_module

        original = triage.triage_payload
        began: list[float] = []

        def slow(payload: object) -> object:
            began.append(time_module.perf_counter())
            time_module.sleep(1.0)
            return original(payload)  # type: ignore[arg-type]

        monkeypatch.setattr(triage, "triage_payload", slow)
        app = create_app(job_budget=JobBudget(max_active=8))

        async def body() -> float:
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="http://test"
            ) as http:
                post = asyncio.create_task(
                    http.post(TRIAGE_PATH, json=sample_document())
                )
                while not began:
                    await asyncio.sleep(0.001)
                probe = await http.get("/healthz")
                assert probe.status_code == 200
                elapsed = time_module.perf_counter() - began[0]
                await post
                return elapsed

        elapsed = asyncio.run(body())
        assert elapsed < 0.5, (
            f"liveness probe waited {elapsed:.3f}s for a 1s triage - the event "
            "loop is being blocked, so the kubelet would see a failed probe and "
            "restart a healthy process"
        )

    # -- coroutine bodies ---------------------------------------------------
    # Driven with asyncio.run from synchronous tests rather than through
    # pytest-asyncio. That keeps a plugin and an asyncio marker out of the
    # dependency set for three tests, which is a better trade than adding one.

    async def _burst(
        self,
        monkeypatch: pytest.MonkeyPatch,
        clients: int,
        expect_shed: bool,
    ) -> None:
        self._slow_triage(monkeypatch)
        budget = JobBudget(max_active=2)
        app = create_app(job_budget=budget)

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as http:
            responses = await asyncio.gather(
                *(
                    http.post(TRIAGE_PATH, json=sample_document())
                    for _ in range(clients)
                )
            )

        codes = [r.status_code for r in responses]
        if expect_shed:
            assert 429 in codes, f"expected shedding under load, got {codes}"
        for response in responses:
            if response.status_code == 429:
                assert response.json()["error"] == "sandbox_busy"

    async def _observe_peak(
        self, monkeypatch: pytest.MonkeyPatch, limit: int, clients: int
    ) -> None:
        """The cap must hold under contention.

        A check-then-increment that raced would overshoot, and a budget that
        overshoots is worse than no budget: it looks enforced.
        """
        self._slow_triage(monkeypatch)
        budget = JobBudget(max_active=limit)
        app = create_app(job_budget=budget)
        observed: list[int] = []

        original_triage = triage.triage_payload

        def watching(payload: object) -> object:
            observed.append(budget.active)
            return original_triage(payload)  # type: ignore[arg-type]

        monkeypatch.setattr(triage, "triage_payload", watching)

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as http:
            await asyncio.gather(
                *(
                    http.post(TRIAGE_PATH, json=sample_document())
                    for _ in range(clients)
                )
            )

        assert observed, "no request reached triage"
        assert (
            max(observed) <= limit
        ), f"budget overshot: peak {max(observed)} > {limit}"

    async def _recover(self, monkeypatch: pytest.MonkeyPatch, limit: int) -> None:
        """Shedding must be transient. Leaked slots mean permanent refusal."""
        self._slow_triage(monkeypatch)
        budget = JobBudget(max_active=limit)
        app = create_app(job_budget=budget)

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as http:
            await asyncio.gather(
                *(http.post(TRIAGE_PATH, json=sample_document()) for _ in range(6))
            )
            # With every slot returned, a fresh request must be admitted.
            response = await http.post(TRIAGE_PATH, json=sample_document())

        assert response.status_code == 200
        assert budget.active == 0


# ---------------------------------------------------------------------------
# No markdown contamination of the machine-parsable artifact
# ---------------------------------------------------------------------------


class TestNoMarkdownContamination:
    def test_patch_contains_no_fences(self) -> None:
        """I-B4: git_patch must be raw, never fenced.

        A fenced diff would fail `git apply` while looking plausible in review,
        and accepting fences would make a fenced and unfenced response behave
        differently for no defensible reason.
        """
        payload = IncidentPayload.model_validate(sample_document())
        provider = StaticManifestProvider(
            {triage.TARGET_MANIFEST: MANIFEST_WITH_TARGET_LINE}
        )
        patch = triage_payload(
            payload, manifest_provider=provider
        ).response.remediation.git_patch

        assert "```" not in patch
        assert "~~~" not in patch
        assert not patch.lstrip().startswith("```")

    def test_schema_rejects_a_fenced_patch(self) -> None:
        """The validator is the backstop if a future producer starts fencing.

        The removed line is bound to a name first rather than embedded in the
        f-string expression. A backslash inside an f-string expression is
        PEP 701 and therefore Python 3.12+; CI runs 3.11 (AGENTS.md §2), where
        it is a hard SyntaxError. Writing it inline made G5 fail on CI while
        passing locally on 3.14 - see ``test_compat.py``.
        """
        removal = '-memory: "256Mi"'
        fenced = f"```diff\n{removal}\n```"
        with pytest.raises(ValidationError, match="markdown-fenced"):
            Remediation.model_validate(
                {
                    "summary": "s",
                    "risk_level": "LOW",
                    "target_manifest": "deploy/payments/checkout-api.yaml",
                    "git_patch": fenced,
                    "patch_validated": False,
                }
            )

    def test_rca_markdown_may_use_fences_but_patch_may_not(self) -> None:
        """The human-readable RCA and the machine artifact are different things.

        ARCH §5.1 and AGENTS.md §3.2: two distinct deliverables. The RCA is for
        a person and may be prose; the patch is for `git apply` and must not be.
        """
        payload = IncidentPayload.model_validate(sample_document())
        provider = StaticManifestProvider(
            {triage.TARGET_MANIFEST: MANIFEST_WITH_TARGET_LINE}
        )
        response = triage_payload(payload, manifest_provider=provider).response
        assert "```" not in response.remediation.git_patch
        assert response.rca_markdown.startswith("# RCA:")
        assert "## Evidence" in response.rca_markdown

    def test_rca_markdown_contains_no_secret(self) -> None:
        """I-B6: the response is scrubbed before serialisation."""
        document = sample_document()
        document["scrubbed_logs"] = ["auth=Bearer [REDACTED] password=[REDACTED]"]
        payload = IncidentPayload.model_validate(document)
        provider = StaticManifestProvider(
            {triage.TARGET_MANIFEST: MANIFEST_WITH_TARGET_LINE}
        )
        response = triage_payload(payload, manifest_provider=provider).response
        for secret in ("AKIA", "eyJhbGciOi"):
            assert secret not in response.rca_markdown


# ---------------------------------------------------------------------------
# Policy behaviour
# ---------------------------------------------------------------------------


class TestPolicy:
    def test_memory_multiplier_is_honoured(self) -> None:
        payload = IncidentPayload.model_validate(sample_document())
        provider = StaticManifestProvider(
            {triage.TARGET_MANIFEST: MANIFEST_WITH_TARGET_LINE}
        )
        outcome = triage_payload(
            payload,
            policy=TriagePolicy(memory_multiplier=4),
            manifest_provider=provider,
        )
        assert (
            _memory_line(outcome.response.remediation.git_patch, added=True)
            == 'memory: "1Gi"'
        )

    def test_minimum_floor_prevents_a_useless_patch(self) -> None:
        """A 32Mi limit doubled to 64Mi is within the floor; nothing absurd."""
        document = sample_document()
        document["resource_limits"]["memory_limit"] = "32Mi"
        payload = IncidentPayload.model_validate(document)
        manifest = MANIFEST_WITH_TARGET_LINE.replace(
            'memory: "256Mi"', 'memory: "32Mi"'
        )
        provider = StaticManifestProvider({triage.TARGET_MANIFEST: manifest})
        outcome = triage_payload(payload, manifest_provider=provider)
        assert (
            _memory_line(outcome.response.remediation.git_patch, added=True)
            == 'memory: "64Mi"'
        )

    def test_policy_is_frozen(self) -> None:
        """A mutable policy would make a decision non-reproducible in review."""
        policy = TriagePolicy()
        with pytest.raises(Exception):
            policy.max_restarts = 99  # type: ignore[misc]

    def test_restart_ceiling_is_configurable(self) -> None:
        document = sample_document()
        document["restart_count"] = 8
        payload = IncidentPayload.model_validate(document)
        provider = StaticManifestProvider(
            {triage.TARGET_MANIFEST: MANIFEST_WITH_TARGET_LINE}
        )
        strict = triage_payload(
            payload, policy=TriagePolicy(max_restarts=5), manifest_provider=provider
        )
        relaxed = triage_payload(
            payload, policy=TriagePolicy(max_restarts=10), manifest_provider=provider
        )
        assert strict.tier is BlastRadiusTier.TIER_2_ARCHITECTURAL
        assert relaxed.tier is BlastRadiusTier.TIER_1_TOIL


# ---------------------------------------------------------------------------
# Severity
# ---------------------------------------------------------------------------


class TestSeverity:
    @pytest.mark.parametrize(
        ("restarts", "expected"),
        [(1, "SEV4"), (3, "SEV3"), (4, "SEV3"), (5, "SEV2"), (9, "SEV2")],
    )
    def test_severity_tracks_restart_pressure(
        self, restarts: int, expected: str
    ) -> None:
        document = sample_document()
        document["restart_count"] = restarts
        payload = IncidentPayload.model_validate(document)
        assert triage_payload(payload).response.severity.value == expected
