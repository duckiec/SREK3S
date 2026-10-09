"""Schema conformance tests for the SREK3S Triage Agent (ARCH §4, §5).

These are the drift detectors. ARCH §3.1 requires the schemas and §4/§5 to
agree, and a mismatch between the Go emitter and this module would otherwise
surface as a production 422 rather than a build failure.

Three classes of assertion:

* **Round-trip** — a valid payload from the ARCH §4 example validates, and
  serialises back to an equivalent document.
* **Rejection** — every required field, every closed enum, and every
  nullability rule is enforced, so a malformed producer is caught at the
  boundary.
* **Invariant** — I-A2, I-A3, I-A4 and I-B1 hold as properties of the model,
  not of a caller.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Final

import pytest
from pydantic import ValidationError

from models import (
    AffectedScope,
    BlastRadiusTier,
    Classification,
    IncidentPayload,
    Reason,
    RedactionReport,
    Remediation,
    ResourceLimits,
    RiskLevel,
    RootCause,
    Severity,
    SuccessCriteria,
    TriageResponse,
    TriageStatus,
    VerificationPolicy,
)

# A valid ULID body (Crockford base32, no I/L/O/U).
VALID_INCIDENT_ID: Final[str] = "inc_01HQ8S7G3M2K9X4B6D0F1R5TJA"

VALID_PATCH: Final[str] = (
    "diff --git a/deploy/payments/checkout-api.yaml b/deploy/payments/checkout-api.yaml\n"
    "index 3f1a2b4..9c8d7e6 100644\n"
    "--- a/deploy/payments/checkout-api.yaml\n"
    "+++ b/deploy/payments/checkout-api.yaml\n"
    "@@ -21,7 +21,7 @@ spec:\n"
    "             resources:\n"
    "               limits:\n"
    '-                memory: "256Mi"\n'
    '+                memory: "512Mi"\n'
)


# ---------------------------------------------------------------------------
# Fixtures — valid documents, deliberately shaped after the ARCH examples.
# ---------------------------------------------------------------------------


def oom_payload() -> dict[str, Any]:
    """A valid Contract A document for an OOMKilled container."""
    return {
        "schema_version": "1.0.0",
        "incident_id": VALID_INCIDENT_ID,
        "timestamp": "2026-09-28T14:32:07.481Z",
        "namespace": "payments",
        "pod_name": "checkout-api-7d9f4b6c8d-x2k9p",
        "container_name": "checkout-api",
        "exit_code": 137,
        "reason": "OOMKilled",
        "resource_limits": {
            "cpu_limit": "500m",
            "cpu_request": "250m",
            "memory_limit": "256Mi",
            "memory_request": "128Mi",
            "memory_working_set_bytes": 268435456,
        },
        "restart_count": 4,
        "previous_reason": "Completed",
        "scrubbed_logs": [
            'ts=2026-09-28T14:32:07.412Z level=error msg="alloc failure" pod=10.42.3.19',
            'ts=2026-09-28T14:32:07.419Z level=warn msg="retrying" auth=Bearer [REDACTED]',
        ],
        "cluster_events": [
            {
                "type": "Warning",
                "reason": "OOMKilled",
                "message": "Container checkout-api was OOMKilled (exit code 137).",
                "count": 4,
                "first_timestamp": "2026-09-28T14:28:11.002Z",
                "last_timestamp": "2026-09-28T14:32:07.470Z",
                "involved_object": "pod/checkout-api-7d9f4b6c8d-x2k9p",
            }
        ],
        "redaction_report": {
            "total_redactions": 3,
            "rules_triggered": ["aws_access_key_id", "bearer_token", "ipv4_address"],
        },
        "detection_latency_ms": 412,
        "sentinel_version": "0.1.0",
    }


def crashloop_payload() -> dict[str, Any]:
    """A valid Contract A document for a crash-looping container.

    ``exit_code`` is ``None``: a container in ``CrashLoopBackOff`` has not
    terminated, so there is no exit code to report (ARCH §4.1).
    """
    payload = oom_payload()
    payload.update(
        {
            "exit_code": None,
            "reason": "CrashLoopBackOff",
            "restart_count": 3,
            "previous_reason": "Error",
        }
    )
    return payload


def triage_response() -> dict[str, Any]:
    """A valid Contract B document for a Tier-1 OOM remediation."""
    return {
        "schema_version": "1.0.0",
        "incident_id": VALID_INCIDENT_ID,
        "status": "TRIAGED",
        "classification": "RESOURCE_EXHAUSTION",
        "severity": "SEV3",
        "confidence": 0.91,
        "blast_radius_tier": "TIER_1_TOIL",
        "root_cause": {
            "summary": (
                "The checkout-api container exceeded its 256Mi memory limit while "
                "holding an unbounded in-memory response buffer; the kernel "
                "OOM-killed it with exit code 137 on restart 4 of 4."
            ),
            "evidence": [
                "reason=OOMKilled with exit_code=137",
                "memory_working_set_bytes (268435456) equals memory_limit (256Mi)",
                "prior termination reason was Completed",
            ],
            "affected_scope": {
                "namespace": "payments",
                "pods": ["checkout-api-7d9f4b6c8d-x2k9p"],
                "replicas_affected": 1,
                "replicas_total": 3,
                "sibling_containers_healthy": True,
            },
        },
        "remediation": {
            "summary": "Raise the checkout-api memory limit from 256Mi to 512Mi.",
            "risk_level": "LOW",
            "target_manifest": "deploy/payments/checkout-api.yaml",
            "git_patch": VALID_PATCH,
            "patch_validated": True,
        },
        "verification_policy": {
            "mode": "POST_REMEDIATION_OBSERVATION",
            "watch_duration_seconds": 300,
            "success_criteria": {
                "no_oomkilled_terminations": True,
                "no_crashloopbackoff_wait": True,
                "container_uptime_seconds_min": 240,
            },
            "on_success": "CLOSE_INCIDENT",
            "on_repeat_failure": "PROMOTE_TO_TIER_2",
            "on_indeterminate": "REQUEUE_BOUNDED",
            "max_requeue_attempts": 3,
        },
        "rca_markdown": "## RCA: checkout-api OOMKilled\n\n**Root cause:** memory limit too low.",
        "analysis_latency_ms": 1830,
        "agent_version": "0.1.0",
    }


# ---------------------------------------------------------------------------
# Contract A — valid documents
# ---------------------------------------------------------------------------


class TestIncidentPayloadAcceptance:
    """Valid payloads must be accepted and round-trip unchanged."""

    def test_oomkilled_payload_validates(self) -> None:
        payload = IncidentPayload.model_validate(oom_payload())
        assert payload.reason is Reason.OOM_KILLED
        assert payload.exit_code == 137
        assert payload.resource_limits.memory_limit == "256Mi"
        assert payload.redaction_report.total_redactions == 3

    def test_crashloop_payload_validates(self) -> None:
        payload = IncidentPayload.model_validate(crashloop_payload())
        assert payload.reason is Reason.CRASH_LOOP_BACKOFF
        # Legitimately null: the container has not terminated.
        assert payload.exit_code is None

    def test_round_trip_preserves_document(self) -> None:
        original = oom_payload()
        payload = IncidentPayload.model_validate(original)
        restored = json.loads(payload.model_dump_json(exclude_unset=False))
        assert restored == original

    def test_nullable_resource_quantities_default_to_none(self) -> None:
        """A Go guard-chain miss must emit null, never omit (ARCH §4.1)."""
        document = oom_payload()
        document["resource_limits"] = {"memory_limit": "256Mi"}
        payload = IncidentPayload.model_validate(document)
        assert payload.resource_limits.cpu_limit is None
        assert payload.resource_limits.memory_request is None
        assert payload.resource_limits.memory_working_set_bytes is None

    def test_empty_logs_and_events_are_legal(self) -> None:
        document = oom_payload()
        document["scrubbed_logs"] = []
        document["cluster_events"] = []
        payload = IncidentPayload.model_validate(document)
        assert payload.scrubbed_logs == []
        assert payload.cluster_events == []


# ---------------------------------------------------------------------------
# Contract A — rejections
# ---------------------------------------------------------------------------


class TestIncidentPayloadRejection:
    """Malformed producer output must fail at the boundary, not downstream."""

    @pytest.mark.parametrize(
        "field",
        [
            "incident_id",
            "timestamp",
            "namespace",
            "pod_name",
            "container_name",
            "reason",
            "resource_limits",
            "redaction_report",
            "detection_latency_ms",
            "sentinel_version",
        ],
    )
    def test_required_field_rejected_when_missing(self, field: str) -> None:
        document = oom_payload()
        del document[field]
        with pytest.raises(ValidationError) as excinfo:
            IncidentPayload.model_validate(document)
        assert field in str(excinfo.value)

    def test_unknown_field_rejected(self) -> None:
        """extra=forbid: an unknown field is drift, not noise (ARCH §3.1)."""
        document = oom_payload()
        document["mutate_cluster"] = True
        with pytest.raises(ValidationError, match="mutate_cluster"):
            IncidentPayload.model_validate(document)

    def test_unknown_reason_rejected(self) -> None:
        document = oom_payload()
        document["reason"] = "SomethingElseEntirely"
        with pytest.raises(ValidationError):
            IncidentPayload.model_validate(document)

    def test_malformed_incident_id_rejected(self) -> None:
        document = oom_payload()
        document["incident_id"] = "not-a-valid-id"
        with pytest.raises(ValidationError):
            IncidentPayload.model_validate(document)

    def test_non_utc_timestamp_rejected(self) -> None:
        """A non-UTC timestamp makes detection_latency_ms meaningless."""
        document = oom_payload()
        document["timestamp"] = "2026-09-28T14:32:07.481+05:30"
        with pytest.raises(ValidationError, match="UTC"):
            IncidentPayload.model_validate(document)

    def test_invalid_dns_name_rejected(self) -> None:
        document = oom_payload()
        document["namespace"] = "Payments_Prod"
        with pytest.raises(ValidationError):
            IncidentPayload.model_validate(document)

    def test_negative_restart_count_rejected(self) -> None:
        document = oom_payload()
        document["restart_count"] = -1
        with pytest.raises(ValidationError):
            IncidentPayload.model_validate(document)

    def test_unknown_event_type_rejected(self) -> None:
        document = oom_payload()
        document["cluster_events"][0]["type"] = "Critical"
        with pytest.raises(ValidationError, match="Normal or Warning"):
            IncidentPayload.model_validate(document)

    def test_oversize_log_payload_rejected(self) -> None:
        """Bounded so an unbounded prompt cannot reach the model (ARCH §4.1)."""
        document = oom_payload()
        document["scrubbed_logs"] = ["line"] * 201
        with pytest.raises(ValidationError, match="max 200"):
            IncidentPayload.model_validate(document)

    def test_bad_schema_version_rejected(self) -> None:
        document = oom_payload()
        document["schema_version"] = "v1"
        with pytest.raises(ValidationError):
            IncidentPayload.model_validate(document)


# ---------------------------------------------------------------------------
# Invariants I-A2, I-A3, I-A4
# ---------------------------------------------------------------------------


class TestIncidentInvariants:
    def test_ia2_oomkilled_requires_exit_137(self) -> None:
        document = oom_payload()
        document["exit_code"] = 1
        with pytest.raises(ValidationError, match="I-A2"):
            IncidentPayload.model_validate(document)

    def test_ia2_oomkilled_requires_memory_limit(self) -> None:
        document = oom_payload()
        document["resource_limits"] = {"cpu_limit": "500m"}
        with pytest.raises(ValidationError, match="I-A2"):
            IncidentPayload.model_validate(document)

    def test_ia3_crashloop_requires_a_restart(self) -> None:
        document = crashloop_payload()
        document["restart_count"] = 0
        with pytest.raises(ValidationError, match="I-A3"):
            IncidentPayload.model_validate(document)

    def test_ia4_detection_latency_is_bounded(self) -> None:
        """PRD AC-1: detection must land inside 2 seconds."""
        document = oom_payload()
        document["detection_latency_ms"] = 2001
        with pytest.raises(ValidationError):
            IncidentPayload.model_validate(document)

    def test_ia4_boundary_value_accepted(self) -> None:
        document = oom_payload()
        document["detection_latency_ms"] = 2000
        assert IncidentPayload.model_validate(document).detection_latency_ms == 2000


# ---------------------------------------------------------------------------
# RedactionReport — counts only (ARCH §6.1 M4)
# ---------------------------------------------------------------------------


class TestRedactionReport:
    def test_counts_and_rules_accepted(self) -> None:
        report = RedactionReport.model_validate(
            {"total_redactions": 3, "rules_triggered": ["jwt", "uuid"]}
        )
        assert report.total_redactions == 3
        assert report.rules_triggered == ["jwt", "uuid"]

    def test_duplicate_rules_deduplicated_preserving_order(self) -> None:
        report = RedactionReport.model_validate(
            {"total_redactions": 5, "rules_triggered": ["jwt", "uuid", "jwt"]}
        )
        assert report.rules_triggered == ["jwt", "uuid"]

    def test_negative_count_rejected(self) -> None:
        with pytest.raises(ValidationError):
            RedactionReport.model_validate({"total_redactions": -1})

    def test_report_cannot_carry_a_value_field(self) -> None:
        """M4: the report is counts only, never the masked material."""
        with pytest.raises(ValidationError):
            RedactionReport.model_validate(
                {"total_redactions": 1, "matched_value": "hunter2"}
            )


# ---------------------------------------------------------------------------
# Contract B — the git_patch unified-diff validator
# ---------------------------------------------------------------------------


class TestUnifiedDiffValidator:
    """The requested validation guard on ``remediation.git_patch``."""

    def test_valid_unified_diff_accepted(self) -> None:
        remediation = Remediation.model_validate(
            {
                "summary": "Raise the memory limit.",
                "risk_level": "LOW",
                "target_manifest": "deploy/payments/checkout-api.yaml",
                "git_patch": VALID_PATCH,
                "patch_validated": True,
            }
        )
        assert remediation.git_patch == VALID_PATCH

    def test_empty_patch_accepted(self) -> None:
        """Legal and required for Tier-2 (ARCH §5.1)."""
        remediation = Remediation.model_validate(
            {
                "summary": "Escalate to a human.",
                "risk_level": "MEDIUM",
                "target_manifest": "deploy/payments/checkout-api.yaml",
                "git_patch": "",
                "patch_validated": False,
            }
        )
        assert remediation.git_patch == ""

    def test_patch_without_minus_header_rejected(self) -> None:
        remediation = {
            "summary": "s",
            "risk_level": "LOW",
            "target_manifest": "deploy/payments/checkout-api.yaml",
            "git_patch": "+++ b/deploy/payments/checkout-api.yaml\n@@ -1 +1 @@\n-a\n+b\n",
            "patch_validated": False,
        }
        with pytest.raises(ValidationError, match="--- a/"):
            Remediation.model_validate(remediation)

    def test_patch_without_plus_header_rejected(self) -> None:
        remediation = {
            "summary": "s",
            "risk_level": "LOW",
            "target_manifest": "deploy/payments/checkout-api.yaml",
            "git_patch": "--- a/deploy/payments/checkout-api.yaml\n@@ -1 +1 @@\n-a\n+b\n",
            "patch_validated": False,
        }
        with pytest.raises(ValidationError, match=r"\+\+\+ b/"):
            Remediation.model_validate(remediation)

    def test_patch_without_hunk_header_rejected(self) -> None:
        """Headers alone are not an applicable diff."""
        remediation = {
            "summary": "s",
            "risk_level": "LOW",
            "target_manifest": "deploy/payments/checkout-api.yaml",
            "git_patch": (
                "--- a/deploy/payments/checkout-api.yaml\n"
                "+++ b/deploy/payments/checkout-api.yaml\n"
                '-memory: "256Mi"\n'
            ),
            "patch_validated": False,
        }
        with pytest.raises(ValidationError, match="hunk header"):
            Remediation.model_validate(remediation)

    @pytest.mark.parametrize(
        "blob",
        [
            "I have raised the memory limit to 512Mi.",
            "{'memory': '512Mi'}",
            "kubectl patch deployment checkout-api -n payments",
            "```diff\n--- a/x\n+++ b/x\n@@ -1 +1 @@\n```",
        ],
        ids=["prose", "json-blob", "shell-command", "fenced"],
    )
    def test_non_diff_content_rejected(self, blob: str) -> None:
        """Freeform or hallucinated output must not become a review artifact."""
        with pytest.raises(ValidationError):
            Remediation.model_validate(
                {
                    "summary": "s",
                    "risk_level": "LOW",
                    "target_manifest": "deploy/payments/checkout-api.yaml",
                    "git_patch": blob,
                    "patch_validated": False,
                }
            )

    def test_markdown_fenced_patch_rejected_explicitly(self) -> None:
        """I-B4 forbids scraping a diff out of markdown, so fences are refused.

        Unwrapping instead would be incoherent: a fenced response would produce
        a review artifact while a byte-identical unfenced one would be
        rejected. The failure message must name the cause so a model author
        learns the actual rule rather than guessing.
        """
        fenced = f"```diff\n{VALID_PATCH}```"
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

    def test_unfenced_identical_patch_is_accepted(self) -> None:
        """The control for the test above: same bytes, no fence, accepted."""
        remediation = Remediation.model_validate(
            {
                "summary": "s",
                "risk_level": "LOW",
                "target_manifest": "deploy/payments/checkout-api.yaml",
                "git_patch": VALID_PATCH,
                "patch_validated": False,
            }
        )
        assert remediation.git_patch == VALID_PATCH

    def test_patch_validated_true_requires_a_patch(self) -> None:
        with pytest.raises(ValidationError, match="patch_validated is true"):
            Remediation.model_validate(
                {
                    "summary": "s",
                    "risk_level": "LOW",
                    "target_manifest": "deploy/payments/checkout-api.yaml",
                    "git_patch": "",
                    "patch_validated": True,
                }
            )


class TestRemediationTargetManifest:
    def test_absolute_path_rejected(self) -> None:
        with pytest.raises(ValidationError, match="repository-relative"):
            Remediation.model_validate(
                {
                    "summary": "s",
                    "risk_level": "LOW",
                    "target_manifest": "/etc/kubernetes/manifests/x.yaml",
                    "git_patch": "",
                    "patch_validated": False,
                }
            )

    def test_parent_traversal_rejected(self) -> None:
        """A patch target outside the repository is unreviewable."""
        with pytest.raises(ValidationError, match="traverse"):
            Remediation.model_validate(
                {
                    "summary": "s",
                    "risk_level": "LOW",
                    "target_manifest": "../../etc/passwd.yaml",
                    "git_patch": "",
                    "patch_validated": False,
                }
            )

    def test_non_manifest_extension_rejected(self) -> None:
        with pytest.raises(ValidationError):
            Remediation.model_validate(
                {
                    "summary": "s",
                    "risk_level": "LOW",
                    "target_manifest": "deploy/payments/checkout-api.sh",
                    "git_patch": "",
                    "patch_validated": False,
                }
            )

    def test_an_unconfigured_target_is_admitted_with_no_patch(self) -> None:
        """`target_manifest` no longer carries `min_length=5`.

        The constraint existed so the shipped default - a path that existed in no
        checkout - could not be encoded as an honest value. It could always be
        *written*, though: the Tier-2 path passed it through on every response,
        so every escalation pointed an operator at a file that was never there.
        Empty is what "nothing is configured and nothing is proposed" looks like
        on the wire, and refusing it would only push the invention somewhere less
        visible.
        """
        remediation = Remediation.model_validate(
            {
                "summary": "s",
                "risk_level": "HIGH",
                "target_manifest": "",
                "git_patch": "",
                "patch_validated": False,
            }
        )
        assert remediation.target_manifest == ""

    def test_a_patch_without_a_target_is_rejected(self) -> None:
        """The direction the relaxation must not reach (I-B2).

        `patch_validated: true` over a diff that names no file asserts that
        `git apply --check` was run against something a reader cannot go and
        look at. Dropping the field constraint without this coupling would have
        made that response valid.
        """
        with pytest.raises(ValidationError, match="target_manifest is empty"):
            Remediation.model_validate(
                {
                    "summary": "s",
                    "risk_level": "LOW",
                    "target_manifest": "",
                    "git_patch": VALID_PATCH,
                    "patch_validated": True,
                }
            )

    def test_a_named_target_with_no_patch_is_still_admitted(self) -> None:
        """The escalation case: a file to edit, and nothing edited yet.

        This is the coupling's asymmetry, and it is deliberate. Only the
        patch-without-target direction is refused; an operator reading an
        escalation is better served by being told which manifest the agent would
        have touched than by being told nothing at all.
        """
        remediation = Remediation.model_validate(
            {
                "summary": "s",
                "risk_level": "HIGH",
                "target_manifest": "deploy/chaos/oom-leak.yaml",
                "git_patch": "",
                "patch_validated": False,
            }
        )
        assert remediation.target_manifest == "deploy/chaos/oom-leak.yaml"


# ---------------------------------------------------------------------------
# Contract B — acceptance and invariant I-B1
# ---------------------------------------------------------------------------


class TestTriageResponseAcceptance:
    def test_tier1_response_validates(self) -> None:
        response = TriageResponse.model_validate(triage_response())
        assert response.status is TriageStatus.TRIAGED
        assert response.blast_radius_tier is BlastRadiusTier.TIER_1_TOIL
        assert response.remediation.patch_validated is True

    def test_round_trip_preserves_document(self) -> None:
        original = triage_response()
        response = TriageResponse.model_validate(original)
        assert json.loads(response.model_dump_json(exclude_unset=False)) == original

    def test_tier2_response_with_empty_patch_validates(self) -> None:
        document = triage_response()
        document.update(
            {
                "status": "ESCALATED",
                "blast_radius_tier": "TIER_2_ARCHITECTURAL",
                "remediation": {
                    "summary": "Architecture review required; cascading 5xx from payments-api.",
                    "risk_level": "HIGH",
                    "target_manifest": "deploy/payments/checkout-api.yaml",
                    "git_patch": "",
                    "patch_validated": False,
                },
            }
        )
        response = TriageResponse.model_validate(document)
        assert response.remediation.git_patch == ""


class TestTriageResponseRejection:
    @pytest.mark.parametrize(
        "field",
        [
            "incident_id",
            "classification",
            "severity",
            "confidence",
            "blast_radius_tier",
            "root_cause",
            "remediation",
            "verification_policy",
            "rca_markdown",
            "agent_version",
        ],
    )
    def test_required_field_rejected_when_missing(self, field: str) -> None:
        document = triage_response()
        del document[field]
        with pytest.raises(ValidationError) as excinfo:
            TriageResponse.model_validate(document)
        assert field in str(excinfo.value)

    def test_unknown_classification_rejected(self) -> None:
        document = triage_response()
        document["classification"] = "SOMETHING_NEW"
        with pytest.raises(ValidationError):
            TriageResponse.model_validate(document)

    @pytest.mark.parametrize("value", [-0.1, 1.1])
    def test_out_of_range_confidence_rejected(self, value: float) -> None:
        document = triage_response()
        document["confidence"] = value
        with pytest.raises(ValidationError):
            TriageResponse.model_validate(document)

    def test_short_root_cause_summary_rejected(self) -> None:
        """ARCH §5.1 requires a summary of at least 20 characters."""
        document = triage_response()
        document["root_cause"]["summary"] = "OOM"
        with pytest.raises(ValidationError):
            TriageResponse.model_validate(document)

    def test_empty_evidence_rejected(self) -> None:
        document = triage_response()
        document["root_cause"]["evidence"] = []
        with pytest.raises(ValidationError):
            TriageResponse.model_validate(document)

    def test_affected_exceeds_total_rejected(self) -> None:
        document = triage_response()
        document["root_cause"]["affected_scope"]["replicas_affected"] = 5
        with pytest.raises(ValidationError, match="exceeds"):
            TriageResponse.model_validate(document)

    def test_unknown_field_rejected(self) -> None:
        document = triage_response()
        document["kubectl_command"] = "kubectl delete ns payments"
        with pytest.raises(ValidationError, match="kubectl_command"):
            TriageResponse.model_validate(document)


class TestTier2Invariants:
    """I-B1: the guarantee that a non-actionable incident carries no change."""

    def test_tier2_with_patch_rejected(self) -> None:
        document = triage_response()
        document["blast_radius_tier"] = "TIER_2_ARCHITECTURAL"
        with pytest.raises(ValidationError, match="I-B1"):
            TriageResponse.model_validate(document)

    def test_tier2_with_patch_validated_rejected(self) -> None:
        document = triage_response()
        document["blast_radius_tier"] = "TIER_2_ARCHITECTURAL"
        document["remediation"]["git_patch"] = ""
        with pytest.raises(ValidationError, match="I-B1"):
            TriageResponse.model_validate(document)

    def test_high_risk_forces_tier2(self) -> None:
        document = triage_response()
        document["remediation"]["risk_level"] = "HIGH"
        with pytest.raises(ValidationError, match="risk_level=HIGH"):
            TriageResponse.model_validate(document)

    def test_unknown_classification_forces_tier2(self) -> None:
        document = triage_response()
        document["classification"] = "UNKNOWN"
        with pytest.raises(ValidationError, match="classification=UNKNOWN"):
            TriageResponse.model_validate(document)


# ---------------------------------------------------------------------------
# Verification policy bounds (ARCH §5.2)
# ---------------------------------------------------------------------------


class TestVerificationPolicy:
    def test_valid_policy_accepted(self) -> None:
        policy = VerificationPolicy.model_validate(
            {
                "mode": "POST_REMEDIATION_OBSERVATION",
                "watch_duration_seconds": 300,
                "success_criteria": {
                    "no_oomkilled_terminations": True,
                    "no_crashloopbackoff_wait": True,
                    "container_uptime_seconds_min": 240,
                },
                "max_requeue_attempts": 3,
            }
        )
        assert policy.watch_duration_seconds == 300

    @pytest.mark.parametrize("seconds", [0, 59, 1801])
    def test_out_of_window_rejected(self, seconds: int) -> None:
        """Bounded [60, 1800]: no unbounded observation (ARCH §5.2)."""
        with pytest.raises(ValidationError):
            VerificationPolicy.model_validate(
                {
                    "mode": "POST_REMEDIATION_OBSERVATION",
                    "watch_duration_seconds": seconds,
                    "success_criteria": {
                        "no_oomkilled_terminations": True,
                        "no_crashloopbackoff_wait": True,
                        "container_uptime_seconds_min": 30,
                    },
                    "max_requeue_attempts": 3,
                }
            )

    def test_uptime_must_be_below_watch_window(self) -> None:
        """Otherwise the check could pass without observing enough uptime."""
        with pytest.raises(ValidationError, match="less than watch_duration_seconds"):
            VerificationPolicy.model_validate(
                {
                    "mode": "POST_REMEDIATION_OBSERVATION",
                    "watch_duration_seconds": 300,
                    "success_criteria": {
                        "no_oomkilled_terminations": True,
                        "no_crashloopbackoff_wait": True,
                        "container_uptime_seconds_min": 300,
                    },
                    "max_requeue_attempts": 3,
                }
            )

    def test_zero_requeue_attempts_rejected(self) -> None:
        """Prevents an infinite retry loop (ARCH §5.2)."""
        with pytest.raises(ValidationError):
            VerificationPolicy.model_validate(
                {
                    "mode": "POST_REMEDIATION_OBSERVATION",
                    "watch_duration_seconds": 300,
                    "success_criteria": {
                        "no_oomkilled_terminations": True,
                        "no_crashloopbackoff_wait": True,
                        "container_uptime_seconds_min": 240,
                    },
                    "max_requeue_attempts": 0,
                }
            )

    @pytest.mark.parametrize(
        "field", ["no_oomkilled_terminations", "no_crashloopbackoff_wait"]
    )
    def test_success_criteria_must_be_true(self, field: str) -> None:
        criteria: dict[str, Any] = {
            "no_oomkilled_terminations": True,
            "no_crashloopbackoff_wait": True,
            "container_uptime_seconds_min": 240,
        }
        criteria[field] = False
        with pytest.raises(ValidationError, match="must be true"):
            SuccessCriteria.model_validate(criteria)


# ---------------------------------------------------------------------------
# ROADMAP 2.1.5 — the cross-language contract fixture
# ---------------------------------------------------------------------------


def _repo_root() -> Path:
    """Walk up from agent/ to the repository root."""
    return Path(__file__).resolve().parents[2]


SAMPLE_INCIDENT = _repo_root() / "tests" / "fixtures" / "sample-incident.json"


def _load_sample_incident() -> dict[str, Any]:
    """Read the contract fixture with its documentation keys removed.

    The ``_comment`` block is fixture documentation, not part of the wire
    contract, and ``extra="forbid"`` correctly rejects it. Stripping it in one
    place keeps every test reading the fixture identically; an earlier version
    of this file stripped it per-test and one test silently forgot, which
    surfaced as a confusing "extra input" failure rather than a real drift.
    """
    document = json.loads(SAMPLE_INCIDENT.read_text(encoding="utf-8"))
    stripped = {k: v for k, v in document.items() if k != "_comment"}
    return dict(stripped)


class TestSampleIncidentFixtureMatchesSchema:
    """ARCH §3.1: the Go emitter and these schemas must not drift.

    The fixture is the only artifact that pins the *wire* format on both sides
    of the language boundary. If the Go struct changes a field name or a
    nullability and this file is not updated in the same commit, this test
    fails here instead of the incident failing in production with a 422.
    """

    def test_fixture_exists(self) -> None:
        if not SAMPLE_INCIDENT.is_file():
            pytest.fail(
                f"missing {SAMPLE_INCIDENT}. ARCH 3.1 requires "
                "tests/fixtures/sample-incident.json in the same commit as any "
                "schema change."
            )

    def test_fixture_validates(self) -> None:
        payload = IncidentPayload.model_validate(_load_sample_incident())
        assert payload.incident_id == VALID_INCIDENT_ID
        assert payload.reason is Reason.OOM_KILLED
        assert payload.exit_code == 137
        assert payload.resource_limits.memory_limit == "256Mi"

    def test_fixture_round_trips(self) -> None:
        document = _load_sample_incident()
        payload = IncidentPayload.model_validate(document)
        assert json.loads(payload.model_dump_json(exclude_unset=False)) == document

    def test_fixture_arrives_scrubbed(self) -> None:
        """The Sentinel is the primary control (ARCH §4); this proves it ran."""
        payload = IncidentPayload.model_validate(_load_sample_incident())
        assert any("[REDACTED]" in line for line in payload.scrubbed_logs)

    def test_fixture_would_be_rejected_if_invariants_broke(self) -> None:
        """Negative control: the fixture is not vacuously valid.

        Proves the assertions above mean something by mutating the very field
        I-A2 constrains and showing the schema refuses it.
        """
        document = _load_sample_incident()
        document["exit_code"] = 1
        with pytest.raises(ValidationError, match="I-A2"):
            IncidentPayload.model_validate(document)


class TestInvariantHoldsOnDirectConstruction:
    """A service-layer caller cannot bypass the invariants."""

    def test_ia2_enforced_without_dict_round_trip(self) -> None:
        with pytest.raises(ValidationError, match="I-A2"):
            IncidentPayload(
                incident_id=VALID_INCIDENT_ID,
                timestamp="2026-09-28T14:32:07.481Z",
                namespace="payments",
                pod_name="checkout-api-7d9f4b6c8d-x2k9p",
                container_name="checkout-api",
                exit_code=1,  # violates I-A2
                reason=Reason.OOM_KILLED,
                resource_limits=ResourceLimits(memory_limit="256Mi"),
                restart_count=1,
                redaction_report=RedactionReport(total_redactions=0),
                detection_latency_ms=100,
                sentinel_version="0.1.0",
            )

    def test_ib1_enforced_on_tier2_construction(self) -> None:
        with pytest.raises(ValidationError, match="I-B1"):
            TriageResponse(
                incident_id=VALID_INCIDENT_ID,
                classification=Classification.RESOURCE_EXHAUSTION,
                severity=Severity.SEV3,
                confidence=0.9,
                blast_radius_tier=BlastRadiusTier.TIER_2_ARCHITECTURAL,
                root_cause=RootCause(
                    summary="Cascading 5xx loop originating upstream of checkout-api.",
                    evidence=["cascading 503s across 12 requests"],
                    affected_scope=AffectedScope(
                        namespace="payments",
                        replicas_affected=3,
                        replicas_total=3,
                    ),
                ),
                # A Tier-2 response must not carry a patch.
                remediation=Remediation(
                    summary="Architecture review required.",
                    risk_level=RiskLevel.MEDIUM,
                    target_manifest="deploy/payments/checkout-api.yaml",
                    git_patch=VALID_PATCH,
                ),
                verification_policy=VerificationPolicy(
                    mode="TIER_2_WAR_ROOM",
                    watch_duration_seconds=300,
                    success_criteria=SuccessCriteria(
                        no_oomkilled_terminations=True,
                        no_crashloopbackoff_wait=True,
                        container_uptime_seconds_min=240,
                    ),
                    max_requeue_attempts=3,
                ),
                rca_markdown="## RCA\n\nEscalated.",
                analysis_latency_ms=900,
                agent_version="0.1.0",
            )
