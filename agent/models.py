"""Pydantic v2 schemas for the SREK3S Triage Agent.

This module is the **schema source of truth** (ARCHITECTURE.md §3). It is the
Python side of two wire contracts:

* **Contract A — Incident Payload** (ARCH §4, produced by the Go emitter,
  consumed here). Modelled by :class:`IncidentPayload`.
* **Contract B — RCA & Remediation** (ARCH §5, produced here, consumed by the
  GitOps PR pipeline and the War-Room dispatcher). Modelled by
  :class:`TriageResponse`.

Design rules that are deliberate rather than incidental:

``extra="forbid"`` everywhere
    An unknown field is a **contract-drift signal**, not noise. Silently
    ignoring it is how a producer adds a field, a consumer drops it, and both
    sides believe the field is honoured when it is discarded. Failing loudly
    at the first version skew is the cheapest possible repair.

Unknown enum values are fatal
    A closed enum is the mechanism that turns a new failure mode into a
    :class:`TriageStatus`.UNKNOWN` escalation rather than a crash or, far
    worse, a misclassification.

Cross-field invariants live here, not in the service layer
    ``I-A2``, ``I-A3``, ``I-A4`` and ``I-B1`` are properties of the payload,
    so they are enforced at construction. A caller cannot construct an
    internally inconsistent incident by any route.

I-B5 is structural
    Neither contract has, and may never acquire, a field capable of expressing
    a cluster write verb. The CI job greps this file for mutating
    verb-shaped field names to keep that true.

Timing note
    ``analysis_latency_ms`` and ``detection_latency_ms`` are *inputs to* this
    schema, produced elsewhere with a monotonic clock
    (``time.perf_counter()``, per AGENTS.md §3.3). Nothing here reads a
    wall clock.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from enum import Enum
from typing import Annotated, Final

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

__all__ = [
    "SCHEMA_VERSION",
    "Classification",
    "Reason",
    "Severity",
    "BlastRadiusTier",
    "TriageStatus",
    "RiskLevel",
    "ClusterEvent",
    "RedactionReport",
    "ResourceLimits",
    "IncidentPayload",
    "AffectedScope",
    "RootCause",
    "Remediation",
    "SuccessCriteria",
    "VerificationPolicy",
    "TriageResponse",
]


#: Pinned contract version. Bumped only on a breaking change (ARCH §4.1).
SCHEMA_VERSION: Final[str] = "1.0.0"

#: incident_id prefix, fixed by ARCH §4.1 ("prefixed ``inc_``").
_INCIDENT_ID_RE: Final[re.Pattern[str]] = re.compile(r"^inc_[0-9A-HJKMNP-TV-Z]{20,}$")

#: A kubernetes DNS-1123 subdomain, used for namespace/pod/container names.
_DNS1123_RE: Final[re.Pattern[str]] = re.compile(r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$")

#: ``256Mi`` / ``500m`` / ``1.5`` — Kubernetes resource quantities.
_QUANTITY_RE: Final[re.Pattern[str]] = re.compile(
    r"^[0-9]+(\.[0-9]+)?(m|k|Ki|M|Mi|G|Gi|T|Ti|P|Pi)?$"
)

#: A semver triple, optionally with a pre-release/build suffix.
_SEMVER_RE: Final[re.Pattern[str]] = re.compile(
    r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$"
)

#: The two unified-diff header lines every conformant patch must carry.
#:
#: Checked as *separate* alternatives because a patch may legitimately contain
#: only one of them (``---`` without ``+++`` is valid for a deletion in some
#: emitters), but ARCH §4.3 for this contract requires both to be present, and a
#: patch missing either will not apply cleanly to a GitOps repository.
_PATCH_MINUS_RE: Final[re.Pattern[str]] = re.compile(r"^--- a/\S", re.MULTILINE)
_PATCH_PLUS_RE: Final[re.Pattern[str]] = re.compile(r"^\+\+\+ b/\S", re.MULTILINE)
_PATCH_HUNK_RE: Final[re.Pattern[str]] = re.compile(
    r"^@@ -\d+(?:,\d+)? \+\d+(?:,\d+)? @@", re.MULTILINE
)

#: A markdown code fence, optionally tagged with a language.
#:
#: Detected purely to be rejected. AGENTS.md §3.1 and ARCH §5.4 I-B4 both make
#: freeform markdown a fatal validation failure, so a fenced diff is refused
#: rather than unwrapped.
_MD_FENCE_RE: Final[re.Pattern[str]] = re.compile(r"```|~~~")

#: A repository-relative path that must not escape the repository.
_MANIFEST_PATH_RE: Final[re.Pattern[str]] = re.compile(r"^[\w./-]+\.(ya?ml|json)$")


# ---------------------------------------------------------------------------
# Enums — all closed. An unrecognised value is a contract violation, not a
# new option to be silently absorbed.
# ---------------------------------------------------------------------------


class Reason(str, Enum):
    """Container termination reason (ARCH §4.1).

    Deliberately limited to the two the Sentinel actually classifies. The Go
    side has a wider internal enum, but anything outside this set is escalated
    rather than triaged, so widening it here would widen the blast radius.
    """

    OOM_KILLED = "OOMKilled"
    CRASH_LOOP_BACKOFF = "CrashLoopBackOff"


class Classification(str, Enum):
    """Root-cause classification (ARCH §5.1)."""

    RESOURCE_EXHAUSTION = "RESOURCE_EXHAUSTION"
    CRASH_LOOP = "CRASH_LOOP"
    CONFIGURATION_ERROR = "CONFIGURATION_ERROR"
    DEPENDENCY_FAILURE = "DEPENDENCY_FAILURE"
    NETWORK_PARTITION = "NETWORK_PARTITION"
    UNKNOWN = "UNKNOWN"


class Severity(str, Enum):
    """Incident severity (ARCH §5.1)."""

    SEV1 = "SEV1"
    SEV2 = "SEV2"
    SEV3 = "SEV3"
    SEV4 = "SEV4"


class BlastRadiusTier(str, Enum):
    """Tier routing outcome (ARCH §5.3).

    Selection is deterministic and deny-by-default: anything not provably
    Tier-1 is Tier-2, so a model failure degrades to human escalation rather
    than to a speculative cluster change.
    """

    TIER_1_TOIL = "TIER_1_TOIL"
    TIER_2_ARCHITECTURAL = "TIER_2_ARCHITECTURAL"


class TriageStatus(str, Enum):
    """Transport-level outcome, distinct from the classification.

    ``UNKNOWN`` and ``REJECTED`` are the fail-closed states: they mean the
    agent could not confidently triage, and the incident goes to a human.
    """

    TRIAGED = "TRIAGED"
    ESCALATED = "ESCALATED"
    UNKNOWN = "UNKNOWN"
    REJECTED = "REJECTED"


class RiskLevel(str, Enum):
    """Remediation risk (ARCH §5.1). ``HIGH`` forces Tier-2."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


# ---------------------------------------------------------------------------
# Constrained string aliases, so validation lives with the type rather than
# being repeated at each use site.
# ---------------------------------------------------------------------------

IncidentId = Annotated[
    str,
    StringConstraints(strip_whitespace=True, min_length=24, max_length=64),
    Field(pattern=r"^inc_"),
]
"""Sentinel-generated, prefixed ``inc_``, unique per incident (ARCH §4.1)."""

SchemaVersion = Annotated[
    str,
    StringConstraints(min_length=5, max_length=32),
    Field(pattern=r"^\d+\.\d+\.\d+$"),
]
"""Pinned semver, bumped only on a breaking change."""

Dns1123Name = Annotated[
    str,
    StringConstraints(strip_whitespace=True, min_length=1, max_length=253),
    Field(pattern=r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$"),
]
"""A Kubernetes DNS-1123 subdomain (namespace, pod, container)."""

Quantity = Annotated[
    str | None,
    StringConstraints(strip_whitespace=True, min_length=1, max_length=32),
    Field(pattern=_QUANTITY_RE.pattern),
]
"""A Kubernetes resource quantity, or ``None`` when the limit is unset."""


def _parse_rfc3339_utc(value: str) -> datetime:
    """Parse an RFC3339 timestamp and require it to be UTC.

    ``datetime.fromisoformat`` accepts offsets other than ``Z``, so the
    resulting tzinfo is checked rather than assumed. A non-UTC timestamp would
    make ``detection_latency_ms`` meaningless, because it would be measured
    against a different clock origin than the one that produced it.
    """
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:  # pragma: no cover - message is the payload
        raise ValueError(f"not a valid RFC3339 timestamp: {value!r}") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"timestamp must carry a UTC offset: {value!r}")
    if parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise ValueError(
            f"timestamp must be UTC, got offset {parsed.utcoffset()}: {value!r}"
        )
    return parsed


def _validate_unified_diff(patch: str) -> str:
    """Reject a non-empty ``git_patch`` that is not a unified diff.

    This is the single most consequential guard in the module. A patch that
    does not carry unified-diff headers is either a truncated response, a
    hallucinated blob, or a second format entirely; all three would fail
    ``git apply --check`` downstream, but only *after* a human had been asked
    to review it. Failing at schema construction keeps the bad patch away from
    the review queue entirely.

    An **empty** patch is always legal: ARCH §5.1 requires ``git_patch == ""``
    for Tier-2, so emptiness is the normal and correct value for a
    non-actionable incident, not an error.

    Markdown fences are **rejected**, not stripped. ``I-B4`` forbids scraping
    a diff out of markdown, and ``AGENTS.md`` §3.1 makes freeform markdown a
    fatal validation failure. Accepting a fenced diff would be exactly that
    scrape: a model that wrapped its answer in a fence would produce a review
    artifact, while an otherwise identical response without fences would be
    rejected. The two behaviours would be incoherent, and strictness is the
    safe direction.
    """
    if patch == "":
        return patch

    if _MD_FENCE_RE.search(patch):
        raise ValueError(
            "git_patch is markdown-fenced; I-B4 forbids extracting a diff from "
            "markdown. Emit a raw unified diff."
        )

    if not _PATCH_MINUS_RE.search(patch):
        raise ValueError(
            "git_patch is non-empty but has no unified-diff '--- a/' header line"
        )
    if not _PATCH_PLUS_RE.search(patch):
        raise ValueError(
            "git_patch is non-empty but has no unified-diff '+++ b/' header line"
        )
    if not _PATCH_HUNK_RE.search(patch):
        raise ValueError(
            "git_patch has headers but no '@@ -n,m +n,m @@' hunk header, "
            "so it cannot be applied"
        )
    return patch


# ---------------------------------------------------------------------------
# Contract A — Incident Payload (Go -> Python)
# ---------------------------------------------------------------------------


class _Strict(BaseModel):
    """Base for every model: closed to unknown fields (see module docstring)."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=False,
        str_strip_whitespace=False,
        validate_assignment=True,
    )


class RedactionReport(_Strict):
    """Counts only, never the masked values (ARCH §4.1, ARCH §6.1 M4).

    Carries no plaintext by construction, so it is safe to log and to ship.
    """

    total_redactions: int = Field(ge=0)
    rules_triggered: list[str] = Field(default_factory=list)

    @field_validator("rules_triggered")
    @classmethod
    def _dedupe_preserve_order(cls, value: list[str]) -> list[str]:
        """De-duplicate while preserving first-seen order.

        The producer already emits manifest order, so ordering is stable across
        runs; de-duplication only guards against a future producer change.
        """
        seen: set[str] = set()
        out: list[str] = []
        for item in value:
            if item not in seen:
                seen.add(item)
                out.append(item)
        return out


class ResourceLimits(_Strict):
    """Container resource configuration (ARCH §4.1).

    Every quantity is nullable because the Go side must emit ``null`` rather
    than omit or invent a value when ``resources.limits`` is nil. A guard-chain
    miss in Go must not turn into a schema violation in Python.
    """

    cpu_limit: Quantity = None
    cpu_request: Quantity = None
    memory_limit: Quantity = None
    memory_request: Quantity = None
    memory_working_set_bytes: int | None = Field(default=None, ge=0)


#: Ceiling on IncidentPayload.cluster_events.
#:
#: Each ClusterEvent allows a 4096-char message, so an unbounded list is a
#: request-size amplifier. The Sentinel's own event List is bounded by
#: internal/k8s telemetry.go, and 64 is comfortably above the number of events
#: Kubernetes attaches to a single failing container.
CLUSTER_EVENTS_MAX: Final[int] = 64


class ClusterEvent(_Strict):
    """A Kubernetes Event matching the incident (ARCH §4.1)."""

    type: str = Field(min_length=1, max_length=32)
    reason: str = Field(min_length=1, max_length=128)
    message: str = Field(min_length=1, max_length=4096)
    count: int = Field(ge=0)
    first_timestamp: str | None = None
    last_timestamp: str | None = None
    involved_object: str = Field(min_length=3, max_length=512)

    @field_validator("first_timestamp", "last_timestamp")
    @classmethod
    def _timestamps_are_rfc3339(cls, value: str | None) -> str | None:
        if value is None:
            return None
        _parse_rfc3339_utc(value)
        return value

    @field_validator("type")
    @classmethod
    def _known_event_type(cls, value: str) -> str:
        if value not in {"Normal", "Warning"}:
            raise ValueError(f"event type must be Normal or Warning, got {value!r}")
        return value


class IncidentPayload(_Strict):
    """Contract A: a scrubbed, classified container failure (ARCH §4).

    Invariants enforced at construction:

    * **I-A2** ``reason == OOMKilled`` implies ``exit_code == 137`` and a
      non-null ``resource_limits.memory_limit``.
    * **I-A3** ``reason == CrashLoopBackOff`` implies ``restart_count >= 1``.
    * **I-A4** ``detection_latency_ms <= 2000`` (PRD AC-1).
    """

    schema_version: SchemaVersion = SCHEMA_VERSION
    incident_id: IncidentId
    timestamp: str

    namespace: Dns1123Name
    pod_name: Dns1123Name
    container_name: Dns1123Name

    exit_code: int | None = None
    reason: Reason
    resource_limits: ResourceLimits
    restart_count: int = Field(ge=0)
    previous_reason: str | None = Field(default=None, max_length=256)

    scrubbed_logs: list[str] = Field(default_factory=list)
    # Capped: every element is materialised, validated field-by-field, and then
    # re-serialised, so an unbounded list is an unbounded-read DoS on a field the
    # producer only ever populates with the events attached to one pod.
    cluster_events: list[ClusterEvent] = Field(
        default_factory=list, max_length=CLUSTER_EVENTS_MAX
    )
    redaction_report: RedactionReport

    detection_latency_ms: int = Field(ge=0, le=2000)
    sentinel_version: str = Field(min_length=1, max_length=64)

    @field_validator("incident_id")
    @classmethod
    def _incident_id_ulid(cls, value: str) -> str:
        """Require a ULID body, so ids sort chronologically and cannot collide."""
        if not _INCIDENT_ID_RE.match(value):
            raise ValueError(
                "incident_id must be 'inc_' followed by a 20-32 character "
                "Crockford base32 (ULID) body"
            )
        return value

    @field_validator("timestamp")
    @classmethod
    def _timestamp_is_rfc3339_utc(cls, value: str) -> str:
        _parse_rfc3339_utc(value)
        return value

    @field_validator("scrubbed_logs")
    @classmethod
    def _logs_are_bounded(cls, value: list[str]) -> list[str]:
        """Bound the log payload.

        The Go side already caps these at 200 lines / 64 KiB (ARCH §4.1), so an
        oversize payload means the producer changed without updating the
        consumer. Rejecting is correct: silently truncating here would hide the
        drift and would also let an unbounded prompt reach the model.
        """
        if len(value) > 200:
            raise ValueError(f"scrubbed_logs has {len(value)} lines, max 200")
        total = sum(len(line) for line in value)
        if total > 64 * 1024:
            raise ValueError(f"scrubbed_logs totals {total} bytes, max 65536")
        return value

    @model_validator(mode="after")
    def _enforce_invariants(self) -> IncidentPayload:
        """I-A2 and I-A3.

        These are checked here rather than in the service layer so that no code
        path — HTTP, queue consumer, or direct construction in a test — can
        produce an internally inconsistent incident.
        """
        if self.reason is Reason.OOM_KILLED:
            # I-A2. exit_code 137 is recorded but is never the *classifier*;
            # it is corroborating evidence here, not a trigger.
            if self.exit_code != 137:
                raise ValueError(
                    "I-A2: reason=OOMKilled requires exit_code=137, got "
                    f"{self.exit_code!r}"
                )
            if self.resource_limits.memory_limit is None:
                raise ValueError(
                    "I-A2: reason=OOMKilled requires a non-null "
                    "resource_limits.memory_limit"
                )
        else:  # CrashLoopBackOff
            # I-A3. exit_code may legitimately be null (the container has not
            # terminated yet), but a crash loop implies at least one restart.
            if self.exit_code is not None and self.exit_code == 0:
                raise ValueError(
                    "I-A3: reason=CrashLoopBackOff cannot have exit_code=0"
                )
            if self.restart_count < 1:
                raise ValueError(
                    f"I-A3: reason=CrashLoopBackOff requires restart_count >= 1, "
                    f"got {self.restart_count}"
                )
        return self


# ---------------------------------------------------------------------------
# Contract B — RCA & Remediation (Python -> Downstream)
# ---------------------------------------------------------------------------


class AffectedScope(_Strict):
    """Pod-level blast radius, used for tier routing (ARCH §5.1, §5.3)."""

    namespace: Dns1123Name
    pods: list[Dns1123Name] = Field(default_factory=list)
    replicas_affected: int = Field(ge=0)
    replicas_total: int = Field(ge=0)
    sibling_containers_healthy: bool = False

    @model_validator(mode="after")
    def _affected_not_more_than_total(self) -> AffectedScope:
        if self.replicas_affected > self.replicas_total:
            raise ValueError(
                f"replicas_affected ({self.replicas_affected}) exceeds "
                f"replicas_total ({self.replicas_total})"
            )
        return self


class RootCause(_Strict):
    """Human-diagnosable root cause with traceable evidence (ARCH §5.1)."""

    summary: str = Field(min_length=20, max_length=2000)
    evidence: list[str] = Field(min_length=1, max_length=20)
    affected_scope: AffectedScope

    @field_validator("evidence")
    @classmethod
    def _evidence_is_bounded(cls, value: list[str]) -> list[str]:
        for item in value:
            if not item.strip():
                raise ValueError("evidence items must be non-empty")
            if len(item) > 512:
                raise ValueError("evidence item exceeds 512 characters")
        return value


class Remediation(_Strict):
    """The proposed fix (ARCH §5.1).

    ``git_patch`` is the machine-parsable deliverable. Its validator is
    :func:`_validate_unified_diff`: a non-empty patch must carry ``--- a/``,
    ``+++ b/`` and a hunk header, while an empty patch is always legal because
    Tier-2 responses must carry one.
    """

    summary: str = Field(min_length=1, max_length=1000)
    risk_level: RiskLevel
    target_manifest: str = Field(min_length=5, max_length=512)
    git_patch: str = Field(default="", max_length=1_000_000)
    patch_validated: bool = False

    @field_validator("target_manifest")
    @classmethod
    def _manifest_is_repo_relative(cls, value: str) -> str:
        """Require a repository-relative manifest path.

        Rejects absolute paths, parent-directory traversal, and non-manifest
        extensions. A patch target outside the GitOps repository would be
        unreviewable and un-revertable, which defeats the whole control.
        """
        if value.startswith(("/", "\\")) or ":" in value:
            raise ValueError("target_manifest must be repository-relative")
        if ".." in value.split("/"):
            raise ValueError("target_manifest must not traverse outside the repository")
        if not _MANIFEST_PATH_RE.match(value):
            raise ValueError(
                "target_manifest must be a .yaml, .yml or .json path, got " f"{value!r}"
            )
        return value

    @field_validator("git_patch")
    @classmethod
    def _patch_is_unified_diff(cls, value: str) -> str:
        """Non-empty patches must be applicable unified diffs."""
        return _validate_unified_diff(value)

    @model_validator(mode="after")
    def _validated_implies_patch_present(self) -> Remediation:
        """``patch_validated`` cannot be true of a non-existent patch."""
        if self.patch_validated and not self.git_patch:
            raise ValueError(
                "patch_validated is true but git_patch is empty; a Tier-2 "
                "response must set patch_validated=false (I-B1)"
            )
        return self


class SuccessCriteria(_Strict):
    """Closure conditions for the verification loop (ARCH §5.2).

    Both boolean criteria must be ``true``: an incident is not closed while the
    fault it was raised for can still recur.
    """

    no_oomkilled_terminations: bool
    no_crashloopbackoff_wait: bool
    container_uptime_seconds_min: int = Field(ge=0)

    @model_validator(mode="after")
    def _both_criteria_required(self) -> SuccessCriteria:
        if not self.no_oomkilled_terminations:
            raise ValueError("success_criteria.no_oomkilled_terminations must be true")
        if not self.no_crashloopbackoff_wait:
            raise ValueError("success_criteria.no_crashloopbackoff_wait must be true")
        return self


class VerificationPolicy(_Strict):
    """Bounded post-remediation observation (ARCH §5.2)."""

    mode: str = Field(min_length=1, max_length=64)
    watch_duration_seconds: int = Field(ge=60, le=1800)
    success_criteria: SuccessCriteria
    on_success: str = Field(default="CLOSE_INCIDENT", max_length=32)
    on_repeat_failure: str = Field(default="PROMOTE_TO_TIER_2", max_length=32)
    on_indeterminate: str = Field(default="REQUEUE_BOUNDED", max_length=32)
    max_requeue_attempts: int = Field(ge=1, le=10)

    @model_validator(mode="after")
    def _uptime_below_watch_window(self) -> VerificationPolicy:
        """Uptime must be observable inside the window, or the check is vacuous.

        ``container_uptime_seconds_min >= watch_duration_seconds`` would let the
        incident close without ever having observed enough uptime to conclude
        anything.
        """
        if (
            self.success_criteria.container_uptime_seconds_min
            >= self.watch_duration_seconds
        ):
            raise ValueError(
                "container_uptime_seconds_min "
                f"({self.success_criteria.container_uptime_seconds_min}) must be "
                f"less than watch_duration_seconds ({self.watch_duration_seconds})"
            )
        return self


class TriageResponse(_Strict):
    """Contract B: the agent's verdict on one incident (ARCH §5).

    Invariant **I-B1** is enforced at construction:
    ``blast_radius_tier == TIER_2_ARCHITECTURAL`` implies an empty
    ``git_patch`` and ``patch_validated == false``. This is the single
    guarantee that a non-actionable incident can never carry a speculative
    cluster change downstream.
    """

    schema_version: SchemaVersion = SCHEMA_VERSION
    incident_id: IncidentId
    status: TriageStatus = TriageStatus.TRIAGED

    classification: Classification
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    blast_radius_tier: BlastRadiusTier

    root_cause: RootCause
    remediation: Remediation
    verification_policy: VerificationPolicy

    rca_markdown: str = Field(min_length=1, max_length=20_000)
    analysis_latency_ms: int = Field(ge=0)
    agent_version: str = Field(min_length=1, max_length=64)

    @field_validator("incident_id")
    @classmethod
    def _incident_id_ulid(cls, value: str) -> str:
        if not _INCIDENT_ID_RE.match(value):
            raise ValueError(
                "incident_id must be 'inc_' followed by a 20-32 character "
                "Crockford base32 (ULID) body"
            )
        return value

    @model_validator(mode="after")
    def _enforce_tier2_carries_no_patch(self) -> TriageResponse:
        """**I-B1**, the central safety invariant of the whole system.

        A Tier-2 response is a request for human judgement. If it also carried a
        patch, that patch would reach the GitOps PR pipeline and could be
        merged by a reviewer who trusted the tier label rather than reading the
        diff. So the two are mutually exclusive by construction, not by
        convention.
        """
        if self.blast_radius_tier is BlastRadiusTier.TIER_2_ARCHITECTURAL:
            if self.remediation.git_patch:
                raise ValueError(
                    "I-B1: blast_radius_tier=TIER_2_ARCHITECTURAL requires an "
                    f"empty git_patch, got {len(self.remediation.git_patch)} chars"
                )
            if self.remediation.patch_validated:
                raise ValueError(
                    "I-B1: blast_radius_tier=TIER_2_ARCHITECTURAL requires "
                    "patch_validated=false"
                )
        return self

    @model_validator(mode="after")
    def _high_risk_forces_tier2(self) -> TriageResponse:
        """``risk_level == HIGH`` must not ride alongside a Tier-1 patch.

        ARCH §5.1 states ``HIGH`` forces Tier-2. Enforcing it here means a
        caller cannot assemble a high-risk change labelled as routine toil.
        """
        if (
            self.remediation.risk_level is RiskLevel.HIGH
            and self.blast_radius_tier is not BlastRadiusTier.TIER_2_ARCHITECTURAL
        ):
            raise ValueError(
                "remediation.risk_level=HIGH requires "
                "blast_radius_tier=TIER_2_ARCHITECTURAL"
            )
        return self

    @model_validator(mode="after")
    def _unknown_classification_forces_tier2(self) -> TriageResponse:
        """``classification == UNKNOWN`` must not carry a patch.

        The fail-closed direction: if the agent cannot name the fault, it must
        not propose a change. This is the schema-level expression of the
        deny-by-default routing in ARCH §5.3.
        """
        if (
            self.classification is Classification.UNKNOWN
            and self.blast_radius_tier is not BlastRadiusTier.TIER_2_ARCHITECTURAL
        ):
            raise ValueError(
                "classification=UNKNOWN requires blast_radius_tier=TIER_2_ARCHITECTURAL"
            )
        return self


# Compile-time evidence that the semver pattern is well-formed and that the
# module's own SCHEMA_VERSION satisfies SchemaVersion. Cheap, and it fails at
# import time rather than in production.
assert _SEMVER_RE.match(SCHEMA_VERSION), "SCHEMA_VERSION must be semver"
