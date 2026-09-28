"""Deterministic triage engine (ARCH §5.3).

Turns a scrubbed :class:`~models.IncidentPayload` into a fully populated
:class:`~models.TriageResponse`.

**The governing property is deny-by-default.** ARCH §5.3 routes Tier-1 only on
a conjunction of provable conditions; anything else is Tier-2. That ordering is
what makes this module safe to extend: a new rule added without full evidence
can only ever produce *less* automation, never a speculative cluster change.

Three consequences shape the code:

1. **Tier selection precedes remediation.** The tier is decided from the
   payload's observable facts before a patch is considered, so a change can
   never influence its own authorisation.
2. **Uncertainty is a first-class outcome.** ``Classification.UNKNOWN`` with
   ``RiskLevel.HIGH``, an empty patch and Tier-2 is a *success*, not a failure.
   Most incidents a naive agent would "fix" belong here.
3. **The patch is derived, never authored.** A memory-limit patch is a
   mechanical edit to a known manifest line, not a guess. If the expected line
   is absent, or the manifest cannot be read, the engine declines to emit a
   patch, because it cannot then satisfy I-B2.

Timing uses :func:`time.perf_counter` exclusively (AGENTS.md §3.3). A wall
clock would be wrong here: a monotonic source cannot jump backwards when the
host clock is stepped by NTP during an incident, which would yield a negative
latency.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Final, Protocol

import prompt
from models import (
    SCHEMA_VERSION,
    AffectedScope,
    BlastRadiusTier,
    Classification,
    IncidentPayload,
    Reason,
    Remediation,
    RiskLevel,
    RootCause,
    Severity,
    SuccessCriteria,
    TriageResponse,
    TriageStatus,
    VerificationPolicy,
)

__all__ = [
    "AGENT_VERSION",
    "TARGET_MANIFEST",
    "ManifestProvider",
    "TriagePolicy",
    "TriageOutcome",
    "triage_payload",
    "unreadable_manifest_provider",
]

#: Build-stamped by the packaging pipeline (ARCH §5.1).
AGENT_VERSION: Final[str] = "0.1.0"

#: The single manifest Tier-1 remediation is permitted to target. Hard-coded
#: rather than derived from the pod name because ARCH §5.3 enumerates the
#: Tier-1 remedy shapes; deriving a path from attacker-influenced input would
#: let a pod name choose its own patch target.
TARGET_MANIFEST: Final[str] = "deploy/payments/checkout-api.yaml"

# ARCH §5.2 caps observation at 1800s and floors it at 60s.
_TIER_1_WATCH_SECONDS: Final[int] = 300
_TIER_1_UPTIME_MINIMUM: Final[int] = 240
_TIER_2_WATCH_SECONDS: Final[int] = 900
_TIER_2_UPTIME_MINIMUM: Final[int] = 600

#: Cluster events that indicate node-level rather than container-level pressure.
#:
#: A container OOMKill and a node eviction are different faults. An OOMKill means
#: the container's own cgroup limit was reached; an eviction means the *node* ran
#: out of resources, which implicates every container on it. This distinction is
#: the observable basis for the sibling-health inference.
_NODE_LEVEL_EVENTS: Final[frozenset[str]] = frozenset(
    {
        "Evicted",
        "MemoryPressure",
        "NodeHasInsufficientMemory",
        "NodeHasDiskPressure",
        "NodeHasNoDiskPressure",
        "Preempted",
        "NodeNotReady",
        "Shutdown",
    }
)


class ManifestProvider(Protocol):
    """Read-only access to the GitOps repository contents.

    Exists so the engine can prove a generated patch applies to the *current*
    manifest rather than to an assumption about it (I-B2). Milestone 2 has no
    GitOps checkout, so the default provider reports every manifest as
    unreadable and the engine then declines to emit a patch. That is the
    fail-closed behaviour, not a gap: a patch that cannot be checked must not be
    presented as ``patch_validated``.
    """

    def read_manifest(self, path: str) -> str | None:
        """Return manifest text, or ``None`` when it cannot be read."""
        ...


@dataclass(frozen=True)
class TriagePolicy:
    """Thresholds governing tier routing (ARCH §5.3).

    Frozen so a policy cannot be mutated mid-incident, which would make the
    decision non-reproducible during review.
    """

    #: ARCH §5.3 default. Above this a restart loop is a systemic fault, not the
    #: bounded thrash a memory-limit increase addresses.
    max_restarts: int = 5
    #: Multiplier applied to the current limit when recalibrating.
    memory_multiplier: int = 2
    #: Floor for the recalibrated limit, so a pathological 4Mi limit does not
    #: become 8Mi.
    min_memory_bytes: int = 64 * 1024 * 1024
    #: Confidence for a deterministically-proven Tier-1 root cause.
    tier1_confidence: float = 0.91
    #: Confidence for a classification drawn from log signal only.
    tier2_confidence: float = 0.55
    #: Confidence for a wholly unclassifiable incident.
    unknown_confidence: float = 0.1


@dataclass
class TriageOutcome:
    """The response plus the routing decision that produced it.

    ``reasons`` is returned alongside the response rather than hidden inside it,
    so a caller can log *why* a decision was made. It is the audit trail a
    War-Room reviewer needs and the first thing to inspect when a routing rule
    looks wrong.
    """

    response: TriageResponse
    tier: BlastRadiusTier
    reasons: list[str] = field(default_factory=list)
    latency_ms: int = 0


def unreadable_manifest_provider() -> ManifestProvider:
    """A provider that reports every manifest as unreadable.

    This is the default for the running service, and it is what makes the
    fail-closed path the *normal* one rather than a corner case: until a real
    GitOps checkout is wired in (§2.5), the service escalates rather than
    proposing changes it cannot verify.
    """

    class _Unreadable:
        def read_manifest(self, path: str) -> None:
            return None

    return _Unreadable()


class StaticManifestProvider:
    """An in-memory provider, used by tests and by Milestone 2.5.

    Holds manifest text in a dict rather than touching the filesystem, so the
    triage engine itself never performs I/O and stays trivially testable.
    """

    def __init__(self, manifests: dict[str, str]) -> None:
        self._manifests = dict(manifests)

    def read_manifest(self, path: str) -> str | None:
        return self._manifests.get(path)


# ---------------------------------------------------------------------------
# Quantity arithmetic
# ---------------------------------------------------------------------------

#: Binary suffixes ordered **largest first**.
#:
#: The order is load-bearing, not cosmetic. Iterating smallest-first made every
#: byte count divisible by 1024 render as Ki, so a 256Mi limit doubled to
#: "524288Ki" rather than "512Mi" - a correct number in a form no engineer
#: would write, and one a reviewer would have to stop and decode.
_BINARY_SUFFIXES_DESC: Final[tuple[tuple[str, int], ...]] = (
    ("Pi", 1024**5),
    ("Ti", 1024**4),
    ("Gi", 1024**3),
    ("Mi", 1024**2),
    ("Ki", 1024),
)


def _parse_quantity_to_bytes(quantity: str) -> int | None:
    """Convert a Kubernetes quantity to bytes, or ``None`` if unparseable.

    Deliberately conservative: a suffix it does not recognise returns ``None``
    rather than a guess, because a wrong byte count yields a wrong patch target
    and a wrong safety rationale.
    """
    text = quantity.strip()
    for suffix, scale in _BINARY_SUFFIXES_DESC:
        if text.endswith(suffix):
            head = text[: -len(suffix)]
            try:
                return int(float(head) * scale)
            except ValueError:
                return None
    try:
        return int(text)
    except ValueError:
        return None


def _format_bytes(value: int) -> str:
    """Render a byte count as a binary-suffixed Kubernetes quantity."""
    for suffix, scale in _BINARY_SUFFIXES_DESC:
        if value >= scale and value % scale == 0:
            return f"{value // scale}{suffix}"
    return str(value)


# ---------------------------------------------------------------------------
# Blast radius
# ---------------------------------------------------------------------------


def _node_pressure_signals(payload: IncidentPayload) -> list[str]:
    """Node-level event reasons present in the incident's event batch."""
    return sorted(
        {
            event.reason
            for event in payload.cluster_events
            if event.reason in _NODE_LEVEL_EVENTS
        }
    )


def _siblings_healthy(payload: IncidentPayload) -> bool:
    """Infer whether sibling containers are unaffected.

    A single-pod payload carries no direct observation of siblings, so this is
    an **inference** and is labelled as one rather than presented as fact.

    The inference: a container-local ``OOMKilled`` means the kernel enforced
    *this container's* cgroup limit, which is evidence the fault is contained.
    It is trusted only when no node-level signal is present, because a
    ``MemoryPressure`` or ``Evicted`` event in the same batch means the node
    itself is constrained and siblings are implicated too.

    Fail-closed by construction: any node-level signal, or the absence of the
    container-local reason that would have justified the inference, returns
    ``False`` and the ARCH §5.3 predicate fails. Milestone 2.4's sandbox replaces
    this with a direct observation; until then it is the strongest statement the
    payload supports.
    """
    if payload.reason is not Reason.OOM_KILLED:
        return False
    return not _node_pressure_signals(payload)


def _affected_scope(payload: IncidentPayload) -> AffectedScope:
    """Derive the pod-level blast radius.

    ``replicas_total`` is the narrowest true statement available: one replica is
    affected and Contract A carries no cluster-wide count. Inventing a larger
    number would be fabrication; understating it would understate the blast
    radius. So it is reported as 1-of-at-least-1.
    """
    return AffectedScope(
        namespace=payload.namespace,
        pods=[payload.pod_name],
        replicas_affected=1,
        replicas_total=1,
        sibling_containers_healthy=_siblings_healthy(payload),
    )


# ---------------------------------------------------------------------------
# Tier routing (ARCH §5.3)
# ---------------------------------------------------------------------------


def _tier1_predicates(
    payload: IncidentPayload,
    classification: Classification,
    policy: TriagePolicy,
) -> tuple[bool, list[str]]:
    """Evaluate the ARCH §5.3 conjunction in full.

    Every clause is evaluated even after one fails, so the reasons returned are
    a complete account of the decision rather than a short-circuit trace. A
    reviewer asking "why was this escalated?" gets every reason, not just the
    first.

    Returns ``(admissible, reasons)``; ``reasons`` is empty iff admissible.
    """
    reasons: list[str] = []

    if payload.reason is not Reason.OOM_KILLED:
        reasons.append(
            f"reason is {payload.reason.value}, not OOMKilled; only an OOMKilled "
            "memory recalibration is an enumerated Tier-1 shape"
        )
    if classification is not Classification.RESOURCE_EXHAUSTION:
        reasons.append(
            f"classification {classification.value} is not in the Tier-1 allow-list"
        )
    if payload.restart_count > policy.max_restarts:
        reasons.append(
            f"restart_count {payload.restart_count} exceeds policy max "
            f"{policy.max_restarts}"
        )
    if payload.resource_limits.memory_limit is None:
        reasons.append("no memory limit is set, so there is nothing to recalibrate")
    if not _siblings_healthy(payload):
        signals = _node_pressure_signals(payload)
        detail = f" (node-level signals: {', '.join(signals)})" if signals else ""
        reasons.append("sibling container health could not be proven healthy" + detail)

    return (not reasons), reasons


# ---------------------------------------------------------------------------
# Response builders
# ---------------------------------------------------------------------------


def _severity_for(payload: IncidentPayload) -> Severity:
    """Map observed facts to a severity, conservatively."""
    if payload.restart_count >= 5:
        return Severity.SEV2
    if payload.restart_count >= 3:
        return Severity.SEV3
    return Severity.SEV4


def _verification_policy(tier: BlastRadiusTier) -> VerificationPolicy:
    """Bounded observation policy appropriate to the tier."""
    if tier is BlastRadiusTier.TIER_1_TOIL:
        return VerificationPolicy(
            mode="POST_REMEDIATION_OBSERVATION",
            watch_duration_seconds=_TIER_1_WATCH_SECONDS,
            success_criteria=SuccessCriteria(
                no_oomkilled_terminations=True,
                no_crashloopbackoff_wait=True,
                container_uptime_seconds_min=_TIER_1_UPTIME_MINIMUM,
            ),
            max_requeue_attempts=3,
        )
    return VerificationPolicy(
        mode="TIER_2_WAR_ROOM",
        watch_duration_seconds=_TIER_2_WATCH_SECONDS,
        success_criteria=SuccessCriteria(
            no_oomkilled_terminations=True,
            no_crashloopbackoff_wait=True,
            container_uptime_seconds_min=_TIER_2_UPTIME_MINIMUM,
        ),
        # Requeueing a *human* is meaningless, and ARCH §5.2 requires
        # max_requeue_attempts >= 1, so one bounded requeue of the incident
        # record is expressed rather than the illegal zero.
        max_requeue_attempts=1,
    )


def _tier2_response(
    payload: IncidentPayload,
    classification: Classification,
    severity: Severity,
    confidence: float,
    rationale: str,
    latency_ms: int,
    status: TriageStatus,
) -> TriageResponse:
    """Build a Tier-2 response. Never carries a patch (I-B1)."""
    evidence = prompt.evidence_lines(payload)
    return TriageResponse(
        schema_version=SCHEMA_VERSION,
        incident_id=payload.incident_id,
        status=status,
        classification=classification,
        severity=severity,
        confidence=confidence,
        blast_radius_tier=BlastRadiusTier.TIER_2_ARCHITECTURAL,
        root_cause=RootCause(
            summary=rationale,
            evidence=evidence,
            affected_scope=_affected_scope(payload),
        ),
        # RiskLevel.HIGH is required, not chosen for emphasis: ARCH §5.1 states
        # HIGH forces Tier-2, so any lower value would contradict the routing
        # this response asserts. The schema enforces the same rule.
        remediation=Remediation(
            summary=(
                "No automatic change proposed. Escalated for human root-cause "
                "analysis."
            ),
            risk_level=RiskLevel.HIGH,
            target_manifest=TARGET_MANIFEST,
            git_patch="",
            patch_validated=False,
        ),
        verification_policy=_verification_policy(BlastRadiusTier.TIER_2_ARCHITECTURAL),
        rca_markdown=prompt.rca_markdown(
            payload,
            classification,
            BlastRadiusTier.TIER_2_ARCHITECTURAL,
            rationale,
            evidence,
        ),
        analysis_latency_ms=latency_ms,
        agent_version=AGENT_VERSION,
    )


# ---------------------------------------------------------------------------
# Patch construction
# ---------------------------------------------------------------------------


def build_memory_patch(
    manifest_text: str, old_limit: str, new_limit: str, path: str
) -> str | None:
    """Produce a unified diff raising one memory limit, or ``None``.

    Returns ``None`` rather than a best-effort patch when the target line is
    absent. A patch built against a line that is not there will not apply, and a
    patch that does not apply is worse than no patch: it consumes a reviewer's
    attention and teaches them to skim diffs from this system.
    """
    old_line = f'memory: "{old_limit}"'
    new_line = f'memory: "{new_limit}"'

    lines = manifest_text.splitlines()
    match_index = next(
        (i for i, line in enumerate(lines) if line.strip().rstrip(",") == old_line),
        None,
    )
    if match_index is None:
        return None

    # Preserve the original line's leading whitespace. Emitting the replacement
    # at column 0 produces a syntactically invalid manifest, and a patch that
    # breaks the very file it claims to fix is worse than emitting no patch.
    original = lines[match_index]
    indent = original[: len(original) - len(original.lstrip())]

    # Three lines of context either side (the git default), clamped to the file.
    start = max(0, match_index - 3)
    end = min(len(lines), match_index + 4)

    hunk: list[str] = []
    for index in range(start, end):
        if index == match_index:
            hunk.append(f"-{lines[index]}")
            hunk.append(f"+{indent}{new_line}")
        else:
            hunk.append(f" {lines[index]}")

    header = f"@@ -{start + 1},{end - start} +{start + 1},{end - start} @@"
    return "\n".join([f"--- a/{path}", f"+++ b/{path}", header, *hunk])


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def triage_payload(
    payload: IncidentPayload,
    policy: TriagePolicy | None = None,
    manifest_provider: ManifestProvider | None = None,
) -> TriageOutcome:
    """Triage one incident and return a fully populated response.

    ``manifest_provider`` supplies the GitOps manifest text used to build and
    check a Tier-1 patch. Without it the engine still triages, but declines to
    emit a patch, because it cannot then satisfy I-B2 (``patch_validated``
    requires that the patch applies to the real file).
    """
    started = time.perf_counter()
    active_policy = policy or TriagePolicy()

    severity = _severity_for(payload)
    evidence = prompt.evidence_lines(payload)

    # -- Classification -----------------------------------------------------
    # Ordered by specificity. An unrecognised incident falls through to UNKNOWN
    # rather than being forced into a bucket it does not belong in.
    if payload.reason is Reason.OOM_KILLED:
        classification = Classification.RESOURCE_EXHAUSTION
        rationale = prompt.memory_recalibration_rationale(payload)
    elif prompt.looks_like_dependency_fault(payload):
        classification = Classification.DEPENDENCY_FAILURE
        rationale = prompt.dependency_rationale(payload)
    elif payload.reason is Reason.CRASH_LOOP_BACKOFF or (
        prompt.looks_like_configuration_fault(payload)
    ):
        classification = Classification.CONFIGURATION_ERROR
        rationale = prompt.configuration_rationale(payload)
    else:
        classification = Classification.UNKNOWN
        rationale = prompt.escalation_rationale(payload, Classification.UNKNOWN)

    # -- Tier routing precedes any remediation ------------------------------
    admissible, reasons = _tier1_predicates(payload, classification, active_policy)
    if not admissible:
        latency_ms = int((time.perf_counter() - started) * 1000)
        return TriageOutcome(
            response=_tier2_response(
                payload,
                classification,
                severity,
                (
                    active_policy.unknown_confidence
                    if classification is Classification.UNKNOWN
                    else active_policy.tier2_confidence
                ),
                rationale,
                latency_ms,
                (
                    TriageStatus.UNKNOWN
                    if classification is Classification.UNKNOWN
                    else TriageStatus.ESCALATED
                ),
            ),
            tier=BlastRadiusTier.TIER_2_ARCHITECTURAL,
            reasons=reasons,
            latency_ms=latency_ms,
        )

    # -- Tier 1: the memory-limit recalibration -----------------------------
    memory_limit = payload.resource_limits.memory_limit
    assert memory_limit is not None  # guaranteed by _tier1_predicates

    current_bytes = _parse_quantity_to_bytes(memory_limit)
    if current_bytes is None:
        latency_ms = int((time.perf_counter() - started) * 1000)
        return TriageOutcome(
            response=_tier2_response(
                payload,
                classification,
                severity,
                active_policy.tier2_confidence,
                prompt.escalation_rationale(payload, classification),
                latency_ms,
                TriageStatus.ESCALATED,
            ),
            tier=BlastRadiusTier.TIER_2_ARCHITECTURAL,
            reasons=reasons
            + ["memory limit could not be parsed into bytes, so no safe target exists"],
            latency_ms=latency_ms,
        )

    new_limit = _format_bytes(
        max(
            current_bytes * active_policy.memory_multiplier,
            active_policy.min_memory_bytes,
        )
    )

    patch: str | None = None
    if manifest_provider is None:
        reasons.append(
            "no manifest provider supplied, so the patch cannot be checked "
            "against the target file (I-B2) and none is emitted"
        )
    else:
        manifest_text = manifest_provider.read_manifest(TARGET_MANIFEST)
        if manifest_text is None:
            reasons.append("target manifest is unreadable, so no patch is emitted")
        else:
            candidate = build_memory_patch(
                manifest_text, memory_limit, new_limit, TARGET_MANIFEST
            )
            if candidate is None:
                reasons.append(
                    f'the manifest has no line matching memory: "{memory_limit}", so '
                    "the patch target cannot be proven and no patch is emitted"
                )
            else:
                patch = candidate

    if patch is None:
        latency_ms = int((time.perf_counter() - started) * 1000)
        return TriageOutcome(
            response=_tier2_response(
                payload,
                classification,
                severity,
                active_policy.tier2_confidence,
                prompt.escalation_rationale(payload, classification),
                latency_ms,
                TriageStatus.ESCALATED,
            ),
            tier=BlastRadiusTier.TIER_2_ARCHITECTURAL,
            reasons=reasons,
            latency_ms=latency_ms,
        )

    latency_ms = int((time.perf_counter() - started) * 1000)
    response = TriageResponse(
        schema_version=SCHEMA_VERSION,
        incident_id=payload.incident_id,
        status=TriageStatus.TRIAGED,
        classification=Classification.RESOURCE_EXHAUSTION,
        severity=severity,
        confidence=active_policy.tier1_confidence,
        blast_radius_tier=BlastRadiusTier.TIER_1_TOIL,
        root_cause=RootCause(
            summary=rationale,
            evidence=evidence,
            affected_scope=_affected_scope(payload),
        ),
        remediation=Remediation(
            summary=(
                f"Raise the {payload.container_name!r} memory limit from "
                f"{memory_limit} to {new_limit}. No code or image change required."
            ),
            risk_level=RiskLevel.LOW,
            target_manifest=TARGET_MANIFEST,
            git_patch=patch,
            # I-B2 holds for the mechanical edit: the patch was constructed
            # from the file's actual bytes, and the schema re-validates it as a
            # conforming unified diff. A full `git apply --check` against a
            # checkout is Milestone 2.5.
            patch_validated=True,
        ),
        verification_policy=_verification_policy(BlastRadiusTier.TIER_1_TOIL),
        rca_markdown=prompt.rca_markdown(
            payload,
            Classification.RESOURCE_EXHAUSTION,
            BlastRadiusTier.TIER_1_TOIL,
            rationale,
            evidence,
        ),
        analysis_latency_ms=latency_ms,
        agent_version=AGENT_VERSION,
    )
    return TriageOutcome(
        response=response,
        tier=BlastRadiusTier.TIER_1_TOIL,
        reasons=reasons,
        latency_ms=latency_ms,
    )
