"""Deterministic classification and tier routing (ARCH §5.3, ROADMAP §2.3).

This module answers two questions and nothing else:

1. **What is wrong?** :func:`classify` maps observed facts to a
   :class:`~models.Classification`.
2. **May we act on it automatically?** :func:`route` applies the ARCH §5.3
   conjunction and returns a :class:`RoutingDecision`.

It builds no response objects and generates no diffs. Keeping routing free of
both is what makes the safety property auditable: the decision can be read, and
tested, without a schema, a manifest, or a patch in the picture.

Deny-by-default
---------------
:func:`route` returns Tier-2 unless **every** precondition holds. Each one is a
named, individually testable predicate, and all are evaluated even after one
fails so the returned reasons are a complete account of the decision rather
than the first failure. A reviewer asking "why was this escalated?" gets every
reason, not one.

Why the router cannot read ``confidence``
-----------------------------------------
ROADMAP 2.3.5 requires that a model's ``confidence`` value is never read by the
router. Rather than assert that in a test, :func:`route` is *typed so it cannot
be*: neither :func:`route` nor the :class:`TierEvidence` it consumes carries a
confidence field. There is no parameter to pass one through, and no attribute to
read one from. A future change that tried to reintroduce that coupling would
fail type checking, not a test - which is the stronger guarantee.

Confidence is assigned afterwards, by :mod:`triage`, from the tier that was
already decided. Ordering it this way is what stops a well-calibrated-looking
number from arguing its way into a tier it has not earned.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Final, Protocol

import prompt
from models import (
    AffectedScope,
    BlastRadiusTier,
    Classification,
    IncidentPayload,
    Reason,
    RiskLevel,
    Severity,
)

__all__ = [
    "TARGET_MANIFEST",
    "ManifestProvider",
    "RemedyShape",
    "TierEvidence",
    "TierPolicy",
    "ClassificationResult",
    "RoutingDecision",
    "StaticManifestProvider",
    "unreadable_manifest_provider",
    "classify",
    "route",
    "PRECONDITIONS",
]

#: The single manifest Tier-1 remediation is permitted to target.
#:
#: Hard-coded rather than derived from the pod or container name. ARCH §5.3
#: enumerates the permitted Tier-1 remedy shapes; deriving the patch target from
#: incident-supplied data would let a payload choose which file this system is
#: willing to propose a change to.
TARGET_MANIFEST: Final[str] = "deploy/payments/checkout-api.yaml"

#: Cluster events indicating node-level rather than container-level pressure.
#:
#: A container OOMKill and a node eviction are different faults. An OOMKill means
#: the container's own cgroup limit was reached; an eviction means the *node* ran
#: out of resources, which implicates every container on it. This distinction is
#: the observable basis for the sibling-health inference.
NODE_LEVEL_EVENTS: Final[frozenset[str]] = frozenset(
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


class RemedyShape(str, Enum):
    """The shape of remediation being proposed (ARCH §5.3 allow-list).

    Only ``MEMORY_LIMIT_RECALIBRATION`` is enumerated as Tier-1. ``UNSPECIFIED``
    is the default for every other classification, and is a distinct value rather
    than ``None`` so "no remedy shape" cannot be confused with "the shape is
    unknown but maybe fine".
    """

    MEMORY_LIMIT_RECALIBRATION = "MEMORY_LIMIT_RECALIBRATION"
    UNSPECIFIED = "UNSPECIFIED"


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


def unreadable_manifest_provider() -> ManifestProvider:
    """A provider that reports every manifest as unreadable.

    This is the default for the running service, and it is what makes the
    fail-closed path the *normal* one rather than a corner case: until a real
    GitOps checkout is wired in (ROADMAP §2.5), the service escalates rather than
    proposing changes it cannot verify.
    """

    class _Unreadable:
        def read_manifest(self, path: str) -> None:
            return None

    return _Unreadable()


class StaticManifestProvider:
    """An in-memory provider, used by tests and by ROADMAP §2.5.

    Holds manifest text in a dict rather than touching the filesystem, so the
    triage engine performs no I/O and stays trivially testable.
    """

    def __init__(self, manifests: dict[str, str]) -> None:
        self._manifests = dict(manifests)

    def read_manifest(self, path: str) -> str | None:
        return self._manifests.get(path)


@dataclass(frozen=True)
class TierPolicy:
    """Thresholds governing tier routing (ARCH §5.3).

    Frozen so a policy cannot be mutated mid-incident, which would make the
    decision non-reproducible during review.
    """

    #: ARCH §5.3 default. Above this a restart loop is a systemic fault, not the
    #: bounded thrash a memory-limit increase addresses.
    max_restarts: int = 5


@dataclass(frozen=True)
class ClassificationResult:
    """What :func:`classify` concluded, before any tier is considered.

    Carries no tier, no confidence and no patch. Classification is a statement
    about the evidence; authorisation is a separate decision made afterwards.

    It also deliberately carries no transport ``status``. Whether a response
    reports TRIAGED or ESCALATED depends on the tier, which is not decided yet;
    an earlier version put a ``status_hint`` here, and escalating a
    RESOURCE_EXHAUSTION incident then reported ``TRIAGED`` beside an empty
    patch. The field looked harmless and was a second source of truth for a
    value that :mod:`triage` computes once the tier is known.
    """

    classification: Classification
    rationale: str
    remedy_shape: RemedyShape
    risk_level: RiskLevel


@dataclass(frozen=True)
class TierEvidence:
    """The facts :func:`route` is permitted to consider.

    **There is deliberately no ``confidence`` field here.** See the module
    docstring: absence of the field is what makes ROADMAP 2.3.5 structural
    rather than merely asserted.
    """

    payload: IncidentPayload
    result: ClassificationResult
    policy: TierPolicy


@dataclass(frozen=True)
class RoutingDecision:
    """The tier decision and the complete audit trail behind it."""

    tier: BlastRadiusTier
    reasons: tuple[str, ...]
    satisfied: tuple[str, ...]

    @property
    def is_tier_one(self) -> bool:
        return self.tier is BlastRadiusTier.TIER_1_TOIL


# ---------------------------------------------------------------------------
# Blast radius
# ---------------------------------------------------------------------------


def node_pressure_signals(payload: IncidentPayload) -> list[str]:
    """Node-level event reasons present in the incident's event batch."""
    return sorted(
        {
            event.reason
            for event in payload.cluster_events
            if event.reason in NODE_LEVEL_EVENTS
        }
    )


def siblings_healthy(payload: IncidentPayload) -> bool:
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
    ``False``. ROADMAP §2.4's sandbox replaces this with a direct observation;
    until then it is the strongest statement the payload supports.
    """
    if payload.reason is not Reason.OOM_KILLED:
        return False
    return not node_pressure_signals(payload)


def affected_scope(payload: IncidentPayload) -> AffectedScope:
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
        sibling_containers_healthy=siblings_healthy(payload),
    )


def severity_for(payload: IncidentPayload) -> Severity:
    """Map observed facts to a severity, conservatively."""
    if payload.restart_count >= 5:
        return Severity.SEV2
    if payload.restart_count >= 3:
        return Severity.SEV3
    return Severity.SEV4


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------


def classify(payload: IncidentPayload) -> ClassificationResult:
    """Map a scrubbed payload to a classification.

    Ordered by specificity, and the ``reason`` field outranks log signal. An
    unrecognised incident falls through to ``UNKNOWN`` rather than being forced
    into a bucket it does not belong in - ``UNKNOWN`` is a legitimate outcome,
    not a failure.

    ``risk_level`` is HIGH for everything that is not an enumerated Tier-1 shape.
    That is not emphasis: ARCH §5.1 states HIGH forces Tier-2, so a MEDIUM risk
    on a non-allow-listed remedy would contradict the routing this result feeds.
    """
    if payload.reason is Reason.OOM_KILLED:
        return ClassificationResult(
            classification=Classification.RESOURCE_EXHAUSTION,
            rationale=prompt.memory_recalibration_rationale(payload),
            remedy_shape=RemedyShape.MEMORY_LIMIT_RECALIBRATION,
            risk_level=RiskLevel.LOW,
        )
    if prompt.looks_like_dependency_fault(payload):
        return ClassificationResult(
            classification=Classification.DEPENDENCY_FAILURE,
            rationale=prompt.dependency_rationale(payload),
            remedy_shape=RemedyShape.UNSPECIFIED,
            risk_level=RiskLevel.HIGH,
        )
    # A CrashLoopBackOff reason is a *symptom*, not a root cause. Treating the
    # reason alone as proof of a configuration fault meant every crash-looping
    # incident was classified CONFIGURATION_ERROR, so an incident with no
    # recognisable evidence at all could never reach UNKNOWN - which is exactly
    # backwards from fail-closed. A configuration verdict now requires an actual
    # configuration signal in the scrubbed logs.
    if prompt.looks_like_configuration_fault(payload):
        return ClassificationResult(
            classification=Classification.CONFIGURATION_ERROR,
            rationale=prompt.configuration_rationale(payload),
            remedy_shape=RemedyShape.UNSPECIFIED,
            risk_level=RiskLevel.HIGH,
        )
    return ClassificationResult(
        classification=Classification.UNKNOWN,
        rationale=prompt.escalation_rationale(payload, Classification.UNKNOWN),
        remedy_shape=RemedyShape.UNSPECIFIED,
        risk_level=RiskLevel.HIGH,
    )


# ---------------------------------------------------------------------------
# Tier routing (ARCH §5.3)
# ---------------------------------------------------------------------------


def _check_reason(evidence: TierEvidence) -> str | None:
    if evidence.payload.reason is not Reason.OOM_KILLED:
        return (
            f"reason is {evidence.payload.reason.value}, not OOMKilled; only an "
            "OOMKilled memory recalibration is an enumerated Tier-1 shape"
        )
    return None


def _check_remedy_shape(evidence: TierEvidence) -> str | None:
    shape = evidence.result.remedy_shape
    if shape is not RemedyShape.MEMORY_LIMIT_RECALIBRATION:
        return (
            f"remedy shape {shape.value} is not in the Tier-1 allow-list "
            "(MEMORY_LIMIT_RECALIBRATION)"
        )
    return None


def _check_restart_ceiling(evidence: TierEvidence) -> str | None:
    restarts = evidence.payload.restart_count
    if restarts > evidence.policy.max_restarts:
        return (
            f"restart_count {restarts} exceeds policy max "
            f"{evidence.policy.max_restarts}"
        )
    return None


def _check_single_replica(evidence: TierEvidence) -> str | None:
    scope = affected_scope(evidence.payload)
    if scope.replicas_affected != 1:
        return (
            f"replicas_affected is {scope.replicas_affected}, not 1; a Tier-1 "
            "change is only permitted against a single replica"
        )
    return None


def _check_sibling_health(evidence: TierEvidence) -> str | None:
    if siblings_healthy(evidence.payload):
        return None
    signals = node_pressure_signals(evidence.payload)
    detail = f" (node-level signals: {', '.join(signals)})" if signals else ""
    return "sibling container health could not be proven healthy" + detail


def _check_risk(evidence: TierEvidence) -> str | None:
    if evidence.result.risk_level is RiskLevel.HIGH:
        return "risk_level is HIGH, which ARCH §5.1 forces to Tier-2"
    return None


def _check_patch_target(evidence: TierEvidence) -> str | None:
    if evidence.payload.resource_limits.memory_limit is None:
        return "no memory limit is set, so there is nothing to recalibrate"
    return None


#: The ARCH §5.3 conjunction, in evaluation order.
#:
#: Exposed as data so tests can assert that every named precondition is actually
#: exercised, and so adding one is a deliberate, visible act rather than an edit
#: buried in a conditional. Order is evaluation order only; all are evaluated
#: even after one fails.
PRECONDITIONS: Final[tuple[tuple[str, object], ...]] = (
    ("reason_is_oom_killed", _check_reason),
    ("remedy_shape_is_allow_listed", _check_remedy_shape),
    ("restart_count_within_policy", _check_restart_ceiling),
    ("single_affected_replica", _check_single_replica),
    ("sibling_containers_healthy", _check_sibling_health),
    ("risk_level_not_high", _check_risk),
    ("memory_limit_present", _check_patch_target),
)


def route(evidence: TierEvidence) -> RoutingDecision:
    """Apply the ARCH §5.3 conjunction and return the tier decision.

    Deny-by-default: the result is Tier-2 unless every precondition returns
    ``None``. The reasons tuple is non-empty for exactly the Tier-2 cases, so
    "escalated" and "unexplained" are the same condition and cannot diverge.
    """
    reasons: list[str] = []
    satisfied: list[str] = []

    for name, check in PRECONDITIONS:
        violation = check(evidence)  # type: ignore[operator]
        if violation is None:
            satisfied.append(name)
        else:
            reasons.append(violation)

    if reasons:
        return RoutingDecision(
            tier=BlastRadiusTier.TIER_2_ARCHITECTURAL,
            reasons=tuple(reasons),
            satisfied=tuple(satisfied),
        )
    return RoutingDecision(
        tier=BlastRadiusTier.TIER_1_TOIL,
        reasons=(),
        satisfied=tuple(satisfied),
    )
