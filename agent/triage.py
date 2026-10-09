"""Triage orchestration: classify, route, remediate (ARCH §5).

Turns a scrubbed :class:`~models.IncidentPayload` into a fully populated
:class:`~models.TriageResponse` by composing three modules that each own one
question:

======================  ====================================================
:mod:`classifier`        What is wrong, and may we act on it automatically?
:mod:`patch`             Given a proven target, what exactly is the diff?
:mod:`prompt`            What do we tell the human, in prose?
:mod:`warroom`           What a Tier-2 responder is handed at 3am.
this module              How do those answers become a Contract B response?
======================  ====================================================

Three properties this module is responsible for:

1. **Tier selection precedes remediation.** The tier is decided by
   :mod:`classifier` from observable facts before a diff is considered, so a
   change can never influence its own authorisation.
2. **Uncertainty is a first-class outcome.** ``UNKNOWN`` + ``HIGH`` + Tier-2 +
   an empty patch is a *success*. Most incidents a naive agent would "fix"
   belong here.
3. **The patch is derived, never authored.** It is a mechanical edit to a line
   that was structurally located in the real manifest, and it is applied back
   against that same manifest before ``patch_validated`` is set. If any of that
   cannot be done, the engine emits no patch at all.

Timing uses :func:`time.perf_counter` exclusively (AGENTS.md §3.3). A wall
clock would be wrong here: a monotonic source cannot jump backwards when the
host clock is stepped by NTP during an incident, which would yield a negative
latency.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Final

import classifier
import llm
import patch as patch_engine
import prompt
import providers
import rescan
import warroom
from classifier import (
    ManifestProvider,
    StaticManifestProvider,
    TierPolicy,
    TARGET_MANIFEST,
    unreadable_manifest_provider,
)
from warroom import WarRoomDispatch
from models import (
    SCHEMA_VERSION,
    BlastRadiusTier,
    Classification,
    IncidentPayload,
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
    "ManifestProvider",
    "TARGET_MANIFEST",
    "StaticManifestProvider",
    "TriagePolicy",
    "TriageOutcome",
    "WarRoomDispatch",
    "triage_payload",
    "unreadable_manifest_provider",
]

#: Build-stamped by the packaging pipeline (ARCH §5.1).
AGENT_VERSION: Final[str] = "0.1.0"

# ARCH §5.2 caps observation at 1800s and floors it at 60s.
_TIER_1_WATCH_SECONDS: Final[int] = 300
_TIER_1_UPTIME_MINIMUM: Final[int] = 240
_TIER_2_WATCH_SECONDS: Final[int] = 900
_TIER_2_UPTIME_MINIMUM: Final[int] = 600


@dataclass(frozen=True)
class TriagePolicy:
    """Routing thresholds and remediation sizing.

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

    @property
    def tier_policy(self) -> TierPolicy:
        """The routing-relevant projection.

        The router is handed only what routing needs, which keeps it from being
        able to read a remediation-sizing constant and start deciding tiers on
        it. The narrowness is the point, not a convenience.
        """
        return TierPolicy(max_restarts=self.max_restarts)


@dataclass
class TriageOutcome:
    """The response plus the routing decision that produced it.

    ``reasons`` is returned alongside the response rather than hidden inside it,
    so a caller can log *why* a decision was made. It is the audit trail a
    War-Room reviewer needs and the first thing to inspect when a routing rule
    looks wrong.

    ``dispatch`` is the Tier-2 War-Room artefact (ARCH §2.6.1). It is ``None``
    for Tier-1, and non-``None`` for **every** Tier-2 outcome - including one
    reached by an unhandled precondition rather than by the tier router itself.
    It is not a field on :class:`~models.TriageResponse` because ARCH §5 fixes
    that schema, and adding a field to it is a breaking contract change (§10).
    It is also not a new HTTP endpoint, because §4 fixes those too. The
    dispatch is therefore carried in-process and *rendered into* the response's
    existing ``rca_markdown``, which is where a responder actually reads it.
    """

    response: TriageResponse
    tier: BlastRadiusTier
    reasons: list[str] = field(default_factory=list)
    latency_ms: int = 0
    dispatch: WarRoomDispatch | None = None


#: Binary suffixes ordered **largest first**.
#:
#: The order is load-bearing, not cosmetic. Iterating smallest-first made every
#: byte count divisible by 1024 render as Ki, so a 256Mi limit doubled to
#: "524288Ki" rather than "512Mi" - a correct number in a form no engineer would
#: write, and one a reviewer would have to stop and decode.
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


def _rescanned_rca(
    payload: IncidentPayload,
    classification: Classification,
    tier: BlastRadiusTier,
    rationale: str,
    evidence: list[str],
) -> str:
    """Render the RCA, then pass the whole document through the ARCH §6 re-scan.

    I-B6. The Go node is the authoritative masking control and this is the
    backstop. It runs over the *rendered* document rather than over individual
    fields, because a secret can be assembled from two fields that are each
    individually innocent.
    """
    rendered = prompt.rca_markdown(payload, classification, tier, rationale, evidence)
    cleaned, _report = rescan.redact(rendered)
    return cleaned[0]


def _narrative_overlay(
    payload: IncidentPayload,
) -> llm.ModelNarrative | None:
    """Ask the model for a narrative, or return None and keep the deterministic one.

    THE MODEL IS NOT AUTHORITATIVE HERE, and the shape of this function is the
    reason. It returns a narrative or it returns nothing: there is no path by
    which a model response replaces the classification, the tier, the risk level,
    the patch, or the verification policy. Those are all decided upstream in
    ARCH §5.3 and are written into the response literal regardless of what comes
    back. Only prose is substitutable.

    Every failure is a fallback, deliberately and without exception:

    * no API key -> None (the shipped default; the agent runs identically)
    * SDK absent -> None
    * transport failure after retries -> None
    * a refusal, a safety block, or malformed output -> None

    The agent has already decided what happened and what to do about it by the
    time this runs, so a model that is slow, down, or compromised costs the
    operator a paragraph - never a verdict, never a patch, never a delay past the
    caller's budget. An RCA that is merely less fluent is a better outcome than
    an RCA that is late.

    Threading note: this is synchronous and runs on the worker's thread, never on
    the event loop (AGENTS.md §3.1), so the ``time`` it spends cannot stall
    ``/healthz`` or ``/readyz``.

    CALL TWICE, ON PURPOSE. :func:`_model_summary` and :func:`_model_rca_section`
    both call this, so a Tier-2 escalation issues at most two model calls and
    pays for the narrative twice. That is a deliberate trade and it is worth
    stating rather than hiding: the alternative was a single call whose result had
    to be threaded through ``_escalate`` into the response constructor, which is
    where an earlier revision lost the long-form text entirely because the
    dispatch render overwrites ``rca_markdown`` after construction. Caching would
    fix the cost and reintroduce the coupling. Two calls cost two tokens of
    latency on a path that is already asynchronous with respect to the operator;
    losing the analysis costs the operator the reason they escalated. If call
    volume ever makes this matter, the fix is a per-request cache keyed on
    ``incident_id`` — not a hidden parameter.
    """
    client = providers.provider_from_env()
    if client is None:
        return None
    try:
        raw = client.complete(llm.build_prompt(payload))
    except llm.ModelOutputError:
        # Deliberately swallowed. The exception type is not logged with its
        # message because provider errors can echo the request, and the request is
        # incident telemetry (AGENTS.md §1: sanitise before egress).
        return None
    try:
        return llm.decode_narrative(raw)
    except llm.ModelOutputError:
        return None


#: ``RootCause.summary`` requires 20 characters, so anything shorter than this is
#: unusable as a summary regardless of what else is true about it.
MIN_MODEL_SUMMARY_CHARS: Final[int] = 20

#: Ceiling on model prose, matching the looser of the two schema ceilings
#: (``rca_markdown`` allows 20000). Exceeding it would raise during response
#: construction, so it is clipped here instead.
MAX_MODEL_PROSE_CHARS: Final[int] = 20_000


def _prefer_model_prose(model_text: str, fallback: str) -> str:
    """Use the model's prose only when it is actually usable, else ``fallback``.

    Three guards, each tied to a failure that actually happened:

    * **Length floor.** ``RootCause.summary`` requires 20 characters. A short or
      empty narrative must not break response construction - that is precisely how
      the 2026-10-01 live run produced a 500 on a request the agent already had
      the evidence to answer.
    * **Sensitivity.** If the prose trips the re-scan, the fallback wins. A model
      can echo a secret back out of its own context, and this is the last point
      before the response leaves the process.
    * **Length ceiling.** ``rca_markdown`` allows 20000 characters; a longer
      model reply would raise during construction. Clipped rather than rejected -
      a truncated paragraph is still useful, and a 500 is not.

    Passing ``""`` as the fallback is legitimate and returns ``""``, so a caller
    can treat a falsy result as "the model offered nothing usable".
    """
    candidate = model_text.strip()
    if len(candidate) < MIN_MODEL_SUMMARY_CHARS:
        return fallback
    if len(candidate) > MAX_MODEL_PROSE_CHARS:
        candidate = candidate[: MAX_MODEL_PROSE_CHARS - 3].rstrip() + "..."
    cleaned, report = rescan.redact(candidate)
    if not report.clean or not cleaned[0].strip():
        return fallback
    return cleaned[0]


def _model_summary(payload: IncidentPayload, deterministic_rationale: str) -> str:
    """The model's one-line root cause, or the deterministic rationale.

    Split from the long-form prose because the two are consumed at different
    points in different functions, and conflating them is what made an earlier
    revision lose the long-form text: `_escalate` overwrites ``rca_markdown``
    wholesale when it renders the war-room dispatch, so anything appended inside
    the response constructor is discarded. The summary survived that overwrite only
    because it is a separate field - which is why the two are now fetched
    separately and appended separately.
    """
    narrative = _narrative_overlay(payload)
    if narrative is None:
        return deterministic_rationale
    return _prefer_model_prose(narrative.summary, deterministic_rationale)


def _model_rca_section(payload: IncidentPayload) -> str | None:
    """The model's long-form analysis, or ``None``.

    Called from :func:`_escalate` AFTER the dispatch render, because that render
    replaces ``rca_markdown`` outright. Appending before it loses the text
    silently - the request still returns 200, the model is still billed, and the
    operator simply never sees the analysis.
    """
    narrative = _narrative_overlay(payload)
    if narrative is None:
        return None
    return _prefer_model_prose(narrative.rca_markdown, "") or None


def _tier2_response(
    payload: IncidentPayload,
    result: classifier.ClassificationResult,
    severity: Severity,
    confidence: float,
    latency_ms: int,
) -> TriageResponse:
    """Build a Tier-2 response. Never carries a patch (I-B1).

    ``status`` is derived from the classification, not from the tier's eventual
    outcome: every response here is Tier-2, so a ``RESOURCE_EXHAUSTION``
    incident that escalated for want of a readable manifest must still report
    ``ESCALATED``. Reporting ``TRIAGED`` beside an empty patch would hand a
    consumer a verdict that contradicts itself.
    """
    status = (
        TriageStatus.UNKNOWN
        if result.classification is Classification.UNKNOWN
        else TriageStatus.ESCALATED
    )
    evidence = prompt.evidence_lines(payload)
    summary = _model_summary(payload, result.rationale)
    return TriageResponse(
        schema_version=SCHEMA_VERSION,
        incident_id=payload.incident_id,
        status=status,
        classification=result.classification,
        severity=severity,
        confidence=confidence,
        blast_radius_tier=BlastRadiusTier.TIER_2_ARCHITECTURAL,
        root_cause=RootCause(
            summary=summary,
            evidence=evidence,
            affected_scope=classifier.affected_scope(payload),
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
        # NOTE: this markdown is DISCARDED and re-rendered by `_escalate` with the
        # war-room dispatch. It is built here only because the dispatch renderer
        # reads it. The model's long-form prose is appended in `_escalate`, after
        # that render - see the comment there. An earlier revision appended here
        # and lost it, which is exactly the kind of silent total failure worth
        # writing down.
        #
        # The summary passed to the renderer is `summary`, not `result.rationale`,
        # so the model's account also appears in the deterministic body.
        rca_markdown=_rescanned_rca(
            payload,
            result.classification,
            BlastRadiusTier.TIER_2_ARCHITECTURAL,
            summary,
            evidence,
        ),
        analysis_latency_ms=latency_ms,
        agent_version=AGENT_VERSION,
    )


def _compose_rca(deterministic: str, model_section: str | None) -> str:
    """Append the model's account to the deterministic document, re-scanned.

    The re-scan runs over the COMBINED text, not over the model section alone. A
    secret can be assembled from a model paragraph and a deterministic line that
    are each individually innocent, which is the reason I-B6 scans the rendered
    document in the first place.
    """
    if not model_section:
        return deterministic
    combined = (
        f"{deterministic}\n\n"
        "### Model analysis\n\n"
        "_Generated by the configured model from the scrubbed evidence above. "
        "Advisory only; the verdict above is deterministic and was not produced "
        "by the model._\n\n"
        f"{model_section}"
    )
    cleaned, _report = rescan.redact(combined)
    return cleaned[0]


def _escalate(
    payload: IncidentPayload,
    result: classifier.ClassificationResult,
    severity: Severity,
    confidence: float,
    reasons: list[str],
    started: float,
) -> TriageOutcome:
    """Fail closed to Tier-2, recording why.

    Every path that lands here also **emits a War-Room dispatch**, which is what
    ROADMAP §2.6.1 asks for and what the classification ``TIER_2_ARCHITECTURAL``
    promises a human. The dispatch is not decoration attached to a tier label:
    it is the deliverable, and it is rendered into ``rca_markdown`` so it
    travels on the wire a responder is already reading.

    That last step is the reason this is not merely a log line. Until it,
    ``warroom.build_dispatch`` had **no production caller at all** - it was
    exercised only by ``agent/tests/test_milestone2.py`` - so a Tier-2 response
    was the only artefact an escalation ever produced. That response cannot
    carry ``do_not_apply`` (ARCH §5.1 has no field for it, and adding one is a
    breaking schema change per ARCH §10), so the one marker ARCH §2.6.2 calls
    "a field a channel renderer cannot drop" existed nowhere an operator could
    reach. Rendering the dispatch into the RCA puts it there without inventing
    a field, a path or an endpoint.
    """
    latency_ms = int((time.perf_counter() - started) * 1000)
    response = _tier2_response(payload, result, severity, confidence, latency_ms)
    dispatch = warroom.build_dispatch(payload, response, reasons)
    # Assignment rather than `model_copy(update=...)`: the model sets
    # `validate_assignment`, so this re-runs the field validators and the
    # I-B1 model validator against the rendered text. `model_copy` would not,
    # and a field that is re-validated by an update but not by a construction
    # is a field nobody can reason about.
    #
    # This render REPLACES rca_markdown wholesale. Anything the model contributed
    # inside _tier2_response is therefore discarded here, and an earlier revision
    # of this function appended it too early and lost it: the summary survived only
    # because it is a different field. The model section is appended after this
    # assignment instead, so the dispatch - which carries the DO-NOT-APPLY marker
    # and the escalation reasons - is never at risk of being overwritten by, or
    # overwriting, model prose.
    response.rca_markdown = warroom.render_markdown(dispatch)
    response.rca_markdown = _compose_rca(
        response.rca_markdown,
        _model_rca_section(payload),
    )
    return TriageOutcome(
        response=response,
        tier=BlastRadiusTier.TIER_2_ARCHITECTURAL,
        reasons=reasons,
        latency_ms=latency_ms,
        dispatch=dispatch,
    )


def _build_remediation_diff(
    payload: IncidentPayload,
    policy: TriagePolicy,
    provider: ManifestProvider,
) -> tuple[str | None, str | None, list[str]]:
    """Produce the Tier-1 diff and the value it installs, or explain why not.

    Returns ``(diff, new_limit, reasons)``. ``diff`` is ``None`` on every path
    where the target could not be proven or the result could not be verified,
    and ``reasons`` says which. A caller that receives ``None`` must escalate.
    """
    reasons: list[str] = []

    # No configured target, so there is nothing to read and nothing to diff
    # against. Checked here rather than left to the provider: the provider would
    # answer `None` for the empty path too, so both routes escalate, but only
    # this one can say *why* in terms an operator can act on. "target manifest is
    # unreadable" is the answer to a filesystem question, and the two look the
    # same from outside while needing different fixes - populate the checkout,
    # or set the variable.
    if not TARGET_MANIFEST:
        return (
            None,
            None,
            [
                "no patch target is configured: SREK3S_TARGET_MANIFEST is unset "
                "or malformed and the agent ships no default, so there is no "
                "manifest this process is permitted to patch (I-B2)"
            ],
        )

    memory_limit = payload.resource_limits.memory_limit
    if memory_limit is None:
        return (
            None,
            None,
            ["no memory limit is set, so there is no recalibration target"],
        )

    manifest_text = provider.read_manifest(TARGET_MANIFEST)
    if manifest_text is None:
        return (
            None,
            None,
            [
                "target manifest is unreadable, so no patch can be derived or checked "
                "(I-B2)"
            ],
        )

    # Structural location: the named container's resources.limits.memory.
    # Anything ambiguous returns None and we escalate.
    target = patch_engine.find_container_memory_limit(
        manifest_text, payload.container_name
    )
    if target is None:
        return (
            None,
            None,
            [
                f"could not uniquely locate resources.limits.memory for container "
                f"{payload.container_name!r} in {TARGET_MANIFEST}; the patch target "
                "is ambiguous or absent, so no patch is emitted"
            ],
        )
    if target.value != memory_limit:
        return (
            None,
            None,
            [
                f"manifest limit {target.value!r} does not match the reported limit "
                f"{memory_limit!r}; the manifest has drifted from the incident, so "
                "no patch is emitted"
            ],
        )

    current_bytes = _parse_quantity_to_bytes(memory_limit)
    if current_bytes is None:
        return (
            None,
            None,
            [
                f"memory limit {memory_limit!r} cannot be converted to an exact byte "
                "count, so no safe patch target exists"
            ],
        )
    new_limit = _format_bytes(
        max(current_bytes * policy.memory_multiplier, policy.min_memory_bytes)
    )

    diff = patch_engine.build_diff(manifest_text, target, new_limit, TARGET_MANIFEST)

    # I-B6 / ARCH §6: a diff is refused, never redacted. Rewriting a line inside a
    # diff would break the artifact - the hunk header's counts would no longer
    # describe its body - and a credential inside a GitOps PR would be copied into
    # every clone of the repository. A leak here is a Tier-2 outcome.
    try:
        rescan.assert_clean(diff)
    except rescan.SecretLeakError as leak:
        return (
            None,
            None,
            [
                f"the generated diff matched masking rule(s) "
                f"{', '.join(leak.rule_ids_found)}; a patch carrying a secret is "
                "refused rather than redacted, so no patch is emitted (ROADMAP 2.5.8)"
            ],
        )

    # I-B2, in full: a structural round-trip *and* `git apply --check`. Both must
    # pass before the patch may be emitted, and neither substitutes for the other.
    verification = patch_engine.verify_patch(
        manifest_text,
        diff,
        target,
        new_limit,
        TARGET_MANIFEST,
        container_name=payload.container_name,
        expected_old=memory_limit,
        # Binds the applicability check to the file the agent actually read. With a
        # checkout present, `git apply --check` runs against the bytes on disk and
        # refuses if they are not the bytes `manifest_text` came from; a diff that
        # applies to a truncated read is no longer reported as `patch_validated`.
        checkout_root=classifier.checkout_root_of(provider),
    )
    if not verification.ok:
        return (
            None,
            None,
            [
                "I-B2 verification failed, so the patch is discarded rather than "
                "emitted unvalidated (ROADMAP 2.5.6): " + verification.reason_text()
            ],
        )

    reasons.append(
        f"verified diff raises {memory_limit} to {new_limit} at "
        f"{target.indent.count(' ')} spaces of indentation"
    )
    reasons.append(
        "I-B2 satisfied: positional round-trip, YAML AST check and "
        "`git apply --check` all passed"
    )
    return diff, new_limit, reasons


def triage_payload(
    payload: IncidentPayload,
    policy: TriagePolicy | None = None,
    manifest_provider: ManifestProvider | None = None,
) -> TriageOutcome:
    """Triage one incident and return a fully populated response.

    ``manifest_provider`` supplies the GitOps manifest text used to locate and
    verify a Tier-1 patch. Without it the engine still triages, but declines to
    emit a patch, because it cannot then satisfy I-B2 (``patch_validated``
    requires that the patch applies to the real file).
    """
    started = time.perf_counter()
    active_policy = policy or TriagePolicy()

    # 1. What is wrong?
    result = classifier.classify(payload)
    severity = classifier.severity_for(payload)

    # 2. May we act automatically? Deny-by-default.
    decision = classifier.route(
        classifier.TierEvidence(
            payload=payload, result=result, policy=active_policy.tier_policy
        )
    )
    reasons = list(decision.reasons)

    if not decision.is_tier_one:
        confidence = (
            active_policy.unknown_confidence
            if result.classification is Classification.UNKNOWN
            else active_policy.tier2_confidence
        )
        return _escalate(payload, result, severity, confidence, reasons, started)

    # 3. Only now, with a tier already decided, is a patch considered.
    if manifest_provider is None:
        reasons.append(
            "no manifest provider supplied, so the patch cannot be checked "
            "against the target file (I-B2) and none is emitted"
        )
        return _escalate(
            payload,
            result,
            severity,
            active_policy.tier2_confidence,
            reasons,
            started,
        )

    diff, new_limit, patch_reasons = _build_remediation_diff(
        payload, active_policy, manifest_provider
    )
    reasons.extend(patch_reasons)
    if diff is None or new_limit is None:
        return _escalate(
            payload,
            result,
            severity,
            active_policy.tier2_confidence,
            reasons,
            started,
        )

    latency_ms = int((time.perf_counter() - started) * 1000)
    evidence = prompt.evidence_lines(payload)
    response = TriageResponse(
        schema_version=SCHEMA_VERSION,
        incident_id=payload.incident_id,
        status=TriageStatus.TRIAGED,
        classification=Classification.RESOURCE_EXHAUSTION,
        severity=severity,
        confidence=active_policy.tier1_confidence,
        blast_radius_tier=BlastRadiusTier.TIER_1_TOIL,
        root_cause=RootCause(
            summary=result.rationale,
            evidence=evidence,
            affected_scope=classifier.affected_scope(payload),
        ),
        remediation=Remediation(
            summary=(
                f"Raise the {payload.container_name!r} memory limit from "
                f"{payload.resource_limits.memory_limit} to {new_limit}. "
                "No code or image change required."
            ),
            risk_level=RiskLevel.LOW,
            target_manifest=TARGET_MANIFEST,
            git_patch=diff,
            # I-B2 is satisfied to the strongest extent available without a
            # GitOps checkout: the target was structurally located in the real
            # manifest text, the diff was applied back against that same text,
            # and the result was asserted to contain the new limit and not the
            # old one. A real `git apply --check` against a checkout is
            # ROADMAP 2.5.5; until then this is a genuine verification, not a
            # bare assertion.
            patch_validated=True,
        ),
        verification_policy=_verification_policy(BlastRadiusTier.TIER_1_TOIL),
        rca_markdown=_rescanned_rca(
            payload,
            Classification.RESOURCE_EXHAUSTION,
            BlastRadiusTier.TIER_1_TOIL,
            result.rationale,
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
