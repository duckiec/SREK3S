"""Constrained decoding and prompt safety (ROADMAP §2.5.1, §2.5.2; I-B4).

There is no model in Milestone 2's analysis path - ARCH §5.3 keeps tier selection
deterministic and ahead of any model consultation - so this module owns the
*boundary* a model will cross, not a model call. That is the safety-critical
part, and it is fully exercisable without a network: the decoder takes a raw
completion string and either produces a validated :class:`~models.TriageResponse`
or raises.

I-B4 is a hard failure, not a recovery
--------------------------------------
Invariant I-B4: freeform or non-JSON model output is a **fatal** validation
failure. No partial response, no best-effort parse, and above all **no regex
scrape of markdown**. A fence-stripping decoder looks helpful and is dangerous:
it makes the agent's behaviour depend on whether the model happened to wrap its
answer, so two runs of the same incident can produce different-shaped evidence
from the same schema. Fenced input raises :class:`ModelOutputError` here, and
:func:`decode_completion` is the only entry point - there is no lenient variant
to reach for later.

The tier cannot be argued
------------------------
A model may propose prose. It may not propose authority. :func:`reconcile` takes
the decoded response and the deterministic decision and **overrides** the model's
tier, risk, patch and validation flags with the router's. A model that claims
``TIER_1_TOIL`` with a patch for an incident the router escalated is not
silently accepted or silently dropped - it is corrected, and the correction is
returned so the caller can log that the model disagreed.

That is the same reasoning that removes ``confidence`` from the router's inputs
(ROADMAP 2.3.5): a number produced alongside a verdict must not be able to
influence the verdict.
"""

from __future__ import annotations

import json
from typing import Any, Final, Protocol

import prompt
from classifier import RoutingDecision
from models import (
    SCHEMA_VERSION,
    BlastRadiusTier,
    Remediation,
    RiskLevel,
    TriageResponse,
    TriageStatus,
)

__all__ = [
    "CompletionClient",
    "ModelOutputError",
    "TierReconciliation",
    "build_prompt",
    "decode_completion",
    "reconcile",
]


class ModelOutputError(RuntimeError):
    """The completion was not a valid, schema-conforming Contract B document.

    Fatal by design (I-B4). The caller must escalate; it must not retry the same
    prompt expecting a different shape, because a model that produced prose once
    will produce prose again.
    """


class CompletionClient(Protocol):
    """The transport a model would arrive over.

    Declared but deliberately not implemented: Milestone 2 has no model, and
    shipping a speculative HTTP client - with its retry policy, timeout and
    endpoint configuration - would be exactly the unrequested surface AGENTS.md
    §5 warns against. Tests inject a stub that returns a fixed string.
    """

    def complete(self, prompt_text: str) -> str:
        """Return the raw completion text, verbatim."""
        ...


#: Tokens that mean "the model answered in prose". Checked before parsing so the
#: error message can be specific without ever attempting a parse.
_FENCE_TOKENS: Final[tuple[str, ...]] = ("```", "~~~")


def build_prompt(payload: Any) -> str:
    """Build the request for a human-readable RCA narrative.

    Evidence is passed as the structured list :func:`prompt.evidence_lines`
    produces, so the model reasons over values the schema already validated
    rather than over re-serialised prose.
    """
    evidence = "\n".join(f"- {line}" for line in prompt.evidence_lines(payload))
    return (
        "You are assisting an on-call Kubernetes reliability engineer.\n"
        "Return a single JSON object conforming to the SREK3S triage contract.\n"
        "Do not wrap it in markdown. Do not include commentary.\n\n"
        f"Observed evidence:\n{evidence}\n"
    )


def _reject_non_json(raw: str) -> None:
    """Refuse anything that is not bare JSON, before attempting a parse.

    The diagnostic deliberately does **not** quote the offending text. This
    function's output goes straight to a log line, and a model that echoes
    incident content back - which is exactly what a model asked about a payload
    sometimes does - would put that content into the logs verbatim. Naming the
    problem is worth far more than quoting the evidence.
    """
    stripped = raw.strip()
    if not stripped:
        raise ModelOutputError("model returned an empty completion")
    for token in _FENCE_TOKENS:
        if token in raw:
            raise ModelOutputError(
                f"model output contains a markdown fence ({token}); fenced output "
                "is a fatal validation failure, not something to strip (I-B4)"
            )
    if not stripped.startswith("{"):
        # Report the length and the first character's class, not the content.
        raise ModelOutputError(
            f"model output is not a JSON object: it is {len(stripped)} characters "
            f"and does not begin with '{{'. I-B4 forbids scraping a document out "
            "of freeform output"
        )


def decode_completion(raw: str) -> TriageResponse:
    """Validate a raw completion against Contract B, or raise.

    The single entry point for model output. It parses JSON strictly, validates
    the whole document against the schema, and returns the typed response. Any
    deviation raises :class:`ModelOutputError`.
    """
    _reject_non_json(raw)
    try:
        document = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ModelOutputError(f"model output is not valid JSON: {exc.msg}") from exc
    if not isinstance(document, dict):
        raise ModelOutputError(
            f"model output must be a JSON object, got {type(document).__name__}"
        )
    try:
        return TriageResponse.model_validate(document)
    except Exception as exc:  # noqa: BLE001 - any schema failure is fatal
        # Only the first line, and never Pydantic's `input` echo: the echoed
        # value can contain incident content, and this message is logged.
        detail = str(exc).splitlines()[0][:200]
        raise ModelOutputError(f"model output failed Contract B validation: {detail}")


class TierReconciliation:
    """The result of comparing a model's claims against the deterministic router."""

    __slots__ = ("corrected", "response", "tier")

    def __init__(
        self, response: TriageResponse, tier: BlastRadiusTier, corrected: list[str]
    ) -> None:
        self.response = response
        self.tier = tier
        self.corrected = corrected

    @property
    def agreed(self) -> bool:
        return not self.corrected


def reconcile(
    decoded: TriageResponse, decision: RoutingDecision, tier: BlastRadiusTier
) -> TierReconciliation:
    """Replace the model's authority with the router's, and record the difference.

    Every field the model is not entitled to decide is overwritten: the tier,
    the blast-radius consequence of that tier, the patch, whether the patch was
    validated, the risk level, and the transport status. Prose - the RCA, the
    root-cause summary, the evidence list - is kept, because a narrative is the
    one thing a model is here to contribute.

    When the router escalated, I-B1 is enforced structurally rather than by
    trusting the model: ``git_patch`` is set to ``""`` and ``patch_validated`` to
    ``False`` regardless of what arrived.
    """
    corrected: list[str] = []
    updates: dict[str, Any] = {}

    if decoded.blast_radius_tier is not tier:
        corrected.append(
            f"blast_radius_tier: model said {decoded.blast_radius_tier.value}, "
            f"router decided {tier.value}"
        )
        updates["blast_radius_tier"] = tier

    if tier is BlastRadiusTier.TIER_2_ARCHITECTURAL:
        # I-B1, enforced here rather than trusted from the model.
        #
        # These live under `remediation`, not at the top level, so they are
        # carried by the rebuilt Remediation below rather than by `updates`.
        # Putting them in `updates` adds unknown keys to TriageResponse, and the
        # strict model then rejects the whole document - which is how this was
        # caught: the correction was structurally wrong in a way that only a real
        # validation would surface.
        if decoded.remediation.git_patch != "":
            corrected.append("git_patch cleared: the router escalated to Tier-2")
        if decoded.remediation.patch_validated:
            corrected.append("patch_validated cleared: the router escalated to Tier-2")
        if decoded.remediation.risk_level is not RiskLevel.HIGH:
            corrected.append(
                "risk_level raised to HIGH: ARCH 5.1 forces HIGH on Tier-2"
            )

    expected_status = (
        TriageStatus.ESCALATED
        if tier is BlastRadiusTier.TIER_2_ARCHITECTURAL
        else TriageStatus.TRIAGED
    )
    if decoded.status is not expected_status:
        corrected.append(
            f"status: model said {decoded.status.value}, tier implies "
            f"{expected_status.value}"
        )
        updates["status"] = expected_status

    if not corrected:
        return TierReconciliation(decoded, tier, [])

    payload = decoded.model_dump()
    payload.update(updates)
    # The incident id must round-trip (I-B3); a model cannot rename an incident.
    payload["incident_id"] = decoded.incident_id
    payload["schema_version"] = SCHEMA_VERSION
    if updates.get("blast_radius_tier") is BlastRadiusTier.TIER_2_ARCHITECTURAL:
        payload["remediation"] = Remediation(
            summary=(
                "No automatic change proposed. Escalated for human root-cause "
                "analysis."
            ),
            risk_level=RiskLevel.HIGH,
            target_manifest=decoded.remediation.target_manifest,
            git_patch="",
            patch_validated=False,
        )
    return TierReconciliation(TriageResponse.model_validate(payload), tier, corrected)
