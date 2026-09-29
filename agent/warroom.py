"""War-Room dispatch for Tier-2 incidents (ROADMAP §2.6.1, §2.6.2).

A Tier-2 incident gets no patch. It gets a document a responder can act on at
3am: what broke, where, what was observed, what has already been ruled out, and
- stated explicitly - that nothing has been changed and nothing should be applied
blindly.

Why the "do not apply blindly" marker is a first-class field
-------------------------------------------------------------
ARCH §5.1 routes Tier-2 to a human, and a GitOps PR is the normal Tier-1 output.
A responder who receives an RCA next to a diff-shaped artefact will apply it. So
the dispatch carries no diff *and* says so, in a field a channel renderer cannot
drop and an alert rule can key on. Silence is not a safety property here.

Every string is passed through the ARCH §6 re-scan before it leaves
(I-B6). The Go node is the primary control; this is the backstop, and the
dispatch is prose a human reads, so findings are redacted rather than refused.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

import prompt
import rescan
from classifier import affected_scope
from models import (
    BlastRadiusTier,
    Classification,
    IncidentPayload,
    Severity,
    TriageResponse,
    TriageStatus,
)

__all__ = [
    "DO_NOT_APPLY",
    "WarRoomDispatch",
    "build_dispatch",
    "render_markdown",
]

#: The explicit marker. Referenced as a constant rather than inlined so a channel
#: renderer or alert rule can match on it exactly.
DO_NOT_APPLY: Final[str] = (
    "DO NOT APPLY ANY CHANGE FROM THIS DISPATCH. No patch was generated and no "
    "cluster state has been modified. This incident requires human root-cause "
    "analysis."
)


@dataclass(frozen=True)
class WarRoomDispatch:
    """One Tier-2 escalation, ready to hand to a responder."""

    incident_id: str
    schema_version: str
    namespace: str
    pod_name: str
    container_name: str
    classification: Classification
    severity: Severity
    blast_radius_tier: BlastRadiusTier
    status: TriageStatus
    summary: str
    evidence: tuple[str, ...]
    routing_reasons: tuple[str, ...]
    do_not_apply: str
    redaction_rules_triggered: tuple[str, ...]
    analysis_latency_ms: int
    agent_version: str

    @property
    def carries_patch(self) -> bool:
        """Always ``False``. I-B5/I-B1: this artefact cannot express a write."""
        return False

    def to_dict(self) -> dict[str, object]:
        """Structured form, for a webhook or a queue message.

        Deliberately has no ``git_patch``, ``command`` or ``kubectl`` key. The
        CI guard in ``.github/workflows/ci.yaml`` asserts that no contract field
        is capable of expressing a cluster write verb (I-B5); keeping the keys
        out entirely is the belt to that braces.
        """
        return {
            "incident_id": self.incident_id,
            "schema_version": self.schema_version,
            "scope": {
                "namespace": self.namespace,
                "pod": self.pod_name,
                "container": self.container_name,
            },
            "verdict": {
                "classification": self.classification.value,
                "severity": self.severity.value,
                "blast_radius_tier": self.blast_radius_tier.value,
                "status": self.status.value,
            },
            "summary": self.summary,
            "evidence": list(self.evidence),
            "routing_reasons": list(self.routing_reasons),
            "do_not_apply": self.do_not_apply,
            "redaction": {
                "total": len(self.redaction_rules_triggered),
                "rules_triggered": list(self.redaction_rules_triggered),
            },
            "analysis_latency_ms": self.analysis_latency_ms,
            "agent_version": self.agent_version,
        }


def build_dispatch(
    payload: IncidentPayload,
    response: TriageResponse,
    routing_reasons: tuple[str, ...] | list[str] = (),
) -> WarRoomDispatch:
    """Assemble a Tier-2 dispatch, re-scanning every outbound string.

    The re-scan runs over the summary and the evidence together rather than each
    in isolation, because a secret can be assembled across two fields - the
    reason ARCH §6 M3 specifies a cross-line pass.
    """
    scope = affected_scope(payload)
    evidence = tuple(prompt.evidence_lines(payload))

    summary, summary_report = rescan.redact(response.root_cause.summary)
    cleaned_evidence, evidence_report = rescan.redact(*evidence)

    merged = rescan.RescanReport(
        findings=tuple(
            sorted(
                {
                    f.rule_id: f
                    for f in (*summary_report.findings, *evidence_report.findings)
                }.values(),
                key=lambda f: f.rule_id,
            )
        )
    )

    return WarRoomDispatch(
        incident_id=response.incident_id,
        schema_version=response.schema_version,
        namespace=scope.namespace,
        pod_name=payload.pod_name,
        container_name=payload.container_name,
        classification=response.classification,
        severity=response.severity,
        blast_radius_tier=response.blast_radius_tier,
        status=response.status,
        summary=summary[0],
        evidence=cleaned_evidence,
        routing_reasons=tuple(routing_reasons),
        do_not_apply=DO_NOT_APPLY,
        redaction_rules_triggered=tuple(merged.rules_triggered),
        analysis_latency_ms=response.analysis_latency_ms,
        agent_version=response.agent_version,
    )


def render_markdown(dispatch: WarRoomDispatch) -> str:
    """Render for a chat channel or a PR comment.

    Bounded like the RCA: a dispatch that pushes a responder's client out of
    view is a dispatch that did not reach anyone.
    """
    lines = [
        f"## Tier-2 escalation: {dispatch.incident_id}",
        "",
        f"> **{dispatch.do_not_apply}**",
        "",
        "### Verdict",
        "",
        f"- Classification: `{dispatch.classification.value}`",
        f"- Severity: `{dispatch.severity.value}`",
        f"- Tier: `{dispatch.blast_radius_tier.value}`",
        f"- Status: `{dispatch.status.value}`",
        "",
        "### Scope",
        "",
        f"- Namespace: `{dispatch.namespace}`",
        f"- Pod: `{dispatch.pod_name}`",
        f"- Container: `{dispatch.container_name}`",
        "",
        "### Summary",
        "",
        dispatch.summary,
        "",
        "### Evidence",
        "",
    ]
    lines.extend(f"- {item}" for item in dispatch.evidence)
    if dispatch.routing_reasons:
        lines.extend(["", "### Why this escalated", ""])
        lines.extend(f"- {reason}" for reason in dispatch.routing_reasons)
    lines.extend(
        [
            "",
            "### Redaction",
            "",
            (
                "Re-scan found: " + ", ".join(dispatch.redaction_rules_triggered)
                if dispatch.redaction_rules_triggered
                else "Re-scan found no secrets in this dispatch."
            ),
            "",
        ]
    )
    text = "\n".join(lines)
    # Final pass over the whole rendered document, because the headers above are
    # built here and were not part of the field-level scan.
    cleaned, _ = rescan.redact(text)
    return prompt.clip(cleaned[0])
