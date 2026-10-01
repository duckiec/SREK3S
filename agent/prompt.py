"""Prompt and rationale templates for the SREK3S Triage Agent.

Kept separate from :mod:`triage` so the decision logic and the human-facing
prose can be reviewed independently, and so a wording change never alters a
tier decision.

**This module contains no model calls.** Milestone 2's triage is fully
deterministic (ARCH §5.3: "Tier selection is deterministic and precedes model
consultation for a fix"). The LLM client arrives with §2.5. What lives here is
the evidence-selection and narrative construction that a constrained-decoding
client will later consume, written now so the deterministic path and the model
path share one description of what the evidence actually says.

The one thing this module must never do is *overstate* certainty. Every
rationale is assembled from values that were actually observed in the payload;
see :func:`evidence_lines`, which takes only the payload and the decision.
"""

from __future__ import annotations

import os
import re
from typing import Final

from models import BlastRadiusTier, Classification, IncidentPayload, Reason

__all__ = [
    "RATIONALE_UNKNOWN",
    "clip",
    "memory_recalibration_rationale",
    "configuration_rationale",
    "dependency_rationale",
    "escalation_rationale",
    "evidence_lines",
    "rca_markdown",
    "MAX_RATIONALE_CHARS",
]

#: Rationales are bounded so a pathological payload cannot produce an
#: unbounded response field. ARCH §5.1 caps the fields that hold them.
MAX_RATIONALE_CHARS: Final[int] = 2_000

RATIONALE_UNKNOWN: Final[str] = (
    "The incident could not be attributed to a known failure mode with the "
    "evidence available in the scrubbed payload. No automatic change is "
    "proposed; a human must determine the root cause."
)

#: Signal words indicating a dependency or network fault rather than a
#: workload-local one.
#:
#: Deliberately strict. An earlier draft included the bare words ``upstream`` and
#: ``timeout``, which made an ordinary line like ``retrying upstream call`` read
#: as a dependency failure - and because the shared sample fixture contains
#: exactly such a line, a crash-loop incident was misclassified as
#: ``DEPENDENCY_FAILURE``. A retry is not a fault; only a *failed* connection is.
#: Both clauses are Tier-2, so the safety property held, but the classification
#: was wrong and would have sent the incident to the wrong war-room queue.
_DEPENDENCY_MARKERS: Final[re.Pattern[str]] = re.compile(
    r"\b(connection (refused|reset|aborted|closed by peer)|"
    r"connect(ion)? timed? ?out|"
    r"no route to host|network (is )?unreachable|"
    r"bad gateway|gateway time-?out|service unavailable|"
    r"\b50[234]\b)\b",
    re.IGNORECASE,
)

#: Signal words that indicate the process itself is failing at startup, which
#: is an application or configuration fault, not resource pressure.
_CONFIG_MARKERS: Final[re.Pattern[str]] = re.compile(
    r"\b(traceback|panic|config(uration)? (error|not found|invalid)|"
    r"entrypoint|exec format error|"
    r"no such file or directory|"
    r"failed to (start|bind|connect to database)|"
    r"migration (failed|error)|exit code 1)\b",
    re.IGNORECASE,
)


def clip(text: str) -> str:
    """Bound any generated prose to :data:`MAX_RATIONALE_CHARS`.

    Public because several modules produce human-facing prose and reaching into a
    private helper for it would be a smell: the bound belongs to the output
    contract, not to one function.
    """
    if len(text) <= MAX_RATIONALE_CHARS:
        return text
    return text[: MAX_RATIONALE_CHARS - 3].rstrip() + "..."


def _joined_logs(payload: IncidentPayload) -> str:
    """All scrubbed log lines as one lowercase-insensitive haystack.

    Bounded by the schema: ARCH §4.1 caps ``scrubbed_logs`` at 200 lines and
    64 KiB, so joining cannot produce an unbounded scan.
    """
    return "\n".join(payload.scrubbed_logs)


#: Whether ``evidence_lines`` includes the log TEXT, or only the metadata
#: describing it. See the note on :func:`evidence_lines` — this is the switch that
#: decides whether attacker-influenced text can reach a model at all.
#:
#: Environment-overridable via SREK3S_LOG_TEXT_EVIDENCE, and the environment is
#: the authority on purpose. Whether an RCA model should see raw log text is a
#: property of the DEPLOYMENT - a cluster where logs are known-trusted and a
#: cluster where any workload can print to stdout are different systems - and not
#: something a source edit should decide for every operator at once. The default
#: stays False because the safe reading is the one that ships.
LOG_TEXT_EVIDENCE_ENV: Final[str] = "SREK3S_LOG_TEXT_EVIDENCE"


#: The hard ceiling on ``RootCause.evidence``, asserted by the schema as
#: ``max_length=20``. This module must not depend on that by accident: emitting
#: 21 lines raises a Pydantic error deep inside response construction, which
#: surfaces as a 500 on a request the agent already had enough evidence to
#: answer. Kept as a named constant so the coupling is visible on both sides.
MAX_EVIDENCE_LINES: Final[int] = 20


def _log_evidence(logs: list[str], budget: int) -> list[str]:
    """The most recent log lines that fit in ``budget``, tail-first.

    TAIL-FIRST IS THE POINT, and it is a correctness decision rather than a
    formatting one. A crashing container writes its traceback LAST: the failing
    line, the exception type, and the timestamp that correlates with the
    restart are all in the final lines, while the first lines are startup
    banners that describe nothing that went wrong. Taking the head would fill the
    budget with the least useful evidence available and drop the traceback - the
    one part of a log an RCA actually needs.

    When lines are dropped, a marker says so and names the count. A silently
    truncated log reads to a model as a complete one, and "the evidence was
    bounded" is itself a fact the model needs.
    """
    if budget <= 0:
        return []
    if len(logs) <= budget:
        return [f"log={line}" for line in logs]
    kept = logs[-budget:]
    # One line of the budget is spent on the marker, so the marker can never
    # itself overflow the ceiling it is reporting.
    return [f"log=[... {len(logs) - budget + 1} earlier lines omitted ...]"] + [
        f"log={line}" for line in kept[1:]
    ]


def log_text_evidence_enabled() -> bool:
    """Whether ``evidence_lines`` emits log text, resolved at CALL time.

    Call time rather than import time so a value injected after start-up is
    honoured, and so a test can flip it without reimporting the module.
    """
    return os.environ.get(LOG_TEXT_EVIDENCE_ENV, "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def evidence_lines(payload: IncidentPayload) -> list[str]:
    """Build the evidence list, one item per fact present in the payload.

    Every entry is traceable to a specific payload field, as ARCH §5.1
    requires. Nothing is inferred: if a field is absent it is not asserted.
    ``reason`` and ``exit_code`` are always present, so the list is never empty
    and the schema's ``min_length=1`` holds without a synthetic filler.

    LOG TEXT IS EXCLUDED BY DEFAULT, and that default is load-bearing.

    This function is what ``llm.build_prompt`` hands to a model, and by default it
    describes the logs (``scrubbed_log_lines=7``) without reproducing them. That
    was not a deliberate privacy win; it was the original shape of the function,
    and it means a prompt-injection payload planted in a stack trace has **no path
    to the model at all**. An injection is data the model cannot see, so no prompt
    engineering is load-bearing against it.

    This is a real limitation, stated rather than hidden: a log is usually the most
    informative evidence available, and a model shown only metadata reasons about
    less than it could. Widening it is therefore
    :func:`log_text_evidence_enabled`, which is off until an operator who has read
    the consequences turns it on. What must hold when they do:

    * the text is the Sentinel-scrubbed ``scrubbed_logs``, never raw container
      output, so a secret is already ``[REDACTED]`` upstream of this module; and
    * the ``system_instruction`` separation in ``llm.py`` becomes load-bearing
      rather than defence-in-depth, because the rules and the attacker-influenced
      text would then occupy the same request.

    Both were verified with a negative control before this flag existed; see
    ``docs/lessons-learned.md``.
    """
    lines: list[str] = [
        f"reason={payload.reason.value}",
        f"exit_code={payload.exit_code!r}",
        f"restart_count={payload.restart_count}",
    ]

    limits = payload.resource_limits
    if limits.memory_limit is not None:
        lines.append(f"memory_limit={limits.memory_limit}")
    else:
        lines.append("memory_limit is unset")
    if limits.memory_working_set_bytes is not None:
        lines.append(f"memory_working_set_bytes={limits.memory_working_set_bytes}")
    if payload.previous_reason:
        lines.append(f"previous_termination_reason={payload.previous_reason}")
    lines.append(f"namespace={payload.namespace}")
    lines.append(f"pod={payload.pod_name}")
    lines.append(f"container={payload.container_name}")
    lines.append(f"scrubbed_log_lines={len(payload.scrubbed_logs)}")
    if payload.cluster_events:
        reasons = sorted({event.reason for event in payload.cluster_events})
        lines.append(f"cluster_event_reasons={','.join(reasons)}")
    if log_text_evidence_enabled():
        lines.extend(
            _log_evidence(payload.scrubbed_logs, MAX_EVIDENCE_LINES - len(lines))
        )
    return lines


def memory_recalibration_rationale(payload: IncidentPayload) -> str:
    """Explain an OOMKilled verdict using only observed values."""
    limits = payload.resource_limits
    working_set = limits.memory_working_set_bytes
    parts = [
        f"Container {payload.container_name!r} in namespace "
        f"{payload.namespace!r} was OOMKilled with exit code 137 "
        f"(SIGKILL) on restart {payload.restart_count}.",
        f"The configured memory limit is {limits.memory_limit!r}.",
    ]
    if working_set is not None:
        # Only assert the comparison that the numbers actually support.
        parts.append(
            f"The last observed working set was {working_set} bytes, which is "
            "consistent with the container reaching its own cgroup limit rather "
            "than being evicted by node-level memory pressure."
        )
    if payload.previous_reason:
        parts.append(
            f"The prior termination reason was {payload.previous_reason!r}, so the "
            "fault is in steady-state operation rather than startup."
        )
    if not payload.scrubbed_logs:
        parts.append(
            "No scrubbed log lines accompanied the incident, so the allocation "
            "path could not be inspected and the remedy is limited to raising "
            "the limit."
        )
    parts.append(
        "The remedy is confined to recalibrating the memory limit, which is an "
        "enumerated Tier-1 shape in ARCH §5.3."
    )
    return clip(" ".join(parts))


def configuration_rationale(payload: IncidentPayload) -> str:
    """Explain a startup or configuration fault. Always Tier-2."""
    return clip(
        f"Container {payload.container_name!r} is failing to start or crash-looping "
        f"(reason={payload.reason.value}, exit_code={payload.exit_code!r}, "
        f"restart_count={payload.restart_count}). The scrubbed logs indicate a "
        "configuration, entrypoint or application fault rather than resource "
        "pressure. Correcting it requires reading the application, which is "
        "outside the enumerated Tier-1 remedy shapes, so no patch is proposed."
    )


def dependency_rationale(payload: IncidentPayload) -> str:
    """Explain an upstream or network fault. Always Tier-2."""
    return clip(
        f"Container {payload.container_name!r} is failing with dependency or network "
        f"errors in its scrubbed logs (reason={payload.reason.value}, "
        f"exit_code={payload.exit_code!r}). The proximate symptom is local but the "
        "cause is upstream, so a workload-local patch would not address it. "
        "Escalating to a human."
    )


def escalation_rationale(
    payload: IncidentPayload, classification: Classification
) -> str:
    """Explain a fail-closed escalation."""
    if classification is Classification.UNKNOWN:
        return RATIONALE_UNKNOWN
    return clip(
        f"Classified as {classification.value} from the scrubbed evidence, but the "
        "conditions for an automatic Tier-1 change are not all satisfied. Under the "
        "deny-by-default routing in ARCH §5.3 this escalates to a human rather than "
        "proposing a speculative cluster change."
    )


def rca_markdown(
    payload: IncidentPayload,
    classification: Classification,
    tier: BlastRadiusTier,
    rationale: str,
    evidence: list[str],
) -> str:
    """Deliverable #1: the human-readable RCA (ARCH §5.1, AGENTS.md §3.2).

    Deliberately plain text. It is read by a person in a War-Room channel, not
    by the PR pipeline, and it must never be the thing a machine parses - the
    machine-parsable artifact is ``remediation.git_patch`` and nothing else
    (AGENTS.md §3.2).
    """
    lines = [
        f"# RCA: {payload.container_name} in {payload.namespace}",
        "",
        "## Summary",
        "",
        rationale,
        "",
        "## Classification",
        "",
        f"- Classification: `{classification.value}`",
        f"- Blast radius tier: `{tier.value}`",
        f"- Reason: `{payload.reason.value}`",
        f"- Exit code: `{payload.exit_code}`",
        f"- Restarts: `{payload.restart_count}`",
        "",
        "## Evidence",
        "",
    ]
    lines.extend(f"- {item}" for item in evidence)
    lines.extend(
        [
            "",
            "## Remediation",
            "",
            _remediation_section(tier),
            "",
        ]
    )
    return clip("\n".join(lines))


def _remediation_section(tier: BlastRadiusTier) -> str:
    if tier is BlastRadiusTier.TIER_1_TOIL:
        return (
            "A unified diff is attached in `remediation.git_patch`. It targets a "
            "single manifest and is intended for a GitOps pull request. It has not "
            "been applied to the cluster by this system; that is the point of the "
            "GitOps boundary."
        )
    return (
        "**No patch is proposed.** This incident was routed to Tier-2 and requires "
        "human judgement. Any change will be authored and reviewed by a person."
    )


def looks_like_dependency_fault(payload: IncidentPayload) -> bool:
    """Whether the scrubbed logs show an upstream or network fault."""
    return bool(_DEPENDENCY_MARKERS.search(_joined_logs(payload)))


def looks_like_configuration_fault(payload: IncidentPayload) -> bool:
    """Whether the scrubbed logs show a startup or configuration fault."""
    return bool(_CONFIG_MARKERS.search(_joined_logs(payload)))


def reason_is_oom(payload: IncidentPayload) -> bool:
    """Convenience predicate.

    The schema already guarantees reason/exit-code coherence (I-A2), so this
    adds no information; it exists so callers read as intent rather than as an
    enum comparison.
    """
    return payload.reason is Reason.OOM_KILLED
