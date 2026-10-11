"""Model prose is clipped to each field's own schema ceiling, never rejected.

`triage` composed the model's prose against a single global ceiling
(`MAX_MODEL_PROSE_CHARS`, mirroring `rca_markdown`'s 20000) and handed the result
to `root_cause.summary`, whose ceiling is 2000, and to a composed `rca_markdown`
whose length can exceed 20000. A model reply past either boundary raised a
`ValidationError` during response construction, which `main` turned into an HTTP
500 - the incident was lost, not escalated.

The fix clips in the model constructor: `mode="before"` validators read each
field's `max_length` from its own metadata, so the clip cannot drift from the
schema it protects. These tests assert an oversized narrative yields a truncated
200-equivalent response instead of an exception.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

import llm
import models
import triage

#: A valid CrashLoopBackOff payload. CrashLoopBackOff with no provider forces the
#: Tier-2 path, which is the path that consults the model for prose.
CRASH_DOCUMENT: dict[str, Any] = {
    "schema_version": "1.0.0",
    "incident_id": "inc_01M3M6W9ENH28NJS8C5T1665PA",
    "timestamp": "2026-09-29T12:00:00.000Z",
    "namespace": "payments",
    "pod_name": "checkout-api-7d9f4b6c8d-x2k9p",
    "container_name": "checkout-api",
    "exit_code": None,
    "reason": "CrashLoopBackOff",
    "resource_limits": {"memory_limit": "256Mi"},
    "restart_count": 4,
    "scrubbed_logs": ["Traceback KeyError cust_8817"],
    "cluster_events": [],
    "redaction_report": {"total_redactions": 1, "rules_triggered": ["uuid"]},
    "detection_latency_ms": 120,
    "sentinel_version": "0.1.0",
}


def _narrative(summary_chars: int, rca_chars: int) -> llm.ModelNarrative:
    """A ModelNarrative carrying the requested string lengths (rescan-inert)."""
    return llm.ModelNarrative.model_validate(
        {
            "root_cause": {"summary": "s" * summary_chars},
            "rca_markdown": "r" * rca_chars,
        }
    )


def _inject(narrative: llm.ModelNarrative, monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_overlay(_payload: models.IncidentPayload) -> llm.ModelNarrative:
        return narrative

    monkeypatch.setattr(triage, "_narrative_overlay", fake_overlay)


class TestOversizedModelProseIsClippedNotRejected:
    def test_a_massive_narrative_becomes_a_response_not_a_500(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # summary 5000 > RootCause.summary's 2000; rca 40000 > rca_markdown's
        # 20000, and the composed document (dispatch + model section) exceeds it.
        _inject(_narrative(5000, 40000), monkeypatch)
        payload = models.IncidentPayload.model_validate(dict(CRASH_DOCUMENT))

        # Before the fix this raised a ValidationError, which main turned into a
        # 500 that lost the incident. It must return a triaged outcome instead.
        outcome = triage.triage_payload(payload)

        summary = outcome.response.root_cause.summary
        rca = outcome.response.rca_markdown
        assert (
            len(summary) <= 2000
        ), f"root_cause.summary is {len(summary)} chars, over the 2000 ceiling"
        assert (
            len(rca) <= 20000
        ), f"rca_markdown is {len(rca)} chars, over the 20000 ceiling"
        # Not an emptied scaffold: the surviving prose is still the model's.
        assert summary.strip()
        assert json.loads(outcome.response.model_dump_json())

    def test_within_ceiling_prose_is_not_truncated(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The clip must not over-truncate a reply that already fits.

        Without this, a validator that clipped everything to a fixed smaller
        bound would pass the massive test while quietly mangling normal output.
        """
        _inject(_narrative(500, 900), monkeypatch)
        payload = models.IncidentPayload.model_validate(dict(CRASH_DOCUMENT))
        outcome = triage.triage_payload(payload)
        assert outcome.response.root_cause.summary == "s" * 500


def test_the_clip_reads_the_schema_maximum_not_a_hardcoded_number() -> None:
    """Control: the clip is bound to the field's own constraint.

    If the schema raised RootCause.summary to 3000, a 2500-char reply must
    survive unclipped. This pins the helper so a validator cannot bake in the
    old number and keep clipping a value the schema now accepts.
    """
    assert models._max_str_length(models.RootCause, "summary") == 2000
    assert models._max_str_length(models.TriageResponse, "rca_markdown") == 20000

    assert models._clip_to_max_length("short", 2000) == "short"
    clipped = models._clip_to_max_length("x" * 5000, 2000)
    assert len(clipped) == 2000
    assert clipped.endswith("...")
    # None (unbounded) and non-str pass through untouched.
    assert models._clip_to_max_length("any", None) == "any"
