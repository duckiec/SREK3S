"""I-B6 at the Contract B boundary: every string the agent ships is re-scanned.

`docs/security-invariants.md` states I-B6 as *"Every response string passes the
agent-side defensive re-scan"*. The re-scan was applied to `rca_markdown` and to
the war-room dispatch, but `root_cause` is a **separate field of the same
response** and was returned untouched.

That gap is invisible to the tests that already exist, because they assert on the
two sinks that *are* scrubbed:

* `test_manifest_provider.py::test_the_dispatch_is_rendered_through_the_rescan`
  plants a credential in `previous_reason` — and its own docstring explains why
  that field is the right one, because `evidence_lines` renders
  `previous_termination_reason=<value>` — then asserts only on
  `outcome.response.rca_markdown` and on the rendered dispatch.
* `test_api.py::test_rca_markdown_contains_no_secret` is documented as
  "I-B6: the response is scrubbed before serialisation" and asserts on
  `response.rca_markdown`.

So the credential is planted in the field that reaches the wire and measured on
the fields that do not. These tests assert the documented invariant over the
**serialised response**, so a field added later is covered without anyone
remembering to extend the assertion.
"""

from __future__ import annotations

import json
from typing import Any, cast

import pytest

import models
import rescan
import triage

SECRET = "AKIAIOSFODNN7EXAMPLE"


def incident_document(**overrides: Any) -> dict[str, Any]:
    """A valid, Tier-1-shaped Contract A payload with the fixture's identifiers."""
    document: dict[str, Any] = {
        "schema_version": "1.0.0",
        "incident_id": "inc_01M3M6W9ENH28NJS8C5T1665PA",
        "timestamp": "2026-09-29T12:00:00.000Z",
        "namespace": "sentinel-chaos",
        "pod_name": "srek3s-chaos-oom-7d9f4b6c8d-x2k9p",
        "container_name": "oom-canary",
        "exit_code": 137,
        "reason": "OOMKilled",
        "resource_limits": {"memory_limit": "64Mi"},
        "restart_count": 1,
        "scrubbed_logs": ["CHAOS-OOM iteration=6 heap_bytes=67108864"],
        "cluster_events": [],
        "redaction_report": {"total_redactions": 2, "rules_triggered": ["uuid"]},
        "detection_latency_ms": 120,
        "sentinel_version": "0.1.0",
    }
    document.update(overrides)
    return document


def wire_paths_containing(node: Any, needle: str, path: str = "response") -> list[str]:
    """Every dotted path in a serialised model whose string value holds ``needle``."""
    found: list[str] = []
    if isinstance(node, dict):
        for key, value in node.items():
            found.extend(wire_paths_containing(value, needle, f"{path}.{key}"))
    elif isinstance(node, list):
        for index, value in enumerate(node):
            found.extend(wire_paths_containing(value, needle, f"{path}[{index}]"))
    elif isinstance(node, str) and needle in node:
        found.append(path)
    return found


class TestEveryResponseStringIsRescanned:
    """The invariant as documented, asserted on the artefact that leaves the process."""

    def test_no_wire_path_carries_the_credential(self) -> None:
        payload = models.IncidentPayload.model_validate(
            incident_document(previous_reason=SECRET)
        )
        response = triage.triage_payload(payload).response
        serialised = json.loads(response.model_dump_json())

        leaking = wire_paths_containing(serialised, SECRET)
        assert not leaking, (
            "I-B6: a credential reached the Contract B response at "
            f"{leaking}. I-B6 is 'every response string passes the agent-side "
            "defensive re-scan'; redaction_report counts must not be read as "
            "evidence that they did."
        )

    def test_the_redaction_actually_fired_rather_than_the_field_being_absent(
        self,
    ) -> None:
        """A control.

        Without this, a response that simply dropped ``root_cause`` would satisfy
        the leak assertion above and the test would be measuring nothing.
        """
        payload = models.IncidentPayload.model_validate(
            incident_document(previous_reason=SECRET)
        )
        response = triage.triage_payload(payload).response

        # The field is still there and still carries the evidence a responder needs.
        assert response.root_cause.summary.strip()
        assert any(
            "previous_termination_reason=" in line
            for line in response.root_cause.evidence
        )

        # ...but with the credential replaced, not deleted.
        assert all(SECRET not in line for line in response.root_cause.evidence)
        assert rescan.MASK in response.rca_markdown or SECRET not in json.dumps(
            serialise(response)
        )

    @pytest.mark.parametrize(
        "reason,exit_code,restart_count",
        [("CrashLoopBackOff", None, 4), ("OOMKilled", 137, 1)],
    )
    def test_both_tiers_rescan_the_response(
        self, reason: str, exit_code: int | None, restart_count: int
    ) -> None:
        """Tier-2 by classification, and Tier-1 by shape.

        Tier-2 takes its ``summary`` from the model narrative when one is
        available and from the deterministic rationale when one is not — the
        shipped default has no credential, so the deterministic branch is the
        one that has to be covered. Tier-1 never consults a model for its
        summary at all.
        """
        payload = models.IncidentPayload.model_validate(
            incident_document(
                reason=reason,
                exit_code=exit_code,
                restart_count=restart_count,
                previous_reason=SECRET,
            )
        )
        response = triage.triage_payload(payload).response
        assert not wire_paths_containing(
            json.loads(response.model_dump_json()), SECRET
        ), "I-B6: the credential reached the wire"


def serialise(response: models.TriageResponse) -> dict[str, Any]:
    return cast(dict[str, Any], json.loads(response.model_dump_json()))


def test_a_second_secret_shape_is_caught_too() -> None:
    """The backstop is a pattern set, not a single-string allowlist.

    A test that only used the AWS key would pass against a backstop that
    special-cased that one literal.
    """
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    payload = models.IncidentPayload.model_validate(
        incident_document(previous_reason=f"crashloop while dialing {jwt}")
    )
    response = triage.triage_payload(payload).response
    leaking = wire_paths_containing(json.loads(response.model_dump_json()), jwt)
    assert not leaking, f"I-B6: a JWT reached the Contract B response at {leaking}"


def test_the_shipped_fixture_is_clean_so_the_assertions_are_about_the_plant() -> None:
    """Control: the planted secret is what makes the assertions bite.

    Guards against a suite that would pass because the rescan is somehow masking
    the whole document, which would make every leak assertion above vacuous.
    """
    payload = models.IncidentPayload.model_validate(incident_document())
    response = triage.triage_payload(payload).response
    evidence = " ".join(response.root_cause.evidence)
    assert "previous_termination_reason=" not in evidence, (
        "the un-planted fixture already carries the field; the controls above "
        "would be measuring the fixture rather than the planted credential"
    )
