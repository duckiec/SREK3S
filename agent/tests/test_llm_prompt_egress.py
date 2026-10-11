"""Outbound prompt egress: the agent redacts before a provider ever receives it.

The Go Sentinel is the authoritative scrubber, but two things reach a model
without it: ``previous_reason`` is the one payload field the Go node never masks
(it is neither ``scrubbed_logs`` nor ``scrubbed_log_messages``), and
``SREK3S_LOG_TEXT_EVIDENCE=1`` widens the prompt to raw log text. ``triage`` hands
the model exactly ``build_prompt(payload)`` (``client.complete(build_prompt(payload))``),
so ``llm.build_prompt`` is the single production choke point. Redacting the
evidence there is a guarantee, not a convention: an unredacted credential in any
payload-derived line cannot reach a provider, whatever the flag or the upstream
scrubber did. Without the fix the plant reaches the outbound prompt and these
tests fail.
"""

from __future__ import annotations

from typing import Any

import pytest

import llm
import models
import prompt as prompt_mod
import rescan

SECRET = "AKIAIOSFODNN7EXAMPLE"


def _incident_document(**overrides: Any) -> dict[str, Any]:
    document: dict[str, Any] = {
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
    document.update(overrides)
    return document


def test_previous_reason_never_reaches_the_prompt_unredacted() -> None:
    """previous_reason is not Go-scrubbed; the prompt must redact it anyway."""
    payload = models.IncidentPayload.model_validate(
        _incident_document(previous_reason=f"dialing cache with {SECRET}")
    )
    built = llm.build_prompt(payload)
    assert SECRET not in built, "a credential survived into the outbound prompt"
    assert rescan.MASK in built, "the re-scan fired rather than the line dropping"
    assert "previous_termination_reason=" in built, "the evidence line survived, masked"


def test_log_text_evidence_widening_cannot_leak_a_secret(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """With the flag on, raw log text enters the prompt; it must be redacted.

    The plant mirrors the worst case the guarantee exists for: the Go scrubber
    did not mask this line (or the widened surface carries it), and the agent
    must still not be the hop that transmits it.
    """
    monkeypatch.setenv(prompt_mod.LOG_TEXT_EVIDENCE_ENV, "1")
    payload = models.IncidentPayload.model_validate(
        _incident_document(scrubbed_logs=[f"GET /healthz?api_key={SECRET} HTTP/1.1"])
    )
    built = llm.build_prompt(payload)
    assert (
        SECRET not in built
    ), "SREK3S_LOG_TEXT_EVIDENCE widened the prompt and the credential survived"
    assert (
        rescan.MASK in built
    ), "the re-scan masked the log text rather than dropping it"


def test_benign_evidence_is_not_masked_so_the_guarantee_is_not_vacuous() -> None:
    """Control: the re-scan targets secrets, not everything.

    A test that only proves "no secret" would also pass against a redactor that
    blanks the whole prompt. This asserts a benign previous_reason survives intact
    and carries no mask, so the masking is about credentials and nothing else.
    """
    payload = models.IncidentPayload.model_validate(
        _incident_document(previous_reason="OOMKilled")
    )
    built = llm.build_prompt(payload)
    assert "previous_termination_reason=OOMKilled" in built
    assert rescan.MASK not in built


def test_a_second_secret_shape_is_redacted_too(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The guard is a rule set, not an allowlist for one literal."""
    jwt = (
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0."
        "dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    )
    monkeypatch.setenv(prompt_mod.LOG_TEXT_EVIDENCE_ENV, "1")
    payload = models.IncidentPayload.model_validate(
        _incident_document(scrubbed_logs=[f"authorization: Bearer {jwt}"])
    )
    assert jwt not in llm.build_prompt(payload)
