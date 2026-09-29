"""Cross-language contract test for the Go emitter (ROADMAP 3.4.6).

The round trip is deliberately split rather than shelled out. A Go test that
invoked CPython would make the Go gate depend on a virtualenv, and a Python test
that imported the Go package would make the Python gate depend on a Go toolchain.
Instead:

1. ``go test ./internal/emitter`` writes ``tests/fixtures/emitted_incident.json``
   from the real :func:`Build` output and fails if that file has drifted.
2. This module validates the committed file against ``models.IncidentPayload``.

A change on either side that the other has not adopted fails a gate. A change to
both is fine, because both gates run.
"""

from __future__ import annotations

import json
import pathlib
from typing import Any, cast

import pytest

from models import IncidentPayload, Reason

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
EMITTED_FIXTURE = REPO_ROOT / "tests" / "fixtures" / "emitted_incident.json"


def emitted() -> dict[str, Any]:
    assert EMITTED_FIXTURE.exists(), (
        f"{EMITTED_FIXTURE} is missing; run "
        "`go test ./internal/emitter -run TestEmittedFixtureIsUpToDate -update`"
    )
    # cast, not a bare return: json.loads is typed Any, and --strict rejects
    # returning Any from a function that promises a concrete type. The cast is a
    # claim about the file's shape, and the assertions below are what test it.
    return cast(
        "dict[str, Any]",
        json.loads(EMITTED_FIXTURE.read_text(encoding="utf-8")),
    )


def test_emitted_fixture_validates_against_schema() -> None:
    """The bytes Go actually puts on the wire satisfy the agent's models.

    This is the whole of ROADMAP 3.4.6. Everything else in this module is a
    narrower claim about a specific field.
    """
    payload = IncidentPayload.model_validate(emitted())
    # The enum *member name* is OOM_KILLED while its *wire value* is "OOMKilled",
    # so the comparison has to go through the member that carries the wire spelling.
    assert payload.reason == Reason.OOM_KILLED
    assert payload.reason.value == "OOMKilled"
    assert payload.exit_code == 137
    assert payload.detection_latency_ms == 412


def test_the_fixture_carries_no_comment_keys() -> None:
    """``extra: forbid`` means a stray key is a 422, not a no-op.

    Worth pinning because the hand-written ``sample-incident.json`` *does* carry a
    ``_comment`` block, so there is a live precedent in this repo for a fixture
    that cannot be submitted. The generated artefact must not copy that habit.
    """
    raw = emitted()
    assert not [
        key for key in raw if key.startswith("_")
    ], f"generated payload has comment keys: {[k for k in raw if k.startswith('_')]}"


def test_nullable_fields_arrive_as_explicit_null() -> None:
    """ARCH §4.1: a Go guard-chain miss is ``null``, not an absent key.

    Both are accepted by Pydantic - the fields have defaults - so only this test
    can tell the difference. The consequence of getting it wrong is not a crash:
    it is a payload whose absent key reads identically to an absent field, which is
    the failure mode ARCH §4.1 was written to forbid.
    """
    raw = emitted()

    # The canonical fixture is an OOMKilled incident, so these are populated. What
    # must be explicit is the one the Sentinel genuinely cannot know.
    assert "memory_working_set_bytes" in raw["resource_limits"]
    assert raw["resource_limits"]["memory_working_set_bytes"] is None, (
        "the Sentinel has no metrics client; a number here would be a measurement "
        "it never took"
    )

    # Every nullable field must be *present*, null or not. A key that is missing
    # from the JSON is not the same input to Pydantic as a key that is null.
    for key in (
        "schema_version",
        "incident_id",
        "timestamp",
        "namespace",
        "pod_name",
        "container_name",
        "exit_code",
        "reason",
        "resource_limits",
        "restart_count",
        "previous_reason",
        "scrubbed_logs",
        "cluster_events",
        "redaction_report",
        "detection_latency_ms",
        "sentinel_version",
    ):
        assert key in raw, f"{key} is absent from the emitted payload"


def test_redaction_report_carries_counts_only() -> None:
    """ARCH §6 M4: the reporting channel has no slot that could hold plaintext.

    Checked structurally - the model declares exactly two fields and neither is a
    free-text one - rather than by scanning for secrets, because a scanner would
    pass just as happily against a model that gained a third field.
    """
    report = emitted()["redaction_report"]
    assert set(report) == {"total_redactions", "rules_triggered"}
    assert all(isinstance(rule, str) for rule in report["rules_triggered"])
    assert report["total_redactions"] > 0, (
        "the canonical incident carries planted secrets; a zero count means the "
        "emitter was fed pre-scrubbed text and the round trip proves nothing"
    )


def test_scrubbed_logs_are_actually_scrubbed() -> None:
    """The logs in the payload are masked, and masking did not empty them.

    Both halves matter. The first is ROADMAP 3.4.5 seen from the consumer's side.
    The second guards against the opposite failure - a scrubber that satisfies the
    leak test by dropping every line, which would leave the agent with nothing to
    reason about while every security assertion stayed green.
    """
    logs = emitted()["scrubbed_logs"]
    assert logs, "no logs at all; masking destroyed the evidence"
    assert any(
        "alloc failure" in line for line in logs
    ), "the diagnostic content of the logs was destroyed along with the secrets"
    for line in logs:
        assert "[REDACTED]" in line, f"a log line carries no redaction: {line!r}"


def test_fixture_is_not_wire_validated_with_extra_keys() -> None:
    """Negative control for :func:`test_the_fixture_carries_no_comment_keys`.

    A guard that cannot fail is indistinguishable from a clean payload. This
    proves the underlying model really does reject an unknown key, so the check
    above is measuring something.
    """
    polluted = emitted() | {"_comment": ["should not be here"]}
    with pytest.raises(ValueError):
        IncidentPayload.model_validate(polluted)
