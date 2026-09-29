"""Offline tests for the E2E runner's sampling invariants (ROADMAP 4.2.1).

The runner cannot be exercised without a cluster, and this file is why that is
acceptable: the knowledge in ``runner.py`` is not in the ``kubectl`` calls, it is
in the invariants, and those are pure functions over a payload or an observation.
Every one of them is tested here against a *planted* incident, including the
failure direction - a runner whose checks cannot fail reports green on a run that
proved nothing, which is the most expensive way for an end-to-end test to be
wrong.
"""

from __future__ import annotations

import pathlib
import sys
from typing import Any

import pytest

_E2E_DIR = pathlib.Path(__file__).resolve().parents[2] / "tests" / "e2e"
sys.path.insert(0, str(_E2E_DIR))

from runner import (  # noqa: E402
    CRASHLOOP_OBSERVABLE_AFTER,
    LOG_TAIL_LINES,
    PLANTED_SECRETS,
    Observation,
    VerificationError,
    check_causal_chain,
    check_diagnostics_survived,
    check_incident_window,
    check_logs_were_captured,
    check_redaction,
    classify_observation,
    gate_redaction,
    verify,
)

# ---------------------------------------------------------------------------
# Fixtures - all synthetic, no cluster
# ---------------------------------------------------------------------------


def scrubbed_logs(n: int = 6) -> list[str]:
    """Logs that look like a real masked capture: markers present, secrets gone."""
    return [
        "CHAOS-CRED seq=0 aws_access_key_id=[REDACTED] "
        "aws_secret_access_key=[REDACTED]",
        "CHAOS-CRED seq=0 jwt=[REDACTED]",
        "CHAOS-CRED seq=0 Authorization: [REDACTED]",
        "CHAOS-CRED seq=0 dsn=postgres://chaos_user:[REDACTED]@db.internal:5432/billing",
        "CHAOS-PHASE creds-planted next=memory-exhaustion",
        "CHAOS-OOM iteration=6 heap_bytes=67108864",
    ][:n]


def good_incident(**overrides: Any) -> dict[str, Any]:
    incident: dict[str, Any] = {
        "incident_id": "inc_01M3M6W9ENH28NJS8C5T1665PA",
        "reason": "OOMKilled",
        "exit_code": 137,
        "restart_count": 2,
        "scrubbed_logs": scrubbed_logs(),
    }
    incident.update(overrides)
    return incident


def oom_then_crashloop() -> list[Observation]:
    """The history a real fixture produces, in order.

    instance 0 runs, allocates, and is OOM-killed at 137. The kubelet restarts it
    once with no backoff. The second failure enters backoff and the reason is
    published, at which point `state.terminated` has already been cleared and the
    cause survives only in `lastState`.
    """
    return [
        Observation(timestamp=0.0, state="Running", restart_count=0),
        Observation(
            timestamp=5.5,
            state="Terminated",
            exit_code=137,
            reason="OOMKilled",
            restart_count=1,
        ),
        Observation(
            timestamp=6.0,
            state="CrashLoopBackOff",
            restart_count=2,
            previous_exit_code=137,
            previous_reason="Error",
        ),
        Observation(
            timestamp=26.0,
            state="CrashLoopBackOff",
            restart_count=3,
            previous_exit_code=137,
            previous_reason="Error",
        ),
    ]


# ---------------------------------------------------------------------------
# The restart_count gate
# ---------------------------------------------------------------------------


def test_first_crash_is_gated_out_because_there_is_no_previous_log() -> None:
    """The most likely way a masking assertion passes vacuously.

    The Sentinel reads the *previous* instance. On the first crash there is none,
    the apiserver rejects the read, and the worker dispatches with empty logs and
    no error. Asserting "no plaintext" on that incident is asserting on "".
    """
    incident = good_incident(restart_count=0, scrubbed_logs=[])
    reason = gate_redaction(incident)
    assert reason is not None, (
        "a restart_count=0 incident was sent to the redaction check; it has no "
        "log to have been scrubbed"
    )
    assert "first crash" in reason or "no previous instance" in reason


def test_gated_incident_returns_a_reason_not_a_bare_bool() -> None:
    """The reason is returned rather than logged.

    A run where every incident is gated out must be visibly different from a run
    where masking was proven, and only a returned reason makes that countable.
    """
    assert gate_redaction(good_incident(restart_count=0)) is not None
    assert gate_redaction(good_incident(restart_count=1)) is None
    assert gate_redaction(good_incident(restart_count=7)) is None


def test_a_run_where_everything_is_gated_is_not_a_pass() -> None:
    """The structural version of the same trap, at the report level."""
    gated_only = [good_incident(restart_count=0, scrubbed_logs=[]) for _ in range(3)]
    report = verify(gated_only, [], window=60.0)
    assert not report.passed, (
        f"a run with 3 gated incidents and 0 checks reported a pass: "
        f"{report.failures}"
    )
    assert any(
        "gated out" in failure for failure in report.failures
    ), f"the report does not say why nothing was checked: {report.failures}"


# ---------------------------------------------------------------------------
# Capture, then redaction
# ---------------------------------------------------------------------------


def test_empty_logs_are_a_failure_not_a_pass() -> None:
    """The assertion that makes the redaction check non-vacuous.

    Without this, "no planted secret appears in scrubbed_logs" is trivially true
    of an empty list, and a capture bug reads as a clean masking result.
    """
    with pytest.raises(VerificationError, match="empty"):
        check_logs_were_captured(good_incident(scrubbed_logs=[]))
    with pytest.raises(VerificationError, match="empty"):
        check_redaction(good_incident(scrubbed_logs=[]))


def test_oversize_logs_are_rejected() -> None:
    """Past the Sentinel's 100-line tail, the planted credentials may be gone.

    Not a masking failure - the run would look clean for the wrong reason.
    """
    with pytest.raises(VerificationError, match="tail"):
        check_logs_were_captured(
            good_incident(scrubbed_logs=["x"] * (LOG_TAIL_LINES + 1))
        )


def test_a_surviving_secret_fails() -> None:
    for secret in PLANTED_SECRETS:
        incident = good_incident(
            scrubbed_logs=[f"CHAOS-CRED leaked {secret}", "CHAOS-PHASE done"]
        )
        with pytest.raises(VerificationError, match="planted secret"):
            check_redaction(incident)


def test_a_clean_payload_passes() -> None:
    logs = check_redaction(good_incident())
    assert logs, "check_redaction returned no logs for a valid payload"
    check_diagnostics_survived(logs)


def test_dropping_every_line_is_caught_by_the_diagnostics_check() -> None:
    """The mirror trap: a scrubber that satisfies the leak test by erasing.

    Leaking nothing because nothing is left is not masking, and the redaction
    check alone cannot tell the two apart.
    """
    with pytest.raises(VerificationError, match="marker"):
        check_diagnostics_survived(["", ""])


def test_logs_with_no_marker_but_no_secret_also_fails() -> None:
    """Neither erasing the secret nor erasing the line is acceptable."""
    with pytest.raises(VerificationError, match="marker"):
        check_diagnostics_survived(["connection reset by peer"])


# ---------------------------------------------------------------------------
# The causal chain
# ---------------------------------------------------------------------------


def test_causal_chain_is_accepted_in_the_right_order() -> None:
    description = check_causal_chain(oom_then_crashloop())
    assert "OOMKilled(137)" in description
    assert "CrashLoopBackOff" in description


def test_causal_chain_rejects_an_inverted_history() -> None:
    """Sampling that missed the cause.

    If the first sample is already in backoff, the runner never saw the
    terminated state - which means it cannot have seen the OOM either, and
    reporting a pass would be asserting a link it did not observe.
    """
    inverted = [
        Observation(
            timestamp=0.0,
            state="CrashLoopBackOff",
            restart_count=2,
            previous_exit_code=137,
            previous_reason="Error",
        ),
        Observation(timestamp=5.0, state="Terminated", exit_code=137, restart_count=3),
    ]
    with pytest.raises(VerificationError, match="inverted"):
        check_causal_chain(inverted)


def test_causal_chain_requires_the_cause_to_be_carried() -> None:
    """`previous_reason` is the link, and its absence is the finding.

    The kubelet clears `state.terminated` on restart, so if the runner samples
    only the backoff state it can see the symptom and not the cause at all.
    """
    without_cause = [
        Observation(timestamp=0.0, state="Terminated", exit_code=137, restart_count=1),
        Observation(timestamp=20.0, state="CrashLoopBackOff", restart_count=2),
    ]
    with pytest.raises(VerificationError, match="previous_reason"):
        check_causal_chain(without_cause)


def test_no_oom_observed_is_reported_as_such() -> None:
    with pytest.raises(VerificationError, match="never observed Terminated"):
        check_causal_chain(
            [Observation(timestamp=0.0, state="CrashLoopBackOff", restart_count=4)]
        )


def test_no_observations_is_reported_as_such() -> None:
    with pytest.raises(VerificationError, match="no observations"):
        check_causal_chain([])


def test_the_documented_floor_is_at_least_the_first_backoff_interval() -> None:
    """The 12s floor is derived from the kubelet, not chosen.

    The first backoff interval is exactly 10s and the reason is not published
    until the *second* failure, so a runner asserting at 5s fails against a
    fixture that is working perfectly. If this assertion ever needs lowering, the
    kubelet behaviour changed and the comment above it is now wrong.
    """
    assert (
        CRASHLOOP_OBSERVABLE_AFTER > 10.0
    ), "the floor dropped below the kubelet's 10s first backoff interval"


# ---------------------------------------------------------------------------
# Observation -> emitted kind must match the Sentinel
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("observation", "expected"),
    [
        (Observation(timestamp=0.0, state="CrashLoopBackOff"), "CrashLoopBackOff"),
        (Observation(timestamp=0.0, state="Terminated", exit_code=137), "OOMKilled"),
        (Observation(timestamp=0.0, state="Terminated", exit_code=1), "Terminated"),
        (Observation(timestamp=0.0, state="Terminated", exit_code=0), None),
        (Observation(timestamp=0.0, state="Running"), None),
    ],
)
def test_classification_mirrors_the_sentinel(
    observation: Observation, expected: str | None
) -> None:
    """A runner that guesses differently reports a pass on an empty run.

    `Terminated` with a non-137 exit is deliberately mapped to a kind the emitter
    *refuses*; that is the point of the test, and `check_incident_window` is what
    catches it arriving anyway.
    """
    assert classify_observation(observation) == expected


def test_incident_window_requires_two_restarts_not_one() -> None:
    """`restart_count >= 1` is too weak to prove backoff happened.

    The kubelet restarts a failed container immediately the first time - no
    backoff entry exists yet - so one restart is observed whether or not the
    fixture ever entered backoff. Two is the threshold that means something.
    """
    with pytest.raises(VerificationError, match="restart_count>=2"):
        check_incident_window([good_incident(restart_count=1)])
    assert "1 incident" in check_incident_window([good_incident(restart_count=2)])


def test_incident_window_rejects_an_unmappable_reason() -> None:
    """The emitter drops these, so their arrival means something upstream is wrong."""
    with pytest.raises(VerificationError, match="outside"):
        check_incident_window([good_incident(reason="Terminated")])


def test_incident_window_does_not_pin_a_count() -> None:
    """Count is a function of wall-clock, so the check must be a window.

    The dedup key includes the restart count, so every restart is a distinct
    incident and nothing is collapsed. An exact-count assertion passes at t=15s
    and fails at t=60s for reasons unrelated to the Sentinel.
    """
    for count in (1, 3, 12, 40):
        incidents = [
            good_incident(incident_id=f"inc_{i:026d}", restart_count=2 + i)
            for i in range(count)
        ]
        description = check_incident_window(incidents)
        assert f"{count} incident" in description


def test_empty_incident_list_names_the_first_things_to_check() -> None:
    """A failure message that only says "no incidents" costs a run cycle.

    The three causes - namespace scope, RBAC, and the agent's response - are
    checked in the order they are cheapest to verify.
    """
    with pytest.raises(VerificationError) as caught:
        check_incident_window([])
    message = str(caught.value)
    for hint in ("WATCH_NAMESPACE", "RBAC", "2xx"):
        assert hint in message, f"the failure message omits {hint!r}: {message}"


# ---------------------------------------------------------------------------
# Negative controls - AGENTS.md §5
# ---------------------------------------------------------------------------


def test_control_redaction_check_rejects_a_leak() -> None:
    """Proves the redaction check can fail on a real leak."""
    leaky = good_incident(
        scrubbed_logs=["CHAOS-CRED aws_access_key_id=AKIAIOSFODNN7EXAMPLE"]
    )
    with pytest.raises(VerificationError):
        check_redaction(leaky)


def test_control_verify_reports_a_leak_as_a_failure() -> None:
    """The end-to-end direction, at the report level.

    And through the property the exit code is derived from, not by inspecting the
    failure list - a report whose pass/fail is not readable from one field is one
    a caller will get wrong.
    """
    leaky = [
        good_incident(scrubbed_logs=["CHAOS-CRED bearer=chaos-planted-bearer-token"])
    ]
    report = verify(leaky, oom_then_crashloop(), window=60.0)
    assert report.failures, "a leaked secret produced no failure in the report"
    assert not report.passed, "a leaked secret still reported passed"


def test_control_empty_run_is_not_a_pass() -> None:
    """A run that collected nothing must exit non-zero.

    The first version of ``main`` returned 0 unconditionally, so an empty run -
    wrong namespace, no RBAC, agent returning 4xx - was a success. The failure
    message names the three cheapest things to check for exactly this reason.
    """
    report = verify([], [], window=60.0)
    assert not report.passed
    joined = " ".join(report.failures)
    assert "no incidents" in joined
    assert "observation" in joined


def test_control_verify_reports_a_healthy_run_as_clean() -> None:
    """The other direction: a correct run must not manufacture failures.

    A check suite that flags good runs gets disabled, which is the same outcome
    as having no checks.
    """
    report = verify([good_incident()], oom_then_crashloop(), window=60.0)
    assert report.passed, f"a healthy run was reported as failing: {report.failures}"
    assert report.gated == [], f"a restart_count=2 incident was gated: {report.gated}"
    # The informational results are still recorded. Separating notes from
    # failures must not mean throwing the evidence away.
    assert report.notes, (
        "a healthy run recorded no notes; the chain was checked "
        "but its result was discarded"
    )


def test_report_passed_property_is_derived_from_failures_only() -> None:
    """Notes must never affect the verdict.

    A run can be a pass while having plenty to say - that is the normal case for
    a healthy run, which reports the incident window and the causal chain. If
    notes blocked the verdict, a healthy run would fail on its own evidence.
    """
    report = verify([good_incident()], oom_then_crashloop(), window=60.0)
    assert (
        report.notes and report.passed
    ), f"notes={report.notes} but passed={report.passed}"


def test_control_chat_loop_checks_cannot_fail() -> None:
    """A run with a single observation cannot observe a chain.

    Without this, a runner that sampled once could report a pass, and the pass
    would mean it had looked once and seen a symptom.
    """
    report = verify([good_incident()], oom_then_crashloop()[:1], window=60.0)
    assert any(
        "observation" in note for note in report.failures
    ), f"a single-sample run reported no complaint: {report.failures}"
