"""Offline tests for the runner's response-half invariants (ROADMAP 4.2.3, 4.2.5-4.2.8).

``runner.py`` already had offline tests for its sampling invariants. These cover
the five boxes that were **unticked** because no assertion existed: detection
latency and the injection ratio, RCA specificity, the Tier-1 patch under real
git, the Tier-2 war-room dispatch, and the no-mutation snapshot.

The shape of every test here is the same, and it is the shape the rest of this
repository has converged on after finding four guards that could not fail: the
positive case proves the check passes on correct data, and a **paired negative
control** proves it fires on the specific defect it exists to catch. A check
that has only the first is a box that looks ticked and is not.

Where a real `git` and real files are needed they are used, because
``verify_patch.py`` exists because a hand-written diff and a forgiving checker
let a P0 through 410 green tests.
"""

from __future__ import annotations

import json
import pathlib
import sys
import tempfile
from typing import Any, Iterator

import pytest

_E2E_DIR = pathlib.Path(__file__).resolve().parents[2] / "tests" / "e2e"
sys.path.insert(0, str(_E2E_DIR))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from runner import (  # noqa: E402
    CAPTURE_KEY,
    CHAOS_NAMESPACE,
    DETECTION_LATENCY_BUDGET_MS,
    MIN_RCA_STRONG_CITATIONS,
    NOISY_SYSTEM_NAMESPACES,
    RCA_STRONG_FACTS,
    SKIP_PREFIX,
    TIER_1,
    TIER_2,
    WAR_ROOM_DO_NOT_APPLY_MARKER,
    Observation,
    RunReport,
    VerificationError,
    _load_snapshot,
    citable_facts,
    check_captured_response_exists,
    check_detection_latency,
    check_no_cluster_mutation,
    check_rca_is_specific,
    check_tier_one_patch,
    check_tier_one_patches,
    check_tier_two_dispatch,
    check_tier_two_dispatches,
    declared_patch_path,
    git_apply,
    injectable_restart_counts,
    oom_restart_counts,
    percentile_nearest_rank,
    render,
    response_of,
    sampler_restart_ceiling,
    semantic_change_paths,
    tier_of,
    verify,
)

import classifier  # noqa: E402
import models  # noqa: E402
import triage  # noqa: E402
import warroom  # noqa: E402

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
CHAOS_MANIFEST = REPO_ROOT / "deploy" / "chaos" / "oom-leak.yaml"

#: The one manifest the agent is ever permitted to patch
#: (``classifier.TARGET_MANIFEST``).
TARGET = classifier.TARGET_MANIFEST


# ---------------------------------------------------------------------------
# Fixtures: a real Tier-1 incident, produced by the real engine
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def manifest_text() -> str:
    assert CHAOS_MANIFEST.is_file(), f"{CHAOS_MANIFEST} is missing"
    return CHAOS_MANIFEST.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def checkout(tmp_path_factory: pytest.TempPathFactory) -> pathlib.Path:
    """A GitOps checkout holding the chaos manifest at ``TARGET_MANIFEST``.

    Built by **copying the real fixture** rather than by writing a toy, because
    a toy would not exercise ``find_container_memory_limit``'s structural
    lookup and a patch that passed here could still fail against the file the
    E2E actually uses.
    """
    root = tmp_path_factory.mktemp("gitops")
    target = root / TARGET
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(CHAOS_MANIFEST.read_text(encoding="utf-8"), encoding="utf-8")
    return root


def chaos_document(**overrides: Any) -> dict[str, Any]:
    """A Contract A payload shaped like the real chaos incident."""
    document: dict[str, Any] = {
        "schema_version": "1.0.0",
        "incident_id": "inc_01M3M6W9ENH28NJS8C5T1665PA",
        "timestamp": "2026-09-29T12:00:00.000Z",
        "namespace": CHAOS_NAMESPACE,
        "pod_name": "srek3s-chaos-oom-7d9f4b6c8d-x2k9p",
        "container_name": "oom-canary",
        "exit_code": 137,
        "reason": "OOMKilled",
        "resource_limits": {"memory_limit": "64Mi"},
        "restart_count": 1,
        "scrubbed_logs": [
            "CHAOS-CRED seq=0 aws_access_key_id=[REDACTED]",
            "CHAOS-OOM iteration=6 heap_bytes=67108864",
        ],
        "cluster_events": [],
        "redaction_report": {"total_redactions": 2, "rules_triggered": ["uuid"]},
        "detection_latency_ms": 120,
        "sentinel_version": "0.1.0",
    }
    document.update(overrides)
    return document


def captured(
    document: dict[str, Any],
    response: dict[str, Any] | None,
    status: int = 200,
) -> dict[str, Any]:
    """A capture-proxy record: the payload plus its namespaced response."""
    record = dict(document)
    record[CAPTURE_KEY] = {"seq": 1, "upstream_status": status, "method": "POST"}
    if response is not None:
        record[CAPTURE_KEY]["upstream_body"] = response
    return record


def triaged(document: dict[str, Any], checkout_root: pathlib.Path) -> dict[str, Any]:
    """Run the **real** engine and wrap the result as a capture record."""
    payload = models.IncidentPayload.model_validate(document)
    outcome = triage.triage_payload(
        payload, manifest_provider=classifier.FileManifestProvider(checkout_root)
    )
    return captured(document, outcome.response.model_dump(mode="json"))


def crashloop_record(checkout_root: pathlib.Path) -> dict[str, Any]:
    """A crash-loop exchange. Tier-2 by construction, not by configuration."""
    return triaged(
        chaos_document(
            incident_id="inc_01M3M6W9ENH28NJS8C5T1665TB",
            reason="CrashLoopBackOff",
            exit_code=None,
            restart_count=2,
        ),
        checkout_root,
    )


def _tier2_shape() -> dict[str, Any]:
    """A hand-written Tier-2 body, for the tests that mutate one field."""
    return {
        "blast_radius_tier": TIER_2,
        "status": "ESCALATED",
        "rca_markdown": (
            f"## Tier-2 escalation\n\n> **{WAR_ROOM_DO_NOT_APPLY_MARKER}** full stop."
        ),
        "remediation": {
            "summary": "No automatic change proposed.",
            "risk_level": "HIGH",
            "target_manifest": TARGET,
            "git_patch": "",
            "patch_validated": False,
        },
        "verification_policy": {
            "mode": "TIER_2_WAR_ROOM",
            "watch_duration_seconds": 900,
            "success_criteria": {
                "no_oomkilled_terminations": True,
                "no_crashloopbackoff_wait": True,
                "container_uptime_seconds_min": 600,
            },
            "on_success": "CLOSE_INCIDENT",
            "on_repeat_failure": "PROMOTE_TO_TIER_2",
            "on_indeterminate": "REQUEUE_BOUNDED",
            "max_requeue_attempts": 1,
        },
    }


# ---------------------------------------------------------------------------
# 4.2.3 - detection latency and the injection/detection ratio
# ---------------------------------------------------------------------------


def oom_at(*restarts: int) -> list[Observation]:
    """Observations that saw a 137 termination at each given restart count."""
    return [
        Observation(
            timestamp=float(index),
            state="Terminated",
            exit_code=137,
            reason="OOMKilled",
            restart_count=restart,
        )
        for index, restart in enumerate(restarts, start=1)
    ]


def oom_then_restarted(*restarts: int) -> list[Observation]:
    """A 137 at each of ``restarts``, then the pod already restarted again.

    This is the shape a live run actually produces when the fixture crashes
    faster than the ~1s sampler. The kubelet has already incremented the restart
    count by the time the next poll lands, so the sampler sees
    ``restartCount=2`` with the ``Terminated`` state cleared and the 137 only in
    ``lastState`` - which ``read_observation`` files under
    ``previous_exit_code``, not ``exit_code``. The sampler therefore *missed* a
    real kill, and the final trailing sample is what proves the restart count
    really did reach ``len(restarts)``.
    """
    history = oom_at(*restarts)
    final = max(restarts) + 1 if restarts else 1
    history.append(
        Observation(
            timestamp=float(len(history) + 1),
            state="CrashLoopBackOff",
            exit_code=None,
            reason=None,
            restart_count=final,
            previous_exit_code=137,
            previous_reason="OOMKilled",
        )
    )
    return history


def latency_record(restart: int, latency_ms: int = 120) -> dict[str, Any]:
    return captured(
        chaos_document(restart_count=restart, detection_latency_ms=latency_ms),
        _tier2_shape(),
    )


def test_latency_and_ratio_pass_on_a_healthy_run() -> None:
    incidents = [latency_record(1, 90), latency_record(2, 410)]
    description = check_detection_latency(incidents, oom_at(1, 2))
    assert "p99" in description
    assert str(DETECTION_LATENCY_BUDGET_MS) in description


# --- 4.2.3 negative control 1: an over-budget latency -----------------------


def test_control_over_budget_latency_fails() -> None:
    """The defect: the Sentinel emitted a detection slower than the budget.

    Catches a regression in the Go emitter's latency measurement, or in the
    clamp at ``internal/emitter``. Note the runner reads the **request** body
    the proxy recorded, not the validated model - and that matters, because
    ``IncidentPayload`` rejects ``detection_latency_ms > 2000`` with a 422, so
    an over-budget payload would never produce a response to assert against.
    Reading the request is what makes the check able to fire at all.
    """
    with pytest.raises(VerificationError, match="over the 2000ms budget"):
        check_detection_latency([latency_record(1, 2001)], oom_at(1))


def test_control_a_single_over_budget_incident_fails_at_p99() -> None:
    """One slow detection out of twenty is still over budget at p99.

    Asserted because an averaged p99 would pass this, and because "p99 of
    twenty samples" is the maximum under nearest rank - so the check is
    strictly the per-sample budget, not a smoothed one.
    """
    incidents = [latency_record(1, 100)] * 19 + [latency_record(2, 5000)]
    with pytest.raises(VerificationError, match="over the 2000ms budget"):
        check_detection_latency(incidents, oom_at(1, 2))


def test_control_a_missing_latency_field_fails() -> None:
    """The defect: an incident with no ``detection_latency_ms`` at all.

    Catches a Silently-dropped field. Computing p99 over only the incidents
    that *do* carry it would narrow the assertion without saying so, and the
    run would report a percentile of a subset as though it were the run's.
    """
    record = captured(chaos_document(), _tier2_shape())
    record.pop("detection_latency_ms")
    with pytest.raises(VerificationError, match="no integer detection_latency_ms"):
        check_detection_latency([record], oom_at(1))


# --- 4.2.3 negative control 2: the ratio -----------------------------------


def test_control_a_missed_detection_fails() -> None:
    """The defect: an observed OOM that produced no incident.

    This is the AC-1 1:1 property, and the case that matters: the Sentinel saw
    the kill and said nothing. The message names *which* restart was missed,
    because a symmetric-difference report is the difference between a fixable
    bug report and a number.
    """
    incidents = [latency_record(1)]
    with pytest.raises(VerificationError) as error:
        check_detection_latency(incidents, oom_at(1, 2, 3))
    message = str(error.value)
    assert "Missed detection" in message
    assert "[2, 3]" in message


def test_control_a_phantom_detection_fails() -> None:
    """The defect: an incident for a restart the runner never saw.

    A 1:1 check that only ever fails on a *low* count would pass a Sentinel
    that emitted twice as many incidents as it should. The reverse direction
    needs its own control.
    """
    incidents = [latency_record(1), latency_record(2)]
    with pytest.raises(VerificationError) as error:
        check_detection_latency(incidents, oom_at(1))
    assert "no observed injection" in str(error.value)


def test_control_a_duplicate_dedup_key_fails() -> None:
    """The defect: the same ``<pod>/<container>:<restart>`` emitted twice.

    ROADMAP 3.3.3's dedup cache. Without this the ratio could still balance -
    one missed detection and one duplicate both change the total, and a
    length-only comparison would see a match. The key set catches it.
    """
    incidents = [latency_record(1), latency_record(1)]
    with pytest.raises(VerificationError, match="reuse a dedup key"):
        check_detection_latency(incidents, oom_at(1))


def test_control_no_observed_injection_fails() -> None:
    """The defect: incidents were detected but the runner saw no 137.

    Catches a sampling window that opened after the restart - the exact harness
    defect that has bitten this project before, and the one that produces a
    "detection happened" reading when in fact the cause was never observed.
    """
    with pytest.raises(VerificationError, match="no termination with exit_code 137"):
        check_detection_latency(
            [latency_record(1)], [Observation(timestamp=1.0, state="CrashLoopBackOff")]
        )


def test_crashloop_incidents_are_excluded_from_the_ratio() -> None:
    """The counting rule, asserted rather than left in a comment.

    A crash-loop record is the *symptom* of an OOM already counted. Counting it
    would inflate the ratio; the runner must count it, report it, and exclude
    it - all three, and this asserts the report says so.
    """
    incidents = [latency_record(1), latency_record(2)]
    incidents.append(
        captured(
            chaos_document(
                incident_id="inc_01M3M6W9ENH28NJS8C5T1665TB",
                reason="CrashLoopBackOff",
                exit_code=None,
                restart_count=3,
            ),
            _tier2_shape(),
        )
    )
    description = check_detection_latency(incidents, oom_at(1, 2))
    assert "1 CrashLoopBackOff symptom" in description
    assert "counting rule" in description


def test_a_crashloop_only_capture_fails_the_ratio() -> None:
    """The mirror: with no OOM detection, the ratio is genuinely unmet.

    Guards against a future "be lenient when everything is a crash loop"
    change, which would turn the AC-1 ratio into a no-op for exactly the runs
    where a missed OOM is least visible.
    """
    with pytest.raises(VerificationError, match="detections != injected events"):
        check_detection_latency(
            [
                captured(
                    chaos_document(
                        reason="CrashLoopBackOff", exit_code=None, restart_count=2
                    ),
                    _tier2_shape(),
                )
            ],
            oom_at(1),
        )


def test_percentile_nearest_rank_is_the_strictest_reading() -> None:
    """The percentile definition is pinned.

    Interpolation would report a p99 no sample ever took, so the assertion would
    be about a number the system never produced. At n=20 nearest rank is the
    maximum, and that is what a per-sample budget should get.
    """
    assert percentile_nearest_rank([5], 0.99) == 5
    assert percentile_nearest_rank([1, 2, 3], 0.99) == 3
    assert percentile_nearest_rank([1, 2, 3], 0.5) == 2
    with pytest.raises(VerificationError, match="no values"):
        percentile_nearest_rank([], 0.99)
    with pytest.raises(VerificationError, match="outside"):
        percentile_nearest_rank([1], 0.0)


# --- 4.2.3: the sampler's resolution, not a phantom detection ---------------
#
# The defect these cover: the fixture OOMs faster than the ~1s sampler can
# resolve, so the Sentinel - which watches continuously - detects a restart the
# runner's one-shot poll never saw. `detected != injected` on restart counts,
# the ratio went above 1, and CI run 36715114506 failed 4.2.3 against a system
# that had detected everything it was injected.


def test_the_accepted_set_is_derived_from_the_pod_not_a_constant() -> None:
    """The ceiling is read off the pod, not hardcoded.

    Pinned because the alternative - a fixed range like ``{0..5}`` - would
    silently stop matching the pod as soon as the fixture's backoff schedule or
    the observation window changed, and would do so by getting *stricter*
    without any visible edit. Two different histories must produce two
    different ceilings, and a pod nothing was read from must produce 0 rather
    than a number that lets anything through.
    """
    assert sampler_restart_ceiling(oom_at(1, 2, 3)) == 3
    assert sampler_restart_ceiling(oom_at(1, 7)) == 7
    assert sampler_restart_ceiling([]) == 0
    assert injectable_restart_counts(oom_at(1, 2, 3)) == {0, 1, 2, 3}
    assert injectable_restart_counts(oom_at(1, 7)) == set(range(8))
    assert injectable_restart_counts([]) == {0}


def test_a_detection_the_sampler_could_not_resolve_is_not_a_phantom() -> None:
    """The positive case, reproducing the live failure.

    The runner observed one 137 (at restart 1) and then saw the pod already on
    restart 2. The Sentinel detected both. The old rule called the second a
    phantom and failed; it is a resolution failure in the *sampler*, and the
    accepted set now says so. The description has to name it, or the next
    reader cannot tell a forgiven detection from an absent one.
    """
    observations = oom_then_restarted(1)
    assert sampler_restart_ceiling(observations) == 2
    incidents = [latency_record(1), latency_record(2)]
    description = check_detection_latency(incidents, observations)
    assert "2 OOMKilled detection(s)" in description
    assert "sampler misses rather than phantoms" in description
    assert "[2]" in description


def test_control_a_detection_beyond_the_final_restart_count_still_fails() -> None:
    """The defect: an incident for a restart the pod never reached.

    The allowance is bounded by the pod's own final observed state, so it
    forgives a *gap* in the sampler's record and nothing more. An incident at a
    restart count above every one the runner read is not a gap - the pod was
    never that far along - so it is a fabricated detection and must still fail.
    Without this bound the fix would degrade the check into a no-op.
    """
    observations = oom_at(1, 2)
    incidents = [latency_record(1), latency_record(2), latency_record(9)]
    with pytest.raises(VerificationError) as error:
        check_detection_latency(incidents, observations)
    message = str(error.value)
    assert "no observed injection" in message
    assert "[9]" in message
    assert "final observed restart count 2" in message


def test_control_a_wide_ceiling_does_not_launder_a_real_miss() -> None:
    """The defect: a 137 the runner saw, with no incident for it.

    **The control that makes the allowance safe.** The accepted set grows with
    the pod's restart count, so a fixture that restarts nine times accepts
    detections anywhere in ``{0..9}``. If the missing-detection direction had
    been relaxed at the same time, a high restart count would launder exactly
    the defect 4.2.3 exists to catch. Here the ceiling is 9 and the incident is
    absent for restart 3, and it must still fail.
    """
    observations = oom_then_restarted(1, 2, 3, 4, 5, 6, 7, 8)
    assert sampler_restart_ceiling(observations) == 9
    # Detections at 1, 2 and 9; the runner saw 137s at 1..8 and there is no
    # incident for restart 3. Only the miss can be responsible for the failure.
    incidents = [latency_record(1), latency_record(2), latency_record(9)]
    with pytest.raises(VerificationError) as error:
        check_detection_latency(incidents, observations)
    message = str(error.value)
    assert "Missed detection" in message
    assert "[3, 4, 5, 6, 7, 8]" in message


def test_a_faster_sampler_would_make_the_allowance_unnecessary() -> None:
    """The rule is a resolution allowance, not a permanent loosening.

    When every 137 the pod produced was also recorded by the sampler, the
    accepted set and the observed set are the same set apart from restart 0 -
    the container's first crash, which carries no ``Terminated`` state the
    sampler can have missed because there is no previous instance to lose it -
    so the rule contributes nothing to the verdict. That is the property which
    says a higher-resolution sampler *retires* the allowance rather than
    contradicting it. Asserted so a future edit that widens the accepted set
    past the pod's own final restart count breaks here first.
    """
    observations = oom_at(1, 2, 3)
    assert sampler_restart_ceiling(observations) == 3
    assert oom_restart_counts(observations) == {1, 2, 3}
    # The observed set is inside the accepted one, and the only member of the
    # accepted set with no observed 137 is restart 0, which is the one restart
    # count a sampler cannot miss: it is the first crash.
    assert oom_restart_counts(observations) <= injectable_restart_counts(observations)
    assert injectable_restart_counts(observations) - oom_restart_counts(
        observations
    ) == {0}

    description = check_detection_latency(
        [latency_record(1), latency_record(2), latency_record(3)], observations
    )
    # Nothing was forgiven, so the description carries no sampler-miss clause.
    assert "sampler misses" not in description


# ---------------------------------------------------------------------------
# 4.2.5 - the RCA is specific
# ---------------------------------------------------------------------------


def test_rca_specificity_passes_on_a_real_engine_run(checkout: pathlib.Path) -> None:
    record = triaged(chaos_document(), checkout)
    description = check_rca_is_specific([record])
    assert str(MIN_RCA_STRONG_CITATIONS) in description


# --- 4.2.5 negative controls: boilerplate must fail ------------------------


BOILERPLATE = """\
# RCA: incident

## Summary

A container failed. No automatic change is proposed.

## Remediation

Escalate to a human.
"""


def test_control_boilerplate_rca_fails() -> None:
    """The defect this box exists to catch, in the shape it actually takes.

    A template that interpolates nothing. It is long enough, well-formed
    markdown, and mentions none of the incident's own identifiers - so it
    satisfies "non-empty" and a length check, and only the specificity bar
    rejects it.
    """
    response = _tier2_shape()
    response["rca_markdown"] = BOILERPLATE
    record = captured(chaos_document(), response)

    with pytest.raises(VerificationError) as error:
        check_rca_is_specific([record])
    assert "distinctive identifiers" in str(error.value)


def test_control_a_single_weak_citation_fails() -> None:
    """The defect: an RCA that quotes only the exit code.

    The weak/strong split is the substance here. "137" is a distinctive number
    and "2" is not - but a *bare* ``restart_count`` of 2 occurs inside
    ``TIER_2``, ``SEV2`` and every ordinal in the document, so a substring test
    on an integer can be satisfied by prose that never looked at the payload.
    Quoting only integers is therefore not specificity.
    """
    response = _tier2_shape()
    response["rca_markdown"] = (
        "# RCA\n\nreason OOMKilled, exit_code=137, restart_count=1, nothing else."
    )
    with pytest.raises(VerificationError, match="distinctive identifiers"):
        check_rca_is_specific([captured(chaos_document(), response)])


def test_control_an_empty_rca_fails() -> None:
    """The defect: a whitespace-only RCA.

    ``TriageResponse.rca_markdown`` has ``min_length=1``, so a captured 200 with
    an empty RCA means the agent or the capture is not what the runner assumes.
    That is worth failing on rather than skipping.
    """
    response = _tier2_shape()
    response["rca_markdown"] = "   \n  "
    with pytest.raises(VerificationError, match="empty on a captured 200"):
        check_rca_is_specific([captured(chaos_document(), response)])


def test_control_an_rca_identical_across_restarts_fails() -> None:
    """The defect: a template that interpolates only the incident id.

    Both RCAs are individually specific enough to pass the citation bar and both
    cite the *same* restart count, so only the cross-incident comparison catches
    the one that is really a template. The response bodies differ (different ids
    and restart counts), so nothing about the payloads is identical - only the
    prose is, which is the whole point.
    """
    shared_rca = (
        f"# RCA: oom-canary in {CHAOS_NAMESPACE}\n\n"
        f"exit 137, restart_count=1, memory_limit=64Mi, "
        f"pod=srek3s-chaos-oom-7d9f4b6c8d-x2k9p"
    )
    first_response = _tier2_shape()
    first_response["rca_markdown"] = shared_rca
    second_response = _tier2_shape()
    second_response["rca_markdown"] = shared_rca

    first = captured(
        chaos_document(incident_id="inc_01M3M6W9ENH28NJS8C5T1665PA"), first_response
    )
    second = captured(
        chaos_document(incident_id="inc_01M3M6W9ENH28NJS8C5T1665PB", restart_count=2),
        second_response,
    )
    with pytest.raises(VerificationError, match="byte-identical"):
        check_rca_is_specific([first, second])


def test_distinct_incidents_may_legitimately_share_no_prose(
    checkout: pathlib.Path,
) -> None:
    """The mirror, so the boilerplate control is not just "two of anything fails".

    Two real engine runs at different restart counts produce different RCAs -
    the dispatch quotes the restart count - so a correct system passes this
    control's own precondition. Asserted, because a control that fires on
    *every* pair would be indistinguishable from a check that rejects valid
    data, which is the other way an invariant becomes worse than a missing one.
    """
    first = triaged(chaos_document(restart_count=1), checkout)
    second = triaged(
        chaos_document(incident_id="inc_01M3M6W9ENH28NJS8C5T1665PB", restart_count=3),
        checkout,
    )
    first_rca = first[CAPTURE_KEY]["upstream_body"]["rca_markdown"]
    second_rca = second[CAPTURE_KEY]["upstream_body"]["rca_markdown"]
    assert first_rca != second_rca
    check_rca_is_specific([first, second])


def test_control_no_captured_response_fails_rather_than_skipping() -> None:
    """The defect: no response at all, where the check would otherwise skip.

    ``check_rca_is_specific`` raises rather than returning SKIP when the capture
    carries records but none of them has a body - because at that point the
    agent answered nothing useful and every response assertion would otherwise
    be skipped on a broken run.
    """
    with pytest.raises(VerificationError, match="would be vacuous"):
        check_rca_is_specific([captured(chaos_document(), None)])


def test_citable_facts_omits_fields_the_payload_does_not_carry() -> None:
    """The bar is never set by a field the emitter nulled out.

    ``exit_code`` is null for a CrashLoopBackOff, and demanding the string
    ``"None"`` appear in the RCA would be demanding a falsehood. Checked by
    name rather than by a golden dict, so adding a citable field later does not
    break this test.
    """
    facts = citable_facts(
        chaos_document(reason="CrashLoopBackOff", exit_code=None, restart_count=2)
    )
    assert "exit_code" not in facts
    assert "restart_count" in facts
    assert facts["container_name"] == "oom-canary"
    assert set(RCA_STRONG_FACTS).issubset(facts)


# ---------------------------------------------------------------------------
# 4.2.6 - the Tier-1 patch, handed to real git
# ---------------------------------------------------------------------------


def test_tier_one_patch_passes_against_the_real_manifest(
    checkout: pathlib.Path, manifest_text: str
) -> None:
    """The positive case, over the real fixture and a real `git apply`.

    Not a hand-written diff. ``tests/e2e/verify_patch.py`` documents the P0
    that survived 410 green tests precisely because every earlier check used a
    hand-written diff or a checker that repaired its input.
    """
    record = triaged(chaos_document(), checkout)
    assert tier_of(record) == TIER_1, "the fixture no longer reaches Tier-1"
    description = check_tier_one_patch(record, manifest_text)
    assert "git apply --check" in description
    assert "exactly one changed field" in description


def test_tier_one_patches_aggregates(
    checkout: pathlib.Path, manifest_text: str
) -> None:
    incidents = [triaged(chaos_document(), checkout)]
    assert "1 Tier-1 patch(es)" in check_tier_one_patches(incidents, manifest_text)


# --- 4.2.6 negative controls ----------------------------------------------


def test_control_a_tampered_patch_is_rejected_by_real_git(
    checkout: pathlib.Path, manifest_text: str
) -> None:
    """The defect: a diff that does not apply to the manifest it names.

    The context lines are altered so the hunk no longer matches. An earlier
    generation of checks in this repository used an applier that *repaired* its
    input, so this is the control for the specific mistake of verifying a
    doctored copy of the artifact instead of the artifact.
    """
    record = triaged(chaos_document(), checkout)
    diff = record[CAPTURE_KEY]["upstream_body"]["remediation"]["git_patch"]
    tampered = diff.replace(
        "-              memory: 64Mi", "-              memory: 32Mi"
    )
    assert tampered != diff, "the tamper did not change the diff"

    record[CAPTURE_KEY]["upstream_body"]["remediation"]["git_patch"] = tampered
    with pytest.raises(VerificationError, match="git rejected the patch"):
        check_tier_one_patch(record, manifest_text)


def test_control_an_unterminated_diff_is_rejected(
    checkout: pathlib.Path, manifest_text: str
) -> None:
    """The P0 itself, re-asserted at the runner's own layer.

    ``build_diff`` used to omit the trailing newline and ``git_apply_check``
    used to append it, so the gate reported ``patch_validated: True`` for a
    patch no GitOps pipeline would accept. The runner writes the bytes exactly
    as given, so this fires where the old checker did not.
    """
    record = triaged(chaos_document(), checkout)
    remediation = record[CAPTURE_KEY]["upstream_body"]["remediation"]
    remediation["git_patch"] = remediation["git_patch"].rstrip("\n")

    with pytest.raises(VerificationError):
        check_tier_one_patch(record, manifest_text)


#: A manifest whose two adjacent limit lines sit inside one 3-line hunk, so a
#: diff that edits **both** is a single well-formed hunk rather than a diff
#: spanning the whole file. Built for the two-field control, which has to be a
#: diff real git accepts - otherwise it would be rejected by the format layer
#: and the semantic layer it is meant to exercise would never run.
TWO_FIELD_MANIFEST = """\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: srek3s-chaos-oom
spec:
  template:
    spec:
      containers:
        - name: oom-canary
          resources:
            limits:
              cpu: 500m
              memory: 64Mi
              ephemeral-storage: 1Gi
          image: busybox:1.36.1
"""


def _hunk(first_line: int, body: list[str]) -> str:
    """Wrap hunk ``body`` in a header with the counts computed from the body.

    Hand-typed hunk headers are the classic way a *control* diff stops being
    valid git and starts passing a real check for the wrong reason - the
    rejection then comes from the format layer and the semantic layer it was
    written to exercise never runs. Computing the counts is the only way to
    keep "this is a well-formed diff" an assumption rather than a hope.
    """
    old = sum(1 for line in body if not line.startswith("+"))
    new = sum(1 for line in body if not line.startswith("-"))
    header = f"--- a/{TARGET}\n+++ b/{TARGET}\n@@ -{first_line},{old} +{first_line},{new} @@\n"
    return header + "\n".join(body) + "\n"


def _two_field_diff() -> str:
    """A single hunk editing both ``cpu`` and ``memory``."""
    return _hunk(
        10,
        [
            "           resources:",
            "             limits:",
            "               cpu: 500m",
            "-              memory: 64Mi",
            "+              memory: 128Mi",
            "+              cpu: 250m",
            "               ephemeral-storage: 1Gi",
            "           image: busybox:1.36.1",
        ],
    )


def test_control_a_patch_changing_two_fields_is_rejected() -> None:
    """The defect: a valid diff that edits more than the stated limit.

    Real git accepts this - the hunk is well-formed and the context matches - so
    the rejection can only come from the YAML AST walk. The precondition is
    asserted first, because a control that is rejected by the *format* layer
    would pass while leaving the semantic layer untested.
    """
    record = captured(chaos_document(), None)
    record[CAPTURE_KEY]["upstream_body"] = {
        "blast_radius_tier": TIER_1,
        "remediation": {
            "summary": "Raise the 'oom-canary' memory limit from 64Mi to 128Mi.",
            "risk_level": "LOW",
            "target_manifest": TARGET,
            "git_patch": _two_field_diff(),
            "patch_validated": True,
        },
    }

    ok, reason, patched = git_apply(
        TWO_FIELD_MANIFEST, _two_field_diff(), TARGET, check_only=False
    )
    assert ok, f"the control must be valid git or it proves nothing: {reason}"
    assert "cpu: 250m" in patched

    with pytest.raises(VerificationError) as error:
        check_tier_one_patch(record, TWO_FIELD_MANIFEST)
    message = str(error.value)
    assert "semantic" in message and "expected exactly one" in message, message


def test_control_a_patch_on_the_wrong_field_is_rejected() -> None:
    """The defect: a valid diff that changes the wrong field entirely.

    A textually perfect, git-acceptable patch that moves the limit onto
    ``cpu`` instead of ``memory``. It is caught by the YAML AST walk, and only
    by it - which is precisely why that layer exists.
    """
    wrong = _hunk(
        10,
        [
            "           resources:",
            "             limits:",
            "-              cpu: 500m",
            "+              cpu: 250m",
            "               memory: 64Mi",
            "               ephemeral-storage: 1Gi",
            "           image: busybox:1.36.1",
        ],
    )
    record = captured(chaos_document(), None)
    record[CAPTURE_KEY]["upstream_body"] = {
        "blast_radius_tier": TIER_1,
        "remediation": {
            "summary": "Raise the 'oom-canary' memory limit from 64Mi to 128Mi.",
            "risk_level": "LOW",
            "target_manifest": TARGET,
            "git_patch": wrong,
            "patch_validated": True,
        },
    }

    ok, reason, patched = git_apply(TWO_FIELD_MANIFEST, wrong, TARGET, check_only=False)
    assert ok, f"the control must be valid git or it proves nothing: {reason}"
    assert "memory: 64Mi" in patched, "the wrong-field patch must not touch memory"

    with pytest.raises(VerificationError) as error:
        check_tier_one_patch(record, TWO_FIELD_MANIFEST)
    message = str(error.value)
    assert "expected exactly one" in message, message


def _yaml(text: str) -> Any:
    import yaml

    return yaml.safe_load(text)


def test_semantic_change_paths_reports_more_than_one_field() -> None:
    """The primitive 4.2.6 leans on, tested directly.

    Without this, the two-field test above could pass because of a git failure
    rather than because the differ works, and the box would be a green check
    over an untested helper.
    """
    left = _yaml(
        "spec:\n  template:\n    spec:\n      containers:\n"
        "        - name: a\n          resources:\n            limits:\n"
        "              memory: 64Mi\n              cpu: 500m\n"
    )
    right = _yaml(
        "spec:\n  template:\n    spec:\n      containers:\n"
        "        - name: a\n          resources:\n            limits:\n"
        "              memory: 128Mi\n              cpu: 1\n"
    )
    paths = semantic_change_paths(left, right)
    assert len(paths) == 2, paths
    assert all(path[-1] in {"memory", "cpu"} for path in paths)


def test_a_type_change_is_always_a_difference() -> None:
    """``256`` and ``"256"`` are not the same document.

    A Kubernetes quantity must not silently change type, and a differ that
    compared with ``==`` would report no change between an int and its decimal
    string - a patch that quoted every quantity in the file would pass it.
    """
    assert semantic_change_paths(1, 1.0) == [("<root>",)]
    assert semantic_change_paths("256", 256) == [("<root>",)]


def test_control_a_declared_path_mismatch_is_rejected(
    checkout: pathlib.Path, manifest_text: str
) -> None:
    """The defect: the diff and the response name different files.

    A reviewer would be sent to one file and handed a diff for another. Cheap
    to assert, and it is the only check that can catch it - git applies
    whatever it is given.
    """
    record = triaged(chaos_document(), checkout)
    record[CAPTURE_KEY]["upstream_body"]["remediation"][
        "target_manifest"
    ] = "deploy/other/somewhere.yaml"
    with pytest.raises(VerificationError, match="the diff declares"):
        check_tier_one_patch(record, manifest_text)


def test_control_a_summary_that_omits_the_change_is_rejected(
    checkout: pathlib.Path, manifest_text: str
) -> None:
    """The defect: a correct patch with a wrong *description*.

    The single most important negative control for "matches the stated root
    cause": the diff applies, parses, and changes exactly the right field, and
    is still not the change the responder was told to review. Only step 6 of
    the check catches this, which is why step 6 exists.
    """
    record = triaged(chaos_document(), checkout)
    record[CAPTURE_KEY]["upstream_body"]["remediation"][
        "summary"
    ] = "Bump the memory limit a little to stop the thrash."
    with pytest.raises(VerificationError, match="does not name"):
        check_tier_one_patch(record, manifest_text)


def test_control_a_tier_one_response_with_no_patch_is_rejected(
    checkout: pathlib.Path,
) -> None:
    """The defect: TIER_1 in the tier field and an empty patch.

    I-B1's mirror. The schema forbids a Tier-2 response carrying a patch; the
    Tier-1-without-one direction is what ROADMAP §5.1's "iff" requires and what
    the runner asserts, because a reviewer told "Tier-1" and handed nothing has
    no way to tell that from a capture bug.
    """
    record = triaged(chaos_document(), checkout)
    response = record[CAPTURE_KEY]["upstream_body"]
    response["remediation"]["git_patch"] = ""
    with pytest.raises(VerificationError, match="requires a Tier-1 incident to carry"):
        check_tier_one_patch(record, "")


def test_no_tier_one_incident_is_a_skip_not_a_pass(
    checkout: pathlib.Path,
) -> None:
    """A run with no Tier-1 incident must say "unproven", not "0 patches, fine".

    The exact shape of the unticked-box problem: reporting success for a check
    that never ran. The SKIP prefix is the machine-readable half of the answer
    and the test asserts on it, so a future "return 0 patches" edit fails.
    """
    result = check_tier_one_patches([crashloop_record(checkout)], None)
    assert result.startswith(SKIP_PREFIX)
    assert "4.2.6 is unproven" in result


def test_a_tier_one_incident_with_no_manifest_is_a_failure() -> None:
    """The defect: asserting on a patch without the file it targets.

    Not a skip. The agent emitted a Tier-1 patch and the harness could not
    verify it, which is precisely the situation 4.2.6 exists to catch - and the
    agent's own I-B2 check ran against *its* copy, so a divergence between that
    and the real checkout is invisible unless this fails.
    """
    incidents = [
        captured(
            chaos_document(),
            {
                "blast_radius_tier": TIER_1,
                "remediation": {"git_patch": "diff", "target_manifest": TARGET},
            },
        )
    ]
    with pytest.raises(VerificationError, match="no manifest was supplied"):
        check_tier_one_patches(incidents, None)


def test_declared_patch_path_is_read_from_the_diff() -> None:
    """The path comes from the artifact, not from a constant.

    A helper that returned ``TARGET_MANIFEST`` unconditionally would make the
    mismatch check above unfireable.
    """
    diff = "--- a/deploy/payments/checkout-api.yaml\n+++ b/deploy/other/x.yaml\n@@ -1,1 +1,1 @@\n"
    assert declared_patch_path(diff) == "deploy/other/x.yaml"
    assert declared_patch_path("not a diff") is None


# ---------------------------------------------------------------------------
# 4.2.7 - Tier-2 carries no patch and a dispatch was emitted
# ---------------------------------------------------------------------------


def test_tier_two_dispatch_passes_on_a_real_engine_run(
    checkout: pathlib.Path,
) -> None:
    """The positive case, on a document the real engine produced.

    The Tier-2 path is forced by ``reason="CrashLoopBackOff"`` rather than by
    withholding a manifest, so the check cannot start passing or failing
    because the provider wiring changed.
    """
    record = crashloop_record(checkout)
    assert tier_of(record) == TIER_2
    description = check_tier_two_dispatch(record)
    assert "no patch, dispatch marker present" in description

    # And the marker it looked for is genuinely in the payload the engine
    # emitted - the assertion above is on the summary, so this is what proves
    # the summary is describing reality.
    body = record[CAPTURE_KEY]["upstream_body"]
    assert WAR_ROOM_DO_NOT_APPLY_MARKER in body["rca_markdown"]


def test_tier_two_dispatches_aggregates(checkout: pathlib.Path) -> None:
    description = check_tier_two_dispatches([crashloop_record(checkout)])
    assert "1 Tier-2 incident(s)" in description


# --- 4.2.7 negative controls ----------------------------------------------


def test_control_a_tier_two_patch_is_rejected() -> None:
    """The defect: I-B1 violated on the wire - Tier-2 with a diff attached.

    The most consequential regression available to this file. The agent's own
    schema refuses to construct such a response, so the only way it appears is
    a serialisation layer that added a field, or a schema that stopped
    enforcing. Neither is visible from inside the model, which is exactly why
    the runner reads the bytes.
    """
    response = _tier2_shape()
    response["remediation"]["git_patch"] = "--- a/x\n+++ b/x\n@@ -1,1 +1,1 @@\n"
    with pytest.raises(VerificationError, match="carries a .*git_patch"):
        check_tier_two_dispatch(captured(chaos_document(), response))


def test_control_patch_validated_true_on_tier_two_is_rejected() -> None:
    """The defect: the other half of I-B1.

    A Tier-2 response claiming its (absent) patch was validated is a lie about
    verification, and it is the half a reviewer would read first.
    """
    response = _tier2_shape()
    response["remediation"]["patch_validated"] = True
    with pytest.raises(VerificationError, match="patch_validated is True"):
        check_tier_two_dispatch(captured(chaos_document(), response))


def test_control_a_missing_dispatch_marker_is_rejected() -> None:
    """The defect: Tier-2 with no war-room dispatch in the deliverable.

    This is the assertion that makes 4.2.7 mean something. Without it, "Tier-2
    and no patch" would be satisfied by a response that told a responder
    nothing about *not applying anything* - which is the one sentence the
    dispatch exists to deliver.
    """
    response = _tier2_shape()
    response["rca_markdown"] = "## RCA\n\nNo change proposed.\n"
    with pytest.raises(VerificationError) as error:
        check_tier_two_dispatch(captured(chaos_document(), response))
    assert WAR_ROOM_DO_NOT_APPLY_MARKER in str(error.value)


def test_control_a_triaged_status_on_tier_two_is_rejected() -> None:
    """The defect: a self-contradicting response.

    ``status: TRIAGED`` beside an empty patch is a verdict that contradicts
    itself, and a consumer branching on the status rather than the tier would
    treat it as actioned.
    """
    response = _tier2_shape()
    response["status"] = "TRIAGED"
    with pytest.raises(VerificationError, match="reporting TRIAGED"):
        check_tier_two_dispatch(captured(chaos_document(), response))


def test_control_a_wrong_verification_mode_is_rejected() -> None:
    """The defect: the Tier-2 observation mode was never selected.

    ``mode`` is what the post-remediation loop keys on, and a Tier-2 response
    carrying ``POST_REMEDIATION_OBSERVATION`` would have a loop waiting to
    confirm a fix that was never proposed.
    """
    response = _tier2_shape()
    response["verification_policy"]["mode"] = "POST_REMEDIATION_OBSERVATION"
    with pytest.raises(VerificationError, match="TIER_2_WAR_ROOM"):
        check_tier_two_dispatch(captured(chaos_document(), response))


def test_control_a_crashloop_capture_with_no_tier_two_fails() -> None:
    """The vacuity guard for 4.2.7, and the sharpest one in this file.

    ROADMAP 4.2.7 reads "for each Tier-2 incident, ...". A capture containing
    a ``CrashLoopBackOff`` exchange and **no** Tier-2 response satisfies that
    sentence trivially - and ARCH §5.3 admits Tier-1 only for ``OOMKilled``,
    so a dispatch was *required*. Without this the box would tick on a run
    where the agent silently dropped every escalation.
    """
    response = _tier2_shape()
    response["blast_radius_tier"] = TIER_1
    incidents = [
        captured(
            chaos_document(reason="CrashLoopBackOff", exit_code=None, restart_count=2),
            response,
        )
    ]
    with pytest.raises(VerificationError) as error:
        check_tier_two_dispatches(incidents)
    assert "no Tier-2 response" in str(error.value)
    assert "required" in str(error.value)


def test_an_all_tier_one_capture_is_a_stated_failure_not_a_silent_pass() -> None:
    """The same guard, on a capture with no Tier-2-*capable* reason.

    Reported as a failure with the reason stated, not as a skip: the run did not
    exercise 4.2.7 and the report must say so in a way a reader cannot miss.
    """
    response = _tier2_shape()
    response["blast_radius_tier"] = TIER_1
    with pytest.raises(VerificationError, match="not exercised by this run"):
        check_tier_two_dispatches([captured(chaos_document(), response)])


def test_no_captured_response_is_a_skip(checkout: pathlib.Path) -> None:
    """The offline direction: nothing captured, so nothing to assert.

    A skip, not a failure, because the offline fixtures genuinely have no agent
    response. ``_verify_response_half`` is the place that decides a total skip
    is allowed, and it records the reason.
    """
    result = check_tier_two_dispatches([captured(chaos_document(), None)])
    assert result.startswith(SKIP_PREFIX)


def test_the_runner_asserts_on_the_real_war_room_marker() -> None:
    """Drift guard between the runner and ``agent.warroom``.

    The runner keeps its own copy of the marker so it stays importable with no
    dependency on the agent's package. That duplication is a real cost, and the
    only thing that makes it acceptable is this test: a wording change to
    ``DO_NOT_APPLY`` that is not mirrored here fails the build instead of
    failing an E2E run four weeks later with an unexplainable assertion.
    """
    assert WAR_ROOM_DO_NOT_APPLY_MARKER in warroom.DO_NOT_APPLY
    assert len(WAR_ROOM_DO_NOT_APPLY_MARKER) > 30, (
        "the marker is too short to be a distinctive prefix; a shortened "
        "constant would make this check pass on a reworded dispatch"
    )


# ---------------------------------------------------------------------------
# 4.2.8 - no cluster mutation
# ---------------------------------------------------------------------------


def snapshot_entry(
    namespace: str, generation: int = 1, resource_version: str = "100"
) -> dict[str, Any]:
    return {
        "generation": generation,
        "namespace": namespace,
        "resourceVersion": resource_version,
        "uid": f"uid-{namespace}",
    }


def healthy_pair() -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    before = {
        "v1/Deployment/default/web": snapshot_entry("default"),
        "v1/Deployment/kube-system/coredns": snapshot_entry("kube-system"),
        f"apps/v1/Deployment/{CHAOS_NAMESPACE}/srek3s-chaos-oom": snapshot_entry(
            CHAOS_NAMESPACE, generation=1, resource_version="200"
        ),
    }
    after = dict(before)
    after[f"apps/v1/Deployment/{CHAOS_NAMESPACE}/srek3s-chaos-oom"] = snapshot_entry(
        CHAOS_NAMESPACE, generation=2, resource_version="900"
    )
    return before, after


def test_an_unchanged_cluster_passes() -> None:
    before, after = healthy_pair()
    description = check_no_cluster_mutation(before, after)
    assert "no mutation outside" in description
    # One *object* changed, not one field: the chaos Deployment moved both its
    # generation and its resourceVersion, and reporting that as two changes
    # would misdescribe what the run did. The tally also covers objects the
    # fixture *created* in the chaos namespace, because a run that only mutated
    # something already present is not what the harness does.
    assert "1 object(s) appeared or changed inside the chaos namespace" in description


# --- 4.2.8 negative controls ----------------------------------------------


def test_control_a_generation_change_outside_chaos_fails() -> None:
    """The defect: a spec write outside the chaos namespace.

    ``generation`` is a spec-change counter the apiserver does not bump for a
    status update, so this is the check that survives a live cluster. It is the
    one that would catch a Sentinel that patched a Deployment.
    """
    before, after = healthy_pair()
    after["v1/Deployment/default/web"] = snapshot_entry(
        "default", generation=2, resource_version="101"
    )
    with pytest.raises(VerificationError, match="changed generation"):
        check_no_cluster_mutation(before, after)


def test_control_a_create_outside_chaos_fails() -> None:
    """The defect: an object created where none was.

    A generation comparison alone would miss a create entirely, and a create is
    the cheapest possible demonstration of write authority.
    """
    before, after = healthy_pair()
    after["v1/Secret/default/stolen"] = snapshot_entry("default", resource_version="1")
    with pytest.raises(VerificationError, match="were created outside"):
        check_no_cluster_mutation(before, after)


def test_control_a_delete_outside_chaos_fails() -> None:
    """The defect: an object removed."""
    before, after = healthy_pair()
    del after["v1/Deployment/default/web"]
    with pytest.raises(VerificationError, match="were deleted outside"):
        check_no_cluster_mutation(before, after)


def test_control_a_resource_version_change_outside_chaos_fails() -> None:
    """The defect: a write with no generation bump - a status update, or a patch.

    Broader than the generation check, which is why it is the one that needs
    the noisy-namespace exclusion below.
    """
    before, after = healthy_pair()
    after["v1/Deployment/default/web"] = snapshot_entry(
        "default", resource_version="777"
    )
    with pytest.raises(VerificationError, match="changed resourceVersion"):
        check_no_cluster_mutation(before, after)


def test_kube_system_churn_is_excluded_but_counted() -> None:
    """The honest form of the exclusion: narrow, named, and visible.

    ``kube-system`` holds a leader-election lease every control-plane component
    renews on a timer, and k3s's Helm controller installs and upgrades coredns
    and traefik **asynchronously** - after any pre-flight baseline is taken. All
    three sub-checks now exempt it, and every exempted change is **counted and
    reported** rather than dropped.

    The generation half is asserted as *excluded and counted* rather than
    *still failing*. That is a real change in what this check can catch, and it
    is the price of a check that runs at all on a live k3s: a control-plane
    Deployment rolling under its own controller is indistinguishable from a spec
    write by a component under test. The narrowing is stated here, and the
    controls below pin the part that was not given up - every namespace outside
    the exempt set is still asserted on all three sub-checks.
    """
    assert "kube-system" in NOISY_SYSTEM_NAMESPACES
    before, after = healthy_pair()
    after["v1/Deployment/kube-system/coredns"] = snapshot_entry(
        "kube-system", resource_version="9999"
    )
    description = check_no_cluster_mutation(before, after)
    assert "1 object(s) churned inside the exempt system namespaces" in description
    assert "1 resourceVersion change(s)" in description

    # A generation bump there is excluded too, and counted separately, so a
    # reader can see that a control-plane roll happened rather than infer it.
    after["v1/Deployment/kube-system/coredns"] = snapshot_entry(
        "kube-system", generation=99, resource_version="9999"
    )
    description = check_no_cluster_mutation(before, after)
    assert "1 generation change(s)" in description


def test_control_a_create_in_a_noisy_namespace_is_excluded_but_counted() -> None:
    """The live failure, reproduced: coredns appears between the two images.

    k3s installs coredns through a Helm controller that finishes after the
    pre-flight snapshot, so its objects exist only in the after-image. Reported
    as a *creation* by a component that structurally holds no write credential,
    this failed 4.2.8 on CI run 36715114506. It is background noise, and the
    check now says so - while counting it, so the exclusion stays visible.
    """
    before, after = healthy_pair()
    after["apps/v1/Deployment/kube-system/coredns"] = snapshot_entry(
        "kube-system", resource_version="1"
    )
    after["v1/ConfigMap/kube-system/coredns"] = snapshot_entry(
        "kube-system", resource_version="1"
    )
    description = check_no_cluster_mutation(before, after)
    assert "2 created" in description
    assert "Helm install/upgrade" in description


def test_control_a_create_outside_chaos_still_fails_after_the_exemption() -> None:
    """**The control that makes the exemption safe.**

    The defect: an object created outside both the chaos namespace and the
    exempt set - a component under test using write authority it does not hold.
    Every namespace in :data:`NOISY_SYSTEM_NAMESPACES` is checked here, because
    the failure mode of a namespace-set exemption is a set that is one entry too
    wide, and ``default`` is where a real agent or Sentinel write would land.

    This is the box 4.2.8 exists to check, so it is asserted per namespace
    rather than once: an exemption that silences the check defeats the box, and
    the only defence is a control that fires after the exemption is in place.
    """
    for namespace in ("default", "srek3s-system", "payments"):
        before, after = healthy_pair()
        after[f"v1/Secret/{namespace}/stolen"] = snapshot_entry(
            namespace, resource_version="1"
        )
        with pytest.raises(VerificationError, match="were created outside"):
            check_no_cluster_mutation(before, after)


def test_control_the_exemption_is_an_exact_namespace_match() -> None:
    """The defect: a namespace that merely *looks* like an exempt one.

    The printer this check replaced matched with a substring test, so
    ``kube-system-staging`` and ``my-kube-system`` were silently treated as
    control-plane namespaces. A prefix or substring exemption turns the one
    check that catches an out-of-namespace write into a no-op over a whole
    family of names, and it would have done so invisibly. Exact match only.
    """
    for namespace in ("kube-system-staging", "my-kube-system", "kube-systemx"):
        assert namespace not in NOISY_SYSTEM_NAMESPACES
        before, after = healthy_pair()
        after[f"v1/Secret/{namespace}/stolen"] = snapshot_entry(
            namespace, resource_version="1"
        )
        with pytest.raises(VerificationError, match="were created outside"):
            check_no_cluster_mutation(before, after)
    # And it must not be a one-way door: a spec write there fails too. Seeded
    # into both images so the object-set check stays quiet and the generation
    # check is the one under test.
    before, after = healthy_pair()
    before["v1/Deployment/kube-system-staging/web"] = snapshot_entry(
        "kube-system-staging", generation=1, resource_version="1"
    )
    after["v1/Deployment/kube-system-staging/web"] = snapshot_entry(
        "kube-system-staging", generation=2, resource_version="2"
    )
    with pytest.raises(VerificationError, match="changed generation"):
        check_no_cluster_mutation(before, after)


def test_control_a_delete_outside_chaos_still_fails_after_the_exemption() -> None:
    """The defect: an object removed, outside both exempt sets.

    The reverse direction of the object-set check, and the one most likely to be
    forgotten when an exemption is added: a create is caught by the "was it
    there before" half and a delete by the "is it still there" half, and they
    are separate predicates in separate lists.
    """
    before, after = healthy_pair()
    del after["v1/Deployment/default/web"]
    with pytest.raises(VerificationError, match="were deleted outside"):
        check_no_cluster_mutation(before, after)

    # And inside an exempt namespace, a delete is absorbed and counted rather
    # than failed - the k3s control plane garbage-collects its own objects.
    before, after = healthy_pair()
    del after["v1/Deployment/kube-system/coredns"]
    description = check_no_cluster_mutation(before, after)
    assert "1 deleted" in description


def test_the_chaos_namespace_exemption_is_preserved() -> None:
    """Everything inside the chaos namespace is allowed, on all three checks.

    The harness applies the fixture there itself, so the Deployment appears, its
    generation moves and its pods churn. A check that asserted any of that
    would fail every run against the harness's own hand.
    """
    before, after = healthy_pair()
    after[f"apps/v1/ReplicaSet/{CHAOS_NAMESPACE}/srek3s-chaos-oom-abc"] = (
        snapshot_entry(CHAOS_NAMESPACE, resource_version="1")
    )
    after[f"v1/Pod/{CHAOS_NAMESPACE}/srek3s-chaos-oom-abc-xyz"] = snapshot_entry(
        CHAOS_NAMESPACE, resource_version="1"
    )
    after[f"v1/ConfigMap/{CHAOS_NAMESPACE}/chaos"] = snapshot_entry(
        CHAOS_NAMESPACE, resource_version="1"
    )
    description = check_no_cluster_mutation(before, after)
    assert "no mutation outside" in description
    # Attributed to the chaos namespace, not to the control plane. The two are
    # exempt for entirely different reasons and a report that merged them would
    # make a reviewer read harness work as cluster noise.
    assert "4 object(s) appeared or changed inside the chaos namespace" in description
    assert "3 created" in description
    assert "0 object(s) churned inside the exempt system namespaces" in description


def test_a_chaos_namespace_that_is_only_a_prefix_is_not_exempt() -> None:
    """The chaos exemption is exact too, and the same reason applies.

    ``sentinel-chaos-evil`` is not the fixture namespace. A prefix match here
    would exempt a second workload that no fixture describes, which is exactly
    where a real write would hide.
    """
    before, after = healthy_pair()
    after["v1/Secret/sentinel-chaos-evil/stolen"] = snapshot_entry(
        "sentinel-chaos-evil", resource_version="1"
    )
    with pytest.raises(VerificationError, match="were created outside"):
        check_no_cluster_mutation(before, after)


def test_a_one_sided_snapshot_is_a_failure_not_a_skip() -> None:
    """The defect: a harness that took only a before-image.

    "Nothing changed" and "nothing was looked at" are indistinguishable from a
    missing half, and treating it as a skip would hide the wiring mistake. This
    is the fourth instance of that shape in this project.
    """
    before, _ = healthy_pair()
    report = RunReport()
    from runner import _verify_no_mutation

    _verify_no_mutation(report, before, None)
    assert not report.passed
    assert any("--snapshot-after" in failure for failure in report.failures)

    report = RunReport()
    _verify_no_mutation(report, None, before)
    assert any("--snapshot-before" in failure for failure in report.failures)


def test_no_snapshot_at_all_is_a_stated_skip() -> None:
    """The offline direction, and it is a skip with a reason, not a pass."""
    from runner import _verify_no_mutation

    report = RunReport()
    _verify_no_mutation(report, None, None)
    assert report.passed
    assert report.skipped and "4.2.8" in report.skipped[0]


def test_load_snapshot_reports_a_corrupt_file(tmp_path: pathlib.Path) -> None:
    """A truncated snapshot must be named, not silently treated as absent."""
    path = tmp_path / "snap.json"
    path.write_text('{"a": {"gener', encoding="utf-8")
    with pytest.raises(VerificationError, match="not valid JSON"):
        _load_snapshot(str(path))

    with pytest.raises(VerificationError, match="could not be read"):
        _load_snapshot(str(tmp_path / "absent.json"))


# --- 4.2.8: the printer and the verdict must not tell different stories ------


def _write_snapshots(
    tmp_path: pathlib.Path,
    before: dict[str, dict[str, Any]],
    after: dict[str, dict[str, Any]],
) -> tuple[str, str]:
    before_path = tmp_path / "before.json"
    after_path = tmp_path / "after.json"
    before_path.write_text(json.dumps(before, indent=2), encoding="utf-8")
    after_path.write_text(json.dumps(after, indent=2), encoding="utf-8")
    return str(before_path), str(after_path)


def test_the_printer_prints_exactly_the_objects_that_fail_the_verdict(
    tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The defect: a clean console beside a red exit code.

    ``show_mutation.py`` carried its own ``SYSTEM_PREFIXES`` tuple and matched
    with a substring test, so it excluded a *different* set of objects from the
    one the verdict was computed over - and it did not know the chaos namespace
    at all, so it printed the harness's own fixture under "CREATED". A reviewer
    reading that section would see nothing wrong while the job failed on the
    same objects. The printer is a diagnostic for the verdict, so a disagreement
    between them is itself a defect, and this asserts the two agree.
    """
    # Function-local, and ignored for mypy: `tests/e2e` is a directory of
    # standalone scripts rather than a package, so it is reachable through the
    # `sys.path` entry at the top of this file. The gate invokes
    # `mypy --strict agent/ tests/`, and passing `tests/` gives mypy those
    # scripts as roots, so the module resolves and needs no ignore here.
    #
    # An earlier version carried `# type: ignore[import-not-found]` on the
    # strength of "mypy reports an unresolved module once per file". That was
    # reasoned from `mypy --strict agent/` alone - a narrower invocation than
    # the gate - and under the real gate the ignore is unused, which
    # --strict reports. Verified against the gate rather than against a guess
    # about which invocation matters.
    import show_mutation

    before, after = healthy_pair()
    after["apps/v1/Deployment/kube-system/coredns"] = snapshot_entry(
        "kube-system", resource_version="1"
    )
    after[f"apps/v1/Deployment/{CHAOS_NAMESPACE}/srek3s-chaos-oom"] = snapshot_entry(
        CHAOS_NAMESPACE, resource_version="1"
    )
    after["v1/Secret/default/stolen"] = snapshot_entry("default", resource_version="1")
    before_path, after_path = _write_snapshots(tmp_path, before, after)

    printed = show_mutation.main([before_path, after_path])
    assert printed == 0
    output = capsys.readouterr().out

    # The verdict fails, and it must fail on exactly one object.
    with pytest.raises(VerificationError) as error:
        check_no_cluster_mutation(before, after)
    offending = "v1/Secret/default/stolen"
    assert offending in str(error.value)

    # The printer lists that object, and its stated verdict is a failure. Both
    # come from the runner, so neither can be quietly wrong.
    assert offending in output
    assert "VERDICT: FAIL" in output
    assert offending in output.split("VERDICT: FAIL")[1]
    # Neither exempt object is listed as offending.
    listed = output.split("CREATED outside")[1].split("exempt churn")[0]
    assert "kube-system/coredns" not in listed
    assert "srek3s-chaos-oom" not in listed


def test_control_the_printer_agrees_on_a_clean_run(
    tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The other direction: a run that passes prints nothing alarming.

    A printer that lists an object the runner accepts would be its own kind of
    lie, and it is the direction a reviewer is most likely to act on - a red
    line in the artifacts step sends someone hunting for a write that did not
    happen.
    """
    import show_mutation  # noqa: PLC0415 - see the note on the first import

    before, after = healthy_pair()
    after["apps/v1/Deployment/kube-system/coredns"] = snapshot_entry(
        "kube-system", resource_version="1"
    )
    after[f"v1/Pod/{CHAOS_NAMESPACE}/srek3s-chaos-oom-abc-xyz"] = snapshot_entry(
        CHAOS_NAMESPACE, resource_version="1"
    )
    before_path, after_path = _write_snapshots(tmp_path, before, after)

    check_no_cluster_mutation(before, after)  # the verdict: clean
    assert show_mutation.main([before_path, after_path]) == 0
    output = capsys.readouterr().out
    outside = output.split("CREATED outside")[1].split("exempt churn")[0]
    assert "v1/Deployment/kube-system/coredns" not in outside
    assert f"v1/Pod/{CHAOS_NAMESPACE}/srek3s-chaos-oom-abc-xyz" not in outside
    # The printer states the verdict the runner reached, not its own.
    assert "VERDICT: no mutation outside" in output
    assert "VERDICT: FAIL" not in output


def test_the_printer_and_the_runner_share_one_exemption_rule() -> None:
    """Structural anti-drift, on top of the behavioural controls above.

    The behavioural controls pin the two to today's namespaces. This pins them
    to *each other*: a future edit that adds a namespace to
    :data:`NOISY_SYSTEM_NAMESPACES` without the printer following is a failure
    here rather than a divergence discovered in a CI log weeks later.
    """
    import show_mutation  # noqa: PLC0415 - see the note on the first import

    for namespace in sorted(NOISY_SYSTEM_NAMESPACES | {CHAOS_NAMESPACE}):
        assert show_mutation.is_exempt_namespace(namespace) is True
    for namespace in ("default", "srek3s-system", "kube-system-staging"):
        assert show_mutation.is_exempt_namespace(namespace) is False


# ---------------------------------------------------------------------------
# The anti-vacuity guard on the whole response half
# ---------------------------------------------------------------------------


def test_a_non_json_upstream_body_is_a_failure(checkout: pathlib.Path) -> None:
    """The defect: the agent answered 500 and the runner skipped everything.

    The proxy records ``upstream_body`` verbatim, so an error envelope lands
    there as an object - and a check that only asked "is it a dict" would be
    satisfied by ``{"error": "analysis_failed"}`` and assert nothing useful.
    """
    record = captured(chaos_document(), None, status=500)
    record[CAPTURE_KEY]["upstream_body_text"] = '{"error":"analysis_failed"}'
    with pytest.raises(VerificationError) as error:
        check_captured_response_exists(record)
    assert "500" in str(error.value)
    assert "would skip" in str(error.value)


def test_control_the_capture_guard_can_actually_fire() -> None:
    """The guard above, paired with the case it must ignore.

    Without the second half, a ``check_captured_response_exists`` that raised on
    *every* record - including an uncaptured offline fixture - would pass its own
    test and break every offline run.
    """
    offline = chaos_document()
    check_captured_response_exists(offline)  # no CAPTURE_KEY: not a failure

    good = captured(chaos_document(), _tier2_shape())
    check_captured_response_exists(good)  # captured and a JSON object: fine


def full_lifecycle_observations() -> list[Observation]:
    """The history a real chaos run produces, for the sampling-side checks.

    ``verify`` also runs the pre-existing incident-window and causal-chain
    checks, so a 4.2.x test that routes through it has to supply a capture the
    older invariants also accept - or it is really testing those and reporting
    a 4.2.x failure.

    The shape is what a crash-looping container produces: killed at restart 1,
    backoff at 2, killed again at 2. ``check_detection_latency`` reads only the
    restart counts carrying ``exit_code == 137``, so the observed injection set
    is ``{1, 2}`` - which is what the incidents below must cover.
    """
    return [
        Observation(timestamp=1.0, state="Running", restart_count=0),
        Observation(timestamp=2.0, state="Terminated", exit_code=137, restart_count=1),
        Observation(
            timestamp=3.0,
            state="CrashLoopBackOff",
            restart_count=2,
            previous_exit_code=137,
            previous_reason="OOMKilled",
        ),
        Observation(timestamp=4.0, state="Terminated", exit_code=137, restart_count=2),
    ]


def matched_capture(checkout: pathlib.Path) -> list[dict[str, Any]]:
    """A capture whose restart counts cover :func:`full_lifecycle_observations`.

    Two OOMKilled exchanges (restarts 1 and 2) and one CrashLoopBackOff
    exchange, which is the mix a real detonation produces. The OOMKilled pair
    is what makes the 4.2.3 ratio balance; the crash-loop one is what makes
    4.2.7 have a Tier-2 to inspect.
    """
    return [
        triaged(chaos_document(restart_count=1), checkout),
        triaged(
            chaos_document(
                incident_id="inc_01M3M6W9ENH28NJS8C5T1665PC", restart_count=2
            ),
            checkout,
        ),
        crashloop_record(checkout),
    ]


def test_verify_reports_the_response_checks_on_a_full_capture(
    checkout: pathlib.Path, manifest_text: str
) -> None:
    """End to end through ``verify``, on a capture the engine really produced.

    Every incident here came out of the real triage engine with a real manifest
    provider, so the Tier-1 patch was built, YAML-checked and ``git apply
    --check``ed by the agent before the runner ever saw it.
    """
    before, after = healthy_pair()
    report = verify(
        matched_capture(checkout),
        full_lifecycle_observations(),
        window=60.0,
        manifest_text=manifest_text,
        snapshot_before=before,
        snapshot_after=after,
    )
    assert not report.failures, report.failures
    labels = " ".join(report.notes)
    for box in ("4.2.3", "4.2.5", "4.2.6", "4.2.7", "4.2.8"):
        assert box in labels, f"{box} recorded no note; notes were {report.notes}"
    # Nothing is left unproven: a run that evaluated every response-half box
    # and the snapshot check must not also report a skip, or one of the checks
    # is silently not running.
    assert not report.skipped, report.skipped


def test_verify_fails_the_run_when_a_tier_two_dispatch_is_missing(
    checkout: pathlib.Path, manifest_text: str
) -> None:
    """The whole-file direction: a Tier-2 capture with its marker stripped.

    Reaches ``verify`` so the failure is asserted on the property the exit code
    is derived from - not on a raised exception. A check that raises is
    reported; a check whose failure reaches ``report.failures`` is what makes
    the CLI exit non-zero, and that is the property this harness exists to have.
    """
    loop = crashloop_record(checkout)
    loop[CAPTURE_KEY]["upstream_body"]["rca_markdown"] = "## RCA\n\nEscalated.\n"
    report = verify(
        [loop],
        full_lifecycle_observations(),
        window=60.0,
        manifest_text=manifest_text,
    )
    assert not report.passed
    assert any("4.2.7" in failure for failure in report.failures), report.failures
    assert any("DO NOT APPLY" in failure for failure in report.failures)


def test_verify_skips_the_response_half_for_uncaptured_fixtures() -> None:
    """The offline direction: an honest, visible skip.

    Asserted that it is a *skip* and not a silent pass, and that the reason names
    the boxes, so a run cannot quietly stop evaluating 4.2.3/4.2.5/4.2.6/4.2.7
    without the log saying so.
    """
    report = verify(
        [chaos_document(restart_count=2)], full_lifecycle_observations(), window=60.0
    )
    assert not report.failures, report.failures
    joined = " ".join(report.skipped)
    for box in ("4.2.3", "4.2.5", "4.2.6", "4.2.7"):
        assert box in joined, f"{box} is not named in the skip reason: {report.skipped}"
    # And 4.2.8 is skipped for the same reason: no snapshot was taken.
    assert "4.2.8" in joined
    assert "PASS (with" in render(report)


def test_render_shows_a_pass_with_skips_as_a_pass_with_unproven_checks() -> None:
    """A green run with unproven boxes must not read as a bare PASS.

    ``RunReport.passed`` deliberately ignores ``skipped`` - otherwise every
    offline fixture run would "fail" for having no cluster. That is a real
    cost, and the rendering is what pays it: the verdict carries the count, so
    a reviewer reading the CI log sees the difference.
    """
    clean = render(RunReport())
    assert "RESULT: PASS" in clean
    assert "unproven" not in clean.split("RESULT:")[1]

    skipped = RunReport(skipped=["4.2.6: no Tier-1 incident"])
    text = render(skipped)
    assert "RESULT: PASS (with 1 unproven check(s)" in text
    assert "SKIP   4.2.6" in text


# ---------------------------------------------------------------------------
# The drift guards
# ---------------------------------------------------------------------------


def test_the_tier_one_gate_survives_a_broken_manifest() -> None:
    """The whole 4.2.6 chain, driven by a manifest that is deliberately wrong.

    A negative control at the *system* level rather than the function level: the
    checkout holds a manifest whose limit does not match the incident, so the
    engine escalates, and the runner must then report 4.2.6 as unproven rather
    than passing. This is what a "wire the provider in" regression that quietly
    removed the drift check would look like from the runner's side.
    """
    drifted = CHAOS_MANIFEST.read_text(encoding="utf-8").replace(
        "memory: 64Mi", "memory: 256Mi"
    )

    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        target = root / TARGET
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(drifted, encoding="utf-8")
        record = triaged(chaos_document(), root)
        assert tier_of(record) == TIER_2
        assert record[CAPTURE_KEY]["upstream_body"]["remediation"]["git_patch"] == ""

        # 4.2.6 has no Tier-1 to check, and says so.
        assert check_tier_one_patches([record], drifted).startswith(SKIP_PREFIX)
        # 4.2.7 does, and the escalation carries a dispatch.
        assert "1 Tier-2 incident(s)" in check_tier_two_dispatches([record])


def test_the_runner_and_the_capture_proxy_agree_on_the_capture_key() -> None:
    """``CAPTURE_KEY`` is duplicated; this is what makes that safe.

    A rename on either side that is not mirrored here would leave
    ``response_of`` returning ``None`` for every incident, every response check
    would skip, and the run would report a clean PASS on a run that proved
    nothing about the agent. The single most expensive way this harness could
    be wrong.
    """
    import capture_proxy

    assert CAPTURE_KEY == capture_proxy.CAPTURE_KEY


def test_the_runner_and_the_agent_agree_on_the_tier_names() -> None:
    """``TIER_1``/``TIER_2`` are literals; the router is the authority."""
    assert TIER_1 == models.BlastRadiusTier.TIER_1_TOIL.value
    assert TIER_2 == models.BlastRadiusTier.TIER_2_ARCHITECTURAL.value
    assert classifier.TARGET_MANIFEST == TARGET


def test_response_of_distinguishes_missing_from_non_object() -> None:
    """``None`` means *not captured*; a non-dict body is a failure elsewhere.

    Collapsing them is how four response checks end up skipping on a run where
    the agent answered nothing.
    """
    assert response_of(chaos_document()) is None
    assert response_of(captured(chaos_document(), None)) is None
    assert response_of(captured(chaos_document(), {"a": 1})) == {"a": 1}
    assert tier_of(captured(chaos_document(), {"blast_radius_tier": TIER_1})) == TIER_1
    assert tier_of(captured(chaos_document(), {"blast_radius_tier": 1})) is None


@pytest.fixture(autouse=True)
def _no_stray_checkout_dirs() -> Iterator[None]:
    """Fail the run if a test left a sibling directory behind.

    The symlink control creates one because the checkout fixture *is*
    ``tmp_path``. Leaving it behind makes the next run's ``mkdir`` fail for an
    unrelated reason, which is exactly the kind of harness flakiness that gets
    dismissed as "just re-run it".
    """
    root = REPO_ROOT
    yield
    strays = [
        path.name for path in root.parent.glob("outside-pytest-*") if path.is_dir()
    ]
    assert not strays, f"a test left directories behind: {strays}"


def test_tier2_response_helper_is_not_used() -> None:
    """The hand-written shape is a control, not the fixture.

    If this shape ever becomes the *only* thing 4.2.7 is tested against, the
    check would be asserting against a document the agent never produced. The
    real-engine tests above are the ones that matter; this keeps the boundary
    between the two visible.
    """
    assert _tier2_shape()["remediation"]["git_patch"] == ""
    assert _tier2_shape()["blast_radius_tier"] == TIER_2
