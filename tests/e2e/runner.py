#!/usr/bin/env python3
"""E2E runner skeleton (ROADMAP 4.2.1).

**This file does not run anything on import.** Every entry point is behind
``if __name__ == "__main__"``, and the module can be imported to unit-test the
sampling invariants below without a cluster, which is the point: the invariants
are where the actual knowledge is, and they should be testable offline.

What this encodes, and why each rule exists:

* **Redaction is gated on ``restart_count >= 1``.** The Sentinel fetches the
  *previous* container instance's log. On a container's first crash there is no
  previous instance, the apiserver rejects the read, and the worker dispatches the
  incident with empty ``scrubbed_logs`` **and no error**. A test that asserts
  "the first emitted incident contains no plaintext" therefore passes against an
  empty string - it measures nothing. This is the single most likely way for the
  masking proof to be vacuous.

* **An empty log is a failure, not a pass.** Handled explicitly and separately
  from the gate above, because the two have different causes and different
  fixes: the first is a timing property of the run, the second is a capture bug.

* **The causal chain is ``Terminated{reason}`` -> ``Waiting{CrashLoopBackOff}``.**
  A Deployment forces ``restartPolicy: Always``, so a pod that OOMs once settles
  into ``CrashLoopBackOff`` permanently. ``OOMKilled`` is the *cause* and
  ``CrashLoopBackOff`` is the *symptom*, and the evidence that links them is
  ``lastState.terminated`` - because the kubelet clears ``state.terminated`` the
  moment it restarts the container. Reading ``state`` at observation time
  returns the symptom and looks like the cause.

* **``CrashLoopBackOff`` is not observable before ~10s.** The kubelet restarts a
  failed container *immediately* the first time (no backoff entry exists yet) and
  only enters backoff from the second failure. Asserting earlier than ~12s fails
  against a fixture that is working perfectly.

* **Incident count is a function of wall-clock, not a constant.** The dedup key is
  ``<podUID>/<containerName>:<restartCount>``, so every restart is a distinct
  incident and nothing is collapsed. An exact-count assertion passes at t=15s and
  fails at t=60s for reasons that have nothing to do with the Sentinel.

* **The response half is asserted too, and a skip is not a pass.** ROADMAP
  4.2.3/4.2.5/4.2.6/4.2.7 are properties of the agent's *answer*, so they read
  ``harness_capture.upstream_body``. Offline fixtures carry no answer, so those
  checks **skip with a printed reason** rather than passing silently; a report
  that says "PASS (with N unproven checks)" is the only honest rendering when
  that happens. ``RunReport.passed`` deliberately ignores ``skipped``, and
  ``render`` prints them at the same prominence as failures so the distinction
  is visible in the CI log rather than inferred from an exit code.
"""

from __future__ import annotations

import argparse
import json
import math
import pathlib
import shutil
import subprocess
import sys
import tempfile
import time
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Final, Sequence

#: Prefix a check returns to say "I could not evaluate this", rather than
#: "this passed" or "this failed". A separate third outcome, because collapsing
#: skip into either of the other two is what makes an unproven box look proven.
SKIP_PREFIX: Final[str] = "SKIP:"

#: ROADMAP 4.1.1. Fixtures are pinned here; the Sentinel should be pointed here.
CHAOS_NAMESPACE: Final[str] = "sentinel-chaos"

#: The only two failure kinds the emitter will serialise
#: (``internal/emitter/mapReason``). Anything else is dropped as unmappable, so a
#: runner that expects a third kind is waiting for a payload that cannot arrive.
FAILURE_KINDS: Final[frozenset[str]] = frozenset({"OOMKilled", "CrashLoopBackOff"})

#: The Sentinel reads at most this many log lines (``internal/k8s/telemetry.go``,
#: ``LogTailLines``). Beyond it the earliest planted credentials rotate out, which
#: silently weakens a masking assertion from "every planted secret" to "a subset".
LOG_TAIL_LINES: Final[int] = 100

#: The literals planted by the chaos fixtures, per ``deploy/chaos/*.yaml``. The
#: assertion is that none of these appear in a fetched payload. Derived from the
#: manifests, not from the scrubber, so a rule change cannot make the test agree
#: with itself.
#:
#: ``chaos_user`` is deliberately **absent**, and the omission is a claim rather
#: than an oversight. It is the username in ``postgres://chaos_user:...@host``.
#: AGENTS.md Â§3 rule 5 requires ``basic_auth_url`` to target the secret segment
#: inside userinfo - ``user:[REDACTED]@host:port`` - and preserve everything
#: else, because destroying the username and the endpoint together ruins the RCA
#: telemetry. An earlier version of this list included it and the check failed
#: against *correct* behaviour: the scrubber was doing exactly what the rule says.
#: A test that demands the username be masked is a test demanding the violation.
#:
#: If a username were ever itself sensitive it belongs in the password position
#: of the fixture, not in the userinfo prefix.
PLANTED_SECRETS: Final[tuple[str, ...]] = (
    "AKIAIOSFODNN7EXAMPLE",
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
    "dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk",
    "chaos-planted-bearer-token",
    "Sup3rS3cretPassw0rd",
)

#: Earliest safe moment to assert ``CrashLoopBackOff``. The kubelet's first
#: backoff interval is exactly 10s and the reason is not published until the
#: *second* failure, so 10s is the boundary and 12s is the floor.
CRASHLOOP_OBSERVABLE_AFTER: Final[float] = 12.0

#: Default verification window. A window, not a count: see the module docstring.
DEFAULT_WINDOW: Final[float] = 60.0


class VerificationError(RuntimeError):
    """A check that must hold for the run to be considered valid."""


# ---------------------------------------------------------------------------
# Invariants - importable and unit-testable without a cluster
# ---------------------------------------------------------------------------


def gate_redaction(incident: dict[str, Any]) -> str | None:
    """Return a reason to skip the redaction check, or ``None`` to run it.

    ``None`` means "check it". Anything else is the reason the check does not
    apply, and the reason is returned rather than logged so a run can report how
    many incidents were *not* checked - a run where every incident was gated out
    looks identical to a run where masking was proven.
    """
    restart_count = incident.get("restart_count")
    if not isinstance(restart_count, int):
        return f"restart_count is {restart_count!r}, not an int"
    if restart_count < 1:
        return (
            f"restart_count={restart_count}: this is the container's first "
            f"crash, so there is no previous instance and no log to have been "
            f"scrubbed"
        )
    return None


def check_logs_were_captured(incident: dict[str, Any]) -> list[str]:
    """Assert the log fetch actually returned something.

    Separated from :func:`check_redaction` because the two failures mean different
    things. An empty ``scrubbed_logs`` on a gated-restart incident is a *capture*
    bug - the runtime truncated the log, or the Sentinel read the wrong instance -
    and asserting "no plaintext present" against an empty list would report that
    bug as a pass.
    """
    logs = incident.get("scrubbed_logs")
    if not isinstance(logs, list):
        raise VerificationError(f"scrubbed_logs is {type(logs).__name__}, want list")
    if not logs:
        raise VerificationError(
            "scrubbed_logs is empty on an incident with restart_count>=1; the "
            "planted credentials should have been captured. An empty list makes "
            "every redaction assertion below vacuous."
        )
    if len(logs) > LOG_TAIL_LINES:
        raise VerificationError(
            f"scrubbed_logs has {len(logs)} lines, past the Sentinel's "
            f"{LOG_TAIL_LINES}-line tail; the planted credentials may have "
            f"rotated out of the window"
        )
    return [str(line) for line in logs]


def check_redaction(incident: dict[str, Any]) -> list[str]:
    """Assert no planted secret survived into the payload.

    Returns the scrubbed logs so a caller can assert the *diagnostic* content
    survived too - see :func:`check_diagnostics_survived`.
    """
    logs = check_logs_were_captured(incident)
    blob = "\n".join(logs)
    survivors = [secret for secret in PLANTED_SECRETS if secret in blob]
    if survivors:
        raise VerificationError(
            f"incident {incident.get('incident_id')!r} carries {len(survivors)} "
            f"planted secret(s) in its scrubbed_logs: {survivors}"
        )
    if "[REDACTED]" not in blob:
        raise VerificationError(
            "scrubbed_logs contain no [REDACTED] marker, so nothing was masked; "
            "a run where the pipeline dropped every line would pass the check "
            "above while proving nothing"
        )
    return logs


def check_diagnostics_survived(logs: Sequence[str]) -> None:
    """Assert masking did not destroy the evidence.

    The mirror of :func:`check_redaction`. Over-masking is recoverable and
    under-masking is not, but a scrubber that satisfies the leak test by dropping
    every line satisfies it perfectly and leaves the agent with nothing to reason
    about - so both halves are asserted.
    """
    blob = "\n".join(logs)
    if "CHAOS-CRED" not in blob and "CHAOS-PHASE" not in blob:
        raise VerificationError(
            "no planted-credential marker survived in scrubbed_logs; masking "
            "appears to have removed the evidence rather than the secret"
        )


@dataclass(frozen=True)
class Observation:
    """One point in a pod's state history, as read from ``kubectl get -o json``."""

    timestamp: float
    state: str
    exit_code: int | None = None
    reason: str | None = None
    restart_count: int = 0
    previous_exit_code: int | None = None
    previous_reason: str | None = None

    @property
    def is_crashloop(self) -> bool:
        return self.state == "CrashLoopBackOff"

    @property
    def is_oom(self) -> bool:
        return self.exit_code == 137


def classify_observation(observation: Observation) -> str | None:
    """Map a pod status onto the kind the Sentinel would emit, or ``None``.

    Mirrors ``internal/k8s/watcher.go``'s ``classify``. A runner that guesses a
    different rule than the Sentinel uses will report a pass on a run where the
    Sentinel emitted nothing at all.
    """
    if observation.is_crashloop:
        return "CrashLoopBackOff"
    if observation.exit_code is not None and observation.exit_code != 0:
        return "OOMKilled" if observation.exit_code == 137 else "Terminated"
    return None


def check_causal_chain(observations: Sequence[Observation]) -> str:
    """Verify ``Terminated{cause}`` preceded ``Waiting{CrashLoopBackOff}``.

    Returns a human-readable description of the chain observed, or raises.

    The check is on *order and persistence*, not on a single snapshot: a snapshot
    taken after the restart can only ever show the symptom, so a runner that
    asserts on one poll cannot observe the cause at all.
    """
    if not observations:
        raise VerificationError("no observations; the pod was never seen")

    ordered = sorted(observations, key=lambda o: o.timestamp)
    terminated = [o for o in ordered if o.is_oom]
    crashloop = [o for o in ordered if o.is_crashloop]

    if not terminated:
        observed = [f"{o.state}/exit={o.exit_code}" for o in ordered]
        raise VerificationError(
            "never observed Terminated{exit_code: 137}; the fixture did not OOM. "
            f"Observed: {observed}. A 137 with a non-nil reason is the only "
            f"evidence of the cause, and it is gone once the container restarts."
        )
    if not crashloop:
        raise VerificationError(
            f"observed the OOM but never Waiting{{CrashLoopBackOff}} across "
            f"{len(ordered)} samples; the fixture did not enter backoff. If this "
            f"run was shorter than {CRASHLOOP_OBSERVABLE_AFTER}s that is expected "
            f"timing, not a fault."
        )

    first_oom = min(o.timestamp for o in terminated)
    first_crashloop = min(o.timestamp for o in crashloop)
    if first_crashloop < first_oom:
        raise VerificationError(
            f"CrashLoopBackOff observed at {first_crashloop:.1f}s, before the "
            f"terminated state at {first_oom:.1f}s; the causal chain is inverted, "
            f"which means the sampling missed the cause rather than the effect"
        )

    # The link between the two, which is the whole point of previous_reason.
    carries_cause = [
        o for o in crashloop if o.previous_exit_code == 137 or o.previous_reason
    ]
    if not carries_cause:
        raise VerificationError(
            "no Waiting{CrashLoopBackOff} sample carried previous_reason or a "
            "previous exit code of 137. The Sentinel emits `previous_reason` "
            "from LastTerminationState for exactly this; without it the agent's "
            "RCA loses the sentence connecting the symptom to the cause."
        )

    return (
        f"OOMKilled(137) at t={first_oom:.1f}s -> "
        f"Waiting{{CrashLoopBackOff}} at t={first_crashloop:.1f}s, "
        f"cause carried by {len(carries_cause)} sample(s)"
    )


def check_incident_window(incidents: Sequence[dict[str, Any]]) -> str:
    """Assert the run saw a usable number of incidents, without pinning a count.

    ``restart_count >= 2``, not ``>= 1``: one restart is the kubelet's immediate
    restart before any backoff exists, so asserting ``>= 1`` would be satisfied by
    a fixture that never entered backoff at all. The threshold that proves backoff
    actually happened is two.
    """
    if not incidents:
        raise VerificationError(
            "no incidents collected. Check, in order: the Sentinel's "
            "WATCH_NAMESPACE, the RBAC Role binding, and whether the agent "
            "returned anything other than 2xx."
        )
    deep = [
        i
        for i in incidents
        if isinstance(i.get("restart_count"), int) and i["restart_count"] >= 2
    ]
    if not deep:
        counts = [i.get("restart_count") for i in incidents]
        raise VerificationError(
            f"no incident reached restart_count>=2 (saw {counts}); nothing proved "
            f"the container actually entered backoff"
        )
    unmappable = [i for i in incidents if i.get("reason") not in FAILURE_KINDS]
    if unmappable:
        raise VerificationError(
            f"{len(unmappable)} incident(s) carry a reason outside "
            f"{sorted(FAILURE_KINDS)}; the emitter refuses to serialise those, "
            f"so they should never have arrived"
        )
    return (
        f"{len(incidents)} incident(s); {len(deep)} at restart_count>=2; "
        f"reasons={sorted({str(i.get('reason')) for i in incidents})}"
    )


# ---------------------------------------------------------------------------
# The agent's answer
#
# Everything below this line asserts on the *response* half of the exchange,
# not just the request. The capture proxy records the agent's Contract B body
# under `harness_capture.upstream_body` (ROADMAP 4.2.1), so `rca_markdown`,
# `git_patch` and the war-room dispatch are all answerable from the same file
# the redaction checks already read.
# ---------------------------------------------------------------------------

#: Key the capture proxy namespaces the upstream response under
#: (``capture_proxy.CAPTURE_KEY``). Duplicated as a literal rather than imported
#: so the runner keeps no dependency on the agent's package; a drift test in
#: ``agent/tests/test_e2e_runner.py`` asserts the two agree, and a rename that
#: breaks that test fails the build rather than silently skipping every check
#: below.
CAPTURE_KEY: Final[str] = "harness_capture"

#: ARCH Â§5.3 tier names.
TIER_1: Final[str] = "TIER_1_TOIL"
TIER_2: Final[str] = "TIER_2_ARCHITECTURAL"

#: Reasons a Tier-2 response is *required* for.
#:
#: ROADMAP 4.2.7 is "for each Tier-2 incident, ...". A run containing no
#: Tier-2 incident satisfies that sentence vacuously, and a vacuous box is
#: worse than an unticked one. So the requirement is derived rather than
#: assumed: ARCH Â§5.3 admits Tier-1 only for `reason == OOMKilled`, so a
#: captured `CrashLoopBackOff` incident *proves* a Tier-2 response must exist in
#: the same capture. Asserting on that is a real precondition, not a guess about
#: how many incidents a run will produce.
TIER_ONLY_POSSIBLE_REASONS: Final[frozenset[str]] = frozenset({"CrashLoopBackOff"})

#: The Tier-2 dispatch's explicit marker (ROADMAP Â§2.6.2), as a distinctive
#: prefix of ``agent.warroom.DO_NOT_APPLY``. A prefix rather than the full
#: sentence so a wording tweak to the constant is a drift-test failure, not an
#: unexplained E2E failure four weeks later. ``test_the_runner_asserts_on_the
#: real_war_room_marker`` keeps the two in step.
WAR_ROOM_DO_NOT_APPLY_MARKER: Final[str] = "DO NOT APPLY ANY CHANGE FROM THIS DISPATCH."


def response_of(incident: dict[str, Any]) -> dict[str, Any] | None:
    """The agent's Contract B body for this exchange, or ``None``.

    ``None`` means *not captured* - an offline fixture, or a run whose capture
    file predates the proxy. It is deliberately distinct from "captured and the
    body was not a JSON object": the second is a failure the caller must raise
    (:func:`check_captured_response_exists`), because a 4xx/5xx envelope
    reaching the agent is exactly what makes every response check skip and the
    run look clean.
    """
    capture = incident.get(CAPTURE_KEY)
    if not isinstance(capture, dict):
        return None
    body = capture.get("upstream_body")
    return body if isinstance(body, dict) else None


def tier_of(incident: dict[str, Any]) -> str | None:
    """The ``blast_radius_tier`` the agent returned, or ``None``."""
    response = response_of(incident)
    if response is None:
        return None
    tier = response.get("blast_radius_tier")
    return tier if isinstance(tier, str) else None


def check_captured_response_exists(incident: dict[str, Any]) -> None:
    """Fail a captured exchange whose upstream body is not a JSON object.

    This is the anti-vacuity guard for everything below. The proxy records
    ``upstream_body`` verbatim, so a ``4xx``/``5xx`` envelope or an HTML error
    page lands there as-is; a runner that only checked `is not None` would skip
    every response assertion and report a clean run on an agent that answered
    nothing useful.
    """
    if CAPTURE_KEY not in incident:
        return
    capture = incident.get(CAPTURE_KEY)
    if not isinstance(capture, dict):
        raise VerificationError(
            f"{incident.get('incident_id')!r}: {CAPTURE_KEY} is "
            f"{type(capture).__name__}, not the exchange record the proxy writes"
        )
    if response_of(incident) is not None:
        return
    status = capture.get("upstream_status")
    text = capture.get("upstream_body_text")
    raise VerificationError(
        f"{incident.get('incident_id')!r}: the agent answered {status!r} with a "
        f"non-JSON body ({str(text)[:120]!r}). Every response assertion below "
        f"would skip, so a run in which the agent rejected or failed on every "
        f"incident would otherwise read as a passing run."
    )


# ---------------------------------------------------------------------------
# ROADMAP 4.2.3 - detection latency and the injection/detection ratio
# ---------------------------------------------------------------------------

#: ARCH Â§4.2 I-A4 / PRD AC-1. The same number the Go emitter clamps to, and the
#: same number ``IncidentPayload`` rejects above with a 422.
DETECTION_LATENCY_BUDGET_MS: Final[int] = 2000

#: Quantile the latency assertion is written against.
P99_QUANTILE: Final[float] = 0.99


def percentile_nearest_rank(values: Sequence[int], quantile: float) -> int:
    """Nearest-rank percentile: the ``ceil(q * n)``-th smallest value.

    Nearest rank, not interpolation, and the choice matters: an interpolated
    p99 of a six-sample run invents a value no sample ever took, so the
    assertion would be about a number the system never produced. With
    ``n <= 100`` nearest rank also degrades to the maximum, which is the
    strictest reading and the one a two-second budget should get.
    """
    if not values:
        raise VerificationError("cannot take a percentile of no values")
    if not 0.0 < quantile <= 1.0:
        raise VerificationError(f"quantile {quantile!r} is outside (0, 1]")
    ordered = sorted(values)
    rank = math.ceil(quantile * len(ordered))
    return ordered[max(1, min(rank, len(ordered))) - 1]


def oom_restart_counts(observations: Sequence[Observation]) -> set[int]:
    """Restart counts at which the runner *directly* observed a 137 kill.

    This is the runner's independent, cluster-side record of an injected event.
    It is a **lower bound** on the truth, and the limitation is stated rather
    than papered over: the runner polls once a second, and the kubelet batches
    status updates, so a kill whose Terminated state was coalesced away is
    simply not in this set. See :func:`sampler_restart_ceiling` for what the
    check does about that.
    """
    return {obs.restart_count for obs in observations if obs.exit_code == 137}


def sampler_restart_ceiling(observations: Sequence[Observation]) -> int:
    """The highest restart count the runner ever read off the pod.

    This is the pod's **own final observed state**, read from the samples rather
    than assumed, and it is what makes a detection at a restart count the
    sampler never saw interpretable. ``0`` when nothing was observed, which is
    the honest answer for a pod the runner never managed to read.
    """
    return max((obs.restart_count for obs in observations), default=0)


def injectable_restart_counts(observations: Sequence[Observation]) -> set[int]:
    """The restart counts at which a kill could have happened unseen: ``{0..N}``.

    **The rule, stated rather than assumed.** If the final restart count the
    runner observed on the pod is ``N``, then a kill at any restart count in
    ``{0, ..., N}`` is a real event on a real pod, and the sampler's failure to
    record it is a *resolution* failure rather than a phantom. The Sentinel
    watches continuously, so it sees every restart; the runner polls at ~1s, so
    a restart faster than one poll interval is invisible to it. Treating that
    as a phantom detection made the ratio fail against a system that detected
    everything it was injected.

    **Why this is right and not a loosening.** The sampler's resolution is the
    limiting factor, and a *faster sampler would make this rule unnecessary
    rather than wrong*: at a poll interval below the kubelet's restart latency
    every restart lands in :func:`oom_restart_counts` and the ceiling equals the
    maximum observed count, so the accepted set is precisely the observed set
    again. What the rule gives up is only the ability to prove the negative -
    that a detection at a restart count within the ceiling is *impossible*. That
    proof is not available from this data source at any poll rate, because the
    failure it would catch is indistinguishable from the sampling gap it
    forgives.

    It is derived, never hardcoded: the ceiling is the maximum
    ``restart_count`` the runner read off the pod, so it tracks the pod's real
    behaviour instead of a constant that silently stops matching it.
    """
    return set(range(sampler_restart_ceiling(observations) + 1))


def check_detection_latency(
    incidents: Sequence[dict[str, Any]],
    observations: Sequence[Observation],
) -> str:
    """ROADMAP 4.2.3: p99 detection latency in budget, and a 1:1 ratio.

    **The counting rule, stated rather than assumed.** The Sentinel's dedup key
    is ``<podUID>/<containerName>:<restartCount>`` (ROADMAP 3.3.3), so the
    restart count is part of the identity. One OOM therefore legitimately
    produces *several* incidents: an ``OOMKilled`` record for the terminated
    instance, and a ``CrashLoopBackOff`` record for the restarted one at the
    next restart count. "One detection per injected event" is consequently
    meaningless without a rule, and the rule used here is:

        detections := distinct (pod_name, container_name, restart_count) among
                       the incidents whose ``reason`` is ``OOMKilled``
        injected   := distinct restart_count at which the runner observed a
                       termination with ``exit_code == 137``
        ceiling    := the highest restart_count the runner read off the pod
        accepted   := {0 .. ceiling}, from :func:`injectable_restart_counts`

    So the two directions are treated differently, and the asymmetry is the
    point:

    * **a miss still fails.** A 137 the runner saw, at a restart count with no
      corresponding incident, is the Sentinel saying nothing about a kill in
      front of it. This is the direction the 1:1 property constrains and it is
      untouched.
    * **a detection the sampler missed does not.** A detection at a restart
      count within the ceiling is a real event on a real pod that the ~1s
      sampler could not resolve. See :func:`injectable_restart_counts` for why
      that is a resolution failure rather than a phantom, and for why a faster
      sampler makes the allowance unnecessary rather than wrong.
    * **a detection beyond the ceiling still fails.** Restart counts above the
      highest the runner ever read are not sampler misses; they name restarts
      the pod did not reach, which is a fabrication and is reported as one.

    ``CrashLoopBackOff`` incidents are counted and reported but excluded from
    the ratio, because they are the *symptom* of an event already counted, not
    a second injection. Counting them would inflate the ratio; ignoring them
    silently would hide a class of detection entirely.

    The comparison is on **sets of restart counts**, not on lengths, so a
    failure names which injection went missing rather than only that the totals
    disagree. The same pass rejects a duplicate dedup key, which is the other
    way the ratio could hold for the wrong reason.
    """
    if not incidents:
        raise VerificationError(
            "no incidents to measure; detection latency over an empty capture "
            "is not a measurement"
        )

    # A latency that is absent or non-numeric is a failure in its own right.
    # Computing p99 over whichever subset *is* numeric would quietly narrow the
    # assertion - the runner would report a percentile of the incidents that
    # happened to carry the field and say nothing about the rest.
    unmeasured = [
        incident.get("incident_id")
        for incident in incidents
        if not isinstance(incident.get("detection_latency_ms"), int)
        or isinstance(incident.get("detection_latency_ms"), bool)
    ]
    if unmeasured:
        raise VerificationError(
            f"{len(unmeasured)} incident(s) carry no integer detection_latency_ms "
            f"(first: {unmeasured[0]!r}); a percentile over the survivors would "
            f"not be the p99 of the run"
        )

    latencies = [int(incident["detection_latency_ms"]) for incident in incidents]
    p99 = percentile_nearest_rank(latencies, P99_QUANTILE)
    if p99 > DETECTION_LATENCY_BUDGET_MS:
        raise VerificationError(
            f"p99 detection latency is {p99}ms over {len(latencies)} incident(s), "
            f"over the {DETECTION_LATENCY_BUDGET_MS}ms budget (ARCH 4.2 I-A4). "
            f"All values: {sorted(latencies)}"
        )

    oom = [incident for incident in incidents if incident.get("reason") == "OOMKilled"]
    keys = [
        (
            str(incident.get("pod_name")),
            str(incident.get("container_name")),
            incident["restart_count"],
        )
        for incident in oom
    ]
    counts = Counter(keys)
    duplicates = sorted(key for key, seen in counts.items() if seen > 1)
    if duplicates:
        raise VerificationError(
            f"{len(duplicates)} OOMKilled detection(s) reuse a dedup key "
            f"<pod>/<container>:<restart_count> that was already emitted "
            f"(e.g. {duplicates[0]}); the Sentinel's dedup cache is not "
            f"suppressing echoes and the ratio below would be wrong"
        )

    injected = oom_restart_counts(observations)
    detected = {restart for _pod, _container, restart in keys}
    if not injected:
        raise VerificationError(
            "no termination with exit_code 137 was observed in the sampling "
            "window, so there is no injection to compare detections against. "
            "Either the fixture did not OOM, or the sampling window opened "
            "after the restart (see the module docstring)."
        )

    # The accepted injected set is the pod's own final observed state, not a
    # constant. See injectable_restart_counts: a detection at a restart count
    # within it is a miss by the sampler, not a phantom, and is reported rather
    # than failed. The missed-detection direction is NOT relaxed - a 137 the
    # runner saw and the Sentinel did not report is still a failure, and that
    # is the direction the 1:1 property actually constrains.
    ceiling = sampler_restart_ceiling(observations)
    unseen = injectable_restart_counts(observations)
    missed = sorted(injected - detected)
    phantoms = sorted(detected - unseen)
    if missed or phantoms:
        raise VerificationError(
            f"detections != injected events. Observed OOM restarts "
            f"{sorted(injected)}; detected {sorted(detected)}; the pod's final "
            f"observed restart count is {ceiling}. "
            f"Missed detection(s) for restart_count {missed}; "
            f"detection(s) with no observed injection at restart_count {phantoms} "
            f"(beyond the pod's final observed restart count {ceiling}, so not a "
            f"restart this pod ever reached)."
        )
    # Detected but not directly observed by the sampler, and within the ceiling:
    # forgiven by the resolution rule. Reported so the count is visible rather
    # than silently absorbed.
    sampler_misses = sorted(detected - injected)

    symptoms = len(incidents) - len(oom)
    return (
        f"p99 detection latency {p99}ms over {len(latencies)} incident(s) "
        f"(budget {DETECTION_LATENCY_BUDGET_MS}ms); {len(oom)} OOMKilled "
        f"detection(s) for {len(injected)} observed OOM restart(s) at "
        f"{sorted(injected)}; {symptoms} CrashLoopBackOff symptom(s) excluded "
        f"from the ratio by the dedup-key counting rule"
        + (
            f"; {len(sampler_misses)} detection(s) at restart_count "
            f"{sampler_misses} were below the pod's final observed restart count "
            f"{ceiling} and were accepted as sampler misses rather than phantoms"
            if sampler_misses
            else ""
        )
    )


# ---------------------------------------------------------------------------
# ROADMAP 4.2.5 - the RCA is specific, not merely non-empty
# ---------------------------------------------------------------------------

#: Payload facts an RCA may cite, split by how much they discriminate.
#:
#: A bare integer is a weak citation: "2" occurs in ``TIER_2``, ``SEV2`` and
#: every line number, so a substring test over ``restart_count=2`` or
#: ``exit_code=137`` can be satisfied by prose that has nothing to do with the
#: incident. The multi-character identifiers cannot. Both classes are required,
#: which is what makes "specific" an assertion rather than a length check.
RCA_STRONG_FACTS: Final[tuple[str, ...]] = (
    "container_name",
    "memory_limit",
    "namespace",
    "pod_name",
)
RCA_WEAK_FACTS: Final[tuple[str, ...]] = ("exit_code", "restart_count")

MIN_RCA_STRONG_CITATIONS: Final[int] = 2
MIN_RCA_CITATIONS: Final[int] = 3


def citable_facts(incident: dict[str, Any]) -> dict[str, str]:
    """Literal strings from the payload that a specific RCA must quote.

    A fact is included only when the payload actually carries it, so the bar is
    never set by a field the emitter nulled out - ``exit_code`` is null for a
    ``CrashLoopBackOff``, and demanding the string ``"None"`` would be
    demanding a falsehood.
    """
    facts: dict[str, str] = {}
    for name in ("container_name", "namespace", "pod_name"):
        value = incident.get(name)
        if isinstance(value, str) and value:
            facts[name] = value
    for name in ("exit_code", "restart_count"):
        value = incident.get(name)
        if isinstance(value, int) and not isinstance(value, bool):
            facts[name] = str(value)
    limits = incident.get("resource_limits")
    if isinstance(limits, dict):
        memory = limits.get("memory_limit")
        if isinstance(memory, str) and memory:
            facts["memory_limit"] = memory
    return facts


def check_rca_is_specific(incidents: Sequence[dict[str, Any]]) -> str:
    """ROADMAP 4.2.5: non-empty, specific, and grounded in this payload.

    "Non-empty" is the schema's job - ``TriageResponse.rca_markdown`` is
    ``min_length=1`` and a captured response that reached a 200 therefore
    already satisfies it. The part that is *not* enforced anywhere upstream is
    specificity, and that is the whole content of this check: the RCA must
    quote at least ``MIN_RCA_STRONG_CITATIONS`` of this incident's distinctive
    identifiers and at least ``MIN_RCA_CITATIONS`` facts in total.

    A template that interpolates nothing - the shape a "boilerplate" failure
    takes - cites zero, so it fails. A length check would pass it.
    """
    checked = 0
    # rca text -> the identity that produced it, for the cross-incident
    # boilerplate control below.
    rcas: dict[str, str] = {}

    for incident in incidents:
        response = response_of(incident)
        if response is None:
            continue
        checked += 1
        identity = str(incident.get("incident_id"))
        rca = response.get("rca_markdown")
        if not isinstance(rca, str) or not rca.strip():
            raise VerificationError(
                f"{identity!r}: rca_markdown is "
                f"{type(rca).__name__}/empty on a captured 200 response; the "
                f"schema's min_length=1 should have rejected it, so either the "
                f"agent or the capture is not what this runner assumes"
            )

        facts = citable_facts(incident)
        if not facts:
            raise VerificationError(
                f"{identity!r}: the payload carries no fact an RCA could cite, "
                f"so specificity cannot be asserted - the payload is too empty "
                f"for the RCA to be grounded in it"
            )
        cited = {name for name, value in facts.items() if value in rca}
        strong = cited.intersection(RCA_STRONG_FACTS)
        if len(strong) < MIN_RCA_STRONG_CITATIONS:
            raise VerificationError(
                f"{identity!r}: rca_markdown cites {len(strong)} of the "
                f"payload's distinctive identifiers ({sorted(RCA_STRONG_FACTS)}), "
                f"needs {MIN_RCA_STRONG_CITATIONS}. It cited {sorted(strong)} of "
                f"{sorted(facts)}. A boilerplate RCA passes a non-empty check "
                f"and fails this one."
            )
        if len(cited) < MIN_RCA_CITATIONS:
            raise VerificationError(
                f"{identity!r}: rca_markdown cites only {sorted(cited)} of "
                f"{sorted(facts)}; {MIN_RCA_CITATIONS} facts are required for it "
                f"to be traceable to this payload"
            )

        # Keyed by the *text*, not by the restart count. Two incidents at
        # different restart counts sharing one RCA is the defect (a template
        # that interpolates nothing but the id); keying by restart count would
        # only ever collide on the one pair a template is least likely to catch.
        previous = rcas.get(rca)
        if previous is not None:
            raise VerificationError(
                f"{identity!r}: the rca_markdown is byte-identical to "
                f"{previous!r}'s, so at least one of the two interpolates nothing "
                f"from its own payload. Distinct incidents that cite the same "
                f"identifiers while differing only in a field the RCA never "
                f"reads is what a boilerplate template looks like."
            )
        rcas[rca] = identity

    if not checked:
        raise VerificationError(
            "no captured response to check rca_markdown on; the 4.2.5 assertion "
            "would be vacuous"
        )
    return (
        f"{checked} RCA(s) checked; each cites at least "
        f"{MIN_RCA_STRONG_CITATIONS} of the payload's own identifiers"
    )


# ---------------------------------------------------------------------------
# ROADMAP 4.2.6 - the Tier-1 patch, handed to real git
# ---------------------------------------------------------------------------

#: Bound on every git invocation. The runner is a verification harness, not
#: the system under test, but an unbounded subprocess is still a way to wedge a
#: CI job, and AGENTS.md Â§3.2 requires the bound.
GIT_TIMEOUT_SECONDS: Final[float] = 30.0


def declared_patch_path(diff: str) -> str | None:
    """The repo-relative path a diff claims to touch, or ``None``.

    Read from the diff rather than assumed, so a patch that targets a different
    file from the one the response names is caught instead of being applied to
    whatever the harness happened to stage.
    """
    for line in diff.splitlines():
        if line.startswith("+++ "):
            candidate = line[4:].strip()
            if candidate.startswith("b/"):
                return candidate[2:]
    return None


def _run_git(
    args: Sequence[str], cwd: pathlib.Path
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - fixed argv, no shell
        ["git", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=GIT_TIMEOUT_SECONDS,
        check=False,
    )


def git_apply(
    manifest_text: str,
    diff: str,
    path: str,
    *,
    check_only: bool,
) -> tuple[bool, str, str]:
    """Hand a patch to real git against ``manifest_text`` staged at ``path``.

    Returns ``(ok, reason, resulting_text)``; ``resulting_text`` is empty when
    ``check_only`` is set or when the call failed.

    The diff is written **exactly as given**. No trailing-newline repair, no
    normalisation - a verifier that edits its input is not a verifier, and the
    P0 this check exists to prevent was a checker that appended the terminator
    ``build_diff`` had omitted and then reported success on the repair.
    """
    if shutil.which("git") is None:
        return False, "git is not on PATH, so the patch cannot be verified", ""
    if path.startswith("/") or ":" in path:
        return False, f"patch path must be repo-relative, got {path!r}", ""

    with tempfile.TemporaryDirectory(prefix="srek3s-e2e-apply-") as tmp:
        root = pathlib.Path(tmp)
        staged = root / path
        patch_file = root / "candidate.patch"
        try:
            staged.parent.mkdir(parents=True, exist_ok=True)
            # newline="" so the bytes on disk equal the manifest exactly.
            # Platform newline translation would put a \r on every context line
            # and the check would fail for a reason that has nothing to do with
            # the patch.
            staged.write_text(manifest_text, encoding="utf-8", newline="")
            # The diff is written EXACTLY as given: no trailing-newline repair,
            # no normalisation. A verifier that edits its input is not a
            # verifier.
            patch_file.write_text(diff, encoding="utf-8", newline="")
        except OSError as exc:
            return False, f"could not stage the manifest for verification: {exc}", ""

        # Built as a list with the flag appended conditionally, never an inline
        # `"--check" if check_only else ""`. That inline form passes an empty
        # argument to git, and git reads it as the patch filename - so the apply
        # path reported "can't open patch ''" for every patch and the check-only
        # path silently became a *real* apply. A guard that stops verifying when
        # asked to verify, while reporting a filename error when asked to
        # apply, is worse than no guard: it looks like a failing system rather
        # than a broken check.
        args = ["-c", "safe.directory=*", "apply"]
        if check_only:
            args.append("--check")
        args += ["--whitespace=nowarn", str(patch_file)]

        try:
            init = _run_git(["init", "-q"], root)
            if init.returncode != 0:
                return False, f"git init failed: {init.stderr.strip()[:120]}", ""
            applied = _run_git(args, root)
        except subprocess.TimeoutExpired:
            return False, f"git exceeded {GIT_TIMEOUT_SECONDS}s", ""
        except OSError as exc:
            return False, f"git could not be executed: {exc}", ""

        if applied.returncode != 0:
            diagnostic = applied.stderr.strip() or applied.stdout.strip() or "none"
            return False, f"git rejected the patch: {diagnostic[:200]}", ""
        if check_only:
            return True, "git apply --check passed", ""
        if check_only:
            return True, "git apply --check passed", ""
        try:
            # Read with newline="" for the same reason the write did: the caller
            # compares this text against the manifest it supplied, and a
            # platform newline translation here would put a \r on every line
            # and make an unchanged document look changed everywhere.
            return True, "git apply passed", staged.read_text(encoding="utf-8")
        except OSError as exc:
            return False, f"the applied manifest could not be read back: {exc}", ""

    # Unreachable in practice; ``git_apply`` returns from inside the context
    # manager. Kept explicit so a future edit that adds a post-``with`` step
    # cannot fall off the end returning ``None``.


def _yaml_module() -> Any:
    try:
        import yaml
    except ImportError:  # pragma: no cover - PyYAML is a declared dependency
        raise VerificationError(
            "PyYAML is unavailable, so the patched manifest cannot be parsed and "
            "ROADMAP 4.2.6 cannot be asserted. Failing closed: an unparsed "
            "patch is an unverified patch."
        ) from None
    return yaml


def yaml_load(text: str, label: str) -> Any:
    """Parse a manifest, or fail the run.

    A parse failure on the *patched* document is the finding 4.2.6 exists to
    catch - a diff that applies cleanly and produces an invalid manifest is the
    worst outcome available to a reviewer - so it is never swallowed.
    """
    yaml = _yaml_module()
    try:
        return yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise VerificationError(f"the {label} manifest does not parse: {exc}") from exc


def container_memory_path(document: Any, container_name: str) -> tuple[Any, ...] | None:
    """Structural path to one container's ``resources.limits.memory``.

    Found by walking the parsed document, not by indentation, so a patch that
    moved the limit onto the wrong container is detected rather than blessed.
    """
    if not isinstance(document, dict):
        return None
    spec = document.get("spec")
    if not isinstance(spec, dict):
        return None
    template = spec.get("template")
    if not isinstance(template, dict):
        return None
    pod_spec = template.get("spec")
    if not isinstance(pod_spec, dict):
        return None
    containers = pod_spec.get("containers")
    if not isinstance(containers, list):
        return None
    for index, container in enumerate(containers):
        if not isinstance(container, dict) or container.get("name") != container_name:
            continue
        resources = container.get("resources")
        if not isinstance(resources, dict):
            return None
        limits = resources.get("limits")
        if not isinstance(limits, dict) or "memory" not in limits:
            return None
        return (
            "spec",
            "template",
            "spec",
            "containers",
            index,
            "resources",
            "limits",
            "memory",
        )
    return None


def semantic_change_paths(
    before: Any, after: Any, prefix: tuple[Any, ...] = ()
) -> list[tuple[Any, ...]]:
    """Every path at which two parsed manifests differ.

    Lists are compared element-wise rather than as opaque values, and a type
    change is always a difference: ``256`` and ``"256"`` are not the same
    document, and a Kubernetes quantity must not silently change type.
    """
    if type(before) is not type(after):
        return [prefix or ("<root>",)]
    if isinstance(before, dict):
        paths: list[tuple[Any, ...]] = []
        for key in sorted(set(before) | set(after), key=str):
            if key not in before or key not in after:
                paths.append(prefix + (key,))
            else:
                paths.extend(
                    semantic_change_paths(before[key], after[key], prefix + (key,))
                )
        return paths
    if isinstance(before, list):
        paths = []
        if len(before) != len(after):
            paths.append(prefix + ("<length>",))
        for index in range(min(len(before), len(after))):
            paths.extend(
                semantic_change_paths(before[index], after[index], prefix + (index,))
            )
        return paths
    if before != after:
        return [prefix or ("<root>",)]
    return []


def check_tier_one_patch(incident: dict[str, Any], manifest_text: str) -> str:
    """ROADMAP 4.2.6: one Tier-1 patch, checked end to end.

    The whole chain, in order, and each step failing the run:

    1. ``git apply --check`` accepts the exact bytes the agent emitted;
    2. ``git apply`` produces a new file, which is read back;
    3. both the original and the patched text parse as YAML;
    4. they differ at **exactly one** semantic field, and that field is
       ``resources.limits.memory`` of the container the incident names;
    5. it moved from the limit the incident reported to a different value; and
    6. the *stated* remedy names that container and both values.

    Step 6 is what makes this "matches the stated root cause" rather than "is a
    valid diff". A patch that raises a limit the RCA never mentions applies
    cleanly, parses, and changes one field - and is still not the change the
    responder was told to review.
    """
    response = response_of(incident)
    if response is None:
        raise VerificationError(
            f"{incident.get('incident_id')!r}: no captured response, so there is "
            f"no Tier-1 patch to verify"
        )
    identity = str(incident.get("incident_id"))
    remediation = response.get("remediation")
    if not isinstance(remediation, dict):
        raise VerificationError(
            f"{identity!r}: the response carries no `remediation` object, so the "
            f"patch cannot be located"
        )

    diff = remediation.get("git_patch")
    if not isinstance(diff, str) or not diff:
        raise VerificationError(
            f"{identity!r}: blast_radius_tier is {TIER_1} but remediation.git_patch "
            f"is {diff!r}; ARCH 5.1 requires a Tier-1 incident to carry a diff"
        )
    if remediation.get("patch_validated") is not True:
        raise VerificationError(
            f"{identity!r}: a Tier-1 patch is reported with "
            f"patch_validated={remediation.get('patch_validated')!r}; ARCH 5.4 "
            f"I-B2 allows that only after verification"
        )

    declared = remediation.get("target_manifest")
    if not isinstance(declared, str) or not declared:
        raise VerificationError(
            f"{identity!r}: remediation.target_manifest is missing, so the "
            f"patch has nothing to be applied against"
        )
    from_diff = declared_patch_path(diff)
    if from_diff != declared:
        raise VerificationError(
            f"{identity!r}: the diff declares {from_diff!r} but the response "
            f"names {declared!r} as its target. A reviewer would be sent to one "
            f"file and handed a diff for another."
        )

    ok, reason, _ = git_apply(manifest_text, diff, declared, check_only=True)
    if not ok:
        raise VerificationError(f"{identity!r}: {reason}")

    ok, reason, patched_text = git_apply(
        manifest_text, diff, declared, check_only=False
    )
    if not ok:
        raise VerificationError(f"{identity!r}: {reason}")

    container = incident.get("container_name")
    if not isinstance(container, str) or not container:
        raise VerificationError(
            f"{identity!r}: no container_name, so the patch's target field "
            f"cannot be located structurally"
        )
    reported = incident.get("resource_limits")
    old_value = reported.get("memory_limit") if isinstance(reported, dict) else None
    if not isinstance(old_value, str) or not old_value:
        raise VerificationError(
            f"{identity!r}: resource_limits.memory_limit is {old_value!r}; "
            f"without the limit the incident reported there is no 'from' to "
            f"check the change against"
        )

    before_doc = yaml_load(manifest_text, "original")
    after_doc = yaml_load(patched_text, "patched")
    expected_path = container_memory_path(before_doc, container)
    if expected_path is None:
        raise VerificationError(
            f"{identity!r}: the manifest has no resources.limits.memory for "
            f"container {container!r}, so a patch claiming to recalibrate it "
            f"cannot be grounded"
        )
    changed = semantic_change_paths(before_doc, after_doc)
    if changed != [expected_path]:
        raise VerificationError(
            f"{identity!r}: applying the patch changes {len(changed)} semantic "
            f"field(s) {changed[:6]}, expected exactly one at {expected_path}. A "
            f"patch that moves more than the named limit is not the stated remedy."
        )

    cursor_before: Any = before_doc
    cursor_after: Any = after_doc
    for part in expected_path:
        cursor_before = cursor_before[part]
        cursor_after = cursor_after[part]
    new_value = str(cursor_after)
    if str(cursor_before) != old_value:
        raise VerificationError(
            f"{identity!r}: the manifest's memory limit is {cursor_before!r} but "
            f"the incident reported {old_value!r}; the agent patched a drifted "
            f"file and the patch proves nothing about the running workload"
        )
    if new_value == old_value:
        raise VerificationError(
            f"{identity!r}: the patch applied and left the memory limit at "
            f"{new_value!r}; a remediation that changes nothing is not one"
        )

    summary = str(remediation.get("summary") or "")
    missing = [value for value in (old_value, new_value) if value not in summary]
    if missing or container not in summary:
        raise VerificationError(
            f"{identity!r}: the patch changes {container!r} from {old_value!r} to "
            f"{new_value!r}, but the stated remedy {summary!r} does not name "
            f"{missing or [container]}. The reviewer is being handed a change "
            f"the RCA does not describe."
        )

    return (
        f"{container} memory limit {old_value} -> {new_value}; git apply --check "
        f"and git apply both passed, and the YAML AST shows exactly one changed "
        f"field at {expected_path}"
    )


def check_tier_one_patches(
    incidents: Sequence[dict[str, Any]], manifest_text: str | None
) -> str:
    """ROADMAP 4.2.6 over every Tier-1 incident in the capture.

    A run with no Tier-1 incident is a **skip, not a pass**, and the skip reason
    is returned so the report can print it. Silently returning "0 Tier-1
    patches" would be the exact shape of the unticked-box problem this file
    exists to avoid: the run would be green and the box would still be
    unproven.
    """
    tier_one = [incident for incident in incidents if tier_of(incident) == TIER_1]
    if not tier_one:
        return f"{SKIP_PREFIX} no Tier-1 incident in the capture, so 4.2.6 is unproven"
    if manifest_text is None:
        raise VerificationError(
            f"{len(tier_one)} Tier-1 incident(s) were emitted but no manifest was "
            f"supplied to apply their patches against. Pass --manifest pointing "
            f"at the GitOps checkout the agent read; asserting on the patch "
            f"without the file it targets is not an assertion."
        )
    for incident in tier_one:
        check_tier_one_patch(incident, manifest_text)
    return f"{len(tier_one)} Tier-1 patch(es) applied with real git and YAML-parsed"


# ---------------------------------------------------------------------------
# ROADMAP 4.2.7 - Tier-2 carries no patch and a dispatch was emitted
# ---------------------------------------------------------------------------


def check_tier_two_dispatch(incident: dict[str, Any]) -> str:
    """ROADMAP 4.2.7 for one Tier-2 incident.

    Two independent halves, both required:

    * **the patch is absent** - ``git_patch == ""`` and ``patch_validated is
      False``. This is ARCH Â§5.4 I-B1, and the agent's schema already enforces
      it by refusing to construct a Tier-2 response that violates it. Asserting
      it here is still worth it: the runner reads the *bytes on the wire*, and
      a serialisation layer that added a field would be invisible to a model
      validator.
    * **a dispatch was emitted** - the response's ``rca_markdown`` is the
      rendered :mod:`agent.warroom` dispatch, which is the only place
      ``do_not_apply`` can reach an operator. ARCH Â§5.1 has no field for that
      marker and adding one is a breaking schema change (ARCH Â§10), so the
      dispatch is rendered into the existing deliverable rather than into a
      new one. Asserting the marker is therefore the assertion that *a
      dispatch*, and not merely a tier label, was produced.

    The other dispatch fields the response can carry are asserted too, because
    they are the same facts the dispatch carries and a response that disagrees
    with its own dispatch is a defect worth catching.
    """
    response = response_of(incident)
    if response is None:
        raise VerificationError(
            f"{incident.get('incident_id')!r}: no captured response, so no Tier-2 "
            f"dispatch to inspect"
        )
    identity = str(incident.get("incident_id"))

    if response.get("blast_radius_tier") != TIER_2:
        raise VerificationError(
            f"{identity!r}: checked as Tier-2 but the response says "
            f"{response.get('blast_radius_tier')!r}"
        )
    remediation = response.get("remediation")
    if not isinstance(remediation, dict):
        raise VerificationError(f"{identity!r}: the response carries no remediation")
    patch = remediation.get("git_patch")
    if patch != "":
        raise VerificationError(
            f"{identity!r}: a Tier-2 response carries a {len(str(patch))}-byte "
            f"git_patch. I-B1 makes that mutually exclusive with the tier, and a "
            f"responder who trusted the label would review a diff nobody "
            f"proposed. (ARCH 5.4 I-B1)"
        )
    if remediation.get("patch_validated") is not False:
        raise VerificationError(
            f"{identity!r}: patch_validated is "
            f"{remediation.get('patch_validated')!r} on a Tier-2 response; I-B1 "
            f"requires False"
        )

    policy = response.get("verification_policy")
    if not isinstance(policy, dict) or policy.get("mode") != "TIER_2_WAR_ROOM":
        raise VerificationError(
            f"{identity!r}: verification_policy.mode is "
            f"{(policy or {}).get('mode')!r}, not TIER_2_WAR_ROOM; the Tier-2 "
            f"observation mode ARCH 5.2 names was not selected"
        )
    if response.get("status") not in {"ESCALATED", "UNKNOWN"}:
        raise VerificationError(
            f"{identity!r}: status is {response.get('status')!r}; a Tier-2 "
            f"response reporting TRIAGED would contradict its own empty patch"
        )

    rca = response.get("rca_markdown")
    if not isinstance(rca, str) or WAR_ROOM_DO_NOT_APPLY_MARKER not in rca:
        raise VerificationError(
            f"{identity!r}: rca_markdown does not carry the war-room dispatch's "
            f"'{WAR_ROOM_DO_NOT_APPLY_MARKER}' marker, so no dispatch was "
            f"emitted. A Tier-2 response is a request for human judgement; the "
            f"marker is what tells the responder not to apply anything. "
            f"(ROADMAP 2.6.2)"
        )
    return f"{identity}: Tier-2, no patch, dispatch marker present"


def check_tier_two_dispatches(incidents: Sequence[dict[str, Any]]) -> str:
    """ROADMAP 4.2.7 over every Tier-2 incident, with the precondition proven.

    The precondition - that at least one Tier-2 incident *must* exist - is
    derived from the capture rather than assumed: a captured
    ``CrashLoopBackOff`` incident cannot be routed to Tier-1 under ARCH Â§5.3,
    because the very first precondition is ``reason == OOMKilled``. Its
    presence therefore guarantees a Tier-2 response, and its absence means the
    box was never exercised.
    """
    captured = [incident for incident in incidents if response_of(incident) is not None]
    if not captured:
        return (
            f"{SKIP_PREFIX} no captured response in the capture, so 4.2.7 is unproven"
        )

    tier_two = [incident for incident in captured if tier_of(incident) == TIER_2]
    demands = [
        incident
        for incident in captured
        if incident.get("reason") in TIER_ONLY_POSSIBLE_REASONS
    ]
    if not tier_two:
        raise VerificationError(
            f"no Tier-2 response in {len(captured)} captured exchange(s)"
            + (
                f", including {len(demands)} whose reason is "
                f"{sorted(TIER_ONLY_POSSIBLE_REASONS)} - ARCH 5.3 admits Tier-1 "
                f"only for OOMKilled, so a dispatch was required and none was "
                f"emitted"
                if demands
                else "; every captured response was Tier-1, so 4.2.7 was not "
                "exercised by this run"
            )
        )
    for incident in tier_two:
        check_tier_two_dispatch(incident)
    return (
        f"{len(tier_two)} Tier-2 incident(s): empty patch and a war-room dispatch each"
    )


# ---------------------------------------------------------------------------
# Cluster interaction - all of it here, none of it at import time
# ---------------------------------------------------------------------------


def run_kubectl(args: Sequence[str], *, check: bool = True) -> str:
    """Invoke kubectl and return stdout.

    Deliberately a subprocess rather than a client library: the runner has to
    work against a cluster the agent under test also talks to, and adding a
    Kubernetes client dependency to a load/verification harness trades a real
    property for a convenience.
    """
    completed = subprocess.run(  # noqa: S603 - fixed argv, no shell
        ["kubectl", *args],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    if check and completed.returncode != 0:
        raise VerificationError(
            f"kubectl {' '.join(args)} failed ({completed.returncode}): "
            f"{completed.stderr.strip()}"
        )
    return completed.stdout


def get_pod(namespace: str, selector: str) -> dict[str, Any] | None:
    """Return the pod's JSON, or ``None`` when nothing matches."""
    raw = run_kubectl(["get", "pods", "-n", namespace, "-l", selector, "-o", "json"])
    items = json.loads(raw).get("items") or []
    return items[0] if items else None


def read_observation(pod: dict[str, Any]) -> list[Observation]:
    """Convert a pod's container statuses into observations.

    Reads ``state`` and ``lastState.terminated`` because the causal chain lives in
    the pair: by the time a CrashLoopBackOff is observable, ``state.terminated``
    has already been cleared and the cause survives only in ``lastState``.
    """
    now = time.monotonic()
    observations: list[Observation] = []
    for status in pod.get("status", {}).get("containerStatuses") or []:
        state = status.get("state") or {}
        waiting = state.get("waiting") or {}
        terminated = state.get("terminated") or {}
        previous = (status.get("lastState") or {}).get("terminated") or {}
        observations.append(
            Observation(
                timestamp=now,
                state=str(
                    waiting.get("reason") or ("Terminated" if terminated else "Running")
                ),
                exit_code=terminated.get("exitCode"),
                reason=terminated.get("reason"),
                restart_count=int(status.get("restartCount") or 0),
                previous_exit_code=previous.get("exitCode"),
                previous_reason=previous.get("reason"),
            )
        )
    return observations


# ---------------------------------------------------------------------------
# ROADMAP 4.2.8 - the run mutated nothing outside the chaos namespace
#
# Why this is a real observation and not a restatement of the RBAC rule
# -----------------------------------------------------------------------
# In the detonation the Sentinel runs as a **local process against the k3s
# admin kubeconfig**, not under its own read-only ServiceAccount. So the thing
# being asserted here is the binary's behaviour with the strongest credential
# it could possibly hold, not a permission it was denied. That is strictly
# stronger evidence than the RBAC manifests, and it is the only form of this
# claim that observes a run rather than a manifest.
# ---------------------------------------------------------------------------

#: Object kinds the snapshot covers.
#:
#: Chosen to be the kinds a mutating client would create or update, including
#: every RBAC and workload kind in `deploy/`. Pods are included deliberately:
#: their `generation` is meaningless, so they are judged on `resourceVersion`,
#: but a pod *appearing* outside the chaos namespace is still a cluster write.
SNAPSHOT_KINDS: Final[tuple[str, ...]] = (
    "daemonsets",
    "configmaps",
    "cronjobs",
    "deployments",
    "jobs",
    "persistentvolumeclaims",
    "pods",
    "replicasets",
    "secrets",
    "serviceaccounts",
    "services",
    "statefulsets",
)

#: Namespaces whose contents change on a live k3s whether or not anything in
#: this project is running.
#:
#: `kube-system` holds a leader-election lease that every control-plane
#: component renews on a timer, and its deployments roll on their own schedule.
#: k3s additionally installs and upgrades coredns and traefik through a Helm
#: controller, **asynchronously** - their objects appear *after* any pre-flight
#: baseline is taken. Asserting anything about that namespace would fail every
#: run for reasons that have nothing to do with the Sentinel - the same
#: "precondition satisfied by the wrong check" shape as the `ctr --namespace`
#: defect recorded in ROADMAP 4.2.2.
#:
#: The exclusion is applied to **all three** sub-checks (object set, generation,
#: resourceVersion). It used to apply only to resourceVersion, which meant a
#: coredns Deployment installed by the Helm controller between the two images
#: was reported as a *creation* by a component that structurally cannot write -
#: a correct check applied to background noise. Every exempt change is still
#: **counted and reported**; what is removed is the failure, not the evidence.
#: That is the honest form of the exclusion: narrow, named, visible, and paired
#: with the stricter checks that still apply everywhere else.
NOISY_SYSTEM_NAMESPACES: Final[frozenset[str]] = frozenset(
    {
        "kube-node-lease",
        "kube-public",
        "kube-system",
        "local-path-storage",
    }
)


def is_exempt_namespace(namespace: str, chaos_namespace: str = CHAOS_NAMESPACE) -> bool:
    """Whether churn in ``namespace`` says nothing about the components under test.

    Two reasons, and they are different in kind:

    * the **chaos namespace** is where the harness applies the fixture itself, so
      every write there is the harness's own and is expected;
    * a **noisy system namespace** is rewritten by the k3s control plane on its
      own schedule (see :data:`NOISY_SYSTEM_NAMESPACES`).

    The comparison is an **exact** namespace match, deliberately. A prefix or
    substring test would exempt ``kube-system-staging`` or ``my-kube-system``,
    which are not the control plane's namespaces, and would turn the exemption
    into a hole in the one check that exists to catch an out-of-namespace
    write. ``tests/e2e/show_mutation.py`` prints the verdict using this same
    function, so the console and the exit code cannot disagree.
    """
    return namespace == chaos_namespace or namespace in NOISY_SYSTEM_NAMESPACES


def snapshot_cluster() -> dict[str, dict[str, Any]]:
    """Capture ``generation`` and ``resourceVersion`` for every object.

    Keyed ``"<apiVersion>/<kind>/<namespace>/<name>"`` and valued with the
    metadata plus the owning namespace, so :func:`check_no_cluster_mutation` is
    a pure function over two of these and the comparison needs no cluster.

    ``check=True``, deliberately. Every kind in :data:`SNAPSHOT_KINDS` is a core
    API group present in any k3s or Kubernetes cluster, so a non-zero exit means
    ``kubectl`` failed - a bad kubeconfig, a missing cluster, an apiserver that
    went away mid-run. Swallowing that would produce an empty snapshot, and an
    empty snapshot compared against an empty after-image passes every
    no-mutation assertion while proving nothing.
    """
    snapshot: dict[str, dict[str, Any]] = {}
    for kind in SNAPSHOT_KINDS:
        document = json.loads(run_kubectl(["get", kind, "-A", "-o", "json"]))
        if not isinstance(document, dict):
            continue
        for item in document.get("items") or []:
            if not isinstance(item, dict):
                continue
            metadata = item.get("metadata") or {}
            if not isinstance(metadata, dict):
                continue
            api_version = str(item.get("apiVersion") or "")
            kind_name = str(item.get("kind") or kind)
            namespace = str(metadata.get("namespace") or "")
            name = str(metadata.get("name") or "")
            if not name:
                continue
            snapshot[f"{api_version}/{kind_name}/{namespace}/{name}"] = {
                "generation": metadata.get("generation"),
                "namespace": namespace,
                "resourceVersion": metadata.get("resourceVersion"),
                "uid": metadata.get("uid"),
            }
    return snapshot


def check_no_cluster_mutation(
    before: dict[str, dict[str, Any]],
    after: dict[str, dict[str, Any]],
    chaos_namespace: str = CHAOS_NAMESPACE,
) -> str:
    """ROADMAP 4.2.8: prove only the chaos namespace changed.

    Three checks, in decreasing strictness, each applied outside the exempt
    namespaces of :func:`is_exempt_namespace`:

    1. **Object set.** Anything created or deleted is a write, full stop. A
       `generation` comparison alone would miss a create entirely, and a create
       is the cheapest possible way to prove write authority was used.
    2. **Generation.** ``generation`` is a spec-change counter; the apiserver
       does not bump it for a status update. A changed generation is therefore
       a spec write and nothing else - which is what makes it assertable on a
       live cluster where ``resourceVersion`` is not.
    3. **resourceVersion.** Strictly broader, and the one that fires most.

    All three share **one** exemption set, the chaos namespace plus
    :data:`NOISY_SYSTEM_NAMESPACES`. Applying it to all three is what makes the
    check usable on a live k3s: the control plane's Helm controller installs
    coredns and traefik *asynchronously*, so their objects legitimately appear
    after the pre-flight baseline. That is background noise, not a mutation by
    a component that holds no write credential.

    **What the exemption does not do.** It is not a deletion of the checks and
    it is not a blanket amnesty:

    * inside the chaos namespace everything is allowed, because the harness
      applies the fixture there itself;
    * a creation, deletion, generation bump or resourceVersion move in *any*
      namespace outside both sets still fails, and each direction has a
      negative control proving it;
    * exempt changes are **counted and reported** in the returned description,
      so a reader sees how much noise was absorbed rather than trusting that
      there was none.
    """

    def _namespace(key: str, entry: dict[str, Any]) -> str:
        value = entry.get("namespace")
        return str(value) if isinstance(value, str) else ""

    def _bucket(namespace: str) -> str:
        """``"chaos"``, ``"noisy"`` or ``"asserted"`` - the only three answers.

        One classifier for all three sub-checks, so an object cannot be exempt
        from the object set and asserted on by the generation check. That
        asymmetry is exactly the defect being fixed: the exemption used to be
        applied to one sub-check and not the others, and a check that is strict
        about some writes and lenient about others is not a check.
        """
        if namespace == chaos_namespace:
            return "chaos"
        if namespace in NOISY_SYSTEM_NAMESPACES:
            return "noisy"
        return "asserted"

    before_keys = set(before)
    after_keys = set(after)
    created = sorted(after_keys - before_keys)
    deleted = sorted(before_keys - after_keys)
    shared = before_keys & after_keys

    # Partitioned once, up front, so every later comparison reads a decision
    # that was already made rather than re-deriving it.
    assert_created = [
        k for k in created if _bucket(_namespace(k, after[k])) == "asserted"
    ]
    assert_deleted = [
        k for k in deleted if _bucket(_namespace(k, before[k])) == "asserted"
    ]
    chaos_created = [k for k in created if _bucket(_namespace(k, after[k])) == "chaos"]
    chaos_deleted = [k for k in deleted if _bucket(_namespace(k, before[k])) == "chaos"]
    noisy_created = [k for k in created if _bucket(_namespace(k, after[k])) == "noisy"]
    noisy_deleted = [k for k in deleted if _bucket(_namespace(k, before[k])) == "noisy"]

    if assert_created:
        raise VerificationError(
            f"{len(assert_created)} object(s) were created outside "
            f"{chaos_namespace!r} and outside {sorted(NOISY_SYSTEM_NAMESPACES)} "
            f"during the run: {assert_created[:6]}. The "
            f"Sentinel and the agent are structurally read-only; a create here "
            f"means one of them held and used a write credential."
        )
    if assert_deleted:
        raise VerificationError(
            f"{len(assert_deleted)} object(s) were deleted outside "
            f"{chaos_namespace!r} and outside {sorted(NOISY_SYSTEM_NAMESPACES)} "
            f"during the run: {assert_deleted[:6]}"
        )

    generation_changes: list[str] = []
    version_changes: list[str] = []
    chaos_changed: set[str] = set()
    #: Exempt objects, keyed by bucket, so the report can attribute a change to
    #: the chaos namespace or to the control plane rather than lumping them
    #: together. They are different reasons and a reader is owed the difference.
    noisy_generation: set[str] = set()
    noisy_version: set[str] = set()
    for key in sorted(shared):
        left = before[key]
        right = after[key]
        bucket = _bucket(_namespace(key, right))
        if left.get("generation") != right.get("generation"):
            if bucket == "chaos":
                chaos_changed.add(key)
            elif bucket == "noisy":
                # A control-plane Deployment rolling under its own controller
                # (k3s upgrading coredns or traefik). Counted and reported, not
                # failed - the same reason the object set is exempt above.
                noisy_generation.add(key)
            else:
                generation_changes.append(
                    f"{key} generation {left.get('generation')!r} -> "
                    f"{right.get('generation')!r}"
                )
        if left.get("resourceVersion") != right.get("resourceVersion"):
            if bucket == "chaos":
                chaos_changed.add(key)
            elif bucket == "noisy":
                noisy_version.add(key)
            else:
                version_changes.append(
                    f"{key} resourceVersion {left.get('resourceVersion')!r} -> "
                    f"{right.get('resourceVersion')!r}"
                )

    if generation_changes:
        raise VerificationError(
            f"{len(generation_changes)} object(s) outside {chaos_namespace!r} "
            f"and outside {sorted(NOISY_SYSTEM_NAMESPACES)} changed generation "
            f"during the run, which is a spec write: {generation_changes[:6]}"
        )
    if version_changes:
        raise VerificationError(
            f"{len(version_changes)} object(s) outside {chaos_namespace!r} and "
            f"outside the continuously-written system namespaces changed "
            f"resourceVersion: {version_changes[:6]}"
        )

    # Counted per **object**, not per event. A coredns Deployment that appears
    # and then has its generation moved is one churned object, and a report
    # saying "3 changes" for it would misdescribe what the cluster did - so the
    # sets are unions, not sums, and an object in both the generation and the
    # resourceVersion tally is counted once.
    chaos_objects = set(chaos_created) | set(chaos_deleted) | chaos_changed
    noisy_objects = (
        set(noisy_created) | set(noisy_deleted) | noisy_generation | noisy_version
    )
    return (
        f"no mutation outside {chaos_namespace!r} and outside "
        f"{sorted(NOISY_SYSTEM_NAMESPACES)}: {len(shared)} shared object(s) "
        f"unchanged in generation and resourceVersion; "
        f"{len(chaos_objects)} object(s) appeared or changed inside the chaos "
        f"namespace ({len(chaos_created)} created, {len(chaos_deleted)} "
        f"deleted, {len(chaos_changed)} changed in place); "
        f"{len(noisy_objects)} object(s) churned inside the exempt system "
        f"namespaces ({len(noisy_created)} created, {len(noisy_deleted)} "
        f"deleted, {len(noisy_generation)} generation change(s), "
        f"{len(noisy_version)} resourceVersion change(s)) - k3s controllers, "
        f"leader election and Helm install/upgrade, excluded by name and "
        f"counted here"
    )


@dataclass
class RunReport:
    """What a run produced, and whether it proved anything.

    ``notes`` and ``failures`` are separate lists, and the separation is
    load-bearing rather than cosmetic. The first version of this type appended
    both to one list and let the renderer prefix them, so a consumer asking "did
    the run pass" had to string-match ``NOTE`` against a rendered string - and
    the CLI returned 0 unconditionally, meaning **a failed verification exited
    successfully**. A report whose pass/fail is a formatting convention is a
    report that reports success.
    """

    incidents: list[dict[str, Any]] = field(default_factory=list)
    observations: list[Observation] = field(default_factory=list)
    gated: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    failures: list[str] = field(default_factory=list)
    #: Checks that could not run, with the reason. Rendered at the same
    #: prominence as failures, because a box nobody could evaluate is not a box
    #: that passed, and the only way to tell those apart from the outside is to
    #: see this list.
    skipped: list[str] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        """Exit-code policy: only ``failures`` block. Notes never do.

        ``skipped`` deliberately does not block either, and that is a decision
        with a cost. A skip is a box left unproven, so hiding it behind a
        non-zero exit would make every offline fixture run "fail" for having no
        cluster. It is instead rendered in its own section next to the verdict,
        so a reader of the log sees "PASS, 2 skipped" rather than a bare PASS.
        """
        return not self.failures

    def note(self, message: str) -> None:
        self.notes.append(message)

    def fail(self, message: str) -> None:
        self.failures.append(message)

    def skip(self, message: str) -> None:
        self.skipped.append(message)


def verify(
    incidents: Sequence[dict[str, Any]],
    observations: Sequence[Observation],
    window: float,
    *,
    manifest_text: str | None = None,
    snapshot_before: dict[str, dict[str, Any]] | None = None,
    snapshot_after: dict[str, dict[str, Any]] | None = None,
) -> RunReport:
    """Run every check and collect the results rather than stopping at the first.

    All-or-nothing would hide the shape of a failure: a run that produced no
    incidents and a run whose incidents were not redacted need completely
    different fixes, and reporting only the first one costs a whole run cycle.

    The keyword-only arguments feed the ROADMAP 4.2.3/4.2.6/4.2.8 checks. They
    default to ``None`` so an offline caller - a fixture array, a unit test -
    gets the checks *skipped with a reason* rather than failed, which is the
    difference between "this run could not evaluate it" and "this run proved it
    wrong".
    """
    report = RunReport(list(incidents), list(observations))

    for incident in incidents:
        skip = gate_redaction(incident)
        if skip is not None:
            report.gated.append(f"{incident.get('incident_id')}: {skip}")
            continue
        try:
            logs = check_redaction(incident)
            check_diagnostics_survived(logs)
        except VerificationError as error:
            # `fail`, not `note`. With both routed to one list this was invisible;
            # once separated, `passed` flipped to True on a leaked secret, which is
            # what the split exists to make impossible to miss.
            report.fail(f"{incident.get('incident_id')}: {error}")

    # Fail when gating left *nothing* checked. A healthy run has some gated
    # first-crash incidents and some checked ones, and that is normal; the trap is
    # a run where the check was skipped throughout and the redaction assertion was
    # therefore never evaluated even once.
    #
    # Written as the length comparison it actually is. An earlier version guarded
    # it with `not any(not i.get("scrubbed_logs") ...)`, which is a statement
    # about empty log lists rather than about gating, and so never fired for the
    # case it was written for.
    if report.gated and len(report.gated) == len(incidents):
        report.fail(
            f"all {len(report.gated)} incident(s) were gated out of the "
            f"redaction check; a run in which nothing was checked is not a "
            f"passing run"
        )

    try:
        report.note(f"incident window: {check_incident_window(incidents)}")
    except VerificationError as error:
        report.fail(str(error))

    try:
        report.note(f"causal chain: {check_causal_chain(observations)}")
    except VerificationError as error:
        report.fail(str(error))

    if len(observations) < 2:
        report.fail(
            f"only {len(observations)} observation(s); the causal chain needs at "
            f"least one sample before and one after the restart to be observable"
        )

    _verify_response_half(report, incidents, observations, manifest_text)
    _verify_no_mutation(report, snapshot_before, snapshot_after)

    return report


def _verify_response_half(
    report: RunReport,
    incidents: Sequence[dict[str, Any]],
    observations: Sequence[Observation],
    manifest_text: str | None,
) -> None:
    """ROADMAP 4.2.3, 4.2.5, 4.2.6 and 4.2.7.

    Split out of :func:`verify` so the ordering of these four relative to the
    sampling checks is visible in one place, and so the "nothing was captured"
    case is decided once rather than four times.
    """
    captured = [i for i in incidents if CAPTURE_KEY in i]
    if not captured:
        report.skip(
            "4.2.3 latency ratio, 4.2.5 rca specificity, 4.2.6 Tier-1 patch and "
            "4.2.7 Tier-2 dispatch: no exchange was captured (the offline "
            "fixtures carry no agent response, so these boxes are unproven by "
            "this run)"
        )
        return

    # One guard for four checks. A capture whose upstream body is not JSON is an
    # agent that answered nothing useful; running the four response checks
    # against a list where `response_of` returns None for every entry would skip
    # all of them and report a clean run.
    for incident in captured:
        try:
            check_captured_response_exists(incident)
        except VerificationError as error:
            report.fail(str(error))
            return

    # Bound explicitly rather than left to inference. An un-annotated tuple of
    # lambdas infers as `tuple[tuple[str, Callable[[], Any]]]`-adjacent types
    # that mypy --strict then treats as untyped calls, and a check dispatched
    # through a `Callable` also loses the guarantee that each one returns `str`
    # - which is what makes the "SKIP:" prefix below meaningful.
    checks: tuple[tuple[str, Callable[[], str]], ...] = (
        (
            "4.2.3 detection latency + injection ratio",
            lambda: check_detection_latency(incidents, observations),
        ),
        ("4.2.5 rca specificity", lambda: check_rca_is_specific(incidents)),
        (
            "4.2.6 Tier-1 patch",
            lambda: check_tier_one_patches(incidents, manifest_text),
        ),
        ("4.2.7 Tier-2 dispatch", lambda: check_tier_two_dispatches(incidents)),
    )
    for label, check in checks:
        try:
            result = check()
        except VerificationError as error:
            report.fail(f"{label}: {error}")
            continue
        if result.startswith(SKIP_PREFIX):
            report.skip(f"{label}: {result[len(SKIP_PREFIX) :].strip()}")
        else:
            report.note(f"{label}: {result}")


def _verify_no_mutation(
    report: RunReport,
    before: dict[str, dict[str, Any]] | None,
    after: dict[str, dict[str, Any]] | None,
) -> None:
    """ROADMAP 4.2.8, skipped with a reason when a snapshot is absent.

    One side without the other is a failure, not a skip: a before-image with no
    after-image proves nothing, and treating the missing half as "no data"
    would hide a wiring mistake in the harness - which is the failure mode this
    file has been bitten by twice.
    """
    label = "4.2.8 no cluster mutation"
    if before is None and after is None:
        report.skip(
            f"{label}: no before/after snapshot was supplied, so no observation "
            f"of cluster state was taken during the run"
        )
        return
    if before is None or after is None:
        missing = "--snapshot-before" if before is None else "--snapshot-after"
        report.fail(
            f"{label}: only one side of the snapshot was supplied; pass {missing} "
            f"as well. A one-sided comparison cannot distinguish 'nothing "
            f"changed' from 'nothing was looked at'."
        )
        return
    try:
        report.note(f"{label}: {check_no_cluster_mutation(before, after)}")
    except VerificationError as error:
        report.fail(f"{label}: {error}")


def render(report: RunReport) -> str:
    lines = [
        "SREK3S E2E report",
        f"  incidents:   {len(report.incidents)}",
        f"  observations:{len(report.observations)}",
        f"  gated out:   {len(report.gated)}",
        f"  unproven:    {len(report.skipped)}",
        "",
    ]
    for gated in report.gated:
        lines.append(f"  GATED  {gated}")
    for skipped in report.skipped:
        lines.append(f"  SKIP   {skipped}")
    for note in report.notes:
        lines.append(f"  note   {note}")
    for failure in report.failures:
        lines.append(f"  FAIL   {failure}")
    lines.append("")
    verdict = "PASS" if report.passed else "FAIL"
    if report.passed and report.skipped:
        verdict += f" (with {len(report.skipped)} unproven check(s) - see SKIP above)"
    lines.append(f"  RESULT: {verdict}")
    return "\n".join(lines)


def load_incidents(path: str) -> list[dict[str, Any]]:
    """Load captured incidents, accepting either a JSON array or NDJSON.

    The capture proxy appends one JSON object per line, because a proxy that
    rewrote a growing file into an array would have to rewrite it on every
    request and would lose everything if it were killed mid-write. NDJSON is
    append-only and crash-tolerant, so that is what the proxy writes - which
    means this loader has to read it.

    Accepting a plain JSON array too is not leniency for its own sake: the
    fixtures in ``tests/fixtures/`` are arrays, and a loader that only read one
    shape would make every offline caller and every live caller disagree about
    what a capture file is.

    A missing file returns ``[]`` rather than raising. That is a *silent* failure
    mode, so it is deliberately left to be caught by ``check_incident_window``
    rather than being papered over: a run with no captures must fail, and that
    invariant is what makes it fail, loudly, with a message naming the cause.
    """
    try:
        raw = pathlib.Path(path).read_text(encoding="utf-8")
    except OSError:
        return []
    if not raw.strip():
        return []

    try:
        parsed: Any = json.loads(raw)
    except json.JSONDecodeError:
        records: list[Any] = []
        for number, line in enumerate(raw.splitlines(), start=1):
            if not line.strip():
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as error:
                raise VerificationError(
                    f"{path}:{number} is not valid JSON: {error}. A truncated line "
                    f"here means the proxy was killed mid-append, which is worth "
                    f"knowing before trusting the rest of the file."
                ) from error
        parsed = records

    # A single NDJSON line parses as an object, not a list. Wrapping it is
    # correct rather than special-casing: one incident is a one-element window.
    if isinstance(parsed, dict):
        return [parsed]
    if not isinstance(parsed, list):
        raise VerificationError(
            f"{path} holds a {type(parsed).__name__}, want a JSON array of "
            f"incidents or NDJSON"
        )
    return [record for record in parsed if isinstance(record, dict)]


def _load_snapshot(path: str | None) -> dict[str, dict[str, Any]] | None:
    """Read a snapshot written by ``--snapshot-out``, or ``None``.

    A path that was given but cannot be read is a hard error rather than
    ``None``. ``None`` means "this check was not wired up", which the report
    records as a skip; a truncated or missing snapshot file means the wiring is
    *broken*, and reporting that as "not attempted" would hide the difference
    between the two - which is precisely how a sampling window ends up opening
    after the fault it was meant to observe.
    """
    if not path:
        return None
    try:
        document = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
    except OSError as exc:
        raise VerificationError(
            f"snapshot {path!r} was named but could not be read: {exc}"
        ) from exc
    except json.JSONDecodeError as exc:
        raise VerificationError(
            f"snapshot {path!r} is not valid JSON: {exc}. A truncated file here "
            f"means the job that wrote it was killed mid-write."
        ) from exc
    if not isinstance(document, dict):
        raise VerificationError(
            f"snapshot {path!r} holds a {type(document).__name__}, want an object"
        )
    return {key: value for key, value in document.items() if isinstance(value, dict)}


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "selector",
        help="pod selector for the fixture, e.g. srek3s.io/chaos=oom",
    )
    parser.add_argument(
        "--namespace", default=CHAOS_NAMESPACE, help="fixture namespace"
    )
    parser.add_argument(
        "--observe-seconds",
        type=float,
        default=DEFAULT_WINDOW,
        help="how long to sample. A window, not a count: the dedup key includes "
        "the restart count, so every restart is a distinct incident.",
    )
    parser.add_argument(
        "--incident-file",
        help="path to a collected incidents JSON file; skips live sampling and "
        "verifies what was captured",
    )
    parser.add_argument(
        "--manifest",
        help="the GitOps manifest a Tier-1 patch is applied against "
        "(ROADMAP 4.2.6). Points at the file the agent's manifest provider "
        "served, e.g. deploy/chaos/oom-leak.yaml.",
    )
    parser.add_argument(
        "--snapshot-before",
        help="cluster snapshot taken before the run (ROADMAP 4.2.8). Must be "
        "written by --snapshot-out, in a step that predates the component "
        "under test.",
    )
    parser.add_argument(
        "--snapshot-after",
        help="write the after-snapshot here, taken the moment sampling ends, "
        "and compare it with --snapshot-before (ROADMAP 4.2.8)",
    )
    parser.add_argument(
        "--snapshot-out",
        help="write a cluster snapshot to this path and exit without verifying "
        "(the before half of ROADMAP 4.2.8; run in a step that predates the "
        "component under test)",
    )
    args = parser.parse_args(argv)

    if args.snapshot_out:
        # Deliberately its own exit path. A snapshot taken in the middle of a
        # verification run would be taken *after* the runner started sampling,
        # and the whole point of the before-image is that it predates the
        # Sentinel. Making it a separate invocation is what enforces that.
        snapshot = snapshot_cluster()
        pathlib.Path(args.snapshot_out).write_text(
            json.dumps(snapshot, indent=2, sort_keys=True), encoding="utf-8"
        )
        print(
            f"wrote {len(snapshot)} object(s) to {args.snapshot_out} "
            f"across {len(SNAPSHOT_KINDS)} kind(s)"
        )
        return 0

    incidents: list[dict[str, Any]] = []
    observations: list[Observation] = []

    manifest_text: str | None = None
    if args.manifest:
        manifest_text = pathlib.Path(args.manifest).read_text(encoding="utf-8")
    try:
        snapshot_before = _load_snapshot(args.snapshot_before)
    except VerificationError as error:
        # A broken snapshot is a harness failure, not a check failure, and it
        # is reported as such rather than as a traceback: the job log is the
        # only diagnostic a reviewer has, and a stack trace here says nothing
        # about which half of the comparison was unreadable.
        print(render(RunReport(failures=[str(error)])))
        return 1

    # Sampling is NOT in an `else`. It was, and that made the two halves of the
    # report mutually exclusive: passing --incident-file supplied payloads but
    # zero observations, so check_causal_chain raised "no observations; the pod
    # was never seen" and verify() added a second failure for the sample count.
    # A run wired the obvious way - capture the wire, then verify - could only
    # ever fail, just with a different message. Both halves are required and
    # both are collected.
    #
    # Sampling runs BEFORE the capture is read, and the order is load-bearing.
    # The capture proxy appends for as long as it is running, so a runner
    # started before the chaos fixture is applied sees the whole lifecycle: the
    # cause while the container is still Terminated, and the symptom after it
    # restarts. Reading the capture first - or starting the runner after the
    # fixture - opens the window too late, and `check_causal_chain` then fails
    # with "never observed Terminated{exit_code: 137}" because a poll taken
    # after the restart can only ever show the symptom. This function's own
    # docstring says so, and the workflow was doing the opposite.
    deadline = time.monotonic() + args.observe_seconds
    while time.monotonic() < deadline:
        pod = get_pod(args.namespace, args.selector)
        if pod is not None:
            observations.extend(read_observation(pod))
        time.sleep(1.0)

    # The after-snapshot, taken here and not in a later step. The comparison has
    # to bracket the whole run, and a separate step could be reordered to run
    # before teardown, or dropped entirely, and either would turn 4.2.8 into a
    # comparison of two images taken at the same instant. Taking it at the point
    # sampling ends also means it observes every write the run caused, rather
    # than racing the tail of them.
    snapshot_after: dict[str, dict[str, Any]] | None = None
    if args.snapshot_after:
        try:
            snapshot_after = snapshot_cluster()
        except VerificationError as error:
            print(render(RunReport(failures=[f"4.2.8: {error}"])))
            return 1
        pathlib.Path(args.snapshot_after).write_text(
            json.dumps(snapshot_after, indent=2, sort_keys=True), encoding="utf-8"
        )
        print(
            f"wrote {len(snapshot_after)} object(s) to {args.snapshot_after} "
            f"after the observation window"
        )

    if args.incident_file:
        incidents = load_incidents(args.incident_file)

    report = verify(
        incidents,
        observations,
        window=args.observe_seconds,
        manifest_text=manifest_text,
        snapshot_before=snapshot_before,
        snapshot_after=snapshot_after,
    )
    print(render(report))
    # Non-zero on failure. The first version returned 0 unconditionally, so a run
    # that proved nothing was indistinguishable from a run that proved everything
    # - which is the one property an end-to-end harness must not get wrong.
    return 0 if report.passed else 1


if __name__ == "__main__":
    sys.exit(main())
