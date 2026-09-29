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
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from dataclasses import dataclass, field
from typing import Any, Final, Sequence

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
#: AGENTS.md §3 rule 5 requires ``basic_auth_url`` to target the secret segment
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

    @property
    def passed(self) -> bool:
        """Exit-code policy: only ``failures`` block. Notes never do."""
        return not self.failures

    def note(self, message: str) -> None:
        self.notes.append(message)

    def fail(self, message: str) -> None:
        self.failures.append(message)


def verify(
    incidents: Sequence[dict[str, Any]],
    observations: Sequence[Observation],
    window: float,
) -> RunReport:
    """Run every check and collect the results rather than stopping at the first.

    All-or-nothing would hide the shape of a failure: a run that produced no
    incidents and a run whose incidents were not redacted need completely
    different fixes, and reporting only the first one costs a whole run cycle.
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

    return report


def render(report: RunReport) -> str:
    lines = [
        "SREK3S E2E report",
        f"  incidents:   {len(report.incidents)}",
        f"  observations:{len(report.observations)}",
        f"  gated out:   {len(report.gated)}",
        "",
    ]
    for gated in report.gated:
        lines.append(f"  GATED  {gated}")
    for note in report.notes:
        lines.append(f"  note   {note}")
    for failure in report.failures:
        lines.append(f"  FAIL   {failure}")
    lines.append("")
    lines.append(f"  RESULT: {'PASS' if report.passed else 'FAIL'}")
    return "\n".join(lines)


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
    args = parser.parse_args(argv)

    incidents: list[dict[str, Any]] = []
    observations: list[Observation] = []

    if args.incident_file:
        incidents = json.loads(open(args.incident_file, encoding="utf-8").read())
    else:
        deadline = time.monotonic() + args.observe_seconds
        while time.monotonic() < deadline:
            pod = get_pod(args.namespace, args.selector)
            if pod is not None:
                observations.extend(read_observation(pod))
            time.sleep(1.0)

    report = verify(incidents, observations, window=args.observe_seconds)
    print(render(report))
    # Non-zero on failure. The first version returned 0 unconditionally, so a run
    # that proved nothing was indistinguishable from a run that proved everything
    # - which is the one property an end-to-end harness must not get wrong.
    return 0 if report.passed else 1


if __name__ == "__main__":
    sys.exit(main())
