"""Tests for ``agent/verify.py`` - post-remediation verification (ROADMAP 4.3.1-4.3.3, 4.3.5).

The module's knowledge is in four claims, and each is tested against the way it
would fail rather than only against the way it works:

1. **The observation window is bounded.** By a monotonic deadline *and* by an
   iteration count, either of which alone would be sufficient to terminate.
2. **``max_requeue_attempts`` is a bound, not a counter the caller holds.** The
   budget is a module-owned value that only decreases; the chain terminates after
   ``max_requeue_attempts + 1`` observation windows; and a caller that tries to
   rewind it is refused rather than believed.
3. **The loop writes nothing.** Proved two ways: by introspecting the module's
   AST for any mutating call or import, and by arming a CPython audit hook around
   a real run. Both checks carry a negative control, because a check that cannot
   fail is not a check.
4. **The blocking read leaves the event loop.** Measured with a heartbeat
   coroutine, with a negative control that deliberately stalls the loop and
   proves the measurement detects it.

Verdict routing is checked against a policy whose three action strings are
mutually distinguishable, so a cross-wired ``action`` cannot pass.
"""

from __future__ import annotations

import ast
import asyncio
import inspect
import json
import sys
import tempfile
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any, Final

import pytest
from pydantic import ValidationError

import classifier
import triage
import verify
from models import IncidentPayload, SuccessCriteria, VerificationPolicy
from verify import (
    ContainerObservation,
    ContainerTarget,
    IndeterminateVerdict,
    ObservationState,
    RequeueBudget,
    RequeueBudgetExhausted,
    UnresolvedCause,
    UnresolvedVerdict,
    VerificationStateError,
    VerifiedVerdict,
    VerdictKind,
    classify,
    verify_incident,
)

#: A valid ULID-bodied incident id (ARCH §4.1).
INCIDENT_ID: Final[str] = "inc_01HQ8S7G3M2K9X4B6D0F1R5TJA"
OTHER_INCIDENT_ID: Final[str] = "inc_01HQ8S7G3M2K9X4B6D0F1R5TJB"

#: Repository root, for the ARCH §5.2 fixture round-trip.
ROOT: Final[Path] = Path(__file__).resolve().parents[2]

#: ARCH §5.2 floors the window at 60s. Used verbatim so a test that passes
#: against a window the spec does not permit means nothing.
WATCH_SECONDS: Final[int] = 60
UPTIME_MIN: Final[int] = 30

TARGET: Final[ContainerTarget] = ContainerTarget(
    namespace="payments",
    pod_name="checkout-api-7d9f4b6c8d-x2k9p",
    container_name="checkout-api",
)


# ---------------------------------------------------------------------------
# Fixtures - synthetic, no cluster, no clock
# ---------------------------------------------------------------------------


def policy(**overrides: Any) -> VerificationPolicy:
    """A valid ARCH §5.2 policy. Every field overridable so tests can vary one."""
    fields: dict[str, Any] = {
        "mode": "POST_REMEDIATION_OBSERVATION",
        "watch_duration_seconds": WATCH_SECONDS,
        "success_criteria": SuccessCriteria(
            no_oomkilled_terminations=True,
            no_crashloopbackoff_wait=True,
            container_uptime_seconds_min=UPTIME_MIN,
        ),
        "max_requeue_attempts": 2,
    }
    fields.update(overrides)
    return VerificationPolicy(**fields)


class ScriptedReader:
    """An ``ObservationReader`` that replays a fixed sequence of states.

    Replays rather than returns a constant so a test can assert *when* the loop
    stopped, which is what distinguishes "observed and gave up" from "observed
    for the whole window".

    ``on_read`` fires inside the read, so a test can model a slow apiserver by
    advancing its fake clock at exactly the moment the loop is blocked. Advancing
    it from the sleep instead would measure the wrong thing: the deadline must
    bound the *reads*, not the pauses between them.
    """

    def __init__(self, states: list[ContainerObservation], on_read: Any = None) -> None:
        self._states = list(states)
        self._on_read = on_read
        self.calls: list[ContainerTarget] = []

    def read(self, target: ContainerTarget) -> ContainerObservation:
        self.calls.append(target)
        if self._on_read is not None:
            self._on_read()
        if len(self.calls) > len(self._states):
            return self._states[-1]
        return self._states[len(self.calls) - 1]


def healthy(uptime: int = UPTIME_MIN + 10) -> ContainerObservation:
    return ContainerObservation(
        visible=True,
        oomkilled_terminations=0,
        crashloopbackoff_wait=False,
        container_uptime_seconds=uptime,
    )


def young(uptime: int = 1) -> ContainerObservation:
    """Alive, no recurrence, uptime not yet at the minimum."""
    return ContainerObservation(
        visible=True,
        oomkilled_terminations=0,
        crashloopbackoff_wait=False,
        container_uptime_seconds=uptime,
    )


def oom() -> ContainerObservation:
    return ContainerObservation(
        visible=True,
        oomkilled_terminations=1,
        crashloopbackoff_wait=False,
        container_uptime_seconds=1,
    )


def crashlooping() -> ContainerObservation:
    return ContainerObservation(
        visible=True,
        oomkilled_terminations=0,
        crashloopbackoff_wait=True,
        container_uptime_seconds=2,
    )


def unseen() -> ContainerObservation:
    return ContainerObservation(
        visible=False,
        oomkilled_terminations=0,
        crashloopbackoff_wait=False,
        note="pod not found",
    )


class FakeClock:
    """A monotonic clock that advances only when a test says so.

    A clock that never advances is the interesting case: it is what a frozen or
    stepped system clock looks like to the loop, and it must not be able to keep
    the loop running.
    """

    def __init__(self, start: float = 0.0, step_on_read: float = 0.0) -> None:
        self.now = start
        self.step_on_read = step_on_read

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds

    def read_taken(self) -> None:
        self.advance(self.step_on_read)


class ManualSleep:
    """Records requested sleeps and advances the clock by the same amount."""

    def __init__(self, clock: FakeClock) -> None:
        self._clock = clock
        self.requested: list[float] = []

    async def __call__(self, seconds: float) -> None:
        self.requested.append(seconds)
        self._clock.advance(seconds)


def run(coro: Any) -> Any:
    """Run one coroutine on a fresh loop."""
    return asyncio.run(coro)


#: Attribute names on the ``time``/``datetime`` modules that can be stepped,
#: paused or re-based by an external process. AGENTS.md §3 rule 5 names one
#: permitted source, so the deny list is everything else.
WALL_CLOCK_FUNCTIONS: Final[frozenset[str]] = frozenset(
    {
        "asctime",
        "ctime",
        "fromtimestamp",
        "gmtime",
        "localtime",
        "monotonic",
        "monotonic_ns",
        "now",
        "perf_counter_ns",
        "strftime",
        "strptime",
        "thread_time",
        "thread_time_ns",
        "time",
        "time_ns",
        "today",
        "utcnow",
    }
)


def _time_attributes(source: str) -> set[str]:
    """Attribute names accessed on a ``time`` or ``datetime`` name in ``source``.

    AST-based rather than textual: ``time.time`` inside a comment or a docstring
    is not a clock read, and a wall clock reached through an alias is still one.
    """
    found: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if (
            isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name)
            and node.value.id in {"time", "datetime"}
        ):
            found.add(node.attr)
    return found


def _threadpool_dispatches(source: str) -> set[str]:
    """Attribute names whose value is handed to ``run_in_threadpool``."""
    found: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "run_in_threadpool"
            and node.args
            and isinstance(node.args[0], ast.Attribute)
        ):
            found.add(node.args[0].attr)
    return found


# ===========================================================================
# ROADMAP 4.3.2 - the three verdicts and their action routing
# ===========================================================================


class TestVerdictSchemas:
    def test_each_verdict_class_pins_its_own_discriminant(self) -> None:
        """A verdict class *is* its kind; it cannot be relabelled at construction."""
        base: dict[str, Any] = {
            "incident_id": INCIDENT_ID,
            "policy": policy(),
            "observation": healthy(),
            "observed_seconds": 1.0,
            "samples_observed": 1,
            "requeues_used": 0,
            "reason": "test",
        }
        for cls, kind, extra in (
            (VerifiedVerdict, VerdictKind.VERIFIED, {}),
            (
                UnresolvedVerdict,
                VerdictKind.UNRESOLVED,
                {"cause": UnresolvedCause.OOM_KILLED.value},
            ),
            (IndeterminateVerdict, VerdictKind.INDETERMINATE, {}),
        ):
            built = cls.model_validate({**base, **extra, "kind": kind.value})
            assert built.kind is kind
            # The negative control: a different discriminant is refused, so the
            # Literal pin is a real constraint and not a default nobody checks.
            with pytest.raises(ValidationError):
                other = next(k for k in VerdictKind if k is not kind)
                cls.model_validate({**base, **extra, "kind": other.value})

    def test_action_is_derived_from_the_policy_and_cannot_be_supplied(self) -> None:
        """No input exists by which a caller can attach an action to a verdict.

        The negative control is the middle assertion: passing ``action=`` fails
        validation, so the routing cannot be forged at the boundary.
        """
        built = VerifiedVerdict(
            kind=VerdictKind.VERIFIED,
            incident_id=INCIDENT_ID,
            policy=policy(),
            observation=healthy(),
            observed_seconds=1.0,
            samples_observed=1,
            requeues_used=0,
            reason="test",
        )
        assert built.action == "CLOSE_INCIDENT"
        with pytest.raises(ValidationError):
            VerifiedVerdict.model_validate(
                {
                    "kind": "VERIFIED",
                    "incident_id": INCIDENT_ID,
                    "policy": policy().model_dump(mode="json"),
                    "observation": healthy().model_dump(mode="json"),
                    "observed_seconds": 1.0,
                    "samples_observed": 1,
                    "requeues_used": 0,
                    "reason": "test",
                    "action": "PROMOTE_TO_TIER_2",
                }
            )

    def test_a_verified_verdict_cannot_exist_without_an_observation(self) -> None:
        """A closure with no evidence behind it is a fabrication, not a verdict."""
        with pytest.raises(ValidationError):
            VerifiedVerdict(
                kind=VerdictKind.VERIFIED,
                incident_id=INCIDENT_ID,
                policy=policy(),
                observation=None,
                observed_seconds=0.0,
                samples_observed=0,
                requeues_used=0,
                reason="verified with nothing observed",
            )

    def test_verdicts_are_frozen(self) -> None:
        """A decision record cannot be edited into claiming a different action."""
        built = VerifiedVerdict(
            kind=VerdictKind.VERIFIED,
            incident_id=INCIDENT_ID,
            policy=policy(),
            observation=healthy(),
            observed_seconds=1.0,
            samples_observed=1,
            requeues_used=0,
            reason="test",
        )
        with pytest.raises(ValidationError):
            built.reason = "edited"
        with pytest.raises(ValidationError):
            built.incident_id = OTHER_INCIDENT_ID

    def test_an_unseen_container_cannot_also_report_an_uptime(self) -> None:
        """``None`` means unreadable. ``0`` means restarted. Collapsing them
        would turn a failed read into a recurrence verdict, and a recurrence
        verdict escalates."""
        with pytest.raises(ValidationError):
            ContainerObservation(
                visible=False,
                oomkilled_terminations=0,
                crashloopbackoff_wait=False,
                container_uptime_seconds=0,
            )


class TestVerdictRouting:
    """Each verdict must route to *its own* policy action.

    The policy is built with three mutually distinguishable action strings, so a
    cross-wired ``action`` - the exact bug where an ``Unresolved`` verdict closes
    the incident - cannot pass.
    """

    DISTINGUISHABLE: Final[dict[str, str]] = {
        "on_success": "ACTION_FOR_VERIFIED",
        "on_repeat_failure": "ACTION_FOR_UNRESOLVED",
        "on_indeterminate": "ACTION_FOR_INDETERMINATE",
    }

    def _policy(self) -> VerificationPolicy:
        return policy(**self.DISTINGUISHABLE)

    def _run(
        self, reader: ScriptedReader
    ) -> tuple[VerifiedVerdict | UnresolvedVerdict | IndeterminateVerdict, Any]:
        active = self._policy()
        budget = RequeueBudget(active, INCIDENT_ID)
        verdict = run(
            verify_incident(
                active,
                TARGET,
                reader,
                incident_id=INCIDENT_ID,
                budget=budget,
                sleep=_no_sleep,
            )
        )
        return verdict, active

    def test_healthy_workload_verifies_and_closes(self) -> None:
        verdict, _ = self._run(ScriptedReader([healthy()]))
        assert isinstance(verdict, VerifiedVerdict)
        assert verdict.action == "ACTION_FOR_VERIFIED"
        assert verdict.samples_observed == 1

    def test_reinjected_oom_is_unresolved_and_promotes(self) -> None:
        verdict, _ = self._run(ScriptedReader([oom()]))
        assert isinstance(verdict, UnresolvedVerdict)
        assert verdict.action == "ACTION_FOR_UNRESOLVED"
        assert verdict.cause is UnresolvedCause.OOM_KILLED

    def test_reinjected_crashloop_is_unresolved_and_promotes(self) -> None:
        verdict, _ = self._run(ScriptedReader([crashlooping()]))
        assert isinstance(verdict, UnresolvedVerdict)
        assert verdict.action == "ACTION_FOR_UNRESOLVED"
        assert verdict.cause is UnresolvedCause.CRASH_LOOP_BACKOFF

    def test_an_unobservable_read_is_indeterminate_and_requeues(self) -> None:
        verdict, _ = self._run(ScriptedReader([unseen()]))
        assert isinstance(verdict, IndeterminateVerdict)
        assert verdict.action == "ACTION_FOR_INDETERMINATE"
        assert "pod not found" in verdict.reason

    def test_only_indeterminate_ever_carries_a_requeue(self) -> None:
        """A requeue is not a retry of a *failure*; it is a retry of an
        *absence of evidence*. Verified and Unresolved are both terminal."""
        verified, _ = self._run(ScriptedReader([healthy()]))
        unresolved, _ = self._run(ScriptedReader([oom()]))
        assert verified.requeues_used == 0
        assert unresolved.requeues_used == 0
        assert verified.action != unresolved.action


# ===========================================================================
# classify() - the pure decision function
# ===========================================================================


class TestClassification:
    def test_healthy_when_uptime_meets_the_minimum(self) -> None:
        assert (
            classify(healthy(uptime=UPTIME_MIN), policy()) is ObservationState.HEALTHY
        )

    def test_one_second_short_of_the_minimum_is_not_healthy(self) -> None:
        """The boundary. A criterion that is ``>=`` in the spec must not be
        ``>`` in the code, which would close an incident one second early."""
        assert (
            classify(healthy(uptime=UPTIME_MIN - 1), policy())
            is ObservationState.UNSTABLE
        )

    def test_a_recurrence_beats_an_uptime_check(self) -> None:
        """A container OOMKilled one second ago has uptime 1.

        Testing uptime first would report UNSTABLE and keep polling a container
        that is already failing, delaying an escalation that is clearly
        warranted. The negative control is the second assertion: the same
        observation *without* the recurrence is UNSTABLE, so the difference is
        caused by the recurrence and not by the uptime.
        """
        assert classify(oom(), policy()) is ObservationState.FAULT_RECURRENCE
        assert classify(young(uptime=1), policy()) is ObservationState.UNSTABLE

    def test_an_unobservable_read_is_not_evidence_about_the_workload(self) -> None:
        assert classify(unseen(), policy()) is ObservationState.UNOBSERVABLE
        # Even when the rest of the record looks perfect, invisibility wins:
        # there is nothing to have an opinion about.
        assert (
            classify(
                unseen().model_copy(update={"oomkilled_terminations": 0}),
                policy(),
            )
            is ObservationState.UNOBSERVABLE
        )

    def test_a_visible_container_with_unreadable_uptime_is_indeterminate(self) -> None:
        """Distinct from ``uptime=0``: the field could not be read."""
        partial = ContainerObservation(
            visible=True,
            oomkilled_terminations=0,
            crashloopbackoff_wait=False,
            container_uptime_seconds=None,
            note="status subresource unavailable",
        )
        assert classify(partial, policy()) is ObservationState.UNOBSERVABLE

    def test_classification_is_a_total_function(self) -> None:
        """Every combination maps to a state; none raises. A classifier that can
        throw is a classifier whose failure mode is a 500, not a verdict."""
        for visible in (True, False):
            for oomkilled in (0, 1):
                for backoff in (False, True):
                    for uptime in (None, 0, 1, UPTIME_MIN, UPTIME_MIN + 60):
                        if not visible and uptime is not None:
                            continue
                        observation = ContainerObservation(
                            visible=visible,
                            oomkilled_terminations=oomkilled,
                            crashloopbackoff_wait=backoff,
                            container_uptime_seconds=uptime,
                        )
                        assert isinstance(
                            classify(observation, policy()), ObservationState
                        )


# ===========================================================================
# ARCH §5.2 conformance - the policy the agent emits is the policy honoured here
# ===========================================================================


class TestArchConformance:
    """The wire example in ARCH §5.2, and the policy ``triage`` actually produces.

    ``agent/models.py`` owns the schema and ``agent/triage.py`` fills it in; this
    module only consumes it. Drift between what is emitted and what is honoured
    would fail no local test, so the boundary is asserted here.
    """

    #: ARCH §5.2: the ``verification_policy`` object from the Contract B example.
    ARCH_EXAMPLE: Final[dict[str, Any]] = {
        "mode": "POST_REMEDIATION_OBSERVATION",
        "watch_duration_seconds": 300,
        "success_criteria": {
            "no_oomkilled_terminations": True,
            "no_crashloopbackoff_wait": True,
            "container_uptime_seconds_min": 240,
        },
        "on_success": "CLOSE_INCIDENT",
        "on_repeat_failure": "PROMOTE_TO_TIER_2",
        "on_indeterminate": "REQUEUE_BOUNDED",
        "max_requeue_attempts": 3,
    }

    def test_the_arch_example_validates_and_names_the_three_actions(self) -> None:
        active = VerificationPolicy.model_validate(self.ARCH_EXAMPLE)
        assert active.watch_duration_seconds == 300
        assert active.max_requeue_attempts == 3
        assert active.on_success == "CLOSE_INCIDENT"
        assert active.on_repeat_failure == "PROMOTE_TO_TIER_2"
        assert active.on_indeterminate == "REQUEUE_BOUNDED"

    def test_each_verdict_routes_to_the_architect_actions(self) -> None:
        active = VerificationPolicy.model_validate(self.ARCH_EXAMPLE)
        expected: list[tuple[type[Any], ScriptedReader, str]] = [
            (VerifiedVerdict, ScriptedReader([healthy(uptime=240)]), "CLOSE_INCIDENT"),
            (UnresolvedVerdict, ScriptedReader([oom()]), "PROMOTE_TO_TIER_2"),
            (
                IndeterminateVerdict,
                ScriptedReader([unseen()]),
                "REQUEUE_BOUNDED",
            ),
        ]
        for cls, reader, action in expected:
            verdict = run(
                verify_incident(
                    active,
                    TARGET,
                    reader,
                    incident_id=INCIDENT_ID,
                    budget=RequeueBudget(active, INCIDENT_ID),
                    sleep=_no_sleep,
                )
            )
            assert isinstance(verdict, cls)
            assert (
                verdict.action == action
            ), f"{cls.__name__} routed to {verdict.action}, not {action}"

    def test_the_policy_triage_emits_is_accepted_here(self) -> None:
        """End of the chain: a real Tier-1 Contract B response, consumed.

        Uses the production triage path with a GitOps manifest, so the policy
        under test is the one a Tier-1 incident actually carries - not a
        hand-built copy that could agree with this module while disagreeing with
        the producer.
        """
        document = json.loads(
            (ROOT / "tests" / "fixtures" / "sample-incident.json").read_text(
                encoding="utf-8"
            )
        )
        document.pop("_comment", None)
        manifest = (ROOT / "tests" / "fixtures" / "oom-restartloop.yaml").read_text(
            encoding="utf-8"
        )
        outcome = triage.triage_payload(
            IncidentPayload.model_validate(document),
            manifest_provider=classifier.StaticManifestProvider(
                {triage.TARGET_MANIFEST: manifest}
            ),
        )
        emitted = outcome.response.verification_policy
        incident_id = outcome.response.incident_id

        verdict = run(
            verify_incident(
                emitted,
                TARGET,
                ScriptedReader([healthy(uptime=241)]),
                incident_id=incident_id,
                budget=RequeueBudget(emitted, incident_id),
                sleep=_no_sleep,
            )
        )
        assert isinstance(verdict, VerifiedVerdict)
        assert verdict.action == emitted.on_success == "CLOSE_INCIDENT"
        assert verdict.incident_id == incident_id
        assert verdict.policy == emitted, (
            "the verdict must carry the policy it was decided against, not a "
            "reconstruction of it"
        )


# ===========================================================================
# ROADMAP 4.3.1 - the window is bounded
# ===========================================================================


async def _no_sleep(_seconds: float) -> None:
    """A sleep that suspends but does not wait, so tests need no wall time."""


class TestBoundedWindow:
    def test_a_window_never_exceeds_watch_duration_seconds(self) -> None:
        """The deadline stops sampling even when reads are slow.

        A fake clock that advances 30s *per read* means the deadline is crossed
        after two reads, long before the 12-sample iteration cap. Asserting only
        the cap would pass against a loop that ignored its own window entirely.
        """
        active = policy(watch_duration_seconds=WATCH_SECONDS)
        clock = FakeClock(step_on_read=30.0)
        sleeper = ManualSleep(clock)
        reader = ScriptedReader([young()] * 200, on_read=clock.read_taken)
        budget = RequeueBudget(active, INCIDENT_ID)

        verdict = run(
            verify_incident(
                active,
                TARGET,
                reader,
                incident_id=INCIDENT_ID,
                budget=budget,
                clock=clock,
                sleep=sleeper,
            )
        )

        iteration_cap = -(-WATCH_SECONDS // int(verify.POLL_INTERVAL_SECONDS))
        assert isinstance(verdict, UnresolvedVerdict)
        assert verdict.cause is UnresolvedCause.UPTIME_BELOW_MINIMUM
        assert verdict.samples_observed == 2 < iteration_cap, (
            "the deadline must stop the window; the iteration cap alone would "
            f"have allowed {iteration_cap} reads"
        )
        assert len(reader.calls) == 2

    def test_a_frozen_clock_cannot_extend_the_window(self) -> None:
        """The iteration cap is the unconditional bound.

        A clock that returns a constant never reaches the deadline, so only the
        iteration count can end this loop. If the cap were removed, this test
        would not fail slowly - it would hang.
        """
        active = policy(watch_duration_seconds=WATCH_SECONDS)
        frozen = FakeClock()
        budget = RequeueBudget(active, INCIDENT_ID)
        reader = ScriptedReader([young()] * 10_000)

        verdict = run(
            verify_incident(
                active,
                TARGET,
                reader,
                incident_id=INCIDENT_ID,
                budget=budget,
                clock=frozen,
                sleep=_no_sleep,
            )
        )

        expected = -(-WATCH_SECONDS // int(verify.POLL_INTERVAL_SECONDS))
        assert isinstance(verdict, UnresolvedVerdict)
        assert verdict.samples_observed == expected == 12
        assert len(reader.calls) == expected
        assert frozen.now == 0.0, "the clock never advanced, so the cap did the work"

    def test_the_loop_polls_at_the_configured_interval(self) -> None:
        active = policy()
        clock = FakeClock()
        sleeper = ManualSleep(clock)
        budget = RequeueBudget(active, INCIDENT_ID)
        run(
            verify_incident(
                active,
                TARGET,
                ScriptedReader([young()] * 100),
                incident_id=INCIDENT_ID,
                budget=budget,
                clock=clock,
                sleep=sleeper,
            )
        )
        assert sleeper.requested
        assert set(sleeper.requested) == {verify.POLL_INTERVAL_SECONDS}

    def test_timing_uses_a_monotonic_clock_and_never_a_wall_clock(self) -> None:
        """AGENTS.md §3 rule 5.

        A steppable clock yields a negative ``observed_seconds`` if NTP moves it
        backwards during a window, and a window that *lengthens* if it moves
        forwards. Checked on the AST rather than on the text, so a clock named
        inside a comment cannot satisfy it and a real call cannot hide behind a
        longer expression.
        """
        source = inspect.getsource(verify)
        assert "perf_counter" in _time_attributes(source)
        assert not _time_attributes(source) & WALL_CLOCK_FUNCTIONS

        # Negative control: the same analyser applied to a source that does use a
        # wall clock, so the empty intersection above is known to be informative.
        planted = "def elapsed() -> float:\n    return time.time() - t0\n"
        assert _time_attributes(planted) & WALL_CLOCK_FUNCTIONS == {"time"}

    def test_observed_seconds_is_never_negative(self) -> None:
        """The negative control for the monotonic claim: a wall clock stepped
        backwards during a window would produce a negative delta, and this
        assertion is what would catch it."""
        active = policy()
        clock = FakeClock(start=1000.0)
        budget = RequeueBudget(active, INCIDENT_ID)
        verdict = run(
            verify_incident(
                active,
                TARGET,
                ScriptedReader([healthy()]),
                incident_id=INCIDENT_ID,
                budget=budget,
                clock=clock,
                sleep=_no_sleep,
            )
        )
        assert verdict.observed_seconds >= 0.0

    def test_a_zero_poll_interval_is_refused(self) -> None:
        """Otherwise ``ceil(watch / 0)`` is a ZeroDivisionError, i.e. a 500."""
        active = policy()
        budget = RequeueBudget(active, INCIDENT_ID)
        with pytest.raises(ValueError):
            run(
                verify_incident(
                    active,
                    TARGET,
                    ScriptedReader([healthy()]),
                    incident_id=INCIDENT_ID,
                    budget=budget,
                    poll_interval_seconds=0.0,
                    sleep=_no_sleep,
                )
            )

    def test_the_module_contains_no_while_loop(self) -> None:
        """Structural: there is no ``while True`` to be unbounded.

        The negative control is ``_while_statements`` applied to a source that
        *does* contain one, so the empty result is known to be informative.
        """
        assert _while_statements(inspect.getsource(verify)) == set()
        planted = "def f():\n    while True:\n        pass\n"
        assert _while_statements(planted) == {"line 2: True"}


# ===========================================================================
# ROADMAP 4.3.3 - max_requeue_attempts is a mathematical bound
# ===========================================================================


class TestRequeueBudgetArithmetic:
    def test_the_allowance_is_the_policy_value_plus_one_window(self) -> None:
        budget = RequeueBudget(policy(max_requeue_attempts=3), INCIDENT_ID)
        assert budget.limit == 3
        assert budget.max_windows == 4
        assert budget.windows_spent == 0
        assert budget.requeues_used == 0
        assert not budget.exhausted

    def test_spending_returns_the_new_requeue_count(self) -> None:
        budget = RequeueBudget(policy(max_requeue_attempts=2), INCIDENT_ID)
        assert budget.spend() == 0, "the first window is the original observation"
        assert budget.spend() == 1
        assert budget.spend() == 2
        assert budget.exhausted

    def test_spending_past_the_bound_raises(self) -> None:
        """The refusal is the bound. Without it the counter would go negative
        and the condition would never trip."""
        budget = RequeueBudget(policy(max_requeue_attempts=1), INCIDENT_ID)
        budget.spend()
        budget.spend()
        assert budget.exhausted
        with pytest.raises(RequeueBudgetExhausted):
            budget.spend()

    def test_the_budget_cannot_be_rewound(self) -> None:
        """A resettable counter is not a counter.

        The negative control is the first assertion: reading ``_windows`` is
        fine, assigning to it is not. A budget that could be rewound would make
        every other test in this class decorative.
        """
        budget = RequeueBudget(policy(), INCIDENT_ID)
        budget.spend()
        assert budget._windows == 1
        for attribute in ("_windows", "_limit", "windows_spent", "used"):
            with pytest.raises(AttributeError):
                setattr(budget, attribute, 0)
        assert budget.windows_spent == 1

    def test_a_zero_allowance_is_refused(self) -> None:
        """ARCH §5.2 requires ``>= 1``. models.py enforces it on the policy; the
        budget enforces it on the value, so a hand-built policy object cannot
        buy an incident an unlimited chain."""
        assert RequeueBudget(policy(max_requeue_attempts=1), INCIDENT_ID).limit == 1
        assert policy(max_requeue_attempts=1) is not None
        with pytest.raises(ValidationError):
            policy(max_requeue_attempts=0)
        with pytest.raises(ValidationError):
            policy(max_requeue_attempts=11)


class TestRequeueChainTerminates:
    """The bound has to hold *across* requeues, not inside one call.

    Every call here is threaded with the previous verdict and the same budget,
    which is how a caller requeues. The chain runs until it refuses, and the
    assertion is on the total work done - not on the number of calls.
    """

    def _chain(self, max_requeue_attempts: int) -> tuple[list[Any], ScriptedReader]:
        active = policy(max_requeue_attempts=max_requeue_attempts)
        budget = RequeueBudget(active, INCIDENT_ID)
        reader = ScriptedReader([unseen()] * 100)
        verdicts: list[Any] = []
        prior: Any = None
        for _ in range(50):  # far more calls than any legal chain permits
            verdict = run(
                verify_incident(
                    active,
                    TARGET,
                    reader,
                    incident_id=INCIDENT_ID,
                    budget=budget,
                    prior=prior,
                    sleep=_no_sleep,
                )
            )
            verdicts.append(verdict)
            if isinstance(verdict, IndeterminateVerdict):
                prior = verdict
                continue
            break
        return verdicts, reader

    @pytest.mark.parametrize("allowance", [1, 2, 3, 10])
    def test_total_observation_windows_never_exceed_the_allowance_plus_one(
        self, allowance: int
    ) -> None:
        verdicts, reader = self._chain(allowance)
        observing = [v for v in verdicts if v.samples_observed > 0]
        assert len(observing) == allowance + 1
        assert len(reader.calls) == allowance + 1, (
            "the cluster read budget is the real measure; a chain that kept "
            "calling read() while reporting no progress is still unbounded"
        )

    @pytest.mark.parametrize("allowance", [1, 2, 3])
    def test_the_chain_ends_in_a_terminal_escalation(self, allowance: int) -> None:
        verdicts, _ = self._chain(allowance)
        final = verdicts[-1]
        assert isinstance(final, UnresolvedVerdict)
        assert final.cause is UnresolvedCause.REQUEUE_BUDGET_EXHAUSTED
        assert (
            final.samples_observed == 0
        ), "an exhausted budget must short-circuit before issuing a read"
        assert final.action == policy().on_repeat_failure

    def test_requeue_accounting_is_monotonic_across_the_chain(self) -> None:
        """Each observing window consumes exactly one requeue; the terminal
        escalation consumes none, so the count repeats rather than advancing.

        The repeat is the evidence that the exhausted path short-circuits before
        spending anything.
        """
        verdicts, _ = self._chain(3)
        counts = [v.requeues_used for v in verdicts]
        assert counts[:-1] == list(range(len(counts) - 1))
        assert counts[-1] == counts[-2] == 3

    def test_a_terminal_verdict_cannot_be_requeued(self) -> None:
        """Once a chain is closed, re-running it is a state error, not a retry."""
        active = policy()
        budget = RequeueBudget(active, INCIDENT_ID)
        terminal = run(
            verify_incident(
                active,
                TARGET,
                ScriptedReader([healthy()]),
                incident_id=INCIDENT_ID,
                budget=budget,
                sleep=_no_sleep,
            )
        )
        with pytest.raises(VerificationStateError):
            run(
                verify_incident(
                    active,
                    TARGET,
                    ScriptedReader([healthy()]),
                    incident_id=INCIDENT_ID,
                    budget=budget,
                    prior=terminal,
                    sleep=_no_sleep,
                )
            )

    def test_a_fresh_budget_cannot_impersonate_a_spent_one(self) -> None:
        """The anti-reset guard, with its negative control.

        Two legitimate requeues are performed against one budget, so the second
        verdict records one consumed requeue. The caller then throws that budget
        away and mints a fresh one claiming zero while still holding the verdict
        - which is precisely "reset the counter and go round again". It is
        refused.

        The first two calls are the negative control: the *same* budget threaded
        through the *same* prior-verdict chain is accepted, so the refusal that
        follows is caused by the forged budget and not by requeueing at all.
        """
        active = policy(max_requeue_attempts=3)
        budget = RequeueBudget(active, INCIDENT_ID)

        first = run(
            verify_incident(
                active,
                TARGET,
                ScriptedReader([unseen()]),
                incident_id=INCIDENT_ID,
                budget=budget,
                sleep=_no_sleep,
            )
        )
        assert isinstance(first, IndeterminateVerdict)
        assert first.requeues_used == 0

        second = run(
            verify_incident(
                active,
                TARGET,
                ScriptedReader([unseen()]),
                incident_id=INCIDENT_ID,
                budget=budget,
                prior=first,
                sleep=_no_sleep,
            )
        )
        assert isinstance(second, IndeterminateVerdict)
        assert second.requeues_used == 1, "the chain threaded one budget cleanly"

        forged = RequeueBudget(active, INCIDENT_ID)
        assert forged.requeues_used == 0, "the forgery starts from zero"
        with pytest.raises(VerificationStateError) as caught:
            run(
                verify_incident(
                    active,
                    TARGET,
                    ScriptedReader([unseen()]),
                    incident_id=INCIDENT_ID,
                    budget=forged,
                    prior=second,
                    sleep=_no_sleep,
                )
            )
        assert "may not be restarted" in str(caught.value)
        assert forged.windows_spent == 0, "a refused call must not spend a window"

    def test_a_budget_belonging_to_another_incident_is_refused(self) -> None:
        """Otherwise one incident's requeues would pay for another's windows."""
        active = policy()
        budget = RequeueBudget(active, OTHER_INCIDENT_ID)
        with pytest.raises(VerificationStateError):
            run(
                verify_incident(
                    active,
                    TARGET,
                    ScriptedReader([healthy()]),
                    incident_id=INCIDENT_ID,
                    budget=budget,
                    sleep=_no_sleep,
                )
            )

    def test_a_prior_verdict_from_another_incident_is_refused(self) -> None:
        active = policy()
        budget = RequeueBudget(active, INCIDENT_ID)
        prior = IndeterminateVerdict(
            kind=VerdictKind.INDETERMINATE,
            incident_id=OTHER_INCIDENT_ID,
            policy=active,
            observation=unseen(),
            observed_seconds=0.0,
            samples_observed=1,
            requeues_used=0,
            reason="belongs elsewhere",
        )
        with pytest.raises(VerificationStateError):
            run(
                verify_incident(
                    active,
                    TARGET,
                    ScriptedReader([unseen()]),
                    incident_id=INCIDENT_ID,
                    budget=budget,
                    prior=prior,
                    sleep=_no_sleep,
                )
            )


# ===========================================================================
# ROADMAP 4.3.5 - strict observation, zero writes (TRUST BOUNDARY)
# ===========================================================================


#: Verbs that would express a cluster write. Mirrors the CI guard on
#: ``agent/models.py`` and extends it to the module's *call graph*, not just its
#: field names.
MUTATING_VERBS: Final[frozenset[str]] = frozenset(
    {
        "apply",
        "apply_patch",
        "create",
        "cordon",
        "delete",
        "delete_resource",
        "drain",
        "exec",
        "exec_command",
        "kubectl",
        "kubectl_command",
        "mutate",
        "patch",
        "patch_resource",
        "replace",
        "rollout",
        "restart_rollout",
        "rm",
        "run_command",
        "scale",
        "set",
        "update",
        "upsert",
    }
)

#: Modules that could reach a cluster, a shell, or a socket. ``agent`` holds no
#: cluster credential (ARCH §2), so importing any of these would be a defect
#: regardless of whether the imported symbol is called.
FORBIDDEN_IMPORTS: Final[frozenset[str]] = frozenset(
    {
        "asyncio.subprocess",
        "httpx",
        "kubernetes",
        "kubernetes_asyncio",
        "os",
        "requests",
        "shutil",
        "socket",
        "subprocess",
        "urllib",
        "urllib3",
    }
)


def _module_root(name: str) -> str:
    return name.split(".")[0]


def _forbidden_imports(source: str) -> set[str]:
    """Root module names imported by ``source`` that could reach a cluster."""
    found: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = _module_root(alias.name)
                if root in FORBIDDEN_IMPORTS or alias.name in FORBIDDEN_IMPORTS:
                    found.add(alias.name)
        elif isinstance(node, ast.ImportFrom) and node.module:
            root = _module_root(node.module)
            if root in FORBIDDEN_IMPORTS or node.module in FORBIDDEN_IMPORTS:
                found.add(node.module)
    return found


def _called_names(source: str) -> set[str]:
    """Every name that appears as a call target or as an attribute access.

    Attribute access is included because ``os.system("kubectl apply ...")``
    reaches a write without the identifier ``apply`` ever being *called*.
    """
    names: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name):
                names.add(func.id)
            elif isinstance(func, ast.Attribute):
                names.add(func.attr)
        elif isinstance(node, ast.Attribute):
            names.add(node.attr)
    return names


def _while_statements(source: str) -> set[str]:
    """Every ``while`` in ``source``, as ``line N: <condition>``."""
    found: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.While):
            condition = "True" if node.test is None else ast.unparse(node.test)
            found.add(f"line {node.lineno}: {condition}")
    return found


class TestZeroWrites:
    def test_the_module_imports_nothing_that_could_reach_a_cluster(self) -> None:
        source = inspect.getsource(verify)
        assert _forbidden_imports(source) == set(), (
            "the verification loop holds no cluster credential and must not "
            "acquire a way to use one"
        )

    def test_the_module_never_names_a_mutating_verb(self) -> None:
        source = inspect.getsource(verify)
        offending = _called_names(source) & MUTATING_VERBS
        assert offending == set()

    def test_those_two_checks_can_actually_fail(self) -> None:
        """The negative control for the two checks above.

        A planted mutating import and a planted mutating call are fed to the same
        analysers. If the analysers cannot see them, the assertions above are
        passing on an empty result rather than on a clean module.
        """
        planted = (
            "import subprocess\n"
            "\n"
            "def rollback(manifest):\n"
            "    subprocess.run(['kubectl', 'apply', '-f', manifest])\n"
            "    client.patch(namespace='payments')\n"
        )
        assert _forbidden_imports(planted) == {"subprocess"}
        assert {"run", "patch"} & MUTATING_VERBS, "the deny list lost its entries"
        assert _called_names(planted) & MUTATING_VERBS

    def test_a_clean_module_analyses_clean(self) -> None:
        """Positive control: the analysers are not simply returning nothing for
        every input. Without this, a broken parser would make the two tests
        above pass unconditionally."""
        clean = (
            "import time\n\n\ndef elapsed() -> float:\n    return time.perf_counter()\n"
        )
        assert _forbidden_imports(clean) == set()
        assert _called_names(clean) & MUTATING_VERBS == set()
        assert "perf_counter" in _called_names(clean)

    def test_the_only_capability_the_module_exposes_is_a_read(self) -> None:
        """The reader protocol is the whole interface. A method named like a
        write verb would be the first crack in the trust boundary."""
        methods = {
            node.name
            for cls in ast.walk(ast.parse(inspect.getsource(verify)))
            if isinstance(cls, ast.ClassDef)
            for node in cls.body
            if isinstance(node, ast.FunctionDef)
        }
        assert "read" in methods
        assert not methods & MUTATING_VERBS


# ---------------------------------------------------------------------------
# Runtime tripwire: a CPython audit hook armed around a real run
# ---------------------------------------------------------------------------

#: Audit events that would mean the loop reached outside the process for a
#: purpose other than reading the workload.
MUTATING_AUDIT_EVENTS: Final[frozenset[str]] = frozenset(
    {
        "os.chmod",
        "os.chown",
        "os.link",
        "os.mkdir",
        "os.remove",
        "os.rename",
        "os.rmdir",
        "os.symlink",
        "os.truncate",
        "os.unlink",
        "os.utime",
        "subprocess.Popen",
        "os.system",
        "os.exec",
        "os.posix_spawn",
        "os.spawn",
        "socket.connect",
        "socket.bind",
        "urllib.Request",
        "http.client.connect",
    }
)

_RECORDED: list[tuple[str, tuple[Any, ...]]] = []
_ARMED: list[bool] = [False]
_HOOK_INSTALLED: list[bool] = [False]


def _audit_hook(event: str, args: tuple[Any, ...]) -> None:
    if _ARMED[0]:
        _RECORDED.append((event, args))


def _arm() -> None:
    if not _HOOK_INSTALLED[0]:
        sys.addaudithook(_audit_hook)
        _HOOK_INSTALLED[0] = True
    _RECORDED.clear()
    _ARMED[0] = True


def _disarm() -> list[tuple[str, tuple[Any, ...]]]:
    _ARMED[0] = False
    recorded = list(_RECORDED)
    _RECORDED.clear()
    return recorded


@pytest.fixture(scope="module")
def warmed_loop() -> Iterator[asyncio.AbstractEventLoop]:
    """An event loop with the threadpool machinery already initialised.

    The audit hook is process-wide and cannot be uninstalled, and asyncio
    creates its self-pipe socket the first time a loop runs. Warming the loop
    first means the tripwire cannot fire on unrelated interpreter start-up, so a
    failure is a real failure of this module rather than noise.
    """
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    active = policy()
    loop.run_until_complete(
        verify_incident(
            active,
            TARGET,
            ScriptedReader([healthy()]),
            incident_id=INCIDENT_ID,
            budget=RequeueBudget(active, INCIDENT_ID),
            sleep=_no_sleep,
        )
    )
    yield loop
    loop.close()
    asyncio.set_event_loop(None)


class TestRuntimeTripwire:
    def test_a_real_run_issues_no_write_and_no_outbound_connection(
        self, warmed_loop: asyncio.AbstractEventLoop
    ) -> None:
        """ROADMAP 4.3.5, observed rather than asserted.

        The full path runs: the loop samples, classifies and returns a verdict,
        with a CPython audit hook recording every filesystem, subprocess and
        socket event. Anything the loop did that reached outside the process
        would appear here.
        """
        active = policy()
        reader = ScriptedReader([young()] * 5)
        budget = RequeueBudget(active, INCIDENT_ID)

        _arm()
        try:
            verdict = warmed_loop.run_until_complete(
                verify_incident(
                    active,
                    TARGET,
                    reader,
                    incident_id=INCIDENT_ID,
                    budget=budget,
                    sleep=_no_sleep,
                )
            )
        finally:
            recorded = _disarm()

        assert isinstance(verdict, UnresolvedVerdict)
        assert (
            verdict.samples_observed > 0
        ), "the tripwire proved nothing on an idle loop"
        offending = [
            (event, args)
            for event, args in recorded
            if event in MUTATING_AUDIT_EVENTS or event == "open"
        ]
        assert (
            offending == []
        ), f"the verification loop reached outside itself: {offending}"

    def test_the_tripwire_itself_can_fire(self) -> None:
        """The negative control.

        A tripwire that never fires proves nothing. Here it is armed and a real
        write *and* a real delete are performed inside the armed region, so the
        check above is known to be capable of failing.
        """
        probe = Path(tempfile.gettempdir()) / "srek3s-verify-tripwire-probe"
        _arm()
        try:
            probe.write_text("x", encoding="utf-8")
            probe.unlink()
            recorded = _disarm()
        finally:
            _ARMED[0] = False
            _RECORDED.clear()
            probe.unlink(missing_ok=True)

        events = {event for event, _ in recorded}
        assert "open" in events, "the file write inside the armed region was not seen"
        assert (
            "os.remove" in events
        ), "the file delete inside the armed region was not seen"
        offending = [
            item
            for item in recorded
            if item[0] in MUTATING_AUDIT_EVENTS or item[0] == "open"
        ]
        assert offending, "the tripwire recorded nothing while a write was in progress"

    def test_the_verdict_carries_no_mutating_verb_in_its_serialised_form(
        self, warmed_loop: asyncio.AbstractEventLoop
    ) -> None:
        """The wire form is where a write would escape to a downstream consumer,
        so the field names themselves are checked, not just the code."""
        active = policy()
        budget = RequeueBudget(active, INCIDENT_ID)
        verdict = warmed_loop.run_until_complete(
            verify_incident(
                active,
                TARGET,
                ScriptedReader([healthy()]),
                incident_id=INCIDENT_ID,
                budget=budget,
                sleep=_no_sleep,
            )
        )
        document = verdict.model_dump(mode="json")
        keys = set(document) | set(document["policy"])
        assert not keys & MUTATING_VERBS
        # The negative control: the field scan must be capable of matching a
        # field that *is* named like a write verb.
        assert {"command", "patch"} & MUTATING_VERBS


# ===========================================================================
# Async boundary - a blocking read must not stall the event loop (AGENTS §3.1)
# ===========================================================================


class BlockingReader:
    """An ``ObservationReader`` whose read blocks for a measurable interval."""

    BLOCK_SECONDS: Final[float] = 0.08

    def __init__(self) -> None:
        self.calls = 0

    def read(self, target: ContainerTarget) -> ContainerObservation:
        self.calls += 1
        time.sleep(self.BLOCK_SECONDS)
        return healthy()


async def _heartbeat(stop: asyncio.Event, ticks: list[int]) -> None:
    while not stop.is_set():
        ticks[0] += 1
        await asyncio.sleep(0.002)


class TestAsyncBoundary:
    @staticmethod
    async def _ticks_during(blocking: Any) -> int:
        """Count heartbeat ticks that land *while* ``blocking`` runs.

        Counting only the delta is what makes the negative control meaningful: a
        heartbeat that ticked once before the read started would otherwise be
        indistinguishable from one that ticked throughout it.
        """
        stop = asyncio.Event()
        ticks = [0]
        beat = asyncio.create_task(_heartbeat(stop, ticks))
        await asyncio.sleep(0.02)  # let the heartbeat reach steady state
        before = ticks[0]
        await blocking()
        during = ticks[0] - before
        stop.set()
        await beat
        return during

    def test_the_blocking_read_does_not_stall_the_event_loop(self) -> None:
        """A 1800-second window executed inline would drop ``/healthz`` and
        ``/readyz``, and a stalled probe is what gets a healthy pod restarted.

        The heartbeat ticks every 2ms while an 80ms blocking read runs. If the
        read ran on the loop, the delta would be zero.
        """
        active = policy()
        reader = BlockingReader()

        async def scenario() -> int:
            return await self._ticks_during(
                lambda: verify_incident(
                    active,
                    TARGET,
                    reader,
                    incident_id=INCIDENT_ID,
                    budget=RequeueBudget(active, INCIDENT_ID),
                    sleep=_no_sleep,
                )
            )

        during = run(scenario())
        assert reader.calls == 1
        assert during > 0, (
            "the event loop got no scheduling slot during the blocking read, so "
            "the read ran inline"
        )

    def test_that_measurement_detects_a_stalled_loop(self) -> None:
        """The negative control for the measurement above.

        The identical harness, with the read called inline instead of through the
        threadpool, must produce zero ticks. If it did not, the assertion in the
        test above would be measuring noise rather than stalling.
        """
        reader = BlockingReader()

        async def stalling_read() -> None:
            reader.read(TARGET)

        assert run(self._ticks_during(stalling_read)) == 0

    def test_the_read_is_dispatched_through_the_threadpool(self) -> None:
        """Structural, complementing the behavioural measurement: the module must
        route its only I/O through ``starlette.concurrency.run_in_threadpool``."""
        source = inspect.getsource(verify)
        assert "from starlette.concurrency import run_in_threadpool" in source
        dispatches = _threadpool_dispatches(source)
        assert dispatches == {"read"}, (
            "every blocking call must go through the threadpool; the module's "
            f"threadpool dispatches were {sorted(dispatches)}"
        )
        # Negative control: the extraction finds a dispatch that is not there
        # when there is not one.
        assert _threadpool_dispatches("def f():\n    return reader.read(t)\n") == set()
