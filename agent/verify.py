"""Post-remediation health verification (ARCH §5.2, ROADMAP §4.3).

A Tier-1 incident is not closed when the diff is produced. It is closed when the
workload has been *re-observed* for a bounded window and the fault the incident
was raised for has not recurred. This module is that re-observation.

Four properties are load-bearing, and each is a place where the obvious
implementation is wrong:

Bounded observation
    The loop runs for at most ``watch_duration_seconds`` and is bounded **twice
    over**: by a monotonic deadline and by a fixed iteration count. The count is
    what makes termination unconditional - a frozen, stepped or patched clock
    cannot extend it - and the deadline is what makes the window *mean*
    ``watch_duration_seconds`` rather than ``polls x interval``. Timing uses
    :func:`time.perf_counter` (AGENTS.md §3 rule 5); a wall clock would be
    steppable by NTP in the middle of an incident.

A requeue bound that a caller cannot reset
    ``max_requeue_attempts`` is enforced as a value owned by the module, not as a
    counter in the caller's hands. :class:`RequeueBudget` is created once per
    incident, exposes no reset, refuses to rewind its own state, and is spent
    once per observation window - so one incident gets at most
    ``max_requeue_attempts + 1`` windows in total, forever, and an exhausted
    budget short-circuits *before* any read is issued. The spent count is also
    carried by each :class:`IndeterminateVerdict`, and the two carriers must
    agree, so a caller that mints a fresh budget while claiming continuity of a
    verdict it still holds is caught rather than trusted.

    There is no ``while True`` in this module.

Zero writes
    ARCH §3 line 53 marks the agent box a TRUST BOUNDARY and §2 records that the
    agent holds no cluster credential. This module therefore holds exactly one
    capability: :meth:`ObservationReader.read`, which returns a value. It has no
    write verb, no Kubernetes client, no subprocess, no socket and no filesystem
    access. ``agent/tests/test_verify.py`` asserts that by introspecting this
    file's AST and by arming a CPython audit hook around a real run, so the claim
    is checked rather than asserted.

Async boundary
    The single I/O call is a blocking read, so it is dispatched through
    :func:`starlette.concurrency.run_in_threadpool`. A verification window runs
    for up to 1800 seconds; executing that inline would stall ``/healthz`` and
    ``/readyz`` and get a healthy pod restarted by the kubelet (AGENTS.md §3
    rule 1).

Verdict routing
    ================= ========================= =====================
    Verdict           Means                     Policy action
    ================= ========================= =====================
    ``VERIFIED``      criteria met, no fault    ``on_success``
    ``UNRESOLVED``    fault recurred or unproven ``on_repeat_failure``
    ``INDETERMINATE`` observation impossible    ``on_indeterminate``
    ================= ========================= =====================

    ``action`` is a **derived property**, not a field. There is no input through
    which a caller can put ``PROMOTE_TO_TIER_2`` on a ``VERIFIED`` verdict, which
    is the only way that guarantee can be structural rather than a review
    convention.
"""

from __future__ import annotations

import asyncio
import math
import time
from collections.abc import Awaitable, Callable
from enum import Enum
from typing import Final, Literal, Protocol, TypeVar

from pydantic import BaseModel, ConfigDict, Field, model_validator
from starlette.concurrency import run_in_threadpool

from models import Dns1123Name, IncidentId, VerificationPolicy

__all__ = [
    "POLL_INTERVAL_SECONDS",
    "ContainerObservation",
    "ContainerTarget",
    "IndeterminateVerdict",
    "ObservationReader",
    "ObservationState",
    "RequeueBudget",
    "RequeueBudgetExhausted",
    "UnresolvedCause",
    "UnresolvedVerdict",
    "VerificationStateError",
    "VerificationVerdict",
    "VerifiedVerdict",
    "VerdictKind",
    "classify",
    "verify_incident",
]

#: How often the workload is re-read inside one observation window.
#:
#: A constant rather than a policy field: ARCH §5.2 fixes the window and the
#: criteria, and a caller-chosen poll interval is a knob that could be set to
#: sample once and declare a workload healthy before it has had time to fail
#: again.
POLL_INTERVAL_SECONDS: Final[float] = 5.0


# ---------------------------------------------------------------------------
# What is observed
# ---------------------------------------------------------------------------


class _Frozen(BaseModel):
    """Closed to unknown fields and immutable.

    ``extra="forbid"`` for the reason given in :mod:`models`: an unknown field is
    a contract-drift signal, not noise. ``frozen=True`` additionally, so a
    verdict - a decision record - cannot be edited after it is returned into
    something that claims a different action.
    """

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        str_strip_whitespace=False,
    )


class ContainerTarget(_Frozen):
    """The single container under observation."""

    namespace: Dns1123Name
    pod_name: Dns1123Name
    container_name: Dns1123Name


class ContainerObservation(_Frozen):
    """One read of the observable state of a container.

    A sampling record, not a cluster object: the module holds no credential to
    read one, and holding a mutable API object would be a capability this module
    is not allowed to have.

    ``container_uptime_seconds is None`` means "uptime could not be read", which
    is different from ``0`` ("the container just restarted"). Collapsing the two
    would turn an unreadable field into a recurrence verdict, and a recurrence
    verdict escalates.
    """

    visible: bool
    oomkilled_terminations: int = Field(ge=0)
    crashloopbackoff_wait: bool
    container_uptime_seconds: int | None = Field(default=None, ge=0)
    note: str = Field(default="", max_length=512)

    @model_validator(mode="after")
    def _invisible_has_no_uptime(self) -> ContainerObservation:
        """An unseen container cannot also be reporting an uptime.

        Without this, a reader that fills in every field regardless of visibility
        would report ``container_uptime_seconds=0`` for a pod it never saw, and
        the classifier would call that a recurrence and promote to Tier-2.
        """
        if not self.visible and self.container_uptime_seconds is not None:
            raise ValueError(
                "container_uptime_seconds must be null when the container is not "
                "visible; an unreadable field is not a zero"
            )
        return self


class ObservationReader(Protocol):
    """The one capability this module holds.

    Read-only by construction: a single method, returning a value. There is no
    verb here that could express a cluster write, so the zero-writes property of
    :func:`verify_incident` is a property of the interface, not of discipline at
    the call site.
    """

    def read(self, target: ContainerTarget) -> ContainerObservation:
        """Return the current observable state of ``target``."""
        ...


# ---------------------------------------------------------------------------
# Verdicts
# ---------------------------------------------------------------------------


class VerdictKind(str, Enum):
    """The explicit discriminant. Dispatch on this, not on ``type()``."""

    VERIFIED = "VERIFIED"
    UNRESOLVED = "UNRESOLVED"
    INDETERMINATE = "INDETERMINATE"


class UnresolvedCause(str, Enum):
    """Why a verdict is ``UNRESOLVED``.

    Four distinct causes collapse to one action, which is correct: a human is
    needed in every case, and the *reason* is what lets that human avoid
    repeating the investigation the agent just did.
    """

    OOM_KILLED = "OOM_KILLED"
    CRASH_LOOP_BACKOFF = "CRASH_LOOP_BACKOFF"
    UPTIME_BELOW_MINIMUM = "UPTIME_BELOW_MINIMUM"
    REQUEUE_BUDGET_EXHAUSTED = "REQUEUE_BUDGET_EXHAUSTED"


#: Which ``VerificationPolicy`` field carries the action for each verdict kind.
#:
#: ARCH §5.2 names three actions and three policy fields; this table is the only
#: place that pairing is written down, so a verdict cannot pick up an action that
#: belongs to a different outcome.
_ACTION_FIELD: Final[dict[VerdictKind, str]] = {
    VerdictKind.VERIFIED: "on_success",
    VerdictKind.UNRESOLVED: "on_repeat_failure",
    VerdictKind.INDETERMINATE: "on_indeterminate",
}

_CAUSE_REASONS: Final[dict[UnresolvedCause, str]] = {
    UnresolvedCause.OOM_KILLED: (
        "the container was OOMKilled again during the observation window, so the "
        "remediation did not hold"
    ),
    UnresolvedCause.CRASH_LOOP_BACKOFF: (
        "the container entered CrashLoopBackOff during the observation window, so "
        "the remediation did not hold"
    ),
    UnresolvedCause.UPTIME_BELOW_MINIMUM: (
        "the observation window closed with no recurrence, but container uptime "
        "never reached the configured minimum, so the remediation is unproven"
    ),
    UnresolvedCause.REQUEUE_BUDGET_EXHAUSTED: (
        "the bounded requeue budget was exhausted without a conclusive "
        "observation, so the incident is escalated rather than observed again"
    ),
}


class _VerdictBase(_Frozen):
    """Shared verdict payload.

    Carries the policy it was decided against, which is what lets ``action`` be
    derived below: the verdict never stores the action string, so no caller,
    deserializer or later edit can substitute one verdict's action for another's.
    """

    #: The discriminant. Declared here so ``action`` can be typed against it, and
    #: narrowed to a single ``Literal`` member by each subclass, so a verdict
    #: class *is* its kind: there is no way to build a ``VerifiedVerdict`` that
    #: claims to be anything else.
    kind: VerdictKind

    incident_id: IncidentId
    policy: VerificationPolicy
    #: The observation that produced the verdict. ``None`` only on a terminal
    #: escalation reached without any read (budget exhausted, no prior verdict
    #: to quote), and even then the reason says so.
    observation: ContainerObservation | None = None
    #: Monotonic seconds spent observing in this call. Never a wall-clock delta.
    observed_seconds: float = Field(ge=0.0)
    #: Reads performed in this call. The audit trail of the requeue bound.
    samples_observed: int = Field(ge=0)
    #: Requeues this incident's chain has consumed, including this call.
    requeues_used: int = Field(ge=0)
    reason: str = Field(min_length=1, max_length=1024)

    @property
    def action(self) -> str:
        """The policy action this verdict routes to (ARCH §5.2).

        Read from the policy embedded in the verdict, through the single
        kind-to-field table above. Not settable, and not one of three literals
        hardcoded here, so a policy that configures a different action string is
        honoured rather than silently overridden.
        """
        return str(getattr(self.policy, _ACTION_FIELD[self.kind]))


class VerifiedVerdict(_VerdictBase):
    """The fault did not recur and every success criterion was met."""

    kind: Literal[VerdictKind.VERIFIED] = VerdictKind.VERIFIED

    @model_validator(mode="after")
    def _must_have_observed(self) -> VerifiedVerdict:
        """A closure verdict with no observation behind it is a fabrication."""
        if self.observation is None:
            raise ValueError(
                "a VERIFIED verdict must carry the observation that " "proves it"
            )
        return self


class UnresolvedVerdict(_VerdictBase):
    """The fault recurred, or the window ended without proving the fix.

    Fail-closed. "Not proven fixed" and "proven still broken" route to the same
    place, because the alternative - leaving an unproven remediation in place
    and quietly re-observing forever - is how a bad memory limit becomes
    permanent.
    """

    kind: Literal[VerdictKind.UNRESOLVED] = VerdictKind.UNRESOLVED
    cause: UnresolvedCause


class IndeterminateVerdict(_VerdictBase):
    """The observation itself could not be made.

    Neither a failure of the workload nor a pass for it. The only verdict kind
    that may consume a requeue.
    """

    kind: Literal[VerdictKind.INDETERMINATE] = VerdictKind.INDETERMINATE


#: The three verdicts. ``kind`` is the discriminant.
VerificationVerdict = VerifiedVerdict | UnresolvedVerdict | IndeterminateVerdict


class RequeueBudgetExhausted(RuntimeError):
    """Raised by :meth:`RequeueBudget.spend` past the bound.

    The exception is the point: the budget is a value that can only decrease, and
    this is the single place where decreasing it further is refused.
    """


class VerificationStateError(RuntimeError):
    """A caller asked to continue a verification chain that is already closed."""


# ---------------------------------------------------------------------------
# The requeue bound
# ---------------------------------------------------------------------------


class RequeueBudget:
    """One incident's observation allowance. Created once, spent down, never reset.

    ARCH §5.2 fixes ``max_requeue_attempts >= 1`` as the thing that "prevents
    infinite retry loops". The arithmetic it implies is: one initial observation
    window, plus at most ``max_requeue_attempts`` requeues, so
    ``max_windows == limit + 1``.

    Why this is a class and not an integer in ``verify_incident``'s signature:

    * An integer parameter is resettable - the caller passes ``0`` again and the
      bound is gone. This object owns the count, exposes no setter, no ``reset``,
      and every counter is a read-only property.
    * ``__setattr__`` refuses to rewind the counter, so even
      ``budget._windows = 0`` is rejected. The only mutation path is
      :meth:`spend`, which raises instead of going negative.
    * :meth:`spend` is called at the *top* of the window, so an exhausted budget
      is detected before a single read is issued, not after.

    The spent count is also carried on every :class:`IndeterminateVerdict`. The
    two carriers must agree (see :func:`verify_incident`), so a caller that mints
    a fresh budget while still holding a prior verdict claiming continuity is
    caught rather than trusted. A caller that discards the verdict *and* mints a
    fresh budget has, in fact, started a new incident; nothing in-process can
    distinguish that from a legitimate first call, and pretending otherwise would
    be a check that cannot fail.
    """

    __slots__ = ("_incident_id", "_limit", "_windows")

    # Declared so the slots are typed. Bare annotations create no class
    # attribute, so they do not collide with __slots__.
    _limit: int
    _incident_id: str
    _windows: int

    def __init__(self, policy: VerificationPolicy, incident_id: str) -> None:
        # ARCH §5.2 requires max_requeue_attempts >= 1; models.py enforces it on
        # the policy and this enforces it on the value, so a hand-built budget
        # cannot buy a zero-allowance incident a free retry.
        if policy.max_requeue_attempts < 1:
            raise ValueError(
                "max_requeue_attempts must be >= 1, got "
                f"{policy.max_requeue_attempts}"
            )
        object.__setattr__(self, "_limit", policy.max_requeue_attempts)
        object.__setattr__(self, "_incident_id", incident_id)
        object.__setattr__(self, "_windows", 0)

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError(
            f"RequeueBudget is immutable; cannot set {name!r}. The requeue bound "
            "is only spendable through spend()."
        )

    def __delattr__(self, name: str) -> None:
        raise AttributeError(f"RequeueBudget is immutable; cannot delete {name!r}")

    @property
    def limit(self) -> int:
        """``verification_policy.max_requeue_attempts``."""
        return self._limit

    @property
    def incident_id(self) -> str:
        """The incident this allowance belongs to. Guards cross-wiring."""
        return self._incident_id

    @property
    def max_windows(self) -> int:
        """Total observation windows this incident may ever run."""
        return self._limit + 1

    @property
    def windows_spent(self) -> int:
        """Windows already started."""
        return self._windows

    @property
    def requeues_used(self) -> int:
        """Requeues consumed so far. The first window is not a requeue."""
        return max(0, self._windows - 1)

    @property
    def remaining(self) -> int:
        """Windows still permitted. Negative once the chain is over."""
        return self.max_windows - self._windows

    @property
    def exhausted(self) -> bool:
        """Whether another observation window is forbidden.

        ``windows_spent == limit + 1`` is the exhausted state. Spending the
        initial window leaves ``windows_spent == 1``, so a limit of 1 still buys
        two windows: the original observation and one requeue.
        """
        return self._windows >= self.max_windows

    def spend(self) -> int:
        """Consume one window. Raises once the bound is passed.

        Returns the new requeue count so the caller can stamp it onto the
        verdict it is about to return, keeping the two carriers in step.
        """
        if self.exhausted:
            raise RequeueBudgetExhausted(
                f"requeue budget exhausted for {self._incident_id}: "
                f"{self._windows} of {self.max_windows} observation windows used "
                f"(max_requeue_attempts={self._limit})"
            )
        object.__setattr__(self, "_windows", self._windows + 1)
        return self.requeues_used

    def __repr__(self) -> str:
        return (
            f"RequeueBudget(incident_id={self._incident_id!r}, "
            f"windows={self._windows}/{self.max_windows})"
        )


# ---------------------------------------------------------------------------
# Classification - pure, no clock, no cluster
# ---------------------------------------------------------------------------


class ObservationState(str, Enum):
    """What a single read means for the incident."""

    HEALTHY = "HEALTHY"
    #: Visible, no recurrence, but uptime has not reached the minimum yet.
    UNSTABLE = "UNSTABLE"
    FAULT_RECURRENCE = "FAULT_RECURRENCE"
    UNOBSERVABLE = "UNOBSERVABLE"


def classify(
    observation: ContainerObservation, policy: VerificationPolicy
) -> ObservationState:
    """Reduce one observation to one state. Total function; never raises.

    The order of the tests is the substance of this function:

    1. *Unobservable first.* A read that could not see the workload is not
       evidence about the workload.
    2. *Recurrence before uptime.* A container OOMKilled one second ago has an
       uptime of 1, below any sensible minimum; checking uptime first would
       report ``UNSTABLE`` and keep polling a container that is already failing,
       delaying a Tier-2 escalation that is clearly warranted.
    3. *Uptime last.* Only a container with no recurrence can be said to still be
       accumulating uptime.
    """
    if not observation.visible:
        return ObservationState.UNOBSERVABLE
    if observation.oomkilled_terminations > 0 or observation.crashloopbackoff_wait:
        return ObservationState.FAULT_RECURRENCE
    if observation.container_uptime_seconds is None:
        return ObservationState.UNOBSERVABLE
    if (
        observation.container_uptime_seconds
        < policy.success_criteria.container_uptime_seconds_min
    ):
        return ObservationState.UNSTABLE
    return ObservationState.HEALTHY


# ---------------------------------------------------------------------------
# The loop
# ---------------------------------------------------------------------------


#: Bound so :func:`_verdict` returns the concrete verdict class it built rather
#: than the shared base, keeping the union return type of verify_incident exact.
_VerdictT = TypeVar("_VerdictT", bound="_VerdictBase")


def _verdict(
    cls: type[_VerdictT],
    kind: VerdictKind,
    policy: VerificationPolicy,
    incident_id: str,
    *,
    observation: ContainerObservation | None,
    observed_seconds: float,
    samples: int,
    requeues_used: int,
    reason: str,
) -> _VerdictT:
    # ``kind`` is passed explicitly and checked against the class's own Literal by
    # Pydantic, rather than being taken from a lookup table. A mismatch is a
    # ValidationError at construction, which is the guarantee that a verdict
    # cannot be labelled with an outcome it did not reach.
    return cls(
        kind=kind,
        incident_id=incident_id,
        policy=policy,
        observation=observation,
        observed_seconds=observed_seconds,
        samples_observed=samples,
        requeues_used=requeues_used,
        reason=reason,
    )


def _unresolved(
    policy: VerificationPolicy,
    incident_id: str,
    *,
    observation: ContainerObservation | None,
    cause: UnresolvedCause,
    observed_seconds: float,
    samples: int,
    requeues_used: int,
) -> UnresolvedVerdict:
    return UnresolvedVerdict(
        incident_id=incident_id,
        policy=policy,
        observation=observation,
        observed_seconds=observed_seconds,
        samples_observed=samples,
        requeues_used=requeues_used,
        cause=cause,
        reason=_CAUSE_REASONS[cause],
    )


async def verify_incident(
    policy: VerificationPolicy,
    target: ContainerTarget,
    reader: ObservationReader,
    *,
    incident_id: str,
    budget: RequeueBudget,
    prior: VerificationVerdict | None = None,
    poll_interval_seconds: float = POLL_INTERVAL_SECONDS,
    clock: Callable[[], float] | None = None,
    sleep: Callable[[float], Awaitable[None]] | None = None,
) -> VerificationVerdict:
    """Observe one workload for at most ``watch_duration_seconds`` and decide.

    One call is one observation window. A requeue is a *subsequent* call that
    hands the same :class:`RequeueBudget` back (and, if it still holds one, the
    previous :class:`IndeterminateVerdict` as ``prior``). That is how
    ``max_requeue_attempts`` bounds the chain, and why the bound holds across
    requeues rather than only inside one call.

    ``budget`` is a required keyword argument. A default would invite the exact
    bug the bound exists to prevent: a caller that forgot to thread it would
    silently get a fresh, unlimited allowance on every call.

    ``clock`` and ``sleep`` are injectable so the bound is testable without
    waiting 60 seconds, and so a test can prove termination does not depend on
    the clock advancing.

    Returns before the window closes when the outcome is already determined: a
    recurrence, or a healthy container that has met the uptime minimum. Polling
    continues only while the container is alive but not yet proven.
    """
    if budget.incident_id != incident_id:
        raise VerificationStateError(
            f"budget belongs to {budget.incident_id!r}, not {incident_id!r}; a "
            "shared budget would let one incident's requeues pay for another's "
            "observation windows"
        )
    if prior is not None:
        if prior.kind is not VerdictKind.INDETERMINATE:
            raise VerificationStateError(
                f"only an INDETERMINATE verdict can be requeued; a "
                f"{prior.kind.value} verdict closed this chain"
            )
        if prior.incident_id != incident_id:
            raise VerificationStateError(
                f"prior verdict is for {prior.incident_id!r}, not {incident_id!r}"
            )
        if prior.requeues_used != budget.requeues_used:
            # The anti-reset guard. Holding a verdict that says "this chain has
            # spent N requeues" while presenting a budget that says 0 means the
            # bound was rewound. Refused rather than believed.
            raise VerificationStateError(
                f"requeue accounting disagrees: prior verdict records "
                f"{prior.requeues_used} requeues, budget says "
                f"{budget.requeues_used}. A requeue chain may not be restarted."
            )
    if poll_interval_seconds <= 0:
        raise ValueError(
            f"poll_interval_seconds must be > 0, got {poll_interval_seconds}"
        )

    # Resolved at call time rather than bound as default arguments, so a caller
    # (or a test) can substitute either one without the signature lying about
    # which clock is in use.
    active_clock: Callable[[], float] = time.perf_counter if clock is None else clock
    active_sleep: Callable[[float], Awaitable[None]] = (
        asyncio.sleep if sleep is None else sleep
    )

    # The bound is checked, and a window is spent, *before* any read is issued -
    # so it holds on observation calls and not merely on returns.
    if budget.exhausted:
        return _unresolved(
            policy,
            incident_id,
            observation=None if prior is None else prior.observation,
            cause=UnresolvedCause.REQUEUE_BUDGET_EXHAUSTED,
            observed_seconds=0.0,
            samples=0,
            requeues_used=budget.requeues_used,
        )
    requeues_used = budget.spend()

    # Two independent bounds, neither sufficient alone. The iteration count makes
    # termination unconditional - a frozen clock cannot spin it - and the
    # monotonic deadline makes the window mean watch_duration_seconds rather than
    # polls x interval, so a fast-poll configuration cannot shorten observation
    # into a sample taken before the container had time to fail again.
    max_samples = max(
        1, math.ceil(policy.watch_duration_seconds / poll_interval_seconds)
    )
    started = active_clock()
    deadline = started + policy.watch_duration_seconds

    last: ContainerObservation | None = None
    samples = 0
    for index in range(max_samples):
        if index > 0:
            await active_sleep(poll_interval_seconds)
            if active_clock() >= deadline:
                # The monotonic deadline. The iteration count alone would keep
                # sampling past the window if a read were slow; the deadline
                # alone would never fire if the clock were frozen.
                break
        # The only I/O in this module, and the only blocking call, so it is the
        # only one that has to leave the event loop (AGENTS.md §3 rule 1).
        last = await run_in_threadpool(reader.read, target)
        state = classify(last, policy)
        samples = index + 1
        elapsed = active_clock() - started
        if state is ObservationState.HEALTHY:
            return _verdict(
                VerifiedVerdict,
                VerdictKind.VERIFIED,
                policy,
                incident_id,
                observation=last,
                observed_seconds=elapsed,
                samples=samples,
                requeues_used=requeues_used,
                reason=(
                    "no OOMKilled termination and no CrashLoopBackOff across "
                    f"{samples} observation(s), with container uptime at or above "
                    f"{policy.success_criteria.container_uptime_seconds_min}s"
                ),
            )
        if state is ObservationState.FAULT_RECURRENCE:
            cause = (
                UnresolvedCause.OOM_KILLED
                if last.oomkilled_terminations > 0
                else UnresolvedCause.CRASH_LOOP_BACKOFF
            )
            return _unresolved(
                policy,
                incident_id,
                observation=last,
                cause=cause,
                observed_seconds=elapsed,
                samples=samples,
                requeues_used=requeues_used,
            )
        if state is ObservationState.UNOBSERVABLE:
            # One unobservable read ends the window. Retrying inside the window
            # would hide a broken observation path behind a longer wait, and the
            # bounded requeue is the mechanism ARCH §5.2 provides for exactly
            # this case.
            return _verdict(
                IndeterminateVerdict,
                VerdictKind.INDETERMINATE,
                policy,
                incident_id,
                observation=last,
                observed_seconds=elapsed,
                samples=samples,
                requeues_used=requeues_used,
                reason=(
                    "the workload could not be observed"
                    + (f": {last.note}" if last.note else "")
                    + f"; requeue {requeues_used}/{policy.max_requeue_attempts} "
                    "consumed"
                ),
            )
        # UNSTABLE: alive, no recurrence, not yet proven. Keep observing.

    return _unresolved(
        policy,
        incident_id,
        observation=last,
        cause=UnresolvedCause.UPTIME_BELOW_MINIMUM,
        observed_seconds=active_clock() - started,
        # The real count, not ``max_samples``. Reporting the cap would make a
        # window that stopped early look like one that ran to completion, which
        # is precisely the evidence a reviewer needs when a verdict looks wrong.
        samples=samples,
        requeues_used=requeues_used,
    )
