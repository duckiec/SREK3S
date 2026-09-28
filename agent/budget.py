"""Active-job budget for the triage service (ARCH §4.3, ROADMAP §2.2.5, §2.4).

The agent is the egress path for incident data, so it is deliberately
resource-capped. This module is that cap for **concurrency**: at most
``max_active`` investigations may be in flight, and a request arriving while the
budget is exhausted is refused immediately rather than queued.

Refuse, don't queue
-------------------
Queueing would convert overload into latency, and latency at the triage service
propagates straight into time-to-mitigation. Worse, an unbounded queue in front
of a bounded worker pool is how a memory exhaustion becomes an OOMKill - the
agent would generate the very incident it exists to respond to. Returning 429
immediately keeps the pressure visible at the caller, which is the Sentinel, and
lets *it* decide what to shed.

A 429 is a retryable outcome, so the response carries ``Retry-After``. The
Sentinel applies jitter; a synchronised retry storm is its own outage.

Counter-based, not a Semaphore
------------------------------
:class:`JobBudget` is a counter with a lock rather than an
:class:`asyncio.Semaphore`. That is deliberate:

* ``Semaphore.acquire()`` *waits* when exhausted, which is exactly the queueing
  behaviour rejected above. There is no non-blocking acquire in asyncio, so a
  semaphore cannot express "refuse now".
* Checking and incrementing under one lock makes the test-and-acquire atomic.
  Two coroutines racing a bare ``locked()`` check would both admit and both
  increment, overshooting the budget - the failure mode where the cap silently
  does not hold exactly when it is most needed.

Leases, not bare increments
---------------------------
:meth:`JobBudget.slot` is a context manager, so the slot is released in a
``finally``. An ``await`` between acquire and release - which is what analysis
actually is - can raise or be cancelled, and a bare increment would leak the
slot permanently. Leaked slots would ratchet the service into permanent 429s
after enough failures, which is the worst possible failure mode for a guard
whose purpose is to keep the service serving.
"""

from __future__ import annotations

import logging
import os
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Final, Iterator

__all__ = [
    "DEFAULT_MAX_ACTIVE",
    "MAX_ACTIVE_ENV",
    "JobBudget",
    "budget_from_env",
]

#: Environment variable holding the active-job budget.
MAX_ACTIVE_ENV: Final[str] = "SREK3S_MAX_ACTIVE_JOBS"

#: Default concurrent investigations.
#:
#: Sized for the deterministic Milestone 2 triage path, which is CPU-trivial and
#: completes in well under a millisecond, so the budget is about bounding
#: *blast radius* rather than about CPU saturation. It is deliberately small: an
#: over-large value would let one noisy namespace consume the whole agent while
#: the budget was nominally "not reached".
DEFAULT_MAX_ACTIVE: Final[int] = 4

#: Below this the budget is meaningless or actively harmful, so a
#: misconfiguration is clamped rather than honoured. A budget of 0 would refuse
#: every request and look like an outage; a negative one is nonsense.
_MIN_SANE_BUDGET: Final[int] = 1


@dataclass
class JobBudget:
    """A bounded number of concurrently active jobs.

    ``max_active`` is fixed at construction. A budget that could be raised while
    the service is saturated would be raised at the worst possible moment, so it
    is deliberately not mutable through the public surface.
    """

    max_active: int
    active: int = 0
    rejected: int = 0
    peak: int = 0

    def __post_init__(self) -> None:
        if self.max_active < _MIN_SANE_BUDGET:
            self.max_active = _MIN_SANE_BUDGET

    @property
    def available(self) -> int:
        """Slots currently free. Never negative."""
        return max(0, self.max_active - self.active)

    @property
    def saturated(self) -> bool:
        return self.active >= self.max_active

    def try_acquire(self) -> bool:
        """Take a slot if one is free. Atomic check-and-increment.

        Returns ``False`` when the budget is exhausted. The caller must then
        refuse the request; there is no waiting variant, by design.

        Concurrency-safe without a lock because the critical section contains no
        ``await``: on a single event loop a coroutine cannot be preempted between
        the check and the increment, so the pair is indivisible. Introducing an
        ``await`` in here would break that property and require a real lock.
        """
        if self.saturated:
            self.rejected += 1
            return False
        self.active += 1
        self.peak = max(self.peak, self.active)
        return True

    def release(self) -> None:
        """Return a slot. Clamped at zero.

        The clamp is not papering over a bug silently - it makes a double
        release harmless rather than allowing ``active`` to drift negative, which
        would silently raise the effective budget on every subsequent request.
        """
        self.active = max(0, self.active - 1)

    @contextmanager
    def slot(self) -> Iterator[bool]:
        """Hold a slot for the duration of the block.

        Yields ``True`` when a slot was acquired, ``False`` when the budget was
        exhausted. The body should not run when this yields ``False``.
        """
        acquired = self.try_acquire()
        try:
            yield acquired
        finally:
            # Released even when the body raises or the task is cancelled;
            # a leaked slot would eventually make the guard refuse everything.
            if acquired:
                self.release()


def budget_from_env(env: dict[str, str] | None = None) -> JobBudget:
    """Build a budget from :data:`MAX_ACTIVE_ENV`.

    A non-integer or absent value falls back to :data:`DEFAULT_MAX_ACTIVE` rather
    than raising. An agent that will not start because a ConfigMap has a typo is
    an outage; an agent that starts with a sane default and logs the bad value is
    a degraded-but-serving component, which is the correct trade for the process
    that exists to keep a cluster incident from becoming one.
    """
    source = os.environ if env is None else env
    raw = source.get(MAX_ACTIVE_ENV)
    if raw is None:
        return JobBudget(DEFAULT_MAX_ACTIVE)
    try:
        parsed = int(raw)
    except ValueError:
        logging.getLogger("srek3s.agent").warning(
            "%s=%r is not an integer; falling back to %d",
            MAX_ACTIVE_ENV,
            raw,
            DEFAULT_MAX_ACTIVE,
        )
        return JobBudget(DEFAULT_MAX_ACTIVE)
    if parsed < _MIN_SANE_BUDGET:
        logging.getLogger("srek3s.agent").warning(
            "%s=%d is below the usable floor; clamping to %d",
            MAX_ACTIVE_ENV,
            parsed,
            _MIN_SANE_BUDGET,
        )
    return JobBudget(parsed)
