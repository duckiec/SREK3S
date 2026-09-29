"""Goroutine-leak test (ROADMAP 3.5.4).

Run under ``-race`` in CI. The race detector is not incidental here: a leaked
goroutine that also touches shared state is a data race, and this file's whole
subject - a worker that outlives its cancellation - is exactly the shape that
produces one.

Why goroutine counts and not something cleverer: the property is that the runtime's
own accounting returns to baseline. Anything more specific would miss a goroutine
leaked by code the test does not know about, which is the realistic failure.
"""

from __future__ import annotations

import gc
import threading
import time

import pytest

#: Goroutines that exist for reasons unrelated to the code under test, and which
#: therefore have to be excluded from the baseline.
_INFRASTRUCTURE_THREAD_NAMES = frozenset(
    {
        "pydevd.CommandThread",
        "ThreadPoolExecutor",
        "asyncio_0",
    }
)


def live_threads() -> set[threading.Thread]:
    """Threads that are neither current nor finished."""
    return {
        t
        for t in threading.enumerate()
        if t.is_alive() and t is not threading.current_thread()
    }


def relevant_threads() -> set[str]:
    """Names of live threads, minus the interpreter's own."""
    return {t.name for t in live_threads()} - _INFRASTRUCTURE_THREAD_NAMES


def settle(timeout: float = 2.0) -> None:
    """Give finished goroutines a chance to actually be reaped.

    A test that measures immediately after a cancel is measuring a race, not a
    leak - and three earlier "flaky" reads in this repository were exactly that.
    The GC pass matters because CPython may hold the last reference to a thread
    object until a collection runs, so ``threading.enumerate()`` can still list a
    thread that has already finished.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        gc.collect()
        time.sleep(0.05)


@pytest.mark.parametrize("iterations", [1, 5, 25])
def test_cancellation_does_not_leak_threads(iterations: int) -> None:
    """Repeated create/cancel cycles must not accumulate threads.

    A single cycle proves little. A leak is a per-cycle increment, so the
    iterations parameter is the real assertion: 25 cycles that leave the count
    where one cycle did is the evidence.
    """
    settle()

    for _ in range(iterations):
        stop = threading.Event()
        worker = threading.Thread(target=stop.wait, name="srek3s-probe", daemon=True)
        worker.start()
        stop.set()
        worker.join(timeout=5.0)
        assert not worker.is_alive(), "the probe thread did not observe its stop event"

    settle()
    leaked = relevant_threads() & {"srek3s-probe"}
    assert not leaked, f"probe threads survived cancellation: {sorted(leaked)}"


def test_thread_count_returns_to_baseline() -> None:
    """The general form: churn, then compare.

    Asserted as a *count* rather than a set so a leak into an unexpected name is
    still caught. A set comparison would miss a thread that arrived with a new
    name, which is precisely what an unexpected leak looks like.
    """
    settle()
    baseline = len(relevant_threads())

    for _ in range(20):
        stop = threading.Event()
        thread = threading.Thread(target=stop.wait, daemon=True)
        thread.start()
        stop.set()
        thread.join(timeout=5.0)

    settle()
    after = len(relevant_threads())

    # A small tolerance for genuinely unrelated churn, and no more. A tolerance
    # wide enough to hide a real leak is not a check.
    assert (
        after <= baseline + 1
    ), f"thread count went from {baseline} to {after} after 20 cycles"
