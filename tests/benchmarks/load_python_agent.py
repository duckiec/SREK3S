#!/usr/bin/env python3
"""Concurrent load test for the SREK3S triage agent's active-job budget.

What this proves, and what it deliberately refuses to prove
-----------------------------------------------------------
The existing suite proves the ``429 sandbox_busy`` path *exists*: it injects a
:class:`JobBudget`, monkeypatches triage to sleep 250 ms, fires an
``httpx.ASGITransport`` burst and asserts a 429 came back. That is a good test
of the code and a weak test of the system, because it removes both of the things
that make saturation hard in production - the network, and triage being fast.

This script closes that gap. It talks to a **running agent over a real socket**
with **real concurrent connections**, so the 429 is produced by the deployed
code path rather than by an in-process harness. It is a load test, not a unit
test, and it is not part of the pytest gate; it is a thing you point at a pod.

The lease it exercises
----------------------
Note for the reader who was told to look in ``agent/sandbox.py``: the lease is
in ``agent/budget.py``. ``JobBudget`` is a plain dataclass counter with a
``slot()`` context manager, *not* a semaphore and *not* lock-protected. Its
safety argument is stated in its own docstring and depends on two facts:

1. ``try_acquire`` contains no ``await``, so on the single uvicorn event loop a
   coroutine cannot interleave between the ``saturated`` check and the
   ``active += 1``. Adding an await inside that critical section would break it
   and require a real lock.
2. ``post_triage`` acquires the slot *before* it awaits anything, so the admit
   decision is made at coroutine start and the slot is held across the whole
   handler - body parse, threadpool triage, and response serialisation.

Consequence for this script: admission is decided at the *top* of the handler,
so what matters is how many requests the event loop has **started** in one
burst, not how long triage takes. A burst of N simultaneous requests admits 4
and sheds N-4, immediately, regardless of whether triage takes 1 ms or 400 ms.

Getting saturation to actually happen
-------------------------------------
Two things outside this script's control, both of which produce a run with zero
429s that looks like a passing result:

* **Point it at one pod, not the Service.** ``deploy/agent.yaml`` sets
  ``replicas: 2``. Every pod has its own ``JobBudget``; a ClusterIP Service
  round-robins, so the *effective* budget is 8 and shedding is half as likely.
* **NetworkPolicy.** The same manifest restricts ingress on port 8000 to
  ``app: srek3s-sentinel``. A load generator from anywhere else in the cluster
  gets connection-refused, not a 429.

And one that makes it far more reliable, if triage is too fast to hold a slot:

* ``SREK3S_SANDBOX=1`` forks a child process per admitted request
  (``main.py`` puts the cost at ~400 ms). With the budget held for hundreds of
  milliseconds, shedding is effectively guaranteed. The deployed default is
  sandbox-off, so a run against a default pod is a genuine race and may
  legitimately produce few or no 429s. The script reports that as a loud
  failure rather than a pass; see ``EXIT_*`` codes below.

Exit codes
----------
===  ==========================================================================
0    saturated, and liveness/readiness held throughout
1    usage / configuration error
2    preflight control failed (payload invalid, endpoint unhealthy, 404/405)
3    NO 429 OBSERVED - saturation was not achieved (this is a failure)
4    contract violation - 400/422 from the schema, or a 429 without the
     {"error": "sandbox_busy"} envelope
5    health probe failed during saturation - shedding moved the failure to kubelet
6    transport or server error - the run measured something other than shedding
===  ==========================================================================

Stdlib only (``concurrent.futures``, ``http.client``, ``threading``). No install
step, and no third-party import except a best-effort import of
``agent/models.py`` for offline payload validation. Targets Python 3.11
(AGENTS.md §2): no PEP 695 type parameters, no PEP 701 f-string syntax.
"""

from __future__ import annotations

import argparse
import http.client
import json
import math
import ssl
import sys
import threading
import time
import urllib.parse
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final, Sequence

# ---------------------------------------------------------------------------
# Exit codes. Named because CI needs to tell "we did not saturate" apart from
# "the agent died" apart from "I typo'd the URL", and a bare non-zero does not.
# ---------------------------------------------------------------------------

EXIT_OK: Final[int] = 0
EXIT_USAGE: Final[int] = 1
EXIT_CONTROL_FAILED: Final[int] = 2
EXIT_NOT_SATURATED: Final[int] = 3
EXIT_CONTRACT_VIOLATION: Final[int] = 4
EXIT_PROBE_FAILED: Final[int] = 5
EXIT_TRANSPORT_FAILED: Final[int] = 6

_REPO_ROOT: Final[Path] = Path(__file__).resolve().parents[2]

#: Preference order. ``emitted_incident.json`` first: it is the Go emitter's
#: actual output and carries no documentation key, so it is the payload least
#: likely to drift from what the Sentinel will really send. ``sample-incident``
#: is the fallback because its ``_comment`` key is stripped below.
_FIXTURES: Final[tuple[Path, ...]] = (
    _REPO_ROOT / "tests" / "fixtures" / "emitted_incident.json",
    _REPO_ROOT / "tests" / "fixtures" / "sample-incident.json",
)

#: The 429 envelope this script asserts on, from ``main.py::_busy``.
_EXPECTED_SHED_ERROR: Final[str] = "sandbox_busy"

_KIND_ADMITTED: Final[str] = "admitted"
_KIND_SHED: Final[str] = "shed"
_KIND_CONTRACT: Final[str] = "contract_violation"
_KIND_SERVER_ERROR: Final[str] = "server_error"
_KIND_TRANSPORT: Final[str] = "transport"
_KIND_UNEXPECTED: Final[str] = "unexpected_status"

#: Single-element holder for the run's monotonic origin, so ``_Prober`` and
#: ``_worker`` can read it without threading an extra parameter through
#: every constructor and closure. Written exactly once - by ``main``, via the
#: ``on_ready`` callback, immediately before the load is released - and never
#: mutated afterwards, which is what makes reading it from another thread safe.
_RUN_START: list[float] = [0.0]


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Sample:
    """One triage request's outcome, on the monotonic run timeline.

    ``send_offset``/``recv_offset`` are seconds since the ``time.perf_counter()``
    taken immediately before the load is released. Every number in the report is
    derived from these offsets or from ``duration``; nothing in this file reads
    a wall clock (AGENTS.md §3.5).
    """

    worker: int
    kind: str
    status: int | None
    send_offset: float
    recv_offset: float
    detail: str = ""

    @property
    def duration(self) -> float:
        return self.recv_offset - self.send_offset


@dataclass(frozen=True)
class ProbeSample:
    """One liveness/readiness probe, on the same monotonic timeline.

    ``recovered`` distinguishes a genuine liveness failure from a keep-alive
    socket the server recycled underneath a reused connection. The kubelet
    opens a fresh connection per probe, so only the former is a liveness event,
    but collapsing the two would hide real evidence.
    """

    endpoint: str
    ok: bool
    recovered: bool
    status: int | None
    offset: float
    duration: float
    detail: str = ""


@dataclass
class Collector:
    """Thread-safe sink for samples. One instance, shared by every thread."""

    samples: list[Sample] = field(default_factory=list)
    probes: list[ProbeSample] = field(default_factory=list)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def add_sample(self, sample: Sample) -> None:
        with self._lock:
            self.samples.append(sample)

    def add_probe(self, probe: ProbeSample) -> None:
        with self._lock:
            self.probes.append(probe)


class _SpinBarrier:
    """Arrival barrier with a deadline, for a tight burst.

    ``threading.Barrier`` releases waiters through the GIL one at a time, and on
    a loaded box the last arrival can be scheduled well after the first. That
    jitter is the same order of magnitude as the server's triage latency, so a
    stagger introduced by the *generator* is indistinguishable from a budget
    that genuinely held. Spinning to a deadline removes the jitter without
    risking a permanent deadlock if a thread dies.

    The deadline is not optional decoration: at concurrency 128 on a 4-core box
    the waiters cannot all be scheduled at once, and without a bounded wait the
    generator would hang instead of producing a degraded-but-reported burst.
    """

    def __init__(self, parties: int, timeout: float) -> None:
        self._parties = max(1, parties)
        self._timeout = timeout
        self._arrived = 0
        self._open = False
        self._lock = threading.Lock()

    def wait(self) -> bool:
        """Block until all parties arrive. ``False`` if the deadline passed."""
        deadline = time.perf_counter() + self._timeout
        with self._lock:
            self._arrived += 1
            if self._arrived >= self._parties:
                self._open = True
        # Plain-attribute reads are atomic under the GIL, so the spin needs no
        # lock. sleep(0) yields the GIL rather than burning a core, which
        # matters because these threads are competing for it with each other.
        while not self._open:
            if time.perf_counter() >= deadline:
                return False
            time.sleep(0)
        return True


# ---------------------------------------------------------------------------
# Statistics
# ---------------------------------------------------------------------------


def _percentile(values: Sequence[float], pct: float) -> float:
    """Nearest-rank percentile of an already-sorted sequence.

    Nearest-rank rather than interpolated: every reported figure is then a
    measurement that actually occurred, which matters when the whole point is
    "a 429 that returns in 2 ms and a 200 that takes 900 ms are different
    failure modes". Interpolating between the two would invent a number no
    request experienced. Returns ``nan`` for an empty input.
    """
    if not values:
        return float("nan")
    rank = max(1, math.ceil((pct / 100.0) * len(values)))
    return values[min(rank, len(values)) - 1]


def _summarise(values: Sequence[float]) -> dict[str, float]:
    """p50/p95/p99/min/max/mean over unsorted samples, all in seconds."""
    if not values:
        nan = float("nan")
        return {
            "n": 0.0,
            "p50": nan,
            "p95": nan,
            "p99": nan,
            "min": nan,
            "max": nan,
            "mean": nan,
        }
    ordered = sorted(values)
    return {
        "n": float(len(ordered)),
        "p50": _percentile(ordered, 50.0),
        "p95": _percentile(ordered, 95.0),
        "p99": _percentile(ordered, 99.0),
        "min": ordered[0],
        "max": ordered[-1],
        "mean": sum(ordered) / len(ordered),
    }


def _fmt_ms(seconds: float) -> str:
    if math.isnan(seconds):
        return "     n/a"
    return "{0:7.2f}ms".format(seconds * 1000.0)


def _fmt_s(seconds: float) -> str:
    if math.isnan(seconds):
        return "n/a"
    return "{0:.4f}s".format(seconds)


def _peak_overlap(intervals: Sequence[tuple[float, float]]) -> int:
    """Maximum simultaneous occupancy over ``[start, end)`` intervals.

    Computed by a sweep rather than by sampling a live counter: it is exact,
    order-independent, and runs after every worker has joined, so it cannot be
    perturbed by the generator's own locking. Release is processed before
    acquire at an identical timestamp, so a request ending exactly as another
    starts is not counted as an overlap.
    """
    events: list[tuple[float, int]] = []
    for start, end in intervals:
        events.append((start, 1))
        events.append((end, -1))
    events.sort(key=lambda item: (item[0], item[1]))
    current = 0
    peak = 0
    for _, delta in events:
        current += delta
        if current > peak:
            peak = current
    return peak


# ---------------------------------------------------------------------------
# Payload
# ---------------------------------------------------------------------------


def _load_payload(explicit: Path | None) -> tuple[dict[str, Any], str, list[str]]:
    """Load a Contract A payload and strip its documentation keys.

    Returns ``(payload, source_description, stripped_keys)``.

    ``extra="forbid"`` on every model in ``agent/models.py`` means an unknown
    key is a 422, not a warning. ``sample-incident.json`` carries a ``_comment``
    key purely as documentation and is rejected by the schema because of it, so
    every key beginning with an underscore is dropped. That is a prefix rule
    rather than a single-name rule so the next documentation key added to a
    fixture does not silently become a 422.
    """
    candidates: tuple[Path | None, ...] = (
        (explicit,) if explicit is not None else _FIXTURES
    )
    last_error = "no fixture candidates"
    for candidate in candidates:
        if candidate is None or not candidate.is_file():
            last_error = "not a file: {0}".format(candidate)
            continue
        document = json.loads(candidate.read_text(encoding="utf-8"))
        if not isinstance(document, dict):
            last_error = "fixture is not a JSON object: {0}".format(candidate)
            continue
        stripped = [key for key in document if key.startswith("_")]
        payload = {k: v for k, v in document.items() if not k.startswith("_")}
        return payload, candidate.relative_to(_REPO_ROOT).as_posix(), stripped
    raise SystemExit(
        "FATAL: no usable Contract A fixture. Tried:\n  "
        + "\n  ".join(str(c) for c in candidates)
        + "\nlast error: "
        + last_error
        + "\nPass --fixture PATH to point at one."
    )


def _preflight_models(payload: dict[str, Any]) -> str | None:
    """Validate ``payload`` against the real ``agent.models.IncidentPayload``.

    Returns ``None`` when it validates, or a human-readable failure string.

    This is the check that makes the rest of the run mean something. Each
    constraint below is enforced by the model, and a load test that trips any of
    them measures 422s rather than load shedding:

    * ``incident_id`` must match ``^inc_[0-9A-HJKMNP-TV-Z]{20,}$`` - a
      Crockford base32 ULID body. Hex or a UUID is rejected, because Crockford
      omits ``I``, ``L``, ``O`` and ``U``.
    * ``reason`` is a closed enum: ``OOMKilled`` or ``CrashLoopBackOff``.
    * **I-A2**: ``reason=OOMKilled`` requires ``exit_code == 137`` *and* a
      non-null ``resource_limits.memory_limit``. A payload that satisfies every
      per-field constraint and violates this one still 422s, which is the trap
      - it looks well-formed field by field.
    * ``timestamp`` must be RFC3339 with an explicit UTC offset.

    ``models.py`` imports only ``re``/``datetime``/``enum``/``pydantic``, so this
    works with the agent's dependencies present and nothing else.
    """
    agent_dir = _REPO_ROOT / "agent"
    if not (agent_dir / "models.py").is_file():
        return "agent/models.py not found at {0}".format(agent_dir)
    inserted = str(agent_dir) not in sys.path
    if inserted:
        sys.path.insert(0, str(agent_dir))
    try:
        # No `type: ignore` here, and its absence is itself the finding.
        #
        # setup.cfg sets `mypy_path = agent`, so this import resolves at
        # *check* time exactly as the `sys.path` insertion above resolves it at
        # *run* time - the two agree by construction rather than by a suppression.
        # The first draft carried `# type: ignore[import-not-found]`, added
        # defensively because the import looks environment-dependent. Once the
        # file came under `mypy --strict`, `warn_unused_ignores` proved it
        # dead: a suppression that suppresses nothing is either obsolete or a
        # symptom, and neither is worth keeping in a script that runs against a
        # production-shaped service.
        from models import IncidentPayload

        IncidentPayload.model_validate(payload)
        return None
    except Exception as exc:  # noqa: BLE001 - any failure is a preflight failure
        return "{0}: {1}".format(type(exc).__name__, exc)
    finally:
        if inserted:
            try:
                sys.path.remove(str(agent_dir))
            except ValueError:  # pragma: no cover - another frame removed it
                pass


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Target:
    """A parsed endpoint plus the connection parameters derived from it."""

    url: str
    host: str
    port: int
    secure: bool
    path: str
    timeout: float

    @staticmethod
    def parse(url: str, timeout: float) -> Target:
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme not in ("http", "https"):
            raise SystemExit("FATAL: --url scheme must be http or https: " + url)
        if not parsed.hostname:
            raise SystemExit("FATAL: --url has no host: " + url)
        path = parsed.path or "/"
        if parsed.query:
            path = path + "?" + parsed.query
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        return Target(
            url=url,
            host=parsed.hostname,
            port=port,
            secure=parsed.scheme == "https",
            path=path,
            timeout=timeout,
        )

    def connect(
        self, context: ssl.SSLContext | None = None
    ) -> http.client.HTTPConnection:
        if self.secure:
            return http.client.HTTPSConnection(
                self.host, self.port, timeout=self.timeout, context=context
            )
        return http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)


def _origin(url: str) -> str:
    parsed = urllib.parse.urlsplit(url)
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    default = 443 if parsed.scheme == "https" else 80
    host = parsed.hostname or "127.0.0.1"
    authority = host if port == default else "{0}:{1}".format(host, port)
    return "{0}://{1}".format(parsed.scheme, authority)


def _request(
    conn: http.client.HTTPConnection,
    method: str,
    path: str,
    body: bytes | None,
    headers: dict[str, str],
) -> tuple[int, bytes]:
    """Issue one request and read the whole response. Raises on transport error.

    Deliberately not ``urllib.request``: that hides the status code behind an
    exception for every 4xx, and the body of a 429 - the entire payload under
    test - would then need a second mechanism to read.
    """
    conn.request(method, path, body=body, headers=headers)
    response = conn.getresponse()
    payload = response.read()
    return response.status, payload


def _short(text: bytes, limit: int = 200) -> str:
    return text[:limit].decode("utf-8", "replace")


def _classify(status: int, body: bytes) -> tuple[str, str]:
    """Map a status code to a sample kind, plus any contract complaint.

    A 429 whose body is not ``{"error": "sandbox_busy"}`` is not the behaviour
    under test, so the mismatch is recorded rather than counted as a clean shed.
    """
    if status == 200:
        return _KIND_ADMITTED, ""
    if status == 429:
        try:
            parsed = json.loads(body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return _KIND_SHED, "429 body is not JSON: " + _short(body, 80)
        if isinstance(parsed, dict) and parsed.get("error") == _EXPECTED_SHED_ERROR:
            return _KIND_SHED, ""
        seen = parsed.get("error") if isinstance(parsed, dict) else parsed
        return _KIND_SHED, "429 body error={0!r}, expected {1!r}".format(
            seen, _EXPECTED_SHED_ERROR
        )
    if status in (400, 422):
        return _KIND_CONTRACT, "body: " + _short(body)
    if status >= 500:
        return _KIND_SERVER_ERROR, "body: " + _short(body)
    return _KIND_UNEXPECTED, "status {0}, body: {1}".format(status, _short(body, 120))


# ---------------------------------------------------------------------------
# Probe prober
# ---------------------------------------------------------------------------


class _Prober:
    """Polls one health endpoint continuously for the whole load run.

    A single probe before the burst proves nothing about the burst. The claim
    under test is that the agent sheds triage work *while staying alive*, so the
    probe has to keep running across the saturation window and be analysed over
    that window specifically. Probes run on their own threads, never on a worker
    thread that is busy holding a slot open.

    Its own dedicated thread rather than the load executor: a worker blocked in
    a 3 s probe timeout must not consume one of the ``concurrency`` slots that
    the burst is trying to fill.
    """

    def __init__(
        self,
        name: str,
        url: str,
        timeout: float,
        interval: float,
        collector: Collector,
        context: ssl.SSLContext | None,
    ) -> None:
        self.name = name
        self.target = Target.parse(url, timeout)
        self.timeout = timeout
        self.interval = interval
        self.collector = collector
        self.context = context
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        # daemon=False: a leaked probe thread outlives the run and, because
        # Python joins non-daemon threads at interpreter exit, would hang CI.
        self._thread = threading.Thread(
            target=self._loop, name="probe-{0}".format(self.name), daemon=False
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=self.timeout * 2.0 + 5.0)

    def _record(
        self, ok: bool, recovered: bool, status: int | None, start: float, detail: str
    ) -> None:
        self.collector.add_probe(
            ProbeSample(
                endpoint=self.name,
                ok=ok,
                recovered=recovered,
                status=status,
                offset=start - _RUN_START[0],
                duration=time.perf_counter() - start,
                detail=detail,
            )
        )

    def _loop(self) -> None:
        try:
            conn = self.target.connect(self.context)
        except OSError as exc:
            now = time.perf_counter()
            self._record(False, False, None, now, "connect failed: {0}".format(exc))
            return
        try:
            while not self._stop.is_set():
                start = time.perf_counter()
                detail = ""
                recovered = False
                try:
                    status, _ = _request(
                        conn,
                        "GET",
                        self.target.path,
                        None,
                        {"Connection": "keep-alive"},
                    )
                    ok = status == 200
                    if not ok:
                        detail = "status {0}".format(status)
                except Exception as exc:  # noqa: BLE001 - a probe never raises
                    ok = False
                    detail = "{0}: {1}".format(type(exc).__name__, exc)
                    # A keep-alive connection the server closed is not a
                    # liveness failure. Distinguishing the two is the difference
                    # between "the agent died" and "the server recycled an idle
                    # socket", and conflating them either produces a false
                    # alarm or hides a real one.
                    try:
                        conn.close()
                    except OSError:
                        pass
                    try:
                        conn = self.target.connect(self.context)
                        status = None
                        ok = True
                        recovered = True
                        detail = "reconnected after " + detail
                    except OSError as exc2:
                        ok = False
                        detail = "reconnect failed: {0} (after {1})".format(
                            exc2, detail
                        )
                self._record(ok, recovered, status, start, detail)
                # wait(), not sleep(): shutdown must not wait out the interval.
                self._stop.wait(self.interval)
        finally:
            try:
                conn.close()
            except OSError:
                pass


# ---------------------------------------------------------------------------
# Load generation
# ---------------------------------------------------------------------------


def _sleep_until(deadline: float) -> None:
    """Sleep to an absolute ``perf_counter`` deadline.

    Absolute rather than relative so that scheduling jitter does not accumulate
    across requests: a paced run of 500 requests must offer 500/rate arrivals
    per second, not 500 arrivals each delayed by the previous one.
    """
    remaining = deadline - time.perf_counter()
    if remaining > 0:
        time.sleep(remaining)


def _worker(
    index: int,
    first_index: int,
    stride: int,
    count: int,
    target: Target,
    body: bytes,
    args: argparse.Namespace,
    go: threading.Event,
    barrier: _SpinBarrier | None,
    collector: Collector,
    context: ssl.SSLContext | None,
) -> None:
    """One connection, ``count`` requests, serialised on that connection.

    Serialised per connection deliberately: the connection is the unit of
    concurrency, so pipelining several requests down one socket would change
    what is being measured from N concurrent connections to N/keepalive.

    ``first_index``/``stride`` give each request a global ordinal. Paced mode
    needs it: if every worker scheduled off its own local index, all workers
    would fire at the same instants and the aggregate rate would be N x rate
    rather than rate.
    """
    conn = target.connect(context)
    headers = {
        "Content-Type": "application/json",
        "Content-Length": str(len(body)),
        "Accept": "application/json",
        "Connection": "keep-alive",
    }
    try:
        # Warm the connection before the burst. A cold TCP handshake is on the
        # order of a tenth of a millisecond on loopback and up to a millisecond
        # otherwise, which is the same order as the triage latency being
        # measured; leaving it in would put the handshake in front of the clock.
        try:
            _request(conn, "GET", "/healthz", None, {"Connection": "keep-alive"})
        except Exception:  # noqa: BLE001 - a failed warm-up is not fatal
            try:
                conn.close()
            except OSError:
                pass
            conn = target.connect(context)

        go.wait()
        if barrier is not None:
            barrier.wait()

        for step in range(count):
            if args.ramp == "staircase":
                _sleep_until(
                    _RUN_START[0] + (index // args.ramp_step) * args.ramp_delay
                )
            elif args.ramp == "paced":
                _sleep_until(_RUN_START[0] + (first_index + step * stride) / args.rate)

            start = time.perf_counter()
            status: int | None = None
            detail = ""
            try:
                status, payload = _request(conn, "POST", target.path, body, headers)
                kind, detail = _classify(status, payload)
            except Exception as exc:  # noqa: BLE001 - a transport failure is data
                kind = _KIND_TRANSPORT
                detail = "{0}: {1}".format(type(exc).__name__, exc)
                # One reconnect-and-retry on a reused connection. Without it, a
                # server that recycles idle keep-alive sockets reports a burst
                # of transport errors that have nothing to do with the budget.
                # Note this can mean the server saw the request twice; the
                # sample records only the retry's outcome.
                try:
                    conn.close()
                except OSError:
                    pass
                try:
                    conn = target.connect(context)
                    status, payload = _request(conn, "POST", target.path, body, headers)
                    kind, detail = _classify(status, payload)
                except Exception as exc2:  # noqa: BLE001
                    status = None
                    kind, detail = _KIND_TRANSPORT, "retry: {0}: {1}".format(
                        type(exc2).__name__, exc2
                    )
            collector.add_sample(
                Sample(
                    worker=index,
                    kind=kind,
                    status=status,
                    send_offset=start - _RUN_START[0],
                    recv_offset=time.perf_counter() - _RUN_START[0],
                    detail=detail,
                )
            )
    finally:
        try:
            conn.close()
        except OSError:
            pass


def _run_load(
    target: Target,
    body: bytes,
    args: argparse.Namespace,
    collector: Collector,
    context: ssl.SSLContext | None,
    on_ready: Any,
) -> int:
    """Drive the burst. Returns the number of connections actually used.

    All pacing lives inside the worker, against an absolute origin, so the
    ordering here is: submit every worker, establish the run origin, release.
    Doing the origin first would fold thread-spawn and connection-warm-up time
    into every offset and make "when did the 429s start" meaningless.
    """
    workers = max(1, min(args.concurrency, args.requests))
    base, remainder = divmod(args.requests, workers)
    counts = [base + (1 if i < remainder else 0) for i in range(workers)]
    active = [i for i, count in enumerate(counts) if count > 0]

    go = threading.Event()
    barrier = (
        _SpinBarrier(len(active), args.barrier_timeout)
        if args.ramp == "instant"
        else None
    )

    # Non-daemon threads, joined via the executor's context manager. A load
    # generator that leaves threads behind makes every subsequent local run
    # slower and eventually exhausts the process thread budget in CI.
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="load") as pool:
        futures: list[Future[None]] = [
            pool.submit(
                _worker,
                index,
                index,
                len(active),
                counts[index],
                target,
                body,
                args,
                go,
                barrier,
                collector,
                context,
            )
            for index in active
        ]
        on_ready()
        go.set()
        for future in futures:
            future.result()
    return len(active)


# ---------------------------------------------------------------------------
# Baseline control
# ---------------------------------------------------------------------------


def _baseline(
    target: Target, body: bytes, context: ssl.SSLContext | None
) -> str | None:
    """One lone request before any load. Returns a failure string, or ``None``.

    The control that gives the 429 its meaning. Without it, a run in which
    every request returns 422 is indistinguishable from a run in which the
    budget shed everything, and the report would claim saturation while having
    measured nothing at all. If this does not come back 200, the flood is
    pointless: the payload, the URL, or the agent is wrong.
    """
    conn = target.connect(context)
    try:
        start = time.perf_counter()
        status, payload = _request(
            conn,
            "POST",
            target.path,
            body,
            {
                "Content-Type": "application/json",
                "Content-Length": str(len(body)),
                "Accept": "application/json",
            },
        )
        elapsed = time.perf_counter() - start
    except Exception as exc:  # noqa: BLE001
        return "baseline request failed: {0}: {1}".format(type(exc).__name__, exc)
    finally:
        try:
            conn.close()
        except OSError:
            pass

    if status == 429:
        return (
            "baseline returned 429 before any load was applied - the budget is "
            "already saturated by something else. Point at an idle agent, or "
            "accept that this run cannot distinguish shedding from noise."
        )
    if status != 200:
        return "baseline returned {0}, expected 200: {1}".format(
            status, _short(payload, 400)
        )
    print(
        "  baseline control   200 in {0}  (payload accepted, endpoint healthy)".format(
            _fmt_ms(elapsed)
        )
    )
    return None


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------


@dataclass
class Analysis:
    duration: float
    total: int
    by_kind: dict[str, int]
    by_status: dict[int, int]
    admitted: list[Sample]
    shed: list[Sample]
    contract: list[Sample]
    server_error: list[Sample]
    transport: list[Sample]
    unexpected: list[Sample]
    shed_envelope_mismatches: list[Sample]
    first_shed_offset: float | None
    last_shed_offset: float | None
    admitted_inflight_at_first_shed: int
    outstanding_at_first_shed: int
    admitted_peak_inflight: int
    shed_ratio: float
    probes: list[ProbeSample]
    probe_failures: list[ProbeSample]
    probe_recoveries: list[ProbeSample]


def _analyse(samples: Sequence[Sample], probes: Sequence[ProbeSample]) -> Analysis:
    ordered = sorted(samples, key=lambda s: s.recv_offset)
    admitted = [s for s in ordered if s.kind == _KIND_ADMITTED]
    shed = [s for s in ordered if s.kind == _KIND_SHED]
    contract = [s for s in ordered if s.kind == _KIND_CONTRACT]
    server_error = [s for s in ordered if s.kind == _KIND_SERVER_ERROR]
    transport = [s for s in ordered if s.kind == _KIND_TRANSPORT]
    unexpected = [s for s in ordered if s.kind == _KIND_UNEXPECTED]

    first_shed = shed[0].recv_offset if shed else None
    last_shed = shed[-1].recv_offset if shed else None

    # The two observations that bracket the effective budget, both computed
    # exactly from recorded intervals rather than sampled from live counters.
    #
    # The server holds a slot for the whole handler, so server-side occupancy is
    # a subset of client-observed overlap. That makes the sweep below an UPPER
    # bound on the true peak, and the admitted-only count at first shed a LOWER
    # bound. The two together bracket it.
    #
    # The counts differ deliberately. ``admitted_inflight`` counts only requests
    # that ultimately returned 200; ``outstanding`` counts every request still
    # open at that instant, including the first 429 itself and any sibling 429s
    # still in flight. The gap between them is the size of the shed burst that
    # was itself still in flight, which is a direct measure of how fast refusal
    # is compared to admission.
    admitted_at_first_shed = 0
    outstanding_at_first_shed = 0
    if first_shed is not None:
        open_admitted = 0
        open_any = 0
        for sample in ordered:
            if sample.send_offset < first_shed < sample.recv_offset:
                open_any += 1
                if sample.kind == _KIND_ADMITTED:
                    open_admitted += 1
        admitted_at_first_shed = open_admitted
        outstanding_at_first_shed = open_any

    peak = _peak_overlap([(s.send_offset, s.recv_offset) for s in admitted])

    by_kind: dict[str, int] = {}
    by_status: dict[int, int] = {}
    for sample in ordered:
        by_kind[sample.kind] = by_kind.get(sample.kind, 0) + 1
        if sample.status is not None:
            by_status[sample.status] = by_status.get(sample.status, 0) + 1

    return Analysis(
        duration=ordered[-1].recv_offset if ordered else 0.0,
        total=len(ordered),
        by_kind=by_kind,
        by_status=by_status,
        admitted=admitted,
        shed=shed,
        contract=contract,
        server_error=server_error,
        transport=transport,
        unexpected=unexpected,
        shed_envelope_mismatches=[s for s in shed if s.detail],
        first_shed_offset=first_shed,
        last_shed_offset=last_shed,
        admitted_inflight_at_first_shed=admitted_at_first_shed,
        outstanding_at_first_shed=outstanding_at_first_shed,
        admitted_peak_inflight=peak,
        shed_ratio=(len(shed) / len(ordered)) if ordered else 0.0,
        probes=list(probes),
        probe_failures=[p for p in probes if not p.ok],
        probe_recoveries=[p for p in probes if p.recovered],
    )


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------


def _print_latency_row(title: str, samples: Sequence[Sample], total: int) -> None:
    stats = _summarise([s.duration for s in samples])
    share = (len(samples) / total * 100.0) if total else 0.0
    print(
        "  {0:<26} {1:>5}  ({2:>6.1f}%)  p50 {3}  p95 {4}  p99 {5}  max {6}".format(
            title,
            len(samples),
            share,
            _fmt_ms(stats["p50"]),
            _fmt_ms(stats["p95"]),
            _fmt_ms(stats["p99"]),
            _fmt_ms(stats["max"]),
        )
    )


def _print_probe_section(
    analysis: Analysis, window: tuple[float, float] | None
) -> None:
    print("")
    print("  HEALTH PROBES")
    if not analysis.probes:
        print("    (no probe samples recorded - the probers never connected)")
        return
    for endpoint in ("healthz", "readyz"):
        probes = [p for p in analysis.probes if p.endpoint == endpoint]
        failures = [p for p in probes if not p.ok]
        recoveries = [p for p in probes if p.recovered]
        stats = _summarise([p.duration for p in probes])
        print(
            "    /{0:<9} {1:>4}/{2:<4} ok   p50 {3}  p95 {4}  p99 {5}  max {6}".format(
                endpoint,
                len(probes) - len(failures),
                len(probes),
                _fmt_ms(stats["p50"]),
                _fmt_ms(stats["p95"]),
                _fmt_ms(stats["p99"]),
                _fmt_ms(stats["max"]),
            )
        )
        if recoveries:
            print(
                "      {0} socket recycle(s) recovered by reconnect - not counted"
                " as failures".format(len(recoveries))
            )
        for failure in failures[:5]:
            print(
                "      FAIL at +{0}: {1}".format(
                    _fmt_s(failure.offset), failure.detail or "non-200"
                )
            )
        if window is not None:
            low, high = window
            during = [p for p in probes if low <= p.offset <= high]
            during_failures = [p for p in during if not p.ok]
            during_stats = _summarise([p.duration for p in during])
            print(
                "      during shedding window (+{0} .. +{1}): {2} probe(s), "
                "{3} failed, p99 {4}, max {5}".format(
                    _fmt_s(low),
                    _fmt_s(high),
                    len(during),
                    len(during_failures),
                    _fmt_ms(during_stats["p99"]),
                    _fmt_ms(during_stats["max"]),
                )
            )


def _print_saturation(analysis: Analysis, args: argparse.Namespace) -> None:
    print("")
    print("  SATURATION")
    if analysis.first_shed_offset is None:
        print("    first 429                       NEVER")
        print("")
        print("    !! NO 429 WAS OBSERVED. THE BUDGET WAS NOT EXERCISED. !!")
        print("       This run is a failure, not a pass. Likely causes, in order:")
        print(
            "         1. concurrency ({0}) is not above the budget ({1}).".format(
                args.concurrency, args.budget
            )
        )
        print("         2. triage finished before the burst reached the handler.")
        print("            The default agent is sandbox-off and triage is")
        print("            sub-millisecond, so this is a genuine race, not a bug.")
        print("            Re-run with the target started as SREK3S_SANDBOX=1, or")
        print("            with a higher --concurrency.")
        print("         3. the target is behind a Service with replicas > 1, so")
        print("            requests spread over pods and the effective budget is")
        print("            N x {0}.".format(args.budget))
        print("         4. the URL is a non-triage route that happens not to 404.")
        return

    print(
        "    first 429                     +{0} after load release".format(
            _fmt_s(analysis.first_shed_offset)
        )
    )
    print(
        "    last 429                      +{0}".format(
            _fmt_s(
                analysis.last_shed_offset
                if analysis.last_shed_offset is not None
                else float("nan")
            )
        )
    )
    accepted_before = sum(
        1 for s in analysis.admitted if s.recv_offset < analysis.first_shed_offset
    )
    print("    200s completed before it      {0}".format(accepted_before))
    print(
        "    admitted in flight at that instant  {0}   (LOWER bound on peak)".format(
            analysis.admitted_inflight_at_first_shed
        )
    )
    print(
        "    all requests open at that instant  {0}   (includes the shed burst)".format(
            analysis.outstanding_at_first_shed
        )
    )
    print(
        "    client-observed admitted peak       {0}   (UPPER bound on peak)".format(
            analysis.admitted_peak_inflight
        )
    )
    print(
        "    => effective budget bracketed to     [{0}, {1}]   configured: {2}".format(
            analysis.admitted_inflight_at_first_shed,
            analysis.admitted_peak_inflight,
            args.budget,
        )
    )
    if analysis.admitted_peak_inflight <= args.budget:
        print("       Consistent with the configured budget: the cap held. Never more")
        print(
            "       than {0} admitted requests were in flight at any instant.".format(
                args.budget
            )
        )
    else:
        print(
            "       WARNING: observed overlap ({0}) exceeds the configured budget"
            " ({1}).".format(analysis.admitted_peak_inflight, args.budget)
        )
        print("       Client-side overlap is a SUPERSET of server-side slot occupancy")
        print("       - the socket is open before the handler acquires - so this is")
        print("       not by itself proof of overshoot. The authoritative number is")
        print("       budget.peak on the server, which this script cannot observe.")
    print(
        "    shedding ratio                {0:.1f}%".format(analysis.shed_ratio * 100.0)
    )
    if analysis.shed_envelope_mismatches:
        print(
            "    !! {0} of the 429 bodies were NOT {{'error': '{1}'}}".format(
                len(analysis.shed_envelope_mismatches), _EXPECTED_SHED_ERROR
            )
        )
        for sample in analysis.shed_envelope_mismatches[:3]:
            print("       " + sample.detail)


def _print_histogram(analysis: Analysis, args: argparse.Namespace) -> None:
    if not analysis.shed:
        return
    buckets = max(1, args.buckets)
    span = max(analysis.duration, 1e-9)
    width = span / buckets
    counts = [0] * buckets
    for sample in analysis.shed:
        index = int(sample.recv_offset / width)
        counts[min(max(index, 0), buckets - 1)] += 1
    peak = max(counts) or 1
    print("")
    print(
        "  429 ARRIVALS OVER TIME  (run {0}, {1} buckets)".format(
            _fmt_s(analysis.duration), buckets
        )
    )
    for index, count in enumerate(counts):
        bar = "#" * int(round(count / peak * 40.0))
        print(
            "    +{0:>7} .. +{1:<7} {2:>4}  {3}".format(
                _fmt_s(index * width), _fmt_s((index + 1) * width), count, bar
            )
        )


def _ramp_description(args: argparse.Namespace) -> str:
    if args.ramp == "staircase":
        return "staircase (waves of {0}, {1}ms apart)".format(
            args.ramp_step, int(args.ramp_delay * 1000)
        )
    if args.ramp == "paced":
        return "paced (open-loop, {0} req/s aggregate)".format(args.rate)
    return "instant (barrier-synchronised burst)"


def _print_report(
    analysis: Analysis, args: argparse.Namespace, source: str, connections: int
) -> None:
    total = analysis.total
    admitted_stats = _summarise([s.duration for s in analysis.admitted])
    shed_stats = _summarise([s.duration for s in analysis.shed])
    rate = (total / analysis.duration) if analysis.duration > 0 else float("nan")

    print("")
    print("=" * 78)
    print(" SREK3S TRIAGE AGENT - LOAD / LOAD-SHEDDING REPORT")
    print("=" * 78)
    print("  target               {0}".format(args.url))
    print("  connections          {0} threads".format(connections))
    print("  requests offered     {0}".format(args.requests))
    print("  ramp                 {0}".format(_ramp_description(args)))
    print("  expected budget      {0}   (SREK3S_MAX_ACTIVE_JOBS)".format(args.budget))
    print("  payload              {0}".format(source))
    print("  run duration         {0}".format(_fmt_s(analysis.duration)))
    print("  offered throughput   {0:.1f} req/s".format(rate))

    print("")
    print("  STATUS BREAKDOWN")
    if not analysis.by_status:
        print("    (no responses completed)")
    for status in sorted(analysis.by_status):
        count = analysis.by_status[status]
        share = (count / total * 100.0) if total else 0.0
        print("    HTTP {0:<4} {1:>5}  ({2:>6.1f}%)".format(status, count, share))
    print(
        "    by kind: "
        + ", ".join(
            "{0}={1}".format(kind, count)
            for kind, count in sorted(analysis.by_kind.items())
        )
    )

    print("")
    print("  LATENCY - ACCEPTED AND REJECTED REPORTED SEPARATELY")
    print("  {0:<26} {1:>5}  {2:>8}  {3}".format("class", "count", "share", "latency"))
    _print_latency_row("200 accepted (in slot)", analysis.admitted, total)
    _print_latency_row("429 shed (out of slot)", analysis.shed, total)
    if analysis.contract:
        _print_latency_row("4xx contract violation", analysis.contract, total)
    if analysis.server_error:
        _print_latency_row("5xx server error", analysis.server_error, total)
    if analysis.transport:
        _print_latency_row("transport failure", analysis.transport, total)
    if analysis.unexpected:
        _print_latency_row("unexpected status", analysis.unexpected, total)

    shed_mean = shed_stats["mean"]
    if analysis.admitted and shed_mean > 0:
        ratio = admitted_stats["mean"] / shed_mean
        print("")
        print(
            "    Accepted mean {0} vs shed mean {1} = {2:.1f}x. A refusal that"
            " costs".format(_fmt_ms(admitted_stats["mean"]), _fmt_ms(shed_mean), ratio)
        )
        print("    about as much as the work it refuses is the point of refusing")
        print("    rather than queueing: budget.py turns overload into a visible")
        print("    429 instead of into latency on the path to time-to-mitigation.")

    _print_saturation(analysis, args)
    _print_histogram(analysis, args)

    window: tuple[float, float] | None = None
    if analysis.first_shed_offset is not None:
        high = analysis.last_shed_offset
        window = (
            analysis.first_shed_offset,
            high if high is not None else analysis.first_shed_offset,
        )
    _print_probe_section(analysis, window)
    print("")


# ---------------------------------------------------------------------------
# Verdict
# ---------------------------------------------------------------------------


def _verdict(analysis: Analysis, args: argparse.Namespace) -> int:
    """Decide the exit code. Ordered, and every branch explains itself."""
    print("=" * 78)
    print(" VERDICT")
    print("=" * 78)

    if analysis.contract:
        print(
            "  FAIL [{0}] contract violation: {1} request(s) got 400/422.".format(
                EXIT_CONTRACT_VIOLATION, len(analysis.contract)
            )
        )
        print("        The body did not satisfy IncidentPayload, so this run")
        print("        measured schema validation, not load shedding. Void.")
        for sample in analysis.contract[:3]:
            print("        " + sample.detail[:300])
        return EXIT_CONTRACT_VIOLATION

    if analysis.transport or analysis.server_error:
        print(
            "  FAIL [{0}] {1} transport failure(s), {2} 5xx response(s).".format(
                EXIT_TRANSPORT_FAILED,
                len(analysis.transport),
                len(analysis.server_error),
            )
        )
        print("        The run did not cleanly exercise shedding.")
        for sample in (analysis.transport + analysis.server_error)[:3]:
            print("        " + sample.detail[:300])
        return EXIT_TRANSPORT_FAILED

    if not analysis.shed:
        print(
            "  FAIL [{0}] SATURATION NOT ACHIEVED - zero 429 responses.".format(
                EXIT_NOT_SATURATED
            )
        )
        print("        A load test that never triggers the guard it exists to")
        print("        test has proven nothing. See the SATURATION section above")
        print("        for the four likely causes; the commonest is triage being")
        print("        faster than the burst, fixed by running the target with")
        print("        SREK3S_SANDBOX=1.")
        return EXIT_NOT_SATURATED

    if analysis.shed_envelope_mismatches:
        print(
            "  FAIL [{0}] {1} 429(s) did not carry the '{2}' envelope.".format(
                EXIT_CONTRACT_VIOLATION,
                len(analysis.shed_envelope_mismatches),
                _EXPECTED_SHED_ERROR,
            )
        )
        print("        The status code is right and the envelope is wrong, which is")
        print("        still contract drift against ARCHITECTURE.md §4.3.")
        for sample in analysis.shed_envelope_mismatches[:3]:
            print("        " + sample.detail[:300])
        return EXIT_CONTRACT_VIOLATION

    print(
        "  PASS [{0}] {1} of {2} requests shed ({3:.1f}%) with the '{4}'"
        " envelope.".format(
            EXIT_OK,
            len(analysis.shed),
            analysis.total,
            analysis.shed_ratio * 100.0,
            _EXPECTED_SHED_ERROR,
        )
    )
    print(
        "       Effective budget bracketed to [{0}, {1}]; configured {2}.".format(
            analysis.admitted_inflight_at_first_shed,
            analysis.admitted_peak_inflight,
            args.budget,
        )
    )

    if analysis.probe_failures:
        if args.allow_probe_failures:
            print(
                "  WARN  {0} health probe failure(s), tolerated by"
                " --allow-probe-failures.".format(len(analysis.probe_failures))
            )
            return EXIT_OK
        print(
            "  FAIL [{0}] {1} health probe failure(s) during the run.".format(
                EXIT_PROBE_FAILED, len(analysis.probe_failures)
            )
        )
        print("        Shedding triage work while losing liveness is not load")
        print("        shedding, it is a crash loop with extra steps: the kubelet")
        print("        would restart a pod that was behaving correctly. AGENTS.md")
        print("        §3.1 exists for exactly this.")
        return EXIT_PROBE_FAILED

    print("       Liveness and readiness held throughout, including the saturation")
    print("       window. The budget did its job and the process stayed alive to")
    print("       keep serving.")
    return EXIT_OK


def _emit_json(
    analysis: Analysis, args: argparse.Namespace, path: Path, code: int
) -> None:
    payload = {
        "target": args.url,
        "concurrency": args.concurrency,
        "connections_used": args.concurrency,
        "requests": args.requests,
        "ramp": args.ramp,
        "expected_budget": args.budget,
        "duration_s": analysis.duration,
        "total": analysis.total,
        "by_kind": analysis.by_kind,
        "by_status": {str(k): v for k, v in analysis.by_status.items()},
        "shed_ratio": analysis.shed_ratio,
        "first_429_offset_s": analysis.first_shed_offset,
        "last_429_offset_s": analysis.last_shed_offset,
        "admitted_inflight_at_first_429": analysis.admitted_inflight_at_first_shed,
        "outstanding_at_first_429": analysis.outstanding_at_first_shed,
        "admitted_peak_inflight": analysis.admitted_peak_inflight,
        "shed_envelope_mismatches": len(analysis.shed_envelope_mismatches),
        "latency_s": {
            "admitted": _summarise([s.duration for s in analysis.admitted]),
            "shed": _summarise([s.duration for s in analysis.shed]),
        },
        "probes": {
            endpoint: {
                "total": len([p for p in analysis.probes if p.endpoint == endpoint]),
                "failed": len(
                    [p for p in analysis.probes if p.endpoint == endpoint and not p.ok]
                ),
                "recovered": len(
                    [
                        p
                        for p in analysis.probes
                        if p.endpoint == endpoint and p.recovered
                    ]
                ),
                "latency_s": _summarise(
                    [p.duration for p in analysis.probes if p.endpoint == endpoint]
                ),
            }
            for endpoint in ("healthz", "readyz")
        },
        "probe_failures": [
            {"endpoint": p.endpoint, "offset_s": p.offset, "detail": p.detail}
            for p in analysis.probe_failures
        ],
        "exit_code": code,
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    print("  machine-readable report written to {0}".format(path))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    origin = "http://127.0.0.1:8000"
    parser = argparse.ArgumentParser(
        prog="load_python_agent.py",
        description=(
            "Saturate the SREK3S triage agent's active-job budget and prove it "
            "sheds with 429 sandbox_busy while staying alive."
        ),
        epilog=(
            "OPERATIONAL NOTES\n"
            "  * Point --url at ONE POD, not the ClusterIP Service.\n"
            "    deploy/agent.yaml runs replicas: 2 and each pod has its own\n"
            "    budget, so a Service gives you an effective budget of N x\n"
            "    --budget and roughly halves the shedding rate.\n"
            "  * That manifest's NetworkPolicy allows ingress only from the\n"
            "    srek3s-sentinel pod. From anywhere else you get connection\n"
            "    refused, which this script reports as a transport failure.\n"
            "  * If no 429 appears, re-run with the agent started as\n"
            "    SREK3S_SANDBOX=1. Sandbox-off triage is sub-millisecond, so a\n"
            "    budget of 4 can genuinely fail to overlap. That is a real\n"
            "    result and this script exits 3 on it rather than reporting a\n"
            "    pass.\n"
            "\n"
            "EXIT CODES\n"
            "  0 saturated and probes held    1 usage / interrupted\n"
            "  2 preflight control failed     3 NOT SATURATED (zero 429s)\n"
            "  4 contract violation (4xx or bad 429 envelope)\n"
            "  5 health probe failed          6 transport error or 5xx\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--url",
        default=origin + "/api/v1/triage",
        help="triage endpoint (default: %(default)s)",
    )
    parser.add_argument("--healthz-url", default=None, help="default: <origin>/healthz")
    parser.add_argument("--readyz-url", default=None, help="default: <origin>/readyz")
    parser.add_argument(
        "-c",
        "--concurrency",
        type=int,
        default=32,
        help="concurrent connections / worker threads (default: %(default)s)",
    )
    parser.add_argument(
        "-n",
        "--requests",
        type=int,
        default=256,
        help="total requests to offer (default: %(default)s)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="per-request socket timeout, seconds (default: %(default)s)",
    )
    parser.add_argument(
        "--ramp",
        choices=("instant", "staircase", "paced"),
        default="instant",
        help="arrival pattern (default: %(default)s)",
    )
    parser.add_argument(
        "--ramp-step",
        type=int,
        default=8,
        help="staircase: workers released per wave (default: %(default)s)",
    )
    parser.add_argument(
        "--ramp-delay",
        type=float,
        default=0.05,
        help="staircase: seconds between waves (default: %(default)s)",
    )
    parser.add_argument(
        "--rate",
        type=float,
        default=50.0,
        help="paced: aggregate arrivals per second (default: %(default)s)",
    )
    parser.add_argument(
        "--budget",
        type=int,
        default=4,
        help="expected SREK3S_MAX_ACTIVE_JOBS, for comparison (default: %(default)s)",
    )
    parser.add_argument(
        "--probe-interval",
        type=float,
        default=0.05,
        help="seconds between health probes (default: %(default)s)",
    )
    parser.add_argument(
        "--probe-timeout",
        type=float,
        default=3.0,
        help="health probe socket timeout (default: %(default)s)",
    )
    parser.add_argument(
        "--barrier-timeout",
        type=float,
        default=2.0,
        help="burst barrier deadline, seconds (default: %(default)s)",
    )
    parser.add_argument(
        "--buckets",
        type=int,
        default=20,
        help="histogram buckets for 429 arrivals (default: %(default)s)",
    )
    parser.add_argument(
        "--fixture",
        type=Path,
        default=None,
        help="explicit Contract A payload JSON (default: tests/fixtures/*.json)",
    )
    parser.add_argument("--insecure", action="store_true", help="skip TLS verification")
    parser.add_argument(
        "--skip-preflight",
        action="store_true",
        help="do not validate the payload against agent/models.py",
    )
    parser.add_argument(
        "--allow-probe-failures",
        action="store_true",
        help="downgrade health probe failures to a warning",
    )
    parser.add_argument(
        "--json-out", type=Path, default=None, help="write the report as JSON"
    )
    return parser


def _validate_args(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    if args.requests < 1:
        parser.error("--requests must be >= 1")
    if args.concurrency < 1:
        parser.error("--concurrency must be >= 1")
    if args.timeout <= 0:
        parser.error("--timeout must be > 0")
    if args.probe_interval <= 0:
        parser.error("--probe-interval must be > 0")
    if args.probe_timeout <= 0:
        parser.error("--probe-timeout must be > 0")
    if args.barrier_timeout <= 0:
        parser.error("--barrier-timeout must be > 0")
    if args.buckets < 1:
        parser.error("--buckets must be >= 1")
    if args.budget < 1:
        parser.error("--budget must be >= 1")
    if args.ramp == "paced" and args.rate <= 0:
        parser.error("--rate must be > 0")
    if args.ramp == "staircase" and args.ramp_step < 1:
        parser.error("--ramp-step must be >= 1")
    if args.ramp == "staircase" and args.ramp_delay < 0:
        parser.error("--ramp-delay must be >= 0")


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    _validate_args(parser, args)

    print("=" * 78)
    print(" SREK3S TRIAGE AGENT - LOAD GENERATOR")
    print("=" * 78)

    # -- Payload, and the preflight that makes the numbers mean something ---
    payload, source, stripped = _load_payload(args.fixture)
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    print("  payload source     {0}".format(source))
    if stripped:
        print(
            "  stripped keys      {0}   (extra=forbid would 422 on these)".format(
                ", ".join(sorted(stripped))
            )
        )
    print("  payload size       {0} bytes".format(len(body)))
    if args.skip_preflight:
        print("  schema preflight   SKIPPED (--skip-preflight)")
    else:
        failure = _preflight_models(payload)
        if failure is not None:
            print("")
            print(
                "  FAIL [{0}] payload does not satisfy IncidentPayload:".format(
                    EXIT_CONTROL_FAILED
                )
            )
            print("        " + failure)
            print("        Fix the payload before load testing; a flood of 422s")
            print("        measures schema validation, not the job budget.")
            return EXIT_CONTROL_FAILED
        print("  schema preflight   OK (validated against agent/models.py)")

    context: ssl.SSLContext | None = None
    if args.url.startswith("https://"):
        context = ssl.create_default_context()
        if args.insecure:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

    target = Target.parse(args.url, args.timeout)
    base = _origin(args.url)
    healthz_url = args.healthz_url or (base + "/healthz")
    readyz_url = args.readyz_url or (base + "/readyz")

    # -- Baseline control: one request, no load ----------------------------
    control = _baseline(target, body, context)
    if control is not None:
        print("")
        print("  FAIL [{0}] baseline control failed:".format(EXIT_CONTROL_FAILED))
        print("        " + control)
        return EXIT_CONTROL_FAILED

    collector = Collector()
    probers = [
        _Prober(
            "healthz",
            healthz_url,
            args.probe_timeout,
            args.probe_interval,
            collector,
            context,
        ),
        _Prober(
            "readyz",
            readyz_url,
            args.probe_timeout,
            args.probe_interval,
            collector,
            context,
        ),
    ]

    def on_ready() -> None:
        """Establish the run origin and start probing, immediately pre-release.

        The origin has to be set here rather than in ``main``: by this point all
        worker threads exist, have connected and have warmed their sockets, so
        the offsets measure the burst and not the generator's own startup. If it
        were set earlier, "first 429 at +3 ms" would really mean "first 429
        three milliseconds after we finished spawning threads".
        """
        _RUN_START[0] = time.perf_counter()
        for prober in probers:
            prober.start()

    try:
        connections = _run_load(target, body, args, collector, context, on_ready)
    except KeyboardInterrupt:
        print("")
        print("  interrupted; tearing down workers")
        for prober in probers:
            prober.stop()
        return EXIT_USAGE
    finally:
        for prober in probers:
            prober.stop()

    analysis = _analyse(collector.samples, collector.probes)
    _print_report(analysis, args, source, connections)
    code = _verdict(analysis, args)
    print("")
    print("  exit code {0}".format(code))
    print("=" * 78)

    if args.json_out is not None:
        _emit_json(analysis, args, args.json_out, code)
    return code


if __name__ == "__main__":
    sys.exit(main())
