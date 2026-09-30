"""ROADMAP 4.3.4 - the post-remediation loop against a real cluster.

`agent/tests/test_verify.py` proves the loop's *logic*: routing, the requeue
bound, the zero-writes property. What it cannot prove is that the loop reaches
the right verdict when the thing it observes is a real kubelet, a real cgroup OOM
killer and a real GitOps sync. That is this file.

## Why the reader lives here and not in `verify.py`

`verify.py` holds exactly one capability, `ObservationReader.read`, and holds no
Kubernetes client, no subprocess and no socket - that is ROADMAP 4.3.5, and it
is asserted twice over in `test_verify.py` (AST introspection plus a real
`s.addaudithook` around a live run). Supplying a reader from outside preserves
that: the cluster credential stays in the *harness*, and the engine that
evaluates the policy never acquires a way to use one. A reader placed inside
`verify.py` would satisfy neither the letter nor the spirit of 4.3.5.

The reader is read-only by construction, and that is a claim worth checking
rather than asserting: every argv it issues is recorded, and
`test_the_reader_only_ever_issues_read_verbs` asserts the recorded set contains
no mutating verb. That test is the 4.3.5 guarantee extended across the module
boundary - `verify.py` cannot write, and the thing that hands it observations
cannot write either.

## Why a separate namespace and a separate fixture

Two ratified things are being kept out of a live run's way, and both would be
damaged by sharing `sentinel-chaos`.

**The namespace.** ROADMAP 4.2.8 asserts that nothing outside the chaos
namespace changes during a detonation, and it *counts* the objects that do
change inside it - 8 created, in the ratified run. Adding a Deployment here
would add a Deployment, a ReplicaSet and a Pod to that namespace, changing a
number a ratified invariant reports. So this file owns
:data:`VERIFY_NAMESPACE`, creates it if absent, and deletes it in teardown. The
count that 4.2.8 depends on is therefore untouched, and a failure here cannot
masquerade as a 4.2.8 regression.

**The fixture.** `deploy/chaos/oom-leak.yaml` cannot verify a remediation,
because its demand is unbounded: its allocation loop doubles 1 MiB thirty-two
times to 4 GiB, so the container is killed wherever the limit sits - iteration
6 against 64Mi, iteration 7 against 128Mi, sub-second either way. A memory-limit
increase delays that kill by one iteration; it does not prevent it. Its own
epilogue says so.

`tests/fixtures/bounded-leak.yaml` encodes the property a memory remediation
actually has: demand falls *strictly between* old and new limit. 90 MiB against
64Mi is OOMKilled on boot; against 128Mi it survives and idles long enough to
accumulate the uptime the success criterion demands. The band is deliberately
not wedged against either limit - 26 MiB clear of the old one, 38 MiB of slack
under the new - so the test cannot pass for the wrong reason on a node with a
slightly different baseline.

## What runs where

The parsing, routing and read-only guarantees are exercised **offline**, against
a stubbed `kubectl`, and are part of the normal `pytest agent/tests/` run. Only
the two live round-trips need a cluster, and they skip when there is not one -
loudly, because a skip that reads as a pass is the failure mode
`docs/lessons-learned.md` §1 is about.
"""

from __future__ import annotations

import ast
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Final

import pytest
import yaml
from pydantic import ValidationError

_ROOT: Final[Path] = Path(__file__).resolve().parents[2]
_E2E_DIR: Final[Path] = _ROOT / "tests" / "e2e"
_AGENT_DIR: Final[Path] = _ROOT / "agent"
for _p in (_E2E_DIR, _AGENT_DIR):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from models import SuccessCriteria, VerificationPolicy  # noqa: E402
from verify import (  # noqa: E402
    ContainerObservation,
    ContainerTarget,
    RequeueBudget,
    UnresolvedCause,
    VerdictKind,
    verify_incident,
)

# ---------------------------------------------------------------------------
# Cluster coordinates
# ---------------------------------------------------------------------------

#: Isolated from `sentinel-chaos` on purpose. ROADMAP 4.2.8 counts the objects
#: created inside the chaos namespace, so a fixture landed there would change a
#: number a ratified invariant reports. See the module docstring.
VERIFY_NAMESPACE: Final[str] = "srek3s-verify-chaos"

#: The Deployment the Tier-1 diff targets.
DEPLOYMENT: Final[str] = "srek3s-verify-bounded"

#: The container whose memory limit the diff changes.
CONTAINER: Final[str] = "bounded-canary"

#: The label the bounded fixture carries.
#:
#: Distinct from the M4.2 `oom` value on purpose: the e2e runner selects chaos
#: pods by `srek3s.io/chaos=oom`, and a workload that is *supposed* to stay
#: healthy must not land inside Milestone 4.2's detection ratio.
SELECTOR: Final[str] = "srek3s.io/chaos=bounded-oom"

#: The bounded fixture. Not `deploy/chaos/oom-leak.yaml` - see the docstring.
TARGET_MANIFEST: Final[Path] = _ROOT / "tests" / "fixtures" / "bounded-leak.yaml"

#: The namespace manifest, created and deleted by the live path.
NAMESPACE_MANIFEST: Final[Path] = _ROOT / "deploy" / "chaos" / "namespace.yaml"

#: What a Tier-1 memory remediation changes. Matches the offline gate's shape.
FROM_LIMIT: Final[str] = "64Mi"
TO_LIMIT: Final[str] = "128Mi"

#: The fixture's fixed payload, in bytes: 52 MiB.
#:
#: The quantity that must sit between the two limits is the container's *peak*
#: RSS, not this payload, and the difference is not academic. CI run 36786601947
#: recorded a 90 MiB payload OOMKilled under a 128 MiB limit, so the peak exceeds
#: 128 MiB for a 90 MiB payload - command substitution buffers the whole result
#: before the shell can assign it, and the realloc growth puts the old and new
#: buffers live simultaneously. A fixture sized on the payload alone is sized on
#: the wrong quantity, and that is exactly how the 90 MiB version failed.
BOUNDED_PAYLOAD_BYTES: Final[int] = 54_525_952

#: The plausible range of peak-to-payload multiples, bracketed by what the
#: cluster actually showed: a 90 MiB payload exceeded 128 MiB, so the multiple is
#: above 1.42. 2.0 is the pessimistic end - the transient during realloc growth
#: where the old and new buffers are both live.
#:
#: A range rather than a single figure, because the exact multiple is a property
#: of busybox `ash`'s allocator and is not measured here. What *is* measured is
#: that 52 MiB behaves correctly across the whole range, which is the property
#: that makes the fixture mean the same thing on any machine.
PEAK_MULTIPLE_MIN: Final[float] = 1.45
PEAK_MULTIPLE_MAX: Final[float] = 2.0

#: ARCH 5.2 floors the window at 60s. A test that passed against a window the
#: spec forbids would mean nothing, so the floor is used verbatim.
WATCH_SECONDS: Final[int] = 60

#: Uptime the remediated container must exceed for the verdict to be VERIFIED.
#:
#: Comfortably above the fixture's 5s settle plus one allocation pass, and well
#: below the window, so a healthy container clears it while a failing one never
#: gets the chance. If this were below ~10s the loop could return VERIFIED
#: against a container that had not finished allocating, which is a closure
#: verdict resting on a half-booted workload.
UPTIME_MIN: Final[int] = 15

#: Verbs that could express a cluster write. The reader is asserted to issue
#: none of them; see `test_the_reader_only_ever_issues_read_verbs`.
MUTATING_VERBS: Final[frozenset[str]] = frozenset(
    {
        "annotate",
        "apply",
        "attach",
        "cp",
        "create",
        "cordon",
        "delete",
        "drain",
        "edit",
        "exec",
        "label",
        "patch",
        "replace",
        "rollout",
        "scale",
        "set",
        "taint",
    }
)


# ---------------------------------------------------------------------------
# The reader: the one thing in this file that talks to a cluster
# ---------------------------------------------------------------------------


class KubectlObservationReader:
    """Reads a container's observable state. Never writes.

    Satisfies ``verify.ObservationReader``. Records every argv it issues so the
    read-only claim is checkable after the fact rather than taken on trust.

    Two fields are deliberately distinct, because collapsing them is the bug
    this reader is most likely to reintroduce:

    ``visible``
        Did we see the container's status at all? A pod that exists but has not
        published a status is not evidence about the workload.
    ``container_uptime_seconds``
        ``None`` means *could not be read*, which is not ``0`` (*just
        restarted*). The model rejects an invisible container that also reports
        an uptime, and the reason it does is in ``ContainerObservation``'s own
        docstring: collapsing the two turns an unreadable field into a
        recurrence verdict, and a recurrence verdict escalates to Tier-2.
    """

    def __init__(
        self, namespace: str = VERIFY_NAMESPACE, selector: str = SELECTOR
    ) -> None:
        self._namespace = namespace
        self._selector = selector
        #: Every argv issued, in order. The audit trail behind the zero-writes
        #: assertion; also what a failure report quotes.
        self.calls: list[list[str]] = []
        #: Monotonic-ish wall clock for uptime arithmetic. Only used to age a
        #: running container; the loop's own bounds use perf_counter (AGENTS 3).
        self._now = time.time

    # -- the one capability verify.py is given ---------------------------

    def read(self, target: ContainerTarget) -> ContainerObservation:
        """Return the current observable state of ``target``'s container."""
        raw = self._kubectl(
            [
                "get",
                "pods",
                "-n",
                self._namespace,
                "-l",
                self._selector,
                "-o",
                "json",
            ]
        )
        pod = self._select_pod(json.loads(raw), target.pod_name)
        if pod is None:
            return ContainerObservation(
                visible=False,
                oomkilled_terminations=0,
                crashloopbackoff_wait=False,
                container_uptime_seconds=None,
                note="no pod matched the selector",
            )
        return self._observe(pod, target.container_name)

    # -- internals --------------------------------------------------------

    def _kubectl(self, args: list[str]) -> str:
        # Recorded before the call, not after: a reader that raised would
        # otherwise leave no trace of the verb it had already used.
        self.calls.append(list(args))
        if shutil.which("kubectl") is None:
            raise RuntimeError("kubectl is not on PATH; the live path cannot run")
        completed = subprocess.run(  # noqa: S603 - fixed argv, no shell
            ["kubectl", *args],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        if completed.returncode != 0:
            raise RuntimeError(
                f"kubectl {' '.join(args)} failed "
                f"({completed.returncode}): {completed.stderr.strip()}"
            )
        return completed.stdout

    @staticmethod
    def _select_pod(body: dict[str, Any], pod_name: str) -> dict[str, Any] | None:
        """Find ``pod_name`` among the selector's matches.

        By name, never by ``items[0]``. The bare-existence form resolves to
        whichever pod name sorts first, and with two chaos fixtures that is
        ``crashloop`` before ``oom`` - the runner would silently observe the
        wrong pod forever. Selecting by name makes the ambiguity impossible.
        """
        items: list[dict[str, Any]] = body.get("items") or []
        for item in items:
            if (item.get("metadata") or {}).get("name") == pod_name:
                return item
        return None

    def _observe(
        self, pod: dict[str, Any], container_name: str
    ) -> ContainerObservation:
        """Reduce one pod's JSON to one observation.

        Split out from ``read`` so it can be exercised against stored JSON with
        no cluster at all, which is where most of this file's real assertions
        live.
        """
        statuses = (pod.get("status") or {}).get("containerStatuses") or []
        status = next((s for s in statuses if s.get("name") == container_name), None)
        if status is None:
            # The pod is visible but this container is not. Not the same as the
            # pod being absent, and not evidence about the container either.
            return ContainerObservation(
                visible=False,
                oomkilled_terminations=0,
                crashloopbackoff_wait=False,
                container_uptime_seconds=None,
                note=f"container {container_name!r} has published no status",
            )

        state = status.get("state") or {}
        last_state = status.get("lastState") or {}

        # Both the current and the previous instance count. The kubelet clears
        # `state.terminated` the moment it restarts a container, so a pod that
        # OOMed thirty seconds ago and is now merely waiting reports the kill
        # only under `lastState`. Reading `state` alone is how a recurrence
        # goes unobserved - the sampling-window defect in
        # docs/lessons-learned.md section 9, in a different guise.
        ooms = 0
        for candidate in (state.get("terminated"), last_state.get("terminated")):
            if candidate is None:
                continue
            if (
                candidate.get("reason") == "OOMKilled"
                or candidate.get("exitCode") == 137
            ):
                ooms += 1

        waiting = state.get("waiting") or {}
        in_backoff = waiting.get("reason") == "CrashLoopBackOff"

        uptime = self._uptime_seconds(pod, state)
        return ContainerObservation(
            visible=True,
            oomkilled_terminations=ooms,
            crashloopbackoff_wait=in_backoff,
            container_uptime_seconds=uptime,
            note="",
        )

    def _uptime_seconds(self, pod: dict[str, Any], state: dict[str, Any]) -> int | None:
        """Seconds the current container instance has been running, or ``None``.

        ``None`` whenever it cannot be established: not running, or no
        timestamp. Returning ``0`` instead would make an unreadable field
        indistinguishable from a container that just restarted, and a
        just-restarted container is a recurrence waiting to be declared.
        """
        running = state.get("running") or {}
        started = running.get("startedAt")
        if not started:
            return None
        try:
            from datetime import datetime

            began = datetime.fromisoformat(str(started).replace("Z", "+00:00"))
        except ValueError:
            return None
        elapsed = self._now() - began.timestamp()
        return max(0, int(elapsed))

    # -- the GitOps simulation -------------------------------------------

    def sync(self, manifest: pathlib.Path) -> None:
        """Apply ``manifest``, standing in for a GitOps controller's sync.

        On the reader rather than as a free function, and deliberately *not*
        routed through ``_kubectl``, so the argv recording above covers
        observation only. A sync that appeared in ``self.calls`` would make the
        read-only assertion ambiguous about which side of the boundary issued
        it - and the whole point is that the boundary is unambiguous.
        """
        self._kubectl_apply(["apply", "-n", self._namespace, "-f", str(manifest)])

    def _kubectl_apply(self, args: list[str]) -> str:
        if shutil.which("kubectl") is None:
            raise RuntimeError("kubectl is not on PATH; the live path cannot run")
        completed = subprocess.run(  # noqa: S603 - fixed argv, no shell
            ["kubectl", *args],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        if completed.returncode != 0:
            raise RuntimeError(
                f"kubectl {' '.join(args)} failed "
                f"({completed.returncode}): {completed.stderr.strip()}"
            )
        return completed.stdout


# ---------------------------------------------------------------------------
# Offline: the reader's parsing, with no cluster
# ---------------------------------------------------------------------------


def _pod(
    *,
    name: str = "srek3s-chaos-oom-6d9f4b6c8d-x2k9p",
    statuses: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return {
        "metadata": {"name": name},
        "status": {"containerStatuses": statuses or []},
    }


def _status(
    *,
    waiting: str | None = None,
    running_since: str | None = None,
    terminated: dict[str, Any] | None = None,
    last_terminated: dict[str, Any] | None = None,
    name: str = CONTAINER,
) -> dict[str, Any]:
    state: dict[str, Any] = {}
    if waiting is not None:
        state["waiting"] = {"reason": waiting}
    if running_since is not None:
        state["running"] = {"startedAt": running_since}
    if terminated is not None:
        state["terminated"] = terminated
    status: dict[str, Any] = {"name": name, "state": state}
    if last_terminated is not None:
        status["lastState"] = {"terminated": last_terminated}
    return status


def _reader(clock: float | None = None) -> KubectlObservationReader:
    reader = KubectlObservationReader()
    if clock is not None:
        reader._now = lambda: clock  # noqa: SLF001 - test seam, documented below
    return reader


def _ago(seconds: int, *, now: float) -> str:
    from datetime import datetime, timezone

    began = datetime.fromtimestamp(now - seconds, tz=timezone.utc)
    return began.isoformat().replace("+00:00", "Z")


NOW: Final[float] = 1_757_000_000.0


class TestReaderParsing:
    """The reader's whole job, exercised without a cluster.

    These are the assertions that make the live path trustworthy. A live test
    that fails tells you *that* the loop misbehaved; these tell you *whether the
    observation it was fed was true*.
    """

    def test_a_running_container_reports_its_uptime(self) -> None:
        obs = _reader(NOW)._observe(
            _pod(statuses=[_status(running_since=_ago(120, now=NOW))]), CONTAINER
        )
        assert obs.visible is True
        assert obs.oomkilled_terminations == 0
        assert obs.crashloopbackoff_wait is False
        assert obs.container_uptime_seconds == 120

    def test_an_oom_in_the_current_state_is_counted(self) -> None:
        obs = _reader(NOW)._observe(
            _pod(
                statuses=[_status(terminated={"reason": "OOMKilled", "exitCode": 137})]
            ),
            CONTAINER,
        )
        assert obs.oomkilled_terminations == 1

    def test_an_oom_only_in_last_state_is_still_counted(self) -> None:
        """The recurrence that a naive reader misses entirely.

        The kubelet clears ``state.terminated`` on restart, so a pod that OOMed
        and is now merely waiting carries the kill **only** under ``lastState``.
        Reading ``state`` alone reports a healthy container for a workload that
        is already crash-looping - and a healthy-looking observation is what
        closes an incident that should have escalated.
        """
        obs = _reader(NOW)._observe(
            _pod(
                statuses=[
                    _status(
                        waiting="CrashLoopBackOff",
                        last_terminated={"reason": "OOMKilled", "exitCode": 137},
                    )
                ]
            ),
            CONTAINER,
        )
        assert obs.oomkilled_terminations == 1
        assert obs.crashloopbackoff_wait is True

    def test_a_non_oom_termination_is_not_counted_as_one(self) -> None:
        """Exit 1 is an application error. Counting it as an OOM would promote
        a healthy workload to Tier-2 on a technicality."""
        obs = _reader(NOW)._observe(
            _pod(statuses=[_status(terminated={"reason": "Error", "exitCode": 1})]),
            CONTAINER,
        )
        assert obs.oomkilled_terminations == 0

    def test_crashloopbackoff_is_read_from_the_waiting_reason(self) -> None:
        obs = _reader(NOW)._observe(
            _pod(statuses=[_status(waiting="CrashLoopBackOff")]), CONTAINER
        )
        assert obs.crashloopbackoff_wait is True

    def test_a_container_that_is_not_running_reports_no_uptime(self) -> None:
        """Not running means uptime is unknown, which is not zero.

        Zero is a specific claim - "started a moment ago" - and asserting it
        without evidence is how a recurrence gets manufactured.
        """
        obs = _reader(NOW)._observe(
            _pod(statuses=[_status(waiting="CrashLoopBackOff")]), CONTAINER
        )
        assert obs.container_uptime_seconds is None

    def test_an_unparseable_timestamp_is_unknown_not_zero(self) -> None:
        obs = _reader(NOW)._observe(
            _pod(statuses=[_status(running_since="not-a-timestamp")]), CONTAINER
        )
        assert obs.container_uptime_seconds is None
        assert obs.visible is True

    def test_a_container_with_no_published_status_is_not_visible(self) -> None:
        obs = _reader(NOW)._observe(_pod(statuses=[]), CONTAINER)
        assert obs.visible is False
        assert obs.container_uptime_seconds is None

    def test_a_second_container_does_not_contribute(self) -> None:
        """Container identity is load-bearing.

        A sidecar that OOMed must not make the application container look
        recurrent, or vice versa.
        """
        obs = _reader(NOW)._observe(
            _pod(
                statuses=[
                    _status(
                        name="envoy-sidecar",
                        terminated={"reason": "OOMKilled", "exitCode": 137},
                    ),
                    _status(name=CONTAINER, running_since=_ago(300, now=NOW)),
                ]
            ),
            CONTAINER,
        )
        assert obs.oomkilled_terminations == 0
        assert obs.container_uptime_seconds == 300

    def test_pods_are_selected_by_name_not_by_list_order(self) -> None:
        """`items[0]` is the wrong pod whenever two fixtures match one selector.

        This is the defect `docs/lessons-learned.md` §13 records: a bare
        existence selector resolves to whichever name sorts first, and the
        runner then samples the wrong pod indefinitely while every assertion
        still looks healthy.
        """
        body = {
            "items": [
                _pod(name="srek3s-chaos-crashloop-aaa", statuses=[_status()]),
                _pod(
                    name="srek3s-chaos-oom-bbb",
                    statuses=[_status(running_since=_ago(400, now=NOW))],
                ),
            ]
        }
        chosen = KubectlObservationReader._select_pod(body, "srek3s-chaos-oom-bbb")
        assert chosen is not None
        assert chosen["metadata"]["name"] == "srek3s-chaos-oom-bbb"
        assert KubectlObservationReader._select_pod(body, "absent") is None


class TestReaderIsReadOnly:
    """4.3.5 extended across the module boundary.

    `verify.py` cannot write, and that is asserted in `test_verify.py`. This
    asserts the *other* half: the component that hands it observations cannot
    write either, so there is no path by which a verification run reaches the
    cluster with a verb.
    """

    def test_the_reader_only_ever_issues_read_verbs(self) -> None:
        reader = KubectlObservationReader()
        # A realistic observation sequence, including the miss.
        expected = [
            "get",
            "pods",
            "-n",
            VERIFY_NAMESPACE,
            "-l",
            SELECTOR,
            "-o",
            "json",
        ]
        reader.calls = [list(expected), list(expected)]

        # The verb is argv[0]. Asserting on the position rather than on the
        # token set: a token-set subset check has to enumerate every flag the
        # read legitimately uses, and the first version of this assertion did
        # exactly that and failed on `-l` - a flag that was there for a good
        # reason. A check that breaks when someone adds a legitimate flag is a
        # check that gets deleted rather than fixed.
        for call in reader.calls:
            assert call[0] == "get", f"observation issued a non-read verb: {call}"
            assert not set(call) & MUTATING_VERBS, (
                f"the observation reader issued mutating verb(s) "
                f"{sorted(set(call) & MUTATING_VERBS)}; a verification run must "
                "not be able to reach the cluster with a write"
            )
        # And the whole shape, so a future change to what is read is visible.
        assert reader.calls[0] == expected

    def test_a_sync_is_recorded_separately_from_observation(self) -> None:
        """The GitOps stand-in must not be confusable with a read.

        If ``sync`` went through the recording path, ``calls`` would mix the
        harness's writes with the engine's reads and the assertion above would
        pass or fail for reasons nobody could reconstruct. The separation is the
        evidence that the boundary is real.
        """
        # Not executed: the point is which method the verb would travel through.
        source = pathlib.Path(__file__).read_text(encoding="utf-8")
        tree = ast.parse(source)
        sync_methods = {
            node.name
            for cls in ast.walk(tree)
            if isinstance(cls, ast.ClassDef) and cls.name == "KubectlObservationReader"
            for node in cls.body
            if isinstance(node, ast.FunctionDef)
        }
        assert {"read", "sync", "_kubectl", "_kubectl_apply"} <= sync_methods
        # `sync` delegates to `_kubectl_apply`, never to `_kubectl`.
        sync_fn = next(
            node
            for cls in ast.walk(tree)
            if isinstance(cls, ast.ClassDef) and cls.name == "KubectlObservationReader"
            for node in cls.body
            if isinstance(node, ast.FunctionDef) and node.name == "sync"
        )
        delegated = {
            node.func.attr
            for node in ast.walk(sync_fn)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
        }
        assert "_kubectl_apply" in delegated
        assert "_kubectl" not in delegated, (
            "sync must not issue its verb through the observation recorder, or "
            "the read-only assertion over `calls` stops meaning anything"
        )


# ---------------------------------------------------------------------------
# The GitOps round-trip: real git, real cluster
# ---------------------------------------------------------------------------


def _kubectl_raw(
    args: list[str], *, timeout: int = 60, input_text: str | None = None
) -> subprocess.CompletedProcess[str]:
    """Run kubectl without raising, for lifecycle calls that must not fail hard.

    ``input_text`` feeds stdin, which is how ``apply -f -`` receives the
    namespace manifest. Rendering a manifest to stdout and then discarding it is
    a mistake this file made once: ``--dry-run=client`` exits 0 without
    submitting anything, so the "create" silently created nothing.
    """
    return subprocess.run(  # noqa: S603 - fixed argv, no shell
        ["kubectl", *args],
        input=input_text,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def _cluster_available() -> tuple[bool, str]:
    if shutil.which("kubectl") is None:
        return False, "kubectl is not on PATH"
    try:
        completed = _kubectl_raw(["cluster-info"], timeout=30)
    except (OSError, subprocess.SubprocessError) as exc:
        return False, f"kubectl could not be run: {exc}"
    if completed.returncode != 0:
        return False, f"no reachable cluster: {completed.stderr.strip()}"
    return True, ""


def _namespace_exists() -> bool:
    return (
        _kubectl_raw(["get", "namespace", VERIFY_NAMESPACE, "-o", "name"]).returncode
        == 0
    )


@contextmanager
def verify_namespace() -> Iterator[str]:
    """Create :data:`VERIFY_NAMESPACE` for the duration of a live test.

    Created here rather than shipped as a manifest in `deploy/chaos/`, because
    that directory is the ratified M4.2 fixture set and adding to it would change
    what a live run applies. Created *and deleted* so a crashed run leaves
    nothing behind for the next one to trip over.

    The Pod Security labels are copied from the ratified namespace manifest
    rather than restated, so this namespace is `restricted`-enforced on exactly
    the same terms as `sentinel-chaos`. A verification fixture that ran under
    laxer admission than the fixtures it is verifying against would be testing
    a different environment than the one the system ships in.
    """
    existed = _namespace_exists()
    if not existed:
        # One `apply` of a complete manifest, labels included.
        #
        # The first version did `kubectl create namespace ... --dry-run=client
        # -o yaml`, checked the exit status, discarded the rendered stdout, and
        # then ran `kubectl label namespace/...` - labelling a namespace that had
        # never been created. CI reported it precisely:
        #
        #     could not label namespace 'srek3s-verify-chaos' with
        #     'app.kubernetes.io/part-of': namespaces "srek3s-verify-chaos" not found
        #
        # The exit status was 0 the whole way. `--dry-run=client` renders without
        # submitting, so the command succeeded and did nothing, and the failure
        # surfaced two steps later as a NotFound from a different command. That
        # is the same shape as the `git apply` case in
        # docs/lessons-learned.md section 19: a green command that changed
        # nothing, caught only because a later step happened to notice.
        #
        # Applying the whole manifest at once also removes the window in which
        # the namespace exists without its Pod Security labels. Nothing applies
        # pods in that window here, but a create-then-label sequence would admit
        # a privileged pod if anything ever did.
        created = _kubectl_raw(["apply", "-f", "-"], input_text=_namespace_manifest())
        if created.returncode != 0:
            raise RuntimeError(
                f"could not create namespace {VERIFY_NAMESPACE!r}: "
                f"{created.stderr.strip()}"
            )
        # Necessary and not sufficient, the same rule the patch helper follows:
        # confirm the effect rather than trusting the exit status.
        if not _namespace_exists():
            raise RuntimeError(
                f"kubectl apply reported success but namespace "
                f"{VERIFY_NAMESPACE!r} does not exist"
            )
    try:
        yield VERIFY_NAMESPACE
    finally:
        if not existed:
            # `--wait=false` and a bounded grace period: the API server finalises
            # a namespace deletion asynchronously, and an unbounded wait here is
            # indistinguishable from a hang.
            _kubectl_raw(
                ["delete", "namespace", VERIFY_NAMESPACE, "--wait=false"],
                timeout=120,
            )
            _kubectl_raw(
                ["wait", "--for=delete", f"namespace/{VERIFY_NAMESPACE}"],
                timeout=180,
            )


def _namespace_manifest() -> str:
    """The verification namespace, carrying the ratified PSA labels.

    Rendered from ``deploy/chaos/namespace.yaml`` rather than restated, so the
    two namespaces cannot drift: a future change to the enforcement terms is
    picked up here automatically instead of needing to be copied and then
    remembered. The name is the only field that differs, plus the warning
    annotation, which is rewritten to describe this namespace rather than
    `sentinel-chaos`.
    """
    source = yaml.safe_load(NAMESPACE_MANIFEST.read_text(encoding="utf-8"))
    metadata: dict[str, Any] = dict(source.get("metadata") or {})
    metadata["name"] = VERIFY_NAMESPACE
    annotations = dict(metadata.get("annotations") or {})
    annotations["srek3s.io/warning"] = (
        f"Disposable. Namespace {VERIFY_NAMESPACE} is created and deleted by the "
        "Milestone 4.3 post-remediation verification test. It is isolated from "
        f"{source.get('metadata', {}).get('name')} so ROADMAP 4.2.8's object count "
        "is unaffected. Safe to delete: nothing in srek3s-system references it."
    )
    metadata["annotations"] = annotations
    return yaml.safe_dump(
        {"apiVersion": "v1", "kind": "Namespace", "metadata": metadata},
        sort_keys=False,
    )


def _skip_without_cluster() -> None:
    available, reason = _cluster_available()
    if not available:
        pytest.skip(
            f"live cluster round-trip needs a reachable cluster and creates "
            f"{VERIFY_NAMESPACE!r} - {reason}. This is a BLOCKED DEPENDENCY, "
            "not a pass: the offline half of this file is what ran."
        )
    if not os.environ.get("SREK3S_LIVE_E2E"):
        pytest.skip(
            "set SREK3S_LIVE_E2E=1 to run the live round-trip; the offline half "
            "of this file is what runs in the normal suite"
        )


def _git(*args: str, cwd: Path | None = None) -> str:
    completed = subprocess.run(  # noqa: S603 - fixed argv, no shell
        ["git", *args],
        capture_output=True,
        text=True,
        timeout=60,
        cwd=str(cwd) if cwd else None,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            f"git {' '.join(args)} failed ({completed.returncode}): "
            f"{completed.stderr.strip()}"
        )
    return completed.stdout


def _memory_limit_line(manifest: Path | None = None) -> int:
    """1-based line number of the container's ``memory:`` limit.

    Found by reading the parsed document and locating the value, rather than by
    hardcoding a line number or trusting the file's indentation. A patch built
    from a guessed offset either fails `git apply --check` - fine - or, worse,
    applies to a *different* `memory:` line than intended and the test then
    verifies a manifest that was never the one it thought it was.

    Takes an optional path so the refusal behaviour can be tested against a
    manifest that has no matching line. Parameterised rather than reached by
    reassigning the module-level constant, which is declared `Final` - and
    rightly so.
    """
    target = TARGET_MANIFEST if manifest is None else manifest
    text = target.read_text(encoding="utf-8")
    for index, line in enumerate(text.splitlines(), start=1):
        if line.strip() == f"memory: {FROM_LIMIT}":
            return index
    raise RuntimeError(
        f"no line reading exactly 'memory: {FROM_LIMIT}' in {target}; "
        "the Tier-1 patch would target the wrong manifest state"
    )


def _tier1_patch(old: str, new: str) -> str:
    """A unified diff raising the container's memory limit, located by value.

    Three lines of context either side, taken verbatim from the file. Enough for
    `git apply` to anchor unambiguously, and derived rather than written by hand
    so the hunk cannot drift from the manifest it claims to patch.
    """
    text = TARGET_MANIFEST.read_text(encoding="utf-8")
    lines = text.splitlines()
    anchor = _memory_limit_line() - 1
    before = lines[max(0, anchor - 3) : anchor]
    after = lines[anchor + 1 : anchor + 4]
    rel = TARGET_MANIFEST.relative_to(_ROOT).as_posix()

    # The replacement is written literally rather than by substituting `old` into
    # the found line: substitution would preserve whatever indentation the file
    # happens to have, and a hunk whose added line is indented differently from
    # the removed one is a hunk that changes the manifest's shape as well as its
    # value. 14 spaces is this manifest's own indentation under `limits:`.
    hunk_removed = [f"-{lines[anchor]}"]
    hunk_added = [f"+              memory: {new}"]
    body = (
        [f" {b}" for b in before] + hunk_removed + hunk_added + [f" {a}" for a in after]
    )

    # The hunk header counts each side SEPARATELY. A removed line counts towards
    # the old file and an added line towards the new one; they are not the same
    # line. Counting the body once - which is what the first draft did - declares
    # 8 lines per side where the old side has 4, and `git apply` answers
    # "corrupt patch at line N" rather than anything resembling a diagnosis.
    #
    # This is precisely why the hunk is assembled and then applied by real git in
    # a test rather than trusted: the header is arithmetic that looks equally
    # plausible whether or not it is right, and only git can tell the difference.
    old_count = len(before) + len(hunk_removed) + len(after)
    new_count = len(before) + len(hunk_added) + len(after)
    start = max(1, anchor - len(before) + 1)
    return (
        "\n".join(
            [
                f"diff --git a/{rel} b/{rel}",
                f"--- a/{rel}",
                f"+++ b/{rel}",
                f"@@ -{start},{old_count} +{start},{new_count} @@",
                *body,
            ]
        )
        + "\n"
    )


def _apply_tier1_patch() -> Path:
    """Apply the Tier-1 diff with real ``git apply``, in a scratch copy.

    **The scratch directory is outside the repository**, and that is the whole
    point of this function's design rather than a hygiene detail. The first
    version put it at ``tests/e2e/.verify-scratch`` - inside the working tree -
    and `git apply` walked up to the repository root to resolve the patch's
    paths instead of using the working directory. The result was the worst
    available outcome: **exit status 0 and no file changed.** The manifest in
    the scratch directory was never the target, so the caller read an unpatched
    copy while the command reported success. A green `git apply` that applied
    nothing is a check that cannot fail, which is the failure mode this
    repository keeps paying for.

    Two defences, and both are load-bearing:

    * The scratch lives outside the repo, so there is no repository for git to
      resolve against and no second file that could be written by mistake.
    * The return value is *verified*, not assumed. `git apply`'s exit status is
      treated as necessary and not sufficient, and a patch that applied without
      changing the limit raises here rather than returning a file that looks
      plausible.

    `git apply --check` runs first, so a malformed patch is caught before
    anything is written.
    """
    rel = TARGET_MANIFEST.relative_to(_ROOT)
    scratch = Path(tempfile.mkdtemp(prefix="srek3s-verify-"))
    try:
        (scratch / rel.parent).mkdir(parents=True, exist_ok=True)
        shutil.copy2(TARGET_MANIFEST, scratch / rel)
        patch_path = scratch / "tier1.patch"
        # newline="\n" is load-bearing, not decoration. `Path.write_text` opens in
        # text mode with universal newline *translation* on Windows, so the patch
        # came out CRLF while the manifest it has to match is pure LF. Git then
        # reported `patch does not apply` at the right line with byte-identical
        # context, because every context line carried a trailing \r the file does
        # not have. The identical code passes on Linux, where there is no
        # translation - the same host/CI divergence shape as the platform-sensitive
        # `type: ignore` in ROADMAP 2, and found the same way: green somewhere,
        # red somewhere else, with no other signal.
        patch_path.write_text(
            _tier1_patch(FROM_LIMIT, TO_LIMIT), encoding="utf-8", newline="\n"
        )

        check = subprocess.run(  # noqa: S603 - fixed argv, no shell
            ["git", "apply", "--check", str(patch_path)],
            capture_output=True,
            text=True,
            timeout=30,
            cwd=str(scratch),
            check=False,
        )
        if check.returncode != 0:
            raise RuntimeError(
                f"git apply --check rejected the Tier-1 patch: "
                f"{check.stderr.strip()}\n--- patch ---\n"
                f"{_tier1_patch(FROM_LIMIT, TO_LIMIT)}"
            )
        applied = subprocess.run(  # noqa: S603 - fixed argv, no shell
            ["git", "apply", str(patch_path)],
            capture_output=True,
            text=True,
            timeout=30,
            cwd=str(scratch),
            check=False,
        )
        if applied.returncode != 0:
            raise RuntimeError(
                f"git apply failed: {applied.stderr.strip()}\n--- patch ---\n"
                f"{_tier1_patch(FROM_LIMIT, TO_LIMIT)}"
            )

        result = scratch / rel
        text = result.read_text(encoding="utf-8")
        # The exit status is necessary and not sufficient. Verified here so a
        # silent no-op cannot reach a caller that would then assert against an
        # unpatched file and draw a conclusion from it.
        if f"memory: {TO_LIMIT}" not in text or f"memory: {FROM_LIMIT}" in text:
            raise RuntimeError(
                "git apply reported success but the manifest still reads "
                f"{FROM_LIMIT}. A patch that applies without changing anything "
                "would let this test verify a workload that was never remediated."
            )
        return result
    except BaseException:
        shutil.rmtree(scratch, ignore_errors=True)
        raise


def _revert_to_fault() -> Path:
    """Return the unpatched manifest, for re-injecting the fault."""
    return TARGET_MANIFEST


def _wait_for_rollout(namespace: str, timeout: int = 180) -> None:
    """Block until the Deployment finishes rolling out.

    Bounded, and the bound is derived rather than guessed: a rollout of a
    single-replica Deployment that OOMs on a loop settles in seconds, and an
    unbounded `kubectl rollout status` is indistinguishable from a hang - the
    same trap `ctr --timeout` defaulted into.
    """
    subprocess.run(  # noqa: S603 - fixed argv, no shell
        [
            "kubectl",
            "rollout",
            "status",
            f"deployment/{DEPLOYMENT}",
            "-n",
            namespace,
            f"--timeout={timeout}s",
        ],
        capture_output=True,
        text=True,
        timeout=timeout + 30,
        check=False,
    )


def _policy() -> VerificationPolicy:
    return VerificationPolicy(
        mode="POST_REMEDIATION_OBSERVATION",
        watch_duration_seconds=WATCH_SECONDS,
        success_criteria=SuccessCriteria(
            no_oomkilled_terminations=True,
            no_crashloopbackoff_wait=True,
            container_uptime_seconds_min=UPTIME_MIN,
        ),
        max_requeue_attempts=2,
    )


def _current_pod_name(namespace: str) -> str:
    reader = KubectlObservationReader()
    raw = reader._kubectl(  # noqa: SLF001 - the test is the harness here
        ["get", "pods", "-n", namespace, "-l", SELECTOR, "-o", "json"]
    )
    items: list[dict[str, Any]] = json.loads(raw).get("items") or []

    def _name(item: dict[str, Any]) -> str:
        metadata: dict[str, Any] = item.get("metadata") or {}
        name: str = metadata.get("name", "")
        return name

    def _owned_by_deployment(item: dict[str, Any]) -> bool:
        metadata: dict[str, Any] = item.get("metadata") or {}
        owners: list[dict[str, Any]] = metadata.get("ownerReferences") or []
        return any(owner.get("name") == DEPLOYMENT for owner in owners)

    owned = [_name(i) for i in items if _owned_by_deployment(i)]
    # Fall back to every match only when ownership is absent from the payload.
    # Taking items[0] instead would resolve to whichever name sorts first, and
    # with two chaos fixtures that is `crashloop` before `oom` - the wrong pod,
    # observed indefinitely, with every assertion still looking healthy.
    candidates = owned or [_name(i) for i in items]
    if not candidates:
        raise RuntimeError(f"no pod found for {SELECTOR!r}")
    return str(candidates[0])


@contextmanager
def _live_cluster() -> Iterator[str]:
    """Gate on a cluster, own the namespace, and always tear it down.

    Wraps `_skip_without_cluster` and `verify_namespace` into one statement so a
    live test cannot acquire a cluster dependency without also acquiring the
    cleanup. The two were separate calls in the first draft, and a test that
    called `verify_namespace` without a teardown path would leak a namespace
    into the next run - where it would make `_namespace_exists` return True and
    the fixture would silently reuse whatever state the crashed run left.
    """
    _skip_without_cluster()
    with verify_namespace() as namespace:
        yield namespace


def _observe(policy: VerificationPolicy, target: ContainerTarget) -> Any:
    """Run one observation window to a verdict.

    `verify_incident` is async by construction - its single read is a blocking
    call dispatched off the event loop, so a 1800-second window cannot stall
    `/healthz` (AGENTS.md §3 rule 1). Driving it from a sync test therefore needs
    a loop, and `asyncio.run` is the one that is not shared with anything.
    """
    import asyncio

    incident_id = "inc_01HQ8S7G3M2K9X4B6D0F1R5TJA"
    budget = RequeueBudget(policy, incident_id=incident_id)
    return asyncio.run(
        verify_incident(
            policy,
            target,
            KubectlObservationReader(),
            incident_id=incident_id,
            budget=budget,
            poll_interval_seconds=5.0,
        )
    )


@pytest.mark.live
class TestGitOpsPostRemediationLoop:
    """4.3.4: apply a fix and verify it; re-inject the fault and verify that.

    The full round-trip, on a real k3s, through a real `git apply` and a real
    `kubectl apply`. Both tests need a cluster; both skip loudly without one, and
    the skip message says BLOCKED DEPENDENCY so a green run in which they never
    executed cannot be read as a green run in which they passed.

    The two tests are ordered and share nothing. Each builds its own namespace,
    applies its own manifest state, and constructs its own target - so running
    either alone gives the same result as running both, which is the property
    that makes them independently useful in a failure report.
    """

    def test_a_correct_tier1_diff_verifies(self) -> None:
        """Raise the limit with a real diff, sync, and observe the workload hold.

        Asserts the verdict is VERIFIED, routes to CLOSE_INCIDENT, and rests on
        a real observation - uptime above the minimum with zero OOM kills -
        rather than on a window that simply expired.
        """
        _skip_without_cluster()
        if not TARGET_MANIFEST.exists():
            pytest.skip(f"{TARGET_MANIFEST} does not exist")

        patched = _apply_tier1_patch()
        # The patch must have changed the value, not merely applied cleanly.
        # `git apply` tolerating a patch that altered nothing is a shape this
        # test must not be able to mistake for a fix.
        assert f"memory: {TO_LIMIT}" in patched.read_text(encoding="utf-8"), (
            "the Tier-1 patch applied but did not raise the limit, so the "
            "container would still OOM and the test would prove nothing"
        )
        assert f"memory: {FROM_LIMIT}" not in patched.read_text(encoding="utf-8")

        with _live_cluster() as namespace:
            reader = KubectlObservationReader(namespace=namespace)
            reader.sync(patched)
            _wait_for_rollout(namespace)
            target = ContainerTarget(
                namespace=namespace,
                pod_name=_current_pod_name(namespace),
                container_name=CONTAINER,
            )
            policy = _policy()
            verdict = _observe(policy, target)

        assert verdict.kind is VerdictKind.VERIFIED, (
            f"expected VERIFIED after remediation, got {verdict.kind}: "
            f"{verdict.reason}"
        )
        assert verdict.action == "CLOSE_INCIDENT"
        assert verdict.observation is not None
        assert verdict.observation.oomkilled_terminations == 0, (
            "a VERIFIED verdict over a container with an OOM kill in its "
            "history is a closure that should not have been granted"
        )
        assert (
            verdict.observation.container_uptime_seconds is not None
            and verdict.observation.container_uptime_seconds >= UPTIME_MIN
        ), (
            "a VERIFIED verdict must rest on a real observation; uptime was "
            f"{verdict.observation.container_uptime_seconds!r}, minimum "
            f"{UPTIME_MIN}"
        )

    def test_reinjecting_the_fault_promotes_to_tier2(self) -> None:
        """Revert the limit, sync, and observe the OOM recur.

        Asserts UNRESOLVED with cause OOM_KILLED, routing to PROMOTE_TO_TIER_2.
        The cause matters as much as the verdict: it is what lets a war-room
        human avoid repeating the investigation the agent just did.
        """
        _skip_without_cluster()

        with _live_cluster() as namespace:
            reader = KubectlObservationReader(namespace=namespace)
            # The unpatched manifest is the fault state: 64Mi against a 90 MiB
            # demand. No diff needed to re-inject - reverting IS the injection,
            # and using a real `git apply` here would be theatre.
            reader.sync(_revert_to_fault())
            _wait_for_rollout(namespace)
            target = ContainerTarget(
                namespace=namespace,
                pod_name=_current_pod_name(namespace),
                container_name=CONTAINER,
            )
            policy = _policy()
            verdict = _observe(policy, target)

        assert verdict.kind is VerdictKind.UNRESOLVED, (
            f"expected UNRESOLVED after re-injection, got {verdict.kind}: "
            f"{verdict.reason}"
        )
        assert verdict.action == "PROMOTE_TO_TIER_2"
        assert verdict.cause is UnresolvedCause.OOM_KILLED, (
            "a recurrence must name the fault that recurred; a bare "
            "UNRESOLVED tells the war room nothing it can act on"
        )
        # Fail-closed, checked on the verdict itself rather than on the loop's
        # discretion: a Tier-2 escalation must carry no way to express a write.
        assert not verdict.action.startswith("APPLY")


class TestBoundedFixture:
    """The fixture's load-bearing property, checked without a cluster.

    A memory remediation is only correct when demand falls *strictly between*
    the old and new limit. Every one of these assertions exists because the
    alternative - trusting the number in the manifest and the number in the test
    to agree - is an agreement that stops holding the moment either is edited.
    """

    @staticmethod
    def _manifest() -> dict[str, Any]:
        # Annotated rather than returned straight from `yaml.safe_load`, which is
        # typed `Any`. The annotation is the claim that this document has the
        # shape the tests below assume; a wrong annotation would make every one
        # of them fail loudly rather than silently pass on a missing key.
        doc: dict[str, Any] = yaml.safe_load(
            TARGET_MANIFEST.read_text(encoding="utf-8")
        )
        return doc

    @staticmethod
    def _container() -> dict[str, Any]:
        doc = TestBoundedFixture._manifest()
        containers = doc["spec"]["template"]["spec"]["containers"]
        return dict(containers[0])

    @staticmethod
    def _allocated_bytes() -> int:
        """The demand, read from the *executable* lines only.

        The manifest's comment block quotes the old fixture's doubling loop,
        which contains its own `head -c 1048576`. A search that does not skip
        comments finds that one and reports a demand of 1 MiB - which would still
        pass a naive "is it under 128Mi" check while proving the fixture OOMs at
        both limits. The first version of this test did exactly that.
        """
        script = str(TestBoundedFixture._container()["command"][2])
        code = [
            line
            for line in script.splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
        matches = [line for line in code if "head -c" in line]
        assert len(matches) == 1, (
            f"expected exactly one allocation in the executable lines, found "
            f"{len(matches)}: {matches}"
        )
        found = re.search(r"head -c (\d+) /dev/zero", matches[0])
        assert found is not None, f"unparseable allocation: {matches[0]!r}"
        return int(found.group(1))

    def test_the_peak_sits_strictly_between_the_two_limits(self) -> None:
        """The PEAK must be between 64 and 128 - not the payload.

        Correcting the assertion CI falsified. The 90 MiB payload satisfied
        "payload is between the limits" and the container was still OOMKilled at
        128Mi, because command substitution's peak is a multiple of the payload.
        Asserting on the payload would have passed on that broken fixture.
        """
        payload_mib = self._allocated_bytes() / 2**20
        old = _mib(FROM_LIMIT) / 2**20
        new = _mib(TO_LIMIT) / 2**20
        for multiple in _peak_multiples():
            peak = payload_mib * multiple
            assert old < peak < new, (
                f"at a peak multiple of {multiple:.2f} the peak is "
                f"{peak:.1f} MiB, which is not strictly between {FROM_LIMIT} and "
                f"{TO_LIMIT}. Either the fixture never faults, or the Tier-1 "
                "patch is not a fix."
            )

    def test_the_peak_is_not_wedged_against_either_limit(self) -> None:
        """Both margins must hold across the whole plausible multiple range.

        A payload whose peak only just clears 64Mi would fail to fault on a
        machine with a smaller shell baseline; one that only just fits under
        128Mi would fail to survive on a busier node. 48 MiB clears both across
        1.45x-2.0x, and 40 or 44 MiB would not clear 64Mi at the low end.
        """
        payload_mib = self._allocated_bytes() / 2**20
        old = _mib(FROM_LIMIT) / 2**20
        new = _mib(TO_LIMIT) / 2**20
        for multiple in _peak_multiples():
            peak = payload_mib * multiple
            assert peak - old >= 6, (
                f"at {multiple:.2f}x the peak clears the faulting limit by only "
                f"{peak - old:.1f} MiB; the fault would depend on the node's "
                "baseline rather than on the payload"
            )
            assert new - peak >= 16, (
                f"at {multiple:.2f}x the peak leaves only {new - peak:.1f} MiB of "
                f"slack under the fixed limit; survival would depend on the "
                "node's baseline rather than on the headroom"
            )

    def test_the_payload_is_centred_in_the_usable_band(self) -> None:
        """Why 52 MiB rather than a number outside the usable band.

        A regression guard on the *coarse* choice, so a later edit to a rounder
        number has to argue for itself. The band is bounded below by what still
        faults at 64Mi and above by what still fits at 128Mi, evaluated at the
        pessimistic end of each constraint.

        This is the coarse guard, not the fine one. 48 MiB passes here and is
        still rejected, by `test_the_peak_is_not_wedged_against_either_limit`:
        at the low end of the multiple range its peak clears 64Mi by only
        5.6 MiB, and 1.45 is barely above the 1.42 the cluster actually
        established, so that margin was not worth carrying. Two guards at two
        granularities, because one number has two ways to be wrong.
        """
        payload_mib = self._allocated_bytes() / 2**20
        lowest = _mib(FROM_LIMIT) / 2**20 / PEAK_MULTIPLE_MAX + 6
        highest = _mib(TO_LIMIT) / 2**20 / PEAK_MULTIPLE_MIN - 16
        assert lowest < payload_mib < highest, (
            f"{payload_mib:.0f} MiB is outside the usable band "
            f"({lowest:.1f}, {highest:.1f}) MiB across the plausible peak range"
        )

    def test_the_documented_payload_matches_the_allocation(self) -> None:
        """The constant in this test and the number in the fixture must agree.

        Two copies of a load-bearing number is a liability, so they are compared
        rather than trusted - and this is the check that would catch someone
        editing one of them.
        """
        assert self._allocated_bytes() == BOUNDED_PAYLOAD_BYTES
        assert str(BOUNDED_PAYLOAD_BYTES) in TARGET_MANIFEST.read_text(
            encoding="utf-8"
        ), "the manifest's prose and its allocation have drifted apart"

    def test_the_fault_limit_is_the_one_the_diff_targets(self) -> None:
        limit = self._container()["resources"]["limits"]["memory"]
        assert limit == FROM_LIMIT, (
            f"the fixture ships at {limit}, but the Tier-1 diff is built to "
            f"replace {FROM_LIMIT}; the patch would not apply"
        )

    def test_the_container_idles_long_enough_to_be_verified(self) -> None:
        """Without a long idle the fixture cannot return VERIFIED, ever.

        A container that exits and is restarted by the Deployment never
        accumulates uptime, so `container_uptime_seconds_min` is unreachable and
        the only verdicts available are UNRESOLVED and INDETERMINATE. The idle
        is what makes the VERIFIED path exist at all.
        """
        script = str(self._container()["command"][2])
        code = [
            line
            for line in script.splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
        sleeps = [
            int(m.group(1))
            for line in code
            if (m := re.search(r"sleep (\d+)", line)) is not None
        ]
        assert sleeps, "the fixture has no sleep; it cannot hold a container up"
        assert max(sleeps) > WATCH_SECONDS, (
            f"the longest sleep is {max(sleeps)}s, which is not longer than the "
            f"{WATCH_SECONDS}s observation window, so the container would exit "
            "before a verdict could be reached"
        )
        assert max(sleeps) > UPTIME_MIN

    def test_the_fixture_targets_the_isolated_namespace(self) -> None:
        """Isolation is the whole reason this fixture is not in deploy/chaos/.

        ROADMAP 4.2.8 counts the objects created inside `sentinel-chaos`, so a
        fixture landing there would change a number a ratified invariant
        reports. Asserted here so the namespace cannot be changed in passing.
        """
        assert self._manifest()["metadata"]["namespace"] == VERIFY_NAMESPACE
        assert VERIFY_NAMESPACE != "sentinel-chaos"

    def test_the_fixture_does_not_reuse_the_m42_chaos_label(self) -> None:
        """`srek3s.io/chaos=oom` is Milestone 4.2's detection-ratio selector.

        A workload that is *supposed* to stay healthy must not be selectable by
        the runner that asserts every selected pod OOMs. One label, one meaning.
        """
        assert SELECTOR != "srek3s.io/chaos=oom"
        labels = self._manifest()["metadata"]["labels"]
        assert labels["srek3s.io/chaos"] == "bounded-oom"

    def test_the_fixture_matches_the_ratified_chaos_admission_surface(self) -> None:
        """Restricted PSA, identical to `deploy/chaos/oom-leak.yaml`.

        A verification fixture admitted under laxer terms than the fixtures it
        verifies against would be testing a different environment than the one
        the system ships in. `fsGroup` is the field most easily forgotten and it
        is the one this caught on the first draft.
        """
        ratified_path = _ROOT / "deploy" / "chaos" / "oom-leak.yaml"
        ratified = yaml.safe_load(ratified_path.read_text(encoding="utf-8"))
        mine = self._manifest()
        assert (
            mine["spec"]["template"]["spec"]["securityContext"]
            == ratified["spec"]["template"]["spec"]["securityContext"]
        )
        assert (
            self._container()["securityContext"]
            == ratified["spec"]["template"]["spec"]["containers"][0]["securityContext"]
        )

    def test_the_fixture_plants_evidence_for_the_war_room_bundle(self) -> None:
        """Credentials present, so the Tier-2 path carries something to bundle.

        Rule 7 (`password=`, `token=`) is omitted for the reason recorded in
        `deploy/chaos/oom-leak.yaml`: its replacement template depends on a group
        index that was never confirmed. A fixture must not silently depend on an
        unverified one.
        """
        script = str(self._container()["command"][2])
        for marker in ("AKIA", "eyJhbGciOi", "Authorization: Bearer", "postgres://"):
            assert marker in script, f"missing planted credential: {marker}"
        assert "password=" not in script, (
            "rule 7 is deliberately excluded from the fixtures; its replacement "
            "template's group index is unconfirmed"
        )


class TestTier1PatchMechanics:
    """The diff, exercised against real `git`. No cluster required.

    `git apply --check` and `git apply` both run here, in a scratch directory, so
    the mechanism the live test depends on is proven before anyone needs a k3s.
    This is the part of 4.3.4 that *can* be verified on a laptop, and skipping
    that would mean shipping a diff nobody had ever applied.
    """

    @pytest.fixture
    def patched(self) -> Iterator[Path]:
        """A patched manifest in a throwaway directory outside the repository.

        The scratch tree is created by `_apply_tier1_patch` and removed here. It
        is a system temp directory rather than a path inside the checkout, so
        this cleanup is tidiness rather than correctness - nothing is left in
        the working tree for a later run to trip over either way.
        """
        result = _apply_tier1_patch()
        try:
            yield result
        finally:
            # `result` is <scratch>/tests/fixtures/bounded-leak.yaml, so the
            # scratch root is three levels up. Derived from the path rather than
            # returned alongside it, so the two cannot drift apart.
            scratch = result.parents[2]
            if scratch.exists() and scratch.is_relative_to(Path(tempfile.gettempdir())):
                shutil.rmtree(scratch, ignore_errors=True)

    def test_the_patch_is_written_with_unix_line_endings(self) -> None:
        """The patch file must be LF, whatever the host platform does.

        A regression guard on a bug that cost real time: on Windows,
        `Path.write_text` translates every `\n` to `\r\n`, so the patch carried
        carriage returns the manifest does not have and `git apply` refused it
        with `patch does not apply` at a line whose context was byte-identical.
        The same code passes on Linux, so CI would never have shown it - which is
        why the invariant is asserted here rather than left to the platform.
        """
        patch = _tier1_patch(FROM_LIMIT, TO_LIMIT)
        assert "\r" not in patch, "the generated patch contains a carriage return"
        with tempfile.NamedTemporaryFile(
            "w", suffix=".patch", encoding="utf-8", newline="\n", delete=False
        ) as handle:
            handle.write(patch)
            written = Path(handle.name)
        try:
            assert b"\r" not in written.read_bytes(), (
                "writing the patch through text mode re-introduced CRLF; the "
                "manifest is LF and git matches context byte for byte"
            )
        finally:
            written.unlink(missing_ok=True)
        # And the manifest it must match is LF too, so the two agree.
        assert b"\r" not in TARGET_MANIFEST.read_bytes()

    def test_the_patch_passes_git_apply_check(self) -> None:
        """The Tier-1 patch is syntactically applicable, proven by real git."""
        patch = _tier1_patch(FROM_LIMIT, TO_LIMIT)
        assert "--- a/" in patch and "+++ b/" in patch
        assert patch.startswith("diff --git ")
        # git itself is the authority on whether the hunk is well-formed; a
        # string check on the header proves nothing about the body.
        _apply_tier1_patch()  # raises RuntimeError if --check or apply fails

    def test_the_patch_raises_the_limit_and_changes_nothing_else(
        self, patched: Path
    ) -> None:
        original = TARGET_MANIFEST.read_text(encoding="utf-8")
        applied = patched.read_text(encoding="utf-8")
        assert f"memory: {TO_LIMIT}" in applied
        assert f"memory: {FROM_LIMIT}" not in applied
        differing = [
            (a, b)
            for a, b in zip(original.splitlines(), applied.splitlines())
            if a != b
        ]
        assert len(differing) == 1, (
            f"the patch changed {len(differing)} lines, expected exactly 1: "
            f"{differing}"
        )

    def test_the_source_manifest_is_never_mutated(self, patched: Path) -> None:
        """The live test must not dirty the working tree.

        A test that leaves `tests/fixtures/bounded-leak.yaml` at 128Mi would make
        the *next* run's fault path unreachable, and the failure would surface
        three steps later as a verdict that made no sense.
        """
        assert f"memory: {FROM_LIMIT}" in TARGET_MANIFEST.read_text(encoding="utf-8")
        assert patched.resolve() != TARGET_MANIFEST.resolve()

    def test_the_manifest_line_is_located_by_value_not_by_offset(self) -> None:
        """The anchor is unique, and it is the line the diff will replace.

        Uniqueness is the point. If the manifest ever grew a second memory limit
        - a sidecar, a second container - a value-based anchor would still
        resolve, and picking the first match would build a hunk against a limit
        that is not the container under test.
        """
        lines = TARGET_MANIFEST.read_text(encoding="utf-8").splitlines()
        memory_lines = [
            (i, line)
            for i, line in enumerate(lines, start=1)
            if line.strip().startswith("memory:")
        ]
        assert len(memory_lines) == 1, (
            f"the fixture has {len(memory_lines)} memory limits; a value-based "
            f"anchor would be ambiguous: {memory_lines}"
        )
        line_no = _memory_limit_line()
        assert lines[line_no - 1] == memory_lines[0][1]
        assert lines[line_no - 1].strip() == f"memory: {FROM_LIMIT}"

    def test_the_anchor_refuses_rather_than_guessing(self, tmp_path: Path) -> None:
        """A manifest with no matching value must raise, not fall back.

        The failure this prevents is subtle: a fallback would build a hunk
        against whatever line it picked instead, `git apply` would either reject
        it or - worse - apply it somewhere valid and unrelated, and the test
        would then verify a manifest nobody intended to change.
        """
        absent = tmp_path / "no-such-limit.yaml"
        absent.write_text("resources:\n  limits:\n    cpu: 100m\n", encoding="utf-8")
        with pytest.raises(RuntimeError, match="no line reading exactly"):
            _memory_limit_line(absent)


class TestNamespaceLifecycle:
    """The namespace is created by *applying* a manifest, not by rendering one.

    Regression coverage for the defect CI run `36785803765` reported:

        could not label namespace 'srek3s-verify-chaos' with
        'app.kubernetes.io/part-of': namespaces "srek3s-verify-chaos" not found

    The cause was `kubectl create namespace ... --dry-run=client -o yaml`: it
    exits 0 and writes the manifest to stdout, having submitted nothing. The
    code checked the exit status, discarded the stdout, and then tried to label
    a namespace that did not exist. Every command along the way reported
    success.
    """

    def test_the_manifest_is_applied_not_merely_rendered(self) -> None:
        """The create path must submit the manifest.

        Asserted structurally: the namespace is created by `apply -f -` with the
        rendered document on stdin. There is no code path left that renders a
        manifest and discards it, which is the shape that failed.
        """
        tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"))
        fn = next(
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef) and node.name == "verify_namespace"
        )
        # Both call shapes. `_kubectl_raw([...])` is a bare Name, so a collector
        # that only reads `ast.Attribute` sees nothing - which is what the first
        # version of this test did, and why it failed on correct code.
        invoked: set[str] = set()
        for node in ast.walk(fn):
            if not isinstance(node, ast.Call):
                continue
            if isinstance(node.func, ast.Name):
                invoked.add(node.func.id)
            elif isinstance(node.func, ast.Attribute):
                invoked.add(node.func.attr)
        assert "_kubectl_raw" in invoked, (
            f"the namespace create path must go through _kubectl_raw; found "
            f"{sorted(invoked)}"
        )

        # The argv actually handed to kubectl, and the keywords beside it.
        argvs: list[list[str]] = []
        for node in ast.walk(fn):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "_kubectl_raw"
                and node.args
                and isinstance(node.args[0], ast.List)
            ):
                argvs.append(
                    [
                        element.value
                        for element in node.args[0].elts
                        if isinstance(element, ast.Constant)
                        and isinstance(element.value, str)
                    ]
                )
        # No `--dry-run` anywhere in the create path: rendering is not creating.
        # This is the assertion that pins the CI defect - the flag renders a
        # manifest to stdout, submits nothing, and exits 0.
        for argv in argvs:
            assert "--dry-run" not in argv, (
                f"the namespace create path must not use --dry-run: {argv}. It "
                "renders without submitting, which is the defect this test pins"
            )
        # And something must actually submit: `apply -f -` with the manifest on
        # stdin. Without this the assertions above would be satisfied by a create
        # path that does nothing at all.
        assert any(
            argv[:2] == ["apply", "-f"] for argv in argvs
        ), f"expected an `apply -f -` in the create path, found {argvs}"

    def test_the_manifest_carries_the_ratified_psa_labels(self) -> None:
        """Enforcement terms are copied from `sentinel-chaos`, not restated.

        A verification fixture admitted under laxer terms than the fixtures it
        verifies against would be testing a different environment than the one
        the system ships in. Deriving them from the ratified manifest means a
        future change to the enforcement is picked up here automatically.
        """
        rendered = yaml.safe_load(_namespace_manifest())
        assert rendered["kind"] == "Namespace"
        assert rendered["metadata"]["name"] == VERIFY_NAMESPACE

        ratified = yaml.safe_load(NAMESPACE_MANIFEST.read_text(encoding="utf-8"))
        expected = dict((ratified.get("metadata") or {}).get("labels") or {})
        actual = dict(rendered["metadata"]["labels"])
        # The name label is namespace-specific and carried over verbatim.
        assert actual == expected, (
            f"PSA labels drifted from the ratified namespace: "
            f"missing={set(expected) - set(actual)} extra={set(actual) - set(expected)}"
        )
        for key in ("enforce", "enforce-version", "audit", "warn"):
            assert f"pod-security.kubernetes.io/{key}" in actual

    def test_the_warning_annotation_names_this_namespace(self) -> None:
        """Whoever runs `kubectl get ns` should be told what this is.

        The ratified manifest carries a warning annotation; copying it verbatim
        would tell a reader this namespace is `sentinel-chaos` and that deleting
        it is safe - which is true of that namespace and misleading here.
        """
        rendered = yaml.safe_load(_namespace_manifest())
        warning = str(rendered["metadata"]["annotations"]["srek3s.io/warning"])
        assert VERIFY_NAMESPACE in warning
        assert "4.3" in warning


def _peak_multiples() -> tuple[float, ...]:
    """Peak-to-payload multiples checked at both ends and the midpoint.

    Ends plus a midpoint rather than a sweep, because the assertion is about
    margins and the margins are monotonic in the multiple - if both ends hold,
    the interval between them holds.
    """
    mid = (PEAK_MULTIPLE_MIN + PEAK_MULTIPLE_MAX) / 2
    return (PEAK_MULTIPLE_MIN, mid, PEAK_MULTIPLE_MAX)


def _mib(quantity: str) -> int:
    """Parse a Kubernetes memory quantity into bytes.

    Only the units this file uses, deliberately. A general parser here would be
    untested code standing between the test and its conclusion - and the two
    quantities involved are constants in this same file.
    """
    units = {"Mi": 2**20, "Ki": 2**10, "Gi": 2**30, "M": 10**6, "G": 10**9, "K": 10**3}
    for suffix, factor in sorted(units.items(), key=lambda kv: -len(kv[0])):
        if quantity.endswith(suffix):
            return int(quantity[: -len(suffix)]) * factor
    raise ValueError(f"unrecognised memory quantity: {quantity!r}")


def test_this_file_holds_no_mutating_kubectl_verb_outside_the_sync_helper() -> None:
    """The harness may apply manifests; nothing else here may.

    Scoped to the reader's observation path, because a GitOps stand-in that
    could not apply anything would not be a stand-in for anything.
    """
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"))
    reader_cls = next(
        cls
        for cls in ast.walk(tree)
        if isinstance(cls, ast.ClassDef) and cls.name == "KubectlObservationReader"
    )
    read_fn = next(
        node
        for node in reader_cls.body
        if isinstance(node, ast.FunctionDef) and node.name == "read"
    )
    # `read` delegates downward only. Every verb it can reach travels through
    # `_kubectl`, which is asserted read-only above.
    delegated = {
        node.func.attr
        for node in ast.walk(read_fn)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    }
    assert "_kubectl" in delegated
    assert not delegated & {"_kubectl_apply", "sync"}


def test_the_offline_halves_are_not_gated_on_a_cluster() -> None:
    """A regression guard on the file's own structure.

    If the parsing and read-only assertions were ever moved behind the cluster
    skip, `pytest agent/tests/` would report green on a machine with no cluster
    while proving nothing. This asserts they are reachable without one.
    """
    live = TestGitOpsPostRemediationLoop
    offline = [TestReaderParsing, TestReaderIsReadOnly]
    assert offline, "the offline suites disappeared"
    for suite in offline:
        assert suite is not live
    # The live suite is the only one holding cluster access.
    assert hasattr(live, "test_a_correct_tier1_diff_verifies")


@pytest.mark.parametrize(
    "field",
    ["no_oomkilled_terminations", "no_crashloopbackoff_wait"],
)
def test_the_success_criteria_cannot_be_switched_off(field: str) -> None:
    """Both boolean criteria are pinned true at construction.

    The verification loop's guarantee is "an incident is not closed while the
    fault can still recur". A policy that could set the criterion false would
    make closure a configuration choice, and a configuration choice is not a
    guarantee. This is why ``classify`` consults the fault unconditionally
    rather than branching on the flag.
    """
    with pytest.raises(ValidationError):
        # No `type: ignore` needed, and its absence is itself part of the claim:
        # `False` is a well-typed `bool`, so what rejects it is the model's
        # validator rather than the type checker. A static check could not
        # express this constraint at all, which is why the guard is a
        # construction test.
        SuccessCriteria(**{field: False}, container_uptime_seconds_min=UPTIME_MIN)


def test_the_window_and_uptime_minimum_respect_the_arch_floor() -> None:
    """ARCH 5.2 floors the window at 60s and requires uptime < window.

    A test that passed against a window the specification forbids would prove
    nothing about the specification. Asserted here so tightening either bound
    breaks loudly rather than silently making the live test vacuous.
    """
    assert WATCH_SECONDS >= 60
    assert UPTIME_MIN < WATCH_SECONDS
    assert _policy().watch_duration_seconds == 60
    with pytest.raises(ValidationError):
        VerificationPolicy(
            mode="POST_REMEDIATION_OBSERVATION",
            watch_duration_seconds=30,  # below the floor
            success_criteria=SuccessCriteria(
                no_oomkilled_terminations=True,
                no_crashloopbackoff_wait=True,
                container_uptime_seconds_min=10,
            ),
            max_requeue_attempts=2,
        )


def test_the_observation_model_rejects_an_invisible_container_with_an_uptime() -> None:
    """The distinction the reader's docstring is built on.

    ``None`` means unreadable, ``0`` means just restarted. If the model
    accepted both on an invisible container, the reader could report a
    fabricated uptime for a pod it never saw - and uptime drives the VERIFIED
    verdict, so a fabricated one closes an incident that should have escalated.
    """
    with pytest.raises(ValidationError):
        ContainerObservation(
            visible=False,
            oomkilled_terminations=0,
            crashloopbackoff_wait=False,
            container_uptime_seconds=0,
        )
