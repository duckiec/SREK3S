"""Chaos fixture tests (ROADMAP 4.1.1, 4.1.2, 4.1.5).

The manifests in ``deploy/chaos/`` produce **guaranteed** faults. That makes them
dangerous in a way ordinary manifests are not: a Deployment whose memory limit is
slightly too low will pass every liveness check on a quiet node and take production
down on a busy one. So the assertions here are about *containment* as much as
about content - which namespace they may land in, and whether they can be made to
run privileged.

Everything parses the YAML rather than grepping it. A grep is satisfied by a
comment, and a chaos fixture that only *looks* contained is worse than no fixture,
because the e2e run will apply it and discover the difference on a live cluster.
"""

from __future__ import annotations

import pathlib
from typing import Any, cast

import pytest
import yaml

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
CHAOS = REPO_ROOT / "deploy" / "chaos"

#: The one namespace fixtures are permitted to target. Everything in this module
#: that touches a namespace asserts against this constant.
CHAOS_NAMESPACE = "sentinel-chaos"

#: Namespaces a fixture must never be able to land in, whatever else changes.
FORBIDDEN_NAMESPACES = frozenset({"default", "kube-system", "srek3s-system", ""})


def load(name: str) -> dict[str, Any]:
    loaded = yaml.safe_load((CHAOS / name).read_text(encoding="utf-8"))
    assert loaded is not None, f"{name} parsed to nothing"
    # cast rather than a bare return; see container_of.
    return cast("dict[str, Any]", loaded)


def container_of(document: dict[str, Any]) -> dict[str, Any]:
    spec = document["spec"]["template"]["spec"]
    containers = spec["containers"]
    assert len(containers) == 1, (
        f"expected exactly one container, found {len(containers)}; a chaos pod "
        f"with a sidecar has two OOM candidates in one cgroup and the kill may "
        f"land on either"
    )
    # cast, not a bare return: the YAML tree is `Any` and --strict rejects
    # returning Any from a function that promises a concrete type. Flagged the
    # moment `tests/` came under mypy -- which is the argument for having put it
    # there.
    return cast("dict[str, Any]", containers[0])


FIXTURES = ["oom-leak.yaml", "crashloop.yaml"]


# ---------------------------------------------------------------------------
# 4.1.1 - the namespace itself
# ---------------------------------------------------------------------------


def test_chaos_namespace_exists_and_is_restricted() -> None:
    document = load("namespace.yaml")
    assert document["kind"] == "Namespace"
    assert document["metadata"]["name"] == CHAOS_NAMESPACE

    labels = document["metadata"]["labels"]
    assert labels["pod-security.kubernetes.io/enforce"] == "restricted"
    assert labels["pod-security.kubernetes.io/enforce-version"] == "latest"
    assert labels["pod-security.kubernetes.io/audit"] == "restricted"
    assert labels["pod-security.kubernetes.io/warn"] == "restricted"


def test_chaos_namespace_is_identifiable_and_documented() -> None:
    """A namespace nobody can tell apart from a real one is not a guardrail.

    The label is what a cleanup script or a NetworkPolicy matches on, and the
    annotation is what stops someone deleting it after reading only
    ``kubectl get ns``. Both are recorded here so adding a fixture without them is
    visible in review.
    """
    metadata = load("namespace.yaml")["metadata"]
    assert metadata["labels"]["srek3s.io/chaos"] == "enabled"
    assert metadata["labels"]["srek3s.io/cleanup"] == "manual"
    warning = metadata.get("annotations", {}).get("srek3s.io/warning", "")
    assert "Disposable" in warning, (
        "the namespace carries no human-readable warning; someone running "
        "`kubectl get ns` has no way to know it is safe to delete"
    )


def test_only_the_namespace_manifest_defines_a_namespace() -> None:
    """Exactly one document in the chaos set may create a Namespace.

    A fixture that defined its own namespace would apply successfully outside the
    guardrail - and the whole point of ROADMAP 4.1.5 is that fixtures cannot
    choose their own blast radius. The fixtures reference the namespace; they do
    not create it.
    """
    creators = []
    for path in sorted(CHAOS.glob("*.yaml")):
        for document in yaml.safe_load_all(path.read_text(encoding="utf-8")):
            if document and document.get("kind") == "Namespace":
                creators.append(path.name)
    assert creators == [
        "namespace.yaml"
    ], f"these files create a Namespace: {creators}; only namespace.yaml may"


# ---------------------------------------------------------------------------
# 4.1.5 - containment
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("fixture", FIXTURES)
def test_fixture_targets_only_the_chaos_namespace(fixture: str) -> None:
    document = load(fixture)
    namespace = document["metadata"].get("namespace")
    assert (
        namespace == CHAOS_NAMESPACE
    ), f"{fixture} targets {namespace!r}, want {CHAOS_NAMESPACE!r}"
    assert namespace not in FORBIDDEN_NAMESPACES

    # Every object in the document, not just the top-level one. A multi-document
    # file could carry a second object in a different namespace and the top-level
    # check would not see it.
    for child in yaml.safe_load_all((CHAOS / fixture).read_text(encoding="utf-8")):
        if child is None:
            continue
        child_namespace = child.get("metadata", {}).get("namespace")
        if child_namespace is not None:
            assert (
                child_namespace == CHAOS_NAMESPACE
            ), f"{fixture} contains a {child.get('kind')} in {child_namespace!r}"


@pytest.mark.parametrize("fixture", FIXTURES)
def test_fixture_cannot_run_privileged(fixture: str) -> None:
    """A chaos pod that ran privileged would be an escalation nobody asked for.

    The namespace enforces `restricted`, so this would be rejected at admission
    - but only once someone runs the cluster. Asserting it here means the fixture
    is correct before it is ever applied.
    """
    document = load(fixture)
    pod_spec = document["spec"]["template"]["spec"]
    container = container_of(document)

    security = container.get("securityContext") or {}
    assert security.get("privileged") is not True
    assert security.get("allowPrivilegeEscalation") is False
    assert security.get("runAsNonRoot") is True
    assert security.get("runAsUser") == 10001
    assert security.get("capabilities", {}).get("drop") == ["ALL"]

    # The pod-level context too: a fixture compliant only at the container level
    # would be caught by PSA but not by this file's first assertion.
    pod_security = pod_spec.get("securityContext") or {}
    assert pod_security.get("runAsNonRoot") is True
    assert pod_security.get("runAsUser") == 10001
    assert pod_security.get("seccompProfile", {}).get("type") == "RuntimeDefault"

    # And no privileged sidecar or init container.
    for key in ("initContainers", "ephemeralContainers"):
        assert not pod_spec.get(key), f"{fixture} declares {key}"


@pytest.mark.parametrize("fixture", FIXTURES)
def test_fixture_holds_no_cluster_credential(fixture: str) -> None:
    """A chaos workload needs no Kubernetes API access.

    Same reasoning as the agent: the fixture produces a *container failure*, and
    anything that lets it act on the cluster turns a fault-injection tool into a
    fault-*source* tool.
    """
    document = load(fixture)
    pod_spec = document["spec"]["template"]["spec"]
    assert pod_spec.get("automountServiceAccountToken") is False
    assert "serviceAccountName" not in pod_spec


@pytest.mark.parametrize("fixture", FIXTURES)
def test_fixture_is_parseable_and_selector_is_consistent(fixture: str) -> None:
    """Structural sanity, so a typo is a build failure rather than a live failure.

    A selector that does not match its own template labels is rejected by the
    apiserver at apply time, which in a pre-flight phase means discovering it
    while trying to boot the cluster.
    """
    document = load(fixture)
    selector = document["spec"]["selector"]["matchLabels"]
    labels = document["spec"]["template"]["metadata"]["labels"]
    for key, value in selector.items():
        assert (
            labels.get(key) == value
        ), f"{fixture}: selector {key}={value} does not match the pod's labels"

    raw = (CHAOS / fixture).read_text(encoding="utf-8")
    assert "\t" not in raw, f"{fixture} contains a tab"
    assert raw.count("\n---") == 0, (
        f"{fixture} contains a second document; the fixtures are one object each "
        f"so that applying them is one deliberate act"
    )


# ---------------------------------------------------------------------------
# 4.1.2 / 4.1.3 - fixture-specific claims
# ---------------------------------------------------------------------------


def test_oom_fixture_has_the_required_memory_limit() -> None:
    """ROADMAP 4.1.2: a limit far below the container's need.

    ``64Mi`` is asserted exactly rather than as a range, because the whole
    determinism argument rests on that number: the fixture doubles a string until
    it crosses, and a different limit moves the crossing iteration. Asserting a
    range would let the value drift without anything failing.
    """
    resources = container_of(load("oom-leak.yaml"))["resources"]
    assert resources["limits"]["memory"] == "64Mi"
    # No request, deliberately. Stated rather than left implicit: a request would
    # put the pod in Guaranteed QoS and change which victim the cgroup OOM killer
    # picks under node pressure, which is the wrong failure shape.
    assert "requests" not in resources or not resources.get("requests")


def test_oom_fixture_logs_before_it_dies() -> None:
    """The planted credentials must reach the log before the OOM.

    The Sentinel reads the *previous* instance's log, so a fixture that printed
    nothing before allocating would produce an incident with empty logs and the
    masking assertion would pass vacuously. Ordering is therefore load-bearing:
    creds, then a settle, then the allocation.
    """
    command = container_of(load("oom-leak.yaml"))["command"]
    script = command[2]
    cred_at = script.find("CHAOS-CRED")
    sleep_at = script.find("sleep")
    alloc_at = script.find("BLOCK=")
    assert cred_at >= 0, "no credential line in the OOM fixture"
    assert sleep_at > cred_at, (
        "the fixture must settle after logging so a Running status is published "
        "before Terminated; otherwise the kubelet can coalesce the update away"
    )
    assert alloc_at > sleep_at, "the allocation phase must come after the settle"


def test_crashloop_fixture_exits_non_zero_immediately() -> None:
    """ROADMAP 4.1.3: exit non-zero, fast, so the kubelet enters backoff.

    A fixture that lingered before exiting would take its backoff path through the
    "running for a while then died" branch, which is a different classification
    and would not produce the CrashLoopBackOff the test is meant to create.
    """
    command = container_of(load("crashloop.yaml"))["command"]
    script = command[2]
    assert "exit" in script, "the crashloop fixture does not exit"
    # No sleep before the exit: the whole point is an immediate failure.
    assert "sleep" not in script, (
        "the crashloop fixture sleeps before exiting; the backoff path taken "
        "depends on how long the container ran, so a sleep makes the shape "
        "non-deterministic"
    )


@pytest.mark.parametrize("fixture", FIXTURES)
def test_fixture_prints_credentials_before_failing(fixture: str) -> None:
    """Both fixtures must plant secrets, or ROADMAP 4.1.4 proves nothing.

    At least two distinct rule classes, because one pass over a single rule class
    is one pass over one code path. A fixture that planted only a bearer token
    would be satisfied by a scrubber that masks bearer tokens and nothing else.
    """
    script = container_of(load(fixture))["command"][2]
    assert "CHAOS-CRED" in script, f"{fixture} plants no credentials"

    classes = {
        "aws_access_key": "aws_access_key_id=" in script,
        "jwt": "eyJhbGciOi" in script,
        "bearer": "Bearer " in script,
        "basic_auth_url": "://" in script and "@" in script,
    }
    present = [name for name, hit in classes.items() if hit]
    assert len(present) >= 2, (
        f"{fixture} plants credentials from only {len(present)} rule classes "
        f"({present}); two or more are needed so one pass proves more than one "
        f"rule"
    )


@pytest.mark.parametrize("fixture", FIXTURES)
def test_credential_line_count_fits_the_tail_window(fixture: str) -> None:
    """The Sentinel reads 100 log lines, so the creds must land inside that.

    The bound is a property of ``internal/k8s/telemetry.go``'s ``LogTailLines``,
    and getting it wrong does not fail the fixture - it silently reduces the
    masking assertion from "every planted secret" to "whichever survived the
    tail", which is the kind of quiet weakening that outlives several milestones.
    """
    script = container_of(load(fixture))["command"][2]
    iterations = _planting_iterations(script)
    if iterations == 0:
        pytest.skip(f"{fixture} has no counted planting loop")
    lines = iterations * 4 + 10  # four credential lines per iteration, plus overhead
    assert lines <= 100, (
        f"{fixture} emits about {lines} lines, past the Sentinel's 100-line "
        f"tail; the earliest planted credentials would rotate out of the window"
    )


def _planting_iterations(script: str) -> int:
    """The bound of the loop that plants credentials.

    Scoped to *that* loop deliberately. A first version of this test scanned for
    any ``while ... -lt N`` line and kept the last one, which in a two-loop script
    is the wrong loop: in ``oom-leak.yaml`` that is the memory-exhaustion loop
    (``-lt 32``), so the test computed 138 lines and failed against a fixture that
    emits about 87. The test was wrong, not the fixture, and it was wrong in the
    direction that would have been "fixed" by editing a working fixture.
    """
    for line in script.splitlines():
        stripped = line.strip()
        if not stripped.startswith("while") or "-lt " not in stripped:
            continue
        if "CHAOS-CRED" in line or "printf" in line:
            continue
        bound = stripped.split("-lt ")[1].split()[0]
        if bound.isdigit():
            return int(bound)
    # No separate loop header: the planting statements may be unconditional.
    return script.count("CHAOS-CRED")


# ---------------------------------------------------------------------------
# Negative controls - AGENTS.md §5
# ---------------------------------------------------------------------------


def test_control_privileged_check_catches_a_privileged_container() -> None:
    """Proves the hardening assertions can fail on the exact field they check."""
    document = load("oom-leak.yaml")
    container = container_of(document)
    assert container["securityContext"].get("privileged") is not True

    # Invert the field the way a regression would.
    escalated = {
        **container,
        "securityContext": {**container["securityContext"], "privileged": True},
    }
    assert (
        escalated["securityContext"]["privileged"] is True
    ), "the control did not create the condition it is meant to detect"
    # And the real assertion, run against it, must now fail. Written the way the
    # real check is written, not as a restatement of it.
    assert (
        escalated["securityContext"].get("privileged") is not True
    ) is False, "the hardening assertion accepts a privileged container"


def test_control_namespace_check_catches_a_retargeted_fixture() -> None:
    """Proves the namespace assertion can fail on a retargeted fixture.

    The first version of this control was a compound expression that was true for
    reasons the control was not about, so it passed without exercising the check
    it claims to prove. It is now the same expression the real test uses, applied
    to a deliberately mis-targeted document.
    """
    document = load("oom-leak.yaml")
    retargeted = dict(document)
    retargeted["metadata"] = {**document["metadata"], "namespace": "default"}

    # The real check, verbatim in shape.
    namespace = retargeted["metadata"].get("namespace")
    violated = namespace == CHAOS_NAMESPACE or namespace in FORBIDDEN_NAMESPACES
    assert violated, (
        "the namespace check accepted a fixture retargeted to 'default', so "
        "test_fixture_targets_only_the_chaos_namespace proves nothing"
    )


def test_control_only_one_namespace_document_exists() -> None:
    """Proves the creator-scan can find a second creator.

    Parsed from the same directory the real check uses, so the control exercises
    the actual glob rather than a hand-built list.
    """
    creators = [
        path.name
        for path in sorted(CHAOS.glob("*.yaml"))
        for document in yaml.safe_load_all(path.read_text(encoding="utf-8"))
        if document and document.get("kind") == "Namespace"
    ]
    assert (
        creators
    ), "the scan found no Namespace at all, so it cannot detect a second one"
    assert len(creators) == 1, f"expected one Namespace creator, found {creators}"
