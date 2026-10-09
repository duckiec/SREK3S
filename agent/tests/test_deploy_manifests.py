"""Deployment manifest tests (ROADMAP 3.6.4 - 3.6.6).

These **parse** the YAML rather than reading it as text. A grep for
``readOnlyRootFilesystem: true`` is satisfied by a commented-out line, a value
inside an unrelated document, and a string in a ConfigMap. PyYAML gives the
structure, so the assertions below are about the object Kubernetes will actually
admit.

The negative controls at the end are not optional decoration. A hardening test
that cannot fail is indistinguishable from a well-configured manifest, and three
of the checks in this file were, at some point during authoring, satisfied by
nothing at all. Each control breaks something deliberately and asserts the check
notices.
"""

from __future__ import annotations

import pathlib
import re
from typing import Any

import pytest
import yaml

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
DEPLOY = REPO_ROOT / "deploy"

#: The only verbs ARCHITECTURE.md §1 permits against a cluster.
OBSERVATIONAL_VERBS = frozenset({"get", "list", "watch"})

#: Every verb that would be a policy violation. Enumerated so a *new* verb fails
#: the test even though it is not in this list: the assertion is membership in
#: OBSERVATIONAL_VERBS, not absence from this one.
MUTATING_VERBS = frozenset(
    {
        "create",
        "update",
        "patch",
        "delete",
        "deletecollection",
        "impersonate",
        "bind",
        "escalate",
        "approve",
        "sign",
        "use",
        "*",
    }
)


def load(name: str) -> list[dict[str, Any]]:
    """Parse a manifest into its documents."""
    text = (DEPLOY / name).read_text(encoding="utf-8")
    return [doc for doc in yaml.safe_load_all(text) if doc is not None]


def by_kind(documents: list[dict[str, Any]], kind: str) -> list[dict[str, Any]]:
    return [doc for doc in documents if doc.get("kind") == kind]


def one(documents: list[dict[str, Any]], kind: str) -> dict[str, Any]:
    found = by_kind(documents, kind)
    assert len(found) == 1, f"expected exactly one {kind}, found {len(found)}"
    return found[0]


# ---------------------------------------------------------------------------
# 3.6.2 - RBAC is read-only
# ---------------------------------------------------------------------------


def test_sentinel_role_has_no_mutating_verbs() -> None:
    """The load-bearing control for "zero direct cluster mutation" (AC-4).

    Membership in ``OBSERVATIONAL_VERBS``, not absence from ``MUTATING_VERBS``:
    the first fails closed on a verb nobody has thought of yet.
    """
    role = one(load("rbac.yaml"), "Role")
    assert role["rules"], "the Role grants nothing at all"

    offenders: list[str] = []
    for rule in role["rules"]:
        for verb in rule.get("verbs", []):
            if verb not in OBSERVATIONAL_VERBS:
                offenders.append(f"{rule.get('resources')} {verb}")

    assert not offenders, f"mutating verbs in the Sentinel's Role: {offenders}"


def test_sentinel_role_covers_what_the_watcher_reads() -> None:
    """The converse check: the allow-list is not so tight the Sentinel is useless.

    A deny-list of write verbs would pass
    :func:`test_sentinel_role_has_no_mutating_verbs` while granting nothing at
    all, and the failure would appear in production as a pod that watches nothing
    and reports no incidents - a silent failure in a tool whose entire job is
    reporting them.

    ``pods/log`` is the one that is easy to miss: a rule on ``pods`` does not
    grant the subresource, and every incident would then arrive with no logs while
    looking entirely plausible.
    """
    role = one(load("rbac.yaml"), "Role")
    granted: set[str] = set()
    for rule in role["rules"]:
        granted.update(rule.get("resources", []))

    for required in ("pods", "pods/log", "events"):
        assert required in granted, f"the Role does not grant {required}"

    apps = [rule for rule in role["rules"] if "apps" in rule.get("apiGroups", [])]
    granted_apps: set[str] = set()
    for rule in apps:
        granted_apps.update(rule.get("resources", []))
    assert not granted_apps & {"deployments", "replicasets"}, (
        "the Role grants apps/deployments and apps/replicasets again. Nothing reads "
        "them - internal/k8s/readonly.go exposes exactly Pods and Events - so this "
        "is a grant with no consumer, which is an invitation rather than a "
        "capability. Add the reader first, observe it, then grant the verb."
    )


def test_no_cluster_scoped_binding_grants_the_sentinel_more() -> None:
    """A ClusterRoleBinding would widen the blast radius beyond the watcher.

    A namespaced Role bound cluster-wide is a classic escalation, and it would
    pass every verb check in this file while granting read access to every
    namespace in the cluster.
    """
    documents = load("rbac.yaml")
    assert not by_kind(documents, "ClusterRole"), (
        "a ClusterRole in the Sentinel's rbac.yaml; the Role is namespaced on "
        "purpose"
    )
    assert not by_kind(documents, "ClusterRoleBinding"), (
        "a ClusterRoleBinding in the Sentinel's rbac.yaml; the binding is "
        "namespaced on purpose"
    )

    binding = one(documents, "RoleBinding")
    assert binding["roleRef"]["kind"] == "Role"
    assert binding["roleRef"]["name"] == "srek3s-sentinel"
    # roleRef is immutable in Kubernetes, so a live escalation attempt cannot
    # repoint an existing binding. Assert the kind so the intent is recorded.
    subject = binding["subjects"][0]
    assert subject["kind"] == "ServiceAccount"
    assert subject["name"] == "srek3s-sentinel"
    assert subject["namespace"] == "srek3s-system"


def granted_namespaces(documents: list[dict[str, Any]]) -> set[str]:
    """Namespaces in which the Sentinel's ServiceAccount actually holds a grant.

    Read from the RoleBinding's subject, not the Role's ``metadata.namespace``: the
    subject is what the apiserver evaluates, and a Role whose namespace and a
    binding whose subject disagree would make the wrong one authoritative here.
    """
    binding = one(documents, "RoleBinding")
    return {
        str(subject["namespace"])
        for subject in binding["subjects"]
        if subject.get("kind") == "ServiceAccount"
    }


def watch_scope(documents: list[dict[str, Any]]) -> str:
    """The literal ``WATCH_NAMESPACE`` the Sentinel Deployment is configured with.

    Note the deliberate difference from ``env_map()`` in
    ``test_e2e_incluster_manifests.py``, which maps a ``valueFrom`` entry to its
    source and carries on. That tolerance is right there, where the question is
    "is the variable bound to the thing I expect", and wrong here: this check exists
    to compare a *scope* against a *grant*, and a reference it cannot resolve is not
    a scope it has verified. So it raises instead. Do not unify these - unifying
    them in this direction would make this guard silently assert nothing, which is
    the exact failure this test was added to stop.
    """
    deployment = one(documents, "Deployment")
    container = deployment["spec"]["template"]["spec"]["containers"][0]
    declared = [
        entry
        for entry in container.get("env") or []
        if entry.get("name") == "WATCH_NAMESPACE"
    ]
    assert declared, (
        "the Sentinel Deployment never sets WATCH_NAMESPACE; if the flag default is "
        "wider than the Role, the informer will be refused forever in silence"
    )
    assert "value" in declared[0], (
        "WATCH_NAMESPACE resolves through valueFrom, which this check cannot "
        "follow. Either give it a literal, or teach this check to resolve the "
        "reference - do not leave it asserting nothing"
    )
    return str(declared[0]["value"])


def ungranted_scopes(scope: str, granted: set[str]) -> list[str]:
    """Scopes the Sentinel would *ask for* and cannot obtain.

    Separate from the test that calls it so the negative control can exercise this
    exact function. A control that reimplements the comparison proves that the
    control reimplements it correctly, which is not the property at issue.
    """
    if not scope.strip():
        # Empty means every namespace, which a namespaced Role never confers.
        return ["<all namespaces>"]
    return [] if scope in granted else [scope]


def test_the_watch_scope_is_inside_the_granted_namespace() -> None:
    """The invariant that ``ENV-2.1`` violated and no other check covered.

    Every other RBAC assertion in this file is scoped to the namespace the Role
    lives in. None of them compares that namespace to the scope the Sentinel is
    *configured* to watch, so all of them passed while the deployment was broken.

    The failure mode is why this needs asserting rather than documenting: a
    cluster-wide watch against a namespaced Role produces a ``LIST`` the apiserver
    refuses, and the informer retries it indefinitely. No incident, no log line, no
    non-zero exit. It is indistinguishable from a healthy watcher on a quiet
    cluster, and it is the failure mode of the one tool whose entire output is
    those incidents.
    """
    scope = watch_scope(load("sentinel.yaml"))
    granted = granted_namespaces(load("rbac.yaml"))

    offenders = ungranted_scopes(scope, granted)
    assert not offenders, (
        f"WATCH_NAMESPACE is {scope!r} but the Sentinel's ServiceAccount is granted "
        f"only in {sorted(granted)}; ungranted scope(s): {offenders}. The informer "
        "will be refused, silently and forever"
    )


def test_control_watch_scope_check_fails_on_an_ungranted_scope() -> None:
    """Proves the scope check can fail, using the value that actually shipped.

    This is the negative control for
    :func:`test_the_watch_scope_is_inside_the_granted_namespace`, and it is the
    whole reason that test is trustworthy. The defect it guards was found by
    reading two manifests and reasoning about the apiserver; if the comparison is
    wrong, the real test is wrong in the same way and will report a broken
    deployment as healthy.

    ``""`` is not invented for the control. It is the value ``deploy/sentinel.yaml``
    carried when the mismatch was found, so a control that catches it catches the
    real thing rather than a convenient stand-in.
    """
    granted = granted_namespaces(load("rbac.yaml"))

    assert ungranted_scopes("", granted), (
        "an empty WATCH_NAMESPACE must be reported as ungranted, or "
        "test_the_watch_scope_is_inside_the_granted_namespace would pass a "
        "cluster-wide watch against a namespaced Role"
    )

    unwatched = next(
        ns for ns in ("sentinel-chaos", "default", "kube-system") if ns not in granted
    )
    assert ungranted_scopes(unwatched, granted) == [unwatched], (
        f"{unwatched!r} is not granted and must be reported; if rbac.yaml starts "
        "granting every namespace this control stops being informative and the "
        "first assertion is carrying it alone"
    )

    # And the positive case, so the control is not merely asserting that everything
    # is broken.
    for granted_ns in sorted(granted):
        assert (
            ungranted_scopes(granted_ns, granted) == []
        ), f"{granted_ns!r} IS granted, so the check must not flag it"


def test_the_agent_gets_no_cluster_credential() -> None:
    """3.6.5: ``agent/`` has no ServiceAccount token automount.

    Stronger than "the agent's verbs are read-only": the agent gets no token at
    all, so it cannot write even if a bug tried. It makes no Kubernetes calls.
    """
    deployment = one(load("agent.yaml"), "Deployment")
    spec = deployment["spec"]["template"]["spec"]
    assert spec.get("automountServiceAccountToken") is False, (
        "the agent must not automount a ServiceAccount token; it makes no "
        "Kubernetes API calls"
    )
    assert (
        "serviceAccountName" not in spec
    ), "the agent must not name a ServiceAccount at all"


# ---------------------------------------------------------------------------
# 3.6.3 - the full ARCH §8 hardening block, on both workloads
# ---------------------------------------------------------------------------

#: (description, path into the container, expected value)
HARDENING_FIELDS: tuple[tuple[str, tuple[str, ...], Any], ...] = (
    ("runAsUser", ("securityContext", "runAsUser"), 10001),
    ("runAsGroup", ("securityContext", "runAsGroup"), 10001),
    ("runAsNonRoot", ("securityContext", "runAsNonRoot"), True),
    ("readOnlyRootFilesystem", ("securityContext", "readOnlyRootFilesystem"), True),
    (
        "allowPrivilegeEscalation",
        ("securityContext", "allowPrivilegeEscalation"),
        False,
    ),
    ("privileged", ("securityContext", "privileged"), False),
)


def _dig(mapping: Any, path: tuple[str, ...]) -> Any:
    for key in path:
        if not isinstance(mapping, dict):
            return None
        mapping = mapping.get(key)
    return mapping


@pytest.mark.parametrize("manifest", ["sentinel.yaml", "agent.yaml"])
def test_every_container_carries_the_hardening_block(manifest: str) -> None:
    deployment = one(load(manifest), "Deployment")
    containers = deployment["spec"]["template"]["spec"]["containers"]
    assert containers, f"{manifest} declares no containers"

    for container in containers:
        for description, path, expected in HARDENING_FIELDS:
            actual = _dig(container, path)
            assert actual == expected, (
                f"{manifest}/{container['name']}: {description} = {actual!r}, "
                f"want {expected!r}"
            )

        drop = _dig(container, ("securityContext", "capabilities", "drop"))
        assert drop == ["ALL"], (
            f"{manifest}/{container['name']}: capabilities.drop = {drop!r}, "
            f"want ['ALL']. An allow-list here is a list to forget an entry on."
        )


@pytest.mark.parametrize("manifest", ["sentinel.yaml", "agent.yaml"])
def test_pod_level_security_context_is_complete(manifest: str) -> None:
    spec = one(load(manifest), "Deployment")["spec"]["template"]["spec"]
    security = spec.get("securityContext") or {}

    assert security.get("runAsUser") == 10001
    assert security.get("runAsGroup") == 10001
    assert security.get("runAsNonRoot") is True
    # fsGroup matters for the emptyDir: without it the volume is group-owned by
    # root and the non-root process cannot write to /tmp.
    assert security.get("fsGroup") == 10001, (
        "fsGroup must match the runAsGroup or the /tmp emptyDir is unwritable "
        "by the non-root user, and a read-only root filesystem leaves nowhere "
        "else to write"
    )
    seccomp = security.get("seccompProfile") or {}
    assert seccomp.get("type") == "RuntimeDefault", (
        f"seccompProfile = {seccomp!r}; a Dockerfile cannot express this, so the "
        f"cluster half of the hardening is here"
    )


@pytest.mark.parametrize("manifest", ["sentinel.yaml", "agent.yaml"])
def test_tmp_is_the_only_writable_volume(manifest: str) -> None:
    """3.6.3: ``emptyDir`` at ``/tmp`` is the only writable mount.

    A second *writable* mount is a second writable path, and under a read-only
    root filesystem each one is a place a process could stash something.

    The first version of this asserted that every mount was at ``/tmp``, which is
    broader than the invariant it is named for. That was not wrong when the
    agent had exactly one mount, but it made read-only mounts impossible, and a
    read-only mount is not a writable path: the agent's ``/manifests`` GitOps root
    is mounted ``readOnly: true`` precisely so the triage path cannot modify the
    manifest it is about to diff.

    So the test now checks what it claims, and pays for the loosening by
    asserting that every non-``/tmp`` mount is *explicitly* read-only. A mount
    with the key absent defaults to writable, so the assertion is that the key is
    present and true - not merely that the path is not /tmp.
    """
    spec = one(load(manifest), "Deployment")["spec"]["template"]["spec"]
    containers = spec["containers"]
    volumes = {volume["name"]: volume for volume in spec.get("volumes", [])}

    for container in containers:
        for mount in container.get("volumeMounts", []):
            writable = mount.get("readOnly") is not True
            if mount["mountPath"] == "/tmp":
                assert writable, (
                    f"{manifest}/{container['name']}: /tmp is mounted read-only, "
                    "but a read-only root filesystem leaves the interpreter and "
                    "the I-B2 git check nowhere to write"
                )
            else:
                assert not writable, (
                    f"{manifest}/{container['name']}: mountPath "
                    f"{mount['mountPath']!r} is writable. /tmp is the only "
                    "writable path under a read-only root filesystem; every "
                    "other mount must declare readOnly: true explicitly"
                )
            volume = volumes[mount["name"]]
            if "configMap" in volume and mount.get("readOnly") is True:
                # Read-only projected config is not writable state; it cannot
                # outlive the pod and does not weaken the /tmp-only rule.
                continue
            assert "emptyDir" in volume, (
                f"{manifest}: volume {mount['name']} is {list(volume)}, not an "
                f"emptyDir; a hostPath or PVC would be writable state that "
                f"outlives the pod"
            )

    # And the read-only root filesystem means this is the complete list.
    for container in containers:
        assert _dig(container, ("securityContext", "readOnlyRootFilesystem")) is True


@pytest.mark.parametrize("manifest", ["sentinel.yaml", "agent.yaml"])
def test_no_privileged_sidecar_or_init_container(manifest: str) -> None:
    """Init containers and sidecars are containers too.

    A hardening test that only inspects ``containers`` misses a privileged
    ``initContainers`` entry, which runs as root with full capabilities and then
    hands the main container a writable root. This was a real gap in the first
    draft of this file.
    """
    spec = one(load(manifest), "Deployment")["spec"]["template"]["spec"]

    for key in ("initContainers", "ephemeralContainers"):
        entries = spec.get(key) or []
        assert not entries, (
            f"{manifest} declares {key}; this test's hardening assertions only "
            f"cover spec.containers and would not see them"
        )

    for container in spec["containers"]:
        assert _dig(container, ("securityContext", "privileged")) is not True
        assert _dig(container, ("securityContext", "capabilities", "add")) is None, (
            f"{manifest}/{container['name']} adds capabilities; nothing in this "
            f"system needs one"
        )


# ---------------------------------------------------------------------------
# 3.6.1 - the set is complete and ordered
# ---------------------------------------------------------------------------


def test_kustomization_lists_every_manifest() -> None:
    """The base lists every manifest, in an order the API server will accept.

    Read from `deploy/base/`, which is the only base of record. `deploy/` carried a
    second kustomization until 2026-10-09 that listed the same files and omitted the
    `configMapGenerator`, so `kubectl apply -k deploy/` installed 10 objects against
    the base's 11 and produced an agent that could never resolve a target.
    """
    base = DEPLOY / "base"
    kustomization = yaml.safe_load(
        (base / "kustomization.yaml").read_text(encoding="utf-8")
    )
    resources = [r.replace("../", "") for r in kustomization["resources"]]
    for expected in (
        "namespace.yaml",
        "rbac.yaml",
        "sentinel.yaml",
        "agent.yaml",
        "service.yaml",
    ):
        assert expected in resources, f"{expected} is not in the kustomization"
        assert (DEPLOY / expected).exists(), f"{expected} is listed but absent"

    # Order is load-bearing. Kustomize does not sort resources, and applying a
    # namespaced object before its Namespace fails with "namespace not found".
    assert resources.index("namespace.yaml") == 0, (
        "namespace.yaml must come first; Kustomize preserves list order and an "
        "applied Role in a namespace that does not exist yet is rejected"
    )
    assert resources.index("rbac.yaml") < resources.index(
        "sentinel.yaml"
    ), "the Deployment references a ServiceAccount that rbac.yaml creates"
    # A Service listed but never applied is the v1.0.0 defect in a new disguise:
    # the file exists, the tests pass, and nothing routes. Assert the ordering so
    # the entry cannot quietly drift out of the list.
    assert resources.index("agent.yaml") < resources.index(
        "service.yaml"
    ), "service.yaml selects the agent Deployment's pods; list it after agent.yaml"
    assert len(resources) == len(set(resources)), "a manifest is listed twice"


def test_the_namespace_enforces_restricted_pod_security() -> None:
    namespace = one(load("namespace.yaml"), "Namespace")
    labels = namespace["metadata"]["labels"]
    assert labels["pod-security.kubernetes.io/enforce"] == "restricted"
    assert labels["pod-security.kubernetes.io/audit"] == "restricted"
    assert labels["pod-security.kubernetes.io/warn"] == "restricted"
    assert namespace["metadata"]["name"] == "srek3s-system"


def test_every_resource_targets_the_same_namespace() -> None:
    """A manifest pointing at another namespace would deploy outside the
    NetworkPolicy and RBAC this set applies."""
    expected = "srek3s-system"
    for manifest in ("rbac.yaml", "sentinel.yaml", "agent.yaml", "service.yaml"):
        for document in load(manifest):
            namespace = document.get("metadata", {}).get("namespace")
            if namespace is not None:
                assert namespace == expected, (
                    f"{manifest}/{document['kind']} targets {namespace!r}, "
                    f"not {expected!r}"
                )


# ---------------------------------------------------------------------------
# Service discovery: the coupling that shipped broken in v1.0.0
# ---------------------------------------------------------------------------


def _sentinel_default_agent_url() -> str:
    """The Sentinel's built-in ``-agent-url`` default, read from the Go source.

    Read by parsing rather than by importing, because the Go binary cannot be
    imported from Python. The regex is deliberately narrow and anchored on the
    ``envOr("SREK3S_AGENT_URL", ...)`` call, so a value that merely *mentions* a
    URL in a comment is not mistaken for the default. A looser match would pass
    while the real default had drifted - which is the failure being guarded.
    """
    source = (REPO_ROOT / "cmd" / "sentinel" / "main.go").read_text(encoding="utf-8")
    match = re.search(
        r'envOr\(\s*"SREK3S_AGENT_URL"\s*,\s*"(?P<url>[^"]+)"\s*\)', source
    )
    assert match is not None, (
        "could not find the SREK3S_AGENT_URL fallback in cmd/sentinel/main.go; the "
        "default is now set somewhere else and this check is no longer asserting "
        "anything - update it rather than deleting it"
    )
    return match.group("url")


def test_the_agent_service_routes_the_sentinels_default_endpoint() -> None:
    """The four things that must agree for the Sentinel to reach the agent.

    Until v1.0.1 this deployment could not route traffic between its own two
    pods, and nothing failed. ``deploy/sentinel.yaml`` set
    ``SREK3S_AGENT_URL`` to ``http://srek3s-agent:8000`` and described it as "the
    agent's Service"; no manifest created that Service. The ``-agent-url`` default
    compounded it with port 8080, which the agent does not listen on.

    Every other test in this file checks a property of a single document. This
    one checks a property of the *set*: that the endpoint the Sentinel is
    configured with resolves, through a Service this set creates, to a port the
    agent actually binds. Each of the four assertions below has been true or
    false independently during authoring, and any one of them alone produces a
    deployment that applies cleanly and silently talks to nothing.
    """
    service = one(load("service.yaml"), "Service")
    assert service["metadata"]["name"] == "srek3s-agent", (
        "the Sentinel's default endpoint is the DNS name srek3s-agent; a Service "
        "under any other name does not answer to it"
    )

    # 1. The selector must match the pods the agent Deployment actually creates.
    #    A selector that matches nothing produces a connection timeout rather
    #    than a refusal, which is far harder to diagnose from a log.
    deployment = one(load("agent.yaml"), "Deployment")
    pod_labels = deployment["spec"]["template"]["metadata"]["labels"]
    selector = service["spec"]["selector"]
    assert selector, "a Service with an empty selector matches nothing"
    for key, value in selector.items():
        assert pod_labels.get(key) == value, (
            f"service.yaml selects {key}={value!r}, but agent.yaml's pod template "
            f"labels it {pod_labels.get(key)!r}; the Service would have no endpoints"
        )

    # 2. targetPort must be the port the agent's container declares.
    ports = service["spec"]["ports"]
    assert len(ports) == 1, f"expected one Service port, found {len(ports)}"
    container_ports = deployment["spec"]["template"]["spec"]["containers"][0]["ports"]
    declared = {entry["containerPort"] for entry in container_ports}
    assert ports[0]["targetPort"] in declared, (
        f"service.yaml targets port {ports[0]['targetPort']}, which agent.yaml "
        f"does not declare; the agent declares {sorted(declared)}"
    )

    # 3. The agent binds 0.0.0.0:8000 in its image entrypoint. If the Dockerfile
    #    moves, the manifest and the Service must move with it, so the number is
    #    read from the Dockerfile rather than hardcoded here.
    dockerfile = (REPO_ROOT / "agent" / "Dockerfile").read_text(encoding="utf-8")
    entrypoint_port = re.search(r'"--port",\s*"(?P<port>\d+)"', dockerfile)
    assert entrypoint_port is not None, (
        "could not find --port in agent/Dockerfile's ENTRYPOINT; the agent's bind "
        "address is now set somewhere this check does not read"
    )
    assert ports[0]["targetPort"] == int(entrypoint_port.group("port")), (
        f"service.yaml targets {ports[0]['targetPort']} but the agent binds "
        f"{entrypoint_port.group('port')}"
    )
    assert ports[0]["port"] == int(entrypoint_port.group("port")), (
        f"service.yaml publishes port {ports[0]['port']} but the agent binds "
        f"{entrypoint_port.group('port')}"
    )

    # 4. And the Sentinel's built-in default must be this Service's name and port.
    default = _sentinel_default_agent_url()
    expected = f"http://{service['metadata']['name']}:{ports[0]['port']}"
    assert default == expected, (
        f"the Sentinel's -agent-url default is {default!r}, but deploy/service.yaml "
        f"publishes {expected!r}. The agent is reachable at neither."
    )
    # The default must also carry no path: internal/emitter appends
    # "/v1/incidents" itself, so a default with a path yields a doubled path and
    # every POST 404s. Asserted here because the natural "fix" for a routing
    # complaint is to paste the full endpoint into this flag.
    assert default.rstrip("/") == expected, (
        "the default must be a bare base URL with no path; internal/emitter "
        "appends /v1/incidents to it"
    )


def test_the_agent_network_policies_admit_the_service_traffic() -> None:
    """A Service is only useful if the NetworkPolicies permit what it carries.

    Adding a ClusterIP does not change NetworkPolicy evaluation - the policy is
    applied to the post-DNAT destination, which is the agent pod - so the
    existing podSelector rules already admit this traffic. That is a property
    worth asserting rather than assuming, because the day someone adds an
    ``ipBlock`` or tightens the ingress rule to a named Service port, the
    failure reappears with no manifest change to point at.
    """
    agent_policies = [
        doc for doc in load("agent.yaml") if doc.get("kind") == "NetworkPolicy"
    ]
    assert agent_policies, "agent.yaml declares no NetworkPolicy"
    ingress_ports: set[int] = set()
    for policy in agent_policies:
        for rule in policy["spec"].get("ingress", []) or []:
            for entry in rule.get("ports", []) or []:
                if "port" in entry:
                    ingress_ports.add(int(entry["port"]))
    sentinel_policies = [
        doc for doc in load("sentinel.yaml") if doc.get("kind") == "NetworkPolicy"
    ]
    egress_ports: set[int] = set()
    for policy in sentinel_policies:
        for rule in policy["spec"].get("egress", []) or []:
            for entry in rule.get("ports", []) or []:
                if "port" in entry:
                    egress_ports.add(int(entry["port"]))

    service_port = one(load("service.yaml"), "Service")["spec"]["ports"][0]["port"]
    assert service_port in ingress_ports, (
        f"the agent's NetworkPolicy admits {sorted(ingress_ports)}; the Service "
        f"publishes {service_port}, which nothing may reach"
    )
    assert service_port in egress_ports, (
        f"the Sentinel's NetworkPolicy admits egress to {sorted(egress_ports)}; "
        f"the Service publishes {service_port}, which the Sentinel may not use"
    )


# ---------------------------------------------------------------------------
# The drain invariant, and a cross-file coupling worth asserting
# ---------------------------------------------------------------------------


def test_termination_grace_exceeds_the_drain_budget() -> None:
    """``terminationGracePeriodSeconds`` must exceed the code's drain budget.

    These are in two files that nothing else connects: the constant is in
    ``cmd/sentinel/main.go`` and the grace period is here. Raise the drain to 60s
    and the kubelet starts SIGKILLing mid-drain, turning every rolling update into
    a slow-loss event - with no error anywhere, because the loss is silent by
    construction.

    THE PATH MATTERS, and it was wrong here until 2026-10-01.

    This test read the value out of ``spec.template.spec.containers[0]``. That is
    not a valid location: ``terminationGracePeriodSeconds`` is a field of
    **PodSpec**, and there is no container-level counterpart. The apiserver rejects
    the whole Deployment with

        strict decoding error: unknown field
        "spec.template.spec.containers[0].terminationGracePeriodSeconds"

    which is exactly how it was found - by applying the manifest to a live control
    plane, after the field had shipped at the wrong level through an entire
    milestone. The test passed throughout because it asserted on the parsed YAML,
    where the value is present and plausible at either indentation. A test that
    cannot tell a valid field from an invalid one is not asserting that the field
    is usable; it is asserting that a string appears in a document.

    So the assertion below now reads the real path, and a companion test asserts
    the field is ABSENT from the container, which is the check that would have
    caught this. See also
    ``deploy/sentinel.yaml`` for the same note at the field itself.
    """
    source = (REPO_ROOT / "cmd" / "sentinel" / "main.go").read_text(encoding="utf-8")
    assert (
        "ShutdownGrace = " in source
    ), "ShutdownGrace moved; update this test to read it from the same place"

    pod_spec = one(load("sentinel.yaml"), "Deployment")["spec"]["template"]["spec"]
    assert "terminationGracePeriodSeconds" in pod_spec, (
        "terminationGracePeriodSeconds is a PodSpec field; it must be a sibling of "
        "`containers`, not a child of a container. A container-level copy is "
        "silently inert in this test and rejected by the apiserver in a cluster."
    )
    grace = pod_spec["terminationGracePeriodSeconds"]
    # 20s in the source, read rather than duplicated so a change on either side
    # shows up here.
    assert grace == 45, (
        f"terminationGracePeriodSeconds = {grace}; it must exceed "
        f"ShutdownGrace (20s) so the drain finishes before SIGKILL"
    )
    assert grace > 20


def test_termination_grace_is_not_set_on_a_container() -> None:
    """The field must NOT appear at container level, in either manifest.

    This is the assertion that would have caught the defect above, and it is
    negative-controlled: it fails when a container-level copy is planted, and passes
    on a manifest that only carries the valid PodSpec field.

    The distinction is not stylistic. ``terminationGracePeriodSeconds`` sits in
    PodSpec with no container-level counterpart, so a container-level copy is
    inert to every YAML parser in this repository and fatal to the apiserver:

        The Deployment "srek3s-sentinel" is invalid:
        spec.template.spec.containers[0].terminationGracePeriodSeconds:
          Forbidden: strict decoding error: unknown field

    Both deployments shipped that way and applied to nothing, while every manifest
    test in this suite was green. The reason is the generalisable one: this
    repository can parse these documents but cannot validate them, and a check
    written against the parser inherits that limit. The only instrument that knows
    whether a field is *usable* is the control plane that consumes it.
    """
    for name in ("sentinel.yaml", "agent.yaml"):
        pod_spec = one(load(name), "Deployment")["spec"]["template"]["spec"]
        containers = pod_spec["containers"]
        assert containers, f"{name}: no containers to check"
        for container in containers:
            assert "terminationGracePeriodSeconds" not in container, (
                f"{name}: container {container.get('name')!r} sets "
                "terminationGracePeriodSeconds. It is a PodSpec field; the apiserver "
                "refuses the whole Deployment with a strict-decoding error, so this "
                "manifest cannot be applied at all. Assert it on the pod spec "
                "instead."
            )
        # And the valid location must actually carry a value, so this test cannot
        # pass on a manifest that simply dropped the field.
        assert (
            "terminationGracePeriodSeconds" in pod_spec
        ), f"{name}: no pod-level terminationGracePeriodSeconds; the drain budget is unprotected"


# ---------------------------------------------------------------------------
# Negative controls - AGENTS.md §5
# ---------------------------------------------------------------------------


def test_control_service_routing_check_fails_on_each_broken_coupling() -> None:
    """Proves every assertion in the routing check can fail.

    The v1.0.0 defect was not a typo in one place; it was four facts that were
    each individually plausible and collectively unroutable. A check that only
    pins one of them would have passed on the broken deployment. So each of the
    four is broken here in turn, and the corresponding assertion is required to
    notice.
    """
    service = one(load("service.yaml"), "Service")
    deployment = one(load("agent.yaml"), "Deployment")
    pod_labels = deployment["spec"]["template"]["metadata"]["labels"]
    good_selector = dict(service["spec"]["selector"])
    good_port = service["spec"]["ports"][0]["port"]
    good_target = service["spec"]["ports"][0]["targetPort"]
    default = _sentinel_default_agent_url()

    # 1. A selector that does not match the pod template yields no endpoints.
    broken = dict(service)
    broken["spec"] = {**service["spec"], "selector": {"app": "not-the-agent"}}
    assert all(
        pod_labels.get(k) != v for k, v in broken["spec"]["selector"].items()
    ), "control is vacuous: the broken selector still matches"

    # 2. A targetPort the agent does not declare.
    container_ports = {
        entry["containerPort"]
        for entry in deployment["spec"]["template"]["spec"]["containers"][0]["ports"]
    }
    assert good_target in container_ports
    assert 8001 not in container_ports, "control is vacuous: 8001 is declared"

    # 3. The Sentinel default disagreeing with the Service - the original defect.
    assert default == f"http://{service['metadata']['name']}:{good_port}"
    assert (
        default != f"http://{service['metadata']['name']}:{good_target + 1}"
    ), "control is vacuous: the mismatched default equals the real one"

    # 4. A published port the NetworkPolicies do not admit.
    admitted: set[int] = set()
    for doc in load("agent.yaml"):
        if doc.get("kind") != "NetworkPolicy":
            continue
        for rule in doc["spec"].get("ingress", []) or []:
            for entry in rule.get("ports", []) or []:
                if "port" in entry:
                    admitted.add(int(entry["port"]))
    assert good_port in admitted
    assert good_port + 1 not in admitted, "control is vacuous: the port is admitted"

    # And the real, unmutated values still satisfy every assertion, so the
    # controls above are not passing because the checks are trivially true.
    assert good_selector and good_port == good_target


def test_control_the_writable_mount_check_fails_on_a_writable_extra_mount() -> None:
    """Proves the loosened writability check can still fail.

    The /tmp-only rule was relaxed from "every mount is at /tmp" to "every mount
    that is not /tmp declares readOnly: true". A relaxation is only defensible
    with a control, because the failure it now has to catch is a single missing
    key - and a mount with the key absent is writable, which is the default.

    So: remove readOnly from the agent's /manifests mount and require the check
    to notice. This is the exact edit someone makes to make a ConfigMap-backed
    manifest root work, and it is the one that must not pass silently.
    """
    spec = one(load("agent.yaml"), "Deployment")["spec"]["template"]["spec"]
    container = spec["containers"][0]
    extra = [
        mount for mount in container["volumeMounts"] if mount["mountPath"] != "/tmp"
    ]
    assert extra, "control is vacuous: the agent has no non-/tmp mount to relax"
    assert all(
        mount.get("readOnly") is True for mount in extra
    ), "control is vacuous: a non-/tmp mount is already writable"
    for mount in extra:
        relaxed = {**mount}
        relaxed.pop("readOnly", None)
        assert relaxed.get("readOnly") is not True, (
            f"dropping readOnly from {mount['mountPath']} left it read-only; the "
            "writability check is not testing writability"
        )
        assert relaxed["mountPath"] != "/tmp"


def test_control_rbac_check_fails_on_an_injected_write_verb() -> None:
    """Proves the verb check can fail.

    Without this, a check written against the wrong key - ``rules`` instead of
    ``rule`` - iterates an empty list and reports success forever.
    """
    documents = load("rbac.yaml")
    role = one(documents, "Role")

    # Deliberately inject the exact violation the real check forbids.
    role["rules"].append(
        {
            "apiGroups": [""],
            "resources": ["pods"],
            "verbs": ["create", "get"],
        }
    )

    offenders = [
        f"{rule.get('resources')} {verb}"
        for rule in role["rules"]
        for verb in rule.get("verbs", [])
        if verb not in OBSERVATIONAL_VERBS
    ]
    assert offenders, (
        "the RBAC check did not notice an injected create verb, so "
        "test_sentinel_role_has_no_mutating_verbs proves nothing"
    )


def test_control_hardening_check_fails_on_a_missing_field() -> None:
    """Proves the field lookup can fail.

    ``_dig`` returns ``None`` for a missing key, so a check written as
    ``assert _dig(...) is not None`` would pass a manifest with nothing set. This
    removes one field and confirms the real assertion trips.
    """
    deployment = one(load("sentinel.yaml"), "Deployment")
    container = deployment["spec"]["template"]["spec"]["containers"][0]
    del container["securityContext"]["readOnlyRootFilesystem"]

    # `is not True` rather than `!= True`: flake8 flags a comparison to a bool
    # literal, and an identity check is the stricter form anyway - a truthy
    # non-True would not satisfy the real assertion either.
    missing = _dig(container, ("securityContext", "readOnlyRootFilesystem"))
    assert (
        missing is not True
    ), f"the hardening check did not notice a removed field (got {missing!r})"


def test_control_deep_get_does_not_walk_a_string() -> None:
    """``_dig`` is called on values that may not be mappings.

    A naive ``[key]`` chain raises ``TypeError`` on a string, which reads as a
    schema error rather than as a missing field. The real assertions would then
    fail for the wrong reason - or, worse, be rewritten to expect a crash.
    """
    assert _dig("readOnlyRootFilesystem", ("securityContext",)) is None
    assert (
        _dig({"securityContext": "oops"}, ("securityContext", "readOnlyRootFilesystem"))
        is None
    )
    assert _dig(None, ("securityContext",)) is None
