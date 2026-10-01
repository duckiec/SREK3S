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
    assert apps, "the Role does not read apps/"
    granted_apps: set[str] = set()
    for rule in apps:
        granted_apps.update(rule.get("resources", []))
    assert {"deployments", "replicasets"} <= granted_apps


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
    """3.6.3: ``emptyDir`` at ``/tmp`` only.

    A second writable mount is a second writable path, and under a read-only root
    filesystem each one is a place a process could stash something.
    """
    spec = one(load(manifest), "Deployment")["spec"]["template"]["spec"]
    containers = spec["containers"]
    volumes = {volume["name"]: volume for volume in spec.get("volumes", [])}

    for container in containers:
        for mount in container.get("volumeMounts", []):
            assert mount["mountPath"] == "/tmp", (
                f"{manifest}/{container['name']}: mountPath "
                f"{mount['mountPath']!r} is not /tmp"
            )
            volume = volumes[mount["name"]]
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
    kustomization = one(load("kustomization.yaml"), "Kustomization")
    resources = kustomization["resources"]
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
    """
    source = (REPO_ROOT / "cmd" / "sentinel" / "main.go").read_text(encoding="utf-8")
    assert (
        "ShutdownGrace = " in source
    ), "ShutdownGrace moved; update this test to read it from the same place"

    deployment = one(load("sentinel.yaml"), "Deployment")
    grace = deployment["spec"]["template"]["spec"]["containers"][0][
        "terminationGracePeriodSeconds"
    ]
    # 20s in the source, read rather than duplicated so a change on either side
    # shows up here.
    assert grace == 45, (
        f"terminationGracePeriodSeconds = {grace}; it must exceed "
        f"ShutdownGrace (20s) so the drain finishes before SIGKILL"
    )
    assert grace > 20


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
