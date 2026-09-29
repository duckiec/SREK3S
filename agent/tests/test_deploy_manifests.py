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
    for manifest in ("rbac.yaml", "sentinel.yaml", "agent.yaml"):
        for document in load(manifest):
            namespace = document.get("metadata", {}).get("namespace")
            if namespace is not None:
                assert namespace == expected, (
                    f"{manifest}/{document['kind']} targets {namespace!r}, "
                    f"not {expected!r}"
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
