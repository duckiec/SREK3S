"""Offline tests for the E2E in-cluster overlay.

Why this file exists at all
---------------------------
The in-cluster leg of the detonation workflow can only be executed against a
real cluster, so locally it is a blocked dependency and its steps are unproven.
That is exactly the condition under which the previous generation of E2E
coverage went wrong: the code that *could* be checked offline was not checked,
and the part that could not be checked was the only part anybody looked at.

So everything about the overlay that does not need a cluster is checked here:
the manifests parse, their cross-references resolve, the hardening is
present, the base is the real ``deploy/`` and not a copy, and every fixture is
marked as a fixture. What cannot be verified offline - that the pods schedule,
that the NetworkPolicies admit the traffic, that ``srek3s-agent`` resolves - is
asserted by the workflow steps and nowhere here, and the distinction is stated
rather than blurred.

The pattern is the one ``test_deploy_manifests.py`` established, and the reason
is the same: every check in that file asserts a property of a *single*
document, and the defect it missed - v1.0.0's missing Service - was a
disagreement *between* documents. So the tests below mostly hold two or three
objects at once.
"""

from __future__ import annotations

import pathlib
import re
from typing import Any

import pytest
import yaml

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
DEPLOY = REPO_ROOT / "deploy"
OVERLAY = REPO_ROOT / "tests" / "e2e" / "fixtures" / "incluster"

#: The only verbs the Sentinel's Role may carry, in any namespace. Mirrors
#: OBSERVATIONAL_VERBS in test_deploy_manifests.py rather than importing it: that
#: module is a test file, and a test importing another test's internals is a
#: coupling that makes both harder to move.
OBSERVATIONAL_VERBS = frozenset({"get", "list", "watch"})

#: Every verb that would be a policy violation.
MUTATING_VERBS = (
    frozenset(
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
            "watch",
        }
    )
    - OBSERVATIONAL_VERBS
)


def load(path: pathlib.Path) -> list[dict[str, Any]]:
    return [doc for doc in yaml.safe_load_all(path.read_text(encoding="utf-8")) if doc]


def by_kind(documents: list[dict[str, Any]], kind: str) -> list[dict[str, Any]]:
    return [doc for doc in documents if doc.get("kind") == kind]


def one(documents: list[dict[str, Any]], kind: str) -> dict[str, Any]:
    found = by_kind(documents, kind)
    assert len(found) == 1, f"expected exactly one {kind}, found {len(found)}"
    return found[0]


def env_map(document: dict[str, Any]) -> dict[str, Any]:
    """``{name: value}`` for a container's env, tolerating ``valueFrom``.

    A previous revision wrote this as a plain comprehension:

        {entry["name"]: entry["value"] for entry in container["env"]}

    which raises ``KeyError: 'value'`` on the first environment variable sourced
    from a Secret or ConfigMap rather than an inline literal. That is not
    hypothetical: adding ``GEMINI_API_KEY`` via ``valueFrom.secretKeyRef`` to
    deploy/agent.yaml broke every test using this comprehension, and the failure
    looked like a manifest defect rather than a test defect.

    ``valueFrom`` entries map to their source instead of a literal, so a caller
    asserting on them sees *what the variable is bound to* rather than a KeyError.
    That is more useful than either the old crash or silently dropping the key.
    """
    result: dict[str, Any] = {}
    for entry in document["spec"]["template"]["spec"]["containers"][0].get("env") or []:
        if "valueFrom" in entry:
            result[entry["name"]] = entry["valueFrom"]
        else:
            result[entry["name"]] = entry["value"]
    return result


def named(documents: list[dict[str, Any]], kind: str, name: str) -> dict[str, Any]:
    """The one object of `kind` called `name`.

    Needed because the overlay holds more than one Deployment - the capture proxy
    and the routing probe - so `one(..., "Deployment")` became ambiguous the
    moment the probe was added. Selecting by name as well as kind is also what
    stops a test from silently binding to the wrong object when a fourth is
    added later.
    """
    found = [
        doc
        for doc in by_kind(documents, kind)
        if doc.get("metadata", {}).get("name") == name
    ]
    assert len(found) == 1, f"expected exactly one {kind}/{name}, found {len(found)}"
    return found[0]


@pytest.fixture(scope="module")
def extra() -> list[dict[str, Any]]:
    """Every object the in-cluster leg applies from this fixture directory.

    Two files, because they are applied two different ways. `extra-resources.yaml`
    goes through the overlay's kustomization and is therefore subject to its
    `namespace:` transform; `chaos-rbac.yaml` is applied with `kubectl apply -f`
    precisely so it is not, and has to live somewhere other than sentinel-chaos.

    They are unioned here so that every assertion below — the chaos Role mirroring
    the shipped one, the RoleBinding naming the real ServiceAccount, the fixture
    marker on every object, nothing created in a production namespace by accident
    — covers both without special-casing either. A fixture list that silently
    covered only the kustomized half would be a test that passes while half the
    objects under test go unchecked.
    """
    return load(OVERLAY / "extra-resources.yaml") + load(OVERLAY / "chaos-rbac.yaml")


@pytest.fixture(scope="module")
def patch() -> list[dict[str, Any]]:
    return load(OVERLAY / "agent-gitops-patch.yaml")


@pytest.fixture(scope="module")
def kustomization() -> dict[str, Any]:
    return one(load(OVERLAY / "kustomization.yaml"), "Kustomization")


@pytest.fixture(scope="module")
def agent_deployment() -> dict[str, Any]:
    return one(load(DEPLOY / "agent.yaml"), "Deployment")


def _applied_manifests() -> list[tuple[pathlib.Path, dict[str, Any]]]:
    """Every object this repository hands to `kubectl apply`.

    Both the shipped deploy set and the e2e fixture overlay, because both are
    applied to a real cluster and neither is generated.
    """
    found: list[tuple[pathlib.Path, dict[str, Any]]] = []
    for root in (DEPLOY, OVERLAY):
        for path in sorted(root.rglob("*.y*ml")):
            if path.name == "kustomization.yaml":
                continue  # not applied directly; its `resources:` are checked elsewhere
            for document in load(path):
                found.append((path, document))
    return found


def test_every_applied_object_names_a_servable_api_version() -> None:
    """apiVersion must carry group AND version, and every kind must have one.

    `rbac.authorization.k8s.io` is a group with no version and maps to nothing:

        resource mapping not found for name: "srek3s-sentinel" namespace:
        "sentinel-chaos": no matches for kind "Role" in version
        "rbac.authorization.k8s.io"

    That defect was in this repository, in a file written minutes earlier, and it
    survived a 908-test offline suite, a clean `kubectl kustomize` render, and a
    review that described the file as "moved verbatim". Nothing offline can catch
    it, because the file is well-formed YAML and every structural test here reads
    `kind` rather than `apiVersion`.

    Which is the point of asserting it. The rule Kubernetes actually applies is
    narrow and checkable without a cluster: an apiVersion is either the bare
    string `v1` (the core group) or exactly one `/` separating group from
    version. A group-only value has no version to resolve and can never be
    served, by any cluster, under any configuration.

    The `kubectl` hint printed alongside the real failure — "ensure CRDs are
    installed first" — sends the reader after a CRD that does not and cannot
    exist for a built-in kind. Catching the shape here is what stops that hunt.
    """
    offenders = [
        f"{path.relative_to(REPO_ROOT)}: {document.get('apiVersion')!r} "
        f"({document.get('kind')})"
        for path, document in _applied_manifests()
        if not _is_servable_api_version(document.get("apiVersion"))
    ]
    assert not offenders, (
        "an apiVersion that is neither 'v1' nor 'group/version' can never be "
        f"served; kubectl reports these as 'resource mapping not found' and "
        f"misleadingly suggests installing CRDs: {offenders}"
    )


def _is_servable_api_version(value: object) -> bool:
    if not isinstance(value, str) or not value:
        return False
    if value == "v1":  # the core group is spelled without a slash
        return True
    return value.count("/") == 1 and all(part for part in value.split("/"))


def _configmaps_mounted_by_the_overlay() -> dict[str, list[str]]:
    """``{configmap name: [objects that mount it]}`` across the whole overlay."""
    mounted: dict[str, list[str]] = {}
    for path in sorted(OVERLAY.glob("*.yaml")):
        if path.name == "kustomization.yaml":
            continue
        for document in load(path):
            where = f"{document.get('kind')}/{document.get('metadata', {}).get('name')}"
            for volume in _walk(
                document.get("spec", {})
                .get("template", {})
                .get("spec", {})
                .get("volumes", [])
            ):
                name = (volume.get("configMap") or {}).get("name")
                if name:
                    mounted.setdefault(name, []).append(where)
    return mounted


def _configmaps_the_workflow_creates() -> set[str]:
    workflow = yaml.safe_load(
        (REPO_ROOT / ".github" / "workflows" / "e2e-detonation.yaml").read_text(
            encoding="utf-8"
        )
    )
    bodies = "\n".join(
        step.get("run", "")
        for job in (workflow.get("jobs") or {}).values()
        for step in (job.get("steps") or [])
    )
    return set(re.findall(r"create\s+configmap\s+(\S+)", bodies))


def _walk(node: object) -> list[dict[str, Any]]:
    """Every dict in a nested structure, so volumes are found at any depth."""
    if isinstance(node, dict):
        return [node] + [d for child in node.values() for d in _walk(child)]
    if isinstance(node, list):
        return [d for child in node for d in _walk(child)]
    return []


def test_every_configmap_the_overlay_mounts_is_one_the_workflow_creates() -> None:
    """The overlay and the workflow must agree on every ConfigMap name.

    This is the defect class the module docstring says it cannot see, seen
    anyway. Nearly every check here asserts a property of a single document, so
    a name that has to match across two files is exactly what nothing covered.

    It shipped as: the workflow created `srek3s-agent-gitops`, the patch mounted
    `srek3s-agent-manifests`, and the two had never been in the same file. The
    agent pod then sat in `Init:0/1` for the full eight-minute step timeout with
    no IP, no restarts and no message, because kubelet cannot mount a ConfigMap
    that does not exist — the init container never starts and so never fails.

    What makes it worth a test rather than a fix is that the workflow's own
    existence assertion passed the whole time. It checked the two names it
    creates, and neither was the one anything mounted: green, correct, and
    irrelevant. An assertion that verifies a name nothing depends on is worse
    than no assertion, because it is read as coverage.

    Every ConfigMap the overlay mounts must therefore be created by the e2e job.
    """
    created = _configmaps_the_workflow_creates()
    mounted = _configmaps_mounted_by_the_overlay()

    assert mounted, "the overlay mounts no ConfigMap at all; the scan is broken"
    orphans = {name: users for name, users in mounted.items() if name not in created}
    assert not orphans, (
        "the overlay mounts ConfigMaps the e2e job never creates; kubelet cannot "
        "mount a missing ConfigMap, so the pod stays in Init:0/1 until the step "
        f"times out with no diagnostic. Not created by the workflow: {orphans}. "
        f"The workflow creates: {sorted(created)}"
    )


def _e2e_step(fragment: str) -> str:
    """The `run:` body of the one e2e job step whose name contains `fragment`."""
    workflow = yaml.safe_load(
        (REPO_ROOT / ".github" / "workflows" / "e2e-detonation.yaml").read_text(
            encoding="utf-8"
        )
    )
    matches = [
        step["run"]
        for job in (workflow.get("jobs") or {}).values()
        for step in (job.get("steps") or [])
        if fragment in step.get("name", "")
    ]
    assert (
        len(matches) == 1
    ), f"expected one step matching {fragment!r}, got {len(matches)}"
    body: str = matches[0]
    return body


def test_the_route_probe_verdict_is_waited_for_and_not_assumed() -> None:
    """The probe reports by stdout, so the workflow has to wait for the stdout.

    The probe is a one-shot script that retries for up to 120s and then prints
    one JSON line. It has no readinessProbe, and that is not an oversight to be
    tidied — it means its pod is Ready the moment the container starts, so
    `rollout status` returns in about two seconds with nothing to say about
    whether the agent answered.

    The step did exactly that and then grepped the logs. Measured on a real
    cluster with a pod of the same shape: rollout returned at t+2s, the logs were
    empty, and the probe's line appeared sixty seconds later. So the assertion
    read an empty stream and failed. Deterministically — the probe cannot finish
    in the gap between rollout returning and the grep running.

    The step's own comment asserted the opposite, which is why it survived
    review: "a DNS failure or a policy refusal is a pod that never reaches Ready
    and is reported as such. `rollout status` is the check." A pod with no
    readinessProbe cannot fail to reach Ready.

    So this asserts the agreement rather than the symptom: if the probe signals
    by stdout, the workflow must poll for that stdout, and must not name
    `rollout status` as the verdict.
    """
    probe = next(
        document
        for document in load(OVERLAY / "extra-resources.yaml")
        if document.get("kind") == "Deployment"
        and document["metadata"]["name"] == "srek3s-route-probe"
    )
    containers = probe["spec"]["template"]["spec"]["containers"]
    assert not any("readinessProbe" in c for c in containers), (
        "the route probe now has a readinessProbe, so `rollout status` would "
        "genuinely gate on its verdict. This test is what forced the workflow to "
        "poll instead; if the probe gained a readinessProbe, update both."
    )

    step = _e2e_step("assert in-cluster DNS routes")
    assert "rollout status deployment/srek3s-route-probe" not in step, (
        "the step treats `rollout status` as the probe's verdict, but the probe "
        "has no readinessProbe so rollout returns before the probe has printed "
        "anything; the grep then runs against an empty stream"
    )
    assert "sleep 5" in step and "probe_deadline" in step, (
        "the step must poll for the probe's verdict with a bounded deadline; "
        "reading the logs once asserts against whatever happens to be there yet"
    )


# ---------------------------------------------------------------------------
# The base is the real deploy set
# ---------------------------------------------------------------------------


def test_the_overlay_bases_on_the_real_deploy_directory(
    kustomization: dict[str, Any],
) -> None:
    """The overlay must reference deploy/, not a copy of it.

    A vendored copy is free to drift from the manifests it claims to test, and a
    test of a copy proves nothing about the original. This is the entire reason
    the in-cluster leg exists, so the reference is checked rather than trusted -
    and it is checked by resolving the path, because a base entry that does not
    resolve produces a kustomize error at apply time, in CI, rather than here.
    """
    bases = [
        entry
        for entry in kustomization["resources"]
        if not entry.endswith((".yaml", ".yml"))
    ]
    assert bases, (
        "the overlay declares no directory base; it must reference deploy/ "
        "relatively so the real manifests are what gets applied"
    )
    resolved = [(OVERLAY / base).resolve() for base in bases]
    for path in resolved:
        assert path == DEPLOY.resolve(), (
            f"the overlay's base resolves to {path}, not {DEPLOY.resolve()}; a "
            "vendored copy of deploy/ would be tested instead of deploy/"
        )
        assert path.is_dir(), f"the overlay's base {path} does not exist"


def test_every_resource_the_overlay_lists_exists(
    kustomization: dict[str, Any],
) -> None:
    """A listed resource that is absent fails at apply time, in CI, not here."""
    for entry in kustomization["resources"]:
        if entry.endswith((".yaml", ".yml")):
            assert (OVERLAY / entry).is_file(), f"{entry} is listed but absent"
    for entry in kustomization.get("patches", []):
        assert (OVERLAY / entry["path"]).is_file(), f"{entry['path']} is absent"


def test_the_patch_targets_the_agent_deployment(
    kustomization: dict[str, Any], patch: list[dict[str, Any]]
) -> None:
    """A patch aimed at the wrong kind or name is silently not applied.

    Kustomize does not error when a strategic-merge patch's target matches
    nothing - it produces a tree identical to the unpatched base. The agent
    would then start with no manifest root, fail closed under I-B2, escalate
    every incident to Tier-2, and the leg would still be *green*, because a
    Tier-2 escalation on an ambiguous incident is a correct outcome. This is the
    most dangerous possible failure for this fixture: silent, and it makes the
    run look like a pass.
    """
    targets = [entry["target"] for entry in kustomization["patches"]]
    assert len(targets) == 1, f"expected one patch target, found {len(targets)}"
    target = targets[0]
    assert target["kind"] == "Deployment"
    assert target["name"] == "srek3s-agent"
    # The patch document must name the same object, or the strategic merge
    # produces a second Deployment rather than patching the first.
    patched = one(patch, "Deployment")
    assert patched["metadata"]["name"] == target["name"]
    assert patched["metadata"]["namespace"] == "srek3s-system"


# ---------------------------------------------------------------------------
# The capture proxy: the subtle one
# ---------------------------------------------------------------------------


def test_the_capture_proxy_is_admitted_by_the_agent_ingress_policy(
    extra: list[dict[str, Any]], agent_deployment: dict[str, Any]
) -> None:
    """The proxy carries the label the agent's NetworkPolicy actually selects on.

    deploy/agent.yaml admits ingress only from
    ``app.kubernetes.io/name: srek3s-sentinel``. An in-path instrument that does
    not carry that label cannot reach the agent at all, and the leg fails at
    connection time with a timeout that gives no hint as to why.

    The alternative - relaxing the production policy so a test can observe it -
    would mean the thing under test had been weakened to make it testable. The
    label is read out of the shipped NetworkPolicy rather than hardcoded, so
    this test fails if the policy ever changes and the fixture is not updated
    with it.
    """
    policies = by_kind(load(DEPLOY / "agent.yaml"), "NetworkPolicy")
    assert policies, "agent.yaml declares no NetworkPolicy to be admitted by"
    admitted: set[str] = set()
    for policy in policies:
        for rule in policy["spec"].get("ingress", []) or []:
            for source in rule.get("from", []) or []:
                selector = (source.get("podSelector") or {}).get("matchLabels") or {}
                admitted |= {str(value) for value in selector.values()}

    capture = named(extra, "Deployment", "srek3s-capture")
    pod_labels = capture["spec"]["template"]["metadata"]["labels"]
    impersonated = [
        value
        for key, value in pod_labels.items()
        if key != "srek3s.io/capture" and str(value) in admitted
    ]
    assert impersonated, (
        f"the capture pod's labels {sorted(pod_labels)} match nothing the agent's "
        f"ingress policy admits ({sorted(admitted)}); the leg would time out "
        "connecting with no indication of the cause"
    )
    # And it must be the Sentinel's label specifically, not merely any admitted
    # value - the property under test is "only the Sentinel reaches the agent".
    assert "srek3s-sentinel" in impersonated, (
        f"the capture pod impersonates {impersonated}, not the Sentinel; the "
        "agent's ingress policy is meant to admit exactly one client"
    )


def test_the_capture_service_cannot_select_the_real_sentinel(
    extra: list[dict[str, Any]],
) -> None:
    """The capture Service must not be selectable onto the real Sentinel pod.

    The capture pod carries the Sentinel's label to satisfy the ingress policy.
    If the Service selected on that label, a Service meant to front the proxy
    could front a real Sentinel instead - and the capture would then contain the
    proxy's own view of nothing, while the leg reported success. The Service
    selects on a label only the fixture sets.
    """
    service = one(extra, "Service")
    selector = service["spec"]["selector"]
    assert "app.kubernetes.io/name" not in selector, (
        f"the capture Service selects on app.kubernetes.io/name ({selector}), which "
        "the real Sentinel pod also carries; it must select only on the fixture's "
        "own label"
    )
    assert "srek3s.io/capture" in selector

    capture = named(extra, "Deployment", "srek3s-capture")
    assert capture["spec"]["selector"]["matchLabels"] == selector, (
        "the capture Deployment's own selector and its Service's selector must "
        "agree, or the Service has no endpoints"
    )


def test_the_capture_proxy_upstream_is_the_production_service_by_dns(
    extra: list[dict[str, Any]],
) -> None:
    """The proxy's upstream is `srek3s-agent:8000`, not a loopback address.

    This is the assertion the whole leg turns on. The host-process leg pointed
    the Sentinel at 127.0.0.1, so `srek3s-agent` was never resolved and the v1.0.0
    missing-Service defect was invisible. If this test is ever satisfied by a
    loopback upstream, the leg has stopped testing what it exists to test.
    """
    capture = named(extra, "Deployment", "srek3s-capture")
    container = capture["spec"]["template"]["spec"]["containers"][0]
    args = container["args"]
    assert "--upstream-host" in args, "the capture proxy has no explicit upstream"
    host = args[args.index("--upstream-host") + 1]
    port = args[args.index("--upstream-port") + 1]
    assert host == "srek3s-agent", (
        f"the capture proxy's upstream host is {host!r}; it must be the Service's "
        "DNS name so the leg exercises in-cluster resolution"
    )
    assert not host.replace(
        ".", ""
    ).isdigit(), "the upstream is a bare IP, which bypasses Service DNS entirely"
    assert str(port) == "8000"


def test_the_capture_proxy_binds_the_pod_interface_not_loopback(
    extra: list[dict[str, Any]],
) -> None:
    """`--listen-host 0.0.0.0`, because a pod Service cannot reach 127.0.0.1.

    capture_proxy.py defaults to 127.0.0.1, which is correct for the host-process
    leg and unreachable from a Service. Left at the default, the proxy would
    start, pass its own TCP readiness probe on loopback, and then accept nothing
    from the Sentinel - a green pod that routes nowhere, which is the v1.0.0
    failure mode in a new place.
    """
    capture = named(extra, "Deployment", "srek3s-capture")
    container = capture["spec"]["template"]["spec"]["containers"][0]
    args = container["args"]
    assert "--listen-host" in args, "the capture proxy has no explicit listen host"
    assert args[args.index("--listen-host") + 1] == "0.0.0.0"


def test_the_capture_pod_carries_the_same_hardening_as_the_agent(
    extra: list[dict[str, Any]], agent_deployment: dict[str, Any]
) -> None:
    """The fixture is held to the standard it is testing.

    A capture pod exempted from readOnlyRootFilesystem or running as root would
    not invalidate the agent's own hardening evidence directly, but it would make
    the `kubectl auth can-i` and pod-security assertions in the workflow describe
    a cluster that is not the one under test. The comparison is against the
    shipped agent container, read from the file, so a change to production
    hardening is a change to the baseline.
    """
    agent_container = agent_deployment["spec"]["template"]["spec"]["containers"][0]
    capture_container = named(extra, "Deployment", "srek3s-capture")["spec"][
        "template"
    ]["spec"]["containers"][0]
    for field in ("runAsUser", "runAsGroup", "readOnlyRootFilesystem", "runAsNonRoot"):
        assert capture_container["securityContext"][field] == (
            agent_container["securityContext"][field]
        ), f"the capture container's {field} differs from the agent's"
    assert capture_container["securityContext"]["allowPrivilegeEscalation"] is False
    assert capture_container["securityContext"]["capabilities"]["drop"] == ["ALL"]

    capture_pod = named(extra, "Deployment", "srek3s-capture")["spec"]["template"][
        "spec"
    ]
    agent_pod = agent_deployment["spec"]["template"]["spec"]
    assert capture_pod["securityContext"] == agent_pod["securityContext"], (
        "the capture pod's securityContext differs from the agent's; the fixture "
        "must be held to the policy it is testing"
    )
    assert capture_pod["automountServiceAccountToken"] is False, (
        "the capture proxy needs no Kubernetes API access; mounting a token would "
        "put a credential in a component that only forwards HTTP"
    )


# ---------------------------------------------------------------------------
# RBAC in the chaos namespace
# ---------------------------------------------------------------------------


def test_the_chaos_grant_is_read_only_and_mirrors_the_shipped_role(
    extra: list[dict[str, Any]],
) -> None:
    """The fixture Role must be exactly as narrow as the one in deploy/.

    The point of running the Sentinel in-cluster is to observe the real Role's
    behaviour. A fixture Role that granted more would not weaken the production
    Role, but it would make the run's read-only evidence describe the fixture
    rather than the thing shipped - and a reader would have no way to tell.
    """
    shipped = one(load(DEPLOY / "rbac.yaml"), "Role")
    fixture = one(extra, "Role")

    def resources_and_verbs(role: dict[str, Any]) -> set[tuple[str, str]]:
        return {
            (resource, verb)
            for rule in role["rules"]
            for resource in rule["resources"]
            for verb in rule["verbs"]
        }

    assert resources_and_verbs(fixture) == resources_and_verbs(shipped), (
        f"the chaos-namespace Role grants {sorted(resources_and_verbs(fixture))}, "
        f"which differs from deploy/rbac.yaml's "
        f"{sorted(resources_and_verbs(shipped))}"
    )
    offenders = sorted(resources_and_verbs(fixture) & MUTATING_VERBS)
    assert not offenders, f"the chaos-namespace Role grants mutating verbs: {offenders}"


def test_the_chaos_rolebinding_binds_the_real_sentinel_serviceaccount(
    extra: list[dict[str, Any]],
) -> None:
    """The subject is production's ServiceAccount, not a fixture-only one.

    Binding a new ServiceAccount would mean the leg observes a different identity
    than the one that ships, and the read-only evidence would be about a
    principal nobody deploys.
    """
    binding = one(extra, "RoleBinding")
    shipped = by_kind(load(DEPLOY / "rbac.yaml"), "ServiceAccount")
    assert shipped, "deploy/rbac.yaml creates no ServiceAccount to bind"
    account = shipped[0]
    assert binding["subjects"] == [
        {
            "kind": "ServiceAccount",
            "name": account["metadata"]["name"],
            "namespace": account["metadata"]["namespace"],
        }
    ], "the chaos RoleBinding does not bind the shipped ServiceAccount"
    assert binding["roleRef"]["name"] == one(extra, "Role")["metadata"]["name"]
    assert binding["roleRef"]["kind"] == "Role"
    assert binding["metadata"]["namespace"] == "sentinel-chaos"


def test_the_chaos_namespace_exists_in_the_fixtures() -> None:
    """The Role binds into sentinel-chaos, so that namespace must be created.

    Applying the overlay before the chaos namespace exists fails with
    "namespace not found" - the same ordering trap deploy/kustomization.yaml
    documents for its own namespace.yaml.

    Read from `chaos-rbac.yaml` rather than through the `extra` fixture, because
    this is specifically about WHERE the grant is applied from. It is the file
    the workflow hands to `kubectl apply -f`, outside kustomize, precisely so the
    overlay's `namespace:` transform cannot move it out of the namespace it binds
    into. Asserting against the union would let a future move back into
    extra-resources.yaml pass this test while reintroducing that defect.
    """
    chaos = one(load(DEPLOY / "chaos" / "namespace.yaml"), "Namespace")
    assert chaos["metadata"]["name"] == "sentinel-chaos"
    assert (
        one(load(OVERLAY / "chaos-rbac.yaml"), "Role")["metadata"]["namespace"]
        == chaos["metadata"]["name"]
    )


def test_the_chaos_grant_is_not_a_resource_of_the_overlay(
    kustomization: dict[str, Any],
) -> None:
    """Listing it would hand it to the namespace transform, which takes it.

    A kustomization that lists a file belonging to another namespace as a
    resource gets every namespaced object in it rewritten to the kustomization's
    `namespace:`, silently. The RoleBinding then references a Role that is not in
    its own namespace, and the build fails with "resource mapping not found" — a
    message about a manifest that is individually valid, which is exactly why no
    offline lint caught it and why this is asserted directly.

    Asserted on the resource LIST rather than on a rendered output, so it holds
    without kustomize installed and without a cluster.
    """
    listed = [str(entry) for entry in kustomization["resources"]]
    assert not any("chaos-rbac" in entry for entry in listed), (
        "chaos-rbac.yaml is listed as an overlay resource, so kustomize will "
        "rewrite it out of sentinel-chaos and the roleRef will stop resolving. "
        f"It must be applied by kubectl -f. Listed: {listed}"
    )


def test_the_chaos_grant_file_exists_and_is_applied_by_the_workflow() -> None:
    """The file is only correct because something applies it directly.

    Being absent from the overlay's resources is what makes the grant safe from
    the namespace transform, and it is also what makes it invisible: nothing in
    the render path touches it. Deleting it, renaming it, or dropping the
    workflow step that applies it would leave every other test here green while
    the in-cluster Sentinel starts with no grant at all — silently unauthorised,
    which is precisely the state this leg exists to rule out.

    So the pair is asserted together: the file is present, and the e2e job
    reaches it with `kubectl apply -f` rather than through `apply -k`.
    """
    grant = OVERLAY / "chaos-rbac.yaml"
    assert grant.is_file(), f"{grant} is missing but the job applies it by path"
    assert one(load(grant), "Role"), f"{grant} carries no Role"

    workflow = yaml.safe_load(
        (REPO_ROOT / ".github" / "workflows" / "e2e-detonation.yaml").read_text(
            encoding="utf-8"
        )
    )
    bodies = "\n".join(
        step.get("run", "")
        for job in (workflow.get("jobs") or {}).values()
        for step in (job.get("steps") or [])
    )

    relative = grant.relative_to(REPO_ROOT).as_posix()
    assert f"kubectl apply -f {relative}" in bodies, (
        f"the e2e job does not apply {relative} directly; without it the "
        "in-cluster Sentinel runs with no grant in sentinel-chaos"
    )
    assert (
        f"apply -k {relative}" not in bodies
    ), f"{relative} must not go through the overlay's namespace transform"


# ---------------------------------------------------------------------------
# The agent's GitOps mount
# ---------------------------------------------------------------------------


def test_the_patch_supplies_exactly_what_the_manifest_provider_reads(
    patch: list[dict[str, Any]], agent_deployment: dict[str, Any]
) -> None:
    """MANIFEST_ROOT must be set, and TARGET_MANIFEST must name a real manifest.

    SREK3S_MANIFEST_ROOT is asserted on the *shipped* manifest, not the patch.
    deploy/agent.yaml owns it - the patch deliberately does not restate it,
    because a value repeated in two files is a second place for them to disagree,
    and this overlay's whole purpose is to observe the shipped manifest rather
    than a variant of it.

    The provider fails closed when the root is absent or empty, so a missing
    variable does not crash the leg - it escalates every incident to Tier-2, which
    is a *correct* outcome and therefore a silent one. This test is the only thing
    standing between "the agent had a manifest root" and "the agent escalated
    everything and the run still passed".
    """
    shipped_env = env_map(agent_deployment)
    assert shipped_env.get("SREK3S_MANIFEST_ROOT"), (
        "deploy/agent.yaml no longer sets SREK3S_MANIFEST_ROOT; the patch must "
        "not become the only place it is declared"
    )

    env = env_map(one(patch, "Deployment"))
    assert "SREK3S_MANIFEST_ROOT" not in env, (
        "the patch restates SREK3S_MANIFEST_ROOT; it belongs to deploy/agent.yaml "
        "alone, and a second declaration is a second thing to keep in sync"
    )
    target = env.get("SREK3S_TARGET_MANIFEST", "")
    assert target.endswith((".yaml", ".yml", ".json")), (
        f"SREK3S_TARGET_MANIFEST={target!r} is not a manifest extension; "
        "classifier.py would reject it at startup and fall back to a default "
        "that does not exist in this repository"
    )
    assert (
        not target.startswith("/") and ":" not in target
    ), "SREK3S_TARGET_MANIFEST must be repo-relative"
    assert (REPO_ROOT / target).is_file(), (
        f"SREK3S_TARGET_MANIFEST names {target}, which does not exist in this "
        "repository; the provider would read a missing file and escalate"
    )
    # The patch target must be the manifest the detonation actually applies. A
    # valid diff against the wrong fixture is worse than no diff: it applies
    # cleanly, satisfies I-B2, and addresses a workload that was never deployed.
    assert target == "deploy/chaos/oom-leak.yaml", (
        f"SREK3S_TARGET_MANIFEST is {target!r}; the detonation applies "
        "deploy/chaos/oom-leak.yaml, and a patch must target the manifest the "
        "incident came from. tests/fixtures/bounded-leak.yaml is the 4.3.4 "
        "live-verification fixture and is deliberately NOT a patch target."
    )
    # TMPDIR: the root filesystem is read-only and both the sandbox and the I-B2
    # git check create a temporary directory. deploy/agent.yaml owns it.
    assert shipped_env.get("TMPDIR") == "/tmp"
    # The agent's own mount of the manifest root is declared by the shipped
    # manifest and must be read-only, so a compromised triage path cannot
    # rewrite the file it is patching. It is asserted here rather than in
    # test_deploy_manifests.py because the reason it must be read-only *here* is
    # the patch: the init container writes into the same volume.
    shipped_mounts = {
        mount["name"]: mount
        for mount in agent_deployment["spec"]["template"]["spec"]["containers"][0][
            "volumeMounts"
        ]
    }
    root_mount = shipped_mounts.get(shipped_env["SREK3S_MANIFEST_ROOT"].lstrip("/"))
    assert root_mount is not None, (
        f"deploy/agent.yaml sets SREK3S_MANIFEST_ROOT="
        f"{shipped_env['SREK3S_MANIFEST_ROOT']!r} but mounts no volume there"
    )
    assert root_mount.get("readOnly") is True, (
        "the agent's manifest root is writable; the triage path could rewrite the "
        "manifest it is about to produce a patch against, and the init container "
        "that stages it needs a different mount for its own write"
    )


def test_the_patch_adds_an_init_container_held_to_the_same_standard(
    patch: list[dict[str, Any]], agent_deployment: dict[str, Any]
) -> None:
    """The staging init container must satisfy restricted pod security.

    deploy/chaos/namespace.yaml enforces `pod-security.kubernetes.io/enforce:
    restricted`, and so does deploy/namespace.yaml. An init container running as
    root, or with privilege escalation enabled, is *rejected at admission* - so
    the agent pod never starts, the leg dies at deploy, and the failure looks
    like a manifest problem rather than a fixture problem.
    """
    init = one(patch, "Deployment")["spec"]["template"]["spec"]["initContainers"][0]
    security = init["securityContext"]
    agent_container = agent_deployment["spec"]["template"]["spec"]["containers"][0]
    assert security["runAsUser"] == agent_container["securityContext"]["runAsUser"]
    assert security["runAsNonRoot"] is True
    assert security["allowPrivilegeEscalation"] is False
    assert security["readOnlyRootFilesystem"] is True
    assert security["capabilities"]["drop"] == ["ALL"]
    # It writes, so it needs the manifest root writable and the staged source
    # read-only.
    by_name = {mount["name"]: mount for mount in init["volumeMounts"]}
    assert "manifests" in by_name, "the init container cannot write the manifest root"
    assert by_name["manifests"].get("readOnly") is not True, (
        "the init container mounts the manifest root read-only, so it cannot "
        "stage into it; the agent's own mount of the same volume is read-only, "
        "and the two must differ"
    )
    assert "manifest-source" in by_name, "the init container has nothing to stage from"
    assert by_name["manifest-source"].get("readOnly") is True

    # The volume list must not redeclare what the shipped manifest declares. A
    # strategic merge of two emptyDir definitions for one name is a second place
    # for the two files to disagree about size and medium.
    pod_spec = one(patch, "Deployment")["spec"]["template"]["spec"]
    redeclared = {volume["name"] for volume in pod_spec.get("volumes", [])}
    shipped_volumes = {
        volume["name"]
        for volume in agent_deployment["spec"]["template"]["spec"].get("volumes", [])
    }
    assert not (redeclared & shipped_volumes), (
        f"the patch redeclares shipped volumes {sorted(redeclared & shipped_volumes)}; "
        "one volume should have one definition"
    )
    # And it must create the nested path the target manifest implies, rather than
    # copying the file flat. The provider resolves the target relative to the
    # root, so a flat copy is a file the provider cannot find.
    args = init["args"][0]
    assert "manifests" in args
    assert "deploy/chaos" in args, (
        "the init container does not create the nested path SREK3S_TARGET_MANIFEST "
        "implies; the provider resolves the target relative to the root, so a flat "
        "copy is a file it can never find"
    )


def test_the_patch_does_not_weaken_the_agent_container(
    patch: list[dict[str, Any]], agent_deployment: dict[str, Any]
) -> None:
    """The patch must not use a directive that removes from the shipped pod.

    The first draft of this test compared the patch document's own lists against
    the shipped agent's and failed on `tmp` - correctly reporting that the patch
    document does not mention the mount, and wrongly concluding the mount was
    being dropped. A Kubernetes strategic merge combines ``volumeMounts`` and
    ``env`` by their ``name`` key, so an entry in the patch is *added* and the
    patched object carries both. The test was comparing a fragment to a whole,
    and it would have "passed" for the wrong reason the moment someone loosened
    it.

    Removal is possible, though, and it is the thing worth asserting. It takes a
    directive rather than an omission: ``$patch: replace`` on a list replaces it
    wholesale, ``$patch: delete`` drops a named entry, and
    ``$deleteFromPrimitiveList`` removes a list element. Any of those would
    silently produce a pod differing from the one production runs, which is the
    entire claim this leg makes.
    """
    raw = (OVERLAY / "agent-gitops-patch.yaml").read_text(encoding="utf-8")
    for directive in ("$patch:", "$deleteFromPrimitiveList", "$setElementOrder"):
        assert directive not in raw, (
            f"the patch uses {directive!r}, which can remove entries from the "
            "shipped pod spec; the leg would then observe a container that "
            "differs from the one production runs"
        )
    patched = one(patch, "Deployment")["spec"]["template"]["spec"]["containers"][0]
    shipped = agent_deployment["spec"]["template"]["spec"]["containers"][0]
    # A strategic merge matches containers by name. A mismatch does not patch the
    # first container, it creates a second one.
    assert patched["name"] == shipped["name"], (
        f"the patch names container {patched['name']!r}, not "
        f"{shipped['name']!r}; a strategic merge would add a second container "
        "rather than patching the shipped one"
    )
    # Anything the patch does restate must restate the shipped value. A patch
    # that changed the image or the probe budget would be measuring something
    # other than the manifest under test.
    for field in ("image", "imagePullPolicy", "startupProbe", "resources"):
        if field in patched:
            assert patched[field] == shipped[field], (
                f"the patch restates {field} with a different value; the leg must "
                "observe the shipped value"
            )


# ---------------------------------------------------------------------------
# Fixtures are marked as fixtures
# ---------------------------------------------------------------------------


def test_every_overlay_object_is_marked_as_a_fixture(
    extra: list[dict[str, Any]],
) -> None:
    """Each object carries `srek3s.io/fixture: e2e-incluster`.

    Without the marker, an object that outlives its run is indistinguishable
    from a production manifest in `kubectl get all` - and someone cleaning up
    after a failed run would have no way to know which is which.
    """
    unmarked = [
        f"{doc['kind']}/{doc['metadata']['name']}"
        for doc in extra
        if doc["metadata"].get("labels", {}).get("srek3s.io/fixture") != "e2e-incluster"
    ]
    assert not unmarked, f"overlay objects not marked as fixtures: {unmarked}"


def test_the_overlay_creates_nothing_in_a_production_namespace_by_accident(
    extra: list[dict[str, Any]],
) -> None:
    """Objects live in `srek3s-system` or `sentinel-chaos`, and nowhere else.

    Both are legitimate here. The assertion is that the set is exactly those two,
    so a namespace typo cannot scatter fixture objects across the cluster.
    """
    allowed = {"srek3s-system", "sentinel-chaos"}
    found = {doc["metadata"].get("namespace") for doc in extra}
    assert found <= allowed, f"overlay objects target unexpected namespaces: {found}"


# ---------------------------------------------------------------------------
# The routing probe
# ---------------------------------------------------------------------------


def test_the_routing_probe_dials_the_service_by_dns_name(
    extra: list[dict[str, Any]],
) -> None:
    """The probe must resolve `srek3s-agent` by name.

    This is the assertion the v1.0.0 defect would have failed. The probe exists
    to make in-cluster name resolution happen and be observed; a probe that
    dialled a ClusterIP, a pod IP, or `localhost` would pass on a cluster with
    no Service at all, which is the exact state v1.0.0 shipped.
    """
    probe = next(
        doc
        for doc in by_kind(extra, "Deployment")
        if doc["metadata"]["name"] == "srek3s-route-probe"
    )
    script = probe["spec"]["template"]["spec"]["containers"][0]["args"][0]
    assert (
        "http://srek3s-agent:8000" in script
    ), "the routing probe does not address the agent's Service DNS name"
    # And it must not resolve the name to something else first.
    for forbidden in ("127.0.0.1", "localhost", "0.0.0.0"):
        assert forbidden not in script, (
            f"the routing probe references {forbidden}; a probe that bypasses "
            "Service DNS cannot detect a missing Service"
        )
    assert (
        "/healthz" in script
    ), "the probe must exercise a real contract endpoint, not just a TCP connect"


def test_the_routing_probe_is_admitted_and_hardened(
    extra: list[dict[str, Any]], agent_deployment: dict[str, Any]
) -> None:
    """The probe carries the Sentinel's label and the agent's hardening.

    Without the label the agent's ingress policy refuses it, and the leg would
    report a routing failure that is really a policy outcome. Without the
    hardening the pod would be rejected at admission by the `restricted` policy
    both namespaces enforce.
    """
    probe = next(
        doc
        for doc in by_kind(extra, "Deployment")
        if doc["metadata"]["name"] == "srek3s-route-probe"
    )
    pod_spec = probe["spec"]["template"]["spec"]
    labels = probe["spec"]["template"]["metadata"]["labels"]
    assert labels["app.kubernetes.io/name"] == "srek3s-sentinel", (
        "the probe must carry the Sentinel's label or the agent's ingress policy "
        "refuses it and the leg measures the policy instead of the routing"
    )
    # It must be distinguishable from the capture proxy, or a `kubectl get pods
    # -l app.kubernetes.io/name=srek3s-sentinel` in triage cannot tell them apart.
    assert "srek3s.io/probe" in labels
    agent_pod = agent_deployment["spec"]["template"]["spec"]
    assert pod_spec["securityContext"] == agent_pod["securityContext"]
    container = pod_spec["containers"][0]
    agent_container = agent_pod["containers"][0]
    assert (
        container["securityContext"] == agent_container["securityContext"]
    ), "the probe's container hardening differs from the agent's"
    assert pod_spec["automountServiceAccountToken"] is False


# ---------------------------------------------------------------------------
# Negative controls
# ---------------------------------------------------------------------------


def test_control_the_dns_assertion_fails_on_a_loopback_upstream(
    extra: list[dict[str, Any]],
) -> None:
    """Proves the DNS assertion can fail.

    Without this, `test_the_capture_proxy_upstream_is_the_production_service_by_dns`
    could be satisfied by any non-empty upstream value, and the leg would pass
    while pointing at 127.0.0.1 - the exact defect it exists to rule out.
    """
    capture = named(extra, "Deployment", "srek3s-capture")
    container = capture["spec"]["template"]["spec"]["containers"][0]
    args = list(container["args"])
    host = args[args.index("--upstream-host") + 1]
    assert host == "srek3s-agent"

    broken = list(args)
    broken[broken.index("--upstream-host") + 1] = "127.0.0.1"
    assert broken[broken.index("--upstream-host") + 1] != host
    assert (
        broken[broken.index("--upstream-host") + 1].replace(".", "").isdigit()
    ), "control is vacuous: the loopback value is not detected as an IP"


def test_control_the_capture_selector_assertion_fails_on_the_sentinel_label(
    extra: list[dict[str, Any]],
) -> None:
    """Proves the Service-selector assertion can fail.

    Re-pointing the capture Service at `app.kubernetes.io/name` must be caught.
    That is the mistake that would let the Service front the real Sentinel, and
    it is invisible at runtime - the Service would resolve, to the wrong pod.
    """
    service = one(extra, "Service")
    good = dict(service["spec"]["selector"])
    assert "app.kubernetes.io/name" not in good

    broken = {**good, "app.kubernetes.io/name": "srek3s-sentinel"}
    assert (
        "app.kubernetes.io/name" in broken
    ), "control is vacuous: the broken selector still lacks the forbidden key"


def test_control_the_hardening_assertion_fails_on_a_relaxed_field(
    extra: list[dict[str, Any]], agent_deployment: dict[str, Any]
) -> None:
    """Proves the hardening comparison can fail.

    Flipping one field on the capture container must break the comparison with
    the shipped agent. If it did not, the assertion would be comparing something
    other than what it appears to compare.
    """
    agent_container = agent_deployment["spec"]["template"]["spec"]["containers"][0]
    capture = named(extra, "Deployment", "srek3s-capture")
    container = capture["spec"]["template"]["spec"]["containers"][0]
    for field in ("runAsUser", "readOnlyRootFilesystem"):
        good = container["securityContext"][field]
        assert good == agent_container["securityContext"][field]
        relaxed = not good if isinstance(good, bool) else 0
        assert (
            relaxed != agent_container["securityContext"][field]
        ), f"control is vacuous for {field}"


def test_control_the_manifest_root_assertion_fails_on_an_unset_variable(
    agent_deployment: dict[str, Any], patch: list[dict[str, Any]]
) -> None:
    """Proves the manifest-root assertion can fail.

    Dropping SREK3S_MANIFEST_ROOT is the failure that does *not* crash: the
    provider fails closed, every incident escalates to Tier-2, and a Tier-2
    escalation is a correct result. So the leg would pass. The control confirms
    the test is looking at the variable at all.

    The root is read from the shipped manifest and the target from the patch,
    which is the split the design settled on - and the first draft of this
    control asserted the opposite, checking the manifest for a variable the
    patch owns. A control that names the wrong document proves nothing about
    either.
    """
    env = env_map(agent_deployment)
    assert "SREK3S_MANIFEST_ROOT" in env
    without = {
        name: value for name, value in env.items() if name != "SREK3S_MANIFEST_ROOT"
    }
    assert "SREK3S_MANIFEST_ROOT" not in without

    patch_env = env_map(one(patch, "Deployment"))
    assert (
        "SREK3S_TARGET_MANIFEST" in patch_env
    ), "the target manifest is declared by the patch, not by deploy/agent.yaml"
    assert "SREK3S_MANIFEST_ROOT" not in patch_env, (
        "the patch restates the manifest root; that would make the shipped "
        "manifest's value decorative"
    )
