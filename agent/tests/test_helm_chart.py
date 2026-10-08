"""Helm chart parity tests (deploy/helm/srek3s).

The chart must render the same objects as `kubectl kustomize deploy/base`
with default values. All tests skip when the `helm` binary is absent, per
the repository's skip discipline: a missing tool is a blocked dependency,
not a pass.
"""

from __future__ import annotations

import json
import pathlib
import shutil
import subprocess

import pytest
import yaml

from typing import Any

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
CHART = REPO_ROOT / "deploy" / "helm" / "srek3s"

helm: str | None = shutil.which("helm")
kubectl: str | None = shutil.which("kubectl")
needs_helm = pytest.mark.skipif(helm is None, reason="helm binary absent")
needs_helm_kubectl = pytest.mark.skipif(
    helm is None or kubectl is None, reason="helm or kubectl binary absent"
)


def render(extra: list[str] | None = None) -> list[dict[str, Any]]:
    assert helm is not None
    cmd = [helm, "template", "srek3s", str(CHART), "-n", "srek3s-system"]
    if extra:
        cmd.extend(extra)
    out = subprocess.run(cmd, capture_output=True, text=True, check=True)
    return [d for d in yaml.safe_load_all(out.stdout) if d]


def one(docs: list[dict[str, Any]], kind: str, name: str) -> dict[str, Any]:
    for d in docs:
        if d.get("kind") == kind and d.get("metadata", {}).get("name") == name:
            return d
    raise AssertionError(f"{kind}/{name} missing from helm render")


def test_chart_files_match_the_static_sources() -> None:
    """The embedded files must be copies, not forks."""
    assert (CHART / "files" / "scrubber.json").read_text() == (
        REPO_ROOT / "deploy" / "scrubber.json"
    ).read_text()
    assert (CHART / "files" / "oom-leak.yaml").read_text() == (
        REPO_ROOT / "deploy" / "chaos" / "oom-leak.yaml"
    ).read_text()


@needs_helm
def test_role_grants_no_mutating_verb() -> None:
    for rule in one(render(), "Role", "srek3s-sentinel")["rules"]:
        assert set(rule["verbs"]) <= {"get", "list", "watch"}, rule


@needs_helm
def test_agent_mounts_no_serviceaccount_token() -> None:
    agent = one(render(), "Deployment", "srek3s-agent")
    assert agent["spec"]["template"]["spec"]["automountServiceAccountToken"] is False


@needs_helm
def test_sentinel_keeps_its_serviceaccount() -> None:
    sentinel = one(render(), "Deployment", "srek3s-sentinel")
    spec = sentinel["spec"]["template"]["spec"]
    assert spec["serviceAccountName"] == "srek3s-sentinel"
    assert spec["automountServiceAccountToken"] is True


@needs_helm
def test_watch_namespace_override_reaches_the_container() -> None:
    docs = render(["--set", "sentinel.watchNamespace=payments"])
    sentinel = one(docs, "Deployment", "srek3s-sentinel")
    env = {
        e["name"]: e.get("value")
        for e in sentinel["spec"]["template"]["spec"]["containers"][0]["env"]
    }
    assert env["WATCH_NAMESPACE"] == "payments"


@needs_helm
def test_monitoring_namespace_opens_9090_ingress() -> None:
    docs = render(["--set", "monitoring.namespace=monitoring"])
    policy = one(docs, "NetworkPolicy", "srek3s-sentinel")
    ingress = policy["spec"]["ingress"]
    assert len(ingress) == 1
    assert ingress[0]["ports"] == [{"protocol": "TCP", "port": 9090}]


@needs_helm
def test_default_render_denies_9090_ingress() -> None:
    policy = one(render(), "NetworkPolicy", "srek3s-sentinel")
    assert policy["spec"]["ingress"] == []


@needs_helm
def test_api_server_cidr_override_reaches_the_policy() -> None:
    docs = render(["--set", "networkPolicy.apiServerCidrs[0]=10.100.0.0/16"])
    policy = one(docs, "NetworkPolicy", "srek3s-sentinel")
    cidrs = [
        to["ipBlock"]["cidr"]
        for rule in policy["spec"]["egress"]
        for to in rule.get("to", [])
        if "ipBlock" in to
    ]
    assert cidrs == ["10.100.0.0/16"]


@needs_helm_kubectl
def test_render_matches_kustomize_base() -> None:
    """Every object the chart renders is byte-identical to deploy/base.

    One documented exception: the Namespace.

    `deploy/base` renders a Namespace because kustomize has no equivalent of
    `helm --create-namespace` and something must create it. The chart
    deliberately does NOT, because rendering one made `helm install` fail in
    both directions:

        $ helm install srek3s ./chart -n srek3s-system
        Error: INSTALLATION FAILED: namespaces "srek3s-system" not found
        $ helm install srek3s ./chart -n srek3s-system --create-namespace
        Error: INSTALLATION FAILED: namespaces "srek3s-system" already exists

    The chart lost ownership of the object, so the invariant is restated rather
    than deleted: nothing else may drift, and the absence of the Namespace is
    asserted rather than tolerated.
    """
    import yaml as _yaml

    base = subprocess.run(
        [
            "kubectl",
            "kustomize",
            "--load-restrictor=LoadRestrictionsNone",
            str(REPO_ROOT / "deploy" / "base"),
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    want = {
        (d.get("kind"), d.get("metadata", {}).get("name")): d
        for d in _yaml.safe_load_all(base.stdout)
        if d
    }
    got = {(d.get("kind"), d.get("metadata", {}).get("name")): d for d in render()}

    namespaces = {k for k in want if k[0] == "Namespace"}
    assert namespaces, "deploy/base should still create the namespace"
    assert not (set(got) & namespaces), (
        f"the chart must not render a Namespace: {set(got) & namespaces}; "
        "helm --create-namespace owns it, and rendering one makes every "
        "helm install fail"
    )

    comparable_want = {k: v for k, v in want.items() if k[0] != "Namespace"}
    assert set(got) == set(comparable_want), (set(got) ^ set(comparable_want),)
    for key in comparable_want:
        assert got[key] == want[key], f"{key} differs between helm and kustomize"
        _ = json.dumps(got[key], sort_keys=True)


def test_the_chart_renders_no_namespace_object() -> None:
    """Guard the fix at its source: the template must not come back.

    A regression here is silent until someone runs `helm install` in anger, and
    the failure mode is a confusing error rather than an obvious one.
    """
    template = REPO_ROOT / "deploy" / "helm" / "srek3s" / "templates" / "namespace.yaml"
    assert not template.exists(), (
        "templates/namespace.yaml must not exist: helm --create-namespace owns "
        "the namespace, and a chart-rendered Namespace makes helm install fail "
        "with either 'not found' or 'already exists'"
    )
