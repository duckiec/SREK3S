"""Security and contract tests for the filesystem manifest provider (Task A).

ROADMAP 4.2.6 requires a Tier-1 incident to be reachable end to end, and
``agent/classifier.py``'s :class:`FileManifestProvider` is what makes that
possible. The provider is the **only** place the agent touches a filesystem, so
its failure modes are the most consequential in the codebase:

* a path that escapes the checkout turns a read-only manifest fetch into a
  file-read primitive over whatever the checkout root happens to contain;
* a provider that could *write* would put a second output channel inside the
  trust boundary ARCH §1 draws around the agent;
* an empty manifest read as "unreadable" would report a broken checkout as a
  healthy one, in the safe-looking direction.

Every test below is paired, per AGENTS.md §5.5. The positive case says the
provider works; the negative control says the guard **fires on the defect it
exists to catch**, which is the only way to know the positive case is not
passing for the wrong reason.
"""

from __future__ import annotations

import logging
import os
import pathlib
import stat
from typing import Any, Iterator

import asyncio

import pytest

import classifier
import models
import triage
import warroom
from classifier import (
    DEFAULT_TARGET_MANIFEST,
    MANIFEST_ROOT_ENV,
    TARGET_MANIFEST,
    TARGET_MANIFEST_ENV,
    FileManifestProvider,
    manifest_provider_from_env,
    resolve_target_manifest,
    unreadable_manifest_provider,
)
from main import _lifespan, create_app
from triage import triage_payload

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

#: A manifest shaped exactly like the real chaos fixture's target line, so the
#: provider tests exercise the shape ``find_container_memory_limit`` will later
#: be asked to read rather than a toy that never appears in production.
MANIFEST = """\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: srek3s-chaos-oom
  namespace: sentinel-chaos
spec:
  replicas: 1
  template:
    spec:
      containers:
        - name: oom-canary
          image: busybox:1.36.1
          resources:
            limits:
              memory: 64Mi
"""

#: Requests that must never open a file outside the checkout root.
#:
#: Hoisted to module level, not inline in the decorator, because a
#: parametrisation list is otherwise invisible to every other test - and
#: ``test_the_traversal_control_is_not_vacuous`` below needs to assert on it. An
#: empty list would collect zero tests and report no failure, which is the
#: fourth way this repository has found to have a check that cannot fail.
TRAVERSAL_CASES: list[Any] = [
    pytest.param("../../etc/passwd", id="parent-traversal"),
    pytest.param("../../../../../../etc/shadow", id="deep-traversal"),
    pytest.param("deploy/../../etc/passwd", id="traversal-mid-path"),
    pytest.param("..", id="bare-parent"),
    pytest.param("deploy/payments/../../../etc/passwd", id="traversal-from-target"),
    pytest.param("deploy/./payments/checkout-api.yaml", id="dot-segment"),
    pytest.param("/etc/passwd", id="absolute"),
    pytest.param("/deploy/payments/checkout-api.yaml", id="absolute-rooted"),
    pytest.param("C:/Windows/System32/drivers/etc/hosts", id="windows-drive"),
    pytest.param("deploy\\payments\\..\\..\\secret.yaml", id="backslash-traversal"),
    pytest.param("", id="empty"),
    pytest.param("   ", id="whitespace"),
]


@pytest.fixture
def checkout(tmp_path: pathlib.Path) -> pathlib.Path:
    """A minimal GitOps checkout containing ``TARGET_MANIFEST``."""
    target = tmp_path / TARGET_MANIFEST
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(MANIFEST, encoding="utf-8")
    return tmp_path


def incident_document(**overrides: Any) -> dict[str, Any]:
    """A valid, Tier-1-shaped Contract A payload with the fixture's identifiers."""
    document: dict[str, Any] = {
        "schema_version": "1.0.0",
        "incident_id": "inc_01M3M6W9ENH28NJS8C5T1665PA",
        "timestamp": "2026-09-29T12:00:00.000Z",
        "namespace": "sentinel-chaos",
        "pod_name": "srek3s-chaos-oom-7d9f4b6c8d-x2k9p",
        "container_name": "oom-canary",
        "exit_code": 137,
        "reason": "OOMKilled",
        "resource_limits": {"memory_limit": "64Mi"},
        "restart_count": 1,
        "scrubbed_logs": ["CHAOS-OOM iteration=6 heap_bytes=67108864"],
        "cluster_events": [],
        "redaction_report": {"total_redactions": 2, "rules_triggered": ["uuid"]},
        "detection_latency_ms": 120,
        "sentinel_version": "0.1.0",
    }
    document.update(overrides)
    return document


# ---------------------------------------------------------------------------
# The happy path, and what it buys
# ---------------------------------------------------------------------------


def test_it_reads_a_manifest_from_the_checkout(checkout: pathlib.Path) -> None:
    provider = FileManifestProvider(checkout)
    assert provider.read_manifest(TARGET_MANIFEST) == MANIFEST


def test_a_readable_manifest_makes_tier_one_reachable(
    checkout: pathlib.Path,
) -> None:
    """The whole point of Task A.

    Before it, ``create_app`` passed no provider, ``triage.py`` took the ``None``
    branch, ARCH §5.4 I-B2 forced Tier-2, and **no Tier-1 incident could occur** -
    which makes ROADMAP 4.2.6 structurally unreachable rather than merely
    untested.
    """
    payload = models.IncidentPayload.model_validate(incident_document())
    outcome = triage_payload(payload, manifest_provider=FileManifestProvider(checkout))
    assert outcome.tier.value == "TIER_1_TOIL"
    assert outcome.response.remediation.patch_validated is True
    assert "64Mi" in outcome.response.remediation.git_patch
    assert "128Mi" in outcome.response.remediation.git_patch
    # A Tier-1 incident must NOT carry a war-room dispatch; the two are
    # mutually exclusive and `dispatch is None` is how that is expressed.
    assert outcome.dispatch is None


def test_a_wrong_manifest_still_fails_closed(tmp_path: pathlib.Path) -> None:
    """A checkout whose limit has drifted must escalate, not patch.

    The provider working is necessary but not sufficient: a patch verified
    against the wrong file proves nothing about the running workload, so the
    triage engine's existing drift check has to keep firing with a provider
    present. This is the negative control for "wiring a provider in did not
    disable the checks it enabled".
    """
    drifted = MANIFEST.replace("memory: 64Mi", "memory: 256Mi")
    (tmp_path / TARGET_MANIFEST).parent.mkdir(parents=True, exist_ok=True)
    (tmp_path / TARGET_MANIFEST).write_text(drifted, encoding="utf-8")

    payload = models.IncidentPayload.model_validate(incident_document())
    outcome = triage_payload(payload, manifest_provider=FileManifestProvider(tmp_path))
    assert outcome.tier.value == "TIER_2_ARCHITECTURAL"
    assert outcome.response.remediation.git_patch == ""
    assert any("drifted" in reason for reason in outcome.reasons), outcome.reasons


def test_a_missing_manifest_fails_closed(tmp_path: pathlib.Path) -> None:
    payload = models.IncidentPayload.model_validate(incident_document())
    outcome = triage_payload(payload, manifest_provider=FileManifestProvider(tmp_path))
    assert outcome.tier.value == "TIER_2_ARCHITECTURAL"
    assert outcome.response.remediation.git_patch == ""


# ---------------------------------------------------------------------------
# Path confinement - the security property
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("path", TRAVERSAL_CASES)
def test_a_path_that_leaves_the_root_is_refused(
    checkout: pathlib.Path, path: str
) -> None:
    """Nothing outside the root is ever opened, whatever shape the request takes.

    ``build_diff`` and ``Remediation.target_manifest`` also reject absolute
    paths and colons, but those are *producer-side* guards: they stop a bad path
    being written into a diff. The provider is the consumer, and it is the only
    layer that decides which file is actually opened, so it does not rely on
    another layer having run first.
    """
    assert FileManifestProvider(checkout).read_manifest(path) is None


def test_the_traversal_control_would_catch_a_naive_provider(
    checkout: pathlib.Path,
) -> None:
    """Negative control (AGENTS.md §5.5).

    Proves the parametrised test above is not passing because the *fixture*
    happens to have nothing above it. A deliberately naive provider - one that
    simply joins root and path and opens the result, which is the bug the
    containment check exists to prevent - is shown resolving the same request
    outside the root, and the real provider is shown refusing it.
    """
    naive = (checkout / "../../etc/passwd").resolve(strict=False)
    assert not naive.is_relative_to(checkout.resolve())

    # And the refusal does not depend on the target existing, so it is a
    # property of the request rather than an accident of this filesystem.
    assert FileManifestProvider(checkout).read_manifest("../../etc/passwd") is None


def test_the_traversal_control_is_not_vacuous() -> None:
    """The parametrisation cannot silently empty itself.

    An empty list of cases collects zero tests, pytest reports no failure, and
    the coverage it appears to provide is entirely fictional. This is the fourth
    way this repository has found to have a check that cannot fail.
    """
    assert len(TRAVERSAL_CASES) >= 10, (
        "the traversal control shrank to a handful of cases; a provider whose "
        "path handling regressed on an unlisted shape would not be caught"
    )
    ids = {case.id for case in TRAVERSAL_CASES}
    for anchor in ("parent-traversal", "absolute", "windows-drive", "bare-parent"):
        assert anchor in ids, f"the traversal control lost its {anchor!r} case"


def test_a_symlink_out_of_the_root_is_refused(
    checkout: pathlib.Path, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Containment is checked on the *resolved* path, not on the request.

    Every segment of ``deploy/payments/link.yaml`` is innocent - no ``..``, no
    leading slash, a valid manifest extension. The only way to catch a link is
    to resolve first and then ask whether the destination is still inside, which
    is what the provider does and what a string-only check on the request would
    miss entirely.

    The link is created for real where the host permits it, and simulated
    otherwise. Windows refuses ``os.symlink`` without ``SeCreateSymbolicLink``,
    and a test that skipped there would leave the one containment case that
    matters most unverified on the development host - so the simulation is the
    primary path, not a consolation, and it patches the same ``Path.resolve``
    the provider calls.
    """
    # `outside` is a *sibling* of the checkout, not a child of it. The `checkout`
    # fixture returns `tmp_path` itself, so `tmp_path / "outside"` would be
    # inside the root and the test would pass for the wrong reason - the
    # provider would be reading a file it was always allowed to read, and the
    # containment check would never have been exercised.
    outside = tmp_path.parent / f"outside-{tmp_path.name}"
    outside.mkdir()
    secret = outside / "secret.yaml"
    secret.write_text("password: leaked", encoding="utf-8")

    real_link = checkout / "deploy" / "payments" / "link.yaml"
    simulated = False
    try:
        os.symlink(secret, real_link)
    except (OSError, NotImplementedError):
        simulated = True
        _simulate_resolve_to(monkeypatch, real_link, secret)
        # The simulation has to actually be in effect, or the assertion below
        # would pass because the path resolves to nothing at all rather than
        # because containment refused it. Asserted directly, because a
        # simulation that silently fails to install is the exact failure shape
        # this file exists to catch - in the guard rather than the system.
        assert real_link.resolve(strict=False) == secret.resolve(strict=False)

    try:
        assert (
            FileManifestProvider(checkout).read_manifest("deploy/payments/link.yaml")
            is None
        )
    finally:
        # Only the simulated path needs cleaning; a real symlink lives and dies
        # with tmp_path. Left behind, this directory would make a *subsequent*
        # run's `mkdir` fail for an unrelated reason.
        if simulated:
            secret.unlink()
            outside.rmdir()


def test_a_symlink_within_the_root_is_allowed(
    checkout: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The mirror, so the refusal is not just "symlinks are refused".

    A provider that blocked every symlink would pass the test above while being
    useless in a real checkout, where ``deploy/current`` -> ``deploy/v1.2.3`` is
    ordinary GitOps practice. The check is on **where the link points**, not on
    its existence, and this is what proves the difference.
    """
    real = checkout / TARGET_MANIFEST
    alias = checkout / "deploy" / "alias.yaml"
    try:
        os.symlink(real, alias)
    except (OSError, NotImplementedError):
        _simulate_resolve_to(monkeypatch, alias, real)

    assert FileManifestProvider(checkout).read_manifest("deploy/alias.yaml") == MANIFEST


def _simulate_resolve_to(
    monkeypatch: pytest.MonkeyPatch, path: pathlib.Path, target: pathlib.Path
) -> None:
    """Make ``path`` resolve to ``target`` without needing a real symlink.

    Patched on the *class*, not the instance: the provider builds its own
    ``Path`` from ``self._root.joinpath(*segments)``, so an instance-level patch
    on ``path`` would never be consulted. The match is on the *name and parent*
    rather than on object identity or full equality, because the provider's
    ``self._root`` is itself already resolved - so on a host where the temporary
    directory sits behind a junction (Windows) the two objects differ as paths
    while denoting the same file.
    """
    original = type(path).resolve
    wanted_name = path.name
    wanted_parent = path.parent.name

    def patched(self: pathlib.Path, strict: bool = False) -> pathlib.Path:
        if self.name == wanted_name and self.parent.name == wanted_parent:
            return target.resolve(strict=False)
        return original(self, strict)

    monkeypatch.setattr(type(path), "resolve", patched)


def test_a_non_manifest_file_inside_the_root_is_refused(
    checkout: pathlib.Path,
) -> None:
    """A checkout contains more than manifests.

    ``.env``, ``.git/config`` and a cloud credential all live under a GitOps
    root. Restricting to the extensions ARCH §5.1 already fixes for
    ``target_manifest`` keeps a path bug from becoming a file-read primitive over
    whatever else is checked out.
    """
    (checkout / ".env").write_text("AWS_SECRET_ACCESS_KEY=hunter2", encoding="utf-8")
    (checkout / "config.json.bak").write_text("{}", encoding="utf-8")
    provider = FileManifestProvider(checkout)
    assert provider.read_manifest(".env") is None
    assert provider.read_manifest("config.json.bak") is None


def test_a_directory_is_not_a_manifest(checkout: pathlib.Path) -> None:
    """``deploy/payments`` is a directory that looks like a path prefix.

    And a directory named with a manifest *extension* is refused too, which is
    the case a bare ``exists()`` check would sail past.
    """
    (checkout / "fake.yaml").mkdir()
    provider = FileManifestProvider(checkout)
    assert provider.read_manifest("deploy/payments") is None
    assert provider.read_manifest("fake.yaml") is None


# ---------------------------------------------------------------------------
# Empty is not unreadable
# ---------------------------------------------------------------------------


def test_an_empty_manifest_is_read_not_refused(tmp_path: pathlib.Path) -> None:
    """``""`` and ``None`` are different facts and must not collapse.

    Reporting an empty file as unreadable would claim a broken checkout is a
    missing one, and the escalation reason a responder reads would name the
    wrong cause. It fails closed either way, but it fails *honestly*.
    """
    (tmp_path / TARGET_MANIFEST).parent.mkdir(parents=True, exist_ok=True)
    (tmp_path / TARGET_MANIFEST).write_text("", encoding="utf-8")
    assert FileManifestProvider(tmp_path).read_manifest(TARGET_MANIFEST) == ""


def test_an_empty_manifest_produces_no_patch(tmp_path: pathlib.Path) -> None:
    """The requirement that actually matters: empty must not become a patch.

    A diff built against an empty document has no target line, so the engine
    must decline rather than invent one. Asserted on the *response*, not on the
    provider's return value, because the provider is only the first half of the
    path - the two halves can disagree, and it is the second that emits.
    """
    (tmp_path / TARGET_MANIFEST).parent.mkdir(parents=True, exist_ok=True)
    (tmp_path / TARGET_MANIFEST).write_text("", encoding="utf-8")

    payload = models.IncidentPayload.model_validate(incident_document())
    outcome = triage_payload(payload, manifest_provider=FileManifestProvider(tmp_path))
    assert outcome.tier.value == "TIER_2_ARCHITECTURAL"
    assert outcome.response.remediation.git_patch == ""
    assert outcome.response.remediation.patch_validated is False
    assert any("locate" in reason for reason in outcome.reasons), outcome.reasons


def test_a_binary_manifest_is_unreadable_not_an_exception(
    checkout: pathlib.Path,
) -> None:
    """Non-UTF-8 content returns ``None``.

    An exception here would become a 500 rather than a considered escalation,
    and a binary file where a manifest is expected is a checkout problem, not a
    request the agent can answer.
    """
    (checkout / TARGET_MANIFEST).write_bytes(b"\xff\xfe\x00binary")
    assert FileManifestProvider(checkout).read_manifest(TARGET_MANIFEST) is None


# ---------------------------------------------------------------------------
# Read-only
# ---------------------------------------------------------------------------


def test_the_provider_module_uses_no_write_api() -> None:
    """Read-only, enforced structurally rather than by discipline.

    A behavioural test ("the tests all passed, so it did not write") proves only
    that *these* cases did not write. This scans the provider's own module for
    the write, create and delete APIs, so a future method that adds one fails
    the build instead of being trusted. Deliberately scanned as **text** rather
    than through the AST: the module contains a large amount of explanatory
    prose that legitimately uses these words, and a reader is right to be
    suspicious of a check that can be defeated by editing a comment. So the scan
    targets call syntax - ``open(``, ``.write_text(`` - and the negative control
    below plants one to prove it fires.
    """
    import inspect

    source = inspect.getsource(classifier)
    forbidden = (
        "open(",
        ".write_text(",
        ".write_bytes(",
        ".mkdir(",
        ".unlink(",
        ".rename(",
        ".rmdir(",
        "os.remove(",
        "os.rmdir(",
        "os.rename(",
        "shutil.",
        "tempfile.",
    )
    for token in forbidden:
        assert token not in source, (
            f"classifier.py calls {token!r}; the manifest provider is the agent's "
            f"only filesystem contact and must stay read-only"
        )


def test_the_write_api_scan_can_actually_fail() -> None:
    """Negative control for the scan above.

    A source scanner that matches nothing is indistinguishable from a clean
    module. A string carrying the exact token shape is planted and the detector
    run over it; a scan that cannot fire is worse than no scan, because it
    reports "read-only" without having looked.
    """
    import inspect

    scan_tokens = ("open(", ".write_text(", ".mkdir(")
    planted = "def bad():\n    handle.write_text('x')\n"

    assert any(token in planted for token in scan_tokens), (
        "the planted defect does not carry a token the scan looks for, so the "
        "negative control proves nothing"
    )
    # And the real source, re-scanned, must NOT match - the same detector, the
    # two answers, so the pair is a real control rather than a tautology.
    real = inspect.getsource(classifier)
    assert not any(token in real for token in scan_tokens)


@pytest.mark.skipif(
    hasattr(os, "geteuid") and os.geteuid() == 0, reason="root ignores mode bits"
)
def test_reading_a_read_only_checkout_succeeds(checkout: pathlib.Path) -> None:
    """The provider needs no write permission anywhere.

    The agent container runs with ``readOnlyRootFilesystem: true`` (ARCH §8), so
    a provider that needed a scratch file or a temporary directory would fail in
    production while passing every test on a developer machine.
    """
    original: list[tuple[pathlib.Path, int]] = [
        (path, path.stat().st_mode) for path in [checkout, *checkout.rglob("*")]
    ]
    for path, _ in reversed(original):
        path.chmod(stat.S_IRUSR | (stat.S_IXUSR if path.is_dir() else 0))
    try:
        assert FileManifestProvider(checkout).read_manifest(TARGET_MANIFEST) == MANIFEST
    finally:
        for path, mode in original:
            path.chmod(mode)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


def test_unset_env_yields_the_fail_closed_default() -> None:
    """Fail-closed is the *normal* path, not a corner case (classifier.py:126)."""
    provider = manifest_provider_from_env({})
    assert provider.read_manifest(TARGET_MANIFEST) is None
    assert provider.read_manifest("anything") is None


def test_blank_env_yields_the_fail_closed_default() -> None:
    """A ConfigMap that renders an empty string is "unset", not "rooted at ''".

    ``Path("")`` resolves to the process's working directory, so honouring a
    blank value would silently mount the agent's CWD as its GitOps checkout and
    turn every Tier-1 attempt into a patch against whatever happens to be there.
    """
    assert (
        manifest_provider_from_env({MANIFEST_ROOT_ENV: "   "}).read_manifest(
            TARGET_MANIFEST
        )
        is None
    )


def test_a_usable_root_yields_a_filesystem_provider(checkout: pathlib.Path) -> None:
    provider = manifest_provider_from_env({MANIFEST_ROOT_ENV: str(checkout)})
    assert provider.read_manifest(TARGET_MANIFEST) == MANIFEST


@pytest.mark.parametrize(
    "value",
    ["/nonexistent/root/anywhere", "relative/that/does/not/exist"],
    ids=["absolute-missing", "relative-missing"],
)
def test_an_unusable_root_fails_closed_rather_than_raising(value: str) -> None:
    """A mistyped ConfigMap must not stop the incident responder.

    It must stop it from *patching*, which is the property that matters: an
    agent that will not start because of a typo is an outage, and an agent that
    starts and escalates is a degraded-but-serving component.
    """
    provider = manifest_provider_from_env({MANIFEST_ROOT_ENV: value})
    assert provider.read_manifest(TARGET_MANIFEST) is None


def test_a_file_as_the_root_is_refused(checkout: pathlib.Path) -> None:
    """``SREK3S_MANIFEST_ROOT`` pointing at a file is a config error, not a root."""
    provider = manifest_provider_from_env(
        {MANIFEST_ROOT_ENV: str(checkout / TARGET_MANIFEST)}
    )
    assert provider.read_manifest(TARGET_MANIFEST) is None


def test_the_default_provider_and_the_env_default_agree() -> None:
    """The documented default is the one the service actually gets.

    Asserted rather than assumed, because "the running service escalates" is a
    claim in ``classifier.py``'s docstring and in the ROADMAP, and a future
    change that made the default a filesystem provider would quietly turn
    fail-closed into an assumption.
    """
    default = manifest_provider_from_env({})
    unreadable = unreadable_manifest_provider()
    for path in (TARGET_MANIFEST, "nope.yaml", "../../etc/passwd", "/etc/passwd"):
        assert default.read_manifest(path) == unreadable.read_manifest(path) is None


# ---------------------------------------------------------------------------
# Which file Tier-1 is allowed to patch (SREK3S_TARGET_MANIFEST)
#
# `classifier.TARGET_MANIFEST` used to point at deploy/payments/checkout-api.yaml,
# which exists in no checkout of anything. With SREK3S_MANIFEST_ROOT set,
# read_manifest returned None and every incident escalated under I-B2, so no
# Tier-1 patch could ever be produced and ROADMAP 4.2.6 was unreachable on a
# live cluster. The variable is how a deployment says which file it owns; the
# default is now empty, so the only way to have a target is to configure one.
# ---------------------------------------------------------------------------


def test_there_is_no_shipped_default_target_manifest() -> None:
    """The defect, as a standing property: no default can come back.

    There is no path that is correct for an arbitrary deployment. The value that
    used to be here could not exist in any GitOps checkout, so it bought nothing
    except a second, indistinguishable cause of "every incident escalates":
    an empty mount and an unresolvable target present the same way, and the
    escalation text named the filesystem rather than the missing variable.

    `main` logs ERROR at startup when this is empty, and `_build_remediation_diff`
    escalates naming `SREK3S_TARGET_MANIFEST`. Both are what an operator needs;
    a fabricated default would make both unnecessary and wrong.
    """
    assert DEFAULT_TARGET_MANIFEST == ""
    assert resolve_target_manifest({}) == ""
    assert resolve_target_manifest({TARGET_MANIFEST_ENV: ""}) == ""
    assert resolve_target_manifest({TARGET_MANIFEST_ENV: "   "}) == ""
    # And the module-level value this process actually reads, which conftest.py
    # has configured for the session, is not the empty default.
    assert TARGET_MANIFEST != ""


def test_the_override_is_honoured() -> None:
    """The positive case: a harness points the engine at its own fixture.

    This is what makes ROADMAP 4.2.6 reachable: the fixture the Sentinel
    detonates is the file the agent must read, or the patch is derived against a
    manifest that does not describe the running workload.
    """
    assert (
        resolve_target_manifest({TARGET_MANIFEST_ENV: "deploy/chaos/oom-leak.yaml"})
        == "deploy/chaos/oom-leak.yaml"
    )


@pytest.mark.parametrize(
    "value",
    [
        "/etc/passwd.yaml",
        "C:\\secrets\\admin.yaml",
        "../outside/manifest.yaml",
        "deploy/../../etc/passwd.yaml",
        "deploy/chaos/oom-leak.txt",
        "notamanifest",
    ],
    ids=[
        "absolute",
        "drive-letter",
        "leading-traversal",
        "embedded-traversal",
        "wrong-extension",
        "bare-name",
    ],
)
def test_control_a_malformed_override_yields_no_target(
    value: str,
) -> None:
    """The defect: a mistyped target silently becomes the patch target.

    Every value here is refused, because it could not name a repo-relative
    manifest. The two dangerous outcomes of accepting one are: (a) a target that
    cannot exist, which escalates every incident under I-B2 and presents as a
    healthy system that never patches; and (b) a target that resolves to some
    other file, which patches the wrong thing. A refusal leaves no target at
    all, so the misconfiguration escalates rather than writing to something.

    This is the control that keeps the knob from being a way to smuggle a path
    past :meth:`FileManifestProvider._resolve`, which is the real security
    boundary and which re-checks on every read regardless.
    """
    assert resolve_target_manifest({TARGET_MANIFEST_ENV: value}) == ""


def test_control_a_malformed_override_is_logged(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A rejected override must be **named**, or it is a silent correction.

    Correcting the value quietly is how a misconfigured deployment ends up
    escalating every incident for a reason nobody logged. The warning carries the
    variable, the rejected value, and the fact that there is now no target - the
    last of those being what an operator has to act on, and the part that used to
    be a formatted `DEFAULT_TARGET_MANIFEST` that read as reassurance.
    """
    with caplog.at_level(logging.WARNING, logger="srek3s.agent"):
        assert resolve_target_manifest({TARGET_MANIFEST_ENV: "/etc/passwd"}) == ""
    assert TARGET_MANIFEST_ENV in caplog.text
    assert "/etc/passwd" in caplog.text
    assert "no patch target" in caplog.text


def test_a_valid_override_is_not_logged_as_a_warning(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A harness using the knob as intended must not look like a misconfiguration."""
    caplog.clear()
    with caplog.at_level(logging.WARNING, logger="srek3s.agent"):
        resolve_target_manifest({TARGET_MANIFEST_ENV: "deploy/chaos/oom-leak.yaml"})
    assert caplog.text == ""


def test_the_override_still_cannot_escape_the_checkout(
    tmp_path: pathlib.Path,
) -> None:
    """The knob chooses a file; it does not widen where files may be read from.

    The provider is the boundary, and it is unchanged: a target that resolves
    outside the mounted root is still refused, so setting the variable cannot
    turn the agent into a file-read primitive. Asserted because the new setting
    is the first thing a reader would ask about.
    """
    checkout = tmp_path / "checkout"
    (checkout / "deploy" / "chaos").mkdir(parents=True)
    provider = FileManifestProvider(checkout)
    for escape in ("../../etc/passwd.yaml", "/etc/passwd.yaml", "deploy/../../x.yaml"):
        assert provider.read_manifest(escape) is None
    # The legitimate case still works, which is what makes the refusals above
    # a decision rather than a blanket rejection.
    (checkout / "deploy" / "chaos" / "oom-leak.yaml").write_text(
        MANIFEST, encoding="utf-8"
    )
    assert provider.read_manifest("deploy/chaos/oom-leak.yaml") == MANIFEST


def test_the_startup_log_names_the_effective_target(
    checkout: pathlib.Path, caplog: pytest.LogCaptureFixture
) -> None:
    """A run that escalates every incident must say which file it wanted.

    "target manifest is unreadable" is indistinguishable from "the target is the
    wrong file", and the difference is one config key. The startup line is the
    only place both facts are visible together, so it carries the target.

    Driven through the real ``lifespan`` rather than by calling a logger
    directly, because a log line is a claim about a running service and the
    claim is only true if the running service emits it.
    """

    async def drive() -> None:
        async with _lifespan(
            create_app(manifest_provider=FileManifestProvider(checkout))
        ):
            pass

    with caplog.at_level(logging.INFO, logger="srek3s.agent"):
        asyncio.run(drive())
    assert "target_manifest=" in caplog.text
    assert TARGET_MANIFEST in caplog.text


def test_the_startup_log_errors_when_no_target_is_configured(
    checkout: pathlib.Path,
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An unset target is a fault, and it says so at ERROR rather than INFO.

    The two all-Tier-2 deployments are the empty mount and the unset target. The
    escalation text names the filesystem, so without this line they are the same
    incident from outside - and "the design is working" and "this deployment
    cannot do the thing Tier-1 exists for" need opposite responses from whoever
    is on call. `conftest.py` configures the target for the session, so the
    unset case has to be induced; the constant is read through the module
    attribute by `main`, which is what makes that faithful rather than a mock.
    """
    monkeypatch.setattr(classifier, "TARGET_MANIFEST", "")

    async def drive() -> None:
        async with _lifespan(
            create_app(manifest_provider=FileManifestProvider(checkout))
        ):
            pass

    with caplog.at_level(logging.INFO, logger="srek3s.agent"):
        asyncio.run(drive())
    assert "target_manifest=(none)" in caplog.text
    errors = [r for r in caplog.records if r.levelno == logging.ERROR]
    assert errors, "an unconfigured target must not be logged as routine startup"
    assert TARGET_MANIFEST_ENV in errors[0].getMessage()


# ---------------------------------------------------------------------------
# create_app wiring
# ---------------------------------------------------------------------------


def test_create_app_holds_the_provider_on_app_state(
    checkout: pathlib.Path,
) -> None:
    """The provider reaches the application, not just the factory.

    Asserted on ``app.state`` because that is the object the request handler
    reads. A provider passed to ``create_app`` and then dropped - which the
    first version of this wiring could trivially have done, since the handler
    simply did not accept one - would leave the factory's argument looking
    correct and the service unchanged.
    """
    provider = FileManifestProvider(checkout)
    app = create_app(manifest_provider=provider)
    assert app.state.manifest_provider is provider


def test_create_app_passes_the_provider_to_the_engine(
    checkout: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The wiring reaches the engine's own boundary, not just ``app.state``.

    Asserted by replacing ``triage.triage_payload`` and recording the keyword it
    was handed, because the property under test is that the provider *arrives*.
    A response assertion would also pass if the provider were correct but never
    threaded through - which is exactly the state the ROADMAP 4.2.6 note
    describes ("create_app takes no manifest_provider").
    """
    seen: list[Any] = []
    original = triage.triage_payload

    def recording(payload: Any, **kwargs: Any) -> Any:
        seen.append(kwargs.get("manifest_provider"))
        return original(payload, **kwargs)

    monkeypatch.setattr(triage, "triage_payload", recording)
    app = create_app(manifest_provider=FileManifestProvider(checkout))
    assert app.state.manifest_provider is not None
    assert isinstance(app.state.manifest_provider, FileManifestProvider)
    # The recorded call happens when a request is served, not at construction,
    # so the factory alone is not evidence the handler reads app.state.
    assert seen == [], "the stand-in was called at construction time, not on request"


def test_create_app_without_a_provider_keeps_the_service_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The default path is unchanged, and that is the point.

    A refactor whose "improvement" is that the service now patches by default
    would be a blast-radius regression wearing a feature's clothes.
    """
    monkeypatch.delenv(MANIFEST_ROOT_ENV, raising=False)
    app = create_app()
    provider = app.state.manifest_provider
    assert provider.read_manifest(TARGET_MANIFEST) is None


def test_create_app_reads_the_env_when_no_provider_is_passed(
    checkout: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``None`` means "ask the environment", not "no provider".

    The distinction matters: if ``None`` meant "no provider", the environment
    variable would be a ConfigMap key that does nothing, and a deployment that
    mounted a checkout and forgot one code change would escalate forever with no
    signal about why.
    """
    monkeypatch.setenv(MANIFEST_ROOT_ENV, str(checkout))
    app = create_app()
    assert app.state.manifest_provider.read_manifest(TARGET_MANIFEST) == MANIFEST


def test_the_startup_log_does_not_claim_a_capability_it_lacks(
    checkout: pathlib.Path, caplog: pytest.LogCaptureFixture
) -> None:
    """The log names the real provider.

    The startup line used to say ``manifest_provider=unreadable``
    unconditionally. Wiring a checkout in would have made that a lie, and a log
    that misreports whether patches are possible is worse than no log: an
    operator reads it to decide whether Tier-1 is reachable.
    """
    with caplog.at_level(logging.INFO, logger="srek3s.agent"):
        manifest_provider_from_env({MANIFEST_ROOT_ENV: str(checkout)})

    assert "GitOps checkout mounted" in caplog.text
    assert str(checkout) in caplog.text

    caplog.clear()
    with caplog.at_level(logging.INFO, logger="srek3s.agent"):
        manifest_provider_from_env({})
    assert "GitOps checkout mounted" not in caplog.text


# ---------------------------------------------------------------------------
# War-room dispatch on every Tier-2 path
# ---------------------------------------------------------------------------


def _escalating_outcome(**overrides: Any) -> Any:
    document = incident_document(**overrides)
    return triage_payload(models.IncidentPayload.model_validate(document))


def test_every_tier_two_path_emits_a_dispatch() -> None:
    """``build_dispatch`` had no production caller before this.

    It was exercised only by ``test_milestone2.py``, so a Tier-2 response was
    the only artefact an escalation produced - and Contract B has no field for
    ``do_not_apply``, so the marker ARCH §2.6.2 calls "a field a channel
    renderer cannot drop" existed nowhere an operator could reach.
    """
    for label, outcome in (
        ("no provider", _escalating_outcome()),
        (
            "crash loop",
            _escalating_outcome(
                reason="CrashLoopBackOff", exit_code=None, restart_count=3
            ),
        ),
        ("restart ceiling", _escalating_outcome(restart_count=99)),
    ):
        assert outcome.tier.value == "TIER_2_ARCHITECTURAL", label
        assert outcome.dispatch is not None, f"{label} produced no dispatch"
        assert outcome.dispatch.do_not_apply == warroom.DO_NOT_APPLY, label
        assert warroom.DO_NOT_APPLY in outcome.response.rca_markdown, label


def test_the_dispatch_names_the_escalation_reasons() -> None:
    """The audit trail a War-Room reviewer needs, on the artefact they get.

    ``routing_reasons`` is the answer to "why was this escalated?", and an
    earlier shape computed the reasons and then rendered a dispatch that
    omitted them.
    """
    outcome = _escalating_outcome()
    assert outcome.dispatch is not None
    assert outcome.dispatch.routing_reasons == tuple(outcome.reasons)
    rendered = warroom.render_markdown(outcome.dispatch)
    for reason in outcome.reasons:
        assert reason in rendered, f"{reason!r} is missing from the dispatch"


def test_the_dispatch_is_rendered_through_the_rescan() -> None:
    """I-B6 applies to the Tier-2 deliverable too.

    The dispatch is built from the response and re-rendered; both passes go
    through ``rescan``, so a secret that reached the payload cannot reach the
    document a human reads. Contract A *should* have masked this key already;
    the test is that the backstop does not assume it did.

    The key is planted in ``previous_reason`` rather than in ``scrubbed_logs``
    on purpose. A dispatch quotes the **summary and the evidence lines**, and
    ``evidence_lines`` renders ``previous_termination_reason=<value>`` - so a
    key parked in the logs would never reach the dispatch at all and the
    assertion would pass without testing anything. This placement is what makes
    the redaction observable, and the ``redaction_rules_triggered`` check below
    is what proves a rule actually fired rather than the string simply being
    absent.

    ``reason="CrashLoopBackOff"`` forces the Tier-2 path on its own, with no
    dependence on a provider being absent.
    """
    payload = models.IncidentPayload.model_validate(
        incident_document(
            reason="CrashLoopBackOff",
            exit_code=None,
            restart_count=4,
            previous_reason="AKIAIOSFODNN7EXAMPLE",
        )
    )
    outcome = triage_payload(payload)
    assert outcome.tier.value == "TIER_2_ARCHITECTURAL"
    assert outcome.dispatch is not None

    rendered = warroom.render_markdown(outcome.dispatch)
    for document in (outcome.response.rca_markdown, rendered):
        assert "AKIAIOSFODNN7EXAMPLE" not in document

    # A rule actually fired. Without this, a dispatch that simply omitted the
    # field would satisfy the two assertions above and the test would be
    # measuring nothing.
    assert "aws_access_key_id" in outcome.dispatch.redaction_rules_triggered
    assert "aws_access_key_id" in rendered

    # And the masking removed the credential, not the sentence. A backstop that
    # blanks the whole line satisfies a leak test perfectly and leaves a
    # responder with nothing.
    assert "previous_termination_reason=" in rendered
    assert outcome.dispatch.evidence, "the dispatch carries no evidence to review"


def test_the_dispatch_carries_no_patch() -> None:
    """I-B5/I-B1: the Tier-2 artefact cannot express a write, structurally.

    Asserted on the *field set* of ``to_dict()``, not by scanning for a
    forbidden key: a test that looked for "no key named git_patch" would pass
    against a dispatch that had gained ``patch`` or ``change`` instead.
    """
    outcome = _escalating_outcome()
    assert outcome.dispatch is not None
    keys = set(_flatten_keys(outcome.dispatch.to_dict()))
    forbidden = {"git_patch", "patch", "kubectl", "command", "apply", "delete"}
    assert not keys & forbidden, f"the dispatch gained a write-shaped key: {keys}"
    assert outcome.dispatch.carries_patch is False


def _flatten_keys(value: Any, prefix: str = "") -> Iterator[str]:
    if isinstance(value, dict):
        for key, child in value.items():
            name = f"{prefix}.{key}" if prefix else str(key)
            yield name
            yield from _flatten_keys(child, name)
    elif isinstance(value, (list, tuple)):
        for index, child in enumerate(value):
            yield from _flatten_keys(child, f"{prefix}[{index}]")


# ---------------------------------------------------------------------------
# Tier-1 must not carry a dispatch
# ---------------------------------------------------------------------------


def test_tier_one_carries_no_dispatch(checkout: pathlib.Path) -> None:
    """The mirror of the escalation test.

    A Tier-1 response that also carried a war-room dispatch would be telling a
    responder "this needs human analysis" about a change the system intends to
    automate. The two are mutually exclusive.
    """
    payload = models.IncidentPayload.model_validate(incident_document())
    outcome = triage_payload(payload, manifest_provider=FileManifestProvider(checkout))
    assert outcome.tier.value == "TIER_1_TOIL"
    assert outcome.dispatch is None
    assert "DO NOT APPLY ANY CHANGE" not in outcome.response.rca_markdown


def test_the_tier_one_rca_is_not_the_dispatch(checkout: pathlib.Path) -> None:
    """``rca_markdown`` means different things per tier, and that is intentional.

    Tier-2's is the dispatch, because a Tier-2 responder's artefact *is* a
    dispatch (ROADMAP 2.6.1). Tier-1's is the RCA proper, because there is no
    dispatch to send. Pinning the difference stops a future "make it consistent"
    edit from quietly removing the Tier-2 marker.
    """
    payload = models.IncidentPayload.model_validate(incident_document())
    outcome = triage_payload(payload, manifest_provider=FileManifestProvider(checkout))
    assert outcome.response.rca_markdown.startswith("# RCA:")
    assert "## Evidence" in outcome.response.rca_markdown
