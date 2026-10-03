"""The GitHub Actions workflows are part of the repository's invariants.

Authored because a broken workflow is invisible until someone else's push: it
does not fail locally, it fails on a machine that is not this one, and by then
the commit is already on `main`.

Four properties are asserted, each of which has a specific silent failure:

1. **Every workflow parses.** A YAML syntax error is a red X with no explanation
   on someone else's pull request.
2. **``on:`` is not boolean True.** YAML 1.1 parses a bare ``on:`` as the boolean
   ``True``, and a workflow keyed on ``True`` never triggers — it looks present
   in review and runs on nothing, forever.
3. **``needs:`` resolves.** A ``needs:`` naming a job that does not exist fails
   at workflow-parse time on GitHub, which is an unhelpful place to learn it.
4. **Least privilege, and pushing is read from structure rather than text.** A
   workflow that installs third-party dependencies on every pull request must
   never hold a registry write token; only the release workflow may, and only on
   the single job that publishes.

Point 4's structure-reading matters and is the reason this file exists rather than
a grep in CI. The first two versions of the push detection used
``"--push" in text``, and both reported `ci.yaml` as publishing — because that
workflow's only occurrences of the string are inside comments explaining why
`--push` is *not* used for a dry run. **A grep cannot tell a comment from
behaviour**, and a check that reads its own documentation as a finding is worse
than no check.

5. **The reachable-CVE gate is present and cannot be neutered.** See
   :class:`TestReachableCveGate`. This is the only assertion here that guards the
   *absence* of a failure, which is the hardest kind of absence to notice: a CI gate
   that quietly stops gating produces no red X and no log line.
"""

from __future__ import annotations

import pathlib
from typing import Any, cast

import pytest
import yaml

WORKFLOWS = pathlib.Path(__file__).resolve().parents[2] / ".github" / "workflows"

#: Workflows this repository must have. A rename that drops one of these breaks a
#: release process, and nothing else would notice.
REQUIRED_WORKFLOWS = frozenset({"ci.yaml", "release.yaml"})

#: Only this workflow may hold a registry write token, and only on one job.
PUBLISHING_WORKFLOW = "release.yaml"


def load(name: str) -> dict[str, Any]:
    document = yaml.safe_load((WORKFLOWS / name).read_text(encoding="utf-8"))
    assert isinstance(document, dict), f"{name} did not parse to a mapping"
    return document


def trigger_of(document: dict[str, Any]) -> Any:
    """The ``on:`` value, tolerant of PyYAML's boolean-True key.

    PyYAML follows YAML 1.1, where a bare ``on:`` is the boolean ``True``. GitHub
    parses with YAML 1.2, where it is the string ``"on"``. So the two disagree about
    a key that is correct in both, and this helper accepts either spelling.

    The cast is not papering over a type error. ``dict[str, Any].get(True)`` is
    genuinely outside the annotation — mypy is right that a ``str``-keyed mapping has
    no boolean key — and the key really can be boolean, because that is exactly what
    the YAML 1.1 resolver produces. The cast records an intentional widening past the
    declared type rather than concealing a mistake.
    """
    if "on" in document:
        return document["on"]
    boolean_keyed = cast("dict[Any, Any]", document)
    return boolean_keyed.get(True)


def actually_pushes(document: dict[str, Any]) -> bool:
    """Whether any step registers and uploads an image, read from the structure.

    Not a text search. Comments in `ci.yaml` mention ``--push`` while explaining
    why it is not used, and a grep reads those as publishing.
    """
    for job in (document.get("jobs") or {}).values():
        for step in job.get("steps") or []:
            uses = str(step.get("uses", ""))
            params = step.get("with") or {}
            if "build-push-action" in uses and params.get("push") is True:
                return True
            if "login-action" in uses and params.get("password"):
                return True
    return False


def permission_holders(document: dict[str, Any], permission: str) -> list[str]:
    """Job ids granted ``permission: write``, at job or workflow level.

    Returns ``["<workflow>"]`` for a workflow-level grant, because that grants it
    to every job and is strictly weaker than the per-job form.
    """
    workflow_level = document.get("permissions") or {}
    if "write" in str(workflow_level.get(permission, "")):
        return ["<workflow-level>"]
    holders: list[str] = []
    for job_id, job in (document.get("jobs") or {}).items():
        perms = job.get("permissions") or {}
        if "write" in str(perms.get(permission, "")):
            holders.append(job_id)
    return holders


class TestWorkflowsExistAndParse:
    def test_every_required_workflow_is_present(self) -> None:
        present = {path.name for path in WORKFLOWS.glob("*.y*ml")}
        missing = REQUIRED_WORKFLOWS - present
        assert not missing, f"missing workflows: {sorted(missing)}"

    @pytest.mark.parametrize("name", sorted(REQUIRED_WORKFLOWS))
    def test_each_parses_to_a_mapping(self, name: str) -> None:
        load(name)

    @pytest.mark.parametrize(
        "path", sorted(WORKFLOWS.glob("*.y*ml")), ids=lambda p: p.name
    )
    def test_no_workflow_has_unparseable_yaml(self, path: pathlib.Path) -> None:
        try:
            document = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:  # pragma: no cover - the assertion is the point
            pytest.fail(f"{path.name}: YAML parse error: {exc}")
        assert isinstance(document, dict), f"{path.name} is not a mapping"


class TestTriggersAreNotSilentlyDisabled:
    @pytest.mark.parametrize(
        "path", sorted(WORKFLOWS.glob("*.y*ml")), ids=lambda p: p.name
    )
    def test_every_workflow_declares_a_resolvable_trigger(
        self, path: pathlib.Path
    ) -> None:
        """The trigger must resolve to a real trigger under BOTH YAML dialects.

        PyYAML follows YAML 1.1, where a bare ``on:`` is the boolean ``True``.
        GitHub parses with YAML 1.2, where it is the string ``"on"``. So the two
        parsers disagree about a key that is correct in both — and a workflow can
        satisfy one and be unreadable to the other.

        An earlier version of this test asserted ``True not in document``, on the
        theory that a boolean key meant the trigger was disabled. That assertion is
        **wrong** and it failed on all three healthy workflows: every one of them
        parses to ``True`` under PyYAML and works correctly under GitHub. The
        hazard is real only for a workflow whose trigger is *empty*; asserting on
        the key's TYPE checks the parser, not the workflow.

        So the assertion is on what the trigger resolves TO, which is the property
        that actually matters and is dialect-independent.
        """
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
        trigger = trigger_of(document)
        assert trigger, (
            f"{path.name}: no trigger. A bare `on:` with no value parses to None "
            "and the workflow never runs."
        )
        assert isinstance(trigger, (dict, list, str)), (
            f"{path.name}: trigger resolved to {type(trigger).__name__}, which is "
            "neither a mapping of events nor a list of event names"
        )

    def test_ci_runs_on_pull_requests_and_main(self) -> None:
        trigger = trigger_of(load("ci.yaml"))
        assert "pull_request" in trigger, "CI must gate pull requests"
        assert "push" in trigger, "CI must run on pushes to main"

    def test_release_runs_on_version_tags_only(self) -> None:
        """A release workflow that also fires on branch pushes publishes on every commit."""
        trigger = trigger_of(load("release.yaml"))
        assert set(trigger) == {"push"}, f"expected push only, got {sorted(trigger)}"
        push_filters = trigger["push"] or {}
        assert "tags" in push_filters, "the release must be tag-gated"
        assert (
            "branches" not in push_filters
        ), "a branch trigger would publish an image on every commit to main"
        assert any(
            t.startswith("v") for t in push_filters["tags"]
        ), f"expected a v-prefixed version tag, got {push_filters['tags']}"


class TestJobGraph:
    @pytest.mark.parametrize(
        "path", sorted(WORKFLOWS.glob("*.y*ml")), ids=lambda p: p.name
    )
    def test_every_needs_reference_resolves(self, path: pathlib.Path) -> None:
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
        jobs = document.get("jobs") or {}
        for job_id, job in jobs.items():
            needs = job.get("needs") or []
            required = [needs] if isinstance(needs, str) else list(needs)
            for dependency in required:
                assert (
                    dependency in jobs
                ), f"{path.name}:{job_id} needs {dependency!r}, which is not a job"


class TestLeastPrivilege:
    @pytest.mark.parametrize(
        "path", sorted(WORKFLOWS.glob("*.y*ml")), ids=lambda p: p.name
    )
    def test_only_the_release_workflow_may_publish(self, path: pathlib.Path) -> None:
        """A test workflow holding `packages: write` is a supply-chain hazard.

        `ci.yaml` installs third-party packages on every pull request — including
        from forks. A registry credential in that job would be handed to whatever
        the pull request's build steps do.
        """
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
        holders = permission_holders(document, "packages")
        if path.name == PUBLISHING_WORKFLOW:
            assert holders, (
                "release.yaml publishes images but grants no packages: write, so "
                "the push would fail"
            )
        else:
            assert not holders, (
                f"{path.name} holds packages: write on {holders}; only "
                f"{PUBLISHING_WORKFLOW} may publish"
            )

    @pytest.mark.parametrize(
        "path", sorted(WORKFLOWS.glob("*.y*ml")), ids=lambda p: p.name
    )
    def test_pushing_is_read_from_structure_not_from_text(
        self, path: pathlib.Path
    ) -> None:
        """Only the release workflow actually uploads.

        The negative control for the comment problem described in the module
        docstring: ci.yaml mentions ``--push`` inside comments explaining why it is
        not used, so any text-based detection reports it as publishing.
        """
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
        publishes = actually_pushes(document)
        if path.name == PUBLISHING_WORKFLOW:
            assert publishes, "release.yaml declares no step with push: true"
        else:
            assert not publishes, f"{path.name} appears to push an image"

    def test_the_write_grant_is_scoped_to_one_job(self) -> None:
        """Per-job, not workflow-level.

        Workflow-level `packages: write` grants it to `validate-tag` as well,
        which does not push anything. Narrowing it means the credential is present
        in exactly one job's environment.
        """
        document = load("release.yaml")
        assert permission_holders(document, "packages") != [
            "<workflow-level>"
        ], "packages: write must be granted per job, not workflow-wide"


#: Actions that BUILD an image. Scoped deliberately: `docker/setup-qemu-action`
#: takes a `platforms:` input too, meaning which emulators to register, and
#: treating that as a build-platform field reported a healthy workflow as missing
#: amd64 — the step says `platforms: arm64` and the assertion wanted a substring
#: that is not in it.
BUILD_ACTIONS = ("build-push-action",)


def build_platforms(document: dict[str, Any]) -> list[tuple[str, str]]:
    """``[(dockerfile, platforms)]`` for every image-building step."""
    found: list[tuple[str, str]] = []
    for job in (document.get("jobs") or {}).values():
        for step in job.get("steps") or []:
            uses = str(step.get("uses", ""))
            if not any(action in uses for action in BUILD_ACTIONS):
                continue
            params = step.get("with") or {}
            platforms = params.get("platforms")
            if platforms:
                found.append((str(params.get("file", "")), str(platforms)))
    return found


class TestMultiArchCoverage:
    @pytest.mark.parametrize("name", sorted(REQUIRED_WORKFLOWS))
    def test_image_builds_cover_both_architectures(self, name: str) -> None:
        """An image that builds for one CPU is not a multi-arch release.

        Before the BuildKit refactor both Dockerfiles compiled for whatever CPU
        ran the build. On a single-architecture runner that is invisible: the image
        builds, every gate passes, and the Dockerfile is wrong. The failure only
        appears on a cluster with the other architecture, as an exec format error.
        """
        document = load(name)
        builds = build_platforms(document)
        assert builds, f"{name}: no image-building step found"
        for dockerfile, platforms in builds:
            assert (
                "linux/amd64" in platforms
            ), f"{name}: {dockerfile} builds {platforms!r}, missing amd64"
            assert (
                "linux/arm64" in platforms
            ), f"{name}: {dockerfile} builds {platforms!r}, missing arm64"

    def test_both_images_are_built_for_both_platforms(self) -> None:
        """The Sentinel and the Agent must both be covered.

        Asserted together because a workflow that covers one and not the other
        produces a release where the daemon is portable and the agent is not —
        which fails on an arm64 cluster at pod start, in the component that is
        harder to diagnose.
        """
        for name in REQUIRED_WORKFLOWS:
            document = load(name)
            builds = build_platforms(document)
            if not builds:
                continue
            files = {dockerfile for dockerfile, _ in builds}
            assert any(
                "sentinel" in f for f in files
            ), f"{name}: no sentinel build; files seen: {sorted(files)}"
            assert any(
                "agent" in f for f in files
            ), f"{name}: no agent build; files seen: {sorted(files)}"


class TestReachableCveGate:
    """G7 must exist, and must fail the job rather than merely report.

    Why this needs guarding at all, given that CI *looks* green either way:

    govulncheck was added as a Go quality gate on 2026-10-03 after it found
    GO-2026-5970 by hand — an infinite loop in ``golang.org/x/text`` reachable
    through ``GetLogs().Stream()``, the sentinel's own log-reading path. Three
    separate ways this gate could have been decorative, each of which a reader
    would have taken at face value:

    1. **Removed.** The step is gone, and no test fails. Nothing else in the suite
       mentions vulnerability scanning, so its absence is silent.
    2. **Reporting rather than gating.** ``govulncheck ./... | tee out.txt``
       without ``pipefail`` has the exit status of ``tee``, which is always 0.
       The scan runs, prints a report, and the job passes on a vulnerable tree.
    3. **Fail-open on its own data source.** Verified by running it against an
       unreachable advisory endpoint, twice — the first attempt silently fell back
       to the local cache and proved nothing. With vuln.go.dev unreachable it exits
       0 and prints "No vulnerabilities found.", byte-identical to a clean scan. On
       a fresh CI runner there is no cache, so an outage turns this gate green
       while it knows of no advisories at all.

    Case 3 is the one worth reading twice. It is not a theoretical concern about
    the tool; it is the observed behaviour of the tool, and it means the scan
    output alone cannot be trusted to mean anything. Hence the explicit
    reachability precheck, and hence an assertion that the precheck exists.
    """

    def _g7_step(self) -> dict[str, Any]:
        document = load("ci.yaml")
        jobs = document.get("jobs") or {}
        go_gates = jobs.get("go-gates") or {}
        matches = [
            step
            for step in (go_gates.get("steps") or [])
            if "govulncheck" in str(step.get("run", ""))
            and "install" not in str(step.get("name", "")).lower()
        ]
        assert (
            matches
        ), "no govulncheck scan step in the go-gates job; G7 has been removed"
        # cast, because the steps list is untyped and mypy will not narrow a
        # list comprehension over `Any` by way of the assert above.
        return cast(dict[str, Any], matches[0])

    def test_the_scan_runs_in_the_go_gates_job(self) -> None:
        assert "govulncheck ./..." in str(self._g7_step()["run"])

    def test_the_scan_can_fail_the_job(self) -> None:
        """``pipefail`` is the whole difference between a gate and a report."""
        run = str(self._g7_step()["run"])
        assert "set -euo pipefail" in run, (
            "the scan step lacks `set -euo pipefail`. Without `pipefail`, a "
            "`govulncheck ... | tee` pipeline reports tee's exit status (always 0) "
            "and the gate passes on every scan, including a vulnerable tree."
        )

    def test_an_unreachable_advisory_database_fails_the_job(self) -> None:
        """The fail-open case, asserted rather than assumed fixed.

        govulncheck reporting "No vulnerabilities found" while unable to fetch any
        advisories is indistinguishable from a genuinely clean scan — so the step
        must establish reachability BEFORE trusting a clean result.
        """
        run = str(self._g7_step()["run"])
        assert "vuln.go.dev" in run, (
            "the step never asserts advisory reachability; govulncheck exits 0 and "
            "reports no vulnerabilities when vuln.go.dev is unreachable, so a "
            "network blip turns this gate green while it knows of nothing"
        )
        assert (
            "exit 1" in run
        ), "the reachability check must be able to fail the step, not just report"

    def test_the_scanner_is_pinned(self) -> None:
        """An unpinned ``@latest`` hands the gate's verdict to whoever publishes next.

        For a security gate that is the wrong default. Dependabot already watches
        this repository, so the bump can arrive through review rather than silently
        changing what "the build passed" means.
        """
        document = load("ci.yaml")
        installs = [
            step
            for job in (document.get("jobs") or {}).values()
            for step in (job.get("steps") or [])
            if "govulncheck@" in str(step.get("run", ""))
        ]
        assert installs, "govulncheck is installed nowhere in any workflow"
        for step in installs:
            assert "@latest" not in str(step["run"]), (
                "govulncheck is installed at @latest; the tool that decides whether "
                "the build passes should change through review"
            )
