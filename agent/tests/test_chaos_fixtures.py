"""The chaos fixtures are CODE, and this file executes them.

Every defect found in `deploy/chaos/real-crash.yaml` on 2026-10-01 was found by
deploying it, and every one of them passed every structural check that existed at
the time. They are worth naming because they share a shape:

1. **`restartPolicy: Never`** made the fixture UNDETECTABLE BY CONSTRUCTION.
   `internal/k8s/watcher.go:236` drops a `Terminated` with a non-zero non-OOM exit,
   deliberately, because Contract A's `reason` admits only `OOMKilled` and
   `CrashLoopBackOff`. Without a restart there is no CrashLoopBackOff, so the
   Sentinel emitted nothing — with zero errors in its log, which is the silent
   blindness that failure mode is famous for.
2. **A `/tmp` marker file** raised `OSError: Read-only file system`, because the
   pod sets `readOnlyRootFilesystem`. The container still crashed, still exited
   non-zero, still emitted a Python traceback, and the RCA described a completely
   unrelated failure.
3. **An apostrophe in a comment** — "the kubelet's backoff" — terminated the shell
   string wrapping `python -c '...'`, producing `IndentationError` in the fixture
   rather than the `KeyError` it exists to produce.

Each is invisible to reading, invisible to a YAML parser, and invisible to every
RBAC and hardening assertion in `test_deploy_manifests.py`. The only thing that
catches them is running the script.

So this file runs it. Not in a cluster — locally, in-process, with a timeout. It
is the cheapest possible check and it would have caught all three before a single
pod was scheduled.

What it deliberately does NOT do is assert the pod reaches CrashLoopBackOff in a
cluster. That is a live property, and this is an offline gate; `REALWORLD_TESTING.md`
covers the live half.
"""

from __future__ import annotations

import pathlib
import subprocess
from typing import Any, Final

import pytest
import yaml

REPO_ROOT: Final[pathlib.Path] = pathlib.Path(__file__).resolve().parents[2]
CHAOS: Final[pathlib.Path] = REPO_ROOT / "deploy" / "chaos"

#: Long enough for `python:3.11-alpine` to start and raise, short enough that a
#: hung fixture fails the suite instead of stalling it.
FIXTURE_TIMEOUT_SECONDS: Final[int] = 30


def _container_command(name: str) -> list[str]:
    document = yaml.safe_load((CHAOS / name).read_text(encoding="utf-8"))
    containers = document["spec"]["template"]["spec"]["containers"]
    assert len(containers) == 1, "expected exactly one container"
    command: list[str] = containers[0]["command"]
    return command


class TestChaosFixturesAreExecutable:
    """Run the inline script the way the kubelet would.

    `sh` is invoked with the script on STDIN rather than as a file, which is
    closer to how a container receives `command: [sh, -c, <script>]` and avoids
    writing to the repository.
    """

    @pytest.mark.parametrize("name", ["real-crash.yaml"])
    def test_the_fixture_script_is_valid_shell(self, name: str) -> None:
        command = _container_command(name)
        assert command[0] == "/bin/sh" and command[1] == "-c"
        result = subprocess.run(
            ["/bin/sh", "-n"],
            input=command[2],
            capture_output=True,
            text=True,
            timeout=FIXTURE_TIMEOUT_SECONDS,
        )
        assert result.returncode == 0, f"shell syntax error: {result.stderr}"

    @pytest.mark.parametrize("name", ["real-crash.yaml"])
    def test_the_fixture_does_not_crash_for_the_wrong_reason(self, name: str) -> None:
        """The failure must be the KeyError under test, not an incidental one.

        This is the assertion whose absence let defects 2 and 3 ship: the container
        crashed, exited non-zero, and wrote a traceback either way. Only the
        EXCEPTION TYPE distinguishes "the fixture demonstrated a Python crash" from
        "the fixture had a bug and demonstrated that instead".
        """
        command = _container_command(name)
        result = subprocess.run(
            ["/bin/sh"],
            input=command[2],
            capture_output=True,
            text=True,
            timeout=FIXTURE_TIMEOUT_SECONDS,
        )
        combined = result.stdout + result.stderr

        assert "KeyError" in combined, (
            "the fixture did not raise KeyError; it produced:\n" + combined
        )
        # Every one of these is a way this fixture has failed while LOOKING healthy.
        for incidental in (
            "IndentationError",
            "SyntaxError",
            "Read-only file system",
            "PermissionError",
            "FileNotFoundError",
            "ModuleNotFoundError",
            "command not found",
        ):
            assert incidental not in combined, (
                f"the fixture failed with {incidental!r}, not the fault under test:\n"
                + combined
            )

    def test_the_fixture_writes_nothing_to_disk(self) -> None:
        """The script must not touch the filesystem at all.

        An earlier guard on this same defect asserted only that `Read-only file
        system` was absent from the output — and it was **vacuous**, caught by its
        own negative control. On the test host `/tmp` is writable, so the planted
        `touch /tmp/.marker` SUCCEEDED, raised nothing, and the guard passed while
        the defect was present. The real failure (`OSError: [Errno 30]`) only occurs
        inside the cluster, where `readOnlyRootFilesystem: true` is set.

        A negative control that fails for the wrong reason is worse than none: it
        reads as a pass. So the property is asserted directly rather than by waiting
        for an environment-dependent error — the script performs no filesystem
        write, which is both the requirement and the thing that was wrong.
        """
        command = _container_command("real-crash.yaml")
        body = command[2]
        for verb in ("touch ", "open(", ">", ">>", "makedirs", "Path("):
            assert verb not in body, (
                f"the fixture script contains {verb!r}; it must not write to the "
                "filesystem, because the pod runs with readOnlyRootFilesystem and "
                "the resulting OSError would replace the fault under test"
            )

    @pytest.mark.parametrize("name", ["real-crash.yaml"])
    def test_the_fixture_produces_a_real_traceback(self, name: str) -> None:
        """A traceback with frames, because that is what the RCA reasons over.

        A one-frame traceback is what a syntax error produces; a multi-frame one is
        what an application fault produces. The model is asked to explain frame
        names, so their absence is a silently degraded RCA.
        """
        command = _container_command(name)
        result = subprocess.run(
            ["/bin/sh"],
            input=command[2],
            capture_output=True,
            text=True,
            timeout=FIXTURE_TIMEOUT_SECONDS,
        )
        combined = result.stdout + result.stderr
        assert combined.count("Traceback (most recent call last):") == 1
        assert combined.count("File ") >= 2, (
            "expected at least two frames in the traceback:\n" + combined
        )

    @pytest.mark.parametrize("name", ["real-crash.yaml"])
    def test_the_fixture_exits_non_zero(self, name: str) -> None:
        command = _container_command(name)
        result = subprocess.run(
            ["/bin/sh"],
            input=command[2],
            capture_output=True,
            text=True,
            timeout=FIXTURE_TIMEOUT_SECONDS,
        )
        assert result.returncode != 0, "a crashing fixture must exit non-zero"

    @pytest.mark.parametrize("name", ["real-crash.yaml"])
    def test_the_planted_credential_reaches_the_log(self, name: str) -> None:
        """The fixture is only useful if the thing it plants actually arrives.

        Asserted positively rather than assumed: a fixture that silently stopped
        printing the key would pass every other test here and prove nothing about
        scrubbing.
        """
        command = _container_command(name)
        result = subprocess.run(
            ["/bin/sh"],
            input=command[2],
            capture_output=True,
            text=True,
            timeout=FIXTURE_TIMEOUT_SECONDS,
        )
        combined = result.stdout + result.stderr
        assert "AKIAIOSFODNN7EXAMPLE" in combined


class TestChaosFixturesAreDetectable:
    """Shape assertions the Sentinel depends on.

    Each corresponds to a way `internal/k8s/watcher.go` will emit nothing, with no
    error logged.
    """

    def _spec(self, name: str) -> dict[str, Any]:
        document = yaml.safe_load((CHAOS / name).read_text(encoding="utf-8"))
        spec: dict[str, Any] = document["spec"]["template"]["spec"]
        return spec

    def test_the_fixture_can_reach_crash_loop_backoff(self) -> None:
        """`restartPolicy` must let the kubelet publish CrashLoopBackOff.

        The single most expensive assertion in this file. With `Never`, the pod
        reaches `Failed` and the watcher drops it at `watcher.go:236` — correct
        behaviour, wrong fixture — and the entire validation run reports zero
        incidents with a clean log.
        """
        assert self._spec("real-crash.yaml")["restartPolicy"] == "Always"

    def test_the_fixture_is_a_deployment_not_a_bare_pod(self) -> None:
        """A bare Pod cannot restart, so it cannot CrashLoop.

        Asserted separately from the restartPolicy because it is the outer cause:
        a Pod with `restartPolicy: Always` is still rejected by the apiserver.
        """
        document = yaml.safe_load(
            (CHAOS / "real-crash.yaml").read_text(encoding="utf-8")
        )
        assert document["kind"] == "Deployment"
        assert document["spec"]["replicas"] == 1

    def test_the_fixture_is_not_oom_killed(self) -> None:
        """The limit must sit well above what the container allocates.

        If the fixture OOMs, the incident is indistinguishable from the sibling
        `oom-leak.yaml` and proves nothing about application-error detection.
        """
        container = yaml.safe_load(
            (CHAOS / "real-crash.yaml").read_text(encoding="utf-8")
        )["spec"]["template"]["spec"]["containers"][0]
        limits = container["resources"]["limits"]["memory"]
        requests = container["resources"]["requests"]["memory"]
        assert limits != requests, "the limit equals the request; an OOM is possible"

    def test_the_fixture_uses_one_unambiguous_image_ref(self) -> None:
        """One spelling per fixture, and it must be the qualified one.

        `imagePullPolicy: Never` resolves against the local store by EXACT ref.
        `python:3.11-alpine` and `docker.io/library/python:3.11-alpine` are
        different refs and only one is what `ctr images import` wrote, so the pod
        fails with `not found` — which points at a registry rather than at the
        naming.

        Scoped to `real-crash.yaml` deliberately. The two older fixtures ship the
        BARE spelling (`busybox:1.36.1`) and deliberately register both names in
        the containerd namespace, which works. Asserting a slash on them would be
        enforcing a preference rather than a correctness rule, and this repository
        has been wrong about exactly that distinction before.
        """
        container = yaml.safe_load(
            (CHAOS / "real-crash.yaml").read_text(encoding="utf-8")
        )["spec"]["template"]["spec"]["containers"][0]
        assert container["imagePullPolicy"] == "Never"
        assert container["image"].startswith(
            "docker.io/library/"
        ), f"{container['image']!r} must be fully qualified"
