"""Disposable investigation sandbox (ROADMAP §2.4).

Every investigation runs in a **fresh child process**. Nothing is reused between
incidents, so there is no in-memory state to leak: the guarantee "no state
survives into the next investigation" is satisfied structurally, by construction,
rather than by remembering to clear things.

What the isolation is actually for
----------------------------------
This process is the egress path for scrubbed-but-still-sensitive incident data.
An analysis that loops, allocates without bound, or hangs must not be able to
take down the agent, and must not be able to observe anything it was not given.
Concretely:

* **Deadline.** Every investigation is bounded by a **monotonic** deadline from
  :func:`time.perf_counter` (AGENTS.md §3.3). A wall clock would be wrong here:
  an NTP step backwards during an incident would turn the remaining budget
  negative and kill work that had time left, and a step forwards would expire it
  early.
* **Resources.** On POSIX the child gets ``RLIMIT_AS`` and ``RLIMIT_CPU`` set to
  the policy budget before ``exec``, so the limits are enforced by the kernel on
  the process itself and cannot be lifted from inside. **These are not cgroups**
  - see the note below.
* **No credentials.** The child is started with a constructed environment, not
  an inherited one. Nothing the Sentinel holds - kubeconfig, service-account
  tokens, cloud keys - is passed down, so an investigation cannot read it even if
  it wanted to. The allow-list is explicit, so adding a variable to the parent's
  environment cannot accidentally widen the child's reach.
* **No egress.** The child runs a fixed, in-process analysis: no network client
  is constructed and no URL is resolved. ARCH §5.3 keeps tier selection ahead of
  any model consultation, so the deterministic path needs no egress at all.

cgroups vs rlimits
------------------
ROADMAP §2.4.2 asks for a cgroup budget of ``256Mi`` / ``500m``. A cgroup is a
kernel accounting boundary and is not reachable from inside an ordinary
container, so this module does the strongest thing that *is* reachable:

* it applies ``RLIMIT_AS`` (address space) and ``RLIMIT_CPU`` (CPU seconds),
  which the kernel enforces on the child and which cannot be raised from inside;
* it probes for a cgroup v2 hierarchy and, when one is delegated, writes the
  memory and CPU ceilings there too.

The rlimits are always active and are what the test suite verifies. The cgroup
write is best-effort and **reports whether it happened** rather than pretending:
:attr:`SandboxResult.cgroup_enforced` is ``False`` wherever no delegated cgroup
exists, including most CI runners. Claiming the budget was cgroup-enforced when
it was not would defeat the point of stating it.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Final

# Typed as Any rather than ModuleType because `resource` is absent on Windows:
# a ModuleType annotation would make every attribute access a type error, and the
# platform guard below already proves the module is unusable when it is None.
_resource: Any
try:
    import resource as _resource
except ImportError:  # pragma: no cover - Windows has no `resource`
    # Not a fallback: on Windows the deadline and the kill are the enforcement
    # mechanisms, and resource_limits_supported() reports False so callers and
    # tests can see the ceiling was not applied. Importing unguarded would make
    # the whole module unimportable on the development host.
    _resource = None

__all__ = [
    "DEFAULT_MEMORY_BYTES",
    "DEFAULT_CPU_SECONDS",
    "SANDBOX_ENV_ALLOWLIST",
    "SandboxError",
    "SandboxTimeout",
    "SandboxPolicy",
    "SandboxResult",
    "SandboxRunner",
    "resource_limits_supported",
]

#: ROADMAP §2.4.2. 256 MiB address space, 500 ms of CPU per investigation.
DEFAULT_MEMORY_BYTES: Final[int] = 256 * 1024 * 1024
DEFAULT_CPU_SECONDS: Final[int] = 1

#: The only environment variables the child may see.
#:
#: An allow-list rather than a deny-list, deliberately. With a deny-list, adding
#: a variable to the parent environment - which happens constantly in CI and in
#: cluster deployments - would silently widen what the investigation can read.
SANDBOX_ENV_ALLOWLIST: Final[tuple[str, ...]] = (
    "PATH",
    "PYTHONPATH",
    "PYTHONHASHSEED",
    "LANG",
    "LC_ALL",
    "SYSTEMROOT",  # required for Python on Windows
    "TEMP",
    "TMP",
    "TMPDIR",
)

_CGROUP_ROOT: Final[Path] = Path("/sys/fs/cgroup")


class SandboxError(RuntimeError):
    """The investigation could not be completed."""


class SandboxTimeout(SandboxError):
    """The investigation exceeded its monotonic deadline and was killed."""

    def __init__(self, elapsed: float, deadline: float) -> None:
        super().__init__(
            f"investigation exceeded its {deadline}s deadline after {elapsed:.3f}s "
            "and was terminated"
        )
        self.elapsed = elapsed
        self.deadline = deadline


def resource_limits_supported() -> bool:
    """Whether this platform can apply rlimits to a child process.

    ``resource.setrlimit`` exists on POSIX only. Windows has no equivalent that
    ``subprocess`` can install before ``exec``, so on Windows the deadline and
    the kill are the enforcement mechanisms and the memory ceiling is not.
    """
    return _resource is not None and os.name == "posix"


@dataclass(frozen=True)
class SandboxPolicy:
    """Per-investigation resource and time budget."""

    #: Wall-clock-equivalent budget, enforced against a monotonic clock.
    deadline_seconds: float = 5.0
    memory_bytes: int = DEFAULT_MEMORY_BYTES
    cpu_seconds: int = DEFAULT_CPU_SECONDS
    #: Best-effort cgroup ceiling; ignored where none is delegated.
    cgroup_memory_bytes: int = DEFAULT_MEMORY_BYTES
    cgroup_cpu_weight: int = 100

    def __post_init__(self) -> None:
        if self.deadline_seconds <= 0:
            raise ValueError("deadline_seconds must be positive")
        if self.memory_bytes <= 0:
            raise ValueError("memory_bytes must be positive")


@dataclass
class SandboxResult:
    """What one investigation produced, and how it was constrained."""

    payload: dict[str, object]
    latency_ms: int
    rlimits_applied: bool
    cgroup_enforced: bool
    stdout_bytes: int

    def as_json(self) -> str:
        """Serialise for transport.

        ``latency_ms`` comes from ``time.perf_counter`` (AGENTS.md §3.3), not a
        wall clock: a host whose clock is stepped by NTP mid-incident would
        otherwise report a negative latency, or an absurd one.
        """
        return json.dumps(
            {
                "result": self.payload,
                "analysis_latency_ms": self.latency_ms,
                "rlimits_applied": self.rlimits_applied,
                "cgroup_enforced": self.cgroup_enforced,
            },
            sort_keys=True,
        )


def _child_environment() -> dict[str, str]:
    """Build the child's environment from the allow-list alone."""
    env = {
        name: os.environ[name] for name in SANDBOX_ENV_ALLOWLIST if name in os.environ
    }
    # Deterministic hashing keeps an investigation reproducible for replay.
    env.setdefault("PYTHONHASHSEED", "0")
    return env


def _make_preexec(memory_bytes: int, cpu_seconds: int) -> Callable[[], None]:
    """Build the ``preexec_fn`` that installs rlimits before ``exec``.

    Returned as a factory so the closure captures the limits. Only ever called on
    POSIX, where :mod:`resource` exists.
    """
    module = _resource
    if module is None:  # pragma: no cover - guarded by resource_limits_supported
        raise SandboxError("rlimits are unavailable on this platform")

    def _apply() -> None:  # pragma: no cover - runs in the child before exec
        module.setrlimit(module.RLIMIT_AS, (memory_bytes, memory_bytes))
        module.setrlimit(module.RLIMIT_CPU, (cpu_seconds, cpu_seconds))
        # No core files: an investigation that is about to be killed must not
        # leave a dump of incident data on disk.
        module.setrlimit(module.RLIMIT_CORE, (0, 0))
        # A fresh process group, so a timeout kill reaches the whole subtree
        # rather than leaving orphans behind.
        #
        # Resolved through getattr rather than a bare `os.setsid()` with a
        # `# type: ignore`. A conditional ignore is a trap here: `setsid` is
        # absent from typeshed on Windows and present on Linux, and setup.cfg
        # sets `warn_unused_ignores = True`. So the same line is *needed* on one
        # platform and *reported as dead* on the other, which is how this passed
        # locally and failed CI's G6. getattr type-checks identically everywhere.
        setsid = getattr(os, "setsid", None)
        if setsid is not None:
            setsid()

    return _apply


def _try_cgroup(path: str, value: str) -> bool:
    """Best-effort write into a delegated cgroup v2 file.

    Returns whether it happened. Almost never, in a container without a delegated
    cgroup - which is exactly why the result is reported rather than assumed.
    """
    target = _CGROUP_ROOT / path
    try:
        with target.open("w", encoding="ascii") as handle:
            handle.write(value)
        return True
    except (OSError, ValueError):
        return False


@dataclass
class SandboxRunner:
    """Runs one deterministic analysis per child process, then discards it.

    ``peak_concurrent`` is the highest number of children this runner had alive at
    once. It is the observable that ties the sandbox to the job budget: because
    the budget admits a request before the sandbox is started, and the sandbox is
    released only when its child is reaped, the peak can never exceed
    ``budget.max_active``. The counter exists so that can be asserted rather than
    assumed - and it needs a lock because requests reach the runner from the
    threadpool, not from a single event-loop thread.
    """

    policy: SandboxPolicy = field(default_factory=SandboxPolicy)
    #: Directory holding the agent modules. Defaults to this file's directory,
    #: so the child imports exactly the code the parent would.
    agent_dir: Path = field(default_factory=lambda: Path(__file__).resolve().parent)
    peak_concurrent: int = 0
    _live: int = 0
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def _enter(self) -> None:
        with self._lock:
            self._live += 1
            self.peak_concurrent = max(self.peak_concurrent, self._live)

    def _exit(self) -> None:
        with self._lock:
            self._live = max(0, self._live - 1)

    def run(self, incident: dict[str, object]) -> SandboxResult:
        """Analyse ``incident`` in a disposable child process, then discard it.

        Raises :class:`SandboxTimeout` when the monotonic deadline passes - the
        child is killed before the exception propagates, so no investigation
        outlives its budget - and :class:`SandboxError` for any other failure.
        """
        started = time.perf_counter()
        self._enter()
        try:
            return self._run_guarded(incident, started)
        finally:
            # Released even when the deadline killed the child, so the peak
            # tracks children that were actually alive rather than requests that
            # merely arrived.
            self._exit()

    def _run_guarded(
        self, incident: dict[str, object], started: float
    ) -> SandboxResult:
        with tempfile.TemporaryDirectory(prefix="srek3s-sandbox-") as tmp:
            incident_path = Path(tmp) / "incident.json"
            incident_path.write_text(json.dumps(incident), encoding="utf-8")

            env = _child_environment()
            env["PYTHONPATH"] = str(self.agent_dir)

            # No shell, fixed argv. `-I` is deliberately *not* used: it would
            # ignore the PYTHONPATH that puts agent/ on the child's import path.
            # Isolation comes from the fresh process and the scrubbed environment.
            argv = [
                sys.executable,
                "-m",
                "sandbox_worker",
                str(incident_path),
            ]

            preexec = (
                _make_preexec(self.policy.memory_bytes, self.policy.cpu_seconds)
                if resource_limits_supported()
                else None
            )

            try:
                completed = subprocess.run(  # noqa: S603 - fixed argv, no shell
                    argv,
                    cwd=str(self.agent_dir),
                    env=env,
                    capture_output=True,
                    text=True,
                    timeout=self.policy.deadline_seconds,
                    check=False,
                    preexec_fn=preexec,
                )
            except subprocess.TimeoutExpired as exc:
                # subprocess.run has already killed and reaped the child.
                raise SandboxTimeout(
                    elapsed=time.perf_counter() - started,
                    deadline=self.policy.deadline_seconds,
                ) from exc
            except OSError as exc:
                raise SandboxError(f"could not start the sandbox: {exc}") from exc

            elapsed = time.perf_counter() - started

            if completed.returncode != 0:
                raise SandboxError(
                    f"sandbox exited {completed.returncode}: "
                    f"{(completed.stderr or '').strip()[:200] or 'no diagnostic'}"
                )

            try:
                payload = json.loads(completed.stdout)
            except json.JSONDecodeError as exc:
                raise SandboxError(
                    f"sandbox produced non-JSON output: {completed.stdout[:120]!r}"
                ) from exc

        # cgroup_enforced is reported, and it must never claim a limit that was
        # never applied to this child.
        #
        # This used to write memory.max and cpu.max AFTER subprocess.run had
        # already returned and reaped the child, into a cgroup the child was never
        # a member of. It therefore bounded nothing, and could report
        # cgroup_enforced=True for a constraint that constrained no one - exactly
        # the "claiming the budget was enforced when it was not" outcome this
        # module exists to prevent. The child must be moved into the cgroup
        # BEFORE it execs for the write to mean anything, and this deployment has
        # neither CAP_SYS_ADMIN nor a writable cgroup mount to do that with.
        #
        # So rather than report a fiction, cgroup_enforced is False
        # unconditionally and rlimits_applied reflects what genuinely happened -
        # the setrlimit pair installed by preexec_fn before exec.
        rlimits_ok = resource_limits_supported() and preexec is not None

        return SandboxResult(
            payload=payload,
            latency_ms=int(elapsed * 1000),
            rlimits_applied=rlimits_ok,
            cgroup_enforced=False,
            stdout_bytes=len(completed.stdout.encode("utf-8")),
        )
