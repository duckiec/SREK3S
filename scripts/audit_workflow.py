"""Pre-push audit of the GitHub Actions workflows.

Exits non-zero on any FAIL, so it is a gate and not a review aid. Run it from the
repository root:

    python scripts/audit_workflow.py

Lives in the repository rather than in a scratch directory because its whole value
is that it runs *before* the push. The first remote detonation run failed at
"Install k3s" for a reason this script could have caught and did not, and a
checking tool that lives in a temp directory is a tool that runs once.

The checks, and the failure each one exists for:

1. **Timeouts.** A step that blocks on an external command needs its own bound.
   The job-level budget is a backstop, not a control: it fires after the runner
   has already been held for the maximum time.

2. **pipefail.** ``curl ... | sh -`` without it fails *green* - a failed download
   pipes an empty body into ``sh``, which exits 0 - and every later step then
   fails against something that was never installed. The Actions default shell
   sets ``-e`` but not ``pipefail``.

3. **Offline gates first.** A check that needs no cluster must not run after the
   cluster is built. ``verify_patch.py`` ran at step 18 of 21, so the one check
   that would have caught the unapplyable-patch P0 was gated behind a full
   cluster bring-up.

4. **Precondition ordering.** A command whose preconditions are not yet satisfied
   fails in a way that looks like an unrelated problem. This is the check whose
   absence let ``kubectl version`` (which contacts the apiserver) run in the k3s
   install step, before the readiness wait that establishes the apiserver. The
   symptom was a failing "Install k3s" step on a cluster that had installed
   correctly.

5. **Streaming.** Unbuffered output is the only live view of a long-running step.
   Without it the Actions console shows nothing for the whole window and then a
   verdict, which is the worst possible shape for diagnosing a timeout.

Every finding names a step by number and by name, so the message points at
something specific rather than at a class of problem.
"""

from __future__ import annotations

import argparse
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
from typing import Any, Final

import yaml

REPO_ROOT: Final[pathlib.Path] = pathlib.Path(__file__).resolve().parents[1]
WORKFLOW_DIR: Final[pathlib.Path] = REPO_ROOT / ".github" / "workflows"

#: Commands that require a reachable API server. A step running one of these must
#: come after the step that establishes the cluster.
SERVER_CONTACTING: Final[tuple[str, ...]] = (
    "kubectl get",
    "kubectl version",  # without --client
    "kubectl apply",
    "kubectl delete",
    "kubectl describe",
    "kubectl logs",
    "kubectl create",
    "kubectl wait",
)

#: Commands that establish the cluster. A server-contacting command may follow one
#: of these, but never precede it.
PROVISIONING: Final[tuple[str, ...]] = (
    "get.k3s.io",
    "kind create",
    "k3d cluster create",
    "minikube start",
)

#: Substrings that make a `SERVER_CONTACTING` token local-only. `kubectl version
#: --client` is the one that matters in practice: it is the same binary and the
#: same verb, and it is the difference between a check that works before the
#: cluster is up and one that does not.
CLIENT_ONLY_FLAGS: Final[tuple[str, ...]] = ("--client", "--client=true")

Finding = tuple[str, str, str]  # (id, severity, detail)


class Audit:
    def __init__(self) -> None:
        self.findings: list[Finding] = []

    def add(self, fid: str, severity: str, detail: str) -> None:
        self.findings.append((fid, severity, detail))

    @property
    def failures(self) -> list[Finding]:
        return [f for f in self.findings if f[1] == "FAIL"]

    def report(self) -> str:
        lines: list[str] = []
        for fid, severity, detail in self.findings:
            lines.append(f"  [{severity:4}] {fid}: {detail}")
        if not self.findings:
            lines.append("  no findings")
        return "\n".join(lines)


def name_of(step: dict[str, Any]) -> str:
    return str(step.get("name", step.get("uses", "?")))


def index_of(steps: list[dict[str, Any]], predicate: Any) -> int:
    for i, step in enumerate(steps):
        if predicate(step):
            return i
    return -1


def audit_job(job_name: str, job: dict[str, Any], audit: Audit) -> None:
    steps: list[dict[str, Any]] = job.get("steps", [])
    if not steps:
        return
    print(f"\n=== {job_name}: {len(steps)} steps ===")

    # --- 1. timeouts ------------------------------------------------------
    if not job.get("timeout-minutes"):
        audit.add("1-job", "FAIL", f"{job_name} has no job-level timeout-minutes")

    blocking = [
        i
        for i, s in enumerate(steps)
        if s.get("run")
        and any(
            tok in str(s["run"])
            for tok in ("curl", "for i in", "while [", "seq 1", "get.k3s.io")
        )
    ]
    unbounded = [i for i in blocking if not steps[i].get("timeout-minutes")]
    if unbounded:
        audit.add(
            "1-step",
            "FAIL",
            f"{job_name}: steps {unbounded} block on an external command or loop "
            f"with no timeout-minutes; the job budget is a backstop, not a control",
        )
    else:
        print("  [ok] every blocking step carries its own timeout-minutes")

    # --- 2. pipefail ------------------------------------------------------
    for i, step in enumerate(steps):
        run = str(step.get("run", ""))
        if not run:
            continue
        pipes_into_sh = any(
            line.strip().startswith(("curl", "wget")) and "|" in line and "sh" in line
            for line in run.splitlines()
        )
        if pipes_into_sh and "pipefail" not in run:
            audit.add(
                "2-pipefail",
                "FAIL",
                f"{job_name} step {i} ('{name_of(step)}') pipes a download into a "
                f"shell without pipefail; a failed fetch exits 0 and the step "
                f"reports success",
            )

    # --- 3. offline gates -------------------------------------------------
    first_provision = index_of(
        steps, lambda s: any(tok in str(s.get("run", "")) for tok in PROVISIONING)
    )
    for i, step in enumerate(steps):
        run = str(step.get("run", ""))
        if "verify_patch.py" in run and 0 <= first_provision < i:
            audit.add(
                "3-offline-order",
                "FAIL",
                f"{job_name}: verify_patch.py runs at step {i}, after cluster "
                f"provisioning at {first_provision}; it needs no cluster and is the "
                f"check that catches an unapplyable patch",
            )
    if any("verify_patch.py" in str(s.get("run", "")) for s in steps):
        print("  [ok] the offline patch gate exists")

    # --- 4. PRECONDITION ORDERING ----------------------------------------
    # The check added after the first remote run failed on a `kubectl version`
    # that preceded the apiserver being ready.
    for i, step in enumerate(steps):
        run = str(step.get("run", ""))
        if not run:
            continue
        server_cmds = []
        for line in run.splitlines():
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            for token in SERVER_CONTACTING:
                if stripped.startswith(token) and not any(
                    flag in stripped for flag in CLIENT_ONLY_FLAGS
                ):
                    server_cmds.append(stripped.split()[0:2])
                    break
        if not server_cmds:
            continue
        # Two ways to be wrong, and the first version of this check only caught
        # the second. It looked for a provisioning step *after* the offending
        # one - so a server command inside the install step itself, which is
        # exactly the `kubectl version` defect this check was written for, was
        # never flagged. The control below is what exposed it.
        self_provisions = any(tok in run for tok in PROVISIONING)
        provisions_after = [
            j
            for j, s in enumerate(steps)
            if j > i and any(tok in str(s.get("run", "")) for tok in PROVISIONING)
        ]
        readiness_before = [
            j
            for j, s in enumerate(steps[:i])
            if "readyz" in str(s.get("run", "")) or "wait" in name_of(s).lower()
        ]
        if self_provisions:
            audit.add(
                "4-precondition",
                "FAIL",
                f"{job_name} step {i} ('{name_of(step)}') provisions the cluster "
                f"and runs {server_cmds[0]}, which contacts the API server, in the "
                f"same step. The server does not exist yet; the command fails for "
                f"want of a precondition and reads as an install fault.",
            )
        elif provisions_after and not readiness_before:
            audit.add(
                "4-precondition",
                "FAIL",
                f"{job_name} step {i} ('{name_of(step)}') runs "
                f"{server_cmds[0]}, which contacts the API server, but cluster "
                f"provisioning is at step {provisions_after[0]}, after it.",
            )
        else:
            print(f"  [ok] step {i} server commands are preceded by readiness")

    # --- 5. streaming -----------------------------------------------------
    for i, step in enumerate(steps):
        run = str(step.get("run", ""))
        if "python" not in run:
            continue
        # Long-running or interactive steps should stream; a bounded one-shot
        # script is fine either way.
        streams = "uvicorn" in run or "runner.py" in run
        if streams and "PYTHONUNBUFFERED" not in run:
            audit.add(
                "5-streaming",
                "FAIL",
                f"{job_name} step {i} ('{name_of(step)}') runs a streaming Python "
                f"process without PYTHONUNBUFFERED; the console shows nothing until "
                f"the step ends",
            )
    if any("PYTHONUNBUFFERED" in str(s.get("run", "")) for s in steps):
        print("  [ok] PYTHONUNBUFFERED is set on the streaming steps")

    # --- 6. no dangling references ---------------------------------------
    # Scoped to known repository roots, and the scoping is load-bearing rather
    # than cosmetic. A bare "does this path exist" scan produces two false
    # positives on this workflow alone:
    #
    #   * /etc/rancher/k3s/k3s.yaml  - a path *on the runner*, not in the repo.
    #   * deploy/payments/checkout-api.yaml - a path inside the throwaway GitOps
    #     checkout that verify_patch.py materialises at run time. It is a patch
    #     *target*, not a repository file, and the patch declares it precisely
    #     because the file is not there.
    #
    # Both were reported by the first version of this check, which is the
    # cheapest possible way to get a lint switched off.
    all_runs = "\n".join(str(s.get("run", "")) for s in steps)
    repo_roots = (
        "deploy/",
        "tests/",
        "agent/",
        "internal/",
        "cmd/",
        "scripts/",
        "docs/",
        ".github/",
    )
    # `deploy/payments/` is the *GitOps patch target*. verify_patch.py materialises
    # it inside a throwaway repository at run time, so its absence from this
    # repository is the point rather than a defect. It has to be named
    # explicitly: the previous scoping already excluded absolute paths and still
    # flagged it, and an audit that cries wolf on the one path it was told about
    # is an audit that gets switched off.
    runtime_only = ("deploy/payments/",)
    for match in sorted(
        set(re.findall(r"[\w./-]+\.(?:py|yaml|yml|json|mod)", all_runs))
    ):
        if match.startswith(("/", "http", ".")):
            continue
        if not match.startswith(repo_roots):
            continue
        if match.startswith(runtime_only):
            continue
        if not (REPO_ROOT / match).exists():
            audit.add(
                "6-reference",
                "FAIL",
                f"{job_name} references {match}, which does not exist in the "
                f"repository",
            )


def find_bash() -> str | None:
    """Locate a bash, including the one Git ships on Windows.

    Returns None when none is found, which is a *reported* skip rather than a
    silent pass: see :func:`check_bash_syntax`.
    """
    for candidate in ("bash", "sh"):
        found = shutil.which(candidate)
        if found:
            return found
    if os.name == "nt":
        for relative in (
            r"C:\Program Files\Git\bin\bash.exe",
            r"C:\Program Files\Git\usr\bin\bash.exe",
            r"C:\Program Files (x86)\Git\bin\bash.exe",
        ):
            if os.path.exists(relative):
                return relative
    return None


def check_bash_syntax(job_name: str, job: dict[str, Any], audit: Audit) -> None:
    """Parse every ``run:`` block with ``bash -n``.

    This exists because four CI failures in a row were shell defects that a
    human would have caught by reading a log - a ``kubectl`` that contacted the
    apiserver before it existed, a containerd socket used without ``sudo``, a
    script path that was not in the working directory, and a ``producer | grep
    -q`` that is a SIGPIPE race under ``set -o pipefail`` and reports failure on
    a check that passed. None of them is a semantic bug; all of them are
    unparseable or subtly wrong shell, and both are cheap to catch before the
    run rather than after.

    A missing bash is a WARN, not a pass. A silently-skipped check is
    indistinguishable from a check that ran, and this repository has already
    shipped one gate that did not do what its name said.
    """
    bash = find_bash()
    if bash is None:
        audit.add(
            "BASH_SYNTAX",
            "WARN",
            "{}: no bash found; cannot parse run: blocks".format(job_name),
        )
        return

    for step in job.get("steps", []):
        script = step.get("run")
        if not script:
            continue
        # GitHub substitutes ${{ ... }} before the shell sees the script. A
        # benign literal keeps the parse faithful to what actually executes.
        source = re.sub(r"\$\{\{[^}]*\}\}", "X", str(script).replace("\r\n", "\n"))
        with tempfile.NamedTemporaryFile(
            "w", suffix=".sh", encoding="utf-8", delete=False, newline="\n"
        ) as handle:
            handle.write(source)
            path = handle.name
        try:
            completed = subprocess.run(
                [bash, "-n", path], capture_output=True, text=True, check=False
            )
        finally:
            os.unlink(path)
        if completed.returncode != 0:
            audit.add(
                "BASH_SYNTAX",
                "FAIL",
                "{}: {}".format(
                    name_of(step),
                    " / ".join((completed.stderr or "").strip().splitlines()[:3]),
                ),
            )


def check_multicommand_if(job_name: str, job: dict[str, Any], audit: Audit) -> None:
    """Reject an ``if`` whose condition is a multi-line command *list*.

    ``if grep A; grep B; grep C; then`` is not "A or B or C". It is a list of
    three commands whose status is the last one's, so only needle C decides the
    branch. Two of this workflow's eleven invariant steps were written that way
    by a generator that joined its needles with newlines, and both reported
    green no matter what the runner said.

    Found because a step that reads ``scrubbed_logs is empty`` was reported as
    passing while the log contained exactly that text - i.e. a guard that
    could not fail, which is the failure mode AGENTS.md 5.5 exists to catch.
    Written to run on the *rendered* run: block, since YAML block scalars
    re-indent a generator's output and the shape in the file is not the shape
    the generator wrote.
    """
    for step in job.get("steps", []):
        script = str(step.get("run") or "")
        if not script:
            continue
        run = script.replace("\r\n", "\n").split("\n")
        for index, line in enumerate(run):
            # `^\s*if\b.*\bgrep\b`, and deliberately not the more elaborate
            # `^\s*if\s+.*(?:^|\s)grep\b` that came first. That version only
            # matched when there were two or more spaces after `if`, because
            # `(?:^|\s)` had to match a space that `\s+` had already consumed and
            # could only backtrack into if more than one was available. So the
            # guard silently passed the exact defect it was written for, and its
            # negative control reported "not fired" for a run in which the defect
            # was present. A regex that fails open on the common spacing is worse
            # than no regex.
            if not re.match(r"^\s*if\b.*\bgrep\b", line):
                continue
            if "||" in line:
                continue
            # Only the multi-line case is checked. A single-line `if cmd; then`
            # cannot be a command list, and trying to split a single line on `;`
            # is wrong: one of this workflow's needles is
            # `observation(s); the causal chain needs`, whose semicolon is
            # inside quotes. Splitting on it produced a false positive on a
            # correct step, which is how the first two versions of this check
            # were useless in opposite directions.
            #
            # The limitation is real and left visible: a hand-written single-line
            # `if grep A; grep B; then` would pass this check.
            if line.rstrip().endswith("; then"):
                continue
            body = [line]
            for follower in run[index + 1 :]:
                body.append(follower)
                if follower.rstrip().endswith("; then"):
                    break
            else:
                continue
            commands = [
                part.rstrip() for part in "\n".join(body).split("\n") if part.strip()
            ]
            # A pipeline is one command, however many greps appear in it, so a
            # line that continues with `\`, `|`, `||` or `&&` does not make a
            # list. ci.yaml's GPU gate is exactly this:
            #     if grep -vE '^\s*#' requirements.txt \
            #        | grep -iE 'torch|cuda'; then
            # and flagging it would be a false positive on a security check that
            # is correct.
            continued = all(
                part.endswith(("\\", "|", "||", "&&")) for part in commands[:-1]
            )
            if len(commands) > 1 and not continued:
                audit.add(
                    "IF_CONDITION_LIST",
                    "FAIL",
                    "{}: an `if` condition lists {} commands without a `||`, `|` "
                    "or line continuation; only the last decides the branch".format(
                        name_of(step), len(commands)
                    ),
                )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--strict",
        action="store_true",
        help="treat WARN findings as failures",
    )
    args = parser.parse_args(argv)

    workflows = sorted(WORKFLOW_DIR.glob("*.yaml"))
    if not workflows:
        print(f"::error::no workflows found in {WORKFLOW_DIR}")
        return 2

    audit = Audit()
    for path in workflows:
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        print(f"\n########## {path.name} ##########")
        for job_name, job in doc.get("jobs", {}).items():
            audit_job(job_name, job, audit)
            check_bash_syntax(job_name, job, audit)
            check_multicommand_if(job_name, job, audit)

    print("\n=== findings ===")
    print(audit.report())
    print(
        "\n  FAIL: {}   WARN: {}".format(
            len(audit.failures), len(audit.findings) - len(audit.failures)
        )
    )

    if audit.failures:
        return 1
    if args.strict and audit.findings:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
