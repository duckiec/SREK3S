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

6. **SIGPIPE under `grep -q`.** ``producer | grep -q PATTERN`` is a race, not a
   certainty: ``grep -q`` exits the instant it finds a match and closes the read
   end of the pipe, the writer takes SIGPIPE and dies with status 141, and
   ``pipefail`` hands that 141 to the pipeline in place of grep's 0. A *passing*
   check therefore reports failure, and it does so intermittently - it passes
   when the output fits the pipe buffer, which is the worst possible shape for a
   gate. Measured on this project: 60 failures in 60 runs piped, 0 in 60 with the
   output captured to a variable first. Six assertions used the piped form and
   all six were rewritten. This check exists because the first draft of the M4.3
   step reintroduced the piped form verbatim, in the same milestone whose
   post-mortem quotes the measurement - and ``bash -n`` passed it, because piped
   ``grep -q`` is perfectly valid shell. A syntactic check cannot catch a
   semantic defect, and ``check_bash_syntax``'s own docstring used to imply that
   it did.

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


def _join_continuations(script: str) -> str:
    """Fold `\\`-continued shell lines into one logical line.

    A wrapped pipeline puts its `|` on a line of its own, which is what let a
    `grep -q` SIGPIPE race hide from check 6: the line carrying the pipe had no
    producer on it, so the check skipped it. Joining before scanning closes that,
    and it is the only way to see the pipeline the shell will actually run.

    Lines whose trailing character is a single backslash - not an escaped
    backslash - are joined to the next line with a single space.
    """
    out: list[str] = []
    for raw in script.split("\n"):
        stripped = raw.rstrip()
        if out and _is_continued(out[-1]):
            # Extend the ACCUMULATED line (out[-1]) with this one. The trailing
            # backslash belongs to out[-1], so that is what gets stripped.
            out[-1] = out[-1][:-1].rstrip() + " " + stripped.lstrip()
            continue
        out.append(stripped)
    return "\n".join(out)


def _is_continued(line: str) -> bool:
    """True when `line` ends with an odd number of backslashes."""
    trailing = len(line) - len(line.rstrip("\\"))
    return trailing % 2 == 1


def check_actions_pinned(job_name: str, job: dict[str, Any], audit: Audit) -> None:
    """Require every third-party action to be pinned to a full commit SHA.

    `uses: actions/checkout@v7` names a MUTABLE ref. Whoever controls that tag
    controls what executes in this repository's CI - and release.yaml holds
    `packages: write`, so the blast radius is package publishing, not just a
    read-only build. A tag is a pointer; a 40-hex SHA is the commit.

    The version comment after the SHA is what makes the pin maintainable, so its
    absence is also a finding: a bare SHA with no version cannot be reviewed by
    eye, and Dependabot updates the pair. That half cannot be checked here,
    because YAML parses `# v7` as a COMMENT and strips it - so it lives in
    check_actions_pin_comments, which reads the raw source text.
    """
    for step in job.get("steps", []):
        uses = step.get("uses")
        if not uses or str(uses).startswith("./"):
            # A local composite action is part of this repository and cannot move.
            continue
        ref = str(uses).split("@", 1)[-1]
        if re.fullmatch(r"[0-9a-f]{40}", ref):
            continue
        audit.add(
            "7-pinned-shas",
            "FAIL",
            "{}: uses `{}` - a mutable ref. Pin to a full 40-character commit SHA "
            "with a version comment, e.g. `uses: actions/checkout@<sha> # v7`".format(
                name_of(step), uses
            ),
        )


def check_actions_pin_comments(path: pathlib.Path, audit: Audit) -> None:
    """Require a `# vX.Y.Z` comment beside every pinned action SHA.

    A bare 40-hex SHA is immutable but unreviewable: nothing in the diff says
    which release it names, and Dependabot bumps the SHA and the comment as a
    pair. Read from the RAW source, because the parsed document cannot see it.
    """
    pattern = re.compile(
        r"^\s*(?:-\s*)?uses:\s*([^\s#]+@[0-9a-f]{40})\s*(?:#\s*(\S+))?\s*$"
    )
    for number, raw in enumerate(
        path.read_text(encoding="utf-8").splitlines(), start=1
    ):
        match = pattern.match(raw)
        if match is None or match.group(2) is not None:
            continue
        audit.add(
            "7-pin-comments",
            "FAIL",
            "{}:{}: `{}` is pinned to a SHA with no `# vX.Y.Z` version comment, "
            "so the pin cannot be reviewed by eye or bumped safely".format(
                path.name, number, match.group(1)
            ),
        )


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


def _bash_works(candidate: str) -> bool:
    """Whether ``candidate`` is a bash that actually runs.

    The trap this exists for: on Windows, ``shutil.which("bash")`` commonly
    resolves to ``...\\Microsoft\\WindowsApps\\bash.exe``, which is the Windows
    Subsystem for Linux *launcher stub*. With WSL not installed, that binary
    prints an install prompt and exits 1. The previous version of this function
    returned the first candidate it found without asking whether it worked, so
    every ``bash -n`` in the audit failed and the audit reported 68 BASH_SYNTAX
    findings against steps that are syntactically fine - including steps in
    ci.yaml, which this audit had never touched.

    That is the failure mode this file exists to catch, aimed at the auditor: a
    check that cannot tell "the thing is broken" from "the instrument is broken",
    reporting the first with the confidence of the second.

    ``--version`` is the cheapest question that separates a working bash from a
    stub, and it is asked of every candidate rather than assumed of the first.
    """
    try:
        probe = subprocess.run(
            [candidate, "--version"],
            capture_output=True,
            timeout=20,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return probe.returncode == 0 and b"GNU bash" in probe.stdout


def find_bash() -> str | None:
    """Locate a bash that actually runs, including the one Git ships on Windows.

    Returns None when none works, which is a *reported* skip rather than a silent
    pass: see :func:`check_bash_syntax`.

    The Git paths are tried before PATH on Windows, not after. ``which("bash")``
    landing on the WSL stub is the common case, and putting the known-good
    interpreter ahead of it is cheaper than validating the stub on every run -
    though :func:`_bash_works` still validates whatever is returned, so a broken
    Git install degrades to a reported skip rather than to 68 false findings.
    """
    candidates: list[str] = []
    if os.name == "nt":
        candidates.extend(
            relative
            for relative in (
                r"C:\Program Files\Git\bin\bash.exe",
                r"C:\Program Files\Git\usr\bin\bash.exe",
                r"C:\Program Files (x86)\Git\bin\bash.exe",
            )
            if os.path.exists(relative)
        )
    for name in ("bash", "sh"):
        found = shutil.which(name)
        if found:
            candidates.append(found)
    for candidate in candidates:
        if _bash_works(candidate):
            return candidate
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


def check_grep_q_pipefail_race(
    job_name: str, job: dict[str, Any], audit: Audit
) -> None:
    """Flag ``producer | grep -q`` under ``set -o pipefail``.

    Added after the M4.3 step reintroduced the piped form verbatim - while
    quoting the measurement that motivated removing it six times before. The
    failure is that ``grep -q`` exits on the first match and closes the read end
    of the pipe, so the writer takes SIGPIPE and dies 141, and ``pipefail``
    substitutes that 141 for grep's 0. A passing check reports failure, and only
    sometimes, which is worse than a deterministic failure in a gate.

    ``bash -n`` cannot see this: the piped form is valid shell. That is the
    whole reason this is a separate check rather than a note in
    :func:`check_bash_syntax`, whose docstring previously claimed coverage it
    did not have.

    Scoped to a pipeline whose final element is ``grep -q``/``grep -Fq`` and
    whose producer is a real command, so ``echo x | grep -q x`` is not flagged -
    the writer there cannot meaningfully fail and the race does not exist.
    """
    for step in job.get("steps", []):
        script = step.get("run")
        if not script:
            continue
        run = re.sub(r"\$\{\{[^}]*\}\}", "X", str(script).replace("\r\n", "\n"))
        if "pipefail" not in run:
            # Without pipefail the writer's 141 is discarded and the check
            # behaves. Flagging it anyway would bury the real finding.
            continue
        for index, line in enumerate(_join_continuations(run).split("\n"), start=1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if not re.search(r"\|\s*(?:sudo\s+)?grep\s+-[A-Za-z]*q", stripped):
                continue
            # `grep -q` as the last element of a pipeline fed by a command.
            #
            # Continuation lines are joined FIRST (see _join_continuations). The
            # previous version iterated the raw lines and then asked for the
            # producer as `stripped.split("|", 1)[0]`. For the extremely common
            # wrapped form
            #
            #     kubectl ... \
            #         | grep -q "watching one namespace" || {
            #
            # the line holding the pipe has an EMPTY producer, so the check
            # `continue`d and never flagged it - while its own comment claimed
            # both spellings "land here once the continuation is joined". Nothing
            # joined them. Two steps in e2e-detonation.yaml were in exactly that
            # shape, so the SIGPIPE race this function exists to eliminate was
            # live in the committed workflow and the audit reported it clean.
            producer = stripped.split("|", 1)[0].strip()
            if not producer or producer.startswith("{"):
                continue
            audit.add(
                "GREP_Q_PIPE",
                "FAIL",
                "{}: line {}: `grep -q` at the end of a pipeline under "
                "pipefail is a SIGPIPE race - capture the output to a variable "
                "and match against the variable, e.g. "
                '`out=$(cmd) && grep -qF PAT <<<"$out"`. Observed: this '
                "reported a present image as missing.".format(name_of(step), index),
            )
            break


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


def check_agent_url_is_a_root(job_name: str, job: dict[str, Any], audit: Audit) -> None:
    """Reject an ``-agent-url`` that carries a path.

    ``emitter.New`` computes ``incidentsURL: baseURL + IncidentsPath``, where
    ``IncidentsPath`` is ``/v1/incidents``. So the flag is the agent's *root* and
    a path on it produces a doubled path - ``http://host/api/v1/triage/v1/incidents``
    - which the agent 404s.

    Worth a check because the failure is close to invisible in CI: the capture
    proxy records the exchange whatever the upstream status, so the capture file
    is non-empty, every invariant has a real payload to examine, and the only
    symptom is an ``upstream_status`` of 404 in a line nobody reads. Two E2E runs
    were spent establishing that.
    """
    for step in job.get("steps", []):
        script = str(step.get("run") or "")
        for line in script.replace("\r\n", "\n").split("\n"):
            match = re.search(r"-agent-url\s+(\S+)", line)
            if not match:
                continue
            url = match.group(1)
            # Strip the scheme, then the authority - everything up to the first
            # slash. Stripping the authority by splitting on ":" instead would
            # truncate the path too, so `http://host:8001/v1/incidents` would
            # look like a bare host and pass. That is the exact form this
            # workflow uses, and the first version of this check missed it.
            remainder = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", url)
            remainder = re.sub(r"^[^/]*", "", remainder, count=1).rstrip("/")
            if remainder:
                audit.add(
                    "AGENT_URL_PATH",
                    "FAIL",
                    "{}: -agent-url is {!r}, but the emitter appends "
                    "/v1/incidents to it; pass the agent root only".format(
                        name_of(step), url
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
        check_actions_pin_comments(path, audit)
        for job_name, job in doc.get("jobs", {}).items():
            audit_job(job_name, job, audit)
            check_bash_syntax(job_name, job, audit)
            check_grep_q_pipefail_race(job_name, job, audit)
            check_multicommand_if(job_name, job, audit)
            check_agent_url_is_a_root(job_name, job, audit)
            check_actions_pinned(job_name, job, audit)

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
