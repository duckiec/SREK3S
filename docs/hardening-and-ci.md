# Hardening and CI

What this project enforces, and where the enforcement is weaker than it looks. The
second half is the point: a controls document that lists only controls is marketing.

Every figure below was read from the running configuration or from a test run, not
inferred from intent. Where a claim could not be verified, it is recorded as
unverified rather than asserted.

## Test suite

### Python

1,146 tests are collected by `pytest agent/tests/`. The default run reports:

```
1145 passed, 1 skipped
```

The single skip is a blocked dependency, not a pass. `test_audit_workflow_tool.py`
probes the Windows Subsystem for Linux launcher stub, which only exists on Windows
(`os.name == "nt"`), so that test runs on Windows and skips on every other host,
including ubuntu-latest and this WSL development box. The two cluster-dependent
skips that `test_verification_e2e.py` used to hold left with that file when it was
deleted alongside `agent/verify.py`.

CI holds the skip count at a recorded baseline of 1 (`EXPECTED_SKIPS` in
`ci.yaml`). The count may fall and the ratchet notes the improvement; a rise fails
the build with an instruction to establish what the new skip is rather than to
raise the baseline.

### Go

179 test functions run under `go test -race -timeout 30s ./...` (gate `G3`). The
race detector requires cgo, so `make doctor` checks that cgo is enabled before a
local run is trusted as equivalent to CI. A nil-safety and goroutine-leak terminal
gate runs alongside it.

### Offline `git apply`

Patch verification has an empirical layer that shells out to real `git apply
--check` in a throwaway repository, against the target manifest's own bytes. It
asserts that the file in the scratch tree *changed* rather than trusting the exit
status, because an earlier harness verified a copy in the wrong directory and
exited 0. `test_patch_newline.py` covers whitespace handling in the same path.

### Live k3s detonation

The end-to-end leg installs k3s and runs the Agent on `127.0.0.1:8000` and the
Sentinel with `-agent-url http://127.0.0.1:8001`, against
`deploy/chaos/oom-leak.yaml`: a planted memory leak that writes a credential into
its own container logs.

It asserts the whole chain, and specifically that the planted credential did not
survive scrubbing, that scrubbing masked *something*, and that masking preserved
the diagnostic evidence a root-cause analysis depends on. Masking everything and
masking nothing are both failures, and both are asserted — a masker that redacts
all 32 maskable corpus cases scores full marks on that count and is useless.

The in-cluster leg is separate and applies `deploy/` for real: it asserts the
Service publishes ready endpoints, cluster DNS resolves `srek3s-agent`, the Agent
answers `/healthz`, a live apiserver grants the Sentinel reads and refuses it
writes, and the running Agent pod is UID 10001 with a read-only root and no
mounted token.

## Static analysis and supply chain

| Control | Command | Notes |
|---|---|---|
| Formatting | `black --check agent/ tests/` | `G4` |
| Style | `flake8 agent/ tests/` | `G5` |
| Typing | `mypy --strict agent/ tests/` | `G6`; strict mode, not a subset |
| Reachable CVEs | `govulncheck ./...` | `G7`, see below |
| Workflow audit | `scripts/audit_workflow.py --strict` | `bash -n`, unpiped `curl \| sh`, `producer \| grep -q` SIGPIPE races, multi-command `if` conditions, referenced paths that do not exist |

`G7` blocks on vulnerabilities **reachable from this code**. govulncheck exits
non-zero only when a vulnerable symbol is actually called, which is strictly
stronger than a version-based alert. A CVE in a required module that nothing calls
is reported and does not block.

The step also asserts its own advisory database is reachable before trusting a
clean result. govulncheck exits 0 and reports no vulnerabilities when it cannot
fetch advisories — a state indistinguishable, in its output, from a genuinely clean
scan. A clean result from an unreachable database is the failure mode this
assertion exists to prevent.

Secret scanning, secret-scanning push protection, and Dependabot security updates
are all enabled at the repository level.

## Repository rules

Enforced by an active ruleset named `main` targeting the `main` branch, not by
classic branch protection.

| Rule | Effect |
|---|---|
| `pull_request` | Changes reach `main` through a pull request. Merge, squash and rebase are all permitted merge methods |
| `required_linear_history` | `main` holds no merge commits; the history is linear |
| `required_signatures` | Commits carry cryptographically verified signatures |
| `required_status_checks` | Five named checks must report before merge |
| `deletion` | The `main` branch cannot be deleted |
| `non_fast_forward` | Force-pushes to `main` are refused |

Signing is SSH (`ed25519`) via `commit.gpgsign=true` with `gpg.format=ssh`. GPG
signing works equally well. Local verification additionally needs
`gpg.ssh.allowedSignersFile` to point at a file mapping the committer address to
the public key; without it git cannot validate a signature and reports a signed
commit as unsigned, which reads exactly like never having signed it.

The invariants these controls defend are in
[security-invariants.md](security-invariants.md), and the gate matrix is in
[development.md](development.md#gates).

## Where the enforcement is weaker than it looks

Four findings. None is hypothetical; each was read from the live configuration.

**A required status check names a job that does not exist.** The ruleset requires
`Go quality gates (G1, G2, G3)`. `ci.yaml` defines a single Go job named
`Go quality gates (G1, G2, G3, G7)`. The required context can therefore never
report, and a pull request cannot satisfy all five required checks without an
administrative bypass. Either rename the job to the older name or delete the stale
context from the ruleset.

**Administrative bypass is enabled, and has been used.** Direct pushes to `main`
have landed repeatedly, which the `pull_request` rule is supposed to prevent. The
signature rule was bypassed on at least one commit that is still reachable from
`main`. Enabling bypass is a reasonable way to keep a repository unblocked; leaving
it enabled is not, because the controls it overrides are the controls above.

**Most of `main` is unsigned.** Of the twenty most recent commits, two verify. The
remainder predate signing being configured. The rule is enforced going forward; it
is not retroactive, and rewriting published history would trade a real property
for a cosmetic one.

**A pull request requires no approval.** `required_approving_review_count` is 0, so
a pull request can be opened and merged by its own author. Required-pull-request
and reviewed are different properties, and only the first is enforced.

**CodeQL's configuration is not in the repository.** The CodeQL workflow is
generated by GitHub at run time (its event source is `dynamic`); there is no
checked-in `.github/workflows/codeql.yaml`. The scan runs and passes, but its query
suite, language set and path filters cannot be reviewed in a diff, and a change to
them would leave no trace in version control.

## Related

[CONTRIBUTING.md](../CONTRIBUTING.md) for the invariants and the normative masking
specification. [runbook.md](runbook.md) for operating the deployed system, and
[ci-triage-protocol.md](ci-triage-protocol.md) for reading a red run.
