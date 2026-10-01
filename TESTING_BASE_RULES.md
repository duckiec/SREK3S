# TESTING_BASE_RULES — Operational Safety & Containment Guardrails

| Field | Value |
|---|---|
| Document ID | `RULES-LIVE-0001` |
| Version | `0.1.0` |
| Status | **Binding on every live test run.** No exceptions without an explicit decision recorded in `ROADMAP.md`. |
| Requirements | `PRD_LIVE_VALIDATION.md` |
| Execution | `REALWORLD_TESTING.md` |
| Host | Fedora 44 / WSL2 / `linux/aarch64`, k3s v1.36.4+k3s1, Docker 29.8.2 |

> These rules are not guidance. Each one corresponds to a way this system can cause
> damage that is **not** visible from inside the process making it: a write verb that
> looks like a read, a scrubber that passes by discarding everything, a namespace that
> outlives its run. Where a rule exists because a plausible shortcut produced a
> **false pass** rather than a false failure, the rule says so, because that is the
> harder failure to notice.

---

## Rule 1 — Structural read-only guarantee (pre-flight, blocking)

The Sentinel's blast radius against the cluster must be **structurally zero**. The
apiserver enforces it; nothing in this repository's code can be trusted to.

### 1.1 Mandatory pre-flight

**Run this before anything is applied to the cluster.** Not after, not as a summary.

```bash
SA=system:serviceaccount:srek3s-system:srek3s-sentinel
NS=sentinel-chaos

for verb in create update patch delete deletecollection; do
  printf '%-16s %s\n' "$verb" "$(sudo kubectl auth can-i $verb pods -n $NS --as=$SA)"
done
```

**Every line must print `no`.** A single `yes` is an immediate failure of the entire
suite and an incident in its own right: the Sentinel holds production write
authority on a live cluster, and every other rule in this document assumes it does
not.

### 1.2 The negative control is mandatory

```bash
sudo kubectl auth can-i list pods   -n $NS --as=$SA   # MUST be: yes
sudo kubectl auth can-i list secrets -n $NS --as=$SA  # MUST be: no
```

The second line is not redundant. Without it, a `no` on `create` is equally
consistent with a ServiceAccount that has **no permissions at all** — a completely
broken configuration that would satisfy every other assertion in Rule 1 while
proving nothing about the safety property. A guard whose output is always "no" is a
guard nobody reads.

### 1.3 Structural assertions

| Assertion | Enforcement layer |
|---|---|
| `Role` verbs are exactly `{get, list, watch}` | `TestSentinelRoleGrantsNoMutatingVerb` parses the manifest |
| No `ClusterRole` / `ClusterRoleBinding` binds the Sentinel | `TestNoClusterScopedBindingWidensTheSentinel` |
| `roleRef.kind == Role` | `roleRef` is immutable, so a live escalation is rejected by the apiserver |
| Verbs are **enumerated**, never wildcarded | an allow-list cannot accidentally cover a future write verb |
| The agent holds **no** ServiceAccount token | `automountServiceAccountToken: false` — the stronger form of the same property |

### 1.4 Scope and grant must agree

`deploy/sentinel.yaml` sets `WATCH_NAMESPACE: ""` (watch **all** namespaces) while
`deploy/rbac.yaml` grants a `Role` in `srek3s-system` **only**. A cluster-wide
`LIST` is unauthorised; the informer retries it; the operator sees **silence**.

**This is a confirmed static defect that has not been reproduced at runtime**
(`AGENTS.md` §5.7). Either side alone is correct, which is why no single-manifest
test catches it. Before a detection test:

```bash
sudo kubectl auth can-i list pods -n "$WATCHED_NS" --as=$SA   # MUST be: yes
```

A `no` here means the run is watching nothing and every downstream "no incidents
detected" is meaningless.

---

## Rule 2 — Fail-closed diff mandates

Every ambiguity escalates to `TIER_2_ARCHITECTURAL` with `git_patch == ""` and
`patch_validated == false`. **A run must never produce a patch it cannot prove.**

### 2.1 Fail-closed conditions — all must escalate

| Condition | Mechanism |
|---|---|
| `/manifests` empty or the target file unreadable | `FileManifestProvider.read_manifest` → `None` → `_build_remediation_diff` guard 2 |
| `SREK3S_TARGET_MANIFEST` names a path that does not exist | the default `deploy/payments/checkout-api.yaml` is **absent from this repository** |
| `resources.limits.memory` is null | nothing to recalibrate |
| the memory line cannot be uniquely located for the named container | `find_container_memory_limit` returns `None` |
| the manifest's value disagrees with the payload's | drift; patching would encode a wrong premise |
| any of the three patch-validation layers fails | the patch is **discarded**, not repaired |
| the diff matches a masking rule | **refused, not redacted** — rewriting a line inside a diff breaks the hunk header's counts, and a credential in a GitOps PR is copied into every clone |
| classification is `UNKNOWN`, or restart count exceeds policy, or node-pressure signals are present | deny-by-default routing |

### 2.2 "Empty or unreadable" is a PASS, not a failure

An all-Tier-2 run against an unpopulated `/manifests` **is the system working**.
Treat it as a failed test and the incentive becomes to populate `/manifests` without
thinking about whether the result is trustworthy — which is the opposite of what this
design wants.

Distinguish the two cases explicitly, because they are indistinguishable from
outside:

```bash
sudo kubectl -n srek3s-system logs deploy/srek3s-agent | grep 'manifest_provider='
```

The startup line reports `manifest_provider=` and `target_manifest=`. It exists
because a service logging a fixed claim about its own capability will eventually log
it **wrongly**: a log that misreports whether patches are possible is worse than no
log, because an operator reads it to decide whether Tier-1 is reachable.

### 2.3 A patch that applies is not a patch that works

Nothing in a live run asserts remediation succeeded. The post-remediation loop is
**unwired** — `agent/verify.py` is imported by no production module
(`ARCHITECTURE.md` §5.5.1). A run that observes a Tier-1 diff must say it observed a
**proposal**, and nothing more.

### 2.4 Never apply a generated diff during validation

SREK3S proposes; a human or an approved GitOps controller applies. Validation asserts
`git apply --check` passes — not that a cluster was mutated to test the result.

---

## Rule 3 — No host toolchain pollution

Live testing runs on **native Linux `aarch64`** only.

### 3.1 Prohibited

| Prohibited | Why |
|---|---|
| Any Windows binary — `/mnt/c/Program Files/Go/bin/go.exe`, `gofmt.exe` | produces Windows artifacts; `-race` needs cgo + TSan, which the Windows host lacks |
| System `python3` (**3.14.3** here) | `AGENTS.md` §2 forbids 3.12+ syntax; `black` pins `target-version = ["py311"]`; `setup.cfg` sets `python_version = 3.11`. Black 26.5.1 formats one file differently under 3.14 than 3.11 |
| Bare `pytest` / `black` / `flake8` / `mypy` | resolve to whatever `PATH` finds first — which is system Python |
| Installing packages outside `.venv311` | pollutes the host and makes a later run unreproducible |
| `usermod -aG docker` | the `docker` group confers root-equivalent control of the daemon. `sudo docker …` is the correct path |

### 3.2 Mandatory

```bash
# Every Python tool, every time:
PY=~/SREK3S/.venv311/bin/python
$PY -m pytest agent/tests/ -q
$PY -m black  --check agent/ tests/
$PY -m flake8 agent/ tests/
$PY -m mypy   --strict agent/ tests/

# Go: assert the interpreter, do not assume it
go version          # MUST contain: linux/arm64
go env CGO_ENABLED  # MUST be: 1  (otherwise -race cannot run)

# Docker and kubectl:
sudo docker ...
sudo kubectl ...
```

**Assert `go version`, not the resolved path.** On this host `which go` resolves to
`/usr/sbin/go`, and `/usr/sbin`, `/usr/bin`, `/sbin`, `/bin` are the same inode — so
an assertion hardcoding `/usr/bin/go` fails against a correctly installed
toolchain. A verification command that is wrong in the safe direction still trains
people to ignore it.

### 3.3 Architecture is part of every claim

| | Local | CI |
|---|---|---|
| Platform | `linux/aarch64` (Fedora 44, WSL2) | `linux/amd64` (`ubuntu-latest`) |
| k3s | v1.36.4+k3s1 | v1.29.9+k3s1 |

Images must target `linux/arm64`. A local image and a CI image are **not
interchangeable**, and a PSA finding is meaningless without naming the control-plane
version, because `enforce-version: latest` resolves against the running apiserver.

---

## Rule 4 — Cluster hygiene and teardown

**Every namespace and object a run creates is removed, and the removal is verified.**
A leftover object changes the next run's results, and the change is invisible.

### 4.1 Define teardown BEFORE creating anything

```bash
sudo kubectl delete namespace sentinel-chaos --wait=true --timeout=180s
sudo kubectl get namespace sentinel-chaos 2>/dev/null && echo "TEARDOWN FAILED"
```

`--wait=true` is not optional. An unawaited delete races the next run, which then
inherits the previous run's state. A run in this repository was lost to exactly that:
the teardown step did not check the deletion completed, and the following test raced
its own predecessor's teardown.

### 4.2 Snapshot accounting

```
before → run → after
```

Assert on `generation` **and** `resourceVersion`. Then:

| Requirement | Reason |
|---|---|
| No object outside `sentinel-chaos` changed | the no-autofix guarantee |
| Objects created inside the chaos namespace are **counted**, not merely excluded | an exemption that is not tallied is indistinguishable from a silent failure |
| System-namespace churn (coredns, traefik) is excluded **by name** | an unbounded "ignore kube-system" swallows real changes |
| The before-snapshot is **non-empty** | an empty before-image compared against an empty after-image passes every no-mutation assertion while proving nothing |

### 4.3 Blast-radius namespace rules

| Namespace | May contain |
|---|---|
| `srek3s-system` | the Sentinel, the agent. **Never** chaos fixtures |
| `sentinel-chaos` | chaos fixtures only. Disposable. Deleted by §4.1 |

`deploy/chaos/*.yaml` target `sentinel-chaos` and `FORBIDDEN_NAMESPACES = {default,
kube-system, srek3s-system, ""}` — the empty entry catches a fixture with no
namespace at all, which would land in whatever context applied it.

### 4.4 Container hygiene

- `--rm` on every `docker run` used for inspection.
- Prune build artefacts only with intent: `docker image prune` removes the very
  images a subsequent in-cluster phase needs.
- `docker save` tarballs go to `/tmp`, not the repository — a tarball in the worktree
  is an untracked multi-hundred-megabyte file that pollutes `git status`.

---

## Rule 5 — Honest gate reporting

Carried from `AGENTS.md` §5.4 and restated because live runs are exactly where the
incentive to round a number up appears.

### 5.1 Prohibited claims

| Do not write | Write instead |
|---|---|
| "No secrets leaked" | "No planted secret survived; `[REDACTED]` markers present; topology preserved" |
| "NetworkPolicy enforced" | "NetworkPolicy enforcement **not yet empirically verified**; no controller pod observed, controller is embedded in `k3s server`" |
| "Detection works" | "p99 detection latency N ms over M incidents, budget 2000 ms" |
| "Tier-1 works in-cluster" | "Tier-1 **unreachable** with an empty `/manifests`; Tier-2 observed as designed" |
| "Verification loop works" | "verification loop is **unwired**; `agent/verify.py` has no production importer" |

### 5.2 Skips are results

A skipped test is reported with its reason and counted. `BLOCKED DEPENDENCY, not a
pass` is the required wording. A run reporting "0 failures" while two checks were
skipped has not established that those two properties hold.

### 5.3 Negative controls

Every security or boundary assertion carries a control proving it **can fail**. The
two traps recorded in this repository:

| Trap | Signature | Rule |
|---|---|---|
| control fails for the wrong reason | a plant that errors during collection instead of tripping the guard | the control must be observed failing **for the intended reason**, with the daemon's own error text |
| assertion passes on an empty result | masking proved by emitting nothing | assert presence **and** absence, never absence alone |

A concrete instance from this session's environment work: a check for the absence of
`/id` in the distroless Sentinel image piped the error through `tail -1`, which
captured Docker's usage hint instead of the failure — so **every** binary read as
"present" and the control proved nothing. The corrected version matches on the
daemon's error string and includes a bogus-path control to prove the error is real.

### 5.4 Reconstruction is labelled

A finding produced by reading code is a deduction about a mechanism, not an
observation of it. Say which, in place:

> **What happened (reconstruction, not yet reproduced):** `deploy/sentinel.yaml`
> sets `WATCH_NAMESPACE: ""` while `deploy/rbac.yaml` grants a namespaced `Role`.
> Reading both manifests indicates the cluster-wide `LIST` will be refused. **This
> has not been reproduced against a running apiserver.**

Do not upgrade a defect report to an incident report on the strength of a correct
argument. The cheapest false claim available is the one that sounds like a finding.

---

## Rule 6 — Hard stop discipline

Phases execute in order. Each ends with a report and a halt.

| Phase | May touch | Must not |
|---|---|---|
| 0 Environment | `dnf`, `.venv311`, systemd `docker` | modify any repo file except `.gitignore` |
| 1 Offline gates | read the repo; run gates | modify source, build images, contact K3s |
| 2 Container builds | `docker build`, `docker run` | import into containerd, contact K3s |
| 3 Image registration | `k3s ctr` | apply manifests |
| 4 Detonation | apply `deploy/chaos/*` | modify non-chaos namespaces |
| 5 In-cluster | apply `deploy/` | create namespaces outside the two named |

**A phase boundary is a stopping point, not a suggestion.** Discovering that the
next phase is required in order to complete the current one does not authorise
crossing the boundary; it authorises reporting the dependency and halting.

---

## Pre-run checklist

```
[ ] Rule 1.1  every mutating verb returns no
[ ] Rule 1.2  reads yes, ungranted-resource reads no
[ ] Rule 1.4  WATCH_NAMESPACE matches a namespace the Role covers
[ ] Rule 2.2  agent startup line reports the real provider and target
[ ] Rule 3.2  go version linux/arm64, CGO_ENABLED=1, python from .venv311
[ ] Rule 4.1  teardown command written and verified-reachable
[ ] Rule 4.2  before-snapshot captured and NON-EMPTY
[ ] images registered in k8s.io under exact qualified names
[ ] busybox:1.36.1 registered (fixtures use imagePullPolicy: Never)
```

Any unchecked box: **halt and report.** Do not begin.
