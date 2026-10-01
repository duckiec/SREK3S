# REALWORLD_TESTING — Tactical Execution Matrix & Chaos Playbook

| Field | Value |
|---|---|
| Document ID | `RUN-LIVE-0001` |
| Version | `0.1.0` |
| Status | Draft — **not yet executed** |
| Requirements | `PRD_LIVE_VALIDATION.md` (LV-*) |
| Rules of engagement | `TESTING_BASE_RULES.md` (binding) |
| Host | Fedora 44 / WSL2 / `linux/aarch64`, k3s v1.36.4+k3s1, Docker 29.8.2 |

> **Every command in this document requires `sudo`.** The k3s kubeconfig is
> `0600` root-owned and `duckie` is not in the `docker` group. `AGENTS.md` §2 records
> both. Commands below are written with `sudo` where it is needed and are otherwise
> literal.

> **Hardening assertion before any destructive step.** A run that has not first
> demonstrated that the Sentinel cannot write is not a run whose blast radius is
> understood. Execute §1 in order.

---

## 1. Pre-flight — the run is not valid until these pass

| # | Step | Command | Pass condition |
|---|---|---|---|
| 1.1 | Namespaces exist | `sudo kubectl get ns srek3s-system sentinel-chaos` | both exist |
| 1.2 | PSA enforced | `sudo kubectl get ns srek3s-system -o yaml` | all four labels present; assert `enforce` and `enforce-version` **separately** |
| 1.3 | **Writes refused (live)** | `sudo kubectl auth can-i create pods -n srek3s-system --as=system:serviceaccount:srek3s-system:srek3s-sentinel` | `no` |
| 1.4 | Same for update/patch/delete | repeat 1.3 with `update`, `patch`, `delete`, `deletecollection` | `no` for every verb |
| 1.5 | Reads granted | `sudo kubectl auth can-i list pods -n <watched-ns> --as=…` | `yes` |
| 1.6 | **Scope matches grant** | `WATCH_NAMESPACE` names a namespace 1.5 answered `yes` for | they agree — see §3 |
| 1.7 | No cluster-scoped widening | `sudo kubectl get clusterrole,clusterrolebinding -o name` | no SREK3S object present |
| 1.8 | Images registered | `sudo k3s ctr --timeout 30s --namespace k8s.io images ls` | exact qualified names present (§4) |
| 1.9 | `busybox` registered | same command | `busybox:1.36.1` present — the fixtures use `imagePullPolicy: Never` |
| 1.10 | Teardown available | §7 | a teardown command exists before anything is applied |

**1.3 is the gate that makes the run safe.** A `yes` here means the Sentinel holds
production write authority and every subsequent step is unbounded. Stop the run.

**1.5/1.6 are the defect in `PRD_LIVE_VALIDATION.md` §4.** If the watched namespace
answers `no` while the run believes it is watched, the watcher is blind and the run
will report a healthy cluster. Both answers must be captured, not inferred.

---

## 2. Scenario 1 — True OOMKill detonation → Tier-1

**Maps to:** LV-AC-8, LV-AC-10. **Fixture:** `deploy/chaos/oom-leak.yaml`.

### 2.1 Preconditions

`busybox:1.36.1` in the `k8s.io` namespace (1.9). A populated `/manifests` mount whose
target manifest contains a `resources.limits.memory` for container `oom-canary`
(`PRD_LIVE_VALIDATION.md` LV-5).

### 2.2 Ordering is load-bearing

**Start the invariant runner BEFORE applying the fixture.** The kubelet clears
`state.terminated` the instant it restarts a container, so the `137` survives only in
`lastState`. A sampler whose window opens after the restart can observe
`CrashLoopBackOff` forever and never the cause — it fails with "never observed
`Terminated{exit_code: 137}`" against a perfectly healthy system under test.

```bash
# 2.2.1 sample first
PYTHONUNBUFFERED=1 ~/SREK3S/.venv311/bin/python tests/e2e/runner.py \
  'srek3s.io/chaos=oom' \
  --namespace sentinel-chaos \
  --observe-seconds 90 \
  --incident-file /tmp/captured_incidents.jsonl \
  --manifest deploy/chaos/oom-leak.yaml \
  --snapshot-before /tmp/snapshot-before.yaml \
  --snapshot-after  /tmp/snapshot-after.yaml  > /tmp/runner.log 2>&1 &
echo $! > /tmp/runner.pid

# 2.2.2 then detonate
sudo kubectl apply -f deploy/chaos/oom-leak.yaml
```

**Observation window ≥ 90s, and this is not a preference.** The kubelet restarts a
failed container *immediately* the first time — no backoff entry exists yet — and
enters backoff only from the second failure. `CrashLoopBackOff` is unobservable
before ~12s. A 5s deadline fails against a fixture working perfectly.

### 2.3 State transition

```bash
sudo kubectl -n sentinel-chaos get pod -l srek3s.io/chaos=oom \
  -o jsonpath='{.items[0].status.containerStatuses[0]}'
```

Assert `terminated.exitCode == 137` **and** `terminated.reason == "OOMKilled"`.

**Negative states, each a distinct diagnosis:**

| Observed | Meaning |
|---|---|
| `Evicted` | node-pressure eviction, not a cgroup OOM — the fixture did not do its job |
| `exit 1`, `Error` | the allocator exited rather than being killed — broken fixture |
| ephemeral-storage failure | the payload wrote to disk instead of allocating on the heap |

### 2.4 Contract A assertions

From the capture (`/tmp/captured_incidents.jsonl`), per incident:

| Field | Assertion |
|---|---|
| `incident_id` | matches `^inc_[0-9A-HJKMNP-TV-Z]{20,}$` (Crockford base32 ULID) |
| `reason` | `OOMKilled` |
| `exit_code` | `137` — **invariant I-A2**; the agent rejects the payload otherwise |
| `resource_limits.memory_limit` | non-null — also I-A2 |
| `detection_latency_ms` | `<= 2000` — I-A4 / AC-1 |
| `scrubbed_logs` | present; an empty list is a low-evidence signal, not a pass |
| `cluster_events[]` | `type: Warning`, each `message` scrubbed |

`detection_latency_ms` is clamped at 2000 by the emitter (`internal/emitter`), and
`ErrLatencyClamped` / `Clamped(payload)` are exposed so a clamp is **countable**
rather than hidden. Report the count of clamped incidents; a run where clamping hides
slow detection is the failure AC-1 exists to catch.

### 2.5 Tier-1 assertions

| Assertion | Source |
|---|---|
| `blast_radius_tier == TIER_1_TOIL` | Contract B |
| `remediation.git_patch` non-empty, unified, **unfenced** | I-B4 |
| `patch_validated == true` | I-B2 — only after real `git apply --check` |
| `git apply --check` against the live mounted manifest exits `0` | AC-3 |
| patched YAML parses, and exactly one field changed: `resources.limits.memory` | `agent/patch.py` layer 2 |

**A diff that applies is not a diff that works.** Nothing here asserts remediation
succeeded — see `PRD_LIVE_VALIDATION.md` §1: the verification loop is unwired.

---

## 3. Scoped RBAC manifest for `sentinel-chaos`

Required by `PRD_LIVE_VALIDATION.md` LV-6. **Zero mutating verbs. No ClusterRole.**

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: srek3s-sentinel
  namespace: sentinel-chaos
  labels:
    app.kubernetes.io/name: srek3s-sentinel
    app.kubernetes.io/part-of: srek3s
rules:
  # Verbs are ENUMERATED, not wildcarded. An allow-list cannot accidentally cover a
  # future write verb; a deny-list of writes can.
  - apiGroups: [""]
    resources: ["pods", "pods/log"]
    verbs: ["get", "list", "watch"]
  - apiGroups: [""]
    resources: ["events"]
    verbs: ["get", "list", "watch"]
  - apiGroups: ["apps"]
    resources: ["deployments", "replicasets"]
    verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: srek3s-sentinel
  namespace: sentinel-chaos
  labels:
    app.kubernetes.io/name: srek3s-sentinel
    app.kubernetes.io/part-of: srek3s
subjects:
  # Points back at srek3s-system: one ServiceAccount, one identity to audit, while
  # the GRANT stays narrow. Many namespaces means many narrow Roles to review, not
  # one wide Role.
  - kind: ServiceAccount
    name: srek3s-sentinel
    namespace: srek3s-system
roleRef:
  kind: Role           # MUST be Role. A ClusterRole here would be the highest-
  name: srek3s-sentinel   # severity change available to this codebase.
  apiGroup: rbac.authorization.k8s.io
```

`roleRef` is immutable in Kubernetes, which is a feature here: a live escalation
attempt is rejected outright, so an attacker must edit a reviewable file.

Then **confirm before trusting it** — both directions:

```bash
SA=system:serviceaccount:srek3s-system:srek3s-sentinel

sudo kubectl auth can-i list pods -n sentinel-chaos --as=$SA   # MUST be: yes
sudo kubectl auth can-i create pods -n sentinel-chaos --as=$SA  # MUST be: no
sudo kubectl auth can-i update pods -n sentinel-chaos --as=$SA  # MUST be: no
sudo kubectl auth can-i patch  pods -n sentinel-chaos --as=$SA  # MUST be: no
sudo kubectl auth can-i delete pods -n sentinel-chaos --as=$SA  # MUST be: no

# and the negative control: a verb nobody granted must also be no
sudo kubectl auth can-i list secrets -n sentinel-chaos --as=$SA # MUST be: no
```

The last line matters: without it, a `no` from the second command is consistent with
a ServiceAccount that simply has no permissions at all — which would make the run
pass while proving nothing.

---

## 4. Scenario 2 — CrashLoopBackOff escalation

**Maps to:** LV-AC-10. **Fixture:** `deploy/chaos/crashloop.yaml`.

### 4.1 Threshold behaviour

| `restart_count` | Expected tier | Mechanism |
|---|---|---|
| `<= 5` | `TIER_1_TOIL` **only if** the reason is `OOMKilled` | `classifier.TierPolicy.max_restarts = 5` |
| `> 5` | `TIER_2_ARCHITECTURAL`, `git_patch == ""` | precondition `restart_count_within_policy` fails → deny-by-default |

**A `CrashLoopBackOff` incident is Tier-2 unconditionally**, regardless of restart
count. `ARCHITECTURE.md` §5.3 admits Tier-1 only for `OOMKilled`, and
`internal/emitter.mapReason` will only serialise those two reasons. Asserting
otherwise is asserting a payload that cannot exist.

### 4.2 Required assertions

| Assertion | Notes |
|---|---|
| `reason == "CrashLoopBackOff"` | Contract A |
| `exit_code` is `null` | the container has not terminated in the current instance; a `0` would assert a clean exit |
| `restart_count >= 1` | invariant I-A3 |
| causal chain: `Terminated{reason}` **precedes** `Waiting{CrashLoopBackOff}` | the chain is carried by `lastState`, because the kubelet clears `state.terminated` |
| Contract B: `blast_radius_tier == TIER_2_ARCHITECTURAL` | |
| Contract B: `git_patch == ""` **and** `patch_validated == false` | invariant I-B1 |
| a War-Room dispatch was emitted | `agent/warroom.py` |
| the dispatch carries **no** field able to express a write verb | invariant I-B5 |

### 4.3 Two fixtures, one selector — a trap

Both chaos pods carry the label `srek3s.io/chaos`. A bare
`kubectl get pods -l srek3s.io/chaos` matches **both**, and `get_pod` returning
`items[0]` sorts `srek3s-chaos-crashloop-*` ahead of `srek3s-chaos-oom-*` — so the
runner samples the crashloop pod only, whose exit code is `1`, never `137`.

**Use the specific selector `srek3s.io/chaos=oom` wherever exit-code-137 evidence is
required.** Widening `get_pod` to return every match does not fix it: `Observation`
carries no pod identity, so the causal-chain check would satisfy its two halves from
two different containers — a false pass, which costs more than the bug it hides.

---

## 5. `/manifests` mount strategy (local validation only)

### 5.1 The problem

`deploy/agent.yaml` ships `emptyDir` at `/manifests`, and
`deploy/payments/checkout-api.yaml` does not exist in this repository. Both make
Tier-1 unreachable, deterministically and by design.

### 5.2 Options, ranked

| Option | Mechanism | Assessment |
|---|---|---|
| **A — overlay hostPath (local validation)** | patch a copy of `deploy/agent.yaml` to mount the repo read-only | **Recommended for this environment.** No cluster storage required; the checkout is the working tree being tested |
| B — PVC + manual copy | `local-path` PV, `kubectl cp` the checkout in | Realistic, more moving parts, survives pod restarts |
| C — git-clone init container | clones on start | Closest to production GitOps; needs egress to a git remote |
| D — leave `emptyDir` | — | Validates **only** the Tier-2 path and the no-mutation guarantee |

### 5.3 Option A overlay — the patch

Applied as an **overlay**, never by editing `deploy/agent.yaml`, because that file is
parsed by the hardening tests and a rendered-only field is a field no test can see.

```yaml
# tests/e2e/fixtures/manifests-hostpath.yaml — Kustomize overlay, NOT applied directly.
apiVersion: v1
kind: Pod
metadata:
  name: _manifests-hostpath-placeholder
  annotations:
    # Inert. Present only so this document has a valid top-level object.
    srek3s.io/note: "overlay fragment; see REALWORLD_TESTING.md §5"
spec:
  containers: [{ name: placeholder, image: busybox:1.36.1 }]
```

The substantive change is to the agent Deployment's volume, expressed as a Kustomize
patch applied **on top of** `deploy/agent.yaml`:

```yaml
# kustomization.yaml for the live-validation overlay
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
namespace: srek3s-system
resources:
  - ../../deploy/namespace.yaml
  - ../../deploy/rbac.yaml
  - ../../deploy/sentinel.yaml
  - ../../deploy/agent.yaml
  - ../../deploy/service.yaml
  - ./chaos-rbac.yaml          # §3
  - ./agent-manifests-hostpath.yaml
patches:
  - path: ./agent-manifests-hostpath.yaml
    target:
      kind: Deployment
      name: srek3s-agent
```

with the patch body:

```yaml
# agent-manifests-hostpath.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: srek3s-agent
spec:
  template:
    spec:
      containers:
        - name: agent
          env:
            # Must name a file that EXISTS inside the mount. The default
            # deploy/payments/checkout-api.yaml does not exist in this repository,
            # which is a second independent cause of deterministic Tier-2.
            - name: SREK3S_TARGET_MANIFEST
              value: deploy/chaos/oom-leak.yaml
          volumeMounts:
            - name: manifests
              mountPath: /manifests
              readOnly: true       # I-B4: the agent must not rewrite the file it diffs against
      volumes:
        - name: manifests
          hostPath:
            # k3s runs inside this WSL distribution, so the "node" filesystem IS
            # the WSL filesystem. /home/duckie/SREK3S is a real node path.
            path: /home/duckie/SREK3S
            type: Directory
```

### 5.4 Constraints on a `hostPath` mount

| Constraint | Reason |
|---|---|
| `type: Directory` | fails fast if the path is absent, rather than creating an empty dir |
| `readOnly: true` on the mount | the agent must not write to the checkout |
| **Forbidden in `deploy/*.yaml`** | a `hostPath` outlives the pod; `internal/deploy`'s `TestTmpIsTheOnlyWritablePath` rejects non-`emptyDir` mounts, and a `hostPath` widens blast radius past the namespace |
| Validate the path is a Git repo | `agent/patch.py` layer 3 runs `git init` in a scratch dir and `git apply --check` against the bytes; it does not need the mount to be a repo, but the mount must be readable by UID 10001 |

**File permission check.** The checkout is owned by `duckie` (uid 1000); the agent
runs as 10001. Verify readability **as that uid**, not as yourself:

```bash
sudo kubectl -n srek3s-system exec deploy/srek3s-agent -- \
  python -c "import os;print(os.access('/manifests/deploy/chaos/oom-leak.yaml', os.R_OK))"
```

`False` here is a permission failure that presents as an unreadable manifest and
therefore as a silent, permanent Tier-2 — the same failure mode as the empty mount,
with a different cause.

---

## 6. Scenario 3 — Tri-directional secret leak validation

**Maps to:** LV-AC-9. This is the scenario most likely to produce a false pass.

### 6.1 The three assertions

| # | Assertion | A failure means |
|---|---|---|
| 1 | No planted secret appears in any agent log, captured payload, or emitted artifact | the core security property is broken |
| 2 | `[REDACTED]` **is present** in the captured payload | an empty or all-dropped log would satisfy assertion 1 vacuously |
| 3 | Diagnostic topology survives | over-masking has destroyed the evidence an RCA reasons over |

**Assertion 1 alone is worthless** as a proof. A pipeline that discards every log
line emits no secrets. Assertions 1 and 2 together are the minimum meaningful pair;
assertion 3 is what keeps masking honest.

### 6.2 Planted credentials

Derive from the fixture, **not** from the scrubber — otherwise a rule change makes the
test agree with itself.

| Value | Rule exercised |
|---|---|
| `AKIAIOSFODNN7EXAMPLE` | 2 `aws_access_key_id` |
| `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY` | 3 `aws_secret_access_key` |
| `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkNoYW9zIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk` | 4 `jwt` |
| `chaos-planted-bearer-token-0123456789` | 5 `bearer_token` |
| `Sup3rS3cretPassw0rd` | 6 `basic_auth_url` |

**The username is deliberately NOT asserted absent.** It appears in
`postgres://chaos_user:Sup3rS3cretPassw0rd@db.production.svc.cluster.local:5432/billing`.
Rule 6 must mask **only the password** and preserve `scheme://user:[REDACTED]@host:port`,
because the host and port are the signal an RCA reasons over. An earlier version of
this check asserted the username was masked and failed against *correct* behaviour: a
test demanding the username be masked is a test demanding the violation.

### 6.3 Tail-window arithmetic

The fixture prints 20 iterations × 4 credential lines = 80 lines, plus ~6 from the
allocation phase. `internal/k8s/telemetry.go` reads `LogTailLines = 100` and
`LogLimitBytes = 51200`, so ~86 lines keeps every planted secret inside the window
actually fetched.

**Raising the iteration count past ~24 rotates the first secrets out of the tail** and
silently weakens this assertion from "all five rules" to "a subset". If the iteration
count changes, this arithmetic changes with it.

### 6.4 Evidence collection

The capture proxy sits **between the Sentinel and the agent**, and external to both —
it instruments the wire, so it stays outside the binary whose behaviour it measures.
No production code is touched.

```bash
# start the agent first, then the proxy, then the Sentinel — so no incident can be
# emitted past the proxy
PYTHONPATH="$PWD/tests/e2e" nohup ~/SREK3S/.venv311/bin/python -m capture_proxy \
  --output /tmp/captured_incidents.jsonl --listen-port 8001 --upstream-port 8000 \
  > /tmp/capture_proxy.log 2>&1 &
```

`-agent-url http://127.0.0.1:8001` — **the proxy's root, never an endpoint path.**
The emitter appends `/v1/incidents` itself; supplying a path yields
`/api/v1/triage/v1/incidents`, which the agent 404s.

### 6.5 Bounded wait before asserting non-emptiness

The proxy forwards upstream first and appends after the response is read, so the file
stays empty for the whole of triage plus patch verification. Test emptiness only
after a **bounded** wait (20 iterations × 1s is the measured figure; the proxy's own
upstream timeout is 10s). Echo the elapsed seconds — a wait that always returns in 0s
is not covering the Tier-1 case it was written for.

---

## 7. Scenario 4 — GitOps patch application

**Maps to:** LV-AC-10. **Hermetic, no cluster required.**

### 7.1 Offline generation gate — run this first

It needs no cluster and costs seconds, which is why it belongs before a 20-step
cluster bring-up rather than at the far end of it.

```bash
~/SREK3S/.venv311/bin/python tests/e2e/verify_patch.py \
  --manifest tests/fixtures/oom-restartloop.yaml \
  --path deploy/payments/checkout-api.yaml \
  --container checkout-api \
  --from-limit 256Mi --to-limit 512Mi
```

Expected: `[ok] structural round-trip`, `[ok] git apply --check`, `[ok] negative
control: git rejects the unterminated variant`, `[ok] agent's I-B2 gate agrees with
real git`, `patch_validated: True`, `RESULT: PASS`.

**The negative control is the load-bearing line.** An earlier version of the harness
appended a trailing newline before verifying, so it checked a *repaired* artifact —
and every emitted patch was unapplyable while the gate reported success. A check that
cannot fail is not a check.

### 7.2 Against the live mounted manifest

```bash
sudo kubectl -n srek3s-system exec deploy/srek3s-agent -- sh -c '
  d=$(mktemp -d); cd "$d"; git init -q .
  mkdir -p "$(dirname deploy/chaos/oom-leak.yaml)"
  cp /manifests/deploy/chaos/oom-leak.yaml deploy/chaos/
  git apply --check --whitespace=nowarn /tmp/patch.diff && echo APPLIES
'
```

### 7.3 Three-layer assertions

| Layer | Catches | Cannot catch |
|---|---|---|
| positional round-trip | a patch that does not change exactly one line | a malformed diff the line arithmetic accepted |
| YAML AST | a textually perfect but semantically wrong patch | malformed diff syntax |
| `git apply --check` | a malformed diff | a wrong start offset — git **tolerates** offset drift when content matches, so the structural layer catches what git forgives |

Measured, not assumed: two of this project's own tests asserted the opposite and
failed against real git.

### 7.4 What is NOT asserted

No diff is applied to the cluster as part of validation
(`PRD_LIVE_VALIDATION.md` NG-3). Asserting that a generated patch applies; do not
assert that applying it fixed anything — that requires the unwired verification loop.

---

## 8. Namespace teardown

**Mandatory before the run starts, not after it fails.** Apply §8.1, verify, then
begin.

```bash
# 8.1 snapshot before
sudo kubectl get deploy,rs,pods,svc,cm -A -o yaml > /tmp/cluster-before.yaml

# 8.2 run scenarios

# 8.3 teardown — verify deletion COMPLETED before declaring done
sudo kubectl delete namespace sentinel-chaos --wait=true --timeout=180s
sudo kubectl get namespace sentinel-chaos && echo "STILL PRESENT — teardown failed"
```

`--wait=true` matters: a delete issued and not awaited races the next run, which then
inherits whatever the previous run left. `docs/lessons-learned.md` records a run lost
to exactly this.

### 8.4 Post-run mutation accounting

```bash
sudo kubectl get deploy,rs,pods,svc,cm -A -o yaml > /tmp/cluster-after.yaml
```

Assert: no object outside `sentinel-chaos` changed `generation` or `resourceVersion`;
objects created inside the chaos namespace are **counted**, not merely excluded — an
exemption that is not tallied is indistinguishable from a silent failure. System
namespace churn (coredns, traefik) is counted and excluded **by name**.

---

## 9. Execution order

```
 §1 pre-flight  ── fail here ⇒ STOP; the run's blast radius is not understood
      │
      ├─ §4 image registration (before any pod is scheduled)
      ├─ §3 scoped RBAC + auth can-i both directions
      ├─ §5 manifests overlay (Tier-1 reachability)
      │
      ├─ Scenario 1  OOMKill      → Tier-1 diff
      ├─ Scenario 2  CrashLoop   → Tier-2 escalation
      ├─ Scenario 3  secrets     → tri-directional, ALL THREE
      ├─ Scenario 4  patch       → hermetic first, then live
      │
      └─ §8 teardown + mutation accounting
```

Scenarios 1 and 3 share one capture and must run against the same fixture window.
Do not interleave Scenario 2 into that window: a second failing pod changes restart
counts and therefore tier decisions for Scenario 1.
