# PRD_LIVE_VALIDATION — Product Requirements: Live & In-Situ Execution

| Field | Value |
|---|---|
| Document ID | `PRD-LIVE-0001` |
| Version | `0.1.0` |
| Status | Draft — **gates the in-cluster phases** |
| Requirement source | `PRD.md` (MVP), `ARCHITECTURE.md` (schemas), `ROADMAP.md` M4 |
| Execution rules | `TESTING_BASE_RULES.md` (binding) |
| Execution matrix | `REALWORLD_TESTING.md` (binding) |
| Host of record | `AGENTS.md` §2 "Runtime Baseline" |

---

## 1. Purpose and scope

This document specifies what must be true for SREK3S to be considered validated
**against a running Kubernetes control plane**, as distinct from the offline
verification already complete.

The MVP was verified offline and, previously, on `ubuntu-latest` CI. Neither proves
the deployed configuration works, because the two failure modes that matter most are
properties of the *cluster*, not of the code:

1. **Routing.** Does the Sentinel's configured `-agent-url` actually resolve, through
   a Service these manifests create, to a port the agent actually binds? v1.0.0
   shipped a deploy set that applied cleanly, passed every manifest test, and could
   not route a single packet.
2. **Authorisation.** Does the apiserver actually reject a write from the Sentinel's
   real ServiceAccount? A manifest that *reads* read-only is an assertion; a `403`
   from a live apiserver is a fact.

In scope: the full incident lifecycle under live observation.

```
pod failure → Sentinel detection → in-memory scrub → Contract A
           → agent triage       → Contract B (Tier-1 diff | Tier-2 RCA)
```

Out of scope, and the reason is the product rather than a deferral: the post-
remediation verification loop (`PRD.md` F4, `ARCHITECTURE.md` §5.2) **is not wired**.
`agent/verify.py` is implemented and tested but imported by no production module
(`AGENTS.md` §2, `ARCHITECTURE.md` §5.5.1). Live validation can therefore observe a
Tier-1 diff being *proposed*; it cannot observe the loop that would *confirm* it.
Any claim that the closed loop works in-cluster is unsupported by this document.

---

## 2. Live-environment requirements

### 2.1 Pod Security Admission — `restricted`, enforced

`srek3s-system` is created with `pod-security.kubernetes.io/enforce: restricted`
(`deploy/namespace.yaml`). This is *enforcement at admission*, not a warning: a pod
violating the baseline is refused rather than admitted and left to this repository's
tests. The tests are the guarantee; admission is the control.

| Requirement | Assertion |
|---|---|
| LV-1.1 | `enforce=restricted` is present on both `srek3s-system` and `sentinel-chaos` |
| LV-1.2 | `enforce-version=latest` is present, and its value is asserted **separately** from `enforce` |

LV-1.2 exists because `grep 'enforce'` is a substring match: an assertion written
that way is satisfied by `enforce-version` appearing with any value, and the check
passes on a namespace that never opted into a version at all.

> **Version skew, recorded rather than discovered later.** Local k3s is
> **v1.36.4+k3s1**; CI's is **v1.29.9+k3s1**. Because `enforce-version: latest`
> resolves against the running control plane, a manifest this host admits can be
> refused by CI for a reason unrelated to the code. Any PSA finding must name the
> control-plane version before it is called a defect.

### 2.2 Non-root execution — UID/GID 10001

| Requirement | Assertion |
|---|---|
| LV-2.1 | Agent image: `docker inspect` reports `User=10001:10001`, **and** `docker run --entrypoint id -u` prints `10001` |
| LV-2.2 | Sentinel image: `docker inspect` reports `User=10001:10001` |
| LV-2.3 | In-cluster: the running pod's effective UID is `10001` |

**LV-2.2 cannot use `id`, and the reason is the product.** The Sentinel image is
`gcr.io/distroless/static-debian12` — no shell, no libc, no coreutils. `id` is not in
the image, so `docker run --entrypoint id` fails with `no such file or directory`.
That is hardening working. Prove it instead by:

```bash
# declared identity
sudo docker inspect registry.internal/srek3s-sentinel:0.1.0 --format 'User={{.Config.User}}'

# the binary is executable by the identity, and runs under a read-only rootfs
sudo docker run --rm --read-only --cap-drop ALL --security-opt no-new-privileges \
  --entrypoint /bin/sentinel registry.internal/srek3s-sentinel:0.1.0 -version   # => 0.1.0-dev

# negative control: the absence of a shell is real, not a broken harness
sudo docker run --rm --entrypoint /sh registry.internal/srek3s-sentinel:0.1.0    # => not found
```

**Negative-control requirement.** The absence of `/sh` and `/id` must be shown with
the daemon's own error, not inferred. A first attempt at this check piped the error
through `tail -1`, which captured Docker's usage hint instead of the failure and made
every binary look "present". A control that fails for the wrong reason is worse than
no control, because it reads as a pass (`AGENTS.md` §5.6).

In-cluster, `kubectl exec … -- id -u` also cannot work against the Sentinel for the
same reason. Assert the **pod spec's** `runAsUser` and the image's `User`, and prove
executability with `/bin/sentinel -version`, which is what the exec liveness probe
already does.

### 2.3 Read-only root filesystem and dropped capabilities

| Requirement | Assertion |
|---|---|
| LV-3.1 | `readOnlyRootFilesystem: true` on both containers |
| LV-3.2 | `capabilities.drop: ["ALL"]`, `add` absent — an allow-list is a list to forget an entry on |
| LV-3.3 | `allowPrivilegeEscalation: false`, `privileged: false` |
| LV-3.4 | `seccompProfile.type: RuntimeDefault` |
| LV-3.5 | `/tmp` is the **only** writable mount, and it is an `emptyDir` |
| LV-3.6 | No `hostPath` in `deploy/*.yaml` (see LV-5 for the local-validation exception) |

### 2.4 NetworkPolicy containment

| Requirement | Assertion |
|---|---|
| LV-4.1 | Sentinel egress: apiserver `6443`, agent `8000`, DNS `53` only |
| LV-4.2 | Agent egress: DNS only; ingress from the Sentinel only, on `8000` |
| LV-4.3 | **Empirically** confirmed — not assumed |

> **LV-4.3 is unverified and must not be reported as satisfied by inspection.** No
> NetworkPolicy controller *pod* is observable in `kube-system` on this host. k3s runs
> its kube-router network-policy controller **embedded in the `k3s server` process**,
> so the absence of a pod is expected rather than alarming — but that is an inference
> about a mechanism, not an observation of it (`AGENTS.md` §5.7). Enforcement is
> confirmed by attempting a connection that the policy should block and recording the
> refusal. Until then, record NetworkPolicy behaviour as **expected, unverified**.

### 2.5 Mounted GitOps manifest integration

`deploy/agent.yaml` mounts `/manifests` and sets `SREK3S_MANIFEST_ROOT=/manifests`,
but the volume is an **`emptyDir`** shipped empty. Consequences, in the order they
occur in `agent/triage.py::_build_remediation_diff`:

1. `FileManifestProvider.read_manifest` returns `None` (the file is absent), and
2. `_build_remediation_diff` bails at its second guard with
   `"target manifest is unreadable, so no patch can be derived or checked (I-B2)"`.

The incident therefore escalates to `TIER_2_ARCHITECTURAL` with `git_patch == ""` and
`patch_validated == false`. **This is fail-closed design working (invariant I-B2).**
It is not a misconfiguration — but it is indistinguishable at a glance from a broken
agent, which is why it is stated in the manifest, the runbook and here.

**A second, independent cause.** `classifier.DEFAULT_TARGET_MANIFEST` is
`deploy/payments/checkout-api.yaml`, and **that file does not exist in this
repository** (verified 2026-10-01). So even with a populated mount, an unset
`SREK3S_TARGET_MANIFEST` yields Tier-2.

| Requirement | Assertion |
|---|---|
| LV-5.1 | A **real** GitOps checkout is mounted at `/manifests`, read-only to the agent |
| LV-5.2 | `SREK3S_TARGET_MANIFEST` names a path **that exists inside that checkout** |
| LV-5.3 | The manifest contains a `resources.limits.memory` for the **named container** the incident reports, or patch synthesis declines honestly |
| LV-5.4 | The agent cannot write to `/manifests` — a triage path that could rewrite the manifest it is about to propose a diff against could make that diff apply to something other than what it was derived from |

LV-5.4 is why `deploy/agent.yaml` mounts `/manifests` with `readOnly: true` while
`/tmp` is writable.

For **local validation only**, a `hostPath` mount is acceptable and is the documented
mechanism — see `REALWORLD_TESTING.md` §5. It is forbidden in `deploy/*.yaml`
(LV-3.6) because a `hostPath` outlives the pod and widens blast radius beyond the
namespace the rest of the design is scoped to.

---

## 3. Non-goals and explicit boundaries

These are architectural commitments. Per `PRD.md` §3.2, each is a decision rather
than a deferral.

### NG-1 — Zero cluster-write authorisation

The Sentinel's ServiceAccount holds `["get","list","watch"]` on `pods`, `pods/log`,
`events`, `deployments`, `replicasets` **in one namespace**. There is no
`ClusterRole`, no `ClusterRoleBinding`, and no wildcard verb list.

A live run must **demonstrate** this rather than assert it: a write attempt from the
Sentinel's real ServiceAccount must be refused by the apiserver with a `403`. A
successful write is an immediate failure of the entire suite — it means the property
this product exists to provide is false on this cluster.

### NG-2 — Zero LLM network egress

`agent/llm.py` declares `CompletionClient` as a `typing.Protocol` with **no
implementation**, deliberately (`AGENTS.md` §5.3). It imports no network library.
`fastembed`/`onnxruntime` appear only in a **comment** in `agent/requirements.txt` and
are installed nowhere. All analysis is deterministic: regex, arithmetic, YAML, and
real `git`.

The agent's egress is therefore DNS-only by construction, and
`deploy/agent.yaml`'s NetworkPolicy permits exactly that. **A live run must observe
no outbound connection to any model endpoint.** If a run cannot produce a Tier-1 diff
without network access to an inference service, that is a defect in the harness, not
a missing feature.

`httpx` is a declared runtime requirement but is used only by tests, through
`httpx.ASGITransport`, which never leaves the process.

### NG-3 — No automated application of generated diffs

SREK3S **proposes**; it never **applies**. A Tier-1 diff is applied by a human, or by
an already-approved GitOps controller. There is no flag, environment variable, or
code path that enables direct mutation — the capability does not exist to be enabled
(`PRD.md` §3.2, `docs/runbook.md` §5).

Consequently, live validation asserts that a generated diff **applies cleanly under
`git apply --check`** and that its YAML remains parseable. It does **not** apply the
diff to a cluster as part of validation. Applying it to observe remediation would
require an external actor and is out of scope here.

### NG-4 — No multi-tenancy, no multi-cloud federation

Carried forward from `PRD.md` §5 unchanged. A dashboard or an IAM federation is a
larger platform project with its own threat model and adds nothing to detection,
masking, or diff generation.

---

## 4. Scope and grant must agree — blocking pre-condition

**This is a confirmed static defect, not yet reproduced at runtime.**

`deploy/sentinel.yaml` sets `WATCH_NAMESPACE: ""`, which selects a cluster-wide
informer whose initial `LIST` is `GET /api/v1/pods` across every namespace.
`deploy/rbac.yaml` grants a `Role` **in `srek3s-system` only**. A cluster-wide list
is therefore unauthorised.

The failure mode is silence, not an error: the informer retries the forbidden
`LIST`, the operator sees no incidents, and a broken watcher is indistinguishable
from a quiet cluster. Neither existing RBAC test catches this, because
`TestSentinelRoleGrantsNoMutatingVerb` and
`TestSentinelRoleGrantsWhatTheWatcherReads` are each correct checks over a single
manifest; neither compares the two.

**LV-6 (blocking):** before any live detection test, either

- `WATCH_NAMESPACE` names a specific namespace **and** a matching `Role` +
  `RoleBinding` exist there, **or**
- a `ClusterRole` is added — **rejected**: widening a watcher's read authority to
  every namespace, including namespaces holding other people's secrets, is the
  single highest-severity change available to this codebase.

The two-sided fix is the only acceptable one. `REALWORLD_TESTING.md` §3 carries the
exact scoped manifest and the `kubectl auth can-i` confirmation.

---

## 5. Acceptance criteria

Each criterion is objective and executable. Met only when its command exits `0`.

| ID | Criterion | Verification |
|---|---|---|
| **LV-AC-1** | Both images build from the repository root on `linux/arm64` | `sudo docker build … -f cmd/sentinel/Dockerfile .` and `-f agent/Dockerfile .` exit `0` |
| **LV-AC-2** | Both images declare UID 10001; the agent proves it at runtime | `docker inspect … User=10001:10001`; `docker run --entrypoint id … -u` → `10001` |
| **LV-AC-3** | Both images are registered in the `k8s.io` namespace under their **exact** qualified names | `sudo k3s ctr --namespace k8s.io images ls` contains `registry.internal/srek3s-{agent,sentinel}:0.1.0` — a `docker.io/library/…` or `sha256:` line means the tag did not register, and presents as `ImagePullBackOff` |
| **LV-AC-4** | Pod Security Admission is `restricted` on both namespaces | four independent label assertions, one per check |
| **LV-AC-5** | The Sentinel's writes are refused by a **live apiserver** | `kubectl auth can-i create pods --as=…srek3s-system:srek3s-sentinel` → `no` |
| **LV-AC-6** | The Sentinel's reads are granted in the watched namespace | `kubectl auth can-i list pods --as=…` → `yes` |
| **LV-AC-7** | The agent Service publishes ready endpoints; DNS resolves `srek3s-agent`; `/healthz` answers | `kubectl get endpoints`, `getent`/DNS probe, `curl` from a pod |
| **LV-AC-8** | A real OOM produces a real incident with p99 detection latency ≤ 2000 ms and a 1:1 injection-to-detection ratio | `REALWORLD_TESTING.md` Scenario 1 |
| **LV-AC-9** | Zero plaintext credentials survive the full pipeline, **and** `[REDACTED]` markers are present, **and** diagnostic topology survives | `REALWORLD_TESTING.md` Scenario 3 (tri-directional) |
| **LV-AC-10** | Tier-1 diffs pass real `git apply --check`; Tier-2 incidents carry `git_patch == ""` | `REALWORLD_TESTING.md` Scenarios 1, 2, 4 |
| **LV-AC-11** | No incident produced a cluster mutation | before/after object `generation`/`resourceVersion` snapshot, chaos-namespace changes counted and excluded by name |
| **LV-AC-12** | No outbound model connection occurred | NetworkPolicy permits DNS only; observed connection set is empty beyond DNS |

LV-AC-9 is deliberately three-directional. "Masked everything" and "masked nothing"
are both failures, and an assertion that only checks for absence passes against an
empty log — the most likely way for a masking proof to be vacuous.

---

## 6. Risks specific to in-situ execution

| ID | Risk | Mitigation |
|---|---|---|
| LR-1 | A wrong namespace scope produces a watcher that is silently blind | LV-6 is **blocking**; confirmed by `kubectl auth can-i`, never by log inspection alone |
| LR-2 | Images imported into the wrong containerd namespace | `k3s ctr` defaults to `default`; the kubelet reads `k8s.io`. Assert the qualified name, not the presence of an image |
| LR-3 | Empty `/manifests` yields 100% Tier-2 and is read as a working agent | §2.5; the agent logs `manifest_provider=` and `target_manifest=` at startup for exactly this |
| LR-4 | NetworkPolicy silently not enforced | LV-4.3 requires an empirical blocked-connection test |
| LR-5 | Architecture skew — local `arm64`, CI `amd64` | state the architecture of every image and every measurement |
| LR-6 | PSA behaviour differs between k3s 1.36 (local) and 1.29 (CI) | §2.1; name the control-plane version with any PSA finding |
| LR-7 | A test namespace left behind alters a later run | `TESTING_BASE_RULES.md` Rule 4 makes teardown mandatory and verified |
| LR-8 | Reading `verify.py`'s existence as a working closed loop | §1 scope exclusion; `ARCHITECTURE.md` §5.5.1 |
