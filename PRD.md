# PRD — Autonomous Reliability Firewall & Incident Sentinel

| Field | Value |
|---|---|
| Document ID | `PRD-0001` |
| Version | `0.1.0` |
| Status | Draft — pending review |
| Subsystem of record | `ARCHITECTURE.md` |
| Delivery plan of record | `ROADMAP.md` |

---

## 1. Summary

The Autonomous Reliability Firewall ("the Sentinel") is a Kubernetes-native incident
detection and remediation-proposal system. It detects reliability failures
(`OOMKilled`, `CrashLoopBackOff`) on a cluster, sanitizes the resulting telemetry
**in memory** before it leaves the node, and routes it to a constrained analysis engine
that produces exactly two artifacts:

1. a human-readable Root Cause Analysis (RCA), and
2. a machine-parsable **unified `git diff`** targeting Kubernetes deployment manifests.

The Sentinel holds **no write path to the cluster**. It proposes changes as reviewable
diffs; humans or an existing GitOps controller (Argo CD / Flux) perform the actual apply.

---

## 2. Problem Statement

### 2.1 The Blast-Radius Problem

"Blast radius" is the maximum extent of damage a single faulty automated action can cause.
In classical operations tooling the blast radius of a bad command is bounded by RBAC and by
the fact that a human typed it. The moment an LLM agent is granted cluster write verbs, that
bound disappears.

A non-deterministic actor with `update`/`patch`/`delete` on workloads can, in a single turn:

- scale a revenue-generating `Deployment` to zero replicas;
- delete a `StatefulSet` and take a database's persistent volume with it;
- mutate a `NetworkPolicy` or `Service` selector and blackhole all east-west traffic;
- restart a crash-looping pod in a loop that exhausts the node's ephemeral storage;
- pivot laterally by patching a `RoleBinding` to grant itself `cluster-admin`.

Crucially, the failure modes of an LLM agent are **correlated, not independent**. The same
misreading of an error message that produces a wrong hypothesis also produces a wrong fix.
The agent's error is not a typo in a correct strategy — it is a coherent but wrong strategy
applied with production-grade privilege and at machine speed. Conventional SRE tooling has no
defence against this, because it was never designed to hand production write authority to a
probabilistic reasoner.

**Required property:** the system's *maximum* blast radius must be structurally zero against
the cluster, regardless of the analysis engine's output. Safety must be a property of the
architecture, not of a prompt, a policy check, or a confidence threshold.

### 2.2 Why Enterprises Reject Raw `kubectl` Write Access by LLMs

Enterprise security review rejects LLM-authored cluster writes for five compounding reasons:

1. **Non-reproducible authority.** A diff can be reviewed, reverted, and attributed. A live
   mutation cannot be diffed before it lands; its audit trail is a cluster audit event, which
   is discovered *after* impact, not *before*.
2. **Unbounded action space.** `kubectl` verbs compose into arbitrary state transitions.
   Sandboxing a text generator does not constrain the verb set it is allowed to choose.
3. **Prompt injection as a control-plane vector.** The agent reads untrusted data — pod logs,
   crash annotations, environment-derived error strings. Any operator who can print text into
   a log line can then attempt to steer the agent's write actions. Read-only agents are
   injectable but not *dangerous*; write agents turn injection into remote execution.
4. **Irreversibility asymmetry.** A wrong PR is reverted in seconds. A wrong `DELETE` on a PVC
   is a data-loss event and an outage-incident report.
5. **Audit and compliance regimes.** SOC 2 / ISO 27001 / PCI-DSS controls require change
   approval, segregation of duties, and evidence of review before production mutation. An
   autonomous writer cannot satisfy "approved by an authorized human" as a system property.

The Sentinel adopts the inverse of the rejected design: the analysis engine is granted
**no cluster credential at all**. Its only output channel is a text artifact that a human (or
an already-approved GitOps controller) evaluates. This converts an unbounded write capability
into an unbounded *proposal* capability, which is bounded by the review process that
enterprises already operate.

### 2.3 The Compliance Gap: Secrets in Telemetry

Sanitizing is not merely defensive hygiene; it is the precondition for the design to be
deployable at all. Kubernetes failure telemetry is unusually secret-dense:

- application logs printed on crash frequently include bearer tokens and API keys from env;
- crash loops reproduce the failing request, including `Authorization` headers and JWTs;
- stack traces and HTTP client dumps include connection strings and cookies;
- `kubectl describe`-derived events include pod IPs and, in sloppy manifests, credentials
  passed as `--env` arguments;
- incident identifiers are frequently UUIDs that map to customer records in ticketing systems.

Because LLMs and most third-party completion APIs are external processors, any secret that
reaches that boundary is a potential data-exfiltration event and a reportable breach. A
security team will not approve egress of pod logs to a third-party model without a
demonstrable masking control — and "we prompt the model not to repeat secrets" is not a
control, because it is probabilistic and post-hoc.

**Therefore:** sanitization is performed **deterministically, in memory, on the Go node,
before JSON serialization and before any socket is opened.** The raw secret-bearing string is
never written to disk, never logged, and never buffered in plaintext. Masking is a
compile-time-bounded regex pipeline with a replacement sentinel, verified by unit tests
against a fixture corpus. This is what makes the LLM path legally and operationally
deployable, and it is a *design constraint*, not an optional feature.

---

## 3. Goals and Non-Goals

### 3.1 Goals (MVP)

- **G1** Detect `OOMKilled` and `CrashLoopBackOff` on watched workloads deterministically and
  within a bounded latency budget.
- **G2** Guarantee that no credential, token, private key, or direct PII leaves the node in
  plaintext.
- **G3** Produce a deterministic, schema-valid RCA and a `git apply`-able unified diff for
  Tier-1 incidents, with **zero** cluster write verbs.
- **G4** Escalate Tier-2 (architectural) incidents to humans with full evidence instead of
  proposing risky edits.
- **G5** Verify that a proposed remediation actually restores health, and close the loop.

### 3.2 Non-Goals

Every non-goal below is an explicit architectural commitment, not a deferral.

- **No cluster write path.** The Sentinel process is constructed with a **read-only**
  `ServiceAccount`. `Role` verbs are `get`/`list`/`watch` on `pods`, `events`, and
  `deployments` only. No `ServiceAccount` in `deploy/` carries a mutating verb.
- **No "autofix" toggle.** There is no flag, env var, or config key that enables direct
  apply. This is not configurable by design.
- **No model client, and no egress to one.** The analysis engine ships a *validation
  boundary*, not a model integration. `agent/llm.py` declares `CompletionClient` as a
  `typing.Protocol` with no implementation, deliberately, and imports no network
  library. All classification, RCA and diff generation is deterministic: regex,
  arithmetic, YAML structural parsing, and real `git`. `fastembed`/`onnxruntime` are
  named in a **comment** in `agent/requirements.txt` and are installed nowhere; the
  CPU-only constraint in §7 A3 is a ceiling this MVP stays under, not a description of
  a path that runs. Adding a model call is a change to the trust boundary in
  `ARCHITECTURE.md` §1 and must be reviewed as one.
- **No reachable post-remediation loop in the shipped service.** F4 specifies the
  behaviour and `agent/verify.py` implements it, but no production module imports
  `verify`; `main.py` and `triage.py` do not. `triage.py` emits `verification_policy`
  on the wire and nothing in the running service consumes it. F4 is therefore a
  **specified and tested component that is not on the HTTP request path** — tracked
  as a known-unwired boundary in `ARCHITECTURE.md` §5.5 and as an open task in
  `ROADMAP.md`. It is listed here rather than in §5 because it is a wiring gap in
  work already claimed as delivered, and that is a different kind of debt from a
  feature deliberately deferred.
- **No multi-tenancy UI.** See §5.
- **No multi-cloud IAM federation.** See §5.

---

## 4. Core Features

### F1 — In-Memory Go PII / Secret Sanitizer

Deterministic regex masking pipeline in `internal/scrubber`, applied to every log line,
annotation, and event message before envelope construction.

- Compiled-once, ordered rule set; every rule has a named identifier and a literal
  replacement sentinel `[REDACTED]`.
- Rules operate on `[]byte`/string in memory. No plaintext scratch file, no temp file, no
  debug-logging path that re-emits the input.
- Replacement is **span-preserving and order-stable**: a longer, more specific rule
  (private key block) is evaluated before a generic `key=value` rule, so redaction is
  idempotent and cannot be undone by a later rule re-wrapping an already-masked token.
- The sanitizer is the only writer of `scrubbed_logs`. Raw telemetry is not retained anywhere
  in the process after the scrub returns.
- A **redaction accounting** field records rule-ID hit counts per incident, so masking is
  auditable without exposing what was masked.

### F2 — Ephemeral Investigation Sandbox

Deep investigation is executed as short-lived, isolated, resource-capped workers.

- Each investigation is a disposable task with a hard cgroup budget (`256Mi` RAM, `500m` CPU).
- Lifetime is bounded by a monotonic deadline; the worker is cancelled and torn down on
  timeout, so no investigation state accumulates across incidents.
- The sandbox has no cluster credential and no egress beyond the single model-API call it is
  authorized to make.
- No GPU / accelerator dependency; CPU-only inference paths only.

### F3 — Graduated Autonomy

Autonomy is not a single dial; it is a two-tier routing decision made by deterministic
classification **before** any model is consulted for a fix.

| Tier | Name | Trigger | Output | Human involvement |
|---|---|---|---|---|
| **TIER_1_TOIL** | Policy-vetted toil | Single-container `OOMKilled` with a healthy sibling; restart count below policy ceiling; known-safe remedy shape (memory limit recalibration) | RCA + **unified `git diff`** | Optional — merged through normal GitOps PR review |
| **TIER_2_ARCHITECTURAL** | Architectural triage | `CrashLoopBackOff` with correlated multi-pod symptoms, dependency/network deadlock, cascading error signature, or any classification the policy engine cannot prove to be Tier-1 | RCA + evidence bundle + **no patch** | Required — War-Room dispatch |

Rationale: the autonomy tier is decided by *verifiable evidence about the failure's scope*,
not by the model's stated confidence. Tier-2 emits `git_patch: ""` by contract — producing a
speculative diff for a cascading failure is itself a blast-radius risk, because such a patch
is most likely to be applied under pressure.

**What an in-cluster deployment demonstrates, and what it cannot.** The shipped agent
manifest mounts `SREK3S_MANIFEST_ROOT=/manifests` on an **`emptyDir`**, and the default
target `deploy/payments/checkout-api.yaml` **does not exist in this repository**. So as
deployed the agent cannot read a target manifest, `FileManifestProvider.read_manifest`
returns `None`, `_build_remediation_diff` bails at its second step, and **every incident
escalates to `TIER_2_ARCHITECTURAL` with `git_patch == ""` and `patch_validated ==
false`.** That is invariant I-B2 failing closed — the design working — but it is visually
indistinguishable from a broken agent, which is why the empty state is stated in
`deploy/agent.yaml`, `README.md` and `docs/runbook.md` in the same words.

The consequence for acceptance is concrete: **an in-cluster run of `deploy/` demonstrates
the Tier-2 war-room path and the no-mutation guarantee. It cannot demonstrate a Tier-1
patch.** Reaching AC-3 in-cluster requires replacing the `emptyDir` with a real GitOps
checkout (a PVC, or an init container that clones the repository) and setting
`SREK3S_TARGET_MANIFEST` to a repo-relative path inside it. Any claim that the in-cluster
deployment produced a validated patch is a claim about a wiring step, not about a test.

### F4 — Post-Remediation Health Verification Loop

A proposed patch is not a resolution. After a Tier-1 diff is merged and applied by GitOps,
the Sentinel re-observes the target workload for a bounded window and classifies the outcome:

- **Verified** — the container completes its full restart interval with no `OOMKilled`
  termination and no new `CrashLoopBackOff` wait state.
- **Unresolved** — the same failure signature recurs inside the verification window; emit a
  Tier-2 War-Room dispatch, because a repeated failure of a policy-vetted fix indicates the
  Tier-1 classification was wrong.
- **Indeterminate** — the observation window closed while the container was still starting;
  re-queue with a bounded attempt counter, never loop indefinitely.

The loop closes on the observation boundary only. The Sentinel does not apply anything to make
the outcome favourable.

**Wiring status: specified and tested, not reachable.** `agent/verify.py` implements this
loop (741 lines) and is exercised by `agent/tests/test_verify.py` and
`agent/tests/test_verification_e2e.py`, including a live-k3s leg recorded in `ROADMAP.md`
box `4.3.4`. But **no production module imports it**: `main.py` and `triage.py` do not,
and `triage.py` merely *emits* `verification_policy` on the wire. Nothing in the running
HTTP service consumes that field, so F4 is **not on the request path**. G5 (the
no-autofix guarantee) cites `verify.py` as evidence for the *agent's* inability to write,
which remains true and is unaffected — a component that is not wired in cannot acquire
authority — but F4's own closing-the-loop claim is not satisfied by the shipped service.
Recorded as a known-unwired boundary in `ARCHITECTURE.md` §5.5 and as an open task in
`ROADMAP.md`; §3.2 lists it as a non-goal of the *shipped* service so that no reader
infers a running loop from the presence of a `verification_policy` field.

---

## 5. Out of Scope for MVP

These are explicitly excluded. Each exclusion states the reason, so that a future proposal to
add them is a deliberate decision rather than a scope drift.

1. **Multi-tenant UI dashboards.** Reason: the MVP's user-facing surface is the GitOps PR and
   the RCA document. A dashboard introduces an authentication, authorization, and
   multi-tenancy model that is strictly larger than the reliability engine itself, and would
   consume the MVP's budget before the detection path is proven.
2. **Active cluster auto-healing (direct cluster writes).** Reason: **strictly forbidden by
   architecture, not deferred by schedule.** Granting the agent mutating verbs reintroduces
   exactly the blast radius described in §2.1 and fails the enterprise controls in §2.2.
   The MVP produces **git diffs and GitOps PR payloads only**. There is no configuration
   under which the Sentinel calls `apply`, `patch`, `delete`, `scale`, or `rollout restart`.
   A future "auto-merge Tier-1 PRs" proposal is a change to *merge policy*, not to the
   Sentinel, and must be evaluated against the same review as any other production change.
3. **Multi-cloud IAM federation.** Reason: the MVP targets a single-node k3s cluster with a
   single in-cluster ServiceAccount. Federating workload identity across cloud providers is a
   distinct platform project with its own threat model; it adds no capability to detection,
   masking, or diff generation.

Additionally out of scope: predictive/ML-based failure forecasting, cost optimization,
multi-cluster fleet management, and natural-language chat interfaces.

---

## 6. Users and Stakeholders

| Role | Interaction | Needs |
|---|---|---|
| On-call SRE | War-Room dispatch, RCA | Evidence, scope, and a clear "do not apply blindly" signal |
| Platform engineer | GitOps PR | A minimal, reviewable, `git apply`-able diff with intent explained |
| Security / compliance reviewer | Masking audit, RBAC review | Provable masking before egress; read-only credentials |
| Platform owner | Milestone sign-off | Objective, executable acceptance criteria |

---

## 7. Assumptions and Constraints

- **A1** Cluster target is single-node k3s; image import targets the internal containerd
  namespace (`k3s ctr images import`).
  - **Environment of record (measured 2026-10-01).** The development host is **WSL2 on
    an ARM64 Windows host, `Fedora Linux 44 (aarch64)`**, kernel
    `6.18.40.1-microsoft-standard-WSL2`, systemd as PID 1. Local k3s is
    **v1.36.4+k3s1**, node `dwindle2` (`control-plane`, Ready, containerd
    `2.3.4-k3s1.36`, internal IP `172.30.181.188`; 10 CPU, ~7.5Gi memory, 110 pods
    allocatable). Docker is **29.8.2**, storage driver `overlayfs`, root
    `/var/lib/docker`, unit `docker` active.
  - **Images must target `linux/arm64`.** The host is `aarch64`; CI builds `amd64`. A
    locally built SREK3S image and a CI-built one are not the same artifact, and the
    architecture has to be stated rather than inferred. `busybox:1.36.1`, which the
    `deploy/chaos/` fixtures pin, publishes an `arm64` manifest, so the chaos
    fixtures are usable on this host without a multi-arch build;
    **no `registry.internal/srek3s-*` image exists anywhere yet**,
    and both must be built locally and registered into the `k8s.io` containerd
    namespace under their exact fully-qualified names
    (`registry.internal/srek3s-agent:0.1.0`, `registry.internal/srek3s-sentinel:0.1.0`)
    or the pods report `ImagePullBackOff`. The `deploy/chaos/` fixtures use
    `imagePullPolicy: Never`, which turns a missing image into a hard apply failure
    rather than a silent pull.
  - **`sudo` is required for every `kubectl` and every `docker` call**, for two unrelated
    reasons: the kubeconfig `/etc/rancher/k3s/k3s.yaml` is mode `0600` and root-owned,
    and user `duckie` is in `wheel` but not in the `docker` group while
    `/var/run/docker.sock` is `srw-rw---- root:docker`. Neither is a defect in this
    repository; both are prerequisites for anyone reproducing a run here.
  - **k3s version skew against CI.** CI runs **v1.29.9+k3s1**; this host runs
    **v1.36.4+k3s1**. `deploy/namespace.yaml` sets
    `pod-security.kubernetes.io/enforce-version: latest`, so Pod Security Admission is
    evaluated against **1.36** here and against whatever `latest` resolves to on the CI
    node. The same manifests can therefore be admitted in one place and refused in the
    other for a reason unrelated to the code, and that must be diagnosed as a skew
    before being diagnosed as a defect.
  - **No NetworkPolicy controller pod is observable in `kube-system`.** k3s runs its
    kube-router netpol controller embedded in the `k3s server` process rather than as a
    separate pod, so the absence of a `kube-router` pod is **not** evidence that
    NetworkPolicy is unenforced. Both policies in `deploy/`
    (`srek3s-sentinel`, `srek3s-agent-egress`) are *expected* to be enforced on k3s.
    That expectation is **unverified on this host** and is recorded as such rather than
    as a guarantee.
  - **Cluster state as of 2026-10-01:** namespaces are `default`, `kube-node-lease`,
    `kube-public`, `kube-system`; **none carries Pod Security Admission labels**, and
    `srek3s-system` **does not exist yet**. Nothing from `deploy/` is applied. The
    `k8s.io` containerd namespace holds only k3s's own images (coredns, traefik,
    metrics-server, local-path-provisioner, klipper-helm, klipper-lb, pause).
- **A2** Sentinel runs as Go 1.23+ using official `k8s.io/client-go`, `k8s.io/api`,
  `k8s.io/apimachinery`. Standard library first; no unvetted third-party runtime frameworks.
  - **Local toolchain:** native `golang.aarch64` reporting `go version go1.26.8-X:nodwarf5 linux/arm64`,
    which satisfies `go.mod`'s `go 1.23`. A Windows Go exists at
    `/mnt/c/Program Files/Go/bin/go.exe`; the Linux path precedes `/mnt/c` in `PATH`, so
    the native toolchain wins. This is the **first `linux/aarch64` host** for this
    project, which is why the `-race` note in `AGENTS.MD` §4 is amended.
    **Assert on `go version` containing `linux/arm64`, not on the resolved path:** this host
    resolves `go` to `/usr/sbin/go`, and `/usr/sbin`, `/usr/bin`, `/sbin` and `/bin` are all
    the same inode here (`/usr/sbin -> bin`), so a check hardcoding `/usr/bin/go` fails
    spuriously on a correctly installed toolchain.
- **A3** Analysis engine is Python 3.11-slim, Pydantic v2 + FastAPI, CPU-only inference
  (`fastembed` / `onnxruntime`). **No PyTorch, no CUDA, no GPU-dependent dependency.**
  - **Correction, stated because the sentence above overstates what runs.** `fastembed`
    and `onnxruntime` are named only in a **comment** in `agent/requirements.txt` and are
    **installed nowhere**; the dependency ban is a real, CI-asserted ceiling, and the
    "CPU-only inference" it guards is the *permitted* future shape, not a live path. See
    §3.2's "No model client".
  - **Interpreter of record:** CPython **3.11.16**. The system default `python3` on the
    `Fedora 44` host is **3.14.3** and is **not acceptable** for any gate: AGENTS §2
    forbids 3.12+ syntax, `agent/pyproject.toml` pins `target-version = ["py311"]`, and
    root `setup.cfg` sets `python_version = 3.11`. The supported environment is the
    virtualenv at `~/SREK3S/.venv311`; every Python gate runs as
    `~/SREK3S/.venv311/bin/python -m <tool>`.
- **A4** Every container runs as non-root `UID 10001` / `GID 10001`, with
  `readOnlyRootFilesystem: true` and `cap_drop: ["ALL"]`.
- **A5** Every blocking operation is bounded by a `context.Context` with an explicit timeout;
  no unbounded goroutines and no unbuffered job channels.
- **A6** **The Sentinel's watch scope and its grant must agree.** `deploy/sentinel.yaml`
  sets `WATCH_NAMESPACE: ""`, which selects a cluster-wide informer and issues
  `LIST /api/v1/pods` against every namespace, while `deploy/rbac.yaml` grants only a
  namespaced `Role` in `srek3s-system` — no `ClusterRole`, no `ClusterRoleBinding`. As
  committed these two are **inconsistent**, and the resulting failure is a cluster-wide
  `LIST` that is unauthorised. The visible symptom is silence: the informer retries the
  forbidden `LIST` and nothing is reported, which is indistinguishable from a healthy
  cluster watching nothing. Any in-cluster run must therefore set `WATCH_NAMESPACE` to a
  specific namespace **and** apply a matching `Role` + `RoleBinding` into that namespace,
  referring to the `srek3s-system` ServiceAccount; the procedure is in `docs/runbook.md`
  §1. Found by static analysis of the two manifests on 2026-10-01 and **not yet
  reproduced at runtime** — see `docs/lessons-learned.md` and the open task in
  `ROADMAP.md`. A6 is a constraint on any future configuration, not a description of a
  working default.
- **A7** **A Tier-1 remediation requires a readable GitOps checkout.** The agent may only
  emit a patch for a manifest it can read and validate; `SREK3S_MANIFEST_ROOT` must point
  at a real checkout and `SREK3S_TARGET_MANIFEST` at a path inside it. Absent either, the
  system fails closed to Tier-2 (see F3). This is a deployment precondition, not a
  fallback.

---

## 8. Acceptance Criteria

Each criterion is objective and executable. A criterion is met only when its verification
command exits `0`.

### AC-1 — Deterministic OOM detection within 2 seconds

> Given a container terminated with `OOMKilled`, the Sentinel must produce a complete,
> schema-valid Incident Payload **within 2 seconds (p99)** of observing the terminal
> container state.

- Measured with `time.perf_counter()` (monotonic), never wall-clock.
- "Complete" means: all mandatory contract fields populated and valid against the Incident
  Payload schema — no empty `incident_id`, `pod_name`, `container_name`, `exit_code`, or
  `reason`.
- Verification: a timing harness running the detection path over the synthetic chaos corpus
  asserts `p99(elapsed) <= 2.0s` and `detections == injected_OOM_events`.
- Failure to meet this is a hard fail: a remediation loop slower than the failure it is
  mitigating is not a mitigation.

### AC-2 — 100% masking of sample API tokens

> Zero occurrences of any credential from the fixture corpus may appear in any emitted
> payload.

- Fixture corpus: `tests/fixtures/secrets_corpus.txt` containing at least one sample for each
  rule in the masking manifest (AWS access key ID, AWS secret access key, bearer token, JWT,
  PEM private key block, generic `key=value` secret, IPv4 address, UUID).
- Verification: unit test asserts (a) `100%` of corpus lines contain `[REDACTED]` after
  scrubbing, (b) a substring scan for every known plaintext secret returns **zero** matches,
  and (c) idempotence — scrubbing twice equals scrubbing once.
- This criterion is checked against **every** egress path, not only the primary one.

### AC-3 — Valid unified `git diff` generation

> For a Tier-1 incident, the emitted `git_patch` must be a valid unified diff that applies
  cleanly to the source manifest.

- Verification: `git apply --check --whitespace=nowarn` against the fixture manifest exits `0`,
  and `git apply` followed by a YAML parse yields a manifest whose change matches the stated
  root cause (e.g. the memory limit actually increased).
- Additional constraints: diff headers present (`---`, `+++`, `@@`), no absolute paths, no
  binary hunks, and `classification` consistent with the tier (Tier-2 must emit an empty patch).
- A patch that does not apply is worse than no patch — it manufactures false confidence during
  an incident. It is a hard fail.
- **Reachability caveat.** AC-3 is satisfied by the offline fixture and golden-file path
  (`tests/fixtures/expected/`, recorded in `ROADMAP.md` box `4.4.1`). It is **not**
  satisfiable by the in-cluster deployment as committed, because `SREK3S_MANIFEST_ROOT`
  is an `emptyDir` and the default target `deploy/payments/checkout-api.yaml` does not exist
  in this repository (F3, A7). A run of `deploy/` that produced only Tier-2 responses has
  **not** failed AC-3 — it has failed to test it.

### AC-4 — Clean non-root container execution

> Every container must run unprivileged with a read-only root filesystem.

- Verification: both `deploy/` manifests are asserted (in CI, by a test that parses the YAML)
  to specify `runAsUser: 10001`, `runAsGroup: 10001`, `runAsNonRoot: true`,
  `readOnlyRootFilesystem: true`, `allowPrivilegeEscalation: false`,
  `capabilities.drop: ["ALL"]`, and `seccompProfile.type: RuntimeDefault`.
- Runtime check: `kubectl exec` reports `id -u` = `10001`; no write occurs to `/`.
- Additionally: the in-cluster `ServiceAccount` is asserted to hold **no** mutating verb.
- **Read grants are an acceptance concern too, not only write absence.** Asserting that no
  mutating verb is held passes trivially when the grant is too narrow to watch anything.
  The paired checks are therefore both required: `TestSentinelRoleGrantsWhatTheWatcherReads`
  (converse: an allow-list for writes would pass the deny-check while granting nothing) and
  a live `kubectl auth can-i list pods` against the namespace the Sentinel is actually
  scoped to. See A6: a Sentinel authorised for `srek3s-system` and configured with
  `WATCH_NAMESPACE: ""` satisfies every verb check in this repository and still reports
  nothing.

---

## 9. Success Metrics

| Metric | MVP Target |
|---|---|
| Detection latency (p99, `OOMKilled`) | ≤ 2s |
| Unmasked secrets in egress | 0 |
| Tier-1 patch validity (`git apply --check`) | 100% |
| Tier-2 escalations that produced a patch | 0 |
| Cluster write verbs held by Sentinel | 0 |
| Non-compliant containers | 0 |

---

## 10. Risks

| ID | Risk | Mitigation |
|---|---|---|
| R1 | Over-eager masking destroys diagnostic signal (e.g. IPs masked, debugging impossible) | Rule set is ordered and reviewable; masking is span-scoped; corpus tests assert both masking **and** preservation of surrounding context |
| R2 | LLM emits invalid or non-applying patches under incident pressure | Strict Pydantic-constrained decoding; `git_patch` validated by apply-check before emission; invalid ⇒ Tier-2 downgrade, never silent pass-through |
| R3 | Incomplete observability (no events, empty logs) leads to speculative RCA | Schema requires explicit presence; missing evidence downgrades confidence and forces Tier-2 |
| R4 | Remediating toil while hiding an architectural fault | Post-remediation verification loop; recurrence promotes the incident to Tier-2 |
| R5 | Unbounded goroutine / channel growth under event storm | Fixed worker pool, buffered job channel, context-bounded sends (AGENTS §3.2) |
| R6 | Watch scope and RBAC grant disagree, so the Sentinel is silently blind (A6) | `WATCH_NAMESPACE` must name a namespace the `Role` covers, and a `Role` + `RoleBinding` must exist there; `docs/runbook.md` §1 gives the procedure and the `kubectl auth can-i` confirmation. **Not yet fixed in the committed manifests** — the pair is inconsistent today, found by static analysis and not yet reproduced at runtime. |
| R7 | An unwired component is mistaken for a working one — `verify.py` is fully implemented and heavily tested but unreachable from the service, and `agent/llm.py` reads as a model client while being a validation boundary | Named explicitly in `ARCHITECTURE.md` §5.5, `AGENTS.MD` §2, `PRD.md` §3.2 and `README.md`, and carried as open tasks in `ROADMAP.md`. Coverage of a module is not evidence that the module runs; a scaffold that imports nothing and is imported by nothing will pass every gate that only runs its tests. |
| R8 | Environment-specific claims get copied between hosts — `arm64` images and `amd64` fixtures, k3s 1.36 locally against 1.29 in CI, a `sudo`-scoped kubeconfig, a `docker` group membership that does not exist | Environment of record pinned in §7 A1-A3 and `AGENTS.MD` §2; each divergence is named where it bites (`README.md`, `docs/runbook.md`, `docs/offline-install.md`) rather than left for the next reader to rediscover. |

---

## 11. Traceability

| Requirement | Architecture section | Roadmap milestone |
|---|---|---|
| F1 masking, AC-2 | §5 Secret Masking Regex Manifest | M1 |
| F3 graduated autonomy, AC-3 | §4 Incident & RCA Contracts | M2 |
| G1 detection, AC-1 | §3 Data Flow | M3 |
| F2 sandbox, AC-4 | §7 Container Hardening | M2, M4 |
| F4 verification loop — **specified, not reachable** (§3.2) | §4 RCA Contract (`verification_policy`); §5.5 Known MVP Boundaries | M4; wiring open in the environment section |
| §5 Out of scope (no writes) | §2 Component Boundary | M3, M4 |
| A6 scope/grant agreement — **inconsistent as committed** | §2 Component Boundary and Least Privilege | Open in the environment section |
| A1-A3 environment of record | §9 Technology Constraints (Binding) | Open in the environment section |
