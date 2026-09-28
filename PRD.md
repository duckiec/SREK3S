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
- **A2** Sentinel runs as Go 1.23+ using official `k8s.io/client-go`, `k8s.io/api`,
  `k8s.io/apimachinery`. Standard library first; no unvetted third-party runtime frameworks.
- **A3** Analysis engine is Python 3.11-slim, Pydantic v2 + FastAPI, CPU-only inference
  (`fastembed` / `onnxruntime`). **No PyTorch, no CUDA, no GPU-dependent dependency.**
- **A4** Every container runs as non-root `UID 10001` / `GID 10001`, with
  `readOnlyRootFilesystem: true` and `cap_drop: ["ALL"]`.
- **A5** Every blocking operation is bounded by a `context.Context` with an explicit timeout;
  no unbounded goroutines and no unbuffered job channels.

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

### AC-4 — Clean non-root container execution

> Every container must run unprivileged with a read-only root filesystem.

- Verification: both `deploy/` manifests are asserted (in CI, by a test that parses the YAML)
  to specify `runAsUser: 10001`, `runAsGroup: 10001`, `runAsNonRoot: true`,
  `readOnlyRootFilesystem: true`, `allowPrivilegeEscalation: false`,
  `capabilities.drop: ["ALL"]`, and `seccompProfile.type: RuntimeDefault`.
- Runtime check: `kubectl exec` reports `id -u` = `10001`; no write occurs to `/`.
- Additionally: the in-cluster `ServiceAccount` is asserted to hold **no** mutating verb.

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

---

## 11. Traceability

| Requirement | Architecture section | Roadmap milestone |
|---|---|---|
| F1 masking, AC-2 | §5 Secret Masking Regex Manifest | M1 |
| F3 graduated autonomy, AC-3 | §4 Incident & RCA Contracts | M2 |
| G1 detection, AC-1 | §3 Data Flow | M3 |
| F2 sandbox, AC-4 | §7 Container Hardening | M2, M4 |
| F4 verification loop | §4 RCA Contract (`verification_policy`) | M4 |
| §5 Out of scope (no writes) | §2 Component Boundary | M3, M4 |
