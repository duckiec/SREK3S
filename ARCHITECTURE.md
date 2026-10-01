# ARCHITECTURE — Autonomous Reliability Firewall & Incident Sentinel

| Field | Value |
|---|---|
| Document ID | `ARCH-0001` |
| Version | `0.1.0` |
| Status | Draft — **single source of truth for schemas and layout** |
| Requirement source | `PRD.md` |
| Delivery plan | `ROADMAP.md` |
| Defect history | `docs/lessons-learned.md` |
| Engineering rationale | [`ENGINEERING.md`](ENGINEERING.md) |

> Per AGENTS.md §5, this document is the single source of truth for schemas and directory
> layout. Changes here require an explicit decision; roadmap tasks must not invent new
> layouts or field names.

> **Reading order.** This document says *what* the system is. [`ENGINEERING.md`](ENGINEERING.md)
> says *why*, and is written for the maintainer who arrives later and cannot tell whether a
> tempting simplification is safe — including the boundaries that look like friction and the
> test methodology that produced them.

---

## 1. System Overview

```
┌─────────────────────────── k3s node (single) ────────────────────────────┐
│                                                                          │
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │  cmd/sentinel  (Go 1.23+, read-only ServiceAccount)               │  │
│  │                                                                    │  │
│  │   internal/k8s ──► Watcher (Informers: pods, events)               │  │
│  │        │             · defensive pointer handling                  │  │
│  │        │             · OOMKilled / CrashLoopBackOff detection      │  │
│  │        ▼                                                           │  │
│  │   internal/scrubber ──► deterministic regex masking (IN MEMORY)    │  │
│  │        │             · no disk, no plaintext retention            │  │
│  │        ▼                                                           │  │
│  │   internal/emitter ──► POST incident JSON (ctx-bounded)            │  │
│  └──────────────────────────────┬─────────────────────────────────────┘  │
│                                 │ HTTPS (scrubbed payload only)         │
│  ┌──────────────────────────────▼─────────────────────────────────────┐  │
│  │  agent/  (Python 3.11-slim, FastAPI, Pydantic v2, CPU-only)      │  │
│  │                                                                    │  │
│  │   validate IncidentPayload ──► classify TIER_1 | TIER_2           │  │
│  │        │                                                           │  │
│  │        ▼  (constrained decoding; freeform ⇒ fatal)                │  │
│  │   ephemeral sandbox (256Mi / 500m, monotonic deadline)            │  │
│  │        │                                                           │  │
│  │        ▼                                                           │  │
│  │   build RCA + unified git diff ──► validate `git apply --check`    │  │
│  └──────────────────────────────┬─────────────────────────────────────┘  │
│                                 │                                        │
│                     ┌───────────┴───────────┐                            │
│                     ▼                       ▼                            │
│        GitOps PR (Tier 1)            War-Room dispatch (Tier 2)          │
│                     │                       │                            │
│                     └──► re-observe ──► verification verdict ──┘         │
│  ══════════════════════════════════════════════════════════════════════  │
│  TRUST BOUNDARY: no component inside this box may mutate cluster state.  │
└──────────────────────────────────────────────────────────────────────────┘
```

**The boundary is the design.** The analysis engine has no `kubeconfig`, no ServiceAccount
token, and no RBAC role of its own. Its only egress is one HTTP POST to the Sentinel, and its
only output is text. Structural absence of a credential is the control — not a policy check.

**Watch scope is part of the boundary, and it is currently inconsistent.** The box above
draws a cluster. What the Sentinel actually watches is set by `WATCH_NAMESPACE`, and what it
is *permitted* to watch is set by `deploy/rbac.yaml`. Those two must agree, and **as
committed they do not** — see §2.1, which is a documented defect rather than a design note.

---

## 2. Component Boundary and Least Privilege

| Component | Cluster credential | Allowed verbs |
|---|---|---|
| `cmd/sentinel` | in-cluster ServiceAccount | `get`, `list`, `watch` on `pods`, `events`, `deployments`, `replicasets` |
| `agent/` | **none** | n/a |
| War-Room dispatcher | **none** | n/a |

No mutating verb (`create`, `update`, `patch`, `delete`, `deletecollection`) appears in any
`Role` under `deploy/`. This is asserted by a test that parses the manifests (PRD AC-4).

### 2.1 Scope and grant must agree — open defect

**This section documents an inconsistency in the committed manifests, found by static
analysis on 2026-10-01 and not yet reproduced at runtime.** It is recorded here rather than
fixed, because `WATCH_NAMESPACE` and the `Role` are both correct in isolation and the defect
is in the pairing; fixing either one alone is a judgement call that belongs with the open
`ROADMAP.md` task, not with a documentation edit.

| Where | What it sets |
|---|---|
| `deploy/sentinel.yaml` → `env: WATCH_NAMESPACE: ""` | Watch **all namespaces**. An empty value is the sentinel for "do not scope", and it selects a cluster-wide informer factory, whose initial `LIST` is `GET /api/v1/pods` against every namespace. |
| `deploy/rbac.yaml` | A **namespaced `Role`** in `srek3s-system`. No `ClusterRole`. No `ClusterRoleBinding`. Nothing anywhere in `deploy/` grants a cluster-scoped read. |

The consequence is exact: the cluster-wide `LIST` is **unauthorised**. The informer retries
the forbidden `LIST` on its backoff, and the observable result is **no incidents and no
error** — the process starts cleanly, logs a startup line, and reports a quiet cluster. That
is indistinguishable, from the outside, from a healthy Sentinel watching a namespace that
happens to have nothing wrong in it.

Three properties make it worth naming rather than fixing quietly:

1. **Every gate in this repository still passes.** `TestSentinelRoleGrantsNoMutatingVerb`
   asserts the Role has no write verb — true. The sibling check
   `TestSentinelRoleGrantsWhatTheWatcherReads` asserts the Role grants the reads the
   watcher *would* make — also true, for `srek3s-system`. Both assertions are scoped to the
   namespace the Role lives in; neither compares that namespace against the value of
   `WATCH_NAMESPACE`. A pair of individually-correct checks over a pair of individually-
   correct manifests, whose composition is wrong.
2. **The fix is not "add a `ClusterRole`."** That is the single highest-severity change
   available to this codebase (PRD §5.2, runbook §1) and it would make the RBAC tests pass
   in a way that widens blast radius rather than restoring function.
3. **The correct fix is two-sided**: set `WATCH_NAMESPACE` to a specific namespace *and*
   place a matching `Role` + `RoleBinding` in that namespace, referring to the ServiceAccount
   in `srek3s-system`. The procedure and its `kubectl auth can-i` confirmation are in
   `docs/runbook.md` §1, "RBAC is namespace-scoped, and that is deliberate". One Role per
   namespace is the intended shape, not a workaround.

**What an operator should expect until this is resolved.** A Sentinel applied from
`deploy/` as committed reports nothing and logs nothing that says why. The startup line
naming `watch_namespace` is the cheapest diagnostic that exists — read it before
concluding the cluster is quiet (`docs/runbook.md` §2).

---

## 3. Directory Layout

```
SREK3S/
├── AGENTS.md                     # engineering guardrails (authoritative)
├── PRD.md                        # requirements + acceptance criteria
├── ARCHITECTURE.md               # THIS FILE — schemas + layout (single source of truth)
├── ENGINEERING.md                # WHY it is built this way; for people changing it
├── ROADMAP.md                    # 4 sequential milestones
├── Makefile                      # make doctor / bootstrap / test / build / deploy
│
├── .github/workflows/
│   ├── ci.yaml                   # G1-G6 + container smoke + multi-arch dry run
│   ├── release.yaml              # tag-gated GHCR publish, linux/amd64 + linux/arm64
│   └── e2e-detonation.yaml       # live-cluster detonation
│
├── cmd/
│   └── sentinel/                 # Go entrypoint; wiring, flags, signal handling
│       ├── main.go
│       └── Dockerfile          # distroless/static image; CGO off, UID 10001
│
├── internal/
│   ├── scrubber/                 # DETERMINISTIC SECRET/PII MASKING ENGINE
│   │   ├── scrubber.go           # rule pipeline, ordering, idempotence
│   │   ├── manifest.go           # compiled-once rule set + rule IDs
│   │   ├── account.go            # redaction accounting (counts, no plaintext)
│   │   └── scrubber_test.go
│   │
│   ├── k8s/                      # READ-ONLY CLUSTER OBSERVABILITY
│   │   ├── client.go             # client-go config; read-only clientset
│   │   ├── watcher.go            # Informers: pods + events, resync policy
│   │   ├── readonly.go           # read-only clientset wrapper; Get/List/Watch only
│   │   ├── telemetry.go          # log + event extraction; PreviousLogsFor
│   │   ├── guard.go              # defensive pointer helpers (nil-safe accessors)
│   │   └── *_test.go
│   │
│   ├── deploy/                   # MANIFEST HARDENING TESTS (test-only package)
│   │   └── *_test.go           # rbac_hardening_test.go, manifests_test.go
│   ├── worker/                   # BOUNDED CONCURRENCY
│   │   └── pool.go               # fixed-size pool; sends selected against ctx.Done()
│   └── emitter/                  # EGRESS BOUNDARY
│       ├── emitter.go            # ctx-bounded HTTP POST to agent
│       ├── payload.go            # Go-side IncidentPayload structs (wire types)
│       ├── ulid.go               # ULID incident-id generation (Contract A 4.1)
│       ├── validate.go           # wire-payload validation; invariants I-A2, I-A3
│       └── emitter_test.go
│
├── agent/                        # PYTHON ANALYSIS ENGINE (FastAPI + Pydantic v2)
│   ├── main.py                   # FastAPI app factory; lifespan; hardening
│   ├── models.py                 # ★ SCHEMA SOURCE OF TRUTH (Pydantic v2)
│   ├── classifier.py             # deterministic tier routing
│   ├── llm.py                    # constrained-decoding client
│   ├── patch.py                  # unified diff synthesis + apply-check validation
│   ├── sandbox.py                # ephemeral worker, cgroup budget, monotonic deadline
│   ├── warroom.py                # Tier-2 dispatch payload
│   ├── verify.py                 # post-remediation health verification loop
│   ├── rescan.py                 # outbound secret re-scan; invariant I-B6
│   ├── prompt.py                 # constrained-decoding prompt + RCA rationale
│   ├── budget.py                 # active-job budget; HTTP 429 sandbox_busy
│   ├── sandbox_worker.py         # disposable analysis worker entrypoint
│   ├── triage.py                 # HTTP surface: classify, route, remediate
│   ├── pyproject.toml
│   ├── requirements.txt          # no torch, no cuda, no gpu extras (asserted in CI)
│   └── tests/                    # pytest suite; includes the layout validator
│
├── deploy/                       # k3s MANIFESTS
│   ├── namespace.yaml
│   ├── rbac.yaml                 # read-only Role + RoleBinding (no mutating verbs)
│   ├── sentinel.yaml             # Go daemon: 10001/10001, RO rootfs, cap_drop ALL
│   ├── agent.yaml                # FastAPI: same hardening
│   ├── service.yaml              # agent ClusterIP; target of SREK3S_AGENT_URL
│   ├── kustomization.yaml
│   └── chaos/                    # deliberate-failure fixtures
│       ├── oom-leak.yaml        # allocates past its cgroup limit
│       ├── crashloop.yaml       # exits non-zero in a loop
│       └── real-crash.yaml      # a REAL app: traceback + planted credential
│
├── scripts/
│   ├── audit_workflow.py         # audits the CI definition itself
│   └── bootstrap.sh              # host pre-flight; `make doctor`
│
│
└── tests/
    ├── benchmarks/         # load generation for the saturation gates
    ├── e2e/                # detonation harness: runner, capture proxy, in-cluster overlay
        ├── capture_proxy.py          # stdlib-only wire instrument; Sentinel to agent
        ├── runner.py                 # samples the lifecycle; asserts ROADMAP 4.2.x
        ├── fixtures/                 # E2E fixtures; the incluster/ subdir is the deploy overlay
            └── incluster/          # overlay: deploy/ base, capture proxy, probe
    └── fixtures/
        ├── incident_corpus.json      # AC-2 masking corpus (8 rule groups, 32 maskable cases)
        ├── sample-incident.json      # canonical valid Incident Payload
        ├── oom-restartloop.yaml      # manifest an OOM diff must patch
        └── expected/                 # golden outputs (RCA + diff) for regression
            └── oom-expected.patch
            └── oom-expected-rca.md
```

### 3.1 Layout Rules

- `internal/` is **not** importable outside the module; it enforces the Sentinel's internal
  boundary.
- `agent/models.py` and this document's §4/§5 must agree. `tests/fixtures/sample-incident.json`
  is validated against `models.py` in CI, so drift fails the build rather than production.
- `deploy/` contains **no** mutating RBAC. `deploy/chaos/` contains deliberately broken
  workloads, scoped to a disposable namespace, and must never be applied outside Milestone 4.

---

## 4. Contract A — Incident Payload (Go → Python)

Transport: `POST /v1/incidents`, `Content-Type: application/json`.
Producer: `internal/emitter`. Consumer: `agent` (`models.py`).

**Guarantee:** every string field in `scrubbed_logs` and `cluster_events` has passed through
`internal/scrubber` before serialization. The emitter physically cannot emit an unsanitized
string field; there is no flag to disable scrubbing.

```json
{
  "schema_version": "1.0.0",
  "incident_id": "inc_01HQ8S7G3M2K9X4B6D0F1R5TJA",
  "timestamp": "2026-09-28T14:32:07.481Z",
  "namespace": "payments",
  "pod_name": "checkout-api-7d9f4b6c8d-x2k9p",
  "container_name": "checkout-api",
  "exit_code": 137,
  "reason": "OOMKilled",
  "resource_limits": {
    "cpu_limit": "500m",
    "cpu_request": "250m",
    "memory_limit": "256Mi",
    "memory_request": "128Mi",
    "memory_working_set_bytes": 268435456
  },
  "restart_count": 4,
  "previous_reason": "Completed",
  "scrubbed_logs": [
    "ts=2026-09-28T14:32:07.412Z level=error msg=\"alloc failure\" pod=10.42.3.19 conn=10.42.0.7:5432",
    "ts=2026-09-28T14:32:07.419Z level=warn msg=\"retrying upstream\" request_id=8f14e45f-ceea-467a-9d9e-1f2b3c4d5e6f auth=Bearer [REDACTED]"
  ],
  "cluster_events": [
    {
      "type": "Warning",
      "reason": "OOMKilled",
      "message": "Container checkout-api was OOMKilled (exit code 137).",
      "count": 4,
      "first_timestamp": "2026-09-28T14:28:11.002Z",
      "last_timestamp": "2026-09-28T14:32:07.470Z",
      "involved_object": "pod/checkout-api-7d9f4b6c8d-x2k9p"
    }
  ],
  "redaction_report": {
    "total_redactions": 3,
    "rules_triggered": ["aws_access_key_id", "bearer_token", "ipv4_address"]
  },
  "detection_latency_ms": 412,
  "sentinel_version": "0.1.0"
}
```

### 4.1 Field Specification

| Field | Type | Required | Nullability | Producer rule |
|---|---|---|---|---|
| `schema_version` | string `semver` | yes | never | pinned; bumped only on breaking change |
| `incident_id` | string | yes | never | Sentinel-generated, prefixed `inc_`, unique per incident |
| `timestamp` | string RFC3339 UTC | yes | never | RFC3339 with milliseconds, `Z` suffix |
| `namespace` | string | yes | never | from `pod.Namespace` |
| `pod_name` | string | yes | never | from `pod.Name` |
| `container_name` | string | yes | never | from `status.ContainerStatuses[i].Name` |
| `exit_code` | integer | yes | **nullable** | `state.Terminated.ExitCode`; `null` for `CrashLoopBackOff` (not yet terminated) |
| `reason` | enum | yes | never | `OOMKilled` \| `CrashLoopBackOff` |
| `resource_limits.cpu_limit` | string \| null | yes | nullable | quantity `String()`; `null` if limits nil |
| `resource_limits.cpu_request` | string \| null | yes | nullable | as above |
| `resource_limits.memory_limit` | string \| null | yes | nullable | as above |
| `resource_limits.memory_request` | string \| null | yes | nullable | as above |
| `resource_limits.memory_working_set_bytes` | integer \| null | no | nullable | `null` when the status field is nil |
| `restart_count` | integer ≥ 0 | yes | never | `ContainerStatuses[i].RestartCount` |
| `previous_reason` | string | no | nullable | prior `Terminated.Reason`, for OOM-after-thrash detection |
| `scrubbed_logs` | string[] | yes | never | **always masked**; `[]` is legal but flagged low-evidence |
| `cluster_events` | Event[] | yes | never | matched by `involvedObject.uid`; each `message` masked |
| `redaction_report` | RedactionReport | yes | never | counts only; **never** the masked values |
| `detection_latency_ms` | integer ≥ 0 | yes | never | measured with monotonic clock |
| `sentinel_version` | string | yes | never | build-stamped |

| `cluster_events[]` field | Type | Required | Notes |
|---|---|---|---|
| `type` | string | yes | `Normal` \| `Warning` |
| `reason` | string | yes | e.g. `OOMKilled`, `BackOff` |
| `message` | string | yes | masked |
| `count` | integer ≥ 0 | yes | event repeat count |
| `first_timestamp` / `last_timestamp` | string \| null | yes | null when the API omits them |
| `involved_object` | string | yes | `kind/name` |

### 4.2 Invariants (CI-asserted)

1. **I-A1** No value under `scrubbed_logs` or `cluster_events[].message` contains any
   plaintext secret from `tests/fixtures/incident_corpus.json`.
2. **I-A2** If `reason == "OOMKilled"` then `exit_code == 137` and `resource_limits.memory_limit`
   is non-null.
3. **I-A3** If `reason == "CrashLoopBackOff"` then `exit_code` may be `null` but
   `restart_count >= 1`.
4. **I-A4** `detection_latency_ms <= 2000` (PRD AC-1).
5. **I-A5** Scrubbing is idempotent: `scrub(scrub(x)) == scrub(x)`.

### 4.3 Error Responses

| Status | Body | Meaning |
|---|---|---|
| `422` | Pydantic validation errors | schema violation — the incident is **not** retried |
| `400` | `{"error":"malformed_json"}` | unparseable body |
| `429` | `{"error":"sandbox_busy"}` | ephemeral sandbox at budget; Sentinel retries with jitter |
| `500` | `{"error":"analysis_failed"}` | non-recoverable; incident is escalated to Tier-2 War-Room |

A `422` is fatal for that payload and must not be silently coerced into a Tier-2 dispatch —
it indicates contract drift, which is a build defect.

---

## 5. Contract B — RCA & Remediation (Python → Downstream)

Producer: `agent` (`models.py`). Consumers: GitOps PR pipeline, War-Room dispatcher,
verification loop.

```json
{
  "schema_version": "1.0.0",
  "incident_id": "inc_01HQ8S7G3M2K9X4B6D0F1R5TJA",
  "classification": "RESOURCE_EXHAUSTION",
  "severity": "SEV3",
  "confidence": 0.91,
  "blast_radius_tier": "TIER_1_TOIL",
  "root_cause": {
    "summary": "The checkout-api container exceeded its 256Mi memory limit while holding an unbounded in-memory response buffer; the kernel OOM-killed it with exit code 137 on restart 4 of 4.",
    "evidence": [
      "reason=OOMKilled with exit_code=137",
      "memory_working_set_bytes (268435456) equals memory_limit (256Mi)",
      "prior termination reason was Completed, isolating the fault to steady-state allocation"
    ],
    "affected_scope": {
      "namespace": "payments",
      "pods": ["checkout-api-7d9f4b6c8d-x2k9p"],
      "replicas_affected": 1,
      "replicas_total": 3,
      "sibling_containers_healthy": true
    }
  },
  "remediation": {
    "summary": "Raise the checkout-api memory limit from 256Mi to 512Mi; no code or image change required.",
    "risk_level": "LOW",
    "target_manifest": "deploy/payments/checkout-api.yaml",
    "git_patch": "diff --git a/deploy/payments/checkout-api.yaml b/deploy/payments/checkout-api.yaml\nindex 3f1a2b4..9c8d7e6 100644\n--- a/deploy/payments/checkout-api.yaml\n+++ b/deploy/payments/checkout-api.yaml\n@@ -21,7 +21,7 @@ spec:\n             resources:\n               limits:\n-                memory: \"256Mi\"\n+                memory: \"512Mi\"\n",
    "patch_validated": true
  },
  "verification_policy": {
    "mode": "POST_REMEDIATION_OBSERVATION",
    "watch_duration_seconds": 300,
    "success_criteria": {
      "no_oomkilled_terminations": true,
      "no_crashloopbackoff_wait": true,
      "container_uptime_seconds_min": 240
    },
    "on_success": "CLOSE_INCIDENT",
    "on_repeat_failure": "PROMOTE_TO_TIER_2",
    "on_indeterminate": "REQUEUE_BOUNDED",
    "max_requeue_attempts": 3
  },
  "rca_markdown": "## RCA: checkout-api OOMKilled\n\n**Root cause:** ...",
  "analysis_latency_ms": 1830,
  "agent_version": "0.1.0"
}
```

### 5.1 Field Specification

| Field | Type | Required | Constraint |
|---|---|---|---|
| `schema_version` | string `semver` | yes | pinned |
| `incident_id` | string | yes | **must equal** the inbound Incident Payload's `incident_id` |
| `classification` | enum | yes | `RESOURCE_EXHAUSTION` \| `CRASH_LOOP` \| `CONFIGURATION_ERROR` \| `DEPENDENCY_FAILURE` \| `NETWORK_PARTITION` \| `UNKNOWN` |
| `severity` | enum | yes | `SEV1`\|`SEV2`\|`SEV3`\|`SEV4` |
| `confidence` | float `[0.0, 1.0]` | yes | advisory only; **never** used to select the tier |
| `blast_radius_tier` | enum | yes | `TIER_1_TOIL` \| `TIER_2_ARCHITECTURAL` |
| `root_cause.summary` | string (min 20 chars) | yes | concise, non-empty, specific to evidence |
| `root_cause.evidence` | string[] | yes | ≥ 1 item; each traceable to a payload field |
| `root_cause.affected_scope` | object | yes | pod-level scope used for tier routing |
| `remediation.summary` | string | yes | human-readable intent |
| `remediation.risk_level` | enum | yes | `LOW` \| `MEDIUM` \| `HIGH`; `HIGH` forces Tier-2 |
| `remediation.target_manifest` | string | yes | repo-relative path |
| `remediation.git_patch` | string | yes | unified diff; **`""` iff Tier-2** |
| `remediation.patch_validated` | boolean | yes | `true` only after `git apply --check` passes |
| `verification_policy` | object | yes | see §5.2 |
| `rca_markdown` | string | yes | human-readable deliverable #1 |
| `analysis_latency_ms` | integer ≥ 0 | yes | `time.perf_counter()` based |
| `agent_version` | string | yes | build-stamped |

### 5.2 `verification_policy`

| Field | Type | Constraint |
|---|---|---|
| `mode` | enum | `POST_REMEDIATION_OBSERVATION` (Tier-1) \| `TIER_2_WAR_ROOM` (Tier-2) |
| `watch_duration_seconds` | integer | bounded `[60, 1800]`; no unbounded observation |
| `success_criteria.no_oomkilled_terminations` | boolean | must be `true` |
| `success_criteria.no_crashloopbackoff_wait` | boolean | must be `true` |
| `success_criteria.container_uptime_seconds_min` | integer | < `watch_duration_seconds` |
| `on_success` | enum | `CLOSE_INCIDENT` |
| `on_repeat_failure` | enum | `PROMOTE_TO_TIER_2` |
| `on_indeterminate` | enum | `REQUEUE_BOUNDED` |
| `max_requeue_attempts` | integer | ≥ 1; prevents infinite retry loops |

### 5.3 Tier Routing Contract

Tier selection is **deterministic and precedes model consultation for a fix**.

```
TIER_1_TOIL  ⟸  reason == OOMKilled
             AND  restart_count <= policy.max_restarts          (default 5)
             AND  affected_scope.replicas_affected == 1
             AND  sibling_containers_healthy == true
             AND  remedy_shape == MEMORY_LIMIT_RECALIBRATION    (allow-list)
             AND  risk_level != HIGH

TIER_2_ARCHITECTURAL  ⟸  otherwise  (default-deny)
```

Anything not provably Tier-1 is Tier-2 — a **deny-by-default** routing, so a model failure or
a new failure mode degrades to human escalation, never to speculative cluster change.

### 5.4 Invariants (CI-asserted)

1. **I-B1** `blast_radius_tier == "TIER_2_ARCHITECTURAL"` ⇒ `remediation.git_patch == ""` and
   `patch_validated == false`.
2. **I-B2** `patch_validated == true` ⇒ `git apply --check` exits `0` against the target
   manifest.
3. **I-B3** `incident_id` round-trips unchanged from Contract A.
4. **I-B4** Freeform/non-JSON model output is a **fatal** validation failure — no partial or
   best-effort parse, no regex scrape of markdown.
5. **I-B5** Neither contract contains any field capable of expressing a cluster write verb.
6. **I-B6** Every string in the response is passed through the agent-side defensive
   re-scan before serialization (defence in depth: the Go node is the primary control).

### 5.5 Known MVP Boundaries

Recorded here because each is a decision rather than an oversight, and because a
reader who discovers one without this note will re-derive it as a bug.

**Single-Shot Workloads.** Workloads configured with `restartPolicy: Never` (e.g.,
batch Jobs) that terminate non-zero without entering backoff are explicitly out of
scope for the MVP. To protect the deduplication cache against event floods, the
Sentinel drops generic `Terminated` states at the watcher level. Therefore, a
container that exits non-zero and never restarts will not emit an incident.

The mechanism this defends against is concrete, and it was measured rather than
assumed. The dedup key is `<podUID>/<containerName>:<restartCount>` and carries no
failure kind, so for one restart count a crash-looping container produces a
transient `Terminated{exit 1}` and then a `Waiting{CrashLoopBackOff}`. The
transient state claims the key first and the state carrying the evidence is
rejected as a duplicate — the incident is detected and then never reported.
Dropping the un-serialisable state before a record is constructed prevents that.

The cost is the boundary above. A `restartPolicy: Never` container that exits
non-zero is neither an OOM kill nor a backoff, so no record is built and no
incident is emitted. It is invisible to the Sentinel.

**What was rejected, and why.** Two alternatives were considered. Adding
`Terminated` to the Contract A `reason` enum was rejected by ruling: the schema
must not be widened. Mapping `Terminated` to `CrashLoopBackOff` was rejected on
the merits — it would report the kubelet asserting a state the Sentinel has not
observed, and because an OOM assertion is what unlocks a memory-limit diff, it
would also risk emitting a remediation for a fault that did not occur. The
watcher filter is the only option of the three that neither widens the contract
nor asserts an unobserved state.

**The generalisable form.** A filter placed upstream of a cache can protect the
cache and lose evidence at the same time. That is a legitimate trade only when
the lost class is named, scoped and written down — which is the purpose of this
section. An unnamed gap of this shape is indistinguishable from a defect, and
will be reported as one.

**Consequence for §5.2.** `verification_policy` (§5.2) evaluates *long-running*
workloads, because only those produce the `Waiting{CrashLoopBackOff}` /
`OOMKilled` states the criteria are written against. A single-shot Job cannot be
verified by this loop, because it will never emit an incident to verify.

### 5.5.1 The verification loop is implemented, tested, and not wired

**`agent/verify.py` is not reachable from the running HTTP service.** The module is 741
lines, implements §5.2 in full, and is covered by `agent/tests/test_verify.py` and
`agent/tests/test_verification_e2e.py` — including a live-k3s leg recorded in `ROADMAP.md`
box `4.3.4` that applied a real unified diff with `git apply`, synced the workload, and
observed both a `VERIFIED` and an `UNRESOLVED` verdict. Its write-incapability is asserted
twice, statically by `TestZeroWrites` walking the module's AST and at runtime by
`TestRuntimeTripwire` arming a real `sys.addaudithook`.

**And no production module imports it.** `main.py` and `triage.py` do not. `triage.py`
*emits* a `verification_policy` on the wire, and nothing in the service reads that field.
So PRD F4 — "close the loop" — is **specified and unit-verified but not reachable in the
shipped service**.

Recorded here because the failure mode is specific and expensive. A reader meeting
`agent/verify.py` in the §3 tree, a `verification_policy` in the §5.1 field spec, sixty
recorded tests (`ROADMAP.md` box `4.3.2`), and a green terminal validation in
`ROADMAP.md` will conclude the loop runs. Nothing
in this repository contradicts that conclusion, because nothing in this repository asserts
the wiring — there is no test that fails when a module is orphaned. **Coverage of a module is
not evidence that the module is called**, and the only check that would catch it is an
import-graph assertion from the FastAPI app factory, which does not exist and is the obvious
candidate for a post-MVP gate.

Two things this does *not* affect, so they are stated to prevent over-correction:

- **The no-autofix guarantee.** `docs/runbook.md` §5 cites `verify.py` as evidence that the
  agent cannot write to a cluster. That remains true, and is arguably strengthened by the
  module being unwired: a component nothing imports cannot acquire authority.
- **`verification_policy` as a contract field.** §5.1 and §5.2 remain accurate as a
  *schema*. The field is emitted; what is absent is a consumer.

Open task in `ROADMAP.md`. Do not write work that assumes the loop is live.

### 5.5.2 `agent/llm.py` is a validation boundary with an optional Gemini client

`agent/llm.py` owns the boundary a model crosses. **As shipped and as wired on 2026-10-01,
the model is not on the decision path**: the deterministic Tier-1 classifier and the tier
router both run ahead of any model consultation (§5.3), and the Gemini client is reached only
to enrich the Tier-2 RCA *narrative*. See the two halves below, because they have different
authority.

**The validation boundary — always on, provider-independent.**

- `CompletionClient` is a `typing.Protocol`. It now has **one implementation**,
  `GeminiCompletionClient`, but the protocol remains the seam: tests inject a stub, and
  `decode_completion` stays the only path from a completion string to a `TriageResponse`.
- The module imports **no network library at module scope.** `google-genai` is imported
  lazily inside `GeminiCompletionClient.complete()`, so a host without the SDK, without a
  `GEMINI_API_KEY`, or air-gapped, still imports this module, still triages, and still
  answers `/healthz`. Verified: the module imported with `google.generativeai` absent from
  `sys.modules`, and `/healthz` + `/readyz` both returned 200 with the SDK installed.
- No test asserts the absence of a client any more — that assertion became false when one
  was added, and a deleted assertion is not a satisfied one. What is asserted instead is the
  property AGENTS.md §5.3 was actually about: `llm` must not hand-roll HTTP. It has no
  `requests`, `httpx`, `urllib.request` or `http.client` attribute; retries, TLS, timeouts
  and endpoint configuration belong to the provider SDK.
- Every artefact the **tier, patch and validation flags** produce is deterministic: regex
  matching, quantity arithmetic, PyYAML structural parsing, and real `git apply`. Two
  incidents with the same payload produce byte-identical output for those fields, which is
  what makes the goldens in `tests/fixtures/expected/` meaningful. **This claim does not
  extend to the prose fields once a model is reachable** — see the second half.

**The Gemini client — present, structured, and deliberately powerless.**

- SDK is **`google-genai`**, not `google-generativeai`. The latter is Google's legacy client,
  carrying `Development Status :: 7 - Inactive` in its own metadata, and
  `ai.google.dev/gemini-api/docs/migrate` directs users to migrate. The default model is a 3.x
  Flash, **not `gemini-1.5-flash`**: the deprecation table lists no 1.5-series model at all,
  so 1.5 has been shut down and a request for it returns `NOT_FOUND`. Both names are
  overridable (`GEMINI_MODEL`) because fleet availability is Google's fact, not this repo's.
- `system_instruction=` carries the behavioural rules as **their own provider field**. The
  telemetry goes in `contents`. This is the prompt-injection control and it is structural
  rather than advisory: anyone able to write to a failing container's stdout can print text
  that reads like an instruction, so "put the rules first in the prompt" is not a defence.
  Verified by capturing the outbound call, not by reading the source — `contents` contained no
  rule marker, and `system_instruction` contained no evidence.
- `response_mime_type="application/json"` plus `response_schema` constrain the output **at the
  provider**. The schema is deliberately narrower than `TriageResponse`: it exposes only
  `root_cause.summary` and `rca_markdown`, and **not** `blast_radius_tier`,
  `remediation.git_patch`, `patch_validated` or `confidence`. A model physically cannot
  return a tier or a patch, because the schema has no field to return one in. `reconcile`
  overwrites those from the router regardless.
- `decode_completion` remains the last line even though the provider constrains the output,
  because a provider behaviour is not a safety property this repository will take on trust.
  I-B4 still holds.
- Failure modes all raise `ModelOutputError`, including a refusal or an empty completion. A
  refusal is a **valid outcome**, and the caller escalates rather than retrying — retrying a
  model that declined once tends to produce prose again.
- `decode_narrative` is the decoder for a real client. `decode_completion` still
  validates the full document and remains the boundary for any client handed the
  whole thing. **These are not interchangeable**: the schema offers two fields and
  the full decoder demands eight, so a perfectly compliant model fails
  `decode_completion`. `ModelNarrative` declares the permitted slice as a model so
  the two halves agree by construction, and a test asserts the field sets match.
- Thinking is disabled (`thinking_budget=0`). 3.x Flash models reason before
  answering and charge that reasoning against `max_output_tokens`; measured with a
  1459-character prompt, the default budget produced `finish_reason=MAX_TOKENS` with
  **no text part at all**. It also restores what `temperature=0.0` means — reasoning
  left enabled can vary between runs in ways 0.0 does not control.
- Retries cover **500/502/503/504 and `UNAVAILABLE`/`DEADLINE_EXCEEDED` only**, at
  most 3 attempts inside the 60s budget. **429 is not retried**: it means either a
  momentary rate limit or an exhausted quota, and only `RESOURCE_EXHAUSTED`
  distinguishes them. An exhausted quota cannot be restored by 1.5s-apart retries,
  and an earlier revision that tried reported it as load-shedding.
- Failure modes raise `ModelOutputError` with the cause named, because they need
  different responses from whoever is on call. `_diagnose_empty` distinguishes
  token exhaustion, safety blocks, recitation blocks, and refusal. A refusal is a
  **valid outcome**.

**Observed live on 2026-10-01.** With log-text evidence enabled and a real
adversarial payload, Gemini 3.5 Flash returned schema-conforming JSON that cited the
actual traceback (`KeyError: 'cust_8817'` at line 88), preserved `[REDACTED]`,
reported the injection as an attack rather than obeying it, and reproduced none of
the system instruction. The container returned HTTP 200 with `TIER_2_ARCHITECTURAL`,
`git_patch: ""`, and the DO-NOT-APPLY banner intact.

Three live defects were found only by making the call, and are recorded in
`docs/lessons-learned.md`: the schema/decoder incompatibility, a log-text overflow of
`RootCause.evidence` that produced HTTP 500, and the misattribution of both
token-exhaustion and quota-exhaustion. Two further defects — a model section silently
discarded by a later field assignment, and a retried 429 — were found by negative
controls rather than by the API.

**Not yet observed.** The deployed `Tier-2` narrative path reached Gemini via
`_model_summary`/`_model_rca_section`, and the adversarial run above is real, but the
quota was exhausted partway through the session, so the final end-to-end container run
served a cached earlier completion rather than a fresh one. Treat the container-level
result as evidence that the wiring reaches the model and preserves authority, not as
a fresh live observation.

### 5.5.2b Where the model is actually consulted, and what it cannot touch

The client exists and is reachable, via `agent/triage.py`:
`_model_summary()` and `_model_rca_section()` call `_narrative_overlay()`, which
returns a `ModelNarrative` **or nothing**. Every failure — no key, SDK absent,
transport error after retries, refusal, safety block, malformed output — returns
nothing and the deterministic prose stands. There is no partial-credit path.

Two properties are structural rather than conventional:

- **Only prose is substitutable.** The Tier-2 response writes `blast_radius_tier`,
  `git_patch`, `patch_validated`, `risk_level`, and `verification_policy` as
  literals or upstream decisions, unreachable from the overlay. Verified by a live
  run with a key configured: all five unchanged.
- **The model's long-form analysis APPENDS to the dispatch document, after
  `_escalate` renders it.** That ordering is not cosmetic: `rca_markdown` is
  assigned wholesale by the war-room renderer, so anything appended earlier is
  silently discarded. It was, once. See `docs/lessons-learned.md`.

The log-text gate is `SREK3S_LOG_TEXT_EVIDENCE`, read at call time and **defaulting
closed**. It controls whether `evidence_lines()` emits log text or only the count of
it. Off by default because sending container-controlled text to a third party should
require a deliberate act; the documentation states plainly that a model shown only
metadata reasons about less than it could.

The shipped baseline has no `GEMINI_API_KEY`, so the agent runs exactly as before:
deterministic, byte-identical for identical input. Setting the key enables the
narrative; nothing else about the tier changes.

Consequences for readers: do not describe SREK3S as "an LLM that fixes Kubernetes". It is a
deterministic classifier whose tier and patch authority is computed before any model is
consulted (§5.3), with an optional model used to write the Tier-2 explanation. The
blast-radius argument in `PRD.md` §2 is *stronger* for that: a model failure degrades to
Tier-2 human escalation rather than to a speculative patch, and a model that is jailbroken
degrades to a bad paragraph inside a Tier-2 escalation that a human already owns. Wiring a
real client was a change to the §1 trust boundary and was reviewed as one; it is recorded here
because a reader who meets the client in `agent/llm.py` needs to know it exists and what it
is not allowed to decide.

### 5.5.3 Sandbox enforcement: rlimits are primary, and the cgroup write lands too late

Two facts about `agent/sandbox.py`, verified by reading the source on 2026-10-01 and not
observed at runtime.

**The cgroup write happens after the process has already exited.** `_run_guarded` calls
`subprocess.run(...)` and, only after it returns (or raises), calls `_try_cgroup` to write
`srek3s-agent/memory.max` and `srek3s-agent/cpu.max`. Those limits are therefore applied
*after* the child they are meant to bound has finished, and cannot constrain it.
`SandboxResult.cgroup_enforced` reports whether the writes succeeded; it does not, and does
not claim to, report whether they bounded anything. The module docstring's "when one is
delegated, writes the memory and CPU ceilings there too" is accurate about the write and
silent about its position in the sequence.

**The real enforcement is `RLIMIT_AS` / `RLIMIT_CPU` plus the `subprocess` timeout.** The
rlimits are installed in `preexec_fn`, i.e. before `exec`, so the kernel applies them to the
child and they cannot be raised from inside. `resource_limits_supported()` reports whether
they applied. This is the mechanism the docstring already describes as primary, and it is the
only one that can be relied on.

**And a documented constant contradicts itself.** The module docstring says the child gets
"500 ms of CPU", and `ROADMAP.md` §2.4.2 asks for `500m`. `DEFAULT_CPU_SECONDS` is `1` —
one CPU-*second*. `RLIMIT_CPU` counts CPU seconds and cannot express a fraction, so `500m`
is not expressible as an rlimit at all; the honest reading is that the budget was rounded up
to the smallest unit an rlimit can carry. The comment on the constant still claims "500 ms of
CPU per investigation", which is wrong by a factor of two. Open task in `ROADMAP.md`: amend
the docstring and the roadmap to say "1 CPU-second", or express the budget as a cgroup
`cpu.max` where a fraction is expressible.

---

## 6. Secret Masking Regex Manifest

Implemented in `internal/scrubber/manifest.go`. All patterns are **RE2-compatible** (Go
`regexp`): no backreferences, no lookahead/lookbehind. Every rule compiles at package
`init()`; a compile failure is a hard startup failure, never a silently skipped rule.
All rules replace matches with the literal sentinel **`[REDACTED]`**.

**Evaluation order is significant.** Rules run top-to-bottom; more specific structural
patterns (PEM blocks, JWTs) run before generic `key=value` patterns, so that a generic rule
cannot re-wrap or partially unmask an already-redacted span. This yields idempotence (I-A5).

| # | Rule ID | Regex (RE2) | Target | Replaces with |
|---|---|---|---|---|
| 1 | `pem_private_key` | `-----BEGIN (RSA \|EC \|DSA \|OPENSSH \|PGP \|ENCRYPTED )?PRIVATE KEY( BLOCK)?-----[\s\S]*?-----END (RSA \|EC \|DSA \|OPENSSH \|PGP \|ENCRYPTED )?PRIVATE KEY( BLOCK)?-----` | Whole PEM block incl. body | `[REDACTED]` |
| 2 | `aws_access_key_id` | `\b((A3T[A-Z0-9]\|AKIA\|ASIA\|ABIA\|ACCA\|AIDA\|AROA\|AIPA\|ANPA\|ANVA)[A-Z0-9]{16})\b` | AWS key IDs (`AKIA…`, `ASIA…`) | `[REDACTED]` |
| 3 | `aws_secret_access_key` | `(?i)aws(.{0,20})?(secret\|private)(.{0,20})?['"][0-9a-zA-Z/+]{40}['"]` | 40-char secret in `aws_secret_access_key = "…"` form | `[REDACTED]` |
| 4 | `jwt` | `\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b` | JSON Web Tokens (`header.payload.signature`) | `[REDACTED]` |
| 5 | `bearer_token` | `(?i)\bbearer\s+[A-Za-z0-9\-._~+/]{8,}=*` | `Authorization: Bearer …` | `[REDACTED]` |
| 6 | `basic_auth_url` | `(?i)([a-z][a-z0-9+.-]*:\/\/[^:\s\/]+:)([^@\s\/]+)(@[^\s\/]+)` | **Amended** — password only. See §6.3. | `$1[REDACTED]$3` |
| 7 | `generic_secret_kv` | `(?i)(\b[\w-]{0,20}(?:api[_-]?key\|secret[_-]?key\|secret\|token\|access[_-]?token\|refresh[_-]?token\|password\|passwd\|pwd\|passphrase\|client[_-]?secret\|private[_-]?key\|authorization\|auth)["']?\s*[:=]\s*["']?)(?P<value>[^"',;}\n]{4,})(["']?)` | **Amended** — see §6.4 (D-1) | `${1}[REDACTED]${3}` |
| 8 | `uuid` | `\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b` | UUIDs (customer/ticket correlation IDs) | `[REDACTED]` |
| 9 | `ipv4_address` | `\b((25[0-5]\|2[0-4][0-9]\|1[0-9][0-9]\|[1-9]?[0-9])\.){3}(25[0-5]\|2[0-4][0-9]\|1[0-9][0-9]\|[1-9]?[0-9])\b` | IPv4 addresses | `[REDACTED]` |
| 10 | `k8s_secret_mount` | `(?i)\b(?:kube-system\|kube-node-lease)\b[^\n]{0,80}(?:token\|secret\|ca\.crt)\|(?i)(?:token\|secret\|ca\.crt)[^\n]{0,80}\b(?:kube-system\|kube-node-lease)\b` | **Amended** — see §6.4 (D-2) | `[REDACTED]` |
| 11 | `private_key_pem_body` | `(?i)-----BEGIN[A-Z ]*PRIVATE[A-Z ]*-----` | orphaned BEGIN marker w/o matching END | `[REDACTED]` |

### 6.1 Masking Rules

- **M1** Replacement is the literal string `[REDACTED]` — constant, not configurable, so no
  environment variable can weaken masking.
- **M2** Processing is **in memory only**. No plaintext scratch buffer, temp file, or
  re-logging of input exists in the package.
- **M3** Rules are applied to log **lines**, then the joined result is re-scanned once to catch
  secrets assembled across line boundaries.
- **M4** A `RedactionReport` records `{total, rules_triggered[]}` — **counts only**. It must
  never contain the matched value or a reversible hash of it.
- **M5** Over-masking (e.g. an ordinary integer mistaken for a UUID) is preferred over
  under-masking. Diagnostic cost is recoverable; a leaked credential is not.
- **M6** The agent applies the same rule IDs as a defence-in-depth re-scan before responding
  (invariant I-B6). Go remains the authoritative control; the agent is a backstop.

### 6.2 Performance Budget

The full 11-rule pipeline must process **≥ 20,000 lines/sec/core** so that masking stays far
inside the 2s detection budget (AC-1). This is benchmarked in M1; rules are compiled once and
never recompiled in the hot path.

### 6.3 Amendment — Rule 6 `basic_auth_url` (ratified)

**Problem.** The original rule 6 replaced the *entire* authority span `scheme://user:pass@` with
`[REDACTED]`. Measured against the reference corpus:

```
postgres://payments:hunter2@10.4.2.9:5432/payments  ->  [REDACTED][REDACTED]:5432/payments
mysql://root:s3cr3tP4ss@db.internal:3306/checkout    ->  [REDACTED]db.internal:3306/checkout
```

Scheme, username **and** the `@` separator were destroyed, so the endpoint topology was lost.
The secret is masked and this is not a leak, but the host and port are exactly the signal an
OOM or network RCA reasons over (PRD F1, F3). Masking must not remove the evidence.

**Amendment.** Rule 6 now uses capture groups and replaces only the password:

```
Pattern:     (?i)([a-z][a-z0-9+.-]*:\/\/[^:\s\/]+:)([^@\s\/]+)(@[^\s\/]+)
Replacement: $1[REDACTED]$3
```

| Preserved | Masked |
|---|---|
| scheme (`postgres`), username (`payments`), the `@`, host, port, path | the password only |

**Idempotence.** Replacing an already-masked password with the same token is byte-identical, so
rule 6 satisfies invariant I-A5 without a guard. Confirmed by `TestIdempotence` and by the
`basic_auth_url` case in `TestRuleByRule`.

**Note on the composed pipeline.** Rule 9 `ipv4_address` runs after rule 6, so an IP-literal host
is additionally masked by design. Port and topology remain intact. The
`postgres://payments:hunter2@10.4.2.9:5432/payments` case is therefore asserted twice: on rule 6
in isolation, where `10.4.2.9:5432` survives verbatim, and on the full pipeline, where the IP is
masked but `:5432` and the `user:[REDACTED]@host:port` shape survive.

### 6.4 Amendments — Rules 7 and 10 (ratified, defects D-1 and D-2)

Both amendments close confirmed secret leaks. Measured against the ratified patterns
before the change:

| Input | Before | After |
|---|---|---|
| `{"password":"hunter2"}` | **unchanged — leak** | `{"password":"[REDACTED]"}` |
| `auth_token=abc123xyz789` | **unchanged — leak** | `auth_token=[REDACTED]` |
| `reading …/serviceaccount/token for kube-system` | **unchanged — leak** | `reading /var/run/[REDACTED]` |

**Rule 7, three changes:**

- `["']?` between the key and the separator. The original required `\s*[:=]` immediately after
  the key, so a closing quote defeated it and every JSON-form secret was missed.
- The key is prefixed `[\w-]{0,20}` and the alternation is non-capturing, so multi-word keys
  match. `\b` alone failed on `auth_token`, because `_` is a word character and therefore no
  boundary exists between the segments.
- The key and trailing quote are captured, so **only the value is replaced**. Without this the
  surrounding JSON was destroyed along with the secret, which would have broken the Contract A
  payload the agent parses.

Negative controls confirm the fix is not merely broader: `token_count=12345`, `secret_version=v3`,
`mytokenizer=abcdefgh` and `password_policy=strict-mode-value` all survive untouched.

**Rule 10** accepts both word orders. The original required the namespace *before* the token,
whereas the canonical log form is the reverse. The gap stays bounded to 80 non-newline characters
so the rule cannot reach across unrelated lines.

### 6.5 Amendments — Cross-line pass scope and rule priority (ratified, defects D-3 and D-5)

**D-3, multi-line rules run first.** The per-line pass previously ran rule 11
`private_key_pem_body` before the cross-line pass ran rule 1 `pem_private_key`. Rule 11 redacted
only the `-----BEGIN` marker, so by the time rule 1 saw the joined batch there was no `BEGIN…END`
pair left to match and the **base64 key body survived verbatim**. The cross-line pass now runs
*before* the per-line pass, on the raw lines, so rule 1 sees an intact block. Multi-line rules
therefore evaluate ahead of the single-line fallbacks, which is the correct precedence: block-level
removal must not be pre-empted by marker-level removal.

**D-5, the cross-line pass runs only multi-line rules.** Each `Rule` now carries an `IsMultiLine`
flag. The flag is derived by probing each compiled pattern with newline-bearing inputs, never by
inspection, and `TestMultiLineFlagMatchesCapability` asserts the flag equals observed capability
in both directions. Only `pem_private_key` qualifies, so the pass runs **1 of 11** patterns rather
than eleven.

> The value class of rule 7 is `[^"',;}\n]` — it deliberately **excludes** a newline. When the
> class admitted `\n`, rule 7 became multi-line-capable, and the cross-line pass then applied it to
> the entire joined batch first, where a single greedy match swallowed every following line: a
> 128-line batch collapsed to one line and only one rule fired. Excluding `\n` confines the
> cross-line pass to `pem_private_key` and restores both correctness and throughput.

**Measured effect** on the shipped corpus, `windows/arm64`:

| State | lines/sec |
|---|---|
| Full manifest in the cross-line pass | ~7,900 |
| D-5 applied (1 of 11 rules) | ~18,700 |
| `-short` skipped; final figure | **~187,000** |

The remaining 10× is the corpus itself: 43 fixture cases including a multi-line PEM block, which is
a heavier mix than the original synthetic fixture. The ARCH §6.2 budget of 20,000 lines/sec is met
with large margin, and CI on `ubuntu-latest` remains the authoritative measurement.

> **Platform note, added 2026-10-01, with the figures deliberately unaltered.** The
> `~187,000` figure was measured on the **old `windows/arm64`** host, which is no longer the
> development environment; the current host is `Fedora Linux 44` on `linux/aarch64` (§9.1).
> This is recorded history and is left exactly as measured. It has **not** been re-measured
> here, and this note makes no throughput claim for `linux/aarch64`. A benchmark re-run on
> the new host should be recorded as a new figure with its platform named, not substituted
> for this one; `ubuntu-latest` (`amd64`) remains the authority.

**Narrowed M3 scope, stated explicitly.** Because rule 7 is now single-line, a `key=value` secret
*split across a newline* is not caught by the cross-line pass. This is a deliberate trade: that
case is rare in practice, whereas the alternative was collapsing whole batches. A future
`secret_continuation` rule may address it; it is recorded as deferred rather than silently dropped.

---

## 7. Concurrency and Safety Model

- **C1** Fixed-size worker pool (default 4). The job channel is **buffered**
  (`default 256`); a full buffer applies backpressure, it never blocks an informer callback
  and never drops an incident silently.
- **C2** Every blocking operation — HTTP request, Kubernetes API call, channel send — is
  bounded by `context.WithTimeout`. No `context.Background()` on a blocking path.
- **C3** Informers run with an explicit resync period and a stop channel tied to
  `SIGINT`/`SIGTERM`; the process drains and exits cleanly.
- **C4** `internal/k8s/guard.go` provides nil-safe accessors. Raw access to
  `.State.Terminated`, `.State.Waiting`, `.Resources.Limits`, or `.ContainerStatuses[i]` is
  **forbidden outside that file** — pointers are checked at every level, not just the first.
- **C5** Detection latency is measured with a monotonic clock only.

---

## 8. Container Hardening

Applied to **both** `sentinel.yaml` and `agent.yaml`, and asserted by a test that parses them:

```yaml
securityContext:
  runAsUser: 10001
  runAsGroup: 10001
  runAsNonRoot: true
  runAsPodGroup: 10001
  fsGroup: 10001
  seccompProfile:
    type: RuntimeDefault
containers:
  - securityContext:
      allowPrivilegeEscalation: false
      privileged: false
      readOnlyRootFilesystem: true
      runAsNonRoot: true
      capabilities:
        drop: ["ALL"]
      # add: [] — no capability is ever added back
```

Writable paths are narrow, explicit, and mounted as `emptyDir` (`/tmp` only). The Python agent
additionally sets `PYTHONDONTWRITEBYTECODE=1` (a read-only root filesystem cannot write
`__pycache__`) and `TMPDIR=/tmp`. No `hostPath`, no `hostNetwork`, no privileged init
container, and no `ServiceAccount` token automount for `agent/`.

### 8.1 The agent's GitOps root ships empty, so Tier-1 is unreachable as deployed

`deploy/agent.yaml` sets `SREK3S_MANIFEST_ROOT=/manifests` and mounts a volume there — and
that volume is an **`emptyDir`**, which is empty by construction. The chain from there is
deterministic and short:

1. `FileManifestProvider.read_manifest` cannot open the target, so it returns `None` (its
   documented "cannot be read" answer — it returns `None` rather than raising for a content
   problem, precisely so the failure routes to a considered escalation instead of a `500`).
2. `triage._build_remediation_diff` returns at **step 2** of the diff build — the memory
   limit is read, then the manifest read fails.
3. The caller escalates. Every incident becomes `TIER_2_ARCHITECTURAL` with `git_patch == ""`
   and `patch_validated == false`.

That is invariant **I-B2** failing closed and the design working as intended. It is recorded
here because the deployed state is otherwise indistinguishable from a broken agent, and a
reader who concludes the latter will go looking for a bug that does not exist.

**To make Tier-1 reachable in-cluster**, replace the `manifests` `emptyDir` with a real
GitOps checkout — a PersistentVolumeClaim, or an init container that clones the repository —
and set `SREK3S_TARGET_MANIFEST` to a repo-relative path inside it. Note the second half of
the trap: the default target is `deploy/payments/checkout-api.yaml`, and **that path does not
exist in this repository**. So leaving `SREK3S_TARGET_MANIFEST` unset, or setting it to the
documented default, produces exactly the same 100% Tier-2 outcome as leaving the volume
empty. Both conditions must be addressed, and neither is discoverable from the other.

**What an in-cluster run can therefore prove.** It proves the Tier-2 war-room path and the
no-mutation guarantee (runbook §5, PRD AC-4). It **cannot** prove AC-3. Offline, against
`tests/fixtures/`, Tier-1 is fully exercised — including real `git apply --check` and the
goldens in `tests/fixtures/expected/` — so the gap is a *deployment-wiring* gap, not an
implementation gap. Stating that distinction matters, because the cheapest false report
available is "the agent cannot generate patches".

### 8.2 Architecture of the built images

The manifests pin `registry.internal/srek3s-{agent,sentinel}:0.1.0` and the project has been
built on two architectures, which are **not interchangeable**:

| | Local host | CI (`ubuntu-latest`) |
|---|---|---|
| Architecture | `linux/arm64` (Fedora 44 on WSL2, aarch64) | `linux/amd64` |
| Image target | must be `--platform linux/arm64` | `amd64` |

A hardening assertion such as "runs as UID 10001" holds on both, and an
`ImagePullBackOff` is architecture-agnostic in its message, so a wrong-platform
image is easy to misdiagnose as a missing image. `busybox:1.36.1`, which the
`deploy/chaos/` fixtures pin, does publish an `arm64` manifest, so the chaos path
works on the local host without a multi-arch build. See
`docs/offline-install.md` for registration into the `k8s.io` containerd namespace under the
exact fully-qualified names.

---

## 9. Technology Constraints (Binding)

| Layer | Constraint |
|---|---|
| Sentinel | Go 1.23+; official `k8s.io/client-go`, `k8s.io/api`, `k8s.io/apimachinery`; stdlib first; no unvetted third-party runtime frameworks |
| Agent | Python 3.11-slim; Pydantic v2 + FastAPI; `fastembed`/`onnxruntime` CPU only; **no PyTorch, no CUDA, no GPU deps**. The inference path is a permitted ceiling, not a running one — see §5.5.2. All shipped analysis is deterministic. |
| Cluster | single-node k3s; images imported into the `k8s.io` containerd namespace under their **exact fully-qualified** names (`registry.internal/srek3s-{agent,sentinel}:0.1.0`), because a name the kubelet cannot resolve is `ImagePullBackOff` and the message does not distinguish a missing tag from a wrong architecture |
| Image platform | `linux/arm64` on the `Fedora 44`/aarch64 development host; `linux/amd64` in CI — see §8.2 |
| Sandbox | `RLIMIT_AS` 256 MiB + `RLIMIT_CPU` (1 CPU-second) + `subprocess` timeout; the cgroup write is best-effort and lands after the child exits — see §5.5.3 |
| Quality gates | `go vet ./...`; `test -z "$(gofmt -l .)"`; `go test -race -timeout 30s ./...`; `black --check agent/`; `flake8 agent/`; `mypy --strict agent/`. Python gates run through `~/SREK3S/.venv311/bin/python -m …` on the `linux/aarch64` host (CPython 3.11.16); the system `python3` there is 3.14.3 and is not a valid interpreter for these commands. |
| Toolchain authority | `go test -race` is executable **locally** on `linux/aarch64` (gcc present), which it was not on the earlier `windows/arm64` host. **CI on `ubuntu-latest` remains the platform authority for every published figure.** Local verification is additional evidence, never a replacement, and no recorded CI result is withdrawn by that. |

### 9.1 Environment of record (measured 2026-10-01)

Pinned because three separate gates and every in-cluster claim depend on it, and because a
reader comparing a local number against a CI number needs to know which machine produced
which. Mirrors `PRD.md` §7 and `AGENTS.md` §2.

| Item | Development host | CI |
|---|---|---|
| OS | WSL2, **Fedora Linux 44 (aarch64)**, kernel `6.18.40.1-microsoft-standard-WSL2`, systemd PID 1 | `ubuntu-latest` |
| Arch | `linux/arm64` | `linux/amd64` |
| Go | `go version go1.26.8-X:nodwarf5 linux/arm64` (native `golang.aarch64`; resolves to `/usr/sbin/go`) | as declared by the runner |
| Python | CPython **3.11.16**; gates via `~/SREK3S/.venv311/bin/python -m …`. System `python3` is **3.14.3** and is **not** valid here | 3.11 |
| Race detector | available (`gcc.aarch64` 16.2.1) — locally verifiable now | available; **authoritative** |
| Docker | 29.8.2, `overlayfs`, root `/var/lib/docker`, unit active. **`sudo docker` required** — `duckie` is not in the `docker` group and `/var/run/docker.sock` is `root:docker` | runner-dependent |
| k3s | **v1.36.4+k3s1**, node `dwindle2`, containerd `2.3.4-k3s1.36`, IP `172.30.181.188`, 10 CPU / ~7.5Gi / 110 pods | **v1.29.9+k3s1** |
| kubectl | v1.36.4+k3s1, kustomize v5.8.1; **`sudo` required** — kubeconfig `/etc/rancher/k3s/k3s.yaml` is `0600` root-owned | runner-owned |
| PSA evaluation | `enforce-version: latest` resolves against **1.36** locally | resolves against whatever `latest` means on that node |
| NetworkPolicy | **enforced.** Verified 2026-10-01 by differential test: a pod WITHOUT the SREK3S labels reached `generativelanguage.googleapis.com:443` while the labelled agent pod got `EHOSTUNREACH` from the same namespace. That also disproved the earlier assumption that k3s's flannel ignores policy. | exercised by the in-cluster E2E leg |
| Cluster state | `srek3s-system` **does not exist**; no namespace carries PSA labels; nothing from `deploy/` applied; `k8s.io` holds only k3s's own images | fixtures and `deploy/` applied per run |
| Images | `linux/arm64` built locally by `make build`; CI builds **both** `linux/amd64` and `linux/arm64` (`output: type=cacheonly`) | multi-arch manifest list pushed to GHCR on a `v*` tag |

**The version skew is a live diagnostic hazard.** The same manifests can be admitted against
k3s 1.36 and refused against 1.29 for a reason that has nothing to do with the code. Diagnose
the skew before diagnosing the manifest.

---

## 10. Change Control

Per AGENTS.md §5, `ARCHITECTURE.md` governs schemas and layout. Therefore:

- Changing a field name, type, or nullability in §4/§5 is a **breaking** change: bump
  `schema_version`, update both implementers, and update
  `tests/fixtures/sample-incident.json` in the same commit.
- Adding an optional field with a default is **non-breaking**: minor bump.
- Adding a directory outside §3 requires an explicit decision recorded here first.
- `TIER_1_TOIL` / `TIER_2_ARCHITECTURAL` are **closed enums**. Adding a tier is a design
  change, not an implementation detail.
- Adding a field to the **model's** `response_schema` (§5.5.2) is a **security change**,
  not a schema change. That schema is the boundary preventing the model from expressing
  authority; a field like `blast_radius_tier` makes the model a participant in routing.
  `ModelNarrative(extra="forbid")` and its negative control exist to make that loud.

### 10.1 Distribution: what CI guarantees, and what it does not

`.github/workflows/ci.yaml` runs the gates, a container smoke test, and a **multi-arch
dry run** (`output: type=cacheonly`, which executes every layer including
foreign-architecture `RUN` steps under QEMU and then discards the artefact).
`.github/workflows/release.yaml` is tag-gated on `v*` and publishes to GHCR using the
default `GITHUB_TOKEN`.

Three asymmetries worth stating rather than leaving to be discovered:

- **`ci.yaml` holds no registry credential.** A workflow that installs third-party
  packages on every pull request must never hold a write token; the token would reach
  whatever the PR's build steps do. `packages: write` is granted to the single
  publishing job and is asserted to be absent everywhere else.
- **A multi-arch dry run proves both platforms COMPILE, not that they RUN.** The
  Sentinel's entrypoint smoke test is skipped on a cross build by design — the binary is
  foreign and the builder is not — and the Dockerfile prints that it skipped and names
  `make verify-images` as the check that executes it.
- **Released images and `deploy/` reference different registries.** GHCR is
  `ghcr.io/OWNER/srek3s-{agent,sentinel}`; the manifests reference
  `registry.internal/`. Deploying a released image therefore needs an `images:`
  transform, and "released" and "what `make deploy` applies" are not the same thing.

### 10.2 The credential requirement

The Gemini API key is **optional**. Tier, patch, and every validation flag are
deterministic; the model writes only Tier-2 prose. Without a key the agent behaves
exactly as it did before the client existed.

- **Locally**: `.env` or `.env.local` in the repository root. Both are gitignored.
- **In-cluster**: a Secret named `srek3s-secrets` with key `GEMINI_API_KEY`, read via
  `valueFrom.secretKeyRef` with **`optional: true`**. That last part is load-bearing —
  without it, a cluster with no Secret produces pods stuck in
  `CreateContainerConfigError`, because a missing `keyRef` is an *admission failure*
  rather than a missing environment variable, and an operator who wants no model could
  not run the agent.
- **Log text to the model** is a separate, second opt-in: `SREK3S_LOG_TEXT_EVIDENCE`,
  default **off**. It governs whether `evidence_lines()` emits log text or only a count.
- The Agent's only non-DNS egress is **TCP 443**, granted in `deploy/agent.yaml`. It is
  `0.0.0.0/0` because a NetworkPolicy selects namespaces, pods, or CIDRs and an external
  provider has no stable CIDR; the cost is stated at the rule.

### 6.6 Amendment — Rule 7 `secret_access_key` (ratified, P0 credential leak)

**Problem.** An **unquoted** AWS secret access key passed the entire 11-rule pipeline unmasked.

```
aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"  ->  masked (rule 3)
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY    ->  NOT MASKED
```

Two rules should have caught it, and both missed:

- **Rule 3** (`aws_secret_access_key`) is anchored on quotes around the 40-character value,
  which is the shape the AWS CLI emits. That is correct for its own input, and useless for an env
  dump or a `key=value` log line.
- **Rule 7** (`generic_secret_kv`) could not cover it either. Its key alternation contained
  `secret[_-]?key`, and that substring does not occur inside `secret_access_key`, so the `[:=]`
  never lined up and the alternative never matched.

The result was a live credential in telemetry, which §6 M5 ranks as the one unacceptable outcome:
over-masking is recoverable, a leaked credential is not.

**Amendment.** Rule 7's key alternation gains an optional access segment:

```
(?:secret(?:[_-]access)?[_-]?key|secret)
```

This covers `secret_key`, `secret-key`, `secretkey`, `secret_access_key` and `secret-access-key`, and
is listed **before** the bare `secret` alternative so the longest match wins without depending on
backtracking.

**Scope.** P0, minimal, and confined to rule 7's key name. No other rule is touched, no replacement
changes, and the group structure is untouched — so rule 7's existing behaviour on `password`, `token`,
`api_key` and the JSON form is bit-for-bit unchanged.

**Parity.** `agent/rescan.py` carries the identical amendment, because ARCH §6 M6 requires the agent's
backstop to apply the same rule IDs as the Go node. A change to one without the other would leave the
two implementations disagreeing about the same credential.

**Idempotency.** Unaffected. The replacement remains `${1}[REDACTED]${3}`, and re-scrubbing
`aws_secret_access_key=[REDACTED]` produces the identical bytes, so invariant I-A5 holds.

**Verified by.** `TestSecretAccessKeyVariantsAreMasked` (Go, rule-by-rule and idempotence),
`TestUnquotedAWSSecretKeyIsScrubbed` (worker, end-to-end through the pool), and
`TestRule7CoversSecretAccessKeyVariants` (Python, parity against the Go manifest).
