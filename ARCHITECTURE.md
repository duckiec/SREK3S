# ARCHITECTURE — Autonomous Reliability Firewall & Incident Sentinel

| Field | Value |
|---|---|
| Document ID | `ARCH-0001` |
| Version | `0.1.0` |
| Status | Draft — **single source of truth for schemas and layout** |
| Requirement source | `PRD.md` |
| Delivery plan | `ROADMAP.md` |

> Per AGENTS.md §5, this document is the single source of truth for schemas and directory
> layout. Changes here require an explicit decision; roadmap tasks must not invent new
> layouts or field names.

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

---

## 2. Component Boundary and Least Privilege

| Component | Cluster credential | Allowed verbs |
|---|---|---|
| `cmd/sentinel` | in-cluster ServiceAccount | `get`, `list`, `watch` on `pods`, `events`, `deployments`, `replicasets` |
| `agent/` | **none** | n/a |
| War-Room dispatcher | **none** | n/a |

No mutating verb (`create`, `update`, `patch`, `delete`, `deletecollection`) appears in any
`Role` under `deploy/`. This is asserted by a test that parses the manifests (PRD AC-4).

---

## 3. Directory Layout

```
SREK3S/
├── AGENTS.md                     # engineering guardrails (authoritative)
├── PRD.md                        # requirements + acceptance criteria
├── ARCHITECTURE.md               # THIS FILE — schemas + layout (single source of truth)
├── ROADMAP.md                    # 4 sequential milestones
│
├── cmd/
│   └── sentinel/                 # Go entrypoint; wiring, flags, signal handling
│       └── main.go
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
│   │   ├── classify.go           # OOMKilled / CrashLoopBackOff extraction
│   │   ├── guard.go              # defensive pointer helpers (nil-safe accessors)
│   │   └── *_test.go
│   │
│   └── emitter/                  # EGRESS BOUNDARY
│       ├── emitter.go            # ctx-bounded HTTP POST to agent
│       ├── payload.go            # Go-side IncidentPayload structs (wire types)
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
│   ├── pyproject.toml
│   └── requirements.txt          # no torch, no cuda, no gpu extras (asserted in CI)
│
├── deploy/                       # k3s MANIFESTS
│   ├── namespace.yaml
│   ├── rbac.yaml                 # read-only Role + RoleBinding (no mutating verbs)
│   ├── sentinel.yaml             # Go daemon: 10001/10001, RO rootfs, cap_drop ALL
│   ├── agent.yaml                # FastAPI: same hardening
│   ├── kustomization.yaml
│   └── chaos/                    # Milestone 4 synthetic chaos fixtures
│       ├── oom-badpod.yaml
│       └── crashloop-badpod.yaml
│
└── tests/
    └── fixtures/
        ├── secrets_corpus.txt        # AC-2 masking corpus (one sample per rule)
        ├── sample-incident.json      # canonical valid Incident Payload
        ├── oom-restartloop.yaml      # manifest an OOM diff must patch
        └── expected/                 # golden outputs (RCA + diff) for regression
            └── oom-expected.patch
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
   plaintext secret from `tests/fixtures/secrets_corpus.txt`.
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

---

## 9. Technology Constraints (Binding)

| Layer | Constraint |
|---|---|
| Sentinel | Go 1.23+; official `k8s.io/client-go`, `k8s.io/api`, `k8s.io/apimachinery`; stdlib first; no unvetted third-party runtime frameworks |
| Agent | Python 3.11-slim; Pydantic v2 + FastAPI; `fastembed`/`onnxruntime` CPU only; **no PyTorch, no CUDA, no GPU deps** |
| Cluster | single-node k3s; images imported into internal containerd namespace via `k3s ctr images import` |
| Quality gates | `go vet ./...`; `test -z "$(gofmt -l .)"`; `go test -race -timeout 30s ./...`; `black --check agent/`; `flake8 agent/`; `mypy --strict agent/` |

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
