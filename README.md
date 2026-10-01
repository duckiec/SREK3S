# SREK3S — Autonomous Reliability Firewall

SREK3S watches a Kubernetes cluster for container failures, produces a root-cause
analysis, and — when the cause is unambiguous and the fix is a one-line resource
change — emits a verified unified `git diff` for a human to merge. It never
writes to the cluster. That is enforced by the cluster, not by convention.

**Status:** MVP sealed — 727 Python tests + 178 Go test functions green, all CI
gates passing. [`ROADMAP.md`](ROADMAP.md) records per-milestone evidence;
[`docs/lessons-learned.md`](docs/lessons-learned.md) records the defects found
along the way, including the ones a passing gate failed to catch.

---

## Getting started

### Prerequisites

| | |
|---|---|
| Go | 1.23+ (`go.mod` pins 1.23) |
| Python | **3.11, strictly.** 3.12+ syntax is not permitted; formatting is pinned to `target-version = ["py311"]`. |
| Cluster | Any conformant cluster. CI uses k3s. |
| `git` | Required in the agent image — patch validation runs `git apply --check`. |
| Docker | Only for building the agent image. |

### Build

```bash
go build -o bin/sentinel ./cmd/sentinel
docker build -t srek3s-agent:0.1.0 -f agent/Dockerfile .
```

The agent image's build context is the **repository root**, not `agent/` — the
Dockerfile needs `agent/` and its config, and assumes nothing outside its own
subtree.

### Deploy

```bash
kubectl apply -k deploy/
```

`deploy/service.yaml` publishes the agent on `srek3s-agent:8000`, which is the
Sentinel's built-in `-agent-url` default. The two are asserted equal — along
with the Service's selector against the agent's pod labels, and its
`targetPort` against the port the agent actually binds — by
`test_the_agent_service_routes_the_sentinels_default_endpoint`. That check
exists because v1.0.0 shipped a deploy set whose Sentinel pointed at a Service no
manifest created, on a port nothing listened to. It applied cleanly, every
manifest test passed, and the two pods could not talk. The E2E never caught it
either: it port-forwards around name resolution entirely.

The manifests reference `registry.internal/srek3s-{agent,sentinel}:0.1.0`.
Those tags are placeholders the release pipeline rewrites in the committed file,
so applying the set against a cluster that cannot pull them yields
`ImagePullBackOff`. For the verified `pull` + `tag` path into a local
containerd, see [`docs/offline-install.md`](docs/offline-install.md).

### Run the tests

None of this needs a cluster.

```bash
go test ./...                     # Go units. Add -race; CI-only where TSan is absent.
pytest agent/tests/ -q            # 727 passed, 2 skipped
black --check agent/ tests/
flake8 agent/ tests/
mypy --strict agent/ tests/
python scripts/audit_workflow.py  # audits the CI definition itself
```

`mypy --strict` must be run against `agent/` **and** `tests/` together — against
`agent/` alone it reports spurious `import-not-found` errors for the test
fixtures.

The 2 skips are live-cluster tests that print `BLOCKED DEPENDENCY, not a pass`.
They need `kubectl` and a reachable cluster; the offline half of that file is
what ran.

### Where to go next

- **Operating it** — [`docs/runbook.md`](docs/runbook.md): deploying, reading
  logs, interpreting a Tier-2 dispatch, reviewing a Tier-1 PR, and the
  No-Autofix guarantee.
- **Understanding it** — [`ARCHITECTURE.md`](ARCHITECTURE.md) is the single
  source of truth for schemas, invariants, and layout. Code and spec
  disagreeing is treated as a stop-the-line discrepancy, not a documentation
  bug.
- **Deploy manifests** — [`deploy/`](deploy/): `namespace.yaml`, `rbac.yaml`,
  `sentinel.yaml`, `agent.yaml`, `kustomization.yaml`, plus `chaos/` for the
  deliberate-failure fixtures.
- **Requirements** — [`PRD.md`](PRD.md).
- **Why any of this exists** — [below](#the-problem-the-llm-blast-radius-gap).

---

## Table of contents

- [Getting started](#getting-started)
- [The problem: the LLM blast-radius gap](#the-problem-the-llm-blast-radius-gap)
- [What SREK3S actually does](#what-srek3s-actually-does)
- [Data flow](#data-flow)
- [Engineering deep dive](#engineering-deep-dive)
  - [1. Zero cluster mutation is structural](#1-zero-cluster-mutation-is-structural)
  - [2. The in-memory scrubber](#2-the-in-memory-scrubber)
  - [3. The ephemeral, resource-capped sandbox](#3-the-ephemeral-resource-capped-sandbox)
  - [4. Fail-closed Tier 1 / Tier 2 routing](#4-fail-closed-tier--1--tier-2-routing)
  - [5. The post-remediation verification loop](#5-the-post-remediation-verification-loop)
  - [6. Invariants](#6-invariants)
  - [7. Verification without a cluster](#7-verification-without-a-cluster)
- [Testing and gates](#testing-and-gates)
- [Repository map](#repository-map)

---

## The problem: the LLM blast-radius gap

Asking a model to fix a production incident couples two things that should be
decoupled: *diagnosing* the fault and *acting* on it. Diagnosis is where a
language model is genuinely useful — correlating a `CrashLoopBackOff` with a
memory limit, a liveness probe, and a previous OOMKilled termination is exactly
the kind of multi-signal reasoning that is tedious and error-prone by hand.

Action is where it is dangerous, because the blast radius of a wrong patch is not
proportional to the confidence that produced it. A plausible `resources.limits`
edit that raises a memory ceiling by 4× on a node that is already under
memory pressure turns a single-container restart loop into a node-level eviction
cascade. The model was *probably* right. The cluster does not grade on a curve.

The compliance problem is adjacent and, for many operators, disqualifying.
Incident telemetry is a rich source of credentials: env-var dumps in crash
reports, connection strings with inline passwords, mounted service-account
tokens. Any system that ships that telemetry to a third-party inference endpoint
is a credential-exfiltration path with a helpful README. Auditors do not
distinguish between "the model was instructed not to log secrets" and "the
secrets are not present in what left the process."

SREK3S treats both as structural problems:

- **Blast radius is decided by policy, not by the model.** The model proposes a
  patch. It does not choose whether to ship it. A verdict of `TIER_2` is
  structurally incapable of carrying a patch at all.
- **Credentials never leave the Go process.** Scrubbing happens in memory, on
  the Sentinel, before the egress boundary. There is no code path in which
  unmasked telemetry reaches the network.

## What SREK3S actually does

1. Watches pods and events through a read-only informer pair.
2. Detects `OOMKilled` and `CrashLoopBackOff`, joining container terminations to
   events by `involvedObject.uid` so cause and effect are ordered rather than
   guessed.
3. Scrubs the last 100 log lines and the joined event messages through 11
   ordered regex rules, in memory, and accounts for what it masked.
4. Ships the scrubbed payload over HTTPS to the Python triage agent.
5. The agent classifies, and routes on a fixed policy: unambiguous and
   policy-vetted → `TIER_1_TOIL` with a patch; anything else →
   `TIER_2_ARCHITECTURAL` with no patch at all.
6. Every `TIER_1` patch is validated twice — YAML AST parse, then `git apply
   --check` against the real target manifest in a throwaway repo — before it is
   labelled valid.
7. After a human merges, the agent watches the workload back and either closes
   the incident or promotes it to `TIER_2`.

Steps 6 and 7 are the difference between a demo and a system. A patch that was
never applied looks identical to a patch that fixed nothing, until you check.

## Data flow

```
  Kubernetes API                    Go Sentinel (UID 10001, read-only)
 ┌──────────────────┐            ┌──────────────────────────────────────┐
 │ pods  (informer) │──┐         │ 1. classify  OOMKilled / CrashLoop    │
 │ events (informer)│──┤         │ 2. join      by involvedObject.uid    │
 └──────────────────┘  │         │ 3. fetch     last 100 log lines       │
                       │         │ 4. SCRUB     11 rules, in memory  ◄──┼── nothing
                       ▼         │ 5. emit      HTTPS, ctx-bounded       │   unmasked
                 bounded worker    └──────────────────────────────────────┘   leaves
                 pool (3)                        │ scrubbed only
                                                   │ Contract A
                                                   ▼
                                            ┌──────────────────┐
                                            │  Python agent    │
                                            │  FastAPI/Pydantic│
                                            │  classify → route│
                                            │  patch → validate│
                                            │  rescan (I-B6)   │
                                            └────────┬─────────┘
                             Tier 1 (verified diff)  │   Tier 2 (no patch)
                                          ▼         ▼
                                    ┌──────────┐  ┌──────────────┐
                                    │ GitOps PR│  │ War room     │
                                    │ human    │  │ dispatch     │
                                    │ merges   │  │ (no autofix) │
                                    └────┬─────┘  └──────────────┘
                                         │ merged
                                         ▼
                                  post-remediation
                                  verification loop
```

---

# Engineering deep dive

## 1. Zero cluster mutation is structural

The Sentinel runs with a namespaced `Role` granting exactly `get`, `list`,
`watch` on `pods`, `pods/log`, and `events`. There is no `ClusterRoleBinding`.
A namespaced `Role` bound cluster-wide, or a `ClusterRole`, would each widen
blast radius past what a watcher needs.

The point is not that the code avoids write calls. It is that a write call
*cannot succeed*:

| Layer | What it catches | What it cannot |
|---|---|---|
| The `Role` itself | A bug reaching a client-go mutating method; the binary being replaced with something else | The `Role` being edited to add a verb |
| `TestSentinelRoleGrantsNoMutatingVerb` | Someone adding an escalation path next quarter | The test being deleted |

Neither subsumes the other, which is why both exist. A `Role` that is correct
but unasserted rots silently; a test that passes while the `Role` is wrong proves
nothing about the cluster. A third layer, invariant **I-B5**, asserts that
neither wire contract contains any field capable of expressing a write verb — so
a patch cannot smuggle one through the model even if the model tried.

`pods/log` is listed explicitly because it is a separate subresource. Omitting
it would not error; it would make every incident arrive with no logs, and the
RCA would be generated from resource limits alone and look entirely plausible.

## 2. The in-memory scrubber

Eleven rules, in a **normative order** fixed by `ARCHITECTURE.md` §6 and
asserted by `TestManifestMatchesSpecification`:

| # | Rule ID | Target |
|---|---|---|
| 1 | `pem_private_key` | Multi-line PEM blocks, BEGIN…END |
| 2 | `aws_access_key_id` | `AKIA`/`ASIA`/`AROA`… + 16 chars |
| 3 | `aws_secret_access_key` | Quoted 40-char secret |
| 4 | `jwt` | Three base64url segments |
| 5 | `bearer_token` | `Bearer <token>` |
| 6 | `basic_auth_url` | Password only, inside `userinfo` |
| 7 | `generic_secret_kv` | `key = value` across many key spellings |
| 8 | `uuid` | UUIDs |
| 9 | `ipv4_address` | IPv4 literals |
| 10 | `k8s_secret_mount` | Mounted SA token paths |
| 11 | `private_key_pem_body` | PEM body fallback |

Every rule emits the same unconfigurable sentinel. The result is idempotent
(**I-A5**): `scrub(scrub(x)) == scrub(x)`, which matters because a redacted
payload is re-scrubbed by the agent before it goes anywhere (**I-B6**).

Four properties that are easy to get wrong and expensive to get wrong:

**Order is normative, not incidental.** Structural patterns run before the
generic `key=value` pattern, so a broad rule cannot re-wrap or partially unmask
a span an earlier rule already redacted. The agent's `key=value` value class
deliberately excludes `\n`: when it did not, one greedy match swallowed every
following line, collapsing a 128-line batch to a single line and masking one rule
instead of eleven.

**Multi-line rules are flagged, and the flag is probed.** Only rules marked
`MultiLine` take part in the cross-line re-scan. Setting the flag optimistically
reintroduces a real defect: a single-line fallback rule redacts a `BEGIN` marker
and leaves the block body exposed. `TestMultiLineFlagMatchesCapability` probes
each compiled pattern with inputs whose only distinguishing feature is an
embedded newline.

**Cancellation happens at line boundaries only.** A line is either scrubbed to
completion or dropped. Aborting mid-rule would return a partially-scrubbed
string, which is a credential leak with extra steps.

**Topology survives redaction.** Rule 6 uses capture groups to replace only the
password segment in `scheme://user:[REDACTED]@host:port`. Wiping the host would
destroy the endpoint topology an RCA depends on — the difference between "the
database is unreachable" and "the connection to db-primary:5432 is failing auth"
is the whole finding.

The scrubber is validated against a 46-case corpus across 8 groups, 32 of which
are maskable, including a `negative_controls` group of 6 cases that must *not*
be masked. A masker that redacts everything scores 100% on the 32 and is
useless.

## 3. The ephemeral, resource-capped sandbox

LLM inference and regex analysis are untrusted compute. The agent runs them in a
disposable process (`python -m sandbox_worker`) with `RLIMIT_AS` at 256 MiB and
`RLIMIT_CPU` at 500 ms, and in-cluster under a `256Mi` / `500m` cgroup. The
worker holds no state between invocations, so there is nothing to leak between
incidents.

Saturation is shed, not queued. An atomic job budget caps concurrent
investigations; a request arriving at a full sandbox gets HTTP `429` with
`{"error": "sandbox_busy"}` immediately. Queueing would convert a capacity limit
into a latency problem and eventually into probe failures.

The CPU limit is small on purpose. A large value would be more defensible if the
workload were CPU-trivial; the ceiling exists to bound blast radius, not to
accommodate a slow analysis.

## 4. Fail-closed Tier 1 / Tier 2 routing

The routing decision is deterministic and lives in the agent, not in the model.
The model is given a constrained decoding schema and can only populate fields
that already exist.

| Verdict | Meaning | Patch |
|---|---|---|
| `TIER_1_TOIL` | Unambiguous, policy-vetted, mechanically fixable | Verified unified diff |
| `TIER_2_ARCHITECTURAL` | Ambiguous, architectural, or unverifiable | **Always empty** |

`TIER_2` carrying a patch is not discouraged — it is **unrepresentable**. The
Pydantic model raises on `blast_radius_tier == TIER_2` with a non-empty
`git_patch` or `patch_validated == true` (**I-B1**). Escalation is also forced
whenever classification is `UNKNOWN`, whenever a patch cannot be validated, and
whenever post-remediation verification observes a repeat failure.

Patch validation is deliberately two-layer, because each layer catches what the
other cannot:

1. **Structural.** YAML AST parse. Rejects a patch that is not a well-formed
   manifest, and rejects Markdown code fences outright (**I-B4**) — an LLM that
   wraps its answer in ```` ```diff ```` has produced a *string*, not a patch,
   and a string that nearly parses is more dangerous than one that does not.
2. **Empirical.** `git apply --check` against the real target manifest, in a
   throwaway repository. This is the only layer that knows whether the patch
   applies to *this* file with *this* context (**I-B2**).

Layer 2 has a documented failure mode worth naming, because it is exactly the
kind of bug that produces green builds: an earlier version of the harness
applied the patch to a copy in the repository root instead of the scratch
directory, and `git apply` exited `0` having verified the wrong file. The
harness now asserts the *effect* — that the target file in the scratch tree
changed — rather than the exit status.

## 5. The post-remediation verification loop

A patch that applies is not a patch that works. After a human merges, the agent
re-observes the workload against a bounded policy:

```python
VerificationPolicy(
    watch_duration_seconds=...,        # 60..1800, bounded
    success_criteria=SuccessCriteria(
        no_oomkilled_terminations=True,      # both booleans must be true
        no_crashloopbackoff_wait=True,
        container_uptime_seconds_min=...,
    ),
    on_success="CLOSE_INCIDENT",
    on_repeat_failure="PROMOTE_TO_TIER_2",
    on_indeterminate="REQUEUE_BOUNDED",
    max_requeue_attempts=...,          # 1..10
)
```

Both boolean criteria must hold. An incident does not close while the fault it
was raised for can still recur. The model also rejects
`container_uptime_seconds_min >= watch_duration_seconds`, which would permit
closure without ever having observed enough uptime to conclude anything.

Indeterminate outcomes requeue within a budget — and the budget is
**monotonic**. `RequeueBudget` is deliberately not a rewindable counter: an
attempt number that can be reset is a loop an incident can never leave, and this
system will eventually meet a workload that is genuinely indeterminate for a
long time. When the budget is exhausted, the cause is recorded explicitly
(`OOM_KILLED`, `CRASH_LOOP_BACKOFF`, `UPTIME_BELOW_MINIMUM`,
`REQUEUE_BUDGET_EXHAUSTED`) and escalated to `TIER_2`. Four causes collapse to
one action — a human is needed in every case — but the *reason* is what lets that
human avoid repeating the investigation the agent just did.

## 6. Invariants

Eleven invariants, each with a test that fails the build when it is violated.

**Sentinel → Agent (Contract A)**

| ID | Invariant |
|---|---|
| `I-A1` | No value under `scrubbed_logs` or `cluster_events[].message` contains any corpus-defined secret |
| `I-A2` | `reason == "OOMKilled"` ⟹ `exit_code == 137` and a memory limit is present |
| `I-A3` | `reason == "CrashLoopBackOff"` ⟹ `exit_code` may be null, backoff is observable |
| `I-A4` | `detection_latency_ms <= 2000` (PRD AC-1) |
| `I-A5` | Scrubbing is idempotent: `scrub(scrub(x)) == scrub(x)` |

**Agent → Human (Contract B)**

| ID | Invariant |
|---|---|
| `I-B1` | `TIER_2_ARCHITECTURAL` ⟹ `git_patch == ""` and `patch_validated == false` |
| `I-B2` | `patch_validated == true` ⟹ `git apply --check` exited `0` against the target |
| `I-B3` | `incident_id` round-trips unchanged from Contract A |
| `I-B4` | Non-JSON model output is a **fatal** failure — no partial acceptance |
| `I-B5` | Neither contract has any field capable of expressing a cluster write verb |
| `I-B6` | Every response string passes the agent-side defensive re-scan |

## 7. Verification without a cluster

The most common way to get a systems project into trouble is to make the
interesting paths testable only against real infrastructure. SREK3S is
structured so the interesting paths are the offline ones.

| Layer | What it exercises | Cluster required |
|---|---|---|
| Go unit + race | Scrubber, classifier, telemetry, pool, nil-safety | No |
| Python unit | Schemas, invariants, patch grammar, sandbox limits, budget | No |
| Corpus replay | 46 secret-shaped cases through the real 11-rule pipeline | No |
| Golden fixtures | Byte-identical diff and RCA output | No |
| Offline `git apply` | Real `git apply --check` in a scratch repo | No |
| E2E detonation | Informer → scrub → egress → classify → patch → verify | Yes (k3s) |

The E2E workflow installs k3s, plants a memory leak, and asserts the entire
chain — including that a planted secret did not survive scrubbing, that
scrubbing *did* mask something, and that masking preserved diagnostic evidence.
"Masked everything" and "masked nothing" are both failures, and both are asserted.

Two of the 727 Python tests skip locally and print `BLOCKED DEPENDENCY, not a
pass`. They need a reachable cluster. `go test -race` and the container build are
likewise CI-only on hosts without ThreadSanitizer or a Docker daemon; this is
reported as blocked rather than checked off.

---

## Testing and gates

| Gate | Command | Scope |
|---|---|---|
| `G1` | `go vet ./...` | Go static analysis |
| `G2` | `gofmt -l .` (empty) | Go formatting |
| `G3` | `go test -race -timeout 30s ./...` | Go units + data races |
| `G4` | `black --check agent/ tests/` | Python formatting |
| `G5` | `flake8 agent/ tests/` | Python style |
| `G6` | `mypy --strict agent/ tests/` | Strict typing |
| M3 | Terminal validation | `TestNilPointerSafety`, `TestNoGoroutineLeak`, `TestIncidentPayloadContract` |
| AC-2 | Corpus replay | 46 cases, 32 maskable |
| AC-4 | Container build + runtime smoke | Asserts UID 10001, imports `main:app` |
| Layout | `test_architecture_layout.py` | `ARCHITECTURE.md` ↔ filesystem parity, both directions |
| Routing | `test_the_agent_service_routes_the_sentinels_default_endpoint` | Service ↔ pod labels ↔ bind port ↔ Sentinel default |
| Workflow | `scripts/audit_workflow.py` | CI definition audit |

Most of these assert a property of a single file. `Routing` asserts a property of
the *set*: that the endpoint the Sentinel is configured with resolves, through a
Service these manifests create, to a port the agent actually binds. v1.0.0
shipped without it, which is how a deploy set applied cleanly and routed
nowhere passed every gate it had.

The layout validator deserves a note, because it exists because a document was
wrong three separate times and no gate noticed. `ARCHITECTURE.md` named
`tests/fixtures/secrets_corpus.txt` and `internal/k8s/classify.go` — neither had
ever existed — while the entire `internal/worker/` package and ten production
modules shipped undocumented. The suite was green throughout, because no test
read the document. It now asserts in both directions: every path the tree names
must exist, and every production source under the directories the tree enumerates
must be named. A one-way check cannot see an omission.

## Repository map

```
cmd/sentinel/          Go entrypoint; wiring, flags, signal handling
internal/scrubber/     11-rule masking engine, normative order, accounting
internal/k8s/          read-only clientset, informers, classification, telemetry
internal/worker/       bounded worker pool; every send selected on ctx.Done()
internal/emitter/      ULID incident ids, wire validation, ctx-bounded HTTPS
agent/                 FastAPI + Pydantic v2 triage engine, sandbox, verification
deploy/                k3s manifests; service.yaml routes to the agent;
                       chaos/ holds the deliberate-failure fixtures
tests/fixtures/        incident corpus, chaos manifests, golden expected output
scripts/               audit_workflow.py — audits the CI definition itself
docs/                  runbook, lessons learned, offline install, CI triage
```

`ARCHITECTURE.md` §3 carries the authoritative layout tree, and
`agent/tests/test_architecture_layout.py` fails the build if it drifts from disk
in either direction.

---

MIT licensed. See [`LICENSE`](LICENSE).
