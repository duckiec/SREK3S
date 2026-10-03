# SREK3S

**A fail-closed, AI-powered Site Reliability Engineer for your Kubernetes cluster.**

[![CI](https://github.com/duckiec/SREK3S/actions/workflows/ci.yaml/badge.svg?branch=main)](https://github.com/duckiec/SREK3S/actions/workflows/ci.yaml)
[![Release](https://github.com/duckiec/SREK3S/actions/workflows/release.yaml/badge.svg)](https://github.com/duckiec/SREK3S/actions/workflows/release.yaml)
[![Multi-arch](https://img.shields.io/badge/platform-linux%2Famd64%20%7C%20linux%2Farm64-4655db)](https://github.com/duckiec/SREK3S)
[![Go](https://img.shields.io/badge/go-1.25%2B-00ADD8?logo=go)](https://go.dev)
[![Python](https://img.shields.io/badge/python-3.11-3776AB?logo=python)](https://www.python.org)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-924%20passed%20%7C%20179%20go-success)](https://github.com/duckiec/SREK3S/actions/workflows/ci.yaml)

It reads your crashing containers, works out *why*, and hands you a reviewed
`git diff`. **It can never change your cluster** — enforced by RBAC, not by
convention.

---

## Quick Start

```bash
git clone https://github.com/duckiec/SREK3S.git && cd SREK3S
make doctor      # verify the host: OS, arch, docker+buildx, go, python 3.11+
make bootstrap   # create .venv311, install deps, download Go modules
make test        # full gate sweep: go vet, gofmt, -race, black, flake8, mypy, pytest
make deploy      # apply the manifests and wait for both rollouts
```

Done. Watch it work with a real crash:

```bash
make deploy-overlay            # scope the sentinel to the chaos namespace
make chaos                     # deploy a real crashing app with a planted secret
kubectl -n sentinel-chaos logs deploy/real-crash   # the raw log, credential and all
kubectl -n srek3s-system logs deploy/srek3s-sentinel -f | grep stats
```

> `make clean` tears down the chaos namespace. It deliberately **will not** delete
> `srek3s-system` — that is someone's deployment, and "clean" is the word someone
> types while annoyed.

---

## Core Features

| | |
|---|---|
| **🔒 Zero-leakage secret scrubbing** | Telemetry is masked **in memory, on the Go node, before any network egress** — 11 enumerated rules, never on disk, never in a queue. Redaction is *selective within the match*, so `postgres://checkout:[REDACTED]@db.internal:5432/prod` loses the password and keeps the diagnosis. |
| **🧯 Fail-closed by construction** | An unverifiable patch is **discarded**, never emitted with a caveat. Unknown classification, unreadable manifest, or a diff that fails `git apply --check` — each escalates to a human war-room with `git_patch: ""`. Tier-2 is the designed resting state, not a failure. |
| **🧫 Prompt-injection defense** | The model's response schema has **no field for a tier or a patch**, so it physically cannot return authority. Rules ride in a native `system_instruction` field, never concatenated with the evidence — anyone who can write to a crashing container's stdout can print text that looks like an instruction. |
| **📦 GitOps auto-patching** | Tier-1 emits a unified diff that survived both a structural YAML AST check *and* a real `git apply --check` against the target manifest's own bytes. For a human to merge. Never applied. |
| **🚫 Zero cluster write authority** | The Sentinel's Role enumerates `["get","list","watch"]`. The Agent has no ServiceAccount token at all. A CI job `ast`-walks the schema and fails the build if any field is shaped like a write verb. |
| **🐳 Multi-arch, one command** | `linux/amd64` and `linux/arm64` via BuildKit cross-compilation. CI proves both compile on **every pull request**; a `v*` tag publishes a real manifest list to GHCR. |
| **🧪 Tested against a live cluster** | Planted credentials and adversarial stack traces in a real crashing workload, detected naturally through the Kubernetes API. Not a mocked payload. |

---

## How It Works

```
   pod crashes
       │
       ▼
┌──────────────────────┐
│  SREK3S Sentinel     │  watches pods + events via read-only informers
│  (Go, read-only)     │  scrubs every log line IN MEMORY before egress
└──────────┬───────────┘
           │  Contract A — scrubbed incident payload
           ▼
┌──────────────────────┐
│  SREK3S Agent        │  deterministic classifier → tier routing
│  (Python, stateless) │  Tier-1 only if the diff VERIFIES twice
└──────────┬───────────┘
           │
     ┌─────┴──────────────────────────────┐
     │                                     │
     ▼                                     ▼
┌────────────────┐              ┌────────────────────┐
│  TIER 1 TOIL   │              │  TIER 2 ARCHITECT. │
│                │              │                    │
│  verified diff │              │  git_patch: ""     │
│  for a human   │              │  war-room dispatch │
│  to merge      │              │  + verification    │
└────────────────┘              │    policy          │
                                └─────────┬──────────┘
                                          │ optional: a model writes the
                                          │ *prose* of the explanation. It
                                          │ cannot set the tier, the patch,
                                          │ or any validation flag.
                                          ▼
```

**Tier-1 requires two independent verifications:** a structural YAML AST check, and
a real `git apply --check` against the target manifest's own bytes. If either fails,
the patch is thrown away and the incident escalates.

---

## Optional: a model, from any provider

**The system runs fine without one.** Tier, patch, and every validation flag are
computed deterministically; a model — when present — writes only the prose in a
Tier-2 explanation a human already has to read. It cannot return a tier or a
patch, because the schema it is handed has no field to return one in.

| Variable | Default | Purpose |
|---|---|---|
| `LLM_PROVIDER` | `gemini` | `gemini` or `openai`. Any server speaking the OpenAI chat-completions protocol works. |
| `LLM_BASE_URL` | *(provider default)* | Repoints the OpenAI-protocol adapter at a local **Ollama, vLLM or LM Studio** endpoint. |
| `LLM_MODEL` | per provider | Model name. `GEMINI_MODEL` wins if set, so an existing pin keeps working. |
| `GEMINI_API_KEY` / `OPENAI_API_KEY` | — | One credential. Absent means "no model", not "no agent". |

```bash
# locally: .env or .env.local, both gitignored
echo 'GEMINI_API_KEY=your-key' > .env.local

# in-cluster: a Secret the agent reads via valueFrom
kubectl -n srek3s-system create secret generic srek3s-secrets \
  --from-literal=GEMINI_API_KEY="$(sed -n 's/^GEMINI_API_KEY=//p' .env.local)"
kubectl -n srek3s-system rollout restart deployment/srek3s-agent
```

Fully self-hosted, no egress and no key:

```yaml
env:
  - name: LLM_PROVIDER
    value: openai
  - name: LLM_BASE_URL
    value: http://ollama.srek3s-system.svc:11434/v1
```

> **A local endpoint is not wired through by default.** The NetworkPolicy in
> `deploy/agent.yaml` permits egress on **TCP 443** to `0.0.0.0/0` and nothing
> else, so Ollama's `11434` or vLLM's `8000` is refused by the network rather
> than by the code. Widening that rule is an egress decision with a real blast
> radius, so it is yours to make deliberately.

`optional: true` on the Secret reference is load-bearing — without it a cluster
with no Secret produces pods stuck in `CreateContainerConfigError`, and an
operator who wants no model at all could not run the agent.

To send raw log text to the model (which is what makes an RCA worth reading), set
`SREK3S_LOG_TEXT_EVIDENCE=true`. It defaults to **off** — sending
container-controlled text to a third party should be deliberate.

> The agent needs egress on **TCP 443**. `deploy/agent.yaml` grants it, and that is
> the only non-DNS egress the pod has.

---

## Documentation & Philosophy

The reasoning behind all of the above lives in documents written for people who
will *change* this system:

| | |
|---|---|
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | **Start here if you intend to contribute.** The four non-negotiable invariants, and what `make test` is expected to catch. |
| [`docs/runbook.md`](docs/runbook.md) | Operational: deploy, watch, interpret, review. |
| [`docs/lessons-learned.md`](docs/lessons-learned.md) | Every defect found — **including the negative controls that failed for the wrong reason.** The most useful file in the repo. |
| [`docs/offline-install.md`](docs/offline-install.md) | Installing the images without a registry. |
| [`docs/ci-triage-protocol.md`](docs/ci-triage-protocol.md) | Reading a red CI run. |

<details>
<summary><b>Why fail-closed (the long version)</b></summary>

## What makes this different from a logging tool

A log aggregator tells you what a container printed. SREK3S tells you **what to do
about it**, and is built so that being wrong is expensive.

**It cannot change your cluster.** Not by policy — structurally. The Sentinel's
ServiceAccount is bound to a Role enumerating `["get","list","watch"]`, and the
Agent has no ServiceAccount token at all. A CI check reads the schema with `ast` and
fails the build if any field is shaped like a write verb.

**It proposes a diff, never applies one.** When the cause is unambiguous and the fix
is a single resource value, it emits a unified `git diff` that survives both a
structural YAML AST check *and* an in-sandbox `git apply --check`. Unverifiable is
not "emit it anyway" — it is **discard it and escalate**. An agent that proposes
something it cannot prove is worse than one that stays quiet.

**Everything is masked before it leaves the process.** Credentials, tokens, and PII
are replaced with `[REDACTED]` while the endpoint topology around them is preserved,
because a diagnosis that cannot name the host it was talking to is not a diagnosis.

**When it is not sure, it stops.** The blast radius of a mistake is a paragraph
somebody reads, not a change somebody discovers in production.

**The model cannot change any of that.** It is consulted only after the tier is
decided, and the schema it receives has no field for a tier or a patch.

</details>

<details>
<summary><b>The problem this solves</b></summary>

## The problem: the LLM blast-radius gap

Every automated SRE tool faces the same asymmetry. When it is right, someone saves an
hour. When it is wrong, it changes production, and the person who has to notice is
asleep. Conventional tooling resolves this by being conservative in *what it does* —
it alerts more, automates less — which drifts toward a dashboard with natural
language on it.

SREK3S takes the opposite position: **the safe outcome is not "do less", it is
"arrive at a human having proved something."**

</details>

<details>
<summary><b>What SREK3S actually does, and the data flow</b></summary>

### What SREK3S actually does

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
   the incident or promotes it to `TIER_2`. **Step 7 is specified and unit-tested but not
   reachable from the running service** — see [§5](#5-the-post-remediation-verification-loop).

Steps 6 and 7 are the difference between a demo and a system. A patch that was
never applied looks identical to a patch that fixed nothing, until you check.


### Data flow

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

</details>

<details>
<summary><b>Engineering deep dive — the seven properties</b></summary>

### 1. Zero cluster mutation is structural

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

**And scope has to agree with the grant.** The `Role` lives in `srek3s-system`, so
the Sentinel is authorised to read exactly that namespace. `deploy/sentinel.yaml`
ships `WATCH_NAMESPACE: ""`, which asks it to read **all** of them. Those two are
inconsistent as committed, and the failure is silent — see the callout under
[Deploy](#deploy). Neither RBAC test catches it, and the reason is worth naming:
both are scoped to the namespace the `Role` lives in, so neither compares that
namespace against the configured watch scope. Two individually-correct assertions
over two individually-correct manifests, wrong in composition.

The fix is two-sided, and deliberately **not** a `ClusterRole`. Scope
`WATCH_NAMESPACE` to a namespace and put a `Role` + `RoleBinding` there, pointing
back at the ServiceAccount in `srek3s-system`
([`docs/runbook.md`](docs/runbook.md) §1). One narrow `Role` per namespace is the
intended shape.


### 2. The in-memory scrubber

Eleven rules, in a **normative order** fixed by the compiled manifest in
`internal/scrubber/manifest.go`, and asserted by `TestManifestMatchesSpecification`:

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


### 3. The ephemeral, resource-capped sandbox

LLM inference and regex analysis are untrusted compute. The agent runs them in a
disposable process (`python -m sandbox_worker`) with `RLIMIT_AS` at 256 MiB and
`RLIMIT_CPU` at 1 CPU-second, and in-cluster under a `256Mi` / `500m` cgroup. The
worker holds no state between invocations, so there is nothing to leak between
incidents.

Those rlimits are the real enforcement — they are installed before `exec` and
cannot be raised from inside. The cgroup is not: the runner probes for a delegated
cgroup v2 hierarchy and writes `memory.max` / `cpu.max` *after* `subprocess.run`
has returned, so those ceilings land after the child they would bound has already
exited. `cgroup_enforced` reports whether the writes succeeded; it does not claim
they bounded anything. The prose saying "500 ms of CPU" is also wrong against
`DEFAULT_CPU_SECONDS = 1`, which is one CPU-*second* — `RLIMIT_CPU` counts CPU
seconds and cannot express a fraction. See `agent/sandbox.py` and its
`DEFAULT_CPU_SECONDS`.

Saturation is shed, not queued. An atomic job budget caps concurrent
investigations; a request arriving at a full sandbox gets HTTP `429` with
`{"error": "sandbox_busy"}` immediately. Queueing would convert a capacity limit
into a latency problem and eventually into probe failures.

The CPU limit is small on purpose. A large value would be more defensible if the
workload were CPU-trivial; the ceiling exists to bound blast radius, not to
accommodate a slow analysis.


### 4. Fail-closed Tier 1 / Tier 2 routing

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


### 5. The post-remediation verification loop

> **Not wired into the running service.** `agent/verify.py` implements this loop
> and is covered by `agent/tests/test_verify.py` and
> `agent/tests/test_verification_e2e.py`, plus a live-k3s leg that applied a
> real diff and observed both verdicts. But **no production module imports it**:
> `main.py` and `triage.py` do not. `triage.py` emits `verification_policy` and
> nothing in the service consumes it. The code below is the design and the schema
> contract; it is not a description of a running loop. Open task: `ENV-2.7`.

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


### 6. Invariants

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


### 7. Verification without a cluster

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
| E2E in-cluster | `deploy/` applies; Service DNS, RBAC, hardening, live | Yes (k3s) |

The E2E detonation workflow installs k3s, plants a memory leak, and asserts the entire
chain — including that a planted secret did not survive scrubbing, that
scrubbing *did* mask something, and that masking preserved diagnostic evidence.
"Masked everything" and "masked nothing" are both failures, and both are asserted.

The **in-cluster leg** exists because the detonation leg runs the Sentinel, the
agent and the capture proxy as host processes on loopback, and applies nothing
from `deploy/`. The Service, both NetworkPolicies, the Role and the container
hardening were therefore never executed by any job. The in-cluster leg applies
`deploy/` through `tests/e2e/fixtures/incluster/`, then asserts that the Service
publishes ready endpoints, that cluster DNS resolves `srek3s-agent` and the agent
answers `/healthz`, that the Sentinel's real ServiceAccount is granted reads and
refused writes by a live apiserver, and that the running agent pod is UID 10001
with a read-only root and no mounted token. It does not detonate anything; that
chain is the detonation leg's job, and duplicating it would re-prove a layer that
is not in question to cover one that is.

Four of the Python tests skip and print `BLOCKED DEPENDENCY, not a
pass`. Three need a reachable cluster. The fourth needs a filesystem that folds
case, which is a Windows property — CI is `ubuntu-latest`, so it skips there too. On the current `Fedora 44` / `linux/aarch64`
host `go test -race` and the container build are **no longer** blocked — `gcc` is
installed and Docker is running (behind `sudo`) — so they can be run locally and
must be *reported as run*, not as blocked. On the earlier `windows/arm64` host
neither was available, which is why so much of the delivery history reads
"CI-only"; those records are left intact.

---

</details>

<details>
<summary><b>Prerequisites, manual build, and manual deploy</b></summary>

### Prerequisites

| | |
|---|---|
| Go | 1.25+ (`go.mod` pins 1.25). |
| Python | **3.11, strictly.** 3.12+ syntax is not permitted; formatting is pinned to `target-version = ["py311"]` and `setup.cfg` sets `python_version = 3.11`. Use the pinned virtualenv `.venv311`, not the system `python3`. |
| Cluster | Any conformant cluster. CI uses k3s; locally, k3s v1.36.4+k3s1. |
| `git` | Required in the agent image — patch validation runs `git apply --check`. |
| Docker | Required to build the images. |
| `gcc` | Needed for `go test -race`. |
| Platform | Images target `linux/arm64` locally; CI builds **both** architectures. |

### Build

```bash
go build -o bin/sentinel ./cmd/sentinel
sudo docker build -t registry.internal/srek3s-agent:0.1.0    -f agent/Dockerfile .
sudo docker build -t registry.internal/srek3s-sentinel:0.1.0 -f cmd/sentinel/Dockerfile .
```

Both images take the **repository root** as their build context — a context of
`agent/` or `cmd/sentinel/` fails at the `COPY`, because the module and the packages
being compiled live outside those directories.

> **A wrong-platform image and a missing image produce the *same*
> `ImagePullBackOff`.** Check which one you have with
> `sudo k3s ctr images ls --namespace k8s.io`.

The Sentinel's image is `gcr.io/distroless/static` rather than `scratch`: no shell,
no libc, no package manager, but it does carry CA certificates, which `scratch`
does not — without them an `https://` agent endpoint fails certificate verification
and presents as a network fault.

Running the binary directly is enough for development:

```bash
./bin/sentinel -agent-url http://127.0.0.1:8001 -namespace default
```

### Deploy

```bash
sudo kubectl apply -k deploy/base
```

`deploy/service.yaml` publishes the agent on `srek3s-agent:8000`, which is the
Sentinel's built-in `-agent-url` default. The two are asserted equal — along with
the Service's selector against the agent's pod labels, and its `targetPort` against
the port the agent actually binds — by
`test_the_agent_service_routes_the_sentinels_default_endpoint`.

> ### Two things to know before you read "silence" as "healthy"
>
> **1. The watch scope and the RBAC grant must agree.** A cluster-wide watch with a
> namespaced Role produces **no incidents and no error** — the informer retries a
> forbidden request forever. `deploy/sentinel.yaml` defaults `WATCH_NAMESPACE` to
> `srek3s-system`, which matches the Role as shipped; widening one without the other
> is the classic silent failure.
>
> **2. A NetworkPolicy matching nothing also produces silence, with zero 403s**,
> because no authorization is ever attempted. An RBAC-only check reports the
> deployment healthy while the watcher sees nothing.
>
> **3. Pod Security Admission failures look like an empty cluster.** A manifest
> rejected by PSA `restricted` fails closed, and a fixture rejected at admission is
> worse than no fixture — it reads as "the cluster is quiet". Note that
> `deploy/namespace.yaml` sets `enforce-version: latest`, so PSA is evaluated
> against whatever control plane is running: the same manifests can be admitted on
> k3s 1.36 and refused on 1.29 for a reason that has nothing to do with the code.
> Diagnose the version skew before diagnosing the manifest.

### Publishing

`git tag v1.0.0 && git push --tags` publishes both images to GitHub Container
Registry as `linux/amd64` + `linux/arm64` manifest lists, using the default
`GITHUB_TOKEN` — no registry credential is stored in this repository.

```bash
ghcr.io/duckiec/srek3s-sentinel:1.0.0    # pin this
ghcr.io/duckiec/srek3s-sentinel:latest
ghcr.io/duckiec/srek3s-agent:1.0.0
ghcr.io/duckiec/srek3s-agent:latest
```

Two things to know. **`:latest` moves** — pin the version tag for anything you care
about. And **the published registry differs from the one in `deploy/`**: the
manifests reference `registry.internal/`, so deploying a released image means
rewriting the image reference, or kustomizing an overlay with an `images:` block.

### Run the tests

```bash
make test          # all of it, in order
```

Or individually:

```bash
PY=~/SREK3S/.venv311/bin/python
go test -race ./...                 # 924 Python tests + 179 Go test functions
$PY -m pytest agent/tests/ -q       # 924 passed, 3 skipped
$PY -m black --check agent/ tests/
$PY -m flake8 agent/ tests/
$PY -m mypy --strict agent/ tests/
$PY scripts/audit_workflow.py       # audits the CI definition itself
```

The 3 skips are a **blocked dependency, not a pass**: a live-cluster round-trip that
needs a reachable apiserver, and the development host's kubeconfig is root-owned.

</details>

<details>
<summary><b>What is not wired, so you do not assume it is</b></summary>

### What is *not* wired

**The post-remediation verification loop.** `agent/verify.py` implements the PRD F4
loop and is covered by `agent/tests/test_verify.py` and
`agent/tests/test_verification_e2e.py` — but **no production module imports it**:
`main.py` and `triage.py` do not. `triage.py` emits `verification_policy` on the wire
and nothing in the service consumes it, so PRD F4 and ARCH §5.2 are not reachable
from the running HTTP service.

**Tier-1 auto-patching as deployed.** `SREK3S_MANIFEST_ROOT` mounts an emptyDir, so
as deployed the manifest provider cannot resolve its target file. Every incident
therefore escalates to Tier-2 under I-B2, and no patch is ever proposed
unverified. That is the intended safe state, not a misconfiguration — but it looks
exactly like a working setup.

</details>

<details>
<summary><b>Testing and gates</b></summary>

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
| Routing | `test_the_agent_service_routes_the_sentinels_default_endpoint` | Service ↔ pod labels ↔ bind port ↔ Sentinel default |
| Workflow | `scripts/audit_workflow.py --strict` | Audits every workflow's own shell: `bash -n`, unpiped `curl \| sh`, `producer \| grep -q` SIGPIPE races, multi-command `if` conditions, and referenced paths that do not exist. Runs as the first CI job, so a broken `run:` block is caught before it executes rather than by whoever pushes next. |
| Manifests | `test_deploy_manifests.py` | PSA compliance, RBAC shape, hardening block |
| Chaos fixtures | `test_chaos_fixtures.py` | **Executes** each fixture's script; asserts the failure is the one under test |
| Images | `test_sentinel_image.py` | Stage split, `CGO_ENABLED=0`, cross-compile ARGs |
| Workflows | `test_workflows.py` | Triggers, `needs:` resolution, multi-arch coverage, least privilege |
| Doc links | `test_docs_links.py` | Every `#anchor` in the user-facing docs resolves. Prose has no assertion to fail, so a document can claim a section is reachable when it is not. |
| Multi-arch | CI `multi-arch-dry-run` job | `linux/amd64` + `linux/arm64`, `output: type=cacheonly` |

Most of these assert a property of a single file. `Routing` asserts a property of
the *set*: that the endpoint the Sentinel is configured with resolves, through a
Service these manifests create, to a port the agent actually binds. v1.0.0
shipped without it, which is how a deploy set applied cleanly and routed
nowhere passed every gate it had.

The layout validator deserved a note, and the note is now historical. It existed
because a document was wrong three separate times and no gate noticed: the
architecture document named `tests/fixtures/secrets_corpus.txt` and
`internal/k8s/classify.go` — neither had ever existed — while the entire
`internal/worker/` package and ten production modules shipped undocumented. The
suite was green throughout, because no test read the document. The validator
asserted the documented tree matched the filesystem in both directions.

It was removed when the build-phase documents were extracted from the
repository, because it was the only check in the suite whose subject was a
Markdown file rather than code or a manifest. **No invariant was lost with it:**
not one of its assertions read an RBAC verb, a tier decision, a patch or a
redaction. Every property in this project that is worth protecting is asserted
against `deploy/*.yaml`, the Go sources, or the Python schemas. A gate that can
only fail because a document drifted is not a safety gate.

</details>

<details>
<summary><b>Repository map and runtime baseline</b></summary>

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
scripts/               audit_workflow.py — audits the CI definition itself;
                       bootstrap.sh — host pre-flight (make doctor);
                       gotest.ps1 — Windows-only G3 workaround, retained
.github/workflows/     ci.yaml (audit, Go + Python gates, multi-arch dry run),
                       release.yaml (tag-gated GHCR publish), e2e-detonation.yaml
docs/                  runbook, lessons learned, offline install, CI triage
```

Every gate in this project reads code or manifests. None of them reads a
document, so the layout of `cmd/`, `internal/`, `agent/`, `deploy/` and `tests/`
is free to change without a test failing for a reason that has nothing to do with
whether the system works.

## Runtime baseline

The development host is **WSL2 on an ARM64 Windows machine, distribution
`Fedora Linux 44 (aarch64)`**, with a live single-node k3s **v1.36.4+k3s1** and Docker
**29.8.2**. Four consequences, none of them optional:

| | |
|---|---|
| **Images must be `linux/arm64`.** | CI builds **both** architectures now. A local image and a CI image are still not the same artifact. |
| **`sudo docker …`** | `duckie` is in `wheel` but not in the `docker` group; `/var/run/docker.sock` is `root:docker`. Plain `docker` fails with `permission denied`. `make build` prints both remedies rather than a socket error. |
| **`sudo kubectl …`** | The k3s kubeconfig is mode `0600` and root-owned. Every `kubectl` call needs it. |
| **Python gates run in `.venv311`.** | The system `python3` here is 3.14.3 and is **not** a valid interpreter for this project. `make test` resolves `.venv311` itself. |

`go test -race` is runnable locally (`gcc` is present on `linux/aarch64`), which it was
not on the earlier `windows/arm64` host. **CI on `ubuntu-latest` remains the platform
authority** for every published figure; a local pass is extra evidence, never a
substitution. `docs/runbook.md` records the full environment of record.

</details>

---

## License

[MIT](LICENSE) © 2026 duckie