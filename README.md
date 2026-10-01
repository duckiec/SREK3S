# SREK3S — Autonomous Reliability Firewall

SREK3S watches a Kubernetes cluster for container failures, produces a root-cause
analysis, and — when the cause is unambiguous and the fix is a one-line resource
change — emits a verified unified `git diff` for a human to merge. It never
writes to the cluster. That is enforced by the cluster, not by convention.

**Status:** MVP sealed — 811 Python tests + 179 Go test functions green and all CI gates
passing **on GitHub Actions `ubuntu-latest`**. That platform, not any single developer
machine, is where those numbers come from; see [Runtime baseline](#runtime-baseline) for
what the local host can and cannot add. [`ROADMAP.md`](ROADMAP.md) records per-milestone
evidence; [`docs/lessons-learned.md`](docs/lessons-learned.md) records the defects found
along the way, including the ones a passing gate failed to catch.

> **Contributing, or want to understand the engine?** Read
> **[`ENGINEERING.md`](ENGINEERING.md)** first. It is a technical breakdown of *why* the
> system is built this way — the fail-closed tier routing, the model boundary, the
> zero-leakage scrubber, and the testing methodology — written for the maintainer who
> arrives later and cannot tell whether a tempting simplification is safe.

---

## Quick Start

Four commands. Everything below is optional detail.

```bash
git clone https://github.com/OWNER/SREK3S.git && cd SREK3S

make doctor      # check the host BEFORE anything else; readable failures, no stack traces
make bootstrap   # create .venv311, install Python deps, download Go modules
make test        # the full gate sweep: go vet, gofmt, race detector, black, flake8, mypy --strict, pytest
make deploy      # apply the base manifests and wait for both rollouts
```

`make doctor` is the one worth running first. It detects the OS and architecture,
verifies `docker`/`buildx`, Go, and a **3.11+** Python, and distinguishes a stopped
Docker daemon from one your user simply cannot reach — which are different problems
with different fixes, and the raw error for both is the same socket message.

```bash
Platform       [ ok ] OS         Linux Fedora Linux 44
               [ ok ] arch       aarch64 (aarch64)
docker 29.8.2 · buildx v0.37.1 · [ ok ] go 1.26.8 · [ ok ] python 3.11.16 (.venv311)
✓ all required dependencies present
```

<details>
<summary>All targets — run <code>make help</code></summary>

| Target | Does |
|---|---|
| `make doctor` | Host pre-flight check (`scripts/bootstrap.sh`) |
| `make bootstrap` | Create `.venv311`, install deps, `go mod download` |
| `make test` | Every gate: Go (vet, gofmt, `-race`) then Python (black, flake8, `mypy --strict`, pytest) |
| `make build` | Both images via `buildx`, host architecture by default |
| `make verify-images` | Build, then **execute** each image's entrypoint |
| `make push-multiarch` | `linux/amd64` + `linux/arm64` manifest list (needs a registry) |
| `make deploy` / `make undeploy` | Apply / remove `deploy/base` |
| `make deploy-overlay` | Apply the local-live overlay (scopes the Sentinel to `sentinel-chaos`) |
| `make chaos` | Deploy the real-crash chaos workload |
| `make clean` | Delete the chaos namespace and `.venv311` — **never** the system namespace |

Cross-build for another architecture:

```bash
make build PLATFORM=linux/amd64
```

</details>

### The Gemini API key (optional, and genuinely optional)

SREK3S runs **without** a model. Tier, patch, and every validation flag are computed
deterministically; the model, when present, only writes the prose in a Tier-2 root-cause
explanation that a human already has to read. If you skip this section, nothing is
degraded except the fluency of one paragraph.

```bash
# Local work: a .env or .env.local in the repository root, both gitignored.
echo 'GEMINI_API_KEY=your-key' > .env.local

# In-cluster: a Secret the Agent reads via valueFrom.
kubectl -n srek3s-system create secret generic srek3s-secrets \
  --from-literal=GEMINI_API_KEY="$(sed -n 's/^GEMINI_API_KEY=//p' .env.local)"
kubectl -n srek3s-system rollout restart deployment/srek3s-agent
```

The manifest reference is `optional: true` on purpose. Without it, a cluster with no
Secret produces pods stuck in `CreateContainerConfigError`, because a missing `keyRef`
is an **admission failure, not a missing environment variable** — meaning an operator
who wants no model at all could not run the agent. With it, an absent Secret leaves the
variable unset and the agent behaves exactly as it did before.

To send the model raw log text — which is what makes an RCA worth reading — set
`SREK3S_LOG_TEXT_EVIDENCE=true`. It defaults to **off**, because sending
container-controlled text to a third party should be a deliberate act.

> **The agent also needs egress on TCP 443.** `deploy/agent.yaml` grants it, and that
> rule is the only non-DNS egress this pod has. It is `0.0.0.0/0` because a
> NetworkPolicy selects namespaces, pods, or CIDRs — and an external provider has no
> stable CIDR. See the comment in the manifest for the reasoning and the cost.

---

## What makes this different from a logging tool

A log aggregator tells you what a container printed. SREK3S tells you **what to do about
it**, and is built so that being wrong is expensive:

**It cannot change your cluster.** Not by policy — structurally. The Sentinel's
ServiceAccount is bound to a Role enumerating `["get","list","watch"]`, and the Agent
has no ServiceAccount token at all. A CI check reads the schema with `ast` and fails the
build if any field is shaped like a write verb. There is no code path that reaches
`kubectl apply`, because there is nothing to call it with.

**It proposes a diff, never applies one.** When the cause is unambiguous and the fix is
a single resource value, it emits a unified `git diff` that survives both a structural
YAML AST check *and* an in-sandbox `git apply --check` against the real target manifest.
Unverifiable is not "emit it anyway" — it is **discard it and escalate**. An agent that
proposes something it cannot prove is worse than one that stays quiet.

**Everything is masked before it leaves the process.** Telemetry is scrubbed in memory
on the Go node — never on disk, never in a queue. Credentials, tokens, and PII are
replaced with `[REDACTED]` while the endpoint topology around them is preserved, because
a diagnosis that cannot name the host it was talking to is not a diagnosis.

**When it is not sure, it stops.** `UNKNOWN` classification, an unreadable target, a
patch that will not verify — each one escalates to a human war-room dispatch with
`git_patch: ""`. The blast radius of a mistake is a paragraph somebody reads, not a
change somebody discovers in production.

**The model cannot change any of that.** A model is consulted only after the tier is
decided. The response schema it receives has no field for a tier or a patch, so a
model physically cannot return one. If you feed it a prompt injection hidden in a
crash log, the worst outcome is a badly-worded paragraph inside an escalation a human
already owns.

---

## Getting started

### Prerequisites

| | |
|---|---|
| Go | 1.23+ (`go.mod` pins 1.23). Local: `go version go1.26.8-X:nodwarf5 linux/arm64` (resolves to `/usr/sbin/go`; see [Runtime baseline](#runtime-baseline)). |
| Python | **3.11, strictly.** 3.12+ syntax is not permitted; formatting is pinned to `target-version = ["py311"]` and `setup.cfg` sets `python_version = 3.11`. Use the pinned virtualenv `~/SREK3S/.venv311`, not the system `python3`. |
| Cluster | Any conformant cluster. CI uses k3s; locally, k3s v1.36.4+k3s1. |
| `git` | Required in the agent image — patch validation runs `git apply --check`. |
| Docker | Required to build the images. `sudo docker` on this host — see [Runtime baseline](#runtime-baseline). |
| `gcc` | Needed for `go test -race`. Present here; absent on the previous host. |
| Platform | Images target `linux/arm64` locally, `linux/amd64` in CI. |

### Build

```bash
go build -o bin/sentinel ./cmd/sentinel
sudo docker build --platform linux/arm64 \
  -t registry.internal/srek3s-agent:0.1.0    -f agent/Dockerfile .
sudo docker build --platform linux/arm64 \
  -t registry.internal/srek3s-sentinel:0.1.0 -f cmd/sentinel/Dockerfile .
```

Both images take the **repository root** as their build context — a context of
`agent/` or `cmd/sentinel/` fails at the `COPY`, because the module and the
packages being compiled live outside those directories. The Sentinel's image is
`gcr.io/distroless/static` rather than `scratch`: no shell, no libc, no package
manager, but it does carry CA certificates, which `scratch` does not — without
them an `https://` agent endpoint fails certificate verification and presents as
a network fault.

Build locally, or on `amd64` CI, or not at all: a wrong-platform image and a
missing image produce the **same** `ImagePullBackOff`. Check which you have with
`sudo k3s ctr images ls --namespace k8s.io`.

Running the binary directly is enough for development:

```bash
./bin/sentinel -agent-url http://127.0.0.1:8001 -namespace default
```

### Deploy

```bash
sudo kubectl apply -k deploy/
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

> ### Two things to know before you read "silence" as "healthy"
>
> **1. `WATCH_NAMESPACE: ""` is committed, and the `Role` is namespaced.** `deploy/sentinel.yaml`
> configures the Sentinel to watch *all* namespaces while `deploy/rbac.yaml` grants it a
> `Role` in `srek3s-system` only — no `ClusterRole`, no `ClusterRoleBinding`. A cluster-wide
> `LIST` is therefore **unauthorised**, and the symptom is not an error: the informer retries
> and reports nothing at all. **Set `WATCH_NAMESPACE` to a namespace, and put a matching
> `Role` + `RoleBinding` in that namespace.** The commands are in
> [`docs/runbook.md`](docs/runbook.md) §1 — "RBAC is namespace-scoped, and that is
> deliberate" — and they are not duplicated here, because the reasoning behind them matters
> more than the commands. **Found by static analysis on 2026-10-01; not yet reproduced at
> runtime.**
>
> **2. The agent's manifest root ships empty, so Tier-1 is unreachable.** `deploy/agent.yaml`
> mounts `/manifests` and points `SREK3S_MANIFEST_ROOT` at it, but the volume is an
> `emptyDir`, and the default target `deploy/payments/checkout-api.yaml` **does not exist in
> this repository**. The agent cannot read a manifest, so every incident escalates to
> Tier-2 with `git_patch == ""` and `patch_validated == false`. That is fail-closed design
> working (invariant **I-B2**) — but it looks exactly like a working setup, which is why the
> manifest and the runbook both say so in those words. Populate it with your real GitOps
> checkout and point `SREK3S_TARGET_MANIFEST` inside it to enable Tier-1.
>
> **An in-cluster run therefore demonstrates the Tier-2 war-room path and the no-mutation
> guarantee. It cannot demonstrate a Tier-1 patch until that checkout is wired.** Offline,
> against `tests/fixtures/`, Tier-1 is fully exercised — real `git apply --check` and golden
> diffs — so this is a deployment-wiring gap, not an implementation gap.

**RBAC is namespace-scoped by design.** `deploy/rbac.yaml` grants the Sentinel a
`Role` in `srek3s-system` and nowhere else — no `ClusterRole`, no
`ClusterRoleBinding`. Monitoring any other namespace means applying the same
read-only `Role` plus a `RoleBinding` **into that namespace**, pointing at the
ServiceAccount in `srek3s-system`. The runbook has the commands and the
verification.

**The images are placeholders.** The manifests reference
`registry.internal/srek3s-{agent,sentinel}:0.1.0`. Those tags are placeholders the
release pipeline rewrites in the committed file, so applying the set against a
cluster that cannot pull them yields `ImagePullBackOff`. For the verified `pull` +
`tag` path into a local containerd, and for the **unverified** air-gapped path this
host is now *able* to test, see [`docs/offline-install.md`](docs/offline-install.md).

### Publishing

`git tag v1.0.0 && git push --tags` publishes both images to GitHub Container
Registry as `linux/amd64` + `linux/arm64` manifest lists, using the default
`GITHUB_TOKEN` — no registry credential is stored in this repository.

```bash
ghcr.io/OWNER/srek3s-sentinel:1.0.0    # pin this
ghcr.io/OWNER/srek3s-sentinel:latest
ghcr.io/OWNER/srek3s-agent:1.0.0
ghcr.io/OWNER/srek3s-agent:latest
```

Two things to know before using them. **`:latest` moves** — pin the version tag for
anything you care about. And **the published registry differs from the one in
`deploy/`**: the manifests reference `registry.internal/`, so deploying a released
image means rewriting the image reference, or kustomizing an overlay with an
`images:` block. That asymmetry is deliberate — a committed image tag that a push
could silently change would be worse — but it does mean "released" and "what
`make deploy` applies" are not the same thing today.

### Run the tests

None of this needs a cluster — but on this host, none of it runs as written unless the
interpreter is pinned.

```bash
make test          # all of it, in order: Go (vet, gofmt, -race) then Python
```

Or individually, if you want to know which one broke:

```bash
PY=~/SREK3S/.venv311/bin/python

go test -race ./...                 # -race is runnable here: gcc present on linux/aarch64
$PY -m pytest agent/tests/ -q       # 811 passed, 3 skipped
$PY -m black --check agent/ tests/
$PY -m flake8 agent/ tests/
$PY -m mypy --strict agent/ tests/
$PY scripts/audit_workflow.py       # audits the CI definition itself
```

The 3 skips are a **blocked dependency, not a pass**: a live-cluster round-trip that
needs a reachable apiserver, and this host's kubeconfig is root-owned.

Use the virtualenv. The system `python3` on this host is **3.14.3**, and this
project's Python configuration is pinned the other way: `black` to
`target-version = ["py311"]`, `setup.cfg` to `python_version = 3.11`. `black` infers
target versions from the syntax it finds and that inference is sensitive to the host
interpreter — `agent/pyproject.toml` records the same black version reformatting one
file differently under 3.11 than under 3.14. A `black --check` failure here is a host
artefact until proven otherwise.

`go test -race` was unavailable on the previous `windows/arm64` host — no
ThreadSanitizer — which is why so much of `ROADMAP.md` says "CI-only". That constraint no
longer applies to local runs. It never applied to CI, and `ubuntu-latest` is still where
the published numbers come from.

`mypy --strict` must be run against `agent/` **and** `tests/` together — against
`agent/` alone it reports spurious `import-not-found` errors for the test
fixtures.

The 2 skips are live-cluster tests that print `BLOCKED DEPENDENCY, not a pass`.
They need `kubectl` and a reachable cluster; the offline half of that file is
what ran.

### What is *not* wired, so you do not assume it is

- **No model.** `agent/llm.py` is a validation boundary, not a model client:
  `CompletionClient` is a `typing.Protocol` with no implementation, the module imports no
  network library, and `fastembed`/`onnxruntime` exist only in a comment in
  `requirements.txt`. Every RCA and diff is deterministic. (`ARCHITECTURE.md` §5.5.2.)
- **No post-remediation loop in the service.** `agent/verify.py` is implemented and heavily
  tested but **imported by no production module**; `triage.py` emits `verification_policy`
  and nothing consumes it. The loop is not reachable from the running HTTP service.
  (`ARCHITECTURE.md` §5.5.1.)

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

- [Quick Start](#quick-start)
- [What makes this different from a logging tool](#what-makes-this-different-from-a-logging-tool)
- [Runtime baseline](#runtime-baseline)
- [Getting started](#getting-started)
- [The problem: the LLM blast-radius gap](#the-problem-the-llm-blast-radius-gap)
- [What SREK3S actually does](#what-srek3s-actually-does)
- [Data flow](#data-flow)
- [Engineering deep dive](#engineering-deep-dive)
  - [1. Zero cluster mutation is structural](#1-zero-cluster-mutation-is-structural)
  - [2. The in-memory scrubber](#2-the-in-memory-scrubber)
  - [3. The ephemeral, resource-capped sandbox](#3-the-ephemeral-resource-capped-sandbox)
  - [4. Fail-closed Tier 1 / Tier 2 routing](#4-fail-closed-tier-1--tier-2-routing)
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
   the incident or promotes it to `TIER_2`. **Step 7 is specified and unit-tested but not
   reachable from the running service** — see [§5](#5-the-post-remediation-verification-loop)
   and `ARCHITECTURE.md` §5.5.1.

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
seconds and cannot express a fraction. `ARCHITECTURE.md` §5.5.3, `ROADMAP.md`
`ENV-2.8`/`ENV-2.9`.

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

> **Not wired into the running service.** `agent/verify.py` (741 lines) implements
> this loop and is covered by the sixty tests recorded in `ROADMAP.md` box `4.3.2`,
> plus a live-k3s leg that applied a
> real diff and observed both verdicts. But **no production module imports it**:
> `main.py` and `triage.py` do not. `triage.py` emits `verification_policy` and
> nothing in the service consumes it. The code below is the design and the schema
> contract; it is not a description of a running loop. `ARCHITECTURE.md` §5.5.1,
> `ROADMAP.md` `ENV-2.7`.

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

Three of the 811 Python tests skip locally and print `BLOCKED DEPENDENCY, not a
pass`. They need a reachable cluster. On the current `Fedora 44` / `linux/aarch64`
host `go test -race` and the container build are **no longer** blocked — `gcc` is
installed and Docker is running (behind `sudo`) — so they can be run locally and
must be *reported as run*, not as blocked. On the earlier `windows/arm64` host
neither was available, which is why so much of `ROADMAP.md` reads "CI-only";
those records are left intact.

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
| Manifests | `test_deploy_manifests.py` | PSA compliance, RBAC shape, hardening block |
| Chaos fixtures | `test_chaos_fixtures.py` | **Executes** each fixture's script; asserts the failure is the one under test |
| Images | `test_sentinel_image.py` | Stage split, `CGO_ENABLED=0`, cross-compile ARGs |
| Workflows | `test_workflows.py` | Triggers, `needs:` resolution, multi-arch coverage, least privilege |
| Multi-arch | CI `multi-arch-dry-run` job | `linux/amd64` + `linux/arm64`, `output: type=cacheonly` |

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
scripts/               audit_workflow.py — audits the CI definition itself;
                       bootstrap.sh — host pre-flight (make doctor)
.github/workflows/     ci.yaml (gates + multi-arch dry run), release.yaml (GHCR),
                       e2e-detonation.yaml (live cluster)
ENGINEERING.md         the fail-closed argument, for people who will change it
docs/                  runbook, lessons learned, offline install, CI triage
```

`ARCHITECTURE.md` §3 carries the authoritative layout tree, and
`agent/tests/test_architecture_layout.py` fails the build if it drifts from disk
in either direction.

---

MIT licensed. See [`LICENSE`](LICENSE).

---

## Runtime baseline

The development host is **WSL2 on an ARM64 Windows machine, distribution
`Fedora Linux 44 (aarch64)`**, with a live single-node k3s **v1.36.4+k3s1** and Docker
**29.8.2**. Four consequences, none of them optional:

| | |
|---|---|
| **Images must be `linux/arm64`.** | CI builds `amd64`. A local image and a CI image are not the same artifact. |
| **`sudo docker …`** | `duckie` is in `wheel` but not in the `docker` group; `/var/run/docker.sock` is `root:docker`. Plain `docker` fails with `permission denied while trying to connect to the docker API`. |
| **`sudo kubectl …`** | The k3s kubeconfig is mode `0600` and root-owned. Every `kubectl` call needs it. |
| **Python gates run in `.venv311`.** | The system `python3` here is 3.14.3 and is **not** a valid interpreter for this project. Use `~/SREK3S/.venv311/bin/python -m pytest`. |

`go test -race` is now runnable locally (`gcc` is present on `linux/aarch64`), which it was
not on the earlier `windows/arm64` host. **CI on `ubuntu-latest` remains the platform
authority** for every published figure; a local pass is extra evidence, never a
substitution. The full environment of record is in
[`ROADMAP.md`](ROADMAP.md) § *Local Environment Baseline*.

---
