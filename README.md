# SREK3S

A deterministic, fail-closed Kubernetes SRE agent. It intercepts pod crashes, scrubs telemetry in-memory, and generates structurally verified GitOps patches with strictly zero cluster write authority.

[![CI](https://github.com/duckiec/SREK3S/actions/workflows/ci.yaml/badge.svg?branch=main)](https://github.com/duckiec/SREK3S/actions/workflows/ci.yaml)
[![Release](https://github.com/duckiec/SREK3S/actions/workflows/release.yaml/badge.svg)](https://github.com/duckiec/SREK3S/actions/workflows/release.yaml)
[![Multi-arch](https://img.shields.io/badge/platform-linux%2Famd64%20%7C%20linux%2Farm64-4655db)](https://github.com/duckiec/SREK3S)
[![Go](https://img.shields.io/badge/go-1.25%2B-00ADD8?logo=go)](https://go.dev)
[![Python](https://img.shields.io/badge/python-3.11-3776AB?logo=python)](https://www.python.org)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-1082%20passed%20%7C%20179%20go-success)](https://github.com/duckiec/SREK3S/actions/workflows/ci.yaml)

Prerequisites: Linux or WSL2, Go 1.25+, Python 3.11 (`.venv311`), Docker with
buildx, `git`, `gcc`, and a cluster. CI uses k3s.

## Demo

![SREK3S In-Memory Redaction & Fail-Closed Triage](docs/assets/demo.gif)

*Live execution: A pod leaking an AWS Secret Access Key to container logs is intercepted and scrubbed in-memory by the Go Sentinel before network egress. The Python Agent applies POSIX sandboxing and YAML AST validation, rejecting hallucinated remedies and failing closed to Tier-2 architectural review.*

## Quick Start

```bash
git clone https://github.com/duckiec/SREK3S.git && cd SREK3S
make doctor      # host pre-flight: OS, arch, docker+buildx, go, python 3.11+
make bootstrap   # create .venv311, install agent deps, download Go modules
make test        # every gate: go vet, gofmt, -race, black, flake8, mypy, pytest
make deploy      # apply deploy/base and wait for both rollouts
```

Detonation: a real crashing workload with a planted credential.

```bash
make deploy-overlay   # scope the Sentinel to the chaos namespace
make chaos            # deploy the memory-leak fixture

# the raw container log, credential intact — this is the input
kubectl -n sentinel-chaos logs deploy/real-crash | grep AWS_SECRET

# the Sentinel's output, credential masked — this is what egress carries
kubectl -n srek3s-system logs deploy/srek3s-sentinel -f | grep stats

make clean             # removes the sentinel-chaos namespace and .venv311
```

`make clean` does not remove `srek3s-system` or the container images.

## Data Flow

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

## Security Invariants

Each invariant below is enforced by a test that fails the build. The properties are
stated once here; no other section restates them.

### The Sentinel cannot mutate the cluster

The Sentinel's ServiceAccount binds a namespaced `Role` granting exactly
`["get", "list", "watch"]` on `pods`, `pods/log`, `pods/status`, `events`,
`deployments` and `replicasets`. There is no `ClusterRole` and no
`ClusterRoleBinding`. `pods/log` is listed as a separate subresource: omitting it does
not error, it makes every incident arrive without logs.

The Agent mounts no ServiceAccount token at all
(`automountServiceAccountToken: false`).

Neither the code nor the RBAC is the only layer. Invariant **I-B5** asserts that
neither wire contract contains any field capable of expressing a write verb, so a
patch cannot carry one through the model.

### Secrets are masked before egress

Telemetry is scrubbed in memory on the Go node before any network call. Nothing
unmasked reaches a queue, a disk, or a socket. The 11 rules, in normative order, are
declared in `internal/scrubber/manifest.go` and mirrored as the normative table in
`CONTRIBUTING.md §5`; `test_scrubber_manifest_spec.py` compares the two and fails on
any drift in ID, order or pattern.

Masking is idempotent (**I-A5**): `scrub(scrub(x)) == scrub(x)`, which matters because
the Agent re-scrubs every response string before it leaves (**I-B6**).

Redaction is selective within the match, preserving the endpoint topology a diagnosis
depends on: `postgres://checkout:[REDACTED]@db-primary:5432/prod` keeps the host, the
port, the database and the user.

Order is normative. Structural rules run before the generic `key=value` rule so a
broad pattern cannot re-wrap a span an earlier rule redacted. Cancellation happens at
line boundaries only — a line is either scrubbed to completion or dropped, because a
partially scrubbed line is a credential leak.

### Unverifiable output is discarded

An incident routes to one of two tiers:

| Tier | Condition | Patch |
|---|---|---|
| `TIER_1_TOIL` | Unambiguous, policy-vetted, mechanically fixable, and verified twice | Verified unified diff |
| `TIER_2_ARCHITECTURAL` | Ambiguous, architectural, or unverifiable | **Always empty** |

A `TIER_2_ARCHITECTURAL` response carrying a patch is unrepresentable, not discouraged.
`TriageResponse._enforce_tier2_carries_no_patch` (`agent/models.py:665`) raises on a
non-empty `git_patch` or `patch_validated == true` (**I-B1**).

Escalation is also forced when classification is `UNKNOWN`, when a patch fails either
verification layer, when a model credential is absent, and when a model call fails or
returns nothing.

**Tier-2 is the designed resting state.** A system that proposes a patch it cannot
prove is worse than one that stays quiet, and the default configuration produces
Tier-2 for every incident (see *Not Wired*).

Every `TIER_1` patch passes two independent verifications before it is labelled valid:

1. **Structural** — YAML AST parse of the patched manifest. Markdown-fenced output is
   rejected outright (**I-B4**); a model that wraps its answer in ` ```diff ` has
   produced a string, not a patch.
2. **Empirical** — `git apply --check` against the target manifest's own bytes, in a
   throwaway repository (**I-B2**). This is the only layer that knows whether the patch
   applies to this file with this context.

Layer 2 asserts the *effect* — that the target file in the scratch tree changed — not
`git apply`'s exit status, because an earlier harness verified a copy in the wrong
directory and exited 0.

### The model cannot return authority

Tier selection, the patch, and every validation flag are computed deterministically
before any model is consulted. A model writes prose in a Tier-2 explanation only.

The schema offered to a model has no field for a tier, a patch, or a status. Schema
construction filters to `llm.NARRATIVE_FIELDS`, so an unlisted key is discarded before
the schema exists. `llm.decode_narrative` re-validates the result with
`extra="forbid"`, so a smuggled field is refused by this process rather than being
unlikely upstream.

Rules reach the model in a field the evidence cannot occupy: `system_instruction` for
Gemini, a `system` message role for the OpenAI protocol, a top-level `system` for
Anthropic. Attacker-influenced container output is never concatenated with them.

`SREK3S_LOG_TEXT_EVIDENCE` defaults to **false**, which keeps container-controlled text
out of the model entirely. Operators who want log text in the RCA set it deliberately.

Non-JSON model output is a fatal failure (**I-B4**): no fence stripping, no partial
parse, no best-effort scrape. The caller degrades to deterministic prose.

### Runtime containment

Both containers run as **UID 10001** with a read-only root filesystem,
`allowPrivilegeEscalation: false`, and every Linux capability dropped. The Agent adds
`automountServiceAccountToken: false`.

The Agent's image is `python:3.11-slim`. The Sentinel's is
`gcr.io/distroless/static-debian12` — no shell, no libc, no package manager, and CA
certificates, without which an `https://` agent endpoint fails certificate
verification and presents as a network fault.

Sandboxed analysis runs in a disposable process with `RLIMIT_AS` at 256 MiB and
`RLIMIT_CPU` at 1 CPU-second. The rlimits are installed before `exec` and cannot be
raised from inside. The cgroup is not: the runner probes for a delegated cgroup v2
hierarchy and writes `memory.max` / `cpu.max` after `subprocess.run` returns, so those
ceilings land after the child exits. `cgroup_enforced` reports whether the writes
succeeded and does not claim they bounded anything.

`RLIMIT_CPU` counts CPU seconds and cannot express a fraction; the budget is 1
CPU-second, not 500 ms.

Saturation is shed rather than queued: a request arriving at a full sandbox receives
HTTP `429` with `{"error": "sandbox_busy"}` immediately. Queueing converts a capacity
limit into a latency problem and then into probe failures.

### Network egress

| Pod | Permitted egress |
|---|---|
| Sentinel | TCP 443 to `10.43.0.0/16` and `10.96.0.0/12` (the cluster service CIDRs); TCP 8000 to the Agent pod |
| Agent | UDP and TCP 53 to `kube-system`; TCP 443 to `0.0.0.0/0` |

The Sentinel cannot reach an arbitrary external address. It reaches the API server
through the service CIDRs and nothing else.

The Agent's TCP 443 rule is why a local Ollama on `11434` or vLLM on `8000` is refused
by the network rather than by code. Widening that rule is an egress change with a
cluster-wide blast radius.

Ingress to the Agent is permitted only from pods labelled
`app.kubernetes.io/name: srek3s-sentinel`, on TCP 8000.

### Not Wired

**The post-remediation verification loop.** `agent/verify.py` implements it and is
covered by `test_verify.py` and `test_verification_e2e.py`, including a live-k3s leg
that applied a real diff and observed both verdicts. No production module imports it:
`main.py` and `triage.py` do not, and `triage.py` emits `verification_policy` on the
wire with no consumer. Open task `ENV-2.7`.

**Tier-1 auto-patching as deployed.** `SREK3S_MANIFEST_ROOT` mounts an `emptyDir`, so
the manifest provider cannot resolve its target file. Every incident escalates to
Tier-2 under I-B2 and no patch is proposed. This is the intended safe state and is
indistinguishable from a working installation.

## Model Providers

Tier, patch and every validation flag are computed before any model is consulted. A
model writes prose only. Absent a credential the narrative degrades to deterministic
text and the service continues to triage, route and answer `/healthz`.

| `LLM_PROVIDER` | Credential | Default endpoint | Protocol | Live-verified |
|---|---|---|---|---|
| `gemini` | `GEMINI_API_KEY` | Google AI Studio | Gemini | yes |
| `anthropic` | `ANTHROPIC_API_KEY` | Anthropic Messages | Messages, forced tool-use | no |
| `openai` | `OPENAI_API_KEY` | OpenAI | OpenAI chat-completions | no |
| `openrouter` | `OPENROUTER_API_KEY` | `openrouter.ai/api/v1` | OpenAI chat-completions | no |
| `groq` | `GROQ_API_KEY` | `api.groq.com/openai/v1` | OpenAI chat-completions | no |
| `deepseek` | `DEEPSEEK_API_KEY` | `api.deepseek.com/v1` | OpenAI chat-completions | no |
| `nvidia` | `NVIDIA_API_KEY` | `integrate.api.nvidia.com/v1` | OpenAI chat-completions | yes |
| `ollama` | none required | `localhost:11434/v1` | OpenAI chat-completions | no |
| `vllm` | none required | `localhost:8000/v1` | OpenAI chat-completions | no |

Live-verified means a real credential, a real endpoint and a real response. All nine
are covered by an offline suite that drives the actual SDK over a mock transport, so
the request shape, the auth header, the retry classification and the reply parsing are
asserted against what the SDK builds and accepts rather than against a
re-implementation. For an unverified row, the first real call is the test. A wrong
model id or an unusable token budget presents as no narrative at all, which is the
fail-closed path behaving correctly; the startup line names the resolved provider and
model.

| Variable | Default | Effect |
|---|---|---|
| `LLM_PROVIDER` | `gemini` | One of the nine above. An unrecognised value falls back to `gemini` with a startup warning rather than refusing to start. |
| `LLM_BASE_URL` | the provider's own | Overrides the endpoint: an LM Studio server, a corporate gateway, a private endpoint. |
| `LLM_MODEL` | per provider | The provider-specific pin — `ANTHROPIC_MODEL`, `GROQ_MODEL`, `VLLM_MODEL` — takes precedence. |

### Credential mounting

`deploy/agent.yaml` ships `LLM_PROVIDER` and mounts a credential reference for
`GEMINI_API_KEY` and `NVIDIA_API_KEY` only. Selecting a different provider requires
editing that file to mount the corresponding `[PROVIDER]_API_KEY` from the
`srek3s-secrets` Secret. Setting `LLM_PROVIDER: anthropic` alone yields
`ANTHROPIC_API_KEY is not set`, which reads as a missing Secret rather than a missing
manifest entry.

```yaml
- name: ANTHROPIC_API_KEY
  valueFrom:
    secretKeyRef:
      name: srek3s-secrets
      key: ANTHROPIC_API_KEY
      optional: true
```

References are not mounted in bulk. Every mounted reference is a credential readable
inside the Agent container, so a deployment mounts the one it uses; a cluster switched
to `groq` gains nothing from `NVIDIA_API_KEY` being readable in its pod. `ollama` and
`vllm` require no reference at all.

`optional: true` is required on every reference. Without it a cluster holding no
Secret produces pods stuck in `CreateContainerConfigError`, and an installation that
wants no model cannot start.

### Behaviour

A credential is never accepted by a provider it does not belong to. `OPENAI_API_KEY`
does not authenticate `anthropic`; `ANTHROPIC_API_KEY` does not authenticate `groq`.
An unrecognised credential degrades to deterministic prose rather than reaching a third
party. To use one OpenAI-shaped credential against an aggregator, set
`LLM_PROVIDER=openai` with `LLM_BASE_URL` pointed at that aggregator.

Provider defaults are models confirmed against a live service at the time of writing.
Pin `ANTHROPIC_MODEL`, `NVIDIA_MODEL` and the rest: providers retire models, and a
retired identifier presents as no model configured rather than as an error.

`vllm` carries no default model. A vLLM server serves whatever the operator launched,
so an unset `VLLM_MODEL` is refused before any request, naming the variable to set.

## Gates

| Gate | Command | Scope |
|---|---|---|
| `G1` | `go vet ./...` | Go static analysis |
| `G2` | `gofmt -l .` | Ensures no unformatted files |
| `G3` | `go test -race -timeout 30s ./...` | Go units and data races |
| `G4` | `black --check agent/ tests/` | Python formatting |
| `G5` | `flake8 agent/ tests/` | Python style |
| `G6` | `mypy --strict agent/ tests/` | Strict typing |
| `G7` | `govulncheck ./...` | Reachable CVEs |
| M3 | Terminal validation | `TestNilPointerSafety`, `TestNoGoroutineLeak`, `TestIncidentPayloadContract` |
| AC-2 | Corpus replay | 46 cases across 8 groups, 32 maskable, 6 negative controls |
| AC-4 | Container build and runtime smoke | Asserts UID 10001, imports `main:app` |
| Routing | `test_the_agent_service_routes_the_sentinels_default_endpoint` | Service selector, pod labels, target port and the Sentinel's built-in default resolve to one endpoint |
| Workflow | `scripts/audit_workflow.py --strict` | Every workflow's own shell: `bash -n`, unpiped `curl \| sh`, `producer \| grep -q` SIGPIPE races, multi-command `if` conditions, referenced paths that do not exist |
| Manifests | `test_deploy_manifests.py` | PSA compliance, RBAC shape, hardening block |
| Chaos fixtures | `test_chaos_fixtures.py` | Executes each fixture script and asserts the failure under test |
| Images | `test_sentinel_image.py` | Stage split, `CGO_ENABLED=0`, cross-compile ARGs |
| Workflows | `test_workflows.py` | Triggers, `needs:` resolution, multi-arch coverage, least privilege, gate presence |
| Doc links | `test_docs_links.py` | Every `#anchor` in the user-facing documents resolves |
| Multi-arch | `multi-arch-dry-run` job | `linux/amd64` and `linux/arm64`, `output: type=cacheonly` |

`G7` blocks on vulnerabilities **reachable from this code**: govulncheck exits
non-zero only when a vulnerable symbol is called, which is a stronger condition than a
version-based alert and blocks reachable moderate findings. A CVE present in a
required module that nothing calls is reported and does not block. The step asserts its
own advisory database is reachable before trusting a clean result, because
govulncheck exits 0 and reports no vulnerabilities when it cannot fetch advisories —
indistinguishable, in its output, from a genuinely clean scan.

The skip ratchet holds the Python skip count at 3. The count may fall; a rise fails
the build. The three skips are a blocked dependency, not a pass: two need a reachable
apiserver and one needs a case-folding filesystem.

<details>
<summary><b>Invariant reference</b></summary>

## Contract A — Sentinel to Agent

| ID | Invariant |
|---|---|
| `I-A1` | No value under `scrubbed_logs` or `cluster_events[].message` contains any corpus-defined secret |
| `I-A2` | `reason == "OOMKilled"` implies `exit_code == 137` and a memory limit is present |
| `I-A3` | `reason == "CrashLoopBackOff"` implies `exit_code` may be null and backoff is observable |
| `I-A4` | `detection_latency_ms <= 2000` |
| `I-A5` | Scrubbing is idempotent: `scrub(scrub(x)) == scrub(x)` |

## Contract B — Agent to Human

| ID | Invariant |
|---|---|
| `I-B1` | `TIER_2_ARCHITECTURAL` implies `git_patch == ""` and `patch_validated == false` |
| `I-B2` | `patch_validated == true` implies `git apply --check` exited 0 against the target |
| `I-B3` | `incident_id` round-trips unchanged from Contract A |
| `I-B4` | Non-JSON model output is a fatal failure; no partial acceptance |
| `I-B5` | Neither contract has any field capable of expressing a cluster write verb |
| `I-B6` | Every response string passes the agent-side defensive re-scan |

</details>

<details>
<summary><b>Scrubber: the 11 rules</b></summary>

| # | Rule ID | Target |
|---|---|---|
| 1 | `pem_private_key` | Multi-line PEM blocks, BEGIN…END |
| 2 | `aws_access_key_id` | `AKIA` / `ASIA` / `AROA` and similar, plus 16 characters |
| 3 | `aws_secret_access_key` | Quoted 40-character secret |
| 4 | `jwt` | Three base64url segments |
| 5 | `bearer_token` | `Bearer <token>` |
| 6 | `basic_auth_url` | Password only, inside `userinfo` |
| 7 | `generic_secret_kv` | `key = value` across many key spellings |
| 8 | `uuid` | UUIDs |
| 9 | `ipv4_address` | IPv4 literals |
| 10 | `k8s_secret_mount` | Mounted ServiceAccount token paths |
| 11 | `private_key_pem_body` | PEM body fallback |

The manifest compiles once at package init and panics on a malformed pattern rather
than skipping a rule; a silently skipped rule is a security defect.

Every rule emits the same unconfigurable sentinel. There is no configuration that
disables a rule, redacts nothing, or substitutes a different placeholder.

Only rules flagged `MultiLine` take part in the cross-line re-scan.
`TestMultiLineFlagMatchesCapability` probes each compiled pattern with inputs whose
only distinguishing feature is an embedded newline, because setting the flag
optimistically lets a single-line fallback rule redact a `BEGIN` marker and leave the
block body exposed.

The Agent's `key=value` value class excludes `\n`. With it included, one greedy match
swallowed every following line, collapsing a 128-line batch to one line and masking one
rule instead of eleven.

Validation is a 46-case corpus across 8 groups, 32 of which are maskable. Six cases form
a dedicated `negative_controls` group that must survive untouched; a masker that
redacts everything scores full marks on the 32 and is useless.

</details>

<details>
<summary><b>Detection and emission pipeline</b></summary>

1. Two read-only informers watch pods and events.
2. `OOMKilled` and `CrashLoopBackOff` are detected; container terminations are joined
   to events by `involvedObject.uid` so cause and effect are ordered rather than
   inferred.
3. The last 100 log lines and the joined event messages are scrubbed through the 11
   rules in memory, and what was masked is accounted for.
4. The scrubbed payload is emitted over HTTPS under a context-bounded worker pool of
   3, every send selected on `ctx.Done()`.
5. The Agent classifies and routes on the fixed policy above.
6. `TIER_1` patches are validated twice before being labelled valid.

The Sentinel fetches the last 100 log lines per container (`LogTailLines` in
`internal/k8s/telemetry.go`). The Agent's schema independently rejects more than 200
lines or 64 KiB, so a payload that bypassed the fetch bound still cannot drive
unbounded work in the consumer.

Detection latency is bounded at 2000 ms (**I-A4**) and asserted.

The Agent re-scrubs every response string before returning it (**I-B6**), so a payload
that reached it through an unmasked path still cannot leave unmasked.

</details>

<details>
<summary><b>Model adapter behaviour</b></summary>

Each adapter isolates the rules from the evidence using its own protocol's mechanism:
`system_instruction` for Gemini, a `system` message role for the OpenAI chat-completions
protocol, a forced tool call with the schema as `input_schema` for Anthropic.

The Anthropic Messages API has no `response_format` parameter, so the permitted slice
is enforced by forcing one tool whose `input_schema` is built from
`llm.NARRATIVE_FIELDS`. The same SDK has no `temperature` parameter, so that adapter
does not pin it and does not claim determinism.

Both adapters are driven in tests through the real SDK over a mock transport. The
`anthropic` package is built on `httpx2` and rejects an `httpx.Client`; `openai` uses
`httpx`.

Retry policy is narrow and shared: at most 3 attempts, 1.5 s apart, and only for
provider load-shedding and gateway timeouts. A 429 is not retried — only
`RESOURCE_EXHAUSTED` distinguishes an exhausted quota from a momentary rate limit, and
three retries cannot restore a quota. A refusal, a malformed reply, or freeform output
is never retried; it degrades to deterministic prose.

A missing credential, an absent endpoint and a retired model identifier present
identically from outside: no narrative. The startup line names the resolved provider
and model, which is the first thing to read.

</details>

<details>
<summary><b>Build, deploy, and silent-failure modes</b></summary>

## Build

```bash
go build -o bin/sentinel ./cmd/sentinel
sudo docker build -t registry.internal/srek3s-agent:0.1.0    -f agent/Dockerfile .
sudo docker build -t registry.internal/srek3s-sentinel:0.1.0 -f cmd/sentinel/Dockerfile .
```

Both images take the repository root as their build context. A context of `agent/` or
`cmd/sentinel/` fails at `COPY`, because the module and the compiled packages live
outside those directories.

Running the binary directly suffices for development:

```bash
./bin/sentinel -agent-url http://127.0.0.1:8001 -namespace default
```

## Deploy

```bash
sudo kubectl apply -k deploy/base
```

`deploy/service.yaml` publishes the Agent on `srek3s-agent:8000`, which is the
Sentinel's built-in `-agent-url` default. The Service selector against the Agent's pod
labels, and its `targetPort` against the port the Agent binds, are asserted equal by
`test_the_agent_service_routes_the_sentinels_default_endpoint`.

## Three silent failures

**A watch scope and its RBAC grant must agree.** A cluster-wide watch against a
namespaced Role produces no incidents and no error: the informer retries a forbidden
request indefinitely. `deploy/sentinel.yaml` ships `WATCH_NAMESPACE: srek3s-system`,
matching the Role as committed. Widening one without the other is the failure. One
narrow `Role` per namespace is the intended shape, each bound back to the Sentinel
ServiceAccount in `srek3s-system`.

**A NetworkPolicy matching nothing also produces silence, with zero 403s**, because no
authorization is attempted. An RBAC-only check reports the deployment healthy while the
watcher observes nothing.

**Pod Security Admission failures read as an empty cluster.** A manifest rejected
under PSA `restricted` fails closed, and a fixture refused at admission is worse than
no fixture: it presents as a quiet cluster. `deploy/namespace.yaml` sets
`enforce-version: latest`, so the same manifests can be admitted on k3s 1.36 and
refused on 1.29. Diagnose version skew before diagnosing the manifest.

`ImagePullBackOff` is produced by both a wrong-platform image and an absent image.
Distinguish them with `sudo k3s ctr images ls --namespace k8s.io`.

## Publishing

`git tag v0.1.0 && git push --tags` publishes both images to GitHub Container Registry
as `linux/amd64` and `linux/arm64` manifest lists, using the default `GITHUB_TOKEN`.
No registry credential is stored in this repository. The `:latest` tag moves; pin the
version tag. The manifests reference `registry.internal/`, so deploying a released
image means rewriting the image reference or kustomizing an overlay with an `images:`
block.

## Running the gates

```bash
make test

PY=~/SREK3S/.venv311/bin/python
go test -race ./...                 # 1082 Python tests + 179 Go test functions
$PY -m pytest agent/tests/ -q       # 1082 passed, 3 skipped
$PY -m black --check agent/ tests/
$PY -m flake8 agent/ tests/
$PY -m mypy --strict agent/ tests/
$PY scripts/audit_workflow.py --strict
```

</details>

<details>
<summary><b>Verification without a cluster</b></summary>

The paths worth testing are the offline ones.

| Layer | Exercises | Cluster |
|---|---|---|
| Go unit and race | Scrubber, classifier, telemetry, worker pool, nil-safety | No |
| Python unit | Schemas, invariants, patch grammar, sandbox limits, budget | No |
| Corpus replay | 46 secret-shaped cases through the real 11-rule pipeline | No |
| Golden fixtures | Byte-identical diff and RCA output | No |
| Offline `git apply` | Real `git apply --check` in a scratch repository | No |
| E2E detonation | Informer, scrub, egress, classify, patch, verify | k3s |
| E2E in-cluster | `deploy/` applies; Service DNS, RBAC, hardening, live | k3s |

The detonation leg installs k3s, plants a memory leak and asserts the whole chain,
including that a planted secret did not survive scrubbing, that scrubbing masked
something, and that masking preserved diagnostic evidence. Masking everything and
masking nothing are both failures and both are asserted.

The in-cluster leg exists because the detonation leg runs the Sentinel, the Agent and
the capture proxy as host processes on loopback and applies nothing from `deploy/`.
It applies `deploy/` and asserts that the Service publishes ready endpoints, that
cluster DNS resolves `srek3s-agent` and the Agent answers `/healthz`, that the
Sentinel's real ServiceAccount is granted reads and refused writes by a live
apiserver, and that the running Agent pod is UID 10001 with a read-only root and no
mounted token. It detonates nothing; that chain belongs to the detonation leg.

Every gate in this project reads code or a manifest. None reads a document, so the
layout of `cmd/`, `internal/`, `agent/`, `deploy/` and `tests/` is free to change
without a test failing for a reason unrelated to whether the system works.

</details>

## Repository Map

```
cmd/sentinel/          Go entrypoint; wiring, flags, signal handling
internal/scrubber/     11-rule masking engine, normative order, accounting
internal/k8s/          read-only clientset, informers, classification, telemetry
internal/worker/       bounded worker pool; every send selected on ctx.Done()
internal/emitter/      ULID incident ids, wire validation, ctx-bounded HTTPS
agent/                 FastAPI + Pydantic v2 triage engine, sandbox, providers
deploy/                k3s manifests; chaos/ holds the deliberate-failure fixtures
tests/fixtures/        incident corpus, chaos manifests, golden expected output
scripts/               audit_workflow.py, bootstrap.sh
.github/workflows/     ci.yaml, release.yaml, e2e-detonation.yaml
docs/                  runbook, lessons learned, offline install, CI triage
```

## Documentation

| Document | Contents |
|---|---|
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | Invariants, gates, and the normative masking specification |
| [`docs/runbook.md`](docs/runbook.md) | Deploy, observe, interpret, review |
| [`docs/lessons-learned.md`](docs/lessons-learned.md) | Defects found, including negative controls that failed for the wrong reason |
| [`docs/offline-install.md`](docs/offline-install.md) | Installing images without a registry |
| [`docs/ci-triage-protocol.md`](docs/ci-triage-protocol.md) | Reading a red CI run |

---

## License

MIT. See [LICENSE](LICENSE).