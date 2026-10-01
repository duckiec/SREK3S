# AGENTS.md — Autonomous Reliability Sentinel & SRE Engine

## 1. System Vision & Core Tenets
You are an autonomous systems engineering agent contributing to an enterprise-grade Kubernetes reliability firewall. 
The core philosophy is **Policy-Bounded, GitOps-Native Reliability**:
- **Zero Direct Cluster Mutation:** The agent never executes direct `kubectl apply`, `patch`, or `delete` against production clusters. All remediations are emitted as verifiable unified git diffs or GitOps PR payloads. Direct mutation authority is structurally denied at the RBAC layer (`verbs: ["get", "list", "watch"]` only).
- **In-Memory Zero-Trust Sanitization:** Telemetry must be deterministically scrubbed for secrets, credentials, tokens, and PII in-memory on the Go node before any network egress or LLM ingestion.
- **Fail-Closed Blast-Radius Policy:** If an incident classification is `UNKNOWN`, telemetry is ambiguous, or patch synthesis cannot be verified with 100% mathematical certainty, blast radius **must** escalate to `TIER_2` (War-Room dispatch) with `git_patch: ""`. Automated remediation is reserved exclusively for unambiguous, policy-vetted `TIER_1` toil.
- **Ephemeral Sandbox Triaging:** Deep investigation workers operate as isolated, resource-constrained tasks with strict cgroup budgets (e.g., 256Mi RAM, 500m CPU).
- **Dual-Layer Patch Verification:** Every synthesized patch must survive structural YAML AST validation **and** an in-sandbox `git apply --check` against the target manifest before being marked valid.

---

## 2. Tech Stack, Toolchain & Runtime Constraints
- **Host Daemon (Sentinel):** Go 1.23+, utilizing official `k8s.io/client-go`, `k8s.io/api`, and `k8s.io/apimachinery`. Standard library first; zero unvetted runtime frameworks.
- **Analysis Engine (Agent):** Python 3.11-slim, strictly typed with Pydantic v2 and FastAPI.
  - **Syntax Constraint:** Target Python 3.11 strictly. Never use Python 3.12+ features (e.g., PEP 701 backslashes inside f-string expressions) or PEP 695 type parameter syntax. All formatting is pinned to `target-version = ["py311"]`.
  - **Dependency Ban:** FastEmbed/ONNX CPU models only. Absolutely NO PyTorch, CUDA binaries, or GPU-dependent dependencies.
- **Container Hardening:** 
  - Every container runs as an unprivileged, non-root user (`UID 10001`, `GID 10001`) with `readOnlyRootFilesystem: true` and all Linux capabilities dropped (`cap_drop: ["ALL"]`).
  - Base image must include `git` for patch validation.
  - Build context is strictly repository-root scoped; Dockerfiles must not make directory assumptions outside their subtree.
- **Tooling Configuration Placement:**
  - `flake8` and `mypy` resolve configuration from the current working directory (repo root). Root `setup.cfg` is the authority.
  - `black` resolves from project markers. `agent/pyproject.toml` pins formatting behavior without colliding with root type-checking paths.
- **Developer entry points are the Makefile.** `make doctor` (host pre-flight via
  `scripts/bootstrap.sh`), `make bootstrap`, `make test`, `make build`, `make deploy`,
  `make clean`. Do not hand-type the gate commands from §4 in a shell: `make` resolves
  the pinned Python interpreter itself, and this host's default `python3` is **not** a
  valid interpreter for these gates. `make clean` deliberately does not delete the
  system namespace.
- **Builds are multi-architecture via BuildKit.** `cmd/sentinel/Dockerfile` cross-compiles
  with `--platform=$BUILDPLATFORM` plus `ARG TARGETOS`/`ARG TARGETARCH`; the agent needs
  no cross-compile machinery and its runtime stage carries no `--platform` (the default is
  already correct, and naming it produces a `RedundantTargetPlatform` warning on every
  build). CI asserts both platforms compile on every pull request.
- **The model client is `google-genai`** (GA). The `google-generativeai` spelling is
  Google's legacy client, marked `Development Status :: 7 - Inactive`. The default model
  is a 3.x Flash: **`gemini-1.5-flash` has been shut down** and returns `NOT_FOUND`.
- **Rationale lives in `ENGINEERING.md`.** This file says what the rules *are*;
  `ENGINEERING.md` says *why*, for the maintainer who arrives later and cannot tell
  whether a tempting simplification is safe. Read it before changing tier routing,
  the model schema, or the scrubber.
- **Runtime Baseline (measured 2026-10-01).** The development host is **WSL2 on an
  ARM64 Windows host, distribution `Fedora Linux 44 (aarch64)`**, kernel
  `6.18.40.1-microsoft-standard-WSL2`, with systemd as PID 1. This is the **first
  `linux/aarch64` host this project has run on**; every earlier local measurement
  recorded in `ROADMAP.md` and in `ARCHITECTURE.md` §6.5 was taken on
  `windows/arm64`. It is pinned here because the platform is load-bearing for every
  gate in §4 and for every image that has to run on a node, and because a reader
  comparing a local number against a CI number needs to know which architecture
  produced which.
  - **Go:** native Linux `golang.aarch64` installs to `/usr/bin/go`
    (`go version go1.26.8 linux/arm64`), which satisfies `go.mod`'s `go 1.23`. A
    Windows Go also exists at `/mnt/c/Program Files/Go/bin/go.exe`, and `/usr/bin`
    precedes `/mnt/c` in `PATH`, so the native toolchain wins. Confirm with
    `command -v go && go version` rather than assuming; the `scripts/gotest.ps1`
    workaround for the old host was a Windows-only artefact and does not apply.
  - **Python:** the system default `python3` here is **3.14.3**, which is **not** an
    acceptable interpreter for any of this project's gates: §2 forbids 3.12+
    syntax, `agent/pyproject.toml` pins `target-version = ["py311"]`, and root
    `setup.cfg` sets `python_version = 3.11`. `python3.11` (3.11.16) is installed
    natively and the virtualenv at `~/SREK3S/.venv311` was built from it with
    `agent/requirements.txt` installed. **Run every Python gate as
    `~/SREK3S/.venv311/bin/python -m <tool>`**, never as bare `pytest`/`black`/
    `flake8`/`mypy`, which would resolve to whatever `PATH` finds first.
  - **Race detector:** `gcc.aarch64` 16.2.1 is installed, so cgo is available and
    `go test -race` is now **runnable locally**. See §4 for what that does and does
    not change.
  - **Images:** every image built on this host must target **`linux/arm64`**. CI
    builds on `amd64`. `busybox:1.36.1`, which the `deploy/chaos/` fixtures pin,
    publishes an `arm64` manifest and is usable here; no `registry.internal/srek3s-*`
    image exists anywhere yet, so both SREK3S images must be built locally and
    registered into the `k8s.io` containerd namespace under their **exact**
    fully-qualified names or the pods report `ImagePullBackOff`
    (`docs/offline-install.md`).
  - **`sudo` is required, for two unrelated reasons.** It is passwordless for
    `duckie`, which is convenient and is not a property of this repository:
    - **every** `kubectl` call, because the k3s kubeconfig
      `/etc/rancher/k3s/k3s.yaml` is mode `0600` and root-owned;
    - **every** `docker` call, because `duckie` is in `wheel` but **not** in the
      `docker` group and `/var/run/docker.sock` is `srw-rw---- root:docker`. Plain
      `docker` fails with `permission denied while trying to connect to the docker
      API`. This is host configuration, not a defect in this repository; the
      correct handling is `sudo docker …` rather than granting a user membership of
      a group that confers root-equivalent control of the daemon.
  - **Cluster:** local k3s is **v1.36.4+k3s1**, single node `dwindle2`
    (`control-plane`, Ready, containerd `2.3.4-k3s1.36`, internal IP
    `172.30.181.188`; 10 CPU, 7908756Ki memory and 110 pods allocatable). CI's
    k3s is **v1.29.9+k3s1**. `deploy/namespace.yaml` sets
    `pod-security.kubernetes.io/enforce-version: latest`, so Pod Security
    Admission is evaluated against **1.36** locally, not 1.29 — a manifest this
    host admits can be refused by CI for a reason that has nothing to do with the
    code, and that skew must be stated rather than diagnosed from scratch.
- **No model client is wired, and the verification loop is not reachable.** Two
  scaffolds are easy to mistake for live paths, and an agent that assumes either
  exists will write work that cannot run:
  - `agent/llm.py` declares `CompletionClient` as a `typing.Protocol` with **no
    implementation**, deliberately, per §5.3 "No Speculative Bloat". `llm.py`
    imports **no network library**. `fastembed`/`onnxruntime` appear only in a
    **comment** in `agent/requirements.txt` and are installed nowhere. All
    analysis in the shipped path is deterministic: regex, arithmetic, YAML, and
    real `git`. `httpx` is a declared runtime requirement but is used only by tests,
    through `httpx.ASGITransport`, which never leaves the process.
  - `agent/verify.py` (741 lines) implements the PRD F4 post-remediation loop and is
    covered by `agent/tests/test_verify.py` and
    `agent/tests/test_verification_e2e.py`, but **no production module imports it**.
    `main.py` and `triage.py` do not. `triage.py` emits `verification_policy` on the
    wire and nothing in the service consumes it, so PRD F4 and `ARCHITECTURE.md`
    §5.2 are **not reachable from the running HTTP service**. Status is tracked as
    a known-unwired boundary in `ARCHITECTURE.md` §5.5.1 and as an open task in
    `ROADMAP.md` (`ENV-2.7`).

---

## 3. Mandatory Coding Guardrails

### Go / Sentinel Safety Rules
1. **Defensive Pointer Handling:** Kubernetes API objects contain deeply nested pointer trees. Never access `.State.Terminated`, `.State.Waiting`, or `.Limits` directly without explicit `nil` checks at every preceding level.
2. **Channel & Worker Pool Discipline:** Never expose unbounded goroutines. Use buffered job channels with fixed worker pools. Every blocking operation (`http.Client`, Kubernetes API calls, channel sends) MUST accept a `context.Context` bounded by `context.WithTimeout`.
3. **Build-Tag Awareness:** Test helpers and platform-specific code must not introduce undefined symbol link errors across build tags. Any tag separation (e.g., `//go:build !race`) must be mirrored across all compiling test suites.
4. **Line-Boundary Cancellation Safety:** In-memory scrubbing operations must observe context cancellation **at line boundaries only**. A line is either scrubbed to completion or dropped entirely. Never abort mid-line or mid-rule; returning partially-scrubbed strings creates critical credential leaks.
5. **Topology-Preserving Redaction:** Credential masking (e.g., Rule 6 `basic_auth_url`) must target the secret segment inside userinfo (`user:[REDACTED]@host:port`) via capture groups. Never wipe hostnames, IPs, or ports; destroying endpoint topology ruins diagnostic RCA telemetry.
6. **Regex Ordering & Multi-Line Isolation:**
   - Multi-line rules (e.g., Rule 1 PEM blocks) must execute before single-line fallback rules.
   - Batch cross-line passes must strictly filter on `Rule.IsMultiLine == true`. Single-line rules must never run against joined multi-line batches.
   - Single-line regex value classes must explicitly exclude `\n` to prevent greedy matches from swallowing subsequent batch lines.
7. **Idempotency & Full-Value Guards:** Secret token replacements must be idempotent. Token presence guards must compare the entire captured token, not naive substrings, preventing attacker-controlled partial-bypass leaks.

### Python / FastAPI Agent Safety Rules
1. **Event Loop Non-Blocking Rule (Probe Protection):** 
   - Never run CPU-intensive triage, regex re-scans, AST parses, or subprocess executions directly on the async event loop.
   - All synchronous compute must execute via `starlette.concurrency.run_in_threadpool` or dedicated worker threads. Stalling the event loop drops Kubernetes liveness/readiness probes (`/healthz`, `/readyz`), causing the kubelet to restart healthy pods under load.
2. **Strict Constrained Decoding & Schema Authority:**
   - The LLM and triage engine must enforce Pydantic schemas directly.
   - `ARCHITECTURE.md` is the single source of truth for schema field names and nesting. Do not invent nested wrappers (`cluster_info`, `workload`) if the spec defines a flat payload.
3. **Patch Grammar & Formatting (I-B4):**
   - Remediation patches must be pure, machine-parsable unified diffs.
   - Markdown code fences (e.g., ````diff ````) are strictly prohibited and must be rejected at the schema validator level.
   - Diffs must be syntactically validated using both YAML AST structural checks and `git apply --check` in an ephemeral sandbox.
4. **Bounded Concurrency & Load Shedding:**
   - Enforce an active job budget using atomic counters/leases.
   - When the investigation sandbox is at capacity, the service must immediately reject incoming triage requests with HTTP `429 Too Many Requests` and an explicit `{"error": "sandbox_busy"}` payload. Do not queue requests indefinitely.
5. **Monotonic Profiling:** Timing measurements must use `time.perf_counter()`, never wall-clock time.

---

## 4. Quality Gates & Verification Commands
Before marking any roadmap task or milestone complete, execute the corresponding verification command in your environment and ensure an exit status of `0`:

### Go Gates
- **Go Linter & Static Analysis:**
  ```bash
  go vet ./...
  test -z "$(gofmt -l .)"
  ```
- **Go Compile-Time Build-Tag Verification:**
  ```bash
  go vet -tags race ./...
  ```
- **Go Unit & Data Race Tests (Linux CI Authority):**
  ```bash
  go test -v -race -timeout 30s ./...
  ```
  *(`-race` requires ThreadSanitizer. On platforms where `-race` is unavailable, GitHub Actions `ubuntu-latest` is the sole passing authority. Local passes without `-race` do not waive this gate.)*
  - **Amended 2026-10-01, and the amendment is about *local* runs only.** `-race`
    needs ThreadSanitizer *and* cgo. On the old `windows/arm64` host neither was
    available, so for two milestones this gate was left unticked locally rather
    than ticked on an assumption — the correct call at the time. The current host
    is `linux/aarch64` with `gcc.aarch64` 16.2.1 present, so this gate **is now
    locally executable and locally verifiable**, and an agent must run it rather
    than report it blocked.
  - **CI on `ubuntu-latest` remains the platform authority for every published
    number.** A local `-race` pass is additional evidence, never a substitute, and
    nothing recorded in `ROADMAP.md` or `docs/lessons-learned.md` about the
    `ubuntu-latest` results is withdrawn by this amendment. The original note above
    remains true for the era that produced it: on a platform where `-race` does not
    exist, a green run without it does not waive this gate.

### Python Gates

  *On this host, run every command below as `~/SREK3S/.venv311/bin/python -m <tool>`.*
  *The bare names resolve to the system `python3`, which is 3.14.3 and is not a
  valid interpreter for this project — see §2.*

- **Formatting Verification:**
  ```bash
  black --check agent/
  ```
- **Style Linting:**
  ```bash
  flake8 agent/
  ```
- **Strict Static Type Checking:**
  ```bash
  mypy --strict agent/
  ```
- **Unit & Integration Suite:**
  ```bash
  pytest agent/tests/ -v
  ```

### Container Verification
- **Hermetic Docker Build & Non-Root Execution:**
  ```bash
  sudo docker build -t srek3s-agent:test -f agent/Dockerfile .
  ```
  *(Must assert effective execution as UID 10001 and successful import of `main:app`.)*
  - **The `sudo` is required on the `linux/aarch64` host**, not optional: `duckie`
    is not a member of the `docker` group. Build `linux/arm64` here — CI builds
    `amd64`, so a local image and a CI image are not interchangeable, and the
    architecture must be stated rather than inferred.

---

## 5. Agent Operational Boundaries & Protocol
1. **Single Source of Truth:** Do NOT modify schemas, API paths, or directory layouts without consulting `ARCHITECTURE.md`. If code and spec disagree, stop and raise the discrepancy.
2. **Atomic Progress:** Execute tasks from `ROADMAP.md` strictly one checkbox at a time. Mark completed items with `- [x]` only after running verification commands with exit status `0`.
3. **No Speculative Bloat:** Do not generate extra helper utilities, UI templates, or unrequested mock libraries unless explicitly directed by the active task.
4. **Honest Gate Reporting:** If a gate cannot run due to missing host tooling (e.g., missing Docker daemon, missing `-race` support), report it as a **blocked dependency**. Never check off a gate based on an unverified assumption or a mock substitute.
5. **Negative Control Verification:** When adding CI guards, regex boundary rules, or security checks, always validate with a negative control to prove the guard actually fails when a defect is present.
6. **Continuous Post-Mortem Documentation:** Whenever a critical defect, pipeline trap, or architectural blind spot is discovered and resolved, the agent MUST append a structured post-mortem to `docs/lessons-learned.md` before transitioning phases. Use the format: `### [Trap Name] (Milestone X)`, followed by `- **What happened:**`, `- **Why it is a problem:**`, and `- **How we fixed it:**`. Never leave a hard-won lesson undocumented.

   Two constraints on this rule that are not optional, because both have been
   violated in this repository and both defeat the purpose of the document:

   - **Record controls that were invalid, not only the ones that worked.** A
     negative control that failed for the wrong reason — a mis-anchored plant, an
     uninstalled module erroring at collection instead of tripping the guard — is
     the most dangerous kind of evidence, because it reads as a pass. If a control
     was rebuilt before it became informative, that belongs in the post-mortem.
   - **Distinguish verbatim record from reconstruction.** Where an account is
     assembled from a mechanism plus an inference rather than from an observation,
     say so in place. A later reader who cannot tell the two apart will cite a
     reconstruction as a quotation.
7. **Static analysis is not runtime verification.** Reading two manifests and
   concluding that a cluster-wide `LIST` will be refused is a deduction about a
   mechanism, not an observation of it. When a finding is produced this way, the
   document recording it must say so in place — name the mechanism, name the
   inference, and state that the behaviour **has not been reproduced**. Do not
   upgrade a defect report to an incident report, or an unticked box to a ticked
   one, on the strength of a correct argument. This is the same rule as §5.4 and
   §5.6's second constraint, applied to code reading instead of to gates: the
   cheapest false claim available is the one that sounds like a finding.
8. **Do not modify the recorded history.** Historical CI run IDs, platform names,
   timings and measured figures in `ROADMAP.md`, `ARCHITECTURE.md` and
   `docs/lessons-learned.md` are a record of what happened on a specific host at a
   specific time. When the environment changes, **annotate and supersede** them in
   place. Editing them destroys the evidence that makes them worth having, and the
   generalisable lesson in most of those entries is precisely that they were
   recorded honestly.