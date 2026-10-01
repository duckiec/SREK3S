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
  *(Note: `-race` requires ThreadSanitizer. On platforms where `-race` is unavailable, GitHub Actions `ubuntu-latest` is the sole passing authority. Local passes without `-race` do not waive this gate.)*

### Python Gates
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
  docker build -t srek3s-agent:test -f agent/Dockerfile .
  ```
  *(Must assert effective execution as UID 10001 and successful import of `main:app`.)*

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