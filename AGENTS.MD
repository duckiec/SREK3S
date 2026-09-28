# AGENTS.md — Autonomous Reliability Sentinel & SRE Engine

## 1. System Vision & Core Tenets
You are an autonomous systems engineering agent contributing to an enterprise-grade Kubernetes reliability firewall. 
The core philosophy is **Policy-Bounded, GitOps-Native Reliability**:
- **Zero Direct Cluster Mutation:** The agent never executes direct `kubectl apply`, `patch`, or `delete` against production clusters. All remediations are emitted as verifiable unified git diffs or GitOps PR payloads.
- **In-Memory Zero-Trust Sanitization:** Telemetry must be deterministically scrubbed for secrets, credentials, tokens, and PII in-memory on the Go node before any network egress or LLM ingestion.
- **Ephemeral Sandbox Triaging:** All deep investigation workers operate as isolated, resource-constrained tasks with strict cgroup budgets (e.g., 256Mi RAM, 500m CPU).
- **Graduated Autonomy:** Trivial, policy-vetted toil (e.g., OOM limit recalibration) produces automated GitOps PRs. Complex failures (e.g., network deadlocks, cascading 5xx loops) produce diagnostic RCA war-room dispatches.

---

## 2. Tech Stack & Versioning Constraints
- **Host Daemon (Sentinel):** Go 1.23+, utilizing official `k8s.io/client-go`, `k8s.io/api`, and `k8s.io/apimachinery`. Standard library first; zero unvetted third-party runtime frameworks.
- **Analysis Engine (Agent):** Python 3.11-slim, typed with Pydantic v2 and FastAPI. Local inference runs via `fastembed` or `onnxruntime` CPU models; cloud fallbacks consume structured JSON completion APIs. Absolutely NO PyTorch, CUDA binaries, or GPU-dependent dependencies.
- **Container Hardening:** Every container must run as an unprivileged, non-root user (`UID 10001`, `GID 10001`) with `readOnlyRootFilesystem: true` and all Linux capabilities dropped (`cap_drop: ["ALL"]`).
- **Cluster Target:** Single-node lightweight distribution (`k3s`). Image importation must target the internal `containerd` namespace directly (`k3s ctr images import`).

---

## 3. Mandatory Coding Guardrails

### Go / client-go Safety Rules
1. **Defensive Pointer Handling:** Kubernetes API objects contain deeply nested pointer trees. Never access `.State.Terminated`, `.State.Waiting`, or `.Limits` directly without explicit `nil` checks at every preceding level.
2. **Channel & Goroutine Hygiene:** Never expose unbounded goroutines. Use buffered job channels with fixed worker pools. Every blocking operation (`http.Client`, Kubernetes API calls, channel sends) MUST accept a `context.Context` bounded by `context.WithTimeout`.
3. **Deterministic Secret Masking:** The Go sanitizer must process log lines through compiled regular expressions (AWS access keys, Bearer tokens, private keys, JWTs, IPv4 addresses, and common secret keys) replacing matches with `[REDACTED]` prior to JSON serialization.

### Python / AI Agent Safety Rules
1. **Strict Constrained Decoding:** The LLM client must enforce Pydantic schemas. Freeform markdown without valid root JSON is a fatal validation failure.
2. **Deterministic Remediation Output:** The agent must output two distinct deliverables:
   - A human-readable Root Cause Analysis (RCA) with a concise diagnostic summary.
   - A machine-parsable unified `git diff` patch targeting Kubernetes deployment manifests.
3. **Monotonic Profiling:** Timing measurements must use `time.perf_counter()`, never wall-clock time.

---

## 4. Quality Gates & Verification Commands
Before marking any roadmap task or milestone complete, execute the corresponding verification command in your environment and ensure an exit status of `0`:

- **Go Linter & Static Analysis:**
  ```bash
  go vet ./...
  test -z "$(gofmt -l .)"
Go Unit & Pointer Tests:

Bash
go test -v -race -timeout 30s ./...
Python Formatting & Type Checking:

Bash
black --check agent/
flake8 agent/
mypy --strict agent/
5. Agent Workflow Boundaries
Single Source of Truth: Do NOT modify schemas or directory layouts without consulting ARCHITECTURE.md.

Atomic Progress: Execute tasks from ROADMAP.md strictly one checkbox at a time. Mark completed items with - [x].

No Speculative Bloat: Do not generate extra helper utilities, UI templates, or unrequested mock libraries unless explicitly directed by the active task.