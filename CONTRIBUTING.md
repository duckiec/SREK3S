# Contributing to SREK3S

SREK3S reads crashing containers, works out why, and hands you a `git diff` to
review. It cannot change your cluster. Everything below exists to keep that
second sentence true, because the failure modes are not crashes — they are a
build that stays green while the guarantee quietly stops holding.

This file is deliberately self-contained. It links to no design document,
because a gate that reads prose is a gate that fails when the prose drifts. The
invariants are stated here, and the tests that enforce them read code and
manifests.

---

## Quick start

```bash
make doctor      # verify the host: OS, arch, docker+buildx, go, python 3.11+
make bootstrap   # create .venv311, install deps, download Go modules
make test        # every gate, Go first then Python, stopping on first failure
```

`make test` is the gate. Do not hand-type the commands in the next section —
`make` resolves the pinned Python interpreter for you, and this project's default
`python3` is frequently not a valid interpreter for it (see
[Interpreters](#interpreters)).

---

## What `make test` runs, and what each gate catches

`make test` is two suites, run **sequentially** on purpose: Go's race detector and
pytest each want the whole machine, and running them together on a laptop
produces flaky failures from timing rather than from code. A flaky gate is a gate
people learn to ignore.

| Gate | Command | Catches |
|---|---|---|
| G1 | `go vet ./...` | Go static analysis |
| G1b | `go vet -tags race ./...` | Symbols missing under the `-race` build. G1 and G2 typecheck the *other* variant, so this is the only thing that catches a helper defined solely in a `//go:build !race` file |
| G2 | `test -z "$(gofmt -l .)"` | Formatting drift |
| G3 | `go test -race -timeout 120s ./...` | Unit failures **and data races** |
| G4 | `black --check agent/ tests/` | Python formatting |
| G5 | `flake8 agent/ tests/` | Style, and unused imports |
| G6 | `mypy --strict agent/ tests/` | Type errors, under the strictest settings |
| — | `pytest agent/tests/ -q` | Every behavioural assertion below |

Skipped tests are a **blocked dependency, not a pass**, and CI enforces that with a
ratchet: the skip count may *fall*, never *rise*. Four skip today — three need a
reachable cluster, one needs a filesystem that folds case. If you add a fifth, the
build goes red until you establish what it is.

---

## The four invariants

These are not style preferences. Each has tests that fail the build when it is
violated, and each is a property a reviewer cannot verify by reading a diff.

### 1. No cluster write authority, without a cluster

The Sentinel runs under a namespaced `Role` enumerating exactly
`["get","list","watch"]` on `pods`, `pods/log` and `events`. There is no
`ClusterRole`, no `ClusterRoleBinding`, and no wildcard. The Agent has **no
ServiceAccount token at all** (`automountServiceAccountToken: false`).

- `internal/deploy/rbac_hardening_test.go` parses `deploy/rbac.yaml` and fails on
  any verb beyond those three.
- `agent/tests/test_deploy_manifests.py` asserts no cluster-scoped binding widens
  the Sentinel, and that the agent automounts no token.
- A CI job `ast`-walks `agent/models.py` and fails if any field is shaped like a
  write verb (`apply`, `exec`, `patch`, `scale`, `delete`, …). `git_patch` and
  `patch_validated` are explicitly allowlisted because they are the *artifact*,
  not an authority.

**Never add a write verb.** Not "temporarily", not "just for the chaos
namespace". A verb on the Sentinel's Role is a capability the process acquires
regardless of whether any code path currently uses it.

### 2. Fail-closed tiers

Anything not provably Tier-1 is Tier-2, and **Tier-2 with an empty patch is a
success, not a failure**. Most incidents a naive agent would "fix" belong there.

Tier-1 requires *every* precondition: `OOMKilled`, restart count within policy,
exactly one affected replica, siblings healthy, a remedy shape on the
`MEMORY_LIMIT_RECALIBRATION` allow-list, risk not HIGH, and a verified target
manifest. All seven are evaluated even after one fails, so the escalation reasons
are a complete account rather than the first failure.

A patch is emitted only after it survives three independent checks: a positional
round-trip, a YAML AST check proving exactly one semantic field changed, and a
real `git apply --check` in a throwaway repo. Any failure discards the patch and
escalates. A diff that matches a masking rule is **refused, not redacted** —
rewriting a line inside a diff breaks the hunk header's counts, and a credential
in a GitOps PR would be copied into every clone.

`TriageResponse` enforces this in the schema: `TIER_2_ARCHITECTURAL` with a
non-empty `git_patch` **raises at construction**. It is unrepresentable, not
discouraged.

### 3. The model has no authority

A model may write the prose in a Tier-2 explanation. It may not return a tier, a
patch, a risk level, a validation flag, or an incident id.

Three structural mechanisms, in order of how much they buy:

1. **The permitted output slice has two fields** — `root_cause.summary` and
   `rca_markdown`. Both provider dialects in `agent/providers.py` are derived from
   the single `llm.NARRATIVE_FIELDS` tuple, so they cannot drift apart, and a
   test asserts the schema, the Pydantic model and the tuple all agree.
2. **The rules never share a string with the evidence.** `SYSTEM_INSTRUCTION`
   travels in the provider's *own* system field — `system_instruction=` for
   Gemini, a `role: "system"` message for the OpenAI protocol. Anyone who can
   write to a crashing container's stdout can print text that reads like an
   instruction, so "put the rules first in the prompt" is not a defence.
3. **The decoder is the last line.** Freeform or fenced output is a **fatal**
   failure (invariant I-B4): no fence-stripping, no regex scrape of markdown, no
   best-effort parse. Provider-side constraint is defence in depth; a provider's
   behaviour is not a safety property worth trusting.

Tier selection is computed **before** any model is consulted, and the router is
typed so it cannot read a confidence value — `classifier.TierEvidence` carries no
such field, so reintroducing that coupling is a type error, not a test failure.

`LLM_PROVIDER` (default `gemini`) and `LLM_BASE_URL` select the transport.
Changing the provider changes nothing about authority. Both SDKs are imported
lazily, so a host without either still imports the module, still triages, and
still answers `/healthz`.

### 4. Secrets are scrubbed before egress, in memory

Telemetry is masked on the Go node, in memory, before any network call.
Eleven ordered rules live in `internal/scrubber/manifest.go`, compiled once at
package init; a compile failure panics rather than silently skipping a rule.

Five properties that are easy to get wrong and expensive to get wrong:

- **Order is normative.** Structural patterns (PEM blocks, JWTs) run before the
  generic `key=value` pattern, so a broad rule cannot re-wrap a span an earlier
  rule redacted. This is also what makes scrubbing idempotent.
- **Topology survives redaction.** Rule 6 replaces only the password inside
  `scheme://user:[REDACTED]@host:port`. Wiping the host would destroy the
  difference between "the database is unreachable" and "the connection to
  db-primary:5432 is failing auth" — which is the whole finding.
- **Cancellation happens at line boundaries only.** A line is scrubbed to
  completion or dropped. Aborting mid-rule would return a partially-scrubbed
  string, which is a credential leak with extra steps.
- **Multi-line rules are flagged, and the flag is probed.** Only rules that can
  match across a newline join the cross-line pass. Setting the flag
  optimistically lets a single-line fallback redact a `BEGIN` marker and leave
  the key body exposed.
- **Nothing is written to disk.** No scratch buffer, no temp file, no re-logging
  of input. `TestNoDiskArtifacts` asserts the package imports no filesystem API.

The agent re-scans its own outbound strings as a backstop. The Go node is the
authoritative control; the agent is defence in depth.

---

## Interpreters

Python **3.11, strictly**. `black` is pinned to `target-version = ["py311"]` and
`mypy` to `python_version = 3.11`.

This matters more than it sounds. On a recent host change, the first commit
passed every local gate and still failed CI's `flake8`, because a test used an
f-string containing a backslash — valid from Python 3.12, a hard `SyntaxError` on
3.11. Locally the host ran 3.14 and parsed it; black, mypy and pytest were all
green. **`ast.parse(feature_version=(3,11))` does not catch this**, so
`agent/tests/test_compat.py` detects it textually and additionally compiles every
source with a real 3.11 when one is reachable.

Run every Python gate as `~/SREK3S/.venv311/bin/python -m <tool>`. Bare
`pytest`/`black`/`flake8`/`mypy` resolve to whatever `PATH` finds first, and will
give you a confident, wrong answer.

`make test` resolves the interpreter itself and **fails loudly** if it cannot
find a valid one, rather than falling back to a newer version.

---

## Testing rules

**Every security check needs a negative control.** A test that has never been
observed to fail is not evidence. When you add a guard, plant the defect it is
meant to catch and confirm the guard trips.

This has bitten harder than it sounds. The I-B5 write-verb guard originally
required *quoted* field names, which Python never uses — it could not have
failed, and it was green for two milestones. A negative control for a
read-only-facade check was vacuous three times over before it exposed a real
method. If a control needed rebuilding before it became informative, that belongs
in `docs/lessons-learned.md`.

**Do not fix a failure by weakening the assertion.** The layout-tree validator was
deleted outright rather than relaxed, and `docs/lessons-learned.md` records what
that cost. That is the right shape: a gate that cannot fail for a reason that
matters is not a gate.

**Corrections are recorded, not erased.** When you get something wrong, write down
what you believed and why, so the next person does not repeat it. The same applies
to measured numbers: record a new figure with its platform named rather than
overwriting the old one.

---

## Adding a model provider

1. Add a class to `agent/providers.py` implementing
   `llm.CompletionClient` — one method, `complete(prompt_text) -> str`.
2. Put the rules in the provider's **own** system field. Never concatenate them
   with the evidence.
3. Derive the response schema from `llm.NARRATIVE_FIELDS`; never type the field
   names out. If your provider needs an extra key to express the boundary, add it
   to both dialects and to `ModelNarrative` in the same commit.
4. Raise `llm.ModelOutputError` for **every** failure — missing key, absent SDK,
   transport error, refusal, empty completion. The caller treats them all the
   same: return nothing and let the deterministic prose stand. Do not retry a
   refusal.
5. Narrow the retry set to genuine transient faults. **429 is not transient**:
   it means either a momentary rate limit or an exhausted quota, and only
   `RESOURCE_EXHAUSTED` tells them apart. An exhausted quota is not restored by
   retries, and an earlier revision reported it as load-shedding — which sends an
   operator to the wrong system.
6. Register the name in `KNOWN_PROVIDERS` and add the API-key variable to
   `_API_KEY_ENV`.
7. Add tests that **capture the outbound call** and assert the system/evidence
   split. Reading the source proves nothing about the dict handed to the SDK.

---

## House rules

- **No GPU dependencies.** No torch, CUDA, cupy, nvidia or onnxruntime-gpu. A CI
  step greps `agent/requirements.txt` and fails on any of them.
- **Both containers run as UID 10001**, `readOnlyRootFilesystem: true`, all
  capabilities dropped, no privilege escalation, `RuntimeDefault` seccomp, and a
  single writable `emptyDir` at `/tmp`. CI asserts the effective UID by *running*
  the image.
- **Never log untrusted text verbatim.** Provider errors can echo the request,
  and the request is incident telemetry. Name the exception *type*, never its
  message.
- **Monotonic clocks only.** `time.perf_counter()` / `time.Since`, never a wall
  clock. An NTP step during an incident must not produce a negative latency.
- **Bound every blocking operation.** No unbounded `context.Background()` on a
  blocking path, no unbounded subprocess, no unbounded retry.
- **One checkbox at a time** on delivery work; mark a step done only after its
  verification command actually exits `0` in the environment you ran it in.

---

## Where things live

| | |
|---|---|
| `cmd/sentinel/` | Go entrypoint: wiring, flags, signal handling, drain |
| `internal/scrubber/` | 11-rule masking engine, normative order, accounting |
| `internal/k8s/` | Read-only clientset, informers, classification, telemetry |
| `internal/worker/` | Bounded worker pool; every send selected on `ctx.Done()` |
| `internal/emitter/` | ULID incident ids, wire validation, ctx-bounded HTTPS |
| `agent/models.py` | **Schema source of truth.** Both wire contracts live here |
| `agent/classifier.py` | Deterministic classification and deny-by-default routing |
| `agent/llm.py` | The model boundary: rules, permitted slice, decoders |
| `agent/providers.py` | Transports. The only module that builds a network client |
| `agent/patch.py` | Diff synthesis and three-layer patch verification |
| `agent/sandbox.py` | Disposable worker, rlimits, monotonic deadline |
| `deploy/` | k3s manifests; `chaos/` holds the deliberate-failure fixtures |
| `docs/runbook.md` | Operational: deploy, watch, interpret, review |
| `docs/lessons-learned.md` | Every defect found, including controls that failed for the wrong reason |

When you add a production module under `cmd/`, `internal/`, `agent/` or `tests/`,
nothing will fail if a document forgets it. That is deliberate. Update
`docs/` when it helps a reader; do not treat documentation as a gate.
