# ROADMAP — Autonomous Reliability Firewall & Incident Sentinel

| Field | Value |
|---|---|
| Document ID | `ROAD-0001` |
| Version | `0.1.0` |
| Status | Draft — all work unstarted |
| Requirements | `PRD.md` |
| Schemas & layout | `ARCHITECTURE.md` (single source of truth) |

---

## Working Agreement

These rules are binding on every task below.

1. **One checkbox at a time.** Execute strictly in order; do not begin item *N+1* until item
   *N* is `[x]` (AGENTS.md §5).
2. **No speculative bloat.** Do not add helper utilities, mock libraries, UI templates, or
   abstractions not named by the active task.
3. **No schema or layout invention.** Field names and directories come from
   `ARCHITECTURE.md` §3/§4/§5. If a task seems to require a new one, stop and amend the
   architecture document first.
4. **Quality gates are part of the task.** The milestone's gate command must exit `0` before
   the milestone's terminal test may be run. A green terminal test on a red gate is not done.
5. **Mark honestly.** `- [x]` means the verification command actually passed in this
   environment. Do not pre-mark.

### Global quality gates (run at the end of every milestone)

```bash
# Go
go vet ./...
test -z "$(gofmt -l .)"
go test -race -timeout 30s ./...

# Python
black --check agent/
flake8 agent/
mypy --strict agent/
```

---

## Milestone 1 — Go Secret Scrubber & PII Masking Engine

**Goal:** a deterministic, in-memory masking engine that makes PRD AC-2 provably satisfiable.
**Delivers:** `internal/scrubber`. **Satisfies:** PRD F1, AC-2; ARCH §6.
**No cluster or network dependency** — this milestone is pure, hermetic, and testable offline.

### 1.1 Manifest and compilation

- [x] `1.1.1` Create `internal/scrubber/` with `manifest.go`, `scrubber.go`, `account.go`.
- [x] `1.1.2` Define `RuleID` typed constants for all 11 rules in ARCH §6 (`pem_private_key`,
      `aws_access_key_id`, `aws_secret_access_key`, `jwt`, `bearer_token`, `basic_auth_url`,
      `generic_secret_kv`, `uuid`, `ipv4_address`, `k8s_secret_mount`,
      `private_key_pem_body`).
- [x] `1.1.3` Encode each rule's regex **verbatim** from the ARCH §6 manifest table. No
      deviation, no added or dropped rules. **Caveat: three verbatim rules leak — see below.**
- [x] `1.1.4` Define `Rule{ID RuleID, RE *regexp.Regexp}` and an ordered `var Manifest []Rule`
      whose order matches the §6 table exactly.
- [x] `1.1.5` Compile the manifest at package `init()`; on compile error, `panic` with the
      offending rule ID. A silently skipped rule is a security defect, not a warning.
- [x] `1.1.6` Add a test that re-compiles every rule and asserts zero errors, and asserts
      `len(Manifest) == 11` and that rule order is unchanged from §6.

### 1.2 Scrub pipeline

- [x] `1.2.1` Define `const RedactionSentinel = "[REDACTED]"` as an **unexported, unconfigurable**
      constant — no env var, flag, or config path may alter it.
- [x] `1.2.2` Implement `ScrubString(ctx context.Context, s string) string` applying all rules
      in manifest order.
- [x] `1.2.3` Implement `ScrubLines(ctx context.Context, lines []string) ([]string, RedactionReport)`.
- [x] `1.2.4` Implement the cross-line safety pass (rule M3): join masked lines, re-scan once
      with the full manifest, redistribute. Catches secrets split across a line boundary.
- [x] `1.2.5` Enforce idempotence — `ScrubString(ScrubString(x)) == ScrubString(x)`.
- [x] `1.2.6` Add `nil`-context handling: a `nil` ctx is replaced with
      `context.Background()` rather than panicking.
- [x] `1.2.7` Thread `ctx` through every entry point and abort mid-pipeline on cancellation,
      returning the partially-masked buffer **already masked** (never raw).

### 1.3 Redaction accounting

- [x] `1.3.1` Implement `RedactionReport{Total int, RulesTriggered []RuleID}`.
- [x] `1.3.2` Count each rule hit; sort `RulesTriggered` deterministically (manifest order) so
      output is byte-stable across runs.
- [x] `1.3.3` Assert in a test that the report contains **no** matched value, no prefix/suffix
      of one, and no reversible encoding of one (rule M4).
- [x] `1.3.4` Assert `Total` equals the sum of per-rule hit counts.

### 1.4 Fixtures and unit tests

- [x] `1.4.1` Create `tests/fixtures/secrets_corpus.txt` with ≥ 1 realistic sample per rule,
      including a multi-line PEM key block and a `key: value` YAML secret.
- [x] `1.4.2` `TestScrubCorpusTotalMasking` — **100%** of corpus lines contain `[REDACTED]`
      after scrubbing.
- [x] `1.4.3` `TestNoPlaintextSecretSurvives` — for each known plaintext secret in the
      corpus, a substring scan of the scrubbed output returns **zero** matches (AC-2).
- [x] `1.4.4` `TestIdempotence` — double-scrub equals single-scrub for the whole corpus.
- [x] `1.4.5` `TestContextPreserved` — diagnostic text around a masked token survives
      (timestamps, log levels, messages remain legible), guarding against over-masking.
- [x] `1.4.6` `TestCrossLineSecret` — a secret split across two lines is still masked.
- [x] `1.4.7` `TestRuleOrdering` — a PEM block is masked as one span, not shredded by the
      generic rule.
- [x] `1.4.8` `TestEmptyAndEdgeInputs` — `""`, whitespace-only, 1 MiB single line, invalid
      UTF-8 bytes, and a nil `[]string` all handled without panic.
- [x] `1.4.9` `BenchmarkScrubThroughput` — full pipeline sustains **≥ 20,000 lines/sec/core**
      (ARCH §6.2). Record the number in the PR description.
- [x] `1.4.10` `TestNoDiskArtifacts` — assert the package imports no `os`, `io/ioutil`, or
      temp-file API; scrubbing leaves nothing on disk.

### 1.5 Milestone 1 quality gate

- [x] `1.5.1` `go vet ./...` exits `0`.
- [x] `1.5.2` `test -z "$(gofmt -l .)"` exits `0`.
- [x] `1.5.3` `go test -race -timeout 30s ./internal/scrubber/...` exits `0` with **no** data
      races and **no** skipped tests.

### 1.6 Defects found in the ratified spec — RESOLVED

All five were found while implementing Milestone 1 and have since been **ratified and fixed**.
`ARCHITECTURE.md` §6.4 and §6.5 carry the amendments; each is covered by a live conformance test.

| # | Defect | Evidence | Severity |
|---|---|---|---|
| **D-1** | **Rule 7 `generic_secret_kv` misses JSON-form secrets.** The alternation is followed by `\s*[:=]\s*`, so a `"` between the key and the colon defeats it. `\b` also fails on `_`, so `auth_token=…` is missed entirely. | `{"password":"hunter2"}` → **unchanged**<br>`{"api_key":"sk-live-abcdef123456"}` → **unchanged**<br>`auth_token=abc123xyz789` → **unchanged** | **High — leak** |
| **D-2** | **Rule 10 `k8s_secret_mount` only matches one word order.** It requires `token`/`secret`/`ca.crt` *after* `kube-system`, but the canonical log form puts the path first. | `reading /var/run/secrets/kubernetes.io/serviceaccount/token for kube-system` → **unchanged** | **High — leak** |
| **D-3** | **Rule 11 pre-empts rule 1 across the M3 join.** The per-line pass redacts the `-----BEGIN` marker, so by the time the cross-line pass runs, rule 1 has no BEGIN…END pair and the **base64 key body survives**. | 4-line PEM block → body `MIIEowIBAAKCAQEAy8Dbv8…` emitted verbatim | **Medium — leak** |
| **D-4** | **1.2.7 is self-contradictory.** "partially-masked buffer … never raw" cannot both hold for an ordered manifest: aborting after rule 6 leaves every rule 7 secret in the buffer. An implementation following the text literally leaks. | Reproduced during implementation: `password=secretNumber16` returned unmasked beside a masked URI on the same line | **High — leak** |
| **D-5** | **ARCH §6.2 budget not met on any measured platform.** 11 rules × 2 passes (per-line + M3) measures **~7,900 lines/sec** on `windows/arm64`, against a 20,000 target. | `BenchmarkScrubThroughput`, 128-line representative slice | Medium |

**Resolution taken for D-4 (already implemented).** Cancellation is observed at **line boundaries
only**; a line is masked to completion or not returned. Rationale is in the `scrub` doc comment:
the pipeline is pure CPU with no I/O, so there is nothing to interrupt, and interrupting it can only
produce a leak. This satisfies 1.2.7's *intent* (prompt abort of a large batch) without its
contradiction.

**Resolutions applied** (all ratified, all covered by live conformance tests):

- **D-1 → fixed** in `ARCHITECTURE.md` §6.4: optional quote before the separator, `[\w-]{0,20}` key
  prefix so `auth_token` matches, and capture groups so only the value is replaced and the
  surrounding JSON survives. Tests: `TestCorpusTotalMasking` (`kv-json-object`, `kv-json-nested`),
  `TestCorpusPreservesDiagnostics`.
- **D-2 → fixed** in §6.4: both word orders accepted, gap still bounded to 80 non-newline
  characters. Tests: `TestRuleByRule` (`k8s_secret_mount`), corpus group `k8s_service_accounts`.
- **D-3 → fixed** in §6.5: the cross-line pass runs before the per-line pass, so multi-line rules
  evaluate ahead of the single-line `private_key_pem_body` fallback and the PEM body no longer
  survives. Test: `TestD3_CrossLinePEMBlockIsRemovedAsOneSpan` (was a skipped defect test; now a
  live conformance test).
- **D-4 → fixed** as described above.
- **D-5 → fixed** in §6.5: `Rule.IsMultiLine` added, derived by probe and asserted in both
  directions by `TestMultiLineFlagMatchesCapability`. The cross-line pass now runs **1 of 11**
  patterns. Rule 7's value class deliberately excludes `\n`, which keeps the pass cheap and
  correct. Tests: `TestMultiLineFlagMatchesCapability`, `TestCrossLinePassRestrictedToMultiLineRules`.

**Throughput after the fixes** (`windows/arm64`, corpus-driven, 13,056-line slice):
**~187,000 lines/sec**, against the ARCH §6.2 budget of 20,000. CI on `ubuntu-latest` remains the
authoritative measurement.

**Deferred, recorded not dropped:** a `key=value` secret split across a newline is no longer caught
by the cross-line pass, since rule 7 is now single-line by design. A future `secret_continuation`
rule may address it (`ARCHITECTURE.md` §6.5).

### ✅ MILESTONE 1 — COMPLETE AND RATIFIED

**Ratified by the Architect. Closed at CI run `36483537879`** (`ubuntu-latest`, Go 1.23, commit
`2827e90`) — job "Go quality gates" **success**, `G3 - go test -race` **success**, no data race
reported. Re-confirmed green on the following documentation commit.

| Gate | Result |
|---|---|
| G1 `go vet ./...` | ✅ exit 0 |
| G2 `test -z "$(gofmt -l .)"` | ✅ clean |
| G3 `go test -v -race -timeout 30s ./...` | ✅ **exit 0 on linux/amd64** |
| `go vet -tags race ./...` (added) | ✅ exit 0 |
| Local suite (windows/arm64, no `-race`) | 25 top-level + 28 subtests, 0 failures, 0 skips |
| Throughput | ~187,000 lines/sec vs the §6.2 budget of 20,000 |

Defects D-1 … D-5 are all closed with live conformance tests (see §1.6). Milestone 2 is
unblocked.

**Standing constraint carried forward:** `-race` is unavailable on `windows/arm64` (a platform
limitation, not configuration). G3 is never verified locally and is never waived — the CI run is its
only authority.

### ▶ TERMINAL VALIDATION TEST — Milestone 1

> **Command:** `go test -race -timeout 30s -run 'TestScrubCorpusTotalMasking|TestNoPlaintextSecretSurvives|TestIdempotence' -v ./internal/scrubber/...`
>
> **Pass condition:** exit code `0`; the corpus masking rate is **100%**; the plaintext
> substring scan returns **zero** matches; idempotence holds byte-for-byte.
>
> **Maps to:** PRD AC-2, ARCH §6, invariants I-A1 and I-A5.
>
> **Done when:** all boxes in Milestone 1 are `[x]`, §1.5 is green, and this command exits `0`.

#### ✅ Milestone 1 status: COMPLETE

**G3 evidence.** CI run **36483324256**, `ubuntu-latest`, Go 1.23, commit `a48ac34` — job
"Go quality gates" **success**, with `G3 - go test -race` **success** and no data race reported.
This is the first and only run in which G3 executed rather than failing to build.

| Gate | Result |
|---|---|
| G1 `go vet ./...` | ✅ exit 0 |
| G2 `test -z "$(gofmt -l .)"` | ✅ clean |
| G3 `go test -v -race -timeout 30s ./...` | ✅ **exit 0 on linux/amd64** |
| `go vet -tags race ./...` (added) | ✅ exit 0 |
| Local suite (windows/arm64, no `-race`) | 25 top-level + 28 subtests, 0 failures, 0 skips |
| Throughput (windows/arm64) | ~187,000 lines/sec vs the §6.2 budget of 20,000 |

**Three corrections made during the G3 push, recorded so they are not repeated:**

1. **My first diagnosis of the G3 failure was wrong.** I attributed it to the 30s budget from
   run *duration* alone and shipped a fix to test sizes. The actual cause was a **build-tag
   defect**: `targetPlatform()`/`goPlatform()` lived in a `//go:build !race` file while
   `benchmark_test.go` (untagged) called them, so the `-race` build failed to link. G1 and G2
   could not see it because they typecheck the opposite variant. Corrected in `73ef836`.
2. **The diagnostic step I added to surface the error broke the workflow.** Runs `36482677704`
   and `36483065331` report **zero jobs** — the signature of a workflow that fails to parse, as
   opposed to a step that fails. Two CI cycles lost to my own instrumentation. Reverted.
3. **Prevention added:** `go vet -tags race ./...` in CI. It typechecks the exact file set G3
   compiles, needs no race runtime, and turns this class of defect into a cheap red step before
   G3 rather than an opaque link error.

**Standing constraint:** `-race` is unavailable on `windows/arm64` (a platform limitation, not a
configuration error). G3 is therefore never verified locally and is *never waived* — the CI run is
its only authority. Any future change to build tags or platform-dependent test helpers must be
checked against the `-race` file set, not just the default one.

---

## Milestone 2 — Python Triage Agent & GitOps Diff Generator

**Goal:** a schema-enforcing analysis service that turns a scrubbed Incident Payload into
either a Tier-1 GitOps diff or a Tier-2 War-Room dispatch. **Delivers:** `agent/`.
**Satisfies:** PRD F2, F3, AC-3; ARCH §4, §5.

### 2.1 Schemas (Pydantic v2)

- [x] `2.1.1` Create `agent/models.py` as the schema source of truth, matching ARCH §4.1 and
      §5.1 field-for-field — names, types, nullability, enums.
- [x] `2.1.2` Define `IncidentPayload`, `ResourceLimits`, `ClusterEvent`, `RedactionReport`,
      `TriageResponse`, `RootCause`, `AffectedScope`, `Remediation`, `VerificationPolicy`,
      `SuccessCriteria`.
      > **Ratified naming decision:** the response model is `TriageResponse`, not `RCAResponse`
      > (2.2.2). It carries a transport-level `status` (`TRIAGED` / `ESCALATED` / `UNKNOWN` /
      > `REJECTED`) that is distinct from the RCA content, so one name covering both is more
      > accurate. ARCH §5 is otherwise followed literally.
- [x] `2.1.3` Define closed enums `Reason`, `Classification`, `Severity`, and
      `BlastRadiusTier` with exactly the ARCH §5 values.
- [x] `2.1.4` Pin `schema_version` as `1.0.0` and reject mismatched majors with a `422`.
- [x] `2.1.5` Validate `tests/fixtures/sample-incident.json` against `IncidentPayload` in a
      test — contract drift fails the build, not production.
- [x] `2.1.6` Assert `exit_code` is nullable and that `reason == OOMKilled` ⇒ `exit_code == 137`
      and a non-null `memory_limit` (invariant I-A2).

#### 2.1 status: COMPLETE

**Confirmed on the remote runner.** CI run **36485670189** (`ubuntu-latest`, Python 3.11, commit
`baf7b9b`): job "Python quality gates" **success**, every step green. The Go job also stayed green in
the same run, so nothing regressed.

| Gate | Local | CI (run 36485670189) |
|---|---|---|
| G1 `go vet ./...` | ✅ exit 0 | ✅ success |
| G2 `test -z "$(gofmt -l .)"` | ✅ clean | ✅ success |
| G3 `go test -race -timeout 30s ./...` | n/a (unsupported on windows/arm64) | ✅ success |
| G4 `black --check agent/` | ✅ exit 0 | ✅ success |
| G5 `flake8 agent/` | ✅ exit 0 | ✅ success |
| G6 `mypy --strict agent/` | ✅ 3 source files clean | ✅ success on **Python 3.11** |
| — `pytest agent/tests/ -q` | ✅ 87 passed | ✅ success |
| — GPU-dependency guard (ARCH §2) | ✅ verified | ✅ success |
| — I-B5 mutation-verb guard (ARCH §5.4) | ✅ verified with negative control | ✅ success |

The CI run of G6 on a genuine 3.11 with only `agent/requirements.txt` installed confirms the host
caveat below was a local artifact and not a schema problem.

**Tooling config lives at the repository root, not in `agent/`.** The charter's commands
(`flake8 agent/`, `mypy --strict agent/`) run from the root, and both tools resolve configuration
relative to the working directory. A `setup.cfg` inside `agent/` is therefore invisible to those
exact invocations — the first version of this work put it there and it silently did nothing, leaving
G5 reporting 79-column violations against black-formatted code.

**Host caveat on G6.** The local interpreter is Python 3.14 and has `numpy` 2.5.3 installed
(a leftover from `fastembed`/`onnxruntime`, which are Milestone 2.7 dependencies and are *not* in
`agent/requirements.txt`). numpy's stubs use PEP 695 `type` statements, which `mypy` refuses to parse
under `--python-version 3.11`. CI installs only `agent/requirements.txt` on a clean 3.11 and has no
numpy, so it is unaffected. Locally the gate is run as
`mypy --strict --python-version 3.14 agent/`.

**Also implemented, beyond the 2.1 checklist:**

- `agent/requirements.txt` — pinned, GPU-free (ARCH §2), with the gate tools included so local and
  CI install identical versions.
- `agent/Dockerfile` — `python:3.11-slim`, UID/GID 10001, `/app` owned by the runtime user,
  `PYTHONUNBUFFERED=1` / `PYTHONDONTWRITEBYTECODE=1` / `TMPDIR=/tmp`, `USER 10001:10001` before any
  runtime step, exec-form uvicorn entrypoint.
- `agent/conftest.py` — puts `agent/` on `sys.path` so `pytest agent/tests/` works from the root.
  ARCH §3 describes a flat module, not a package, so `import models` does not otherwise resolve
  from the root.
- `tests/fixtures/sample-incident.json` — the canonical Contract A payload (2.1.5).
- Two new CI guards, both **verified with a negative control** so they are known to fire:
  GPU-dependency rejection (scoped to non-comment lines, because the requirements file's own
  header explains the prohibition in prose and a naive grep matched its own documentation), and
  an `ast`-based scan of `agent/models.py` for mutating-verb field names enforcing ARCH §5.4 I-B5.
  The earlier grep-based version of the I-B5 guard required quoted field names, which Python never
  uses, so it could not have failed.

**The git-patch validator rejects markdown-fenced diffs.** `I-B4` forbids scraping a diff out of
markdown, so ``` ```diff ``` fences are refused rather than unwrapped. Accepting a fenced diff would
mean a model that wrapped its answer produced a review artifact while a byte-identical unfenced
response was rejected — incoherent, and the strict direction is the safe one. There is a paired test
proving the unfenced equivalent is still accepted.

### 2.2 FastAPI service

- [x] `2.2.1` Create `agent/main.py` with an app factory, lifespan context, and
      `GET /healthz`.
- [x] `2.2.2` `POST /v1/incidents` accepts `IncidentPayload`, returns `TriageResponse`.
      **Both paths are served, one handler.** `/v1/incidents` is the canonical contract (ARCH §4,
      and ROADMAP 3.4.4 has the Go emitter POST there in Milestone 3); `/api/v1/triage` is the
      versioned-prefix form this task specified. The mistake is not symmetric — serving only the
      alias would leave M3's emitter posting to a 404, surfacing only at integration — so both are
      mounted on a single handler and `TestBothTriagePaths` asserts they cannot diverge. **Worth
      ratifying:** if only one path is wanted, remove the other and update ARCH §4 plus 3.4.4 in the
      same change.
- [x] `2.2.3` Return `422` with Pydantic errors on schema violation — **never** coerce into a
      Tier-2 dispatch (ARCH §4.3).
- [x] `2.2.4` Return `400 {"error":"malformed_json"}` for unparseable bodies.
- [x] `2.2.5` `429 {"error":"sandbox_busy"}` when the sandbox budget is exhausted.
      **Implemented as a concurrency budget, not a cgroup sandbox.** `agent/budget.py` bounds
      in-flight investigations and returns `429 {"error":"sandbox_busy"}` with `Retry-After`.
      The envelope and the mechanism are real and tested, but the *sandbox* this is named after
      does not exist until 2.4, so what is enforced today is concurrency only. Worth renaming
      when the sandbox lands.
      **Deferred to 2.4.** No sandbox exists yet, so there is no budget to exhaust. The envelope
      is reserved in `main.py` and covered by the structured-error tests, but nothing can currently
      return 429. Ticking it now would claim a capability that does not exist.
- [x] `2.2.6` Return `500 {"error":"analysis_failed"}` on unrecoverable failure, with the
      incident escalated to Tier-2.

#### 2.2 status: COMPLETE (except 2.2.5, deferred to 2.4)

**Authoritative evidence: CI run `36489573043`, commit `ab659c0`, conclusion `success`.** Every Python
step green on real CPython 3.11, and G3 `go test -race` green (never waived, ARCH AD-10).

| Gate | Result |
|---|---|
| G4 `black --check agent/` | ✅ exit 0, 8 files unchanged |
| G5 `flake8 agent/` | ✅ exit 0, 0 findings |
| G6 `mypy --strict agent/` | ✅ no issues in 8 source files |
| `pytest agent/tests/ -q` | ✅ **148 passed**, 0 failed |
| G1/G2/G3 (Go) | ✅ unregressed; G3 green on CI |
| Dockerfile static audit | ✅ **20/20** checks |
| `docker build` | ❌ **BLOCKED — no container runtime on this host** |

**The first 2.2 commit passed every local gate and still failed CI's G5.** Worth recording because the
signature was misleading: G4 *passed* and G5 *failed*, which reads like a formatting disagreement but
was actually the interpreter.

`agent/tests/test_api.py:692` contained an f-string with a backslash inside its expression part — PEP
701, valid from Python 3.12. The dev host runs 3.14, where it parses; CI pins 3.11 (AGENTS.md §2),
where it is a hard `SyntaxError`, so flake8 reported **E999** remotely while black, mypy and pytest
were all green locally. Confirmed by compiling every source with a real CPython 3.11.16:
`f-string expression part cannot include a backslash`.

Three gaps this exposed, all now closed:

1. **`ast.parse(feature_version=(3,11))` does not gate PEP 701.** The cheap syntax check gave a false
   pass. Detection in `test_compat.py` is therefore textual, and additionally compiles every source
   with a real 3.11 when one is reachable.
2. **`black --check` was not deterministic across hosts.** The same black 26.5.1 reformatted a file
   differently under 3.11 than 3.14, because auto target-detection is host-sensitive.
   `agent/pyproject.toml` pins `target-version = ["py311"]`. It lives in `agent/` rather than the repo
   root on purpose: black resolves config from the common base of its sources, but **mypy** resolves it
   from the CWD, so a root `pyproject.toml` would have hijacked mypy's discovery and silently dropped
   `mypy_path = agent`. Verified empirically that mypy still reads `setup.cfg`.
3. **A UTF-8 BOM in `pyproject.toml` breaks black** with `TOMLDecodeError` at line 1. BOMs are
   forbidden by the TOML spec; stripped, and the repo is audited clean.

The new guard was validated with a negative control: planting the exact construct fails it on **both**
3.14 and 3.11, and real 3.11 rejects the plant. (A first control attempt planted `chr(92)` instead of
a literal backslash and passed — the guard was right and the control was wrong.)

**Triage behaviour.** `OOMKilled` with a readable manifest and a container-local fault produces
`TIER_1_TOIL` with a one-line unified diff raising `256Mi → 512Mi`. Everything else escalates:
node pressure, a restart count above the policy ceiling, a crash loop, a dependency fault, an
unparseable quantity, an unreadable manifest, or a manifest without the target line.

**The running service escalates by default.** It is wired to `unreadable_manifest_provider()`, so
with no GitOps checkout it cannot satisfy I-B2 and emits no patch. Fail-closed is the *normal* path
until Milestone 2.5 provides a real checkout — not a corner case.

**Three real bugs caught by the tests, all now fixed:**

1. **Byte formatter iterated suffixes smallest-first**, so any multiple of 1024 rendered as `Ki`.
   A 256Mi limit doubled to `524288Ki` instead of `512Mi` — numerically correct, but a form no
   engineer writes and a reviewer has to stop and decode.
2. **The replacement line lost its indentation.** The diff emitted `+memory: "512Mi"` at column 0,
   which would produce an invalid manifest. A patch that breaks the file it claims to fix is worse
   than no patch. The original line's leading whitespace is now preserved, and a test asserts the
   indent is unchanged rather than matching a literal space count.
3. **`"upstream"` was too weak a dependency signal.** The shared fixture contains
   `retrying upstream call`, so a crash-loop incident was classified `DEPENDENCY_FAILURE` instead
   of `CONFIGURATION_ERROR`. Both are Tier-2, so the safety property held, but the incident would
   have reached the wrong war-room queue. Markers now require an actual *failed* connection.

**Sibling health is an inference, and is labelled as one.** Contract A carries no observation of
sibling containers, so `_siblings_healthy` infers containment from the fact that a *container-local*
`OOMKilled` means the kernel enforced that container's cgroup limit — and returns `False` whenever a
node-level signal (`Evicted`, `MemoryPressure`, …) is present. Without this predicate the Tier-1 path
would be unreachable; with it, a node-wide memory shortage cannot be "fixed" by raising a limit that
was never the problem. Milestone 2.4's sandbox replaces the inference with a direct observation.

**Container build is BLOCKED, not waived.** `docker`, `podman`, `nerdctl` and `buildah` are all
absent and no container service is running, so `docker build -t srek3s-agent:test -f agent/Dockerfile .`
could not be executed. What *was* verified statically: 20/20 hardening checks (base image, UID/GID
10001, nologin shell, `/app` ownership, `PYTHONDONTWRITEBYTECODE`, `TMPDIR`, `USER` preceding
`ENTRYPOINT`, exec form, no `--privileged`/`cap_add`/`security_opt`, no root fallback, layer
ordering), both `COPY` sources resolve from the repo-root build context, and `main:app` imports and
registers its routes with only `agent/` on the path. What a real build would additionally prove and
this host cannot: layer resolution, `groupadd`/`useradd` succeeding in the slim image, pip
resolving on linux/amd64, and the read-only-rootfs runtime.

### 2.3 Deterministic classifier
- [x] `2.3.1` Create `agent/classifier.py` implementing the deny-by-default routing rule from
      ARCH §5.3 exactly.
- [x] `2.3.2` Implement all six Tier-1 preconditions: `OOMKilled`, `restart_count <=
      policy.max_restarts` (default 5), single affected replica, healthy siblings, remedy shape
      in the `MEMORY_LIMIT_RECALIBRATION` allow-list, `risk_level != HIGH`.
- [x] `2.3.3` Default to `TIER_2_ARCHITECTURAL` when any precondition is unproven.
- [x] `2.3.4` Add table-driven tests: 10+ Tier-1 cases and 10+ Tier-2 cases, including
      10 Tier-1 and 10 Tier-2 cases, covering dependency failure, cascading 5xx and node-level
      pressure. **Caveat:** "multi-pod correlation" is represented by node-pressure events
      (`Evicted`, `MemoryPressure`, `NodeNotReady`), because Contract A carries a single pod and
      cannot express genuine multi-pod correlation. That needs a wider input.
      multi-pod correlation, dependency failure, and cascading-error signatures.
- [x] `2.3.5` Assert the model's `confidence` value is **never** read by the router
      (self-test: shuffle confidence, tier must not change).

### 2.4 Ephemeral investigation sandbox

- [x] `2.4.1` Create `agent/sandbox.py` with a disposable worker per investigation.
- [x] `2.4.2` Enforce the cgroup budget: `256Mi` memory, `500m` CPU.
      **Enforced with `RLIMIT_AS`/`RLIMIT_CPU`, not a delegated cgroup.** The limits are installed in
      the child before `exec`, so the kernel enforces them and they cannot be raised from inside. A
      cgroup is not reachable from inside an ordinary container, so the runner *probes* for a cgroup v2
      hierarchy and writes there when one exists, and reports `cgroup_enforced=False` when it does not.
      Claiming a cgroup budget that was never applied would be worse than reporting no budget. The
      rlimits are exercised on CI's `ubuntu-latest`; on Windows they are not available and the deadline
      plus the kill are the enforcement mechanisms, which `resource_limits_supported()` reports.
- [x] `2.4.3` Bound every investigation with a **monotonic** deadline via
      `time.perf_counter()` — never wall-clock (AGENTS §3.3).
- [x] `2.4.4` Tear the worker down on timeout/cancel; assert no state survives into the next
      investigation.
- [x] `2.4.5` Assert the sandbox holds no cluster credential and no egress other than the one
      The child gets a constructed environment from an explicit **allow-list**
      (`SANDBOX_ENV_ALLOWLIST`), never an inherited one, so no kubeconfig, service-account token or
      cloud key reaches it and adding a variable to the parent cannot widen its reach. Egress is
      restricted at the network layer by the `NetworkPolicy` in `deploy/agent.yaml`, so the
      authoritative control is not trusted to the code.
      authorized model call.
- [x] `2.4.6` Emit `analysis_latency_ms` computed from `time.perf_counter()`.

### 2.5 Constrained decoding and patch generation

- [x] `2.5.1` Create `agent/llm.py` enforcing Pydantic-constrained decoding against
      `RCAResponse`.
- [x] `2.5.2` Treat freeform markdown or non-JSON output as a **fatal** validation failure —
      no regex scrape, no best-effort parse, no partial response (invariant I-B4).
- [x] `2.5.3` Produce both deliverables: human-readable `rca_markdown` **and** machine-parsable
      Both `rca_markdown` and `remediation.git_patch` are populated on every response and asserted
      separately; the patch is never fenced (I-B4).
      `remediation.git_patch`.
- [x] `2.5.4` Create `agent/patch.py` to synthesize a unified diff with `---`/`+++`/`@@`
      headers, repo-relative paths, no absolute paths, and no binary hunks.
- [x] `2.5.5` Validate every patch with `git apply --check --whitespace=nowarn` against the
      **Three layers, all required** (AGENTS.md §1 "Dual-Layer Patch Verification", §3.3): the
      positional round-trip, a **YAML AST** check that both documents parse and differ at exactly one
      semantic field (`resources.limits.memory` of the named container, located structurally), and
      `git apply --check --whitespace=nowarn` against those same bytes in a throwaway repository. Each
      catches what the others cannot: the YAML layer catches a textually perfect but semantically wrong
      patch, and git catches a malformed diff the line arithmetic happened to accept.
      **NOT DONE - and the current `patch_validated: true` is weaker than this checkbox.**
      `patch_validated` is set after an in-process round-trip: the diff is applied back against
      the real manifest text and asserted to change exactly the resolved line and no other. That
      is a genuine verification of *applies to this manifest*, but it is not the `git apply
      --check` that ARCH §5.4 I-B2 names and this checkbox requires - there is no GitOps checkout
      to run it against. **I-B2 is therefore only partially satisfied, and this needs a
      decision:** either wire a real `git apply --check` in, or amend I-B2 to say that
      positional round-trip verification satisfies it.
      target manifest before setting `patch_validated: true`.
- [x] `2.5.6` On apply-check failure, **downgrade to Tier-2** with an empty patch. Never emit an
      Any of the three layers failing discards the patch and escalates to Tier-2 with `git_patch: ""`.
      A diff that matches a masking rule is also **refused rather than redacted**: rewriting a line
      inside a diff would break the hunk header's counts, and a credential in a GitOps PR would be
      copied into every clone.
      Not done: the downgrade path is real and tested, but it triggers on the positional
      verification, not on the `git apply --check` failure this checkbox names.
      unvalidated diff (PRD R2).
- [x] `2.5.7` Enforce Tier-2 ⇒ `git_patch == ""` and `patch_validated == false` (invariant I-B1).
- [x] `2.5.8` Apply the ARCH §6 rule set as a defence-in-depth re-scan to every outbound string
      (invariant I-B6), using the same rule IDs.

### 2.6 War-Room dispatch (Tier-2)

- [x] `2.6.1` Create `agent/warroom.py` emitting an RCA + evidence bundle with no patch.
- [x] `2.6.2` Include incident identity, affected scope, scrubbed evidence, and the explicit
      "do not apply blindly" marker.
- [x] `2.6.3` Assert Tier-2 output contains **no** field capable of expressing a cluster write
      verb (invariant I-B5).

### 2.7 Dependencies and hardening

- [x] `2.7.1` Create `agent/requirements.txt` and `agent/pyproject.toml` with Pydantic v2 and
      FastAPI.
- [x] `2.7.2` Add a CI assertion that **no** `torch`, `nvidia-*`, `cuda*`, or `tensorflow`
      package is present in the dependency tree (AGENTS §2).
- [x] `2.7.3` Add `deploy/agent.yaml` with `runAsUser/Group: 10001`, `readOnlyRootFilesystem:
      `deploy/agent.yaml` carries UID/GID 10001, `readOnlyRootFilesystem: true`, `capabilities.drop:
      ["ALL"]`, `allowPrivilegeEscalation: false`, `seccompProfile: RuntimeDefault`, a writable
      `emptyDir` at `/tmp` only, and `automountServiceAccountToken: false`. The last is deliberate: I-B5
      is that no artefact can express a write verb, and withholding the token entirely is the stronger
      form of the same property.
      true`, `capabilities.drop: ["ALL"]`, `allowPrivilegeEscalation: false`,
      `seccompProfile: RuntimeDefault`, writable `emptyDir` at `/tmp` only.
- [x] `2.7.4` Set `PYTHONDONTWRITEBYTECODE=1` and `TMPDIR=/tmp` in the agent container.

### 2.8 Milestone 2 quality gate

- [x] `2.8.1` `black --check agent/` exits `0`.
      Verified on CI run `36492481971`, commit `abf7b15`, real CPython 3.11.16: 12 files unchanged, exit 0.
- [x] `2.8.2` `flake8 agent/` exits `0`.
      Verified on CI run `36492481971`: exit 0, 0 findings.
- [x] `2.8.3` `mypy --strict agent/` exits `0`.
      Verified on CI run `36492481971`: no issues in 12 source files.
- [x] `2.8.4` `pytest agent/ -q` exits `0`.
      Verified on CI run `36492481971`: **249 passed**, 0 failed.

### 2.8 status: COMPLETE

**All quality gates pass, and all 42 Milestone 2 checkboxes are now ticked and individually evidenced.**

**Authoritative record: CI run `36519511237`, commit `f41a91f`, conclusion `success`** — all 13 Go
steps and all 15 Python steps green, including G3 `go test -race` (never waived, ARCH AD-10), the
container build, and the runtime assertion that the effective uid is `10001` and `main:app` imports.

| Gate | Result |
|---|---|
| G1 `go vet ./...` | ✅ exit 0 |
| G2 `test -z "$(gofmt -l .)"` | ✅ clean |
| G3 `go test -v -race -timeout 30s ./...` | ✅ green on CI |
| G4 `black --check agent/` | ✅ exit 0 |
| G5 `flake8 agent/` | ✅ exit 0 |
| G6 `mypy --strict agent/` | ✅ no issues in 20 source files |
| `pytest agent/tests/ -q` | ✅ **327 passed**, 0 failed |
| Container build | ✅ green on `ubuntu-latest` |
| Container runtime smoke | ✅ `main:app` imports; effective uid `10001` |
| Terminal validation test | ✅ **318 passed** |

**Two places where the implementation is narrower than the checkbox, recorded so nobody has to
rediscover them:**

1. **`2.4.2` is enforced with `RLIMIT_AS`/`RLIMIT_CPU`, not a delegated cgroup.** The rlimits are
   installed in the child before `exec` and cannot be raised from inside. A cgroup is not reachable
   from inside an ordinary container, so the runner probes for a cgroup v2 hierarchy, writes there when
   one exists, and reports `cgroup_enforced=False` when it does not. The budget is real and
   kernel-enforced; it is simply not a cgroup, and `SandboxResult` says so rather than implying
   otherwise. The rlimits are exercised on CI's `ubuntu-latest`; on Windows they do not exist and the
   monotonic deadline plus the kill are the enforcement.
2. **`2.5.5` is three layers, not two.** The positional round-trip and `git apply --check` that the
   checkbox names, plus a YAML AST check, because AGENTS.md §1 and §3.3 require structural YAML
   validation and the positional check is not that. Each layer catches something the others cannot.

**Bugs the tests caught while building this, all fixed** — recorded because each was invisible to the
layer that existed before it:

- Every `- name:` sequence entry was read as a container name. Kubernetes manifests are full of those
  that are not containers (named ports, named volume mounts), so a realistic Deployment silently
  switched the target off and every Tier-1 patch against it failed to locate its target. It failed
  closed — no wrong patch was ever emitted — but it escalated incidents that were cleanly remediable,
  which is the other half of being wrong.
- The first fix for that was itself wrong: gating the `- name:` test on `containers` being in scope,
  while `containers` was only recorded *after* a container had been found, made the guard
  unsatisfiable and broke every lookup including the trivial ones.
- `verify_patch` required the old value to vanish document-wide, so a correct patch was rejected
  wherever `requests.memory` equalled `limits.memory`.
- A `CrashLoopBackOff` reason was treated as proof of a `CONFIGURATION_ERROR`, so an incident with no
  recognisable evidence could never reach `UNKNOWN`.
- A `status_hint` field let an escalated incident report `status: TRIAGED` beside an empty patch.
- `llm.reconcile` wrote `git_patch`/`risk_level` at the top level of `TriageResponse` when they live
  under `remediation`; the strict model rejected the document. Only a real validation surfaced it.
- The `llm` error message quoted the offending output, which put model-echoed incident content into
  logs verbatim — a disclosure bug in the safety path itself.

**A third host/CI divergence, same signature as the two before it.** G6 passed on the
windows/arm64 development host and failed on `ubuntu-latest`, with no other signal. Cause:
`os.setsid()  # type: ignore[attr-defined]` in `sandbox.py`. `setsid` is absent from typeshed on
Windows and present on Linux, so the ignore was **used** locally and **dead** on CI — and
`setup.cfg` sets `warn_unused_ignores = True`. Fixed with `getattr(os, "setsid", None)`, which
type-checks identically on both. `agent/tests/test_compat_platform.py` now fails the build if an
ignore ever sits on a platform-sensitive line again, and it carries a negative control so the
detector itself cannot silently stop working.

**Measured, not assumed:** `git apply` *tolerates* a wrong start offset when the content matches, so
the structural check catches what git forgives and git catches what a line diff would miss. Two of my
own tests asserted the opposite and failed; both are now corrected and one pins the tolerance
deliberately.

### ▶ TERMINAL VALIDATION TEST — Milestone 2

> **Command:** `pytest agent/tests/test_schemas.py agent/tests/test_triage.py agent/tests/test_ib2.py agent/tests/test_milestone2.py agent/tests/test_api.py -v`
>
> **Pass condition:** exit code `0`, asserting all of:
> 1. `sample-incident.json` validates against `IncidentPayload`; every field in ARCH §4.1 is
>    present with the specified nullability.
> 2. The generated `git_patch` passes `git apply --check` against
>    `tests/fixtures/oom-restartloop.yaml` (exit `0`), passes the YAML AST check, and
>    increases `resources.limits.memory`.
> 3. Freeform non-JSON model output raises a fatal error — no partial response is returned.
> 4. Tier-2 classification yields `git_patch == ""` and `patch_validated == false`.
> 5. The sandbox tears down on timeout and leaks no state between investigations.
> 6. No forbidden GPU dependency appears in `requirements.txt`.
>
> **Maps to:** PRD AC-3, ARCH §4/§5, invariants I-A2, I-B1, I-B2, I-B4, I-B5, I-B6.
>
> **Done when:** all boxes in Milestone 2 are `[x]`, §2.8 is green, and this command exits `0`.

---

## Milestone 3 — Go Sentinel Event Watcher

**Goal:** read-only, defensive cluster observation producing contract-valid Incident Payloads
within the 2s budget. **Delivers:** `cmd/sentinel`, `internal/k8s`, `internal/emitter`,
`deploy/`. **Satisfies:** PRD G1, AC-1, AC-4; ARCH §3, §7, §8.

### 3.1 Read-only client

- [ ] `3.1.1` Create `internal/k8s/client.go` using official `k8s.io/client-go`,
      `k8s.io/api`, `k8s.io/apimachinery` (AGENTS §2).
- [ ] `3.1.2` Build the clientset from in-cluster config with an explicit, context-bounded
      timeout; no `context.Background()` on any blocking call.
- [ ] `3.1.3` Handle and log (safely) the in-cluster config failure path — no credential
      material in error text.
- [ ] `3.1.4` Confirm **no** mutating client method is reachable from any package.

### 3.2 Defensive pointer handling

- [ ] `3.2.1` Create `internal/k8s/guard.go` with nil-safe accessors for the fields named in
      AGENTS §3.1: `State.Terminated`, `State.Waiting`, `State.LastTerminationState`,
      `Resources.Limits`, `Resources.Requests`, `ContainerStatuses[i]`.
- [ ] `3.2.2` Check **every** preceding level in the pointer chain, not just the first hop.
- [ ] `3.2.3` Enforce that raw chained access outside `guard.go` is forbidden; add a lint/test
      note and a reviewer checklist entry.
- [ ] `3.2.4` `TestNilPointerSafety` — feed synthetic `Pod` objects with nil `ContainerStatuses`,
      nil `State`, nil `Terminated`, nil `Waiting`, and nil `Limits`; assert **no panic**.
- [ ] `3.2.5` Run the nil-safety tests under `-race`.

### 3.3 Informers and classification

- [ ] `3.3.1` Create `internal/k8s/watcher.go` with pod and event Informers on a shared
      `cache.SharedInformerFactory` with an explicit resync period.
- [ ] `3.3.2` Create `internal/k8s/classify.go` extracting `OOMKilled` (terminated, exit code
      `137`) and `CrashLoopBackOff` (waiting, reason `CrashLoopBackOff`).
- [ ] `3.3.3` Deduplicate per `(pod_uid, container_name, failure_signature)` so a stable
      crash loop does not emit one incident per resync.
- [ ] `3.3.4` Join cluster events by `involvedObject.uid`, tolerating an empty event list.
- [ ] `3.3.5` Tie a stop channel to `SIGINT`/`SIGTERM`; drain in-flight jobs before exit.

### 3.4 Egress and scrubbing integration

- [ ] `3.4.1` Create `internal/emitter/payload.go` with wire types matching ARCH §4 **exactly**.
- [ ] `3.4.2` Run **all** log lines and event messages through `internal/scrubber` before
      serialization. There is no code path that serializes raw telemetry.
- [ ] `3.4.3` Populate `redaction_report` from the scrubber's accounting; never emit masked
      values.
- [ ] `3.4.4` Create `internal/emitter/emitter.go`: `POST /v1/incidents` via
      `http.Client` with `context.WithTimeout`; classify `429` as retryable-with-jitter,
      `422` as fatal, `500` as Tier-2 escalation.
- [ ] `3.4.5` Assert no raw secret can reach the HTTP request body — a test scans the
      marshalled body against the fixture corpus.
- [ ] `3.4.6` Round-trip test: emitted JSON validates against `agent/models.py` via the
      canonical fixture.

### 3.5 Concurrency hygiene

- [ ] `3.5.1` Fixed-size worker pool (default 4) consuming a **buffered** channel
      (default 256); a full buffer applies backpressure.
- [ ] `3.5.2` All channel sends are `select`ed against `ctx.Done()` — never an unconditional
      blocking send.
- [ ] `3.5.3` Measure `detection_latency_ms` with a monotonic clock (`time.Since` on a
      monotonic base); no wall-clock timestamps for duration.
- [ ] `3.5.4` `TestNoGoroutineLeak` under `-race`: goroutine count returns to baseline after
      cancellation.

### 3.6 Deployment manifests

- [ ] `3.6.1` Create `deploy/namespace.yaml`, `deploy/kustomization.yaml`.
- [ ] `3.6.2` Create `deploy/rbac.yaml` with a read-only `Role`: `get`/`list`/`watch` on `pods`,
      `events`, `deployments`, `replicasets`. **No** `create`/`update`/`patch`/`delete`.
- [ ] `3.6.3` Create `deploy/sentinel.yaml` with the full ARCH §8 hardening block
      (`runAsUser/Group: 10001`, `readOnlyRootFilesystem: true`, `cap_drop: ["ALL"]`,
      `allowPrivilegeEscalation: false`, `seccompProfile: RuntimeDefault`, `emptyDir` at
      `/tmp` only).
- [ ] `3.6.4` Write a test that **parses** the deploy YAML and asserts every hardening field
      and the absence of any mutating RBAC verb (AC-4, and PRD §3.2).
- [ ] `3.6.5` Assert `agent/` has no ServiceAccount token automount.
- [ ] `3.6.6` Document the offline-import path: `k3s ctr images import` into the internal
      containerd namespace (AGENTS §2).

### 3.7 Milestone 3 quality gate

- [ ] `3.7.1` `go vet ./...` exits `0`.
- [ ] `3.7.2` `test -z "$(gofmt -l .)"` exits `0`.
- [ ] `3.7.3` `go test -race -timeout 30s ./...` exits `0`, including the nil-pointer and
      goroutine-leak tests.
- [ ] `3.7.4` `mypy --strict agent/` still exits `0` (contract unchanged).

### ▶ TERMINAL VALIDATION TEST — Milestone 3

> **Command:** `go test -race -timeout 30s -run 'TestNilPointerSafety|TestNoGoroutineLeak|TestIncidentPayloadContract' -v ./...`
>
> **Pass condition:** exit code `0`, asserting all of:
> 1. No panic and no race on nil-`State` / nil-`Terminated` / nil-`Waiting` / nil-`Limits`
>    synthetic pods.
> 2. Goroutine count returns to baseline after cancellation.
> 3. An emitted payload carries every mandatory ARCH §4 field, is schema-valid, and its
>    scrubbed strings contain zero fixture-corpus plaintexts.
> 4. The parsed `deploy/rbac.yaml` contains **no** mutating verb and `deploy/sentinel.yaml`
>    satisfies every ARCH §8 hardening assertion.
> 5. `detection_latency_ms <= 2000` on the synthetic OOM corpus.
>
> **Maps to:** PRD AC-1, AC-4, ARCH §7/§8, invariants I-A1, I-A2, I-A4.
>
> **Done when:** all boxes in Milestone 3 are `[x]`, §3.7 is green, and this command exits `0`.

---

## Milestone 4 — End-to-End Synthetic Chaos Validation

**Goal:** prove the whole chain against a real k3s cluster — bad pod in, clean RCA and valid
git diff out, no cluster mutation. **Delivers:** `deploy/chaos/`, `tests/e2e/`,
verification loop. **Satisfies:** PRD F4, AC-1, AC-2, AC-3, AC-4 end-to-end.

### 4.1 Chaos fixtures

- [ ] `4.1.1` Create a disposable namespace (e.g. `sentinel-chaos`) with cleanup policy and an
      explicit blast-radius guardrail.
- [ ] `4.1.2` Create `deploy/chaos/oom-badpod.yaml` — a Deployment with a memory limit far
      below the container's steady-state need, so it is deterministically `OOMKilled`.
- [ ] `4.1.3` Create `deploy/chaos/crashloop-badpod.yaml` — a container exiting non-zero on
      start to force `CrashLoopBackOff`.
- [ ] `4.1.4` Embed a **planted** credential in each chaos pod's log output, to verify
      end-to-end that masking holds across the real pipeline.
- [ ] `4.1.5` Assert the chaos manifests cannot be applied outside the disposable namespace
      (namespace guard test).

### 4.2 End-to-end harness

- [ ] `4.2.1` Create `tests/e2e/` with a runner that applies chaos manifests, waits for
      detection, and collects emitted payloads.
- [ ] `4.2.2` Import images into the internal containerd namespace via `k3s ctr images import`
      (AGENTS §2).
- [ ] `4.2.3` Record `detection_latency_ms` for every injected `OOMKilled`; assert
      **p99 ≤ 2000 ms** and `detections == injected_events` (AC-1).
- [ ] `4.2.4` Scan every collected payload against the planted credentials; assert **zero**
      plaintext survivals end-to-end (AC-2).
- [ ] `4.2.5` Assert `rca_markdown` is non-empty, specific, and cites evidence actually
      present in the payload.
- [ ] `4.2.6` For each Tier-1 incident, run `git apply --check` on `git_patch` against the
      chaos manifest and then `git apply` + YAML-parse it; assert the change matches the stated
      root cause (AC-3).
- [ ] `4.2.7` For each Tier-2 incident, assert `git_patch == ""` and that a War-Room dispatch
      was emitted.
- [ ] `4.2.8` Assert no incident in the run produced a cluster mutation: capture the cluster's
      object generation/versions before and after and prove only chaos-namespace changes
      occurred.

### 4.3 Post-remediation health verification loop

- [ ] `4.3.1` Create `agent/verify.py` implementing the `verification_policy` evaluation
      (ARCH §5.2) against a bounded `watch_duration_seconds`.
- [ ] `4.3.2` Emit the three verdicts: `Verified`, `Unresolved` (recurrence ⇒
      `PROMOTE_TO_TIER_2`), `Indeterminate` (`REQUEUE_BOUNDED`).
- [ ] `4.3.3` Enforce `max_requeue_attempts` — no infinite requeue loop.
- [ ] `4.3.4` Integration test: apply a correct Tier-1 diff via GitOps and assert a `Verified`
      verdict; re-inject the same fault and assert `Unresolved` + promotion to Tier-2.
- [ ] `4.3.5` Assert the loop observes only — it performs no write of its own.

### 4.4 Regression golden files

- [ ] `4.4.1` Store `tests/fixtures/expected/oom-expected.patch` as the golden Tier-1 diff.
- [ ] `4.4.2` Assert the generated diff matches the golden diff within an explicitly documented
      tolerance (exact for manifests, normalized for context lines).
- [ ] `4.4.3` Add a golden RCA with an assertion on required sections, so RCA regressions are
      caught without brittle full-text equality.
- [ ] `4.4.4` Ensure every golden file itself contains zero plaintext secrets.

### 4.5 Documentation and final gates

- [ ] `4.5.1` Write operator runbook: deploy, observe, interpret a War-Room dispatch, review a
      Tier-1 PR.
- [ ] `4.5.2` Document the explicit statement that **no** configuration enables direct cluster
      writes, and where that is enforced in code.
- [ ] `4.5.3` `go vet ./...` exits `0`.
- [ ] `4.5.4` `test -z "$(gofmt -l .)"` exits `0`.
- [ ] `4.5.5` `go test -race -timeout 30s ./...` exits `0`.
- [ ] `4.5.6` `black --check agent/`, `flake8 agent/`, `mypy --strict agent/` all exit `0`.
- [ ] `4.5.7` Full acceptance re-run: AC-1, AC-2, AC-3, AC-4 all evidenced in one report.

### ▶ TERMINAL VALIDATION TEST — Milestone 4

> **Command:** `./tests/e2e/run.sh` (requires a running single-node k3s), followed by
> `pytest tests/e2e/test_acceptance.py -v`.
>
> **Pass condition:** exit code `0` across the whole chain, asserting all of:
> 1. Bad pods deployed to k3s produce detected incidents with **p99 detection latency
>    ≤ 2000 ms** and a 1:1 injection-to-detection ratio.
> 2. Every emitted RCA is clean, schema-valid, non-empty, and evidence-grounded.
> 3. Every Tier-1 `git_patch` passes `git apply --check`, applies, and parses; the resulting
>    manifest change matches the stated root cause.
> 4. Every Tier-2 incident yields `git_patch == ""` and a War-Room dispatch.
> 5. **Zero** plaintext credentials appear in any payload, log, or golden file — end-to-end.
> 6. **Zero** cluster mutations by the Sentinel: object generations before and after are
>    identical outside the chaos namespace.
> 7. The post-remediation loop returns `Verified` for a good fix and promotes to Tier-2 for a
>    repeated fault.
> 8. Both containers report `id -u` = `10001` with a read-only root filesystem.
>
> **Maps to:** PRD F4 and **all four** acceptance criteria; ARCH §3/§4/§5/§8.
>
> **Done when:** all boxes in Milestone 4 are `[x]`, §4.5 is green, and this command exits `0`.

---

## Milestone Dependency Summary

```
M1 Scrubber  ──────────────► M2 Agent ──────────────► M3 Watcher ──────────────► M4 E2E Chaos
     │                          │                        │                          │
  AC-2 masking            AC-3 diff validity       AC-1 ≤2s detection        All four ACs
  ARCH §6                 ARCH §4/§5               AC-4 non-root            proven E2E
                          F2 sandbox, F3 tiers     read-only RBAC           F4 verify loop
```

| Milestone | Deliverable | Primary criteria | Terminal test |
|---|---|---|---|
| 1 | `internal/scrubber` | AC-2 | M1 §▶ |
| 2 | `agent/` | AC-3 | M2 §▶ |
| 3 | `cmd/sentinel`, `internal/k8s`, `internal/emitter`, `deploy/` | AC-1, AC-4 | M3 §▶ |
| 4 | `deploy/chaos/`, `tests/e2e/`, `agent/verify.py` | AC-1…AC-4 | M4 §▶ |

---

## Definition of Done (project)

The MVP is complete when:

- [ ] All four milestones are `[x]` with green terminal validation tests.
- [ ] All four global quality gates exit `0`.
- [ ] PRD AC-1 (≤2s p99), AC-2 (100% masking), AC-3 (valid diff), AC-4 (non-root) each have
      recorded evidence.
- [ ] The Sentinel holds **no** mutating RBAC verb, verified by a test that parses the manifests.
- [ ] No configuration, flag, or code path can enable a direct cluster write.
- [ ] `ARCHITECTURE.md` matches the implemented schemas and layout exactly.
