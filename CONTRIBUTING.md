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
| G7 | `govulncheck ./...` | **Reachable** CVEs. See below |
| — | `pytest agent/tests/ -q` | Every behavioural assertion below |

G7 is numbered after the Python gates rather than beside the other Go ones because
the sequence is global: Go is G1–G3, Python is G4–G6. Naming a Go gate "G4" would
put two unrelated checks under one label, and the first person to look up G4 would
find formatting.

**G7 gates on reachability, which is the point.** govulncheck exits non-zero only
when a vulnerable symbol is actually *called* from this code; a CVE sitting in a
required module that nothing reaches is reported and does not block. So it answers
"can this binary be affected", which is a different and much more actionable
question than the one Dependabot alerts answer ("is this version in the graph").
It is also stricter than a high/critical filter: a reachable *moderate* blocks too,
and a DoS on the log-reading path is precisely what severity ratings understate.

**Two ways this gate can silently stop gating, both guarded by tests.** The first is
`govulncheck ./... | tee out.txt` without `pipefail`, where the step reports `tee`'s
exit status — always 0. The second is worse: govulncheck is **fail-open on its
advisory database**. With `vuln.go.dev` unreachable it exits 0 and prints
"No vulnerabilities found.", byte-identical to a genuinely clean scan, and
`-version` is no help because it reports a cached timestamp either way. On a fresh
CI runner there is no cache, so an outage would turn G7 green while it knew of no
advisories at all. The step therefore asserts the advisory service answers *before*
trusting a clean result, and `TestReachableCveGate` in `agent/tests/test_workflows.py`
fails if any of that is removed. All four failure modes were plant-tested by
reintroducing the defect and confirming a control goes red.

Skipped tests are a **blocked dependency, not a pass**, and CI enforces that with a
ratchet: the skip count may *fall*, never *rise*. Three skip today — two need a
reachable apiserver, and one is a Windows-only hazard with nothing to test on a
Linux runner. If you add a fourth, the build goes red until you establish what
it is.

---

## The four invariants

These are not style preferences. Each has tests that fail the build when it is
violated, and each is a property a reviewer cannot verify by reading a diff.

### 1. No cluster write authority, without a cluster

The Sentinel runs under a namespaced `Role` enumerating exactly
`["get","list","watch"]` on three rule groups, verbatim from `deploy/rbac.yaml`:
`pods` + `pods/log` (core), `events` (core), and `deployments` + `replicasets`
(`apps`). There is **no** `pods/status` — an earlier revision of this document
omitted the `apps` rule and `docs/security-invariants.md` claimed `pods/status`;
neither matched the file. `deploy/rbac.yaml` is the source of truth. There is no
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

**Adding a provider is one table row, not a new adapter class.** Everything that
varies between providers lives in `ProviderSpec` (`agent/providers.py`): the
credential variable, the model pin, the default model, the default endpoint, which
adapter serves it, and whether it may be keyless. `_API_KEY_ENV`, `_DEFAULT_MODEL`,
`_PROVIDER_SPECIFIC_MODEL_ENV` and `KNOWN_PROVIDERS` are all **derived** from that
table, so a provider cannot be registered in three of four places.

Nine are registered. Seven share the OpenAI chat-completions protocol and are pure
configurations of one adapter; `anthropic` needs its own class because the Messages
API has no `response_format` at all; `gemini` has always had one.

Because one class serves several providers, every per-provider fact must be resolved
from the *environment*, never from the class:

```python
provider = resolve_provider_name(self._env) if self._env else PROVIDER_OPENAI
```

Getting this wrong is silent and offline-invisible. `model_name` once returned
`resolve_model(PROVIDER_OPENAI, env)`, so an NVIDIA deployment asked NVIDIA's
endpoint for `gpt-4o-mini`; `complete()` once resolved its credential the same way,
so an NVIDIA deployment holding only `NVIDIA_API_KEY` reported a missing
credential while holding a good one. Both produced no error anywhere — a plausible
value, substituted for another plausible value.
`agent/tests/test_provider_matrix.py` asserts what the SDK is **handed** — the model
on the outbound call and the `api_key` the client was constructed with — because a
property can report the right string while the request sends another.

**A credential must never cross providers.** There is deliberately **no** fallback
from a provider-specific variable to `OPENAI_API_KEY`, even for OpenAI-protocol
providers, even though that is how OpenRouter's own documentation tells you to
configure a key. It was implemented, and two existing tests refused it: with it in
place, `LLM_PROVIDER=nvidia` alongside a leftover `OPENAI_API_KEY` stopped degrading
to the deterministic prose and started making authenticated calls to a third party —
the mirror image of the bug above. Say `LLM_PROVIDER=openai` with `LLM_BASE_URL`
pointed at the aggregator instead.

**Defaults must be models that work.** `meta/llama-3.1-70b-instruct` returned HTTP
410 (EOL 2026-08-26) and `claude-sonnet-4-5` raises a deprecation warning (EOL
2026-11-30) — both chosen because they were real and popular. A default that fails on
every call is not a default, it is a broken deployment, and neither is findable
without calling the endpoint. Verify a default against the live service, and pin what
you ship.

**Whether a missing credential is fatal is a module-level decision**, because it
depends on the endpoint rather than on the adapter. `_may_proceed_without_credential`
answers it once and the factory *and* every adapter consult it. Two call sites
answering "is this deployment configured?" is the same partial-registration trap as
the parallel tables, one level up — and the disagreement was real: the adapter
exempted a pinned `LLM_BASE_URL` while the factory tested only for the key, so the
documented keyless local setup still produced no narrative.

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

## 5. Secret Masking Regex Manifest (normative)

This is the **authoritative specification** for invariant 4. It is not a summary.
The rule table, the ordering constraints, the throughput budget and every ratified
amendment are reproduced verbatim from the project's design record, and
`agent/tests/test_scrubber_manifest_spec.py` parses the table below and fails the
build if it drifts from `internal/scrubber/manifest.go`. The invariant holds only
if the code and this table agree, so the agreement is asserted rather than assumed.

> **Renumbered, and deliberately the only part of this file a test reads.** This was
> `ARCHITECTURE.md` §6, which arrived in two non-contiguous blocks because the
> amendments were appended as they were ratified. §6.6 — the P0 credential leak on
> rule 7 — sat after unrelated sections and is easy to miss when extracting by
> heading alone; it is included here. Cross-references were renumbered `§6.x` →
> `§5.x`; the content is otherwise unmodified, and the amendment identifiers
> (`D-1`, `D-5`, `M6`) are historical names, not section numbers.
>
> This is in tension with the note at the top of this file, which says a gate that
> reads prose is a gate that fails when the prose drifts. That is true, and it is
> accepted here for one specific table: the alternative was code-as-spec for the
> masking rules, and "the manifest has 11 entries" checked against a literal `11` is
> a weaker guarantee than the table agreeing with the code. Every other section of
> this file is unasserted on purpose.

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
| 6 | `basic_auth_url` | `(?i)([a-z][a-z0-9+.-]*:\/\/[^:\s\/]+:)([^@\s\/]+)(@[^\s\/]+)` | **Amended** — password only. See §5.3. | `$1[REDACTED]$3` |
| 7 | `generic_secret_kv` | `(?i)(\b[\w-]{0,20}(?:api[_-]?key\|secret(?:[_-]access)?[_-]?key\|secret\|token\|access[_-]?token\|refresh[_-]?token\|password\|passwd\|pwd\|passphrase\|client[_-]?secret\|private[_-]?key\|authorization\|auth)["']?\s*[:=]\s*["']?)(?P<value>[^"',;}\n]{4,})(["']?)` | **Amended** — see §5.4 (D-1) and §5.6 (P0) | `${1}[REDACTED]${3}` |
| 8 | `uuid` | `\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b` | UUIDs (customer/ticket correlation IDs) | `[REDACTED]` |
| 9 | `ipv4_address` | `\b((25[0-5]\|2[0-4][0-9]\|1[0-9][0-9]\|[1-9]?[0-9])\.){3}(25[0-5]\|2[0-4][0-9]\|1[0-9][0-9]\|[1-9]?[0-9])\b` | IPv4 addresses | `[REDACTED]` |
| 10 | `k8s_secret_mount` | `(?i)\b(?:kube-system\|kube-node-lease)\b[^\n]{0,80}(?:token\|secret\|ca\.crt)\|(?i)(?:token\|secret\|ca\.crt)[^\n]{0,80}\b(?:kube-system\|kube-node-lease)\b` | **Amended** — see §5.4 (D-2) | `[REDACTED]` |
| 11 | `private_key_pem_body` | `(?i)-----BEGIN[A-Z ]*PRIVATE[A-Z ]*-----` | orphaned BEGIN marker w/o matching END | `[REDACTED]` |

### 5.1 Masking Rules

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

### 5.2 Performance Budget

The full 11-rule pipeline must process **≥ 20,000 lines/sec/core** so that masking stays far
inside the 2s detection budget (AC-1). This is benchmarked in M1; rules are compiled once and
never recompiled in the hot path.

### 5.3 Amendment — Rule 6 `basic_auth_url` (ratified)

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

### 5.4 Amendments — Rules 7 and 10 (ratified, defects D-1 and D-2)

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

### 5.5 Amendments — Cross-line pass scope and rule priority (ratified, defects D-3 and D-5)

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
a heavier mix than the original synthetic fixture. The §5.2 budget of 20,000 lines/sec is met
with large margin, and CI on `ubuntu-latest` remains the authoritative measurement.

> **Platform note, added 2026-10-01, with the figures deliberately unaltered.** The
> `~187,000` figure was measured on the **old `windows/arm64`** host, which is no longer the
> development environment; the current host is `Fedora Linux 44` on `linux/aarch64` (§9.1).
> This is recorded history and is left exactly as measured. It has **not** been re-measured
> here, and this note makes no throughput claim for `linux/aarch64`. A benchmark re-run on
> the new host should be recorded as a new figure with its platform named, not substituted
> for this one; `ubuntu-latest` (`amd64`) remains the authority.

**Narrowed M3 scope, stated explicitly.** Because rule 7 is now single-line, a `key=value` secret
*split across a newline* is not caught by the cross-line pass. This is a deliberate trade: that
case is rare in practice, whereas the alternative was collapsing whole batches. A future
`secret_continuation` rule may address it; it is recorded as deferred rather than silently dropped.

---


### 5.6 Amendment — Rule 7 `secret_access_key` (ratified, P0 credential leak)

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

The result was a live credential in telemetry, which §5 M5 ranks as the one unacceptable outcome:
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

**Parity.** `agent/rescan.py` carries the identical amendment, because §5 M6 requires the agent's
backstop to apply the same rule IDs as the Go node. A change to one without the other would leave the
two implementations disagreeing about the same credential.

**Idempotency.** Unaffected. The replacement remains `${1}[REDACTED]${3}`, and re-scrubbing
`aws_secret_access_key=[REDACTED]` produces the identical bytes, so invariant I-A5 holds.

**Verified by.** `TestSecretAccessKeyVariantsAreMasked` (Go, rule-by-rule and idempotence),
`TestUnquotedAWSSecretKeyIsScrubbed` (worker, end-to-end through the pool), and
`TestRule7CoversSecretAccessKeyVariants` (Python, parity against the Go manifest).

> **This row was wrong until 2026-10-02.** It carried the pre-amendment
> alternation (`secret[_-]?key`) and referenced only §5.4, so the summary table
> described a pattern with a known P0 credential leak while the code below it had
> been correct since the amendment was ratified. The narrative in §5.6 was right and
> the table was not, which is how a summary table drifts from the thing it
> summarises. It was caught by `agent/tests/test_scrubber_manifest_spec.py` on the
> day that guard was written — the table and the code had been out of agreement for
> as long as both existed, with nothing comparing them.

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
