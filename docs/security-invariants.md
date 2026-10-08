# Security Invariants

Each invariant below is enforced by a test that fails the build. The properties are
stated once here; no other section restates them.

## The Sentinel cannot mutate the cluster

The Sentinel's ServiceAccount binds a namespaced `Role` granting exactly
`["get", "list", "watch"]` on three rule groups, verbatim from `deploy/rbac.yaml` —
the file of record, which is what this paragraph must be read against:

```yaml
- apiGroups: [""]
  resources: ["pods", "pods/log"]
  verbs: ["get", "list", "watch"]
- apiGroups: [""]
  resources: ["events"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["apps"]
  resources: ["deployments", "replicasets"]
  verbs: ["get", "list", "watch"]
```

There is no `ClusterRole` and no `ClusterRoleBinding`. Note there is **no**
`pods/status`: an earlier revision of this document claimed it, which was wrong
and is exactly the drift this paragraph exists to prevent. `pods/log` is listed as
a separate subresource: omitting it does not error, it makes every incident arrive
without logs.

Three documents used to state three different grants for this Role
(`docs/security-invariants.md` claimed `pods/status`, `CONTRIBUTING.md` omitted
the `apps` rule entirely, and `.ai/INVARIANTS.md` repeated the `pods/status`
error). `deploy/rbac.yaml` is the single source of truth; these documents
restate it and must be corrected when it changes.

The Agent mounts no ServiceAccount token at all
(`automountServiceAccountToken: false`).

Neither the code nor the RBAC is the only layer. Invariant **I-B5** asserts that
neither wire contract contains any field capable of expressing a write verb, so a
patch cannot carry one through the model.

## Secrets are masked before egress

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

## Unverifiable output is discarded

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

## The model cannot return authority

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

## Runtime containment

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

## Network egress

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

## Not Wired

**The post-remediation verification loop is removed.** `agent/verify.py` and its
tests (`test_verify.py`, `test_verification_e2e.py`) were deleted: nothing in
production imported them, and Tier-1 incidents close when the verified diff is
handed to a human, not when a loop re-observes the workload. `triage.py` still
emits `verification_policy` on the wire with no consumer.

**Tier-1 auto-patching as deployed.** `SREK3S_MANIFEST_ROOT` mounts an `emptyDir`, so
the manifest provider cannot resolve its target file. Every incident escalates to
Tier-2 under I-B2 and no patch is proposed. This is the intended safe state and is
indistinguishable from a working installation.

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

## Scrubber: the 11 rules

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
