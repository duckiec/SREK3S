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
```

There is no `ClusterRole` and no `ClusterRoleBinding`. Note there is **no**
`pods/status`: an earlier revision of this document claimed it, which was wrong
and is exactly the drift this paragraph exists to prevent. `pods/log` is listed as
a separate subresource: omitting it does not error, it makes every incident arrive
without logs.

There is also **no `apps` rule**, and its absence is now stated here rather than
left to be discovered. This file used to grant `deployments` and `replicasets`
"for attributing an incident to a workload". Nothing read them — see *Grants
without a reader* below — and both this paragraph and four other documents
restated the grant. `deploy/rbac.yaml` is the source of truth; these documents
restate it and must be corrected when it changes, which is what happened here.

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
| Sentinel | TCP 443 to `10.43.0.0/16` and `10.96.0.0/12` (the cluster service CIDRs); TCP 6443 to `0.0.0.0/0`; TCP 8000 to the Agent pod |
| Agent | UDP and TCP 53 to `kube-system`; TCP 443 to `0.0.0.0/0` |

The Sentinel cannot reach an arbitrary *service*. It reaches the API server through
the service CIDRs and nothing else.

**Why there is a `0.0.0.0/0` rule on the Sentinel, which sounds like the opposite of
that claim.** NetworkPolicy evaluation order is not uniform, and getting it wrong
makes the Sentinel unable to do its only job.

kube-router — the default CNI on k3s, and therefore the default for anyone who
follows the Quick Start — evaluates policy **after** kube-proxy has DNAT'd the
ClusterIP. At that point the destination is no longer `10.43.0.1:443` but the
apiserver's node address on `6443`, which matches neither the `ipBlock` above nor
the port. Measured on a stock k3s, with two pods differing only in whether this
policy applied:

```
NO NetworkPolicy        -> 10.43.0.1:443 = OPEN
Sentinel-shaped policy  -> 10.43.0.1:443 = REFUSED
```

and the packet capture shows a healthy DNAT, which is what exonerates the
dataplane:

```
cni0 In  10.42.0.20 -> 172.30.181.188:6443   Flags [S]    <- DNAT applied
cni0 Out 10.43.0.1:443 -> 10.42.0.20         Flags [S.]   <- SYN-ACK returned
```

The rule permits the **port**, not an address. The port survives a reboot; the node
address does not, which is why an earlier revision that hardcoded
`172.30.181.188/32` was correctly rejected and then wrongly left without the port.
On a pre-DNAT CNI the extra rule is inert.

What it costs, stated plainly: the Sentinel may open a TCP connection to port 6443
on any address it can route to. It still cannot do anything with that connection
its namespaced Role does not permit, so this is defence in depth behind the RBAC
control rather than a substitute for it. No other port, protocol or destination
class is widened, and `test_sentinel_policy_widens_nothing_but_6443` fails if that
ever changes.

The Agent's TCP 443 rule is why a local Ollama on `11434` or vLLM on `8000` is refused
by the network rather than by code. Widening that rule is an egress change with a
cluster-wide blast radius.

Ingress to the Agent is permitted only from pods labelled
`app.kubernetes.io/name: srek3s-sentinel`, on TCP 8000.

## Boot fails closed, but only where silence would be a security property

The Sentinel refuses to start rather than start degraded. A scrubber that fails to
load is not a Sentinel with fewer rules; it is a Sentinel whose guarantees no
longer hold, and the only safe reading of that state is to refuse to serve.

`cmd/sentinel/main.go` reads the manifest and calls `scrubber.LoadManifestBytes`
before the watcher exists. Either error returns wrapped, and `main` does not
recover:

```go
raw, err := os.ReadFile(manifest)
if err != nil {
    return fmt.Errorf("read scrubber manifest %q: %w", manifest, err)
}
if err := scrubber.LoadManifestBytes(raw); err != nil {
    return fmt.Errorf("load scrubber manifest %q: %w", manifest, err)
}
```

`LoadManifestBytes` rejects a schema violation, an unknown rule ID, a duplicate ID,
an out-of-order table, an omitted canonical rule, and an invalid regex. There is no
partial install and no skip-and-continue, because a silently skipped rule is a
security defect wearing a successful exit code.

Two things about this are worth stating precisely rather than as a slogan:

- **It is an exit 1, not a panic.** `internal/scrubber/loader.go` still documents
  "the caller panics on a non-nil error", which is stale: the caller returns, and
  the process exits non-zero. The distinction matters because a panic under a
  recovering supervisor reads as a crash-loop and may be restarted into the same
  failure, whereas exit 1 reads as a configuration error. The comment is wrong and
  should be corrected when that file is next touched.
- **It is not uniform, on purpose.** An unparseable `LOG_LEVEL` does *not* stop
  boot; it falls back to `INFO`, with the reasoning in `newLogger`:

  > A bad level is not worth refusing to start over: the safe default is the one
  > that logs. Failing here would mean a typo in a ConfigMap takes the reliability
  > monitor down, which is a worse outcome than verbose logs.

That is the boundary. Fail closed where continuing means a guarantee is quietly
absent. Degrade loudly where continuing means only that a log is chattier.

## Escalation reaches a human, and what that path costs

A `TIER_2_ARCHITECTURAL` outcome carries no patch. It carries a Markdown document,
and getting that document to a human is the only thing standing between an incident
and a page nobody reads.

`agent/notify.py` dispatches it to Slack, Discord, PagerDuty and Telegram. Four
properties are deliberate:

- **It is a no-op unless configured.** `Dispatcher.enabled` is true only when at
  least one target is set, and the triage path logs
  `notify disabled: no webhook configured` rather than failing.
- **It cannot raise.** Every target method returns a human verdict string — an HTTP
  status, `no_chat_id`, or an exception class name — and never propagates. A
  webhook outage must not turn into a triage failure, because the triage already
  happened and is correct.
- **It cannot block the Sentinel.** `dispatch(wait=False)` hands delivery to a
  daemon thread and returns immediately, so a slow or hanging endpoint never delays
  the HTTP 200 the emitter is waiting on. Tests pass `wait=True` to collect verdicts
  deterministically.
- **It cannot exfiltrate over plaintext.** `_require_https_url` rejects a target
  URL that is not `https://` at construction time, before any incident exists to
  send through it.

Each call is bounded by `DISPATCH_TIMEOUT_SECONDS = 4.0`. Queueing is shed, not
buffered, for the same reason the sandbox sheds at `429`: converting a capacity
limit into a latency problem produces a worse failure than saying no.

**Two properties were gaps and are now enforced.** Both were open items on
`.ai/ROADMAP.md`; neither is a comment any more.

1. **The recipient is `TELEGRAM_CHAT_ID` and nothing else.** With it unset,
   `_telegram_deliver` used to call `getUpdates` and post to whichever chat had
   most recently written to the bot. The bot token authenticates the *API call*;
   it says nothing about the *recipient*. So anyone who could message the bot could
   redirect reports carrying someone else's namespace, pod, container and exit code
   — and the code logged a `WARNING` and sent the message anyway, which is the
   worst of both: the finding was recorded and the exfiltration proceeded. A
   security property that is announced and not enforced is documentation. It now
   returns `chat_id_not_configured`, logs at `ERROR`, and **makes no HTTP request at
   all** — not even the discovery call, which would itself tell whoever was
   watching the bot that an incident existed.
2. **Concurrency is bounded.** `dispatch(wait=False)` started a daemon thread per
   escalation. `DISPATCH_TIMEOUT_SECONDS` bounded any *one* delivery; nothing bounded
   how many ran at once, so a burst spawned a burst, each holding an HTTP client and
   its pool. Deliveries now go through one bounded queue (`NOTIFY_QUEUE_DEPTH = 32`)
   drained by a single worker, started lazily. `put_nowait` cannot block, which
   preserves the property that made it asynchronous. On overflow the report is
   **shed and logged at `ERROR`**, not queued without limit and not dropped
   silently — the same choice the sandbox makes at `429`, for the same reason.

   The queue depth is a bound on *outstanding* deliveries. `DISPATCH_TIMEOUT_SECONDS`
   remains the bound on any single one.

## Grants without a reader are removed, not tolerated

`deploy/rbac.yaml` granted `get`/`list`/`watch` on `apps` `deployments` and
`replicasets`, "for attributing an incident to a workload rather than to a bare
pod name". **Nothing read them.** The client in `internal/k8s/readonly.go` exposes
exactly two readers — `CoreV1().Pods` and `CoreV1().Events` — and a non-test grep
for `Deployments(` or `ReplicaSets(` across `internal/` and `cmd/` returns nothing.

The grant is gone, and that is the substantive part. A grant without a reader is
not merely redundant: the read-only verb set makes today's blast radius small, but
the grant is an invitation to the next person to reach for it, and what it permits
should be a decision rather than something that grows on its own. Two tests now
assert the **absence** of `deployments` and `replicasets`, so reinstating it is a
deliberate act with a failing test attached rather than a merge nobody reads.

Attribution — the stated purpose — never needed it. An incident already carries
the pod name and container name, and the owning Deployment's labels are on the pod
object the watcher is already holding. Nothing required the extra read.

The order matters if this ever comes back: **add the reader, observe it working,
then grant the verb.** Not the reverse. The previous sequence was grant first, and
the reader it was waiting for was never built.

Five other documents restated the grant verbatim — `CONTRIBUTING.md`,
`docs/runbook.md`, the Helm chart's Role template, the two chaos-namespace Roles,
and this file — and were corrected with it. That is the drift this section exists
to prevent, and the reason `deploy/rbac.yaml` carries the explanation at the point
where the rule used to be rather than in a document that describes it.

## Not Wired

**The post-remediation verification loop is removed.** `agent/verify.py` and its
tests (`test_verify.py`, `test_verification_e2e.py`) were deleted: nothing in
production imported them, and Tier-1 incidents close when the verified diff is
handed to a human, not when a loop re-observes the workload. `triage.py` still
emits `verification_policy` on the wire with no consumer.

**Tier-1 auto-patching as deployed.** Which of the two install paths you take
decides this, and the difference is easy to miss because both produce Tier-2.

- `deploy/agent.yaml` mounts an `emptyDir` at `SREK3S_MANIFEST_ROOT`. The manifest
  provider cannot resolve a target file that is not there, so every incident
  escalates under **I-B2** and no patch is proposed. That is the intended safe
  state, and it is indistinguishable from a working installation if you only look
  at the tier label.
- The chart ships a default `agent.gitops.repoUrl`, so the Agent clones a
  repository at startup instead. `agent.targetManifest` still defaults to empty,
  and **an empty target manifest is the whole gate**: with it unset every incident
  still escalates. Set it and Tier-1 becomes reachable:

  ```bash
  helm install srek3s deploy/helm/srek3s -n srek3s-system --create-namespace \
    --set agent.gitops.repoUrl=https://github.com/duckiec/SREK3S.git \
    --set agent.targetManifest=deploy/chaos/oom-leak.yaml
  ```

`make demo` sets both, which is why it produces `TIER_1_TOIL` verdicts where a
default install produces `TIER_2_ARCHITECTURAL`. Both are correct; only one of them
proposes a patch. The clone happens **once, at startup, with no retry** — a cluster
whose DNS is not yet resolvable strands the Agent in the fallback for its whole
lifetime, which is why `make demo` blocks on `throwaway-wait` before installing the
chart.

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
