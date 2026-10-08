# OOM recalibration: one incident, start to finish

Every byte below was captured from a live `make demo` run on a disposable k3s
cluster. Nothing here is hand-written to look plausible.

Reproduce it yourself:

```bash
make demo
```

## How it was captured

`tests/e2e/capture_proxy.py` — the same instrument the CI detonation leg uses —
was run in-cluster between the Sentinel and the Agent. It forwards verbatim and
records both directions to NDJSON. The recording is external to both binaries on
purpose: the Sentinel is never asked to write its own payload anywhere, because
the scrubber's "no disk, no plaintext" property is one of the things this page
depends on.

```
srek3s-sentinel ──POST /v1/incidents──▶ srek3s-capture ──▶ srek3s-agent:8000
                                             │
                                             └─ /tmp/evidence/captured.jsonl
```

---

## 1. The input: a crashing pod with a planted credential

`deploy/chaos/oom-leak.yaml` allocates on an unbounded curve against a `64Mi`
limit and prints a synthetic credential on every iteration. The raw container
log, credential intact:

```console
$ kubectl -n sentinel-chaos logs deploy/srek3s-chaos-oom -c oom-canary --tail=6
CHAOS-CRED seq=19 dsn=postgres://chaos_user:Sup3rS3cretPassw0rd@db.production.svc.cluster.local:5432/billing
CHAOS-PHASE creds-planted next=memory-exhaustion
CHAOS-OOM iteration=1 heap_bytes=2097152
CHAOS-OOM iteration=2 heap_bytes=4194304
CHAOS-OOM iteration=3 heap_bytes=8388608
CHAOS-OOM iteration=4 heap_bytes=16777216
```

`Sup3rS3cretPassw0rd` is a fixture value planted by the chaos manifest, and it is
in this repository in plaintext at `deploy/chaos/oom-leak.yaml:157`. Showing it
here adds no exposure. The contrast between this line and the one below is the
whole point of the page.

## 2. What crossed the wire: scrubbed in memory, before egress

The captured `POST /v1/incidents` body. The DSN is structurally preserved — host,
port, database and user survive, because a diagnosis needs the topology — and only
the password is gone:

```json
{
  "schema_version": "1.0.0",
  "incident_id": "inc_01M4ET3G3MJMFAQQRM8XHJ3M3B",
  "namespace": "sentinel-chaos",
  "pod_name": "srek3s-chaos-oom-5866466cbb-cj9zr",
  "container_name": "oom-canary",
  "reason": "OOMKilled",
  "previous_reason": "OOMKilled",
  "exit_code": 137,
  "restart_count": 3,
  "detection_latency_ms": 23,
  "sentinel_version": "0.1.0-dev",
  "resource_limits": {
    "cpu_limit": null,
    "cpu_request": null,
    "memory_limit": "64Mi",
    "memory_request": "64Mi",
    "memory_working_set_bytes": null
  },
  "scrubbed_logs": [
    "CHAOS-CRED seq=0 aws_access_key_id=[REDACTED] [REDACTED]",
    "CHAOS-CRED seq=0 jwt=[REDACTED]",
    "CHAOS-CRED seq=0 Authorization: [REDACTED]",
    "CHAOS-CRED seq=0 dsn=postgres://chaos_user:[REDACTED]@db.production.svc.cluster.local:5432/billing",
    "CHAOS-OOM iteration=1 heap_bytes=2097152"
  ],
  "redaction_report": {
    "rules_triggered": [
      "aws_access_key_id",
      "aws_secret_access_key",
      "jwt",
      "bearer_token",
      "basic_auth_url",
      "generic_secret_kv",
      "uuid"
    ],
    "total_redactions": 120
  }
}
```

Seven of the eleven rules fired, 120 times, across 85 log lines. Note what is
*not* present: there is no field in this contract capable of expressing a write
verb, no `kubectl`, no `apply`, no token. That is invariant `I-B5` and it is
asserted, not hoped for.

Two readings worth making explicitly:

- `exit_code: 137` with `reason: "OOMKilled"` is a real SIGKILL from the kernel
  cgroup, not a liveness probe firing.
- `previous_reason: "OOMKilled"` is what separates a startup problem from a
  steady-state one. The pod is not failing to boot; it is being killed after it
  has already started working. That distinction is what selects the remedy below.

## 3. The Tier-1 decision

```json
{
  "incident_id": "inc_01M4ET3G3MJMFAQQRM8XHJ3M3B",
  "blast_radius_tier": "TIER_1_TOIL",
  "classification": "RESOURCE_EXHAUSTION",
  "severity": "SEV3",
  "confidence": 0.91,
  "status": "TRIAGED",
  "analysis_latency_ms": 29,
  "agent_version": "0.1.0",
  "root_cause": {
    "affected_scope": {
      "namespace": "sentinel-chaos",
      "replicas_affected": 1,
      "replicas_total": 1,
      "sibling_containers_healthy": true
    },
    "evidence": [
      "reason=OOMKilled",
      "exit_code=137",
      "restart_count=3",
      "memory_limit=64Mi",
      "previous_termination_reason=OOMKilled",
      "namespace=sentinel-chaos",
      "container=oom-canary",
      "cluster_event_reasons=OOMKilled"
    ]
  },
  "remediation": {
    "target_manifest": "deploy/chaos/oom-leak.yaml",
    "patch_validated": true,
    "risk_level": "LOW",
    "summary": "Raise the 'oom-canary' memory limit from 64Mi to 128Mi. No code or image change required.",
    "git_patch": "..."
  }
}
```

`TIER_1_TOIL` is not a confidence score. It is the statement that this remedy is
enumerated in advance: single manifest, one resource field, no code or image
change, no schema question, and mechanically checkable. An OOMKill whose fix is
"raise a limit that is demonstrably too low" is in that set. A CrashLoopBackOff
whose cause is a config bug is not, and would go to `TIER_2_ARCHITECTURAL` with
`git_patch: ""` — a state that is unrepresentable rather than discouraged.

`patch_validated: true` is only reachable after **both** verification layers
pass: a YAML AST parse of the patched manifest, then `git apply --check` against
the target file's own bytes. Neither is optional, and the second one is the only
layer that knows whether this diff applies to *this* file with *this* context.

## 4. The patch

```diff
--- a/deploy/chaos/oom-leak.yaml
+++ b/deploy/chaos/oom-leak.yaml
@@ -245,7 +245,7 @@
               # incident emittable at all. `64Mi` also matches the agent's
               # Quantity pattern ^[0-9]+(\.[0-9]+)?(m|k|Ki|M|Mi|G|Gi|T|Ti|P|Pi)?$
               # and survives resource.Quantity.String() unchanged as "64Mi".
-              memory: 64Mi
+              memory: 128Mi
               # No `requests` block, deliberately. See the report: a request
               # would let the scheduler reserve 64Mi of allocatable and refuse to
               # place the pod on a small node, turning a chaos run into a
```

One line changed. The diff carries its own context, including the reasoning
comment already in the file, so a reviewer applying it in a pull request sees why
the value was there and what the new one is bounded by.

### This diff was never applied to the cluster

That is the entire boundary, and it is the reason the Agent has no token mounted
(`automountServiceAccountToken: false`) and the Sentinel's Role grants only
`get`/`list`/`watch`. SREK3S produces a diff and hands it to a human. It does not
merge one. A system that could close its own loop would need write authority, and
that is the authority this project is built not to have.

## Reproducing this exact exchange

```bash
make demo
```

For the wire bytes rather than the summary, `make demo` logs to the Sentinel and
Agent; the CI leg at `.github/workflows/e2e-detonation.yaml` runs the same capture
proxy and uploads the NDJSON as an artifact. The interesting fields to look at
first:

| Field | What it tells you |
|---|---|
| `redaction_report.total_redactions` | Scrubbing actually did work, not just ran |
| `redaction_report.rules_triggered` | Which of the 11 rules the fixture reached |
| `detection_latency_ms` | Detection budget is 2000 ms (`I-A4`) |
| `remediation.patch_validated` | Whether both verification layers passed |
| `remediation.git_patch` | Empty string on every Tier-2, always (`I-B1`) |