# Architecture

Technical reference for how an incident moves through the system: the component
topology, and the detection and emission path that produces a scrubbed payload.
Operational material lives in [development.md](development.md); the security
properties live in [security-invariants.md](security-invariants.md).

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
