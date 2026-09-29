# CI failure triage protocol

Which agent investigates a GitHub Actions failure, and why the boundaries are where
they are.

The routing is by **domain**, not by severity. A failure is a question about a
subsystem, and the agent that owns that subsystem is the one that can answer it
without first learning the shape of the problem. A `--race` data race reported to
a profiler produces latency numbers; a latency spike reported to a
synchronisation specialist produces a mutex. Routing by severity would put both in
the wrong place roughly half the time, and an agent asked about something outside
its domain will produce confident analysis of the wrong thing.

## Routing table

| # | Domain | Owner | Why this one |
|---|---|---|---|
| 1 | `go test -race` data races; channel and mutex synchronisation; goroutine accounting | **Primary** | The failure *is* the synchronisation model. Delegating it would mean relaying a detector's report through an agent that did not run the detector, and the interesting part is which of two apparently-symmetric orders was actually wrong. |
| 2 | Container bootstrap: k3s/kind install, kubeconfig permissions, apiserver readiness, image import into containerd, PSA admission, pod scheduling, cgroup limits and OOM victim selection, backoff timing | **Primary** for bootstrap (steps 8–10); `@chaos-engineer` for admission, scheduling and cgroup behaviour (steps 12–16) | The two halves need different things. "Will the installer start, and can this user read the kubeconfig" is an environment question with a short answer. "Will a 64Mi limit OOM-kill this container, and which process does the cgroup killer pick" is a fixture question, and the fixture is the agent's artefact. |
| 3 | Sentinel event extraction, telemetry bounds, redaction, ULID generation, wire serialisation, `git apply --check`, payload invariants | `@e2e-verifier` | The question is what the bytes actually say. A verifier that can diff the captured payload against the corpus and against the expected wire form answers it directly; anyone else has to reconstruct the payload from a description of it. |
| 4 | Runner CPU starvation, egress buffer drops, load-shedding, liveness/readiness timeouts, latency budgets | `@sre-profiler` | These are questions about time and capacity, and the agent's method is to generate load and measure. A saturated runner and an over-strict timeout are indistinguishable from a bug in either without that measurement. |

## Why bootstrap sits with the Primary and not `@chaos-engineer`

This is the boundary that was not obvious and is now written down.

A first draft of this table had no entry for cluster bootstrap at all, so
`Install k3s` failing routed to the Primary **by absence rather than by design**.
The first remote detonation run failed there, and the cause was a defect in a
workflow step the Primary had written: `kubectl version` contacts the apiserver,
it ran in the install step, and the cluster did not exist yet. The step reported
failure for a reason that had nothing to do with installing k3s.

Had that been routed to `@chaos-engineer` under a broad "container problems" rule,
the agent would have been asked to inspect a k3s install it has no stake in, and
would have returned an analysis of the fixtures — which were never reached,
because every step after the failure was skipped.

The rule this produces: **if the failing step is part of the harness, it belongs
to whoever wrote the harness.** Steps 8–10 build the environment; steps 12–16 use
it to exercise a fixture; the fixture is the subagent's, the harness is not.

## When a failure spans domains

Prefer the earliest step in the workflow that can explain it, and fix that first.
A workflow is a pipeline: a later failure is frequently the shadow of an earlier
one, and diagnosing the shadow costs a run cycle per attempt.

The exception is a *latent* failure — one where an earlier step passed but should
not have. Those are the expensive ones, and the case above was one: the step
failed correctly, on the wrong precondition, and the harness was at fault for
running the command at all.

## Evidence before delegation

Route with the step number, the step name, and the conclusion. Do not route with a
hypothesis, because a hypothesis attached to a subagent prompt becomes the frame
through which that agent reads its evidence.

CI logs require repository admin rights and return `403` to the unauthenticated
API. Step and job *conclusions* are readable unauthenticated and are usually
sufficient to localise a failure. When they are not, reproduce locally before
delegating: several of the defects in this project were found by executing the
code path rather than by reading the report about it, and one of them — a
credential leak reported by an agent on the wrong regex engine — was entirely
absent on the engine that ships.
