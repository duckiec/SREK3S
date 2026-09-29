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

Routing is by **assertion target** - what the failing step is checking - and never
by step number. Step indices are fragile in a way that is easy to miss: the
detonation workflow grew from 21 to 27 steps over four CI iterations, and an
earlier version of this document cited "steps 12-16" for admission. By the time
that citation was written, step 16 was a namespace-label assertion in *my* harness
file, and routing it to the chaos engineer would have sent an agent to a file it
does not own. Indices rot silently and read as authoritative while doing it.

If a step is added, moved, or reordered, this table needs no edit. That is the
whole point of keying on the assertion rather than the position.

| Assertion target | Owner | Why this one |
|---|---|---|
| **Harness**: workflow steps, cluster bootstrap, kubeconfig permissions, apiserver readiness, image acquisition and registration, timeouts, and assertions over harness-owned files such as `deploy/chaos/namespace.yaml` | **Primary** | The failing artefact is one the Primary wrote. Nothing here is a question about the system's behaviour; it is a question about whether the thing that exercises the system works. |
| **Fixture behaviour**: whether a chaos manifest produces the failure it claims, cgroup limits and OOM victim selection, backoff timing, kubelet status transitions, pod scheduling | `@chaos-engineer` | The fixture is that agent's artefact, and the questions are about kernel and kubelet behaviour rather than about this repository's code. |
| **Wire and payload**: Sentinel event extraction, telemetry bounds, redaction, ULID generation, serialisation, `git apply --check`, payload invariants, anything requiring a byte-level diff of a captured payload | `@e2e-verifier` | The question is what the bytes say. A verifier that can diff a payload against the corpus and against the expected wire form answers it directly; anyone else reconstructs the payload from a description of it. |
| **Capacity and time**: runner CPU starvation, egress buffer drops, load shedding, liveness and readiness timeouts, latency budgets, saturation thresholds | `@sre-profiler` | These are questions about time and capacity, and that agent's method is to generate load and measure. A saturated runner and an over-strict timeout are indistinguishable without that measurement. |
| **Concurrency**: `go test -race` data races, channel and mutex synchronisation, goroutine accounting, deadlock or livelock | **Primary** | The failure *is* the synchronisation model. Delegating it would mean relaying a detector's report through an agent that did not run the detector, and the interesting part is which of two apparently-symmetric orders was actually wrong. |

### The dividing question

> **If the failing step is part of the harness, it belongs to whoever wrote the
> harness. If it is part of a fixture, it belongs to whoever wrote the fixture.**

Applied to the four detonation failures so far, this routed all of them to the
Primary, and each was a defect in a workflow step: a server-contacting `kubectl`
ahead of the readiness wait, a root-only containerd socket used without `sudo`,
an image pulled into the wrong containerd namespace, and a `docker` daemon
dependency on a runner where it was not reliably present. None was a question
about chaos fixtures - the fixtures were never reached, because every step after
a failure is skipped.

## Why the harness/fixture line is where it is

An earlier draft of this table had no entry for cluster bootstrap, so a failing
`Install k3s` routed to the Primary **by absence rather than by design**. The first
remote detonation run failed there, and the cause was a defect in a workflow step
the Primary had written: `kubectl version` contacts the apiserver, it ran in the
install step, and the cluster did not exist yet. The step reported failure for a
reason that had nothing to do with installing k3s.

Had that been routed to `@chaos-engineer` under a broad "container problems" rule,
the agent would have been asked to inspect a k3s install it has no stake in and
would have returned an analysis of the fixtures - which were never reached,
because every step after the failure is skipped.

A second instance made the same point: a later step numbered 16 was a namespace
label assertion over `deploy/chaos/namespace.yaml`, a file the Primary authored.
A table keyed on "admission lives in steps 12-16" would have routed it to the
chaos engineer; a table keyed on what the step asserts routes it correctly.

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
