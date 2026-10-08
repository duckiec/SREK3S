<div align="center">
  <img src="docs/assets/banner.svg" alt="SREK3S banner: the project mark and wordmark" width="100%" />
  <br />
  <p>
    <a href="https://github.com/duckiec/SREK3S/actions/workflows/ci.yaml"><img src="https://github.com/duckiec/SREK3S/actions/workflows/ci.yaml/badge.svg?branch=main" alt="CI" /></a> <a href="https://github.com/duckiec/SREK3S/actions/workflows/release.yaml"><img src="https://github.com/duckiec/SREK3S/actions/workflows/release.yaml/badge.svg" alt="Release" /></a> <a href="https://github.com/duckiec/SREK3S"><img src="https://img.shields.io/badge/platform-linux%2Famd64%20%7C%20linux%2Farm64-4655db" alt="Multi-arch" /></a> <a href="https://go.dev"><img src="https://img.shields.io/badge/go-1.26%2B-00ADD8?logo=go" alt="Go" /></a> <a href="https://www.python.org"><img src="https://img.shields.io/badge/python-3.11-3776AB?logo=python" alt="Python" /></a> <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License: MIT" /></a>
  </p>
</div>

# SREK3S

## Secret-safe, read-only Kubernetes incident triage

SREK3S watches for pod failures, scrubs credentials **in memory before anything
leaves the node**, and produces a reviewable Git patch you can merge yourself. It
holds a namespaced `get`/`list`/`watch` Role and nothing else — no ClusterRole, no
write verb on either wire contract, and no ServiceAccount token mounted in the
component that talks to the model.

## See it in 60 seconds

![SREK3S in-memory redaction and fail-closed triage](docs/assets/demo.gif)

```bash
git clone https://github.com/duckiec/SREK3S.git && cd SREK3S
make demo
```

`make demo` runs three steps, and prints what each one is before it happens:

| Step | What it does |
|---|---|
| `throwaway-up` | Starts a disposable k3s cluster in Docker, on its own bridge network |
| `throwaway-wait` | Blocks until the node is Ready **and** cluster DNS resolves |
| `throwaway-detonate` | Builds both images, installs the chart, applies a real OOMKill fixture, waits for triage, then asserts |

**Your kubectl context is never switched.** Every command is pinned to
`KUBECONFIG=/tmp/k3s-throwaway.yaml`, so a production kubeconfig you already have
loaded stays loaded and stays untouched. Nothing is applied to any cluster except
the throwaway, and no cluster-admin rights are needed anywhere in this repository.

It ends with assertions, not a screenshot:

```
===================== ASSERTIONS ====================
  [ok] sentinel emitted 3 incident(s)
  [ok] agent triaged (3 verdict(s))
  [ok] GitOps checkout succeeded (3 Tier-1 verdict(s))
```

Clean up with `make throwaway-down`.

## Why SREK3S?

**It fails closed, and the failure is unrepresentable.** Tier selection, the patch,
and every validation flag are computed deterministically *before* a model is
consulted. A `TIER_2_ARCHITECTURAL` response carrying a patch raises rather than
being discouraged (`I-B1`), so a hallucinated remedy has nowhere to land. A system
that proposes a patch it cannot prove is worse than one that stays quiet.

**The read-only claim is checkable, not rhetorical.** The Sentinel's Role grants
exactly `["get", "list", "watch"]` on `pods`, `pods/log` and `events`. The Agent
sets `automountServiceAccountToken: false` and mounts no token at all. Neither
contract has a field capable of expressing a write verb (`I-B5`), so a patch
cannot carry one through the model.

**Tier-1 and Tier-2 are deterministic, not a confidence score.** `TIER_1_TOIL` means
the remedy was enumerated in advance — one manifest, one resource field, no code or
image change — and then survived a YAML AST parse *and* `git apply --check`
against the target's own bytes. Anything ambiguous is `TIER_2_ARCHITECTURAL`, which
carries no patch at all.

**Secrets are masked before egress, not after.** Eleven ordered rules run on the
Go node in memory. Nothing unmasked reaches a queue, a disk, or a socket. Redaction
is selective within the match, so `postgres://checkout:[REDACTED]@db-primary:5432/prod`
keeps the host, port, database and user that the diagnosis depends on.

**A bad log message stops the Sentinel; a bad log level does not.** A scrubber that
fails to load means the guarantees no longer hold, so boot refuses. An unparseable
`LOG_LEVEL` degrades to `INFO` with a comment explaining why. The distinction is
the product: fail closed where silence would be a security defect, degrade loudly
everywhere else.

## Visual evidence

[`examples/oom-recalibration/`](examples/oom-recalibration/) is one real incident,
captured off the wire end to end: the crashing pod's log with a planted credential
intact, the scrubbed payload that actually crossed, the Tier-1 decision, and the
diff it produced — `memory: 64Mi` → `memory: 128Mi`, with `patch_validated: true`.
Every byte is from a live run. Reproduce it with `make demo`.

## Installation

```bash
kubectl kustomize --load-restrictor LoadRestrictionsNone deploy/overlays/quickstart \
  | kubectl apply -f -
```

The Agent runs with `automountServiceAccountToken: false` and holds no token; only
the Sentinel mounts one, and only to read.

The default install reaches `TIER_2_ARCHITECTURAL` for every incident. That is the
designed safe state, not a misconfiguration — `agent.targetManifest` is the gate,
and [`docs/security-invariants.md`](docs/security-invariants.md) explains why an
empty target and a broken target look identical from the outside.

Prerequisites: `git`, `kubectl`, and a cluster you can write to.

## Documentation

Start here:

| Document | Contents |
|---|---|
| [`docs/security-invariants.md`](docs/security-invariants.md) | **The guarantees.** Fail-closed boot, scrubbing, Tier-1 verification, RBAC and network posture, the `I-A*`/`I-B*` invariant tables, and the gaps that are still open |
| [`docs/runbook.md`](docs/runbook.md) | Deploy, observe, interpret, review |
| [`examples/oom-recalibration/`](examples/oom-recalibration/) | One captured incident, payload to patch |

Then:

| Document | Contents |
|---|---|
| [`docs/architecture.md`](docs/architecture.md) | Component topology, and the detection and emission path a scrubbed payload travels |
| [`docs/models.md`](docs/models.md) | Nine providers across three protocols, credential mounting, and adapter behaviour |
| [`docs/development.md`](docs/development.md) | Gates, build, deploy, publishing, silent-failure modes, verification without a cluster |
| [`docs/hardening-and-ci.md`](docs/hardening-and-ci.md) | Test matrices, static analysis, repository rulesets, and where the enforcement is weaker than it looks |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | Invariants, gates, and the normative masking specification |
| [`docs/lessons-learned.md`](docs/lessons-learned.md) | Defects found, including negative controls that failed for the wrong reason |
| [`docs/offline-install.md`](docs/offline-install.md) | Installing images without a registry |
| [`docs/ci-triage-protocol.md`](docs/ci-triage-protocol.md) | Reading a red CI run |

## Working on it

Linux or WSL2, Go 1.26+, Python 3.11, Docker with buildx, `gcc`, and a cluster.

```bash
make doctor      # host pre-flight: OS, arch, docker+buildx, go, python 3.11+
make bootstrap   # create .venv311, install agent deps, download Go modules
make test        # every gate: go vet, gofmt, -race, black, flake8, mypy, pytest
make check       # gates, then images, then supply-chain checks
make deploy      # apply deploy/base and wait for both rollouts
```

## Project structure

```
cmd/sentinel/          Go entrypoint; wiring, flags, signal handling
internal/scrubber/     11-rule masking engine, normative order, accounting
internal/k8s/          read-only clientset, informers, classification, telemetry
internal/worker/       bounded worker pool; every send selected on ctx.Done()
internal/emitter/      ULID incident ids, wire validation, ctx-bounded HTTPS
agent/                 FastAPI + Pydantic v2 triage engine, sandbox, providers
deploy/                k3s manifests; chaos/ holds the deliberate-failure fixtures
tests/fixtures/        incident corpus, chaos manifests, golden expected output
scripts/               audit_workflow.py, bootstrap.sh
.github/workflows/     ci.yaml, release.yaml, e2e-detonation.yaml
docs/                  architecture, security invariants, models, development,
                       runbook, lessons learned, offline install, CI triage
```

---

## License

MIT. See [LICENSE](LICENSE).