<div align="center">
  <img src="docs/assets/banner.svg" alt="SREK3S banner: the project mark and wordmark" width="100%" />
  <br />
  <h1>SREK3S</h1>
  <p>
    <a href="https://github.com/duckiec/SREK3S/actions/workflows/ci.yaml"><img src="https://github.com/duckiec/SREK3S/actions/workflows/ci.yaml/badge.svg?branch=main" alt="CI" /></a> <a href="https://github.com/duckiec/SREK3S/actions/workflows/release.yaml"><img src="https://github.com/duckiec/SREK3S/actions/workflows/release.yaml/badge.svg" alt="Release" /></a> <a href="https://github.com/duckiec/SREK3S"><img src="https://img.shields.io/badge/platform-linux%2Famd64%20%7C%20linux%2Farm64-4655db" alt="Multi-arch" /></a> <a href="https://go.dev"><img src="https://img.shields.io/badge/go-1.25%2B-00ADD8?logo=go" alt="Go" /></a> <a href="https://www.python.org"><img src="https://img.shields.io/badge/python-3.11-3776AB?logo=python" alt="Python" /></a> <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License: MIT" /></a> <a href="https://github.com/duckiec/SREK3S/actions/workflows/ci.yaml"><img src="https://img.shields.io/badge/tests-1087%20passed%20%7C%20179%20go-success" alt="Tests" /></a>
  </p>
</div>

Most Kubernetes AI agents are a rootkit waiting to happen. They demand cluster-admin rights and stream raw stdout to external LLM APIs. SREK3S is a zero-trust, read-only incident response agent. It intercepts pod crashes, scrubs secrets in-memory before network egress, and sandboxes LLM triage in a POSIX-jailed worker. It generates verified GitOps patches with strictly zero cluster write authority and deterministically fails closed to human review.

## Features

- **Zero cluster mutations**: namespaced `get`/`list`/`watch` only. No ClusterRole, no write field on either wire contract, no mounted token on the Agent.
- **In-memory secret scrubbing**: 11 ordered regex rules run before egress. Nothing unmasked reaches a queue, a disk, or a socket.
- **AST YAML validation**: a patch survives a YAML AST parse, then `git apply --check` against the target's own bytes.
- **Deterministic Tier-2 escalation**: tier, patch, and every flag are computed before a model is consulted. Tier-2 carries no patch, unrepresentably.
- **POSIX-jailed triage worker**: `RLIMIT_AS`, `RLIMIT_CPU`, `RLIMIT_CORE` set before `exec`, unraisable inside.
- **Nine providers, three protocols**: Gemini, Anthropic Messages, OpenAI chat-completions. No credential degrades to deterministic prose.

Full detail in [`docs/security-invariants.md`](docs/security-invariants.md).

## Demo

![SREK3S In-Memory Redaction & Fail-Closed Triage](docs/assets/demo.gif)

*Live execution: A pod leaking an AWS Secret Access Key to container logs is intercepted and scrubbed in-memory by the Go Sentinel before network egress. The Python Agent applies POSIX sandboxing and YAML AST validation, rejecting hallucinated remedies and failing closed to Tier-2 architectural review.*

## Quick Start

Prerequisites: `git`, `kubectl`, and a cluster you can write to. For local development, Go 1.25+, Python 3.11, and Docker with buildx.

```bash
git clone https://github.com/duckiec/SREK3S.git && cd SREK3S

# Deploy SREK3S to any k8s/k3s cluster using prebuilt multi-arch images
kubectl kustomize --load-restrictor LoadRestrictionsNone deploy/overlays/quickstart \
  | kubectl apply -f -
```

Detonation: a real crashing workload with a planted credential.

```bash
make deploy-overlay OVERLAY=deploy/overlays/quickstart-live  # scope the Sentinel to the chaos namespace
make chaos            # deploy the real-crash fixture

# the raw container log, credential intact — this is the input
kubectl -n sentinel-chaos logs deploy/real-crash | grep AWS_SECRET

# the Sentinel's output, credential masked — this is what egress carries
kubectl -n srek3s-system logs deploy/srek3s-sentinel -f | grep stats

make clean             # removes the sentinel-chaos namespace and .venv311
```

### Working on it

The Quick Start runs published images and builds nothing. To work on SREK3S, or to
run the gates against your own build, you need the toolchain: Linux or WSL2, Go
1.25+, Python 3.11 (`.venv311`), Docker with buildx, `gcc`, and a cluster.

```bash
make doctor      # host pre-flight: OS, arch, docker+buildx, go, python 3.11+
make bootstrap   # create .venv311, install agent deps, download Go modules
make test        # every gate: go vet, gofmt, -race, black, flake8, mypy, pytest
make deploy      # apply deploy/base and wait for both rollouts
```

`make deploy` applies your locally built `registry.internal/...` images, so follow it
with a plain `make deploy-overlay` and no `OVERLAY=` to detonate against your own
build. The remaining targets are in [`docs/development.md`](docs/development.md).

## Project Structure

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

## Documentation

| Document | Contents |
|---|---|
| [`docs/architecture.md`](docs/architecture.md) | Component topology, and the detection and emission path a scrubbed payload travels |
| [`docs/security-invariants.md`](docs/security-invariants.md) | The invariants and their enforcing tests, both wire contracts, and the 11 scrubber rules |
| [`docs/models.md`](docs/models.md) | Nine providers across three protocols, credential mounting, and adapter behaviour |
| [`docs/development.md`](docs/development.md) | Gates, build, deploy, publishing, silent-failure modes, and verification without a cluster |
| [`docs/hardening-and-ci.md`](docs/hardening-and-ci.md) | Test matrices, static analysis, repository rulesets, and where the enforcement is weaker than it looks |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | Invariants, gates, and the normative masking specification |
| [`docs/runbook.md`](docs/runbook.md) | Deploy, observe, interpret, review |
| [`docs/lessons-learned.md`](docs/lessons-learned.md) | Defects found, including negative controls that failed for the wrong reason |
| [`docs/offline-install.md`](docs/offline-install.md) | Installing images without a registry |
| [`docs/ci-triage-protocol.md`](docs/ci-triage-protocol.md) | Reading a red CI run |

---

## License

MIT. See [LICENSE](LICENSE).
