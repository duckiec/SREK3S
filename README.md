# SREK3S

[![CI](https://github.com/duckiec/SREK3S/actions/workflows/ci.yaml/badge.svg?branch=main)](https://github.com/duckiec/SREK3S/actions/workflows/ci.yaml)
[![Release](https://github.com/duckiec/SREK3S/actions/workflows/release.yaml/badge.svg)](https://github.com/duckiec/SREK3S/actions/workflows/release.yaml)
[![Multi-arch](https://img.shields.io/badge/platform-linux%2Famd64%20%7C%20linux%2Farm64-4655db)](https://github.com/duckiec/SREK3S)
[![Go](https://img.shields.io/badge/go-1.25%2B-00ADD8?logo=go)](https://go.dev)
[![Python](https://img.shields.io/badge/python-3.11-3776AB?logo=python)](https://www.python.org)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-1082%20passed%20%7C%20179%20go-success)](https://github.com/duckiec/SREK3S/actions/workflows/ci.yaml)

Most autonomous infrastructure agents are a security breach waiting to happen. SREK3S is a deterministic, fail-closed Kubernetes AI agent that triages pod crashes and generates GitOps patches with strictly zero cluster write authority. It scrubs secrets in-memory before network egress and sandboxes LLM generations to eliminate hallucinated blast radiuses.

## ✨ Features

- 🔒 **Zero cluster write authority** — the Sentinel's Role grants only `get`, `list` and `watch`. There is no `ClusterRole`, no `ClusterRoleBinding`, and no field on either wire contract capable of expressing a write verb. The Agent mounts no ServiceAccount token at all.
- 🧹 **In-memory secret scrubbing before egress** — 11 ordered rules mask credentials on the Go node before any network call, so nothing unmasked reaches a queue, a disk, or a socket. Masking is idempotent, and the Agent re-scrubs every string it returns.
- 📦 **POSIX & YAML AST sandboxing** — generated code runs in a disposable process under `RLIMIT_AS`, `RLIMIT_CPU` and `RLIMIT_CORE`; a proposed patch must survive a YAML AST parse before anything downstream is entitled to believe it.
- 🛑 **Deterministic fail-closed escalation** — tier, patch and every validation flag are computed before a model is consulted. The unverifiable case is Tier-2, and a Tier-2 response carrying a patch is unrepresentable rather than merely discouraged.
- ✅ **Two-layer patch verification** — a YAML AST parse, then `git apply --check` against the target manifest's own bytes in a throwaway repository. The second layer asserts the file actually changed rather than trusting an exit status.
- 🔌 **Nine providers, three protocols** — Gemini, Anthropic Messages with forced tool-use, and the OpenAI chat-completions shape, including local Ollama and vLLM. With no credential the service degrades to deterministic prose and keeps triaging.

Prerequisites: Linux or WSL2, Go 1.25+, Python 3.11 (`.venv311`), Docker with
buildx, `git`, `gcc`, and a cluster. CI uses k3s.

## Demo

![SREK3S In-Memory Redaction & Fail-Closed Triage](docs/assets/demo.gif)

*Live execution: A pod leaking an AWS Secret Access Key to container logs is intercepted and scrubbed in-memory by the Go Sentinel before network egress. The Python Agent applies POSIX sandboxing and YAML AST validation, rejecting hallucinated remedies and failing closed to Tier-2 architectural review.*

## Quick Start

```bash
git clone https://github.com/duckiec/SREK3S.git && cd SREK3S
make doctor      # host pre-flight: OS, arch, docker+buildx, go, python 3.11+
make bootstrap   # create .venv311, install agent deps, download Go modules
make test        # every gate: go vet, gofmt, -race, black, flake8, mypy, pytest
make deploy      # apply deploy/base and wait for both rollouts
```

Detonation: a real crashing workload with a planted credential.

```bash
make deploy-overlay   # scope the Sentinel to the chaos namespace
make chaos            # deploy the memory-leak fixture

# the raw container log, credential intact — this is the input
kubectl -n sentinel-chaos logs deploy/real-crash | grep AWS_SECRET

# the Sentinel's output, credential masked — this is what egress carries
kubectl -n srek3s-system logs deploy/srek3s-sentinel -f | grep stats

make clean             # removes the sentinel-chaos namespace and .venv311
```

`make clean` does not remove `srek3s-system` or the container images.

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
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | Invariants, gates, and the normative masking specification |
| [`docs/runbook.md`](docs/runbook.md) | Deploy, observe, interpret, review |
| [`docs/lessons-learned.md`](docs/lessons-learned.md) | Defects found, including negative controls that failed for the wrong reason |
| [`docs/offline-install.md`](docs/offline-install.md) | Installing images without a registry |
| [`docs/ci-triage-protocol.md`](docs/ci-triage-protocol.md) | Reading a red CI run |

---

## License

MIT. See [LICENSE](LICENSE).
