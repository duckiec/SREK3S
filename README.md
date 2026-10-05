# SREK3S

[![CI](https://github.com/duckiec/SREK3S/actions/workflows/ci.yaml/badge.svg?branch=main)](https://github.com/duckiec/SREK3S/actions/workflows/ci.yaml)
[![Release](https://github.com/duckiec/SREK3S/actions/workflows/release.yaml/badge.svg)](https://github.com/duckiec/SREK3S/actions/workflows/release.yaml)
[![Multi-arch](https://img.shields.io/badge/platform-linux%2Famd64%20%7C%20linux%2Farm64-4655db)](https://github.com/duckiec/SREK3S)
[![Go](https://img.shields.io/badge/go-1.25%2B-00ADD8?logo=go)](https://go.dev)
[![Python](https://img.shields.io/badge/python-3.11-3776AB?logo=python)](https://www.python.org)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-1087%20passed%20%7C%20179%20go-success)](https://github.com/duckiec/SREK3S/actions/workflows/ci.yaml)

**Zero-trust, read-only AI incident response for Kubernetes.**

Most autonomous cluster agents demand broad write privileges and stream raw stdout to external APIs. SREK3S draws a hard boundary: it triages pod crashes and generates verified GitOps patches with strictly zero cluster write authority. By enforcing in-memory secret scrubbing before egress and sandboxing LLM validations in a POSIX worker, it eliminates the blast radius of hallucinated remediations.

## Features

- **Zero cluster mutations** — the Sentinel's Role grants only `get`, `list` and `watch`. There is no `ClusterRole`, no `ClusterRoleBinding`, and no field on either wire contract capable of expressing a write verb. The Agent mounts no ServiceAccount token at all.
- **In-memory regex secret scrubbing** — 11 ordered `regexp` rules mask credentials on the Go node before any network call, so nothing unmasked reaches a queue, a disk, or a socket. Masking is idempotent, and the Agent re-scrubs every string it returns.
- **AST YAML validation** — a proposed patch must survive a YAML AST parse before anything downstream is entitled to believe it, and then `git apply --check` against the target manifest's own bytes in a throwaway repository.
- **Deterministic Tier-2 escalation** — tier, patch and every validation flag are computed before any model is consulted. The unverifiable case is Tier-2, and a Tier-2 response carrying a patch is unrepresentable rather than merely discouraged.
- **POSIX worker containment** — generated code runs in a disposable process under `RLIMIT_AS`, `RLIMIT_CPU` and `RLIMIT_CORE`, installed before `exec` and unraisable from inside.
- **Nine providers, three protocols** — Gemini, Anthropic Messages with forced tool-use, and the OpenAI chat-completions shape, including local Ollama and vLLM. With no credential the service degrades to deterministic prose and keeps triaging.

Prerequisites for the Quick Start: `git`, `kubectl`, and a cluster you can write to.
For local development: Linux or WSL2, Go 1.25+, Python 3.11 (`.venv311`), Docker with
buildx, `git`, `gcc`, and a cluster. CI uses k3s; the components are not k3s-specific.

## Demo

![SREK3S In-Memory Redaction & Fail-Closed Triage](docs/assets/demo.gif)

*Live execution: A pod leaking an AWS Secret Access Key to container logs is intercepted and scrubbed in-memory by the Go Sentinel before network egress. The Python Agent applies POSIX sandboxing and YAML AST validation, rejecting hallucinated remedies and failing closed to Tier-2 architectural review.*

## Quick Start

Nothing to build. The published images are multi-arch (`linux/amd64` and
`linux/arm64`) and public, so this is a clone, an apply, and a detonation. The
prerequisite list above is the whole list — no Go toolchain, no Python virtualenv, no
Docker, no registry login. `make` is needed for the detonation only, so run this from
a local clone or a Codespace rather than from a tarball.

This is not a k3s project with a k3s convenience. The Sentinel uses stock
`client-go` shared informers and the in-cluster credential path, so it behaves
identically on k3s, kubeadm, kind, minikube, EKS, GKE, AKS, or any other conformant
cluster. See [`docs/security-invariants.md`](docs/security-invariants.md) for the
network policy that reaches the API server, and note the one cluster-specific edit
below.

```bash
git clone https://github.com/duckiec/SREK3S.git && cd SREK3S

# Deploy SREK3S to any k8s/k3s cluster using prebuilt multi-arch images
kubectl kustomize --load-restrictor LoadRestrictionsNone deploy/overlays/quickstart \
  | kubectl apply -f -
```

`make deploy-quickstart` is the same thing with a rollout wait on both Deployments,
if you would rather not read the pipe.

> **On your API server address.** The Sentinel's egress rule permits TCP 443 to the
> default Service CIDRs — `10.43.0.0/16` (k3s) and `10.96.0.0/12` (kubeadm, kind,
> minikube, EKS, GKE). If your API server is external to the Service CIDR, patch that
> `ipBlock` in your own overlay. The symptom if you skip this is a Sentinel that logs
> `failed to list *v1.Pod` every 30 seconds with `watcher_emitted: 0` and **zero
> 403s**, which is a silently blind watcher rather than an error. The rationale is
> in `deploy/sentinel.yaml`.

> **On what it watches by default.** `WATCH_NAMESPACE` ships as `srek3s-system`,
> which is the same namespace `deploy/rbac.yaml` grants — so the shipped watch scope
> and the shipped read authority agree, and the Sentinel sees nothing outside its own
> namespace. That is deliberate, and it means a fresh install on your cluster reports
> no incidents until you widen **both** halves. To watch a namespace, set
> `WATCH_NAMESPACE` and grant the read verbs there; `deploy/overlays/local-live`
> does exactly this for `sentinel-chaos`. Applying only one half produces a forbidden
> `LIST` retried forever, which is silence rather than an error.

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

The `OVERLAY=` is load-bearing. Without it `make deploy-overlay` applies
`deploy/overlays/local-live`, which renders the `registry.internal/...` placeholders
the manifests ship with, and both Deployments would start `ImagePullBackOff` after a
successful Quick Start. `deploy/overlays/quickstart-live` is the same chaos
configuration against the published images. See
[`Makefile`](Makefile) and `deploy/overlays/quickstart-live/kustomization.yaml`.

`make clean` does not remove `srek3s-system` or the container images.

## Developer Setup

The Quick Start above builds nothing. To work on SREK3S, or to run the full gate
sweep against your own build, add the toolchain listed at the top of this file.

```bash
git clone https://github.com/duckiec/SREK3S.git && cd SREK3S
make doctor      # host pre-flight: OS, arch, docker+buildx, go, python 3.11+
make bootstrap   # create .venv311, install agent deps, download Go modules
make test        # every gate: go vet, gofmt, -race, black, flake8, mypy, pytest
make deploy      # apply deploy/base and wait for both rollouts
```

`make deploy` applies your locally built `registry.internal/...` images, so follow it
with the plain `make deploy-overlay` — no `OVERLAY=` — to detonate against your own
build. Without a registry, [`docs/offline-install.md`](docs/offline-install.md) has
the `docker save` / `ctr images tag` path.

| Target | What it does |
|---|---|
| `make help` | Every target, with the resolved interpreter and the common overrides |
| `make deploy-quickstart` | The Quick Start, as a target |
| `make verify-images` | Build, then **execute** each entrypoint — a layer list can be right while the binary cannot run |
| `make push-multiarch` | Build and push a `linux/amd64` + `linux/arm64` manifest list |
| `make clean-images` | Remove the two local images |

`docs/development.md` covers the gates, publishing, silent-failure modes, and how to
verify without a cluster.

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
