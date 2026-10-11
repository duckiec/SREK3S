<div align="center">
  <img src="docs/assets/banner.svg" alt="SREK3S banner: the project mark and wordmark" width="100%" />
  <br />
  <p>
    <a href="https://github.com/duckiec/SREK3S/actions/workflows/ci.yaml"><img src="https://github.com/duckiec/SREK3S/actions/workflows/ci.yaml/badge.svg?branch=main" alt="CI" /></a> <a href="https://github.com/duckiec/SREK3S/actions/workflows/release.yaml"><img src="https://github.com/duckiec/SREK3S/actions/workflows/release.yaml/badge.svg" alt="Release" /></a> <a href="https://github.com/duckiec/SREK3S"><img src="https://img.shields.io/badge/platform-linux%2Famd64%20%7C%20linux%2Farm64-4655db" alt="Multi-arch" /></a> <a href="https://go.dev"><img src="https://img.shields.io/badge/go-1.26%2B-00ADD8?logo=go" alt="Go" /></a> <a href="https://www.python.org"><img src="https://img.shields.io/badge/python-3.11-3776AB?logo=python" alt="Python" /></a> <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License: MIT" /></a>
  </p>
</div>

SREK3S watches for pod failures, masks credentials in memory before anything leaves the node, and hands you a Git patch to review. Its ServiceAccount binds a namespaced Role granting `get`, `list`, and `watch`. The Agent holds no ServiceAccount token.

## Run it in 60 seconds

```bash
git clone https://github.com/duckiec/SREK3S.git && cd SREK3S
make demo
```

Three targets run in order:

| Target | What it does |
|---|---|
| `throwaway-up` | Starts a disposable k3s cluster in Docker on its own bridge network |
| `throwaway-wait` | Blocks until the node is Ready and cluster DNS resolves |
| `throwaway-detonate` | Builds both images, installs the chart, applies a real OOMKill fixture, waits for triage, asserts |

Each command pins `KUBECONFIG=/tmp/k3s-throwaway.yaml`. Your current kubectl context stays loaded, and nothing lands on any cluster but the throwaway.

The run ends in assertions, not a screenshot:

```
===================== ASSERTIONS ====================
  [ok] sentinel emitted 3 incident(s)
  [ok] agent triaged (2 verdict(s))
  [ok] GitOps checkout succeeded (2 Tier-1 verdict(s))
```

`make throwaway-down` removes the container.

## What the demo captures

![SREK3S in-memory redaction and fail-closed triage](docs/assets/demo.gif)

The recording shows a pod leaking a credential to its logs, the Go Sentinel masking it before network egress, and the Python Agent declining a hallucinated remedy and escalating to human review.

[`examples/oom-recalibration/`](examples/oom-recalibration/) holds one incident captured off the wire: the crashing pod's log with the credential intact, the payload that crossed, the Tier-1 decision, and the diff it produced.

## How it decides

**Tier selection runs before any model.** The Agent computes the tier, the patch, and each validation flag from the evidence, then asks a model for prose. A `TIER_2_ARCHITECTURAL` response carrying a patch raises instead of logging a warning, so the failure stays unrepresentable rather than discouraged.

**Tier-1 requires an enumerated remedy.** One manifest, one resource field, no code or image change, decided in advance rather than inferred per incident. A patch earns the label by surviving a YAML AST parse and `git apply --check` against the target file's own bytes.

**The Go node masks secrets in memory, before egress.** Eleven ordered rules run ahead of any network call. Redaction keeps the parts a diagnosis needs:

```
postgres://checkout:[REDACTED]@db-primary:5432/prod
```

Host, port, database, and user survive. The password does not.

**No configuration can weaken a rule.** The loader checks each rule against the compiled table at boot: pattern, `multiLine`, and `template` must match exactly. A ConfigMap that flips `multiLine` to `false`, swaps in a pattern that compiles but matches nothing, or rewrites a template to `${1}${2}${3}` fails to load and exits 1 before the watcher starts. A test pins all five shipped copies to the compiled table.

**Read-only is checkable.** Neither wire contract carries a field that can express a write verb, so a patch cannot smuggle one through the model.

**Every response string passes the re-scan.** The Go node masks before egress; the Agent re-masks each response field, including `root_cause.summary` and `root_cause.evidence`, before it leaves.

**Busy pods stay in contract.** The Sentinel caps fetched events at the Agent's `cluster_events` limit, so a crash-looping pod with a long history produces a payload the Agent accepts instead of a 422.

**Boot fails closed where silence would be a security property.** A scrubber manifest that will not parse, or that weakens a rule, exits 1 before the watcher starts, because a Sentinel running with fewer rules than it claims is worse than one that never began. A malformed `LOG_LEVEL` degrades to `INFO` instead, and the comment beside it explains the asymmetry.

**The Sentinel needs an explicit port rule to reach the API server on kube-router.** That CNI evaluates NetworkPolicy after kube-proxy rewrites the ClusterIP, so a policy allowing `<service CIDR>:443` denies the connections that matter. The shipped rule permits TCP 6443 by port, which survives a reboot.

## Install

```bash
kubectl kustomize --load-restrictor LoadRestrictionsNone deploy/overlays/quickstart \
  | kubectl apply -f -
```

`deploy/base/` is the kustomize base of record. It sits in its own directory because an overlay referencing `../..` trips kustomize's cycle detection, and a test fails if a second base appears beside it.

The Agent runs with `automountServiceAccountToken: false`. Only the Sentinel mounts a token, and only to read.

A default install routes each incident to `TIER_2_ARCHITECTURAL`. `agent.targetManifest` is empty, so no patch can pass verification, and that matches the designed resting state. Reach Tier-1 by setting it:

```bash
helm install srek3s deploy/helm/srek3s -n srek3s-system --create-namespace \
  --set agent.gitops.repoUrl=https://github.com/duckiec/SREK3S.git \
  --set agent.targetManifest=deploy/chaos/oom-leak.yaml
```

Prerequisites: `git`, `kubectl`, and a cluster you can write to.

## Documentation

| Document | Contents |
|---|---|
| [`docs/security-invariants.md`](docs/security-invariants.md) | The guarantees, the `I-A*` and `I-B*` tables, and the gaps still open |
| [`docs/runbook.md`](docs/runbook.md) | Deploy, observe, interpret, review |
| [`examples/oom-recalibration/`](examples/oom-recalibration/) | One captured incident, payload to patch |
| [`docs/architecture.md`](docs/architecture.md) | Component topology and the emission path |
| [`docs/models.md`](docs/models.md) | Nine providers across three protocols |
| [`docs/development.md`](docs/development.md) | Gates, build, deploy, verification without a cluster |
| [`docs/hardening-and-ci.md`](docs/hardening-and-ci.md) | Test matrices, static analysis, where enforcement is weaker than it looks |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | Invariants, gates, the normative masking specification |
| [`docs/lessons-learned.md`](docs/lessons-learned.md) | Defects found, including controls that failed for the wrong reason |
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

Your Go toolchain decides what a local `govulncheck` covers. A distro build reports its version with a suffix, such as `go1.26.8-X:nodwarf5`, and the scanner drops the standard-library advisories when the version matches no release. `make check-supply-chain` prints the toolchain it is about to trust and warns when it is a patched build. CI pins `GO_VERSION` to an exact patch for the same reason.

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
