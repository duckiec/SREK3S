# Development, Gates and Deployment

How the project is built, gated, verified and published.

## Gates

| Gate | Command | Scope |
|---|---|---|
| `G1` | `go vet ./...` | Go static analysis |
| `G2` | `gofmt -l .` | Ensures no unformatted files |
| `G3` | `go test -race -timeout 30s ./...` | Go units and data races |
| `G4` | `black --check agent/ tests/` | Python formatting |
| `G5` | `flake8 agent/ tests/` | Python style |
| `G6` | `mypy --strict agent/ tests/` | Strict typing |
| `G7` | `govulncheck ./...` | Reachable CVEs |
| M3 | Terminal validation | `TestNilPointerSafety`, `TestNoGoroutineLeak`, `TestIncidentPayloadContract` |
| AC-2 | Corpus replay | 46 cases across 8 groups, 32 maskable, 6 negative controls |
| AC-4 | Container build and runtime smoke | Asserts UID 10001, imports `main:app` |
| Routing | `test_the_agent_service_routes_the_sentinels_default_endpoint` | Service selector, pod labels, target port and the Sentinel's built-in default resolve to one endpoint |
| Workflow | `scripts/audit_workflow.py --strict` | Every workflow's own shell: `bash -n`, unpiped `curl \| sh`, `producer \| grep -q` SIGPIPE races, multi-command `if` conditions, referenced paths that do not exist |
| Manifests | `test_deploy_manifests.py` | PSA compliance, RBAC shape, hardening block |
| Chaos fixtures | `test_chaos_fixtures.py` | Executes each fixture script and asserts the failure under test |
| Images | `test_sentinel_image.py` | Stage split, `CGO_ENABLED=0`, cross-compile ARGs |
| Workflows | `test_workflows.py` | Triggers, `needs:` resolution, multi-arch coverage, least privilege, gate presence |
| Doc links | `test_docs_links.py` | Every `#anchor` in the user-facing documents resolves |
| Multi-arch | `multi-arch-dry-run` job | `linux/amd64` and `linux/arm64`, `output: type=cacheonly` |

`G7` blocks on vulnerabilities **reachable from this code**: govulncheck exits
non-zero only when a vulnerable symbol is called, which is a stronger condition than a
version-based alert and blocks reachable moderate findings. A CVE present in a
required module that nothing calls is reported and does not block. The step asserts its
own advisory database is reachable before trusting a clean result, because
govulncheck exits 0 and reports no vulnerabilities when it cannot fetch advisories —
indistinguishable, in its output, from a genuinely clean scan.

The skip ratchet holds the Python skip count at 3. The count may fall; a rise fails
the build. The three skips are a blocked dependency, not a pass: two need a reachable
apiserver and one needs a case-folding filesystem.

## Build

```bash
go build -o bin/sentinel ./cmd/sentinel
sudo docker build -t registry.internal/srek3s-agent:0.1.0    -f agent/Dockerfile .
sudo docker build -t registry.internal/srek3s-sentinel:0.1.0 -f cmd/sentinel/Dockerfile .
```

Both images take the repository root as their build context. A context of `agent/` or
`cmd/sentinel/` fails at `COPY`, because the module and the compiled packages live
outside those directories.

Running the binary directly suffices for development:

```bash
./bin/sentinel -agent-url http://127.0.0.1:8001 -namespace default
```

## Deploy

```bash
sudo kubectl kustomize --load-restrictor LoadRestrictionsNone deploy/base \
  | kubectl apply -f -
```

`deploy/service.yaml` publishes the Agent on `srek3s-agent:8000`, which is the
Sentinel's built-in `-agent-url` default. The Service selector against the Agent's pod
labels, and its `targetPort` against the port the Agent binds, are asserted equal by
`test_the_agent_service_routes_the_sentinels_default_endpoint`.

## Three silent failures

**A watch scope and its RBAC grant must agree.** A cluster-wide watch against a
namespaced Role produces no incidents and no error: the informer retries a forbidden
request indefinitely. `deploy/sentinel.yaml` ships `WATCH_NAMESPACE: srek3s-system`,
matching the Role as committed. Widening one without the other is the failure. One
narrow `Role` per namespace is the intended shape, each bound back to the Sentinel
ServiceAccount in `srek3s-system`.

**A NetworkPolicy matching nothing also produces silence, with zero 403s**, because no
authorization is attempted. An RBAC-only check reports the deployment healthy while the
watcher observes nothing.

**Pod Security Admission failures read as an empty cluster.** A manifest rejected
under PSA `restricted` fails closed, and a fixture refused at admission is worse than
no fixture: it presents as a quiet cluster. `deploy/namespace.yaml` sets
`enforce-version: latest`, so the same manifests can be admitted on k3s 1.36 and
refused on 1.29. Diagnose version skew before diagnosing the manifest.

`ImagePullBackOff` is produced by both a wrong-platform image and an absent image.
Distinguish them with `sudo k3s ctr images ls --namespace k8s.io`.

## Publishing

`git tag v0.1.0 && git push --tags` publishes both images to GitHub Container Registry
as `linux/amd64` and `linux/arm64` manifest lists, using the default `GITHUB_TOKEN`.
No registry credential is stored in this repository. The `:latest` tag moves; pin the
version tag. The manifests reference `registry.internal/`, so deploying a released
image means rewriting the image reference or kustomizing an overlay with an `images:`
block.

## Running the gates

```bash
make test

PY=~/SREK3S/.venv311/bin/python
go test -race ./...                 # 1090 Python tests + 179 Go test functions
$PY -m pytest agent/tests/ -q       # 1087 passed, 3 skipped
$PY -m black --check agent/ tests/
$PY -m flake8 agent/ tests/
$PY -m mypy --strict agent/ tests/
$PY scripts/audit_workflow.py --strict
```

## Make targets

The four in the README's Quick Start cover a normal working session. The rest:

| Target | What it does |
|---|---|
| `make help` | Every target, with the resolved interpreter and the common overrides |
| `make deploy-quickstart` | The Quick Start, as a target |
| `make verify-images` | Build, then **execute** each entrypoint — a layer list can be right while the binary cannot run |
| `make push-multiarch` | Build and push a `linux/amd64` + `linux/arm64` manifest list |
| `make clean-images` | Remove the two local images |

`make deploy` applies your locally built `registry.internal/...` images, so follow it
with the plain `make deploy-overlay` — no `OVERLAY=` — to detonate against your own
build. Without a registry, [offline-install.md](offline-install.md) has the
`docker save` / `ctr images tag` path.

## Verification without a cluster

The paths worth testing are the offline ones.

| Layer | Exercises | Cluster |
|---|---|---|
| Go unit and race | Scrubber, classifier, telemetry, worker pool, nil-safety | No |
| Python unit | Schemas, invariants, patch grammar, sandbox limits, budget | No |
| Corpus replay | 46 secret-shaped cases through the real 11-rule pipeline | No |
| Golden fixtures | Byte-identical diff and RCA output | No |
| Offline `git apply` | Real `git apply --check` in a scratch repository | No |
| E2E detonation | Informer, scrub, egress, classify, patch, verify | k3s |
| E2E in-cluster | `deploy/` applies; Service DNS, RBAC, hardening, live | k3s |

The detonation leg installs k3s, plants a memory leak and asserts the whole chain,
including that a planted secret did not survive scrubbing, that scrubbing masked
something, and that masking preserved diagnostic evidence. Masking everything and
masking nothing are both failures and both are asserted.

The in-cluster leg exists because the detonation leg runs the Sentinel, the Agent and
the capture proxy as host processes on loopback and applies nothing from `deploy/`.
It applies `deploy/` and asserts that the Service publishes ready endpoints, that
cluster DNS resolves `srek3s-agent` and the Agent answers `/healthz`, that the
Sentinel's real ServiceAccount is granted reads and refused writes by a live
apiserver, and that the running Agent pod is UID 10001 with a read-only root and no
mounted token. It detonates nothing; that chain belongs to the detonation leg.

Every gate in this project reads code or a manifest. None reads a document, so the
layout of `cmd/`, `internal/`, `agent/`, `deploy/` and `tests/` is free to change
without a test failing for a reason unrelated to whether the system works.
