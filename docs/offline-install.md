# Image installation into k3s

**Two mechanisms, and the difference between them is the point of this document.**
One has been run against a real k3s node. The other has not. They are kept apart
here rather than presented as one workflow, because conflating them produces a
document that is confidently wrong about the case that matters most.

| | Mechanism | Needs a registry? | Verified on a real node? |
|---|---|---|---|
| **A** | `ctr images pull` + `ctr images tag` | **Yes** | **Yes** — every E2E detonation run |
| **B** | `ctr images import <tarball>` | No | **No** |

**Status unchanged as of 2026-10-01.** Mechanism B is still unverified. What has
changed is that this repository now has a development host — WSL2, `Fedora Linux 44
(aarch64)`, with a native Docker and a live single-node k3s v1.36.4 — which is
exactly what B needs in order to be tested. Capability is not verification; see
[Mechanism B is now executable — and still unverified](#mechanism-b-is-now-executable--and-still-unverified).

Mechanism A is the **connected** path: the node fetches from a registry and tags
the result for the kubelet. It is verified, and it is what
`.github/workflows/e2e-detonation.yaml` exercises against real k3s containerd on
every run.

Mechanism B is the **air-gapped** path: the image is built elsewhere, shipped as
a tarball, and loaded locally with no registry reachable. It is the case this
document is really about, and **it has not been executed against a real node.**

> **`pull` is not an offline path and must not be documented as one.** It requires
> a reachable registry, which is the thing an air-gapped cluster by definition
> does not have. A runbook that offers `pull` as the offline answer hands the
> reader a command that cannot work in the situation the document was written for,
> and the failure surfaces as `ImagePullBackOff` with no obvious cause.

The reasoning for mechanism B is settled, and getting it wrong is expensive: the
failure mode is a node reaching for a registry it cannot see while the image sits
on disk in a namespace nothing reads.

---

## Mechanism A — verified: `pull` then `tag`

This is the path CI runs. Reproduced from `e2e-detonation.yaml` L353-355:

```bash
# Pull into k8s.io - the namespace kubelet reads - then tag the image under the
# name the manifests reference. The fixtures use imagePullPolicy: Never, so a
# missing tag is ImagePullBackOff rather than a silent pull at container start.
sudo k3s ctr --timeout 30s --namespace k8s.io images pull <registry>/<image>:<tag>
sudo k3s ctr --timeout 30s --namespace k8s.io images tag  <registry>/<image>:<tag> \
                                                            <name-the-manifest-asks-for>
```

Observed on E2E detonation run `36795230898`:

```
containerd socket reachable as runner via sudo
containerd image service is ready.
pull attempt 1: mirror.gcr.io/library/busybox:1.36.1 (timeout 60s)
pulled mirror.gcr.io/library/busybox:1.36.1
docker.io/library/busybox:1.36.1
busybox registered in k8s.io under the name the fixtures reference
```

**What this proves**, which is more than it first appears:

- `k3s ctr` reaches containerd as an unprivileged user with `sudo`.
- `--namespace k8s.io` is indeed the namespace the kubelet resolves against.
- A tag written by hand is what `imagePullPolicy: Never` then consumes — proven by
  the fixture pods starting at all.
- The whole chain works on a real node rather than in a mock.

**What this does not prove:** that `images import` of a tarball behaves the same
way. The two commands share a namespace argument and nothing else worth assuming.

`--timeout 30s` on every `ctr` call is not decoration. The global default is `0`,
which means wait-forever, and CI reports a step killed by timeout with
`conclusion: failure` — byte-identical to a real error. An unbounded wait is
indistinguishable from a failure without logs.

### Mechanism A on a local host — three differences

On the `Fedora 44` / k3s v1.36.4 development host the same two commands apply,
with three additions that are not optional:

- **`sudo` on every `ctr` call, for the same reason as in CI.** The containerd
  socket under `/run/k3s/containerd/` is root-owned, so an unprivileged
  `k3s ctr` cannot reach it. This is the same fact CI discovered the hard way and
  recorded above.
- **`--platform linux/arm64` on the build, not on the pull.** The host is
  `aarch64`. `ctr images pull` resolves whatever the registry serves; if the
  image was pushed `amd64`-only, you get an `amd64` image on an `arm64` node and
  the failure surfaces as a container that cannot start — or, worse, as a
  `kubectl describe` message about a missing executable. Build for the node.
- **The exact fully-qualified name is the whole point.** `deploy/sentinel.yaml`
  asks for `registry.internal/srek3s-sentinel:0.1.0` and `deploy/agent.yaml` for
  `registry.internal/srek3s-agent:0.1.0`. A tag registered as
  `docker.io/library/srek3s-agent:0.1.0` is a different name to the kubelet, and
  the error is `ImagePullBackOff`, which does not mention naming. Verify with
  `sudo k3s ctr images ls --namespace k8s.io` before blaming the cluster.

`busybox:1.36.1` is needed separately: `deploy/chaos/` pins it with
`imagePullPolicy: Never`, so a missing image is a **hard apply failure** rather
than a pull at container start — which makes it the cheapest possible check that
registration actually works. It does publish an `arm64` manifest, so it is
available on this host without a multi-arch build.

---

## Mechanism B — not verified: `import` (air-gapped)

Documented because the reasoning holds and because it is the case that matters.
**Unverified. Run it against a real node before trusting it in an air-gapped
cluster.**

### Why the default import is not enough

`k3s ctr images import` puts an image into the **k3s containerd namespace**, which
is *not* the `k8s.io` namespace that kubelet actually reads from. An image
imported without the namespace argument lands somewhere the kubelet never looks,
and `kubectl get pods` reports `ImagePullBackOff` even though the image is present
on the node. This is the single most common failure in this workflow, and it looks
like a network problem rather than a namespace problem.

`--all-namespaces` avoids the question. It is the right choice for a first-boot
install, where no image has been pulled yet so there is no existing namespace to
conflict with. A repeated import into a running cluster should use the explicit
namespace below instead, so the operation is visible and idempotent rather than
scattering copies.

### First boot, before any pod has pulled an image

```bash
# Build the two images locally, tagged for the internal registry the manifests
# reference. The tags must match deploy/sentinel.yaml and deploy/agent.yaml
# exactly: a tag mismatch produces ImagePullBackOff, not a manifest error.
#
# `sudo docker` because the user is not in the docker group; `--platform
# linux/arm64` because this host is aarch64 and a wrong-platform image imports
# cleanly and then fails to execute. Both Dockerfiles take the repository root
# as their context.
sudo docker build --platform linux/arm64 -f agent/Dockerfile         -t registry.internal/srek3s-agent:0.1.0 .
sudo docker build --platform linux/arm64 -f cmd/sentinel/Dockerfile  -t registry.internal/srek3s-sentinel:0.1.0 .

# Save and import.
sudo docker save registry.internal/srek3s-agent:0.1.0    -o /tmp/srek3s-agent.tar
sudo docker save registry.internal/srek3s-sentinel:0.1.0 -o /tmp/srek3s-sentinel.tar

sudo k3s ctr images import /tmp/srek3s-agent.tar    --all-namespaces
sudo k3s ctr images import /tmp/srek3s-sentinel.tar --all-namespaces
```

> **Corrected 2026-10-01, and the correction is the point.** This block previously
> read `docker build -f Dockerfile -t registry.internal/srek3s-sentinel:0.1.0 .`
> — a path that has never existed. There is no `Dockerfile` at the repository root;
> the Sentinel's is at `cmd/sentinel/Dockerfile`, and `README.md` and
> `docs/runbook.md` both say so. It sat in the *unverified* section, where a wrong
> command is exactly as invisible as a right one, which is a fair argument for
> expecting it to rot and a poor reason to leave it. A command in a runbook that
> cannot run is a trap, not a placeholder.

### Repeated import into a running cluster

```bash
# Explicit namespace, no --all-namespaces. Idempotent, and the images land exactly
# where kubelet looks.
sudo k3s ctr images import /tmp/srek3s-agent.tar    --namespace k8s.io
sudo k3s ctr images import /tmp/srek3s-sentinel.tar --namespace k8s.io
```

### Verify before deploying

```bash
# The images must be present AND qualified — no registry host prefix, because the
# manifests reference registry.internal/... . This is the check that catches a
# namespace mistake.
sudo k3s ctr images ls --namespace k8s.io | grep srek3s
```

Expected, and nothing else:

```
registry.internal/srek3s-agent:0.1.0    application/vnd.docker.distribution.manifest.v2+json    ...
registry.internal/srek3s-sentinel:0.1.0 application/vnd.docker.distribution.manifest.v2+json    ...
```

A `docker.io/library/...` or `sha256:...` line means the import did not register
the tag the manifests ask for. Fix by tagging explicitly after importing:

```bash
sudo k3s ctr images tag registry.internal/srek3s-agent:0.1.0 docker.io/library/srek3s-agent:0.1.0
```

Note this is `tag` *after* `import` — the same pairing mechanism A uses in the
other order. The pairing is what puts an image in the right namespace under the
right name; which of `pull` or `import` fills it first is what differs.

---

## Mechanism B is now executable — and still unverified

**Read the heading.** The commands below have not been run. What changed on
2026-10-01 is that they *can* be: the development host is `Fedora Linux 44
(aarch64)` under WSL2 with a working Docker daemon and a live single-node k3s
**v1.36.4+k3s1**, which is precisely the configuration mechanism B requires and
which, until now, did not exist anywhere in this project's development
environment. `ROADMAP.md` `ENV-2.4` tracks the execution.

**This section is a staged procedure, not a result.** Nothing below should be cited
as evidence that B works. The honest statement is: *B's reasoning is sound, B is
untested, and there is now a host on which to test it.* Those are three different
claims and conflating the first two is the specific failure this document exists to
prevent.

### What is available, as of 2026-10-01

| Prerequisite for B | State |
|---|---|
| A Docker daemon that can produce a tarball | **Yes** — 29.8.2, `overlayfs`, root `/var/lib/docker`. Requires `sudo docker`; see `docs/runbook.md` §1 |
| A live k3s with a reachable containerd | **Yes** — v1.36.4+k3s1, node `dwindle2`, containerd `2.3.4-k3s1.36` |
| Root access to the containerd socket | **Yes** — `sudo` is passwordless for `duckie` |
| A built SREK3S image | **No** — nothing has been built; `registry.internal/srek3s-*` exists nowhere |
| `busybox:1.36.1` registered in `k8s.io` | **No** — the namespace currently holds only k3s's own images |
| **B itself executed** | **No** |

### The sequence, in order

Run it from the repository root. Every step is a step at which a wrong answer looks
like the next step's failure, so they are not compressed.

```bash
# 1. Build for this node. arm64 is not optional on an aarch64 host.
sudo docker build --platform linux/arm64 \
  -t registry.internal/srek3s-agent:0.1.0    -f agent/Dockerfile .
sudo docker build --platform linux/arm64 \
  -t registry.internal/srek3s-sentinel:0.1.0 -f cmd/sentinel/Dockerfile .

# 2. Sanity-check the architecture before saving, not after.
#    A wrong-platform tarball imports cleanly and fails at container start.
sudo docker image inspect registry.internal/srek3s-agent:0.1.0 \
  --format '{{.Os}}/{{.Architecture}}'     # expect: linux/arm64

# 3. Save. Both images need the exact tag the manifests reference.
sudo docker save registry.internal/srek3s-agent:0.1.0    -o /tmp/srek3s-agent.tar
sudo docker save registry.internal/srek3s-sentinel:0.1.0 -o /tmp/srek3s-sentinel.tar

# 4. Import into the namespace the kubelet reads. See "Why the default import is
#    not enough" above for why this argument is load-bearing.
sudo k3s ctr images import /tmp/srek3s-agent.tar    --namespace k8s.io
sudo k3s ctr images import /tmp/srek3s-sentinel.tar --namespace k8s.io

# 5. Verify both presence AND qualification. No docker.io prefix, no bare digest.
sudo k3s ctr images ls --namespace k8s.io | grep srek3s
```

Expected at step 5, and nothing else:

```
registry.internal/srek3s-agent:0.1.0    application/vnd.docker.distribution.manifest.v2+json    ...
registry.internal/srek3s-sentinel:0.1.0 application/vnd.docker.distribution.manifest.v2+json    ...
```

### Then prove it end to end, because a successful import is not a working pod

```bash
sudo kubectl apply -k deploy/
sudo kubectl -n srek3s-system rollout status deployment/srek3s-agent --timeout=120s
sudo kubectl -n srek3s-system exec deploy/srek3s-agent -- python -c \
  "import os,uid; print('uid', os.getuid())"        # expect: uid 10001
```

`ctr images import` exiting `0` proves the image landed in a namespace. It does not
prove the kubelet resolved that name, that the platform matched, or that the
container started — and the last of those is the only one an operator cares about.
A pod that is `ErrImagePull` after a successful import means the name is wrong; a pod
that starts and immediately `CrashLoopBackOff` on a `exec format error` means the
architecture is wrong. Same import, same exit status, completely different defect.

### What would count as closing B

Not "the commands ran". The box is closed when all of the following are true and
recorded with the run's output:

1. both images imported into `k8s.io` under the exact fully-qualified names;
2. `deploy/` applied and **both** Deployments reached ready;
3. the agent answered `/healthz` over cluster DNS at `srek3s-agent:8000`;
4. `id -u` reported `10001` from the running agent pod.

Anything less is a partial result, and a partial result should be reported as one.
The same standard was applied when mechanism A was accepted: the evidence recorded
for A includes fixture pods *starting*, not merely the tag existing.

---

## Apply

```bash
# kustomize preserves the resource order in deploy/kustomization.yaml: namespace,
# then RBAC, then the workloads. A Role applied before its Namespace exists fails
# with "namespace not found", which is why that file is ordered by hand rather
# than alphabetically.
# `sudo` on a k3s-installed host: /etc/rancher/k3s/k3s.yaml is 0600 and root-owned.
sudo kubectl apply -k deploy/

sudo kubectl -n srek3s-system rollout status deployment/srek3s-sentinel --timeout=120s
sudo kubectl -n srek3s-system rollout status deployment/srek3s-agent    --timeout=120s
```

Expect `deploy/` to come up **silent**, and know why before you go looking: with
`WATCH_NAMESPACE: ""` against a `Role` scoped to `srek3s-system`, the Sentinel is
refused the cluster-wide `LIST` it asks for. That is `docs/runbook.md` §1's open
defect, it is a real one, and it is not a consequence of the image install. The
rollouts above reaching ready is a statement about images and manifests only.

## Confirm the hardening actually took effect

```bash
# The effective UID must be 10001. This is the same assertion the CI container
# smoke test makes, and it is the one field a manifest typo would silently lose:
# `runAsNonRoot: true` with no `runAsUser` runs as the image's user, and a
# Dockerfile edit that dropped USER would change that with no manifest diff.
sudo kubectl -n srek3s-system exec deploy/srek3s-sentinel -- id -u   # => 10001

# The read-only root filesystem is observable: the sentinel writes only to /tmp,
# so an attempt to write elsewhere must fail.
sudo kubectl -n srek3s-system exec deploy/srek3s-sentinel -- sh -c 'touch /root/x'  # must fail

# And the RBAC must be read-only. A rejected write is the proof; a successful one
# is an incident.
sudo kubectl -n srek3s-system exec deploy/srek3s-sentinel -- \
  sh -c 'wget -qO- --post-data="" http://localhost:6443/api/v1/namespaces/default/pods'
# => a 403 with "forbidden: ... cannot create resource"
```

## Rollback

```bash
# The Sentinel holds no cluster write authority, so rollback is a delete and a
# re-apply. Nothing outside the namespace needs reverting, which is the property
# that makes a rollback this cheap.
sudo kubectl delete -k deploy/

# Confirm no state survives: the sentinel writes to /tmp only, and the emptyDir is
# per-pod, so there is nothing to clean up on disk.
sudo kubectl -n srek3s-system get pvc   # must be empty
```

## Not covered here

- **HA control plane**: with more than one server node, run the image load on
  every node. These commands are per-node and are not replicated by k3s. That
  applies to mechanism B *and* to mechanism A's tag step, which writes to one
  node's containerd.
- **Image signing**: `k3s` is started here without `--disable-image-defaults` and
  without a containerd registry configuration, so no signature is verified. An
  air-gapped production install should configure `mirrors` in
  `/etc/rancher/k3s/registries.yaml` with a `configs` block, and set
  `--disable=image` only after the local import path is proven.
- **Version skew**: this covers the `0.1.0` tags in the current manifests. A
  release that bumps the pipeline's `checksum` annotation but not the image tag
  would load the old image and report success, which is why the tag is a
  build-time `-ldflags "-X main.version=..."` stamp rather than a hand-maintained
  string.
- **Architecture skew**: this covers a single architecture. The local host is
  `linux/arm64` and CI is `linux/amd64`; the commands above are identical for both,
  and the *build* is not. A multi-arch deployment needs per-architecture images or a
  manifest list, and the `image inspect` step in the staged procedure above is the
  cheap check that catches having got it wrong — a wrong-platform image imports and
  reports success, then fails to execute.
- **Pod Security Admission is evaluated against the local k3s version**, which
  differs from CI's. `deploy/namespace.yaml` sets
  `pod-security.kubernetes.io/enforce-version: latest`, so locally (k3s v1.36.4)
  admission is judged by 1.36's rules and in CI (k3s v1.29.9) by 1.29's. An image
  can install perfectly and then be refused at apply. That is a version difference,
  not an image problem, and conflating the two sends the investigation to the wrong
  artifact.
