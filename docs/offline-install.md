# Image installation into k3s

**Two mechanisms, and the difference between them is the point of this document.**
One has been run against a real k3s node. The other has not. They are kept apart
here rather than presented as one workflow, because conflating them produces a
document that is confidently wrong about the case that matters most.

| | Mechanism | Needs a registry? | Verified on a real node? |
|---|---|---|---|
| **A** | `ctr images pull` + `ctr images tag` | **Yes** | **Yes** — every E2E detonation run |
| **B** | `ctr images import <tarball>` | No | **No** |

Mechanism A is the **connected** path: the node fetches from a registry and tags
the result for the kubelet. It is verified, and it is what
`.github/workflows/e2e-detonation.yaml` exercises against real k3s containerd on
every run.

Mechanism B is the **air-gapped** path: the image is built elsewhere, shipped as
a tarball, and loaded locally with no registry reachable. It is the case this
document is really about, and **it has not been executed against a real node.**
There is no k3s, no containerd and no built image on the development host.

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
docker build -f agent/Dockerfile -t registry.internal/srek3s-agent:0.1.0 .
docker build -f Dockerfile     -t registry.internal/srek3s-sentinel:0.1.0 .

# Save and import.
docker save registry.internal/srek3s-agent:0.1.0    -o /tmp/srek3s-agent.tar
docker save registry.internal/srek3s-sentinel:0.1.0 -o /tmp/srek3s-sentinel.tar

sudo k3s ctr images import /tmp/srek3s-agent.tar    --all-namespaces
sudo k3s ctr images import /tmp/srek3s-sentinel.tar --all-namespaces
```

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

## Apply

```bash
# kustomize preserves the resource order in deploy/kustomization.yaml: namespace,
# then RBAC, then the workloads. A Role applied before its Namespace exists fails
# with "namespace not found", which is why that file is ordered by hand rather
# than alphabetically.
kubectl apply -k deploy/

kubectl -n srek3s-system rollout status deployment/srek3s-sentinel --timeout=120s
kubectl -n srek3s-system rollout status deployment/srek3s-agent    --timeout=120s
```

## Confirm the hardening actually took effect

```bash
# The effective UID must be 10001. This is the same assertion the CI container
# smoke test makes, and it is the one field a manifest typo would silently lose:
# `runAsNonRoot: true` with no `runAsUser` runs as the image's user, and a
# Dockerfile edit that dropped USER would change that with no manifest diff.
kubectl -n srek3s-system exec deploy/srek3s-sentinel -- id -u   # => 10001

# The read-only root filesystem is observable: the sentinel writes only to /tmp,
# so an attempt to write elsewhere must fail.
kubectl -n srek3s-system exec deploy/srek3s-sentinel -- sh -c 'touch /root/x'  # must fail

# And the RBAC must be read-only. A rejected write is the proof; a successful one
# is an incident.
kubectl -n srek3s-system exec deploy/srek3s-sentinel -- \
  sh -c 'wget -qO- --post-data="" http://localhost:6443/api/v1/namespaces/default/pods'
# => a 403 with "forbidden: ... cannot create resource"
```

## Rollback

```bash
# The Sentinel holds no cluster write authority, so rollback is a delete and a
# re-apply. Nothing outside the namespace needs reverting, which is the property
# that makes a rollback this cheap.
kubectl delete -k deploy/

# Confirm no state survives: the sentinel writes to /tmp only, and the emptyDir is
# per-pod, so there is nothing to clean up on disk.
kubectl -n srek3s-system get pvc   # must be empty
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
