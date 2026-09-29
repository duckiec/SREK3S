# Offline image import into k3s

**Status: written, unverified.** AGENTS.md §5.4 requires a gate be reported as a blocked
dependency rather than checked on an unverified assumption, and this one cannot be verified on
the development host — there is no k3s, no containerd, and no built image here. ROADMAP
`3.6.6` stays open until the commands below are run against a real node and the output pasted
into that box.

The commands are written because the *reasoning* is settled and getting it wrong is expensive:
the failure mode of a wrong import path is a node that pulls from a registry it cannot reach, and
in an air-gapped cluster that surfaces as `ImagePullBackOff` with no local image and no obvious
cause.

## Why the default import is not enough

`k3s ctr images import` puts an image into the **k3s containerd namespace**, which is *not* the
`k8s.io` namespace that kubelet actually reads from. An image imported without the namespace
argument lands somewhere the kubelet never looks, and `kubectl get pods` reports
`ImagePullBackOff` even though the image is present on the node. This is the single most common
failure in this workflow and it looks like a network problem rather than a namespace problem.

`--all-namespaces` avoids the question. It is the right choice here for two reasons: this is a
first-boot install where no image has been pulled yet, so there is no existing namespace to
conflict with; and a repeated import into a running cluster should use the explicit namespace
below instead, so the operation is visible and idempotent rather than scattering copies.

## First boot, before any pod has pulled an image

```bash
# Build the two images locally, tagged for the internal registry the manifests
# reference. The tags must match deploy/sentinel.yaml and deploy/agent.yaml exactly:
# a tag mismatch produces ImagePullBackOff, not a manifest error.
docker build -f agent/Dockerfile -t registry.internal/srek3s-agent:0.1.0 .
docker build -f Dockerfile     -t registry.internal/srek3s-sentinel:0.1.0 .

# Save and import.
docker save registry.internal/srek3s-agent:0.1.0    -o /tmp/srek3s-agent.tar
docker save registry.internal/srek3s-sentinel:0.1.0 -o /tmp/srek3s-sentinel.tar

sudo k3s ctr images import /tmp/srek3s-agent.tar    --all-namespaces
sudo k3s ctr images import /tmp/srek3s-sentinel.tar --all-namespaces
```

## Repeated import into a running cluster

```bash
# Explicit namespace, no --all-namespaces. Idempotent, and the images land exactly
# where kubelet looks.
sudo k3s ctr images import /tmp/srek3s-agent.tar    --namespace k8s.io
sudo k3s ctr images import /tmp/srek3s-sentinel.tar --namespace k8s.io
```

## Verify before deploying

```bash
# Both images must be present AND unqualified - no registry host prefix, because
# the manifests reference them as registry.internal/... and the local tag is
# unqualified. This is the check that catches a namespace mistake.
sudo k3s ctr images ls --namespace k8s.io | grep srek3s
```

Expected, and nothing else:

```
registry.internal/srek3s-agent:0.1.0    application/vnd.docker.distribution.manifest.v2+json    ...
registry.internal/srek3s-sentinel:0.1.0 application/vnd.docker.distribution.manifest.v2+json    ...
```

A `docker.io/library/...` or `sha256:...` line means the import did not register the tag the
manifests ask for. Fix by tagging explicitly before importing:

```bash
sudo k3s ctr images tag registry.internal/srek3s-agent:0.1.0 docker.io/library/srek3s-agent:0.1.0
```

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
# smoke test makes, and it is the one field a manifest typo would silently lose -
# `runAsNonRoot: true` with no `runAsUser` runs as the image's user, and a
# Dockerfile edit that dropped USER would change that without any manifest diff.
kubectl -n srek3s-system exec deploy/srek3s-sentinel -- id -u   # => 10001

# The read-only root filesystem is observable: the sentinel writes only to
# /tmp, so an attempt to write elsewhere must fail.
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

# Confirm no state survives: the sentinel writes to /tmp only, and the emptyDir
# is per-pod, so there is nothing to clean up on disk.
kubectl -n srek3s-system get pvc   # must be empty
```

## Not covered here

- **HA control plane**: with more than one server node, run the import on every node. The
  commands above are per-node and are not replicated by k3s.
- **Image signing**: `k3s` is started here without `--disable-image-defaults` and without a
  containerd registry configuration, so no signature is verified. An air-gapped production
  install should configure `mirrors` in `/etc/rancher/k3s/registries.yaml` with a
  `configs` block, and set `--disable=image` only after the local import path is proven.
- **Version skew**: this covers the `0.1.0` tags in the current manifests. A release that bumps
  the pipeline's `checksum` annotation but not the image tag would import the old image and
  report success, which is why the tag is a build-time `-ldflags "-X main.version=..."` stamp
  rather than a hand-maintained string.
