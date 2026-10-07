# srek3s Helm chart

Installs the SREK3S zero-trust incident response agent: the Go Sentinel
(read-only watcher) and the Python triage agent, with RBAC, NetworkPolicies,
and the scrubber ConfigMap.

## Install

```bash
helm install srek3s deploy/helm/srek3s -n srek3s-system --create-namespace
```

With default values this renders the same objects as
`kubectl kustomize deploy/base`. No Helm-managed labels are added, so the
render stays comparable to the static manifests.

## Overrides

API server CIDR (when your control plane sits outside k3s/kubeadm defaults):

```bash
helm install srek3s deploy/helm/srek3s -n srek3s-system \
  --set networkPolicy.apiServerCidrs[0]=10.100.0.0/16
```

Watch a different namespace (you must also grant the read verbs there with a
RoleBinding back to this release's ServiceAccount; never use a ClusterRole):

```bash
helm install srek3s deploy/helm/srek3s -n srek3s-system \
  --set sentinel.watchNamespace=payments
```

Pinned images:

```bash
helm install srek3s deploy/helm/srek3s -n srek3s-system \
  --set images.sentinel.repository=ghcr.io/duckiec/srek3s-sentinel \
  --set images.sentinel.tag=sha-abc123
```

## Monitoring

The Sentinel serves Prometheus metrics on `:9090/metrics`. Ingress stays
deny-by-default; open it from your monitoring namespace:

```bash
helm install srek3s deploy/helm/srek3s -n srek3s-system \
  --set monitoring.namespace=monitoring
```

## Operator-created resources (not in this chart)

- `srek3s-secrets` Secret with `GEMINI_API_KEY`, `NVIDIA_API_KEY`,
  `TELEGRAM_API_KEY`, `TELEGRAM_CHAT_ID` (all optional).
- Tier-1 patches require a real GitOps checkout mounted at `/manifests`.
  The chart ships the fail-closed `emptyDir`, so every incident escalates
  to Tier-2 until you replace it.
