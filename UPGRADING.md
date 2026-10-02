# Upgrading

This file documents changes that require an action from an operator. A change
that applies cleanly is not a change that works, and the difference has bitten
this project before — see the second entry.

---

## `srek3s-sentinel` must be deleted before upgrading

**Applies to:** any installation upgrading to a revision containing
`srek3s.io/component: sentinel` in the Sentinel's pod labels.

**Why.** Kubernetes makes `Deployment.spec.selector` **immutable after creation**.
This revision adds a discriminator label to the Sentinel's selector so that it
identifies its own pods and only its own pods:

```yaml
selector:
  matchLabels:
    app.kubernetes.io/name: srek3s-sentinel
    srek3s.io/component: sentinel      # added
```

Applying the new manifests over an existing Sentinel cannot succeed. The
apiserver rejects it:

```
The Deployment "srek3s-sentinel" is invalid: spec.selector: Invalid value:
  {"matchLabels":{"app.kubernetes.io/name":"srek3s-sentinel",
  "srek3s.io/part-of":"srek3s"}}: field is immutable
```

**The failure is loud**, which is the good case: the apply reports an error and
the old ReplicaSet keeps running. It does not silently half-deploy.

### What to run

```sh
kubectl -n srek3s-system delete deployment srek3s-sentinel
kubectl apply -k deploy/
```

The delete is safe. The Sentinel holds no state that is not either
reconstructible or on the agent's side: its informer rebuilds its watch from the
apiserver on start, and its dedup cache is per-process by design (which is why
`replicas: 1`). Detection resumes within one resync interval. **Incidents raised
during the gap are missed** — do this in a maintenance window, or accept the gap
knowingly.

A fresh cluster, including the CI e2e run, is unaffected: there is no existing
Deployment to conflict with.

### Why the change was made

The Sentinel's selector was `app.kubernetes.io/name: srek3s-sentinel`, and the e2e
fixtures impersonate exactly that label so the agent's ingress NetworkPolicy
admits them. The selector therefore matched three components' pods, and
`kubectl logs deployment/srek3s-sentinel` returned the **capture proxy's**
stdout. An assertion about the Sentinel's namespace scoping read the wrong
component and reported a confident, specific, wrong answer.

The new label is the one thing a fixture cannot claim without declaring itself to
be the Sentinel. Impersonating a *network identity* and claiming to *be a
workload* are different acts and are now expressed by different labels.

`agent/tests/test_e2e_incluster_manifests.py` asserts this property against the
rendered manifests, so a future fixture that collides fails offline rather than in
a twenty-minute CI run.

---

## A note on `commonLabels`

Earlier revisions used `commonLabels` in `deploy/kustomization.yaml`. It is sugar
for `labels: [{includeSelectors: true}]`, and `includeSelectors: true` rewrites
**every** selector in the rendered output — including `NetworkPolicy` selectors,
which are a security boundary.

It caused two defects that raw-file tests could not see, because the files were
correct and the *render* was not:

1. The agent Service's selector gained a label the raw files did not carry,
   producing a Service with no ready endpoints behind a perfectly healthy agent.
2. The agent's **ingress** rule gained a label the fixtures did not carry, so the
   e2e route probe was not admitted — and the leg that exists to prove the
   Sentinel can reach the agent could not reach the agent.

It was also *accidentally* hiding the selector collision described above: with
`part-of` injected into the Sentinel's selector, the fixtures no longer matched
it. Removing the injection did not create that bug. It uncovered one that had
been masked.

Nothing here requires action if you apply with `kubectl apply -k deploy/`. The
rendered selectors are now exactly what the files say.

**The rule, now asserted by a test:** a selector never depends on a transform. If
a selector needs a label, the file that owns the object writes it.