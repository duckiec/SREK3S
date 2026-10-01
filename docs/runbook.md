# SREK3S Operator Runbook

For the human on call, or the agent reading this on your behalf. It covers the
four things an operator actually does with this system: deploy it, watch it,
interpret what it escalates, and review what it proposes.

Two claims are made here that are worth checking rather than taking on trust,
and both are checked in [§5](#5-the-no-autofix-guarantee): **the Sentinel cannot
write to your cluster**, and **the agent cannot write to your cluster**. They are
enforced at three independent layers, and no configuration turns either off.

---

## 1. Deploying the Sentinel

The deployment set is `deploy/`, ordered by `kustomization.yaml`.

```bash
kubectl apply -k deploy/
```

**Do not apply the files individually, and do not reorder them.** Kustomize does
not order resources, so `kubectl apply` sends them in the order the API receives
them. `namespace.yaml` must land before `rbac.yaml`, because the Role and
ServiceAccount the Deployment references must exist before it is admitted; and
`rbac.yaml` must land before `sentinel.yaml`, because a Deployment referencing a
missing ServiceAccount stays Pending with an error that does not mention RBAC at
all. The comment in `deploy/kustomization.yaml` says this too, but the failure
mode is opaque enough to be worth repeating.

### What gets deployed

| File | Contents |
|---|---|
| `deploy/namespace.yaml` | The `srek3s-system` namespace |
| `deploy/rbac.yaml` | The ServiceAccount and a read-only `Role` — see [§5](#5-the-no-autofix-guarantee) |
| `deploy/sentinel.yaml` | The Go watcher (pods, events) |
| `deploy/agent.yaml` | The Python triage service |
| `deploy/service.yaml` | The agent's ClusterIP, `srek3s-agent:8000` - the Sentinel's default `-agent-url` |

The image tags in the manifests are the placeholders
`registry.internal/...:0.1.0`. There is deliberately **no kustomize `images:`
block**: an override there would hide the tag that is actually deployed from the
manifest the hardening tests parse. The release pipeline rewrites the tag in the
committed file, so what is tested is what ships.

Build them with:

```bash
docker build -t registry.internal/srek3s-agent:0.1.0    -f agent/Dockerfile .
docker build -t registry.internal/srek3s-sentinel:0.1.0 -f cmd/sentinel/Dockerfile .
```

Both take the **repository root** as their build context. A context of
`agent/` or `cmd/sentinel/` fails at the `COPY`, because the module and the
packages being compiled live outside those directories.

### RBAC is namespace-scoped, and that is deliberate

**`deploy/rbac.yaml` grants the Sentinel a `Role` in `srek3s-system` and
nowhere else.** A `Role` is namespaced by definition, and a `RoleBinding` in
`srek3s-system` can only reference a `Role` in `srek3s-system`. There is no
`ClusterRole` and no `ClusterRoleBinding` in this set, and adding one would be
the single highest-severity change available to this codebase.

The reason is blast radius. A watcher's entire authority is the set of things it
can read, and a cluster-wide grant reads every namespace, including the ones that
hold other people's secrets. Scoping the grant to one namespace makes the blast
radius of a compromised Sentinel equal to that namespace rather than the cluster.

**The consequence you must act on:** the Sentinel is authorised to read only
`srek3s-system`. If you set `-namespace` to anything else — `default`,
`payments`, your application's namespace — **it will be refused**, and the
failure looks like a hang rather than an error: the informer retries an
unauthorised `LIST`, and the symptom is no incidents rather than a permission
message.

To monitor a namespace, apply the same `Role` and a `RoleBinding` into **that**
namespace, referring to the ServiceAccount in `srek3s-system`:

```bash
NS=payments   # the namespace you actually want to watch

kubectl -n "$NS" create role srek3s-sentinel \
  --verb=get,list,watch --resource=pods,pods/log,events
kubectl -n "$NS" create role srek3s-sentinel \
  --verb=get,list,watch --api-group=apps --resource=deployments,replicasets

kubectl -n "$NS" create rolebinding srek3s-sentinel \
  --role=srek3s-sentinel \
  --serviceaccount=srek3s-system:srek3s-sentinel
```

Then confirm it before trusting it:

```bash
kubectl auth can-i list pods -n "$NS" \
  --as=system:serviceaccount:srek3s-system:srek3s-sentinel   # must be: yes
kubectl auth can-i create pods -n "$NS" \
  --as=system:serviceaccount:srek3s-system:srek3s-sentinel   # must be: no
```

Two things to keep straight. First, **read only**: the verbs above are
`get,list,watch` and nothing else, and the second command is the one that
matters — it is the difference between a watcher and an actor. Second, **the
RoleBinding lives in the target namespace and points back at `srek3s-system`**:
that keeps a single ServiceAccount, and a single identity to audit, while the
grant itself stays narrow. Covering many namespaces means many narrow Roles to
review, not one wide Role.

Do this once per namespace you want watched. There is no wildcard form, and that
is the intended shape: every namespace in the grant is one somebody chose to put
this thing in.

### The agent's manifest root ships empty

`deploy/agent.yaml` sets `SREK3S_MANIFEST_ROOT=/manifests` and mounts a volume
there, and **as deployed that volume is an empty `emptyDir`**. The agent therefore
cannot read a target manifest, every incident escalates to Tier-2 under I-B2, and
no patch is ever proposed unverified.

That is the intended safe state, not a fault — but it looks exactly like a
working setup. To get Tier-1 patches, replace the `manifests` volume with the
GitOps checkout your pipeline actually applies (a PVC, or an init container that
clones the repository) and set `SREK3S_TARGET_MANIFEST` to a repo-relative path
inside it. Until you do, 100% Tier-2 is the design working.

### Configuration

The Sentinel takes six flags, each also settable by environment variable:

| Flag | Env | Default | Notes |
|---|---|---|---|
| `-namespace` | `WATCH_NAMESPACE` | *(empty — watches all)* | **Set this.** See below. |
| `-agent-url` | `SREK3S_AGENT_URL` | `http://srek3s-agent:8000` | Base URL only. No path - the emitter appends `/v1/incidents` itself. The default is the `srek3s-agent` Service in `deploy/service.yaml`. |
| `-workers` | — | pool default | Fixed-size worker pool. Not a queue. |
| `-log-level` | `LOG_LEVEL` | `info` | |
| `-kubeconfig` | — | in-cluster | For running outside the cluster. |
| `-version` | — | — | Prints version and exits. |

> **`-namespace` empty means every namespace in the cluster.** That is the
> default, and it is not what you want in production. Scope the Sentinel to the
> namespaces it is meant to watch. This is the same defect that cost a milestone
> earlier: an option applied after the namespace scope silently rebuilt the
> informer factory *without* the scope, and the Sentinel quietly widened back to
> watching everything. The fix was to build the factory once, after every option
> has run.

The agent reads three environment variables:
`SREK3S_LOG_LEVEL`, `SREK3S_MANIFEST_ROOT` (where manifests live for patch
generation), and `SREK3S_SANDBOX`.

### Verifying the deployment

```bash
kubectl -n srek3s-system get pods
kubectl -n srek3s-system logs -l app.kubernetes.io/part-of=srek3s -c sentinel
kubectl auth can-i --as=system:serviceaccount:srek3s-system:srek3s-sentinel \
  create pods -n srek3s-system
```

The last command **must print `no`**. If it prints `yes`, the read-only
guarantee is broken and this runbook's central claim is false. Check it on every
upgrade rather than trusting that it was once true.

---

## 2. Observing the logs

The Sentinel emits structured JSON, one object per line.

### Startup

A healthy start looks like this — a startup line naming the scope it is actually
watching, then periodic stats:

```json
{"msg":"startup","watch_namespace":"srek3s-system","workers":8,...}
{"msg":"stats","watcher_emitted":7,"watcher_dropped":0,"watcher_queue_depth":0,
 "dedup_admitted":7,"dedup_suppressed":5,"dedup_size":3,"processed":7,
 "failed":0,"in_flight":0}
```

**Read `watch_namespace` in that startup line every time.** It is the cheapest
possible check that the scope is what you intended, and it is the number that has
been wrong before.

### The stats line, field by field

This is the health dashboard. Every field is a number that can only go wrong, and
each one has a distinct meaning:

| Field | Healthy | What a non-zero value means |
|---|---|---|
| `watcher_emitted` | growing | Informer observed a failing container. |
| `watcher_dropped` | **0** | Egress queue full; **an incident was lost**. Investigate. |
| `watcher_queue_depth` | near 0 | Sustained depth means the worker pool cannot keep up. |
| `dedup_admitted` | ≤ `emitted` | Incidents that passed deduplication. |
| `dedup_suppressed` | any | Correct duplicates. **High *and* falling with no new incidents is a bug** — see below. |
| `failed` | 0 | Incidents that could not be dispatched. Read the error field. |
| `in_flight` | small | Bounded by `workers`. |

### `dedup_suppressed` is not automatically good news

Deduplication keys on `<podUID>/<containerName>:<restartCount>`. A high
suppression count usually means a steady-state crash loop being correctly
collapsed into one incident. It has also meant a real defect: a transient
`Terminated` state claiming the key for the same restart count, so the
`CrashLoopBackOff` behind it was **suppressed as a duplicate and never
reported at all**.

> **Symptom to watch for:** a container is visibly crash-looping in
> `kubectl get pods`, the Sentinel is running, and nothing has been dispatched
> for it. That is this class of bug. The dedup cache is doing exactly what it was
> built to do, and the observable result is that a real incident disappears.

### Reading a single dispatch failure

```json
{"msg":"dispatch failed","incident":"ns/pod:container",
 "kind":"OOMKilled","error":"..."}
```

`error` values worth recognising:

| Error | Meaning | Action |
|---|---|---|
| `agent unreachable` | The agent is down, or `-agent-url` is wrong. | Check the agent pod. Check for a **doubled path** — see below. |
| `failure kind has no wire representation` | The watcher produced a state with no `reason` the contract admits. | A watcher filter is missing. This is fail-closed and correct; report it. |
| `log fetch failed` / `event fetch failed` | Watch-only, apiserver slow. | Dispatch continues **without** logs or events. The incident is still raised. |

> **`-agent-url` must be a base URL with no path.** The emitter appends
> `/v1/incidents`. Supplying `-agent-url http://host/api/v1/triage` produces
> `/api/v1/triage/v1/incidents` and a 404 — and because the capture proxy records
> exchanges whatever the upstream status, the 404 is visible only as a status
> code in a line nobody reads. There is now an automated check for this.

---

## 3. Interpreting a War-Room dispatch (Tier-2)

A Tier-2 response means **a human is needed**. It is not a failure of the system;
it is the system correctly refusing to guess.

### The decisive field

```json
{"blast_radius_tier":"TIER_2_ARCHITECTURAL","incident_id":"inc_...",
 "classification":"RESOURCE_EXHAUSTION","status":"TRIAGED","patch_validated":false}
```

**`git_patch` is always the empty string at Tier-2.** That is invariant **I-B1**,
enforced in the Pydantic model at construction: `TIER_2_ARCHITECTURAL` implies an
empty patch and `patch_validated: false`. A Tier-2 response cannot carry a
speculative cluster change downstream. If you ever see a Tier-2 response with a
patch, that is an **I-B1 violation** — treat it as a critical defect and report
it.

### Why it escalated

Routing is **deterministic and deny-by-default**: anything not *provably* Tier-1
is Tier-2. The escalation reasons, in the order you are most likely to hit them:

| Reason | Meaning | What to do |
|---|---|---|
| `no manifest provider configured` | The agent has no manifest to patch. Expected outside a GitOps checkout. | Point `SREK3S_MANIFEST_ROOT` at one. |
| `patch failed structural validation` | The generated diff did not survive YAML AST checks. | A fixture or generator bug. Report it. |
| `patch failed git apply --check` | The diff did not apply to the target manifest. | A fixture or generator bug. Report it. |
| `patch would change more than the target key` | The diff touched something beyond the memory limit. | Correct refusal — the model produced a broader change than intended. |
| `model output was not schema-valid` | Freeform or non-JSON output. | **I-B4**: a fatal validation failure. There is no partial parse and no regex scrape of markdown. Correct. |

### The five things in the bundle that earn their place

Every dispatch carries an RCA and an evidence bundle. In priority order:

1. **`reason` and `exit_code`** — `OOMKilled` with 137 is SIGKILL from the memory
   cgroup. A different non-zero exit is an application error, and it routes
   differently.
2. **`resource_limits.memory_limit`** — the number the fix will change, and the
   number to sanity-check. `null` on an OOM is itself a signal.
3. **`restart_count`** and **`previous_reason`** — whether the fault recurred or
   terminated once.
4. **`detection_latency_ms`** — time from the kubelet reporting the fault to the
   Sentinel dispatching.
5. **`redaction_report.rules_triggered`** — which scrubber rules fired, and how
   many times. If this is zero on an incident with substantial logs, the scrubber
   may not have run.

### What the RCA will not tell you

It will not tell you the workload's *peak* memory use, and this is deliberate
rather than an omission. The contract carries the exit code, the configured
limit, and the restart count. It does **not** carry a peak-RSS sample, so an RCA
asserting "peak allocation during the load cycle exceeded the limit" would be
stating something the telemetry does not contain.

That distinction is not pedantic. `$(head -c N /dev/zero | tr ...)` in a shell
buffers the entire pipeline result before the shell can assign it, so a payload
of *N* bytes peaks at a *multiple* of *N* — a 90 MiB payload was measured peaking
above 128 MiB, and the container was OOMKilled under a 128Mi limit. Sizing a
remediation on the payload rather than the peak produces a fix that does not fix
anything.

> If you need peak reasoning in an RCA, that requires a memory sample in the
> incident contract. It does not exist today.

---

## 4. Reviewing a Tier-1 GitOps PR

A Tier-1 response carries a unified diff in `git_patch`. **The Sentinel has not
applied it, and neither has the agent.** It is a proposal for a human to review
and merge through whatever GitOps controller you run.

### The checklist

**1. It passes its own gates — then check them yourself.**

```bash
git apply --check remediation.patch     # against the target manifest
git apply remediation.patch
python -c "import yaml,sys; yaml.safe_load(open('target.yaml'))"
```

`git_patch` already came through `git apply --check` and a YAML AST check before
being reported as `patch_validated: true`. Re-run them anyway: `git apply`
*tolerates* a wrong start offset when the content matches, so the structural check
catches what git forgives and git catches what a line diff would miss. Both halves
are needed.

**2. It changes one line, and it is the line you expect.**

```bash
git diff --stat
git diff
```

The intended mutation is a single key:

```diff
-              memory: 64Mi
+              memory: 128Mi
```

Reject the PR if it touches more. A diff that changes a second key is either a
model failure or the I-B2 gate having been bypassed, and both are worth a
conversation before merge.

**3. The new limit is defensible against actual demand.**

This is where [§3](#3-interpreting-a-war-room-dispatch-tier-2)'s peak-versus-payload
warning bites. A limit raised "just in case" is how a cluster ends up with
pods that cannot be scheduled. Ask what the workload's real peak is — from its
own metrics, not from the payload size in its script.

**4. The RCA's stated cause matches the diff's actual change.**

The diff is the machine-checkable artifact and the RCA is the human-readable one.
If the RCA says "insufficient memory" and the diff changes a CPU limit, the RCA is
describing a different incident from the one being fixed. The goldens in
`tests/fixtures/expected/` pin both shapes and will catch a drift.

### What a correct Tier-1 PR looks like end to end

A crash-looping `OOMKilled` pod → an RCA naming exit 137, the pod, and the
configured limit → a one-line diff raising that limit → `git apply --check`
passes → you review, merge, and the GitOps controller syncs → the verification
loop observes the workload holding uptime above `container_uptime_seconds_min`
with zero OOM kills → `VERIFIED` / `CLOSE_INCIDENT`.

That last step exists because a diff that applies is not a fix that worked. If
the workload is still OOMKilled after the merge, the verdict is `UNRESOLVED` with
cause `OOM_KILLED` and the action is `PROMOTE_TO_TIER_2` — a human, again, and
now with evidence that the automated remediation was wrong.

---

## 5. The No-Autofix Guarantee

> **No configuration flag, environment variable, manifest field or API parameter
> in SREK3S enables the Sentinel or the agent to write to a cluster.**
>
> There is no "autofix mode". There is no `--allow-write`. There is no
> `SREK3S_AUTOFIX=true`. If you are looking for the switch that lets this system
> change your cluster, it does not exist, and adding one would fail the build.

This is the load-bearing safety property of the whole system, so it is enforced
at three independent layers. Any one of them would block a write; all three must
be defeated simultaneously, which is why this is worth stating as a fact rather
than a policy.

### Layer 1 — The Sentinel's ServiceAccount has no write verbs

`deploy/rbac.yaml` defines a `Role` whose every rule is an explicit enumeration of
read verbs:

```yaml
- apiGroups: [""]
  resources: ["pods", "pods/log"]
  verbs: ["get", "list", "watch"]
```

The verbs are **enumerated, never wildcarded**, and the comment in the manifest
says why: a wildcard would cover future write verbs by accident, so the
enumeration is the control. The same `["get", "list", "watch"]` applies to
`events`, and to `deployments`/`replicasets` in `apps`.

This is enforced by `TestSentinelRoleGrantsNoMutatingVerb` in
`internal/deploy/rbac_hardening_test.go`, which **parses the manifest and fails
the build** if a mutating verb appears. It is a test over the YAML, not a
convention.

Verify it at any time, against your live cluster:

```bash
kubectl auth can-i --as=system:serviceaccount:srek3s-system:srek3s-sentinel \
  create pods -n srek3s-system       # -> no
kubectl auth can-i --as=system:serviceaccount:srek3s-system:srek3s-sentinel \
  patch pods -n srek3s-system        # -> no
kubectl auth can-i --as=system:serviceaccount:srek3s-system:srek3s-sentinel \
  list pods -n srek3s-system         # -> yes
```

### Layer 2 — The agent holds no cluster credential at all

The agent is not merely restricted; it is **not issued a kubeconfig**. ARCH §3
marks the agent box a trust boundary and §2 records that it holds no cluster
credential. It reaches the filesystem to read manifests for patch generation and
nothing else. There is no verb to widen, because there is no identity.

`agent/verify.py` makes this structural rather than aspirational. Its only
capability is `ObservationReader.read`, a one-method `Protocol` that returns a
value. It has no write verb, no Kubernetes client, no subprocess, no socket and no
filesystem access — and `TestZeroWrites` asserts that by walking the module's
**AST** for forbidden imports and for any mutating verb in a call-target or
attribute position.

### Layer 3 — The response schema cannot express a write

Even if both of the above were bypassed, there is nowhere to put a write.

- **I-B1** (enforced in `agent/models.py`): `blast_radius_tier ==
  "TIER_2_ARCHITECTURAL"` implies `git_patch == ""` and `patch_validated ==
  false`. A Tier-2 response *cannot carry* a patch; this is a Pydantic
  model-validator at construction, not a convention.
- **I-B5**: neither contract contains any field capable of expressing a cluster
  write verb. The only mutating artifact in the system is a unified diff, which
  is text for a human to review — not a command, and not an API call.
- **I-B4**: freeform or non-JSON model output is a **fatal** validation failure.
  There is no partial parse, no best-effort recovery, and no regex scrape of
  markdown. A model cannot smuggle an instruction through the schema, because the
  schema is enforced before anything downstream sees the value.

### The one legitimate write path, and why it is not a loophole

The Sentinel writes to **its own** process: logs, and nothing else. The agent
writes to **its own** process: the War-Room dispatch it emits. Neither writes to a
cluster.

The only path by which a change reaches a cluster is a human merging a reviewed
unified diff through a GitOps controller. That is the design, not a workaround:
the automation proposes, a human disposes.

### If you need this guarantee to be true

Run the check. Do not read it and believe it:

```bash
# Layer 1 - the RBAC manifest has no write verbs.
go test ./internal/deploy/ -run TestSentinelRoleGrantsNoMutatingVerb -v

# Layer 2 - the verification loop cannot write.
pytest agent/tests/test_verify.py -k ZeroWrites -v

# Layer 2, at runtime rather than statically.
pytest agent/tests/test_verify.py -k RuntimeTripwire -v
```

> **Read the output, not the exit status.** `go test -run` with a name that
> matches nothing exits **0** and prints `[no tests to run]`. A typo in a test
> filter is therefore a green result proving nothing — which is the failure mode
> this runbook has now hit twice, once in `dedup_suppressed` above and once
> writing this very section. The correct name is
> `TestSentinelRoleGrantsNoMutatingVerb`; note the singular. `deploy/rbac.yaml`
> refers to it by a name that does not exist.

---

## 6. When something is wrong

| Symptom | First thing to check |
|---|---|
| Sentinel running, no incidents, pod visibly crash-looping | `dedup_suppressed` in the stats line — [§2](#2-observing-the-logs) |
| `dispatch failed … agent unreachable` | The agent pod; then `-agent-url` for a doubled path |
| Every incident is Tier-2 with `no manifest provider` | `SREK3S_MANIFEST_ROOT` is unset or empty |
| Sentinel watching the wrong namespaces | The `watch_namespace` startup field, [§1](#1-deploying-the-sentinel) |
| `watcher_dropped` above zero | The egress queue overflowed and **an incident was lost** |
| Canary fails in CI on something that passes locally | Host/CI divergence — see `docs/lessons-learned.md` §3, §15, §20 |

### Where the history lives

`docs/lessons-learned.md` records every defect found between Milestone 1 and 4.4,
in the format each one deserves rather than the format that flatters it. It is the
right place to look before concluding that something is novel — several "new"
failures in this project have turned out to be a known trap met again.
