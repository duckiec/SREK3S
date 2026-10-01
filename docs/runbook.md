# SREK3S Operator Runbook

For the human on call, or the agent reading this on your behalf. It covers the
four things an operator actually does with this system: deploy it, watch it,
interpret what it escalates, and review what it proposes.

Two claims are made here that are worth checking rather than taking on trust,
and both are checked in [§5](#5-the-no-autofix-guarantee): **the Sentinel cannot
write to your cluster**, and **the agent cannot write to your cluster**. They are
enforced at three independent layers, and no configuration turns either off.

> **Before any of this:** run `make doctor`. It verifies the OS, architecture,
> Docker + buildx, Go, and a **3.11+** Python, and it distinguishes a stopped Docker
> daemon from one your user cannot reach — which are different problems that
> otherwise produce the same socket error. Then `make bootstrap` and `make test`.

---

## 1. Deploying the Sentinel

The deployment set is `deploy/base` (the production set, exposed as a directory so
an overlay can reference it without `--load-restrictor`). `make deploy` applies it
and waits for both rollouts:

```bash
make deploy
```

Equivalent by hand:

```bash
sudo kubectl apply -k deploy/base
```

**Every `kubectl` in this runbook needs `sudo`** on a k3s-installed host. The
kubeconfig k3s writes — `/etc/rancher/k3s/k3s.yaml` — is mode `0600` and
root-owned, so an unprivileged `kubectl` reports a permission error against the
kubeconfig rather than against the API. That is a host configuration fact, not a
manifest problem. (CI hits the same class of fact through the containerd socket;
see `docs/offline-install.md` Mechanism A.) On a cluster where your kubeconfig is
yours, drop the `sudo`.

**Do not apply the files individually, and do not reorder them.** Kustomize does
not order resources, so `kubectl apply` sends them in the order the API receives
them. `namespace.yaml` must land before `rbac.yaml`, because the Role and
ServiceAccount the Deployment references must exist before it is admitted; and
`rbac.yaml` must land before `sentinel.yaml`, because a Deployment referencing a
missing ServiceAccount stays Pending with an error that does not mention RBAC at
all. The comment in `deploy/kustomization.yaml` says this too, but the failure
mode is opaque enough to be worth repeating.

### Two committed states that read as "healthy"

Both are properties of the `deploy/` set as committed. One is a **real defect**; one
is the design working. Neither announces itself, which is the problem — the first is a
silent misconfiguration and the second a silent no-op, and both present as a quiet
cluster.

| | Committed state | What you see |
|---|---|---|
| **Watch scope vs grant** | `sentinel.yaml` sets `WATCH_NAMESPACE: ""` (all namespaces); `rbac.yaml` grants a `Role` in `srek3s-system` only | A cluster-wide `LIST` is unauthorised. The informer retries it. **No incidents and no error** — indistinguishable from a healthy cluster watching nothing. Fix in [the next section](#rbac-is-namespace-scoped-and-that-is-deliberate). Found by static analysis on 2026-10-01; **not yet reproduced at runtime.** |
| **Agent manifest root** | `agent.yaml` mounts `/manifests` as an `emptyDir`, and the default target `deploy/payments/checkout-api.yaml` does not exist in this repository | Every incident escalates to `TIER_2_ARCHITECTURAL` with `git_patch == ""`. **That is the design working** (invariant I-B2), not a fault — see [The agent's manifest root ships empty](#the-agents-manifest-root-ships-empty). |

The honest summary: **an in-cluster run of `deploy/` demonstrates the Tier-2
war-room path and the no-mutation guarantee. It cannot demonstrate a Tier-1 patch.**
Tier-1 is fully exercised offline against `tests/fixtures/` with real `git apply
--check`, so this is a wiring gap in the deployment, not a gap in the engine.

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
sudo docker build --platform linux/arm64 \
  -t registry.internal/srek3s-agent:0.1.0    -f agent/Dockerfile .
sudo docker build --platform linux/arm64 \
  -t registry.internal/srek3s-sentinel:0.1.0 -f cmd/sentinel/Dockerfile .
```

Both take the **repository root** as their build context. A context of
`agent/` or `cmd/sentinel/` fails at the `COPY`, because the module and the
packages being compiled live outside those directories.

**`sudo docker`, not `docker`.** On a host where your user is not in the `docker`
group and the socket is `srw-rw---- root:docker`, plain `docker` fails with
`permission denied while trying to connect to the docker API`. That group confers
root-equivalent control of the daemon, so `sudo docker …` is the recommended form
rather than a group membership to add. This is the same shape as the `sudo kubectl`
above: the failure is about the socket, not about anything SREK3S does.

**`--platform` matters and is easy to omit.** A local `arm64` image and a CI
`amd64` image are different artifacts, and a wrong-platform image reports the same
`ImagePullBackOff` as a missing one. `busybox:1.36.1` and the chaos fixtures do
publish `arm64` manifests, so those work without a multi-arch build; the two
SREK3S images have to be built for whichever node will run them. Registration into
the node's containerd namespace is `docs/offline-install.md`'s subject.

### RBAC is namespace-scoped, and that is deliberate

> **Read this before your first deploy, because `deploy/` ships in a state this
> section contradicts.** `deploy/sentinel.yaml` sets `WATCH_NAMESPACE: ""`, which
> asks the Sentinel to watch every namespace. The `Role` described here authorises
> it to read exactly one. Those two do not compose: the cluster-wide `LIST` is
> refused, and **the symptom is silence, not an error** — the process starts
> cleanly and reports nothing. Both halves must be fixed together; see
> "The consequence you must act on" below, which already contains the procedure.
>
> This mismatch was found by **static analysis on 2026-10-01 and has not been
> reproduced at runtime** — nothing was deployed when it was found. It is recorded
> as an open defect in `ARCHITECTURE.md` §2.1 and `ROADMAP.md` `ENV-2.1`, and
> neither the manifest nor this runbook has been changed to hide it.
>
> The reason no gate caught it is worth knowing, because you will write the next
> one: `TestSentinelRoleGrantsNoMutatingVerb` and
> `TestSentinelRoleGrantsWhatTheWatcherReads` both pass, and both are scoped to the
> namespace the `Role` lives in. Neither compares that namespace to the configured
> watch scope. Correct assertions over correct manifests, wrong in composition.

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
message. **Leaving it empty has the same effect for the opposite reason**: an
empty value means *every* namespace, and "every namespace" is unauthorised by a
`Role` that only covers one. Both directions of misconfiguration produce silence.

To monitor a namespace, apply the same `Role` and a `RoleBinding` into **that**
namespace, referring to the ServiceAccount in `srek3s-system`:

```bash
NS=payments   # the namespace you actually want to watch

sudo kubectl -n "$NS" create role srek3s-sentinel \
  --verb=get,list,watch --resource=pods,pods/log,events
sudo kubectl -n "$NS" create role srek3s-sentinel \
  --verb=get,list,watch --api-group=apps --resource=deployments,replicasets

sudo kubectl -n "$NS" create rolebinding srek3s-sentinel \
  --role=srek3s-sentinel \
  --serviceaccount=srek3s-system:srek3s-sentinel
```

Then set the Sentinel's scope to that same namespace — in `deploy/sentinel.yaml`,
`env: WATCH_NAMESPACE: "payments"`, or with `-namespace payments` when running
outside the cluster. **Setting the Role without setting the scope leaves the
Sentinel watching everything and being refused for all of it; setting the scope
without the Role leaves it watching one namespace and being refused for that
one.** The two edits travel together or not at all.

Confirm it before trusting it:

```bash
sudo kubectl auth can-i list pods -n "$NS" \
  --as=system:serviceaccount:srek3s-system:srek3s-sentinel   # must be: yes
sudo kubectl auth can-i create pods -n "$NS" \
  --as=system:serviceaccount:srek3s-system:srek3s-sentinel   # must be: no
sudo kubectl auth can-i list pods --all-namespaces \
  --as=system:serviceaccount:srek3s-system:srek3s-sentinel   # must be: no
```

The third command is the one that catches this defect specifically: it asks the
exact question `WATCH_NAMESPACE: ""` implies, and its answer is what the Sentinel
will find when it tries.

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
there, and **as deployed that volume is an empty `emptyDir`**. The chain from that
to what you will see:

1. `FileManifestProvider.read_manifest` cannot open the target file, so it returns
   `None` — its documented "cannot be read" answer. It returns rather than raises
   on purpose, so a content problem becomes a considered escalation instead of a
   `500`.
2. `triage._build_remediation_diff` returns at **step 2**, before any diff is
   synthesised.
3. The caller escalates. Every incident comes back `TIER_2_ARCHITECTURAL` with
   `git_patch == ""` and `patch_validated == false`.

That is the intended safe state — invariant **I-B2** failing closed — and **not a
fault. But it looks exactly like a working setup**, which is why the manifest and
this runbook both say so in those words.

**There is a second, independent way to land in the same state.** The default
target is `deploy/payments/checkout-api.yaml`, and that file **does not exist in
this repository**. So a populated `/manifests` with `SREK3S_TARGET_MANIFEST` left
unset produces byte-identical behaviour: 100% Tier-2. Fixing the volume alone does
not enable Tier-1.

To get Tier-1 patches, do both: replace the `manifests` volume with the GitOps
checkout your pipeline actually applies (a PVC, or an init container that clones
the repository) **and** set `SREK3S_TARGET_MANIFEST` to a repo-relative path that
exists inside it. Until then, 100% Tier-2 is the design working.

### Configuration

The Sentinel takes six flags, each also settable by environment variable:

| Flag | Env | Default | Notes |
|---|---|---|---|
| `-namespace` | `WATCH_NAMESPACE` | *(empty — watches all)* | **Set this, and set the matching `Role`.** See above. |
| `-agent-url` | `SREK3S_AGENT_URL` | `http://srek3s-agent:8000` | Base URL only. No path - the emitter appends `/v1/incidents` itself. The default is the `srek3s-agent` Service in `deploy/service.yaml`. |
| `-workers` | — | pool default | Fixed-size worker pool. Not a queue. |
| `-log-level` | `LOG_LEVEL` | `info` | |
| `-kubeconfig` | — | in-cluster | For running outside the cluster. |
| `-version` | — | — | Prints version and exits. |

> **`-namespace` empty means every namespace in the cluster.** That is the
> default, and it is not what you want in production — with the committed
> namespaced `Role` it is not even permitted. Scope the Sentinel to the
> namespaces it is meant to watch, and place a `Role` there. This is the same defect
> that cost a milestone earlier: an option applied after the namespace scope
> silently rebuilt the informer factory *without* the scope, and the Sentinel
> quietly widened back to watching everything. The fix was to build the factory
> once, after every option has run. **Reading `watch_namespace` in the startup log
> line is the only way to tell which of these you have.**

The agent reads three environment variables:
`SREK3S_LOG_LEVEL`, `SREK3S_MANIFEST_ROOT` (where manifests live for patch
generation), and `SREK3S_SANDBOX`.

### Verifying the deployment

```bash
sudo kubectl -n srek3s-system get pods
sudo kubectl -n srek3s-system logs -l app.kubernetes.io/part-of=srek3s -c sentinel
sudo kubectl auth can-i --as=system:serviceaccount:srek3s-system:srek3s-sentinel \
  create pods -n srek3s-system
```

The last command **must print `no`**. If it prints `yes`, the read-only
guarantee is broken and this runbook's central claim is false. Check it on every
upgrade rather than trusting that it was once true.

Add the converse check, because it is the one that catches the defect in
[§1](#two-committed-states-that-read-as-healthy):

```bash
sudo kubectl auth can-i list pods -n srek3s-system \
  --as=system:serviceaccount:srek3s-system:srek3s-sentinel   # must be: yes
sudo kubectl auth can-i list pods --all-namespaces \
  --as=system:serviceaccount:srek3s-system:srek3s-sentinel   # must be: no
```

A deployment that cannot read anything and a deployment that is refused are
different faults with the same symptom — silence — and only these two commands
distinguish them.

### NetworkPolicy enforcement: expected, not verified

`deploy/` ships two NetworkPolicies — `srek3s-sentinel` (egress restricted to the
apiserver, the agent, and DNS; no ingress rules at all) and `srek3s-agent-egress`
(ingress from the Sentinel only; egress to DNS only). On a k3s node they are
**expected** to be enforced.

Expectation, not guarantee, and the distinction is not pedantic. On k3s the
kube-router netpol controller runs **inside the `k3s server` process** rather than
as a separate pod, so **`kube-system` contains no NetworkPolicy controller pod**.
Looking for one and not finding it is the natural check, and it proves nothing:
a cluster with enforcement fully on and a cluster with enforcement fully off look
identical from `kubectl get pods -n kube-system`.

So do not report "no netpol controller pod, therefore the policies are inert", and
do not report "the policies are applied, therefore they are enforced". The only
check that distinguishes them is a **negative** one:

```bash
# From inside the agent pod, reach something its policy does not permit.
# Must FAIL. If it succeeds, egress is not being enforced here.
sudo kubectl -n srek3s-system exec deploy/srek3s-agent -- \
  python -c "import socket; socket.create_connection(('1.1.1.1', 443), 5)"
```

A permitted connection succeeding proves nothing, because it also succeeds with no
controller at all. That negative assertion is `ROADMAP.md` `ENV-2.6`, and it is
**open** — it has not been run on the `Fedora 44` / k3s v1.36.4 host this runbook's
environment section describes.

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

> **That last step is not wired into the running service.** The loop is
> implemented — `agent/verify.py`, 741 lines, and it is genuinely good code: the
> observation window is bounded twice, by a monotonic deadline *and* by a fixed
> iteration count, so a stepped clock cannot extend it, and `RequeueBudget` is
> deliberately not a rewindable counter. It is exercised by the sixty tests recorded
> in `ROADMAP.md` box `4.3.2`, plus a live-k3s leg that applied a real diff and
> observed both a `VERIFIED` and an `UNRESOLVED` verdict (`ROADMAP.md` box `4.3.4`).
>
> **But no production module imports it.** `main.py` and `triage.py` do not.
> `triage.py` emits `verification_policy` on the wire; nothing in the HTTP service
> reads that field. So today the verification verdict is **yours** to produce — the
> paragraph above describes the intended contract and the policy object you would
> evaluate, not a loop that runs while you watch. `ARCHITECTURE.md` §5.5.1,
> `ROADMAP.md` `ENV-2.7`.
>
> Nothing in §5's No-Autofix guarantee changes: a component nothing imports cannot
> acquire authority, and the write-incapability of `verify.py` is asserted
> independently.

---

## 5. The No-Autofix Guarantee

> **No configuration flag, environment variable, manifest field or API parameter
> in SREK3S enables the Sentinel or the agent to write to a cluster.**
>
> There is no "autofix mode". There is no `--allow-write`. There is no
> `SREK3S_AUTOFIX=true`. If you are looking for the switch that lets this system
> change your cluster, it does not exist, and adding one would fail the build.

> **One thing that DOES change behaviour, so it is called out rather than left
> for you to find:** an optional Gemini API key. With `srek3s-secrets` present, a
> model writes the *prose* of a Tier-2 explanation. It cannot change the tier,
> the patch, or any validation flag — the response schema it receives has no field
> for them. Without the key the system is unchanged and still fully operational.

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
sudo kubectl auth can-i --as=system:serviceaccount:srek3s-system:srek3s-sentinel \
  create pods -n srek3s-system       # -> no
sudo kubectl auth can-i --as=system:serviceaccount:srek3s-system:srek3s-sentinel \
  patch pods -n srek3s-system        # -> no
sudo kubectl auth can-i --as=system:serviceaccount:srek3s-system:srek3s-sentinel \
  list pods -n srek3s-system         # -> yes
# The read side has a ceiling too, and the ceiling is the point:
sudo kubectl auth can-i --as=system:serviceaccount:srek3s-system:srek3s-sentinel \
  list pods --all-namespaces         # -> no
```

That last line is the mirror of the three above. "No write verbs" is only half of
least privilege; the other half is that the grant does not reach further than the
watcher needs. A `ClusterRole` would pass all three write checks and fail that one
— which is why it is never the fix for the scope mismatch in
[§1](#rbac-is-namespace-scoped-and-that-is-deliberate).

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

Two notes so this citation is not read for more than it says. First, that module
is **not wired into the service** — nothing in `main.py` or `triage.py` imports it,
so the post-remediation loop is unreachable today ([§4](#4-reviewing-a-tier-1-gitops-pr)).
That makes the guarantee *stronger*, not weaker: a component nothing imports cannot
acquire authority. Second, the argument does not rest on `verify.py` alone. The
agent's `ServiceAccount` automount is `false` in `deploy/agent.yaml`, so it holds
no token to widen in the first place.

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
~/SREK3S/.venv311/bin/python -m pytest agent/tests/test_verify.py -k ZeroWrites -v

# Layer 2, at runtime rather than statically.
~/SREK3S/.venv311/bin/python -m pytest agent/tests/test_verify.py -k RuntimeTripwire -v
```

The `~/SREK3S/.venv311/bin/python -m` prefix is this host's requirement, not
incidental: the system `python3` here is 3.14.3 and running the suite under it is
not the same experiment.

> **Read the output, not the exit status.** `go test -run` with a name that
> matches nothing exits **0** and prints `[no tests to run]`. A typo in a test
> filter is therefore a green result proving nothing — which is the failure mode
> this runbook has now hit twice, once in `dedup_suppressed` above and once
> writing this very section. The correct name is
> `TestSentinelRoleGrantsNoMutatingVerb`; note the singular. `deploy/rbac.yaml`
> refers to it by a name that does not exist.
>
> **A fourth thing these commands do not prove.** All four of Layer 1's and Layer
> 2's checks pass on the manifests as committed, and the deployment still cannot
> watch anything, because `WATCH_NAMESPACE: ""` asks for a grant the `Role` does
> not confer. See
> [§1](#rbac-is-namespace-scoped-and-that-is-deliberate). "Every test green" is a
> statement about the tests, and the tests here are each about a different thing
> than the one that broke.

---

## 6. When something is wrong

| Symptom | First thing to check |
|---|---|
| **Sentinel running, no incidents, no errors, nothing happening anywhere** | **`kubectl auth can-i list pods --all-namespaces` as the Sentinel's SA.** If that is `no` and `watch_namespace` is empty, this is the scope/RBAC mismatch — [§1](#rbac-is-namespace-scoped-and-that-is-deliberate) |
| Sentinel running, no incidents, pod visibly crash-looping | `dedup_suppressed` in the stats line — [§2](#2-observing-the-logs) |
| `dispatch failed … agent unreachable` | The agent pod; then `-agent-url` for a doubled path |
| Every incident is Tier-2 with `no manifest provider` | `SREK3S_MANIFEST_ROOT` is unset or empty, **or** the `/manifests` volume is still an `emptyDir` — [§1](#the-agents-manifest-root-ships-empty). If you *have* wired a checkout, also check `SREK3S_TARGET_MANIFEST`: its default, `deploy/payments/checkout-api.yaml`, does not exist in this repository |
| Sentinel watching the wrong namespaces | The `watch_namespace` startup field, [§1](#1-deploying-the-sentinel) |
| `watcher_dropped` above zero | The egress queue overflowed and **an incident was lost** |
| Pods `ImagePullBackOff` on a local host | Image not built for `linux/arm64`, or not registered in `k8s.io` under the exact `registry.internal/...` name — [`docs/offline-install.md`](offline-install.md) |
| `kubectl` reports a kubeconfig permission error | k3s writes `0600` root-owned; use `sudo kubectl` |
| `permission denied while trying to connect to the docker API` | User is not in the `docker` group; use `sudo docker` |
| `black --check` fails on syntax the code obviously uses | Wrong interpreter. Use `~/SREK3S/.venv311/bin/python -m black`, not the system 3.14 |
| Canary fails in CI on something that passes locally | Host/CI divergence — see `docs/lessons-learned.md` §3, §15, §20. Now also: k3s **1.36** locally vs **1.29** in CI, with `enforce-version: latest` deciding which PSA rules apply |

### Where the history lives

`docs/lessons-learned.md` records every defect found between Milestone 1 and 4.4,
in the format each one deserves rather than the format that flatters it. It is the
right place to look before concluding that something is novel — several "new"
failures in this project have turned out to be a known trap met again.
