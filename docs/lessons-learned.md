# Lessons Learned

Engineering traps hit between Milestone 1 and Milestone 4, and what actually fixed
each one. Every entry is written against something that was observed or measured,
not against what was believed at the time. Where a commonly-repeated account of a
trap turned out to be wrong for this codebase, that is said plainly, because the
wrong version is the one that will be re-introduced.

Two themes run through the whole list, and they are worth stating first because
they caused more wasted cycles than any individual bug:

1. **A check that cannot fail is worse than a missing check.** It converts an
   untested claim into a falsely-proven one. This project produced that failure
   three times — see §8, §9 and §11.
2. **A diagnostic you cannot read is not a diagnostic.** For most of Milestone 4
   this was a hard constraint: CI logs returned HTTP 403 to the unauthenticated
   API, so step *names* were the finest signal available, and most of §12 exists
   because of it. **That constraint has since been lifted** — see the correction
   at the head of §12 — which makes the discipline it produced more valuable, not
   less: every hypothesis formed from a step name instead of a log was a guess, and
   the run that finally went green came from a hypothesis nobody had submitted.

Sections 1–13 were written at the end of Milestone 4.2 and record what was known
then. Sections 14–18 were added afterwards, covering defects found or closed
later — including the Milestone 4.2 ratification run itself. Where an entry is
reconstruction rather than verbatim record, it says so in place.

Sections 26–27 were added on 2026-10-01 and record the move to a `Fedora Linux 44`
/ `linux/aarch64` development host. **§26 is a reconstruction from reading two
manifests and an authorisation rule; it has not been reproduced at runtime, and it
says so in the first line of its own body rather than only here.** §27 is about a
platform transition rather than a defect, and is included because the *documenting*
of such a transition is where the wrong lesson gets written down. Neither section
alters any earlier entry: §27 exists specifically to say that the `windows/arm64`
records throughout this file are correct history and are kept.

---

## 1. The Quiet-Failure Trap (Scrubber & CI)

**Trap.** Asserting the *absence* of a secret trivially passes. An empty
`scrubbed_logs` array contains no planted credential, so "zero plaintext
survivals" is satisfied — while the pipeline has, in fact, delivered nothing
useful. The redaction invariant would have reported green on a total capture
failure.

This was not hypothetical. When `PreviousLogsFor` returned the wrong container
instance (§5), the log fetch failed, and the incident shipped with
`scrubbed_logs: []`. The secret-survival check passed **vacuously** on that
empty list.

**Fix.** `check_redaction` asserts both directions:

- no planted secret survives, **and**
- a `[REDACTED]` marker is present.

The second assertion is what makes the first meaningful. A pipeline that dropped
every line, or received nothing, cannot satisfy it. `check_logs_were_captured`
was split out for the same reason — it distinguishes "the logs were empty"
(a *capture* bug) from "the logs were unmasked" (a *scrubber* bug), which are
different failures needing different fixes.

The same principle applies to the whole E2E report. `render()` distinguishes a
pass-with-skips from a clean pass, and the workflow splits each invariant into
its own named step precisely so that "skipped" can never read as "passed".

---

## 2. Regex Engine Precedence (Milestone 1)

**Trap.** Ordering single-line rules before multi-line ones shreds structural
blocks. A PEM rule that only matches the `-----BEGIN`/`-----END` fences runs
against a base64 body first; the single-line `generic_secret_kv` rule can then
redact fragments *inside* what should have been removed as a unit, leaving
partial structure and, in the worst case, a body that no longer matches the
multi-line pattern at all.

**Fix.** `internal/scrubber` runs the cross-line pass **first**, on raw input,
strictly filtering `Rule.IsMultiLine == true`; only then does the per-line pass
run over the redistributed text. Single-line value classes explicitly exclude
`\n` so a greedy match cannot swallow following lines.

Two further constraints from the same area, both consequences of the ordering:

- Cancellation is observed at **line boundaries only**. A line is either masked
  to completion or not returned. Returning a partially-masked line would leak.
- Masking must not destroy topology. Credential masking targets the secret
  segment inside userinfo (`user:[REDACTED]@host:port`) via capture groups.
  Wiping hostnames, IPs or ports destroys the diagnostic material the RCA
  reasons over — the credential is gone and so is the evidence.

---

## 3. Python 3.11 AST & Formatting Artifacts (Milestone 2)

**Trap.** Syntax accepted by the developer's local interpreter can be rejected
outright by the CI interpreter. Two constructs bit this project:

- **PEP 695** type-parameter syntax (`def f[T](x: T)`) is a 3.12+ feature.
- **PEP 701** backslashes inside f-string expressions is 3.12+ as well.

The PEP 701 case is the instructive one, because **mypy silently accepts it**.
`mypy --strict` parses the file and reports no error, so the gate that is
supposed to catch version-incompatible syntax does not catch this one. The guard
that actually worked was a *textual* scan for the construct, not a type check.

**Fix.** CI pins the minimum supported interpreter, `pyproject.toml` pins
`target-version = ["py311"]` for deterministic `black` output, and a textual scan
exists specifically because the static analyser cannot be relied on for this
class of defect. **A gate that cannot fail is worse than no gate** — see §1.

---

## 4. Kubernetes Informer Backpressure & Nil-Pointers (Milestone 3)

**Trap (backpressure).** Informer callbacks run on a shared goroutine. An
unconditional send into the egress channel blocks that goroutine when the worker
pool is saturated — and because the informer and every other watcher share it,
the *entire* monitoring plane stalls, not just the saturated incident.

**Fix.** The egress is non-blocking: a `select` with a `default` arm drops and
logs rather than blocking. Dropping is safe here precisely because the buffer is
explicitly bounded and every drop is observable. The alternative — applying
backpressure from an informer callback — converts one slow consumer into a
cluster-wide outage.

**Trap (nil pointers).** Kubernetes API objects are deeply nested pointer trees.
`status.containerStatuses[0].state.terminated.exitCode` can be absent at every
level, and a missing hop anywhere produces a nil dereference or, worse, a
plausible-looking zero that silently corrupts a decision.

**Fix.** `internal/k8s/guard.go` enforces explicit nil checks at every pointer
hop. The rule is not "check defensively" but "there is no unchecked hop": every
access is either guarded or provably non-nil.

---

## 5. The `PreviousLogsFor` Race Condition (Milestone 3)

**Trap.** `Previous: true` tells the kubelet to serve the log of the instance
*before* the current one. Which instance holds the evidence depends entirely on
what the container is doing, and the two cases point in opposite directions:

- `Terminated{OOMKilled}` — the current instance **is** the one that died. Its
  log is served without `previous`. Asking for the previous instance either fails
  outright (there is none on a first crash) or silently serves an *older*
  instance's log, which is evidence about a different failure.
- `Waiting{CrashLoopBackOff}` — the current instance is one the kubelet cannot
  start, and it is blank by construction. The dead instance **is** the previous
  one.

This function returned `true` for all three shapes the watcher emits, with a
doc comment claiming it existed "so that the reasoning is testable". It did
neither, and the accompanying test asserted the wrong value with a comment
explaining why it was right — a test encoding the wrong belief, passing.

**A correction to the usual account of this bug.** It is commonly described as
"returns HTTP 400". That was **not** what was observed here. `Logs()` returns
`("", err)` on any failure and `pool.go` logs a warning and dispatches the
incident with `scrubbed_logs: []`. The HTTP status was never visible, because CI
logs return 403 (§12). The observable symptom was an **empty log array**, and
that is what §1's two-directional assertion caught. Believing the 400 story would
have sent the investigation to the wrong layer.

**Fix.** `Previous` is strictly the inverse of "does this incident carry an exit
code": non-nil exit code means the container is terminated now, so the log is
the current instance's and `previous` must be `false`; nil exit code means it is
waiting to restart, so the log is the previous instance's and `previous` must be
`true`. `internal/emitter` pins the equivalence from the other side — the two
predicates must be inverses — because they live in different packages, are keyed
on the same field by different means, and nothing had forced them to agree.

---

## 6. Shell Evaluation & SIGPIPE Races (Milestone 4)

**Trap.** `producer | grep -q PATTERN` under `set -o pipefail` reports failure on
a *passing* check. `grep -q` exits the instant it finds a match, closing the read
end of the pipe; the producer takes SIGPIPE and dies with status 141; and
`pipefail` hands that 141 to the pipeline in place of grep's 0.

Measured on this host:

```
{ printf 'needle\n'; seq 1 200000; } | grep -q needle   -> failed 60 / 60 runs, status 141
output captured to a variable, then grep on the variable -> failed  0 / 60 runs
```

It is a race, not a certainty: when the output fits the pipe buffer and is written
before grep exits, there is no SIGPIPE and the step passes. A step written this
way passes usually and fails sometimes, on identical code, which is the worst
possible shape for a gate.

Six assertions used this form. All were rewritten to capture the output to a
variable and match against it.

**Fix.** Capture first, then match:

```bash
list=$(sudo k3s ctr --namespace k8s.io images list)
grep -qF 'docker.io/library/busybox:1.36.1' <<<"$list"
```

Two related bounds came out of the same investigation:

- **`ctr`'s global `--timeout` defaults to 0, which means wait-forever.** A
  stalled connection blocks until the step timeout kills the process, and CI
  reports a killed step with `conclusion: failure` — byte-identical to an error.
  An unbounded wait is therefore indistinguishable from a failure without logs.
  Every `ctr` call now carries an explicit `--timeout`.
- The **budget must be computed, not estimated.** An earlier retry loop was
  described in its own commit message as having "ample headroom" while its worst
  case was 705s against a 600s step timeout — arithmetically incapable of
  completing. The retry was a no-op behind a timeout. Sizing is now derived from
  the file's own literals and validated against a control that must fail.

---

## 7. The E2E Runner Race Window (Milestone 4)

**Trap.** A CI step asserting the capture file is non-empty ran while the agent's
inference was still in flight, and failed a run in which the Sentinel had
correctly emitted.

The mechanism is in the capture proxy: `do_POST` calls `forward()` and **only
then** appends the record. The capture file therefore becomes non-empty *after*
the agent has fully answered. The fail-closed Tier-2 escalation the agent used to
return is fast; the Tier-1 path runs bounded LLM inference first. Making Tier-1
reachable lengthened the window between the Sentinel's first POST and the capture
appearing — so **fixing 4.2.6 regressed 4.2.1**. Neither was broken; the harness
had a wait-free assertion sitting inside a window it did not know existed.

**Fix.** A bounded poll before the assertion. Twenty one-second iterations is
twice a ceiling that already exists rather than a number chosen to look patient:
the proxy's `DEFAULT_UPSTREAM_TIMEOUT` is 10s and the workflow does not override
it, so a healthy exchange is on disk within ~10s of the Sentinel posting however
slow the inference, and past that the proxy records its own 502 and the file is
non-empty anyway.

The wait makes the assertion honest but cannot make the runner *see* anything it
missed: `runner.py` samples first and reads the capture afterwards, by design. So
the step also checks that the runner is still alive, and names an early exit as a
harness timing fault rather than letting it surface four steps later as a
missing-capture invariant — which would name the wrong half.

The step echoes the elapsed seconds. A wait that finishes in 0s is not covering
the case it was written for; one that always exhausts its budget means the budget
is wrong or the component is dead.

---

## 8. An `if` Condition Is Not An `||` Chain

**Trap.** `if grep -q A; grep -q B; grep -q C; then` is **not** "A or B or C". It
is a list of three commands whose status is the **last** one's. Only C decides
the branch.

Two of eleven per-invariant steps were written this way by a generator that
joined its needles with newlines. Both reported green regardless of what the
runner said. One of them was then cited as evidence that a payload's logs were
non-empty — an inference drawn from a guard that could not fail.

This is the third instance in this project of the pattern in §1, and the most
expensive, because it was discovered only by someone reading the generated shell
rather than the intent behind it.

**Fix.** `||`-join the conditions, and add a check to `scripts/audit_workflow.py`
that rejects a multi-line `if` condition with no `||`, `|` or line continuation.

Getting *that* check right took three attempts, and the failures are instructive:

1. Too eager — it walked past single-line conditions into step bodies and flagged
   ten correct steps.
2. Then silent on everything. The regex `^\s*if\s+.*(?:^|\s)grep\b` needs
   `(?:^|\s)` to match a space that `\s+` had already consumed, which only
   backtracks when there are two or more spaces after `if`. It never matched the
   common single-space form. **The negative control reported "guard did not
   fire" on a run where the defect was demonstrably present**, and the honest
   reading of that result — the guard is broken, not the defect absent — is what
   caught it.
3. Finally a false positive on a genuine two-line *pipeline*, whose `if` status is
   correct.

A guard that fails open on the common case is worse than no guard.

---

## 9. A Sampling Window That Opens Too Late

**Trap.** The E2E runner sampled pod state **after** the chaos fixture had been
applied and after the pod had already reached its failure state. Since
`is_oom` is `exit_code == 137` and the kubelet clears `state.terminated` on
restart — leaving the 137 only in `lastState`, which is filed under
`previous_exit_code` — every sample could show only the symptom. The chain check
failed with "never observed Terminated{exit_code: 137}" on a cluster where the
OOM had worked perfectly.

The runner's own docstring states the requirement this contradicted: *"a snapshot
taken after the restart can only ever show the symptom, so a runner that asserts
on one poll cannot observe the cause at all."*

**Fix.** The runner is started **before** the fixture and samples across the whole
lifecycle. A related ordering rule followed: the capture is read *after* sampling
ends, because the proxy appends continuously and reading first would load an empty
file.

**The generalisable form.** A precondition arranged so the thing depending on it
cannot run when it matters. This exact shape appeared twice — once here, and once
as the `if`-chain in §8 — and it is worth naming because it is the failure mode
that keeps recurring rather than any individual line of it.

---

## 10. Diagnostics Arranged So They Cannot Run

**Trap.** The E2E runner step ended with `exit "$rc"`. GitHub skips the remainder
of a job after a failing step, so the eleven per-invariant steps behind it — the
mechanism added specifically to name the failing invariant — were **all skipped**.
The diagnostic was gated behind the failure it was meant to explain.

**Fix.** The runner step now always exits 0; it runs, prints, and does not judge.
The verdict belongs to the steps behind it. A final step, "Runner verdict",
reads the recorded exit code and fails when nothing else has — because a runner
that died on a bad JSON line or a `kubectl` error would otherwise leave all
eleven invariant steps green and the job would pass on a harness that proved
nothing.

---

## 11. Two Predicates With No Reason To Agree

**Trap.** The emitted payload's "does this incident carry an exit code" and the
telemetry layer's "should I ask for the previous instance" are the same question
asked twice, in two packages, keyed on the same field by different means. Nothing
forced them to agree, and they did not — which is §5.

**Fix.** A test asserting the two predicates must be **inverses**, with controls
in both directions. A detection beyond the pod's final observed restart count
must still fail (a fabricated detection); a genuinely *missed* detection must
still fail even when the ceiling is high. Without that second control, a pod that
restarted many times would launder exactly the defect the assertion exists to
catch.

The same shape governs 4.2.8: the printer and the runner must read the *same*
exemption function, so the console and the exit code cannot tell different
stories. The printer calls the runner's predicate rather than restating it.

---

## 12. Log-Blindness, and What It Costs

> **CORRECTION — this constraint no longer holds, and the old text was the most
> dangerous thing in this file.** CI logs used to return HTTP 403 to the
> unauthenticated API, so only step and job *conclusions* were readable. That is
> no longer true: an authenticated GitHub client can read full job logs, and it
> now does. Milestone 4.2's final diagnosis — the `Terminated` dispatch failures
> in §16 — came from reading the log text directly, not from a step name.
>
> If you are reading this and concluding that logs are unavailable, you have read
> a stale constraint. The failure mode this section describes is now a choice, not
> a limitation: every fix below remains correct, but the reason to split compound
> steps is legibility, not necessity. The original text is kept because the
> *discipline* it produced is what ended the guessing, and because a reader who
> was told "logs are unreadable" once will not believe otherwise without seeing it
> stated here.

**Trap.** CI logs return HTTP 403 to the unauthenticated GitHub API for this
repository. Only step and job *conclusions* are readable. A step that runs eleven
checks and reports one boolean tells a reviewer nothing they can act on.

This constraint did more damage than any individual bug in §6, §7 or §9. Four
consecutive CI runs were consumed by hypotheses formed from step names alone. Two
of them were wrong, and one of those cost two runs.

**Fixes that generalise:**

- **Split compound steps into individually named ones**, so a failure names itself.
- **Report invariants as step conclusions**, each matching only the failure text
  that one invariant can produce.
- **Put diagnostics in a step that always runs** (`if: always()`). A report
  readable only inside a failing step is not available when the run fails.
- **Make the step itself informative** — echo elapsed time, counts, and the
  configuration in effect, so a single number distinguishes "the guard is not
  covering this case" from "the budget is wrong".

**The honest cost, recorded.** Guessing from a step name is not analysis. Across
this milestone several fixes were right for the wrong reason — a removed
dependency, a race, an ordering bug — and one hypothesis (a registry rate limit)
was ruled out on the next run. The practice that ended the guessing was not
cleverness but refusing to submit a fourth blind change, and asking instead for a
log that a maintainer could read.

---

## 13. Smaller Traps Worth Keeping

- **A doubled path is nearly invisible in CI.** The emitter appends
  `/v1/incidents` to the agent's root, so `-agent-url` must not carry a path.
  Ours produced `/api/v1/triage/v1/incidents` and a 404 — and the capture proxy
  records exchanges whatever the upstream status, so the capture file stayed
  non-empty and every invariant had a real payload to examine. The only symptom
  was a status code in a line nobody read. There is now an audit check for it.
- **`get_pod` returns `items[0]`.** With two chaos fixtures, a bare existence
  selector resolves to whichever pod name sorts first — `crashloop` before
  `oom` — and the runner silently samples the wrong pod forever. Adding a second
  fixture turns the selector into a correctness question. A test now fails loudly
  if the ordering changes.
- **Multi-line `python -c` inside a YAML block scalar.** Continuation lines must
  carry the block's indentation; when they do not, the file stops being valid
  YAML and the *workflow* breaks rather than the command. This bit twice.
  `bash -n` is now an audit check over every `run:` block — and it was reported as
  a blocked dependency for two commits before anyone checked that Git ships bash.
- **A context argument is not a design decision.** The first readiness gate in the
  detonation workflow waited on the wrong thing: the apiserver's `/readyz` does not
  imply containerd's image service is serving, and `ctr version` only proves the
  daemon process is up. Same shape as the namespace-scoping defect found earlier —
  a precondition satisfied by the wrong check.
- **Trust the gate, not the claim about the gate.** A subagent reported that
  `mypy --strict agent/` was red "at HEAD" and that the gate "cannot currently
  pass". It had run `agent/` alone; the gate is `agent/ tests/`, and the gate was
  green. The actual defect it introduced was three errors in the real invocation.

---

## 14. Rule 7 and Rule 10 — Two Confirmed Secret Leaks (Milestone 1)

### Quoting defeated the key pattern, so every JSON-form secret survived (D-1)

- **What happened:** Rule 7 (`generic_secret_kv`) required `\s*[:=]` immediately
  after the key name. Any closing quote sat between the two and the rule did not
  match. Separately, the key was anchored with `\b`, which fails on `auth_token`
  because `_` is a word character and therefore no boundary exists between the
  segments. Measured against the ratified patterns, all three of these passed
  through unchanged: `{"password":"hunter2"}`, `auth_token=abc123xyz789`, and
  `reading /var/run/secrets/kubernetes.io/serviceaccount/token for kube-system`.
- **Why it is a problem:** This is a plain credential leak in the safety path.
  The scrubber is the only thing standing between raw container output and an LLM
  and a network egress, and a rule that reports "matched" while matching nothing
  is worse than an absent rule, because it is counted as coverage.
- **How we fixed it:** Three changes to Rule 7: an optional `["']?` between key
  and separator; the key prefixed `[\w-]{0,20}` with a non-capturing alternation so
  multi-word keys match; and the key plus its trailing quote are **captured**, so
  only the value is replaced. That last one is load-bearing — replacing the whole
  match would destroy the surrounding JSON and break the Contract A payload the
  agent parses. Negative controls confirm the widening did not become a
  bludgeon: `token_count=12345`, `secret_version=v3`, `mytokenizer=abcdefgh` and
  `password_policy=strict-mode-value` all survive untouched. Rule 10 now accepts
  both word orders — the original required the namespace *before* the token,
  while the canonical log form is the reverse — bounded to 80 non-newline
  characters so it cannot reach across unrelated lines.

### Marker-level redaction ran before block-level removal (D-3)

- **What happened:** The per-line pass ran rule 11 `private_key_pem_body` before
  the cross-line pass ran rule 1 `pem_private_key`. Rule 11 redacted only the
  `-----BEGIN` marker, so by the time rule 1 saw the joined batch there was no
  `BEGIN…END` pair left to match, and the base64 key body survived verbatim.
- **Why it is a problem:** A private key is the highest-value secret in the
  corpus, and the failure mode is a green report. The pipeline processed the log,
  matched a rule, and shipped a body it believed it had removed.
- **How we fixed it:** The cross-line pass runs **first**, on the raw lines, so
  rule 1 sees an intact block; multi-line rules therefore evaluate ahead of the
  single-line fallbacks. Each `Rule` now carries `IsMultiLine`, and the cross-line
  pass filters strictly on it, so single-line rules can never run against a joined
  batch. The general rule, which cost a second defect (D-5) to learn: **block-level
  removal must not be pre-empted by marker-level removal.**

---

## 15. A `type: ignore` That Was Correct on One Platform and Fatal on Another (Milestone 2)

- **What happened:** `sandbox.py` carried `os.setsid()  # type: ignore[attr-defined]`.
  `setsid` is absent from typeshed on Windows and present on Linux, so the ignore
  was **used** on the `windows/arm64` development host and **dead** on
  `ubuntu-latest`. `setup.cfg` sets `warn_unused_ignores = True`, so CI failed on
  an ignore that the local machine was relying on.
- **Why it is a problem:** This is the third host/CI divergence with the same
  signature — green locally, red on CI, with no other signal. The failure mode is
  that the local machine is not running the configuration that will be graded, so
  a passing local gate stops being evidence of anything. It is also the exact
  inverse of the usual worry: the ignore was not hiding a type error, it was
  hiding the fact that the type only exists on one platform.
- **How we fixed it:** `getattr(os, "setsid", None)`, which type-checks identically
  on both. `agent/tests/test_compat_platform.py` now fails the build if an ignore
  ever sits on a platform-sensitive line again, and it carries its own negative
  control so the detector cannot silently stop working. See also §3: the same
  milestone produced the PEP 701 case, where mypy accepts syntax the CI
  interpreter rejects — two gates, one lesson, that a type checker is not a
  portability check.

---

## 16. The Dedup Key Carries No Kind, So the Symptom Was Suppressed as a Duplicate (Milestone 4.2)

- **What happened:** The dedup key is `<podUID>/<containerName>:<restartCount>`
  and does not include the failure kind. A crash-looping container therefore
  produces, for the *same* restart count, a transient
  `Terminated{exit 1, reason: Error}` and then a `Waiting{CrashLoopBackOff}`. The
  transient state claims the key first, and the state carrying the evidence is
  rejected as a duplicate. The E2E log showed five `dispatch failed` lines for the
  crashloop pod, every one `kind: Terminated — failure kind has no wire
  representation`, and **not one** `CrashLoopBackOff`. The emitter was never at
  fault: refusing an unmappable kind is correct fail-closed behaviour, and
  emitting the nearest member would have asserted an OOM kill that never
  happened — which is precisely what unlocks a memory-limit diff.
- **Why it is a problem:** A container was detected and then never reported at
  all. The failure is silent in the worst way: the dedup cache is doing exactly
  what it was built to do, and the observable result is that a real incident
  disappears. Nothing in the system distinguishes "already seen this" from "seen
  this, then it changed into something worse".
- **How we fixed it:** Non-OOM terminations are dropped in `internal/k8s/watcher.go`
  **before the record is constructed**, so the un-serialisable state never claims
  a key. Mapping `Terminated` to `CrashLoopBackOff` instead was rejected: it
  would report the kubelet asserting a state the Sentinel never observed, and it
  would make the 4.2.7 check pass without ever exercising it.
- **The limitation this leaves, recorded deliberately.** A container that exits
  non-zero and *stays dead* — `restartPolicy: Never` — is now completely silent.
  It is neither an OOM nor a backoff, so no record is built. This is a real
  observability hole introduced by the fix, accepted because the architect ruled
  the schema must not widen, and it is written down here so that a later
  maintainer rediscovers it as a decision rather than re-deriving it as a bug.

---

## 17. Blind Structural Changes, Because the Failure Left No Trace (Milestone 4)

- **What happened:** Four consecutive CI runs were consumed by hypotheses formed
  from step *names* alone, two of them wrong, one costing two runs. The
  structural changes thrown at the pipeline during that stretch were blind: the
  interesting shape of the episode is a fixture whose failure mode was altered
  to try to make evidence appear, when the evidence's absence was a property of
  the *observation*, not of the workload. A Deployment forces
  `restartPolicy: Always`, so an OOM'd pod settles permanently into
  `CrashLoopBackOff` and the chain `Terminated → Waiting{CrashLoopBackOff}` is
  observable — but only if sampled *across* the lifecycle, because the kubelet
  clears `state.terminated` the instant it restarts the container. A pod
  configured to *not* restart removes the backoff states entirely: it would
  produce a `Terminated` and then nothing, so an assertion on the symptom would
  see no symptom and the change would read as a regression rather than as the
  removal of the very evidence being looked for.
- **Why it is a problem:** Changing the system under test in order to make a test
  pass is the failure mode that produces green runs proving nothing. It is
  especially dangerous when the change is *plausible* — a `restartPolicy` edit
  looks like configuration, and its blast radius reaches the causal chain the
  runner depends on. The reason it kept happening is the one in §12: with no
  readable log, the only evidence available was a boolean, and a boolean cannot
  distinguish "the workload failed differently" from "the observation is still
  wrong".
- **How we fixed it:** Two independent changes, one to the harness and one to the
  discipline. The harness: the runner is started **before** the fixture and samples
  across the whole lifecycle, and each invariant became its own named step so a
  failure names itself (§9, §10, §12). The discipline, which was the part that
  actually mattered: **refusing to submit a fourth blind change and asking instead
  for a log a maintainer could read.** A green run arrived on the next attempt
  from a hypothesis nobody had submitted, which is the clearest possible statement
  of what the previous four runs had been buying.
- **Provenance note.** The four-run episode, the two wrong hypotheses and the
  fourth-change refusal are recorded in §12. The `restartPolicy: Never` framing is
  an account of the *shape* of the change rather than a verbatim record: no
  `restartPolicy: Never` fixture exists in `deploy/chaos/`, and
  `tests/e2e/runner.py` documents only the `Always` case. It is written down here
  as the generalisable trap — do not alter the subject to satisfy the observer —
  and flagged as reconstruction so a later reader does not treat it as a quote.

---

## 18. `git add -A` in a Tree Where Tool Configs Appear (Milestone 4.2)

- **What happened:** A `git add -A` swept `opencode.json` — the MCP config created
  when the GitHub server was added — into a commit. It holds a live personal
  access token on line 15.
- **Why it is a problem:** Every local gate passed over it. A leaked credential is
  not a syntax error and not a type error, so `go vet`, `gofmt`, `black`,
  `flake8`, `mypy --strict` and the test suites all reported green over a
  repository containing a live secret. The only thing that caught it was GitHub
  push protection, a server-side rule that happened to exist. Had the repository
  not had push protection enabled, the token would have been public history and
  the recovery would have been rotation plus history rewrite rather than one
  amended commit.
- **How we fixed it:** The token was removed from the commit, the orphaned object
  was pruned with `reflog expire --expire=now --all` and `git gc --prune=now`, and
  the token was rotated. The durable fix is that credential-bearing files are now
  un-addable **by shape and at any depth** — `opencode.json`, `.mcp.json`, `.env*`,
  kubeconfig in all spellings, PEM and key material, cloud and package
  credentials — with template and fixture forms re-admitted explicitly so the
  protection costs no legitimate commit. A landmine check confirms **zero** already
  tracked files are matched by any pattern, because a pattern that shadows a
  tracked file silently untracks it on the next `git add`.
- **The second channel, which the first fix missed.** `.gitignore` protects
  exactly one channel. The Docker build context is uploaded to the daemon on every
  `docker build -f agent/Dockerfile .`, and `ci.yaml` does precisely that, so the
  token was in the context of every CI and local build. No `COPY` reaches the
  repository root, so it was never baked into an image layer — but it was
  uploaded, which becomes a network transfer the moment anyone builds against a
  remote builder. `.dockerignore` now lists the same shapes, and the two files say
  in comments that they must be kept in step. The generalisable form: **a file one
  ignore list protects is still shipped by every other channel that reads the
  working tree.**

---

## 19. A Unified Diff Hunk Header Counts Each Side Separately (Milestone 4.3.4)

### `git apply` exited 0 and changed nothing

- **What happened:** The Tier-1 patch was generated in the test rather than
  written by hand, and the hunk header was built as
  `@@ -{start},{len(body)} +{start},{len(body)} @@`. That counts the hunk body
  once and applies the number to both sides. It is wrong: a `-` line counts
  toward the old file and a `+` line toward the new one, and they are not the
  same line. For a three-lines-of-context change it declared 8 per side where the
  old side has 4, and git answered `corrupt patch at line 13`.
- **Why it is a problem:** The header is arithmetic that looks exactly as
  plausible whether or not it is right, and nothing about reading the code
  reveals the error. Worse, the diagnostic is opaque — "corrupt patch" at a line
  number, with no hint that the counts are at fault. Hand-written diffs get
  reviewed; generated ones get trusted, which is precisely backwards.
- **How we fixed it:** Each side is counted from its own constituents —
  `old_count = context + removed`, `new_count = context + added`. More
  importantly the patch is now assembled *and applied by real git* in a test
  rather than generated and trusted: `git apply --check` and `git apply` both
  run, in a scratch tree, on every local test run. No cluster required.

### The scratch tree was inside the repository

- **What happened:** The scratch copy lived at `tests/e2e/.verify-scratch`,
  inside the working tree. `git apply` walks up to find the repository root and
  resolves the patch's paths against *that*, not against the working directory —
  so it targeted the repository's own copy of the manifest (untracked, so git
  declined to write it) and left the scratch copy untouched. The command
  **exited 0**.
- **Why it is a problem:** The worst outcome available: a green command that
  applied nothing. A test reading the scratch file would have examined an
  unpatched manifest while every status it checked reported success. This is
  §8's failure mode in a different hat — a check that cannot fail — and it is
  worse than a missing check, because it manufactures a false proof.
- **How we fixed it:** Two defences, both load-bearing. The scratch tree moved
  **outside** the repository, so there is no repository for git to resolve
  against and no second file that could be written by mistake. And the exit status
  is now *necessary and not sufficient*: the helper re-reads the result and
  raises if the limit did not actually change. A patch that applies without
  changing anything now fails loudly instead of yielding a plausible file.

---

## 20. `Path.write_text` Silently Produced a CRLF Patch (Milestone 4.3.4)

- **What happened:** The patch was written with
  `patch_path.write_text(patch, encoding="utf-8")`. On Windows, text mode
  performs newline *translation*, so every `\n` became `\r\n`. The manifest it
  must match is pure LF. Git compared the hunk's context byte for byte, found a
  trailing carriage return on every line, and reported `patch does not apply` at
  a line whose context was otherwise identical. The same code on Linux writes LF
  and passes.
- **Why it is a problem:** The third host/CI divergence in this project with an
  identical signature — see §3 and §15 — and the property that makes each one
  expensive is the same: **the local machine is not running the configuration
  that will be graded**, so a passing local run stops being evidence. Here the
  failure also points in the wrong direction, blaming the patch's *content* when
  the defect is its *encoding* and the content is provably correct.
- **How we fixed it:** `newline="\n"` is passed explicitly, with a comment
  saying why it is load-bearing rather than decorative. A regression test asserts
  that the generated patch contains no `\r`, that a patch written through text
  mode on this host contains none either, and that the manifest is LF — so the
  next person to drop the argument gets a failing test rather than a confusing
  git error on a platform that happens not to have the problem.

---

## 21. Controls That Fail For The Wrong Reason Are Worse Than No Controls (Milestone 4.3)

- **What happened:** Four negative controls across this milestone were invalid
  before they were informative, and every one *looked* like a result. A guard was
  "proved" by planting `import kubernetes`, which is not installed — so pytest
  errored at collection instead of tripping the guard. A second was proved by
  planting a dead `def apply_patch`, which a check inspecting call targets and
  attribute names is *right* not to flag. A third missed on CRLF anchors against
  an LF file. A fourth anchored on the test file when the defect lived in the
  fixture, so the plant never landed. All four were, at the moment, reported as
  controls run.
- **Why it is a problem:** A control that fails for the wrong reason produces
  exactly the false confidence it exists to prevent, and it is worse than
  omitting the control, because the record then claims a proof that was never
  obtained. This is the mechanism behind §8's third instance and behind every
  green-then-red cycle in §12.
- **How we fixed it:** AGENTS.md §5 rule 6 now requires invalid controls to be
  recorded alongside working ones, stated in the file the next agent reads before
  writing one. Three habits did the practical work: **assert the plant is present
  before running the test**; **read the whole test output rather than filtering to
  the line that looks like a verdict**; and **check the anchor against the file
  the defect is actually in**. The controls that count are the sixteen run with a
  verified plant — ten against the fixture, two against the diff mechanics, and
  the four from the zero-writes guard — all of which failed their guard as they
  should.
- **Provenance note.** The count above is the controls that fired. The four
  earlier attempts are named here as failures rather than omitted, and each is
  described in the commit message for `1a8ad96` with the specific reason it was
  invalid. Nothing in this section is a quotation from a run that produced the
  result; the fixture arithmetic, the diff mechanics and the PSA-surface drift
  were all measured, and the *reasons* the invalid controls were invalid are
  reconstructions from the failure output rather than from a log that was kept.

---

## 22. Reintroducing a Documented Fix, In the Milestone That Documents It (Milestone 4.3)

### `grep -q` at the end of a pipeline, again

- **What happened:** The new M4.3 workflow step checked that busybox was present
  in k3s containerd with
  `sudo k3s ctr ... | grep -qF 'docker.io/library/busybox:1.36.1'`. That is
  verbatim the form §6 records as a SIGPIPE race, removed from six assertions
  after it was measured at 60 failures in 60 runs. It reported the image
  **missing** on a cluster where it was present and every Milestone 4.2 fixture
  had already started and passed. The step also omitted `--timeout` on `ctr`,
  which §6 records as defaulting to 0, meaning wait-forever.
- **Why it is a problem:** Two failures in one. The immediate one is a false
  negative in a preflight gate, which is the §1 shape again: a check that
  cannot distinguish "the thing is absent" from "my way of asking is wrong". The
  structural one is worse. This was written in the same milestone that added the
  post-mortem protocol, in a file whose §6 explains the defect in detail, by an
  agent that had read that section earlier in the same session. **Knowing a trap
  does not prevent walking into it**, which means the only thing that reliably
  prevents it is a check that fires without anyone having to remember.
- **How we fixed it:** The step now uses the ratified form from the existing
  "Verify k3s Image Registration" step verbatim — capture to a variable, match
  from the variable, `--timeout 30s` — rather than a freshly written one. The
  deeper fix is in `scripts/audit_workflow.py`: a new `GREP_Q_PIPE` check flags
  any `grep -q` terminating a pipeline in a `run:` block that sets `pipefail`,
  naming the step, the line and the replacement. It exists because
  `check_bash_syntax` passed the defect: piped `grep -q` is valid shell, so
  `bash -n` has nothing to say, and that function's docstring had been claiming
  coverage of this defect class since it was written. **A check whose docstring
  overstates what it detects is worse than no check**, because it is consulted
  as evidence and is not evidence.

### The generalisable form

Two distinct lessons, and the second is the one worth keeping.

1. *Reach for the ratified form.* When a workflow already contains a working
   instance of a check, copy it. Writing a fresh one re-opens every trap the
   working one had already been hardened against, and does so invisibly.
2. *A guard that cannot see the defect is not a guard.* `check_bash_syntax` is
   named for syntax and does syntax; its docstring drifted to imply it covered
   semantic shell defects, and for several milestones that implication was load
   bearing in the wrong direction. The correction is not to widen the function
   but to add the missing check as its own thing and to make the docstring state
   only what the code does.

The negative control for the new check reintroduces the exact line that failed
in run `36785083401`; the audit reports
`GREP_Q_PIPE: M4.3 - Live Post-Remediation Verification Loop: line 28` and exits
1. On the corrected workflow it reports nothing, so it is not simply flagging
every pipeline in the repository.

## 23. Sixteen Green Manifest Tests, And A Deployment That Routed Nowhere (v1.0.1)

Found while writing the v1.0.0 README, not by a gate. `deploy/` shipped without
a `Service`, while `deploy/sentinel.yaml` set `SREK3S_AGENT_URL` to
`http://srek3s-agent:8000` and described it in a comment as "the agent's
Service". Nothing created that name, so the Sentinel could not resolve the agent
it was configured to call. Compounding it, the `-agent-url` flag default was
`http://srek3s-agent:8080` — a port nothing listens on, while the agent binds
`0.0.0.0:8000`.

`kubectl apply -k deploy/` succeeded. Every pod started. Neither pod could reach
the other.

### Why sixteen tests missed it

Every check in `test_deploy_manifests.py` asserted a property of **one
document**: the Role grants no mutating verb, the containers carry the hardening
block, the namespace enforces restricted PSA, `/tmp` is the only writable volume.
All true. All worth having. None of them can observe that a value in file A
refers to a resource that file B was supposed to create and does not.

A check that only ever opens one file cannot fail on a defect that spans two.
The missing Service was a disagreement *between* documents, and the suite had no
notion of a disagreement.

### Why the E2E missed it too

The detonation workflow applies only `deploy/chaos/*`, then runs the Sentinel and
the agent as host processes with `-agent-url http://127.0.0.1:8001` over a
`kubectl port-forward`. That path sidesteps name resolution completely — no
Service, no DNS, no ClusterIP. So the one workflow that runs the real binaries
against a real cluster exercises precisely the part of the deployment that was
broken, by routing around it.

This is the more expensive half of the lesson. A test harness that substitutes a
convenient transport for the real one is not a weaker test; for the code path
concerned, it is **no test at all**, and it is worse than no test because it
occupies the slot where the real coverage would go.

### What changed

`test_the_agent_service_routes_the_sentinels_default_endpoint` asserts the four
facts that must agree, and reads each from its authoritative source rather than
hardcoding it:

1. the Service is named `srek3s-agent` — the DNS name the Sentinel dials;
2. its `selector` matches `agent.yaml`'s **pod template** labels — a selector
   that matches nothing yields a *timeout*, not a *refusal*, which is much
   harder to diagnose from a log;
3. its `targetPort` and `port` equal the port parsed out of the Dockerfile's
   `ENTRYPOINT`, not a constant in the test;
4. the Sentinel's `-agent-url` default, parsed out of `main.go` with a regex
   anchored on the `envOr("SREK3S_AGENT_URL", …)` call, equals
   `http://<service name>:<service port>` — with no path, because
   `internal/emitter` appends `/v1/incidents` itself.

A second test asserts the two NetworkPolicies admit that port, on the reasoning
that a ClusterIP does not change policy evaluation (the policy applies to the
post-DNAT destination, which is the pod) — true today, and worth pinning before
someone adds an `ipBlock`.

All seven ways of breaking the coupling are mutation-tested against the real
files: targetPort moved, selector mistyped, default reverted to `:8080`, default
given a path, Dockerfile port moved, `service.yaml` dropped from the
kustomization, Service published on a port no policy admits. Every one fails the
build.

### The generalisable form

*A suite of per-file assertions has a blind spot exactly the width of the space
between files.* Adding more per-file checks does not narrow it. When a defect
class is "these two things must agree", the check has to hold both in hand, and
it has to read each side from the place a future edit would actually change.

The corollary is about the harness. When an end-to-end workflow replaces the
production transport with a convenient one, ask what the substitution made
unobservable — and check that the answer is not "the thing that was broken".
Here it was, and the workflow passed for a full milestone.


## 24. The Port-Forward That Was Never There (v1.0.1 follow-on)

A directive arrived to "eliminate the E2E's use of `kubectl port-forward` for
Sentinel-to-Agent communication", on the premise that the harness was inserting
itself into the routing with a port-forward.

There is no `kubectl port-forward` in this repository. A whole-repo search finds
the string only in prose - in this file, in a manifest comment, and in the
README. The E2E ran the Sentinel, the agent and the capture proxy as three host
processes on loopback, and never applied `deploy/` at all.

The premise was wrong, and the truth was worse.

### What the E2E actually exercised

In-cluster: the victim workload, and nothing else. Out-of-cluster: everything
under test. So the following were never executed by any job, ever:

- `deploy/service.yaml` - the Service, and with it all of Service routing;
- `deploy/agent.yaml` and `deploy/sentinel.yaml` - both Deployments;
- both NetworkPolicies;
- `deploy/rbac.yaml` - the Role, the ServiceAccount, the binding;
- `readOnlyRootFilesystem`, `runAsUser: 10001`, `cap_drop: ALL`, restricted PSA.

Every one of those is a security control. The system had a green E2E, a green
CI, and a ratified Definition of Done, and none of it had ever started the thing
it was shipping.

### Why the substitution was invisible

The harness substituted 127.0.0.1 for in-cluster DNS, and loopback for
ClusterIP routing. Both substitutions are invisible *in the passing direction*:
everything that works on loopback also works through a Service. They are only
visible in the failing direction, and they removed every way for the deployment
layer to fail.

This is the sharp edge of a convenience substitution. Replacing a component with
something simpler does not just test less - it can remove the only path by which
a whole class of defect could have been observed, while leaving the suite green
and the run looking thorough.

### The fixtures that fell out

Building the in-cluster leg surfaced three further gaps, none of which any gate
had seen:

1. **The Sentinel cannot watch any namespace but its own.** `deploy/rbac.yaml`
   grants a Role in `srek3s-system` only. Run the Sentinel with
   `-namespace sentinel-chaos`, as the runbook instructs, and it is
   unauthorised. The chaos-namespace grant now lives in the E2E overlay, not in
   `deploy/`, because shipping a Role bound to a disposable test namespace into
   every production deployment is worse than the gap. The gap is filed, not
   papered over.
2. **No root `Dockerfile` exists.** `deploy/sentinel.yaml` references
   `registry.internal/srek3s-sentinel:0.1.0` and `docs/offline-install.md` line
   105 documents `docker build -f Dockerfile` to produce it. The only Dockerfile
   in the repository is `agent/Dockerfile`. The deploy set references an image
   nothing builds - so the in-cluster leg can deploy the agent and assert the
   Service route, and cannot yet start the Sentinel.
3. **The agent needs a manifest root it has no way to get in-cluster.** The
   provider fails closed when `SREK3S_MANIFEST_ROOT` is unset, which is correct
   and means a missing mount produces a *correct* Tier-2 escalation rather than
   an error. A leg that watched for incidents would have seen plausible Tier-2
   output and passed.

### The impersonation, stated plainly

`deploy/agent.yaml` admits ingress only from
`app.kubernetes.io/name: srek3s-sentinel`. An in-path instrument has to be
admitted by that policy, and NetworkPolicy authenticates labels rather than
identities, so the capture proxy and the routing probe both carry the
Sentinel's label.

That is impersonation. It is the right trade *here* - in a disposable namespace,
for a fixture that exists for one CI run - because it leaves the policy under
test unmodified, so "only a pod claiming to be the Sentinel may reach the
agent" is still genuinely enforced while the leg runs. It would be the wrong
trade in a production namespace, which is why neither object is in `deploy/`.
The alternative, relaxing the policy to admit a second identity, would have meant
weakening the control so a test could observe it.

### What the leg does and does not prove

Proves: `deploy/` applies; the Service publishes ready endpoints; cluster DNS
resolves `srek3s-agent` and the agent answers `/healthz`; the Sentinel's real
ServiceAccount is granted reads and refused writes by a live apiserver in both
namespaces; the agent's ServiceAccount holds nothing; and the running agent pod
is UID 10001 with a read-only root and no token.

Does not prove: that the Sentinel Deployment starts (no image), or that anything
detonates in-cluster. Detection and patch generation are proven by the
host-process leg against a real OOM, and duplicating that would re-prove a chain
that is not in question in order to re-verify a layer that is.

### The generalisable form

*Ask what a test harness's convenience substitution made unobservable - and
check that the answer is not "the layer nobody was testing".* Here the
substitution was loopback for Service routing, and the layer nobody was testing
was the entire deployment.

The second half is the one to keep. **A green end-to-end run means the paths that
ran are covered. It says nothing about the paths that were substituted out, and
the substitution is usually invisible in the passing direction.** "End-to-end" is
a claim about the ends. It is not a claim about the middle.


## 25. The Gate That Reported 68 False Failures And Was Believed (v1.0.1 follow-on)

Adding shell steps to the E2E workflow made `scripts/audit_workflow.py` go from
`FAIL: 0` to `FAIL: 68` in one run. The steps it named included ones in
`ci.yaml`, which that audit had never touched and which had passed every previous
run. Sixty-eight findings, on a change that could not possibly have broken the
shell in `Show toolchain` or `G2 - gofmt`.

The instrument was broken, not the workflows.

### What was wrong

`find_bash()` returned the first candidate it found without asking whether the
candidate worked:

```python
for candidate in ("bash", "sh"):
    found = shutil.which(candidate)
    if found:
        return found          # <- returned, never tested
```

On Windows, `shutil.which("bash")` resolves to
`C:\Users\<you>\AppData\Local\Microsoft\WindowsApps\bash.exe` - the Windows
Subsystem for Linux **launcher stub**. With WSL not installed, that binary prints
an install prompt to stderr and exits 1. Every `bash -n` the audit ran therefore
failed, and every step carrying a `run:` block was reported as a syntax error.

Git ships a working bash at two known paths, listed in the same function, and
they were never reached because the PATH lookup came first.

### Why this one is worth the space

The findings were false. That is the ordinary kind of instrument failure and it
would have been caught by reading one line of output.

The expensive part is the second thing: the false findings were **indistinguishable
in kind** from a real one. `BASH_SYNTAX: G2 - gofmt` means the same thing
whether gofmt's step has a genuine quoting error or the auditor cannot start its
own shell. A reader - including me - has no way to tell from the finding alone,
so the only available response is to go and look. Sixty-eight steps' worth of
looking, at a change that broke none of them.

And the trigger is the uncomfortable direction. The audit went green-to-red on
the same commit that *added* the shell steps. So the most natural reading of the
result - "my new steps broke shell syntax, loudly, everywhere" - is exactly
backwards, and the plausible one. A gate that is wrong in the direction that
*confirms* your worst suspicion is more dangerous than one that is wrong in the
other direction, because it is the failure you are least likely to investigate.

### The fix

`--version` against every candidate, requiring exit 0 and `GNU bash` on stdout,
and the Git paths tried before PATH on Windows so the known-good interpreter is
not behind a known trap. With that, the same audit reports `FAIL: 0` - on the
same steps it had just condemned, and on the new ones.

`_bash_works` is now covered by `agent/tests/test_audit_workflow_tool.py`, which
also asserts the candidate *ordering* by reading the source, so moving the PATH
lookup back to the front fails a test on any Windows host with both. Shelling out
to the audit could only ever assert its exit code; importing it is what allows a
test to ask `find_bash()` what it picked and require that it runs.

### A smaller instance, same shape

`mypy --strict` failed on the new test with `import-not-found` for
`audit_workflow`, while `pytest` ran the same file green. Both tools were
correct: the test does a runtime `sys.path.insert`, which mypy never executes
because it resolves imports statically. The fix was one line in `setup.cfg`
(`mypy_path = agent, scripts`).

Worth recording because the symptom is alarming and the cause is mundane - and
because the tempting fix is a `# type: ignore`, which would have silenced the
error and left `audit_workflow.py` **completely unchecked by G6** while
appearing to resolve it.

### The generalisable form

*Before believing a gate, confirm the gate ran.* A finding that appears
immediately after a change, names files the change did not touch, and scales with
the size of the repository rather than the size of the change, is describing the
instrument. Those three properties together are the signature, and checking them
takes ten seconds against an afternoon of reading 68 correct-looking errors.

The narrower form, worth more: **a gate must be able to report that it could not
measure.** This one could not - it had no way to say "I never successfully
invoked bash" as distinct from "your shell is broken", so it answered a question
nobody asked with a confidence nobody had earned.

---

### `Path.exists()` Is Case-Insensitive On Windows And Case-Sensitive On Linux (v1.0.1 follow-on)

- **What happened:** `AGENTS.md` was tracked in git as `AGENTS.MD` — an uppercase
  file extension — while every other markdown file in the repository used
  lowercase, and while `ARCHITECTURE.md` §3's layout tree names it `AGENTS.md`.
  The layout validator added earlier in this phase, which parses that tree and
  asserts every path it names exists, passed on every local run.
  It would have failed on **every** CI run of the same commit, on `ubuntu-latest`,
  because `_ROOT / "AGENTS.md"` does not resolve on ext4 when the file on disk is
  `AGENTS.MD`.

  Found while committing unrelated work, not by a gate. The sequence was:
  `git status` reported a clean tree, so the file looked tracked and current;
  `git show HEAD:AGENTS.md` failed with *"path exists on disk, but not in
  'HEAD'"*, which is the message git gives when the name differs in case. The
  check that located it was comparing the git index against the layout tree
  entry-by-entry rather than asking `Path.exists()`.

- **Why it is a problem:** The validator was *weaker on the machine that ran it
  most often than on the machine that runs it in CI.* `pathlib.Path.exists()`
  resolves case-insensitively on NTFS and case-sensitively on ext4, so the same
  assertion had two different meanings depending on where it executed. A gate
  whose behaviour depends on the filesystem it runs on is not a gate; it is a
  coin flip that lands green on the developer's desk.

  The specific damage is a **latent red build**. The commit that introduced the
  validator (`e4011eb`, the v1.0.0 README) is the same commit that introduced the
  failure, so CI has been failing — or would have been, on the first run since —
  for a reason that has nothing to do with anything anyone changed. The next
  person to push would have found an unexplained failure in a check they had
  written, on a file they had not touched, and the cheapest available response
  would have been to delete the check.

  It is also the fourth instance of the same shape in this repository, which is
  what makes it worth more than a one-line `git mv`: a document or a check
  asserts something about the filesystem, and nothing verifies that the
  assertion is true *on every filesystem the project runs on*.

- **How we fixed it:** `git mv AGENTS.MD AGENTS.md`, in two steps, because a
  case-insensitive filesystem cannot perform a case-only rename in one. The
  intermediate name is what makes it work: the first move gets the file off the
  tracked name, the second puts it back under the correct casing.

  The fix that matters is in the check, not the filename.
  `test_architecture_layout.py` no longer calls `Path.exists()`. It walks the
  path one component at a time through `os.listdir()` and compares each part
  against the directory's actual entries as exact strings, which behaves
  identically on NTFS and ext4. A developer on Windows and a runner on Linux now
  get the same answer to the same question.

  > **Superseded.** `test_architecture_layout.py` was deleted on 2026-10-02 when
  > the build-phase documents were extracted from the repository; the reasoning
  > above is left as the record of how it was fixed. See *"A quality gate that
  > could only fail on a Markdown file"* at the end of this file.

  When a path fails the exact check but succeeds a case-insensitive one, the
  failure is reported as a *spelling* problem and names what the file is actually
  called — `"AGENTS.md (declared as a file, but the file on disk is spelled
  'AGENTS.MD' - a clone on a case-sensitive filesystem will not have this path)"`.
  On a case-insensitive filesystem "not on disk" and "spelled differently" are
  indistinguishable by probing, and a reader left to guess which one occurred
  will guess wrong.

## 26. Watch Scope And Grant Disagree, And Neither Test Compares Them (v1.0.1 follow-on)

**Status of this entry, stated before anything else: this is a reconstruction,
not a verbatim record.** It was produced by reading two manifests and a
Kubernetes authorisation rule on **2026-10-01**. Nothing was deployed, no pod was
run, no `LIST` was observed, and **no forbidden response was captured**. The
mechanism is standard Kubernetes behaviour; the specific behaviour of this
deployment has not been reproduced. Everything below is a deduction from a
mechanism, and the corresponding `ROADMAP.md` box `ENV-2.1` is open for that
reason.

### Watch scope and RBAC grant were never compared to each other (Milestone 3)

- **What happened:** `deploy/sentinel.yaml` sets `WATCH_NAMESPACE: ""`, which
  selects a cluster-wide informer and issues `LIST /api/v1/pods` against every
  namespace. `deploy/rbac.yaml` grants a **namespaced** `Role` in
  `srek3s-system` only - no `ClusterRole`, no `ClusterRoleBinding`, nothing
  anywhere in `deploy/` that grants a cluster-scoped read. A `Role` in one
  namespace authorises nothing in another, so the cluster-wide `LIST` the
  informer issues is unauthorised. The informer retries the forbidden `LIST` on
  its backoff, which means the visible result is **no incidents and no error** -
  indistinguishable, from outside, from a healthy Sentinel watching a quiet
  cluster.
- **Why it is a problem:** Three properties compound, and the third is the one
  that should have caught it.
  1. **The failure is silent, and silence is the system's healthy-looking
     state.** This is the same family as §12 (log-blindness), §16 (dedup
     suppression) and §24 (the port-forward that was never there): a defect whose
     observable result is that a real thing is not reported. Nothing in the
     running system distinguishes "nothing is wrong" from "I am not able to see".
  2. **The fix everyone reaches for first is the worst one available.** The
     obvious repair for "my Sentinel sees nothing" is to widen the grant - add a
     `ClusterRole`, bind the Role cluster-wide. That would make every existing
     RBAC test pass while converting the project into the thing `PRD.md` §5.2
     calls "the single highest-severity change available to this codebase". A
     trap whose most natural remedy increases blast radius is not a nuisance.
  3. **Both RBAC tests are individually correct and both pass.** This is the
     part worth writing down. `TestSentinelRoleGrantsNoMutatingVerb` asserts no
     write verb - true. `TestSentinelRoleGrantsWhatTheWatcherReads` asserts the
     grant covers the reads the watcher makes - also true, *for
     `srek3s-system`*. Both are scoped to the namespace the `Role` lives in, and
     **neither compares that namespace to the configured watch scope.** Two
     correct assertions over two correct manifests, wrong only in composition -
     and no gate in the repository asserts the composition, so no gate can fail.
- **How we fixed it:** **Not yet. That is the honest answer and it is the point
  of recording this before fixing it.** What has been done is documentation, so
  that the next operator meets the trap before it meets them: `PRD.md` A6,
  `ARCHITECTURE.md` §2.1, the callouts in `README.md` and `docs/runbook.md` §1,
  and open box `ENV-2.1`. The fix itself is two-sided and deliberately excludes
  a `ClusterRole`: scope `WATCH_NAMESPACE` to one namespace **and** place a
  matching `Role` + `RoleBinding` there, referring to the `srek3s-system`
  ServiceAccount. A deployment procedure that is not a code change is not a fix,
  and this entry does not claim one.

### The controls that were invalid, which is the part that generalises

AGENTS §5.6 requires recording controls that were invalid and not only the ones
that worked, so, plainly: **two controls existed, both ran, both passed, and
neither was about the thing that broke.** That is a different failure from §21,
where a control failed for the wrong reason. A control that is *silently out of
scope* is worse, because it produces the comfortable reading - green checks,
working system - rather than an alarm.

The obvious missing check is a cross-document assertion: read the namespace every
namespaced `Role` in `deploy/` is created in, read the value of
`WATCH_NAMESPACE` from `deploy/sentinel.yaml`, and require them to agree. Nothing
larger than that is required — both values are already in the tree the existing
manifest tests parse. It is stated here as the candidate, not as something that
exists.

Two smaller instances of the same shape, recorded because they are the same
mistake at lower severity:

- `deploy/rbac.yaml`'s comment cited `TestSentinelHasNoMutatingVerbs`, which does
  not exist (noted in ROADMAP's Definition of Done). A `-run` filter naming a
  non-existent test exits `0` printing `[no tests to run]` - a green result
  proving nothing. Already recorded there; repeated here because it is the same
  pattern: *a reference that reads as evidence and is not.*
- `ARCHITECTURE.md` §3 named `tests/fixtures/secrets_corpus.txt` and
  `internal/k8s/classify.go`, neither of which has ever existed, and no gate
  noticed for two milestones (Definition of Done, and the layout validator that
  now exists because of it). Same shape at a different layer: documents assert
  facts about each other, and nothing checks the assertions against reality.

### The generalisable form

*Checks that verify one half of a pair will pass while the pair is incoherent.*
Write the assertion that names the relationship, not just the parts. Every gate
here asks "is this manifest correct?" and none asks "do these two manifests agree
with each other?" - and the defect lives entirely in the agreement.

The sharper version, and the one worth carrying: **the most natural repair for a
silent permission failure is to widen permissions.** A system whose central safety
property is least privilege will, under pressure, be told to grant more, because
granting more is what makes the symptom go away. That is the argument for making
the *intended* grant legible enough that widening is visibly unnecessary - which
is what `docs/runbook.md` §1's per-namespace procedure is for.

---

## 27. The Race Detector Was A Host Property, Not A Code Property (v1.0.1 follow-on)

This entry is about a platform transition rather than a bug, and it is recorded
because the *documentation* of that transition is where the wrong lesson lives.

### `-race` was unavailable because the host was, and the host has changed (Milestones 1-3)

- **What happened:** For two milestones, `go test -race` could not be run on the
  development host, because the host was `windows/arm64` and the race detector
  needs ThreadSanitizer and cgo, neither of which exists there. GitHub Actions
  `ubuntu-latest` was therefore the sole passing authority, and every record -
  ROADMAP boxes `1.5`, `2.8`, `3.7.3`, `docs/lessons-learned.md` §15, and the
  `AGENTS.md` §4 note - says so. The gate was left **unticked** locally rather
  than ticked on an assumption, and that was the correct call: `AGENTS.md` §5.4
  forbids the alternative.

  The development host is now WSL2 running **`Fedora Linux 44 (aarch64)`**, kernel
  `6.18.40.1-microsoft-standard-WSL2`, with `gcc.aarch64` 16.2.1 installed. cgo is
  therefore available, which is the host requirement the race detector had, and
  `go test -race` is now **runnable and locally verifiable** on this machine. This is
  the project's first `linux/aarch64` host. What it is *not* yet is a recorded local
  result: the gate has to be run before anyone cites it. `ROADMAP.md` box `ENV-1.2`
  claims the **capability** and says so in those words; no box claims a local pass.
- **Why it is a problem:** Not because the change is bad - it is strictly an
  improvement - but because the *wording* around it is now wrong in two specific
  ways, and both are the kind that get copied forward.
  1. **`-race` availability was never a property of the code.** It was a property
     of the machine, and the documents described it in the present tense as though
     it were a standing constraint of the project. "GitHub Actions is the sole
     authority" reads as an architectural fact and is a statement about Windows.
     An agent reading it a year from now on a Linux host would report a
     locally-verifiable gate as blocked - the exact "blocked dependency" fiction
     `AGENTS.md` §5.4 exists to prevent.
  2. **The temptation is to delete the historical record.** The clean-looking
     move is to strike every mention of `windows/arm64` and the standing
     constraint, leaving a tidy document. That would be the worst outcome. The
     recorded results are the evidence for how this project has behaved over four
     milestones, §15 is built entirely on a host/CI divergence, and the CI run
     IDs are the only proof that the race gate was ever green. Superseding them
     would destroy the record to improve the prose.
- **How we fixed it:** By **annotating, not editing**. `AGENTS.md` §4 keeps the
  original note verbatim and adds a dated amendment that scopes the change to
  *local runs only*; `AGENTS.md` §5 rule 8 now makes non-destruction of recorded
  history a standing instruction rather than a habit. The environment of record is
  pinned as `ENV-1.1`/`ENV-1.2` in `ROADMAP.md` with the platform of every
  measurement named; `ARCHITECTURE.md` §6.5 carries a note that its `windows/arm64`
  throughput figures are historical and unaltered, with an explicit refusal to
  claim a `linux/arm64` number that was not measured; §9.1 states the split
  authority in a table. **CI on `ubuntu-latest` remains the platform authority for
  every published figure.** A local pass is additional evidence, never a
  substitution, and no CI result recorded anywhere in this repository is
  withdrawn.

  One consequence is deliberately left as an **open** box rather than quietly
  fixed: the `windows/arm64` throughput figures (`~187,000` lines/sec and the
  intermediate 7,900 / 18,700) have **not** been re-measured on this host, so no
  `linux/arm64` performance claim is made anywhere. `ENV-2.10` re-runs the
  benchmark and records a new figure *with the platform named*, rather than
  overwriting the old one.

### The generalisable form

*When the environment changes, the question is not "which statements are now
false" but "which statements were always about the machine rather than the
system".* The second question is harder, and it is the one worth asking: it
separates a genuine constraint from a temporary condition that happened to be
written down in the present tense.

The pairing is with §15, and the two are the same subject from opposite ends. §15
is a `type: ignore` that was correct on Windows and fatal on Linux - the local
machine running a configuration the grader never sees. This is the same divergence
resolved: the local machine now runs a configuration that *is* graded, which is
why a local pass is worth having and still is not the published number. Both are
the reason `AGENTS.md` §4 keeps the platform named in every gate command rather
than letting "locally" stand in for it.

### The requested library and the model name were both already dead (Milestone 3)

- **What happened:** `agent/llm.py` was to be wired to `google-generativeai` with
  `gemini-1.5-flash`, per an explicit instruction. Both names were already
  unusable. The package's own metadata carries
  `Development Status :: 7 - Inactive`, and
  `ai.google.dev/gemini-api/docs/migrate` says to migrate to `google-genai`. The
  model is absent from the deprecation table entirely - not even as
  deprecated-with-a-shutdown-date, which is how already-retired models are still
  listed - so `gemini-1.5-flash` has been shut down and returns `NOT_FOUND`.

- **Why it is a problem:** Following the instruction literally would have produced
  code that passes every offline gate and fails on first contact with the API. The
  `type: ignore` on the import, the lazy-import guard, the timeout, the schema
  check - all green, because none of them execute the call. A spec that names a
  dead dependency has a half-life, and the failure surfaces in someone else's
  incident window.

- **How we fixed it:** Used `google-genai` (GA, and ships `py.typed`, so `mypy
  --strict` checks the call rather than `Any`), defaulted the model to a 3.x Flash,
  and made the model name overridable via `GEMINI_MODEL` because fleet
  availability is Google's fact and not something a repository should hard-code as
  eternal. The SDK and model choices are documented at their definitions in
  `agent/llm.py`, each citing what was read and when.

### A missing API key is a blocked dependency, not an invitation (Milestone 3)

- **What happened:** The live LLM detonation was specified as passing
  `GEMINI_API_KEY` "securely from the host environment". No such variable was set,
  in no shell profile, in no `.env` file, and no SDK was installed. The host
  resolves `generativelanguage.googleapis.com`, so the blocker is a missing
  credential and not a missing network.

- **Why it is a problem:** The two available shortcuts were to fabricate a key
  (which fails at the provider) or to hand-write a JSON blob and present it as
  Gemini's output (which is worse - it is fabricated evidence presented as an
  observation, which is precisely what this repository exists to prevent).

- **How we fixed it:** Every structural property was verified by capturing the
  outbound request through a stubbed `genai.Client`, which is evidence about *this
  code*; the live call is reported as **BLOCKED**, and `ARCHITECTURE.md` §5.5.2
  states in place that no adversarial payload has been sent to Google. Nothing in
  the committed tree asserts a model response was observed.

- **The distinction worth keeping:** capturing a request proves the code sends
  what it claims. It says nothing about what the provider does with it. Those are
  different claims and only one of them was available.

### The injection payload had no path to the model, so the test could not have tested it (Milestone 3)

- **What happened:** An adversarial plan required planting a prompt injection in a
  stack trace and proving Gemini ignores it. The payload was built and the traps
  fired as expected at the scrubber (`aws_access_key_id`,
  `basic_auth_url`, `generic_secret_kv` all found; `AKIA` absent from the
  report). Then the prompt was inspected - and none of the seven log lines were in
  it. `evidence_lines()` emits `scrubbed_log_lines=<count>`, a number. The log
  *text* has never reached the model, by the original shape of that function.

- **Why it is a problem:** The planned test would have passed for the wrong
  reason. "Gemini ignored the injection" and "the injection was never sent" are
  indistinguishable from the outside, and only one of them is the property anyone
  thinks was demonstrated. A vacuous pass here is worse than no test: it would be
  filed as evidence that the `system_instruction` separation works, and it would
  be filed without ever having been under load.

- **How we fixed it:** Verified by inspection rather than assumed, then made the
  fact explicit instead of leaving it to be discovered later: the behaviour is
  now a named constant, `prompt.LOG_TEXT_EVIDENCE_ENABLED`, documented at
  `evidence_lines()` with what widens it and what becomes load-bearing when it
  does. The secret and injection both reach the prompt when the flag is on, and
  the `system_instruction` separation was re-confirmed to hold in that widened
  configuration. Separately, `test_the_behavioural_rules_are_not_in_the_prompt`
  got a negative control that concatenates `SYSTEM_INSTRUCTION` back into the
  prompt; the guard fired, so the guard is not vacuous.

- **The generalisable form:** Before claiming an adversarial control proved
  anything, check that the attack **reaches** the thing under test. A test whose
  subject never receives the payload is a test of the plumbing, and it will read
  exactly like a pass.

### Four defects that only a live API call could find (Milestone 3)

Every gate was green and the suite passed 768 tests before the first real Gemini
request was made. None of the four below were visible offline, and none would
have been.

- **What happened:**

  1. **The narrow schema and the strict decoder were mutually incompatible.**
     `gemini_response_schema()` permits two fields because the model does not
     decide authority; `decode_completion` validated against the full
     `TriageResponse`, which requires eight field groups. A model that obeyed the
     schema perfectly failed with eleven validation errors. Two halves of one
     design, never connected.
  2. **Log text overflowed a schema ceiling.** With `SREK3S_LOG_TEXT_EVIDENCE`
     enabled, `evidence_lines()` emitted 23 items against `RootCause.evidence`'s
     `max_length=20`, and the request returned **HTTP 500** with a Pydantic error
     raised deep inside response construction. No offline test caught it because
     nothing offline turns the flag on.
  3. **A working model was reported as a refusal.** 3.x Flash models reason
     before answering and charge reasoning against `max_output_tokens`. At a tight
     budget the candidate finished `MAX_TOKENS` with no text part, which the code
     reported as "it may have refused" — sending an operator hunting a jailbreak
     that had not happened.
  4. **An exhausted quota was reported as load-shedding.** A burst of test calls
     returned `429 RESOURCE_EXHAUSTED`. The retry classifier listed 429 as
     transient, so it retried three times at 1.5s intervals and then named the
     cause "the provider is load-shedding" — pointing an operator at the wrong
     system entirely.

- **Why it is a problem:** All four are invisible to a green suite, and three of
  them produce a *confidently wrong story* rather than an obvious failure. Defect
  2 is the worst class: the agent had already decided the incident correctly and
  then failed to answer because of an unrelated bound. Defects 3 and 4 are worse
  in a different way — they do not fail loudly, they misattribute.

- **How we fixed it:**

  1. `decode_narrative` + a `ModelNarrative` model, so the decoder validates
     exactly what the schema asked for. A test asserts the two field sets are
     equal, with a negative control that widens one side and confirms the guard
     fires.
  2. `MAX_EVIDENCE_LINES` and **tail-first** truncation, because a crashing
     container writes its traceback last. Taking the head would fill the budget
     with startup banners and drop the exception. Truncation is declared in the
     output, since a silently shortened log reads to a model as a complete one.
  3. `thinking_budget=0`, which also restores the meaning of `temperature=0.0`:
     leaving reasoning enabled lets two runs over identical evidence differ in
     ways 0.0 does not control. `_diagnose_empty` now reads `finish_reason` and
     names budget exhaustion, safety blocks, and refusals separately.
  4. Classification by the SDK's **status name**, not the integer — 429 means
     both a momentary rate limit and a permanently exhausted quota, and only
     `RESOURCE_EXHAUSTED` distinguishes them. 429 is no longer retried; the
     message names quota exhaustion rather than blaming the request or the key.

- **The generalisable form:** A green suite proves the pieces are internally
  consistent. It says nothing about whether the pieces agree with an *external*
  contract — an API's schema, its token accounting, its error taxonomy. Those are
  verified only by calling it. Three of these four were a wrong *explanation* of
  an observed symptom, which is the failure mode a test suite structurally
  cannot catch.

### A field that was overwritten two frames later (Milestone 3)

- **What happened:** `triage._escalate` assigns
  `response.rca_markdown = warroom.render_markdown(dispatch)` — a **wholesale
  replacement**. The model's analysis was appended inside `_tier2_response`,
  before that assignment, and was therefore discarded every time. The request
  returned **HTTP 200** with a complete, correct, deterministic RCA, and the model
  analysis was simply absent. The summary survived, because it is a different
  field, which made the bug look like a partial success.

- **Why it is a problem:** Total and silent. The model would have been called,
  billed for, and paid out on latency, with zero observable effect — a feature
  that ships working-looking and does nothing. Two independent controls caught it:
  flake8's F841 on an earlier revision of the same code, and a negative control
  asserting the fallback path. Neither was the test I would have written.

- **How we fixed it:** The model section is appended in `_escalate`, *after* the
  dispatch render, and `_model_summary` / `_model_rca_section` fetch separately so
  neither can be lost to the overwrite. The composite is re-scanned as a whole
  (I-B6), because a secret can be assembled from a model paragraph and a
  deterministic line that are each individually innocent.

- **The generalisable form:** When a field is assigned more than once on a path,
  find every assignment before reasoning about any of them. A value computed in a
  constructor is not thereby in the object that leaves the function.

### The agent pod could not reach the internet, and the policy said it must not (Milestone 3)

- **What happened:** With `GEMINI_API_KEY` mounted from a Secret, every completion
  failed with `OSError: [Errno 101] Network is unreachable`.
  `deploy/agent.yaml`'s `srek3s-agent-egress` NetworkPolicy permitted DNS to
  kube-system and nothing else — correct for an agent that needs no model, and
  incompatible with one that has an API key.

- **Why it is a problem:** The degradation is **silent and total**. The agent
  answered `/healthz` and `/readyz` with 200, triaged every incident, and produced
  a complete and plausible deterministic RCA — with no model involved and nothing
  in any log to say so. A credential mounted and a client constructed are both
  visible in the pod spec and the process; neither implies a request was sent.

  Two hypotheses had to be separated before the cause could be named, and the
  first was wrong. "Network unreachable" reads like a policy DROP, but a dropped
  packet **times out**; `EHOSTUNREACH` means the kernel had no route. The
  distinguishing test was a throwaway pod in the same namespace **without** the
  SREK3S labels, which the policy's `podSelector` does not match: it reached
  `generativelanguage.googleapis.com:443` (`TCP_OK`) while the agent could not.
  That also disproved the second hypothesis, that k3s's default flannel ignores
  NetworkPolicy — on this cluster the dataplane enforces them.

- **How we fixed it:** Added one egress rule — TCP 443 to `0.0.0.0/0` — to
  `deploy/agent.yaml`, with the cost stated at the rule: **the pod can now open a
  TLS connection to any host on 443.** The narrower alternative does not exist
  here. A NetworkPolicy `to:` selects a namespace, a pod set, or a CIDR, and
  Google's endpoint is a large geographically-varying Anycast set with no stable
  CIDR; a hand-maintained list would silently stop matching, which is exactly the
  "ephemeral address in a committed manifest" defect `deploy/sentinel.yaml` was
  rewritten to eliminate. `deploy/sentinel.yaml` reaches its apiserver by `ipBlock`
  on the Service CIDR because that address **is** knowable; an external provider
  is not. A DNS-based egress gateway or a CNI with FQDN policy (Cilium) is the
  tighter answer and neither is available on this dataplane.

  Port 443 only, and UDP/TCP 53 elsewhere still refused. The agent holds no
  cluster credential (`automountServiceAccountToken: false`) and its only input is
  scrubbed telemetry, so this is not an exfiltration path for cluster secrets.

- **The generalisable form:** A credential in a pod and a client in a process are
  both *evidence of intent*. Neither is evidence that a request left. When an
  egress path is newly required, assert the connection rather than inferring it
  from the manifest.

### A chaos fixture passed every check while demonstrating the wrong failure (Milestone 3)

`deploy/chaos/real-crash.yaml` took four defects to become correct. Every one was
invisible to the structural gates, and three of the four produced a container that
crashed, exited non-zero, and emitted a Python traceback — so any assertion about
"did it fail" passed while the RCA described something else entirely.

1. **`restartPolicy: Never` made it UNDETECTABLE BY CONSTRUCTION.** The pod reached
   `Failed`, and the Sentinel emitted nothing with a completely clean log:
   `{"watcher_emitted":0,"dedup_admitted":0,"processed":0}`. Cause, read from
   source rather than guessed: `internal/k8s/watcher.go:236` deliberately DROPS a
   `Terminated` with a non-OOM non-zero exit, because Contract A's `reason` admits
   only `OOMKilled` and `CrashLoopBackOff`. Without a restart there is no
   CrashLoopBackOff. Correct behaviour, wrong fixture — and the most total
   possible silent failure.
2. **A `/tmp` marker file** raised `OSError: [Errno 30] Read-only file system`,
   because the pod sets `readOnlyRootFilesystem`. Real traceback, wrong cause.
3. **An apostrophe in a prose comment** — "the kubelet's backoff" — terminated the
   shell string wrapping `python -c '...'`, producing `IndentationError` in the
   *fixture* rather than the `KeyError` it exists to produce.
4. **No `set -e`**, so the shell continued past Python's failure and the trailing
   `echo` succeeded: a container that raised a `KeyError`, wrote a full traceback,
   and exited **0**. Found by the new test, not by the cluster.

- **How we fixed it:** `agent/tests/test_chaos_fixtures.py` now **executes** the
  fixture's inline script locally and asserts the exception type is the one under
  test, that no incidental error appears, that there are at least two traceback
  frames, and that the exit code is non-zero. Plus shape assertions for the
  detectability properties. Four negative controls plant each defect and confirm
  the guards fire.

- **A negative control that failed for the wrong reason.** The first guard for
  defect 2 asserted only that `Read-only file system` was absent from the output —
  and was **vacuous**. On the test host `/tmp` is writable, so the planted
  `touch` SUCCEEDED, raised nothing, and the guard passed with the defect present.
  The real error only occurs in-cluster. The guard was replaced with a direct
  assertion that the script performs no filesystem write at all, which is both the
  requirement and the thing that was wrong. Recorded because a control that passes
  for the wrong reason is worse than no control: it reads as a pass.

- **The generalisable form:** An inline script in a manifest is code, and it is not
  reviewed as code until something executes it. Executing it locally costs
  milliseconds and would have caught all four before a pod was scheduled. The
  second lesson is about detection, not fixture shape: **"the workload failed" is
  not "the workload failed for the reason under test"**, and only the exception
  type distinguishes them.

### A `valueFrom` env var broke every test that read env as literals (Milestone 3)

- **What happened:** Adding `GEMINI_API_KEY` to `deploy/agent.yaml` via
  `valueFrom.secretKeyRef` failed two tests with `KeyError: 'value'`. Both built
  their environment map as `{entry["name"]: entry["value"] for entry in env}`,
  which raises on the first variable sourced from a Secret or ConfigMap rather
  than an inline literal.

- **Why it is a problem:** The error pointed at the **manifest**, and the manifest
  was correct. Anyone reading that failure would have concluded the `valueFrom`
  block was malformed, "fixed" it by inlining a literal — and committed a
  credential into a tracked file. The failure mode of the test was a redirect away
  from the safest available action.

- **How we fixed it:** One `env_map()` helper, used everywhere, which maps a
  `valueFrom` entry to its **source** rather than crashing or dropping the key. A
  caller asserting on it now sees what the variable is bound to, which is more
  useful than either the old crash or a silent omission.

- **The generalisable form:** A helper that assumes the common case becomes a trap
  the moment the uncommon-but-legal one appears, and it fails in a way that
  misattributes the cause. `valueFrom` is not exotic; it is how every credential
  enters a pod.

## 28. A Runbook Describing A Defect That Was Fixed Four Milestones Ago (v1.0.2)

- **What happened:** `docs/runbook.md` §1 was rewritten to be scannable. Before
  restructuring it, five places still asserted that `deploy/sentinel.yaml` ships
  `WATCH_NAMESPACE: ""` and that the deployment "cannot watch anything" as
  committed. That was true when written. It stopped being true when the base
  manifest was changed to `srek3s-system` to match the namespaced `Role` — which is
  the fix recorded as `ENV-2.1`. The runbook was never revisited, so for four
  milestones it instructed a reader to go fix a defect that no longer existed, using
  a procedure for a condition that could no longer be observed.

- **Why it is a problem:** The cost is not the wasted reading time. It is that the
  runbook's whole argument for §1 — "if you see silence, suspect the scope/grant
  mismatch" — rested on the base state being broken. With the base fixed, the
  correct advice is the *pairing* ("compare these two fields"), and a reader who
  followed the stale text would have widened the watch scope to reproduce a defect
  they believed was still open, thereby **causing** the exact silence the section
  warns about. Documentation that is stale in the direction of a false alarm is
  worse than documentation that is absent, because it gets acted on.

- **How we fixed it:** All five sites rewritten to describe the invariant instead of
  the incident: the two fields agree as committed, breaking the pairing is silent,
  here is the field to compare, here is the assertion that now enforces it. The
  historical defect is described rather than deleted — `ENV-2.1` in `ROADMAP.md` and
  §26 of this file are the record, and neither is amended. The troubleshooting row
  in §6 was changed from a `kubectl auth can-i` invocation to a two-field
  comparison, because the command answered a question about the old state.

- **The generalisable form:** Fixing a defect and documenting the fix are separate
  acts, and only the first one has a test. A guard proves a *manifest* is correct;
  nothing proves a *document* still describes that manifest, because prose has no
  assertion to fail. When a fix changes shipped state, searching for the places
  that describe that state is part of the fix, not a follow-up — and
  `grep -rn '<the-old-value>' --include='*.md'` finds them in seconds, which a
  careful re-read of 1,492 lines of prose does not.

- **Also recorded, because it is the same defect in a different medium:** while
  fixing the runbook, the corrected text cited
  `test_the_watch_scope_is_inside_the_granted_namespace` as the assertion enforcing
  the pairing. **That test did not exist.** It had been intended in a previous cycle
  and never written, and the sentence asserting it was a fabrication with a
  plausible-looking name in it — the exact shape `AGENTS.md` §5.7 warns about. It
  was caught only because the name was grepped before being trusted. The test was
  then written, given a negative control, and plant-tested against the real manifest
  (§29). **A documentation claim about a test is a claim that can be checked in one
  command, and the fact that it reads like its neighbours is not a reason to skip
  the check.**

## 29. A Negative Control That Duplicated The Assertion Instead Of Exercising It (v1.0.2)

- **What happened:** The first version of the control for the watch-scope guard
  (`test_control_watch_scope_check_fails_on_an_ungranted_scope`) built its own
  offender list inline:

      offenders = [ns for ns in ("", *sorted(granted)) if not ns.strip()]
      assert offenders == [""]

  and then separately asserted that `"sentinel-chaos"` was not granted. It passed.
  It was also worthless: the inline list comprehension shares no code with the real
  comparison, so the control proved that *the control's own copy* of the logic
  detects an empty scope. It would have passed unchanged if the real
  `ungranted_scopes()` were deleted outright.

- **Why it is a problem:** This is the vacuous-control trap in its purest form, and
  it is attractive precisely because it looks thorough — it has a fixture, an
  injected value, and an assertion. What it lacks is the one property that makes a
  control worth having: that it fails when the thing it guards fails. A control
  carrying its own logic is a second opinion nobody asked for, and it raises the
  count of green tests without raising the count of verified behaviour.

- **How we fixed it:** Extracted the comparison into
  `ungranted_scopes(scope, granted) -> list[str]`, called by both the real test and
  the control, so the control exercises the shipped function with the value that
  actually shipped (`""`) rather than an invented stand-in. It now also asserts the
  **positive** case — that a granted namespace is *not* flagged — because a
  comparison that flags everything passes a negative control perfectly while flagging
  a correct deployment as broken on every run.

  The in-file control was still not sufficient evidence, so the guard was
  additionally **plant-tested**: `deploy/sentinel.yaml` was edited in place to carry
  the historical `value: ""`, the real test was run, and it failed; the file was
  then restored with `git checkout --` rather than an in-memory copy, so an
  interrupted run leaves a dirty tree instead of a clean-looking wrong one. Observed
  result: `1 failed, 25 deselected` while planted, `2 passed, 24 deselected` after
  restore, and the restored file compared byte-identical to the committed one.

- **The generalisable form:** A negative control must exercise the unit under test,
  not paraphrase it — if deleting the real function leaves the control passing, the
  control is measuring itself. And a control that proves only *failure is
  detectable* is half a control: a guard that fails closed on everything satisfies it
  perfectly while being useless, so the control needs a case the guard must
  **pass**.

## 30. `git checkout --` In A Plant Script Ate Four Milestones Of Uncommitted Work (v1.0.2)

- **What happened:** To prove the new documentation-link guard was not vacuous, a
  script planted a broken anchor in `docs/runbook.md`, ran the test, and then
  restored the file with `git checkout -- docs/runbook.md`. That runbook was
  **715 lines of unstaged edits** — a navigation table, a condensed RBAC section,
  three corrected stale passages. Every one of them was discarded. The restore came
  from the *index*, which still held the committed revision, so the file went back
  four milestones into the past and `git status` showed a clean, confident, wrong
  file.

- **Why it is a problem:** `git checkout --` reads as "undo my temporary edit" and
  is actually "restore this path to the index". Those coincide only when the file
  has no uncommitted changes, which is exactly the case a plant test does **not**
  guarantee — a plant test is run specifically when the file is being worked on.
  The failure is silent, the script exits 0, and the printout says "restored":
  identical to committed = False, but only because the comparison happened to be
  there. Without that line, four milestones of work would have been reported as
  restored and discovered later, or not at all. The earlier plant on
  `deploy/sentinel.yaml` succeeded with the same code **because that file had no
  unstaged edits** — the technique was validated by luck and then reused.

- **How we fixed it:** The runbook edits were redone and verified with marker
  greps rather than a line count. The restore strategy is now the rule: **a plant
  script must restore the exact bytes it read, from memory, and then assert the
  file is byte-identical to what it started as.** `git checkout` is acceptable only
  when the script has first confirmed `git diff --quiet -- <path>`, i.e. that the
  file is clean and there is therefore nothing to lose. The assert-the-restore step
  is not optional bookkeeping — it is the only thing standing between a verification
  technique and silent data loss.

- **The generalisable form:** Any technique that mutates state to prove a check can
  fire is a **destructive** technique, and its safety depends on a precondition that
  is invisible in the code that performs it. "This worked last time" is the weakest
  possible evidence, because the precondition was different last time. The general
  fix is to make the script *prove* it restored what it found, rather than trusting
  that it did — the same rule this file keeps arriving at for negative controls. A
  verification step that can destroy the thing it is verifying needs a stronger
  completion check than one that only reads.

## 31. A Negative Control That Could Only Ever Pass On NTFS, In A Commit About Windows Case-Folding (v1.0.2)

- **What happened:** Merging `fa1e89f` (pushed directly to GitHub, never run locally
  on this host) surfaced a failing test:
  `test_the_case_exact_check_fails_on_a_wrongly_cased_path`. That commit is *about*
  the fact that `Path.exists()` folds case on Windows and does not on Linux, it
  rewrites `_exists_exact` to walk `os.listdir()` component by component, and it
  adds this control. On this host — Fedora 44, ext4 — the control fails.

  Two assertions are host-dependent, and both require the filesystem to **fold**
  case:

      assert (_ROOT / flipped).exists(), "control is vacuous on a case-insensitive
                                          filesystem: ..."

      assert "spelled" in reported[0], ...

  The first is visible. The second was **masked by it** and only appeared after the
  first was worked around — which is the more dangerous half, because it is not a
  precondition at all but an assertion on output. `_unresolved` reaches the spelling
  branch only when `not _exists_exact(path)` **and** `target.exists()`, so on ext4
  the diagnostic is unreachable by construction and `"spelled" in reported[0]` can
  never be true. The control could only ever pass where case folds.

- **Why it is a problem:** CI runs on `ubuntu-latest` — ext4. So this control fails
  on **every CI run**, in the one commit whose entire subject is that the gate was
  weaker on the machine that ran it than on the machine that runs it in CI. The
  commit message reasons correctly about the mechanism and then encodes the very
  assumption it had just argued against, as a hard `assert`. Its own post-mortem
  even records that an earlier version of this control "asserted a case-insensitive
  probe succeeds, which holds on Windows and would raise FileNotFoundError on Linux,
  erroring at collection instead of tripping the guard" — so the hazard was
  identified, documented, and then reintroduced in the same shape one commit later.
  Nothing local could have caught it: **the commit was never run on a
  case-sensitive filesystem.**

- **How we fixed it:** The control is split. Host-independent assertions stay
  ungated and run everywhere — `_exists_exact` resolves the real name, rejects the
  case-flipped one, and an absent path is reported as *absent*. The two
  host-dependent assertions move behind a single `if not (_ROOT / flipped).exists():`
  gate that calls `pytest.skip` with a reason stating it is a **BLOCKED DEPENDENCY,
  not a pass**, which diagnostic is unreachable here and why. The skip branch
  gained its own assertion (`"not on disk" in reported[0]`), so gating costs no
  coverage rather than simply declining to run.

  **What has not been verified:** the gated half — that the report names the
  spelling problem and names the file's real spelling — cannot be observed on this
  host and was not observed. It remains unexercised here, exactly as it was
  unexercised before this change; what changed is that it no longer fails a suite it
  has no way to pass.

  **SUPERSEDED BY OBSERVATION (2026-10-01).** The inference in this entry that CI
  would fail is no longer an inference. Run #68 on `fa1e89f` was read from the
  GitHub API and it failed, in CI, at exactly this test:

      FAILED agent/tests/test_architecture_layout.py::test_the_case_exact_check_fails_on_a_wrongly_cased_path
      AssertionError: control is vacuous on a case-insensitive filesystem
      1 failed, 766 passed, 3 skipped

  Run #69, on the merge that restructured this control, is green across all three
  jobs. The mechanism predicted here from a local measurement was confirmed by the
  thing it predicted. See §32.

- **The generalisable form:** **A control inherits the host assumptions of the
  mechanism it controls.** When a control's purpose is to demonstrate that check A is
  stricter than probe B, the control needs a filesystem where B accepts the input and
  A does not — and if that host property does not hold, the control is asserting
  something about the *host*, not about the code. The tell is an assertion whose
  failure message describes the machine rather than the defect. And the second
  lesson is about masking: this one had two independent host-dependent assertions,
  and fixing the visible one revealed the hidden one. **Fixing a failing test
  without asking what else was behind it is how a masked defect gets promoted to
  "fixed".**

## 32. A CI Failure Blamed On The Merge That Fixed It (v1.0.2)

- **What happened:** A request arrived asserting that "the recent merge to main
  broke the GitHub Actions CI pipeline" and asking which step failed. The merge in
  question was `d90cf61`. The actual state, read from the GitHub API rather than
  assumed:

  | Run | SHA | Conclusion |
  |---|---|---|
  | #63–#67 | various | **failure** |
  | #68 | `fa1e89f` | **failure** |
  | #69 | `d90cf61` | **success**, all 3 jobs, every step green |

  Six consecutive red runs, all of them predating the merge. The merge is the
  first green run in seven. The premise was inverted.

- **Why it is a problem:** Not because the premise was wrong — that cost one API
  call to establish. Because the *correct* version of the report was already
  available and more valuable: run #68's log contains the literal failure that §31
  predicted, observed rather than inferred:

      FAILED agent/tests/test_architecture_layout.py::test_the_case_exact_check_fails_on_a_wrongly_cased_path
      AssertionError: control is vacuous on a case-insensitive filesystem
      1 failed, 766 passed, 3 skipped

  And §31 had been written as "That CI would have failed is inferred from the
  mechanism measured here; no CI run has been witnessed." It has now been
  witnessed. A merge presented as a regression invites a rollback of the fix, and
  the rollback would restore a control that cannot pass on any Linux runner.

- **How we fixed it:** Reported the divergence before acting on the request, with
  the run table as evidence. §31's inference is annotated as now-observed rather
  than edited to read as though it had always been. The work that was actually
  worth doing — hardening the control so it skips honestly on ext4 — had already
  been done in `d90cf61`, and CI agreed.

- **The generalisable form:** "The last change broke it" is the most common first
  report about a red pipeline and the most expensive thing to act on, because the
  most recent change is the one most likely to be *innocent* — a red run that
  predates it is a red run someone has been living with, and the newest commit is
  the easiest thing to revert. **Read the run list before the theory.** Six red
  runs ending at the previous commit and one green at the merge is a completely
  different problem from "the merge broke it", and only one of them is fixed by
  reverting.

## 33. A Step Named "Check" That Contained No Check (v1.0.2)

- **What happened:** Reading `release.yaml` as part of a CI review turned up a step
  named **"Check the tag against the committed image references"**. It greps the
  committed manifests, echoes them, prints a NOTE about the registry mismatch, and
  reaches the end of the script. There is no comparison. It has no branch that
  exits non-zero. It cannot fail, and it sits in the release path.

- **Why it is a problem:** It is the exact failure this file keeps recording, in
  the place where being wrong costs the most: a guard that cannot fail wearing the
  name of one that can. A reviewer skimming names — which is how workflows get
  reviewed — reads "Check" and moves on. Worse, its existence suggests the
  tag/manifest consistency problem is handled, and the day it is handled *wrong*
  the reader will not look for the second place.

  The honest constraint is that a real equality gate is unavailable: the manifests
  carry `registry.internal/srek3s-*:0.1.0` while a release publishes the tag, so
  asserting equality is a permanent red build over a documented registry mismatch.

- **How we fixed it:** Renamed to **"Report the committed image references (not a
  gate)"** and recorded, in the step itself, why it is a report and what would make
  it a real check. The asymmetry is now in the name and in the comment, so the next
  person is told what to do instead of what was assumed.

- **Also fixed in the same review: a check that counted instead of naming.**
  "Verify both images are multi-arch" asserted `len(manifests) >= 2`. A manifest
  list carrying two entries for the *same* architecture satisfies that, and the
  step's own comment claimed the guarantee was "a node that cannot use one of them
  fails visibly at pull time rather than running the wrong binary" — a claim that
  requires both architectures specifically. It now parses the `os/architecture`
  pairs and requires `linux/amd64` and `linux/arm64` **by name**. Verified against
  seven manifest shapes: amd64+arm64 passes, amd64-only, arm64-only, empty,
  platform-less entries, and **two amd64 entries** are all refused.

- **The generalisable form:** A threshold is not a specification. `>= 2` encodes
  "at least two of something"; "amd64 and arm64" encodes "both of these". They
  differ on exactly the input the check exists to catch. And a step's *name* is an
  assertion a reader will trust without reading the body — which makes a name that
  overclaims a defect in its own right, independent of whatever the body does.

## 34. An Embedded Script Written To Work Around Its Own Host, Then Shipped That Way (v1.0.2)

- **What happened:** While rewriting `release.yaml`'s manifest verification, the
  embedded parser had to avoid single quotes — it was being passed to
  `python3 -c '...'`, and a single-quoted shell string cannot contain one. The
  first draft solved this with a no-op:

      out.add(f"{p[chr(39)+chr(39)] if False else p['os']}/{p['architecture']}")

  It evaluates correctly. It is unreadable, it says nothing about why the
  constraint exists, and a later reader cannot tell it from a typo. In the same
  edit, `timeout-minutes: 20` was placed *after* `run: |`, putting a YAML key
  inside a shell script body where it would have executed as a command.

- **Why it is a problem:** Both would have been caught by the cheapest possible
  check — the workflow auditor, which already parses every `run:` block with
  `bash -n` — but it was not run until after both were written. The `chr(39)`
  construct is the more interesting of the two, because it is a *workaround that
  survives review*: it is valid, it produces the right value, and no test fails.
  The honest signal that it is wrong is that nobody could explain it, and I could
  not, which is the moment to remove the constraint rather than to encode it.

- **How we fixed it:** Removed the constraint instead of encoding it. The raw
  manifest JSON goes to a temp file and the parser is a `<<'PY'` heredoc — a
  *quoted* heredoc, which the shell does not interpret at all, so the Python can use
  whatever quoting it likes. That also matches the shape the surrounding comment
  already demanded for an unrelated reason (piping into a reader is a SIGPIPE race
  under `pipefail`), so the fix reduced the number of concepts rather than adding
  one. `timeout-minutes` moved above `run:`.

  Both scripts were then extracted from the shipped YAML and executed against
  real inputs: the parser against seven manifest shapes, and the CI skip ratchet
  against eight synthetic pytest reports. The ratchet run found two further holes
  — it passed a report containing `1 failed`, and passed one containing
  `3 errors` — both fixed and both now covered by a case.

- **The generalisable form:** **A workaround that cannot fail is not a working
  solution, it is an undocumented constraint.** When you find yourself encoding
  something bizarre, the question is not "what expression produces the value" but
  "why is the constraint here at all" — and the answer is usually that a different
  shape has no problem. Separately: a heredoc is the right tool for embedded code
  almost always, and the fact that this workflow already needed `pipefail`-safe
  capture meant the constraint-solving rewrite could *reduce* complexity instead of
  adding it. And an embedded script nobody can run locally is an untested script —
  extracting it from the YAML and executing it against real inputs is cheap, and it
  found two defects on its first run.
### A quality gate that could only fail on a Markdown file (Post-Milestone 4)

- **What happened:** the build-phase documents were extracted out of the repository
  into a gitignored `_scaffolding/` directory, and
  `agent/tests/test_architecture_layout.py` was deleted with them. That file was
  13 test functions and 15 collected assertions, and it was the **only** thing in
  the suite whose subject was prose: it parsed a layout tree drawn inside
  `ARCHITECTURE.md` and compared it to the filesystem in both directions. Moving
  the document turned it from 14 passed / 1 skipped into 15 failed with
  `FileNotFoundError`, which is what surfaced the coupling in the first place.

  The decision to delete rather than rewrite was made by reading every function's
  subject before touching it. Not one assertion read an RBAC verb, a tier
  decision, a patch or a redaction. Every mention of `internal/`, `deploy/` or
  `agent/` in the file was a docstring or a path string copied *out of* the tree
  being checked.

- **Why it is a problem:** a gate that fails only because a document drifted is not
  a safety gate, but it costs exactly what a safety gate costs — reviewer
  attention, and a build that cannot go green for a reason unrelated to whether
  the system works. The generalisable form: **ask what a check reads before
  defending it.** "It has lots of assertions and a negative control for each" is a
  description of effort, not of value. The question is whether the thing it
  inspects is a thing whose correctness anyone depends on. Here, the answer was no,
  and the check had been silently accruing credibility it had not earned.

- **How we fixed it:** deleted the file, and recorded the removal in three places
  so it cannot be silently undone. `CONTRIBUTING.md` states the new rule — every
  remaining gate reads code or a manifest, so the layout of `cmd/`, `internal/`,
  `agent/`, `deploy/` and `tests/` is free to change without a test failing.
  `README.md` keeps a rewritten paragraph explaining what the validator was and
  why it went, because deleting the explanation while deleting the thing is how the
  next person re-adds it. `.gitignore` records the reasoning next to the entry.

  The capability genuinely lost is named rather than glossed: bidirectional
  layout-drift detection. It caught a real bug once — a document naming two files
  that had never existed. But it caught a *documentation* bug, in a document that
  is no longer shipped, and the invariants in its neighbourhood were already
  covered against real inputs (`TestSentinelRoleGrantsNoMutatingVerb` parses
  `deploy/rbac.yaml`; `test_deploy_manifests.py` parses the hardening surface;
  `models.py` enforces I-B1 at construction).

- **Also worth recording:** the skip count fell 4 → 3 as a side effect, because the
  deleted file held the case-conditional skip. The CI ratchet permits a falling
  count and then *asks* for `EXPECTED_SKIPS` to be lowered. Leaving it at 4 would
  have worked and taught people to ignore the number, so it was lowered.

### An exception with no HTTP status was misread as permanent (Post-Milestone 4)

- **What happened:** the adversarial suite for the new OpenAI-protocol adapter
  (`agent/tests/test_llm_adversarial.py`) drove the real SDK over an
  `httpx.MockTransport` and asserted that a read timeout is retryable. It failed.
  `_is_transient_openai` classified `APITimeoutError` as **permanent** and raised
  on the first attempt.

  The cause was the branch structure, not a typo. The function read a status code,
  found none — because a timeout never got far enough to have one — and fell
  through to `isinstance(exc, (TimeoutError, ConnectionError, OSError))`, which
  the SDK's exception hierarchy does not satisfy. The only class that did match was
  a builtin `OSError`, which no HTTP SDK raises.

- **Why it is a problem:** the wrong direction in both senses. The caller lost a
  narrative a second identical attempt would have supplied, and the error message
  told an operator their **configuration** was at fault when the endpoint was
  merely slow. That is the same failure mode as the retired retry-429 bug recorded
  elsewhere in this file: a diagnosis that points at the wrong system. Both were
  cases of the adapter *guessing* rather than *observing*.

  The deeper lesson is about test shape. Every pre-existing provider test used a
  stub that either succeeded or raised an exception carrying a status. A stub that
  cannot represent "the server never answered" is not a neutral stub — it is a stub
  that has pre-decided the question. The defect was invisible not because it was
  subtle but because the harness had no vocabulary for it.

- **How we fixed it:** transport failures are now identified by walking the MRO for
  a known base class (`TransportError`, `TimeoutException` for httpx;
  `APIConnectionError`, `APITimeoutError` for the SDK) rather than by
  `isinstance` against builtins. Name-matching the MRO was necessary because the
  SDK is imported lazily, so a module-scope `isinstance` would make importing
  `providers.py` fail on a host without the SDK — exactly what the lazy import
  exists to prevent — and it also means a base class is listed once instead of
  every leaf that inherits from it.

  A regression test now pins the full classification matrix: transport errors
  retry, status-coded 5xx retries, 429 and 4xx do not, and an exception the adapter
  does not recognise does **not** retry. That last row is deliberate: guessing
  wrong in the other direction costs a retry storm, and an unrecognised error
  getting three attempts is worse than one lost narrative.

## 35. One Adapter Class Serving Three Providers Is A Silent Substitution Waiting To Happen (v1.0.3)

- **What happened:** NVIDIA NIM was added the way the design intends — as a
  *configuration* of `OpenAIProvider` rather than a third adapter class, because it
  speaks the OpenAI chat-completions protocol. Three table entries and one branch in
  the factory. That is the design working.

  Then two bugs appeared that no offline test could see, both the same mistake:

      model_name  ->  resolve_model(PROVIDER_OPENAI, env)     # asked NIM for gpt-4o-mini
      complete()  ->  _api_key_for(PROVIDER_OPENAI, env)      # reported a missing key

  An NVIDIA deployment configured with `LLM_PROVIDER=nvidia` and a valid
  `NVIDIA_API_KEY` was asking NVIDIA's endpoint for an OpenAI model name, and
  reporting that its credential was missing while holding a working one. Both
  produced no error anywhere: `gpt-4o-mini` is a plausible string, `OPENAI_API_KEY`
  is a plausible variable name, and every existing test still passed.

- **Why it is a problem:** The abstraction that removes vendor lock-in is the
  abstraction that hid this. When one class equals one provider, reading a
  per-provider fact off `self` is safe by construction and reads cleanly. The moment
  one class serves several providers, every such read is a silent substitution — and
  the substitution is between two *valid* values, which is why nothing complains.
  Neither bug degraded loudly. The credential one degraded into exactly the
  fail-closed behaviour the system advertises (deterministic prose, no escalation
  change), which is the best possible outcome and still nearly invisible.

- **How we fixed it:** Both reads now resolve from the environment, never from the
  class:

      provider = resolve_provider_name(self._env) if self._env else PROVIDER_OPENAI

  The `if self._env` guard is load-bearing for a second reason: an *empty*
  environment has no `LLM_PROVIDER`, so `resolve_provider_name` returns its default
  (`gemini`) and the OpenAI adapter would name `GEMINI_API_KEY`. That surfaced as a
  real test failure — `test_providers.py` asserts the error names `OPENAI_API_KEY`
  for a direct construction — which is the control working.

  `agent/tests/test_nvidia_provider.py` then asserts what the SDK is **handed**: the
  `model` on the outbound call and the `api_key` the client was constructed with. A
  property can report the right string while the call sends another, so asserting
  the property would have missed both bugs. Four of the controls were plant-tested by
  reverting the fix and confirming they went red; the credential fix takes three
  down. The file restores itself byte-for-byte, verified by hash — post-mortem 30 is
  about what happened the last time a plant script cleaned up after itself.

## 36. A Default That Fails On Every Call Is A Deployment, Not A Default (v1.0.3)

- **What happened:** `meta/llama-3.1-70b-instruct` was chosen as the NVIDIA default
  because it was the model named in the request and it is a real, widely served
  model. It returns:

      HTTP 410 Gone — "has reached its end of life on 2026-08-26 and is no longer
      available"

  A default that 410s on every call is not a permissive default. It is a
  configuration that only appears to work, because the fail-closed degradation is
  indistinguishable from having no key at all: deterministic prose, no tier change,
  no error, no log line saying the model was never consulted.

  The neighbouring hazard is worse and is not this repository's to fix: most
  `nvidia/*` models on NIM answered `404 Function '<uuid>': Not found for account`
  for the same credential that could list 81 models. **Catalogue access and model
  entitlement are different things.** So even a model that is not retired may be
  invisible to the key that can see it listed.

- **Why it is a problem:** A default is only ever exercised when nothing is
  configured, which is precisely when nobody is watching, and a wrong default
  presents as a working system. This one was only findable by calling the endpoint.
  No amount of offline validation could have caught it: the string is well-formed,
  correctly namespaced, and looks exactly like every other model id in the file.

- **How we fixed it:** The default is now a model verified to return
  schema-conformant JSON against this deployment, the retired id is named in a test
  as a specific historical fact rather than left implicit, and the runbook tells
  operators to **pin** `NVIDIA_MODEL` and — before concluding a credential is broken
  — to check the startup line for the resolved model. The entitlement hazard is
  recorded in `providers.py` and the runbook too, because the next operator to hit
  a 404 will otherwise assume the adapter is at fault.

## 37. The RCA Was Ungrounded Because The Harness Never Sent The Evidence (v1.0.3)

- **What happened:** Asked whether the model grounds its RCA in the real traceback,
  a harness produced an answer about `OOMKilled` in namespace `payments` when the
  evidence contained `KeyError: 'cust_8817'`, and reported that as a grounding
  failure. It was not one. Three separate harness defects stacked:

  1. The log-injection step searched the fixture for a dict with a `"logs"` key.
     The payload field is `scrubbed_logs`, so the injector wrote **nothing**, in
     silence, and the model was shown the fixture's original OOM evidence.
  2. `IncidentPayload` is a Pydantic model, not a dataclass; `dataclasses.fields`
     raised before reaching the evidence at all.
  3. `model_copy(update=...)` bypasses validation, so `reason="CrashLoopBackOff"`
     arrived as a bare `str` and `payload.reason.value` raised inside the agent.

  The OOM answer was *correct for the evidence actually sent*. Reporting it as a
  grounding failure would have put a false finding into the permanent record.

- **Why it is a problem:** The failure mode is not the bug, it is the bug being
  **credible**. A grounded-RCA harness that silently fails to send the logs yields
  confident, specific, wrong conclusions about the model — and the model's answer
  looks entirely reasonable, so there is nothing to sanity-check it against. The
  fourth layer, found only after the first three were fixed: `SREK3S_LOG_TEXT_EVIDENCE`
  defaults to **False**, so log text does not reach a model unless an operator opts
  in per deployment. The traceback could never have appeared in that RCA regardless
  of how the harness was written. That default is a *feature* — attacker-influenced
  container stdout is kept out of the model entirely — but it means the shipped
  default closes the prompt-injection surface before the model is consulted, and
  any test of grounding must set the switch explicitly or it is testing nothing.

- **How we fixed it:** Every grounding run now prints the rendered prompt and
  asserts the traceback is present **before** calling a model, and asserts on
  `llm.build_prompt` — not on a re-implementation of it. Grounding is only assessed
  after that proof. With the switch on and the metadata made coherent (crash-loop
  framing matching an exit-1 traceback), the live RCA names the `KeyError`, the
  missing `cust_8817`, the `charge()` frame and the exception at startup, and
  correctly declines to implicate the 128Mi memory limit.

  The same run recorded a genuine defect rather than papering over it: NVIDIA's
  `openai/gpt-oss-20b` returns the prose as a bare string in `root_cause` where the
  schema declares `{"summary": ...}`, so `.summary` raised `AttributeError` in the
  caller **after** tier, patch and every validation flag were written. Total failure,
  not partial — nothing was compromised — but a total failure in the one code path
  whose contract is "degrade to the deterministic prose" is the wrong shape for it
  to have. `_normalise_root_cause` now accepts that one shape. It is a *shape*
  tolerance, not a scope change: `extra="forbid"` still rejects a tier or a patch
  arriving through the seam, freeform and fenced output are still fatal, and an
  ambiguous multi-key object is refused rather than guessed. Both directions were
  plant-tested — removing the normalisation reds two acceptance controls, making it
  guess reds the ambiguity control.
