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