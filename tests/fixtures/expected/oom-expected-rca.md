# RCA: checkout-api in payments

## Summary

The container was OOMKilled (exit 137) with a configured memory limit of 256Mi.

## Classification

- Classification: `RESOURCE_EXHAUSTION`
- Blast radius tier: `TIER_1_TOIL`
- Reason: `OOMKilled`
- Exit code: `137`
- Restarts: `4`

## Evidence

- exit code 137 (SIGKILL from the memory cgroup) on pod checkout-api-7d9f4b6c8d-x2k9p
- resource_limits.memory_limit = 256Mi at the time of the kill
- restart_count = 4, so the fault recurred rather than terminating once

## Remediation

A unified diff is attached in `remediation.git_patch`. It targets a single manifest and is intended for a GitOps pull request. It has not been applied to the cluster by this system; that is the point of the GitOps boundary.

---

<!--
================================================================================
EVERYTHING BELOW THIS LINE IS ANNOTATION.

Not agent output. Not a template. Not a claim the agent makes.
================================================================================

Provenance
----------
Everything above the separator is the verbatim output of
`prompt.rca_markdown(...)` for `tests/fixtures/emitted_incident.json` at
Classification=RESOURCE_EXHAUSTION, BlastRadiusTier=TIER_1_TOIL. It is stored, not
authored: `agent/tests/test_golden.py::test_the_golden_rca_matches_the_generator`
re-runs the generator and fails if this file drifts from it, so the golden cannot
rot while still looking authoritative.

The structure is the generator's, not a design invented for this file. There is
no `## RCA:` heading - the title is `# RCA:` - and there is no `**Root cause:**`
field; the root-cause statement is the `## Summary` paragraph. Both facts are
asserted explicitly in `test_generated_rca_structure`, because a maintainer
writing a golden by hand reaches for exactly those two and would produce a
document the agent never emits.

Why this file is not compared byte for byte
-------------------------------------------
Because it is produced by a language model at runtime. A reworded sentence is not
a regression, and a golden that failed on one would be uninstallable within a
release. What is pinned instead is the structure a reader depends on - the
headings, the classification facts, and the evidence markers - plus the generator
match above. The golden diff is compared byte for byte; the asymmetry is
deliberate, and `test_this_file_never_compares_an_rca_by_whole_text_equality`
guards it structurally.

The peak-versus-payload lesson
------------------------------
Milestone 4.3 found that a memory fixture sized on its *payload* is sized on the
wrong quantity. `tests/fixtures/bounded-leak.yaml` allocated 90 MiB via

    BOUNDED=$(head -c N /dev/zero | tr '\000' 'x')

Command substitution buffers the entire pipeline result before the shell can
assign it, and the old and new buffers are live simultaneously during realloc
growth. A 90 MiB payload therefore peaked above 128 MiB, and the container was
OOMKilled under a 128Mi limit. CI run 36786601947 recorded it exactly:

    ContainerObservation(visible=True, oomkilled_terminations=1,
                         container_uptime_seconds=4)

The fixture now allocates 52 MiB, which peaks between roughly 75 and 104 MiB
across the plausible range of that overhead - above the 64Mi fault and below the
128Mi fix at every point in the range. 40 and 44 MiB would survive at 64Mi and
so produce no fault at all; 60 MiB leaves only 8 MiB under 128Mi.

THE AGENT CANNOT KNOW ANY OF THIS
---------------------------------
That is why the lesson lives here and not in the RCA body above, and the
distinction is load-bearing rather than stylistic.

Contract A carries `exit_code: 137`, `resource_limits.memory_limit` and
`restart_count`. It carries no peak RSS, no allocation profile, and no notion of
what the workload was doing at the moment it was killed. An RCA asserting "the
container's peak allocation during the load cycle exceeded the limit" would be
stating something the telemetry does not contain.

This is the same class of error `emitter.mapReason` refuses to commit. It rejects
an unmappable failure kind rather than emitting the nearest member, because
emitting `OOMKilled` for a state that was not observed would assert a fault that
did not happen - and an OOM assertion is what unlocks a memory-limit diff. The
reasoning is identical here and the correct behaviour is the same: **do not
assert what was not observed.**

So the rule for future maintainers is: the peak-versus-payload knowledge belongs
to the fixture and to the test that validates it (`TestBoundedFixture` in
`test_verification_e2e.py`), and it may appear in a golden only below the
separator. `test_the_peak_versus_payload_lesson_is_recorded_as_annotation`
enforces both halves - present in the annotation, absent from the output.

What would be required for the agent to derive it
-------------------------------------------------
Contract A would have to carry the observation - a peak-RSS or
`container_memory_working_set_bytes` sample taken at or near the kill - and
`prompt.rca_markdown` would need a field to state it in. Neither exists. That is
a schema change under ARCH section 4, not a prompt change, and it is not made
here.

The nearest honest statement the agent CAN make
-----------------------------------------------
Given only the current payload, the defensible root-cause statement is the one in
`## Summary`: the container was OOMKilled with a configured limit of that size.
It does not distinguish peak from static demand because it cannot, and it does not
pretend to. A golden that blurred that line would teach precisely the
overclaiming this repository's fail-closed posture exists to prevent.
-->
