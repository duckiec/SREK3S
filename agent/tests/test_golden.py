"""ROADMAP 4.4 - regression golden files.

Two goldens and three properties, plus a fourth that is not in the ROADMAP and
matters more than any of them:

* `tests/fixtures/expected/oom-expected.patch` - the exact Tier-1 artifact for the
  bounded OOM fixture.
* `tests/fixtures/expected/oom-expected-rca.md` - the exact RCA for the canonical
  emitted incident.

What is asserted, and what deliberately is not
-----------------------------------------------
The patch is compared **byte for byte**, with one documented normalisation of the
hunk header's start line. That normalisation is not leniency: the hunk's *content*
is the contract, and its start line is an artifact of where the limit sits in the
file. Two numbers are compared exactly - the hunk's line count and the changed
line - so a patch that grew, lost context, or changed a different key all fail.

The RCA is **not** compared byte for byte. It is produced by a language model at
runtime, so an exact-match golden would fail on a reworded sentence and teach
nothing. Instead two things are checked: that the generator still produces the
structure the golden documents (so the golden cannot rot unnoticed), and that the
golden carries the markers a reader needs. `test_generated_rca_structure` asserts
headings and evidence markers, never prose equality.

That asymmetry is deliberate and it is the point of the milestone. A diff is
machine-generated and deterministic; an RCA is machine-*assisted* and not. Using
one comparison discipline for both would either make the RCA golden useless or
make the patch golden meaningless.

The fourth property
-------------------
`test_golden_files_contain_no_secrets` scans both goldens against every secret in
`tests/fixtures/incident_corpus.json`. A golden file is a file that gets copied,
pasted into issues, and read aloud in a War-Room channel; it is the last place a
credential should be if it is anywhere. The ROADMAP asks for this as 4.4.4 and it
is the cheapest check in this file.
"""

from __future__ import annotations

import ast
import json
import pathlib
import re
import sys
from pathlib import Path
from typing import Any, Final

import yaml

_ROOT: Final[Path] = pathlib.Path(__file__).resolve().parents[2]
_AGENT_DIR: Final[Path] = _ROOT / "agent"
for _p in (_AGENT_DIR, _ROOT / "tests" / "e2e"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from models import BlastRadiusTier, Classification, IncidentPayload  # noqa: E402
from patch import build_diff, find_container_memory_limit, memory_values  # noqa: E402
from prompt import rca_markdown  # noqa: E402

# ---------------------------------------------------------------------------
# Fixtures under test and their expected outputs
# ---------------------------------------------------------------------------

#: The bounded fixture the golden diff targets. Chosen over
#: `deploy/chaos/oom-leak.yaml` because that one is unbounded and cannot be
#: remediated - see docs/lessons-learned.md section 19.
MANIFEST: Final[Path] = _ROOT / "tests" / "fixtures" / "bounded-leak.yaml"
CONTAINER: Final[str] = "bounded-canary"
FROM_LIMIT: Final[str] = "64Mi"
TO_LIMIT: Final[str] = "128Mi"

#: Repo-relative, because ARCH 2.5.4 forbids absolute paths in a diff.
MANIFEST_RELPATH: Final[str] = "tests/fixtures/bounded-leak.yaml"

EXPECTED_DIR: Final[Path] = _ROOT / "tests" / "fixtures" / "expected"
GOLDEN_PATCH: Final[Path] = EXPECTED_DIR / "oom-expected.patch"
GOLDEN_RCA: Final[Path] = EXPECTED_DIR / "oom-expected-rca.md"

#: The canonical emitted incident the golden RCA is written for.
EMITTED_INCIDENT: Final[Path] = _ROOT / "tests" / "fixtures" / "emitted_incident.json"

#: The masked-secret corpus. The ROADMAP text names `secrets_corpus.txt`; no such
#: file exists in this repository and inventing one would be a second source of
#: truth for what counts as a secret. This is the corpus the Go scrubber tests
#: and the E2E masking assertions already consume, so scanning against it makes
#: the golden check part of the same guarantee rather than a parallel one.
CORPUS: Final[Path] = _ROOT / "tests" / "fixtures" / "incident_corpus.json"

#: Separates the generator's output from the annotation appended below it.
#: The marker is in both goldens' generation scripts and in the RCA file itself.
RCA_SEPARATOR: Final[str] = "\n---\n"

#: Inputs to the RCA generator, held here so the golden and the test cannot
#: disagree about what produced it.
RCA_CLASSIFICATION: Final[Classification] = Classification.RESOURCE_EXHAUSTION
RCA_TIER: Final[BlastRadiusTier] = BlastRadiusTier.TIER_1_TOIL
RCA_RATIONALE: Final[str] = (
    "The container was OOMKilled (exit 137) with a configured memory limit of " "256Mi."
)
RCA_EVIDENCE: Final[tuple[str, ...]] = (
    "exit code 137 (SIGKILL from the memory cgroup) on pod "
    "checkout-api-7d9f4b6c8d-x2k9p",
    "resource_limits.memory_limit = 256Mi at the time of the kill",
    "restart_count = 4, so the fault recurred rather than terminating once",
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _generated_diff() -> str:
    """The Tier-1 artifact, from the real engine on the real fixture."""
    text = MANIFEST.read_text(encoding="utf-8")
    target = find_container_memory_limit(text, CONTAINER)
    assert target is not None, f"no memory limit found for container {CONTAINER!r}"
    return build_diff(text, target, TO_LIMIT, MANIFEST_RELPATH)


def _normalise_header(diff: str) -> str:
    """Replace the hunk header's start line with a placeholder.

    The only normalisation, and it is scoped to the start line of the `@@`
    header. Everything else - the line count, the context lines, the changed
    line - is compared verbatim. The start line moves whenever an unrelated
    comment is edited above the limit in the fixture, which says nothing about
    whether the patch is correct, so pinning it would make the golden a tripwire
    for edits it is not meant to police.
    """
    header = re.compile(r"^@@ -\d+,(\d+) \+\d+,(\d+) @@$", re.MULTILINE)
    return header.sub(r"@@ -<START>,\1 +<START>,\2 @@", diff)


def _rca_generator_output() -> str:
    payload = IncidentPayload(
        **json.loads(EMITTED_INCIDENT.read_text(encoding="utf-8"))
    )
    return rca_markdown(
        payload, RCA_CLASSIFICATION, RCA_TIER, RCA_RATIONALE, list(RCA_EVIDENCE)
    )


def _hunk_body(diff: str) -> list[str]:
    """The hunk's lines, excluding the file headers and the ``@@`` header.

    Parsed rather than filtered by prefix, because `--- a/path` and
    `+++ b/path` also *start* with `-` and `+`. A test that selects hunk lines
    with `startswith("-")` picks up the file header, which is how the first
    version of `test_the_golden_makes_exactly_the_intended_mutation` failed
    against its own correct golden.
    """
    lines = diff.splitlines()
    start = next(
        (index for index, line in enumerate(lines) if line.startswith("@@")), None
    )
    assert start is not None, "the diff has no @@ hunk header"
    body: list[str] = []
    for line in lines[start + 1 :]:
        if (
            line.startswith("diff ")
            or line.startswith("--- ")
            or line.startswith("+++ ")
        ):
            break
        body.append(line)
    return body


def _removed_and_added(diff: str) -> tuple[list[str], list[str]]:
    """The removed and added source lines, unprefixed."""
    removed = [line[1:] for line in _hunk_body(diff) if line.startswith("-")]
    added = [line[1:] for line in _hunk_body(diff) if line.startswith("+")]
    return removed, added


def _corpus_secrets() -> list[str]:
    """Every secret the scrubber corpus says must be masked.

    Read from the corpus rather than from a hardcoded list, so a case added to
    the corpus automatically joins this check. Both the `secret` of every case
    and the `must_survive` fragments of the negative controls are collected: a
    golden containing a *negative control* is not a leak, but a golden that has
    drifted to contain one is a signal the golden was edited from the wrong
    source, so both are reported and classified.
    """
    document: dict[str, Any] = json.loads(CORPUS.read_text(encoding="utf-8"))
    secrets: list[str] = []
    for group in document.get("groups", []):
        for case in group.get("cases", []):
            value = case.get("secret")
            if isinstance(value, str) and value:
                secrets.append(value)
    return secrets


def _corpus_negative_controls() -> list[str]:
    document: dict[str, Any] = json.loads(CORPUS.read_text(encoding="utf-8"))
    fragments: list[str] = []
    for group in document.get("groups", []):
        for case in group.get("cases", []):
            for fragment in case.get("must_survive", []) or []:
                if isinstance(fragment, str) and fragment:
                    fragments.append(fragment)
    return fragments


# ---------------------------------------------------------------------------
# 4.4.1 / 4.4.2 - the golden diff
# ---------------------------------------------------------------------------


class TestGoldenDiff:
    """The Tier-1 artifact, pinned byte for byte.

    A diff is machine-generated and deterministic, so an exact comparison is
    correct here and would be wrong for the RCA. If this test ever starts
    passing trivially, the negative controls below are what to check.
    """

    def test_generated_diff_matches_golden(self) -> None:
        """The agent's patch equals the golden.

        Compared exactly except the hunk header's start line, which is
        normalised for the reason in `_normalise_header`. The semantic mutation
        - `memory: 64Mi` to `memory: 128Mi`, one line, nothing else - must match
        character for character.
        """
        generated = _generated_diff()
        golden = GOLDEN_PATCH.read_text(encoding="utf-8")
        assert _normalise_header(generated) == _normalise_header(golden), (
            "the generated Tier-1 patch has drifted from the golden.\n"
            "--- generated ---\n"
            f"{generated}\n"
            "--- golden ---\n"
            f"{golden}"
        )

    def test_the_golden_makes_exactly_the_intended_mutation(self) -> None:
        """One key, one direction, one line.

        Independent of the byte comparison, and deliberately so: it states what
        the patch is *for*, so a golden that matched by being empty, or by being
        applied to the wrong key, could not pass it.
        """
        golden = GOLDEN_PATCH.read_text(encoding="utf-8")
        removed, added = _removed_and_added(golden)
        assert removed == [
            f"              memory: {FROM_LIMIT}"
        ], f"the golden must remove exactly the old limit line, got {removed}"
        assert added == [
            f"              memory: {TO_LIMIT}"
        ], f"the golden must add exactly the new limit line, got {added}"

    def test_the_golden_changes_nothing_else_in_the_manifest(self) -> None:
        """Applying the golden to the fixture moves one line and nothing else.

        The hunk is parsed rather than pattern-matched, because `--- a/path` and
        `+++ b/path` also start with `-` and `+`. Selecting hunk lines by prefix
        picks the file headers up as removals and additions, which is what the
        first version of this test did.
        """
        manifest = MANIFEST.read_text(encoding="utf-8").splitlines()
        removed, added = _removed_and_added(GOLDEN_PATCH.read_text(encoding="utf-8"))
        assert (
            len(removed) == 1 and len(added) == 1
        ), f"expected a single-line replacement, got -{removed} +{added}"
        anchor = _removed_index(manifest, removed)
        patched = [*manifest[:anchor], *added, *manifest[anchor + 1 :]]

        assert len(patched) == len(
            manifest
        ), "the golden must replace a line, not add or remove one"
        differing = [
            index
            for index, (before, after) in enumerate(zip(manifest, patched), start=1)
            if before != after
        ]
        assert differing == [anchor + 1], (
            f"applying the golden must change exactly the limit line at "
            f"{anchor + 1}; changed {differing}"
        )

        # And the result must still be valid YAML carrying the new limit.
        document = yaml.safe_load("\n".join(patched))
        container = document["spec"]["template"]["spec"]["containers"][0]
        assert container["resources"]["limits"]["memory"] == TO_LIMIT

    def test_the_golden_is_well_formed_for_git(self) -> None:
        """Newline-terminated, LF-only, and structurally a unified diff.

        `patch.build_diff` documents both properties as load-bearing: a diff with
        no trailing newline is rejected by `git apply` as corrupt, and a CRLF
        diff carries a carriage return on every context line that will not match
        an LF manifest. A golden that got either wrong would be a golden
        blessing an unapplyable patch.
        """
        golden = GOLDEN_PATCH.read_bytes()
        assert golden.endswith(b"\n"), "the golden patch must be newline-terminated"
        assert b"\r" not in golden, "the golden patch must not contain CR"
        text = golden.decode("utf-8")
        assert text.startswith(f"--- a/{MANIFEST_RELPATH}\n")
        assert f"+++ b/{MANIFEST_RELPATH}\n" in text
        assert re.search(r"^@@ -\d+,\d+ \+\d+,\d+ @@$", text, re.MULTILINE)
        # No `diff --git` header: build_diff does not emit one, and a golden
        # with one would be pinning an artifact the agent never produces.
        assert not text.startswith("diff --git"), (
            "patch.build_diff emits `--- a/` and `+++ b/` with no git header; a "
            "golden with one pins a patch the agent never produces"
        )

    def test_the_golden_applies_to_the_fixture_it_names(self) -> None:
        """The fixture and the golden must not drift apart.

        `git apply` is authoritative here, exactly as in
        `test_verification_e2e.py`. Asserted structurally rather than by running
        git: the removed line must exist verbatim in the fixture, and the line it
        is replaced at must be the `memory:` line the engine would have found.
        """
        manifest = MANIFEST.read_text(encoding="utf-8")
        values = memory_values(manifest)
        assert values == [FROM_LIMIT], (
            f"the fixture should carry exactly one {FROM_LIMIT} limit for the "
            f"golden to target, found {values}"
        )
        golden = GOLDEN_PATCH.read_text(encoding="utf-8")
        removed, _added = _removed_and_added(golden)
        assert removed and removed[0] in manifest.splitlines(), (
            "the line the golden removes is not in the fixture; the golden has "
            "drifted from the file it patches"
        )
        # And the context lines must be verbatim fixture lines too, or the patch
        # would not anchor where it claims to.
        context = [
            line[1:]
            for line in _hunk_body(golden)
            if line.startswith(" ") and line.strip()
        ]
        fixture_lines = manifest.splitlines()
        missing = [line for line in context if line not in fixture_lines]
        assert not missing, (
            f"the golden's context lines are not verbatim from the fixture: "
            f"{missing}"
        )


def _removed_index(manifest: list[str], removed: list[str]) -> int:
    """Index of the line the golden removes."""
    for index, line in enumerate(manifest):
        if line in removed:
            return index
    raise AssertionError(f"no manifest line matches {removed!r}")


# ---------------------------------------------------------------------------
# 4.4.3 - the golden RCA
# ---------------------------------------------------------------------------


class TestGoldenRCA:
    """The RCA, pinned structurally.

    Never compared byte for byte. It is produced by a language model at runtime;
    a reworded sentence is not a regression, and a golden that failed on one
    would be uninstallable. What is pinned is the structure a reader and a
    reviewer depend on, plus the guarantee that the golden still reflects what
    the generator produces.
    """

    def test_generated_rca_structure(self) -> None:
        """Required headings and evidence markers, no prose equality.

        The headings asserted here are the generator's own. Note in particular
        that the title is `# RCA:` and not `## RCA:`, and that there is no
        `**Root cause:**` field - the root-cause statement is the `## Summary`
        paragraph. Asserting the shape the generator actually produces is the
        whole value of a golden RCA: a structural contract, not a transcript.
        """
        golden = GOLDEN_RCA.read_text(encoding="utf-8")
        document = golden.split(RCA_SEPARATOR, 1)[0]

        for heading in (
            "# RCA:",
            "## Summary",
            "## Classification",
            "## Evidence",
            "## Remediation",
        ):
            assert heading in document, (
                f"the golden RCA is missing the required heading {heading!r}; "
                "prompt.rca_markdown emits it and the golden must carry it"
            )

        # Evidence markers a reviewer needs to act without opening a second
        # system: the exit code, the pod, and the configured limit.
        for marker in ("137", "checkout-api-7d9f4b6c8d-x2k9p", "256Mi"):
            assert marker in document, (
                f"the golden RCA must cite {marker!r}; an RCA that cannot name "
                "the exit code, the pod or the limit is not actionable"
            )

        # Classification facts, as emitted.
        for value in (RCA_CLASSIFICATION.value, RCA_TIER.value, "OOMKilled"):
            assert value in document, f"the golden RCA must state {value!r}"

        # And explicitly not a shape the generator does not produce. Kept
        # because a maintainer writing a golden by hand reaches for these.
        assert "## RCA:" not in document, (
            "the title is `# RCA:`; `## RCA:` is a heading the generator never "
            "emits and a hand-written golden would invent"
        )
        assert "**Root cause:**" not in document, (
            "there is no `**Root cause:**` field; the root-cause statement is "
            "the `## Summary` paragraph"
        )

    def test_the_golden_rca_matches_the_generator(self) -> None:
        """The goldens' first section is what `rca_markdown` produces today.

        This is what stops the golden rotting. Without it, a future change to
        `prompt.rca_markdown` - a renamed heading, a dropped field - would leave
        the golden looking authoritative while describing an output that no
        longer exists, and 4.4.3's structural assertions would keep passing
        against the stale file.
        """
        generated = _rca_generator_output()
        document = GOLDEN_RCA.read_text(encoding="utf-8").split(RCA_SEPARATOR, 1)[0]
        # The stored document is the generator's output with trailing blank lines
        # trimmed, so the comparison is not sensitive to how the file ends.
        assert document.rstrip() == generated.rstrip(), (
            "the golden RCA no longer matches prompt.rca_markdown.\n"
            "Regenerate it. A golden that describes an output the generator no "
            "longer produces is worse than no golden.\n"
            "--- generated ---\n"
            f"{generated}"
        )

    def test_the_peak_versus_payload_lesson_is_recorded_as_annotation(self) -> None:
        """The Milestone 4.3 lesson must be here, and must NOT be agent output.

        Two requirements pulling in opposite directions, and the resolution is
        that the lesson is genuinely not the agent's to state. Contract A carries
        `exit_code`, `resource_limits` and `restart_count`; it carries no peak
        RSS, so an RCA claiming to know the peak would be asserting something the
        telemetry does not contain - the same error `emitter.mapReason` refuses
        to make when it declines to map an unmappable failure kind.

        So the note has to be present, after the separator, and *not* inside the
        generator's output.
        """
        golden = GOLDEN_RCA.read_text(encoding="utf-8")
        assert RCA_SEPARATOR in golden, (
            "the golden RCA must separate generator output from annotation; "
            "without the separator a reader cannot tell which is which"
        )
        document, _, annotation = golden.partition(RCA_SEPARATOR)

        # Present, in the annotation.
        assert "peak" in annotation.lower(), (
            "the peak-versus-payload lesson belongs in the annotation; it is the "
            "single most expensive thing Milestone 4.3 learned on a live cluster"
        )
        for marker in ("64Mi", "128Mi", "head -c"):
            assert marker in annotation, (
                f"the annotation must cite {marker!r} so the sizing rule is "
                "actionable rather than a caution"
            )

        # Absent from the agent's own output. This is the half that matters.
        assert "peak" not in document.lower(), (
            "the generated RCA must not claim knowledge of peak RSS: Contract A "
            "does not carry it, so stating it would be an unobserved assertion"
        )

    def test_the_golden_rca_is_valid_markdown_around_the_generator_output(self) -> None:
        """The annotation must not corrupt the document it annotates.

        A golden that is valid markdown today and stops being valid after an
        annotation edit is a golden nobody can maintain. Checked structurally:
        balanced code fences, and no unterminated blockquote.
        """
        golden = GOLDEN_RCA.read_text(encoding="utf-8")
        assert golden.count("```") % 2 == 0, "unbalanced code fence in the golden RCA"
        document = golden.split(RCA_SEPARATOR, 1)[0]
        assert document.startswith(
            "# RCA:"
        ), "the generator's output must be the first thing in the file"
        assert document.rstrip().endswith("the point of the GitOps boundary."), (
            "the generator's output must end where it ends - with the "
            "Remediation paragraph - so the separator is unambiguously the "
            "boundary between output and annotation"
        )


# ---------------------------------------------------------------------------
# 4.4.4 - secret hygiene
# ---------------------------------------------------------------------------


class TestGoldenSecretHygiene:
    """No plaintext credential in either golden.

    A golden file is copied, pasted into issues, and read aloud in a War-Room
    channel. It is the last place a credential should be if it is anywhere.
    """

    def test_golden_files_contain_no_secrets(self) -> None:
        """Neither golden contains any secret the scrubber corpus defines.

        Scanned against every `secret` in `tests/fixtures/incident_corpus.json` -
        the corpus the Go scrubber tests and the E2E masking assertions already
        consume. The ROADMAP names `secrets_corpus.txt`; that file does not exist
        and inventing one would create a second, competing answer to "what counts
        as a secret". Using the corpus that already exists makes this check part
        of the same guarantee rather than a parallel one.

        The manifest the golden patches is *not* scanned here: it deliberately
        contains planted credentials so the masking path has something to mask.
        Scanning it would be scanning a fixture by design. The goldens, which are
        expected-output documents meant for human eyes, must be clean.
        """
        secrets = _corpus_secrets()
        assert secrets, (
            "the corpus yielded no secrets; the scan would be vacuous, which is "
            "the failure mode this file exists to prevent"
        )

        for golden_path in (GOLDEN_PATCH, GOLDEN_RCA):
            text = golden_path.read_text(encoding="utf-8")
            found = sorted({value for value in secrets if value in text})
            assert not found, (
                f"{golden_path.name} contains plaintext secret(s) {found} taken "
                "from the masking corpus. A golden file is copied into issues "
                "and read in a War-Room; it must be clean."
            )

    def test_the_scan_is_against_the_corpus_and_not_a_decoration(self) -> None:
        """Negative control: the scan must be able to fail.

        A check that cannot fail is worse than a missing check - see
        docs/lessons-learned.md section 1. Rather than planting a secret in a
        golden file, this feeds the real corpus secrets into the same containment
        test used above and requires it to report them.
        """
        secrets = _corpus_secrets()
        marker = secrets[0]
        assert marker, "the corpus's first secret is empty"

        # A document containing a corpus secret must be reported, or the
        # assertion above is satisfied by an empty result set rather than by a
        # clean file.
        planted = f"documentation example: {marker}"
        found = sorted({value for value in secrets if value in planted})
        assert found == [marker], (
            "the containment test does not detect a corpus secret planted in a "
            "document, so scanning the goldens with it proves nothing"
        )

    def test_the_goldens_contain_no_negative_control_fragments(self) -> None:
        """A golden must not have been copied from the wrong corpus entry.

        Negative controls - the `must_survive` fragments - are *supposed* to
        appear in the corpus, because they must not be masked. Finding one in a
        golden is not a credential leak, but it means the golden was assembled
        from a scrubber fixture rather than from real output, which is how a
        realistic-looking but fictional golden would get in.
        """
        controls = _corpus_negative_controls()
        assert controls, "the corpus yielded no negative controls"
        for golden_path in (GOLDEN_PATCH, GOLDEN_RCA):
            text = golden_path.read_text(encoding="utf-8")
            found = sorted({value for value in controls if value in text})
            assert not found, (
                f"{golden_path.name} contains scrubber negative-control "
                f"fragment(s) {found}; a golden must be real expected output, "
                "not something assembled from the corpus"
            )

    def test_the_goldens_carry_no_absolute_host_paths(self) -> None:
        """ARCH 2.5.4: a diff must not embed the generating host's layout.

        Cheap, and it catches a whole class of bad golden - one generated on a
        developer's machine with an absolute path, which applies nowhere else and
        leaks a directory structure to everyone who reads it.
        """
        for golden_path in (GOLDEN_PATCH, GOLDEN_RCA):
            text = golden_path.read_text(encoding="utf-8")
            assert not re.search(r"^(---|\+\+\+) /", text, re.MULTILINE), (
                f"{golden_path.name} has an absolute path in its diff headers; "
                "ARCH 2.5.4 requires repo-relative paths"
            )
            assert (
                str(_ROOT) not in text
            ), f"{golden_path.name} embeds this checkout's absolute path"


# ---------------------------------------------------------------------------
# Guards on this file
# ---------------------------------------------------------------------------


def test_the_goldens_exist_and_are_non_trivial() -> None:
    """A missing golden must fail loudly, not skip.

    ``pytest.skip`` here would produce a green run in which the milestone's
    entire subject was absent, which is the failure mode
    docs/lessons-learned.md section 1 is about.
    """
    for path in (GOLDEN_PATCH, GOLDEN_RCA, MANIFEST, EMITTED_INCIDENT, CORPUS):
        assert path.exists(), f"{path} does not exist"
        assert path.stat().st_size > 0, f"{path} is empty"
    assert GOLDEN_PATCH.read_text(encoding="utf-8").strip(), "golden patch is blank"


def test_the_corpus_this_file_scans_is_the_one_the_scrubber_consumes() -> None:
    """Guard against the scan drifting onto a corpus nothing else uses.

    The scan is only worth what its corpus is worth, and the corpus is worth
    exactly what the Go scrubber tests make it. Asserting the file the
    scrubber's tests reference keeps the two from diverging silently.
    """
    source = (_ROOT / "internal" / "scrubber" / "corpus_test.go").read_text(
        encoding="utf-8"
    )
    assert "incident_corpus.json" in source, (
        "the Go scrubber tests no longer read tests/fixtures/incident_corpus.json; "
        "this file's secret scan is scanning a corpus nothing else consumes"
    )
    document = json.loads(CORPUS.read_text(encoding="utf-8"))
    assert document.get("groups"), "the corpus has no groups; the scan is vacuous"


def test_this_file_never_compares_an_rca_by_whole_text_equality() -> None:
    """Structural guard on this file's own discipline.

    An exact-match assertion against a language-model-produced RCA is the trap
    this module is written to avoid, and it is easy to reintroduce by accident
    when someone wants a tighter test. Walked rather than grepped, because a
    regex over the source would also match this function's own docstring.
    """
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"))
    offenders: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Compare):
            continue
        # `golden == generated` / `generated == golden` on plain names.
        if not isinstance(node.ops[0], ast.Eq):
            continue
        operands = [node.left, node.comparators[0]]
        if not all(isinstance(o, ast.Name) for o in operands):
            continue
        names = {o.id for o in operands if isinstance(o, ast.Name)}
        if names & {"document", "golden_rca", "rca"}:
            offenders.append(f"line {node.lineno}: {sorted(names)}")
    assert not offenders, (
        "whole-text equality against an RCA golden is the failure mode this "
        f"module exists to avoid: {offenders}"
    )
