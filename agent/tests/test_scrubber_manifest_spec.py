"""The masking manifest in ``CONTRIBUTING.md`` §5 is what the code implements.

This is the only part of ``CONTRIBUTING.md`` that a test reads, and that is a
deliberate exception to the file's own stated principle ("a gate that reads prose
is a gate that fails when the prose drifts"). The alternative was code-as-spec for
the masking rules — and ``internal/scrubber/manifest.go`` already says its patterns
are "transcribed verbatim from the §5 manifest table", which was an unbacked claim
while that table lived in a deleted document. A claim of transcription is either
asserted or it is a comment.

What is compared
----------------
Not just the rule *IDs* — the *patterns*. A table listing eleven names is a
checklist; a table carrying the RE2 patterns is a specification, and matching the
patterns is what catches a pattern edited in one place and not the other. Order is
compared too, because order is normative: structural patterns must run before the
generic ``key=value`` one or redaction is not idempotent.

What this replaces
------------------
``agent/tests/test_architecture_layout.py`` (711 lines) was deleted with the design
record. That was the right call — it asserted a whole repository layout, which is
what made it expensive to maintain. But it also carried one assertion that was not
about layout at all: that the manifest agreed with its specification. That is the
assertion kept here, in twenty lines, pointed at a table that now lives in a file
that exists.
"""

from __future__ import annotations

import pathlib
import re
from typing import Any

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
CONTRIBUTING = REPO_ROOT / "CONTRIBUTING.md"
MANIFEST_GO = REPO_ROOT / "internal" / "scrubber" / "manifest.go"

#: The eleven rule IDs, in normative evaluation order. Independent of both sources,
#: so the test is a three-way comparison rather than one file agreeing with another.
EXPECTED_IDS: tuple[str, ...] = (
    "pem_private_key",
    "aws_access_key_id",
    "aws_secret_access_key",
    "jwt",
    "bearer_token",
    "basic_auth_url",
    "generic_secret_kv",
    "uuid",
    "ipv4_address",
    "k8s_secret_mount",
    "private_key_pem_body",
)

#: A row of the §5 table: | # | `id` | `regex` | target | replacement |
ROW = re.compile(
    r"^\|\s*(?P<number>\d+)\s*\|"
    r"\s*`(?P<id>[a-z0-9_]+)`\s*\|"
    r"\s*`(?P<regex>[^`]*)`\s*\|",
    re.M,
)

#: The Go constants:    RulePEMPrivateKey RuleID = "pem_private_key"
GO_CONST = re.compile(
    r'^\s*(?P<name>Rule[A-Za-z0-9_]*)\s+RuleID\s*=\s*"(?P<id>[a-z0-9_]+)"', re.M
)

#: A pattern-map entry:  RulePEMPrivateKey: `-----BEGIN ...`,
GO_PATTERN = re.compile(r"^\s*(?P<name>Rule[A-Za-z0-9_]*):\s*`(?P<regex>[^`]*)`", re.M)

#: The rulePatterns map declaration. Scoping to the map body is load-bearing: a
#: whole-file scan also matches `ruleTemplates`, whose entries are Go string
#: concatenations that happen to open with a backtick, and pairing those against
#: the rule constants silently yields thirteen entries for eleven rules.
RULE_PATTERNS_BLOCK = re.compile(
    r"var\s+rulePatterns\s*=\s*map\[RuleID\]string\{(?P<body>.*?)\n\}", re.S
)


def spec_rows() -> list[tuple[str, str]]:
    """``[(rule_id, regex)]`` from CONTRIBUTING.md's §5 manifest table."""
    text = CONTRIBUTING.read_text(encoding="utf-8")
    assert "## 5. Secret Masking Regex Manifest (normative)" in text, (
        "CONTRIBUTING.md no longer has §5, so the masking manifest has no "
        "specification and internal/scrubber/manifest.go is asserting 'transcribed "
        "verbatim' against nothing"
    )
    # Three capture groups (number, id, regex); the row number is dropped because
    # order is asserted against EXPECTED_IDS directly rather than against it.
    matched = ROW.findall(text)
    if not matched:
        raise AssertionError(
            "no rows parsed from CONTRIBUTING.md §5; the table's shape changed"
        )
    rows: list[tuple[str, str]] = []
    for _number, rule_id, regex in matched:
        # A regex cell escapes its literal pipes as \| so the markdown table
        # survives. The specification is the unescaped pattern, and comparing the
        # escaped form against Go raw strings would never match.
        rows.append((rule_id, regex.replace(r"\|", "|")))
    return rows


def go_patterns() -> dict[str, str]:
    """``{rule_id: regex}`` from manifest.go's ``rulePatterns`` map.

    Pairing is by constant name, not by position: the map is keyed by Go constants
    and the constants are what carry the rule IDs, so a map entry is resolved
    through ``RuleXxx RuleID = "id"`` rather than assumed to be in manifest order.
    """
    text = MANIFEST_GO.read_text(encoding="utf-8")

    constant_to_id = {
        match.group("name"): match.group("id") for match in GO_CONST.finditer(text)
    }

    block = RULE_PATTERNS_BLOCK.search(text)
    assert block is not None, (
        "internal/scrubber/manifest.go has no `var rulePatterns = map[RuleID]string{"
        "` block; the manifest moved and this check is asserting nothing"
    )
    entries = list(GO_PATTERN.finditer(block.group("body")))
    assert entries, "rulePatterns block found but no entries parsed from it"

    resolved: dict[str, str] = {}
    for match in entries:
        name = match.group("name")
        assert (
            name in constant_to_id
        ), f"rulePatterns is keyed by {name!r}, which declares no RuleID"
        resolved[constant_to_id[name]] = match.group("regex")

    # Compare rule IDs, not constant names: `constant_to_id` is keyed by the Go
    # constant, so `set(constant_to_id)` holds names like RulePEMPrivateKey while
    # `resolved` is keyed by rule ID. Comparing the two collections reports all
    # eleven as missing on a perfectly correct file.
    missing = sorted(set(constant_to_id.values()) - set(resolved))
    assert not missing, f"RuleID constants with no pattern in rulePatterns: {missing}"
    return resolved


def test_the_specification_declares_the_eleven_rules_in_order() -> None:
    ids = [rule_id for rule_id, _ in spec_rows()]
    assert ids == list(EXPECTED_IDS), (
        "CONTRIBUTING.md §5 declares a different rule set or order than the "
        f"normative manifest.\n  spec: {ids}\n  want: {list(EXPECTED_IDS)}"
    )


def test_the_specification_patterns_match_the_code() -> None:
    """The load-bearing one: ``manifest.go`` claims verbatim transcription."""
    spec = dict(spec_rows())
    code = go_patterns()

    missing_in_code = sorted(set(spec) - set(code))
    missing_in_spec = sorted(set(code) - set(spec))
    assert (
        not missing_in_code
    ), f"in CONTRIBUTING.md §5 but not in manifest.go: {missing_in_code}"
    assert (
        not missing_in_spec
    ), f"in manifest.go but not in CONTRIBUTING.md §5: {missing_in_spec}"

    mismatched = {
        rule_id: (spec[rule_id], code[rule_id])
        for rule_id in spec
        if spec[rule_id] != code[rule_id]
    }
    assert not mismatched, (
        "manifest.go says its patterns are transcribed verbatim from "
        "CONTRIBUTING.md §5, and for these they are not:\n"
        + "\n".join(
            f"  {rule_id}\n    spec: {documented}\n    code: {actual}"
            for rule_id, (documented, actual) in mismatched.items()
        )
    )


class TestNegativeControls:
    """These assertions are worthless unless the check can fail.

    Each control plants a defect the real check is supposed to catch and requires
    the comparison to notice. They run against synthesised text rather than the
    repository, so a failure here means the control is broken rather than the code.
    """

    @staticmethod
    def _compare(spec: dict[str, str], code: dict[str, str]) -> dict[str, Any]:
        """The comparison from ``test_the_specification_patterns_match_the_code``."""
        mismatched = {
            rule_id: (spec[rule_id], code[rule_id])
            for rule_id in spec
            if rule_id in code and spec[rule_id] != code[rule_id]
        }
        return mismatched

    def test_control_detects_a_pattern_edited_in_the_table_only(self) -> None:
        spec = {rule_id: "ORIGINAL" for rule_id in EXPECTED_IDS}
        code = dict(spec)
        spec["jwt"] = "EDITED-IN-THE-TABLE"

        mismatched = self._compare(spec, code)
        assert list(mismatched) == ["jwt"], (
            "a pattern edited in CONTRIBUTING.md §5 alone was not detected, so "
            "test_the_specification_patterns_match_the_code would pass a table that "
            "describes different rules from the code"
        )

    def test_control_detects_a_rule_removed_from_the_table(self) -> None:
        spec = {rule_id: "X" for rule_id in EXPECTED_IDS}
        code = dict(spec)
        removed = EXPECTED_IDS[3]
        del spec[removed]

        assert removed not in spec
        assert removed in code, (
            "the control is vacuous: the rule it removed is absent from both sides, "
            "so it proves nothing"
        )

    def test_control_detects_a_rule_removed_from_the_code(self) -> None:
        spec = {rule_id: "X" for rule_id in EXPECTED_IDS}
        code = dict(spec)
        removed = EXPECTED_IDS[7]
        del code[removed]

        assert removed in spec and removed not in code, (
            "the control is vacuous: it removed a rule from the code that was also "
            "absent from the specification"
        )

    def test_control_detects_a_reordered_table(self) -> None:
        """Order is normative, so a reshuffle must not compare equal.

        Swapping the generic ``key=value`` rule ahead of the structural ones breaks
        idempotence, which no per-rule pattern comparison would notice.
        """
        spec_order = list(EXPECTED_IDS)
        code_order = list(EXPECTED_IDS)
        spec_order.remove("uuid")
        code_order.remove("uuid")
        spec_order.insert(0, "uuid")

        assert spec_order != code_order, (
            "a reordered table compared equal, so order is not actually being "
            "checked and the idempotence guarantee is unasserted"
        )

    def test_control_the_real_specification_is_not_vacuous(self) -> None:
        """The live inputs must be non-empty and complete.

        A parser that silently matches nothing returns ``[]``, an empty dict
        compares equal to an empty dict, and every assertion above passes. This is
        the cheapest possible way to tell that apart from a working check.
        """
        rows = spec_rows()
        code = go_patterns()
        assert len(rows) == 11, f"expected 11 spec rows, parsed {len(rows)}"
        assert len(code) == 11, f"expected 11 Go patterns, parsed {len(code)}"
        assert all(rule_id for rule_id, _ in rows)
        assert all(regex for _, regex in rows)
        assert not self._compare(
            dict(rows), code
        ), "the real specification and the real code already disagree"
