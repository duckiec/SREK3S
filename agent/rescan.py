"""Outbound secret re-scan (ARCH §6, invariant I-B6, ROADMAP §2.5.8).

The Go Sentinel is the authoritative masking control: it scrubs telemetry in
memory before anything leaves the host. This module is the **backstop**. If a
secret ever reaches the agent - because a masking rule missed it, because a new
field was added without a rule, because a payload arrived through a path that
bypasses the Sentinel - the agent must not be the thing that forwards it.

Rule parity is the point
------------------------
ARCH §6 M6 requires the agent to apply **the same rule IDs** as the Go node.
The patterns below are transcribed from ``internal/scrubber/manifest.go`` and the
IDs are identical, so a finding here names the same rule an operator would see
in a Go-side ``RedactionReport``. Reimplementing with fresh, differently-named
rules would make the two reports incomparable, which is the main reason a
backstop is worth having.

The replacement token is the literal ``[REDACTED]`` and is not configurable
(§6 M1): no environment variable may weaken masking. Over-masking is preferred
over under-masking (M5) - a diagnostic that loses an IP is recoverable, a leaked
credential is not.

Counts only
-----------
A :class:`RescanReport` records which rules fired and how many times, never what
they matched (§6 M4). It is emitted to logs and to the response, so a report
containing the secret would defeat its own purpose.

Redaction vs refusal
--------------------
Prose (the RCA, rationales, evidence) is **redacted**: losing a character from a
sentence costs a human nothing, and redacting keeps the dispatch useful.

A unified diff is **refused**, not redacted. Rewriting a line inside a diff would
corrupt the artifact and produce a patch that no longer matches its own hunk
header, so a secret found in ``git_patch`` is a hard failure that forces Tier-2
and an empty patch (I-B1, ROADMAP §2.5.6).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final, NamedTuple

from models import RedactionReport

__all__ = [
    "MASK",
    "RESCAN_RULES",
    "Rule",
    "RescanReport",
    "SecretFound",
    "assert_clean",
    "redact",
    "scan",
    "rule_ids",
]

#: ARCH §6 M1. Constant, not configurable, so nothing can weaken masking.
MASK: Final[str] = "[REDACTED]"


class Rule(NamedTuple):
    """One mirrored masking rule."""

    rule_id: str
    pattern: re.Pattern[str]
    #: ``True`` when the replacement preserves capture groups, which is how rules
    #: 6 and 7 keep surrounding structure (scheme, key name, quotes) intact.
    group_preserving: bool = False


def _rule(rule_id: str, pattern: str, group_preserving: bool = False) -> Rule:
    return Rule(rule_id, re.compile(pattern), group_preserving)


#: ARCH §6 §6.1, in normative order. Transcribed from
#: ``internal/scrubber/manifest.go``; the IDs match the Go manifest exactly.
#:
#: Ordering matters for the multi-line rules, which must run before the
#: single-line ``private_key_pem_body`` so a whole key block is removed rather
#: than just its header - the defect D-3 recorded in ARCH §6.5.
RESCAN_RULES: Final[tuple[Rule, ...]] = (
    _rule(
        "pem_private_key",
        r"-----BEGIN (RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY"
        r"( BLOCK)?-----[\s\S]*?-----END (RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?"
        r"PRIVATE KEY( BLOCK)?-----",
    ),
    _rule(
        "aws_access_key_id",
        r"\b((A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA|AIDA|AROA|AIPA|ANPA|ANVA)"
        r"[A-Z0-9]{16})\b",
    ),
    _rule(
        "aws_secret_access_key",
        r"(?i)aws(.{0,20})?(secret|private)(.{0,20})?['\"][0-9a-zA-Z/+]{40}['\"]",
    ),
    _rule("jwt", r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
    _rule("bearer_token", r"(?i)\bbearer\s+[A-Za-z0-9\-._~+/]{8,}=*"),
    # ARCH §6.3: only the password is replaced; scheme, user and host survive.
    _rule(
        "basic_auth_url",
        r"(?i)([a-z][a-z0-9+.-]*:\/\/[^:\s\/]+:)([^@\s\/]+)(@[^\s\/]+)",
        group_preserving=True,
    ),
    # ARCH §6.6: `secret(?:[_-]access)?[_-]?key` must be listed before the bare
    # `secret` so the longest match wins without relying on backtracking. This
    # mirrors internal/scrubber/manifest.go exactly - the two implementations are
    # required to stay rule-for-rule identical (ARCH §6 M6), and a divergence here
    # means the backstop disagrees with the control.
    #
    # ARCH §6.4: the key name and the closing quote survive, so JSON structure
    # does not collapse when a password is masked.
    _rule(
        "generic_secret_kv",
        r"(?i)(\b[\w-]{0,20}(?:api[_-]?key|secret(?:[_-]access)?[_-]?key|secret|token"
        r"|access[_-]?token|refresh[_-]?token|password|passwd|pwd|passphrase"
        r"|client[_-]?secret|private[_-]?key|authorization|auth)"
        r"[\"']?\s*[:=]\s*[\"']?)(?P<value>[^\"',;}\n]{4,})([\"']?)",
        group_preserving=True,
    ),
    _rule(
        "uuid",
        r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
        r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b",
    ),
    _rule(
        "ipv4_address",
        r"\b((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}"
        r"(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\b",
    ),
    # Go writes this as two alternations, each with its own inline `(?i)`. Python's
    # `re` rejects a global flag that is not at the very start of the expression
    # (`re.error: global flags not at the start`), so the flag is hoisted and the
    # alternation rewritten. Same intent - both branches case-insensitive, both
    # matched within 80 characters - so the rule ID still names the same detection.
    _rule(
        "k8s_secret_mount",
        r"(?i)\b(?:kube-system|kube-node-lease)\b[^\n]{0,80}"
        r"(?:token|secret|ca\.crt)"
        r"|(?:token|secret|ca\.crt)[^\n]{0,80}"
        r"\b(?:kube-system|kube-node-lease)\b",
    ),
    # Must stay last: it matches the BEGIN header on its own, and running it
    # before the multi-line rule would leave the key body exposed.
    _rule("private_key_pem_body", r"(?i)-----BEGIN[A-Z ]*PRIVATE[A-Z ]*-----"),
)


@dataclass(frozen=True)
class SecretFound:
    """One rule firing. Carries the rule ID and a count, never the value."""

    rule_id: str
    count: int


@dataclass(frozen=True)
class RescanReport:
    """Which rules fired across a set of scanned strings."""

    findings: tuple[SecretFound, ...] = ()

    @property
    def clean(self) -> bool:
        return not self.findings

    @property
    def total(self) -> int:
        return sum(f.count for f in self.findings)

    @property
    def rules_triggered(self) -> list[str]:
        """Rule IDs, ordered, for a :class:`~models.RedactionReport`."""
        return [f.rule_id for f in self.findings]

    def to_redaction_report(self) -> RedactionReport:
        """Convert to the wire shape.

        §6 M4: counts only. The matched text is never included, because this
        report is itself emitted.
        """
        return RedactionReport(
            total_redactions=self.total,
            rules_triggered=self.rules_triggered,
        )

    def summary(self) -> str:
        """Human-readable, safe to log."""
        if self.clean:
            return "no secrets found"
        return ", ".join(f"{f.rule_id}x{f.count}" for f in self.findings)


def rule_ids() -> list[str]:
    """Every mirrored rule ID, for a parity assertion against the Go manifest."""
    return [rule.rule_id for rule in RESCAN_RULES]


def scan(*texts: str) -> RescanReport:
    """Report which rules fire in ``texts``, without altering them.

    Counted over the *whole* text rather than line by line, because a secret can
    be assembled across a line boundary - the reason ARCH §6 M3 specifies a
    cross-line re-scan. The multi-line rules additionally rely on ``[\\s\\S]``
    to see embedded newlines.
    """
    tally: dict[str, int] = {}
    for text in texts:
        if not text:
            continue
        for rule in RESCAN_RULES:
            hits = len(rule.pattern.findall(text))
            if hits:
                tally[rule.rule_id] = tally.get(rule.rule_id, 0) + hits
    return RescanReport(
        findings=tuple(
            SecretFound(rule_id=rid, count=count)
            for rid, count in sorted(tally.items())
        )
    )


def _apply(text: str, rule: Rule) -> str:
    """Run one rule, preserving capture groups where the Go node does."""
    if rule.group_preserving:
        # Both group-preserving rules have exactly three groups, with the secret
        # in the middle: `scheme://user:` + password + `@host`, and
        # `key<sep>` + value + `"`. Keeping the outer two is what lets
        # {"password":"hunter2"} become {"password":"[REDACTED]"} instead of
        # destroying the surrounding JSON, and what keeps the endpoint topology
        # an RCA reasons over (ARCH §6.3).
        def _replace(match: re.Match[str]) -> str:
            return f"{match.group(1)}{MASK}{match.group(3)}"

        return rule.pattern.sub(_replace, text)
    return rule.pattern.sub(MASK, text)


def redact(*texts: str) -> tuple[tuple[str, ...], RescanReport]:
    """Redact ``texts`` in place-independent fashion.

    Returns the redacted strings and a report. The input is never mutated, and no
    scratch buffer holds plaintext: everything happens on the string being
    returned (§6 M2).
    """
    results: list[str] = []
    tally: dict[str, int] = {}
    for text in texts:
        current = text
        for rule in RESCAN_RULES:
            hits = len(rule.pattern.findall(current))
            if hits:
                tally[rule.rule_id] = tally.get(rule.rule_id, 0) + hits
                current = _apply(current, rule)
        results.append(current)
    report = RescanReport(
        findings=tuple(
            SecretFound(rule_id=rid, count=count)
            for rid, count in sorted(tally.items())
        )
    )
    return tuple(results), report


class SecretLeakError(RuntimeError):
    """A secret survived into a machine-consumed artifact.

    Raised only for ``git_patch``. Prose is redacted instead, because corrupting
    a diff to remove a credential would produce a patch that no longer applies.
    """

    def __init__(self, rule_ids_found: list[str]) -> None:
        super().__init__(
            "a secret reached the patch artifact under rule(s): "
            + ", ".join(rule_ids_found)
        )
        self.rule_ids_found = rule_ids_found


def assert_clean(patch: str) -> RescanReport:
    """Refuse a diff that carries a secret.

    Raising is the point: the caller downgrades to Tier-2 with an empty patch
    rather than shipping a credential inside a GitOps pull request, which would
    copy it into every clone of the repository and into the PR diff itself.
    """
    report = scan(patch)
    if not report.clean:
        raise SecretLeakError(report.rules_triggered)
    return report
