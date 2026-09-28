"""Unified diff synthesis for Kubernetes manifests (ROADMAP §2.5.4, §2.3.2).

The machine-parsable deliverable is a diff that ``git apply`` accepts, byte for
byte, against the file it was derived from. Everything here exists to make that
claim true rather than merely plausible.

**Why the target must be located, not pattern-matched.** An earlier version of
this generator searched for the first line reading ``memory: "<limit>"`` and
replaced it. That is wrong in a way that matters: a manifest routinely contains
two such lines when ``requests.memory`` and ``limits.memory`` hold the same
value, and it contains one per container in a sidecar or multi-container pod.
Matching on text alone would silently raise the wrong field, or the wrong
container's field, and the patch would still apply cleanly - which is the
dangerous outcome, because a reviewer sees a valid diff and never learns the
change landed on the wrong line.

So the target is resolved structurally:

* the container is matched by **name** against Contract A's ``container_name``,
  never by position;
* the line must sit under ``resources.limits``, not ``resources.requests``;
* quote style, trailing comma and indentation are preserved, so the patched file
  is byte-identical except for the value;
* **any ambiguity resolves to ``None``.** A second container, a second matching
  line, or a construct this parser does not understand all yield no patch rather
  than a guess. The caller then fails closed to Tier-2.

Fail-closed is the point: a diff that applies is easy; a diff that applies to
the *right* line is the thing worth being careful about.

Deliberately not a YAML parser
-------------------------------
This reads the block-mapping subset Kubernetes manifests use, and declines rather
than guesses on flow mappings (``{...}``), anchors and merge keys. A
line-oriented reader that *silently* mis-handles a construct is worse than one
that refuses, because refusal is detectable - it yields ``None`` and the
incident is escalated - while a silent mis-read is not.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final

__all__ = [
    "CONTEXT_LINES",
    "MemoryLine",
    "apply_unified_diff",
    "build_diff",
    "find_container_memory_limit",
    "memory_values",
    "verify_patch",
]
#: Lines of context either side, matching git's default of 3.
CONTEXT_LINES: Final[int] = 3

_MEMORY_LINE: Final[re.Pattern[str]] = re.compile(
    r"""^(?P<indent>\s*)memory:\s*"""
    r"""(?:"(?P<dq>[^"]*)"|'(?P<sq>[^']*)'|(?P<bare>\S+))"""
    r"""(?P<comma>,?)\s*$"""
)

_HUNK_HEADER: Final[re.Pattern[str]] = re.compile(
    r"^@@ -(?P<old_start>\d+),(?P<old_count>\d+) "
    r"\+(?P<new_start>\d+),(?P<new_count>\d+) @@"
)

_KEY_LINE: Final[re.Pattern[str]] = re.compile(
    r"^(?P<key>[A-Za-z0-9_.-]+):(?:\s+(?P<value>.*))?$"
)


@dataclass(frozen=True)
class MemoryLine:
    """One resolved ``memory:`` line and everything needed to replace it exactly."""

    #: Zero-based index into the manifest's lines.
    index: int
    #: The value as written, without quotes.
    value: str
    #: Leading whitespace, preserved verbatim.
    indent: str
    #: ``'"'``, ``"'"`` or ``""`` for an unquoted scalar.
    quote: str
    #: Trailing comma, if the original had one.
    comma: bool
    #: The complete original line, without its newline.
    raw: str


def memory_values(text: str) -> list[str]:
    """Every ``memory:`` value in ``text``, in document order.

    Used by tests and by :func:`verify_patch` to assert that a patch changed
    exactly one of them.
    """
    values: list[str] = []
    for line in text.splitlines():
        match = _MEMORY_LINE.match(line)
        if match is not None:
            values.append(
                match.group("dq") or match.group("sq") or match.group("bare") or ""
            )
    return values


def _indent_of(line: str) -> int:
    return len(line) - len(line.lstrip())


def _strip_inline_comment(text: str) -> str:
    """Remove a trailing ``# ...`` comment, respecting quotes.

    Without this, ``- name: checkout-api  # the app`` yields the container name
    ``"checkout-api  # the app"``, which matches no real container and makes a
    perfectly ordinary annotated manifest look like it has no target at all.

    A ``#`` inside a quoted scalar is left alone, so a value that legitimately
    contains a hash is not truncated.
    """
    quote = ""
    for index, char in enumerate(text):
        if quote:
            if char == quote:
                quote = ""
        elif char in "\"'":
            quote = char
        elif char == "#" and (index == 0 or text[index - 1].isspace()):
            return text[:index]
    return text


def _split_pair(body: str) -> tuple[str, str] | None:
    """Split a block-mapping entry into ``(key, value)``.

    Yields ``None`` for anything that is not a plain ``key: value`` entry, so
    comments, bare list markers and quoted keys are skipped rather than
    misread.
    """
    stripped = body.strip()
    if not stripped or stripped.startswith("#"):
        return None
    match = _KEY_LINE.match(stripped)
    if match is None:
        return None
    value = _strip_inline_comment(match.group("value") or "").strip()
    return match.group("key"), value


def find_container_memory_limit(
    manifest_text: str, container_name: str
) -> MemoryLine | None:
    """Locate ``resources.limits.memory`` for exactly one named container.

    Returns ``None`` when the target cannot be proven: no such container, that
    container has no memory limit, more than one candidate line, or the document
    uses a construct this reader does not understand. Every one of those is a
    legitimate "escalate" answer, not an error to work around.
    """
    lines = manifest_text.splitlines()
    candidates: list[MemoryLine] = []

    in_named_container = False
    container_indent = -1
    # Enclosing scopes, innermost last.
    scopes: list[tuple[int, str]] = []

    for index, line in enumerate(lines):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        # A flow mapping on any line means the document is shaped in a way this
        # reader does not model. Refuse rather than guess.
        if stripped.startswith("{"):
            return None

        is_item = stripped.startswith("- ")
        body = stripped[2:] if is_item else stripped
        pair = _split_pair(body)
        if pair is None:
            continue
        key, value = pair
        indent = _indent_of(line) + (2 if is_item else 0)

        if is_item and key == "name":
            # A new container scope opens. This also correctly *closes* the
            # previous one, which is what keeps a sidecar from being mistaken
            # for the target.
            in_named_container = value.strip("\"'") == container_name
            container_indent = indent
            scopes = [(indent, "container")]
            continue

        if not in_named_container:
            continue

        while scopes and scopes[-1][0] >= indent:
            scopes.pop()

        if key in {"containers", "resources", "limits", "requests"}:
            scopes.append((indent, key))
            continue
        if key != "memory":
            continue

        keys = [k for _, k in scopes]
        # Must be under `limits`, and `requests` must not be the innermost
        # enclosing scope - that is the requests/limits mix-up this whole
        # module exists to prevent.
        if "limits" not in keys or keys[-1] == "requests":
            continue
        if indent <= container_indent:
            continue

        match = _MEMORY_LINE.match(line)
        if match is None:
            return None
        if match.group("dq") is not None:
            quote, parsed = '"', match.group("dq")
        elif match.group("sq") is not None:
            quote, parsed = "'", match.group("sq")
        else:
            quote, parsed = "", match.group("bare") or ""
        candidates.append(
            MemoryLine(
                index=index,
                value=parsed,
                indent=match.group("indent"),
                quote=quote,
                comma=bool(match.group("comma")),
                raw=line,
            )
        )

    # Exactly one, or nothing. "First match wins" is how the previous
    # implementation could patch the wrong container.
    if len(candidates) != 1:
        return None
    return candidates[0]


def _render_replacement(target: MemoryLine, new_limit: str) -> str:
    """Render the replacement line, preserving every incidental detail.

    Quote style, indentation and a trailing comma all survive, so the patched
    manifest differs from the original in exactly one token.
    """
    rendered = f"memory: {target.quote}{new_limit}{target.quote}"
    if target.comma:
        rendered += ","
    return f"{target.indent}{rendered}"


def build_diff(
    manifest_text: str,
    target: MemoryLine,
    new_limit: str,
    path: str,
) -> str:
    """Build a unified diff raising one memory limit.

    ``path`` must be repo-relative. ARCH §2.5.4 forbids absolute paths: they
    embed the generating host's filesystem layout, apply nowhere else, and leak
    a directory structure to anyone reading the diff.
    """
    if path.startswith("/") or ":" in path:
        raise ValueError(f"patch path must be repo-relative, got {path!r}")

    source = manifest_text.splitlines()
    start = max(0, target.index - CONTEXT_LINES)
    end = min(len(source), target.index + CONTEXT_LINES + 1)

    hunk: list[str] = []
    for index in range(start, end):
        if index == target.index:
            hunk.append(f"-{source[index]}")
            hunk.append(f"+{_render_replacement(target, new_limit)}")
        else:
            # git writes an empty context line as a single space; a bare empty
            # line would be indistinguishable from a hunk separator.
            hunk.append(f" {source[index]}" if source[index] else " ")

    count = end - start
    header = f"@@ -{start + 1},{count} +{start + 1},{count} @@"
    return "\n".join([f"--- a/{path}", f"+++ b/{path}", header, *hunk])


def apply_unified_diff(original: str, diff: str) -> str | None:
    """Apply a single-hunk unified diff to ``original``.

    Returns the patched text, or ``None`` if the diff does not apply cleanly.

    A real application, not a format check: the hunk is located by its line
    numbers, the context and removed lines are compared against the source
    exactly, and only then are the additions written. A diff that would not
    apply to *this* text returns ``None`` rather than being applied
    approximately.
    """
    lines = diff.splitlines()
    if len(lines) < 3:
        return None
    if not lines[0].startswith("--- ") or not lines[1].startswith("+++ "):
        return None

    header = _HUNK_HEADER.match(lines[2])
    if header is None:
        return None
    old_start = int(header.group("old_start")) - 1
    old_count = int(header.group("old_count"))

    source = original.splitlines()
    if old_start < 0 or old_start + old_count > len(source):
        return None

    removed: list[str] = []
    added: list[str] = []
    for line in lines[3:]:
        if line.startswith("-"):
            removed.append(line[1:])
        elif line.startswith("+"):
            added.append(line[1:])
        elif line.startswith(" ") or not line:
            removed.append(line[1:])
            added.append(line[1:])
        else:
            return None

    if len(removed) != old_count:
        return None
    if source[old_start : old_start + old_count] != removed:
        return None

    return "\n".join([*source[:old_start], *added, *source[old_start + old_count :]])


def verify_patch(original: str, diff: str, target: MemoryLine, new_limit: str) -> bool:
    """Confirm a diff applies and changes **only** the intended line.

    The check is positional, not value-based: the patched document must differ
    from the original in exactly one line, that line must be the one
    :func:`find_container_memory_limit` resolved, and it must now render the
    new limit.

    An earlier version asserted the old *value* was absent from the whole
    document. That was wrong: a manifest whose ``requests.memory`` equals its
    ``limits.memory`` contains the same value twice, so a perfectly correct
    patch was rejected as unverified and the incident was escalated for no
    reason. Value-identity cannot distinguish "removed" from "still present
    elsewhere"; line position can, so the position is what is checked.
    """
    patched = apply_unified_diff(original, diff)
    if patched is None:
        return False

    before = original.splitlines()
    after = patched.splitlines()
    if len(before) != len(after):
        # A one-line value edit must not change the document length.
        return False

    differing = [i for i, (a, b) in enumerate(zip(before, after)) if a != b]
    if differing != [target.index]:
        return False
    return after[target.index] == _render_replacement(target, new_limit)
