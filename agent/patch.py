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
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

__all__ = [
    "CONTEXT_LINES",
    "GIT_APPLY_TIMEOUT_SECONDS",
    "MemoryLine",
    "VerificationResult",
    "apply_unified_diff",
    "build_diff",
    "find_container_memory_limit",
    "git_apply_check",
    "memory_values",
    "verify_patch",
    "verify_yaml_ast",
    "verify_patch_structure",
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
    #: Effective indent of the `containers:` sequence entries. Kubernetes
    #: manifests are full of *other* `- name:` sequence entries - named ports
    #: and volume mounts use exactly that shape - and the only thing separating
    #: them from a container entry is how deep they sit. The first `- name:`
    #: directly under a `containers:` block establishes that depth; anything
    #: deeper belongs to something else.
    container_seq_indent: int | None = None
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
            if "containers" not in [k for _, k in scopes]:
                continue
            if container_seq_indent is None:
                container_seq_indent = indent
            if indent != container_seq_indent:
                # A named port or volume mount, not a container. Ignoring it is
                # the whole point: treating these as containers silently
                # switched the target off against any realistic Deployment, so
                # every Tier-1 patch failed to locate its target. It failed
                # closed - no wrong patch was emitted - but it escalated
                # incidents that were cleanly remediable, which is the other
                # half of being wrong. Found by tests/fixtures/oom-restartloop.yaml.
                continue
            # A container entry at the sequence's own depth. Opening a scope here
            # also closes the previous container's, which is what stops a
            # sibling container's limits being collected as candidates.
            in_named_container = value.strip("\"'") == container_name
            container_indent = indent
            # `containers` is deliberately preserved rather than dropped, so a
            # later sibling `- name:` at the same depth is still recognised as a
            # container entry.
            scopes = [entry for entry in scopes if entry[1] == "containers"] + [
                (indent, "container")
            ]
            continue

        # `containers` must be tracked before the container is known, because the
        # `- name:` test above depends on it. Gating this behind
        # in_named_container meant `containers` was never recorded, the guard
        # could never pass, and *every* lookup returned None.
        if key == "containers":
            while scopes and scopes[-1][0] >= indent:
                scopes.pop()
            scopes.append((indent, "containers"))
            container_seq_indent = None
            continue

        if not in_named_container:
            continue

        while scopes and scopes[-1][0] >= indent:
            scopes.pop()

        if key in {"resources", "limits", "requests"}:
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
    # Newline-terminated, and this is load-bearing rather than stylistic.
    #
    # A unified diff whose last line carries no terminator is not a diff git can
    # read: `git apply --check` rejects it with "corrupt patch" and a non-zero
    # exit. This function used to return the join without a trailing newline, so
    # **every** patch the agent emitted was unapplyable by a real GitOps
    # pipeline, while `patch_validated: True` was reported alongside it.
    #
    # It went unnoticed because `git_apply_check` appended the missing newline
    # before verifying, so the gate checked a repair of the artifact rather than
    # the artifact. Both halves are fixed; see that function and
    # TestGitApplyCheckDoesNotForgiveAnUnterminatedDiff.
    #
    # POSIX "\n" specifically, not os.linesep: a CRLF diff has \r on every context
    # line, which will not match an LF-terminated manifest, so emitting CRLF would
    # trade one unapplyable patch for another.
    return "\n".join([f"--- a/{path}", f"+++ b/{path}", header, *hunk]) + "\n"


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


def verify_patch_structure(
    original: str, diff: str, target: MemoryLine, new_limit: str
) -> bool:
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


# ---------------------------------------------------------------------------
# I-B2: `git apply --check`
# ---------------------------------------------------------------------------

#: Bound on every `git` invocation. AGENTS.md §3.2 requires every blocking
#: operation to be deadline-bounded; an unbounded subprocess on the triage path
#: is a way to wedge the very service that exists to respond to incidents.
GIT_APPLY_TIMEOUT_SECONDS: Final[float] = 10.0


@dataclass(frozen=True)
class VerificationResult:
    """The combined patch-verification verdict, with the reasons it failed.

    Three layers, all required (AGENTS.md §1 "Dual-Layer Patch Verification",
    §3.3):

    ``structural_ok``
        The positional round-trip: the diff, applied to the manifest text, changes
        exactly the resolved line and nothing else. Proves *position*.
    ``yaml_ast_ok``
        The patched and original manifests both parse, and differ at exactly one
        semantic field - ``resources.limits.memory`` of the named container, found
        structurally. Proves *meaning*, and is what catches a textually perfect
        patch that is semantically wrong.
    ``git_apply_ok``
        ``git apply --check --whitespace=nowarn`` accepts the diff against those
        same bytes. Proves *format*, via an independent implementation.

    A bare boolean would be enough to gate on, but the caller records *why* a patch
    was discarded in its escalation audit trail, so the failures travel with the
    result rather than being dropped or recomputed.
    """

    ok: bool
    structural_ok: bool
    yaml_ast_ok: bool
    git_apply_ok: bool
    failures: tuple[str, ...] = ()

    def reason_text(self) -> str:
        """A single line suitable for a Tier-2 escalation reason."""
        return "; ".join(self.failures) if self.failures else "verified"


def _observed_bytes(
    manifest_text: str, path: str, checkout_root: str | None
) -> tuple[str | None, str]:
    """The bytes the applicability check must run against.

    Returns ``(source, note)``, where ``source`` is ``None`` when the state
    cannot be established - in which case ``note`` is the reason to fail with.
    ``note`` is otherwise the description of which source was used, so the caller's
    own report can say what was attested to rather than implying it.
    """
    if checkout_root is None:
        return manifest_text, "the bytes the manifest provider returned"

    on_disk = Path(checkout_root) / path
    try:
        text = on_disk.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        # A missing or unreadable target is a Tier-2 outcome, not a 500: the
        # whole point of the check is that it fails closed.
        return None, (
            f"the checkout at {checkout_root!r} cannot supply {path!r} ({exc}), "
            f"so the patch cannot be checked against the state the agent observed"
        )

    if text != manifest_text:
        # The agent read one thing and the checkout holds another. Which is
        # authoritative is a race for ArgoCD or the merge queue to settle, but a
        # patch validated against neither is not `patch_validated`.
        return None, (
            f"the file at {path!r} in the checkout no longer matches the bytes the "
            f"agent read; a diff validated against a manifest that is not the one "
            f"on disk is not `patch_validated` (I-B2)"
        )
    return text, "the file in the GitOps checkout"


def git_apply_check(
    manifest_text: str,
    diff: str,
    path: str,
    timeout_seconds: float = GIT_APPLY_TIMEOUT_SECONDS,
    checkout_root: str | None = None,
) -> tuple[bool, str]:
    """Run ``git apply --check`` against the manifest the agent actually observed.

    ## What this attests to

    I-B2 is that ``patch_validated: true`` means the diff applies to the file it
    claims. Which file it applies to is the whole question, and there are two
    candidates:

    * ``manifest_text`` - the bytes :class:`ManifestProvider` handed back.
    * the file in the GitOps checkout - the bytes on disk.

    Validating against the first certifies **self-consistency**: the diff applies
    to the string it was derived from. That is necessary and it is not sufficient,
    because nothing ties the string to a real file. A provider that returns a
    truncated read yields a diff with a shrunken trailing context, the diff applies
    perfectly to the truncated bytes, and the response reports I-B2 satisfied for a
    patch that does not apply to the manifest it names.

    When ``checkout_root`` is given, the bytes staged for the check are read from
    disk at ``<checkout_root>/<path>``, and ``manifest_text`` is used only to
    confirm the agent read that same file. The attestation then binds to the state
    the agent observed, which is what a GitOps pipeline will apply.

    Without a root - a :class:`StaticManifestProvider` in a test, where the held
    text *is* the state - the staged bytes are ``manifest_text`` and the
    attestation is the weaker self-consistency one. That asymmetry is stated
    rather than hidden: the two are the same property on different sources, and a
    static provider has no separate source to disagree with.

    Returns ``(passed, reason)``. Fails closed in every uncertain case - git
    absent, git unable to initialise, a timeout, an unreadable target - because an
    unverified patch must never be presented as ``patch_validated``.
    """
    if path.startswith("/") or ":" in path:
        return False, f"patch path must be repo-relative, got {path!r}"

    git = shutil.which("git")
    if git is None:
        return False, "git is not available, so `git apply --check` cannot run"

    # The bytes the check runs against. Read from the checkout when there is one,
    # so the attestation binds to the state the agent observed rather than to the
    # string it happened to receive.
    source, source_note = _observed_bytes(manifest_text, path, checkout_root)
    if source is None:
        return False, source_note

    with tempfile.TemporaryDirectory(prefix="srek3s-ib2-") as tmp:
        root = Path(tmp)
        target = root / path
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            # newline="" so the bytes on disk match the source exactly. A
            # platform newline translation would make the context lines differ
            # from those in the diff for reasons unrelated to the patch, and the
            # check would fail spuriously on Windows.
            target.write_text(source, encoding="utf-8", newline="")
            patch_file = root / "candidate.patch"
            # The diff is written **exactly as given**. No normalisation, no
            # repair, no "helpful" trailing newline.
            #
            # This line previously read `diff if diff.endswith("\n") else diff +
            # "\n"`, which silently fixed `build_diff`'s missing terminator before
            # verifying. The consequence was a gate that could not fail on the
            # defect it existed to catch: the check passed on a *repaired* copy
            # while the agent shipped the broken original, and reported "I-B2
            # satisfied" for a patch no GitOps pipeline would have accepted.
            #
            # A verifier that edits its input is not a verifier. If the generator
            # emits a malformed diff, the correct outcome is a failed check and a
            # Tier-2 escalation, not a passing check on a substituted artifact.
            #
            # `newline=""` is retained, and it is not a mutation: it disables
            # platform newline *translation* so the bytes on disk equal the bytes
            # supplied. Without it, Windows would rewrite every "\n" to "\r\n",
            # putting a \r on each context line, and the check would fail for a
            # reason that has nothing to do with the patch. The manifest above is
            # written the same way, and the two must agree.
            patch_file.write_text(diff, encoding="utf-8", newline="")
        except OSError as exc:
            return False, f"could not stage the manifest for verification: {exc}"

        try:
            init = subprocess.run(
                [git, "init", "-q"],
                cwd=tmp,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                check=False,
            )
            if init.returncode != 0:
                return False, f"git init failed: {init.stderr.strip()[:120]}"

            # `-c safe.directory=*` avoids the dubious-ownership refusal some
            # hosts raise for a freshly created temp directory. Passing it
            # per-invocation means no user or system git config is read or
            # written, which matters for a process that handles incident data.
            checked = subprocess.run(
                [
                    git,
                    "-c",
                    "safe.directory=*",
                    "apply",
                    "--check",
                    "--whitespace=nowarn",
                    str(patch_file),
                ],
                cwd=tmp,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return False, f"`git apply --check` exceeded {timeout_seconds}s"
        except OSError as exc:
            return False, f"`git apply --check` could not be executed: {exc}"

        if checked.returncode == 0:
            return True, "git apply --check passed"
        diagnostic = checked.stderr.strip() or checked.stdout.strip() or "no diagnostic"
        return False, f"`git apply --check` rejected the patch: {diagnostic[:160]}"


def verify_patch(
    original: str,
    diff: str,
    target: MemoryLine,
    new_limit: str,
    path: str,
    container_name: str,
    expected_old: str,
    git_checker: bool = True,
    checkout_root: str | None = None,
) -> VerificationResult:
    """Full I-B2 verification: structural round-trip **and** ``git apply --check``.

    Both checks must pass. The structural check proves the diff changes exactly
    the resolved line and nothing else; ``git apply --check`` proves an
    independent implementation of the unified-diff format accepts it against
    this manifest. Neither subsumes the other - the first would not notice a
    malformed hunk header if the line arithmetic happened to work out, and the
    second cannot tell a correct patch from one aimed at the wrong field.

    ``checkout_root`` decides what the second check attests to; see
    :func:`git_apply_check`. With it, the check runs against the bytes on disk in
    the GitOps checkout and refuses if they are not the bytes the agent read.

    ``git_checker`` exists so the fail-closed path can be exercised on a host
    with no git binary. It is not a production escape hatch: callers leave it on.
    """
    failures: list[str] = []

    structural_ok = verify_patch_structure(original, diff, target, new_limit)
    if not structural_ok:
        failures.append(
            "structural round-trip failed: applying the diff to the manifest did "
            "not change exactly the resolved line and nothing else"
        )

    patched = apply_unified_diff(original, diff)
    yaml_ok = False
    if patched is None:
        failures.append("YAML AST check skipped: the diff does not apply at all")
    else:
        yaml_ok, yaml_reason = verify_yaml_ast(
            original, patched, container_name, expected_old, new_limit
        )
        if not yaml_ok:
            failures.append(yaml_reason)

    git_ok = False
    if git_checker:
        git_ok, git_reason = git_apply_check(
            original, diff, path, checkout_root=checkout_root
        )
        if not git_ok:
            failures.append(git_reason)
    else:
        failures.append("`git apply --check` was disabled for this call")

    return VerificationResult(
        ok=structural_ok and yaml_ok and git_ok,
        structural_ok=structural_ok,
        yaml_ast_ok=yaml_ok,
        git_apply_ok=git_ok,
        failures=tuple(failures),
    )


# ---------------------------------------------------------------------------
# YAML AST verification
# ---------------------------------------------------------------------------
#
# AGENTS.md §1 "Dual-Layer Patch Verification" and §3.3 require structural YAML
# validation as one of the two layers. The positional round-trip above proves the
# *text* changed in exactly one place; it cannot tell whether the result is still
# a valid Kubernetes object, nor whether the changed text meant what we thought it
# meant. This layer parses both documents and proves the change is *semantically*
# exactly one field: `resources.limits.memory` of one named container.
#
# That is the check that would catch a patch which is textually perfect and
# semantically wrong - a diff that reparses but moves the limit onto the wrong
# container, drops a key, or turns an integer into a string where the schema wants
# a quantity. None of those are visible in a line diff.

#: Keys that are compared case-sensitively; Kubernetes keys are lowercase.
_MEMORY_KEY: Final[str] = "memory"


def _container_limits_path(
    document: object, container_name: str
) -> tuple[object, ...] | None:
    """Locate the ``resources.limits`` mapping for ``container_name``.

    Returns the path to the mapping itself, so its ``memory`` child is one step
    deeper. Uses the parsed structure rather than indentation, which is the whole
    point: this layer is independent of how the file happens to be laid out.
    """
    if not isinstance(document, dict):
        return None
    spec = document.get("spec")
    if not isinstance(spec, dict):
        return None
    template = spec.get("template")
    if not isinstance(template, dict):
        return None
    pod_spec = template.get("spec")
    if not isinstance(pod_spec, dict):
        return None
    containers = pod_spec.get("containers")
    if not isinstance(containers, list):
        return None
    for index, container in enumerate(containers):
        if not isinstance(container, dict) or container.get("name") != container_name:
            continue
        resources = container.get("resources")
        if not isinstance(resources, dict):
            return None
        limits = resources.get("limits")
        if not isinstance(limits, dict):
            return None
        return ("spec", "template", "spec", "containers", index, "resources", "limits")
    return None


def _diff_paths(
    left: Any, right: Any, prefix: tuple[Any, ...] = ()
) -> list[tuple[Any, ...]]:
    """Every path at which two parsed documents differ.

    Lists are compared element-wise by index rather than as opaque values, so a
    reorder or an insertion is reported as a difference instead of being absorbed
    into "the list changed". Type changes are always a difference: ``256`` and
    ``"256"`` are not the same document, and a Kubernetes quantity must not
    silently change type.
    """
    if type(left) is not type(right):
        return [prefix or ("<root>",)]
    if isinstance(left, dict):
        paths: list[tuple[Any, ...]] = []
        for key in sorted(set(left) | set(right), key=str):
            if key not in left or key not in right:
                paths.append(prefix + (key,))
            else:
                paths.extend(_diff_paths(left[key], right[key], prefix + (key,)))
        return paths
    if isinstance(left, list):
        paths = []
        if len(left) != len(right):
            paths.append(prefix + ("<length>",))
        for index in range(min(len(left), len(right))):
            paths.extend(_diff_paths(left[index], right[index], prefix + (index,)))
        return paths
    if left != right:
        return [prefix or ("<root>",)]
    return []


def verify_yaml_ast(
    original: str,
    patched: str,
    container_name: str,
    expected_old: str,
    expected_new: str,
) -> tuple[bool, str]:
    """Prove the patch changes exactly one semantic field, correctly.

    Four conditions, all required:

    1. both documents parse as YAML;
    2. they differ at exactly one path;
    3. that path is ``resources.limits.memory`` of the named container, found
       structurally rather than by index;
    4. the value moved from ``expected_old`` to ``expected_new``.

    Fails closed on anything else, including a document this layer cannot model.
    """
    try:
        import yaml
    except ImportError:  # pragma: no cover - PyYAML is a declared dependency
        return False, "PyYAML is unavailable, so the YAML AST check cannot run"

    try:
        before = yaml.safe_load(original)
        after = yaml.safe_load(patched)
    except yaml.YAMLError as exc:
        which = "patched" if "patched" in str(exc) else "original"
        return (
            False,
            f"YAML AST check failed: the {which} document does not parse ({exc})",
        )

    limits_path = _container_limits_path(before, container_name)
    if limits_path is None:
        return (
            False,
            f"YAML AST check failed: no resources.limits for container "
            f"{container_name!r} in the parsed document",
        )

    differences = _diff_paths(before, after)
    if len(differences) != 1:
        return (
            False,
            "YAML AST check failed: the patch changes "
            f"{len(differences)} semantic field(s) {differences[:6]}, "
            "expected exactly 1",
        )

    changed = differences[0]
    if tuple(changed[:-1]) != limits_path or changed[-1] != _MEMORY_KEY:
        return (
            False,
            f"YAML AST check failed: the patch changes {changed}, expected only "
            f"{limits_path + (_MEMORY_KEY,)}",
        )

    before_value = before["spec"]["template"]["spec"]["containers"][limits_path[4]][
        "resources"
    ]["limits"][_MEMORY_KEY]
    after_value = after["spec"]["template"]["spec"]["containers"][limits_path[4]][
        "resources"
    ]["limits"][_MEMORY_KEY]
    if str(before_value) != expected_old or str(after_value) != expected_new:
        return (
            False,
            f"YAML AST check failed: memory moved from {before_value!r} to "
            f"{after_value!r}, expected {expected_old!r} to {expected_new!r}",
        )

    return True, "YAML AST check passed"
