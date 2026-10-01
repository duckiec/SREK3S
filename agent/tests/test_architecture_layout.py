"""ROADMAP: structural enforcement of `ARCHITECTURE.md` layout parity.

`ARCHITECTURE.md` is the single source of truth for this repository's layout
(AGENTS.md §5.1). That claim is worth nothing if the document can drift from the
filesystem silently, and it did - three times, in three different forms, none of
which any gate caught:

1. `tests/fixtures/secrets_corpus.txt` was named in the layout tree and in
   invariant **I-A1**, and in ROADMAP box `1.4.1` - a file that has never
   existed. Every corpus test reads `incident_corpus.json`, so the entire suite
   was green while three documents pointed at a phantom.
2. `internal/k8s/classify.go` was named in the tree. It has never existed either;
   the classification logic lives in `watcher.go`.
3. Roughly a dozen production files, including the whole `internal/worker/`
   package, existed and were undocumented.

None of these is a code defect. All of them are the same defect: a document that
is wrong about the repository, which is indistinguishable - from the test suite -
from a document that is right. A gate that passes on a document describing files
that do not exist is worse than no gate, because it is read as evidence.

## What is asserted, and why both directions

**Forward: every path the tree names must exist.** The directed requirement, and
the one that catches defects 1 and 2.

**Reverse: every production source file must be named by the tree.** Catches
defect 3, which the forward direction cannot see by construction - a document
that omits a file entirely is not lying about it.

Reverse is scoped to what the tree claims to enumerate. The tree names `cmd/`,
`internal/`, `agent/`, `deploy/` and `tests/fixtures/`; it does not attempt to
enumerate `docs/`, `.github/`, `scripts/` or `tests/e2e/`, and this test does not
require it to. Test files, caches and build output are excluded on the same
reason - a layout diagram is not a file inventory, and a test that demanded one
would be a test that gets deleted the first time it was inconvenient.

## Parsing

The tree is read out of `ARCHITECTURE.md` rather than restated here, so this test
and the document cannot disagree about what the document says. Indentation is
regular by construction - each nesting level is four columns - and depth is the
column at which the name begins divided by four. Verified against the tree
before being relied on, and `test_the_tree_parser_agrees_with_the_geometry`
keeps that honest.

Glob entries such as `internal/k8s/*_test.go` are expanded and must match at
least one file. A glob matching nothing is a path that does not exist, wearing a
different hat.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Final

import pytest

_ROOT: Final[Path] = Path(__file__).resolve().parents[2]
_ARCHITECTURE: Final[Path] = _ROOT / "ARCHITECTURE.md"

#: Box-drawing characters used in the tree: │ ├ └ ─ and friends.
_BOX: Final[frozenset[str]] = frozenset("│┌┐└├─╭╰")

#: Columns per nesting level in the tree. Depth is `column // _INDENT`.
_INDENT: Final[int] = 4

#: The root line names the repository itself rather than a path within it.
_ROOT_ENTRY: Final[str] = "SREK3S/"

#: Top-level directories the tree enumerates, and which the reverse checks
#: therefore cover. A directory absent from this set is out of scope, and adding
#: one is a deliberate decision about what the document claims to describe.
#:
#: ``tests`` was added when the in-cluster E2E overlay landed. It had been out of
#: scope, which meant the directory check could not see ``tests/e2e/`` - the same
#: blind spot ``internal/deploy/`` had, in the directory holding every E2E
#: fixture. A validator that covers the code and not its harness is measuring
#: half the repository, and the half it skipped is the half that runs against a
#: cluster.
_ENUMERATED_ROOTS: Final[tuple[str, ...]] = ("cmd", "internal", "agent", "tests")

#: Never enumerated: build output, caches, and anything dot-prefixed.
_IGNORED_DIR_PARTS: Final[frozenset[str]] = frozenset(
    {"__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", "bin", "docs"}
)

#: Test files are excluded from the reverse check. The tree names one glob for
#: them; listing every test file would turn a layout diagram into a file
#: inventory.
_TEST_SUFFIXES: Final[tuple[str, ...]] = ("_test.go", "_test.py", "conftest.py")


def _tree_lines() -> list[str]:
    """The fenced block that holds the layout tree.

    Located by content rather than by line number, so inserting a paragraph
    above the tree does not silently redirect the test at some other fenced
    block - which is precisely how a check passes on the wrong thing.
    """
    text = _ARCHITECTURE.read_text(encoding="utf-8")
    lines = text.splitlines()
    start: int | None = None
    for index, line in enumerate(lines):
        if line.startswith("```") and not line.startswith("```json"):
            candidate = lines[index + 1 :]
            block: list[str] = []
            for offset, inner in enumerate(candidate):
                if inner.startswith("```"):
                    body = candidate[:offset]
                    if any(entry.startswith(_ROOT_ENTRY) for entry in body):
                        start = index
                        return body
                    break
                block.append(inner)
            continue
    if start is None:
        raise AssertionError(
            f"{_ARCHITECTURE.name} contains no fenced block holding a tree whose "
            f"first entry is {_ROOT_ENTRY!r}; the layout parser has nothing to "
            "read and this test would otherwise pass on an empty result"
        )
    raise AssertionError("unreachable")


def _parse_tree(lines: list[str]) -> dict[str, bool]:
    """Map every path named in the tree to whether the tree calls it a directory.

    Returns ``{path: is_directory}``. Order-independent and rebuilt on every
    call, so a test cannot poison another's view of the document.
    """
    stack: dict[int, str] = {}
    entries: dict[str, bool] = {}
    for line in lines:
        if not line.strip():
            continue
        column = 0
        while column < len(line) and (line[column] in _BOX or line[column] == " "):
            column += 1
        name = line[column:].split("#", 1)[0].strip()
        if not name or name == _ROOT_ENTRY:
            continue
        if column % _INDENT:
            # A name that does not sit on a level boundary means the tree's
            # geometry changed and the depth arithmetic below would be wrong.
            # Failing loudly beats resolving every path one level too deep.
            raise AssertionError(
                f"tree entry {name!r} starts at column {column}, which is not a "
                f"multiple of {_INDENT}; the indent width assumed by this parser "
                "no longer matches the document"
            )
        depth = column // _INDENT
        if depth == 0:
            # Depth 0 belongs to the `SREK3S/` marker and to nothing else. An
            # entry here would produce an empty path key, which resolves to the
            # repository root and reports as "declared as a file, is a
            # directory" - a confusing error about a real directory instead of
            # the actual defect, which is an unplaceable entry.
            raise AssertionError(
                f"tree entry {name!r} starts at column 0, which is reserved for "
                f"the {_ROOT_ENTRY!r} marker; a top-level file belongs one level "
                "in, alongside AGENTS.md and ROADMAP.md"
            )
        is_directory = name.endswith("/")
        stack[depth] = name.rstrip("/")
        for stale in [key for key in stack if key > depth]:
            del stack[stale]
        path = "/".join(stack[level] for level in range(1, depth + 1))
        entries[path] = is_directory
    return entries


def _tree() -> dict[str, bool]:
    return _parse_tree(_tree_lines())


def _production_sources() -> list[str]:
    """Every non-test source file under the directories the tree enumerates."""
    found: list[str] = []
    for top in _ENUMERATED_ROOTS:
        for path in sorted((_ROOT / top).rglob("*")):
            if not path.is_file():
                continue
            relative = path.relative_to(_ROOT)
            # A `tests/` directory is excluded wholesale, not by suffix. Python
            # test modules are named `test_api.py`, `test_golden.py` and so on,
            # so a `_test.py` suffix rule catches almost none of them - the first
            # version of this check reported 20 test files as undocumented
            # production sources, which is a check crying wolf rather than a
            # check that works.
            if "tests" in relative.parts:
                continue
            if any(
                part in _IGNORED_DIR_PARTS or part.startswith(".")
                for part in relative.parts
            ):
                continue
            if path.suffix not in {".go", ".py"}:
                continue
            if path.name.endswith(_TEST_SUFFIXES):
                continue
            found.append(relative.as_posix())
    return found


# ---------------------------------------------------------------------------
# The directed invariant: the document may not name what does not exist
# ---------------------------------------------------------------------------


def _exists_exact(relative: str) -> bool:
    """Whether ``relative`` exists on disk under *exactly* that casing.

    ``Path.exists()`` is case-insensitive on Windows and case-sensitive on Linux,
    so using it makes this check weaker on the machine that runs it most often
    than on the machine that runs it in CI. That is not theoretical: ``AGENTS.MD``
    was tracked with an uppercase extension while ``ARCHITECTURE.md``'s tree names
    it ``AGENTS.md``. Both resolve on NTFS, so the forward layout check passed
    locally on every run - and on ext4 the path does not exist, so the same check
    would have failed on every CI run of the commit that added it.

    The fix is to stop asking the filesystem and ask the directory listing, whose
    entries are compared as exact strings and therefore behave identically on
    every platform. A developer on Windows and a runner on Linux now get the same
    answer to the same question, which is the only property a layout gate can
    actually rely on.
    """
    current = _ROOT
    for part in relative.split("/"):
        try:
            entries = os.listdir(current)
        except OSError:
            return False
        if part not in entries:
            return False
        current = current / part
    return current.exists()


def _unresolved(tree: dict[str, bool]) -> list[str]:
    """Every path the tree names that does not resolve on disk.

    Extracted from the test below so the negative controls call the *same*
    function the assertion does. A control that re-implements the check proves
    only that the control's own copy works; a control that calls the check
    proves the check can fail.
    """
    missing: list[str] = []
    for path, is_directory in sorted(tree.items()):
        target = _ROOT / path
        if "*" in path:
            # A glob is a claim that something matching it exists. Matching
            # nothing is the same defect as naming a literal file that is absent,
            # with an extra layer of indirection.
            if not list(_ROOT.glob(path)):
                missing.append(f"{path}  (glob matches no file)")
            continue
        if not _exists_exact(path):
            kind = "directory" if is_directory else "file"
            found = target.exists()
            if found:
                # The case-insensitive lookup succeeded, so the name is wrong
                # rather than absent. Said explicitly, because on a
                # case-insensitive filesystem the two are indistinguishable by
                # probing and the reader is left guessing which one happened.
                actual = _actual_spelling(path)
                missing.append(
                    f"{path}  (declared as a {kind}, but the file on disk is "
                    f"spelled {actual!r} - a clone on a case-sensitive filesystem "
                    f"will not have this path)"
                )
            else:
                missing.append(f"{path}  (declared as a {kind}, not on disk)")
        elif is_directory and not target.is_dir():
            missing.append(f"{path}  (declared as a directory, is a file)")
        elif not is_directory and target.is_dir():
            missing.append(f"{path}  (declared as a file, is a directory)")
    return missing


def _actual_spelling(relative: str) -> str:
    """The on-disk spelling of ``relative``, matching its case-insensitively.

    Only reached when ``_exists_exact`` failed but a case-insensitive lookup
    succeeded, so every component is guaranteed to be present under some casing.
    """
    parts: list[str] = []
    current = _ROOT
    for part in relative.split("/"):
        for entry in os.listdir(current):
            if entry.lower() == part.lower():
                parts.append(entry)
                current = current / entry
                break
        else:  # pragma: no cover - unreachable given the caller's precondition
            parts.append(part)
            break
    return "/".join(parts)


def test_every_path_named_in_the_layout_tree_exists() -> None:
    """ARCHITECTURE.md may not name a file or directory that is not there.

    This is the gate that should have caught `secrets_corpus.txt` and
    `internal/k8s/classify.go`, both of which sat in this document naming files
    that have never existed.
    """
    missing = _unresolved(_tree())
    assert not missing, (
        "ARCHITECTURE.md names paths that do not exist. It is the single source "
        "of truth for layout (AGENTS.md 5.1), so a path it names must resolve.\n"
        "  " + "\n  ".join(missing)
    )


def test_the_tree_names_a_meaningful_number_of_paths() -> None:
    """The parser must not pass on an empty or truncated read.

    A layout check that finds nothing to check has proved nothing, and would
    report green on a document whose tree had been emptied - which is the failure
    mode this file exists to prevent. Every level of the tree is required to
    appear, so a parser that silently loses half the document fails here rather
    than passing quietly.
    """
    tree = _tree()
    assert len(tree) >= 40, f"only {len(tree)} paths parsed from the layout tree"
    for required in (
        "cmd/sentinel/main.go",
        "cmd/sentinel/Dockerfile",
        "internal/scrubber/manifest.go",
        "internal/k8s/watcher.go",
        "internal/worker",
        "agent/models.py",
        "agent/verify.py",
        "deploy/rbac.yaml",
        "deploy/chaos/oom-leak.yaml",
        "tests/fixtures/incident_corpus.json",
        "tests/fixtures/expected/oom-expected.patch",
    ):
        assert required in tree, (
            f"the layout tree no longer names {required!r}; either the document "
            "changed shape or the parser is reading the wrong block"
        )
    # Depth is load-bearing, so prove the stack was exercised at more than one
    # level rather than collapsing everything to the top.
    assert max(p.count("/") for p in tree) >= 3, (
        "no path in the tree is nested three deep; the depth stack is not "
        "reconstructing paths and the existence check would be shallow"
    )


def test_the_tree_parser_agrees_with_the_geometry() -> None:
    """Depth is derived from indentation, so the indentation must be regular.

    `test_every_path_named_in_the_layout_tree_exists` depends on the arithmetic
    ``column // 4``. A tree with irregular indentation would resolve every path
    one level too deep and still report green against a matching file layout, so
    the regularity is asserted rather than assumed.
    """
    for line in _tree_lines():
        if not line.strip():
            continue
        column = 0
        while column < len(line) and (line[column] in _BOX or line[column] == " "):
            column += 1
        # A bare vertical bar is a spacer, not an entry. It carries no name and
        # its column is meaningless - testing it against the indent width
        # produced a failure on a line that describes nothing, which is the
        # mirror image of the false pass this file is written to prevent.
        if not line[column:].split("#", 1)[0].strip():
            continue
        assert column % _INDENT == 0, (
            f"tree line {line!r} has its name at column {column}, which is not a "
            f"multiple of {_INDENT}; this parser's depth arithmetic would be wrong"
        )


# ---------------------------------------------------------------------------
# The reverse invariant: the filesystem may not contain what the tree omits
# ---------------------------------------------------------------------------


def _undocumented(tree: dict[str, bool], sources: list[str]) -> list[str]:
    """Production sources the tree does not name. Shared with its control below."""
    documented = set(tree)
    # A glob covers every test file beneath it, so a file under a documented
    # glob is documented.
    globs = {path for path in documented if "*" in path}
    return [
        path
        for path in sources
        if path not in documented
        and not any(_ROOT.glob(glob) and Path(path).match(glob) for glob in globs)
    ]


def test_every_production_source_file_is_named_in_the_layout_tree() -> None:
    """A file the tree does not mention is a file the document does not describe.

    Forward parity is not enough on its own. A tree that simply omits a package
    passes every existence check while leaving the document silent about code
    that ships - which is how the entire ``internal/worker/`` package went
    undocumented, along with the emitter's wire-validation and the agent's
    sandbox worker.

    Scoped to the directories the tree enumerates, and to production sources.
    Test files, caches and build output are excluded: a layout diagram is not a
    file inventory.
    """
    undocumented = _undocumented(_tree(), _production_sources())
    assert not undocumented, (
        "these production files exist but ARCHITECTURE.md's layout tree does not "
        "name them. A path the document omits is a path it does not describe, and "
        "no existence check can see it.\n  " + "\n  ".join(undocumented)
    )


def _source_directories() -> list[str]:
    """Every directory under the roots the tree enumerates, caches excluded."""
    found: list[str] = []
    for top in _ENUMERATED_ROOTS:
        for path in sorted((_ROOT / top).rglob("*")):
            if not path.is_dir():
                continue
            relative = path.relative_to(_ROOT)
            if any(
                part in _IGNORED_DIR_PARTS or part.startswith(".")
                for part in relative.parts
            ):
                continue
            found.append(relative.as_posix())
    return found


def test_every_source_directory_is_named_in_the_layout_tree() -> None:
    """A package the tree omits is a package the document does not describe.

    The file-level reverse check above cannot see a test-only package, and that
    is not a hypothetical gap. `internal/deploy/` holds nothing but `_test.go`
    files - including `rbac_hardening_test.go`, the test that parses
    `deploy/rbac.yaml` and fails the build on a mutating verb, which is the
    guarantee the whole no-autofix story rests on. `_production_sources()`
    filters `_test.go` by design, and the forward direction only inspects paths
    the tree already names, so between them the two checks were blind to an
    entire package. It was undocumented, and the gate that exists to catch
    undocumented packages reported green.

    Checking directories closes it. A layout diagram is still not a file
    inventory - the tree keeps its `*_test.go` glob rather than listing each test
    - but every package gets named, and naming the package is what makes a
    reader able to find it.
    """
    tree = _tree()
    undocumented = [path for path in _source_directories() if path not in tree]
    assert not undocumented, (
        "these directories exist but ARCHITECTURE.md's layout tree does not name "
        "them. A package the document omits is a package the document does not "
        "describe - and a package of nothing but test files is invisible to the "
        "file-level check above.\n  " + "\n  ".join(undocumented)
    )


# ---------------------------------------------------------------------------
# Controls
# ---------------------------------------------------------------------------


def _entry_prefix(line: str) -> str:
    """The bars, padding and branch glyph that precede an entry's name."""
    column = 0
    while column < len(line) and (line[column] in _BOX or line[column] == " "):
        column += 1
    return line[:column]


def _control_tree_with(entry: str, planted_name: str) -> list[str]:
    """The real tree with `planted_name` inserted directly after `entry`.

    The planted line reuses `entry`'s own prefix verbatim. The first version
    synthesised the prefix as spaces, on the assumption that a tree line is
    padding + branch + name; it is bars + padding + branch + name. Without the
    bars the name landed on a different column, `_parse_tree` derived a
    different depth, and the control ended up asserting against a path the
    parser never produced - a control that fails for the wrong reason, and one
    that had to be hand-patched to name the right depth. Copying the sibling's
    prefix makes the planted entry's parent and depth correct by construction,
    so the control tests the rule under test and nothing else.
    """
    lines = _tree_lines()
    for index, line in enumerate(lines):
        if entry in line:
            return [
                *lines[: index + 1],
                _entry_prefix(line) + planted_name,
                *lines[index + 1 :],
            ]
    raise AssertionError(f"control anchor {entry!r} not found in the tree")


@pytest.mark.parametrize(
    ("anchor", "why"),
    [
        ("manifest.go", "a phantom file beside a real one"),
        ("oom-leak.yaml", "a phantom file in the deploy tree"),
        ("PRD.md", "a phantom file at the repository's top level"),
    ],
)
def test_the_existence_check_fails_on_a_planted_phantom(anchor: str, why: str) -> None:
    """Negative control: a path that does not exist must fail the check.

    Fed the real tree with one fabricated line, the check itself must report it.
    Without this, a parser that silently returned nothing would satisfy
    `test_every_path_named_in_the_layout_tree_exists` on every run - a check
    that cannot fail is worse than no check (docs/lessons-learned.md §1).
    """
    reported = _unresolved(_parse_tree(_control_tree_with(anchor, "ghost-file.go")))
    assert any("ghost-file.go" in entry for entry in reported), (
        f"a planted phantom was not detected ({why}); the check reported "
        f"{reported or 'nothing at all'}"
    )


def test_the_existence_check_fails_on_a_planted_glob_matching_nothing() -> None:
    """Negative control for the glob rule: a glob matching nothing must fail.

    The tree's own ``internal/k8s/*_test.go`` is the model - same parent, same
    depth, same prefix - so renaming it isolates the glob rule from the
    geometry. Asserting only that the glob matches nothing would be vacuous: it
    would pass whether or not the check noticed, which is the property under
    test.
    """
    planted = _parse_tree(_control_tree_with("*_test.go", "nothing-here-*_test.go"))
    glob = "internal/k8s/nothing-here-*_test.go"
    assert (
        glob in planted
    ), f"the planted glob resolved somewhere unexpected; got {sorted(planted)[-4:]}"
    reported = _unresolved(planted)
    assert any(
        glob in entry for entry in reported
    ), f"a glob matching no file was not reported; the check reported {reported}"


def test_the_reverse_check_fails_on_an_undocumented_file() -> None:
    """Negative control for the file-level reverse direction.

    Drops one real production file from the documented set and requires the
    check to report it. Proves the reverse check detects drift in the direction
    that forward parity cannot see - a document that silently omits a file is
    invisible to every existence assertion, so this is the only thing standing
    between the tree and a module that ships undocumented.
    """
    sources = _production_sources()
    tree = _tree()
    assert not _undocumented(
        tree, sources
    ), "control is vacuous: the check already fails"
    dropped = next(path for path in sources if path in tree)
    without = {path: flag for path, flag in tree.items() if path != dropped}
    assert dropped in _undocumented(without, sources), (
        f"removing {dropped!r} from the documented set did not make it "
        "undocumented, so the reverse check cannot fail"
    )


def test_the_directory_check_fails_on_an_undocumented_package() -> None:
    """Negative control for the directory-level reverse direction.

    The file-level control above cannot fail for a test-only package, because
    every file in one is filtered out of `_production_sources()`. This control
    drops a real *directory* from the documented set instead, which is the only
    way to show the directory check is load-bearing rather than decorative -
    and it is the case that actually occurred with `internal/deploy/`.
    """
    tree = _tree()
    directories = _source_directories()
    assert not [
        path for path in directories if path not in tree
    ], "control is vacuous: the check already fails"
    named = next(path for path in directories if path in tree)
    without = {path: flag for path, flag in tree.items() if path != named}
    assert named not in without
    assert named in [
        path for path in _source_directories() if path not in without
    ], f"removing {named!r} from the documented set did not make it undocumented"


def test_the_tree_block_is_located_by_content_not_by_line_number() -> None:
    """The parser finds the tree by its content, so moving it is safe.

    Without this, inserting a paragraph above the tree would point the test at
    some other fenced block - and a check running on the wrong block is worse
    than a check that fails.
    """
    lines = _ARCHITECTURE.read_text(encoding="utf-8").splitlines()
    assert any(
        line.startswith("```") for line in lines
    ), "no fenced blocks in ARCHITECTURE.md"
    parsed = _tree()
    assert len(parsed) >= 40, f"the located block yielded only {len(parsed)} paths"
    # Every other fenced block must be rejected, not silently parsed. The
    # document's first block is the system-overview diagram; if the locator ever
    # regressed to "the first fenced block", this is what would notice.
    for index, line in enumerate(lines):
        if not line.startswith("```") or line.startswith("```json"):
            continue
        close = next(
            (j for j in range(index + 1, len(lines)) if lines[j].startswith("```")),
            None,
        )
        if close is None or index + 1 >= len(lines):
            continue
        body = lines[index + 1 : close]
        if body and body[0].split("#", 1)[0].strip() == _ROOT_ENTRY:
            continue
        with pytest.raises(AssertionError):
            _parse_tree(body)
        return
    raise AssertionError("no non-tree fenced block found to test the locator against")


def test_a_broken_geometry_is_rejected_rather_than_misparsed() -> None:
    """Irregular indentation must fail, not resolve one level too deep.

    The depth arithmetic is ``column // 4``. Feed it a name at column 6 and it
    would silently floor to depth 1, producing a path that might exist by
    coincidence. Refusing is the only safe response.
    """
    planted = [*_tree_lines(), "      └── misplaced.go"]
    with pytest.raises(AssertionError, match="multiple of"):
        _parse_tree(planted)


def test_the_case_exact_check_fails_on_a_wrongly_cased_path() -> None:
    """Negative control for the case-sensitivity fix.

    A path differing from a real file only in case is reported, and reported as a
    *spelling* problem rather than an absence. The distinction matters: on a
    case-insensitive filesystem "not on disk" and "spelled differently" look
    identical to a probe, and the second is a bug that only manifests on the
    machine nobody developing it has - which is precisely what happened with
    `AGENTS.MD`.

    The control asserts both halves: that the exact name resolves, and that a
    case-flipped name does not and is named as a spelling rather than an absence.
    A control that only checked the first would pass whether or not the check had
    any teeth.
    """
    real = "ARCHITECTURE.md"
    flipped = "architecture.md"
    assert _exists_exact(real), "the real path must resolve exactly"
    assert not _exists_exact(flipped), (
        "a case-flipped path resolved exactly; the check is case-insensitive and "
        "would pass on Windows while failing on every Linux CI run"
    )
    # And the case-insensitive probe agrees - which is the whole reason the
    # exact check is needed rather than redundant.
    assert (_ROOT / flipped).exists(), (
        "control is vacuous on a case-insensitive filesystem: the flipped name "
        "does not resolve even case-insensitively, so this proves nothing here"
    )
    reported = _unresolved({flipped: False})
    assert reported, "a wrongly-cased path was not reported"
    assert (
        "spelled" in reported[0]
    ), f"the report does not name the spelling problem: {reported[0]!r}"
    assert (
        "ARCHITECTURE.md" in reported[0]
    ), f"the report does not say what the file is actually called: {reported[0]!r}"


def test_an_entry_at_column_zero_is_rejected() -> None:
    """Depth 0 is reserved for the root marker.

    An entry there yields an empty path key, which resolves to the repository
    root and is reported as "declared as a file, is a directory" - an error
    about a real directory that names the actual defect nowhere.

    The repository-root phantom control is what surfaced this. It was written to
    plant a file at the repository root, produced exactly that misleading
    message, and would have gone on passing while pointing an operator at the
    wrong path - a control that fails to detect its own defect.
    """
    planted = [*_tree_lines(), "stray-root-entry.go"]
    with pytest.raises(AssertionError, match="reserved"):
        _parse_tree(planted)
