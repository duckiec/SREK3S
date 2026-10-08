"""Makefile expansion order: `:=` must not reference a variable defined later.

A `:=` assignment is expanded by `make` at the moment the line is read, not when
the variable is used. A `:=` that references a variable assigned further down the
file therefore expands to the empty string, silently, and every use site inherits
the hole.

This is not theoretical. `THROWAWAY_KUBECONFIG_KUBECTL` sat eighteen lines above
`KUBECTL ?= kubectl`, so it expanded to `KUBECONFIG=/tmp/k3s-throwaway.yaml`
with no `kubectl` in it. Every `throwaway-detonate` assertion ran

    KUBECONFIG=/tmp/k3s-throwaway.yaml  -n srek3s-system logs deployment/...

bash could not find `-n`, `2>/dev/null || true` swallowed it, the assertion read
an empty string, and the target reported

    FATAL: the Sentinel emitted no incidents (watcher_emitted=0).

while the Sentinel's own logs said `watcher_emitted:3, processed:3, failed:0`.

The reason this survived as long as it did is the part worth encoding: for a
while the assertion reported zero *correctly*, because the Sentinel genuinely was
emitting zero. A real defect (the Sentinel's NetworkPolicy denied API access
under post-DNAT evaluation) produced the same output as a broken assertion. Only
fixing the Sentinel exposed it. A verification that is right for the wrong reason
has already retired the alarm it exists to raise, so the ordering is pinned here.
"""

from __future__ import annotations

import pathlib
import re

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
MAKEFILE = REPO_ROOT / "Makefile"

#: `NAME := value`, `NAME ?= value`, `NAME != value` at column 0. Recipe lines
#: start with a tab and are excluded, because a recipe body is shell, not make.
#: The operator is captured so the caller can tell an immediate expansion from
#: a lazy one without re-parsing the line.
_ASSIGN = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\s*(\?\=|:=|!=|\+=|=)\s*(.*)$")

#: `$(NAME)` where NAME is a bare identifier. Anything containing a space, a
#: nested `$(`, or a function name (`$(shell`, `$(wildcard`) is not a variable
#: reference and is deliberately not matched.
_REF = re.compile(r"\$\(([A-Za-z_][A-Za-z0-9_]*)\)")


def _assignment_lines() -> list[tuple[int, str, str, str]]:
    """`(lineno, name, operator, value)` for assignments outside a recipe.

    The operator is captured rather than re-derived from the line afterwards. The
    first version split on the first `=` to find the operator, which reported
    `THROWAWAY_KUBECONFIG_KUBECTL := KUBECONFIG=...` as an ordinary `=`
    assignment and skipped it — so the general guard silently declined to check
    the very line it was written for.
    """
    out: list[tuple[int, str, str, str]] = []
    for n, raw in enumerate(MAKEFILE.read_text().splitlines(), start=1):
        if raw.startswith(("\t", "#")):
            continue
        m = _ASSIGN.match(raw.split(" #", 1)[0])
        if m:
            out.append((n, m.group(1), m.group(2), m.group(3)))
    return out


def test_makefile_exists() -> None:
    assert MAKEFILE.is_file()


def test_no_immediate_assignment_references_a_later_definition() -> None:
    """The general guard: `:=` before its dependency is always a latent hole."""
    assigns = _assignment_lines()

    # First definition wins for ordering purposes; a later re-assignment is an
    # override, not the introduction of a new name.
    first_seen: dict[str, int] = {}
    for lineno, name, _op, _value in assigns:
        first_seen.setdefault(name, lineno)

    offenders: list[str] = []
    for lineno, name, op, value in assigns:
        # Only `:=` expands eagerly. `?=`, `=` and `!=` expand at use.
        if op != ":=":
            continue
        for ref in _REF.findall(value):
            if ref not in first_seen:
                continue  # built-in (CURDIR, MAKEFILE_LIST, ...) or a shell var
            if first_seen[ref] > lineno:
                offenders.append(
                    f"line {lineno}: {name} := ... $({ref}) ... but {ref} is "
                    f"first defined at line {first_seen[ref]}; `:=` expands now, "
                    f"so $({ref}) is empty here"
                )

    assert not offenders, "\n".join(offenders)


def test_throwaway_kubectl_wrapper_expands_to_a_real_command() -> None:
    """The specific regression, asserted through `make` itself.

    Parsing the file would only prove the text is ordered correctly. Running
    `make -n` proves the *expansion* is, which is the thing that actually broke:
    the defect was invisible in the source and visible only after expansion.
    """
    import shutil
    import subprocess

    make = shutil.which("make")
    if make is None:
        import pytest

        pytest.skip("make binary absent")

    out = subprocess.run(
        [make, "-n", "throwaway-detonate"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout

    lines = [ln for ln in out.splitlines() if "logs deployment/srek3s-sentinel" in ln]
    assert lines, "throwaway-detonate should read the Sentinel's logs to assert on"

    for line in lines:
        assert "kubectl -n " in line or "$(" in line and "kubectl" in line, (
            "the Sentinel log read must expand to a real kubectl invocation; got "
            f"{line.strip()!r}. A missing binary here reads as 'no incidents' "
            "rather than as an error."
        )


def test_throwaway_wrapper_is_defined_after_kubectl() -> None:
    """The ordering, asserted directly so the failure names the cause."""
    lines = MAKEFILE.read_text().splitlines()
    kubectl_at = next(
        n for n, ln in enumerate(lines, start=1) if ln.startswith("KUBECTL ?=")
    )
    wrapper_at = next(
        n
        for n, ln in enumerate(lines, start=1)
        if ln.startswith("THROWAWAY_KUBECONFIG_KUBECTL")
    )
    assert wrapper_at > kubectl_at, (
        f"THROWAWAY_KUBECONFIG_KUBECTL (line {wrapper_at}) must be defined after "
        f"KUBECTL (line {kubectl_at}): `:=` expands immediately, so defining it "
        "first silently yields a wrapper with no kubectl in it"
    )
