"""Tests for scripts/audit_workflow.py's own machinery.

The audit is a gate. A gate whose instrument is broken does not report "I could
not measure" - it reports a confident number, and the number is wrong.

## The bug this exists for

`find_bash()` returned the first candidate it found without checking that the
candidate *worked*. On Windows, `shutil.which("bash")` usually resolves to
`C:\\Users\\<you>\\AppData\\Local\\Microsoft\\WindowsApps\\bash.exe`, which is the
Windows Subsystem for Linux launcher stub. With WSL not installed it prints an
install prompt and exits 1.

The result: every `bash -n` invocation in the audit failed, and the audit
reported **68 BASH_SYNTAX findings** against workflow steps that were
syntactically fine - including steps in `ci.yaml`, which the audit had never
touched and which had passed every previous run.

Two things were wrong with that output, and the second is the one that matters:

1. the findings were false;
2. they were *indistinguishable in kind* from a real syntax error. A reader
   checking "did I break the shell in that step?" had no way to tell that the
   shell was never consulted successfully.

The fix is `_bash_works()`: run `--version` against every candidate and require
exit 0 and `GNU bash` on stdout. These tests pin that behaviour, including the
negative control - a stub that exits non-zero must be rejected, and rejecting it
must mean falling through to a real interpreter rather than giving up.
"""

from __future__ import annotations

import os
import pathlib
import subprocess
import sys

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPTS = REPO_ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import audit_workflow  # noqa: E402


def test_a_real_bash_is_found_and_actually_runs() -> None:
    """`find_bash` must return something that executes.

    If this host has no working bash the audit *reports a skip* rather than a
    pass (see `check_bash_syntax`), so a None here is a legitimate outcome and
    the test says so instead of failing. What must never happen is returning a
    path that does not run.
    """
    found = audit_workflow.find_bash()
    if found is None:
        pytest.skip("no working bash on this host; the audit reports this as a skip")
    probe = subprocess.run(
        [found, "--version"], capture_output=True, timeout=20, check=False
    )
    assert probe.returncode == 0, f"{found} exits {probe.returncode} on --version"
    assert b"GNU bash" in probe.stdout, f"{found} did not identify as GNU bash"


def test_a_stub_that_exits_nonzero_is_rejected() -> None:
    """The core of the fix: a present-but-broken bash must not be accepted.

    Every `run:` block in every workflow is a candidate to be judged by this, so
    the judgement is asserted directly against a stand-in that behaves exactly
    like the WSL stub - present on disk, exits 1, prints nothing useful.
    """
    stub = REPO_ROOT / "agent" / "tests" / "_not_a_bash_stub"
    # A .bat shim is the closest portable stand-in for the WindowsApps stub: it
    # exists, PATH resolution finds it, and it fails. Guarded so a stray file is
    # never left behind in the repository.
    try:
        stub.write_text("@echo off\r\nexit /b 1\r\n", encoding="ascii")
        assert not audit_workflow._bash_works(
            str(stub)
        ), "a file that exits 1 was accepted as a bash"
    finally:
        stub.unlink(missing_ok=True)


def test_a_nonexistent_path_is_rejected_rather_than_raising() -> None:
    """A missing candidate must be False, not an exception.

    `find_bash` walks a candidate list that includes paths it has already
    existence-checked, but a file can disappear between the check and the call,
    and an audit that crashes on a missing interpreter reports nothing at all.
    """
    missing = str(REPO_ROOT / "definitely" / "not" / "here" / "bash.exe")
    assert not os.path.exists(missing)
    assert not audit_workflow._bash_works(missing)


def test_the_windows_stub_is_not_preferred_over_a_real_interpreter() -> None:
    """Candidate order matters, and the order is the bug.

    On Windows the Git paths are tried *before* PATH precisely because
    `which("bash")` lands on the WSL stub. This asserts the ordering rather than
    trusting the comment: if a future edit moves the PATH lookup back to the
    front, this fails on any Windows host that has both.

    Skipped elsewhere - the WindowsApps stub does not exist on Linux or in CI.
    """
    if os.name != "nt":
        pytest.skip("the WSL launcher stub is a Windows-only hazard")
    import shutil

    stub = shutil.which("bash")
    if stub is None or "WindowsApps" not in stub:
        pytest.skip("this host resolves `bash` somewhere other than WindowsApps")
    source = (SCRIPTS / "audit_workflow.py").read_text(encoding="utf-8")
    git_block = source.index('if os.name == "nt":')
    path_block = source.index('for name in ("bash", "sh"):')
    assert git_block < path_block, (
        "the PATH lookup for bash comes before the Git paths, so which('bash') "
        "can return the WSL launcher stub ahead of a working interpreter"
    )


def test_the_audit_reports_no_findings_on_the_committed_workflows() -> None:
    """The gate itself, run as a gate.

    This is the check that would have caught the 68 false findings being taken
    at face value: if the auditor cannot measure, it must say so rather than
    emit a confident FAIL. Asserting the committed workflows are clean also
    keeps the newly added in-cluster steps honest - they are `run:` blocks full
    of quoting, and a shell syntax error in one of them is invisible until CI.
    """
    proc = subprocess.run(
        [sys.executable, str(SCRIPTS / "audit_workflow.py")],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert (
        proc.returncode == 0
    ), f"audit_workflow.py exited {proc.returncode}:\n{proc.stdout[-3000:]}"
    assert "FAIL: 0" in proc.stdout, proc.stdout[-2000:]
