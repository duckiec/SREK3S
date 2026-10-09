"""What the Tier-1 path leaves on disk.

Two classes: the staged GitOps credential helper, and the clone directory.
"""

from __future__ import annotations

import atexit
import logging
import os
import subprocess
from pathlib import Path
from typing import Final

import pytest

import gitops

CANARY: Final[str] = "ghp_CANARYTOKEN_0123456789abcdefghij"


def _init_repo_with_file(name: str, relative: str, content: str) -> Path:
    """A local origin repo holding one file, so a clone can actually succeed."""
    origin = Path(tempfile_dir()) / f"{name}-origin.git"
    work = Path(tempfile_dir()) / f"{name}-work"
    if origin.exists():
        return origin
    work.mkdir(parents=True, exist_ok=True)
    target = work / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    subprocess.run(["git", "init", "-q"], cwd=work, check=True, capture_output=True)
    for args in (
        ["add", "-A"],
        [
            "-c",
            "user.email=t@e.local",
            "-c",
            "user.name=t",
            "commit",
            "-q",
            "-m",
            "init",
        ],
        ["remote", "add", "origin", str(origin)],
        ["init", "-q", "--bare", str(origin)],
        ["push", "-q", "origin", "HEAD:main"],
    ):
        subprocess.run(["git", *args], cwd=work, check=True, capture_output=True)
    return origin


def clone_with_token(token: str = CANARY) -> tuple[str | None, str | None]:
    """Run _clone and return (credential residue on disk, the failure reason)."""
    before = set(Path(tempfile_dir()).glob("srek3s-gitops-cred-*"))
    reason = gitops._clone(
        "file:///nonexistent/srek3s-test-repo",
        token,
        "main",
        str(Path(tempfile_dir()) / "dest"),
        10.0,
    )
    after = set(Path(tempfile_dir()).glob("srek3s-gitops-cred-*"))
    residue = [
        str(p) for p in (after - before) if CANARY in p.read_text(errors="replace")
    ]
    return (residue[0] if residue else None), reason


def tempfile_dir() -> str:
    import tempfile

    return tempfile.gettempdir()


def credential_files() -> list[Path]:
    return list(Path(tempfile_dir()).glob("srek3s-gitops-cred-*"))


class TestCredentialResidue:
    def test_a_failed_clone_leaves_no_credential(self) -> None:
        residue, reason = clone_with_token()
        assert (
            reason is not None
        ), "the clone is expected to fail against file:///nonexistent"
        assert residue is None, f"a bearer token survived at {residue}"
        assert not any(
            CANARY in p.read_text(errors="replace") for p in credential_files()
        )

    def test_a_staging_failure_leaves_no_credential(self) -> None:
        """The leak: `chmod` raising returned before the cleanup `finally`.

        The old cleanup hung off the subprocess block, which a staging failure
        never entered, so a full disk mid-staging left a file containing
        ``Authorization: Bearer <token>`` on disk with no log line.
        """

        def failing_chmod(path: str, mode: int) -> None:
            raise OSError(28, "No space left on device")

        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(os, "chmod", failing_chmod)
            residue, reason = clone_with_token()

        assert reason is not None
        assert "credential" in reason
        assert (
            residue is None
        ), f"a bearer token survived a staging failure at {residue}"
        assert not any(
            CANARY in p.read_text(errors="replace") for p in credential_files()
        )

    def test_a_failed_unlink_is_reported_rather_than_swallowed(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Silently passing is what made the residue invisible in the first place."""
        with pytest.MonkeyPatch.context() as mp:

            def failing_unlink(path: str) -> None:
                raise OSError(13, "Permission denied")

            mp.setattr(os, "unlink", failing_unlink)
            with caplog.at_level(logging.ERROR, logger="srek3s.agent.gitops"):
                gitops._discard_credential("/tmp/srek3s-gitops-cred-does-not-matter")

        assert "bearer token" in caplog.text
        assert "must be erased by hand" in caplog.text

    def test_a_successful_anonymous_clone_stages_nothing(self) -> None:
        before = set(credential_files())
        reason = gitops._clone(
            "file:///nonexistent/srek3s-test-repo",
            "",
            "main",
            str(Path(tempfile_dir()) / "dest-anon"),
            10.0,
        )
        assert reason is not None
        assert (
            set(credential_files()) == before
        ), "an anonymous clone must write no credential"

    def test_a_real_clone_leaves_no_credential_on_success(self) -> None:
        """The positive case, against a repository that actually exists."""
        origin = _init_repo_with_file("srek3s-real", "README.md", "x\n")
        dest = Path(tempfile_dir()) / f"srek3s-clone-dest-{os.getpid()}"
        if dest.exists():
            subprocess.run(["rm", "-rf", str(dest)], check=True, capture_output=True)
        reason = gitops._clone(f"file://{origin}", CANARY, "main", str(dest), 30.0)
        assert reason is None, reason
        assert Path(dest).exists(), "the clone should have succeeded"
        assert not any(
            CANARY in p.read_text(errors="replace") for p in credential_files()
        ), "a bearer token survived a successful clone"


class TestCheckoutLifecycle:
    def test_a_successful_checkout_is_removed_when_the_process_exits(self) -> None:
        """The checkout must outlive the call and die with the process.

        Removing it on return would make Tier-1 permanently unreachable, because
        it is the manifest root the provider reads from. What it must not do is
        outlive the process: /manifests is a memory-backed tmpfs.
        """
        registered: list[tuple[object, tuple[object, ...]]] = []

        def spy(func: object, *args: object) -> None:
            registered.append((func, args))

        def local_clone(
            url: str, token: str, ref: str, dest: str, timeout: float
        ) -> str | None:
            """Stand in for the network, materialising the checkout locally.

            The https check is left running and passes, because that check is a
            security control and stubbing it here would be stubbing the thing under
            test elsewhere.
            """
            target = Path(dest) / "deploy" / "x.yaml"
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("kind: ConfigMap\n", encoding="utf-8")
            return None

        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(atexit, "register", spy)
            mp.setattr(gitops, "_clone", local_clone)
            provider = gitops.materialise_manifest_root(
                {gitops.GITOPS_REPO_URL_ENV: "https://github.com/duckiec/SREK3S.git"}
            )

        assert type(provider).__name__ == "FileManifestProvider", type(
            provider
        ).__name__
        assert registered, "a materialised checkout must register its own removal"
        func, args = registered[-1]
        assert func is gitops._rmtree
        dest = str(args[0])
        assert Path(dest).exists(), "the checkout must still be there while in use"
        gitops._rmtree(dest)
        assert not Path(dest).exists(), "and gone once the process ends"

    def test_a_failed_checkout_is_removed_immediately(self) -> None:
        before = set(Path(tempfile_dir()).glob("srek3s-gitops-*"))
        provider = gitops.materialise_manifest_root(
            {gitops.GITOPS_REPO_URL_ENV: "file:///nonexistent/srek3s-nope.git"}
        )
        after = set(Path(tempfile_dir()).glob("srek3s-gitops-*"))
        assert type(provider).__name__ == "_Unreadable", type(provider).__name__
        assert after - before == set(), f"a failed clone left {after - before}"
