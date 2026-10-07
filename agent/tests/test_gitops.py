"""Tests for the just-in-time GitOps checkout (agent/gitops.py).

No test touches the network or a real git binary: ``subprocess.run`` and
``shutil.which`` are patched. Every failure mode must return the unreadable
provider, never raise.
"""

from __future__ import annotations

import shutil
import subprocess
from typing import Any
from unittest import mock

import pytest

import gitops
from classifier import MANIFEST_ROOT_ENV
from gitops import (
    GITOPS_REF_ENV,
    GITOPS_REPO_URL_ENV,
    GITOPS_TOKEN_ENV,
    materialise_manifest_root,
)

URL = "https://git.example.com/org/gitops.git"


def _ok_run(*args: Any, **kwargs: Any) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(args=args, returncode=0, stdout="", stderr="")


def test_no_config_falls_back_to_existing_behavior() -> None:
    provider = materialise_manifest_root({})
    assert provider.read_manifest("deploy/x.yaml") is None


def test_manifest_root_still_wins(
    tmp_path: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "deploy" / "x.yaml"
    target.parent.mkdir(parents=True)
    target.write_text("apiVersion: v1\n")
    with mock.patch.object(subprocess, "run") as run:
        provider = materialise_manifest_root(
            {
                MANIFEST_ROOT_ENV: str(tmp_path),
                GITOPS_REPO_URL_ENV: URL,
                GITOPS_TOKEN_ENV: "tok",
            }
        )
    run.assert_not_called()
    assert provider.read_manifest("deploy/x.yaml") is not None


def test_successful_clone_serves_the_checkout() -> None:

    def fake_run(cmd: Any, **kwargs: Any) -> Any:
        assert cmd[cmd.index("clone") + 1 : cmd.index("clone") + 4] == [
            "--depth",
            "1",
            "--single-branch",
        ]
        import os as _os

        dest = cmd[-1]
        _os.makedirs(_os.path.join(dest, "deploy"), exist_ok=True)
        with open(_os.path.join(dest, "deploy", "x.yaml"), "w") as handle:
            handle.write("apiVersion: v1\n")
        return _ok_run()

    with (
        mock.patch.object(shutil, "which", return_value="/usr/bin/git"),
        mock.patch.object(subprocess, "run", side_effect=fake_run),
    ):
        provider = materialise_manifest_root(
            {GITOPS_REPO_URL_ENV: URL, GITOPS_TOKEN_ENV: "tok"}
        )
    assert provider.read_manifest("deploy/x.yaml") == "apiVersion: v1\n"


def test_token_never_reaches_argv(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[list[str]] = []

    def fake_run(cmd: Any, **kwargs: Any) -> Any:
        seen.append([str(part) for part in cmd])
        return _ok_run()

    with (
        mock.patch.object(shutil, "which", return_value="/usr/bin/git"),
        mock.patch.object(subprocess, "run", side_effect=fake_run),
    ):
        materialise_manifest_root(
            {GITOPS_REPO_URL_ENV: URL, GITOPS_TOKEN_ENV: "sekret-token"}
        )
    assert seen, "expected git to be invoked"
    for argv in seen:
        assert not any("sekret-token" in part for part in argv)


def test_clone_failure_degrades_to_unreadable() -> None:
    def bad_run(*args: Any, **kwargs: Any) -> Any:
        return subprocess.CompletedProcess(
            args=args, returncode=128, stdout="", stderr="auth failed"
        )

    with (
        mock.patch.object(shutil, "which", return_value="/usr/bin/git"),
        mock.patch.object(subprocess, "run", side_effect=bad_run),
    ):
        provider = materialise_manifest_root(
            {GITOPS_REPO_URL_ENV: URL, GITOPS_TOKEN_ENV: "bad"}
        )
    assert provider.read_manifest("deploy/x.yaml") is None


def test_clone_timeout_degrades_to_unreadable() -> None:
    def slow_run(*args: Any, **kwargs: Any) -> Any:
        raise subprocess.TimeoutExpired(cmd=args, timeout=1)

    with (
        mock.patch.object(shutil, "which", return_value="/usr/bin/git"),
        mock.patch.object(subprocess, "run", side_effect=slow_run),
    ):
        provider = materialise_manifest_root(
            {GITOPS_REPO_URL_ENV: URL, GITOPS_TOKEN_ENV: "tok"}
        )
    assert provider.read_manifest("deploy/x.yaml") is None


def test_missing_git_degrades_to_unreadable() -> None:
    with mock.patch.object(shutil, "which", return_value=None):
        provider = materialise_manifest_root(
            {GITOPS_REPO_URL_ENV: URL, GITOPS_TOKEN_ENV: "tok"}
        )
    assert provider.read_manifest("deploy/x.yaml") is None


def test_non_https_url_is_refused() -> None:
    with mock.patch.object(subprocess, "run") as run:
        provider = materialise_manifest_root(
            {
                GITOPS_REPO_URL_ENV: "git@github.com:org/repo.git",
                GITOPS_TOKEN_ENV: "tok",
            }
        )
    run.assert_not_called()
    assert provider.read_manifest("deploy/x.yaml") is None


def test_missing_token_clones_anonymously() -> None:
    seen_env: list[dict[str, str]] = []

    def fake_run(cmd: Any, **kwargs: Any) -> Any:
        seen_env.append(dict(kwargs.get("env", {})))
        return _ok_run()

    with (
        mock.patch.object(shutil, "which", return_value="/usr/bin/git"),
        mock.patch.object(subprocess, "run", side_effect=fake_run),
    ):
        provider = materialise_manifest_root({GITOPS_REPO_URL_ENV: URL})
    assert provider.read_manifest("deploy/x.yaml") is None
    assert seen_env, "expected git to be invoked"
    for env in seen_env:
        assert "GIT_CONFIG_GLOBAL" not in env


def test_dash_ref_is_refused() -> None:
    with mock.patch.object(subprocess, "run") as run:
        provider = materialise_manifest_root(
            {
                GITOPS_REPO_URL_ENV: URL,
                GITOPS_TOKEN_ENV: "tok",
                GITOPS_REF_ENV: "--upload-pack=evil",
            }
        )
    run.assert_not_called()
    assert provider.read_manifest("deploy/x.yaml") is None


def test_timeout_parsing() -> None:
    assert gitops._resolve_timeout("") == gitops.DEFAULT_TIMEOUT_SECONDS
    assert gitops._resolve_timeout("not-a-number") == gitops.DEFAULT_TIMEOUT_SECONDS
    assert gitops._resolve_timeout("1") == gitops.DEFAULT_TIMEOUT_SECONDS
    assert gitops._resolve_timeout("30") == 30.0
    assert gitops._resolve_timeout("9999") == gitops.MAX_TIMEOUT_SECONDS
