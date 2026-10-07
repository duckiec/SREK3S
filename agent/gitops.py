"""Just-in-time GitOps checkout for the Tier-1 manifest provider.

The Tier-1 path needs a real checkout to verify patches against (I-B2), but
the shipped deployment mounts an emptyDir at the manifest root, so every
incident escalates. This module closes that gap for operators who opt in: when
a repository URL and token are configured, it clones once at startup and hands
the result to :class:`FileManifestProvider`.

Anything that goes wrong returns the unreadable provider. A failed clone is a
Tier-2 incident, never a crashed process.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import tempfile
from collections.abc import Mapping
from typing import Final

from classifier import (
    MANIFEST_ROOT_ENV,
    FileManifestProvider,
    ManifestProvider,
    manifest_provider_from_env,
    unreadable_manifest_provider,
)

logger = logging.getLogger("srek3s.agent.gitops")

__all__ = [
    "GITOPS_REPO_URL_ENV",
    "GITOPS_TOKEN_ENV",
    "GITOPS_REF_ENV",
    "GITOPS_TIMEOUT_ENV",
    "materialise_manifest_root",
]

GITOPS_REPO_URL_ENV: Final[str] = "SREK3S_GITOPS_REPO_URL"
GITOPS_TOKEN_ENV: Final[str] = "SREK3S_GITOPS_TOKEN"
GITOPS_REF_ENV: Final[str] = "SREK3S_GITOPS_REF"
GITOPS_TIMEOUT_ENV: Final[str] = "SREK3S_GITOPS_TIMEOUT_SECONDS"

DEFAULT_REF: Final[str] = "main"
DEFAULT_TIMEOUT_SECONDS: Final[float] = 30.0
MIN_TIMEOUT_SECONDS: Final[float] = 5.0
MAX_TIMEOUT_SECONDS: Final[float] = 300.0


def _resolve_timeout(raw: str) -> float:
    try:
        value = float(raw.strip())
    except (TypeError, ValueError):
        return DEFAULT_TIMEOUT_SECONDS
    if value != value or value < MIN_TIMEOUT_SECONDS:
        return DEFAULT_TIMEOUT_SECONDS
    return min(value, MAX_TIMEOUT_SECONDS)


def _clone(url: str, token: str, ref: str, dest: str, timeout: float) -> str | None:
    """Clone url into dest. Returns None on success, a reason on failure.

    The token never appears in argv. When set, it is written to a temporary
    gitconfig file carrying an Authorization header, and git reads it via
    GIT_CONFIG_GLOBAL. When unset, the clone runs anonymously, which is the
    correct behaviour for a public repository: sending a bogus bearer token
    makes GitHub reject even public reads with "invalid credentials".
    """
    git = shutil.which("git")
    if git is None:
        return "git is not available"
    config_path: str | None = None
    if token:
        fd, config_path = tempfile.mkstemp(prefix="srek3s-gitops-cred-")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(
                    "[http]\n\textraHeader = Authorization: Bearer " + token + "\n"
                )
            os.chmod(config_path, 0o600)
        except OSError as exc:
            return f"could not stage git credential: {exc}"
    env = dict(os.environ)
    if config_path is not None:
        env["GIT_CONFIG_GLOBAL"] = config_path
    env["GIT_CONFIG_SYSTEM"] = os.devnull
    env["GIT_TERMINAL_PROMPT"] = "0"
    try:
        completed = subprocess.run(
            [
                git,
                "-c",
                "safe.directory=*",
                "clone",
                "--depth",
                "1",
                "--single-branch",
                "--branch",
                ref,
                "--",
                url,
                dest,
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            env=env,
        )
    except subprocess.TimeoutExpired:
        return f"git clone exceeded {timeout:g}s"
    except OSError as exc:
        return f"git clone could not be executed: {exc}"
    finally:
        if config_path is not None:
            try:
                os.unlink(config_path)
            except OSError:
                pass
    if completed.returncode != 0:
        diagnostic = (
            completed.stderr.strip() or completed.stdout.strip() or "no diagnostic"
        )
        return f"git clone failed: {diagnostic[:160]}"
    return None


def materialise_manifest_root(env: Mapping[str, str] | None = None) -> ManifestProvider:
    """Build the manifest provider, cloning a GitOps checkout when configured.

    Resolution order:

    * ``SREK3S_MANIFEST_ROOT`` names a usable directory -> use it, as before.
    * ``SREK3S_GITOPS_REPO_URL`` is set -> shallow-clone it into a fresh
      directory under the process temp dir and serve that.
    * neither -> the unreadable provider, as before.

    A failed clone logs once and returns the unreadable provider. The caller
    keeps answering incident traffic; every incident simply escalates.
    """
    source = os.environ if env is None else env
    if (source.get(MANIFEST_ROOT_ENV) or "").strip():
        return manifest_provider_from_env(dict(source))

    url = (source.get(GITOPS_REPO_URL_ENV) or "").strip()
    if not url:
        return manifest_provider_from_env(dict(source))
    if not url.startswith("https://"):
        logger.warning(
            "%s must be an https URL, got %r; every incident escalates",
            GITOPS_REPO_URL_ENV,
            url,
        )
        return unreadable_manifest_provider()

    token = (source.get(GITOPS_TOKEN_ENV) or "").strip()
    if token:
        logger.info(
            "%s is set; the clone will authenticate",
            GITOPS_TOKEN_ENV,
        )

    ref = (source.get(GITOPS_REF_ENV) or "").strip() or DEFAULT_REF
    if ref.startswith("-"):
        logger.warning(
            "%s=%r is not a valid ref; every incident escalates",
            GITOPS_REF_ENV,
            ref,
        )
        return unreadable_manifest_provider()
    timeout = _resolve_timeout(source.get(GITOPS_TIMEOUT_ENV) or "")

    try:
        dest = tempfile.mkdtemp(prefix="srek3s-gitops-")
    except OSError as exc:
        logger.warning("could not create GitOps checkout directory: %s", exc)
        return unreadable_manifest_provider()

    failure = _clone(url, token, ref, dest, timeout)
    if failure is not None:
        logger.warning(
            "GitOps clone of %s failed (%s); every incident escalates",
            GITOPS_REPO_URL_ENV,
            failure,
        )
        return unreadable_manifest_provider()
    try:
        return FileManifestProvider(dest)
    except ValueError as exc:
        logger.warning("cloned GitOps checkout is unusable: %s", exc)
        return unreadable_manifest_provider()
