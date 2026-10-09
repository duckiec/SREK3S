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

import atexit
import logging
import os
import shutil
import subprocess
import tempfile
from collections.abc import Mapping
from typing import Final, Literal

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


def _discard_credential(config_path: str | None) -> None:
    """Erase a staged git credential, loudly if it cannot be erased.

    The old cleanup sat in a ``finally`` attached to the *subprocess* block, so
    every failure during staging returned before ever reaching it: a full disk at
    the ``chmod`` left a file containing ``Authorization: Bearer <token>`` on disk
    with no log line saying so. Two rejections now - one at staging, one at
    teardown - and the whole staging-through-clone span is wrapped once, so there
    is no path out of this function that skips it.

    A credential that cannot be erased is reported rather than swallowed. Silently
    passing is what made the residue invisible in the first place.
    """
    if config_path is None:
        return
    try:
        os.unlink(config_path)
    except FileNotFoundError:
        return
    except OSError as exc:
        logger.error(
            "could not remove the staged GitOps credential at %s (%s); it holds a "
            "bearer token and must be erased by hand",
            config_path,
            exc,
        )


def _stage_credential(token: str) -> str | Literal[False]:
    """Write the Authorization header to a private file.

    Returns the path on success, or ``False`` if it could not be staged and must
    not be referenced. ``False`` rather than ``None`` because ``None`` already
    means "no credential, nothing to clean up", and conflating the two is how a
    partial file ends up referenced.
    """
    fd, config_path = tempfile.mkstemp(prefix="srek3s-gitops-cred-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(
                "[http]\n\textraHeader = Authorization: Bearer " + token + "\n"
            )
        os.chmod(config_path, 0o600)
    except OSError as exc:
        logger.error("could not stage the GitOps credential: %s", exc)
        # The file may already exist holding a partial token, so it is erased here
        # rather than left for a cleanup that this failure path skips.
        _discard_credential(config_path)
        return False
    return config_path


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
    try:
        if token:
            staged = _stage_credential(token)
            if staged is False:
                return "could not stage git credential"
            config_path = staged

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
        # One span, no early return above it, so the credential is erased on every
        # outcome: success, clone failure, timeout, exec failure, and a staging
        # failure partway through writing it.
        _discard_credential(config_path)

    if completed.returncode != 0:
        diagnostic = (
            completed.stderr.strip() or completed.stdout.strip() or "no diagnostic"
        )
        return f"git clone failed: {diagnostic[:160]}"
    return None


def materialise_manifest_root(env: Mapping[str, str] | None = None) -> ManifestProvider:
    """Build the manifest provider, cloning a GitOps checkout when configured.

    Resolution order (this order was previously INVERTED, which made the whole
    module dead code as shipped):

    * ``SREK3S_GITOPS_REPO_URL`` is set -> shallow-clone it into a fresh
      directory under the process temp dir and serve that. THIS IS CHECKED
      FIRST.
    * ``SREK3S_MANIFEST_ROOT`` names a usable directory -> use it.
    * neither -> the unreadable provider.

    Why the order matters. deploy/agent.yaml and the Helm chart BOTH set
    SREK3S_MANIFEST_ROOT=/manifests *and* SREK3S_GITOPS_REPO_URL. The old code
    tested MANIFEST_ROOT first and returned immediately, so _clone never ran in
    either deployment, SREK3S_GITOPS_TOKEN was read and never used, and the
    agent served an emptyDir that is indistinguishable from a real checkout.

    The root is still honoured when no repo URL is configured - that is the
    documented file-mounted mode - but a configured repository now wins, and the
    provider that is actually built is logged by name so this can never be
    ambiguous again.

    A failed clone logs once and falls back to the manifest root if there is a
    usable one, and only then to the unreadable provider. The caller keeps
    answering incident traffic; every incident simply escalates.
    """
    source = os.environ if env is None else env
    root = (source.get(MANIFEST_ROOT_ENV) or "").strip()

    url = (source.get(GITOPS_REPO_URL_ENV) or "").strip()
    if not url:
        return _from_root(root, dict(source))

    if not url.startswith("https://"):
        logger.warning(
            "%s must be an https URL, got %r; falling back to %s",
            GITOPS_REPO_URL_ENV,
            url,
            MANIFEST_ROOT_ENV,
        )
        return _from_root(root, dict(source))

    token = (source.get(GITOPS_TOKEN_ENV) or "").strip()
    if token:
        logger.info(
            "%s is set; the clone will authenticate",
            GITOPS_TOKEN_ENV,
        )

    ref = (source.get(GITOPS_REF_ENV) or "").strip() or DEFAULT_REF
    if ref.startswith("-"):
        logger.warning(
            "%s=%r is not a valid ref; falling back to %s",
            GITOPS_REF_ENV,
            ref,
            MANIFEST_ROOT_ENV,
        )
        return _from_root(root, dict(source))
    timeout = _resolve_timeout(source.get(GITOPS_TIMEOUT_ENV) or "")

    try:
        dest = tempfile.mkdtemp(prefix="srek3s-gitops-")
    except OSError as exc:
        logger.warning("could not create GitOps checkout directory: %s", exc)
        return _from_root(root, dict(source))

    failure = _clone(url, token, ref, dest, timeout)
    if failure is not None:
        logger.warning(
            "GitOps clone of %s failed (%s); falling back to %s",
            GITOPS_REPO_URL_ENV,
            failure,
            MANIFEST_ROOT_ENV,
        )
        _rmtree(dest)
        return _from_root(root, dict(source))
    try:
        provider = FileManifestProvider(dest)
    except ValueError as exc:
        logger.warning("cloned GitOps checkout is unusable: %s", exc)
        _rmtree(dest)
        return _from_root(root, dict(source))

    # Which provider was actually built. The emptyDir case and a real checkout
    # were previously indistinguishable from each other in the logs, which is
    # precisely the failure classifier._target_manifest_is_wellformed's comment
    # says it wants to avoid.
    logger.info(
        "GitOps checkout materialised from %s (ref=%s) at %s; %s is set but NOT used",
        url,
        ref,
        dest,
        MANIFEST_ROOT_ENV,
    )
    # The checkout outlives this call - it is the manifest root the provider reads
    # from, so removing it here would make Tier-1 permanently unreachable. What it
    # must not do is outlive the *process*: /manifests is a memory-backed tmpfs, so
    # a worktree plus its .git stays resident for the pod's lifetime and is
    # reclaimed by the kernel only after SIGKILL. atexit runs on a normal exit and
    # on SIGTERM's handler, which covers every orderly path; a SIGKILL leaves the
    # directory to the container filesystem, which is the same guarantee the
    # emptyDir's sizeLimit already relies on.
    atexit.register(_rmtree, dest)
    return provider


def _rmtree(path: str) -> None:
    """Remove a temp checkout directory, ignoring failure."""
    try:
        shutil.rmtree(path, ignore_errors=True)
    except OSError:  # pragma: no cover - defensive
        pass


def _from_root(root: str, env: Mapping[str, str]) -> ManifestProvider:
    """Serve ``root`` if it is configured, else the unreadable provider."""
    if not root:
        return unreadable_manifest_provider()
    return manifest_provider_from_env(dict(env))
