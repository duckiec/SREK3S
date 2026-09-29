"""Generate a patch and verify it with real git. ROADMAP 4.2.1 / 4.3.1.

Exists because the agent cannot produce a patch over HTTP: ``create_app`` takes
no manifest provider, so ``triage.py`` escalates with an empty diff every time
(ARCH §5.4 I-B2 - the patch cannot be checked against a target file that was
never supplied). That gap is recorded, not worked around silently: this script
generates the diff **in process**, where a provider can be injected, and then
hands the exact bytes to ``git apply --check`` in a throwaway repository.

The distinction matters, and it is the whole point of this file. A pre-flight run
found a P0 where ``build_diff`` omitted the diff's trailing newline and
``git_apply_check`` appended it before verifying - so the gate approved a repaired
copy while the agent shipped the broken original, and reported
``patch_validated: True`` for a patch no pipeline would accept. 410 green tests
coexisted with that, because every check of this shape either used a hand-written
diff or went through the forgiving checker.

Nothing asked *git* about a diff the generator had actually produced. This does.

Exits non-zero on any failure, so the workflow step is a gate and not a notice.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Final, Sequence

_REPO_ROOT: Final[Path] = Path(__file__).resolve().parents[2]
_AGENT_DIR: Final[Path] = _REPO_ROOT / "agent"
if str(_AGENT_DIR) not in sys.path:
    sys.path.insert(0, str(_AGENT_DIR))

#: Bumped when the GitOps checkout is wired into the running service, at which
#: point the HTTP path produces patches and this script becomes a second opinion
#: rather than the only one. Recorded so "why does the agent not emit patches
#: over HTTP?" has a single answer to grep for.
PROVIDER_GAP: Final[str] = (
    "create_app() takes no manifest_provider, so the HTTP path always escalates "
    "with an empty diff (ARCH 5.4 I-B2)"
)

_GIT = shutil.which("git")


def git_run(args: Sequence[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - fixed argv, no shell
        [str(_GIT), *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False,
    )


def init_repo(root: Path, target: Path, manifest_text: str) -> None:
    """Materialise the manifest and commit it, so `git apply` has a baseline."""
    target.parent.mkdir(parents=True, exist_ok=True)
    # newline="" so the bytes on disk equal the manifest exactly; a platform
    # newline translation would put a \r on every context line and the check
    # would fail for a reason that has nothing to do with the patch.
    target.write_text(manifest_text, encoding="utf-8", newline="")
    for args in (
        ("init", "-q"),
        ("config", "user.email", "e2e@srek3s.local"),
        ("config", "user.name", "srek3s e2e"),
        ("add", "-A"),
        ("commit", "-q", "-m", "baseline"),
    ):
        result = git_run(list(args), root)
        if result.returncode != 0:
            raise SystemExit(f"git {args[0]} failed: {result.stderr.strip()}")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, help="manifest to patch")
    parser.add_argument(
        "--path",
        default="deploy/payments/checkout-api.yaml",
        help="repo-relative path the diff will declare",
    )
    parser.add_argument("--container", default="checkout-api")
    parser.add_argument("--from-limit", default="256Mi")
    parser.add_argument("--to-limit", default="512Mi")
    args = parser.parse_args(argv)

    if _GIT is None:
        print("::error::git is not on PATH; this check cannot run")
        return 2

    # Imported here, after the PATH check, so the failure mode above is a clear
    # error rather than a stack trace from a module that shells out to git.
    import patch as patch_engine  # noqa: PLC0415 - deliberate late import

    manifest_text = (Path(args.manifest)).read_text(encoding="utf-8")

    target = patch_engine.find_container_memory_limit(manifest_text, args.container)
    if target is None:
        print(
            f"::error::could not locate resources.limits.memory for container "
            f"{args.container!r} in {args.manifest}"
        )
        return 1
    if args.from_limit not in manifest_text:
        print(
            f"::error::the manifest does not contain the expected limit "
            f"{args.from_limit!r}; the diff would be built against a fixture that "
            f"is not the one under test"
        )
        return 1

    diff = patch_engine.build_diff(manifest_text, target, args.to_limit, args.path)
    print(f"  generated diff: {len(diff)} bytes, terminated={diff.endswith(chr(10))}")
    print()
    print("=== GENERATED DIFF ===")
    print(diff)

    # --- 1. structural round-trip, the agent's own applier -----------------
    patched = patch_engine.apply_unified_diff(manifest_text, diff)
    if patched is None:
        print("::error::the agent's own applier cannot apply the agent's own diff")
        return 1
    if args.to_limit not in patched:
        print(f"::error::the applied manifest does not contain {args.to_limit!r}")
        return 1
    print("  [ok] structural round-trip")

    # --- 2. real git, on the exact bytes -----------------------------------
    with tempfile.TemporaryDirectory(prefix="srek3s-e2e-verify-") as tmp:
        root = Path(tmp)
        target_file = root / args.path
        init_repo(root, target_file, manifest_text)

        patch_file = root / "generated.patch"
        # The exact bytes the agent would emit. No trailing-newline repair here
        # either; the whole P0 was a verifier normalising its input.
        patch_file.write_text(diff, encoding="utf-8", newline="")

        checked = git_run(
            ["apply", "--check", "--whitespace=nowarn", str(patch_file)], root
        )
        if checked.returncode != 0:
            print("::error::real git rejected the generated diff:")
            print(checked.stderr.strip())
            return 1
        print("  [ok] git apply --check")

        # --- 3. negative control ------------------------------------------
        # A check that cannot fail is not a check. Break the diff the way the P0
        # broke it - remove the terminator - and confirm real git rejects it.
        broken_file = root / "unterminated.patch"
        broken_file.write_text(diff[:-1], encoding="utf-8", newline="")
        broken = git_run(
            ["apply", "--check", "--whitespace=nowarn", str(broken_file)], root
        )
        if broken.returncode == 0:
            print(
                "::error::git accepted an unterminated diff; the positive result "
                "above is not meaningful"
            )
            return 1
        print("  [ok] negative control: git rejects the unterminated variant")

        # --- 4. and the agent's own gate agrees ----------------------------
        ok, reason = patch_engine.git_apply_check(manifest_text, diff, args.path)
        if not ok:
            print(f"::error::git_apply_check disagreed with real git: {reason}")
            return 1
        print("  [ok] agent's I-B2 gate agrees with real git")

    # --- 5. and the agent, given a provider, reaches Tier-1 ----------------
    outcome = _triage_round_trip(args, manifest_text)
    if outcome != 0:
        return outcome

    print()
    print("  RESULT: PASS - generated, applied, and independently verified")
    print(f"  note: {PROVIDER_GAP}")
    return 0


def _triage_round_trip(args: Any, manifest_text: str) -> int:
    """The whole path, with a provider injected so I-B2 can be satisfied."""
    import classifier  # noqa: PLC0415
    import models  # noqa: PLC0415
    import triage  # noqa: PLC0415

    document = json.loads(
        (_REPO_ROOT / "tests" / "fixtures" / "sample-incident.json").read_text(
            encoding="utf-8"
        )
    )
    # The canonical fixture carries an explanatory `_comment` block, and
    # IncidentPayload sets extra: forbid. Leaving it in is the loud way to find
    # out; stripping it is the right way to build a request.
    document.pop("_comment", None)
    document["container_name"] = args.container
    document["reason"] = "OOMKilled"
    document["exit_code"] = 137
    # I-A2: an OOMKill with no memory limit is not a Tier-1 shape, and the
    # emitter refuses to build it at all.
    document.setdefault("resource_limits", {})["memory_limit"] = args.from_limit
    document["scrubbed_logs"] = [
        "CHAOS-CRED aws_access_key_id=[REDACTED] aws_secret_access_key=[REDACTED]",
        "CHAOS-CRED jwt=[REDACTED]",
        "CHAOS-CRED dsn=postgres://chaos_user:[REDACTED]@db.internal:5432/billing",
        "CHAOS-PHASE creds-planted next=memory-exhaustion",
    ]
    document["redaction_report"] = {
        "total_redactions": 6,
        "rules_triggered": [
            "aws_access_key_id",
            "aws_secret_access_key",
            "jwt",
            "basic_auth_url",
        ],
    }

    try:
        payload = models.IncidentPayload.model_validate(document)
    except Exception as exc:  # noqa: BLE001 - the message is the diagnostic
        print(f"::error::the synthetic incident does not satisfy the schema: {exc}")
        return 1

    provider = classifier.StaticManifestProvider({args.path: manifest_text})
    outcome = triage.triage_payload(payload, manifest_provider=provider)
    response = outcome.response

    print(f"  tier:            {outcome.tier}")
    print(f"  status:          {response.status}")
    print(f"  patch_validated: {response.remediation.patch_validated}")

    # I-B1, the invariant that a Tier-2 response carries no patch. Asserted here
    # as well as in the unit suite because this is the shape the workflow
    # depends on, and a Tier-2 with a patch would be the most consequential
    # possible regression.
    if str(outcome.tier).endswith("TIER_2_ARCHITECTURAL"):
        if response.remediation.git_patch or response.remediation.patch_validated:
            print("::error::I-B1 violated: a Tier-2 response carries a patch")
            return 1
        print("  [ok] I-B1 held: Tier-2 carries no patch")
        for reason in outcome.reasons:
            print(f"        reason: {reason}")
        return 0

    if not response.remediation.patch_validated:
        print("::error::Tier-1 reached but the patch is not marked validated")
        return 1
    if not response.remediation.git_patch.endswith("\n"):
        print("::error::the emitted patch is not newline-terminated (the P0)")
        return 1
    print(f"  patch bytes:     {len(response.remediation.git_patch)}")
    print("  [ok] Tier-1 with a validated, terminated patch")
    return 0


if __name__ == "__main__":
    sys.exit(main())
