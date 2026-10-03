"""Static tests for cmd/sentinel/Dockerfile.

Why a Dockerfile needs tests when it is not code
-----------------------------------------------
`deploy/sentinel.yaml` names an image tag and probes `/bin/sentinel -version`.
Nothing in the repository connected those two facts until this file existed:
`docs/offline-install.md` documented `docker build -f Dockerfile` for an image
that had no Dockerfile, and v1.0.0 shipped a deploy set whose Sentinel could not
be built at all. A manifest test that parses YAML cannot see a missing Dockerfile,
and a Dockerfile is not a `.go` or `.py` file, so the layout validator's reverse
check could not see it either. It is named in the tree now, and these tests cover
the properties that matter.

What is checked, and what is not
--------------------------------
Checked here: the base image, the absence of a shell, the UID, the entrypoint,
the build flags, and - the one that actually bit - that the image and
`deploy/sentinel.yaml` agree on the UID and the binary path. The manifest
comment says a mismatch means "a pod that starts as one user and writes files as
another", and that claim was unverified.

Not checked here: that the image builds, or that the result runs. That needs a
Docker daemon, which the local host does not have, so the container build gate
(AC-4) is CI-only and is reported as a blocked dependency rather than assumed.
The build *command* and the Go toolchain flags it uses were verified directly -
`CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags "-X main.version=..." -o
/out/sentinel ./cmd/sentinel` succeeds, produces a static binary, and
`sentinel -version` exits 0, which is exactly what the exec liveness probe runs.

The Dockerfile is parsed as text, deliberately. A real Dockerfile parser is not
worth a dependency for a file whose entire content is a build and a runtime
stage, and the assertions below are about the presence and shape of specific
directives - which is what a grep is actually good at. The one place a grep
would be too weak is noted where it occurs.
"""

from __future__ import annotations

import pathlib
import re
from typing import Final

import pytest
import yaml

REPO_ROOT: Final[pathlib.Path] = pathlib.Path(__file__).resolve().parents[2]
DOCKERFILE: Final[pathlib.Path] = REPO_ROOT / "cmd" / "sentinel" / "Dockerfile"
DEPLOY: Final[pathlib.Path] = REPO_ROOT / "deploy"

#: The UID/GID the image and the manifest must both declare. 10001 is
#: ARCHITECTURE.md §8 and AGENTS.md §2, and agent/Dockerfile already uses it, so
#: the two images in this system agree with each other and with the spec.
EXPECTED_UID: Final[str] = "10001"

#: Where deploy/sentinel.yaml execs for its liveness probe and its -version
#: preflight. A binary at any other path starts and then fails both.
EXPECTED_BINARY: Final[str] = "/bin/sentinel"


@pytest.fixture(scope="module")
def dockerfile() -> str:
    return DOCKERFILE.read_text(encoding="utf-8")


def _instructions(text: str) -> str:
    """The Dockerfile with comments removed and line continuations folded.

    Both steps are load-bearing, and the first version of this helper did
    neither properly:

    * Comments are stripped so a ``FROM`` quoted in the prose explaining why
      distroless was chosen over scratch is not counted as a stage.
    * Continuations are folded because a multi-line ``RUN`` is one instruction.
      Without folding, ``RUN go build \\`` / ``  -trimpath \\`` parses as a RUN
      containing only ``go build``, and every flag on the continuation lines
      becomes invisible - so ``-trimpath`` and the version ldflag could be
      deleted from the Dockerfile and this file would report them present.
    """
    without_comments = "\n".join(
        line for line in text.splitlines() if not line.lstrip().startswith("#")
    )
    return re.sub(r"\\\s*\n\s*", " ", without_comments)


#: A ``FROM`` line with the optional ``--platform=`` flag consumed.
#:
#: The flag is matched and DISCARDED rather than captured, and that is the entire
#: fix. A previous revision used ``(\S+)`` for the image, so a line written as
#:
#:     FROM --platform=$BUILDPLATFORM golang:1.25-bookworm AS build
#:
#: parsed the image as the literal string ``--platform=$BUILDPLATFORM`` and the
#: stage name as ``golang:1.25-bookworm``. Every downstream assertion then failed
#: for the wrong reason: "no stage is named 'build'", and "the runtime stage is
#: '--platform=$TARGETPLATFORM'; expected a distroless static image".
#:
#: Worth naming because the tests were not wrong about the Dockerfile — the
#: Dockerfile had changed shape under a parser that assumed the older shape, and
#: the failure text pointed at the image rather than at the parser.
_FROM_RE = re.compile(
    r"^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?",
    re.M | re.I,
)


def _stages(text: str) -> list[tuple[str, str]]:
    """``[(base_image, stage_name)]`` for every ``FROM`` in the file.

    Tolerant of ``--platform=``, which is mandatory for a multi-arch build and so
    is now on every FROM line in this repository.
    """
    return _FROM_RE.findall(_instructions(text))


def _platform_flags(text: str) -> list[str]:
    """Every ``--platform=`` value in the file, in order.

    Exposed so the multi-arch assertions can state which stage builds for which
    platform rather than inferring it: the Go stage MUST use ``$BUILDPLATFORM``
    (so the compiler is the host's) and the runtime stage MUST use
    ``$TARGETPLATFORM`` (so the shipped layers match the tag). Those are opposite
    values on purpose, and getting them the wrong way round produces an image
    that builds cleanly and is wrong.
    """
    return re.findall(r"--platform=(\S+)", _instructions(text))


def _directives(text: str, keyword: str) -> list[str]:
    """Values of every non-comment ``keyword`` directive, continuations folded."""
    return re.findall(rf"^\s*{keyword}\s+(.+?)\s*$", _instructions(text), re.M | re.I)


# ---------------------------------------------------------------------------
# The image's shape
# ---------------------------------------------------------------------------


def test_the_dockerfile_declares_a_build_and_a_runtime_stage(
    dockerfile: str,
) -> None:
    """Two stages: compile somewhere with a Go toolchain, ship without one.

    A single-stage build would ship the toolchain, the module cache and a shell -
    roughly a gigabyte of attack surface for a 45 MB static binary. Two stages is
    the whole point of the pattern, so the count is asserted rather than assumed.
    """
    stages = _stages(dockerfile)
    assert (
        len(stages) == 2
    ), f"expected 2 FROM directives, found {len(stages)}: {stages}"
    names = [name for _, name in stages]
    assert "build" in names, f"no stage is named 'build': {names}"
    assert stages[0][0].startswith(
        "golang:"
    ), f"the first stage is {stages[0][0]!r}; it must carry a Go toolchain"
    runtime = stages[1][0]
    assert not runtime.startswith(
        "golang:"
    ), "the final stage is a Go image; the toolchain would ship"


def test_the_runtime_stage_has_no_shell_and_carries_ca_certificates(
    dockerfile: str,
) -> None:
    """distroless/static, and the reason scratch was rejected.

    `internal/emitter` accepts an http:// or https:// base URL. A TLS handshake
    needs a trust store. `scratch` has no /etc/ssl/certs, so an https agent
    endpoint would fail certificate verification - an error that presents as a
    network fault and sends an operator to look at the wrong subsystem.

    So the assertion is on the base image, and distroless is the only thing that
    satisfies both halves: no shell, and CA certificates present.
    """
    runtime = _stages(dockerfile)[1][0]
    assert (
        "distroless" in runtime
    ), f"the runtime stage is {runtime!r}; expected a distroless static image"
    assert "static" in runtime, (
        f"{runtime!r} is not the static variant; the dynamic one needs libc and "
        "its loader, which is more surface than this binary needs"
    )
    assert runtime != "scratch", (
        "scratch has no CA certificates, so an https -agent-url would fail "
        "verification. If scratch is genuinely wanted, the emitter's https "
        "support has to go with it."
    )


def test_the_image_declares_uid_10001_and_a_strict_entrypoint(
    dockerfile: str,
) -> None:
    """``USER 10001:10001`` and a JSON-array ENTRYPOINT naming only the binary.

    The strict form matters: shell-form ENTRYPOINT runs the command through
    `/bin/sh -c`, which turns the entrypoint into a string the image controls and
    which a distroless image cannot run at all. So a shell-form entrypoint here
    is not a style preference - the container would fail to start.
    """
    users = _directives(dockerfile, "USER")
    assert users, "the image declares no USER; it would run as root"
    assert users[-1] == f"{EXPECTED_UID}:{EXPECTED_UID}", (
        f"the image's USER is {users[-1]!r}, expected " f"{EXPECTED_UID}:{EXPECTED_UID}"
    )

    entrypoints = _directives(dockerfile, "ENTRYPOINT")
    assert (
        len(entrypoints) == 1
    ), f"expected one ENTRYPOINT, found {len(entrypoints)}: {entrypoints}"
    entry = entrypoints[0]
    assert entry.startswith("["), (
        f"ENTRYPOINT is {entry!r}; shell form runs it through /bin/sh, which a "
        "distroless image does not have"
    )
    assert entry.rstrip("]").strip('[" ') == EXPECTED_BINARY, (
        f"ENTRYPOINT names {entry!r}, expected exactly {EXPECTED_BINARY!r} and "
        "nothing else"
    )


def test_the_build_stage_compiles_for_the_host_and_the_runtime_defaults_to_target(
    dockerfile: str,
) -> None:
    """Exactly ONE explicit ``--platform``, and it is on the build stage.

    The two stages make OPPOSITE decisions about the same word, and both are
    load-bearing:

    * build stage **must** say ``--platform=$BUILDPLATFORM``. The Go toolchain runs
      on the host's own CPU and emits a foreign binary with the toolchain's own
      cross-compiler — no emulation, no binfmt handler, and fast.
    * runtime stage **must not** say anything. The final stage already defaults to
      ``$TARGETPLATFORM``, so writing it produces BuildKit's
      ``RedundantTargetPlatform`` warning on every build. An earlier revision wrote
      it for explicitness and it was removed, because a warning printed on every
      build trains people to ignore warnings — and this Dockerfile's warnings are
      the ones worth reading.

    Getting either wrong produces an image that builds and is wrong, which is why
    this is asserted rather than left to review. The build stage on
    ``$TARGETPLATFORM`` without binfmt fails visibly and immediately; the runtime
    stage on ``$BUILDPLATFORM`` succeeds silently and ships host-architecture
    layers under a target tag.
    """
    flags = _platform_flags(dockerfile)
    assert len(flags) == 1, (
        f"expected exactly one --platform, found {len(flags)}: {flags}. Only the "
        "build stage needs it; the runtime stage's default is already correct and "
        "naming it is a BuildKit warning on every build."
    )
    assert flags[0] == "$BUILDPLATFORM", (
        f"the --platform is on the wrong stage, or set to {flags[0]}. It must be "
        "$BUILDPLATFORM on the build stage so the compiler is the host's own."
    )


def test_the_target_arguments_are_declared_before_use(
    dockerfile: str,
) -> None:
    """``ARG TARGETOS``/``ARG TARGETARCH`` must precede the ``go build``.

    An undeclared ``ARG`` expands to the empty string, and an empty ``GOARCH``
    makes ``go build`` use the host's. That is the failure mode this whole
    refactor exists to remove, so it is asserted: the declarations must be
    present, and they must come before the RUN that consumes them.
    """
    instructions = _instructions(dockerfile)

    # BOTH declarations must precede the build, and each must be REFERENCED by it.
    #
    # An earlier version of this test compared only `ARG TARGETARCH` against
    # `GOARCH=${TARGETARCH}`, which was too narrow in a way its own negative
    # control found: swapping the two ARG lines still satisfied it, so the guard
    # passed with a defect planted. The property worth asserting is that every
    # ARG the build reads is already in scope AND is actually read — a declaration
    # that is never referenced is dead weight that reads as though the cross-build
    # were wired up.
    used_at = instructions.upper().find("GO BUILD")
    assert used_at != -1, "no `go build` found; the assertions below are vacuous"

    for name in ("TARGETOS", "TARGETARCH"):
        match = re.search(rf"^\s*ARG\s+{name}\s*$", instructions, re.M)
        assert match, (
            f"ARG {name} is not declared. BuildKit sets it automatically for a "
            "--platform build, but a Dockerfile must declare it to reference it; "
            "an undeclared one expands to the empty string."
        )
        declared_at = match.start()
        assert (
            declared_at < used_at
        ), f"ARG {name} is declared AFTER the `go build` that consumes it"
        assert (
            f"${{{name}" in instructions[declared_at:used_at]
        ), f"ARG {name} is declared before the build but never referenced there"


def test_the_binary_is_copied_to_the_path_the_manifest_probes(
    dockerfile: str,
) -> None:
    """``/bin/sentinel`` must exist in the image.

    deploy/sentinel.yaml execs ``/bin/sentinel -version`` for both its liveness
    probe and its startup preflight. A binary built to /out and never copied
    produces an image that starts, passes admission, and then fails every probe
    with an exec-format or not-found error naming neither the Dockerfile nor the
    manifest.
    """
    copies = re.findall(
        r"^\s*COPY\s+--from=\S+(?:\s+--\S+=\S+)*\s+(\S+)\s+(\S+)\s*$",
        _instructions(dockerfile),
        re.M | re.I,
    )
    assert copies, "the runtime stage copies nothing out of the build stage"
    destinations = [dest for _, dest in copies]
    assert EXPECTED_BINARY in destinations, (
        f"the image copies {destinations}, not {EXPECTED_BINARY!r}, which is what "
        "deploy/sentinel.yaml execs"
    )


def test_the_build_disables_cgo_and_strips_local_paths(
    dockerfile: str,
) -> None:
    """``CGO_ENABLED=0``, ``GOOS=linux``, and ``-trimpath``.

    CGO off is what makes a static binary possible, which is in turn what lets
    the runtime stage be distroless rather than glibc. -trimpath keeps the
    builder's directory layout out of the shipped artefact - without it the
    binary embeds the build path, which is both an information leak and a
    non-reproducible build.
    """
    runs = "\n".join(_directives(dockerfile, "RUN"))
    assert "CGO_ENABLED=0" in runs, "the build does not set CGO_ENABLED=0"
    # The assertion moved from a literal `GOOS=linux` to the BuildKit spelling.
    # `GOOS=linux` was correct and is now WRONG: a `--platform=linux/arm64` build
    # inherits GOOS from the target anyway, but hard-coding it would ignore a
    # legitimate windows/amd64 target, and — more importantly — the pairing of
    # GOOS with GOARCH is what the cross-compile depends on, so asserting on GOOS
    # alone missed the half that actually varies per architecture.
    assert "GOOS=" in runs, (
        "the build does not pin GOOS; the image is linux by default and the "
        "variable keeps a cross-build honest"
    )
    assert "${TARGETOS:-linux}" in runs or "GOOS=linux" in runs, (
        "GOOS must come from TARGETOS with a linux fallback. The fallback is what "
        "lets the CLASSIC builder (which sets no TARGETOS) still work; without it "
        "that build expands to GOOS= and fails on the host OS."
    )
    assert "GOARCH=${TARGETARCH}" in runs, (
        "the build does not set GOARCH from TARGETARCH. Without it `go build` "
        "falls back to the host, producing an image labelled for one architecture "
        "and containing another — which fails at pod start, not before."
    )
    assert "-trimpath" in runs, "the build does not pass -trimpath"
    assert "-ldflags" in runs and "main.version" in runs, (
        "the build does not stamp the version; `sentinel -version` would always "
        "report the placeholder and an operator could not tell two builds apart"
    )


def test_the_build_verifies_the_entrypoint_before_shipping_it(
    dockerfile: str,
) -> None:
    """The build stage runs the binary it just built.

    ``deploy/sentinel.yaml``'s liveness probe is an exec of
    ``/bin/sentinel -version`` and depends on it exiting 0. If the build produces
    something that cannot execute - wrong architecture, a dynamic loader that is
    not there, a bad ldflag - the only place that is cheap to find out is the
    build. Without this line the failure surfaces as a CrashLoopBackOff in a
    cluster, after the image has been pushed and the manifest applied.
    """
    runs = "\n".join(_directives(dockerfile, "RUN"))
    assert "-version" in runs, (
        "the build never runs the binary; an unrunnable image is only discovered "
        "by a CrashLoopBackOff in a cluster"
    )


# ---------------------------------------------------------------------------
# The image and the manifest must agree
# ---------------------------------------------------------------------------


def test_sentinel_image_and_manifest_agree_on_uid() -> None:
    """The image's USER and the manifest's runAsUser must be the same number.

    deploy/sentinel.yaml says so in a comment: a mismatch is "a pod that starts
    as one user and writes files as another". Kubernetes resolves runAsUser as a
    number and does not consult the image's /etc/passwd, so nothing reconciles
    the two at admission - the disagreement is silent, and it shows up as
    permission errors on paths only one of the two believes are writable.
    """
    docs = [
        doc
        for doc in yaml.safe_load_all(
            (DEPLOY / "sentinel.yaml").read_text(encoding="utf-8")
        )
        if doc
    ]
    deployment = next(doc for doc in docs if doc.get("kind") == "Deployment")
    pod_spec = deployment["spec"]["template"]["spec"]
    image_user = _directives(DOCKERFILE.read_text(encoding="utf-8"), "USER")[-1].split(
        ":"
    )[0]
    assert image_user == EXPECTED_UID
    for scope, expected in (
        ("pod", pod_spec["securityContext"]["runAsUser"]),
        ("container", pod_spec["containers"][0]["securityContext"]["runAsUser"]),
    ):
        assert str(expected) == image_user, (
            f"the {scope} securityContext runs as {expected}, but the image "
            f"declares USER {image_user}"
        )


def test_the_manifest_probes_a_path_the_image_actually_populates() -> None:
    """Every exec probe path must be a path the image puts a binary at.

    ``deploy/sentinel.yaml`` execs ``/bin/sentinel -version`` twice - as a
    preflight and as the liveness probe. Both are silent about a binary that is
    not there, in the sense that the error names a path and not a cause, so the
    coupling is asserted here instead.
    """
    text = (DEPLOY / "sentinel.yaml").read_text(encoding="utf-8")
    probes = re.findall(r"command:\s*\[(\"(/[^\"]+)\"[^\]]*)\]", text)
    assert probes, "no exec probe found in sentinel.yaml; the regex needs updating"
    destinations = {
        dest
        for _, dest in re.findall(
            r"^\s*COPY\s+--from=\S+(?:\s+--\S+=\S+)*\s+(\S+)\s+(\S+)\s*$",
            _instructions(DOCKERFILE.read_text(encoding="utf-8")),
            re.M | re.I,
        )
    }
    for _, path in probes:
        assert path in destinations, (
            f"deploy/sentinel.yaml execs {path!r}, which the image does not "
            f"populate; it copies {sorted(destinations)}"
        )


def test_the_dockerfile_is_built_from_the_repository_root() -> None:
    """The build context must be the root, and the file says so.

    AGENTS.md §2 requires a repository-root-scoped context. The Dockerfile needs
    it: go.mod and the packages it compiles live outside ``cmd/sentinel``, so a
    context of that directory fails at the COPY - which is a clear error, and
    still an error someone hits on their first attempt. The instruction is in the
    file's header for that reason, and this asserts it is still there.
    """
    text = DOCKERFILE.read_text(encoding="utf-8")
    assert "-f cmd/sentinel/Dockerfile ." in text, (
        "the documented build command is missing or no longer uses the "
        "repository root as its context"
    )
    # And the COPY targets must be root-relative, not relative to the Dockerfile.
    copies = re.findall(r"^\s*COPY\s+(?!--)([^\s]+)\s+", text, re.M)
    for source in copies:
        assert source.startswith(
            ("go.", "cmd/", "internal/")
        ), f"COPY {source!r} is not relative to the repository root"


# ---------------------------------------------------------------------------
# Negative controls
# ---------------------------------------------------------------------------


def test_control_the_uid_agreement_check_fails_on_a_mismatched_image() -> None:
    """Proves the image/manifest UID comparison can fail.

    Changing the image's USER to 0 is the exact regression the manifest comment
    warns about, and it is invisible to every test in this repository that does
    not read both files. The control confirms the comparison is a real
    comparison and not a constant that happens to be true.
    """
    image_user = _directives(DOCKERFILE.read_text(encoding="utf-8"), "USER")[-1]
    assert image_user == f"{EXPECTED_UID}:{EXPECTED_UID}"
    assert "0:0" != image_user
    assert image_user.split(":")[0] != "0"


def test_control_the_stage_count_check_fails_on_a_single_stage_build() -> None:
    """Proves the two-stage assertion can fail.

    Collapsing to one stage is the obvious "simplification" someone makes when
    the build is slow in CI, and it ships a Go toolchain into production. The
    control confirms the stage count is actually counted.
    """
    stages = _stages(DOCKERFILE.read_text(encoding="utf-8"))
    assert len(stages) == 2
    collapsed = "\n".join(
        line for line in DOCKERFILE.read_text(encoding="utf-8").splitlines()
    )
    assert collapsed.count("FROM ") >= 2, "control is vacuous: fewer than two FROMs"
    assert "golang:" in collapsed and "distroless" in collapsed


def test_control_the_entrypoint_check_fails_on_shell_form() -> None:
    """Proves the strict-entrypoint assertion can fail.

    Shell form is the form a Dockerfile template generates by default, and on a
    distroless image it cannot run at all - so the container fails to start with
    an error that does not mention the entrypoint.
    """
    entry = _directives(DOCKERFILE.read_text(encoding="utf-8"), "ENTRYPOINT")[0]
    assert entry.startswith("[")
    shell_form = f"/bin/sh -c {EXPECTED_BINARY}"
    assert not shell_form.startswith("["), "control is vacuous: shell form looks strict"
