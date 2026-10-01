# SREK3S Sentinel image.
#
# This file is referenced by docs/offline-install.md and by the E2E in-cluster
# leg, and until it existed both referenced a Dockerfile that was not here.
# deploy/sentinel.yaml names registry.internal/srek3s-sentinel:0.1.0 and probes
# /bin/sentinel -version; nothing in the repository could produce either.
#
# Build context is the REPOSITORY ROOT, not cmd/sentinel:
#
#   docker build -t registry.internal/srek3s-sentinel:0.1.0 -f cmd/sentinel/Dockerfile .
#
# AGENTS.md 2 requires a root-scoped context, and this Dockerfile needs it: the
# module's dependencies live in go.mod at the root and the packages it compiles
# live under cmd/ and internal/. A context of cmd/sentinel would contain neither,
# and the build would fail on the COPY rather than on a missing assumption.
#
# Why distroless/static and not scratch
# -------------------------------------
# The obvious minimal choice is scratch, and it is wrong here. internal/emitter
# accepts an http:// or https:// base URL, and a TLS handshake needs a trust
# store. scratch has no /etc/ssl/certs, so pointing -agent-url at an https
# endpoint would fail certificate verification - an error that reads as a network
# fault and sends an operator looking at the wrong thing. distroless/static ships
# ca-certificates and nothing else: no shell, no package manager, no libc, no
# busybox. That is the same set of things scratch would give, plus the trust
# anchors, and the difference is the whole reason to prefer it.
#
# The client-go in-cluster path needs nothing from the image: the ServiceAccount
# token, its CA, and the namespace file are all projected into the pod by the
# kubelet at /var/run/secrets/kubernetes.io/serviceaccount/, not baked in.
#
# Why UID 10001 numerically, with no /etc/passwd entry
# ---------------------------------------------------
# distroless ships no shell and no user database, and adding one would mean
# choosing a base image that has one. Kubernetes resolves runAsUser as a number
# and does not consult /etc/passwd, so USER 10001:10001 is sufficient and
# correct. It also agrees with deploy/sentinel.yaml's runAsUser, which is the
# point: the image's own declaration and the cluster's must match, or the pod
# starts as one user and writes as another. The manifest's comment says so, and
# TestSentinelImageAndManifestAgreeOnUid asserts it.
#
# /tmp is not created here
# -----------------------
# distroless has no /tmp, and this image does not add one. TMPDIR is set below
# anyway, because deploy/sentinel.yaml sets it and mounts an emptyDir there, and
# the two must agree; but the directory itself comes from the manifest. Creating
# it in the image would be a write into a layer that is mounted over at runtime,
# so the image's copy would never be the one in use - a second place where the
# image and the manifest could disagree while both looked correct.

# ---------------------------------------------------------------------------
# Build stage. Pinned to the minor version go.mod requires (1.23) rather than
# `latest`: a build that silently changes Go version can change what a build tag
# means, and a tag like `ignore` or `osusergo` is exactly the kind of thing that
# differs between releases.
# ---------------------------------------------------------------------------
FROM --platform=$BUILDPLATFORM golang:1.23-bookworm AS build

WORKDIR /src

# Dependencies first, as their own layer. The source COPY below invalidates on
# every edit, and without this split every source change would re-download the
# whole client-go tree.
#
# `go mod download` runs for the HOST's toolchain, not the target's. That is
# correct and is the whole point of the `--platform=$BUILDPLATFORM` above: the
# module graph is architecture-independent, so there is no reason to emulate a
# foreign CPU to populate it.
COPY go.mod go.sum ./
RUN go mod download

COPY cmd/ cmd/
COPY internal/ internal/

# Stamped here because main.go's version var is a placeholder ("0.1.0-dev") and
# the -version flag is what deploy/sentinel.yaml's exec liveness probe runs. An
# unstamped build reports 0.1.0-dev and the probe still passes, so the stamp is
# not load-bearing for health - it is for telling a running pod which build it is.
ARG VERSION=0.1.0-dev

# ---------------------------------------------------------------------------
# CROSS-COMPILATION
# ---------------------------------------------------------------------------
# `ARG TARGETOS` / `ARG TARGETARCH` are BuildKit's automatic platform arguments.
# They are declared here rather than used implicitly because an undeclared ARG is
# silently empty, and an empty GOARCH makes `go build` fall back to the host -
# producing an image that is labelled for one architecture and contains another,
# which fails at pod start on an exec format error and not before.
#
# `--platform=$BUILDPLATFORM` on the FROM line is what makes this GENUINE
# cross-compilation rather than emulation. The builder stays on the host's own
# CPU and emits a foreign-architecture binary with the Go toolchain's own
# cross-compiler. Nothing is translated and no binfmt handler is needed, because
# the resulting binary is never EXECUTED during the build - only written.
#
# That last clause is the entire design, because of the smoke test below.
#
# `TARGETARCH` is the GOARCH spelling BuildKit provides (`amd64`, `arm64`), not
# the Dockerfile platform spelling (`x86_64`, `aarch64`). They differ and using
# the wrong one is the classic cross-build failure: `GOARCH=x86_64` is invalid
# and `go build` reports it, while `GOARCH=aarch64` is invalid and the failure
# appears much later, as a binary that will not run.
#
# `${TARGETOS:-linux}` is a fallback, not a default: BuildKit always sets
# TARGETOS for a `FROM --platform=` build, so the fallback exists solely for the
# CLASSIC builder, which sets neither and would otherwise expand to `GOOS=` and
# fail with a message about the host OS.
ARG TARGETOS
ARG TARGETARCH

# CGO_ENABLED=0: the module has no cgo imports (asserted by the absence of any
# `import "C"`, and the resulting binary is verified to be static), and a static
# binary is what lets the runtime stage be distroless rather than glibc. It also
# means the output is runnable on any kernel of the target architecture, which is
# what lets one image be loaded on nodes of mixed architecture.
# -trimpath strips local filesystem paths from the binary; without it the build
# embeds the builder's directory layout into the shipped artefact.
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build \
      -trimpath \
      -ldflags "-s -w -X main.version=${VERSION}" \
      -o /out/sentinel \
      ./cmd/sentinel

# ---------------------------------------------------------------------------
# THE SMOKE TEST, AND WHY IT IS CONDITIONAL
# ---------------------------------------------------------------------------
# `/bin/sentinel -version` must exit 0: a file that exists but is not executable
# fails the liveness probe with a permission error naming neither this file nor
# the manifest, so this assertion is worth having.
#
# It can only run when the target architecture IS the build architecture. On this
# host (linux/arm64) a `--platform=linux/amd64` build produces an amd64 binary, and
# executing it needs a binfmt handler - `/proc/sys/fs/binfmt_misc/` on a stock
# WSL2 host contains only `register`, `status` and `WSLInterop`, so the exec
# fails with ENOEXEC and the build dies on a cross-compilation that in fact
# SUCCEEDED.
#
# So the assertion is gated on the build being native, and the gate is explicit
# rather than a silent skip: a cross build reports that it did not run the smoke
# test, so the omission is visible in the build log instead of being invisible in
# a layer that was cached.
#
# WHAT THIS COSTS, stated rather than hidden: on a cross build, "the entrypoint
# runs" is verified by `go build` succeeding and by the executable bit existing,
# not by execution. That is weaker. It is not nothing - a bad linker target or a
# missing package fails the build outright - but it does not prove the binary
# starts. `make verify-images` runs the smoke test natively for the host
# architecture, which is where the host CAN execute what it built; the cross-arch
# leg is verified by loading the image and running it under emulation, which is a
# separate, opt-in target.
RUN set -eu; \
    build_arch="$(go env GOHOSTARCH)"; \
    target_arch="${TARGETARCH:-$build_arch}"; \
    if [ "$build_arch" = "$target_arch" ]; then \
      echo "native build ($build_arch): running the entrypoint smoke test"; \
      /out/sentinel -version >/dev/null; \
    else \
      echo "cross build ($build_arch -> $target_arch): SKIPPING the entrypoint smoke test."; \
      echo "  The binary cannot be executed here without a binfmt handler."; \
      echo "  Verify it with 'make verify-images PLATFORM=linux/$target_arch' on a host with emulation."; \
    fi

# ---------------------------------------------------------------------------
# Runtime stage.
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Runtime stage.
# ---------------------------------------------------------------------------
# NO `--platform=` FLAG HERE, and BuildKit agrees: the final stage defaults to
# `$TARGETPLATFORM`, so `RedundantTargetPlatform: Setting platform to predefined
# $TARGETPLATFORM in FROM is redundant` is the warning it emits if you write it.
#
# An earlier revision DID write `--platform=$TARGETPLATFORM` here, on the reasoning
# that naming the value was clearer than relying on a default. That is a real
# trade — explicitness versus a warning on every build — and it resolved toward
# silence, because a warning printed on every build teaches people to ignore
# warnings, and this Dockerfile's warnings are the ones that matter.
#
# The asymmetry with the BUILD stage above is intentional and is the thing worth
# remembering: `--platform=$BUILDPLATFORM` there is load-bearing (it is what makes
# the build a genuine cross-compile rather than an emulation), and its absence
# here is equally load-bearing (the default is already correct). Same word, two
# opposite decisions, for two different reasons.
#
# The pin to `-debian12` is also multi-arch: distroless static publishes both
# linux/amd64 and linux/arm64, so one line serves both. Had that not been true the
# first arm64 build would have failed with `no matching manifest`, an error that
# names the tag rather than the architecture.
FROM gcr.io/distroless/static-debian12

LABEL org.opencontainers.image.title="srek3s-sentinel" \
      org.opencontainers.image.description="Read-only Kubernetes failure watcher; emits scrubbed incidents" \
      org.opencontainers.image.licenses="MIT"

# 0755 rather than the 0750 that would be tidier: a distroless image has no
# group database, so a group-owned mode depends on the kubelet resolving 10001
# through fsGroup, and a probe that cannot execute is a pod that crashloops with
# a permission error naming neither cause.
COPY --from=build --chmod=0755 /out/sentinel /bin/sentinel

ENV TMPDIR=/tmp

USER 10001:10001

# Strictly the binary and nothing else. No shell, so there is nothing for an
# attacker who reaches the container to run a command through; the liveness
# probe execs /bin/sentinel directly rather than through a shell, so it does not
# need one.
ENTRYPOINT ["/bin/sentinel"]
