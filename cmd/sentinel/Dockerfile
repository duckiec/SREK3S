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
FROM golang:1.23-bookworm AS build

WORKDIR /src

# Dependencies first, as their own layer. The source COPY below invalidates on
# every edit, and without this split every source change would re-download the
# whole client-go tree.
COPY go.mod go.sum ./
RUN go mod download

COPY cmd/ cmd/
COPY internal/ internal/

# Stamped here because main.go's version var is a placeholder ("0.1.0-dev") and
# the -version flag is what deploy/sentinel.yaml's exec liveness probe runs. An
# unstamped build reports 0.1.0-dev and the probe still passes, so the stamp is
# not load-bearing for health - it is for telling a running pod which build it is.
ARG VERSION=0.1.0-dev

# CGO_ENABLED=0: the module has no cgo imports (asserted by the absence of any
# `import "C"`, and the resulting binary is verified to be static), and a static
# binary is what lets the runtime stage be distroless rather than glibc.
# -trimpath strips local filesystem paths from the binary; without it the build
# embeds the builder's directory layout into the shipped artefact.
RUN CGO_ENABLED=0 GOOS=linux go build \
      -trimpath \
      -ldflags "-s -w -X main.version=${VERSION}" \
      -o /out/sentinel \
      ./cmd/sentinel

# The entrypoint is probed, not the file's mode: /bin/sentinel -version must
# exit 0, and a file that exists but is not executable fails the liveness probe
# with a permission error that names neither the Dockerfile nor the manifest.
RUN /out/sentinel -version >/dev/null

# ---------------------------------------------------------------------------
# Runtime stage.
# ---------------------------------------------------------------------------
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
