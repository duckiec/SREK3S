# SREK3S Triage Agent — runtime image.
#
# Hardening is the point of this file, not an afterthought. AGENTS.md §2 and
# ARCHITECTURE.md §8 require: non-root UID/GID 10001, read-only root
# filesystem, all Linux capabilities dropped. The container is also the egress
# path for incident data, so anything that weakens its isolation matters twice.

# Pinned to 3.11-slim: matches ARCHITECTURE.md §2 exactly, and -slim keeps the
# image small enough to audit. The tag publishes both linux/amd64 and linux/arm64.
#
# ---------------------------------------------------------------------------
# MULTI-ARCHITECTURE
# ---------------------------------------------------------------------------
# Python needs NO cross-compilation machinery, and that is worth being precise
# about rather than leaving implicit. There is no `GOARCH` equivalent here:
# `pip install` resolves wheels for the interpreter that is RUNNING, not for a
# declared target, so a `--platform=linux/arm64` build runs an arm64 interpreter
# and installs arm64 wheels — correctly, without being told to.
#
# What the default gives this file is precisely what that reasoning wanted.
# The opposite — `--platform=$BUILDPLATFORM` — would have been an ACTIVE bug: on an
# arm64 host building an amd64 image it would install ARM64 wheels (including
# `google-generativeai`'s arm64 protobuf) into an image labelled `linux/amd64`.
# The install SUCCEEDS, the label is a lie, and the failure appears at pod start
# as an `Illegal instruction` or a missing `.so` — long after the build reported
# success. That failure mode is why the wrong value here is worse than no value,
# and it is the opposite of the Sentinel's Go stage, where $BUILDPLATFORM IS
# correct.
#
# NO `--platform=` FLAG HERE, for the same reason as the Sentinel's runtime
# stage: the final stage already defaults to $TARGETPLATFORM, and naming it makes
# BuildKit emit `RedundantTargetPlatform` on every single build. That warning was
# seen on the Sentinel, removed there, and then observed again here — which is the
# argument for checking rather than fixing once.
#
# What the default gives this file is precisely what the reasoning above wanted:
# an arm64 build runs an arm64 interpreter and installs arm64 wheels. The opposite
# -- `--platform=$BUILDPLATFORM` -- would have been an ACTIVE bug: an arm64 host
# building an amd64 image would install arm64 wheels into an image labelled
# `linux/amd64`. The install succeeds, the tag lies, and the failure surfaces at
# pod start as an `Illegal instruction` or a missing `.so`.
FROM python:3.11-slim

# Declared so the architecture assertion further down can read TARGETARCH.
# BuildKit sets it automatically for `docker buildx build --platform=...`; a plain
# `docker build` leaves it EMPTY, which the assertion treats as "native" — correct,
# because without --platform the image is for the build host.
ARG TARGETARCH

# Fail the build rather than the deploy if a package is missing from the index.
ARG PYTHON_DEPS=agent/requirements.txt

# ---------------------------------------------------------------------------
# git IS A RUNTIME DEPENDENCY, NOT A BUILD-TIME ONE.
#
# AGENTS.md §2 requires it: "Base image must include `git` for patch validation."
# It was missing, and the consequence was that NO Tier-1 patch could ever be
# produced from this image. Observed live, not inferred:
#
#   $ docker run --rm --entrypoint sh registry.internal/srek3s-agent:0.1.0 \
#       -c 'command -v git || echo GIT_ABSENT'
#   GIT_ABSENT
#
# and in the agent's own triage log, for every incident:
#
#   escalated to Tier-2 ... reasons=I-B2 verification failed, so the patch is
#   discarded rather than emitted unvalidated (ROADMAP 2.5.6): git is not
#   available, so `git apply --check` cannot run
#
# This is the fail-closed path working exactly as designed — an unverifiable patch
# is discarded rather than emitted — which is why the system looked healthy while
# being permanently incapable of Tier-1. A defect that degrades to the safe state
# is the hardest kind to notice: nothing errors, nothing crashes, and every
# escalation is individually correct.
#
# WHY NO TEST CAUGHT IT. `agent/tests/test_sentinel_image.py` and the Dockerfile
# static audit check base image, UID/GID, env vars, USER ordering and COPY sources.
# None of them executes the image's entrypoint path far enough to reach
# `shutil.which("git")` inside `agent/patch.py::git_apply_check`, because that
# function is only reached when a manifest is readable AND a patch is synthesised —
# neither of which is true in the offline suite, where the provider is a fixture.
# The gap is the same shape as `terminationGracePeriodSeconds`: the assertion was
# satisfied without exercising the capability it was asserting.
#
# WHY IT IS INSTALLED HERE AND NOT IN requirements.txt: it is a BINARY, not a
# Python package. pip cannot provide it, and pretending otherwise is how the
# requirement was satisfied on paper.
# ---------------------------------------------------------------------------
RUN apt-get update \
 && apt-get install --no-install-recommends -y git \
 && rm -rf /var/lib/apt/lists/*

# ---------------------------------------------------------------------------
# Dependencies first, in their own layer.
#
# Copied before the source so that editing application code does not invalidate
# the dependency layer. This is a build-time optimisation only; it has no
# bearing on the runtime posture below.
# ---------------------------------------------------------------------------
COPY ${PYTHON_DEPS} /tmp/requirements.txt
RUN python -m pip install --no-cache-dir --upgrade pip \
 && python -m pip install --no-cache-dir -r /tmp/requirements.txt \
 && rm -f /tmp/requirements.txt

# Fail the BUILD, not the deploy. Asserting it here rather than in a test means the
# defect cannot ship in an image at all: a Dockerfile that loses this line fails
# loudly at build time instead of producing an agent that silently escalates every
# incident to Tier-2 for the life of the deployment.
RUN command -v git >/dev/null || (echo "FATAL: git missing; Tier-1 can never be reached" >&2; exit 1)

# ---------------------------------------------------------------------------
# ARCHITECTURE ASSERTION — the check that catches a wrong --platform line.
# ---------------------------------------------------------------------------
# Everything above this point can succeed while producing an image for the wrong
# CPU. Nothing in apt-get or pip notices, because each was asked to do the right
# thing on the machine it was already running on.
#
# So assert it directly, comparing the interpreter's own view of its platform
# against what buildx said it was building. `dpkg --print-architecture` is the
# Debian spelling and is the one that agrees with docker's `TARGETARCH`, because
# both come from the same base-image naming; `platform.machine()` is the kernel
# spelling (`x86_64`, `aarch64`) and would need a translation table to compare.
#
# `python -c` rather than a shell test: the interpreter is what runs in
# production, so asking the interpreter is asking the thing that matters.
RUN set -eu; \
    declared="${TARGETARCH:-}"; \
    if [ -z "$declared" ]; then \
      echo "TARGETARCH unset (classic builder); image is for the build host by construction"; \
    else \
      actual="$(dpkg --print-architecture)"; \
      echo "  TARGETARCH=$declared  dpkg=$actual"; \
      if [ "$declared" != "$actual" ]; then \
        echo "FATAL: image architecture ($actual) does not match TARGETARCH ($declared)." >&2; \
        echo "       A wrong --platform= line would ship a mislabelled image whose" >&2; \
        echo "       wheels match a different CPU than its tag claims." >&2; \
        exit 1; \
      fi; \
    fi

# ---------------------------------------------------------------------------
# Unprivileged runtime identity.
#
# A group is created first so the user can own files by GID as well as UID,
# which matters because a read-only root filesystem leaves /tmp as the only
# writable path.
# ---------------------------------------------------------------------------
RUN groupadd --gid 10001 sentinel \
 && useradd --uid 10001 --gid 10001 --create-home --home-dir /home/sentinel --shell /usr/sbin/nologin sentinel

# Working directory owned by the runtime user, so the app is readable and
# writable by the identity that actually runs it.
WORKDIR /app
COPY --chown=10001:10001 agent/ /app/

# ---------------------------------------------------------------------------
# Environment.
#
# PYTHONDONTWRITEBYTECODE is not optional: a read-only root filesystem cannot
# write __pycache__, and without this the interpreter fails at import time
# rather than degrading quietly.
# ---------------------------------------------------------------------------
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    TMPDIR=/tmp \
    PATH="/app:${PATH}"

# Drop root before anything else runs. After this instruction no process in
# the image can regain UID 0.
USER 10001:10001

EXPOSE 8000

# Exec form, no shell: uvicorn becomes PID 1 directly, so it receives
# SIGTERM from the kubelet and shuts down cleanly rather than being orphaned
# behind a shell that ignores signals.
#
# --host 0.0.0.0 is required for the pod network; the ServiceAccount and
# NetworkPolicy, not the bind address, are what limit reachability.
ENTRYPOINT ["python", "-m", "uvicorn", "main:app", \
            "--host", "0.0.0.0", \
            "--port", "8000", \
            "--no-access-log"]
