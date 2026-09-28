# SREK3S Triage Agent — runtime image.
#
# Hardening is the point of this file, not an afterthought. AGENTS.md §2 and
# ARCHITECTURE.md §8 require: non-root UID/GID 10001, read-only root
# filesystem, all Linux capabilities dropped. The container is also the egress
# path for incident data, so anything that weakens its isolation matters twice.

# Pinned to 3.11-slim: matches ARCHITECTURE.md §2 exactly, and -slim keeps the
# image small enough to audit.
FROM python:3.11-slim

# Fail the build rather than the deploy if a package is missing from the index.
ARG PYTHON_DEPS=agent/requirements.txt

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
