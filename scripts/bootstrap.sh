#!/usr/bin/env bash
# SREK3S host pre-flight check.
#
# Runs BEFORE a developer invests in a build, so that a missing dependency is a
# sentence rather than a stack trace from somewhere in the middle of a toolchain.
#
# The design rule is that every failure message must answer three questions:
#
#   1. What is missing?
#   2. Why does this project need it? (not "it's required" — WHY)
#   3. What can I do about it?  (a command, or a link)
#
# A message that says only "error: command not found" pushes all three back onto
# the reader, and a reader who cannot answer them will work around the tool rather
# than install it.
#
# Exit codes are meaningful, because a CI wrapper will read them and a person
# should not have to:
#
#   0  all required dependencies present
#   1  a required dependency is missing or unusable
#   2  a warning condition (works, but something is worth knowing)
#
# NEVER print a secret, a token, or any part of an API key. This script reads
# credential FILES to report their presence and prints only lengths.

set -uo pipefail

# The repository root, resolved from this script's own location. A pre-flight
# check that only works when run from the root is a pre-flight check that gets
# run from the root by luck.
ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
# NOTE the ORDER: every `:=` default is assigned BEFORE the `readonly`. The first
# revision had `readonly REQUIRED_GO_MINOR` above its `:=`, so the variable was
# readonly-and-empty and `set -u` aborted the whole script mid-report — with a bare
# "unbound variable" that named neither the tool nor the value. A readonly that
# prevents assignment is only useful once the value exists.
MIN_PYTHON="${MIN_PYTHON:-3.11}"
REQUIRED_GO="${REQUIRED_GO:-1.23}"
REQUIRED_GO_MINOR="${REQUIRED_GO_MINOR:-23}"
readonly MIN_PYTHON REQUIRED_GO REQUIRED_GO_MINOR

FAILURES=0
WARNINGS=0

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  C_RED=$'\033[31m'; C_GRN=$'\033[32m'; C_YEL=$'\033[33m'
  C_BLU=$'\033[34m'; C_BLD=$'\033[1m';  C_RST=$'\033[0m'
else
  C_RED=""; C_GRN=""; C_YEL=""; C_BLU=""; C_BLD=""; C_RST=""
fi

pass()    { printf '  %s[ ok ]%s %s\n' "$C_GRN" "$C_RST" "$1"; }
fail()    { printf '  %s[FAIL]%s %s\n' "$C_RED" "$C_RST" "$1"; FAILURES=$((FAILURES + 1)); }
warn()    { printf '  %s[WARN]%s %s\n' "$C_YEL" "$C_RST" "$1"; WARNINGS=$((WARNINGS + 1)); }
info()    { printf '       %s\n' "$1"; }
section() { printf '\n%s%s%s\n' "$C_BLD" "$1" "$C_RST"; }

# Print a multi-line remedy indented under a failure. Kept separate so every
# failure message has the same shape, which is most of why they get read.
remedy() { printf '       %s\n' "$1"; }

# ---------------------------------------------------------------------------
# 1. Platform
# ---------------------------------------------------------------------------
section "Platform"

# `uname` is the only portable source here. /etc/os-release is parsed separately
# because it is the only reliable source of the DISTRO, and the distro decides
# which package manager the remedy names.
UNAME_S=$(uname -s)
UNAME_M=$(uname -m)
HOST_OS=""
HOST_DISTRO=""
HOST_DISTRO_VERSION=""

case "$UNAME_S" in
  Linux)  HOST_OS="Linux" ;;
  Darwin) HOST_OS="Darwin" ;;
  *)
    fail "unsupported operating system: $UNAME_S"
    remedy "SREK3S is developed on Linux and macOS."
    remedy "On Windows, use WSL2 — a Linux userspace is required."
    ;;
esac

if [ -r /etc/os-release ]; then
  # shellcheck disable=SC1091
  . /etc/os-release 2>/dev/null || true
  HOST_DISTRO="${NAME:-unknown}"
  HOST_DISTRO_VERSION="${VERSION_ID:-}"
fi

case "$UNAME_M" in
  x86_64|amd64)  HOST_ARCH="x86_64" ;;
  aarch64|arm64) HOST_ARCH="aarch64" ;;
  *)
    fail "unsupported architecture: $UNAME_M"
    remedy "Supported: x86_64 (amd64) and aarch64 (arm64)."
    ;;
esac

if [ -n "$HOST_ARCH" ]; then
  pass "OS         $HOST_OS ${HOST_DISTRO:+$HOST_DISTRO $HOST_DISTRO_VERSION}"
  pass "arch       $HOST_ARCH ($(uname -m))"
fi

# Map this platform to the packages each dependency needs. A remedy naming the
# wrong package manager is worse than no remedy, so it is derived rather than
# guessed.
pkg_install_hint() {
  case "$1" in
    docker)    echo "https://docs.docker.com/engine/install/" ;;
    go)        echo "https://go.dev/dl/ (install 1.23 or newer)" ;;
    python)    echo "install python3.11+" ;;
    git)       echo "install git" ;;
    make)      echo "install GNU make" ;;
    *)         echo "install $1" ;;
  esac
}

# ---------------------------------------------------------------------------
# 2. docker
# ---------------------------------------------------------------------------
section "Container runtime"

if ! command -v docker >/dev/null 2>&1; then
  fail "docker: not found on PATH"
  remedy "SREK3S builds two container images and the gates assert their contents."
  remedy "Docker: $(pkg_install_hint docker)"
else
  DOCKER_VERSION=$(docker --version 2>/dev/null | head -1 | sed 's/.*version //')
  pass "docker     ${DOCKER_VERSION:-version unknown}"

  # Reachability is separate from presence, and there are TWO reasons it can fail
  # with very different remedies: the daemon is stopped, or this user lacks
  # permission to talk to it.
  #
  # Distinguishing them matters. The first revision reported "daemon not
  # reachable, start Docker" on a machine where Docker was running perfectly and
  # the user simply was not in the `docker` group — telling a developer to restart
  # a healthy daemon. The permission case is a WARNING, not a failure: every
  # command in this project works with `sudo docker …`, so nothing is blocked, and
  # marking it [FAIL] would train people to ignore the failures that matter.
  if docker info >/dev/null 2>&1; then
    pass "daemon     reachable"
  elif sudo -n docker info >/dev/null 2>&1; then
    warn "docker daemon: reachable only with sudo"
    info "This user cannot talk to the daemon socket directly."
    info "That is a host permission arrangement, not a project defect: every"
    info "command here works as 'sudo docker …'. Add yourself to the docker"
    info "group if you would rather not type sudo."
  else
    fail "docker daemon: not reachable, though the CLI is installed"
    if docker info 2>&1 | grep -qi 'permission denied'; then
      remedy "The daemon socket is refusing this user AND sudo did not work."
      remedy "Add yourself to the docker group, or start the daemon."
    else
      remedy "The daemon appears to be stopped. Start Docker and re-run."
      remedy "If DOCKER_HOST is set, check it points at a running daemon."
    fi
  fi

  # buildx is required by `make build`, and a plain `docker build` works without
  # it — so a developer can pass several targets successfully and then hit this
  # for the first time on the one that matters.
  if docker buildx version >/dev/null 2>&1; then
    BUILDX_VERSION=$(docker buildx version 2>/dev/null | head -1 | sed 's/.*v\([0-9.]*\).*/\1/')
    pass "buildx     v${BUILDX_VERSION:-unknown}"
  else
    fail "docker buildx: not available"
    remedy "'make build' uses buildx for multi-architecture support."
    remedy "On Linux this ships with Docker; on Docker Desktop it is built in."
    remedy "Otherwise install the buildx plugin."
  fi
fi

# ---------------------------------------------------------------------------
# 3. Go
# ---------------------------------------------------------------------------
section "Go toolchain"

if ! command -v go >/dev/null 2>&1; then
  fail "go: not found on PATH"
  remedy "The Sentinel daemon is Go and 'make test-go' is a required gate."
  remedy "Go $(printf '%s' "$REQUIRED_GO")+: $(pkg_install_hint go)"
else
  GO_VERSION_RAW=$(go version 2>/dev/null | awk '{print $3}')
  GO_VERSION_RAW="${GO_VERSION_RAW#go}"
  pass "go         ${GO_VERSION_RAW:-unknown}"

  # Compare numerically, not lexically: "go1.9" sorts ABOVE "go1.23" as a string,
  # which would pass a 1.9 toolchain and fail every build with a confusing error
  # from the module loader.
  GO_MAJOR=$(printf '%s' "$GO_VERSION_RAW" | cut -d. -f1)
  GO_MINOR=$(printf '%s' "$GO_VERSION_RAW" | cut -d. -f2)
  if [ -n "$GO_MAJOR" ] && [ -n "$GO_MINOR" ]; then
    if [ "$GO_MAJOR" -gt 1 ] || { [ "$GO_MAJOR" -eq 1 ] && [ "$GO_MINOR" -ge "$REQUIRED_GO_MINOR" ]; }; then
      pass "version    >= $(printf '%s' "$REQUIRED_GO") (required by go.mod)"
    else
      fail "go $(printf '%s' "$GO_VERSION_RAW") is older than the required $(printf '%s' "$REQUIRED_GO")"
      remedy "go.mod declares 'go $(printf '%s' "$REQUIRED_GO")'; older toolchains refuse the module."
      remedy "$(pkg_install_hint go)"
    fi
  fi

  # The race detector needs cgo, which needs a C compiler. This is checked here
  # rather than discovered as a linker error, because "go test -race is a
  # required gate" plus a missing gcc is otherwise discovered halfway through.
  if go env CGO_ENABLED 2>/dev/null | grep -q '^1$'; then
    pass "cgo        enabled (race detector available)"
  elif command -v cc >/dev/null 2>&1 || command -v gcc >/dev/null 2>&1; then
    pass "cgo        a C compiler is present"
  else
    warn "no C compiler found and CGO_ENABLED=0"
    info "'go test -race' may be unavailable; it is a required gate in CI."
    info "Install gcc (Linux) or the Xcode command line tools (macOS)."
  fi
fi

# ---------------------------------------------------------------------------
# 4. Python
# ---------------------------------------------------------------------------
section "Python interpreter"

# AGENTS.md §2 pins 3.11 and forbids 3.12+ syntax. This check matters more than it
# looks: a developer's default `python3` is frequently too NEW, and a too-new
# interpreter produces black/flake8/mypy errors that read as style violations
# rather than as a version mismatch.
PY_OK=""
for candidate in "$ROOT_DIR/.venv311/bin/python" python3.11 python3.12 python3.13 python3; do
  [ -n "$candidate" ] || continue
  # A path containing a slash is used directly; a bare name goes through PATH.
  if [[ "$candidate" == */* ]]; then
    [ -x "$candidate" ] || continue
    BIN="$candidate"
  else
    command -v "$candidate" >/dev/null 2>&1 || continue
    BIN="$candidate"
  fi
  if "$BIN" -c "import sys; sys.exit(0 if sys.version_info[:2] >= (3, 11) else 1)" 2>/dev/null; then
    PY_OK="$BIN"
    break
  fi
done

if [ -z "$PY_OK" ]; then
  fail "no Python >= ${MIN_PYTHON} interpreter found"
  remedy "The gates pin Python ${MIN_PYTHON} strictly (AGENTS.md §2) and forbid 3.12+ syntax."
  remedy "This machine's default python3 is often NEWER than that, which fails the gates."
  remedy "Install ${MIN_PYTHON}+, then run 'make bootstrap' to create .venv311."
else
  PY_VERSION=$("$PY_OK" -c 'import sys; print("%d.%d.%d" % sys.version_info[:3])' 2>/dev/null)
  pass "python     $PY_VERSION  ($PY_OK)"
  case "$PY_OK" in
    *.venv311/*) pass "venv       using .venv311 (the pinned interpreter)" ;;
    *)
      warn "using a system interpreter, not .venv311"
      info "'make bootstrap' creates .venv311, which is what the gates are pinned to."
      ;;
  esac
fi

# ---------------------------------------------------------------------------
# 5. Supporting tools
# ---------------------------------------------------------------------------
section "Supporting tools"

for tool in git make; do
  if command -v "$tool" >/dev/null 2>&1; then
    pass "$(printf '%-10s' "$tool") $($tool --version 2>/dev/null | head -1 | cut -c1-48)"
  else
    if [ "$tool" = "make" ]; then
      fail "make: not found on PATH"
      remedy "Every developer entry point is a Makefile target."
      remedy "macOS: xcode-select --install   Debian/Ubuntu: apt install make   Fedora: dnf install make"
    else
      fail "$tool: not found on PATH"
      remedy "$(pkg_install_hint "$tool")"
    fi
  fi
done

# ---------------------------------------------------------------------------
# 6. Cluster access — a warning, never a failure
# ---------------------------------------------------------------------------
section "Cluster"

if ! command -v kubectl >/dev/null 2>&1; then
  warn "kubectl not found"
  info "'make deploy' and the live tests need it; the offline gates do not."
else
  KUBECTL_VERSION=$(kubectl version --client 2>/dev/null | head -1 | sed 's/.*v\([0-9.]*\).*/\1/')
  pass "kubectl    v${KUBECTL_VERSION:-unknown}"
  if kubectl cluster-info >/dev/null 2>&1; then
    CTX=$(kubectl config current-context 2>/dev/null || echo unknown)
    pass "cluster    reachable ($CTX)"
  else
    warn "no reachable cluster from the current context"
    info "The offline gates ('make test') do not need one; 'make deploy' does."
  fi
fi

# ---------------------------------------------------------------------------
# 7. Credentials — presence only, never a value
# ---------------------------------------------------------------------------
section "Credentials (optional)"

CRED_FOUND=0
for f in .env .env.local; do
  if [ ! -f "$f" ]; then
    continue
  fi
  CRED_FOUND=1
  if grep -q '^GEMINI_API_KEY=' "$f" 2>/dev/null; then
    LEN=$(grep '^GEMINI_API_KEY=' "$f" | head -1 | cut -d= -f2- | tr -d '"'"'"'\r\n' | wc -c | tr -d ' ')
    info "$f: GEMINI_API_KEY present (${LEN} bytes — value not shown)"
  else
    info "$f: present, no GEMINI_API_KEY"
  fi
done

if [ "$CRED_FOUND" -eq 0 ]; then
  info "no .env or .env.local found."
  info "Without a key the agent still runs: tier, patch and validation are"
  info "deterministic and the model is only used for the Tier-2 narrative."
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
printf '\n%s%s%s\n' "$C_BLD" "────────────────────────────────────────────────────────" "$C_RST"
if [ "$FAILURES" -eq 0 ]; then
  printf '%s%s✓ all required dependencies present%s' "$C_BLD" "$C_GRN" "$C_RST"
  if [ "$WARNINGS" -gt 0 ]; then
    printf ' (%s warning(s))' "$WARNINGS"
  fi
  printf '\n'
  printf '  Next: make bootstrap && make test\n'
  exit 0
fi

printf '%s%s✗ %s required dependency problem(s)%s' "$C_BLD" "$C_RED" "$FAILURES" "$C_RST"
if [ "$WARNINGS" -gt 0 ]; then
  printf ', %s warning(s)' "$WARNINGS"
fi
printf '\n'
printf '\n  The offline gates can still run without a container runtime.\n'
printf '  Everything else needs the items marked [FAIL] above.\n'
exit 1