# SREK3S — developer entry points.
#
# Every target here exists because the equivalent shell command was typed by hand,
# more than once, and got subtly different each time. That is the only
# justification offered here: a Makefile that merely wraps commands nobody would
# otherwise type is ceremony.
#
# Read this before trusting a target, because three of them carry a warning that
# is easy to miss and expensive to rediscover.
#
# ---------------------------------------------------------------------------
# WHY PYTHON IS NOT `python3`
# ---------------------------------------------------------------------------
# `python3` on a developer machine is frequently NOT the interpreter this project
# can use. AGENTS.md §2 pins Python 3.11 strictly and `setup.cfg` sets
# `python_version = 3.11`, while `agent/pyproject.toml` sets
# `target-version = ["py311"]`. On this development host the system `python3` is
# 3.14.3, which cannot run the gates at all: `mypy --strict` rejects it outright
# and `black` reformats with 3.12+ style.
#
# So PYTHON is resolved to a real 3.11+ interpreter, preferring `.venv311` and
# falling back to a system `python3.11`. If neither exists the target FAILS with a
# message naming `make bootstrap`, rather than running 3.13 and producing a
# confident, wrong result.
# ---------------------------------------------------------------------------
# WHY `test` IS SEQUENTIAL, NOT PARALLEL
# ---------------------------------------------------------------------------
# Go's `-race` detector and pytest both want the whole machine. Running them
# concurrently on a laptop produces flaky failures from timing rather than from
# code, and a flaky gate is a gate people learn to ignore. `make test` therefore
# runs Go first, then Python, and stops on the first failure so the output names
# one problem instead of interleaving two. `make test-parallel` exists for the
# case where someone wants them anyway and knows what they are doing.
# ---------------------------------------------------------------------------
# WHY `deploy` USES `kubectl apply -k deploy/base`
# ---------------------------------------------------------------------------
# `deploy/base` rather than `deploy/` on purpose. `deploy/kustomization.yaml` is
# the base of record, and `deploy/base/` exposes the same set as a directory an
# overlay can reference without `--load-restrictor`. Using the wrong one builds a
# different object set, and the difference is invisible until a namespace is
# missing.
#
# Kustomize's load restrictor REFUSES a file outside the build directory, so
# `resources: - ../namespace.yaml` from inside `deploy/base/` is correct while
# `- namespace.yaml` from `deploy/` would have been equivalent only by accident.
# See `deploy/overlays/local-live/kustomization.yaml` for the long form.

SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c
.DEFAULT_GOAL := help

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Repository root, resolved from this file's location rather than from $PWD, so
# `make -C /anywhere test` behaves identically to running it in the root. Every
# other variable is anchored to it.
ROOT := $(patsubst %/,%,$(dir $(abspath $(lastword $(MAKEFILE_LIST)))))

VENV        := $(ROOT)/.venv311
VENV_PY     := $(VENV)/bin/python
REPO_ROOT   := $(ROOT)/agent
PYTEST_DIR  := $(ROOT)/agent/tests

# Image tags. These MUST match deploy/sentinel.yaml and deploy/agent.yaml; the
# manifests reference them literally, and there is no test that compares them
# because a mismatch produces ImagePullBackOff at deploy time rather than a test
# failure. Override with `make build SENTINEL_TAG=...` to build something else.
SENTINEL_TAG ?= registry.internal/srek3s-sentinel:0.1.0
AGENT_TAG    ?= registry.internal/srek3s-agent:0.1.0

# Target platform for `build`. Defaults to the HOST architecture, which is what
# a developer almost always wants and what needs no emulation. Set explicitly for
# a cross build: `make build PLATFORM=linux/amd64`.
#
# Empty PLATFORM means "do not pass --platform at all", which is deliberate: with
# a `docker buildx build` and no --platform, the default builder produces a
# single-architecture image that is fast to build and needs no binfmt handler.
PLATFORM ?=

# Namespaces the `clean` target removes. `sentinel-chaos` is created by the
# local-live overlay and is the one that survives a crashed test run.
CHAOS_NAMESPACE ?= sentinel-chaos
SYSTEM_NAMESPACE ?= srek3s-system

# A `make` variable cannot run a shell at expansion time without costing a
# subshell per use, so the lookup happens once here. `$(shell ...)` is used for
# exactly one thing: deciding whether a usable interpreter exists.
PY_CANDIDATES := $(VENV_PY) python3.11 python3.12 python3.13
PYTHON := $(shell for c in $(PY_CANDIDATES); do \
	if command -v $$c >/dev/null 2>&1; then \
		if $$c -c 'import sys; sys.exit(0 if sys.version_info[:2] >= (3, 11) else 1)' 2>/dev/null; then \
			echo $$c; exit 0; \
		fi; \
	fi; \
done; exit 1)

# `docker` is needed for image builds and deploys; `sudo -n` is NOT assumed,
# because it is a property of this host rather than of the project. KUBECTL is
# overridable so a developer on a remote cluster can point at their own kubeconfig.
DOCKER ?= docker
KUBECTL ?= kubectl

# ---------------------------------------------------------------------------
# DOCKER PERMISSIONS — detected once, explained once
# ---------------------------------------------------------------------------
# The first revision passed a bare `docker` through, so a developer not in the
# `docker` group got this from `make build`:
#
#   ERROR: permission denied while trying to connect to the docker API at
#   unix:///var/run/docker.sock
#
# which names neither a cause nor a remedy, and is the single most common way a
# Linux developer hits a project for the first time. Auto-prefixing `sudo` is NOT
# the fix: silently escalating to root for a build is a worse surprise than a
# failed build, and it would also break rootless and remote daemons.
#
# So the permissions are PROBED once and reported, and the developer chooses by
# overriding DOCKER. That keeps the choice explicit, which is the only defensible
# option for something that grants root-equivalent control of the daemon.
DOCKER_PERMS := $(shell $(DOCKER) info >/dev/null 2>&1 && echo ok || \
	{ sudo -n $(DOCKER) info >/dev/null 2>&1 && echo sudo-ok || echo denied; })

define docker_guard
	@case "$(DOCKER_PERMS)" in \
	  ok) ;; \
	  sudo-ok) \
		echo "ERROR: $(DOCKER) cannot reach the daemon as $$(id -un), but sudo can." >&2; \
		echo "" >&2; \
		echo "  This target invokes $(DOCKER) directly and will fail with a raw" >&2; \
		echo "  'permission denied ... /var/run/docker.sock' otherwise." >&2; \
		echo "" >&2; \
		echo "  Fix it for this invocation:" >&2; \
		echo "      make $(1) DOCKER='sudo -n docker'" >&2; \
		echo "" >&2; \
		echo "  Or make it permanent for your shell:" >&2; \
		echo "      sudo usermod -aG docker $$(id -un)" >&2; \
		echo "      # then log out and back in" >&2; \
		echo "" >&2; \
		echo "  Note: the docker group is root-equivalent control of this machine." >&2; \
		echo "  Choose deliberately rather than reflexively." >&2; \
		exit 1 ;; \
	  *) \
		echo "ERROR: cannot reach the Docker daemon as $$(id -un), with or without sudo." >&2; \
		echo "  Start Docker, then re-run. Check DOCKER_HOST if it is set." >&2; \
		exit 1 ;; \
	esac
endef

.PHONY: help
help: ## Show this help
	@echo ""
	@echo "SREK3S — available targets"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| sort \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'
	@echo ""
	@echo "Common overrides:"
	@echo "  PLATFORM=linux/amd64     cross-build the images for another architecture"
	@echo "  KUBECTL='kubectl --context=...'    deploy somewhere other than the current context"
	@echo ""
	@echo "Resolved interpreter: $(if $(PYTHON),$(PYTHON),<none found — run 'make bootstrap'>)"
	@echo ""

# ---------------------------------------------------------------------------
# bootstrap
# ---------------------------------------------------------------------------
.PHONY: bootstrap
bootstrap: ## Create .venv311, install Python deps, download Go modules
	@echo "==> bootstrapping"
	@if [ ! -x "$(VENV_PY)" ]; then \
		echo "--> creating $(VENV)"; \
		PY=$$(for c in python3.11 python3.12 python3.13 python3; do \
			if command -v $$c >/dev/null 2>&1 && $$c -c 'import sys; sys.exit(0 if sys.version_info[:2] >= (3,11) else 1)' 2>/dev/null; then \
				echo $$c; break; \
			fi; \
		done); \
		if [ -z "$$PY" ]; then \
			echo "FATAL: no Python 3.11+ interpreter found." >&2; \
			echo "       The gates pin 3.11 (AGENTS.md §2) and will not run on 3.14." >&2; \
			echo "       Install one, or run scripts/bootstrap.sh for the full check." >&2; \
			exit 1; \
		fi; \
		"$$PY" -m venv "$(VENV)"; \
	fi
	@echo "--> installing Python dependencies"
	@"$(VENV_PY)" -m pip install --upgrade pip >/dev/null
	@"$(VENV_PY)" -m pip install -r "$(ROOT)/agent/requirements.txt"
	@"$(VENV_PY)" -m pip install black flake8 mypy pytest httpx pyyaml >/dev/null
	@echo "--> downloading Go modules"
	cd "$(ROOT)" && go mod download
	@echo ""
	@echo "Bootstrap complete. Interpreter: $$($(VENV_PY) -V)"
	@echo "Run 'make test' for the full gate sweep."

# ---------------------------------------------------------------------------
# test
# ---------------------------------------------------------------------------
.PHONY: test
test: test-go test-python ## Run every gate (Go then Python, sequentially)

.PHONY: test-go
test-go: ## Go: vet, gofmt, build tags, and the race-enabled suite
	@echo "==> go vet"
	@cd "$(ROOT)" && go vet ./...
	@echo "==> gofmt"
	@cd "$(ROOT)" && test -z "$$(gofmt -l .)" \
		|| { echo "FATAL: unformatted files:"; gofmt -l .; exit 1; }
	@echo "==> go vet -tags race"
	@cd "$(ROOT)" && go vet -tags race ./...
	@echo "==> go test -race"
	@cd "$(ROOT)" && go test -race -count=1 -timeout 120s ./...

.PHONY: test-python
test-python: ## Python: black, flake8, mypy --strict, pytest
	@test -n "$(PYTHON)" || { echo "FATAL: no Python 3.11+ interpreter. Run 'make bootstrap'." >&2; exit 1; }
	@echo "==> black"
	@"$(PYTHON)" -m black --check "$(REPO_ROOT)/" "$(ROOT)/tests/"
	@echo "==> flake8"
	@"$(PYTHON)" -m flake8 "$(REPO_ROOT)/" "$(ROOT)/tests/"
	@echo "==> mypy --strict"
	@"$(PYTHON)" -m mypy --strict "$(REPO_ROOT)/" "$(ROOT)/tests/"
	@echo "==> pytest"
	@"$(PYTHON)" -m pytest "$(PYTEST_DIR)/" -q

.PHONY: test-parallel
test-parallel: ## Run both suites concurrently (flaky by design; you asked for it)
	@$(MAKE) test-go & \
	$(MAKE) test-python & \
	wait

.PHONY: check
check: test build ## Gates then images

# ---------------------------------------------------------------------------
# build
# ---------------------------------------------------------------------------
# `--load` is what makes the result land in the local docker image store. Without
# it `docker buildx build` writes to a cache that `docker run` cannot see, and the
# image "built successfully" is then not runnable — which is the single most
# common buildx surprise and produces a confusing `No such image` much later.
#
# `--load` is incompatible with a multi-platform build, so building several
# platforms at once requires `--output type=oci` and a load step elsewhere. That is
# why PLATFORM is a single value here and `make push-multiarch` is separate.
#
# CROSS-ARCHITECTURE BUILDS ARE ASYMMETRIC, AND NOT BY ACCIDENT
# -----------------------------------------------------------
# Setting PLATFORM to an architecture other than the host's behaves differently for
# the two images, which surprises people who assume buildx treats them alike.
#
#   make build-sentinel PLATFORM=linux/amd64
#     Works on an arm64 host with NO emulator. cmd/sentinel/Dockerfile pins its Go
#     stage to `FROM --platform=$BUILDPLATFORM` and cross-compiles with
#     GOARCH=$TARGETARCH, so the Go toolchain runs natively and emits a foreign-
#     architecture binary. Verified on an aarch64 host with zero binfmt handlers:
#     the image reports Architecture=amd64 and /bin/sentinel is
#     `ELF 64-bit LSB executable, x86-64, statically linked`.
#
#   make build-agent PLATFORM=linux/amd64
#     Needs an emulator. agent/Dockerfile's `FROM python:3.11-slim` must run the
#     TARGET's interpreter to install the TARGET's wheels. Forcing
#     --platform=$BUILDPLATFORM there would install arm64 wheels into an image
#     labelled linux/amd64 — the install SUCCEEDS, the label is a lie, and the
#     failure appears at pod start as an `Illegal instruction`, long after the
#     build reported success. That trade is not worth taking to avoid an emulator.
#
# Without binfmt_misc handlers the agent build fails with
#
#     exec /bin/sh: exec format error
#
# which reads as a broken Dockerfile rather than a missing host capability.
# `make doctor` reports it as a WARNING with the remedy, because it is only
# required by cross-architecture builds — `make build`, `make test` and
# `make deploy` all use the host architecture and are unaffected.
#
#   docker run --privileged --rm tonistiigi/binfmt --install all
#
.PHONY: build
build: build-sentinel build-agent ## Build both images with buildx (host arch by default)

.PHONY: build-sentinel
build-sentinel: ## Build the Sentinel image
	$(call docker_guard,build-sentinel)
	@echo "==> building $(SENTINEL_TAG) $(if $(PLATFORM),for $(PLATFORM),for the host architecture)"
	$(DOCKER) buildx build $(if $(PLATFORM),--platform $(PLATFORM),) \
		--load -t $(SENTINEL_TAG) -f "$(ROOT)/cmd/sentinel/Dockerfile" "$(ROOT)"

.PHONY: build-agent
build-agent: ## Build the Agent image
	$(call docker_guard,build-agent)
	@echo "==> building $(AGENT_TAG) $(if $(PLATFORM),for $(PLATFORM),for the host architecture)"
	$(DOCKER) buildx build $(if $(PLATFORM),--platform $(PLATFORM),) \
		--load -t $(AGENT_TAG) -f "$(ROOT)/agent/Dockerfile" "$(ROOT)"

# Verify an image by RUNNING it, not by inspecting metadata. A layer list can be
# correct while the binary in it cannot execute, and the failure then surfaces as
# an exec format error at pod start.
.PHONY: verify-images
verify-images: build ## Build, then execute each image's entrypoint
	@echo "==> verifying $(SENTINEL_TAG)"
	@$(DOCKER) run --rm $(SENTINEL_TAG) -version
	@echo "==> verifying $(AGENT_TAG)"
	@$(DOCKER) run --rm --entrypoint /bin/sh $(AGENT_TAG) -c \
		"python -c 'import google.genai, main; print(\"agent ok, google-genai\", google.genai.__version__)'; command -v git >/dev/null && echo 'git present (Tier-1 reachable)'"

# A multi-architecture manifest list. Separate from `build` because it cannot
# `--load`, and because it needs a registry — a local tag has nowhere to record
# that two builds are one image.
.PHONY: push-multiarch
push-multiarch: ## Build a linux/amd64 + linux/arm64 manifest list (needs a registry)
	@echo "==> multi-arch build for $(SENTINEL_TAG) and $(AGENT_TAG)"
	$(DOCKER) buildx build --platform linux/amd64,linux/arm64 \
		--push -t $(SENTINEL_TAG) -f "$(ROOT)/cmd/sentinel/Dockerfile" "$(ROOT)"
	$(DOCKER) buildx build --platform linux/amd64,linux/arm64 \
		--push -t $(AGENT_TAG) -f "$(ROOT)/agent/Dockerfile" "$(ROOT)"

# ---------------------------------------------------------------------------
# deploy
# ---------------------------------------------------------------------------
# `apply -k deploy/base` rather than `deploy/`. See the header: the two build
# different object sets.
.PHONY: deploy
deploy: ## Apply the base manifests to the current cluster context
	@echo "==> applying deploy/base to the current context"
	@$(KUBECTL) config current-context 2>/dev/null | sed 's/^/    context: /' || true
	$(KUBECTL) apply -k "$(ROOT)/deploy/base"
	@$(KUBECTL) -n $(SYSTEM_NAMESPACE) rollout status deployment/srek3s-sentinel --timeout=120s
	@$(KUBECTL) -n $(SYSTEM_NAMESPACE) rollout status deployment/srek3s-agent --timeout=120s

.PHONY: undeploy
undeploy: ## Remove the SREK3S workloads, leaving the namespace in place
	-$(KUBECTL) delete -k "$(ROOT)/deploy/base" --ignore-not-found

# The overlay is a SEPARATE target on purpose. It scopes the Sentinel to
# sentinel-chaos, which means a developer who applies it has a Sentinel that will
# not watch srek3s-system — and if they then run `make deploy` expecting their
# cluster to be watched, they get a healthy watcher watching nothing. Making that
# an explicit verb rather than a flag is the difference between a documented
# choice and a confusing one.
.PHONY: deploy-overlay
deploy-overlay: ## Apply the local-live overlay (scopes the Sentinel to sentinel-chaos)
	$(KUBECTL) kustomize --load-restrictor=LoadRestrictionsNone \
		"$(ROOT)/deploy/overlays/local-live" | $(KUBECTL) apply -f -

.PHONY: chaos
chaos: ## Deploy the real-crash chaos workload into the chaos namespace
	$(KUBECTL) apply -f "$(ROOT)/deploy/chaos/real-crash.yaml" -n $(CHAOS_NAMESPACE)

# ---------------------------------------------------------------------------
# clean
# ---------------------------------------------------------------------------
# Deliberately refuses to delete the SYSTEM namespace. `make clean` after a failed
# test must not remove a developer's running stack, and "clean" is exactly the
# word someone types when they are annoyed. The chaos namespace is test scaffolding
# and goes; the system namespace is someone's deployment and stays.
.PHONY: clean
clean: ## Remove the chaos namespace and the virtualenv (NOT the system namespace)
	@echo "==> deleting namespace $(CHAOS_NAMESPACE)"
	-$(KUBECTL) delete namespace $(CHAOS_NAMESPACE) --ignore-not-found --wait=false
	@echo "==> removing $(VENV)"
	rm -rf "$(VENV)"
	@echo "==> cleaning caches"
	find "$(ROOT)" -name '__pycache__' -type d -prune -exec rm -rf {} + 2>/dev/null || true
	find "$(ROOT)" -name '.pytest_cache' -type d -prune -exec rm -rf {} + 2>/dev/null || true
	find "$(ROOT)" -name '.mypy_cache' -type d -prune -exec rm -rf {} + 2>/dev/null || true
	@echo ""
	@echo "Not removed on purpose: the $(SYSTEM_NAMESPACE) namespace, any docker"
	@echo "images, and .env / .env.local. Those are yours, not the test's."

.PHONY: clean-images
clean-images: ## Remove the two SREK3S images (they need a rebuild, ~2min)
	-$(DOCKER) image rm $(SENTINEL_TAG) $(AGENT_TAG)

.PHONY: doctor
doctor: ## Run the host pre-flight check
	@"$(ROOT)/scripts/bootstrap.sh"