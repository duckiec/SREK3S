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

# ---------------------------------------------------------------------------
# THROWAWAY CLUSTER
# ---------------------------------------------------------------------------
# A disposable single-node k3s, used for the live E2E leg. It exists as a
# `docker run` container rather than an install on the host because that is the
# only way to get a second control plane on a machine that already runs one
# without the two fighting over the same data directory, cgroups and containerd
# socket.
#
# It runs on its OWN docker network with its own subnet, and its own data
# directory inside the container, so it shares nothing with the host cluster
# except memory and CPU. Do not put it on the host network: kube-proxy in a
# host-networked container writes to the host's netfilter tables.
THROWAWAY_NAME       ?= k3s-throwaway
THROWAWAY_IMAGE      ?= rancher/k3s:v1.36.4-k3s1
THROWAWAY_NETWORK    ?= throwaway
THROWAWAY_SUBNET     ?= 192.168.100.0/24
THROWAWAY_IP         ?= 192.168.100.2
THROWAWAY_APISERVER  ?= 6445
THROWAWAY_KUBECONFIG ?= /tmp/k3s-throwaway.yaml
THROWAWAY_RELEASE    ?= srek3s

# The throwaway sentinel watches the chaos namespace so the chaos fixture's
# hardcoded `namespace: sentinel-chaos` lines up with a grant it actually holds.
# The chaos Role/RoleBinding for that namespace come from
# deploy/overlays/local-live/chaos-rbac.yaml, applied below. This is set at
# install time rather than baked into the chart so the production overlay does
# not inherit a fixture scope.
THROWAWAY_WATCH_NS   ?= $(CHAOS_NAMESPACE)

# The container's containerd socket. Images are built on the host and piped in,
# because there is no registry between them.
THROWAWAY_CTR        := /run/k3s/containerd/containerd.sock
THROWAWAY_CTR_ADDR   := --address $(THROWAWAY_CTR) --namespace k8s.io

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

# kubectl pinned to the throwaway, for use inside recipe bodies where the
# KUBECONFIG prefix would otherwise have to be repeated on every line.
#
# THIS MUST BE DEFINED AFTER `KUBECTL`, AND THAT IS NOT COSMETIC.
#
# `:=` expands immediately at the point of definition. When this line sat above
# `KUBECTL ?= kubectl`, `$(KUBECTL)` was still undefined here, so the variable
# silently became the empty string and every use site expanded to
#
#     KUBECONFIG=/tmp/k3s-throwaway.yaml  -n srek3s-system logs ...
#
# with no `kubectl` in it at all. bash then failed to find `-n`, `2>/dev/null
# || true` swallowed the error, the assertion read an empty string, and
# throwaway-detonate reported `watcher_emitted=0` for a Sentinel that had in
# fact emitted three.
#
# That failure had been there from the first draft. It agreed with the truth for
# a while only because the Sentinel genuinely WAS emitting zero — a real bug
# (the NetworkPolicy denied post-DNAT API access) was producing the same number
# as a broken assertion. Fixing the Sentinel left the assertion still reporting
# zero, which is how the two were told apart.
#
# A verification that reports the right answer for the wrong reason is worse
# than no verification: it retires the alarm that would have caught the next
# fault. `agent/tests/test_makefile.py` now asserts this ordering so a future
# reordering cannot reintroduce it silently.
THROWAWAY_KUBECONFIG_KUBECTL := KUBECONFIG=$(THROWAWAY_KUBECONFIG) $(KUBECTL)

# Where `go install` puts binaries (GOBIN, else $GOPATH/bin). Used by
# check-supply-chain to find govulncheck without hardcoding a path.
GOBIN ?= $(shell go env GOPATH 2>/dev/null)/bin

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
	@echo "  OVERLAY=deploy/overlays/quickstart-live   chaos patches against the published images"
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

# ---------------------------------------------------------------------------
# demo
# ---------------------------------------------------------------------------
# The first thing a newcomer runs, so it has to be honest before it is impressive.
# `make demo` builds images, installs the chart and detonates a real OOMKill on
# a disposable cluster. It never touches a cluster you care about, and it says so
# before doing anything, because a tool that mutates a cluster on first contact
# does not get a second run.

.PHONY: demo
demo: ## 60-second proof on a disposable cluster: real crash, scrubbed incident, Tier-1 patch
	@echo "==============================================================="
	@echo " SREK3S demo"
	@echo "==============================================================="
	@echo ""
	@echo " WHAT THIS DOES, IN ORDER"
	@echo "   1. throwaway-up       a throwaway k3s cluster in Docker, on its own"
	@echo "                         bridge network, with NO relation to any"
	@echo "                         cluster you are using"
	@echo "   2. throwaway-wait    blocks until the node is Ready AND cluster DNS"
	@echo "                         resolves (the agent clones once at startup)"
	@echo "   3. throwaway-detonate builds both images, installs the chart into the"
	@echo "                         throwaway, applies deploy/chaos/oom-leak.yaml,"
	@echo "                         and waits for the Sentinel to observe the real"
	@echo "                         OOMKill, scrub it, and have the agent produce a"
	@echo "                         verified Tier-1 patch"
	@echo ""
	@echo " WHAT IT WILL NOT TOUCH"
	@echo "   Your current kubectl context is never switched. Every command here"
	@echo "   is pinned with KUBECONFIG=$(THROWAWAY_KUBECONFIG), so if you have a"
	@echo "   production kubeconfig loaded it stays loaded and stays untouched."
	@echo "   Nothing is applied to any cluster except the throwaway."
	@echo ""
	@echo " WHAT IT LEAVES BEHIND"
	@echo "   The throwaway container, so you can read the logs. Remove it with:"
	@echo "       make throwaway-down"
	@echo ""
	@echo "   It costs a multi-arch-free image build on first run."
	@echo "==============================================================="
	@echo ""
	@$(MAKE) throwaway-up
	@$(MAKE) throwaway-wait
	@$(MAKE) throwaway-detonate
	@echo ""
	@echo "==============================================================="
	@echo " demo complete"
	@echo "==============================================================="
	@echo " Clean up the throwaway with:  make throwaway-down"

# ---------------------------------------------------------------------------
# check
# ---------------------------------------------------------------------------
# `check` used to be `test build` and nothing else. Three properties that had
# already produced defects were therefore only ever verified by remembering to
# run them, and each one cost a real bug:
#
#   * A stale `govulncheck.txt` sat in the repository for a release. Nobody
#     noticed because nothing ran govulncheck locally.
#   * The chart rendered a Namespace, so every `helm install` failed. `make test`
#     was green throughout, because it never rendered the chart.
#   * The chart and `deploy/base` silently diverged. Same cause.
#
# So they are dependencies now, not folklore.
.PHONY: check
check: test build check-supply-chain ## Gates, then images, then the checks that were being forgotten

# The dependency checks. Split out so CI and a developer can run exactly this
# subset without rebuilding images.
.PHONY: check-supply-chain
check-supply-chain: ## helm lint, chart/base parity, govulncheck, workflow audit

	@echo "==> helm lint --strict"
	@helm lint --strict "$(ROOT)/deploy/helm/srek3s"

	@echo "==> chart / deploy-base parity"
	@# Deliberately NOT a naive byte diff of the two renders. They differ by one
	@# object on purpose: `deploy/base` renders a Namespace because kustomize has
	@# no `--create-namespace`, while the chart must not render one or every
	@# `helm install` fails (with or without that flag). The invariant is therefore
	@# "the chart renders no Namespace, and every other object is byte-identical",
	@# and test_helm_chart.py::test_render_matches_kustomize_base already encodes
	@# it. Re-implementing it here as a shell diff would reintroduce the false
	@# failure that motivated the test.
	@test -n "$(PYTHON)" || { echo "FATAL: no Python 3.11+ interpreter. Run 'make bootstrap'." >&2; exit 1; }
	@"$(PYTHON)" -m pytest "$(PYTEST_DIR)/test_helm_chart.py::test_render_matches_kustomize_base" -q

	@echo "==> govulncheck"
	@# READ THIS BEFORE TRUSTING A LOCAL CLEAN RESULT.
	@#
	@# govulncheck matches STANDARD LIBRARY advisories by comparing the running
	@# toolchain's version against each advisory's affected range. A toolchain that
	@# is not a plain upstream release - a distro or vendor build, anything carrying
	@# a suffix like `go1.26.8-X:nodwarf5` - matches nothing, and every stdlib
	@# advisory is silently skipped. The scan still runs, still reads the database,
	@# and still reports "No vulnerabilities found".
	@#
	@# Measured on this repository, same tree, same scanner, same database, the only
	@# variable being which Go executed it:
	@#
	@#   genuine go1.26.8     -> exit 3, 9 vulnerabilities
	@#   go1.26.8-X:nodwarf5  -> exit 0, "No vulnerabilities found"
	@#   genuine go1.26.9     -> exit 0, "No vulnerabilities found"
	@#
	@# So a local "clean" is only evidence about the standard library if you know
	@# which Go produced it. Check with `go version` first:
	@#
	@#   GOTOOLCHAIN=go1.26.9 $(GOBIN)/govulncheck ./...
	@#
	@# CI is the authority here, and it pins GO_VERSION to an exact patch precisely so
	@# this ambiguity cannot decide a gate. Locally, treat a clean stdlib scan from a
	@# suffixed toolchain as unverified and say so rather than reporting it.
	@echo "    toolchain: $$(go version 2>/dev/null || echo unknown)"
	@if go version 2>/dev/null | grep -qE '^go version go[0-9]+\.[0-9]+\.[0-9]+ '; then \
		echo "    (upstream release build - standard library IS in scope)"; \
	else \
		echo "    WARNING: not a plain upstream release. Standard-library advisories" >&2; \
		echo "    may be silently out of scope; see the comment above. Re-run with" >&2; \
		echo "    GOTOOLCHAIN=go1.26.9 to cover them, or trust CI." >&2; \
	fi
	@# Assignment and use must stay in ONE shell. A `@`-prefixed recipe line is its
	@# own `bash -c`, so splitting them left `$$GOVULNCHECK` unbound on the line that
	@# needed it - the same trap that made the first draft of the detonation
	@# assertions pass vacuously.
	@GOVULNCHECK="$$(command -v govulncheck || echo '$(GOBIN)/govulncheck')"; \
	if [ ! -x "$$GOVULNCHECK" ]; then \
		echo "FATAL: govulncheck not found." >&2; \
		echo "       Install it with: go install golang.org/x/vuln/cmd/govulncheck@latest" >&2; \
		echo "       (or point GOVULNCHECK= at an existing binary)" >&2; \
		exit 1; \
	fi; \
	cd "$(ROOT)" && "$$GOVULNCHECK" ./...

	@echo "==> workflow definition audit"
	@"$(PYTHON)" "$(ROOT)/scripts/audit_workflow.py" --strict

# ---------------------------------------------------------------------------
# throwaway (disposable cluster for the live E2E leg)
# ---------------------------------------------------------------------------
# These three targets exist because the E2E leg was previously ~15 hand-typed
# commands with a memorised sequence of docker flags, a kubeconfig path that
# only existed for as long as /tmp did, and a binfmt handler that had to be
# registered by hand on an arm64 host. A verification you have to remember is a
# verification that gets skipped.

.PHONY: throwaway-up
throwaway-up: ## Start the disposable k3s cluster and write its kubeconfig
	@echo "==> throwaway: network $(THROWAWAY_NETWORK) ($(THROWAWAY_SUBNET))"
	@$(DOCKER) network inspect "$(THROWAWAY_NETWORK)" >/dev/null 2>&1 \
		|| $(DOCKER) network create --subnet "$(THROWAWAY_SUBNET)" "$(THROWAWAY_NETWORK)" >/dev/null
	@if $(DOCKER) ps -a --format '{{.Names}}' | grep -qx "$(THROWAWAY_NAME)"; then \
		echo "==> removing the previous $(THROWAWAY_NAME)"; \
		$(DOCKER) rm -f "$(THROWAWAY_NAME)" >/dev/null; \
	fi
	@# binfmt handlers are HOST-GLOBAL and are the one thing a throwaway cannot
	@# avoid touching. They are needed only for cross-architecture builds (see
	@# the CROSS-ARCHITECTURE BUILDS note above); on an amd64 host this is a no-op.
	@if [ "$$(uname -m)" = "aarch64" ] && [ ! -e /proc/sys/fs/binfmt_misc/qemu-x86_64 ]; then \
		echo "==> registering binfmt handler for linux/amd64 (host is aarch64)"; \
		$(DOCKER) run --privileged --rm tonistiigi/binfmt --install amd64 >/dev/null; \
	fi
	@echo "==> starting $(THROWAWAY_NAME)"
	@$(DOCKER) run -d --privileged --name "$(THROWAWAY_NAME)" \
		--network "$(THROWAWAY_NETWORK)" --hostname "$(THROWAWAY_NAME)" \
		-p $(THROWAWAY_APISERVER):6443 \
		"$(THROWAWAY_IMAGE)" server \
		--disable traefik --disable servicelb --disable metrics-server >/dev/null
	@echo "==> waiting for the API server"
	@# The bundled `kubectl`, NOT `k3s kubectl`. Inside the rancher/k3s image the
	@# `k3s` multicall dispatches to the kubectl sub-binary in a way that answers
	@# `unknown command "kubectl" for "kubectl"` and still exits 0, so a probe
	@# built on it waits out the full timeout against a perfectly healthy cluster.
	@# Requires a READY node, not merely a responsive API server. The apiserver
	@# answers well before the node object is registered, so an API-only probe
	@# reports ready and then prints "No resources found" two lines later.
	@for i in $$(seq 1 60); do \
		if $(DOCKER) exec "$(THROWAWAY_NAME)" kubectl get nodes --no-headers 2>/dev/null | grep -q ' Ready '; then \
			echo "==> ready after $$((i * 2))s"; break; \
		fi; \
		if [ $$i -eq 60 ]; then \
			echo "FATAL: no Ready node after 120s" >&2; \
			$(DOCKER) logs --tail 20 "$(THROWAWAY_NAME)" >&2 || true; \
			exit 1; \
		fi; \
		sleep 2; \
	done
	@echo "==> writing $(THROWAWAY_KUBECONFIG)"
	@$(DOCKER) cp "$(THROWAWAY_NAME):/etc/rancher/k3s/k3s.yaml" "$(THROWAWAY_KUBECONFIG)"
	@sed -i.bak "s#https://127.0.0.1:6443#https://$(THROWAWAY_IP):6443#" "$(THROWAWAY_KUBECONFIG)"
	@rm -f "$(THROWAWAY_KUBECONFIG).bak"
	@echo "    use with:  export KUBECONFIG=$(THROWAWAY_KUBECONFIG)"
	@KUBECONFIG=$(THROWAWAY_KUBECONFIG) $(KUBECTL) get nodes

.PHONY: throwaway-wait
throwaway-wait: ## Block until the throwaway is genuinely ready: node Ready AND DNS resolving
	@# Readiness is two conditions, and the second is the one that is easy to miss.
	@#
	@# `throwaway-up` waits for a Ready NODE. That is necessary and it is not
	@# sufficient: the Agent clones its GitOps repo once, at startup, before it
	@# serves its first request. A cluster that has a Ready node but no resolver
	@# yet makes that clone fail, and the agent then degrades PERMANENTLY to the
	@# manifest-root fallback with no retry:
	@#
	@#   fatal: unable to access 'https://github.com/...': Could not resolve host
	@#   ...; falling back to SREK3S_MANIFEST_ROOT
	@#
	@# Every subsequent incident then escalates to Tier-2 for a reason that has
	@# nothing to do with the incident, which is the worst way for a demo to fail.
	@# The symptom looks like a broken product; the cause is a cluster that was
	@# Ready for four seconds.
	@#
	@# The probe is kube-dns ENDPOINTS rather than a pod running a resolver,
	@# deliberately: this runs BEFORE the images are imported, so there is no
	@# image in the throwaway yet to run a probe in. Endpoints being non-empty is
	@# the earliest signal that a resolver will answer.
	@echo "==> waiting for a Ready node"
	@for i in $$(seq 1 60); do \
		if KUBECONFIG=$(THROWAWAY_KUBECONFIG) $(KUBECTL) get nodes --no-headers 2>/dev/null | grep -q ' Ready '; then \
			echo "==> node Ready after $$((i * 2))s"; break; \
		fi; \
		if [ $$i -eq 60 ]; then \
			echo "FATAL: no Ready node after 120s." >&2; \
			echo "       Is $(THROWAWAY_NAME) running? 'make throwaway-up'." >&2; \
			exit 1; \
		fi; \
		sleep 2; \
	done
	@echo "==> waiting for cluster DNS to answer"
	@for i in $$(seq 1 60); do \
		EPS="$$(KUBECONFIG=$(THROWAWAY_KUBECONFIG) $(KUBECTL) -n kube-system get endpoints kube-dns \
			-o jsonpath='{.subsets[*].addresses[*].ip}' 2>/dev/null || true)"; \
		if printf '%s' "$$EPS" | grep -q '[0-9]'; then \
			echo "==> kube-dns ready after $$((i * 2))s ($$EPS)"; break; \
		fi; \
		if [ $$i -eq 60 ]; then \
			echo "FATAL: kube-dns published no endpoints after 120s." >&2; \
			echo "       The Agent clones GitOps at startup and does not retry, so" >&2; \
			echo "       installing now would strand it in Tier-2 for the whole run." >&2; \
			$(DOCKER) logs --tail 20 "$(THROWAWAY_NAME)" >&2 || true; \
			exit 1; \
		fi; \
		sleep 2; \
	done
	@echo "==> throwaway is ready"

.PHONY: throwaway-down
throwaway-down: ## Stop and remove the disposable cluster and its kubeconfig
	@if $(DOCKER) ps -a --format '{{.Names}}' | grep -qx "$(THROWAWAY_NAME)"; then \
		echo "==> stopping $(THROWAWAY_NAME)"; \
		$(DOCKER) rm -f "$(THROWAWAY_NAME)" >/dev/null && echo "    removed"; \
	else \
		echo "==> $(THROWAWAY_NAME) is not present"; \
	fi
	@rm -f "$(THROWAWAY_KUBECONFIG)" && echo "==> removed $(THROWAWAY_KUBECONFIG)"
	@$(DOCKER) network rm "$(THROWAWAY_NETWORK)" >/dev/null 2>&1 \
		&& echo "==> removed network $(THROWAWAY_NETWORK)" || true

.PHONY: throwaway-detonate
throwaway-detonate: throwaway-up ## Full live E2E: build, import, install, detonate, show logs
	@echo "==> context: $(THROWAWAY_KUBECONFIG)"
	@KUBECONFIG=$(THROWAWAY_KUBECONFIG) $(KUBECTL) get nodes >/dev/null \
		|| { echo "FATAL: throwaway is not reachable; run 'make throwaway-up' first" >&2; exit 1; }
	@echo "==> building images"
	@$(MAKE) build-sentinel build-agent
	@echo "==> importing images into $(THROWAWAY_NAME) containerd"
	@$(DOCKER) save "$(SENTINEL_TAG)" "$(AGENT_TAG)" busybox:1.36.1 \
		| $(DOCKER) exec -i "$(THROWAWAY_NAME)" ctr $(THROWAWAY_CTR_ADDR) images import - >/dev/null
	@echo "==> cleaning any previous release"
	@KUBECONFIG=$(THROWAWAY_KUBECONFIG) helm uninstall "$(THROWAWAY_RELEASE)" -n "$(SYSTEM_NAMESPACE)" >/dev/null 2>&1 || true
	@KUBECONFIG=$(THROWAWAY_KUBECONFIG) $(KUBECTL) delete ns "$(SYSTEM_NAMESPACE)" --wait=true >/dev/null 2>&1 || true
	@KUBECONFIG=$(THROWAWAY_KUBECONFIG) $(KUBECTL) delete ns "$(CHAOS_NAMESPACE)" --wait=true >/dev/null 2>&1 || true
	@echo "==> creating the chaos namespace and granting the sentinel read verbs there"
	@# BEFORE the chart, deliberately. A RoleBinding may reference a ServiceAccount
	@# that does not exist yet - the apiserver accepts it and resolves the subject
	@# when the account appears - so this ordering is legal and removes the race
	@# that the other way round introduces. Installing first and granting
	@# afterwards leaves the Sentinel's informer retrying a forbidden LIST:
	@#
	@#   failed to list *v1.Pod: pods is forbidden: User
	@#   "system:serviceaccount:srek3s-system:srek3s-sentinel" cannot list
	@#   resource "pods" in API group "" in the namespace "sentinel-chaos"
	@#
	@# which it recovers from, so the detonation still passes and the ordering
	@# defect is invisible in the result. Same trap deploy/kustomization.yaml
	@# documents for its own namespace: resource order is not alphabetical.
	@KUBECONFIG=$(THROWAWAY_KUBECONFIG) $(KUBECTL) apply -f "$(ROOT)/deploy/overlays/local-live/chaos-namespace.yaml" >/dev/null
	@KUBECONFIG=$(THROWAWAY_KUBECONFIG) $(KUBECTL) apply -f "$(ROOT)/deploy/overlays/local-live/chaos-rbac.yaml" >/dev/null
	@# HERE and not only in `make demo`: the Agent's one-shot GitOps clone runs at
	@# pod start, so the resolver must exist before the chart lands. Gating this in
	@# the demo alone would leave `make throwaway-detonate` - the target CI and
	@# contributors actually use - racy.
	@$(MAKE) throwaway-wait
	@echo "==> installing the chart (watch scope: $(THROWAWAY_WATCH_NS))"
	@KUBECONFIG=$(THROWAWAY_KUBECONFIG) helm install "$(THROWAWAY_RELEASE)" \
		"$(ROOT)/deploy/helm/srek3s" -n "$(SYSTEM_NAMESPACE)" --create-namespace \
		--set sentinel.watchNamespace="$(THROWAWAY_WATCH_NS)" \
		--set agent.gitops.repoUrl=https://github.com/duckiec/SREK3S.git \
		--set agent.targetManifest=deploy/chaos/oom-leak.yaml \
		--wait --timeout 300s
	@KUBECONFIG=$(THROWAWAY_KUBECONFIG) $(KUBECTL) -n "$(SYSTEM_NAMESPACE)" rollout status deployment/srek3s-sentinel --timeout=180s
	@KUBECONFIG=$(THROWAWAY_KUBECONFIG) $(KUBECTL) -n "$(SYSTEM_NAMESPACE)" rollout status deployment/srek3s-agent --timeout=180s
	@echo "==> detonating $(ROOT)/deploy/chaos/oom-leak.yaml"
	@KUBECONFIG=$(THROWAWAY_KUBECONFIG) $(KUBECTL) apply -f "$(ROOT)/deploy/chaos/oom-leak.yaml" -n "$(CHAOS_NAMESPACE)"
	@echo "==> waiting for the failure to be observed and triaged"
	@sleep 60
	@echo
	@echo "===================== sentinel ====================="
	@KUBECONFIG=$(THROWAWAY_KUBECONFIG) $(KUBECTL) -n "$(SYSTEM_NAMESPACE)" logs deployment/srek3s-sentinel --tail=15
	@echo
	@echo "===================== ASSERTIONS ===================="
	@# A detonation target that prints logs and exits 0 whether or not anything was
	@# detected is worse than no target: it manufactures a green result from a
	@# failed run. These assertions are what make this a verification.
	@#
	@# Each one is a SELF-CONTAINED shell. A `@`-prefixed recipe line is its own
	@# `bash -c`, so a variable assigned on one line does not survive to the next -
	@# the first draft of this block spread one script over several lines and the
	@# assertion silently passed with an empty variable. The extraction pattern
	@# also avoids literal double quotes, which do not survive `bash -c` inside a
	@# make recipe cleanly; `[^0-9]*` stands in for the JSON colon.
	@S="$$($(THROWAWAY_KUBECONFIG_KUBECTL) -n $(SYSTEM_NAMESPACE) logs deployment/srek3s-sentinel --tail=300 2>/dev/null || true)"; \
	E="$$(printf '%s' "$$S" | grep -oE 'watcher_emitted[^0-9]*[0-9]+' | tail -1 | grep -oE '[0-9]+$$' || true)"; \
	if [ "$${E:-0}" -lt 1 ]; then \
		echo "FATAL: the Sentinel emitted no incidents (watcher_emitted=$${E:-0})." >&2; \
		printf '%s' "$$S" | grep -q 'connection refused' \
			&& { echo "       The informer cannot reach the API server ClusterIP. The Sentinel" >&2; \
			     echo "       is healthy and authorised; the cluster dataplane is not. Check" >&2; \
			     echo "       kube-proxy ClusterIP DNAT from a pod in this cluster." >&2; }; \
		printf '%s' "$$S" | grep -q 'is forbidden' \
			&& echo "       The Sentinel lacks read verbs in $(THROWAWAY_WATCH_NS)." >&2; \
		exit 1; \
	fi; \
	echo "  [ok] sentinel emitted $$E incident(s)"
	@A="$$($(THROWAWAY_KUBECONFIG_KUBECTL) -n $(SYSTEM_NAMESPACE) logs deployment/srek3s-agent --tail=300 2>/dev/null || true)"; \
	if ! printf '%s' "$$A" | grep -q 'triaged incident_id'; then \
		echo "FATAL: the Agent never reported a triage verdict." >&2; \
		printf '%s\n' "$$A" | tail -20 >&2; \
		exit 1; \
	fi; \
	echo "  [ok] agent triaged ($$(printf '%s' "$$A" | grep -c 'triaged incident_id' || true) verdict(s))"
	@A="$$($(THROWAWAY_KUBECONFIG_KUBECTL) -n $(SYSTEM_NAMESPACE) logs deployment/srek3s-agent --tail=300 2>/dev/null || true)"; \
	if printf '%s' "$$A" | grep -q 'GitOps clone.*failed'; then \
		echo "FATAL: the GitOps clone failed; Tier-1 is unreachable." >&2; \
		printf '%s\n' "$$A" | grep 'GitOps clone' >&2; \
		exit 1; \
	fi; \
	echo "  [ok] GitOps checkout succeeded ($$(printf '%s' "$$A" | grep -c 'tier=TIER_1_TOIL' || true) Tier-1 verdict(s))"
	@echo
	@echo "===================== agent ========================"
	@KUBECONFIG=$(THROWAWAY_KUBECONFIG) $(KUBECTL) -n "$(SYSTEM_NAMESPACE)" logs deployment/srek3s-agent --tail=25
	@echo
	@echo "===================== agent ========================"
	@KUBECONFIG=$(THROWAWAY_KUBECONFIG) $(KUBECTL) -n "$(SYSTEM_NAMESPACE)" logs deployment/srek3s-agent --tail=25
	@echo
	@echo "==> scratch cluster: 'make throwaway-down' when finished"

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
# deploy/base is a BASE, not a leaf: it references ../namespace.yaml and friends, and
# kustomize's default RootOnly load restrictor refuses files above the build root.
# Its own header documents that rendering it REQUIRES --load-restrictor. This target
# omitted the flag, so `make deploy` failed on a clean checkout with:
#     security; file 'deploy/namespace.yaml' is not in or below 'deploy/base'
# `kubectl apply -k` does not accept --load-restrictor, so the render is piped
# instead - the same shape deploy-overlay below already used.
	$(KUBECTL) kustomize --load-restrictor=LoadRestrictionsNone \
		"$(ROOT)/deploy/base" | $(KUBECTL) apply -f -
	@$(KUBECTL) -n $(SYSTEM_NAMESPACE) rollout status deployment/srek3s-sentinel --timeout=120s
	@$(KUBECTL) -n $(SYSTEM_NAMESPACE) rollout status deployment/srek3s-agent --timeout=120s

.PHONY: undeploy
undeploy: ## Remove the SREK3S workloads, leaving the namespace in place
# Pipelined for the same reason as `deploy`: `delete -k` takes no --load-restrictor,
# and a base kustomization that cannot be rendered cannot be deleted by name either.
	-$(KUBECTL) kustomize --load-restrictor=LoadRestrictionsNone \
		"$(ROOT)/deploy/base" | $(KUBECTL) delete -f - --ignore-not-found

# The overlay is a SEPARATE target on purpose. It scopes the Sentinel to
# sentinel-chaos, which means a developer who applies it has a Sentinel that will
# not watch srek3s-system — and if they then run `make deploy` expecting their
# cluster to be watched, they get a healthy watcher watching nothing. Making that
# an explicit verb rather than a flag is the difference between a documented
# choice and a confusing one.
# The overlay applied by `deploy-overlay`. Defaults to local-live, which renders
# `registry.internal/...` and therefore pairs with `make build`.
#
# It is a variable rather than a hardcoded path because the README's zero-build flow
# needs the SAME chaos patches against the PUBLISHED images, and hardcoding either
# choice would break the other:
#
#   make deploy-overlay OVERLAY=deploy/overlays/quickstart-live
#
# deploy/overlays/quickstart-live consumes local-live unchanged and adds only the
# `images:` rewrite, so the local-image flow above keeps working and the two cannot
# drift into disagreeing about anything except the image reference. This target used
# to name local-live directly, which meant the detonation step of the README's
# zero-build flow pushed both Deployments back to `registry.internal/...` and
# ImagePullBackOff'd them about thirty seconds after a successful quickstart.
OVERLAY ?= $(ROOT)/deploy/overlays/local-live

.PHONY: deploy-overlay
deploy-overlay: ## Apply the chaos overlay (OVERLAY=... to choose; default local-live)
	$(KUBECTL) kustomize --load-restrictor=LoadRestrictionsNone \
		"$(OVERLAY)" | $(KUBECTL) apply -f -

# The zero-build path: the published multi-arch images, no build, no registry login.
#
# Renders to a pipe rather than `apply -k` because `kubectl apply -k` cannot pass
# `--load-restrictor`, and `deploy/base` is not self-contained under the default
# restrictor — it references `../namespace.yaml`, above its own root. The same reason
# `deploy` above pipes, and the same reason it is a flag on the invocation rather
# than `loadRestrictions: LoadRestrictionsNone` in a committed file: the relaxation
# belongs to ONE invocation, not to every future `apply -k` that touches the overlay.
.PHONY: deploy-quickstart
deploy-quickstart: ## Apply the quickstart overlay (prebuilt ghcr.io images, no build)
	@echo "==> applying deploy/overlays/quickstart to the current context"
	@$(KUBECTL) config current-context 2>/dev/null | sed 's/^/    context: /' || true
	$(KUBECTL) kustomize --load-restrictor=LoadRestrictionsNone \
		"$(ROOT)/deploy/overlays/quickstart" | $(KUBECTL) apply -f -
	@$(KUBECTL) -n $(SYSTEM_NAMESPACE) rollout status deployment/srek3s-sentinel --timeout=180s
	@$(KUBECTL) -n $(SYSTEM_NAMESPACE) rollout status deployment/srek3s-agent --timeout=180s

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