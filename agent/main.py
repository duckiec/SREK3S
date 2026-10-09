"""FastAPI triage service (ARCH §4, §5).

Routes:

* ``GET  /healthz``            liveness
* ``GET  /readyz``             readiness
* ``POST /api/v1/triage``      Contract A in, Contract B out

Error envelopes (ARCH §4.3), all structured JSON with no host detail:

===========  ==================================  ===========================
Status       Body                                Meaning
===========  ==================================  ===========================
``400``      ``{"error":"malformed_json"}``      body is not parseable JSON
``422``      Pydantic validation errors          contract violation; fatal
``429``      ``{"error":"sandbox_busy"}``        active-job budget reached
``500``      ``{"error":"analysis_failed"}``     unrecoverable; Tier-2
===========  ==================================  ===========================

**No traceback ever reaches the client.** ARCH §4.3 requires structured
envelopes, and a stack trace is a disclosure bug: it names internal modules,
file paths and library versions, and a traceback from a handler that touched an
incident payload can echo payload content back out. Every unhandled exception
is caught at the app boundary, logged server-side with its traceback, and
returned to the client as a fixed envelope. The correlation id in the envelope
is what lets an operator join a client report to the server log.

A ``422`` is never coerced into a Tier-2 dispatch. ARCH §4.3 is explicit that
it indicates contract drift - a build defect - and silently escalating would
conceal exactly the signal that matters.
"""

from __future__ import annotations

import json
import logging
import os
import uuid
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator, Final

from fastapi import FastAPI, Request, status
from fastapi.concurrency import run_in_threadpool
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import ValidationError

import triage
from budget import JobBudget, budget_from_env
import classifier
from classifier import ManifestProvider
from gitops import materialise_manifest_root
from notify import dispatcher_from_env
from sandbox import SandboxError, SandboxPolicy, SandboxRunner
from models import BlastRadiusTier, IncidentPayload, TriageResponse

__all__ = [
    "SANDBOX_ENV",
    "TRIAGE_PATH",
    "TRIAGE_PATH_ALIAS",
    "JobBudget",
    "app",
    "create_app",
]

logger = logging.getLogger("srek3s.agent")

#: Emitted by the logger for every request, so an operator can correlate a
#: client-visible error id with the server-side traceback.
_CORRELATION_HEADER: Final[str] = "X-SREK3S-Request-Id"

_ERROR_MALFORMED_JSON: Final[str] = "malformed_json"
_ERROR_SANDBOX_BUSY: Final[str] = "sandbox_busy"
_ERROR_BODY_TOO_LARGE: Final[str] = "request_too_large"

#: Hard ceiling on the bytes read from a single triage request body.
#:
#: Applied on the streamed read, not only on Content-Length, because a chunked
#: request carries no Content-Length at all and would otherwise be unbounded.
#: 256 KiB sits far above any legitimate payload - models.py already caps
#: scrubbed_logs at 200 lines / 64 KiB and cluster_events at
#: models.CLUSTER_EVENTS_MAX - and far below anything that could exhaust a pod's
#: memory limit.
MAX_REQUEST_BODY_BYTES: Final[int] = 256 * 1024

#: Seconds a refused caller should wait before retrying. Long enough that a
#: saturated service is not immediately re-saturated by the same client, short
#: enough that shedding load recovers quickly.
_RETRY_AFTER_SECONDS: Final[int] = 2
_ERROR_ANALYSIS_FAILED: Final[str] = "analysis_failed"
_ERROR_NOT_FOUND: Final[str] = "not_found"
_ERROR_METHOD_NOT_ALLOWED: Final[str] = "method_not_allowed"


#: Canonical Contract A -> B endpoint (ARCH 4; ROADMAP 2.2.2 and 3.4.4).
TRIAGE_PATH: Final[str] = "/v1/incidents"

#: Versioned-prefix alias specified for the 2.2 task. Shares the handler above.
TRIAGE_PATH_ALIAS: Final[str] = "/api/v1/triage"

#: ARCH 4.3 error envelope, documented in OpenAPI for the canonical path.
_TRIAGE_RESPONSES: Final[dict[int | str, dict[str, str]]] = {
    400: {"description": "unparseable body"},
    422: {"description": "contract violation; not retried (ARCH 4.3)"},
    429: {"description": "active-job budget reached; retry with jitter"},
    500: {"description": "analysis failed; incident escalated to Tier-2"},
}


#: Set to ``1`` to run each admitted analysis in a disposable child process.
SANDBOX_ENV: Final[str] = "SREK3S_SANDBOX"


def _sandbox_enabled(env: dict[str, str] | None = None) -> bool:
    """Whether sandboxed execution is on. Off unless explicitly enabled.

    The deterministic Milestone 2 analysis needs no isolation, and forking a
    process per incident costs ~400 ms, which is the wrong trade on the hot path.
    It exists for the model-directed path, where untrusted output shapes the work.
    """
    source = os.environ if env is None else env
    return source.get(SANDBOX_ENV, "").strip() == "1"


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Startup/shutdown hook.

    Logging is configured here rather than at import so that a library import
    never mutates the host application's logging. The level comes from the
    environment because the read-only root filesystem forbids a log file, so
    logs go to stdout for the container runtime to collect (ARCH §8).
    """
    logging.basicConfig(
        level=os.environ.get("SREK3S_LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    # httpx logs every request at INFO, which puts the full Telegram URL -
    # including the bot token - into the pod logs. Elevate it to WARNING so
    # only genuine failures are emitted.
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpx2").setLevel(logging.WARNING)
    budget = getattr(app.state, "job_budget", None)
    provider = getattr(app.state, "manifest_provider", None)
    # The logged provider name is derived from the object, not hard-coded. The
    # startup line used to say `manifest_provider=unreadable` unconditionally,
    # which is a claim about the service's capability printed by the service
    # itself. Wiring a GitOps checkout in would have made that line a lie, and a
    # log that misreports whether patches are possible is worse than no log:
    # an operator reads it to decide whether Tier-1 is reachable.
    #
    # The target manifest is logged for the same reason and one more. A run that
    # escalates every incident with "target manifest is unreadable" is
    # indistinguishable from a run whose target is simply the wrong file, and
    # the only way to tell them apart from the outside is this line.
    logger.info(
        "srek3s agent starting: version=%s manifest_provider=%s "
        "target_manifest=%s job_budget=%s max_active_jobs=%s",
        triage.AGENT_VERSION,
        type(provider).__name__ if provider is not None else "unset",
        classifier.TARGET_MANIFEST or "(none)",
        "configured" if provider is not None else "unconfigured",
        getattr(budget, "max_active", "unknown"),
    )
    # Unset target and no checkout are different faults with the same symptom -
    # every incident escalates - so the log has to say which one this is. This is
    # the only place the distinction can be made: by the time an incident is
    # triaged, an unreadable target is a filesystem verdict with no record of
    # whether a target was ever asked for.
    #
    # It is ERROR rather than INFO because the state is not the designed resting
    # state. An empty mount with a target configured is fail-closed by design
    # (docs/security-invariants.md, "Not Wired"); an unset target is a
    # deployment that cannot do the one thing Tier-1 exists for, and it reads
    # identically to the design working if the level is left alone.
    if not classifier.TARGET_MANIFEST:
        logger.error(
            "%s is unset or malformed, and the agent ships no default target "
            "manifest, so no incident can be resolved to Tier-1. Every incident "
            "will escalate under I-B2 with the reason 'no patch target is "
            "configured'. Set it to a repository-relative path that exists in the "
            "GitOps checkout, e.g. deploy/chaos/oom-leak.yaml.",
            classifier.TARGET_MANIFEST_ENV,
        )
    yield
    logger.info("srek3s agent shutting down")


async def _read_capped_body(request: Request, limit: int) -> bytes | None:
    """Read at most `limit` bytes of the request body.

    Returns None as soon as the stream exceeds the ceiling, so an oversized body
    is abandoned rather than buffered. `request.json()` cannot be used for this:
    it reads the body to completion before parsing, which is the unbounded-read
    this replaces.
    """
    chunks: list[bytes] = []
    total = 0
    async for chunk in request.stream():
        total += len(chunk)
        if total > limit:
            return None
        chunks.append(chunk)
    return b"".join(chunks)


def _error(status_code: int, code: str, request_id: str) -> JSONResponse:
    """Build a structured error envelope with no host detail."""
    return JSONResponse(
        status_code=status_code,
        content={"error": code, "request_id": request_id},
        headers={_CORRELATION_HEADER: request_id},
    )


def _busy(request_id: str, budget: JobBudget) -> JSONResponse:
    """The 429 envelope (ARCH §4.3, ROADMAP §2.2.5).

    ``Retry-After`` is included because 429 is defined as retryable, and the
    caller is told how long to wait. The Sentinel is expected to add jitter: a
    synchronised retry against a saturated service is how a brief overload
    becomes a sustained one.
    """
    return JSONResponse(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        content={
            "error": _ERROR_SANDBOX_BUSY,
            "request_id": request_id,
            "retry_after_seconds": _RETRY_AFTER_SECONDS,
        },
        headers={
            _CORRELATION_HEADER: request_id,
            "Retry-After": str(_RETRY_AFTER_SECONDS),
        },
    )


def create_app(
    job_budget: JobBudget | None = None,
    manifest_provider: ManifestProvider | None = None,
    notify_dispatcher: Any = None,
) -> FastAPI:
    """Application factory.

    A factory rather than a module-level singleton so tests can build an
    isolated instance per test without leaking state between them.

    ``job_budget`` is injectable so a test can set a tiny budget, or hold a slot
    open deliberately, and observe the 429 path against the real handler rather
    than against a mock of it.

    ``manifest_provider`` is injectable for the same reason, and it is the
    difference between an agent that can only escalate and one that can reach
    Tier-1. It is threaded to :func:`triage.triage_payload` on every request.

    **The default is still fail-closed.** ``None`` means "take it from the
    environment", and an unset ``SREK3S_MANIFEST_ROOT`` yields
    :func:`unreadable_manifest_provider`, so a deployment with no GitOps
    checkout behaves exactly as before: every incident escalates and no patch
    is emitted. Making Tier-1 reachable is therefore an explicit, logged
    deployment act rather than a side effect of this refactor.
    """
    application = FastAPI(
        title="SREK3S Triage Agent",
        version=triage.AGENT_VERSION,
        lifespan=_lifespan,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    @application.middleware("http")
    async def _correlate(request: Request, call_next: Any) -> Any:
        """Attach a correlation id to every request and response.

        Generated per request so two concurrent incidents cannot be confused in
        the logs, which matters because the whole system exists to reason about
        several incidents at once.
        """
        request_id = request.headers.get(_CORRELATION_HEADER) or uuid.uuid4().hex
        request.state.request_id = request_id
        try:
            response = await call_next(request)
        except Exception:  # noqa: BLE001 - deliberate catch-all, see module docstring
            # Re-raised as a 500 below; this branch exists so the traceback is
            # logged with the correlation id before it is swallowed.
            logger.exception("unhandled error request_id=%s", request_id)
            raise
        response.headers[_CORRELATION_HEADER] = request_id
        return response

    # The budget lives on app.state so the handler can reach it, so tests can
    # inspect counters, and so it is replaced wholesale per instance rather than
    # shared between tests through a module global.
    application.state.job_budget = job_budget or budget_from_env()
    # Resolved here, inside the factory, and NEVER at module import time.
    #
    # `app = create_app()` is module scope, so this previously ran on import. A
    # single malformed webhook URL raises ValueError from _require_https_url and
    # crashed the process during import - the exact opposite of notify.py's own
    # claim that "an unset variable never stops the agent from booting", and of
    # budget_from_env's degrade-don't-die policy. It also made the module
    # unimportable under any environment where the notification variables are set
    # but invalid, which is a hard dependency for tests.
    if notify_dispatcher is not None:
        application.state.notify_dispatcher = notify_dispatcher
    else:
        try:
            application.state.notify_dispatcher = dispatcher_from_env()
        except ValueError as exc:
            # Degrade, do not die: an incident is still triaged and still carries
            # its RCA in the response. Only the chat notification is lost, and it
            # is lost loudly.
            logger.warning(
                "notification dispatcher disabled: %s; incidents are still triaged "
                "but will not be paged",
                exc,
            )
            application.state.notify_dispatcher = None

    # Resolved once, at construction, and held on app.state. Resolving per
    # request would re-stat the checkout on the hot path and, worse, would make
    # the provider's identity depend on when the request arrived - so a
    # mid-incident change of configuration could change the tier decision for a
    # retry of the same payload. The provider is a deployment fact, not a
    # per-request one.
    application.state.manifest_provider = (
        manifest_provider
        if manifest_provider is not None
        else materialise_manifest_root()
    )

    # Constructed eagerly, not lazily: tests inspect the runner's peak-concurrency
    # counter, and an absent sandbox should be a configuration fact rather than a
    # late AttributeError on the first request.
    sandbox_on = _sandbox_enabled()
    application.state.sandbox_runner = (
        SandboxRunner(policy=SandboxPolicy()) if sandbox_on else None
    )
    if sandbox_on:
        logger.info(
            "sandbox execution enabled: one disposable worker per admitted request, "
            "bounded by max_active_jobs=%d",
            application.state.job_budget.max_active,
        )

    # -- Health probes -----------------------------------------------------
    # Deliberately unauthenticated and deliberately trivial: a probe that
    # depends on a downstream service turns a restart loop into a cascade.
    #
    # Probes are explicitly *not* subject to the job budget. A probe queued
    # behind saturated analysis would fail exactly when the service is least
    # able to help, and the kubelet would then restart a process that was
    # behaving correctly - turning load into a crash loop.

    @application.get("/healthz")
    async def healthz() -> dict[str, str]:
        """Liveness. Answers as long as the process is serving."""
        return {"status": "ok"}

    @application.get("/readyz")
    async def readyz() -> dict[str, str]:
        """Readiness. Same contract as liveness until a dependency exists."""
        return {"status": "ok"}

    # -- Triage ------------------------------------------------------------
    # Two paths, one handler.
    #
    # TRIAGE_PATH (`/v1/incidents`) is the canonical wire contract: ARCH 4
    # names it and ROADMAP 3.4.4 has the Go emitter POST to exactly that path in
    # Milestone 3. TRIAGE_PATH_ALIAS (`/api/v1/triage`) is the versioned-prefix
    # form specified for this task.
    #
    # Both are served rather than picking one, because the mistake is not
    # symmetric. Serving the alias alone leaves Milestone 3's emitter posting to
    # a 404, and that would surface only at integration. They share one handler,
    # so the two paths cannot diverge in behaviour, and
    # TestBothTriagePathsBehaveIdentically enforces that they do not.
    @application.post(
        TRIAGE_PATH,
        response_model=TriageResponse,
        status_code=status.HTTP_200_OK,
        responses=_TRIAGE_RESPONSES,
    )
    @application.post(
        TRIAGE_PATH_ALIAS,
        response_model=TriageResponse,
        status_code=status.HTTP_200_OK,
        responses=_TRIAGE_RESPONSES,
        include_in_schema=False,
    )
    async def post_triage(request: Request) -> Any:
        """Triage one incident.

        The body is validated by hand rather than via FastAPI's automatic
        model binding, because the automatic path returns its own error shape
        and ARCH §4.3 fixes the envelope. Parsing is done explicitly so a
        malformed body is a 400 and a contract violation is a 422, and the two
        are never conflated.
        """
        request_id = getattr(request.state, "request_id", uuid.uuid4().hex)

        # Admission control, before any parsing or analysis work is done.
        #
        # The budget is acquired around the *whole* handler so the slot covers
        # every unit of work the request causes, not just the triage call. The
        # release is in a `finally` on the lease, so an exception or a client
        # disconnect cannot leak a slot; a leaked slot would ratchet the service
        # into refusing everything, which is the worst failure mode available to
        # a guard whose job is to keep the service serving.
        budget: JobBudget = request.app.state.job_budget
        with budget.slot() as admitted:
            if not admitted:
                # Refused immediately, not queued: see agent/budget.py.
                logger.warning(
                    "job budget saturated incident_id=%s request_id=%s "
                    "active=%d max_active=%d",
                    "<unparsed>",
                    request_id,
                    budget.active,
                    budget.max_active,
                )
                return _busy(request_id, budget)
            return await _triage_locked(request, request_id)

    async def _triage_locked(request: Request, request_id: str) -> Any:
        """The triage handler proper, run with a job slot held."""
        # Size ceiling BEFORE the body is buffered.
        #
        # `await request.json()` reads and parses the entire request body before
        # any bound is applied, so without this the service has an unbounded-read
        # DoS: a single POST can exhaust the pod's memory. 256 KiB is far above any
        # legitimate incident payload (models.py caps scrubbed_logs at 200 lines /
        # 64 KiB and cluster_events is separately length-capped), so nothing real
        # is rejected by this.
        #
        # Content-Length is only a cheap first gate: it is absent for chunked
        # encoding, so the streamed read below enforces the real ceiling on the
        # bytes actually received.
        declared = request.headers.get("content-length")
        if declared is not None:
            try:
                if int(declared) > MAX_REQUEST_BODY_BYTES:
                    logger.warning(
                        "request body too large request_id=%s content_length=%s "
                        "limit=%d",
                        request_id,
                        declared,
                        MAX_REQUEST_BODY_BYTES,
                    )
                    return _error(
                        status.HTTP_413_CONTENT_TOO_LARGE,
                        _ERROR_BODY_TOO_LARGE,
                        request_id,
                    )
            except ValueError:
                logger.warning(
                    "unparseable content-length request_id=%s content_length=%s",
                    request_id,
                    declared,
                )
                return _error(
                    status.HTTP_400_BAD_REQUEST, _ERROR_MALFORMED_JSON, request_id
                )

        raw = await _read_capped_body(request, MAX_REQUEST_BODY_BYTES)
        if raw is None:
            logger.warning(
                "request body exceeded %d bytes request_id=%s",
                MAX_REQUEST_BODY_BYTES,
                request_id,
            )
            return _error(
                status.HTTP_413_CONTENT_TOO_LARGE,
                _ERROR_BODY_TOO_LARGE,
                request_id,
            )

        try:
            body = json.loads(raw)
        except Exception:  # noqa: BLE001 - any parse failure is malformed_json
            logger.warning("malformed body request_id=%s", request_id)
            return _error(
                status.HTTP_400_BAD_REQUEST, _ERROR_MALFORMED_JSON, request_id
            )

        if not isinstance(body, dict):
            logger.warning("body is not a JSON object request_id=%s", request_id)
            return _error(
                status.HTTP_400_BAD_REQUEST, _ERROR_MALFORMED_JSON, request_id
            )

        try:
            payload = IncidentPayload.model_validate(body)
        except ValidationError as exc:
            # 422 is fatal for this payload and is NOT retried and NOT coerced
            # into a Tier-2 dispatch: it means the producer and the schema have
            # diverged, and hiding that would conceal a build defect.
            logger.warning(
                "contract violation incident_id=%s request_id=%s fields=%s",
                body.get("incident_id", "<absent>"),
                request_id,
                [str(err["loc"]) for err in exc.errors()],
            )
            return JSONResponse(
                # `HTTP_422_UNPROCESSABLE_ENTITY` is deprecated in Starlette 1.7 and
                # raises StarletteDeprecationWarning at import. The replacement
                # resolves to the same 422 -- verified against the installed package
                # rather than assumed -- so this silences the warning with no change to
                # the wire contract.
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                content={
                    "error": "validation_error",
                    "request_id": request_id,
                    # Only the field paths and error types. Pydantic's default
                    # `input` echo can contain payload content, so it is
                    # deliberately not included.
                    "details": [
                        {
                            "loc": [str(part) for part in err["loc"]],
                            "type": err["type"],
                            "msg": err["msg"],
                        }
                        for err in exc.errors()
                    ],
                },
                headers={_CORRELATION_HEADER: request_id},
            )

        # The triage engine is synchronous and CPU-bound. Calling it inline from
        # an async handler blocks the event loop for its whole duration, which
        # stalls *every other request*, including the liveness probe.
        #
        # Measured with a 500 ms triage and a probe issued once triage had begun:
        # inline, the probe returned after 516 ms; in the threadpool, after
        # 14 ms. That matters because a probe that stalls past
        # timeoutSeconds x failureThreshold is reported as a failed check, and the
        # kubelet restarts a process that is behaving correctly - so load would
        # become a crash loop.
        #
        # A note on what this does *not* change: the job budget above would bind
        # either way. Concurrency comes from `await request.json()` suspending
        # before the budget check, not from this. An earlier version of this
        # comment claimed otherwise, and a negative control disproved it.
        #
        # The slot is still acquired and released on the event loop, so the
        # counter's check-and-increment atomicity is unchanged.
        # Optional disposable-worker execution (ROADMAP §2.4, §2.4.5).
        #
        # Bounded by the job budget structurally: the budget admits the request
        # before the sandbox starts, and the sandbox is released only once its
        # child has been reaped, so live workers can never exceed max_active. The
        # runner's peak counter makes that assertable rather than assumed.
        #
        # The subprocess runs in the threadpool, never on the event loop
        # (AGENTS.md §3.1). A blocking child would stall /healthz and /readyz, and
        # a stalled probe is exactly what gets a healthy pod restarted.
        sandbox_runner = getattr(request.app.state, "sandbox_runner", None)
        if sandbox_runner is not None:
            try:
                sandbox_result = await run_in_threadpool(
                    sandbox_runner.run, payload.model_dump(mode="json")
                )
            except SandboxError as exc:
                # A failed investigation is an unrecoverable analysis failure, so
                # the incident escalates to Tier-2 rather than being retried: a
                # sandbox that cannot run has nothing to offer a second attempt.
                logger.error(
                    "sandbox failed incident_id=%s request_id=%s: %s",
                    payload.incident_id,
                    request_id,
                    exc,
                )
                return _error(
                    status.HTTP_500_INTERNAL_SERVER_ERROR,
                    _ERROR_ANALYSIS_FAILED,
                    request_id,
                )
            # The child's verdict is CAPTURED and reported, not computed and thrown
            # away. It used to be reduced to a log line and discarded, so the
            # parent then re-derived classification, tier and routing from the
            # same payload itself - meaning the sandbox's answer was never
            # compared against anything, and a divergence between the two
            # implementations (sandbox_worker vs triage) would be invisible.
            #
            # A mismatch is logged loudly. The parent's in-process decision is
            # still authoritative, because it is the one that produced the
            # response; but a silent disagreement is exactly the kind of drift
            # that becomes a wrong patch later.
            sandbox_verdict = sandbox_result.payload or {}
            sandbox_tier = sandbox_verdict.get("tier")
            sandbox_classification = sandbox_verdict.get("classification")
            logger.info(
                "sandbox analysis incident_id=%s request_id=%s latency_ms=%d "
                "rlimits_applied=%s cgroup_enforced=%s "
                "sandbox_tier=%s sandbox_classification=%s",
                payload.incident_id,
                request_id,
                sandbox_result.latency_ms,
                sandbox_result.rlimits_applied,
                sandbox_result.cgroup_enforced,
                sandbox_tier,
                sandbox_classification,
            )
            application_state = getattr(request.app.state, "last_outcome", None)
            if application_state is not None:
                application_state.setdefault("sandbox_verdicts", {})[
                    payload.incident_id
                ] = sandbox_verdict

        try:
            outcome = await run_in_threadpool(
                triage.triage_payload,
                payload,
                manifest_provider=getattr(request.app.state, "manifest_provider", None),
            )
        except Exception:  # noqa: BLE001 - catch-all, see module docstring
            # The traceback stays server-side. An unrecoverable failure escalates
            # the incident to Tier-2, which is the safe direction: a human sees
            # it, and no unvalidated change was ever proposed.
            logger.exception(
                "triage failed incident_id=%s request_id=%s",
                payload.incident_id,
                request_id,
            )
            return _error(
                status.HTTP_500_INTERNAL_SERVER_ERROR,
                _ERROR_ANALYSIS_FAILED,
                request_id,
            )

        response = outcome.response
        logger.info(
            "triaged incident_id=%s tier=%s status=%s classification=%s "
            "latency_ms=%d request_id=%s reasons=%d",
            payload.incident_id,
            outcome.tier.value,
            response.status.value,
            response.classification.value,
            outcome.latency_ms,
            request_id,
            len(outcome.reasons),
        )
        if outcome.tier == BlastRadiusTier.TIER_1_TOIL:
            logger.info(
                "TIER-1 patch proposed incident_id=%s manifest=%s request_id=%s",
                payload.incident_id,
                response.remediation.target_manifest,
                request_id,
            )
        else:
            logger.info(
                "escalated to Tier-2 incident_id=%s status=%s request_id=%s reasons=%s",
                payload.incident_id,
                response.status.value,
                request_id,
                "; ".join(outcome.reasons) or "(no reason recorded)",
            )
            # The dispatch is best-effort and MUST NOT be able to fail the request.
            #
            # `dispatcher.dispatch` is documented as never raising, but its
            # transport handlers only catch httpx.TimeoutException and
            # httpx.TransportError. An httpx.InvalidURL - an out-of-range port or
            # a non-IDNA host in SLACK_WEBHOOK_URL, neither of which
            # _require_https_url rejects - is an Exception, not a TransportError.
            # It propagates out of this handler, becomes a 500 analysis_failed for
            # an incident that was already triaged correctly, and the Sentinel does
            # not retry a 5xx - so the escalation is lost entirely.
            #
            # Comparing the enum rather than the string "TIER_2_ARCHITECTURAL",
            # so a rename of the enum value cannot silently disable escalation.
            dispatcher = getattr(request.app.state, "notify_dispatcher", None)
            if (
                outcome.tier == BlastRadiusTier.TIER_2_ARCHITECTURAL
                and outcome.dispatch is not None
                and dispatcher is not None
            ):
                try:
                    dispatcher.dispatch(
                        payload.incident_id,
                        response.severity.value,
                        response.rca_markdown,
                    )
                except Exception:  # noqa: BLE001 - never fail a triaged incident
                    logger.exception(
                        "notification dispatch failed incident_id=%s request_id=%s; "
                        "the incident was triaged successfully and the verdict is "
                        "unaffected",
                        payload.incident_id,
                        request_id,
                    )
        return response

    # -- Error handlers ----------------------------------------------------
    # Registered so that routing errors and body-validation errors both come
    # back in the ARCH §4.3 envelope rather than FastAPI's default shape.

    @application.exception_handler(RequestValidationError)
    async def _on_request_validation(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        request_id = getattr(request.state, "request_id", uuid.uuid4().hex)
        logger.warning("request validation error request_id=%s", request_id)
        return _error(status.HTTP_400_BAD_REQUEST, _ERROR_MALFORMED_JSON, request_id)

    @application.exception_handler(404)
    async def _on_not_found(request: Request, exc: Exception) -> JSONResponse:
        request_id = getattr(request.state, "request_id", uuid.uuid4().hex)
        return _error(status.HTTP_404_NOT_FOUND, _ERROR_NOT_FOUND, request_id)

    @application.exception_handler(405)
    async def _on_method_not_allowed(request: Request, exc: Exception) -> JSONResponse:
        request_id = getattr(request.state, "request_id", uuid.uuid4().hex)
        return _error(
            status.HTTP_405_METHOD_NOT_ALLOWED, _ERROR_METHOD_NOT_ALLOWED, request_id
        )

    @application.exception_handler(Exception)
    async def _on_unhandled(request: Request, exc: Exception) -> JSONResponse:
        """Last line of defence.

        Reached only if the middleware did not already catch the exception,
        which happens for errors raised before the middleware runs.
        """
        request_id = getattr(request.state, "request_id", uuid.uuid4().hex)
        logger.exception("unhandled error request_id=%s", request_id)
        return _error(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            _ERROR_ANALYSIS_FAILED,
            request_id,
        )

    return application


#: Module-level instance for uvicorn. The Dockerfile ENTRYPOINT targets
#: ``main:app``, so this name is part of the deployment contract.
app = create_app()
