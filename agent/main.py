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
from models import IncidentPayload, TriageResponse

__all__ = [
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
    budget = getattr(app.state, "job_budget", None)
    logger.info(
        "srek3s agent starting: version=%s manifest_provider=unreadable "
        "(tier-1 patches require a GitOps checkout, ARCH 5.4 I-B2) "
        "max_active_jobs=%s",
        triage.AGENT_VERSION,
        getattr(budget, "max_active", "unknown"),
    )
    yield
    logger.info("srek3s agent shutting down")


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


def create_app(job_budget: JobBudget | None = None) -> FastAPI:
    """Application factory.

    A factory rather than a module-level singleton so tests can build an
    isolated instance per test without leaking state between them.

    ``job_budget`` is injectable so a test can set a tiny budget, or hold a slot
    open deliberately, and observe the 429 path against the real handler rather
    than against a mock of it.
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
        try:
            body = await request.json()
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
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
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
        try:
            outcome = await run_in_threadpool(triage.triage_payload, payload)
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
        if outcome.tier.value == "TIER_1_TOIL":
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
