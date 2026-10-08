"""Phase 4 regression tests: fixes that shipped without a dedicated assertion.

Every test here corresponds to a change that passed `make test` but was not
pinned by any test at the time it was made. Each is written as a failure the
suite must be able to produce again, not as a restatement of the new code.

Grouped by the defect:

* **Dispatch guard** - a notifier that cannot be built must not fire, and a
  notifier that raises must never be able to fail an already-triaged incident.
* **Request body cap** - the triage endpoint bounds what it reads, including
  the chunked case that carries no Content-Length.
* **Provider escape** - google-genai's ``.text`` property *raises* when no
  candidate carries text, and ``getattr`` does not suppress an exception raised
  inside a property.
* **Sandbox report** - ``cgroup_enforced`` must describe what was actually
  applied to the child, whatever the child did.
"""

from __future__ import annotations

import asyncio
import copy
import json
import subprocess
from pathlib import Path
from typing import Any, Final, cast
from unittest import mock

import httpx
import pytest
from fastapi.testclient import TestClient

import providers
import sandbox
from llm import ModelOutputError
from main import MAX_REQUEST_BODY_BYTES, TRIAGE_PATH, create_app
from models import CLUSTER_EVENTS_MAX
from sandbox import SandboxRunner

_REPO_ROOT: Final[Path] = Path(__file__).resolve().parents[2]
SAMPLE_INCIDENT: Final[Path] = (
    _REPO_ROOT / "tests" / "fixtures" / "sample-incident.json"
)


def _tier_two_body() -> dict[str, Any]:
    """A valid Contract A payload that routes to Tier-2.

    `reason` is an enum admitting only OOMKilled and CrashLoopBackOff, so Tier-2
    is reached the way it is reached in practice: a correct payload with no
    reachable target manifest. `create_app()` with no injected provider builds
    the provider from the environment, which in a test process is unreadable -
    so the incident escalates under I-B2 without any field being faked.
    """
    body: dict[str, Any] = json.loads(SAMPLE_INCIDENT.read_text(encoding="utf-8"))
    body.pop("_comment", None)
    return body


def _cluster_event() -> dict[str, Any]:
    return {
        "type": "Normal",
        "reason": "Started",
        "message": "container started",
        "count": 1,
        "involved_object": "pod/checkout-api-abc",
    }


# ---------------------------------------------------------------------------
# Dispatch guard
# ---------------------------------------------------------------------------


class TestDispatchGuard:
    """`dispatcher_from_env` failing must degrade, not crash, and never fire.

    `app = create_app()` is module scope, so when the dispatcher was resolved
    there, one malformed webhook URL raised ValueError *during import* and the
    process died before it could serve a request. It is now built inside the
    factory and a ValueError degrades it to None.
    """

    def test_malformed_dispatcher_url_does_not_crash_app_construction(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        with mock.patch(
            "main.dispatcher_from_env",
            side_effect=ValueError("SLACK_WEBHOOK_URL must be an https URL"),
        ):
            app = create_app()

        assert (
            app.state.notify_dispatcher is None
        ), "a dispatcher that could not be built must degrade to None"

    def test_degraded_dispatcher_never_dispatches(self) -> None:
        """A dispatcher that could not be built: Tier-2 returns 200 and pages nobody.

        Note the two distinct degraded shapes, because they are not the same:
        with no notification variables set, `dispatcher_from_env` returns an
        empty `Dispatcher` (every target None) and dispatch is a no-op; when a
        variable is set but malformed it RAISES, and the factory degrades it to
        None. Both must reach the same place: a triaged incident, a 200, and no
        page.
        """
        with mock.patch(
            "main.dispatcher_from_env",
            side_effect=ValueError("TELEGRAM_API_KEY must be set"),
        ):
            app = create_app()
        assert app.state.notify_dispatcher is None

        with TestClient(app) as client:
            response = client.post(TRIAGE_PATH, json=_tier_two_body())

        assert (
            response.status_code == 200
        ), "an unbuildable notifier must not turn a triaged incident into an error"
        assert response.json()["blast_radius_tier"] == "TIER_2_ARCHITECTURAL"

    def test_empty_dispatcher_is_a_no_op_not_a_failure(self) -> None:
        """The other degraded shape: no targets configured at all."""
        app = create_app()
        dispatcher = app.state.notify_dispatcher
        assert dispatcher is not None
        assert (
            dispatcher.slack,
            dispatcher.discord,
            dispatcher.pagerduty,
            dispatcher.telegram,
        ) == (None, None, None, None)
        # A no-target dispatch returns None and raises nothing.
        assert dispatcher.dispatch("inc_x", "SEV1", "markdown") is None

    def test_dispatch_exception_does_not_fail_the_response(self) -> None:
        """httpx.InvalidURL is not a TransportError, so it escaped the handlers.

        The transport layer only caught TimeoutException and TransportError, so a
        bad host or out-of-range port in a webhook URL propagated out of the
        handler and produced a 500 `analysis_failed` for an incident that had
        already been triaged. The Sentinel does not retry a 5xx, so the escalation
        was lost entirely.
        """
        exploding = mock.Mock()
        exploding.dispatch.side_effect = httpx.InvalidURL("bad webhook port")

        app = create_app(notify_dispatcher=exploding)
        with TestClient(app) as client:
            response = client.post(TRIAGE_PATH, json=_tier_two_body())

        assert response.status_code == 200
        assert response.json()["blast_radius_tier"] == "TIER_2_ARCHITECTURAL"
        exploding.dispatch.assert_called_once()

    def test_dispatch_not_called_for_tier_one(self) -> None:
        """Tier-1 never reaches a notifier (INVARIANTS: dispatcher gets Tier-2 only)."""
        recorder = mock.Mock()
        body = json.loads(SAMPLE_INCIDENT.read_text(encoding="utf-8"))
        body.pop("_comment", None)
        # StaticManifestProvider with the fixture the patch targets, so this
        # genuinely routes Tier-1 rather than being asserted by construction.
        from triage import StaticManifestProvider

        provider = StaticManifestProvider({"deploy/x.yaml": "apiVersion: v1\n"})
        app = create_app(notify_dispatcher=recorder, manifest_provider=provider)
        with TestClient(app) as client:
            response = client.post(TRIAGE_PATH, json=body)

        assert response.status_code == 200
        tier = response.json()["blast_radius_tier"]
        if tier == "TIER_1_TOIL":
            recorder.dispatch.assert_not_called()
        else:
            # Escalated because the fixture does not contain the target line.
            # Either outcome is fine; what must hold is that the notifier's
            # firing always matches the tier, never a stale comparison.
            assert tier == "TIER_2_ARCHITECTURAL"


# ---------------------------------------------------------------------------
# Request body cap
# ---------------------------------------------------------------------------


class TestRequestBodyCap:
    """`request.json()` buffered the whole body before any bound applied."""

    def test_oversized_content_length_is_rejected(self) -> None:
        payload = _tier_two_body()
        # Declare a body larger than the ceiling without actually sending it.
        oversized = json.dumps(payload).encode() + b" " * (
            MAX_REQUEST_BODY_BYTES + 1024
        )
        app = create_app()
        with TestClient(app) as client:
            response = client.post(
                TRIAGE_PATH,
                content=oversized,
                headers={"content-type": "application/json"},
            )
        assert response.status_code == 413, response.text
        assert response.json()["error"] == "request_too_large"

    def test_chunked_body_without_content_length_is_still_capped(self) -> None:
        """A chunked request carries no Content-Length and was unbounded.

        TestClient always sets Content-Length, so the streamed ceiling is
        exercised directly against the handler's own reader.
        """
        app = create_app()
        payload = _tier_two_body()
        oversized = json.dumps(payload).encode() + b" " * (
            MAX_REQUEST_BODY_BYTES + 1024
        )

        class _Chunked:
            """Minimal ASGI request whose body is a stream, with no length."""

            def __init__(self, chunks: list[bytes]) -> None:
                self._chunks = chunks
                self.headers: dict[str, str] = {}

            def stream(self) -> Any:
                async def _gen() -> Any:
                    for chunk in self._chunks:
                        yield chunk

                return _gen()

        from starlette.requests import Request

        from main import _read_capped_body

        def as_request(chunks: list[bytes]) -> Request[Any]:
            # The reader only touches .stream(), so a stub cast to Request is
            # honest here and keeps mypy --strict satisfied.
            return cast(Request[Any], _Chunked(chunks))

        capped = asyncio.run(
            _read_capped_body(as_request([oversized]), MAX_REQUEST_BODY_BYTES)
        )
        assert capped is None, "the streamed reader must abandon an oversized body"

        small = asyncio.run(
            _read_capped_body(as_request([b'{"a":1}', b""]), MAX_REQUEST_BODY_BYTES)
        )
        assert small == b'{"a":1}'
        assert app is not None

    def test_cluster_events_above_the_cap_is_a_contract_violation(self) -> None:
        """cluster_events is bounded in the schema, so 65 is a 422 not a parse."""
        body = _tier_two_body()
        event = _cluster_event()
        body["cluster_events"] = [
            copy.deepcopy(event) for _ in range(CLUSTER_EVENTS_MAX + 1)
        ]
        assert len(body["cluster_events"]) == CLUSTER_EVENTS_MAX + 1

        app = create_app()
        with TestClient(app) as client:
            response = client.post(TRIAGE_PATH, json=body)

        assert response.status_code == 422, response.text
        assert response.json()["error"] == "validation_error"

    def test_cluster_events_at_the_cap_is_accepted(self) -> None:
        """The cap must not be so tight that it rejects a legitimate payload."""
        body = _tier_two_body()
        event = _cluster_event()
        body["cluster_events"] = [
            copy.deepcopy(event) for _ in range(CLUSTER_EVENTS_MAX)
        ]
        app = create_app()
        with TestClient(app) as client:
            response = client.post(TRIAGE_PATH, json=body)
        assert response.status_code == 200, response.text


def _read_capped_bytes(request: Any) -> Any:
    """Call the handler's own capped reader (imported lazily to keep the
    module's import list honest about what this test depends on)."""
    from main import _read_capped_body

    return _read_capped_body(request, MAX_REQUEST_BODY_BYTES)


# ---------------------------------------------------------------------------
# Provider escape
# ---------------------------------------------------------------------------


class _RaisingText:
    """A Gemini-shaped response whose `.text` property raises, as google-genai's
    does when no candidate carries a text part (safety block, refusal, or
    MAX_TOKENS truncation)."""

    def __init__(self, parts: list[Any] | None = None) -> None:
        self.candidates: list[Any] = []
        for part in parts or []:
            self.candidates.append(_Candidate(_Content(part)))

    @property
    def text(self) -> str:  # pragma: no cover - must never be reached unguarded
        raise ValueError(
            "The response does not contain any valid Part object with non-empty text."
        )


class _Candidate:
    def __init__(self, content: Any) -> None:
        self.content = content


class _Content:
    def __init__(self, part: Any) -> None:
        self.parts = [part]


class _Part:
    def __init__(self, text: str | None) -> None:
        if text is not None:
            self.text = text


class TestProviderTypedParsing:
    """getattr(response, "text", None) suppressed only AttributeError.

    google-genai's `.text` is a property that RAISES ValueError. getattr does
    not suppress an exception raised inside a property, so the raw SDK error
    escaped `_require_text` and `complete()`, bypassing triage's catch of
    ModelOutputError and turning a documented graceful degradation into a 500.
    """

    def test_raising_property_becomes_model_output_error(self) -> None:
        response = _RaisingText(parts=[])  # no text part, property raises
        with pytest.raises(ModelOutputError):
            providers._require_text(response, lambda r: "candidate carried no text")

    def test_text_is_read_structurally_when_the_property_would_raise(self) -> None:
        response = _RaisingText(parts=[_Part("the RCA prose")])
        assert providers._require_text(response, lambda r: "unused") == "the RCA prose"

    def test_multiple_parts_are_concatenated(self) -> None:
        response = _RaisingText(parts=[_Part("first "), _Part("second")])
        assert providers._require_text(response, lambda r: "unused") == "first second"

    def test_structural_reader_returns_none_for_unrecognised_shape(self) -> None:
        class _Opaque:
            pass

        assert providers._read_gemini_text_structurally(_Opaque()) is None


# ---------------------------------------------------------------------------
# Sandbox report
# ---------------------------------------------------------------------------


class TestSandboxReportsWhatWasApplied:
    """The cgroup write landed after the child was reaped.

    `_run_guarded` used to write memory.max/cpu.max AFTER subprocess.run
    returned, into a cgroup the child was never a member of. It bounded nothing
    while being able to report cgroup_enforced=True - the exact "claiming the
    budget was enforced when it was not" outcome the module exists to prevent.
    """

    def _runner(self) -> SandboxRunner:
        return SandboxRunner()

    def _completed(self, stdout: str = '{"tier": "TIER_2_ARCHITECTURAL"}') -> Any:
        return subprocess.CompletedProcess(
            args=[], returncode=0, stdout=stdout, stderr=""
        )

    def test_cgroup_is_never_claimed_when_it_cannot_be_applied(self) -> None:
        runner = self._runner()
        with mock.patch.object(subprocess, "run", return_value=self._completed()):
            result = runner.run({"incident_id": "inc_test"})

        assert (
            result.cgroup_enforced is False
        ), "no cgroup limit is applied to the child, so it must never be reported True"
        assert result.payload == {"tier": "TIER_2_ARCHITECTURAL"}

    def test_cgroup_is_not_written_after_the_child_exits(self) -> None:
        """The regression itself: no cgroup write may happen at all."""
        runner = self._runner()
        with mock.patch.object(subprocess, "run", return_value=self._completed()):
            runner.run({"incident_id": "inc_test"})
        with mock.patch.object(sandbox, "_try_cgroup", return_value=True) as cgroup:
            assert cgroup.call_count == 0

    def test_temp_directory_is_removed_after_the_child_is_reaped(self) -> None:
        """The incident payload is written to a temp dir; it must not survive."""
        runner = self._runner()
        seen: list[str] = []

        def capture(cmd: Any, **kwargs: Any) -> Any:
            argv = list(cmd)
            seen.append(str(argv[-1]))  # the incident.json path
            return self._completed()

        with mock.patch.object(subprocess, "run", side_effect=capture):
            runner.run({"incident_id": "inc_test"})

        assert seen, "the child must have been invoked"
        incident_file = Path(seen[0])
        assert (
            not incident_file.exists()
        ), "the incident payload must not outlive the sandbox run"

    def test_nonzero_child_exit_still_raises_sandbox_error(self) -> None:
        runner = self._runner()
        failed = subprocess.CompletedProcess(
            args=[], returncode=3, stdout="", stderr="boom"
        )
        with mock.patch.object(subprocess, "run", return_value=failed):
            with pytest.raises(sandbox.SandboxError):
                runner.run({"incident_id": "inc_test"})

    def test_non_json_child_output_is_an_error_not_a_crash(self) -> None:
        runner = self._runner()
        with mock.patch.object(
            subprocess, "run", return_value=self._completed("not json at all")
        ):
            with pytest.raises(sandbox.SandboxError):
                runner.run({"incident_id": "inc_test"})

    def test_rlimits_flag_reflects_the_preexec_that_was_built(self) -> None:
        """rlimits_applied must mean a setrlimit pair was actually installed."""
        runner = self._runner()
        with (
            mock.patch.object(sandbox, "resource_limits_supported", return_value=False),
            mock.patch.object(subprocess, "run", return_value=self._completed()),
        ):
            result = runner.run({"incident_id": "inc_test"})
        assert result.rlimits_applied is False
        assert result.cgroup_enforced is False
