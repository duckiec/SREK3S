"""Adversarial tests for the model transports.

The model endpoint is treated here as an unreliable and actively hostile service:
it returns truncated JSON, smuggles fields it was never offered, drops the
connection, hangs, or lies about what it is. A transport only ever tested against
a well-behaved stub has a failure path that is fiction.

How the network boundary is mocked
----------------------------------
``OpenAIProvider`` is driven through the **real** ``openai`` SDK over an
``httpx.MockTransport``. Only the socket is replaced: the SDK still builds the
request, attaches its headers, parses the response and raises its own exception
hierarchy. That is deliberate, because the base-URL routing assertions below read
the URL the SDK was actually handed — not a constructor keyword. Asserting the
keyword would not catch a client that ignored it and quietly defaulted to a
public endpoint, which for a self-hosted model is both a correctness failure and
a data-egress failure.

``GeminiProvider`` is driven through a capture at ``genai.Client``. That SDK does
not expose a comparable seam for injecting an HTTP transport, so a fake is the
only honest option, and the assertions are written against what the adapter
*received* and *did* rather than against the SDK's internals.

Nothing here mocks a decoder. Every malformed payload goes through the real
``llm.decode_narrative``.
"""

from __future__ import annotations

import json
import pathlib
import sys
import typing

import httpx
import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

import llm  # noqa: E402
import providers  # noqa: E402

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
_SAMPLE = json.loads(
    (REPO_ROOT / "tests/fixtures/sample-incident.json").read_text(encoding="utf-8")
)

#: The fixture as it goes on the wire.
#:
#: `sample-incident.json` carries a `_comment` key documenting the corpus, and
#: `IncidentPayload` is `extra="forbid"` — so posting the file verbatim returns
#: 422, correctly. That is the schema doing its job, not a fixture defect, and
#: it is worth keeping rather than relaxing: these tests POST a real payload, and
#: the annotation is not part of one.
SAMPLE_INCIDENT: dict[str, typing.Any] = {
    key: value for key, value in _SAMPLE.items() if not key.startswith("_")
}

#: A well-formed completion. Every "the pipeline must not break" test needs one
#: control next to its poisoned variant, or the suite proves only that failure is
#: easy.
_VALID: dict[str, typing.Any] = {
    "root_cause": {"summary": "The container exceeded its declared memory limit."},
    "rca_markdown": "## RCA\n\nThe container was OOM-killed.",
}

_LLM_ENV_VARS = (
    "LLM_PROVIDER",
    "LLM_BASE_URL",
    "LLM_MODEL",
    "GEMINI_MODEL",
    "GEMINI_API_KEY",
    "OPENAI_API_KEY",
    "OPENAI_MODEL",
    "SREK3S_LOG_TEXT_EVIDENCE",
)


@pytest.fixture(autouse=True)
def _hermetic(monkeypatch: pytest.MonkeyPatch) -> None:
    """No ambient LLM configuration, and no real retry sleep.

    Hermetic because a developer's exported ``LLM_BASE_URL`` would otherwise
    redirect every assertion below, and fast because an adversarial suite must
    not spend 1.5s per retry to assert a retry budget.
    """
    for name in _LLM_ENV_VARS:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(providers, "GEMINI_RETRY_BACKOFF_SECONDS", 0.0)


# ===========================================================================
# A. Malformed and truncated payloads
# ===========================================================================


@pytest.mark.parametrize(
    ("label", "completion"),
    [
        ("markdown_fenced", f"```json\n{json.dumps(_VALID)}\n```"),
        ("markdown_fenced_no_language", f"```\n{json.dumps(_VALID)}\n```"),
        ("tilde_fenced", f"~~~\n{json.dumps(_VALID)}\n~~~"),
        ("dropped_closing_braces", '{"root_cause": {"summary": "OOM-killed'),
        ("dropped_closing_bracket", '{"root_cause": {"summary": "OOM"}'),
        ("cut_mid_string", '{"root_cause": {"summary": "The container exceed'),
        ("trailing_comma", '{"root_cause": {"summary": "x"},'),
        ("empty_string", ""),
        ("whitespace_only", "   \n\t  \n "),
        ("json_array", "[1, 2, 3]"),
        ("json_scalar", '"just a string"'),
        ("json_number", "42"),
        ("json_null", "null"),
        ("bare_prose", "The container was OOM-killed because it exceeded its limit."),
        ("html_error_page", "<html><body>502 Bad Gateway</body></html>"),
        ("prose_then_json", 'Here is your analysis: {"root_cause": {"summary": "x"}}'),
    ],
)
def test_a_malformed_completion_is_refused_and_never_salvaged(
    label: str, completion: str
) -> None:
    """I-B4: freeform output is a fatal validation failure.

    No fence stripping, no regex scrape, no best-effort parse. Each of these
    would pass a lenient decoder, and a lenient decoder makes the agent's
    behaviour depend on whether the model happened to wrap its answer.
    """
    with pytest.raises(llm.ModelOutputError):
        llm.decode_narrative(completion)


def test_the_refusal_names_the_problem_without_quoting_the_payload() -> None:
    """A model can echo incident text back. Logging it verbatim is a leak.

    The diagnostic must describe the failure, never reproduce the content, or the
    error message becomes a disclosure path around the scrubbing boundary.
    """
    secret_looking = 'aws_secret_access_key = "wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY"'
    with pytest.raises(llm.ModelOutputError) as caught:
        llm.decode_narrative(secret_looking)
    assert "wJalrXUtnFEMI" not in str(caught.value)


def test_a_truncated_completion_is_reported_as_a_document_problem() -> None:
    """A malformed document and a transport fault need different responses."""
    with pytest.raises(llm.ModelOutputError) as caught:
        llm.decode_narrative('{"root_cause": {"summary": "OOM')
    message = str(caught.value).lower()
    assert "json" in message


def test_control_the_refusals_are_discriminating_not_blind() -> None:
    """Proves the malformed cases above are doing work.

    A decoder that rejected everything would pass all sixteen and mean nothing.
    """
    narrative = llm.decode_narrative(json.dumps(_VALID))
    assert narrative.summary.startswith("The container exceeded")
    assert narrative.rca_markdown.startswith("## RCA")


# ===========================================================================
# B. Schema poisoning — extra="forbid"
# ===========================================================================


@pytest.mark.parametrize(
    ("label", "poison"),
    [
        ("unauthorized_exec", {"unauthorized_exec": "rm -rf /"}),
        ("blast_radius_tier", {"blast_radius_tier": "TIER_1_TOIL"}),
        ("patch_validated", {"patch_validated": True}),
        ("incident_id_rename", {"incident_id": "inc_AAAAAAAAAAAAAAAAAAAAAAAA"}),
        ("status", {"status": "TRIAGED"}),
        ("confidence", {"confidence": 1.0}),
        ("severity", {"severity": "SEV1"}),
    ],
)
def test_an_unauthorized_top_level_field_is_rejected_outright(
    label: str, poison: dict[str, typing.Any]
) -> None:
    """The model has no field in which to return authority, and none to invent.

    ``extra="forbid"`` is load-bearing rather than stylistic: silently dropping
    the key would make the schema's guarantee a claim about the provider instead
    of a property of this process.
    """
    with pytest.raises(llm.ModelOutputError):
        llm.decode_narrative(json.dumps({**_VALID, **poison}))


def test_an_extra_key_inside_root_cause_is_inert_rather_than_fatal() -> None:
    """The nesting is asymmetric, deliberately, and the reason matters.

    ``ModelNarrative.root_cause`` is a ``dict[str, Any]``, so a key smuggled
    *inside* it is tolerated rather than rejected. That is safe because nothing
    reads it: :attr:`ModelNarrative.summary` is the only accessor, it fetches the
    one string it wants, and every authority-bearing field the model could
    imagine is absent from the declared schema entirely.

    Asserting this matters in both directions. A test that expected rejection
    here would be wrong and would push someone to "fix" a non-defect; a test that
    ignored the nesting would miss a future change that starts reading a
    sibling key.
    """
    narrative = llm.decode_narrative(
        json.dumps(
            {
                "root_cause": {
                    "summary": "A specific and defensible root cause statement.",
                    "blast_radius_tier": "TIER_1_TOIL",
                    "git_patch": "diff --git a/etc/passwd b/etc/passwd",
                },
                "rca_markdown": "## RCA",
            }
        )
    )
    assert narrative.summary == "A specific and defensible root cause statement."
    # The smuggled authority is simply not reachable from the model.
    assert not hasattr(narrative, "blast_radius_tier")
    assert not hasattr(narrative, "git_patch")


def test_a_smuggled_nested_key_never_reaches_the_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """End-to-end: the poison is in, the authority is not."""
    openai_serving(
        monkeypatch,
        json.dumps(
            {
                "root_cause": {
                    "summary": "The container exceeded its memory limit.",
                    "blast_radius_tier": "TIER_1_TOIL",
                    "patch_validated": True,
                },
                "rca_markdown": "## RCA\n\nNothing needed.",
            }
        ),
    )
    with _api_client(monkeypatch) as client:
        response = client.post("/v1/incidents", json=SAMPLE_INCIDENT)

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["blast_radius_tier"] == "TIER_2_ARCHITECTURAL"
    assert body["remediation"]["patch_validated"] is False
    assert "TIER_1_TOIL" not in response.text


def test_a_model_cannot_smuggle_a_second_authorised_shape() -> None:
    """A nested ``remediation`` carrying a patch is as dangerous as a top-level one."""
    document = {
        **_VALID,
        "remediation": {
            "summary": "Raise the memory limit.",
            "risk_level": "LOW",
            "target_manifest": "deploy/chaos/oom-leak.yaml",
            "git_patch": (
                "--- a/deploy/chaos/oom-leak.yaml\n"
                "+++ b/deploy/chaos/oom-leak.yaml\n"
                "@@ -1,1 +1,1 @@\n"
                "-                memory: 64Mi\n"
                "+                memory: 128Mi\n"
            ),
            "patch_validated": True,
        },
    }
    with pytest.raises(llm.ModelOutputError) as caught:
        llm.decode_narrative(json.dumps(document))
    assert "narrative validation" in str(caught.value)


# ===========================================================================
# C. Transport outages — OpenAI, through the real SDK
# ===========================================================================


def _completion_body(
    content: typing.Any, finish_reason: str = "stop"
) -> dict[str, typing.Any]:
    return {
        "id": "chatcmpl-adversarial",
        "object": "chat.completion",
        "created": 0,
        "model": "test-model",
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": content},
                "finish_reason": finish_reason,
            }
        ],
        "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
    }


class Wire:
    """An httpx-level fake the real openai SDK cannot distinguish from a server."""

    def __init__(
        self, handler: typing.Callable[[httpx.Request], httpx.Response]
    ) -> None:
        self.requests: list[httpx.Request] = []
        self.bodies: list[dict[str, typing.Any]] = []
        self.transport = httpx.MockTransport(self._wrap(handler))

    def _wrap(
        self, handler: typing.Callable[[httpx.Request], httpx.Response]
    ) -> typing.Callable[[httpx.Request], httpx.Response]:
        def wrapped(request: httpx.Request) -> httpx.Response:
            self.requests.append(request)
            self.bodies.append(json.loads(request.content or b"{}"))
            return handler(request)

        return wrapped

    @property
    def url(self) -> str:
        assert self.requests, "no request was issued"
        return str(self.requests[-1].url)

    @property
    def last_request(self) -> httpx.Request:
        assert self.requests, "no request was issued"
        return self.requests[-1]

    @property
    def messages(self) -> list[dict[str, typing.Any]]:
        assert self.bodies, "no request body was captured"
        messages: list[dict[str, typing.Any]] = self.bodies[-1]["messages"]
        return messages


def _install(monkeypatch: pytest.MonkeyPatch, wire: Wire) -> None:
    """Route the real openai SDK through ``wire``."""
    import openai

    real = openai.OpenAI

    def factory(**kwargs: typing.Any) -> typing.Any:
        kwargs["http_client"] = httpx.Client(transport=wire.transport)
        return real(**kwargs)

    monkeypatch.setattr(openai, "OpenAI", factory)


def openai_serving(
    monkeypatch: pytest.MonkeyPatch, content: typing.Any, finish_reason: str = "stop"
) -> Wire:
    wire = Wire(
        lambda _r: httpx.Response(200, json=_completion_body(content, finish_reason))
    )
    _install(monkeypatch, wire)
    return wire


def openai_faulting(
    monkeypatch: pytest.MonkeyPatch,
    handler: typing.Callable[[httpx.Request], httpx.Response],
) -> Wire:
    wire = Wire(handler)
    _install(monkeypatch, wire)
    return wire


def _boom(exc: BaseException) -> typing.Callable[[httpx.Request], httpx.Response]:
    def handler(request: httpx.Request) -> httpx.Response:
        raise exc

    return handler


def _refused() -> typing.Callable[[httpx.Request], httpx.Response]:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("[Errno 111] Connection refused", request=request)

    return handler


def _timed_out() -> typing.Callable[[httpx.Request], httpx.Response]:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("timed out", request=request)

    return handler


def test_a_refused_connection_becomes_a_model_output_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    openai_faulting(monkeypatch, _refused())
    with pytest.raises(llm.ModelOutputError) as caught:
        providers.OpenAIProvider(api_key="sk-test").complete("evidence")
    assert "Traceback" not in str(caught.value)
    assert "Connection refused" not in str(
        caught.value
    ), "the provider's own text must not be reproduced into a log-bound message"


@pytest.mark.parametrize("status", [500, 502, 503, 504])
def test_a_gateway_drop_is_retried_within_a_bounded_budget(
    monkeypatch: pytest.MonkeyPatch, status: int
) -> None:
    """A server-side fault is the one category a second attempt can ride out."""
    wire = openai_faulting(
        monkeypatch, lambda _r: httpx.Response(status, json={"error": "upstream"})
    )
    with pytest.raises(llm.ModelOutputError):
        providers.OpenAIProvider(
            api_key="sk-test", env={}, timeout_seconds=30
        ).complete("e")
    assert len(wire.requests) == llm.GEMINI_MAX_ATTEMPTS


@pytest.mark.parametrize("status", [400, 401, 403, 404, 422])
def test_a_configuration_failure_is_never_retried(
    monkeypatch: pytest.MonkeyPatch, status: int
) -> None:
    """A bad key, a wrong model or a malformed request will not fix itself.

    Retrying burns the whole budget and then reports the wrong cause, which sends
    an operator to a system that is working perfectly well.
    """
    wire = openai_faulting(
        monkeypatch, lambda _r: httpx.Response(status, json={"error": "nope"})
    )
    with pytest.raises(llm.ModelOutputError):
        providers.OpenAIProvider(
            api_key="sk-test", env={}, timeout_seconds=30
        ).complete("e")
    assert len(wire.requests) == 1


def test_an_exhausted_quota_is_not_reported_as_load_shedding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """429 is the exact case a naive retry policy gets wrong.

    Three attempts 1.5s apart cannot restore an exhausted quota, and calling that
    "the provider is busy" sends the on-call engineer to the wrong system.
    """
    wire = openai_faulting(
        monkeypatch,
        lambda _r: httpx.Response(
            429, json={"error": {"code": "insufficient_quota", "message": "quota"}}
        ),
    )
    with pytest.raises(llm.ModelOutputError):
        providers.OpenAIProvider(
            api_key="sk-test", env={}, timeout_seconds=30
        ).complete("e")
    assert len(wire.requests) == 1


def test_a_hanging_endpoint_is_bounded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The Sentinel's emitter retries a slow agent, so unbounded is not an option."""
    openai_faulting(monkeypatch, _timed_out())
    with pytest.raises(llm.ModelOutputError):
        providers.OpenAIProvider(api_key="sk-test", env={}, timeout_seconds=1).complete(
            "evidence"
        )


def _sdk_request() -> typing.Any:
    """A ``Request`` of whatever HTTP library the installed ``openai`` builds on.

    The SDK moved from ``httpx`` to ``httpx2`` between major versions, and its
    exception constructors are annotated against whichever one is present.
    Resolving at runtime keeps this test valid across both instead of pinning a
    generation the next dependency bump would invalidate.

    Typed ``Any`` on purpose: the point is precisely that the type is not fixed.
    """
    import importlib

    for module in ("httpx2", "httpx"):
        try:
            return importlib.import_module(module).Request(
                "POST", "http://model.internal/v1/chat/completions"
            )
        except ImportError:
            continue
    raise RuntimeError("no HTTP client library is importable")  # pragma: no cover


def test_a_timeout_is_retryable_but_an_unknown_error_is_not() -> None:
    """Pins the classification the outage tests above depend on.

    A connection timeout should get another attempt — nothing about the request
    is wrong, the server simply was not reachable this time. An exception the
    adapter does not recognise should not, because guessing wrong here means
    either a retry storm or a lost narrative.
    """
    import openai

    request = _sdk_request()

    # Transport-level: retryable.
    assert (
        providers._is_transient_openai(httpx.ConnectError("refused", request=request))
        is True
    )
    assert (
        providers._is_transient_openai(httpx.ReadTimeout("slow", request=request))
        is True
    )
    assert (
        providers._is_transient_openai(openai.APIConnectionError(request=request))
        is True
    )
    assert (
        providers._is_transient_openai(openai.APITimeoutError(request=request)) is True
    )
    assert providers._is_transient_openai(ConnectionResetError()) is True

    # Unknown: not retryable.
    class _Unknown(Exception):
        pass

    assert providers._is_transient_openai(_Unknown()) is False

    # Status-coded: decided by the code, and 429 excluded on both adapters.
    class _Coded(Exception):
        def __init__(self, code: int) -> None:
            super().__init__("x")
            self.status_code = code

    assert providers._is_transient_openai(_Coded(503)) is True
    assert providers._is_transient_openai(_Coded(429)) is False
    assert providers._is_transient_openai(_Coded(401)) is False


# ---------------------------------------------------------------------------
# Gemini, through a capture at genai.Client
# ---------------------------------------------------------------------------


class _GeminiError(Exception):
    """Shaped like the SDK's, because the adapter reads ``.status`` / ``.code``."""

    def __init__(self, status: str | None, code: int | None) -> None:
        super().__init__("provider exploded")
        self.status = status
        self.code = code


def _gemini_capture(
    monkeypatch: pytest.MonkeyPatch,
    *,
    text: typing.Any = None,
    finish: str = "STOP",
    raise_with: BaseException | None = None,
) -> list[dict[str, typing.Any]]:
    from google import genai

    calls: list[dict[str, typing.Any]] = []

    class _Models:
        def generate_content(self, **kwargs: typing.Any) -> typing.Any:
            calls.append(kwargs)
            if raise_with is not None:
                raise raise_with
            finish_reason = type("F", (), {"name": finish})()
            candidate = type("C", (), {"finish_reason": finish_reason})()
            return type("R", (), {"text": text, "candidates": [candidate]})()

    class _FakeClient:
        def __init__(self, **_kwargs: typing.Any) -> None:
            self.models = _Models()

    monkeypatch.setattr(genai, "Client", _FakeClient)
    return calls


@pytest.mark.parametrize(
    ("finish", "expected"),
    [
        ("SAFETY", "safety"),
        ("MAX_TOKENS", "MAX_OUTPUT_TOKENS"),
        ("RECITATION", "RECITATION"),
        ("PROHIBITED_CONTENT", "PROHIBITED_CONTENT"),
    ],
)
def test_a_gemini_refusal_is_diagnosed_from_the_finish_reason(
    monkeypatch: pytest.MonkeyPatch, finish: str, expected: str
) -> None:
    """A refusal, a safety block and a token overflow need different responses.

    Collapsing them into "the model refused" once sent an operator hunting a
    jailbreak that had never happened.
    """
    _gemini_capture(monkeypatch, text=None, finish=finish)
    with pytest.raises(llm.ModelOutputError) as caught:
        providers.GeminiProvider(api_key="k", env={}).complete("e")
    assert expected in str(caught.value)


def test_a_gemini_refusal_is_not_retried(monkeypatch: pytest.MonkeyPatch) -> None:
    """Re-asking a model that declined tends to produce prose instead of JSON."""
    calls = _gemini_capture(monkeypatch, text=None, finish="SAFETY")
    with pytest.raises(llm.ModelOutputError):
        providers.GeminiProvider(api_key="k", env={}).complete("e")
    assert len(calls) == 1


def test_a_gemini_quota_exhaustion_is_named_as_such(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = _gemini_capture(
        monkeypatch, raise_with=_GeminiError("RESOURCE_EXHAUSTED", 429)
    )
    with pytest.raises(llm.ModelOutputError) as caught:
        providers.GeminiProvider(api_key="k", env={}).complete("e")
    assert "quota is exhausted" in str(caught.value)
    assert len(calls) == 1, "an exhausted quota cannot be restored by retrying"


def test_a_gemini_transient_fault_is_retried_within_the_cap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = _gemini_capture(monkeypatch, raise_with=_GeminiError("UNAVAILABLE", 503))
    with pytest.raises(llm.ModelOutputError):
        providers.GeminiProvider(api_key="k", env={}, timeout_seconds=30).complete("e")
    assert len(calls) == llm.GEMINI_MAX_ATTEMPTS


def test_a_gemini_error_message_quotes_neither_key_nor_provider_text(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Provider errors can echo the request, and the request is incident telemetry."""
    _gemini_capture(monkeypatch, raise_with=_GeminiError("INVALID_ARGUMENT", 400))
    with pytest.raises(llm.ModelOutputError) as caught:
        providers.GeminiProvider(api_key="k-secret", env={}).complete("e")
    assert "k-secret" not in str(caught.value)
    assert "provider exploded" not in str(caught.value)


def test_gemini_keeps_the_rules_out_of_the_content_field(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The prompt-injection control, on the second transport.

    ``content`` is the evidence and nothing else. Anything else is the defect
    that would let a failing container rewrite its own rules.
    """
    from models import IncidentPayload

    calls = _gemini_capture(monkeypatch, text=json.dumps(_VALID))
    payload = IncidentPayload.model_validate(SAMPLE_INCIDENT)
    providers.GeminiProvider(api_key="k", env={}).complete(llm.build_prompt(payload))

    assert calls[0]["config"].system_instruction == llm.SYSTEM_INSTRUCTION
    content = calls[0]["contents"]
    assert "TRUST BOUNDARY" not in content
    assert "Never reveal" not in content
    assert "<EVIDENCE>" in content


# ===========================================================================
# D. Base URL and env resolution — asserted on the wire, not on a keyword
# ===========================================================================


@pytest.mark.parametrize(
    "base_url",
    [
        "http://ollama.srek3s-system.svc:11434/v1",
        "http://vllm-gpu.gpu.svc:8000/v1",
        "https://llm.internal.corp/v1",
        "http://127.0.0.1:8080/v1",
    ],
)
def test_requests_actually_go_to_the_configured_base_url(
    monkeypatch: pytest.MonkeyPatch, base_url: str
) -> None:
    """Read the URL off the socket the SDK was handed, not off a constructor kwarg.

    Asserting the keyword would not catch a client that ignored it and quietly
    defaulted to the public endpoint — which, for a self-hosted model, means
    incident prose leaving the cluster.
    """
    wire = openai_serving(monkeypatch, json.dumps(_VALID))
    env = {
        "LLM_PROVIDER": "openai",
        "OPENAI_API_KEY": "sk-test",
        "LLM_BASE_URL": base_url,
    }
    client = providers.provider_from_env(env)
    assert isinstance(client, providers.OpenAIProvider)
    client.complete("evidence")

    assert wire.url.startswith(base_url), f"went to {wire.url}, not {base_url}"
    assert "openai.com" not in wire.url
    assert "googleapis.com" not in wire.url


def test_switching_the_provider_reroutes_to_a_different_host(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Changing the configuration between calls changes where they go."""
    wire = openai_serving(monkeypatch, json.dumps(_VALID))
    for host in ("http://first.internal:9000/v1", "http://second.internal:9001/v1"):
        client = providers.provider_from_env(
            {
                "LLM_PROVIDER": "openai",
                "OPENAI_API_KEY": "sk",
                "LLM_BASE_URL": host,
            }
        )
        client.complete("e")  # type: ignore[union-attr]
        assert wire.url.startswith(host)
    assert len(wire.requests) == 2


def test_with_no_base_url_the_sdk_default_is_used(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Unset is not the same request as empty, and must reach the real default."""
    wire = openai_serving(monkeypatch, json.dumps(_VALID))
    providers.OpenAIProvider(api_key="sk-test", env={}).complete("e")
    assert "api.openai.com" in wire.url


def test_an_unreachable_base_url_fails_rather_than_falling_back(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A misconfigured self-hosted endpoint must NOT silently become a public call.

    This is the failure that would matter most in production: the operator
    believes traffic stays inside the cluster, and it does not.
    """
    wire = openai_faulting(monkeypatch, _refused())
    client = providers.OpenAIProvider(
        api_key="sk", env={"LLM_BASE_URL": "http://x.invalid:1/v1"}
    )
    with pytest.raises(llm.ModelOutputError):
        client.complete("e")
    assert wire.url.startswith(
        "http://x.invalid:1/v1"
    ), "the request must have been addressed to the configured host, not a default"


def test_a_local_endpoint_needs_no_credential(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A self-hosted server usually has no API key, and requiring one would be wrong."""
    wire = openai_serving(monkeypatch, json.dumps(_VALID))
    providers.OpenAIProvider(
        api_key="", env={"LLM_BASE_URL": "http://ollama:11434/v1"}
    ).complete("e")
    assert wire.url.startswith("http://ollama:11434/v1")


def test_a_keyless_hosted_endpoint_is_refused_before_any_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No key and no endpoint override is a configuration error, not a guess."""
    wire = openai_serving(monkeypatch, json.dumps(_VALID))
    with pytest.raises(llm.ModelOutputError) as caught:
        providers.OpenAIProvider(api_key="", env={}).complete("e")
    assert "OPENAI_API_KEY" in str(caught.value)
    assert not wire.requests, "nothing may be sent without a resolvable credential"


def test_the_key_never_appears_in_the_request_body(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    wire = openai_serving(monkeypatch, json.dumps(_VALID))
    providers.OpenAIProvider(api_key="sk-super-secret", env={}).complete("e")
    assert "sk-super-secret" not in json.dumps(wire.bodies[-1])
    assert "sk-super-secret" not in wire.last_request.content.decode()


def test_the_prompt_is_split_into_a_system_and_a_user_message(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Captured from the wire, which is the only way to prove the SDK kept it."""
    wire = openai_serving(monkeypatch, json.dumps(_VALID))
    providers.OpenAIProvider(api_key="sk-test", env={}).complete("evidence")
    roles = [m["role"] for m in wire.messages]
    assert roles == ["system", "user"]
    assert wire.messages[0]["content"] == llm.SYSTEM_INSTRUCTION
    assert "TRUST BOUNDARY" not in wire.messages[1]["content"]


# ===========================================================================
# E. End-to-end: a hostile model must never become a 500
# ===========================================================================


def _api_client(monkeypatch: pytest.MonkeyPatch) -> typing.Any:
    from fastapi.testclient import TestClient
    from main import create_app

    monkeypatch.setenv("LLM_PROVIDER", "openai")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    return TestClient(create_app())


@pytest.mark.parametrize(
    ("label", "content"),
    [
        ("fenced", "```json\n{}\n```"),
        ("truncated", '{"root_cause": {"summary": "cut off'),
        ("empty", ""),
        ("schema_poisoned", json.dumps({**_VALID, "unauthorized_exec": "rm -rf /"})),
        ("prose", "The container was OOM-killed. Here is my analysis."),
        ("null_bytes", "\x00\x00\x00"),
    ],
)
def test_a_hostile_model_yields_tier2_and_never_a_500(
    monkeypatch: pytest.MonkeyPatch, label: str, content: str
) -> None:
    """The whole point: a broken model costs prose, not availability.

    Tier, empty patch and HTTP 200 are all decided before the model is consulted,
    so a model returning nonsense cannot widen the blast radius or take the
    service down.
    """
    openai_serving(monkeypatch, content)
    with _api_client(monkeypatch) as client:
        response = client.post("/v1/incidents", json=SAMPLE_INCIDENT)

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["blast_radius_tier"] == "TIER_2_ARCHITECTURAL"
    assert body["remediation"]["git_patch"] == ""
    assert body["remediation"]["patch_validated"] is False
    assert body["incident_id"] == SAMPLE_INCIDENT["incident_id"]


def test_a_model_outage_produces_a_200_not_a_500(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The Sentinel retries the agent on 5xx. A model outage must not become one."""
    openai_faulting(monkeypatch, _refused())
    with _api_client(monkeypatch) as client:
        response = client.post("/v1/incidents", json=SAMPLE_INCIDENT)
    assert response.status_code == 200, response.text
    assert response.json()["blast_radius_tier"] == "TIER_2_ARCHITECTURAL"


def test_no_stack_trace_or_provider_text_reaches_the_client(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No traceback, no path, no provider diagnostic in a client response.

    A stack trace is a disclosure bug: it names internal modules and library
    versions, and one raised from a handler that touched an incident payload can
    echo payload content straight back out.
    """
    openai_faulting(
        monkeypatch,
        _boom(
            httpx.ConnectError(
                "refused /v1/chat/completions from 10.43.7.19", request=None
            )
        ),
    )
    with _api_client(monkeypatch) as client:
        response = client.post("/v1/incidents", json=SAMPLE_INCIDENT)

    raw = response.text
    for leak in (
        "Traceback",
        'File "',
        "__cause__",
        "site-packages",
        "10.43.7.19",
        "Connection refused",
        "ModelOutputError",
        "connect_error",
    ):
        assert leak not in raw, f"{leak!r} leaked into the client response"

    assert set(response.json()) >= {"schema_version", "incident_id", "rca_markdown"}


def test_a_poisoned_model_cannot_widen_the_blast_radius(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A model claiming everything is fine must not move the tier.

    The router decides first and the response writes literals regardless. This is
    the end-to-end proof against a model that is actively trying.
    """
    wire = openai_serving(
        monkeypatch,
        json.dumps(
            {
                "root_cause": {"summary": "Nothing is wrong here at all, no action."},
                "rca_markdown": "## RCA\n\nNo action required.",
            }
        ),
    )
    with _api_client(monkeypatch) as client:
        response = client.post("/v1/incidents", json=SAMPLE_INCIDENT)

    body = response.json()
    assert wire.messages[0]["role"] == "system", "the rules must lead"
    assert body["blast_radius_tier"] == "TIER_2_ARCHITECTURAL"
    assert body["remediation"]["risk_level"] == "HIGH"
    assert body["remediation"]["git_patch"] == ""
    assert body["status"] in {"ESCALATED", "UNKNOWN"}


def test_control_the_end_to_end_path_reaches_the_model_at_all(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If the model were never consulted, every test above would pass vacuously.

    A configured key must produce a provider; an absent one must produce nothing
    so the deterministic prose stands. Both are asserted on the wire, so this is
    evidence rather than assumption.
    """
    assert providers.provider_from_env({}) is None

    wire = openai_serving(monkeypatch, json.dumps(_VALID))
    with _api_client(monkeypatch) as client:
        response = client.post("/v1/incidents", json=SAMPLE_INCIDENT)

    assert wire.requests, "the configured model was never contacted"
    assert response.status_code == 200
    assert "Model analysis" in response.json()["rca_markdown"], (
        "a compliant model reply should reach the dispatch document; if this "
        "fails the narrative path is broken and the other tests prove nothing"
    )
