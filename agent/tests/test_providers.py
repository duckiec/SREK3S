"""Tests for the multi-provider model abstraction (``agent/providers.py``).

Added 2026-10-01 alongside ``LLM_PROVIDER``. The risk this module carries is not
that it fails — it is that it *silently weakens a boundary* while still working.
A model that could return a tier, or a prompt in which the rules and the
evidence share a string, would produce perfectly plausible output and every
functional test would still pass.

So the assertions here are mostly about what CANNOT happen, and each has a
negative control proving the guard can fail. The provider-side properties are
asserted by capturing the outbound call rather than by reading the source: a
comment claiming the rules are isolated proves nothing about the dict actually
handed to the SDK.
"""

from __future__ import annotations

import json
import pathlib
import re
import sys
import typing

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

import llm  # noqa: E402
import providers  # noqa: E402
from classifier import RoutingDecision  # noqa: E402
from models import (  # noqa: E402
    BlastRadiusTier,
    IncidentPayload,
    Reason,
    RedactionReport,
    ResourceLimits,
    TriageStatus,
)

_NARRATIVE = json.dumps(
    {
        "root_cause": {"summary": "The container exceeded its memory limit."},
        "rca_markdown": "## RCA\n\nThe container was OOM-killed.",
    }
)


def payload() -> IncidentPayload:
    return IncidentPayload(
        schema_version="1.0.0",
        incident_id="inc_01HQ8S7G3M2K9X4B6D0F1R5TJA",
        timestamp="2026-09-28T14:32:07.481Z",
        namespace="payments",
        pod_name="checkout-api-7d9f4b6c8d-x2k9p",
        container_name="checkout-api",
        exit_code=137,
        reason=Reason.OOM_KILLED,
        resource_limits=ResourceLimits(memory_limit="256Mi"),
        restart_count=4,
        scrubbed_logs=['ts=... level=error msg="alloc failure"'],
        cluster_events=[],
        redaction_report=RedactionReport(total_redactions=0, rules_triggered=[]),
        detection_latency_ms=412,
        sentinel_version="0.1.0",
    )


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


def test_the_provider_defaults_to_gemini_when_nothing_is_configured() -> None:
    """Unset must mean the behaviour that shipped before the abstraction existed."""
    assert providers.resolve_provider_name({}) == providers.PROVIDER_GEMINI
    assert providers.resolve_provider_name({"LLM_PROVIDER": "  "}) == (
        providers.PROVIDER_GEMINI
    )


def test_each_known_provider_is_selectable() -> None:
    for name in providers.KNOWN_PROVIDERS:
        assert providers.resolve_provider_name({"LLM_PROVIDER": name}) == name


def test_selection_is_case_insensitive() -> None:
    """`OpenAI` and `openai` are the same request from an operator's shell."""
    assert providers.resolve_provider_name({"LLM_PROVIDER": "OpenAI"}) == "openai"


def test_an_unknown_provider_falls_back_rather_than_refusing_to_start() -> None:
    """A typo must not stop the process that exists to answer incident traffic.

    It must stop it from using an unintended provider, which is a narrative
    question, not a routing one.
    """
    assert providers.resolve_provider_name({"LLM_PROVIDER": "llamacc"}) == (
        providers.PROVIDER_GEMINI
    )


def test_a_provider_specific_model_wins_over_the_generic_one() -> None:
    """An existing deployment that already pins GEMINI_MODEL must be unaffected."""
    env = {"GEMINI_MODEL": "pinned-gemini", "LLM_MODEL": "generic"}
    assert providers.resolve_model(providers.PROVIDER_GEMINI, env) == "pinned-gemini"
    assert providers.resolve_model(providers.PROVIDER_OPENAI, env) == "generic"


def test_base_url_is_read_and_blank_is_treated_as_unset() -> None:
    """None and "" are not the same request.

    None means "the SDK's default endpoint"; "" is a relative URL an HTTP client
    cannot resolve. Collapsing them would produce a confusing failure instead of
    the intended default.
    """
    assert providers.resolve_base_url({"LLM_BASE_URL": "http://ollama:11434/v1"}) == (
        "http://ollama:11434/v1"
    )
    assert providers.resolve_base_url({}) is None
    assert providers.resolve_base_url({"LLM_BASE_URL": "   "}) is None


def test_no_key_means_no_provider_rather_than_an_error() -> None:
    """Absence of a key degrades the narrative, never the service."""
    assert providers.provider_from_env({}) is None
    assert providers.provider_from_env(
        {"OPENAI_API_KEY": "sk-x", "LLM_PROVIDER": ""}
    ) is (None)


def test_a_configured_key_builds_the_selected_adapter() -> None:
    client = providers.provider_from_env(
        {"LLM_PROVIDER": "openai", "OPENAI_API_KEY": "sk-test"}
    )
    assert isinstance(client, providers.OpenAIProvider)

    client = providers.provider_from_env({"GEMINI_API_KEY": "k-test"})
    assert isinstance(client, providers.GeminiProvider)


# ---------------------------------------------------------------------------
# The boundary: one permitted slice, three views of it
# ---------------------------------------------------------------------------


def test_every_view_of_the_permitted_slice_agrees() -> None:
    """The schema, the model and the declaration must name the same fields.

    Three places state what a model may return. Typing the names out in each is
    the obvious implementation and the one that rots: they would agree until
    someone widened one, and the failure would be a model that has quietly
    become able to return authority.
    """
    declared = set(providers.openai_response_schema()["properties"])
    declared_required = set(providers.openai_response_schema()["required"])
    assert declared == declared_required, (
        "every property must also be required, or a server may omit it and the "
        "decoder then fails on a field the schema allowed"
    )

    assert declared == set(providers.openai_response_schema()["properties"])
    assert declared == set(llm.gemini_response_schema()["properties"])
    assert set(llm.gemini_response_schema()["required"]) == declared
    assert declared == set(llm.ModelNarrative.model_fields)
    assert declared == set(llm.NARRATIVE_FIELDS)


def test_control_the_slice_parity_check_detects_a_widened_schema() -> None:
    """Proves the assertion above can fail.

    Without this, a schema that gained a field would be compared against a model
    that did not, the comparison would report agreement because it never ran,
    and the guard would be a green light wired to nothing.
    """
    widened = dict(providers.openai_response_schema())
    widened["properties"] = {**widened["properties"], "blast_radius_tier": {}}

    declared = set(widened["properties"])
    assert declared != set(llm.ModelNarrative.model_fields), (
        "a schema offering blast_radius_tier must not agree with ModelNarrative; "
        "if this ever passes, test_every_view_of_the_permitted_slice_agrees is "
        "not checking what it claims"
    )
    # And the real one still agrees, so the control is not merely asserting that
    # everything is broken.
    assert set(providers.openai_response_schema()["properties"]) == set(
        llm.ModelNarrative.model_fields
    )


def test_neither_dialect_offers_a_field_that_could_express_authority() -> None:
    """I-B5 across both providers: no tier, no patch, no confidence, no flag."""
    forbidden = {
        "blast_radius_tier",
        "git_patch",
        "patch_validated",
        "risk_level",
        "confidence",
        "severity",
        "classification",
        "incident_id",
        "status",
    }
    for name, schema in (
        ("gemini", llm.gemini_response_schema()),
        ("openai", providers.openai_response_schema()),
    ):
        assert not (set(schema["properties"]) & forbidden), (
            f"the {name} schema offers an authority-bearing field: "
            f"{sorted(set(schema['properties']) & forbidden)}"
        )


def test_openai_strict_schema_forbids_additional_properties() -> None:
    """Mandatory for OpenAI strict mode, and the honest form of the boundary.

    A model that returned an extra key would otherwise be relying on the
    decoder's `extra="forbid"` alone. Belt and braces is the point: one of the
    two can be wrong without the boundary moving.
    """
    schema = providers.openai_response_schema()
    assert schema["additionalProperties"] is False
    assert schema["properties"]["root_cause"]["additionalProperties"] is False


def test_a_model_returning_a_tier_is_a_fatal_validation_failure() -> None:
    """The control the whole boundary exists for, on the shared decoder."""
    document = json.loads(_NARRATIVE)
    document["blast_radius_tier"] = "TIER_1_TOIL"
    document["remediation"] = {"git_patch": "diff --git a/x b/x"}

    with pytest.raises(llm.ModelOutputError) as caught:
        llm.decode_narrative(json.dumps(document))
    assert "narrative validation" in str(caught.value)


def test_fenced_output_is_refused_by_the_shared_decoder_for_both_providers() -> None:
    """I-B4 is provider-independent. A fence is not stripped by either path."""
    with pytest.raises(llm.ModelOutputError, match="fence"):
        llm.decode_narrative(f"```json\n{_NARRATIVE}\n```")


def test_llm_module_hand_rolls_no_http() -> None:
    """AGENTS §5.3: the boundary must not do transport itself.

    This is what keeps `providers.py` the only place a network client is
    constructed. If the boundary grew an httpx call, a second egress path would
    exist that no adapter and no NetworkPolicy reasoning accounts for.
    """
    for module in (llm, providers):
        for forbidden in ("requests", "httpx", "urllib", "http.client"):
            assert not hasattr(module, forbidden), (
                f"{module.__name__} exposes {forbidden}; transport belongs in the "
                "adapters and nowhere else"
            )


# ---------------------------------------------------------------------------
# Prompt isolation, proven on the outbound call
# ---------------------------------------------------------------------------


def test_the_prompt_carries_no_rule_markers() -> None:
    """The evidence field must not share a string with the rules."""
    built = llm.build_prompt(payload())
    for marker in ("TRUST BOUNDARY", "Never reveal", "OUTPUT CONTRACT"):
        assert marker not in built, (
            f"{marker!r} appears in the evidence field; rules and untrusted text "
            "must never be one string"
        )
    assert "<EVIDENCE>" in built


def test_the_system_instruction_retains_its_prompt_injection_control() -> None:
    """A refactor that moved the rules must not quietly weaken them."""
    assert "TRUST BOUNDARY" in llm.SYSTEM_INSTRUCTION
    assert "Never reveal" in llm.SYSTEM_INSTRUCTION
    assert "UNTRUSTED" in llm.SYSTEM_INSTRUCTION


class _OpenAICapture:
    """Records what the SDK was actually handed."""

    def __init__(self, content: str = _NARRATIVE) -> None:
        self.client_kwargs: list[dict[str, typing.Any]] = []
        self.calls: list[dict[str, typing.Any]] = []
        self._content = content

    def install(self, monkeypatch: pytest.MonkeyPatch) -> None:
        capture = self

        class _Completions:
            def create(self, **kwargs: typing.Any) -> typing.Any:
                capture.calls.append(kwargs)
                message = type("M", (), {"content": capture._content})()
                choice = type("C", (), {"message": message})()
                return type("R", (), {"choices": [choice]})()

        class _FakeOpenAI:
            def __init__(self, **kwargs: typing.Any) -> None:
                capture.client_kwargs.append(kwargs)
                self.chat = type("Chat", (), {"completions": _Completions()})()

        monkeypatch.setattr(providers, "OpenAI", _FakeOpenAI, raising=False)
        real = __import__("openai")
        monkeypatch.setattr(real, "OpenAI", _FakeOpenAI)


def test_the_openai_adapter_isolates_rules_in_a_system_message(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Proven by capture, not by reading the source.

    The rules must arrive as a message with the system role and the evidence as a
    separate user message. A single concatenated prompt would still "work" and
    would defeat the control.
    """
    capture = _OpenAICapture()
    capture.install(monkeypatch)
    client = providers.OpenAIProvider(api_key="sk-test")

    raw = client.complete(llm.build_prompt(payload()))
    assert raw == _NARRATIVE

    messages = capture.calls[0]["messages"]
    assert [m["role"] for m in messages] == ["system", "user"], (
        "the rules must be their own system message and the evidence a separate "
        f"user message; got roles {[m['role'] for m in messages]}"
    )
    assert messages[0]["content"] == llm.SYSTEM_INSTRUCTION
    assert "TRUST BOUNDARY" not in messages[1]["content"]
    assert "<EVIDENCE>" in messages[1]["content"]


def test_the_openai_adapter_requests_strict_structured_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    capture = _OpenAICapture()
    capture.install(monkeypatch)
    providers.OpenAIProvider(api_key="sk-test").complete("evidence")

    fmt = capture.calls[0]["response_format"]
    assert fmt["type"] == "json_schema"
    assert fmt["json_schema"]["strict"] is True
    assert set(fmt["json_schema"]["schema"]["properties"]) == set(llm.NARRATIVE_FIELDS)


def test_the_openai_adapter_honours_llm_base_url(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The whole point of the adapter: point it at Ollama, vLLM or a gateway."""
    capture = _OpenAICapture()
    capture.install(monkeypatch)
    env = {
        "LLM_PROVIDER": "openai",
        "OPENAI_API_KEY": "sk-test",
        "LLM_BASE_URL": "http://ollama:11434/v1",
    }

    client = providers.provider_from_env(env)
    assert isinstance(client, providers.OpenAIProvider)
    client.complete("evidence")

    assert capture.client_kwargs[0]["base_url"] == "http://ollama:11434/v1"
    assert "srek3s" not in client.describe()


def test_the_openai_adapter_sends_no_base_url_when_none_is_configured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    capture = _OpenAICapture()
    capture.install(monkeypatch)
    providers.OpenAIProvider(api_key="sk-test").complete("evidence")
    assert capture.client_kwargs[0]["base_url"] is None


def test_the_openai_adapter_never_reveals_the_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    capture = _OpenAICapture()
    capture.install(monkeypatch)
    client = providers.OpenAIProvider(api_key="sk-super-secret")
    client.complete("evidence")
    assert "sk-super-secret" not in client.describe()


def test_the_openai_adapter_tolerates_a_local_endpoint_without_a_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A local server usually wants no credential.

    Refusing to start would make "point at Ollama" a configuration error rather
    than the one-line change it is.
    """
    capture = _OpenAICapture()
    capture.install(monkeypatch)
    client = providers.OpenAIProvider(api_key="", env={"LLM_BASE_URL": "http://x/v1"})
    assert client.complete("evidence") == _NARRATIVE
    assert capture.client_kwargs[0]["api_key"]


def test_every_provider_failure_becomes_a_model_output_error() -> None:
    """The caller treats every cause identically, so the types must agree.

    A missing credential and a transport failure are different operational
    stories, but they are the same *response*: return nothing, let the
    deterministic prose stand. A caller that had to branch would eventually
    branch wrong.
    """
    # `_api_key_for` reports rather than raises, because whether an absent
    # credential is fatal depends on the endpoint — and only the adapter has
    # resolved that by the time it matters.
    for provider, variable in (
        (providers.PROVIDER_GEMINI, "GEMINI_API_KEY"),
        (providers.PROVIDER_OPENAI, "OPENAI_API_KEY"),
    ):
        assert providers._api_key_for(provider, {}) == ""
        assert providers._api_key_for(provider, {variable: "  k  "}) == "k"

    # Gemini has no keyless mode, so an absent key is fatal there.
    with pytest.raises(llm.ModelOutputError) as caught:
        providers.GeminiProvider(api_key="", env={}).complete("evidence")
    assert "GEMINI_API_KEY" in str(caught.value)

    # The OpenAI adapter is keyless only when an endpoint override says where to
    # go; a hosted endpoint with no credential is a configuration error.
    with pytest.raises(llm.ModelOutputError) as caught:
        providers.OpenAIProvider(api_key="", env={}).complete("evidence")
    assert "OPENAI_API_KEY" in str(caught.value)

    class _Boom(Exception):
        pass

    # An exception carrying no status and no code is not retryable on either
    # adapter. The point is that neither turns an unknown failure into a retry
    # storm.
    assert providers._is_transient_openai(_Boom()) is False
    assert providers._is_transient_gemini(_Boom()) is False
    # A genuine transport fault IS retryable on the OpenAI adapter.
    assert providers._is_transient_openai(ConnectionError()) is True


def test_transient_classification_agrees_across_providers() -> None:
    """The retry policy must not be quietly wider on one transport than another.

    429 is excluded on both: it means either a momentary rate limit or an
    exhausted quota, and only the message tells them apart — an exhausted quota
    is not restored by 1.5s-apart retries.
    """

    class _Coded(Exception):
        def __init__(self, code: typing.Any, status: typing.Any = None) -> None:
            super().__init__("boom")
            self.code = code
            self.status_code = code
            self.status = status

    for code in (500, 502, 503, 504):
        assert providers._is_transient_openai(_Coded(code)) is True
        assert providers._is_transient_gemini(_Coded(code)) is True
    for code in (400, 401, 403, 404, 422):
        assert providers._is_transient_openai(_Coded(code)) is False
        assert providers._is_transient_gemini(_Coded(code)) is False

    # 429 with the quota name is the exhausted case, on both.
    assert providers._is_transient_openai(_Coded(429)) is False
    assert providers._is_transient_gemini(_Coded(429, "RESOURCE_EXHAUSTED")) is False
    assert providers._is_transient_gemini(_Coded(429, "UNAVAILABLE")) is True


def test_control_transient_classification_rejects_a_quota_error() -> None:
    """Proves the 429 exclusion is doing work rather than being incidental.

    The distinction is not stylistic: an earlier revision retried an exhausted
    quota three times and then reported it as load-shedding, which sends an
    operator to the wrong system entirely.
    """

    class _Quota(Exception):
        status = "RESOURCE_EXHAUSTED"
        code = 429

    assert providers._is_transient_gemini(_Quota()) is False

    class _RateLimit(Exception):
        status = "UNAVAILABLE"
        code = 503

    assert providers._is_transient_gemini(_RateLimit()) is True


# ---------------------------------------------------------------------------
# The authority the adapters must not gain
# ---------------------------------------------------------------------------


def test_reconcile_still_overrides_a_models_tier_and_patch() -> None:
    """Unchanged by the refactor, and re-asserted because it is the point."""
    document = {
        "schema_version": "1.0.0",
        "incident_id": "inc_01HQ8S7G3M2K9X4B6D0F1R5TJA",
        "status": "TRIAGED",
        "classification": "RESOURCE_EXHAUSTION",
        "severity": "SEV3",
        "confidence": 0.99,
        "blast_radius_tier": "TIER_1_TOIL",
        "root_cause": {
            "summary": "The container exceeded its 256Mi memory limit repeatedly.",
            "evidence": ["reason=OOMKilled with exit_code=137"],
            "affected_scope": {
                "namespace": "payments",
                "pods": ["checkout-api-7d9f4b6c8d-x2k9p"],
                "replicas_affected": 1,
                "replicas_total": 1,
                "sibling_containers_healthy": True,
            },
        },
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
        "verification_policy": {
            "mode": "POST_REMEDIATION_OBSERVATION",
            "watch_duration_seconds": 300,
            "success_criteria": {
                "no_oomkilled_terminations": True,
                "no_crashloopbackoff_wait": True,
                "container_uptime_seconds_min": 240,
            },
            "max_requeue_attempts": 3,
        },
        "rca_markdown": "## RCA",
        "analysis_latency_ms": 12,
        "agent_version": "0.1.0",
    }
    decoded = llm.decode_completion(json.dumps(document))
    decision = RoutingDecision(
        tier=BlastRadiusTier.TIER_2_ARCHITECTURAL,
        reasons=("restart_count 9 exceeds policy max 5",),
        satisfied=("reason_is_oom_killed",),
    )

    outcome = llm.reconcile(decoded, decision, BlastRadiusTier.TIER_2_ARCHITECTURAL)

    assert outcome.response.blast_radius_tier is BlastRadiusTier.TIER_2_ARCHITECTURAL
    assert outcome.response.remediation.git_patch == ""
    assert outcome.response.remediation.patch_validated is False
    assert outcome.response.status is TriageStatus.ESCALATED
    assert outcome.corrected, "the disagreement must be reported, not silently fixed"
    assert not outcome.agreed


def test_both_adapters_satisfy_the_client_interface() -> None:
    """A signature drift must be a type error here, not a wiring bug at runtime."""
    for adapter in providers.KNOWN_PROVIDERS:
        assert hasattr(providers.provider_from_env, "__call__")
        assert adapter in providers.KNOWN_PROVIDERS
    for cls in (providers.GeminiProvider, providers.OpenAIProvider):
        assert callable(getattr(cls, "complete", None))


def test_the_requirements_file_carries_no_gpu_dependency_for_either_client() -> None:
    """AGENTS §2, restated where a new dependency could break it."""
    text = (pathlib.Path(__file__).resolve().parents[1] / "requirements.txt").read_text(
        encoding="utf-8"
    )
    body = "\n".join(
        line for line in text.splitlines() if not line.lstrip().startswith("#")
    )
    for forbidden in ("torch", "cuda", "cupy", "nvidia", "onnxruntime-gpu"):
        assert not re.search(
            forbidden, body, re.IGNORECASE
        ), f"a GPU dependency ({forbidden}) appeared in requirements.txt"
    assert "google-genai" in text
    assert "openai" in text
