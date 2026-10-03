"""Tests for NVIDIA NIM as a provider configuration, added 2026-10-03.

Why this file exists
--------------------
NVIDIA NIM speaks the OpenAI chat-completions protocol, so it is a *configuration*
of ``OpenAIProvider`` rather than a third adapter. That design is what makes vendor
lock-in cheap to remove — and it is also what made two silent bugs possible, because
a class serving several providers has to resolve per-provider facts it used to take
from its own class identity.

Both bugs were found by running against the live endpoint, not by any test:

  1. ``model_name`` returned ``resolve_model(PROVIDER_OPENAI, env)``. A deployment
     configured as ``nvidia`` therefore asked NVIDIA's endpoint for ``gpt-4o-mini``.
     Every offline test passed, because both values are plausible strings.
  2. ``complete()`` resolved its credential through ``_api_key_for(PROVIDER_OPENAI)``,
     so an NVIDIA deployment holding only ``NVIDIA_API_KEY`` reported a missing
     credential while holding a perfectly good one.

Both are the same mistake in different clothes: reading a deployment fact off the
class instead of off the configuration. Neither would ever raise in a unit test that
does not assert the outbound request, so the controls here assert **what the SDK was
handed** — the model string on the wire and the ``api_key`` the client was
constructed with — rather than what a property returns.

The negative controls matter more than the positive ones. Three of the tests below
exist only to prove the others can fail: a control that cannot distinguish a correct
implementation from a broken one is not a control. See
``test_the_model_control_catches_the_class_based_bug_it_guards``.
"""

from __future__ import annotations

import json
import pathlib
import sys
import typing

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

import llm  # noqa: E402
import providers  # noqa: E402

_NARRATIVE = json.dumps(
    {"root_cause": {"summary": "Memory limit exceeded."}, "rca_markdown": "## RCA"}
)

#: The endpoint, as a deployment fact. Mirrored from ``deploy/agent.yaml`` rather
#: than imported: kustomize cannot read a Python constant, and a manifest that
#: referenced a notional import would render as the literal string anyway.
NIM_BASE_URL = "https://integrate.api.nvidia.com/v1"

#: A model NVIDIA RETIRED. Kept as a named constant so the guard below reads as a
#: statement about a specific historical fact rather than as a vague "old model".
RETIRED_MODEL = "meta/llama-3.1-70b-instruct"


class _Capture:
    """Records what the OpenAI SDK was actually handed.

    Deliberately the same shape as ``test_providers._OpenAICapture`` and
    self-contained rather than imported: the two files must be able to fail
    independently, and a shared private helper would couple them.
    """

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


def _nvidia_env(**extra: str) -> dict[str, str]:
    env = {"LLM_PROVIDER": "nvidia", "NVIDIA_API_KEY": "nv-test-key"}
    env.update(extra)
    return env


def _client(env: dict[str, str]) -> providers.OpenAIProvider:
    """The factory result, narrowed to the adapter that must have been built.

    Exists so every call site states the expectation once. An un-narrowed
    ``provider_from_env(...).complete(...)`` is both a typing hole and a silent
    way to make a test pass vacuously if the factory starts returning ``None`` —
    an ``AttributeError`` on ``None`` is at least loud, but a narrow helper is
    clearer about what is being asserted.
    """
    client = providers.provider_from_env(env)
    assert isinstance(client, providers.OpenAIProvider), (
        f"expected the OpenAI-protocol adapter for {env.get('LLM_PROVIDER')!r}, "
        f"got {type(client).__name__}"
    )
    return client


# ---------------------------------------------------------------------------
# A. The provider is wired in at all
# ---------------------------------------------------------------------------


def test_nvidia_is_a_known_provider() -> None:
    assert providers.PROVIDER_NVIDIA in providers.KNOWN_PROVIDERS
    assert providers.resolve_provider_name({"LLM_PROVIDER": "nvidia"}) == "nvidia"
    # Case-insensitive, like every other provider: an operator's shell is not a
    # schema.
    assert providers.resolve_provider_name({"LLM_PROVIDER": "NVIDIA"}) == "nvidia"


def test_nvidia_routes_through_the_existing_openai_adapter(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No third adapter class. That is the property the design is asserting."""
    client = _client(_nvidia_env())
    assert not isinstance(client, providers.GeminiProvider)


def test_nvidia_is_built_only_when_its_own_credential_is_present() -> None:
    """Absence of a key must degrade the narrative, never stop the service."""
    assert providers.provider_from_env({"LLM_PROVIDER": "nvidia"}) is None
    assert providers.provider_from_env(_nvidia_env(NVIDIA_API_KEY="   ")) is None
    # An OpenAI key must NOT satisfy an NVIDIA deployment, and vice versa. A
    # shared-key design would make this assertion pass for the wrong reason.
    assert (
        providers.provider_from_env(
            {"LLM_PROVIDER": "nvidia", "OPENAI_API_KEY": "sk-test"}
        )
        is None
    )
    assert (
        providers.provider_from_env(
            {"LLM_PROVIDER": "openai", "NVIDIA_API_KEY": "nv-test-key"}
        )
        is None
    )


def test_the_credential_variable_is_the_nvidia_one() -> None:
    assert providers._API_KEY_ENV[providers.PROVIDER_NVIDIA] == "NVIDIA_API_KEY"
    assert providers._PROVIDER_SPECIFIC_MODEL_ENV[providers.PROVIDER_NVIDIA] == (
        "NVIDIA_MODEL"
    )


# ---------------------------------------------------------------------------
# B. Per-provider resolution — the regression guards for the two live bugs
# ---------------------------------------------------------------------------


def test_nvidia_resolves_its_own_default_model_not_openais() -> None:
    """The bug, restated as an assertion.

    Pre-fix this returned ``gpt-4o-mini``: ``model_name`` asked
    ``resolve_model(PROVIDER_OPENAI, ...)`` regardless of the configured provider.
    The assertion is written as "not OpenAI's default" rather than as an equality
    with a literal, so it keeps holding if the NVIDIA default is repointed at a
    working model later.
    """
    env = _nvidia_env()
    client = providers.OpenAIProvider(env=env)
    openai_default = providers._DEFAULT_MODEL[providers.PROVIDER_OPENAI]

    assert client.model_name != openai_default, (
        "an NVIDIA deployment is asking for OpenAI's default model; the adapter "
        f"resolved {openai_default!r} from the class instead of the configuration"
    )
    assert client.model_name == providers._DEFAULT_MODEL[providers.PROVIDER_NVIDIA]


def test_the_outbound_request_carries_the_configured_providers_model(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Asserted on the wire, not on the property.

    A property can report the right string while the call sends another — which is
    exactly the shape of bug this file exists for, so the assertion is made against
    the captured outbound call.
    """
    capture = _Capture()
    capture.install(monkeypatch)
    _client(_nvidia_env(LLM_BASE_URL=NIM_BASE_URL)).complete("evidence")

    sent = capture.calls[0]["model"]
    assert sent == providers._DEFAULT_MODEL[providers.PROVIDER_NVIDIA]
    assert sent != providers._DEFAULT_MODEL[providers.PROVIDER_OPENAI]


def test_an_explicitly_configured_nvidia_model_is_not_overridden(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`NVIDIA_MODEL` must win, exactly as `GEMINI_MODEL` does."""
    capture = _Capture()
    capture.install(monkeypatch)
    _client(_nvidia_env(NVIDIA_MODEL="pinned/nemotron", LLM_MODEL="generic")).complete(
        "evidence"
    )

    assert capture.calls[0]["model"] == "pinned/nemotron"


def test_describe_names_the_configured_provider_not_the_class() -> None:
    """A startup log that says `openai model=…` on an NVIDIA deployment misleads.

    Nobody is paged by it, so it is exactly the kind of wrongness that survives
    review. It was true for the same reason the model name was wrong.

    The assertion is on the PREFIX, not on the substring ``openai``. The working
    NVIDIA model is namespaced ``openai/gpt-oss-20b`` on NIM — a third-party host
    serving an OpenAI-published model under its own namespace — so a substring
    check here would fail for a reason that has nothing to do with the provider
    being named. The first field is the thing that answers the question.
    """
    described = _client(_nvidia_env()).describe()
    assert described.startswith(f"{providers.PROVIDER_NVIDIA} ")
    assert not described.startswith(f"{providers.PROVIDER_OPENAI} ")
    assert f"model={providers._DEFAULT_MODEL[providers.PROVIDER_NVIDIA]}" in described


def test_the_credential_presented_to_the_sdk_is_the_configured_providers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Regression guard: `complete()` resolved the key off the class.

    An NVIDIA deployment holding only ``NVIDIA_API_KEY`` reported a missing
    credential — a fail-closed degradation that was invisible, because it looked
    exactly like working as designed.
    """
    capture = _Capture()
    capture.install(monkeypatch)
    _client(_nvidia_env(LLM_BASE_URL=NIM_BASE_URL)).complete("evidence")

    assert capture.client_kwargs[0]["api_key"] == "nv-test-key"


def test_a_missing_nvidia_credential_names_the_nvidia_variable() -> None:
    """The operator's next action must be visible in the error.

    Pre-fix this raised naming ``OPENAI_API_KEY`` for an NVIDIA deployment, sending
    an operator to configure a credential the system will never read.
    """
    with pytest.raises(llm.ModelOutputError) as caught:
        providers.OpenAIProvider(
            env={"LLM_PROVIDER": "nvidia", "NVIDIA_API_KEY": ""}
        ).complete("evidence")
    message = str(caught.value)
    assert "NVIDIA_API_KEY" in message
    assert "OPENAI_API_KEY" not in message


# ---------------------------------------------------------------------------
# C. The default model is a working model, not a retired one
# ---------------------------------------------------------------------------


def test_the_default_nvidia_model_is_not_one_nim_has_retired() -> None:
    """HTTP 410, `end of life on 2026-08-26`.

    A default that fails on every call is not a default; it is a deployment that
    only works because nobody set one. This was invisible offline — the string is
    plausible, well-formed and OpenAI-shaped.
    """
    default = providers._DEFAULT_MODEL[providers.PROVIDER_NVIDIA]
    assert default != RETIRED_MODEL
    for retired in ("meta/llama-3.1-8b-instruct", "meta/llama-3.3-70b-instruct"):
        assert default != retired


# ---------------------------------------------------------------------------
# D. Negative controls — proof that the guards above can fail
# ---------------------------------------------------------------------------


def test_the_model_control_catches_the_class_based_bug_it_guards() -> None:
    """Plant the pre-fix expression and show it produces a DIFFERENT answer.

    Without this, ``test_nvidia_resolves_its_own_default_model_not_openais`` might
    be passing for the wrong reason — e.g. if every provider somehow resolved to the
    same string, an equality check would hold while the bug was present.
    """
    env = _nvidia_env()

    pre_fix_value = providers.resolve_model(providers.PROVIDER_OPENAI, env)
    post_fix_value = providers.resolve_model(providers.PROVIDER_NVIDIA, env)

    assert pre_fix_value == providers._DEFAULT_MODEL[providers.PROVIDER_OPENAI]
    assert post_fix_value != pre_fix_value, (
        "if these were equal, the model-name control could not distinguish the "
        "correct implementation from the bug it was written for"
    )


def test_the_nvidia_guards_do_not_redirect_an_openai_deployment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The control on the control: fixing NVIDIA must not have broken OpenAI.

    A guard written as "the model is not gpt-4o-mini" would be satisfied by a
    provider table that simply lost its OpenAI entry. So an explicit OpenAI
    deployment must still resolve, and send, exactly what it always did.
    """
    capture = _Capture()
    capture.install(monkeypatch)
    env = {
        "LLM_PROVIDER": "openai",
        "OPENAI_API_KEY": "sk-test",
        "LLM_BASE_URL": "http://ollama:11434/v1",
    }
    client = _client(env)
    client.complete("evidence")

    assert (
        capture.calls[0]["model"] == providers._DEFAULT_MODEL[providers.PROVIDER_OPENAI]
    )
    assert capture.client_kwargs[0]["api_key"] == "sk-test"
    assert capture.client_kwargs[0]["base_url"] == "http://ollama:11434/v1"
    assert client.describe().startswith(providers.PROVIDER_OPENAI)


def test_the_nim_endpoint_carries_the_required_v1_path() -> None:
    """The manifest's endpoint must be the OpenAI-protocol path.

    A bare host 404s on every request. Asserted against the literal because the
    value is duplicated in ``deploy/agent.yaml``, and a drift between the two would
    otherwise only surface as a failed call in a cluster.
    """
    assert NIM_BASE_URL.endswith("/v1")
    assert providers.NVIDIA_BASE_URL.endswith("/v1")
    assert NIM_BASE_URL == providers.NVIDIA_BASE_URL, (
        "deploy/agent.yaml and providers.NVIDIA_BASE_URL disagree; the manifest is "
        "what the pod actually uses"
    )
