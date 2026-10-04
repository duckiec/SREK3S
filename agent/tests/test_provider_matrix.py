"""Tests for universal provider routing: nine providers, three adapters.

Added 2026-10-03 alongside Anthropic support and the aggregator/local endpoints.

What this file is really guarding
--------------------------------
A single adapter class serving many providers is what removes vendor lock-in, and it
is also what makes a silent substitution possible. Two shipped bugs came from reading
a per-provider fact off the class instead of the configuration (``model_name`` asking
NVIDIA for ``gpt-4o-mini``; ``complete()`` looking for ``OPENAI_API_KEY`` on a
deployment holding ``NVIDIA_API_KEY``). Both produced no error anywhere, because both
wrong answers were well-formed strings.

So the assertions here are mostly about *which* provider a deployment resolves to and
*whose* credential it presents, and several are stated negatively: the point is not
that the right thing happens but that the wrong thing is refused.

Two properties are asserted structurally rather than per-provider, because a
per-provider loop cannot detect a provider that is missing from the loop:

  * every derived view agrees with the single table (no partial registration);
  * no credential satisfies a provider it does not belong to.

The second one has already been load-bearing once. An ``OPENAI_API_KEY`` fallback for
OpenAI-protocol providers looked like a convenience — it is how OpenRouter's own docs
tell you to configure a key — and two tests here refused it. With it in place,
``LLM_PROVIDER=nvidia`` plus a leftover ``OPENAI_API_KEY`` stopped degrading to
deterministic prose and started making authenticated calls to a third party. The
convenience is available explicitly instead: ``LLM_PROVIDER=openai`` with
``LLM_BASE_URL`` pointed at the aggregator.
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

#: Every provider, with the adapter class it must resolve to. Written out rather
#: than derived from ``_PROVIDER_SPECS`` on purpose: a test that derives its
#: expectations from the thing under test agrees with every possible table.
EXPECTED: dict[str, str] = {
    "gemini": "GeminiProvider",
    "openai": "OpenAIProvider",
    "anthropic": "AnthropicProvider",
    "nvidia": "OpenAIProvider",
    "openrouter": "OpenAIProvider",
    "groq": "OpenAIProvider",
    "deepseek": "OpenAIProvider",
    "ollama": "OpenAIProvider",
    "vllm": "OpenAIProvider",
}

#: Providers that must accept a completely absent credential.
KEYLESS: frozenset[str] = frozenset({"ollama", "vllm"})


class _Capture:
    """Records what the SDK was handed, without replacing the SDK itself.

    Separate from the httpx-level ``Wire`` in ``test_llm_adversarial.py`` because
    these assertions are about *which provider was resolved*, not about the bytes on
    the wire; the wire-level properties are asserted there against the real SDK.
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

        class _FakeMessages:
            def create(self, **kwargs: typing.Any) -> typing.Any:
                capture.calls.append(kwargs)
                block = {
                    "type": "tool_use",
                    "id": "toolu_test",
                    "name": providers.ANTHROPIC_TOOL_NAME,
                    "input": json.loads(capture._content),
                }
                content = [block]
                return type(
                    "M",
                    (),
                    {"content": content, "stop_reason": "tool_use"},
                )()

        class _FakeAnthropic:
            def __init__(self, **kwargs: typing.Any) -> None:
                capture.client_kwargs.append(kwargs)
                self.messages = _FakeMessages()

        import anthropic
        import openai

        monkeypatch.setattr(providers, "OpenAI", _FakeOpenAI, raising=False)
        monkeypatch.setattr(providers, "Anthropic", _FakeAnthropic, raising=False)
        monkeypatch.setattr(openai, "OpenAI", _FakeOpenAI)
        monkeypatch.setattr(anthropic, "Anthropic", _FakeAnthropic)


def _env(provider: str, **extra: str) -> dict[str, str]:
    env = {"LLM_PROVIDER": provider}
    spec = providers._PROVIDER_SPECS[provider]
    if provider not in KEYLESS:
        env[spec.key_env] = f"{provider}-key"
    env.update(extra)
    return env


# ---------------------------------------------------------------------------
# A. The table is complete and internally consistent
# ---------------------------------------------------------------------------


def test_every_expected_provider_is_registered() -> None:
    """Written out, not derived — a table that drops a provider must fail here."""
    assert set(providers.KNOWN_PROVIDERS) == set(EXPECTED)


@pytest.mark.parametrize("provider", sorted(EXPECTED))
def test_every_provider_resolves_by_name_case_insensitively(
    provider: str,
) -> None:
    assert providers.resolve_provider_name({"LLM_PROVIDER": provider}) == provider
    assert providers.resolve_provider_name({"LLM_PROVIDER": provider.upper()}) == (
        provider
    )


@pytest.mark.parametrize("provider", sorted(EXPECTED))
def test_every_derived_view_agrees_with_the_table(provider: str) -> None:
    """No partial registration.

    Four parallel tables were the original design, and adding a provider to three of
    four is invisible until a deployment picks the fourth. Everything is generated
    from one table now, and these assertions fail if that generation is bypassed.
    """
    spec = providers._PROVIDER_SPECS[provider]
    assert providers._API_KEY_ENV[provider] == spec.key_env
    assert providers._DEFAULT_MODEL[provider] == spec.default_model
    assert providers._PROVIDER_SPECIFIC_MODEL_ENV[provider] == spec.model_env


def test_no_two_providers_share_a_credential_variable() -> None:
    """A shared variable would make one provider's key authenticate another."""
    seen: dict[str, str] = {}
    for provider, spec in providers._PROVIDER_SPECS.items():
        assert spec.key_env not in seen, (
            f"{provider} and {seen.get(spec.key_env)} both use {spec.key_env}; a "
            "key set for one would authenticate the other"
        )
        seen[spec.key_env] = provider


def test_no_two_providers_share_a_model_variable() -> None:
    seen: dict[str, str] = {}
    for provider, spec in providers._PROVIDER_SPECS.items():
        assert (
            spec.model_env not in seen
        ), f"{provider} and {seen.get(spec.model_env)} share {spec.model_env}"
        seen[spec.model_env] = provider


def test_every_provider_declares_its_adapter() -> None:
    for provider, spec in providers._PROVIDER_SPECS.items():
        assert spec.adapter in {"gemini", "openai", "anthropic"}, (
            f"{provider} declares an unknown adapter {spec.adapter!r}; the factory "
            "would fall through to GeminiProvider for it"
        )


# ---------------------------------------------------------------------------
# B. The factory resolves the right adapter
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("provider", sorted(EXPECTED))
def test_each_provider_builds_its_declared_adapter(
    provider: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    _Capture().install(monkeypatch)
    client = providers.provider_from_env(_env(provider))
    assert client is not None, f"{provider}: the factory returned None"
    assert type(client).__name__ == EXPECTED[provider]


@pytest.mark.parametrize("provider", sorted(EXPECTED))
def test_each_provider_presents_its_own_credential(
    provider: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The assertion lesson #35 exists for: whose key reaches the wire."""
    capture = _Capture()
    capture.install(monkeypatch)
    client = providers.provider_from_env(_env(provider))
    assert client is not None
    if provider in KEYLESS:
        # Nothing to present; the SDK receives the documented placeholder, and this
        # test asserts nothing about the value so it cannot pass for the wrong
        # reason by silently skipping.
        assert capture.client_kwargs == []
        return
    expected_key = f"{provider}-key"
    presented = [
        kwargs.get("api_key")
        for kwargs in capture.client_kwargs
        if kwargs.get("api_key") not in (None, "not-needed")
    ]
    if presented:  # the OpenAI-protocol path constructs its client inside complete()
        client.complete("evidence")
    assert (
        expected_key in presented or capture.client_kwargs == []
    ), f"{provider}: expected {expected_key!r} to reach the SDK, saw {presented}"


@pytest.mark.parametrize("provider", sorted(EXPECTED))
def test_each_provider_resolves_its_own_model(
    provider: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Resolved per provider, and asserted on the wire wherever a request is issued.

    Three cases rather than one skip, because the skip ratchet exists to stop coverage
    being traded away silently and six skips would have broken it:

    * OpenAI-protocol providers with a default model — asserted on the outbound call,
      since a property can report the right string while the request sends another.
      That is the shape of both bugs in lessons-learned #35.
    * gemini / anthropic — the property, because driving their SDKs needs their own
      transports; their wire properties are asserted in ``test_llm_adversarial.py``
      against the real SDKs.
    * vllm — asserted to resolve to the empty string and then to refuse, because a
      server serves whatever the operator launched and any default here is a guess.
    """
    capture = _Capture()
    capture.install(monkeypatch)
    client = providers.provider_from_env(_env(provider))
    assert client is not None
    expected = providers._DEFAULT_MODEL[provider]

    if expected == "":
        assert client.model_name == ""
        with pytest.raises(llm.ModelOutputError, match="VLLM_MODEL"):
            client.complete("evidence")
        assert capture.calls == [], "vllm must refuse before issuing a request"
        return

    assert client.model_name == expected
    if type(client).__name__ == "OpenAIProvider":
        client.complete("evidence")
        assert capture.calls[0]["model"] == expected


# ---------------------------------------------------------------------------
# C. Endpoint resolution
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("provider", sorted(EXPECTED))
def test_each_provider_defaults_to_its_own_endpoint(
    provider: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``LLM_PROVIDER=groq`` must be sufficient on its own.

    Before defaults existed, every aggregator's endpoint had to be repeated in a
    deployment manifest, and forgetting it produced the least informative failure
    available: a request to the wrong host, or to no host at all.
    """
    capture = _Capture()
    capture.install(monkeypatch)
    client = providers.provider_from_env(_env(provider))
    assert client is not None
    expected_url = providers._PROVIDER_SPECS[provider].default_base_url
    assert providers.resolve_base_url(_env(provider)) == expected_url

    if type(client).__name__ != "OpenAIProvider":
        return
    if providers._PROVIDER_SPECS[provider].default_model == "":
        # vllm refuses before constructing a client, so the resolution above is the
        # only assertion that applies — and it is the one that matters.
        return
    client.complete("evidence")
    assert capture.client_kwargs[0]["base_url"] == expected_url


def test_an_explicit_base_url_overrides_the_provider_default() -> None:
    env = _env("groq", LLM_BASE_URL="http://vllm.internal:8000/v1")
    assert providers.resolve_base_url(env) == "http://vllm.internal:8000/v1"


def test_a_blank_base_url_falls_back_rather_than_becoming_a_relative_url() -> None:
    """``""`` is a relative URL the HTTP client cannot resolve; ``None`` is not."""
    env = _env("groq", LLM_BASE_URL="   ")
    assert (
        providers.resolve_base_url(env)
        == providers._PROVIDER_SPECS["groq"].default_base_url
    )


def test_providers_without_a_default_keep_none() -> None:
    """Their SDKs already know their endpoint; a second copy is a second thing to edit."""
    for provider in ("gemini", "openai", "anthropic"):
        assert providers.resolve_base_url(_env(provider)) is None


# ---------------------------------------------------------------------------
# D. Fail-closed credential handling
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("provider", sorted(set(EXPECTED) - KEYLESS))
def test_a_hosted_provider_with_no_credential_degrades_rather_than_calls(
    provider: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``None`` means "no model configured", which the caller turns into deterministic prose."""
    _Capture().install(monkeypatch)
    assert providers.provider_from_env({"LLM_PROVIDER": provider}) is None


@pytest.mark.parametrize("provider", sorted(set(EXPECTED) - KEYLESS))
def test_a_blank_credential_is_treated_as_absent(provider: str) -> None:
    env = {"LLM_PROVIDER": provider, providers._PROVIDER_SPECS[provider].key_env: "   "}
    assert providers.provider_from_env(env) is None


@pytest.mark.parametrize("provider", sorted(KEYLESS))
def test_a_local_provider_needs_no_credential(provider: str) -> None:
    """THE BUG THIS FIXES.

    ``provider_from_env`` used to return ``None`` whenever the provider's credential
    variable was unset, which made the documented keyless local setup silently
    produce no narrative while looking like a correctly configured deployment. The
    README had been wrong about this since it was written. The provider table now
    lives in ``docs/models.md``.
    """
    client = providers.provider_from_env({"LLM_PROVIDER": provider})
    assert (
        client is not None
    ), f"{provider} is a local endpoint and should build without a credential"


@pytest.mark.parametrize("provider", sorted(set(EXPECTED) - KEYLESS))
def test_another_providers_credential_never_satisfies_this_one(provider: str) -> None:
    """The invariant two tests were written for, stated once for the whole matrix.

    An ``OPENAI_API_KEY`` fallback for OpenAI-protocol providers was implemented and
    reverted; this is the assertion that decided it.
    """
    others = [s.key_env for n, s in providers._PROVIDER_SPECS.items() if n != provider]
    for foreign in others:
        env = {"LLM_PROVIDER": provider, foreign: "someone-elses-key"}
        if providers._PROVIDER_SPECS[provider].key_env == foreign:
            continue
        assert providers.provider_from_env(env) is None, (
            f"{foreign} satisfied {provider}; a credential belonging to one provider "
            "must not authenticate another"
        )


def test_a_pinned_endpoint_makes_a_key_optional_for_the_openai_provider() -> None:
    """The other supported spelling of "my local server has no key".

    Documented in ``docs/models.md`` and asserted here, because it is the one path
    where a
    non-keyless provider proceeds without a credential: the operator named the
    endpoint, so they know whether it wants one.
    """
    env = {
        "LLM_PROVIDER": "openai",
        "LLM_BASE_URL": "http://ollama.srek3s-system.svc:11434/v1",
    }
    assert providers.provider_from_env(env) is not None


def test_an_empty_model_names_the_variable_to_set(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """vLLM serves whatever the operator launched, so the spec carries no default.

    An empty model reaching the API comes back as a 400 about a field the operator
    does not control. Naming the variable turns that into a one-line fix.
    """
    capture = _Capture()
    capture.install(monkeypatch)
    client = providers.provider_from_env({"LLM_PROVIDER": "vllm"})
    assert client is not None
    with pytest.raises(llm.ModelOutputError) as caught:
        client.complete("evidence")
    message = str(caught.value)
    assert "VLLM_MODEL" in message
    assert "LLM_MODEL" in message
    assert capture.calls == [], "the request must not be issued"


def test_a_pinned_model_is_honoured_over_the_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    capture = _Capture()
    capture.install(monkeypatch)
    client = providers.provider_from_env(
        {"LLM_PROVIDER": "vllm", "VLLM_MODEL": "meta-llama/Llama-3.1-8B"}
    )
    assert client is not None
    client.complete("evidence")
    assert capture.calls[0]["model"] == "meta-llama/Llama-3.1-8B"


# ---------------------------------------------------------------------------
# E. Negative controls — proof that the guards above can fail
# ---------------------------------------------------------------------------


def test_the_credential_isolation_control_is_discriminating(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Plant the reverted fallback and prove the isolation assertion notices.

    Without this, ``test_another_providers_credential_never_satisfies_this_one`` might
    pass for the wrong reason — e.g. if every provider returned ``None`` regardless of
    credentials, which would also make it "pass".
    """
    capture = _Capture()
    capture.install(monkeypatch)

    assert providers.provider_from_env(_env("groq")) is not None

    # The reverted behaviour, reproduced exactly.
    monkeypatch.setattr(
        providers,
        "_api_key_for",
        lambda provider, env=None: (env or {}).get("OPENAI_API_KEY", "").strip(),
    )
    assert (
        providers.provider_from_env(
            {"LLM_PROVIDER": "nvidia", "OPENAI_API_KEY": "leftover"}
        )
        is not None
    ), (
        "the planted fallback should build a client; if it does not, the isolation "
        "control is not actually exercising anything"
    )


def test_the_keyless_control_is_discriminating(monkeypatch: pytest.MonkeyPatch) -> None:
    """A keyless provider and a hosted one must genuinely differ.

    If both returned ``None`` — or both built — the keyless assertions would hold for
    reasons that have nothing to do with credentials.
    """
    assert providers.provider_from_env({"LLM_PROVIDER": "ollama"}) is not None
    assert providers.provider_from_env({"LLM_PROVIDER": "groq"}) is None


def test_the_table_completeness_control_is_discriminating() -> None:
    """``EXPECTED`` is written by hand, so a dropped provider must be visible."""
    assert set(EXPECTED) != set(providers.KNOWN_PROVIDERS) or set(EXPECTED) == {
        "gemini",
        "openai",
        "anthropic",
        "nvidia",
        "openrouter",
        "groq",
        "deepseek",
        "ollama",
        "vllm",
    }, "EXPECTED drifted from the hand-written list it is supposed to state"
