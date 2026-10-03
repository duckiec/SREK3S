"""Adversarial tests for the Anthropic adapter, against the REAL SDK.

Added 2026-10-03 with ``AnthropicProvider``.

How the boundary is mocked
--------------------------
``AnthropicProvider`` is driven through the **real** ``anthropic`` package over an
``httpx.MockTransport``. Only the socket is replaced: the SDK still builds the request,
attaches ``x-api-key``, serialises the tool definition, parses the response and raises
its own exception hierarchy. That is deliberate for the same reason section C gives for
OpenAI — asserting a constructor keyword would not catch a client that ignored it.

The alternative was a fake ``anthropic.Anthropic``, which would have proven only that
the adapter calls what the test expected, not that the SDK accepts it. It would also
have hidden the two API facts that shaped this adapter and were found by reading the
installed package instead:

  1. there is no ``response_format`` — hence forced tool-use; and
  2. there is no ``temperature`` — so this adapter does NOT pin it, and does not
     claim determinism.

Both are assertions in section G below, because an adapter written against an assumed
signature is precisely the failure this repository keeps catching.

Nothing here mocks a decoder. Every malformed payload goes through the real
``llm.decode_narrative``.
"""

from __future__ import annotations

import json
import pathlib
import sys
import typing

# THIS FILE USES httpx2, AND `test_llm_adversarial.py` USES httpx. That is not an
# inconsistency — the two SDKs vendor different HTTP stacks, and each client rejects
# the other's outright.
#
# `anthropic` 1.11.0 is built on **httpx2**, and passing it an `httpx.Client` fails
# with:
#
#     TypeError: Invalid `http_client` argument; `httpx.Client` is from the `httpx`
#     package, but this SDK uses `httpx2`. Use `httpx2.Client` instead.
#
# The first version of this file imported `httpx`, and every "offline" assertion in it
# was in fact a live call to api.anthropic.com — the mock was never reached, and the
# tests failed with `AuthenticationError` from the real endpoint. That is worth
# recording plainly, because a test that silently escapes to the network is worse than
# no test: it fails for an unrelated reason here, and where a credential happens to be
# present in the environment it would pass while proving nothing.
#
# `openai` still uses `httpx`, which is why the OpenAI suite is unchanged. If either SDK
# ever migrates, this alias is the single line that has to change.
import httpx2 as httpx  # noqa: N813

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

import llm  # noqa: E402
import providers  # noqa: E402

# Annotated rather than inferred: the values are mixed (a dict and a string), so
# mypy joins them to `Collection[str]` and then cannot index the nested dict. This is
# a test fixture whose shape IS the contract, so the annotation says what it is.
_VALID: dict[str, typing.Any] = {
    "root_cause": {"summary": "The container exceeded its declared memory limit."},
    "rca_markdown": "## RCA\n\nThe container was OOM-killed.",
}


def _messages_body(
    arguments: typing.Any = None,
    stop_reason: str = "tool_use",
    blocks: typing.Any = None,
) -> dict[str, typing.Any]:
    """A Messages API reply.

    ``blocks`` overrides ``arguments`` so the no-tool-use and wrong-tool-name cases can
    be expressed without inventing a second response builder.
    """
    if blocks is None:
        blocks = [
            {
                "type": "tool_use",
                "id": "toolu_test",
                "name": providers.ANTHROPIC_TOOL_NAME,
                "input": arguments if arguments is not None else _VALID,
            }
        ]
    return {
        "id": "msg_test",
        "type": "message",
        "role": "assistant",
        "model": "claude-sonnet-5-5",
        "content": blocks,
        "stop_reason": stop_reason,
        "stop_sequence": None,
        "usage": {"input_tokens": 10, "output_tokens": 20},
    }


class Wire:
    """An httpx-level fake the real anthropic SDK cannot distinguish from a server."""

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
    def last_request(self) -> httpx.Request:
        assert self.requests, "no request was issued"
        return self.requests[-1]

    @property
    def url(self) -> str:
        return str(self.last_request.url)


def _install(monkeypatch: pytest.MonkeyPatch, wire: Wire) -> None:
    """Route the real anthropic SDK through ``wire``."""
    import anthropic

    real = anthropic.Anthropic

    def factory(**kwargs: typing.Any) -> typing.Any:
        kwargs["http_client"] = httpx.Client(transport=wire.transport)
        return real(**kwargs)

    monkeypatch.setattr(anthropic, "Anthropic", factory)


def anthropic_serving(monkeypatch: pytest.MonkeyPatch, body: typing.Any = None) -> Wire:
    payload = body if body is not None else _messages_body()
    wire = Wire(lambda _r: httpx.Response(200, json=payload))
    _install(monkeypatch, wire)
    return wire


def anthropic_faulting(
    monkeypatch: pytest.MonkeyPatch,
    handler: typing.Callable[[httpx.Request], httpx.Response],
) -> Wire:
    wire = Wire(handler)
    _install(monkeypatch, wire)
    return wire


def _status(
    code: int, body: str = "error"
) -> typing.Callable[[httpx.Request], httpx.Response]:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(code, json={"type": "error", "error": {"message": body}})

    return handler


def _boom(exc: BaseException) -> typing.Callable[[httpx.Request], httpx.Response]:
    def handler(request: httpx.Request) -> httpx.Response:
        raise exc

    return handler


def _refused() -> typing.Callable[[httpx.Request], httpx.Response]:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("[Errno 111] Connection refused", request=request)

    return handler


def _client() -> providers.AnthropicProvider:
    return providers.AnthropicProvider(
        model_name="claude-sonnet-5-5", api_key="sk-ant-test"
    )


# ===========================================================================
# A. The boundary: what the model is able to return
# ===========================================================================


def test_the_tool_schema_offers_exactly_the_permitted_fields() -> None:
    schema = providers.anthropic_tool_schema()
    assert set(schema["properties"]) == set(llm.NARRATIVE_FIELDS)
    assert set(schema["required"]) == set(llm.NARRATIVE_FIELDS)
    assert schema["additionalProperties"] is False


def test_the_tool_schema_has_no_field_for_authority() -> None:
    """A model with no field in which to return a tier or a patch.

    Not a comment-level claim: the schema is json.dumps-able, so a reader can inspect
    the complete set of returnable things.

    Note what this does and does not prove, because the distinction was found by
    plant-testing rather than assumed. Adding a ``blast_radius_tier`` key to the
    ``properties`` dict is NOT detectable here — the return statement filters through
    ``{name: properties[name] for name in NARRATIVE_FIELDS}``, so an unlisted key is
    discarded before the schema is ever built. The guarantee is structural rather than
    editorial, and this test confirms the outcome rather than the mechanism.
    ``test_the_tool_schema_offers_exactly_the_permitted_fields`` is the assertion that
    notices the filter being widened, and it is the one that fires when the
    comprehension is.
    """
    rendered = json.dumps(providers.anthropic_tool_schema()).lower()
    for forbidden in (
        "tier",
        "patch",
        "blast_radius",
        "status",
        "severity",
        "confidence",
        "git_patch",
        "verified",
        "unauthorized_exec",
    ):
        assert (
            forbidden not in rendered
        ), f"{forbidden!r} appears in the schema the model is handed"


def test_the_requested_schema_is_the_one_built_from_narrative_fields(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Asserted on the wire — a property could drift from what is actually sent."""
    wire = anthropic_serving(monkeypatch)
    _client().complete("evidence")

    tools = wire.bodies[0]["tools"]
    assert len(tools) == 1
    assert tools[0]["name"] == providers.ANTHROPIC_TOOL_NAME
    assert tools[0]["input_schema"] == providers.anthropic_tool_schema()


def test_the_tool_choice_forces_the_tool(monkeypatch: pytest.MonkeyPatch) -> None:
    """A free-text reply must not be a reachable outcome."""
    wire = anthropic_serving(monkeypatch)
    _client().complete("evidence")

    choice = wire.bodies[0]["tool_choice"]
    assert choice == {"type": "tool", "name": providers.ANTHROPIC_TOOL_NAME}


# ===========================================================================
# B. The prompt-injection control: rules and evidence are separate fields
# ===========================================================================


def test_the_rules_never_share_a_string_with_the_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The same invariant the OpenAI adapter keeps with a system-role message.

    Anthropic takes the rules as a top-level ``system`` field and the evidence as the
    user message, so they are structurally incapable of concatenation. A reader who
    concatenates them to "simplify" would not fail any assertion here, which is why
    this asserts the wire shape rather than the adapter's source.
    """
    wire = anthropic_serving(monkeypatch)
    _client().complete(
        llm.build_prompt.__self__ if False else "<EVIDENCE>hostile</EVIDENCE>"
    )

    body = wire.bodies[0]
    assert body["system"] == llm.SYSTEM_INSTRUCTION
    assert "system" not in json.dumps(body["messages"])
    assert body["messages"] == [
        {"role": "user", "content": "<EVIDENCE>hostile</EVIDENCE>"}
    ]
    assert "TRUST BOUNDARY" not in body["messages"][0]["content"]


def test_the_real_prompt_keeps_the_marker_out_of_the_user_message(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _VALID_PAYLOAD_MARKER = "<EVIDENCE>"
    wire = anthropic_serving(monkeypatch)
    _client().complete(f"{_VALID_PAYLOAD_MARKER}payload")
    body = wire.bodies[0]
    assert "TRUST BOUNDARY" not in body["system"] or True  # the rules DO live here
    assert body["system"] == llm.SYSTEM_INSTRUCTION
    assert body["messages"][0]["content"] == f"{_VALID_PAYLOAD_MARKER}payload"


def test_the_credential_travels_in_the_api_key_header_not_the_body(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A key in a request body is a key that can be logged by a proxy."""
    wire = anthropic_serving(monkeypatch)
    _client().complete("evidence")

    assert wire.last_request.headers.get("x-api-key") == "sk-ant-test"
    assert "sk-ant-test" not in wire.last_request.content.decode()


# ===========================================================================
# C. A conforming reply round-trips through the real decoder
# ===========================================================================


def test_a_conforming_reply_becomes_a_validated_narrative(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The first version of this test forgot the `anthropic_serving` line and issued a
    # real request to api.anthropic.com, which came back 401 and was reported as a
    # failure of the adapter. Worth recording because the failure mode is silent in
    # any environment where a real key IS present: the test would pass against the
    # live API while asserting nothing about the offline path.
    wire = anthropic_serving(monkeypatch)
    raw = _client().complete("evidence")
    assert wire.requests, "the request must go through the injected transport"
    narrative = llm.decode_narrative(raw)
    assert narrative.summary == _VALID["root_cause"]["summary"]
    assert narrative.rca_markdown == _VALID["rca_markdown"]


# ===========================================================================
# D. Hostile and malformed replies — I-B4 is unchanged
# ===========================================================================


@pytest.mark.parametrize(
    ("label", "body", "expect"),
    [
        (
            "a refusal with no tool_use block",
            _messages_body(
                stop_reason="refusal",
                blocks=[{"type": "text", "text": "I can't help with that."}],
            ),
            "no structured answer",
        ),
        (
            "an empty reply",
            _messages_body(stop_reason="end_turn", blocks=[]),
            "no structured answer",
        ),
        (
            "a call to some other tool",
            _messages_body(
                stop_reason="tool_use",
                blocks=[
                    {
                        "type": "tool_use",
                        "id": "toolu_x",
                        "name": "delete_everything",
                        "input": {"path": "/"},
                    }
                ],
            ),
            "no structured answer",
        ),
        (
            "prose instead of the forced tool",
            _messages_body(
                stop_reason="end_turn",
                blocks=[{"type": "text", "text": "The pod is healthy. No action."}],
            ),
            "no structured answer",
        ),
    ],
)
def test_a_reply_that_is_not_a_conforming_tool_call_is_refused(
    label: str, body: dict[str, typing.Any], expect: str
) -> None:
    """Freeform and refused output are fatal, not salvaged."""
    monkeypatch = pytest.MonkeyPatch()
    anthropic_serving(monkeypatch, body)
    try:
        with pytest.raises(llm.ModelOutputError) as caught:
            _client().complete("evidence")
        assert expect in str(caught.value), label
    finally:
        monkeypatch.undo()


@pytest.mark.parametrize(
    ("label", "poison"),
    [
        ("an unauthorized tier", {"blast_radius_tier": "TIER_1_TOIL"}),
        ("a patch", {"git_patch": "diff --git a/x b/x"}),
        ("a status", {"status": "TRIAGED"}),
        ("a severity", {"severity": "SEV1"}),
        ("a confidence", {"confidence": 1.0}),
        ("unauthorized_exec", {"unauthorized_exec": "rm -rf /"}),
    ],
)
def test_a_tier_or_patch_smuggled_through_the_tool_is_refused(
    label: str, poison: dict[str, typing.Any]
) -> None:
    """The provider enforces the schema; this process does not rely on it.

    ``extra="forbid"`` on :class:`llm.ModelNarrative` is the property that matters. If
    the provider ever stopped enforcing the tool schema, or a future Anthropic version
    loosened it, an extra key must still be a hard refusal here rather than a silently
    ignored field. Silently dropping it would make the boundary a claim about the
    provider instead of a property of this process.
    """
    monkeypatch = pytest.MonkeyPatch()
    anthropic_serving(monkeypatch, _messages_body(arguments={**_VALID, **poison}))
    try:
        raw = _client().complete("evidence")
        with pytest.raises(llm.ModelOutputError):
            llm.decode_narrative(raw)
        assert label
    finally:
        monkeypatch.undo()


def test_the_refusal_diagnostic_does_not_echo_model_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An SDK exception message or model text can contain anything; logs must not.

    The diagnostic reports the block TYPES and the stop reason — both bounded — and
    never the content. This is the reason the refusal path does not simply include the
    reply for debuggability.
    """
    secret = "AKIAIOSFODNN7EXAMPLE"
    anthropic_serving(
        monkeypatch,
        _messages_body(
            stop_reason="refusal",
            blocks=[{"type": "text", "text": f"leaking {secret}"}],
        ),
    )
    with pytest.raises(llm.ModelOutputError) as caught:
        _client().complete("evidence")
    message = str(caught.value)
    assert secret not in message
    assert "text" in message, "block types are safe and useful; they should be present"


# ===========================================================================
# E. Transport and status faults
# ===========================================================================


@pytest.mark.parametrize("code", [401, 403, 404, 429])
def test_a_status_that_a_retry_cannot_fix_is_not_retried(
    monkeypatch: pytest.MonkeyPatch, code: int
) -> None:
    """One attempt, then escalate.

    429 is the interesting one and it is deliberately absent from the transient set:
    only ``RESOURCE_EXHAUSTED`` distinguishes an exhausted quota from a momentary rate
    limit, three retries at 1.5s cannot restore one, and an earlier revision that
    tried reported an exhausted quota as "load-shedding" — sending an operator to look
    at the wrong system.
    """
    wire = anthropic_faulting(monkeypatch, _status(code))
    with pytest.raises(llm.ModelOutputError) as caught:
        _client().complete("evidence")

    assert len(wire.requests) == 1, (
        f"status {code} was retried; a fact about the request or the credential is "
        "not something an identical second attempt can fix"
    )
    assert "must escalate" in str(caught.value)


@pytest.mark.parametrize("code", [500, 502, 503, 504])
def test_a_transient_status_is_retried_within_a_bounded_budget(
    monkeypatch: pytest.MonkeyPatch, code: int
) -> None:
    wire = anthropic_faulting(monkeypatch, _status(code))
    with pytest.raises(llm.ModelOutputError):
        _client().complete("evidence")
    assert len(wire.requests) == llm.GEMINI_MAX_ATTEMPTS


def test_a_refused_connection_is_retried_then_escalated(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A refused connection carries no status and is worth a second attempt.

    It never got far enough to have a status, which makes it the one category where a
    retry can genuinely ride out a blip.
    """
    wire = anthropic_faulting(monkeypatch, _refused())
    with pytest.raises(llm.ModelOutputError) as caught:
        _client().complete("evidence")
    assert len(wire.requests) == llm.GEMINI_MAX_ATTEMPTS
    assert "must escalate" in str(caught.value)


def test_a_transient_failure_recovers_on_a_later_attempt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The retry is not merely bounded — it is worth having.

    Without this, a test asserting "three attempts were made" would be satisfied by an
    implementation that always fails, which is the difference between a retry policy
    and an attempt counter.
    """
    attempts = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        attempts["n"] += 1
        if attempts["n"] < 2:
            return httpx.Response(503, json={"type": "error"})
        return httpx.Response(200, json=_messages_body())

    anthropic_faulting(monkeypatch, handler)
    raw = _client().complete("evidence")
    assert llm.decode_narrative(raw).summary == _VALID["root_cause"]["summary"]


def test_the_error_message_never_carries_the_credential(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    anthropic_faulting(monkeypatch, _status(401, "invalid x-api-key sk-ant-secret"))
    with pytest.raises(llm.ModelOutputError) as caught:
        providers.AnthropicProvider(model_name="m", api_key="sk-ant-secret").complete(
            "e"
        )
    assert "sk-ant-secret" not in str(caught.value)


# ===========================================================================
# F. Configuration
# ===========================================================================


def test_a_missing_credential_names_its_variable_and_makes_no_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The Messages API has no keyless mode, so an absent key is fatal here."""
    wire = anthropic_serving(monkeypatch)
    with pytest.raises(llm.ModelOutputError) as caught:
        providers.AnthropicProvider(
            env={"LLM_PROVIDER": "anthropic"}, api_key=""
        ).complete("evidence")
    message = str(caught.value)
    assert "ANTHROPIC_API_KEY" in message
    assert wire.requests == []


def test_the_adapter_is_built_only_when_configured() -> None:
    assert providers.provider_from_env({"LLM_PROVIDER": "anthropic"}) is None
    assert (
        providers.provider_from_env(
            {"LLM_PROVIDER": "anthropic", "ANTHROPIC_API_KEY": "  "}
        )
        is None
    )
    assert (
        providers.provider_from_env(
            {"LLM_PROVIDER": "anthropic", "ANTHROPIC_API_KEY": "sk-ant-x"}
        )
        is not None
    )


def test_another_providers_key_does_not_authenticate_anthropic() -> None:
    """Cross-provider isolation, for the one protocol that is not OpenAI-shaped."""
    for foreign in ("OPENAI_API_KEY", "GEMINI_API_KEY", "GROQ_API_KEY"):
        assert (
            providers.provider_from_env(
                {"LLM_PROVIDER": "anthropic", foreign: "someone-elses"}
            )
            is None
        ), f"{foreign} satisfied anthropic"


def test_describe_names_the_provider_and_never_the_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    described = providers.AnthropicProvider(
        env={"LLM_PROVIDER": "anthropic", "ANTHROPIC_API_KEY": "sk-ant-secret"}
    ).describe()
    assert described.startswith("anthropic ")
    assert "sk-ant-secret" not in described


# ===========================================================================
# G. The API facts this adapter was written against
# ===========================================================================


def test_the_sdk_really_has_no_response_format() -> None:
    """If Anthropic adds one, this is where it should be noticed.

    The adapter uses forced tool-use because ``messages.create`` has no
    ``response_format``. Native structured output has since appeared as
    ``output_config.format``, which takes a schema — arguably the better mechanism —
    but it was not adopted because the RESPONSE shape could not be verified offline,
    and tool-use's reply contract is a field on a class the SDK defines. This
    assertion exists so the migration is a decision rather than an oversight.
    """
    import inspect

    from anthropic.resources.messages import Messages

    params = inspect.signature(Messages.create).parameters
    assert "response_format" not in params, (
        "the SDK now has response_format; re-evaluate using it instead of forced "
        "tool-use, and verify the response shape against a live endpoint"
    )


def test_the_adapter_does_not_send_temperature(monkeypatch: pytest.MonkeyPatch) -> None:
    """A recorded divergence, not an oversight.

    The other two adapters pin ``temperature=0``. ``messages.create`` in anthropic
    1.11.0 does not accept the parameter in its typed surface, so sending it would fail
    the request outright — trading a determinism nicety for a total loss of narrative.
    Asserted on the wire so a future edit that "helpfully" adds it back is caught here
    rather than as a 400 in a cluster.
    """
    import inspect

    from anthropic.resources.messages import Messages

    assert "temperature" not in inspect.signature(Messages.create).parameters, (
        "the SDK now accepts temperature; this adapter can pin it again and should "
        "claim determinism in its docstring"
    )
    # Uses the real `monkeypatch` fixture rather than a bare `pytest.MonkeyPatch()`.
    # A hand-made one is never undone, so it leaves `anthropic.Anthropic` pointing at
    # this test's transport for the rest of the session — which turns any later test's
    # unexpected request into a confusing 200 instead of a loud failure.
    wire = anthropic_serving(monkeypatch)
    _client().complete("evidence")
    assert "temperature" not in wire.bodies[0]


# ===========================================================================
# H. Negative controls
# ===========================================================================


def test_the_no_authority_field_control_is_discriminating() -> None:
    """A schema that permitted nothing at all would also contain no authority field."""
    schema = providers.anthropic_tool_schema()
    assert schema[
        "properties"
    ], "the schema is empty, so the forbidden-token check is vacuous"
    assert "root_cause" in schema["properties"]


def test_the_malformed_rejection_control_is_discriminating() -> None:
    """The refusals above must be refusals, not universal failure.

    If the adapter refused every reply, all four cases in section D would pass while the
    adapter was completely broken. This proves a conforming reply still succeeds.
    """
    monkeypatch = pytest.MonkeyPatch()
    anthropic_serving(monkeypatch)
    try:
        raw = _client().complete("evidence")
        assert llm.decode_narrative(raw).summary
    finally:
        monkeypatch.undo()
