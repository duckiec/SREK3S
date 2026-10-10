"""The per-incident model-time ceiling, and the arithmetic that enforces it.

## The defect this pins

``perIncidentTimeout`` on the Sentinel side is 135s. The agent had no ceiling of
its own on model time. Each adapter set a deadline of ``LLM_TIMEOUT_SECONDS`` (60s)
*per call* and gave **every attempt inside that call the full 60s**, so the
deadline check could only refuse a further retry — it could never shorten the
attempt already in flight. The Tier-2 path calls the model twice
(``_model_summary`` then ``_model_rca_section``, each via ``_narrative_overlay``),
so one incident could spend far more than the Sentinel was willing to wait for it.

The measured consequence, from the pass that found it: a provider slow enough to
fail once produced four POSTs that arrived unanswered, the pool saturated at
``max_active=4``, and further requests were refused with 429. One slow provider on
one pod degraded the whole service.

## What is asserted here

The ceiling is arithmetic, not a hope:

* a per-call budget that is an equal share of the per-incident one, so N calls sum
  to the budget by construction;
* a per-attempt timeout that is the *remaining* budget, so retries cannot extend a
  call past its own deadline.

The wall-clock test drives all three adapters through the worst case the retry
loop permits, on a virtual clock, and asserts the total. A virtual clock is not a
weakening: the code under test is doing real arithmetic on real deadlines, and the
alternative - actually sleeping - would make a unit test take two minutes.
"""

from __future__ import annotations

import ast
import pathlib
import time
import typing

import pytest

import llm
import providers
from test_providers import payload as _payload

#: What the Sentinel waits for one incident. Anything at or below this is safe for
#: the agent to spend on the model alone; the rest is telemetry and serialisation.
SENTINEL_PER_INCIDENT_TIMEOUT_SECONDS = 135

#: The ceiling this test enforces, from the remediation: strictly under 120s.
REQUIRED_CEILING_SECONDS = 120

TRIAGE_SOURCE = pathlib.Path(__file__).resolve().parent.parent / "triage.py"


# --------------------------------------------------------------------------
# A clock that only moves when the code under test says time passed.
# --------------------------------------------------------------------------


class VirtualClock:
    def __init__(self) -> None:
        self.now = 10_000.0
        self.sleeps: list[float] = []

    def perf_counter(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds

    def install(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(time, "perf_counter", self.perf_counter)
        monkeypatch.setattr(time, "sleep", self.sleep)

    @property
    def elapsed(self) -> float:
        return self.now - 10_000.0


# --------------------------------------------------------------------------
# The arithmetic.
# --------------------------------------------------------------------------


def test_two_calls_stay_under_the_ceiling() -> None:
    """The budget must hold by construction, not by the retry loop behaving.

    If ``MODEL_CALLS_PER_INCIDENT`` calls each get an equal share of the incident
    budget, the sum is the budget regardless of how any single call is spent. This
    is the property the remediation relies on, so it is stated as a property of the
    constants rather than of a run.
    """
    per_call = llm.model_call_budget_seconds()
    total = llm.MODEL_CALLS_PER_INCIDENT * per_call
    assert total <= REQUIRED_CEILING_SECONDS, (
        f"{llm.MODEL_CALLS_PER_INCIDENT} calls x {per_call:g}s = {total:g}s, which "
        f"exceeds the {REQUIRED_CEILING_SECONDS}s ceiling"
    )
    assert total <= SENTINEL_PER_INCIDENT_TIMEOUT_SECONDS
    # The remainder is the Sentinel's own telemetry, serialisation and response
    # path. If this closes, one incident's model time is the whole budget.
    assert (
        SENTINEL_PER_INCIDENT_TIMEOUT_SECONDS - llm.INCIDENT_MODEL_BUDGET_SECONDS >= 20
    ), f"{llm.INCIDENT_MODEL_BUDGET_SECONDS}s of model time leaves the Sentinel "
    "under 20s to serialise and respond within its own "
    f"{SENTINEL_PER_INCIDENT_TIMEOUT_SECONDS}s"


def test_the_per_attempt_timeout_is_the_remaining_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The defect in one assertion: attempt 2 is not handed attempt 1's timeout."""
    clock = VirtualClock()
    clock.install(monkeypatch)
    deadline = clock.now + 55.0

    first = llm.attempt_timeout_seconds(deadline)
    assert first == pytest.approx(55.0)

    clock.sleep(40.0)
    second = llm.attempt_timeout_seconds(deadline)
    assert second == pytest.approx(15.0), (
        "a retry must be told what is LEFT, not what the call started with; "
        f"got {second:g}s after 40s of a 55s budget"
    )

    # Past the deadline it must not go negative - a negative httpx timeout is a
    # different failure than a short one.
    clock.sleep(60.0)
    assert llm.attempt_timeout_seconds(deadline) > 0


def _narrative_call_sites(function: ast.FunctionDef) -> list[ast.Call]:
    """Every ``_narrative_overlay(...)`` call inside one function."""
    return [
        node
        for node in ast.walk(function)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "_narrative_overlay"
    ]


def _inside_a_loop(function: ast.FunctionDef, target: ast.Call) -> bool:
    """Whether this call sits inside a for/while, so one site runs many times."""
    for loop in ast.walk(function):
        if isinstance(loop, (ast.For, ast.While, ast.AsyncFor)):
            for inner in ast.walk(loop):
                if inner is target:
                    return True
    return False


def test_the_call_count_matches_the_budget_divisor() -> None:
    """The whole budget rests on there being exactly N calls per incident.

    Read from the source rather than asserted by hand, because a third call would
    silently invalidate the arithmetic above while every timing test kept passing -
    the tests would be measuring two calls while the code made three.

    Three separate things are checked, because each has its own failure mode:

    * **which functions** reach the model. A new one means the Tier-2 path changed.
    * **how many call sites** there are in total. A second call inside an existing
      function is the same hazard and a set of names cannot see it - that was the
      surviving mutant when this test was first written.
    * **that no call site is inside a loop**, which would multiply a single site
      into an unbounded number of calls with the divisor unchanged.
    """
    tree = ast.parse(TRIAGE_SOURCE.read_text(encoding="utf-8"))
    callers = {
        node.name: _narrative_call_sites(node)
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and _narrative_call_sites(node)
    }
    assert set(callers) == {
        "_model_summary",
        "_model_rca_section",
    }, (
        "the functions that reach the model on the Tier-2 path changed; "
        f"{sorted(callers)} must match MODEL_CALLS_PER_INCIDENT="
        f"{llm.MODEL_CALLS_PER_INCIDENT}"
    )

    sites = [call for calls in callers.values() for call in calls]
    assert len(sites) == llm.MODEL_CALLS_PER_INCIDENT, (
        f"{len(sites)} _narrative_overlay call sites found "
        f"({ {name: len(calls) for name, calls in callers.items()} }); the budget "
        f"assumes {llm.MODEL_CALLS_PER_INCIDENT} and would be exceeded by "
        f"{(len(sites) - llm.MODEL_CALLS_PER_INCIDENT) * llm.model_call_budget_seconds():g}s"
    )

    tree_functions = {
        node.name: node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)
    }
    for name, calls in callers.items():
        for call in calls:
            assert not _inside_a_loop(tree_functions[name], call), (
                f"{name} reaches the model from inside a loop, so one call site "
                "can run more than MODEL_CALLS_PER_INCIDENT times"
            )


# --------------------------------------------------------------------------
# The wall-clock property, per adapter.
# --------------------------------------------------------------------------


class SlowProvider:
    """A provider that takes exactly as long as it is allowed to, then fails.

    ``hang_attempts`` counts from the end: attempt N fails instantly, the last one
    consumes its whole timeout. That is the worst case the retry loop permits and
    the shape that actually happens - a provider that rejects fast while its
    connection is being established, then holds the socket open.
    """

    def __init__(self, clock: VirtualClock, hang_attempts: int = 1) -> None:
        self.clock = clock
        self.hang_attempts = hang_attempts
        self.timeouts_seen: list[float] = []
        #: Set by the Anthropic fake, which receives its per-attempt timeout on
        #: a copy of the client rather than as a request argument.
        self.current: float = 0.0

    def _spend(self, timeout: float) -> None:
        self.timeouts_seen.append(timeout)
        if len(self.timeouts_seen) <= (llm.GEMINI_MAX_ATTEMPTS - self.hang_attempts):
            # An instant rejection: no time passes, but a retry is warranted.
            self.clock.sleep(0.01)
        else:
            self.clock.sleep(timeout)
        raise _SlowProviderFault("the provider held the socket and then dropped it")


class _SlowProviderFault(Exception):
    """A fault every adapter agrees is worth one more attempt.

    This detail is load-bearing and was got wrong the first time. A bare
    ``ConnectionError`` is retryable on the OpenAI and Anthropic adapters but
    **not** on Gemini, which reads a string ``status`` and treats an absent one as
    a configuration fault. With a bare ConnectionError the Gemini half of the
    wall-clock test passed in 0.01s having retried nothing - a green test
    measuring nothing. Both surfaces are therefore set here: the SDK-specific
    string name and the protocol-specific integer code.

    `test_every_adapter_retries_this_fault` keeps that honest.
    """

    status = "UNAVAILABLE"
    status_code = 503
    code = 503


def test_every_adapter_retries_this_fault() -> None:
    """The wall-clock test is only meaningful if the retry loop actually runs."""
    fault = _SlowProviderFault("boom")
    assert providers._is_transient_gemini(fault) is True
    assert providers._is_transient_openai(fault) is True


def _install_openai(monkeypatch: pytest.MonkeyPatch, slow: SlowProvider) -> None:
    class _Completions:
        def create(self, **kwargs: typing.Any) -> typing.Any:
            slow._spend(float(kwargs["timeout"]))

    class _FakeOpenAI:
        def __init__(self, **kwargs: typing.Any) -> None:
            self.chat = type("Chat", (), {"completions": _Completions()})()

    monkeypatch.setattr(providers, "OpenAI", _FakeOpenAI, raising=False)
    monkeypatch.setattr(__import__("openai"), "OpenAI", _FakeOpenAI)


def _install_anthropic(monkeypatch: pytest.MonkeyPatch, slow: SlowProvider) -> None:
    class _Messages:
        def create(self, **kwargs: typing.Any) -> typing.Any:
            slow._spend(slow.current)

    class _FakeAnthropic:
        current = 0.0

        def __init__(self, **kwargs: typing.Any) -> None:
            self.messages = _Messages()

        def with_options(self, **kwargs: typing.Any) -> typing.Any:
            # with_options returns a copy; the attempt timeout travels on it.
            clone = _FakeAnthropic()
            clone.current = float(kwargs.get("timeout", 0.0))
            slow.current = clone.current
            return clone

    monkeypatch.setattr(providers, "Anthropic", _FakeAnthropic, raising=False)
    monkeypatch.setattr(__import__("anthropic"), "Anthropic", _FakeAnthropic)
    slow.current = 0.0


def _install_gemini(monkeypatch: pytest.MonkeyPatch, slow: SlowProvider) -> None:
    from google import genai

    class _Models:
        def generate_content(self, **kwargs: typing.Any) -> typing.Any:
            options = kwargs["config"].http_options
            assert options is not None, (
                "the Gemini adapter must cap the timeout per request; there is no "
                "other supported way (see the comment at the call site)"
            )
            slow._spend(float(options.timeout) / 1000.0)

    class _FakeGenaiClient:
        def __init__(self, **kwargs: typing.Any) -> None:
            self.models = _Models()

    # The adapter imports `google.genai` inside the call, so the seam is the module
    # attribute, not a name in providers.
    monkeypatch.setattr(genai, "Client", _FakeGenaiClient)


@pytest.mark.parametrize(
    ("name", "adapter", "installer"),
    [
        (
            "gemini",
            lambda: providers.GeminiProvider(api_key="k", env={}),
            _install_gemini,
        ),
        (
            "openai",
            lambda: providers.OpenAIProvider(api_key="k", env={}),
            _install_openai,
        ),
        (
            "anthropic",
            lambda: providers.AnthropicProvider(api_key="k", env={}),
            _install_anthropic,
        ),
    ],
)
def test_one_incident_of_model_time_stays_under_the_ceiling(
    monkeypatch: pytest.MonkeyPatch,
    name: str,
    adapter: typing.Callable[[], typing.Any],
    installer: typing.Callable[[pytest.MonkeyPatch, SlowProvider], None],
) -> None:
    """Two calls, each taking the longest its budget permits, under 120s total.

    This is the test the remediation asked for. It drives the real adapters through
    the real retry loop with a provider that is slow in the worst way the loop
    allows, and measures the elapsed time rather than trusting the constants.
    """
    clock = VirtualClock()
    clock.install(monkeypatch)
    slow = SlowProvider(clock)
    installer(monkeypatch, slow)

    client = adapter()
    for call in range(llm.MODEL_CALLS_PER_INCIDENT):
        with pytest.raises(llm.ModelOutputError):
            client.complete(llm.build_prompt(_payload()))
        spent = clock.elapsed
        assert spent <= REQUIRED_CEILING_SECONDS, (
            f"{name} call {call + 1} spent {spent:g}s of the "
            f"{REQUIRED_CEILING_SECONDS}s ceiling on its own"
        )

    total = clock.elapsed
    assert total < REQUIRED_CEILING_SECONDS, (
        f"{name} spent {total:g}s of model time on one incident; the Sentinel stops "
        f"waiting at {SENTINEL_PER_INCIDENT_TIMEOUT_SECONDS}s and the abandoned job "
        f"keeps holding a pool slot. Per-attempt timeouts seen: "
        f"{[round(t, 2) for t in slow.timeouts_seen]}"
    )
    # The retries must have happened, not merely been bounded. A provider that
    # failed once and gave up would clear the total above while exercising
    # nothing, which is exactly how the Gemini case passed vacuously the first
    # time this test was written.
    assert len(slow.timeouts_seen) >= llm.MODEL_CALLS_PER_INCIDENT * 2, (
        f"{name} made {len(slow.timeouts_seen)} attempts across "
        f"{llm.MODEL_CALLS_PER_INCIDENT} calls; each call must have retried at "
        "least once for this test to mean anything"
    )
    assert clock.sleeps, "the retry backoff never ran"


def test_a_second_attempt_gets_less_time_than_the_first(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Proven on one adapter, because it is the same line in all three."""
    clock = VirtualClock()
    clock.install(monkeypatch)
    slow = SlowProvider(clock, hang_attempts=1)
    _install_openai(monkeypatch, slow)

    with pytest.raises(llm.ModelOutputError):
        providers.OpenAIProvider(api_key="k", env={}).complete("evidence")

    assert len(slow.timeouts_seen) >= 2
    assert slow.timeouts_seen[1] < slow.timeouts_seen[0], (
        "the retry was handed a fresh full timeout, which is the defect; "
        f"saw {slow.timeouts_seen}"
    )


def test_the_genini_client_option_is_not_the_per_attempt_timeout() -> None:
    """Pins why the Gemini cap is a request option.

    ``genai.Client`` copies http_options at construction and builds its httpx
    client from the copy, so assigning to the object afterwards is inert. This was
    measured, not assumed: the first attempt at this fix mutated the client-level
    HttpOptions and the timeout did not move. The test asserts the SDK's behaviour
    so the comment at the call site cannot become a lie, and so a future SDK that
    makes the cheap version work again is noticed rather than shipped over.
    """
    from google.genai import Client, types as genai_types

    ours = genai_types.HttpOptions(timeout=60_000)
    client = Client(api_key="k", http_options=ours)
    held = client._api_client._http_options  # noqa: SLF001 - the point of the test

    ours.timeout = 5_000

    assert held.timeout == 60_000, (
        "genai.Client now aliases the caller's http_options; the call site could "
        "pass the per-attempt cap as a client option again. The request option it "
        "uses today is still correct, so this is information, not a break."
    )
