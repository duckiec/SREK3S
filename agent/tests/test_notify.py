"""Tests for the Tier-2 webhook dispatcher (agent/notify.py).

No test may open a real socket: every target is driven through
``httpx.MockTransport``. A dispatcher failure must never escape
:meth:`Dispatcher.dispatch`, so the negative controls assert the call returns
normally rather than raising.
"""

from __future__ import annotations

import json
import pathlib
import threading
import time
from typing import Any

import httpx
import pytest

import notify
from notify import (
    Dispatcher,
    SlackTarget,
    DiscordTarget,
    PagerDutyTarget,
    dispatcher_from_env,
    discord_payload,
    pagerduty_payload,
    slack_payload,
)

_INCIDENT = "inc_01M48W8J4PMFZYH8Z0EAM9BM6F"
_MD = "## Tier-2 escalation\n\nSomething broke."


def _dispatcher_with_transport(handler: Any, **kwargs: Any) -> Dispatcher:
    def client_factory(timeout: float | httpx.Timeout) -> httpx.Client:
        return httpx.Client(transport=httpx.MockTransport(handler), timeout=timeout)

    d = Dispatcher(**kwargs)
    d._client_factory = client_factory
    return d


class _Recorder:
    """Stand-in dispatcher for handler tests. Records calls, never does I/O."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str, str]] = []

    def dispatch(
        self, incident_id: str, severity: str, markdown: str, *, wait: bool = False
    ) -> None:
        self.calls.append((incident_id, severity, markdown))


def test_slack_payload_uses_block_kit() -> None:
    body = slack_payload(_INCIDENT, _MD)
    blocks = body["blocks"]
    assert blocks[0]["type"] == "header"
    assert _INCIDENT in blocks[0]["text"]["text"]
    assert blocks[1]["type"] == "section"
    assert blocks[1]["text"]["type"] == "mrkdwn"
    assert _MD in blocks[1]["text"]["text"]


def test_discord_payload_embed_and_truncation() -> None:
    long_md = "x" * (notify.DISCORD_DESCRIPTION_LIMIT + 500)
    body = discord_payload(_INCIDENT, long_md)
    embed = body["embeds"][0]
    assert len(embed["description"]) == notify.DISCORD_DESCRIPTION_LIMIT
    assert embed["description"].endswith("[truncated]")


def test_pagerduty_payload_shape() -> None:
    body = pagerduty_payload("RK123", _INCIDENT, "SEV1", _MD)
    assert body["routing_key"] == "RK123"
    assert body["event_action"] == "trigger"
    assert body["payload"]["severity"] == "critical"
    assert body["custom_details"]["report_markdown"] == _MD


def test_pagerduty_severity_mapping_defaults_to_warning() -> None:
    assert (
        pagerduty_payload("k", _INCIDENT, "SEV4", _MD)["payload"]["severity"] == "info"
    )
    assert (
        pagerduty_payload("k", _INCIDENT, "UNKNOWN", _MD)["payload"]["severity"]
        == "warning"
    )


def test_dispatcher_from_env_unset_is_noop() -> None:
    d = dispatcher_from_env({})
    assert not d.enabled()
    assert d.deliver(_INCIDENT, "SEV2", _MD) == {}


def test_dispatcher_from_env_validates_urls() -> None:
    with pytest.raises(ValueError, match="SLACK_WEBHOOK_URL"):
        dispatcher_from_env({"SLACK_WEBHOOK_URL": "not-a-url"})
    with pytest.raises(ValueError, match="DISCORD_WEBHOOK_URL"):
        dispatcher_from_env({"DISCORD_WEBHOOK_URL": "http://insecure.example/hook"})
    d = dispatcher_from_env(
        {
            "SLACK_WEBHOOK_URL": "https://hooks.slack.com/services/T/B/xxx",
            "PAGERDUTY_ROUTING_KEY": "RK123",
        }
    )
    assert d.enabled()
    assert d.slack is not None and d.discord is None and d.pagerduty is not None


def test_all_targets_receive_the_report() -> None:
    seen: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen[request.url.host] = json.loads(request.content)
        return httpx.Response(204)

    d = _dispatcher_with_transport(
        handler,
        slack=SlackTarget("https://hooks.slack.com/services/T/B/x"),
        discord=DiscordTarget("https://discord.com/api/webhooks/1/abc"),
        pagerduty=PagerDutyTarget("RK123"),
    )
    results = d.deliver(_INCIDENT, "SEV2", _MD)
    assert results == {"slack": "ok", "discord": "ok", "pagerduty": "ok"}
    assert "blocks" in seen["hooks.slack.com"]
    assert "embeds" in seen["discord.com"]
    assert seen["events.pagerduty.com"]["custom_details"]["report_markdown"] == _MD


@pytest.mark.parametrize(
    "status,label", [(403, "Forbidden"), (500, "Server Error"), (429, "Rate Limited")]
)
def test_http_failures_do_not_raise(status: int, label: str) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status)

    d = _dispatcher_with_transport(
        handler, slack=SlackTarget("https://hooks.slack.com/x")
    )
    results = d.deliver(_INCIDENT, "SEV2", _MD)
    assert results["slack"] == f"http_{status}"


def test_timeout_does_not_raise() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("timed out", request=request)

    d = _dispatcher_with_transport(
        handler, discord=DiscordTarget("https://discord.com/api/webhooks/1/x")
    )
    assert d.deliver(_INCIDENT, "SEV2", _MD)["discord"] == "ReadTimeout"


def test_pagerduty_500_does_not_raise() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500)

    d = _dispatcher_with_transport(handler, pagerduty=PagerDutyTarget("RK"))
    assert d.deliver(_INCIDENT, "SEV2", _MD)["pagerduty"] == "http_500"


def test_telegram_without_chat_id_sends_nothing() -> None:
    """No configured chat means no delivery, and no discovery either.

    The `getUpdates` fallback chose the RECIPIENT of an incident report by asking
    the bot who had messaged it most recently. Anyone able to message the bot could
    therefore redirect reports carrying someone else's namespace, pod, container and
    exit code. The old code logged a warning and sent anyway.

    This asserts the absence of the whole exchange, not just the outcome: an
    implementation that called `getUpdates` and then decided not to use the result
    would still leak the incident's existence to whoever was watching the bot.
    """
    import notify as n

    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        return httpx.Response(200, json={"ok": True})

    d = _dispatcher_with_transport(handler, telegram=n.TelegramTarget("TOK123"))
    results = d.deliver(_INCIDENT, "SEV2", _MD)
    assert results["telegram"] == "chat_id_not_configured"
    assert calls == [], f"no request may be made at all, got {calls}"


def test_telegram_without_chat_id_logs_an_error_not_a_warning(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The missing configuration is recorded as a failure, not a caveat.

    The old behaviour emitted WARNING and delivered anyway. A security property
    that is announced and not enforced is documentation, so the level matters: the
    only thing that changed is that nothing is sent, and the log has to say so at a
    level an operator actually filters on.
    """
    import logging as _logging

    import notify as n

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"ok": True})

    d = _dispatcher_with_transport(handler, telegram=n.TelegramTarget("TOK"))
    with caplog.at_level(_logging.DEBUG, logger="srek3s.agent.notify"):
        d.deliver(_INCIDENT, "SEV2", _MD)
    errors = [r for r in caplog.records if r.levelname == "ERROR"]
    assert errors, "a refused Telegram delivery must be logged at ERROR"
    assert "chat_id_not_configured" in errors[0].getMessage()


def test_telegram_chat_id_bypasses_getupdates() -> None:
    import notify as n

    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        return httpx.Response(200, json={"ok": True})

    d = _dispatcher_with_transport(
        handler, telegram=n.TelegramTarget("TOK", chat_id="8642246079")
    )
    assert d.deliver(_INCIDENT, "SEV2", _MD)["telegram"] == "ok"
    assert calls == ["/botTOK/sendMessage"]


def test_telegram_sends_to_the_configured_chat_and_nobody_else() -> None:
    """The recipient is the configured chat, whatever the bot's inbox says."""
    import notify as n

    sent: list[dict[str, Any]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/sendMessage"):
            sent.append(json.loads(request.content))
        return httpx.Response(200, json={"ok": True})

    d = _dispatcher_with_transport(
        handler, telegram=n.TelegramTarget("TOK", chat_id="-1009999")
    )
    assert d.deliver(_INCIDENT, "SEV2", _MD)["telegram"] == "ok"
    assert [body["chat_id"] for body in sent] == ["-1009999"]


def test_getupdates_helper_is_no_longer_reachable() -> None:
    """The discovery helper is dead code, and that is deliberate.

    `_latest_chat_id` only ever served the fallback that chose the recipient from
    the bot's inbox. Nothing calls it now. The test exists so that wiring it back in
    is a deliberate act with a failing test attached, rather than a refactor that
    looks harmless.
    """
    import notify as n

    source = pathlib.Path(n.__file__).read_text(encoding="utf-8")
    body = source.split("def _latest_chat_id", 1)[1]
    assert "_latest_chat_id(" not in body, (
        "_latest_chat_id has a caller again; the Telegram recipient must stay "
        "TELEGRAM_CHAT_ID and nothing else"
    )


def test_telegram_message_escapes_and_truncates() -> None:
    import notify as n

    out = n.telegram_message(_INCIDENT, "a < b & c " + "x" * 5000)
    assert len(out) <= notify.TELEGRAM_MESSAGE_LIMIT
    assert "&lt;" in out and "&amp;" in out
    assert out.endswith("[truncated]")


def test_dispatch_wait_false_does_not_block() -> None:
    gate = threading.Event()

    def handler(request: httpx.Request) -> httpx.Response:
        gate.wait(timeout=2.0)
        return httpx.Response(204)

    d = _dispatcher_with_transport(
        handler, slack=SlackTarget("https://hooks.slack.com/x")
    )
    try:
        out = d.dispatch(_INCIDENT, "SEV2", _MD, wait=False)
        assert out is None
    finally:
        gate.set()


def test_handler_dispatches_exactly_on_tier2() -> None:
    """The triage handler must fire the dispatcher for TIER_2 and not for TIER_1."""
    import pathlib

    import triage

    import models
    from main import create_app
    from fastapi.testclient import TestClient

    fixture = json.loads(
        (
            pathlib.Path(__file__).resolve().parents[2]
            / "tests"
            / "fixtures"
            / "emitted_incident.json"
        ).read_text()
    )
    app = create_app(notify_dispatcher=_Recorder())
    recorder: _Recorder = app.state.notify_dispatcher

    tier2_outcome = triage.triage_payload(
        models.IncidentPayload.model_validate(fixture)
    )
    assert tier2_outcome.tier.value == "TIER_2_ARCHITECTURAL"

    with TestClient(app) as client:
        resp = client.post("/v1/incidents", json=fixture)
    assert resp.status_code == 200
    assert len(recorder.calls) == 1
    assert recorder.calls[0][0] == fixture["incident_id"]


def test_async_dispatch_uses_one_worker_not_one_thread_per_incident() -> None:
    """Concurrency is bounded by the queue, not by how many incidents arrive.

    The first implementation started a daemon thread per escalation, which meant
    `DISPATCH_TIMEOUT_SECONDS` capped any ONE delivery and nothing capped how many
    ran at once. A burst of incidents - exactly when a responder cannot absorb thread
    exhaustion - spawned a burst, each holding an HTTP client and its pool.

    The assertion is deliberately about thread names rather than timing, so it fails
    on the old shape rather than merely being slow under it. The handler is held
    open so every dispatch is still outstanding when the count is taken.
    """
    release = threading.Event()
    delivered: list[str] = []
    started = threading.Event()

    def handler(request: httpx.Request) -> httpx.Response:
        started.set()
        release.wait(timeout=5)
        delivered.append(request.url.path)
        return httpx.Response(200, json={"ok": True})

    d = _dispatcher_with_transport(
        handler, slack=SlackTarget("https://hooks.example/x")
    )

    # Count workers created BY THIS DISPATCHER, not process-wide. An earlier test
    # leaves its own worker alive, and asserting on every thread named
    # "notify-dispatch" made this test fail on ordering rather than on the property
    # it exists to check.
    def workers() -> set[int]:
        ids: set[int] = set()
        for t in threading.enumerate():
            # `ident` is None for a thread that has not started yet, so the
            # narrowing is real rather than a cast.
            if t.name == "notify-dispatch" and t.ident is not None:
                ids.add(t.ident)
        return ids

    before = workers()

    burst = 12
    for i in range(burst):
        d.dispatch(f"inc_burst_{i}", "SEV2", _MD)

    assert started.wait(timeout=5), "the worker never picked up the first delivery"

    new_workers = workers() - before
    assert (
        len(new_workers) == 1
    ), f"one dispatcher must add exactly one delivery worker, added {len(new_workers)}"
    per_incident = [
        t.name for t in threading.enumerate() if t.name.startswith("notify-inc_")
    ]
    assert not per_incident, (
        "a thread was created per incident again: "
        f"{per_incident}. Escalation "
        "bursts must be bounded by NOTIFY_QUEUE_DEPTH, not by spawning."
    )

    release.set()
    deadline = time.monotonic() + 5
    while len(delivered) < burst and time.monotonic() < deadline:
        time.sleep(0.02)
    assert len(delivered) == burst, f"only {len(delivered)}/{burst} were delivered"


def test_queue_overflow_sheds_and_says_so(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Overflow is reported, not absorbed and not silently dropped.

    The point of a bound is that exceeding it is visible. A queue that grows without
    limit has moved the failure rather than prevented it; a queue that drops quietly
    makes an operator believe an incident was paged when it was not.
    """
    import logging as _logging

    import notify as n

    release = threading.Event()
    started = threading.Event()

    def handler(request: httpx.Request) -> httpx.Response:
        started.set()
        release.wait(timeout=5)
        return httpx.Response(200, json={"ok": True})

    d = _dispatcher_with_transport(
        handler, slack=SlackTarget("https://hooks.example/x")
    )

    total = n.NOTIFY_QUEUE_DEPTH + 5
    with caplog.at_level(_logging.DEBUG, logger="srek3s.agent.notify"):
        for i in range(total):
            assert d.dispatch(f"inc_overflow_{i}", "SEV2", _MD) is None
    assert started.wait(timeout=5)

    shed = [r for r in caplog.records if "queue_full" in r.getMessage()]
    assert shed, (
        f"dispatching {total} with the worker held open must report shedding past "
        f"NOTIFY_QUEUE_DEPTH={n.NOTIFY_QUEUE_DEPTH}"
    )
    assert any(r.levelname == "ERROR" for r in shed)
    release.set()
