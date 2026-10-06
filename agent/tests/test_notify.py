"""Tests for the Tier-2 webhook dispatcher (agent/notify.py).

No test may open a real socket: every target is driven through
``httpx.MockTransport``. A dispatcher failure must never escape
:meth:`Dispatcher.dispatch`, so the negative controls assert the call returns
normally rather than raising.
"""

from __future__ import annotations

import json
import threading
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


def test_telegram_full_flow_dynamic_chat_id() -> None:
    import notify as n

    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        if request.url.path.endswith("/getUpdates"):
            return httpx.Response(
                200,
                json={
                    "ok": True,
                    "result": [
                        {"update_id": 1, "message": {"chat": {"id": 111}}},
                        {"update_id": 2, "message": {"chat": {"id": 222}}},
                    ],
                },
            )
        return httpx.Response(200, json={"ok": True})

    d = _dispatcher_with_transport(handler, telegram=n.TelegramTarget("TOK123"))
    results = d.deliver(_INCIDENT, "SEV2", _MD)
    assert results["telegram"] == "ok"
    assert calls[0].endswith("/getUpdates")
    assert calls[1].endswith("/sendMessage")


def test_telegram_getupdates_401_is_quiet() -> None:
    import notify as n

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401)

    d = _dispatcher_with_transport(handler, telegram=n.TelegramTarget("BAD"))
    assert d.deliver(_INCIDENT, "SEV2", _MD)["telegram"] == "http_401"


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


def test_telegram_discovery_logs_insecure_warning(
    caplog: pytest.LogCaptureFixture,
) -> None:
    import logging as _logging

    import notify as n

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/getUpdates"):
            return httpx.Response(
                200,
                json={"ok": True, "result": [{"message": {"chat": {"id": 42}}}]},
            )
        return httpx.Response(200, json={"ok": True})

    d = _dispatcher_with_transport(handler, telegram=n.TelegramTarget("TOK"))
    with caplog.at_level(_logging.WARNING, logger="srek3s.agent.notify"):
        d.deliver(_INCIDENT, "SEV2", _MD)
    warning = next(r for r in caplog.records if r.levelname == "WARNING")
    assert (
        "TELEGRAM_CHAT_ID is unset. Dynamically resolved to 42." in warning.getMessage()
    )
    assert "TELEGRAM_CHAT_ID=42" in warning.getMessage()


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
