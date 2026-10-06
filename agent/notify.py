"""Egress dispatcher for Tier-2 war-room reports.

A Tier-2 outcome produces no patch. It produces a Markdown document a responder
reads. This module ships that document to the alerting systems configured for
this deployment: Slack, Discord, and PagerDuty.

The dispatcher is a no-op unless the operator set at least one webhook
environment variable. All three are optional, and an unset variable never stops
the agent from booting.
"""

from __future__ import annotations

import logging
import os
import threading
from dataclasses import dataclass, field
from typing import Any, Final
from urllib.parse import urlparse

import httpx

logger = logging.getLogger("srek3s.agent.notify")

SLACK_WEBHOOK_URL_ENV: Final[str] = "SLACK_WEBHOOK_URL"
DISCORD_WEBHOOK_URL_ENV: Final[str] = "DISCORD_WEBHOOK_URL"
PAGERDUTY_ROUTING_KEY_ENV: Final[str] = "PAGERDUTY_ROUTING_KEY"
TELEGRAM_API_KEY_ENV: Final[str] = "TELEGRAM_API_KEY"
TELEGRAM_CHAT_ID_ENV: Final[str] = "TELEGRAM_CHAT_ID"

#: Absolute cap on one webhook call, seconds. The main triage loop must never
#: wait on egress longer than this, so it is a ceiling, not a tuning knob.
DISPATCH_TIMEOUT_SECONDS: Final[float] = 4.0

PAGERDUTY_EVENTS_URL: Final[str] = "https://events.pagerduty.com/v2/enqueue"

#: Discord and Telegram both cap a message body at 4096 characters.
DISCORD_DESCRIPTION_LIMIT: Final[int] = 4096
TELEGRAM_MESSAGE_LIMIT: Final[int] = 4096
_OMISSION_NOTE: Final[str] = "\n\n[truncated]"


def _escape_html(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def telegram_message(incident_id: str, markdown: str) -> str:
    """HTML parse-mode body: a bold header line plus the escaped report."""
    header = f"<b>Tier-2 escalation: {_escape_html(incident_id)}</b>\n\n"
    body = _escape_html(markdown)
    room = TELEGRAM_MESSAGE_LIMIT - len(header)
    if len(body) > room:
        body = body[: room - len(_OMISSION_NOTE)] + _OMISSION_NOTE
    return header + body


#: PagerDuty's Events API accepts this severity set and nothing else.
_PAGERDUTY_SEVERITY: Final[dict[str, str]] = {
    "SEV1": "critical",
    "SEV2": "error",
    "SEV3": "warning",
    "SEV4": "info",
}


def _require_https_url(raw: str, *, env_name: str) -> str:
    """Return the URL unchanged, or raise ValueError at boot time.

    A malformed URL here means the operator mis-set the environment. Catching
    that at startup is strictly better than a 4xx from every incident at
    runtime.
    """
    value = raw.strip()
    try:
        parsed = urlparse(value)
    except ValueError as exc:
        raise ValueError(f"{env_name} is not a parseable URL: {exc}") from exc
    if parsed.scheme != "https" or not parsed.netloc or not parsed.path:
        raise ValueError(
            f"{env_name} must be an https URL with a host and a path, got {raw!r}"
        )
    return value


@dataclass(frozen=True)
class SlackTarget:
    url: str


@dataclass(frozen=True)
class DiscordTarget:
    url: str


@dataclass(frozen=True)
class PagerDutyTarget:
    routing_key: str


@dataclass(frozen=True)
class TelegramTarget:
    bot_token: str
    chat_id: str = ""


def _truncate_for_discord(markdown: str) -> str:
    if len(markdown) <= DISCORD_DESCRIPTION_LIMIT:
        return markdown
    keep = DISCORD_DESCRIPTION_LIMIT - len(_OMISSION_NOTE)
    return markdown[:keep] + _OMISSION_NOTE


def slack_payload(incident_id: str, markdown: str) -> dict[str, Any]:
    return {
        "blocks": [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": f"Tier-2: {incident_id}"},
            },
            {"type": "section", "text": {"type": "mrkdwn", "text": markdown}},
        ]
    }


def discord_payload(incident_id: str, markdown: str) -> dict[str, Any]:
    return {
        "embeds": [
            {
                "title": f"Tier-2 escalation: {incident_id}",
                "description": _truncate_for_discord(markdown),
                "color": 15158332,
            }
        ]
    }


def pagerduty_payload(
    routing_key: str, incident_id: str, severity: str, markdown: str
) -> dict[str, Any]:
    return {
        "routing_key": routing_key,
        "event_action": "trigger",
        "dedup_key": incident_id,
        "payload": {
            "summary": f"SREK3S Tier-2 escalation {incident_id}",
            "source": "srek3s-agent",
            "severity": _PAGERDUTY_SEVERITY.get(severity, "warning"),
        },
        "custom_details": {"report_markdown": markdown},
    }


@dataclass
class Dispatcher:
    """Routes one Tier-2 report to every configured target."""

    slack: SlackTarget | None = None
    discord: DiscordTarget | None = None
    pagerduty: PagerDutyTarget | None = None
    telegram: TelegramTarget | None = None
    timeout_seconds: float = DISPATCH_TIMEOUT_SECONDS
    _client_factory: Any = field(default=httpx.Client, repr=False)

    def enabled(self) -> bool:
        return any((self.slack, self.discord, self.pagerduty, self.telegram))

    def _post(
        self, url: str, json_body: dict[str, Any], *, target: str, incident_id: str
    ) -> str:
        """One webhook call. Returns a human verdict, never raises."""
        try:
            with self._client_factory(timeout=self.timeout_seconds) as client:
                response = client.post(url, json=json_body)
            if 200 <= response.status_code < 300:
                logger.info(
                    "notify delivered target=%s incident_id=%s status=%d",
                    target,
                    incident_id,
                    response.status_code,
                )
                return "ok"
            logger.error(
                "notify failed target=%s incident_id=%s status=%d",
                target,
                incident_id,
                response.status_code,
            )
            return f"http_{response.status_code}"
        except (httpx.TimeoutException, httpx.TransportError) as exc:
            logger.error(
                "notify failed target=%s incident_id=%s error=%s",
                target,
                incident_id,
                type(exc).__name__,
            )
            return type(exc).__name__

    def _telegram_deliver(self, incident_id: str, markdown: str) -> str:
        """Resolve the chat ID dynamically, then send. Never raises."""
        assert self.telegram is not None
        token = self.telegram.bot_token
        base = f"https://api.telegram.org/bot{token}"
        try:
            with self._client_factory(timeout=self.timeout_seconds) as client:
                if self.telegram.chat_id:
                    chat_id: int | str = self.telegram.chat_id
                else:
                    updates = client.get(f"{base}/getUpdates")
                    if updates.status_code != 200:
                        logger.error(
                            "notify failed target=telegram incident_id=%s "
                            "step=getUpdates status=%d",
                            incident_id,
                            updates.status_code,
                        )
                        return f"http_{updates.status_code}"
                    chat_id = _latest_chat_id(updates.json()) or ""
                    if not chat_id:
                        logger.error(
                            "notify failed target=telegram incident_id=%s "
                            "error=no_chat_id_in_updates",
                            incident_id,
                        )
                        return "no_chat_id"
                    logger.warning(
                        "TELEGRAM_CHAT_ID is unset. Dynamically resolved to %s. "
                        "This is insecure for production. Lock this routing by "
                        "setting TELEGRAM_CHAT_ID=%s in your environment.",
                        chat_id,
                        chat_id,
                    )
                response = client.post(
                    f"{base}/sendMessage",
                    json={
                        "chat_id": chat_id,
                        "text": telegram_message(incident_id, markdown),
                        "parse_mode": "HTML",
                    },
                )
            if 200 <= response.status_code < 300:
                logger.info(
                    "notify delivered target=telegram incident_id=%s "
                    "chat_id=%s status=%d",
                    incident_id,
                    chat_id,
                    response.status_code,
                )
                return "ok"
            logger.error(
                "notify failed target=telegram incident_id=%s "
                "status=%d step=sendMessage",
                incident_id,
                response.status_code,
            )
            return f"http_{response.status_code}"
        except (httpx.TimeoutException, httpx.TransportError) as exc:
            logger.error(
                "notify failed target=telegram incident_id=%s error=%s",
                incident_id,
                type(exc).__name__,
            )
            return type(exc).__name__

    def deliver(self, incident_id: str, severity: str, markdown: str) -> dict[str, str]:
        """Send to every configured target. Never raises."""
        results: dict[str, str] = {}
        if self.slack is not None:
            results["slack"] = self._post(
                self.slack.url,
                slack_payload(incident_id, markdown),
                target="slack",
                incident_id=incident_id,
            )
        if self.discord is not None:
            results["discord"] = self._post(
                self.discord.url,
                discord_payload(incident_id, markdown),
                target="discord",
                incident_id=incident_id,
            )
        if self.pagerduty is not None:
            results["pagerduty"] = self._post(
                PAGERDUTY_EVENTS_URL,
                pagerduty_payload(
                    self.pagerduty.routing_key, incident_id, severity, markdown
                ),
                target="pagerduty",
                incident_id=incident_id,
            )
        if self.telegram is not None:
            results["telegram"] = self._telegram_deliver(incident_id, markdown)
        if not results:
            logger.info(
                "notify disabled: no webhook configured incident_id=%s", incident_id
            )
        return results

    def dispatch(
        self, incident_id: str, severity: str, markdown: str, *, wait: bool = False
    ) -> dict[str, str] | None:
        """Fire the deliveries. With wait=False this returns immediately.

        The triage path calls this with wait=False so a slow webhook never
        delays the HTTP 200 back to the Sentinel. Tests pass wait=True to
        collect the per-target verdicts deterministically.
        """
        if wait:
            return self.deliver(incident_id, severity, markdown)
        thread = threading.Thread(
            target=self.deliver,
            args=(incident_id, severity, markdown),
            name=f"notify-{incident_id}",
            daemon=True,
        )
        thread.start()
        return None


def _latest_chat_id(document: dict[str, Any]) -> int | None:
    """The chat.id of the most recent message in a getUpdates payload."""
    results = document.get("result") or []
    for update in reversed(results):
        message = update.get("message") or update.get("channel_post") or {}
        chat = message.get("chat") or {}
        chat_id = chat.get("id")
        if isinstance(chat_id, int):
            return chat_id
    return None


def dispatcher_from_env(env: dict[str, str] | None = None) -> Dispatcher:
    source = os.environ if env is None else env
    slack_raw = (source.get(SLACK_WEBHOOK_URL_ENV) or "").strip()
    discord_raw = (source.get(DISCORD_WEBHOOK_URL_ENV) or "").strip()
    pagerduty_raw = (source.get(PAGERDUTY_ROUTING_KEY_ENV) or "").strip()
    telegram_raw = (source.get(TELEGRAM_API_KEY_ENV) or "").strip()
    telegram_chat_id = (source.get(TELEGRAM_CHAT_ID_ENV) or "").strip()

    slack = (
        SlackTarget(_require_https_url(slack_raw, env_name=SLACK_WEBHOOK_URL_ENV))
        if slack_raw
        else None
    )
    discord = (
        DiscordTarget(_require_https_url(discord_raw, env_name=DISCORD_WEBHOOK_URL_ENV))
        if discord_raw
        else None
    )
    pagerduty = PagerDutyTarget(pagerduty_raw) if pagerduty_raw else None
    telegram = (
        TelegramTarget(telegram_raw, chat_id=telegram_chat_id) if telegram_raw else None
    )

    return Dispatcher(
        slack=slack, discord=discord, pagerduty=pagerduty, telegram=telegram
    )
