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
import queue as queue_mod
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

#: How many undelivered reports may be waiting when the dispatcher is busy.
#:
#: This is the bound that replaced "one thread per escalation". It is a queue depth,
#: not a timeout: DISPATCH_TIMEOUT_SECONDS caps a single delivery, and this caps how
#: many can be outstanding. Sized for a burst a responder could plausibly still read
#: (a bad rollout takes a namespace down in ones and tens), and small enough that
#: exceeding it is reported rather than absorbed.
NOTIFY_QUEUE_DEPTH: Final[int] = 32

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
    #: The single delivery worker, created on first async dispatch. Bounded queue
    #: plus one consumer, so concurrent deliveries are capped at NOTIFY_QUEUE_DEPTH
    #: regardless of how many incidents escalate at once.
    _worker_queue: "queue_mod.Queue[tuple[str, str, str]] | None" = field(
        default=None, repr=False
    )
    _worker: threading.Thread | None = field(default=None, repr=False)
    _worker_lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

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
        """Send to the configured chat. Never raises.

        The recipient is whatever TELEGRAM_CHAT_ID says, and nothing else.
        """
        assert self.telegram is not None
        token = self.telegram.bot_token
        base = f"https://api.telegram.org/bot{token}"
        try:
            with self._client_factory(timeout=self.timeout_seconds) as client:
                if not self.telegram.chat_id:
                    # THE FALLBACK THIS USED TO TAKE IS GONE, AND IT WAS A HOLE.
                    #
                    # With TELEGRAM_CHAT_ID unset, this called `getUpdates` and posted
                    # to whichever chat had most recently written to the bot. The bot
                    # token authenticates the API *call*; it says nothing about who
                    # the *recipient* is. So anyone who could message the bot could
                    # choose where incident reports - which contain the namespace,
                    # pod name, container name and exit code of someone else's
                    # workload - are delivered.
                    #
                    # The old code logged a WARNING and then sent the message anyway,
                    # which is the worst of both: the finding was recorded and the
                    # exfiltration proceeded. A security property that is announced
                    # and not enforced is documentation, not a control.
                    #
                    # Failing closed here is also the honest reading of the rest of
                    # this module. Every other target here refuses a missing URL at
                    # construction time (`_require_https_url`), and `Dispatcher.enabled`
                    # treats "not configured" as a no-op. A bot token with no chat is
                    # the same condition and now behaves the same way.
                    logger.error(
                        "notify failed target=telegram incident_id=%s "
                        "error=chat_id_not_configured",
                        incident_id,
                    )
                    return "chat_id_not_configured"
                chat_id: int | str = self.telegram.chat_id
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

        WHY NOT ONE THREAD PER ESCALATION
        ----------------------------------
        The first draft started a daemon thread per call. That is unbounded in the
        one dimension that matters: `DISPATCH_TIMEOUT_SECONDS` bounds how long any
        ONE delivery takes, and nothing bounded how many were in flight at once. A
        burst of incidents spawned a burst of threads, each holding an HTTP client
        and its connection pool for up to four seconds.

        An unbounded fan-out is worse than a slow queue here because the failure is
        invisible until it matters: a burst is exactly when the responder is least
        able to absorb thread exhaustion, and the process that pays for it is the
        triage engine, not the webhook.

        So deliveries go through ONE bounded queue drained by ONE worker thread.
        `put_nowait` cannot block, which preserves the property that made this
        asynchronous in the first place, and the queue depth is the single number
        that bounds concurrent deliveries. On overflow the report is SHED and said
        so, rather than queued without limit or silently dropped - the same
        choice the sandbox makes at `429`, for the same reason: converting a
        capacity limit into an unbounded backlog produces a worse failure than
        admitting one.
        """
        if wait:
            return self.deliver(incident_id, severity, markdown)
        queue = self._ensure_worker()
        try:
            queue.put_nowait((incident_id, severity, markdown))
        except queue_mod.Full:
            logger.error(
                "notify shed target=dispatcher incident_id=%s depth=%d "
                "error=queue_full",
                incident_id,
                NOTIFY_QUEUE_DEPTH,
            )
            return None
        return None

    def _ensure_worker(self) -> "queue_mod.Queue[tuple[str, str, str]]":
        """Start the single delivery worker on first use. Never raises.

        Double-checked on the QUEUE rather than the thread, because the queue is
        the thing callers need and checking it narrows the return type honestly.
        Checking the thread instead leaves mypy unable to prove the queue is set.
        """
        existing = self._worker_queue
        if existing is not None:
            return existing
        with self._worker_lock:
            again = self._worker_queue
            if again is not None:
                return again
            q: queue_mod.Queue[tuple[str, str, str]] = queue_mod.Queue(
                maxsize=NOTIFY_QUEUE_DEPTH
            )
            worker = threading.Thread(
                target=self._drain,
                args=(q,),
                name="notify-dispatch",
                daemon=True,
            )
            # Publish both fields BEFORE starting. The worker immediately calls
            # q.get(); starting first would race a dispatcher that saw a thread
            # with no queue to hand out.
            self._worker_queue = q
            self._worker = worker
            worker.start()
            return q

    def _drain(self, q: "queue_mod.Queue[tuple[str, str, str]]") -> None:
        """Deliver until the process ends. Never raises, never dies quietly."""
        while True:
            try:
                incident_id, severity, markdown = q.get()
            except Exception:  # pragma: no cover - Queue.get does not raise
                return
            try:
                self.deliver(incident_id, severity, markdown)
            except Exception as exc:  # pragma: no cover - deliver never raises
                logger.error(
                    "notify worker crashed incident_id=%s error=%s",
                    incident_id,
                    type(exc).__name__,
                )
            finally:
                q.task_done()


def _latest_chat_id(document: dict[str, Any]) -> int | None:
    """The chat.id of the most recent message in a getUpdates payload.

    DEAD CODE, KEPT DELIBERATELY. Nothing calls this any more.

    It existed only to serve the `getUpdates` discovery path in
    `Dispatcher._telegram_deliver`, which chose the recipient of an incident report
    by asking the bot who had messaged it last. That is not a routing decision an
    incident channel should delegate to an unauthenticated third party, and the
    delivery path now refuses to send without TELEGRAM_CHAT_ID.

    Deleting it would have made the diff smaller and the history harder to read. The
    useful record is that this function existed, what it decided, and why it stopped
    being called - and a reader who greps for "chat_id" should find that reason at
    the definition site rather than only in a commit message.
    """
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
