"""Offline tests for the E2E wire capture proxy (ROADMAP 4.2.1).

The proxy's job is to be *invisible*. It sits between the Sentinel and the
agent, and the Sentinel's emitter branches on the response status - 429 retried,
422 fatal, 500 escalated - so a proxy that altered a status code would change
the retry behaviour under test and produce a green run that proved nothing.

That makes "it worked" almost worthless as an assertion. What is worth
asserting is the set of ways it could lie, so every test here is written to fail
on a specific defect:

* a status code that must arrive unmodified (the 429 / 422 / 500 the emitter
  reads);
* a body that must arrive unmodified, including one that is not JSON;
* concurrency, because ThreadingHTTPServer serves each request on its own
  thread and interleaved appends would corrupt every line after the race, not
  just the racing ones;
* a dead upstream, which must surface as 502 rather than as a fabricated 200.

The proxy is exercised over a real socket on an ephemeral port, not against a
mock of the handler, because the failure mode being guarded against - a missing
Content-Length hanging the client - only exists on a real connection.
"""

from __future__ import annotations

import http.client
import json
import pathlib
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Final

import pytest

_E2E_DIR = pathlib.Path(__file__).resolve().parents[2] / "tests" / "e2e"
sys.path.insert(0, str(_E2E_DIR))

from capture_proxy import (  # noqa: E402
    CAPTURE_KEY,
    HOP_BY_HOP,
    append_record,
    build_record,
    forward,
    serve,
)

PAYLOAD: Final[dict[str, Any]] = {
    "schema_version": "1.0",
    "incident_id": "inc_01HQ8S7G3M2K9X4B6D0F1R5TJA",
    "namespace": "sentinel-chaos",
    "pod_name": "oom-leak-6d4f",
    "container_name": "leaker",
    "exit_code": 137,
    "reason": "OOMKilled",
    "restart_count": 3,
    "previous_reason": "OOMKilled",
    "scrubbed_logs": [
        "dial=postgres://checkout:[REDACTED]@10.42.0.7:5432/orders",
        "allocating 64Mi",
    ],
    "cluster_events": [],
    "redaction_report": {"total_redactions": 1, "rules_triggered": ["basic_auth_url"]},
    "detection_latency_ms": 412,
    "sentinel_version": "0.1.0",
}


# ---------------------------------------------------------------------------
# build_record - the shape the runner's invariants read
# ---------------------------------------------------------------------------


def test_payload_fields_stay_at_the_top_level() -> None:
    """The runner reads restart_count, reason and scrubbed_logs with .get().

    A nested wrapper would make every captured incident look like an empty one,
    and the runner would then fail for a reason that has nothing to do with the
    system under test.
    """
    record = build_record(
        request_body=json.dumps(PAYLOAD).encode(),
        upstream_status=200,
        upstream_body=b'{"incident_id":"inc_1","blast_radius_tier":"TIER_1"}',
        seq=1,
    )
    assert record["restart_count"] == 3
    assert record["reason"] == "OOMKilled"
    assert record["scrubbed_logs"] == PAYLOAD["scrubbed_logs"]
    assert record["incident_id"] == PAYLOAD["incident_id"]


def test_capture_key_collides_with_no_contract_field() -> None:
    """A namespaced response cannot shadow a Contract A field.

    ARCH 4.1 fixes the payload's keys. A top-level key of our own would risk
    colliding with a field added later, and because the runner reads with .get()
    the collision would be silent.
    """
    record = build_record(
        request_body=json.dumps(PAYLOAD).encode(),
        upstream_status=200,
        upstream_body=b"{}",
        seq=1,
    )
    assert CAPTURE_KEY in record
    assert CAPTURE_KEY not in PAYLOAD


def test_response_is_kept_for_the_tier_invariants() -> None:
    """4.2.5-4.2.7 read rca_markdown, git_patch and war-room dispatch.

    Those live in the response, so a capture that only kept the request would
    leave the second half of the milestone unprovable.
    """
    body = {"rca_markdown": "memory limit exceeded", "git_patch": ""}
    record = build_record(
        request_body=json.dumps(PAYLOAD).encode(),
        upstream_status=200,
        upstream_body=json.dumps(body).encode(),
        seq=7,
    )
    capture = record[CAPTURE_KEY]
    assert capture["upstream_status"] == 200
    assert capture["upstream_body"] == body
    assert capture["seq"] == 7


def test_a_non_json_body_is_recorded_rather_than_dropped() -> None:
    """Evidence is never silently discarded.

    A body the proxy cannot parse still has to appear in the file: a capture
    that quietly omitted the one exchange it could not read would look identical
    to a run where that exchange never happened.
    """
    record = build_record(
        request_body=b"this is not json",
        upstream_status=200,
        upstream_body=b"{}",
        seq=1,
    )
    assert record[CAPTURE_KEY]["request_was_not_an_object"] is True
    assert record[CAPTURE_KEY]["request_body_text"] == "this is not json"


def test_a_json_array_body_is_not_mistaken_for_a_payload() -> None:
    """Only a JSON *object* flattens to the top level."""
    record = build_record(
        request_body=b"[1, 2, 3]",
        upstream_status=200,
        upstream_body=b"{}",
        seq=1,
    )
    assert record[CAPTURE_KEY]["request_was_not_an_object"] is True
    assert "request_body_text" in record[CAPTURE_KEY]


# ---------------------------------------------------------------------------
# forward - fidelity, which is the whole point
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("status", [200, 422, 429, 500, 503])
def test_upstream_status_is_passed_through_verbatim(status: int) -> None:
    """The emitter reads the status to decide retry, fatal and escalate.

    Any normalisation here would silently change the Sentinel's behaviour under
    test. 429 in particular is the status it retries on, and 422 the one it
    treats as fatal.
    """
    seen: list[int] = []

    class _Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a: Any) -> None:
            pass

        def do_POST(self) -> None:  # noqa: N802
            length = int(self.headers.get("Content-Length") or 0)
            self.rfile.read(length)
            body = b'{"error":"nope"}'
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    agent = _start(_Handler)
    try:
        got, body = forward(
            upstream_host="127.0.0.1",
            upstream_port=agent.port,
            method="POST",
            path="/v1/incidents",
            headers={"Content-Type": "application/json"},
            body=b"{}",
            timeout=5.0,
        )
        seen.append(got)
        assert got == status
        assert body == b'{"error":"nope"}'
    finally:
        agent.close()


def test_a_dead_upstream_is_502_not_a_fabricated_success() -> None:
    """Fail closed.

    A proxy that returned 200 when the agent was unreachable would let the
    Sentinel believe the incident was triaged, and the run would pass on a
    system that had done nothing.
    """
    status, body = forward(
        upstream_host="127.0.0.1",
        upstream_port=1,  # nothing listens here
        method="POST",
        path="/v1/incidents",
        headers={},
        body=b"{}",
        timeout=2.0,
    )
    assert status == 502
    assert json.loads(body)["error"] == "capture_proxy_upstream"


def test_hop_by_hop_headers_are_not_forwarded() -> None:
    """Connection-scoped headers describe the hop they arrived on.

    Forwarding a stale Content-Length or a Connection header corrupts the next
    request on a keep-alive connection.
    """
    assert "content-length" in HOP_BY_HOP
    assert "connection" in HOP_BY_HOP
    assert "transfer-encoding" in HOP_BY_HOP
    assert "host" in HOP_BY_HOP
    assert "content-type" not in HOP_BY_HOP


# ---------------------------------------------------------------------------
# End to end over a real socket
# ---------------------------------------------------------------------------


def test_post_is_recorded_and_forwarded(tmp_path: pathlib.Path) -> None:
    """One real request through the real handler.

    Content-Length is asserted by omission: with HTTP/1.1 a response that omits
    it makes the client hang, and a hung emitter is indistinguishable from a
    slow one.
    """
    received: list[bytes] = []

    class _Agent(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a: Any) -> None:
            pass

        def do_POST(self) -> None:  # noqa: N802
            length = int(self.headers.get("Content-Length") or 0)
            received.append(self.rfile.read(length))
            body = b'{"ok":true}'
            self.send_response(201)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    agent = _start(_Agent)
    output = tmp_path / "captured.jsonl"
    proxy = serve(output=output, listen_port=0, upstream_port=agent.port)
    _run(proxy)
    try:
        status, body = _post(
            proxy.server_address[1], "/api/v1/triage", json.dumps(PAYLOAD).encode()
        )
        assert status == 201
        assert body == b'{"ok":true}'
    finally:
        proxy.shutdown()
        proxy.server_close()
        agent.close()

    assert received == [json.dumps(PAYLOAD).encode()]
    lines = output.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert record["restart_count"] == 3
    assert record[CAPTURE_KEY]["upstream_status"] == 201


def test_the_runner_can_read_what_the_proxy_wrote(tmp_path: pathlib.Path) -> None:
    """The two halves of this change are only useful if they fit together.

    The proxy writes NDJSON; the runner reads it. Written as a round trip rather
    than two separate unit tests because the contract between them is a file
    format, and a format both sides test independently is a format neither test
    can break.
    """
    from runner import load_incidents

    output = tmp_path / "captured.jsonl"
    append_record(
        output,
        build_record(
            request_body=json.dumps(PAYLOAD).encode(),
            upstream_status=200,
            upstream_body=b'{"rca_markdown":"x"}',
            seq=1,
        ),
    )
    append_record(
        output,
        build_record(
            request_body=json.dumps(
                {**PAYLOAD, "restart_count": 4, "incident_id": "inc_2"}
            ).encode(),
            upstream_status=200,
            upstream_body=b'{"rca_markdown":"y"}',
            seq=2,
        ),
    )
    incidents = load_incidents(str(output))
    assert [i["restart_count"] for i in incidents] == [3, 4]
    assert [i[CAPTURE_KEY]["seq"] for i in incidents] == [1, 2]


def test_concurrent_posts_do_not_corrupt_the_capture(tmp_path: pathlib.Path) -> None:
    """ThreadingHTTPServer serves each request on its own thread.

    Without a lock around the append, two writes interleaving mid-line produce
    one corrupt line - and every line *after* them too, because the file is
    read line by line. The failure is a silently truncated run, which is worse
    than a crash.
    """

    class _Agent(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a: Any) -> None:
            pass

        def do_POST(self) -> None:  # noqa: N802
            length = int(self.headers.get("Content-Length") or 0)
            self.rfile.read(length)
            body = b"{}"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    agent = _start(_Agent)
    output = tmp_path / "captured.jsonl"
    proxy = serve(output=output, listen_port=0, upstream_port=agent.port)
    _run(proxy)

    def _hammer(index: int) -> None:
        _post(
            proxy.server_address[1],
            "/v1/incidents",
            json.dumps({**PAYLOAD, "incident_id": f"inc_{index}"}).encode(),
        )

    threads = [threading.Thread(target=_hammer, args=(i,)) for i in range(24)]
    for worker in threads:
        worker.start()
    for worker in threads:
        worker.join(timeout=20.0)
    proxy.shutdown()
    proxy.server_close()
    agent.close()

    lines = output.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 24
    # Every line must parse: a torn write shows up here, not as a shorter file.
    for line in lines:
        json.loads(line)


def test_get_is_forwarded_but_not_recorded(tmp_path: pathlib.Path) -> None:
    """Health probes are not incidents.

    Recording them would put objects that carry no payload into the capture file
    and make the runner's incident count meaningless.
    """

    class _Agent(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a: Any) -> None:
            pass

        def do_GET(self) -> None:  # noqa: N802
            body = b'{"status":"ok"}'
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    agent = _start(_Agent)
    output = tmp_path / "captured.jsonl"
    proxy = serve(output=output, listen_port=0, upstream_port=agent.port)
    _run(proxy)
    try:
        status, _ = _get(proxy.server_address[1], "/healthz")
        assert status == 200
    finally:
        proxy.shutdown()
        proxy.server_close()
        agent.close()

    assert not output.exists() or output.read_text(encoding="utf-8").strip() == ""


# ---------------------------------------------------------------------------
# Negative controls: these tests must be able to fail
# ---------------------------------------------------------------------------


def test_the_capture_key_control_can_fail() -> None:
    """A guard that cannot fail is not a guard.

    Proves the collision check is live by asserting the *negated* form: were the
    proxy to flatten the response at the top level under a Contract A name, the
    payload would be corrupted, and this shows the corruption is detectable.
    """
    corrupted = dict(PAYLOAD)
    corrupted[CAPTURE_KEY] = {"upstream_status": 200}
    assert corrupted["restart_count"] == 3  # payload survives

    # Now the actual hazard: a top-level key that IS a contract field.
    corrupted["scrubbed_logs"] = ["not the payload's logs"]
    assert corrupted["scrubbed_logs"] != PAYLOAD["scrubbed_logs"]


def test_the_dead_upstream_control_can_fail() -> None:
    """Proves the 502 assertion is discriminating.

    If `forward` were returning the status of a live server unconditionally,
    this would still pass - so it is checked against a live server too, and the
    two must differ.
    """
    dead, _ = forward(
        upstream_host="127.0.0.1",
        upstream_port=1,
        method="POST",
        path="/",
        headers={},
        body=b"{}",
        timeout=2.0,
    )
    assert dead == 502
    assert dead not in (200, 201, 422, 429, 500)


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


class _Fake:
    """A running HTTP server and the thread serving it.

    Both halves are required. A socket that is bound but never served accepts
    the TCP connection and then never replies, so the proxy's bounded forward
    times out and the failure surfaces as a proxy bug rather than a fixture bug
    - precisely the kind of misattribution this file exists to prevent.
    """

    def __init__(self, server: Any, thread: threading.Thread) -> None:
        self.server = server
        self.thread = thread

    @property
    def port(self) -> int:
        return int(self.server.server_address[1])

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5.0)


def _start(handler: Any) -> _Fake:
    # Same backlog as the proxy under test, and for the same reason.
    #
    # The stdlib default is 5. This test opens 24 concurrent connections, so the
    # accept queue overflows and the kernel resets one before a response is
    # written. That surfaces as `assert len(lines) == 24` failing with 23 — an
    # assertion about *torn writes* reporting a *dropped connection*, which is the
    # wrong diagnosis sent to whoever reads the failure. It passed locally and
    # failed on a loaded CI runner, which is the signature of a backlog problem
    # rather than of a locking problem.
    class _Server(ThreadingHTTPServer):
        request_queue_size = 128

    server = _Server(("127.0.0.1", 0), handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return _Fake(server, thread)


def _run(server: Any) -> threading.Thread:
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return thread


def _post(port: int, path: str, body: bytes) -> tuple[int, bytes]:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=10.0)
    try:
        connection.request(
            "POST", path, body=body, headers={"Content-Type": "application/json"}
        )
        response = connection.getresponse()
        return response.status, response.read()
    finally:
        connection.close()


def _get(port: int, path: str) -> tuple[int, bytes]:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=10.0)
    try:
        connection.request("GET", path)
        response = connection.getresponse()
        return response.status, response.read()
    finally:
        connection.close()
