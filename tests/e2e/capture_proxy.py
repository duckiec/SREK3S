"""Wire capture proxy for the E2E detonation.

Why this exists
---------------
ROADMAP 4.2.1 requires a runner that "collects emitted payloads", and 4.2.4
through 4.2.7 are all assertions *over collected payloads*. Until something puts
the wire bytes where the runner can see them, every one of those boxes is
unprovable, and ``tests/e2e/runner.py`` cannot pass: with no ``--incident-file``
its ``incidents`` list is always empty, so ``check_incident_window([])`` raises
and the step exits 1 on every run.

The alternative - having the Sentinel write the payload to disk - was rejected.
ARCHITECTURE.md line 30 places the scrubber behind "no disk, no plaintext
retention", and the reasoning holds even though that line constrains the
scrubber rather than the emitter: the harness must stay external to the binary
whose behaviour it is measuring. So this proxy sits between the two, records
what crossed, and changes no production code.

The hazard this design has to manage
------------------------------------
An instrument on the wire can perturb the thing it measures. The Sentinel's
emitter branches on the response status - 429 is retried, 422 is fatal and not
retried, 500 escalates - so a proxy that mangled a status code would change the
retry behaviour under test and produce a green run that proved nothing. Three
consequences, all of them load-bearing:

* the upstream status and body are passed through **verbatim**, never
  reinterpreted or normalised;
* every request is forwarded on a **separate connection with a bounded
  timeout**, so a hung upstream cannot hold a worker open indefinitely;
* a record is flushed to disk as soon as it is written, so a proxy killed at
  teardown cannot lose the exchange it was in the middle of recording.

Imports are pure stdlib by charter (ARCH 9): no test dependency, nothing added
to the agent's requirements.
"""

from __future__ import annotations

import argparse
import http.client
import json
import pathlib
import threading
import time
from collections.abc import Sequence
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Final

DEFAULT_LISTEN: Final[str] = "127.0.0.1"
DEFAULT_LISTEN_PORT: Final[int] = 8001
DEFAULT_UPSTREAM: Final[str] = "127.0.0.1"
DEFAULT_UPSTREAM_PORT: Final[int] = 8000
DEFAULT_OUTPUT: Final[str] = "/tmp/captured_incidents.jsonl"

# Bounded because the emitter has its own per-request deadline
# (emitter.DefaultTimeout). A proxy that waits longer than the client is
# already worse than no proxy: it turns a timeout into a stall.
DEFAULT_UPSTREAM_TIMEOUT: Final[float] = 10.0

# Hop-by-hop headers (RFC 9110 7.6.1). These describe the connection they
# arrived on, not the message, and forwarding them corrupts the next hop.
# Content-Length and Transfer-Encoding are deliberately excluded from the
# forwarded set: http.client computes Content-Length from the body we hand it,
# and a stale Content-Length from the inbound request would be a lie.
HOP_BY_HOP: Final[frozenset[str]] = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "trailers",
        "transfer-encoding",
        "upgrade",
        "content-length",
        "host",
    }
)

# Namespaced so it cannot shadow a Contract A field. ARCH 4.1 fixes the payload
# keys; adding a top-level key of our own would risk colliding with a field
# added later, and the runner reads the payload with .get(), so a collision
# would be silent.
CAPTURE_KEY: Final[str] = "harness_capture"


def _decode_json(raw: bytes) -> Any:
    """Parse JSON, or return ``None`` rather than raising.

    A body that is not JSON must not be able to stop the proxy recording. The
    exchange is still evidence - the raw text is kept - so the failure is
    downgraded to "no structured form" instead of being swallowed.
    """
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None


def build_record(
    *,
    request_body: bytes,
    upstream_status: int,
    upstream_body: bytes,
    seq: int,
    monotonic: float | None = None,
) -> dict[str, Any]:
    """One captured exchange, shaped for the runner's invariants.

    The payload's own fields stay at the **top level** because that is the shape
    ``tests/e2e/runner.py`` asserts against: it reads ``restart_count``,
    ``reason`` and ``scrubbed_logs`` with ``.get()``, so a nested wrapper would
    make every incident look like an empty one. The response is namespaced under
    :data:`CAPTURE_KEY` instead, which keeps ROADMAP 4.2.5-4.2.7 (``rca_markdown``,
    ``git_patch``, war-room dispatch) answerable from the same file.
    """
    decoded = _decode_json(request_body)
    response = _decode_json(upstream_body)

    capture: dict[str, Any] = {
        "seq": seq,
        "upstream_status": upstream_status,
        "upstream_body": response,
        "method": "POST",
    }
    if response is None:
        capture["upstream_body_text"] = upstream_body.decode("utf-8", "replace")
    if monotonic is not None:
        # perf_counter, never wall clock: this is a duration, not a timestamp,
        # and a wall clock can go backwards (AGENTS 3.5).
        capture["monotonic"] = monotonic

    if isinstance(decoded, dict):
        record = dict(decoded)
        record[CAPTURE_KEY] = capture
        return record

    # Not a JSON object. Still record it, under a shape the runner will treat as
    # an incident with no payload - which fails the invariants, correctly,
    # rather than vanishing and making the capture look partial.
    capture["request_body_text"] = request_body.decode("utf-8", "replace")
    capture["request_was_not_an_object"] = True
    return {CAPTURE_KEY: capture}


def append_record(path: pathlib.Path, record: dict[str, Any]) -> None:
    """Append one NDJSON line and flush it.

    Flushed per record, not per batch: the proxy is killed at teardown while
    exchanges may still be in flight, and a buffered write would discard the
    evidence for exactly the incidents a reviewer wants to read.
    """
    line = json.dumps(record, separators=(",", ":"), sort_keys=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(line + "\n")
        handle.flush()


def forward(
    *,
    upstream_host: str,
    upstream_port: int,
    method: str,
    path: str,
    headers: dict[str, str],
    body: bytes,
    timeout: float,
) -> tuple[int, bytes]:
    """Send one request upstream and return ``(status, body)`` verbatim.

    A connection failure surfaces as 502 rather than propagating, because a
    handler that raises leaves the Sentinel to distinguish a broken proxy from a
    broken agent - and it cannot, because both arrive as a transport error. 502
    is not a status the emitter retries, so a genuinely dead upstream escalates
    instead of spinning, which is the correct reading.
    """
    connection = http.client.HTTPConnection(
        upstream_host, upstream_port, timeout=timeout
    )
    try:
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        return response.status, response.read()
    except (OSError, http.client.HTTPException) as error:
        return 502, json.dumps(
            {"error": "capture_proxy_upstream", "detail": str(error)}
        ).encode("utf-8")
    finally:
        connection.close()


class _Handler(BaseHTTPRequestHandler):
    """Forwards to the agent and records the exchange."""

    server_version = "srek3s-capture-proxy/1.0"
    # HTTP/1.1 so the emitter's connection pool can be reused. It obliges us to
    # send an accurate Content-Length on every response including error paths,
    # which is why _respond is the only place a response is ever written.
    protocol_version = "HTTP/1.1"

    upstream_host: str
    upstream_port: int
    upstream_timeout: float
    output: pathlib.Path
    lock: threading.Lock
    counter: int

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        """Silence the default stderr access log.

        The proxy's own log would interleave with the runner's captured output
        in the CI console, and the runner is what a reviewer reads.
        """

    def _respond(self, status: int, body: bytes, content_type: str) -> None:
        """The single write path, so Content-Length is never omitted."""
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _record(self, record: dict[str, Any]) -> None:
        # Serialised: ThreadingHTTPServer serves each request on its own
        # thread, and two appends interleaving mid-line would corrupt the NDJSON
        # for every line after them, not just the racing one.
        with self.lock:
            append_record(self.output, record)

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""

        headers = {
            key: value
            for key, value in self.headers.items()
            if key.lower() not in HOP_BY_HOP
        }
        status, response_body = forward(
            upstream_host=self.upstream_host,
            upstream_port=self.upstream_port,
            method="POST",
            path=self.path,
            headers=headers,
            body=body,
            timeout=self.upstream_timeout,
        )

        with self.lock:
            self.counter += 1
            seq = self.counter
        self._record(
            build_record(
                request_body=body,
                upstream_status=status,
                upstream_body=response_body,
                seq=seq,
                monotonic=time.perf_counter(),
            )
        )

        content_type = self.headers.get("Content-Type") or "application/json"
        self._respond(status, response_body, content_type)

    def do_GET(self) -> None:  # noqa: N802
        """Forward reads without recording.

        The health probes are not incidents, and recording them would put
        non-incident objects in the capture file.
        """
        status, body = forward(
            upstream_host=self.upstream_host,
            upstream_port=self.upstream_port,
            method="GET",
            path=self.path,
            headers={},
            body=b"",
            timeout=self.upstream_timeout,
        )
        self._respond(status, body, "application/json")


def serve(
    *,
    output: pathlib.Path,
    listen_host: str = DEFAULT_LISTEN,
    listen_port: int = DEFAULT_LISTEN_PORT,
    upstream_host: str = DEFAULT_UPSTREAM,
    upstream_port: int = DEFAULT_UPSTREAM_PORT,
    timeout: float = DEFAULT_UPSTREAM_TIMEOUT,
) -> ThreadingHTTPServer:
    """Build a configured server without starting it.

    Split from :func:`main` so tests can bind port 0 and get a real socket
    rather than asserting against a mock of the handler.
    """
    output.parent.mkdir(parents=True, exist_ok=True)
    handler = type(
        "ConfiguredHandler",
        (_Handler,),
        {
            "upstream_host": upstream_host,
            "upstream_port": upstream_port,
            "upstream_timeout": timeout,
            "output": output,
            "lock": threading.Lock(),
            "counter": 0,
        },
    )
    server = ThreadingHTTPServer((listen_host, listen_port), handler)
    server.daemon_threads = True
    return server


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default=DEFAULT_OUTPUT)
    parser.add_argument("--listen-host", default=DEFAULT_LISTEN)
    parser.add_argument("--listen-port", type=int, default=DEFAULT_LISTEN_PORT)
    parser.add_argument("--upstream-host", default=DEFAULT_UPSTREAM)
    parser.add_argument("--upstream-port", type=int, default=DEFAULT_UPSTREAM_PORT)
    parser.add_argument(
        "--upstream-timeout", type=float, default=DEFAULT_UPSTREAM_TIMEOUT
    )
    args = parser.parse_args(argv)

    server = serve(
        output=pathlib.Path(args.output),
        listen_host=args.listen_host,
        listen_port=args.listen_port,
        upstream_host=args.upstream_host,
        upstream_port=args.upstream_port,
        timeout=args.upstream_timeout,
    )
    host = str(server.server_address[0])
    port = int(server.server_address[1])
    print(f"capture proxy listening on {host}:{port}")
    print(f"  upstream {args.upstream_host}:{args.upstream_port}")
    print(f"  writing to {args.output}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
