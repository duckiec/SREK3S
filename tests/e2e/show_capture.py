"""Print one captured exchange, readably.

Exists because the E2E workflow has to show a reviewer what the agent actually
proposed, and a `git_patch` is a multi-line string that no amount of grep makes
legible. It is a harness utility: it reads a file the capture proxy wrote and
prints it. It opens nothing else, mutates nothing, and takes no cluster action.

Usage: ``python tests/e2e/show_capture.py /tmp/one-capture.json``
"""

from __future__ import annotations

import json
import pathlib
import sys
from typing import Any

CAPTURE_KEY = "harness_capture"

PAYLOAD_FIELDS = (
    "incident_id",
    "namespace",
    "pod_name",
    "container_name",
    "reason",
    "exit_code",
    "restart_count",
    "previous_reason",
    "detection_latency_ms",
)


def _summary(record: dict[str, Any]) -> None:
    print("  --- incident payload ---")
    for field in PAYLOAD_FIELDS:
        if field in record:
            print("    {:<24} {}".format(field, record[field]))
    logs = record.get("scrubbed_logs")
    if isinstance(logs, list):
        masked = sum(1 for line in logs if "[REDACTED]" in str(line))
        print(
            "    {:<24} {} lines, {} masked".format("scrubbed_logs", len(logs), masked)
        )
        for line in logs[:4]:
            print("        {}".format(line))
        if len(logs) > 4:
            print("        ... {} more".format(len(logs) - 4))


def _response(record: dict[str, Any]) -> None:
    capture = record.get(CAPTURE_KEY) or {}
    body = capture.get("upstream_body")
    if not isinstance(body, dict):
        print("  --- TriageResponse ---")
        print(
            "    (none captured; upstream status {})".format(
                capture.get("upstream_status")
            )
        )
        return

    print("  --- TriageResponse ---")
    print("    {:<24} {}".format("blast_radius_tier", body.get("blast_radius_tier")))
    print("    {:<24} {}".format("status", body.get("status")))
    rca = body.get("rca_markdown")
    if isinstance(rca, str):
        print("    rca_markdown ({} chars):".format(len(rca)))
        for line in rca.splitlines()[:8]:
            print("        {}".format(line))
    remediation = body.get("remediation") or {}
    patch = remediation.get("git_patch") or ""
    print("    {:<24} {}".format("patch_validated", remediation.get("patch_validated")))
    if patch:
        print("    --- git_patch ({} bytes) ---".format(len(patch)))
        for line in patch.splitlines():
            print("        {}".format(line))
    else:
        print("    git_patch               (empty)")


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 1:
        print("usage: show_capture.py <capture.json>", file=sys.stderr)
        return 2
    path = pathlib.Path(args[0])
    if not path.is_file():
        print("  (no capture at {})".format(path))
        return 0
    try:
        record = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        print("  (unreadable capture: {})".format(error))
        return 0
    if not isinstance(record, dict):
        print("  (capture is a {}, not an object)".format(type(record).__name__))
        return 0
    _summary(record)
    _response(record)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
