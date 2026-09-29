"""The disposable analysis worker (ROADMAP §2.4.1).

Executed as ``python -m sandbox_worker <incident.json>`` in a fresh process by
:mod:`sandbox`. It is **not** importable application code: it exists to be
thrown away, and it must stay trivial so that "nothing survives into the next
investigation" is true by construction rather than by remembering to reset
something.

It performs the deterministic analysis only - classification and tier routing,
per ARCH §5.3 - and writes one JSON document to stdout. It performs no I/O beyond
reading the incident file it was given, opens no socket, resolves no name, and
reads no environment variable other than what :mod:`sandbox` explicitly passed.

Two rules it must never break:

* **It must not raise.** An unhandled exception exits non-zero and the parent
  turns that into a ``SandboxError``. A stack trace on stdout would be both noise
  and a disclosure risk, so failures are reported as a structured JSON document
  and the exit code carries the severity.
* **It must not print anything but the JSON.** The parent parses stdout directly.
  A stray print would corrupt it, which is why logging goes nowhere.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Final

__all__ = ["main"]

#: Exit code when the incident could not be analysed at all. Distinct from the
#: "analysed and escalated" case, which is a success.
EXIT_FAILED: Final[int] = 2


def main(argv: list[str]) -> int:
    """Read the incident, analyse it, print the verdict as JSON."""
    if len(argv) != 1:
        print(
            json.dumps(
                {"error": "usage: python -m sandbox_worker <incident.json>"},
            )
        )
        return EXIT_FAILED

    incident_path = Path(argv[0])
    try:
        incident = json.loads(incident_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(json.dumps({"error": f"incident unreadable: {exc}"}))
        return EXIT_FAILED

    # Imported here, not at module scope: the parent sets PYTHONPATH for the
    # child, and importing at module level would make the failure mode of a bad
    # PYTHONPATH an ImportError traceback rather than a structured report.
    from classifier import TierEvidence, TierPolicy, classify, route, siblings_healthy
    from models import IncidentPayload

    try:
        payload = IncidentPayload.model_validate(incident)
    except Exception as exc:  # noqa: BLE001 - any validation failure is a failure
        # Field paths only. Pydantic's default error body can echo the offending
        # input, and this output crosses back into the parent process.
        print(
            json.dumps(
                {
                    "error": "contract_violation",
                    "detail": str(exc).splitlines()[0][:200],
                }
            )
        )
        return EXIT_FAILED

    result = classify(payload)
    decision = route(
        TierEvidence(payload=payload, result=result, policy=TierPolicy(max_restarts=5))
    )

    print(
        json.dumps(
            {
                "classification": result.classification.value,
                "remedy_shape": result.remedy_shape.value,
                "risk_level": result.risk_level.value,
                "blast_radius_tier": decision.tier.value,
                "routing_reasons": list(decision.reasons),
                "satisfied_preconditions": list(decision.satisfied),
                "sibling_containers_healthy": siblings_healthy(payload),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised via the sandbox
    sys.exit(main(sys.argv[1:]))
