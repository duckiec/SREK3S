"""Pytest bootstrap for the SREK3S Triage Agent.

ARCHITECTURE.md §3 describes ``agent/`` as a flat module: ``models.py`` is the
schema source of truth and is imported as a top-level module, not as part of an
installed package. There is deliberately no ``__init__.py``.

That layout means ``import models`` only resolves when ``agent/`` is on
``sys.path``. It is when pytest runs from ``agent/``, but the charter's gate
command is ``pytest agent/tests/`` from the repository root, where it does not.
This file puts the directory on the path so both invocations behave identically
and the gate command does not depend on the working directory.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

AGENT_DIR = Path(__file__).resolve().parent

if str(AGENT_DIR) not in sys.path:
    sys.path.insert(0, str(AGENT_DIR))

#: Configure a patch target for the whole test session.
#:
#: `classifier.TARGET_MANIFEST` is resolved once, at import, and
#: `classifier.DEFAULT_TARGET_MANIFEST` is empty: the agent ships no default,
#: so an unset variable means no patch target and every escalation carries an
#: empty `remediation.target_manifest`. Every test that exercises the Tier-1
#: path - I-B2 verification, the diff, the wire shape - needs a target, and
#: setting it here rather than per-test means those tests cover the configured
#: deployment, which is the only deployment in which Tier-1 exists.
#:
#: It has to happen here, before any test module imports `classifier`, because
#: resolution is deliberately import-time and per-test `monkeypatch.setenv`
#: would arrive too late. `deploy/chaos/oom-leak.yaml` is the fixture the
#: incident is generated from in-cluster (`deploy/overlays/local-live` and
#: `.github/workflows/e2e-detonation.yaml` both set it), so the tests and the
#: detonation agree on what the target is. Assigned rather than defaulted, so a
#: gate run does not depend on the shell it was launched from.
os.environ["SREK3S_TARGET_MANIFEST"] = "deploy/chaos/oom-leak.yaml"
