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

import sys
from pathlib import Path

AGENT_DIR = Path(__file__).resolve().parent

if str(AGENT_DIR) not in sys.path:
    sys.path.insert(0, str(AGENT_DIR))
