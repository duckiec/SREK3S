"""Negative controls on the *wiring*, not the checks.

`test_e2e_response_invariants.py` proves each new invariant can fail, by
calling it directly. That is necessary and not sufficient: it says nothing
about whether ``verify()`` - the function the CI step actually runs - invokes
it. An implemented check that no code path reaches is the failure mode this
project has now produced twice, and it is worse than a missing check because it
makes an untested ROADMAP box look implemented.

So each control here runs the passing scenario the rest of the suite already
builds, breaks it exactly one way, and requires ``verify()`` to go red *and* to
say which item failed. A control that stays green is reported, not skipped.
"""

from __future__ import annotations

import copy
import pathlib
import sys
from typing import Any

import pytest

_E2E_DIR = pathlib.Path(__file__).resolve().parents[2] / "tests" / "e2e"
sys.path.insert(0, str(_E2E_DIR))

from runner import RunReport, verify  # noqa: E402

# The fixtures that build a real GitOps checkout and a capture the engine
# actually produced. Imported under aliases because a fixture must be requested
# by parameter name, and shadowing the imported name is what lets pytest resolve
# it. Importing them as themselves raises F811 on every control below.
from test_e2e_response_invariants import checkout as _checkout_fixture  # noqa: E402
from test_e2e_response_invariants import (  # noqa: E402
    full_lifecycle_observations,
    manifest_text as _manifest_text_fixture,
    matched_capture,
)

checkout = pytest.fixture(scope="module")(_checkout_fixture.__wrapped__)  # type: ignore[attr-defined]
manifest_text = pytest.fixture(scope="module")(_manifest_text_fixture.__wrapped__)  # type: ignore[attr-defined]


def _passing(
    checkout_path: pathlib.Path, text: str
) -> tuple[list[dict[str, Any]], dict[str, Any], dict[str, Any]]:
    """The passing baseline, plus the two snapshots the mutation check needs."""
    healthy: dict[str, Any] = {
        "payments/checkout-api": {
            "resourceVersion": "100",
            "generation": 3,
            "kind": "Deployment",
        }
    }
    return matched_capture(checkout_path), dict(healthy), dict(healthy)


def _run(
    incidents: list[dict[str, Any]],
    text: str,
    before: dict[str, Any],
    after: dict[str, Any],
) -> RunReport:
    return verify(
        incidents,
        full_lifecycle_observations(),
        window=60.0,
        manifest_text=text,
        snapshot_before=before,
        snapshot_after=after,
    )


def _body(record: dict[str, Any]) -> dict[str, Any]:
    return dict((record.get("harness_capture") or {}).get("upstream_body") or {})


def _put(record: dict[str, Any], body: dict[str, Any]) -> None:
    capture = dict(record.get("harness_capture") or {})
    capture["upstream_body"] = body
    record["harness_capture"] = capture


def test_the_baseline_passes(checkout: pathlib.Path, manifest_text: str) -> None:
    """Every control below is void unless the unmodified scenario is green."""
    incidents, before, after = _passing(checkout, manifest_text)
    report = _run(incidents, manifest_text, before, after)
    assert report.passed, report.failures


def control_4_2_3_latency(checkout: pathlib.Path, manifest_text: str) -> None:
    incidents, before, after = _passing(checkout, manifest_text)
    for record in incidents:
        record["detection_latency_ms"] = 999_999
    report = _run(incidents, manifest_text, before, after)
    assert not report.passed, "an over-budget detection latency passed"
    assert any("4.2.3" in f for f in report.failures), report.failures


def control_4_2_5_rca(checkout: pathlib.Path, manifest_text: str) -> None:
    incidents, before, after = _passing(checkout, manifest_text)
    for record in incidents:
        _put(record, {**_body(record), "rca_markdown": "TODO"})
    report = _run(incidents, manifest_text, before, after)
    assert not report.passed, "a boilerplate rca_markdown passed"
    assert any("4.2.5" in f for f in report.failures), report.failures


def control_4_2_6_patch(checkout: pathlib.Path, manifest_text: str) -> None:
    incidents, before, after = _passing(checkout, manifest_text)
    tampered = 0
    for record in incidents:
        body = _body(record)
        remediation = dict(body.get("remediation") or {})
        # `git_patch` lives under `remediation`, not at the top level. The first
        # version of this control wrote `body["git_patch"]`, which the runner
        # never reads - a control that mutates the wrong field proves nothing
        # while appearing to.
        if remediation.get("git_patch"):
            remediation["git_patch"] = "this is not a unified diff\n"
            _put(record, {**body, "remediation": remediation})
            tampered += 1
    assert tampered, "the baseline had no Tier-1 patch to tamper with"
    report = _run(incidents, manifest_text, before, after)
    assert not report.passed, "a Tier-1 patch that real git rejects passed"
    assert any("4.2.6" in f for f in report.failures), report.failures


def control_4_2_7_dispatch(checkout: pathlib.Path, manifest_text: str) -> None:
    incidents, before, after = _passing(checkout, manifest_text)
    changed = 0
    for record in incidents:
        body = _body(record)
        if str(body.get("blast_radius_tier", "")).startswith("TIER_2"):
            remediation = dict(body.get("remediation") or {})
            remediation["git_patch"] = "--- a\n+++ b\n"
            # Strip the marker the runner reads to prove a dispatch happened.
            _put(
                record,
                {
                    **body,
                    "remediation": remediation,
                    "rca_markdown": "Escalated for manual review.",
                },
            )
            changed += 1
    assert changed, "the baseline had no Tier-2 incident"
    report = _run(incidents, manifest_text, before, after)
    assert not report.passed, "a Tier-2 carrying a patch and no dispatch passed"
    assert any("4.2.7" in f for f in report.failures), report.failures


def control_4_2_8_mutation(checkout: pathlib.Path, manifest_text: str) -> None:
    incidents, before, after = _passing(checkout, manifest_text)
    mutated = copy.deepcopy(before)
    mutated["kube-system/coredns"] = {"resourceVersion": "77", "generation": 1}
    report = _run(incidents, manifest_text, before, mutated)
    assert not report.passed, "an out-of-namespace creation passed"
    assert any("4.2.8" in f for f in report.failures), report.failures


@pytest.mark.parametrize(
    "control",
    [
        control_4_2_3_latency,
        control_4_2_5_rca,
        control_4_2_6_patch,
        control_4_2_7_dispatch,
        control_4_2_8_mutation,
    ],
    ids=lambda f: f.__name__.removeprefix("control_"),
)
def test_verify_goes_red_when_each_new_invariant_is_violated(
    control: Any, checkout: pathlib.Path, manifest_text: str
) -> None:
    control(checkout, manifest_text)
