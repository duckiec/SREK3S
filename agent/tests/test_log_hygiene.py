"""Log-line hygiene for untrusted identifiers.

The agent logs a caller-supplied ``incident_id`` on the contract-violation path,
and it does so *before* the schema has seen it - which is the point of the path,
since the violation is the schema's refusal. So the value reaching the logger is
whatever the caller sent.
"""

from __future__ import annotations

import io
import logging

from fastapi.testclient import TestClient

import main


def drive_contract_violation(body: dict[str, object]) -> str:
    """POST a body that cannot validate, and return everything the agent logged.

    Driven through the real handler rather than by calling the sanitiser, because
    a log line is a claim about what a running service emits, and the claim is only
    true if the running service emits it.
    """
    buffer = io.StringIO()
    handler = logging.StreamHandler(buffer)
    handler.setFormatter(logging.Formatter("%(levelname)s %(name)s %(message)s"))
    root = logging.getLogger()
    root.addHandler(handler)
    previous = root.level
    root.setLevel(logging.INFO)
    try:
        response = TestClient(main.app).post(main.TRIAGE_PATH, json=body)
    finally:
        root.removeHandler(handler)
        root.setLevel(previous)
    assert response.status_code == 422, response.status_code
    return buffer.getvalue()


def violation_lines(logged: str) -> list[str]:
    return [ln for ln in logged.splitlines() if "contract violation" in ln]


class TestSanitiseForLog:
    def test_a_valid_ulid_is_unchanged(self) -> None:
        ulid = "inc_01M4ET3G3MJMFAQQRM8XHJ3M3B"
        assert main.sanitise_for_log(ulid) == ulid

    def test_a_newline_cannot_start_a_second_record(self) -> None:
        forged = "inc_fake\nWARNING forged-record severity=HIGH incident_id=inc_real"
        out = main.sanitise_for_log(forged)
        assert "\n" not in out
        assert out.startswith("inc_fake?WARNING forged-record")

    def test_every_control_character_is_replaced(self) -> None:
        out = main.sanitise_for_log("a\x00b\x07c\x1bd\te\x7ff")
        assert out == "a?b?c?d?e?f"

    def test_length_is_capped(self) -> None:
        out = main.sanitise_for_log("A" * 10_000)
        assert len(out) <= main._MAX_LOGGED_ID_LEN + len("...(truncated)")
        assert out.endswith("...(truncated)")

    def test_a_value_at_the_cap_is_not_truncated(self) -> None:
        exact = "A" * main._MAX_LOGGED_ID_LEN
        assert main.sanitise_for_log(exact) == exact

    def test_non_string_values_render_rather_than_raise(self) -> None:
        """The call site is already handling a malformed request.

        A sanitiser that raised on ``None`` would turn a 422 into a 500, and one
        that raised on a dict would produce a traceback in place of the log line
        the operator needs to see the violation at all.
        """
        assert main.sanitise_for_log(None) == "None"
        assert main.sanitise_for_log(12345) == "12345"
        assert main.sanitise_for_log({"a": 1}) == "{'a': 1}"
        assert main.sanitise_for_log(["x"]) == "['x']"

    def test_the_cap_applies_after_replacement(self) -> None:
        """A payload of pure control characters must not exceed the cap either."""
        out = main.sanitise_for_log("\n" * 10_000, limit=32)
        assert len(out) <= 32 + len("...(truncated)")


class TestTheViolationLogLineIsInert:
    def test_a_hostile_identifier_cannot_forge_a_record(self) -> None:
        logged = drive_contract_violation(
            {
                "incident_id": (
                    "inc_bad\n2026-10-09 ERROR sentinel crashed: database unreachable"
                ),
                "schema_version": "1.0.0",
            }
        )
        lines = [ln for ln in logged.splitlines() if ln.strip()]
        assert len(violation_lines(logged)) == 1, f"one incident, one record: {lines}"
        # The injected text is still present - as evidence of what was sent - but
        # on the same line, so it cannot be mistaken for a second event.
        assert "sentinel crashed" in violation_lines(logged)[0]
        assert not any("sentinel crashed" in ln for ln in lines[1:])

    def test_a_bloated_identifier_is_truncated_in_the_log(self) -> None:
        logged = drive_contract_violation(
            {"incident_id": "inc_" + "Z" * 20_000, "schema_version": "1.0.0"}
        )
        assert len(violation_lines(logged)) == 1
        assert (
            len(violation_lines(logged)[0]) < 512
        ), "a caller must not size the log line"
        assert "truncated" in violation_lines(logged)[0]

    def test_an_absent_identifier_is_named_as_absent(self) -> None:
        logged = drive_contract_violation({"schema_version": "1.0.0"})
        assert len(violation_lines(logged)) == 1, logged
        assert "<absent>" in violation_lines(logged)[0]

    def test_no_value_type_can_break_the_log_line(self) -> None:
        """body.get returns whatever the JSON decoder produced."""
        for value in (None, 42, {"incident_id": "x"}, ["a", "b"]):
            logged = drive_contract_violation(
                {"incident_id": value, "schema_version": "1.0.0"}
            )
            assert len(violation_lines(logged)) == 1, (value, logged)
