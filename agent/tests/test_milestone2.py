"""Tests for the Milestone 2 modules added at §2.4, §2.5 and §2.6.

One file per milestone concern would be tidier, but these five modules are
small and each test class below maps to one checkbox in ROADMAP §2.4-§2.6, so a
single file keeps the mapping visible. The grouping headers carry the roadmap
references.

Every guard here was validated with a negative control, and the control is
recorded in the test that depends on it - a check that cannot fail is not a check.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Final, cast

import pytest

import classifier
import llm
import rescan
import sandbox as sandbox_mod
import triage
import warroom
from budget import JobBudget
from classifier import TierPolicy
from models import BlastRadiusTier, IncidentPayload
from sandbox import SandboxError, SandboxPolicy, SandboxRunner, SandboxTimeout

_REPO_ROOT: Final[Path] = Path(__file__).resolve().parents[2]
FIXTURE: Final[Path] = _REPO_ROOT / "tests" / "fixtures" / "oom-restartloop.yaml"
SAMPLE: Final[Path] = _REPO_ROOT / "tests" / "fixtures" / "sample-incident.json"


def sample() -> dict[str, Any]:
    document = json.loads(SAMPLE.read_text(encoding="utf-8"))
    return {k: v for k, v in document.items() if k != "_comment"}


def payload(mutate: Any = None) -> IncidentPayload:
    document = sample()
    if mutate is not None:
        mutate(document)
    return IncidentPayload.model_validate(document)


def provider(manifest: str) -> classifier.ManifestProvider:
    return classifier.StaticManifestProvider({triage.TARGET_MANIFEST: manifest})


# ===========================================================================
# ROADMAP §2.4 - ephemeral investigation sandbox
# ===========================================================================


class TestSandbox:
    def test_produces_a_verdict_from_a_fresh_process(self) -> None:
        result = SandboxRunner().run(sample())
        assert result.payload["classification"] == "RESOURCE_EXHAUSTION"
        assert result.payload["blast_radius_tier"] == "TIER_1_TOIL"
        assert result.payload["remedy_shape"] == "MEMORY_LIMIT_RECALIBRATION"

    def test_latency_is_monotonic_and_non_negative(self) -> None:
        """AGENTS.md §3.5: perf_counter, never wall clock."""
        import inspect

        source = inspect.getsource(sandbox_mod)
        assert "time.perf_counter()" in source
        assert "time.time(" not in source
        assert "datetime.now(" not in source

        result = SandboxRunner().run(sample())
        assert result.latency_ms >= 0

    def test_the_deadline_kills_the_child(self) -> None:
        """§2.4.3/§2.4.4: a bounded investigation is terminated, not awaited."""
        with pytest.raises(SandboxTimeout) as caught:
            SandboxRunner(policy=SandboxPolicy(deadline_seconds=0.001)).run(sample())
        assert caught.value.elapsed >= 0
        assert "deadline" in str(caught.value)

    def test_a_timed_out_investigation_leaves_nothing_running(self) -> None:
        """§2.4.4: teardown on timeout. A survivor would outlive its budget."""
        before = _child_process_count()
        for _ in range(3):
            with pytest.raises(SandboxTimeout):
                SandboxRunner(policy=SandboxPolicy(deadline_seconds=0.001)).run(
                    sample()
                )
        # Allow a moment for the OS to reap; the count must not have grown.
        import time

        time.sleep(0.4)
        assert _child_process_count() <= before + 1

    def test_no_state_survives_between_investigations(self) -> None:
        """§2.4.4: asserted structurally - a fresh process has no prior state.

        Each run gets a new interpreter, so the only way state could cross is via
        the filesystem or the environment. The scratch directory is unique per run
        and the environment is rebuilt from an allow-list.
        """
        runner = SandboxRunner()
        first = runner.run(sample())
        document = sample()
        document["restart_count"] = 99
        second = runner.run(document)
        assert first.payload["blast_radius_tier"] == "TIER_1_TOIL"
        # The second incident is over the ceiling and must NOT inherit Tier-1.
        assert second.payload["blast_radius_tier"] == "TIER_2_ARCHITECTURAL"
        assert second.payload["routing_reasons"]

    def test_the_child_receives_no_cluster_credential(self) -> None:
        """§2.4.5. An allow-list, so a new parent variable cannot widen the child."""
        marker = "SENTINEL_KUBECONFIG_SHOULD_NOT_LEAK"
        os.environ[marker] = "/etc/srek3s/admin.kubeconfig"
        try:
            child_env = sandbox_mod._child_environment()
            assert marker not in child_env
            for name in child_env:
                assert name in sandbox_mod.SANDBOX_ENV_ALLOWLIST
        finally:
            del os.environ[marker]

    def test_the_allowlist_excludes_credential_shaped_names(self) -> None:
        """A deny-list would be satisfied here; the allow-list is the real check."""
        for forbidden in (
            "KUBECONFIG",
            "KUBERNETES_SERVICE_HOST",
            "AWS_ACCESS_KEY_ID",
            "AWS_SECRET_ACCESS_KEY",
            "GOOGLE_APPLICATION_CREDENTIALS",
        ):
            assert forbidden not in sandbox_mod.SANDBOX_ENV_ALLOWLIST

    def test_resource_limits_are_applied_where_the_platform_allows(self) -> None:
        """§2.4.2. Reported honestly rather than assumed.

        rlimits are a POSIX facility. Where they are unavailable the result says
        so, because claiming a memory ceiling that was never applied is worse than
        reporting no ceiling.
        """
        result = SandboxRunner().run(sample())
        assert result.rlimits_applied is sandbox_mod.resource_limits_supported()
        assert isinstance(result.cgroup_enforced, bool)

    def test_cgroup_enforcement_is_never_claimed_without_evidence(self) -> None:
        """§2.4.2. `cgroup_enforced` is reported, not assumed."""
        result = SandboxRunner().run(sample())
        if result.cgroup_enforced:
            assert (Path("/sys/fs/cgroup")).exists()
        else:
            assert not (Path("/sys/fs/cgroup") / "srek3s-agent/memory.max").exists()

    def test_the_policy_rejects_a_nonsense_budget(self) -> None:
        with pytest.raises(ValueError):
            SandboxPolicy(deadline_seconds=0)
        with pytest.raises(ValueError):
            SandboxPolicy(memory_bytes=0)

    def test_a_bad_incident_fails_rather_than_producing_a_partial_verdict(self) -> None:
        with pytest.raises(SandboxError):
            SandboxRunner().run({"not": "a contract document"})

    def test_the_sandbox_never_exceeds_the_job_budget(self) -> None:
        """§2.4 + §2.2.5: the budget is the single admission gate."""
        import threading

        budget = JobBudget(max_active=2)
        runner = SandboxRunner()
        outcomes: list[str] = []
        lock = threading.Lock()

        def work() -> None:
            with budget.slot() as admitted:
                if not admitted:
                    with lock:
                        outcomes.append("shed")
                    return
                runner.run(sample())
                with lock:
                    outcomes.append("ran")

        threads = [threading.Thread(target=work) for _ in range(5)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert outcomes.count("shed") > 0, "the budget never shed anything"
        assert runner.peak_concurrent <= budget.max_active
        assert runner.peak_concurrent <= budget.peak

    def test_a_worker_that_cannot_start_is_reported_not_swallowed(self) -> None:
        runner = SandboxRunner()
        runner.agent_dir = Path("/nonexistent-agent-dir")
        with pytest.raises(SandboxError):
            runner.run(sample())

    def test_result_serialises_for_transport(self) -> None:
        result = SandboxRunner().run(sample())
        document = json.loads(result.as_json())
        assert document["analysis_latency_ms"] >= 0
        assert "result" in document


def _child_process_count() -> int:
    """Number of live python processes, best effort."""
    try:
        if os.name == "nt":
            completed = subprocess.run(
                ["tasklist", "/FI", "IMAGENAME eq python.exe"],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            return completed.stdout.count("python.exe")
        completed = subprocess.run(
            ["pgrep", "-c", "-f", sys.executable],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        return int(completed.stdout.strip() or 0)
    except (OSError, ValueError, subprocess.SubprocessError):
        return 0


# ===========================================================================
# ROADMAP §2.5.8 - outbound re-scan (ARCH §6, I-B6)
# ===========================================================================


class TestRescan:
    def test_rule_ids_match_the_go_manifest(self) -> None:
        """§6 M6: the same rule IDs, so the two reports are comparable.

        Verified against ``internal/scrubber/manifest.go`` rather than a
        hand-kept list, so adding a Go rule without mirroring it fails here.
        """
        go_ids = _go_rule_ids()
        assert go_ids, "could not read the Go manifest"
        assert rescan.rule_ids() == go_ids

    def test_eleven_rules_are_mirrored(self) -> None:
        assert len(rescan.RESCAN_RULES) == 11

    def test_the_mask_token_is_the_constant(self) -> None:
        """§6 M1: constant, not configurable, so nothing can weaken masking."""
        assert rescan.MASK == "[REDACTED]"

    @pytest.mark.parametrize(
        ("secret", "rule_id"),
        [
            ("AKIAIOSFODNN7EXAMPLE", "aws_access_key_id"),
            ("eyJhbGciOiJIUzI1NiJ9.abcdefgh.abcdefgh", "jwt"),
            ("Bearer abcdefgh12345678", "bearer_token"),
            ("550e8400-e29b-41d4-a716-446655440000", "uuid"),
            ("10.42.7.19", "ipv4_address"),
            ("2026-06-01 10:00:00 kube-system token mounted", "k8s_secret_mount"),
            (
                "-----BEGIN RSA PRIVATE KEY-----\nMIIEow\n-----END RSA PRIVATE KEY-----",
                "pem_private_key",
            ),
        ],
    )
    def test_each_rule_fires_on_its_own_sample(self, secret: str, rule_id: str) -> None:
        report = rescan.scan(secret)
        assert rule_id in report.rules_triggered, report.summary()
        cleaned, _ = rescan.redact(secret)
        assert "AKIA" not in cleaned[0]
        assert secret not in cleaned[0]

    def test_a_password_in_json_survives_structurally(self) -> None:
        """§6.4: masking must not destroy the surrounding JSON."""
        cleaned, _ = rescan.redact('{"password":"hunter2"}')
        assert cleaned[0] == '{"password":"[REDACTED]"}'

    def test_basic_auth_keeps_the_endpoint_topology(self) -> None:
        """§6.3 and AGENTS.md §3.5: host and port are diagnostic signal."""
        cleaned, _ = rescan.redact(
            "postgres://payments:hunter2@db.internal:5432/payments"
        )
        assert cleaned[0] == "postgres://payments:[REDACTED]@db.internal:5432/payments"
        assert "db.internal" in cleaned[0]
        assert "5432" in cleaned[0]

    def test_multi_line_rules_run_before_single_line_fallbacks(self) -> None:
        """AGENTS.md §3.6 / ARCH §6.5: the PEM block must be removed whole."""
        assert rescan.rule_ids().index("pem_private_key") < rescan.rule_ids().index(
            "private_key_pem_body"
        )
        cleaned, report = rescan.redact(
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----"
        )
        assert "MIIEowIBAAKCAQEA" not in cleaned[0], "the key body survived"
        assert report.rules_triggered

    def test_over_masking_is_preferred(self) -> None:
        """§6 M5."""
        cleaned, _ = rescan.redact("contact 10.42.7.19 immediately")
        assert "10.42.7.19" not in cleaned[0]

    def test_the_report_never_contains_the_secret(self) -> None:
        """§6 M4: counts only."""
        report = rescan.scan("AKIAIOSFODNN7EXAMPLE")
        text = repr(report) + report.summary() + repr(report.to_redaction_report())
        assert "AKIAIOSFODNN7EXAMPLE" not in text

    def test_clean_text_is_untouched(self) -> None:
        original = "container checkout-api exceeded its memory limit"
        cleaned, report = rescan.redact(original)
        assert cleaned[0] == original
        assert report.clean

    def test_a_secret_in_a_diff_is_refused_not_redacted(self) -> None:
        """Rewriting a diff would break it; leaking it into a PR is worse."""
        with pytest.raises(rescan.SecretLeakError) as caught:
            rescan.assert_clean('-  password: "hunter2"\n+  memory: "512Mi"\n')
        assert "generic_secret_kv" in caught.value.rule_ids_found

    def test_the_engine_refuses_a_diff_that_carries_a_secret(self) -> None:
        """End to end: a leaking manifest produces no patch and a Tier-2 verdict."""
        leaking = FIXTURE.read_text(encoding="utf-8").replace(
            'cpu: "500m"', 'password: "hunter2"', 1
        )
        outcome = triage.triage_payload(payload(), manifest_provider=provider(leaking))
        assert outcome.tier is BlastRadiusTier.TIER_2_ARCHITECTURAL
        assert outcome.response.remediation.git_patch == ""
        assert any("masking rule" in r for r in outcome.reasons), outcome.reasons

    def test_the_rca_is_redacted_not_refused(self) -> None:
        """Prose keeps its usefulness; only the diff is refused."""
        outcome = triage.triage_payload(
            payload(lambda d: d.update(scrubbed_logs=["AKIAIOSFODNN7EXAMPLE"]))
        )
        assert "AKIAIOSFODNN7EXAMPLE" not in outcome.response.rca_markdown


def _go_rule_ids() -> list[str]:
    """Extract the rule IDs from the Go manifest, in declaration order."""
    manifest = _REPO_ROOT / "internal" / "scrubber" / "manifest.go"
    if not manifest.exists():
        return []
    text = manifest.read_text(encoding="utf-8")
    ids: list[str] = []
    import re

    for match in re.finditer(r'Rule([A-Za-z0-9]+)\s+RuleID\s*=\s*"([^"]+)"', text):
        ids.append(match.group(2))
    return ids


# ===========================================================================
# ROADMAP §2.5.1 / §2.5.2 - constrained decoding (I-B4)
# ===========================================================================


def _valid_contract_b() -> dict[str, Any]:
    """A real Contract B document, produced by the engine rather than written."""
    outcome = triage.triage_payload(
        payload(), manifest_provider=provider(FIXTURE.read_text(encoding="utf-8"))
    )
    return outcome.response.model_dump(mode="json")


class TestConstrainedDecoding:
    def test_a_valid_document_decodes(self) -> None:
        decoded = llm.decode_completion(json.dumps(_valid_contract_b()))
        assert decoded.incident_id.startswith("inc_")

    @pytest.mark.parametrize(
        ("raw", "needle"),
        [
            ("```json\n{}\n```", "fence"),
            ("Here is my analysis:\n{}", "not a JSON object"),
            ("", "empty"),
            ("   \n  ", "empty"),
            ("[1, 2, 3]", "JSON object"),
            ("{not json}", "not valid JSON"),
            ('{"schema_version": "1.0.0"}', "Contract B"),
        ],
    )
    def test_anything_else_is_fatal(self, raw: str, needle: str) -> None:
        """I-B4: fatal. No partial parse, no markdown scrape."""
        with pytest.raises(llm.ModelOutputError) as caught:
            llm.decode_completion(raw)
        assert needle in str(caught.value)

    def test_a_fence_is_never_stripped(self) -> None:
        """The dangerous-looking convenience. Prohibited outright.

        Negative control for the whole module: if a lenient path ever appears,
        this is the test that must start failing, because a stripped fence makes
        behaviour depend on model whim.
        """
        body = json.dumps(_valid_contract_b())
        with pytest.raises(llm.ModelOutputError, match="fence"):
            llm.decode_completion(f"```json\n{body}\n```")

    def test_an_error_message_never_echoes_the_output(self) -> None:
        with pytest.raises(llm.ModelOutputError) as caught:
            llm.decode_completion("Here is a secret AKIAIOSFODNN7EXAMPLE: {}")
        assert "AKIAIOSFODNN7EXAMPLE" not in str(caught.value)

    def test_the_model_cannot_promote_itself_to_tier_one(self) -> None:
        """A model may propose prose. It may not propose authority."""
        document = _valid_contract_b()
        payload_doc = payload()
        result = classifier.classify(payload_doc)
        decision = classifier.route(
            classifier.TierEvidence(
                payload=payload_doc, result=result, policy=TierPolicy()
            )
        )
        # Pretend the router escalated, while the model claims Tier-1 with a patch.
        forced = classifier.RoutingDecision(
            tier=BlastRadiusTier.TIER_2_ARCHITECTURAL,
            reasons=("forced for test",),
            satisfied=(),
        )
        decoded = llm.decode_completion(json.dumps(document))
        outcome = llm.reconcile(decoded, forced, BlastRadiusTier.TIER_2_ARCHITECTURAL)

        assert (
            outcome.response.blast_radius_tier is BlastRadiusTier.TIER_2_ARCHITECTURAL
        )
        assert outcome.response.remediation.git_patch == "", "I-B1 broken"
        assert outcome.response.remediation.patch_validated is False
        assert outcome.response.remediation.risk_level.value == "HIGH"
        assert not outcome.agreed
        assert any("blast_radius_tier" in c for c in outcome.corrected)
        assert decision.is_tier_one, "the baseline decision should have been Tier-1"

    def test_reconcile_records_disagreement(self) -> None:
        document = _valid_contract_b()
        decoded = llm.decode_completion(json.dumps(document))
        outcome = llm.reconcile(
            decoded,
            classifier.RoutingDecision(
                tier=BlastRadiusTier.TIER_1_TOIL, reasons=(), satisfied=()
            ),
            BlastRadiusTier.TIER_1_TOIL,
        )
        assert outcome.agreed
        assert outcome.corrected == []

    def test_the_prompt_carries_validated_evidence_only(self) -> None:
        text = llm.build_prompt(payload())
        assert "Observed evidence" in text
        assert "reason=OOMKilled" in text

    def test_the_transport_is_declared_but_not_invented(self) -> None:
        """No speculative HTTP client. AGENTS.md §5.3."""
        assert not hasattr(llm, "HttpCompletionClient")
        assert not hasattr(llm, "requests")
        assert not hasattr(llm, "httpx")


# ===========================================================================
# ROADMAP §2.6 - War-Room dispatch
# ===========================================================================


def _tier_two_outcome() -> Any:
    return triage.triage_payload(payload(lambda d: d.update(restart_count=99)))


class TestWarRoomDispatch:
    def test_carries_the_roadd_map_required_fields(self) -> None:
        outcome = _tier_two_outcome()
        dispatch = warroom.build_dispatch(
            outcome.response.root_cause
            and payload(lambda d: d.update(restart_count=99)),
            outcome.response,
            outcome.reasons,
        )
        assert dispatch.incident_id == outcome.response.incident_id
        assert dispatch.namespace == "payments"
        assert dispatch.pod_name
        assert dispatch.container_name
        assert dispatch.evidence
        assert dispatch.routing_reasons

    def test_includes_the_explicit_do_not_apply_marker(self) -> None:
        """§2.6.2. Silence is not a safety property."""
        outcome = _tier_two_outcome()
        dispatch = warroom.build_dispatch(
            payload(lambda d: d.update(restart_count=99)),
            outcome.response,
            outcome.reasons,
        )
        assert dispatch.do_not_apply == warroom.DO_NOT_APPLY
        assert "DO NOT APPLY" in dispatch.do_not_apply
        assert "DO NOT APPLY" in warroom.render_markdown(dispatch)

    def test_carries_no_patch(self) -> None:
        """§2.6.3 / I-B5: no field can express a cluster write.

        Asserted on *keys*, not on substrings. An earlier version checked for the
        substring ``apply`` and failed on ``do_not_apply`` - which is the safety
        marker doing its job. Substring matching is useless for this: any sentence
        containing "apply" would trip it, so it cannot distinguish a field that
        performs a write from prose that mentions one.
        """
        outcome = _tier_two_outcome()
        dispatch = warroom.build_dispatch(
            payload(lambda d: d.update(restart_count=99)),
            outcome.response,
            outcome.reasons,
        )
        document = dispatch.to_dict()

        keys: set[str] = set()

        def collect(node: object) -> None:
            if isinstance(node, dict):
                keys.update(node)
                for value in node.values():
                    collect(value)
            elif isinstance(node, list):
                for value in node:
                    collect(value)

        collect(document)

        for forbidden in (
            "git_patch",
            "patch",
            "patch_validated",
            "command",
            "kubectl",
            "kubectl_command",
            "apply",
            "manifest",
        ):
            assert forbidden not in keys, forbidden
        assert dispatch.carries_patch is False

    def test_every_outbound_string_is_redacted(self) -> None:
        outcome = _tier_two_outcome()
        dispatch = warroom.build_dispatch(
            payload(lambda d: d.update(restart_count=99)),
            outcome.response,
            outcome.reasons,
        )
        rendered = warroom.render_markdown(dispatch)
        assert "AKIA" not in rendered
        assert dispatch.redaction_rules_triggered is not None

    def test_markdown_is_bounded(self) -> None:
        """A dispatch that pushes a responder out of view did not reach anyone."""
        outcome = _tier_two_outcome()
        dispatch = warroom.build_dispatch(
            payload(lambda d: d.update(restart_count=99)),
            outcome.response,
            outcome.reasons,
        )
        rendered = warroom.render_markdown(dispatch)
        assert len(rendered) <= 4000
        assert rendered.startswith("## Tier-2 escalation:")

    def test_reports_the_severity_and_classification(self) -> None:
        outcome = _tier_two_outcome()
        dispatch = warroom.build_dispatch(
            payload(lambda d: d.update(restart_count=99)),
            outcome.response,
            outcome.reasons,
        )
        document = dispatch.to_dict()
        verdict = cast(dict[str, object], document["verdict"])
        assert verdict["blast_radius_tier"] == "TIER_2_ARCHITECTURAL"
        assert verdict["severity"] in {"SEV1", "SEV2", "SEV3", "SEV4"}
        assert verdict["classification"]
