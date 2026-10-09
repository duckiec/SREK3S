"""`_MANIFEST_PATH_RE`, and what the engine's own shape check says about it.

The pattern used ``re.match`` with a trailing ``$``, and ``$`` matches before a
final newline. So ``deploy/oom-leak.yaml\n`` passed validation - and that value is
interpolated into ``main.py``'s Tier-1 log line, where ``logging`` renders a
newline as a record separator. One manifest became two log records, and the
second carried whatever followed.
"""

from __future__ import annotations

import re

import pytest
from pydantic import ValidationError

from classifier import _target_manifest_is_wellformed
from models import Remediation

VALID_PATCH = (
    "--- a/x.yaml\n+++ b/x.yaml\n@@ -1 +1 @@\n" '-memory: "256Mi"\n+memory: "512Mi"\n'
)


class TestManifestPathRegex:
    @pytest.mark.parametrize(
        "value",
        [
            "deploy/oom-leak.yaml\n",
            "deploy/oom-leak.yaml\r",
            "deploy/oom-leak.yaml\nMALICIOUS_STUFF",
            "deploy/oom-leak.yaml\n\n",
            "deploy/oom-leak.yaml\nforged=WARNING severity=HIGH",
        ],
    )
    def test_a_trailing_payload_is_refused(self, value: str) -> None:
        """`$` matches before a final newline; `\\A`/`\\Z` do not.

        The value reached `main.py`'s Tier-1 log line, and `logging` renders a
        newline as a record separator, so one manifest became two log records and
        the second carried whatever followed.
        """
        with pytest.raises(ValidationError, match="yaml|yml|json"):
            Remediation.model_validate(
                {
                    "summary": "s",
                    "risk_level": "LOW",
                    "target_manifest": value,
                    "git_patch": VALID_PATCH,
                    "patch_validated": True,
                }
            )

    @pytest.mark.parametrize(
        "value",
        ["deploy/oom-leak.yaml", "a.yaml", "deep/nested/dir/x.json", "a-b_c.yaml"],
    )
    def test_a_legitimate_path_is_still_accepted(self, value: str) -> None:
        assert (
            Remediation.model_validate(
                {
                    "summary": "s",
                    "risk_level": "LOW",
                    "target_manifest": value,
                    "git_patch": VALID_PATCH,
                    "patch_validated": True,
                }
            ).target_manifest
            == value
        )

    def test_the_engine_shape_check_agrees_with_the_schema(self) -> None:
        """Four shapes the schema admitted and the provider refused.

        `./deploy/x.yaml`, `a//b.yaml` and `a/./b.yaml` pass the schema's character
        class and are refused by `FileManifestProvider._resolve`, which rejects
        empty, `.` and `..` segments. A `patch_validated: true` naming one of them
        asserts a check nobody can reproduce.
        """
        assert re.fullmatch(r"[\w./-]+\.(ya?ml|json)", "./deploy/x.yaml") is not None
        for shape in ("./deploy/x.yaml", "a//b.yaml", "a/./b.yaml"):
            assert _target_manifest_is_wellformed(shape) is False, shape
