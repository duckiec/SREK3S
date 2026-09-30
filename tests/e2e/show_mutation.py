"""Diff two cluster snapshots and report what changed.

ROADMAP 4.2.8 asks for evidence that no incident mutated the cluster. The
comparison itself already lives in ``runner.py`` as a pure function over two
snapshot documents; this prints the same comparison in a form a human can read
from a CI log, because the runner's verdict is one line and the reasoning behind
it is the interesting part.

Purely a reader. It opens two files, prints, and returns. It takes no cluster
action, writes nothing, and imports nothing from the agent or the runner, so it
cannot drift from them.

Usage: ``python tests/e2e/show_mutation.py before.json after.json``
"""

from __future__ import annotations

import json
import pathlib
import sys
from typing import Any

# Namespaces whose churn is expected: the one under test, and the system
# namespaces where controllers and leader election move resourceVersion on their
# own. Excluded from the verdict, but still counted and shown - a large number
# here is worth knowing about even though it proves nothing either way.
SYSTEM_PREFIXES = (
    "kube-system",
    "kube-public",
    "kube-node-lease",
    "local-path-storage",
)


def _load(path: str) -> dict[str, Any] | None:
    try:
        data = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        print("  (cannot read {}: {})".format(path, error))
        return None
    if not isinstance(data, dict):
        print("  ({} is a {}, not a snapshot)".format(path, type(data).__name__))
        return None
    return data


def _version(entry: Any) -> Any:
    if isinstance(entry, dict):
        return entry.get("resourceVersion")
    return None


def _is_system(key: str) -> bool:
    return any(part in key for part in SYSTEM_PREFIXES)


def _show(label: str, keys: list[str], limit: int = 12) -> None:
    print("  {} ({}):".format(label, len(keys)))
    for key in keys[:limit]:
        print("      {}".format(key))
    if len(keys) > limit:
        print("      ... and {} more".format(len(keys) - limit))


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 2:
        print("usage: show_mutation.py <before.json> <after.json>", file=sys.stderr)
        return 2

    before = _load(args[0])
    after = _load(args[1])
    if before is None or after is None:
        return 0

    print("  objects before/after: {}/{}".format(len(before), len(after)))
    if not before or not after:
        print("  *** one side is EMPTY. An empty before-image compared against an")
        print("      empty after-image passes every no-mutation assertion while")
        print("      proving nothing, so this is reported rather than counted.")

    created = sorted(set(after) - set(before))
    deleted = sorted(set(before) - set(after))
    changed = sorted(
        key
        for key in set(before) & set(after)
        if _version(before[key]) != _version(after[key])
    )

    interesting_created = [k for k in created if not _is_system(k)]
    interesting_deleted = [k for k in deleted if not _is_system(k)]
    interesting_changed = [k for k in changed if not _is_system(k)]

    print()
    _show("CREATED (excluding system namespaces)", interesting_created)
    _show("DELETED (excluding system namespaces)", interesting_deleted)
    _show("CHANGED (excluding system namespaces)", interesting_changed)
    print()
    print(
        "  system-namespace churn, counted and excluded: "
        "{} created, {} deleted, {} changed".format(
            len(created) - len(interesting_created),
            len(deleted) - len(interesting_deleted),
            len(changed) - len(interesting_changed),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
