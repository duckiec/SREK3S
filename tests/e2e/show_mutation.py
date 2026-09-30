"""Diff two cluster snapshots and report what changed.

ROADMAP 4.2.8 asks for evidence that no incident mutated the cluster. The
comparison itself already lives in ``runner.py`` as a pure function over two
snapshot documents; this prints the same comparison in a form a human can read
from a CI log, because the runner's verdict is one line and the reasoning behind
it is the interesting part.

Purely a reader. It opens two files, prints, and returns. It takes no cluster
action and writes nothing.

**It asks the runner for the verdict, rather than reimplementing it.** An
earlier revision carried its own ``SYSTEM_PREFIXES`` tuple, matched with a
substring test, and printed its own "excluding system namespaces" sections. That
is the defect this import exists to remove: the printer excluded a *different*
set of objects from the one the exit code was computed over, and it did not know
the chaos namespace at all, so it printed the harness's own fixture under
"CREATED". A CI log could therefore show a clean listing while the job failed on
the very objects in it - and a reviewer reading that section would be looking at
a tool that had already been told the answer and printed something else.

So the verdict is not reimplemented here. The listing is for a human; the
**verdict** is :func:`runner.check_no_cluster_mutation`'s, quoted verbatim, and
the two cannot diverge because there is only one of them.

Usage: ``python tests/e2e/show_mutation.py before.json after.json [namespace]``
"""

from __future__ import annotations

import json
import pathlib
import sys
from typing import Any

# Imported, not duplicated. `runner` is a sibling script rather than a package,
# so the directory holding this file goes on the path. Everything `runner`
# imports at module scope is stdlib, so the import has no side effects and
# cannot fail on a machine with no cluster tooling.
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from runner import (  # noqa: E402
    CHAOS_NAMESPACE,
    VerificationError,
    check_no_cluster_mutation,
    is_exempt_namespace,
)

# Re-exported deliberately, and named here because `mypy --strict` implies
# `no_implicit_reexport`: without it, `show_mutation.is_exempt_namespace` is an
# attribute mypy refuses to let another module reach, even though the runtime
# import above is real and the test suite uses it.
#
# The re-export is the point rather than an accident of the import list. The
# printer and the runner must agree on which namespaces are exempt, and the
# anti-drift test asserts they read the *same* function. Re-exporting makes that
# a declared contract instead of an incidental side effect of import order.
__all__ = [
    "CHAOS_NAMESPACE",
    "VerificationError",
    "check_no_cluster_mutation",
    "is_exempt_namespace",
    "main",
]


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


def _namespace_of(key: str, entry: Any) -> str:
    """The namespace of one snapshot entry, from the entry or from its key.

    ``snapshot_cluster`` writes ``metadata.namespace`` into every entry, so the
    first read is the normal path. The key fallback exists because a snapshot
    is a file a reviewer may have edited or hand-built, and a printer that
    silently treated the namespace as empty would classify every object as
    out-of-namespace. The key is ``<apiVersion>/<kind>/<namespace>/<name>`` and
    ``apiVersion`` itself contains a slash, so the split is from the right.
    """
    if isinstance(entry, dict):
        value = entry.get("namespace")
        if isinstance(value, str) and value:
            return value
    parts = key.rsplit("/", 2)
    return parts[1] if len(parts) == 3 else ""


def _show(label: str, keys: list[str], limit: int = 12) -> None:
    print("  {} ({}):".format(label, len(keys)))
    for key in keys[:limit]:
        print("      {}".format(key))
    if len(keys) > limit:
        print("      ... and {} more".format(len(keys) - limit))


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) not in (2, 3):
        print(
            "usage: show_mutation.py <before.json> <after.json> [chaos-namespace]",
            file=sys.stderr,
        )
        return 2
    # Optional third argument, so the chaos namespace is stated rather than
    # assumed by the printer. It defaults to the runner's own constant, which
    # is the namespace the verdict was computed against in the first place.
    chaos_namespace = args[2] if len(args) == 3 else CHAOS_NAMESPACE

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

    def is_exempt(key: str, snapshot: dict[str, Any]) -> bool:
        return is_exempt_namespace(_namespace_of(key, snapshot[key]), chaos_namespace)

    interesting_created = [k for k in created if not is_exempt(k, after)]
    interesting_deleted = [k for k in deleted if not is_exempt(k, before)]
    interesting_changed = [k for k in changed if not is_exempt(k, after)]

    print()
    print(
        "  exempt from the verdict: the chaos namespace {!r} plus the k3s"
        " system".format(chaos_namespace)
    )
    print(
        "  namespaces (helm install/upgrade, leader election, local-path provisioner)."
    )
    print()
    _show("CREATED outside the exempt namespaces", interesting_created)
    _show("DELETED outside the exempt namespaces", interesting_deleted)
    _show("CHANGED outside the exempt namespaces", interesting_changed)
    print()
    print(
        "  exempt churn, counted and excluded: "
        "{} created, {} deleted, {} changed".format(
            len(created) - len(interesting_created),
            len(deleted) - len(interesting_deleted),
            len(changed) - len(interesting_changed),
        )
    )

    # The verdict, from the runner, quoted. Not reimplemented and not inferred
    # from the lists above: the exit code this job reports comes from the same
    # call, so a reader of this log is reading the decision rather than a
    # reconstruction of it.
    print()
    try:
        print(
            "  VERDICT: {}".format(
                check_no_cluster_mutation(before, after, chaos_namespace)
            )
        )
    except VerificationError as error:
        print("  VERDICT: FAIL - {}".format(error))
        print("  (the runner's exit code is non-zero for this comparison)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
