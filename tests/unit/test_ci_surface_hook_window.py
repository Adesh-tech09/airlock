"""The fetch/execute pairing across adjacent install-hook lines (issue 42)."""

from __future__ import annotations

from tests.fixtures import Case, File, context
from tests.fixtures.ci_surface_hook_window import EXECUTE, FETCH, HOOK

from airlock.model import Severity
from airlock.runner import scan


def findings(case: Case):
    return scan(context(case))


def hook(*lines: str) -> Case:
    return Case(files=(File(HOOK, text="\n".join(lines) + "\n"),))


class TestInstallHookWindow:
    def test_split_fetch_and_execute_is_high_on_the_fetch_line(self) -> None:
        found = [
            item
            for item in findings(hook(FETCH, EXECUTE))
            if item.rule_id == "pat-lifecycle-exec"
        ]

        assert len(found) == 1
        assert found[0].severity is Severity.HIGH
        assert found[0].line == 1
        assert "line 2" in found[0].message

    def test_lint_only_hook_is_clean(self) -> None:
        assert findings(hook("pre-commit run --all-files")) == []

    def test_window_does_not_pair_lines_in_a_package_manifest(self) -> None:
        case = Case(
            files=(
                File(
                    "package.json",
                    text='{"scripts":{"postinstall":"' + FETCH + '\\n' + EXECUTE + '"}}\n',
                ),
            )
        )

        assert not any(item.rule_id == "pat-lifecycle-exec" for item in findings(case))

    def test_over_cap_fetch_or_execute_line_is_not_used(self) -> None:
        over_cap_fetch = hook(FETCH + (" " * 91), EXECUTE)
        over_cap_execute = hook(FETCH, EXECUTE + (" " * 91))

        assert not any(
            item.rule_id == "pat-lifecycle-exec" for item in findings(over_cap_fetch)
        )
        assert not any(
            item.rule_id == "pat-lifecycle-exec" for item in findings(over_cap_execute)
        )

    def test_hook_window_is_three_lines_inclusive(self) -> None:
        inside = findings(hook(FETCH, "# reviewed", EXECUTE))
        outside = findings(hook(FETCH, "# one", "# two", EXECUTE))

        assert any(item.rule_id == "pat-lifecycle-exec" for item in inside)
        assert not any(item.rule_id == "pat-lifecycle-exec" for item in outside)

    def test_one_fetch_yields_at_most_one_pairing(self) -> None:
        found = [
            item
            for item in findings(hook(FETCH, EXECUTE, "bash /tmp/x"))
            if item.rule_id == "pat-lifecycle-exec"
        ]

        assert len(found) == 1
