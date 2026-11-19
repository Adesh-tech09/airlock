"""Cargo patch, git and escaped-path dependency checks (issue 45)."""

from __future__ import annotations

from tests.fixtures import Case, context
from tests.fixtures.cargo_vectors_patch import GIT_SOURCE, OUTSIDE_PATH, cargo

from airlock.runner import scan


def findings(case: Case):
    return scan(context(case))


class TestCargoVectors:
    def test_patch_git_and_escaped_path_are_reported_with_context(self) -> None:
        found = findings(
            cargo(
                "[patch.crates-io]\n"
                'sample = { git = "' + GIT_SOURCE + '" }\n'
                "\n"
                "[dependencies]\n"
                'remote = { git = "' + GIT_SOURCE + '" }\n'
                'escaped = { path = "' + OUTSIDE_PATH + '" }\n'
            )
        )
        messages = [item.message for item in found if item.rule_id.startswith("cargo-")]

        assert any("patch.crates-io" in message and "sample" in message for message in messages)
        assert any("dependencies" in message and "remote" in message for message in messages)
        assert any("escaped" in message and OUTSIDE_PATH in message for message in messages)

    def test_registry_version_and_in_repository_path_are_clean(self) -> None:
        case = cargo(
            "[dependencies]\n"
            'sample = "1.2.3"\n'
            'local = { path = "crates/local" }\n'
        )

        assert not any(item.rule_id.startswith("cargo-") for item in findings(case))

    def test_git_dependency_in_workspace_table_is_found(self) -> None:
        case = cargo(
            "[workspace.dependencies]\n"
            'remote = { git = "' + GIT_SOURCE + '" }\n'
        )

        assert any("remote" in item.message for item in findings(case))

    def test_inline_and_standard_dependency_tables_are_handled(self) -> None:
        case = cargo(
            "[dependencies]\n"
            "inline = { version = \"1\", git = \"" + GIT_SOURCE + "\" }\n"
            "\n"
            "[dev-dependencies.standard]\n"
            'git = "' + GIT_SOURCE + '"\n'
        )

        found = [item for item in findings(case) if item.rule_id.startswith("cargo-")]
        assert len(found) >= 2

    def test_malformed_toml_becomes_detector_error(self) -> None:
        found = findings(cargo("[dependencies\nsample = \"1.2.3\"\n"))

        assert any(item.rule_id == "detector-error" for item in found)
