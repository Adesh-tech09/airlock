"""Cargo dependency source checks (issue 45; Architecture section 9.5)."""

from __future__ import annotations

import posixpath
import tomllib
from collections.abc import Iterable, Mapping
from pathlib import PurePosixPath

from ..fingerprint import PendingFinding
from ..model import FileEntry, Rule, ScanContext
from ..rules import finding_for

PATCH_RULE_ID = "cargo-patch-override"
GIT_RULE_ID = "cargo-git-dependency"
PATH_RULE_ID = "cargo-path-escape"
DEPENDENCY_TABLES = ("dependencies", "dev-dependencies", "build-dependencies")


def _required_rule(rules: Mapping[str, Rule], rule_id: str) -> Rule:
    rule = rules.get(rule_id)
    if rule is None:
        raise ValueError(f"cargo_vectors cannot run without the {rule_id} rule loaded")
    return rule


def _mapping(value: object) -> Mapping[str, object] | None:
    return value if isinstance(value, dict) else None


def _outside_repository(manifest_path: str, dependency_path: str) -> bool:
    normalized_path = dependency_path.replace("\\", "/")
    if PurePosixPath(normalized_path).is_absolute() or (
        len(normalized_path) >= 3 and normalized_path[1] == ":" and normalized_path[2] == "/"
    ):
        return True
    manifest_dir = posixpath.dirname(manifest_path)
    resolved = posixpath.normpath(posixpath.join(manifest_dir, normalized_path))
    return resolved == ".." or resolved.startswith("../")


def _emit(
    rule: Rule,
    entry: FileEntry,
    *,
    table: str,
    dependency: str,
    source: str,
) -> PendingFinding:
    return finding_for(
        rule,
        entry,
        0,
        evidence=source,
        message=f"{rule.title}: [{table}] dependency {dependency} uses {source}",
    )


def _dependency_findings(
    entry: FileEntry,
    table_name: str,
    dependencies: object,
    rules: Mapping[str, Rule],
) -> Iterable[PendingFinding]:
    table = _mapping(dependencies)
    if table is None:
        if dependencies is not None:
            raise ValueError(f"Cargo [{table_name}] must be a table")
        return
    for name, details in table.items():
        if not isinstance(name, str):
            continue
        dependency = _mapping(details)
        if dependency is None:
            if not isinstance(details, str):
                err = f"Cargo [{table_name}] dependency {name} must be a table or version"
                raise ValueError(err)
            continue
        git_source = dependency.get("git")
        if isinstance(git_source, str):
            yield _emit(
                _required_rule(rules, GIT_RULE_ID),
                entry,
                table=table_name,
                dependency=name,
                source=f"git source {git_source}",
            )
        path_source = dependency.get("path")
        if isinstance(path_source, str) and _outside_repository(entry.path, path_source):
            yield _emit(
                _required_rule(rules, PATH_RULE_ID),
                entry,
                table=table_name,
                dependency=name,
                source=f"path {path_source}",
            )


def _patch_findings(
    entry: FileEntry, patch_tables: object, rules: Mapping[str, Rule]
) -> Iterable[PendingFinding]:
    patches = _mapping(patch_tables)
    if patches is None:
        if patch_tables is not None:
            raise ValueError("Cargo [patch] must contain registry tables")
        return
    rule = _required_rule(rules, PATCH_RULE_ID)
    for registry, packages_value in patches.items():
        packages = _mapping(packages_value)
        if packages is None:
            raise ValueError(f"Cargo [patch.{registry}] must be a table")
        table_name = f"patch.{registry}"
        for name, details in packages.items():
            source = "replacement source"
            dependency = _mapping(details)
            if dependency is not None:
                git_source = dependency.get("git")
                path_source = dependency.get("path")
                if isinstance(git_source, str):
                    source = f"git source {git_source}"
                elif isinstance(path_source, str):
                    source = f"path {path_source}"
            elif not isinstance(details, str):
                raise ValueError(f"Cargo [patch.{registry}] entry {name} must be a table")
            yield _emit(
                rule,
                entry,
                table=table_name,
                dependency=str(name),
                source=source,
            )
            if (
                dependency is not None
                and isinstance(path_source, str)
                and _outside_repository(entry.path, path_source)
            ):
                yield _emit(
                    _required_rule(rules, PATH_RULE_ID),
                    entry,
                    table=table_name,
                    dependency=str(name),
                    source=f"path {path_source}",
                )


def _manifest_findings(
    entry: FileEntry, document: Mapping[str, object], rules: Mapping[str, Rule]
) -> Iterable[PendingFinding]:
    for table_name in DEPENDENCY_TABLES:
        yield from _dependency_findings(entry, table_name, document.get(table_name), rules)

    workspace = _mapping(document.get("workspace"))
    if document.get("workspace") is not None and workspace is None:
        raise ValueError("Cargo workspace must be a table")
    if workspace is not None:
        yield from _dependency_findings(
            entry, "workspace.dependencies", workspace.get("dependencies"), rules
        )

    yield from _patch_findings(entry, document.get("patch"), rules)


def run(ctx: ScanContext) -> Iterable[PendingFinding]:
    """Inspect tracked Cargo manifests as TOML data; never invoke Cargo."""
    rules = {rule.id: rule for rule in ctx.rules}
    for entry in ctx.entries:
        if entry.path.rsplit("/", 1)[-1] != "Cargo.toml" or entry.text is None:
            continue
        document = tomllib.loads(entry.text)
        yield from _manifest_findings(entry, document, rules)
