"""Check npm lockfile tarball hosts without resolving or fetching packages."""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from urllib.parse import urlsplit

from ..fingerprint import PendingFinding
from ..model import FileEntry, Rule, ScanContext
from ..rules import finding_for

RULE_ID = "npm-registry-bypass"
LOCKFILE_NAME = "package-lock.json"
TRUSTED_HOST = "registry.npmjs.org"


def _require_rule(rules: Mapping[str, Rule]) -> Rule:
    rule = rules.get(RULE_ID)
    if rule is None:
        raise ValueError(f"npm_registry cannot run without the {RULE_ID} rule loaded")
    return rule


def _package_entries(lock: object) -> Iterable[tuple[str, Mapping[str, object]]]:
    if not isinstance(lock, dict):
        raise ValueError("package-lock.json root must be a JSON object")

    packages = lock.get("packages")
    if packages is not None:
        if not isinstance(packages, dict):
            raise ValueError("package-lock.json packages must be a JSON object")
        for package_path, package in packages.items():
            if not isinstance(package_path, str) or not isinstance(package, dict):
                raise ValueError("package-lock.json packages entries must be objects")
            if not package_path:
                continue
            yield package_path, package
        return

    dependencies = lock.get("dependencies")
    if dependencies is not None:
        if not isinstance(dependencies, dict):
            raise ValueError("package-lock.json dependencies must be a JSON object")
        yield from _nested_dependencies(dependencies, "")


def _nested_dependencies(
    dependencies: Mapping[str, object], parent: str
) -> Iterable[tuple[str, Mapping[str, object]]]:
    for name, value in dependencies.items():
        if not isinstance(name, str) or not isinstance(value, dict):
            raise ValueError("package-lock.json dependency entries must be objects")
        package_path = f"{parent}/node_modules/{name}" if parent else f"node_modules/{name}"
        yield package_path, value
        nested = value.get("dependencies")
        if nested is not None:
            if not isinstance(nested, dict):
                raise ValueError(f"package-lock.json {package_path} dependencies must be an object")
            yield from _nested_dependencies(nested, package_path)


def _host(resolved: object, package_path: str) -> str | None:
    if resolved is None:
        return None
    if not isinstance(resolved, str):
        raise ValueError(f"package-lock.json {package_path} resolved value must be a string")
    parsed = urlsplit(resolved)
    if parsed.scheme.lower() not in {"http", "https"}:
        return None
    return (parsed.hostname or "<missing>").lower()


def _lockfile_findings(
    entry: FileEntry, document: object, rule: Rule
) -> Iterable[PendingFinding]:
    for package_path, metadata in _package_entries(document):
        resolved = metadata.get("resolved")
        host = _host(resolved, package_path)
        if host is None or host == TRUSTED_HOST:
            continue
        yield finding_for(
            rule,
            entry,
            0,
            evidence=resolved if isinstance(resolved, str) else package_path,
            message=(
                f"{rule.title}: package {package_path} resolves from host {host}, "
                f"not {TRUSTED_HOST}"
            ),
        )


def run(ctx: ScanContext) -> Iterable[PendingFinding]:
    """Report each HTTP(S) package tarball resolved outside the npm registry."""
    rules = {rule.id: rule for rule in ctx.rules}
    rule = _require_rule(rules)
    for entry in ctx.entries:
        if entry.path.rsplit("/", 1)[-1] != LOCKFILE_NAME or entry.text is None:
            continue
        document = json.loads(entry.text)
        yield from _lockfile_findings(entry, document, rule)
