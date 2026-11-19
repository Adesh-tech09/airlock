"""npm lockfile resolved-host checks (issue 46)."""

from __future__ import annotations

from tests.fixtures import Case, File, context
from tests.fixtures.npm_lockfile_registry import GIT_URL, MIRROR, REGISTRY

from airlock.model import Severity
from airlock.runner import scan


def findings(case: Case):
    return scan(context(case))


def lock(text: str) -> Case:
    return Case(files=(File("package-lock.json", text=text),))


class TestNpmLockfileRegistry:
    def test_non_registry_tarball_names_package_and_host(self) -> None:
        found = [
            item
            for item in findings(
                lock(
                    '{"lockfileVersion":3,"packages":{"node_modules/pkg":'
                    '{"resolved":"' + MIRROR + 'pkg.tgz"}}}'
                )
            )
            if item.rule_id == "npm-registry-bypass"
        ]

        assert len(found) == 1
        assert found[0].severity is Severity.HIGH
        assert "node_modules/pkg" in found[0].message
        assert "mirror.example.invalid" in found[0].message

    def test_official_registry_and_non_http_sources_are_clean(self) -> None:
        case = lock(
            '{"lockfileVersion":2,"packages":{'
            '"node_modules/pkg":{"resolved":"' + REGISTRY + 'pkg.tgz"},'
            '"node_modules/git":{"resolved":"' + GIT_URL + '"},'
            '"node_modules/local":{"resolved":"file:../local"},'
            '"node_modules/link":{"resolved":"link:../link"},'
            '"node_modules/workspace":{"resolved":"workspace:*"}}}'
        )

        assert not any(item.rule_id == "npm-registry-bypass" for item in findings(case))

    def test_version_one_nested_dependency_is_walked(self) -> None:
        case = lock(
            '{"lockfileVersion":1,"dependencies":{"outer":{"dependencies":'
            '{"inner":{"resolved":"' + MIRROR + 'inner.tgz"}}}}}'
        )

        found = [item for item in findings(case) if item.rule_id == "npm-registry-bypass"]
        assert len(found) == 1
        assert "outer" in found[0].message
        assert "inner" in found[0].message

    def test_malformed_json_is_a_detector_error(self) -> None:
        found = findings(lock('{"lockfileVersion":3,"packages":'))

        assert any(item.rule_id == "detector-error" for item in found)

    def test_nested_packages_are_reported_individually(self) -> None:
        case = lock(
            '{"lockfileVersion":3,"packages":{'
            '"node_modules/a":{"resolved":"' + MIRROR + 'a.tgz"},'
            '"node_modules/a/node_modules/b":{"resolved":"' + MIRROR + 'b.tgz"}}}'
        )

        found = [item for item in findings(case) if item.rule_id == "npm-registry-bypass"]
        assert len(found) == 2
