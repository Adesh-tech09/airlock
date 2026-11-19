"""A trusted-base config file cannot be unbounded (`ARCHITECTURE.md` 6.5, 7.6 and 8).

`full` mode refuses a working-tree `airlock.toml` over `MAX_CONFIG_BYTES`; the base copy was the
one config read with no ceiling, so a change could commit a huge policy, have it become the base
later, and turn the next `pr` run into a parse failure with no report. These cases run against a
real temporary git repository because the property is a git fact: what the blob at a ref weighs,
and what `git show` would hand back.

The oversize fixtures are valid TOML with one long comment, so a parse would have succeeded. That
is what makes the cap the thing under test rather than a syntax error.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from airlock.model import BOOTSTRAP_POLICY, EMPTY_MANIFEST, Mode, Severity
from airlock.policy import (
    MANIFEST_FILENAME,
    MAX_CONFIG_BYTES,
    POLICY_FILENAME,
    TrustedConfig,
    resolve_policy,
)

BASE_POLICY = """version = 1

[policy]
fail_on = "high"
line_cap = 500
"""

WEAKENED_POLICY = """version = 1

[policy]
fail_on = "info"
line_cap = 500
"""


def git(root: Path, *args: str) -> str:
    result = subprocess.run(
        [
            "git",
            "-C",
            str(root),
            "-c",
            "user.name=airlock-test",
            "-c",
            "user.email=airlock-test@example.invalid",
            "-c",
            "core.hooksPath=/dev/null",
            *args,
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    git(root, "init", "-q", "--initial-branch=main")
    # The fixtures are counted in bytes, so line-ending conversion must not change the blob.
    git(root, "config", "core.autocrlf", "false")
    return root


def write(root: Path, rel: str, data: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(data, encoding="utf-8", newline="\n")
    git(root, "add", "-A")


def commit(root: Path, message: str = "fixture") -> str:
    git(root, "commit", "-q", "-m", message)
    return git(root, "rev-parse", "HEAD").strip()


def sized(target_bytes: int, policy: str) -> str:
    """`policy` padded with one comment line so the document is exactly `target_bytes` long."""
    filler = target_bytes - len(policy.encode("utf-8")) - len("\n# \n")
    assert filler >= 0, "the fixture policy is longer than the size wanted"
    return policy + "\n# " + "x" * filler + "\n"


def oversize(policy: str) -> str:
    return sized(MAX_CONFIG_BYTES + 1, policy)


def blob_size(root: Path, ref: str, path: str) -> int:
    return int(git(root, "cat-file", "-s", f"{ref}:{path}").strip())


def rule_ids(result: TrustedConfig) -> list[str]:
    return [finding.rule_id for finding in result.pending]


def seed(root: Path, policy: str, manifest: str = "version = 1\n") -> str:
    write(root, POLICY_FILENAME, policy)
    write(root, MANIFEST_FILENAME, manifest)
    return commit(root)


class TestOversizeBasePolicy:
    def test_the_base_copy_is_a_high_skip_and_the_defaults_apply(self, repo: Path) -> None:
        base = seed(repo, oversize(BASE_POLICY))
        assert blob_size(repo, base, POLICY_FILENAME) == MAX_CONFIG_BYTES + 1
        write(repo, "README.md", "unrelated\n")
        head = commit(repo, "the change under review")

        result = resolve_policy(repo, Mode.PR, head, base=base)

        assert result.policy is BOOTSTRAP_POLICY
        assert result.base == base
        assert rule_ids(result) == ["skipped-unreadable"]
        finding = result.pending[0]
        assert finding.severity is Severity.HIGH
        assert finding.path == POLICY_FILENAME
        assert str(MAX_CONFIG_BYTES + 1) in finding.message
        assert "over the" in finding.message
        assert finding.suppressible is False

    def test_a_changed_copy_is_not_compared_so_no_policy_changed_is_claimed(
        self, repo: Path
    ) -> None:
        base = seed(repo, oversize(BASE_POLICY))
        write(repo, POLICY_FILENAME, WEAKENED_POLICY)
        head = commit(repo, "weaken the policy")

        result = resolve_policy(repo, Mode.PR, head, base=base)

        assert "policy-changed" not in rule_ids(result)
        assert result.policy is BOOTSTRAP_POLICY
        assert result.policy.fail_on is not Severity.INFO

    def test_a_base_copy_exactly_at_the_limit_is_still_read(self, repo: Path) -> None:
        base = seed(repo, sized(MAX_CONFIG_BYTES, BASE_POLICY))
        assert blob_size(repo, base, POLICY_FILENAME) == MAX_CONFIG_BYTES

        result = resolve_policy(repo, Mode.PR, base, base=base)

        assert result.policy is not BOOTSTRAP_POLICY
        assert result.policy.line_cap == 500
        assert result.pending == ()


class TestOversizeBaseManifest:
    def test_the_base_manifest_is_a_high_skip_and_stays_empty(self, repo: Path) -> None:
        base = seed(repo, BASE_POLICY, oversize("version = 1\n"))
        assert blob_size(repo, base, MANIFEST_FILENAME) == MAX_CONFIG_BYTES + 1
        write(repo, "README.md", "unrelated\n")
        head = commit(repo, "the change under review")

        result = resolve_policy(repo, Mode.PR, head, base=base)

        assert result.manifest is EMPTY_MANIFEST
        assert result.policy.line_cap == 500
        assert rule_ids(result) == ["skipped-unreadable"]
        finding = result.pending[0]
        assert finding.severity is Severity.HIGH
        assert finding.path == MANIFEST_FILENAME


class TestOversizeCopyInTheChange:
    def test_the_base_policy_still_governs_and_the_copies_are_not_compared(
        self, repo: Path
    ) -> None:
        base = seed(repo, BASE_POLICY)
        write(repo, POLICY_FILENAME, oversize(WEAKENED_POLICY))
        head = commit(repo, "add a huge policy")

        result = resolve_policy(repo, Mode.PR, head, base=base)

        assert result.policy.line_cap == 500
        assert result.policy.fail_on is Severity.HIGH
        assert rule_ids(result) == ["policy-changed"]
        finding = result.pending[0]
        assert finding.severity is Severity.WARN
        assert str(MAX_CONFIG_BYTES + 1) in finding.message
        assert "no comparison was made" in finding.message
        # The message cap is 200 characters and the policy prefix spends about half of it.
        assert len(finding.message) < 200
