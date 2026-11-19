"""`pr` and `push` never read the trusted files from the working tree (#48).

`policy._from_working_tree` is the only caller of `_working_text`, which is the only code that
opens the checkout's `airlock.toml` or `wasm-manifest.toml`. If a fallback were added when a base
lookup returns None, the change under review could be judged by the policy it wrote, and the
existing assertions in `test_policy.py` would still pass because base and head usually agree.

The absence of a call is proven by making the call fail: `_working_text` is module level, so one
monkeypatch is the trap. The control drives `full` mode and shows the trap is reached there.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from airlock import policy
from airlock.model import Mode, Policy
from airlock.policy import MANIFEST_FILENAME, POLICY_FILENAME, TrustedConfig, resolve_policy

BASE_POLICY = """version = 1

[policy]
fail_on = "high"
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
    return root


def write(root: Path, rel: str, data: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(data, encoding="utf-8")
    git(root, "add", "-A")


def commit(root: Path) -> str:
    git(root, "commit", "-q", "-m", "fixture")
    return git(root, "rev-parse", "HEAD").strip()


def seed(root: Path) -> str:
    write(root, POLICY_FILENAME, BASE_POLICY)
    write(root, MANIFEST_FILENAME, "version = 1\n")
    write(root, "postcss.config.mjs", "export default { plugins: [] }\n")
    return commit(root)


def resolve_push(root: Path, before: str, head: str) -> TrustedConfig:
    return resolve_policy(root, Mode.PUSH, head, before=before)


@pytest.fixture
def working_tree_trap(monkeypatch: pytest.MonkeyPatch) -> None:
    def trap(root: Path, path: str) -> str | None:
        raise AssertionError(f"{path} was read from the working tree")

    monkeypatch.setattr(policy, "_working_text", trap)


class TestTrustedSourceOnly:
    def test_pr_mode_returns_the_base_policy_without_the_working_tree(
        self, repo: Path, working_tree_trap: None
    ) -> None:
        base = seed(repo)
        write(repo, POLICY_FILENAME, BASE_POLICY.replace("line_cap = 500", "line_cap = 2000000"))
        head = commit(repo)

        result = resolve_policy(repo, Mode.PR, head, base=base)

        assert result.base == base
        assert result.policy == Policy(line_cap=500)

    def test_push_mode_returns_the_before_policy_without_the_working_tree(
        self, repo: Path, working_tree_trap: None
    ) -> None:
        base = seed(repo)
        write(repo, POLICY_FILENAME, BASE_POLICY.replace("line_cap = 500", "line_cap = 2000000"))
        head = commit(repo)

        result = resolve_push(repo, base, head)

        assert result.base == base
        assert result.policy == Policy(line_cap=500)

    def test_the_control_reaches_the_trap_in_full_mode(
        self, repo: Path, working_tree_trap: None
    ) -> None:
        # The guard bites: if `_working_text` were not reachable, the two tests above would
        # prove nothing about a trap that can never fire.
        base = seed(repo)

        with pytest.raises(AssertionError, match="airlock.toml was read"):
            resolve_policy(repo, Mode.FULL, base)
