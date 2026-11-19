"""The size-source probe for task 9.12 (Issue #10).

`_collect_one` records `os.path.getsize` before it reads, so the honest way to make a recorded
size disagree with the bytes on disk is to mock that size source, which is what Issue #10 asks
for. A file whose recorded size is above or below what the read returns is a
`skipped-unreadable` skip at HIGH, with no hash and no text. A file that was not resized is
hashed and decoded whole.

The module is self-contained and duplicates the small git helpers on purpose:
`tests/unit/test_collector.py` calls `os.geteuid` while it defines `TestLimits`, so on Windows
that module fails to import and every test in it is uncollectable, including its size
regressions. Nothing here needs file permissions, so these cases collect everywhere.
"""

from __future__ import annotations

import hashlib
import os
import subprocess
from pathlib import Path

import pytest

from airlock.collector import SKIP_UNREADABLE, collect
from airlock.model import Policy, Severity

#: Nothing here is a tooling config or an editor task, so path roles add nothing to the scan.
ROLE_GLOBS: dict[str, tuple[str, ...]] = {}


def git(root: Path, *args: str) -> None:
    subprocess.run(
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


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    git(root, "init", "-q", "--initial-branch=main")
    return root


def write(repo: Path, rel: str, data: bytes) -> Path:
    path = repo / rel
    path.write_bytes(data)
    git(repo, "add", "-A")
    return path


def commit(repo: Path) -> None:
    git(repo, "commit", "-q", "-m", "fixture")


def scan(repo: Path):
    return collect(repo, Policy(), ROLE_GLOBS)


def size_source(target: Path, reported: int):
    """`os.path.getsize`, except `target` reports `reported` bytes.

    Every other path gets the real size, so the mock changes one file's recorded size and
    nothing else about the scan.
    """
    real = os.path.getsize

    def getsize(path: str | os.PathLike[str]) -> int:
        return reported if os.fspath(path) == os.fspath(target) else real(path)

    return getsize


def entry_of(result, rel: str):
    for entry in result.entries:
        if entry.path == rel:
            return entry
    raise AssertionError(f"{rel} is not in the collected entries")


def assert_unreadable_skip(result, rel: str) -> None:
    """The whole pass condition for a size disagreement: skip, no hash, no text, one HIGH."""
    entry = entry_of(result, rel)
    assert entry.skip_reason == SKIP_UNREADABLE
    assert entry.sha256 is None
    assert entry.text is None
    assert [finding.rule_id for finding in result.pending] == ["skipped-unreadable"]
    finding = result.pending[0]
    assert finding.severity is Severity.HIGH
    assert finding.message == "file changed size while being read"
    assert result.files_skipped == {SKIP_UNREADABLE: 1}


class TestRecordedSizeAboveTheBytesRead:
    """A file that shrank since `getsize` must not be hashed from its short buffer."""

    def test_a_size_above_the_bytes_read_is_a_skip(
        self, repo: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        target = write(repo, "shrunk.py", b"y" * 100)
        commit(repo)
        assert target.stat().st_size == 100
        monkeypatch.setattr(os.path, "getsize", size_source(target, 5000))

        result = scan(repo)

        # 5000 is over the 100 bytes on disk, so the collector takes its second read and
        # still comes back short: the old `len(data) > size_bytes` comparison hashed this
        # buffer and called the prefix the whole file.
        assert_unreadable_skip(result, "shrunk.py")


class TestRecordedSizeBelowTheBytesRead:
    """A file that grew since `getsize` was already a skip; it has to stay one."""

    def test_a_size_below_the_bytes_read_is_a_skip(
        self, repo: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        target = write(repo, "grew.py", b"y" * 100)
        commit(repo)
        assert target.stat().st_size == 100
        monkeypatch.setattr(os.path, "getsize", size_source(target, 40))

        result = scan(repo)

        # 40 is under the 100 bytes read by the head-only pass, so the second read never
        # happens and the counter check compares 100 against 40 directly.
        assert_unreadable_skip(result, "grew.py")


class TestUnchangedSizeSource:
    """The real size source still hashes and decodes a file whole."""

    def test_an_untouched_file_is_hashed_and_decoded_whole(self, repo: Path) -> None:
        data = b"z" * 40
        write(repo, "small.py", data)
        commit(repo)

        result = scan(repo)

        entry = entry_of(result, "small.py")
        assert entry.sha256 == hashlib.sha256(data).hexdigest()
        assert entry.text == "z" * 40
        assert entry.skip_reason is None
        assert result.pending == ()
        assert result.files_skipped == {}
