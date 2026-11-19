"""Manifest comparison for LFS pointers, using only the pointer's declared oid (issue 44)."""

from __future__ import annotations

import hashlib

from tests.fixtures import Case, context
from tests.fixtures.wasm_lfs_pointer import PATH, _case, _entry, pointer
from tests.fixtures.wasm_manifest import wasm_bytes

from airlock.model import Manifest, Severity
from airlock.runner import scan


def findings(case: Case):
    return scan(context(case))


class TestWasmLfsPointer:
    def test_matching_lfs_oid_is_clean_and_clears_stale_entry(self) -> None:
        artifact = wasm_bytes(42)
        oid = hashlib.sha256(artifact).hexdigest()

        assert findings(_case(pointer(oid, len(artifact)), Manifest(entries=(_entry(oid),)))) == []

    def test_unknown_lfs_oid_is_high_and_in_the_message(self) -> None:
        artifact = wasm_bytes(43)
        oid = hashlib.sha256(artifact).hexdigest()
        found = findings(_case(pointer(oid, len(artifact))))

        unlisted = [item for item in found if item.rule_id == "wasm-unlisted"]
        assert len(unlisted) == 1
        assert unlisted[0].severity is Severity.HIGH
        assert oid[:12] in unlisted[0].message

    def test_malformed_pointer_bad_oid_and_invalid_size_remain_unlisted(self) -> None:
        candidates = (
            "not a pointer\n",
            pointer("bad-oid", 32),
            pointer("a" * 64, 0),
        )

        for text in candidates:
            assert any(item.rule_id == "wasm-unlisted" for item in findings(_case(text)))

    def test_pointer_without_lfs_attributes_remains_unlisted(self) -> None:
        artifact = wasm_bytes(44)
        oid = hashlib.sha256(artifact).hexdigest()
        case = _case(pointer(oid, len(artifact)), attributes="")

        assert any(item.rule_id == "wasm-unlisted" for item in findings(case))

    def test_pointer_path_is_still_the_reported_path(self) -> None:
        artifact = wasm_bytes(45)
        oid = hashlib.sha256(artifact).hexdigest()
        found = findings(_case(pointer(oid, len(artifact))))

        assert any(item.rule_id == "wasm-unlisted" and item.path == PATH for item in found)
