"""Git LFS Wasm pointer fixtures, generated without fetching an object (issue 44)."""

from __future__ import annotations

from airlock.model import Manifest, WasmEntry

from . import Case, File

PATH = "contracts/sample.wasm"
ATTRIBUTES = "*.wasm filter=lfs diff=lfs merge=lfs -text\n"


def pointer(oid: str, size: int) -> str:
    return f"version https://git-lfs.github.com/spec/v1\noid sha256:{oid}\nsize {size}\n"


def _entry(oid: str) -> WasmEntry:
    return WasmEntry(
        sha256=oid,
        paths=(PATH,),
        origin="built",
        source="synthetic fixture",
        build="fixture",
    )


def _case(
    pointer_text: str,
    manifest: Manifest | None = None,
    *,
    attributes: str = ATTRIBUTES,
) -> Case:
    manifest_obj = Manifest() if manifest is None else manifest
    return Case(
        files=(
            File(".gitattributes", text=attributes),
            File(PATH, text=pointer_text),
        ),
        manifest=manifest_obj,
    )
