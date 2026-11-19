"""Cargo dependency-source fixtures (issue 45)."""

from __future__ import annotations

from . import Case, File, Fixture

GIT_SOURCE = "https://example.invalid/" + "replacement.git"
OUTSIDE_PATH = "../../../outside"


def cargo(text: str, path: str = "Cargo.toml") -> Case:
    return Case(files=(File(path, text=text),))


def cargo_vectors_patch() -> Fixture:
    return Fixture(
        positive=cargo(
            "[patch.crates-io]\n"
            'sample = { git = "' + GIT_SOURCE + '", rev = "abc123" }\n'
            "\n"
            "[workspace.dependencies]\n"
            'git_dep = { git = "' + GIT_SOURCE + '" }\n'
            'escaped = { path = "' + OUTSIDE_PATH + '" }\n'
        ),
        negative=cargo('[dependencies]\nsample = "1.2.3"\nlocal = { path = "crates/local" }\n'),
    )


BUILDERS = {"cargo_vectors_patch": cargo_vectors_patch}
