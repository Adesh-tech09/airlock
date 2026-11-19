"""Synthetic npm lockfile fixtures for registry host validation (issue 46)."""

from __future__ import annotations

from . import Case, File, Fixture

REGISTRY = "https://" + "registry.npmjs.org/"
MIRROR = "https://" + "mirror.example.invalid/"
GIT_URL = "git+" + "https://example.invalid/repo.git"


def _lock(text: str) -> Case:
    return Case(files=(File("package-lock.json", text=text),))


def npm_lockfile_registry() -> Fixture:
    return Fixture(
        positive=_lock(
            '{"lockfileVersion":3,"packages":{"":{"name":"root"},'
            '"node_modules/left-pad":{"version":"1.0.0","resolved":"'
            + MIRROR
            + 'left-pad/-/left-pad.tgz"}}}'
        ),
        negative=_lock(
            '{"lockfileVersion":3,"packages":{'
            '"node_modules/left-pad":{"resolved":"' + REGISTRY + 'left-pad/-/left-pad.tgz"},'
            '"node_modules/git-package":{"resolved":"'
            + GIT_URL
            + '"},"node_modules/local":{"resolved":"file:../local"}}}'
        ),
    )


BUILDERS = {"npm_lockfile_registry": npm_lockfile_registry}
