"""`STATE_RULE_IDS` covers every state finding its producers can emit (#50).

`model.STATE_RULE_IDS` is hand-written, and the existing test only asserts the documented ids are
a subset of it. That leaves the dangerous direction uncovered: an id the engine emits but the set
lacks is a scanner-state finding an owner could suppress by name, and `policy._entry_problem`
would not refuse it.

The producers are read from source with `ast`, not by inspecting running modules, so a producer
that is removed or whose id constant is renamed is caught. Most policy call sites pass a module
constant, so the first argument is resolved through the module-level string assignments.
"""

from __future__ import annotations

import ast
from pathlib import Path

from airlock.model import STATE_RULE_IDS
from airlock.rules import LONG_LINE_RULE_ID
from airlock.runner import DETECTOR_ERROR_RULE_ID

REPO_ROOT = Path(__file__).resolve().parents[2]
SOURCE_ROOT = REPO_ROOT / "src" / "airlock"

#: Modules that build state findings through a local `_state` helper.
STATE_PRODUCERS = (SOURCE_ROOT / "collector.py", SOURCE_ROOT / "policy.py")

#: The two ids built outside a `_state` call, with the file that owns each.
EXTERNAL_PRODUCERS = {
    DETECTOR_ERROR_RULE_ID: "src/airlock/runner.py",
    LONG_LINE_RULE_ID: "src/airlock/rules.py",
}


def _module_string_constants(tree: ast.Module) -> dict[str, str]:
    """Module-level `NAME = "literal"` assignments, which is how policy names its ids."""
    constants: dict[str, str] = {}
    for node in tree.body:
        if isinstance(node, ast.Assign):
            targets, value = node.targets, node.value
        elif isinstance(node, ast.AnnAssign):
            targets, value = [node.target], node.value
        else:
            continue
        if value is None:
            continue
        for target in targets:
            if (
                isinstance(target, ast.Name)
                and isinstance(value, ast.Constant)
                and isinstance(value.value, str)
            ):
                constants[target.id] = value.value
    return constants


def _resolve(argument: ast.expr | None, constants: dict[str, str]) -> str | None:
    if isinstance(argument, ast.Constant) and isinstance(argument.value, str):
        return argument.value
    if isinstance(argument, ast.Name):
        return constants.get(argument.id)
    return None


def state_ids_from(path: Path) -> dict[str, str]:
    """Every `_state(...)` first argument in one module, mapped to that module."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    constants = _module_string_constants(tree)
    found: dict[str, str] = {}
    relative = path.relative_to(REPO_ROOT).as_posix()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if not isinstance(node.func, ast.Name) or node.func.id != "_state":
            continue
        rule_id = _resolve(node.args[0] if node.args else None, constants)
        assert rule_id is not None, (
            f"{relative}:{node.lineno}: _state first argument is neither a string literal nor a "
            "module-level string constant"
        )
        found.setdefault(rule_id, relative)
    return found


def derived_state_ids() -> dict[str, str]:
    """The ids the engine emits, each mapped to the file that emits it."""
    derived: dict[str, str] = {}
    for path in STATE_PRODUCERS:
        for rule_id, source in state_ids_from(path).items():
            derived.setdefault(rule_id, source)
    for rule_id, source in EXTERNAL_PRODUCERS.items():
        derived.setdefault(rule_id, source)
    return derived


def coverage_problems(derived: dict[str, str], state_ids: frozenset[str]) -> list[str]:
    """One line per disagreement, naming one id and the file it came from."""
    problems: list[str] = []
    for rule_id in sorted(set(derived) - state_ids):
        problems.append(
            f"{rule_id} is emitted by {derived[rule_id]} but missing from STATE_RULE_IDS"
        )
    for rule_id in sorted(set(state_ids) - set(derived)):
        problems.append(f"{rule_id} is in STATE_RULE_IDS but no producer emits it")
    return problems


def _state_rule_literal_ids(tree: ast.Module) -> list[str]:
    """The string ids written in the `STATE_RULE_IDS = frozenset({...})` literal."""
    for node in ast.walk(tree):
        targets: list[ast.expr]
        if isinstance(node, ast.Assign):
            targets, value = node.targets, node.value
        elif isinstance(node, ast.AnnAssign):
            targets, value = [node.target], node.value
        else:
            continue
        named = any(
            isinstance(target, ast.Name) and target.id == "STATE_RULE_IDS" for target in targets
        )
        if not named:
            continue
        return [
            child.value
            for child in ast.walk(value)
            if isinstance(child, ast.Constant) and isinstance(child.value, str)
        ]
    raise AssertionError("STATE_RULE_IDS is not assigned anywhere in model.py")


class TestStateRuleIds:
    def test_every_emitted_state_id_is_in_the_frozenset(self) -> None:
        assert coverage_problems(derived_state_ids(), STATE_RULE_IDS) == []

    def test_the_checker_names_a_missing_id_and_its_file(self) -> None:
        derived = derived_state_ids()
        source = derived["no-trusted-base"]
        shrunk = frozenset(STATE_RULE_IDS - {"no-trusted-base"})
        problems = coverage_problems(derived, shrunk)
        assert len(problems) == 1
        assert "no-trusted-base" in problems[0]
        assert source in problems[0]

    def test_the_checker_names_an_extra_id(self) -> None:
        derived = derived_state_ids()
        derived["not-produced"] = "src/airlock/model.py"
        problems = coverage_problems(derived, STATE_RULE_IDS)
        assert problems == [
            "not-produced is emitted by src/airlock/model.py but missing from STATE_RULE_IDS"
        ]

    def test_the_frozenset_literal_holds_no_duplicate(self) -> None:
        # A frozenset deduplicates silently, so a repeated literal would look like an id that is
        # present and leave the producer it was meant to add uncovered. The literal is the only
        # place the duplication is still visible.
        tree = ast.parse(
            (SOURCE_ROOT / "model.py").read_text(encoding="utf-8"),
            filename=str(SOURCE_ROOT / "model.py"),
        )
        literal = _state_rule_literal_ids(tree)
        duplicated = sorted({rule_id for rule_id in literal if literal.count(rule_id) > 1})
        assert duplicated == []
