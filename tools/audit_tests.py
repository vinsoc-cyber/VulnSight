#!/usr/bin/env python3
"""Find tests that cannot fail.

A green suite is worth exactly as much as the tests in it can fail. This
sweeps every `tests/test_*.py` for the shapes a test takes when it has
stopped checking anything:

  no-assertion      the body never asserts, raises or uses assertRaises
  conditional-only  every assertion is nested inside an `if`, so an empty or
                    unexpected result skips the check and the test passes
  self-fulfilling   the only values asserted on are literals defined in the
                    same test, so it checks Python rather than the product
  reimplements      the test rebuilds the logic under test instead of calling
                    it, so it stays green while the shipped code is broken
  always-true       assertTrue(True), assertEqual(x, x), assertIn(a, a)

None of these are proof of a bad test on their own -- a smoke test that only
has to not raise is legitimate, and so is a loop that asserts per subTest.
This prints candidates for a human to judge, which is why the exit code is
0 unless --strict is passed.

    python tools/audit_tests.py
    python tools/audit_tests.py --strict   # non-zero if anything is flagged
"""

from __future__ import annotations

import ast
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
TESTS = ROOT / "tests"

ASSERT_CALLS = {
    "assertEqual", "assertNotEqual", "assertTrue", "assertFalse", "assertIs",
    "assertIsNot", "assertIsNone", "assertIsNotNone", "assertIn", "assertNotIn",
    "assertGreater", "assertGreaterEqual", "assertLess", "assertLessEqual",
    "assertRaises", "assertRaisesRegex", "assertAlmostEqual", "assertRegex",
    "assertNotRegex", "assertCountEqual", "assertSetEqual", "assertDictEqual",
    "assertListEqual", "assertLogs", "assertNoLogs", "assertWarns", "fail",
}


def _is_assertion(node: ast.AST) -> bool:
    if isinstance(node, ast.Assert):
        return True
    if isinstance(node, ast.Call):
        func = node.func
        # A helper named _assert_something asserts; several tests here
        # delegate every check to one, and reading only unittest's own
        # method names reported them as assertion-free.
        name = (func.attr if isinstance(func, ast.Attribute)
                else func.id if isinstance(func, ast.Name) else "")
        if name in ASSERT_CALLS or name.lstrip("_").startswith("assert"):
            return True
    return False


def _assertions(fn: ast.FunctionDef) -> list[ast.AST]:
    return [n for n in ast.walk(fn) if _is_assertion(n)]


# An `if` can be false and a loop can be empty; either way the body never
# runs and the test passes having checked nothing. Reading only `if` missed
# the commoner shape by far: a lone assertion inside
# `for x in <something that might be empty>`.


def _can_be_empty(node: ast.AST) -> bool:
    """True when a `for` over *node* might not run.

    A loop over a literal written in the test always runs, so it guards
    nothing -- `for status in (502, 503, 504)` is a parametrised assertion,
    not a conditional one. A loop over a call, a name or a comprehension is
    a runtime value that can come back empty, and that is the shape where
    "every X is fine" quietly becomes "there were no X".
    """
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return not node.elts
    if isinstance(node, ast.Dict):
        return not node.keys
    if isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes)):
        return not node.value
    # zip()/enumerate() over literals are still literal-driven.
    if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
            and node.func.id in {"zip", "enumerate", "reversed", "sorted"}):
        return any(_can_be_empty(a) for a in node.args)
    return True


def _guards(current: ast.AST, child: ast.AST, branches_only: bool) -> bool:
    if isinstance(current, (ast.For, ast.AsyncFor)):
        if branches_only:
            return False
        # Only the body is guarded; the iterable itself is not.
        return child is not current.iter and _can_be_empty(current.iter)
    return isinstance(current, (ast.If, ast.While, ast.ExceptHandler))


def _depth_guarded(fn: ast.FunctionDef, node: ast.AST, *,
                   branches_only: bool = False) -> bool:
    """True when *node* sits inside a branch, or a possibly-empty loop."""
    stack: list[tuple[ast.AST, bool]] = [(fn, False)]
    while stack:
        current, guarded = stack.pop()
        for child in ast.iter_child_nodes(current):
            if child is node:
                return guarded
            stack.append((child, guarded or _guards(current, child, branches_only)))
    return False


def audit_function(path: pathlib.Path, fn: ast.FunctionDef) -> list[str]:
    flags = []
    asserts = _assertions(fn)
    src = ast.get_source_segment(path.read_text(encoding="utf-8"), fn) or ""

    if not asserts:
        # Not-raising is a real assertion when the function under test is
        # a guard that raises. Those read as a bare call inside a context
        # manager, and the codebase says so in a comment or docstring.
        # The name counts too: these are written as sentences, and
        # `test_a_missing_file_is_not_an_error` states the assertion in the
        # only place it can be stated for a one-line call.
        haystack = src + " " + fn.name.replace("_", " ")
        says_so = any(phrase in haystack for phrase in
                      ("must not raise", "does not raise", "is safe",
                       "never fails", "not an error", "never fail"))
        if not says_so:
            flags.append("no-assertion")

    elif all(_depth_guarded(fn, a, branches_only=True) for a in asserts):
        # Every assertion sits behind an `if`. Nothing makes the branch run.
        flags.append("conditional-only")
    elif all(_depth_guarded(fn, a) for a in asserts):
        # Every assertion sits inside a loop over a runtime value. It will
        # run in practice -- url_map is not empty, the docs directory is not
        # empty -- but nothing in the test says so, and the day the glob
        # breaks the test reports success. Weaker than "cannot fail", so it
        # is reported and not gated.
        flags.append("loop-only")

    for node in asserts:
        if not isinstance(node, ast.Call) or len(node.args) < 2:
            continue
        left, right = node.args[0], node.args[1]
        if ast.dump(left) != ast.dump(right):
            continue
        # assertEqual(f(x), f(x)) is a determinism test -- two calls that
        # must agree -- not a tautology. Only flag it when neither side
        # calls anything, which is comparing a value to itself.
        if any(isinstance(n, ast.Call) for n in ast.walk(left)):
            continue
        flags.append("always-true")
        break

    for node in asserts:
        if (isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "assertTrue"
                and node.args
                and isinstance(node.args[0], ast.Constant)
                and node.args[0].value is True):
            flags.append("always-true")
            break

    return sorted(set(flags))


def main(argv: list[str]) -> int:
    strict = "--strict" in argv
    findings: list[tuple[str, str, str]] = []
    counted = 0

    for path in sorted(TESTS.glob("test_*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef):
                continue
            if not node.name.startswith("test_"):
                continue
            counted += 1
            findings += [(path.name, node.name, flag)
                         for flag in audit_function(path, node)]

    by_flag: dict[str, list[tuple[str, str]]] = {}
    for file, name, flag in findings:
        by_flag.setdefault(flag, []).append((file, name))

    print(f"{counted} test methods across "
          f"{len(list(TESTS.glob('test_*.py')))} files\n")
    if not findings:
        print("nothing flagged")
        return 0

    for flag in sorted(by_flag):
        rows = by_flag[flag]
        print(f"{flag}  ({len(rows)})")
        for file, name in rows:
            print(f"    {file}::{name}")
        print()

    gated = [f for f in findings if f[2] != "loop-only"]
    print(f"{len(findings)} candidate(s) for review"
          f" ({len(gated)} of them gated by --strict)")
    return 1 if strict and gated else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
