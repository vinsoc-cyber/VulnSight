#!/usr/bin/env python3
"""Find tests that cannot fail.

A green suite is worth exactly as much as the tests in it can fail. This
sweeps every `tests/test_*.py` for the shapes a test takes when it has
stopped checking anything:

  no-assertion      the body never asserts, raises or uses assertRaises
  conditional-only  every assertion is nested inside an `if`, so an empty or
                    unexpected result skips the check and the test passes
  loop-only         every assertion sits inside a loop over a runtime value,
                    so an empty sequence is a pass
  self-fulfilling   nothing under test is ever called: every name the test
                    asserts on was assigned in the test itself, so it checks
                    Python rather than the product
  reimplements      the test rebuilds an expected value with the same
                    operations the code under test uses, so it stays green
                    while the shipped code is broken in the same way
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


def _imported_names(tree: ast.Module) -> set[str]:
    """Top-level names bound by imports, for the self-fulfilling check."""
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                names.add(alias.asname or alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                names.add(alias.asname or alias.name)
    return names


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


def _assertions(fn: ast.AST) -> list[ast.AST]:
    """Assertions in this function, not in functions nested inside it.

    `ast.walk` descended into nested `def`s, so a test that *defines* a
    helper full of assertions and never calls it counted as asserting --
    which is the shape of a test that has been commented out from the
    inside.
    """
    found: list[ast.AST] = []
    stack: list[ast.AST] = [fn]
    while stack:
        node = stack.pop()
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue          # a nested def is its own scope
            if _is_assertion(child):
                found.append(child)
            stack.append(child)
    return found


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


def _depth_guarded(fn: ast.AST, node: ast.AST, *,
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


def _references_anything_outside(fn: ast.AST, imported: set[str],
                                 helpers: set[str]) -> bool:
    """True when the test reaches anything defined outside its own body.

    The stated defect is "the only values asserted on are literals defined
    in the same test, so it checks Python rather than the product", and the
    first implementation asked a much narrower question -- "does it *call*
    an imported name" -- which flagged 45 honest tests. A product function
    passed as a callback (`key=search_service._cve_sort_key`) is reaching
    the product without being called here, and a test that asserts on a
    module's source text through a file-reading helper is reaching it too.

    So: does any imported name, or any module-level helper from the same
    file, appear anywhere in this function? If nothing does, the test can
    only be examining values it made up.
    """
    for node in ast.walk(fn):
        if isinstance(node, ast.Name) and (node.id in imported
                                           or node.id in helpers):
            return True
        if isinstance(node, ast.Attribute):
            root = node
            while isinstance(root, ast.Attribute):
                root = root.value
            if isinstance(root, ast.Name):
                if root.id in imported or root.id in helpers:
                    return True
                # self.<x> where x is not an assertion reaches a fixture.
                if root.id == "self" and not node.attr.startswith(("assert", "fail")):
                    return True
    return False


# Operators that a test re-applying the code's own arithmetic will use. A
# literal expectation is fine; recomputing one is how `min(max(x, 10), 2000)`
# ended up on both sides of an assertEqual.
_ARITHMETIC = (ast.Add, ast.Sub, ast.Mult, ast.Div, ast.FloorDiv, ast.Mod,
               ast.Pow)


def _all_literal(node: ast.AST) -> bool:
    """True when nothing in *node* is a name or a call.

    `120 * 86400` is a readable spelling of "120 days in seconds", not a
    reimplementation of anything -- it was the detector's first and only
    false positive, against an assertion that measured a real duration
    against a documented bound.
    """
    return not any(isinstance(inner, (ast.Name, ast.Call, ast.Attribute))
                   for inner in ast.walk(node))


def _is_computed(side: ast.AST) -> bool:
    """True when this side of a comparison is calculated rather than stated.

    A constant expression does not count, however it is spelled.
    """
    for inner in ast.walk(side):
        if (isinstance(inner, ast.BinOp) and isinstance(inner.op, _ARITHMETIC)
                and not _all_literal(inner)):
            return True
        if (isinstance(inner, ast.Call) and isinstance(inner.func, ast.Name)
                and inner.func.id in {"min", "max", "round", "abs", "sum"}
                and not _all_literal(inner)):
            return True
    return False


def audit_function(source: str,
                   fn: ast.FunctionDef | ast.AsyncFunctionDef,
                   imported: set[str] | None = None,
                   helpers: set[str] | None = None) -> list[str]:
    """Flags for one test function.

    *source* is the file's text. It replaced a per-function re-read of the
    file from disk -- a 1,400-line test module was read ninety times -- and
    is kept now that the checks work from the AST alone, because a future
    check that needs the raw text should not reintroduce that read.
    """
    flags = []
    asserts = _assertions(fn)

    if not asserts:
        # Not-raising is a real assertion when the function under test is
        # a guard that raises. Those read as a bare call inside a context
        # manager, and the codebase says so in a comment or docstring.
        # The name counts too: these are written as sentences, and
        # `test_a_missing_file_is_not_an_error` states the assertion in the
        # only place it can be stated for a one-line call.
        # The claim has to be in the DOCSTRING or the NAME, not anywhere in
        # the source. Searching the whole function body cleared any test
        # that happened to contain one of these phrases in a variable, a
        # comment or an unrelated string -- an escape hatch that widened
        # every time somebody wrote the words "is safe" for another reason.
        doc = ast.get_docstring(fn) or ""
        haystack = doc + " " + fn.name.replace("_", " ")
        says_so = any(phrase in haystack.lower() for phrase in
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

    # self-fulfilling: asserts, but never reaches the product.
    if (asserts and imported is not None and helpers is not None
            and not _references_anything_outside(fn, imported, helpers)):
        flags.append("self-fulfilling")

    # reimplements: both sides of a comparison are computed the same way.
    # Only flagged when BOTH sides compute, because one computed side is an
    # ordinary expectation ("twice the page size").
    for node in asserts:
        if not (isinstance(node, ast.Call) and len(node.args) >= 2):
            continue
        # Both sides, because one computed side is an ordinary expectation
        # ("twice the page size"). Both computed the same way is the shape
        # where the test and the code can be wrong together.
        if _is_computed(node.args[0]) and _is_computed(node.args[1]):
            flags.append("reimplements")
            break

    return sorted(set(flags))


def main(argv: list[str]) -> int:
    strict = "--strict" in argv
    findings: list[tuple[str, str, str]] = []
    counted = 0

    files = sorted(TESTS.glob("test_*.py"))
    # A floor. An empty glob printed "0 test methods / nothing flagged" and
    # returned 0 under --strict, so a misconfigured path reported a clean
    # sweep of nothing -- the exact shape this tool exists to find.
    if len(files) < 5:
        print(f"only {len(files)} test file(s) under {TESTS}; refusing to "
              f"report a clean sweep", file=sys.stderr)
        return 2

    for path in files:
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source)
        imported = _imported_names(tree)
        helpers = {node.name for node in tree.body
                   if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}
        helpers |= {target.id for node in tree.body
                    if isinstance(node, ast.Assign)
                    for target in node.targets if isinstance(target, ast.Name)}
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if not node.name.startswith("test_"):
                continue
            counted += 1
            findings += [(path.name, node.name, flag)
                         for flag in audit_function(source, node, imported, helpers)]

    by_flag: dict[str, list[tuple[str, str]]] = {}
    for file, name, flag in findings:
        by_flag.setdefault(flag, []).append((file, name))

    print(f"{counted} test methods across {len(files)} files\n")
    if counted < 50:
        print(f"only {counted} test methods found; refusing to report a "
              f"clean sweep", file=sys.stderr)
        return 2
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
