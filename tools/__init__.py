"""Maintenance tools, importable so the tests can drive them.

Each is a standalone script with a `main(argv)` that returns an exit code --
`tests/test_docs.py` runs the --check mode of the doc generators against the
shipped docs, so a doc that has drifted fails the suite rather than waiting
for someone to remember to run the script.
"""
