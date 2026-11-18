"""Reverts for the fixes that no behavioural revert can reach.

Dead-code removals, extractions and caches leave behaviour identical by
construction, so there is no edit that makes an ordinary assertion fail.
What they produced is a property of the tree, and `tests/test_cleanup_stays_clean.py`
asserts those properties directly -- these entries prove those assertions
actually bite, which is the same job the other groups do for behaviour.
"""

from __future__ import annotations

Edit = tuple[str, str, str]

CHECKS: list[tuple[str, list[Edit], str]] = [
    (
        # The gated categories, not the advisory one: `loop-only` is
        # reported and deliberately does not fail the build, so a revert
        # that only produces it proves nothing. A first attempt at these
        # two checks did exactly that and reported a false gap.
        "a test's only assertion hides behind an if",
        [("tests/test_ui_e2e.py",
          "        # Hiding it at every width would satisfy \"never cut off where shown\".\n"
          "        self.assertTrue(shown_somewhere,\n"
          '                        "the wordmark is never shown at any width")',
          "")],
        "test_cleanup_stays_clean",
    ),
    (
        "a test compares a value with itself",
        [("tests/test_records.py",
          '        self.assertEqual(records.identify({"other": "x"}, "id"), "")',
          '        self.assertEqual("", "")')],
        "test_cleanup_stays_clean",
    ),
    (
        "the image stops declaring the bind it chose",
        [("Dockerfile",
          "    VULNSIGHT_DATA_DIR=/data \\\n    VULNSIGHT_BIND=0.0.0.0",
          "    VULNSIGHT_DATA_DIR=/data")],
        "test_deployment",
    ),
    (
        "compose publishes the port on every interface",
        [("docker-compose.yml",
          '      - "127.0.0.1:${PORT:-5000}:5000"',
          '      - "${PORT:-5000}:5000"')],
        "test_deployment",
    ),
    (
        "the container goes back to running as root",
        [("Dockerfile", "USER vulnsight", "USER root")],
        "test_deployment",
    ),
    (
        "gunicorn is given more workers than the limiter allows",
        [("Dockerfile", '"--workers", "1",', '"--workers", "4",')],
        "test_deployment",
    ),
    (
        "curl is left in the shipped image",
        [("Dockerfile",
          "    && apt-get purge -y --auto-remove curl \\\n",
          "")],
        "test_deployment",
    ),
    (
        "the entrypoint forks instead of exec'ing",
        [("docker-entrypoint.sh", 'exec "$@"', '"$@"')],
        "test_deployment",
    ),
    (
        "an env var the code reads is documented nowhere",
        [("modules/config.py",
          "def load_dotenv(",
          'def _undocumented_knob():\n'
          '    return os.environ.get("VULNSIGHT_SECRET_KNOB", "")\n\n\n'
          "def load_dotenv(")],
        "test_deployment",
    ),
    (
        "a helper with no caller comes back",
        [("modules/nvd_client.py",
          "def _build_date_windows(",
          "def _build_date_params(start, end):\n"
          "    return {'pubStartDate': start, 'pubEndDate': end}\n\n\n"
          "def _build_date_windows(")],
        "test_cleanup_stays_clean",
    ),
    (
        "the second key-rotation implementation comes back",
        [("modules/ai_classifier.py",
          "    def seconds_until_any_live(self)",
          "    def rotate_token(self):\n"
          "        self._current_idx = (self._current_idx + 1) % len(self.tokens)\n"
          "        return self.tokens[self._current_idx]\n\n"
          "    def seconds_until_any_live(self)")],
        "test_cleanup_stays_clean",
    ),
    (
        "the published-window cache is removed",
        [("modules/query_filters.py",
          "@functools.lru_cache(maxsize=64)\ndef _published_bounds_cached",
          "def _published_bounds_cached")],
        "test_cleanup_stays_clean",
    ),
    (
        "gh is invoked by bare name again",
        # The shipped line is `gh_executable() or "gh"`: the fallback only
        # fires when gh is not on PATH at all, where it fails at exec. The
        # defect is dropping the resolved path entirely.
        [("modules/ghsa_client.py",
          '[gh_executable() or "gh", "api", "-i", "-X", "GET", path_with_query,',
          '["gh", "api", "-i", "-X", "GET", path_with_query,')],
        "test_cleanup_stays_clean",
    ),
    (
        "the picker goes back to asking the DOM per option",
        [("static/app.js",
          "    function isPicked(entry, checked) {",
          "    function isPicked(entry) {\n"
          "      const checked = checkedClassKeys();")],
        "test_cleanup_stays_clean",
    ),
    (
        "a generator binds the name g again",
        [("app.py",
          "                existing = next(\n"
          "                    (grp for grp in groups if grp[\"name\"] == name), None)",
          "                existing = next(\n"
          "                    (g for g in groups if g[\"name\"] == name), None)")],
        "test_cleanup_stays_clean",
    ),
]
