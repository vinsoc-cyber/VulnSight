"""The deployment surface: Dockerfile, compose, entrypoint, run.sh.

These four files were never part of the six dimension reviews -- those were
organised by subsystem (HTTP layer, search pipeline, source clients, AI
classifier, taxonomy, frontend), and the files that decide how the app is
actually launched belong to none of them. They are also the most
security-relevant files in the repo after `modules/security.py`: they choose
the bind address, the user, and what else is in an image that holds a GitHub
token and AI keys.
"""

import os
import re
import shutil
import subprocess
import tempfile
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read(name):
    with open(os.path.join(ROOT, name), encoding="utf-8") as handle:
        return handle.read()


def _read_directives(name):
    """The file with its comment lines removed.

    Every one of these checks is about what the file *does*. Grepping the
    raw text keeps catching the comment that explains the defect being
    guarded against -- which reads as the defect still being present.
    """
    return "\n".join(line for line in _read(name).splitlines()
                      if not line.lstrip().startswith("#"))


class TestTheImageDeclaresItsOwnBind(unittest.TestCase):
    """`HOST` is read by `app.py`'s `__main__` only. The shipped CMD is
    gunicorn, which never runs it, so nothing calls `declare_self_bind()` and
    the "is this exposed, and is a token therefore mandatory?" decision fell
    through to a default. The answer was right; nothing in the image said so,
    and a change to that default would have moved a security decision
    silently."""

    def test_the_dockerfile_states_the_bind_it_chose(self):
        dockerfile = _read("Dockerfile")
        self.assertRegex(dockerfile, r"VULNSIGHT_BIND=0\.0\.0\.0",
                         "the image binds 0.0.0.0 but does not declare it")
        self.assertRegex(dockerfile, r"--bind[\"', ]+0\.0\.0\.0:",
                         "the CMD no longer binds 0.0.0.0; re-check the declaration")

    def test_compose_states_the_same_bind(self):
        compose = _read("docker-compose.yml")
        self.assertIn('VULNSIGHT_BIND: "0.0.0.0"', compose)

    def test_compose_publishes_to_loopback_only(self):
        """Every doc promises the published port is loopback-only. If that
        ever becomes 0.0.0.0, the token stops being optional."""
        compose = _read("docker-compose.yml")
        ports = re.findall(r'^\s*-\s*"([^"]+)"', compose, re.M)
        self.assertTrue(ports, "no published ports found")
        for mapping in ports:
            self.assertTrue(
                mapping.startswith("127.0.0.1:"),
                f"published port {mapping!r} is not loopback-only")

    def test_the_container_runs_as_a_non_root_user(self):
        dockerfile = _read("Dockerfile")
        users = re.findall(r"^USER\s+(\S+)", dockerfile, re.M)
        self.assertTrue(users, "the image never drops root")
        self.assertNotIn("root", users)
        self.assertEqual(users[-1], "vulnsight")

    def test_one_worker_because_the_limiter_is_per_process(self):
        """The rate limiter and the job pool are per process, and the docs
        say so. More than one worker silently multiplies every limit."""
        dockerfile = _read("Dockerfile")
        match = re.search(r'"--workers",\s*"(\d+)"', dockerfile)
        self.assertIsNotNone(match, "the worker count is no longer pinned")
        assert match is not None
        self.assertEqual(match.group(1), "1")

    def test_the_build_tool_is_not_left_in_the_shipped_image(self):
        """curl exists only to fetch the gh keyring at build time. An image
        that holds a GitHub token and AI keys should not also ship a
        general-purpose HTTP client."""
        dockerfile = _read("Dockerfile")
        self.assertIn("apt-get purge -y --auto-remove curl", dockerfile)


class TestTheEntrypointAndLauncher(unittest.TestCase):
    def test_both_shell_scripts_fail_fast(self):
        """Without `set -e` a failed mkdir or pip install is a warning and
        the server starts anyway, in a state nobody chose."""
        for name in ("docker-entrypoint.sh", "run.sh"):
            with self.subTest(script=name):
                head = _read(name).splitlines()[:5]
                self.assertTrue(
                    # `set -u` alone matched the old pattern, so a script
                    # that does not fail fast passed a test named for it.
                    any(re.match(r"set -[a-z]*e", line.strip()) for line in head),
                    f"{name} does not set -e")

    def test_the_entrypoint_execs_rather_than_forking(self):
        """`exec "$@"` makes gunicorn PID 1's child-of-record, so docker
        stop reaches it. A plain call leaves the shell holding the signal."""
        self.assertIn('exec "$@"', _read("docker-entrypoint.sh"))

    def test_run_sh_protects_a_dotenv_it_finds(self):
        """.env holds the GitHub and AI tokens in plain text."""
        self.assertIn("chmod 600 .env", _read("run.sh"))

    @unittest.skipUnless(
        subprocess.run(["sh", "-c", "command -v sh"],
                       capture_output=True).returncode == 0,
        "no POSIX shell")
    def test_the_shell_scripts_parse(self):
        """Nothing else executes these in CI, so a syntax error ships."""
        for name, shell in (("docker-entrypoint.sh", "sh"), ("run.sh", "bash")):
            with self.subTest(script=name):
                proc = subprocess.run([shell, "-n", os.path.join(ROOT, name)],
                                      capture_output=True, text=True, timeout=30)
                self.assertEqual(proc.returncode, 0,
                                 f"{name} does not parse:\n{proc.stderr}")


class TestBothPagesHaveTheSameHead(unittest.TestCase):
    """There are two rendered templates. Everything that is a property of
    "a VulnSight page" rather than of one page has to be on both, or the
    second one quietly degrades -- which is what happened: index.html got a
    favicon and apidocs.html did not, so every first load of /api/docs
    logged a 404."""

    TEMPLATES = ("templates/index.html", "templates/apidocs.html")

    def test_both_declare_an_icon(self):
        for name in self.TEMPLATES:
            with self.subTest(template=name):
                self.assertIn('rel="icon"', _read(name),
                              f"{name} leaves the browser to guess /favicon.ico")

    def test_both_declare_charset_viewport_and_description(self):
        for name in self.TEMPLATES:
            source = _read(name)
            for needle in ('charset="utf-8"', 'name="viewport"',
                           'name="description"', 'name="theme-color"'):
                with self.subTest(template=name, meta=needle):
                    self.assertIn(needle, source)

    def test_both_declare_a_language(self):
        for name in self.TEMPLATES:
            with self.subTest(template=name):
                self.assertIn('<html lang="en"', _read(name))

    def test_the_icon_they_reference_exists(self):
        self.assertTrue(os.path.isfile(os.path.join(ROOT, "static", "favicon.svg")))


class TestEveryKnobIsDocumented(unittest.TestCase):
    """`tests/test_docs.py` checks that every documented env var exists in
    the code. It never checked the other direction, so a new knob could ship
    read-by-the-code and documented nowhere -- which is how an operator ends
    up unable to find the setting that governs whether a token is required."""

    def _env_vars_in_code(self):
        source = _read("app.py")
        modules = os.path.join(ROOT, "modules")
        for name in sorted(os.listdir(modules)):
            if name.endswith(".py"):
                source += _read(os.path.join("modules", name))
        # os.environ.get("X") / os.environ["X"] / env_int("X", ...)
        return set(re.findall(
            r'(?:environ\.get\(|environ\[|env_int\(|env_float\(|getenv\()\s*["\']'
            r'(VULNSIGHT_[A-Z_]+|AI_[A-Z_]+|NVD_API_KEY|GH_TOKEN|GITHUB_TOKEN'
            r'|CVE_AI_PROVIDER|MAX_REQUEST_BYTES)["\']', source))

    def test_every_env_var_the_code_reads_is_documented(self):
        documented = set()
        for name in ("docs/configuration.md", ".env.example", "README.md"):
            documented |= set(re.findall(
                r"(VULNSIGHT_[A-Z_]+|AI_[A-Z_]+|NVD_API_KEY|GH_TOKEN"
                r"|GITHUB_TOKEN|CVE_AI_PROVIDER|MAX_REQUEST_BYTES)",
                _read(name)))
        undocumented = sorted(self._env_vars_in_code() - documented)
        self.assertEqual(
            undocumented, [],
            f"the code reads these and no doc mentions them: {undocumented}")

    def test_the_bind_knob_is_documented_where_an_operator_will_look(self):
        """It decides whether an API token is mandatory. Of all of them this
        is the one that must not be folklore."""
        config = _read("docs/configuration.md")
        self.assertIn("VULNSIGHT_BIND", config)


class TestTheImageDoesNotTrustItsOwnRuntimeUser(unittest.TestCase):
    """`chown -R vulnsight:vulnsight /app /data` made the application source
    writable by the account the app runs as. The app imports from /app, so
    any file-write primitive -- a traversal in a cache or report path, an
    archive extraction -- became persistent code execution that survives a
    restart. /data is the volume and needs to be writable; /app does not."""

    def test_app_is_not_chowned_to_the_runtime_user(self):
        self.assertNotRegex(
            _read_directives("Dockerfile"),
            r"chown\s+-R\s+vulnsight:vulnsight[^\n]*\s/app",
            "/app is writable by the user the app runs as")

    def test_data_is_still_writable(self):
        self.assertRegex(_read_directives("Dockerfile"),
                         r"chown\s+-R\s+vulnsight:vulnsight[^\n]*/data")

    def test_group_and_other_write_are_stripped_from_app(self):
        self.assertIn("chmod -R go-w /app", _read_directives("Dockerfile"))

    def test_the_gh_apt_source_is_not_left_in_the_image(self):
        """The keyring and the sources.list entry exist to install gh at
        build time. Leaving them means the shipped image carries an extra
        third-party apt source it never uses again."""
        dockerfile = _read("Dockerfile")
        self.assertRegex(dockerfile, r"rm -f /etc/apt/sources\.list\.d/github-cli\.list")


class TestDependenciesArePinnedExactly(unittest.TestCase):
    """A range plus Docker layer caching ships a stale wheel forever: the
    `pip install` layer is keyed on requirements.txt, which never changes,
    so a rebuild after a Flask security release installs nothing new -- into
    an image that holds a GitHub token and AI keys. Two builds from one
    commit were also not reproducible."""

    def test_every_requirement_is_an_exact_version(self):
        for line in _read("requirements.txt").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            with self.subTest(requirement=line):
                self.assertRegex(
                    line, r"^[A-Za-z0-9_.\-]+==[0-9][^,]*$",
                    "pin this exactly; a range cannot invalidate the layer")
                self.assertNotIn(">", line)
                self.assertNotIn("<", line)

    def test_gunicorn_is_pinned_too(self):
        self.assertRegex(_read("Dockerfile"), r'"gunicorn==[0-9]')


class TestCredentialsNeedNotLiveInTheEnvironment(unittest.TestCase):
    """A value in `environment` is visible in `docker inspect`, in
    /proc/1/environ, in a crash dump and in `docker compose config` -- the
    last being the first thing anyone pastes into a bug report. The app
    already writes its own token to a 0600 file, so the file-based pattern
    exists; the entrypoint now accepts it for the inbound ones too."""

    def test_the_entrypoint_reads_every_credential_from_a_file_if_asked(self):
        entrypoint = _read("docker-entrypoint.sh")
        for var in ("GH_TOKEN", "GITHUB_TOKEN", "NVD_API_KEY", "AI_TOKEN",
                    "VULNSIGHT_API_TOKEN"):
            with self.subTest(var=var):
                self.assertIn(var, entrypoint)
        self.assertIn("_FILE", entrypoint)

    def test_an_unreadable_secret_file_stops_the_container(self):
        """Falling through would start the app with no credential and a
        confusing auth failure several minutes later."""
        self.assertRegex(_read("docker-entrypoint.sh"),
                         r"cannot be read[\s\S]{0,80}exit 1")

    def test_the_secret_value_is_never_echoed(self):
        entrypoint = _read_directives("docker-entrypoint.sh")
        for line in entrypoint.splitlines():
            stripped = line.strip()
            if not stripped.startswith("echo"):
                continue
            with self.subTest(line=stripped[:60]):
                self.assertNotIn("$(cat", stripped)

    def test_the_image_still_declares_a_healthcheck_of_its_own(self):
        """compose has one; `docker run` does not read compose."""
        self.assertIn("HEALTHCHECK", _read("Dockerfile"))


class TestTheLauncherRefusesAReadableDotEnv(unittest.TestCase):
    """`chmod 600 .env 2>/dev/null || true` defeated the `set -e` above it,
    discarded the error and never checked the result -- so the server could
    start with a world-readable credentials file and say nothing."""

    def test_the_chmod_is_not_swallowed(self):
        self.assertNotIn("chmod 600 .env 2>/dev/null || true",
                         _read_directives("run.sh"))

    def test_the_check_runs_before_the_slow_work(self):
        """Finding out after a minute of `pip install` is a minute spent
        with the tokens still readable."""
        directives = _read_directives("run.sh")
        self.assertLess(directives.index("if [ -f .env ]"),
                        directives.index("pip install"))

    def test_it_verifies_the_resulting_mode(self):
        run_sh = _read("run.sh")
        self.assertRegex(run_sh, r"stat .*\.env")
        self.assertRegex(run_sh, r"600\|400")

    def _run_launcher(self, mode):
        """The real script, against a real .env at *mode*.

        Copied into a scratch directory because run.sh does
        `cd "$(dirname "$0")"` -- pointing cwd at a temp dir is not enough,
        it would read this repo's own .env. A stub .venv skips the
        bootstrap, and a chmod shim lets the mode under test survive to the
        check, which is the state an operator reaches when .env is owned by
        someone else.
        """
        with tempfile.TemporaryDirectory() as tmp:
            shutil.copy(os.path.join(ROOT, "run.sh"), os.path.join(tmp, "run.sh"))
            os.makedirs(os.path.join(tmp, ".venv", "bin"))
            with open(os.path.join(tmp, ".venv", "bin", "activate"), "w") as fh:
                fh.write("# stub\n")
            env_path = os.path.join(tmp, ".env")
            with open(env_path, "w", encoding="utf-8") as fh:
                fh.write("GH_TOKEN=xxx\n")
            os.chmod(env_path, mode)
            shim = os.path.join(tmp, "bin")
            os.makedirs(shim)
            with open(os.path.join(shim, "chmod"), "w", encoding="utf-8") as fh:
                fh.write("#!/bin/sh\nexit 0\n")
            os.chmod(os.path.join(shim, "chmod"), 0o755)
            # pip must not actually run; the check is meant to come first.
            with open(os.path.join(shim, "pip"), "w", encoding="utf-8") as fh:
                fh.write("#!/bin/sh\necho PIP-RAN\nexit 0\n")
            os.chmod(os.path.join(shim, "pip"), 0o755)
            env = dict(os.environ, PATH=shim + os.pathsep + os.environ["PATH"])
            return subprocess.run(
                ["bash", os.path.join(tmp, "run.sh")],
                cwd=tmp, env=env, capture_output=True, text=True, timeout=120)

    def test_a_group_readable_dotenv_stops_the_launcher(self):
        proc = self._run_launcher(0o644)
        output = proc.stdout + proc.stderr
        self.assertNotEqual(proc.returncode, 0,
                            "the launcher started with a readable .env")
        self.assertIn("Refusing to start", output)
        self.assertNotIn("PIP-RAN", output,
                         "it did a minute of work before checking")


if __name__ == "__main__":
    unittest.main()
