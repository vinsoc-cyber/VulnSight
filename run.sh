#!/usr/bin/env bash
# Bootstrap venv, install deps, and launch VulnSight.
set -euo pipefail
cd "$(dirname "$0")"

VENV=".venv"
if [ ! -d "$VENV" ]; then
  echo "==> Creating virtualenv"
  python3 -m venv "$VENV"
fi
# shellcheck disable=SC1091
source "$VENV/bin/activate"

# Before anything slow. A readable credentials file is a reason to stop,
# and finding that out after a minute of `pip install` is a minute spent
# with the tokens still readable.
if [ -f .env ]; then
  # Not best-effort. `chmod 600 .env 2>/dev/null || true` defeated the
  # `set -e` above, discarded the error and never checked the result, so the
  # server could start with a world-readable credentials file and say
  # nothing. If the mode cannot be fixed -- another owner, a symlink, a
  # filesystem without permission bits -- that is worth stopping for.
  if ! chmod 600 .env 2>/dev/null; then
    echo "!! Could not chmod 600 .env (owned by someone else, or a symlink?)."
    echo "!! It holds your GitHub and AI tokens. Fix it, or move it aside."
    exit 1
  fi
  mode="$(stat -c '%a' .env 2>/dev/null || stat -f '%Lp' .env 2>/dev/null || echo '')"
  case "$mode" in
    600|400) ;;
    "") echo "!! Could not read the mode of .env; continuing." ;;
    *)
      echo "!! .env is mode $mode — group or world readable, and it holds"
      echo "!! your GitHub and AI tokens. Refusing to start."
      exit 1
      ;;
  esac
else
  echo "!! No .env found — copy .env.example and add your own AI token for AI."
fi

echo "==> Installing dependencies"
pip install -q --upgrade pip >/dev/null
pip install -q -r requirements.txt

# Preflight checks
if ! command -v gh >/dev/null 2>&1; then
  echo "!! gh CLI not found. Install it: https://cli.github.com/"
elif ! gh auth status >/dev/null 2>&1; then
  echo "!! gh not authenticated. Run: gh auth login"
fi


echo "==> Starting server on http://127.0.0.1:${PORT:-5000}"
exec python app.py "$@"
