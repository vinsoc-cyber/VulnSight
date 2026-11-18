#!/bin/sh
set -eu

data_dir="${VULNSIGHT_DATA_DIR:-/data}"
mkdir -p "${data_dir}/osv_cache"

# Docker secrets, read here rather than passed as environment variables.
#
# A value in the environment shows up in `docker inspect`, in
# /proc/1/environ, in any crash dump, and in `docker compose config` --
# which is the first thing anyone pastes into a bug report. A secret is a
# 0400 file in a tmpfs that only this container can read. The *_FILE
# convention is what the postgres and redis images use, so it is the shape
# an operator already expects.
#
# Environment variables still work, so nothing that worked before stops.
for var in GH_TOKEN GITHUB_TOKEN NVD_API_KEY AI_TOKEN GLM_TOKEN \
           OPENAI_TOKEN ANTHROPIC_TOKEN VULNSIGHT_API_TOKEN; do
  eval "file=\${${var}_FILE:-}"
  if [ -n "${file}" ]; then
    if [ ! -r "${file}" ]; then
      echo "!! ${var}_FILE is set to ${file}, which cannot be read." >&2
      exit 1
    fi
    # No echo of the value, and the subshell keeps it off the process list.
    eval "export ${var}=\"\$(cat \"${file}\")\""
    echo "==> ${var}: loaded from a file"
  fi
done

if [ -n "${GH_TOKEN:-}${GITHUB_TOKEN:-}" ]; then
  echo "==> gh: using token from the environment"
elif gh auth status >/dev/null 2>&1; then
  echo "==> gh: already authenticated"
else
  echo "!! gh not authenticated — GHSA searches will fail."
  echo "   Host login is stored in the OS keyring, so the container cannot reuse it."
  echo "   Pass a token:  GH_TOKEN=\$(gh auth token) docker compose up --build"
  echo "   or set GH_TOKEN in .env"
fi

exec "$@"
