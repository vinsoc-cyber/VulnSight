FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    HOST=0.0.0.0 \
    PORT=5000 \
    VULNSIGHT_DATA_DIR=/data \
    VULNSIGHT_BIND=0.0.0.0

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg \
         -o /usr/share/keyrings/githubcli-archive-keyring.gpg \
    && chmod go+r /usr/share/keyrings/githubcli-archive-keyring.gpg \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" \
         > /etc/apt/sources.list.d/github-cli.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends gh \
    && apt-get purge -y --auto-remove curl \
    && rm -f /etc/apt/sources.list.d/github-cli.list \
             /usr/share/keyrings/githubcli-archive-keyring.gpg \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt "gunicorn==23.0.0"

COPY app.py .
COPY modules ./modules
COPY static ./static
COPY templates ./templates
COPY docker-entrypoint.sh /entrypoint.sh

# /data is writable by the runtime user; /app deliberately is not.
#
# `chown -R vulnsight:vulnsight /app /data` made the whole application
# source writable by the account the app runs as, so any file-write
# primitive -- a traversal in a cache or report path, an archive extraction
# -- became persistent code execution that survives a restart, because the
# app imports from /app. The cache, the OSV zips and the generated API
# token all live in /data, which is the volume.
RUN chmod +x /entrypoint.sh \
    && useradd --create-home --uid 1000 --shell /usr/sbin/nologin vulnsight \
    && mkdir -p /data/osv_cache \
    && chown -R vulnsight:vulnsight /data \
    && chown -R root:root /app \
    && chmod -R go-w /app

USER vulnsight

EXPOSE 5000
VOLUME ["/data"]

# compose declares one too; this covers `docker run`, which does not read
# docker-compose.yml. /api/meta is in _UNAUTHENTICATED_ENDPOINTS, so it
# answers 200 even when an API token is required.
HEALTHCHECK --interval=30s --timeout=8s --start-period=20s --retries=3 \
    CMD ["python", "-c", \
         "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/api/meta', timeout=5)"]

ENTRYPOINT ["/entrypoint.sh"]
# Bind every interface *inside* the container. Compose publishes
# 127.0.0.1:5000; do not map 0.0.0.0:5000 without VULNSIGHT_API_TOKEN.
#
# HOST above is read only by `python app.py`. Under this CMD gunicorn owns
# the bind and app.py's __main__ never runs, so nothing calls
# declare_self_bind() -- which is why VULNSIGHT_BIND is set as well. Without
# it the "is this exposed?" decision falls through to a default instead of
# being stated by the image that chose the bind.
CMD ["gunicorn", \
     "--bind", "0.0.0.0:5000", \
     "--workers", "1", \
     "--threads", "8", \
     "--timeout", "180", \
     "--access-logfile", "-", \
     "--error-logfile", "-", \
     "app:create_app()"]
