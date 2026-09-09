# syntax=docker/dockerfile:1.7
# ---------------------------------------------------------------------------
# Stage 1 - build a self-contained virtualenv.
# ---------------------------------------------------------------------------
FROM python:3.12-alpine AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /src

# Dependency metadata first so the layer caches across source edits.
COPY pyproject.toml README.md LICENSE ./
COPY guardenv ./guardenv

RUN python -m venv /opt/venv \
 && /opt/venv/bin/pip install --no-cache-dir . \
 && find /opt/venv -name '__pycache__' -type d -prune -exec rm -rf {} + \
 && find /opt/venv -name '*.dist-info' -type d -exec rm -rf {}/RECORD \;

# ---------------------------------------------------------------------------
# Stage 2 - minimal runtime.
# ---------------------------------------------------------------------------
FROM python:3.12-alpine AS runtime

LABEL org.opencontainers.image.title="GuardEnv" \
      org.opencontainers.image.description="High-speed detection of leaked credentials in source trees." \
      org.opencontainers.image.source="https://github.com/guardenv/guardenv" \
      org.opencontainers.image.licenses="MIT"

ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    # `rich` disables colour when it cannot detect a TTY; force it on so that
    # `docker run` output stays readable in CI logs.
    FORCE_COLOR=1

COPY --from=builder /opt/venv /opt/venv

# Run unprivileged: the scanner only ever needs read access to the mounted tree.
RUN addgroup -S guardenv && adduser -S -G guardenv -h /workspace guardenv
USER guardenv
WORKDIR /workspace

ENTRYPOINT ["guardenv"]
CMD ["scan", "."]
