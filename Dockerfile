# Jnvoy privacy and security gateway
# Production Dockerfile, in two stages: the first installs everything (it needs a compiler to
# be safe against packages without a ready-made build), the second copies only the result.
# The image that runs has no compiler, no pip cache and no build tools.

# ── Stage 1: install ──────────────────────────────────────────────────────────
FROM python:3.12-slim AS builder

ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
RUN apt-get update && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/*

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Requirements first, so this layer is reused until a dependency changes
WORKDIR /build
COPY requirements.txt constraints.txt ./
RUN pip install -r requirements.txt

# Download spaCy models
RUN python -m spacy download en_core_web_lg && python -m spacy download en_core_web_sm

# ── Stage 2: run ──────────────────────────────────────────────────────────────
FROM python:3.12-slim

ENV PATH="/opt/venv/bin:$PATH" PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1

# curl is only for the health check below
RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

# Non-root user for security
RUN useradd -m -u 1000 jnvoy

COPY --from=builder /opt/venv /opt/venv

WORKDIR /app
COPY --chown=jnvoy:jnvoy . .
USER jnvoy

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Start the server
# One worker on purpose: the response cache and the per-minute rate limit live in memory, so
# with several workers each would keep its own count and the limits would be wrong. Scale by
# running more containers behind a shared limiter once that exists.
CMD ["uvicorn", "api.proxy_v2:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1", "--no-access-log"]
